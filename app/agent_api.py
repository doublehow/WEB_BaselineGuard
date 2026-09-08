"""Agent 回報 API —— 獨立埠(預設 8074),與 Web UI(8073)完全隔離。

- 無登入 session;所有端點以主機各自的 Agent token 驗證(X-UCC-Token 標頭
  或 token 查詢參數),token 於「主機管理」新增 Agent 模式主機時產生。
- GET  /install?token=…  一鍵安裝腳本(烙入伺服器位址與 token;curl | sudo bash)
- GET  /script           最新版檢查腳本(agent 每次執行前自動更新)
- POST /report           回報檢查結果(表單欄位 json=結果 JSON、raw=人類可讀報告)

**腳本完整性(X-UCC-Sig)**:兩埠皆為純 HTTP,agent 每日以 root 執行從
/script 取回的腳本 —— 若不驗證來源,管理網段內的 MITM 即可對全機群下達
root RCE。token 本身就是伺服器與該台 agent 的共享秘密,故 /script 回應
附帶 `X-UCC-Sig: HMAC-SHA256(key=token, msg=腳本內容)` 的 hex;安裝腳本
以 `openssl dgst -sha256 -hmac "$TOKEN"` 自算比對,不符即拒絕更新、沿用
本機既有版本(fail-safe,絕不執行未驗證的腳本)。
舊版 agent 不驗此標頭仍可正常取回腳本(向後相容),但要獲得這層保護
**必須重跑一鍵安裝指令**。
"""
from __future__ import annotations

import asyncio
import hmac
import json as _json
import logging
import secrets as _secrets
from hashlib import sha256
from urllib.parse import parse_qsl

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from app.checker import save_report, script_text
from app.config import local_now, settings
from app.database import SessionLocal
from app.models import Host

logger = logging.getLogger("ucc.agent_api")

# 回報 payload 上限:未認證者連 body 都讀不到(先驗 token 再讀),
# 認證後仍設限,避免單台異常 agent 把記憶體/DB 撐爆。
BODY_MAX = 5 * 1024 * 1024      # 整個表單 body 位元組上限
JSON_MAX = 2 * 1024 * 1024      # json 欄位字串長度上限
ITEMS_MAX = 500                 # 檢查項筆數上限(目前最多的 Linux 約 100 項)
REPORT_MIN_INTERVAL = 60        # 同主機兩次回報最小間隔秒數(防持 token 灌報)
SIG_HEADER = "X-UCC-Sig"        # /script 回應的腳本 HMAC 簽章標頭

agent_app = FastAPI(title="BaselineGuard Agent API",
                    docs_url=None, redoc_url=None, openapi_url=None)


def _host_by_token(db, token: str) -> Host | None:
    """token → 啟用中的 Agent 主機(逐台常數時間比對,防時序側漏)。

    憑證密文非決定性,無法用 WHERE 直接查,只能逐台比對;
    `compare_digest` 的 str 版要求兩邊皆 ASCII,非 ASCII 的 token 先擋下
    視為無效(否則拋 TypeError → 500,可被拿來刷錯誤 log)。
    """
    if not token or not token.isascii():
        return None
    for h in db.query(Host).filter(Host.mode == "agent",
                                   Host.enabled.is_(True)).all():
        if h.agent_token and _secrets.compare_digest(h.agent_token, token):
            return h
    return None


def _lookup_agent(token: str) -> dict | None:
    """(於工作執行緒內)token → 主機摘要 dict;查無回 None。

    只回純量,不把 ORM 物件帶出 session,避免跨 thread 使用同一 session。
    """
    with SessionLocal() as db:
        host = _host_by_token(db, token)
        if host is None:
            return None
        return {"id": host.id, "name": host.name,
                "slow": "1" if host.slow_scan else "0",
                "last_checked_at": host.last_checked_at}


def _store_report(host_id: int, data: dict, raw: str) -> dict | None:
    """(於工作執行緒內)開 session → 取主機 → 入庫;失敗記完整 log 並回 None。

    session 的建立與使用都在同一執行緒內完成;SQLite busy 時最長會卡 30 秒,
    故整段由 `asyncio.to_thread` 呼叫,不佔用 Agent API 的 event loop。
    """
    try:
        with SessionLocal() as db:
            host = db.get(Host, host_id)
            if host is None:      # 驗 token 後、入庫前被刪除
                logger.error("回報入庫時主機 id=%s 已不存在", host_id)
                return None
            run = save_report(db, host, data, raw, "agent")
            return {"run_id": run.id,
                    "summary": {"pass": run.c_pass, "fail": run.c_fail,
                                "warn": run.c_warn}}
    except Exception:  # noqa: BLE001 — 例外不得裸奔成 500 traceback
        logger.exception("主機 id=%s 回報入庫失敗", host_id)
        return None


async def _read_body(request: Request) -> bytes | None:
    """串流讀取 request body,累積超過 BODY_MAX 立即中止並回 None。

    不用 `Form(...)`:框架會在進入 handler 前就把整份表單讀進記憶體,
    等於在驗 token 之前先替攻擊者買單。
    """
    declared = request.headers.get("content-length") or ""
    if declared.isdigit() and int(declared) > BODY_MAX:
        return None
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > BODY_MAX:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def _parse_form(body: bytes) -> dict[str, str]:
    """解析 application/x-www-form-urlencoded。

    舊版 agent 以 `curl --data-urlencode "json@…" "raw@…"` 送出即為此格式,
    手動解析維持完全相容(同名欄位取最後一個,與框架行為一致)。
    """
    return dict(parse_qsl(body.decode("utf-8", "replace"),
                          keep_blank_values=True))


@agent_app.get("/")
async def root():
    return PlainTextResponse("BaselineGuard Agent API")


@agent_app.get("/script")
async def get_script(x_ucc_token: str = Header(""), token: str = ""):
    presented = x_ucc_token or token
    if await asyncio.to_thread(_lookup_agent, presented) is None:
        return PlainTextResponse("invalid token", status_code=401)
    body = script_text().encode("utf-8")
    # 以該主機 token 為金鑰對腳本內容簽章,供 agent 端驗完整性(見檔頭說明)
    sig = hmac.new(presented.encode("utf-8"), body, sha256).hexdigest()
    return PlainTextResponse(body, media_type="text/x-shellscript",
                             headers={SIG_HEADER: sig})


@agent_app.get("/install")
async def get_installer(request: Request, x_ucc_token: str = Header(""),
                        token: str = ""):
    # 優先取標頭(token 不進 access log / bash history);
    # 查詢參數保留,以相容主機詳情頁既有的一鍵安裝指令
    presented = x_ucc_token or token
    info = await asyncio.to_thread(_lookup_agent, presented)
    if info is None:
        return PlainTextResponse("invalid token", status_code=401)
    # 以 agent 實際連入的主機名組回報位址(埠固定為 agent_api_port)
    server_url = (f"{request.url.scheme}://{request.url.hostname}"
                  f":{settings.agent_api_port}")
    script = (_INSTALLER_TEMPLATE
              .replace("__SERVER_URL__", server_url)
              .replace("__TOKEN__", presented)
              .replace("__SLOW__", info["slow"])
              .replace("__CHECK_TIME__", settings.agent_check_time))
    return PlainTextResponse(script, media_type="text/x-shellscript")


@agent_app.post("/report")
async def post_report(request: Request):
    # 1) 先驗 token(只讀標頭),未認證者的 body 一個位元組都不收
    token = request.headers.get("x-ucc-token", "")
    info = await asyncio.to_thread(_lookup_agent, token)
    if info is None:
        return JSONResponse({"ok": False, "error": "invalid token"},
                            status_code=401)
    name = info["name"]

    # 1.5) 頻率下限:正常 Agent 為每日 timer,一分鐘內重複回報必屬異常
    #(灌報會撐大 DB 與版本軸、淹沒近期異動);429 讓正常 retry 稍後再來
    last = info.get("last_checked_at")
    if last and (local_now() - last).total_seconds() < REPORT_MIN_INTERVAL:
        logger.warning("主機 %s 回報間隔低於 %s 秒,已拒絕", name,
                       REPORT_MIN_INTERVAL)
        return JSONResponse({"ok": False, "error": "report too frequent"},
                            status_code=429)

    # 2) 有上限地讀 body 並自行解析表單
    body = await _read_body(request)
    if body is None:
        logger.warning("主機 %s 回報 payload 超過上限 %s bytes,已拒絕",
                       name, BODY_MAX)
        return JSONResponse({"ok": False, "error": "payload too large"},
                            status_code=413)
    fields = _parse_form(body)
    json_payload = fields.get("json", "")
    raw = fields.get("raw", "")

    # 3) 內容檢核(格式 + 規模),任何一項不過就是 400,絕不讓例外變成 500
    if len(json_payload) > JSON_MAX:
        logger.warning("主機 %s 回報 json 長度 %s 超過上限 %s",
                       name, len(json_payload), JSON_MAX)
        return JSONResponse({"ok": False, "error": "json too large"},
                            status_code=400)
    try:
        data = _json.loads(json_payload)
    except Exception:  # noqa: BLE001
        logger.warning("主機 %s 回報格式錯誤(json 無法解析)", name)
        return JSONResponse({"ok": False, "error": "bad json"},
                            status_code=400)
    if not isinstance(data, dict) or not isinstance(data.get("items"), list):
        logger.warning("主機 %s 回報格式錯誤(缺 items 陣列)", name)
        return JSONResponse({"ok": False, "error": "bad json"},
                            status_code=400)
    items = data["items"]
    if len(items) > ITEMS_MAX:
        logger.warning("主機 %s 回報檢查項 %s 筆超過上限 %s",
                       name, len(items), ITEMS_MAX)
        return JSONResponse({"ok": False, "error": "too many items"},
                            status_code=400)
    if not all(isinstance(it, dict) for it in items):
        logger.warning("主機 %s 回報格式錯誤(items 內含非物件元素)", name)
        return JSONResponse({"ok": False, "error": "bad items"},
                            status_code=400)

    # 4) 入庫(同步 SQLite,丟到工作執行緒避免卡住整個 event loop)
    result = await asyncio.to_thread(_store_report, info["id"], data, raw)
    if result is None:
        return JSONResponse({"ok": False, "error": "server error"},
                            status_code=500)
    return {"ok": True, **result}


# ──────────────────────────────────────────────────────────────────
# 一鍵安裝腳本模板(__XXX__ 佔位由 /install 端點代換)
# ──────────────────────────────────────────────────────────────────
_INSTALLER_TEMPLATE = r"""#!/bin/bash
#===============================================================================
# BaselineGuard Agent 一鍵安裝(由伺服器產生;請以 root 執行)
# 安裝內容:/opt/ucc/(agent.conf、ucc_agent.sh、ucc_check.sh)
#   systemd:ucc-check.service + ucc-check.timer(每日 __CHECK_TIME__,隨機延遲 ≤30 分)
# 移除方式:systemctl disable --now ucc-check.timer && rm -rf /opt/ucc \
#          /etc/systemd/system/ucc-check.{service,timer} && systemctl daemon-reload
#===============================================================================
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "請以 root 執行(curl ... | sudo bash)"; exit 1; }
command -v curl >/dev/null || { echo "需要 curl(apt install curl / dnf install curl)"; exit 1; }
command -v openssl >/dev/null || { echo "需要 openssl 驗證檢查腳本簽章(apt install openssl / dnf install openssl)"; exit 1; }

mkdir -p /opt/ucc
cat > /opt/ucc/agent.conf <<'CONF'
SERVER_URL="__SERVER_URL__"
TOKEN="__TOKEN__"
SLOW=__SLOW__
CONF
chmod 600 /opt/ucc/agent.conf

cat > /opt/ucc/ucc_agent.sh <<'WRAP'
#!/bin/bash
# BaselineGuard Agent:更新檢查腳本 → 執行唯讀檢查 → 回報結果
set -u
. /opt/ucc/agent.conf
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
# 每次執行先向伺服器取最新檢查腳本(失敗沿用本機既有版本)。
# 傳輸為純 HTTP,故務必驗證伺服器附的 HMAC 簽章(金鑰=本機 TOKEN):
# 驗不過代表內容遭竄改或非本伺服器所發,一律拒絕更新 —— 這支腳本是以
# root 執行的,寧可沿用舊版也不能執行未驗證的內容。
if curl -fsSk -D "$TMP/hdr.txt" -H "X-UCC-Token: $TOKEN" \
     -o "$TMP/ucc_check.sh" "$SERVER_URL/script"; then
  SIG=$(tr -d '\r' < "$TMP/hdr.txt" \
        | awk 'tolower($1)=="x-ucc-sig:"{print $2}' | tail -1)
  CALC=$(openssl dgst -sha256 -hmac "$TOKEN" "$TMP/ucc_check.sh" 2>/dev/null \
         | awk '{print $NF}')
  if [[ -n "$SIG" && -n "$CALC" && "$SIG" == "$CALC" ]]; then
    mv "$TMP/ucc_check.sh" /opt/ucc/ucc_check.sh
  else
    echo "檢查腳本簽章驗證失敗,拒絕更新(沿用本機既有版本)" >&2
  fi
fi
[[ -f /opt/ucc/ucc_check.sh ]] || { echo "無檢查腳本可執行"; exit 1; }
SLOW="${SLOW:-0}" UCC_JSON_OUT="$TMP/result.json" NO_COLOR=1 \
  bash /opt/ucc/ucc_check.sh > "$TMP/output.txt" 2>&1 || true
[[ -s "$TMP/result.json" ]] || { echo "檢查未產生結果:"; tail -20 "$TMP/output.txt"; exit 1; }
curl -fsSk -X POST -H "X-UCC-Token: $TOKEN" \
  --data-urlencode "json@$TMP/result.json" \
  --data-urlencode "raw@$TMP/output.txt" \
  "$SERVER_URL/report" && echo "" && echo "回報完成"
WRAP
chmod 700 /opt/ucc/ucc_agent.sh

cat > /etc/systemd/system/ucc-check.service <<'UNIT'
[Unit]
Description=BaselineGuard GCB/CIS daily compliance check
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/opt/ucc/ucc_agent.sh
UNIT

cat > /etc/systemd/system/ucc-check.timer <<'UNIT'
[Unit]
Description=BaselineGuard daily check timer

[Timer]
OnCalendar=*-*-* __CHECK_TIME__:00
RandomizedDelaySec=1800
Persistent=true

[Install]
WantedBy=timers.target
UNIT

systemctl daemon-reload
systemctl enable --now ucc-check.timer
echo "安裝完成(排程:每日 __CHECK_TIME__ ±30 分);立即執行第一次檢查..."
/opt/ucc/ucc_agent.sh
"""
