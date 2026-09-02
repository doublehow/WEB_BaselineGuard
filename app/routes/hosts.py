"""主機管理:CRUD、測試連線、立即檢查、Agent token 產生。"""
from __future__ import annotations

import asyncio
import json
import secrets as _secrets

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.audit import audit
from app.auth import roles_of
from app.checker import run_ssh_check_bg, test_connection
from app.config import settings
from app.database import get_db
from app.devtypes import (
    CONN_LABEL, TYPE_LABEL, TYPE_SPEC, implemented_device_types, visible_device_types,
)
from app.models import CheckResult, CheckRun, Host, MODE_LABELS, ResultChange
from app.webutil import host_trends, render

router = APIRouter()


def _latest_run_map(db: Session, only_success: bool = False) -> dict[int, CheckRun]:
    """各主機最新一筆 CheckRun,一次查完(避免逐主機 N+1)。"""
    q = db.query(func.max(CheckRun.id)).group_by(CheckRun.host_id)
    if only_success:
        q = q.filter(CheckRun.status == "success")
    max_ids = [i for (i,) in q.all()]
    if not max_ids:
        return {}
    return {r.host_id: r for r in
            db.query(CheckRun).filter(CheckRun.id.in_(max_ids)).all()}


def _clamp_int(v, default: int, lo: int = 0, hi: int = 1_000_000) -> int:
    try:
        return min(hi, max(lo, int(str(v).strip())))
    except (TypeError, ValueError):
        return default


def _new_token() -> str:
    return _secrets.token_urlsafe(32)


# 刪除主機時 in_() 的分批大小(SQLite bind 變數上限:舊版 999 / 新版 32766)
_DELETE_BATCH = 500


@router.get("/hosts")
async def host_list(request: Request, db: Session = Depends(get_db),
                    error: str = ""):
    hosts = db.query(Host).order_by(Host.name).all()
    sparks, changes = host_trends(db)
    import json as _json
    return render(request, "hosts.html", "hosts",
                  hosts=hosts, error=error, mode_labels=MODE_LABELS,
                  device_types=visible_device_types(),
                  conn_label=CONN_LABEL,
                  type_spec_json=_json.dumps(TYPE_SPEC),
                  latest=_latest_run_map(db),
                  sparks=sparks, changes=changes)


@router.post("/hosts")
async def host_create(
    request: Request, db: Session = Depends(get_db),
    name: str = Form(...), mode: str = Form("ssh"), note: str = Form(""),
    device_type: str = Form("linux"),
    ip_address: str = Form(""), ssh_port: str = Form("22"),
    username: str = Form(""), password: str = Form(""),
    private_key: str = Form(""), sudo_password: str = Form(""),
    api_key: str = Form(""), api_verify_ssl: str = Form(""),
    interval_minutes: str = Form("1440"), slow_scan: str = Form(""),
):
    n = name.strip()
    if not n:
        return RedirectResponse("/hosts?error=主機名稱不可為空", status_code=303)
    if db.query(Host).filter(Host.name == n).first():
        return RedirectResponse(f"/hosts?error=主機名稱「{n}」已存在", status_code=303)
    if device_type != "linux":
        if device_type not in TYPE_LABEL:
            return RedirectResponse("/hosts?error=無效的設備類型", status_code=303)
        if device_type not in implemented_device_types():
            return RedirectResponse(
                f"/hosts?error={TYPE_LABEL[device_type]} 的檢查 driver 尚未實作(規劃中)",
                status_code=303)
        mode = "api"          # 網路設備一律伺服器連入 API
    elif mode not in ("agent", "ssh"):
        mode = "ssh"
    # SSH 憑證逐台獨立(無全域預設可後備),留空等同建了一台永遠連不上的主機
    if mode == "ssh":
        if not username.strip():
            return RedirectResponse(
                "/hosts?error=SSH 模式需填 SSH 帳號", status_code=303)
        if not (password or private_key.strip()):
            return RedirectResponse(
                "/hosts?error=SSH 模式需填 SSH 密碼或私鑰(擇一)", status_code=303)
    h = Host(
        name=n, mode=mode, device_type=device_type, note=note.strip(),
        ip_address=ip_address.strip(), ssh_port=_clamp_int(ssh_port, 22, 1, 65535),
        username=username.strip(), password=password,
        private_key=private_key.strip(), sudo_password=sudo_password,
        api_key=api_key.strip(), api_verify_ssl=bool(api_verify_ssl),
        interval_minutes=_clamp_int(interval_minutes, 1440, 0, 43200),
        slow_scan=bool(slow_scan),
        agent_token=_new_token() if mode == "agent" else "",
    )
    db.add(h)
    db.commit()
    audit(request, "host_create", f"新增主機:{n}({h.type_label}/{h.mode_label})")
    return RedirectResponse(f"/hosts/{h.id}", status_code=303)


@router.get("/hosts/{host_id}")
async def host_detail(request: Request, host_id: int,
                      db: Session = Depends(get_db), msg: str = ""):
    h = db.get(Host, host_id)
    if h is None:
        return RedirectResponse("/hosts", status_code=303)
    runs = (db.query(CheckRun).filter(CheckRun.host_id == host_id)
            .order_by(CheckRun.id.desc()).limit(50).all())
    from app.routes.logs_routes import fail_deltas
    fail_delta = fail_deltas(db, runs)

    # 與上一次成功檢查的差異(狀態變化的項目)
    ok_runs = [r for r in runs if r.status == "success"][:2]
    diff = []
    if len(ok_runs) == 2:
        cur, prev = ok_runs[0], ok_runs[1]
        cur_map = {r.item_id: r for r in db.query(CheckResult)
                   .filter(CheckResult.run_id == cur.id).all()}
        prev_map = {r.item_id: r for r in db.query(CheckResult)
                    .filter(CheckResult.run_id == prev.id).all()}
        for iid, r in cur_map.items():
            p = prev_map.get(iid)
            if p is None:
                diff.append({"item": r, "before": None})
            elif p.status != r.status:
                diff.append({"item": r, "before": p})

    # Agent 一鍵安裝指令(token 屬敏感資訊,模板僅對 can_write 顯示)
    # 位址指向獨立的 Agent API 埠(8074),非 Web UI 埠。
    # token 走 X-UCC-Token 標頭而非查詢字串:放 URL 會被伺服器 access log
    # 與管理者本機的 shell history 記下,取得者即可偽造該主機的合規回報。
    install_cmd = ""
    if h.mode == "agent" and h.agent_token:
        agent_base = (f"{request.url.scheme}://{request.url.hostname}"
                      f":{settings.agent_api_port}")
        install_cmd = (f'curl -fsSk -H "X-UCC-Token: {h.agent_token}" '
                       f'"{agent_base}/install" | sudo bash')

    return render(request, "host_detail.html", "hosts",
                  h=h, runs=runs, diff=diff, msg=msg,
                  install_cmd=install_cmd, fail_delta=fail_delta)


@router.get("/hosts/{host_id}/edit")
async def host_edit_page(request: Request, host_id: int,
                         db: Session = Depends(get_db), error: str = ""):
    # 編輯頁含連線設定等敏感內容,唯讀角色導回詳情頁
    if "full_admin" not in roles_of(request.session.get("user") or {}):
        return RedirectResponse(f"/hosts/{host_id}", status_code=303)
    h = db.get(Host, host_id)
    if h is None:
        return RedirectResponse("/hosts", status_code=303)
    # 該設備類型宣告的連線欄位(creds):api 模式編輯表單依此動態顯示,
    # 避免表單缺欄位而在儲存時清空既有值(帳密型設備都需要 username)
    creds = TYPE_SPEC.get(h.device_type, {}).get("creds", [])
    return render(request, "host_edit.html", "hosts", h=h, creds=creds,
                  error=error)


@router.post("/hosts/{host_id}/edit")
async def host_edit_save(
    request: Request, host_id: int, db: Session = Depends(get_db),
    name: str = Form(...), note: str = Form(""), enabled: str = Form(""),
    ip_address: str | None = Form(None), ssh_port: str | None = Form(None),
    username: str | None = Form(None), password: str | None = Form(None),
    private_key: str | None = Form(None), sudo_password: str | None = Form(None),
    api_key: str | None = Form(None),
    interval_minutes: str | None = Form(None), slow_scan: str = Form(""),
    clear_password: str = Form(""), clear_private_key: str = Form(""),
    clear_sudo_password: str = Form(""), clear_api_key: str = Form(""),
    clear_hostkey: str = Form(""),
    api_verify_ssl: str = Form(""), api_verify_ssl_present: str = Form(""),
):
    """儲存主機編輯。

    連線類欄位一律用 `Form(None)`,以區分兩種情況:
    - `None`(表單根本沒送此欄,例如該模式/類型不顯示)→ **保留既有值**;
    - `""`(表單有此欄但使用者刻意清空)→ 寫入空字串。
    如此不論哪種模式都不會因表單缺欄位而清空既有資料。
    憑證欄位語意:留空 = 不變更;勾選對應的「清除」核取方塊 = 移除已存值。
    """
    h = db.get(Host, host_id)
    if h is None:
        return RedirectResponse("/hosts", status_code=303)
    old_ip = (h.ip_address or "").strip()
    n = name.strip()
    if not n:
        return RedirectResponse(
            f"/hosts/{host_id}/edit?error=主機名稱不可為空", status_code=303)
    if db.query(Host).filter(Host.name == n, Host.id != host_id).first():
        return RedirectResponse(
            f"/hosts/{host_id}/edit?error=主機名稱「{n}」已存在", status_code=303)
    h.name = n
    h.note = note.strip()
    h.enabled = bool(enabled)
    h.slow_scan = bool(slow_scan)
    if ip_address is not None:
        h.ip_address = ip_address.strip()
    if ssh_port is not None:
        h.ssh_port = _clamp_int(ssh_port, h.ssh_port or 22, 1, 65535)
    if username is not None:
        h.username = username.strip()
    if interval_minutes is not None:
        cur_iv = h.interval_minutes if h.interval_minutes is not None else 1440
        h.interval_minutes = _clamp_int(interval_minutes, cur_iv, 0, 43200)
    # 憑證類欄位:未送出 = 不動;送出但留空 = 不變更(編輯頁不回填明碼);
    # 勾「清除」= 移除已存值(讓「只用私鑰、不留密碼」等設定可從 UI 完成)
    if clear_password:
        h.password = ""
    elif password and password.strip():
        h.password = password
    if clear_sudo_password:
        h.sudo_password = ""
    elif sudo_password and sudo_password.strip():
        h.sudo_password = sudo_password
    if clear_private_key:
        h.private_key = ""
    elif private_key and private_key.strip():
        h.private_key = private_key.strip()
    if clear_api_key:
        h.api_key = ""
    elif api_key and api_key.strip():
        h.api_key = api_key.strip()
    # SSH 憑證逐台獨立(無全域預設可後備):驗證「套用後」的結果,
    # 避免把一台原本連得上的主機清成永遠連不上(清除鈕誤勾最容易踩到)
    if h.mode == "ssh":
        if not (h.username or "").strip():
            db.rollback()
            return RedirectResponse(
                f"/hosts/{host_id}/edit?error=SSH 模式需填 SSH 帳號",
                status_code=303)
        if not (h.password or h.private_key):
            db.rollback()
            return RedirectResponse(
                f"/hosts/{host_id}/edit?error=SSH 模式需保留 SSH 密碼或私鑰(擇一),"
                "不可兩者皆清除", status_code=303)
    # TLS 驗證開關:checkbox 未勾不會出現在表單,需以 present 旗標區分
    # 「表單有此欄(設備編輯頁)」與「表單根本沒這欄(Linux 頁)」
    if api_verify_ssl_present:
        h.api_verify_ssl = bool(api_verify_ssl)
    # SSH 主機金鑰(TOFU)重置:手動勾清除,或 IP 變更視同新主機
    if clear_hostkey or (h.ip_address or "").strip() != old_ip:
        h.ssh_hostkey = ""
    cleared = [lb for flag, lb in ((clear_password, "密碼"),
                                  (clear_sudo_password, "sudo 密碼"),
                                  (clear_private_key, "私鑰"),
                                  (clear_api_key, "API Token"),
                                  (clear_hostkey, "SSH 主機金鑰")) if flag]
    db.commit()
    audit(request, "host_edit",
          f"編輯主機:{h.name}"
          + (f"(清除憑證:{'、'.join(cleared)})" if cleared else ""))
    return RedirectResponse(f"/hosts/{host_id}", status_code=303)


@router.post("/hosts/{host_id}/delete")
async def host_delete(request: Request, host_id: int,
                      db: Session = Depends(get_db)):
    h = db.get(Host, host_id)
    if h:
        # SQLite 未開 FK 強制 → 手動依序刪明細/主檔(避免 ORM 逐筆載入)。
        # in_() 每個 id 佔一個 bind 變數,SQLite 有上限(舊版 999 / 新版 32766),
        # 跑很久的主機一次全塞會炸 "too many SQL variables" → 分批處理。
        run_ids = [i for (i,) in db.query(CheckRun.id)
                   .filter(CheckRun.host_id == host_id).all()]
        for start in range(0, len(run_ids), _DELETE_BATCH):
            batch = run_ids[start:start + _DELETE_BATCH]
            # 順序固定:先刪 CheckResult 再刪 CheckRun(避免留下孤兒明細)
            db.query(CheckResult).filter(
                CheckResult.run_id.in_(batch)).delete(synchronize_session=False)
            db.query(CheckRun).filter(
                CheckRun.id.in_(batch)).delete(synchronize_session=False)
        db.query(ResultChange).filter(
            ResultChange.host_id == host_id).delete(synchronize_session=False)
        from app.models import ItemVersion
        db.query(ItemVersion).filter(
            ItemVersion.host_id == host_id).delete(synchronize_session=False)
        name = h.name
        db.delete(h)
        db.commit()
        audit(request, "host_delete", f"刪除主機:{name}(含 {len(run_ids)} 筆檢查紀錄)")
    return RedirectResponse("/hosts", status_code=303)


@router.post("/hosts/{host_id}/run")
async def host_run_now(request: Request, host_id: int,
                       db: Session = Depends(get_db), slow: str = Form("")):
    """手動立即檢查(SSH 連入 / 設備 API 兩種模式):背景執行,結果至檢查紀錄查看。

    Agent 模式由目標機自行回報,無法從伺服器觸發。
    """
    h = db.get(Host, host_id)
    if h is None:
        return RedirectResponse("/hosts", status_code=303)
    if h.mode == "agent":
        return RedirectResponse(
            f"/hosts/{host_id}?msg=Agent 模式由主機端定時回報,無法從伺服器觸發",
            status_code=303)
    # 防重入:已有執行中的檢查就不再開一條(避免使用者連點兩下開兩條)
    running = (db.query(CheckRun.id)
               .filter(CheckRun.host_id == host_id,
                       CheckRun.status == "running").first())
    if running is not None:
        return RedirectResponse(
            f"/hosts/{host_id}?msg=已有檢查在執行中,請待其完成後再觸發",
            status_code=303)
    run_ssh_check_bg(host_id, slow=bool(slow))
    audit(request, "host_run", f"手動檢查:{h.name}{'(含慢速掃描)' if slow else ''}")
    return RedirectResponse(
        f"/hosts/{host_id}?msg=檢查已在背景啟動,約 1~2 分鐘後重新整理查看結果",
        status_code=303)


@router.post("/hosts/{host_id}/token")
async def host_token_rotate(request: Request, host_id: int,
                            db: Session = Depends(get_db)):
    """重新產生 Agent token(舊 token 立即失效,需重新執行安裝指令)。"""
    h = db.get(Host, host_id)
    if h and h.mode == "agent":
        h.agent_token = _new_token()
        db.commit()
        audit(request, "host_token", f"重新產生 Agent token:{h.name}")
    return RedirectResponse(f"/hosts/{host_id}", status_code=303)


@router.post("/hosts/test-connection")
async def host_test_connection(request: Request, db: Session = Depends(get_db)):
    """AJAX:以表單目前填的值測試連線(SSH+sudo 或設備 API);憑證留空退回已存值。

    安全性:憑證欄位在 UI 看不到明碼,若允許「沿用已存憑證 + 任意目標 IP」,
    等於開了一條把解密後憑證送往外部主機的管道。因此只要實際沿用了該主機
    已存的任一憑證,目標位址就必須等於該主機自己已存的 ip_address;
    要測試其他位址請在表單填入完整憑證。每次測試都寫稽核紀錄。
    """
    try:
        data = json.loads(await request.body())
    except Exception:  # noqa: BLE001
        return {"ok": False, "message": "無效的請求格式"}
    if not isinstance(data, dict):
        return {"ok": False, "message": "無效的請求格式"}
    stored = None
    hid = data.get("host_id")
    if isinstance(hid, int) or (isinstance(hid, str) and hid.isdigit()):
        stored = db.get(Host, int(hid))

    in_password = data.get("password") or ""
    in_private_key = (data.get("private_key") or "").strip()
    in_sudo_password = data.get("sudo_password") or ""
    in_api_key = (data.get("api_key") or "").strip()
    tmp = Host(
        name="_test",
        device_type=(data.get("device_type") or "linux").strip() or "linux",
        ip_address=(data.get("ip_address") or "").strip(),
        ssh_port=_clamp_int(data.get("ssh_port"), 22, 1, 65535),
        username=(data.get("username") or "").strip(),
        password=in_password or (stored.password if stored else ""),
        private_key=in_private_key or (stored.private_key if stored else ""),
        sudo_password=in_sudo_password or (stored.sudo_password if stored else ""),
        api_key=in_api_key or (stored.api_key if stored else ""),
    )
    # 是否實際沿用了已存憑證(表單留空且該主機確實存有該憑證)
    used_stored = bool(stored) and bool(
        (not in_password and stored.password)
        or (not in_private_key and stored.private_key)
        or (not in_sudo_password and stored.sudo_password)
        or (not in_api_key and stored.api_key))
    if not tmp.ip_address:
        return {"ok": False, "message": "請先填 IP"}
    if used_stored and tmp.ip_address != (stored.ip_address or "").strip():
        audit(request, "host_test_conn_denied",
              f"拒絕測試連線:{stored.name} 的已存憑證被要求送往 {tmp.ip_address}"
              f"(該主機已存位址為 {stored.ip_address or '(未設定)'})")
        return {"ok": False,
                "message": "沿用已存憑證時,只能測試該主機已存的 IP;"
                           "要測試其他位址請在表單填入完整憑證後再測。"}
    # 網路設備:依該類型 creds 宣告檢查必填欄位(token 型 vs 帳密型)
    if tmp.device_type != "linux":
        spec = TYPE_SPEC.get(tmp.device_type, {})
        labels = {"username": "帳號", "password": "密碼", "api_key": "API Token"}
        missing = [labels[col] for col, _l, _p in spec.get("creds", [])
                   if not getattr(tmp, col, "")]
        if missing:
            return {"ok": False, "message": f"請先填 {'、'.join(missing)}"}
    ok, message = await asyncio.to_thread(test_connection, tmp)
    audit(request, "host_test_conn",
          f"測試連線:{TYPE_LABEL.get(tmp.device_type, 'Linux 主機')} "
          f"{tmp.ip_address}:{tmp.ssh_port}"
          f"({'沿用已存憑證' if used_stored else '表單填入憑證'}"
          f"{',主機 ' + stored.name if stored else ''})"
          f"→ {'成功' if ok else '失敗'}")
    return {"ok": ok, "message": message}
