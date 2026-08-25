"""NetApp ONTAP 組態強化檢查 driver v1.0(唯讀,REST API)。

依據:NetApp ONTAP 9 Security Hardening Guide(TR-4569)、DISA 通用
儲存/NDM SRG、CIS 通用原則(章級標示)。範圍:cluster 管理面強化
(NTP/SSH 演算法/SNMP/稽核/橫幅);SVM 資料服務、volume 不納入。

連線:REST,HTTP Basic(cluster 管理帳號);
憑證用 Host.username / Host.password。

v1.0.1 修正:
- /api/support/snmp/users 漏帶 fields:ONTAP REST 的集合 GET 預設只回 key
  欄位,authentication_method 恆為 None,導致所有 SNMP 使用者(含 v3 usm)
  都被當成 v1/v2c community,純 v3 的合規設備被誤判不符(假陽性)。
  改帶 ?fields=name,authentication_method,並在「所有記錄都缺該欄位」時
  標「人工」,避免日後欄位改名又造成誤判。
- SNMP 服務狀態改判「enabled 欄位是否存在」:欄位缺失時標「人工」,
  原本會因 falsy 而判成「SNMP 未啟用」→ 假陰性。
- base URL 與逾時改用 base.device_base_url / base.API_TIMEOUT 統一。
"""
from __future__ import annotations

import httpx

from app.drivers.base import API_TIMEOUT, device_base_url, ssl_verify

DRIVER_VERSION = "netapp-1.0.1"
TIMEOUT = API_TIMEOUT

_WEAK_CIPHER = ("cbc", "3des", "arcfour", "blowfish")
_WEAK_MAC = ("umac_64", "hmac_md5", "hmac_sha1", "_96")

_ENDPOINTS = {
    "cluster": "/api/cluster?fields=version,name,timezone",
    "ntp": "/api/cluster/ntp/servers",
    "snmp": "/api/support/snmp",
    # 集合 GET 預設只回 key 欄位,判 v1/v2c 需要 authentication_method,
    # 必須明列 fields(漏帶會讓 v3 使用者被當成 community)
    "snmp_users": "/api/support/snmp/users?fields=name,authentication_method",
    "ssh": "/api/security/ssh",
    "audit": "/api/security/audit",
    "audit_dest": "/api/security/audit/destinations",
    "login_msg": "/api/security/login/messages?fields=*",
    "accounts": "/api/security/accounts?fields=name,locked,scope",
}


def _base(host) -> str:
    return device_base_url(host, default_port=443)


def _client(host) -> httpx.Client:
    return httpx.Client(verify=ssl_verify(False), timeout=TIMEOUT,
                        auth=(host.username, host.password))


def _fetch(client, base, path):
    r = client.get(base + path)
    if r.status_code == 401:
        raise RuntimeError("401 未授權——帳密錯誤或帳號權限不足")
    try:
        body = r.json()
    except ValueError:
        raise RuntimeError(f"HTTP {r.status_code}(回應非 JSON)")
    if r.status_code != 200:
        msg = body.get("error", {}).get("message", "") if isinstance(body, dict) else ""
        raise RuntimeError(f"HTTP {r.status_code}:{msg[:100]}")
    return body


def test(host) -> tuple[bool, str]:
    try:
        with _client(host) as c:
            body = _fetch(c, _base(host), "/api/cluster?fields=version,name")
        ver = body.get("version", {}).get("full", "?")
        return True, f"連線成功:{body.get('name', '?')}({ver[:40]})"
    except RuntimeError as exc:
        return False, f"NetApp ONTAP API 失敗:{exc}"
    except httpx.HTTPError as exc:
        return False, f"連線失敗:{type(exc).__name__}: {exc}"


def inspect(host) -> tuple[str, dict]:
    base = _base(host)
    data: dict = {}
    errors: dict[str, str] = {}
    with _client(host) as c:
        for key, path in _ENDPOINTS.items():
            try:
                data[key] = _fetch(c, base, path)
            except RuntimeError as exc:
                errors[key] = str(exc)
            except httpx.HTTPError as exc:
                raise RuntimeError(f"連線失敗:{type(exc).__name__}: {exc}")
    if not data:
        raise RuntimeError("所有 ONTAP 端點皆無法讀取:" +
                           "; ".join(list(errors.values())[:2]))

    items: list[dict] = []
    lines: list[str] = []

    def add(iid, cat, status, desc):
        items.append({"id": iid, "cat": cat, "status": status, "desc": desc})
        mark = {"pass": "[符合]", "fail": "[不符]", "warn": "[注意]",
                "manual": "[人工]", "na": "[不適用]"}[status]
        lines.append(f"  {mark} {desc}")

    def sect(t):
        lines.append(f"\n━━━ {t} ━━━")

    def miss(iid, cat, name, key):
        add(iid, cat, "manual",
            f"{name}——端點讀取失敗,無法判定({errors.get(key, '未知')[:80]})")

    # ===== 1. 時間 =====
    CAT = "1. 時間"
    sect(CAT)
    ntp = data.get("ntp")
    if ntp is None:
        miss("netapp-ntp", CAT, "NTP", "ntp")
    else:
        recs = ntp.get("records", [])
        add("netapp-ntp", CAT, "pass" if recs else "fail",
            f"NTP 伺服器 {len(recs)} 台" if recs else "NTP 未設定(TR-4569)")
    cl = data.get("cluster")
    if cl is None:
        miss("netapp-timezone", CAT, "時區", "cluster")
    else:
        tz = (cl.get("timezone") or {}).get("name", "")
        add("netapp-timezone", CAT, "pass" if tz else "fail",
            f"時區 timezone={tz or '未設'}")

    # ===== 2. SSH 演算法 =====
    CAT = "2. SSH 演算法"
    sect(CAT)
    ssh = data.get("ssh")
    if ssh is None:
        miss("netapp-ssh-ciphers", CAT, "SSH", "ssh")
        miss("netapp-ssh-macs", CAT, "SSH", "ssh")
    else:
        ciphers = [str(x).lower() for x in ssh.get("ciphers", [])]
        weak_c = [c for c in ciphers if any(w in c for w in _WEAK_CIPHER)]
        add("netapp-ssh-ciphers", CAT, "fail" if weak_c else "pass",
            f"SSH 加密含弱演算法:{weak_c}(應移除 cbc/3des;TR-4569)" if weak_c
            else "SSH 加密無弱演算法")
        macs = [str(x).lower() for x in ssh.get("mac_algorithms", [])]
        weak_m = [m for m in macs if any(w in m for w in _WEAK_MAC)]
        add("netapp-ssh-macs", CAT, "fail" if weak_m else "pass",
            f"SSH MAC 含弱演算法:{weak_m}(應移除 umac-64/md5/sha1)" if weak_m
            else "SSH MAC 無弱演算法")

    # ===== 3. SNMP =====
    CAT = "3. SNMP"
    sect(CAT)
    snmp = data.get("snmp")
    users = data.get("snmp_users")
    if snmp is None:
        miss("netapp-snmp-v1v2c", CAT, "SNMP", "snmp")
    elif not isinstance(snmp, dict) or "enabled" not in snmp:
        # fail-safe:欄位不存在不等於「未啟用」
        add("netapp-snmp-v1v2c", CAT, "manual",
            "SNMP 服務狀態 enabled 欄位未取得,無法判定"
            "——請人工確認 v1/v2c community 已停用")
    elif not snmp.get("enabled"):
        add("netapp-snmp-v1v2c", CAT, "pass", "SNMP 未啟用(無 v1/v2c 暴露)")
    elif users is None:
        miss("netapp-snmp-v1v2c", CAT, "SNMP users", "snmp_users")
    else:
        # v3 使用者有 authentication_method(usm);community(v1/v2c)無。
        # 前提是查詢有帶 fields —— 若所有記錄都缺這個欄位,代表欄位未回傳
        # (漏帶 fields 或欄位改名),此時全部會被誤認成 community,不可判定
        recs = users.get("records", []) if isinstance(users, dict) else []
        if recs and all("authentication_method" not in u for u in recs):
            add("netapp-snmp-v1v2c", CAT, "manual",
                f"SNMP 使用者 {len(recs)} 筆皆未回傳 authentication_method 欄位"
                "(ONTAP 版本欄位差異),無法區分 v3 usm 與 v1/v2c community")
        else:
            comms = [u.get("name") for u in recs
                     if not u.get("authentication_method")]
            add("netapp-snmp-v1v2c", CAT, "fail" if comms else "pass",
                f"SNMP v1/v2c community {len(comms)} 組(應停用改 v3)" if comms
                else f"SNMP 僅 v3(共 {len(recs)} 使用者,無 v1/v2c community)")

    # ===== 4. 稽核 =====
    CAT = "4. 稽核與日誌"
    sect(CAT)
    audit = data.get("audit")
    if audit is None:
        miss("netapp-audit", CAT, "稽核", "audit")
    else:
        on = audit.get("cli") or audit.get("ontapi") or audit.get("http")
        add("netapp-audit", CAT, "pass" if on else "fail",
            f"管理稽核 cli={audit.get('cli')}、ontapi={audit.get('ontapi')}、"
            f"http={audit.get('http')}(TR-4569:應啟用命令稽核)")
    dest = data.get("audit_dest")
    if dest is None:
        miss("netapp-audit-dest", CAT, "稽核轉送", "audit_dest")
    else:
        n = dest.get("num_records", len(dest.get("records", [])))
        add("netapp-audit-dest", CAT, "pass" if n else "warn",
            f"稽核遠端轉送 {n} 台已設定" if n
            else "未設定稽核遠端轉送(建議集中收集)")

    # ===== 5. 橫幅與帳號 =====
    CAT = "5. 橫幅與帳號"
    sect(CAT)
    lm = data.get("login_msg")
    if lm is None:
        miss("netapp-banner", CAT, "登入橫幅", "login_msg")
    else:
        has_msg = any(r.get("message") or r.get("banner")
                      for r in lm.get("records", []))
        add("netapp-banner", CAT, "pass" if has_msg else "fail",
            "登入橫幅/訊息已設定" if has_msg
            else "未設定登入橫幅/訊息(TR-4569/SRG)")
    acc = data.get("accounts")
    if acc is None:
        miss("netapp-admin-default", CAT, "帳號", "accounts")
    else:
        names = [a.get("name") for a in acc.get("records", [])]
        has_admin = "admin" in names
        add("netapp-admin-default", CAT, "manual" if has_admin else "pass",
            (f"存在預設 admin 帳號(共 {len(names)} 帳號)——請人工確認密碼已變更"
             "、非必要應停用") if has_admin
            else f"無預設 admin 帳號(共 {len(names)} 帳號)")

    name = (cl or {}).get("name", host.name)
    ver = (cl or {}).get("version", {}).get("full", "")
    raw = (f"NetApp ONTAP 組態強化檢查(driver {DRIVER_VERSION},唯讀)\n"
           f"主機:{host.name}({host.ip_address})  cluster {name}\n"
           + "\n".join(lines))
    if errors:
        raw += ("\n\n部分端點讀取失敗(相關項已標「人工」):\n  - "
                + "\n  - ".join(f"{k}: {v}" for k, v in errors.items()))

    result = {
        "script_version": DRIVER_VERSION,
        "family": "netapp",
        "hostname": name,
        "os": ver.split(":")[0] if ver else "NetApp ONTAP",
        "kernel": "",
        "slow": False,
        "items": items,
    }
    return raw, result
