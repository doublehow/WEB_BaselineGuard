"""VMware vCenter(VCSA appliance)組態強化檢查 driver v1.0(唯讀,REST API)。

依據:DISA VMware vSphere 8.0 vCenter STIG / vCenter Server Appliance
Management(章級標示)。CIS VMware ESXi 8.0 Benchmark 明文排除 vCenter、
無 VCSA 條目,故不引用(見 sample/cis-compare-vcenter.md)。範圍:VCSA appliance
管理面強化(NTP/SSH/shell/日誌/本機帳號密碼原則);ESXi 主機、VM、
權限指派(ERS 已涵蓋)不納入。

連線(vSphere Automation REST API):
- POST /api/session(Basic auth)取 session token,後續帶
  `vmware-api-session-id` header;結束 DELETE /api/session 釋放。
- 憑證用 Host.username(如 administrator@vsphere.local)/ Host.password。

v1.0.1 修正:
- dcui 端點失敗時原本連「人工」都不補,vc-dcui 會整項消失;改為補 miss。
- r.json() 只包 httpx.HTTPError,回應非 JSON(例如被導到登入 HTML 頁)時會
  以裸 ValueError 逸出;改為捕捉並轉成 RuntimeError,訊息說明回應非 JSON。
- max_days / max_days_between_password_change 改用 base.to_int,並區分
  「欄位不存在」(API 形狀有變 → 人工)與「值為 null / -1」(未設過期 → 不符)。
- base URL 與逾時改用 base.device_base_url / base.API_TIMEOUT 統一。
"""
from __future__ import annotations

import httpx

from app.drivers.base import API_TIMEOUT, device_base_url, ssl_verify, to_int

DRIVER_VERSION = "vc-1.0.1"
TIMEOUT = API_TIMEOUT

_ENDPOINTS = {
    "ntp": "/api/appliance/ntp",
    "timesync": "/api/appliance/timesync",
    "ssh": "/api/appliance/access/ssh",
    "shell": "/api/appliance/access/shell",
    "dcui": "/api/appliance/access/dcui",
    "syslog": "/api/appliance/logging/forwarding",
    "global_policy": "/api/appliance/local-accounts/global-policy",
    "root": "/api/appliance/local-accounts/root",
    "version": "/api/appliance/system/version",
}


def _base(host) -> str:
    return device_base_url(host, default_port=443)


def _json(r: httpx.Response, what: str):
    """解析 JSON 回應;非 JSON(如被導向登入 HTML 頁)轉成 RuntimeError,
    不讓裸 ValueError 逸出到呼叫端。"""
    try:
        return r.json()
    except ValueError:
        raise RuntimeError(
            f"{what}:回應非 JSON(HTTP {r.status_code};"
            "可能被導向登入頁或前置代理攔截)")


def _session(client: httpx.Client, base: str, host) -> str:
    r = client.post(f"{base}/api/session",
                    auth=(host.username, host.password))
    if r.status_code in (200, 201):
        return _json(r, "取 session")
    if r.status_code == 401:
        raise RuntimeError("401 未授權——帳密錯誤(需 administrator@vsphere.local 等)")
    raise RuntimeError(f"取 session 失敗:HTTP {r.status_code}")


def test(host) -> tuple[bool, str]:
    try:
        with httpx.Client(verify=ssl_verify(bool(host.api_verify_ssl)), timeout=TIMEOUT) as c:
            base = _base(host)
            tok = _session(c, base, host)
            r = c.get(f"{base}/api/appliance/system/version",
                      headers={"vmware-api-session-id": tok})
            ver = "?"
            if r.status_code == 200:
                body = _json(r, "讀 system/version")
                ver = body.get("version", "?") if isinstance(body, dict) else "?"
            c.delete(f"{base}/api/session",
                     headers={"vmware-api-session-id": tok})
        return True, f"連線成功:vCenter {ver}"
    except RuntimeError as exc:
        return False, f"vCenter API 失敗:{exc}"
    except httpx.HTTPError as exc:
        return False, f"連線失敗:{type(exc).__name__}: {exc}"


def inspect(host) -> tuple[str, dict]:
    base = _base(host)
    data: dict = {}
    errors: dict[str, str] = {}
    with httpx.Client(verify=ssl_verify(bool(host.api_verify_ssl)), timeout=TIMEOUT) as c:
        tok = _session(c, base, host)
        h = {"vmware-api-session-id": tok}
        try:
            for key, path in _ENDPOINTS.items():
                try:
                    r = c.get(base + path, headers=h)
                    if r.status_code == 200:
                        data[key] = _json(r, path)
                    else:
                        errors[key] = f"HTTP {r.status_code}"
                except RuntimeError as exc:
                    # 單一端點回應非 JSON:記為該端點失敗,相關項標「人工」
                    errors[key] = str(exc)
                except httpx.HTTPError as exc:
                    raise RuntimeError(f"連線失敗:{type(exc).__name__}: {exc}")
        finally:
            try:
                c.delete(f"{base}/api/session", headers=h)
            except httpx.HTTPError:
                pass
    if not data:
        raise RuntimeError("所有 appliance 端點皆無法讀取:" +
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

    # ===== 1. 時間同步 =====
    CAT = "1. 時間同步"
    sect(CAT)
    ntp = data.get("ntp")
    if ntp is None:
        miss("vc-ntp", CAT, "NTP", "ntp")
    else:
        servers = ntp if isinstance(ntp, list) else []
        add("vc-ntp", CAT, "pass" if servers else "fail",
            f"NTP 伺服器={servers or '未設'}(STIG 要求時間同步)")
    ts = data.get("timesync")
    if ts is None:
        miss("vc-timesync", CAT, "timesync", "timesync")
    else:
        mode = ts if isinstance(ts, str) else ts.get("mode", "")
        add("vc-timesync", CAT, "pass" if str(mode).upper() == "NTP" else "fail",
            f"時間同步模式={mode}(STIG 要求 NTP,非 HOST/DISABLED)")

    # ===== 2. 管理存取 =====
    CAT = "2. 管理存取"
    sect(CAT)
    ssh = data.get("ssh")
    if ssh is None:
        miss("vc-ssh", CAT, "SSH 存取", "ssh")
    else:
        on = (str(ssh).lower() == "true") if isinstance(ssh, (str, bool)) \
            else bool(ssh.get("enabled"))
        add("vc-ssh", CAT, "fail" if on else "pass",
            f"SSH 存取={'啟用' if on else '停用'}(STIG:非必要應停用)")
    shell = data.get("shell")
    if shell is None:
        miss("vc-shell", CAT, "Bash shell", "shell")
    else:
        on = bool(shell.get("enabled")) if isinstance(shell, dict) \
            else str(shell).lower() == "true"
        add("vc-shell", CAT, "pass" if not on else "fail",
            f"Bash shell 存取={'啟用' if on else '停用'}(STIG:應停用)")
    dcui = data.get("dcui")
    if dcui is None:
        miss("vc-dcui", CAT, "DCUI 主控台存取", "dcui")
    else:
        on = (str(dcui).lower() == "true") if isinstance(dcui, (str, bool)) \
            else bool(dcui.get("enabled"))
        add("vc-dcui", CAT, "manual",
            f"DCUI 主控台存取={'啟用' if on else '停用'}——請依營運需要人工評估")

    # ===== 3. 日誌 =====
    CAT = "3. 日誌"
    sect(CAT)
    sl = data.get("syslog")
    if sl is None:
        miss("vc-syslog", CAT, "日誌轉送", "syslog")
    else:
        fwd = sl if isinstance(sl, list) else []
        add("vc-syslog", CAT, "pass" if fwd else "fail",
            f"日誌轉送 {len(fwd)} 台已設定" if fwd
            else "未設定遠端日誌轉送(STIG/CIS 要求集中日誌)")

    # ===== 4. 帳號密碼原則 =====
    CAT = "4. 帳號密碼原則"
    sect(CAT)
    gp = data.get("global_policy")
    if gp is None:
        miss("vc-pwd-maxage", CAT, "密碼原則", "global_policy")
    else:
        if not isinstance(gp, dict) or "max_days" not in gp:
            # 欄位不存在代表 API 形狀與預期不同,不可據此判定
            add("vc-pwd-maxage", CAT, "manual",
                "本機帳號密碼原則 max_days 欄位未取得,無法判定(STIG/CIS:≤90)")
        else:
            raw_maxd = gp.get("max_days")
            maxd = to_int(raw_maxd)
            if raw_maxd is None:
                add("vc-pwd-maxage", CAT, "fail",
                    "本機帳號密碼最長天數 max_days 未設定(等同永不過期;"
                    "STIG/CIS:≤90)")
            elif maxd is None:
                add("vc-pwd-maxage", CAT, "manual",
                    f"本機帳號密碼最長天數 max_days={raw_maxd!r} 非數值,無法判定")
            else:
                add("vc-pwd-maxage", CAT,
                    "pass" if 0 < maxd <= 90 else "fail",
                    f"本機帳號密碼最長天數 max_days={maxd}(STIG/CIS:≤90)")
    root = data.get("root")
    if root is None:
        miss("vc-root-expiry", CAT, "root 密碼過期", "root")
    else:
        key = "max_days_between_password_change"
        if not isinstance(root, dict) or key not in root:
            add("vc-root-expiry", CAT, "manual",
                f"root 帳號 {key} 欄位未取得,無法判定"
                "(STIG:root 密碼須設過期)")
        else:
            md = to_int(root.get(key))
            if md is None and root.get(key) is not None:
                add("vc-root-expiry", CAT, "manual",
                    f"root 密碼過期 {key}={root.get(key)!r} 非數值,無法判定")
            else:
                add("vc-root-expiry", CAT,
                    "pass" if md is not None and md > 0 else "fail",
                    f"root 密碼過期 {key}={root.get(key)}"
                    "(STIG:root 密碼須設過期,-1/未設=永不過期為不符)")

    ver = ""
    v = data.get("version")
    if isinstance(v, dict):
        ver = v.get("version", "")
    raw = (f"VMware vCenter(VCSA)組態強化檢查(driver {DRIVER_VERSION},唯讀)\n"
           f"主機:{host.name}({host.ip_address})  vCenter {ver}\n"
           + "\n".join(lines))
    if errors:
        raw += ("\n\n部分端點讀取失敗(相關項已標「人工」):\n  - "
                + "\n  - ".join(f"{k}: {v}" for k, v in errors.items()))

    result = {
        "script_version": DRIVER_VERSION,
        "family": "vcenter",
        "hostname": host.name,
        "os": f"vCenter {ver}".strip(),
        "kernel": "",
        "slow": False,
        "items": items,
    }
    return raw, result
