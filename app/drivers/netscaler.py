"""Citrix NetScaler / ADC 組態強化檢查 driver v1.0(唯讀,NITRO REST)。

依據:Citrix NetScaler Secure Deployment Guide(廠商官方強化指南,
docs.netscaler.com/en-us/netscaler-adc-secure-deployment.html)、
DISA 通用 NDM SRG 交叉參照。範圍:僅系統管理面強化;LB/CS vserver、
政策內容不納入。
註(2026-08-24 查證 cisecurity.org):CIS 並無 NetScaler / Citrix ADC
Benchmark(Network Devices 類別無 Citrix),先前標示的「CIS NetScaler
章級」不成立,出處已改為 Citrix SDG,判定邏輯不變。

連線:NITRO REST,
X-NITRO-USER / X-NITRO-PASS header;舊 appliance 憑證走 base.ssl_verify
(SECLEVEL=1,否則 SSL 握手失敗)。憑證用 Host.username / Host.password。

v1.0.1 修正:
- NITRO 對「零筆」集合回 200 + errorcode 0 但**省略資源鍵**,原本一律當成
  讀取失敗標「人工」,導致 ns-ntp 永遠不會判不符(沒設 NTP 的設備被藏成
  「人工」)、ns-snmp-community 永遠不會判符合。改為:集合型端點缺鍵且
  errorcode 正常時回空 list,讓「零筆」與「讀取失敗」可區分;單筆(dict)型
  端點(systemparameter/sslparameter)缺鍵仍視為異常,維持標「人工」。
- 集合回空但依常識不該為空者(nsip / systemuser)標「人工」而非判符合。
- timeout / minpasswordlen 改用 base.to_int;欄位缺失或非數值標「人工」。
- base URL 與逾時改用 base.device_base_url / base.API_TIMEOUT 統一。
"""
from __future__ import annotations

import httpx

from app.drivers.base import API_TIMEOUT, device_base_url, ssl_verify, to_int

DRIVER_VERSION = "ns-1.0.1"
TIMEOUT = API_TIMEOUT

_ENDPOINTS = {
    "systemparameter": "/nitro/v1/config/systemparameter",
    "nsip": "/nitro/v1/config/nsip",
    "ntpserver": "/nitro/v1/config/ntpserver",
    "snmpcommunity": "/nitro/v1/config/snmpcommunity",
    "auditsyslogaction": "/nitro/v1/config/auditsyslogaction",
    "sslparameter": "/nitro/v1/config/sslparameter",
    "systemuser": "/nitro/v1/config/systemuser",
}

# 集合型端點(NITRO 回 list;零筆時會直接省略資源鍵)
_LIST_ENDPOINTS = {"nsip", "ntpserver", "snmpcommunity", "auditsyslogaction",
                   "systemuser"}


def _base(host) -> str:
    return device_base_url(host, default_port=443)


def _client(host) -> httpx.Client:
    return httpx.Client(
        verify=ssl_verify(False), timeout=TIMEOUT,
        headers={"X-NITRO-USER": host.username,
                 "X-NITRO-PASS": host.password})


def _fetch(client: httpx.Client, base: str, path: str, key: str,
           as_list: bool = False):
    """GET 一個 NITRO 端點;回資源內容。錯誤拋 RuntimeError。

    NITRO 對「零筆」的集合會回 200 + errorcode 0 但**省略資源鍵**。
    若一律當成 None,呼叫端無從分辨「真的沒設定」與「讀不到」——前者會被
    藏成「人工」(合規檢查最危險的假陰性)。故集合型端點在回應正常時
    缺鍵一律回空 list;單筆(dict)型端點缺鍵才是真的異常,拋錯標人工。
    """
    r = client.get(base + path)
    if r.status_code == 401:
        raise RuntimeError("401 未授權——帳密錯誤或帳號被鎖")
    try:
        body = r.json()
    except ValueError:
        raise RuntimeError(f"HTTP {r.status_code}(回應非 JSON)")
    if r.status_code != 200:
        raise RuntimeError(f"HTTP {r.status_code}:{body.get('message', '')[:120]}")
    if not isinstance(body, dict):
        raise RuntimeError("回應格式非預期(非 JSON 物件)")
    if key in body:
        return body[key]
    err = body.get("errorcode")
    if as_list and err in (0, None):
        return []
    raise RuntimeError(
        f"回應缺 {key} 欄位(errorcode={err}、"
        f"message={str(body.get('message', ''))[:80]})")


def test(host) -> tuple[bool, str]:
    try:
        with _client(host) as c:
            _fetch(c, _base(host), "/nitro/v1/config/nsversion", "nsversion")
        return True, "連線成功:NITRO API 可讀"
    except RuntimeError as exc:
        return False, f"NetScaler NITRO 失敗:{exc}"
    except httpx.HTTPError as exc:
        return False, f"連線失敗:{type(exc).__name__}: {exc}"


def inspect(host) -> tuple[str, dict]:
    base = _base(host)
    data: dict = {}
    errors: dict[str, str] = {}
    with _client(host) as c:
        for key, path in _ENDPOINTS.items():
            try:
                data[key] = _fetch(c, base, path, key,
                                   as_list=key in _LIST_ENDPOINTS)
            except RuntimeError as exc:
                errors[key] = str(exc)
            except httpx.HTTPError as exc:
                raise RuntimeError(f"連線失敗:{type(exc).__name__}: {exc}")
    if not data:
        raise RuntimeError("所有 NITRO 端點皆無法讀取:" +
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
            f"{name}——端點讀取失敗,無法判定({errors.get(key, '未知')[:100]})")

    # ===== 1. 管理介面存取(NSIP)=====
    CAT = "1. 管理介面存取"
    sect(CAT)
    _NSIP_IDS = ("ns-nsip-telnet", "ns-nsip-ftp", "ns-nsip-gui",
                 "ns-nsip-restrict")
    nsips = data.get("nsip")
    if nsips is None:
        for i in _NSIP_IDS:
            miss(i, CAT, "NSIP 管理存取", "nsip")
    elif not nsips:
        # NetScaler 必有 NSIP;清單為空代表列舉不到(權限/分割),不可判符合
        for i in _NSIP_IDS:
            add(i, CAT, "manual",
                "NSIP 管理存取——未列出任何 IP(帳號權限或 partition 限制),無法判定")
    else:
        mgmt = [ip for ip in nsips if ip.get("type") == "NSIP"]
        tgt = mgmt or nsips
        telnet_on = [ip.get("ipaddress", "?") for ip in tgt
                     if ip.get("telnet") == "ENABLED"]
        ftp_on = [ip.get("ipaddress", "?") for ip in tgt
                  if ip.get("ftp") == "ENABLED"]
        gui_plain = [ip.get("ipaddress", "?") for ip in tgt
                     if ip.get("gui") == "ENABLED"]
        no_restrict = [ip.get("ipaddress", "?") for ip in tgt
                       if ip.get("restrictaccess") == "DISABLED"]
        add("ns-nsip-telnet", CAT, "fail" if telnet_on else "pass",
            f"NSIP Telnet 管理:{'開放 ' + '、'.join(telnet_on) if telnet_on else '已停用'}"
            "(應停用)")
        add("ns-nsip-ftp", CAT, "fail" if ftp_on else "pass",
            f"NSIP FTP 管理:{'開放 ' + '、'.join(ftp_on) if ftp_on else '已停用'}"
            "(應停用)")
        add("ns-nsip-gui", CAT, "fail" if gui_plain else "pass",
            f"NSIP GUI:{'明文 HTTP 開放 ' + '、'.join(gui_plain) if gui_plain else 'SECUREONLY 或停用'}"
            "(應 SECUREONLY)")
        add("ns-nsip-restrict", CAT, "fail" if no_restrict else "pass",
            f"NSIP restrictaccess:{'未限制 ' + '、'.join(no_restrict) if no_restrict else '已限制'}"
            "(建議 ENABLED,只允許啟用的管理服務)")

    # ===== 2. 系統參數 =====
    CAT = "2. 系統參數"
    sect(CAT)
    sp = data.get("systemparameter")
    if not isinstance(sp, dict):
        for i in ("ns-timeout", "ns-strong-password", "ns-min-password"):
            miss(i, CAT, "systemparameter", "systemparameter")
    else:
        to = to_int(sp.get("timeout"))
        if to is None:
            add("ns-timeout", CAT, "manual",
                f"CLI/GUI session timeout 未取得或非數值(={sp.get('timeout')!r})")
        else:
            add("ns-timeout", CAT, "pass" if 1 <= to <= 900 else "fail",
                f"管理 session 逾時 timeout={to} 秒(應設定且 ≤900)")
        if "strongpassword" not in sp:
            # fail-safe:欄位不存在不等於停用,也不等於已啟用
            add("ns-strong-password", CAT, "manual",
                "強密碼原則 strongpassword 欄位未取得,無法判定(應 enableall)")
        else:
            sp_strong = str(sp.get("strongpassword")).lower()
            add("ns-strong-password", CAT,
                "pass" if sp_strong != "disabled" else "fail",
                f"強密碼原則 strongpassword={sp.get('strongpassword')}"
                "(應 enableall)")
        ml = to_int(sp.get("minpasswordlen"))
        if ml is None:
            add("ns-min-password", CAT, "manual",
                "密碼最小長度 minpasswordlen 未取得或非數值"
                f"(={sp.get('minpasswordlen')!r};CIS/STIG:≥8)")
        else:
            add("ns-min-password", CAT, "pass" if ml >= 8 else "fail",
                f"密碼最小長度 minpasswordlen={ml}(CIS/STIG:≥8)")

    # ===== 3. SSL 管理 =====
    CAT = "3. SSL 管理"
    sect(CAT)
    ssl_p = data.get("sslparameter")
    if not isinstance(ssl_p, dict):
        miss("ns-ssl-reneg", CAT, "sslparameter", "sslparameter")
    else:
        reneg = str(ssl_p.get("denysslreneg", "NO")).upper()
        add("ns-ssl-reneg", CAT, "pass" if reneg not in ("NO", "FRONTEND_CLIENT") else "warn",
            f"SSL 重新協商 denysslreneg={ssl_p.get('denysslreneg')}"
            "(建議 NONSECURE 或 ALL)")

    # ===== 4. NTP =====
    CAT = "4. 時間同步"
    sect(CAT)
    ntp = data.get("ntpserver")
    if ntp is None:
        miss("ns-ntp", CAT, "NTP", "ntpserver")
    else:
        add("ns-ntp", CAT, "pass" if ntp else "fail",
            f"NTP 伺服器 {len(ntp)} 台" if ntp else "NTP 未設定(CIS/STIG)")

    # ===== 5. SNMP =====
    CAT = "5. SNMP"
    sect(CAT)
    comm = data.get("snmpcommunity")
    if comm is None:
        miss("ns-snmp-community", CAT, "SNMP community", "snmpcommunity")
    else:
        add("ns-snmp-community", CAT, "fail" if comm else "pass",
            f"SNMP v1/v2c community {len(comm)} 組(應停用改 v3)" if comm
            else "SNMP 無 v1/v2c community")

    # ===== 6. 日誌 =====
    CAT = "6. 日誌"
    sect(CAT)
    sl = data.get("auditsyslogaction")
    if sl is None:
        miss("ns-syslog", CAT, "syslog", "auditsyslogaction")
    else:
        add("ns-syslog", CAT, "pass" if sl else "warn",
            f"遠端 syslog action {len(sl)} 個已設定" if sl
            else "未設定遠端 syslog(CIS/STIG)")

    # ===== 7. 帳號 =====
    CAT = "7. 管理帳號"
    sect(CAT)
    users = data.get("systemuser")
    if users is None:
        miss("ns-default-nsroot", CAT, "systemuser", "systemuser")
    elif not users:
        # NetScaler 必有本機管理帳號;空清單代表列舉不到,不可判「無 nsroot」
        add("ns-default-nsroot", CAT, "manual",
            "未列出任何本機管理帳號(帳號權限限制),無法確認預設 nsroot 是否存在")
    else:
        names = [u.get("username") for u in users]
        has_nsroot = "nsroot" in names
        add("ns-default-nsroot", CAT, "manual" if has_nsroot else "pass",
            (f"存在預設 nsroot 帳號(共 {len(names)} 管理帳號)——請人工確認"
             "密碼已變更(API 無法驗證)") if has_nsroot
            else f"無預設 nsroot 帳號(共 {len(names)} 管理帳號)")

    raw = (f"Citrix NetScaler 組態強化檢查(driver {DRIVER_VERSION},唯讀)\n"
           f"主機:{host.name}({host.ip_address})\n" + "\n".join(lines))
    if errors:
        raw += ("\n\n部分端點讀取失敗(相關項已標「人工」):\n  - "
                + "\n  - ".join(f"{k}: {v}" for k, v in errors.items()))

    result = {
        "script_version": DRIVER_VERSION,
        "family": "netscaler",
        "hostname": host.name,
        "os": "Citrix NetScaler / ADC",
        "kernel": "",
        "slow": False,
        "items": items,
    }
    return raw, result
