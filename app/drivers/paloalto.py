"""Palo Alto PAN-OS 組態強化檢查 driver v1.0(唯讀,XML API)。

依據:CIS Palo Alto Firewall 11 Benchmark v1.2.0(2025-10-03;條次與門檻
已逐條核對原文,比對紀錄見 sample/cis-compare-paloalto.md)、DISA Palo Alto
NDM STIG 交叉參照。範圍:僅系統管理面強化;security policy / 解密 / zone
等內容類不納入(屬政策管理平台職責)。CIS 無對應條目的 4 項(hostname/timezone/
superuser/admin-default)標「平台自訂」。

連線:XML API,`X-PAN-KEY` header;
GET /api/?type=config&action=get&xpath=... 取候選組態(running config 的
mgt 區段)。設備連線設定存 Host:ip_address、ssh_port(管理埠,443 省略)、
api_key(PAN-OS API key)。舊 appliance 憑證走 base.ssl_verify 放寬。

v1.0.1 修正:
- idle-timeout / admin-lockout / 密碼最小長度改用 base.to_int 安全轉換,
  欄位為非數字時不再讓整輪 inspect 以 ValueError 中斷(改標「人工」)。
- 各端點失敗時補齊該區段全部檢查項為「人工」(原本只補 1 項,其餘會整項
  消失,造成計數縮水與平台端假異動)。
- pan-ntp-auth 在「NTP 未設定」時改標「不適用」而非整項消失,維持項目數穩定。
- base URL 與逾時改用 base.device_base_url / base.API_TIMEOUT 統一。

v1.1.0(2026-08-24,依 CIS PAN-OS 11 v1.2.0 原文逐條對齊):
- pan-idle-timeout:0(永不登出)不再判符合(CIS 1.4.1:0 < t ≤ 10);
  元素未設改判不符(PAN-OS 生效預設 60 分 > 10,官方 Web Help 查證)。
- pan-snmp-v2c:access-setting 未設不再判符合——PAN-OS SNMP 版本預設即 V2c
  (官方 Web Help 查證),改標人工請確認 SNMP 服務是否啟用。
- pan-permitted-ip:含 0.0.0.0/0 或 ::/0 視同未限制(CIS 1.2.1)。
- pan-lockout:failed-attempts=0(不限次數)改判不符;補顯示 lockout-time
  (=0 時 PAN-OS 語意為鎖到人工解鎖,列注意)。CIS 1.4.2 稽核位置為
  Authentication Profile,平台讀 Authentication Settings 作全域下限,
  desc 註明差異。
- pan-ntp:CIS 1.6.2 要求主+次雙 NTP,僅設 primary 列注意;
  pan-ntp-auth 同時查 secondary,MD5 對稱金鑰列注意(CIS 僅建議 SHA1)。
- pan-log-forward:改同時掃 deviceconfig 與 shared 兩處 log-settings 的
  syslog/send-syslog;未設改判不符(CIS 1.1.1.1 為 L1 Automated,
  無 Panorama 替代條款)。
- 新增 9 項:pan-pwd-uppercase/lowercase/numeric/special(1.3.3–1.3.6)、
  pan-pwd-expiry(1.3.7)、pan-pwd-differs(1.3.8)、pan-pwd-history(1.3.9)、
  pan-pwd-profiles(1.3.10)、pan-log-high-dp(1.1.3)。
- os 欄位改帶 show system info 的 sw-version(best-effort)。
註:password-complexity 子欄位與 shared log-settings 元素名依 PAN-OS 組態
結構實作,尚未真機核對,請跑一次立即檢查確認。
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

import httpx

from app.drivers.base import API_TIMEOUT, device_base_url, ssl_verify, to_int

DRIVER_VERSION = "pan-1.1.0"
TIMEOUT = API_TIMEOUT

_DEV = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig"
_XPATHS = {
    "system": f"{_DEV}/system",
    "setting": f"{_DEV}/setting",
    "users": "/config/mgt-config/users",
    "pwd_complexity": "/config/mgt-config/password-complexity",
    "snmp": f"{_DEV}/system/snmp-setting",
    "log_settings": f"{_DEV}/log-settings",
    "log_shared": "/config/shared/log-settings",
    "pwd_profiles": "/config/mgt-config/password-profiles",
}

# 未設定的節點 xpath get 會回 success + 空 result,不會落到 errors;
# 只有連線/權限問題才會進 miss_group。

# 各 xpath 端點涵蓋的檢查項——端點失敗時必須全部補「人工」,
# 否則這些項目會整項消失(計數縮水、平台端誤記為異動)。
_GROUP_IDS = {
    "system": ("pan-hostname", "pan-timezone", "pan-login-banner",
               "pan-permitted-ip", "pan-disable-telnet", "pan-disable-http",
               "pan-ntp", "pan-ntp-auth", "pan-update-verify"),
    "setting": ("pan-idle-timeout", "pan-lockout", "pan-log-high-dp"),
    "pwd_complexity": ("pan-pwd-complexity", "pan-pwd-minlen",
                       "pan-pwd-uppercase", "pan-pwd-lowercase",
                       "pan-pwd-numeric", "pan-pwd-special",
                       "pan-pwd-expiry", "pan-pwd-differs",
                       "pan-pwd-history"),
    "users": ("pan-superuser", "pan-admin-default"),
    "snmp": ("pan-snmp-v2c",),
    "log_settings": ("pan-log-forward",),
    "pwd_profiles": ("pan-pwd-profiles",),
}


def _base(host) -> str:
    return device_base_url(host, default_port=443)


def _client(host) -> httpx.Client:
    return httpx.Client(headers={"X-PAN-KEY": host.api_key},
                        verify=ssl_verify(False), timeout=TIMEOUT)


def _get(client: httpx.Client, base: str, xpath: str) -> ET.Element:
    """type=config&action=get 取 xpath;回 <result> 元素。錯誤拋 RuntimeError。"""
    r = client.get(f"{base}/api/", params={
        "type": "config", "action": "get", "xpath": xpath})
    if r.status_code == 403:
        raise RuntimeError(
            "403 Forbidden——API key 失效,或管理帳號無讀取權/來源 IP 不在允許清單")
    if r.status_code != 200:
        raise RuntimeError(f"HTTP {r.status_code}")
    try:
        root = ET.fromstring(r.text)
    except ET.ParseError as exc:
        raise RuntimeError(f"回應非 XML:{exc}")
    if root.get("status") != "success":
        msg = root.findtext(".//msg") or r.text[:160]
        raise RuntimeError(f"PAN-OS API 非 success:{msg}")
    return root.find("result")


def test(host) -> tuple[bool, str]:
    """測試連線與 API key(讀 system,取 hostname)。"""
    try:
        with _client(host) as c:
            result = _get(c, _base(host), _XPATHS["system"])
        hn = result.findtext(".//hostname", "?") if result is not None else "?"
        return True, f"連線成功:PAN-OS 管理面可讀(hostname {hn})"
    except RuntimeError as exc:
        return False, f"PAN-OS API 失敗:{exc}"
    except httpx.HTTPError as exc:
        return False, f"連線失敗:{type(exc).__name__}: {exc}"


def inspect(host) -> tuple[str, dict]:
    """執行唯讀檢查;回 (人類可讀報告, 結果 dict)。連線層錯誤拋 RuntimeError。"""
    base = _base(host)
    data: dict[str, ET.Element] = {}
    errors: dict[str, str] = {}
    with _client(host) as c:
        for key, xp in _XPATHS.items():
            try:
                data[key] = _get(c, base, xp)
            except RuntimeError as exc:
                errors[key] = str(exc)
            except httpx.HTTPError as exc:
                raise RuntimeError(f"連線失敗:{type(exc).__name__}: {exc}")
    if not data:
        raise RuntimeError("所有 API 端點皆無法讀取:" +
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

    def miss_group(cat, name, key):
        """端點失敗時,把該端點涵蓋的所有檢查項一次補「人工」。"""
        for iid in _GROUP_IDS[key]:
            miss(iid, cat, name, key)

    sysr = data.get("system")
    setr = data.get("setting")

    # ===== 1. 系統管理強化 =====
    CAT = "1. 系統管理強化"
    sect(CAT)
    if sysr is None:
        miss_group(CAT, "system 各項", "system")
    else:
        def st(path, default=None):
            return sysr.findtext(path, default)

        hn = st(".//hostname", "")
        add("pan-hostname", CAT, "pass" if hn else "fail",
            f"主機名稱 hostname={hn or '未設'}(平台自訂;CIS v1.2.0 無此項)")
        tz = st(".//timezone", "")
        add("pan-timezone", CAT, "pass" if tz else "fail",
            f"時區已設定 timezone={tz or '未設'}(平台自訂;CIS v1.2.0 無此項)")
        # 注意:xpath get 的 <result> 包一層 <system>,故一律用 .// 後代選取,
        # 不用 ./(會少一層而誤判未設 → 危險的假不符)
        banner = st(".//login-banner", "")
        add("pan-login-banner", CAT, "pass" if banner else "fail",
            f"登入警語 login-banner {'已設定' if banner else '未設'}(CIS 1.1.2)")
        pip = sysr.find(".//permitted-ip")
        pip_names = ([e.get("name", "") for e in pip.findall("./entry")]
                     if pip is not None else [])
        pip_any = {"0.0.0.0/0", "::/0"} & set(pip_names)
        if not pip_names:
            add("pan-permitted-ip", CAT, "fail",
                "管理介面未限制來源 IP(permitted-ip 未設;CIS 1.2.1)")
        elif pip_any:
            add("pan-permitted-ip", CAT, "fail",
                f"permitted-ip 含 {'、'.join(sorted(pip_any))},等同未限制"
                "(CIS 1.2.1)")
        else:
            add("pan-permitted-ip", CAT, "pass",
                f"管理介面已限制來源 IP({len(pip_names)} 筆;CIS 1.2.1 為 "
                "Manual 項,清單合理性請人工複核)")
        telnet = st(".//service/disable-telnet")
        add("pan-disable-telnet", CAT,
            "pass" if telnet == "yes" else "fail",
            f"Telnet 管理停用 disable-telnet={telnet or '未設'}(CIS 1.2.3)")
        http = st(".//service/disable-http")
        add("pan-disable-http", CAT, "pass" if http == "yes" else "fail",
            f"HTTP 明文管理停用 disable-http={http or '未設'}(CIS 1.2.3)")
        # NTP:CIS 1.6.2 要求主+次雙台(冗餘);認證屬 Rationale 建議
        ntp_p = st(".//primary-ntp-server/ntp-server-address", "")
        ntp_s = st(".//secondary-ntp-server/ntp-server-address", "")
        if ntp_p and ntp_s:
            add("pan-ntp", CAT, "pass",
                f"NTP 已設定 primary {ntp_p}、secondary {ntp_s}(CIS 1.6.2)")
        elif ntp_p:
            add("pan-ntp", CAT, "warn",
                f"NTP 僅設 primary {ntp_p},未設 secondary"
                "(CIS 1.6.2 要求冗餘雙台;列注意)")
        else:
            add("pan-ntp", CAT, "fail", "NTP 伺服器未設定(CIS 1.6.2)")
        if ntp_p:
            weak_auth = []
            for tag, name in (("primary-ntp-server", "primary"),
                              ("secondary-ntp-server", "secondary")):
                if not st(f".//{tag}/ntp-server-address", ""):
                    continue
                if sysr.find(f".//{tag}/authentication-type/none") is not None:
                    weak_auth.append(f"{name}=none")
                elif sysr.find(
                        f".//{tag}/authentication-type/symmetric-key/"
                        "algorithm/md5") is not None:
                    weak_auth.append(f"{name}=MD5(已被攻破)")
            add("pan-ntp-auth", CAT, "warn" if weak_auth else "pass",
                f"NTP 認證不足:{'、'.join(weak_auth)}"
                "(CIS 1.6.2 Rationale 僅建議 SHA1)" if weak_auth
                else "NTP 已啟用認證(非 none/MD5)")
        else:
            # NTP 未設定時認證項無標的;標「不適用」而非略過,避免項目消失
            add("pan-ntp-auth", CAT, "na",
                "NTP 伺服器未設定,NTP 認證不適用(先修正 pan-ntp)")
        upd_verify = st(".//server-verification")
        add("pan-update-verify", CAT,
            "pass" if upd_verify == "yes" else "fail",
            f"更新伺服器憑證驗證 server-verification={upd_verify or '未設'}"
            "(CIS 1.6.1)")

    if setr is None:
        miss_group(CAT, "management setting 各項", "setting")
    else:
        to_raw = setr.findtext(".//management/idle-timeout")
        to = to_int(to_raw)
        if to_raw is None:
            # PAN-OS 生效預設 60 分(> 10),未明確設定即不符(CIS 1.4.1)
            add("pan-idle-timeout", CAT, "fail",
                "閒置逾時 idle-timeout 未設定——PAN-OS 預設 60 分 > 10"
                "(CIS 1.4.1)")
        elif to is None:
            add("pan-idle-timeout", CAT, "manual",
                f"閒置逾時 idle-timeout={to_raw!r} 非數值,無法判定")
        elif to == 0:
            add("pan-idle-timeout", CAT, "fail",
                "閒置逾時 idle-timeout=0(永不自動登出;CIS 1.4.1:須 ≤10)")
        else:
            add("pan-idle-timeout", CAT, "pass" if to <= 10 else "fail",
                f"管理閒置逾時 idle-timeout={to} 分(CIS 1.4.1:≤10)")
        fa_raw = setr.findtext(".//management/admin-lockout/failed-attempts")
        lt_raw = setr.findtext(".//management/admin-lockout/lockout-time")
        fa, lt = to_int(fa_raw), to_int(lt_raw)
        # CIS 1.4.2 的稽核位置是 Authentication Profile;平台讀
        # Authentication Settings 作全域下限(profile 未套用帳號時的保底)。
        if fa_raw is None:
            add("pan-lockout", CAT, "fail",
                "登入失敗鎖定未設定(admin-lockout;PAN-OS 預設 0=不限次數;"
                "CIS 1.4.2 要求兩值皆非零)")
        elif fa is None:
            # 欄位存在但非數字(版本差異):不猜測,標人工
            add("pan-lockout", CAT, "manual",
                f"登入失敗鎖定 failed-attempts={fa_raw!r} 非數值,無法判定")
        elif fa == 0:
            add("pan-lockout", CAT, "fail",
                "failed-attempts=0(不限失敗次數;CIS 1.4.2 要求非零)")
        elif lt is not None and lt == 0:
            add("pan-lockout", CAT, "warn",
                f"failed-attempts={fa},lockout-time=0(PAN-OS 語意為鎖到"
                "人工解鎖,較 CIS 1.4.2 的非零自動解鎖更嚴;列注意)")
        else:
            add("pan-lockout", CAT, "pass",
                f"登入失敗鎖定 failed-attempts={fa}、lockout-time="
                f"{lt if lt is not None else '未設'}(CIS 1.4.2;"
                "全域 Authentication Settings 層)")

        dp = setr.findtext(".//management/enable-log-high-dp-load")
        add("pan-log-high-dp", CAT, "pass" if dp == "yes" else "fail",
            f"高資料面負載記錄 enable-log-high-dp-load={dp or '未設'}"
            "(CIS 1.1.3 要求啟用;PAN-OS 預設停用)")

    # ===== 2. 密碼原則 =====
    CAT = "2. 密碼原則"
    sect(CAT)
    pwd = data.get("pwd_complexity")
    if pwd is None:
        miss_group(CAT, "密碼複雜度", "pwd_complexity")
    else:
        enabled = pwd.findtext(".//enabled")
        ml_raw = pwd.findtext(".//minimum-length")
        ml = to_int(ml_raw)
        if enabled != "yes":
            add("pan-pwd-complexity", CAT, "fail",
                "密碼複雜度未啟用(password-complexity;CIS 管理面)")
            add("pan-pwd-minlen", CAT, "fail",
                "密碼最小長度未設(密碼複雜度未啟用)")
        else:
            add("pan-pwd-complexity", CAT, "pass",
                "密碼複雜度已啟用(CIS 1.3.1)")
            if ml_raw is not None and ml is None:
                add("pan-pwd-minlen", CAT, "manual",
                    f"密碼最小長度 minimum-length={ml_raw!r} 非數值,無法判定")
            else:
                add("pan-pwd-minlen", CAT,
                    "pass" if ml is not None and ml >= 12 else "fail",
                    f"密碼最小長度 minimum-length={ml if ml is not None else '未設'}"
                    "(CIS 1.3.2:≥12)")

        # CIS 1.3.3–1.3.9:複雜度子門檻(元素缺 = 未設定 = 0,依 CIS 不符;
        # 複雜度整體未啟用時各子項不適用,先修 pan-pwd-complexity)。
        # ID 一律以字面值傳入 add(),供 verify_item_ids 靜態掃描。
        def _pwd_min(el: str, floor: int, cis: str, name: str):
            if enabled != "yes":
                return ("na", f"{name}:密碼複雜度未啟用,不適用"
                        "(先修 pan-pwd-complexity)")
            v = to_int(pwd.findtext(f".//{el}"))
            return ("pass" if v is not None and v >= floor else "fail",
                    f"{name} {el}={v if v is not None else '未設'}"
                    f"({cis}:≥{floor})")

        add("pan-pwd-uppercase", CAT, *_pwd_min(
            "minimum-uppercase-letters", 1, "CIS 1.3.3", "大寫字母下限"))
        add("pan-pwd-lowercase", CAT, *_pwd_min(
            "minimum-lowercase-letters", 1, "CIS 1.3.4", "小寫字母下限"))
        add("pan-pwd-numeric", CAT, *_pwd_min(
            "minimum-numeric-letters", 1, "CIS 1.3.5", "數字下限"))
        add("pan-pwd-special", CAT, *_pwd_min(
            "minimum-special-characters", 1, "CIS 1.3.6", "特殊字元下限"))
        add("pan-pwd-differs", CAT, *_pwd_min(
            "new-password-differs-by-characters", 3, "CIS 1.3.8",
            "新舊密碼相異字元數"))
        add("pan-pwd-history", CAT, *_pwd_min(
            "password-history-count", 24, "CIS 1.3.9", "密碼重用限制"))
        if enabled != "yes":
            add("pan-pwd-expiry", CAT, "na",
                "密碼有效期:密碼複雜度未啟用,不適用")
        else:
            exp = to_int(pwd.findtext(
                ".//password-change/expiration-period"))
            if exp is None or exp == 0:
                add("pan-pwd-expiry", CAT, "fail",
                    f"密碼有效期 expiration-period={exp if exp is not None else '未設'}"
                    "(0/未設=永不到期;CIS 1.3.7:1–90 天)")
            else:
                add("pan-pwd-expiry", CAT,
                    "pass" if exp <= 90 else "fail",
                    f"密碼有效期 expiration-period={exp} 天(CIS 1.3.7:≤90)")

    # 密碼 Profile 不得存在弱於全域的設定(CIS 1.3.10)
    prof = data.get("pwd_profiles")
    if prof is None:
        miss_group("2. 密碼原則", "密碼 Profile", "pwd_profiles")
    else:
        p_names = [e.get("name", "?") for e in prof.findall(".//entry")]
        add("pan-pwd-profiles", "2. 密碼原則",
            "warn" if p_names else "pass",
            f"存在密碼 Profile:{'、'.join(p_names)}——可能弱於全域原則,"
            "請人工比對(CIS 1.3.10 要求不存在)" if p_names
            else "無個別密碼 Profile(CIS 1.3.10)")

    # ===== 3. 帳號 =====
    CAT = "3. 管理帳號"
    sect(CAT)
    users = data.get("users")
    if users is None:
        miss_group(CAT, "管理帳號", "users")
    else:
        entries = users.findall(".//users/entry")
        supers = [e.get("name") for e in entries
                  if e.find(".//role-based/superuser") is not None
                  and (e.findtext(".//role-based/superuser") == "yes")]
        add("pan-superuser", CAT, "warn" if len(supers) > 2 else "pass",
            f"superuser 帳號 {len(supers)} 個(共 {len(entries)} 管理帳號)"
            + (f":{'、'.join(supers)};最小權限原則(平台自訂)"
               if len(supers) > 2 else ";最小權限原則(平台自訂)"))
        has_admin = any(e.get("name") == "admin" for e in entries)
        add("pan-admin-default", CAT, "manual" if has_admin else "pass",
            "存在預設 admin 帳號——請人工確認密碼已變更(API 無法驗證密碼)"
            if has_admin else "無預設 admin 帳號")

    # ===== 4. SNMP =====
    CAT = "4. SNMP"
    sect(CAT)
    snmp = data.get("snmp")
    if snmp is None:
        miss_group(CAT, "SNMP 設定", "snmp")
    else:
        has_v2c = snmp.find(".//access-setting/version/v2c") is not None
        has_v3 = snmp.find(".//access-setting/version/v3") is not None
        has_any = snmp.find(".//access-setting") is not None
        if not has_any:
            # PAN-OS SNMP 版本預設即 V2c(官方 Web Help):未設定 ≠ 未啟用,
            # 判「符合」會是假陰性;SNMP 服務本身是否監聽 API 讀不到 → 人工
            add("pan-snmp-v2c", CAT, "manual",
                "SNMP access-setting 未設定——PAN-OS 預設版本為 V2c,"
                "請人工確認 SNMP 服務未啟用或已改選 V3(CIS 1.5.1)")
        elif has_v2c:
            add("pan-snmp-v2c", CAT, "fail",
                "SNMP v2c community 啟用(CIS 1.5.1 要求僅 V3)")
        else:
            add("pan-snmp-v2c", CAT, "pass",
                f"SNMP 僅用 v3{'(已設定)' if has_v3 else ''}"
                "(無 v2c;CIS 1.5.1)")

    # ===== 5. 日誌 =====
    CAT = "5. 日誌"
    sect(CAT)
    logs = data.get("log_settings")
    logs_shared = data.get("log_shared")
    if logs is None and logs_shared is None:
        miss_group(CAT, "日誌設定", "log_settings")
    else:
        # syslog 轉送兩個可能位置:deviceconfig/log-settings(舊)與
        # shared/log-settings(profile + match-list 的 send-syslog)
        def _has_syslog(el):
            return el is not None and (
                el.find(".//send-syslog") is not None
                or el.find(".//syslog/entry") is not None
                or el.find(".//syslog") is not None)

        found = _has_syslog(logs) or _has_syslog(logs_shared)
        add("pan-log-forward", CAT, "pass" if found else "fail",
            "已設定 syslog 日誌轉送(CIS 1.1.1.1)" if found
            else "未設定 syslog 轉送(CIS 1.1.1.1 為 L1 必要項,無 Panorama"
                 " 替代條款;若確以 Panorama 集中請人工評估後停用本項)")

    # best-effort:op 指令取 sw-version / model(失敗不影響檢查)
    sw_ver, model = "", ""
    try:
        with _client(host) as c:
            r = c.get(f"{base}/api/", params={
                "type": "op",
                "cmd": "<show><system><info></info></system></show>"})
            if r.status_code == 200:
                op = ET.fromstring(r.text)
                if op.get("status") == "success":
                    sw_ver = op.findtext(".//sw-version", "") or ""
                    model = op.findtext(".//model", "") or ""
    except (httpx.HTTPError, ET.ParseError):
        pass

    hn_final = (sysr.findtext(".//hostname", host.name)
                if sysr is not None else host.name)
    raw = (f"PaloAlto PAN-OS 組態強化檢查(driver {DRIVER_VERSION},唯讀)\n"
           f"主機:{host.name}({host.ip_address})  hostname {hn_final}\n"
           + "\n".join(lines))
    if errors:
        raw += ("\n\n部分端點讀取失敗(相關項已標「人工」):\n  - "
                + "\n  - ".join(f"{k}: {v}" for k, v in errors.items()))

    result = {
        "script_version": DRIVER_VERSION,
        "family": "paloalto",
        "hostname": hn_final,
        "os": f"PAN-OS {sw_ver}".strip(),
        "kernel": model,
        "slow": False,
        "items": items,
    }
    return raw, result
