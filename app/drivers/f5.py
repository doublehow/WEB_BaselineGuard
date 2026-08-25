"""F5 BIG-IP 組態強化檢查 driver v1.0(唯讀,iControl REST)。

依據:DISA F5 BIG-IP TMOS Device Management (NDM) STIG V1R2(逐條見 sample/stig-compare-f5.md)、
CIS F5 Networks Benchmark v1.0.0(ARCHIVE,2021;條次已逐條核對原文,
比對紀錄見 sample/cis-compare-f5.md。該文件未宣告 TMOS 版本,推斷為
13.1–15.x 世代;其 4.5 SSH 演算法清單含 CBC/RC4 已過時,平台以現行
標準另定判準)。範圍:僅系統管理面強化;LTM/ASM 的 VS、policy、WAF
政策內容不納入。

連線:
- 先 POST /mgmt/shared/authn/login 取 X-F5-Auth-Token(loginProviderName=tmos),
  失敗退回 HTTP Basic;憑證用 Host.username / Host.password。
- 已知限制(TMOS 17.5 真機實測):/mgmt/tm/sys/snmp 對非 admin 角色回
  400 "unexpected argument"——SNMP 項自動降為「人工」,不誤判。

v1.0.1 修正:
- sslProtocol 為空(欄位未取得)時改標「人工」,原本會因 token 清單為空而
  推出「弱協定皆未啟用」→ 誤判符合(假陰性)。
- sslProtocol 的排除項(-TLSv1)改與正向項一致轉小寫比對;Apache SSLProtocol
  大小寫不敏感,原本大小寫不一致會把已排除的弱版本誤報為啟用(假陽性)。
- 各數值欄位改用 base.to_int;欄位缺失或非數值時標「人工」而非以 0 代入判不符。
- 各端點失敗時補齊該區段全部檢查項為「人工」(原本每個端點只補 1 項,
  其餘會整項消失,造成計數縮水與平台端假異動)。
- base URL 與逾時改用 base.device_base_url / base.API_TIMEOUT 統一。

v1.1.0(2026-08-24,依 CIS F5 v1.0.0 原文逐條對齊):
- 門檻收緊:console/SSH 閒置逾時 900→600 秒(CIS 4.4/4.2 標題 ≤10 分);
  GUI/SSH banner 補查警語文字非空(CIS 4.1 要求輸入文字);
  密碼最小長度 8→12(CIS 1.1.3);登入失敗鎖定 1–5→1–3(CIS 1.1.3);
  複雜度四類不足由「注意」改「不符」(CIS 要求四類皆 ≥1);
  NTP 改要求冗餘雙台(CIS 5.1),僅一台列注意。
- 假陰性修正:sslProtocol 的 +前綴 token 未剝除(+SSLv3 不會被認出);
  SNMP communities 改 expandSubcollections=true 讀取,鍵不存在時標人工
  (原本鍵缺失會得空清單而判符合)。
- 新增 8 項:f5-ssh-algos(CIS 4.5–4.7,以現行標準判弱演算法)、
  f5-tmsh-timeout(4.3)、f5-pwd-maxage / f5-pwd-memory / f5-pwd-warning
  (1.1.3 其餘子門檻)、f5-remote-role / f5-remote-partition /
  f5-remote-console(2.4–2.6,未用遠端認證時不適用)。
新增端點(cli/auth source/remote-user)未經真機驗證,請跑一次立即檢查。
"""
from __future__ import annotations

import re

import httpx

from app.drivers.base import API_TIMEOUT, device_base_url, ssl_verify, to_int

DRIVER_VERSION = "f5-1.1.0"
TIMEOUT = API_TIMEOUT

_ENDPOINTS = {
    "version": "/mgmt/tm/sys/version",
    "global_settings": "/mgmt/tm/sys/global-settings",
    "sshd": "/mgmt/tm/sys/sshd",
    "httpd": "/mgmt/tm/sys/httpd",
    "ntp": "/mgmt/tm/sys/ntp",
    "syslog": "/mgmt/tm/sys/syslog",
    "snmp": "/mgmt/tm/sys/snmp?expandSubcollections=true",
    "pwd_policy": "/mgmt/tm/auth/password-policy",
    "users": "/mgmt/tm/auth/user",
    "cli": "/mgmt/tm/cli/global-settings",
    "auth_source": "/mgmt/tm/auth/source",
    "remote_user": "/mgmt/tm/auth/remote-user",
}

# 各端點涵蓋的檢查項——端點失敗時必須全部補「人工」,
# 否則這些項目會整項消失(計數縮水、平台端誤記為異動)。
# 註:global_settings 另外涵蓋 f5-hostname,該項在「2. 系統設定」段
# 自行處理(段落不同,描述文字也不同),故不列在此。
_GROUP_IDS = {
    "global_settings": ("f5-gui-banner", "f5-console-timeout"),
    "sshd": ("f5-sshd-banner", "f5-sshd-timeout", "f5-sshd-allow",
             "f5-ssh-algos"),
    "httpd": ("f5-httpd-allow", "f5-gui-timeout", "f5-tls-version"),
    "ntp": ("f5-ntp", "f5-timezone"),
    "pwd_policy": ("f5-pwd-policy", "f5-pwd-minlen", "f5-pwd-complexity",
                   "f5-login-failures", "f5-pwd-maxage", "f5-pwd-memory",
                   "f5-pwd-warning"),
    "users": ("f5-admin-default",),
    "syslog": ("f5-syslog-remote",),
    "cli": ("f5-tmsh-timeout",),
    "remote_user": ("f5-remote-role", "f5-remote-partition",
                    "f5-remote-console"),
}

# sshd include 中不接受的弱演算法樣式(以現行標準;CIS v1.0.0 原文 4.5
# 建議清單含 CBC/RC4,已過時不採,改排除式判定)
_WEAK_SSH_RE = re.compile(
    r"arcfour\S*|\S*-cbc|3des\S*|blowfish\S*|hmac-md5\S*|"
    r"hmac-sha1-96|diffie-hellman-group1-sha1|diffie-hellman-group14-sha1",
    re.IGNORECASE)


def _base(host) -> str:
    return device_base_url(host, default_port=443)


def _client(host) -> httpx.Client:
    return httpx.Client(verify=ssl_verify(False), timeout=TIMEOUT,
                        auth=(host.username, host.password))


def _auth_headers(client: httpx.Client, base: str, host) -> dict:
    """取 X-F5-Auth-Token;失敗回空 dict(改用 Basic)。比照 ERS。"""
    try:
        r = client.post(f"{base}/mgmt/shared/authn/login",
                        json={"username": host.username,
                              "password": host.password,
                              "loginProviderName": "tmos"})
        if r.status_code == 200:
            tok = r.json().get("token", {}).get("token")
            if tok:
                return {"X-F5-Auth-Token": tok}
    except httpx.HTTPError:
        pass
    return {}


def _fetch(client: httpx.Client, base: str, path: str, headers: dict) -> dict:
    r = client.get(base + path, headers=headers)
    if r.status_code == 401:
        raise RuntimeError("401 未授權——帳密錯誤或帳號被鎖")
    try:
        body = r.json()
    except ValueError:
        raise RuntimeError(f"HTTP {r.status_code}(回應非 JSON)")
    if r.status_code != 200:
        raise RuntimeError(
            f"HTTP {r.status_code}:{body.get('message', '')[:120]}")
    return body


def test(host) -> tuple[bool, str]:
    """測試連線與帳密(讀 sys/version)。"""
    try:
        with _client(host) as c:
            base = _base(host)
            headers = _auth_headers(c, base, host)
            body = _fetch(c, base, _ENDPOINTS["version"], headers)
        ver = "?"
        try:
            ent = body["entries"]
            ver = next(iter(ent.values()))["nestedStats"]["entries"]["Version"]["description"]
        except Exception:  # noqa: BLE001 —— 版本解析失敗不影響連線判定
            pass
        mode = "token" if headers else "Basic"
        return True, f"連線成功:BIG-IP {ver}({mode} 認證)"
    except RuntimeError as exc:
        return False, f"F5 API 失敗:{exc}"
    except httpx.HTTPError as exc:
        return False, f"連線失敗:{type(exc).__name__}: {exc}"


def inspect(host) -> tuple[str, dict]:
    """執行唯讀檢查;回 (人類可讀報告, 結果 dict)。連線層錯誤拋 RuntimeError。"""
    base = _base(host)
    data: dict[str, dict] = {}
    errors: dict[str, str] = {}
    with _client(host) as c:
        headers = _auth_headers(c, base, host)
        for key, path in _ENDPOINTS.items():
            try:
                data[key] = _fetch(c, base, path, headers)
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

    def num(src: dict, field: str):
        """取數值欄位;回 (值 or None, 說明字串)。缺欄位/非數值一律回 None,
        由呼叫端標「人工」——不可用 0 代入,否則欄位改名會變成假的不符。"""
        if field not in src:
            return None, f"{field} 欄位不存在"
        val = to_int(src.get(field))
        if val is None:
            return None, f"{field}={src.get(field)!r} 非數值"
        return val, ""

    ver = ""
    try:
        ent = data["version"]["entries"]
        ver = next(iter(ent.values()))["nestedStats"]["entries"]["Version"]["description"]
    except Exception:  # noqa: BLE001
        pass

    g = data.get("global_settings")
    sshd = data.get("sshd")
    httpd = data.get("httpd")

    # ===== 1. 管理介面強化 =====
    CAT = "1. 管理介面強化"
    sect(CAT)
    if g is None:
        miss_group(CAT, "global-settings 各項", "global_settings")
    else:
        gsb = g.get("guiSecurityBanner")
        gsb_txt = str(g.get("guiSecurityBannerText", "") or "").strip()
        if gsb != "enabled":
            add("f5-gui-banner", CAT, "fail",
                f"GUI 登入警語 guiSecurityBanner={gsb or '未設'}"
                "(CIS 4.1/STIG 要求 enabled)")
        elif not gsb_txt:
            add("f5-gui-banner", CAT, "warn",
                "GUI 登入警語已啟用但文字為空(CIS 4.1 要求輸入警語文字)")
        else:
            add("f5-gui-banner", CAT, "pass",
                "GUI 登入警語啟用且已設文字(CIS 4.1/STIG)")
        cto, why = num(g, "consoleInactivityTimeout")
        if cto is None:
            add("f5-console-timeout", CAT, "manual",
                f"Console 閒置逾時無法判定({why};STIG:1~900 秒)")
        else:
            add("f5-console-timeout", CAT,
                "pass" if 1 <= cto <= 600 else "fail",
                f"Console 閒置逾時 consoleInactivityTimeout={cto or '0(停用)'}"
                "(CIS 4.4:1–600 秒)")
    if sshd is None:
        miss_group(CAT, "sshd 各項", "sshd")
    else:
        sb = sshd.get("banner")
        sb_txt = str(sshd.get("bannerText", "") or "").strip()
        if sb != "enabled":
            add("f5-sshd-banner", CAT, "fail",
                f"SSH 登入警語 banner={sb or '未設'}(CIS 4.1/STIG 要求 enabled)")
        elif not sb_txt:
            add("f5-sshd-banner", CAT, "warn",
                "SSH 登入警語已啟用但文字為空(CIS 4.1 要求輸入警語文字)")
        else:
            add("f5-sshd-banner", CAT, "pass",
                "SSH 登入警語啟用且已設文字(CIS 4.1/STIG)")
        sto, why = num(sshd, "inactivityTimeout")
        if sto is None:
            add("f5-sshd-timeout", CAT, "manual",
                f"SSH 閒置逾時無法判定({why};STIG:1~900 秒)")
        else:
            add("f5-sshd-timeout", CAT, "pass" if 1 <= sto <= 600 else "fail",
                f"SSH 閒置逾時 inactivityTimeout={sto or '0(停用)'}"
                "(CIS 4.2:1–600 秒)")
        allow = [str(a) for a in (sshd.get("allow") or [])]
        open_all = any(a.upper() == "ALL" for a in allow)
        add("f5-sshd-allow", CAT, "fail" if open_all or not allow else "pass",
            f"SSH 管理來源限制 allow={allow or '未設'}"
            + "(ALL = 未限制;STIG/CIS 要求限管理網段)" if open_all or not allow
            else f"SSH 管理來源已限制 allow={allow}")
        inc = str(sshd.get("include", "") or "").strip()
        if not inc or inc.lower() == "none":
            add("f5-ssh-algos", CAT, "warn",
                "sshd include 未明確限制 Ciphers/MACs/KexAlgorithms"
                "(採 TMOS 版本預設;CIS 4.5–4.7 要求明確設定,請人工確認)")
        else:
            hits = sorted({m.lower() for m in _WEAK_SSH_RE.findall(inc)})
            add("f5-ssh-algos", CAT, "fail" if hits else "pass",
                (f"SSH 演算法含弱項:{'、'.join(hits)}"
                 "(CIS 4.5–4.7;以現行標準判定)") if hits
                else "SSH 演算法無弱項(sshd include 已明確設定;CIS 4.5–4.7)")
    if httpd is None:
        miss_group(CAT, "httpd 各項", "httpd")
    else:
        h_allow = [str(a) for a in (httpd.get("allow") or [])]
        h_open = any(a.lower() == "all" for a in h_allow)
        add("f5-httpd-allow", CAT, "fail" if h_open or not h_allow else "pass",
            (f"GUI 管理來源未限制 allow={h_allow or '未設'}(STIG/CIS 要求限管理網段)")
            if h_open or not h_allow
            else f"GUI 管理來源已限制 allow={h_allow}")
        gto, why = num(httpd, "authPamIdleTimeout")
        if gto is None:
            add("f5-gui-timeout", CAT, "manual",
                f"GUI 閒置逾時無法判定({why};STIG:≤600 秒)")
        else:
            add("f5-gui-timeout", CAT, "pass" if 1 <= gto <= 600 else "fail",
                f"GUI 閒置逾時 authPamIdleTimeout={gto} 秒(STIG:≤600)")
        # sslProtocol 形如 "all -SSLv2 -SSLv3 -TLSv1":token 精確比對
        # (TLSv1 與 TLSv1.1 是不同 token,不會前綴誤匹配)
        sslp = str(httpd.get("sslProtocol", "") or "").strip()
        if not sslp:
            # fail-safe:欄位未取得時 token 清單為空,若照算會推出「弱協定
            # 皆未啟用」而判符合——那是假陰性,一律標人工
            add("f5-tls-version", CAT, "manual",
                "管理 GUI TLS 設定 sslProtocol 未取得,無法判定"
                "(應排除 SSLv2/SSLv3/TLSv1/TLSv1.1)")
        else:
            tokens = sslp.split()
            # Apache SSLProtocol 大小寫不敏感(-tlsv1 與 -TLSv1 等效),
            # 排除項與正向項都轉小寫比對,否則會把已排除的版本誤報為啟用
            negated = {t[1:].lower() for t in tokens if t.startswith("-")}
            # Apache 語法允許 +TLSv1.2 這種正向前綴,剝掉再比對
            positive = {t.lstrip("+").lower() for t in tokens
                        if not t.startswith("-")}
            weak = []
            for p in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                enabled = (p.lower() not in negated) if "all" in positive \
                    else (p.lower() in positive)
                if enabled:
                    weak.append(p)
            add("f5-tls-version", CAT, "fail" if weak else "pass",
                f"管理 GUI TLS 設定 sslProtocol={sslp}"
                + (f"(仍允許 {'/'.join(weak)};應排除 SSLv2/SSLv3/TLSv1/TLSv1.1)"
                   if weak else "(無弱版本)"))

    cli = data.get("cli")
    if cli is None:
        miss_group(CAT, "tmsh CLI 逾時", "cli")
    else:
        it_raw = cli.get("idleTimeout")
        it = to_int(it_raw)
        if it_raw is None:
            add("f5-tmsh-timeout", CAT, "manual",
                "tmsh 閒置逾時 idleTimeout 欄位不存在,無法判定(CIS 4.3)")
        elif str(it_raw).lower() == "disabled" or it == 0:
            add("f5-tmsh-timeout", CAT, "fail",
                f"tmsh 閒置逾時 idleTimeout={it_raw}(停用;CIS 4.3:1–10 分)")
        elif it is None:
            add("f5-tmsh-timeout", CAT, "manual",
                f"tmsh 閒置逾時 idleTimeout={it_raw!r} 非數值,無法判定")
        else:
            add("f5-tmsh-timeout", CAT, "pass" if it <= 10 else "fail",
                f"tmsh 閒置逾時 idleTimeout={it} 分(CIS 4.3:≤10)")

    # ===== 2. 系統設定 =====
    CAT = "2. 系統設定"
    sect(CAT)
    if g is not None:
        hn = g.get("hostname", "")
        add("f5-hostname", CAT, "pass" if hn else "fail",
            f"主機名稱 hostname={hn or '未設'}")
    else:
        miss("f5-hostname", CAT, "主機名稱", "global_settings")
    ntp = data.get("ntp")
    if ntp is None:
        miss_group(CAT, "NTP / 時區", "ntp")
    else:
        servers = ntp.get("servers") or []
        if len(servers) >= 2:
            add("f5-ntp", CAT, "pass",
                f"NTP 伺服器={servers}(冗餘雙台;CIS 5.1)")
        elif servers:
            add("f5-ntp", CAT, "warn",
                f"NTP 僅 1 台 {servers}(CIS 5.1 要求冗餘 ≥2;列注意)")
        else:
            add("f5-ntp", CAT, "fail", "NTP 伺服器未設(CIS 5.1/STIG)")
        tz = ntp.get("timezone", "")
        add("f5-timezone", CAT, "pass" if tz else "fail",
            f"時區 timezone={tz or '未設'}")

    # ===== 3. 密碼與帳號 =====
    CAT = "3. 密碼與帳號"
    sect(CAT)
    pp = data.get("pwd_policy")
    if pp is None:
        miss_group(CAT, "密碼原則", "pwd_policy")
    else:
        pe = pp.get("policyEnforcement")
        add("f5-pwd-policy", CAT, "pass" if pe == "enabled" else "fail",
            f"密碼原則強制 policyEnforcement={pe or '未設'}(STIG/CIS)")
        ml, why = num(pp, "minimumLength")
        if ml is None:
            add("f5-pwd-minlen", CAT, "manual",
                f"密碼最小長度無法判定({why};CIS 1.1.3:≥12)")
        else:
            add("f5-pwd-minlen", CAT, "pass" if ml >= 12 else "fail",
                f"密碼最小長度 minimumLength={ml}(CIS 1.1.3:≥12;"
                "STIG 建議 15)")
        req_keys = ("requiredUppercase", "requiredLowercase",
                    "requiredNumeric", "requiredSpecial")
        req = {}
        req_bad = []
        for k in req_keys:
            v, w = num(pp, k)
            if v is None:
                req_bad.append(w)
            else:
                req[k] = v
        if req_bad:
            # 四類欄位任一讀不到就不猜測(若以 0 代入會變成假的「不符」)
            add("f5-pwd-complexity", CAT, "manual",
                "密碼複雜度無法判定(" + "、".join(req_bad) + ")")
        else:
            n_req = sum(1 for v in req.values() if v >= 1)
            add("f5-pwd-complexity", CAT, "pass" if n_req == 4 else "fail",
                "密碼複雜度 " + "、".join(f"{k[8:].lower()}={v}"
                                      for k, v in req.items())
                + f"(4 類中 {n_req} 類 ≥1;CIS 1.1.3 要求四類皆 ≥1)")
        mlf, why = num(pp, "maxLoginFailures")
        if mlf is None:
            add("f5-login-failures", CAT, "manual",
                f"登入失敗鎖定無法判定({why};CIS 1.1.3:1–3)")
        else:
            add("f5-login-failures", CAT, "pass" if 1 <= mlf <= 3 else "fail",
                f"登入失敗鎖定 maxLoginFailures={mlf or '0(停用)'}"
                "(CIS 1.1.3:1–3)")

        # CIS 1.1.3 其餘子門檻(同一端點,零新請求)
        mdur, why = num(pp, "maxDuration")
        if mdur is None:
            add("f5-pwd-maxage", CAT, "manual",
                f"密碼最長使用期無法判定({why};CIS 1.1.3:≤180 天)")
        else:
            add("f5-pwd-maxage", CAT, "pass" if 1 <= mdur <= 180 else "fail",
                f"密碼最長使用期 maxDuration={mdur} 天(CIS 1.1.3:1–180)")
        pmem, why = num(pp, "passwordMemory")
        if pmem is None:
            add("f5-pwd-memory", CAT, "manual",
                f"密碼記憶無法判定({why};CIS 1.1.3:≥24 代)")
        else:
            add("f5-pwd-memory", CAT, "pass" if pmem >= 24 else "fail",
                f"密碼記憶 passwordMemory={pmem} 代(CIS 1.1.3:≥24)")
        pw_warn, why = num(pp, "expirationWarning")
        if pw_warn is None:
            add("f5-pwd-warning", CAT, "manual",
                f"到期前警告無法判定({why};CIS 1.1.3:≥14 天)")
        else:
            add("f5-pwd-warning", CAT, "pass" if pw_warn >= 14 else "fail",
                f"密碼到期前警告 expirationWarning={pw_warn} 天"
                "(CIS 1.1.3:≥14)")
    users = data.get("users")
    if users is None:
        miss_group(CAT, "管理帳號", "users")
    else:
        names = [u.get("name") for u in users.get("items", [])]
        has_admin = "admin" in names
        add("f5-admin-default", CAT, "manual" if has_admin else "pass",
            (f"存在預設 admin 帳號(共 {len(names)} 個管理帳號)——請人工確認"
             "密碼已變更(API 無法驗證)") if has_admin
            else f"無預設 admin 帳號(共 {len(names)} 個管理帳號)")

    # CIS 2.4–2.6:外部(遠端認證)使用者預設權限;本機認證時不適用
    asrc = data.get("auth_source")
    ru = data.get("remote_user")
    if ru is None:
        miss_group(CAT, "外部使用者預設權限", "remote_user")
    elif asrc is None:
        for _iid in _GROUP_IDS["remote_user"]:
            miss(_iid, CAT, "外部使用者預設權限(auth source 讀取失敗)",
                 "auth_source")
    elif asrc.get("type", "local") in ("local", ""):
        for _iid, _nm in (("f5-remote-role", "預設角色"),
                          ("f5-remote-partition", "Partition 存取"),
                          ("f5-remote-console", "終端存取")):
            add(_iid, CAT, "na",
                f"外部使用者{_nm}:認證來源為 local,未用遠端認證"
                "(CIS 2.4–2.6 不適用)")
    else:
        rtype = asrc.get("type")
        role = ru.get("defaultRole")
        if role is None:
            add("f5-remote-role", CAT, "manual",
                "defaultRole 欄位不存在,無法判定(CIS 2.4)")
        else:
            add("f5-remote-role", CAT,
                "pass" if role == "no-access" else "fail",
                f"外部使用者預設角色 defaultRole={role}"
                f"(認證來源 {rtype};CIS 2.4 要求 no-access)")
        part = ru.get("defaultPartition")
        if part is None:
            add("f5-remote-partition", CAT, "manual",
                "defaultPartition 欄位不存在,無法判定(CIS 2.5)")
        else:
            add("f5-remote-partition", CAT,
                "fail" if str(part).lower() == "all" else "pass",
                f"外部使用者 Partition 存取 defaultPartition={part}"
                "(CIS 2.5:不得為 All)")
        cons = ru.get("remoteConsoleAccess")
        if cons is None:
            add("f5-remote-console", CAT, "manual",
                "remoteConsoleAccess 欄位不存在,無法判定(CIS 2.6)")
        else:
            add("f5-remote-console", CAT,
                "pass" if cons == "disabled" else "fail",
                f"外部使用者終端存取 remoteConsoleAccess={cons}"
                "(CIS 2.6 要求 disabled)")

    # ===== 4. SNMP =====
    CAT = "4. SNMP"
    sect(CAT)
    snmp = data.get("snmp")
    if snmp is None:
        add("f5-snmp-v1v2c", CAT, "manual",
            "SNMP 設定無法經 REST 讀取(TMOS 版本/帳號角色限制)——請人工確認"
            "v1/v2c community 已停用、來源已限制"
            f"({errors.get('snmp', '')[:80]})")
    else:
        comm = snmp.get("communities")
        if comm is None:
            # iControl 子集合未展開時鍵不存在;空清單推「無 community」是
            # 假陰性(讀不到 ≠ 合規),一律標人工
            add("f5-snmp-v1v2c", CAT, "manual",
                "SNMP communities 欄位未取得(子集合未展開或角色限制)"
                "——請人工確認 v1/v2c 已停用(CIS 6.2)")
        elif comm:
            add("f5-snmp-v1v2c", CAT, "fail",
                f"SNMP v1/v2c community {len(comm)} 組"
                "(CIS 6.2 要求僅 v3)")
        else:
            v3_users = snmp.get("users")
            add("f5-snmp-v1v2c", CAT, "pass" if v3_users else "warn",
                "SNMP 無 v1/v2c community" + (
                    "(已設 v3 使用者;CIS 6.2)" if v3_users else
                    ";但未見 v3 使用者——CIS 6.2 另要求至少一組 v3,列注意"))

    # ===== 5. 日誌 =====
    CAT = "5. 日誌"
    sect(CAT)
    sl = data.get("syslog")
    if sl is None:
        miss_group(CAT, "遠端日誌", "syslog")
    else:
        remotes = sl.get("remoteServers") or []
        add("f5-syslog-remote", CAT, "pass" if remotes else "warn",
            f"遠端 syslog {len(remotes)} 台已設定" if remotes
            else "未設定遠端 syslog——若由其他機制集中收集可列替代(STIG/CIS)")

    hn_final = (g or {}).get("hostname", host.name)
    raw = (f"F5 BIG-IP 組態強化檢查(driver {DRIVER_VERSION},唯讀)\n"
           f"主機:{host.name}({host.ip_address})  hostname {hn_final}"
           f"  TMOS {ver or '?'}\n" + "\n".join(lines))
    if errors:
        raw += ("\n\n部分端點讀取失敗(相關項已標「人工」):\n  - "
                + "\n  - ".join(f"{k}: {v}" for k, v in errors.items()))

    result = {
        "script_version": DRIVER_VERSION,
        "family": "f5",
        "hostname": hn_final,
        "os": f"BIG-IP {ver}".strip(),
        "kernel": "",
        "slow": False,
        "items": items,
    }
    return raw, result
