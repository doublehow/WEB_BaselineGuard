"""Aruba Mobility Controller(AOS 8)組態強化檢查 driver v1.0(唯讀,REST Showcommand)。

依據:Aruba AOS 8 Hardening / Security Best Practices、通用 NDM SRG
(章級標示)。範圍:控制器管理面強化;WLAN/AP/角色政策內容不納入。
註(2026-08-24):CIS 無 Mobility Controller 專屬 Benchmark;
CIS「HPE Aruba Networking CX Switch」Benchmark 適用 AOS-CX 交換器,
與本 driver 產品不對口,不得引用其條次(比對紀錄見
sample/cis-compare-aruba.md)。若未來納入 AOS-CX,應另立 device_type。

連線:
- GET /v1/api/login 取 UIDARUBA(+ AOS 8.7+ X-CSRF-Token);
- GET /v1/configuration/showcommand?command=show+...&UIDARUBA=<t>;
- GET /v1/api/logout 釋放 session(控制器併發上限 64,務必登出)。
部署 REST API 可能在 443 或 4343(由 Host.ssh_port 覆寫);憑證帳密。
showcommand 回傳:結構化表格(具名 keys)或 {"_data": [文字行]}——後者以
文字解析。read-only 角色即可跑。

v1.0.1 修正:
- _show() 原本在 HTTP/JSON 失敗時回 {} 並吞掉例外,「指令失敗」與「真的沒
  設定」完全無法區分。改為回 (結果, 錯誤原因) 並比照其他 driver 建立
  errors 追蹤;指令失敗一律標「人工」,全部指令都失敗則整輪 RuntimeError。
- SNMP 兩項原本 `.get("SNMP COMMUNITIES", [])` 給了 list 預設值,
  isinstance 檢查恆真、else 的「人工」分支永不可達 → 指令失敗會被判成
  「無 v1/v2c community」(假陰性)。改為不給預設值,缺鍵即標「人工」。
- aruba-ntp / aruba-banner 原本用空字串判「未設定」,指令失敗會被當成
  沒設定(假不符);改為指令失敗標「人工」,指令成功但內容為空才判不符。
- aruba-ssh-ciphers 原本抓不到 Ciphers 欄位時弱演算法集合為空 → 判符合
  (假陰性);改為抓不到即標「人工」。
- base URL 改用 base.device_base_url:原本自行拼字串,不支援 ip_address
  帶 scheme 的反向代理寫法(會產生 https://https://...);逾時統一 API_TIMEOUT。
"""
from __future__ import annotations

import re

import httpx

from app.drivers.base import API_TIMEOUT, device_base_url, ssl_verify

DRIVER_VERSION = "aruba-1.0.1"
TIMEOUT = API_TIMEOUT
_IP = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_DEFAULT_COMM = {"public", "private"}

# 檢查用 show 指令(全部唯讀)
_CMDS = ("show snmp community", "show ntp servers", "show telnet", "show ssh",
         "show banner", "show aaa password-policy mgmt", "show mgmt-user")


def _base(host) -> str:
    # AOS8 控制器 REST 預設在 4343(部分部署改 443,由 Host.ssh_port 覆寫)
    return device_base_url(host, default_port=4343)


def _login(client, base, host):
    r = client.get(f"{base}/v1/api/login",
                   params={"username": host.username, "password": host.password})
    if r.status_code == 401:
        raise RuntimeError("401 未授權——帳密錯誤")
    try:
        body = r.json()
    except ValueError:
        raise RuntimeError(
            f"登入回應非 JSON(HTTP {r.status_code};"
            "可能連到非 REST 埠或被前置代理攔截)")
    g = body.get("_global_result", {}) if isinstance(body, dict) else {}
    uid = g.get("UIDARUBA")
    if not uid:
        raise RuntimeError(f"登入未取得 UIDARUBA(status={g.get('status_str', '?')})")
    csrf = g.get("X-CSRF-Token")
    return uid, ({"X-CSRF-Token": csrf} if csrf else {})


def _show(client, base, uid, headers, cmd) -> tuple[dict | None, str]:
    """執行一個 show 指令;回 (結果 dict, 錯誤原因)。成功時錯誤原因為空字串。

    失敗一律回 (None, 原因),不可回 {} 把例外吞掉——否則呼叫端無從分辨
    「指令失敗」與「設備真的沒設定」,前者會被判成不符(假不符)或
    判成沒有暴露面(假陰性),兩種誤判在合規檢查上都不可接受。
    """
    try:
        r = client.get(f"{base}/v1/configuration/showcommand",
                       params={"command": cmd, "UIDARUBA": uid},
                       headers=headers)
    except httpx.HTTPError as exc:
        return None, f"{type(exc).__name__}: {exc}"
    if r.status_code != 200:
        return None, f"HTTP {r.status_code}"
    try:
        body = r.json()
    except ValueError:
        return None, f"回應非 JSON(HTTP {r.status_code})"
    if not isinstance(body, dict):
        return None, "回應格式非預期(非 JSON 物件)"
    return body, ""


def test(host) -> tuple[bool, str]:
    try:
        with httpx.Client(verify=ssl_verify(bool(host.api_verify_ssl)), timeout=TIMEOUT,
                          follow_redirects=True) as c:
            base = _base(host)
            uid, h = _login(c, base, host)
            c.get(f"{base}/v1/api/logout")
        return True, "連線成功:AOS8 REST 可讀(showcommand)"
    except RuntimeError as exc:
        return False, f"Aruba API 失敗:{exc}"
    except httpx.HTTPError as exc:
        return False, f"連線失敗:{type(exc).__name__}: {exc}"


def inspect(host) -> tuple[str, dict]:
    base = _base(host)
    data: dict = {}
    errors: dict[str, str] = {}
    with httpx.Client(verify=ssl_verify(bool(host.api_verify_ssl)), timeout=TIMEOUT,
                      follow_redirects=True) as c:
        try:
            uid, h = _login(c, base, host)
        except httpx.HTTPError as exc:
            raise RuntimeError(f"連線失敗:{type(exc).__name__}: {exc}")
        try:
            for cmd in _CMDS:
                body, err = _show(c, base, uid, h, cmd)
                if body is None:
                    errors[cmd] = err
                else:
                    data[cmd] = body
        finally:
            try:
                c.get(f"{base}/v1/api/logout")
            except httpx.HTTPError:
                pass

    # 全部指令都失敗 → 整輪失敗(權限/session 問題),不產生一整份「人工」報告
    if not data:
        raise RuntimeError("所有 showcommand 皆無法讀取:" +
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

    def miss(iid, cat, name, cmd):
        add(iid, cat, "manual",
            f"{name}——showcommand `{cmd}` 失敗,無法判定"
            f"({errors.get(cmd, '未知原因')[:100]})")

    def rows_of(cmd):
        """取 {"_data": [...]} 的文字行;回 None 表示回應不含 _data(無法解析)。"""
        raw_rows = data.get(cmd, {}).get("_data")
        if not isinstance(raw_rows, list):
            return None
        return [str(x) for x in raw_rows if x]

    # ===== 1. 管理服務 =====
    CAT = "1. 管理服務"
    sect(CAT)
    if "show telnet" not in data:
        miss("aruba-telnet", CAT, "Telnet 狀態", "show telnet")
    else:
        rows = rows_of("show telnet")
        telnet = "\n".join(rows) if rows else ""
        if not telnet:
            add("aruba-telnet", CAT, "manual",
                "指令成功但無可解析輸出,無法判定 Telnet CLI 狀態")
        else:
            off = "telnet cli is disabled" in telnet.lower()
            add("aruba-telnet", CAT, "pass" if off else "fail",
                "Telnet CLI 已停用" if off else "Telnet CLI 啟用(應停用)")

    if "show ssh" not in data:
        miss("aruba-ssh-dsa", CAT, "SSH 主機金鑰", "show ssh")
        miss("aruba-ssh-ciphers", CAT, "SSH 加密演算法", "show ssh")
    else:
        rows = rows_of("show ssh")
        ssh_txt = "\n".join(rows) if rows else ""
        if not ssh_txt:
            add("aruba-ssh-dsa", CAT, "manual",
                "指令成功但無可解析輸出,無法判定 SSH 主機金鑰")
            add("aruba-ssh-ciphers", CAT, "manual",
                "指令成功但無可解析輸出,無法判定 SSH 加密演算法")
        else:
            dsa_on = bool(re.search(r"DSA\s+Enabled", ssh_txt))
            add("aruba-ssh-dsa", CAT, "fail" if dsa_on else "pass",
                "SSH DSA 主機金鑰啟用(弱,應停用)" if dsa_on
                else "SSH DSA 主機金鑰已停用")
            m = re.search(r"Ciphers\s+(\S+)", ssh_txt)
            if not m:
                # fail-safe:抓不到 Ciphers 欄位時弱演算法集合必為空,
                # 若照算會判符合 → 假陰性
                add("aruba-ssh-ciphers", CAT, "manual",
                    "輸出未含 Ciphers 欄位(AOS 版本差異),無法判定弱演算法")
            else:
                ciph = m.group(1)
                weak = [c for c in ciph.split(",") if "cbc" in c or "3des" in c]
                add("aruba-ssh-ciphers", CAT, "fail" if weak else "pass",
                    f"SSH 加密含弱演算法:{weak}(應移除 cbc/3des)" if weak
                    else f"SSH 加密無弱演算法({ciph})")

    # ===== 2. SNMP =====
    CAT = "2. SNMP"
    sect(CAT)
    if "show snmp community" not in data:
        miss("aruba-snmp-v1v2c", CAT, "SNMP community", "show snmp community")
        miss("aruba-snmp-default", CAT, "SNMP community", "show snmp community")
    else:
        # 不給 [] 預設值:缺鍵代表輸出格式非預期,不可當成「沒有 community」
        comms = data["show snmp community"].get("SNMP COMMUNITIES")
        if not isinstance(comms, list):
            add("aruba-snmp-v1v2c", CAT, "manual",
                "回應未含 SNMP COMMUNITIES 表格(AOS 版本差異),無法判定 v1/v2c")
            add("aruba-snmp-default", CAT, "manual",
                "回應未含 SNMP COMMUNITIES 表格(AOS 版本差異),無法判定預設名稱")
        else:
            v12 = [c for c in comms if "V1" in str(c.get("VERSION", ""))
                   or "V2" in str(c.get("VERSION", ""))]
            add("aruba-snmp-v1v2c", CAT, "fail" if v12 else "pass",
                f"SNMP v1/v2c community {len(v12)} 組(應停用改 v3)" if v12
                else "無 SNMP v1/v2c community")
            defaults = [c.get("COMMUNITY") for c in comms
                        if str(c.get("COMMUNITY", "")).lower() in _DEFAULT_COMM]
            add("aruba-snmp-default", CAT, "fail" if defaults else "pass",
                f"存在預設 community 名稱:{defaults}(應移除)" if defaults
                else "無預設 community 名稱(public/private)")

    # ===== 3. 時間 / 橫幅 =====
    CAT = "3. 時間與橫幅"
    sect(CAT)
    if "show ntp servers" not in data:
        miss("aruba-ntp", CAT, "NTP 伺服器", "show ntp servers")
    else:
        rows = rows_of("show ntp servers")
        if rows is None:
            add("aruba-ntp", CAT, "manual",
                "回應未含文字輸出(AOS 版本差異),無法判定 NTP 伺服器")
        else:
            # server 行:分隔線之後含 IP 的資料列
            ntp_rows = [l for l in rows
                        if _IP.search(l) and "version" not in l.lower()]
            add("aruba-ntp", CAT, "pass" if ntp_rows else "fail",
                f"NTP 伺服器 {len(ntp_rows)} 台" if ntp_rows
                else "未設定 NTP 伺服器(SRG)")
    if "show banner" not in data:
        miss("aruba-banner", CAT, "登入橫幅", "show banner")
    else:
        rows = rows_of("show banner")
        if rows is None:
            add("aruba-banner", CAT, "manual",
                "回應未含文字輸出(AOS 版本差異),無法判定登入橫幅")
        else:
            add("aruba-banner", CAT, "pass" if rows else "fail",
                "登入橫幅已設定" if rows else "未設定登入橫幅(SRG)")

    # ===== 4. 密碼原則 =====
    CAT = "4. 密碼原則"
    sect(CAT)
    _POL_CMD = "show aaa password-policy mgmt"
    if _POL_CMD not in data:
        miss("aruba-pwd-policy", CAT, "密碼原則", _POL_CMD)
        miss("aruba-pwd-minlen", CAT, "密碼最小長度", _POL_CMD)
    else:
        pol = data[_POL_CMD].get("Mgmt Password Policy")
        if not isinstance(pol, list) or not pol:
            add("aruba-pwd-policy", CAT, "manual",
                "回應未含 Mgmt Password Policy 表格,無法判定密碼原則")
            add("aruba-pwd-minlen", CAT, "manual",
                "回應未含 Mgmt Password Policy 表格,無法判定密碼最小長度")
        else:
            pmap = {p.get("Parameter", ""): p.get("Value", "") for p in pol}
            en_raw = pmap.get("Enable password policy")
            if en_raw is None:
                add("aruba-pwd-policy", CAT, "manual",
                    "表格未含「Enable password policy」欄位,無法判定")
            else:
                enabled = str(en_raw).strip().lower() == "yes"
                add("aruba-pwd-policy", CAT, "pass" if enabled else "fail",
                    f"密碼原則 Enable password policy={en_raw}(應 Yes)")
            mlen_raw = pmap.get("Minimum password length required")
            m = re.search(r"\d+", str(mlen_raw)) if mlen_raw is not None else None
            if m is None:
                add("aruba-pwd-minlen", CAT, "manual",
                    f"密碼最小長度欄位未取得或非數值(={mlen_raw!r};SRG/CIS:≥8)")
            else:
                mlen = int(m.group(0))
                add("aruba-pwd-minlen", CAT, "pass" if mlen >= 8 else "fail",
                    f"密碼最小長度={mlen}(SRG/CIS:≥8)")

    # ===== 5. 管理帳號 =====
    CAT = "5. 管理帳號"
    sect(CAT)
    if "show mgmt-user" not in data:
        miss("aruba-admin-default", CAT, "管理帳號清單", "show mgmt-user")
    else:
        users = data["show mgmt-user"].get("Management User Table")
        if not isinstance(users, list) or not users:
            add("aruba-admin-default", CAT, "manual",
                "未列出任何管理帳號(回應格式差異或權限限制),無法判定")
        else:
            names = [u.get("USER") for u in users]
            has_admin = "admin" in names
            add("aruba-admin-default", CAT, "manual" if has_admin else "pass",
                (f"存在預設 admin 帳號(共 {len(names)} 管理帳號)——請人工確認密碼已變更")
                if has_admin else f"無預設 admin 帳號(共 {len(names)} 管理帳號)")

    raw = (f"Aruba 控制器組態強化檢查(driver {DRIVER_VERSION},唯讀)\n"
           f"主機:{host.name}({host.ip_address})\n" + "\n".join(lines))
    if errors:
        raw += ("\n\n部分 showcommand 讀取失敗(相關項已標「人工」):\n  - "
                + "\n  - ".join(f"{k}: {v}" for k, v in errors.items()))

    result = {
        "script_version": DRIVER_VERSION,
        "family": "aruba",
        "hostname": host.name,
        "os": "Aruba AOS 8",
        "kernel": "",
        "slow": False,
        "items": items,
    }
    return raw, result
