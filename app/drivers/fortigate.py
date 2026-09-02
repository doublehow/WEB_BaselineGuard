"""FortiGate(FortiOS)組態強化檢查 driver v1.0(唯讀,CMDB REST API)。

依據:CIS FortiGate 7.4.x Benchmark v1.0.1(2026-01-07;條次與門檻已逐條
核對原文,比對紀錄見 sample/cis-compare-fortigate.md)、DISA FortiGate
Firewall NDM STIG V1R5 交叉參照(逐條比對見 sample/stig-compare-fortigate.md)。
範圍:僅系統管理面強化(CIS 第 1、2 章 + SNMP + 日誌);policy 內容類
項目(CIS 第 3、4 章)依平台定位不納入(policy 管理屬防火牆政策管理平台)。

連線:
- Bearer token(api-user);?scope=global 讀 global 層。
- 403 常見原因:token 失效/輪換、api-user trusthost 未含本伺服器 IP、
  accprofile 缺 sysgrp 讀取權——訊息中明確提示。
- 429:FortiOS 對連續失敗節流,稍候再試。
- token 權限不足時可能回 200+success 但 results 空(size>0),需主動偵測。
欄位名以 FortiOS 7.4 文件為準;缺欄位時該項標「人工」不猜測、不誤判。

v1.0.1 修正:
- admin-https-ssl-versions 為空(欄位未取得)時改標「人工」,原本會因
  弱版本集合為空而誤判符合(假陰性)。
- SNMP sysinfo 缺 status 欄位時改標「人工」,原本會判成「SNMP agent 停用」。
- admintimeout / admin-lockout-* 改用 base.to_int 安全轉換,非數字不再讓
  整輪檢查以 ValueError 中斷。
- system/global 端點失敗時補齊該區段全部 10 項為「人工」(原本只補 1 項,
  其餘 9 項會整項消失,造成計數縮水與假異動)。
- hostname 預設名判定改為全等比對,FGT-DC1-FW 這類正規命名不再誤標注意。
- WAN allowaccess 弱服務集合直接列舉,不再用「先放 ping 再減掉」的寫法。
- base URL 與逾時改用 base.device_base_url / base.API_TIMEOUT 統一。

v1.1.0(2026-08-24,依 CIS 7.4.x v1.0.1 原文逐條對齊):
- fgt-pwd-policy:門檻 ≥8 → ≥14,並須 apply-to 含 admin-password(CIS 2.2.1)。
- fgt-wan-mgmt:弱服務集合補 https/ssh/ping(CIS 1.3 明列)。
- fgt-hostname:預設名改樣式比對(機型名 FortiGate 2000E / FGT60F)+ 序號比對。
- fgt-tls-version:CIS 2.1.10 僅接受 tlsv1-3;含 tlsv1-2 改列注意。
- fgt-idle-timeout:≤5 符合、6–15 注意(CIS 上限 15)、>15 不符。
- fgt-lockout:duration 改 60–900(CIS 2.2.2 ≤900;≥60 為平台下限),不符改 fail。
- fgt-admin-ports:補判 admin-port≠80 與 admin-https-redirect=disable
  (CIS 2.4.7 NOTE:僅改 sport 仍會聽 80),不符改 fail。
- fgt-trusthost:納入 ip6-trusthost1..10,僅設 IPv6 名單的帳號不再誤判。
- fgt-syslog:未設 syslog 但 FortiAnalyzer 啟用 → 注意(CIS 7.2.1 Audit 僅列 syslog)。
- 新增:fgt-ssl-static-keys(2.1.8)、fgt-gui-hostname(2.1.13)、
  fgt-cpu-log(2.1.12)、fgt-event-logging(7.1.1)、fgt-faz-encryption(7.3.1)。
"""
from __future__ import annotations

import re

import httpx

from app.drivers.base import API_TIMEOUT, device_base_url, ssl_verify, to_int

DRIVER_VERSION = "fgt-1.1.0"
TIMEOUT = API_TIMEOUT

# 檢查用端點(全部唯讀 GET)
_ENDPOINTS = {
    "global": "/api/v2/cmdb/system/global",
    "dns": "/api/v2/cmdb/system/dns",
    "ntp": "/api/v2/cmdb/system/ntp",
    "snmp_sysinfo": "/api/v2/cmdb/system.snmp/sysinfo",
    "snmp_community": "/api/v2/cmdb/system.snmp/community",
    "admin": "/api/v2/cmdb/system/admin",
    "pwd_policy": "/api/v2/cmdb/system/password-policy",
    "interface": "/api/v2/cmdb/system/interface",
    "syslog": "/api/v2/cmdb/log.syslogd/setting",
    "auto_install": "/api/v2/cmdb/system/auto-install",
    "eventfilter": "/api/v2/cmdb/log/eventfilter",
    "faz": "/api/v2/cmdb/log.fortianalyzer/setting",
}

# system/global 端點涵蓋的檢查項——該端點失敗時必須全部補「人工」,
# 否則這些項目會整項消失(計數縮水、平台端誤記為異動)。
_GLOBAL_IDS = (
    "fgt-prelogin-banner", "fgt-postlogin-banner", "fgt-hostname",
    "fgt-timezone", "fgt-tls-version", "fgt-idle-timeout", "fgt-lockout",
    "fgt-strong-crypto", "fgt-admin-telnet", "fgt-admin-ports",
    "fgt-ssl-static-keys", "fgt-gui-hostname", "fgt-cpu-log",
)

# WAN 介面不應開放的服務(CIS 1.3 明列 ping/https/ssh 也不得開在 WAN)
_WAN_WEAK_ACCESS = {"http", "https", "ssh", "telnet", "ping",
                    "snmp", "radius-acct", "fgfm"}

# FortiGate 出廠預設主機名樣式:機型名(FortiGate 2000E / FortiGate-201F /
# FGT60F)——CIS 2.1.5 Default Value 即機型名;FGT-DC1-FW 這類正規命名不會誤中。
_DEFAULT_HOSTNAME_RE = re.compile(
    r"^(fortigate|fgt)([\s_-]?\d+[a-z0-9]*)?$", re.IGNORECASE)


def _base(host) -> str:
    return device_base_url(host, default_port=443)


def _client(host) -> httpx.Client:
    return httpx.Client(
        headers={"Authorization": f"Bearer {host.api_key}"},
        verify=ssl_verify(bool(host.api_verify_ssl)), timeout=TIMEOUT)


def _diag(status_code: int) -> str:
    if status_code == 403:
        return ("403 Forbidden——常見原因:API token 已失效/輪換、"
                "api-user 的 trusted host 未包含本伺服器 IP、"
                "或 accprofile 缺 sysgrp 讀取權")
    if status_code == 429:
        return "429 Too Many Requests——FortiOS 節流中(連續失敗觸發),請稍候再試"
    return f"HTTP {status_code}"


def _fetch(client: httpx.Client, base: str, path: str) -> dict | list:
    """GET 一個 CMDB 端點;回 results(dict 或 list)。錯誤拋 RuntimeError。"""
    r = client.get(base + path, params={"scope": "global"})
    if r.status_code != 200:
        raise RuntimeError(f"{path}:{_diag(r.status_code)}")
    body = r.json()
    if body.get("status") != "success":
        raise RuntimeError(f"{path}:API 回應非 success({body.get('status')})")
    results = body.get("results")
    # 實戰經驗:權限不足時 200+success 但 results 空(size>0)→ 明確報錯
    if (isinstance(results, list) and not results
            and isinstance(body.get("size"), int) and body["size"] > 0):
        raise RuntimeError(
            f"{path}:token 權限不足(表上有 {body['size']} 筆卻讀不到),"
            "請確認 accprofile 讀取權")
    body["_results"] = results
    return body


def test(host) -> tuple[bool, str]:
    """測試連線與 token(讀 system/dns,小且無敏感內容)。"""
    try:
        with _client(host) as c:
            body = _fetch(c, _base(host), _ENDPOINTS["dns"])
        ver = body.get("version", "?")
        return True, f"連線成功:FortiOS {ver}(serial {body.get('serial', '?')})"
    except RuntimeError as exc:
        return False, f"FortiGate API 失敗:{exc}"
    except httpx.HTTPError as exc:
        return False, f"連線失敗:{type(exc).__name__}: {exc}"


# ──────────────────────────────────────────────────────────────────
# 檢查評估
# ──────────────────────────────────────────────────────────────────

def inspect(host) -> tuple[str, dict]:
    """執行唯讀檢查;回 (人類可讀報告, 結果 dict)。連線層錯誤拋 RuntimeError。"""
    base = _base(host)
    data: dict[str, dict] = {}
    errors: dict[str, str] = {}
    with _client(host) as c:
        for key, path in _ENDPOINTS.items():
            try:
                data[key] = _fetch(c, base, path)
            except RuntimeError as exc:
                errors[key] = str(exc)
            except httpx.HTTPError as exc:
                # 網路層失敗直接視為整體失敗(非單端點權限問題)
                raise RuntimeError(f"連線失敗:{type(exc).__name__}: {exc}")

    # 全部端點都失敗 → 整體失敗(token/trusthost 問題)
    if not data:
        raise RuntimeError("所有 API 端點皆無法讀取:" +
                           "; ".join(list(errors.values())[:2]))

    items: list[dict] = []
    lines: list[str] = []

    def add(iid: str, cat: str, status: str, desc: str) -> None:
        items.append({"id": iid, "cat": cat, "status": status, "desc": desc})
        mark = {"pass": "[符合]", "fail": "[不符]", "warn": "[注意]",
                "manual": "[人工]", "na": "[不適用]"}[status]
        lines.append(f"  {mark} {desc}")

    def sect(title: str) -> None:
        lines.append(f"\n━━━ {title} ━━━")

    def res(key: str):
        """端點 results;讀不到回 None(該群檢查標人工)。"""
        return data.get(key, {}).get("_results") if key in data else None

    def miss(iid: str, cat: str, name: str, key: str) -> None:
        add(iid, cat, "manual", f"{name}——端點讀取失敗,無法判定"
            f"({errors.get(key, '未知原因')[:120]})")

    ver = next(iter(data.values())).get("version", "?")
    serial = next(iter(data.values())).get("serial", "?")

    # ===== 1. 基礎設定 =====
    CAT = "1. 基礎設定"
    sect(CAT)
    dns = res("dns")
    if dns is None:
        miss("fgt-dns", CAT, "DNS 設定", "dns")
    else:
        p, s = dns.get("primary", "0.0.0.0"), dns.get("secondary", "0.0.0.0")
        if p not in ("", "0.0.0.0"):
            add("fgt-dns", CAT, "pass", f"DNS 已設定(primary {p}"
                + (f"、secondary {s}" if s not in ("", "0.0.0.0") else "") + ")")
        else:
            add("fgt-dns", CAT, "fail", "DNS 未設定(CIS 1.1)")

    ifaces = res("interface")
    g = res("global") or {}
    if ifaces is None:
        miss("fgt-wan-mgmt", CAT, "WAN 介面管理服務", "interface")
    else:
        bad = []
        for it in ifaces:
            if it.get("role") != "wan":
                continue
            acc = set(str(it.get("allowaccess", "")).split())
            weak = acc & _WAN_WEAK_ACCESS
            if weak:
                bad.append(f"{it.get('name')}({'/'.join(sorted(weak))})")
        if bad:
            add("fgt-wan-mgmt", CAT, "fail",
                f"WAN 介面開放管理服務:{'、'.join(bad)}(CIS 1.3 應停用)")
        else:
            add("fgt-wan-mgmt", CAT, "pass",
                "WAN 介面未開放明文/管理服務(CIS 1.3)")

    # ===== 2. 系統管理強化 =====
    CAT = "2. 系統管理強化"
    sect(CAT)
    if not g:
        for _i in _GLOBAL_IDS:
            miss(_i, CAT, "system/global 各項", "global")
    else:
        def gval(k, default=None):
            return g.get(k, default)

        add("fgt-prelogin-banner", CAT,
            "pass" if gval("pre-login-banner") == "enable" else "fail",
            f"登入前警語 pre-login-banner={gval('pre-login-banner', '未設')}"
            "(CIS 2.1.1 要求 enable)")
        add("fgt-postlogin-banner", CAT,
            "pass" if gval("post-login-banner") == "enable" else "fail",
            f"登入後警語 post-login-banner={gval('post-login-banner', '未設')}"
            "(CIS 2.1.2 要求 enable)")
        hn = gval("hostname", "")
        # 預設名 = 機型名樣式或等於序號(CIS 2.1.5 Default Value 為機型名)
        is_default = bool(_DEFAULT_HOSTNAME_RE.match(hn)) or (
            serial not in ("", "?") and hn.lower() == str(serial).lower())
        add("fgt-hostname", CAT, "pass" if hn and not is_default else "warn",
            f"主機名稱 hostname={hn or '未設'}"
            "(CIS 2.1.5;預設名/機型名建議更改)")
        tz = gval("timezone", "")
        add("fgt-timezone", CAT, "pass" if tz else "fail",
            f"時區已設定 timezone={tz or '未設'}(CIS 2.1.3)")
        vers = str(gval("admin-https-ssl-versions", "") or "").strip()
        if not vers:
            # fail-safe:欄位未取得時弱版本集合必為空,若判 pass 就是假陰性
            add("fgt-tls-version", CAT, "manual",
                "管理 GUI TLS 版本 admin-https-ssl-versions 未取得,無法判定"
                "(CIS 2.1.10)")
        else:
            toks = set(vers.split())
            weak_tls = {"tlsv1-0", "tlsv1-1", "sslv3"} & toks
            if weak_tls:
                add("fgt-tls-version", CAT, "fail",
                    f"管理 GUI TLS 版本={vers}(含弱版本 "
                    f"{'/'.join(sorted(weak_tls))};CIS 2.1.10)")
            elif "tlsv1-2" in toks:
                add("fgt-tls-version", CAT, "warn",
                    f"管理 GUI TLS 版本={vers}"
                    "(無弱版本;CIS 2.1.10 僅接受 tlsv1-3,列注意)")
            else:
                add("fgt-tls-version", CAT, "pass",
                    f"管理 GUI TLS 版本={vers}(僅 TLS 1.3;CIS 2.1.10)")
        to = to_int(gval("admintimeout"))
        if to is None:
            add("fgt-idle-timeout", CAT, "manual",
                f"閒置逾時 admintimeout 未取得或非數值"
                f"(={gval('admintimeout')!r})")
        else:
            _st = "pass" if to <= 5 else ("warn" if to <= 15 else "fail")
            add("fgt-idle-timeout", CAT, _st,
                f"閒置逾時 admintimeout={to} 分"
                "(CIS 2.4.4:上限 15、Remediation 5;6–15 列注意)")
        lk_t = to_int(gval("admin-lockout-threshold"))
        lk_d = to_int(gval("admin-lockout-duration"))
        if lk_t is None or lk_d is None:
            add("fgt-lockout", CAT, "manual",
                f"登入失敗鎖定設定未取得或非數值(threshold="
                f"{gval('admin-lockout-threshold')!r}、duration="
                f"{gval('admin-lockout-duration')!r})")
        else:
            ok = lk_t <= 3 and 60 <= lk_d <= 900
            add("fgt-lockout", CAT, "pass" if ok else "fail",
                f"登入失敗鎖定 threshold={lk_t}、duration={lk_d} 秒"
                "(CIS 2.2.2:threshold ≤3、duration ≤900;≥60 為平台下限)")
        add("fgt-strong-crypto", CAT,
            "pass" if gval("strong-crypto") == "enable" else "fail",
            f"強加密 strong-crypto={gval('strong-crypto', '未取得')}"
            "(CIS 2.1.9/STIG 要求 enable)")
        telnet = gval("admin-telnet")
        if telnet is None:
            add("fgt-admin-telnet", CAT, "manual",
                "admin-telnet 欄位不存在(此版本可能無此選項,見介面檢查)")
        else:
            add("fgt-admin-telnet", CAT,
                "pass" if telnet == "disable" else "fail",
                f"Telnet 管理 admin-telnet={telnet}(CIS 2.4.5 要求 disable)")
        sport, port80 = gval("admin-sport"), gval("admin-port")
        redirect = gval("admin-https-redirect")
        # CIS 2.4.7 NOTE:僅改 sport 而 redirect 未停用時,設備仍監聽 80
        ports_ok = (str(sport) not in ("443", "None")
                    and str(port80) not in ("80", "None")
                    and redirect == "disable")
        add("fgt-admin-ports", CAT, "pass" if ports_ok else "fail",
            f"管理埠 admin-sport={sport}、admin-port={port80}、"
            f"https-redirect={redirect}"
            "(CIS 2.4.7:sport≠443、port≠80 且 redirect=disable)")

        # 新增三項(同 system/global 端點;ID 一律字面值,供 verify_item_ids
        # 靜態掃描)。fail-safe:欄位不存在 ≠ 合規,一律標人工。
        sk = gval("ssl-static-key-ciphers")
        if sk is None:
            add("fgt-ssl-static-keys", CAT, "manual",
                "TLS 靜態金鑰套件 ssl-static-key-ciphers 欄位未取得,"
                "無法判定(CIS 2.1.8)")
        else:
            add("fgt-ssl-static-keys", CAT,
                "pass" if sk == "disable" else "fail",
                f"TLS 靜態金鑰加密套件 ssl-static-key-ciphers={sk}"
                "(CIS 2.1.8 要求 disable)")
        gh = gval("gui-display-hostname")
        if gh is None:
            add("fgt-gui-hostname", CAT, "manual",
                "登入頁顯示主機名稱 gui-display-hostname 欄位未取得,"
                "無法判定(CIS 2.1.13)")
        else:
            add("fgt-gui-hostname", CAT,
                "pass" if gh == "disable" else "fail",
                f"登入頁顯示主機名稱 gui-display-hostname={gh}"
                "(CIS 2.1.13 要求 disable)")
        cl = gval("log-single-cpu-high")
        if cl is None:
            add("fgt-cpu-log", CAT, "manual",
                "單核 CPU 過載事件記錄 log-single-cpu-high 欄位未取得,"
                "無法判定(CIS 2.1.12)")
        else:
            add("fgt-cpu-log", CAT, "pass" if cl == "enable" else "fail",
                f"單核 CPU 過載事件記錄 log-single-cpu-high={cl}"
                "(CIS 2.1.12 要求 enable)")

    if ifaces is not None:
        plain = []
        for it in ifaces:
            acc = set(str(it.get("allowaccess", "")).split())
            bad = acc & {"http", "telnet"}
            if bad:
                plain.append(f"{it.get('name')}({'/'.join(sorted(bad))})")
        add("fgt-encrypted-mgmt", CAT, "fail" if plain else "pass",
            ("介面開放明文管理通道:" + "、".join(plain) + "(CIS 2.4.5)")
            if plain else "全部介面僅加密管理通道(無 http/telnet;CIS 2.4.5)")
    else:
        miss("fgt-encrypted-mgmt", CAT, "明文管理通道", "interface")

    admins = res("admin")
    if admins is None:
        miss("fgt-trusthost", CAT, "管理帳號 trusted host", "admin")
        miss("fgt-admin-default", CAT, "預設 admin 帳號", "admin")
    else:
        open_admins = []
        for a in admins:
            ths = [str(a.get(f"trusthost{i}", "")) for i in range(1, 11)]
            ths += [str(a.get(f"ip6-trusthost{i}", "")) for i in range(1, 11)]
            ths = [t for t in ths
                   if t and t not in ("0.0.0.0 0.0.0.0", "::/0")]
            if not ths:
                open_admins.append(a.get("name", "?"))
        add("fgt-trusthost", CAT, "fail" if open_admins else "pass",
            (f"未設 trusted host 的管理帳號:{'、'.join(open_admins)}"
             "(CIS 2.4.2)") if open_admins
            else f"全部 {len(admins)} 個管理帳號皆設 trusted host(CIS 2.4.2)")
        has_default = any(a.get("name") == "admin" for a in admins)
        add("fgt-admin-default", CAT, "manual" if has_default else "pass",
            "存在預設 admin 帳號——請人工確認密碼已變更(CIS 2.4.1;"
            "API 無法驗證密碼)" if has_default
            else "無預設 admin 帳號(已改名/移除;CIS 2.4.1)")

    pwd = res("pwd_policy")
    if pwd is None:
        miss("fgt-pwd-policy", CAT, "密碼原則", "pwd_policy")
    else:
        st = pwd.get("status")
        raw_ml = pwd.get("minimum-length")
        ml = to_int(raw_ml)
        apply_to = pwd.get("apply-to")
        if st is None or ml is None:
            # fail-safe:status/minimum-length 任一讀不到就無法判定
            add("fgt-pwd-policy", CAT, "manual",
                f"密碼原則欄位未取得(status={st!r}、minimum-length={raw_ml!r})"
                "——無法判定(CIS 2.2.1)")
        elif apply_to is None:
            # 只啟用但 scope 不含管理密碼時等同未生效,缺欄位不可判符合
            add("fgt-pwd-policy", CAT, "manual",
                f"密碼原則 status={st}、minimum-length={ml},但 apply-to 欄位"
                "未取得,無法確認涵蓋管理密碼(CIS 2.2.1)")
        else:
            ok = (st == "enable" and ml >= 14
                  and "admin-password" in str(apply_to))
            add("fgt-pwd-policy", CAT, "pass" if ok else "fail",
                f"密碼原則 status={st}、minimum-length={ml}、"
                f"apply-to={apply_to}"
                "(CIS 2.2.1:enable、≥14 且含 admin-password)")

    ntp = res("ntp")
    if ntp is None:
        miss("fgt-ntp", CAT, "NTP 同步", "ntp")
    else:
        add("fgt-ntp", CAT,
            "pass" if ntp.get("ntpsync") == "enable" else "fail",
            f"NTP 同步 ntpsync={ntp.get('ntpsync', '未設')}"
            "(CIS 2.1.4,Manual 項;僅查設定值,未驗實際同步狀態)")

    # ===== 3. SNMP =====
    CAT = "3. SNMP"
    sect(CAT)
    sysinfo = res("snmp_sysinfo")
    comm = res("snmp_community")
    if sysinfo is None:
        miss("fgt-snmp-v1v2c", CAT, "SNMP 設定", "snmp_sysinfo")
    else:
        snmp_status = sysinfo.get("status") if isinstance(sysinfo, dict) else None
        snmp_on = snmp_status == "enable"
        n_comm = len(comm) if isinstance(comm, list) else None
        if snmp_status is None:
            # fail-safe:欄位不存在不等於「已停用」,不可判符合
            add("fgt-snmp-v1v2c", CAT, "manual",
                "SNMP sysinfo 缺 status 欄位,無法判定 agent 是否啟用"
                "——請人工確認 v1/v2c 已停用")
        elif not snmp_on:
            add("fgt-snmp-v1v2c", CAT, "pass",
                f"SNMP agent 停用(status={snmp_status};v1/v2c 無暴露)")
        elif n_comm is None:
            add("fgt-snmp-v1v2c", CAT, "manual",
                "SNMP 啟用但 community 清單讀取失敗,無法判定 v1/v2c")
        elif n_comm == 0:
            add("fgt-snmp-v1v2c", CAT, "pass",
                "SNMP 啟用但無 v1/v2c community(僅 v3;CIS 2.3.1)")
        else:
            add("fgt-snmp-v1v2c", CAT, "fail",
                f"SNMP v1/v2c community 存在 {n_comm} 組(應停用改用 v3)")

    # ===== 4. 日誌與更新 =====
    CAT = "4. 日誌與更新"
    sect(CAT)
    sl = res("syslog")
    faz = res("faz")
    if sl is None:
        miss("fgt-syslog", CAT, "遠端日誌", "syslog")
    else:
        st = sl.get("status")
        if st == "enable":
            add("fgt-syslog", CAT, "pass",
                f"遠端 syslog status=enable(server {sl.get('server', '?')};"
                "CIS 7.2.1)")
        elif isinstance(faz, dict) and faz.get("status") == "enable":
            add("fgt-syslog", CAT, "warn",
                "syslog 未啟用,但 FortiAnalyzer 已啟用——集中日誌以 FAZ 達成"
                "(CIS 7.2.1 Audit 僅列 syslog,列注意)")
        else:
            add("fgt-syslog", CAT, "fail",
                f"遠端 syslog status={st or '未設'}"
                "(CIS 7.2.1/STIG 要求集中日誌)")

    ef = res("eventfilter")
    if ef is None:
        miss("fgt-event-logging", CAT, "事件日誌 eventfilter", "eventfilter")
    else:
        ev = ef.get("event") if isinstance(ef, dict) else None
        if ev is None:
            add("fgt-event-logging", CAT, "manual",
                "log eventfilter 缺 event 欄位,無法判定(CIS 7.1.1)")
        else:
            add("fgt-event-logging", CAT,
                "pass" if ev == "enable" else "fail",
                f"事件日誌 eventfilter event={ev}(CIS 7.1.1 要求 enable)")

    if faz is None:
        miss("fgt-faz-encryption", CAT, "FortiAnalyzer 傳輸加密", "faz")
    else:
        fst = faz.get("status") if isinstance(faz, dict) else None
        if fst != "enable":
            add("fgt-faz-encryption", CAT, "na",
                f"未使用 FortiAnalyzer(status={fst or '未設'};"
                "CIS 7.3.1 不適用)")
        else:
            rel, enc = faz.get("reliable"), faz.get("enc-algorithm")
            ok = rel == "enable" and enc == "high"
            add("fgt-faz-encryption", CAT, "pass" if ok else "fail",
                f"FAZ 傳輸 reliable={rel}、enc-algorithm={enc}"
                "(CIS 7.3.1:reliable enable 且 enc-algorithm high)")
    ai = res("auto_install")
    if ai is None:
        miss("fgt-usb-autoinstall", CAT, "USB 自動安裝", "auto_install")
    else:
        cfg, img = ai.get("auto-install-config"), ai.get("auto-install-image")
        ok = cfg == "disable" and img == "disable"
        add("fgt-usb-autoinstall", CAT, "pass" if ok else "fail",
            f"USB 自動安裝 config={cfg}、image={img}"
            "(CIS 2.1.7/STIG 要求 disable)")

    raw = (f"FortiGate 組態強化檢查(driver {DRIVER_VERSION},唯讀)\n"
           f"主機:{host.name}({host.ip_address})  FortiOS {ver}"
           f"  serial {serial}\n" + "\n".join(lines))
    if errors:
        raw += ("\n\n部分端點讀取失敗(相關項已標「人工」):\n  - "
                + "\n  - ".join(f"{k}: {v}" for k, v in errors.items()))

    result = {
        "script_version": DRIVER_VERSION,
        "family": "fortigate",
        "hostname": (res("global") or {}).get("hostname", host.name),
        "os": f"FortiOS {ver}",
        "kernel": f"serial {serial}",
        "slow": False,
        "items": items,
    }
    return raw, result
