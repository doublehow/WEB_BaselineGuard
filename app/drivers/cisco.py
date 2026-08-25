"""Cisco IOS / IOS-XE 交換器組態強化檢查 driver v1.0(唯讀,SSH CLI)。

依據:CIS Cisco IOS XE 17.x Benchmark v2.2.1(條次與門檻已逐條核對原文,
比對紀錄見 sample/cis-compare-cisco.md)、DISA Cisco IOS Switch NDM STIG
交叉參照。範圍:管理面強化(AAA/vty/web/SSH/SNMP/NTP/日誌/banner/逾時);
L2/L3 轉發、VLAN、路由認證、資料面 ACL 不納入。

連線:SSH 帳密,privilege 15(讀
running-config 需要);超高 pty 避免分頁 + terminal length 0 雙保險;
完全不改設備組態(只下 show)。host key 自動信任(內網盤點用途)。
堆疊共用 config,收一次涵蓋整台。解析為純函式(parse_config,離線可測)。

v1.0.1 修正:
- running-config 讀取加尾端完整性檢查:IOS 的 show running-config 一律以
  單獨一行 `end` 收尾,讀不到 `end` 代表輸出中途被截斷 → 直接拋錯讓整輪
  標為失敗。原本靜默截斷,截斷點之後的 snmp-server community / banner /
  ntp 等設定會整批消失,產生一大批假的「符合」(最危險的假陰性)。
- 讀取上限 30 → 60 秒、無資料停止門檻 1.5 → 3 秒(大型 config 分段吐出時
  中途停頓超過 1.5 秒並不罕見)。
- cisco-vty-ssh 改為逐個 line vty 區塊判定:任一群組未設 transport input
  即標「注意」(舊版 IOS 預設允許 telnet),不再因為「有設的那組是 ssh」
  就判全部符合。

v1.1.0(2026-08-24,依 CIS IOS XE 17.x v2.2.1 原文逐條對齊):
- cisco-exec-timeout 假陽性修正:CIS 1.2.8 NOTE 明載「exec-timeout 設 10 分
  (預設值)時不會顯示在組態中」——未見 exec-timeout 行 = 預設 10 分 = 符合,
  原本判不符是誤報;另補抓 `no exec-timeout`(= 永不逾時)判不符。
- cisco-logging 未設遠端 syslog 由「注意」改「不符」(CIS 2.2.4 為 Automated)。
- cisco-ntp:CIS 2.3.2 Rationale 要求至少兩台(至佳三台),1 台改列注意。
- 新增 7 項:cisco-aaa-auth-login(1.1.2)、cisco-vty-acl(1.2.5)、
  cisco-user-secret(1.4.3)、cisco-ssh-ver(2.1.1.2)、
  cisco-timestamps(2.2.6)、cisco-login-log(2.2.8)、
  cisco-ntp-auth(2.3.1.1–2.3.1.3;未用 NTP 時不適用)。
"""
from __future__ import annotations

import re
import time

import paramiko

DRIVER_VERSION = "cisco-1.1.0"
CONNECT_TIMEOUT = 20
# SSH 類 driver 的讀取上限與 API 類(base.API_TIMEOUT=20)性質不同:
# 這裡要等設備把整份 running-config 逐段吐完,大型堆疊 config 可達數千行,
# 且 IOS 會在中途短暫停頓。60 秒總上限 + 3 秒無資料才收手,是為了避免
# 靜默截斷;截斷的組態會讓缺漏的設定被誤判成「未設定 = 符合」。
READ_TIMEOUT = 60
IDLE_STOP = 3.0
_WEAK_MAC = re.compile(r"hmac-sha1|hmac-md5|-96", re.I)
_WEAK_ENC = re.compile(r"3des|-cbc|arcfour|blowfish", re.I)


def _read(chan, timeout: float, idle_stop: float = IDLE_STOP) -> str:
    buf = ""
    last = time.time()
    end = time.time() + timeout
    while time.time() < end:
        if chan.recv_ready():
            data = chan.recv(65535)
            if not data:
                break
            buf += data.decode("utf-8", "replace")
            last = time.time()
        elif chan.closed or chan.exit_status_ready():
            while chan.recv_ready():
                buf += chan.recv(65535).decode("utf-8", "replace")
            break
        else:
            if time.time() - last > idle_stop:
                break
            time.sleep(0.2)
    return buf


def _config_complete(out: str) -> bool:
    """running-config 是否完整讀到結尾。

    IOS / IOS-XE 的 show running-config 一律以單獨一行 `end` 收尾,其後
    可能只剩 CLI 提示字元。尾端幾行找不到 `end` 就代表輸出被截斷——
    此時絕不可拿去判定:截斷點之後的設定行(snmp-server community、
    banner、ntp server…)會全部「看起來沒設定」,多數檢查項的邏輯會把
    它讀成符合。
    """
    tail = [l.strip() for l in out.strip().splitlines() if l.strip()]
    return any(l == "end" for l in tail[-5:])


def _connect(host) -> paramiko.SSHClient:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host.ip_address, port=host.ssh_port or 22,
                username=host.username, password=host.password,
                timeout=CONNECT_TIMEOUT, allow_agent=False, look_for_keys=False)
    return ssh


def _get_running_config(host) -> str:
    ssh = _connect(host)
    try:
        chan = ssh.invoke_shell(width=512, height=10000)
        _read(chan, 4, idle_stop=1.0)   # 只是清掉登入橫幅,不必等滿門檻
        chan.send("terminal length 0\n")
        time.sleep(0.4)
        _read(chan, 3, idle_stop=1.0)
        chan.send("show running-config\n")
        out = _read(chan, READ_TIMEOUT)
    finally:
        ssh.close()
    if "Invalid input" in out or "% " in out.split("show running-config")[-1][:200]:
        if "username" not in out and "line vty" not in out:
            raise RuntimeError("讀不到 running-config(帳號可能非 privilege 15)")
    if not _config_complete(out):
        # 寧可整輪標為失敗,也不拿截斷的組態產生假結果
        raise RuntimeError(
            f"running-config 讀取不完整(共 {len(out)} 字元,輸出未見結尾的 "
            "`end`,可能在傳輸中途被截斷)——本輪不予判定,請重試或確認"
            "設備分頁設定(terminal length 0)與網路穩定度")
    return out


def test(host) -> tuple[bool, str]:
    try:
        ssh = _connect(host)
        try:
            chan = ssh.invoke_shell(width=512, height=10000)
            out = _read(chan, 4, idle_stop=1.0)
        finally:
            ssh.close()
        return True, "SSH 連線成功(可登入;檢查時讀 running-config 需 privilege 15)"
    except paramiko.AuthenticationException:
        return False, "SSH 認證失敗(帳號或密碼錯誤)"
    except Exception as exc:  # noqa: BLE001
        return False, f"SSH 連線失敗:{type(exc).__name__}: {exc}"


# ──────────────────────────────────────────────────────────────────
# 解析(純函式,離線可測)
# ──────────────────────────────────────────────────────────────────

def _line_blocks(cfg: str, kind: str = "vty") -> list[tuple[str, list[str]]]:
    """切出 running-config 的 `line <kind> ...` 區塊,回 [(標頭, 子命令行)]。

    IOS 把 line 區塊的子命令縮排一格,區塊以 `!` 或下一個頂層命令結束。
    逐區塊看待是必要的:`line vty 0 4` 與 `line vty 5 15` 是兩組獨立設定,
    只看「有出現過的 transport input」會漏掉沒設的那組(舊版 IOS 預設
    允許 telnet)。
    """
    blocks: list[tuple[str, list[str]]] = []
    name: str | None = None
    body: list[str] = []
    for raw in cfg.splitlines():
        stripped = raw.strip()
        indented = raw[:1] in (" ", "\t")
        if not indented and re.match(r"^line\s+\S+", stripped):
            if name is not None:
                blocks.append((name, body))
            name, body = stripped, []
            continue
        if name is None:
            continue
        if indented and stripped:
            body.append(stripped)
        elif stripped:            # 回到頂層命令(含 `!`)→ 區塊結束
            blocks.append((name, body))
            name, body = None, []
    if name is not None:
        blocks.append((name, body))
    return [(n, b) for n, b in blocks if re.match(rf"^line\s+{kind}\b", n)]


def parse_config(cfg: str) -> list[dict]:
    """running-config → 檢查項結果清單(不依賴連線,可單測)。"""
    lines = cfg.splitlines()
    items: list[dict] = []

    def add(iid, cat, status, desc):
        items.append({"id": iid, "cat": cat, "status": status, "desc": desc})

    def has(pat):
        return any(re.search(pat, l) for l in lines)

    # ===== 1. 管理服務 =====
    CAT = "1. 管理服務"
    http_on = has(r"^\s*ip http server\b") and not has(r"^\s*no ip http server")
    https_on = has(r"^\s*ip http secure-server\b") and not has(r"^\s*no ip http secure-server")
    if not http_on and (not https_on or has(r"ip http access-class")):
        add("cisco-web-mgmt", CAT, "pass",
            "Web 管理已關閉或受限(no ip http server / secure-server 受 access-class)")
    else:
        add("cisco-web-mgmt", CAT, "fail",
            f"Web 管理開放(http={'on' if http_on else 'off'}、"
            f"https={'on' if https_on else 'off'} 無 access-class;"
            "STIG 應關閉或限制,CIS 1.2.9 另要求 max-connections)")

    # vty transport:逐個 line vty 區塊判定——每一組都必須明確僅允許 ssh。
    # 只要有任一組沒設 transport input,就不能判符合(舊版 IOS 預設允許
    # telnet,常見情境是只設了 line vty 0 4、漏掉 line vty 5 15)。
    vty_blocks = _line_blocks(cfg, "vty")
    if not vty_blocks:
        add("cisco-vty-ssh", CAT, "manual",
            "未找到 line vty 區塊(組態格式非預期),請人工確認 VTY 傳輸協定")
        add("cisco-vty-acl", CAT, "manual",
            "未找到 line vty 區塊(組態格式非預期),請人工確認 access-class")
    else:
        bad_vty, undef_vty = [], []
        for name, body in vty_blocks:
            ti = None
            for l in body:
                m = re.match(r"transport input\s+(.+)", l)
                if m:
                    ti = m.group(1).strip()
            if ti is None:
                undef_vty.append(name)
            elif "telnet" in ti or "all" in ti:
                bad_vty.append(f"{name}({ti})")
        if bad_vty:
            add("cisco-vty-ssh", CAT, "fail",
                f"VTY 允許非 SSH 傳輸:{'、'.join(bad_vty)}(CIS 1.2.2 應僅 ssh)")
        elif undef_vty:
            add("cisco-vty-ssh", CAT, "warn",
                f"以下 VTY 群組未設 transport input,採 IOS 預設:"
                f"{'、'.join(undef_vty)}——舊版 IOS 預設允許 telnet,"
                "請人工確認該版本的預設值(CIS 1.2.2 應明確設為僅 ssh)")
        else:
            add("cisco-vty-ssh", CAT, "pass",
                f"全部 {len(vty_blocks)} 組 VTY 皆明確僅允許 SSH"
                "(transport input ssh;CIS 1.2.2)")

        # CIS 1.2.5:每組 VTY 皆須 access-class 限制來源
        no_acl = [n for n, b in vty_blocks
                  if not any(re.match(r"access-class\s+\S+\s+in", l)
                             for l in b)]
        add("cisco-vty-acl", CAT, "fail" if no_acl else "pass",
            f"以下 VTY 群組未設 access-class 來源限制:{'、'.join(no_acl)}"
            "(CIS 1.2.5)" if no_acl
            else f"全部 {len(vty_blocks)} 組 VTY 皆設 access-class(CIS 1.2.5)")

    # ===== 2. SSH 演算法 =====
    CAT = "2. SSH 演算法"
    mac_lines = " ".join(re.findall(r"ip ssh server algorithm mac (.+)", cfg))
    enc_lines = " ".join(re.findall(r"ip ssh server algorithm encryption (.+)", cfg))
    if mac_lines or enc_lines:
        weak = []
        if mac_lines and _WEAK_MAC.search(mac_lines):
            weak.append("MAC")
        if enc_lines and _WEAK_ENC.search(enc_lines):
            weak.append("加密")
        add("cisco-ssh-algo", CAT, "fail" if weak else "pass",
            f"SSH 演算法含弱項:{'/'.join(weak)}(應移除 sha1/md5/3des/cbc)" if weak
            else "SSH 伺服器演算法無弱項(MAC/加密)")
    else:
        add("cisco-ssh-algo", CAT, "manual",
            "未明列 SSH 演算法(採 IOS 預設)——請依 IOS 版本人工確認無弱演算法"
            "(STIG;CIS 17.x 無演算法專條)")

    # CIS 2.1.1.2:僅用 SSH v2(未明設時啟用 SSH 為 v1/v2 相容模式)
    if has(r"^\s*ip ssh version 2\b"):
        add("cisco-ssh-ver", CAT, "pass", "已明設 ip ssh version 2(CIS 2.1.1.2)")
    else:
        add("cisco-ssh-ver", CAT, "warn",
            "未明設 ip ssh version 2——IOS 啟用 SSH 時預設為 v1/v2 相容模式"
            "(CIS 2.1.1.2 要求僅 v2)")

    # ===== 3. 密碼保護 =====
    CAT = "3. 密碼保護"
    add("cisco-pwd-encryption", CAT,
        "pass" if has(r"^\s*service password-encryption") else "fail",
        "service password-encryption 已啟用" if has(r"^\s*service password-encryption")
        else "未啟用 service password-encryption(CIS)")
    if has(r"^\s*enable secret"):
        add("cisco-enable-secret", CAT, "pass",
            "已設 enable secret(強雜湊;CIS 1.4.1)")
    elif has(r"^\s*enable password"):
        add("cisco-enable-secret", CAT, "fail",
            "使用 enable password(弱)而非 enable secret(CIS 1.4.1)")
    else:
        add("cisco-enable-secret", CAT, "warn", "未設 enable secret/password")

    # CIS 1.4.3:本機帳號一律用 username ... secret(不可用 password)
    user_lines = [l for l in lines if re.match(r"^\s*username\s+\S+", l)]
    weak_users = [l.split()[1] for l in user_lines
                  if re.search(r"\bpassword\b", l)]
    if not user_lines:
        add("cisco-user-secret", CAT, "na",
            "未定義本機 username(全走 AAA 遠端認證時屬正常;CIS 1.4.3)")
    elif weak_users:
        add("cisco-user-secret", CAT, "fail",
            f"本機帳號使用弱儲存 username password:{'、'.join(weak_users)}"
            "(CIS 1.4.3 應一律 username secret)")
    else:
        add("cisco-user-secret", CAT, "pass",
            f"全部 {len(user_lines)} 個本機帳號皆用 username secret(CIS 1.4.3)")

    # ===== 4. SNMP =====
    CAT = "4. SNMP"
    comm = re.findall(r"^\s*snmp-server community\s", cfg, re.M)
    add("cisco-snmp-community", CAT, "fail" if comm else "pass",
        f"SNMP v1/v2c community {len(comm)} 組(應停用改 v3;"
        "CIS 1.5.1–1.5.3/STIG,平台較嚴禁用全部 community)" if comm
        else "無 SNMP v1/v2c community(CIS 1.5.1–1.5.3)")

    # ===== 5. 時間 / 日誌 =====
    CAT = "5. 時間與日誌"
    ntp = re.findall(r"^\s*ntp server\s", cfg, re.M)
    if len(ntp) >= 2:
        add("cisco-ntp", CAT, "pass",
            f"NTP 伺服器 {len(ntp)} 台(CIS 2.3.2:至少兩台)")
    elif ntp:
        add("cisco-ntp", CAT, "warn",
            "NTP 僅 1 台(CIS 2.3.2 Rationale 要求至少兩台;列注意)")
    else:
        add("cisco-ntp", CAT, "fail", "未設定 NTP(CIS 2.3.2/STIG)")

    # CIS 2.3.1.1–2.3.1.3:NTP 認證三件組(未用 NTP 時不適用)
    if not ntp:
        add("cisco-ntp-auth", CAT, "na",
            "未設定 NTP 伺服器,NTP 認證不適用(先修正 cisco-ntp)")
    else:
        ntp_missing = [name for pat, name in (
            (r"^\s*ntp authenticate\b", "ntp authenticate"),
            (r"^\s*ntp authentication-key\s", "ntp authentication-key"),
            (r"^\s*ntp trusted-key\s", "ntp trusted-key"),
        ) if not has(pat)]
        add("cisco-ntp-auth", CAT, "fail" if ntp_missing else "pass",
            f"NTP 認證未完整:缺 {'、'.join(ntp_missing)}"
            "(CIS 2.3.1.1–2.3.1.3)" if ntp_missing
            else "NTP 認證已設定(authenticate/authentication-key/trusted-key;"
                 "CIS 2.3.1.1–2.3.1.3)")

    log = re.findall(r"^\s*logging (host|server)?\s*\d", cfg, re.M) or \
        re.findall(r"^\s*logging host\s", cfg, re.M)
    add("cisco-logging", CAT, "pass" if log else "fail",
        f"遠端 syslog {len(log)} 台已設定(CIS 2.2.4)" if log
        else "未設定遠端 syslog(CIS 2.2.4/STIG)")

    # CIS 2.2.6:debug 訊息時間戳
    if has(r"^\s*service timestamps debug datetime"):
        add("cisco-timestamps", CAT, "pass",
            "service timestamps debug datetime 已設定(CIS 2.2.6)")
    elif has(r"^\s*service timestamps log datetime"):
        add("cisco-timestamps", CAT, "warn",
            "僅設 log datetime 時間戳,缺 debug datetime(CIS 2.2.6)")
    else:
        add("cisco-timestamps", CAT, "fail",
            "未設 service timestamps debug datetime(CIS 2.2.6)")

    # CIS 2.2.8:登入成功/失敗記錄
    login_missing = [name for pat, name in (
        (r"^\s*login on-failure log", "login on-failure log"),
        (r"^\s*login on-success log", "login on-success log"),
    ) if not has(pat)]
    add("cisco-login-log", CAT, "fail" if login_missing else "pass",
        f"登入稽核記錄未完整:缺 {'、'.join(login_missing)}(CIS 2.2.8)"
        if login_missing
        else "登入成功/失敗皆記錄(login on-success/on-failure log;CIS 2.2.8)")

    # ===== 6. AAA / Banner / 逾時 =====
    CAT = "6. AAA / 橫幅 / 逾時"
    add("cisco-aaa", CAT, "pass" if has(r"^\s*aaa new-model") else "fail",
        "aaa new-model 已啟用(CIS 1.1.1)" if has(r"^\s*aaa new-model")
        else "未啟用 aaa new-model(CIS 1.1.1)")
    add("cisco-aaa-auth-login", CAT,
        "pass" if has(r"^\s*aaa authentication login\s") else "fail",
        "aaa authentication login 已設定(CIS 1.1.2)"
        if has(r"^\s*aaa authentication login\s")
        else "未設 aaa authentication login(CIS 1.1.2;預設停用)")
    add("cisco-banner", CAT,
        "pass" if has(r"^\s*banner (motd|login|exec)") else "fail",
        "已設登入橫幅 banner(CIS 1.3.1–1.3.3)"
        if has(r"^\s*banner (motd|login|exec)")
        else "未設登入橫幅(CIS 1.3.1–1.3.3/STIG)")
    # exec-timeout:任一 >10 分、=0 0(永不逾時)或 no exec-timeout 判不符。
    # CIS 1.2.8 NOTE:exec-timeout 設 10 分(IOS 預設)時不會顯示在組態中,
    # 故「完全沒有 exec-timeout 行」= 全部採預設 10 分 = 符合(原判不符是誤報)
    tos = [(int(a), int(b)) for a, b in re.findall(r"exec-timeout (\d+) (\d+)", cfg)]
    no_to = re.findall(r"^\s+no exec-timeout", cfg, re.M)
    bad = [f"{m}分{s}秒" for m, s in tos if m == 0 and s == 0 or m > 10]
    if no_to:
        bad.append(f"no exec-timeout ×{len(no_to)}(永不逾時)")
    if bad:
        add("cisco-exec-timeout", CAT, "fail",
            f"部分 line exec-timeout 過長/停用:{bad}"
            "(CIS 1.2.6–1.2.8:≤10 分)")
    elif tos:
        add("cisco-exec-timeout", CAT, "pass",
            f"所有明設的 exec-timeout ≤10 分(共 {len(tos)} 條;"
            "未明設的 line 採 IOS 預設 10 分;CIS 1.2.6–1.2.8)")
    else:
        add("cisco-exec-timeout", CAT, "pass",
            "未見 exec-timeout 行——IOS 預設 10 分且預設值不顯示於組態"
            "(CIS 1.2.8 NOTE),符合 ≤10 分")

    return items


def inspect(host) -> tuple[str, dict]:
    cfg = _get_running_config(host)
    items = parse_config(cfg)

    lines = []
    for it in items:
        mark = {"pass": "[符合]", "fail": "[不符]", "warn": "[注意]",
                "manual": "[人工]", "na": "[不適用]"}[it["status"]]
        lines.append(f"  {mark} {it['desc']}")
    # 主機名(running-config 的 hostname 行)
    m = re.search(r"^hostname (\S+)", cfg, re.M)
    hn = m.group(1) if m else host.name
    raw = (f"Cisco 交換器組態強化檢查(driver {DRIVER_VERSION},唯讀)\n"
           f"主機:{host.name}({host.ip_address})  hostname {hn}\n"
           + "\n".join(lines))

    result = {
        "script_version": DRIVER_VERSION,
        "family": "cisco",
        "hostname": hn,
        "os": "Cisco IOS / IOS-XE",
        "kernel": "",
        "slow": False,
        "items": items,
    }
    return raw, result
