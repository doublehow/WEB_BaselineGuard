"""FortiAuthenticator(FAC)組態強化檢查 driver v1.0(唯讀,SSH CLI)。

FAC 的管理面組態多在 GUI;CLI(FortiOS 受限)僅 `show full-configuration`
吐出 router/interface/dns/global/ha 等區段。本 driver 檢查 CLI 可得的
管理面強化項:管理服務(allowaccess 明文)、管理來源限制(allowed-hosts)、
維護帳號(admin-maintainer)、DNS、時區。**SNMP/NTP/密碼原則為 GUI-only,
CLI 不提供,不在本 driver 範圍**(盤點文件載明)。

依據:FortiAuthenticator Admin Guide / FortiOS 通用強化、NDM SRG(章級)。
連線:SSH keyboard-interactive(FAC 僅此認證)+ 管理員帳密;只下 show,零改動。

v1.0.1 修正:
- show full-configuration 讀取加尾端完整性檢查(FortiOS CLI 以單獨一行
  `end` 收尾)。原本只驗開頭有 `config system`,輸出中途被截斷時後半段
  設定會整批消失,parse_config 會把它們讀成「未設定」而產生假結果。
- 讀取上限 15 → 60 秒、無資料停止門檻 1.8 → 3 秒。
"""
from __future__ import annotations

import re
import time

import paramiko

DRIVER_VERSION = "fac-1.0.1"
CONNECT_TIMEOUT = 20
# SSH 類 driver 的讀取上限與 API 類(base.API_TIMEOUT=20)性質不同:
# 這裡要等 FAC 把整份 full-configuration 逐段吐完,中途停頓不罕見。
# 60 秒總上限 + 3 秒無資料才收手,避免靜默截斷造成假結果。
READ_TIMEOUT = 60
IDLE_STOP = 3.0


def _kbd(password):
    def handler(title, instructions, prompt_list):
        return [password for _ in prompt_list]
    return handler


def _read(chan, timeout: float, idle_stop: float = IDLE_STOP) -> str:
    buf = ""
    last = time.time()
    end = time.time() + timeout
    while time.time() < end:
        if chan.recv_ready():
            buf += chan.recv(65535).decode("utf-8", "replace")
            last = time.time()
        elif chan.closed:
            break
        else:
            if time.time() - last > idle_stop:
                break
            time.sleep(0.2)
    return buf


def _config_complete(out: str) -> bool:
    """full-configuration 是否完整讀到結尾。

    FortiOS CLI 的 show full-configuration 以單獨一行 `end` 收尾(最後一個
    config 區段的結束),其後可能只剩提示字元。尾端幾行找不到 `end` 就是
    輸出被截斷——截斷後的區段會「看起來沒設定」,parse_config 會把
    fac-dns / fac-timezone / fac-allowed-hosts 等判成不符或漏判。
    """
    tail = [l.strip() for l in out.strip().splitlines() if l.strip()]
    return any(l == "end" for l in tail[-5:])


def _open(host):
    """回傳已認證的 paramiko Transport(FAC keyboard-interactive)。"""
    from app.checker import verify_hostkey   # 函式內匯入避免載入順序耦合
    tp = paramiko.Transport((host.ip_address, host.ssh_port or 22))
    tp.start_client(timeout=CONNECT_TIMEOUT)
    try:
        verify_hostkey(host, tp.get_remote_server_key())   # 認證前 TOFU 檢核
    except Exception:
        tp.close()
        raise
    tp.auth_interactive(host.username, _kbd(host.password))
    return tp


def _get_config(host) -> str:
    tp = _open(host)
    try:
        chan = tp.open_session()
        chan.get_pty(width=512, height=100000)
        chan.invoke_shell()
        _read(chan, 3, idle_stop=1.0)   # 只是清掉登入橫幅,不必等滿門檻
        chan.send("show full-configuration\n")
        out = _read(chan, READ_TIMEOUT)
    finally:
        tp.close()
    return out


def test(host) -> tuple[bool, str]:
    try:
        tp = _open(host)
        try:
            chan = tp.open_session()
            chan.get_pty(width=256, height=1000)
            chan.invoke_shell()
            _read(chan, 3, idle_stop=1.0)
            chan.send("get system status\n")
            out = _read(chan, 6)
        finally:
            tp.close()
        m = re.search(r"Version:\s*(\S+)", out)
        return True, f"連線成功:FAC {m.group(1) if m else 'CLI 可讀'}"
    except paramiko.AuthenticationException:
        return False, "SSH 認證失敗(帳號或密碼錯誤)"
    except Exception as exc:  # noqa: BLE001
        return False, f"SSH 連線失敗:{type(exc).__name__}: {exc}"


def parse_config(cfg: str) -> list[dict]:
    """show full-configuration → 檢查項(純函式,離線可測)。"""
    items: list[dict] = []

    def add(iid, cat, status, desc):
        items.append({"id": iid, "cat": cat, "status": status, "desc": desc})

    # 抓 config system global 區段
    gm = re.search(r"config system global(.*?)\nend", cfg, re.S)
    global_block = gm.group(1) if gm else ""

    # ===== 1. 管理介面存取 =====
    CAT = "1. 管理介面存取"
    # 各 interface 的 allowaccess(不得含 telnet/http 明文)
    allow_lines = re.findall(r"set allowaccess ([^\n]+)", cfg)
    bad = []
    for line in allow_lines:
        svcs = line.split()
        weak = [s for s in svcs if s in ("telnet", "http")]
        if weak:
            bad.append("/".join(weak))
    if allow_lines:
        add("fac-mgmt-access", CAT, "fail" if bad else "pass",
            (f"管理介面開放明文服務:{bad}(應僅 ssh/https)" if bad
             else f"管理介面僅加密服務(共 {len(allow_lines)} 介面,無 telnet/http)"))
    else:
        add("fac-mgmt-access", CAT, "manual", "未取得 interface allowaccess")
    # allowed-hosts:限制管理來源
    if re.search(r"set allowed-hosts \S", global_block):
        hosts = re.search(r"set allowed-hosts ([^\n]+)", global_block).group(1)
        add("fac-allowed-hosts", CAT, "pass",
            f"管理來源已限制 allowed-hosts={hosts.strip()}")
    else:
        add("fac-allowed-hosts", CAT, "fail",
            "未限制管理來源 allowed-hosts(SRG 建議限管理網段)")

    # ===== 2. 帳號 =====
    CAT = "2. 帳號"
    # admin-maintainer:主控台維護帳號(可繞過重設密碼)——STIG 建議停用
    mm = re.search(r"set admin-maintainer (\w+)", global_block)
    if mm:
        on = mm.group(1).lower() == "enabled"
        add("fac-admin-maintainer", CAT, "fail" if on else "pass",
            f"維護帳號 admin-maintainer={mm.group(1)}"
            "(STIG:主控台維護帳號可重設密碼,建議停用)")
    else:
        add("fac-admin-maintainer", CAT, "manual",
            "未取得 admin-maintainer 設定")

    # ===== 3. 系統 =====
    CAT = "3. 系統"
    dm = re.search(r"config system dns(.*?)\nend", cfg, re.S)
    dns_primary = re.search(r"set primary (\S+)", dm.group(1)) if dm else None
    add("fac-dns", CAT, "pass" if dns_primary else "fail",
        f"DNS 已設定(primary {dns_primary.group(1)})" if dns_primary
        else "DNS 未設定")
    tz = re.search(r"set timezone (\S+)", global_block)
    add("fac-timezone", CAT, "pass" if tz else "fail",
        f"時區已設定 timezone={tz.group(1)}" if tz else "時區未設定")

    return items


def inspect(host) -> tuple[str, dict]:
    cfg = _get_config(host)
    if "config system" not in cfg:
        raise RuntimeError("未取得組態(show full-configuration 無輸出;"
                           "請確認帳號可執行 show)")
    if not _config_complete(cfg):
        # 寧可整輪標為失敗,也不拿截斷的組態產生假結果
        raise RuntimeError(
            f"組態讀取不完整(共 {len(cfg)} 字元,輸出未見結尾的 `end`,"
            "可能在傳輸中途被截斷)——本輪不予判定,請重試")
    items = parse_config(cfg)
    lines = []
    for it in items:
        mark = {"pass": "[符合]", "fail": "[不符]", "warn": "[注意]",
                "manual": "[人工]", "na": "[不適用]"}[it["status"]]
        lines.append(f"  {mark} {it['desc']}")
    raw = (f"FortiAuthenticator 組態強化檢查(driver {DRIVER_VERSION},唯讀)\n"
           f"主機:{host.name}({host.ip_address})\n"
           "註:SNMP/NTP/密碼原則為 FAC GUI-only,CLI 不提供,不在檢查範圍。\n"
           + "\n".join(lines))
    result = {
        "script_version": DRIVER_VERSION,
        "family": "fortiauth",
        "hostname": host.name,
        "os": "FortiAuthenticator",
        "kernel": "",
        "slow": False,
        "items": items,
    }
    return raw, result
