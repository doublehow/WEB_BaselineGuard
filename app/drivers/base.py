"""網路設備 driver 共用連線工具。

沿用 ERS 既有連線方式,讓各設備 driver 一致:
- base_url():組管理 API base URL(host 可含 scheme;443/80 省略埠)。
- device_base_url():上層包裝,統一處理「ssh_port 借用為管理埠」的慣例。
- ssl_verify():httpx 的 verify 參數;舊 appliance(如 NetScaler)管理憑證
  弱加密套件需放寬 SECLEVEL=1,否則 OpenSSL 3.x 預設 SECLEVEL 2 會
  SSL 握手失敗;TLS 版本下限維持預設(1.2),不放行過時協定。
- to_int():設備 API 數值欄位的安全轉換(轉不了回 None,讓呼叫端標「人工」)。
- API_TIMEOUT:API 類 driver 共用逾時。

本平台的設備連線設定存 Host:ip_address(host)、ssh_port(管理埠,443
   時省略)、api_key(token)。目前一律不驗設備自簽憑證(verify_ssl 概念
   對應 ERS 的 verify_ssl=False),故 ssl_verify() 回放寬 context。
"""
from __future__ import annotations

import ssl

# API 類 driver(fortigate/paloalto/f5/netscaler/vcenter/netapp/aruba)共用逾時。
# 取值理由:內網設備管理 API 正常回應 <2 秒,20 秒足以容忍 appliance 忙碌、
# 憑證放寬(SECLEVEL=1)造成的額外握手成本,以及 Aruba showcommand 這類
# 需控制器現算的指令;同時不至於讓單一端點卡死整輪(單機 6~10 個端點)。
# SSH 類 driver(cisco/fortiauth)另有自己的連線/讀取上限——那裡要等設備把
# 整份 running-config 吐完,性質不同,見各檔說明。
API_TIMEOUT = 20.0


def base_url(host, default_port: int = 443, scheme: str = "https") -> str:
    """組設備管理 API base URL。ip_address 可含 scheme(反向代理/測試環境)。"""
    h = (host.ip_address or "").strip().rstrip("/")
    if h.startswith(("http://", "https://")):
        return h
    port = host.ssh_port or default_port
    if port in (443, 80):
        return f"{scheme}://{h}"
    return f"{scheme}://{h}:{port}"


def device_base_url(host, default_port: int = 443, scheme: str = "https") -> str:
    """網路設備管理 API base URL(各 API 類 driver 共用)。

    Host.ssh_port 這個欄位對 Linux 主機是 SSH 埠,對網路設備借用為「管理埠」;
    未設或仍是 Linux 預設值 22 時視為「未指定管理埠」,改用 default_port
    (多數設備 443;Aruba 控制器 4343)。其餘處理(ip_address 可含 scheme 的
    反向代理寫法、443/80 省略埠)一律沿用 base_url(),避免各 driver 各自
    拼字串而行為分歧。
    """
    port = host.ssh_port if host.ssh_port and host.ssh_port != 22 else default_port
    tmp = type("_H", (), {"ip_address": host.ip_address, "ssh_port": port})()
    return base_url(tmp, default_port=default_port, scheme=scheme)


def to_int(value, default=None):
    """安全轉整數;轉不了一律回 default(預設 None)。

    設備 API 的數值欄位常以字串回傳,且不同版本可能給出 ""、"unlimited"、
    "never" 這類非數字。直接 int() 會讓整輪檢查以 ValueError 中斷;回 None
    則讓呼叫端依 fail-safe 原則標「人工」,絕不因此判成符合。
    """
    if value is None or isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        return default
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return int(float(text))
    except ValueError:
        return default


def ssl_verify(verify: bool = False):
    """httpx 的 verify 參數(比照 ERS base.ssl_verify)。

    verify=True → 嚴格驗證;False → 放寬 SSLContext(不驗憑證 + SECLEVEL=1),
    相容舊 appliance 弱加密套件(如某些 NetScaler 預設管理憑證)。
    """
    if verify:
        return True
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("DEFAULT@SECLEVEL=1")
    except ssl.SSLError:
        pass
    return ctx
