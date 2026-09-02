"""網路設備類型註冊表:新增設備類型從這裡開始。

- 每類型對應一組獨立的**檢查項歸組**(catalog family);同類型多台設備
  檢查同一份目錄——「檢查項目」頁按 family 分頁。F5 ADC/WAF 同一型(BIG-IP)。
- Linux 主機為平台內建(不在本註冊表):檢查項歸組依發行版自動偵測分
  deb/rpm 兩組;Windows 與 AD 網域暫不納入。
- FortiGate 已實作(drivers/fortigate.py + 20 項目錄);其餘規劃中:
  類型/歸組/連線欄位(creds)先行建立,driver 與檢查項目錄待實作——
  動工前先做可行性盤點與來源查證(CIS/STIG/原廠 hardening guide,
  連線作法參考既有 driver 實作)。
- 每類型宣告自己的 creds(所需連線欄位):新增/編輯主機時依選取類型
  動態顯示對應欄位(前端依類型切換)。
"""
from __future__ import annotations

# 每類型所需連線欄位;(col, label, placeholder)
# col 對應 Host 欄位:username / password / api_key。新增/編輯頁依此動態顯示。
_TOKEN = [("api_key", "API Token", "設備 api-user 核發")]
_USERPASS = [("username", "帳號", ""), ("password", "密碼", "")]
_USERKEY = [("username", "帳號", ""), ("api_key", "API Token", "")]
_SSHPASS = [("username", "SSH 帳號", ""), ("password", "SSH 密碼", "")]

# key:內部識別(Host.device_type / driver 對應)
# label:UI 顯示;transport:連線方式
# port:該型預設管理埠;creds:所需連線欄位;implemented:driver 已實作
DEVICE_TYPES: list[dict] = [
    # 防火牆 / ADC / 網路設備
    {"key": "fortigate", "label": "FortiGate 防火牆", "transport": "REST API",
     "port": 443, "creds": _TOKEN, "implemented": True},
    {"key": "paloalto", "label": "PaloAlto 防火牆", "transport": "XML API",
     "port": 443, "creds": _TOKEN, "implemented": True},
    {"key": "f5", "label": "F5 BIG-IP", "transport": "iControl REST",
     "port": 443, "creds": _USERPASS, "implemented": True},
    {"key": "netscaler", "label": "Citrix NetScaler", "transport": "NITRO REST",
     "port": 443, "creds": _USERPASS, "implemented": True},
    {"key": "cisco", "label": "Cisco 交換器", "transport": "SSH CLI",
     "port": 22, "creds": _SSHPASS, "implemented": True},
    {"key": "aruba", "label": "Aruba 控制器", "transport": "REST API",
     "port": 443, "creds": _USERPASS, "implemented": True,
     "note": "對象為 Mobility Controller(AOS 8)。CIS 無控制器專屬 "
             "Benchmark,檢查項依 Aruba Hardening Guide / NDM SRG;"
             "CIS Aruba CX Switch 文件適用 AOS-CX 交換器,非本類型。"},
    # 管理 / 平台系統
    {"key": "vcenter", "label": "vCenter", "transport": "REST API",
     "port": 443, "creds": _USERPASS, "implemented": True},
    {"key": "netapp", "label": "NetApp ONTAP", "transport": "REST API",
     "port": 443, "creds": _USERPASS, "implemented": True},
    {"key": "cyberark", "label": "CyberArk PAM", "transport": "PVWA REST",
     "port": 443, "creds": _USERPASS, "implemented": False, "hidden": True,
     "note": "2026-08 真機盤點(PVWA 14.2 auditor):API 只讀版本/使用者/保險庫/"
             "平台清單,無設備強化組態端點(Configuration/password-policy 皆 404)。"
             "CyberArk 屬 PAM 應用非網路設備,其強化在 Windows OS 層 + 主原則,"
             "與本平台的 SNMP/NTP/SSH/TLS 類設備組態不同範疇;帳號治理面與 ERS 重疊。"
             "結論:不適用本平台的設備組態強化模型。"},
    {"key": "fortiauth", "label": "FortiAuthenticator", "transport": "SSH CLI",
     "port": 22, "creds": _SSHPASS, "implemented": True},
    {"key": "fortisiem", "label": "FortiSIEM(Rocky)", "transport": "SSH(Linux)",
     "port": 22, "creds": _SSHPASS, "implemented": False, "hidden": True,
     "note": "底層 OS 為 Rocky Linux 8.10(已真機驗證:root/bash/rpm/免密 sudo)。"
             "**直接以「Linux 主機 / SSH 連入」加入即可**,ucc_check.sh 自動走 rpm "
             "分支(實測 97 項),毋須專屬 driver。不要選本類型,改選「Linux 主機」。"},
]

# 連線方式歸類(UI 用):transport 以 SSH 開頭者走 SSH CLI,其餘走管理 API。
# 主機表單的類型下拉只標 [SSH] / [API](transport 細節不上 UI),模式說明段落亦依此切換。
for _t in DEVICE_TYPES:
    _t["conn"] = "ssh" if _t["transport"].startswith("SSH") else "api"

TYPE_LABEL = {t["key"]: t["label"] for t in DEVICE_TYPES}
CONN_LABEL = {"ssh": "SSH", "api": "API"}

# 前端依類型動態切換欄位:{key: {port, conn, creds:[[col,label,ph],...]}}
TYPE_SPEC = {
    t["key"]: {"port": t["port"], "conn": t["conn"],
               "creds": [[c, l, p] for c, l, p in t["creds"]]}
    for t in DEVICE_TYPES
}

# 檢查項歸組(family)→ 顯示名稱:「檢查項目」頁分頁依此渲染。
# 順序:Linux 兩組(內建、已實作)在前,網路設備類型在後。
# hidden 者不列入(該型不會有自己的檢查項目錄,列出來只會是空分頁)。
FAMILY_LABEL: dict[str, str] = {
    "deb": "Ubuntu / Debian",
    "rpm": "RHEL / Rocky",
}
for _t in DEVICE_TYPES:
    if not _t.get("hidden"):
        FAMILY_LABEL[_t["key"]] = _t["label"]

# 已有檢查項目錄的歸組(其餘為規劃中,「檢查項目」頁顯示待訂說明)
IMPLEMENTED_FAMILIES = {"deb", "rpm", "fortigate", "paloalto", "f5",
                        "netscaler", "vcenter", "cisco", "netapp", "aruba",
                        "fortiauth"}


def implemented_device_types() -> list[str]:
    """已有 driver 的設備類型 key 清單(主機表單可選)。"""
    return [t["key"] for t in DEVICE_TYPES if t["implemented"]]


def visible_device_types() -> list[dict]:
    """UI 上要呈現的設備類型(主機表單下拉、檢查項目分頁)。

    `hidden` 的類型不出現在任何選單:CyberArk 為「不適用本平台的設備組態
    強化模型」(結論已定,非待辦)、FortiSIEM 應改以「Linux 主機」加入。
    兩者若以「規劃中」之姿留在選單裡,會被誤讀成「之後會支援」而反覆被問。
    註冊表仍保留該筆與 note,供文件、盤點與日後翻案查考。
    """
    return [t for t in DEVICE_TYPES if not t.get("hidden")]
