"""網路設備檢查 driver 註冊表。

每個 driver 模組實作:
- test(host) -> (ok: bool, message: str):測試連線(不執行檢查)。
- inspect(host) -> (raw_text: str, data: dict):執行唯讀檢查,回傳
  人類可讀報告與結果 dict(family/os/hostname/items,形狀同 ucc_check.sh
  的 JSON 輸出);入庫走共用的 checker.save_report。
driver 只負責「打設備、評估、正規化」。
"""
from app.drivers import (
    aruba, cisco, f5, fortiauth, fortigate, netapp, netscaler, paloalto,
    vcenter,
)

DRIVERS = {
    "fortigate": fortigate,
    "paloalto": paloalto,
    "f5": f5,
    "netscaler": netscaler,
    "vcenter": vcenter,
    "cisco": cisco,
    "netapp": netapp,
    "aruba": aruba,
    "fortiauth": fortiauth,
}


def get(device_type: str):
    """取設備 driver;未實作的類型回 None。"""
    return DRIVERS.get(device_type)
