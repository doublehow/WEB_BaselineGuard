"""應用設定:優先讀 config.json,其次環境變數 / .env。

- config.json 由 Web 設定頁(/settings)維護,是設定的權威來源。
- 存檔即就地更新記憶體單例,排程/檢查等功能立即讀到新值。
- config.json 含帳密(AD service account),已列入 .gitignore,切勿提交。
- 分工:每台主機的連線設定(IP/SSH 帳密/金鑰/Agent token)存 DB(hosts 表);
  此處為全域營運設定(AD 登入、排程、保留天數、Agent 檢查時間等)。
"""
from __future__ import annotations

import json
import secrets
import threading
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from pydantic_settings import (
    BaseSettings,
    JsonConfigSettingsSource,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_FILE = BASE_DIR / "config.json"

# 由設定頁管理、可持久化到 config.json 的欄位
UI_FIELDS = (
    # AD(NTLM)登入
    "ad_enabled",
    "ad_domain",
    "ad_servers",
    "ad_service_user",
    "ad_service_password",
    "ad_allowed_group",
    "ad_base_dn",
    "local_admin_password",
    "default_role",
    # 系統層告警(Telegram 群組 + SMTP 系統收件人)
    "smtp_host",
    "smtp_port",
    "smtp_tls",
    "smtp_user",
    "smtp_password",
    "smtp_from",
    "smtp_to",
    "telegram_bot_token",
    "telegram_chat_id",
    "alert_on_recovery",
    # 排程 / 保留 / Agent
    "scheduler_enabled",
    "log_retention_days",
    "agent_check_time",
    "agent_offline_hours",
    # 其他
    "timezone",
)

# 可持久化但不在設定頁顯示的內部欄位
_PERSIST_FIELDS = UI_FIELDS + ("session_secret",)

# 密碼類欄位:設定頁留空 = 不變更(避免把明碼 render 到 HTML)
SECRET_FIELDS = (
    "ad_service_password",
    "local_admin_password",
    "smtp_password",
    "telegram_bot_token",
)

# config.json 中以密文保存的欄位(記憶體單例一律持有明文)
_ENC_FIELDS = SECRET_FIELDS + ("session_secret",)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="UCC_",
        env_file=".env",
        env_file_encoding="utf-8",
        json_file=CONFIG_FILE,
        json_file_encoding="utf-8",
        extra="ignore",
    )

    # ---- AD(NTLM)驗證登入 ----
    ad_enabled: bool = False
    ad_domain: str = ""              # NetBIOS 名,例:CORP
    ad_servers: list[str] = []       # AD 伺服器 IP 清單(設定頁以逗號分隔)
    ad_service_user: str = ""        # 查詢使用者用的 service account
    ad_service_password: str = ""
    ad_allowed_group: str = ""       # 允許登入的群組
    ad_base_dn: str = ""             # 例:DC=example,DC=com;留空自動偵測
    local_admin_password: str = "admin"   # 本機備援登入(上線前務必改)
    default_role: str = "readonly"        # 未分權帳號的預設角色(見 auth.ROLE_LABELS)

    # 註:全域「預設 SSH 連線帳密」已於 2026-08 移除,SSH 憑證一律逐台填寫。
    # 既有 config.json 殘留的 default_ssh_* 鍵不影響載入(extra="ignore"),
    # 並由啟動時的 purge_obsolete_fields() 就地清除(內含憑證,不可留著)。

    # ---- 系統層告警(檢查失敗/Agent 失聯等營運事件)----
    smtp_host: str = ""
    smtp_port: int = 25       # 465 走 SMTPS(隱含 TLS),其他埠依 smtp_tls
    smtp_tls: bool = False    # STARTTLS(465 埠時忽略)
    smtp_user: str = ""       # 留空 = 不做 SMTP AUTH(內部 relay 常見)
    smtp_password: str = ""
    smtp_from: str = ""       # 寄件人;留空用 smtp_user 或 configcheck@<host>
    smtp_to: str = ""         # 系統告警收件人(逗號分隔)
    telegram_bot_token: str = ""   # BotFather 核發,形如 123456:ABC-...
    telegram_chat_id: str = ""     # 個人/群組 chat id(群組為負數)
    alert_on_recovery: bool = False  # 恢復正常時也通知(預設只在失敗時)

    # ---- 排程 / 保留 / Agent ----
    scheduler_enabled: bool = True   # 背景排程總開關(SSH 定期檢查 + 清理 + 失聯偵測)
    log_retention_days: int = 365    # 檢查/稽核紀錄保留天數(0 = 不自動清理;合規證跡建議 ≥1 年)
    agent_check_time: str = "06:30"  # Agent 每日檢查時間 HH:MM(烙進安裝腳本的 systemd timer)
    agent_offline_hours: int = 48    # Agent 超過 N 小時未回報視為失聯並告警(0 = 不偵測)

    # ---- 服務埠(改埠需重啟;不在設定頁,由 config.json / 環境變數 UCC_* 管理)----
    web_port: int = 8073        # Web UI(登入後操作介面)
    agent_api_port: int = 8074  # Agent 回報 API(token 驗證,無登入;僅 /install /script /report)

    # ---- 其他 ----
    timezone: str = "Asia/Taipei"    # IANA 名稱

    # ---- 內部(不在設定頁顯示)----
    session_secret: str = ""

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        # 優先序:初始化參數 > config.json > 環境變數 > .env
        return (
            init_settings,
            JsonConfigSettingsSource(settings_cls),
            env_settings,
            dotenv_settings,
        )


settings = Settings()

# 載入後就地解密 secret 欄位(config.json 存密文,記憶體持明文)
from app import secret_store  # noqa: E402 —— 置後避免循環匯入疑慮

for _f in _ENC_FIELDS:
    setattr(settings, _f, secret_store.decrypt(getattr(settings, _f)))


# 已移除功能殘留在 config.json 的欄位:啟動時清掉(其中含憑證,不可留著)
_OBSOLETE_FIELDS = (
    "default_ssh_username",
    "default_ssh_password",
    "default_ssh_key",
    "default_sudo_password",
)


def purge_obsolete_fields() -> None:
    """移除 config.json 中已廢除功能的殘留欄位(冪等)。

    save_settings() 是讀-改-寫,會保留檔內既有鍵 —— 光是把欄位從
    Settings 拿掉,舊值(含加密後的預設 SSH/sudo 密碼)會永遠留在檔案裡。
    這些是已不再使用的憑證素材,啟動時就地清除。
    """
    with _save_lock:
        data = _read_config_file()
        dropped = [f for f in _OBSOLETE_FIELDS if f in data]
        for f in dropped:
            data.pop(f, None)
        if dropped:
            CONFIG_FILE.write_text(
                json.dumps(data, ensure_ascii=False, indent=2),
                encoding="utf-8")
    if dropped:
        import logging
        logging.getLogger("ucc.secret").info(
            "已清除 config.json 內已廢除功能的殘留欄位:%s", ", ".join(dropped))


def migrate_plaintext_secrets() -> None:
    """啟動時把 config.json 既有明文 secret 就地改寫為密文(冪等)。"""
    with _save_lock:
        data = _read_config_file()
        changed = [f for f in _ENC_FIELDS
                   if data.get(f) and not secret_store.is_encrypted(data[f])]
        for f in changed:
            data[f] = secret_store.encrypt(data[f])
        if changed:
            CONFIG_FILE.write_text(
                json.dumps(data, ensure_ascii=False, indent=2),
                encoding="utf-8")
    if changed:
        import logging
        logging.getLogger("ucc.secret").info(
            "config.json 明文 secret 已改寫為密文:%s", ", ".join(changed))


def local_now() -> datetime:
    """settings.timezone 的當下時間(naive,DB 統一格式)。

    所有「取現在時間」一律經此函式,避免伺服器系統時區與
    settings.timezone 不一致時,DB 內混存兩種時間基準。
    """
    try:
        return datetime.now(ZoneInfo(settings.timezone)).replace(tzinfo=None)
    except Exception:  # noqa: BLE001 —— timezone 設錯時退回系統時區,不擋主流程
        return datetime.now()


def _read_config_file() -> dict:
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


_save_lock = threading.Lock()


def save_settings(updates: dict) -> None:
    """更新記憶體單例並持久化到 config.json(只接受可持久化欄位)。

    讀-改-寫全程持鎖,避免併發儲存互相覆蓋;
    secret 欄位落地前加密(記憶體單例維持明文供功能使用)。
    """
    with _save_lock:
        data = _read_config_file()
        for key, value in updates.items():
            if key not in _PERSIST_FIELDS:
                continue
            setattr(settings, key, value)
            data[key] = (secret_store.encrypt(value)
                         if key in _ENC_FIELDS and value else value)
        CONFIG_FILE.write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def ensure_session_secret() -> str:
    """回傳 session 簽章密鑰;不存在時自動生成並持久化(登入功能用)。"""
    if not settings.session_secret:
        save_settings({"session_secret": secrets.token_hex(32)})
    return settings.session_secret
