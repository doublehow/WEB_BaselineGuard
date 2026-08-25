"""資料模型(SQLAlchemy 2.0 風格)。

- Host:受檢主機(agent 回報 / ssh 連入 兩種模式;憑證以 EncryptedStr 落地)
- CheckRun:單次檢查執行(host_name 名稱快照,主機刪除後紀錄仍可讀)
- CheckResult:單一檢查項結果(item_id 為腳本內的穩定 ID,跨主機彙總用)
- AccountRole / AuditLog:帳號分權與稽核
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from app.config import local_now
from app.secret_store import EncryptedStr


class Base(DeclarativeBase):
    pass


# ---- 標籤字典(模板顯示用,與 model 並置)----
MODE_LABELS = {"agent": "Agent 回報", "ssh": "SSH 連入", "api": "API 連入"}
RUN_STATUS_LABELS = {"running": "執行中", "success": "完成", "failed": "失敗"}
STATUS_LABELS = {"pass": "符合", "fail": "不符", "warn": "注意",
                 "manual": "人工", "na": "不適用"}
# 對應 base.html 的語意 badge 色
STATUS_CSS = {"pass": "allow", "fail": "deny", "warn": "warn",
              "manual": "manual", "na": "muted"}
STATUS_ORDER = ("fail", "warn", "manual", "pass", "na")   # 檢視時的預設排序


class Host(Base):
    __tablename__ = "hosts"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    mode: Mapped[str] = mapped_column(String(10), default="ssh")  # agent / ssh / api
    device_type: Mapped[str] = mapped_column(String(20), default="linux")  # linux 或 devtypes key
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    note: Mapped[str] = mapped_column(String(300), default="")

    # SSH 模式連線設定(agent 模式僅需 token)
    #
    # EncryptedStr 欄位的宣告長度指的是**密文**長度:密文 = 7 字前綴 +
    # base64(16 nonce + 16 tag + 明文長度) ≒ 明文 × 1.4 + 40。原本的
    # String(500) 只容得下 337 字明文、String(8000) 容不下一支 8192-bit
    # RSA 私鑰(約 6,000 字 → 密文約 8,440 字)。SQLite 不強制長度所以現況
    # 不會炸,但欄位語意不成立 —— 這裡一律按 ceil(明文上限 × 1.4)+ 40 放寬。
    ip_address: Mapped[str] = mapped_column(String(100), default="")
    ssh_port: Mapped[int] = mapped_column(Integer, default=22)
    username: Mapped[str] = mapped_column(String(100), default="")
    password: Mapped[str] = mapped_column(EncryptedStr(1000), default="")
    private_key: Mapped[str] = mapped_column(EncryptedStr(16000), default="")
    sudo_password: Mapped[str] = mapped_column(EncryptedStr(1000), default="")
    interval_minutes: Mapped[int] = mapped_column(Integer, default=1440)  # SSH 排程間隔(0=不排程)
    slow_scan: Mapped[bool] = mapped_column(Boolean, default=False)       # 排程時是否含全磁碟掃描

    # Agent 模式:回報 token(安裝指令綁定)
    agent_token: Mapped[str] = mapped_column(EncryptedStr(1000), default="")

    # API 模式(網路設備):設備 API token / 金鑰
    api_key: Mapped[str] = mapped_column(EncryptedStr(1000), default="")

    # 最近一次檢查摘要(由 checker.save_report 維護)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_run_status: Mapped[str] = mapped_column(String(10), default="")   # success/failed
    reported_hostname: Mapped[str] = mapped_column(String(200), default="")
    os_name: Mapped[str] = mapped_column(String(200), default="")
    kernel: Mapped[str] = mapped_column(String(100), default="")
    script_version: Mapped[str] = mapped_column(String(20), default="")
    offline_alerted: Mapped[bool] = mapped_column(Boolean, default=False)  # 失聯告警已發(去重)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=local_now)

    runs: Mapped[list["CheckRun"]] = relationship(
        back_populates="host", cascade="all, delete-orphan")

    @property
    def mode_label(self) -> str:
        return MODE_LABELS.get(self.mode, self.mode)

    @property
    def type_label(self) -> str:
        if self.device_type == "linux":
            return "Linux 主機"
        from app.devtypes import TYPE_LABEL
        return TYPE_LABEL.get(self.device_type, self.device_type)


class CheckRun(Base):
    __tablename__ = "check_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(
        ForeignKey("hosts.id", ondelete="CASCADE"))
    host_name: Mapped[str] = mapped_column(String(100), default="")  # 名稱快照
    mode: Mapped[str] = mapped_column(String(10), default="ssh")
    status: Mapped[str] = mapped_column(String(10), default="running")  # running/success/failed
    started_at: Mapped[datetime] = mapped_column(DateTime, default=local_now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    script_version: Mapped[str] = mapped_column(String(20), default="")
    slow: Mapped[bool] = mapped_column(Boolean, default=False)
    message: Mapped[str] = mapped_column(Text, default="")      # 失敗原因等
    raw_output: Mapped[str] = mapped_column(Text, default="")   # 人類可讀完整報告

    c_pass: Mapped[int] = mapped_column(Integer, default=0)
    c_fail: Mapped[int] = mapped_column(Integer, default=0)
    c_warn: Mapped[int] = mapped_column(Integer, default=0)
    c_manual: Mapped[int] = mapped_column(Integer, default=0)
    c_na: Mapped[int] = mapped_column(Integer, default=0)
    total: Mapped[int] = mapped_column(Integer, default=0)

    host: Mapped[Host] = relationship(back_populates="runs")
    results: Mapped[list["CheckResult"]] = relationship(
        back_populates="run", cascade="all, delete-orphan")

    @property
    def status_label(self) -> str:
        return RUN_STATUS_LABELS.get(self.status, self.status)

    @property
    def mode_label(self) -> str:
        """本次檢查的模式(比照 Host.mode_label;含設備 API 模式)。"""
        return MODE_LABELS.get(self.mode, self.mode)

    @property
    def pass_pct(self) -> int:
        """符合率:符合 /(符合+不符)。注意/人工/不適用不計入分母。"""
        denom = self.c_pass + self.c_fail
        return round(self.c_pass / denom * 100) if denom else 0


class CheckResult(Base):
    __tablename__ = "check_results"

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(
        ForeignKey("check_runs.id", ondelete="CASCADE"))
    item_id: Mapped[str] = mapped_column(String(80), default="")   # 腳本內穩定 ID
    category: Mapped[str] = mapped_column(String(80), default="")  # 章節名(如「10. SSH 伺服器…」)
    status: Mapped[str] = mapped_column(String(10), default="")    # pass/fail/warn/manual/na
    description: Mapped[str] = mapped_column(String(600), default="")

    run: Mapped[CheckRun] = relationship(back_populates="results")

    @property
    def status_label(self) -> str:
        return STATUS_LABELS.get(self.status, self.status)

    @property
    def status_css(self) -> str:
        return STATUS_CSS.get(self.status, "muted")


class ResultChange(Base):
    """檢查結果異動:入庫時與該主機前一次成功檢查比對的狀態轉變。

    儀表板「近期異動」直接讀本表(收集時比對、持久化)。
    before/after 為空字串表示「新出現」/「消失」的項目。
    """
    __tablename__ = "result_changes"

    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(Integer)          # 不設 FK,主機刪除由路由連帶清理
    host_name: Mapped[str] = mapped_column(String(100), default="")
    run_id: Mapped[int] = mapped_column(Integer, default=0)
    detected_at: Mapped[datetime] = mapped_column(DateTime, default=local_now)
    item_id: Mapped[str] = mapped_column(String(80), default="")
    category: Mapped[str] = mapped_column(String(80), default="")
    before_status: Mapped[str] = mapped_column(String(10), default="")
    after_status: Mapped[str] = mapped_column(String(10), default="")
    description: Mapped[str] = mapped_column(String(600), default="")

    @property
    def before_label(self) -> str:
        return STATUS_LABELS.get(self.before_status, self.before_status)

    @property
    def after_label(self) -> str:
        return STATUS_LABELS.get(self.after_status, self.after_status)

    @property
    def before_css(self) -> str:
        return STATUS_CSS.get(self.before_status, "muted")

    @property
    def after_css(self) -> str:
        return STATUS_CSS.get(self.after_status, "muted")


VERSION_KIND_LABELS = {"initial": "初始基線", "new": "新增項",
                        "status": "狀態變更", "desc": "內容變更",
                        "gone": "項目消失"}
VERSION_KIND_CSS = {"initial": "muted", "new": "allow", "status": "warn",
                    "desc": "manual", "gone": "deny"}


class ItemVersion(Base):
    """檢查項版本歷程:只存「初始基線」與「異動」(版本歷程頁讀此表)。

    與 ResultChange(儀表板近期異動,受保留天數清理)分工:本表為長期
    版本軸,**不受 log_retention_days 清理**,主機刪除時才連帶刪除;
    用途是回溯單一設定(item)從初始到現在的每一次變化。
    kind:initial=首輪基線 / new=新增項(或消失後重新出現)/
          status=狀態變更 / desc=內容變更(狀態不變)/ gone=項目消失。
    寫入邏輯見 checker._record_versions;歷史回填見 checker.rebuild_versions。
    """
    __tablename__ = "item_versions"

    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(Integer)   # 不設 FK,主機刪除由路由連帶清理
    host_name: Mapped[str] = mapped_column(String(100), default="")
    run_id: Mapped[int] = mapped_column(Integer, default=0)
    recorded_at: Mapped[datetime] = mapped_column(DateTime, default=local_now)
    item_id: Mapped[str] = mapped_column(String(80), default="")
    category: Mapped[str] = mapped_column(String(80), default="")
    kind: Mapped[str] = mapped_column(String(10), default="")
    before_status: Mapped[str] = mapped_column(String(10), default="")
    status: Mapped[str] = mapped_column(String(10), default="")
    before_desc: Mapped[str] = mapped_column(String(600), default="")
    description: Mapped[str] = mapped_column(String(600), default="")

    @property
    def kind_label(self) -> str:
        return VERSION_KIND_LABELS.get(self.kind, self.kind)

    @property
    def kind_css(self) -> str:
        return VERSION_KIND_CSS.get(self.kind, "muted")

    @property
    def before_label(self) -> str:
        return STATUS_LABELS.get(self.before_status, self.before_status)

    @property
    def before_css(self) -> str:
        return STATUS_CSS.get(self.before_status, "muted")

    @property
    def status_label(self) -> str:
        return STATUS_LABELS.get(self.status, self.status) if self.status else ""

    @property
    def status_css(self) -> str:
        return STATUS_CSS.get(self.status, "muted")


class CheckItemDisable(Base):
    """停用的檢查項(按系列):有列 = 該系列此項停用;預設(無列)= 啟用。

    停用效果:入庫時過濾(不存明細、不計入統計),兩種模式即刻生效;
    已入庫的歷史紀錄不追溯。目錄見 app/check_items.py。
    """
    __tablename__ = "check_item_disables"
    __table_args__ = (
        UniqueConstraint("family", "item_id", name="uq_item_disable"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    # 系列 key:Linux 的 deb / rpm,加上各網路設備類型(fortigate / paloalto /
    # f5 / netscaler / vcenter / cisco / netapp / aruba / fortiauth …)。
    # 長度比照 Host.device_type 的 String(20),留給日後 10 字以上的 key
    # (如 checkpoint);SQLite 的 VARCHAR 長度只是註記、不強制,故本次放寬
    # 不需要 database._migrate 補動作。
    family: Mapped[str] = mapped_column(String(20))
    item_id: Mapped[str] = mapped_column(String(80))


class AccountRole(Base):
    __tablename__ = "account_roles"
    __table_args__ = (
        UniqueConstraint("username", "role", name="uq_account_roles_username_role"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(100))
    role: Mapped[str] = mapped_column(String(20), default="readonly")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=local_now)
    user: Mapped[str] = mapped_column(String(100), default="")
    action: Mapped[str] = mapped_column(String(50), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
