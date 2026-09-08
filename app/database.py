from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DATA_DIR.mkdir(exist_ok=True)

engine = create_engine(
    f"sqlite:///{DATA_DIR / 'configcheck.db'}",
    connect_args={"check_same_thread": False, "timeout": 30},
)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def init_db() -> None:
    from app import models

    models.Base.metadata.create_all(engine)
    # 讀寫並行(排程背景檢查 + Agent 回報 + Web 讀取)→ WAL 模式避免互鎖
    with engine.begin() as conn:
        conn.exec_driver_sql("PRAGMA journal_mode=WAL")
        # create_all 不會補既有表的索引,這裡冪等補上(檢查明細量大,必加)
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_checkrun_host"
            " ON check_runs (host_id)")
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_checkresult_run"
            " ON check_results (run_id)")
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_checkresult_item"
            " ON check_results (item_id)")
        # 固定週期查詢的欄位(原本全表掃):
        #   status      — scheduler 每分鐘掃 running、儀表板掃 success
        #   started_at  — due 計算的 group_by max 與保留期限過濾
        #   host_id+status — 各主機最新成功紀錄(趨勢圖、異動比對)
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_checkrun_status"
            " ON check_runs (status)")
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_checkrun_started"
            " ON check_runs (started_at)")
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_checkrun_host_status"
            " ON check_runs (host_id, status)")
        # 儀表板「近期異動」與主機刪除時的連帶清理
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_resultchange_host"
            " ON result_changes (host_id)")
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_resultchange_detected"
            " ON result_changes (detected_at)")
        # 版本歷程(只存初始+異動;不受保留清理,主機刪除時連帶清)
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_itemversion_host"
            " ON item_versions (host_id)")
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_itemversion_item"
            " ON item_versions (item_id)")
    _migrate(engine)


def _migrate(engine) -> None:
    """輕量遷移:models 新增欄位時補進既有表(create_all 不會 ALTER 舊表)。"""
    migrations: list[tuple[str, str, str]] = [  # (表, 欄位, ALTER 子句)
        ("hosts", "device_type",
         "ALTER TABLE hosts ADD COLUMN device_type VARCHAR(20) DEFAULT 'linux'"),
        ("hosts", "api_key",
         "ALTER TABLE hosts ADD COLUMN api_key VARCHAR(500) DEFAULT ''"),
        ("hosts", "ssh_hostkey",
         "ALTER TABLE hosts ADD COLUMN ssh_hostkey VARCHAR(700) DEFAULT ''"),
        ("hosts", "api_verify_ssl",
         "ALTER TABLE hosts ADD COLUMN api_verify_ssl BOOLEAN DEFAULT 0"),
    ]
    with engine.begin() as conn:
        for table, col, ddl in migrations:
            cols = {r[1] for r in
                    conn.exec_driver_sql(f"PRAGMA table_info({table})")}
            if cols and col not in cols:
                conn.exec_driver_sql(ddl)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
