"""內建背景排程:SSH 定期檢查 + Agent 失聯偵測 + 紀錄清理。

- scheduler_loop() 由 main.py lifespan 以 create_task 啟動,每分鐘 tick 一次;
  設定改變(scheduler_enabled)下一個 tick 即生效,毋須重啟。
  進迴圈前先做一次 checker.reset_orphan_runs():程序重啟會留下永遠停在
  running 的 CheckRun,而排程會跳過有 running 紀錄的主機。
- _tick() 為同步阻塞(經 asyncio.to_thread 執行),到期主機以執行緒池並行
  (上限 _MAX_PARALLEL),每台各自 try/except 與各自的 DB session,
  單台慢或失敗都不影響其他主機;loop 本身永不因例外中斷。
"""
from __future__ import annotations

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import timedelta

from sqlalchemy import func

from app import notify
from app.config import local_now, settings
from app.database import SessionLocal

logger = logging.getLogger("ucc.scheduler")

_STARTUP_DELAY = 15    # 開機緩衝(秒)
_TICK = 60             # tick 週期(秒)
_CLEANUP_EVERY = 3600  # 清理 / 失聯偵測週期(秒)
_MAX_PARALLEL = 5      # 同時執行的檢查上限(避免單台 hang 拖垮整個 tick)
_DELETE_BATCH = 500    # 清理時每批刪除筆數(SQLite bind 變數上限 32766)
_since_cleanup = _CLEANUP_EVERY  # 首輪 tick 就做一次


def _due_ssh_hosts(db) -> list:
    """到期且未在執行中的拉取式主機清單(SSH 主機 + API 網路設備)。

    取清單前先做逾時仲裁:卡死的 running 紀錄若不結案,該主機會被永久跳過。
    """
    from app.checker import expire_stale_runs
    from app.models import CheckRun, Host
    try:
        expire_stale_runs(db)
    except Exception:  # noqa: BLE001 —— 仲裁失敗不影響本輪其他主機
        logger.exception("執行中紀錄逾時仲裁失敗")
        db.rollback()
    now = local_now()
    last_map = dict(
        db.query(CheckRun.host_id, func.max(CheckRun.started_at))
        .group_by(CheckRun.host_id).all())
    running = {hid for (hid,) in db.query(CheckRun.host_id)
               .filter(CheckRun.status == "running").distinct().all()}
    due = []
    for h in db.query(Host).filter(Host.mode.in_(("ssh", "api")),
                                   Host.enabled.is_(True)).all():
        if h.interval_minutes <= 0 or h.id in running:
            continue
        last = last_map.get(h.id)
        if last is None or now - last >= timedelta(minutes=h.interval_minutes):
            due.append(h.id)
    return due


def _agent_offline_check(db) -> None:
    """Agent 主機超過 agent_offline_hours 未回報 → 告警一次(轉態去重)。"""
    from app.models import Host
    hours = settings.agent_offline_hours
    if hours <= 0:
        return
    cutoff = local_now() - timedelta(hours=hours)
    for h in db.query(Host).filter(Host.mode == "agent",
                                   Host.enabled.is_(True),
                                   Host.offline_alerted.is_(False)).all():
        # 從未回報的主機不算失聯(可能剛建好還沒安裝 agent)
        if h.last_checked_at is not None and h.last_checked_at < cutoff:
            h.offline_alerted = True
            db.commit()
            logger.warning("Agent 主機失聯:%s(最後回報 %s)",
                           h.name, h.last_checked_at)
            notify.send_async(
                "🔴 BaselineGuard Agent 失聯",
                f"主機 {h.name} 已超過 {hours} 小時未回報檢查結果"
                f"(最後回報:{h.last_checked_at:%F %H:%M})")


def _cleanup(db) -> None:
    """依保留天數清理檢查與稽核紀錄(0 = 不清理)。"""
    from app.models import AuditLog, CheckResult, CheckRun, ResultChange
    days = settings.log_retention_days
    if days <= 0:
        return
    cutoff = local_now() - timedelta(days=days)
    old_ids = [i for (i,) in db.query(CheckRun.id)
               .filter(CheckRun.started_at < cutoff).all()]
    # 分批刪除:一次 in_() 全塞會撞 SQLite bind 變數上限(32766,舊版 999),
    # 長期未清理後首次啟用或大幅調低保留天數時筆數很容易破表
    for i in range(0, len(old_ids), _DELETE_BATCH):
        batch = old_ids[i:i + _DELETE_BATCH]
        # SQLite 未開 FK 強制,bulk delete 不會 cascade → 先刪明細再刪主檔
        db.query(CheckResult).filter(
            CheckResult.run_id.in_(batch)).delete(synchronize_session=False)
        db.query(CheckRun).filter(
            CheckRun.id.in_(batch)).delete(synchronize_session=False)
        db.commit()
    db.query(ResultChange).filter(
        ResultChange.detected_at < cutoff).delete(synchronize_session=False)
    # item_versions(版本歷程)刻意不清理:只存初始+異動、量小,
    # 存在目的就是跨越保留期限的長期設定變更追溯;主機刪除時才連帶刪。
    n_audit = db.query(AuditLog).filter(
        AuditLog.ts < cutoff).delete(synchronize_session=False)
    db.commit()
    if old_ids or n_audit:
        logger.info("清理逾期紀錄:檢查 %s 筆、稽核 %s 筆", len(old_ids), n_audit)


def _tick(do_cleanup: bool) -> None:
    """(同步,於 thread 內執行)一輪排程工作。

    到期主機以執行緒池並行(上限 _MAX_PARALLEL):逐台串行時一台 hang 到
    EXEC_TIMEOUT(3600 秒)會讓其後所有主機、清理與失聯偵測一起順延一小時。
    每條各自 with SessionLocal()(checker.run_ssh_check 內部處理),
    DB 為 WAL + busy timeout 30 秒,少量並行寫入安全。
    """
    from app.checker import run_ssh_check
    with SessionLocal() as db:
        if do_cleanup:
            try:
                _cleanup(db)
            except Exception:  # noqa: BLE001
                logger.exception("清理失敗(不影響檢查)")
                db.rollback()
            try:
                _agent_offline_check(db)
            except Exception:  # noqa: BLE001
                logger.exception("失聯偵測失敗(不影響檢查)")
                db.rollback()
        due = _due_ssh_hosts(db)
    if not due:
        return
    workers = min(_MAX_PARALLEL, len(due))
    logger.info("本輪到期主機 %s 台(並行 %s)", len(due), workers)
    with ThreadPoolExecutor(max_workers=workers,
                            thread_name_prefix="ucc-check") as pool:
        futures = {pool.submit(run_ssh_check, hid): hid for hid in due}
        for fut in as_completed(futures):
            try:
                fut.result()   # 內部已各自收斂例外到 CheckRun
            except Exception:  # noqa: BLE001 —— 最後防線
                logger.exception("主機排程檢查例外(host_id=%s)",
                                 futures[fut])


async def scheduler_loop() -> None:
    global _since_cleanup
    await asyncio.sleep(_STARTUP_DELAY)
    # 啟動時復位遺留的 running 紀錄(上次程序在檢查途中被結束):
    # 不復位的話這些主機會被排程永久跳過,且完全不報錯
    from app.checker import reset_orphan_runs
    await asyncio.to_thread(reset_orphan_runs)
    logger.info("背景排程啟動(tick=%ss)", _TICK)
    while True:
        if settings.scheduler_enabled:   # 每 tick 重讀設定,改設定即生效
            _since_cleanup += _TICK
            do_cleanup = _since_cleanup >= _CLEANUP_EVERY
            if do_cleanup:
                _since_cleanup = 0
            try:
                await asyncio.to_thread(_tick, do_cleanup)
            except Exception as exc:  # noqa: BLE001 —— loop 永不因例外中斷
                logger.error("排程 tick 例外:%s", exc)
        await asyncio.sleep(_TICK)
