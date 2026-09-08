"""紀錄:檢查紀錄 + 稽核紀錄 兩分頁。"""
from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import AuditLog, CheckRun, Host
from app.webutil import render

router = APIRouter()


@router.get("/logs")
async def log_list(request: Request, db: Session = Depends(get_db),
                   tab: str = "check", host: str = "", status: str = ""):
    if tab not in ("check", "audit"):
        tab = "check"
    hosts = db.query(Host).order_by(Host.name).all()

    runs, audit_logs = [], []
    fail_delta: dict[int, int] = {}
    if tab == "check":
        q = db.query(CheckRun)
        if host.isdigit():
            q = q.filter(CheckRun.host_id == int(host))
        if status in ("success", "failed", "running"):
            q = q.filter(CheckRun.status == status)
        runs = q.order_by(CheckRun.id.desc()).limit(200).all()
        fail_delta = fail_deltas(db, runs)
    else:
        audit_logs = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(200).all()

    return render(request, "logs.html", "logs",
                  tab=tab, hosts=hosts, host_id=host, status=status,
                  runs=runs, audit_logs=audit_logs, fail_delta=fail_delta)


def fail_deltas(db: Session, runs: list) -> dict[int, int]:
    """各成功 run 與「同主機前一次成功檢查」的不符數差(run_id → Δ不符)。

    一次撈相關主機的歷史計數,避免逐列 N+1;首輪(無前次)不在 dict 中。
    """
    host_ids = {r.host_id for r in runs}
    if not host_ids:
        return {}
    hist = (db.query(CheckRun.id, CheckRun.host_id, CheckRun.c_fail)
            .filter(CheckRun.host_id.in_(host_ids),
                    CheckRun.status == "success")
            .order_by(CheckRun.id).all())
    deltas: dict[int, int] = {}
    last_by_host: dict[int, int] = {}
    for rid, hid, cf in hist:
        if hid in last_by_host:
            deltas[rid] = cf - last_by_host[hid]
        last_by_host[hid] = cf
    return deltas
