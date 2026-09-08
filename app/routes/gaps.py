"""不符彙總:跨主機的差距分析——各檢查項有哪些主機不符,依影響面排序。

取「每台啟用主機的最新一次成功檢查」為基準,將指定狀態(預設:不符)的
項目依 item_id 分組,列出受影響主機;供訂定改善計畫與 GCB 例外清單。
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.config import local_now
from app.database import get_db
from app.models import STATUS_CSS, STATUS_LABELS, CheckResult, CheckRun, Host
from app.webutil import csv_response, render

router = APIRouter()


def _gap_data(db: Session, st: str) -> tuple[list, int]:
    """各啟用主機最新成功 run 中,指定狀態的項目依 item_id 分組。"""
    max_ids = [i for (i,) in
               db.query(func.max(CheckRun.id))
               .join(Host, Host.id == CheckRun.host_id)
               .filter(CheckRun.status == "success", Host.enabled.is_(True))
               .group_by(CheckRun.host_id).all()]
    groups: dict[str, dict] = {}
    host_total = 0
    if max_ids:
        runs = db.query(CheckRun).filter(CheckRun.id.in_(max_ids)).all()
        host_total = len(runs)
        run_host = {r.id: r.host_name for r in runs}
        rows = (db.query(CheckResult)
                .filter(CheckResult.run_id.in_(max_ids),
                        CheckResult.status == st).all())
        for r in rows:
            g = groups.setdefault(r.item_id, {
                "item_id": r.item_id, "category": r.category,
                "description": r.description, "hosts": []})
            g["hosts"].append(run_host.get(r.run_id, "?"))
    gap_list = sorted(groups.values(),
                      key=lambda g: (-len(g["hosts"]), g["item_id"]))
    for g in gap_list:
        g["hosts"].sort()
    return gap_list, host_total


@router.get("/gaps")
async def gap_overview(request: Request, db: Session = Depends(get_db),
                       st: str = "fail"):
    if st not in ("fail", "warn", "manual"):
        st = "fail"
    gap_list, host_total = _gap_data(db, st)
    return render(request, "gaps.html", "gaps",
                  gaps=gap_list, st=st, host_total=host_total,
                  status_labels=STATUS_LABELS, status_css=STATUS_CSS)


@router.get("/gaps/export.csv")
async def gap_export(db: Session = Depends(get_db), st: str = "fail"):
    """不符彙總匯出 CSV(改善計畫/例外清單陳核附件用)。"""
    if st not in ("fail", "warn", "manual"):
        st = "fail"
    gap_list, host_total = _gap_data(db, st)
    rows = [(g["item_id"], g["category"], g["description"],
             f"{len(g['hosts'])}/{host_total}", "、".join(g["hosts"]))
            for g in gap_list]
    ts = local_now().strftime("%Y%m%d")
    return csv_response(
        f"BaselineGuard_不符彙總_{STATUS_LABELS[st]}_{ts}.csv",
        ["項目ID", "章節", "說明", "主機數", "受影響主機"], rows)
