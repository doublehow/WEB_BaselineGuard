"""版本歷程:檢查結果的長期版本軸——只存「初始基線」與「異動」。

與儀表板「近期異動」(result_changes,受保留天數清理)分工:
item_versions 不受 log_retention_days 清理,可回溯單一設定(item)
從初始基線到現在的每一次變化(狀態變更/內容變更/新增/消失);
主機刪除時才連帶刪除。寫入邏輯見 checker._record_versions。
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.config import local_now
from app.database import get_db
from app.models import VERSION_KIND_LABELS, Host, ItemVersion
from app.webutil import csv_response, render

router = APIRouter()

_LIMIT = 500  # 單頁上限(表只存異動,量小;超過以篩選縮小範圍)


def _query(db: Session, host_id: int, item: str, kind: str):
    q = db.query(ItemVersion)
    if host_id:
        q = q.filter(ItemVersion.host_id == host_id)
    if item:
        q = q.filter(ItemVersion.item_id.contains(item))
    if kind in VERSION_KIND_LABELS:
        q = q.filter(ItemVersion.kind == kind)
    return q


@router.get("/versions")
async def versions_page(request: Request, host_id: int = 0, item: str = "",
                        kind: str = "", db: Session = Depends(get_db)):
    item = item.strip()[:80]
    q = _query(db, host_id, item, kind)
    total = q.count()
    rows = q.order_by(ItemVersion.id.desc()).limit(_LIMIT).all()
    hosts = db.query(Host).order_by(Host.name).all()
    return render(request, "versions.html", "versions",
                  rows=rows, total=total, limit=_LIMIT,
                  hosts=hosts, host_id=host_id, item=item, kind=kind,
                  kind_labels=VERSION_KIND_LABELS)


@router.get("/versions/export.csv")
async def versions_export(host_id: int = 0, item: str = "", kind: str = "",
                          db: Session = Depends(get_db)):
    """版本歷程匯出 CSV(依目前篩選;含全部符合筆數,不受單頁上限)。"""
    rows = (_query(db, host_id, item.strip()[:80], kind)
            .order_by(ItemVersion.id.desc()).all())
    data = [(v.recorded_at.strftime("%Y-%m-%d %H:%M") if v.recorded_at else "",
             v.host_name, v.item_id, v.category, v.kind_label,
             v.before_label, v.status_label,
             v.before_desc, v.description) for v in rows]
    ts = local_now().strftime("%Y%m%d")
    return csv_response(
        f"BaselineGuard_版本歷程_{ts}.csv",
        ["時間", "主機", "項目ID", "章節", "類型",
         "變更前狀態", "變更後狀態", "變更前內容", "變更後內容"], data)
