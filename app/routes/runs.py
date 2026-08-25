"""檢查紀錄:執行清單、單次結果明細、與前次比較。"""
from __future__ import annotations

from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import STATUS_LABELS, STATUS_ORDER, CheckResult, CheckRun
from app.webutil import csv_response, render

router = APIRouter()

_RUN_STATUS = ("success", "failed", "running")


# ──────────────────────────────────────────────────────────────────
# 來源篩選的往返(紀錄頁 → 明細 → 比較 → 回紀錄頁)
#
# 明細/比較頁以 fh(主機)/ fs(狀態)兩個參數記住「使用者是從哪一組篩選
# 進來的」,返回連結據此重建紀錄頁網址,免得按返回後篩選條件消失。
# 值一律先驗證再組網址(不把使用者輸入原樣拼進 URL)。
# ──────────────────────────────────────────────────────────────────

def _logs_url(fh: str = "", fs: str = "") -> str:
    """「紀錄」頁網址,保留來源的主機/狀態篩選。"""
    params = {"tab": "check"}
    if fh.isdigit():
        params["host"] = fh
    if fs in _RUN_STATUS:
        params["status"] = fs
    return "/logs?" + urlencode(params)


def _src_qs(fh: str = "", fs: str = "") -> str:
    """明細/比較頁互連時夾帶的來源篩選(含前導 ?;無則回空字串)。"""
    params = {}
    if fh.isdigit():
        params["fh"] = fh
    if fs in _RUN_STATUS:
        params["fs"] = fs
    return ("?" + urlencode(params)) if params else ""


@router.get("/runs")
async def run_list(host: str = "", status: str = ""):
    """檢查紀錄清單已併入「紀錄」頁的檢查紀錄分頁(舊網址轉導,保留篩選)。"""
    return RedirectResponse(
        f"/logs?tab=check&host={host}&status={status}", status_code=303)


@router.get("/runs/{run_id}")
async def run_detail(request: Request, run_id: int,
                     db: Session = Depends(get_db), st: str = "", q: str = "",
                     fh: str = "", fs: str = ""):
    run = db.get(CheckRun, run_id)
    if run is None:
        return RedirectResponse(_logs_url(fh, fs), status_code=303)
    results = (db.query(CheckResult).filter(CheckResult.run_id == run_id)
               .order_by(CheckResult.id).all())
    if st in STATUS_LABELS:
        results = [r for r in results if r.status == st]
    kw = q.strip()
    if kw:
        low = kw.lower()
        results = [r for r in results
                   if low in r.description.lower() or low in r.item_id.lower()]
    # 預設排序:不符 → 注意 → 人工 → 符合 → 不適用(同狀態維持腳本輸出順序)
    order = {s: i for i, s in enumerate(STATUS_ORDER)}
    results.sort(key=lambda r: order.get(r.status, 9))
    return render(request, "run_detail.html", "logs",
                  run=run, results=results, st=st, q=kw,
                  status_labels=STATUS_LABELS,
                  back_url=_logs_url(fh, fs), src_qs=_src_qs(fh, fs),
                  fh=fh if fh.isdigit() else "",
                  fs=fs if fs in _RUN_STATUS else "")


@router.get("/runs/{run_id}/export.csv")
async def run_export(run_id: int, db: Session = Depends(get_db)):
    """單次檢查結果匯出 CSV(稽核/陳核附件用)。"""
    run = db.get(CheckRun, run_id)
    if run is None:
        return RedirectResponse("/runs", status_code=303)
    results = (db.query(CheckResult).filter(CheckResult.run_id == run_id)
               .order_by(CheckResult.id).all())
    rows = [(r.item_id, r.category, r.status_label, r.description)
            for r in results]
    ts = run.started_at.strftime("%Y%m%d_%H%M")
    return csv_response(f"BaselineGuard_{run.host_name}_{ts}.csv",
                        ["項目ID", "章節", "結果", "說明"], rows)


@router.get("/runs/{run_id}/diff")
async def run_diff(request: Request, run_id: int,
                   db: Session = Depends(get_db), fh: str = "", fs: str = ""):
    """與同主機「前一次成功檢查」比較,列出狀態有變化 / 新增 / 消失的項目。"""
    run = db.get(CheckRun, run_id)
    if run is None:
        return RedirectResponse(_logs_url(fh, fs), status_code=303)
    prev = (db.query(CheckRun)
            .filter(CheckRun.host_id == run.host_id,
                    CheckRun.status == "success",
                    CheckRun.id < run.id)
            .order_by(CheckRun.id.desc()).first())
    changed, added, removed = [], [], []
    if prev is not None:
        cur_map = {r.item_id: r for r in db.query(CheckResult)
                   .filter(CheckResult.run_id == run.id).all()}
        prev_map = {r.item_id: r for r in db.query(CheckResult)
                    .filter(CheckResult.run_id == prev.id).all()}
        for iid, r in cur_map.items():
            p = prev_map.get(iid)
            if p is None:
                added.append(r)
            elif p.status != r.status:
                changed.append({"cur": r, "prev": p})
        removed = [p for iid, p in prev_map.items() if iid not in cur_map]
    return render(request, "run_compare.html", "logs",
                  run=run, prev=prev,
                  changed=changed, added=added, removed=removed,
                  back_url=_logs_url(fh, fs), src_qs=_src_qs(fh, fs))
