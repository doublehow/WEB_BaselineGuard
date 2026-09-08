"""檢查項目:全部檢查項清單(依系列分頁),可逐項啟用/停用。

- 目錄來源 app/check_items.py(對映 ucc_check.sh);停用狀態存
  check_item_disables(有列 = 停用),入庫時過濾、即刻生效、不追溯歷史。
"""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.audit import audit
from app.check_items import FAMILIES, IMPLEMENTED_FAMILIES, items_for, valid_ids
from app.database import get_db
from app.models import CheckItemDisable
from app.webutil import render

router = APIRouter()


@router.get("/items")
async def item_list(request: Request, db: Session = Depends(get_db),
                    fam: str = "deb"):
    if fam not in FAMILIES:
        fam = "deb"
    disabled = {r.item_id for r in db.query(CheckItemDisable)
                .filter(CheckItemDisable.family == fam).all()}
    items = items_for(fam)
    # 依章節分組(維持目錄順序)
    groups: list[dict] = []
    for it in items:
        if not groups or groups[-1]["cat"] != it["cat"]:
            groups.append({"cat": it["cat"], "items": []})
        groups[-1]["items"].append(it)
    from app.devtypes import DEVICE_TYPES
    fam_note = next((t.get("note", "") for t in DEVICE_TYPES if t["key"] == fam), "")
    return render(request, "items.html", "items",
                  fam=fam, families=FAMILIES, groups=groups,
                  total=len(items), disabled=disabled,
                  fam_implemented=fam in IMPLEMENTED_FAMILIES, fam_note=fam_note,
                  disabled_count=len(disabled & {i["id"] for i in items}))


@router.post("/items/toggle")
async def item_toggle(request: Request, db: Session = Depends(get_db)):
    """AJAX:切換單一檢查項啟用狀態(寫入權限由 middleware 強制)。

    輸入驗證用明確條件判斷,不可用 assert —— `python -O` 會剝除 assert,
    導致無效的 family/item_id 寫入 check_item_disables 垃圾列,
    且後續 `FAMILIES[fam]` 會 KeyError 500。
    """
    try:
        data = json.loads(await request.body())
    except Exception:  # noqa: BLE001
        return {"ok": False, "message": "無效的請求格式"}
    if not isinstance(data, dict):
        return {"ok": False, "message": "無效的請求格式"}
    fam = data.get("family")
    item_id = data.get("item_id")
    if not isinstance(fam, str) or fam not in FAMILIES:
        return {"ok": False, "message": "無效的檢查項系列"}
    if not isinstance(item_id, str) or item_id not in valid_ids(fam):
        return {"ok": False, "message": "無效的檢查項 ID"}
    enabled = bool(data.get("enabled"))
    row = (db.query(CheckItemDisable)
           .filter(CheckItemDisable.family == fam,
                   CheckItemDisable.item_id == item_id).first())
    if enabled and row is not None:
        db.delete(row)
        db.commit()
        audit(request, "item_enable", f"啟用檢查項:{FAMILIES[fam]} {item_id}")
    elif not enabled and row is None:
        db.add(CheckItemDisable(family=fam, item_id=item_id))
        db.commit()
        audit(request, "item_disable", f"停用檢查項:{FAMILIES[fam]} {item_id}")
    n = (db.query(CheckItemDisable)
         .filter(CheckItemDisable.family == fam).count())
    return {"ok": True, "enabled": enabled, "disabled_count": n}
