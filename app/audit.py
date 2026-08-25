"""稽核紀錄 helper。

在各異動路由呼叫 audit(request, action, detail) 寫一筆 AuditLog;
用獨立 session、整段防護 —— 稽核寫入失敗絕不影響主流程。
user 欄:自 request.session 帶入登入者(無 session 時可用 user= 指定)。
"""
from fastapi import Request

from app.database import SessionLocal
from app.models import AuditLog


def audit(request: Request | None, action: str, detail: str, user: str = "") -> None:
    """寫入稽核紀錄;失敗不影響主流程。"""
    try:
        if not user and request is not None:
            u = request.session.get("user") or {}  # 尚未掛 SessionMiddleware 時會丟例外
            user = u.get("name") or u.get("id") or ""
    except Exception:  # noqa: BLE001
        pass
    try:
        with SessionLocal() as db:
            db.add(AuditLog(user=user, action=action, detail=detail))
            db.commit()
    except Exception:  # noqa: BLE001
        pass
