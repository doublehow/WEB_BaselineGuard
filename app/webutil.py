"""模板共用:templates 實例、導覽列、render 快捷(注入登入者/角色)、CSV 匯出。"""
import csv
import io
from pathlib import Path
from urllib.parse import quote

from fastapi import Request
from fastapi.responses import Response
from fastapi.templating import Jinja2Templates

from app.auth import ROLE_LABELS, roles_of

templates = Jinja2Templates(directory=str(Path(__file__).parent / "web" / "templates"))

NAV = [
    ("dashboard", "/", "儀表板"),
    ("hosts", "/hosts", "主機管理"),
    ("gaps", "/gaps", "不符彙總"),
    ("items", "/items", "檢查項目"),
    ("versions", "/versions", "版本歷程"),
    ("logs", "/logs", "紀錄"),
    ("settings", "/settings", "設定"),
]


def session_user(request: Request) -> dict:
    """目前登入者(session 異常時回空 dict)。"""
    try:
        return request.session.get("user") or {}
    except Exception:  # noqa: BLE001 —— session 尚未就緒時容錯
        return {}


def role_flags(request: Request) -> dict:
    """角色權限旗標(僅供模板顯示;伺服器端於 route / middleware 強制)。"""
    roles = roles_of(session_user(request))
    return {"can_write": "full_admin" in roles}


def csv_response(filename: str, header: list[str], rows) -> Response:
    """CSV 下載回應:UTF-8 BOM 讓 Excel 直接開啟不亂碼;中文檔名走 RFC 5987。"""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    w.writerows(rows)
    return Response(
        "\ufeff" + buf.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition":
                 f"attachment; filename=export.csv;"
                 f" filename*=UTF-8''{quote(filename)}"})


def render(request: Request, name: str, active: str, **ctx):
    user = session_user(request)
    roles = roles_of(user)
    label = "、".join(ROLE_LABELS.get(r, r) for r in ROLE_LABELS if r in roles)
    return templates.TemplateResponse(request, name, {
        "nav": NAV, "active": active,
        "user_name": user.get("name", ""), "user_id": user.get("id", ""),
        "role_label": label or "唯讀",
        **role_flags(request),
        **ctx})
