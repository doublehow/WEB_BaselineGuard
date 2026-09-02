"""模板共用:templates 實例、導覽列、render 快捷(注入登入者/角色)、CSV 匯出。"""
import csv
import io
from pathlib import Path
from urllib.parse import quote

from fastapi import Request
from fastapi.responses import Response
from fastapi.templating import Jinja2Templates

from sqlalchemy.orm import Session

from app.auth import ROLE_LABELS, roles_of
from app.models import CheckRun

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


def _csv_cell(v):
    """防 CSV 公式注入:儲存格以 = + - @ Tab CR 開頭時前綴 '(Excel 視為文字)。

    匯出欄位含受稽核設備回傳的描述文字(較低信任來源),被攻陷的受檢主機
    可讓某檢查項描述以 =HYPERLINK/=cmd| 開頭,對開啟 CSV 的稽核人員工作站
    發動公式/DDE 攻擊——在此單點消毒,全站三個匯出點一併覆蓋。"""
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", chr(9), chr(13)):
        return "'" + v
    return v


def csv_response(filename: str, header: list[str], rows) -> Response:
    """CSV 下載回應:UTF-8 BOM 讓 Excel 直接開啟不亂碼;中文檔名走 RFC 5987。"""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    w.writerows([_csv_cell(c) for c in row] for row in rows)
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

def _sparkline(vals: list[int], w: int = 92, h: int = 24, pad: int = 3) -> dict | None:
    """符合率序列 → 迷你折線圖座標(模板直接渲染 inline SVG)。

    y 軸用 min/max 加緩衝(平線置中),重點是趨勢形狀而非絕對刻度;
    絕對值由 <title> 提示與旁邊的符合率欄承擔。
    """
    if not vals:
        return None
    lo, hi = min(vals), max(vals)
    if hi - lo < 1:          # 全平序列:上下各留 1,讓線落在中間
        lo, hi = lo - 1, hi + 1
    n = len(vals)
    pts = []
    for i, v in enumerate(vals):
        x = pad + (w - 2 * pad) * (i / (n - 1) if n > 1 else 0.5)
        y = pad + (h - 2 * pad) * (1 - (v - lo) / (hi - lo))
        pts.append((round(x, 1), round(y, 1)))
    points = " ".join(f"{x},{y}" for x, y in pts)
    area = (f"{pts[0][0]},{h - pad} " + points + f" {pts[-1][0]},{h - pad}")
    return {"points": points, "area": area, "last": pts[-1],
            "vals": vals, "w": w, "h": h}


def _change_bars(deltas: list[int], w: int = 92, h: int = 24,
                 pad: int = 2) -> dict | None:
    """每次檢查的不符增減 → 紅綠長條(改善向上綠、惡化向下紅、持平中線刻度)。

    deltas 為「改善量」(前次不符 − 本次不符):正 = 進步。
    """
    if not deltas:
        return None
    n = len(deltas)
    slot = (w - 2 * pad) / n
    bw = max(3, round(slot - 2, 1))
    mid = h / 2
    scale = (mid - 2) / max(1, max(abs(d) for d in deltas))
    items = []
    for i, d in enumerate(deltas):
        x = round(pad + i * slot + (slot - bw) / 2, 1)
        bh = round(abs(d) * scale, 1)
        if d > 0:
            items.append({"x": x, "y": round(mid - bh, 1), "bh": bh, "dir": "up"})
        elif d < 0:
            items.append({"x": x, "y": mid, "bh": bh, "dir": "down"})
        else:
            items.append({"x": x, "y": round(mid - 0.75, 1), "bh": 1.5,
                          "dir": "zero"})
    return {"w": w, "h": h, "mid": mid, "bw": bw, "items": items,
            "vals": deltas}


def host_trends(db: Session, host_ids: list[int],
                 limit: int = 12) -> tuple[dict, dict]:
    """各主機近 N 次成功檢查的趨勢(一次查完):

    回傳 (sparks, changes):host_id → 符合率折線 / 不符增減長條。
    """
    if not host_ids:
        return {}, {}
    rows = (db.query(CheckRun.host_id, CheckRun.c_pass, CheckRun.c_fail)
            .filter(CheckRun.host_id.in_(host_ids),
                    CheckRun.status == "success")
            .order_by(CheckRun.id).all())
    pct_series: dict[int, list[int]] = {}
    fail_series: dict[int, list[int]] = {}
    for hid, cp, cf in rows:
        denom = cp + cf
        pct_series.setdefault(hid, []).append(
            round(cp / denom * 100) if denom else 0)
        fail_series.setdefault(hid, []).append(cf)
    sparks = {hid: _sparkline(vals[-limit:])
              for hid, vals in pct_series.items()}
    changes = {}
    for hid, fails in fail_series.items():
        tail = fails[-(limit + 1):]
        # 改善量 = 前次不符 − 本次不符(正 = 進步)
        deltas = [tail[i - 1] - tail[i] for i in range(1, len(tail))]
        changes[hid] = _change_bars(deltas[-limit:])
    return sparks, changes
