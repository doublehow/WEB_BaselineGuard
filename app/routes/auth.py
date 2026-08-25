"""登入 / 登出 / 帳號分權(RBAC 管理)。"""
import asyncio

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.audit import audit
from app.auth import ROLE_LABELS, authenticate_ad, resolve_roles
from app.config import settings
from app.database import get_db
from app.models import AccountRole
from app.webutil import templates

router = APIRouter()


# ---------- 登入 / 登出 ----------
@router.get("/login")
async def login_page(request: Request, error: str = ""):
    if request.session.get("user"):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(
        request, "login.html", {"error": error, "ad_enabled": settings.ad_enabled})


@router.post("/login")
async def login_submit(request: Request, username: str = Form(...),
                       password: str = Form(...)):
    uname = username.strip()
    # 本機管理帳號(緊急備援,不經 AD;恆為管理者)
    if uname == "admin" and password == settings.local_admin_password:
        request.session["user"] = {"id": "admin", "name": "本機管理員",
                                   "role": "full_admin",
                                   "roles": ["full_admin"]}
        audit(request, "login", "本機管理員登入(管理者)")
        return RedirectResponse("/", status_code=303)

    if settings.ad_enabled:
        # ldap3 的 Connection 是同步網路 I/O:直接在 async 路由內呼叫會卡住
        # 整個 event loop(AD 無回應時,TCP 逾時期間全站所有請求一起卡死),
        # 一律丟到執行緒(比照 settings_routes 的 ad-test)
        ok, result = await asyncio.to_thread(authenticate_ad, uname, password)
        if ok:
            # resolve_roles 只查本機 SQLite(不打 AD),但仍是阻塞 DB I/O,
            # 一併丟執行緒保持登入路徑完全非阻塞
            roles = await asyncio.to_thread(resolve_roles,
                                            result.get("id", uname))
            result["roles"] = roles
            result["role"] = roles[0]   # 主要角色(相容顯示用)
            request.session["user"] = result
            labels = "、".join(ROLE_LABELS.get(r, r) for r in roles)
            audit(request, "login", f"AD 登入:{uname}({labels})")
            return RedirectResponse("/", status_code=303)
        # 回給使用者的訊息一律統一,避免由「找不到帳號 / 密碼錯誤 / 不在授權
        # 群組」的差異枚舉出帳號是否存在;詳細原因只寫進稽核紀錄供管理者查。
        audit(None, "login_failed", f"登入失敗:{uname}(原因:{result})",
              user=uname)
        return RedirectResponse("/login?error=帳號或密碼錯誤", status_code=303)

    audit(None, "login_failed", f"登入失敗:{uname}", user=uname)
    return RedirectResponse(
        "/login?error=帳號或密碼錯誤(AD 未啟用,請用本機 admin 帳號或至設定頁啟用 AD)",
        status_code=303)


@router.post("/logout")
async def logout(request: Request):
    """登出(POST):補稽核紀錄,並避免 GET 被 `<img src="/logout">` 之類跨站觸發。

    /logout 在 main.py 的 PUBLIC_PATHS 內,不受「非 GET 僅 full_admin」限制,
    唯讀角色一樣可登出。base.html 的登出已改為 POST 表單。
    """
    u = request.session.get("user") or {}
    who = u.get("name") or u.get("id") or ""
    request.session.clear()
    if who:
        audit(None, "logout", f"登出:{who}", user=who)
    return RedirectResponse("/login", status_code=303)


@router.get("/logout")
async def logout_get(request: Request):
    """舊書籤相容:GET 不清 session(防跨站強制登出),導回登入頁由使用者自行操作。"""
    if request.session.get("user"):
        return RedirectResponse("/", status_code=303)
    return RedirectResponse("/login", status_code=303)


# ---------- 帳號分權(管理 UI 在設定頁;寫入由 middleware 強制僅 full_admin)----------
@router.post("/roles")
async def roles_set(request: Request, db: Session = Depends(get_db),
                    username: str = Form(...), role: str = Form("readonly")):
    """新增一筆帳號+角色(重複的組合略過)。"""
    uname = username.strip()
    if uname and role in ROLE_LABELS:
        existing = db.query(AccountRole).filter(
            AccountRole.username == uname,
            AccountRole.role == role).first()
        if existing is None:
            db.add(AccountRole(username=uname, role=role))
            db.commit()
            audit(request, "role_set",
                  f"帳號分權:{uname} 新增角色 {ROLE_LABELS[role]}")
    return RedirectResponse("/settings", status_code=303)


@router.post("/roles/{role_id}/delete")
async def roles_delete(request: Request, role_id: int,
                       db: Session = Depends(get_db)):
    r = db.get(AccountRole, role_id)
    if r:
        db.delete(r)
        db.commit()
        audit(request, "role_delete", f"移除分權:{r.username}")
    return RedirectResponse("/settings", status_code=303)
