"""設定頁:AD 登入 / 排程與保留 / Agent / 告警 / 帳號分權;含 AD 逐步測試(AJAX)。"""
import asyncio
import json
import re

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.audit import audit
from app.auth import ROLE_LABELS
from app.config import save_settings, settings
from app.database import get_db
from app.models import AccountRole
from app.webutil import render

router = APIRouter()


@router.get("/settings")
async def settings_page(request: Request, db: Session = Depends(get_db),
                        saved: str = ""):
    roles = db.query(AccountRole).order_by(AccountRole.username).all()
    return render(request, "settings.html", "settings",
                  s=settings, saved=saved,
                  roles=roles, role_labels=ROLE_LABELS)


@router.post("/settings")
async def settings_save(
    request: Request,
    ad_enabled: str = Form(""),
    ad_domain: str = Form(""),
    ad_servers: str = Form(""),
    ad_service_user: str = Form(""),
    ad_service_password: str = Form(""),
    ad_allowed_group: str = Form(""),
    ad_base_dn: str = Form(""),
    local_admin_password: str = Form(""),
    default_role: str = Form("readonly"),
    smtp_host: str = Form(""),
    smtp_port: str = Form("25"),
    smtp_tls: str = Form(""),
    smtp_user: str = Form(""),
    smtp_password: str = Form(""),
    smtp_from: str = Form(""),
    smtp_to: str = Form(""),
    telegram_bot_token: str = Form(""),
    telegram_chat_id: str = Form(""),
    alert_on_recovery: str = Form(""),
    scheduler_enabled: str = Form(""),
    log_retention_days: str = Form("365"),
    agent_check_time: str = Form("06:30"),
    agent_offline_hours: str = Form("48"),
):
    def _int(v, default):
        try:
            return max(0, int(v))
        except (TypeError, ValueError):
            return default

    updates = {
        "ad_enabled": bool(ad_enabled),
        "ad_domain": ad_domain.strip(),
        "ad_servers": [s.strip() for s in ad_servers.replace("，", ",").split(",")
                       if s.strip()],
        "ad_service_user": ad_service_user.strip(),
        "ad_allowed_group": ad_allowed_group.strip(),
        "ad_base_dn": ad_base_dn.strip(),
        "default_role": default_role if default_role in ROLE_LABELS else "readonly",
        "smtp_host": smtp_host.strip(),
        "smtp_port": _int(smtp_port, 25) or 25,
        "smtp_tls": bool(smtp_tls),
        "smtp_user": smtp_user.strip(),
        "smtp_from": smtp_from.strip(),
        "smtp_to": smtp_to.strip(),
        "telegram_chat_id": telegram_chat_id.strip(),
        "alert_on_recovery": bool(alert_on_recovery),
        "scheduler_enabled": bool(scheduler_enabled),
        "log_retention_days": _int(log_retention_days, 365),
        "agent_check_time": (agent_check_time.strip()
                             if re.fullmatch(r"([01]?\d|2[0-3]):[0-5]\d",
                                             agent_check_time.strip())
                             else "06:30"),
        "agent_offline_hours": _int(agent_offline_hours, 48),
    }
    # 密碼/Token/金鑰類欄位:留空 = 不變更
    for field, value in (("ad_service_password", ad_service_password),
                         ("local_admin_password", local_admin_password),
                         ("smtp_password", smtp_password),
                         ("telegram_bot_token", telegram_bot_token.strip())):
        if value:
            updates[field] = value
    save_settings(updates)
    audit(request, "settings_save", "更新全域設定")
    return RedirectResponse("/settings?saved=1", status_code=303)


@router.post("/settings/alert-test")
async def alert_test():
    """AJAX:依已儲存設定發系統測試告警(Telegram + 郵件收件人)。"""
    from app import notify
    ok, message = await asyncio.to_thread(notify.send_test)
    return {"ok": ok, "message": message}


@router.post("/settings/ad-test")
async def ad_test(request: Request):
    """AJAX:以表單填入的 AD 設定即時逐步測試(Server 連通 → Service Account
    bind → 使用者認證 → 群組驗證),不需先儲存。密碼欄留空時退回已儲存值。"""
    try:
        data = json.loads(await request.body())
    except Exception:  # noqa: BLE001
        return {"ok": False, "steps": [], "message": "無效的請求格式"}
    # LDAP 測試為同步阻塞,丟 thread 避免卡住整個 event loop
    return await asyncio.to_thread(_ad_test_run, data)


def _ad_test_run(data: dict) -> dict:
    """(同步,於 thread 內執行)AD 連線逐步測試主體。"""
    from ldap3 import ALL, NTLM, SUBTREE, Connection, Server
    from ldap3.core.exceptions import LDAPBindError, LDAPException
    import app.auth  # noqa: F401 —— 觸發 MD4 修補(NTLM 需要)

    server_ips_raw = data.get("ad_servers", "").strip()
    domain = data.get("ad_domain", "").strip()
    svc_account = data.get("ad_service_user", "").strip()
    svc_password = data.get("ad_service_password", "").strip() or settings.ad_service_password
    allowed_group = data.get("ad_allowed_group", "").strip()
    base_dn = data.get("ad_base_dn", "").strip()
    test_user = data.get("test_username", "").strip()
    test_pass = data.get("test_password", "")

    steps = []
    if not server_ips_raw or not domain:
        return {"ok": False, "steps": steps, "message": "AD Server IP 或 Domain 未填寫"}

    servers = [s.strip() for s in server_ips_raw.replace("，", ",").split(",") if s.strip()]
    steps.append({"label": "設定解析", "ok": True,
                  "detail": f"Server: {servers},Domain: {domain}"})

    # 測試 Service Account Bind(未填則測匿名連通)
    svc_bind_ok = False
    for ip in servers:
        try:
            ldap_server = Server(ip, get_info=ALL, connect_timeout=5)
            if svc_account and svc_password:
                try:
                    conn = Connection(
                        ldap_server, user=f"{domain}\\{svc_account}",
                        password=svc_password, authentication=NTLM,
                        auto_bind=True, receive_timeout=8)
                    conn.unbind()
                    steps.append({"label": f"Service Account Bind ({ip})", "ok": True,
                                  "detail": f"{domain}\\{svc_account} bind 成功"})
                    svc_bind_ok = True
                    break
                except LDAPBindError as exc:
                    steps.append({"label": f"Service Account Bind ({ip})", "ok": False,
                                  "detail": f"bind 失敗:{exc}"})
                except LDAPException as exc:
                    steps.append({"label": f"Service Account Bind ({ip})", "ok": False,
                                  "detail": f"LDAP 例外:{exc}"})
            else:
                try:
                    conn = Connection(ldap_server, receive_timeout=5)
                    conn.open()
                    conn.unbind()
                    steps.append({"label": f"Server 連通 ({ip})", "ok": True,
                                  "detail": "Server 可達(未使用 Service Account)"})
                    svc_bind_ok = True
                    break
                except Exception as exc:  # noqa: BLE001
                    steps.append({"label": f"Server 連通 ({ip})", "ok": False,
                                  "detail": f"連線失敗:{exc}"})
        except Exception as exc:  # noqa: BLE001
            steps.append({"label": f"Server 連接 ({ip})", "ok": False, "detail": str(exc)})

    # 測試使用者認證(需提供測試帳密)
    if test_user and test_pass:
        for ip in servers:
            try:
                ldap_server = Server(ip, get_info=ALL, connect_timeout=5)
                try:
                    conn = Connection(
                        ldap_server, user=f"{domain}\\{test_user}",
                        password=test_pass, authentication=NTLM,
                        auto_bind=True, receive_timeout=8)
                    conn.unbind()
                    steps.append({"label": f"使用者認證 ({ip})", "ok": True,
                                  "detail": f"{test_user} 認證成功"})
                    # 群組驗證
                    if allowed_group and base_dn and svc_account and svc_password:
                        conn2 = Connection(
                            ldap_server, user=f"{domain}\\{svc_account}",
                            password=svc_password, authentication=NTLM,
                            auto_bind=True, receive_timeout=8)
                        conn2.search(
                            search_base=base_dn,
                            search_filter=f"(sAMAccountName={test_user})",
                            search_scope=SUBTREE, attributes=["memberOf"])
                        if not conn2.entries:
                            steps.append({"label": "群組驗證", "ok": False,
                                          "detail": f"在 Base DN 找不到使用者 {test_user}"})
                        else:
                            try:
                                member_of = list(conn2.entries[0].memberOf) or []
                            except Exception:  # noqa: BLE001
                                member_of = []
                            conn2.unbind()
                            match = any(allowed_group.lower() in str(dn).lower()
                                        for dn in member_of)
                            steps.append({
                                "label": "群組驗證", "ok": match,
                                "detail": (f"共 {len(member_of)} 個群組,"
                                           f"{'包含' if match else '不包含'} "
                                           f"'{allowed_group}'")})
                    break
                except LDAPBindError as exc:
                    steps.append({"label": f"使用者認證 ({ip})", "ok": False,
                                  "detail": f"帳號或密碼錯誤:{exc}"})
                    break
                except LDAPException as exc:
                    steps.append({"label": f"使用者認證 ({ip})", "ok": False,
                                  "detail": f"LDAP 例外:{exc}"})
            except Exception as exc:  # noqa: BLE001
                steps.append({"label": f"使用者認證 ({ip})", "ok": False,
                              "detail": str(exc)})
    else:
        steps.append({"label": "使用者認證", "ok": None,
                      "detail": "未提供測試帳號密碼,跳過"})

    return {"ok": svc_bind_ok, "steps": steps,
            "message": "測試完成" if svc_bind_ok else "部分測試失敗,請查看詳情"}
