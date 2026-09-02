"""AD(NTLM)驗證 + 帳號分權(RBAC)。

- 驗證流程:Service Account 搜尋使用者 → 使用者帳密 bind 驗密 → 群組授權。
- LDAP 群組只控制「誰能登入」;登入後權限由 account_roles(帳號→角色)決定。
- 角色:full_admin(管理者)/ readonly(唯讀,擋所有寫入)。
  未在對照表中的帳號套用 settings.default_role(預設 readonly);
  內建 admin 恆為 full_admin(緊急備援,防鎖死)。
"""
from __future__ import annotations

import logging

# ── MD4 相容性修補(Python 3.9+/OpenSSL 3.x 停用 MD4,NTLM 需要)──
import hashlib

try:
    hashlib.new("md4")
except ValueError:
    from Crypto.Hash import MD4 as _MD4_impl

    class _MD4Shim:
        name = "md4"
        digest_size = 16
        block_size = 64

        def __init__(self, d=b""):
            self._h = _MD4_impl.new(d)

        def update(self, d):
            self._h.update(d)
            return self

        def digest(self):
            return self._h.digest()

        def hexdigest(self):
            return self._h.hexdigest()

        def copy(self):
            c = _MD4Shim()
            c._h = self._h.copy()
            return c

    _orig_hashlib_new = hashlib.new

    def _patched_hashlib_new(name, *args, **kwargs):
        if name.lower() == "md4":
            return _MD4Shim(args[0] if args else b"")
        return _orig_hashlib_new(name, *args, **kwargs)

    hashlib.new = _patched_hashlib_new
# ── MD4 修補結束 ──

from ldap3 import ALL, FIRST, NTLM, SUBTREE, Connection, Server, ServerPool
from ldap3.utils.conv import escape_filter_chars

from app.config import save_settings, settings
from app.database import SessionLocal
from app.models import AccountRole

logger = logging.getLogger("ucc.auth")

ROLE_LABELS = {
    "full_admin": "管理者",
    "readonly": "唯讀",
}
_DEFAULT = "readonly"   # fail-safe:未知/未設 → 最小權限


def resolve_roles(username: str) -> list[str]:
    """登入帳號 → 角色清單(依 ROLE_LABELS 順序正規化)。

    內建 admin 恆為 ["full_admin"];未在對照表者套 default_role。
    """
    if username == "admin":
        return ["full_admin"]
    roles: set[str] = set()
    try:
        with SessionLocal() as db:
            for r in db.query(AccountRole).all():
                if (r.username.strip().lower() == username.strip().lower()
                        and r.role in ROLE_LABELS):
                    roles.add(r.role)
    except Exception:  # noqa: BLE001
        pass
    if not roles:
        role = settings.default_role
        roles = {role if role in ROLE_LABELS else _DEFAULT}
    return [r for r in ROLE_LABELS if r in roles]


_roles_cache: dict[str, tuple[float, list[str]]] = {}
_ROLES_TTL = 10.0


def resolve_roles_cached(username: str) -> list[str]:
    """resolve_roles 的短 TTL 快取版(middleware / 模板每請求呼叫)。

    授權即時化:角色不再沿用「登入當下」寫進 session 的快照——分權表
    變更(如撤掉 full_admin)最晚 _ROLES_TTL 秒內對既有 session 生效,
    不必等對方登出;快取避免每個請求都打一次 SQLite。
    """
    import time
    now = time.monotonic()
    hit = _roles_cache.get(username)
    if hit and now - hit[0] < _ROLES_TTL:
        return hit[1]
    roles = resolve_roles(username)
    _roles_cache[username] = (now, roles)
    return roles


def roles_of(user: dict) -> set:
    """session user → 角色集合(相容舊 session 只有單一 role 的情況)。"""
    return set((user or {}).get("roles") or [(user or {}).get("role", "readonly")])


def group_match(member_of, allowed_group: str) -> bool:
    """群組授權比對:取每個群組 DN 的第一個 RDN(CN=值)不分大小寫精確相等。

    不用子字串比對——「BG-Admins」不可放行「BG-Admins-Test」,也不可因
    DN 路徑(OU 名)恰含該字串而誤放行。"""
    want = (allowed_group or "").strip().lower()
    if not want:
        return False
    for gdn in member_of or []:
        rdn = str(gdn).split(",", 1)[0].strip()
        if rdn.lower().startswith("cn=") and rdn[3:].strip().lower() == want:
            return True
    return False


def authenticate_ad(username: str, password: str) -> tuple[bool, object]:
    """回傳 (True, {'id','name'}) 或 (False, 錯誤訊息字串)。"""
    # 統一帳號格式為純 sAMAccountName
    if "\\" in username:
        username = username.split("\\", 1)[1]
    elif "/" in username:
        username = username.split("/", 1)[1]
    elif "@" in username:
        username = username.split("@", 1)[0]
    username = username.strip()

    # 空帳密直接拒絕:LDAP 對空密碼可能以匿名/未驗證 bind 回報成功,
    # 不能把「bind 成功」當「密碼正確」
    if not username or not password:
        return False, "帳號與密碼不可為空"

    domain = settings.ad_domain
    server_ips = settings.ad_servers
    svc_user = settings.ad_service_user
    svc_pass = settings.ad_service_password
    allowed_group = settings.ad_allowed_group
    base_dn = settings.ad_base_dn

    if not server_ips:
        return False, "尚未設定 AD 伺服器"

    servers = [Server(ip, get_info=ALL) for ip in server_ips]
    server_pool = ServerPool(servers, pool_strategy=FIRST)
    full_svc = f"{domain}\\{svc_user}" if "\\" not in svc_user else svc_user

    try:
        # Step 1:Service Account 連線搜尋使用者
        conn = Connection(
            server_pool, user=full_svc, password=svc_pass,
            authentication=NTLM, auto_bind=True,
        )
        if not base_dn:
            try:
                if conn.server and conn.server.info:
                    base_dn = conn.server.info.other.get(
                        "defaultNamingContext", [None])[0]
            except Exception:  # noqa: BLE001
                base_dn = None
            if not base_dn:
                return False, "無法自動偵測 Base DN,請於設定頁手動填寫"
            save_settings({"ad_base_dn": base_dn})

        conn.search(
            base_dn,
            f"(&(objectClass=user)(sAMAccountName={escape_filter_chars(username)}))",
            attributes=["distinguishedName", "memberOf", "displayName"],
            search_scope=SUBTREE,
        )
        if not conn.entries:
            return False, "找不到該使用者帳號"

        entry = conn.entries[0]
        display_name = entry.displayName.value if "displayName" in entry else username
        member_of = entry.memberOf.value if "memberOf" in entry else []
        conn.unbind()

        # Step 2:使用者帳密驗密
        user_conn = Connection(
            server_pool, user=f"{domain}\\{username}",
            password=password, authentication=NTLM,
        )
        if not user_conn.bind():
            return False, "密碼錯誤"
        user_conn.unbind()

        # Step 3:群組授權(未設允許群組 = 通過驗證即放行)
        if isinstance(member_of, str):
            member_of = [member_of]
        user_info = {"id": username, "name": display_name}
        if not allowed_group:
            return True, user_info
        if group_match(member_of, allowed_group):
            return True, user_info
        return False, f"驗證通過,但您不在授權群組({allowed_group})內"

    except Exception as exc:  # noqa: BLE001
        return False, f"AD 連線或驗證錯誤:{exc}"
