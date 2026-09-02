"""BaselineGuard — 組態基線稽核平台(GCB/CIS) 進入點。

啟動:  .\\.venv\\Scripts\\python.exe run.py
      (Web UI 埠 8073;Agent 回報 API 於 lifespan 內另起 uvicorn 服務埠 8074,
       兩埠同一程序、共用 DB 與排程,埠號由 config.json / 環境變數 UCC_* 調整)
"""
import asyncio
import logging
import threading
from contextlib import asynccontextmanager

import uvicorn
from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from sqlalchemy import func
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from app.agent_api import agent_app
from app.auth import resolve_roles_cached
from app.config import (
    ensure_session_secret, migrate_plaintext_secrets, purge_obsolete_fields,
    settings,
)
from app.database import get_db, init_db
from app.models import CheckResult, CheckRun, Host, ResultChange
from app.routes import (
    auth, gaps, hosts, items_routes, logs_routes, runs, settings_routes,
    versions_routes,
)
from app.webutil import host_trends, latest_run_map, render

# 免登入路徑(Agent API 在獨立埠 8074,不經此 app)
PUBLIC_PATHS = {"/login", "/logout", "/favicon.ico"}

# 統一 log 格式:[2026-08-20 13:10:21,784: INFO/ucc.scheduler] 訊息
_LOG_FORMAT = "[%(asctime)s: %(levelname)s/%(name)s] %(message)s"


def _setup_logging() -> None:
    """讓應用層(ucc.*)與 uvicorn 的 log 都帶時間戳。"""
    logging.basicConfig(level=logging.INFO, format=_LOG_FORMAT)
    fmt = logging.Formatter(_LOG_FORMAT)
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        for h in logging.getLogger(name).handlers:
            h.setFormatter(fmt)


_setup_logging()
migrate_plaintext_secrets()  # config.json 既有明文 secret 就地改寫密文(冪等)
purge_obsolete_fields()      # 清除已廢除功能殘留的欄位(含舊的預設 SSH 憑證)


async def _verify_agent_api(server: uvicorn.Server,
                            thread: threading.Thread) -> None:
    """確認 Agent API 真的起來了,沒起來就 error log + 系統告警。

    埠被占用時 uvicorn 的 OSError 只死在 daemon thread 裡,Web UI 一切正常,
    但**所有 agent 的每日回報自此靜默失敗**,要等 agent_offline_hours
    (預設 48 小時)後才以「失聯」形式浮現 —— 太晚了,啟動當下就要吵。
    刻意不讓整個程序拒絕啟動:Web UI / SSH 排程仍可用,半殘勝過全掛。
    """
    log = logging.getLogger("ucc.main")
    port = server.config.port
    for _ in range(50):                       # 最多等 5 秒
        if server.started or not thread.is_alive():
            break
        await asyncio.sleep(0.1)
    if server.started:
        log.info("Agent API 服務於埠 %s", port)
        return
    msg = (f"Agent API 未能在埠 {port} 啟動"
           f"(埠被占用或權限不足)。Web UI 仍可使用,但所有 Agent 模式主機的"
           f"每日回報都會失敗,請檢查埠占用後重啟服務。")
    log.error("%s", msg)
    from app import notify
    notify.send_async("⚠️ BaselineGuard Agent API 啟動失敗", msg)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    # 版本歷程首次啟動回填:item_versions 空表時用既有歷史重建(冪等);
    # 失敗只記 log,不阻擋服務啟動
    try:
        from app.checker import rebuild_versions
        from app.database import SessionLocal
        with SessionLocal() as _vdb:
            rebuild_versions(_vdb)
    except Exception:  # noqa: BLE001
        logging.getLogger("ucc.main").exception("版本歷程回填失敗(不影響啟動)")
    from app.scheduler import scheduler_loop
    sched_task = asyncio.create_task(scheduler_loop())
    # Agent 回報 API:同程序另起一個 uvicorn 服務,綁獨立埠。
    # 跑在獨立 thread(非主執行緒時 uvicorn 不會攔 SIGINT,
    # 避免搶走主伺服器的 Ctrl+C 關閉訊號)
    # log_config=None:第二個 uvicorn 不得重設 logging,否則會把
    # _setup_logging 統一的「[時間: 等級/名稱] 訊息」格式蓋回 uvicorn 預設
    # access_log=False:此埠只有 agent 在打,而 access log 會把完整 URL
    # (含 /install?token=… 的 token)寫進 log,任何可讀 log 的人都能取得
    # token 偽造合規回報 —— 直接不記
    agent_cfg = uvicorn.Config(agent_app, host="0.0.0.0",
                               port=settings.agent_api_port,
                               log_level="info", lifespan="off",
                               log_config=None, access_log=False)
    agent_server = uvicorn.Server(agent_cfg)
    agent_thread = threading.Thread(target=agent_server.run,
                                    name="agent-api", daemon=True)
    agent_thread.start()
    await _verify_agent_api(agent_server, agent_thread)
    yield
    sched_task.cancel()
    # 先請 uvicorn 收工,再等它把手上的 /report 處理完(daemon thread 若隨
    # 直譯器直接退出,正在 commit 的回報會被硬切、該台當日回報就此遺失)
    agent_server.should_exit = True
    agent_thread.join(timeout=5)
    if agent_thread.is_alive():
        logging.getLogger("ucc.main").warning(
            "Agent API 未在 5 秒內收工,將隨程序結束中止")


app = FastAPI(title="BaselineGuard — 組態基線稽核平台(GCB/CIS)",
              lifespan=lifespan)
app.include_router(auth.router)
app.include_router(hosts.router)
app.include_router(runs.router)
app.include_router(gaps.router)
app.include_router(items_routes.router)
app.include_router(versions_routes.router)
app.include_router(logs_routes.router)
app.include_router(settings_routes.router)


@app.middleware("http")
async def require_login(request: Request, call_next):
    """未登入導向 /login;唯讀角色擋寫入(非 GET)請求。"""
    path = request.url.path
    if path in PUBLIC_PATHS or path.startswith("/static/"):
        return await call_next(request)
    user = request.session.get("user")
    if not user:
        if "application/json" in (request.headers.get("accept") or ""):
            return JSONResponse({"error": "未登入"}, status_code=401)
        return RedirectResponse("/login", status_code=303)
    # 角色授權(伺服器端強制;模板隱藏按鈕只是 UI 禮貌)。
    # 每請求經短 TTL 快取重查分權表,而非沿用登入當下的 session 快照,
    # 撤權最晚 10 秒內生效;查表是阻塞 DB I/O,丟執行緒保持非阻塞
    roles = set(await asyncio.to_thread(
        resolve_roles_cached, str(user.get("id", ""))))
    if "full_admin" not in roles and request.method not in ("GET", "HEAD"):
        msg = "此帳號為唯讀權限,不可執行此寫入操作。"
        if "application/json" in (request.headers.get("accept") or ""):
            return JSONResponse({"error": msg}, status_code=403)
        return HTMLResponse(
            f'<div style="font-family:sans-serif;padding:40px;max-width:600px">'
            f'<h2>403 權限不足</h2><p>{msg}</p>'
            f'<p><a href="javascript:history.back()">← 返回</a></p></div>',
            status_code=403)
    return await call_next(request)


# SessionMiddleware 後加 → 最外層 → 先執行,讓 require_login 內能讀 request.session。
# session_cookie 取專屬名稱:cookie 只認主機不分埠,同機其他 starlette 系統
# 若都用預設名 "session" 會互相覆蓋、造成彼此莫名登出。
app.add_middleware(SessionMiddleware, secret_key=ensure_session_secret(),
                   same_site="lax", session_cookie="ucc_session")


@app.get("/favicon.ico")
async def favicon():
    return Response(status_code=204)


def _donut(parts: list[tuple[str, int, str]]) -> dict | None:
    """(標籤, 數量, CSS 變數名) → conic-gradient 甜甜圈資料。

    回傳 {gradient, legend, total};總數為 0 回 None(模板顯示空狀態)。
    """
    total = sum(c for _, c, _ in parts)
    if total == 0:
        return None
    stops, legend, acc = [], [], 0
    for label, count, var in parts:
        if count == 0:
            continue
        start = acc / total * 100
        acc += count
        end = acc / total * 100
        stops.append(f"var({var}) {start:.2f}% {end:.2f}%")
        legend.append({"label": label, "count": count,
                       "pct": round(count / total * 100), "var": var})
    return {"gradient": ", ".join(stops), "legend": legend, "total": total}



@app.get("/api/status")
async def status_api(db: Session = Depends(get_db)):
    """各主機最後檢查時間與狀態,供頂欄指示器 30 秒輪詢。"""
    data = []
    for h in db.query(Host).filter(Host.enabled.is_(True)).all():
        data.append({
            "id": h.id,
            "name": h.name,
            "last_checked_at": (h.last_checked_at.isoformat()
                                if h.last_checked_at else None),
            "last_status": h.last_run_status or None,
        })
    return {"hosts": data}


@app.get("/")
async def dashboard(request: Request, db: Session = Depends(get_db)):
    hosts_all = db.query(Host).order_by(Host.name).all()
    latest = latest_run_map(db)

    host_rows = [{"h": h, "run": latest.get(h.id)} for h in hosts_all]
    ok_hosts = sum(1 for r in host_rows
                   if r["run"] is not None and r["run"].status == "success"
                   and r["run"].c_fail == 0)
    failed_hosts = sum(1 for r in host_rows
                       if r["run"] is not None and r["run"].status == "failed")
    offline_hosts = sum(1 for h in hosts_all if h.offline_alerted)
    success_runs = [r["run"] for r in host_rows
                    if r["run"] is not None and r["run"].status == "success"]
    avg_pct = (round(sum(r.pass_pct for r in success_runs) / len(success_runs))
               if success_runs else 0)

    # 甜甜圈:全機隊檢查結果分布(各主機最新成功 run 的五類加總)
    donut_status = _donut([
        ("符合", sum(r.c_pass for r in success_runs), "--allow"),
        ("不符", sum(r.c_fail for r in success_runs), "--deny"),
        ("注意", sum(r.c_warn for r in success_runs), "--warn"),
        ("人工判定", sum(r.c_manual for r in success_runs), "--manual"),
        ("不適用", sum(r.c_na for r in success_runs), "--text3"),
    ])

    # 甜甜圈:主機狀態分布(每台歸入一類)
    cat = {"clean": 0, "gap": 0, "failed": 0, "offline": 0, "none": 0}
    for row in host_rows:
        h, r = row["h"], row["run"]
        if h.offline_alerted:
            cat["offline"] += 1
        elif r is None:
            cat["none"] += 1
        elif r.status == "failed":
            cat["failed"] += 1
        elif r.status == "success" and r.c_fail == 0:
            cat["clean"] += 1
        else:
            cat["gap"] += 1
    donut_hosts = _donut([
        ("全數符合", cat["clean"], "--allow"),
        ("有不符項", cat["gap"], "--deny"),
        ("檢查失敗", cat["failed"], "--warn"),
        ("Agent 失聯", cat["offline"], "--manual"),
        ("尚無紀錄", cat["none"], "--text3"),
    ])

    # 跨主機共通不符項 Top 10(以各主機最新成功 run 彙總)
    ok_ids = [r.id for r in success_runs]
    top_fails = []
    if ok_ids:
        rows = (db.query(CheckResult.item_id,
                         func.count().label("n"),
                         func.max(CheckResult.description))
                .filter(CheckResult.run_id.in_(ok_ids),
                        CheckResult.status == "fail")
                .group_by(CheckResult.item_id)
                .order_by(func.count().desc())
                .limit(10).all())
        top = max((n for _, n, _ in rows), default=1) or 1
        top_fails = [{"item_id": iid, "count": n, "desc": desc,
                      "pct": round(n / top * 100)}
                     for iid, n, desc in rows]

    # 各主機最新 run 與前次的不符數差(「變化」欄)
    from app.routes.logs_routes import fail_deltas
    fail_delta = fail_deltas(db, [r for r in latest.values()])

    # 各主機趨勢迷你圖(近 12 次成功檢查:符合率折線 + 不符增減長條)
    sparks, changes = host_trends(db)

    # 近期異動(入庫時與前一輪比對;卡片固定高度內捲動,故多取一些)
    recent_changes = (db.query(ResultChange)
                      .order_by(ResultChange.id.desc()).limit(50).all())
    change_total = db.query(ResultChange).count()

    return render(
        request, "dashboard.html", "dashboard",
        recent_changes=recent_changes, change_total=change_total,
        host_rows=host_rows, fail_delta=fail_delta,
        sparks=sparks, changes=changes,
        total_hosts=len(hosts_all),
        ok_hosts=ok_hosts,
        failed_hosts=failed_hosts,
        offline_hosts=offline_hosts,
        avg_pct=avg_pct,
        top_fails=top_fails,
        donut_status=donut_status,
        donut_hosts=donut_hosts,
    )
