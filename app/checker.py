"""檢查執行核心:SSH 連入執行 + 檢查結果入庫(agent / ssh 兩模式共用)。

- run_ssh_check():開獨立 DB session,先建 running 的 CheckRun(UI 立即可見),
  再以 paramiko 連入目標主機 → sftp 上傳 ucc_check.sh → sudo 執行 →
  取回 JSON 結果與人類可讀報告 → save_report() 入庫。
- save_report():兩模式共用的入庫邏輯(Agent 回報端點也走這裡),
  同時維護 Host 的最近檢查摘要,並在「執行失敗 ↔ 恢復」轉態時發系統告警。
- 檢查腳本本身唯讀(只稽核、零改動);本模組對目標主機的寫入僅限
  /tmp 暫存腳本與結果檔,執行後即刪除。
- running 生命週期守護:排程會跳過任何有 running 紀錄的主機,遺留的 running
  等同該主機「永久靜默停擺」,因此三道防線 ——
  reset_orphan_runs()(啟動復位)、expire_stale_runs()(逾時仲裁)、
  run_ssh_check() 的防重入閘(排程與手動同時觸發只跑一條)。
"""
from __future__ import annotations

import io
import json
import logging
import secrets
import threading
from datetime import timedelta
from pathlib import Path

import paramiko

from app import notify
from app.config import local_now, settings
from app.database import SessionLocal
from app.models import (
    CheckItemDisable, CheckResult, CheckRun, Host, ResultChange,
)

logger = logging.getLogger("ucc.checker")

SCRIPT_PATH = Path(__file__).parent / "agent" / "ucc_check.sh"
CONNECT_TIMEOUT = 15
EXEC_TIMEOUT = 3600     # SLOW=1 全磁碟掃描在大磁碟上可能跑很久
RAW_MAX = 200_000       # raw_output 入庫上限(防異常輸出撐爆 DB)
STALE_RUN_SECONDS = 7200   # running 逾時門檻(EXEC_TIMEOUT + 緩衝);超過視為卡死
_HISTORY_RUNS = 5          # 比對異動時回溯的成功檢查輪數(判斷是否為真的新項目)
_TRIGGER_LABELS = {"schedule": "排程", "manual": "手動"}


def script_text() -> str:
    """檢查腳本內容(統一 LF;Windows 開發機 checkout 造成的 CRLF 會弄壞 bash)。"""
    return SCRIPT_PATH.read_text(encoding="utf-8").replace("\r\n", "\n")


def script_version() -> str:
    for line in script_text().splitlines():
        if line.startswith("SCRIPT_VERSION="):
            return line.split("=", 1)[1].strip().strip('"')
    return "unknown"


# ──────────────────────────────────────────────────────────────────
# 入庫(兩模式共用)
# ──────────────────────────────────────────────────────────────────

# 舊版 agent(ucc_check.sh v2.1.1 之前)JSON 未帶 family,只能由 os 字串推斷
_DEB_HINTS = ("ubuntu", "debian", "mint", "kali", "raspbian", "devuan",
              "pop!_os", "elementary", "zorin")
_RPM_HINTS = ("red hat", "redhat", "rhel", "centos", "rocky", "alma",
              "fedora", "oracle linux", "suse", "amazon linux", "anolis")


def _resolve_family(host: Host, data: dict) -> str:
    """判定檢查結果所屬系列(停用項過濾用)。

    正常情況一律由回報端提供 family(ucc_check.sh v2.1.1 起與所有 driver 皆有),
    只有舊版 agent 需由 os 字串推斷。推不出來時記 warning 而非靜默落入 rpm;
    網路設備 driver 沒帶 family 則屬程式錯誤,直接拋例外(套錯停用清單會讓
    檢查項無聲消失,對合規平台是最危險的假陰性)。
    """
    family = str(data.get("family") or "").strip()
    if family:
        return family
    if host.device_type != "linux":
        raise RuntimeError(
            f"設備類型 {host.device_type} 的 driver 回傳結果未帶 family,"
            "無法判定檢查項系列(請修正該 driver)")
    os_name = str(data.get("os", "")).lower()
    if any(k in os_name for k in _DEB_HINTS):
        return "deb"
    if any(k in os_name for k in _RPM_HINTS):
        return "rpm"
    logger.warning(
        "主機 %s 回報的結果未帶 family,且無法由 os 字串「%s」判定系列;"
        "暫以 rpm 套用停用清單,請將 agent 檢查腳本更新到 v2.1.1 以上",
        host.name, data.get("os", ""))
    return "rpm"


def save_report(db, host: Host, data: dict, raw_output: str,
                mode: str, run: CheckRun | None = None) -> CheckRun:
    """檢查結果 JSON → CheckRun + CheckResult;同時更新 Host 摘要與告警轉態。

    data 為 ucc_check.sh 的 JSON 輸出(summary/items/os/kernel...)。
    run 傳入既有的 running 紀錄(SSH 模式);Agent 回報時為 None、就地新建。
    """
    items = data.get("items") or []

    # 停用項過濾(依系列;v2.1.1 起 JSON 帶 family,舊版由 os 字串推斷)
    family = _resolve_family(host, data)
    disabled = {r.item_id for r in db.query(CheckItemDisable)
                .filter(CheckItemDisable.family == family).all()}
    if disabled:
        items = [it for it in items if str(it.get("id", "")) not in disabled]

    # 計數以過濾後的明細重算(不採信腳本 summary,兩者在有停用項時會不一致);
    # 未知 status(拼錯/新增)一律正規化為 manual 並記 warning,
    # 確保 total 恆等於五類計數合計,不會有無聲落在統計外的項目
    cnt = {"pass": 0, "fail": 0, "warn": 0, "manual": 0, "na": 0}
    for it in items:
        s = str(it.get("status", ""))
        if s not in cnt:
            logger.warning("主機 %s 檢查項 %s 回傳未知狀態「%s」,已正規化為 manual",
                           host.name, it.get("id", ""), s)
            it["status"] = "manual"
            s = "manual"
        cnt[s] += 1

    if run is None:
        run = CheckRun(host_id=host.id, host_name=host.name, mode=mode)
        db.add(run)
    run.status = "success"
    run.finished_at = local_now()
    run.script_version = str(data.get("script_version", ""))[:20]
    run.slow = bool(data.get("slow"))
    run.raw_output = (raw_output or "")[:RAW_MAX]
    run.c_pass = cnt["pass"]
    run.c_fail = cnt["fail"]
    run.c_warn = cnt["warn"]
    run.c_manual = cnt["manual"]
    run.c_na = cnt["na"]
    run.total = len(items)
    db.flush()  # 取得 run.id
    for it in items:
        db.add(CheckResult(
            run_id=run.id,
            item_id=str(it.get("id", ""))[:80],
            category=str(it.get("cat", ""))[:80],
            status=str(it.get("status", ""))[:10],
            description=str(it.get("desc", ""))[:600],
        ))
    _record_changes(db, host, run, items, disabled)
    _record_versions(db, host, run, items, disabled)
    _trim_versions(db, host)

    prev_status = host.last_run_status
    host.last_checked_at = local_now()
    host.last_run_status = "success"
    host.reported_hostname = str(data.get("hostname", ""))[:200]
    host.os_name = str(data.get("os", ""))[:200]
    host.kernel = str(data.get("kernel", ""))[:100]
    host.script_version = run.script_version
    was_offline = host.offline_alerted
    host.offline_alerted = False
    db.commit()

    if (prev_status == "failed" or was_offline) and settings.alert_on_recovery:
        notify.send_async(
            "✅ BaselineGuard 恢復",
            f"主機 {host.name} 檢查恢復正常"
            f"(符合 {run.c_pass}/不符 {run.c_fail})")
    logger.info("主機 %s 檢查完成:符合 %s/不符 %s/注意 %s/人工 %s/不適用 %s",
                host.name, run.c_pass, run.c_fail, run.c_warn,
                run.c_manual, run.c_na)
    return run


def _record_changes(db, host: Host, run: CheckRun, items: list,
                    disabled: set[str] | None = None) -> None:
    """與該主機前一次成功檢查比對,把狀態轉變寫入 result_changes(儀表板近期異動)。

    首輪檢查建基線不記;before/after 空字串表示新出現/消失的項目。
    四道噪音防護:
    1. 現在停用中的檢查項不參與比對 —— 否則管理者一停用 N 項,下一輪每台
       主機都冒出 N 筆假「消失」。
    2. 前一輪若沒有任何可比對的明細,視同無基線 → 不記異動,避免全部項目
       被記成「新出現」洪水。
    3. 前一輪缺席、但更前面幾輪出現過的項目不記「新出現」 —— 對應
       「停用後重新啟用」與前一輪部分缺漏的情形。
    4. 本輪完全沒有明細(driver 部分失敗回空 items)同樣不記 —— 否則會反向
       灌入整批假「消失」。
    """
    disabled = disabled or set()
    if not items:
        logger.warning("主機 %s 本輪檢查沒有任何明細,不記異動(避免整批假『消失』)",
                       host.name)
        return
    # 一次取回最近幾輪成功檢查的 id:第一筆是比對基準,整批用來判斷「曾出現過」
    recent_ids = [i for (i,) in
                  db.query(CheckRun.id)
                  .filter(CheckRun.host_id == host.id,
                          CheckRun.status == "success",
                          CheckRun.id != run.id)
                  .order_by(CheckRun.id.desc()).limit(_HISTORY_RUNS).all()]
    if not recent_ids:
        return                       # 首輪檢查:只建基線
    prev_map = {r.item_id: r for r in db.query(CheckResult)
                .filter(CheckResult.run_id == recent_ids[0]).all()
                if r.item_id not in disabled}
    if not prev_map:
        logger.info("主機 %s 前一輪檢查沒有可比對的明細,本輪視同重建基線不記異動",
                    host.name)
        return
    seen_before = {i for (i,) in
                   db.query(CheckResult.item_id)
                   .filter(CheckResult.run_id.in_(recent_ids)).distinct().all()}
    cur_ids = set()
    for it in items:
        iid = str(it.get("id", ""))[:80]
        cur_ids.add(iid)
        status = str(it.get("status", ""))[:10]
        p = prev_map.get(iid)
        if p is not None and p.status == status:
            continue
        if p is None and iid in seen_before:
            continue    # 前一輪缺席但更早出現過 → 重新啟用/前輪缺漏,不記假「新出現」
        db.add(ResultChange(
            host_id=host.id, host_name=host.name, run_id=run.id,
            item_id=iid, category=str(it.get("cat", ""))[:80],
            before_status=p.status if p else "",
            after_status=status,
            description=str(it.get("desc", ""))[:600]))
    for iid, p in prev_map.items():
        if iid not in cur_ids:
            db.add(ResultChange(
                host_id=host.id, host_name=host.name, run_id=run.id,
                item_id=iid, category=p.category,
                before_status=p.status, after_status="",
                description=p.description))


_VERSIONS_CAP_PER_HOST = 20000   # 版本軸安全閥(正常用量遠低於此,見 _trim_versions)


def _trim_versions(db, host: Host) -> None:
    """版本歷程每主機筆數安全閥:超過即修剪最舊者。

    ItemVersion 設計上不受保留天數清理(長期版本軸),但這也讓持有 token
    的被攻陷主機可藉由每次回報翻轉大量項目狀態,無上限地灌爆資料庫。
    正常使用(數百項 × 偶發異動)遠低於此閥值,觸發即代表異常灌報。
    """
    from sqlalchemy import func as _f
    from app.models import ItemVersion
    db.flush()
    n = (db.query(_f.count(ItemVersion.id))
         .filter(ItemVersion.host_id == host.id).scalar() or 0)
    if n <= _VERSIONS_CAP_PER_HOST:
        return
    overflow = n - _VERSIONS_CAP_PER_HOST
    oldest = [vid for (vid,) in
              db.query(ItemVersion.id)
              .filter(ItemVersion.host_id == host.id)
              .order_by(ItemVersion.id).limit(overflow).all()]
    (db.query(ItemVersion).filter(ItemVersion.id.in_(oldest))
     .delete(synchronize_session=False))
    logger.warning("主機 %s 版本歷程達安全閥 %s 筆,修剪最舊 %s 筆(疑似異常灌報)",
                   host.name, _VERSIONS_CAP_PER_HOST, overflow)


def _record_versions(db, host: Host, run: CheckRun, items: list,
                     disabled: set[str] | None = None, ts=None) -> None:
    """版本歷程:只存初始基線與異動 → item_versions(「版本歷程」頁)。

    與 _record_changes(近期異動,受保留清理)分工:本表為長期版本軸,
    比對對象是「每個 item 最後一筆版本」而非前一輪,因此狀態未變但內容
    變了也會記一筆 kind=desc(看得出設定值的變化)。
    噪音防護比照 _record_changes:本輪空明細不記(避免整批假「消失」)、
    停用中的項目不記「消失」。ts 供歷史回填指定時間(預設當下)。
    """
    from app.models import ItemVersion
    disabled = disabled or set()
    if not items:
        return
    when = ts or local_now()
    last: dict[str, ItemVersion] = {}
    for v in (db.query(ItemVersion).filter(ItemVersion.host_id == host.id)
              .order_by(ItemVersion.id).all()):
        last[v.item_id] = v          # 後蓋前 → 每項只留最後版本

    def _add(iid, cat, kind, b_st, st, b_desc, desc):
        db.add(ItemVersion(
            host_id=host.id, host_name=host.name, run_id=run.id,
            recorded_at=when, item_id=iid[:80], category=(cat or "")[:80],
            kind=kind, before_status=(b_st or "")[:10], status=(st or "")[:10],
            before_desc=(b_desc or "")[:600], description=(desc or "")[:600]))

    if not last:                     # 首輪:全部項目建初始基線
        for it in items:
            _add(str(it.get("id", "")), str(it.get("cat", "")), "initial",
                 "", str(it.get("status", "")), "", str(it.get("desc", "")))
        return
    cur_ids: set[str] = set()
    for it in items:
        iid = str(it.get("id", ""))[:80]
        cur_ids.add(iid)
        st = str(it.get("status", ""))[:10]
        desc = str(it.get("desc", ""))[:600]
        cat = str(it.get("cat", ""))
        lv = last.get(iid)
        if lv is None or lv.kind == "gone":
            _add(iid, cat, "new", "", st, "", desc)
        elif lv.status != st:
            _add(iid, cat, "status", lv.status, st, lv.description, desc)
        elif lv.description != desc:
            _add(iid, cat, "desc", lv.status, st, lv.description, desc)
    for iid, lv in last.items():
        if iid in cur_ids or iid in disabled or lv.kind == "gone":
            continue
        _add(iid, lv.category, "gone", lv.status, "", lv.description, "")


def rebuild_versions(db) -> int:
    """item_versions 空表時,以既有歷史回填版本軸(啟動時呼叫,冪等)。

    各主機的成功 run 依序重放 _record_versions;時間取各 run 的完成時間。
    歷史明細本就是入庫當時已過濾停用項的結果,回填不再套用停用設定。
    已有任何資料則不動,回 0。
    """
    from app.models import ItemVersion
    if db.query(ItemVersion.id).first() is not None:
        return 0
    for host in db.query(Host).order_by(Host.id).all():
        runs = (db.query(CheckRun)
                .filter(CheckRun.host_id == host.id,
                        CheckRun.status == "success")
                .order_by(CheckRun.id).all())
        for r in runs:
            items = [{"id": res.item_id, "cat": res.category,
                      "status": res.status, "desc": res.description}
                     for res in db.query(CheckResult)
                     .filter(CheckResult.run_id == r.id).all()]
            _record_versions(db, host, r, items,
                             ts=r.finished_at or r.started_at)
        db.commit()
    n = db.query(ItemVersion).count()
    if n:
        logger.info("版本歷程回填完成:%s 筆(初始基線+異動)", n)
    return n


def _finish_failed(db, run_id: int, host_id: int, message: str) -> None:
    """標記執行失敗並在轉態(上次成功 → 這次失敗)時發告警。

    這是失敗路徑的最後防線,自身絕不拋例外:save_report() 若在 flush/commit
    途中失敗(SQLite busy 逾時、長時間 SSH 期間主機被刪),session 會停在
    pending-rollback 狀態,直接 commit 會再拋 PendingRollbackError,
    導致該 run 永遠卡在 running、該主機排程從此靜默停擺。
    因此:先 rollback → 重新取得 run/host(rollback 後原物件可能已過期或不存在)
    → 才寫入失敗狀態;整段再包一層防護,最壞情況只留 log。
    """
    host_name, host_ip, prev_status, need_notify = str(host_id), "", "", False
    try:
        db.rollback()          # 先解除可能的 pending-rollback,否則後面必炸
        run = db.get(CheckRun, run_id)
        host = db.get(Host, host_id)
        if run is None:        # 紀錄已被刪(主機刪除/清理),無處可記
            logger.error("檢查失敗但紀錄已不存在(run_id=%s):%s", run_id, message)
            return
        host_name = run.host_name or host_name
        run.status = "failed"
        run.finished_at = local_now()
        run.message = (message or "")[:2000]
        if host is not None:
            host_name, host_ip = host.name, host.ip_address
            prev_status = host.last_run_status
            host.last_checked_at = local_now()
            host.last_run_status = "failed"
        need_notify = prev_status != "failed"
        db.commit()
    except Exception:  # noqa: BLE001 —— 失敗處理本身不得再拋出
        logger.exception("寫入檢查失敗狀態時發生例外(run_id=%s):%s",
                         run_id, message)
        try:
            db.rollback()
        except Exception:  # noqa: BLE001
            pass
        return
    logger.error("主機 %s 檢查失敗:%s", host_name, message)
    if need_notify:
        notify.send_async("🔴 BaselineGuard 檢查失敗",
                          f"主機 {host_name}({host_ip})\n{message}")


# ──────────────────────────────────────────────────────────────────
# running 生命週期守護(遺留/卡死的執行中紀錄會讓該主機排程永久停擺)
# ──────────────────────────────────────────────────────────────────

def _fail_running_runs(db, runs: list, message: str) -> int:
    """把一批仍是 running 的紀錄結案為失敗,並同步修正主機的最近檢查狀態。

    不動 host.last_checked_at:這些檢查並未真正完成,只把狀態改為失敗,
    讓排程與手動觸發不再被卡住的 running 擋下。
    """
    now = local_now()
    for run in runs:
        run.status = "failed"
        run.finished_at = now
        run.message = message[:2000]
        host = db.get(Host, run.host_id)
        if host is not None:
            host.last_run_status = "failed"
        logger.warning("復位執行中紀錄:run_id=%s 主機 %s —— %s",
                       run.id, run.host_name, message)
    db.commit()
    return len(runs)


def reset_orphan_runs() -> int:
    """程序啟動時復位遺留的 running 紀錄;回傳復位筆數(自身不拋例外)。

    檢查執行中程序被重啟(改設定、部署、當機)會留下永遠停在 running 的
    CheckRun,而排程會跳過任何有 running 紀錄的主機 → 該主機從此不再被檢查
    且不報錯(合規平台最糟的失效模式)。由 scheduler_loop() 進迴圈前呼叫一次。
    """
    try:
        with SessionLocal() as db:
            runs = db.query(CheckRun).filter(
                CheckRun.status == "running").all()
            if not runs:
                return 0
            n = _fail_running_runs(
                db, runs, "程序重啟,執行中斷(啟動時自動復位)")
            logger.warning("啟動復位:%s 筆執行中紀錄已標記為失敗", n)
            return n
    except Exception:  # noqa: BLE001 —— 啟動流程不得因此中斷
        logger.exception("啟動復位執行中紀錄失敗")
        return 0


def expire_stale_runs(db, older_than: int = STALE_RUN_SECONDS) -> int:
    """逾時仲裁:started_at 超過門檻仍是 running 的紀錄視為卡死,結案釋放主機。

    程序沒重啟、但執行走到未預期路徑卡住時的自癒手段(排程每 tick 呼叫,
    手動觸發前也呼叫)。回傳結案筆數。
    """
    cutoff = local_now() - timedelta(seconds=older_than)
    runs = (db.query(CheckRun)
            .filter(CheckRun.status == "running",
                    CheckRun.started_at < cutoff).all())
    if not runs:
        return 0
    n = _fail_running_runs(
        db, runs, f"執行逾時({older_than // 60} 分鐘未結束),已強制結案")
    logger.error("逾時仲裁:%s 筆執行中紀錄超過 %s 秒未結束,已標記失敗",
                 n, older_than)
    return n


# ──────────────────────────────────────────────────────────────────
# SSH 模式
# ──────────────────────────────────────────────────────────────────

_BAD_PASSPHRASE_HINTS = ("checkint", "decrypt", "padding", "bad password",
                         "invalid password", "corrupt data")


def _load_pkey(text: str, password: str = "") -> paramiko.PKey:
    """PEM/OpenSSH 私鑰文字 → paramiko 金鑰物件(依序嘗試常見類型)。

    password 為金鑰 passphrase(主機的密碼欄兼作 passphrase):三種金鑰類型
    都先帶 passphrase 試、再不帶試,加密金鑰因此不再直接判死。
    錯誤訊息區分「格式不支援」與「需要 passphrase / passphrase 不正確」,
    避免把加密金鑰誤報成金鑰格式問題。
    """
    pw = password or None
    attempts = [pw, None] if pw else [None]
    last_exc: Exception | None = None
    need_pass = False        # 金鑰有加密
    bad_pass = False         # 有帶 passphrase 但解不開
    for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        for p in attempts:
            try:
                return cls.from_private_key(io.StringIO(text), password=p)
            except paramiko.PasswordRequiredException as exc:
                need_pass, last_exc = True, exc
            except Exception as exc:  # noqa: BLE001 —— 類型不符或解密失敗
                last_exc = exc
                if p is not None and any(h in str(exc).lower()
                                         for h in _BAD_PASSPHRASE_HINTS):
                    need_pass = bad_pass = True
    if bad_pass or (need_pass and pw):
        raise ValueError("私鑰已加密,提供的密碼無法解開(密碼欄即金鑰 passphrase)")
    if need_pass:
        raise ValueError("私鑰有 passphrase,請在主機的密碼欄填入該 passphrase")
    raise ValueError(f"無法解析私鑰(支援 Ed25519/ECDSA/RSA):{last_exc}")


def _effective_creds(host: Host) -> tuple[str, str, str, str]:
    """該主機的連線憑證(逐台獨立填寫,本平台不提供全域預設帳密)。

    回傳 (username, password, private_key, sudo_password)。
    唯一的後備是 sudo 密碼留空時沿用 SSH 密碼(同一組帳密的常見情形)。

    註:全域「預設 SSH 連線帳密」已於 2026-08 移除 —— 該設計是為了免去重複
    輸入,但實務上即使同類型設備各台帳密也都不同,預設值幾乎用不到;留著
    反而讓「憑證欄空白」有兩種意思(套用預設 vs 真的沒設)而難以判讀。
    """
    username = (host.username or "").strip()
    sudo_pw = host.sudo_password or host.password
    return username, host.password, host.private_key, sudo_pw


def verify_hostkey(host, key) -> None:
    """SSH 主機金鑰 TOFU 檢核:首次連線記錄(由呼叫端 session commit 落地),
    之後不符即拋錯中斷。

    此檢核發生在「認證之前」,密碼/私鑰尚未送出,可擋管理網段的 SSH
    中間人竊取憑證。主機重灌或金鑰輪替時,於主機編輯頁勾「清除已記錄的
    SSH 主機金鑰」重新信任(IP 變更亦自動重置)。
    """
    cur = f"{key.get_name()} {key.get_base64()}"
    stored = (host.ssh_hostkey or "").strip()
    if not stored:
        host.ssh_hostkey = cur
        return
    if stored != cur:
        raise RuntimeError(
            "SSH 主機金鑰與先前記錄不符,已中斷連線(憑證未送出)。"
            "可能原因:主機重灌、IP 重用或中間人攻擊;確認無虞後請於"
            "主機編輯頁勾選「清除已記錄的 SSH 主機金鑰」再重試")


class TofuHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """paramiko SSHClient 用的 TOFU 政策(委派 verify_hostkey)。"""

    def __init__(self, host):
        self._host = host

    def missing_host_key(self, client, hostname, key):
        verify_hostkey(self._host, key)


def _connect(host: Host) -> paramiko.SSHClient:
    username, password, pkey, _ = _effective_creds(host)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(TofuHostKeyPolicy(host))
    kwargs: dict = dict(
        hostname=host.ip_address, port=host.ssh_port or 22,
        username=username, timeout=CONNECT_TIMEOUT,
        banner_timeout=CONNECT_TIMEOUT, auth_timeout=CONNECT_TIMEOUT,
        allow_agent=False, look_for_keys=False,
    )
    if pkey:
        # 密碼欄兼作金鑰 passphrase(加密金鑰必須在解析階段就帶進去)
        kwargs["pkey"] = _load_pkey(pkey, password)
        if password:
            kwargs["password"] = password  # 金鑰認證被拒時退回密碼認證
    else:
        kwargs["password"] = password
    client.connect(**kwargs)
    return client


def _sudo_prefix(host: Host) -> tuple[str, str]:
    """回傳 (sudo 前綴, 需餵入 stdin 的密碼);root 或免密環境不餵密碼。"""
    username, _, _, sudo_pw = _effective_creds(host)
    if username == "root":
        return "", ""
    if sudo_pw:
        return "sudo -S -p '' ", sudo_pw
    return "sudo -n ", ""       # 金鑰登入且未存密碼:需目標機設定免密 sudo


def _exec(client: paramiko.SSHClient, cmd: str, feed: str = "",
          timeout: int = EXEC_TIMEOUT) -> tuple[int, str]:
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    if feed:
        stdin.write(feed + "\n")
        stdin.flush()
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    rc = stdout.channel.recv_exit_status()
    return rc, out + (("\n" + err) if err.strip() else "")


def _ssh_execute(host: Host, slow: bool) -> tuple[str, dict]:
    """連入主機執行檢查;回傳 (人類可讀報告, JSON 結果 dict);失敗拋 RuntimeError。"""
    client = _connect(host)
    try:
        rnd = secrets.token_hex(6)
        rpath = f"/tmp/ucc_check_{rnd}.sh"
        jpath = f"/tmp/ucc_result_{rnd}.json"
        sftp = client.open_sftp()
        sftp.putfo(io.BytesIO(script_text().encode("utf-8")), rpath)

        sudo, sudo_pw = _sudo_prefix(host)
        envs = (f"SLOW={'1' if slow else '0'} UCC_JSON_OUT={jpath} "
                f"NO_COLOR=1")
        rc, raw = _exec(client, f"{sudo}env {envs} bash {rpath}", feed=sudo_pw)

        data: dict | None = None
        try:
            with sftp.open(jpath) as f:
                data = json.loads(f.read().decode("utf-8"))
        except Exception:  # noqa: BLE001 —— 結果檔不存在=腳本沒跑完,下面統一報錯
            data = None

        # 清理暫存(結果檔由 root 產生,刪除也需 sudo;失敗不影響結果)
        _exec(client, f"{sudo}rm -f {rpath} {jpath}", feed=sudo_pw, timeout=30)
        sftp.close()

        if data is None:
            tail = "\n".join(raw.strip().splitlines()[-15:])
            raise RuntimeError(
                f"檢查腳本未產生結果(exit={rc});輸出尾段:\n{tail}")
        return raw, data
    finally:
        client.close()


def run_ssh_check(host_id: int, slow: bool | None = None,
                  trigger: str = "schedule") -> int | None:
    """執行一次拉取式檢查(SSH 或設備 API;同步阻塞,供排程/to_thread 呼叫)。

    Linux 走 SSH 上傳腳本;網路設備走對應 driver(app/drivers)。
    slow=None 時沿用主機設定的 slow_scan。trigger 僅用於 log(排程/手動)。
    回傳 run id(主機不存在、或已有檢查在執行中而略過時回 None)。

    防重入:排程的 running 快照是 tick 開始時取的,手動觸發可能在快照之後才
    落地 running,兩條路徑會同時開跑同一台主機 → 交錯的異動紀錄與被覆寫的
    主機摘要。因此建立 CheckRun 前後各擋一次(建立前查、建立後複驗)。
    """
    trig = _TRIGGER_LABELS.get(trigger, trigger)
    with SessionLocal() as db:
        host = db.get(Host, host_id)
        if host is None or host.mode == "agent":
            return None
        expire_stale_runs(db)   # 先做逾時仲裁,免得卡死的紀錄擋掉之後每一次檢查
        busy = (db.query(CheckRun.id)
                .filter(CheckRun.host_id == host.id,
                        CheckRun.status == "running")
                .order_by(CheckRun.id.desc()).first())
        if busy is not None:
            logger.info("主機 %s 已有執行中的檢查(run_id=%s),略過本次%s觸發",
                        host.name, busy[0], trig)
            return None

        is_device = host.device_type != "linux"
        run = CheckRun(host_id=host.id, host_name=host.name, mode=host.mode,
                       slow=False if is_device
                       else bool(host.slow_scan if slow is None else slow))
        db.add(run)
        db.commit()   # 先落地 running 狀態,UI 立即可見
        run_id = run.id
        # 複驗:兩條路徑幾乎同時通過上面那道閘時,只留 id 較小的那條
        other = (db.query(CheckRun.id)
                 .filter(CheckRun.host_id == host.id,
                         CheckRun.status == "running",
                         CheckRun.id < run_id).first())
        if other is not None:
            db.delete(run)      # 尚未寫入任何明細,直接撤銷本次紀錄
            db.commit()
            logger.info("主機 %s 檢查競態:已有 run_id=%s 在執行,撤銷本次%s觸發",
                        host.name, other[0], trig)
            return None

        logger.info("主機 %s 開始檢查(%s觸發,run_id=%s)", host.name, trig, run_id)
        try:
            if is_device:
                from app import drivers
                drv = drivers.get(host.device_type)
                if drv is None:
                    raise RuntimeError(
                        f"設備類型 {host.device_type} 的檢查 driver 尚未實作")
                raw, data = drv.inspect(host)
            else:
                raw, data = _ssh_execute(host, run.slow)
            save_report(db, host, data, raw, host.mode, run=run)
        except Exception as exc:  # noqa: BLE001 —— 連線/認證/執行任何失敗都收斂到紀錄
            _finish_failed(db, run_id, host_id, f"{type(exc).__name__}: {exc}")
        return run_id


def run_ssh_check_bg(host_id: int, slow: bool | None = None,
                     trigger: str = "manual") -> None:
    """背景執行(手動「立即檢查」用):route 立刻返回,結果由紀錄頁查看。"""
    threading.Thread(target=run_ssh_check, args=(host_id, slow),
                     kwargs={"trigger": trigger}, daemon=True).start()


def test_connection(host: Host) -> tuple[bool, str]:
    """測試連線(不執行檢查);回 (ok, 訊息)。網路設備轉交對應 driver。"""
    if host.device_type != "linux":
        from app import drivers
        drv = drivers.get(host.device_type)
        if drv is None:
            return False, f"設備類型 {host.device_type} 的 driver 尚未實作"
        return drv.test(host)
    try:
        client = _connect(host)
    except Exception as exc:  # noqa: BLE001
        return False, f"SSH 連線失敗:{exc}"
    try:
        rc, out = _exec(client, "id -un", timeout=15)
        if rc != 0:
            return False, f"指令執行失敗:{out.strip()}"
        user = out.strip().splitlines()[0] if out.strip() else host.username
        if user == "root":
            return True, f"連線成功(root 直連,無需 sudo)"
        sudo, sudo_pw = _sudo_prefix(host)
        rc, out = _exec(client, f"{sudo}true", feed=sudo_pw, timeout=15)
        if rc == 0:
            return True, f"連線成功:{user},sudo 可用"
        return False, (f"連線成功({user})但 sudo 失敗:"
                       f"{out.strip() or '請確認 sudo 密碼或免密 sudo 設定'}")
    except Exception as exc:  # noqa: BLE001
        return False, f"測試失敗:{exc}"
    finally:
        client.close()
