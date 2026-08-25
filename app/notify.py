"""系統層告警通知(僅系統層,不含用戶層流程通知)。

- send():檢查失敗 / Agent 失聯 / 恢復等營運事件、測試通知。
  走設定頁的 Telegram 群組 + SMTP 系統收件人(smtp_to)。
- 同步阻塞實作;任何管道失敗都不拋出、不影響主流程,回傳結果字串
  由呼叫端記 log;send_async 為背景 fire-and-forget(有界工作執行緒,
  告警風暴時不會一則一 thread 地無限開下去)。
- SMTP:埠 465 走 SMTPS(隱含 TLS),其他埠依 smtp_tls 勾 STARTTLS;
  smtp_user 留空 = 不做 SMTP AUTH(內部 relay 常見)。
"""
from __future__ import annotations

import json
import logging
import queue
import smtplib
import threading
import urllib.request
from email.message import EmailMessage
from email.utils import formatdate

from app.config import settings

logger = logging.getLogger("ucc.notify")
TIMEOUT = 15.0

# 背景送信的有界工作池:固定 N 條 daemon 執行緒消化佇列。
# 用 daemon thread(而非 ThreadPoolExecutor)是為了保留原本「關閉時立即
# 退出、不被 15 秒 SMTP timeout 拖住」的語意;佇列滿了就丟棄並記 log,
# 告警送不出去絕不能反過來卡住主流程。
_WORKERS = 4
_QUEUE_MAX = 100
_queue: "queue.Queue[tuple[str, str]]" = queue.Queue(maxsize=_QUEUE_MAX)
_workers_lock = threading.Lock()
_workers_started = False


def send(subject: str, text: str) -> str:
    """系統管理告警:對所有已設定管道送出;回傳各管道結果彙總(不拋例外)。"""
    results = _send(subject, text)
    return ";".join(results) if results else "未設定任何告警管道"


def _worker() -> None:
    """工作執行緒:取出佇列中的告警送出;任何例外都不得讓執行緒死掉。"""
    while True:
        subject, text = _queue.get()
        try:
            logger.info("系統告警「%s」→ %s", subject, send(subject, text))
        except Exception:  # noqa: BLE001 — send() 已吞例外,這是最後一道保險
            logger.exception("送出系統告警「%s」時發生未預期錯誤", subject)
        finally:
            _queue.task_done()


def _ensure_workers() -> None:
    """首次使用時才起工作執行緒(未設定告警管道的環境不必白開 thread)。"""
    global _workers_started
    with _workers_lock:
        if _workers_started:
            return
        for i in range(_WORKERS):
            threading.Thread(target=_worker, name=f"ucc-notify-{i}",
                             daemon=True).start()
        _workers_started = True


def send_async(subject: str, text: str) -> None:
    """背景送系統告警(fire-and-forget),結果記 log。"""
    _ensure_workers()
    try:
        _queue.put_nowait((subject, text))
    except queue.Full:
        logger.warning("告警佇列已滿(%s 則待送),丟棄告警「%s」",
                       _QUEUE_MAX, subject)


def send_test() -> tuple[bool, str]:
    """設定頁的測試告警:對已設定的管道(Telegram / SMTP)各發一則。"""
    if not ((settings.telegram_bot_token and settings.telegram_chat_id)
            or (settings.smtp_host and settings.smtp_to)):
        return False, "未設定任何告警管道(Telegram / SMTP 收件人),請先儲存設定"
    results = _send("BaselineGuard 告警測試",
                    "🔔 這是 BaselineGuard 設定頁發出的測試告警 — 看到這則代表管道正常,"
                    "檢查失敗、Agent 失聯等系統告警將送達此處。")
    ok = not any("失敗" in r for r in results)
    return ok, ";".join(results)


def _send(subject: str, text: str) -> list[str]:
    results: list[str] = []

    if settings.telegram_bot_token and settings.telegram_chat_id:
        try:
            req = urllib.request.Request(
                f"https://api.telegram.org/bot{settings.telegram_bot_token}"
                "/sendMessage",
                data=json.dumps(
                    # Telegram 單則上限 4096 字,主旨併入內文
                    {"chat_id": settings.telegram_chat_id,
                     "text": f"{subject}\n{text}"[:4000]},
                    ensure_ascii=False).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                body = json.loads(resp.read().decode("utf-8"))
            if not body.get("ok"):
                raise RuntimeError(body.get("description", "未知錯誤"))
            results.append("Telegram 已送出")
        except Exception as exc:  # noqa: BLE001
            results.append(f"Telegram 失敗:{exc}")

    if settings.smtp_host and settings.smtp_to:
        tos = [t.strip() for t in settings.smtp_to.split(",") if t.strip()]
        results.append(_smtp_send(subject, text, tos))

    return results


def _smtp_send(subject: str, text: str, tos: list[str]) -> str:
    try:
        sender = (settings.smtp_from or settings.smtp_user
                  or f"configcheck@{settings.smtp_host}")
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = ", ".join(tos)
        msg["Date"] = formatdate(localtime=True)
        msg.set_content(text)

        if settings.smtp_port == 465:
            smtp = smtplib.SMTP_SSL(settings.smtp_host,
                                    settings.smtp_port, timeout=TIMEOUT)
        else:
            smtp = smtplib.SMTP(settings.smtp_host,
                                settings.smtp_port, timeout=TIMEOUT)
        with smtp:
            if settings.smtp_tls and settings.smtp_port != 465:
                smtp.starttls()
            if settings.smtp_user:
                smtp.login(settings.smtp_user, settings.smtp_password)
            smtp.send_message(msg)
        return f"郵件已送出({', '.join(tos)})"
    except Exception as exc:  # noqa: BLE001
        return f"郵件失敗:{exc}"
