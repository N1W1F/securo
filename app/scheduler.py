"""Scheduler — periodic auto-scan then notify (feature 10).

A single daemon thread wakes hourly, and when the configured interval has
elapsed it runs one scan (via an injected scan function) and fires a
Windows toast notification if urgent items were found — zero setup, no
account, no password. State (last run) persists to a small file so
restarts don't reset the clock. Enabled purely by schedule_enabled — no
external service required.
"""
import json
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from security import BASE_DIR
from audit import log
import appconfig
import notify

AGENT = "Scheduler"
STATE_PATH = BASE_DIR / "scheduler_state.json"
CHECK_EVERY_SECS = 3600  # wake hourly, act only when due
DAY_SECS = 86400

_thread = None
_scan_lock = threading.Lock()


def _now() -> float:
    return time.time()


def _load_state() -> dict:
    if STATE_PATH.is_file():
        try:
            return json.loads(STATE_PATH.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {"last_run_epoch": 0}


def _save_state(state: dict):
    STATE_PATH.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")


def status() -> dict:
    cfg = appconfig.load_config()
    state = _load_state()
    interval = cfg.get("schedule_interval_days", 7) * DAY_SECS
    last = state.get("last_run_epoch", 0)
    enabled = bool(cfg.get("schedule_enabled"))  # toast needs zero config
    next_epoch = (last + interval) if last else _now()
    return {
        "enabled": enabled,
        "interval_days": cfg.get("schedule_interval_days", 7),
        "last_run": datetime.fromtimestamp(last, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if last else None,
        "next_run": datetime.fromtimestamp(next_epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if enabled else None,
    }


def run_cycle_now(scan_fn, decision_provider=None) -> dict:
    """Scan, then notify. Toast fires whenever the post-scan decision has
    urgent items — the only notification channel, zero setup.
    `decision_provider`, when given, returns (urgent_count, health_score)
    computed fresh after the scan."""
    if not _scan_lock.acquire(blocking=False):
        return {"ok": False, "reason": "busy"}
    try:
        log(AGENT, "cycle start: scan")
        scan_fn()
        _save_state({"last_run_epoch": _now()})

        urgent_count, health_score = 0, None
        if decision_provider:
            try:
                urgent_count, health_score = decision_provider()
            except Exception as e:
                log(AGENT, f"decision_provider error: {type(e).__name__}")

        toast_sent = False
        if urgent_count:
            toast_sent = notify.send(
                "Securo — تنبيه أمني عاجل",
                f"{urgent_count} عنصر يحتاج قرارك الآن. مؤشر الصحة: {health_score if health_score is not None else '—'}",
            )

        log(AGENT, f"cycle done: urgent={urgent_count} toast={toast_sent}")
        return {"ok": True, "urgent": urgent_count, "toast_sent": toast_sent}
    finally:
        _scan_lock.release()


def _loop(scan_fn, decision_provider=None):
    while True:
        try:
            cfg = appconfig.load_config()
            if bool(cfg.get("schedule_enabled")):
                interval = cfg.get("schedule_interval_days", 7) * DAY_SECS
                last = _load_state().get("last_run_epoch", 0)
                if _now() - last >= interval:
                    run_cycle_now(scan_fn, decision_provider)
        except Exception as e:
            log(AGENT, f"loop error: {type(e).__name__}")
        time.sleep(CHECK_EVERY_SECS)


def start(scan_fn, decision_provider=None):
    global _thread
    if _thread and _thread.is_alive():
        return
    _thread = threading.Thread(target=_loop, args=(scan_fn, decision_provider), daemon=True)
    _thread.start()
    log(AGENT, "scheduler thread started")
