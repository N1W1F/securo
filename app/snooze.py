"""Snooze store for urgent findings — pure data, zero execution capability.

Snoozing a finding only changes *when it resurfaces as urgent again*. It
never touches winget, never applies an update, never runs a command. The
worst a bug here can do is show (or hide) a reminder at the wrong time.
"""
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from security import BASE_DIR

SNOOZE_PATH = BASE_DIR / "snoozes.json"
MAX_SNOOZE_DAYS = 90
FINDING_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._+\-:]{0,120}$")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _load() -> dict:
    if not SNOOZE_PATH.is_file():
        return {}
    try:
        return json.loads(SNOOZE_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _save(data: dict) -> None:
    SNOOZE_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def snooze_until(finding_id: str, remind_at_iso: str) -> bool:
    if not FINDING_ID_RE.match(finding_id or ""):
        return False
    try:
        remind_at = datetime.fromisoformat(remind_at_iso.replace("Z", "+00:00"))
    except ValueError:
        return False
    if remind_at.tzinfo is None:
        remind_at = remind_at.replace(tzinfo=timezone.utc)

    now = _now()
    earliest, latest = now, now + timedelta(days=MAX_SNOOZE_DAYS)
    if remind_at < earliest or remind_at > latest:
        return False

    data = _load()
    data[finding_id] = remind_at.isoformat()
    _save(data)
    return True


def is_snoozed(finding_id: str) -> bool:
    data = _load()
    remind_at_iso = data.get(finding_id)
    if not remind_at_iso:
        return False
    try:
        remind_at = datetime.fromisoformat(remind_at_iso)
    except ValueError:
        return False
    return _now() < remind_at


def clear_expired() -> list[str]:
    """Removes expired snoozes, returns the finding ids that just expired
    (so callers can re-surface them as reminders)."""
    data = _load()
    now = _now()
    expired = []
    for fid, remind_at_iso in list(data.items()):
        try:
            remind_at = datetime.fromisoformat(remind_at_iso)
        except ValueError:
            del data[fid]
            continue
        if now >= remind_at:
            expired.append(fid)
            del data[fid]
    if expired:
        _save(data)
    return expired


def active_snoozes() -> dict:
    return _load()
