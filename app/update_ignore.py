"""Ignore list for winget updates the user chooses to dismiss.

Pure data store — never touches winget, never applies anything. Ignoring an
update only removes it from the scan results shown to the user, keyed to
the specific available version so a *later* update to the same package
still resurfaces.
"""
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from security import BASE_DIR

IGNORE_PATH = BASE_DIR / "ignored_updates.json"
PACKAGE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+_.\-]{0,120}$")


def _load() -> dict:
    if not IGNORE_PATH.is_file():
        return {}
    try:
        return json.loads(IGNORE_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _save(data: dict) -> None:
    IGNORE_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def ignore(package_id: str, available_version: str) -> bool:
    if not PACKAGE_ID_RE.match(package_id or ""):
        return False
    data = _load()
    data[package_id] = str(available_version or "")
    _save(data)
    return True


def unignore(package_id: str) -> bool:
    data = _load()
    if package_id in data:
        del data[package_id]
        _save(data)
    return True


def is_ignored(package_id: str, available_version: str) -> bool:
    """True only if this exact version was the one dismissed — a newer
    available version always resurfaces."""
    return _load().get(package_id) == str(available_version or "")
