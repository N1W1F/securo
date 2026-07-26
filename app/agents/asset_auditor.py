"""Agent Beta — Asset Auditor.

Read-only by construction: only ever opens security.INVENTORY_PATH through
security.read_only_open, which enforces the sandbox + size cap. Never writes.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from security import BASE_DIR, INVENTORY_PATH, read_only_open, sanitize_software_name
from audit import log
from agents import winget_table

AGENT = "Asset Auditor"

WINGET = "winget"
SNAPSHOT_PATH = BASE_DIR / "inventory_snapshot.json"
GAME_RE = re.compile(r"\b(steam|epic games|gog|xbox|battle\.net|riot games|origin|ea app|ubisoft|playstation|minecraft|roblox)\b", re.I)
# Redistributables/drivers rarely have a matchable NVD entry by name and just
# add dead-weight NVD queries; they still get winget updates via the
# Updates tab (package_manager scans winget directly, independent of this).
REDIST_RE = re.compile(
    # no trailing \b on branches ending in a symbol (e.g. "c\+\+") — \b requires
    # a word/non-word transition, and "+" followed by a space is non-word-to-
    # non-word, so a wrapping \b(...)​\b silently never matches "Visual C++ ...".
    r"(visual c\+\+|vc\+\+ redistributable|\.net (runtime|desktop runtime|framework)\b|"
    r"\bdirectx\b|\brealtek .*(driver|audio|ethernet)\b|\bnvidia .*driver\b|\bamd .*driver\b|"
    r"\bintel .*driver\b|\bwebview2 runtime\b|\bgame ?input\b)", re.I,
)


def _parse_winget(raw: str) -> list[dict]:
    # Delegates to the shared locale-independent parser. This used to match
    # on the English header words, which returned [] on any non-English
    # Windows (including Arabic — this app's primary audience) and made the
    # scan silently report an empty, "clean" machine.
    return winget_table.parse(raw)


def _write_snapshot(payload: dict) -> None:
    """Local status only; no user-controlled path or secrets."""
    SNAPSHOT_PATH.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


_EMPTY_STATUS = {"total": 0, "scanned": 0, "excluded_games": 0, "excluded_redist": 0,
                 "excluded_items": [], "updated_at": None}


def inventory_status() -> dict:
    if not SNAPSHOT_PATH.is_file():
        return dict(_EMPTY_STATUS)
    try:
        data = json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))
        merged = dict(_EMPTY_STATUS)
        merged.update(data)
        return merged
    except (OSError, json.JSONDecodeError):
        return dict(_EMPTY_STATUS)


def _load_winget_assets() -> list[str]:
    try:
        result = subprocess.run([WINGET, "list", "--accept-source-agreements"], capture_output=True,
                                text=True, timeout=90, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        log(AGENT, f"winget inventory failed: {type(exc).__name__}")
        _write_snapshot({**_EMPTY_STATUS, "error": "winget_unavailable"})
        return []

    # "winget ran but produced nothing we can read" must never be reported
    # as "this machine has no software" — that is an all-clear the scan
    # never earned. Record it as an explicit error state instead.
    if not winget_table.looks_like_table(result.stdout):
        log(AGENT, "winget output was not a readable table — reporting as an error, not as an empty machine")
        _write_snapshot({**_EMPTY_STATUS, "error": "winget_unreadable_output"})
        return []

    rows = _parse_winget(result.stdout)
    excluded_games, excluded_redist, accepted, seen = [], [], [], set()
    for row in rows:
        name = sanitize_software_name(row.get("Name", ""))
        if not name:
            continue
        if GAME_RE.search(name):
            excluded_games.append(name)
            continue
        if REDIST_RE.search(name):
            excluded_redist.append(name)
            continue
        key = name.casefold()
        if key not in seen:
            seen.add(key)
            # append the installed version so threat_hunter's cache key (and
            # a forced re-scan after a winget update) actually changes when
            # the software changes — without this, "Telegram Desktop" was
            # the cache key both before AND after an update, so the same
            # pre-update CVE matches kept being served forever.
            version = (row.get("Version") or "").strip()
            entry = f"{name} {version}" if version and version.lower() != "unknown" else name
            accepted.append(entry)
    from datetime import datetime, timezone
    _write_snapshot({
        "total": len(rows), "scanned": len(accepted),
        "excluded_games": len(excluded_games), "excluded_redist": len(excluded_redist),
        "excluded_items": (excluded_games + excluded_redist)[:40],
        "updated_at": datetime.now(timezone.utc).isoformat(),
    })
    log(AGENT, f"winget inventory: {len(accepted)} scanned, {len(excluded_games)} games + "
              f"{len(excluded_redist)} redistributables/drivers excluded")
    return accepted


def load_assets() -> list[str]:
    # winget is source of truth. inventory.txt remains a safe fallback for PCs without winget.
    winget_assets = _load_winget_assets()
    if winget_assets:
        return winget_assets
    if not INVENTORY_PATH.is_file():
        return []

    assets: list[str] = []
    with read_only_open(INVENTORY_PATH) as f:
        for lineno, raw_line in enumerate(f, start=1):
            name = sanitize_software_name(raw_line)
            if name is None:
                continue
            assets.append(name)

    _write_snapshot({**_EMPTY_STATUS, "total": len(assets), "scanned": len(assets),
                     "source": "inventory_fallback"})
    log(AGENT, f"loaded {len(assets)} valid asset entries from inventory.txt")
    return assets
