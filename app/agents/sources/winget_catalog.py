"""winget community catalog — the only source that exposes real versions.

This is what recovers updates `winget upgrade` cannot see: a program
installed outside any catalog has no Source in `winget list`, so winget
never version-checks it, but the same program usually DOES exist in the
catalog and can be looked up by name.
"""
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from agents import winget_table
from agents.sources import Match

NAME = "winget"
CAN_COMPARE = True

WINGET = "winget"
TIMEOUT_SECS = 25          # one catalog lookup; measured ~0.2s
_CREATE_NO_WINDOW = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0


def lookup(name: str) -> Match | None:
    """Exact-name catalog lookup. None when unknown or unavailable.

    `--exact` is load-bearing. A fuzzy search for "Discord" also returns
    "Discord Canary" and "BetterDiscord"; offering one of those as an update
    would replace the user's software with a different program.
    """
    name = (name or "").strip()
    if not name:
        return None
    try:
        result = subprocess.run(
            [WINGET, "search", "--name", name, "--source", NAME, "--exact",
             "--accept-source-agreements"],
            capture_output=True, text=True, timeout=TIMEOUT_SECS,
            creationflags=_CREATE_NO_WINDOW,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None        # winget missing or wedged — other sources still run
    if result.returncode != 0 or not winget_table.looks_like_table(result.stdout):
        return None        # "No package found matching input criteria." — normal

    rows = winget_table.parse(result.stdout)
    if not rows:
        return None
    if len(rows) > 1:
        # Several distinct packages share this exact name. Picking one would
        # be a guess with the user's software as the stake.
        return Match(source=NAME, package_id="", version=None, ambiguous=True)

    row = rows[0]
    return Match(
        source=NAME,
        package_id=(row.get("Id") or "").strip(),
        version=(row.get("Version") or "").strip() or None,
    )
