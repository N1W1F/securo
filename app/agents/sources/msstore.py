"""Microsoft Store — identifies Store apps, but can never version them.

`winget search --source msstore` returns real package identities and
`Version: Unknown` for every single result; the Store simply does not
publish version numbers through this interface. Measured on a real machine:
32 of 116 untracked programs are Store apps, all with no version.

So this source deliberately declares CAN_COMPARE = False. It cannot answer
"is this out of date?" — but it CAN answer "what is this, and who updates
it?", which turns 32 unexplained entries into 32 entries the user knows
Windows keeps current on its own. Explaining is honest; guessing a version
comparison here would not be.
"""
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from agents import winget_table
from agents.sources import Match

NAME = "msstore"
CAN_COMPARE = False        # the Store exposes no version numbers

WINGET = "winget"
TIMEOUT_SECS = 25
_CREATE_NO_WINDOW = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0


def lookup(name: str) -> Match | None:
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
        return None
    if result.returncode != 0 or not winget_table.looks_like_table(result.stdout):
        return None

    rows = winget_table.parse(result.stdout)
    if not rows:
        return None

    row = rows[0]
    version = (row.get("Version") or "").strip()
    return Match(
        source=NAME,
        package_id=(row.get("Id") or "").strip(),
        # Normalised to None rather than passed through as the literal string
        # "Unknown", so no caller can ever mistake it for a comparable value.
        version=None if version.lower() in ("", "unknown") else version,
    )
