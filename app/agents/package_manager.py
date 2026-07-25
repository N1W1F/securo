"""Agent Delta — Package Manager (scan + apply updates via winget).

Design choices driven by safety, not convenience:
  - Every winget invocation is a fixed argv list — never shell=True, never a
    string built from user input.
  - `scan_upgradable` is read-only (winget list) and is the ONLY source of
    truth for what package IDs exist; `apply_update` refuses any ID that
    wasn't present in the most recent scan, so a tampered API call can't
    smuggle in an arbitrary winget package ID.
  - Updates are applied one package at a time via winget's own installer
    flow (signed packages, its own elevation prompts when required) — we
    never suppress UAC or bypass Windows' own consent mechanism.
"""
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from audit import log
from agents import winget_table

AGENT = "Package Manager"

WINGET = "winget"
SCAN_TIMEOUT_SECS = 90
DETAILS_TIMEOUT_SECS = 40
UPDATE_TIMEOUT_SECS = 900
PACKAGE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+_.\-]{0,120}$")

_last_scanned_ids: set[str] = set()
_details_cache: dict[str, dict] = {}

_CREATE_NO_WINDOW = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0


def _run(args: list[str], timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        creationflags=_CREATE_NO_WINDOW,
    )


def _human_size(n: int) -> str:
    step = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if step < 1024 or unit == "GB":
            return f"{step:.0f} {unit}" if unit == "B" else f"{step:.1f} {unit}"
        step /= 1024
    return f"{n} B"


def _parse_table(raw: str) -> list[dict]:
    # Delegates to the shared locale-independent parser. Matching on the
    # English header words returned [] on any non-English Windows, which
    # surfaced as "no updates available" on a machine full of outdated
    # software.
    return winget_table.parse(raw)


# Package sources winget can actually upgrade for us. Previously this was
# hardcoded to just "winget", which silently dropped any Microsoft Store
# package that had an update available — the row was parsed correctly and
# then thrown away, so the update simply never appeared in the UI.
UPGRADABLE_SOURCES = {"winget", "msstore"}

_last_coverage = {"total": 0, "tracked": 0, "untracked": 0}


def coverage() -> dict:
    """How much of the installed software winget can even check for updates.

    Packages with no Source (installed outside any winget catalog, or apps
    that self-update like browsers) are invisible to update detection — on
    a typical machine that's the MAJORITY of installed software. Surfacing
    this stops "N updates available" from being read as "N is everything
    that's out of date", which it is not."""
    return dict(_last_coverage)


def scan_upgradable() -> list[dict]:
    global _last_scanned_ids
    log(AGENT, "scanning installed packages via winget list")
    try:
        # Plain `winget list` (no --include-unknown: that flag is only legal
        # alongside --upgrade-available, and passing it here makes winget
        # refuse the command outright and emit no table at all).
        result = _run([WINGET, "list", "--accept-source-agreements"], SCAN_TIMEOUT_SECS)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        log(AGENT, f"winget scan failed: {e}")
        return []

    rows = _parse_table(result.stdout)
    tracked = [r for r in rows if r.get("Source") in UPGRADABLE_SOURCES]
    _last_coverage.update({
        "total": len(rows),
        "tracked": len(tracked),
        "untracked": len(rows) - len(tracked),
    })

    upgradable = [
        r for r in tracked
        if r.get("Available")
        and r.get("Available") not in ("", "Unknown")
        and PACKAGE_ID_RE.match(r.get("Id", ""))
    ]
    _last_scanned_ids = {r["Id"] for r in upgradable}
    log(AGENT, f"found {len(upgradable)} package(s) with an available update "
               f"({len(tracked)} of {len(rows)} installed packages are update-trackable)")
    return upgradable


def get_details(package_id: str) -> dict:
    """Publisher + real download size for one upgradable package.

    Size comes from a HEAD request against the installer URL that winget's
    own manifest reports (never a URL from the client). Only https + HEAD,
    timed out, no body downloaded. Result cached per id.
    """
    if package_id not in _last_scanned_ids or not PACKAGE_ID_RE.match(package_id):
        return {"id": package_id, "publisher": None, "sizeBytes": None, "sizeText": None}
    if package_id in _details_cache:
        return _details_cache[package_id]

    publisher, installer_url = None, None
    try:
        res = _run([WINGET, "show", "--id", package_id, "-e", "--disable-interactivity"],
                   DETAILS_TIMEOUT_SECS)
        for line in res.stdout.splitlines():
            s = line.strip()
            if s.startswith("Publisher:") and publisher is None:
                publisher = s.split(":", 1)[1].strip()
            elif s.startswith("Installer Url:"):
                installer_url = s.split(":", 1)[1].strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    size_bytes = None
    if installer_url and installer_url.lower().startswith("https://"):
        try:
            req = urllib.request.Request(installer_url, method="HEAD",
                                         headers={"User-Agent": "threat-intel-agent/1.0"})
            with urllib.request.urlopen(req, timeout=15) as r:
                cl = r.headers.get("Content-Length")
                size_bytes = int(cl) if cl and cl.isdigit() else None
        except Exception:
            size_bytes = None

    details = {
        "id": package_id,
        "publisher": publisher,
        "sizeBytes": size_bytes,
        "sizeText": _human_size(size_bytes) if size_bytes else None,
    }
    _details_cache[package_id] = details
    log(AGENT, f"details for {package_id}: publisher={publisher} size={details['sizeText']}")
    return details


def _failure_message(package_id: str, returncode: int, last_line: str) -> str:
    """winget's silent-mode output is usually a progress line, not the real
    error — the raw exit code is often the only diagnosable signal. Surface
    it as hex (matches what shows up if you search the code online) plus a
    generic hint, instead of an opaque progress fragment."""
    code_hex = f"0x{returncode & 0xFFFFFFFF:08X}"
    hint = ("may need admin rights, the app may be running, or another "
            "install may be in progress — try again, or run "
            f"'winget upgrade --id {package_id}' in a terminal for the full error")
    tail = last_line or "(no output captured)"
    return f"{tail} — exit {code_hex}; {hint}"


def apply_update(package_id: str, on_line=None) -> dict:
    if package_id not in _last_scanned_ids:
        log(AGENT, f"refused update for '{package_id}': not in last scanned set")
        return {"id": package_id, "ok": False, "message": "not scanned — rescan first"}

    if not PACKAGE_ID_RE.match(package_id):
        return {"id": package_id, "ok": False, "message": "invalid package id"}

    argv = [WINGET, "upgrade", "--id", package_id, "-e",
            "--accept-package-agreements", "--accept-source-agreements", "--silent"]
    log(AGENT, f"updating {package_id} via winget upgrade")

    if on_line is None:
        # blocking path (used by tests / non-streaming callers)
        try:
            result = _run(argv, UPDATE_TIMEOUT_SECS)
        except subprocess.TimeoutExpired:
            return {"id": package_id, "ok": False, "message": "timed out"}
        ok = result.returncode == 0
        tail = (result.stdout or result.stderr or "").strip().splitlines()[-1:] or [""]
        message = tail[0] if ok else _failure_message(package_id, result.returncode, tail[0])
        return {"id": package_id, "ok": ok, "message": message}

    # streaming path — feed each output line to on_line for live progress
    try:
        proc = subprocess.Popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, creationflags=_CREATE_NO_WINDOW,
        )
    except FileNotFoundError:
        return {"id": package_id, "ok": False, "message": "winget not found"}

    last = ""
    for raw in proc.stdout:
        line = raw.rstrip("\r\n")
        if line.strip():
            last = line.strip()
        try:
            on_line(line)
        except Exception:
            pass
    proc.wait()
    ok = proc.returncode == 0
    log(AGENT, f"{package_id} update {'succeeded' if ok else 'failed'} (exit {proc.returncode})")
    message = last if ok else _failure_message(package_id, proc.returncode, last)
    return {"id": package_id, "ok": ok, "message": message}
