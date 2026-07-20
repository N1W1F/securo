"""Sandbox and validation primitives shared by every agent.

All filesystem and input boundaries live here so agents never touch
os.path / open() directly — that keeps the trust boundary in one file.
"""
from __future__ import annotations

import re
import os
import sys
from pathlib import Path

FROZEN = bool(getattr(sys, "frozen", False))


def _resolve_dirs(frozen: bool, executable: str, meipass: str | None, this_file: str) -> tuple[Path, Path]:
    """Pure BASE_DIR/RUNTIME_DIR computation, factored out so tests can
    exercise the frozen-vs-dev branching with fake inputs directly — without
    ever mutating real sys.frozen/sys.executable or reloading this module.
    A module reload rebinds every class defined here (SecurityError included)
    to a NEW object, which desyncs from the SecurityError every other
    already-imported module is holding via `from security import SecurityError`,
    silently breaking their `except SecurityError:` clauses for the rest of
    the process's life. Never reload this module."""
    if frozen:
        # PyInstaller: __file__ resolves inside the ephemeral per-run extraction
        # dir (sys._MEIPASS), which is wiped after the process exits — writing
        # user data there would silently lose history/config/secrets on every
        # restart. Persistent data instead lives next to the built .exe;
        # RUNTIME_DIR (bundled read-only assets like static/) stays in MEIPASS.
        base_dir = Path(executable).resolve().parent
        runtime_dir = Path(meipass) if meipass else base_dir
    else:
        runtime_dir = Path(this_file).resolve().parent   # .../app
        base_dir = runtime_dir.parent                     # threat-intel-agent/
    return base_dir, runtime_dir


BASE_DIR, RUNTIME_DIR = _resolve_dirs(FROZEN, sys.executable, getattr(sys, "_MEIPASS", None), __file__)
INVENTORY_PATH = (BASE_DIR / "inventory.txt").resolve()
REPORT_PATH = (BASE_DIR / "threat_intel_report.md").resolve()
FINDINGS_JSON_PATH = (BASE_DIR / "threat_intel_findings.json").resolve()
AUDIT_LOG_PATH = (BASE_DIR / "audit.log").resolve()

MAX_INVENTORY_BYTES = 1_000_000  # 1MB — reject anything larger as anomalous
MAX_LINE_LEN = 200
SOFTWARE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._+\-/]{0,80}$")


class SecurityError(Exception):
    pass


def assert_within_sandbox(path: Path) -> Path:
    """Resolve `path` and reject anything that escapes BASE_DIR (path traversal,
    symlink escape, absolute-path injection)."""
    resolved = path.resolve()
    try:
        resolved.relative_to(BASE_DIR)
    except ValueError:
        raise SecurityError(f"Path escapes sandbox: {resolved}")
    return resolved


def read_only_open(path: Path):
    path = assert_within_sandbox(path)
    if not path.is_file():
        raise SecurityError(f"Not a regular file: {path}")
    if path.stat().st_size > MAX_INVENTORY_BYTES:
        raise SecurityError(f"File exceeds size cap ({MAX_INVENTORY_BYTES} bytes): {path}")
    return open(path, "r", encoding="utf-8", errors="strict")


def write_report_atomic(path: Path, content: str) -> None:
    """Write only ever targets REPORT_PATH — enforced here, not by caller discipline."""
    path = assert_within_sandbox(path)
    if path != REPORT_PATH:
        raise SecurityError(f"Refusing to write outside the fixed report path: {path}")
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(content)
    os.replace(tmp_path, path)  # atomic on Windows (same volume)


def write_findings_atomic(path: Path, content: str) -> None:
    """Write only ever targets FINDINGS_JSON_PATH — the structured sidecar
    the decision engine reads instead of re-parsing the human-readable
    markdown report (that markdown-parsing path has broken twice already
    on embedded newlines and empty descriptions; structured fields like
    CVSS attack complexity/vector have no safe place in the bullet-line
    format at all)."""
    path = assert_within_sandbox(path)
    if path != FINDINGS_JSON_PATH:
        raise SecurityError(f"Refusing to write outside the fixed findings path: {path}")
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(content)
    os.replace(tmp_path, path)  # atomic on Windows (same volume)


def sanitize_software_name(raw: str) -> str | None:
    """Strict allowlist for anything that will be interpolated into a URL or
    file. Returns None (drop the entry) instead of raising, so one bad line
    in inventory.txt can't take down the whole run."""
    candidate = raw.strip()
    if not candidate or len(candidate) > MAX_LINE_LEN:
        return None
    if candidate.startswith("#"):
        return None
    if not SOFTWARE_NAME_RE.match(candidate):
        return None
    return candidate
