"""Audit logging with a tamper-evident hash chain.

Console output stays exactly as before (server.py's subprocess pipe parses
"[LEVEL] (Agent) message" lines to drive the live UI log — do not change
that format). The file write is separate: each line to audit.log is chained
to a SHA-256 of the previous line, so editing or deleting a past entry
breaks the chain from that point forward. verify_chain() lets the Golden
Dataset (or a human) detect tampering; nothing auto-repairs a broken chain.
"""
import hashlib
import logging
import threading
from datetime import datetime, timezone

from security import AUDIT_LOG_PATH

logger = logging.getLogger("threat_intel_agent")
logger.setLevel(logging.INFO)

_console = logging.StreamHandler()
_console.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
logger.addHandler(_console)

_chain_lock = threading.Lock()
_GENESIS = "0" * 64
_prev_hash = _GENESIS


def _load_prev_hash() -> None:
    global _prev_hash
    if not AUDIT_LOG_PATH.is_file():
        return
    try:
        lines = AUDIT_LOG_PATH.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return
    for line in reversed(lines):
        if " chain=" in line:
            _prev_hash = line.rsplit(" chain=", 1)[1].strip()
            return


_load_prev_hash()


def _append_chained(body: str) -> None:
    global _prev_hash
    with _chain_lock:
        digest = hashlib.sha256((_prev_hash + body).encode("utf-8")).hexdigest()
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"{body} chain={digest}\n")
        _prev_hash = digest


def log(agent: str, message: str) -> None:
    logger.info("(%s) %s", agent, message)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    _append_chained(f"{ts} [INFO] ({agent}) {message}")


def verify_chain(path=None) -> dict:
    """Walks a chained log file recomputing the hash chain (defaults to the
    real audit.log; tests can point this at an isolated file so a tamper
    test doesn't permanently poison the shared log). Returns
    {"ok": bool, "lines": int, "broken_at": int | None}."""
    target = path or AUDIT_LOG_PATH
    if not target.is_file():
        return {"ok": True, "lines": 0, "broken_at": None}
    prev = _GENESIS
    lines = target.read_text(encoding="utf-8", errors="ignore").splitlines()
    for i, line in enumerate(lines, start=1):
        if " chain=" not in line:
            continue
        body, digest = line.rsplit(" chain=", 1)
        digest = digest.strip()
        expected = hashlib.sha256((prev + body).encode("utf-8")).hexdigest()
        if expected != digest:
            return {"ok": False, "lines": len(lines), "broken_at": i}
        prev = digest
    return {"ok": True, "lines": len(lines), "broken_at": None}
