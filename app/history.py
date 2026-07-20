"""Scan history + diff (features 9 and 11).

One JSON line appended per completed scan. Used to draw the risk-over-time
chart and to diff the latest scan against the previous one (new vs resolved
findings). Pure data — no LLM, no network.
"""
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from security import BASE_DIR, REPORT_PATH

HISTORY_PATH = BASE_DIR / "history.jsonl"
MAX_RECORDS = 200

_H2 = re.compile(r"^## (.+)$")
_FIND = re.compile(r"^- \*\*(.+?)\*\* \((.+?)\) — ")
_FIND_FULL = re.compile(r"^- \*\*(.+?)\*\* \((.+?)\) — (.+)$")


def parse_findings(text: str) -> list[dict]:
    """Detailed findings [{product, id, severity, desc}] for LLM re-assessment."""
    out, product = [], None
    for raw in text.splitlines():
        line = raw.strip()
        m = _H2.match(line)
        if m:
            product = m.group(1)
            continue
        mf = _FIND_FULL.match(line)
        if mf and product:
            out.append({"product": product, "id": mf.group(1),
                        "severity": mf.group(2).upper(), "desc": mf.group(3)})
    return out


def parse_report(text: str) -> dict:
    """Return {assets, ids:[product::cve], sev:{SEVERITY:count}, total}."""
    sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    ids, product, assets = [], None, 0
    for raw in text.splitlines():
        line = raw.strip()
        m = _H2.match(line)
        if m:
            product = m.group(1)
            assets += 1
            continue
        mf = _FIND.match(line)
        if mf and product:
            cve, s = mf.group(1), mf.group(2).upper()
            sev[s] = sev.get(s, 0) + 1
            ids.append(f"{product}::{cve}")
    return {"assets": assets, "ids": ids, "sev": sev, "total": len(ids)}


def record_current_report() -> dict | None:
    if not REPORT_PATH.is_file():
        return None
    parsed = parse_report(REPORT_PATH.read_text(encoding="utf-8"))
    record = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "assets": parsed["assets"],
        "total": parsed["total"],
        "sev": parsed["sev"],
        "ids": parsed["ids"],
    }
    with open(HISTORY_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    _trim()
    return record


def _trim():
    lines = read_raw()
    if len(lines) > MAX_RECORDS:
        HISTORY_PATH.write_text("\n".join(json.dumps(r, ensure_ascii=False)
                                          for r in lines[-MAX_RECORDS:]) + "\n",
                                encoding="utf-8")


def read_raw() -> list[dict]:
    if not HISTORY_PATH.is_file():
        return []
    out = []
    for line in HISTORY_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def series() -> list[dict]:
    """Chart-friendly points (no heavy id lists)."""
    return [{"ts": r["ts"], "total": r.get("total", 0), "sev": r.get("sev", {})}
            for r in read_raw()]


def diff_last_two() -> dict:
    runs = read_raw()
    if len(runs) < 2:
        return {"has_previous": False, "new": [], "resolved": []}
    prev, cur = set(runs[-2].get("ids", [])), set(runs[-1].get("ids", []))
    return {
        "has_previous": True,
        "new": sorted(cur - prev),
        "resolved": sorted(prev - cur),
    }
