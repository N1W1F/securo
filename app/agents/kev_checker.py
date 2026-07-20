"""Agent Zeta — KEV Checker.

Cross-references report CVEs against CISA's Known Exploited Vulnerabilities
(KEV) catalog — the US government's list of vulnerabilities with confirmed
real-world exploitation. This turns "theoretical CVE match" into "actively
being exploited right now," which is the signal that should actually drive
urgency.

Security posture matches threat_hunter.py: one hardcoded host, HTTPS only,
size-capped response, short timeout, and a failure here degrades to
"unknown" instead of ever crashing the pipeline.
"""
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from audit import log

AGENT = "KEV Checker"

KEV_HOST = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REQUEST_TIMEOUT_SECS = 10
MAX_RESPONSE_BYTES = 8_000_000
CACHE_TTL_SECS = 12 * 3600

_cache = {"ids": None, "fetched_at": 0.0}


def _fetch_kev_ids() -> set[str]:
    try:
        req = urllib.request.Request(KEV_HOST, headers={"User-Agent": "threat-intel-agent/1.0"})
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECS) as resp:
            if resp.status != 200:
                log(AGENT, f"non-200 status {resp.status} fetching KEV catalog")
                return set()
            raw = resp.read(MAX_RESPONSE_BYTES)
        data = json.loads(raw)
        vulns = data.get("vulnerabilities", []) if isinstance(data, dict) else []
        ids = {v.get("cveID") for v in vulns if isinstance(v, dict) and v.get("cveID")}
        log(AGENT, f"fetched {len(ids)} known-exploited CVE ids from CISA KEV")
        return ids
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as e:
        log(AGENT, f"KEV fetch failed, treating as unknown: {e}")
        return set()


def get_kev_ids() -> set[str]:
    now = time.time()
    if _cache["ids"] is not None and (now - _cache["fetched_at"]) < CACHE_TTL_SECS:
        return _cache["ids"]
    ids = _fetch_kev_ids()
    _cache["ids"] = ids
    _cache["fetched_at"] = now
    return ids


def annotate(findings: list[dict]) -> list[dict]:
    """Adds an 'exploited' bool to each finding dict (mutates + returns)."""
    kev_ids = get_kev_ids()
    for f in findings:
        f["exploited"] = f.get("id") in kev_ids if kev_ids else False
    return findings
