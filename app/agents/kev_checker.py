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
        # None, not set() — see get_kev_ids(). Returning an empty set here
        # would read downstream as "CISA confirms nothing is exploited".
        log(AGENT, f"KEV fetch failed, exploitation status unknown: {e}")
        return None


def get_kev_ids() -> set[str]:
    """Returns the KEV id set, or None when the catalog could not be fetched.

    None and empty-set mean very different things and must not be conflated:
    an empty set is "CISA says nothing is exploited", None is "we don't
    know". A failed fetch used to be cached as an empty set for the full
    12h TTL, which made every finding non-exploited — so one offline moment
    during a scan silently downgraded genuinely exploited CVEs out of the
    urgent tier and suppressed the notification for half a day.
    """
    now = time.time()
    if _cache["ids"] is not None and (now - _cache["fetched_at"]) < CACHE_TTL_SECS:
        return _cache["ids"]
    ids = _fetch_kev_ids()
    if ids is None:
        # Do NOT cache a failure. Keep any previous good data if we still
        # have it; otherwise report "unknown" and retry on the next scan.
        return _cache["ids"]
    _cache["ids"] = ids
    _cache["fetched_at"] = now
    return ids


def annotate(findings: list[dict]) -> list[dict]:
    """Adds an 'exploited' bool to each finding dict (mutates + returns).

    Also sets 'kev_unknown' when the catalog was unreachable, so the UI can
    say "couldn't verify" instead of implying a clean result.
    """
    kev_ids = get_kev_ids()
    unknown = kev_ids is None
    for f in findings:
        f["exploited"] = (f.get("id") in kev_ids) if kev_ids else False
        f["kev_unknown"] = unknown
    return findings
