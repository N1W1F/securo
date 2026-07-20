"""Agent Alpha — Threat Hunter.

Queries the official NVD CVE API (services.nvd.nist.gov) only. The host is
hardcoded (no caller-controlled URL construction), all query params go
through urlencode, and every network call is bounded by timeout + retry cap
to avoid the agent hanging or being used as a proxy for arbitrary requests.

Speed: NVD's public rate limit (no API key) is 5 requests/30s, forcing a
6-second sleep between every query — a 126-app scan spends 12+ minutes just
sleeping. Two independent fixes, both optional and safe to skip:
  1. Result cache keyed by "product version" with a 24h TTL — a re-scan only
     queries NVD for software that's new or changed since last time.
  2. Optional user-supplied NVD API key (free, self-serve, email-only sign-up
     at nvd.nist.gov/developers/request-an-api-key) raises the limit to
     50 requests/30s; when present we shrink the sleep accordingly.
"""
import json
import re
import sys
import time
from datetime import datetime, timezone
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from audit import log
from security import BASE_DIR
import appconfig

AGENT = "Threat Hunter"

NVD_HOST = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT_SECS = 10
MAX_RETRIES = 2
MIN_SECONDS_BETWEEN_CALLS_NO_KEY = 6     # public NVD rate limit: 5 req / 30s
MIN_SECONDS_BETWEEN_CALLS_WITH_KEY = 0.65  # keyed NVD rate limit: 50 req / 30s
MAX_RESULTS_PER_QUERY = 5

CACHE_PATH = BASE_DIR / "nvd_cache.json"
CACHE_TTL_SECS = 24 * 3600

_VERSION_SUFFIX_RE = re.compile(r"^(?P<product>.+?)\s+(?P<version>[\d][\w.\-]*)$")


def _split_product_version(entry: str) -> tuple[str, str | None]:
    m = _VERSION_SUFFIX_RE.match(entry)
    if m:
        return m.group("product").strip(), m.group("version").strip()
    return entry.strip(), None


_FIXED_BEFORE_RE = re.compile(r"\b(?:before|prior to)\s+(?:version\s+)?(\d+(?:\.\d+){1,4})", re.I)


def _version_tuple(v: str) -> tuple[int, ...]:
    parts = []
    for p in v.split("."):
        digits = "".join(c for c in p if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def _already_fixed(summary: str, installed_version: str | None) -> bool:
    """NVD keyword search matches by product name only, not version — this
    is the one case where the description text itself is unambiguous: "X
    before 2.1.0.1" means the bug was fixed AT that version, so an install
    already at or past it plainly isn't affected. Without this, a years-old
    already-patched CVE stays permanently "urgent" (worse, KEV-exploited
    ones can never be downgraded by any other rule) with literally no
    update to apply, since the fix already shipped long ago."""
    if not installed_version:
        return False
    m = _FIXED_BEFORE_RE.search(summary)
    if not m:
        return False
    try:
        return _version_tuple(installed_version) >= _version_tuple(m.group(1))
    except (ValueError, TypeError):
        return False


def _min_seconds_between_calls() -> float:
    key = (appconfig.load_secrets() or {}).get("nvd_api_key")
    return MIN_SECONDS_BETWEEN_CALLS_WITH_KEY if key else MIN_SECONDS_BETWEEN_CALLS_NO_KEY


def _build_url(product: str) -> str:
    """Build the NVD query URL. Host is the fixed NVD_HOST constant and the
    product name only ever enters as a urlencoded query value — it can never
    change the host or inject extra parameters (SSRF / query-injection guard)."""
    query = urllib.parse.urlencode({
        "keywordSearch": product,
        "resultsPerPage": str(MAX_RESULTS_PER_QUERY),
    })
    return f"{NVD_HOST}?{query}"


def _load_cache() -> dict:
    if not CACHE_PATH.is_file():
        return {}
    try:
        return json.loads(CACHE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _save_cache(cache: dict) -> None:
    try:
        CACHE_PATH.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        pass


def _cache_key(entry: str) -> str:
    return entry.strip().casefold()


def _fetch(product: str) -> dict | None:
    url = _build_url(product)
    headers = {"User-Agent": "threat-intel-agent/1.0"}
    api_key = (appconfig.load_secrets() or {}).get("nvd_api_key")
    if api_key:
        headers["apiKey"] = api_key

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECS) as resp:
                if resp.status != 200:
                    log(AGENT, f"non-200 status {resp.status} for '{product}', skipping")
                    return None
                raw = resp.read(5_000_000)  # cap response size defensively
                data = json.loads(raw)
                if not isinstance(data, dict) or "vulnerabilities" not in data:
                    log(AGENT, f"unexpected NVD response shape for '{product}', ignoring")
                    return None
                return data
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError) as e:
            log(AGENT, f"attempt {attempt}/{MAX_RETRIES} failed for '{product}': {e}")
            time.sleep(2 * attempt)
    return None


def _parse_matches(data: dict, installed_version: str | None = None) -> list[dict]:
    matches, seen_ids = [], set()
    for item in data.get("vulnerabilities", [])[:MAX_RESULTS_PER_QUERY]:
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id or cve_id in seen_ids:
            continue
        seen_ids.add(cve_id)
        descriptions = cve.get("descriptions", [])
        summary = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "")
        # some NVD descriptions embed literal newlines — collapsing to single
        # spaces keeps each finding on exactly one markdown bullet line
        # (a raw newline here orphans the rest of the text onto its own
        # un-bulleted line, which breaks both the report's markdown
        # structure and the UI's line-by-line report parser).
        summary = " ".join(summary.split())
        metrics = cve.get("metrics", {})
        severity = "UNKNOWN"
        attack_complexity, attack_vector = "UNKNOWN", "UNKNOWN"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                cvss_data = metrics[key][0].get("cvssData", {})
                severity = cvss_data.get("baseSeverity", "UNKNOWN")
                if key == "cvssMetricV2":
                    # v2 field names differ from v3 but mean the same thing
                    attack_complexity = (cvss_data.get("accessComplexity") or "UNKNOWN").upper()
                    attack_vector = (cvss_data.get("accessVector") or "UNKNOWN").upper()
                else:
                    attack_complexity = (cvss_data.get("attackComplexity") or "UNKNOWN").upper()
                    attack_vector = (cvss_data.get("attackVector") or "UNKNOWN").upper()
                break
        published = cve.get("published", "")
        old = False
        try:
            # NVD's real "published" field has no trailing Z (e.g.
            # "2019-05-07T20:29:00.363") -> fromisoformat returns a naive
            # datetime. Comparing naive < aware raises TypeError, which the
            # old code silently swallowed — old-CVE detection never actually
            # fired in production. Force both sides to be timezone-aware.
            pub_dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
            if pub_dt.tzinfo is None:
                pub_dt = pub_dt.replace(tzinfo=timezone.utc)
            ten_years_ago = datetime.now(timezone.utc).replace(year=datetime.now(timezone.utc).year - 10)
            old = pub_dt < ten_years_ago
        except (ValueError, TypeError):
            pass
        if _already_fixed(summary, installed_version):
            review_reason = "version_fixed"
        else:
            review_reason = "missing_severity" if severity == "UNKNOWN" else ("old_candidate" if old else "")
        matches.append({"id": cve_id, "summary": summary[:300], "severity": severity,
                        "review": bool(review_reason), "review_reason": review_reason, "published": published,
                        "attack_complexity": attack_complexity, "attack_vector": attack_vector})
    return matches


def hunt(assets: list[str]) -> dict[str, list[dict]]:
    """Returns {asset_entry: [ {id, summary, severity, review, review_reason,
    published} ]} for each asset with at least one plausible CVE match.
    Cache-first: unchanged software (same cache key, still fresh) skips both
    the network call and the mandatory rate-limit sleep entirely."""
    findings: dict[str, list[dict]] = {}
    cache = _load_cache()
    now = time.time()
    min_gap = _min_seconds_between_calls()
    made_network_call = False

    for entry in assets:
        product, version = _split_product_version(entry)
        key = _cache_key(entry)
        cached = cache.get(key)

        if cached and (now - cached.get("ts", 0)) < CACHE_TTL_SECS:
            if cached.get("matches"):
                findings[entry] = cached["matches"]
            log(AGENT, f"cache hit for '{product}' (skipped network + rate-limit wait)")
            continue

        if made_network_call:
            time.sleep(min_gap)
        made_network_call = True

        log(AGENT, f"querying NVD for product='{product}'")
        data = _fetch(product)
        matches = _parse_matches(data, version) if data else []
        cache[key] = {"ts": now, "matches": matches}

        if matches:
            findings[entry] = matches
            log(AGENT, f"found {len(matches)} candidate CVE(s) for '{entry}'")

    _save_cache(cache)
    return findings
