"""Agent Eta — Decision Agent.

The one agent in this system that makes a judgment call instead of just
reporting data: given findings (optionally KEV-annotated), it computes an
overall health score and classifies each finding into an urgency tier.

Hard boundary (by design, not just convention): this module never imports
package_manager, subprocess, or anything with side effects. It can only
produce a verdict — a tier label and a reason string. Turning that verdict
into an actual update install always goes through the existing
CSRF-protected /api/upgrades/apply button click; nothing here can reach it.
"""

TIER_URGENT = "urgent"
TIER_ROUTINE = "routine"
TIER_INFO = "info"

_SEVERITY_WEIGHT = {  # used only for sort ordering, not for the score
    "CRITICAL": 15,
    "HIGH": 8,
    "MEDIUM": 3,
    "LOW": 1,
    "UNKNOWN": 0,
}

# Health score is driven by ACTIONABLE risk (the decision tier), NOT by the
# raw count of NVD keyword matches. Raw matching over-reports massively
# (hundreds of near-constant noise findings on any real machine), so scoring
# by raw severity pinned the number near 0 forever and it never moved when
# the user actually patched something. Scoring by tier means: only genuinely
# urgent items (has update, realistically exploitable, or KEV-confirmed) hurt
# the score a lot; routine items barely; already-fixed / no-update / info
# items not at all. Now the number reflects real posture and rises as urgent
# items get resolved.
_TIER_PENALTY = {TIER_URGENT: 12, TIER_ROUTINE: 2, TIER_INFO: 0}
_TIER_PENALTY_CAP = {TIER_URGENT: 60, TIER_ROUTINE: 24, TIER_INFO: 0}


_HARD_TO_EXPLOIT_VECTORS = {"LOCAL", "PHYSICAL", "ADJACENT_NETWORK", "ADJACENT"}


def _hard_to_exploit(attack_complexity: str, attack_vector: str) -> bool:
    """HIGH attack complexity or anything short of network-reachable means
    real-world exploitation needs conditions an attacker doesn't fully
    control — not zero risk, but not pager-worthy either."""
    return (attack_complexity or "").upper() == "HIGH" or (attack_vector or "").upper() in _HARD_TO_EXPLOIT_VECTORS


def _tier_for(severity: str, exploited: bool, has_update: bool,
              attack_complexity: str, attack_vector: str, version_fixed: bool = False) -> tuple[str, str]:
    severity = (severity or "UNKNOWN").upper()

    # The CVE's own description says it was fixed at a version the install
    # has already reached or passed — this overrides even a KEV match,
    # since exploiting a years-old, already-patched build proves nothing
    # about the current one. Without this a fixed CVE can get stuck
    # permanently "urgent" with literally no update to apply.
    if version_fixed:
        return TIER_INFO, "النسخة المثبتة أحدث من الإصدار المذكور بالثغرة — غالباً مُصلحة بالفعل، تحقق يدوياً إذا لزم"

    # KEV-confirmed real-world exploitation overrides everything else —
    # actual attackers already found a way in, regardless of how "hard"
    # the CVSS vector says it should be.
    if exploited:
        urgent_reason = "ثغرة مستغلة فعلياً حسب قائمة CISA KEV"
        if severity in ("CRITICAL", "HIGH"):
            return TIER_URGENT, urgent_reason
        return TIER_ROUTINE, urgent_reason

    if severity == "CRITICAL":
        if not has_update:
            return TIER_ROUTINE, "ثغرة حرجة لكن لا يوجد تحديث متاح حالياً لإصلاحها"
        if _hard_to_exploit(attack_complexity, attack_vector):
            return TIER_ROUTINE, "ثغرة حرجة لكن استغلالها يتطلب شروطاً صعبة (وصول محلي أو تعقيد عالٍ)"
        return TIER_URGENT, "ثغرة حرجة ولها تحديث متاح"

    if severity == "HIGH":
        return TIER_ROUTINE, "ثغرة تستحق المتابعة القريبة"
    if severity == "MEDIUM":
        return TIER_ROUTINE, "ثغرة متوسطة، يُفضّل الجدولة"
    return TIER_INFO, "خطورة منخفضة أو غير مؤكدة"


def decide(findings: list[dict]) -> dict:
    """findings: [{id, product, severity, desc, exploited(optional bool),
    has_update(optional bool), attack_complexity(optional str),
    attack_vector(optional str)}]

    Returns {"health_score": int, "items": [{..., tier, reason}]}.
    Pure function — no I/O, no side effects.
    """
    items = []
    tier_penalty = {}
    for f in findings:
        severity = (f.get("severity") or "UNKNOWN").upper()
        exploited = bool(f.get("exploited"))
        has_update = bool(f.get("has_update"))
        attack_complexity = f.get("attack_complexity") or "UNKNOWN"
        attack_vector = f.get("attack_vector") or "UNKNOWN"
        version_fixed = f.get("review_reason") == "version_fixed"
        tier, reason = _tier_for(severity, exploited, has_update, attack_complexity, attack_vector, version_fixed)
        # score by the actionable tier, not raw severity — version_fixed items
        # are TIER_INFO already, so they contribute 0 automatically.
        tier_penalty[tier] = tier_penalty.get(tier, 0) + _TIER_PENALTY.get(tier, 0)
        items.append({
            "id": f.get("id"),
            "product": f.get("product"),
            "severity": severity,
            "exploited": exploited,
            "has_update": has_update,
            "tier": tier,
            "reason": reason,
        })

    penalty = sum(min(v, _TIER_PENALTY_CAP.get(tier, v)) for tier, v in tier_penalty.items())
    health_score = max(0, min(100, 100 - penalty))
    items.sort(key=lambda i: (i["tier"] != TIER_URGENT, -_SEVERITY_WEIGHT.get(i["severity"], 0)))
    return {"health_score": health_score, "items": items}
