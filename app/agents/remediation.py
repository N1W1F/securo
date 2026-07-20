"""Agent Gamma — Remediation / Report Writer.

Only entry point that writes to disk, and it can only ever write to the two
fixed paths enforced by security.write_report_atomic / write_findings_atomic
— there is no filename or directory parameter here for a caller to
manipulate. The markdown report is for humans; the JSON sidecar carries the
full structured findings (including fields with no safe markdown
representation, like CVSS attack complexity/vector) for the decision engine.
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from security import REPORT_PATH, FINDINGS_JSON_PATH, write_report_atomic, write_findings_atomic
from audit import log

AGENT = "Remediation"


def build_report(assets: list[str], findings: dict[str, list[dict]]) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# تقرير استخبارات التهديدات ومطابقة الأصول",
        f"تم توليده تلقائياً بواسطة نظام Multi-Agent — {timestamp}",
        "",
        f"عدد الأصول المفحوصة: {len(assets)}",
        f"عدد الأصول ذات ثغرات محتملة: {len(findings)}",
        "",
        "---",
        "",
    ]

    if not findings:
        lines.append("لم يُعثر على تطابقات CVE واضحة لأي من الأصول المفحوصة في هذا التشغيل.")
    else:
        for entry, matches in findings.items():
            lines.append(f"## {entry}")
            likely = [m for m in matches if not m.get("review")]
            review = [m for m in matches if m.get("review")]
            lines.append("### نتائج مرتبطة غالبًا")
            for m in likely:
                lines.append(f"- **{m['id']}** ({m['severity']}) — {m['summary']}")
            if review:
                lines.append("### نتائج تحتاج مراجعة")
                for m in review:
                    reason = "مرشح قديم أو غير مؤكد" if m.get("review_reason") == "old_candidate" else "بيانات شدة غير مكتملة"
                    lines.append(f"- **{m['id']}** ({m['severity']}) — {reason}: {m['summary']}")
            lines.append("")

    lines += [
        "---",
        "*هذا التقرير آلي، والنتائج تعتمد على مطابقة نصية بواسطة NVD keyword search — "
        "تحقق يدوياً قبل اتخاذ أي إجراء تشغيلي حاسم.*",
    ]
    return "\n".join(lines)


def build_findings_json(assets: list[str], findings: dict[str, list[dict]]) -> str:
    """Structured mirror of the report — one flat list of findings, each
    tagged with its owning asset entry (product + version, when known)."""
    flat = []
    for entry, matches in findings.items():
        for m in matches:
            flat.append({**m, "product": entry})
    return json.dumps({"assets": assets, "findings": flat}, ensure_ascii=False, indent=2)


def write(assets: list[str], findings: dict[str, list[dict]]) -> Path:
    content = build_report(assets, findings)
    write_report_atomic(REPORT_PATH, content)
    write_findings_atomic(FINDINGS_JSON_PATH, build_findings_json(assets, findings))
    log(AGENT, f"report written to {REPORT_PATH}")
    return REPORT_PATH
