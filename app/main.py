"""Orchestrator — coordinates Threat Hunter, Asset Auditor, and Remediation
agents sequentially. No agent has more access than it needs:
  - asset_auditor: read-only, sandboxed to inventory.txt
  - threat_hunter: network-only, fixed host, no disk access
  - remediation:   write-only, fixed output path

Run with: python main.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from agents import asset_auditor, threat_hunter, remediation
from audit import log
from security import SecurityError

AGENT = "Orchestrator"


def main() -> int:
    log(AGENT, "run started")

    try:
        assets = asset_auditor.load_assets()
    except SecurityError as e:
        log(AGENT, f"aborting — asset auditor security violation: {e}")
        return 1

    if not assets:
        log(AGENT, "no valid assets found, nothing to hunt")
        return 0

    findings = threat_hunter.hunt(assets)

    try:
        report_path = remediation.write(assets, findings)
    except SecurityError as e:
        log(AGENT, f"aborting — remediation security violation: {e}")
        return 1

    log(AGENT, f"run complete — report at {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
