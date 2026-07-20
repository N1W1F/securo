# Improvement plans — Threat Intel & Asset Monitor

Advisor output from `/improve`. Advisory only — no source was modified. Each
plan is self-contained for a fresh executor. No git repo present, so plans
are stamped against file state at authoring time, not a commit hash.

## Findings (vetted, leverage-ordered)

| # | Finding | Category | Impact | Effort | Plan |
|---|---------|----------|--------|--------|------|
| 1 | TOCTOU race on scan start → two concurrent orchestrator subprocesses corrupt `threat_intel_findings.json` | correctness/concurrency | Medium | S | [001](001-fix-scan-start-toctou.md) |
| 2 | `app/static/app.js` is a 1063-line monolith (tabs, poll, report, AI, settings, updates all inline) | tech debt | Medium | M | not planned (see note) |
| 3 | `/api/security/run` runs the full 124-test suite synchronously in the HTTP handler thread — blocks, no timeout | perf/DX | Low | S | not planned |
| 4 | `_rate_buckets` never evicts stale IP keys — unbounded dict growth (localhost = 1–2 keys in practice) | tech debt | Trivial | S | not planned |

## Execution order

1. **001** — the only correctness bug; do it first. Independent, no prerequisites.

## Not planned (deliberate)

- **#2** is real but M-effort with regression risk on a finished, well-tested
  project; splitting `app.js` into modules is a refactor to schedule when the
  UI next changes substantially, not a standalone task worth the risk now.
- **#3 / #4** are low/trivial impact on a localhost-only single-user app;
  noted for awareness, not worth a plan.

## Considered and rejected

- `_version_tuple` unequal-length comparison in `threat_hunter.py` — looked
  like a version-compare bug, but Python's element-wise tuple ordering is
  semantically correct here for "installed >= fixed-at" (`(4,) >= (2,1,0,1)`
  is True; `(2,1) >= (2,1,0,1)` is False). By-design, not a finding.

## Status

| Plan | Status |
|------|--------|
| 001  | DONE — atomic `_try_start_orchestrator()` claim; both trigger paths routed through it; concurrency test added (125/125) |
