# Securo — Architecture

Securo is a local-only desktop application that inventories the software
installed on a Windows machine, matches it against the official NVD
vulnerability database, and tells the user which findings actually warrant
action today.

Everything runs on the user's machine. The only outbound network calls are
to NVD and to CISA's KEV feed, both read-only. Nothing is uploaded.

---

## The eight agents

The system is deliberately split into small agents with one job each. Four
of them run inside the scan subprocess, four run inside the server process —
a split that matters, because it dictates how the UI observes them.

| # | Agent | Runs in | Responsibility |
|---|-------|---------|----------------|
| 1 | **Orchestrator** | scan subprocess | Drives the pipeline: calls the agents in order, writes the final report |
| 2 | **Asset Auditor** | scan subprocess | Inventories installed software via `winget list`, excludes games and driver packages, pins exact versions |
| 3 | **Package Manager** | server process | Asks the update sources whether a newer version exists; applies updates through winget |
| 4 | **Threat Hunter** | scan subprocess | Queries NVD per product and scores each CVE match |
| 5 | **KEV Checker** | server process | Flags findings that appear on CISA's Known Exploited Vulnerabilities list |
| 6 | **Decision** | server process | Ranks findings into urgent / routine / info and computes the health score |
| 7 | **Remediation** | scan subprocess | Turns raw findings into the human-readable report |
| 8 | **Analyst** | server process | Optional local LLM (Ollama) that explains findings and answers questions |

### Why the split is visible in the UI

The scan runs as a **separate process** (`main.py`, or the frozen exe
re-invoked with `--run-scan`). Its agents announce themselves by writing
`(Agent Name)` tags into stdout, which the server captures as the live log.
The other four never touch that log — they run in the server itself.

So the dashboard observes agent activity through two different channels:

- **subprocess agents** — parsed out of the scan log (`/api/status`)
- **in-process agents** — recorded by an activity tracker and served from
  `/api/agents`

Before this split was handled, the 3D scene only knew about the log, so it
rendered four agents and the app looked like a four-agent system.

---

## Data flow

```
                    ┌──────────────┐
   winget list ────▶│ Asset Auditor│───▶ installed assets (name + version)
                    └──────────────┘              │
                                                  ▼
                    ┌──────────────┐      ┌───────────────┐
   NVD API ────────▶│ Threat Hunter│◀─────│  Orchestrator │
                    └──────────────┘      └───────────────┘
                            │                     │
                            ▼                     ▼
                  threat_intel_findings.json   threat_intel_report.md
                            │
                            ▼
   ┌────────────────────────────────────────────────────┐
   │  server: _recompute_decision()                     │
   │                                                    │
   │   findings ──▶ has_update?  ◀── Package Manager    │
   │           ──▶ KEV Checker   ◀── CISA KEV feed      │
   │           ──▶ Decision      ──▶ tiers + health     │
   └────────────────────────────────────────────────────┘
                            │
                            ▼
                    dashboard (urgent banner, KPIs, 3D scene)
```

**Ordering is load-bearing.** `has_update` is resolved *before* the Decision
agent runs. It is a tri-state — `True` / `False` / `None` — and `None` means
"not checked yet", never "no update exists". The Decision agent fails toward
showing risk when it is `None`, so if the update scan had not run, every
CRITICAL finding was promoted to urgent with the reason "update availability
not checked yet" while the updates tab sat empty. The scan pipeline now runs
the update check before deciding tiers, and the server also primes it in the
background at startup.

---

## Update sources

`winget upgrade` only considers packages that carry a catalog `Source`. On a
real machine that was 67 of 183 installed programs; the remaining 116 were
invisible to update detection — which is what "some programs have an update
but never show up in the list" actually was.

Rather than special-case each catalog inside one growing function, every
source implements the same contract (`app/agents/sources/`):

```python
NAME         : str    # stable identifier
CAN_COMPARE  : bool   # does this source expose real version numbers?
lookup(name) -> Match | None
```

| Source | `CAN_COMPARE` | What it can answer |
|--------|---------------|--------------------|
| `winget_catalog` | ✅ | Both *what is this* and *is it out of date* |
| `msstore` | ❌ | Only *what is this* — the Store publishes **no** version numbers (`Version: Unknown` for every result) |

`CAN_COMPARE` is not a detail; it is the whole reason the layer exists. A
source that cannot version a package must never be allowed to imply one is
outdated.

### Guards against inventing updates

Reporting a phantom update is worse than missing a real one — it sends the
user to reinstall software that is already current. So:

- **`--exact` search only.** A fuzzy match for "Discord" also returns
  "Discord Canary" and "BetterDiscord"; offering one of those would replace
  the user's software with a different program.
- **Ambiguity means silence.** More than one catalog match → report nothing.
- **Strict numeric comparison.** Both versions must parse as plain dotted
  numbers, compared as zero-padded integer tuples. `Unknown`, `23H2` and
  anything else report nothing.
- **Already-installed guard.** If the matched catalog package is already
  installed under its own row, the untracked row is a different component
  sharing a name. This machine lists both `WinRAR` (the MSIX shell
  extension, 1.0.0.2) and `WinRAR 7.23 (64-bit)` (`RARLab.WinRAR`, current);
  without this guard the extension's version was compared against the app's
  package and invented an upgrade to a version already installed.

### Honest classification of what is left

Everything that still cannot be update-checked is bucketed and explained,
rather than reported as one opaque number:

| Bucket | Meaning | User action |
|--------|---------|-------------|
| `recovered` | A real update the standard winget check missed | Update it |
| `store` | Microsoft Store app | None — Windows updates it |
| `no_source` | In no catalog at all (drivers, OEM bundles) | Check inside the program |
| `no_version` | Publishes no comparable version | Can't be determined |
| `duplicate` | Already covered by another row, or current | None |
| `ambiguous` | Matches several catalog packages | Left unreported by design |

---

## Trust boundaries

| Boundary | Control |
|----------|---------|
| Browser → server | Binds `127.0.0.1` only. Host-header allowlist defeats DNS rebinding. Every state-changing POST needs a same-origin `Origin`/`Referer` **and** a per-process CSRF token. No CORS is granted, so a cross-site page cannot read the token. Load-bearing: `/api/upgrades/apply` installs software. |
| Server → winget | Fixed `argv` lists. Never `shell=True`, never a command built from request data. `apply_update` refuses any package ID that was not in the most recent scan, so a tampered API call cannot smuggle in an arbitrary package. |
| Server → NVD / KEV | Read-only HTTPS to fixed hosts. A failed KEV fetch yields `None` (unknown), never an empty set that would read as "nothing is exploited". |
| Report → browser | Strict CSP: `script-src 'self'`, `style-src 'self'`, no inline scripts or styles, no CDN. All third-party code (Three.js) is vendored locally. |
| Findings → disk | Written atomically inside a sandboxed base directory; paths are validated before any write. |

### A recurring failure mode this codebase guards against

Three separate bugs shared one shape: **missing information rendered as a
clean result.**

- KEV fetch failed → every finding shown as "not exploited"
- Update scan hadn't run → every finding shown as "no update exists"
- winget output unparseable → machine shown as "no software installed"

All three now have an explicit unknown state that the UI surfaces rather
than silently resolving in the reassuring direction.

---

## Layout

```
app/
  main.py                  Orchestrator — the scan subprocess entry point
  server.py                Local dashboard, agent activity tracker, API
  desktop_app.py           Native window wrapper (pywebview)
  security.py              Sandbox, atomic writes, input sanitising
  agents/
    asset_auditor.py       Inventory
    threat_hunter.py       NVD matching + result cache
    package_manager.py     Update detection + apply
    kev_checker.py         CISA KEV annotation
    decision.py            Tiering + health score
    remediation.py         Report generation
    analyst.py             Local LLM (optional)
    winget_table.py        Locale-independent winget table parser
    sources/               Update-source layer
      __init__.py          Contract + Match dataclass
      winget_catalog.py    Version-capable
      msstore.py           Identity only
  static/                  Dashboard UI (CSP-safe, no inline JS/CSS)
    pipeline3d.js          Live 3D agent scene
    scene3d.js             Ambient starfield + health orb
  tests/
    golden_dataset.py      Security test suite (141 tests)
```

---

## Locale independence

`winget` localises its table headers to the Windows display language.
Matching on the English header words returned zero rows on Arabic Windows —
and zero rows was then reported as "no software installed" and "no updates
available": a clean bill of health for a scan that examined nothing.

`winget_table.py` parses **structurally** instead: it finds the dashes rule,
takes the line above it as the header, derives column offsets from it, and
maps columns positionally. Column order is fixed regardless of language.
