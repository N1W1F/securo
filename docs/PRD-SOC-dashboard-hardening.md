# Product Requirements Document: SOC Dashboard Hardening

**Product:** Threat Intel & Asset Monitor  
**Status:** Approved direction pending PRD review  
**Date:** 2026-07-21

## 1. Purpose

Make the local Threat Intel & Asset Monitor dependable as a security-operations dashboard. The application must accurately communicate its data state, never show fabricated, sample, stale, or inferred inventory as current data, and provide a focused dark SOC command-center experience for real scans, software updates, findings, history, and configuration.

## 2. Problem statement

The application combines a Python localhost service with a browser dashboard. Several views present operational data, but the system must be reviewed end-to-end for defects that can produce incorrect status, races, unhelpful errors, broken interactions, insecure handling, stale results, or misleading visual states. In particular, a local `inventory.txt` fallback must not be used to represent an installed-software inventory when `winget` cannot provide one.

## 3. Goals

1. Audit all production frontend and backend code for correctness, reliability, safety, maintainability, accessibility, and UX defects.
2. Fix defects that can be verified from source inspection or tests without expanding unrelated scope.
3. Replace the existing generic dashboard feel with a coherent dark SOC command-center visual system.
4. Make every operational panel dynamic: it must render only state returned by a real local backend operation or be explicitly empty, loading, unavailable, or failed.
5. Prevent scans from using the text-file fallback as inventory. When live inventory cannot be collected, scanning must stop with a precise actionable state.
6. Verify the application with automated checks and targeted API/UI smoke checks where the local environment permits.

## 4. Non-goals

- Do not invent threat findings, package updates, history points, KPIs, progress percentages, device inventory, or AI answers for visual effect.
- Do not add cloud telemetry, remote storage, authentication services, or third-party analytics.
- Do not change the core product into a multi-user SOC platform.
- Do not automatically install updates without the existing user-triggered workflow.
- Do not treat test fixtures, golden-dataset cases, cached NVD responses, examples, or documentation samples as live UI data.

## 5. Users and primary jobs

**Local security-conscious Windows user**

- Discover whether a trustworthy local asset inventory is available.
- Launch and follow a vulnerability scan.
- Understand severity and prioritized next actions.
- Inspect available Windows package updates and choose whether to apply them.
- Review scan history and changes between scans.
- Configure local schedule, startup, NVD key, and optional local AI support.

## 6. Functional requirements

### 6.1 Inventory integrity

- `winget` is the only source for live installed-software inventory.
- The app must not read or use `inventory.txt` as fallback inventory during normal scans.
- If `winget` is missing, errors, times out, or produces no parseable inventory, the inventory API must return a machine-readable unavailable/empty state with a human-readable reason.
- The scan workflow must not query NVD or generate a scan report when no verified live inventory is available.
- The UI must show a dedicated unavailable state and recovery guidance; it must not show old, example, or placeholder assets as current.
- If a prior report/history exists, it must be identified as prior scan data and include its timestamp/source status. It must never be visually presented as a current scan.

### 6.2 Data provenance and state truthfulness

- Each API-fed view must distinguish these states: initial, loading/running, available, empty, unavailable, failed, and stale/prior where applicable.
- Dashboard KPIs are populated only from a verified decision/report response associated with the available scan state.
- Update lists are populated only after a real `winget upgrade` scan completes.
- Progress indicators may display backend-reported progress. Any estimate must be explicitly marked as estimated and must never be used as a result value.
- API errors must be surfaced in context with a retry path when safe.
- Any cache must be invalidated or visibly marked stale when its underlying inventory, scan, or update state changes.

### 6.3 SOC command-center interface

- Use a dark, high-legibility visual system with restrained accent colors reserved for actionable status.
- Provide an operations header that shows current system/data state and primary scan action.
- Present a scan pipeline with live stage states: idle, running, complete, failed, blocked, and unavailable.
- Make the overview a clear risk-and-action surface: health posture, finding counts, critical/high count, verified asset count, urgent actions, and report summary.
- Preserve the existing feature areas (updates, security validation, history, AI/settings) while improving hierarchy, responsive behavior, keyboard navigation, Arabic RTL, and English LTR presentation.
- Use intentional empty states rather than decorative values. Empty states must explain why no result is displayed and how to produce a real one.

### 6.4 Backend robustness

- Review all routes, state transitions, subprocess calls, threads, scheduling, configuration, report/history handling, and agent boundaries.
- Ensure state-changing endpoints validate input types, sizes, identifiers, and allowed transitions.
- Eliminate observable start/race windows for scan and update actions.
- Ensure subprocess failures/timeouts produce controlled API/UI errors.
- Preserve localhost binding, CSRF controls, host checks, CSP, and other existing security constraints while correcting weaknesses found in review.
- Avoid exposing secrets in responses, reports, logs, or UI.

## 7. UX behavior matrix

| Condition | Backend behavior | UI behavior |
| --- | --- | --- |
| Before any verified scan | Return explicit initial/no-current-result state | Show no-data overview; no synthetic KPIs or findings |
| `winget` unavailable/fails | Return inventory unavailable with reason; block scan | Show prominent inventory-unavailable panel and recovery steps |
| `winget` returns no parseable installed packages | Return empty inventory; block scan | Show explicit zero/empty inventory, not a scan result |
| Scan running | Stream or poll real state/logs | Show running stages and real log output |
| Scan succeeds | Persist/report real result then refresh decision state | Populate findings/KPIs/report from returned current scan data |
| Scan fails | Preserve failure reason and completed state | Show failed stage/status and retain only clearly labeled previous results |
| Update scan not run | Empty update state | Prompt to run a real update scan |
| Update scan succeeds with no updates | Return empty real result | State that no updates were reported by winget |
| API/network error | Return non-success status + safe reason | Contextual failure state and retry option |

## 8. Detailed UI and UX design

### 8.1 Design concept: "SOC Prism"

The UI is a dark, layered operations console, not a decorative game scene. It uses depth to separate live operational surfaces from supporting controls:

- **Base plane:** near-black blue background with a subtle grid/noise texture generated in CSS. No image asset or fake telemetry pattern.
- **Command deck:** central raised glass panel holding current scan state, metrics, and urgent actions.
- **Data modules:** smaller stacked panels with a consistent 3D edge, shadow, and thin status glow.
- **Focus layer:** a selected finding, report item, or update expands forward into a modal/side inspector; background remains visible but inert.
- **No decorative live feed:** animated elements only communicate actual loading, polling, focus, hover, or status transitions.

Use CSS transforms, gradients, shadows, `backdrop-filter` with a solid-color fallback, and small SVG/CSS primitives. Do not add a heavy 3D engine, canvas scene, external CDN, or telemetry library. Native CSS keeps the local application lightweight, offline-friendly, CSP-compatible, accessible, and compatible with RTL.

### 8.2 Page structure

**A. Persistent left/right rail**

- Brand at top, product name and small `LOCALHOST / VERIFIED` badge.
- Navigation is icon + text; active item becomes a raised illuminated rail tile, not only a color change.
- Bottom rail contains language switch and connection/data-state icon.
- RTL moves rail to right and reverses keyboard focus order only where visual ordering requires it; semantic DOM order remains logical.
- On narrow screens, rail becomes a bottom navigation bar with four labeled actions; settings moves into overflow panel.

**B. Operations top bar**

- Left: page title and short source line: `Inventory: live via winget`, `Inventory unavailable`, or `Last verified scan: <timestamp>`.
- Right: primary `Run verified scan` action, compact scan state chip, optional live elapsed time only while server reports a run.
- Run button is disabled with reason when inventory is unavailable, update operation is active, or scan already runs. Tooltip/inline text names exact reason.

**C. Command deck overview**

- First row is four perspective cards: security posture, findings, critical/high findings, verified assets.
- No-result values display `—` plus state label such as `No verified scan`; they never display zero unless server actually reports zero.
- Cards tilt 1.5-3 degrees toward pointer only on devices with fine pointer and `prefers-reduced-motion: no-preference`. Keyboard focus gets same raised state without pointer tilt.
- Selecting a card opens its real-data drilldown below; it never invents breakdown values.
- Health ring draws from backend health score. With no score it renders an empty neutral ring, not a 0% score.

**D. Scan pipeline**

- Horizontal chain: Inventory, Match, Analyze, Report. Each node is a raised beacon with status icon, label, timestamp/elapsed info when real, and concise state text.
- States: neutral gray (idle), cyan pulse (running), green stable (complete), amber (blocked/unavailable), red (failed).
- Connecting line animates only while that stage is reported active. Completed line stays static.
- Clicking a node opens log/context drawer using server log lines, failure reason, or unavailable reason. No generated “activity” lines.

**E. Findings and action zone**

- Urgent banner becomes an action queue: severity edge, CVE/package identity, reason, and safe actions (`Explain`, `Snooze`, `Open report`).
- Each action queue row has subtle hover elevation and keyboard-visible focus ring.
- Report has `Summary` and `Full evidence` views. Summary uses real counts and top findings. Full view preserves report text safely escaped/rendered.
- Empty state: shield outline, "No verified findings to show", and one recovery action. Previous report state says "Previous scan" with timestamp, never "current".

**F. Updates workspace**

- Top strip states `Not checked`, `Checking winget`, `N updates found`, `No updates reported`, or `Check failed`.
- Package rows use selection, actual installed/available versions, details panel, ignore action, and explicit update confirmation.
- Install progress reflects parsed backend progress. If backend only has an estimate, label it `Estimated`; on no progress data show indeterminate activity, not a made-up percentage.

**G. Secondary workspaces**

- Security validation: test summary, category chips, and detail table. It is clearly labeled test output, separate from machine threat findings.
- History: real scan points only. Before two stored scans, diff panel says comparison unavailable.
- AI/settings: local-model availability signal, answer source disclaimer, settings grouped by scan schedule, startup, notifications, credentials. AI unavailable is honest and actionable.

### 8.3 Visual tokens

- Background: `#07111F`; raised surface: `#0D1B2A`; elevated surface: `#12243A`.
- Text: primary `#E6F1FF`; muted `#8EA3B8`; divider `rgba(143, 174, 204, .18)`.
- Operational cyan: `#31D7FF`; healthy: `#4EE6A4`; warning: `#FFBE5C`; critical: `#FF5A6D`; neutral: `#71859A`.
- Module edge: 1px translucent border, inner highlight, outer shadow. Use color alone never as status signal; pair every color with icon/text.
- Typography: existing system font stack, tabular numerals for metrics, generous line-height for Arabic.
- Contrast meets WCAG AA for regular text and UI controls.

### 8.4 Motion and interaction rules

- Default transitions: 160-220ms ease-out for hover/focus, 260ms for panel expand/collapse.
- Run scan: button locks only after server accepts request; pipeline begins only from server running state.
- API polling refreshes values without layout jumps; changed real value gets one brief outline flash, no count-up animation until actual number exists.
- Status pulse only for currently running state. Failure and unavailable states do not pulse.
- Modals/drawers trap focus, close with Escape, restore opener focus, and prevent background interaction.
- `prefers-reduced-motion: reduce` disables tilts, pulses, count animation, and expansion motion while retaining state changes.
- Touch devices use tap/long press alternatives; no hover-only information or controls.

### 8.5 State-specific screen behavior

**No live inventory**

- Command deck shows blocked amber state.
- Primary content states: `Live software inventory unavailable` and real backend reason.
- Run action unavailable. Show `Check winget installation and try again` guidance.
- Existing historical data appears only under History with `Previous scan` label.

**First app launch**

- Show empty neutral metrics and no findings. No zeros masquerading as measurements.
- Explain scan prerequisites and expose only valid primary action.

**Successful scan with zero findings**

- Show real `0` findings with positive but restrained healthy state, matched asset count, completion timestamp, and report evidence.

**Request or server failure**

- Keep last known verified data visually separated and timestamped.
- Place failure message adjacent to failed control; give safe retry. Do not clear user choices or claim scan success.

### 8.6 Accessibility and responsive requirements

- All controls have labels, live status messages, visible focus, and keyboard operation.
- Status regions use `aria-live` only for meaningful state changes; polling must not repeatedly announce unchanged values.
- No critical information exists only in charts, color, hover, or 3D effect.
- Desktop: three content columns where space permits. Tablet: two columns. Mobile: one column and fixed bottom navigation.
- Avoid horizontal overflow at 320 CSS pixels. Tables scroll inside labeled containers.

## 9. Implementation choices

- Build 3D depth with existing HTML/CSS/JS only; no external dependency needed.
- Use progressive enhancement: readable flat layout first; depth/filter/tilt only when browser supports them.
- Keep all dynamic values sourced from existing local API contracts after they are hardened. Rendering functions accept explicit `loading`, `empty`, `unavailable`, `failed`, `stale`, or `available` state.
- Store no fake client-side seed data. Example strings may remain only as clearly identified input placeholders.

## 10. Technical approach

1. Establish the actual data contract for inventory, scanning, reports, decisions, updates, history, and configuration.
2. Remove the text inventory fallback from production collection paths and make inventory availability a first-class server state.
3. Normalize API error/status payloads where needed so the frontend can render reliable states without inferring data.
4. Repair backend lifecycle, concurrency, validation, and error-handling issues identified in code review.
5. Refactor frontend state rendering around semantic view states and escaped rendering helpers.
6. Apply the SOC visual system using the existing static HTML/CSS/JS architecture, preserving bilingual support.
7. Add or extend regression tests for inventory-unavailable behavior and key backend transitions.

## 11. Acceptance criteria

- When `winget` is unavailable or inventory collection fails, no NVD scan runs and the UI does not show assets/findings/KPIs as current data.
- `inventory.txt` is not read by production inventory/scanning paths.
- On first load with no valid scan, all metric positions and result areas communicate unavailable/empty state rather than fabricated values.
- Every interactive button has a valid loading, success, empty, or error result and does not remain indefinitely disabled after a failed request.
- The UI works in both Arabic RTL and English LTR without clipped or inverted controls.
- Existing security tests and new/updated relevant tests pass.
- Python modules compile successfully; browser JavaScript passes a syntax check.
- A manual smoke test confirms the server responds locally and key endpoints return truthful states.
- UI has the specified SOC Prism hierarchy, real status pipeline, explicit no-inventory screen, reduced-motion support, and RTL/LTR layout.
- 3D effects improve focus only; layout remains fully usable without them.

## 12. Risks and mitigations

| Risk | Mitigation |
| --- | --- |
| Local `winget` output varies by version/locale | Make parser failure explicit; cover known formats with tests; never substitute file data |
| Existing reports can outlive current inventory | Tag and present them as prior results; do not populate current KPI state without a current successful run |
| UI redesign accidentally hides errors | Define and test loading/empty/error/unavailable states before visual polish |
| Long scans block interaction | Maintain non-blocking server state and clear cancellation/failure completion paths where supported |
| Security hardening changes behavior | Preserve existing local-only/CSRF/CSP contract and run golden security dataset |

## 13. Verification plan

- Static review of all production Python, HTML, CSS, and JavaScript files.
- Automated Python compilation and the existing security/golden tests.
- Focused tests for unavailable/empty live inventory and scan blocking.
- JavaScript syntax validation and browser/API smoke validation against a local server, subject to installed runtime availability.
- Inspect all rendered empty, unavailable, running, failed, and populated screens at desktop and compact viewport sizes.
