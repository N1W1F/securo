# Securo

A local, multi-agent security dashboard. It reads a list of your installed
software, checks each item against the public **NVD** CVE database, writes a
report, and (via **winget**) can show and apply available updates. Everything
runs on your own machine — the UI is a local window bound to `127.0.0.1`.

Bilingual UI (العربية / English) with full RTL/LTR support.

**What this is not:** Securo only cross-references locally-installed software
names/versions against public vulnerability databases (NVD, CISA KEV) — the
same category of check as a software updater. It never scans network ports,
never probes other machines, and never attempts to exploit anything. It is a
personal patch-awareness tool, not a penetration-testing or exploitation tool.

**Privacy:** this program will not transfer any information to other
networked systems unless specifically requested by the user or the person
installing or operating it. No telemetry, no analytics, no data collection.

---

## بالعربية

تطبيق أمني محلي متعدد الوكلاء يقرأ قائمة برامجك، يفحصها مقابل قاعدة ثغرات NVD،
يكتب تقريراً، ويعرض التحديثات المتاحة عبر winget مع إمكانية تطبيقها. كل شيء يعمل
على جهازك — الواجهة نافذة محلية على `127.0.0.1` فقط، بدون أي اتصال خارجي عدا
موقع NVD الرسمي.

### التشغيل
1. ثبّت المتطلبات: `pip install -r requirements.txt`
2. انسخ `inventory.example.txt` إلى `inventory.txt` وعدّله ببرامجك (أو استخدم `winget list`).
3. شغّل: `python app/desktop_app.py`  — أو انقر اختصار سطح المكتب.

---

## Requirements

- Windows 10/11 (winget updates use the Windows Package Manager)
- Python 3.10+
- `pip install -r requirements.txt`

## Run

```bash
python app/desktop_app.py      # native desktop window
# or
python app/server.py           # then open http://127.0.0.1:8765 in a browser
```

Create your `inventory.txt` first (copy `inventory.example.txt`).

## What each agent does

Eight agents, each with one job. Four run inside the scan subprocess and
announce themselves in the live log; the other four run in the server process.

| Agent | Role | Access |
|---|---|---|
| Orchestrator | Coordinates the run, sequences the others | — |
| Asset Auditor | Inventories installed software via winget | read-only, sandboxed |
| Package Manager | Checks update catalogs; applies winget updates | fixed `winget` argv only |
| Threat Hunter | Queries NVD for CVEs matching your assets | network only (NVD host) |
| KEV Checker | Flags CVEs on CISA's Known Exploited list | network only (CISA host) |
| Decision | Tiers findings urgent/routine/info, scores health | — |
| Remediation | Writes `threat_intel_report.md` | write-only, fixed path |
| Analyst | Optional local LLM (Ollama) explanations and Q&A | localhost only |

See [ARCHITECTURE.md](ARCHITECTURE.md) for the data flow, the update-source
layer, and the trust boundaries.

## Notable behaviour

- **Update coverage beyond `winget upgrade`.** `winget upgrade` only considers
  packages carrying a catalog Source — on a real machine that was 67 of 183
  installed programs. Securo additionally looks up untracked programs by exact
  name and compares versions, recovering updates that would otherwise stay
  invisible. Everything still unreachable is classified and explained (Store
  apps Windows updates itself, drivers in no catalog, entries with no
  comparable version) rather than reported as one opaque number.

- **Deep scan.** Ignores the 24-hour NVD result cache and re-queries every
  installed program from scratch. Ordinary scans reuse cached results, so a
  re-scan is fast; deep scan is the "check everything again" button.

- **Urgent means actionable.** A finding reaches the urgent tier only if a fix
  actually exists and exploitation is realistic. Update availability is
  tri-state — `unknown` is never rendered as "no update exists".

- **Live 3D agent scene.** Shows all eight agents driven by real execution
  state, not a simulation. It is still while idle and animates only while work
  is happening.

- **Print / save as PDF** for the scan report.

## Security

See [SHARING.md](SHARING.md) for the full security posture and how to share
this app with others safely. In short: source-only (inspectable), localhost
only, CSRF-protected local API, strict input validation, no `shell=True`,
no telemetry.

## Project governance

Single-maintainer project. All roles below are currently held by the same
person ([N1W1F](https://github.com/N1W1F)):

- **Author / Committer**: trusted to modify source directly.
- **Reviewer**: reviews any externally-proposed change (pull request) before merge.
- **Approver**: approves what gets tagged as a release / signed build.

`main` is branch-protected — no change reaches it without the automated
142-test Golden Dataset security suite passing first (see
[.github/workflows/ci.yml](.github/workflows/ci.yml)).

## Code signing policy

Windows builds of this project are code-signed for free by
[SignPath.io](https://about.signpath.io/), certificate provided by
[SignPath Foundation](https://signpath.org/), once accepted into their
open-source program.
