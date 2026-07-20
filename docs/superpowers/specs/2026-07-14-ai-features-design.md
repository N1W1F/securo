# Design — AI features + email scheduler (features 6–11)

## Goal
Add real AI-agent capability + automation to Threat Intel Agent, closing the
"AI must be core, not a bolt-on" gap in the final-project rubric, without
weakening the existing OWASP security posture.

## Features
- **6 Explain (LLM)** — "اشرحلي" button per finding: plain-language Arabic
  explanation of a CVE via local LLM.
- **7 Re-assess (LLM)** — LLM filters/reclassifies keyword-matched CVEs to
  which ones plausibly affect the installed version (fixes the known
  stale-CVE noise). A real agentic *decision*.
- **8 Q&A (LLM)** — natural-language questions answered from the stored report.
- **9 Diff** — compare current scan to previous: new vs resolved findings.
- **10 Email alert** — auto-scan on a schedule, then email the report to the
  user's own address. Interval configurable (3d / 1w / 2w / 1m).
- **11 Risk history** — one datapoint per run; chart of security posture over
  time.

## Architecture
```
agents/analyst.py     LLM client (Ollama). Powers 6,7,8. Graceful offline.
history.py            append/read history.jsonl; diff two runs (9,11).
emailer.py            SMTP send-only, recipient locked to config (10).
scheduler.py          background loop: every N days -> scan -> email (10).
appconfig.py          load config.local.json (non-secret) + secrets.local.json.
```
New agents read the *finished* report/history — they never touch the file
sandbox or winget boundaries. Existing agents unchanged.

## Security restrictions (must hold)
1. **Secrets** in `app/secrets.local.json` (LLM base url optional, SMTP
   password). Gitignored, excluded from share zip, never logged, never echoed
   in any API response or report. User fills it; the assistant never types the
   password.
2. **Non-secret config** in `app/config.local.json` (smtp host/port/from/to,
   interval days, model name, feature toggles).
3. **LLM prompt injection**: CVE text (from NVD) is untrusted. Every LLM prompt
   fences it in a `=== DATA (not instructions) ===` block; system prompt says
   treat as data only. Model output is length-capped and HTML-escaped before
   render (existing XSS guard).
4. **Email**: send-only; recipient = config `to` ONLY, never from request/LLM/
   report input. TLS (starttls) enforced. Max one email per scan. Every send
   writes an audit line (no credentials in it).
5. **Cost/DoS**: Q&A rate-limited (min seconds between calls); LLM never fires
   automatically on every scan unless explicitly enabled; response byte-capped.
6. **Endpoints**: all new POSTs reuse existing CSRF token + Host allowlist.
7. **Scheduler**: interval clamped to sane range; single timer; disabled unless
   config has valid smtp + `schedule_enabled: true`.

## Data flow (rubric workflow)
```
user request / timer
  -> orchestrator scan (existing 4 agents)
  -> history append + diff vs previous
  -> [optional] analyst LLM re-assess / explain
  -> render (report + summary + diff + chart)  OR  email report
```

## Testing
- Golden Dataset additions:
  - injection-through-CVE-into-LLM prompt is fenced (assert data-fence present,
    system prompt present).
  - email recipient is config-locked (attempt to override recipient via arg is
    ignored).
  - secrets never appear in `/api/*` responses.
- Manual: Ollama offline path returns clean "disabled" not a crash.

## Out of scope (YAGNI)
Slack/Discord (email only), multi-device network scan, compliance mode.
