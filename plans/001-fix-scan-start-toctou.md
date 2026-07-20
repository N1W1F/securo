# Plan 001 — Fix TOCTOU race on scan start (concurrent orchestrator processes corrupt findings JSON)

**Written against:** no git repo (project at `C:\Users\PC\Documents\threat-intel-agent`, no `.git`). Match file state as of this plan; if the excerpts below don't match, STOP and report.

**Category:** correctness / concurrency
**Effort:** S (≈20 lines, one file)
**Risk of fix:** low

---

## Problem (full context — executor has not seen this codebase)

`app/server.py` runs the scan pipeline (`main.py` / the frozen `--run-scan` path) as a subprocess launched from a background thread `_run_orchestrator()`. That subprocess writes two shared output files via `agents/remediation.py`:
- `threat_intel_report.md`
- `threat_intel_findings.json`  ← the structured file the decision engine reads

The "is a scan already running?" guard is checked in the HTTP handler, but the `running` flag is only *set* later, inside the spawned thread. So two triggers that arrive close together both see `running == False` and both spawn a subprocess. Two subprocesses then write the same two files concurrently → interleaved/corrupt `threat_intel_findings.json`, which `_recompute_decision()` then fails to parse (silently returns, leaving a stale decision).

There are **two** trigger paths with this exact race:
1. `POST /api/run` (user clicks "Run scan", or double-clicks).
2. The auto-rescan fired after a successful winget update (`_run_apply` tail).

### Evidence — current code

`app/server.py`, `_run_orchestrator` sets the flag only inside the thread:

```python
def _run_orchestrator():
    with _state_lock:
        _state["running"] = True
        _state["done"] = False
        _state["log"] = []
        _state["exit_code"] = None
        _state["started_at"] = time.time()

    proc = subprocess.Popen(
        _SCAN_CMD,
        cwd=str(APP_DIR),
        ...
```

`app/server.py`, `POST /api/run` handler — checks then spawns (flag not yet set):

```python
        if self.path == "/api/run":
            with _state_lock:
                already = _state["running"]
            if already:
                self._json({"status": "already_running"})
                return
            threading.Thread(target=_run_orchestrator, daemon=True).start()
            self._json({"status": "started"})
```

`app/server.py`, auto-rescan tail of `_run_apply` — same check-then-spawn:

```python
    if any_ok:
        # a package version just changed under us ...
        with _state_lock:
            already_scanning = _state["running"]
        if not already_scanning:
            threading.Thread(target=_run_orchestrator, daemon=True).start()
```

Between the `with _state_lock: already = _state["running"]` read and the thread actually setting `running = True`, a second request wins the same check.

---

## Fix — claim the flag atomically at the decision point, in one place

Introduce a single helper that atomically tests-and-sets `running` under `_state_lock` and starts the thread only if it won the claim. Both trigger paths call it. `_run_orchestrator` no longer sets `running = True` itself (the claimer already did) but still clears it in its `finally`.

### Step 1 — add the claim helper

In `app/server.py`, immediately **above** `def _run_orchestrator():`, add:

```python
def _try_start_orchestrator() -> bool:
    """Atomically claim the 'scan running' flag and start the pipeline
    thread. Returns False if a scan is already running (the claim failed),
    so two near-simultaneous triggers can never spawn two subprocesses that
    would clobber threat_intel_findings.json / _report.md concurrently."""
    with _state_lock:
        if _state["running"]:
            return False
        _state["running"] = True
        _state["done"] = False
        _state["log"] = []
        _state["exit_code"] = None
        _state["started_at"] = time.time()
    threading.Thread(target=_run_orchestrator, daemon=True).start()
    return True
```

### Step 2 — remove the now-duplicated state init from `_run_orchestrator`

Change the top of `_run_orchestrator` from:

```python
def _run_orchestrator():
    with _state_lock:
        _state["running"] = True
        _state["done"] = False
        _state["log"] = []
        _state["exit_code"] = None
        _state["started_at"] = time.time()

    proc = subprocess.Popen(
```

to:

```python
def _run_orchestrator():
    # state was claimed + initialized by _try_start_orchestrator() under the
    # lock before this thread started — do NOT re-init here.
    proc = subprocess.Popen(
```

Leave the rest of `_run_orchestrator` unchanged, including the tail that sets `running = False`, `done = True`, `exit_code`. That tail stays — it releases the claim.

### Step 3 — route `POST /api/run` through the helper

Replace:

```python
        if self.path == "/api/run":
            with _state_lock:
                already = _state["running"]
            if already:
                self._json({"status": "already_running"})
                return
            threading.Thread(target=_run_orchestrator, daemon=True).start()
            self._json({"status": "started"})
```

with:

```python
        if self.path == "/api/run":
            if _try_start_orchestrator():
                self._json({"status": "started"})
            else:
                self._json({"status": "already_running"})
```

### Step 4 — route the auto-rescan through the helper

Replace the `_run_apply` tail:

```python
    if any_ok:
        # a package version just changed under us ...
        with _state_lock:
            already_scanning = _state["running"]
        if not already_scanning:
            threading.Thread(target=_run_orchestrator, daemon=True).start()
```

with:

```python
    if any_ok:
        # a package version just changed under us — the urgent list still
        # reflects CVEs matched against the OLD version until a fresh full
        # scan runs. Auto-trigger one (atomic claim; no-op if one is
        # already running) so "already updated" software stops showing as
        # still-urgent without the user manually re-scanning.
        _try_start_orchestrator()
```

---

## Scope

**In scope:** `app/server.py` only — the four edits above.
**Out of scope — do NOT touch:** `_run_scan` / `_upg_state` (winget update scan; separate lock, separate state, not affected). `_scan_blocking` (scheduler path; runs `subprocess.run` synchronously and is already serialized by `scheduler._scan_lock` — leave it). Any agent file. Any test file except the new test in the test plan below.

---

## Done criteria (machine-checkable)

1. `cd app && "C:/Users/PC/AppData/Local/Programs/Python/Python312/python.exe" -c "import server"` prints nothing and exits 0 (module imports clean under the real runtime Python).
2. `grep -n "_state\[.running.\] = True" app/server.py` returns **exactly one** line, and it is inside `_try_start_orchestrator`.
3. `cd app && "C:/Users/PC/AppData/Local/Programs/Python/Python312/python.exe" tests/golden_dataset.py` still ends with `Passed: N   Failed: 0` (N ≥ 124 after the new test below).

## Test plan

Add one test to `app/tests/golden_dataset.py`, following the existing decorator/style used by other server tests there (they call `srv` = the imported `server` module). Place it near the other `srv`-touching tests. It asserts the claim is single-winner:

```python
@test("Concurrency", "بدء الفحص المتزامن لا يشغّل عمليتين (claim ذري)",
      "المحاولة الثانية ترجع False دون تشغيل ثريد ثانٍ",
      "server._try_start_orchestrator atomic claim", "State & Concurrency")
def scan_start_is_single_winner():
    orig_running = srv._state["running"]
    started = []
    orig_thread = srv.threading.Thread

    class _FakeThread:
        def __init__(self, *a, **k): pass
        def start(self): started.append(1)

    srv.threading.Thread = _FakeThread
    srv._state["running"] = False
    try:
        first = srv._try_start_orchestrator()   # should win, "start" one thread
        second = srv._try_start_orchestrator()  # should lose (running now True)
    finally:
        srv.threading.Thread = orig_thread
        srv._state["running"] = orig_running
    return first is True and second is False and len(started) == 1, f"first={first} second={second} threads={len(started)}"
```

Verify it passes: run the suite (done-criterion 3). If the existing tests reference the server module under a different alias than `srv`, match that alias instead — check the imports at the top of `golden_dataset.py` first.

## Maintenance note

Any future third trigger for a full scan (e.g. a "rescan" button, a webhook) must also go through `_try_start_orchestrator()` — never spawn `_run_orchestrator` directly. The single-writer invariant on `threat_intel_findings.json` depends on it.

## Escape hatch

If `_run_orchestrator`'s tail does **not** already set `_state["running"] = False` in a `finally` (i.e. an exception before the tail could leave the flag stuck True forever), STOP and report — the claim helper makes a stuck flag permanently block all future scans, so the tail must be exception-safe first. (As of this plan the tail runs unconditionally after `proc.wait()`, but a raised exception in `history.record_current_report()` / `_recompute_decision()` is already caught locally, so the tail is reached. Confirm this before finishing.)
