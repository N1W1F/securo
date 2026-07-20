"""Native desktop wrapper. Starts the same local-only HTTP server (127.0.0.1
only, see server.py) on a background thread, then opens it in a pywebview
window instead of a browser tab.

pythonw.exe (used by the desktop shortcut, so no console flashes up) silently
swallows stdout/stderr — so any exception here just looks like "nothing
happened" to the user. Everything is therefore wrapped so failures land in
crash.log instead of vanishing, and a PID lock prevents a second click from
launching a second WebView2 instance (which fails silently on a locked
per-process profile folder).
"""
import atexit
import os
import sys
import threading
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from security import FROZEN, BASE_DIR as _PROJECT_ROOT, RUNTIME_DIR

# APP_DIR is "the folder the running app lives in": app/ in dev (unchanged
# from before — LOCK_FILE/CRASH_LOG must stay there so existing .gitignore
# entries still match), or the exe's own folder when frozen (persistent;
# __file__ would otherwise resolve inside the ephemeral MEIPASS extraction
# dir, which is wiped on exit — the single-instance lock would never
# actually block a second launch). app.ico is a bundled read-only asset, so
# it always comes from RUNTIME_DIR (MEIPASS in a frozen build, app/ in dev).
APP_DIR = _PROJECT_ROOT if FROZEN else RUNTIME_DIR
LOCK_FILE = APP_DIR / ".instance.lock"
CRASH_LOG = APP_DIR / "crash.log"
ICON_PATH = RUNTIME_DIR / "app.ico"


def _pid_is_alive(pid: int) -> bool:
    if sys.platform != "win32":
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False
    import ctypes
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if handle:
        ctypes.windll.kernel32.CloseHandle(handle)
        return True
    return False


def _acquire_single_instance_lock() -> bool:
    if LOCK_FILE.is_file():
        try:
            existing_pid = int(LOCK_FILE.read_text().strip())
        except ValueError:
            existing_pid = -1
        if existing_pid > 0 and _pid_is_alive(existing_pid):
            return False  # another instance is already running

    LOCK_FILE.write_text(str(os.getpid()))
    atexit.register(lambda: LOCK_FILE.unlink(missing_ok=True))
    return True


def main() -> None:
    if not _acquire_single_instance_lock():
        return  # an instance is already open; do nothing rather than fail silently

    import webview
    from server import BIND_HOST, BIND_PORT, main as run_server

    t = threading.Thread(target=run_server, daemon=True)
    t.start()

    webview.create_window(
        "Threat Intel & Asset Monitor",
        f"http://{BIND_HOST}:{BIND_PORT}",
        width=1180,
        height=780,
        min_size=(860, 560),
        background_color="#0b0f14",
    )
    try:
        if ICON_PATH.is_file():
            webview.start(icon=str(ICON_PATH))  # honoured where the backend supports it
        else:
            webview.start()
    except TypeError:
        webview.start()  # older pywebview without the icon kwarg


def _run_scan_and_exit() -> int:
    """Frozen builds have no standalone main.py to spawn as a subprocess —
    the exe IS the interpreter. server.py instead re-invokes THIS exe with
    --run-scan, which just runs the scan pipeline headlessly and exits; the
    GUI path below never runs in that case."""
    import main as scan_main
    return scan_main.main()


if __name__ == "__main__":
    if "--run-scan" in sys.argv:
        sys.exit(_run_scan_and_exit())
    try:
        main()
    except Exception:
        CRASH_LOG.write_text(traceback.format_exc())
        raise
