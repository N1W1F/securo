"""Opt-in Windows Startup shortcut — NOT auto-registered.

Deliberately not a scheduled task: this drops a plain .lnk file into the
user's standard Startup folder, identical to how any normal desktop app
(Discord, Steam, ...) offers "launch at login". No elevated privileges, no
new Windows service, no system-wide registration — the user can remove it
in two clicks from the same Startup folder (Win+R -> shell:startup) at any
time, or via this module's remove() function.
"""
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from security import BASE_DIR

APP_DIR = Path(__file__).resolve().parent
LAUNCH_VBS = APP_DIR / "launch.vbs"
# Prefer the packaged .exe (proper taskbar/window icon, no console-flash
# risk) when it exists; fall back to the pythonw+vbs launcher for dev
# checkouts that haven't built one.
EXE_PATH = BASE_DIR / "ThreatIntelAgent.exe"
SHORTCUT_NAME = "Threat Intel Agent.lnk"


def _startup_dir() -> Path | None:
    if sys.platform != "win32":
        return None
    import os
    appdata = os.environ.get("APPDATA")
    if not appdata:
        return None
    return Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"


def is_enabled() -> bool:
    d = _startup_dir()
    return bool(d and (d / SHORTCUT_NAME).is_file())


def enable() -> bool:
    d = _startup_dir()
    if not d:
        return False
    target = d / SHORTCUT_NAME
    if EXE_PATH.is_file():
        ps = (
            "$s = (New-Object -ComObject WScript.Shell).CreateShortcut('{link}'); "
            "$s.TargetPath = '{exe}'; "
            "$s.WorkingDirectory = '{cwd}'; "
            "$s.IconLocation = '{exe}'; "
            "$s.Save()"
        ).format(link=str(target), exe=str(EXE_PATH), cwd=str(BASE_DIR))
    elif LAUNCH_VBS.is_file():
        ps = (
            "$s = (New-Object -ComObject WScript.Shell).CreateShortcut('{link}'); "
            "$s.TargetPath = 'wscript.exe'; "
            "$s.Arguments = '\"{vbs}\"'; "
            "$s.WorkingDirectory = '{cwd}'; "
            "$s.WindowStyle = 7; "
            "$s.Save()"
        ).format(link=str(target), vbs=str(LAUNCH_VBS), cwd=str(APP_DIR))
    else:
        return False
    try:
        subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (subprocess.TimeoutExpired, OSError):
        return False
    return target.is_file()


def disable() -> bool:
    d = _startup_dir()
    if not d:
        return False
    target = d / SHORTCUT_NAME
    try:
        target.unlink(missing_ok=True)
    except OSError:
        return False
    return True
