"""Windows toast notifications — the default alert channel (no account, no
password, no external service). Uses the WinRT toast API via a fixed
PowerShell invocation, the same subprocess pattern already used for winget
elsewhere in this codebase (fixed argv, no shell=True). All user-controlled
text (title/message) is XML-escaped before it reaches the script.

CreateToastNotifier() needs an AUMID (app identity) that Windows actually
recognizes — an arbitrary string like "Securo" is accepted
without error but the toast is then silently dropped (no popup, nothing in
Action Center either), which is exactly the "nothing happens" bug this
file used to have. The fix Microsoft documents for unpackaged apps is a
one-time per-user registry registration under
HKCU\\Software\\Classes\\AppUserModelId — done lazily here (idempotent —
Set-ItemProperty on an already-correct value is a no-op) rather than at
install time, since there is no installer.
"""
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit import log
from security import RUNTIME_DIR

AGENT = "Notifier"
TIMEOUT_SECS = 15
MAX_TITLE_CHARS = 120
MAX_MESSAGE_CHARS = 300
AUMID = "Securo.DesktopApp"

_TOAST_SCRIPT = r'''
$aumid = "__AUMID__"
$regPath = "HKCU:\Software\Classes\AppUserModelId\$aumid"
if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
Set-ItemProperty -Path $regPath -Name "DisplayName" -Value "Securo"
Set-ItemProperty -Path $regPath -Name "IconUri" -Value "__ICON__"
Set-ItemProperty -Path $regPath -Name "IconBackgroundColor" -Value "0xFF0A0612"

[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom, ContentType=WindowsRuntime] | Out-Null
$xmlText = @"
<toast>
  <visual>
    <binding template="ToastGeneric">
      <text>__TITLE__</text>
      <text>__MESSAGE__</text>
    </binding>
  </visual>
</toast>
"@
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml($xmlText)
$toast = New-Object Windows.UI.Notifications.ToastNotification $xml
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($aumid).Show($toast)
'''


def _xml_escape(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace('"', "&quot;").replace("'", "&apos;"))


def send(title: str, message: str) -> bool:
    if sys.platform != "win32":
        return False
    title = _xml_escape((title or "")[:MAX_TITLE_CHARS])
    message = _xml_escape((message or "")[:MAX_MESSAGE_CHARS])
    icon_path = str(RUNTIME_DIR / "static" / "icon.png")
    script = (_TOAST_SCRIPT.replace("__TITLE__", title).replace("__MESSAGE__", message)
                            .replace("__AUMID__", AUMID).replace("__ICON__", icon_path))
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=TIMEOUT_SECS,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode != 0:
            log(AGENT, f"toast failed: {(result.stderr or '').strip()[:200]}")
            return False
        log(AGENT, f"toast sent: {title}")
        return True
    except (subprocess.TimeoutExpired, OSError) as e:
        log(AGENT, f"toast failed: {type(e).__name__}")
        return False
