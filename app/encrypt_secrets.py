"""One-time migration: encrypt the plaintext NVD API key in
secrets.local.json at rest using Windows DPAPI, then lock the file's ACL to
the current user only.

Run manually after filling in secrets.local.json:
    python app/encrypt_secrets.py
"""
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import secure_secrets
from appconfig import SECRETS_PATH


def lock_file_acl(path: Path) -> None:
    """Best-effort: restrict the file to the current user only. Never fatal —
    a failure here just means the OS-level ACL wasn't tightened; the DPAPI
    encryption above is the primary protection either way."""
    if sys.platform != "win32":
        return
    try:
        subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{__import__('os').getlogin()}:F"],
            capture_output=True, text=True, timeout=15,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass


def main() -> int:
    if not SECRETS_PATH.is_file():
        print(f"no secrets file at {SECRETS_PATH} — nothing to do")
        return 0

    data = json.loads(SECRETS_PATH.read_text(encoding="utf-8"))
    key = data.get("nvd_api_key", "")
    if not key:
        print("no nvd_api_key set — nothing to encrypt")
    elif secure_secrets.is_encrypted(key):
        print("nvd_api_key already encrypted")
    else:
        data["nvd_api_key"] = secure_secrets.encrypt(key)
        SECRETS_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        print("nvd_api_key encrypted at rest (DPAPI, current user only)")

    lock_file_acl(SECRETS_PATH)
    print(f"ACL locked (best-effort): {SECRETS_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
