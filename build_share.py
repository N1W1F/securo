"""Build a clean, shareable source zip + SHA-256 checksum.

Deliberately EXCLUDES anything private or generated: your real inventory.txt,
the generated report, logs, caches, the single-instance lock, and dev-only
files. What ships is inspectable source plus an example inventory — the safest
form to hand to someone else (see SHARING.md).
"""
import hashlib
import shutil
import zipfile
from pathlib import Path

BASE = Path(__file__).resolve().parent
OUT_DIR = BASE / "share"
VERSION = "1.0"
ZIP_PATH = OUT_DIR / f"Securo-v{VERSION}-source.zip"

INCLUDE_TOP = ["README.md", "SHARING.md", "SUBMISSION.md", "requirements.txt",
               "inventory.example.txt", "SECURITY_GOLDEN_DATASET.md", "SECURITY_GOLDEN_DATASET.json"]
INCLUDE_APP = "app"

EXCLUDE_NAMES = {"__pycache__", ".instance.lock", "crash.log", "out.log",
                 "secrets.local.json", "config.local.json", "history.jsonl",
                 "snoozes.json", "scheduler_state.json", "inventory_snapshot.json",
                 "nvd_cache.json", "ignored_updates.json"}
EXCLUDE_SUFFIXES = {".pyc", ".log"}
EXCLUDE_APP_FILES = {"build_share.py"}


def _keep(path: Path) -> bool:
    if path.name in EXCLUDE_NAMES or path.name in EXCLUDE_APP_FILES:
        return False
    if path.suffix in EXCLUDE_SUFFIXES:
        return False
    if any(part == "__pycache__" for part in path.parts):
        return False
    return True


def build() -> Path:
    OUT_DIR.mkdir(exist_ok=True)
    if ZIP_PATH.exists():
        ZIP_PATH.unlink()

    added = 0
    with zipfile.ZipFile(ZIP_PATH, "w", zipfile.ZIP_DEFLATED) as z:
        for name in INCLUDE_TOP:
            f = BASE / name
            if f.is_file():
                z.write(f, f"threat-intel-agent/{name}")
                added += 1

        app_dir = BASE / INCLUDE_APP
        for f in app_dir.rglob("*"):
            if f.is_file() and _keep(f):
                rel = f.relative_to(BASE)
                z.write(f, f"threat-intel-agent/{rel.as_posix()}")
                added += 1

    return ZIP_PATH, added


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    zip_path, count = build()
    digest = sha256(zip_path)
    checksum_file = zip_path.with_suffix(zip_path.suffix + ".sha256")
    checksum_file.write_text(f"{digest}  {zip_path.name}\n", encoding="utf-8")
    print(f"packaged {count} files -> {zip_path}")
    print(f"SHA-256: {digest}")
    print(f"checksum written -> {checksum_file}")


if __name__ == "__main__":
    main()
