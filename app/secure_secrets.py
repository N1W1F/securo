"""At-rest encryption for the SMTP password using Windows DPAPI.

DPAPI (CryptProtectData) ties the ciphertext to the current Windows user
account — the file is unreadable if copied to another machine or opened by
another user on the same machine, without needing us to manage a key at all.
This does not protect against malware running as the same user (nothing
local-only can), but it closes the much more common exposure: the plaintext
password sitting in a file that a screen-share, backup, or "cat this file to
debug" moment could leak.

Windows-only. On other platforms this module is inert (encrypt/decrypt are
no-ops) and the caller falls back to plaintext, matching the previous
behavior rather than breaking cross-platform dev.
"""
import base64
import ctypes
import ctypes.wintypes
import sys

DPAPI_PREFIX = "dpapi:"
_IS_WINDOWS = sys.platform == "win32"


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _to_blob(data: bytes) -> _DATA_BLOB:
    buf = ctypes.create_string_buffer(data, len(data))
    return _DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))


def encrypt(plaintext: str) -> str:
    """Returns 'dpapi:<base64>' on Windows, or the plaintext unchanged elsewhere."""
    if not _IS_WINDOWS or not plaintext:
        return plaintext
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32

    in_blob = _to_blob(plaintext.encode("utf-8"))
    out_blob = _DATA_BLOB()
    ok = crypt32.CryptProtectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob))
    if not ok:
        return plaintext  # fail closed to "unchanged", never crash the caller
    try:
        encrypted = ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)
    return DPAPI_PREFIX + base64.b64encode(encrypted).decode("ascii")


def decrypt(value: str) -> str:
    """Reverses encrypt(). Non-DPAPI values pass through unchanged."""
    if not value or not value.startswith(DPAPI_PREFIX):
        return value
    if not _IS_WINDOWS:
        return ""  # can't decrypt DPAPI blobs off-Windows; fail closed, not with a wrong password
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32

    raw = base64.b64decode(value[len(DPAPI_PREFIX):])
    in_blob = _to_blob(raw)
    out_blob = _DATA_BLOB()
    ok = crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob))
    if not ok:
        return ""
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData).decode("utf-8")
    finally:
        kernel32.LocalFree(out_blob.pbData)


def is_encrypted(value: str) -> bool:
    return bool(value) and value.startswith(DPAPI_PREFIX)
