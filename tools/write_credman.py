"""Write a generic credential to Windows Credential Manager.

Usage:
  python tools\write_credman.py --target ghost_audit_key --secret "my-secret"

Writes a generic credential (CRED_TYPE_GENERIC) with the provided secret as the credential blob.
"""
import argparse
import sys
import ctypes
from ctypes import wintypes

if sys.platform != "win32":
    print("This helper only runs on Windows.")
    sys.exit(1)

advapi32 = ctypes.windll.advapi32
kernel32 = ctypes.windll.kernel32

class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.c_void_p)]


class FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]


class CREDENTIALW(ctypes.Structure):
    _fields_ = [
        ("Flags", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("TargetName", wintypes.LPWSTR),
        ("Comment", wintypes.LPWSTR),
        ("LastWritten", FILETIME),
        ("CredentialBlobSize", wintypes.DWORD),
        ("CredentialBlob", ctypes.c_void_p),
        ("Persist", wintypes.DWORD),
        ("AttributeCount", wintypes.DWORD),
        ("Attributes", ctypes.c_void_p),
        ("TargetAlias", wintypes.LPWSTR),
        ("UserName", wintypes.LPWSTR),
    ]


def write_credential(target: str, secret: bytes, persist: int = 2) -> None:
    # CRED_TYPE_GENERIC = 1
    cred = CREDENTIALW()
    cred.Flags = 0
    cred.Type = 1
    cred.TargetName = ctypes.c_wchar_p(target)
    cred.Comment = None
    cred.CredentialBlobSize = len(secret)
    # allocate buffer for blob
    buf = ctypes.create_string_buffer(secret, len(secret))
    cred.CredentialBlob = ctypes.cast(buf, ctypes.c_void_p)
    cred.Persist = persist
    cred.AttributeCount = 0
    cred.Attributes = None
    cred.TargetAlias = None
    cred.UserName = None

    res = advapi32.CredWriteW(ctypes.byref(cred), 0)
    if not res:
        raise ctypes.WinError()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--target", required=True)
    p.add_argument("--secret", required=True)
    args = p.parse_args()

    write_credential(args.target, args.secret.encode("utf-8"))
    print(f"Wrote credential '{args.target}' to Windows Credential Manager")


if __name__ == "__main__":
    main()
