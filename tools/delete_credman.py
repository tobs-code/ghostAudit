"""Delete a generic credential from Windows Credential Manager.

Usage:
  python tools\delete_credman.py --target ghost_audit_key
"""
import argparse
import sys
import ctypes
from ctypes import wintypes

if sys.platform != "win32":
    print("This helper only runs on Windows.")
    sys.exit(1)

advapi32 = ctypes.windll.advapi32


def delete_credential(target: str) -> None:
    res = advapi32.CredDeleteW(ctypes.c_wchar_p(target), wintypes.DWORD(1), wintypes.DWORD(0))
    if not res:
        raise ctypes.WinError()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--target", required=True)
    args = p.parse_args()

    delete_credential(args.target)
    print(f"Deleted credential '{args.target}' from Windows Credential Manager")


if __name__ == "__main__":
    main()
