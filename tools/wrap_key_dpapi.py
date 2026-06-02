"""Helper: wrap a master key into a DPAPI-protected blob file (Windows only).

Usage:
  python tools\wrap_key_dpapi.py --out C:\keys\ghost_key.dpapi --key "my-super-secret"

The resulting file can be read by `DPAPIKeyProvider`.
"""
import argparse
import sys
import ctypes
from ctypes import wintypes

if sys.platform != "win32":
    print("This helper only runs on Windows.")
    sys.exit(1)

crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def _dpapi_protect(plaintext: bytes) -> bytes:
    buf = ctypes.create_string_buffer(plaintext, len(plaintext))
    blob_in = DATA_BLOB()
    blob_in.cbData = len(plaintext)
    blob_in.pbData = ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte))
    blob_out = DATA_BLOB()

    if not crypt32.CryptProtectData(
        ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
    ):
        raise ctypes.WinError(ctypes.get_last_error())

    try:
        data = bytes(ctypes.cast(blob_out.pbData, ctypes.POINTER(ctypes.c_byte * blob_out.cbData)).contents)
        return data
    finally:
        kernel32.LocalFree(blob_out.pbData)



def main():
    p = argparse.ArgumentParser()
    p.add_argument("--out", required=True, help="Output path for dpapi blob")
    p.add_argument("--key", required=True, help="Master key string to protect")
    args = p.parse_args()

    blob = _dpapi_protect(args.key.encode("utf-8"))
    with open(args.out, "wb") as f:
        f.write(blob)
    print(f"Wrote DPAPI blob to {args.out}")


if __name__ == "__main__":
    main()
