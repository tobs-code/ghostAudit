"""Key provider abstraction and Windows DPAPI implementation.

Provides:
- KeyProvider (abstract)
- EnvKeyProvider (dev fallback)
- DPAPIKeyProvider (reads DPAPI-protected blob file and unprotects it)

Also includes a small DPAPI helper using Windows CryptProtectData / CryptUnprotectData.
"""
from abc import ABC, abstractmethod
import os
import sys
import ctypes
from ctypes import wintypes


class KeyProvider(ABC):
    @abstractmethod
    def get_master_key(self) -> bytes:
        """Return the master key bytes. Must be kept secret by the provider."""


class EnvKeyProvider(KeyProvider):
    def __init__(self, env_var="GHOST_AUDIT_KEY"):
        self.env_var = env_var

    def get_master_key(self) -> bytes:
        v = os.environ.get(self.env_var)
        if not v:
            raise RuntimeError(f"Environment variable {self.env_var} not set")
        return v.encode("utf-8")


# --- Minimal DPAPI helpers (Windows only) ---
if sys.platform == "win32":
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

    def _dpapi_unprotect(encrypted_blob: bytes) -> bytes:
        """Unprotect bytes using Windows DPAPI (CryptUnprotectData)."""
        buf = ctypes.create_string_buffer(encrypted_blob, len(encrypted_blob))
        blob_in = DATA_BLOB()
        blob_in.cbData = len(encrypted_blob)
        blob_in.pbData = ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte))
        blob_out = DATA_BLOB()

        if not crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
        ):
            raise ctypes.WinError(ctypes.get_last_error())

        try:
            data = bytes(ctypes.cast(blob_out.pbData, ctypes.POINTER(ctypes.c_byte * blob_out.cbData)).contents)
            return data
        finally:
            kernel32.LocalFree(blob_out.pbData)

else:
    def _dpapi_unprotect(encrypted_blob: bytes) -> bytes:
        raise RuntimeError("DPAPI is only supported on Windows (win32)")


class DPAPIKeyProvider(KeyProvider):
    """Reads a DPAPI-protected key blob from a file and returns the unprotected master key.

    Usage:
      provider = DPAPIKeyProvider(path="C:\\keys\\ghost_key.dpapi")
      master = provider.get_master_key()
    """
    def __init__(self, path: str):
        self.path = path

    def get_master_key(self) -> bytes:
        if not os.path.exists(self.path):
            raise FileNotFoundError(f"DPAPI key file not found: {self.path}")
        with open(self.path, "rb") as f:
            blob = f.read()
        return _dpapi_unprotect(blob)


class WinCredKeyProvider(KeyProvider):
    """KeyProvider that reads a generic credential from Windows Credential Manager.

    target_name: the credential target name used in CredWrite/CredRead.
    """
    def __init__(self, target_name: str):
        if sys.platform != "win32":
            raise RuntimeError("WinCredKeyProvider is only supported on Windows")
        self.target_name = target_name
        self._advapi32 = ctypes.windll.advapi32

    def get_master_key(self) -> bytes:
        # CREDENTIALW structure (partial) for reading
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

        pcred = ctypes.c_void_p()
        res = self._advapi32.CredReadW(ctypes.c_wchar_p(self.target_name), wintypes.DWORD(1), wintypes.DWORD(0), ctypes.byref(pcred))
        if not res:
            raise ctypes.WinError()

        try:
            cred = ctypes.cast(pcred, ctypes.POINTER(CREDENTIALW)).contents
            size = int(cred.CredentialBlobSize)
            if size == 0 or not cred.CredentialBlob:
                return b""
            data = ctypes.string_at(cred.CredentialBlob, size)
            return data
        finally:
            # Free memory allocated by CredRead
            try:
                self._advapi32.CredFree(pcred)
            except Exception:
                pass


if __name__ == "__main__":
    print("This module provides KeyProvider implementations. Use the wrap helper in tools to create DPAPI blobs.")
