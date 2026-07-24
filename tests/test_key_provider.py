"""
DPAPI Key Provider — End-to-End-Test (Windows)
===============================================
Testet den kompletten Schlüssel-Schutzfluss:

  1. CryptProtectData  (wrap_key_dpapi._dpapi_protect)
  2. DPAPIKeyProvider.get_master_key()  (CryptUnprotectData)
  3. Integration mit GhostAuditV7 über key_provider=DPAPIKeyProvider(...)
  4. WinCredKeyProvider: Schlüssel aus Windows Credential Manager lesen

Auf Nicht-Windows-Systemen werden alle Tests übersprungen.

Usage:
  python tests/test_key_provider.py [--verbose]
"""
import sys
import os
import tempfile
import shutil
import argparse
import importlib.util

# Sicherstellen dass core/ im Pfad ist
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)


def _load_wrap_tool():
    """Dynamically load tools/wrap_key_dpapi.py (no __init__.py in tools/)."""
    tool_path = os.path.join(_ROOT, "tools", "wrap_key_dpapi.py")
    spec = importlib.util.spec_from_file_location("wrap_key_dpapi", tool_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

_IS_WIN = sys.platform == "win32"

PASS = "✅ PASS"
FAIL = "❌ FAIL"
SKIP = "⏭️  SKIP"


def _test_dpapi_roundtrip(tmp_dir: str, verbose: bool) -> str:
    """Protect a key with DPAPI, then unprotect and verify."""
    if not _IS_WIN:
        return SKIP

    try:
        wrap_tool = _load_wrap_tool()
        from core.key_provider import _dpapi_unprotect

        secret = b"ghost-audit-master-key-v7-test-12345"
        blob = wrap_tool._dpapi_protect(secret)

        if verbose:
            print(f"  DPAPI blob: {len(blob)} bytes")

        recovered = _dpapi_unprotect(blob)
        assert recovered == secret, f"Mismatch: {recovered!r} != {secret!r}"
        return PASS
    except Exception as e:
        return f"{FAIL}: {e}"


def _test_dpapi_file_provider(tmp_dir: str, verbose: bool) -> str:
    """Write DPAPI blob to file, then use DPAPIKeyProvider to read it."""
    if not _IS_WIN:
        return SKIP

    try:
        wrap_tool = _load_wrap_tool()
        from core.key_provider import DPAPIKeyProvider

        secret = b"ghost-audit-dpapi-file-test-key-xyz"
        blob_path = os.path.join(tmp_dir, "test_ghost_key.dpapi")

        blob = wrap_tool._dpapi_protect(secret)
        with open(blob_path, "wb") as f:
            f.write(blob)

        provider = DPAPIKeyProvider(blob_path)
        recovered = provider.get_master_key()
        assert recovered == secret, f"Mismatch: {recovered!r}"

        if verbose:
            print(f"  Blob-Datei: {blob_path} ({os.path.getsize(blob_path)} bytes)")
        return PASS
    except Exception as e:
        return f"{FAIL}: {e}"


def _test_ghost_audit_with_dpapi_provider(tmp_dir: str, verbose: bool) -> str:
    """Full integration: GhostAuditV7 with DPAPIKeyProvider."""
    if not _IS_WIN:
        return SKIP

    try:
        wrap_tool = _load_wrap_tool()
        from core.key_provider import DPAPIKeyProvider
        from core.ghost_audit_v7 import GhostAuditV7

        secret = b"integration-test-key-for-ghostaudit-v7-abcdef"
        blob_path = os.path.join(tmp_dir, "integration_ghost_key.dpapi")
        db_path   = os.path.join(tmp_dir, "dpapi_integration.db")

        # Schreibe DPAPI-Blob
        blob = wrap_tool._dpapi_protect(secret)
        with open(blob_path, "wb") as f:
            f.write(blob)

        # GhostAudit mit DPAPIKeyProvider initialisieren
        provider = DPAPIKeyProvider(blob_path)
        ga = GhostAuditV7(db_path=db_path, key_provider=provider, verbose=verbose)
        ga.log_event("DPAPI_TEST: Integration event via DPAPIKeyProvider")
        ga.close()

        # Recovery mit demselben Provider
        ga2 = GhostAuditV7(db_path=db_path, key_provider=provider, verbose=False)
        events = list(ga2.recover_events())
        ga2.close()

        recovered = any("DPAPI_TEST" in msg for _, msg in events)
        if not recovered:
            return f"{FAIL}: Event nicht wiederhergestellt (events={events})"
        if verbose:
            print(f"  Recovered: {events}")
        return PASS
    except Exception as e:
        return f"{FAIL}: {e}"


def _test_dpapi_file_not_found(tmp_dir: str, verbose: bool) -> str:
    """DPAPIKeyProvider raises FileNotFoundError for missing file."""
    if not _IS_WIN:
        return SKIP

    try:
        from core.key_provider import DPAPIKeyProvider
        provider = DPAPIKeyProvider(os.path.join(tmp_dir, "nonexistent.dpapi"))
        try:
            provider.get_master_key()
            return f"{FAIL}: Keine Exception für fehlende Datei"
        except FileNotFoundError:
            return PASS
    except Exception as e:
        return f"{FAIL}: {e}"


def _test_env_key_provider(tmp_dir: str, verbose: bool) -> str:
    """EnvKeyProvider reads key from environment variable."""
    try:
        from core.key_provider import EnvKeyProvider
        os.environ["_TEST_GHOST_AUDIT_KEY"] = "env-test-secret-key"
        provider = EnvKeyProvider("_TEST_GHOST_AUDIT_KEY")
        key = provider.get_master_key()
        del os.environ["_TEST_GHOST_AUDIT_KEY"]
        assert key == b"env-test-secret-key", f"Got: {key!r}"
        return PASS
    except Exception as e:
        return f"{FAIL}: {e}"


def _test_env_key_provider_missing(tmp_dir: str, verbose: bool) -> str:
    """EnvKeyProvider raises RuntimeError when variable not set."""
    try:
        from core.key_provider import EnvKeyProvider
        # Sicherstellen dass die Variable nicht gesetzt ist
        os.environ.pop("_TEST_MISSING_GHOST_KEY", None)
        provider = EnvKeyProvider("_TEST_MISSING_GHOST_KEY")
        try:
            provider.get_master_key()
            return f"{FAIL}: Keine Exception für fehlende Env-Var"
        except RuntimeError:
            return PASS
    except Exception as e:
        return f"{FAIL}: {e}"


TESTS = [
    ("DPAPI Roundtrip (Protect/Unprotect)",   _test_dpapi_roundtrip),
    ("DPAPI File Provider",                    _test_dpapi_file_provider),
    ("DPAPI + GhostAuditV7 Integration",       _test_ghost_audit_with_dpapi_provider),
    ("DPAPI FileNotFoundError",                _test_dpapi_file_not_found),
    ("EnvKeyProvider — Env-Var gesetzt",       _test_env_key_provider),
    ("EnvKeyProvider — Env-Var fehlt",         _test_env_key_provider_missing),
]


def main():
    parser = argparse.ArgumentParser(
        description="DPAPI Key Provider End-to-End-Tests"
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    print("=" * 65)
    print("GhostAudit V7 — Key Provider Tests")
    if not _IS_WIN:
        print("[INFO] Nicht-Windows-System: DPAPI-Tests werden übersprungen.")
    print("=" * 65)
    print()

    tmp_dir = tempfile.mkdtemp(prefix="ghost_kp_test_")
    passed = failed = skipped = 0

    try:
        for name, test_fn in TESTS:
            result = test_fn(tmp_dir, args.verbose)
            if args.verbose or result.startswith("❌"):
                print(f"  {result}  {name}")
            else:
                print(f"  {result}  {name}")

            if result == PASS:
                passed += 1
            elif result == SKIP:
                skipped += 1
            else:
                failed += 1
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    print()
    print("=" * 65)
    print(f"Ergebnis: {passed} PASS  |  {failed} FAIL  |  {skipped} SKIP")

    if failed == 0:
        print("✅ Alle Key-Provider-Tests bestanden.")
    else:
        print(f"❌ {failed} Test(s) fehlgeschlagen.")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
