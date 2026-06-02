"""Test: write secret to Windows Credential Manager, read via WinCredKeyProvider,
and perform a small GhostAuditV7 log/recover cycle.

Usage:
  python tests\key_provider_credman_test.py
"""
import os
import subprocess
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TOOLS = os.path.join(ROOT, "tools")

if sys.platform != "win32":
    print("Test is Windows-only")
    sys.exit(0)

TARGET = "ghost_audit_test_key"
SECRET = "test-credman-secret-12345"

# 1) write credential via helper
cmd = [sys.executable, os.path.join(TOOLS, "write_credman.py"), "--target", TARGET, "--secret", SECRET]
print("Writing credential...")
subprocess.check_call(cmd)

time.sleep(0.5)

print("Importing providers and GhostAuditV7")
sys.path.insert(0, ROOT)
from key_provider import WinCredKeyProvider
from core.ghost_audit_v7 import GhostAuditV7

prov = WinCredKeyProvider(TARGET)
master = prov.get_master_key()
print("Master key (len):", len(master))

ga = GhostAuditV7(db_path="credman_test.db", key_provider=prov, verbose=True)
ga.log_event("TEST_CREDMAN_EVENT")
recovered = ga.recover_events()
print("Recovered events:", recovered)
ga.close()

# cleanup
try:
    os.remove("credman_test.db")
except Exception:
    pass

print("Removing credential from Credential Manager...")
subprocess.check_call([sys.executable, os.path.join(TOOLS, "delete_credman.py"), "--target", TARGET])

print("Test complete")
