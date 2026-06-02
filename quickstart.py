#!/usr/bin/env python3
"""
GhostAudit — Quickstart Demo

Shows the core workflow:
  1. Log events into a SQLite database (steganographically hidden in user data)
  2. Simulate an attacker deleting the visible log tables
  3. Recover all events from the hidden carrier layer
  4. Verify integrity via Merkle root and per-event MACs
  5. Export a signed checkpoint as external witness

Run:
    python quickstart.py
"""

import secrets
import sqlite3
import os
from core.ghost_audit_v7 import GhostAuditV7

DB       = "quickstart_demo.db"
EVOLVE   = "quickstart_demo.evolve"
CKPT     = "quickstart_demo_checkpoint.json"

# Clean slate
for f in (DB, EVOLVE, CKPT):
    if os.path.exists(f):
        os.remove(f)

# --- 1. Setup ---
key = secrets.token_hex(32)   # 256-bit master key — keep this secret!
ga = GhostAuditV7(
    db_path=DB,
    secret_key=key,
    external_state_path=EVOLVE,
    force_reinit=True,
    verbose=False,
)
print("GhostAudit initialised.\n")

# --- 2. Log some audit events ---
events = [
    "user=alice action=login ip=192.168.1.10",
    "user=alice action=read_file path=/etc/passwd",
    "user=root  action=delete_table table=audit_log",   # attacker covers tracks
    "user=alice action=export_data rows=50000",
]
ga.log_events(events)
for msg in events:
    print(f"  logged: {msg}")

# --- 3. Simulate attacker deleting visible logs ---
print("\nAttacker deleted audit_log and audit_archive.")
attacker_con = sqlite3.connect(DB)
attacker_con.execute("DELETE FROM audit_log")
attacker_con.execute("DELETE FROM audit_archive")
attacker_con.commit()
attacker_con.close()
print("Visible tables are empty. Nothing to find... or so they think.\n")

# --- 4. Recovery from hidden carrier layer ---
recovered = ga.recover_events()
print(f"Recovered {len(recovered)} events from sys_cache carrier layer:")
for seq, msg in recovered:
    print(f"  [{seq}] {msg}")

# --- 5. Integrity verification ---
print()
root = ga.get_verification_digest()
print(f"Merkle root : {root}")

mac_results = ga.verify_all_event_macs()
all_ok = all(r["valid"] for r in mac_results)
# Note: MACs reference entries in audit_log — after the attacker deleted it,
# this correctly reports tampering. The carrier recovery above is independent.
print(f"Per-event MACs: {'ALL VALID ✓' if all_ok else 'TAMPERING DETECTED ✗ (audit_log was wiped — expected)'}")

# --- 6. Checkpoint export (sign current state for external witness) ---
cp = ga.export_checkpoint(CKPT)
print(f"\nCheckpoint exported  seq={cp['seq']}  root={cp['root'][:16]}...")

result = ga.verify_checkpoint(cp)
print(f"Checkpoint valid: {result['valid']} — {result['details']}")

# --- Cleanup ---
ga.close()
for f in (DB, EVOLVE, CKPT):
    if os.path.exists(f):
        os.remove(f)
