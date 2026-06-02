"""
MUX Row-Wipe Sweep: uniform-random vs. clustered deletion.
Tests 5/10/15/20% row deletion against V8 recovery.
v2: only payload rows (skip headers), no blanket manifest delete.
"""
import sys, os, json, shutil
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import sqlite3, random
from core.ghost_audit_v7 import GhostAuditV7

DB = "ghost_audit_v8_wipe_sweep.db"
BL = "ghost_audit_v8_wipe_sweep_baseline.db"
KEY = "sweep-key-v8-1234567890"


def _cleanup(path):
    for s in ("", "-wal", "-shm", "-journal"):
        try:
            os.remove(path + s)
        except OSError:
            pass


def _raw(db):
    raw = sqlite3.connect(db)
    for t in ("sys_cache_guard_update", "sys_cache_guard_insert",
              "sys_cache_guard_delete", "sys_cache_block_null_bio",
              "sys_cache_block_null_score"):
        raw.execute(f"DROP TRIGGER IF EXISTS {t}")
    raw.execute("UPDATE sys_cache_write_gate SET allow_write=1 WHERE id=1")
    raw.commit()
    return raw


def setup():
    _cleanup(DB)
    _cleanup(BL)
    ga = GhostAuditV7(db_path=DB, secret_key=KEY, verbose=False)
    ga.log_event("EVENT_1: System startup complete")
    ga.log_event("EVENT_2: User admin logged in")
    ga.log_event("EVENT_3: Backup job finished")
    ga.close()
    shutil.copyfile(DB, BL)


def get_payload_ids():
    ga = GhostAuditV7(db_path=DB, secret_key=KEY, verbose=False)
    payload = []
    for k in range(ga.SLOT_COUNT):
        s = k * ga.SLOT_SIZE
        slot = ga._orig_ids[s : s + ga.SLOT_SIZE]
        payload.extend(slot[ga.HEADER_BIT_COUNT:])
    ga.close()
    return payload


def wipe_and_recover(fraction, clustered=False):
    _cleanup(DB)
    shutil.copyfile(BL, DB)

    payload_ids = get_payload_ids()
    n = max(1, int(len(payload_ids) * fraction))
    if clustered:
        targets = payload_ids[:n]
    else:
        targets = random.sample(payload_ids, n)

    raw = _raw(DB)
    for rid in targets:
        raw.execute("DELETE FROM sys_cache WHERE id=?", (rid,))
        raw.execute("DELETE FROM sys_cache_manifest WHERE id=?", (rid,))
    raw.commit()
    raw.close()

    ga2 = GhostAuditV7(db_path=DB, secret_key=KEY, verbose=False)
    conn3 = sqlite3.connect(DB)
    conn3.execute("DELETE FROM audit_log")
    conn3.execute("DELETE FROM audit_archive")
    conn3.execute("DELETE FROM event_mac_tags")
    conn3.commit()
    conn3.close()
    try:
        recovered = ga2.recover_events()
    except Exception as e:
        ga2.close()
        return {"status": "exception", "error": str(e), "total": 0, "valid": 0}
    ga2.close()

    if not recovered:
        return {"status": "lost", "total": 0, "valid": 0}

    tampered = sum(1 for e in recovered if "[TAMPERING DETECTED]" in str(e))
    valid = len(recovered) - tampered
    return {"status": "ok", "total": len(recovered), "valid": valid, "tampered": tampered}


def main():
    print("=" * 65)
    print("MUX Row-Wipe Sweep v2 — Payload rows only, no blanket manifest delete")
    print("=" * 65)
    setup()

    results = []
    for mode, clustered in [("uniform", False), ("clustered", True)]:
        print(f"\n--- Mode: {mode} (payload-only, manifest per-row) ---")
        for pct in [5, 10, 15, 20]:
            r = wipe_and_recover(pct / 100, clustered=clustered)
            label = "RECOVERED" if r["valid"] == 3 else ("LOST" if r["valid"] == 0 else "PARTIAL")
            print(f"  {pct:>2}% wipe → {r['valid']}/3 events valid ({label})"
                  f"  total={r['total']} tampered={r.get('tampered',0)}"
                  + (f" [{r.get('error','')}]" if r.get("error") else ""))
            results.append({"mode": mode, "pct": pct, **r})

    print("\n" + "=" * 65)
    print("Summary")
    print("=" * 65)
    for r in results:
        label = "✅" if r["valid"] == 3 else ("❌" if r["valid"] == 0 else "⚠️")
        print(f"  {label} {r['mode']:>10} {r['pct']:>2}% → {r['valid']}/3 valid  ({r['total']} total)")
    print()

    with open("sweep_wipe_v8_results.json", "w") as f:
        json.dump(results, f, indent=2)

    _cleanup(DB)
    _cleanup(BL)


if __name__ == "__main__":
    main()
