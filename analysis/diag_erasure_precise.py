"""
Genauer Erasure-Toleranz-Test für GhostAudit V6.
Misst: wie viele sys_cache-Zeilen können gelöscht werden, bevor Recovery fehlschlägt?
Nutzt 5 Slots = 5 Fragmente × 1528 Payload-Rows = 7640 Bit-Wiederholungen insgesamt.
"""

import sqlite3, random, os, hmac, hashlib, struct, zlib, json
from core.ghost_audit_v6 import GhostAuditV6
from reedsolo import RSCodec, ReedSolomonError


def get_all_payload_ids(ga):
    """Sammel Payload-IDs über ALLE 5 Slots."""
    ids = []
    for slot in range(ga.SLOT_COUNT):
        start = slot * ga.SLOT_SIZE
        slot_ids = ga._orig_ids[start : start + ga.SLOT_SIZE]
        ids.extend(slot_ids[ga.HEADER_BIT_COUNT:])
    return ids


def erase_and_recover(db_path, secret_key, del_pct, payload_ids, hdr_info):
    """Lösche del_pct% der Payload-IDs und versuche Recovery."""
    total = len(payload_ids)
    to_kill = random.sample(payload_ids, max(1, int(total * del_pct / 100)))

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    # Bypass gate
    cur.execute("DROP TRIGGER IF EXISTS sys_cache_guard_update")
    cur.execute("DROP TRIGGER IF EXISTS sys_cache_guard_insert")
    cur.execute("DROP TRIGGER IF EXISTS sys_cache_guard_delete")
    cur.execute("UPDATE sys_cache_write_gate SET allow_write=1 WHERE id=1")
    conn.commit()

    # Manifest neu bauen vor Löschung
    cur.execute("DELETE FROM sys_cache_manifest")
    for rid, bio, score in cur.execute(
        "SELECT id, bio, trust_score FROM sys_cache ORDER BY id"
    ).fetchall():
        if bio is None or score is None:
            continue
        payload = struct.pack(">I", rid) + bio.encode("utf-8") + b"\x00" + struct.pack(">d", float(score))
        cur.execute("INSERT OR REPLACE INTO sys_cache_manifest (id, row_mac) VALUES (?, ?)", (rid, hmac.new(hdr_info["k_hmac"], payload, hashlib.sha256).digest()))
    conn.commit()
    # Jetzt löschen
    for rid in to_kill:
        cur.execute("DELETE FROM sys_cache WHERE id=?", (rid,))
    cur.execute("DELETE FROM audit_log")
    cur.execute("DELETE FROM audit_archive")
    conn.commit()
    conn.close()

    ga2 = GhostAuditV6(db_path=db_path, secret_key=secret_key, verbose=False)
    try:
        rec = ga2.recover_logs()
        ga2.close()
        if rec is None:
            rec = []
        success = len(rec) > 0 and "TAMPERING" not in str(rec[0])
        return {"del_pct": del_pct, "success": success, "recovered": len(rec), "tampered": "TAMPERING" in str(rec) if rec else False, "entries": [str(e)[:60] for e in rec]}
    except Exception as e:
        ga2.close()
        return {"del_pct": del_pct, "success": False, "error": str(e)}


def main():
    db = "diag_erasure_precise.db"
    secret = "diag-key-precise"
    rates = [1, 5, 10, 15, 20, 25, 30]

    # ---- Setup ----
    if os.path.exists(db):
        os.remove(db)
    ga = GhostAuditV6(db_path=db, secret_key=secret, verbose=False)
    ga.log_event("ERASURE_BENCH_EVENT")
    ga.close()

    # Hole Header-Info und Payload-IDs
    ga = GhostAuditV6(db_path=db, secret_key=secret, verbose=False)
    orig_ids = ga._orig_ids
    payload_ids = get_all_payload_ids(ga)
    k_hmac = ga.k_hmac

    # Header für Seq 1 auslesen
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    hdr_info = {"k_hmac": k_hmac, "seq": 1}
    conn.close()
    ga.close()

    total_payload = len(payload_ids)
    print("Payload rows across 5 slots: %d" % total_payload)

    # ---- Teste jede Löschrate ----
    results = []
    for pct in rates:
        res = erase_and_recover(db, secret, pct, payload_ids, hdr_info)
        results.append(res)
        status = "OK" if res["success"] else "FAIL"
        print("  %3d%% deletion: [%s] recovered=%d tampered=%s" % (
            pct, status, res.get("recovered", 0), res.get("tampered", "N/A")))
        if not res["success"] and "entries" in res:
            for e in res["entries"][:3]:
                print("    entry: %s" % e)

    # Summary
    max_ok = max((r["del_pct"] for r in results if r["success"]), default=0)
    print("\nMax tolerated erasure rate: %d%%" % max_ok)

    with open("erasure_precise_results.json", "w") as f:
        json.dump({"results": results, "max_tolerated_pct": max_ok}, f, indent=2)
    print("Saved to erasure_precise_results.json")

    # Cleanup
    for suffix in ("", "-wal", "-shm"):
        try:
            if os.path.exists(db + suffix):
                os.remove(db + suffix)
        except OSError:
            pass


if __name__ == "__main__":
    main()
