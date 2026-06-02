import sqlite3, random, os, hmac, hashlib, struct, zlib
from core.ghost_audit_v6 import GhostAuditV6
from reedsolo import RSCodec, ReedSolomonError

def run_erasure_test(db, secret_key, del_pct, label):
    """Test recovery after X% payload-row deletions (with fresh manifest before deletion)."""
    if os.path.exists(db):
        os.remove(db)

    ga = GhostAuditV6(db_path=db, secret_key=secret_key, verbose=False)
    ga.log_event("ERASURE_DIAG")
    ga._set_sys_cache_write_mode(True)

    # Get payload ids for slot 0
    orig_ids = ga._orig_ids
    slot0_start = 0 * ga.SLOT_SIZE
    slot0_ids = orig_ids[slot0_start : slot0_start + ga.SLOT_SIZE]
    payload_ids = slot0_ids[ga.HEADER_BIT_COUNT:]

    # Header info for reference
    header_ids = slot0_ids[:ga.HEADER_BIT_COUNT]
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    h_bits = []
    for rid in header_ids:
        cur.execute("SELECT bio, trust_score FROM sys_cache WHERE id=?", (rid,))
        res = cur.fetchone()
        if res and res[0] is not None and res[1] is not None:
            h_bits.append(ga._decode_header_bit(res[0], res[1]))
        else:
            h_bits.append(0)
    hdr = ga._decode_header(h_bits, 0)
    total_payload_bytes = 16 + hdr["payload_len"] + hdr["nsym"]
    print("[%s] Total payload bytes: %d, payload rows: %d" % (label, total_payload_bytes, len(payload_ids)))

    # Rebuild manifest NOW (before deletion) so manifest reflects current state
    for rid, bio, score in cur.execute(
        "SELECT id, bio, trust_score FROM sys_cache ORDER BY id"
    ).fetchall():
        if bio is None or score is None:
            continue
        payload = struct.pack(">I", rid) + bio.encode("utf-8") + b"\x00" + struct.pack(">d", float(score))
        row_mac = hmac.new(ga.k_hmac, payload, hashlib.sha256).digest()
        cur.execute("INSERT OR REPLACE INTO sys_cache_manifest (id, row_mac) VALUES (?, ?)", (rid, row_mac))
    conn.commit()

    # Now delete
    del_count = max(1, int(len(payload_ids) * del_pct / 100))
    to_kill = random.sample(payload_ids, del_count)
    for rid in to_kill:
        cur.execute("DELETE FROM sys_cache WHERE id=?", (rid,))
    cur.execute("DELETE FROM audit_log")
    cur.execute("DELETE FROM audit_archive")
    conn.commit()
    conn.close()
    ga._set_sys_cache_write_mode(False)
    ga.close()

    # Recover
    ga2 = GhostAuditV6(db_path=db, secret_key=secret_key, verbose=False)

    # Write what happens internally
    cursor = ga2.conn.cursor()

    # Read bits for ALL slots
    slot_debug = []
    for k in range(ga2.SLOT_COUNT):
        slot_start = k * ga2.SLOT_SIZE
        slot_ids2 = ga2._orig_ids[slot_start : slot_start + ga2.SLOT_SIZE]
        header_ids2 = slot_ids2[:ga2.HEADER_BIT_COUNT]
        hb = []
        slot_t = False
        for rid in header_ids2:
            cursor.execute("SELECT bio, trust_score FROM sys_cache WHERE id=?", (rid,))
            res = cursor.fetchone()
            if res and res[0] is not None and res[1] is not None and ga2._verify_sys_cache_row(rid, res[0], res[1]):
                hb.append(ga2._decode_header_bit(res[0], res[1]))
            else:
                slot_t = True
                hb.append(0)
        hd = ga2._decode_header(hb, 0)
        if hd:
            slot_debug.append((k, hd, slot_t))

    print("[%s] Slots with valid headers: %d (mode frag=%d legacy=%d)" % (
        label, len(slot_debug),
        sum(1 for _, h, _ in slot_debug if h["mode"] == "fragment"),
        sum(1 for _, h, _ in slot_debug if h["mode"] == "legacy"),
    ))

    try:
        rec = ga2.recover_logs()
    except Exception as e:
        print("[%s] RECOVERY EXCEPTION: %s" % (label, e))
        ga2.close()
        return
    ga2.close()

    if rec:
        for idx, entry in enumerate(rec):
            flag = "TAMPERED" if "TAMPERING" in str(entry) else "OK"
            print("  [%d] [%s] %s" % (idx, flag, str(entry)[:60]))
    else:
        print("  [no entries recovered]")
    print()

db = "diag_erasure.db"
for pct in [5, 10, 20, 30]:
    run_erasure_test(db, "diag-key", pct, "ERASE%d%%" % pct)
