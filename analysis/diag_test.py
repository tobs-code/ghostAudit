import sqlite3, random, os, hmac, hashlib, struct, zlib
from core.ghost_audit_v6 import GhostAuditV6
from reedsolo import RSCodec, ReedSolomonError

db = "diag_erasure.db"
if os.path.exists(db):
    os.remove(db)

ga = GhostAuditV6(db_path=db, secret_key="diag-key", verbose=False)
ga.log_event("DIAG_ERASURE_TEST_EVENT")
ga.close()

ga = GhostAuditV6(db_path=db, secret_key="diag-key", verbose=False)
slot_ids = ga._orig_ids[0 : ga.SLOT_SIZE]
header_ids = slot_ids[: ga.HEADER_BIT_COUNT]
payload_ids = slot_ids[ga.HEADER_BIT_COUNT :]
print("Slot rows:", ga.SLOT_SIZE, "Header:", len(header_ids), "Payload:", len(payload_ids))

conn = sqlite3.connect(db)
cur = conn.cursor()
# Bypass the write gate
cur.execute("DROP TRIGGER IF EXISTS sys_cache_guard_update")
cur.execute("DROP TRIGGER IF EXISTS sys_cache_guard_insert")
cur.execute("DROP TRIGGER IF EXISTS sys_cache_guard_delete")
cur.execute("UPDATE sys_cache_write_gate SET allow_write=1 WHERE id=1")
conn.commit()

h_bits = []
for rid in header_ids:
    cur.execute("SELECT bio, trust_score FROM sys_cache WHERE id=?", (rid,))
    res = cur.fetchone()
    if res and res[0] is not None and res[1] is not None:
        h_bits.append(ga._decode_header_bit(res[0], res[1]))
    else:
        h_bits.append(0)

hdr = ga._decode_header(h_bits, 0)
print("Header: magic=0x%02x mode=%s seq=%d payload_len=%d nsym=%d" % (
    hdr["magic"], hdr["mode"], hdr["sequence_number"],
    hdr["payload_len"], hdr["nsym"]))
total_bytes = 16 + hdr["payload_len"] + hdr["nsym"]
print("Total payload bytes:", total_bytes)

# 5% deletion
del_count = max(1, int(len(payload_ids) * 0.05))
to_delete = random.sample(payload_ids, del_count)
for rid in to_delete:
    cur.execute("DELETE FROM sys_cache WHERE id=?", (rid,))
cur.execute("DELETE FROM audit_log")
cur.execute("DELETE FROM audit_archive")
conn.commit()
conn.close()

ga2 = GhostAuditV6(db_path=db, secret_key="diag-key", verbose=False)
rec = ga2.recover_logs()
ga2.close()
print("Recovered (5%% deletion, %d rows removed): %s" % (del_count, rec))

if os.path.exists(db):
    os.remove(db)
