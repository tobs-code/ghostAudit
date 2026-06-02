from core.ghost_audit_v7 import GhostAuditV7
import os, binascii

db='test_diag_detail_v7.db'
if os.path.exists(db):
    os.remove(db)

ghost = GhostAuditV7(db_path=db, verbose=False)
ghost.log_event('Detail inspection')
cur = ghost.conn.cursor()
slot_ids = ghost._orig_ids[:ghost.SLOT_SIZE]
header_ids = slot_ids[:ghost.HEADER_BIT_COUNT]

# reconstruct expected header bytes
cur.execute('SELECT sequence_number, stored_msg, compressed FROM audit_log ORDER BY sequence_number DESC LIMIT 1')
row = cur.fetchone()
seq, stored_msg, compressed = row[0], row[1], row[2]
stored_len = len(stored_msg)
candidate = ghost._build_legacy_header(stored_len, 2, seq, bool(compressed))
candidate_bits=[]
for b in candidate:
    candidate_bits.extend([int(x) for x in format(b,'08b')])

print('candidate bytes hex', binascii.hexlify(candidate))

for idx, rid in enumerate(header_ids[:32]):
    cur.execute(f"SELECT bio, trust_score FROM {ghost.AUX_TABLE} WHERE id=?", (rid,))
    res = cur.fetchone()
    bio = res[0]; trust = res[1]
    header_bit = ghost._decode_header_bit(rid, bio, trust)
    print('idx', idx, 'rid', rid, 'candidate_bit', candidate_bits[idx], 'header_bit', header_bit, 'bio[:80]', bio[:80].replace('\n',' '), 'ends_space', bio.endswith(' '))

ghost.close()
if os.path.exists(db):
    os.remove(db)
