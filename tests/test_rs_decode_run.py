import pytest
pytest.skip("Debug script, not a test suite", allow_module_level=True)

from core.ghost_audit_v7 import GhostAuditV7
from reedsolo import RSCodec
import os, binascii

DB='test_rs_v7.db'
for f in [DB, DB.replace('.db', '.evolve'), DB.replace('.db', '.evolve.tmp')]:
    if os.path.exists(f):
        os.remove(f)

ghost = GhostAuditV7(db_path=DB, verbose=False)
msg='Roundtrip test message'
ghost.log_event(msg)
cur=ghost.conn.cursor()
# read header bits
orig_ids=ghost._orig_ids
slot_ids=orig_ids[:ghost.SLOT_SIZE]
header_ids=slot_ids[:ghost.HEADER_BIT_COUNT]
h_bits=[ghost._decode_header_bit(rid, *cur.execute(f"SELECT bio, trust_score FROM {ghost.AUX_TABLE} WHERE id=?", (rid,)).fetchone()) if cur.execute(f"SELECT bio, trust_score FROM {ghost.AUX_TABLE} WHERE id=?", (rid,)).fetchone() else 0 for rid in header_ids]
# The above is messy; instead reuse header decode from earlier script
h_bits=[]
for rid in header_ids:
    cur.execute(f"SELECT bio, trust_score FROM {ghost.AUX_TABLE} WHERE id=?", (rid,))
    res=cur.fetchone()
    if res:
        h_bits.append(ghost._decode_header_bit(rid, res[0], res[1]))
    else:
        h_bits.append(0)
header=ghost._decode_header(h_bits, 0)
print('header', header)
nsym=header['nsym']
encoded_counts = ghost._per_channel_rs_encoded_bit_count(header['payload_len'], nsym)
print('encoded_counts', encoded_counts)
all_payload_ids = slot_ids[ghost.HEADER_BIT_COUNT:]
for c in range(ghost.CHANNEL_COUNT):
    ch_bytes, erasures = ghost._extract_channel_encoded_bits_v7(cur, c, all_payload_ids, encoded_counts[c])
    print('channel',c,'len',len(ch_bytes),'erasures',erasures,'hex',binascii.hexlify(ch_bytes[:64]))
    try:
        dec = RSCodec(nsym).decode(ch_bytes, erase_pos=erasures)
        print('decoded ok', len(dec[0]) if isinstance(dec, tuple) else len(dec))
    except Exception as e:
        print('decode error', e)

ghost.close()
for f in [DB, DB.replace('.db', '.evolve'), DB.replace('.db', '.evolve.tmp')]:
    if os.path.exists(f):
        os.remove(f)
