from core.ghost_audit_v7 import GhostAuditV7
from reedsolo import RSCodec
import os, binascii

DB='test_compare_v7.db'
if os.path.exists(DB):
    os.remove(DB)

ghost = GhostAuditV7(db_path=DB, verbose=False)
# Log event
ghost.log_event('Compare test message')
cur = ghost.conn.cursor()
# Get latest audit_log entry
cur.execute('SELECT sequence_number, stored_msg, mac, compressed FROM audit_log ORDER BY sequence_number DESC LIMIT 1')
row = cur.fetchone()
seq, stored_msg, mac, compressed = row[0], row[1], row[2], row[3]
stored_msg_bytes = stored_msg
payload = mac + stored_msg_bytes

# Find header bits and nsym
orig_ids = ghost._orig_ids
slot_ids = orig_ids[:ghost.SLOT_SIZE]
header_ids = slot_ids[:ghost.HEADER_BIT_COUNT]
h_bits = []
for rid in header_ids:
    cur.execute(f"SELECT bio, trust_score FROM {ghost.AUX_TABLE} WHERE id=?", (rid,))
    res = cur.fetchone()
    if res:
        bit = ghost._decode_header_bit(rid, res[0], res[1])
    else:
        bit = 0
    h_bits.append(bit)
header = ghost._decode_header(h_bits, 0)
print('header', header)
nsym = header['nsym'] if header else 32

# Re-encode payload using same nsym
channel_blocks = ghost._encode_payload_per_channel_v7(payload, nsym)
for c in range(ghost.CHANNEL_COUNT):
    print('encoded channel', c, len(channel_blocks[c]), binascii.hexlify(channel_blocks[c][:64]))
    try:
        dec = RSCodec(nsym).decode(channel_blocks[c])
        print(' RS decode encoded ok, out len', len(dec[0]) if isinstance(dec, tuple) else len(dec))
    except Exception as e:
        print(' RS decode encoded error', e)

# Extract from DB
all_payload_ids = slot_ids[ghost.HEADER_BIT_COUNT:]
for c in range(ghost.CHANNEL_COUNT):
    ch_bytes, erasures = ghost._extract_channel_encoded_bits_v7(cur, c, all_payload_ids, len(channel_blocks[c])*8)
    print('extracted channel', c, len(ch_bytes), 'erasures', erasures, binascii.hexlify(ch_bytes[:64]) if ch_bytes else b'')
    # Compare first 32 bytes
    print('first 32 equal?:', ch_bytes[:32] == channel_blocks[c][:32])

ghost.close()
if os.path.exists(DB):
    os.remove(DB)
