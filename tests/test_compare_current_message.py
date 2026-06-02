from core.ghost_audit_v7 import GhostAuditV7
from reedsolo import RSCodec
import os, binascii

DB='test_compare_curr.db'
if os.path.exists(DB):
    os.remove(DB)

ghost = GhostAuditV7(db_path=DB, verbose=False)
msg='Roundtrip test message'
ghost.log_event(msg)
cur=ghost.conn.cursor()
orig_ids=ghost._orig_ids
slot_ids=orig_ids[:ghost.SLOT_SIZE]
header_ids=slot_ids[:ghost.HEADER_BIT_COUNT]

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
enc_counts = ghost._per_channel_rs_encoded_bit_count(header['payload_len'], nsym)
print('enc_counts', enc_counts)
all_payload_ids = slot_ids[ghost.HEADER_BIT_COUNT:]
extracted = {}
for c in range(ghost.CHANNEL_COUNT):
    ch_bytes, erasures = ghost._extract_channel_encoded_bits_v7(cur, c, all_payload_ids, enc_counts[c])
    extracted[c] = ch_bytes
    print('extracted',c,len(ch_bytes),binascii.hexlify(ch_bytes[:64]))

# Re-encode payload
cur.execute('SELECT stored_msg, mac FROM audit_log ORDER BY sequence_number DESC LIMIT 1')
row = cur.fetchone()
stored_msg, mac = row[0], row[1]
payload = mac + stored_msg
channel_blocks = ghost._encode_payload_per_channel_v7(payload, nsym)
for c in range(ghost.CHANNEL_COUNT):
    print('encoded',c,len(channel_blocks[c]),binascii.hexlify(channel_blocks[c][:64]))
    # compare full
    print('full equal?', channel_blocks[c] == extracted[c])

# Try RS decode on extracted
for c in range(ghost.CHANNEL_COUNT):
    try:
        dec = RSCodec(nsym).decode(extracted[c])
        print('RS decode success for channel', c, 'len out', len(dec[0]) if isinstance(dec, tuple) else len(dec))
    except Exception as e:
        print('RS decode error for channel', c, e)


ghost.close()
if os.path.exists(DB):
    os.remove(DB)
