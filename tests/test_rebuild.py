from core.ghost_audit_v7 import GhostAuditV7
from reedsolo import RSCodec
import os, binascii, hmac, hashlib, zlib

DB='test_rebuild_v7.db'
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
all_payload_ids = slot_ids[ghost.HEADER_BIT_COUNT:]
channel_plain = {}
for c in range(ghost.CHANNEL_COUNT):
    ch_bytes, erasures = ghost._extract_channel_encoded_bits_v7(cur, c, all_payload_ids, enc_counts[c])
    try:
        dec = RSCodec(nsym).decode(ch_bytes, erase_pos=erasures)
        decoded = dec[0] if isinstance(dec, tuple) else dec
        channel_plain[c] = decoded
        print('decoded channel',c,len(decoded))
    except Exception as e:
        print('rs decode error', c, e)

# Try to rebuild payload
stored_msg_len = header['payload_len']
print('trying rebuild with stored_msg_len', stored_msg_len)
payload = ghost._rebuild_payload_from_channel_bytes(channel_plain, stored_msg_len)
print('payload len', len(payload) if payload else None)
if payload:
    recovered_mac = payload[:16]
    recovered_msg = payload[16:]
    expected_mac = hmac.new(ghost.k_hmac, recovered_msg, hashlib.sha256).digest()[:16]
    print('recovered_mac', recovered_mac.hex())
    print('expected_mac', expected_mac.hex())
    print('mac match', hmac.compare_digest(recovered_mac, expected_mac))
    try:
        print('message:', (zlib.decompress(recovered_msg) if header['compressed'] else recovered_msg).decode('utf-8'))
    except Exception as e:
        print('decompress/decoding error', e)


ghost.close()
if os.path.exists(DB):
    os.remove(DB)
