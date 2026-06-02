from core.ghost_audit_v7 import GhostAuditV7
from reedsolo import RSCodec
import os, binascii, json

DB='test_diag_full_v7.db'
if os.path.exists(DB):
    os.remove(DB)

ghost = GhostAuditV7(db_path=DB, verbose=False)
ghost.log_event('Diagnostic full header message')
cur=ghost.conn.cursor()
orig_ids = ghost._orig_ids
slot_start = 0
slot_ids = orig_ids[slot_start:slot_start+ghost.SLOT_SIZE]
header_ids = slot_ids[:ghost.HEADER_BIT_COUNT]

h_bits_full = []
for rid in header_ids:
    cur.execute(f"SELECT bio, trust_score FROM {ghost.AUX_TABLE} WHERE id=?", (rid,))
    res = cur.fetchone()
    if res:
        bit = ghost._decode_header_bit(rid, res[0], res[1])
    else:
        bit = 0
    h_bits_full.append(bit)

print('[diag-full] Collected header bits:', len(h_bits_full))
print(h_bits_full[:32])

# Reconstruct raw bytes from header bits (debug)
bytes_data = bytearray()
for i in range(0, len(h_bits_full), 8):
    bits_str = ''.join(map(str, h_bits_full[i:i+8]))
    bytes_data.append(int(bits_str, 2))
print('[diag-full] header bytes hex:', binascii.hexlify(bytes_data))
# Also show reversed-bit-order per byte (LSB-first vs MSB-first)
bytes_data_rev = bytearray()
for i in range(0, len(h_bits_full), 8):
    bits_str = ''.join(map(str, h_bits_full[i:i+8]))
    bits_rev = bits_str[::-1]
    bytes_data_rev.append(int(bits_rev, 2))
print('[diag-full] header bytes hex (reversed bits per byte):', binascii.hexlify(bytes_data_rev))
header_data = ghost._decode_header(h_bits_full, 0)
print('[diag-full] Decoded header:', header_data)

if header_data:
    nsym = header_data['nsym']
    plen = header_data['payload_len']
    print('[diag-full] nsym', nsym, 'payload_len', plen)
    enc_counts = ghost._per_channel_rs_encoded_bit_count(plen, nsym)
    print('[diag-full] encoded bit counts (per channel):', enc_counts)
    all_payload_ids = slot_ids[ghost.HEADER_BIT_COUNT:]
    for c in range(ghost.CHANNEL_COUNT):
        ch_bytes, erasures = ghost._extract_channel_encoded_bits_v7(cur, c, all_payload_ids, enc_counts[c])
        print(f'[diag-full] channel {c} bytes len', len(ch_bytes), 'erasures', erasures)
        if ch_bytes:
            print('  hex', binascii.hexlify(ch_bytes[:32]))
            try:
                dec = RSCodec(nsym).decode(ch_bytes, erase_pos=erasures)
                print('  RS decode ok, decoded len', len(dec[0]) if isinstance(dec, tuple) else len(dec))
            except Exception as e:
                print('  RS decode error', e)

# Save snapshot
with open('diag_full_snapshot.json','w') as f:
    json.dump({'header_bits_len': len(h_bits_full), 'header_data': header_data}, f)

print('[diag-full] done')

# Compare candidate header bytes from audit_log
cur.execute('SELECT sequence_number, stored_msg, compressed FROM audit_log ORDER BY sequence_number DESC LIMIT 1')
row = cur.fetchone()
if row:
    seq, stored_msg, compressed = row[0], row[1], row[2]
    stored_len = len(stored_msg) if stored_msg else 0
    print('[diag-full] audit_log entry: seq=', seq, 'stored_len=', stored_len, 'compressed=', compressed)
    for ns in [1,2,4,8,16,32]:
        try:
            candidate = ghost._build_legacy_header(stored_len, ns, seq, bool(compressed))
            print('[diag-full] candidate nsym', ns, 'hex', binascii.hexlify(candidate))
        except Exception as e:
            print(' candidate build error', e)

ghost.close()
if os.path.exists(DB):
    os.remove(DB)

