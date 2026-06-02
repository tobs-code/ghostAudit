from core.ghost_audit_v7 import GhostAuditV7
import os, binascii, json

DB='test_diag_v7.db'
if os.path.exists(DB):
    os.remove(DB)

ghost = GhostAuditV7(db_path=DB, verbose=False)
print('[diag] GhostAuditV7 initialized')

ghost.log_event('Diagnostic message for V7')
print('[diag] Logged event')

cur=ghost.conn.cursor()
cur.execute(f"SELECT COUNT(*) FROM {ghost.AUX_TABLE}")
print('[diag] sys_cache rows:', cur.fetchone()[0])

orig_ids = ghost._orig_ids
print('[diag] orig_ids len', len(orig_ids))

slot_start = 0
slot_ids = orig_ids[slot_start:slot_start+ghost.SLOT_SIZE]
header_ids = slot_ids[:ghost.HEADER_BIT_COUNT]
print('[diag] HEADER BIT COUNT', ghost.HEADER_BIT_COUNT)

h_bits=[]
rows=[]
print('\n[diag] Sample header rows (first 12):')
for rid in header_ids[:12]:
    cur.execute(f"SELECT bio, trust_score FROM {ghost.AUX_TABLE} WHERE id=?", (rid,))
    res=cur.fetchone()
    bio = res[0] if res else None
    trust = res[1] if res else None
    ok = ghost._verify_sys_cache_row(rid, bio, trust) if res else False
    try:
        bit = ghost._decode_header_bit(rid, bio, trust) if res else None
    except Exception as e:
        bit = f'ERR:{e}'
    try:
        logical = ghost._decode_all_columns_shuffled(rid, bio, trust) if res else None
    except Exception as e:
        logical = f'ERR:{e}'
    print('id', rid, 'bio_len', len(bio) if bio else None, 'trust', trust, 'verify', ok)
    print(' header_bit:', bit)
    print(' logical:', logical)
    print('---')
    h_bits.append(bit if isinstance(bit, int) else 0)
    rows.append({'id': rid, 'bio': bio[:120] if bio else None, 'trust': trust, 'verify': ok, 'header_bit': bit, 'logical': logical})

print('\n[diag] Header bits sample (first 64):')
print(h_bits[:64])
print('[diag] Decoded header:', ghost._decode_header(h_bits, 0))

# Try extracting small number of bits for channel 0
print('\n[diag] Extract channel 0 small test')
ch_bytes, erasures = ghost._extract_channel_encoded_bits_v7(cur, 0, slot_ids[ghost.HEADER_BIT_COUNT:], 64)
print('[diag] ch_bytes len', len(ch_bytes), 'erasures', erasures)
print('[diag] ch_bytes hex', binascii.hexlify(ch_bytes[:16]) if ch_bytes else b'')

# RS decode attempt
try:
    dec = ghost.rs_codecs[0].decode(ch_bytes)
    print('[diag] RS decode ok, len', len(dec[0]) if isinstance(dec, tuple) else len(dec))
except Exception as e:
    print('[diag] RS decode error:', e)

# Save diagnostic snapshot
with open('diag_snapshot.json','w',encoding='utf-8') as f:
    json.dump({'rows': rows, 'h_bits': h_bits[:128]}, f, indent=2)

print('\n[diag] Wrote diag_snapshot.json')

ghost.close()
if os.path.exists(DB):
    os.remove(DB)
print('[diag] done')
