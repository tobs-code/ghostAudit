from core.ghost_audit_v7 import GhostAuditV7

g = GhostAuditV7(db_path=':memory:', secret_key='test', ecc_symbols=36, verbose=False)
# test fragmentation
for max_frag in (5,3,10):
    data = b'A'*100
    frags = g._fragment_encoded_bytes(data, max_frag, max_bytes_per_fragment=12)
    print('max_frag', max_frag, 'frag_count', len(frags), [len(f) for f in frags])

# test without explicit max
frags2 = g._fragment_encoded_bytes(b'A'*100, 5)
print('frag2_count', len(frags2), [len(f) for f in frags2])
