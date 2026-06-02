import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.ghost_audit_v7 import GhostAuditV7, StegoEngine
from reedsolo import RSCodec, ReedSolomonError
import hmac, hashlib, zlib

DB='test_parity_v7.db'
if os.path.exists(DB):
    os.remove(DB)
# Remove stale external state file so V8.3 rollback-detection doesn't fire
_evolve = DB + ".evolve"
if os.path.exists(_evolve):
    os.remove(_evolve)

# Write a message, then verify the full recovery pipeline works
ghost = GhostAuditV7(db_path=DB, verbose=False)
msg='Parity recovery test message'
ghost.log_event(msg)
ghost.close()

# Full recovery
ghost2 = GhostAuditV7(db_path=DB, verbose=False)
recovered = ghost2.recover_events()
ghost2.close()

assert len(recovered) == 1, f'Expected 1 event, got {len(recovered)}'
seq, msg_out = recovered[0]
assert 'TAMPERING' not in str(msg_out), f'Event was tampered: {msg_out}'
assert msg_out == msg, f'Message mismatch: {msg_out!r} != {msg!r}'
print(f'OK: recovered message = {msg_out!r}')
print('PASS: full recovery pipeline works with RAID-6')

if os.path.exists(DB):
    os.remove(DB)
