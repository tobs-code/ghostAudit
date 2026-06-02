from core.ghost_audit_v7 import GhostAuditV7
import os
DB='test_recover_v7.db'
if os.path.exists(DB):
    os.remove(DB)
# Remove stale external state file so V8.3 rollback-detection doesn't fire
_evolve = DB + ".evolve"
if os.path.exists(_evolve):
    os.remove(_evolve)

ghost = GhostAuditV7(db_path=DB, verbose=True, force_reinit=True)
ghost.log_event('Roundtrip test message')
recovered = ghost.recover_events()
print('Recovered:', recovered)
ghost.close()
if os.path.exists(DB):
    os.remove(DB)
