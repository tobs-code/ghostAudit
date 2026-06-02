"""Debug script: test TRIM degradation recovery with verbose output."""
import sys, tempfile, os, sqlite3
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.ghost_audit_v7 import GhostAuditV7

with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
    db = f.name

ga = GhostAuditV7(db_path=db, secret_key='test-key', verbose=False)
ga.log_event('TEST EVENT: system is currently active and working')
ga.close()

# Apply TRIM
conn = sqlite3.connect(db)
cur = conn.cursor()
cur.execute('UPDATE sys_cache_write_gate SET allow_write=1 WHERE id=1')
conn.commit()
cur.execute('SELECT id, bio FROM sys_cache')
rows = cur.fetchall()
trim_count = sum(1 for _, bio in rows if bio and bio != bio.rstrip())
for rid, bio in rows:
    if bio and bio != bio.rstrip():
        cur.execute('UPDATE sys_cache SET bio=? WHERE id=?', (bio.rstrip(), rid))
cur.execute('UPDATE sys_cache_write_gate SET allow_write=0 WHERE id=1')
conn.commit()
conn.close()
print(f'Trimmed {trim_count}/{len(rows)} rows')

ga2 = GhostAuditV7(db_path=db, secret_key='test-key', verbose=True)
events = list(ga2.recover_events())
ga2.close()
print('Events:', events[:3])
os.unlink(db)
