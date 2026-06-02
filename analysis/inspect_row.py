from core.ghost_audit_v7 import GhostAuditV7
import os

DB='test_inspect_row_v7.db'
if os.path.exists(DB):
    os.remove(DB)

ghost = GhostAuditV7(db_path=DB, verbose=False)
ghost.log_event('Row inspect')
cur = ghost.conn.cursor()
# pick rid 7 from slot 0 header
rid=7
cur.execute(f"SELECT bio, trust_score FROM {ghost.AUX_TABLE} WHERE id=?", (rid,))
res=cur.fetchone()
print('rid', rid, res)
from core.ghost_audit_v7 import StegoEngine
print('decode_case', StegoEngine.decode_bit_case(res[0]) if res and res[0] else None)
print('decode_trailing', StegoEngine.decode_bit_trailing_space(res[0]) if res and res[0] else None)
print('decode_float', StegoEngine.decode_bit_float_lsb(res[1]) if res and res[1] else None)
print('decode_header_bit', ghost._decode_header_bit(rid, res[0], res[1]))

ghost.close()
if os.path.exists(DB):
    os.remove(DB)
