import os, sys, random, uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.ghost_audit_v7 import GhostAuditV7


def run_sweep(erasure_rate, n_events, msg, trials=5):
    ok = 0
    for t in range(trials):
        db = f"t_{uuid.uuid4().hex[:6]}.db"
        try:
            g = GhostAuditV7(db_path=db, verbose=False)
            for e in range(n_events):
                g.log_event(msg)
            cursor = g.conn.cursor()
            ids = g._all_payload_ids()
            nd = int(len(ids) * erasure_rate)
            g._set_sys_cache_write_mode(True)
            try:
                delete_ids = random.sample(ids, nd)
                cursor.executemany(
                    "DELETE FROM sys_cache WHERE id=?", [(rid,) for rid in delete_ids]
                )
                cursor.executemany(
                    "DELETE FROM sys_cache_manifest WHERE id=?",
                    [(rid,) for rid in delete_ids],
                )
                g.conn.commit()
            finally:
                g._set_sys_cache_write_mode(False)
            r = g.recover_events()
            recovered = sum(1 for _, m in r if m == msg)
            if recovered == n_events:
                ok += 1
            g.close()
        finally:
            if os.path.exists(db):
                try:
                    os.remove(db)
                except PermissionError:
                    pass
    return ok / trials * 100


if __name__ == "__main__":
    print("=== 1 Event (3 Replicas), short msg 'T0' ===")
    for rate in [10, 20, 30, 40, 50, 60, 70, 80]:
        p = run_sweep(rate / 100, 1, "T0", 3)
        print(f"  {rate}% erasure: {p:.0f}% recovery")

    print("\n=== 3 Events (1-3 Replicas), 'T0' ===")
    for rate in [10, 15, 20, 25, 30]:
        p = run_sweep(rate / 100, 3, "T0", 3)
        print(f"  {rate}% erasure: {p:.0f}% recovery")

    print("\n=== 1 Event, longer msg 'Hello World 123' ===")
    for rate in [10, 20, 30, 40]:
        p = run_sweep(rate / 100, 1, "Hello World 123", 3)
        print(f"  {rate}% erasure: {p:.0f}% recovery")

    print("\ndone")
