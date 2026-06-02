"""
V8 Throughput Benchmark: write + recovery speed for varying payload sizes.
Uses FileCarrier (real file I/O) and native SQLite GhostAuditV7.
"""
import os, sys, time, uuid, hashlib, hmac, struct

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'tests'))

from core.ghost_audit_v7 import GhostAuditV7, StegoEngine
try:
    from hardware_resilience_test import FileCarrierGhostAuditV7, _cleanup
except ImportError:
    FileCarrierGhostAuditV7 = None

PAYLOADS = {
    "tiny (5B)":      "A" * 5,
    "small (50B)":    "B" * 50,
    "medium (200B)":  "C" * 200,
    "large (500B)":   "D" * 500,
    "xlarge (1KB)":   "E" * 1024,
}
EVENT_COUNT = 10

def bench_filecarrier():
    """FileCarrier: real binary file I/O per carrier row."""
    if FileCarrierGhostAuditV7 is None:
        return {}
    results = {}
    for label, payload in PAYLOADS.items():
        db = f"bw_fc_{uuid.uuid4().hex[:6]}.db"
        car = f"bw_fc_{uuid.uuid4().hex[:6]}.bin"
        try:
            g = FileCarrierGhostAuditV7(db, car, verbose=False)
            g.log_event("WARMUP")

            writes = []
            for i in range(EVENT_COUNT):
                t0 = time.perf_counter()
                g.log_event(f"{payload}_{i}")
                writes.append(time.perf_counter() - t0)

            t0 = time.perf_counter()
            recovered = g.recover_events()
            rec_time = time.perf_counter() - t0

            ok = sum(1 for _, m in recovered if "[TAMPERING" not in str(m))
            g.close()

            w_avg = sum(writes) / len(writes) * 1000
            w_min = min(writes) * 1000
            w_max = max(writes) * 1000
            rec_ms = rec_time * 1000
            results[label] = {
                "write_avg_ms": round(w_avg, 1),
                "write_min_ms": round(w_min, 1),
                "write_max_ms": round(w_max, 1),
                "recovery_ms": round(rec_ms, 1),
                "ok": ok,
                "total": len(recovered),
            }
        finally:
            _cleanup(db, car)
    return results

def bench_native_sqlite():
    """Native SQLite GhostAuditV7 (no file I/O — carrier in DB columns)."""
    results = {}
    stable_key = "benchmark-key-stable-001"
    for label, payload in PAYLOADS.items():
        db = f"bw_sql_{uuid.uuid4().hex[:6]}.db"
        try:
            g = GhostAuditV7(db_path=db, secret_key=stable_key, verbose=False)
            g.log_event("WARMUP")

            writes = []
            for i in range(EVENT_COUNT):
                t0 = time.perf_counter()
                g.log_event(f"{payload}_{i}")
                writes.append(time.perf_counter() - t0)

            t0 = time.perf_counter()
            recovered = g.recover_events()
            rec_time = time.perf_counter() - t0

            ok = sum(1 for _, m in recovered if "[TAMPERING" not in str(m))
            g.close()

            w_avg = sum(writes) / len(writes) * 1000
            w_min = min(writes) * 1000
            w_max = max(writes) * 1000
            rec_ms = rec_time * 1000
            results[label] = {
                "write_avg_ms": round(w_avg, 1),
                "write_min_ms": round(w_min, 1),
                "write_max_ms": round(w_max, 1),
                "recovery_ms": round(rec_ms, 1),
                "ok": ok,
                "total": len(recovered),
            }
        finally:
            _cleanup(db)
    return results

def bench_batch_vs_sequential():
    """Compare batch log_events vs sequential log_event."""
    msgs = [f'E{i:04d}_' + 'x' * 100 for i in range(10)]
    results = {}
    for label, use_batch in [('FileCarrier seq', False), ('FileCarrier batch', True),
                              ('SQLite seq', False), ('SQLite batch', True)]:
        db = f"bb_{uuid.uuid4().hex[:6]}.db"
        car = f"bb_{uuid.uuid4().hex[:6]}.bin" if 'FileCarrier' in label else None
        try:
            kw = dict(secret_key='bench-batch', verbose=False)
            if 'FileCarrier' in label:
                g = FileCarrierGhostAuditV7(db, car, **kw)
            else:
                g = GhostAuditV7(db_path=db, **kw)
            t0 = time.perf_counter()
            if use_batch:
                g.log_events(msgs)
            else:
                for m in msgs:
                    g.log_event(m)
            write_t = time.perf_counter() - t0
            r = g.recover_events()
            rec_t = time.perf_counter() - t0 - write_t
            g.close()
            ok = sum(1 for _, m in r if '[TAMPERING' not in str(m))
            results[label] = {
                "write_ms": round(write_t * 1000, 1),
                "write_per_ev_ms": round(write_t / len(msgs) * 1000, 1),
                "recovery_ms": round(rec_t * 1000, 1),
                "ok": ok, "total": len(r),
            }
        finally:
            _cleanup(db) if car is None else _cleanup(db, car)
    return results

def bench_hot_second_write():
    """Measure second write to same instance (already seeded, tables exist)."""
    db = f"bw_hot_{uuid.uuid4().hex[:6]}.db"
    car = None
    try:
        if FileCarrierGhostAuditV7:
            car = f"bw_hot_{uuid.uuid4().hex[:6]}.bin"
            g = FileCarrierGhostAuditV7(db, car, verbose=False)
        else:
            g = GhostAuditV7(db_path=db, secret_key="bench-hot", verbose=False)
        g.log_event("COLD_START")

        # Measure 10 sequential writes
        times = []
        for i in range(10):
            t0 = time.perf_counter()
            g.log_event(f"HOT_{i}")
            times.append(time.perf_counter() - t0)

        avg = sum(times) / len(times) * 1000
        g.close()
        return {
            "cold_write_ms": round(times[0] * 1000, 1) if times else 0,
            "hot_avg_ms": round(avg, 1),
            "hot_min_ms": round(min(times) * 1000, 1),
            "hot_max_ms": round(max(times) * 1000, 1),
        }
    finally:
        _cleanup(db) if car is None else _cleanup(db, car)


if __name__ == "__main__":
    print("=" * 70)
    print("V8 THROUGHPUT BENCHMARK")
    print("=" * 70)

    print("\n--- FileCarrier (real I/O) ---")
    fc = bench_filecarrier()
    for label, r in fc.items():
        print(f"  {label:20s}  write={r['write_avg_ms']:7.1f}ms "
              f"(min={r['write_min_ms']:.1f} max={r['write_max_ms']:.1f})  "
              f"recovery={r['recovery_ms']:8.1f}ms  "
              f"events={r['ok']}/{r['total']}")

    print("\n--- Native SQLite ---")
    sql = bench_native_sqlite()
    for label, r in sql.items():
        print(f"  {label:20s}  write={r['write_avg_ms']:7.1f}ms "
              f"(min={r['write_min_ms']:.1f} max={r['write_max_ms']:.1f})  "
              f"recovery={r['recovery_ms']:8.1f}ms  "
              f"events={r['ok']}/{r['total']}")

    print("\n--- Hot Write (sequential writes, same instance) ---")
    hot = bench_hot_second_write()
    if hot:
        print(f"  FileCarrier cold: {hot['cold_write_ms']:.1f}ms  "
              f"hot avg: {hot['hot_avg_ms']:.1f}ms  "
              f"(min={hot['hot_min_ms']:.1f} max={hot['hot_max_ms']:.1f})")

    print("\n--- Batch vs Sequential (10 events, 100B) ---")
    batch = bench_batch_vs_sequential()
    for label, r in batch.items():
        print(f"  {label:22s} write={r['write_ms']:7.1f}ms ({r['write_per_ev_ms']:5.1f}ms/ev)  "
              f"rec={r['recovery_ms']:7.1f}ms  ok={r['ok']}/{r['total']}")

    print("\ndone")
