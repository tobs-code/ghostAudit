import os
import sys
import json

def main(argv):
    # args: ecc, reps, per_channel_rs (0/1), rate, trial, out_db
    if len(argv) < 7:
        print(json.dumps({"error": "insufficient args"}))
        return 2

    ecc = argv[1]
    reps = argv[2]
    per_channel_rs = argv[3]
    rate = float(argv[4])
    trial = int(argv[5])
    out_db = argv[6]

    os.environ["GHOST_AUDIT_PER_CHANNEL_MIN_REPS"] = str(reps)
    os.environ["GHOST_AUDIT_ECC_SYMBOLS"] = str(ecc)
    os.environ["GHOST_AUDIT_PER_CHANNEL_RS"] = str(per_channel_rs)

    # Import AFTER setting env so ghost_audit_v7 picks up class-level env reads
    from resilience_benchmark_v7 import ResilienceBenchmarkV7

    bench = ResilienceBenchmarkV7(verbose=False)
    ok = bench.test_erasure_tolerance(db_path=out_db, erasure_rate=rate)
    out = bench.results["tests"]["erasure_tolerance"].copy()
    out.update({"config": {"ecc": int(ecc), "reps": int(reps), "per_channel_rs": bool(int(per_channel_rs)), "rate": rate, "trial": trial}})
    sys.stdout.write(json.dumps(out))
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
