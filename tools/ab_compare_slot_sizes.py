import json
import os
import sys
from statistics import mean

# ensure project root is on sys.path so imports like ghost_audit_v7 work
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

SLOT_SIZES = [1600, 2000]
RATES = [0.05, 0.10, 0.15, 0.20, 0.25, 0.30]
TRIALS = 3

OUT_JSON = 'ab_compare_slot_sizes.json'
OUT_CSV = 'ab_compare_slot_sizes.csv'

results = {}

for size in SLOT_SIZES:
    # Import and set SLOT_SIZE before importing benchmark
    import importlib
    import ghost_audit_v7
    ghost_audit_v7.GhostAuditV7.SLOT_SIZE = size
    # reload module to ensure any module-level calculations pick it up
    importlib.reload(ghost_audit_v7)
    from resilience_benchmark_v7 import ResilienceBenchmarkV7

    bench = ResilienceBenchmarkV7(verbose=False)
    size_key = f"SLOT_{size}"
    results[size_key] = {"sweep": []}
    for rate in RATES:
        trials_out = []
        for t in range(TRIALS):
            db = f"ab_tmp_{size}_{int(rate*100)}_{t}.db"
            ok = bench.test_erasure_tolerance(db_path=db, erasure_rate=rate)
            trials_out.append(bench.results["tests"]["erasure_tolerance"].copy())
            if os.path.exists(db):
                try: os.remove(db)
                except: pass
        results[size_key]["sweep"].append({"rate": rate, "trials": trials_out})

# Save JSON
with open(OUT_JSON, 'w') as f:
    json.dump(results, f, indent=2)

# Save CSV summary
with open(OUT_CSV, 'w') as f:
    f.write('slot_size,rate,avg_pass_rate,pass_count,total_trials\n')
    for size in SLOT_SIZES:
        key = f"SLOT_{size}"
        for entry in results[key]['sweep']:
            rate = entry['rate']
            pass_rates = [t.get('pass_rate', 0.0) for t in entry['trials']]
            statuses = [t.get('status') for t in entry['trials']]
            avg_pass = mean(pass_rates) if pass_rates else 0.0
            pass_count = sum(1 for s in statuses if s == 'PASS')
            total = len(statuses)
            f.write(f"{size},{rate},{avg_pass},{pass_count},{total}\n")

print('Wrote', OUT_JSON, 'and', OUT_CSV)
