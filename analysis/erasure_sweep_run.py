import json, os
from resilience_benchmark_v7 import ResilienceBenchmarkV7

rates = [0.05, 0.10, 0.15, 0.20, 0.25, 0.30]
trials = 3
results = {"sweep": []}

for rate in rates:
    print(f"Running rate {rate}")
    bench = ResilienceBenchmarkV7(verbose=False)
    trials_out = []
    for t in range(trials):
        db = f"sweep_tmp_{int(rate*100)}_{t}.db"
        ok = bench.test_erasure_tolerance(db_path=db, erasure_rate=rate)
        trials_out.append(bench.results["tests"]["erasure_tolerance"].copy())
        if os.path.exists(db):
            try: os.remove(db)
            except: pass
    results["sweep"].append({"rate": rate, "trials": trials_out})
    print(f"Completed rate {rate}")

outf = "erasure_sweep_results_run.json"
with open(outf, "w") as f:
    json.dump(results, f, indent=2)
print(f"Saved to {outf}")
