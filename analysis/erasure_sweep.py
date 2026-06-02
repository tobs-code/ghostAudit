import json
import os
from resilience_benchmark_v7 import ResilienceBenchmarkV7

rates = [0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.35]
trials_per_rate = 5

results = {"sweep": []}
bench = ResilienceBenchmarkV7(verbose=False)

for rate in rates:
    rate_entry = {"rate": rate, "trials": []}
    for t in range(trials_per_rate):
        db = f"sweep_erasure_{int(rate*100)}_{t}.db"
        ok = bench.test_erasure_tolerance(db_path=db, erasure_rate=rate)
        entry = bench.results["tests"]["erasure_tolerance"].copy()
        entry["trial"] = t
        rate_entry["trials"].append(entry)
        # cleanup db if left
        if os.path.exists(db):
            try:
                os.remove(db)
            except:
                pass
    results["sweep"].append(rate_entry)

outf = "erasure_sweep_results.json"
with open(outf, "w") as f:
    json.dump(results, f, indent=2)

print(f"Sweep complete. Results saved to {outf}")
