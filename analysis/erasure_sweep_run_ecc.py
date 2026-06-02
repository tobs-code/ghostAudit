import json, os
from resilience_benchmark_v7 import ResilienceBenchmarkV7

ecc_values = [40, 48]
rates = [0.05, 0.10, 0.15, 0.20, 0.25, 0.30]
trials = 3
results = {"sweep_by_ecc": []}

for ecc in ecc_values:
    print(f"Starting sweep for ecc_symbols={ecc}")
    ecc_out = {"ecc_symbols": ecc, "sweep": []}
    for rate in rates:
        print(f"  Running rate {rate} (ecc={ecc})")
        bench = ResilienceBenchmarkV7(verbose=False)
        trials_out = []
        for t in range(trials):
            db = f"sweep_tmp_e{ecc}_{int(rate*100)}_{t}.db"
            ok = bench.test_erasure_tolerance(db_path=db, erasure_rate=rate)
            # Inject ecc into results for traceability
            entry = bench.results["tests"]["erasure_tolerance"].copy()
            entry["ecc_symbols"] = ecc
            trials_out.append(entry)
            if os.path.exists(db):
                try: os.remove(db)
                except: pass
        ecc_out["sweep"].append({"rate": rate, "trials": trials_out})
    results["sweep_by_ecc"].append(ecc_out)
    print(f"Completed sweep for ecc_symbols={ecc}")

outf = "erasure_sweep_results_by_ecc.json"
with open(outf, "w") as f:
    json.dump(results, f, indent=2)

print(f"Saved to {outf}")
