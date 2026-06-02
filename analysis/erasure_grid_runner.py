import subprocess, json, os

ecc_values = [56, 64]
reps_values = [6, 8]
per_channel_rs_options = [1, 0]  # 1 = per-channel RS, 0 = combined RS
rates = [0.05, 0.10, 0.15, 0.20, 0.25, 0.30]
trials = 3

results = {"grid": []}

for ecc in ecc_values:
    for reps in reps_values:
        for per_rs in per_channel_rs_options:
            cfg = {"ecc": ecc, "reps": reps, "per_channel_rs": bool(per_rs), "sweep": []}
            print(f"Running config ecc={ecc} reps={reps} per_channel_rs={per_rs}")
            for rate in rates:
                trials_out = []
                for t in range(trials):
                    db = f"grid_tmp_e{ecc}_r{int(rate*100)}_{reps}_{per_rs}_{t}.db"
                    cmd = [
                        "python",
                        "worker_erasure.py",
                        str(ecc),
                        str(reps),
                        str(per_rs),
                        str(rate),
                        str(t),
                        db,
                    ]
                    try:
                        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
                        out = json.loads(proc.stdout)
                    except subprocess.CalledProcessError as e:
                        out = {"error": "proc_failed", "stderr": e.stderr}
                    trials_out.append(out)
                    if os.path.exists(db):
                        try: os.remove(db)
                        except: pass
                cfg["sweep"].append({"rate": rate, "trials": trials_out})
            results["grid"].append(cfg)

outf = "erasure_grid_results.json"
with open(outf, "w") as f:
    json.dump(results, f, indent=2)

print(f"Saved to {outf}")
