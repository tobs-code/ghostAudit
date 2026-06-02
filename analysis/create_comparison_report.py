import json, csv

files = [
    ("erasure_sweep_results.json", "baseline"),
    ("erasure_sweep_results_by_ecc.json", "by_ecc"),
    ("erasure_sweep_results_run.json", "latest_run"),
]

summary = []
rows = []

for fname, tag in files:
    try:
        with open(fname) as f:
            data = json.load(f)
    except Exception as e:
        print(f"Skipping {fname}: {e}")
        continue

    if tag == "by_ecc":
        # flatten by ecc_symbols entries: compute avg pass per rate across ecc groups
        for ecc_block in data.get("sweep_by_ecc",[]):
            ecc = ecc_block.get("ecc_symbols")
            for rate_entry in ecc_block.get("sweep",[]):
                rate = rate_entry.get("rate")
                trials = rate_entry.get("trials", [])
                avg_pass = sum(t.get("pass_rate",0) for t in trials)/max(1,len(trials))
                avg_recov = sum(t.get("messages_recovered",0) for t in trials)/max(1,len(trials))
                rows.append({"source": fname, "tag": tag, "ecc": ecc, "rate": rate, "avg_pass_rate": avg_pass, "avg_messages_recovered": avg_recov, "total_rows": trials[0].get("total_rows") if trials else None})
                summary.append((fname, tag, ecc, rate, avg_pass))
    else:
        sweep = data.get("sweep", [])
        for rate_entry in sweep:
            rate = rate_entry.get("rate")
            trials = rate_entry.get("trials", [])
            # trials can be list of trial dicts
            avg_pass = sum(t.get("pass_rate",0) for t in trials)/max(1,len(trials))
            avg_recov = sum(t.get("messages_recovered",0) for t in trials)/max(1,len(trials))
            rows.append({"source": fname, "tag": tag, "ecc": None, "rate": rate, "avg_pass_rate": avg_pass, "avg_messages_recovered": avg_recov, "total_rows": trials[0].get("total_rows") if trials else None})
            summary.append((fname, tag, None, rate, avg_pass))

# write CSV
csvf = "comparison_report.csv"
with open(csvf, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["source","tag","ecc","rate","avg_pass_rate","avg_messages_recovered","total_rows"])
    writer.writeheader()
    for r in rows:
        writer.writerow(r)

# write summary JSON
out = {
    "generated_from": [f for f,_ in files],
    "rows_written": len(rows),
    "summary": []
}
for s in summary:
    fname, tag, ecc, rate, avg_pass = s
    out["summary"].append({"source": fname, "tag": tag, "ecc": ecc, "rate": rate, "avg_pass_rate": avg_pass})

with open("comparison_report.json","w") as f:
    json.dump(out, f, indent=2)

print(f"Wrote {csvf} and comparison_report.json")
