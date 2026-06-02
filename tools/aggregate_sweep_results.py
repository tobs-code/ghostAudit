import json
import glob
import re
import csv
from statistics import mean

INPUT_GLOB = 'sweep_param_runs/erasure_sweep_ecc*_rep*_pc*.json'
CSV_OUT = 'compact_comparison_report.csv'
JSON_OUT = 'compact_comparison_report.json'

rows = []
summary = {}

for path in glob.glob(INPUT_GLOB):
    m = re.search(r'erasure_sweep_ecc(\d+)_rep(\d+)_pc(\d+)\.json$', path)
    if not m:
        continue
    ecc = int(m.group(1))
    rep = int(m.group(2))
    pc = int(m.group(3))
    key = f"ecc{ecc}_rep{rep}_pc{pc}"
    with open(path, 'r') as f:
        data = json.load(f)
    rates = []
    rate_entries = []
    for entry in data.get('sweep', []):
        rate = entry['rate']
        trials = entry['trials']
        pass_rates = [t.get('pass_rate', 0.0) for t in trials]
        statuses = [t.get('status') for t in trials]
        avg_pass = mean(pass_rates) if pass_rates else 0.0
        pass_count = sum(1 for s in statuses if s == 'PASS')
        total = len(trials)
        rate_entries.append({
            'rate': rate,
            'avg_pass_rate': avg_pass,
            'pass_count': pass_count,
            'total_trials': total
        })
        rates.append(avg_pass)
        rows.append({'ecc': ecc, 'rep': rep, 'pc': pc, 'rate': rate, 'avg_pass_rate': avg_pass, 'pass_count': pass_count, 'total_trials': total})
    overall_score = mean(rates) if rates else 0.0
    summary[key] = {
        'ecc': ecc,
        'rep': rep,
        'pc': pc,
        'overall_avg_pass_rate_across_rates': overall_score,
        'rates': rate_entries
    }

# write CSV
with open(CSV_OUT, 'w', newline='') as csvf:
    fieldnames = ['ecc', 'rep', 'pc', 'rate', 'avg_pass_rate', 'pass_count', 'total_trials']
    writer = csv.DictWriter(csvf, fieldnames=fieldnames)
    writer.writeheader()
    for r in sorted(rows, key=lambda x: (x['ecc'], x['rep'], x['rate'])):
        writer.writerow(r)

# write JSON summary
with open(JSON_OUT, 'w') as jf:
    json.dump({'summary': summary}, jf, indent=2)

print('Wrote', CSV_OUT, 'and', JSON_OUT)
