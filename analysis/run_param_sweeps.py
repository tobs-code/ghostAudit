import os
import subprocess
import shutil

configs = []
for ecc in range(32, 41, 2):
    for rep in (5,6):
        configs.append((ecc, rep, 0))  # PER_CHANNEL_RS=0 => combined-RS

out_dir = 'sweep_param_runs'
os.makedirs(out_dir, exist_ok=True)

for ecc, rep, pc in configs:
    print(f"Running ecc={ecc}, rep={rep}, per_channel_rs={pc}")
    env = os.environ.copy()
    env['GHOST_AUDIT_ECC_SYMBOLS'] = str(ecc)
    env['GHOST_AUDIT_PER_CHANNEL_MIN_REPS'] = str(rep)
    env['GHOST_AUDIT_PER_CHANNEL_RS'] = str(pc)
    # Run the sweep script which writes erasure_sweep_results_run.json
    res = subprocess.run(['python','erasure_sweep_run.py'], env=env)
    src = 'erasure_sweep_results_run.json'
    if os.path.exists(src):
        dst = os.path.join(out_dir, f'erasure_sweep_ecc{ecc}_rep{rep}_pc{pc}.json')
        shutil.move(src, dst)
        print('Saved', dst)
    else:
        print('No output for', ecc, rep, pc)

print('All runs completed. Results in', out_dir)
