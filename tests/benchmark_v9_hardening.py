import os
import sys
import sqlite3
import random
import time
import shutil
import tempfile
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.carrier_config import CarrierConfig
from core.ghost_audit_v9 import GhostAuditInterceptor, TextShapeCarrier

def generate_noisy_bios(count: int):
    """Generate a mix of bios with varying Oxford comma presence and structure."""
    templates = [
        "Currently working on {}, {} and {}.",         # variant 0
        "Presently focused on {}, {}, and {}.",        # variant 1
        "Active on {}, {} and {}.",                    # variant 0
        "Online and working on {}, {}, and {}.",        # variant 1
        "The system is currently active in {}, {} and {}.", # variant 0
        "I like {} and {}.",                           # Not eligible
    ]
    items = ["Python", "Rust", "Go", "Docker", "K8s", "Linux", "Security", "Stego", "Audit", "Cloud"]
    
    bios = []
    for _ in range(count):
        tpl = random.choice(templates)
        # Sample unique items
        sample = random.sample(items, tpl.count("{"))
        bios.append(tpl.format(*[s for s in sample]))
    return bios

def generate_noisy_floats(count: int):
    """Generate a mix of floats: high precision, rounded, and biased."""
    vals = []
    for i in range(count):
        mode = i % 4
        if mode == 0:
            # High precision random
            vals.append(random.uniform(0.0, 1.0))
        elif mode == 1:
            # Rounded to 2 decimal places (Should cause bias at 10^6, better at 10^2)
            vals.append(round(random.uniform(0.0, 1.0), 2))
        elif mode == 2:
            # Rounded to 4 decimal places
            vals.append(round(random.uniform(0.0, 1.0), 4))
        else:
            # Biased around 0.5
            vals.append(0.5 + random.gauss(0, 0.05))
    return vals

def run_benchmark():
    print("=== GhostAudit V9 Hardening Benchmark ===")
    tmpdir = tempfile.mkdtemp()
    db_path = os.path.join(tmpdir, "benchmark.db")
    
    try:
        # 1. Setup Database
        conn = sqlite3.connect(db_path)
        conn.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                bio TEXT,
                trust_score REAL,
                profile_score REAL,
                avatar_url TEXT
            )
        """)
        
        sample_size = 5000
        bios = generate_noisy_bios(sample_size)
        floats_a = generate_noisy_floats(sample_size)
        floats_b = generate_noisy_floats(sample_size)
        
        rows = []
        for i in range(sample_size):
            rows.append((i+1, bios[i], floats_a[i], floats_b[i], f"https://example.com/{i}.jpg"))
        
        conn.executemany("INSERT INTO users VALUES (?,?,?,?,?)", rows)
        conn.commit()
        conn.close()
        
        # 2. Initialize GhostAudit
        cfg = CarrierConfig(
            table="users",
            id_field="id",
            semantic_field="bio",
            float_a_field="trust_score",
            float_b_field="profile_score",
            tilde_field="avatar_url",
            slot_size=5000,
            slot_count=1
        )
        
        ga = GhostAuditInterceptor(
            db_path=db_path,
            carrier_config=cfg,
            verbose=True,
            temporal_delay_rows=20,
            target_spread_factor=1.0, # Disable scheduler skipping for this test
            float_warmup_samples=500
        )
        
        # 3. Measurement: Coverage
        print("\n--- Measurement 1: Carrier Coverage ---")
        text_stats = ga.measure_text_shape_coverage(sample_size=sample_size)
        print(f"TextShape Coverage (Oxford Comma): {text_stats['coverage_ratio']:.2%} ({text_stats['eligible']}/{text_stats['sample_size']})")
        
        # 4. Measurement: Float Fit
        print("\n--- Measurement 2: Float Best-Scale Fit ---")
        ga.calibrate_floats(sample_size=sample_size)
        float_stats = ga.measure_float_coverage()
        print(f"Float Best Scale: {float_stats['best_scale']}")
        print(f"Float Coverage: {float_stats['coverage_ratio']:.2%} (Ready: {float_stats['ready']})")
        
        # 5. Measurement: Temporal Latency & Scheduler
        print("\n--- Measurement 3: Scheduler Spread ---")
        
        # 5a. Establish app write rate EMA first
        print("Warm-up: establishing app write rate...")
        for i in range(20):
            # Use a non-header row (e.g. 500)
            ga.intercept(500, {"bio": ""})
            time.sleep(0.01) # 10ms gap -> 100 writes/s
            
        print(f"App Write Rate EMA: {ga._app_write_rate_ema:.1f} writes/s")

        # 5b. Establish event interval EMA
        ga.log_event("Establish EMA Rate Event 1")
        time.sleep(0.5)
        ga.log_event("Establish EMA Rate Event 2")
        time.sleep(0.5)
        
        # Clear the queue so we only benchmark ONE clean event
        # (V9 currently supports one concurrent event per slot)
        ga._payload_queue = []
        
        main_msg = "High Sensitivity Audit"
        ga.log_event(main_msg)
        
        print(f"Avg Event Interval EMA: {ga._avg_event_interval_ema:.3f}s")
        print(f"Calculated Probability: {ga._current_embedding_probability():.4f}")
        
        pending_bits = ga.pending_bit_count()
        print(f"Initial pending bits (main event): {pending_bits}")
        
        write_times = []
        # Simulate app updates SEQUENTIALLY to match FIFO queue with DB order
        # (This proves that order is the issue)
        embedded_count = 0
        total_attempts = 0
        
        # Sort rows to ensure deterministic order
        sorted_rids = list(range(1, sample_size + 1))
        
        for rid in sorted_rids:
            total_attempts += 1
            # Fetch current row state
            conn = sqlite3.connect(db_path)
            row = conn.execute("SELECT bio, trust_score, profile_score, avatar_url FROM users WHERE id=?", (rid,)).fetchone()
            conn.close()
            
            if not row: continue
            
            fields = {"bio": row[0], "trust_score": row[1], "profile_score": row[2], "avatar_url": row[3]}
            
            # Intercept
            res = ga.intercept_result(rid, fields)
            
            if res.modified:
                embedded_count += 1
                write_times.append(total_attempts)
                
                # Update DB to simulate real write
                conn = sqlite3.connect(db_path)
                conn.execute("UPDATE users SET bio=?, trust_score=?, profile_score=?, avatar_url=? WHERE id=?", 
                             (res.fields["bio"], res.fields["trust_score"], res.fields["profile_score"], res.fields["avatar_url"], rid))
                conn.commit()
                conn.close()
            
            if ga.pending_event_count() == 0:
                break

        print(f"All payloads completed at attempt {total_attempts}")
            
        print(f"Embedding completed after {total_attempts} app-write attempts.")
        print(f"Embedded {embedded_count} logical bit-tuples.")
        
        if write_times:
            avg_delay = sum(write_times) / len(write_times)
            min_delay = min(write_times)
            max_delay = max(write_times)
            print(f"Temporal Spread (attempts): min={min_delay}, max={max_delay}, avg={avg_delay:.1f}")
            
            # Check for immediate writes (bad for steganalyse)
            immediate = sum(1 for t in write_times if t < 5)
            print(f"Immediate writes (within first 5 attempts): {immediate}")

        # 6. Recovery Check
        print("\n--- Measurement 4: Integrity Check ---")
        recovered = ga.recover_events()
        if recovered and "High Sensitivity Audit" in recovered[0][1]:
            print("SUCCESS: Event recovered correctly from noisy corpus.")
        else:
            print("FAILURE: Event recovery failed.")
            if recovered:
                print(f"Recovered: {recovered}")
            else:
                print("No events recovered.")

        ga.close()
        
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

if __name__ == "__main__":
    run_benchmark()
