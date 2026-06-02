"""
Gradual Decay Ramp V8.2: Maps the cliff-performance of the adaptive cascade.
Increases BER by `step_pct` per event until the system hits TAMPERING.
"""
import sys, os, csv, time, random, re, struct, hashlib, hmac, math, sqlite3
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.ghost_audit_v7 import GhostAuditV7, StegoEngine
from reedsolo import RSCodec, ReedSolomonError

DB_PATH = "gradual_decay_ramp.db"
STABLE_KEY = "gradual-decay-key-v82-2026"
STEP_BER = 0.01       # 1% BER increase per event
MAX_BER = 0.50        # stop at 50% BER
EVENTS_BASELINE = 3   # healthy events before ramp starts


def _raw_conn(path):
    raw = sqlite3.connect(path)
    for t in ("sys_cache_guard_update", "sys_cache_guard_insert",
              "sys_cache_guard_delete", "sys_cache_block_null_bio",
              "sys_cache_block_null_score"):
        try: raw.execute(f"DROP TRIGGER IF EXISTS {t}")
        except: pass
    raw.execute("UPDATE sys_cache_write_gate SET allow_write=1 WHERE id=1")
    raw.commit()
    return raw


def apply_ber(raw, ga, ber):
    """Apply BER as per-row corruption across all 5 carriers."""
    cur = raw.execute("SELECT id, bio, trust_score, profile_score, avatar_url FROM sys_cache ORDER BY id")
    rows = cur.fetchall()
    all_keywords = [kw for pair in StegoEngine.SEMANTIC_MAP.values() for kw in pair]
    updated = 0
    for rid, bio, ts, ps, av in rows:
        bio = bio or ""
        av = av or ""
        for carrier in range(5):
            if random.random() >= ber:
                continue
            updated += 1
            if carrier == 0:  # Semantic
                swapped = False
                for base, (v0, v1) in StegoEngine.SEMANTIC_MAP.items():
                    pat = re.compile(rf"\b({v0}|{v1})\b", re.IGNORECASE)
                    m = pat.search(bio)
                    if m:
                        matched = m.group(1)
                        replacement = v1 if matched.lower() == v0 else v0
                        if matched.isupper(): replacement = replacement.upper()
                        elif matched.istitle(): replacement = replacement.title()
                        bio = pat.sub(replacement, bio, count=1)
                        swapped = True
                        break
                if not swapped:
                    alpha = [i for i, c in enumerate(bio) if c.isalpha()]
                    if alpha:
                        p = random.choice(alpha)
                        s = list(bio)
                        s[p] = random.choice("abcdefghijklmnopqrstuvwxyz")
                        bio = "".join(s)
            elif carrier == 1:  # Float LSB trust_score
                scaled = int(round(ts * 1000000))
                scaled ^= 1
                ts = float(scaled) / 1000000
            elif carrier == 2:  # Trailing space
                if bio.endswith(" "):
                    bio = bio.rstrip()
                else:
                    bio = bio + " "
            elif carrier == 3:  # Float LSB profile_score
                scaled = int(round(ps * 1000000))
                scaled ^= 1
                ps = float(scaled) / 1000000
            elif carrier == 4:  # Tilde
                if av.endswith("~"):
                    av = av.rstrip("~")
                else:
                    av = av + "~"
        cur.execute("UPDATE sys_cache SET bio=?, trust_score=?, profile_score=?, avatar_url=? WHERE id=?",
                    (bio, ts, ps, av, rid))
    raw.commit()
    return updated


def safe_remove(path):
    for s in ("", "-wal", "-shm", "-journal"):
        try: os.remove(path + s)
        except: pass


def run_ramp():
    safe_remove(DB_PATH)
    evolve_path = os.path.splitext(DB_PATH)[0] + ".evolve"
    safe_remove(evolve_path)
    results = []

    # --- Stage 1: Baseline writes ---
    ga = GhostAuditV7(db_path=DB_PATH, secret_key=STABLE_KEY, verbose=False)
    for i in range(EVENTS_BASELINE):
        ga.log_event(f"BASELINE_{i}")
    ga.close()

    # --- Stage 2: Ramp loop ---
    ber = 0.0
    step = 0
    all_tampered = False

    print("ber,step,D,nsym,min_reps,pre_ecc_ber,rs_status,integrity,total,valid,tampered,ema_lag")

    while ber <= MAX_BER and not all_tampered:
        # Apply BER corruption
        raw = _raw_conn(DB_PATH)
        n_flips = apply_ber(raw, ga, ber)
        raw.close()

        # Open fresh instance (trigger adaptive probe)
        ga = GhostAuditV7(db_path=DB_PATH, secret_key=STABLE_KEY, verbose=False, force_reinit=True)

        # Capture the adaptive params that log_event will use
        cursor = ga.conn.cursor()
        slot_sequences = ga._scan_slots(cursor)
        active_seqs = set(seq for _, seq in slot_sequences if seq > 0)
        active_count = len(active_seqs)
        replica_count = min(ga.REPLICA_COUNT,
                           max(1, ga.SLOT_COUNT // max(1, active_count + 1)), len(slot_sequences))
        target_slots = [s for s, _ in slot_sequences[:replica_count]]
        first_slot = target_slots[0] if target_slots else 0
        slot_start = first_slot * ga.SLOT_SIZE
        slot_ids = ga._orig_ids[slot_start: slot_start + ga.SLOT_SIZE]
        payload_ids = slot_ids[ga.HEADER_BIT_COUNT:]

        history = ga._get_channel_quality(first_slot)
        probe = ga._probe_carrier_integrity(cursor, payload_ids)
        if history is not None:
            D = max(max(probe[c], history.get(c, 0.0)) for c in range(ga.CHANNEL_COUNT))
        else:
            probe[2] = 0.0
            probe[4] = 0.0
            D = max(probe.values())
        params = ga._degradation_to_params({c: D for c in range(ga.CHANNEL_COUNT)})

        # Write event with adaptive params
        ga.log_event(f"DECAY_step{step}_BER{ber:.3f}")

        # Recovery
        recovered = ga.recover_events()

        tampered = sum(1 for _, m in recovered if "[TAMPERING" in str(m))
        valid = len(recovered) - tampered

        # Determine RS status from the recovery messages
        rs_status = "SUCCESS"
        for _, msg in recovered:
            if "[TAMPERING DETECTED]" in str(msg):
                rs_status = "UNCORRECTABLE"
                break
            if "[PARTIAL RECOVERY" in str(msg):
                rs_status = "PARTIAL"

        end_integrity = "VALID" if valid > tampered else "TAMPER_DETECTED"

        # Estimate EMA lag: D - actual BER (clamped)
        ema_lag = max(0.0, D - ber)

        row = {
            "ber": round(ber, 4),
            "step": step,
            "D": round(D, 4),
            "nsym": ga._current_min_repetitions,  # placeholder, real nsym from event header
            "min_reps": params["min_reps"],
            "pre_ecc_ber": round(ber, 4),
            "rs_status": rs_status,
            "integrity": end_integrity,
            "total": len(recovered),
            "valid": valid,
            "tampered": tampered,
            "ema_lag": round(ema_lag, 4),
        }

        # Try to get actual nsym from slot headers
        try:
            for k in range(ga.SLOT_COUNT):
                s_start = k * ga.SLOT_SIZE
                s_ids = ga._orig_ids[s_start: s_start + ga.SLOT_SIZE]
                h_ids = s_ids[:ga.HEADER_BIT_COUNT]
                h_bits = []
                for rid in h_ids:
                    cu = ga.conn.cursor()
                    cu.execute(f"SELECT bio, trust_score, profile_score, avatar_url FROM {ga.AUX_TABLE} WHERE id=?", (rid,))
                    r = cu.fetchone()
                    if r and r[0] and r[1]:
                        h_bits.append(ga._decode_header_bit(rid, r[0], r[1], profile_score=r[2], avatar_url=r[3]))
                    else:
                        h_bits.append(0)
                hd = ga._decode_header(h_bits, k)
                if hd and hd.get("nsym", 0) > 0:
                    row["nsym"] = hd["nsym"]
                    break
        except:
            pass

        results.append(row)
        print(f"{row['ber']:.3f},{step},{row['D']:.2f},{row['nsym']},{row['min_reps']},{row['pre_ecc_ber']:.3f},{row['rs_status']},{row['integrity']},{row['total']},{valid},{tampered},{row['ema_lag']:.3f}")

        ga.close()
        ber += STEP_BER
        step += 1

        if tampered == len(recovered) and len(recovered) > 0:
            all_tampered = True

    # Save CSV
    csv_path = "gradual_decay_ramp_results.csv"
    with open(csv_path, "w", newline="") as f:
        if results:
            w = csv.DictWriter(f, fieldnames=results[0].keys())
            w.writeheader()
            w.writerows(results)
    print(f"\nResults saved to {csv_path}")
    return results


if __name__ == "__main__":
    random.seed(42)
    run_ramp()
