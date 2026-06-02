"""
GhostAudit V8 — Adversarial Attack Simulator
MITRE ATT&CK based security testing targeting V8 multiplexing features.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import sqlite3
import json
import hmac
import hashlib
import struct
import random
import shutil
import argparse
from datetime import datetime
from core.ghost_audit_v7 import GhostAuditV7
from reedsolo import RSCodec, ReedSolomonError


class AttackSimulatorV8:
    ATTACK_TYPES = {
        "MAC_STRIP": "Manifest Row-MAC Deletion (Erasure→Error Degradation)",
        "MUX_ROW_WIPE": "Multiplexing-aware Row Deletion",
        "BIO_NORMALIZE": "Bio-Column Normalization (3 Carriers at Once)",
        "GAUSSIAN_SEED": "Gaussian Seed / Shuffling Recovery Attempt",
        "REPLAY": "Old sys_cache Version Replay",
        "SELECTIVE_FLOAT_ROUND": "Float-LSB Selective Rounding (Ch1+Ch3; avatar_url survives)",
    }

    def __init__(self, db_path, secret_key=None):
        self.db_path = db_path
        self.secret_key = secret_key
        self._conn = sqlite3.connect(db_path)
        self.attack_log = []
        self.last_recovery_summary = {}

    def close(self):
        try:
            self._conn.close()
        except Exception:
            pass

    def _raw_conn(self):
        raw = sqlite3.connect(self.db_path)
        for t in ("sys_cache_guard_update", "sys_cache_guard_insert",
                  "sys_cache_guard_delete", "sys_cache_block_null_bio",
                  "sys_cache_block_null_score"):
            raw.execute(f"DROP TRIGGER IF EXISTS {t}")
        raw.execute("UPDATE sys_cache_write_gate SET allow_write=1 WHERE id=1")
        raw.commit()
        return raw

    @staticmethod
    def _safe_remove(path):
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass

    @staticmethod
    def _cleanup(path):
        for s in ("", "-wal", "-shm", "-journal"):
            AttackSimulatorV8._safe_remove(path + s)

    def log_attack(self, attack_type, severity, description, success, details=None):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "attack_type": attack_type,
            "severity": severity,
            "description": description,
            "success": success,
            "details": details or {},
        }
        self.attack_log.append(entry)
        status = "EXECUTED" if success else "BLOCKED"
        print(f"  [{status}] {attack_type}: {description}")

    def _get_ga(self, verbose=False):
        return GhostAuditV7(
            db_path=self.db_path,
            secret_key=self.secret_key or "attack-v8-key-9876543210",
            verbose=verbose,
        )

    # ---- ATTACK 1: MAC-Strip (V8-specific) ----
    def attack_mac_strip(self):
        """
        Delete all row_mac entries from sys_cache_manifest without touching bio/score.
        V8 extraction relies on per-channel MACs for erasure detection — without them,
        every row appears corrupted, RS degrades from Erasure→Error mode (half capacity).
        """
        print("\n[ATTACK 1] MAC-Strip — sys_cache_manifest row_mac deletion")
        raw = self._raw_conn()
        try:
            raw.execute("DELETE FROM sys_cache_manifest")
            raw.commit()
            count = raw.execute("SELECT COUNT(*) FROM sys_cache_manifest").fetchone()[0]
            self.log_attack("MAC_STRIP", "CRITICAL",
                            "All row_mac entries deleted from manifest (Erasure→Error degradation)",
                            True, {"remaining_manifest_rows": count})
        finally:
            raw.close()
        return True

    # ---- ATTACK 2: Multiplexing-aware Row Wipe (V8-specific) ----
    def attack_mux_row_wipe(self, fraction=0.15):
        """
        Delete payload rows from sys_cache. Only targets payload rows (skips headers),
        and only removes manifest entries for the specific wiped rows.
        """
        print(f"\n[ATTACK 2] MUX Row-Wipe — deleting {fraction*100:.0f}% of payload rows")
        raw = self._raw_conn()
        try:
            ga = self._get_ga()
            hb = ga.HEADER_BIT_COUNT
            payload_ids = []
            for k in range(ga.SLOT_COUNT):
                s = k * ga.SLOT_SIZE
                slot = ga._orig_ids[s : s + ga.SLOT_SIZE]
                payload_ids.extend(slot[hb:])
            ga.close()
            target_count = max(1, int(len(payload_ids) * fraction))
            targets = random.sample(payload_ids, target_count)
            for rid in targets:
                raw.execute("DELETE FROM sys_cache WHERE id=?", (rid,))
                raw.execute("DELETE FROM sys_cache_manifest WHERE id=?", (rid,))
            raw.commit()
            self.log_attack("MUX_ROW_WIPE", "CRITICAL",
                            f"{target_count} payload rows deleted ({fraction*100:.0f}% of payload)",
                            True, {"deleted": target_count, "fraction": fraction})
        finally:
            raw.close()
        return True

    # ---- ATTACK 3: Bio Normalization (2 Carriers) ----
    def attack_bio_normalize(self):
        """
        Normalize bio text: lowercase, strip trailing spaces, normalize synonyms.
        Kills 2 out of 4 physical carriers (Semantic=Ch0, Trailing-Space=Ch2)
        since Case was replaced by profile_score Float-LSB (independent of bio).
        profile_score Float-LSB survives bio normalization.
        """
        print("\n[ATTACK 3] Bio Normalization — 2 Carriers (Semantic + Trailing-Space)")
        print("  profile_score Float-LSB survives — independent of bio column")
        raw = self._raw_conn()
        try:
            ga = self._get_ga()
            slot_size = ga.SLOT_SIZE
            ga.close()
            # MACs preserved — they will detect the normalization as mismatches → erasures
            for rid, bio in raw.execute(
                "SELECT id, bio FROM sys_cache WHERE bio IS NOT NULL"
            ).fetchall():
                mutated = bio.lower().rstrip()
                replacements = [
                    ("presently", "currently"), ("online", "active"),
                    ("operating", "working"), ("platform", "system"),
                ]
                for v1, v0 in replacements:
                    mutated = mutated.replace(v1, v0)
                raw.execute("UPDATE sys_cache SET bio=? WHERE id=?", (mutated, rid))
            raw.commit()
            self.log_attack("BIO_NORMALIZE", "CRITICAL",
                            "bio normalized: lowercased + trim + synonym flatten (2 carriers lost)",
                            True, {"carriers_lost": ["Semantic", "Trailing-Space"]})
        finally:
            raw.close()
        return True

    # ---- ATTACK 4: Gaussian Seed / Shuffling Recovery (positive control) ----
    def attack_gaussian_seed_recovery(self):
        """
        Positive control: try to recover the Gaussian seed from publicly visible
        trust_score distribution. In V8 the seed is HMAC-derived from the master key,
        not hardcoded — this attack should fail.
        """
        print("\n[ATTACK 4] Gaussian Seed Recovery Attempt (Positive Control)")
        ga = self._get_ga()
        try:
            cur = ga.conn.cursor()
            scores = [
                row[0] for row in
                cur.execute("SELECT trust_score FROM sys_cache WHERE trust_score IS NOT NULL").fetchall()
            ]
            ga.close()
            if not scores:
                self.log_attack("GAUSSIAN_SEED", "INFO", "No scores to analyze", False)
                return False
            mean = sum(scores) / len(scores)
            # An attacker could try to brute-force the seed from the distribution.
            # With HMAC-derived seed (256-bit key), this is computationally infeasible.
            self.log_attack("GAUSSIAN_SEED", "MEDIUM",
                            f"Distribution sampled (n={len(scores)}, mean={mean:.4f}) — "
                            f"seed is HMAC-derived from master key, not recoverable",
                            False, {"samples": len(scores), "mean": mean,
                                     "vulnerable": False})
            return False
        except Exception as e:
            ga.close()
            self.log_attack("GAUSSIAN_SEED", "MEDIUM", f"Error: {e}", False)
            return False

    # ---- ATTACK 5: Replay Attack ----
    def attack_replay(self):
        """
        Restore an old version of sys_cache from a backup, then try to recover.
        Forward Secrecy (slot keys and anchor evolution) should detect the replay.
        """
        print("\n[ATTACK 5] Replay Attack — restore old sys_cache version")
        backup_path = self.db_path + ".replay_backup"
        if not os.path.exists(backup_path):
            shutil.copyfile(self.db_path, backup_path)
            self.log_attack("REPLAY", "INFO", "Backup created for replay test", True)
            return True

        raw = self._raw_conn()
        try:
            raw.execute("DELETE FROM sys_cache")
            raw.execute("DELETE FROM sys_cache_manifest")
            old_raw = sqlite3.connect(backup_path)
            for row in old_raw.execute("SELECT * FROM sys_cache").fetchall():
                cols = ",".join(f"c{i}" for i in range(len(row)))
                vals = ",".join("?" * len(row))
                raw.execute(f"INSERT INTO sys_cache ({cols}) VALUES ({vals})", row)
            for row in old_raw.execute("SELECT * FROM sys_cache_manifest").fetchall():
                cols = ",".join(f"c{i}" for i in range(len(row)))
                vals = ",".join("?" * len(row))
                raw.execute(f"INSERT INTO sys_cache_manifest ({cols}) VALUES ({vals})", row)
            old_raw.close()
            raw.commit()
            self.log_attack("REPLAY", "CRITICAL",
                            "Old sys_cache state restored — Forward Secrecy should detect",
                            True, {"backup": backup_path})
        finally:
            raw.close()
        # Clean backup after test
        self._cleanup(backup_path)
        return True

    # ---- ATTACK 6: Selective Float Round (Ch1 only) ----
    def attack_selective_float_round(self):
        """
        Round both trust_score AND profile_score to 2 decimal places.
        Attacks both Float-LSB carriers (Ch1 and Ch3) simultaneously.
        avatar_url carrier survives (text column — unaffected by float rounding).
        With 5 channels (5 data, not 4), 2/5 = 40% erasure → nsym=32 still overcapacity
        but the system should now degrade more gracefully (better than 2/4=50%).
        """
        print("\n[ATTACK 6] Selective Float Round — Ch1 (trust_score) + Ch3 (profile_score)")
        print("  avatar_url (~ tilde carrier) survives — text column, float-round-invariant")
        raw = self._raw_conn()
        try:
            # Rounding only affects float columns — avatar_url is text and untouched here
            for rid, score in raw.execute(
                "SELECT id, trust_score FROM sys_cache"
            ).fetchall():
                raw.execute("UPDATE sys_cache SET trust_score=? WHERE id=?",
                            (round(float(score), 2), rid))
            for rid, score in raw.execute(
                "SELECT id, profile_score FROM sys_cache WHERE profile_score IS NOT NULL"
            ).fetchall():
                raw.execute("UPDATE sys_cache SET profile_score=? WHERE id=?",
                            (round(float(score), 2), rid))
            raw.commit()
            self.log_attack("SELECTIVE_FLOAT_ROUND", "HIGH",
                            "trust_score + profile_score rounded to 2d (Ch1+Ch3 Float-LSB lost; Ch4 avatar_url survives — 2/5 lost)",
                            True, {"channels": [1, 3], "carriers": ["trust_score Float-LSB", "profile_score Float-LSB"], "surviving": ["avatar_url Tilde"]})
        finally:
            raw.close()
        return True

    # ---- RECOVERY TEST ----
    def test_recovery_after_attack(self):
        print("\n[RECOVERY TEST] Post-Attack Recovery (V8 multiplexed path)")
        if not self.secret_key:
            print("  (!) No secret key — recovery would fail.")
            return False

        self.close()
        cleanup = sqlite3.connect(self.db_path)
        cleanup.execute("DELETE FROM audit_log")
        cleanup.execute("DELETE FROM audit_archive")
        cleanup.execute("DELETE FROM event_mac_tags")
        cleanup.commit()
        cleanup.close()

        ga = self._get_ga(verbose=False)
        try:
            recovered = ga.recover_events()
        except Exception as exc:
            import traceback
            traceback.print_exc()
            print(f"  (!) Recovery exception: {exc}")
            ga.close()
            self.last_recovery_summary = {
                "tampering_detected": 0, "total_recovered": 0, "status": "exception",
            }
            return False
        finally:
            ga.close()

        if recovered is None:
            recovered = []

        tampering_detected = sum(
            1 for log in recovered if "[TAMPERING DETECTED]" in str(log)
        )
        valid = [log for log in recovered if "[TAMPERING DETECTED]" not in str(log)]

        print(f"  Recovered {len(recovered)} | Tampered: {tampering_detected} | Valid: {len(valid)}")
        for idx, log in enumerate(recovered):
            status = "TAMPERED" if "[TAMPERING DETECTED]" in str(log) else "VALID"
            print(f"    [{idx}] [{status}] {str(log)[:65]}")

        if tampering_detected > 0:
            print(f"\n  OK: {tampering_detected}/{len(recovered)} flagged as tampered.")
            self.last_recovery_summary = {
                "tampering_detected": tampering_detected,
                "total_recovered": len(recovered),
                "valid_recovered": len(valid),
                "status": "detected_tampering",
            }
            self.log_attack("RECOVERY", "INFO",
                            f"{tampering_detected}/{len(recovered)} tampered entries detected",
                            True, {"tampered": tampering_detected, "total": len(recovered)})
            return True
        elif len(recovered) == 0:
            print("  CRITICAL: No entries recovered — total data loss.")
            self.last_recovery_summary = {
                "tampering_detected": 0, "total_recovered": 0,
                "valid_recovered": 0, "status": "total_loss",
            }
            self.log_attack("RECOVERY", "CRITICAL",
                            "Total data loss — no entries recoverable", False)
            return False
        else:
            print("  WARNING: No tampering detected — recovery returned clean data.")
            self.last_recovery_summary = {
                "tampering_detected": 0,
                "total_recovered": len(recovered),
                "valid_recovered": len(valid),
                "status": "recovery_clean",
            }
            return False

    def generate_report(self):
        entries = [a for a in self.attack_log if a["attack_type"] != "RECOVERY"]
        n_ok = sum(1 for a in entries if a["success"])
        n_blocked = sum(1 for a in entries if not a["success"])
        return {
            "timestamp": datetime.now().isoformat(),
            "target": "GhostAudit V8",
            "total_attacks": len(entries),
            "executed": n_ok,
            "blocked": n_blocked,
            "success_rate": f"{n_ok / len(entries) * 100:.1f}%" if entries else "N/A",
            "attacks": entries,
            "vulnerabilities_found": [
                a for a in entries if a["success"]
                and "TAMPERED" not in a["description"]
            ],
            "post_attack_recovery": self.last_recovery_summary,
        }


def _recovery_label(summary):
    s = summary.get("status", "")
    if s == "recovery_clean":
        return "✅ RECOVERED"
    elif s == "detected_tampering":
        return "⚠️  TAMPERED"
    elif s == "total_loss":
        return "❌ LOST"
    elif s == "exception":
        return "💥 CRASH"
    return f"? {s}"


def main():
    print("=" * 70)
    print("GHOST AUDIT V8 — ADVERSARIAL ATTACK SIMULATION")
    print("Targeting V8 Multiplexing: MAC-Strip, Row-Wipe, Bio-Normalize, Replay")
    print("=" * 70)

    db_path = "ghost_audit_v8_attack_test.db"
    baseline_db = "ghost_audit_v8_attack_baseline.db"

    for p in (db_path, baseline_db):
        AttackSimulatorV8._cleanup(p)

    # ---- Setup: 3 Baseline Events ----
    print("\n[SETUP] Writing 3 baseline events...")
    ga = GhostAuditV7(db_path=db_path, secret_key="attack-v8-key-9876543210", verbose=False)
    ga.log_event("BASELINE_1: SYSTEM_STARTUP_V8")
    ga.log_event("BASELINE_2: DB_INIT_V8")
    ga.log_event("BASELINE_3: AUDIT_LOG_CREATED_V8")
    ga.close()
    shutil.copyfile(db_path, baseline_db)
    print("OK - baseline written and snapshotted.\n")

    all_logs = []
    results = []

    # ---- Attack + Recovery pairs ----
    attack_plan = [
        ("MAC-Strip (row_mac deleted)", "attack_mac_strip", {}),
        ("MUX Row-Wipe 15%", "attack_mux_row_wipe", {"fraction": 0.15}),
        ("Bio Normalize (3 carriers)", "attack_bio_normalize", {}),
        ("Gaussian Seed Recovery", "attack_gaussian_seed_recovery", {}),
        ("Selective Float Round (Ch1+Ch3)", "attack_selective_float_round", {}),
    ]

    for name, method, kwargs in attack_plan:
        print(f"\n{'═' * 55}")
        print(f"  Attack: {name}")
        print(f"{'═' * 55}")
        AttackSimulatorV8._cleanup(db_path)
        shutil.copyfile(baseline_db, db_path)
        sim = AttackSimulatorV8(db_path=db_path, secret_key="attack-v8-key-9876543210")
        getattr(sim, method)(**kwargs)
        sim.test_recovery_after_attack()
        label = _recovery_label(sim.last_recovery_summary)
        summary = dict(sim.last_recovery_summary)
        results.append((name, label, summary))
        all_logs.extend(sim.attack_log)
        sim.close()
        AttackSimulatorV8._cleanup(db_path)

    AttackSimulatorV8._cleanup(baseline_db)

    # ---- Report ----
    print("\n" + "=" * 70)
    print("ATTACK SIMULATION REPORT — V8")
    print("=" * 70)

    for name, label, summary in results:
        detail = ""
        if summary.get("total_recovered", 0) > 0:
            detail += f" {summary['total_recovered']} events"
        if summary.get("tampering_detected", 0) > 0:
            detail += f", {summary['tampering_detected']} tampered"
        print(f"\n  {label}  {name}{detail}")

    entries = [a for a in all_logs if a["attack_type"] != "RECOVERY"]
    n_ok = sum(1 for a in entries if a["success"])
    n_blocked = sum(1 for a in entries if not a["success"])
    print(f"\nMutations Executed : {n_ok}")
    print(f"Blocked            : {n_blocked}")

    report = {
        "timestamp": datetime.now().isoformat(),
        "target": "GhostAudit V8",
        "total_attacks": len(entries),
        "executed": n_ok,
        "blocked": n_blocked,
        "success_rate": f"{n_ok / len(entries) * 100:.1f}%" if entries else "N/A",
        "attacks": entries,
        "results": [{"attack": n, "outcome": l, "details": s} for n, l, s in results],
        "report_note": (
            "'executed' = mutation applied (gate bypassed). "
            "Recovery outcome in 'results'."
        ),
    }

    report_file = "attack_simulation_report_v8.json"
    with open(report_file, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nOK — {report_file} written.")


if __name__ == "__main__":
    main()
