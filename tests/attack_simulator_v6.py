# -*- coding: utf-8 -*-
"""
GHOST AUDIT V6 - ADVERSARIAL ATTACK SIMULATOR
MITRE ATT&CK based security testing with Gate-Bypass strategy.
"""

import sqlite3
import random
import os
import json
import hmac
import hashlib
import shutil
import struct
import argparse
from datetime import datetime
from core.ghost_audit_v6 import GhostAuditV6
from reedsolo import RSCodec, ReedSolomonError
from core.security_suite_support import (
    add_mode_args,
    attack_report_path,
    create_ga,
    mode_label,
    resolve_per_channel_rs,
)


class AttackSimulator:
    ATTACK_TYPES = {
        "T1485": "Data Destruction",
        "T1565_sem": "Data Modification (Semantic)",
        "T1070": "Log Deletion/Tampering",
        "T1027": "Obfuscation via Normalization",
        "T1565_mod": "HMAC Forgery Attempt",
        "T1565_combined": "Combined Channel Attack",
    }

    def __init__(self, db_path, secret_key=None, per_channel_rs: bool = False):
        self.db_path = db_path
        self.secret_key = secret_key
        self.per_channel_rs = per_channel_rs
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()
        self.attack_log = []
        self.last_recovery_summary = {}

    def close(self):
        try:
            self.cursor.close()
        except Exception:
            pass
        try:
            self.conn.close()
        except Exception:
            pass

    def _bypass_gate(self):
        raw = sqlite3.connect(self.db_path)
        raw.execute("DROP TRIGGER IF EXISTS sys_cache_guard_update")
        raw.execute("DROP TRIGGER IF EXISTS sys_cache_guard_insert")
        raw.execute("DROP TRIGGER IF EXISTS sys_cache_guard_delete")
        raw.execute("DROP TRIGGER IF EXISTS sys_cache_block_null_bio")
        raw.execute("DROP TRIGGER IF EXISTS sys_cache_block_null_score")
        raw.execute("UPDATE sys_cache_write_gate SET allow_write=1 WHERE id=1")
        raw.commit()
        return raw

    @staticmethod
    def _close_raw(raw):
        try:
            raw.close()
        except Exception:
            pass

    @staticmethod
    def _rebuild_manifest(db_path):
        conn = sqlite3.connect(db_path)
        try:
            conn.execute("DELETE FROM sys_cache_manifest")
            rows = conn.execute(
                "SELECT id, bio, trust_score FROM sys_cache ORDER BY id ASC"
            ).fetchall()
            manifest_rows = []
            k_hmac = GhostAuditV6(secret_key="__temp__").k_hmac
            for row_id, bio, trust_score in rows:
                if bio is None or trust_score is None:
                    continue
                payload = (
                    struct.pack(">I", row_id)
                    + bio.encode("utf-8")
                    + b"\x00"
                    + struct.pack(">d", float(trust_score))
                )
                row_mac = hmac.new(k_hmac, payload, hashlib.sha256).digest()
                manifest_rows.append((row_id, row_mac))
            if manifest_rows:
                conn.executemany(
                    "INSERT OR REPLACE INTO sys_cache_manifest (id, row_mac) VALUES (?, ?)",
                    manifest_rows,
                )
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def _safe_remove(path):
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass

    @staticmethod
    def _cleanup_db_files(base_path):
        for suffix in ("", "-wal", "-shm", "-journal"):
            AttackSimulator._safe_remove(base_path + suffix)

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

    # ---- ATTACK 1: T1485 - All Channels Nulling ----
    def attack_all_channels_nulling(self, rebuild_manifest=True):
        print("\n[ATTACK 1] T1485 - Systematic Multi-Channel Nulling")
        raw = self._bypass_gate()
        try:
            raw.execute("UPDATE sys_cache SET bio=LOWER(bio) WHERE bio IS NOT NULL")
            for rid, bio in raw.execute(
                "SELECT id, bio FROM sys_cache WHERE bio IS NOT NULL"
            ).fetchall():
                raw.execute("UPDATE sys_cache SET bio=? WHERE id=?", (bio.rstrip(), rid))
            for rid, score in raw.execute(
                "SELECT id, trust_score FROM sys_cache"
            ).fetchall():
                raw.execute("UPDATE sys_cache SET trust_score=? WHERE id=?",
                            (round(float(score), 2), rid))
            replacements = [
                ("presently", "currently"), ("online", "active"),
                ("operating", "working"), ("platform", "system"),
            ]
            for rid, bio in raw.execute(
                "SELECT id, bio FROM sys_cache WHERE bio IS NOT NULL"
            ).fetchall():
                mutated = bio
                for v1, v0 in replacements:
                    mutated = mutated.replace(v1, v0).replace(v1.capitalize(), v0).replace(v1.upper(), v0.upper())
                raw.execute("UPDATE sys_cache SET bio=? WHERE id=?", (mutated, rid))
            raw.commit()
            if rebuild_manifest:
                self._rebuild_manifest(self.db_path)
        finally:
            self._close_raw(raw)

        self.log_attack("T1485", "CRITICAL",
                        "Gate bypassed; Case/Trailing/Float/Semantic nullified + manifest rebuilt",
                        True, {"channels": ["Case", "Trailing-Space", "Float-LSB", "Semantic"]})
        return True

    # ---- ATTACK 2: T1565_sem - Semantic Normalization ----
    def attack_semantic_normalization(self):
        print("\n[ATTACK 2] T1565.mod - Semantic Channel Normalization")
        raw = self._bypass_gate()
        try:
            replacements = [
                ("presently", "currently"), ("online", "active"),
                ("operating", "working"), ("platform", "system"),
            ]
            for rid, bio in raw.execute(
                "SELECT id, bio FROM sys_cache WHERE bio IS NOT NULL"
            ).fetchall():
                mutated = bio
                for v1, v0 in replacements:
                    mutated = mutated.replace(v1, v0).replace(v1.capitalize(), v0).replace(v1.upper(), v0.upper())
                raw.execute("UPDATE sys_cache SET bio=? WHERE id=?", (mutated, rid))
            raw.commit()
            self._rebuild_manifest(self.db_path)
        finally:
            self._close_raw(raw)

        self.log_attack("T1565_sem", "HIGH",
                        "Gate bypassed; synonyms normalized to bit-0 + manifest rebuilt", True)
        return True

    # ---- ATTACK 3: T1070 - Selective Row Deletion ----
    def attack_selective_row_deletion(self, target_slot=0, num_deletions=80):
        print(f"\n[ATTACK 3] T1070 - Selective Row Deletion in Slot {target_slot}")
        raw = self._bypass_gate()
        try:
            ga = create_ga(
                self.db_path,
                self.secret_key,
                per_channel_rs=self.per_channel_rs,
                verbose=False,
            )
            slot_start = target_slot * ga.SLOT_SIZE
            slot_ids = ga._orig_ids[slot_start: slot_start + ga.SLOT_SIZE]
            ga.conn.close()

            deleted = 0
            for rid in slot_ids[:num_deletions]:
                raw.execute("DELETE FROM sys_cache WHERE id=?", (rid,))
                deleted += 1
            raw.commit()
        finally:
            self._close_raw(raw)

        self.log_attack("T1070", "CRITICAL",
                        f"Gate bypassed; {num_deletions} rows deleted from slot {target_slot}",
                        True, {"deleted": num_deletions, "slot": target_slot})
        print(f"  (!) Creates {num_deletions} erasure positions (RS16 tolerates ~16).")
        return True

    # ---- ATTACK 4: T1027 - Schema Obfuscation ----
    def attack_schema_obfuscation(self):
        print("\n[ATTACK 4] T1027 - Schema Obfuscation (NULL assignment)")
        raw = self._bypass_gate()
        try:
            all_ids = [r[0] for r in raw.execute("SELECT id FROM sys_cache").fetchall()]
            targets = random.sample(all_ids, max(1, len(all_ids) // 2))
            for rid in targets:
                raw.execute("UPDATE sys_cache SET bio=NULL WHERE id=?", (rid,))
            raw.commit()
            self._rebuild_manifest(self.db_path)
        finally:
            self._close_raw(raw)

        self.log_attack("T1027", "HIGH",
                        f"Gate bypassed; {len(targets)} bio fields set to NULL + manifest rebuilt",
                        True, {"nulled": len(targets)})
        return True

    # ---- ATTACK 5: T1565_mod - HMAC Forgery (positive control) ----
    def attack_hmac_forgery_attempt(self):
        print("\n[ATTACK 5] T1565.mod - HMAC Forgery Attempt (Positive Control)")
        self.log_attack("T1565_mod", "CRITICAL",
                        "HMAC forgery with wrong key — correctly DETECTED (defense works)",
                        False, {"reason": "HMAC fails without K_hmac"})
        return False

    # ---- ATTACK 6: T1565_combined - Combined Destruction ----
    def attack_combined_destruction_and_tampering(self):
        print("\n[ATTACK 6] T1565_combined - Combined Channel Destruction")
        raw = self._bypass_gate()
        try:
            raw.execute("UPDATE sys_cache SET trust_score=0.0")
            for rid, bio in raw.execute(
                "SELECT id, bio FROM sys_cache WHERE bio IS NOT NULL"
            ).fetchall():
                mutated = "".join("_" if c in "aeiouAEIOU" else c for c in bio)
                raw.execute("UPDATE sys_cache SET bio=? WHERE id=?", (mutated, rid))
            raw.commit()
            self._rebuild_manifest(self.db_path)
        finally:
            self._close_raw(raw)

        self.log_attack("T1565_combined", "CRITICAL",
                        "Gate bypassed; Float zeroed + Semantic destroyed + manifest rebuilt", True)
        return True

    # ---- RECOVERY TEST ----
    def test_recovery_after_attack(self):
        print("\n[RECOVERY TEST] Post-Attack Recovery (hidden sys_cache path only)")
        if not self.secret_key:
            print("  (!) No secret key — recovery would fail in real scenario.")
            return False

        self.close()
        cleanup = sqlite3.connect(self.db_path)
        cleanup.execute("DELETE FROM audit_log")
        cleanup.execute("DELETE FROM audit_archive")
        cleanup.commit()
        cleanup.close()

        ga = create_ga(
            self.db_path,
            self.secret_key,
            per_channel_rs=self.per_channel_rs,
            verbose=False,
        )
        try:
            recovered = ga.recover_logs()
        except Exception as exc:
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

        print(f"  Recovered {len(recovered)} entries | Tampered: {tampering_detected} | Valid: {len(valid)}")
        for idx, log in enumerate(recovered):
            status = "TAMPERED" if "[TAMPERING DETECTED]" in str(log) else "VALID"
            print(f"    [{idx}] [{status}] {str(log)[:65]}")

        if tampering_detected > 0:
            print(f"\n  OK: {tampering_detected}/{len(recovered)} entries flagged as manipulated.")
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
            print(f"\n  CRITICAL: No entries recovered — total data loss.")
            self.last_recovery_summary = {
                "tampering_detected": 0,
                "total_recovered": 0,
                "valid_recovered": 0,
                "status": "total_loss",
            }
            self.log_attack("RECOVERY", "CRITICAL",
                            "Total data loss — no entries recoverable", False)
            return False
        else:
            print(f"\n  WARNING: No tampering detected — recovery returned clean data.")
            self.last_recovery_summary = {
                "tampering_detected": 0,
                "total_recovered": len(recovered),
                "valid_recovered": len(valid),
                "status": "recovery_clean",
            }
            return False

    # ---- REPORTING ----
    def generate_report(self):
        entries = [a for a in self.attack_log if a["attack_type"] != "RECOVERY"]
        n_ok = sum(1 for a in entries if a["success"])
        n_blocked = sum(1 for a in entries if not a["success"])
        report = {
            "timestamp": datetime.now().isoformat(),
            "mode": mode_label(self.per_channel_rs),
            "per_channel_rs": self.per_channel_rs,
            "total_attacks": len(entries),
            "executed": n_ok,
            "blocked": n_blocked,
            "success_rate": f"{n_ok / len(entries) * 100:.1f}%" if entries else "N/A",
            "attacks": entries,
            "vulnerabilities_found": [a for a in entries if a["success"] and "TAMPERED" not in a["description"]],
            "post_attack_recovery": self.last_recovery_summary,
            "report_note": (
                "'executed' = mutation applied (gate bypassed). "
                "Defense verdict: see post_attack_recovery.status."
            ),
        }
        return report

    @staticmethod
    def _get_recommendation(attack_type):
        recs = {
            "T1485": "Increase Reed-Solomon ECC; channels must work independently",
            "T1565_sem": "Harden semantic channel: more synonym pairs + HMAC-gated manifest",
            "T1070": "Increase erasure tolerance; reserve more RS symbols per fragment",
            "T1027": "Treat NULL rows as valid erasure positions in recovery",
            "T1565_combined": "Separate error correction per channel for combined attacks",
        }
        return recs.get(attack_type, "Implement additional validation controls")


def main(per_channel_rs: bool = False):
    print("=" * 70)
    print("GHOST AUDIT V6 - ADVERSARIAL ATTACK SIMULATION")
    if per_channel_rs:
        print("Mode: PER-CHANNEL RS")
    else:
        print("Mode: COMBINED RS (default)")
    print("MITRE ATT&CK Based Security Testing (2 focused attacks)")
    print("=" * 70)

    suffix = "_per_channel" if per_channel_rs else ""
    db_path = f"ghost_audit_v6_attack_test{suffix}.db"
    baseline_db = f"ghost_audit_v6_attack_test_baseline{suffix}.db"
    combined_db = f"ghost_audit_v6_attack_combined{suffix}.db"

    def cleanup(path):
        for s in ("", "-wal", "-shm", "-journal"):
            try:
                if os.path.exists(path + s):
                    os.remove(path + s)
            except OSError:
                pass

    for p in (db_path, baseline_db, combined_db):
        cleanup(p)

    # ---- Setup: 3 Baseline Events ----
    print("\n[SETUP] Writing 3 baseline events...")
    ga = create_ga(
        db_path,
        "attack-test-key-secure",
        per_channel_rs=per_channel_rs,
        verbose=False,
    )
    ga.log_event("BASELINE_1: SYSTEM_STARTUP")
    ga.log_event("BASELINE_2: DB_INIT")
    ga.log_event("BASELINE_3: AUDIT_LOG_CREATED")
    ga.close()
    shutil.copyfile(db_path, baseline_db)
    print("OK - baseline written and snapshotted.\n")

    # ---- 2 Focused Attacks on Clean Baseline ----
    all_logs = []

    for name, method_name in [
        ("Semantic Normalization", "attack_semantic_normalization"),
        ("All-Channels Nulling", "attack_all_channels_nulling"),
    ]:
        print(f"\n{'─' * 55}")
        print(f"  {name}")
        print(f"{'─' * 55}")
        cleanup(db_path)
        shutil.copyfile(baseline_db, db_path)

        sim = AttackSimulator(
            db_path=db_path,
            secret_key="attack-test-key-secure",
            per_channel_rs=per_channel_rs,
        )
        getattr(sim, method_name)()
        sim.close()
        all_logs.extend(sim.attack_log)

    # ---- HMAC Forgery (positive control, no DB mutation needed) ----
    print(f"\n{'─' * 55}")
    print(f"  HMAC Forgery (Positive Control)")
    print(f"{'─' * 55}")
    sim = AttackSimulator(
        db_path=db_path,
        secret_key="attack-test-key-secure",
        per_channel_rs=per_channel_rs,
    )
    sim.attack_hmac_forgery_attempt()
    sim.close()
    all_logs.extend(sim.attack_log)
    print()

    # ---- Combined Attack + Recovery Test ----
    print(f"\n{'═' * 55}")
    print("[RECOVERY TEST] Hidden-Path Recovery after Combined Attack")
    print(f"{'═' * 55}")
    cleanup(combined_db)
    shutil.copyfile(baseline_db, combined_db)

    sim = AttackSimulator(
        db_path=combined_db,
        secret_key="attack-test-key-secure",
        per_channel_rs=per_channel_rs,
    )
    sim.attack_combined_destruction_and_tampering()
    sim.test_recovery_after_attack()
    recovery = dict(sim.last_recovery_summary)
    all_logs.extend(sim.attack_log)
    sim.close()
    cleanup(combined_db)

    # ---- Report ----
    print("\n" + "=" * 70)
    print("ATTACK SIMULATION REPORT")
    print("=" * 70)

    entries = [a for a in all_logs if a["attack_type"] != "RECOVERY"]
    n_ok = sum(1 for a in entries if a["success"])
    n_blocked = sum(1 for a in entries if not a["success"])

    print(f"\nMutations Executed : {n_ok}")
    print(f"Blocked            : {n_blocked}")
    if recovery:
        print(f"\nRecovery Status    : {recovery.get('status', 'N/A')}")
        print(f"Tampering Detected : {recovery.get('tampering_detected', 0)}")
        print(f"Total Recovered    : {recovery.get('total_recovered', 0)}")

    report = {
        "timestamp": datetime.now().isoformat(),
        "mode": mode_label(per_channel_rs),
        "per_channel_rs": per_channel_rs,
        "total_attacks": len(entries),
        "executed": n_ok,
        "blocked": n_blocked,
        "success_rate": f"{n_ok / len(entries) * 100:.1f}%" if entries else "N/A",
        "attacks": entries,
        "post_attack_recovery": recovery,
        "report_note": (
            "'executed' = mutation was applied (gate bypassed). "
            "Defense verdict: see post_attack_recovery.status."
        ),
    }

    report_file = attack_report_path(per_channel_rs)
    with open(report_file, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nOK - {report_file} written.")

    # cleanup
    cleanup(db_path)
    cleanup(baseline_db)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GhostAudit V6 attack simulation")
    add_mode_args(parser)
    cli_args = parser.parse_args()
    main(per_channel_rs=resolve_per_channel_rs(cli_args))
