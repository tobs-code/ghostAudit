"""
🛡️ GHOST AUDIT V6 - RESILIENCE BENCHMARK FRAMEWORK

Umfassendes Testing-Framework basierend auf:
1. MITRE ATT&CK Mapping
2. Chaos Engineering Principles  
3. Fuzzing-basierte Robustheitstests
4. Quantitative Resilience Metrics

Messgrößen:
- Tamper Detection Rate (TDR): % erkannter Manipulationen
- Data Recovery Rate (DRR): % wiederhergestellter Bits
- Erasure Tolerance (ET): Max. löschbare Bytes ohne Datenverlust
- HMAC Resistance Score: Widerstand gegen Schlüsselfälschung
"""

import sqlite3
import os
import json
import random
import uuid
import string
import argparse
import numpy as np
from typing import Dict, List, Tuple
from core.ghost_audit_v6 import GhostAuditV6
from reedsolo import RSCodec, ReedSolomonError
from core.security_suite_support import (
    add_mode_args,
    clear_visible_audit_trail,
    create_ga,
    metrics_report_path,
    mode_label,
    open_sys_cache_raw,
    resolve_per_channel_rs,
)


class ResilienceBenchmark:
    """Quantitative Resilienz-Metriken für GhostAudit V6"""
    
    def __init__(self, db_path: str, secret_key: str, per_channel_rs: bool = False):
        self.db_path = db_path
        self.secret_key = secret_key
        self.per_channel_rs = per_channel_rs
        self.metrics: Dict = {
            "mode": mode_label(per_channel_rs),
            "per_channel_rs": per_channel_rs,
        }
        
    def run_full_benchmark(self) -> Dict:
        """Führe alle Benchmark-Tests durch"""
        print("\n" + "="*80)
        title = "🛡️  GHOST AUDIT V6 - RESILIENCE BENCHMARK"
        if self.per_channel_rs:
            title += " (PER-CHANNEL RS)"
        print(title)
        print("="*80)

        self.metrics.update({
            "timestamp": str(__import__('datetime').datetime.now()),
            "erasure_tolerance": self._test_erasure_tolerance(),
            "bit_flip_resistance": self._test_bit_flip_resistance(),
            "channel_isolation": self._test_channel_isolation(),
            "key_sensitivity": self._test_key_sensitivity(),
            "recovery_accuracy": self._test_recovery_accuracy(),
            "long_event_recovery": self._test_long_event_recovery(),
        })
        if self.per_channel_rs:
            self.metrics["targeted_channel_erasure"] = self._test_targeted_channel_erasure()

        return self.metrics

    def _make_ga(self, db_path: str, secret_key: str | None = None, verbose: bool = False) -> GhostAuditV6:
        return create_ga(
            db_path,
            secret_key or self.secret_key,
            per_channel_rs=self.per_channel_rs,
            verbose=verbose,
        )

    def _recovery_ga(self, db_path: str, secret_key: str | None = None) -> GhostAuditV6:
        ga = self._make_ga(db_path, secret_key=secret_key, verbose=False)
        clear_visible_audit_trail(ga)
        return ga

    @staticmethod
    def _format_max_success_rate(results: List[Dict], value_key: str) -> str:
        successful_rates = []
        for result in results:
            if result.get("success"):
                rate = result.get(value_key, "").rstrip("%")
                try:
                    successful_rates.append(float(rate))
                except ValueError:
                    continue
        if not successful_rates:
            return "0%"
        return f"{max(successful_rates):.0f}%"

    @staticmethod
    def _safe_remove(path: str):
        if os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass

    @staticmethod
    def _payload_ids_for_slots(ga: GhostAuditV6, slot_count: int) -> List[int]:
        payload_ids = []
        for slot in range(slot_count):
            slot_start = slot * ga.SLOT_SIZE
            slot_ids = ga._orig_ids[slot_start:slot_start + ga.SLOT_SIZE]
            payload_ids.extend(slot_ids[ga.HEADER_BIT_COUNT:])
        return payload_ids

    @staticmethod
    def _channel_payload_ids_for_slots(ga: GhostAuditV6, channel: int, slot_count: int = 1) -> List[int]:
        payload_ids = ResilienceBenchmark._payload_ids_for_slots(ga, slot_count)
        return [
            rid
            for idx, rid in enumerate(payload_ids)
            if idx % ga.CHANNEL_COUNT == channel
        ]

    @staticmethod
    def _temp_db_path(prefix: str) -> str:
        return f"{prefix}_{uuid.uuid4().hex}.db"
    
    def _test_erasure_tolerance(self) -> Dict:
        """
        Test: Wieviele Zeilen können gelöscht werden, bevor Recovery fehlschlägt?
        Metrik: Maximum Erasure Rate (MER)
        """
        print("\n[1/5] Testing Erasure Tolerance...")
        
        results = []
        for deletion_rate in [0.05, 0.10, 0.15, 0.20, 0.25, 0.30]:
            temp_db = self._temp_db_path("temp_erasure_test")
            
            ga_test = self._make_ga(temp_db, verbose=False)
            event_msg = "ERASE_OK" if self.per_channel_rs else "ERASURE_TEST_EVENT"
            ga_test.log_event(event_msg)
            ga_test._set_sys_cache_write_mode(True)
            payload_ids = self._payload_ids_for_slots(ga_test, slot_count=1)
            ga_test.close()
            
            conn = open_sys_cache_raw(temp_db)
            cursor = conn.cursor()

            rows_to_delete = int(len(payload_ids) * deletion_rate)
            ids_to_delete = random.sample(payload_ids, rows_to_delete)
            
            for rid in ids_to_delete:
                cursor.execute("DELETE FROM sys_cache WHERE id=?", (rid,))
            cursor.execute("DELETE FROM audit_log")
            cursor.execute("DELETE FROM audit_archive")
            conn.commit()
            conn.close()  # Close connection
            ga_gate = self._make_ga(temp_db, verbose=False)
            ga_gate._set_sys_cache_write_mode(False)
            ga_gate.close()

            ga_recovery = self._recovery_ga(temp_db)
            try:
                recovered = ga_recovery.recover_logs()
                if recovered is None:
                    success = False
                else:
                    success = len(recovered) > 0 and not any("[TAMPERING DETECTED]" in log for log in recovered)
                results.append({
                    "deletion_rate": f"{deletion_rate*100:.0f}%",
                    "success": success
                })
                print(f"  Deletion Rate {deletion_rate*100:.0f}%: {'✓ RECOVERED' if success else '✗ FAILED'}")
            except Exception as e:
                success = False
                results.append({"deletion_rate": f"{deletion_rate*100:.0f}%", "success": success})
                print(f"  Deletion Rate {deletion_rate*100:.0f}%: ✗ FAILED ({str(e)[:30]})")
            finally:
                ga_recovery.close()
                self._safe_remove(temp_db)
        
        return {
            "description": "Maximum Erasure Rate (MER)",
            "results": results,
            "max_erasure_tolerated": self._format_max_success_rate(results, "deletion_rate")
        }

    def _test_targeted_channel_erasure(self) -> Dict:
        """
        Delete rows of a single stego channel only (idx % 4 == channel).
        Measures whether other channels keep per-channel RS recovery alive.
        """
        print("\n[7/7] Testing Targeted Single-Channel Erasure (per-channel RS only)...")
        channel_names = ["Semantic", "Float LSB", "Trailing Space", "Case-Switching"]
        summary = {}
        deletion_rate = 0.20

        for channel in range(4):
            temp_db = self._temp_db_path("temp_ch_erase")
            ga_test = self._make_ga(temp_db, verbose=False)
            ga_test.log_event("CH_ERASE")
            ch_ids = self._channel_payload_ids_for_slots(ga_test, channel, slot_count=1)
            ga_test.close()

            conn = open_sys_cache_raw(temp_db)
            cursor = conn.cursor()

            rows_to_delete = int(len(ch_ids) * deletion_rate)
            if rows_to_delete > 0:
                rng = random.Random(42 + channel)
                for rid in rng.sample(ch_ids, rows_to_delete):
                    cursor.execute("DELETE FROM sys_cache WHERE id=?", (rid,))
            cursor.execute("DELETE FROM audit_log")
            cursor.execute("DELETE FROM audit_archive")
            conn.commit()
            conn.close()

            ga_recovery = self._recovery_ga(temp_db)
            try:
                recovered = ga_recovery.recover_logs()
                success = bool(recovered) and not any(
                    "[TAMPERING DETECTED]" in log for log in (recovered or [])
                )
            except Exception:
                success = False
            finally:
                ga_recovery.close()
                self._safe_remove(temp_db)

            summary[channel_names[channel]] = "SURVIVED" if success else "DISRUPTED"
            print(
                f"  Channel {channel_names[channel]} @ {deletion_rate*100:.0f}% row loss: "
                f"{'✓ SURVIVED' if success else '✗ DISRUPTED'}"
            )

        survived = sum(1 for status in summary.values() if status == "SURVIVED")
        return {
            "description": "Erasure limited to one channel's carrier rows",
            "deletion_rate": "20%",
            "results": summary,
            "channels_survived": f"{survived}/{len(summary)}",
        }
    
    def _test_bit_flip_resistance(self) -> Dict:
        """
        Test: Wie viele Bit-Flips können toleriert werden?
        Metrik: Bit Error Rate (BER) tolerance
        """
        print("\n[2/5] Testing Bit Flip Resistance...")
        
        results = []
        
        # Fixed seed for reproducibility
        rng = random.Random(42)
        
        for flip_rate in [0.01, 0.05, 0.10, 0.15, 0.20, 0.25, 0.30]:
            temp_db = self._temp_db_path("temp_bitflip_test")
            
            ga_test = self._make_ga(temp_db, verbose=False)
            event_msg = "FLIP_OK" if self.per_channel_rs else "BIT_FLIP_TEST_EVENT"
            ga_test.log_event(event_msg)
            ga_test._set_sys_cache_write_mode(True)
            
            payload_ids = self._payload_ids_for_slots(ga_test, slot_count=1)
            
            # Perform mathematically precise stego bit-flips
            cursor = ga_test.conn.cursor()
            for rid in payload_ids:
                cursor.execute("SELECT bio, trust_score FROM sys_cache WHERE id=?", (rid,))
                res = cursor.fetchone()
                if not res:
                    continue
                bio, score = res
                
                # Decode current stego bits for each of the 4 channels
                semantic = ga_test._decode_channel_bit(0, bio, score) or 0
                float_lsb = ga_test._decode_channel_bit(1, bio, score) or 0
                trailing = ga_test._decode_channel_bit(2, bio, score) or 0
                case = ga_test._decode_channel_bit(3, bio, score) or 0
                
                bits = {0: semantic, 1: float_lsb, 2: trailing, 3: case}
                flipped_any = False
                for c in range(4):
                    if rng.random() < flip_rate:
                        bits[c] = 1 - bits[c]
                        flipped_any = True
                
                if flipped_any:
                    new_bio, new_score = ga_test._encode_all_columns(bio, score, bits)
                    cursor.execute("UPDATE sys_cache SET bio=?, trust_score=? WHERE id=?", (new_bio, new_score, rid))
            
            # Rebuild manifest so rows pass structural integrity but contain flipped stego bits
            ga_test._rebuild_sys_cache_manifest()
            
            # Clear visible audit log to force auxiliary-only recovery
            clear_visible_audit_trail(ga_test)
            ga_test.close()
            
            ga_recovery = self._recovery_ga(temp_db)
            try:
                recovered = ga_recovery.recover_logs()
                if recovered is None:
                    success = False
                else:
                    success = len(recovered) > 0 and not any("[TAMPERING DETECTED]" in log for log in recovered)
                results.append({
                    "flip_rate": f"{flip_rate*100:.0f}%",
                    "success": success
                })
                print(f"  Bit Flip Rate {flip_rate*100:.0f}%: {'✓ RECOVERED' if success else '✗ FAILED'}")
            except Exception as e:
                print(f"  Bit Flip Rate {flip_rate*100:.0f}%: ✗ FAILED ({str(e)[:30]})")
                results.append({"flip_rate": f"{flip_rate*100:.0f}%", "success": False})
            finally:
                ga_recovery.close()
                self._safe_remove(temp_db)
        
        return {
            "description": "Bit Error Rate (BER) Tolerance",
            "results": results,
            "tolerance": self._format_max_success_rate(results, "flip_rate")
        }
    
    def _test_channel_isolation(self) -> Dict:
        """
        Test: Wie robust ist jeder einzelne Kanal?
        Metrik: Per-Channel Resilience Score
        """
        print("\n[3/5] Testing Channel Isolation...")
        
        channels = ["Semantic", "Float LSB", "Trailing Space", "Case-Switching"]
        results = {}
        
        for channel_name in channels:
            temp_db = self._temp_db_path("temp_channel_test")
            
            ga_test = self._make_ga(temp_db, verbose=False)
            if self.per_channel_rs:
                short = {
                    "Semantic": "sem",
                    "Float LSB": "flt",
                    "Trailing Space": "spc",
                    "Case-Switching": "case",
                }
                ga_test.log_event(f"CH_{short[channel_name]}")
            else:
                ga_test.log_event(f"CHANNEL_ISOLATION_TEST: {channel_name}")
            ga_test._set_sys_cache_write_mode(True)
            ga_test.close()
            
            conn = open_sys_cache_raw(temp_db)
            cursor = conn.cursor()

            # Zerstöre spezifischen Kanal
            if channel_name == "Semantic":
                rows = cursor.execute("SELECT id, bio FROM sys_cache").fetchall()
                for rid, bio in rows:
                    # Normalisiere alle Synonyme
                    bio = bio.replace("presently", "currently").replace("Presently", "Currently")
                    bio = bio.replace("online", "active").replace("Online", "Active")
                    cursor.execute("UPDATE sys_cache SET bio=? WHERE id=?", (bio, rid))
            
            elif channel_name == "Float LSB":
                cursor.execute("UPDATE sys_cache SET trust_score = ROUND(trust_score, 2)")
            
            elif channel_name == "Trailing Space":
                rows = cursor.execute("SELECT id, bio FROM sys_cache").fetchall()
                for rid, bio in rows:
                    cursor.execute("UPDATE sys_cache SET bio=? WHERE id=?", (bio.rstrip(), rid))
            
            elif channel_name == "Case-Switching":
                cursor.execute("UPDATE sys_cache SET bio = LOWER(bio)")
            
            conn.commit()
            cursor.execute("DELETE FROM audit_log")
            cursor.execute("DELETE FROM audit_archive")
            conn.close()  # Close connection
            ga_gate = self._make_ga(temp_db, verbose=False)
            ga_gate._set_sys_cache_write_mode(False)
            ga_gate.close()
            
            ga_recovery = self._recovery_ga(temp_db)
            try:
                recovered = ga_recovery.recover_logs()
                integrity_ok = bool(recovered) and not any("[TAMPERING DETECTED]" in log for log in recovered)
                results[channel_name] = "SURVIVED" if integrity_ok else "DISRUPTED"
                print(f"  {channel_name}: {'✓ SURVIVED' if integrity_ok else '✗ DISRUPTED'}")
            except Exception as e:
                results[channel_name] = "FAILED"
                print(f"  {channel_name}: ✗ FAILED ({str(e)[:30]})")
            finally:
                ga_recovery.close()
                self._safe_remove(temp_db)
        
        description = "Per-Channel Resilience (100% corruption of one channel)"
        if self.per_channel_rs:
            interpretation = "Per-channel RS blocks are independent, so 100% corruption of one channel naturally disrupts that block."
        else:
            interpretation = "Combined RS uses majority voting across channels, so surviving channels can vote out a 100% corrupted channel."

        return {
            "description": description,
            "results": results,
            "interpretation": interpretation
        }
    
    def _test_key_sensitivity(self) -> Dict:
        """
        Test: Wie sensitive ist das System auf Key-Änderungen?
        Metrik: Key Avalanche Effect.
        Der korrekte Key muss eine Recovery erlauben, falsche Keys muessen scheitern.
        """
        print("\n[4/5] Testing Key Sensitivity...")
        
        temp_db = self._temp_db_path("temp_key_test")
        
        # Setup mit richtigem Key
        correct_key = "correct-key-12345"
        test_message = (
            "KEY_TEST_OK"
            if self.per_channel_rs
            else "KEY_SENSITIVITY_TEST: Encrypted with correct key"
        )
        ga_correct = self._make_ga(temp_db, secret_key=correct_key)
        ga_correct.log_event(test_message)
        ga_correct.close()
        
        results = []

        # Positive control: Recovery mit dem korrekten Key muss funktionieren
        try:
            ga_good = self._recovery_ga(temp_db, secret_key=correct_key)
            recovered = ga_good.recover_logs()
            ga_good.close()
            success = bool(recovered) and test_message in recovered
            results.append({
                "key": "correct-key-12345",
                "recovery_possible": success,
                "severity": "OK" if success else "CRITICAL"
            })
            print(f"  Key '{correct_key[:20]}...': {'✓ OK - Recovered' if success else '✗ CRITICAL - Could not recover'}")
        except Exception as e:
            results.append({
                "key": "correct-key-12345",
                "recovery_possible": False,
                "severity": "CRITICAL"
            })
            print(f"  Key '{correct_key[:20]}...': ✗ CRITICAL - Recovery errored ({str(e)[:30]})")

        # Versuche Recovery mit falschem Key
        wrong_keys = [
            "wrong-key-12345",
            "correct-key-12346",  # Off-by-one
            "",  # Leerer Key
        ]
        
        for wrong_key in wrong_keys:
            try:
                ga_wrong = self._recovery_ga(temp_db, secret_key=wrong_key)
                recovered = ga_wrong.recover_logs()
                ga_wrong.close()
                if recovered is None:
                    success = False
                else:
                    # Wenn Recovery mit falschem Key funktioniert = SCHWÄCHE
                    success = len(recovered) > 0
                results.append({
                    "key": wrong_key[:15] + "...",
                    "recovery_possible": success,
                    "severity": "CRITICAL" if success else "OK"
                })
                print(f"  Key '{wrong_key[:20]}...': {'✗ CRITICAL - Decrypted!' if success else '✓ OK - Failed as expected'}")
            except Exception as e:
                results.append({
                    "key": wrong_key[:15] + "...",
                    "recovery_possible": False,
                    "severity": "OK"
                })
                print(f"  Key '{wrong_key[:20]}...': ✓ OK - Failed as expected")
        
        self._safe_remove(temp_db)
        
        return {
            "description": "Key Sensitivity / Avalanche Effect",
            "results": results,
            "expected": "Correct key should recover; wrong keys should FAIL"
        }
    
    def _test_recovery_accuracy(self) -> Dict:
        """
        Test: Wie genau ist die Recovery nach Korruption?
        Metrik: Data Integrity Rate (DIR)
        """
        print("\n[5/5] Testing Recovery Accuracy...")
        
        temp_db = self._temp_db_path("temp_accuracy_test")
        
        # Definiere Test-Events
        if self.per_channel_rs:
            # Short payloads: one slot per event (multi-slot reserved for long-event test).
            test_messages = ["ACC_1", "ACC_2", "ACC_3"]
        else:
            test_messages = [
                "ACCURATE_TEST_1: Small event",
                "ACCURATE_TEST_2: This is a medium test message for validation",
                "ACCURATE_TEST_3: " + "X" * 30,
            ]
        
        ga_setup = self._make_ga(temp_db, secret_key="accuracy-test-key")
        original_logs = []
        
        for msg in test_messages:
            ga_setup.log_event(msg)
            original_logs.append(msg)
        ga_setup._set_sys_cache_write_mode(True)
        
        # Limit row IDs to active slots that actually contain test events
        payload_ids = self._payload_ids_for_slots(ga_setup, slot_count=len(test_messages))
        
        ga_setup.close()
        
        # Jetzt introduziere gezielt Korruption und teste Recovery
        conn = open_sys_cache_raw(temp_db)
        cursor = conn.conn.cursor() if hasattr(conn, 'conn') else conn.cursor()

        # Lösche deterministisch eine moderate Menge an Payload-Zeilen der genutzten Slots
        rng = random.Random(42)
        ids_to_delete = rng.sample(payload_ids, max(1, int(len(payload_ids) * 0.05)))
        
        for rid in ids_to_delete:
            cursor.execute("DELETE FROM sys_cache WHERE id=?", (rid,))
        conn.commit()
        conn.close()  # Close connection
        ga_gate = self._make_ga(temp_db, secret_key="accuracy-test-key")
        ga_gate._set_sys_cache_write_mode(False)
        ga_gate.close()

        ga_recovery = self._recovery_ga(temp_db, secret_key="accuracy-test-key")
        recovered_logs = ga_recovery.recover_logs()
        ga_recovery.close()
        
        if recovered_logs is None:
            recovered_logs = []
        
        # Vergleich tolerant gegenüber partieller Recovery
        accuracy = sum(1 for orig in original_logs if orig in recovered_logs)
        
        accuracy_rate = (accuracy / len(original_logs) * 100) if original_logs else 0
        
        print(f"  Original Events: {len(original_logs)}")
        print(f"  Recovered Events: {len(recovered_logs)}")
        print(f"  Accuracy: {accuracy_rate:.1f}%")
        
        self._safe_remove(temp_db)
        
        return {
            "description": "Recovery Accuracy after Corruption",
            "original_events": len(original_logs),
            "recovered_events": len(recovered_logs),
            "accuracy_rate": f"{accuracy_rate:.1f}%",
            "exact_matches": accuracy
        }

    def _test_long_event_recovery(self) -> Dict:
        """
        Test: Kann ein schlecht komprimierbares, langes Event fragmentiert und
        danach exakt wiederhergestellt werden?
        """
        print("\n[6/6] Testing Long Event Recovery...")

        temp_db = self._temp_db_path("temp_long_event_test")
        alphabet = string.ascii_letters + string.digits
        long_event = "LONG_EVENT_TEST: " + "".join(random.choice(alphabet) for _ in range(260))

        ga_setup = self._make_ga(temp_db, secret_key="long-event-test-key", verbose=False)
        ga_setup.log_event(long_event)
        ga_setup.close()

        ga_recovery = self._recovery_ga(temp_db, secret_key="long-event-test-key")
        recovered_logs = ga_recovery.recover_logs()
        ga_recovery.close()

        success = bool(recovered_logs) and long_event in recovered_logs

        print(f"  Long Event Length: {len(long_event)}")
        print(f"  Recovery: {'✓ RECOVERED' if success else '✗ FAILED'}")

        self._safe_remove(temp_db)

        return {
            "description": "Recovery of long, poorly compressible event payloads",
            "event_length": len(long_event),
            "success": success,
            "recovered": long_event if success else None,
        }
    
    def export_metrics(self, filename: str | None = None):
        """Exportiere Benchmark-Ergebnisse"""
        if filename is None:
            filename = metrics_report_path(self.per_channel_rs)
        with open(filename, "w") as f:
            json.dump(self.metrics, f, indent=2)
        print(f"\n✓ Metrics exported to: {filename}")
        return filename


def main():
    """Benchmark Execution"""
    parser = argparse.ArgumentParser(description="GhostAudit V6 resilience benchmark")
    add_mode_args(parser)
    args = parser.parse_args()
    per_channel_rs = resolve_per_channel_rs(args)

    db_path = (
        "ghost_audit_v6_benchmark_per_channel.db"
        if per_channel_rs
        else "ghost_audit_v6_benchmark.db"
    )
    if os.path.exists(db_path):
        os.remove(db_path)

    print("\n[SETUP] Initializing benchmark database...")
    benchmark = ResilienceBenchmark(
        db_path=db_path,
        secret_key="benchmark-secure-key",
        per_channel_rs=per_channel_rs,
    )

    metrics = benchmark.run_full_benchmark()
    benchmark.export_metrics()
    
    # Pretty Print Summary
    print("\n" + "="*80)
    print("📊 RESILIENCE METRICS SUMMARY")
    print("="*80)
    
    for test_name, results in metrics.items():
        if test_name != "timestamp":
            print(f"\n{test_name.upper().replace('_', ' ')}:")
            if isinstance(results, dict) and 'description' in results:
                print(f"  Description: {results['description']}")
                if 'max_erasure_tolerated' in results:
                    print(f"  Max Erasure: {results['max_erasure_tolerated']}")
                if 'accuracy_rate' in results:
                    print(f"  Accuracy Rate: {results['accuracy_rate']}")
                if 'event_length' in results:
                    print(f"  Event Length: {results['event_length']}")
                if 'success' in results:
                    print(f"  Success: {results['success']}")
                if 'results' in results and isinstance(results['results'], dict):
                    for channel, status in results['results'].items():
                        print(f"    - {channel}: {status}")
    
    print("\n" + "="*80)


if __name__ == "__main__":
    main()

