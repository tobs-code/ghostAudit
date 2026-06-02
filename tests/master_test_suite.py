#!/usr/bin/env python3
"""
🔴 GHOST AUDIT V6 - MASTER TEST SUITE
Integrated Security Testing & Compliance Validation

Kombiniert:
1. Attack Simulation (MITRE ATT&CK)
2. Resilience Benchmarking
3. Compliance Reporting
4. Metrics Export
"""

import os
import sys
import json
import subprocess
from datetime import datetime
from pathlib import Path

from core.security_suite_support import attack_report_path, metrics_report_path, mode_label


class MasterTestSuite:
    """Orchestriert alle Security-Tests für GhostAudit V6"""
    
    def __init__(self):
        self.results = {}
        self.timestamp = datetime.now().isoformat()
        self.test_dir = Path("security_test_results")
        self.test_dir.mkdir(exist_ok=True)
        
    def run_all_tests(self):
        """Führe kompletten Test-Workflow durch"""
        
        print("\n" + "="*100)
        print("🔴 GHOST AUDIT V6 - MASTER SECURITY TEST SUITE")
        print("="*100)
        print(f"Timestamp: {self.timestamp}")
        print("="*100)
        
        tests = [
            ("attack_simulator_v6.py", "Attack Simulation (combined RS)", ["--combined-rs"]),
            ("resilience_benchmark_v6.py", "Resilience Benchmark (combined RS)", ["--combined-rs"]),
            ("attack_simulator_v6.py", "Attack Simulation (per-channel RS)", ["--per-channel-rs"]),
            ("resilience_benchmark_v6.py", "Resilience Benchmark (per-channel RS)", ["--per-channel-rs"]),
        ]

        for script, description, extra_args in tests:
            run_key = f"{script}{' '.join(extra_args)}".strip()
            print(f"\n[{'='*50}]")
            print(f"Running: {description}")
            print(f"Script: {script} {' '.join(extra_args)}".strip())
            print(f"[{'='*50}]\n")

            try:
                result = subprocess.run(
                    [sys.executable, script, *extra_args],
                    capture_output=False,
                    timeout=300,
                )
                self.results[run_key] = {
                    "status": "PASS" if result.returncode == 0 else "FAIL",
                    "exit_code": result.returncode,
                    "args": extra_args,
                }
            except subprocess.TimeoutExpired:
                print("⚠️  Test timed out after 300 seconds")
                self.results[run_key] = {"status": "TIMEOUT", "exit_code": -1, "args": extra_args}
            except Exception as e:
                print(f"❌ Test failed with exception: {str(e)}")
                self.results[run_key] = {"status": "ERROR", "exit_code": -1, "args": extra_args}
        
        # Generate Final Report
        self._generate_master_report()
    
    def _generate_master_report(self):
        """Erstelle einen umfassenden Master-Report"""
        
        print("\n" + "="*100)
        print("📊 MASTER TEST REPORT - SUMMARY")
        print("="*100)
        
        combined_attack = self._load_json(attack_report_path(False))
        combined_metrics = self._load_json(metrics_report_path(False))
        per_channel_attack = self._load_json(attack_report_path(True))
        per_channel_metrics = self._load_json(metrics_report_path(True))

        master_report = {
            "timestamp": self.timestamp,
            "test_execution_status": self.results,
            "combined_rs": {
                "mode": mode_label(False),
                "attack_simulation": combined_attack,
                "resilience_metrics": combined_metrics,
                **self._assessment_fields(combined_attack, combined_metrics),
            },
            "per_channel_rs": {
                "mode": mode_label(True),
                "attack_simulation": per_channel_attack,
                "resilience_metrics": per_channel_metrics,
                **self._assessment_fields(per_channel_attack, per_channel_metrics),
            },
            "attack_simulation": combined_attack,
            "resilience_metrics": combined_metrics,
            **self._assessment_fields(combined_attack, combined_metrics),
            "recommendations": self._generate_recommendations(
                combined_attack, combined_metrics
            ),
        }
        
        # Display Summary
        print(f"\n✓ Tests Executed: {len(self.results)}")
        passed = sum(1 for r in self.results.values() if r["status"] == "PASS")
        print(f"✓ Passed: {passed}/{len(self.results)}")
        
        for block_name, attack_report, metrics_report, block_key in (
            ("COMBINED RS", combined_attack, combined_metrics, "combined_rs"),
            ("PER-CHANNEL RS", per_channel_attack, per_channel_metrics, "per_channel_rs"),
        ):
            breakdown = master_report[block_key].get("assessment_breakdown", {})
            self._print_mode_summary(block_name, attack_report, metrics_report, breakdown)
        
        # Export Master Report
        report_file = self.test_dir / "master_security_report.json"
        with open(report_file, "w") as f:
            json.dump(master_report, f, indent=2)
        
        print(f"\n✓ Master report saved to: {report_file}")
        
        # Print Recommendations
        print(f"\n🛡️  KEY RECOMMENDATIONS:")
        print("\n🛡️  COMBINED RS — Top recommendations:")
        for idx, rec in enumerate(master_report["combined_rs"]["recommendations"][:3], 1):
            print(f"  {idx}. {rec}")
        print("\n🛡️  PER-CHANNEL RS — Top recommendations:")
        for idx, rec in enumerate(master_report["per_channel_rs"]["recommendations"][:3], 1):
            print(f"  {idx}. {rec}")

        return master_report

    def _assessment_fields(self, attack_report, metrics_report) -> dict:
        breakdown = self._build_assessment(attack_report, metrics_report)
        return {
            "overall_assessment": breakdown["headline"],
            "assessment_breakdown": breakdown,
            "recommendations": self._generate_recommendations(
                attack_report, metrics_report, breakdown
            ),
        }

    def _print_mode_summary(self, block_name, attack_report, metrics_report, breakdown=None):
        print(f"\n{'─'*60}")
        print(f"  {block_name}")
        print(f"{'─'*60}")
        if breakdown:
            print(f"  Gesamt: {breakdown.get('headline', 'N/A')}")
            bench = breakdown.get("benchmark", {})
            post = breakdown.get("post_attack", {})
            print(f"  Benchmark (partielle Korruption, aux-only): {bench.get('grade', 'N/A')} — {bench.get('summary', '')}")
            print(f"  Vollangriff (post-attack): {post.get('grade', 'N/A')} — {post.get('summary', '')}")
        if attack_report:
            hmac_ok = any(
                a.get("attack_type") == "T1565_mod" and not a.get("success")
                for a in attack_report.get("attacks", [])
            )
            print(
                f"  Attacks: {attack_report.get('total_attacks', 'N/A')} | "
                f"Executed: {attack_report.get('executed', 'N/A')} | "
                f"Recovery: {attack_report.get('post_attack_recovery', {}).get('status', 'N/A')} | "
                f"HMAC blockiert: {'ja' if hmac_ok else 'nein'}"
            )
        else:
            print("  Attack report: missing")
        if metrics_report:
            er = metrics_report.get("erasure_tolerance", {}).get("max_erasure_tolerated", "N/A")
            acc = metrics_report.get("recovery_accuracy", {}).get("accuracy_rate", "N/A")
            long_ev = metrics_report.get("long_event_recovery", {})
            if long_ev.get("skipped"):
                long_status = "SKIPPED"
            elif long_ev.get("success"):
                long_status = "PASS"
            elif long_ev.get("success") is False:
                long_status = "FAIL"
            else:
                long_status = "N/A"
            targeted = metrics_report.get("targeted_channel_erasure", {})
            targeted_summary = targeted.get("channels_survived", "n/a")
            print(
                f"  Erasure: {er} | Accuracy: {acc} | Long event: {long_status} | "
                f"Targeted ch. erasure: {targeted_summary}"
            )
        else:
            print("  Metrics report: missing")
    
    def _load_json(self, filename: str):
        """Lade JSON Report"""
        try:
            with open(filename, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            return None
        except Exception as e:
            print(f"⚠️  Could not load {filename}: {str(e)}")
            return None
    
    def _build_assessment(self, attack_report, metrics_report) -> dict:
        """
        Getrennte Bewertung: Benchmark (partielle Korruption) vs. Vollangriff (post-attack).
        total_loss nach Combined Attack ist erwartbar und senkt nicht die Benchmark-Note.
        """
        if not attack_report or not metrics_report:
            return {
                "headline": "INCOMPLETE - Reports missing",
                "benchmark": {"grade": "N/A", "summary": "No metrics"},
                "post_attack": {"grade": "N/A", "summary": "No attack report"},
            }

        accuracy = self._parse_percent(
            metrics_report.get("recovery_accuracy", {}).get("accuracy_rate", "0%")
        )
        erasure = self._parse_percent(
            metrics_report.get("erasure_tolerance", {}).get("max_erasure_tolerated", "0%")
        )
        bit_flip = self._parse_percent(
            metrics_report.get("bit_flip_resistance", {}).get("tolerance", "0%")
        )
        long_ev = metrics_report.get("long_event_recovery", {})
        long_ok = bool(long_ev.get("success")) and not long_ev.get("skipped")

        channel_results = metrics_report.get("channel_isolation", {}).get("results", {})
        channels_survived = sum(1 for s in channel_results.values() if s == "SURVIVED")
        channel_total = len(channel_results) or 4

        targeted = metrics_report.get("targeted_channel_erasure", {})
        targeted_survived = targeted.get("channels_survived", "n/a")

        post = attack_report.get("post_attack_recovery", {})
        recovery_status = post.get("status", "unknown")
        tampering_detected = post.get("tampering_detected", 0)

        hmac_blocked = any(
            a.get("attack_type") == "T1565_mod" and not a.get("success")
            for a in attack_report.get("attacks", [])
        )

        # --- Benchmark (aux-only, controlled corruption) ---
        bench_score = 0
        if accuracy >= 100:
            bench_score += 2
        elif accuracy >= 90:
            bench_score += 1
        if long_ok:
            bench_score += 1
        if erasure >= 15:
            bench_score += 2
        elif erasure >= 5:
            bench_score += 1
        if bit_flip >= 15:
            bench_score += 2
        elif bit_flip >= 5:
            bench_score += 1
        if channels_survived >= 3:
            bench_score += 1
        if metrics_report.get("per_channel_rs") and "4/4" in str(targeted_survived):
            bench_score += 1

        if accuracy < 80:
            bench_grade = "CRITICAL"
            bench_summary = "Aux-Recovery bricht bei leichter Korruption ein."
        elif bench_score >= 5:
            bench_grade = "GOOD"
            bench_summary = (
                f"Stabile aux-Recovery (Erasure {erasure:.0f}%, Bit-Flip {bit_flip:.0f}%, "
                f"Accuracy {accuracy:.0f}%)."
            )
        elif bench_score >= 3:
            bench_grade = "MODERATE"
            bench_summary = (
                f"Funktioniert, aber begrenzte Toleranz (Erasure {erasure:.0f}%, "
                f"Bit-Flip {bit_flip:.0f}%) — eher strikte Detektion als hohe Redundanz."
            )
        else:
            bench_grade = "LOW"
            bench_summary = (
                f"Geringe partielle Toleranz (Erasure {erasure:.0f}%, Bit-Flip {bit_flip:.0f}%)."
            )

        # --- Post-attack (full stego destruction scenario) ---
        if recovery_status == "total_loss":
            post_grade = "EXPECTED"
            post_summary = (
                "Versteckte Spur nach Vollangriff weg — bei zerstoerter sys_cache erwartbar; "
                "sichtbares audit_log separat pruefen."
            )
        elif recovery_status == "detected_tampering":
            post_grade = "GOOD"
            post_summary = f"Manipulation erkannt ({tampering_detected} Eintraege)."
        elif recovery_status == "recovery_clean":
            post_grade = "REVIEW"
            post_summary = "Nach Vollangriff noch saubere Recovery — unerwartet, genauer pruefen."
        else:
            post_grade = "UNKNOWN"
            post_summary = f"Status: {recovery_status}"

        # --- Headline (does not treat total_loss as benchmark failure) ---
        if bench_grade == "CRITICAL":
            headline = "CRITICAL - Aux-Recovery unzuverlaessig"
        elif bench_grade == "GOOD" and post_grade in ("EXPECTED", "GOOD"):
            headline = "GOOD - Benchmark robust; Vollangriff-Verhalten erwartbar"
        elif bench_grade in ("GOOD", "MODERATE") and post_grade == "EXPECTED":
            headline = (
                "MODERATE - Solide Detektion und Kanal-Resilienz; "
                "niedrige partielle Erasure-Toleranz; total_loss nur post-attack"
            )
        elif bench_grade == "LOW":
            headline = "LOW BENCHMARK TOLERANCE - Erhoehe ECC oder Per-Kanal-RS"
        else:
            headline = f"{bench_grade} benchmark / {post_grade} post-attack"

        return {
            "headline": headline,
            "benchmark": {
                "grade": bench_grade,
                "summary": bench_summary,
                "erasure_tolerance": metrics_report.get("erasure_tolerance", {}).get(
                    "max_erasure_tolerated", "N/A"
                ),
                "bit_flip_tolerance": metrics_report.get("bit_flip_resistance", {}).get(
                    "tolerance", "N/A"
                ),
                "recovery_accuracy": metrics_report.get("recovery_accuracy", {}).get(
                    "accuracy_rate", "N/A"
                ),
                "long_event": "PASS" if long_ok else ("SKIPPED" if long_ev.get("skipped") else "FAIL"),
                "channel_isolation": f"{channels_survived}/{channel_total} SURVIVED",
                "targeted_channel_erasure": targeted_survived,
            },
            "post_attack": {
                "grade": post_grade,
                "summary": post_summary,
                "status": recovery_status,
                "tampering_detected": tampering_detected,
            },
            "integrity": {
                "hmac_forgery_blocked": hmac_blocked,
                "attacks_executed": attack_report.get("executed", 0),
                "attacks_blocked": attack_report.get("blocked", 0),
            },
        }

    def _compute_overall_assessment(self, attack_report, metrics_report) -> str:
        """Legacy: nur Headline-Zeile."""
        return self._build_assessment(attack_report, metrics_report)["headline"]

    @staticmethod
    def _parse_percent(value) -> float:
        if value is None:
            return 0.0
        try:
            return float(str(value).rstrip('%'))
        except ValueError:
            return 0.0
    
    def _generate_recommendations(
        self, attack_report, metrics_report, breakdown=None
    ) -> list:
        """Empfehlungen abhängig von Benchmark vs. Post-Attack."""
        recommendations = []

        if not attack_report:
            return ["Run full attack simulation to identify vulnerabilities"]

        if breakdown is None:
            breakdown = self._build_assessment(attack_report, metrics_report)

        bench = breakdown.get("benchmark", {})
        post = breakdown.get("post_attack", {})
        integrity = breakdown.get("integrity", {})

        if bench.get("grade") in ("LOW", "CRITICAL"):
            if metrics_report.get("per_channel_rs"):
                recommendations.append(
                    "Per-Kanal-Erasure unter Ziel — ECC erhoehen oder mehr Slots nutzen"
                )
            else:
                recommendations.append(
                    "Combined RS: geringe aux-Toleranz — ECC 32→64 oder Per-Kanal-RS fuer Produktion"
                )
        elif bench.get("grade") == "MODERATE":
            recommendations.append(
                "Partielle Erasure-Toleranz begrenzt — bei Bedarf Per-Kanal-RS oder mehr Fragment-Slots"
            )

        if post.get("grade") == "EXPECTED":
            recommendations.append(
                "Post-attack total_loss ist kein Benchmark-Fail — Defense-in-Depth: audit_log + Backups"
            )

        if integrity.get("hmac_forgery_blocked"):
            recommendations.append("HMAC-Integritaet wirkt — beibehalten und Keys per Env erzwingen")

        for vuln in attack_report.get("vulnerabilities_found", []):
            recommendations.append(vuln.get("recommendation", "Implement additional controls"))

        if len(recommendations) < 3:
            recommendations.extend([
                "check_integrity() periodisch in Produktion",
                "audit_log und sys_cache getrennt ueberwachen",
                "Master-Report nach Aenderungen neu generieren",
            ])

        seen = set()
        unique = []
        for item in recommendations:
            if item not in seen:
                seen.add(item)
                unique.append(item)
        return unique[:10]


def create_test_runner_script():
    """Erstelle ein einfaches Batch-Test-Script"""
    
    runner_content = """#!/bin/bash
# GhostAudit V6 - Test Runner

echo "🔴 GhostAudit V6 - Test Suite Execution"
echo "======================================"

python ghost_audit_v6.py
python attack_simulator_v6.py --combined-rs
python resilience_benchmark_v6.py --combined-rs
python attack_simulator_v6.py --per-channel-rs
python resilience_benchmark_v6.py --per-channel-rs
python master_test_suite.py

echo "\\n✓ All tests completed!"
"""
    
    with open("run_all_tests.sh", "w", encoding='utf-8') as f:
        f.write(runner_content)
    
    # Windows batch version
    batch_content = """@echo off
REM GhostAudit V6 - Test Runner (Windows)

echo 🔴 GhostAudit V6 - Test Suite Execution
echo ======================================

echo.
echo [1/4] Running V6 base functionality...
python ghost_audit_v6.py

echo.
echo [2/6] Running attack simulator (combined)...
python attack_simulator_v6.py --combined-rs

echo.
echo [3/6] Running resilience benchmark (combined)...
python resilience_benchmark_v6.py --combined-rs

echo.
echo [4/6] Running attack simulator (per-channel RS)...
python attack_simulator_v6.py --per-channel-rs

echo.
echo [5/6] Running resilience benchmark (per-channel RS)...
python resilience_benchmark_v6.py --per-channel-rs

echo.
echo [6/6] Generating master report...
python master_test_suite.py

echo.
echo ✓ All tests completed!
echo View results in security_test_results/ directory
pause
"""
    
    with open("run_all_tests.bat", "w", encoding='utf-8') as f:
        f.write(batch_content)
    
    print("✓ Created: run_all_tests.sh (Linux/Mac)")
    print("✓ Created: run_all_tests.bat (Windows)")


if __name__ == "__main__":
    
    # Create test runner scripts
    create_test_runner_script()
    
    # Run master test suite
    suite = MasterTestSuite()
    suite.run_all_tests()
    
    print("\n" + "="*100)
    print("✓ COMPLETE SECURITY TEST SUITE FINISHED")
    print("="*100)
    print("\nNext Steps:")
    print("1. Review security_test_results/master_security_report.json")
    print("2. Implement recommendations from the report")
    print("3. Re-run tests after implementing fixes")
    print("4. Archive results for compliance documentation")
