#!/usr/bin/env python3
"""
Master Test Suite V7: Comprehensive GhostAudit V7 Validation
Combines resilience benchmarks with security testing.
Generates unified JSON report in security_test_results/
"""

import json
import os
import sys
import subprocess
from datetime import datetime
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.resilience_benchmark_v7 import ResilienceBenchmarkV7

class MasterTestSuiteV7:
    def __init__(self, verbose=True):
        self.verbose = verbose
        self.report = {
            "version": "GhostAudit V7",
            "timestamp": datetime.now().isoformat(),
            "components": {}
        }
        self.output_dir = "security_test_results"
        os.makedirs(self.output_dir, exist_ok=True)

    def run_resilience_benchmark(self):
        """Run resilience benchmark V7."""
        if self.verbose:
            print("\n" + "="*70)
            print("PHASE 1: Resilience Benchmark V7")
            print("="*70)

        try:
            benchmark = ResilienceBenchmarkV7(verbose=self.verbose)
            results = benchmark.run_all_tests()
            self.report["components"]["resilience_benchmark"] = results
            return True
        except Exception as e:
            if self.verbose:
                print(f"[ERROR] Resilience benchmark failed: {e}")
            self.report["components"]["resilience_benchmark"] = {
                "status": "FAILED",
                "error": str(e)
            }
            return False

    def run_sanity_checks(self):
        """Run basic sanity checks on V7 core."""
        if self.verbose:
            print("\n" + "="*70)
            print("PHASE 2: Sanity Checks")
            print("="*70)

        test_results = {}
        
        # Test 1: Basic import and instantiation
        try:
            from core.ghost_audit_v7 import GhostAuditV7
            test_results["import_v7"] = "PASS"
            if self.verbose:
                print("[PASS] GhostAuditV7 imports successfully")
        except Exception as e:
            test_results["import_v7"] = f"FAIL: {str(e)}"
            if self.verbose:
                print(f"[FAIL] GhostAuditV7 import failed: {e}")
            return False

        # Test 2: Instantiation with test DB
        try:
            from core.ghost_audit_v7 import GhostAuditV7
            test_db = "sanity_test_v7.db"
            ghost = GhostAuditV7(db_path=test_db, verbose=False)
            test_results["instantiation"] = "PASS"
            if self.verbose:
                print("[PASS] GhostAuditV7 instantiates successfully")
            ghost.close()
            if os.path.exists(test_db):
                os.remove(test_db)
        except Exception as e:
            test_results["instantiation"] = f"FAIL: {str(e)}"
            if self.verbose:
                print(f"[FAIL] Instantiation failed: {e}")
            return False

        # Test 3: Log and recover cycle
        try:
            from core.ghost_audit_v7 import GhostAuditV7
            import traceback
            test_db = "sanity_cycle_v7.db"
            ghost = GhostAuditV7(db_path=test_db, verbose=False)
            test_msg = "Sanity check test message"
            ghost.log_event(test_msg)
            recovered = ghost.recover_events()
            
            found = False
            for seq, msg in recovered:
                if msg == test_msg:
                    found = True
                    break
            
            if found:
                test_results["log_recover_cycle"] = "PASS"
                if self.verbose:
                    print("[PASS] Log and recover cycle works")
            else:
                test_results["log_recover_cycle"] = "FAIL: Message not recovered"
                if self.verbose:
                    print("[FAIL] Message not recovered in cycle test")
            
            ghost.close()
            if os.path.exists(test_db):
                os.remove(test_db)
        except Exception as e:
            test_results["log_recover_cycle"] = f"FAIL: {str(e)}"
            if self.verbose:
                print(f"[FAIL] Log/recover cycle failed: {e}")
                import traceback
                traceback.print_exc()
            return False

        # Test 4: Row-level shuffling
        try:
            from core.ghost_audit_v7 import GhostAuditV7
            ghost = GhostAuditV7(db_path=":memory:", verbose=False)
            
            # Test shuffling determinism
            mapping1 = ghost._get_row_carrier_mapping(row_id=1)
            mapping2 = ghost._get_row_carrier_mapping(row_id=1)
            
            if mapping1 == mapping2:
                test_results["row_shuffling_determinism"] = "PASS"
                if self.verbose:
                    print("[PASS] Row-level shuffling is deterministic")
            else:
                test_results["row_shuffling_determinism"] = "FAIL: Non-deterministic mapping"
                if self.verbose:
                    print("[FAIL] Row-level shuffling is non-deterministic")
            
            ghost.close()
        except Exception as e:
            test_results["row_shuffling_determinism"] = f"FAIL: {str(e)}"
            if self.verbose:
                print(f"[FAIL] Shuffling test failed: {e}")

        # Test 5: XOR parity computation
        try:
            from core.ghost_audit_v7 import GhostAuditV7
            ghost = GhostAuditV7(db_path=":memory:", verbose=False)
            
            # Test XOR parity
            ch_bytes = {
                0: b"\x01\x02",
                1: b"\x03\x04",
                2: b"\x05\x06"
            }
            
            ghost._orig_ids = list(range(8000))
            ghost._orig_id_to_idx = {rid: idx for idx, rid in enumerate(range(8000))}
            parity = ghost._compute_p_parity(ch_bytes)
            
            # Verify: P = C0 XOR C1 XOR C2
            expected = bytes([0x01 ^ 0x03 ^ 0x05, 0x02 ^ 0x04 ^ 0x06])
            if parity == expected:
                test_results["xor_parity"] = "PASS"
                if self.verbose:
                    print("[PASS] XOR parity computation is correct")
            else:
                test_results["xor_parity"] = "FAIL: Incorrect parity"
                if self.verbose:
                    print("[FAIL] XOR parity is incorrect")
            
            ghost.close()
        except Exception as e:
            test_results["xor_parity"] = f"FAIL: {str(e)}"
            if self.verbose:
                print(f"[FAIL] Parity test failed: {e}")

        self.report["components"]["sanity_checks"] = test_results
        
        passed = sum(1 for v in test_results.values() if v == "PASS")
        total = len(test_results)
        
        if self.verbose:
            print(f"\nSanity Checks: {passed}/{total} passed")
        
        return passed == total

    def generate_final_report(self):
        """Generate unified final report."""
        if self.verbose:
            print("\n" + "="*70)
            print("FINAL REPORT GENERATION")
            print("="*70)

        # Compute overall statistics
        all_status = []
        
        if "sanity_checks" in self.report["components"]:
            checks = self.report["components"]["sanity_checks"]
            all_status.extend([v == "PASS" for v in checks.values()])
        
        if "resilience_benchmark" in self.report["components"]:
            benchmark = self.report["components"]["resilience_benchmark"]
            if "tests" in benchmark:
                all_status.extend([
                    test_data.get("status") == "PASS"
                    for test_data in benchmark["tests"].values()
                ])

        self.report["overall_status"] = "PASS" if all(all_status) else "FAIL"
        self.report["overall_pass_rate"] = sum(all_status) / len(all_status) if all_status else 0.0

        # Save report
        report_file = os.path.join(self.output_dir, "master_security_report_v7.json")
        with open(report_file, "w") as f:
            json.dump(self.report, f, indent=2)

        if self.verbose:
            print(f"\n[REPORT SAVED] {report_file}")
            print(f"Overall Status: {self.report['overall_status']}")
            print(f"Overall Pass Rate: {self.report['overall_pass_rate']:.1%}")

        return self.report

    def run(self):
        """Execute complete master test suite."""
        if self.verbose:
            print("\n" + "="*70)
            print("GhostAudit V7: Master Test Suite")
            print("Orthogonal Grid Defense - Comprehensive Validation")
            print("="*70)

        try:
            # Run sanity checks
            sanity_ok = self.run_sanity_checks()
            
            # Run resilience benchmark
            bench_ok = self.run_resilience_benchmark()
            
            # Generate final report
            self.generate_final_report()
            
            if self.verbose:
                print("\n" + "="*70)
                print("TEST SUITE COMPLETE")
                print("="*70)
            
            return self.report
        
        except Exception as e:
            if self.verbose:
                print(f"\n[CRITICAL ERROR] Test suite failed: {e}")
            self.report["error"] = str(e)
            return self.report


if __name__ == "__main__":
    suite = MasterTestSuiteV7(verbose=True)
    report = suite.run()
    
    # Exit with appropriate code
    sys.exit(0 if report.get("overall_status") == "PASS" else 1)
