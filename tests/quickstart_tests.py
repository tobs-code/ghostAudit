#!/usr/bin/env python3
"""
🚀 GHOST AUDIT V6 - QUICK START TEST GUIDE

Schnelle Ausführung aller Security-Tests mit klarer Visualisierung
"""

import subprocess
import sys
import os
import json
from pathlib import Path
from datetime import datetime


class QuickStart:
    """Interactive Quick Start für Security Testing"""
    
    TESTS = {
        "1": ("ghost_audit_v6.py", "Base Functionality Test", "Ringbuffer, Persistenz, Per-Kanal aux (Default RS)"),
        "2": ("attack_simulator_v6.py --combined-rs", "Attack Simulation (combined RS)", "MITRE ATT&CK + Recovery"),
        "3": ("resilience_benchmark_v6.py --combined-rs", "Resilience (combined RS)", "Quantitative Metriken"),
        "4": ("attack_simulator_v6.py --per-channel-rs", "Attack Simulation (per-channel RS)", "MITRE ATT&CK"),
        "5": ("resilience_benchmark_v6.py --per-channel-rs", "Resilience (per-channel RS)", "inkl. targeted channel erasure"),
        "6": ("master_test_suite.py", "Complete Security Report", "Alle Modi + Master-JSON"),
    }
    
    def display_menu(self):
        """Zeige interaktives Menü"""
        
        print("\n" + "="*80)
        print("🔴 GHOST AUDIT V6 - SECURITY TEST QUICK START")
        print("="*80)
        print(f"\nTimestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("\nAvailable Tests:")
        print("-"*80)
        
        for key, (script, name, description) in self.TESTS.items():
            print(f"\n  [{key}] {name}")
            print(f"      Script: {script}")
            print(f"      {description}")
        
        print("\n  [all] Run ALL tests in sequence")
        print("  [q] Quit")
        
        print("\n" + "-"*80)
    
    def run_test(self, choice: str):
        """Führe einzelnen Test durch"""
        
        if choice not in self.TESTS and choice != "all":
            print("❌ Invalid choice!")
            return
        
        if choice == "q":
            print("Exiting...")
            sys.exit(0)
        
        if choice == "all":
            for key in ["1", "2", "3", "4", "5", "6"]:
                self.run_test(key)
            return

        entry = self.TESTS[choice]
        script = entry[0]
        name = entry[1]
        
        print(f"\n{'='*80}")
        print(f"▶️  Running: {name}")
        print(f"{'='*80}\n")
        
        try:
            result = subprocess.run([sys.executable, *script.split()])
            
            if result.returncode == 0:
                print(f"\n✓ {name} COMPLETED SUCCESSFULLY")
            else:
                print(f"\n⚠️  {name} finished with issues (exit code: {result.returncode})")
        
        except FileNotFoundError:
            print(f"❌ Script not found: {script}")
        except Exception as e:
            print(f"❌ Error: {str(e)}")
    
    def show_results_summary(self):
        """Zeige Zusammenfassung der Ergebnisse"""
        
        print("\n" + "="*80)
        print("📊 TEST RESULTS SUMMARY")
        print("="*80)
        
        # Prüfe vorhandene Report-Dateien
        reports = [
            ("attack_simulation_report.json", "Attack (combined)"),
            ("attack_simulation_report_per_channel.json", "Attack (per-channel)"),
            ("resilience_metrics.json", "Metrics (combined)"),
            ("resilience_metrics_per_channel.json", "Metrics (per-channel)"),
            ("security_test_results/master_security_report.json", "Master Report"),
        ]
        
        for filepath, title in reports:
            if os.path.exists(filepath):
                try:
                    with open(filepath) as f:
                        data = json.load(f)
                    
                    print(f"\n✓ {title} ({filepath})")
                    
                    # Display relevant metrics
                    if "total_attacks" in data:
                        print(f"  Attacks: {data['total_attacks']} (Success: {data['successful']})")
                    
                    if "vulnerabilities_found" in data:
                        print(f"  Vulnerabilities: {len(data['vulnerabilities_found'])}")
                    
                    if "accuracy_rate" in data:
                        print(f"  Recovery Accuracy: {data['accuracy_rate']}")

                    if "long_event_recovery" in data:
                        long_event = data["long_event_recovery"]
                        if isinstance(long_event, dict):
                            print(f"  Long Event Recovery: {long_event.get('success', 'N/A')}")
                    
                except Exception as e:
                    print(f"⚠️  Could not read {filepath}")
            else:
                print(f"\n✗ {title} not found")
    
    def interactive_session(self):
        """Starte interaktive Test-Session"""
        
        while True:
            self.display_menu()
            
            choice = input("\nSelect test (1-6 / all / q): ").strip().lower()
            
            self.run_test(choice)
            
            if choice != "q":
                cont = input("\n[Enter] Continue, [r] Show Results, [q] Quit: ").strip().lower()
                if cont == "r":
                    self.show_results_summary()
                elif cont == "q":
                    break


def print_architecture_guide():
    """Zeige Architecture & Data Flow"""
    
    architecture = """
┌─────────────────────────────────────────────────────────────────────┐
│                     GHOSTAUDIT V6 ARCHITECTURE                       │
└─────────────────────────────────────────────────────────────────────┘

INPUT (Events to Log)
    │
    ├─→ HMAC Generation (16-byte authentication)
    │   └─→ MAC = HMAC-SHA256(K_hmac, message)
    │
    ├─→ Reed-Solomon ECC (32 symbols = 16 byte error correction)
    │   └─→ encoded_bytes = rs.encode(MAC + message)
    │
    ├─→ 4-Channel Steganographic Embedding:
    │   ├─ Channel 0: Semantic (currently ↔ presently)
    │   ├─ Channel 1: Float LSB (0.123 LSB = bit value)
    │   ├─ Channel 2: Trailing Space (trailing space = 1)
    │   └─ Channel 3: Case-Switching (First char: upper/lower = bit)
    │
    └─→ Secure Shuffling (HMAC-based address randomization)
        └─→ STORE IN 5-SLOT FRAGMENT RINGBUFFER

DATABASE (audit_carrier table with 8000 rows)
    │
    └─→ 5 Slots × 1600 rows each
        ├─ Header (64 bits): Magic + Length + ECC Symbols + Sequence
        └─ Payload: Encoded message fragments + ECC

RECOVERY PROCESS
    │
    ├─→ Extract from all 5 slots and fragment blocks
    ├─→ Sort by sequence number (Chronological order)
    ├─→ Decode 4 channels
    ├─→ Reassemble long-event fragments when needed
    ├─→ Apply Reed-Solomon decoding (with erasure positions)
    ├─→ Verify HMAC
    └─→ Output: Messages [✓ VALID] or [✗ TAMPERING DETECTED]

┌─────────────────────────────────────────────────────────────────────┐
│                        ATTACK VECTORS                               │
└─────────────────────────────────────────────────────────────────────┘

T1485 - Multi-Channel Nulling
  └─ Attacker normalizes: Case → lowercase, Spaces → remove, Float → round
     Impact: Destroys 3/4 channels, forces ECC to recover from 25% loss or fragment pressure

T1565 - Semantic Normalization
  └─ Attacker replaces: "presently" → "currently" (all instances)
     Impact: Destroys semantic channel completely

T1070 - Selective Row Deletion
  └─ Attacker deletes 80-150 rows strategically
     Impact: Creates erasure positions, tests Erasure-Decoding limits

T1027 - Schema Obfuscation
  └─ Attacker sets fields to NULL or changes types
     Impact: Breaks assumptions about data structure

T1565 - HMAC Forgery Attempt
  └─ Attacker tries to forge valid HMAC
     Impact: FAILS (without K_hmac) - TAMPERING DETECTED

┌─────────────────────────────────────────────────────────────────────┐
│                    RESILIENCE METRICS                               │
└─────────────────────────────────────────────────────────────────────┘

1. Erasure Tolerance (MER)
   └─ Question: Max % of rows that can be deleted?
      Target: >25% (Reed-Solomon with 16 symbols)
      Current: ~30% based on testing

2. Bit Flip Resistance (BER)
   └─ Question: Max % of bits that can be corrupted?
      Target: >5%
      Current: ~30% based on testing

If Recovery Accuracy < 90%:
  └─ Add redundancy: Store in 2 different carrier tables

If Tamper Detection is missed:
  └─ Verify HMAC generation: Check K_hmac derivation

If Long Event Recovery fails:
  └─ Check fragment reassembly, header decoding, and slot allocation

If Performance degrades:
  └─ Implement caching for shuffling operations
"""
    
    print(architecture)


if __name__ == "__main__":
    
    # Check if architecture guide should be shown
    if len(sys.argv) > 1 and sys.argv[1] == "--architecture":
        print_architecture_guide()
        sys.exit(0)
    
    # Check if automated mode
    if len(sys.argv) > 1 and sys.argv[1] == "--all":
        print(f"Running all tests automatically...")
        qs = QuickStart()
        for key in ["1", "2", "3", "4"]:
            qs.run_test(key)
        qs.show_results_summary()
        sys.exit(0)
    
    # Start interactive session
    qs = QuickStart()
    qs.interactive_session()
