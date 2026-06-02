#!/bin/bash
# GhostAudit V6 - Test Runner

echo "🔴 GhostAudit V6 - Test Suite Execution"
echo "======================================"

python ghost_audit_v6.py
python attack_simulator_v6.py --combined-rs
python resilience_benchmark_v6.py --combined-rs
python attack_simulator_v6.py --per-channel-rs
python resilience_benchmark_v6.py --per-channel-rs
python master_test_suite.py

echo "\n✓ All tests completed!"
