@echo off
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
