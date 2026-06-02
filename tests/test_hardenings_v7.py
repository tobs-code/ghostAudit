import os
import json
import sqlite3
from core.ghost_audit_v7 import GhostAuditV7, StegoEngine

def test_all_hardenings():
    db_path = "test_hardenings_v7.db"
    # Remove DB and .evolve state file so V8.3 rollback-detection starts clean
    for suffix in ("", ".evolve", ".evolve.tmp"):
        p = db_path + suffix
        if os.path.exists(p):
            os.remove(p)

    print("=== [V7 HARDENING TEST] ===")
    
    # 1. Initialize GhostAuditV7
    print("[TEST 1] Initializing GhostAuditV7...")
    ga = GhostAuditV7(db_path=db_path, secret_key="test-secure-master-key-v7-987654321")
    
    # 2. Log events
    print("[TEST 2] Logging events...")
    events = [
        "SYS_ALERT: Unauthorized admin login detected.",
        "SYS_EVENT: Backup completed successfully.",
        "SYS_ALERT: Database configuration changed."
    ]
    for ev in events:
        ga.log_event(ev)
        print(f"Logged: {ev}")

    # 3. Test Merkle Tree Root & Anchoring
    print("[TEST 3] Calculating Merkle Root Hash...")
    merkle_root1 = ga.get_verification_digest()
    print(f"Merkle Root Hash (Initial): {merkle_root1}")
    assert len(merkle_root1) == 64, "Invalid Merkle root hash length"

    # Manipulate database to check Merkle tree detection
    print("Simulating minor data manipulation (bypassing write gate)...")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    # Open gate
    cursor.execute("UPDATE sys_cache_write_gate SET allow_write = 1 WHERE id = 1")
    # Change a float score slightly
    cursor.execute("UPDATE sys_cache SET trust_score = trust_score + 0.001 WHERE id = 100")
    # Close gate
    cursor.execute("UPDATE sys_cache_write_gate SET allow_write = 0 WHERE id = 1")
    conn.commit()
    conn.close()

    merkle_root2 = ga.get_verification_digest()
    print(f"Merkle Root Hash (Post-Manipulation): {merkle_root2}")
    assert merkle_root1 != merkle_root2, "Merkle Tree failed to detect manipulation!"
    print("SUCCESS: Merkle Tree successfully detected data tampering!")

    # Restore DB for remaining tests — also remove .evolve so rollback-detection starts fresh
    ga.close()
    for suffix in ("", ".evolve", ".evolve.tmp"):
        p = db_path + suffix
        if os.path.exists(p):
            os.remove(p)
    ga = GhostAuditV7(db_path=db_path, secret_key="test-secure-master-key-v7-987654321", force_reinit=True)
    for ev in events:
        ga.log_event(ev)

    # 4. Test SIEM & Forensic Export (JSONL & CEF)
    print("[TEST 4] Testing Forensic Export...")
    jsonl_path = "exported_logs.jsonl"
    cef_path = "exported_logs.cef"
    
    if os.path.exists(jsonl_path):
        os.remove(jsonl_path)
    if os.path.exists(cef_path):
        os.remove(cef_path)

    ga.export_recovered_logs(jsonl_path, format="jsonl")
    ga.export_recovered_logs(cef_path, format="cef")

    assert os.path.exists(jsonl_path), "JSONL export file not created"
    assert os.path.exists(cef_path), "CEF export file not created"

    # Verify JSONL content
    with open(jsonl_path, "r", encoding="utf-8") as f:
        jsonl_lines = f.readlines()
        assert len(jsonl_lines) == len(events), "JSONL entry count mismatch"
        first_entry = json.loads(jsonl_lines[0])
        assert first_entry["event"] == events[0], "JSONL content mismatch"

    # Verify CEF content
    with open(cef_path, "r", encoding="utf-8") as f:
        cef_lines = f.readlines()
        assert len(cef_lines) == len(events), "CEF entry count mismatch"
        assert "EVENT_RECOVERED" in cef_lines[0], "CEF signature mismatch"

    print("SUCCESS: JSONL and CEF exports verified successfully!")

    # 5. Test LSB-Matching
    print("[TEST 5] Testing Float LSB-Matching...")
    val1 = StegoEngine.encode_bit_float_lsb(0.95, 1, row_id=42)
    val2 = StegoEngine.encode_bit_float_lsb(0.95, 1, row_id=43)
    
    bit1 = StegoEngine.decode_bit_float_lsb(val1)
    bit2 = StegoEngine.decode_bit_float_lsb(val2)
    
    assert bit1 == 1, "LSB-matching decoding failed for row 42"
    assert bit2 == 1, "LSB-matching decoding failed for row 43"
    print("SUCCESS: Float LSB-matching successfully encodes/decodes!")

    # 6. Test Slot-Level Forward Security
    print("[TEST 6] Testing Forward Security slot-keys...")
    key0_shuff, key0_hm = ga._get_slot_keys(0)
    key1_shuff, key1_hm = ga._get_slot_keys(1)
    
    assert key0_shuff != key1_shuff, "Slot shuffling keys must be distinct!"
    assert key0_hm != key1_hm, "Slot HMAC keys must be distinct!"
    print("SUCCESS: Forward-secure slot key evolution verified!")

    # 7. Test Persistent Merkle Root Anchoring & Offline Verification
    print("[TEST 7] Testing Persistent Merkle Root Anchoring...")
    anchors = ga.list_merkle_anchors()
    print(f"Merkle anchors in DB: {len(anchors)}")
    assert len(anchors) == len(events), "Expected one anchor per logged event"
    for i, a in enumerate(anchors):
        print(f"  Anchor #{a['id']}: seq={a['sequence_number']}, root={a['merkle_root'][:16]}...")
        assert len(a['merkle_root']) == 64, f"Anchor {i}: invalid root length"

    latest = ga.get_merkle_anchor(anchors[0]['id'])
    print(f"Latest anchor id={latest['id']}: seq={latest['sequence_number']}, root={latest['merkle_root'][:16]}...")
    assert latest['anchor_mac'], "Missing anchor_mac"
    assert latest['anchor_hash'], "Missing anchor_hash"
    assert latest['prev_anchor_hash'], "Missing prev_anchor_hash"
    print("SUCCESS: Merkle anchors are stored and retrievable!")

    # Verify anchor integrity
    print("[TEST 7b] Verifying anchor integrity...")
    verify_result = ga.verify_merkle_root()
    print(f"  root_match={verify_result['root_match']}, mac_valid={verify_result['mac_valid']}, chain_valid={verify_result['chain_valid']}, hash_valid={verify_result['hash_valid']}, authentic={verify_result['authentic']}")
    assert verify_result['authentic'], f"Anchor authenticity failed: {verify_result}"
    assert verify_result['root_match'], f"Latest anchor root mismatch: {verify_result}"
    assert verify_result['valid'], f"Anchor verification failed: {verify_result}"
    print("SUCCESS: Anchor integrity verified!")

    # Offline verification: close DB, reopen, verify anchors still valid
    print("[TEST 7c] Testing offline verification (close + reopen)...")
    ga.close()
    ga = GhostAuditV7(db_path=db_path, secret_key="test-secure-master-key-v7-987654321")
    offline_anchors = ga.list_merkle_anchors()
    assert len(offline_anchors) == len(events), "Anchors lost after reopen"
    for i in range(len(events)):
        verify_result = ga.verify_merkle_root(offline_anchors[i]['id'])
        assert verify_result['authentic'], f"Anchor {i} inauthentic after reopen: {verify_result}"
    print("SUCCESS: Offline verification passes after reopen!")

    # Tamper detection: manipulate DB, verify anchor detects change
    print("[TEST 7d] Testing tamper detection via Merkle anchor...")
    conn2 = sqlite3.connect(db_path)
    c2 = conn2.cursor()
    c2.execute("UPDATE sys_cache_write_gate SET allow_write = 1 WHERE id = 1")
    c2.execute("UPDATE sys_cache SET trust_score = trust_score + 0.001 WHERE id = 100")
    c2.execute("UPDATE sys_cache_write_gate SET allow_write = 0 WHERE id = 1")
    conn2.commit()
    conn2.close()
    ga.conn.commit()
    verify_result = ga.verify_merkle_root()
    assert not verify_result['root_match'], "Merkle anchor should detect tampering!"
    assert not verify_result['valid'], "Verification should fail after tampering!"
    assert verify_result['authentic'], "Anchor itself should remain authentic (anchor table untouched)"
    print(f"  Current root differs from anchored root: {verify_result['current_root'][:16]}... != {verify_result['stored_root'][:16]}...")
    print("SUCCESS: Merkle anchor successfully detected offline tampering!")

    # 8. Test anchor hash chain integrity
    print("[TEST 8] Testing Merkle anchor hash chain...")
    all_anchors = ga.list_merkle_anchors(limit=100)
    for i in range(len(all_anchors) - 1):
        current = ga.get_merkle_anchor(all_anchors[i]['id'])
        predecessor = ga.get_merkle_anchor(all_anchors[i + 1]['id'])
        assert current['prev_anchor_hash'] == predecessor['anchor_hash'], \
            f"Hash chain broken: anchor {current['id']}.prev != anchor {predecessor['id']}.hash"
    oldest = ga.get_merkle_anchor(all_anchors[-1]['id'])
    assert oldest['prev_anchor_hash'] == "0000000000000000000000000000000000000000000000000000000000000000", \
        "Oldest anchor should have zero prev_anchor_hash"
    print("SUCCESS: Merkle anchor hash chain is intact!")

    # 9. Test optional auto-SIEM-export on each log_event
    print("[TEST 9] Testing auto-SIEM-export on log_event...")
    siem_path = "test_auto_siem.jsonl"
    if os.path.exists(siem_path):
        os.remove(siem_path)
    ga_siem = GhostAuditV7(db_path="test_siem_auto.db", secret_key="test-secure-master-key-v7-987654321", verbose=False, siem_export_path=siem_path)
    siem_events = ["EVENT_A: test one", "EVENT_B: test two", "EVENT_C: test three"]
    for ev in siem_events:
        ga_siem.log_event(ev)
    assert os.path.exists(siem_path), "Auto-SIEM file not created"
    with open(siem_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    assert len(lines) == len(siem_events), f"Expected {len(siem_events)} lines, got {len(lines)}"
    for i, ev in enumerate(siem_events):
        parsed = json.loads(lines[i])
        assert parsed["event"] == ev, f"Line {i}: event mismatch"
        assert parsed["sequence_number"] == i + 1, f"Line {i}: seq mismatch"
        assert parsed["system"] == "GhostAudit", f"Line {i}: system mismatch"
    print(f"  JSONL auto-export: {len(lines)} events written to {siem_path}")
    ga_siem.close()
    if os.path.exists(siem_path):
        os.remove(siem_path)
    if os.path.exists("test_siem_auto.db"):
        os.remove("test_siem_auto.db")

    # 9b. Test CEF auto-export format
    print("[TEST 9b] Testing auto-SIEM-export in CEF format...")
    siem_cef_path = "test_auto_siem.cef"
    if os.path.exists(siem_cef_path):
        os.remove(siem_cef_path)
    ga_siem2 = GhostAuditV7(db_path="test_siem_cef.db", secret_key="test-secure-master-key-v7-987654321", verbose=False, siem_export_path=siem_cef_path, siem_export_format="cef")
    for ev in siem_events:
        ga_siem2.log_event(ev)
    assert os.path.exists(siem_cef_path), "Auto-SIEM CEF file not created"
    with open(siem_cef_path, "r", encoding="utf-8") as f:
        cef_lines = f.readlines()
    assert len(cef_lines) == len(siem_events), f"Expected {len(siem_events)} CEF lines, got {len(cef_lines)}"
    for i, ev in enumerate(siem_events):
        assert "GhostAudit" in cef_lines[i], f"CEF line {i}: missing vendor"
        assert ev in cef_lines[i], f"CEF line {i}: missing event text"
        assert f"seq={i+1}" in cef_lines[i], f"CEF line {i}: missing seq"
    print(f"  CEF auto-export: {len(cef_lines)} events written to {siem_cef_path}")
    ga_siem2.close()
    if os.path.exists(siem_cef_path):
        os.remove(siem_cef_path)
    if os.path.exists("test_siem_cef.db"):
        os.remove("test_siem_cef.db")

    # 10. Test Forward Secrecy: key evolution after each event
    print("[TEST 10] Testing Forward Secrecy key evolution...")
    fs_db = "test_fs_evolution.db"
    if os.path.exists(fs_db):
        os.remove(fs_db)
    ga_fs = GhostAuditV7(db_path=fs_db, secret_key="test-secure-master-key-v7-987654321", verbose=False)
    assert ga_fs._key_evolve_count == 0, "Fresh DB: evolve_count should be 0"
    k0 = bytes(ga_fs._k_write_merkle)
    ga_fs.log_event("Event A")
    assert ga_fs._key_evolve_count == 1, "After 1 event: evolve_count should be 1"
    k1 = bytes(ga_fs._k_write_merkle)
    assert k1 != k0, "Forward secrecy: _k_write_merkle must evolve after event"
    ga_fs.log_event("Event B")
    assert ga_fs._key_evolve_count == 2, "After 2 events: evolve_count should be 2"
    k2 = bytes(ga_fs._k_write_merkle)
    assert k2 != k1, "Forward secrecy: _k_write_merkle must evolve again"
    ga_fs.log_event("Event C")
    assert ga_fs._key_evolve_count == 3, "After 3 events: evolve_count should be 3"
    k3 = bytes(ga_fs._k_write_merkle)
    assert k3 != k2, "Forward secrecy: _k_write_merkle must evolve on third event"
    print(f"  Key evolution: {k0[:4].hex()}... → {k1[:4].hex()}... → {k2[:4].hex()}... → {k3[:4].hex()}...")
    print("SUCCESS: Forward-secure key evolution verified!")

    # Verify old anchors still verifiable after key evolution
    print("[TEST 10b] Testing old anchor verification after key evolution...")
    anchors_fs = ga_fs.list_merkle_anchors()
    for a in anchors_fs:
        vr = ga_fs.verify_merkle_root(a['id'])
        assert vr['authentic'], f"Anchor #{a['id']} (kv={a['key_version']}) should remain authentic: {vr}"
        if vr['is_latest']:
            assert vr['root_match'], f"Latest anchor must have matching root: {vr}"
    print("SUCCESS: All anchors authentic after key evolution!")

    # Re-open and verify catch-up
    print("[TEST 10c] Testing key catch-up on re-open...")
    ga_fs.close()
    ga_fs2 = GhostAuditV7(db_path=fs_db, secret_key="test-secure-master-key-v7-987654321", verbose=False)
    assert ga_fs2._key_evolve_count == 3, f"Re-open: evolve_count should be 3, got {ga_fs2._key_evolve_count}"
    assert bytes(ga_fs2._k_write_merkle) == k3, "Re-open: _k_write_merkle must catch up to last state"
    # Recovery must still work (row MACs use static k_hmac, not affected by evolution)
    recovered = ga_fs2.recover_events()
    assert len(recovered) == 3, f"Recovery after re-open: expected 3 events, got {len(recovered)}"
    assert recovered[0][0] == 1 and "Event A" in recovered[0][1], "First event content mismatch"
    print(f"  Recovered {len(recovered)} events after re-open: {[m for _, m in recovered]}")
    print("SUCCESS: Key catch-up and recovery after re-open work correctly!")
    ga_fs2.close()
    if os.path.exists(fs_db):
        os.remove(fs_db)

    # 11. Test Metronome Heartbeats
    print("[TEST 11] Testing Metronome heartbeats...")
    metro_db = "test_metronome.db"
    if os.path.exists(metro_db):
        os.remove(metro_db)
    ga_m = GhostAuditV7(db_path=metro_db, secret_key="test-secure-master-key-v7-987654321", verbose=False, metronome_interval=3600)
    # First event triggers immediate heartbeat (last_heartbeat_time=0)
    ga_m.log_event("User event 1")
    rec = [(s, m) for s, m in ga_m.recover_events()]
    assert len(rec) == 2, f"Expected 2 events (1 hb + 1 user), got {len(rec)}"
    assert any(m.startswith("[METRONOME]") for _, m in rec), "Should have heartbeat"
    assert ga_m._last_heartbeat_beat == 1, "Beat counter should be 1"
    print(f"  After first event: {len(rec)} events, {sum(1 for _,m in rec if '[METRONOME]' in m)} heartbeat")
    # Fast event: interval (3600s) not elapsed → no heartbeat
    ga_m.log_event("User event 2")
    rec = [(s, m) for s, m in ga_m.recover_events()]
    hb_count = sum(1 for _, m in rec if m.startswith("[METRONOME]"))
    assert hb_count == 1, f"Fast event should NOT trigger heartbeat (have {hb_count})"
    print(f"  After fast event: {len(rec)} events, {hb_count} heartbeats")
    # Force heartbeat by resetting timer, then check it appears
    ga_m._last_heartbeat_time = 0.0
    ga_m.log_event("User event 3")
    rec = [(s, m) for s, m in ga_m.recover_events()]
    hb_count = sum(1 for _, m in rec if m.startswith("[METRONOME]"))
    assert hb_count >= 1, "Should have at least 1 heartbeat after forced timer reset"
    assert any("beat=2" in m for _, m in rec), "Should have beat=2 heartbeat"
    assert ga_m._last_heartbeat_beat == 2, "Beat counter should be 2"
    print(f"  After forced heartbeat: {len(rec)} events, beat=2 heartbeat present")
    print("SUCCESS: Metronome heartbeats work correctly!")

    # 11b. Test truncation detection (uses synthetic event list)
    print("[TEST 11b] Testing truncation detection...")
    complete = [(1, "normal"), (2, "[METRONOME] beat=1"), (3, "normal"), (4, "[METRONOME] beat=2"), (5, "normal"), (6, "[METRONOME] beat=3")]
    truncated = [(1, "normal"), (2, "[METRONOME] beat=1"), (3, "normal"), (6, "[METRONOME] beat=3")]  # missing beat=2 at seq=4-5
    gaps = ga_m.detect_truncation(complete)
    assert len(gaps) == 0, "No gaps expected in complete log"
    gaps = ga_m.detect_truncation(truncated)
    assert len(gaps) == 1, f"Should detect 1 truncation gap, got {len(gaps)}"
    if gaps:
        print(f"  Truncation gap: beat {gaps[0]['from_beat']}→{gaps[0]['to_beat']} ({gaps[0]['missing_beats']} missing)")
    print("SUCCESS: Truncation detection works!")

    # 11c. Test metronome=0 produces no heartbeats
    print("[TEST 11c] Testing metronome=0 produces no heartbeats...")
    ga_m2 = GhostAuditV7(db_path="test_metro_off.db", secret_key="test-secure-master-key-v7-987654321", verbose=False, metronome_interval=0)
    ga_m2.log_event("Normal event")
    recovered = ga_m2.recover_events()
    assert all(not m.startswith("[METRONOME]") for _, m in recovered), "metronome=0 should not create heartbeats"
    print("SUCCESS: metronome=0 correctly disables heartbeats!")
    ga_m2.close()
    if os.path.exists("test_metro_off.db"):
        os.remove("test_metro_off.db")

    ga_m.close()
    if os.path.exists(metro_db):
        os.remove(metro_db)

    # 12. Test Per-Entry MAC Tags
    print("[TEST 12] Testing Per-Entry MAC Tags...")
    mac_db = "test_event_mac.db"
    if os.path.exists(mac_db):
        os.remove(mac_db)
    ga_em = GhostAuditV7(db_path=mac_db, secret_key="test-secure-master-key-v7-987654321", verbose=False)
    mac_events = ["EVENT_1: first entry", "EVENT_2: second entry", "EVENT_3: third entry"]
    for ev in mac_events:
        ga_em.log_event(ev)
    # Verify each event's MAC
    for seq in range(1, 4):
        result = ga_em.verify_event_mac(seq)
        assert result["valid"], f"Event {seq} MAC should be valid: {result}"
    # Verify all at once
    all_results = ga_em.verify_all_event_macs()
    assert len(all_results) == 3, f"Expected 3 results, got {len(all_results)}"
    assert all(r["valid"] for r in all_results), "All event MACs should be valid"
    print(f"  {len(all_results)} event MACs verified: all valid")
    print("SUCCESS: Per-Entry MAC Tags creation and verification works!")

    # 12b. Tamper detection: modify an event in audit_log
    print("[TEST 12b] Testing MAC tag tamper detection...")
    conn = sqlite3.connect(mac_db)
    c = conn.cursor()
    c.execute("UPDATE audit_log SET event_msg = 'EVENT_1: TAMPERED' WHERE sequence_number = 1")
    conn.commit()
    conn.close()
    ga_em.conn.commit()
    r1 = ga_em.verify_event_mac(1)
    r2 = ga_em.verify_event_mac(2)
    assert not r1["valid"], "Tampered event should have invalid MAC"
    assert r2["valid"], "Untampered event should still have valid MAC"
    print(f"  Event 1 (tampered): valid={r1['valid']}, Event 2 (clean): valid={r2['valid']}")
    # Verify non-existent event
    r3 = ga_em.verify_event_mac(999)
    assert not r3["valid"], "Non-existent event should have invalid MAC"
    print("SUCCESS: MAC tag tamper detection works!")

    # 12c. MAC tags survive reopen
    print("[TEST 12c] Testing MAC tags after reopen...")
    ga_em.close()
    ga_em2 = GhostAuditV7(db_path=mac_db, secret_key="test-secure-master-key-v7-987654321", verbose=False)
    r1 = ga_em2.verify_event_mac(1)
    r2 = ga_em2.verify_event_mac(2)
    assert r2["valid"], "MAC should survive reopen for untampered event"
    assert not r1["valid"], "MAC for tampered event should still fail after reopen"
    print(f"  Event 1 (tampered): valid={r1['valid']}, Event 2 (clean): valid={r2['valid']}")
    print("SUCCESS: MAC tags persist after reopen!")
    ga_em2.close()
    if os.path.exists(mac_db):
        os.remove(mac_db)

    # Clean up files
    ga.close()
    if os.path.exists(db_path):
        os.remove(db_path)
    if os.path.exists(jsonl_path):
        os.remove(jsonl_path)
    if os.path.exists(cef_path):
        os.remove(cef_path)
        
    print("\nALL HARDENING TESTS PASSED SUCCESSFULLY! 100% CORRECT!")

if __name__ == "__main__":
    test_all_hardenings()
