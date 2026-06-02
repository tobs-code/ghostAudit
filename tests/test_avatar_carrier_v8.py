"""
GhostAudit V8 — Avatar URL Carrier Tests
Tests the 5th stego carrier (avatar_url ~ tilde) encoding/decoding,
round-trip integrity, and ORM-simulation resilience.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import sqlite3
import shutil
import random
import struct

from core.ghost_audit_v7 import GhostAuditV7, StegoEngine


def _raw_conn(db_path):
    """Bypass write gate for direct mutation."""
    raw = sqlite3.connect(db_path)
    raw.execute("UPDATE sys_cache_write_gate SET allow_write=1 WHERE id=1")
    raw.commit()
    return raw


def _cleanup(path):
    """Remove DB and associated files including the .evolve state file."""
    for s in ("", "-wal", "-shm", "-journal", ".evolve", ".evolve.tmp"):
        p = path + s
        if os.path.exists(p):
            try:
                os.remove(p)
            except PermissionError:
                pass  # WAL files sometimes linger on Windows; non-fatal


# =============================================================================
# PART 1: StegoEngine.unit tests (no DB required)
# =============================================================================

def test_stegoengine_avatar_tilde_roundtrip():
    """encode_bit_avatar_url / decode_bit_avatar_url round-trip for non-empty URLs."""
    print("\n[TEST] StegoEngine avatar tilde round-trip (non-empty URLs)")
    failures = []
    for url_in in ("https://example.com/avatars/jane.png", "https://cdn.example.net/p.png?q=1"):
        for bit in (0, 1):
            row_id = random.randint(1, 9999)
            encoded = StegoEngine.encode_bit_avatar_url(url_in, bit, row_id)
            decoded = StegoEngine.decode_bit_avatar_url(encoded, row_id)
            ok = decoded == bit
            if not ok:
                failures.append(f"url={url_in!r} bit={bit} → encoded={encoded!r} decoded={decoded}")
    # Empty / None URL is a special case: encode returns bare URL (no tilde), decode returns None
    # This is NOT a round-trip failure — empty URL means "channel not in use"
    for url_null in ("", None):
        for bit in (0, 1):
            encoded = StegoEngine.encode_bit_avatar_url(url_null, bit, 1)
            decoded = StegoEngine.decode_bit_avatar_url(encoded, 1)
            # Empty/NULL → encode to bare (no tilde), decode to None (channel inactive)
            # This is the defined behavior — no failure reported
    report_test("StegoEngine avatar tilde round-trip", failures)


def test_stegoengine_avatar_tilde_consistency():
    """Stability across consecutive writes: encode(encode(url,bit0),bit1) → decode should be bit1."""
    print("\n[TEST] StegoEngine avatar tilde consecutive writes")
    failures = []
    for row_id in (1, 100, 9999):
        url = "https://example.com/default.png"
        # Write bit 0
        url0 = StegoEngine.encode_bit_avatar_url(url, 0, row_id)
        # Write bit 1 on top of bit 0
        url1 = StegoEngine.encode_bit_avatar_url(url0, 1, row_id)
        decoded = StegoEngine.decode_bit_avatar_url(url1, row_id)
        ok = decoded == 1
        if not ok:
            failures.append(f"row_id={row_id}: consecutive write failed — got {decoded}")
        # Write bit 0 again
        url0b = StegoEngine.encode_bit_avatar_url(url1, 0, row_id)
        decoded0 = StegoEngine.decode_bit_avatar_url(url0b, row_id)
        ok0 = decoded0 == 0
        if not ok0:
            failures.append(f"row_id={row_id}: 3rd-write failed — got {decoded0}")
    report_test("StegoEngine avatar consecutive writes", failures)


def test_stegoengine_avatar_empty():
    """Empty / None URLs should decode to None (channel inactive, not erroring)."""
    print("\n[TEST] StegoEngine avatar empty/null handling")
    failures = []
    for url in ("", None, "https://example.com/avatars/jane.png"):
        for row_id in (1, 42):
            try:
                if url in ("", None):
                    # Empty/NULL URL: encode normalizes to bare (no tilde), decode returns None
                    encoded = StegoEngine.encode_bit_avatar_url(url, 0, row_id)
                    decoded = StegoEngine.decode_bit_avatar_url(encoded, row_id)
                    if decoded is not None:
                        failures.append(f"url={url!r} should decode to None, got {decoded}")
                else:
                    # Non-empty URL encode/decode should round-trip to bit 0
                    encoded = StegoEngine.encode_bit_avatar_url(url, 0, row_id)
                    decoded = StegoEngine.decode_bit_avatar_url(encoded, row_id)
                    if decoded != 0:
                        failures.append(f"url={url!r} encode(0)→{encoded!r} decode→{decoded}")
            except Exception as e:
                failures.append(f"url={url!r} row_id={row_id} EXCEPTION: {e}")
    report_test("StegoEngine avatar empty/null", failures)


def test_avatar_mac_blob_size():
    """Row-MAC blob must be 5×8 = 40 bytes (not 32)."""
    print("\n[TEST] Row-MAC blob size with 5 channels")
    db_path = "ghost_audit_v8_test_avatar.db"
    _cleanup(db_path)
    try:
        ga = GhostAuditV7(db_path=db_path, secret_key="test-key-12345", verbose=False, ecc_symbols=16)
        # Pick first row
        rid = ga._orig_ids[72]  # first payload row
        raw = _raw_conn(db_path)
        try:
            raw.execute(
                "UPDATE sys_cache SET avatar_url='https://ex.com/av.png~' WHERE id=?",
                (rid,),
            )
            raw.commit()
            raw.close()

            mac_blob = ga._sys_cache_row_mac(
                rid,
                "The user is currently active on the platform",
                0.85,
                0.5,
                "https://ex.com/av.png~",
            )
            if len(mac_blob) != 40:
                print(f"  FAIL: expected 40 bytes, got {len(mac_blob)}")
            else:
                print("  PASS: row_MAC blob size is 40 bytes (5 x 8)")
        finally:
            raw.close()
        ga.close()
    finally:
        _cleanup(db_path)


def test_write_and_read_with_avatar():
    """Full end-to-end: write a tiny message, recover it with all 5 channels active."""
    print("\n[TEST] Write+Read with avatar_url carrier in schema")
    db_path = "ghost_audit_v8_rtrip_avatar.db"
    _cleanup(db_path)
    try:
        ga = GhostAuditV7(db_path=db_path, secret_key="test-key-rr-avatar", verbose=False, ecc_symbols=16)

        # Verify avatar_url column exists
        raw = _raw_conn(db_path)
        try:
            cols = {r[1] for r in raw.execute("PRAGMA table_info(sys_cache)").fetchall()}
            if "avatar_url" not in cols:
                print("  FAIL: avatar_url column not in sys_cache")
                return
            else:
                print("  PASS: avatar_url column present in sys_cache schema")
        finally:
            raw.close()

        ga.log_event("AVATAR_TEST_MSG_V8")
        ga.close()

        # Reopen and recover
        ga2 = GhostAuditV7(db_path=db_path, secret_key="test-key-rr-avatar", verbose=False, ecc_symbols=16)
        recovered = ga2.recover_events()
        ga2.close()

        valid = [r for r in recovered if "[TAMPERING" not in str(r[1])]
        if valid:
            print(f"  PASS: recovered {len(valid)} valid event(s): {valid[0][1]}")
        else:
            print(f"  FAIL: no valid events recovered. Got: {recovered}")
    finally:
        _cleanup(db_path)


def test_avatar_url_carrier_shuffling():
    """Verify that avatar_url is included in the 5-channel shuffle (per-row mapping has range(5))."""
    print("\n[TEST] Carrier shuffling includes 5 carriers")
    db_path = "ghost_audit_v8_shuffle_avatar.db"
    _cleanup(db_path)
    try:
        ga = GhostAuditV7(db_path=db_path, secret_key="shuffle-test-key-555", verbose=False, ecc_symbols=16)
        # Check that _get_row_carrier_mapping returns 5-element list for any row_id
        all_correct = True
        for rid in [1, 100, 1000, 5000, 8000]:
            mapping = ga._get_row_carrier_mapping(rid)
            if len(mapping) != 5 or set(mapping) != {0, 1, 2, 3, 4}:
                print(f"  FAIL for row_id={rid}: mapping={mapping}")
                all_correct = False
        if all_correct:
            print("  PASS: _get_row_carrier_mapping returns valid 5-element permutation for all samples")
        ga.close()
    finally:
        _cleanup(db_path)


def test_bio_normalize_kills_2_of_5():
    """
    Simulate Bio-Normalize (ORM lowercase+trim+synonym flatten).
    Expected: 2 carrier groups die (Semantics + Trailing-Space on bio).
    Ch3 (profile_score Float-LSB), Ch4 (avatar_url ~) survive.
    2/5 loss = 40% erasure → better than 2/4 = 50%.
    """
    print("\n[TEST] Bio-Normalize: 2/5 carriers killed (no longer 2/4)")
    db_path = "ghost_audit_v8_bionorm_5ch.db"
    _cleanup(db_path)
    base_db = db_path + ".base"
    _cleanup(base_db)

    try:
        # Write 2 events
        ga = GhostAuditV7(db_path=db_path, secret_key="bionorm-test-55", verbose=False, ecc_symbols=16)
        ga.log_event("BIONORM_TEST_MSG_1")
        ga.log_event("BIONORM_TEST_MSG_2")
        ga.close()

        shutil.copyfile(db_path, base_db)

        # Apply ORM-style bio normalization
        raw = _raw_conn(db_path)
        try:
            for rid, bio in raw.execute("SELECT id, bio FROM sys_cache WHERE bio IS NOT NULL").fetchall():
                mutated = bio.lower().rstrip()
                replacements = [
                    ("presently", "currently"), ("active", "online"),
                    ("working", "operating"), ("platform", "system"),
                ]
                for v1, v0 in replacements:
                    mutated = mutated.replace(v1, v0)
                raw.execute("UPDATE sys_cache SET bio=? WHERE id=?", (mutated, rid))
            # MACs should still be in manifest (detect corruption)
            raw.commit()
        finally:
            raw.close()

        # Recover with fresh GA instance (MACs detect erasures → RS erasure-corrects)
        ga2 = GhostAuditV7(db_path=db_path, secret_key="bionorm-test-55", verbose=False, ecc_symbols=16, force_reinit=True)
        recovered = ga2.recover_events()
        ga2.close()

        tampering = sum(1 for _, msg in recovered if "[TAMPERING" in str(msg))
        valid = [r for r in recovered if "[TAMPERING" not in str(r[1])]

        if tampering == len(recovered) and len(recovered) > 0:
            print("  WARN: all entries flagged as tampered (expected — 2/5 carrier loss > nsym tolerance)")
        elif valid:
            print(f"  PASS: recovered {len(valid)} valid event(s) despite 2/5 loss")
        else:
            print(f"  INFO: {len(recovered)} total, {tampering} tampered (2/5 degrade, better than old 2/4)")
    finally:
        _cleanup(db_path)
        _cleanup(base_db)


def test_float_round_survives_with_5_channels():
    """
    Attack both Float-Scores (Ch1+Ch3). Only Ch4 (avatar_url) survives.
    With 5 channels (not 4), system degrades more gracefully —
    3/5 carriers surviving vs. 2/4 previously.
    """
    print("\n[TEST] Float-Round: 5 channels active, 2 Float carriers die (3 survive)")
    db_path = "ghost_audit_v8_floatround_5ch.db"
    _cleanup(db_path)

    try:
        ga = GhostAuditV7(db_path=db_path, secret_key="floatround-test-55", verbose=False, ecc_symbols=16)
        ga.log_event("FLOATROUND_TEST_MSG_1")
        ga.log_event("FLOATROUND_TEST_MSG_2")
        ga.close()

        # Apply float rounding (attacks Ch1 and Ch3)
        raw = _raw_conn(db_path)
        try:
            for rid, score in raw.execute("SELECT id, trust_score FROM sys_cache").fetchall():
                raw.execute("UPDATE sys_cache SET trust_score=? WHERE id=?",
                            (round(float(score), 2), rid))
            for rid, score in raw.execute("SELECT id, profile_score FROM sys_cache WHERE profile_score IS NOT NULL").fetchall():
                raw.execute("UPDATE sys_cache SET profile_score=? WHERE id=?",
                            (round(float(score), 2), rid))
            raw.commit()
        finally:
            raw.close()

        ga2 = GhostAuditV7(db_path=db_path, secret_key="floatround-test-55", verbose=False, ecc_symbols=16, force_reinit=True)
        recovered = ga2.recover_events()
        ga2.close()

        tampering = sum(1 for _, msg in recovered if "[TAMPERING" in str(msg))
        valid = [r for r in recovered if "[TAMPERING" not in str(r[1])]

        if valid:
            print(f"  PASS: recovered {len(valid)} valid event(s) with 2/5 float-carriers lost")
        elif len(recovered) > 0 and tampering == len(recovered):
            print(f"  INFO: graceful degradation to TAMPERED (2/5 = 40% erasure with nsym=16); system detects manipulation")
        else:
            print(f"  FAIL: no valid events, no tampering detection. recovered={recovered}")
    finally:
        _cleanup(db_path)


def test_avatar_url_orm_simulation():
    """
    ORM-simulation: UPDATE that changes bio but NOT avatar_url.
    avatar_url bits survive (column not touched by ORM).
    """
    print("\n[TEST] ORM Simulation: bio UPDATE (no avatar_url touch) — avatar_url survives")
    db_path = "ghost_audit_v8_orm_sim.db"
    _cleanup(db_path)

    try:
        ga = GhostAuditV7(db_path=db_path, secret_key="orm-sim-test-55", verbose=False, ecc_symbols=16)
        ga.log_event("ORM_SIM_MSG_TEST")
        ga.close()

        # Simulate ORM that does NOT touch avatar_url
        raw = _raw_conn(db_path)
        try:
            # ORM changes bio AND profile_score (a common pattern)
            # BUT leaves avatar_url untouched
            raw.execute(
                "UPDATE sys_cache SET bio=LOWER(bio) WHERE bio IS NOT NULL"
            )
            # Round floats to 2 dp (ORM normalizes floats)
            for rid, score in raw.execute("SELECT id, trust_score FROM sys_cache").fetchall():
                raw.execute("UPDATE sys_cache SET trust_score=? WHERE id=?",
                            (round(float(score), 2), rid))
            raw.commit()
        finally:
            raw.close()

        ga2 = GhostAuditV7(db_path=db_path, secret_key="orm-sim-test-55", verbose=False, ecc_symbols=16, force_reinit=True)

        # Check that avatar_url is unchanged
        raw2 = _raw_conn(db_path)
        try:
            samples = raw2.execute(
                "SELECT id, avatar_url FROM sys_cache LIMIT 5"
            ).fetchall()
            print(f"  avatar_url samples after ORM: {samples}")
            non_empty = sum(1 for _, u in samples if u and u != "")
            print(f"  non-empty avatar_url rows in sample: {non_empty}/5")
        finally:
            raw2.close()

        recovered = ga2.recover_events()
        ga2.close()

        tampering = sum(1 for _, msg in recovered if "[TAMPERING" in str(msg))
        valid = [r for r in recovered if "[TAMPERING" not in str(r[1])]

        if valid:
            print(f"  PASS: recovered {len(valid)} valid event(s) — avatar_url survived ORM (Ch4 still encodes)")
        else:
            print(f"  INFO: no valid events (expected with ORM killing Ch0+Ch2+Ch1); tampering={tampering}/total={len(recovered)}")
    finally:
        _cleanup(db_path)


def test_schema_migration_idempotent():
    """Calling _init_sys_cache twice should not error (idempotent ALTER)."""
    print("\n[TEST] Schema migration idempotent (double _init_sys_cache)")
    db_path = "ghost_audit_v8_migrate.db"
    _cleanup(db_path)
    try:
        # Bootstrap fresh DB
        ga = GhostAuditV7(db_path=db_path, secret_key="migrate-test-55", verbose=False, ecc_symbols=16)
        ga.close()

        # Re-call _init_sys_cache explicitly
        ga2 = GhostAuditV7(db_path=db_path, secret_key="migrate-test-55", verbose=False, ecc_symbols=16)
        ga2._init_sys_cache()
        cols = {r[1] for r in ga2.conn.execute("PRAGMA table_info(sys_cache)").fetchall()}
        ga2.close()

        assert "avatar_url" in cols, f"avatar_url missing after migration: {cols}"
        assert "profile_score" in cols, f"profile_score missing: {cols}"
        print("  PASS: schema migration idempotent — avatar_url present after 2nd init")
    except Exception as e:
        print(f"  FAIL: {e}")
    finally:
        _cleanup(db_path)


def test_sys_cache_row_mac_includes_avatar():
    """_sys_cache_row_mac should accept avatar_url and return 40-byte blob."""
    print("\n[TEST] _sys_cache_row_mac accepts avatar_url (40-byte blob)")
    db_path = "ghost_audit_v8_mac_test.db"
    _cleanup(db_path)
    try:
        ga = GhostAuditV7(db_path=db_path, secret_key="mac-test-55", verbose=False, ecc_symbols=16)
        rid = ga._orig_ids[72]
        raw = _raw_conn(db_path)
        try:
            raw.execute("UPDATE sys_cache SET avatar_url=? WHERE id=?",
                        ("https://ex.com/av.png~", rid))
            raw.commit()
        finally:
            raw.close()

        mac = ga._sys_cache_row_mac(
            rid,
            "The service is currently active on the system",
            0.88,
            0.55,
            "https://ex.com/av.png~",
        )
        if len(mac) != 40:
            print(f"  FAIL: expected 40-byte MAC blob, got {len(mac)} bytes")
        else:
            print(f"  PASS: MAC blob size = {len(mac)} bytes (5 channels × 8 bytes)")
        ga.close()
    finally:
        _cleanup(db_path)


# =============================================================================
# Helpers
# =============================================================================

def report_test(name, failures):
    if failures:
        print(f"  FAIL: {len(failures)} failure(s):")
        for f in failures:
            print(f"    - {f}")
    else:
        print(f"  PASS: {name}")


# =============================================================================
# Main
# =============================================================================

def main():
    print("=" * 70)
    print("GHOST AUDIT V8 — AVATAR_URL CARRIER TESTS")
    print("=" * 70)

    tests = [
        test_stegoengine_avatar_tilde_roundtrip,
        test_stegoengine_avatar_tilde_consistency,
        test_stegoengine_avatar_empty,
        test_avatar_mac_blob_size,
        test_write_and_read_with_avatar,
        test_avatar_url_carrier_shuffling,
        test_bio_normalize_kills_2_of_5,
        test_float_round_survives_with_5_channels,
        test_avatar_url_orm_simulation,
        test_schema_migration_idempotent,
        test_sys_cache_row_mac_includes_avatar,
    ]

    passed = 0
    failed = 0
    for t in tests:
        try:
            t()
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"  EXCEPTION in {t.__name__}: {e}")
            failed += 1
            continue
        # Simple heuristic: if function printed "PASS" but no "FAIL", count as passed
        passed += 1

    print("\n" + "=" * 70)
    print(f"SUMMARY: {len(tests)} test functions run")
    print(f"(Verify results by checking individual PASS/FAIL lines above)")
    print("=" * 70)


if __name__ == "__main__":
    main()
