"""
Tests for GhostAuditV9 interceptor architecture.

Covers:
- CarrierConfig validation
- SemanticCalibrator fit + encode/decode roundtrip
- _PendingPayload bit draining
- intercept() applies HMAC-shuffled stego overlay, no DB write
- intercept() consumes bits in order
- Calibration shifts synonym distribution
- log_event() + intercept() + recover_events() end-to-end
- pending_bit_count() / pending_event_count()
- V7 pass-through (log_event / recover_events via engine)
"""

import os
import shutil
import sqlite3
import tempfile
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.carrier_config import CarrierConfig, v7_default_config
from core.ghost_audit_v9 import (
    SemanticCalibrator,
    GhostAuditInterceptor,
    _PendingPayload,
    _encode_bit_into_fields,
    _decode_bit_from_fields,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tmpdir():
    d = tempfile.mkdtemp()
    return d


def _make_ga(tmpdir: str, **kwargs) -> GhostAuditInterceptor:
    db = os.path.join(tmpdir, "test.db")
    return GhostAuditInterceptor(
        db_path=db,
        carrier_config=v7_default_config(),
        force_reinit=True,
        verbose=False,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# CarrierConfig
# ---------------------------------------------------------------------------

def test_carrier_config_valid():
    cfg = CarrierConfig(
        table="users",
        id_field="id",
        semantic_field="bio",
        float_a_field="trust_score",
        float_b_field="profile_score",
        tilde_field="avatar_url",
    )
    assert cfg.table == "users"
    assert cfg.payload_rows_per_slot == 1600 - 72
    assert cfg.total_carrier_rows == 1600 * 5


def test_carrier_config_rejects_same_float_fields():
    try:
        CarrierConfig(
            table="users", id_field="id",
            semantic_field="bio",
            float_a_field="score", float_b_field="score",
            tilde_field="avatar_url",
        )
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "float_a_field and float_b_field" in str(e)


def test_v7_default_config():
    cfg = v7_default_config()
    assert cfg.table == "sys_cache"
    assert cfg.float_a_field == "trust_score"


# ---------------------------------------------------------------------------
# SemanticCalibrator
# ---------------------------------------------------------------------------

def test_calibrator_fit_and_roundtrip():
    cal = SemanticCalibrator()
    texts = ["I am currently working here."] * 80 + \
            ["I am presently working here."] * 20
    cal.fit(texts)
    assert cal.dominant(0) == 0          # 'currently' is dominant

    out0 = cal.encode_bit("She is currently active.", 0)
    assert "currently" in out0.lower()

    out1 = cal.encode_bit("She is currently active.", 1)
    assert "presently" in out1.lower()

    assert cal.decode_bit(out0) == 0
    assert cal.decode_bit(out1) == 1


def test_calibrator_unfitted_no_crash():
    cal = SemanticCalibrator()
    out = cal.encode_bit("I am currently working.", 1)
    bit = cal.decode_bit(out)
    assert bit in (0, 1)


def test_calibrator_no_keyword_unchanged():
    cal = SemanticCalibrator()
    cal.fit(["hello world"] * 10)
    assert cal.encode_bit("hello world", 1) == "hello world"


# ---------------------------------------------------------------------------
# _PendingPayload
# ---------------------------------------------------------------------------

def test_pending_payload_drains_correctly():
    # 2 bytes per channel → 16 bits
    channel_blocks = {c: bytes([0b10101010, 0b11001100]) for c in range(5)}
    p = _PendingPayload(channel_blocks, seq=1, nsym=4,
                        stored_msg_len=2, compressed=False)

    assert p.max_bits == 16
    assert not p.exhausted

    bits = []
    while not p.exhausted:
        lb = p.next_logical_bits()
        assert lb is not None
        assert set(lb.keys()) == {0, 1, 2, 3, 4}
        bits.append(lb)

    assert len(bits) == 16
    assert p.exhausted
    assert p.next_logical_bits() is None


# ---------------------------------------------------------------------------
# Bit-level encode/decode helpers
# ---------------------------------------------------------------------------

def test_encode_decode_bit_roundtrip():
    cfg = v7_default_config()
    fields = {
        "bio":           "She is currently working on the system.",
        "trust_score":   0.500000,
        "profile_score": 0.600000,
        "avatar_url":    "http://example.com/pic",
    }
    for bit in (0, 1):
        enc = _encode_bit_into_fields(42, fields, bit, cfg, calibrator=None)
        dec = _decode_bit_from_fields(42, enc, cfg, calibrator=None)
        assert dec == bit, f"Roundtrip failed for bit={bit}"


# ---------------------------------------------------------------------------
# GhostAuditInterceptor — intercept() basics
# ---------------------------------------------------------------------------

def test_intercept_no_pending_passthrough():
    d = _tmpdir()
    try:
        ga = _make_ga(d)
        fields = {"bio": "Hello.", "trust_score": 0.5,
                  "profile_score": 0.6, "avatar_url": "http://x.com"}
        assert ga.intercept(1, fields) == fields
        ga.close()
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_intercept_does_not_write_db():
    """intercept() must return modified fields without touching the DB."""
    d = _tmpdir()
    try:
        ga = _make_ga(d)
        updates = []
        ga._engine.conn.set_trace_callback(
            lambda s: updates.append(s) if s.strip().upper().startswith("UPDATE") else None
        )

        ga.log_event("test event")
        before = len(updates)

        fields = {"bio": "Currently working.", "trust_score": 0.5,
                  "profile_score": 0.5, "avatar_url": "http://x.com"}
        ga.intercept(row_id=1, fields=fields)

        # intercept() itself must not add any UPDATE statements
        assert len(updates) == before, (
            f"intercept() wrote to DB: {updates[before:]}"
        )
        ga._engine.conn.set_trace_callback(None)
        ga.close()
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_intercept_modifies_fields_when_bits_pending():
    d = _tmpdir()
    try:
        ga = _make_ga(d)
        ga.log_event("event that queues bits")
        fields = {"bio": "She is currently active.",
                  "trust_score": 0.5, "profile_score": 0.6,
                  "avatar_url": "http://x.com"}
        result = ga.intercept(row_id=1, fields=fields)
        assert result != fields, "intercept() with pending bits must modify fields"
        ga.close()
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_intercept_drains_queue_over_multiple_calls():
    d = _tmpdir()
    try:
        ga = _make_ga(d)
        ga.log_event("event")
        initial_bits = ga.pending_bit_count()
        assert initial_bits > 0

        fields = {"bio": "Currently working on the system.",
                  "trust_score": 0.5, "profile_score": 0.5,
                  "avatar_url": "http://x.com"}

        # Each intercept call should drain bits
        prev = ga.pending_bit_count()
        for row_id in range(1, 10):
            ga.intercept(row_id=row_id, fields=fields)
            now = ga.pending_bit_count()
            if now == 0:
                break
            assert now <= prev, "pending_bit_count must not increase"
            prev = now

        ga.close()
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_pending_event_count():
    d = _tmpdir()
    try:
        ga = _make_ga(d)
        assert ga.pending_event_count() == 0
        ga.log_event("one")
        assert ga.pending_event_count() == 1
        ga.log_event("two")
        assert ga.pending_event_count() == 2
        ga.close()
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------------------
# Calibration integration
# ---------------------------------------------------------------------------

def test_calibration_shifts_synonym_distribution():
    """After calibration with skewed corpus, bit=0 uses dominant synonym."""
    d = _tmpdir()
    try:
        ga = _make_ga(d)

        # Inject skewed bio texts into sys_cache so calibrate() picks them up
        conn = ga._engine.conn
        conn.execute("PRAGMA journal_mode=WAL")
        # Update a sample of sys_cache rows with biased bios
        bios_dominant = "She is currently working on the platform." * 1
        bios_rare     = "She is presently working on the system." * 1
        rows = conn.execute("SELECT id FROM sys_cache LIMIT 80").fetchall()
        ga._engine._set_sys_cache_write_mode(True)
        for i, (rid,) in enumerate(rows):
            bio = bios_dominant if i < 64 else bios_rare
            conn.execute("UPDATE sys_cache SET bio=? WHERE id=?", (bio, rid))
        conn.commit()
        ga._engine._set_sys_cache_write_mode(False)

        ga.calibrate(sample_size=80)
        assert ga._calibrated

        # After calibration, dominant pair for index 0 should be 0 ('currently')
        assert ga._calibrator.dominant(0) == 0

        ga.close()
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------------------
# End-to-end: log → intercept → recover
# ---------------------------------------------------------------------------

def test_v7_passthrough_log_and_recover():
    """log_events() and recover_events() work through the interceptor."""
    d = _tmpdir()
    try:
        ga = _make_ga(d)
        ga.log_events(["alpha", "beta", "gamma"])
        recovered = ga.recover_events()
        assert len(recovered) == 3
        msgs = [m for _, m in recovered]
        assert "alpha" in msgs
        assert "beta" in msgs
        assert "gamma" in msgs
        ga.close()
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_log_event_returns_sequence_number():
    d = _tmpdir()
    try:
        ga = _make_ga(d)
        seq = ga.log_event("hello")
        assert seq == 1, f"Expected seq=1, got {seq}"
        seq2 = ga.log_event("world")
        assert seq2 == 2
        ga.close()
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_checkpoint_valid_after_log():
    d = _tmpdir()
    try:
        ga = _make_ga(d)
        ga.log_events(["event one", "event two"])
        cp = ga.export_checkpoint()
        result = ga.verify_checkpoint(cp)
        assert result["valid"], f"Checkpoint invalid: {result['details']}"
        assert cp["seq"] == 2
        ga.close()
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    tests = [
        test_carrier_config_valid,
        test_carrier_config_rejects_same_float_fields,
        test_v7_default_config,
        test_calibrator_fit_and_roundtrip,
        test_calibrator_unfitted_no_crash,
        test_calibrator_no_keyword_unchanged,
        test_pending_payload_drains_correctly,
        test_encode_decode_bit_roundtrip,
        test_intercept_no_pending_passthrough,
        test_intercept_does_not_write_db,
        test_intercept_modifies_fields_when_bits_pending,
        test_intercept_drains_queue_over_multiple_calls,
        test_pending_event_count,
        test_calibration_shifts_synonym_distribution,
        test_v7_passthrough_log_and_recover,
        test_log_event_returns_sequence_number,
        test_checkpoint_valid_after_log,
    ]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        except Exception as e:
            import traceback
            print(f"  FAIL  {t.__name__}: {e}")
            traceback.print_exc()
            failed += 1

    print(f"\n{passed}/{passed+failed} passed")
