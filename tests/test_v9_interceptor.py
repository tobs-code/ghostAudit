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
    TextShapeCarrier,
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
    kwargs.setdefault("temporal_delay_rows", 0)
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
# TextShapeCarrier
# ---------------------------------------------------------------------------

def test_text_shape_carrier_oxford_roundtrip():
    base = "She works on auth, billing and analytics."
    enc0 = TextShapeCarrier.encode_bit(base, 0)
    enc1 = TextShapeCarrier.encode_bit(base, 1)

    assert enc0.written
    assert enc1.written
    assert TextShapeCarrier.decode_bit(enc0.text) == 0
    assert TextShapeCarrier.decode_bit(enc1.text) == 1
    assert "billing, and analytics" in enc1.text


def test_text_shape_carrier_rejects_unsafe_text():
    base = "She is currently working on the system."
    enc = TextShapeCarrier.encode_bit(base, 1)
    assert not enc.written
    assert enc.text == base
    assert TextShapeCarrier.decode_bit(base) is None


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
        fields = {"bio": "She is currently active on auth, billing and analytics.",
                  "trust_score": 0.5, "profile_score": 0.6,
                  "avatar_url": "http://x.com"}
        result = ga.intercept(row_id=100, fields=fields)
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

        fields = {"bio": "Currently working on auth, billing and analytics.",
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


def test_intercept_result_reports_carrier_gating_without_consuming_bit():
    d = _tmpdir()
    try:
        ga = _make_ga(d)
        ga.log_event("event")
        before = ga.pending_bit_count()

        fields = {"bio": "No safe shape here.",
                  "trust_score": 0.5, "profile_score": 0.5,
                  "avatar_url": "http://x.com"}
        result = ga.intercept_result(row_id=100, fields=fields)

        assert not result.modified
        assert result.reason.startswith("carrier_gating:")
        assert result.fields == fields
        assert ga.pending_bit_count() == before
        ga.close()
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_temporal_delay_defers_initial_payload_rows():
    d = _tmpdir()
    try:
        ga = _make_ga(d, temporal_delay_rows=3)
        chosen = None
        for msg in ["event-a", "event-bb", "event-ccc", "event-dddd"]:
            ga.log_event(msg)
            if ga._payload_queue and ga._payload_queue[0].start_after_rows > 0:
                chosen = msg
                break
            ga._payload_queue.clear()
            ga._completed_payloads.clear()

        assert chosen is not None, "Need a payload with non-zero temporal delay for this test"

        before = ga.pending_bit_count()
        fields = {"bio": "She is currently active on auth, billing and analytics.",
                  "trust_score": 0.5, "profile_score": 0.5,
                  "avatar_url": "http://x.com"}

        r1 = ga.intercept_result(row_id=100, fields=fields)
        r2 = ga.intercept_result(row_id=101, fields=fields)
        assert r1.reason == "temporal_delay"
        assert r2.reason == "temporal_delay" or r2.reason == "embedded"
        assert ga.pending_bit_count() <= before
        ga.close()
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_text_shape_coverage_reports_empirical_ratio():
    d = _tmpdir()
    try:
        db = _make_app_db(d)
        ga = _make_external_ga(db)
        stats = ga.measure_text_shape_coverage(sample_size=200)

        assert stats["sample_size"] > 0
        assert 0.0 <= stats["coverage_ratio"] <= 1.0
        # Our fixture rows all contain a list-like text shape, so the first-cut
        # carrier should be broadly eligible.
        assert stats["coverage_ratio"] > 0.5

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
        # Update enough rows with biased bios so the sample is deterministic.
        bios_dominant = "She is currently working on the platform." * 1
        bios_rare     = "She is presently working on the system." * 1
        rows = conn.execute("SELECT id FROM sys_cache").fetchall()
        ga._engine._set_sys_cache_write_mode(True)
        for i, (rid,) in enumerate(rows):
            bio = bios_dominant if i < int(len(rows) * 0.8) else bios_rare
            conn.execute("UPDATE sys_cache SET bio=? WHERE id=?", (bio, rid))
        conn.commit()
        ga._engine._set_sys_cache_write_mode(False)

        ga.calibrate(sample_size=len(rows))
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
# External carrier table (real app table, no sys_cache created)
# ---------------------------------------------------------------------------

def _make_app_db(tmpdir: str) -> str:
    """Create a realistic 'users' table with enough rows for 1 slot."""
    db_path = os.path.join(tmpdir, "app.db")
    con = sqlite3.connect(db_path)
    con.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            bio TEXT NOT NULL DEFAULT '',
            trust_score REAL NOT NULL DEFAULT 0.5,
            profile_score REAL NOT NULL DEFAULT 0.5,
            avatar_url TEXT NOT NULL DEFAULT ''
        )
    """)
    import random
    rng = random.Random(42)
    bios = [
        "She is currently working on auth, billing and analytics.",
        "He is presently active on search, storage and sync.",
        "The system is currently operating across api, cache and workers.",
        "User is online and working on deploys, metrics and alerts.",
        "Currently focused on database, indexing and migration tasks.",
    ]
    rows = []
    for i in range(1, 1601):  # 1 full slot
        bio = bios[i % len(bios)]
        ts  = max(0.01, min(0.99, rng.gauss(0.75, 0.12)))
        ps  = max(0.01, min(0.99, rng.gauss(0.50, 0.15)))
        av  = f"https://cdn.example.com/avatars/{i}.jpg"
        rows.append((i, bio, ts, ps, av))
    con.executemany("INSERT INTO users VALUES (?,?,?,?,?)", rows)
    con.commit()
    con.close()
    return db_path


def _make_external_ga(db_path: str) -> GhostAuditInterceptor:
    cfg = CarrierConfig(
        table="users",
        id_field="id",
        semantic_field="bio",
        float_a_field="trust_score",
        float_b_field="profile_score",
        tilde_field="avatar_url",
        slot_size=1600,
        slot_count=1,   # 1 slot = 1600 rows, fits our test table
    )
    return GhostAuditInterceptor(
        db_path=db_path,
        carrier_config=cfg,
        force_reinit=True,
        verbose=False,
        temporal_delay_rows=6,
    )


def test_external_carrier_does_not_create_sys_cache():
    """When an external table is used, sys_cache must NOT be created."""
    d = _tmpdir()
    try:
        db = _make_app_db(d)
        ga = _make_external_ga(db)

        con = sqlite3.connect(db)
        tables = {r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        con.close()

        assert "sys_cache" not in tables, (
            f"sys_cache should not exist in external-carrier mode, got: {tables}"
        )
        assert "users" in tables
        assert "audit_log" in tables
        assert "merkle_anchor" in tables
        ga.close()
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_external_carrier_orig_ids_from_real_table():
    """_orig_ids must be populated from real table PKs, not HMAC arithmetic."""
    d = _tmpdir()
    try:
        db = _make_app_db(d)
        ga = _make_external_ga(db)

        # Real PKs are 1..1600
        assert len(ga._engine._orig_ids) == 1600
        assert ga._engine._orig_ids[0] == 1
        assert ga._engine._orig_ids[-1] == 1600
        ga.close()
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_external_carrier_no_write_gate_on_app_table():
    """The app table must not have write-gate triggers attached to it."""
    d = _tmpdir()
    try:
        db = _make_app_db(d)
        ga = _make_external_ga(db)

        con = sqlite3.connect(db)
        triggers = {r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='users'"
        ).fetchall()}
        con.close()

        # GhostAudit must not install gate triggers on the app table
        gate_triggers = {t for t in triggers if "gate" in t.lower()}
        assert not gate_triggers, (
            f"Write-gate triggers must not be on app table 'users': {gate_triggers}"
        )
        ga.close()
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_external_carrier_intercept_and_log():
    """Full flow: log_event → intercept → recover with external app table."""
    d = _tmpdir()
    try:
        db = _make_app_db(d)
        ga = _make_external_ga(db)
        ga.calibrate()

        # Log an event — bits enter the queue
        seq = ga.log_event("user=alice action=login ip=10.0.0.1")
        assert seq == 1
        assert ga.pending_event_count() >= 1

        # Simulate app updating users rows — stego bits get embedded
        con = sqlite3.connect(db)
        rows = con.execute(
            "SELECT id, bio, trust_score, profile_score, avatar_url "
            "FROM users ORDER BY id"
        ).fetchall()

        for row in rows:
            rid, bio, ts, ps, av = row
            fields = {"bio": bio, "trust_score": ts,
                      "profile_score": ps, "avatar_url": av}
            final = ga.intercept(rid, fields)
            con.execute(
                "UPDATE users SET bio=?, trust_score=?, profile_score=?, avatar_url=? WHERE id=?",
                (final["bio"], final["trust_score"],
                 final["profile_score"], final["avatar_url"], rid),
            )
            if ga.pending_bit_count() == 0:
                break
        con.commit()
        con.close()
        assert ga.pending_bit_count() == 0

        # Recovery
        recovered = ga.recover_events()
        assert len(recovered) >= 1
        assert any("alice" in msg for _, msg in recovered)

        ga.close()
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_app_table_write_is_single_statement():
    """After intercept(), the app makes ONE update — no double-write."""
    d = _tmpdir()
    try:
        db = _make_app_db(d)
        ga = _make_external_ga(db)

        ga.log_event("sentinel event")

        updates_on_users = []
        ga._engine.conn.set_trace_callback(
            lambda s: updates_on_users.append(s)
            if "UPDATE" in s.upper() and "users" in s.lower() else None
        )

        fields = {"bio": "She is currently working on the platform.",
                  "trust_score": 0.75, "profile_score": 0.50,
                  "avatar_url": "https://cdn.example.com/1.jpg"}

        before = len(updates_on_users)
        ga.intercept(row_id=1, fields=fields)
        after = len(updates_on_users)

        assert after == before, (
            f"intercept() must not write to DB, saw {after - before} UPDATE(s)"
        )
        ga._engine.conn.set_trace_callback(None)
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
        test_text_shape_carrier_oxford_roundtrip,
        test_text_shape_carrier_rejects_unsafe_text,
        test_pending_payload_drains_correctly,
        test_encode_decode_bit_roundtrip,
        test_intercept_no_pending_passthrough,
        test_intercept_does_not_write_db,
        test_intercept_modifies_fields_when_bits_pending,
        test_intercept_drains_queue_over_multiple_calls,
        test_intercept_result_reports_carrier_gating_without_consuming_bit,
        test_text_shape_coverage_reports_empirical_ratio,
        test_pending_event_count,
        test_calibration_shifts_synonym_distribution,
        test_v7_passthrough_log_and_recover,
        test_log_event_returns_sequence_number,
        test_checkpoint_valid_after_log,
        # External carrier tests
        test_external_carrier_does_not_create_sys_cache,
        test_external_carrier_orig_ids_from_real_table,
        test_external_carrier_no_write_gate_on_app_table,
        test_external_carrier_intercept_and_log,
        test_app_table_write_is_single_statement,
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
