"""
Tests for carrier discovery module.

Covers:
- PRAGMA column parsing
- Pattern matching for all carrier roles
- Warning generation for missing carriers
- Edge cases: empty table, no PK, no floats, no integers
"""

import os
import shutil
import sqlite3
import tempfile
from core.discovery import discover_carrier, discover_columns
from core.carrier_config import CarrierConfig


def _make_db(create_sql: str) -> str:
    d = tempfile.mkdtemp()
    db = os.path.join(d, "test.db")
    con = sqlite3.connect(db, timeout=10)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute(create_sql)
    con.commit()
    con.close()
    return db  # caller must cleanup dir


def test_discover_full_schema():
    db = _make_db("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            bio TEXT,
            trust_score REAL,
            profile_score REAL,
            avatar_url TEXT,
            created_at INTEGER,
            ui_prefs INTEGER DEFAULT 0
        )
    """)
    try:
        r = discover_carrier(db, "users")
        cfg = r.suggested_config
        assert cfg["id_field"] == "id"
        assert cfg["float_a_field"] == "trust_score"
        assert cfg["float_b_field"] == "profile_score"
        assert cfg["tilde_field"] == "avatar_url"
        assert cfg["timestamp_field"] == "created_at"
        assert cfg["integer_channel_field"] == "ui_prefs"
        assert cfg["semantic_field"] == "bio"
        assert len(r.warnings) == 0, f"warnings: {r.warnings}"
    finally:
        shutil.rmtree(os.path.dirname(db), ignore_errors=True)


def test_discover_no_pk():
    db = _make_db("CREATE TABLE t (name TEXT, value REAL)")
    try:
        r = discover_carrier(db, "t")
        assert "id_field" not in r.suggested_config
        assert any("id_field" in w for w in r.warnings)
    finally:
        shutil.rmtree(os.path.dirname(db), ignore_errors=True)


def test_discover_no_floats():
    db = _make_db("""
        CREATE TABLE t (
            id INTEGER PRIMARY KEY,
            bio TEXT,
            avatar_url TEXT,
            ui_prefs INTEGER DEFAULT 0
        )
    """)
    try:
        r = discover_carrier(db, "t")
        assert "float_a_field" not in r.suggested_config
        assert any("Float" in w for w in r.warnings)
    finally:
        shutil.rmtree(os.path.dirname(db), ignore_errors=True)


def test_discover_no_integer_channel():
    db = _make_db("""
        CREATE TABLE t (
            id INTEGER PRIMARY KEY,
            bio TEXT,
            trust_score REAL,
            profile_score REAL,
            avatar_url TEXT
        )
    """)
    try:
        r = discover_carrier(db, "t")
        assert "integer_channel_field" not in r.suggested_config
        assert any("Integer" in w for w in r.warnings)
        # Fallback: semantic_field should still be suggested
        assert r.suggested_config.get("semantic_field") == "bio"
    finally:
        shutil.rmtree(os.path.dirname(db), ignore_errors=True)


def test_discover_empty_table():
    d = tempfile.mkdtemp()
    db = os.path.join(d, "empty.db")
    sqlite3.connect(db).close()
    try:
        r = discover_carrier(db, "nonexistent")
        assert any("existiert nicht" in w for w in r.warnings)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_discover_columns_parsing():
    db = _make_db("""
        CREATE TABLE x (
            a INTEGER PRIMARY KEY,
            b TEXT NOT NULL DEFAULT 'hello',
            c REAL
        )
    """)
    try:
        cols = discover_columns(db, "x")
        assert cols[0].name == "a"
        assert cols[0].type == "INTEGER"
        assert cols[0].pk == True
        assert cols[1].notnull == True
        assert cols[1].dflt_value == "'hello'"
        assert cols[2].type == "REAL"
    finally:
        shutil.rmtree(os.path.dirname(db), ignore_errors=True)


def test_discover_generated_config_is_valid():
    db = _make_db("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            bio TEXT,
            trust_score REAL,
            profile_score REAL,
            avatar_url TEXT,
            created_at INTEGER,
            ui_prefs INTEGER DEFAULT 0
        )
    """)
    try:
        r = discover_carrier(db, "users")
        cfg_dict = r.suggested_config
        # Build a real CarrierConfig from suggestions
        cfg = CarrierConfig(
            table="users",
            id_field=cfg_dict["id_field"],
            semantic_field=cfg_dict["semantic_field"],
            float_a_field=cfg_dict["float_a_field"],
            float_b_field=cfg_dict["float_b_field"],
            tilde_field=cfg_dict["tilde_field"],
            timestamp_field=cfg_dict.get("timestamp_field", ""),
            integer_channel_field=cfg_dict.get("integer_channel_field", ""),
        )
        assert cfg.total_carrier_rows == 8000  # default 1600*5
    finally:
        shutil.rmtree(os.path.dirname(db), ignore_errors=True)


if __name__ == "__main__":
    tests = [
        test_discover_full_schema,
        test_discover_no_pk,
        test_discover_no_floats,
        test_discover_no_integer_channel,
        test_discover_empty_table,
        test_discover_columns_parsing,
        test_discover_generated_config_is_valid,
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
