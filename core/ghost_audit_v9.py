"""
GhostAudit V9 — Interceptor Architecture

Key differences from V7
-----------------------
1. **No synthetic carrier table.**  The caller supplies an existing application
   table via ``CarrierConfig``.  GhostAudit reads existing rows and writes
   minimal overlays on top of real app data.

2. **Interceptor API — timing-safe single-write embedding.**
   The app calls ``ga.intercept(row_id, fields)`` *before* its own UPDATE,
   receives back the field dict with stego overlays applied, and uses *that*
   dict for the single DB write.  One UPDATE per row — no timing anomaly in
   the WAL journal, no double-write pattern detectable by an analyst.

3. **Corpus-calibrated synonym encoding.**  ``SemanticCalibrator`` learns
   synonym frequencies from existing rows so the stego distribution matches
   the real app distribution.  50/50 split becomes invisible.

4. **Configurable carrier layout.**  All table/field names come from
   ``CarrierConfig`` — nothing is hardcoded.

5. **Full ECC/RAID-6 reused from V7.**  ``log_event()`` encodes the event
   payload with Reed-Solomon + RAID-6 P+Q parity and enqueues the resulting
   bits.  ``intercept()`` drains that queue one bit-tuple per app write.
   ``recover_events()`` reads the carrier table and decodes via the same V7
   extraction path.

Everything else (HMAC-shuffling, forward secrecy, Merkle anchors, rollback
detection, checkpoints) is provided by the embedded V7 engine unchanged.

Status: V9 is under active development.  V7 standalone mode is unaffected.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import os
import re
import random
import time
import threading
import sqlite3
import struct
import zlib
from typing import Any, NamedTuple

from core.carrier_config import CarrierConfig, v7_default_config
from core.ghost_audit_v7 import GhostAuditV7, StegoEngine
from core.timestamp_witness import TimestampWitness
from reedsolo import RSCodec, ReedSolomonError


@dataclass(frozen=True)
class EncodeResult:
    text: str
    written: bool
    reason: str = ""
    carrier_family: str = ""


@dataclass(frozen=True)
class InterceptResult:
    fields: dict[str, Any]
    modified: bool
    reason: str = ""
    row_id: Any = None


class QueueOverflowError(RuntimeError):
    """Raised when the pending stego queue is full and cannot accept new events."""
    pass


# ---------------------------------------------------------------------------
# V9 Engine — GhostAuditV7 subclass that uses an external carrier table
# ---------------------------------------------------------------------------

class _V9Engine(GhostAuditV7):
    """GhostAuditV7 with a patched _setup_db that skips carrier-table
    creation when an external app table is used as carrier.

    In external-carrier mode:
    - The carrier table (e.g. 'users') already exists with real app data.
    - We must NOT create it, populate it with synthetic rows, or attach
      write-gate triggers to it (the app needs unrestricted write access).
    - All internal GhostAudit tables (audit_log, merkle_anchor, etc.) are
      still created as normal.
    - _orig_ids is populated from the actual carrier table row IDs rather
      than HMAC-stepped arithmetic.
    """

    # Set by GhostAuditInterceptor before instantiation
    _external_carrier: bool = False
    _carrier_config: "CarrierConfig | None" = None

    def __init__(self, *args, **kwargs):
        # Extract params needed before super().__init__
        self.force_reinit = kwargs.get("force_reinit", False)
        self.verbose = kwargs.get("verbose", False)

        # Pop slot_size / slot_count — GhostAuditV7 does not accept them,
        # they are class-level constants on V7 and we set them on the
        # instance *after* super().__init__ to override the defaults.
        self._init_slot_size = kwargs.pop("slot_size", None)
        self._init_slot_count = kwargs.pop("slot_count", None)

        # Patch AUX_TABLE on the *instance* before super().__init__ calls
        # _setup_db, so every table reference inside _setup_db is correct.
        if type(self)._external_carrier and type(self)._carrier_config:
            self.AUX_TABLE = type(self)._carrier_config.table

        # Initialize float_scale BEFORE super().__init__ because super().__init__
        # calls _setup_db -> _rebuild_sys_cache_manifest -> _decode_channel_bit.
        self.float_scale = 1000000
        self.semantic_calibrator = None # Set by Interceptor
        super().__init__(*args, **kwargs)

        # Apply the slot configuration that the caller (Interceptor) requested.
        if self._init_slot_size is not None:
            self.SLOT_SIZE = self._init_slot_size
        if self._init_slot_count is not None:
            self.SLOT_COUNT = self._init_slot_count

    def _decode_channel_bit(self, channel: int, bio: str, score: float,
                            profile_score: float = 0.0, avatar_url: str = "",
                            timestamp_value: int = 0):
        """Decode a bit from physical carrier (0-4), matching V9 carriers."""
        if channel == 0:      # Data: Semantic (bio synonym switching)
            if self.semantic_calibrator and self.semantic_calibrator._fitted:
                bit = self.semantic_calibrator.decode_bit(bio)
                return bit if bit is not None else 0
            return StegoEngine.decode_bit_semantic(bio)
        elif channel == 1:    # Data: Float-LSB (trust_score)
            return StegoEngine.decode_bit_float_lsb(score, scale=self.float_scale)
        elif channel == 2:    # Data: Timestamp-LSB (or TextShape fallback)
            if self._carrier_config and self._carrier_config.timestamp_field:
                return StegoEngine.decode_bit_float_lsb(float(timestamp_value), scale=1)
            bit = TextShapeCarrier.decode_bit(bio)
            return bit if bit is not None else 0
        elif channel == 3:    # P Parity: Float-LSB (profile_score)
            return StegoEngine.decode_bit_float_lsb(profile_score, scale=self.float_scale)
        elif channel == 4:    # Q Parity: Avatar Tilde (~)
            return StegoEngine.decode_bit_avatar_url(avatar_url, row_id=0)
        raise ValueError(f"Unknown channel: {channel}")

    def _encode_channel_bit(self, channel: int, bio: str, score: float, bit: int,
                            row_id=None, profile_score: float = 0.0,
                            avatar_url: str = ""):
        """Encode a bit to physical carrier (0-4), matching V9 carriers.

        NOTE: Channel 2 (timestamp LSB) is handled by the Interceptor's
        intercept_result() path. This engine-level override keeps TextShape
        fallback for V7 compatibility paths.
        """
        if channel == 0:      # Data: Semantic (bio)
            return StegoEngine.encode_bit_semantic(bio, bit), score, profile_score, avatar_url
        elif channel == 1:    # Data: Float-LSB (trust_score)
            return bio, StegoEngine.encode_bit_float_lsb(score, bit, row_id=row_id, scale=self.float_scale), profile_score, avatar_url
        elif channel == 2:    # Data: TextShape fallback (V7 compat)
            res = TextShapeCarrier.encode_bit(bio, bit)
            return res.text, score, profile_score, avatar_url
        elif channel == 3:    # P Parity: Float-LSB (profile_score)
            return bio, score, StegoEngine.encode_bit_float_lsb(profile_score, bit, row_id=row_id, scale=self.float_scale), avatar_url
        elif channel == 4:    # Q Parity: Avatar Tilde (~) (avatar_url)
            return bio, score, profile_score, StegoEngine.encode_bit_avatar_url(avatar_url, bit, row_id=row_id)
        raise ValueError(f"Unknown channel: {channel}")

    def _sys_cache_row_mac(self, row_id, bio, score, profile_score=0.0, avatar_url="",
                           timestamp_value: int | None = None):
        """V9: Calculate 5 separate 8-Byte MACs over raw carrier field values.
        
        When ``timestamp_value`` is ``None`` (default), the timestamp is excluded
        from the MAC — backward-compatible with configs that have no timestamp_field.
        When a number is provided, it is canonicalised to int64 and included.
        """
        
        # Slot-based key for MAC calculation
        slot_idx = self._get_slot_idx_for_row(row_id)
        _, k_hm = self._get_slot_keys(slot_idx)
        
        # Round floats to a fixed precision to ensure consistent serialization,
        # mitigating floating-point representation issues across reads/writes.
        rounded_score = round(float(score), 6)
        rounded_profile_score = round(float(profile_score), 6)
        
        # Serialize raw field values consistently
        import struct
        data_to_mac_base = struct.pack(">I", row_id)
        data_to_mac_base += bio.encode('utf-8') if bio is not None else b''
        data_to_mac_base += struct.pack(">d", rounded_score) # double for float
        data_to_mac_base += struct.pack(">d", rounded_profile_score) # double for float
        data_to_mac_base += avatar_url.encode('utf-8') if avatar_url is not None else b''
        if timestamp_value is not None:
            data_to_mac_base += struct.pack(">q", int(timestamp_value))
        
        blob = b""
        for c in range(5): # Iterate for each of the 5 logical channels
            # Include the channel index in the data to MAC to make each MAC unique
            data_for_channel_mac = data_to_mac_base + struct.pack(">B", c)
            mac = hmac.new(
                k_hm,
                data_for_channel_mac,
                hashlib.sha256
            ).digest()[:8] # Truncate to 8 bytes as per original design
            blob += mac
            
        return blob

    def _rebuild_sys_cache_manifest(self):
        """Override V7 manifest rebuild to use V9 CarrierConfig fields."""
        if not self._external_carrier or not self._carrier_config:
            super()._rebuild_sys_cache_manifest()
            return

        cfg = self._carrier_config
        cursor = self.conn.cursor()
        
        self._set_sys_cache_write_mode(True, commit=False)
        try:
            cursor.execute(f"DELETE FROM {self.AUX_MANIFEST_TABLE}")
            
            # Build SELECT fields: all known carriers + optional timestamp_field
            select_fields = [
                cfg.id_field, cfg.semantic_field,
                cfg.float_a_field, cfg.float_b_field, cfg.tilde_field,
            ]
            if cfg.timestamp_field and cfg.timestamp_field not in select_fields:
                select_fields.append(cfg.timestamp_field)
            
            cursor.execute(
                f"SELECT {', '.join(select_fields)} "
                f"FROM {cfg.table} ORDER BY {cfg.id_field} ASC"
            )
            
            manifest_rows = []
            has_ts = bool(cfg.timestamp_field)
            for row in cursor.fetchall():
                row_id, bio, fa, fb, til = row[:5]
                ts_raw = row[5] if has_ts and len(row) > 5 else None
                ts_val = (GhostAuditInterceptor._parse_timestamp_to_int(ts_raw)
                          if ts_raw is not None else None)
                if bio is None or fa is None:
                    continue
                
                manifest_rows.append(
                    (row_id, self._sys_cache_row_mac(row_id, bio, fa, fb, til, ts_val))
                )
                
            if manifest_rows:
                cursor.executemany(
                    f"INSERT OR REPLACE INTO {self.AUX_MANIFEST_TABLE} (id, row_mac) VALUES (?, ?)",
                    manifest_rows,
                )
            self.conn.commit()
        finally:
            self._set_sys_cache_write_mode(False, commit=True)

    def _verify_sys_cache_row(self, row_id, bio, score, profile_score=0.0, avatar_url="",
                              timestamp_value: int | None = None):
         """Verify the integrity of a sys_cache row using its manifest HMAC."""
         cursor = self.conn.cursor()
         cursor.execute(
             f"SELECT row_mac FROM {self.AUX_MANIFEST_TABLE} WHERE id=?",
             (row_id,),
         )
         res = cursor.fetchone()
         if not res:
             return False # In V9, we expect a manifest entry for every row
         
         stored_mac = res[0]
         current_mac = self._sys_cache_row_mac(
             row_id, bio, score, profile_score, avatar_url, timestamp_value
         )
         
         return hmac.compare_digest(stored_mac, current_mac)

    def _write_event_to_slots(self, cursor, channel_blocks, stored_msg_bytes, selected_nsym, new_seq, store_compressed, slot_sequences):
        """V9: Carrier writes are handled by the Interceptor's intercept() loop.
        
        The engine's log_events() path must NOT write directly to the app table
        to maintain steganographic stealth and avoid uncoordinated updates.
        """
        active_seqs = set(seq for _, seq in slot_sequences if seq > 0)
        active_count = len(active_seqs)
        max_replicas = max(1, self.SLOT_COUNT // max(1, active_count + 1))
        replica_count = min(self.REPLICA_COUNT, max_replicas, len(slot_sequences))
        replica_slots = [slot_idx for slot_idx, _ in slot_sequences[:replica_count]]
        
        # We return the slots we WOULD have written to, so V7's sequence tracking
        # in log_events() remains correct.
        return replica_slots

    def _setup_db(self):
        # Always ensure V9 tables exist
        self._create_pending_queue_table()
        self._create_scheduler_state_table()

        if not self._external_carrier:
            # Standard V7 path — synthetic sys_cache, full bootstrap
            super()._setup_db()
            return

        cfg = self._carrier_config
        cursor = self.conn.cursor()

        # Existence checks for GhostAudit-internal tables
        def _exists(name):
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                (name,),
            )
            return cursor.fetchone() is not None

        if self.force_reinit:
            if self.verbose:
                print(f"[V9] Force reinit: dropping internal audit tables.")
            cursor.execute(f"DROP TABLE IF EXISTS {self.VISIBLE_LOG_TABLE}")
            cursor.execute(f"DROP TABLE IF EXISTS {self.AUX_MANIFEST_TABLE}")
            cursor.execute(f"DROP TABLE IF EXISTS {self.DECOY_ARCHIVE_TABLE}")
            cursor.execute(f"DROP TABLE IF EXISTS {self.MERKLE_ANCHOR_TABLE}")
            cursor.execute(f"DROP TABLE IF EXISTS sys_cache_write_gate")
            self.conn.commit()

        visible_exists  = _exists(self.VISIBLE_LOG_TABLE)
        manifest_exists = _exists(self.AUX_MANIFEST_TABLE)
        decoy_exists    = _exists(self.DECOY_ARCHIVE_TABLE)
        anchor_exists   = _exists(self.MERKLE_ANCHOR_TABLE)

        # Write-gate table (guards internal tables, not the app carrier)
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS sys_cache_write_gate (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                allow_write INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        cursor.execute(
            "INSERT OR IGNORE INTO sys_cache_write_gate (id, allow_write) VALUES (1, 1)"
        )
        cursor.execute("UPDATE sys_cache_write_gate SET allow_write=1 WHERE id=1")
        self.conn.commit()

        self._create_key_state_table()
        self._create_metronome_table()
        self._create_event_mac_table()

        if visible_exists:
            if self.verbose:
                print(f"[V9] Persistent mode: existing tables detected.")
            if not manifest_exists:
                self._rebuild_sys_cache_manifest()
            if not decoy_exists:
                cursor.execute(
                    f"""
                    CREATE TABLE {self.DECOY_ARCHIVE_TABLE} (
                        sequence_number INTEGER PRIMARY KEY,
                        event_msg TEXT NOT NULL,
                        record_digest BLOB NOT NULL,
                        archive_tag TEXT NOT NULL,
                        archived_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
            if not anchor_exists:
                self._create_merkle_anchor_table()
            else:
                self._migrate_merkle_anchor_table()
            self._load_key_evolve_state()
            self._load_metronome_state()
            self.conn.commit()
            self._ensure_channel_quality_table()
            self._ensure_internal_table_guards()
            self._seed_carrier_quality()
            self._set_sys_cache_write_mode(False, commit=True)
            return

        # First-run bootstrap — internal tables only, no carrier table creation
        if self.verbose:
            print(f"[V9] Bootstrap: creating internal tables (carrier='{cfg.table}').")

        cursor.execute(
            f"""
            CREATE TABLE {self.VISIBLE_LOG_TABLE} (
                sequence_number INTEGER PRIMARY KEY,
                event_msg TEXT NOT NULL,
                stored_msg BLOB NOT NULL,
                compressed INTEGER NOT NULL,
                mac BLOB NOT NULL,
                entry_hash BLOB NOT NULL,
                prev_hash BLOB NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        cursor.execute(
            f"""
            CREATE TABLE {self.DECOY_ARCHIVE_TABLE} (
                sequence_number INTEGER PRIMARY KEY,
                event_msg TEXT NOT NULL,
                record_digest BLOB NOT NULL,
                archive_tag TEXT NOT NULL,
                archived_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        # Manifest table for carrier row MACs
        cursor.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {self.AUX_MANIFEST_TABLE} (
                id INTEGER PRIMARY KEY,
                row_mac BLOB,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        self._create_merkle_anchor_table()
        self._load_key_evolve_state()
        self._load_metronome_state()
        self.conn.commit()

        # Build manifest from existing carrier rows
        self._rebuild_sys_cache_manifest()

        self._ensure_channel_quality_table()
        self._ensure_internal_table_guards()
        self._seed_carrier_quality()
        self._set_sys_cache_write_mode(False, commit=True)

    def _create_pending_queue_table(self):
        cursor = self.conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS sys_cache_pending_queue (
                seq INTEGER PRIMARY KEY,
                nsym INTEGER NOT NULL,
                stored_msg_len INTEGER NOT NULL,
                compressed INTEGER NOT NULL,
                repetitions INTEGER NOT NULL,
                start_after_rows INTEGER NOT NULL,
                rows_seen INTEGER NOT NULL DEFAULT 0,
                pos_0 INTEGER NOT NULL DEFAULT 0,
                pos_1 INTEGER NOT NULL DEFAULT 0,
                pos_2 INTEGER NOT NULL DEFAULT 0,
                pos_3 INTEGER NOT NULL DEFAULT 0,
                pos_4 INTEGER NOT NULL DEFAULT 0,
                channel_bits_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        self.conn.commit()

    def _create_scheduler_state_table(self):
        cursor = self.conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS sys_cache_scheduler_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                app_write_rate_ema REAL NOT NULL DEFAULT 0.0,
                avg_event_interval_ema REAL NOT NULL DEFAULT 0.0,
                last_intercept_time REAL NOT NULL DEFAULT 0.0,
                last_event_time REAL NOT NULL DEFAULT 0.0,
                carrier_schema_version INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        cursor.execute(
            "INSERT OR IGNORE INTO sys_cache_scheduler_state (id) VALUES (1)"
        )
        # Migration: add carrier_schema_version for pre-existing tables
        cols = {r[1] for r in cursor.execute("PRAGMA table_info(sys_cache_scheduler_state)")}
        if "carrier_schema_version" not in cols:
            cursor.execute(
                "ALTER TABLE sys_cache_scheduler_state ADD COLUMN "
                "carrier_schema_version INTEGER NOT NULL DEFAULT 1"
            )
        self.conn.commit()


# ---------------------------------------------------------------------------
# Semantic calibrator
# ---------------------------------------------------------------------------

class SemanticCalibrator:
    """Learn synonym frequencies from existing carrier rows.

    Once fitted, ``encode_bit`` emits the *less common* synonym for bit=1
    and the *more common* synonym for bit=0.  This makes the resulting
    distribution statistically indistinguishable from natural language use.

    Example
    -------
    If 'currently' appears 80% of the time and 'presently' 20% in real rows:
      bit=0 → 'currently'   (dominant, expected by analyst)
      bit=1 → 'presently'   (rare, but not anomalously so)

    Without calibration both would appear 50/50 — immediately detectable.
    """

    PAIRS: list[tuple[str, str]] = [
        ("currently",  "presently"),
        ("active",     "online"),
        ("working",    "operating"),
        ("system",     "platform"),
    ]

    def __init__(self):
        self._counts: dict[int, list[int]] = {
            i: [0, 0] for i in range(len(self.PAIRS))
        }
        self._fitted = False

    def fit(self, texts: list[str]) -> "SemanticCalibrator":
        """Count synonym occurrences in a list of text values."""
        for text in texts:
            if not text:
                continue
            low = text.lower()
            for i, (w0, w1) in enumerate(self.PAIRS):
                if re.search(rf"\b{w0}\b", low):
                    self._counts[i][0] += 1
                if re.search(rf"\b{w1}\b", low):
                    self._counts[i][1] += 1
        self._fitted = True
        return self

    def dominant(self, pair_index: int) -> int:
        """Return 0 if word0 is dominant, 1 if word1 is dominant."""
        c0, c1 = self._counts[pair_index]
        return 0 if c0 >= c1 else 1

    def encode_bit(self, text: str, bit: int) -> str:
        """Encode bit into text using calibrated synonym preference.

        bit=0 → dominant synonym  (matches natural frequency)
        bit=1 → non-dominant synonym
        """
        for i, (w0, w1) in enumerate(self.PAIRS):
            dom = self.dominant(i)
            target_bit0 = w0 if dom == 0 else w1
            target_bit1 = w1 if dom == 0 else w0
            chosen = target_bit0 if bit == 0 else target_bit1

            m0 = re.search(rf"\b{re.escape(w0)}\b", text, re.IGNORECASE)
            m1 = re.search(rf"\b{re.escape(w1)}\b", text, re.IGNORECASE)
            m  = m0 or m1
            if m:
                matched = m.group(0)
                if matched.isupper():
                    chosen = chosen.upper()
                elif matched.istitle():
                    chosen = chosen.title()
                return text[:m.start()] + chosen + text[m.start() + len(matched):]
        return text

    def decode_bit(self, text: str) -> int | None:
        """Decode bit from text using calibrated synonym preference."""
        if not text:
            return None
        low = text.lower()
        for i, (w0, w1) in enumerate(self.PAIRS):
            dom = self.dominant(i)
            m0 = re.search(rf"\b{re.escape(w0)}\b", low)
            m1 = re.search(rf"\b{re.escape(w1)}\b", low)
            if m0 and (not m1 or m0.start() < m1.start()):
                return 0 if dom == 0 else 1
            if m1 and (not m0 or m1.start() < m0.start()):
                return 1 if dom == 0 else 0
        return None


# ---------------------------------------------------------------------------
# Float calibrator
# ---------------------------------------------------------------------------

class FloatCalibrator:
    """Track whether a float carrier has enough real samples to be used.

    In V9, this also performs a distribution fit by finding the scale
    (precision level) where the natural LSB distribution is closest to 50/50.
    """

    def __init__(self, min_samples: int = 0):
        self.min_samples = max(0, min_samples)
        self.count = 0
        self.min_seen: float | None = None
        self.max_seen: float | None = None
        self.best_scale: int = 1000000  # Default V7 scale
        self._scales = [1000, 10000, 100000, 1000000, 10000000]

    def fit(self, values: list[float]) -> "FloatCalibrator":
        for value in values:
            if value is None:
                continue
            self.count += 1
            self.min_seen = value if self.min_seen is None else min(self.min_seen, value)
            self.max_seen = value if self.max_seen is None else max(self.max_seen, value)

        if self.count >= 10:
            # Find scale with best 50/50 LSB distribution
            best_diff = 1.0
            best_s = 1000000
            for s in self._scales:
                ones = sum(1 for v in values if v is not None and int(round(v * s)) % 2 == 1)
                ratio = ones / len(values) if values else 0.5
                diff = abs(ratio - 0.5)
                if diff < best_diff:
                    best_diff = diff
                    best_s = s
            self.best_scale = best_s

        return self

    @property
    def ready(self) -> bool:
        return self.count >= self.min_samples

    def coverage(self) -> float:
        if self.min_samples <= 0:
            return 1.0
        return min(1.0, self.count / float(self.min_samples))


# ---------------------------------------------------------------------------
# Text-shape carrier
# ---------------------------------------------------------------------------

class TextShapeCarrier:
    """Opportunistic replacement for the trailing-space carrier.

    Invariant: the learned/profiled corpus may decide whether we are allowed
    to write, but decoding must be profile-independent.  Recovery reads the
    bit from the text shape itself; missing/ambiguous shapes are erasures.
    """

    # Broadened family: Oxford comma in lists of three items.
    # Matches items that can contain spaces, but not commas.
    # bit=1: "A, B, and C"; bit=0: "A, B and C".
    _OXFORD_RE = re.compile(
        r"([A-Za-z0-9][^,]{1,40}), "  # Item 1
        r"([A-Za-z0-9][^,]{1,40})"   # Item 2
        r"(,?) and "                 # Potential Oxford Comma
        r"([A-Za-z0-9][^.]{1,40})"   # Item 3
    )

    @classmethod
    def encode_bit(cls, text: str, bit: int) -> EncodeResult:
        if not text:
            return EncodeResult(text or "", False, "empty_text", "text_shape")

        m = cls._OXFORD_RE.search(text)
        if not m:
            return EncodeResult(text, False, "no_safe_text_shape", "text_shape")

        comma = "," if bit else ""
        replacement = f"{m.group(1)}, {m.group(2)}{comma} and {m.group(4)}"
        new_text = text[:m.start()] + replacement + text[m.end():]
        return EncodeResult(new_text, True, "", "text_shape_oxford")

    @classmethod
    def decode_bit(cls, text: str) -> int | None:
        if not text:
            return None
        m = cls._OXFORD_RE.search(text)
        if not m:
            return None
        return 1 if m.group(3) == "," else 0


# ---------------------------------------------------------------------------
# Bit-level carrier helpers
# ---------------------------------------------------------------------------

def _encode_bit_into_fields(
    row_id: Any,
    fields: dict[str, Any],
    bit: int,
    config: CarrierConfig,
    calibrator: SemanticCalibrator | None,
    float_scale: int = 1000000,
) -> dict[str, Any]:
    """Apply a single stego bit to a field dict using all 5 carriers.

    Returns a *new* dict with overlaid values.  Does not touch the DB.
    """
    result = dict(fields)
    sem = config.semantic_field
    fa  = config.float_a_field
    fb  = config.float_b_field
    til = config.tilde_field
    ts_field = config.timestamp_field

    # carrier 0: semantic synonym (bio)
    if sem in result and result[sem] is not None:
        if calibrator and calibrator._fitted:
            result[sem] = calibrator.encode_bit(result[sem], bit)
        else:
            result[sem] = StegoEngine.encode_bit_semantic(result[sem], bit)

    # carrier 1: float_a LSB
    if fa in result and result[fa] is not None:
        result[fa] = StegoEngine.encode_bit_float_lsb(
            result[fa], bit, row_id=row_id, scale=float_scale
        )

    # carrier 2: timestamp LSB (fallback to text-shape if no timestamp_field)
    if ts_field and ts_field in result and result[ts_field] is not None:
        ts_raw = result[ts_field]
        # REAL Unix seconds → scale=1000, keep as REAL
        if isinstance(ts_raw, float) and ts_raw < 1e11:
            result[ts_field] = StegoEngine.encode_bit_float_lsb(
                ts_raw, bit, row_id=row_id, scale=1000
            )
        else:
            # INTEGER ms or TEXT → canonical int64, scale=1, return int
            ts_int = GhostAuditInterceptor._parse_timestamp_to_int(ts_raw) or 0
            result[ts_field] = int(round(StegoEngine.encode_bit_float_lsb(
                float(ts_int), bit, row_id=row_id, scale=1
            )))
    elif not ts_field and sem in result and result[sem] is not None:
        encoded = TextShapeCarrier.encode_bit(result[sem], bit)
        if encoded.written:
            result[sem] = encoded.text

    # carrier 3: float_b LSB
    if fb in result and result[fb] is not None:
        result[fb] = StegoEngine.encode_bit_float_lsb(
            result[fb], bit, row_id=row_id, scale=float_scale
        )

    # carrier 4: tilde suffix
    if til in result and result[til] is not None:
        result[til] = StegoEngine.encode_bit_avatar_url(result[til], bit, row_id=row_id)

    return result


def _decode_bit_from_fields(
    row_id: Any,
    fields: dict[str, Any],
    config: CarrierConfig,
    calibrator: SemanticCalibrator | None,
    float_scale: int = 1000000,
) -> int | None:
    """Majority-vote decode of one stego bit from a field dict."""
    votes: list[int] = []
    sem = config.semantic_field
    fa  = config.float_a_field
    fb  = config.float_b_field
    til = config.tilde_field
    ts_field = config.timestamp_field

    if sem in fields and fields[sem]:
        b = (calibrator.decode_bit(fields[sem])
             if calibrator and calibrator._fitted
             else StegoEngine.decode_bit_semantic(fields[sem]))
        if b is not None:
            votes.append(b)

    if fa in fields and fields[fa] is not None:
        b = StegoEngine.decode_bit_float_lsb(fields[fa], scale=float_scale)
        if b is not None:
            votes.append(b)

    # carrier 2: timestamp LSB (fallback to text-shape)
    if ts_field and ts_field in fields and fields[ts_field] is not None:
        ts_val = float(GhostAuditInterceptor._parse_timestamp_to_int(fields[ts_field]))
        b = StegoEngine.decode_bit_float_lsb(ts_val, scale=1)
        if b is not None:
            votes.append(b)
    elif not ts_field and sem in fields and fields[sem]:
        b = TextShapeCarrier.decode_bit(fields[sem])
        if b is not None:
            votes.append(b)

    if fb in fields and fields[fb] is not None:
        b = StegoEngine.decode_bit_float_lsb(fields[fb], scale=float_scale)
        if b is not None:
            votes.append(b)

    if til in fields and fields.get(til) is not None:
        b = StegoEngine.decode_bit_avatar_url(fields[til] or "", row_id=row_id)
        if b is not None:
            votes.append(b)

    if not votes:
        return None
    return 1 if sum(votes) > len(votes) // 2 else 0


# ---------------------------------------------------------------------------
# Pending payload — buffered ECC-encoded bits waiting for intercept() calls
# ---------------------------------------------------------------------------

class _PendingPayload:
    """Holds RS+RAID-6 encoded bits for one event, to be drained by intercept().

    Structure mirrors V7's per-channel layout:
      channels 0-2: data (RS-encoded)
      channel  3:   P parity (XOR)
      channel  4:   Q parity (GF(2^8))

    Each intercept() call drains one logical_bits dict
    {0: bit, 1: bit, 2: bit, 3: bit, 4: bit} for one row.
    """

    def __init__(
        self,
        channel_blocks: dict[int, bytes] | None = None,
        seq: int = 0,
        nsym: int = 0,
        stored_msg_len: int = 0,
        compressed: bool = False,
        repetitions: int = 1,
        start_after_rows: int = 0,
        channel_bits: dict[int, list[int]] | None = None,
    ):
        # Convert each channel's bytes to a flat bit list
        if channel_bits is not None:
            self.channel_bits = channel_bits
        elif channel_blocks is not None:
            self.channel_bits: dict[int, list[int]] = {}
            for c, data in channel_blocks.items():
                bits = []
                for byte_val in data:
                    bits.extend([int(b) for b in format(byte_val, "08b")])
                self.channel_bits[c] = bits
        else:
            self.channel_bits = {}

        self.seq = seq
        self.nsym = nsym
        self.stored_msg_len = stored_msg_len
        self.compressed = compressed
        self.repetitions = max(1, repetitions)
        self.start_after_rows = max(0, start_after_rows)
        self.rows_seen = 0
        self._pos = {c: 0 for c in range(5)} # independent pointer per channel

    @property
    def source_bit_count(self) -> int:
        return max(len(b) for b in self.channel_bits.values()) if self.channel_bits else 0

    @property
    def max_bits(self) -> int:
        return self.source_bit_count * self.repetitions

    @property
    def exhausted(self) -> bool:
        # Exhausted when all channel pointers have reached the end
        return all(self._pos[c] >= len(self.channel_bits.get(c, [])) * self.repetitions 
                   for c in range(5))

    @property
    def remaining_bits(self) -> int:
        """Total bits remaining to be embedded across all channels."""
        total = 0
        for c in range(5):
            max_bits_ch = len(self.channel_bits.get(c, [])) * self.repetitions
            total += max(0, max_bits_ch - self._pos[c])
        return total

    def peek_bit(self, channel: int) -> int:
        """Return the next bit for a specific channel."""
        pos = self._pos[channel] // self.repetitions
        bits = self.channel_bits.get(channel, [])
        return bits[pos] if pos < len(bits) else 0

    def peek_logical_bits(self) -> dict[int, int] | None:
        """Return the next {channel: bit} tuple without advancing.
        
        Used for tests and legacy callers.
        """
        if self.exhausted:
            return None
        return {c: self.peek_bit(c) for c in range(5)}

    def advance(self, channel: int | None = None) -> None:
        """Mark the current bit(s) as successfully embedded.
        
        If channel is None, advance all channels (legacy behavior).
        """
        if channel is not None:
            max_bits_ch = len(self.channel_bits.get(channel, [])) * self.repetitions
            if self._pos[channel] < max_bits_ch:
                self._pos[channel] += 1
        else:
            # Legacy: advance all
            for c in range(5):
                self.advance(c)

    def should_defer(self) -> bool:
        """Return True while this payload should wait for more carrier rows."""
        return self.rows_seen < self.start_after_rows

    def note_row(self) -> None:
        """Record that one eligible carrier row was considered."""
        self.rows_seen += 1

    def next_logical_bits(self) -> dict[int, int] | None:
        """Return the next {channel: bit} dict and advance position.

        Kept for tests and legacy callers.
        """
        result = self.peek_logical_bits()
        if result is not None:
            self.advance()
        return result


# ---------------------------------------------------------------------------
# Main interceptor class
# ---------------------------------------------------------------------------

class GhostAuditInterceptor:
    """V9 interceptor — wraps a GhostAuditV7 engine and exposes the
    intercept API for timing-safe single-write stego embedding.
    """

    # Conservative fixed estimate for external carrier coverage to ensure
    # capacity planning and recovery are deterministic.
    # In Round-Robin mode, each channel only gets 20% of rows.
    # If 20% of those are eligible (semantic/text_shape), total coverage is 4%.
    EXTERNAL_COVERAGE_ESTIMATE = 0.04

    # ------------------------------------------------------------------ init

    def __init__(
        self,
        db_path: str,
        carrier_config: CarrierConfig | None = None,
        secret_key: str | None = None,
        key_provider=None,
        ecc_symbols: int = 36,
        verbose: bool = False,
        siem_export_path: str | None = None,
        siem_export_format: str = "jsonl",
        metronome_interval: int = 0,
        temporal_delay_rows: int = 6,
        target_spread_factor: float = 10.0,
        float_warmup_samples: int = 0,
        external_state_path: str | None = None,
        force_reinit: bool = False,
        max_queue_size: int = 100,
    ):
        self.config = carrier_config or v7_default_config()
        self.verbose = verbose
        self._target_spread_factor = target_spread_factor
        self.max_queue_size = max(1, max_queue_size)
        
        # Scheduler state
        self._app_write_rate_ema = 0.0      # app writes per second
        self._avg_event_interval_ema = 0.0 # seconds between log_event() calls
        self._last_intercept_time = 0.0
        self._last_event_time = 0.0
        self._ema_alpha = 0.1             # smoothing factor

        # Determine whether to use external-carrier mode
        is_external = (carrier_config is not None and
                       carrier_config.table != "sys_cache")

        # Pre-configure the engine subclass before __init__ runs _setup_db
        _V9Engine._external_carrier = is_external
        _V9Engine._carrier_config   = self.config

        self._engine = _V9Engine(
            db_path=db_path,
            secret_key=secret_key,
            key_provider=key_provider,
            ecc_symbols=ecc_symbols,
            verbose=verbose,
            siem_export_path=siem_export_path,
            siem_export_format=siem_export_format,
            metronome_interval=metronome_interval,
            external_state_path=external_state_path,
            force_reinit=force_reinit,
            slot_size=self.config.slot_size,
            slot_count=self.config.slot_count,
        )

        # Ensure the engine uses the same slot configuration as the interceptor
        self._engine.SLOT_SIZE = self.config.slot_size
        self._engine.SLOT_COUNT = self.config.slot_count

        # Point V7's AUX_TABLE at the configured carrier table
        self._engine.AUX_TABLE = self.config.table
        
        # Set busy timeout to prevent "database is locked" in multi-threaded/multi-process environments
        self._engine.conn.execute("PRAGMA busy_timeout=30000")

        self._calibrator = SemanticCalibrator()
        self._engine.semantic_calibrator = self._calibrator
        self._calibrated = False
        self._float_calibrator = FloatCalibrator(min_samples=float_warmup_samples)
        self._payload_queue: list[_PendingPayload] = []
        self._completed_payloads: list[_PendingPayload] = []
        self._temporal_delay_rows = max(0, temporal_delay_rows)
        self._float_warmup_samples = max(0, float_warmup_samples)
        self._row_id_list: list[Any] = []
        self._row_id_index: dict[Any, int] = {}
        self._carrier_rows_loaded = False
        self._intercept_count = 0
        self._restarted = True
        self._lock = threading.RLock()
        self._carrier_schema_version = 1
        root, _ = os.path.splitext(db_path)
        self._evolve_path = external_state_path or (root + ".evolve")

        # Load persisted state
        self._load_scheduler_state()
        self._load_pending_queue()

        # Migration: if timestamp_field is newly enabled, force manifest rebuild
        # so all rows have MACs that include the canonical timestamp value.
        if (self.config.timestamp_field
            and self._carrier_schema_version < 2):
            if self.verbose:
                print("[V9] Carrier schema v1→v2: rebuilding manifest with timestamp_field")
            self._engine._rebuild_sys_cache_manifest()
            self._carrier_schema_version = 2
            self._save_scheduler_state()

        self._witness = TimestampWitness(
            conn=self._engine.conn,
            evolve_path=self._evolve_path,
            poll_interval=30.0,
        )

        # For external carrier: populate _orig_ids from real table rows
        if is_external:
            self._ensure_carrier_rows()
        else:
            # sys_cache mode: use V7 engine's generated IDs
            self._row_id_list = list(self._engine._orig_ids)
            self._row_id_index = {rid: idx for idx, rid in enumerate(self._row_id_list)}
            self._carrier_rows_loaded = True

        self._compute_capacity_metrics()

    # ------------------------------------------------------------------ persistence

    def _load_scheduler_state(self):
        cursor = self._engine.conn.cursor()
        cursor.execute(
            """
            SELECT app_write_rate_ema, avg_event_interval_ema, 
                   last_intercept_time, last_event_time,
                   carrier_schema_version
            FROM sys_cache_scheduler_state WHERE id=1
            """
        )
        row = cursor.fetchone()
        if row:
            (self._app_write_rate_ema, self._avg_event_interval_ema, 
             self._last_intercept_time, self._last_event_time,
             self._carrier_schema_version) = row

    def _save_scheduler_state(self):
        cursor = self._engine.conn.cursor()
        cursor.execute(
            """
            UPDATE sys_cache_scheduler_state SET
                app_write_rate_ema = ?,
                avg_event_interval_ema = ?,
                last_intercept_time = ?,
                last_event_time = ?,
                carrier_schema_version = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = 1
            """,
            (self._app_write_rate_ema, self._avg_event_interval_ema, 
             self._last_intercept_time, self._last_event_time,
             self._carrier_schema_version)
        )
        self._engine.conn.commit()

    def _load_pending_queue(self):
        cursor = self._engine.conn.cursor()
        cursor.execute("SELECT * FROM sys_cache_pending_queue ORDER BY seq ASC")
        rows = cursor.fetchall()
        cols = [description[0] for description in cursor.description]
        
        self._payload_queue = []
        for row in rows:
            data = dict(zip(cols, row))
            # JSON keys are strings, need to convert back to int for channel_bits
            raw_bits = json.loads(data["channel_bits_json"])
            ch_bits = {int(k): v for k, v in raw_bits.items()}
            
            payload = _PendingPayload(
                seq=data["seq"],
                nsym=data["nsym"],
                stored_msg_len=data["stored_msg_len"],
                compressed=bool(data["compressed"]),
                repetitions=data["repetitions"],
                start_after_rows=data["start_after_rows"],
                channel_bits=ch_bits
            )
            payload.rows_seen = data["rows_seen"]
            payload._pos = {
                0: data["pos_0"],
                1: data["pos_1"],
                2: data["pos_2"],
                3: data["pos_3"],
                4: data["pos_4"]
            }
            self._payload_queue.append(payload)
        
        if self.verbose and self._payload_queue:
            print(f"[V9] Loaded {len(self._payload_queue)} pending payloads from DB.")

    def _save_payload(self, payload: _PendingPayload):
        cursor = self._engine.conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO sys_cache_pending_queue (
                seq, nsym, stored_msg_len, compressed, repetitions,
                start_after_rows, rows_seen, pos_0, pos_1, pos_2, pos_3, pos_4,
                channel_bits_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload.seq, payload.nsym, payload.stored_msg_len, int(payload.compressed),
                payload.repetitions, payload.start_after_rows, payload.rows_seen,
                payload._pos[0], payload._pos[1], payload._pos[2], payload._pos[3], payload._pos[4],
                json.dumps({str(k): v for k, v in payload.channel_bits.items()})
            )
        )
        self._engine.conn.commit()

    def _delete_payload(self, seq: int):
        cursor = self._engine.conn.cursor()
        cursor.execute("DELETE FROM sys_cache_pending_queue WHERE seq = ?", (seq,))
        self._engine.conn.commit()

    # ------------------------------------------------------------------ capacity metrics

    def _compute_capacity_metrics(self) -> None:
        cfg = self.config
        total_rows = len(self._row_id_list)
        required = cfg.total_carrier_rows
        deficit = max(0, required - total_rows)
        capacity_pct = min(100.0, total_rows / required * 100) if required else 0.0
        payload_rows_total = cfg.slot_count * cfg.payload_rows_per_slot
        effective = int(payload_rows_total * self.EXTERNAL_COVERAGE_ESTIMATE)

        self._capacity_metrics = dict(
            total_rows=total_rows,
            required_rows=required,
            deficit=deficit,
            capacity_pct=round(capacity_pct, 1),
            slot_count=cfg.slot_count,
            slot_size=cfg.slot_size,
            header_rows_per_slot=cfg.header_row_count,
            payload_rows_total=payload_rows_total,
            coverage_estimate=self.EXTERNAL_COVERAGE_ESTIMATE,
            effective_payload_rows=effective,
            queue_size=len(self._payload_queue),
            max_queue_size=self.max_queue_size,
        )

        if deficit > 0 and self.verbose:
            print(
                f"[V9] Capacity: {total_rows}/{required} rows ({capacity_pct:.0f}%), "
                f"{deficit} short.  Effective payload rows: ~{effective} "
                f"(coverage={self.EXTERNAL_COVERAGE_ESTIMATE}). "
                f"Queue: {len(self._payload_queue)}/{self.max_queue_size}."
            )

    def get_capacity_metrics(self) -> dict:
        self._capacity_metrics["queue_size"] = len(self._payload_queue)
        return dict(self._capacity_metrics)

    # ------------------------------------------------------------------ carrier row index

    def _ensure_carrier_rows(self) -> None:
        """Build the ordered list of carrier row IDs from the real app table.

        V7 generates synthetic IDs via HMAC-stepped arithmetic.  V9 instead
        reads the actual primary key values from the app table in stable order
        (ORDER BY pk) and uses those as the slot ID list.

        This must be called before any intercept/recover operations.
        """
        with self._lock:
            if self._carrier_rows_loaded:
                return
            cfg = self.config
            cursor = self._engine.conn.cursor()
            cursor.execute(
                f"SELECT {cfg.id_field} FROM {cfg.table} ORDER BY {cfg.id_field}"
            )
            rows = cursor.fetchall()
            self._row_id_list = [r[0] for r in rows]
            self._row_id_index = {rid: idx for idx, rid in enumerate(self._row_id_list)}

            # Also update the V7 engine's _orig_ids so its ECC/header paths work
            required = cfg.slot_count * cfg.slot_size
            if len(self._row_id_list) < required:
                if self.verbose:
                    print(
                        f"[V9] Warning: carrier table '{cfg.table}' has "
                        f"{len(self._row_id_list)} rows, need {required}. "
                        f"Interception will be limited."
                    )
            self._engine._orig_ids = self._row_id_list[:required]
            self._engine._orig_id_to_idx = {
                rid: idx for idx, rid in enumerate(self._engine._orig_ids)
            }
            self._carrier_rows_loaded = True

    # ------------------------------------------------------------------ calibration

    def calibrate(self, sample_size: int = 5000) -> "GhostAuditInterceptor":
        """Fit the semantic calibrator from existing carrier rows.

        Call once at application startup after the carrier table has real data.
        Safe to call multiple times — each call re-fits from scratch.
        """
        cfg = self.config
        cursor = self._engine.conn.cursor()
        cursor.execute(
            f"SELECT {cfg.semantic_field} FROM {cfg.table} "
            f"ORDER BY RANDOM() LIMIT ?",
            (sample_size,),
        )
        texts = [row[0] for row in cursor.fetchall() if row[0]]
        
        # Fit a new instance outside the lock to avoid blocking intercept()
        new_calibrator = SemanticCalibrator().fit(texts)
        
        with self._lock:
            self._calibrator = new_calibrator
            self._engine.semantic_calibrator = new_calibrator
            self._calibrated = True
            # Rebuild manifest since decoded bits changed
            if self._engine._external_carrier:
                self._engine._rebuild_sys_cache_manifest()
            
        if self.verbose:
            print(f"[V9 CALIBRATE] Fitted on {len(texts)} rows from '{cfg.table}'")
        return self

    def calibrate_floats(self, sample_size: int = 5000) -> "GhostAuditInterceptor":
        """Warm up float carriers from existing rows.

        This is the first-cut answer to the Float-LSB bootstrap problem:
        we only enable float writes after seeing enough real values.
        """
        cfg = self.config
        cursor = self._engine.conn.cursor()
        cursor.execute(
            f"SELECT {cfg.float_a_field}, {cfg.float_b_field} FROM {cfg.table} "
            f"ORDER BY RANDOM() LIMIT ?",
            (sample_size,),
        )
        vals: list[float] = []
        for a, b in cursor.fetchall():
            if a is not None:
                vals.append(float(a))
            if b is not None:
                vals.append(float(b))
        
        # Fit a new instance outside the lock to avoid blocking intercept()
        new_float_calibrator = FloatCalibrator(
            min_samples=self._float_warmup_samples
        ).fit(vals)
        
        with self._lock:
            self._float_calibrator = new_float_calibrator
            # Sync scale to engine for MAC calculation
            self._engine.float_scale = new_float_calibrator.best_scale
            # Rebuild manifest since decoded bits changed
            if self._engine._external_carrier:
                self._engine._rebuild_sys_cache_manifest()
            
        if self.verbose:
            print(
                f"[V9 FLOAT-CAL] fitted {self._float_calibrator.count} values "
                f"from '{cfg.table}'"
            )
        return self

    def measure_float_coverage(self) -> dict[str, Any]:
        """Return the current warm-up coverage for float carriers."""
        stats = {
            "count": self._float_calibrator.count,
            "min_samples": self._float_calibrator.min_samples,
            "ready": self._float_calibrator.ready,
            "coverage_ratio": self._float_calibrator.coverage(),
            "min_seen": self._float_calibrator.min_seen,
            "max_seen": self._float_calibrator.max_seen,
            "best_scale": self._float_calibrator.best_scale,
        }
        if self.verbose:
            print(
                f"[V9 FLOAT] count={stats['count']} "
                f"coverage={stats['coverage_ratio']:.3f} ready={stats['ready']} "
                f"best_scale={stats['best_scale']}"
            )
        return stats

    def measure_text_shape_coverage(self, sample_size: int = 5000) -> dict[str, Any]:
        """Estimate how often TextShapeCarrier can safely write on this corpus.

        Returns a small stats dict so Problem 2 can be validated empirically
        before we commit to a larger row budget.
        """
        cfg = self.config
        cursor = self._engine.conn.cursor()
        cursor.execute(
            f"SELECT {cfg.semantic_field} FROM {cfg.table} "
            f"ORDER BY RANDOM() LIMIT ?",
            (sample_size,),
        )
        texts = [row[0] for row in cursor.fetchall() if row[0] is not None]
        eligible = sum(1 for text in texts if TextShapeCarrier.encode_bit(text, 0).written)
        total = len(texts)
        ratio = (eligible / total) if total else 0.0
        stats = {
            "sample_size": total,
            "eligible": eligible,
            "coverage_ratio": ratio,
            "carrier_family": "text_shape_oxford",
        }
        if self.verbose:
            print(
                f"[V9 TEXT-SHAPE] eligible={eligible}/{total} "
                f"coverage={ratio:.3f} on '{cfg.table}'"
            )
        return stats

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _parse_timestamp_to_int(val) -> int | None:
        """Normalize a timestamp field value to int64 (Unix ms).

        Handles SQLite type chaos:
          - INTEGER         → Unix ms, direkt
          - REAL            → Unix **seconds** (< 1e11) oder Unix ms (≥ 1e11)
          - TEXT ISO-8601   → „2024-01-15 14:23:07.832[Z]" o.Ä.

        Returns ``None`` when *val* is empty/unparseable.
        """
        if val is None:
            return None
        if isinstance(val, int):
            return val
        if isinstance(val, float):
            if val < 1e11:          # Unix seconds (bis ~Sep 5138)
                return int(round(val * 1000))
            return int(val)         # schon ms
        if isinstance(val, str):
            val = val.strip()
            if not val:
                return None
            try:
                return int(val)
            except ValueError:
                pass
            try:
                from datetime import datetime, timezone
                # Strip trailing Z / UTC offset for parsing
                clean = val.upper().rstrip("Z").replace("T", " ")
                for fmt in [
                    "%Y-%m-%d %H:%M:%S.%f",
                    "%Y-%m-%d %H:%M:%S",
                ]:
                    try:
                        dt = datetime.strptime(clean, fmt)
                        dt = dt.replace(tzinfo=timezone.utc)
                        return int(dt.timestamp() * 1000)
                    except ValueError:
                        continue
            except ImportError:
                pass
        return None

    # ------------------------------------------------------------------ intercept API

    def intercept(self, row_id: Any, fields: dict[str, Any]) -> dict[str, Any]:
        """Compatibility wrapper returning only modified fields.

        Use ``intercept_result`` when callers need to distinguish passthrough,
        header rows, unknown rows, and carrier-gating skips.
        """
        return self.intercept_result(row_id, fields).fields

    def _current_embedding_probability(self) -> float:
        """Calculate dynamic p based on rates and target spread.

        Goal: finish the current event in self._target_spread_factor * event_interval.
        """
        if not self._payload_queue:
            return 1.0

        # target_spread_factor <= 0 disables the scheduler (for tests/debug)
        if self._target_spread_factor <= 0:
            return 1.0

        # If we have no rate data yet, default to full speed (safe but detectable)
        # to ensure the system works until EMA stabilizes.
        if self._app_write_rate_ema == 0 or self._avg_event_interval_ema == 0:
            return 1.0

        payload = self._payload_queue[0]
        # Use TOTAL bits (max_bits) instead of remaining bits to maintain
        # a constant, predictable spread rate throughout the event duration.
        # This prevents the "deceleration" effect as the queue empties.
        total_steps = max(1, payload.max_bits)

        # target_duration = spread_factor * inter_event_interval
        target_duration = self._target_spread_factor * self._avg_event_interval_ema

        # expected_app_writes = target_duration * writes_per_second
        expected_app_writes = target_duration * self._app_write_rate_ema

        # p = total_steps / expected_writes
        p = float(total_steps) / max(1.0, expected_app_writes)

        return max(0.01, min(1.0, p))

    def intercept_result(self, row_id: Any, fields: dict[str, Any]) -> InterceptResult:
        """Apply the next pending stego logical-bit-tuple to a field dict.

        Called by the application *before* its own UPDATE statement.
        Returns a new dict with the same keys but stego-overlaid values.
        If there are no pending bits, returns fields unchanged (zero overhead).

        When all bits of a pending event have been embedded, the payload is
        queued for a later header flush.  ``recover_events()`` flushes those
        headers after the app has had a chance to commit its own carrier-row
        updates.

        Parameters
        ----------
        row_id : Any
            Primary key value of the row being updated.
        fields : dict
            Current field values the application intends to write.

        Profile data may decide whether a carrier may write, but decoding must
        not depend on that profile.  Opportunistic carriers therefore imply
        opportunistic row selection: if TextShape cannot safely write on this
        row, the pending payload position is not consumed.
        """
        with self._lock:
            self._intercept_count += 1
            # Update app write rate EMA (even if no pending payload, to keep rate current)
            now = time.time()
            if self._last_intercept_time > 0 and not self._restarted:
                dt = now - self._last_intercept_time
                if dt > 0:
                    rate = 1.0 / dt
                    if self._app_write_rate_ema == 0:
                        self._app_write_rate_ema = rate
                    else:
                        self._app_write_rate_ema = (
                            self._ema_alpha * rate + (1 - self._ema_alpha) * self._app_write_rate_ema
                        )
            self._last_intercept_time = now
            self._restarted = False
            
            # Persist scheduler state periodically or when it changes significantly
            if self._intercept_count % 100 == 0:
                self._save_scheduler_state()

            if not self._payload_queue:
                return InterceptResult(dict(fields), False, "no_pending_payload", row_id)

            if self.config.table != "sys_cache":
                self._ensure_carrier_rows()
                row_idx = self._row_id_index.get(row_id)
                if row_idx is None:
                    return InterceptResult(dict(fields), False, "unknown_row", row_id)
                if (row_idx % self.config.slot_size) < self.config.header_row_count:
                    return InterceptResult(dict(fields), False, "header_row", row_id)

            payload = self._payload_queue[0]

            if payload.should_defer():
                payload.note_row()
                if payload.rows_seen % 50 == 0:
                    self._save_payload(payload)
                return InterceptResult(dict(fields), False, "temporal_delay", row_id)

            # Determine which channel this row belongs to (Round-Robin)
            row_idx = self._row_id_index.get(row_id, 0)
            target_channel = (row_idx % self.config.slot_size) % 5

            # Check if this channel is already finished for this payload
            # (Needed because channels might have slightly different bit counts due to RS)
            max_bits_ch = len(payload.channel_bits.get(target_channel, [])) * payload.repetitions
            if payload._pos[target_channel] >= max_bits_ch:
                # This channel is done, but others might not be. 
                # We skip this row to avoid corrupting it with old bits.
                return InterceptResult(dict(fields), False, "channel_exhausted", row_id)

            # Probability Gate (Rate-adaptive Scheduler)
            prob = self._current_embedding_probability()
            if random.random() > prob:
                return InterceptResult(dict(fields), False, "scheduler_skip", row_id)

            bit = payload.peek_bit(target_channel)

            result = dict(fields)
            mapping = self._engine._get_row_carrier_mapping(row_id)
            cfg = self.config

            # Find which physical carrier maps to this logical channel
            # mapping[physical_idx] = logical_channel
            physical_idx = -1
            for p_idx, l_ch in enumerate(mapping):
                if l_ch == target_channel:
                    physical_idx = p_idx
                    break
            
            if physical_idx == -1:
                return InterceptResult(dict(fields), False, "channel_mapping_error", row_id)

            sem = cfg.semantic_field
            fa  = cfg.float_a_field
            fb  = cfg.float_b_field
            til = cfg.tilde_field

            # Only modify the ONE physical carrier that maps to our target channel
            if physical_idx == 0:
                if sem in result and result[sem] is not None:
                    if self._calibrated:
                        result[sem] = self._calibrator.encode_bit(result[sem], bit)
                    else:
                        result[sem] = StegoEngine.encode_bit_semantic(result[sem], bit)
            elif physical_idx == 1:
                if fa in result and result[fa] is not None:
                    if self._float_warmup_samples > 0 and not self._float_calibrator.ready:
                        return InterceptResult(dict(fields), False, "float_warmup", row_id)
                    result[fa] = StegoEngine.encode_bit_float_lsb(
                        result[fa], bit, row_id=row_id,
                        scale=self._float_calibrator.best_scale
                    )
            elif physical_idx == 2:
                ts_field = cfg.timestamp_field
                if ts_field and ts_field in result and result[ts_field] is not None:
                    ts_raw = result[ts_field]
                    ts_int = self._parse_timestamp_to_int(ts_raw)
                    # Encode LSB on canonical INT64 ms, then preserve input type
                    if isinstance(ts_raw, float) and ts_raw < 1e11:
                        # REAL Unix seconds → scale=1000, keep as REAL
                        encoded = StegoEngine.encode_bit_float_lsb(
                            float(ts_raw), bit, row_id=row_id, scale=1000
                        )
                        result[ts_field] = encoded
                    else:
                        # INTEGER ms or REAL ms → scale=1, cast back to int
                        encoded = StegoEngine.encode_bit_float_lsb(
                            float(ts_int), bit, row_id=row_id, scale=1
                        )
                        result[ts_field] = int(round(encoded))
                elif not ts_field and sem in result and result[sem] is not None:
                    encoded = TextShapeCarrier.encode_bit(result[sem], bit)
                    if not encoded.written:
                        return InterceptResult(dict(fields), False, f"carrier_gating:{encoded.reason}", row_id)
                    result[sem] = encoded.text
                else:
                    return InterceptResult(dict(fields), False, "carrier_gating:no_timestamp", row_id)
            elif physical_idx == 3:
                if fb in result and result[fb] is not None:
                    if self._float_warmup_samples > 0 and not self._float_calibrator.ready:
                        return InterceptResult(dict(fields), False, "float_warmup", row_id)
                    result[fb] = StegoEngine.encode_bit_float_lsb(
                        result[fb], bit, row_id=row_id,
                        scale=self._float_calibrator.best_scale
                    )
            elif physical_idx == 4:
                if til in result and result[til] is not None:
                    result[til] = StegoEngine.encode_bit_avatar_url(
                        result[til], bit, row_id=row_id
                    )

            payload.advance(target_channel)

            # Compute MAC from the modified fields (including timestamp if configured).
            # The MAC is written BEFORE the app commits, so any app rollback
            # creates a MAC mismatch → erasure → RAID-6 recovery.
            ts_raw = result.get(cfg.timestamp_field) if cfg.timestamp_field else None
            ts_val = self._parse_timestamp_to_int(ts_raw) if ts_raw is not None else None
            new_mac = self._engine._sys_cache_row_mac(
                row_id,
                result.get(cfg.semantic_field, ""),
                result.get(cfg.float_a_field, 0.0),
                result.get(cfg.float_b_field, 0.0),
                result.get(cfg.tilde_field, ""),
                ts_val,
            )
            self._engine._set_sys_cache_write_mode(True, commit=False)
            try:
                self._engine.conn.execute(
                    f"INSERT OR REPLACE INTO {self._engine.AUX_MANIFEST_TABLE} (id, row_mac, updated_at) "
                    f"VALUES (?, ?, CURRENT_TIMESTAMP)",
                    (row_id, new_mac)
                )
            finally:
                self._engine._set_sys_cache_write_mode(False, commit=True)

            # If this was the last bit, queue the header for a later flush.
            if payload.exhausted:
                completed = self._payload_queue.pop(0)
                self._delete_payload(completed.seq)
                self._completed_payloads.append(completed)
                self._save_scheduler_state()
            else:
                # Persist progress after every bit-tuple embedding for maximum integrity.
                # While this adds a small DB overhead, it ensures that audit events
                # survive process crashes with zero bit loss.
                self._save_payload(payload)

            return InterceptResult(result, result != fields, "embedded", row_id)

    def flush_headers(self) -> None:
        """Write headers for payloads whose bits have fully been embedded."""
        with self._lock:
            while self._completed_payloads:
                self._flush_slot_header(self._completed_payloads.pop(0))

    def _flush_slot_header(self, payload: "_PendingPayload") -> None:
        """Write the slot header for a completed payload to the carrier table.

        Uses V7's _write_header_bits_to_slot path.  The header occupies the
        first ``header_row_count`` rows of the slot — these rows are written
        directly via the internal engine connection (bypassing the app write
        path).  This is a single batch write, not per-row.
        """
        e   = self._engine
        cfg = self.config
        self._ensure_carrier_rows()

        # Use slot 0 for now (multi-slot support is a future extension)
        slot_idx   = 0
        slot_start = slot_idx * cfg.slot_size
        slot_ids   = e._orig_ids[slot_start : slot_start + cfg.slot_size]
        header_ids = slot_ids[: cfg.header_row_count]

        header_bytes = e._build_legacy_header(
            payload.stored_msg_len,
            payload.nsym,
            payload.seq,
            payload.compressed,
            slot_idx,
        )

        cursor = e.conn.cursor()
        # Header write goes through write gate
        e._set_sys_cache_write_mode(True, commit=False)
        try:
            e._write_header_bits_to_slot(cursor, header_bytes, header_ids, slot_idx)
            e.conn.commit()
        finally:
            e._set_sys_cache_write_mode(False, commit=True)

        if self.verbose:
            print(
                f"[V9] Header flushed slot={slot_idx} seq={payload.seq} "
                f"nsym={payload.nsym} msg_len={payload.stored_msg_len}"
            )

    def decode_row(self, row_id: Any, fields: dict[str, Any]) -> dict[int, int]:
        """Decode all 5 logical channel bits from a carrier row's field values.

        Returns {logical_channel: bit} dict.  V9 uses Timestamp-LSB for physical
        carrier 2, falling back to TextShape if no timestamp_field configured.
        """
        ts_raw = fields.get(self.config.timestamp_field) if self.config.timestamp_field else None
        ts_val = self._parse_timestamp_to_int(ts_raw) if ts_raw is not None else None
        return self._decode_all_columns_v9(
            row_id,
            fields.get(self.config.semantic_field, ""),
            fields.get(self.config.float_a_field, 0.0),
            fields.get(self.config.float_b_field, 0.0),
            fields.get(self.config.tilde_field, ""),
            ts_val,
        )

    def _decode_all_columns_v9(
        self,
        row_id: Any,
        bio: str,
        score: float,
        profile_score: float = 0.0,
        avatar_url: str = "",
        timestamp_value: int = 0,
    ) -> dict[int, int | None]:
        mapping = self._engine._get_row_carrier_mapping(row_id)
        cfg = self.config
        logical_bits: dict[int, int | None] = {}

        for physical_carrier in range(5):
            logical_ch = mapping[physical_carrier]
            if physical_carrier == 0:
                bit = (self._calibrator.decode_bit(bio)
                       if self._calibrated
                       else StegoEngine.decode_bit_semantic(bio))
            elif physical_carrier == 1:
                bit = StegoEngine.decode_bit_float_lsb(
                    score, scale=self._float_calibrator.best_scale
                )
            elif physical_carrier == 2:
                if cfg.timestamp_field:
                    bit = StegoEngine.decode_bit_float_lsb(
                        float(timestamp_value), scale=1
                    )
                else:
                    bit = TextShapeCarrier.decode_bit(bio)
            elif physical_carrier == 3:
                bit = StegoEngine.decode_bit_float_lsb(
                    profile_score, scale=self._float_calibrator.best_scale
                )
            else:
                bit = StegoEngine.decode_bit_avatar_url(avatar_url or "", row_id=row_id)
            logical_bits[logical_ch] = bit

        return logical_bits

    def pending_event_count(self) -> int:
        """Number of events with bits still waiting to be embedded."""
        return len(self._payload_queue)

    def pending_bit_count(self) -> int:
        """Total stego bits across all pending payloads."""
        return sum(p.remaining_bits for p in self._payload_queue)

    # ------------------------------------------------------------------ log_event

    def log_event(self, event_msg: str, immediate_commit: bool = True) -> int | None:
        """Log an audit event.

        Encodes the event with RS+RAID-6 and enqueues the resulting bits for
        embedding via future ``intercept()`` calls.  Also writes to the V7
        audit_log table so Merkle anchors and checkpoints work normally.

        Returns the sequence number.
        """
        return self._log_and_enqueue([event_msg], immediate_commit)[0] \
            if True else None

    def log_events(
        self, event_msgs: list[str], immediate_commit: bool = True
    ) -> list[int]:
        """Batch-log multiple events.  Returns list of sequence numbers."""
        return self._log_and_enqueue(event_msgs, immediate_commit)

    def _log_and_enqueue(
        self, event_msgs: list[str], immediate_commit: bool
    ) -> list[int]:
        """Internal: log via V7 engine AND enqueue ECC bits for intercept()."""
        with self._lock:
            # Capacity check (Reject-New strategy)
            if len(self._payload_queue) + len(event_msgs) > self.max_queue_size:
                err_msg = (f"Queue overflow: current={len(self._payload_queue)}, "
                           f"new={len(event_msgs)}, max={self.max_queue_size}. "
                           "Rejecting new events to prevent history flushing.")
                if self.verbose:
                    print(f"[V9] {err_msg}")
                
                # Emit a SIEM warning if possible (V7 engine handles the export)
                # We log a synthetic event about the overflow to the visible log
                # so the gap is documented.
                self._engine.log_events(
                    [f"SYSTEM_WARNING: GhostAudit Queue Overflow. {err_msg}"],
                    immediate_commit=True
                )
                raise QueueOverflowError(err_msg)

            # Update event interval EMA
            now = time.time()
            if self._last_event_time > 0 and not self._restarted:
                dt = now - self._last_event_time
                if self._avg_event_interval_ema == 0:
                    self._avg_event_interval_ema = dt
                else:
                    self._avg_event_interval_ema = (
                        self._ema_alpha * dt + (1 - self._ema_alpha) * self._avg_event_interval_ema
                    )
            self._last_event_time = now
            self._restarted = False
            self._save_scheduler_state()

            # Early-warning: queue >50% full
            qlen = len(self._payload_queue)
            if qlen > self.max_queue_size // 2 and self.verbose and qlen % 10 == 0:
                m = self.get_capacity_metrics()
                print(
                    f"[V9] Queue {qlen}/{self.max_queue_size} ({qlen/self.max_queue_size*100:.0f}%). "
                    f"Effective payload rows: ~{m['effective_payload_rows']}. "
                    f"Row deficit: {m['deficit']}."
                )

            seqs = self._engine.log_events(event_msgs, immediate_commit=immediate_commit)

            if immediate_commit and seqs and self._evolve_path:
                try:
                    last_seq = seqs[-1]
                    self._witness.add_pending(last_seq, self._evolve_path)
                except Exception:
                    if self.verbose:
                        print("[V9] Witness add_pending failed (non-fatal)")

            for msg in event_msgs:
                self._enqueue_event_bits(msg)

            return seqs if seqs else []

    def _enqueue_event_bits(self, event_msg: str) -> None:
        """RS+RAID-6 encode one event message and push to _payload_queue."""
        # Note: caller (_log_and_enqueue) holds self._lock
        e = self._engine
        msg_bytes = event_msg.encode("utf-8")
        compressed_bytes = __import__("zlib").compress(msg_bytes, level=9)
        store_compressed = len(compressed_bytes) < len(msg_bytes)
        stored = compressed_bytes if store_compressed else msg_bytes

        mac = hmac.new(e.k_hmac, stored, __import__("hashlib").sha256).digest()[:16]
        payload_bytes = mac + stored

        payload_rows = self.config.slot_size - self.config.header_row_count

        # For external carriers, we must account for coverage (not all rows are
        # eligible). We use a conservative fixed estimate for capacity
        # planning to ensure recovery remains deterministic without storing
        # the measurement in the header.
        coverage = 1.0
        if self.config.table != "sys_cache":
            coverage = self.EXTERNAL_COVERAGE_ESTIMATE
        
        effective_payload_rows = int(payload_rows * coverage)
        
        nsym = e._select_ecc_symbols(
            len(stored), effective_payload_rows, per_channel=True
        )
        channel_blocks = e._encode_payload_per_channel_v7(payload_bytes, nsym)
        source_bit_count = max(len(block) for block in channel_blocks.values()) * 8
        repetitions = e._get_dynamic_repetitions(source_bit_count, effective_payload_rows)

        # Determine sequence number from last logged event
        cursor = e.conn.cursor()
        cursor.execute(
            f"SELECT MAX(sequence_number) FROM {e.VISIBLE_LOG_TABLE}"
        )
        row = cursor.fetchone()
        seq = row[0] if row and row[0] is not None else 0
        delay_seed = hmac.new(
            e.k_hmac,
            f"v9-delay:{seq}:{len(stored)}".encode("utf-8"),
            hashlib.sha256,
        ).digest()[0]
        start_after_rows = min(
            self._temporal_delay_rows,
            delay_seed % (self._temporal_delay_rows + 1)
            if self._temporal_delay_rows > 0
            else 0,
        )

        payload = _PendingPayload(
            channel_blocks=channel_blocks,
            seq=seq,
            nsym=nsym,
            stored_msg_len=len(stored),
            compressed=store_compressed,
            repetitions=repetitions,
            start_after_rows=start_after_rows,
        )
        self._payload_queue.append(payload)
        self._save_payload(payload)

    # ------------------------------------------------------------------ recovery

    def recover_events(self) -> list[tuple[int, str]]:
        """Recover logged events from the carrier table.

        For the default sys_cache mode, delegates to V7's full recovery path.
        For external-carrier mode, uses V9's own recovery which reads bits
        directly from the app table rows in slot order.
        """
        self._ensure_carrier_rows()
        self.flush_headers()
        is_external = (self.config.table != "sys_cache")
        if not is_external:
            return self._engine.recover_events()
        return self._recover_from_external_carrier()

    def _recover_from_external_carrier(self) -> list[tuple[int, str]]:
        """V9 recovery path for external app-table carriers.

        Reads all carrier rows in order, extracts per-row logical bits via
        V7's HMAC-shuffled decode, reconstructs per-channel bit streams,
        RS+RAID-6 decodes, and returns [(seq, message), ...].
        """
        cfg   = self.config
        e     = self._engine
        conn  = e.conn
        cursor = conn.cursor()

        orig_ids = e._orig_ids
        if not orig_ids:
            return []

        slot_count = cfg.slot_count
        slot_size  = cfg.slot_size
        hdr_count  = cfg.header_row_count
        logs: list[tuple[int, str]] = []

        for slot_idx in range(slot_count):
            slot_start   = slot_idx * slot_size
            slot_ids     = orig_ids[slot_start : slot_start + slot_size]
            if not slot_ids:
                continue
            header_ids   = slot_ids[:hdr_count]
            payload_ids  = slot_ids[hdr_count:]

            # ---- Build SELECT fields (all carriers + optional timestamp) ----
            sel_fields = [
                cfg.id_field, cfg.semantic_field,
                cfg.float_a_field, cfg.float_b_field, cfg.tilde_field,
            ]
            if cfg.timestamp_field and cfg.timestamp_field not in sel_fields:
                sel_fields.append(cfg.timestamp_field)
            sel_cols = ', '.join(sel_fields)

            # ---- Decode header bits ----
            placeholders = ",".join("?" * len(header_ids))
            cursor.execute(
                f"SELECT {sel_cols} "
                f"FROM {cfg.table} WHERE {cfg.id_field} IN ({placeholders}) "
                f"ORDER BY {cfg.id_field}",
                header_ids,
            )
            hdr_rows = {r[0]: r for r in cursor.fetchall()}

            h_bits: list[int] = []
            for rid in header_ids:
                row = hdr_rows.get(rid)
                if row:
                    _, bio, fa, fb, til = row[:5]
                    bit = e._decode_header_bit(rid, bio, fa,
                                             profile_score=fb, avatar_url=til)
                    h_bits.append(bit)
                else:
                    h_bits.append(0)

            perm = e._get_header_bit_permutation(slot_idx)
            h_bits_perm = [h_bits[perm[i]] for i in range(len(h_bits))]
            header_data = e._decode_header(h_bits_perm, slot_idx)
            if not header_data:
                continue

            nsym        = header_data["nsym"]
            seq         = header_data["sequence_number"]
            payload_len = header_data["payload_len"]
            compressed  = header_data.get("compressed", False)

            if seq == 0 or payload_len == 0:
                continue

            delay_seed = hmac.new(
                e.k_hmac,
                f"v9-delay:{seq}:{payload_len}".encode("utf-8"),
                hashlib.sha256,
            ).digest()[0]
            start_after_rows = min(
                self._temporal_delay_rows,
                delay_seed % (self._temporal_delay_rows + 1)
                if self._temporal_delay_rows > 0
                else 0,
            )

            # ---- Extract payload bits (per-channel) ----
            enc_bit_counts = e._per_channel_rs_encoded_bit_count(payload_len, nsym)
            # _per_channel_rs_encoded_bit_count returns a list [ch0_bits, ch1_bits, ...]
            max_bits = max(enc_bit_counts) if enc_bit_counts else 0
            if max_bits == 0:
                continue

            # IMPORTANT: temporal delay skips rows from the TOTAL payload row list,
            # not just the eligible ones.
            if start_after_rows > 0:
                payload_ids = payload_ids[start_after_rows:]

            placeholders = ",".join("?" * len(payload_ids))
            cursor.execute(
                f"SELECT {sel_cols} "
                f"FROM {cfg.table} WHERE {cfg.id_field} IN ({placeholders}) "
                f"ORDER BY {cfg.id_field}",
                payload_ids,
            )
            payload_rows = {r[0]: r for r in cursor.fetchall()}
            
            # Repetition count must be calculated based on the total
            # slot capacity scaled by our conservative coverage estimate.
            total_payload_rows = cfg.slot_size - cfg.header_row_count
            effective_payload_rows = int(total_payload_rows * self.EXTERNAL_COVERAGE_ESTIMATE)
            repetitions = e._get_dynamic_repetitions(max_bits, effective_payload_rows)

            channel_votes: dict[int, list[list[int]]] = {c: [[] for _ in range(max_bits)] for c in range(5)}

            # Iterate through all payload rows and collect bits for their assigned channels
            for rid in payload_ids:
                row = payload_rows.get(rid)
                if not row:
                    continue
                _, bio, fa, fb, til = row[:5]
                has_ts = bool(cfg.timestamp_field)
                ts_val = self._parse_timestamp_to_int(row[5]) if has_ts and len(row) > 5 else None
                
                # Verify Row-MAC before extracting bits (Vector A resilience)
                # If tampering is detected, we skip the row, which turns the error
                # into an erasure for the RS decoder.
                if not e._verify_sys_cache_row(rid, bio, fa, profile_score=fb, avatar_url=til,
                                               timestamp_value=ts_val):
                    if self.verbose:
                        print(f"[V9 DEBUG] Row MAC failed for rid={rid} - turning into erasure")
                    continue

                row_idx = self._row_id_index.get(rid, 0)
                target_channel = (row_idx % cfg.slot_size) % 5
                
                # Check eligibility for this channel
                mapping = e._get_row_carrier_mapping(rid)
                physical_idx = -1
                for p_idx, l_ch in enumerate(mapping):
                    if l_ch == target_channel:
                        physical_idx = p_idx
                        break
                
                if physical_idx == -1: continue

                bit = None
                if physical_idx == 0: # semantic
                    bit = (self._calibrator.decode_bit(bio) if self._calibrated 
                           else StegoEngine.decode_bit_semantic(bio))
                elif physical_idx == 1: # float_a
                    bit = StegoEngine.decode_bit_float_lsb(fa, scale=self._float_calibrator.best_scale)
                elif physical_idx == 2: # timestamp_lsb or text_shape fallback
                    if cfg.timestamp_field:
                        bit = StegoEngine.decode_bit_float_lsb(float(ts_val), scale=1)
                    else:
                        bit = TextShapeCarrier.decode_bit(bio)
                elif physical_idx == 3: # float_b
                    bit = StegoEngine.decode_bit_float_lsb(fb, scale=self._float_calibrator.best_scale)
                elif physical_idx == 4: # avatar
                    bit = StegoEngine.decode_bit_avatar_url(til or "", row_id=rid)
                
                if bit is not None:
                    # We found a bit. Which bit_idx does it belong to?
                    # We need to track how many eligible rows we've seen for this channel.
                    # Wait, we need a counter per channel.
                    if not hasattr(self, "_tmp_ch_counters"):
                        self._tmp_ch_counters = {c: 0 for c in range(5)}
                    
                    curr_pos = self._tmp_ch_counters[target_channel]
                    bit_idx = curr_pos // repetitions
                    if bit_idx < max_bits:
                        channel_votes[target_channel][bit_idx].append(bit)
                    self._tmp_ch_counters[target_channel] += 1

            if hasattr(self, "_tmp_ch_counters"):
                del self._tmp_ch_counters

            channel_bits: dict[int, list[int]] = {c: [] for c in range(5)}
            erasures: dict[int, list[int]] = {c: [] for c in range(5)}

            for c in range(5):
                for bit_idx in range(max_bits):
                    vs = channel_votes[c][bit_idx]
                    if vs:
                        channel_bits[c].append(1 if sum(vs) > len(vs) // 2 else 0)
                    else:
                        channel_bits[c].append(0)
                        if bit_idx < enc_bit_counts[c]:
                            byte_pos = bit_idx // 8
                            if byte_pos not in erasures[c]:
                                erasures[c].append(byte_pos)

            # ---- RS + RAID-6 decode ----
            channel_bytes: dict[int, bytes] = {}
            for c in range(5):
                bits = channel_bits[c]
                # Match byte boundary (round up)
                expected_bytes = (enc_bit_counts[c] + 7) // 8
                raw = e._bits_to_bytes(bits[:enc_bit_counts[c]])
                raw = raw[:expected_bytes] if len(raw) >= expected_bytes else raw
                channel_bytes[c] = raw

            # Try per-channel RS decode for ALL 5 channels to identify which are "clean"
            from reedsolo import RSCodec, ReedSolomonError
            channel_plain: dict[int, bytes] = {}
            failed_channels = []
            
            for c in range(5):
                raw = channel_bytes.get(c, b"")
                if not raw:
                    failed_channels.append(c)
                    continue
                try:
                    dec = RSCodec(nsym).decode(raw, erase_pos=erasures.get(c, []))
                    channel_plain[c] = dec[0] if isinstance(dec, tuple) else dec
                except ReedSolomonError:
                    failed_channels.append(c)

            # RAID-6 recovery if any DATA channel (0,1,2) is missing from channel_plain
            if any(c not in channel_plain for c in range(3)):
                # We must provide RAW RS-encoded blocks to _recover_from_pq_parity,
                # but ONLY for the channels that are "working". Missing channels
                # must be absent from the dict so they get reconstructed.
                working_raw = {c: v for c, v in channel_bytes.items() if c not in failed_channels}
                
                # V7's _recover_from_pq_parity reconstructs missing blocks and decodes them.
                recovered_ch = e._recover_from_pq_parity(
                    working_raw, nsym, erasures
                )
                if recovered_ch:
                    for c in range(3):
                        if c in recovered_ch:
                            channel_plain[c] = recovered_ch[c]

            if any(c not in channel_plain for c in range(3)):
                continue

            # Reassemble payload bytes from 3 data channels
            # V7 interleaves bits round-robin across channels
            try:
                ch_bits_dec: list[list[int]] = []
                for c in range(3):
                    data = channel_plain[c]
                    bits = []
                    for b in data:
                        bits.extend([int(x) for x in format(b, "08b")])
                    ch_bits_dec.append(bits)

                max_ch_bits = max(len(b) for b in ch_bits_dec)
                interleaved: list[int] = []
                for i in range(max_ch_bits):
                    for c in range(3):
                        if i < len(ch_bits_dec[c]):
                            interleaved.append(ch_bits_dec[c][i])

                # IMPORTANT: truncate to actual payload size (MAC + stored_msg_len)
                # payload_len from header is the length of the stored_msg.
                total_payload_bits = (16 + payload_len) * 8
                interleaved = interleaved[:total_payload_bits]

                payload_bytes = e._bits_to_bytes(interleaved)
                
                # Further ensure byte-level truncation matches header
                payload_bytes = payload_bytes[:16 + payload_len]
            except Exception:
                continue

            # Strip HMAC (first 16 bytes), verify, decompress
            if len(payload_bytes) < 17:
                continue
            mac_stored = payload_bytes[:16]
            stored_msg = payload_bytes[16:]
            mac_expected = hmac.new(
                e.k_hmac, stored_msg, __import__("hashlib").sha256
            ).digest()[:16]
            if not hmac.compare_digest(mac_stored, mac_expected):
                continue  # HMAC mismatch — corrupted or wrong slot

            try:
                if compressed:
                    msg_bytes = __import__("zlib").decompress(stored_msg)
                else:
                    msg_bytes = stored_msg
                event_msg = msg_bytes.decode("utf-8")
            except Exception:
                continue

            logs.append((seq, event_msg))

        logs.sort(key=lambda x: x[0])
        return logs

    # ------------------------------------------------------------------ V7 pass-through

    def get_verification_digest(self) -> str:
        return self._engine.get_verification_digest()

    def verify_merkle_root(self, anchor_id: int | None = None) -> dict:
        return self._engine.verify_merkle_root(anchor_id)

    def verify_event_mac(self, sequence_number: int) -> dict:
        return self._engine.verify_event_mac(sequence_number)

    def verify_all_event_macs(self) -> list:
        return self._engine.verify_all_event_macs()

    def export_checkpoint(self, path: str | None = None) -> dict:
        cp = self._engine.export_checkpoint(path)
        cp["witness"] = self.get_witness_status()
        return cp

    def get_witness_status(self) -> dict:
        return self._witness.get_status()

    def verify_checkpoint(self, checkpoint, path: str | None = None) -> dict:
        return self._engine.verify_checkpoint(checkpoint, path)

    def export_recovered_logs(self, target_path: str, format: str = "jsonl"):
        return self._engine.export_recovered_logs(target_path, format)

    def detect_truncation(self, recovered_events: list | None = None) -> list:
        return self._engine.detect_truncation(recovered_events)

    def list_merkle_anchors(self, limit: int = 10) -> list:
        return self._engine.list_merkle_anchors(limit)

    def close(self):
        self._witness.stop(timeout=5.0)
        self._engine.close()
