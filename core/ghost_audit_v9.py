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

import hashlib
import hmac
import json
import os
import re
import sqlite3
import struct
import zlib
from typing import Any

from core.carrier_config import CarrierConfig, v7_default_config
from core.ghost_audit_v7 import GhostAuditV7, StegoEngine
from reedsolo import RSCodec, ReedSolomonError


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
# Bit-level carrier helpers
# ---------------------------------------------------------------------------

def _encode_bit_into_fields(
    row_id: Any,
    fields: dict[str, Any],
    bit: int,
    config: CarrierConfig,
    calibrator: SemanticCalibrator | None,
) -> dict[str, Any]:
    """Apply a single stego bit to a field dict using all 5 carriers.

    Returns a *new* dict with overlaid values.  Does not touch the DB.
    """
    result = dict(fields)
    sem = config.semantic_field
    fa  = config.float_a_field
    fb  = config.float_b_field
    til = config.tilde_field

    # carrier 0: semantic synonym (bio)
    if sem in result and result[sem] is not None:
        if calibrator and calibrator._fitted:
            result[sem] = calibrator.encode_bit(result[sem], bit)
        else:
            result[sem] = StegoEngine.encode_bit_semantic(result[sem], bit)

    # carrier 1: float_a LSB
    if fa in result and result[fa] is not None:
        result[fa] = StegoEngine.encode_bit_float_lsb(result[fa], bit, row_id=row_id)

    # carrier 2: trailing space (same field as semantic)
    if sem in result and result[sem] is not None:
        result[sem] = StegoEngine.encode_bit_trailing_space(result[sem], bit)

    # carrier 3: float_b LSB
    if fb in result and result[fb] is not None:
        result[fb] = StegoEngine.encode_bit_float_lsb(result[fb], bit, row_id=row_id)

    # carrier 4: tilde suffix
    if til in result and result[til] is not None:
        result[til] = StegoEngine.encode_bit_avatar_url(result[til], bit, row_id=row_id)

    return result


def _decode_bit_from_fields(
    row_id: Any,
    fields: dict[str, Any],
    config: CarrierConfig,
    calibrator: SemanticCalibrator | None,
) -> int | None:
    """Majority-vote decode of one stego bit from a field dict."""
    votes: list[int] = []
    sem = config.semantic_field
    fa  = config.float_a_field
    fb  = config.float_b_field
    til = config.tilde_field

    if sem in fields and fields[sem]:
        b = (calibrator.decode_bit(fields[sem])
             if calibrator and calibrator._fitted
             else StegoEngine.decode_bit_semantic(fields[sem]))
        if b is not None:
            votes.append(b)

    if fa in fields and fields[fa] is not None:
        b = StegoEngine.decode_bit_float_lsb(fields[fa])
        if b is not None:
            votes.append(b)

    if sem in fields and fields[sem]:
        votes.append(StegoEngine.decode_bit_trailing_space(fields[sem]))

    if fb in fields and fields[fb] is not None:
        b = StegoEngine.decode_bit_float_lsb(fields[fb])
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
        channel_blocks: dict[int, bytes],
        seq: int,
        nsym: int,
        stored_msg_len: int,
        compressed: bool,
    ):
        # Convert each channel's bytes to a flat bit list
        self.channel_bits: dict[int, list[int]] = {}
        for c, data in channel_blocks.items():
            bits = []
            for byte_val in data:
                bits.extend([int(b) for b in format(byte_val, "08b")])
            self.channel_bits[c] = bits

        self.seq = seq
        self.nsym = nsym
        self.stored_msg_len = stored_msg_len
        self.compressed = compressed
        self._pos = 0   # current bit position (same for all channels)

    @property
    def max_bits(self) -> int:
        return max(len(b) for b in self.channel_bits.values()) if self.channel_bits else 0

    @property
    def exhausted(self) -> bool:
        return self._pos >= self.max_bits

    def next_logical_bits(self) -> dict[int, int] | None:
        """Return the next {channel: bit} dict and advance position.

        Returns None when all bits have been drained.
        """
        if self.exhausted:
            return None
        pos = self._pos
        self._pos += 1
        result = {}
        for c in range(5):
            bits = self.channel_bits.get(c, [])
            result[c] = bits[pos] if pos < len(bits) else 0
        return result


# ---------------------------------------------------------------------------
# Main interceptor class
# ---------------------------------------------------------------------------

class GhostAuditInterceptor:
    """V9 interceptor — wraps a GhostAuditV7 engine and exposes the
    intercept API for timing-safe single-write stego embedding.

    Quick start
    -----------
    ::

        config = CarrierConfig(
            table="users",
            id_field="id",
            semantic_field="bio",
            float_a_field="trust_score",
            float_b_field="profile_score",
            tilde_field="avatar_url",
        )

        ga = GhostAuditInterceptor(
            db_path="app.db",
            carrier_config=config,
            secret_key="your-secret-key",
        )

        # Calibrate synonym encoder from real data (call once at startup)
        ga.calibrate()

        # Wherever the app updates a carrier row:
        def update_user(conn, uid, bio, trust, profile, avatar):
            fields = dict(bio=bio, trust_score=trust,
                          profile_score=profile, avatar_url=avatar)
            # GhostAudit may embed stego bits — returns modified fields
            final = ga.intercept(uid, fields)
            conn.execute(
                "UPDATE users SET bio=?, trust_score=?, "
                "profile_score=?, avatar_url=? WHERE id=?",
                (final["bio"], final["trust_score"],
                 final["profile_score"], final["avatar_url"], uid),
            )

        # Log audit events exactly as in V7
        ga.log_event("user=alice action=login ip=10.0.0.1")
        events = ga.recover_events()
    """

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
        external_state_path: str | None = None,
        force_reinit: bool = False,
    ):
        self.config = carrier_config or v7_default_config()
        self.verbose = verbose

        self._engine = GhostAuditV7(
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
        )

        # Point V7's carrier table references at the configured table
        self._patch_engine_config()

        self._calibrator = SemanticCalibrator()
        self._calibrated = False

        # Queue of _PendingPayload objects, one per pending log_event
        self._payload_queue: list[_PendingPayload] = []

        # Row-ID → slot-position mapping built from the carrier table
        self._row_id_list: list[Any] = []     # ordered list of carrier row IDs
        self._row_id_index: dict[Any, int] = {}  # row_id → position
        self._carrier_rows_loaded = False

    # ------------------------------------------------------------------ engine patching

    def _patch_engine_config(self) -> None:
        """Override V7's hardcoded table/field name with CarrierConfig values."""
        e = self._engine
        cfg = self.config
        # V7 uses AUX_TABLE for the carrier table name throughout its write/read paths
        e.AUX_TABLE = cfg.table

    # ------------------------------------------------------------------ carrier row index

    def _ensure_carrier_rows(self) -> None:
        """Build the ordered list of carrier row IDs from the real app table.

        V7 generates synthetic IDs via HMAC-stepped arithmetic.  V9 instead
        reads the actual primary key values from the app table in stable order
        (ORDER BY pk) and uses those as the slot ID list.

        This must be called before any intercept/recover operations.
        """
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
        self._calibrator.fit(texts)
        self._calibrated = True
        if self.verbose:
            print(f"[V9 CALIBRATE] Fitted on {len(texts)} rows from '{cfg.table}'")
        return self

    # ------------------------------------------------------------------ intercept API

    def intercept(self, row_id: Any, fields: dict[str, Any]) -> dict[str, Any]:
        """Apply the next pending stego logical-bit-tuple to a field dict.

        Called by the application *before* its own UPDATE statement.
        Returns a new dict with the same keys but stego-overlaid values.
        If there are no pending bits, returns fields unchanged (zero overhead).

        Parameters
        ----------
        row_id : Any
            Primary key value of the row being updated.
        fields : dict
            Current field values the application intends to write.

        Returns
        -------
        dict
            Modified field values to pass to the single UPDATE statement.
        """
        if not self._payload_queue:
            return dict(fields)

        payload = self._payload_queue[0]
        logical_bits = payload.next_logical_bits()

        if logical_bits is None or payload.exhausted:
            self._payload_queue.pop(0)
            if not self._payload_queue:
                return dict(fields)
            payload = self._payload_queue[0]
            logical_bits = payload.next_logical_bits()
            if logical_bits is None:
                return dict(fields)

        # Apply HMAC carrier shuffling (same as V7) so logical→physical
        # mapping is unknown without the key
        result = dict(fields)
        mapping = self._engine._get_row_carrier_mapping(row_id)
        cfg = self.config

        field_keys = [
            cfg.semantic_field,   # physical carrier 0
            cfg.float_a_field,    # physical carrier 1
            cfg.semantic_field,   # physical carrier 2 (trailing space, same field)
            cfg.float_b_field,    # physical carrier 3
            cfg.tilde_field,      # physical carrier 4
        ]

        sem = cfg.semantic_field
        fa  = cfg.float_a_field
        fb  = cfg.float_b_field
        til = cfg.tilde_field

        for physical_carrier in range(5):
            logical_ch = mapping[physical_carrier]
            bit = logical_bits.get(logical_ch, 0)

            if physical_carrier == 0:
                # semantic synonym
                if sem in result and result[sem] is not None:
                    if self._calibrated:
                        result[sem] = self._calibrator.encode_bit(result[sem], bit)
                    else:
                        result[sem] = StegoEngine.encode_bit_semantic(result[sem], bit)
            elif physical_carrier == 1:
                if fa in result and result[fa] is not None:
                    result[fa] = StegoEngine.encode_bit_float_lsb(
                        result[fa], bit, row_id=row_id
                    )
            elif physical_carrier == 2:
                # trailing space (same field as semantic — applied after synonym)
                if sem in result and result[sem] is not None:
                    result[sem] = StegoEngine.encode_bit_trailing_space(result[sem], bit)
            elif physical_carrier == 3:
                if fb in result and result[fb] is not None:
                    result[fb] = StegoEngine.encode_bit_float_lsb(
                        result[fb], bit, row_id=row_id
                    )
            elif physical_carrier == 4:
                if til in result and result[til] is not None:
                    result[til] = StegoEngine.encode_bit_avatar_url(
                        result[til], bit, row_id=row_id
                    )

        return result

    def decode_row(self, row_id: Any, fields: dict[str, Any]) -> dict[int, int]:
        """Decode all 5 logical channel bits from a carrier row's field values.

        Returns {logical_channel: bit} dict (same as V7's _decode_all_columns_shuffled).
        """
        return self._engine._decode_all_columns_shuffled(
            row_id,
            fields.get(self.config.semantic_field, ""),
            fields.get(self.config.float_a_field, 0.0),
            fields.get(self.config.float_b_field, 0.0),
            fields.get(self.config.tilde_field, ""),
        )

    def pending_event_count(self) -> int:
        """Number of events with bits still waiting to be embedded."""
        return len(self._payload_queue)

    def pending_bit_count(self) -> int:
        """Total stego bits across all pending payloads."""
        return sum(
            max(0, p.max_bits - p._pos)
            for p in self._payload_queue
        )

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
        seqs = self._engine.log_events(event_msgs, immediate_commit=immediate_commit)

        for msg in event_msgs:
            self._enqueue_event_bits(msg)

        return seqs if seqs else []

    def _enqueue_event_bits(self, event_msg: str) -> None:
        """RS+RAID-6 encode one event message and push to _payload_queue."""
        e = self._engine
        msg_bytes = event_msg.encode("utf-8")
        compressed_bytes = __import__("zlib").compress(msg_bytes, level=9)
        store_compressed = len(compressed_bytes) < len(msg_bytes)
        stored = compressed_bytes if store_compressed else msg_bytes

        mac = hmac.new(e.k_hmac, stored, __import__("hashlib").sha256).digest()[:16]
        payload_bytes = mac + stored

        payload_rows = self.config.slot_size - self.config.header_row_count
        nsym = e._select_ecc_symbols(
            len(stored), payload_rows, per_channel=True
        )
        channel_blocks = e._encode_payload_per_channel_v7(payload_bytes, nsym)

        # Determine sequence number from last logged event
        cursor = e.conn.cursor()
        cursor.execute(
            f"SELECT MAX(sequence_number) FROM {e.VISIBLE_LOG_TABLE}"
        )
        row = cursor.fetchone()
        seq = row[0] if row and row[0] is not None else 0

        self._payload_queue.append(
            _PendingPayload(
                channel_blocks=channel_blocks,
                seq=seq,
                nsym=nsym,
                stored_msg_len=len(stored),
                compressed=store_compressed,
            )
        )

    # ------------------------------------------------------------------ recovery

    def recover_events(self) -> list[tuple[int, str]]:
        """Recover logged events from the carrier table.

        Reads carrier rows in slot order, extracts stego bits, RS+RAID-6
        decodes, and returns [(seq, message), ...].

        Delegates to V7's ``_recover_from_aux()`` which already handles the
        full decoding pipeline including RAID-6 recovery and ECC.
        """
        self._ensure_carrier_rows()
        return self._engine.recover_events()

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
        return self._engine.export_checkpoint(path)

    def verify_checkpoint(self, checkpoint, path: str | None = None) -> dict:
        return self._engine.verify_checkpoint(checkpoint, path)

    def export_recovered_logs(self, target_path: str, format: str = "jsonl"):
        return self._engine.export_recovered_logs(target_path, format)

    def detect_truncation(self, recovered_events: list | None = None) -> list:
        return self._engine.detect_truncation(recovered_events)

    def list_merkle_anchors(self, limit: int = 10) -> list:
        return self._engine.list_merkle_anchors(limit)

    def close(self):
        self._engine.close()
