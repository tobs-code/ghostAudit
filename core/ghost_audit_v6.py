import sqlite3
import numpy as np
import random
import hashlib
import hmac
import time
import struct
import os
import zlib
import re
from reedsolo import RSCodec, ReedSolomonError

class StegoEngine:
    SEMANTIC_MAP = {
        "currently": ["currently", "presently"],
        "active": ["active", "online"],
        "working": ["working", "operating"],
        "system": ["system", "platform"]
    }

    @staticmethod
    def encode_bit_trailing_space(text, bit):
        return text.rstrip() + (" " if bit else "")

    @staticmethod
    def decode_bit_trailing_space(text):
        return 1 if text.endswith(" ") else 0

    @staticmethod
    def encode_bit_case(text, bit):
        for i, char in enumerate(text):
            if char.isalpha():
                new_char = char.upper() if bit else char.lower()
                return text[:i] + new_char + text[i+1:]
        return text

    @staticmethod
    def decode_bit_case(text):
        for char in text:
            if char.isalpha():
                return 1 if char.isupper() else 0
        return 0

    @staticmethod
    def encode_bit_float_lsb(value, bit):
        scale = 1000000
        scaled = int(round(value * scale))
        if (scaled % 2) != bit:
            scaled += 1
        return float(scaled) / scale

    @staticmethod
    def decode_bit_float_lsb(value):
        if value is None:
            return None
        if abs(value) < 1e-12:
            return None
        scale = 1000000
        scaled = int(round(value * scale))
        return scaled % 2

    @staticmethod
    def encode_bit_semantic(text, bit):
        for _, synonyms in StegoEngine.SEMANTIC_MAP.items():
            val0 = synonyms[0]
            val1 = synonyms[1]
            chosen = val1 if bit else val0
            match0 = re.search(rf"\b{re.escape(val0)}\b", text, re.IGNORECASE)
            match1 = re.search(rf"\b{re.escape(val1)}\b", text, re.IGNORECASE)
            match = match0 or match1
            if match:
                idx = match.start()
                matched_word = match.group(0)
                if matched_word.isupper():
                    chosen = chosen.upper()
                elif matched_word.istitle():
                    chosen = chosen.title()
                return text[:idx] + chosen + text[idx+len(matched_word):]
        return text

    @staticmethod
    def decode_bit_semantic(text):
        if text is None:
            return None
        for _, synonyms in StegoEngine.SEMANTIC_MAP.items():
            val0 = synonyms[0]
            val1 = synonyms[1]
            match0 = re.search(rf"\b{re.escape(val0)}\b", text, re.IGNORECASE)
            match1 = re.search(rf"\b{re.escape(val1)}\b", text, re.IGNORECASE)
            if match1 and (not match0 or match1.start() < match0.start()):
                return 1
            if match0 and (not match1 or match0.start() < match1.start()):
                return 0
        return None


class GhostAuditV6:
    SLOT_COUNT = 5
    # Increased slot size by +25% to test capacity effects (was 1600)
    # Default slot size. Use GHOST_AUDIT_SLOT_SIZE env var to override for experiments.
    SLOT_SIZE = int(os.environ.get("GHOST_AUDIT_SLOT_SIZE", "1600"))
    HEADER_BIT_COUNT = 72
    MAX_BIT_REPETITIONS = 6
    MIN_BIT_REPETITIONS = 4
    PER_CHANNEL_MIN_BIT_REPETITIONS = max(
        1,
        int(os.environ.get("GHOST_AUDIT_PER_CHANNEL_MIN_REPS", "3")),
    )
    CHANNEL_COUNT = 4          # Anzahl Stego-Kanäle
    PER_CHANNEL_RS = os.environ.get("GHOST_AUDIT_PER_CHANNEL_RS", "1").lower() not in (
        "0",
        "false",
        "no",
    )
    LEGACY_MAGIC = 0x56
    FRAGMENT_MAGIC = 0x57
    VISIBLE_LOG_TABLE = "audit_log"
    DECOY_ARCHIVE_TABLE = "audit_archive"
    AUX_TABLE = "sys_cache"
    AUX_MANIFEST_TABLE = "sys_cache_manifest"

    # ---- Pro-Kanal-Bitoperationen ----
    @staticmethod
    def _encode_channel_bit(channel: int, bio: str, score: float, bit: int):
        """Codiert ein Bit nur auf den angegebenen Kanal (0–3)."""
        if channel == 0:      # Semantic
            return StegoEngine.encode_bit_semantic(bio, bit), score
        elif channel == 1:    # Float-LSB
            return bio, StegoEngine.encode_bit_float_lsb(score, bit)
        elif channel == 2:    # Trailing-Space
            return StegoEngine.encode_bit_trailing_space(bio, bit), score
        elif channel == 3:    # Case-Switching
            return StegoEngine.encode_bit_case(bio, bit), score
        raise ValueError(f"Unbekannter Kanal: {channel}")

    @staticmethod
    def _decode_channel_bit(channel: int, bio: str, score: float):
        """Dekodiert ein Bit nur aus dem angegebenen Kanal (0–3)."""
        if channel == 0:      # Semantic
            return StegoEngine.decode_bit_semantic(bio)
        elif channel == 1:    # Float-LSB
            return StegoEngine.decode_bit_float_lsb(score)
        elif channel == 2:    # Trailing-Space
            return StegoEngine.decode_bit_trailing_space(bio)
        elif channel == 3:    # Case-Switching
            return StegoEngine.decode_bit_case(bio)
        raise ValueError(f"Unbekannter Kanal: {channel}")

    def _bits_to_bytes(self, bits: list) -> bytes:
        """Wandle eine Liste von 0/1-Bits in Bytes um (Restbits mit 0 auffüllen)."""
        padded = list(bits)
        while len(padded) % 8:
            padded.append(0)
        b = bytearray()
        for i in range(0, len(padded), 8):
            chunk = padded[i : i + 8]
            b.append(int("".join(map(str, chunk)), 2))
        return bytes(b)

    def _bytes_to_bits(self, data: bytes) -> list:
        """Wandle Bytes in eine Liste von 0/1-Bits um."""
        bits = []
        for byte in data:
            bits.extend([int(b) for b in format(byte, "08b")])
        return bits

    def _combine_channel_bytes(self, channel_bytes: dict) -> bytes:
        """Kombiniere 4 Kanal-Byte-Ströme zu einem gemeinsamen Strom.
        channel_bytes = {0: c0_bytes, 1: c1_bytes, 2: c2_bytes, 3: c3_bytes}
        Jedes kombinierte Byte = [c0_bit7, c1_bit7, c2_bit7, c3_bit7, c0_bit6, c1_bit6, ...]
        """
        c0 = channel_bytes[0]
        c1 = channel_bytes[1]
        c2 = channel_bytes[2]
        c3 = channel_bytes[3]
        combined = bytearray()
        for b_idx in range(min(len(c0), len(c1), len(c2), len(c3))):
            bits_combined = 0
            for bit_pos in range(8):
                bits_combined |= (
                    ((c0[b_idx] >> (7 - bit_pos)) & 1) << 7
                    | ((c1[b_idx] >> (7 - bit_pos)) & 1) << 6
                    | ((c2[b_idx] >> (7 - bit_pos)) & 1) << 5
                    | ((c3[b_idx] >> (7 - bit_pos)) & 1) << 4
                )
            combined.append(bits_combined)
        return bytes(combined)

    def _split_combined_to_channels(self, combined_bytes: bytes) -> dict:
        """Trenne einen gemeinsamen Bitstrom wieder in 4 Kanal-Byte-Ströme."""
        channels = {c: bytearray() for c in range(self.CHANNEL_COUNT)}
        for b in combined_bytes:
            for bit_pos in range(8):
                global_bit = (b >> (7 - bit_pos)) & 1
                for c in range(self.CHANNEL_COUNT):
                    channels[c].append((global_bit >> (3 - c)) & 1)
        return {c: bytes(ch[c]) for c, ch in channels.items()}

    def _encode_payload_per_channel(self, payload_bytes: bytes, selected_nsym: int):
        """Pro-Kanal-RS-Kodierung: teilt Payload in 4 Bit-Ströme auf und kodiert je Kanal."""
        raw_bits = self._bytes_to_bits(payload_bytes)
        total_channel_bits = len(raw_bits)                  # Bits pro Kanal
        channel_bits = [[] for _ in range(self.CHANNEL_COUNT)] #Round-Robin-Verteilung

        for b_idx, bit_val in enumerate(raw_bits):
            channel_bits[b_idx % self.CHANNEL_COUNT].append(bit_val)

        results = []
        for c in range(self.CHANNEL_COUNT):
            ch_bytes = self._bits_to_bytes(channel_bits[c])
            rs = RSCodec(selected_nsym)
            encoded = rs.encode(ch_bytes)
            results.append((c, encoded))
        return results  # [(channel_idx, rs_encoded_block), ...]

    def _all_payload_ids(self):
        """Flat list of all sys_cache payload row IDs (all slots, post-header)."""
        ids = []
        for slot_idx in range(self.SLOT_COUNT):
            slot_start = slot_idx * self.SLOT_SIZE
            slot_ids = self._orig_ids[slot_start : slot_start + self.SLOT_SIZE]
            ids.extend(slot_ids[self.HEADER_BIT_COUNT :])
        return ids

    def _channel_payload_ids(self, all_payload_ids, channel):
        return [
            rid
            for idx, rid in enumerate(all_payload_ids)
            if idx % self.CHANNEL_COUNT == channel
        ]

    def _channel_carrier_order(self, ch_ids, channel: int):
        """Spread bit replicas across carrier rows (deterministic, keyed shuffle)."""
        return sorted(
            ch_ids,
            key=lambda rid: hmac.new(
                self.k_shuffling,
                f"pc:{channel}:{rid}".encode("utf-8"),
                hashlib.sha256,
            ).digest(),
        )

    @staticmethod
    def _channel_raw_bit_count(total_raw_bits, channel):
        return (total_raw_bits + GhostAuditV6.CHANNEL_COUNT - 1 - channel) // GhostAuditV6.CHANNEL_COUNT

    def _per_channel_rs_encoded_bit_count(self, stored_msg_len, nsym):
        """RS-encoded bit count per channel (matches _encode_payload_per_channel)."""
        payload_bit_count = (16 + stored_msg_len) * 8
        counts = []
        for c in range(self.CHANNEL_COUNT):
            n_bits = self._channel_raw_bit_count(payload_bit_count, c)
            ch_bytes = self._bits_to_bytes([0] * n_bits)
            encoded = RSCodec(nsym).encode(ch_bytes)
            counts.append(len(encoded) * 8)
        return counts

    def _extract_channel_encoded_bits(self, cursor, channel, all_payload_ids, num_bits):
        """Read RS-encoded bits for one channel (same row order as log_event write)."""
        ch_ids = self._channel_payload_ids(all_payload_ids, channel)
        if num_bits <= 0 or not ch_ids:
            return None, []

        repetitions = self._get_bit_repetitions(num_bits, len(ch_ids))
        ordered = self._channel_carrier_order(ch_ids, channel)
        used = ordered[: num_bits * repetitions]
        extracted_bits = []
        erasure_pos = []

        for bit_idx in range(num_bits):
            byte_idx = bit_idx // 8
            votes = []
            for rep in range(repetitions):
                rid = used[bit_idx * repetitions + rep]
                cursor.execute(
                    f"SELECT bio, trust_score FROM {self.AUX_TABLE} WHERE id=?",
                    (rid,),
                )
                res = cursor.fetchone()
                if res is None or res[0] is None or res[1] is None:
                    continue
                if not self._verify_sys_cache_row(rid, res[0], res[1]):
                    continue
                try:
                    votes.append(self._detect_channel_bit(res[0], res[1], channel))
                except Exception:
                    continue

            if not votes:
                extracted_bits.append(0)
                if byte_idx not in erasure_pos:
                    erasure_pos.append(byte_idx)
                continue

            vote = self._majority_vote(votes)
            if vote is None:
                extracted_bits.append(0)
                if byte_idx not in erasure_pos:
                    erasure_pos.append(byte_idx)
            else:
                extracted_bits.append(vote)

        return self._bits_to_bytes(extracted_bits), erasure_pos

    def _rebuild_payload_from_channel_bytes(self, channel_bytes, stored_msg_len):
        """Round-robin inverse of _encode_payload_per_channel bit split."""
        total_bits = (16 + stored_msg_len) * 8
        raw_bits = []
        for global_idx in range(total_bits):
            channel = global_idx % self.CHANNEL_COUNT
            local_idx = global_idx // self.CHANNEL_COUNT
            byte_idx = local_idx // 8
            bit_pos = 7 - (local_idx % 8)
            block = channel_bytes.get(channel)
            if block is None or byte_idx >= len(block):
                return None
            raw_bits.append((block[byte_idx] >> bit_pos) & 1)
        payload = self._bits_to_bytes(raw_bits)
        return payload[: 16 + stored_msg_len]

    def _recover_per_channel_payload(self, cursor, all_payload_ids, stored_msg_len, nsym, compressed):
        """Decode four independent RS blocks and rebuild MAC + message bytes."""
        encoded_bit_counts = self._per_channel_rs_encoded_bit_count(stored_msg_len, nsym)
        channel_plain = {}

        for c in range(self.CHANNEL_COUNT):
            chunk_bytes, erasures = self._extract_channel_encoded_bits(
                cursor, c, all_payload_ids, encoded_bit_counts[c]
            )
            if chunk_bytes is None:
                return None
            try:
                decoded = RSCodec(nsym).decode(chunk_bytes, erase_pos=erasures)
                channel_plain[c] = decoded[0] if isinstance(decoded, tuple) else decoded
            except ReedSolomonError:
                return None

        payload_bytes = self._rebuild_payload_from_channel_bytes(channel_plain, stored_msg_len)
        if payload_bytes is None or len(payload_bytes) < 16:
            return None

        recovered_mac = payload_bytes[:16]
        recovered_msg = payload_bytes[16:]
        expected_mac = hmac.new(self.k_hmac, recovered_msg, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(recovered_mac, expected_mac):
            return None

        try:
            msg_body = zlib.decompress(recovered_msg) if compressed else recovered_msg
            return msg_body.decode("utf-8")
        except (UnicodeDecodeError, zlib.error):
            return None

    def _write_channel_encoded_to_slot(self, cursor, channel, encoded_bytes, slot_payload_ids):
        """Write one channel's RS-encoded bytes into a slot using round-robin row indices."""
        ch_ids = self._channel_payload_ids(slot_payload_ids, channel)
        ch_bits = []
        for byte_val in encoded_bytes:
            ch_bits.extend([int(b) for b in format(byte_val, "08b")])

        if not ch_bits:
            return

        repetitions = self._get_bit_repetitions(len(ch_bits), len(ch_ids))
        ordered = self._channel_carrier_order(ch_ids, channel)
        used = ordered[: len(ch_bits) * repetitions]

        for bit_idx, bit_val in enumerate(ch_bits):
            for rep in range(repetitions):
                rid = used[bit_idx * repetitions + rep]
                cursor.execute(
                    f"SELECT bio, trust_score FROM {self.AUX_TABLE} WHERE id=?",
                    (rid,),
                )
                res = cursor.fetchone()
                if not res:
                    continue
                bio, score = res
                bio, score = self._encode_channel_bit_for_row(channel, bio, score, bit_val)
                cursor.execute(
                    f"UPDATE {self.AUX_TABLE} SET bio=?, trust_score=? WHERE id=?",
                    (bio, score, rid),
                )
                cursor.execute(
                    f"""
                    INSERT OR REPLACE INTO {self.AUX_MANIFEST_TABLE} (id, row_mac, updated_at)
                    VALUES (?, ?, CURRENT_TIMESTAMP)
                    """,
                    (rid, self._sys_cache_row_mac(rid, bio, score)),
                )

    def _write_header_bits_to_slot(self, cursor, header_bytes, header_ids):
        h_bits = []
        for b in header_bytes:
            h_bits.extend([int(x) for x in format(b, "08b")])

        for i, bit in enumerate(h_bits):
            if i >= len(header_ids):
                break
            rid = header_ids[i]
            cursor.execute(
                f"SELECT bio, trust_score FROM {self.AUX_TABLE} WHERE id=?",
                (rid,),
            )
            res = cursor.fetchone()
            if not res:
                continue
            bio, score = res
            new_bio, new_score = self._encode_header_bit(bio, score, bit)
            cursor.execute(
                f"UPDATE {self.AUX_TABLE} SET bio=?, trust_score=? WHERE id=?",
                (new_bio, new_score, rid),
            )
            cursor.execute(
                f"""
                INSERT OR REPLACE INTO {self.AUX_MANIFEST_TABLE} (id, row_mac, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                """,
                (rid, self._sys_cache_row_mac(rid, new_bio, new_score)),
            )

    def _recover_fragmented_event_per_channel(self, cursor, fragments_by_index):
        """Reassemble per-channel RS fragments spread across multiple slots."""
        expected_count = None
        sequence_number = None
        compressed = False
        nsym = None
        channel_encoded_parts = {c: bytearray() for c in range(self.CHANNEL_COUNT)}

        for fragment_index in sorted(fragments_by_index.keys()):
            header_data, slot_ids = fragments_by_index[fragment_index]
            if expected_count is None:
                expected_count = header_data["fragment_count"]
                sequence_number = header_data["sequence_number"]
                compressed = header_data["compressed"]
                nsym = header_data["nsym"]
            elif header_data["fragment_count"] != expected_count:
                return None

            slot_payload_ids = slot_ids[self.HEADER_BIT_COUNT :]
            frag_len = header_data["payload_len"]
            encoded_bit_counts = [frag_len * 8] * self.CHANNEL_COUNT

            for c in range(self.CHANNEL_COUNT):
                chunk_bytes, _ = self._extract_channel_encoded_bits(
                    cursor, c, slot_payload_ids, encoded_bit_counts[c]
                )
                if chunk_bytes is None:
                    return None
                channel_encoded_parts[c].extend(chunk_bytes[:frag_len])

        if expected_count is None or len(fragments_by_index) != expected_count:
            return None

        channel_plain = {}
        for c in range(self.CHANNEL_COUNT):
            try:
                decoded = RSCodec(nsym).decode(bytes(channel_encoded_parts[c]))
                channel_plain[c] = decoded[0] if isinstance(decoded, tuple) else decoded
            except ReedSolomonError:
                return (sequence_number, "[TAMPERING DETECTED]")

        for stored_msg_len in range(512, 0, -1):
            payload_bytes = self._rebuild_payload_from_channel_bytes(channel_plain, stored_msg_len)
            if payload_bytes is None or len(payload_bytes) < 16:
                continue
            recovered_mac = payload_bytes[:16]
            recovered_msg = payload_bytes[16:]
            expected_mac = hmac.new(self.k_hmac, recovered_msg, hashlib.sha256).digest()[:16]
            if not hmac.compare_digest(recovered_mac, expected_mac):
                continue
            try:
                msg_body = zlib.decompress(recovered_msg) if compressed else recovered_msg
                return (sequence_number, msg_body.decode("utf-8"))
            except (UnicodeDecodeError, zlib.error):
                continue

        return (sequence_number, "[TAMPERING DETECTED]")

    def close(self):
        self.conn.close()

    def _secure_shuffle(self, items):
        def get_hash(item):
            return hmac.new(self.k_shuffling, str(item).encode('utf-8'), hashlib.sha256).digest()
        return sorted(items, key=get_hash)

    def _setup_db(self):
        cursor = self.conn.cursor()
        
        # BEHEBUNG SCHWÄCHE 4: Zerstörungsfreies Setup
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (self.VISIBLE_LOG_TABLE,))
        visible_exists = cursor.fetchone()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (self.DECOY_ARCHIVE_TABLE,))
        decoy_exists = cursor.fetchone()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (self.AUX_TABLE,))
        aux_exists = cursor.fetchone()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (self.AUX_MANIFEST_TABLE,))
        manifest_exists = cursor.fetchone()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_ledger'")
        legacy_visible = cursor.fetchone()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_carrier'")
        legacy_aux = cursor.fetchone()

        if legacy_visible and not visible_exists:
            cursor.execute(f"ALTER TABLE audit_ledger RENAME TO {self.VISIBLE_LOG_TABLE}")
            self.conn.commit()
            visible_exists = True
        if legacy_aux and not aux_exists:
            cursor.execute(f"ALTER TABLE audit_carrier RENAME TO {self.AUX_TABLE}")
            self.conn.commit()
            aux_exists = True

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (self.VISIBLE_LOG_TABLE,))
        visible_exists = cursor.fetchone()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (self.AUX_TABLE,))
        aux_exists = cursor.fetchone()

        if visible_exists and aux_exists:
            self._ensure_sys_cache_guards()
            if not manifest_exists:
                self._rebuild_sys_cache_manifest()
            if self.verbose:
                print("[V6] Existing audit_log and sys_cache tables detected. Loading database in persistent mode.")
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
                self.conn.commit()
            return
        if visible_exists and not aux_exists:
            if self.verbose:
                print("[V6] Existing audit_log table detected. Creating missing sys_cache table.")
            cursor.execute(
                f"""
                CREATE TABLE {self.AUX_TABLE} (
                    id INTEGER PRIMARY KEY,
                    bio TEXT NOT NULL,
                    trust_score REAL NOT NULL
                )
                """
            )
            self.conn.commit()
            self._ensure_sys_cache_guards()
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
                self.conn.commit()
            return
        if aux_exists and not visible_exists:
            if self.verbose:
                print("[V6] Existing sys_cache table detected. Creating missing audit_log table.")
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
            self.conn.commit()
            self._ensure_sys_cache_guards()
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
                self.conn.commit()
            return

        print("[V6] No existing audit_log table found. Initializing database (bootstrap mode).")
        cursor.execute(
            f"CREATE TABLE {self.AUX_TABLE} (id INTEGER PRIMARY KEY, bio TEXT NOT NULL, trust_score REAL NOT NULL)"
        )
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
        
        # Templates disjoint wie in V5
        templates = [
            "The developer is currently focused on backend code.",
            "This user is active on the main database.",
            "He is working hard to resolve security alerts.",
            "The database system is configured for high reliability."
        ]
        
        rng_scores = random.Random(1234)
        users = []
        for idx, cid in enumerate(self._orig_ids):
            bio_template = templates[idx % len(templates)]
            users.append((cid, bio_template, rng_scores.uniform(0.9, 1.0)))
        
        cursor.executemany(f"INSERT INTO {self.AUX_TABLE} VALUES (?, ?, ?)", users)
        self.conn.commit()
        self._ensure_sys_cache_guards()
        self._rebuild_sys_cache_manifest()
        self._set_sys_cache_write_mode(False)

    def _ensure_sys_cache_guards(self):
        cursor = self.conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS sys_cache_write_gate (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                allow_write INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        cursor.execute(
            """
            INSERT OR IGNORE INTO sys_cache_write_gate (id, allow_write)
            VALUES (1, 0)
            """
        )
        cursor.execute(
            f"""
            CREATE TRIGGER IF NOT EXISTS sys_cache_block_null_bio
            BEFORE UPDATE OF bio ON {self.AUX_TABLE}
            WHEN NEW.bio IS NULL
            BEGIN
                SELECT RAISE(ABORT, 'sys_cache.bio cannot be NULL');
            END;
            """
        )
        cursor.execute(
            f"""
            CREATE TRIGGER IF NOT EXISTS sys_cache_block_null_score
            BEFORE UPDATE OF trust_score ON {self.AUX_TABLE}
            WHEN NEW.trust_score IS NULL
            BEGIN
                SELECT RAISE(ABORT, 'sys_cache.trust_score cannot be NULL');
            END;
            """
        )
        cursor.execute(
            f"""
            CREATE TRIGGER IF NOT EXISTS sys_cache_guard_update
            BEFORE UPDATE ON {self.AUX_TABLE}
            WHEN (SELECT allow_write FROM sys_cache_write_gate WHERE id = 1) = 0
            BEGIN
                SELECT RAISE(ABORT, 'sys_cache writes require internal gate');
            END;
            """
        )
        cursor.execute(
            f"""
            CREATE TRIGGER IF NOT EXISTS sys_cache_guard_insert
            BEFORE INSERT ON {self.AUX_TABLE}
            WHEN (SELECT allow_write FROM sys_cache_write_gate WHERE id = 1) = 0
            BEGIN
                SELECT RAISE(ABORT, 'sys_cache writes require internal gate');
            END;
            """
        )
        cursor.execute(
            f"""
            CREATE TRIGGER IF NOT EXISTS sys_cache_guard_delete
            BEFORE DELETE ON {self.AUX_TABLE}
            WHEN (SELECT allow_write FROM sys_cache_write_gate WHERE id = 1) = 0
            BEGIN
                SELECT RAISE(ABORT, 'sys_cache writes require internal gate');
            END;
            """
        )
        cursor.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {self.AUX_MANIFEST_TABLE} (
                id INTEGER PRIMARY KEY,
                row_mac BLOB NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        self.conn.commit()

    def _set_sys_cache_write_mode(self, enabled):
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE sys_cache_write_gate SET allow_write=? WHERE id=1",
            (1 if enabled else 0,),
        )
        self.conn.commit()

    def _sys_cache_row_mac(self, row_id, bio, trust_score):
        payload = (
            struct.pack(">I", row_id)
            + bio.encode("utf-8")
            + b"\x00"
            + struct.pack(">d", float(trust_score))
        )
        return hmac.new(self.k_hmac, payload, hashlib.sha256).digest()

    def _rebuild_sys_cache_manifest(self):
        cursor = self.conn.cursor()
        cursor.execute(f"DELETE FROM {self.AUX_MANIFEST_TABLE}")
        cursor.execute(
            f"SELECT id, bio, trust_score FROM {self.AUX_TABLE} ORDER BY id ASC"
        )
        manifest_rows = []
        for row_id, bio, trust_score in cursor.fetchall():
            if bio is None or trust_score is None:
                continue
            manifest_rows.append(
                (row_id, self._sys_cache_row_mac(row_id, bio, trust_score))
            )
        if manifest_rows:
            cursor.executemany(
                f"INSERT OR REPLACE INTO {self.AUX_MANIFEST_TABLE} (id, row_mac) VALUES (?, ?)",
                manifest_rows,
            )
        self.conn.commit()

    def _verify_sys_cache_row(self, row_id, bio, trust_score):
        cursor = self.conn.cursor()
        cursor.execute(
            f"SELECT row_mac FROM {self.AUX_MANIFEST_TABLE} WHERE id=?",
            (row_id,),
        )
        res = cursor.fetchone()
        if not res:
            return False
        expected_mac = self._sys_cache_row_mac(row_id, bio, trust_score)
        return hmac.compare_digest(res[0], expected_mac)

    def _entry_hash(self, sequence_number, stored_msg_bytes, compressed, mac, prev_hash):
        payload = (
            struct.pack(">I", sequence_number)
            + prev_hash
            + struct.pack(">B", 1 if compressed else 0)
            + mac
            + stored_msg_bytes
        )
        return hmac.new(self.k_hmac, payload, hashlib.sha256).digest()

    def _load_visible_event(self, sequence_number):
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT event_msg, stored_msg, compressed, mac, entry_hash, prev_hash
            FROM audit_log
            WHERE sequence_number=?
            """,
            (sequence_number,),
        )
        row = cursor.fetchone()
        if not row:
            return None

        event_msg, stored_msg, compressed, mac, entry_hash, prev_hash = row
        compressed = bool(compressed)
        expected_entry_hash = self._entry_hash(sequence_number, stored_msg, compressed, mac, prev_hash)
        if not hmac.compare_digest(entry_hash, expected_entry_hash):
            return None

        expected_mac = hmac.new(self.k_hmac, stored_msg, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(mac, expected_mac):
            return None

        try:
            msg_body = zlib.decompress(stored_msg) if compressed else stored_msg
            msg_text = msg_body.decode("utf-8")
        except (UnicodeDecodeError, zlib.error):
            return None

        if msg_text != event_msg:
            return None

        return msg_text

    def _recover_from_visible_log(self):
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT sequence_number, event_msg, stored_msg, compressed, mac, entry_hash, prev_hash
            FROM audit_log
            ORDER BY sequence_number ASC
            """
        )

        logs = []
        for sequence_number, event_msg, stored_msg, compressed, mac, entry_hash, prev_hash in cursor.fetchall():
            compressed = bool(compressed)
            expected_entry_hash = self._entry_hash(sequence_number, stored_msg, compressed, mac, prev_hash)
            if not hmac.compare_digest(entry_hash, expected_entry_hash):
                continue

            expected_mac = hmac.new(self.k_hmac, stored_msg, hashlib.sha256).digest()[:16]
            if not hmac.compare_digest(mac, expected_mac):
                continue

            try:
                msg_body = zlib.decompress(stored_msg) if compressed else stored_msg
                msg_text = msg_body.decode("utf-8")
            except (UnicodeDecodeError, zlib.error):
                continue

            if msg_text != event_msg:
                continue

            logs.append((sequence_number, msg_text))

        return logs

    def _recover_from_aux(self):
        cursor = self.conn.cursor()
        orig_ids = self._orig_ids
        logs = []

        if self.PER_CHANNEL_RS:
            fragments_by_seq = {}
            legacy_by_seq = {}

            for k in range(self.SLOT_COUNT):
                slot_start = k * self.SLOT_SIZE
                slot_ids = orig_ids[slot_start : slot_start + self.SLOT_SIZE]
                header_ids = slot_ids[: self.HEADER_BIT_COUNT]

                h_bits = []
                for rid in header_ids:
                    cursor.execute(
                        f"SELECT bio, trust_score FROM {self.AUX_TABLE} WHERE id=?",
                        (rid,),
                    )
                    res = cursor.fetchone()
                    if (
                        res
                        and res[0] is not None
                        and res[1] is not None
                        and self._verify_sys_cache_row(rid, res[0], res[1])
                    ):
                        h_bits.append(self._decode_header_bit(res[0], res[1]))
                    else:
                        h_bits.append(0)

                header_data = self._decode_header(h_bits)
                if not header_data:
                    continue

                seq = header_data["sequence_number"]
                if header_data.get("mode") == "fragment":
                    fragments_by_seq.setdefault(seq, {})[header_data["fragment_index"]] = (
                        header_data,
                        slot_ids,
                    )
                elif header_data.get("mode") == "legacy":
                    legacy_by_seq[seq] = (header_data, slot_ids)

            recovered_seqs = set()
            for seq, frag_map in fragments_by_seq.items():
                result = self._recover_fragmented_event_per_channel(cursor, frag_map)
                if result is None:
                    continue
                logs.append(result)
                recovered_seqs.add(seq)

            for seq, (header_data, slot_ids) in legacy_by_seq.items():
                if seq in recovered_seqs:
                    continue
                slot_payload_ids = slot_ids[self.HEADER_BIT_COUNT :]
                msg_text = self._recover_per_channel_payload(
                    cursor,
                    slot_payload_ids,
                    header_data["payload_len"],
                    header_data["nsym"],
                    header_data["compressed"],
                )
                if msg_text is None:
                    logs.append((seq, "[TAMPERING DETECTED]"))
                else:
                    logs.append((seq, msg_text))

            logs.sort(key=lambda x: x[0])
            return logs

        # --- Legacy / combined path ---
        for k in range(self.SLOT_COUNT):
            slot_start = k * self.SLOT_SIZE
            slot_ids = orig_ids[slot_start : slot_start + self.SLOT_SIZE]
            header_ids = slot_ids[:self.HEADER_BIT_COUNT]
            slot_tampered = False

            h_bits = []
            for rid in header_ids:
                cursor.execute(f"SELECT bio, trust_score FROM {self.AUX_TABLE} WHERE id=?", (rid,))
                res = cursor.fetchone()
                if res and res[0] is not None and res[1] is not None and self._verify_sys_cache_row(rid, res[0], res[1]):
                    h_bits.append(self._decode_header_bit(res[0], res[1]))
                else:
                    slot_tampered = True
                    h_bits.append(0)

            header_data = self._decode_header(h_bits)
            if not header_data:
                continue

            if header_data["mode"] == "legacy":
                total_bytes = 16 + header_data["payload_len"] + header_data["nsym"]
                chunk_bytes, erasure_pos = self._decode_slot_payload_bytes(
                    cursor, slot_ids, total_bytes
                )
                if chunk_bytes is None:
                    if slot_tampered:
                        logs.append((header_data["sequence_number"], "[TAMPERING DETECTED]"))
                    continue

                try:
                    rs_slot = RSCodec(header_data["nsym"])
                    decoded_bytes = rs_slot.decode(chunk_bytes, erase_pos=erasure_pos)[0]
                except ReedSolomonError:
                    print(f"[V6] Slot {k}: Reed-Solomon unrecoverable ({len(erasure_pos)} erasures, nsym={header_data['nsym']}).")
                    if slot_tampered:
                        logs.append((header_data["sequence_number"], "[TAMPERING DETECTED]"))
                    continue

                if len(decoded_bytes) < 16:
                    if slot_tampered:
                        logs.append((header_data["sequence_number"], "[TAMPERING DETECTED]"))
                    continue

                recovered_mac = decoded_bytes[:16]
                recovered_msg = decoded_bytes[16:]
                expected_mac = hmac.new(self.k_hmac, recovered_msg, hashlib.sha256).digest()[:16]

                if not hmac.compare_digest(recovered_mac, expected_mac):
                    logs.append((header_data["sequence_number"], "[TAMPERING DETECTED]"))
                    continue

                try:
                    msg_body = (
                        zlib.decompress(recovered_msg)
                        if header_data["compressed"]
                        else recovered_msg
                    )
                    msg_text = msg_body.decode("utf-8")
                    logs.append((header_data["sequence_number"], msg_text))
                except (UnicodeDecodeError, zlib.error):
                    continue

        logs.sort(key=lambda x: x[0])
        return logs

    def _get_bit_repetitions(self, total_bits, available_rows):
        for repetitions in range(self.MAX_BIT_REPETITIONS, 0, -1):
            if total_bits * repetitions <= available_rows:
                return repetitions
        raise ValueError("Message too long for slot capacity!")

    def _per_channel_min_repetitions(self, msg_len: int, nsym: int, available_rows: int) -> int:
        """Minimum stego repetitions across channels for a given RS width."""
        payload_bits = (16 + msg_len) * 8
        min_rep = self.MAX_BIT_REPETITIONS
        for c in range(self.CHANNEL_COUNT):
            ch_nbits = self._channel_raw_bit_count(payload_bits, c)
            ch_bytes = self._bits_to_bytes([0] * ch_nbits)
            try:
                encoded = RSCodec(nsym).encode(ch_bytes)
            except Exception:
                return 0
            try:
                rep = self._get_bit_repetitions(len(encoded) * 8, available_rows)
            except ValueError:
                return 0
            min_rep = min(min_rep, rep)
        return min_rep

    def _select_ecc_symbols(self, msg_len, available_rows, per_channel=False):
        """Pick RS parity symbols that fit into available carrier rows."""
        if per_channel:
            best_nsym = None
            best_min_rep = 0
            # Prefer the largest nsym that still yields at least MIN_BIT_REPETITIONS
            # repetitions while fitting into available fragments. Fall back to
            # maximizing repetitions if no candidate meets the threshold.
            for nsym in range(self.ecc_symbols, 1, -2):
                min_rep = self._per_channel_min_repetitions(msg_len, nsym, available_rows)
                if min_rep < 1:
                    continue
                # If this nsym yields at least the minimum desired repetitions,
                # prefer the largest such nsym immediately.
                if min_rep >= self.MIN_BIT_REPETITIONS:
                    return nsym
                if min_rep > best_min_rep or (min_rep == best_min_rep and nsym > (best_nsym or 0)):
                    best_min_rep = min_rep
                    best_nsym = nsym
            if best_nsym is not None:
                return best_nsym
            return self.ecc_symbols

        for nsym in range(self.ecc_symbols, 1, -2):
            total_bits = (16 + msg_len + nsym) * 8
            repetitions = self._get_bit_repetitions(total_bits, available_rows)
            if repetitions >= self.MIN_BIT_REPETITIONS:
                return nsym
        return self.ecc_symbols

    def _encode_header_bit(self, text, score, bit):
        text = StegoEngine.encode_bit_case(text, bit)
        text = StegoEngine.encode_bit_trailing_space(text, bit)
        score = StegoEngine.encode_bit_float_lsb(score, bit)
        return text, score

    def _decode_header_bit(self, text, score):
        votes = [
            StegoEngine.decode_bit_case(text),
            StegoEngine.decode_bit_trailing_space(text),
        ]
        float_vote = StegoEngine.decode_bit_float_lsb(score)
        if float_vote is not None:
            votes.append(float_vote)
        valid_votes = [vote for vote in votes if vote is not None]
        if not valid_votes:
            return 0
        ones = sum(valid_votes)
        zeros = len(valid_votes) - ones
        return 1 if ones > zeros else 0

    def __init__(self, db_path="ghost_audit_v6.db", secret_key=None, ecc_symbols=32, verbose=True):
        self.db_path = db_path
        
        if secret_key is None:
            secret_key = os.environ.get("GHOST_AUDIT_KEY")
            if not secret_key:
                if verbose:
                    print("[WARNING] No GHOST_AUDIT_KEY environment variable set! Using development fallback key.")
                secret_key = "dev-fallback-super-long-secure-key-123456789"
        
        self.secret_key = secret_key.encode('utf-8')
        self.ecc_symbols = ecc_symbols
        self.verbose = verbose
        
        self.k_shuffling = hmac.new(self.secret_key, b"shuffling_subkey", hashlib.sha256).digest()
        self.k_hmac = hmac.new(self.secret_key, b"hmac_subkey", hashlib.sha256).digest()
        
        self.conn = sqlite3.connect(db_path)
        
        # V6 generates 8000 rows to accommodate 5 slots of 1600 rows
        self._orig_ids = []
        c = 1
        for idx in range(self.SLOT_COUNT * self.SLOT_SIZE):
            self._orig_ids.append(c)
            h = hmac.new(self.k_shuffling, f"step_{idx}".encode('utf-8'), hashlib.sha256).digest()
            step = (h[0] % 3) + 1
            c += step
            
        self._setup_db()

    def _encode_all_columns(self, bio: str, score: float, bits_for_channels: dict):
        """Encode 1 bit per channel (0-3) into all 4 column positions of a sys_cache row.

        bits_for_channels = {0: bit0, 1: bit1, 2: bit2, 3: bit3}
        Returns (new_bio, new_score)
        """
        b, s = bio, score
        for c in range(self.CHANNEL_COUNT):
            b, s = self._encode_channel_bit(c, b, s, bits_for_channels.get(c, 0))
        return b, s

    def _encode_channel_bit_for_row(self, channel: int, bio: str, score: float, bit: int):
        """Encode one channel bit into a combined 4-column sys_cache row.

        Only ``channel`` is set to ``bit``; the other three channels are 0.
        Uses ``_encode_all_columns`` so that each column position is
        independently covered by the correct StegoEngine encoder.
        """
        bits = {c: 0 for c in range(self.CHANNEL_COUNT)}
        bits[channel] = bit
        return self._encode_all_columns(bio, score, bits)

    def _detect_channel_bit(self, bio: str, score: float, channel: int):
        """Read one channel bit from a combined 4-column sys_cache row.
        
        In combined round-robin mode each sys_cache row stores 4 bits (one per
        channel in parallel).  StegoEngine's channel methods all decode a **single**
        bit from ``(bio, score)`` independent of the other channels — so call the
        right decoder for the channel in question.
        
        Returns 0/1.
        """
        if channel == 0:
            decoded = StegoEngine.decode_bit_semantic(bio)
        elif channel == 1:
            decoded = StegoEngine.decode_bit_float_lsb(score)
        elif channel == 2:
            decoded = StegoEngine.decode_bit_trailing_space(bio)
        elif channel == 3:
            decoded = StegoEngine.decode_bit_case(bio)
        else:
            raise ValueError(f"Unknown channel {channel}")
        return decoded if decoded is not None else 0

    def _encode_payload_row(self, bio, score, bit):
        bio = StegoEngine.encode_bit_semantic(bio, bit)
        score = StegoEngine.encode_bit_float_lsb(score, bit)
        bio = StegoEngine.encode_bit_trailing_space(bio, bit)
        bio = StegoEngine.encode_bit_case(bio, bit)
        return bio, score

    def _decode_payload_row(self, bio, score):
        semantic = StegoEngine.decode_bit_semantic(bio)
        float_lsb = StegoEngine.decode_bit_float_lsb(score)
        trailing = StegoEngine.decode_bit_trailing_space(bio)
        case = StegoEngine.decode_bit_case(bio)
        return semantic, float_lsb, trailing, case

    @staticmethod
    def _majority_vote(bits):
        valid_bits = [bit for bit in bits if bit is not None]
        if not valid_bits:
            return None
        ones = sum(valid_bits)
        zeros = len(valid_bits) - ones
        if ones == zeros:
            return 0
        return 1 if ones > zeros else 0

    def _decode_header(self, header_bits):
        if len(header_bits) < self.HEADER_BIT_COUNT:
            return None
        bytes_data = bytearray()
        for i in range(0, self.HEADER_BIT_COUNT, 8):
            bits_str = "".join(map(str, header_bits[i:i+8]))
            bytes_data.append(int(bits_str, 2))

        try:
            magic = bytes_data[0]
            flags_and_nsym = bytes_data[3]
            nsym = flags_and_nsym & 0x7F
            compressed = bool(flags_and_nsym & 0x80)

            if magic == self.LEGACY_MAGIC:
                msg_len = (bytes_data[1] << 8) | bytes_data[2]
                sequence_number = (
                    (bytes_data[4] << 24)
                    | (bytes_data[5] << 16)
                    | (bytes_data[6] << 8)
                    | bytes_data[7]
                )
                return {
                    "magic": magic,
                    "payload_len": msg_len,
                    "nsym": nsym,
                    "sequence_number": sequence_number,
                    "compressed": compressed,
                    "fragment_index": 0,
                    "fragment_count": 1,
                    "mode": "legacy",
                }

            if magic == self.FRAGMENT_MAGIC:
                if len(bytes_data) < 9:
                    return None
                fragment_len = (bytes_data[1] << 8) | bytes_data[2]
                sequence_number = (bytes_data[4] << 16) | (bytes_data[5] << 8) | bytes_data[6]
                # fragment_meta ist jetzt ein 16-Bit-Int in bytes_data[7..8]
                fragment_meta = (bytes_data[7] << 8) | bytes_data[8]
                fragment_index = (fragment_meta >> 8) & 0xFF
                fragment_count = fragment_meta & 0xFF
                if fragment_count < 1 or fragment_index >= fragment_count:
                    return None
                return {
                    "magic": magic,
                    "payload_len": fragment_len,
                    "nsym": nsym,
                    "sequence_number": sequence_number,
                    "compressed": compressed,
                    "fragment_index": fragment_index,
                    "fragment_count": fragment_count,
                    "mode": "fragment",
                }
        except Exception:
            return None
        return None

    def _build_legacy_header(self, stored_msg_len, nsym, sequence_number, compressed):
        flags_and_nsym = nsym | (0x80 if compressed else 0)
        return struct.pack(">B H B I", self.LEGACY_MAGIC, stored_msg_len, flags_and_nsym, sequence_number)

    def _build_fragment_header(self, fragment_len, nsym, sequence_number, compressed, fragment_index, fragment_count):
        flags_and_nsym = nsym | (0x80 if compressed else 0)
        # 8 Bit Index + 8 Bit Count → bis zu 255 Fragmente, als 16-Bit-Int gepackt
        fragment_meta = (fragment_index << 8) | fragment_count
        return struct.pack(">B H B 3B H", self.FRAGMENT_MAGIC, fragment_len, flags_and_nsym,
                           (sequence_number >> 16) & 0xFF, (sequence_number >> 8) & 0xFF,
                           sequence_number & 0xFF, fragment_meta)

    def _fragment_encoded_bytes(self, encoded_bytes, max_fragments, max_bytes_per_fragment: int = None):
        """Split encoded bytes into at most ``max_fragments``.

        If ``max_bytes_per_fragment`` is provided, prefer that as the per-fragment
        capacity (used to align fragments to slot/channel capacities). Otherwise
        fall back to evenly-sized chunks (ceil division).
        """
        if max_fragments < 1:
            raise ValueError("No fragments available for payload encoding")

        total_len = len(encoded_bytes)
        if total_len == 0:
            return [b""] if max_fragments >= 1 else []

        if max_bytes_per_fragment is None:
            max_bytes_per_fragment = max(1, (total_len + max_fragments - 1) // max_fragments)

        fragments = []
        start = 0
        while start < total_len:
            end = min(total_len, start + max_bytes_per_fragment)
            fragments.append(encoded_bytes[start:end])
            start = end

        if len(fragments) > max_fragments:
            new_size = max(1, (total_len + max_fragments - 1) // max_fragments)
            fragments = []
            start = 0
            while start < total_len:
                end = min(total_len, start + new_size)
                fragments.append(encoded_bytes[start:end])
                start = end

        if len(fragments) > max_fragments:
            raise ValueError("Message too long for available slot fragments")

        return fragments

    def _decode_slot_payload_bytes(self, cursor, slot_ids, payload_len):
        """Extrahiere Payload-Bits aus einem Slot.

        Rückgabe: ``(bytes | None, erasure_positions)``

        ``erasure_positions`` listet Byte-Indizes auf, die bei der RS-Decodierung
        als gelöscht markiert werden sollen.  Eine fehlende Zeile
        oder Manifest-Missbrauch wird *nicht* als Tampering gewertet —
        das entscheidet erst die RS-Decodierung + HMAC-Prüfung in
        ``_recover_from_aux``.
        """
        if payload_len <= 0:
            return None, []

        remaining_ids = slot_ids[self.HEADER_BIT_COUNT:]
        shuffled_ids = self._secure_shuffle(remaining_ids)

        total_bits = payload_len * 8
        try:
            repetitions = self._get_bit_repetitions(total_bits, len(remaining_ids))
        except ValueError:
            return None, []

        used_payload_ids = shuffled_ids[:total_bits * repetitions]
        extracted_bits = []
        erasure_pos = []

        for bit_idx in range(total_bits):
            byte_idx = bit_idx // 8
            bit_votes = []

            for rep in range(repetitions):
                rid = used_payload_ids[bit_idx * repetitions + rep]
                cursor.execute(
                    f"SELECT bio, trust_score FROM {self.AUX_TABLE} WHERE id=?",
                    (rid,),
                )
                res = cursor.fetchone()
                if res is None:
                    if byte_idx not in erasure_pos:
                        erasure_pos.append(byte_idx)
                    continue

                bio, score = res
                if bio is None or score is None:
                    if byte_idx not in erasure_pos:
                        erasure_pos.append(byte_idx)
                    continue
                if not self._verify_sys_cache_row(rid, bio, score):
                    # Manifest-Missbrauch → Erasure-Markierung, KEINE Tamper-Flag
                    # RS korrigiert das bei genügend Redundanz
                    if byte_idx not in erasure_pos:
                        erasure_pos.append(byte_idx)
                    continue

                try:
                    semantic, float_lsb, trailing, case = self._decode_payload_row(
                        bio, score
                    )
                    vote = self._majority_vote((semantic, float_lsb, trailing, case))
                    if vote is not None:
                        bit_votes.append(vote)
                except Exception:
                    continue

            if not bit_votes:
                extracted_bits.append(0)
                if byte_idx not in erasure_pos:
                    erasure_pos.append(byte_idx)
                continue

            ones = sum(bit_votes)
            zeros = len(bit_votes) - ones
            if ones == zeros:
                extracted_bits.append(0)
                if byte_idx not in erasure_pos:
                    erasure_pos.append(byte_idx)
            else:
                extracted_bits.append(1 if ones > zeros else 0)

        extracted_bytes = bytearray()
        for i in range(0, len(extracted_bits), 8):
            extracted_bytes.append(int("".join(map(str, extracted_bits[i:i+8])), 2))

        return bytes(extracted_bytes), erasure_pos

    def log_event(self, event_msg):
        cursor = self.conn.cursor()
        orig_ids = self._orig_ids

        slot_sequences = []
        for k in range(self.SLOT_COUNT):
            slot_start = k * self.SLOT_SIZE
            slot_ids = orig_ids[slot_start : slot_start + self.SLOT_SIZE]
            header_ids = slot_ids[:self.HEADER_BIT_COUNT]

            h_bits = []
            for rid in header_ids:
                cursor.execute(f"SELECT bio, trust_score FROM {self.AUX_TABLE} WHERE id=?", (rid,))
                res = cursor.fetchone()
                if res and res[0] is not None and res[1] is not None:
                    h_bits.append(self._decode_header_bit(res[0], res[1]))
                else:
                    h_bits.append(0)

            header_data = self._decode_header(h_bits)
            if header_data:
                slot_sequences.append((k, header_data["sequence_number"]))
            else:
                slot_sequences.append((k, 0))

        slot_sequences.sort(key=lambda x: x[1])
        new_seq = max(seq for _, seq in slot_sequences) + 1 if any(seq > 0 for _, seq in slot_sequences) else 1

        msg_bytes = event_msg.encode("utf-8")
        compressed_bytes = zlib.compress(msg_bytes, level=9)
        store_compressed = len(compressed_bytes) < len(msg_bytes)
        stored_msg_bytes = compressed_bytes if store_compressed else msg_bytes
        mac = hmac.new(self.k_hmac, stored_msg_bytes, hashlib.sha256).digest()[:16]
        payload_bytes = mac + stored_msg_bytes
        cursor.execute(
            f"SELECT sequence_number, entry_hash FROM {self.VISIBLE_LOG_TABLE} ORDER BY sequence_number DESC LIMIT 1"
        )
        prev_visible_row = cursor.fetchone()
        prev_hash = prev_visible_row[1] if prev_visible_row else b"\x00" * 32
        visible_entry_hash = self._entry_hash(new_seq, stored_msg_bytes, store_compressed, mac, prev_hash)

        payload_rows = self.SLOT_SIZE - self.HEADER_BIT_COUNT
        rows_per_channel_slot = payload_rows // self.CHANNEL_COUNT
        if self.PER_CHANNEL_RS:
            # One slot fragment uses one channel's carrier rows at a time.
            rows_for_ecc = rows_per_channel_slot
        else:
            rows_for_ecc = self.SLOT_COUNT * payload_rows
        ecc_plan_len = len(stored_msg_bytes)
        if self.PER_CHANNEL_RS and len(stored_msg_bytes) >= 200:
            # ECC + repetitions must fit one slot fragment, not the full payload at once.
            bits_per_fragment = rows_per_channel_slot // max(
                self.PER_CHANNEL_MIN_BIT_REPETITIONS, 1
            )
            ecc_plan_len = max(
                8,
                min(len(stored_msg_bytes), max(1, bits_per_fragment // 8 - 16)),
            )
        selected_nsym = self._select_ecc_symbols(
            ecc_plan_len,
            rows_for_ecc,
            per_channel=self.PER_CHANNEL_RS,
        )

        if self.PER_CHANNEL_RS:
            channel_results = self._encode_payload_per_channel(payload_bytes, selected_nsym)
            channel_blocks = {c: enc for c, enc in channel_results}
            max_enc_len = max(len(enc) for enc in channel_blocks.values())
            pc_min_rep = self._per_channel_min_repetitions(
                len(stored_msg_bytes), selected_nsym, rows_per_channel_slot
            )
            max_ch_bits_per_slot = rows_per_channel_slot // max(1, pc_min_rep)
            max_ch_bytes_per_slot = max(1, max_ch_bits_per_slot // 8)
            fragment_count = min(
                self.SLOT_COUNT,
                max(1, (max_enc_len + max_ch_bytes_per_slot - 1) // max_ch_bytes_per_slot),
            )
            channel_fragments = {
                c: self._fragment_encoded_bytes(channel_blocks[c], fragment_count, max_bytes_per_fragment=max_ch_bytes_per_slot)
                for c in range(self.CHANNEL_COUNT)
            }
            fragments = None
        else:
            rs_slot = RSCodec(selected_nsym)
            encoded_bytes = rs_slot.encode(payload_bytes)
            max_bytes_per_fragment = max(1, payload_rows // (self.MIN_BIT_REPETITIONS * 8))
            fragment_count = min(
                self.SLOT_COUNT,
                max(1, (len(encoded_bytes) + max_bytes_per_fragment - 1) // max_bytes_per_fragment),
            )
            fragments = self._fragment_encoded_bytes(encoded_bytes, fragment_count, max_bytes_per_fragment=max_bytes_per_fragment)
            channel_fragments = None

        fragment_slots = [slot_idx for slot_idx, _ in slot_sequences[:fragment_count]]
        if len(fragment_slots) < fragment_count:
            raise ValueError("Message too long for available slot fragments")

        if self.PER_CHANNEL_RS and len(stored_msg_bytes) < 200:
            fragment_count = 1
            fragment_slots = [fragment_slots[0]]
            channel_fragments = {
                c: [channel_blocks[c]] for c in range(self.CHANNEL_COUNT)
            }

        print(f"[V6] Selected {fragment_count} slot fragment(s) for New Seq: {new_seq}")

        self._set_sys_cache_write_mode(True)
        try:
            if self.PER_CHANNEL_RS:
                for fragment_index in range(fragment_count):
                    target_slot = fragment_slots[fragment_index]
                    slot_start = target_slot * self.SLOT_SIZE
                    slot_ids = orig_ids[slot_start : slot_start + self.SLOT_SIZE]
                    slot_payload_ids = slot_ids[self.HEADER_BIT_COUNT :]
                    header_ids = slot_ids[: self.HEADER_BIT_COUNT]

                    pieces = [
                        channel_fragments[c][fragment_index] for c in range(self.CHANNEL_COUNT)
                    ]
                    frag_len = max(len(piece) for piece in pieces)

                    for c in range(self.CHANNEL_COUNT):
                        piece = pieces[c]
                        padded = piece + b"\x00" * (frag_len - len(piece))
                        self._write_channel_encoded_to_slot(
                            cursor, c, padded, slot_payload_ids
                        )

                    if fragment_count == 1:
                        header_bytes = self._build_legacy_header(
                            len(stored_msg_bytes), selected_nsym, new_seq, store_compressed
                        )
                    else:
                        header_bytes = self._build_fragment_header(
                            frag_len,
                            selected_nsym,
                            new_seq,
                            store_compressed,
                            fragment_index,
                            fragment_count,
                        )
                    self._write_header_bits_to_slot(cursor, header_bytes, header_ids)

                print(
                    f"[V6] Per-channel RS: wrote {self.CHANNEL_COUNT} channels across "
                    f"{fragment_count} slot fragment(s) for New Seq: {new_seq} "
                    f"(nsym={selected_nsym}, min_rep={pc_min_rep})"
                )
            else:
                for fragment_index, fragment_bytes in enumerate(fragments):
                    target_slot = fragment_slots[fragment_index]
                    slot_start = target_slot * self.SLOT_SIZE
                    slot_ids = orig_ids[slot_start : slot_start + self.SLOT_SIZE]
                    header_ids = slot_ids[:self.HEADER_BIT_COUNT]
                    remaining_ids = slot_ids[self.HEADER_BIT_COUNT:]

                    payload_bits = []
                    for byte in fragment_bytes:
                        payload_bits.extend([int(b) for b in format(byte, "08b")])

                    repetitions = self._get_bit_repetitions(len(payload_bits), len(remaining_ids))
                    required_rows = len(payload_bits) * repetitions

                    shuffled_ids = self._secure_shuffle(remaining_ids)
                    used_payload_ids = shuffled_ids[:required_rows]

                    for i, bit in enumerate(payload_bits):
                        for rep in range(repetitions):
                            rid = used_payload_ids[i * repetitions + rep]
                            cursor.execute(f"SELECT bio, trust_score FROM {self.AUX_TABLE} WHERE id=?", (rid,))
                            res = cursor.fetchone()
                            if not res:
                                continue
                            bio, score = res
                            bio, score = self._encode_payload_row(bio, score, bit)
                            cursor.execute(
                                f"UPDATE {self.AUX_TABLE} SET bio=?, trust_score=? WHERE id=?",
                                (bio, score, rid),
                            )
                            cursor.execute(
                                f"""
                                INSERT OR REPLACE INTO {self.AUX_MANIFEST_TABLE} (id, row_mac, updated_at)
                                VALUES (?, ?, CURRENT_TIMESTAMP)
                                """,
                                (rid, self._sys_cache_row_mac(rid, bio, score)),
                            )

                    if fragment_count == 1:
                        header_bytes = self._build_legacy_header(
                            len(stored_msg_bytes), selected_nsym, new_seq, store_compressed
                        )
                    else:
                        header_bytes = self._build_fragment_header(
                            len(fragment_bytes),
                            selected_nsym,
                            new_seq,
                            store_compressed,
                            fragment_index,
                            fragment_count,
                        )

                    h_bits = []
                    for b in header_bytes:
                        h_bits.extend([int(x) for x in format(b, "08b")])

                    for i, bit in enumerate(h_bits):
                        rid = header_ids[i]
                        cursor.execute(f"SELECT bio, trust_score FROM {self.AUX_TABLE} WHERE id=?", (rid,))
                        res = cursor.fetchone()
                        if not res:
                            continue
                        bio, score = res
                        new_bio, new_score = self._encode_header_bit(bio, score, bit)
                        cursor.execute(
                            f"UPDATE {self.AUX_TABLE} SET bio=?, trust_score=? WHERE id=?",
                            (new_bio, new_score, rid),
                        )
                        cursor.execute(
                            f"""
                            INSERT OR REPLACE INTO {self.AUX_MANIFEST_TABLE} (id, row_mac, updated_at)
                            VALUES (?, ?, CURRENT_TIMESTAMP)
                            """,
                            (rid, self._sys_cache_row_mac(rid, new_bio, new_score)),
                        )

            cursor.execute(
                """
                INSERT OR REPLACE INTO audit_log (
                    sequence_number, event_msg, stored_msg, compressed, mac, entry_hash, prev_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    new_seq,
                    event_msg,
                    stored_msg_bytes,
                    1 if store_compressed else 0,
                    mac,
                    visible_entry_hash,
                    prev_hash,
                ),
            )

            archive_digest = hashlib.sha256(
                struct.pack(">I", new_seq) + event_msg.encode("utf-8")
            ).digest()
            cursor.execute(
                f"""
                INSERT OR REPLACE INTO {self.DECOY_ARCHIVE_TABLE} (
                    sequence_number, event_msg, record_digest, archive_tag
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    new_seq,
                    event_msg,
                    archive_digest,
                    "archive_mirror",
                ),
            )

            self.conn.commit()
            if fragment_count == 1:
                print(f"[V6] Event logged successfully in slot {fragment_slots[0]}: '{event_msg}'")
            else:
                print(f"[V6] Event logged successfully across {fragment_count} slots: '{event_msg}'")
        finally:
            self._set_sys_cache_write_mode(False)

    def _recover_fragmented_event(self, cursor, fragments_by_index):
        ordered_fragments = []
        expected_count = None
        sequence_number = None
        compressed = False
        nsym = None
        slot_tampered_flag = False

        for fragment_index in sorted(fragments_by_index.keys()):
            header_data, slot_ids, slot_tampered = fragments_by_index[fragment_index]
            if expected_count is None:
                expected_count = header_data["fragment_count"]
                sequence_number = header_data["sequence_number"]
                compressed = header_data["compressed"]
                nsym = header_data["nsym"]
            elif header_data["fragment_count"] != expected_count:
                return None

            fragment_bytes, erasures = self._decode_slot_payload_bytes(
                cursor,
                slot_ids,
                header_data["payload_len"],
            )
            if fragment_bytes is None:
                return None
            slot_tampered_flag = slot_tampered_flag or slot_tampered
            ordered_fragments.append((fragment_index, fragment_bytes, erasures))

        if expected_count is None or len(ordered_fragments) != expected_count:
            return None

        encoded_bytes = bytearray()
        erasure_pos = []
        offset = 0
        for _, fragment_bytes, fragment_erasures in ordered_fragments:
            encoded_bytes.extend(fragment_bytes)
            erasure_pos.extend(offset + pos for pos in fragment_erasures)
            offset += len(fragment_bytes)

        try:
            rs_slot = RSCodec(nsym)
            decoded_bytes = rs_slot.decode(bytes(encoded_bytes), erase_pos=sorted(erasure_pos))[0]
        except ReedSolomonError:
            # RS konnte nicht korrigieren — überspringe, nur bei echten Manifest-Fehlern als TAMPER markieren
            if slot_tampered_flag:
                return (sequence_number, "[TAMPERING DETECTED]")
            return None

        if len(decoded_bytes) < 16:
            if slot_tampered_flag:
                return (sequence_number, "[TAMPERING DETECTED]")
            return None

        recovered_mac = decoded_bytes[:16]
        recovered_msg = decoded_bytes[16:]
        expected_mac = hmac.new(self.k_hmac, recovered_msg, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(recovered_mac, expected_mac):
            return (sequence_number, "[TAMPERING DETECTED]")

        try:
            msg_body = zlib.decompress(recovered_msg) if compressed else recovered_msg
            msg_text = msg_body.decode("utf-8")
            return (sequence_number, msg_text)
        except (UnicodeDecodeError, zlib.error):
            return (sequence_number, "[TAMPERING DETECTED]")

    def recover_logs(self):
        ledger_logs = self._recover_from_visible_log()
        carrier_logs = self._recover_from_aux()

        if ledger_logs:
            print("[V6] Visible audit-log recovery path active. Returning canonical audit events.")
        elif carrier_logs:
            print("[V6] Auxiliary recovery path active. Returning hidden stego-recovered audit events.")

        merged = {}
        for sequence_number, msg_text in ledger_logs:
            merged[sequence_number] = msg_text
        for sequence_number, msg_text in carrier_logs:
            merged.setdefault(sequence_number, msg_text)

        merged_logs = sorted(merged.items(), key=lambda x: x[0])
        return [msg for seq, msg in merged_logs]

    def check_integrity(self):
        """
        Perform integrity check on recovered logs.
        Returns list of tampered entries if any detected.
        This enables continuous integrity monitoring in production.
        """
        recovered = self.recover_logs()
        if recovered is None:
            return ["RECOVERY_FAILED"]

        tampering_alerts = []
        for log in recovered:
            if "[TAMPERING DETECTED]" in str(log):
                tampering_alerts.append(log)

        return tampering_alerts


if __name__ == "__main__":
    print("--- 👻 GhostAudit V6: Multi-Event Ringbuffer & Persistence Test ---")
    
    # Sicherstellen, dass wir mit einer frischen DB starten für den Testlauf
    db_file = "ghost_audit_v6.db"
    if os.path.exists(db_file):
        os.remove(db_file)

    # 1. Bootstrapping & Logging von Event 1
    print("\n--- TEST 1: Initial Setup and Event 1 ---")
    ga1 = GhostAuditV6(db_path=db_file, secret_key="secure-v6-key")
    ga1.log_event("EVENT_1: ADMIN_LOGIN")

    # 2. Persistenz prüfen (Neue Instanz ohne DB-Reset!)
    print("\n--- TEST 2: Persistence and Event 2 (No DB Drop) ---")
    ga2 = GhostAuditV6(db_path=db_file, secret_key="secure-v6-key")
    ga2.log_event("EVENT_2: SENSITIVE_READ")

    # Logging Event 3
    ga2.log_event("EVENT_3: CONFIG_CHANGE")

    # Logs chronologisch auslesen
    logs = ga2.recover_logs()
    print(f"Recovered Active Logs in chronological order:")
    for idx, log in enumerate(logs):
        print(f"  [{idx + 1}] {log}")

    # 3. Ringbuffer Überlauf-Test (Wir loggen 3 weitere Events bei 5 Slots total)
    print("\n--- TEST 3: Ringbuffer Overflow ---")
    ga2.log_event("EVENT_4: BACKUP_START")
    ga2.log_event("EVENT_5: BACKUP_END")
    print(">> Logging EVENT_6 (This should overwrite EVENT_1 in Slot 0!) <<")
    ga2.log_event("EVENT_6: LOGOUT_ADMIN")

    # Logs erneut auslesen
    overflown_logs = ga2.recover_logs()
    print(f"Recovered Logs after Ringbuffer Overflow (Chronological Order):")
    for idx, log in enumerate(overflown_logs):
        print(f"  [{idx + 1}] {log}")

    ga1.close()
    ga2.close()

    print("\n--- TEST 4: Per-Channel RS (aux-only recovery) ---")
    pc_db = "ghost_audit_v6_per_channel.db"
    if os.path.exists(pc_db):
        os.remove(pc_db)
    ga_pc = GhostAuditV6(db_path=pc_db, secret_key="secure-v6-key", verbose=False)
    ga_pc.PER_CHANNEL_RS = True
    ga_pc.log_event("PER_CHANNEL_EVENT")
    ga_pc.conn.execute(f"DELETE FROM {GhostAuditV6.VISIBLE_LOG_TABLE}")
    ga_pc.conn.commit()
    pc_aux = ga_pc._recover_from_aux()
    print(f"Aux recovery: {pc_aux}")
    ga_pc.close()
    if os.path.exists(pc_db):
        os.remove(pc_db)

    # Continuous Integrity Monitoring Example
    print("\n--- CONTINUOUS INTEGRITY MONITORING EXAMPLE ---")
    print("In production, you would call check_integrity() periodically:")
    print("  alerts = ga.check_integrity()")
    print("  if alerts:")
    print("      trigger_security_alert(alerts)")
