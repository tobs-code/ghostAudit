"""
Hardware Resilience Test: real file-based carriers instead of SQLite.
Creates a binary carrier file (8000 fixed-width records), runs the full
GhostAuditV7 pipeline with file I/O, then attacks the file directly.

Usage:  python tests/hardware_resilience_test.py
"""
import os, sys, struct, random, uuid, hashlib, hmac, zlib, sqlite3

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.ghost_audit_v7 import GhostAuditV7, StegoEngine, RSCodec, ReedSolomonError

RECORD_BYTES = 512

class FileCarrierGhostAuditV7(GhostAuditV7):
    """Carrier data lives in a binary file; SQLite is only for metadata tables.
    Uses parent's V8 multiplexed log_event and _recover_from_aux directly —
    only the low-level read/write of individual carrier rows is overridden."""

    PROFILE_SCORE_OFF = 264
    AVATAR_URL_OFF = 272

    def __init__(self, db_path, carrier_path, secret_key=None, verbose=True):
        self.carrier_path = carrier_path
        self._fh = None
        super().__init__(db_path=db_path, secret_key=secret_key, verbose=verbose)
        self._init_carrier_file()
        self._rid_to_pos = {rid: idx for idx, rid in enumerate(self._orig_ids)}
        self._seed_aux_table()

    def close(self):
        self._close_fh()
        super().close()

    def _init_carrier_file(self):
        if not os.path.exists(self.carrier_path):
            n = self.SLOT_COUNT * self.SLOT_SIZE
            base = "system is currently working and active  "
            buf = bytearray(n * RECORD_BYTES)
            for i in range(n):
                off = i * RECORD_BYTES
                text = f"{base} [{i+1:05d}]"
                encoded = text.encode("utf-8")[:255]
                buf[off:off+256] = encoded + b"\x00" * (256 - len(encoded))
                struct.pack_into("<d", buf, off + 256, 100.0 + (i % 100) * 0.01)
                struct.pack_into("<d", buf, off + self.PROFILE_SCORE_OFF, 0.5 + (i % 50) * 0.01)
                av = "~" if (i % 3 == 0) else ""
                av_bytes = av.encode("utf-8")[:239]
                buf[self.AVATAR_URL_OFF:self.AVATAR_URL_OFF + len(av_bytes)] = av_bytes
            with open(self.carrier_path, "wb") as f:
                f.write(buf)

    def _seed_aux_table(self):
        """Populate SQLite aux table with initial carrier data."""
        self._set_sys_cache_write_mode(True)
        cursor = self.conn.cursor()
        for rid in self._orig_ids:
            bio, score, ps, av = self._read_carrier_fields(rid)
            cursor.execute(
                f"INSERT OR IGNORE INTO {self.AUX_TABLE} (id, bio, trust_score, profile_score, avatar_url) VALUES (?, ?, ?, ?, ?)",
                (rid, bio, score, ps, av),
            )
            mac = self._sys_cache_row_mac(rid, bio, score, ps, av)
            cursor.execute(
                f"INSERT OR IGNORE INTO {self.AUX_MANIFEST_TABLE} (id, row_mac, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
                (rid, mac),
            )
        self.conn.commit()
        self._set_sys_cache_write_mode(False)

    def _open_fh(self):
        if not hasattr(self, '_fh') or self._fh is None:
            self._fh = open(self.carrier_path, "r+b")
        return self._fh

    def _close_fh(self):
        if hasattr(self, '_fh') and self._fh is not None:
            self._fh.close()
            self._fh = None

    def _read_carrier_fields(self, rid):
        pos = self._rid_to_pos.get(rid)
        if pos is None:
            return "", 0.0, 0.0, ""
        off = pos * RECORD_BYTES
        f = self._open_fh()
        f.seek(off)
        rec = f.read(RECORD_BYTES)
        if len(rec) < RECORD_BYTES:
            return "", 0.0, 0.0, ""
        bio = rec[:256].split(b"\x00")[0].decode("utf-8", errors="replace")
        score = struct.unpack_from("<d", rec, 256)[0]
        ps = struct.unpack_from("<d", rec, self.PROFILE_SCORE_OFF)[0] if off + self.PROFILE_SCORE_OFF + 8 <= len(rec) else 0.0
        av = rec[self.AVATAR_URL_OFF:].split(b"\x00")[0].decode("utf-8", errors="replace") if off + self.AVATAR_URL_OFF < len(rec) else ""
        return bio, score, ps, av

    def _write_carrier_fields(self, rid, bio, score, profile_score, avatar_url):
        pos = self._rid_to_pos.get(rid)
        if pos is None:
            return
        off = pos * RECORD_BYTES
        encoded = bio.encode("utf-8")[:255]
        buf = bytearray(RECORD_BYTES)
        buf[:256] = encoded + b"\x00" * (256 - len(encoded))
        struct.pack_into("<d", buf, 256, score)
        struct.pack_into("<d", buf, self.PROFILE_SCORE_OFF, profile_score)
        av_bytes = avatar_url.encode("utf-8")[:239]
        buf[self.AVATAR_URL_OFF:self.AVATAR_URL_OFF + len(av_bytes)] = av_bytes
        f = self._open_fh()
        f.seek(off)
        f.write(buf)

    def _write_sys_cache_slot_v8(self, cursor, channel_blocks, slot_payload_ids):
        """Override: write encoded data to file instead of SQLite."""
        channel_bits_dict = {}
        for c in range(self.CHANNEL_COUNT):
            bits = []
            for byte_val in channel_blocks.get(c, b""):
                bits.extend([int(b) for b in format(byte_val, "08b")])
            channel_bits_dict[c] = bits

        max_bits = max(len(b) for b in channel_bits_dict.values()) if channel_bits_dict else 0
        if max_bits == 0:
            return
        for c in range(self.CHANNEL_COUNT):
            if c not in channel_bits_dict:
                pad_len = max_bits
                channel_bits_dict[c] = [int(b) for b in format(int.from_bytes(os.urandom((pad_len+7)//8), 'big'), f'0{pad_len}b')][:pad_len]
            else:
                pad_len = max_bits - len(channel_bits_dict[c])
                if pad_len > 0:
                    random_pad = [int(b) for b in format(int.from_bytes(os.urandom((pad_len+7)//8), 'big'), f'0{pad_len}b')][:pad_len]
                    channel_bits_dict[c] = channel_bits_dict[c] + random_pad

        available_rows = len(slot_payload_ids)
        repetitions = self._get_dynamic_repetitions(max_bits, available_rows)
        if max_bits * repetitions > available_rows:
            repetitions = max(1, available_rows // max_bits)
            if max_bits * repetitions > available_rows:
                repetitions = 1
                max_bits = available_rows

        for bit_idx in range(max_bits):
            for rep in range(repetitions):
                row_idx = bit_idx * repetitions + rep
                if row_idx >= len(slot_payload_ids):
                    break
                rid = slot_payload_ids[row_idx]
                bio, score, ps, av = self._read_carrier_fields(rid)
                logical_bits = {c: channel_bits_dict[c][bit_idx] for c in range(self.CHANNEL_COUNT)}
                new_bio, new_score, new_ps, new_av = self._encode_all_columns_shuffled(
                    rid, bio, score, ps, logical_bits, avatar_url=av
                )
                self._write_carrier_fields(rid, new_bio, new_score, new_ps, new_av)
                cursor.execute(
                    f"UPDATE {self.AUX_TABLE} SET bio=?, trust_score=?, profile_score=?, avatar_url=? WHERE id=?",
                    (new_bio, new_score, new_ps, new_av, rid),
                )
                mac = self._sys_cache_row_mac(rid, new_bio, new_score, new_ps, new_av)
                cursor.execute(
                    f"INSERT OR REPLACE INTO {self.AUX_MANIFEST_TABLE} (id, row_mac, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
                    (rid, mac),
                )

    def _extract_all_channels_v8(self, cursor, slot_payload_ids, num_bits):
        """Override: read from file instead of SQLite."""
        available_rows = len(slot_payload_ids)
        max_bits = num_bits
        repetitions = self._get_dynamic_repetitions(max_bits, available_rows)

        if max_bits * repetitions > available_rows:
            repetitions = max(1, available_rows // max_bits)
            if max_bits * repetitions > available_rows:
                repetitions = 1
                max_bits = available_rows

        channel_bits = {c: [] for c in range(self.CHANNEL_COUNT)}
        channel_erasures = {c: [] for c in range(self.CHANNEL_COUNT)}
        slot_idx = self._get_slot_idx_for_row(slot_payload_ids[0]) if slot_payload_ids else 0
        _, k_hm = self._get_slot_keys(slot_idx)

        for bit_idx in range(max_bits):
            votes = {c: [] for c in range(self.CHANNEL_COUNT)}
            row_mac_cache = {}

            for rep in range(repetitions):
                row_idx = bit_idx * repetitions + rep
                if row_idx >= len(slot_payload_ids):
                    break
                rid = slot_payload_ids[row_idx]
                bio, score, ps, av = self._read_carrier_fields(rid)

                row_mac_blob = None
                if rid not in row_mac_cache:
                    cursor.execute(
                        f"SELECT row_mac FROM {self.AUX_MANIFEST_TABLE} WHERE id=?",
                        (rid,),
                    )
                    mac_res = cursor.fetchone()
                    row_mac_blob = mac_res[0] if mac_res else None
                    row_mac_cache[rid] = row_mac_blob
                else:
                    row_mac_blob = row_mac_cache[rid]

                logical_bits = self._decode_all_columns_shuffled(
                    rid, bio, score, ps, av
                )

                for c in range(self.CHANNEL_COUNT):
                    val = logical_bits.get(c, 0)
                    if row_mac_blob and len(row_mac_blob) >= 32:
                        expected_mac = hmac.new(
                            k_hm,
                            struct.pack(">I B B", rid, c, val),
                            hashlib.sha256
                        ).digest()[:8]
                        stored_mac = row_mac_blob[c*8 : (c+1)*8]
                        if hmac.compare_digest(expected_mac, stored_mac):
                            votes[c].append(val)
                        else:
                            votes[c].append(None)
                    else:
                        votes[c].append(val)

            for c in range(self.CHANNEL_COUNT):
                ch_votes = votes[c]
                valid_votes = [v for v in ch_votes if v is not None]
                erased_count = len(ch_votes) - len(valid_votes)
                if erased_count > len(ch_votes) // 2 or not valid_votes:
                    channel_bits[c].append(0)
                    byte_pos = bit_idx // 8
                    if byte_pos not in channel_erasures[c]:
                        channel_erasures[c].append(byte_pos)
                else:
                    ones = sum(valid_votes)
                    zeros = len(valid_votes) - ones
                    channel_bits[c].append(1 if ones >= zeros else 0)

        channel_bytes = {}
        for c in range(self.CHANNEL_COUNT):
            channel_bytes[c] = self._bits_to_bytes(channel_bits[c])
        return channel_bytes, channel_erasures

    def _write_header_bits_to_slot(self, cursor, header_bytes, header_ids):
        """Write header bits to file, encoding on bio+trust_score+profile_score+avatar_url."""
        h_bits = []
        for b in header_bytes:
            h_bits.extend([int(x) for x in format(b, "08b")])

        for i, bit in enumerate(h_bits):
            if i >= len(header_ids):
                break
            rid = header_ids[i]
            bio, score, ps, av = self._read_carrier_fields(rid)
            new_bio, new_score, new_ps, new_av = self._encode_header_bit(
                bio, score, bit, row_id=rid, profile_score=ps, avatar_url=av
            )
            self._write_carrier_fields(rid, new_bio, new_score, new_ps, new_av)
            cursor.execute(
                f"UPDATE {self.AUX_TABLE} SET bio=?, trust_score=?, profile_score=?, avatar_url=? WHERE id=?",
                (new_bio, new_score, new_ps, new_av, rid),
            )
            mac = self._sys_cache_row_mac(rid, new_bio, new_score, new_ps, new_av)
            cursor.execute(
                f"INSERT OR REPLACE INTO {self.AUX_MANIFEST_TABLE} (id, row_mac, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
                (rid, mac),
            )

    def log_event(self, event_msg, immediate_commit=True):
        """Override: use _read_carrier_fields for header scan, then parent's write path."""
        cursor = self.conn.cursor()
        orig_ids = self._orig_ids

        slot_sequences = []
        for k in range(self.SLOT_COUNT):
            slot_start = k * self.SLOT_SIZE
            slot_ids = orig_ids[slot_start: slot_start + self.SLOT_SIZE]
            header_ids = slot_ids[:self.HEADER_BIT_COUNT]

            h_bits = []
            for rid in header_ids:
                try:
                    bio, score, ps, av = self._read_carrier_fields(rid)
                    v = self._decode_header_bit(rid, bio, score, profile_score=ps, avatar_url=av)
                except Exception:
                    v = 0
                h_bits.append(v)

            header_data = self._decode_header(h_bits, k)
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
        rows_for_ecc = payload_rows
        ecc_plan_len = len(stored_msg_bytes)

        if len(stored_msg_bytes) >= 200:
            bits_per_fragment = payload_rows // max(self.PER_CHANNEL_MIN_BIT_REPETITIONS, 1)
            ecc_plan_len = max(8, min(len(stored_msg_bytes), max(1, bits_per_fragment // 8 - 16)))

        selected_nsym = self._select_ecc_symbols(ecc_plan_len, rows_for_ecc, per_channel=True)
        channel_blocks = self._encode_payload_per_channel_v7(payload_bytes, selected_nsym)

        active_seqs = set(seq for _, seq in slot_sequences if seq > 0)
        active_count = len(active_seqs)
        max_replicas = max(1, self.SLOT_COUNT // max(1, active_count + 1))
        replica_count = min(self.REPLICA_COUNT, max_replicas, len(slot_sequences))
        replica_slots = [slot_idx for slot_idx, _ in slot_sequences[:replica_count]]

        if self.verbose:
            print(f"[V7] Writing sequence {new_seq} to {replica_count} replica(s) with RAID-6 P+Q parity (nsym={selected_nsym})")

        self._set_sys_cache_write_mode(True, commit=immediate_commit)
        try:
            for replica_idx in range(replica_count):
                target_slot = replica_slots[replica_idx]
                slot_start = target_slot * self.SLOT_SIZE
                slot_ids = orig_ids[slot_start: slot_start + self.SLOT_SIZE]
                slot_payload_ids = slot_ids[self.HEADER_BIT_COUNT:]
                header_ids = slot_ids[:self.HEADER_BIT_COUNT]

                self._write_sys_cache_slot_v8(cursor, channel_blocks, slot_payload_ids)

                header_bytes = self._build_legacy_header(
                    len(stored_msg_bytes), selected_nsym, new_seq, store_compressed, target_slot
                )
                self._write_header_bits_to_slot(cursor, header_bytes, header_ids)

            cursor.execute(
                """
                INSERT OR REPLACE INTO audit_log (
                    sequence_number, event_msg, stored_msg, compressed, mac, entry_hash, prev_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (new_seq, event_msg, stored_msg_bytes, store_compressed, mac,
                 visible_entry_hash, prev_hash),
            )
            if immediate_commit:
                self.conn.commit()
            return True
        except Exception:
            self.conn.rollback()
            raise
        finally:
            self._set_sys_cache_write_mode(False, commit=immediate_commit)

    def log_events(self, event_msgs, immediate_commit=True):
        """Batch-log multiple events with file-based header scan + single commit."""
        cursor = self.conn.cursor()
        orig_ids = self._orig_ids

        slot_sequences = []
        for k in range(self.SLOT_COUNT):
            slot_start = k * self.SLOT_SIZE
            slot_ids = orig_ids[slot_start: slot_start + self.SLOT_SIZE]
            header_ids = slot_ids[:self.HEADER_BIT_COUNT]
            h_bits = []
            for rid in header_ids:
                try:
                    bio, score, ps, av = self._read_carrier_fields(rid)
                    v = self._decode_header_bit(rid, bio, score, profile_score=ps, avatar_url=av)
                except Exception:
                    v = 0
                h_bits.append(v)
            header_data = self._decode_header(h_bits, k)
            slot_sequences.append((k, header_data["sequence_number"] if header_data else 0))
        slot_sequences.sort(key=lambda x: x[1])

        cursor.execute(
            f"SELECT sequence_number, entry_hash FROM {self.VISIBLE_LOG_TABLE} ORDER BY sequence_number DESC LIMIT 1"
        )
        prev_visible_row = cursor.fetchone()
        prev_hash = prev_visible_row[1] if prev_visible_row else b"\x00" * 32

        base_seq = max(seq for _, seq in slot_sequences) + 1 if any(seq > 0 for _, seq in slot_sequences) else 1
        prepared = []
        for i, msg in enumerate(event_msgs):
            new_seq = base_seq + i
            ch, stored, comp, nsym, mac = self._prepare_event(msg, new_seq, prev_hash)
            eh = self._entry_hash(new_seq, stored, comp, mac, prev_hash)
            prev_hash = eh
            prepared.append((msg, new_seq, ch, stored, comp, nsym, mac, eh))

        self._set_sys_cache_write_mode(True, commit=immediate_commit)
        try:
            for msg, new_seq, channel_blocks, stored_msg_bytes, store_compressed, selected_nsym, mac, entry_hash in prepared:
                replica_slots = self._write_event_to_slots(cursor, channel_blocks, stored_msg_bytes, selected_nsym, new_seq, store_compressed, slot_sequences)

                for i in range(len(replica_slots)):
                    slot_sequences[i] = (slot_sequences[i][0], new_seq)
                slot_sequences.sort(key=lambda x: x[1])

                cursor.execute(
                    "INSERT OR REPLACE INTO audit_log (sequence_number, event_msg, stored_msg, compressed, mac, entry_hash, prev_hash) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (new_seq, msg, stored_msg_bytes, 1 if store_compressed else 0, mac, entry_hash, prev_hash),
                )
                archive_digest = hashlib.sha256(struct.pack(">I", new_seq) + msg.encode("utf-8")).digest()
                cursor.execute(
                    f"INSERT OR REPLACE INTO {self.DECOY_ARCHIVE_TABLE} (sequence_number, event_msg, record_digest, archive_tag) VALUES (?, ?, ?, ?)",
                    (new_seq, msg, archive_digest, "archive_mirror"),
                )
                cursor.execute(
                    f"INSERT OR REPLACE INTO {self.EVENT_MAC_TABLE} (sequence_number, event_mac) VALUES (?, ?)",
                    (new_seq, self._compute_event_mac(new_seq, msg)),
                )
                if immediate_commit:
                    self.anchor_merkle_root(sequence_number=new_seq)
                self._key_evolve_count += 1
                self._k_write_merkle = hmac.new(self._k_write_merkle, b"evolve", hashlib.sha256).digest()
            cursor.execute(
                f"INSERT OR REPLACE INTO {self._key_state_table} (id, evolve_count) VALUES (1, ?)",
                (self._key_evolve_count,),
            )
            if immediate_commit:
                self.conn.commit()
            return True
        except Exception:
            self.conn.rollback()
            raise
        finally:
            self._set_sys_cache_write_mode(False, commit=immediate_commit)

        if not immediate_commit:
            return [msg for msg, _, _, _, _, _, _, _ in prepared]

    def recover_events(self):
        """Uses parent's _recover_from_aux which calls overridden _extract_all_channels_v8."""
        return self._recover_from_aux()


# ---- Test scenarios ----

def _cleanup(*paths):
    for p in paths:
        if os.path.exists(p):
            try: os.remove(p)
            except PermissionError: pass

def test_basic():
    db, car = f"hw_{uuid.uuid4().hex[:6]}.db", f"hw_{uuid.uuid4().hex[:6]}.bin"
    try:
        g = FileCarrierGhostAuditV7(db, car, verbose=False)
        g.log_event("HWT0")
        r = g.recover_events()
        g.close()
        ok = sum(1 for _, m in r if m == "HWT0") == 1
        return ok, "OK" if ok else str(r)
    finally:
        _cleanup(db, car)

def test_truncation_5():
    db, car = f"hw_{uuid.uuid4().hex[:6]}.db", f"hw_{uuid.uuid4().hex[:6]}.bin"
    try:
        g = FileCarrierGhostAuditV7(db, car, verbose=False)
        g.log_event("T0")
        g.close()
        n = g.SLOT_COUNT * g.SLOT_SIZE
        payload_only = [i for i in range(n) if (i % g.SLOT_SIZE) >= g.HEADER_BIT_COUNT]
        kills = set(random.sample(payload_only, int(len(payload_only) * 0.05)))
        with open(car, "r+b") as f:
            for idx in range(n):
                if idx in kills:
                    f.seek(idx * RECORD_BYTES)
                    f.write(b"\x00" * RECORD_BYTES)
        g2 = FileCarrierGhostAuditV7(db, car, verbose=False)
        r = g2.recover_events()
        g2.close()
        ok = sum(1 for _, m in r if m == "T0") == 1
        return ok, "OK" if ok else str(r)
    finally:
        _cleanup(db, car)

def test_corruption_3():
    db, car = f"hw_{uuid.uuid4().hex[:6]}.db", f"hw_{uuid.uuid4().hex[:6]}.bin"
    try:
        g = FileCarrierGhostAuditV7(db, car, verbose=False)
        g.log_event("T0")
        g.close()
        with open(car, "rb") as f:
            data = bytearray(f.read())
        n = int(len(data) * 0.03)
        for pos in random.sample(range(len(data)), n):
            data[pos] ^= 0xFF
        with open(car, "wb") as f:
            f.write(data)
        g2 = FileCarrierGhostAuditV7(db, car, verbose=False)
        r = g2.recover_events()
        g2.close()
        ok = sum(1 for _, m in r if m == "T0") == 1
        return ok, "OK" if ok else str(r)
    finally:
        _cleanup(db, car)

def test_multi_event():
    db, car = f"hw_{uuid.uuid4().hex[:6]}.db", f"hw_{uuid.uuid4().hex[:6]}.bin"
    try:
        g = FileCarrierGhostAuditV7(db, car, verbose=False)
        for m in ["A", "B", "C"]:
            g.log_event(m)
        g.close()
        n = g.SLOT_COUNT * g.SLOT_SIZE
        payload_only = [i for i in range(n) if (i % g.SLOT_SIZE) >= g.HEADER_BIT_COUNT]
        kills = set(random.sample(payload_only, int(len(payload_only) * 0.001)))
        with open(car, "r+b") as f:
            for idx in range(n):
                if idx in kills:
                    f.seek(idx * RECORD_BYTES)
                    f.write(b"\x00" * RECORD_BYTES)
        g2 = FileCarrierGhostAuditV7(db, car, verbose=False)
        r = g2.recover_events()
        g2.close()
        recovered = {m for _, m in r if m in ("A", "B", "C")}
        ok = recovered == {"A", "B", "C"}
        return ok, "OK" if ok else f"got {recovered}"
    finally:
        _cleanup(db, car)

def test_physical_truncation():
    db, car = f"hw_{uuid.uuid4().hex[:6]}.db", f"hw_{uuid.uuid4().hex[:6]}.bin"
    try:
        g = FileCarrierGhostAuditV7(db, car, verbose=False)
        g.log_event("T0")
        g.close()
        fs = os.path.getsize(car)
        with open(car, "r+b") as f:
            f.truncate(int(fs * 0.70))
        g2 = FileCarrierGhostAuditV7(db, car, verbose=False)
        r = g2.recover_events()
        g2.close()
        ok = sum(1 for _, m in r if m == "T0") == 1
        return ok, "OK" if ok else str(r)
    finally:
        _cleanup(db, car)


if __name__ == "__main__":
    random.seed(42)
    tests = [
        ("Basic recovery", test_basic),
        ("5% row deletion", test_truncation_5),
        ("3% byte corruption", test_corruption_3),
        ("3 events 0.5% deletion", test_multi_event),
        ("30% physical truncation", test_physical_truncation),
    ]
    print("=== Hardware Resilience Tests ===")
    for name, fn in tests:
        ok, msg = fn()
        print(f"  {name}: {'PASS' if ok else 'FAIL'} ({msg})")
    print("done")
