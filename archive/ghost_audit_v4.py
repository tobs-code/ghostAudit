import sqlite3
import numpy as np
import random
import hashlib
import time
import struct
from reedsolo import RSCodec, ReedSolomonError

class StegoEngine:
    SEMANTIC_MAP = {
        "currently": ["currently", "presently"],
        "active": ["active", "online"],
        "working": ["working", "operating"],
        "system": ["system", "platform"],
        "active and": ["active and", "active &"]
    }

    @staticmethod
    def encode_bit_trailing_space(text, bit):
        return text.rstrip() + (" " if bit else "")

    @staticmethod
    def decode_bit_trailing_space(text):
        return 1 if text.endswith(" ") else 0

    @staticmethod
    def encode_bit_case(text, bit):
        # We need to make sure we modify a character that IS alphabetic
        # and that the change persists. 
        # SQLite TEXT might have issues if we only change case? No, it should be fine.
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
        s = f"{value:.8f}"
        last_digit = int(s[-1])
        if (last_digit % 2) != bit:
            last_digit = (last_digit + 1) % 10
        return float(s[:-1] + str(last_digit))

    @staticmethod
    def decode_bit_float_lsb(value):
        s = f"{value:.8f}"
        return int(s[-1]) % 2

    @staticmethod
    def encode_bit_semantic(text, bit):
        for key, synonyms in StegoEngine.SEMANTIC_MAP.items():
            if key in text.lower():
                chosen = synonyms[1] if bit else synonyms[0]
                return text.replace(key, chosen)
        return text

    @staticmethod
    def decode_bit_semantic(text):
        for key, synonyms in StegoEngine.SEMANTIC_MAP.items():
            if synonyms[1] in text.lower(): return 1
            if synonyms[0] in text.lower(): return 0
        return 0

class GhostAuditV4:
    def __init__(self, db_path="ghost_audit_v4.db", secret_key="v4-stealth-key", ecc_symbols=32):
        self.db_path = db_path
        self.secret_key = secret_key
        self.ecc_symbols = ecc_symbols
        self.rs = RSCodec(ecc_symbols)
        self.conn = sqlite3.connect(db_path)
        # Pre-compute canonical ID sequence once (seed=42) so setup, log and recover all agree.
        rng_ids = random.Random(42)
        self._orig_ids = []
        c = 1
        for i in range(500):
            self._orig_ids.append(c)
            c += rng_ids.randint(1, 4)
        self._setup_db()

    def _setup_db(self):
        cursor = self.conn.cursor()
        cursor.execute("DROP TABLE IF EXISTS audit_carrier")
        cursor.execute("CREATE TABLE audit_carrier (id INTEGER PRIMARY KEY, bio TEXT, trust_score REAL)")
        # Use a separate RNG for trust scores so it doesn't affect _orig_ids.
        rng_scores = random.Random(1234)
        users = [
            (cid, "System access is currently active.", rng_scores.uniform(0.9, 1.0))
            for cid in self._orig_ids
        ]
        cursor.executemany("INSERT INTO audit_carrier VALUES (?, ?, ?)", users)
        self.conn.commit()

    def _decode_header(self, header_bits):
        if len(header_bits) < 64: return None
        bytes_data = bytearray()
        for i in range(0, 64, 8):
            bits_str = "".join(map(str, header_bits[i:i+8]))
            bytes_data.append(int(bits_str, 2))
        
        # DEBUG: Print hex representation
        print(f"[Debug] Header Raw Bytes (hex): {bytes_data.hex()}")
        
        try:
            # We unpack manually to be 100% sure about the bit order
            magic = bytes_data[0]
            msg_len = (bytes_data[1] << 8) | bytes_data[2]
            nsym = bytes_data[3]
            max_id = (bytes_data[4] << 24) | (bytes_data[5] << 16) | (bytes_data[6] << 8) | bytes_data[7]
            
            if magic == 0x47: return msg_len, nsym, max_id
        except Exception as e:
            print(f"[Debug] Header Manual Unpack Error: {e}")
            return None
        return None

    def log_event(self, event_msg):
        cursor = self.conn.cursor()
        # Use the canonical ID sequence pre-computed in __init__.
        orig_ids = self._orig_ids

        # 1. Header IDs (first 64)
        header_ids = orig_ids[:64]
        
        # 2. Payload Bits
        data_bytes = event_msg.encode('utf-8')
        encoded_bytes = self.rs.encode(data_bytes)
        payload_bits = []
        for byte in encoded_bytes:
            payload_bits.extend([int(b) for b in format(byte, '08b')])
            
        # 3. Embed Payload in remaining IDs
        remaining_ids = orig_ids[64:]
        rng = random.Random(self.secret_key)
        rng.shuffle(remaining_ids)
        
        used_payload_ids = remaining_ids[:len(payload_bits)]
        max_id_at_log = max(used_payload_ids)
        
        print(f"[Debug] Log-time MaxID: {max_id_at_log}")
        
        for i, bit in enumerate(payload_bits):
            rid = used_payload_ids[i]
            cursor.execute("SELECT bio, trust_score FROM audit_carrier WHERE id=?", (rid,))
            res = cursor.fetchone()
            if not res: continue # Natural gap
            bio, score = res
            channel = i % 4
            if channel == 0: bio = StegoEngine.encode_bit_semantic(bio, bit)
            elif channel == 1: score = StegoEngine.encode_bit_float_lsb(score, bit)
            elif channel == 2: bio = StegoEngine.encode_bit_trailing_space(bio, bit)
            else: bio = StegoEngine.encode_bit_case(bio, bit)
            cursor.execute("UPDATE audit_carrier SET bio=?, trust_score=? WHERE id=?", (bio, score, rid))
            
        # 4. Header (8 bytes)
        header_bytes = struct.pack(">B H B I", 0x47, len(event_msg), self.ecc_symbols, max_id_at_log)
        print(f"[Debug] Writing Header Bytes (hex): {header_bytes.hex()}")
        
        h_bits = []
        for b in header_bytes:
            bits_str = format(b, '08b')
            h_bits.extend([int(x) for x in bits_str])
        
        for i, bit in enumerate(h_bits):
            rid = header_ids[i]
            cursor.execute("SELECT bio FROM audit_carrier WHERE id=?", (rid,))
            res = cursor.fetchone()
            if not res: continue
            bio = res[0]
            new_bio = StegoEngine.encode_bit_case(bio, bit)
            cursor.execute("UPDATE audit_carrier SET bio=? WHERE id=?", (new_bio, rid))
            
        self.conn.commit()
        
        # VERIFICATION
        verify_bits = []
        for rid in header_ids:
            cursor.execute("SELECT bio FROM audit_carrier WHERE id=?", (rid,))
            res = cursor.fetchone()
            verify_bits.append(StegoEngine.decode_bit_case(res[0]) if res else 0)
        verify_bytes = bytearray()
        for i in range(0, 64, 8):
            verify_bytes.append(int("".join(map(str, verify_bits[i:i+8])), 2))
        print(f"[Debug] Verification Header Bytes (hex): {verify_bytes.hex()}")
        
        print(f"[V4] Event logged: '{event_msg}' (MaxID={max_id_at_log})")

    def recover_logs(self, original_msg_len):
        cursor = self.conn.cursor()
        
        # 1. Recover Header from the canonical root anchors (first 64 IDs).
        # Using self._orig_ids guarantees the same sequence as log_event.
        orig_ids = self._orig_ids
        orig_header_ids = orig_ids[:64]
        
        h_bits = []
        for rid in orig_header_ids:
            cursor.execute("SELECT bio FROM audit_carrier WHERE id=?", (rid,))
            res = cursor.fetchone()
            if res:
                h_bits.append(StegoEngine.decode_bit_case(res[0]))
            else:
                # Root ID missing -> Header is likely corrupt. 
                # For PoC, let's just use 0 and hope magic byte survives.
                h_bits.append(0)
        
        header_data = self._decode_header(h_bits)
        if not header_data: return "[ERROR] Header corrupt."
        msg_len, nsym, max_id_at_log = header_data
        print(f"[V4] Header Decoded: MsgLen={msg_len}, NSym={nsym}, MaxID={max_id_at_log}")

        # 2. Payload Recovery (same logic)
        remaining_ids = orig_ids[64:]
        rng = random.Random(self.secret_key)
        rng.shuffle(remaining_ids)
        
        total_bits = (msg_len + nsym) * 8
        used_payload_ids = remaining_ids[:total_bits]
        
        extracted_bits = []
        erasure_pos = []
        
        for i, rid in enumerate(used_payload_ids):
            byte_idx = i // 8
            cursor.execute("SELECT bio, trust_score FROM audit_carrier WHERE id=?", (rid,))
            res = cursor.fetchone()
            
            if res is None: # DELETED!
                extracted_bits.append(0)
                if byte_idx not in erasure_pos: erasure_pos.append(byte_idx)
                continue
                
            bio, score = res
            channel = i % 4
            try:
                if channel == 0: bit = StegoEngine.decode_bit_semantic(bio)
                elif channel == 1: bit = StegoEngine.decode_bit_float_lsb(score)
                elif channel == 2: bit = StegoEngine.decode_bit_trailing_space(bio)
                else: bit = StegoEngine.decode_bit_case(bio)
                extracted_bits.append(bit)
            except:
                extracted_bits.append(0)
                if byte_idx not in erasure_pos: erasure_pos.append(byte_idx)

        extracted_bytes = bytearray()
        for i in range(0, len(extracted_bits), 8):
            extracted_bytes.append(int("".join(map(str, extracted_bits[i:i+8])), 2))
            
        try:
            erasure_pos.sort()
            print(f"[V4] Attempting RS decode with {len(erasure_pos)} erasures at {erasure_pos}")
            decoded_bytes = self.rs.decode(extracted_bytes, erase_pos=erasure_pos)[0]
            return decoded_bytes.decode('utf-8')
        except ReedSolomonError:
            return "[ERROR] Recovery failed."

if __name__ == "__main__":
    ga = GhostAuditV4(ecc_symbols=32)
    msg = "V4_OK"
    ga.log_event(msg)
    
    print("\n--- Simulating Targeted Attack (within RS capacity) ---")
    cursor = ga.conn.cursor()
    # Delete some rows in the payload area
    cursor.execute("DELETE FROM audit_carrier WHERE id BETWEEN 100 AND 150")
    ga.conn.commit()
    
    print(f"Recovered: {ga.recover_logs(len(msg))}")
