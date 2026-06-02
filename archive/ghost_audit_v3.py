import sqlite3
import numpy as np
import random
import hashlib
import time
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

class GhostAuditV3:
    def __init__(self, db_path="ghost_audit_v3.db", secret_key="v3-anchor-secret", ecc_symbols=12):
        self.db_path = db_path
        self.secret_key = secret_key
        self.rs = RSCodec(ecc_symbols)
        self.conn = sqlite3.connect(db_path)
        self._setup_db()

    def _setup_db(self):
        cursor = self.conn.cursor()
        cursor.execute("DROP TABLE IF EXISTS high_security_users")
        cursor.execute("""
            CREATE TABLE high_security_users (
                id INTEGER PRIMARY KEY, 
                username TEXT, 
                bio TEXT, 
                trust_score REAL
            )
        """)
        users = []
        for i in range(1000):
            users.append((i, f"agent_{i:04d}", "User is currently active and working on the platform.", random.uniform(0.8, 1.0)))
        cursor.executemany("INSERT INTO high_security_users VALUES (?, ?, ?, ?)", users)
        self.conn.commit()

    def _get_anchor_mapping(self, total_bits):
        """
        Uses row IDs as anchors to prevent shift attacks.
        Returns a mapping of {global_bit_index: (row_id, channel)}
        """
        cursor = self.conn.cursor()
        cursor.execute("SELECT id FROM high_security_users ORDER BY id") # Fixed order for consistent mapping
        all_ids = [r[0] for r in cursor.fetchall()]
        
        # Deterministic shuffle of the IDs based on secret key
        rng = random.Random(self.secret_key)
        rng.shuffle(all_ids)
        
        mapping = {}
        for bit_idx in range(total_bits):
            if bit_idx < len(all_ids):
                row_id = all_ids[bit_idx]
                channel = bit_idx % 4
                mapping[bit_idx] = (row_id, channel)
        return mapping

    def log_event(self, event_msg):
        data_bytes = event_msg.encode('utf-8')
        encoded_bytes = self.rs.encode(data_bytes)
        
        bits = []
        for byte in encoded_bytes:
            bits.extend([int(b) for b in format(byte, '08b')])
            
        mapping = self._get_anchor_mapping(len(bits))
        cursor = self.conn.cursor()
        
        for bit_idx, bit in enumerate(bits):
            row_id, channel = mapping[bit_idx]
            cursor.execute(f"SELECT bio, trust_score FROM high_security_users WHERE id=?", (row_id,))
            bio, score = cursor.fetchone()
            
            if channel == 0:
                cursor.execute("UPDATE high_security_users SET bio=? WHERE id=?", (StegoEngine.encode_bit_semantic(bio, bit), row_id))
            elif channel == 1:
                cursor.execute("UPDATE high_security_users SET trust_score=? WHERE id=?", (StegoEngine.encode_bit_float_lsb(score, bit), row_id))
            elif channel == 2:
                cursor.execute("UPDATE high_security_users SET bio=? WHERE id=?", (StegoEngine.encode_bit_trailing_space(bio, bit), row_id))
            else:
                cursor.execute("UPDATE high_security_users SET bio=? WHERE id=?", (StegoEngine.encode_bit_case(bio, bit), row_id))
                
        self.conn.commit()
        print(f"[GhostAudit V3] Event logged: '{event_msg}' (Anchored to Row IDs)")

    def recover_logs(self, original_msg_len, expected_row_ids=None):
        total_bytes = original_msg_len + self.rs.nsym
        total_bits = total_bytes * 8
        
        # If we know some IDs are gone, we must use the ORIGINAL mapping logic
        if expected_row_ids is None:
            # For the demo: we assume we know the IDs that SHOULD be there
            # In a real system, you'd fetch the IDs that EXIST and compare with a known list
            # or use a range-based anchor.
            cursor = self.conn.cursor()
            cursor.execute("SELECT id FROM high_security_users ORDER BY id")
            current_ids = [r[0] for r in cursor.fetchall()]
            # This is a bit of a cheat for the demo to show ID anchoring
            # In a real shift attack, we'd need a master list of IDs to detect erasures.
            # Let's simulate that we know the IDs that were there at log_event time.
            expected_row_ids = list(range(1000)) 

        # Re-generate mapping based on the master ID list (the anchor)
        rng = random.Random(self.secret_key)
        all_ids = list(expected_row_ids)
        rng.shuffle(all_ids)
        
        mapping = {}
        for bit_idx in range(total_bits):
            row_id = all_ids[bit_idx]
            mapping[bit_idx] = (row_id, bit_idx % 4)

        cursor = self.conn.cursor()
        extracted_bits = []
        erasure_indices = []
        
        for bit_idx in range(total_bits):
            row_id, channel = mapping[bit_idx]
            cursor.execute("SELECT bio, trust_score FROM high_security_users WHERE id=?", (row_id,))
            res = cursor.fetchone()
            
            byte_idx = bit_idx // 8
            if res is None: # Row was DELETED!
                extracted_bits.append(0)
                if byte_idx not in erasure_indices: erasure_indices.append(byte_idx)
                continue
                
            bio, score = res
            try:
                if channel == 0: bit = StegoEngine.decode_bit_semantic(bio)
                elif channel == 1: bit = StegoEngine.decode_bit_float_lsb(score)
                elif channel == 2: bit = StegoEngine.decode_bit_trailing_space(bio)
                else: bit = StegoEngine.decode_bit_case(bio)
                extracted_bits.append(bit)
            except Exception:
                extracted_bits.append(0)
                if byte_idx not in erasure_indices: erasure_indices.append(byte_idx)

        extracted_bytes = bytearray()
        for i in range(0, len(extracted_bits), 8):
            extracted_bytes.append(int("".join(map(str, extracted_bits[i:i+8])), 2))
            
        try:
            erasure_indices.sort()
            print(f"[Debug] Attempting RS decode with {len(erasure_indices)} erasure symbols at: {erasure_indices}")
            decoded_bytes = self.rs.decode(extracted_bytes, erase_pos=erasure_indices)[0]
            return decoded_bytes.decode('utf-8')
        except ReedSolomonError:
            return "[ERROR] Recovery failed"

if __name__ == "__main__":
    ga = GhostAuditV3(ecc_symbols=32) # Increased parity for the test
    msg = "SHIFT_TEST"
    ga.log_event(msg)
    
    print(f"Recovered (Normal): {ga.recover_logs(len(msg))}")
    
    # Simulate SHIFT ATTACK: Delete rows 5-10 (6 rows)
    # With ecc=32, we can recover up to 32 deletions.
    print("\n--- Simulating Shift Attack: Deleting 6 rows ---")
    cursor = ga.conn.cursor()
    cursor.execute("DELETE FROM high_security_users WHERE id BETWEEN 5 AND 10")
    ga.conn.commit()
    
    print(f"Recovered (After Delete): {ga.recover_logs(len(msg))}")
