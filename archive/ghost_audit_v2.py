import sqlite3
import numpy as np
import random
import hashlib
import time
from reedsolo import RSCodec, ReedSolomonError

class StegoEngine:
    """
    Advanced Engine with Diversity Channels and Semantic-Aware Carriers.
    """
    
    # Simple semantic dictionary for bit encoding
    # 0: First word, 1: Second word (Synonyms)
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
        """Encodes a bit into the least significant digit of a float."""
        s = f"{value:.8f}"
        # We change the last digit to be even for 0, odd for 1
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
        """Encodes a bit by choosing a synonym from SEMANTIC_MAP."""
        for key, synonyms in StegoEngine.SEMANTIC_MAP.items():
            if key in text.lower():
                chosen = synonyms[1] if bit else synonyms[0]
                # Maintain original casing if possible (simplified here)
                return text.replace(key, chosen)
        return text

    @staticmethod
    def decode_bit_semantic(text):
        """Decodes a bit by checking which synonym was used."""
        for key, synonyms in StegoEngine.SEMANTIC_MAP.items():
            if synonyms[1] in text.lower(): return 1
            if synonyms[0] in text.lower(): return 0
        return 0

class GhostAudit:
    def __init__(self, db_path="ghost_audit_v2.db", secret_key="advanced-secret", ecc_symbols=8):
        self.db_path = db_path
        self.secret_key = secret_key
        self.rs = RSCodec(ecc_symbols) # ecc_symbols bytes of parity
        self.conn = sqlite3.connect(db_path)
        self._setup_advanced_db()

    def _setup_advanced_db(self):
        cursor = self.conn.cursor()
        cursor.execute("DROP TABLE IF EXISTS high_security_users")
        # Table with multiple potential carriers: TEXT, FLOAT, TIMESTAMP
        cursor.execute("""
            CREATE TABLE high_security_users (
                id INTEGER PRIMARY KEY, 
                username TEXT, 
                bio TEXT, 
                trust_score REAL, 
                last_login TIMESTAMP
            )
        """)
        
        users = []
        base_time = time.time()
        for i in range(1000):
            users.append((
                i, 
                f"agent_{i:04d}", 
                f"User is currently active and working on the platform.",
                random.uniform(0.8, 1.0),
                base_time + i * 60
            ))
        cursor.executemany("INSERT INTO high_security_users VALUES (?, ?, ?, ?, ?)", users)
        
        # Add a trigger example (commented out as it's for documentation)
        """
        CREATE TRIGGER audit_on_update AFTER UPDATE ON high_security_users
        BEGIN
            -- Logic to update ghost bits would go here
            UPDATE high_security_users SET bio = bio || ' ' WHERE id = NEW.id;
        END;
        """
        
        self.conn.commit()

    def _get_seeded_rows(self, count, target_table="high_security_users"):
        cursor = self.conn.cursor()
        cursor.execute(f"SELECT id FROM {target_table}")
        ids = [r[0] for r in cursor.fetchall()]
        rng = random.Random(self.secret_key)
        rng.shuffle(ids)
        return ids[:count]

    def log_event(self, event_msg, target_table="high_security_users"):
        """Logs event using Reed-Solomon and Multi-Channel Diversity."""
        # 1. Reed-Solomon Encoding (works on bytes)
        data_bytes = event_msg.encode('utf-8')
        encoded_bytes = self.rs.encode(data_bytes)
        
        # 2. Convert bytes to bits
        bits = []
        for byte in encoded_bytes:
            bits.extend([int(b) for b in format(byte, '08b')])
            
        # 3. Embed bits using different channels
        row_ids = self._get_seeded_rows(len(bits), target_table)
        cursor = self.conn.cursor()
        
        for i, bit in enumerate(bits):
            row_id = row_ids[i]
            cursor.execute(f"SELECT bio, trust_score, last_login FROM {target_table} WHERE id=?", (row_id,))
            bio, score, login = cursor.fetchone()
            
            # Channel Rotation: Semantic -> Float -> Trailing Space -> Case
            channel = i % 4
            if channel == 0:
                new_bio = StegoEngine.encode_bit_semantic(bio, bit)
                cursor.execute(f"UPDATE {target_table} SET bio=? WHERE id=?", (new_bio, row_id))
            elif channel == 1:
                new_score = StegoEngine.encode_bit_float_lsb(score, bit)
                cursor.execute(f"UPDATE {target_table} SET trust_score=? WHERE id=?", (new_score, row_id))
            elif channel == 2:
                new_bio = StegoEngine.encode_bit_trailing_space(bio, bit)
                cursor.execute(f"UPDATE {target_table} SET bio=? WHERE id=?", (new_bio, row_id))
            else:
                new_bio = StegoEngine.encode_bit_case(bio, bit)
                cursor.execute(f"UPDATE {target_table} SET bio=? WHERE id=?", (new_bio, row_id))
                
        self.conn.commit()
        print(f"[GhostAudit V2] Embedded event '{event_msg}' using 4 channels and Reed-Solomon.")

    def recover_logs(self, original_msg_len, target_table="high_security_users"):
        """Recovers logs and handles burst errors via Reed-Solomon."""
        # RS encoded length = msg_len + nsym
        total_bytes = original_msg_len + self.rs.nsym
        total_bits = total_bytes * 8
        
        row_ids = self._get_seeded_rows(total_bits, target_table)
        cursor = self.conn.cursor()
        extracted_bits = []
        
        for i, row_id in enumerate(row_ids):
            cursor.execute(f"SELECT bio, trust_score FROM {target_table} WHERE id=?", (row_id,))
            bio, score = cursor.fetchone()
            
            channel = i % 4
            if channel == 0:
                extracted_bits.append(StegoEngine.decode_bit_semantic(bio))
            elif channel == 1:
                extracted_bits.append(StegoEngine.decode_bit_float_lsb(score))
            elif channel == 2:
                extracted_bits.append(StegoEngine.decode_bit_trailing_space(bio))
            else:
                extracted_bits.append(StegoEngine.decode_bit_case(bio))
                
        # Convert bits to bytes
        extracted_bytes = bytearray()
        for i in range(0, len(extracted_bits), 8):
            byte_bits = extracted_bits[i:i+8]
            byte_val = int("".join(map(str, byte_bits)), 2)
            extracted_bytes.append(byte_val)
            
        # Reed-Solomon Decode
        try:
            decoded_bytes = self.rs.decode(extracted_bytes)[0]
            return decoded_bytes.decode('utf-8')
        except ReedSolomonError:
            return "[ERROR] Could not recover log. Too many corruptions."

if __name__ == "__main__":
    ga = GhostAudit(ecc_symbols=10) # 10 bytes of parity for high robustness
    
    msg = "CRITICAL_AUTH_FAILURE"
    ga.log_event(msg)
    
    # Recovery
    recovered = ga.recover_logs(len(msg))
    print(f"Recovered: {recovered}")
    
    # Simulate BURST ATTACK: A whole range of rows is wiped
    print("\n--- Simulating Burst Attack: Wiping 20 rows of the carrier ---")
    cursor = ga.conn.cursor()
    cursor.execute("UPDATE high_security_users SET bio = LOWER(TRIM(bio)), trust_score = ROUND(trust_score, 2) WHERE id BETWEEN 100 AND 120")
    ga.conn.commit()
    
    recovered_after_burst = ga.recover_logs(len(msg))
    print(f"Recovered after burst attack: {recovered_after_burst}")
