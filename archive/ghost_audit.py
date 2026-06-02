import sqlite3
import numpy as np
import random
import hashlib

class Hamming74:
    """Implementation of Hamming (7,4) error correction code."""
    G = np.array([[1,1,0,1],[1,0,1,1],[1,0,0,0],[0,1,1,1],[0,1,0,0],[0,0,1,0],[0,0,0,1]])
    H = np.array([[1,0,1,0,1,0,1],[0,1,1,0,0,1,1],[0,0,0,1,1,1,1]])

    @staticmethod
    def encode(data_4bits):
        d = np.array(data_4bits).reshape(4, 1)
        return (np.dot(Hamming74.G, d) % 2).flatten().tolist()

    @staticmethod
    def decode(code_7bits):
        c = np.array(code_7bits).reshape(7, 1)
        s = np.dot(Hamming74.H, c) % 2
        syndrome_val = int(s[0][0] + s[1][0]*2 + s[2][0]*4)
        if syndrome_val != 0:
            c[syndrome_val - 1] = (c[syndrome_val - 1] + 1) % 2
        # Extract data bits (indices 2, 4, 5, 6 in our G matrix)
        return [int(c[2][0]), int(c[4][0]), int(c[5][0]), int(c[6][0])]

class StegoEngine:
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

class GhostAudit:
    def __init__(self, db_path="ghost_audit.db", secret_key="secret"):
        self.db_path = db_path
        self.secret_key = secret_key
        self.conn = sqlite3.connect(db_path)
        self._setup_demo_db()

    def _setup_demo_db(self):
        cursor = self.conn.cursor()
        cursor.execute("DROP TABLE IF EXISTS system_users")
        cursor.execute("CREATE TABLE system_users (id INTEGER PRIMARY KEY, username TEXT, status_msg TEXT)")
        
        # Populate with 500 dummy users
        users = []
        for i in range(500):
            users.append((i, f"user_{i:03d}", f"User {i} is currently active and working on the system."))
        cursor.executemany("INSERT INTO system_users VALUES (?, ?, ?)", users)
        self.conn.commit()

    def _get_seeded_rows(self, count, target_table="system_users"):
        """Returns a deterministic pseudo-random list of row IDs based on the secret key."""
        cursor = self.conn.cursor()
        cursor.execute(f"SELECT id FROM {target_table}")
        ids = [r[0] for r in cursor.fetchall()]
        
        rng = random.Random(self.secret_key)
        rng.shuffle(ids)
        return ids[:count]

    def log_event(self, event_msg, target_table="system_users", target_column="status_msg"):
        """Embeds an audit event message into the DB noise."""
        # 1. Convert message to bits
        msg_bits = [int(b) for b in ''.join(format(ord(c), '08b') for c in event_msg)]
        
        # 2. Pad to multiple of 4 bits for Hamming(7,4)
        while len(msg_bits) % 4 != 0:
            msg_bits.append(0)
            
        # 3. Hamming Encode
        encoded_bits = []
        for i in range(0, len(msg_bits), 4):
            encoded_bits.extend(Hamming74.encode(msg_bits[i:i+4]))
            
        # 4. We need encoded_bits rows. (Each row stores 1 bit for simplicity here, 
        # but we could store 2: TS and Case). Let's use 1 bit per row for max robustness.
        row_ids = self._get_seeded_rows(len(encoded_bits), target_table)
        
        cursor = self.conn.cursor()
        for i, bit in enumerate(encoded_bits):
            row_id = row_ids[i]
            cursor.execute(f"SELECT {target_column} FROM {target_table} WHERE id=?", (row_id,))
            original_text = cursor.fetchone()[0]
            
            # Alternate between TS and Case for diversity
            if i % 2 == 0:
                new_text = StegoEngine.encode_bit_trailing_space(original_text, bit)
            else:
                new_text = StegoEngine.encode_bit_case(original_text, bit)
                
            cursor.execute(f"UPDATE {target_table} SET {target_column}=? WHERE id=?", (new_text, row_id))
        
        self.conn.commit()
        print(f"[GhostAudit] Event logged: '{event_msg}' ({len(encoded_bits)} bits embedded)")

    def recover_logs(self, char_count, target_table="system_users", target_column="status_msg"):
        """Recovers the audit log from the DB noise."""
        # Calculate how many bits we expect
        bit_count_data = char_count * 8
        while bit_count_data % 4 != 0:
            bit_count_data += 1
        bit_count_encoded = (bit_count_data // 4) * 7
        
        row_ids = self._get_seeded_rows(bit_count_encoded, target_table)
        
        cursor = self.conn.cursor()
        extracted_bits = []
        for i, row_id in enumerate(row_ids):
            cursor.execute(f"SELECT {target_column} FROM {target_table} WHERE id=?", (row_id,))
            text = cursor.fetchone()[0]
            
            if i % 2 == 0:
                extracted_bits.append(StegoEngine.decode_bit_trailing_space(text))
            else:
                extracted_bits.append(StegoEngine.decode_bit_case(text))
                
        # Hamming Decode
        decoded_bits = []
        for i in range(0, len(extracted_bits), 7):
            decoded_bits.extend(Hamming74.decode(extracted_bits[i:i+7]))
            
        # Convert bits back to string
        message = ""
        for i in range(0, len(decoded_bits), 8):
            byte_bits = decoded_bits[i:i+8]
            if len(byte_bits) == 8:
                byte_str = "".join(map(str, byte_bits))
                message += chr(int(byte_str, 2))
                
        return message

if __name__ == "__main__":
    ga = GhostAudit(secret_key="top-secret-salt")
    
    # 1. Log an event
    ga.log_event("ADMIN_LOGIN")
    
    # 2. Extract it
    recovered = ga.recover_logs(len("ADMIN_LOGIN"))
    print(f"Recovered: {recovered}")
    
    # 3. Simulate an attack (delete some trailing spaces or change case)
    print("\n--- Simulating Attack: Normalizing data ---")
    cursor = ga.conn.cursor()
    # Let's corrupt 5 random rows of the carrier table
    cursor.execute("SELECT id FROM system_users ORDER BY RANDOM() LIMIT 5")
    corrupt_ids = [r[0] for r in cursor.fetchall()]
    for cid in corrupt_ids:
        cursor.execute("UPDATE system_users SET status_msg = LOWER(TRIM(status_msg)) WHERE id=?", (cid,))
    ga.conn.commit()
    print(f"Corrupted {len(corrupt_ids)} rows.")
    
    # 4. Recover again with ECC
    recovered_after_attack = ga.recover_logs(len("ADMIN_LOGIN"))
    print(f"Recovered after attack: {recovered_after_attack}")
