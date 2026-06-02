import sqlite3
import binascii

class StegoEngine:
    """
    Engine to encode and decode bits into SQL data noise.
    """
    
    @staticmethod
    def encode_bit_trailing_space(text, bit):
        """Encodes a bit by adding or not adding a trailing space."""
        base = text.rstrip()
        return base + (" " if bit else "")

    @staticmethod
    def decode_bit_trailing_space(text):
        """Decodes a bit based on the presence of a trailing space."""
        return 1 if text.endswith(" ") else 0

    @staticmethod
    def encode_bit_case(text, bit):
        """Encodes a bit using the case of the first alphabetic character."""
        for i, char in enumerate(text):
            if char.isalpha():
                new_char = char.upper() if bit else char.lower()
                return text[:i] + new_char + text[i+1:]
        return text

    @staticmethod
    def decode_bit_case(text):
        """Decodes a bit based on the case of the first alphabetic character."""
        for char in text:
            if char.isalpha():
                return 1 if char.isupper() else 0
        return 0

class GhostAudit:
    def __init__(self, db_path=":memory:"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self._prepare_db()

    def _prepare_db(self):
        cursor = self.conn.cursor()
        # A normal business table that will act as a carrier
        cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, bio TEXT)")
        users = [
            (1, "alice", "Developer from Berlin"),
            (2, "bob", "Loves SQL and Python"),
            (3, "charlie", "Security researcher"),
            (4, "diana", "Data scientist"),
            (5, "eve", "Interested in crypto")
        ]
        cursor.executemany("INSERT INTO users VALUES (?, ?, ?)", users)
        self.conn.commit()

    def embed_audit_log(self, message, target_table="users", target_column="bio"):
        """
        Embeds an audit message into the target table's column noise.
        Simplified version: 1 bit per row.
        """
        # Convert message to bits
        bits = ''.join(format(ord(c), '08b') for c in message)
        
        cursor = self.conn.cursor()
        cursor.execute(f"SELECT id, {target_column} FROM {target_table} ORDER BY id")
        rows = cursor.fetchall()
        
        if len(bits) > len(rows):
            raise ValueError("Not enough rows to store the message")
            
        for i, bit_str in enumerate(bits):
            row_id, original_text = rows[i]
            bit = int(bit_str)
            
            # Use Trailing Space as carrier
            new_text = StegoEngine.encode_bit_trailing_space(original_text, bit)
            
            cursor.execute(f"UPDATE {target_table} SET {target_column} = ? WHERE id = ?", (new_text, row_id))
        
        self.conn.commit()
        print(f"Embedded {len(bits)} bits into {target_table}.{target_column}")

    def extract_audit_log(self, bit_count, target_table="users", target_column="bio"):
        cursor = self.conn.cursor()
        cursor.execute(f"SELECT {target_column} FROM {target_table} ORDER BY id LIMIT ?", (bit_count,))
        rows = cursor.fetchall()
        
        bits = ""
        for (text,) in rows:
            bits += str(StegoEngine.decode_bit_trailing_space(text))
            
        # Convert bits back to string
        message = ""
        for i in range(0, len(bits), 8):
            byte = bits[i:i+8]
            if len(byte) == 8:
                message += chr(int(byte, 2))
        return message

if __name__ == "__main__":
    ga = GhostAudit()
    log_msg = "LOGIN" # 5 chars * 8 bits = 40 bits. We need 40 rows.
    # Our users table only has 5 rows. Let's scale it.
    
    print("--- GhostAudit Demo ---")
    # Add more dummy rows for the demo
    cursor = ga.conn.cursor()
    for i in range(6, 100):
        cursor.execute("INSERT INTO users VALUES (?, ?, ?)", (i, f"user{i}", f"This is bio for user {i}"))
    ga.conn.commit()
    
    ga.embed_audit_log(log_msg)
    extracted = ga.extract_audit_log(len(log_msg) * 8)
    print(f"Original: {log_msg}")
    print(f"Extracted: {extracted}")
