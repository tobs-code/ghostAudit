import sqlite3
import numpy as np
import random
import hashlib
import hmac
import time
import struct
import os
from reedsolo import RSCodec, ReedSolomonError

class StegoEngine:
    # Dictionary for synonym substitution
    # 0: First word, 1: Second word
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
                # Try to respect the casing of the match
                idx = text.lower().find(key)
                if idx != -1:
                    orig_case = text[idx:idx+len(key)]
                    if orig_case.istitle():
                        chosen = chosen.title()
                    elif orig_case.isupper():
                        chosen = chosen.upper()
                    return text[:idx] + chosen + text[idx+len(key):]
        return text

    @staticmethod
    def decode_bit_semantic(text):
        for key, synonyms in StegoEngine.SEMANTIC_MAP.items():
            if synonyms[1] in text.lower(): return 1
            if synonyms[0] in text.lower(): return 0
        return 0


class GhostAuditV5:
    def __init__(self, db_path="ghost_audit_v5.db", secret_key=None, ecc_symbols=32):
        self.db_path = db_path
        
        # Key Management: Require key from environment or fallback with strong warning
        if secret_key is None:
            secret_key = os.environ.get("GHOST_AUDIT_KEY")
            if not secret_key:
                print("[WARNING] No GHOST_AUDIT_KEY environment variable set! Using development fallback key.")
                secret_key = "dev-fallback-super-long-secure-key-123456789"
        
        self.secret_key = secret_key.encode('utf-8')
        self.ecc_symbols = ecc_symbols
        self.rs = RSCodec(ecc_symbols)
        
        # KDF (Key Derivation Function): Derive specialized subkeys
        self.k_shuffling = hmac.new(self.secret_key, b"shuffling_subkey", hashlib.sha256).digest()
        self.k_hmac = hmac.new(self.secret_key, b"hmac_subkey", hashlib.sha256).digest()
        
        self.conn = sqlite3.connect(db_path)
        
        # Pre-compute secure deterministic ID sequence (using HMAC of index)
        # This keeps the anchor IDs stable across setup, log, and recovery
        self._orig_ids = []
        c = 1
        # Deterministic but unguessable step size using HMAC
        for idx in range(1000):
            self._orig_ids.append(c)
            # Use HMAC to derive a step size between 1 and 3
            h = hmac.new(self.k_shuffling, f"step_{idx}".encode('utf-8'), hashlib.sha256).digest()
            step = (h[0] % 3) + 1
            c += step
            
        self._setup_db()

    def _secure_shuffle(self, items):
        """Deterministically and cryptographically shuffles items using K_shuffling."""
        def get_hash(item):
            return hmac.new(self.k_shuffling, str(item).encode('utf-8'), hashlib.sha256).digest()
        return sorted(items, key=get_hash)

    def _setup_db(self):
        cursor = self.conn.cursor()
        cursor.execute("DROP TABLE IF EXISTS audit_carrier")
        cursor.execute("CREATE TABLE audit_carrier (id INTEGER PRIMARY KEY, bio TEXT, trust_score REAL)")
        
        # Generate heterogeneous, realistic-looking profiles for stealth
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
            
        cursor.executemany("INSERT INTO audit_carrier VALUES (?, ?, ?)", users)
        self.conn.commit()

    def _decode_header(self, header_bits):
        if len(header_bits) < 64: return None
        bytes_data = bytearray()
        for i in range(0, 64, 8):
            bits_str = "".join(map(str, header_bits[i:i+8]))
            bytes_data.append(int(bits_str, 2))
        
        try:
            magic = bytes_data[0]
            msg_len = (bytes_data[1] << 8) | bytes_data[2]
            nsym = bytes_data[3]
            max_id = (bytes_data[4] << 24) | (bytes_data[5] << 16) | (bytes_data[6] << 8) | bytes_data[7]
            
            if magic == 0x56: # V5 signature
                return msg_len, nsym, max_id
        except Exception:
            return None
        return None

    def log_event(self, event_msg):
        cursor = self.conn.cursor()
        orig_ids = self._orig_ids

        # 1. Header IDs (first 64)
        header_ids = orig_ids[:64]
        
        # 2. HMAC Calculation (16 bytes for efficiency)
        msg_bytes = event_msg.encode('utf-8')
        mac = hmac.new(self.k_hmac, msg_bytes, hashlib.sha256).digest()[:16]
        
        # 3. Payload = HMAC + msg
        payload_bytes = mac + msg_bytes
        
        # 4. Reed-Solomon Encoding
        encoded_bytes = self.rs.encode(payload_bytes)
        payload_bits = []
        for byte in encoded_bytes:
            payload_bits.extend([int(b) for b in format(byte, '08b')])
            
        # 5. Embed Payload using Cryptographically Secure Shuffle
        remaining_ids = orig_ids[64:]
        shuffled_ids = self._secure_shuffle(remaining_ids)
        
        used_payload_ids = shuffled_ids[:len(payload_bits)]
        max_id_at_log = max(used_payload_ids)
        
        for i, bit in enumerate(payload_bits):
            rid = used_payload_ids[i]
            cursor.execute("SELECT bio, trust_score FROM audit_carrier WHERE id=?", (rid,))
            res = cursor.fetchone()
            if not res: continue
            bio, score = res
            channel = i % 4
            if channel == 0: bio = StegoEngine.encode_bit_semantic(bio, bit)
            elif channel == 1: score = StegoEngine.encode_bit_float_lsb(score, bit)
            elif channel == 2: bio = StegoEngine.encode_bit_trailing_space(bio, bit)
            else: bio = StegoEngine.encode_bit_case(bio, bit)
            cursor.execute("UPDATE audit_carrier SET bio=?, trust_score=? WHERE id=?", (bio, score, rid))
            
        # 6. Header Generation (Magic 0x56)
        header_bytes = struct.pack(">B H B I", 0x56, len(event_msg), self.ecc_symbols, max_id_at_log)
        
        h_bits = []
        for b in header_bytes:
            h_bits.extend([int(x) for x in format(b, '08b')])
        
        for i, bit in enumerate(h_bits):
            rid = header_ids[i]
            cursor.execute("SELECT bio FROM audit_carrier WHERE id=?", (rid,))
            res = cursor.fetchone()
            if not res: continue
            bio = res[0]
            new_bio = StegoEngine.encode_bit_case(bio, bit)
            cursor.execute("UPDATE audit_carrier SET bio=? WHERE id=?", (new_bio, rid))
            
        self.conn.commit()
        print(f"[V5] Event logged successfully: '{event_msg}'")

    def recover_logs(self):
        cursor = self.conn.cursor()
        orig_ids = self._orig_ids
        orig_header_ids = orig_ids[:64]
        
        # 1. Recover Header
        h_bits = []
        for rid in orig_header_ids:
            cursor.execute("SELECT bio FROM audit_carrier WHERE id=?", (rid,))
            res = cursor.fetchone()
            if res:
                h_bits.append(StegoEngine.decode_bit_case(res[0]))
            else:
                h_bits.append(0)
        
        header_data = self._decode_header(h_bits)
        if not header_data:
            return "[ERROR] Header corrupt or magic mismatch."
            
        msg_len, nsym, max_id_at_log = header_data

        # 2. Payload Recovery
        remaining_ids = orig_ids[64:]
        shuffled_ids = self._secure_shuffle(remaining_ids)
        
        # 16 bytes HMAC + msg_len + nsym
        total_bytes = 16 + msg_len + nsym
        total_bits = total_bytes * 8
        used_payload_ids = shuffled_ids[:total_bits]
        
        extracted_bits = []
        erasure_pos = []
        
        for i, rid in enumerate(used_payload_ids):
            byte_idx = i // 8
            cursor.execute("SELECT bio, trust_score FROM audit_carrier WHERE id=?", (rid,))
            res = cursor.fetchone()
            
            if res is None: # Row Deleted!
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
            except Exception:
                extracted_bits.append(0)
                if byte_idx not in erasure_pos: erasure_pos.append(byte_idx)

        extracted_bytes = bytearray()
        for i in range(0, len(extracted_bits), 8):
            extracted_bytes.append(int("".join(map(str, extracted_bits[i:i+8])), 2))
            
        # 3. RS Decode & Reconstruct Bytes
        try:
            erasure_pos.sort()
            decoded_bytes = self.rs.decode(extracted_bytes, erase_pos=erasure_pos)[0]
        except ReedSolomonError:
            return "[ERROR] Reed-Solomon recovery failed. Too many corruptions."

        if len(decoded_bytes) < 16:
            return "[ERROR] Recovered payload too short."

        # 4. Active Tampering Verification (HMAC check)
        recovered_mac = decoded_bytes[:16]
        recovered_msg = decoded_bytes[16:]
        
        expected_mac = hmac.new(self.k_hmac, recovered_msg, hashlib.sha256).digest()[:16]
        
        if hmac.compare_digest(recovered_mac, expected_mac):
            return recovered_msg.decode('utf-8')
        else:
            return "[TAMPERING DETECTED] Authenticity verification failed! The logs have been modified."


if __name__ == "__main__":
    print("--- 👻 GhostAudit V5: Interactive Test Suite ---")
    
    # 1. Normal execution
    ga = GhostAuditV5(db_path="ghost_audit_v5.db", secret_key="super-secret-key-phrase")
    msg = "AUTH_SUCCESS: user=admin"
    ga.log_event(msg)
    
    recovered = ga.recover_logs()
    print(f"Test 1 (Normal Recovery): {recovered}\n")
    
    # 2. RS Burst Error Recovery
    print("--- Simulating targeted row deletion (within RS capacity) ---")
    cursor = ga.conn.cursor()
    # Delete some rows
    cursor.execute("DELETE FROM audit_carrier WHERE id BETWEEN 100 AND 130")
    ga.conn.commit()
    
    recovered_after_deletion = ga.recover_logs()
    print(f"Test 2 (Recovery with Erasures): {recovered_after_deletion}\n")
    
    # 3. Active Tampering Detection
    print("--- Simulating direct database modifications (Tampering) ---")
    # Reset DB and log a fresh event
    ga_tamper = GhostAuditV5(db_path="ghost_audit_v5.db", secret_key="super-secret-key-phrase")
    ga_tamper.log_event("SENSITIVE_READ: client_ip=192.168.1.5")
    
    # Let's selectively modify values to change the decrypted output but tricking RS
    # (or simply making changes that bypass simple error correction but mismatch HMAC)
    cursor = ga_tamper.conn.cursor()
    cursor.execute("UPDATE audit_carrier SET bio = LOWER(TRIM(bio)) WHERE id BETWEEN 200 AND 220")
    ga_tamper.conn.commit()
    
    tamper_result = ga_tamper.recover_logs()
    print(f"Test 3 (Tampered DB Recovery): {tamper_result}\n")
    
    # 4. Wrong Key Access Prevention
    print("--- Attempting recovery with invalid secret key ---")
    ga_wrong_key = GhostAuditV5(db_path="ghost_audit_v5.db", secret_key="attacker-key")
    wrong_key_result = ga_wrong_key.recover_logs()
    print(f"Test 4 (Invalid Key Recovery): {wrong_key_result}\n")
