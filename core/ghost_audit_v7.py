"""
GhostAudit V7: Orthogonal Grid Defense (RAID-6 Erasure Coding)
Combines:
  - Logical-to-Physical Shuffling (per-row channel mapping)
  - RAID-6 Cross-Channel Parity: P (XOR) + Q (GF(2^8)) — 3 data + 2 parity
  - Dynamic Repetition Scaling (maximize majority vote resilience)

This implementation provides orthogonal protection against:
  - Column-level attacks (entire carrier column wiped)
  - Row-level attacks (random bit-flips, row erasures)
  - Dual-channel failures (RAID-6: 2 beliebige der 3 Datenkanäle recoverable)
"""

import sqlite3
import hmac
import hashlib
import time
import json
import math
import os
import random
import re
import struct
import threading
import zlib
import subprocess
from contextlib import contextmanager
from reedsolo import RSCodec, ReedSolomonError

# ---------------------------------------------------------------------------
# Proactive Self-Healing — Rebuild constants
# Modul-Level mit Env-Var-Override, konsistent mit GHOST_AUDIT_ECC_SYMBOLS etc.
# ---------------------------------------------------------------------------
# nsym used when re-writing a degraded slot (always >= adaptive state + 8,
# capped against actual slot capacity in _migrate_slot).
ECC_REBUILD_NSYM = int(os.getenv("GHOST_AUDIT_REBUILD_ECC_SYMBOLS", "52"))
# Minimum repetitions used during a slot rebuild.
ECC_REBUILD_REPS = int(os.getenv("GHOST_AUDIT_REBUILD_MIN_REPS", "4"))
# Degradation threshold (0.0–1.0) above which a slot is considered rebuild-worthy.
REBUILD_DEGRADATION_THRESHOLD = float(os.getenv("GHOST_AUDIT_REBUILD_THRESHOLD", "0.35"))
# _idle_restore_check() is called at most every N log_event() calls.
REBUILD_CHECK_INTERVAL = int(os.getenv("GHOST_AUDIT_REBUILD_INTERVAL", "50"))


class StegoEngine:
    """V8.6: Corpus-based template lattice for Bio-Carrier."""
    
    _TEMPLATES = None
    # Keep SEMANTIC_MAP for backward compatibility in internal methods if needed
    SEMANTIC_MAP = {
        "currently": ["currently", "presently"],
        "active": ["active", "online"],
        "working": ["working", "operating"],
        "system": ["system", "platform"]
    }

    @classmethod
    def _load_templates(cls):
        if cls._TEMPLATES is None:
            with open("config/stego_templates.json", "r") as f:
                cls._TEMPLATES = json.load(f)
        return cls._TEMPLATES

    @classmethod
    def encode_template(cls, bit_seq: str) -> str:
        templates = cls._load_templates()
        if bit_seq not in templates:
            # Fallback for undefined bit sequences
            return "Currently working as a developer."
            
        data = templates[bit_seq]
        template = data["template"]
        variants = data["variants"]
        
        # Randomly choose variants
        mapping = {k: random.choice(v) for k, v in variants.items()}
        return template.format(**mapping)

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
    def encode_bit_float_lsb(value, bit, row_id=None, scale=1000000):
        scaled = int(round(value * scale))
        if (scaled % 2) != bit:
            # Always use row_id or a hash of the value to decide direction
            # to avoid static +1 bias.
            seed_data = str(row_id).encode() if row_id is not None else str(scaled).encode()
            h = hashlib.sha256(seed_data).digest()[0]
            direction = 1 if h % 2 == 1 else -1
            
            # Ensure we don't go out of range if possible
            scaled += direction
        return float(scaled) / scale

    @staticmethod
    def decode_bit_float_lsb(value, scale=1000000):
        if value is None:
            return None
        if abs(value) < 1e-12:
            return None
        scaled = int(round(value * scale))
        return scaled % 2

    @staticmethod
    def encode_bit_semantic(text, bit, verbose=False):
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
        if verbose:
            print(f"[WARN] Semantic carrier: no keyword found in bio='{text[:60]}...'")
        return text

    # ---- Carrier 4: avatar_url (prefix/length pattern) ----
    # ORCache-safe: operates on URL path (case-sensitive but / separators are
    # ORM-invariant). Uses a hash-chaining scheme so every state transition is
    # deterministic — avatar_url survives any UPDATE whose WHERE clause does NOT
    # touch the avatar_url column.
    #
    # Scheme:  we maintain a hidden "pointer" word embedded in the URL path.
    #   empty          → bit = None (channel not in use)
    #   url starts with /s_ → state hash,  bit = LSB of first ptr-byte
    #   url starts with /b_ → baseline state, bit = 0 (fallback)
    #
    # The pointer value is a 16-byte HMAC (state), updated whenever a bit is
    # written so that consecutive writes produce different patterns → ORCache-safe.
    # Read: derive the same state from previous content → extract LSB.

    _AVATAR_EMPTY_TAG   = "/b_"
    _AVATAR_STATE_TAG   = "/s_"
    _AVATAR_PTR_LEN    = 16   # bytes of state-HMAC encoded as 32 hex chars
    _AVATAR_PATH_CHARS = 36   # max path chars after tag

    @classmethod
    def encode_bit_avatar_url(cls, url: str, bit: int, row_id: int) -> str:
        """Encode bit into avatar_url via final-char parity (~ suffix).

        ORM-invariant: the tilde is an allowed unreserved char appended to
        the URL path — does not change the URL structure.
        bit=1: URL ends with '~'   bit=0: URL is bare (no trailing tilde)
        """

        # Normalize to empty string if None
        if url is None:
            url = ""

        # Strip any existing tilde
        url_base = url.rstrip("~")

        if bit == 1:
            return url_base + "~"
        else:
            return url_base

    @classmethod
    def decode_bit_avatar_url(cls, url: str, row_id: int) -> int | None:
        """Extract bit from avatar_url via final-char parity (~ suffix).

        Returns 1 if URL ends with '~', 0 if not, None if URL is empty.
        The row_id is accepted for API compatibility but not used here
        (avoids leaking the row_key into the decoding logic).
        ORM-safe: ~ is an unreserved character (RFC 3986) that survives typical
        URL normalization in Django/Flask/SQLAlchemy field handling.
        """
        if url is None or url == "":
            return None
        return 1 if url.endswith("~") else 0

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

    # --- GF(2^8) arithmetic for RAID-6 Q parity ---
    # Primitive polynomial: x^8 + x^4 + x^3 + x^2 + 1 (0x11D = 285)
    # Same field as reedsolo (generator=2, prim=285)
    _GF_PRIM = 0x1D  # lower 8 bits of 0x11D

    @staticmethod
    def gf_mul(x: int, y: int) -> int:
        """Multiply two bytes in GF(2^8)."""
        if x == 0 or y == 0:
            return 0
        result = 0
        for _ in range(8):
            if y & 1:
                result ^= x
            carry = x & 0x80
            x = (x << 1) & 0xFF
            if carry:
                x ^= StegoEngine._GF_PRIM
            y >>= 1
        return result

    @staticmethod
    def gf_pow(x: int, power: int) -> int:
        """x^power in GF(2^8)."""
        result = 1
        for _ in range(power):
            result = StegoEngine.gf_mul(result, x)
        return result

    @staticmethod
    def gf_inv(x: int) -> int:
        """Multiplicative inverse in GF(2^8). x^(-1) = x^254."""
        if x == 0:
            return 0
        return StegoEngine.gf_pow(x, 254)

    @staticmethod
    def gf_div(x: int, y: int) -> int:
        """x / y in GF(2^8)."""
        if y == 0:
            raise ZeroDivisionError("division by zero in GF(2^8)")
        if x == 0:
            return 0
        return StegoEngine.gf_mul(x, StegoEngine.gf_inv(y))

    @staticmethod
    def gf_weight(channel_idx: int) -> int:
        """Weight g^channel_idx for RAID-6 Q parity: Q = Σ g^i · D_i."""
        return StegoEngine.gf_pow(2, channel_idx)


class ExternalStateCounter:
    """Key-Evolve monotonic counter in a separate file.

    Two-phase write protocol (``committed`` / ``pending``) prevents false
    ``ROLLBACK_DETECTED`` on system crash during the write window.

    File format::

        committed <count> <root_hex>
        pending   <count> <root_hex>      ← only present during write window

    On initialisation the counter is compared with the value stored inside the
    database – if the database claims a *lower* counter it means an attacker
    restored an old snapshot (rollback / fork attack).

    The protection relies on **location separation**: if an attacker clones
    both ``*.db`` *and* the external state file from the same snapshot, the
    rollback is invisible.  In production the two files should reside on
    different volumes / mounts.
    """

    def __init__(self, path: str | None = None):
        self._path = path

    @staticmethod
    def _default_path(db_path: str) -> str:
        root, _ = os.path.splitext(db_path)
        return root + ".evolve"

    def _git_witness_checkpoint(self) -> None:
        """Atomically commit the state file to git if in a repository."""
        if not self._path:
            return
        
        # Check if we are inside a git repo
        try:
            subprocess.run(
                ["git", "rev-parse", "--is-inside-work-tree"],
                check=True,
                capture_output=True,
                timeout=2
            )
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            return

        # Perform the git witness checkpoint
        try:
            subprocess.run(
                ["git", "add", self._path],
                check=True,
                capture_output=True,
                timeout=5
            )
            subprocess.run(
                ["git", "commit", "-m", f"GhostAudit Witness Checkpoint: {self._path}"],
                check=True,
                capture_output=True,
                timeout=5
            )
        except Exception as e:
            # Witnessing is an advisory/best-effort protection
            pass

    def _write_atomic(self, path: str, content: str) -> None:
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        for attempt in range(5):
            try:
                os.replace(tmp, path)
                break
            except PermissionError:
                __import__('gc').collect()
                if attempt < 4:
                    time.sleep(0.05 * (attempt + 1))
                else:
                    raise
        self._git_witness_checkpoint()

    def read(self) -> tuple[int, str] | None:
        """Return (committed_count, committed_root_hex) or None if file missing."""
        if self._path is None or not os.path.isfile(self._path):
            return None
        committed = None
        pending = None
        with open(self._path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(" ", 2)
                if len(parts) != 3:
                    continue
                kind, count_str, root = parts
                try:
                    count = int(count_str)
                except ValueError:
                    continue
                if kind == "committed":
                    committed = (count, root)
                elif kind == "pending":
                    pending = (count, root)
        if committed is None:
            return None
        return committed

    def _read_pending(self) -> tuple[int, str] | None:
        """Return (pending_count, pending_root) or None."""
        if self._path is None or not os.path.isfile(self._path):
            return None
        with open(self._path, "r") as f:
            for line in f:
                line = line.strip()
                parts = line.split(" ", 2)
                if len(parts) == 3 and parts[0] == "pending":
                    try:
                        return (int(parts[1]), parts[2])
                    except ValueError:
                        pass
        return None

    def begin_write(self, next_evolve_count: int, root_hash: bytes | str) -> None:
        """Phase 1: write pending state before DB commit."""
        if self._path is None:
            return
        if isinstance(root_hash, bytes):
            root_hash = root_hash.hex()
        committed = self.read()
        content = f"committed {committed[0]} {committed[1]}\n" if committed else ""
        content += f"pending {next_evolve_count} {root_hash}\n"
        self._write_atomic(self._path, content)

    def finalize(self, evolve_count: int, root_hash: bytes | str) -> None:
        """Phase 2: promote pending to committed (after DB commit)."""
        if self._path is None:
            return
        if isinstance(root_hash, bytes):
            root_hash = root_hash.hex()
        content = f"committed {evolve_count} {root_hash}\n"
        self._write_atomic(self._path, content)

    def maybe_recover_pending(self, db_evolve_count: int) -> tuple[int, str] | None:
        """If a crash left pending ahead of committed, repair and return repaired state."""
        pending = self._read_pending()
        if pending is None:
            return None
        p_count, p_root = pending
        committed = self.read()
        if committed is None:
            return None
        c_count, c_root = committed
        # Legitimate crash: DB advanced by 1 but finalize never ran
        if p_count == c_count + 1 and p_count == db_evolve_count:
            self.finalize(p_count, p_root)
            return (p_count, p_root)
        return None

    def verify(self, db_evolve_count: int, db_root_hash: bytes | str) -> bool:
        """Return True if external state agrees with db (or no external file)."""
        entry = self.read()
        if entry is None:
            return True
        ext_count, ext_root = entry
        if isinstance(db_root_hash, bytes):
            db_root_hash = db_root_hash.hex()
        if db_evolve_count < ext_count:
            return False
        if db_evolve_count == ext_count and db_root_hash != ext_root:
            return False
        return True


class GhostAuditV7:
    """V7: Orthogonal Grid Defense with shuffling + RAID-6 P+Q parity."""
    
    SLOT_COUNT = 5
    # Default slot size. Use GHOST_AUDIT_SLOT_SIZE env var to override for experiments.
    SLOT_SIZE = int(os.environ.get("GHOST_AUDIT_SLOT_SIZE", "1600"))
    HEADER_BIT_COUNT = 72
    MAX_BIT_REPETITIONS = 6
    MIN_BIT_REPETITIONS = 4
    PER_CHANNEL_MIN_BIT_REPETITIONS = max(
        1,
        int(os.environ.get("GHOST_AUDIT_PER_CHANNEL_MIN_REPS", "5")),
    )
    CHANNEL_COUNT = 5          # 3 data + 2 parity (RAID-6)
    DATA_CHANNEL_COUNT = 3     # Data channels 0, 1, 2
    PARITY_CHANNEL = 3         # P parity (XOR of data channels)
    SECOND_PARITY_CHANNEL = 4  # Q parity (GF(2^8) weighted sum of data channels)
    REPLICA_COUNT = max(1, min(int(os.environ.get("GHOST_AUDIT_REPLICA_COUNT", "3")), 5))
    
    # V7 verwendet ausschließlich Per-Channel-RS (kein Combined-Modus).
    # Das Env-Flag GHOST_AUDIT_PER_CHANNEL_RS wird ignoriert.
    PER_CHANNEL_RS = True
    # Magic bytes are derived via k_magic — no hardcoded constants.
    # An attacker scanning for fixed marker bytes cannot detect GhostAudit headers.
    VISIBLE_LOG_TABLE = "audit_log"
    DECOY_ARCHIVE_TABLE = "audit_archive"
    AUX_TABLE = "sys_cache"
    AUX_MANIFEST_TABLE = "sys_cache_manifest"
    MERKLE_ANCHOR_TABLE = "merkle_anchor"
    EVENT_MAC_TABLE = "event_mac_tags"

    # --- Slot-Level Key Derivation & Evolution (Forward Security) ---
    def _get_slot_idx_for_row(self, row_id: int) -> int:
        """Find which slot index a row belongs to (O(1) dict lookup)."""
        row_idx = self._orig_id_to_idx.get(row_id)
        if row_idx is None:
            return 0
        return row_idx // self.SLOT_SIZE

    def _get_slot_keys(self, slot_idx: int) -> tuple:
        """Derive slot-specific keys (Forward Security)."""
        info_shuffling = f"shuffling_v7_slot_{slot_idx}".encode("utf-8")
        info_hmac = f"hmac_v7_slot_{slot_idx}".encode("utf-8")
        k_shuffling_s = hmac.new(self.k_shuffling, info_shuffling, hashlib.sha256).digest()
        k_hmac_s = hmac.new(self.k_hmac, info_hmac, hashlib.sha256).digest()
        return k_shuffling_s, k_hmac_s

    @staticmethod
    def _keyed_magic(k_magic: bytes, is_fragment: bool = False) -> int:
        """Derive a 1-byte header magic from the key instead of a hardcoded constant."""
        label = b"fragment_magic_v8" if is_fragment else b"legacy_magic_v8"
        return hmac.new(k_magic, label, hashlib.sha256).digest()[0]

    # --- Row-specific Carrier Shuffling (NEW in V7) ---
    def _get_row_carrier_mapping(self, row_id: int) -> list:
        """
        Generate pseudo-random permutation of [0, 1, 2, 3, 4] for a specific row.

        mapping[physical_carrier_idx] = logical_channel_idx

        Logical channels (RAID-6 3D+2P):
          0 = Data:   Semantic (bio)
          1 = Data:   Float LSB (trust_score)
          2 = Data:   Trailing Space (bio)
          3 = Parity: P (XOR) — Float LSB (profile_score)
          4 = Parity: Q (GF(2^8)) — Avatar Tilde (~) (avatar_url)
        """
        slot_idx = self._get_slot_idx_for_row(row_id)
        k_shuff, _ = self._get_slot_keys(slot_idx)
        hmac_bytes = hmac.new(
            k_shuff,
            f"row_carrier:{row_id}".encode("utf-8"),
            hashlib.sha256
        ).digest()

        # Generate permutation deterministically from HMAC
        indices = list(range(5))
        for i in range(4):
            swap_idx = (hmac_bytes[i] % (5 - i)) + i
            indices[i], indices[swap_idx] = indices[swap_idx], indices[i]
        return indices

    def _get_header_bit_permutation(self, slot_idx: int):
        """HMAC-keyed permutation of 0..HEADER_BIT_COUNT-1 for header bit-to-row mapping.
        perm[bit_pos] = row_index_within_header_ids.
        """
        k_shuff, _ = self._get_slot_keys(slot_idx)
        h = hmac.new(k_shuff, b"header_bit_perm", hashlib.sha256).digest()
        n = self.HEADER_BIT_COUNT
        perm = list(range(n))
        for i in range(n):
            j = h[i % len(h)] % (n - i) + i
            perm[i], perm[j] = perm[j], perm[i]
        return perm

    # --- Encoding with Shuffling (NEW in V7) ---
    def _encode_all_columns_shuffled(self, row_id: int, bio: str, score: float,
                                    profile_score: float, logical_bits: dict,
                                    avatar_url: str = "") -> tuple:
        """
        Encode logical channel bits using shuffled physical carriers.

        logical_bits = {0: bit0, 1: bit1, 2: bit2, 3: bit3, 4: bit4}

        The physical carriers are mapped to logical channels via _get_row_carrier_mapping().
        Returns (bio, score, profile_score, avatar_url).
        """
        mapping = self._get_row_carrier_mapping(row_id)
        b, s, p, a = bio, score, profile_score, avatar_url

        for physical_carrier in range(5):
            logical_ch = mapping[physical_carrier]
            bit = logical_bits.get(logical_ch, 0)
            if physical_carrier == 0:
                old_bio = b
            b, s, p, a = self._encode_channel_bit(
                physical_carrier, b, s, bit, row_id=row_id,
                profile_score=p, avatar_url=a
            )
            if physical_carrier == 0 and b == old_bio:
                self._semantic_miss_count += 1

        return b, s, p, a

    def _decode_all_columns_shuffled(self, row_id: int, bio: str, score: float,
                                   profile_score: float = 0.0,
                                   avatar_url: str = "") -> dict:
        """
        Decode logical channel bits from shuffled physical carriers.

        Returns {logical_channel: bit} dict.
        """
        mapping = self._get_row_carrier_mapping(row_id)
        logical_bits = {}

        for physical_carrier in range(5):
            logical_ch = mapping[physical_carrier]
            bit = self._decode_channel_bit(
                physical_carrier, bio, score, profile_score, avatar_url
            )
            logical_bits[logical_ch] = bit if bit is not None else 0

        return logical_bits

    # --- XOR Cross-Channel Parity (NEW in V7) ---
    def _compute_p_parity(self, channel_bytes: dict) -> bytes:
        """XOR parity P = C0 ⊕ C1 ⊕ C2 (padded to longest)."""
        data_channels = [channel_bytes.get(c, b"") for c in range(self.DATA_CHANNEL_COUNT)]
        max_len = max(len(ch) for ch in data_channels) if data_channels else 0
        parity = bytearray(max_len)
        for c in range(self.DATA_CHANNEL_COUNT):
            ch = data_channels[c]
            for i, byte_val in enumerate(ch):
                parity[i] ^= byte_val
        return bytes(parity)

    def _compute_q_parity(self, channel_bytes: dict) -> bytes:
        """
        Q parity: Q = Σ g^i · D_i for i = 0..DATA_CHANNEL_COUNT-1
        GF(2^8) weighted sum of the encoded data channels.
        """
        data_channels = [channel_bytes.get(c, b"") for c in range(self.DATA_CHANNEL_COUNT)]
        max_len = max(len(ch) for ch in data_channels) if data_channels else 0
        parity = bytearray(max_len)
        for c in range(self.DATA_CHANNEL_COUNT):
            ch = data_channels[c]
            w = StegoEngine.gf_weight(c)  # g^c
            for i, byte_val in enumerate(ch):
                parity[i] ^= StegoEngine.gf_mul(w, byte_val)
        return bytes(parity)

    def _recover_from_pq_parity(self, channel_bytes: dict, nsym: int,
                                 per_channel_erasures: dict) -> dict:
        """
        RAID-6 recovery: reconstruct failed data channels using P and Q parity.

        Cases:
        1 data channel lost + P survives → XOR recovery (same as before)
        1 data channel lost + P lost, Q survives → GF recovery via Q
        2 data channels lost + P + Q survive → GF 2×2 system
        """
        result = {}
        parity_p = channel_bytes.get(self.PARITY_CHANNEL, b"")
        parity_q = channel_bytes.get(self.SECOND_PARITY_CHANNEL, b"")
        p_ok = len(parity_p) > 0
        q_ok = len(parity_q) > 0

        missing = [c for c in range(self.DATA_CHANNEL_COUNT) if c not in channel_bytes]
        if not missing:
            return channel_bytes  # all present, nothing to do

        # Build working data dict
        working = {c: channel_bytes[c] for c in range(self.DATA_CHANNEL_COUNT) if c in channel_bytes}
        data_len = max(len(v) for v in working.values()) if working else 0

        if len(missing) == 1:
            fc = missing[0]
            if p_ok and (fc in working or len(working) == self.DATA_CHANNEL_COUNT - 1):
                # XOR recovery via P (same as before)
                reconstructed = bytearray(len(parity_p))
                for i, bv in enumerate(parity_p):
                    reconstructed[i] = bv
                for c, ch in working.items():
                    for i in range(min(len(ch), len(reconstructed))):
                        reconstructed[i] ^= ch[i]
            elif q_ok:
                # GF recovery via Q (when P is lost, e.g. Float Round)
                reconstructed = bytearray(len(parity_q))
                w_fail = StegoEngine.gf_weight(fc)
                w_inv = StegoEngine.gf_inv(w_fail)
                for i, bv in enumerate(parity_q):
                    reconstructed[i] = bv
                for c, ch in working.items():
                    w = StegoEngine.gf_weight(c)
                    for i in range(min(len(ch), len(reconstructed))):
                        reconstructed[i] ^= StegoEngine.gf_mul(w, ch[i])
                for i in range(len(reconstructed)):
                    reconstructed[i] = StegoEngine.gf_mul(w_inv, reconstructed[i])
            else:
                return None

            try:
                rx_erasures = [p for p in per_channel_erasures.get(fc, []) if p < len(reconstructed)]
                decoded = RSCodec(nsym).decode(bytes(reconstructed), erase_pos=rx_erasures)
                result[fc] = decoded[0] if isinstance(decoded, tuple) else decoded
                for c, v in working.items():
                    result[c] = v
                return result
            except ReedSolomonError:
                return None

        if len(missing) == 2 and p_ok and q_ok:
            i, j = missing  # i < j by construction
            wi = StegoEngine.gf_weight(i)
            wj = StegoEngine.gf_weight(j)
            w_ij = StegoEngine.gf_mul(wi, StegoEngine.gf_inv(wj)) if wj != 0 else 0
            w_factor = wi ^ wj  # = gf_add(wi, wj) = wi ⊕ wj
            w_inv = StegoEngine.gf_inv(w_factor)

            recon_i = bytearray(max(len(parity_p), len(parity_q)))
            recon_j = bytearray(max(len(parity_p), len(parity_q)))

            for idx in range(len(recon_i)):
                Pv = parity_p[idx] if idx < len(parity_p) else 0
                Qv = parity_q[idx] if idx < len(parity_q) else 0
                for c, ch in working.items():
                    w = StegoEngine.gf_weight(c)
                    bv = ch[idx] if idx < len(ch) else 0
                    Pv ^= bv
                    Qv ^= StegoEngine.gf_mul(w, bv)
                # Solve 2×2 GF system:
                # Pv = d_i ⊕ d_j
                # Qv = g^i · d_i ⊕ g^j · d_j
                # d_i = (Qv ⊕ g^j · Pv) / (g^i ⊕ g^j)
                # d_j = Pv ⊕ d_i
                t = Qv ^ StegoEngine.gf_mul(wj, Pv)
                recon_i[idx] = StegoEngine.gf_mul(w_inv, t)
                recon_j[idx] = Pv ^ recon_i[idx]

            for fc, raw in [(i, bytes(recon_i)), (j, bytes(recon_j))]:
                try:
                    rx_erasures = [p for p in per_channel_erasures.get(fc, []) if p < len(raw)]
                    decoded = RSCodec(nsym).decode(raw, erase_pos=rx_erasures)
                    result[fc] = decoded[0] if isinstance(decoded, tuple) else decoded
                except ReedSolomonError:
                    return None

            for c, v in working.items():
                result[c] = v
            return result

        return None

    # --- Per-Channel Encoding/Decoding (3 data + P + Q) ---
    @staticmethod
    def _encode_channel_bit(channel: int, bio: str, score: float, bit: int,
                            row_id=None, profile_score: float = 0.0,
                            avatar_url: str = ""):
        """Encode a bit to physical carrier (0-4)."""
        if channel == 0:      # Data: Semantic (bio)
            return StegoEngine.encode_bit_semantic(bio, bit), score, profile_score, avatar_url
        elif channel == 1:    # Data: Float-LSB (trust_score)
            return bio, StegoEngine.encode_bit_float_lsb(score, bit, row_id=row_id), profile_score, avatar_url
        elif channel == 2:    # Data: Trailing-Space (bio)
            return StegoEngine.encode_bit_trailing_space(bio, bit), score, profile_score, avatar_url
        elif channel == 3:    # P Parity: Float-LSB (profile_score)
            return bio, score, StegoEngine.encode_bit_float_lsb(profile_score, bit, row_id=row_id), avatar_url
        elif channel == 4:    # Q Parity: Avatar Tilde (~) (avatar_url)
            return bio, score, profile_score, StegoEngine.encode_bit_avatar_url(avatar_url, bit, row_id=row_id)
        raise ValueError(f"Unknown channel: {channel}")

    @staticmethod
    def _decode_channel_bit(channel: int, bio: str, score: float,
                            profile_score: float = 0.0, avatar_url: str = ""):
        """Decode a bit from physical carrier (0-4)."""
        if channel == 0:      # Data: Semantic (bio synonym switching)
            return StegoEngine.decode_bit_semantic(bio)
        elif channel == 1:    # Data: Float-LSB (trust_score)
            return StegoEngine.decode_bit_float_lsb(score)
        elif channel == 2:    # Data: Trailing-Space
            return StegoEngine.decode_bit_trailing_space(bio)
        elif channel == 3:    # P Parity: Float-LSB (profile_score)
            return StegoEngine.decode_bit_float_lsb(profile_score)
        elif channel == 4:    # Q Parity: Avatar Tilde (~)
            return StegoEngine.decode_bit_avatar_url(avatar_url, row_id=0)
        raise ValueError(f"Unknown channel: {channel}")

    def _bits_to_bytes(self, bits: list) -> bytes:
        """Convert bit list to bytes (pad rest with 0s)."""
        padded = list(bits)
        while len(padded) % 8:
            padded.append(0)
        b = bytearray()
        for i in range(0, len(padded), 8):
            chunk = padded[i : i + 8]
            b.append(int("".join(map(str, chunk)), 2))
        return bytes(b)

    def _bytes_to_bits(self, data: bytes) -> list:
        """Convert bytes to bit list."""
        bits = []
        for byte in data:
            bits.extend([int(b) for b in format(byte, "08b")])
        return bits

    # --- Encode Payload with RAID-6 Parity (P + Q) ---
    def _encode_payload_per_channel_v7(self, payload_bytes: bytes, selected_nsym: int):
        """
        Per-Channel RS encoding with RAID-6 P+Q parity (3 data + 2 parity).

        - Partition payload into 3 data channels (round-robin)
        - RS-encode each independently
        - Compute P (XOR) and Q (GF(2^8) weighted sum)
        - Return {channel: encoded_bytes} for channels 0-4
        """
        raw_bits = self._bytes_to_bits(payload_bytes)
        channel_bits = [[] for _ in range(self.DATA_CHANNEL_COUNT)]

        for b_idx, bit_val in enumerate(raw_bits):
            channel_bits[b_idx % self.DATA_CHANNEL_COUNT].append(bit_val)

        channel_encoded = {}
        for c in range(self.DATA_CHANNEL_COUNT):
            ch_bytes = self._bits_to_bytes(channel_bits[c])
            encoded = RSCodec(selected_nsym).encode(ch_bytes)
            channel_encoded[c] = encoded

        p_bytes = self._compute_p_parity(channel_encoded)
        q_bytes = self._compute_q_parity(channel_encoded)
        channel_encoded[self.PARITY_CHANNEL] = RSCodec(selected_nsym).encode(p_bytes)
        channel_encoded[self.SECOND_PARITY_CHANNEL] = RSCodec(selected_nsym).encode(q_bytes)

        return channel_encoded

    # --- Decode Payload with Parity Recovery (V7) ---
    def _extract_channel_encoded_bits_v7(self, cursor, channel, all_payload_ids, num_bits):
        """
        Extract logical channel bits from physical carriers (with shuffling).
        Each row encodes all 5 logical channels (shuffled to different carriers).
        """
        # Filter round-robin rows for this channel (inlined old _channel_payload_ids)
        ch_ids = [
            rid
            for idx, rid in enumerate(all_payload_ids)
            if idx % self.CHANNEL_COUNT == channel
        ]
        if num_bits <= 0 or not ch_ids:
            return b"", []

        available_rows = len(ch_ids)
        repetitions = self._get_dynamic_repetitions(num_bits, available_rows)

        # Ensure repetitions fit
        if num_bits * repetitions > available_rows:
            repetitions = max(1, available_rows // num_bits)
            if num_bits * repetitions > available_rows:
                num_bits = available_rows
                repetitions = 1

        # Deterministic HMAC-based shuffle (inlined old _channel_carrier_order)
        slot_idx = self._get_slot_idx_for_row(ch_ids[0]) if ch_ids else 0
        k_shuff, _ = self._get_slot_keys(slot_idx)
        ordered = sorted(
            ch_ids,
            key=lambda rid: hmac.new(
                k_shuff,
                f"ch_order:{channel}:{rid}".encode("utf-8"),
                hashlib.sha256,
            ).digest(),
        )
        used = ordered[: num_bits * repetitions]
        extracted_bits = []

        for bit_idx in range(num_bits):
            votes = []

            for rep in range(repetitions):
                idx = bit_idx * repetitions + rep
                if idx >= len(used):
                    break
                rid = used[idx]
                cursor.execute(
                    f"SELECT bio, trust_score, profile_score, avatar_url FROM {self.AUX_TABLE} WHERE id=?",
                    (rid,),
                )
                res = cursor.fetchone()
                if res is None or res[0] is None or res[1] is None:
                    continue
                p_score = res[2] if res[2] is not None else 0.0
                av = res[3] or "" if len(res) > 3 else ""
                if not self._verify_sys_cache_row(rid, res[0], res[1], p_score, av):
                    continue

                try:
                    # Decode using shuffled carrier mapping
                    logical_bits = self._decode_all_columns_shuffled(rid, res[0], res[1], p_score, av)
                    bit_value = logical_bits.get(channel, 0)
                    if bit_value is not None:
                        votes.append(bit_value)
                except Exception:
                    continue

            if not votes:
                extracted_bits.append(0)
                continue

            vote = self._majority_vote(votes)
            extracted_bits.append(vote if vote is not None else 0)

        return self._bits_to_bytes(extracted_bits), []

    # --- Dynamic Repetition Scaling (NEW in V7) ---
    def _get_dynamic_repetitions(self, total_bits: int, available_rows: int, min_repetitions: int = 1) -> int:
        """
        Compute maximum repetitions within slot capacity.
        Minimally yields at least min_repetitions (caller handles truncation).
        """
        for reps in range(self.MAX_BIT_REPETITIONS, min_repetitions - 1, -1):
            if total_bits * reps <= available_rows:
                return reps
        for reps in range(min_repetitions - 1, 0, -1):
            if total_bits * reps <= available_rows:
                return reps
        return 1

    def _all_payload_ids(self):
        """Flat list of all sys_cache payload row IDs (post-header)."""
        ids = []
        for slot_idx in range(self.SLOT_COUNT):
            slot_start = slot_idx * self.SLOT_SIZE
            slot_ids = self._orig_ids[slot_start : slot_start + self.SLOT_SIZE]
            ids.extend(slot_ids[self.HEADER_BIT_COUNT :])
        return ids

    def _per_channel_rs_encoded_bit_count(self, stored_msg_len, nsym):
        """RS-encoded bit count per channel (3 data + 2 parity)."""
        payload_bit_count = (16 + stored_msg_len) * 8
        counts = []

        data_encoded_lens = []
        for c in range(self.DATA_CHANNEL_COUNT):
            n_bits = (payload_bit_count + self.DATA_CHANNEL_COUNT - 1 - c) // self.DATA_CHANNEL_COUNT
            ch_bytes = self._bits_to_bytes([0] * n_bits)
            encoded = RSCodec(nsym).encode(ch_bytes)
            data_encoded_lens.append(len(encoded))

        for l in data_encoded_lens:
            counts.append(l * 8)

        # P parity (XOR of data channels)
        parity_source_len = max(data_encoded_lens) if data_encoded_lens else 0
        p_encoded = RSCodec(nsym).encode(b"\x00" * parity_source_len) if parity_source_len > 0 else b""
        counts.append(len(p_encoded) * 8)

        # Q parity (GF(2^8) weighted sum — same source length as P)
        q_encoded = RSCodec(nsym).encode(b"\x00" * parity_source_len) if parity_source_len > 0 else b""
        counts.append(len(q_encoded) * 8)
        return counts

    def _rebuild_payload_from_channel_bytes(self, channel_bytes, stored_msg_len):
        """Round-robin inverse to rebuild payload from 5 channels (3 data + 2 parity)."""
        total_bits = (16 + stored_msg_len) * 8
        raw_bits = []
        for global_idx in range(total_bits):
            # Payload bits were round-robin distributed across DATA_CHANNEL_COUNT (4), parity is separate
            channel = global_idx % self.DATA_CHANNEL_COUNT
            local_idx = global_idx // self.DATA_CHANNEL_COUNT
            byte_idx = local_idx // 8
            bit_pos = 7 - (local_idx % 8)
            block = channel_bytes.get(channel)
            if block is None or byte_idx >= len(block):
                return None
            raw_bits.append((block[byte_idx] >> bit_pos) & 1)
        payload = self._bits_to_bytes(raw_bits)
        return payload[: 16 + stored_msg_len]

    @staticmethod
    def _majority_vote(bits):
        """Majority voting for bit recovery."""
        valid_bits = [bit for bit in bits if bit is not None]
        if not valid_bits:
            return None
        ones = sum(valid_bits)
        zeros = len(valid_bits) - ones
        if ones == zeros:
            return None
        return 1 if ones > zeros else 0

    def _write_sys_cache_slot_v8(self, cursor, channel_blocks, slot_payload_ids):
        """Write all 5 logical channels to slot payload rows using bulk staging + executemany."""
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
        repetitions = self._get_dynamic_repetitions(max_bits, available_rows, self._current_min_repetitions)
        if max_bits * repetitions > available_rows:
            repetitions = max(1, available_rows // max_bits)
            if max_bits * repetitions > available_rows:
                repetitions = 1
                max_bits = available_rows

        placeholders = ','.join(['?'] * len(slot_payload_ids))
        cursor.execute(
            f"SELECT id, bio, trust_score, profile_score, avatar_url FROM {self.AUX_TABLE} WHERE id IN ({placeholders}) ORDER BY id",
            slot_payload_ids
        )
        rows = cursor.fetchall()
        row_map = {r[0]: r for r in rows}

        slot_idx = self._get_slot_idx_for_row(slot_payload_ids[0]) if slot_payload_ids else 0
        _, k_hm = self._get_slot_keys(slot_idx)

        update_buffer = []
        manifest_buffer = []

        for bit_idx in range(max_bits):
            for rep in range(repetitions):
                row_idx = bit_idx * repetitions + rep
                if row_idx >= len(slot_payload_ids):
                    break
                rid = slot_payload_ids[row_idx]
                row_data = row_map.get(rid)
                if not row_data:
                    continue
                _, bio, score, profile_score_val, avatar_url = row_data
                avatar_url = avatar_url or ""

                logical_bits = {
                    0: channel_bits_dict[0][bit_idx],
                    1: channel_bits_dict[1][bit_idx],
                    2: channel_bits_dict[2][bit_idx],
                    3: channel_bits_dict[3][bit_idx],
                    4: channel_bits_dict[4][bit_idx],
                }

                new_bio, new_score, new_profile, new_avatar = self._encode_all_columns_shuffled(
                    rid, bio, score, profile_score_val, logical_bits, avatar_url=avatar_url
                )

                row_mac = self._compute_row_mac_from_logical_bits(rid, logical_bits, k_hm)

                update_buffer.append((new_bio, new_score, new_profile, new_avatar, rid))
                manifest_buffer.append((rid, row_mac))

        cursor.executemany(
            f"UPDATE {self.AUX_TABLE} SET bio=?, trust_score=?, profile_score=?, avatar_url=? WHERE id=?",
            update_buffer
        )
        cursor.executemany(
            f"INSERT OR REPLACE INTO {self.AUX_MANIFEST_TABLE} (id, row_mac, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
            manifest_buffer
        )

    def _extract_all_channels_v8(self, cursor, slot_payload_ids, num_bits):
        """Extract all 5 logical channels via bulk SELECT, with erasure checking."""
        available_rows = len(slot_payload_ids)
        if num_bits <= 0 or available_rows <= 0:
            return {c: b"" for c in range(self.CHANNEL_COUNT)}, {c: [] for c in range(self.CHANNEL_COUNT)}

        repetitions = self._get_dynamic_repetitions(num_bits, available_rows)
        if num_bits * repetitions > available_rows:
            repetitions = max(1, available_rows // num_bits)
            if num_bits * repetitions > available_rows:
                num_bits = available_rows
                repetitions = 1

        placeholders = ','.join(['?'] * len(slot_payload_ids))
        cursor.execute(
            f"SELECT id, bio, trust_score, profile_score, avatar_url FROM {self.AUX_TABLE} WHERE id IN ({placeholders}) ORDER BY id",
            slot_payload_ids
        )
        rows = cursor.fetchall()
        row_map = {r[0]: (r[1], r[2], r[3], r[4] or "") for r in rows}

        cursor.execute(
            f"SELECT id, row_mac FROM {self.AUX_MANIFEST_TABLE} WHERE id IN ({placeholders}) ORDER BY id",
            slot_payload_ids
        )
        manifest_rows = cursor.fetchall()
        manifest_map = {r[0]: r[1] for r in manifest_rows}

        slot_idx = self._get_slot_idx_for_row(slot_payload_ids[0]) if slot_payload_ids else 0
        _, k_hm = self._get_slot_keys(slot_idx)

        channel_bits = {c: [] for c in range(self.CHANNEL_COUNT)}
        channel_erasures = {c: [] for c in range(self.CHANNEL_COUNT)}

        for bit_idx in range(num_bits):
            votes = {c: [] for c in range(self.CHANNEL_COUNT)}

            for rep in range(repetitions):
                row_idx = bit_idx * repetitions + rep
                if row_idx >= len(slot_payload_ids):
                    break
                rid = slot_payload_ids[row_idx]
                row_data = row_map.get(rid)
                if not row_data:
                    continue

                bio, score, profile_score, avatar_url = row_data
                row_mac_blob = manifest_map.get(rid, b"")

                logical_bits = self._decode_all_columns_shuffled(
                    rid, bio, score, profile_score, avatar_url
                )

                for c in range(self.CHANNEL_COUNT):
                    val = logical_bits.get(c, 0)
                    if len(row_mac_blob) >= 32:
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
                    vote = 1 if ones >= len(valid_votes) - ones else 0
                    channel_bits[c].append(vote)

        channel_bytes = {}
        for c in range(self.CHANNEL_COUNT):
            channel_bytes[c] = self._bits_to_bytes(channel_bits[c])

        return channel_bytes, channel_erasures

    # --- Header Operations (same as V6) ---
    def _encode_header_bit(self, text, score, bit, row_id=None, profile_score=None, avatar_url=None):
        text = StegoEngine.encode_bit_case(text, bit)
        text = StegoEngine.encode_bit_trailing_space(text, bit)
        score = StegoEngine.encode_bit_float_lsb(score, bit, row_id=row_id)
        if profile_score is not None:
            profile_score = StegoEngine.encode_bit_float_lsb(profile_score, bit, row_id=row_id)
        if avatar_url is not None:
            avatar_url = StegoEngine.encode_bit_avatar_url(avatar_url, bit, row_id=row_id or 0)
        return text, score, profile_score, avatar_url

    def _decode_header_bit(self, rid, text, score, profile_score=None, avatar_url=None):
        """Decode header bit using shuffled carriers, excluding degraded carriers."""
        carrier_votes = [
            StegoEngine.decode_bit_case(text),
            StegoEngine.decode_bit_trailing_space(text),
            StegoEngine.decode_bit_float_lsb(score),
            StegoEngine.decode_bit_float_lsb(profile_score) if profile_score is not None else None,
            StegoEngine.decode_bit_avatar_url(avatar_url, row_id=0) if avatar_url is not None else None,
        ]
        valid = [(i, v) for i, v in enumerate(carrier_votes) if v is not None]
        if not valid:
            return 0
        if len(valid) <= 3:
            ones = sum(v for _, v in valid)
            return 1 if ones > len(valid) - ones else 0
        mapping = self._get_row_carrier_mapping(rid)
        # Exclude carriers with known-high degradation from voting
        slot_idx = self._get_slot_idx_for_row(rid)
        excluded = self._header_dead_carriers(slot_idx)
        active = [(i, v) for i, v in valid if i not in excluded]
        if not active:
            active = valid
        if len(active) <= 3:
            ones = sum(v for _, v in active)
            return 1 if ones > len(active) - ones else 0
        # From the active set, pick top-3 by HMAC carrier order (lowest logical_ch wins)
        ranked = sorted(active, key=lambda x: mapping.index(x[0]))
        top3 = ranked[:3]
        ones = sum(v for _, v in top3)
        zeros = len(top3) - ones
        return 1 if ones > zeros else 0

    def _header_dead_carriers(self, slot_idx: int) -> set:
        """Return set of physical carrier indices with erasure_pct >= 0.3 for a slot."""
        if slot_idx in self._header_dead_carrier_cache:
            return self._header_dead_carrier_cache[slot_idx]
        q = self._get_channel_quality(slot_idx)
        if q is None:
            self._header_dead_carrier_cache[slot_idx] = set()
            return set()
        dead = {ch for ch, pct in q.items() if pct >= 0.3}
        self._header_dead_carrier_cache[slot_idx] = dead
        return dead

    def _write_header_bits_to_slot(self, cursor, header_bytes, header_ids, slot_idx=0):
        h_bits = []
        for b in header_bytes:
            h_bits.extend([int(x) for x in format(b, "08b")])

        perm = self._get_header_bit_permutation(slot_idx)
        for i, bit in enumerate(h_bits):
            if i >= len(header_ids):
                break
            rid = header_ids[perm[i]]
            cursor.execute(
                f"SELECT bio, trust_score, profile_score, avatar_url FROM {self.AUX_TABLE} WHERE id=?",
                (rid,),
            )
            res = cursor.fetchone()
            if not res:
                continue
            bio, score, profile_score_val, avatar_url = res
            profile_score_val = profile_score_val if profile_score_val is not None else 0.0
            avatar_url = avatar_url or ""
            new_bio, new_score, new_ps, new_av = self._encode_header_bit(
                bio, score, bit, row_id=rid,
                profile_score=profile_score_val, avatar_url=avatar_url
            )
            cursor.execute(
                f"UPDATE {self.AUX_TABLE} SET bio=?, trust_score=?, profile_score=?, avatar_url=? WHERE id=?",
                (new_bio, new_score, new_ps, new_av, rid),
            )
            row_mac_val = self._sys_cache_row_mac(rid, new_bio, new_score, new_ps, new_av)
            cursor.execute(
                f"""
                INSERT OR REPLACE INTO {self.AUX_MANIFEST_TABLE} (id, row_mac, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                """,
                (rid, row_mac_val),
            )

    def _decode_header(self, header_bits, slot_idx=0):
        """Keyed-magic header decode. slot_idx determines expected magic byte."""
        if len(header_bits) < self.HEADER_BIT_COUNT:
            return None
        bytes_data = bytearray()
        for i in range(0, self.HEADER_BIT_COUNT, 8):
            bits_str = "".join(map(str, header_bits[i:i+8]))
            bytes_data.append(int(bits_str, 2))

        try:
            magic = bytes_data[0]
            legacy_expected = self._keyed_magic(self.k_magic, is_fragment=False)
            fragment_expected = self._keyed_magic(self.k_magic, is_fragment=True)

            if magic == legacy_expected:
                if len(bytes_data) < 8:
                    return None
                flags_and_nsym = bytes_data[3]
                nsym = flags_and_nsym & 0x7F
                compressed = bool(flags_and_nsym & 0x80)
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

            if magic == fragment_expected:
                if len(bytes_data) < 9:
                    return None
                stored_msg_len = (bytes_data[1] << 8) | bytes_data[2]
                frag_len = (bytes_data[3] << 8) | bytes_data[4]
                flags_and_nsym = bytes_data[5]
                nsym = flags_and_nsym & 0x3F
                multi_frag = bool(flags_and_nsym & 0x40)
                compressed = bool(flags_and_nsym & 0x80)
                sequence_number = (bytes_data[6] << 16) | (bytes_data[7] << 8) | bytes_data[8]
                fragment_count = 2 if multi_frag else 1
                return {
                    "magic": magic,
                    "payload_len": stored_msg_len,
                    "frag_len": frag_len,
                    "nsym": nsym,
                    "sequence_number": sequence_number,
                    "compressed": compressed,
                    "fragment_index": 0,
                    "fragment_count": fragment_count,
                    "mode": "fragment",
                }
        except Exception:
            return None
        return None

    def _build_legacy_header(self, stored_msg_len, nsym, sequence_number, compressed, slot_idx=0):
        magic = self._keyed_magic(self.k_magic, is_fragment=False)
        flags_and_nsym = nsym | (0x80 if compressed else 0)
        return struct.pack(">B H B I", magic, stored_msg_len, flags_and_nsym, sequence_number)

    def _build_fragment_header(self, stored_msg_len, nsym, sequence_number, compressed, fragment_index, fragment_count, frag_len, slot_idx=0):
        magic = self._keyed_magic(self.k_magic, is_fragment=True)
        flags_and_nsym = nsym | ((1 if fragment_count > 1 else 0) << 6) | (0x80 if compressed else 0)
        return struct.pack(">B H H B 3B", magic, stored_msg_len, frag_len, flags_and_nsym,
                           (sequence_number >> 16) & 0xFF, (sequence_number >> 8) & 0xFF,
                           sequence_number & 0xFF)

    def _fragment_encoded_bytes(self, encoded_bytes, max_fragments, max_bytes_per_fragment: int = None):
        """Split encoded bytes into at most ``max_fragments``.

        If ``max_bytes_per_fragment`` is provided, prefer that as the per-fragment
        capacity (used to align fragments to slot/channel capacities). Otherwise
        fall back to evenly-sized chunks (ceil division).

        Always returns exactly ``max_fragments`` fragments (padding with empty
        bytes) so callers can safely iterate up to ``max_fragments``.
        """
        if max_fragments < 1:
            raise ValueError("No fragments available for payload encoding")

        total_len = len(encoded_bytes)
        if total_len == 0:
            return [b""] * max_fragments

        if max_bytes_per_fragment is None:
            # Default: evenly distribute bytes across fragments
            max_bytes_per_fragment = max(1, (total_len + max_fragments - 1) // max_fragments)

        # Greedy split using the provided per-fragment capacity. This ensures
        # fragments will fit the expected slot/channel capacity when caller
        # supplies a realistic max_bytes_per_fragment.
        fragments = []
        start = 0
        while start < total_len:
            end = min(total_len, start + max_bytes_per_fragment)
            fragments.append(encoded_bytes[start:end])
            start = end

        if len(fragments) > max_fragments:
            # Rebalance: ceil division to fit in max_fragments
            new_size = max(1, (total_len + max_fragments - 1) // max_fragments)
            fragments = []
            start = 0
            while start < total_len:
                end = min(total_len, start + new_size)
                fragments.append(encoded_bytes[start:end])
                start = end

        if len(fragments) > max_fragments:
            raise ValueError("Message too long for available slot fragments")

        # Pad to exactly max_fragments
        while len(fragments) < max_fragments:
            fragments.append(b"")

        return fragments

    def _compute_row_mac_from_logical_bits(self, row_id, logical_bits, k_hm=None):
        """Compute 5×8-byte row MAC from pre-decoded logical bits (no redundant shuffle)."""
        if k_hm is None:
            slot_idx = self._get_slot_idx_for_row(row_id)
            _, k_hm = self._get_slot_keys(slot_idx)
        mac_blob = bytearray()
        for c in range(5):
            val = logical_bits.get(c, 0) or 0
            payload = struct.pack(">I B B", row_id, c, val)
            mac_blob += hmac.new(k_hm, payload, hashlib.sha256).digest()[:8]
        return bytes(mac_blob)

    def _sys_cache_row_mac(self, row_id, bio, trust_score, profile_score=0.0, avatar_url=""):
        """V8: 5 separate 8-Byte MACs over decoded *logical* channel bits (per-row shuffle)."""
        logical_bits = self._decode_all_columns_shuffled(
            row_id, bio, trust_score, profile_score, avatar_url
        )
        return self._compute_row_mac_from_logical_bits(row_id, logical_bits)

    def _verify_sys_cache_row(self, row_id, bio, trust_score, profile_score=0.0, avatar_url=""):
        """Verify sys_cache row MAC."""
        cursor = self.conn.cursor()
        cursor.execute(
            f"SELECT row_mac FROM {self.AUX_MANIFEST_TABLE} WHERE id=?",
            (row_id,),
        )
        res = cursor.fetchone()
        if not res:
            return False
        expected_mac = self._sys_cache_row_mac(row_id, bio, trust_score, profile_score, avatar_url)
        return hmac.compare_digest(res[0], expected_mac)

    def _entry_hash(self, sequence_number, stored_msg_bytes, compressed, mac, prev_hash):
        """Compute entry hash for visible log."""
        payload = (
            struct.pack(">I", sequence_number)
            + prev_hash
            + struct.pack(">B", 1 if compressed else 0)
            + mac
            + stored_msg_bytes
        )
        return hmac.new(self.k_hmac, payload, hashlib.sha256).digest()

    def _get_probe_rows(self, slot_payload_ids, sample_size=30):
        """Deterministic HMAC-keyed row selection for carrier probing."""
        if not slot_payload_ids:
            return []
        slot_idx = self._get_slot_idx_for_row(slot_payload_ids[0])
        k_shuff, _ = self._get_slot_keys(slot_idx)
        ordered = sorted(
            slot_payload_ids,
            key=lambda rid: hmac.new(k_shuff, f"probe:{rid}".encode(), hashlib.sha256).digest()
        )
        return ordered[:min(sample_size, len(ordered))]

    def _probe_carrier_integrity(self, cursor, slot_payload_ids, initial_sample=15, extend_sample=25):
        """Check physical carrier health via sequential syntactic analysis.

        Starts with ``initial_sample`` rows. If degradation is uncertain
        (0.2–0.8), extends by ``extend_sample`` rows for better statistical power.
        Returns per-channel degradation (0.0=healthy, 1.0=dead).
        """
        def _analyze(probe_ids):
            if not probe_ids:
                return None
            placeholders = ','.join(['?'] * len(probe_ids))
            cursor.execute(
                f"SELECT id, bio, trust_score, profile_score, avatar_url FROM {self.AUX_TABLE} WHERE id IN ({placeholders})",
                probe_ids
            )
            rows = cursor.fetchall()
            if not rows:
                return None
            total = len(rows)
            ts, ss, ls, ps, at = 0, 0, 0, 0, 0
            all_kw = [kw for pair in StegoEngine.SEMANTIC_MAP.values() for kw in pair]
            for _, bio, score, pscore, avatar in rows:
                bio = bio or ""
                avatar = avatar or ""
                if bio.endswith(" "): ts += 1
                if any(re.search(rf"\b{kw}\b", bio, re.IGNORECASE) for kw in all_kw): ss += 1
                ls += int(round(score * 1000000)) % 2
                ps += int(round(pscore * 1000000)) % 2
                if avatar.endswith("~"): at += 1

            def r(n):
                return n / max(total, 1)

            return {
                0: 1.0 - min(r(ss) * 3, 1.0),
                1: 0.0 if 0.15 <= r(ls) <= 0.85 else 1.0,
                2: 1.0 - min(r(ts) * 4, 1.0),
                3: 0.0 if 0.15 <= r(ps) <= 0.85 else 1.0,
                4: 1.0 - min(r(at) * 4, 1.0),
            }

        probe_ids = self._get_probe_rows(slot_payload_ids, initial_sample)
        result = _analyze(probe_ids)
        if result is None:
            return {c: 0.0 for c in range(self.CHANNEL_COUNT)}

        D = max(result.values())
        if 0.2 < D < 0.8:
            extra = self._get_probe_rows(slot_payload_ids, initial_sample + extend_sample)
            extra_ids = [rid for rid in extra if rid not in probe_ids][:extend_sample]
            if extra_ids:
                extended = _analyze(probe_ids + extra_ids)
                if extended is not None:
                    result = extended

        return result

    def _get_channel_quality(self, slot_idx):
        """Load per-channel erasure history for a slot. Returns {channel: erasure_pct} or None if no history."""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT channel, erasure_pct, sample_count FROM sys_channel_quality WHERE slot_idx=? ORDER BY channel",
            (slot_idx,)
        )
        rows = cursor.fetchall()
        if not rows:
            return None
        return {r[0]: r[1] for r in rows}

    def _update_channel_quality(self, slot_idx, channel, erasure_pct, sample_count=1):
        """Persist per-channel erasure rate (asymmetric EMA: fast attack, slow release)."""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT erasure_pct, sample_count FROM sys_channel_quality WHERE slot_idx=? AND channel=?",
            (slot_idx, channel)
        )
        existing = cursor.fetchone()
        if existing:
            old_pct, old_count = existing
            new_count = old_count + sample_count
            alpha = 0.6 if erasure_pct > old_pct else 0.1
            smoothed = alpha * erasure_pct + (1 - alpha) * old_pct
            cursor.execute(
                "UPDATE sys_channel_quality SET erasure_pct=?, sample_count=?, updated_at=CURRENT_TIMESTAMP WHERE slot_idx=? AND channel=?",
                (smoothed, new_count, slot_idx, channel)
            )
        else:
            cursor.execute(
                "INSERT INTO sys_channel_quality (slot_idx, channel, erasure_pct, sample_count) VALUES (?, ?, ?, ?)",
                (slot_idx, channel, erasure_pct, sample_count)
            )
        self.conn.commit()

    def _degradation_to_params(self, degradation):
        """Map per-channel degradation (0.0-1.0) to adaptive nsym and min_reps."""
        D = max(degradation.values())
        if D < 0.15:
            return {"min_nsym": 0, "min_reps": 1}
        elif D < 0.4:
            return {"min_nsym": 8, "min_reps": 2}
        elif D < 0.6:
            return {"min_nsym": 16, "min_reps": 3}
        else:
            return {"min_nsym": 24, "min_reps": 4}

    def __init__(self, db_path="ghost_audit_v7.db", secret_key=None, key_provider=None, ecc_symbols=36, verbose=True, siem_export_path=None, siem_export_format="jsonl", metronome_interval=0, external_state_path=None, force_reinit=False, shares=None, share_threshold=2):
        self.db_path = db_path
        self.ecc_symbols = ecc_symbols
        self.verbose = verbose
        self.siem_export_path = siem_export_path
        self.siem_export_format = siem_export_format.lower() if siem_export_format else "jsonl"
        self.metronome_interval = metronome_interval
        self._last_heartbeat_beat = 0
        self._last_heartbeat_time = 0.0
        self._metronome_table = "fs_metronome"
        self.external_state = ExternalStateCounter(
            external_state_path or ExternalStateCounter._default_path(db_path)
        )

        # --- Master key acquisition (priority: shares > key_provider > secret_key / env) ---
        master_key = None
        if shares is not None:
            from core.shamir_secret_sharing import reconstruct_from_sources
            try:
                master_key = reconstruct_from_sources(shares)
                if verbose:
                    print(f"[V7] Master key reconstructed from {len(shares)} shares (threshold={share_threshold})")
            except Exception as e:
                if verbose:
                    print(f"[V7] SSS reconstruction failed: {e}")
                raise

        if master_key is None and key_provider is not None:
            try:
                master_key = key_provider.get_master_key()
            except Exception as e:
                if self.verbose:
                    print(f"[V7] key_provider.get_master_key() failed: {e}")
                raise

        if master_key is None:
            if secret_key is None:
                secret_key = os.environ.get("GHOST_AUDIT_KEY")
                if not secret_key:
                    if verbose:
                        print("[V7] No GHOST_AUDIT_KEY set. Using dev fallback.")
                    secret_key = "dev-fallback-super-long-secure-key-v7-123456789"
            master_key = secret_key.encode("utf-8")

        self.master_key = master_key

        # --- Derive subkeys using HKDF (defence-in-depth) ---
        def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
            return hmac.new(salt if salt is not None else b"", ikm, hashlib.sha256).digest()

        def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
            """Simple HKDF-Expand implementation returning `length` bytes."""
            okm = b""
            t = b""
            counter = 1
            while len(okm) < length:
                t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
                okm += t
                counter += 1
            return okm[:length]

        prk = hkdf_extract(b"", self.master_key)
        self.k_shuffling = hkdf_expand(prk, b"shuffling_v7", 32)
        self.k_hmac = hkdf_expand(prk, b"hmac_v7", 32)
        self.k_merkle = hkdf_expand(prk, b"merkle_anchor_v7", 32)
        self.k_magic = hkdf_expand(prk, b"magic_v8", 32)
        self._semantic_miss_count = 0
        self._current_min_repetitions = 1
        self._gate_depth = 0
        self._header_dead_carrier_cache = {}
        self._write_lock = threading.RLock()

        # Forward-secure Merkle anchor key (evolves after each event)
        self._k_write_merkle = hmac.new(self.k_merkle, b"forward_merkle_v7", hashlib.sha256).digest()
        self._key_evolve_count = 0
        self._key_state_table = "fs_key_state"
        self._cached_slot_sequences = None
        self._log_event_count = 0  # for REBUILD_CHECK_INTERVAL rate-limiting
        
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA cache_size=-10000")
        
        # Generate 8000 row IDs (5 slots × 1600 rows)
        self._orig_ids = []
        c = 1
        for idx in range(self.SLOT_COUNT * self.SLOT_SIZE):
            self._orig_ids.append(c)
            h = hmac.new(self.k_shuffling, f"step_v7_{idx}".encode('utf-8'), hashlib.sha256).digest()
            step = (h[0] % 3) + 1
            c += step
        self._orig_id_to_idx = {rid: idx for idx, rid in enumerate(self._orig_ids)}
        
        self._setup_db()
        self._verify_external_state(force_reinit=force_reinit)

    def _setup_db(self):
        """Initialize or load database (same as V6 structure)."""
        cursor = self.conn.cursor()
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (self.VISIBLE_LOG_TABLE,))
        visible_exists = cursor.fetchone()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (self.AUX_TABLE,))
        aux_exists = cursor.fetchone()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (self.AUX_MANIFEST_TABLE,))
        manifest_exists = cursor.fetchone()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (self.DECOY_ARCHIVE_TABLE,))
        decoy_exists = cursor.fetchone()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (self.MERKLE_ANCHOR_TABLE,))
        anchor_exists = cursor.fetchone()

        # Create + open write gate for setup (triggers don't exist yet on bootstrap).
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
        cursor.execute(
            "UPDATE sys_cache_write_gate SET allow_write=1 WHERE id=1"
        )
        self.conn.commit()

        self._create_key_state_table()
        self._create_metronome_table()
        self._create_event_mac_table()
        if visible_exists and aux_exists:
            self._ensure_sys_cache_guards()
            if not manifest_exists:
                self._rebuild_sys_cache_manifest()
            if self.verbose:
                print("[V7] Existing tables detected. Loading in persistent mode.")
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
            self._migrate_sys_cache_v8_profile_score()
            self._load_key_evolve_state()
            self._load_metronome_state()
            self.conn.commit()
            self._ensure_channel_quality_table()
            self._ensure_internal_table_guards()
            self._seed_carrier_quality()
            self._set_sys_cache_write_mode(False, commit=True)
            return

        if self.verbose:
            print("[V7] Bootstrap mode: creating new tables.")

        cursor.execute(
            f"CREATE TABLE {self.AUX_TABLE} (id INTEGER PRIMARY KEY, bio TEXT NOT NULL, trust_score REAL NOT NULL, profile_score REAL NOT NULL DEFAULT 0.0, avatar_url TEXT NOT NULL DEFAULT '')"
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
        self._create_merkle_anchor_table()
        self._load_key_evolve_state()
        self._load_metronome_state()
        
        # Templates for initial rows — extended pool for forensic plausibility.
        # Synonym pairs (currently/presently, active/online, working/operating,
        # system/platform) are naturally seeded here so the stego substitutions
        # remain indistinguishable from normal text variation.
        templates = [
            "The developer is currently focused on backend code.",
            "This user is presently active on the main database.",
            "He is working hard to resolve security alerts.",
            "The database system is configured for high reliability.",
            "Service account is currently operating in maintenance mode.",
            "This user is online and active within the platform.",
            "The platform is presently undergoing routine diagnostics.",
            "She is operating on the primary system to finalize the build.",
            "User account is currently syncing with the backend system.",
            "The system is active and currently processing queued tasks.",
            "He is presently working on the database migration scripts.",
            "This service is online and operating within normal parameters.",
            "The developer is actively working on the monitoring platform.",
            "Automated account is currently running scheduled system checks.",
            "This user is presently online and working on the main platform.",
            "The system is currently active and operating at full capacity.",
        ]

        # Gaussian trust_score distribution (μ=0.78, σ=0.12) mimics real
        # user-reputation scores; clamped to [0.01, 0.99] to avoid boundary
        # artefacts that statistical tests would flag as uniform.
        seed_int = int.from_bytes(self.k_shuffling[:8], 'big')
        rng_scores = random.Random(seed_int)
        users = []
        for idx, cid in enumerate(self._orig_ids):
            bio_template = templates[idx % len(templates)]
            raw_score = rng_scores.gauss(0.78, 0.12)
            score = max(0.01, min(0.99, raw_score))
            raw_profile = rng_scores.gauss(0.5, 0.15)
            profile_score_val = max(0.01, min(0.99, raw_profile))
            users.append((cid, bio_template, score, profile_score_val))
        
        cursor.executemany(f"INSERT INTO {self.AUX_TABLE} VALUES (?, ?, ?, ?, '')", users)
        self.conn.commit()
        self._ensure_sys_cache_guards()
        self._rebuild_sys_cache_manifest()
        self._set_sys_cache_write_mode(False)
        self._ensure_channel_quality_table()
        self._ensure_internal_table_guards()
        self._seed_carrier_quality()

    def _seed_carrier_quality(self):
        """Constructor-time carrier probe to seed EMA before first write.
        Probes the first occupied slot (or slot 0) and seeds sys_channel_quality.
        No-op if the probe table is empty (fresh DB with no rows yet on bootstrap
        path — bootstrap seeds after rows are populated).
        """
        cursor = self.conn.cursor()
        slot_payload_ids = self._orig_ids[self.HEADER_BIT_COUNT : self.SLOT_SIZE]
        probe = self._probe_carrier_integrity(cursor, slot_payload_ids)
        if probe and any(v > 0.0 for v in probe.values()):
            self._set_sys_cache_write_mode(True, commit=False)
            try:
                for channel, pct in probe.items():
                    self._update_channel_quality(0, channel, pct)
                self.conn.commit()
            finally:
                self._set_sys_cache_write_mode(False, commit=True)

    def _ensure_sys_cache_guards(self):
        """Set up write guards and manifest for sys_cache."""
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
        cursor.execute(f"""
            CREATE TRIGGER IF NOT EXISTS sys_cache_block_null_bio
            BEFORE UPDATE OF bio ON {self.AUX_TABLE}
            WHEN NEW.bio IS NULL
            BEGIN
                SELECT RAISE(ABORT, 'sys_cache.bio cannot be NULL');
            END;
        """)
        cursor.execute(f"""
            CREATE TRIGGER IF NOT EXISTS sys_cache_block_null_score
            BEFORE UPDATE OF trust_score ON {self.AUX_TABLE}
            WHEN NEW.trust_score IS NULL
            BEGIN
                SELECT RAISE(ABORT, 'sys_cache.trust_score cannot be NULL');
            END;
        """)
        for op, opname in [("UPDATE", "update"), ("INSERT", "insert"), ("DELETE", "delete")]:
            cursor.execute(f"""
                CREATE TRIGGER IF NOT EXISTS gate_guard_{self.AUX_TABLE}_{opname}
                BEFORE {op} ON {self.AUX_TABLE}
                WHEN (SELECT allow_write FROM sys_cache_write_gate WHERE id = 1) = 0
                BEGIN
                    SELECT RAISE(ABORT, 'writes to {self.AUX_TABLE} require internal gate');
                END;
            """)
        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS {self.AUX_MANIFEST_TABLE} (
                id INTEGER PRIMARY KEY,
                row_mac BLOB NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        self.conn.commit()

    def _ensure_internal_table_guards(self):
        """Create gate triggers for non-sys_cache internal tables (runs after all tables exist)."""
        cursor = self.conn.cursor()
        for tbl in ["sys_channel_quality", self._key_state_table, self._metronome_table,
                     self.MERKLE_ANCHOR_TABLE, self.EVENT_MAC_TABLE, self.AUX_MANIFEST_TABLE]:
            for op, opname in [("UPDATE", "update"), ("INSERT", "insert"), ("DELETE", "delete")]:
                trig_name = f"gate_guard_{tbl}_{opname}".replace(".", "_")
                cursor.execute(f"""
                    CREATE TRIGGER IF NOT EXISTS {trig_name}
                    BEFORE {op} ON {tbl}
                    WHEN (SELECT allow_write FROM sys_cache_write_gate WHERE id = 1) = 0
                    BEGIN
                        SELECT RAISE(ABORT, 'writes to {tbl} require internal gate');
                    END;
                """)
        self.conn.commit()

    def _set_sys_cache_write_mode(self, enabled, commit=True):
        if enabled:
            if self._gate_depth == 0:
                cursor = self.conn.cursor()
                cursor.execute(
                    "UPDATE sys_cache_write_gate SET allow_write=1 WHERE id=1",
                )
                if commit:
                    self.conn.commit()
            self._gate_depth += 1
        else:
            if self._gate_depth <= 0:
                self._gate_depth = 0
            else:
                self._gate_depth -= 1
            if self._gate_depth == 0:
                cursor = self.conn.cursor()
                cursor.execute(
                    "UPDATE sys_cache_write_gate SET allow_write=0 WHERE id=1",
                )
                if commit:
                    self.conn.commit()

    @contextmanager
    def _write_gate(self, immediate_commit=True):
        """Thread-safe context manager for database write operations."""
        with self._write_lock:
            self._set_sys_cache_write_mode(True, commit=immediate_commit)
            try:
                yield
            finally:
                self._set_sys_cache_write_mode(False, commit=immediate_commit)

    def _create_key_state_table(self):
        cursor = self.conn.cursor()
        pc = getattr(self, '_process_count', 1)
        if pc > 1:
            cursor.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {self._key_state_table} (
                    id INTEGER PRIMARY KEY,
                    evolve_count INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            for pid in range(pc):
                cursor.execute(
                    f"INSERT OR IGNORE INTO {self._key_state_table} (id, evolve_count) VALUES (?, 0)",
                    (pid + 1,),
                )
        else:
            cursor.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {self._key_state_table} (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    evolve_count INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            cursor.execute(
                f"INSERT OR IGNORE INTO {self._key_state_table} (id, evolve_count) VALUES (1, 0)"
            )
        self.conn.commit()

    def _create_metronome_table(self):
        cursor = self.conn.cursor()
        cursor.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {self._metronome_table} (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                last_heartbeat_beat INTEGER NOT NULL DEFAULT 0,
                last_heartbeat_time REAL NOT NULL DEFAULT 0.0
            )
            """
        )
        cursor.execute(
            f"""
            INSERT OR IGNORE INTO {self._metronome_table} (id, last_heartbeat_beat, last_heartbeat_time)
            VALUES (1, 0, 0.0)
            """
        )
        self.conn.commit()

    def _load_metronome_state(self):
        if self.metronome_interval <= 0:
            return
        cursor = self.conn.cursor()
        cursor.execute(f"SELECT last_heartbeat_beat, last_heartbeat_time FROM {self._metronome_table} WHERE id=1")
        row = cursor.fetchone()
        if row:
            self._last_heartbeat_beat = row[0]
            self._last_heartbeat_time = row[1]

    def _save_metronome_state(self):
        cursor = self.conn.cursor()
        cursor.execute(
            f"INSERT OR REPLACE INTO {self._metronome_table} (id, last_heartbeat_beat, last_heartbeat_time) VALUES (1, ?, ?)",
            (self._last_heartbeat_beat, self._last_heartbeat_time),
        )

    def _load_key_evolve_state(self):
        cursor = self.conn.cursor()
        kid = getattr(self, '_process_id', 0) + 1
        cursor.execute(f"SELECT evolve_count FROM {self._key_state_table} WHERE id=?", (kid,))
        row = cursor.fetchone()
        if row and row[0] > 0:
            self._key_evolve_count = row[0]
            for _ in range(self._key_evolve_count):
                self._k_write_merkle = hmac.new(
                    self._k_write_merkle, b"evolve", hashlib.sha256
                ).digest()

    def _verify_external_state(self, force_reinit=False):
        """Check external monotonic counter against DB state. Raises RuntimeError on rollback."""
        db_count = self._key_evolve_count

        # Try crash recovery first: pending may be stuck after an unclean shutdown
        recovered = self.external_state.maybe_recover_pending(db_count)
        if recovered is not None:
            ext_count, ext_root = recovered
        else:
            entry = self.external_state.read()
            # File missing: clean first init (count=0) is OK; anything else is sabotage.
            if entry is None:
                if db_count == 0 or force_reinit:
                    return
                raise RuntimeError(
                    f"STATE_FILE_MISSING: external state counter file not found, "
                    f"but database has evolve_count={db_count}. "
                    "An attacker may have deleted the counter file after a rollback. "
                    "To override, pass force_reinit=True to GhostAuditV7()."
                )
            ext_count, ext_root = entry

        if db_count < ext_count:
            if force_reinit:
                return
            raise RuntimeError(
                f"ROLLBACK_DETECTED: external state counter ({ext_count}) "
                f"ahead of database ({db_count}). "
                "The database was restored from an older snapshot."
            )
        if db_count > ext_count:
            return
        if force_reinit:
            return
        db_root = self.get_verification_digest()
        if isinstance(db_root, bytes):
            db_root = db_root.hex()
        if db_root != ext_root:
            raise RuntimeError(
                f"ROLLBACK_DETECTED: Merkle root mismatch at count {db_count}. "
                f"External: {ext_root}, DB: {db_root}."
            )

    def _migrate_merkle_anchor_table(self):
        cursor = self.conn.cursor()
        cursor.execute(f"PRAGMA table_info({self.MERKLE_ANCHOR_TABLE})")
        columns = [col[1] for col in cursor.fetchall()]
        if 'key_version' not in columns:
            cursor.execute(
                f"ALTER TABLE {self.MERKLE_ANCHOR_TABLE} ADD COLUMN key_version INTEGER NOT NULL DEFAULT 0"
            )
            self.conn.commit()

    def _migrate_sys_cache_v8_profile_score(self):
        """V8: migrate profile_score + avatar_url columns, auto-adds missing columns."""
        self._init_sys_cache()
        if self.verbose:
            print("[V8] sys_cache schema ensured (profile_score + avatar_url)")

    def _init_sys_cache(self):
        """Ensure all V8 columns exist — idempotent per-column ADD IF NOT EXISTS via ALTER."""
        cursor = self.conn.cursor()
        cursor.execute(f"PRAGMA table_info({self.AUX_TABLE})")
        columns = {col[1] for col in cursor.fetchall()}
        migrations = []
        if 'profile_score' not in columns:
            cursor.execute(
                f"ALTER TABLE {self.AUX_TABLE} ADD COLUMN profile_score REAL NOT NULL DEFAULT 0.0"
            )
            self.conn.commit()
            migrations.append("profile_score")
        if 'avatar_url' not in columns:
            cursor.execute(
                f"ALTER TABLE {self.AUX_TABLE} ADD COLUMN avatar_url TEXT NOT NULL DEFAULT ''"
            )
            self.conn.commit()
            migrations.append("avatar_url")
        if migrations and self.verbose:
            print(f"[V8] sys_cache schema migration: {migrations}")

    def _create_merkle_anchor_table(self):
        cursor = self.conn.cursor()
        cursor.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {self.MERKLE_ANCHOR_TABLE} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sequence_number INTEGER NOT NULL,
                merkle_root TEXT NOT NULL,
                anchor_mac BLOB NOT NULL,
                anchor_hash BLOB NOT NULL,
                prev_anchor_hash BLOB NOT NULL,
                key_version INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        self.conn.commit()

    def _create_event_mac_table(self):
        cursor = self.conn.cursor()
        cursor.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {self.EVENT_MAC_TABLE} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sequence_number INTEGER NOT NULL UNIQUE,
                event_mac BLOB NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        self.conn.commit()

    def _ensure_channel_quality_table(self):
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sys_channel_quality (
                slot_idx INTEGER NOT NULL,
                channel INTEGER NOT NULL,
                erasure_pct REAL NOT NULL DEFAULT 0.0,
                sample_count INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (slot_idx, channel)
            )
        """)
        self.conn.commit()

    def _compute_event_mac(self, sequence_number: int, event_msg: str) -> bytes:
        payload = struct.pack(">I", sequence_number) + event_msg.encode("utf-8")
        return hmac.new(self.k_hmac, payload, hashlib.sha256).digest()

    def verify_event_mac(self, sequence_number: int) -> dict:
        cursor = self.conn.cursor()
        cursor.execute(
            f"SELECT event_mac FROM {self.EVENT_MAC_TABLE} WHERE sequence_number=?",
            (sequence_number,),
        )
        row = cursor.fetchone()
        if not row:
            return {"sequence_number": sequence_number, "valid": False, "error": "MAC tag not found"}
        stored_mac = row[0]
        cursor.execute(
            f"SELECT event_msg FROM {self.VISIBLE_LOG_TABLE} WHERE sequence_number=?",
            (sequence_number,),
        )
        msg_row = cursor.fetchone()
        if not msg_row:
            return {"sequence_number": sequence_number, "valid": False, "error": "Event not in audit_log"}
        expected = self._compute_event_mac(sequence_number, msg_row[0])
        valid = hmac.compare_digest(stored_mac, expected)
        return {"sequence_number": sequence_number, "valid": valid}

    def verify_all_event_macs(self) -> list:
        cursor = self.conn.cursor()
        cursor.execute(f"SELECT sequence_number FROM {self.EVENT_MAC_TABLE} ORDER BY sequence_number")
        seqs = [row[0] for row in cursor.fetchall()]
        return [self.verify_event_mac(s) for s in seqs]

    def _compute_anchor_mac(self, sequence_number: int, merkle_root: str) -> bytes:
        payload = struct.pack(">I", sequence_number) + merkle_root.encode("utf-8")
        return hmac.new(self._k_write_merkle, payload, hashlib.sha256).digest()

    def _compute_anchor_hash(self, sequence_number: int, merkle_root: str, prev_anchor_hash: bytes) -> bytes:
        payload = (
            struct.pack(">I", sequence_number)
            + merkle_root.encode("utf-8")
            + prev_anchor_hash
        )
        return hmac.new(self.k_hmac, payload, hashlib.sha256).digest()

    def anchor_merkle_root(self, sequence_number: int = None) -> dict:
        cursor = self.conn.cursor()
        cursor.execute(f"SELECT MAX(sequence_number) FROM {self.VISIBLE_LOG_TABLE}")
        max_seq = cursor.fetchone()[0]
        if max_seq is None:
            return {"error": "No events logged yet"}
        seq = sequence_number if sequence_number is not None else max_seq
        if seq > max_seq:
            seq = max_seq
        merkle_root = self.get_verification_digest()
        cursor.execute(
            f"SELECT anchor_hash FROM {self.MERKLE_ANCHOR_TABLE} ORDER BY id DESC LIMIT 1"
        )
        prev_row = cursor.fetchone()
        prev_hash = prev_row[0] if prev_row else b"\x00" * 32
        anchor_mac = self._compute_anchor_mac(seq, merkle_root)
        anchor_hash = self._compute_anchor_hash(seq, merkle_root, prev_hash)
        cursor.execute(
            f"""
            INSERT INTO {self.MERKLE_ANCHOR_TABLE}
                (sequence_number, merkle_root, anchor_mac, anchor_hash, prev_anchor_hash, key_version)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (seq, merkle_root, anchor_mac, anchor_hash, prev_hash, self._key_evolve_count),
        )
        self.conn.commit()
        anchor_id = cursor.lastrowid
        result = {
            "id": anchor_id,
            "sequence_number": seq,
            "merkle_root": merkle_root,
            "anchor_mac": anchor_mac.hex(),
            "anchor_hash": anchor_hash.hex(),
            "prev_anchor_hash": prev_hash.hex(),
            "key_version": self._key_evolve_count,
        }
        if self.verbose:
            print(f"[V7 ANCHOR] Merkle root anchored at id={anchor_id}, seq={seq}, kv={self._key_evolve_count}: {merkle_root[:16]}...")
        return result

    def _get_k_merkle_at_version(self, target_evolve_count: int) -> bytes:
        k = hmac.new(self.k_merkle, b"forward_merkle_v7", hashlib.sha256).digest()
        for _ in range(target_evolve_count):
            k = hmac.new(k, b"evolve", hashlib.sha256).digest()
        return k

    def verify_merkle_root(self, anchor_id: int = None) -> dict:
        cursor = self.conn.cursor()
        if anchor_id is not None:
            cursor.execute(
                f"SELECT id, sequence_number, merkle_root, anchor_mac, anchor_hash, prev_anchor_hash, key_version FROM {self.MERKLE_ANCHOR_TABLE} WHERE id=?",
                (anchor_id,),
            )
        else:
            cursor.execute(
                f"SELECT id, sequence_number, merkle_root, anchor_mac, anchor_hash, prev_anchor_hash, key_version FROM {self.MERKLE_ANCHOR_TABLE} ORDER BY id DESC LIMIT 1"
            )
        row = cursor.fetchone()
        if not row:
            return {"error": "No anchor found", "valid": False}
        anchor_id, seq, stored_root, stored_mac, stored_hash, stored_prev, anchor_kv = row
        current_root = self.get_verification_digest()
        # Evolve k_merkle back to the anchor's key_version for MAC verification
        k_merkle_at_anchor = self._get_k_merkle_at_version(anchor_kv)
        expected_mac = hmac.new(k_merkle_at_anchor, struct.pack(">I", seq) + stored_root.encode("utf-8"), hashlib.sha256).digest()
        mac_ok = hmac.compare_digest(stored_mac, expected_mac)
        cursor.execute(
            f"SELECT anchor_hash FROM {self.MERKLE_ANCHOR_TABLE} WHERE id < ? ORDER BY id DESC LIMIT 1",
            (anchor_id,),
        )
        actual_prev = cursor.fetchone()
        actual_prev_hash = actual_prev[0] if actual_prev else b"\x00" * 32
        chain_ok = hmac.compare_digest(stored_prev, actual_prev_hash)
        expected_hash = self._compute_anchor_hash(seq, stored_root, stored_prev)
        hash_ok = hmac.compare_digest(stored_hash, expected_hash)
        root_match = current_root == stored_root
        is_latest = True
        cursor.execute(
            f"SELECT COUNT(*) FROM {self.MERKLE_ANCHOR_TABLE} WHERE id > ?",
            (anchor_id,),
        )
        if cursor.fetchone()[0] > 0:
            is_latest = False
        return {
            "id": anchor_id,
            "sequence_number": seq,
            "stored_root": stored_root,
            "current_root": current_root,
            "root_match": root_match,
            "is_latest": is_latest,
            "mac_valid": mac_ok,
            "chain_valid": chain_ok,
            "hash_valid": hash_ok,
            "authentic": mac_ok and chain_ok and hash_ok,
            "valid": (root_match or not is_latest) and mac_ok and chain_ok and hash_ok,
        }

    def list_merkle_anchors(self, limit: int = 10) -> list:
        cursor = self.conn.cursor()
        cursor.execute(
            f"SELECT id, sequence_number, merkle_root, created_at FROM {self.MERKLE_ANCHOR_TABLE} ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        return [
            {
                "id": row[0],
                "sequence_number": row[1],
                "merkle_root": row[2],
                "created_at": row[3],
            }
            for row in cursor.fetchall()
        ]

    def get_merkle_anchor(self, anchor_id: int) -> dict:
        cursor = self.conn.cursor()
        cursor.execute(
            f"SELECT id, sequence_number, merkle_root, anchor_mac, anchor_hash, prev_anchor_hash, key_version, created_at FROM {self.MERKLE_ANCHOR_TABLE} WHERE id=?",
            (anchor_id,),
        )
        row = cursor.fetchone()
        if not row:
            return {"error": f"Anchor id={anchor_id} not found"}
        return {
            "id": row[0],
            "sequence_number": row[1],
            "merkle_root": row[2],
            "anchor_mac": row[3].hex(),
            "anchor_hash": row[4].hex(),
            "prev_anchor_hash": row[5].hex(),
            "key_version": row[6],
            "created_at": row[7],
        }

    def _rebuild_sys_cache_manifest(self):
        cursor = self.conn.cursor()
        cursor.execute(f"DELETE FROM {self.AUX_MANIFEST_TABLE}")
        cursor.execute(
            f"SELECT id, bio, trust_score, profile_score, avatar_url FROM {self.AUX_TABLE} ORDER BY id ASC"
        )
        manifest_rows = []
        for row in cursor.fetchall():
            row_id = row[0]
            bio = row[1]
            trust_score = row[2]
            profile_score_val = row[3] if len(row) > 3 and row[3] is not None else 0.0
            avatar_url = row[4] if len(row) > 4 and row[4] is not None else ""
            if bio is None or trust_score is None:
                continue
            manifest_rows.append(
                (row_id, self._sys_cache_row_mac(row_id, bio, trust_score, profile_score_val, avatar_url))
            )
        if manifest_rows:
            cursor.executemany(
                f"INSERT OR REPLACE INTO {self.AUX_MANIFEST_TABLE} (id, row_mac) VALUES (?, ?)",
                manifest_rows,
            )
        self.conn.commit()

    def _secure_shuffle(self, items):
        """Shuffle items using HMAC."""
        def get_hash(item):
            return hmac.new(self.k_shuffling, str(item).encode('utf-8'), hashlib.sha256).digest()
        return sorted(items, key=get_hash)

    def _select_ecc_symbols(self, msg_len, total_available_rows, per_channel=False, min_nsym=0):
        """Select RS parity symbols that fit available capacity.

        ``total_available_rows`` is the total per-channel capacity across all
        slots.  ``per_slot_rows = total_available_rows // SLOT_COUNT`` is used
        for fragment-fitting calculations.
        """
        start_nsym = self.ecc_symbols + min_nsym
        if per_channel:
            per_ch_rows = total_available_rows
            best_1_frag_rep2 = 0
            best_1_frag_any = 0
            best_multi_rep2 = 0
            best_multi_any = 0
            for nsym in range(start_nsym, 1, -2):
                min_rep = self._per_channel_min_repetitions(msg_len, nsym, per_ch_rows)
                if min_rep < 1:
                    continue

                payload_bits = (16 + msg_len) * 8
                data_encoded_lens = []
                for c in range(self.DATA_CHANNEL_COUNT):
                    ch_nbits = (payload_bits + self.DATA_CHANNEL_COUNT - 1 - c) // self.DATA_CHANNEL_COUNT
                    ch_bytes = self._bits_to_bytes([0] * ch_nbits)
                    try:
                        enc = RSCodec(nsym).encode(ch_bytes)
                    except Exception:
                        enc = None
                    if enc is None:
                        data_encoded_lens = None
                        break
                    data_encoded_lens.append(len(enc))
                if data_encoded_lens is None:
                    continue

                parity_source_len = max(data_encoded_lens) if data_encoded_lens else 0
                try:
                    p_enc = RSCodec(nsym).encode(b"\x00" * parity_source_len) if parity_source_len > 0 else b""
                except Exception:
                    continue
                try:
                    q_enc = RSCodec(nsym).encode(b"\x00" * parity_source_len) if parity_source_len > 0 else b""
                except Exception:
                    continue
                max_enc_len = max(max(data_encoded_lens), len(p_enc), len(q_enc))

                max_ch_bits_per_slot = per_ch_rows // max(1, min_rep)
                max_ch_bytes_per_slot = max(1, max_ch_bits_per_slot // 8)
                fragment_count = math.ceil(max_enc_len / max_ch_bytes_per_slot) if max_ch_bytes_per_slot > 0 else float('inf')

                if fragment_count > self.SLOT_COUNT:
                    continue

                fits_1_frag = fragment_count <= 1
                has_rep2 = min_rep >= 2

                if fits_1_frag and has_rep2:
                    if best_1_frag_rep2 == 0:
                        best_1_frag_rep2 = nsym
                elif fits_1_frag:
                    if best_1_frag_any == 0:
                        best_1_frag_any = nsym
                elif has_rep2:
                    if best_multi_rep2 == 0:
                        best_multi_rep2 = nsym
                elif best_multi_any == 0:
                    best_multi_any = nsym
            result = best_1_frag_rep2 or best_1_frag_any or best_multi_rep2 or best_multi_any
            return result if result > 0 else min(self.ecc_symbols, per_ch_rows // 8)

        for nsym in range(start_nsym, 1, -2):
            total_bits = (16 + msg_len + nsym) * 8
            repetitions = self._get_dynamic_repetitions(total_bits, total_available_rows)
            if repetitions >= self.MIN_BIT_REPETITIONS:
                return nsym
        return self.ecc_symbols

    def _per_channel_min_repetitions(self, msg_len: int, nsym: int, available_rows: int) -> int:
        """Minimum repetitions for per-channel RS (3 data + 2 parity)."""
        payload_bits = (16 + msg_len) * 8
        min_rep = self.MAX_BIT_REPETITIONS
        data_encoded = []
        for c in range(self.DATA_CHANNEL_COUNT):
            n_bits = (payload_bits + self.DATA_CHANNEL_COUNT - 1 - c) // self.DATA_CHANNEL_COUNT
            ch_bytes = self._bits_to_bytes([0] * n_bits)
            try:
                encoded = RSCodec(nsym).encode(ch_bytes)
            except Exception:
                return 0
            data_encoded.append(encoded)
            try:
                rep = self._get_dynamic_repetitions(len(encoded) * 8, available_rows)
            except ValueError:
                return 0
            min_rep = min(min_rep, rep)
        parity_source = max(len(e) for e in data_encoded) if data_encoded else 0
        # Both P and Q parity channels have the same source length
        for _ in range(2):  # P and Q
            try:
                parity_encoded = RSCodec(nsym).encode(b"\x00" * parity_source) if parity_source > 0 else b""
            except Exception:
                return 0
            try:
                parity_rep = self._get_dynamic_repetitions(len(parity_encoded) * 8, available_rows)
            except ValueError:
                return 0
            min_rep = min(min_rep, parity_rep)
        return min_rep

    def _maybe_heartbeat(self):
        if self.metronome_interval <= 0:
            return
        now = time.time()
        if now - self._last_heartbeat_time >= self.metronome_interval:
            self._last_heartbeat_beat += 1
            self._last_heartbeat_time = now
            self.log_event(f"[METRONOME] beat={self._last_heartbeat_beat}")
            with self._write_gate(immediate_commit=False):
                self._save_metronome_state()

    def detect_truncation(self, recovered_events: list = None) -> list:
        if recovered_events is None:
            recovered_events = self.recover_events()
        beats = [(seq, msg) for seq, msg in recovered_events if msg.startswith("[METRONOME]")]
        if len(beats) < 2:
            return []
        gaps = []
        for i in range(1, len(beats)):
            prev_seq, prev_msg = beats[i - 1]
            curr_seq, curr_msg = beats[i]
            try:
                prev_beat = int(prev_msg.split("beat=")[1])
                curr_beat = int(curr_msg.split("beat=")[1])
                if curr_beat - prev_beat > 1:
                    expected = curr_beat - prev_beat - 1
                    gaps.append({
                        "from_seq": prev_seq,
                        "to_seq": curr_seq,
                        "from_beat": prev_beat,
                        "to_beat": curr_beat,
                        "missing_beats": expected,
                    })
            except (IndexError, ValueError):
                continue
        return gaps

    def _scan_slots(self, cursor):
        """Scan all slots and return sorted [(slot_idx, seq)]."""
        if self._cached_slot_sequences is not None:
            return self._cached_slot_sequences
        self._header_dead_carrier_cache.clear()
        orig_ids = self._orig_ids
        slot_sequences = []
        for k in range(self.SLOT_COUNT):
            slot_start = k * self.SLOT_SIZE
            slot_ids = orig_ids[slot_start : slot_start + self.SLOT_SIZE]
            header_ids = slot_ids[:self.HEADER_BIT_COUNT]

            h_bits = []
            for rid in header_ids:
                cursor.execute(f"SELECT bio, trust_score, profile_score, avatar_url FROM {self.AUX_TABLE} WHERE id=?", (rid,))
                res = cursor.fetchone()
                if res and res[0] is not None and res[1] is not None:
                    h_bits.append(self._decode_header_bit(rid, res[0], res[1], profile_score=res[2], avatar_url=res[3]))
                else:
                    h_bits.append(0)

            perm = self._get_header_bit_permutation(k)
            h_bits = [h_bits[perm[i]] for i in range(len(h_bits))]

            header_data = self._decode_header(h_bits, k)
            slot_sequences.append((k, header_data["sequence_number"] if header_data else 0))

        slot_sequences.sort(key=lambda x: x[1])
        self._cached_slot_sequences = slot_sequences
        return slot_sequences

    def _prepare_event(self, event_msg, new_seq, prev_hash, min_nsym=0, min_repetitions=1):
        """Encode an event: compress, MAC, RS-encode. Returns (channel_blocks, stored_msg_bytes, store_compressed, selected_nsym, mac)."""
        msg_bytes = event_msg.encode("utf-8")
        compressed_bytes = zlib.compress(msg_bytes, level=9)
        store_compressed = len(compressed_bytes) < len(msg_bytes)
        stored_msg_bytes = compressed_bytes if store_compressed else msg_bytes
        mac = hmac.new(self.k_hmac, stored_msg_bytes, hashlib.sha256).digest()[:16]
        payload_bytes = mac + stored_msg_bytes

        payload_rows = self.SLOT_SIZE - self.HEADER_BIT_COUNT
        rows_for_ecc = payload_rows
        ecc_plan_len = len(stored_msg_bytes)

        if len(stored_msg_bytes) >= 200:
            bits_per_fragment = payload_rows // max(self.PER_CHANNEL_MIN_BIT_REPETITIONS, 1)
            ecc_plan_len = max(8, min(len(stored_msg_bytes), max(1, bits_per_fragment // 8 - 16)))

        selected_nsym = self._select_ecc_symbols(ecc_plan_len, rows_for_ecc, per_channel=True, min_nsym=min_nsym)
        self._current_min_repetitions = min_repetitions
        channel_blocks = self._encode_payload_per_channel_v7(payload_bytes, selected_nsym)
        return channel_blocks, stored_msg_bytes, store_compressed, selected_nsym, mac

    def _write_event_to_slots(self, cursor, channel_blocks, stored_msg_bytes, selected_nsym, new_seq, store_compressed, slot_sequences):
        """Write an event's encoded data to its replica slots. Returns replica_slots list."""
        active_seqs = set(seq for _, seq in slot_sequences if seq > 0)
        active_count = len(active_seqs)
        max_replicas = max(1, self.SLOT_COUNT // max(1, active_count + 1))
        replica_count = min(self.REPLICA_COUNT, max_replicas, len(slot_sequences))
        replica_slots = [slot_idx for slot_idx, _ in slot_sequences[:replica_count]]

        if self.verbose:
            print(f"[V8] Writing sequence {new_seq} to {replica_count} replica(s) (nsym={selected_nsym})")

        for replica_idx in range(replica_count):
            target_slot = replica_slots[replica_idx]
            slot_start = target_slot * self.SLOT_SIZE
            slot_ids = self._orig_ids[slot_start : slot_start + self.SLOT_SIZE]
            slot_payload_ids = slot_ids[self.HEADER_BIT_COUNT :]
            header_ids = slot_ids[: self.HEADER_BIT_COUNT]

            self._write_sys_cache_slot_v8(cursor, channel_blocks, slot_payload_ids)
            header_bytes = self._build_legacy_header(
                len(stored_msg_bytes), selected_nsym, new_seq, store_compressed, target_slot
            )
            self._write_header_bits_to_slot(cursor, header_bytes, header_ids, slot_idx=target_slot)
        return replica_slots

    def _recover_single_slot(self, cursor, slot_idx: int):
        """Attempt to recover the payload from a single slot.

        Returns ``(stored_msg_bytes, compressed, nsym, seq)`` on success,
        or ``None`` if the slot cannot be decoded.  This is a lightweight
        wrapper around the existing per-slot recovery logic used by
        ``_recover_from_aux`` — it re-uses the same header-decode and
        channel-extraction path without touching any other slot.
        """
        slot_start = slot_idx * self.SLOT_SIZE
        slot_ids = self._orig_ids[slot_start : slot_start + self.SLOT_SIZE]
        header_ids = slot_ids[: self.HEADER_BIT_COUNT]
        slot_payload_ids = slot_ids[self.HEADER_BIT_COUNT :]

        # --- Decode header ---
        h_bits = []
        for rid in header_ids:
            cursor.execute(
                f"SELECT bio, trust_score, profile_score, avatar_url FROM {self.AUX_TABLE} WHERE id=?",
                (rid,),
            )
            res = cursor.fetchone()
            if res and res[0] is not None and res[1] is not None:
                h_bits.append(self._decode_header_bit(rid, res[0], res[1], profile_score=res[2], avatar_url=res[3]))
            else:
                h_bits.append(0)

        perm = self._get_header_bit_permutation(slot_idx)
        h_bits = [h_bits[perm[i]] for i in range(len(h_bits))]
        header_data = self._decode_header(h_bits, slot_idx)
        if not header_data:
            return None

        nsym = header_data["nsym"]
        seq = header_data["sequence_number"]
        payload_len = header_data.get("payload_len", 0)
        compressed = header_data.get("compressed", False)

        # --- Extract channels ---
        enc_bit_counts = self._per_channel_rs_encoded_bit_count(payload_len, nsym)
        max_bits = max(enc_bit_counts[c] for c in range(self.CHANNEL_COUNT)) if enc_bit_counts else 0
        slot_channel_bytes, slot_erasures = self._extract_all_channels_v8(cursor, slot_payload_ids, max_bits)

        per_channel_encoded = {}
        for c in range(self.CHANNEL_COUNT):
            chunk = slot_channel_bytes.get(c, b"")
            expected_bytes = enc_bit_counts[c] // 8
            if chunk and len(chunk) >= expected_bytes:
                per_channel_encoded[c] = chunk[:expected_bytes]
            elif chunk:
                per_channel_encoded[c] = chunk
            else:
                per_channel_encoded[c] = b""

        # --- RS decode per channel ---
        channel_plain = {}
        for c in range(self.CHANNEL_COUNT):
            enc_data = per_channel_encoded.get(c, b"")
            if not enc_data:
                continue
            erasures = [p for p in slot_erasures.get(c, []) if p < len(enc_data)]
            try:
                dec = RSCodec(nsym).decode(enc_data, erase_pos=erasures)
                channel_plain[c] = dec[0] if isinstance(dec, tuple) else dec
            except ReedSolomonError:
                pass

        # --- RAID-6 parity recovery ---
        pq_recovered = self._recover_from_pq_parity(channel_plain, nsym, slot_erasures)
        if pq_recovered:
            channel_plain.update(pq_recovered)

        if len(channel_plain) < self.DATA_CHANNEL_COUNT:
            return None

        # --- HMAC verification ---
        payload_bytes = self._rebuild_payload_from_channel_bytes(channel_plain, payload_len)
        if payload_bytes is None or len(payload_bytes) < 16:
            return None
        recovered_mac = payload_bytes[:16]
        maybe_msg = payload_bytes[16:]
        expected_mac = hmac.new(self.k_hmac, maybe_msg, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(recovered_mac, expected_mac):
            return None

        return maybe_msg, compressed, nsym, seq

    def _migrate_slot(self, slot_idx: int) -> bool:
        """Proactive Self-Healing: recover a degraded slot and rewrite it with
        boosted ECC parameters.

        Strategy
        --------
        1. Recover the current payload via ``_recover_single_slot``.
        2. Compute rebuild nsym = max(adaptive_nsym + 8, ECC_REBUILD_NSYM),
           capped against actual slot capacity.
        3. Re-encode and rewrite the slot via ``_write_sys_cache_slot_v8``
           (bypasses the event pipeline — key-state / counter / Merkle are
           untouched).
        4. Invalidate the slot header so the next ``log_event`` overwrites it
           cleanly (prevents stale-header confusion).
        5. Log a ``[GHOST_REBUILD]`` audit event for forensic transparency.

        Returns ``True`` on success, ``False`` on unrecoverable failure
        (a ``[GHOST_REBUILD_FAILED]`` event is logged in that case).
        """
        if self.verbose:
            print(f"[GHOST_REBUILD] Starting slot {slot_idx} migration …")

        cursor = self.conn.cursor()

        # Step 1 — recover
        result = self._recover_single_slot(cursor, slot_idx)
        if result is None:
            # Unrecoverable — document the loss as a full audit event
            fail_msg = f"[GHOST_REBUILD_FAILED] slot={slot_idx} carrier_total_loss=True"
            if self.verbose:
                print(f"[GHOST_REBUILD] {fail_msg}")
            try:
                self.log_event(fail_msg)
            except Exception as exc:
                if self.verbose:
                    print(f"[GHOST_REBUILD] Could not log failure event: {exc}")
            return False

        stored_msg_bytes, compressed, current_nsym, seq = result

        # Step 2 — compute boosted nsym
        history = self._get_channel_quality(slot_idx)
        adaptive_nsym = 0
        if history:
            degradation = history
            adaptive_nsym = self._degradation_to_params(degradation).get("min_nsym", 0)
        # Always at least ECC_REBUILD_NSYM, always at least adaptive + 8
        target_nsym = max(adaptive_nsym + 8, ECC_REBUILD_NSYM)
        # Cap against slot capacity: payload_rows // 8 is a rough upper bound
        payload_rows = self.SLOT_SIZE - self.HEADER_BIT_COUNT
        max_nsym_for_slot = max(1, payload_rows // 8)
        rebuild_nsym = min(target_nsym, max_nsym_for_slot)
        rebuild_reps = max(ECC_REBUILD_REPS, self._current_min_repetitions)

        if self.verbose:
            print(
                f"[GHOST_REBUILD] slot={slot_idx} seq={seq} "
                f"old_nsym={current_nsym} rebuild_nsym={rebuild_nsym} "
                f"rebuild_reps={rebuild_reps}"
            )

        # Step 3 — re-encode with boosted parameters
        payload_bytes_full = hmac.new(self.k_hmac, stored_msg_bytes, hashlib.sha256).digest()[:16] + stored_msg_bytes
        self._current_min_repetitions = rebuild_reps
        channel_blocks = self._encode_payload_per_channel_v7(payload_bytes_full, rebuild_nsym)

        slot_start = slot_idx * self.SLOT_SIZE
        slot_ids = self._orig_ids[slot_start : slot_start + self.SLOT_SIZE]
        slot_payload_ids = slot_ids[self.HEADER_BIT_COUNT :]
        header_ids = slot_ids[: self.HEADER_BIT_COUNT]

        with self._write_gate(immediate_commit=False):
            self._write_sys_cache_slot_v8(cursor, channel_blocks, slot_payload_ids)

            # Step 4 — rewrite header with updated nsym/reps
            header_bytes = self._build_legacy_header(
                len(stored_msg_bytes), rebuild_nsym, seq, compressed, slot_idx
            )
            self._write_header_bits_to_slot(cursor, header_bytes, header_ids, slot_idx=slot_idx)
            self.conn.commit()

        # Step 5 — forensic audit event (outside the gate, uses normal log_event)
        rebuild_msg = (
            f"[GHOST_REBUILD] slot={slot_idx} seq={seq} "
            f"old_nsym={current_nsym} new_nsym={rebuild_nsym} reps={rebuild_reps}"
        )
        try:
            self.log_event(rebuild_msg)
        except Exception as exc:
            if self.verbose:
                print(f"[GHOST_REBUILD] Could not log rebuild event: {exc}")

        if self.verbose:
            print(f"[GHOST_REBUILD] slot={slot_idx} migration complete.")
        return True

    def _idle_restore_check(self) -> None:
        """Heuristic: scan sys_channel_quality and trigger _migrate_slot for
        degraded slots.

        Called from ``log_event()`` outside the write gate, rate-limited to
        once every ``REBUILD_CHECK_INTERVAL`` events so audit throughput is
        not impacted.  Only slots whose worst-channel degradation exceeds
        ``REBUILD_DEGRADATION_THRESHOLD`` are rebuilt.
        """
        self._log_event_count += 1
        if self._log_event_count % REBUILD_CHECK_INTERVAL != 0:
            return

        if self.verbose:
            print(f"[GHOST_REBUILD] Idle restore check (event #{self._log_event_count}) …")

        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT slot_idx, MAX(erasure_pct) as worst FROM sys_channel_quality GROUP BY slot_idx"
        )
        rows = cursor.fetchall()
        for slot_idx, worst_pct in rows:
            if worst_pct is not None and worst_pct >= REBUILD_DEGRADATION_THRESHOLD:
                if self.verbose:
                    print(
                        f"[GHOST_REBUILD] slot={slot_idx} worst_degradation={worst_pct:.2f} "
                        f">= threshold={REBUILD_DEGRADATION_THRESHOLD} → triggering rebuild"
                    )
                self._migrate_slot(slot_idx)

    def log_event(self, event_msg, immediate_commit=True):
        """Log a single audit event. Delegates to log_events() for correct carrier writes."""
        result = self.log_events([event_msg], immediate_commit=immediate_commit)
        # log_events returns a list of sequence numbers; unwrap to a single value
        if result and isinstance(result, list):
            return result[0]
        return result

    def log_events(self, event_msgs, immediate_commit=True):

        """Batch-log multiple events with a single header scan + commit."""
        if self.metronome_interval > 0:
            now = time.time()
            if now - self._last_heartbeat_time >= self.metronome_interval:
                self._last_heartbeat_beat += 1
                self._last_heartbeat_time = now
                event_msgs = [f"[METRONOME] beat={self._last_heartbeat_beat}"] + list(event_msgs)
        cursor = self.conn.cursor()
        slot_sequences = self._scan_slots(cursor)
        if getattr(self, '_process_count', 1) > 1:
            n = len(event_msgs)
            cursor.execute("UPDATE sys_sequence_counter SET next_seq = next_seq + ? WHERE id = 1", (n,))
            cursor.execute("SELECT next_seq - ? FROM sys_sequence_counter WHERE id = 1", (n,))
            base_seq = cursor.fetchone()[0]
        else:
            cursor.execute(f"SELECT COALESCE(MAX(sequence_number), 0) FROM {self.VISIBLE_LOG_TABLE}")
            base_seq = cursor.fetchone()[0] + 1

        cursor.execute(
            f"SELECT sequence_number, entry_hash FROM {self.VISIBLE_LOG_TABLE} ORDER BY sequence_number DESC LIMIT 1"
        )
        prev_visible_row = cursor.fetchone()
        prev_hash = prev_visible_row[1] if prev_visible_row else b"\x00" * 32

        prepared = []
        active_seqs = set(seq for _, seq in slot_sequences if seq > 0)
        active_count = len(active_seqs)
        max_replicas = max(1, self.SLOT_COUNT // max(1, active_count + 1))
        replica_count = min(self.REPLICA_COUNT, max_replicas, len(slot_sequences))
        target_slots = [slot_idx for slot_idx, _ in slot_sequences[:replica_count]]
        first_slot = target_slots[0] if target_slots else 0
        slot_start = first_slot * self.SLOT_SIZE
        slot_ids = self._orig_ids[slot_start : slot_start + self.SLOT_SIZE]
        slot_payload_ids = slot_ids[self.HEADER_BIT_COUNT:]

        history = self._get_channel_quality(first_slot)
        probe = self._probe_carrier_integrity(cursor, slot_payload_ids)
        if history is not None:
            degradation = {c: max(probe[c], history.get(c, 0.0)) for c in range(self.CHANNEL_COUNT)}
        else:
            degradation = probe
            degradation[2] = 0.0
            degradation[4] = 0.0
        params = self._degradation_to_params(degradation)

        if self.verbose and params["min_nsym"] > 0:
            print(f"[V8 ADAPT] batch degradation={max(degradation.values()):.2f} nsym_bump={params['min_nsym']} min_reps={params['min_reps']}")

        for i, msg in enumerate(event_msgs):
            new_seq = base_seq + i
            ch, stored, comp, nsym, mac = self._prepare_event(msg, new_seq, prev_hash, min_nsym=params["min_nsym"])
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
                    """
                    INSERT OR REPLACE INTO audit_log (
                        sequence_number, event_msg, stored_msg, compressed, mac, entry_hash, prev_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
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
                    anchor_result = self.anchor_merkle_root(sequence_number=new_seq)
                if hasattr(self, 'siem_export_path') and self.siem_export_path:
                    self._append_siem_event(new_seq, msg)
                self._key_evolve_count += 1
                self._k_write_merkle = hmac.new(self._k_write_merkle, b"evolve", hashlib.sha256).digest()

            cursor.execute(
                f"INSERT OR REPLACE INTO {self._key_state_table} (id, evolve_count) VALUES (?, ?)",
                (getattr(self, '_process_id', 0) + 1, self._key_evolve_count,),
            )
            if immediate_commit:
                # Two-phase external state (begin: before commit, finalize: after)
                mr = anchor_result.get("merkle_root", "") if isinstance(anchor_result, dict) else ""
                if mr:
                    self.external_state.begin_write(self._key_evolve_count, mr)
                self.conn.commit()
                if mr:
                    self.external_state.finalize(self._key_evolve_count, mr)
            if self.metronome_interval > 0:
                self._save_metronome_state()
        except Exception:
            self.conn.rollback()
            raise
        finally:
            self._set_sys_cache_write_mode(False, commit=immediate_commit)

        # Rate-limited self-healing check — runs outside the write gate
        # and only every REBUILD_CHECK_INTERVAL events.
        # Skip for internal rebuild/metronome events to avoid recursion.
        _skip_tags = ("[GHOST_REBUILD", "[METRONOME]")
        if not any(m.startswith(_skip_tags) for m in event_msgs):
            self._idle_restore_check()

        return [seq for _, seq, _, _, _, _, _, _ in prepared]

    def _recover_from_aux(self):
        """Recover events from sys_cache with V7 parity recovery."""
        self._header_dead_carrier_cache.clear()
        cursor = self.conn.cursor()
        orig_ids = self._orig_ids
        logs = []
        slot_quality = {}

        fragments_by_seq = {}

        for k in range(self.SLOT_COUNT):
            slot_start = k * self.SLOT_SIZE
            slot_ids = orig_ids[slot_start : slot_start + self.SLOT_SIZE]
            header_ids = slot_ids[: self.HEADER_BIT_COUNT]

            h_bits = []
            for rid in header_ids:
                cursor.execute(
                    f"SELECT bio, trust_score, profile_score, avatar_url FROM {self.AUX_TABLE} WHERE id=?",
                    (rid,),
                )
                res = cursor.fetchone()
                if (
                    res
                    and res[0] is not None
                    and res[1] is not None
                ):
                    h_bits.append(self._decode_header_bit(rid, res[0], res[1], profile_score=res[2], avatar_url=res[3]))
                else:
                    h_bits.append(0)

            perm = self._get_header_bit_permutation(k)
            h_bits = [h_bits[perm[i]] for i in range(len(h_bits))]

            header_data = self._decode_header(h_bits, k)
            if not header_data:
                continue

            seq = header_data["sequence_number"]
            fragments_by_seq.setdefault(seq, {})[k] = (
                header_data,
                slot_ids,
                h_bits,
            )

        # Cross-slot majority voting for header bits
        # If multiple slots claim the same seq, vote on raw header bits per position
        for seq in list(fragments_by_seq.keys()):
            frag_map = fragments_by_seq[seq]
            if len(frag_map) > 1:
                all_bits = [entry[2] for entry in frag_map.values()]
                merged = []
                for i in range(self.HEADER_BIT_COUNT):
                    votes = [bits[i] for bits in all_bits if i < len(bits)]
                    merged.append(max(set(votes), key=votes.count) if votes else 0)
                merged_hd = self._decode_header(merged, list(frag_map.keys())[0])
                if merged_hd and merged_hd["sequence_number"] == seq:
                    for k in frag_map:
                        hd, sid, _ = frag_map[k]
                        frag_map[k] = (merged_hd, sid, merged)

        # Recover per-sequence
        for seq in sorted(fragments_by_seq.keys()):
            frag_map = fragments_by_seq[seq]
            if not frag_map:
                continue

            # Always read metadata from the lowest available fragment index
            # so that the compressed-flag and fragment_count are correct even
            # when fragment 0 is missing.
            lowest_frag_idx = min(frag_map.keys())
            first_header = frag_map[lowest_frag_idx][0]
            expected_count = first_header["fragment_count"]
            nsym = first_header["nsym"]
            available_count = len(frag_map)
            is_partial = available_count < expected_count

            if self.verbose:
                print(
                    f"[V8 RECOVER] seq={seq} expected_fragments={expected_count} "
                    f"available={available_count} nsym={nsym}"
                    + (" [PARTIAL]" if is_partial else "")
                )

            # Compute expected RS-encoded bit count per channel
            enc_bit_counts = self._per_channel_rs_encoded_bit_count(
                first_header["payload_len"], nsym
            )

            # V8: single-pass multiplexed extraction for each fragment/slot
            per_channel_frags = {c: [] for c in range(self.CHANNEL_COUNT)}
            per_channel_frag_erasures = {c: [] for c in range(self.CHANNEL_COUNT)}
            for frag_idx in sorted(frag_map.keys()):
                header_data, slot_ids, _ = frag_map[frag_idx]
                slot_payload_ids = slot_ids[self.HEADER_BIT_COUNT:]

                max_bits = max(enc_bit_counts[c] for c in range(self.CHANNEL_COUNT)) if enc_bit_counts else 0
                slot_channel_bytes, slot_erasures = self._extract_all_channels_v8(
                    cursor, slot_payload_ids, max_bits
                )

                for c in range(self.CHANNEL_COUNT):
                    chunk = slot_channel_bytes.get(c, b"")
                    erasures = slot_erasures.get(c, [])
                    total = len(chunk)
                    if total > 0:
                        rate = len([p for p in erasures if p < total]) / total
                        slot_quality.setdefault(frag_idx, {}).setdefault(c, []).append(rate)

                for c in range(self.CHANNEL_COUNT):
                    chunk_bytes = slot_channel_bytes.get(c, b"")
                    erasures = slot_erasures.get(c, [])
                    expected_bytes = enc_bit_counts[c] // 8
                    if chunk_bytes and len(chunk_bytes) >= expected_bytes:
                        per_channel_frags[c].append(chunk_bytes[:expected_bytes])
                    elif chunk_bytes:
                        per_channel_frags[c].append(chunk_bytes)
                    else:
                        per_channel_frags[c].append(b"")
                    per_channel_frag_erasures[c].append(erasures)

                if self.verbose:
                    print(f"[V8 RECOVER] frag={frag_idx} bits_per_ch={enc_bit_counts}")

            # Reconstruct full RS codeword per channel (replica or fragment mode)
            per_channel_encoded = {}
            is_replica_mode = expected_count == 1 and len(per_channel_frags[0]) > 1
            pre_decoded = {}  # channels already decoded in individual pass
            for c in range(self.CHANNEL_COUNT):
                frags = per_channel_frags[c]
                if not frags or all(len(f) == 0 for f in frags):
                    per_channel_encoded[c] = b""
                    continue
                if is_replica_mode and len(frags) > 1:
                    # Try RS decode on each fragment individually first
                    single_ok = None
                    single_raw = None
                    for fi, single_frag in enumerate(frags):
                        if not single_frag:
                            continue
                        frag_erase_list = per_channel_frag_erasures.get(c, [])
                        fe = frag_erase_list[fi] if fi < len(frag_erase_list) else []
                        fe_filtered = [p for p in fe if p < len(single_frag)]
                        try:
                            dec = RSCodec(nsym).decode(single_frag, erase_pos=fe_filtered)
                            candidate = dec[0] if isinstance(dec, tuple) else dec
                            if candidate:
                                single_ok = candidate
                                single_raw = single_frag
                                if self.verbose:
                                    print(f"[V8 RECOVER] replica fragment={fi} channel={c} decoded individually")
                                break
                        except ReedSolomonError:
                            continue
                    if single_ok is not None:
                        pre_decoded[c] = single_ok
                        per_channel_encoded[c] = single_raw
                        if self.verbose:
                            print(f"[V8 RECOVER]  → using clean fragment raw data for channel={c}")
                        continue
                    # All fragments failed individually → byte-level merge fallback
                    target_len = max(len(f) for f in frags)
                    merged = bytearray(target_len)
                    for pos in range(target_len):
                        byte_votes = {}
                        for f in frags:
                            if pos < len(f):
                                bv = f[pos]
                                byte_votes[bv] = byte_votes.get(bv, 0) + 1
                        if byte_votes:
                            majority = max(byte_votes, key=byte_votes.get)
                            merged[pos] = majority
                    per_channel_encoded[c] = bytes(merged)
                    if self.verbose:
                        print(f"[V8 RECOVER] replica fallback (byte-merge) channel={c}")
                else:
                    concat = b"".join(frags)
                    expected_bytes = enc_bit_counts[c] // 8
                    if concat and len(concat) >= expected_bytes:
                        per_channel_encoded[c] = concat[:expected_bytes]
                    elif concat:
                        per_channel_encoded[c] = concat

            # Merge erasure positions across fragments
            per_channel_erasures = {c: [] for c in range(self.CHANNEL_COUNT)}
            if is_replica_mode:
                for c in range(self.CHANNEL_COUNT):
                    encoded = per_channel_encoded.get(c, b"")
                    if not encoded:
                        continue
                    n_frags = len(per_channel_frags[c])
                    for pos in range(len(encoded)):
                        zero_len = sum(1 for f in per_channel_frags[c] if pos >= len(f))
                        if zero_len > n_frags // 2:
                            per_channel_erasures[c].append(pos)
                    # Merge MAC-based fragment erasures (from _extract_all_channels_v8)
                    frag_erasures_list = per_channel_frag_erasures.get(c, [])
                    if frag_erasures_list:
                        for pos in range(len(encoded)):
                            erased = sum(1 for fe in frag_erasures_list if pos in fe)
                            if erased > n_frags // 2 and pos not in per_channel_erasures[c]:
                                per_channel_erasures[c].append(pos)
            else:
                for c in range(self.CHANNEL_COUNT):
                    offset = 0
                    for fi, frag_erasures in enumerate(per_channel_frag_erasures.get(c, [])):
                        for pos in frag_erasures:
                            per_channel_erasures[c].append(offset + pos)
                        if fi < len(per_channel_frags.get(c, [])):
                            offset += len(per_channel_frags[c][fi])

            if self.verbose:
                for c in range(self.CHANNEL_COUNT):
                    d = per_channel_encoded.get(c, b"")
                    print(f"[V8 RECOVER] channel={c} encoded_len={len(d)} expected_bytes={enc_bit_counts[c] // 8}")

            # Decode all channels via RS
            channel_plain = dict(pre_decoded)  # use pre-decoded data from individual decode
            for c in range(self.CHANNEL_COUNT):
                if c in pre_decoded:
                    continue  # already decoded in individual pass
                try:
                    enc_data = per_channel_encoded.get(c)
                    if enc_data and len(enc_data) > 0:
                        erasures = [p for p in per_channel_erasures.get(c, []) if p < len(enc_data)]
                        decoded = RSCodec(nsym).decode(
                            enc_data,
                            erase_pos=erasures,
                        )
                        channel_plain[c] = decoded[0] if isinstance(decoded, tuple) else decoded
                except ReedSolomonError as e:
                    if self.verbose:
                        print(f"[V8 RECOVER] RS decode failed for channel={c}: {e}")

            if self.verbose:
                print(f"[V8 RECOVER] channel_plain_keys={list(channel_plain.keys())}")

            # ----------------------------------------------------------------
            # Attempt full reconstruction from concatenated fragments
            # ----------------------------------------------------------------
            # RAID-6 recovery: try to reconstruct missing data channels
            # using P (XOR) and/or Q (GF(2^8)) parity.
            pq_recovered = self._recover_from_pq_parity(
                channel_plain, nsym, per_channel_erasures
            )
            if pq_recovered is not None:
                recovered_count = len(pq_recovered)
                for c, v in pq_recovered.items():
                    channel_plain[c] = v
                if self.verbose:
                    print(f"[V8 RECOVER] P+Q recovery: {recovered_count}/{self.CHANNEL_COUNT} channels OK")

            if len(channel_plain) < self.DATA_CHANNEL_COUNT:
                if is_partial:
                    logs.append((seq, f"[PARTIAL RECOVERY: {available_count}/{expected_count} fragments - RS decode failed]"))
                else:
                    logs.append((seq, "[TAMPERING DETECTED]"))
                continue

            # Try HMAC verification — first using header payload_len, then fallback sweep
            recovered_msg = None
            partial_msgs = []
            header_len = first_header.get("payload_len", 0)
            candidate_lengths = [header_len] if header_len > 0 else []
            candidate_lengths += [l for l in range(512, 0, -1) if l != header_len]
            for stored_msg_len in candidate_lengths:
                payload_bytes = self._rebuild_payload_from_channel_bytes(
                    channel_plain, stored_msg_len
                )
                if payload_bytes is None:
                    continue
                if len(payload_bytes) < 16:
                    continue
                recovered_mac = payload_bytes[:16]
                maybe_msg = payload_bytes[16:]
                expected_mac = hmac.new(
                    self.k_hmac, maybe_msg, hashlib.sha256
                ).digest()[:16]
                if hmac.compare_digest(recovered_mac, expected_mac):
                    try:
                        compressed = first_header["compressed"]
                        msg_body = (
                            zlib.decompress(maybe_msg) if compressed else maybe_msg
                        )
                        logs.append((seq, msg_body.decode("utf-8")))
                        recovered_msg = maybe_msg
                        break
                    except (UnicodeDecodeError, zlib.error):
                        continue

            if recovered_msg is None:
                logs.append((seq, "[TAMPERING DETECTED]"))

        known_seqs = {r[0] for r in cursor.execute(f"SELECT sequence_number FROM {self.VISIBLE_LOG_TABLE}").fetchall()}
        logs = [e for e in logs if e[0] in known_seqs]

        logs.sort(key=lambda x: x[0])

        self._set_sys_cache_write_mode(True)
        try:
            for slot_idx, channel_data in slot_quality.items():
                for channel, rates in channel_data.items():
                    avg_rate = sum(rates) / len(rates)
                    self._update_channel_quality(slot_idx, channel, avg_rate, len(rates))
        finally:
            self._set_sys_cache_write_mode(False)

        return logs

    def recover_events(self):
        """Recover all logged events from database."""
        return self._recover_from_aux()

    def _append_siem_event(self, sequence_number: int, event_msg: str):
        path = self.siem_export_path
        if not path:
            return
        fmt = self.siem_export_format
        try:
            with open(path, "a", encoding="utf-8") as f:
                if fmt == "jsonl":
                    entry = {
                        "sequence_number": sequence_number,
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "event": event_msg,
                        "system": "GhostAudit",
                        "version": "V7",
                    }
                    f.write(json.dumps(entry) + "\n")
                elif fmt == "cef":
                    timestamp = time.strftime("%b %d %H:%M:%S", time.gmtime())
                    line = f"{timestamp} GhostAudit V7:0|Security|AuditLogger|1.0|EVENT|{event_msg}|5|msg={event_msg} seq={sequence_number}\n"
                    f.write(line)
        except OSError as e:
            if self.verbose:
                print(f"[V7 SIEM] Write failed: {e}")

    def export_recovered_logs(self, target_path: str, format: str = "jsonl"):
        """
        Recover all logged events and export them in jsonl or cef format.
        """
        recovered = self.recover_events()
        format = format.lower()
        
        with open(target_path, "w", encoding="utf-8") as f:
            for idx, event_tuple in enumerate(recovered):
                # recover_logs() returns tuples (seq, message)
                seq, event_msg = event_tuple
                if format == "jsonl":
                    entry = {
                        "index": idx + 1,
                        "sequence_number": seq,
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "event": event_msg,
                        "system": "GhostAudit",
                        "version": "V7"
                    }
                    f.write(json.dumps(entry) + "\n")
                elif format == "cef":
                    # CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|[Extension]
                    timestamp = time.strftime("%b %d %H:%M:%S", time.gmtime())
                    cef_line = f"{timestamp} GhostAudit V7:0|Security|AuditLogger|1.0|EVENT_RECOVERED|{event_msg}|5|msg={event_msg} seq={seq}\n"
                    f.write(cef_line)
                else:
                    raise ValueError(f"Unsupported export format: {format}")
        if self.verbose:
            print(f"[V7 EXPORT] Successfully exported {len(recovered)} events to {target_path} in {format.upper()} format.")

    def get_verification_digest(self) -> str:
        """
        Calculate Merkle Root Hash over all 5 active slots.
        """
        cursor = self.conn.cursor()
        slot_hashes = []
        
        for k in range(self.SLOT_COUNT):
            slot_start = k * self.SLOT_SIZE
            slot_ids = self._orig_ids[slot_start : slot_start + self.SLOT_SIZE]
            
            placeholders = ",".join("?" * len(slot_ids))
            cursor.execute(
                f"SELECT bio, trust_score, avatar_url FROM {self.AUX_TABLE} WHERE id IN ({placeholders}) ORDER BY id",
                slot_ids,
            )
            rows = cursor.fetchall()

            # Hash the slot contents deterministically
            hasher = hashlib.sha256()
            for r in rows:
                hasher.update(r[0].encode("utf-8"))
                hasher.update(struct.pack(">d", r[1]))
                hasher.update((r[2] or "").encode("utf-8"))
            slot_hashes.append(hasher.digest())
        
        # Build a simple Merkle Tree
        while len(slot_hashes) > 1:
            next_level = []
            for i in range(0, len(slot_hashes), 2):
                if i + 1 < len(slot_hashes):
                    combined = hmac.new(self.k_hmac, slot_hashes[i] + slot_hashes[i+1], hashlib.sha256).digest()
                    next_level.append(combined)
                else:
                    combined = hmac.new(self.k_hmac, slot_hashes[i] + slot_hashes[i], hashlib.sha256).digest()
                    next_level.append(combined)
            slot_hashes = next_level
            
        return slot_hashes[0].hex() if slot_hashes else ""

    def export_checkpoint(self, path: str = None) -> dict:
        """Export a signed checkpoint for external verification.

        A checkpoint is a compact, self-contained JSON document that captures
        the current DB state at a specific sequence number.  It is designed to
        be stored in a read-only external location (git repo, separate file,
        pastebin, …) to act as an independent witness against rollback or
        wholesale-deletion attacks.

        What the checkpoint proves (with master key):
        - The Merkle root of sys_cache was exactly R at sequence number N.
        - The anchor chain was intact up to that point (prev_anchor_hash).
        - The event chain was intact up to that point (last entry_hash).
        - The checkpoint itself has not been tampered with (mac field).

        What the checkpoint does NOT prove (by design):
        - It does not prove the content of individual events without the key.
        - It does not replace the steganographic layer — it complements it.

        Verification later:  ga.verify_checkpoint(checkpoint_dict_or_path)

        Args:
            path: Optional file path to write the checkpoint JSON.
                  If None, the checkpoint is only returned as a dict.

        Returns:
            dict with keys: seq, root, entry_chain, anchor_chain,
                            timestamp, key_version, mac
        """
        cursor = self.conn.cursor()

        # --- Current sequence number ---
        cursor.execute(
            f"SELECT MAX(sequence_number) FROM {self.VISIBLE_LOG_TABLE}"
        )
        row = cursor.fetchone()
        seq = row[0] if row and row[0] is not None else 0

        # --- Current Merkle root (over sys_cache slots) ---
        root = self.get_verification_digest()

        # --- Last entry_hash from the event chain ---
        cursor.execute(
            f"SELECT entry_hash FROM {self.VISIBLE_LOG_TABLE} "
            f"ORDER BY sequence_number DESC LIMIT 1"
        )
        row = cursor.fetchone()
        entry_chain = row[0].hex() if row and row[0] else ("00" * 32)

        # --- Last anchor_hash from the anchor chain ---
        cursor.execute(
            f"SELECT anchor_hash FROM {self.MERKLE_ANCHOR_TABLE} "
            f"ORDER BY id DESC LIMIT 1"
        )
        row = cursor.fetchone()
        anchor_chain = row[0].hex() if row and row[0] else ("00" * 32)

        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        key_version = self._key_evolve_count

        # --- MAC over all checkpoint fields (prevents field-level tampering) ---
        mac_payload = (
            struct.pack(">I", seq)
            + root.encode("utf-8")
            + bytes.fromhex(entry_chain)
            + bytes.fromhex(anchor_chain)
            + timestamp.encode("utf-8")
            + struct.pack(">I", key_version)
        )
        mac = hmac.new(self.k_hmac, mac_payload, hashlib.sha256).digest().hex()

        checkpoint = {
            "ghost_audit_checkpoint": True,
            "version": "1.0",
            "seq": seq,
            "root": root,
            "entry_chain": entry_chain,
            "anchor_chain": anchor_chain,
            "timestamp": timestamp,
            "key_version": key_version,
            "mac": mac,
        }

        if path:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(checkpoint, f, indent=2)
            if self.verbose:
                print(f"[CHECKPOINT] Exported seq={seq} root={root[:16]}... → {path}")

        return checkpoint

    def verify_checkpoint(self, checkpoint, path: str = None) -> dict:
        """Verify a previously exported checkpoint against the current DB state.

        Accepts either a dict (as returned by export_checkpoint) or a file path
        to a JSON checkpoint file.

        Checks performed:
        1. MAC integrity  — checkpoint fields have not been tampered with.
        2. Root match     — stored root matches current get_verification_digest().
        3. Entry chain    — stored entry_chain matches last entry_hash in audit_log.
        4. Anchor chain   — stored anchor_chain matches last anchor_hash in merkle_anchor.

        Returns a dict with keys:
            valid (bool), mac_valid, root_match, entry_chain_match,
            anchor_chain_match, seq, root, timestamp, details (str)
        """
        if path is not None:
            with open(path, "r", encoding="utf-8") as f:
                checkpoint = json.load(f)

        if not isinstance(checkpoint, dict) or not checkpoint.get("ghost_audit_checkpoint"):
            return {"valid": False, "details": "Not a valid GhostAudit checkpoint"}

        seq          = checkpoint.get("seq", 0)
        root         = checkpoint.get("root", "")
        entry_chain  = checkpoint.get("entry_chain", "00" * 32)
        anchor_chain = checkpoint.get("anchor_chain", "00" * 32)
        timestamp    = checkpoint.get("timestamp", "")
        key_version  = checkpoint.get("key_version", 0)
        stored_mac   = checkpoint.get("mac", "")

        # 1 — MAC integrity
        mac_payload = (
            struct.pack(">I", seq)
            + root.encode("utf-8")
            + bytes.fromhex(entry_chain)
            + bytes.fromhex(anchor_chain)
            + timestamp.encode("utf-8")
            + struct.pack(">I", key_version)
        )
        expected_mac = hmac.new(self.k_hmac, mac_payload, hashlib.sha256).digest().hex()
        mac_valid = hmac.compare_digest(stored_mac, expected_mac)

        # 2 — Root match against current DB state
        current_root = self.get_verification_digest()
        root_match = (current_root == root)

        # 3 — Entry chain match
        cursor = self.conn.cursor()
        cursor.execute(
            f"SELECT entry_hash FROM {self.VISIBLE_LOG_TABLE} "
            f"ORDER BY sequence_number DESC LIMIT 1"
        )
        row = cursor.fetchone()
        current_entry_chain = row[0].hex() if row and row[0] else ("00" * 32)
        entry_chain_match = hmac.compare_digest(current_entry_chain, entry_chain)

        # 4 — Anchor chain match
        cursor.execute(
            f"SELECT anchor_hash FROM {self.MERKLE_ANCHOR_TABLE} "
            f"ORDER BY id DESC LIMIT 1"
        )
        row = cursor.fetchone()
        current_anchor_chain = row[0].hex() if row and row[0] else ("00" * 32)
        anchor_chain_match = hmac.compare_digest(current_anchor_chain, anchor_chain)

        valid = mac_valid and root_match and entry_chain_match and anchor_chain_match

        details_parts = []
        if not mac_valid:
            details_parts.append("MAC mismatch — checkpoint tampered")
        if not root_match:
            details_parts.append(f"root mismatch (stored={root[:16]}… current={current_root[:16]}…)")
        if not entry_chain_match:
            details_parts.append("entry chain mismatch — events added/removed/modified since checkpoint")
        if not anchor_chain_match:
            details_parts.append("anchor chain mismatch — merkle anchors modified since checkpoint")
        details = "; ".join(details_parts) if details_parts else "OK"

        result = {
            "valid": valid,
            "mac_valid": mac_valid,
            "root_match": root_match,
            "entry_chain_match": entry_chain_match,
            "anchor_chain_match": anchor_chain_match,
            "seq": seq,
            "root": root,
            "timestamp": timestamp,
            "details": details,
        }

        if self.verbose:
            status = "VALID" if valid else "INVALID"
            print(f"[CHECKPOINT] verify seq={seq} → {status}: {details}")

        return result

    def close(self):
        """Close database connection."""
        self.conn.close()
