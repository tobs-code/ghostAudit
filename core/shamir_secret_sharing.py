import os
import sqlite3
import struct


_GF256_EXP = [0] * 512
_GF256_LOG = [0] * 256

_poly = 0x11B


def _gf_mul_raw(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        a = ((a << 1) ^ (_poly if a & 0x80 else 0)) & 0xFF
        b >>= 1
    return r


_GEN = 3
v = 1
for i in range(255):
    _GF256_EXP[i] = v
    _GF256_LOG[v] = i
    v = _gf_mul_raw(v, _GEN)
for i in range(255, 512):
    _GF256_EXP[i] = _GF256_EXP[i - 255]


def _gf_add(a, b):
    return a ^ b


def _gf_sub(a, b):
    return a ^ b


def _gf_mul(a, b):
    if a == 0 or b == 0:
        return 0
    return _GF256_EXP[_GF256_LOG[a] + _GF256_LOG[b]]


def _gf_div(a, b):
    if b == 0:
        raise ZeroDivisionError("division by zero in GF(256)")
    if a == 0:
        return 0
    return _GF256_EXP[(_GF256_LOG[a] - _GF256_LOG[b]) % 255]


def _gf_pow(a, p):
    if a == 0:
        return 0
    return _GF256_EXP[(_GF256_LOG[a] * p) % 255]


def _eval_poly(coeffs, x):
    y = 0
    for c in reversed(coeffs):
        y = _gf_add(_gf_mul(y, x), c)
    return y


def _interpolate_constant(shares):
    result = 0
    for i, (xi, yi) in enumerate(shares):
        num = yi
        den = 1
        for j, (xj, _) in enumerate(shares):
            if i == j:
                continue
            num = _gf_mul(num, xj)
            den = _gf_mul(den, _gf_sub(xj, xi))
        result ^= _gf_div(num, den)
    return result


def _rand_byte():
    return os.urandom(1)[0]


def split_secret(secret: bytes, n: int, k: int) -> list[tuple[int, bytes]]:
    if k < 2:
        raise ValueError("threshold k must be >= 2")
    if n < k:
        raise ValueError("n must be >= k")
    if n > 255:
        raise ValueError("n must be <= 255")

    shares = [bytearray(len(secret)) for _ in range(n)]
    for byte_idx in range(len(secret)):
        coeffs = [secret[byte_idx]] + [_rand_byte() for _ in range(k - 1)]
        for share_idx in range(n):
            x = share_idx + 1
            shares[share_idx][byte_idx] = _eval_poly(coeffs, x)

    return [(i + 1, bytes(shares[i])) for i in range(n)]


def reconstruct_secret(shares: list[tuple[int, bytes]]) -> bytes:
    if len(shares) < 2:
        raise ValueError("need at least 2 shares")
    byte_len = len(shares[0][1])
    for _, val in shares:
        if len(val) != byte_len:
            raise ValueError("all share values must have the same length")

    result = bytearray(byte_len)
    for byte_idx in range(byte_len):
        points = [(x, val[byte_idx]) for x, val in shares]
        result[byte_idx] = _interpolate_constant(points)
    return bytes(result)


SHARE_TABLE_DDL = """
CREATE TABLE IF NOT EXISTS shamir_shares (
    share_id INTEGER PRIMARY KEY,
    share_value BLOB NOT NULL
);
"""


def create_share_db(db_path: str):
    conn = sqlite3.connect(db_path)
    conn.execute(SHARE_TABLE_DDL)
    conn.commit()
    conn.close()


def write_share(db_path: str, table: str, share_id: int, value: bytes):
    conn = sqlite3.connect(db_path)
    conn.execute(f"INSERT OR REPLACE INTO {table} (share_id, share_value) VALUES (?, ?)",
                 (share_id, value))
    conn.commit()
    conn.close()


def read_share(db_path: str, table: str, share_id: int) -> bytes | None:
    conn = sqlite3.connect(db_path)
    row = conn.execute(f"SELECT share_value FROM {table} WHERE share_id=?", (share_id,)).fetchone()
    conn.close()
    return row[0] if row else None


def read_all_shares(db_path: str, table: str) -> list[tuple[int, bytes]]:
    conn = sqlite3.connect(db_path)
    rows = conn.execute(f"SELECT share_id, share_value FROM {table} ORDER BY share_id").fetchall()
    conn.close()
    return [(r[0], bytes(r[1])) for r in rows]


def reconstruct_from_sources(sources: list[tuple[str, str, int]]) -> bytes:
    shares = []
    for db_path, table, share_id in sources:
        val = read_share(db_path, table, share_id)
        if val is not None:
            shares.append((share_id, val))
    if len(shares) < 2:
        raise RuntimeError(
            f"not enough shares available ({len(shares)} < 2)"
        )
    return reconstruct_secret(shares)
