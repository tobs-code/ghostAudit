
import sys
import sqlite3
import math
from collections import Counter

def shannon_entropy(data):
    """Calculate Shannon entropy of a list of bytes/data."""
    if not data:
        return 0
    counts = Counter(data)
    n = len(data)
    entropy = 0
    for count in counts.values():
        p = count / n
        entropy -= p * math.log2(p)
    return entropy

def analyze_entropy(db_path):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT bio, trust_score FROM sys_cache")
    rows = cur.fetchall()
    conn.close()

    bios = [r[0] for r in rows if r[0]]
    scores = [r[1] for r in rows if r[1] is not None]

    # Combine all chars from bio
    bio_data = "".join(bios).encode('utf-8')
    # Combine scores as strings to get distribution
    score_data = "".join([f"{s:.6f}" for s in scores]).encode('utf-8')

    bio_h = shannon_entropy(bio_data)
    score_h = shannon_entropy(score_data)

    print(f"Entropy Analysis (Shannon):")
    print(f"  Bio:         {bio_h:.4f} bits/byte")
    print(f"  Float-Score: {score_h:.4f} bits/byte")
    
    # Simple distribution check for floats
    print(f"  Float-LSB (0/1): {Counter([int(round(s * 1000000)) % 2 for s in scores])}")
    
    # Typical English text entropy: 3.5 - 5.0
    # Typical float score entropy depends on precision.
    
    # Just print for now to establish baseline
    return bio_h, score_h

if __name__ == "__main__":
    analyze_entropy("audit.db")
