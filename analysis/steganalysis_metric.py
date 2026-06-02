
import sqlite3
import numpy as np
from collections import Counter
from scipy.stats import entropy

# --- Referenz-Baseline (Synthetisch) ---
# LSB-Verteilung (0,1) von natürlichen Floats (Gauß-verteilt)
# Ein perfektes System sollte LSBs haben, die der natürlichen Verteilung entsprechen,
# nicht zwangsläufig 50/50.
BASELINE_LSB_DIST = np.array([0.5, 0.5]) # Annahme: Natürliche Floats sind uniform in LSBs
BASELINE_CHAR_DIST = np.array([0.5, 0.5]) # Annahme: Char-Parity uniform

def get_lsb_dist(scores):
    lsbs = [int(round(s * 1000000)) % 2 for s in scores]
    counts = Counter(lsbs)
    return np.array([counts.get(0, 0) / len(lsbs), counts.get(1, 0) / len(lsbs)])

def get_char_dist(bios):
    chars = [ord(b[0]) % 2 for b in bios if b]
    counts = Counter(chars)
    return np.array([counts.get(0, 0) / len(chars), counts.get(1, 0) / len(chars)])

def calculate_kl(p, q):
    # Add epsilon to avoid division by zero / log(0)
    eps = 1e-10
    p = p + eps
    q = q + eps
    return entropy(p, q)

def run_analysis(db_path):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT bio, trust_score FROM sys_cache WHERE bio IS NOT NULL AND trust_score IS NOT NULL")
    rows = cur.fetchall()
    conn.close()

    bios = [r[0] for r in rows]
    scores = [r[1] for r in rows]

    # Berechne Verteilungen
    lsb_dist = get_lsb_dist(scores)
    char_dist = get_char_dist(bios)

    # Berechne KL-Divergenz
    kl_lsb = calculate_kl(lsb_dist, BASELINE_LSB_DIST)
    kl_char = calculate_kl(char_dist, BASELINE_CHAR_DIST)

    print(f"--- Steganalyse Metrik (GhostAudit vs. Baseline) ---")
    print(f"Float-LSB Distribution: {lsb_dist}")
    print(f"Float-LSB KL-Divergence: {kl_lsb:.6f}")
    print(f"Char-Parity Distribution: {char_dist}")
    print(f"Char-Parity KL-Divergence: {kl_char:.6f}")
    print("\nInterpretation:")
    print("KL Divergence -> 0 bedeutet 'perfekte Tarnung' (Identisch zur Baseline).")
    print("Höhere Werte bedeuten stärkere statistische Detektierbarkeit.")

if __name__ == "__main__":
    run_analysis("audit.db")
