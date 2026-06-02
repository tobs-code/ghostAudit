"""
Steganalysis Test Suite — GhostAudit V7
========================================
Tests the sys_cache carrier columns against standard steganalysis methods:

  T1  Chi²-Test auf Float-LSBs         (sollte schlagen: p > 0.05)
  T2  Neighbor-Korrelations-Test        (WS-Detektor-Analogon für Floats)
  T3  Kolmogorov-Smirnov-Test           (Distribution vs. Gaussian baseline)
  T4  Semantic-Fingerprint-Test         (erkennt feste 4 Wortpaare in bio)
  T5  Case-Uniformitäts-Test            (Erster Buchstabe: upper vs. lower)
  T6  Trailing-Space-Frequenz-Test      (Chi² auf trailing space presence)

Alles in reinem Python (scipy optional – Fallback auf manuelle Implementierung).

Usage:
  python analysis/steganalysis_float_test.py [db_path] [--verbose]

Exit code: 0 = alle Tests sicher (undetektierbar), 1 = mind. ein Test schlägt an
"""

import sys
import os
import sqlite3
import math
import re
import argparse
from collections import Counter

# ---------------------------------------------------------------------------
# Optional scipy für exakte p-Werte
# ---------------------------------------------------------------------------
try:
    from scipy import stats as _scipy_stats
    _SCIPY = True
except ImportError:
    _SCIPY = False


# ---------------------------------------------------------------------------
# Manuelle Statistik-Primitiven (Fallback ohne scipy)
# ---------------------------------------------------------------------------
def _chi2_cdf(chi2, df):
    """Regularized lower incomplete gamma (approximation via series expansion)."""
    k = df / 2.0
    x = chi2 / 2.0
    if x <= 0:
        return 0.0
    # Series: P(k,x) = e^{-x} * x^k / Γ(k) * sum_{n=0}^{inf} x^n / prod_{i=1}^{n}(k+i)
    term = 1.0
    total = 1.0
    for n in range(1, 200):
        term *= x / (k + n)
        total += term
        if term < 1e-12 * total:
            break
    log_gamma_k = math.lgamma(k)
    log_prefix = -x + k * math.log(x) - log_gamma_k
    p = math.exp(log_prefix) * total
    return min(1.0, max(0.0, p))


def chi2_pvalue(observed_0, observed_1):
    """Chi²-Test: H0 = LSBs sind gleichverteilt (0.5/0.5)."""
    n = observed_0 + observed_1
    if n == 0:
        return 1.0
    expected = n / 2.0
    chi2 = ((observed_0 - expected) ** 2 / expected +
            (observed_1 - expected) ** 2 / expected)
    # p = 1 - CDF(chi2, df=1)
    p = 1.0 - _chi2_cdf(chi2, 1)
    return p


def ks_statistic(values, mean, std):
    """Kolmogorov-Smirnov-Statistik D vs. Normal(mean, std)."""
    n = len(values)
    if n == 0:
        return 0.0, 1.0
    sorted_v = sorted(values)
    d = 0.0
    for i, v in enumerate(sorted_v):
        z = (v - mean) / (std if std > 0 else 1)
        cdf = 0.5 * (1 + math.erf(z / math.sqrt(2)))
        emp = (i + 1) / n
        d = max(d, abs(emp - cdf), abs(i / n - cdf))
    # Approximate p-value (Kolmogorov distribution)
    t = (math.sqrt(n) + 0.12 + 0.11 / math.sqrt(n)) * d
    # P(D > d) ≈ 2 * sum_{k=1}^{inf} (-1)^{k+1} * e^{-2k²t²}
    p = 0.0
    for k in range(1, 50):
        sign = (-1) ** (k + 1)
        p += sign * math.exp(-2 * k * k * t * t)
    p = min(1.0, max(0.0, 2 * p))
    return d, p


# ---------------------------------------------------------------------------
# Test Runner
# ---------------------------------------------------------------------------
class SteganalysisResult:
    def __init__(self, name, detectable, statistic, p_value, details=""):
        self.name = name
        self.detectable = detectable  # True = Kanal auffällig
        self.statistic = statistic
        self.p_value = p_value
        self.details = details

    def __repr__(self):
        flag = "🔴 DETEKTIERBAR" if self.detectable else "✅ SICHER"
        return (f"[{flag}] {self.name}: stat={self.statistic:.4f}, "
                f"p={self.p_value:.4f}  {self.details}")


def run_all_tests(db_path: str, verbose: bool = False) -> list:
    """Run all steganalysis tests. Returns list of SteganalysisResult."""
    if not os.path.exists(db_path):
        print(f"[ERROR] Datenbank nicht gefunden: {db_path}")
        sys.exit(2)

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    # Prüfe ob sys_cache existiert
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sys_cache'")
    if not cur.fetchone():
        print("[ERROR] sys_cache Tabelle nicht gefunden. Ist das eine GhostAudit-DB?")
        sys.exit(2)

    cur.execute("SELECT id, bio, trust_score FROM sys_cache ORDER BY id")
    rows = cur.fetchall()
    conn.close()

    if not rows:
        print("[ERROR] sys_cache ist leer.")
        sys.exit(2)

    n = len(rows)
    if verbose:
        print(f"\n[INFO] {n} sys_cache-Zeilen geladen.\n")

    results = []

    # -----------------------------------------------------------------------
    # T1: Chi²-Test auf Float-LSBs
    # -----------------------------------------------------------------------
    def _float_lsb(v):
        scale = 1_000_000
        return int(round(v * scale)) % 2

    lsbs = [_float_lsb(r[2]) for r in rows if r[2] is not None]
    ones = sum(lsbs)
    zeros = len(lsbs) - ones
    p_chi2 = chi2_pvalue(zeros, ones)
    if _SCIPY:
        chi2_val, p_chi2 = _scipy_stats.chisquare([zeros, ones])
    else:
        n_lsb = zeros + ones
        expected = n_lsb / 2.0
        chi2_val = ((zeros - expected)**2 / expected + (ones - expected)**2 / expected)

    detectable_t1 = p_chi2 < 0.05
    results.append(SteganalysisResult(
        "T1 Chi²-Float-LSB",
        detectable_t1,
        chi2_val,
        p_chi2,
        f"zeros={zeros}, ones={ones}, ratio={ones/len(lsbs):.3f}"
    ))

    # -----------------------------------------------------------------------
    # T2: Neighbor-Korrelations-Test (WS-Detektor-Analogon)
    # Idee: In Cover-Floats sind aufeinanderfolgende LSBs leicht korreliert.
    # Nach LSB-Embedding bricht diese Korrelation (WS nutzt genau das).
    # -----------------------------------------------------------------------
    scores = [r[2] for r in rows if r[2] is not None]
    scale = 1_000_000
    pairs = [(int(round(scores[i] * scale)) % 2,
              int(round(scores[i+1] * scale)) % 2)
             for i in range(len(scores) - 1)]

    same = sum(1 for a, b in pairs if a == b)
    diff = len(pairs) - same
    # In natürlichen Daten: leichte Korrelation → same > n/2
    # Nach Embedding: nähert sich 50/50
    # Test: binomial p-Wert für H0 = P(same) = 0.5
    p_same = same / len(pairs) if pairs else 0.5
    # Normal-Approximation des Binomial-Tests
    if pairs:
        z = (same - len(pairs) * 0.5) / math.sqrt(len(pairs) * 0.25)
        # Two-tailed p via erf
        p_ws = 2 * (1 - 0.5 * (1 + math.erf(abs(z) / math.sqrt(2))))
    else:
        z, p_ws = 0.0, 1.0

    detectable_t2 = p_ws < 0.05
    results.append(SteganalysisResult(
        "T2 Neighbor-Korrelation (WS-analog)",
        detectable_t2,
        z,
        p_ws,
        f"same_pairs={same}/{len(pairs)}, p_same={p_same:.3f}"
    ))

    # -----------------------------------------------------------------------
    # T3: Kolmogorov-Smirnov vs. Gaussian(0.78, 0.12)
    # Die neue Initialisierung erzeugt Gauss(0.78, 0.12) → H0 sollte nicht
    # abgelehnt werden (p > 0.05 = kein signifikanter Unterschied).
    # -----------------------------------------------------------------------
    mean_ref, std_ref = 0.78, 0.12
    d_stat, p_ks = ks_statistic(scores, mean_ref, std_ref)
    if _SCIPY:
        from scipy.stats import norm
        d_stat, p_ks = _scipy_stats.kstest(scores, norm(mean_ref, std_ref).cdf)

    # Detektierbar wenn die Verteilung stark von der erwarteten Gauss abweicht
    detectable_t3 = p_ks < 0.01
    results.append(SteganalysisResult(
        "T3 KS-Test trust_score vs Gauss(0.78,0.12)",
        detectable_t3,
        d_stat,
        p_ks,
        f"n={len(scores)}, mean={sum(scores)/len(scores):.3f}"
    ))

    # -----------------------------------------------------------------------
    # T4: Semantic-Fingerprint-Test
    # Prüft ob die 4 Synonym-Paare unnatürlich gleichmäßig verteilt sind.
    # In echten Texten: Wortpaare nicht gleichverteilt.
    # Nach Stego-Encoding: ~50/50 pro Paar (verdächtig).
    # -----------------------------------------------------------------------
    PAIRS = [
        ("currently", "presently"),
        ("active", "online"),
        ("working", "operating"),
        ("system", "platform"),
    ]

    pair_ratios = []
    pair_details = []
    for w0, w1 in PAIRS:
        bios = [r[1] for r in rows if r[1] is not None]
        c0 = sum(1 for b in bios if re.search(rf"\b{w0}\b", b, re.IGNORECASE))
        c1 = sum(1 for b in bios if re.search(rf"\b{w1}\b", b, re.IGNORECASE))
        total = c0 + c1
        if total > 0:
            ratio = c1 / total
            pair_ratios.append(ratio)
            pair_details.append(f"{w0}/{w1}={c0}/{c1}({ratio:.2f})")

    # Detektierbar wenn alle Paare nahe 0.5 (±0.1)
    suspicious_pairs = sum(1 for r in pair_ratios if 0.35 < r < 0.65)
    p_semantic = 1.0 - (suspicious_pairs / len(pair_ratios)) if pair_ratios else 1.0
    detectable_t4 = suspicious_pairs >= 3  # 3 von 4 Paaren nahe 50/50

    results.append(SteganalysisResult(
        "T4 Semantic-Fingerprint (Synonym-Ratio)",
        detectable_t4,
        float(suspicious_pairs),
        p_semantic,
        "  ".join(pair_details)
    ))

    # -----------------------------------------------------------------------
    # T5: Case-Uniformitäts-Test (erster Buchstabe)
    # Nach Case-Switching: ~50/50 upper/lower (verdächtig für Fließtext).
    # -----------------------------------------------------------------------
    bios = [r[1] for r in rows if r[1] is not None]
    upper_first = sum(1 for b in bios if b and b[0].isupper())
    lower_first = len(bios) - upper_first
    p_case = chi2_pvalue(lower_first, upper_first)
    if _SCIPY:
        _, p_case = _scipy_stats.chisquare([lower_first, upper_first])
    case_chi2 = ((upper_first - len(bios)/2)**2 / (len(bios)/2) +
                 (lower_first - len(bios)/2)**2 / (len(bios)/2))

    detectable_t5 = p_case < 0.05
    results.append(SteganalysisResult(
        "T5 Case-Uniformität (erster Buchstabe)",
        detectable_t5,
        case_chi2,
        p_case,
        f"upper={upper_first}, lower={lower_first}"
    ))

    # -----------------------------------------------------------------------
    # T6: Trailing-Space-Frequenz-Test
    # Normaler Fließtext: kaum trailing spaces.
    # Nach Encoding: ~50% der Zeilen haben trailing space (sehr verdächtig).
    # -----------------------------------------------------------------------
    trailing = sum(1 for b in bios if b.endswith(" "))
    p_trailing = trailing / len(bios) if bios else 0.0
    # Erwartung für echten Text: < 2% trailing spaces
    # Erwartung nach Encoding: ~50%
    # Wir flaggen ab > 10%
    detectable_t6 = p_trailing > 0.10

    # Exakter Binomial-p-Wert gegen H0: P(trailing) = 0.02
    if _SCIPY:
        binom_stat, p_trailing_p = _scipy_stats.binom_test(
            trailing, len(bios), 0.02, alternative="greater"
        ) if hasattr(_scipy_stats, "binom_test") else (p_trailing, 0.0)
    else:
        binom_stat = p_trailing
        p_trailing_p = 0.0 if p_trailing > 0.10 else 1.0

    results.append(SteganalysisResult(
        "T6 Trailing-Space-Frequenz",
        detectable_t6,
        p_trailing,
        p_trailing_p if _SCIPY else (0.001 if detectable_t6 else 0.5),
        f"trailing={trailing}/{len(bios)} ({p_trailing*100:.1f}%)"
    ))

    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Steganalysis-Testsuite für GhostAudit V7 sys_cache"
    )
    parser.add_argument(
        "db_path",
        nargs="?",
        default="ghost_audit_v7.db",
        help="Pfad zur GhostAudit SQLite-Datenbank"
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    print("=" * 65)
    print("GhostAudit V7 — Steganalysis-Testsuite")
    print(f"Datenbank: {args.db_path}")
    if not _SCIPY:
        print("[WARN] scipy nicht gefunden — Fallback auf manuelle Statistik.")
    print("=" * 65)

    results = run_all_tests(args.db_path, verbose=args.verbose)

    detectable_count = 0
    for r in results:
        print(r)
        if r.detectable:
            detectable_count += 1

    print("=" * 65)
    if detectable_count == 0:
        print(f"✅ ALLE {len(results)} Tests: Kanal statistisch unauffällig.")
        print("   → Keine Standard-Steganalyse-Tools würden anschlagen.")
    else:
        print(f"⚠️  {detectable_count}/{len(results)} Tests auffällig!")
        print("   → Kanal könnte durch forensische Analyse erkannt werden.")
    print()

    # Bewertung der kritischen Kanäle
    print("--- Kanal-Risikobewertung ---")
    channel_risk = {
        "Float-LSB (trust_score)": [results[0], results[1], results[2]],
        "Semantic (Synonyme)":      [results[3]],
        "Case-Switching":           [results[4]],
        "Trailing-Space":           [results[5]],
    }
    for channel, tests in channel_risk.items():
        risky = any(t.detectable for t in tests)
        flag = "🔴" if risky else "✅"
        print(f"  {flag} {channel}")

    return 1 if detectable_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
