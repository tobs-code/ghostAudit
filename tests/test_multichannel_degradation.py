"""
Multi-Kanal-Degradation Stress-Test — GhostAudit V7
=====================================================
Testet systematisch was passiert wenn physische Carrier-Spalten durch
externe Prozesse (ORM-TRIM, Lowercase-Normalisierung, DB-Backup-Tools)
korrumpiert werden.

Getestete Szenarien:
  SC1  Trailing-Space komplett gewippt (TRIM())          → Ch2 verloren
  SC2  Case-Normalisierung (alles lowercase)             → Ch3 verloren
  SC3  SC1 + SC2 gleichzeitig                            → Ch2 + Ch3 verloren
  SC4  Semantic-Wörter auf Index-0 normalisiert           → Ch0 verloren
  SC5  Float-Score gerundet auf 2 Dezimalstellen          → Ch1 verloren
  SC6  SC1 + SC4 (Trailing + Semantic)                   → Ch0 + Ch2 verloren
  SC7  SC2 + SC5 (Case + Float-Round)                    → Ch1 + Ch3 verloren

Für jedes Szenario:
  - Legt eine frische Test-DB an, loggt 1 Event
  - Korrumpiert die Carrier-Spalten direkt in der DB (simuliert externen Prozess)
  - Versucht recover_events()
  - Meldet: RECOVERED / PARTIAL / LOST

Usage:
  python tests/test_multichannel_degradation.py [--verbose]
"""
import sys
import os
import sqlite3
import tempfile
import shutil
import argparse

# Sicherstellen dass core/ im Pfad ist
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from core.ghost_audit_v7 import GhostAuditV7

TEST_KEY = "test-degradation-key-abcdefgh-1234"
TEST_MSG = "SYS_ALERT: Degradation stress test event"


def make_fresh_db(tmp_dir: str, scenario_name: str) -> str:
    """Create and populate a fresh GhostAudit DB for one scenario."""
    db_path = os.path.join(tmp_dir, f"degrad_{scenario_name}.db")
    ga = GhostAuditV7(db_path=db_path, secret_key=TEST_KEY, verbose=False)
    ga.log_event(TEST_MSG)
    ga.close()
    return db_path


def corrupt_db(db_path: str, scenario: str, verbose: bool = False):
    """Apply corruption directly to sys_cache (bypassing the write gate)."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    # Disable the write gate trigger for direct manipulation
    cur.execute("UPDATE sys_cache_write_gate SET allow_write=1 WHERE id=1")
    conn.commit()

    if verbose:
        print(f"  [corrupt] Szenario: {scenario}")

    if "TRIM" in scenario:
        # SC1, SC3, SC6: Trailing-Space wipe (simulates ORM TRIM())
        cur.execute("SELECT id, bio FROM sys_cache")
        for row_id, bio in cur.fetchall():
            if bio is not None:
                cur.execute("UPDATE sys_cache SET bio=? WHERE id=?",
                            (bio.rstrip(), row_id))
        if verbose:
            print("    → trailing spaces entfernt")

    if "LOWER" in scenario:
        # SC2, SC3, SC7: Case-Normalisierung (alles lowercase)
        cur.execute("SELECT id, bio FROM sys_cache")
        for row_id, bio in cur.fetchall():
            if bio is not None:
                cur.execute("UPDATE sys_cache SET bio=? WHERE id=?",
                            (bio.lower(), row_id))
        if verbose:
            print("    → bio auf lowercase normalisiert")

    if "SEM" in scenario:
        # SC4, SC6: Semantic-Normalisierung — alle Synonyme auf Index-0 setzen
        import re
        PAIRS = [
            ("presently", "currently"),
            ("online",    "active"),
            ("operating", "working"),
            ("platform",  "system"),
        ]
        cur.execute("SELECT id, bio FROM sys_cache")
        rows = cur.fetchall()
        for row_id, bio in rows:
            if bio is None:
                continue
            new_bio = bio
            for variant, canonical in PAIRS:
                new_bio = re.sub(rf"\b{re.escape(variant)}\b", canonical,
                                 new_bio, flags=re.IGNORECASE)
            if new_bio != bio:
                cur.execute("UPDATE sys_cache SET bio=? WHERE id=?",
                            (new_bio, row_id))
        if verbose:
            print("    → Synonyme auf Variante-0 normalisiert")

    if "ROUND" in scenario:
        # SC5, SC7: Float-Score auf 2 Dezimalstellen gerundet
        cur.execute("SELECT id, trust_score FROM sys_cache")
        for row_id, score in cur.fetchall():
            if score is not None:
                cur.execute("UPDATE sys_cache SET trust_score=? WHERE id=?",
                            (round(score, 2), row_id))
        if verbose:
            print("    → trust_score auf 2 Dezimalstellen gerundet")

    # Re-disable write gate
    cur.execute("UPDATE sys_cache_write_gate SET allow_write=0 WHERE id=1")
    conn.commit()
    conn.close()


def try_recover(db_path: str) -> tuple:
    """Try to recover events. Returns (success: bool, events: list, error: str)."""
    try:
        ga = GhostAuditV7(db_path=db_path, secret_key=TEST_KEY, verbose=False)
        events = list(ga.recover_events())
        ga.close()
        recovered = any(TEST_MSG in msg for _, msg in events)
        return recovered, events, ""
    except Exception as e:
        return False, [], str(e)


SCENARIOS = [
    ("SC1_TRIM",        "Trailing-Space gewippt (TRIM)",        "TRIM"),
    ("SC2_LOWER",       "Case-Normalisierung (lowercase)",       "LOWER"),
    ("SC3_TRIM_LOWER",  "TRIM + Lowercase gleichzeitig",         "TRIM+LOWER"),
    ("SC4_SEM",         "Semantic-Synonyme normalisiert",        "SEM"),
    ("SC5_ROUND",       "Float-Score gerundet (2 Dez.)",         "ROUND"),
    ("SC6_TRIM_SEM",    "TRIM + Semantic (Ch0+Ch2 verloren)",    "TRIM+SEM"),
    ("SC7_LOWER_ROUND", "Lowercase + Float-Round (Ch1+Ch3)",     "LOWER+ROUND"),
]


def main():
    parser = argparse.ArgumentParser(
        description="Multi-Kanal-Degradation Stress-Test für GhostAudit V7"
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    print("=" * 65)
    print("GhostAudit V7 — Multi-Kanal-Degradation Stress-Test")
    print("=" * 65)
    print()

    tmp_dir = tempfile.mkdtemp(prefix="ghost_degrad_")
    results = []

    try:
        for sc_id, description, corrupt_flags in SCENARIOS:
            if args.verbose:
                print(f"--- {sc_id}: {description} ---")

            db_path = make_fresh_db(tmp_dir, sc_id)
            corrupt_db(db_path, corrupt_flags, verbose=args.verbose)
            recovered, events, error = try_recover(db_path)

            status = "✅ RECOVERED" if recovered else "❌ LOST"
            results.append((sc_id, description, recovered, error))
            print(f"  {status}  {sc_id}: {description}")
            if args.verbose and error:
                print(f"           Error: {error}")
            if args.verbose and events:
                for seq, msg in events:
                    print(f"           [{seq}] {msg[:60]}")
            if args.verbose:
                print()

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    print()
    print("=" * 65)
    total = len(results)
    recovered_count = sum(1 for _, _, ok, _ in results if ok)
    lost_count = total - recovered_count

    print(f"Ergebnis: {recovered_count}/{total} Szenarien recovert")
    print()

    # Analyse der Ergebnisse
    print("--- Analyse ---")
    single_channel_lost = [r for r in results if r[0] in ("SC1_TRIM", "SC2_LOWER", "SC4_SEM", "SC5_ROUND")]
    dual_channel_lost   = [r for r in results if r[0] in ("SC3_TRIM_LOWER", "SC6_TRIM_SEM", "SC7_LOWER_ROUND")]

    sc_ok = sum(1 for _, _, ok, _ in single_channel_lost if ok)
    dc_ok = sum(1 for _, _, ok, _ in dual_channel_lost if ok)

    print(f"  Einzelkanal-Ausfall ({len(single_channel_lost)} Tests): "
          f"{sc_ok}/{len(single_channel_lost)} recovert")
    print(f"  Doppelkanal-Ausfall ({len(dual_channel_lost)} Tests): "
          f"{dc_ok}/{len(dual_channel_lost)} recovert")
    print()

    if lost_count == 0:
        print("✅ Vollständige Degradations-Resilienz — alle Szenarien bestanden.")
    elif dc_ok == len(dual_channel_lost) and sc_ok < len(single_channel_lost):
        print("⚠️  Einige Einzelkanal-Szenarien versagen — XOR-Parity greift nicht.")
    elif sc_ok == len(single_channel_lost) and dc_ok < len(dual_channel_lost):
        print("⚠️  Doppelkanal-Ausfall überwältigt XOR-Parity — erwartetes Verhalten.")
        print("   → V8-Strategie: Erasure Coding über > 3 Datenkanäle nötig.")
    else:
        print(f"❌ {lost_count} Szenarien nicht recovert — Härtung empfohlen.")

    print()

    # Empfehlungen
    failed = [r for r in results if not r[2]]
    if failed:
        print("--- Empfehlungen ---")
        has_trim_fail   = any("SC1" in r[0] or "SC3" in r[0] or "SC6" in r[0] for r in failed)
        has_lower_fail  = any("SC2" in r[0] or "SC3" in r[0] or "SC7" in r[0] for r in failed)
        has_sem_fail    = any("SC4" in r[0] or "SC6" in r[0] for r in failed)
        has_round_fail  = any("SC5" in r[0] or "SC7" in r[0] for r in failed)

        if has_trim_fail:
            print("  [Trailing-Space] ORM-TRIM zerstört Ch2 → Ch2 durch zweiten")
            print("   robusteren Kanal ersetzen (z.B. Unicode Zero-Width-Spaces).")
        if has_lower_fail:
            print("  [Case-Switching] ORM-Lowercase zerstört Ch3 → Case-Carrier")
            print("   in der Schema-Definition schützen (COLLATE BINARY in SQLite).")
        if has_sem_fail:
            print("  [Semantic] Synonym-Normalisierung durch ORM-Sanitizer →")
            print("   ORM Whitelist der erlaubten Synonyme konfigurieren.")
        if has_round_fail:
            print("  [Float-Round] ROUND(trust_score,2) zerstört LSB →")
            print("   Skalierung auf 6+ Stellen per CHECK-Constraint erzwingen.")

    return 0 if lost_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
