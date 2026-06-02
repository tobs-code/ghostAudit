# GhostAudit V6 — Testing Framework (Deployment Summary)

Uebersicht ueber das Security-Testing-Framework fuer GhostAudit V6. Stand: Pro-Kanal-RS als Default, Master-Suite mit `assessment_breakdown`, letzter Referenzlauf **2026-05-23**.

---

## Komponenten im Workspace

### Test-Skripte

| Datei | Zeilen (ca.) | Rolle |
|-------|----------------|-------|
| `ghost_audit_v6.py` | ~1540 | Kern: Stego, RS, Recovery, Gate |
| `attack_simulator_v6.py` | ~470 | 4 fokussierte MITRE-nahe Angriffe + Recovery-Test |
| `resilience_benchmark_v6.py` | ~590 | Erasure, Bit-Flip, Isolation, Keys, Accuracy, Long Event; Per-Kanal: targeted erasure |
| `master_test_suite.py` | ~460 | 4 serielle Laeufe, Master-JSON, Bewertung |
| `quickstart_tests.py` | ~235 | Interaktives Menue (1–6) |
| `security_suite_support.py` | ~65 | `create_ga`, CLI-Flags, Report-Pfade |

### Dokumentation

| Datei | Inhalt |
|-------|--------|
| `README_GHOST_AUDIT.md` | Architektur, Pro-Kanal-RS, Snapshot-Ergebnisse |
| `TEST_SUITE_OVERVIEW.md` | Testfluss, Interpretation |
| `TESTING_GUIDE_V6.md` | Methodologie, Hardening |
| `QUICK_REFERENCE.md` | Kurzbefehle |
| Diese Datei | Deployment-Ueberblick |

---

## Quick Start

### Option 1: Interaktiv

```bash
python quickstart_tests.py
```

Menue (Stand Code):

| Taste | Skript |
|-------|--------|
| 1 | `ghost_audit_v6.py` — Baseline, Ringbuffer, Per-Kanal aux |
| 2 | `attack_simulator_v6.py --combined-rs` |
| 3 | `resilience_benchmark_v6.py --combined-rs` |
| 4 | `attack_simulator_v6.py --per-channel-rs` |
| 5 | `resilience_benchmark_v6.py --per-channel-rs` |
| 6 | `master_test_suite.py` — alle Modi + Master-Report |
| all | 1→6 seriell |

### Option 2: Produktion / CI (empfohlen)

```bash
python master_test_suite.py
```

Seriell (4 Subprozesse):

1. `attack_simulator_v6.py --combined-rs`
2. `resilience_benchmark_v6.py --combined-rs`
3. `attack_simulator_v6.py --per-channel-rs`
4. `resilience_benchmark_v6.py --per-channel-rs`

Ausgabe: `security_test_results/master_security_report.json`

### Option 3: Einzeltests

```bash
python ghost_audit_v6.py
python attack_simulator_v6.py --per-channel-rs
python resilience_benchmark_v6.py --combined-rs
```

**RS-Modus:** Default in `ghost_audit_v6` = Per-Kanal (`GHOST_AUDIT_PER_CHANNEL_RS=1`). Combined: `--combined-rs` oder Env `=0`.

---

## Was wird getestet?

### Phase 1: Baseline (`ghost_audit_v6.py`)

- DB-Init, Persistenz (kein Drop im Normalfall)
- Mehrere Events, Ringbuffer (5 Slots)
- Recovery, optional Per-Kanal aux-Test (TEST 4)

### Phase 2: Attack Simulation (`attack_simulator_v6.py`)

Aktiver Hauptpfad (4 Eintraege im Report):

| ID | Angriff | Erwartung |
|----|---------|-----------|
| T1565_sem | Semantic Normalization (Gate-Bypass) | Mutation erfolgreich |
| T1485 | Multi-Channel Nulling | Mutation erfolgreich |
| T1565_mod | HMAC Forgery (falscher Key) | **blockiert** (Defense) |
| T1565_combined | Combined Destruction + Recovery-Test | Mutation + `post_attack_recovery` |

Zusaetzliche Methoden im Code (T1070, T1027) sind fuer manuelle Erweiterung, nicht Teil des Standard-`main()`-Flows.

Recovery-Test laeuft auf frischem **Baseline-Snapshot** (kein kumulativer Totalschaden-Stack).

### Phase 3: Resilience Benchmark (`resilience_benchmark_v6.py`)

| # | Test | Combined (Referenz) | Per-Channel (Referenz) |
|---|------|---------------------|-------------------------|
| 1 | Erasure tolerance (aux-only) | 0% | 15% |
| 2 | Bit-flip resistance | 0% | 1% |
| 3 | Channel isolation | 4/4 SURVIVED | 0/4 DISRUPTED |
| 4 | Key sensitivity | falscher Key scheitert | gleich |
| 5 | Recovery accuracy | 100% | 100% |
| 6 | Long event (5 Slots) | PASS | PASS |
| 7 | Targeted channel erasure (20 %) | n/a | 4/4 SURVIVED |

Werte stammen aus dem letzten Master-Lauf; nach Aenderungen neu messen.

### Phase 4: Master-Report (`master_test_suite.py`)

Pro Modus (`combined_rs`, `per_channel_rs`):

- Rohdaten: `attack_simulation`, `resilience_metrics`
- `overall_assessment` (Headline)
- **`assessment_breakdown`**:
  - `benchmark` — partielle Korruption, aux-only
  - `post_attack` — nach Vollangriff (`total_loss` → **EXPECTED**)
  - `integrity` — HMAC, Anzahl ausgefuehrter/blockierter Angriffe
- `recommendations` — kontextabhaengig (kein pauschales HIGH RISK)

---

## Referenz-Snapshot (2026-05-23)

| | Combined RS | Per-Channel RS |
|---|-------------|----------------|
| Gesamt | MODERATE | GOOD |
| Benchmark | Erasure 0%, Bit-Flip 0%, Accuracy 100% | Erasure 15%, Bit-Flip 1%, Accuracy 100% |
| Post-Attack | EXPECTED (`total_loss`) | EXPECTED (`total_loss`) |
| Attack-Sim | 3 ausgefuehrt, 1 blockiert | 3 ausgefuehrt, 1 blockiert |

**Lesart:** Combined = starkes Voting bei Einzelkanal-Angriffen, geringe zufaellige Erasure-Toleranz. Per-Channel = bessere partielle Erasure-Toleranz, Einzelkanal-Angriffe stoeren den jeweiligen RS-Block staerker. `total_loss` nach zerstoerter `sys_cache` ist **kein** Benchmark-Fehler.

---

## Report-Dateien

```
security_test_results/
  master_security_report.json     # kanonisch: combined_rs + per_channel_rs + assessment_breakdown

attack_simulation_report.json
resilience_metrics.json
attack_simulation_report_per_channel.json
resilience_metrics_per_channel.json
```

### Beispiel Master-JSON (gekuerzt)

```json
{
  "timestamp": "2026-05-23T00:19:28.621623",
  "test_execution_status": { "...": { "status": "PASS", "exit_code": 0 } },
  "combined_rs": {
    "mode": "combined_rs",
    "attack_simulation": {
      "total_attacks": 4,
      "executed": 3,
      "blocked": 1,
      "post_attack_recovery": { "status": "total_loss", "total_recovered": 0 }
    },
    "resilience_metrics": {
      "erasure_tolerance": { "max_erasure_tolerated": "0%" },
      "recovery_accuracy": { "accuracy_rate": "100.0%" }
    },
    "overall_assessment": "MODERATE - Solide Detektion ...",
    "assessment_breakdown": {
      "benchmark": { "grade": "MODERATE", "channel_isolation": "4/4 SURVIVED" },
      "post_attack": { "grade": "EXPECTED", "status": "total_loss" },
      "integrity": { "hmac_forgery_blocked": true, "attacks_executed": 3 }
    }
  },
  "per_channel_rs": { "...": "GOOD / 15% erasure / 0/4 DISRUPTED / ..." }
}
```

---

## Sicherheitsbewertung (aktuell)

Bewertung immer aus `assessment_breakdown` lesen — nicht aus fixen Schwellen wie „Erasure >25% = gruen“.

| Signal | Combined (typ.) | Per-Channel (typ.) | Bedeutung |
|--------|-----------------|---------------------|-----------|
| Benchmark-Grade | MODERATE | GOOD | aux-only unter kontrollierter Korruption |
| Post-Attack | EXPECTED | EXPECTED | versteckte Spur nach Vollangriff weg |
| HMAC | blockiert | blockiert | Integritaet wirkt |
| Stego-Mutationen | 3/4 erfolgreich (bei Gate-Bypass) | gleich | Angriffsflaeche `sys_cache` bleibt relevant |

**Defense-in-Depth:** `audit_log` (sichtbar) + `sys_cache` (versteckt) + externe Backups. Vollstaendiger forensischer Verlust erfordert typischerweise beide Pfade oder die ganze DB.

### Legacy-Zielwerte (nur Orientierung)

Die alten Targets (>25 % Erasure, >5 % Bit-Flip) gelten nicht mehr pauschal als PASS/FAIL. Modus und Methodik (aux-only, Per-Kanal vs Combined) bestimmen die erwartbare Toleranz.

---

## Key Metriken

| Metrik | Abk. | Quelle im JSON | Hinweis |
|--------|------|----------------|---------|
| Erasure tolerance | MER | `erasure_tolerance.max_erasure_tolerated` | Payload-Zonen, aux-only |
| Bit-flip resistance | BER | `bit_flip_resistance.tolerance` | |
| Recovery accuracy | DIR | `recovery_accuracy.accuracy_rate` | Ziel typ. 100% im Benchmark |
| Channel isolation | — | `channel_isolation.results` | Combined vs Per-Channel unterschiedlich |
| Targeted erasure | — | `targeted_channel_erasure` | nur Per-Kanal |
| Gesamtbewertung | — | `assessment_breakdown` | Benchmark ≠ Post-Attack |

---

## Naechste Schritte

1. Tests ausfuehren: `python master_test_suite.py` (unter Windows seriell wegen SQLite-Locks).
2. Report pruefen: `security_test_results/master_security_report.json`.
3. Empfehlungen aus `combined_rs.recommendations` / `per_channel_rs.recommendations` priorisieren.
4. Nach Code-Aenderungen: Master-Suite erneut laufen und ggf. README-Snapshot aktualisieren.

```powershell
Get-Content security_test_results/master_security_report.json | ConvertFrom-Json |
  Select-Object -ExpandProperty combined_rs |
  Select-Object overall_assessment, assessment_breakdown
```

---

## Dokumentations-Index

| Dokument | Wann |
|----------|------|
| `QUICK_REFERENCE.md` | Schnellbefehle |
| `README_GHOST_AUDIT.md` | Architektur + Snapshot |
| `TEST_SUITE_OVERVIEW.md` | Testfluss + Interpretation |
| `TESTING_GUIDE_V6.md` | Deep Dive, Hardening |
| `master_security_report.json` | Aktuelle Zahlen |

---

## CI/CD (Beispiel)

```yaml
name: GhostAudit Security Tests
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install -r requirements.txt
      - run: python master_test_suite.py
      - uses: actions/upload-artifact@v4
        with:
          name: security-reports
          path: |
            security_test_results/
            attack_simulation_report*.json
            resilience_metrics*.json
```

---

## FAQ

**Wie lange dauert `master_test_suite.py`?**  
Ca. 45–60 Minuten (4 Subprozesse mit Benchmark + Attack je Modus). Einzeltests sind kuerzer.

**Warum zwei RS-Modi?**  
Combined: ein RS-Block + 4-Kanal-Voting. Per-Kanal: eigener RS pro Kanal, bessere partielle Erasure-Toleranz, andere Isolation-Eigenschaften.

**Was bedeutet Post-Attack `total_loss`?**  
Nach kombiniertem Zerstoeren der Stego-Spur in `sys_cache` keine aux-Recovery — im Master-Report als **EXPECTED** eingestuft.

**Was bedeutet „3/4 Angriffe ausgefuehrt“?**  
Stego-Mutationen mit Gate-Bypass gelingen; HMAC-Forgery wird erwartungsgemäss blockiert.

**Tests fehlgeschlagen?**  
Siehe `TESTING_GUIDE_V6.md` (Troubleshooting). Unter Windows parallele Laeufe auf dieselbe DB vermeiden.

---

## Status

Framework ist einsatzbereit fuer lokale und CI-Messungen:

- 4 fokussierte Angriffe + Recovery-Szenario pro Modus
- Benchmark inkl. Long Event und (Per-Kanal) gezielter Kanal-Erasure
- Master-Report mit getrennter Bewertung (Benchmark / Post-Attack / Integrity)
- Interaktives und automatisiertes Ausfuehrungsmodell

GhostAudit V6 bleibt ein **Prototyp** — klassische Audit-Logs und Backups sind das Primaersystem.
