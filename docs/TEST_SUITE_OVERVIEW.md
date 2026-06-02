# GhostAudit V6 - Test Suite Overview

Diese Datei beschreibt den aktuellen Stand der Test-Suite fuer GhostAudit V6. Sie ist bewusst auf den tatsaechlichen Implementierungs- und Messergebnissen des aktuellen Codes ausgerichtet und ersetzt fruehere, zu optimistische Erwartungswerte.

## Kernskripte

| Datei | Zweck | Start |
|---|---|---|
| `ghost_audit_v6.py` | Basisszenario, Persistenz, Ringbuffer | `python ghost_audit_v6.py` |
| `attack_simulator_v6.py` | adversariale Manipulationsszenarien | `python attack_simulator_v6.py` |
| `resilience_benchmark_v6.py` | quantitative Robustheitsmessung | `python resilience_benchmark_v6.py` |
| `master_test_suite.py` | 4 Laeufe, Master-JSON inkl. `assessment_breakdown` | `python master_test_suite.py` |
| `security_suite_support.py` | Factory/CLI-Helfer (`--per-channel-rs`) | importiert von Benchmark/Attack/Master |
| `quickstart_tests.py` | interaktives Menue (Baseline, Benchmark, Master, …) | `python quickstart_tests.py` |

## Testfluss

1. Baseline:
   `ghost_audit_v6.py` schreibt mehrere Events, prueft Persistenz und Ringbuffer-Recovery.
2. Angriffssimulation:
   `attack_simulator_v6.py` fuehrt gezielte Datenbankmanipulationen aus.
3. Benchmark:
   `resilience_benchmark_v6.py` misst Loesch-, Bitflip- und Recovery-Verhalten.
4. Aggregation:
   `master_test_suite.py` sammelt JSON-Reports und erzeugt `security_test_results/master_security_report.json` mit getrennter Bewertung pro Modus (`assessment_breakdown`: Benchmark / Post-Attack / Integrity).

### Pro-Kanal-RS (`--per-channel-rs`)

```bash
python attack_simulator_v6.py --per-channel-rs
python resilience_benchmark_v6.py --per-channel-rs
python master_test_suite.py   # beide Modi seriell
```

Reports:

- `attack_simulation_report_per_channel.json`
- `resilience_metrics_per_channel.json`
- Master-Report: Abschnitte `combined_rs` und `per_channel_rs`

## Wichtige inhaltliche Punkte zum aktuellen Stand

- GhostAudit V6 arbeitet aktuell mit `5` Slots zu je `1600` Carrier-Zeilen.
- Die sichtbare Audit-Oberflaeche liegt in `audit_log`; `audit_archive` wirkt als Decoy-Fallback; die verdeckte Rueckfallspur liegt in `sys_cache`.
- Header und Payload sind inzwischen robuster gegen einzelne Kanal-Ausfaelle.
- Der kombinierte Angriff in `attack_simulator_v6.py` wird auf einem frischen Baseline-Snapshot ausgefuehrt, damit er als kombinierter Vektor und nicht als kompletter Totalschaden-Stack bewertet wird.
- Die Benchmark-Methodik arbeitet fuer Erasure- und Accuracy-Tests auf den genutzten Payload-Zonen statt blind auf der gesamten Tabelle.

## Aktuelle Messergebnisse

Nach `python master_test_suite.py` → `security_test_results/master_security_report.json`:

- Vier Laeufe: combined + per-channel (Attack + Benchmark jeweils)
- Per-Kanal-Benchmark zusaetzlich: `targeted_channel_erasure` (20 % Loeschung nur eines Kanals)
- Long-Event: Per-Kanal ueber **5 Slot-Fragmente** (nicht skipped)
- Bewertung: `overall_assessment` + **`assessment_breakdown`** (kein flaches `HIGH RISK` mehr)

### Snapshot (2026-05-23, serieller Lauf)

| | Combined RS | Per-Channel RS |
|---|-------------|----------------|
| Gesamt | MODERATE | GOOD |
| Benchmark | Erasure 0%, Bit-Flip 0%, Accuracy 100% | Erasure 15%, Bit-Flip 1%, Accuracy 100% |
| Kanal-Isolation | 4/4 SURVIVED | 0/4 DISRUPTED |
| Targeted erasure (20 %) | n/a | 4/4 SURVIVED |
| Post-Attack | EXPECTED (`total_loss`) | EXPECTED (`total_loss`) |
| Attack-Sim | 3 ausgefuehrt, 1 blockiert (HMAC) | 3 ausgefuehrt, 1 blockiert (HMAC) |

Kennzahlen immer aus `combined_rs` / `per_channel_rs` im Master-Report lesen — Felder `assessment_breakdown.benchmark` und `.post_attack` sind die kanonische Einordnung.

## Interpretation

Was aktuell gut aussieht:

- Baseline-Recovery und Long-Event-Fragmentierung funktionieren
- Combined RS: starke Kanal-Isolation im Benchmark (4/4 SURVIVED)
- Per-Channel RS: hoehere aux-only Erasure-Toleranz (z. B. 15 % im letzten Lauf)
- HMAC-Forgery wird blockiert; falsche Keys fuehren nicht zu Recovery
- Post-Attack `total_loss` wird als **EXPECTED** gewertet, nicht als Benchmark-Fail

Was aktuell noch schwach ist:

- Combined RS: geringe zufaellige Erasure/Bit-Flip-Toleranz im Benchmark (strikte Detektion)
- Per-Channel RS: Einzelkanal-Stego-Angriffe stoeren den jeweiligen RS-Block (0/4 SURVIVED im Isolation-Test)
- gezielte 20 %-Kanal-Erasure: mit Repliken + korrigierter Erasure-Extraktion 4/4 SURVIVED (Benchmark `[7/7]`)
- sichtbare `audit_log`-Spur und `sys_cache` bleiben getrennte Angriffsflaechen
- Attack-Simulation mit Gate-Bypass: 3/4 Mutationen weiterhin „erfolgreich“ (Stego zerstoert, nicht HMAC)

## Erwartungshaltung fuer neue Aenderungen

Wenn du V6 weiterentwickelst, solltest du die Test-Suite nicht gegen fixe Wunschwerte optimieren, sondern gegen diese praktischen Ziele:

- Recovery Accuracy unter allgemeiner Korruption erhoehen
- Bit-Flip-Resistenz ueber `1%` bringen
- Angriffsreport und Benchmark weiterhin methodisch ehrlich halten
- keine stillen Datenkorruptionen einfuehren

## Report-Dateien

Nach einem aktuellen Lauf sind vor allem diese Dateien relevant:

- `attack_simulation_report.json` / `attack_simulation_report_per_channel.json`
- `resilience_metrics.json` / `resilience_metrics_per_channel.json`
- `security_test_results/master_security_report.json` (inkl. `assessment_breakdown`)

## Empfehlung

Nutze fuer echte Vergleiche immer `python master_test_suite.py` als serielle Referenz. Parallele Teststarts koennen unter Windows bei SQLite-Dateien zusaetzliche Locks und damit unnoetiges Rauschen erzeugen.
