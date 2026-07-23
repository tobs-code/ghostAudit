# Steganalysis Hardening Plan

Ziel: GhostAudit gegen einen aktiven Analysten resistent machen der statistisch nach
versteckten Daten sucht. Ursprünglich waren 4 primäre Angriffsvektoren offen; der
aktuelle V9-Umsetzungsstand ist unten markiert. Die Maßnahmen sind nach
Aufwand/Impact sortiert.

---

## Umsetzungsstand nach V9

| Problem | Status | Stand |
|---------|--------|-------|
| 4 — synthetische `sys_cache`-Tabelle | **Umgesetzt für V9** | `GhostAuditInterceptor` nutzt eine echte App-Tabelle via `CarrierConfig`; `sys_cache` wird im External-Carrier-Modus nicht angelegt. |
| 3 — Synonym-Verteilung | **Umgesetzt für V9** | `SemanticCalibrator` lernt Synonym-Häufigkeiten aus echten Carrier-Rows und wird per Hot-Swap thread-safe aktiviert. |
| 2 — Trailing-Space anomal | **Umgesetzt für V9** | V9 ersetzt den Trailing-Space-Carrier durch `TextShapeCarrier` (Oxford-Comma) mit deterministischem Round-Robin-Gating. |
| 1 — Float-LSB-Verteilung | **Umgesetzt für V9** | `FloatCalibrator` findet per `calibrate_floats()` die optimale Skalierung (best-scale fit) mit thread-safe Hot-Swap. |
| 6 — Temporale Korrelation | **Umgesetzt für V9.1** | `AdaptiveProbabilityScheduler` entkoppelt Schreibfrequenz von Event-Frequenz via EMA-Tracking; `temporal_delay_rows` bleibt als zusätzliche Jitter-Stufe. |
| 5 — Shuffling mit Master-Key rekonstruierbar | **Dokumentiert** | Kein Code-Fix geplant; Sicherheitsgrenze bleibt der Master-Key. |

**V9 erledigt den kritischen Architekturwechsel:** Events werden mit V7-ECC/RAID-6
codiert, als pending Payloads gehalten und über `intercept(row_id, fields)` in
normale App-Writes eingebettet. V9.1 ergänzt dies um einen **Adaptive Probability Scheduler**,
der die Schreibdichte dynamisch an die App-Aktivität anpasst, sowie eine **persistente Queue**,
die Audit-Integrität über Prozess-Restarts hinweg garantiert.

---

## Problem 1 — Float-LSB-Verteilung ist detektierbar

**Status V9:** teilweise umgesetzt.

**Was der Analyst sieht:**
`trust_score` und `profile_score` haben eine statistisch perfekte 50/50 LSB-Verteilung.
In echten Systemen sind Floats normalverteilt oder folgen Geschäftslogik — das LSB ist
dann nicht gleichverteilt. Chi²-Test oder Histogram reicht zur Detektion.

**Fix: Echte Baseline-Floats mit Stego-Overlay**

Statt Floats von Grund auf zu schreiben, existierende App-Werte minimal anpassen (±1
im 6. Dezimalstellenbereich). Das setzt voraus dass `sys_cache` wirklich eine aktive
Applikationstabelle ist (siehe Problem 4). Zusätzlich:

- Float-Werte dürfen nur in einem plausiblen Wertebereich liegen (z.B. 0.0–1.0 für
  Scores, nicht gleichverteilt)
- **Best-Scale-Fit:** `FloatCalibrator` sucht bei der Kalibrierung die Skalierung
  (z.B. 10^4 bis 10^7), bei der das natürliche Rauschen der App-Daten am nächsten
  an einer 50/50 LSB-Verteilung liegt.
- Das steganographische Overlay wird dann nur auf dieser optimalen Skalierungsebene
  aufgebracht, was die statistische Signatur (Chi²-Test) minimiert.
- LSB-Encoding auf `round(value * scale) % 2` bleibt erhalten, aber `scale` ist
  korpus-adaptiv.

**Implementierter Stand:** `FloatCalibrator` mit `calibrate_floats()`,
`measure_float_coverage()` und automatischer Skalierungswahl; Float-Carrier werden
erst nach Erreichen der Mindeststichprobe aktiviert.

**Aufwand:** Mittel — erfordert Anpassung von `encode_bit_float_lsb` und
`decode_bit_float_lsb` sowie Kenntnis der echten Score-Verteilung.

---

## Problem 2 — Trailing-Space-Häufigkeit ist anomal

**Status V9:** Umgesetzt.

V9 ersetzt den Payload-Trailing-Space-Carrier durch `TextShapeCarrier`. Der erste
Schnitt nutzt eine enge Oxford-Comma-Textform (`A, B and C` vs. `A, B, and C`) und
schreibt nur, wenn die Row diese Form sicher enthält. Ein deterministisches
Round-Robin-Verfahren (`row_idx % slot_size % 5`) weist jeder Zeile einen festen
logischen Kanal zu, was Kanal-Interferenzen verhindert. Wenn keine sichere
Textform für den zugewiesenen Kanal vorliegt, wird die Row übersprungen.

Design-Invariante: **Profil beeinflusst, ob wir schreiben, nicht wie wir lesen.**
Decode bleibt profilarm: erkennbare Textform → Bit, keine/mehrdeutige Textform →
Erasure bzw. nicht eligible Row.

**Was der Analyst sieht:**
In echten Bio-Texten gibt es nahezu keine Trailing Spaces. Ein einfaches
`SELECT COUNT(*) WHERE bio LIKE '% '` zeigt sofort eine unnatürliche Häufigkeit.
Selbst bei 50% Bit-1-Rate ist das ~50% aller Carrier-Rows — komplett auffällig.

**Fix: Carrier ersetzen oder verstecken**

Option A — Carrier wechseln: Trailing-Space durch einen unauffälligeren Carrier
ersetzen. Kandidaten:
- Interpunktionsvarianten (`. ` vs `…`) wenn im Korpus vorhanden
- Zeilenlängen-Parität (kurze vs lange Zeilen) wenn Bio-Texte variabel lang sind

Zero-width characters (z.B. U+200B) sind **nicht** der bevorzugte Fix. Sie sind
bekannt genug, dass forensische Unicode-Scans gezielt danach suchen. Besser sind
Carrier, die semantisch oder statistisch in normale Textvariation integriert sind.

**Bevorzugte Richtung:** Zeilenlängen-Parität oder Interpunktionsvarianten.
Zeilenlängen-Parität hat den Vorteil, dass Bio-Texte ohnehin natürlich in der Länge
variieren. Es gibt keinen einfachen Regex-Fingerprint wie bei Trailing-Spaces oder
Zero-width-Zeichen; ein Analyst müsste eine kontextabhängige Längenverteilung
modellieren.

**Implementierter erster Schnitt:** Interpunktionsvariante über Oxford-Comma-Formen.
Das ist bewusst konservativ und opportunistisch. Der nächste Schritt ist empirisch:
Wie viele echte Rows sind `TextShapeCarrier`-eligible, und reicht diese Kapazität
unter realer App-Write-Rate?

Option B — Normalisierungsschutz: Trailing-Space-Carrier nur auf Rows schreiben die
sowieso durch App-Writes berührt werden, sodass die Häufigkeit mit echter App-Aktivität
kovariiert.

**Aufwand:** Mittel — neuer Carrier, Anpassung von Encode/Decode, Carrier-Tabelle
in `SEMANTIC_MAP`-Äquivalent updaten.

---

## Problem 3 — Synonym-Verteilung ist nicht authentisch

**Status V9:** Umgesetzt.

V9 enthält `SemanticCalibrator`, der Synonym-Häufigkeiten aus den realen Carrier-Rows
liest und beim Encoding bevorzugt die im Korpus häufigeren Varianten nutzt. Aktivierung
erfolgt über `ga.calibrate()` mittels thread-safe Hot-Swap.

**Was der Analyst sieht:**
Die vier Synonym-Paare (`currently/presently`, `active/online`, etc.) sind in der
aktuellen Implementierung statistisch gleichverteilt (50/50 pro Paar). In echten
Nutzertexten gibt es starke Präferenzen — `currently` ist z.B. 3–4× häufiger als
`presently` im englischen Sprachgebrauch.

**Fix: Corpus-kalibriertes Synonym-Encoding**

1. Echte Häufigkeiten aus einem repräsentativen Textkorpus ermitteln
   (z.B. aus den tatsächlichen Nutzer-Bios der Zielanwendung)
2. Beim Encoding: Bit-0 → häufigeres Synonym (z.B. `currently`, ~75%),
   Bit-1 → selteneres (z.B. `presently`, ~25%)
3. Die resultierende Verteilung ist dann statistisch ununterscheidbar von echtem
   Nutzertext — ein Analyst sieht nur die erwartete Sprachpräferenz

**Abhängigkeit:** Erfordert Zugriff auf echte Nutzerdaten für Kalibrierung,
oder einen hochwertigen Textgenerator der den Nutzerstil imitiert.

`stego_templates.json` (V8.6) geht in diese Richtung, ist aber noch nicht
corpus-kalibriert.

**Aufwand:** Mittel bis Hoch — erfordert Korpus-Analyse und Anpassung von
`SEMANTIC_MAP` + Encoding-Logik in `encode_bit_semantic`.

---

## Problem 4 — `sys_cache` ist als synthetische Tabelle erkennbar

**Status V9:** umgesetzt für den External-Carrier-Pfad.

V9 führt `CarrierConfig` und `GhostAuditInterceptor` ein:
- vorhandene App-Tabelle wird als Carrier genutzt (`table`, `id_field`, Feldnamen konfigurierbar)
- `_V9Engine` überspringt die synthetische `sys_cache`-Initialisierung
- `_orig_ids` stammen aus den echten Primary Keys der App-Tabelle
- keine Write-Gate-Trigger auf der App-Tabelle
- `intercept(row_id, fields)` liefert modifizierte Felder für den normalen App-UPDATE zurück
- `recover_events()` dekodiert aus der externen Carrier-Tabelle

Abgedeckt durch `test_external_carrier_does_not_create_sys_cache`,
`test_external_carrier_orig_ids_from_real_table`,
`test_external_carrier_no_write_gate_on_app_table`,
`test_app_table_write_is_single_statement` und
`test_external_carrier_intercept_and_log`.

**Was der Analyst sieht:**
8000 Rows mit offensichtlich generierten Bios (4 rotierende Templates), gleichmäßig
verteilten Scores, keiner echten Aktivitätshistorie, keinen Foreign Keys zu anderen
Tabellen — das schreit nach einer Stego-Carrier-Tabelle.

**Das ist das fundamentale Problem.** Alle anderen Fixes helfen wenig solange
`sys_cache` als Artefakt erkennbar ist.

**Fix: `sys_cache` muss eine echte Applikationstabelle sein**

Das bedeutet: GhostAudit wird nicht *neben* die App gestellt, sondern *in* die App
integriert. Die Carrier-Rows sind echte Nutzer-Rows (z.B. `users`-Tabelle mit
`bio`, `trust_score`, `profile_score`, `avatar_url`).

Konkret:
- GhostAudit übernimmt eine vorhandene Tabelle als Carrier statt eine eigene anzulegen
- Die Applikation schreibt weiterhin normal in diese Tabelle
- GhostAudit-Writes passieren als minimale Overlays auf App-Writes (Hook-Architektur)
- Aus Sicht des Analysten: eine normale User-Tabelle mit normaler Aktivität

**Architektur-Implikation:**
```
App-Write → GhostAudit-Hook → Stego-Overlay → DB-Write
```
Statt:
```
App-Write → DB (audit_log)
GhostAudit-Write → DB (sys_cache, separat)
```

**Aufwand:** Hoch — fundamentale Architekturänderung. Erfordert:
- Konfigurierbarer Carrier-Tabellenname + Feldnamen statt Hardcoding
- Hook-API für App-seitige Integration
- Carrier-Initialisierung aus vorhandenen Daten statt synthetischer Generierung
- Statistik-Kalibrierung gegen echte App-Daten

---

## Problem 5 — Carrier-Shuffling ist deterministisch rekonstruierbar

**Was ein Analyst mit dem Master-Key tun würde:**
Da das Carrier-Shuffling via HMAC aus dem Master-Key abgeleitet wird, ist es für
jeden mit dem Key vollständig rekonstruierbar. Das ist by design für Recovery —
aber es bedeutet auch dass die Carrier-Zuordnung kein Geheimnis ist wenn der Key
kompromittiert ist.

Ohne Key ist das Shuffling opak — das ist die eigentliche Sicherheitsgrenze.
Kein Fix nötig, aber dokumentieren: **Sicherheit steht und fällt mit dem Master-Key.**

---

## Problem 6 — Temporale Korrelation von Carrier-Writes

**Status V9.1:** Umgesetzt.

**Was der Analyst sieht:**
V9 verschiebt Payload-Writes in normale App-Updates, aber ohne Scheduler entstehen
Schreib-Bursts unmittelbar nach Audit-Events. Ein Analyst mit Zeitreihen-Zugriff
könnte korrelierende Schreibmuster in der Carrier-Tabelle finden.

**Fix: Adaptive Probability Scheduler (V9.1)**

- **Frequenz-Messung:** Der Interceptor misst via Exponential Moving Average (EMA)
  sowohl die `app_write_rate` (App-Updates/s) als auch das `avg_event_interval`
  (Zeit zwischen Audit-Events).
- **Dynamisches p:** Statt einer fixen Wahrscheinlichkeit wird $p$ bei jedem
  `intercept()` neu berechnet: $p = \frac{\text{verbleibende\_bits}}{\text{target\_duration} \times \text{app\_write\_rate}}$.
- **Spread-Faktor:** Ein `target_spread_factor` (Default: 10.0) sorgt dafür, dass
  ein Audit-Event über die 10-fache Dauer des typischen Event-Intervalls gestreckt
  wird.
- **Multi-Process-Sicherheit:** Der Scheduler ist thread-safe (via Locking) und
  unterstützt multi-process Deployments. Da jeder Worker eine eigene RAM-Queue
  führt, erhöht sich die steganografische Entropie durch unabhängiges Scheduling.
- **Ergebnis:** Das Schreibmuster ist temporal vollständig entkoppelt. Selbst bei
  einem Event-Burst bleibt die Carrier-Schreibdichte stabil niedrig, während die
  `pending_queue` die Last abfängt.

**Aufwand:** Erledigt in V9.1.

---

## Prioritäten

| # | Problem | Impact auf Steganalyse-Resistenz | Aufwand |
|---|---------|----------------------------------|---------|
| 4 | Synthetische `sys_cache`-Tabelle | **Erledigt in V9** | Erledigt |
| 6 | Temporale Korrelation | **Erledigt in V9.1** — Adaptive Scheduler aktiv | Erledigt |
| 2 | Trailing-Space anomal | **Erledigt in V9** — `TextShapeCarrier` + Round-Robin | Erledigt |
| 1 | Float-LSB-Verteilung | **Erledigt in V9** — Best-Scale Fit + Hot-Swap | Erledigt |
| 3 | Synonym-Verteilung | **Erledigt in V9** — `SemanticCalibrator` + Hot-Swap | Erledigt |
| 5 | Shuffling deterministisch | Niedrig — nur mit Key angreifbar | Kein Fix |

**Ergebnis:** V9.2 schließt die wesentlichen Lücken der Steganalyse-Härtung. Alle
primären Carrier (Semantic, Float, TextShape, Avatar) sind nun korpus-adaptiv,
thread-safe und durch einen temporal entkoppelten Scheduler geschützt.

Problem 4 war die Voraussetzung für alle anderen und ist im V9-Pfad umgesetzt.
Dadurch werden 1–3 teilweise durch echtes Datenrauschen entschärft, aber nicht
vollständig gelöst. Der nächste harte Schritt bei Problem 2 ist nicht mehr das
Entfernen von Trailing-Space selbst, sondern Kapazitäts- und Unauffälligkeitsmessung
des `TextShapeCarrier` auf einem realistischen Korpus. Problem 6 ist bereits
teilweise entschärft, muss aber noch auf Scheduler-Ebene ausgebaut werden, damit die
Write-Timing-Signatur weiter sinkt. Problem 1 hat nun Warm-up-Gating und
Coverage-Messung; als Nächstes fehlt der eigentliche Verteilungsfit.

**Messfunktion:** V9 hat `measure_text_shape_coverage(sample_size=...)` als
empirische Schranke. Sie misst, welcher Anteil der Carrier-Rows die Oxford-Comma-
Textform überhaupt sicher tragen kann. Diese Coverage-Zahl ist der nächste
entscheidende Input für die Carrier-Kapazität. Für Problem 1 ist die analoge Metrik
`measure_float_coverage()` bzw. der Status von `FloatCalibrator.ready`. Für Problem 6
ist der relevante Messwert die beobachtete Zeitdifferenz zwischen `log_event()` und
erstem Carrier-Write bei unterschiedlichen `temporal_delay_rows`-Werten.

**Threat-Model-Erweiterung:** Der Plan adressiert bis hierher primär passive Steganalyse plus forensische Zeitreihenanalyse. Ein aktiver Analyst mit Schreibrechten, der gezielt Carrier-Rows modifiziert und Recovery-Verhalten beobachtet, ist ein separates V9-Threat-Model-Update und sollte als eigener Planabschnitt behandelt werden.

---

## Active Analyst Threat Model (Neu in V9.2)

Ein aktiver Analyst geht über die rein statistische Beobachtung (passive Steganalyse)
hinaus und manipuliert gezielt Daten, um die Reaktion des Systems zu provozieren.

### Vektor A — Probe & Tamper (Gezielte Korruption)
Der Analyst vermutet einen Carrier in einer bestimmten Spalte und flippt dort Bits.
- **Abwehr:** GhostAudit nutzt **Row-level HMACs** im Manifest. Jede Manipulation
  an einer Carrier-Row wird beim Recovery-Versuch sofort als Erasure erkannt.
- **Resilienz:** Dank **RAID-6 (P+Q)** und **Reed-Solomon** kann das System den
  Verlust von bis zu zwei kompletten physischen Carriern (z.B. `bio` und `trust_score`)
  kompensieren, ohne dass Daten verloren gehen.

### Vektor B — Column Wipe (Großflächiges Löschen)
Der Analyst setzt eine komplette Spalte auf Null oder Default-Werte (z.B. alle Bios löschen).
- **Abwehr:** Das **HMAC-basierte Shuffling** verteilt die logischen Kanäle (Data 0-2, P, Q)
  über alle 5 physischen Spalten. Das Löschen einer Spalte führt nur zum Verlust von
  ca. 20% der Bits pro logischem Kanal, was weit innerhalb der RS-Korrekturkapazität liegt.
- **Detektion:** Die `verify_merkle_root()`-Funktion erkennt sofort, dass der
  Carrier-Layer großflächig manipuliert wurde, selbst wenn die Recovery noch gelingt.

### Vektor C — Timing & Correlation (Schreibmuster-Analyse)
Der Analyst löst ein Audit-Event aus und beobachtet, welche DB-Zeilen sich unmittelbar danach ändern.
- **Abwehr:** Der **Adaptive Probability Scheduler (V9.1)** entkoppelt den Schreibvorgang
  zeitlich vom Event. Die Bits werden stochastisch über einen Zeitraum (`target_spread_factor`)
  verteilt, der deutlich über dem normalen Event-Intervall liegt.
- **Jitter:** Zusätzliche `temporal_delay_rows` sorgen dafür, dass selbst der Start
  des Embeddings nicht deterministisch mit dem Event-Zeitpunkt korreliert.

### Vektor D — Forensic Injection (Gefälschte Events)
Der Analyst versucht, eigene Stego-Bits in die Carrier-Rows zu schreiben, um das Audit-Log zu korrumpieren.
- **Abwehr:** Ohne den **Master-Key** kann der Analyst die HMAC-shuffled Positionen
  nicht berechnen. Jedes Bit, das nicht an der kryptographisch erwarteten Stelle
  liegt oder dessen Row-MAC nicht passt, wird ignoriert.
- **Integrität:** Die Merkle-Anchor-Chain in Verbindung mit dem **Git-Witness (V8.5)**
  stellt sicher, dass keine historischen Events unentdeckt verändert oder injiziert werden können.

---

## Fazit & Nächste Schritte

---

## Was sich nicht ändern muss

- RAID-6, Reed-Solomon, Merkle, Forward Secrecy — alles gut
- Checkpoint/Git-Witness — löst das externe Trust-Problem sauber
- Write-Gate — sinnvolle Defense-in-Depth
- Rollback-Erkennung via `.evolve` — funktioniert unabhängig von Steganalyse-Resistenz
