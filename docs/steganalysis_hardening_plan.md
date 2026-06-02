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
| 3 — Synonym-Verteilung | **Teilweise umgesetzt** | `SemanticCalibrator` lernt Synonym-Häufigkeiten aus echten Carrier-Rows und kann per `ga.calibrate()` aktiviert werden. |
| 2 — Trailing-Space anomal | **Teilweise umgesetzt** | V9 ersetzt den Payload-Trailing-Space-Carrier durch `TextShapeCarrier` mit row-level gating; breitere Korpusvalidierung offen. |
| 1 — Float-LSB-Verteilung | **Teilweise/Offen** | V9 überlagert echte App-Floats statt synthetische Scores zu erzeugen; dynamische Verteilungskalibrierung für Float-LSB fehlt noch. |
| 6 — Temporale Korrelation | **Teilweise umgesetzt** | V9 nutzt `temporal_delay_rows` als kleinen, deterministischen Puffer vor Payload-Verbrauch; weitergehende Scheduler-Entkopplung bleibt offen. |
| 5 — Shuffling mit Master-Key rekonstruierbar | **Dokumentiert** | Kein Code-Fix geplant; Sicherheitsgrenze bleibt der Master-Key. |

**V9 erledigt den kritischen Architekturwechsel:** Events werden mit V7-ECC/RAID-6
codiert, als pending Payloads gehalten und über `intercept(row_id, fields)` in
normale App-Writes eingebettet. Header-Rows werden pro Slot reserviert und nach
vollständigem Payload-Embedding via `flush_headers()` bzw. vor `recover_events()`
geschrieben. Der External-Carrier-End-to-End-Pfad ist durch
`tests/test_v9_interceptor.py` abgedeckt.

---

## Problem 1 — Float-LSB-Verteilung ist detektierbar

**Status V9:** teilweise entschärft, aber nicht vollständig gelöst.

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
- LSB-Encoding auf `round(value * scale) % 2` beibehalten, aber `scale` dynamisch
  wählen sodass die resultierende Verteilung die echte App-Verteilung imitiert
- Alternativ: Float-Carrier durch einen Carrier ersetzen der keine statistischen
  Fingerabdrücke hinterlässt (z.B. Integer-Felder mit hoher Kardinalität)

**Offenes Henne-Ei-Problem:** Für echte Kalibrierung braucht das System echte
App-Daten. Beim ersten Deployment kann diese Baseline fehlen oder noch zu klein sein.
Mögliche Betriebsmodi:
- **Warm-up-Modus:** Carrier-Rows und Score-Verteilungen nur beobachten, noch keine
  Float-Bits schreiben, bis Mindeststichprobe und Driftgrenzen erreicht sind.
- **Konfigurierter Prior:** Betreiber liefert erwartete Score-Verteilung, Wertebereich
  und erlaubte Quantisierung; GhostAudit startet konservativ und lernt später nach.
- **Carrier-Gating:** Float-Carrier erst aktivieren, wenn ein Kalibrator genügend
  Datenpunkte und stabile Histogramme gesehen hat; bis dahin nur robustere Carrier nutzen.

**Aufwand:** Mittel — erfordert Anpassung von `encode_bit_float_lsb` und
`decode_bit_float_lsb` sowie Kenntnis der echten Score-Verteilung.

---

## Problem 2 — Trailing-Space-Häufigkeit ist anomal

**Status V9:** teilweise umgesetzt.

V9 ersetzt den Payload-Trailing-Space-Carrier durch `TextShapeCarrier`. Der erste
Schnitt nutzt eine enge Oxford-Comma-Textform (`A, B and C` vs. `A, B, and C`) und
schreibt nur, wenn die Row diese Form sicher enthält. Wenn keine sichere Textform
vorliegt, gibt `intercept_result()` `modified=False` mit `reason="carrier_gating:..."`
zurück und das pending Payload-Bit wird **nicht** verbraucht.

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

**Status V9:** teilweise umgesetzt.

V9 enthält `SemanticCalibrator`, der Synonym-Häufigkeiten aus den realen Carrier-Rows
liest und beim Encoding bevorzugt die im Korpus häufigeren Varianten nutzt. Aktivierung
erfolgt über `ga.calibrate()`. Offen bleibt die Validierung gegen größere reale Korpora
und die Frage, ob die lokale Synonym-Liste ausreichend breit ist.

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

**Status V9:** teilweise umgesetzt.

**Was der Analyst sieht:**
V9 verschiebt Payload-Writes in normale App-Updates, aber ein Analyst mit DB-Forensik
kann Zeitreihen auswerten: `updated_at`-Felder, WAL-Schreibmuster, Trigger-Logs,
App-Events und Audit-Frequenz. Wenn ein Audit-Event unmittelbar danach zufällige
Carrier-Row-Updates erzeugt, entsteht ein Muster wie:

```
login event → kurz danach User-Bio/Profile-Update
```

Das ist kein kryptographischer Bruch, aber ein forensisches Signal. Besonders kritisch
ist der Metronome-Heartbeat: `[METRONOME]` alle exakt N Sekunden kann ein regelmäßiges
Schreibmuster in der Carrier-Tabelle erzeugen. Auch ohne Payload-Inhalt wäre ein
300-Sekunden-Rhythmus auffällig.

V9 entschärft den direkten Zusammenhang mit einem kleinen deterministischen
`temporal_delay_rows`-Puffer pro Payload. Das glättet den sofortigen
`log_event()` → `intercept()`-Pfad, ersetzt aber noch keinen echten Scheduler.

**Fix: Opportunistisches und entkoppeltes Scheduling**

- Pending Payloads nicht sofort nach `log_event()` aggressiv drainen, sondern nur auf
  ohnehin auftretende App-Writes legen.
- Row-Auswahl und Drain-Rate an echte App-Aktivitätsverteilung koppeln, inklusive
  Backpressure wenn nicht genug natürliche Writes passieren.
- Header-Flush nicht unmittelbar nach Payload-Ende erzwingen, sondern in ein
  plausibles Wartungs-/App-Write-Fenster legen.
- Metronome-Events jittered und/oder opportunistisch schreiben: Heartbeat als logische
  Deadline behandeln, nicht als exakt periodischen DB-Write.
- Optional Cover-Traffic nur dann nutzen, wenn die Zielanwendung ohnehin ähnliche
  Hintergrundupdates hat; sonst erzeugt Cover-Traffic selbst ein Signal.

**Aufwand:** Mittel bis Hoch — erfordert einen Scheduler für pending Payloads,
Zeitfenster/Jitter-Policy, App-Aktivitätsmodell und Tests gegen Zeitreihenanalyse.
Die aktuelle `temporal_delay_rows`-Stufe ist nur der erste Schritt.

---

## Prioritäten

| # | Problem | Impact auf Steganalyse-Resistenz | Aufwand |
|---|---------|----------------------------------|---------|
| 4 | Synthetische `sys_cache`-Tabelle | **Erledigt in V9** — External-Carrier-Pfad vorhanden | Erledigt |
| 3 | Synonym-Verteilung nicht authentisch | Teilweise erledigt — `SemanticCalibrator`, Validierung offen | Rest: Mittel |
| 2 | Trailing-Space anomal | Teilweise erledigt — `TextShapeCarrier`, Korpusvalidierung offen | Rest: Mittel |
| 1 | Float-LSB-Verteilung | Teilweise entschärft — echte Baseline-Floats, Kalibrierung offen | Mittel |
| 6 | Temporale Korrelation | Teilweise erledigt — kleiner Delay-Puffer vorhanden, Scheduler offen | Mittel bis Hoch |
| 5 | Shuffling deterministisch | Niedrig — nur mit Key angreifbar | Kein Fix |

**Neue sinnvolle Reihenfolge:** 2-Korpusvalidierung → 6-Ausbau → 1 → 3-Validierung

Problem 4 war die Voraussetzung für alle anderen und ist im V9-Pfad umgesetzt.
Dadurch werden 1–3 teilweise durch echtes Datenrauschen entschärft, aber nicht
vollständig gelöst. Der nächste harte Schritt bei Problem 2 ist nicht mehr das
Entfernen von Trailing-Space selbst, sondern Kapazitäts- und Unauffälligkeitsmessung
des `TextShapeCarrier` auf einem realistischen Korpus. Problem 6 ist bereits
teilweise entschärft, muss aber noch auf Scheduler-Ebene ausgebaut werden, damit die
Write-Timing-Signatur weiter sinkt.

**Messfunktion:** V9 hat `measure_text_shape_coverage(sample_size=...)` als
empirische Schranke. Sie misst, welcher Anteil der Carrier-Rows die Oxford-Comma-
Textform überhaupt sicher tragen kann. Diese Coverage-Zahl ist der nächste
entscheidende Input für die Carrier-Kapazität. Für Problem 6 ist der relevante
Messwert künftig die beobachtete Zeitdifferenz zwischen `log_event()` und erstem
Carrier-Write bei unterschiedlichen `temporal_delay_rows`-Werten.

**Threat-Model-Erweiterung:** Der Plan adressiert bis hierher primär passive
Steganalyse plus forensische Zeitreihenanalyse. Ein aktiver Analyst mit Schreibrechten,
der gezielt Carrier-Rows modifiziert und Recovery-Verhalten beobachtet, ist ein
separates V9-Threat-Model-Update und sollte als eigener Planabschnitt behandelt werden.

---

## Was sich nicht ändern muss

- RAID-6, Reed-Solomon, Merkle, Forward Secrecy — alles gut
- Checkpoint/Git-Witness — löst das externe Trust-Problem sauber
- Write-Gate — sinnvolle Defense-in-Depth
- Rollback-Erkennung via `.evolve` — funktioniert unabhängig von Steganalyse-Resistenz
