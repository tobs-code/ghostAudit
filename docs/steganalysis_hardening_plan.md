# Steganalysis Hardening Plan

Ziel: GhostAudit gegen einen aktiven Analysten resistent machen der statistisch nach
versteckten Daten sucht. Aktuell sind 4 Angriffsvektoren offen. Die Maßnahmen sind
nach Aufwand/Impact sortiert.

---

## Problem 1 — Float-LSB-Verteilung ist detektierbar

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

**Aufwand:** Mittel — erfordert Anpassung von `encode_bit_float_lsb` und
`decode_bit_float_lsb` sowie Kenntnis der echten Score-Verteilung.

---

## Problem 2 — Trailing-Space-Häufigkeit ist anomal

**Was der Analyst sieht:**
In echten Bio-Texten gibt es nahezu keine Trailing Spaces. Ein einfaches
`SELECT COUNT(*) WHERE bio LIKE '% '` zeigt sofort eine unnatürliche Häufigkeit.
Selbst bei 50% Bit-1-Rate ist das ~50% aller Carrier-Rows — komplett auffällig.

**Fix: Carrier ersetzen oder verstecken**

Option A — Carrier wechseln: Trailing-Space durch einen unauffälligeren Carrier
ersetzen. Kandidaten:
- Zero-width characters (U+200B) am Satzende — in Unicode-Datenbanken plausibel,
  schwerer zu entdecken als Leerzeichen
- Interpunktionsvarianten (`. ` vs `…`) wenn im Korpus vorhanden
- Zeilenlängen-Parität (kurze vs lange Zeilen) wenn Bio-Texte variabel lang sind

Option B — Normalisierungsschutz: Trailing-Space-Carrier nur auf Rows schreiben die
sowieso durch App-Writes berührt werden, sodass die Häufigkeit mit echter App-Aktivität
kovariiert.

**Aufwand:** Mittel — neuer Carrier, Anpassung von Encode/Decode, Carrier-Tabelle
in `SEMANTIC_MAP`-Äquivalent updaten.

---

## Problem 3 — Synonym-Verteilung ist nicht authentisch

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

## Prioritäten

| # | Problem | Impact auf Steganalyse-Resistenz | Aufwand |
|---|---------|----------------------------------|---------|
| 4 | Synthetische `sys_cache`-Tabelle | **Kritisch** — alles andere baut darauf | Hoch |
| 3 | Synonym-Verteilung nicht authentisch | Hoch — einfachster statistischer Test | Mittel |
| 2 | Trailing-Space anomal | Hoch — trivial detektierbar | Mittel |
| 1 | Float-LSB-Verteilung | Mittel — braucht mehr Analyse | Mittel |
| 5 | Shuffling deterministisch | Niedrig — nur mit Key angreifbar | Kein Fix |

**Sinnvolle Reihenfolge:** 4 → 3 → 2 → 1

Problem 4 ist die Voraussetzung für alle anderen — wenn `sys_cache` eine echte
App-Tabelle ist, lösen sich 1–3 teilweise von selbst durch echtes Datenrauschen.

---

## Was sich nicht ändern muss

- RAID-6, Reed-Solomon, Merkle, Forward Secrecy — alles gut
- Checkpoint/Git-Witness — löst das externe Trust-Problem sauber
- Write-Gate — sinnvolle Defense-in-Depth
- Rollback-Erkennung via `.evolve` — funktioniert unabhängig von Steganalyse-Resistenz
