# GhostAudit V8 — Orthogonal Grid Defense

> **Wichtig:** Dieses Projekt ist ein Forschungs- und Lernprojekt. Es ist **nicht** als Produktions-Auditsystem gedacht.

GhostAudit versteckt Audit-Logs steganographisch in normalen SQLite-Nutzerdaten. Ein privilegierter Angreifer, der die sichtbaren Log-Tabellen löscht, findet die echten forensischen Daten nicht — sie sind unsichtbar in Carrier-Feldern eingebettet und kryptographisch gesichert.

---

## Architektur auf einen Blick (V8 Multiplexing)

```
┌───────────────────────────────────────────────────────────┐
│                      SQLite Datenbank                     │
│                                                           │
│  ┌──────────────┐  ┌───────────────────────────────────┐ │
│  │  audit_log   │  │   sys_cache (HIDDEN LAYER)        │ │
│  │  (Köder)     │  │                                   │ │
│  │              │  │  Slot 0…4  (je 1600 Zeilen)       │ │
│  │  audit_      │  │  ┌─────────────────────────────┐  │ │
│  │  archive     │  │  │ Jede Zeile = alle 5 Kanäle  │  │ │
│  │  (Decoy)     │  │  │ ┌─Ch0──Ch1──Ch2──Ch3──Par.─┐ │  │ │
│  └──────────────┘  │  │ │ RS   RS   RS   RS   XOR+RS│ │  │ │
│                    │  │ └──────────────────────────┘ │  │ │
│                    │  │ Row-MAC (5×8-Byte HMACs)       │  │ │
│                    │  │ HKDF-SlotKeys · Carrier-       │  │ │
│                    │  │   Shuffle pro Zeile (5 Träger)│  │ │
│                    │  └─────────────────────────────┘  │ │
│                    └───────────────────────────────────┘ │
└───────────────────────────────────────────────────────────┘
```

**Kernunterschied zu V7:** Während V7 jedem logischen Kanal eine eigene Teilmenge der Zeilen zuwies (Round-Robin), kodiert V8 **alle 5 Kanäle gleichzeitig in jede Zeile**. Jede Zeile trägt 1 Bit von Kanal 0, 1 Bit von Kanal 1, 1 Bit von Kanal 2, 1 Bit von Kanal 3 und 1 Bit vom Paritätskanal — via per-Zeilen-Shuffle auf 5 physische Carrier verteilt.

Die ECC-Kapazität jedes Kanals steigt dadurch auf das **Vierfache** (alle Zeilen statt ¼ der Zeilen).

### Fünf Stego-Kanäle (5 Bit pro Carrier-Zeile, Carrier-Shuffling pro Zeile)

| Kanal | Physischer Carrier | Feld | Methode |
|-------|--------------------|------|---------|
| Ch0 | 0 — Semantik | `bio` (Text) | Synonym-Switching (4 Wortpaare: `currently/presently`, `active/online`, `working/operating`, `system/platform`) |
| Ch1 | 1 — Float-LSB | `trust_score` (Float) | **LSB-Matching ±1** (stochastisch, undetektierbar) |
| Ch2 | 2 — Trailing-Space | `bio` (Text) | Leerzeichen am Ende |
| Ch3 | 3 — Float-LSB | `profile_score` (Float) | **LSB-Matching ±1** (stochastisch, undetektierbar) |
| Ch4 | 4 — Tilde-Suffix | `avatar_url` (Text) | URL endet auf `~` = Bit 1, kein `~` = Bit 0 — ORM-invariant (RFC-3986 unreserved) |

**Carrier-Shuffling:** Jede Zeile bildet die 5 physischen Carrier via HMAC-basierter Permutation auf 5 logische Kanäle (4 Daten + 1 Parität) ab. Ein Angriff auf einen physischen Carrier schädigt daher alle 5 logischen Kanäle gleichmäßig (~20% pro Kanal).

> **Bio-SPOF Fix:** Carrier 3 war ursprünglich `Case-Switching` auf `bio`. ORM-Normalisierung (lowercase, trim, synonym-flatten) zerstört jedoch **alle 3 bio-basierten Carrier** (Semantik, Case, Trailing-Space) gleichzeitig → Single-Point-of-Failure.  
> `profile_score REAL` ist eine unabhängige Float-Spalte (DDL: `profile_score REAL NOT NULL DEFAULT 0.0`), die von ORM-Operationen auf `bio` nicht betroffen ist. Initialisiert mit Gauß-verteilten Werten (μ=0.5, σ=0.15) pro Row.  
> **Konsequenz:** Bio-Normalize killt nun 2/5 Carrier (Semantik + Trailing-Space) statt 3/5 — reduziert die ECC-Last von 60% auf 40% Fehlerrate.

### Schutzschichten (innen → außen)

1. **Reed-Solomon ECC** — Per-Channel-RS auf 4 Datenkanälen (plus 1 Parität), korrigiert bis zu `nsym` Byte-Erasures pro Kanal (doppelt so viele wie Errors, da Erasure-Positionen bekannt sind); nsym wird automatisch via `SELECT_ECC` gewählt
2. **Replikation über konsekutive Zeilen** — jedes Bit-Tupel (b0,b1,b2,b3,b4) wird in `repetitions` aufeinanderfolgende Zeilen geschrieben, Majority-Vote + MAC-Verifikation bei Extraktion (dynamisch: 1–5 Repliken je nach verbleibender Kapazität)
3. **Per-Channel Row-MAC (V8)** — 5 separate 8-Byte-HMACs pro Zeile (übers extrahierte Stego-Bit pro Kanal), ermöglicht **Erasure-Detection** auf Kanal-Ebene
4. **HMAC-SHA256** — 16-Byte-MAC pro Payload-Block, Forgery blockiert
5. **XOR Cross-Channel Parity** — rekonstruiert einen verlorenen Datenkanal aus den restlichen 3 Datenkanälen + Parität
6. **Carrier-Shuffling** — HMAC-basierte Permutation der physischen Carrier pro Zeile, Angreifer kennt Zuordnung nicht
7. **Forward-secure Slot-Keys** — jeder Slot nutzt HKDF-abgeleiteten Subkey (Kompromittierung eines Slots gefährdet keine anderen)
8. **SQLite-Trigger Schreib-Gate** — blockiert unkontrollierte `sys_cache`-Writes
9. **Merkle-Root Verifikation** — kryptographischer Fingerabdruck über alle 5 Slots
10. **Forward Secrecy (Anchor-Keys)** — Key-Evolution nach jedem Event schützt alte Anchors vor Kompromittierung
11. **Proactive Self-Healing (V8.4)** — degradierte Slots werden im Hintergrund mit erhöhten ECC-Parametern neu geschrieben; Rebuilds sind forensisch als `[GHOST_REBUILD]`-Events dokumentiert

---

## V8.4 Proactive Self-Healing (Hintergrund-Rebuild)

Während V8.2 die ECC-Parameter *reaktiv* beim nächsten Write erhöht, schreibt V8.4 degradierte Slots **proaktiv** neu — bevor ein weiterer Angriff die verbleibende RS-Kapazität aufbraucht.

### Architektur

```
log_event() — nach dem Write-Gate:
    │
    ▼
_idle_restore_check()          ← rate-limitiert: 1× alle 50 Events
    │
    ├─ sys_channel_quality scannen
    │   MAX(erasure_pct) pro Slot
    │
    └─ Slot degradiert? (≥ 0.35)
        │
        ▼
    _migrate_slot(slot_idx)
        │
        ├─ 1. _recover_single_slot()   ← isolierte Recovery (kein Event-Pipeline-Eingriff)
        │       Header-Decode → _extract_all_channels_v8 → RS-Decode → RAID-6 → HMAC-Check
        │
        ├─ 2. Rebuild-nsym berechnen
        │       nsym = max(adaptive_nsym + 8, ECC_REBUILD_NSYM=52)
        │       nsym = min(nsym, payload_rows // 8)   ← Kapazitäts-Cap
        │
        ├─ 3. _write_sys_cache_slot_v8()   ← direkt, umgeht Event-Pipeline
        │       Key-State / evolve_count / Merkle bleiben unberührt
        │
        └─ 4. log_event("[GHOST_REBUILD] slot=N …")   ← forensische Transparenz
               Bei Totalverlust: log_event("[GHOST_REBUILD_FAILED] slot=N …")
```

### Forensische Transparenz

Jeder Rebuild erzeugt ein vollwertiges Audit-Event:

```
[GHOST_REBUILD] slot=2 seq=17 old_nsym=36 new_nsym=52 reps=4
```

Das macht die Kette **Carrier-Verschlechterung → Migration** für den Analysten lückenlos nachvollziehbar. Ein unrettbarer Slot wird als:

```
[GHOST_REBUILD_FAILED] slot=2 carrier_total_loss=True
```

dokumentiert — der Carrier-Totalverlust ist damit selbst Teil der Audit-Kette.

### nsym-Berechnung im Rebuild

Der Rebuild-nsym ist immer **mindestens so stark wie der aktuelle adaptive State**:

```python
target_nsym = max(adaptive_nsym + 8, ECC_REBUILD_NSYM)   # nie schwächer als adaptiv
rebuild_nsym = min(target_nsym, payload_rows // 8)         # Kapazitäts-Cap
```

Beispiel: Adaptiver State hat `nsym=44` (D=0.3 → +8 Bump). Rebuild nimmt `max(44+8, 52) = 52`. Bei sehr hoher Degradation (D>0.6, adaptiv=60): `max(60+8, 52) = 68`, gedeckelt auf Slot-Kapazität.

### Rekursionsschutz

`_idle_restore_check()` wird in `log_event()` nur für echte User-Events aufgerufen — `[GHOST_REBUILD*]`- und `[METRONOME]`-Events sind explizit ausgenommen:

```python
if not event_msg.startswith(("[GHOST_REBUILD]", "[GHOST_REBUILD_FAILED]", "[METRONOME]")):
    self._idle_restore_check()
```

### Modul-Level-Konstanten (Env-Var-Override)

| Konstante | Default | Env-Var | Beschreibung |
|-----------|---------|---------|--------------|
| `ECC_REBUILD_NSYM` | `52` | `GHOST_AUDIT_REBUILD_ECC_SYMBOLS` | Rebuild-nsym (Untergrenze) |
| `ECC_REBUILD_REPS` | `4` | `GHOST_AUDIT_REBUILD_MIN_REPS` | Rebuild-Replikationen (Untergrenze) |
| `REBUILD_DEGRADATION_THRESHOLD` | `0.35` | `GHOST_AUDIT_REBUILD_THRESHOLD` | Degradations-Schwelle für Rebuild-Trigger |
| `REBUILD_CHECK_INTERVAL` | `50` | `GHOST_AUDIT_REBUILD_INTERVAL` | Events zwischen zwei Idle-Checks |

### Neue Methoden

| Methode | Beschreibung |
|---------|--------------|
| `_recover_single_slot(cursor, slot_idx)` | Isolierte Recovery eines Slots; gibt `(stored_msg_bytes, compressed, nsym, seq)` zurück oder `None` |
| `_migrate_slot(slot_idx)` | Rebuild-Logik: Recovery → Boost-Encode → `_write_sys_cache_slot_v8` → Audit-Event |
| `_idle_restore_check()` | Heuristik: scannt `sys_channel_quality`, triggert `_migrate_slot` für degradierte Slots |

---

### Multiplexing (alle 5 Kanäle pro Zeile)

V8 schreibt nicht mehr Round-Robin (`Zeile 0→Kanal 0`, `Zeile 4→Kanal 0`, …), sondern **jede Zeile kodiert alle 5 Kanäle gleichzeitig**:

```
V7 (Round-Robin):             V8 (Multiplexing):
Zeile 0: Ch0_bit[0]           Zeile 0: {Ch0_bit[0], Ch1_bit[0], Ch2_bit[0], Ch3_bit[0], P_bit[0]}
Zeile 1: Ch1_bit[0]           Zeile 1: {Ch0_bit[0], Ch1_bit[0], Ch2_bit[0], Ch3_bit[0], P_bit[0]}  ← Rep
Zeile 2: Ch2_bit[0]           Zeile 2: {Ch0_bit[1], Ch1_bit[1], Ch2_bit[1], Ch3_bit[1], P_bit[1]}
Zeile 3: P_bit[0]             Zeile 3: {Ch0_bit[1], Ch1_bit[1], Ch2_bit[1], Ch3_bit[1], P_bit[1]}  ← Rep
Zeile 4: Ch0_bit[0] (Rep)     ...
```

- **1× SELECT + UPDATE** pro Zeile (alle Kanäle in einem Durchlauf)
- **ECC-Kapazität ×4** pro Kanal (alle Zeilen statt ¼)
- **Konsekutive Repetition** des Bit-Tupels (b0,b1,b2,b3,b4) statt verstreuter Repliken → besserer Lokalitäts-Schutz

### Per-Channel Row-MAC (5×8 Byte)

`_sys_cache_row_mac()` erzeugt 5 separate 8-Byte-HMACs über die **extrahierten Stego-Bits** jedes Kanals, verpackt in ein 40-Byte-BLOB:

```
row_mac BLOB (40 Bytes):
├── Bytes  0-7:  HMAC(k, row_id || 0x00 || bit_ch0)[:8]
├── Bytes  8-15: HMAC(k, row_id || 0x01 || bit_ch1)[:8]
├── Bytes 16-23: HMAC(k, row_id || 0x02 || bit_ch2)[:8]
├── Bytes 24-31: HMAC(k, row_id || 0x03 || bit_ch3)[:8]
└── Bytes 32-39: HMAC(k, row_id || 0x04 || bit_ch4)[:8]
```

**Erasure-Bonus:** Schlägt ein Channel-MAC fehl, wird dieses Bit als **Erasure** markiert. RS korrigiert Erasures doppelt so effizient wie Errors (`RS(n,k)` korrigiert bis zu `(n-k)` Erasures statt `(n-k)/2` Errors). Ein ORM, das `TRIM()` ausführt, erzeugt bekannte Erasures — das spielt direkt in die Hände des Decoders.

### Per-Fragment RS Decode (Fix: Doppel-Decode-Korruption)

Ursprünglich wurden Replikat-Daten per **Byte-Level Majority-Vote** gemergt und dann einmal RS-decodiert. Problem: Bei 75% Fragment-Disagreement erzeugt Majority-Vote Coin-Flip-Bytes → RS kann nicht korrigieren.

**Fix:** Jedes Fragment durchläuft RS-Decode **unabhängig**. Das erste Fragment mit sauberem RS-Decode gewinnt. Rohdaten werden **roh** (encoded) pro Fragment gespeichert — kein zweiter RS-Durchlauf auf bereits decodierten Bytes.

```
# Vorher (byte-merge):   rep0_raw + rep1_raw + rep2_raw → majority-vote → merged_bytes → RS_decode
# Nachher (per-fragment): rep0_raw → RS_decode → OK? → nimm rep0
#                         rep1_raw → RS_decode → OK? → nimm rep1  (fallback)
#                         rep2_raw → RS_decode → OK? → nimm rep2  (fallback)
#                         byte-merge → RS_decode                 (letzter Ausweg)
```

**Ergebnis:** Solange mindestens 1 Fragment pro Kanal sauber RS-decodiert (≤nsym Erasures), ist die Recovery erfolgreich — unabhängig vom Disagreement-Grad mit anderen Fragmenten.

### Write- und Extract-Pipeline (V8)

```python
# Write: alle 5 Kanäle simultan in jeden Slot schreiben
channel_blocks = ga._encode_payload_per_channel_v7(payload_bytes, nsym)
ga._write_sys_cache_slot_v8(cursor, channel_blocks, slot_payload_ids)

# Extract: alle 5 Kanäle in einem DB-Pass lesen + MAC-Verifikation
slot_channel_bytes, slot_erasures = ga._extract_all_channels_v8(
    cursor, slot_payload_ids, max_bits
)

# RS-Decode mit Erasure-Positionen (doppelte Korrektur-Kapazität)
decoded = RSCodec(nsym).decode(
    per_channel_encoded[c],
    erase_pos=per_channel_erasures.get(c, []),
)
```

### Weitere V7→V8-Änderungen

- **Keyed Magic-Byte** statt hartkodierter Konstanten: `magic = HMAC(k_magic, domain_label)[0]` — kein fixer Marker für Angreifer (keine Inkompatibilität, da Key-Basis gleich)
- **Gaussian Seed** aus Master-Key abgeleitet: `seed_int = int.from_bytes(k_shuffling[:8], 'big')` statt hartkodiertem `1234`
- **Padding mit Zufallsbits** statt Nullbits (vermeidet Steganalyse-Zero-Bias)
- Obsolete V7-Helper (`_channel_payload_ids`, `_channel_carrier_order`) entfernt
- **Rollback-Schutz in Batch-API**: `log_events` / `log_event` führen bei Fehler `conn.rollback()` aus — kein halbgeschriebener DB-Zustand mehr
- **`immediate_commit=False` Parameter**: `log_event(msg, immediate_commit=False)` und `log_events(msgs, immediate_commit=False)` deferieren Commit und Merkle-Anchor. Caller commitet manuell via `g.conn.commit()` und ruft `g.anchor_merkle_root(seq)` für jede Sequence. Nützlich für externe Transaktionssteuerung.
- **Slot-Sequence-Header-Cache**: `_scan_slots` cached das Resultat in `_cached_slot_sequences`. Nach jedem Write wird der Cache in-place aktualisiert. Spart 360 SQL-Queries bei sequentiellen `log_event`-Aufrufen.

---

## V8.1 Bulk-Staging (Performance-Optimierung)

Die V8.1-Optimierungen adressieren das SQLite-I/O-Nadelöhr: Statt 13.500 Einzel-Statements pro Event reduzieren sie die Python-zu-C-Grenzübergänge auf 3.

### In-Memory-Staging (Write-Pfad)

`_write_sys_cache_slot_v8` arbeitet nun in drei Phasen:

```
1. SELECT-PHASE:  Einmaliger Bulk-Read des gesamten Slots (1.528 Zeilen)
2. RAM-PHASE:     Alle HMACs, Permutationen und Stego-Encodings im Python-Speicher
3. COMMIT-PHASE:  Zwei executemany-Aufrufe (UPDATE + INSERT Manifest)
```

### Bulk-Extract (Recovery-Pfad)

`_extract_all_channels_v8` liest ebenfalls per Bulk-SELECT: Ein Query für alle Carrier-Zeilen, einer für alle Manifest-Rows → Verarbeitung komplett im RAM.

### MAC-Shortcircuit

`_compute_row_mac_from_logical_bits()` ersetzt den zweiten `_decode_all_columns_shuffled`-Aufruf in `_sys_cache_row_mac`. Die logical_bits sind im Write-Pfad bereits aus der Encode-Phase bekannt → das Mapping-HMAC entfällt zur Hälfte.

### SQLite-PRAGMA-Tuning

```sql
PRAGMA journal_mode = WAL;      -- Write-Ahead-Log statt Rollback-Journal
PRAGMA synchronous = NORMAL;    -- 1× fsync statt 3× pro Transaktion
PRAGMA cache_size = -10000;     -- 10 MB Cache für Slot-Rows
```

### Performance-Gewinn

| Metrik | Vorher | Nachher | Speedup |
|--------|--------|---------|---------|
| Write (5B) | 345 ms | 126 ms | **2,7×** |
| Write (200B) | 393 ms | 129 ms | **3,0×** |
| Recovery (5B) | 2.183 ms | 336 ms | **6,5×** |
| Recovery (1KB) | 1.496 ms | 355 ms | **4,2×** |
| Batch 10× seq | 3.050 ms | 1.461 ms | **2,1×** |

---

## V8.2 Adaptive Feedback Loop (Carrier-Qualitätsüberwachung)

Das System passt ECC-Stärke und Replikationen automatisch an die beobachtete Träger-Qualität an – ähnlich wie Adaptive Modulation and Coding (AMC) im Mobilfunk.

### Architektur

```
Schreib-Pfad:                           Extraktions-Pfad:
                                              │
  Probe (15 Zeilen, bei Unsicherheit +25)     ▼
  ↓                               _extract_all_channels_v8
  Historische Qualität laden       liefert per-channel Erasure-Raten
  ↓                                         │
  Hybrid-Degradation D                       ▼
  ↓                               _update_channel_quality (asym. EMA)
  nsym += f(D), reps += f(D)       persistiert in sys_channel_quality
  ↓                                         │
  Write mit angepassten Parametern           │
                                              ▼
                                     Nächster Write nutzt EMA-Daten
```

### Write-Time Carrier-Probe (syntaktisch, kein Key nötig)

`_probe_carrier_integrity` prüft **15 HMAC-deterministisch** ausgewählte Zeilen. Liegt die maximale Degradation D im Unsicherheitsbereich (0.2–0.8), werden **25 weitere Zeilen** nachgezogen (total 40) für bessere statistische Power.

| Kanal | Prüfung | Erkennt |
|-------|---------|---------|
| Ch0 (Semantik) | Sind Synonym-Keywords im `bio`? | ORM-Textnormalisierung |
| Ch1 (Float-LSB) | Ist LSB-Verteilung ~50/50? | Float-Rounding |
| Ch2 (Trailing-Space) | Enden Zeilen mit Leerzeichen? | TRIM-Wipe |
| Ch3 (Float-LSB) | Ist LSB-Verteilung ~50/50? | Float-Rounding |
| Ch4 (Tilde) | Enden URLs mit `~`? | URL-Normalisierung |

Die Probe-Selektion ist HMAC-keyed (`probe:{rid}`) → Angreifer kann die Stichprobe nicht gezielt intakt lassen.

### Extract-Time Qualitätsrückmeldung

Nach jeder `recover_events()` werden per-channel Erasure-Raten aus den **Row-MAC-Verifikationen** extrahiert und per **asymmetrischem EMA** (α_attack=0.6 bei Verschlechterung, α_release=0.1 bei Besserung) in `sys_channel_quality` persistiert. Der schnelle Attack eliminiert den früheren Lag (~2,3 Schritte), der langsame Release verhindert Oszillation (Hunting).

### Parametermapping

| Max Degradation D | nsym-Bump | Min Repetitions |
|-------------------|-----------|-----------------|
| < 15% | 0 (Default 36) | 1 |
| 15–40% | +8 (→ 44) | 2 |
| 40–60% | +16 (→ 52) | 3 |
| > 60% | +24 (→ 60) | 4 |

> **Hinweis:** `min_nsym` wird als relativer Offset auf `ecc_symbols` (36) addiert, nicht als absolute Untergrenze interpretiert. Die tatsächlich genutzte nsym kann niedriger sein, wenn die verfügbare Zeilenkapazität keine höheren Werte zulässt.

### Cold Start

Frische Slots haben keine Qualitäts-Historie. Ch2 (Trailing-Space) und Ch4 (Tilde) werden beim ersten Write mit 0% Degradation angenommen (frische DB hat noch keine Carrier-Artefakte).

### Tabellen

```sql
CREATE TABLE sys_channel_quality (
    slot_idx INTEGER NOT NULL,
    channel INTEGER NOT NULL,
    erasure_pct REAL NOT NULL DEFAULT 0.0,
    sample_count INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (slot_idx, channel)
);
```

---

## V8.3 External State Counter (Rollback-Schutz)

Der ExternalStateCounter persistiert evolve_count + merkle_root in einer separaten Datei ausserhalb der SQLite-Datenbank. Wird die DB auf einen alten Snapshot zurueckgesetzt, erkennt das System beim naechsten Start die Diskrepanz und wirft RuntimeError.

### Two-Phase Write Protocol

Ein Systemabsturz (Stromausfall, Kernel Panic) im Write-Fenster kann keinen False-Positive ausloesen. Die `.evolve`-Datei verwendet ein `committed`/`pending`-Format:

```
committed 5 abc123...
pending   6 def456...    ← nur waehrend des Write-Fensters
```

| Crash-Zeitpunkt | DB | .evolve | Beim naechsten Start |
|-----------------|----|---------|---------------------|
| Vor begin_write | N | committed=N | OK |
| Nach begin_write, vor DB-commit | N | committed=N, pending=N+1 | pending verworfen |
| Nach DB-commit, vor finalize | N+1 | committed=N, pending=N+1 | **pending promoted** (Crash Recovery) |
| Nach finalize | N+1 | committed=N+1 | OK |

### Split-Brain-Toleranz

Der einzige verbleibende Split-Brain-Fall bei `db_count < committed_count` wird als echter Rollback gewertet und blockiert. In der Praxis tritt dieser Fall nur bei einem Snapshot-Rollback auf, nicht bei einem Systemabsturz.

### API

```python
ga = GhostAuditV7(
    db_path="audit.db",
    secret_key="mein-key",
    external_state_path="E:\\secure_mount\\audit.evolve",
    force_reinit=True,  # Admin-Override bei STATE_FILE_MISSING
)
```

### Erkennungsmatrix

| Angriff | DB | external_state | Ergebnis |
|---------|----|----------------|----------|
| Nur DB geklont | alter Stand | neuer Stand | ROLLBACK_DETECTED |
| Beide aus selbem Snapshot | alter Stand | alter Stand | Kein Fehler (dokumentierte Grenze) |
| Nur external_state geloescht | aktuell | fehlt | Kein Fehler (Counter neu initialisiert) |

### Test

```bash
| 	ests/test_rollback_v82.py | **Rollback/Forking-Angriff Test (V8.3 ExternalStateCounter)** |
```

---

## V7-Härtungen (weiterhin aktiv)

### LSB-Matching (Float-Steganographie)
- Statt hartem LSB-Setzen wird `trust_score` um `±1` verändert, **wenn das LSB nicht bereits stimmt**
- Statistische Verteilung bleibt natürlich → Chi²-Tests schlagen fehl
- Implementiert in `StegoEngine.encode_bit_float_lsb`

### Forward Security (Slot-Keys)
- Jeder der 5 Slots erhält einen eigenen HKDF-abgeleiteten Schlüssel
- Kompromittierung eines Slot-Keys gefährdet keine anderen Slots
- Keys über `_get_slot_keys(slot_idx)` → `(k_shuffling, k_hmac)`

### Merkle-Root Verification Digest
- HMAC-SHA256-Baum über alle 5 Slot-Hashes (keyed mit k_hmac)
- Erkennt jede nachträgliche Manipulation der `sys_cache`-Tabelle
- API: `ga.get_verification_digest()` → hex-String

### Forensic Export (SIEM-ready)
- Export aller wiederhergestellten Events in **JSONL** oder **CEF** Format
- JSONL: strukturiert, maschinenlesbar, direkt in Splunk/ELK ladbar
- CEF: Common Event Format, kompatibel mit QRadar, ArcSight
- API: `ga.export_recovered_logs("output.jsonl", format="jsonl")`
- **Auto-Export**: `GhostAuditV7(siem_export_path="audit.jsonl", siem_export_format="jsonl")` exportiert jedes geloggte Event sofort als Append — ohne nachträgliche Recovery

---

## Datenlayout

- **5 Slots**, je **1600 Carrier-Zeilen** (IDs via HMAC-Step deterministisch)
- **72 Header-Bits** pro Slot (keyed Magic, stored_msg_len, flags+nsym, sequence_number) — kein fixer 0x5C/0x5B mehr
- Header nutzt feste Carrier (Case, Trailing-Space, Float) — kein Multiplexing
- Restliche Zeilen: **V8-Multiplexing** — jede Zeile kodiert 1 Bit von allen 5 logischen Kanälen (4 Daten + 1 Parität) via per-Zeilen-Shuffle
- Konsekutive Repetition des Bit-Tupels (b0,b1,b2,b3,b4) über `repetitions` Zeilen
- Jeder Kanal bekommt einen **eigenen RS(nsym)-Codewort-Block** — aber mit **allen Zeilen** statt ¼
- **Keine Fragmentierung** über mehrere Slots: Jedes Event nutzt genau 1 Slot (von 5). Die übrigen Slots stehen für weitere Events zur Verfügung.

---

## Installation & Abhängigkeiten

```bash
pip install reedsolo cryptography
```

Keine weiteren externen Abhängigkeiten — nur Python-Stdlib + SQLite.

---

## Quickstart

```python
from ghost_audit_v7 import GhostAuditV7

ga = GhostAuditV7(
    db_path="mein_audit.db",
    secret_key="mein-sicherer-master-key",  # min. 16 Zeichen
    verbose=False,
)

# Event loggen (V8 Multiplexing + Row-MACs automatisch aktiv)
ga.log_event("SYS_ALERT: Unauthorized admin login detected")
ga.log_event("SYS_EVENT: Backup completed")

# Alle Events wiederherstellen (V8 Extraction + Erasure-basierter RS-Decode)
for seq, msg in ga.recover_events():
    print(f"[{seq}] {msg}")

# Integrität prüfen (Merkle-Root)
digest_before = ga.get_verification_digest()
print(f"Merkle-Root: {digest_before}")

# SIEM-Export
ga.export_recovered_logs("audit_export.jsonl", format="jsonl")
ga.export_recovered_logs("audit_export.cef",  format="cef")

ga.close()
```

---

## CLI / Test-Befehle

```bash
# Key-Provider-Tests (DPAPI, EnvKeyProvider)
python tests/test_key_provider.py

# Multi-Kanal-Degradation Stress-Test (7 Szenarien)
python tests/test_multichannel_degradation.py

# Resilienz-Benchmark V7 (5 Tests, quantitative Robustheitsmessung)
python tests/resilience_benchmark_v7.py

# Härtungs-Tests (LSB-Matching, Forward Security, Merkle, Export)
python tests/test_hardenings_v7.py

# Parity- und Rebuild-Checks
python tests/test_rebuild.py
python tests/test_parity_recovery.py

# Master-Testsuite V7 (alle Läufe, JSON-Report)
python tests/master_test_suite_v7.py

# Interaktives Kurztest-Menü
python tests/quickstart_tests.py
```

---

## Aktuelle Testergebnisse

### V8 Attack Simulation (`attack_simulator_v8.py`) — Stand 2026-06-01

| Attacke | Vektor | Ergebnis |
|---------|--------|----------|
| **MAC-Strip** | `row_mac` aus Manifest gelöscht | ✅ RECOVERED 3/3 — MAC-Fallback vertraut Bits bei fehlendem MAC |
| **MUX Row-Wipe 15%** | 15% der Payload-Zeilen gelöscht | ✅ RECOVERED 3/3 — RS32 + Per-Fragment RS Decode |
  | **Bio Normalize** | `bio` lowercased+trim+synonym (2 Carrier lost) | ✅ RECOVERED 3/3 — RAID-6 P+Q: 3D+2P toleriert 2/5 Carrier-Kill |

  | **Gaussian Seed** | Seed-Recovery-Versuch (Positive Control) | ✅ RECOVERED 3/3 — kein Angriff |

  | **Both-Floats Round** | `trust_score` + `profile_score` gerundet (2 Carrier lost) | ✅ RECOVERED 3/3 — RAID-6 P+Q: 3D+2P + 3-Replica+Majority-Vote überleben 2/5 Carrier-Kill |

### Both-Floats Analyse (RS-Kapazitätsgrenze)

Gleichzeitiges Runden beider Float-Spalten killt 2/5 Carrier → 40% Fehlerrate pro Rep → ~90% Byte-Erasures auf den betroffenen Kanälen → überläuft nsym=32.

**Kein Bug**, sondern fundamentale RS-Kapazitätsgrenze: `RS(n,k)` mit nsym=32 kann maximal 32 Byte-Erasures korrigieren. Bei 90% Byte-Erasures auf 45 Bytes (360 Bit) sind ~40 Erasures → Overcapacity.

**Akzeptierte Degradation:** System erkennt die Manipulation (3/3 TAMPERED) statt stiller Korruption — das ist das korrekte Verhalten.

**Workaround (optional):**
- `GHOST_AUDIT_ECC_SYMBOLS=48` für größere RS-Kapazität
- avatar_url als 5. Carrier senkt Kill-Rate von 2/4 (vor avatar_url) auf 2/5

### Multi-Kanal-Degradation (`test_multichannel_degradation.py`) — Stand 2026-06-01

| Szenario | Ergebnis |
|----------|----------|
| SC1: Trailing-Space gewippt (TRIM) | ✅ RECOVERED |
| SC2: Case-Normalisierung (lowercase) | ✅ RECOVERED |
  | SC3: TRIM + Lowercase gleichzeitig | ✅ RECOVERED (RAID-6: 2/5 Carrier-Kill toleriert) |

  | SC4: Semantic-Synonyme normalisiert | ✅ RECOVERED |

  | SC5: Float-Score gerundet (2 Dez.) | ✅ RECOVERED |

  | SC6: TRIM + Semantic (Ch0+Ch2) | ✅ RECOVERED (RAID-6 3D+2P: 2/5 Carrier-Kill recoverbar) |

  | SC7: Lowercase + Float-Round (Ch1+Ch3) | ✅ RECOVERED (RAID-6 3D+2P: 2/5 Carrier-Kill recoverbar) |

**Hinweis:** Die Multi-Kanal-Degradation-Tests wurden vor dem Bio-SPOF Fix (profile_score als Carrier 3) erstellt und testen noch den alten Carrier 3 (Case). Die Ergebnisse sind historisch korrekt, aber das System hat sich verbessert: Case ist kein Carrier mehr, stattdessen schützt profile_score vor Bio-ORM-Normalisierung.

### Resilienz-Benchmark V7 (`resilience_benchmark_v7.py`) — Stand 2026-06-01

| Test | Schwelle | Ergebnis |
|------|----------|----------|
| **Erasure Tolerance** | ≥90% Recovery bei 8% Row-Erasure | ✅ 100% PASS |
| **Bit-Flip Resistance** | ≥80% Recovery bei 10% BER | ✅ 100% PASS |
| **Channel Isolation** | ≥90% Recovery bei partieller Kanal-0-Korruption | ✅ 100% PASS |
| **Multi-Column Erasure** | ≥70% Recovery bei 50% Trailing-Space-Wipe | ✅ 100% PASS |
| **High BER Tolerance** | ≥70% Recovery bei 10% Float-BER | ✅ 100% PASS |

**5/5 Tests — 100% PASSED**

### V8.1 Throughput Benchmark (`benchmark_throughput_v8.py`) — Stand 2026-06-01

Native SQLite (WAL, Bulk-Staging):

| Payload | Write Ø | Recovery Ø |
|---------|---------|------------|
| 5B | 126 ms | 336 ms |
| 50B | 129 ms | 325 ms |
| 200B | 129 ms | 341 ms |
| 500B | 134 ms | 325 ms |
| 1KB | 135 ms | 355 ms |

Batch (10 Events, 100B): **146 ms/Event** (seq) / **154 ms/Event** (batch)

### V8.2 Gradual Decay Ramp Test (`gradual_decay_ramp_v82.py`) — Stand 2026-06-01

50-stufiger BER-Sweep (0–49%, 1%/Step) mit allen V8.2-Optimierungen:

| Metrik | Ergebnis |
|--------|----------|
| CORRUPTED_LEAK | **0%** – kein unentdeckt korruptes Event |
| VALID / TAMPER_DETECTED | 100% – System bricht kontrolliert ab |
| 1. UNCORRECTABLE | Schritt 7 (BER=7%) – RS-mathematische Grenze |
| nsym-Bereich | 36–56 (adaptiv) |
| min_reps ab D>0.15 | 2–4 (stabil, keine Oszillation) |
| EMA-Lag bei Schritt 8 | +0.49 (Attack α=0.6 eliminiert Unterschwinger) |

**Kernerkenntnis:** Die HMAC-Kette verhindert jede RS-Miscorrection. Das System produziert exakt 0% `CORRUPTED_LEAK` über alle 50 BER-Stufen. Der erste `UNCORRECTABLE` tritt an der theoretischen RS-Cliff auf (~nsym/2 Byte-Errors bei 7% BER). Mit nsym=36 Baseline + 15/40 sequentieller Probe + asymmetrischem EMA wird der Angreifer an die mathematische Grenze des Reed-Solomon-Codes getrieben.

---

## Bekannte Grenzen

- System ist ein **Forschungsprototyp**, kein produktionsreifes Auditsystem
- Textnormalisierung (z. B. durch ORM oder Backup/Restore) kann Stego-Kanäle zerstören — Bio-SPOF Fix (profile_score als Carrier 3) reduziert das Risiko von 3/5 auf 2/5 Carrier-Kill
- `audit_archive` ist absichtlicher Köder — echte Recovery nur aus `sys_cache`
- **RAID-6 3D+2P (GF(2⁸) P+Q-Parität):** System verträgt 2/5 Carrier-Kill (jede beliebige Kombination). Bio-Normalize (Semantic+Trailing-Space) und Both-Floats Round (trust+profile) werden vollständig über P-XOR + Q-GF(2⁸)-Recovery rekonstruiert. 3-Replica-Modus + Per-Channel-MAC-Majority-Vote liefern in der Regel 1+ fehlerfreie Fragment(e) pro Kanal → RAID-6 muss nur selten aktiv werden.
- Vollständiger Verlust beider Pfade = `total_loss` (erwartbar bei Vollangriff)
- Forward Security schützt Slots voneinander, nicht vor Verlust des Master-Keys
- **Optionale Abhilfe bei 2/5 Carrier-Kill:** `GHOST_AUDIT_ECC_SYMBOLS=48` für höhere Erasure-Toleranz (Default seit V8.2: 36)
- **V8.2 Optimierungen:** asymmetrischer EMA (α_attack=0.6, α_release=0.1), sequentielle Probe (15/40 Zeilen), nsym-Baseline auf 36 erhöht, Kaskadenschwelle auf 0.15 gesenkt
- **nsym-Kaskaden-Bugfix:** `start_nsym = ecc_symbols + min_nsym` (war `max(ecc_symbols, min_nsym)`) – die adaptive nsym-Erhöhung war in V8.1/V8.2 initial ein No-Op

---

## Relevante Dateien

| Datei | Beschreibung |
|-------|--------------|
| `ghost_audit_v7.py` | **Kernimplementierung (V7 + V8 Multiplexing, profile_score Carrier)** |
| `tests/attack_simulator_v8.py` | **V8-Angriffssimulation (MAC-Strip, Row-Wipe, Bio-Normalize, Float-Round)** |
| `tests/sweep_wipe_v8.py` | **MUX Row-Wipe Sweep (5/10/15/20% uniform+clustered)** |
| `tests/gradual_decay_ramp_v82.py` | **BER-Rampentest (50 Stufen 0–49%, V8.2 Adaptiv)** |
| `tests/test_rollback_v82.py` | **Rollback/Forking-Angriff Test (V8.3 ExternalStateCounter)** |
| `tests/benchmark_throughput_v8.py` | **V8.1 Durchsatz-Benchmark** |
| `tests/test_multichannel_degradation.py` | Multi-Kanal-Degradation Stress-Test (7 Szenarien, pre-profile_score) |
| `tests/test_hardenings_v7.py` | Tests: LSB-Matching, Forward Security, Merkle, Export |
| `tests/resilience_benchmark_v7.py` | Quantitative Robustheitsmessung V7 |
| `tests/attack_simulator_v6.py` | Adversariale Angriffssimulation (V6) |
| `tests/master_test_suite_v7.py` | Master-Orchestrator V7, erzeugt JSON-Report |
| `core/security_suite_support.py` | Factory, CLI-Flags, Gate-Bypass für Tests |
| `tests/quickstart_tests.py` | Interaktives Testmenü |
| `docs/QUICK_REFERENCE.md` | Kurzbefehle auf einen Blick |
| `docs/TEST_SUITE_OVERVIEW.md` | Testfluss und Interpretation |
| `tests/hardware_resilience_test.py` | FileCarrier: carrier in binärer Datei statt SQLite |
| `docs/HARDWARE_CARRIER_TEST.md` | FileCarrier-Architektur und Bug-Chronik |
| `core/ghost_audit_v6.py` | Vorgänger-Implementierung (Referenz) |

---

## Experimentelle Optionen

```powershell
# Slot-Größe überschreiben (Default: 1600)
$env:GHOST_AUDIT_SLOT_SIZE="2000"
python analysis/erasure_sweep_run.py

# Min. Stego-Repliken (Default: 5 für V7, 3 für V6)
$env:GHOST_AUDIT_PER_CHANNEL_MIN_REPS="3"
python tests/resilience_benchmark_v7.py

# ECC-Symbolstärke (Default: 36 seit V8.2)
$env:GHOST_AUDIT_ECC_SYMBOLS="48"
python tests/resilience_benchmark_v7.py

# Proactive Self-Healing — Rebuild-Parameter (V8.4)
$env:GHOST_AUDIT_REBUILD_ECC_SYMBOLS="60"   # Rebuild-nsym (Default: 52)
$env:GHOST_AUDIT_REBUILD_MIN_REPS="5"       # Rebuild-Replikationen (Default: 4)
$env:GHOST_AUDIT_REBUILD_THRESHOLD="0.25"   # Degradations-Schwelle (Default: 0.35)
$env:GHOST_AUDIT_REBUILD_INTERVAL="25"      # Check-Intervall in Events (Default: 50)

# A/B-Vergleich Slot-Größen
python tools\ab_compare_slot_sizes.py

# Sweep aggregieren
python tools\aggregate_sweep_results.py
```

---

## Nächste sinnvolle Schritte

- [x] V8 Multiplexing: Alle 5 Kanäle simultan in jede Zeile schreiben
- [x] V8 Per-Channel Row-MAC (5×8-Byte HMACs für Erasure-Detection)
- [x] V8 Extraktion mit MAC-basierter Erasure-Generierung
- [x] RS-Decode mit `erase_pos` für doppelte Korrektur-Kapazität (V8)
- [x] Per-Fragment RS Decode Fix (Doppel-Decode-Korruption eliminiert)
- [x] Bio-SPOF Fix: Carrier 3 = profile_score REAL (ORM-unabhängig)
- [x] Both-Floats Analyse: 2/5 Carrier-Kill → akzeptierte Degradation zu Tamper Detection
- [x] V8 Attack Simulation (5 Angriffsvektoren getestet)
- [x] V8.1 Bulk-Staging: Write 3,0× / Recovery 6,5× schneller
- [x] V8.1 PRAGMA-Tuning: WAL + synchronous=NORMAL + cache_size
- [x] V8.1 MAC-Shortcircuit: doppeltes Mapping-HMAC eliminiert
- [x] V8.2 Adaptive Feedback Loop: Carrier-Probe + Qualitäts-Historie + autom. nsym/reps-Anpassung
- [x] V8.2 nsym-Baseline auf 36 erhöht, Kaskadenschwelle auf 0.15 gesenkt
- [x] V8.2 Asymmetrischer EMA (α_attack=0.6, α_release=0.1) eliminiert Totband
- [x] V8.2 Sequentielles Probe-Sampling (15/40 Zeilen) reduziert high-BER-Varianz
- [x] V8.2 nsym-Kaskaden-Bugfix (min_nym als Offset statt Absolutwert)
- [x] V8.2 Gradual Decay Ramp Test: 0% CORRUPTED_LEAK ueber 50 BER-Stufen (0–49%)
- [x] V8.3 External State Counter: Rollback-Schutz via separater monotonic Counter-Datei
- [x] V8.4 Proactive Self-Healing: `_migrate_slot` + `_idle_restore_check` + forensische `[GHOST_REBUILD]`-Events

### Forward Secrecy (V7.1)

- **`_k_write_merkle`** wird nach jedem `log_event()` via HMAC weiterentwickelt (`k_n = HMAC(k_{n-1}, "evolve")`)
- Der vorherige Key wird überschrieben → Angreifer mit aktuellem Speicherdump kann keine alten Anchor-MACs fälschen
- `key_version` wird pro Anchor in der `merkle_anchor`-Tabelle gespeichert
- Verifikation evolviert `k_merkle` von der Basis auf die gespeicherte `key_version` → alte Anchors bleiben prüfbar
- `evolve_count` wird in `fs_key_state`-Tabelle persistiert → nach Neustart wird der Key automatisch nachgezogen
- Row-MACs nutzen weiterhin den statischen `k_hmac` → Recovery bleibt vollständig kompatibel

### Metronome Heartbeats (V7.1)

- **`metronome_interval`** (Sekunden, default 0=aus) aktiviert periodische Heartbeat-Events
- Vor jedem `log_event()` prüft `_maybe_heartbeat()`, ob das Intervall seit dem letzten Heartbeat vergangen ist
- Bei Fälligkeit wird automatisch ein Event mit `[METRONOME] beat=N` geloggt
- Heartbeat-Zustand wird in `fs_metronome`-Tabelle persistiert (überlebt Neustarts)
- `detect_truncation(recovered_events)` scannt wiederhergestellte Events auf Heartbeat-Lücken
- Heartbeat-Events durchlaufen die volle RS-Codierung + Replikation → genauso geschützt wie Nutzerevents
- `metronome=0` (Default): kein Heartbeat, kein Overhead

### Quickstart mit Metronome

```python
ga = GhostAuditV7(
    db_path="audit.db",
    secret_key="mein-key",
    metronome_interval=300,  # Heartbeat alle 5 Minuten
)

# Heartbeat erfolgt automatisch vor dem ersten Event
# und danach alle 300s
ga.log_event("SYS_ALERT: Login detected")

# Truncation-Prüfung
events = ga.recover_events()
gaps = ga.detect_truncation(events)
if gaps:
    print(f"WARN: {len(gaps)} Truncation-Lücke(n) entdeckt!")
```

### Per-Entry MAC-Tags (V7.1)

- Jeder `log_event()` speichert einen HMAC-SHA256-Tag in der `event_mac_tags`-Tabelle
- Tag = `HMAC(k_hmac, seq + event_msg)` → eindeutig pro Event + Inhalt
- **Feingranulare Verifikation:** `verify_event_mac(seq)` prüft ein einzelnes Event
- **Bulk-Prüfung:** `verify_all_event_macs()` prüft alle gespeicherten Tags auf einmal
- Erkennt gezielte Manipulation einzelner Log-Einträge in der sichtbaren Tabelle
- Tags überleben Neustarts (persistiert in SQLite)
- Ergänzt den aggregierten Merkle-Root: dieser erkennt *dass* etwas geändert wurde, MAC-Tags sagen *welches* Event
