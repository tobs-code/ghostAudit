# FileCarrier Hardware Carrier Test (Experimentell)

## Übersicht

Ersetzt die SQLite-basierten `bio`/`score`-Carrier durch eine **binäre Carrier-Datei** mit 512-Byte-Records. SQLite wird nur noch für Metadaten-Tabellen (`audit_log`, `slot_sequences`) verwendet — die tatsächlichen Steganographie-Daten liegen in der `.bin`-Datei.

Ziel: Pipeline auch ohne SQLite-Struktur testen (z. B. RAW-Datenträger, Embedded Devices).

## Datei-Format

| Offset | Größe | Feld |
|--------|-------|------|
| 0      | 256   | `bio` (Text, null-terminiert) |
| 256    | 8     | `trust_score` (double, little-endian) |
| 264    | 248   | Padding (null) |

Gesamt: **512 Bytes pro Record**. 8000 Records (5 Slots × 1600) = 4 MB.

## Architektur

`FileCarrierGhostAuditV7(GhostAuditV7)` in `tests/hardware_resilience_test.py`:

- **`_read_carrier(rid)` / `_write_carrier(rid, bio, score)`** — lesen/schreiben direkt in der `.bin`-Datei via `rid → Record-Index`-Map
- **Cached File Handle** — `_open_fh()`/`_close_fh()` vermeiden `open/close` pro Zugriff (27s → 0.4s bei 3 Events)
- **5 Write/Read-Overrides** ersetzen die SQLite-Cursor-APIs:

### Override-Methoden

| Base-Klasse | FileCarrier-Override | Grund |
|---|---|---|
| `_write_channel_encoded_to_slot_v7` | Datei statt SQLite | carrier I/O |
| `_write_header_bits_to_slot` | Datei statt SQLite | carrier I/O |
| `_extract_channel_encoded_bits_v7` | Datei statt SQLite | carrier I/O |
| `_recover_from_aux` | Seq-Gruppierung + Dedup | SQLite-unabhängige Recovery |
| `log_event` | Slot-Sequenzen aus Datei-Header | Base liest `slot_sequences`-Tabelle (leer) |

## Gefundene & gefixte Bugs

| Bug | Symptom | Fix |
|-----|---------|-----|
| `ch_bits = [b for ...]` lieferte Strings | Alle Bits als 1 interpretiert → Payload korrupt | `int(b)` in List-Comprehension |
| Wrong Tuple-Unpack `_, slot_ids = raw_bits[k]` | `slot_ids` = 72 Header-Bits statt 1600 | `slot_ids, _ = raw_bits[k]` |
| `log_event` las Slot-Sequenzen aus SQLite | Slot 0..4 immer als frei gemeldet → Überschreibung | Override mit `_read_carrier`-basiertem Scan |
| "Unmatched Slots" in Recovery | Slots 1–4 fälschlich zu seq=3 gruppiert → Majority-Vote corrupt | Entfernt (jeder Slot bleibt exklusiv in seiner Seq-Gruppe) |
| Header seq=0 aus korrupten Slots | False-Positive-Recovery | `if seq == 0: continue` |
| `_seed_aux_table` überschrieb Manifest-MACs | HMAC-Prüfung erkannte korrupte Zeilen nicht → alle Attacken außer Basic fehlschlugen | `INSERT OR REPLACE` → `INSERT OR IGNORE` für Manifest-Tabelle |

## Recovery-Logik (`_recover_from_aux`)

1. **Header-Scan:** Alle 5 Slots → individuelle `_decode_header` → `seq_groups[seq] = [(slot_idx, slot_ids, h_bits)]`
2. **Seq-Gruppierung:** Pro Seq (≥1) → Majority-Vote der Header-Bits → merged Header verifizieren → `fragments_by_seq[seq][slot] = header`
3. **Payload-Extraktion:** Pro Seq → `_extract_channel_encoded_bits_v7` aus allen Fragmenten
4. **Cross-Slot Majority:** Bei expected=1 und mehreren Fragmenten → Byte-Level Majority-Vote (toleriert korrupte Einzelfragmente)
5. **RS-Dekodierung + HMAC:** Pro Kanal → Parity-Recovery → HMAC-Prüfung
6. **Dedup:** Nach Body-Inhalt deduplizieren (niedrigste Seq gewinnt)

## Tests (Stand 2026-06-01)

Alle unter `random.seed(42)`, Angriff nur auf Payload-Zone (Header unangetastet):

| Test | Angriff | Ergebnis |
|------|---------|----------|
| Basic Recovery | Keiner | ✅ PASS |
| 5% Row Deletion | 5% Payload-Records gelöscht | ✅ PASS |
| 3% Byte Corruption | 3% aller Bytes flippen | ✅ PASS |
| Multi-Event (3 Events) | 0.5% Payload-Records gelöscht | ✅ PASS |
| 30% Physical Truncation | Datei auf 70% gekürzt | ✅ PASS |

**5/5 PASS** (Stand 2026-06-01)

## Bekannte Grenzen

- **Slot-Recycling:** `max_replicas = SLOT_COUNT // (active_count + 1)` verteilt Slots dynamisch. Bei 5 Slots und 3 Events bekommt Event C nur Slot 0 zugewiesen (überschreibt alte Daten). Bei mehr als 5 Events kollidieren Replicas.
- **Kein Header-RS:** Die 72 Header-Bits haben keinen RS-Schutz. Angriffe auf Header-Zone (0..71 pro Slot) führen zu 100% Datenverlust.
- **HMAC-Brute-Force:** 16-Byte-MAC ohne Rate-Limiting im Test-Code.
- **Performance:** Kein Index auf `_rid_to_pos` (lineare Map, für 8000 Einträge irrelevant).

## Nutzung

```bash
python tests/hardware_resilience_test.py
```
