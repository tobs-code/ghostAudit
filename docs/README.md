# GhostAudit

> Research project — not intended for production use.

GhostAudit hides audit logs **steganographically inside ordinary SQLite user data**. In the current V9 path, the carrier is a real application table supplied by the caller, and GhostAudit overlays bits on normal app writes. A privileged attacker who deletes the visible log tables finds nothing — the real forensic data is invisibly embedded in carrier fields and cryptographically secured.

```python
from core.carrier_config import CarrierConfig
from core.ghost_audit_v9 import GhostAuditInterceptor
import secrets

carrier = CarrierConfig(
    table="users",
    id_field="id",
    semantic_field="bio",
    float_a_field="trust_score",
    float_b_field="profile_score",
    tilde_field="avatar_url",
    timestamp_field="created_at",   # V9.3: Ch2 Timestamp-LSB (kein Bio-SPOF)
)

ga = GhostAuditInterceptor(
    db_path="app.db",
    carrier_config=carrier,
    secret_key=secrets.token_hex(32),
)
ga.log_event("user=alice action=login ip=10.0.0.1")

# App write hook: one UPDATE, with stego overlay folded into the app fields.
fields = {"bio": bio, "trust_score": trust, "profile_score": profile, "avatar_url": url}
fields = ga.intercept(row_id=user_id, fields=fields)
# UPDATE users SET bio=?, trust_score=?, profile_score=?, avatar_url=? WHERE id=?

# attacker deletes audit_log — recovery still reads the carrier table
events = ga.recover_events()   # → [( 1, "user=alice action=login ip=10.0.0.1")]
```

**How it works:** Events are encoded into synonym choices in bio text, LSBs of float score columns, timestamp-LSB of a write-once datetime column, and URL tilde suffixes — spread across 5 logical channels with RAID-6 erasure coding and Reed-Solomon ECC. An attacker who doesn't know the master key cannot find, read, or undetectably modify the logs.

```
pip install reedsolo cryptography numpy rfc3161ng requests
```

See [quickstart.py](../quickstart.py) for the legacy standalone demo including attack simulation and recovery.

---

> Forschungsprojekt — nicht für den Produktionseinsatz gedacht.

GhostAudit versteckt Audit-Logs steganographisch in normalen SQLite-Nutzerdaten. Der aktuelle V9-Pfad nutzt dafür eine echte Applikationstabelle als Carrier und legt Stego-Bits als minimale Overlays auf normale App-Writes. Ein privilegierter Angreifer, der die sichtbaren Log-Tabellen löscht, findet die echten forensischen Daten nicht — sie sind unsichtbar in Carrier-Feldern eingebettet und kryptographisch gesichert.

---

## Inhaltsverzeichnis

1. [Schnellstart](#schnellstart)
2. [Architektur](#architektur)
3. [Stego-Kanäle](#stego-kanäle)
4. [Schutzschichten](#schutzschichten)
5. [Feature-Übersicht nach Version](#feature-übersicht-nach-version)
6. [Konfiguration & Env-Vars](#konfiguration--env-vars)
7. [API-Referenz](#api-referenz)
8. [Tests ausführen](#tests-ausführen)
9. [Testergebnisse](#testergebnisse)
10. [Bekannte Grenzen](#bekannte-grenzen)
11. [Projektstruktur](#projektstruktur)

---

## Schnellstart

```bash
pip install reedsolo cryptography numpy
```

```python
from core.carrier_config import CarrierConfig
from core.ghost_audit_v9 import GhostAuditInterceptor
import secrets

# Generiere einen sicheren 256-Bit Schlüssel
my_key = secrets.token_hex(32)

carrier = CarrierConfig(
    table="users",
    id_field="id",
    semantic_field="bio",
    float_a_field="trust_score",
    float_b_field="profile_score",
    tilde_field="avatar_url",
    timestamp_field="created_at",  # V9.3: Ch2 wird via Timestamp-LSB kodiert
)

ga = GhostAuditInterceptor(
    db_path="app.db",
    carrier_config=carrier,
    secret_key=my_key,
    verbose=False,
    target_spread_factor=10.0, # (V9.1) Streckfaktor relativ zum Event-Intervall
    max_queue_size=100,        # (V9.2) Schutz vor RAM-Exhaustion (pro Prozess!)
)
```

> **Hinweis zu Multi-Process Deployments:** In Umgebungen mit mehreren Workern (z.B. Gunicorn) führt jeder Prozess eine eigene In-Memory Queue. Die effektive Gesamtkapazität ist `max_queue_size * num_workers`. Die Persistenz in SQLite sorgt dafür, dass jeder Worker seinen Teil der Audit-Last unabhängig und crash-sicher abarbeitet.

ga.calibrate()  # optional: Synonym-Verteilung aus echten Rows lernen
```

Mit Rollback-Schutz und Heartbeat:

```python
ga = GhostAuditInterceptor(
    db_path="app.db",
    carrier_config=carrier,
    secret_key="mein-key",
    external_state_path="E:\\secure_mount\\audit.evolve",
    metronome_interval=300,   # Heartbeat alle 5 Minuten
    siem_export_path="audit.jsonl",
    siem_export_format="jsonl",
)
```

---

## Architektur

```
SQLite-Datenbank
│
├── audit_log          ← sichtbarer Köder (Angreifer löscht hier)
├── audit_archive      ← zweiter Köder
│
└── users              ← echte App-Tabelle als Carrier (V9)
    │
    ├── Slot 0..4      ← je 1.600 Zeilen
    │   ├── 72 Header-Bits  (keyed Magic, Länge, nsym, Sequence)
    │   └── 1.528 Payload-Zeilen
    │       └── Jede Zeile kodiert alle 5 logischen Streams gleichzeitig (V8 Multiplexing)
    │           {Data0, Data1, Data2, P-Parity, Q-Parity} via HMAC-Permutation auf 5 Carrier
    │
    ├── sys_cache_manifest        ← Row-MACs (5×8 Byte pro Zeile)
    ├── sys_cache_pending_queue   ← Persistente ECC-Bits (V9.1)
    ├── sys_cache_scheduler_state ← Persistente EMA-Raten (V9.1)
    ├── sys_channel_quality       ← EMA-Degradationshistorie pro Kanal
    ├── sys_witness_queue         ← TSA-Witness pending Entries (V9.4)
    ├── merkle_anchor            ← kryptographische Slot-Fingerabdrücke
    ├── event_mac_tags           ← per-Event HMAC-Tags
    └── fs_key_state             ← Forward-Secrecy evolve_count
```

Im V7/V8-Kompatibilitätsmodus heißt die Carrier-Tabelle weiterhin `sys_cache`.
V9 ist der steganalytisch härtere Pfad: Die Carrier-Rows stammen aus einer echten
Applikationstabelle, `sys_cache` wird in diesem Modus nicht synthetisch angelegt,
und das App-Schema wird über `CarrierConfig` beschrieben.

**V8 Multiplexing vs. V7 Round-Robin:**

```
V7: Zeile 0→Ch0, Zeile 1→Ch1, Zeile 2→Ch2, Zeile 3→Parity, Zeile 4→Ch0 (Rep)
V8: Zeile 0→{Ch0,Ch1,Ch2,Ch3,P}, Zeile 1→{Ch0,Ch1,Ch2,Ch3,P} (Rep), Zeile 2→{...}
```

Jeder Kanal nutzt damit alle Zeilen statt ¼ → **4× ECC-Kapazität pro Kanal**.

---

## Stego-Kanäle

Fünf physische Carrier, per HMAC-Permutation pro Zeile auf logische Kanäle gemappt:

| Kanal | Feld | Methode | ORM-Risiko |
|-------|------|---------|------------|
| Ch0 | `bio` | Synonym-Switching (`currently/presently`, `active/online`, `working/operating`, `system/platform`) | TRIM, lowercase |
| Ch1 | `trust_score` | Float LSB-Matching ±1 (stochastisch) | Float-Rounding |
| Ch2 | `created_at` (Timestamp-LSB) | Float/Integer/TEXT → `_parse_timestamp_to_int` → LSB-Embedding (scale=1 für ms, scale=1000 für s) | Keines — write-once, kein ORM-Touch |
| Ch3 | `profile_score` | Float LSB-Matching ±1 (ORM-unabhängig von `bio`) | Float-Rounding |
| Ch4 | `avatar_url` | Tilde-Suffix (`~` = Bit 1) — RFC-3986 unreserved | URL-Normalisierung |

**Carrier-Shuffling:** Die Zuordnung physischer Carrier zu logischen Kanälen wechselt per HMAC pro Zeile. Ein Angriff auf einen physischen Carrier verteilt den Schaden gleichmäßig auf alle 5 logischen Kanäle (~20% pro Kanal).

**Adaptive Probability Scheduler (V9.1):** Um zeitliche Korrelationen zwischen Audit-Events und Carrier-Writes zu unterdrücken, misst der Interceptor via EMA die App-Schreibfrequenz und das Event-Intervall. Die Embedding-Wahrscheinlichkeit $p$ wird dynamisch so angepasst, dass Payloads über einen längeren Zeitraum (`target_spread_factor`) gestreckt werden.

**Persistent Queue Manager (V9.1):** Die `_payload_queue` und der Scheduler-State werden in SQLite persistiert. Audit-Events überleben dadurch Prozess-Restarts ohne Bit-Verlust (Zero-Loss-Integrity).

**Reject-New Overflow Strategy (V9.2):** Bei Erreichen der `max_queue_size` werden neue Events mit einem `QueueOverflowError` abgelehnt und ein `SYSTEM_WARNING` im sichtbaren Log erzeugt. Dies verhindert, dass Angreifer alte Events durch Bursts aus der Queue drängen (Anti-History-Flushing).

**Thread-Safety (V9.2):** Der Interceptor ist durch ein internes `threading.Lock` gegen Race-Conditions in Multi-Threaded-Umgebungen (WSGI/ASGI) geschützt.

**Bio-SPOF Fix (V8 → V9):** Carrier 3 war ursprünglich Case-Switching auf `bio` (V7). ORM-Normalisierung hätte damit 3/5 Carrier gleichzeitig zerstört. V8 zog Ch2 auf `profile_score` (unabhängige Float-Spalte) — Bio-Normalize killte nur noch 2/5. **V9 eliminiert den Bio-SPOF endgültig:** Ch2 liegt auf `created_at` (Timestamp-LSB), einem write-once-Feld ohne ORM-Exposition. Bio-TRIM/lowercase killt jetzt nur noch **1/5 Carrier** (Ch0).

**TextShapeCarrier (V9, Fallback):** Der frühere Trailing-Space-Carrier wurde im V9-Payload-Pfad durch einen opportunistischen Textform-Carrier ersetzt. Seit V9.3 ist er **Fallback** für Ch2: primär wird Ch2 via Timestamp-LSB auf `created_at` (oder einem konfigurierten Timestamp-Feld) kodiert. Nur wenn kein Timestamp-Feld konfiguriert ist (`timestamp_field=""`), fällt das System auf TextShape zurück.

**Temporal Delay (V9):** Payloads starten nicht immer sofort auf der ersten elegiblen Row. Ein kleiner deterministischer `temporal_delay_rows`-Puffer glättet den direkten `log_event()` → `intercept()`-Pfad, damit das Schreibmuster weniger eng an einzelne Audit-Events gebunden ist.

**Float Warm-up (V9):** Float-LSB-Carrier können optional erst nach `float_warmup_samples` echten Werten aktiviert werden. `calibrate_floats()` lädt die Baseline, `measure_float_coverage()` zeigt den aktuellen Warm-up-Stand.

---

## Schutzschichten

Von innen nach außen:

| # | Schicht | Beschreibung |
|---|---------|--------------|
| 1 | **Reed-Solomon ECC** | Per-Channel RS, nsym=36 Baseline (adaptiv bis 60). Erasures werden doppelt so effizient korrigiert wie Errors. |
| 2 | **Replikation** | Jedes Bit-Tupel wird in 1–5 konsekutive Zeilen geschrieben. Majority-Vote + MAC-Verifikation bei Extraktion. |
| 3 | **Per-Channel Row-MAC** | 5×8-Byte HMACs pro Zeile. Fehlgeschlagener MAC → Bit als Erasure markiert (RS-Bonus). |
| 4 | **HMAC-SHA256** | 16-Byte-MAC pro Payload-Block. Verhindert unentdeckte Korruption (0% CORRUPTED_LEAK). |
| 5 | **RAID-6 P+Q Parität** | XOR-Parität (P) + GF(2⁸)-gewichtete Parität (Q). Toleriert Verlust beliebiger 2/5 Kanäle. |
| 6 | **Carrier-Shuffling** | HMAC-basierte Permutation pro Zeile. Angreifer kennt Carrier-Zuordnung nicht. |
| 7 | **Forward-Secure Slot-Keys** | HKDF-abgeleitete Subkeys pro Slot. Kompromittierung eines Slots gefährdet keine anderen. |
| 8 | **SQLite Write-Gate** | Trigger blockiert unkontrollierte interne Carrier-Writes im Legacy-Pfad; V9 legt keine Gate-Trigger auf die App-Tabelle. |
| 9 | **Merkle-Root** | HMAC-SHA256-Baum über alle 5 Slots. Erkennt jede nachträgliche Manipulation. |
| 10 | **Forward Secrecy (Anchor-Keys)** | `k_write_merkle` evolviert nach jedem Event via HMAC. Alter Key wird überschrieben. |
| 11 | **Proactive Self-Healing** | Degradierte Slots werden im Hintergrund mit erhöhten ECC-Parametern neu geschrieben. |
| 12 | **TSA Witness (V9.4)** | `.evolve`-Digest wird via RFC 3161 an Public Time-Stamp Authority gesubmitted (Background-Thread, asynchron). Der signierte Timestamp-Token (TST) beweist die Existenz des Checkpoints zu einem bestimmten Zeitpunkt — Both-Snapshot-Angriff wird zum Both-Snapshot-AND-TSA-Compromise. |

---

## Feature-Übersicht nach Version

### V9 — Real-Carrier Interceptor

- `GhostAuditInterceptor` nutzt eine vorhandene App-Tabelle statt synthetischer `sys_cache`-Rows
- `CarrierConfig` macht Tabellen- und Feldnamen konfigurierbar (`users.bio`, `trust_score`, `profile_score`, `avatar_url`, ...)
- `intercept(row_id, fields)` faltet Stego-Bits in den normalen App-Write ein: ein App-UPDATE, kein separater Carrier-Write pro Row
- Header-Rows werden pro Slot reserviert; Payload-Bits werden nur in Payload-Rows eingebettet
- Vollständig eingebettete Payloads werden später per `flush_headers()` bzw. automatisch vor `recover_events()` mit V7-Headern versehen
- Synonym-Encoding kann via `calibrate()` aus echten Rows an die lokale Textverteilung angepasst werden
- V7 ECC/RAID-6, HMAC-Shuffling, Merkle, Rollback-Schutz und Checkpoints bleiben als Engine-Primitiven erhalten
- `timestamp_field` in `CarrierConfig`: Ch2 wechselt von `bio` (TextShape) auf Timestamp-LSB (`created_at` o.ä.) — kein Bio-SPOF mehr, nur 1/5 Carrier betroffen bei ORM-Normalisierung
- `carrier_schema_version` in `sys_cache_scheduler_state` migriert automatisch von V1 (kein Timestamp) zu V2 (Timestamp) beim ersten Start mit `timestamp_field`
- `_parse_timestamp_to_int`: Typ-sicheres Parsen von INTEGER (ms), REAL (Sekunden vs. ms via `<1e11`-Heuristik) und TEXT (ISO-8601 mit Z)
- **V9.1+:** Adaptive Probability Scheduler, persistente Queue, Reject-New Overflow-Schutz und Thread-Safety.
- **V9.4 — Timestamp Witness (RFC 3161 TSA):** Background-Thread submitte SHA256(.evolve)-Digest an Public Time-Stamp Authority. Der signierte Timestamp-Token (TST) beweist, dass der `.evolve`-State zu einem bestimmten Zeitpunkt existierte — der Angreifer müsste DB, `.evolve` *und* den TSA-Log gleichzeitig snapshotten. Im Fehlerfall (TSA down) bleibt die Entry `pending` und wird im nächsten Poll-Zyklus erneut versucht. Der Write-Pfad blockiert nie.

### V8 — Multiplexing & RAID-6

- Alle 5 Kanäle simultan in jede Zeile (statt Round-Robin) → 4× ECC-Kapazität
- Per-Channel Row-MAC (5×8 Byte) für Erasure-Detection auf Kanal-Ebene
- Per-Fragment RS Decode: jedes Replikat wird unabhängig decodiert, erstes sauberes gewinnt
- Keyed Magic-Bytes (kein fixer Marker mehr), Gaussian Seed aus Master-Key, Zufalls-Padding
- Slot-Sequence-Header-Cache: spart 360 SQL-Queries bei sequentiellen Writes

### V8.1 — Bulk-Staging (Performance)

Statt 13.500 Einzel-Statements pro Event: 1× Bulk-SELECT → RAM-Verarbeitung → 2× `executemany`.

| Metrik | Vorher | Nachher | Speedup |
|--------|--------|---------|---------|
| Write (5B) | 345 ms | 126 ms | 2,7× |
| Write (200B) | 393 ms | 129 ms | 3,0× |
| Recovery (5B) | 2.183 ms | 336 ms | 6,5× |
| Recovery (1KB) | 1.496 ms | 355 ms | 4,2× |
| Batch 10× (100B) | 3.050 ms | 1.461 ms | 2,1× |

SQLite-PRAGMAs: `journal_mode=WAL`, `synchronous=NORMAL`, `cache_size=-10000`.

### V8.2 — Adaptive Feedback Loop

Das System passt ECC-Stärke und Replikationen automatisch an die beobachtete Carrier-Qualität an.

**Write-Pfad:** `_probe_carrier_integrity` prüft 15 HMAC-deterministisch gewählte Zeilen. Bei Unsicherheit (D=0.2–0.8) werden 25 weitere nachgezogen (total 40).

**Extract-Pfad:** Row-MAC-Verifikationen liefern per-channel Erasure-Raten → asymmetrischer EMA (α_attack=0.6, α_release=0.1) → persistiert in `sys_channel_quality`.

**Parametermapping:**

| Max Degradation D | nsym-Bump | Min Reps |
|-------------------|-----------|----------|
| < 15% | 0 (→ 36) | 1 |
| 15–40% | +8 (→ 44) | 2 |
| 40–60% | +16 (→ 52) | 3 |
| > 60% | +24 (→ 60) | 4 |

Weitere Fixes: nsym-Baseline auf 36 erhöht, Kaskadenschwelle auf 0.15 gesenkt, nsym-Bugfix (`start_nsym = ecc_symbols + min_nsym` statt `max()`).

### V8.3 — Rollback-Schutz (External State Counter)

`ExternalStateCounter` persistiert `evolve_count + merkle_root` in einer separaten Datei außerhalb der SQLite-DB. Wird die DB auf einen alten Snapshot zurückgesetzt, erkennt das System die Diskrepanz beim nächsten Start und wirft `RuntimeError`.

**Two-Phase Write Protocol** — kein False-Positive bei Systemabsturz:

```
committed 5 abc123...
pending   6 def456...    ← nur während des Write-Fensters
```

| Crash-Zeitpunkt | DB | .evolve | Beim nächsten Start |
|-----------------|----|---------|---------------------|
| Vor begin_write | N | committed=N | OK |
| Nach begin_write, vor DB-commit | N | committed=N, pending=N+1 | pending verworfen |
| Nach DB-commit, vor finalize | N+1 | committed=N, pending=N+1 | pending promoted (Crash Recovery) |
| Nach finalize | N+1 | committed=N+1 | OK |

**Erkennungsmatrix:**

| Angriff | Ergebnis |
|---------|----------|
| Nur DB geklont (DB alt, .evolve neu) | `ROLLBACK_DETECTED` |
| Beide aus gleichem Snapshot | Kein Fehler (dokumentierte Grenze) |
| Nur .evolve gelöscht | Kein Fehler (Counter neu initialisiert) |

### V8.4 — Proactive Self-Healing

Während V8.2 ECC-Parameter *reaktiv* beim nächsten Write erhöht, schreibt V8.4 degradierte Slots **proaktiv** neu — bevor ein weiterer Angriff die verbleibende RS-Kapazität aufbraucht.

**Flow:**

```
log_event() [nach Write-Gate]
    └── _idle_restore_check()        rate-limitiert: 1× alle 50 Events
            └── sys_channel_quality scannen
                    └── MAX(erasure_pct) >= 0.35?
                            └── _migrate_slot(slot_idx)
                                    ├── _recover_single_slot()   Header → RS → RAID-6 → HMAC
                                    ├── rebuild_nsym = max(adaptive+8, 52), cap auf Slot-Kapazität
                                    ├── _write_sys_cache_slot_v8()   direkt, kein Event-Pipeline-Eingriff
                                    └── log_event("[GHOST_REBUILD] slot=N seq=M old_nsym=X new_nsym=Y reps=Z")
```

**nsym-Berechnung:** Rebuild ist immer mindestens so stark wie der aktuelle adaptive State:

```python
target_nsym  = max(adaptive_nsym + 8, ECC_REBUILD_NSYM)  # nie schwächer als adaptiv
rebuild_nsym = min(target_nsym, payload_rows // 8)         # Kapazitäts-Cap
```

**Forensische Transparenz:** Jeder Rebuild erzeugt ein vollwertiges Audit-Event:
```
[GHOST_REBUILD] slot=2 seq=17 old_nsym=36 new_nsym=52 reps=4
[GHOST_REBUILD_FAILED] slot=2 carrier_total_loss=True   ← bei Totalverlust
```

**Rekursionsschutz:** `[GHOST_REBUILD*]`- und `[METRONOME]`-Events inkrementieren den Rate-Limit-Counter nicht und lösen keinen weiteren Check aus.

### V8.5 — Checkpoint-Export (externer Witness)

Ein Checkpoint ist ein kompaktes, signiertes JSON-Dokument, das den DB-Zustand zu einem bestimmten Zeitpunkt festhält. Er ist dafür gedacht, in einer **externen, read-only Location** gespeichert zu werden — Git-Repo, separate Datei, Pastebin — und dort als unabhängiger Witness zu fungieren.

**Was ein Checkpoint beweist (mit Master-Key):**
- Der Merkle-Root des Carrier-Layers war genau `R` bei Sequence `N`
- Die Event-Kette (`entry_hash`-Chain) war zu diesem Zeitpunkt intakt
- Die Anchor-Kette (`anchor_hash`-Chain) war zu diesem Zeitpunkt intakt
- Der Checkpoint selbst wurde nicht manipuliert (MAC-Feld)

**Was ein Checkpoint nicht beweist (by design):**
- Inhalt einzelner Events ohne Master-Key — das ist kein Bug, sondern Threat-Model-Konsistenz: Ein Angreifer ohne Key kann auch keinen gefälschten Checkpoint bauen.

**Checkpoint-Format:**
```json
{
  "ghost_audit_checkpoint": true,
  "version": "1.0",
  "seq": 42,
  "root": "a3f9...",
  "entry_chain": "b7c2...",
  "anchor_chain": "d4e1...",
  "timestamp": "2026-06-02T14:30:00Z",
  "key_version": 42,
  "mac": "f8a3..."
}
```

**Verifikation:**

```python
result = ga.verify_checkpoint(cp)
# result["valid"]              → alle 4 Checks OK?
# result["mac_valid"]          → Checkpoint nicht manipuliert?
# result["root_match"]         → Carrier-Layer unverändert seit Checkpoint?
# result["entry_chain_match"]  → Event-Kette unverändert?
# result["anchor_chain_match"] → Anchor-Kette unverändert?
# result["details"]            → "OK" oder Fehlerbeschreibung
```

**TSA-Witness (V9.4):** Seit V9.4 wird der `.evolve`-Digest automatisch nach jedem `log_event(immediate_commit=True)` an eine RFC 3161 Time-Stamp Authority gesubmitted (Best-Effort Background-Thread, pollt alle 30s). Der signierte Timestamp-Token wird in `sys_witness_queue` persistiert. `export_checkpoint()` hängt den Witness-Status ans Checkpoint-Dict an:

```python
cp = ga.export_checkpoint()
# cp enthälält zusätzlich:
# cp["witness"] = {
#     "evolve_path": "app.evolve",
#     "pending_count": 0,
#     "total_entries": 42,
#     "recent": [{"seq": 42, "state": "confirmed", "tsa_url": "https://freetsa.org/tsr", "confirmed_at": 1763845211000}, ...],
#     "thread_alive": True
# }
```

Ein Both-Snapshot-Angriff müsste jetzt neben DB und `.evolve` auch den TSA-Log kompromittieren — praktisch nicht realisierbar für einen Angreifer ohne Netzwerk-Kontrolle.

**Warum kein vollständiger Event-Level Merkle-Tree?**
Ein Inclusion Proof (O(log n) Sibling-Hashes pro Event) wäre nur dann stärker, wenn der Root-Hash extern gesichert ist — was der Checkpoint bereits leistet. Der vollständige Umbau würde Komplexität hinzufügen ohne zusätzlichen Schutz im GhostAudit-Threat-Model: Ein privilegierter Angreifer, der die DB kontrolliert, kann einen neuen konsistenten Tree berechnen. Der externe Checkpoint ist die eigentliche Vertrauensgrenze.

### V7.1 — Forward Secrecy, Metronome, Per-Entry MACs

**Forward Secrecy (Anchor-Keys)**
- `_k_write_merkle` evolviert nach jedem `log_event()`: `k_n = HMAC(k_{n-1}, "evolve")`
- Alter Key wird überschrieben → kein Fälschen alter Anchor-MACs mit aktuellem Speicherdump
- `evolve_count` in `fs_key_state` persistiert → Key wird nach Neustart automatisch nachgezogen
- Verifikation evolviert `k_merkle` von der Basis auf `key_version` → alte Anchors bleiben prüfbar

**Metronome Heartbeats**
- `metronome_interval` (Sekunden, default 0=aus) aktiviert periodische `[METRONOME] beat=N`-Events
- `detect_truncation(recovered_events)` erkennt Heartbeat-Lücken (Hinweis auf gelöschte Events)
- Heartbeat-Zustand in `fs_metronome` persistiert, überlebt Neustarts

**Per-Entry MAC-Tags**
- Jeder `log_event()` speichert `HMAC(k_hmac, seq + event_msg)` in `event_mac_tags`
- `verify_event_mac(seq)` / `verify_all_event_macs()` für feingranulare Verifikation
- Ergänzt Merkle-Root: Merkle sagt *dass* etwas geändert wurde, MAC-Tags sagen *welches* Event

### V9.2 — Active-Analyst Test Suite

V9.2 erweitert das Threat-Model um einen **aktiven Analysten** mit Schreibrechten, der gezielt Carrier-Rows manipuliert, um die Reaktion des Systems zu provozieren. Die Test-Suite in [`tests/test_v9_active_analyst.py`](file:///c:/Users/tobs/.cursor/workspace/err/tests/test_v9_active_analyst.py) deckt fünf Angriffsvektoren ab:

| Vektor | Angriff | Erwartete Reaktion |
|--------|---------|--------------------|
| **A** — Probe & Tamper | Analyst flippt Bits in `trust_score` (5% der Rows) | RS+RAID-6 toleriert Verlust, Recovery findet Event |
| **B** — Column Wipe | Analyst setzt `trust_score = 0.0` für alle Rows | RAID-6 P+Q kompensiert 1/5 Kanal-Verlust |
| **C** — Timing & Correlation | Analyst beobachtet Schreib-Bursts nach `log_event()` | Adaptive Scheduler streut Writes (siehe V9.1) |
| **D** — Forensic Injection | Analyst injiziert Tilde-Noise in `avatar_url` | HMAC-shuffled Positionen verhindern Decodierung |
| **E** — Erasure Challenge | Analyst löscht 15% der Carrier-Rows | RS+RAID-6 toleriert Erasures bis zur Kapazitätsgrenze |

**Ausführen:**

```bash
python tests/test_v9_active_analyst.py
```

**Erwartete Ausgabe:**

```
=== Running Active Analyst Threat Model Tests ===
  PASS Vector A: Embedding + Tampering completed
  PASS Vector B: Column Wipe completed
  PASS Vector C: Timing Correlation check completed
  PASS Vector D: Forensic Injection completed
  PASS Vector E: Erasure Challenge completed
=== All Active Analyst Tests Passed ===
```

**Architektur-Implikation:** Die Tests verwenden `ga._engine.conn` direkt für Datenbank-Manipulationen, um Transaktionsisolierung mit dem Interceptor zu gewährleisten. Separate `sqlite3.connect()`-Verbindungen können in WAL-Mode zu Konflikten mit dem `_write_gate` führen.

**Manifest-Integrität:** Die `_sys_cache_row_mac`-Funktion in [`ghost_audit_v9.py`](file:///c:/Users/tobs/.cursor/workspace/err/core/ghost_audit_v9.py) hasht 5 separate 8-Byte-MACs über die rohen Carrier-Feldwerte (mit 6-stelliger Float-Rundung) plus optional den `timestamp_value` (als `>q` packed, wenn nicht `None`), sodass das Manifest konsistent bleibt, auch wenn die Carrier-Rows durch steganografische Operationen modifiziert werden. Der Timestamp wird nur dann in den MAC einbezogen, wenn ein `timestamp_field` konfiguriert und der Wert ein `int` ist (`None` = Backward Compat).

---

## Konfiguration & Env-Vars

Alle Parameter haben sinnvolle Defaults und können per Env-Var überschrieben werden:

| Env-Var | Default | Beschreibung |
|---------|---------|--------------|
| `GHOST_AUDIT_KEY` | — | Master-Key (bevorzugt gegenüber `secret_key`-Parameter) |
| `GHOST_AUDIT_SLOT_SIZE` | `1600` | Carrier-Zeilen pro Slot |
| `GHOST_AUDIT_PER_CHANNEL_MIN_REPS` | `5` | Max. Stego-Replikationen |
| `GHOST_AUDIT_ECC_SYMBOLS` | `36` | RS-Paritätssymbole (Baseline) |
| `GHOST_AUDIT_REPLICA_COUNT` | `3` | Anzahl Slot-Repliken pro Event |
| `GHOST_AUDIT_EXTERNAL_STATE` | `<db>.evolve` | Pfad zur Rollback-Erkennungsdatei |
| `GHOST_AUDIT_REBUILD_ECC_SYMBOLS` | `52` | Rebuild-nsym (Untergrenze, V8.4) |
| `GHOST_AUDIT_REBUILD_MIN_REPS` | `4` | Rebuild-Replikationen (Untergrenze, V8.4) |
| `GHOST_AUDIT_REBUILD_THRESHOLD` | `0.35` | Degradations-Schwelle für Rebuild-Trigger (V8.4) |
| `GHOST_AUDIT_REBUILD_INTERVAL` | `50` | Events zwischen zwei Idle-Checks (V8.4) |

**Beispiele (PowerShell):**

```powershell
# Höhere ECC-Stärke für sensible Umgebungen
$env:GHOST_AUDIT_ECC_SYMBOLS="48"

# Aggressiveres Self-Healing
$env:GHOST_AUDIT_REBUILD_THRESHOLD="0.20"
$env:GHOST_AUDIT_REBUILD_INTERVAL="25"

# Rollback-Schutz auf separatem Datenträger
$env:GHOST_AUDIT_EXTERNAL_STATE="E:\secure_mount\audit.evolve"
```

**TSA-Witness (V9.4, ersetzt Git-Witness):**

Seit V9.4 ist der **TSA-Witness** der primäre externe Zeuge. Der lokale Git-Witness aus V8.6 wird davon abgelöst: Der Background-Thread in `TimestampWitness` submitte SHA256(.evolve)-Digests an eine RFC 3161 Time-Stamp Authority (TSA) und persistiert die signierten Timestamp-Token in `sys_witness_queue`. Der Write-Pfad blockiert nie — bei TSA-Ausfall bleiben Entries `pending` und werden beim nächsten Poll-Zyklus nachgeholt.

```python
# Witness-Status abfragen:
status = ga.get_witness_status()
# → {"evolve_path": "app.evolve", "pending_count": 0,
#     "recent": [...], "thread_alive": True}
```

---

## API-Referenz

### V9 Konstruktor

```python
from core.carrier_config import CarrierConfig
from core.ghost_audit_v9 import GhostAuditInterceptor

carrier = CarrierConfig(
    table="users",
    id_field="id",
    semantic_field="bio",
    float_a_field="trust_score",
    float_b_field="profile_score",
    tilde_field="avatar_url",
    timestamp_field="created_at",  # V9.3: Ch2 Timestamp-LSB (optional, "" deaktiviert)
    slot_size=1600,
    slot_count=5,
)

ga = GhostAuditInterceptor(
    db_path="app.db",
    carrier_config=carrier,    # None nutzt Legacy-sys_cache-Layout
    secret_key=None,           # oder GHOST_AUDIT_KEY env-var
    key_provider=None,         # DPAPI / EnvKeyProvider
    ecc_symbols=36,
    verbose=True,
    siem_export_path=None,     # Auto-Export bei jedem log_event()
    siem_export_format="jsonl",# "jsonl" oder "cef"
    metronome_interval=0,      # Heartbeat-Intervall in Sekunden (0=aus)
    external_state_path=None,  # Rollback-Erkennungsdatei
    force_reinit=False,        # Admin-Override: überspringt alle Rollback-Checks (für Tests / DB-Neuanlage)
)
```

### V9 App-Write-Hook

```python
ga.log_event("user=alice action=login")

# fields sind die Werte, die du in die DB schreiben willst.
# Der Caller muss sicherstellen, dass alle relevanten Felder vollständig
# übergeben werden — auch wenn die App nur ein Subset updatet.
fields = {
    "bio": new_bio,              # der Wert, den das UPDATE gleich setzen wird
    "trust_score": new_score,
    "profile_score": new_profile,
    "avatar_url": new_avatar,
    "created_at": current_ts,    # V9.3: Ch2 Timestamp-LSB — write-once, nie vom ORM berührt
}
fields = ga.intercept(row_id=user_id, fields=fields)
# ↑ intercept() darf die Werte minimal transformieren (TextShape, Synonym,
#   Float-LSB). Der Rückgabewert ist das, was tatsächlich geschrieben wird.

# Die App schreibt genau diesen Rückgabewert mit ihrem normalen UPDATE.
# Nach dem Commit kann optional explizit geflusht werden; recover_events()
# ruft flush_headers() ebenfalls automatisch auf.
ga.flush_headers()
```

**`intercept()` — Caller Contract (in einem Satz):**

> `fields` sind die Werte, die du schreiben willst; `intercept()` gibt dir
> zurück, was du tatsächlich schreiben sollst.

**Daraus folgt:**

- Der Caller baut `fields` aus *seinen* neuen Werten auf (oder liest erst
  die DB, wenn das Update nur ein Subset betrifft — das ist Sache der App,
  nicht von GhostAudit).
- `intercept()` kennt **keinen** Vorher-Wert. Es arbeitet ausschließlich auf
  dem übergebenen Dict. Wenn ein Carrier-Feld (z.B. `bio` für Ch0) keine
  geeignete Embedding-Form trägt oder der Timestamp-Wert nicht parsbaren
  Typs ist (INTEGER/REAL/TEXT ISO-8601), wird die Row übersprungen und das
  pending Bit auf eine andere elegible Row verteilt.
- Der Rückgabewert ist **immer** ein vollständiges Dict mit denselben Keys
  wie `fields`. Auch wenn kein Bit eingebettet wurde, ist `returned == input`
  mit identischen Werten — die App kann bedingungslos schreiben.
- Es gibt **keinen** `current_fields`-Parameter. Wer Carrier-Kontext aus
  dem Vorher-Zustand braucht, muss den DB-Read vor `intercept()` machen.

### Logging

```python
ga.log_event("event message")           # gibt Sequenznummer zurück
ga.log_event("event", immediate_commit=False)  # deferred commit
ga.log_events(["msg1", "msg2"])          # Batch — gibt Liste von Sequenznummern zurück
```

### Recovery

```python
events = ga.recover_events()          # → [(seq, msg), ...]
gaps   = ga.detect_truncation(events) # Heartbeat-Lücken
```

### Verifikation

```python
ga.get_verification_digest()          # Merkle-Root als hex-String
ga.verify_event_mac(seq)              # einzelnes Event
ga.verify_all_event_macs()            # alle Events
ga.verify_merkle_root()               # aktueller Anchor
ga.list_merkle_anchors(limit=10)
```

### Checkpoint (externer Witness)

```python
# Checkpoint exportieren — in externe, read-only Location speichern
cp = ga.export_checkpoint(path="checkpoint.json")
# cp = {"seq": 42, "root": "a3f9...", "entry_chain": "...",
#        "anchor_chain": "...", "timestamp": "...", "mac": "..."}

# Später verifizieren (z.B. nach einem Incident)
result = ga.verify_checkpoint(cp)                        # aus dict
result = ga.verify_checkpoint(None, path="checkpoint.json")  # aus Datei
# result["valid"]              → True/False
# result["root_match"]         → Carrier-Layer unverändert?
# result["entry_chain_match"]  → Event-Kette unverändert?
# result["anchor_chain_match"] → Anchor-Kette unverändert?
# result["details"]            → "OK" oder Fehlerbeschreibung
```

### Export

```python
ga.export_recovered_logs("out.jsonl", format="jsonl")
ga.export_recovered_logs("out.cef",   format="cef")

### Capacity Metrics (V9.5)

```python
m = ga.get_capacity_metrics()
# m = {
#     "total_rows": 200,              # Zeilen in der Carrier-Tabelle
#     "required_rows": 8000,          # slot_count * slot_size
#     "deficit": 7800,                # Fehlende Zeilen
#     "capacity_pct": 2.5,            # Prozent der benötigten Zeilen
#     "slot_count": 5,
#     "slot_size": 1600,
#     "header_rows_per_slot": 72,
#     "payload_rows_total": 7640,     # 5 * (1600-72)
#     "coverage_estimate": 0.04,      # ~4% Rows sind elegibel
#     "effective_payload_rows": 305,  # payl. * coverage
#     "queue_size": 0,                # Aktuell eingereihte Events
#     "max_queue_size": 100,
# }
```

Bei einem Defizit >0 wird beim Start (`verbose=True`) eine Capacity-Warnung ausgegeben. Sobald die Queue >50% voll ist, erscheint alle 10 Events eine Early-Warning.

### Witness-Status (V9.4)

```python
status = ga.get_witness_status()
# status = {
#     "evolve_path": "app.evolve",
#     "pending_count": 0,                # noch nicht an TSA gesendet
#     "total_entries": 42,
#     "oldest_pending_age_ms": 0,        # 0 = keine pending
#     "health": "healthy",                # healthy | degraded | stale
#     "max_pending_age_s": 300,          # 5 min bis stale
#     "recent": [
#         {"seq": 42, "state": "confirmed", "tsa_url": "...", "confirmed_at": ...},
#         {"seq": 41, "state": "pending", "tsa_url": "", "confirmed_at": 0},
#     ],
#     "thread_alive": True,
# }
```

**Health-Zustände:**
- `healthy` — keine pending Entries, alles sauber
- `degraded` — pending Entries, aber jünger als `max_pending_age` (5 min) → TSA kurzzeitig nicht erreichbar
- `stale` — älteste pending Entry älter als `max_pending_age` → TSA länger ausgefallen, **einmalige Warnung via logger**
```
```

---

## Tests ausführen

```bash
# Interaktives Menü (Einstiegspunkt)
python tests/quickstart_tests.py

# Resilienz-Benchmark (5 quantitative Tests)
python tests/resilience_benchmark_v7.py

# Angriffssimulation V8 (5 Vektoren)
python tests/attack_simulator_v8.py

# Gradual Decay Ramp (50 BER-Stufen 0–49%)
python tests/gradual_decay_ramp_v82.py

# MUX Row-Wipe Sweep (5/10/15/20%)
python tests/sweep_wipe_v8.py

# Rollback-Erkennung
python tests/test_rollback_v82.py

# V9 Interceptor / echter Carrier
python -m pytest tests/test_v9_interceptor.py -q

# Härtungs-Tests (LSB, Forward Security, Merkle, Export)
python tests/test_hardenings_v7.py

# Multi-Kanal-Degradation (7 Szenarien)
python tests/test_multichannel_degradation.py

# Master-Testsuite (alle Läufe, JSON-Report)
python tests/master_test_suite_v7.py

# Durchsatz-Benchmark
python tests/benchmark_throughput_v8.py
```

---

## Testergebnisse

### Angriffssimulation V8

| Angriff | Vektor | Ergebnis |
|---------|--------|----------|
| MAC-Strip | `row_mac` aus Manifest gelöscht | ✅ 3/3 RECOVERED |
| MUX Row-Wipe 15% | 15% der Payload-Zeilen gelöscht | ✅ 3/3 RECOVERED |
| Bio-Normalize | `bio` lowercase+trim+synonym (2/5 Carrier) | ✅ 3/3 RECOVERED |
| Both-Floats Round | `trust_score`+`profile_score` gerundet (2/5 Carrier) | ✅ 3/3 RECOVERED |
| Gaussian Seed | Seed-Recovery-Versuch (Positive Control) | ✅ 3/3 RECOVERED |

### Resilienz-Benchmark V7

| Test | Schwelle | Ergebnis |
|------|----------|----------|
| Erasure Tolerance | ≥90% bei 8% Row-Erasure | ✅ 100% |
| Bit-Flip Resistance | ≥80% bei 10% BER | ✅ 100% |
| Channel Isolation | ≥90% bei partieller Ch0-Korruption | ✅ 100% |
| Multi-Column Erasure | ≥70% bei 50% Trailing-Space-Wipe | ✅ 100% |
| High BER Tolerance | ≥70% bei 10% Float-BER | ✅ 100% |

**5/5 — 100% PASSED**

### Gradual Decay Ramp (V8.2)

50-stufiger BER-Sweep (0–49%):

| Metrik | Ergebnis |
|--------|----------|
| CORRUPTED_LEAK | **0%** |
| Erster UNCORRECTABLE | Schritt 7 (BER=7%) — RS-mathematische Grenze |
| nsym-Bereich | 36–56 (adaptiv) |
| min_reps | 2–4 (stabil, keine Oszillation) |

---

## Bekannte Grenzen

- **Forschungsprototyp** — kein produktionsreifes Auditsystem
- V9 benötigt genügend echte Carrier-Rows und App-Writes, um pending Payload-Bits vollständig einzubetten.
- Header-Rows werden aktuell slotweise direkt über die GhostAudit-Engine geschrieben; Payload-Writes laufen über den App-Hook.
- ORM-Textnormalisierung (TRIM, lowercase, synonym-flatten) zerstört bio-basierte Carrier. Bio-SPOF Fix (V9.3) eliminiert Ch2 via Timestamp-LSB → nur noch **1/5 Carrier** betroffen (Ch0).
- RAID-6 toleriert **beliebige** 2/5 Carrier-Kill. Bei 3/5 ist keine Recovery möglich.
- Forward Security schützt Slots voneinander, nicht vor Verlust des Master-Keys.
- Rollback-Schutz hatte eine dokumentierte Grenze: Werden DB und `.evolve`-Datei gemeinsam aus demselben Snapshot wiederhergestellt, wurde kein Rollback erkannt. **Seit V9.4 ist diese Lücke durch den TSA-Witness geschlossen** — der `.evolve`-Digest ist in einem Public Append-Only Log signiert. Ein Both-Snapshot müsste zusätzlich den TSA-Log kompromittieren.
- `audit_archive` ist absichtlicher Köder — echte Recovery kommt aus der Carrier-Tabelle (`users` in V9, `sys_cache` im Legacy-Modus).

---

## Projektstruktur

```
core/
├── ghost_audit_v9.py          Interceptor-Architektur mit echtem App-Carrier
├── carrier_config.py          Konfiguration für Carrier-Tabelle und Felder
├── ghost_audit_v7.py          Engine und Legacy-sys_cache-Modus (V7–V8.x)
├── ecc_layer.py               Reed-Solomon Utilities
├── key_provider.py            DPAPI / EnvKeyProvider
├── timestamp_witness.py       RFC 3161 TSA-Witness (V9.4)
├── worker_erasure.py          Erasure-Recovery
└── security_suite_support.py  Factory, CLI-Flags, Test-Gate-Bypass

tests/
├── test_v9_interceptor.py     V9 Hook, echter Carrier, External-Carrier-Recovery
├── quickstart_tests.py        Interaktives Testmenü
├── master_test_suite_v7.py    Orchestrator, erzeugt JSON-Report
├── attack_simulator_v8.py     5 Angriffsvektoren (MITRE ATT&CK)
├── resilience_benchmark_v7.py 5 quantitative Robustheitstests
├── gradual_decay_ramp_v82.py  50-Stufen BER-Sweep
├── sweep_wipe_v8.py           MUX Row-Wipe Sweep
├── test_rollback_v82.py       Rollback-Erkennung
├── test_hardenings_v7.py      LSB, Forward Security, Merkle, Export
├── test_multichannel_degradation.py  7 ORM-Szenarien
├── benchmark_throughput_v8.py Durchsatz-Benchmark
└── hardware_resilience_test.py FileCarrier (binäre Datei statt SQLite)

docs/
├── README.md                  Diese Datei
├── README_GHOST_AUDIT.md      Ausführliche Vorgänger-Dokumentation
├── QUICK_REFERENCE.md         Kurzbefehle auf einen Blick
├── TEST_SUITE_OVERVIEW.md     Testfluss und Interpretation
└── HARDWARE_CARRIER_TEST.md   FileCarrier-Architektur

analysis/                      Sweep-Runner, Kapazitätsanalyse, Steganalyse
tools/                         Slot-Größen-Vergleich, Sweep-Aggregation, Key-Utilities
```
