# GhostAudit — Quick Reference (V8 + V7)

## V8 Schnellstart

```bash
# V8 Attack Simulation (5 Angriffsvektoren)
python tests/attack_simulator_v8.py

# V8 MUX Row-Wipe Sweep (multi-level)
python tests/sweep_wipe_v8.py

# V8.2 Gradual Decay Ramp (50 BER-Stufen 0–49%)
python tests/gradual_decay_ramp_v82.py

# V8.2 Rollback-Detection Test
python tests/test_rollback_v82.py
```

## V7 Schnellstart

```bash
# Resilienz-Benchmark (5 Tests)
python tests/resilience_benchmark_v7.py

# Härtungs-Tests
python tests/test_hardenings_v7.py
```

## RS-Modus

| Version | Default | Modi |
|---------|---------|------|
| **V8** | Per-Channel RS + Per-Fragment Decode | 5 Carrier: Semantik(bio), Float-LSB(trust_score), Trailing-Space(bio), Float-LSB(profile_score), Tilde(avatar_url) — Carrier-Shuffling über 5 Träger |
| **V7** | Per-Channel RS (fest) | 4 Datenkanäle + XOR-Parität, Carrier-Shuffling |
| **V6** | Per-Channel RS | `--combined-rs` / `--per-channel-rs` / `GHOST_AUDIT_PER_CHANNEL_RS=0\|1` |

### Environment-Variablen

| Variable | V8 Default | Beschreibung |
|----------|-----------|--------------|
| `GHOST_AUDIT_SLOT_SIZE` | 1600 | Carrier-Zeilen pro Slot |
| `GHOST_AUDIT_PER_CHANNEL_MIN_REPS` | 5 | Max. Stego-Repliken (Obergrenze) |
| `GHOST_AUDIT_ECC_SYMBOLS` | 36 | RS-Paritätssymbole (Default seit V8.2) — erhöht Toleranz bei 2/5 Carrier-Kill |
| `GHOST_AUDIT_KEY` | — | Master-Key (Env bevorzugt) |
| `GHOST_AUDIT_EXTERNAL_STATE` | — | Pfad zur externen Zustandsdatei für Rollback-Erkennung (Default: db_path + ".evolve") |

### Verbindungs-PRAGMAs (V8.1)

## V8.2 Adaptive Feedback + Rollback-Schutz

```python
# External State Counter aktivieren (separate Datei, Standard neben DB)
ga = GhostAuditV7(
    db_path="audit.db",
    secret_key="mein-key",
    external_state_path="E:\\secure_mount\\audit.evolve",  # separater Datenträger!
)

# Bei Rollback (DB zurückgesetzt, *.evolve aber neuer) → RuntimeError
```

| Feature | Beschreibung |
|---------|-------------|
| Asymmetrischer EMA | α_attack=0.6, α_release=0.1 — schnelle Reaktion, kein Hunting |
| Sequentielle Probe | 15 Zeilen initial, +25 bei Unsicherheit (D 0.2–0.8) |
| nsym-Baseline | 36 (von 32) — +4 RS-Paritätssymbole = ~1,8% Platz-Overhead |
| Kaskadenschwelle | 0.15 (von 0.2) — frühere Aktivierung |
| nsym-Bugfix | `start_nsym = ecc_symbols + min_nsym` (war `max()`) |
| ExternalStateCounter | Monotoner Zähler in separater Datei erkennt Snapshot-Rollback |
| Gradual Decay Ramp | 0% CORRUPTED_LEAK über 50 BER-Stufen (0–49%) |

Automatisch gesetzt bei `GhostAuditV7()`:
```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA cache_size = -10000;  -- 10 MB
```

## Aktuelle Referenzwerte

### V8.1 Throughput (Native SQLite, Bulk-Staging + WAL) — 2026-06-01

| Payload | Write Ø | Recovery Ø |
|---------|---------|------------|
| 5B | **126 ms** | **336 ms** |
| 200B | **129 ms** | **341 ms** |
| 1KB | **135 ms** | **355 ms** |
| Batch 10× (100B) | **146 ms/ev** | — |

Write-Speedup ggü. V8: **2–3×** | Recovery-Speedup: **4–6×**

### V8 Attack Resilience (2026-06-01) — 5 Carrier aktiv

| Attacke | Ergebnis |
|---------|----------|
| MAC-Strip (row_mac deleted) | ✅ 3/3 RECOVERED |
| MUX Row-Wipe 15% | ✅ 3/3 RECOVERED |
| Bio Normalize (2/5 Carrier lost) | ✅ 3/3 RECOVERED (RAID-6 3D+2P: GF(2⁸) P+Q toleriert 2-Kanal-Verlust) |

| Gaussian Seed (Positive Control) | ✅ 3/3 RECOVERED |

| Selective Float Round (2/5 Carrier lost) | ✅ 3/3 RECOVERED (RAID-6 3D+2P + 3-Replica+Majority-Vote) |

### V7 Resilience Benchmark (2026-06-01) — 5/5 Tests ✅

| Test | Schwelle | Ergebnis |
|------|----------|----------|
| Erasure Tolerance | ≥90% @ 8% Row-Erasure | 100% |
| Bit-Flip Resistance | ≥80% @ 10% BER | 100% |
| Channel Isolation | ≥90% @ partielle Kanal-0-Korr. | 100% |
| Multi-Column Erasure | ≥70% @ 50% Trailing-Wipe | 100% |
| High BER Tolerance | ≥70% @ 10% Float-BER | 100% |

## Wichtige Hinweise

- V8 nutzt `5 x 1600` Carrier-Zeilen mit **5 Kanälen** (4 Daten + 1 Parität).
- **Carrier 4 (avatar_url):** Tilde-Suffix (`~`) als Bit-Marker — ORM-invariant, RFC-3986 unreserved.
- **Bio-SPOF Fix:** Carrier 3 = `profile_score REAL` (Float-LSB) statt Case-Switching — überlebt ORM-bio-Normalisierung.
- **Per-Fragment RS Decode:** Jedes Replikat wird einzeln RS-decodiert (kein Byte-Majority-Vote) → erstes sauberes Fragment gewinnt.
- **2/5 Carrier-Kill:** RAID-6 3D+2P (GF(2⁸) P+Q) toleriert jeden 2-Kanal-Verlust — Bio-Normalize und Float-Round sind vollständig recoverbar.
- Sichtbar: `audit_log` | Köder: `audit_archive` | Versteckt: `sys_cache`
- Seriell testen (SQLite-Locks unter Windows).

## Schnelle Einordnung

Grün: V8 Attack Sim — 4/5 Vektoren RECOVERED (inkl. Bio Normalize + Float Round), 1 TAMPERED (ökonomisch: 2/5 ohne RAID-6-Relevanz).

Erwartet: 2/5 Carrier-Kill mit RAID-6 3D+2P vollständig recoverbar. Bio-Normalize und Float-Round sind keine Verlustszenarien mehr.

Rot: `audit_log` und `sys_cache` beide verloren ohne Defense-in-Depth, oder Recovery bricht ohne Tamper-Hinweis.
