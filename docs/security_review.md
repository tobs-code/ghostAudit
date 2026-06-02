# 🔍 Security Review: GhostAudit V1–V6

## Übersicht

Dieses Dokument ist der kumulative Security-Review für alle Versionen von GhostAudit.
Abschnitte sind mit der betroffenen Version markiert.

---

## ✅ In V6 behobene Issues (aus V1–V4 Review)

| # | Issue | Status in V6 |
|---|---|---|
| 1 | Kein HMAC/MAC | ✅ Behoben — `k_hmac` pro Slot, HMAC-SHA256, Verifikation in `recover_logs()` |
| 2 | Hardcoded Secret Key | ✅ Teilweise — Fallback vorhanden, aber `GHOST_AUDIT_KEY`-Env-Var bevorzugt |
| 3 | `random.Random` statt krypto-PRNG | ✅ Behoben — Shuffling via `hmac.new(k_shuffling, ...)` deterministisch und kryptographisch |
| 4 | `_setup_db()` zerstört alles | ✅ Behoben — zerstörungsfreies Setup mit Legacy-Table-Rename |
| 6 | Nur 1 Event speicherbar | ✅ Ringbuffer mit 5 Slots + Fragmentierung |
| 7 | `recover_logs` braucht `msg_len` | ✅ Behoben — selbstbeschreibender Header mit validierter Payload-Länge |
| 10 | Trailing-Space unzuverlässig | ⚠️ Verbessert — Teil von 4-Kanal-Voting, bleibt fragil |
| 11 | Kanal-Interferenz (bio-Feld) | ⚠️ Verbessert — Header nutzt Case+Trailing+Float, Payload nutzt Semantic+Float+Trailing+Case |
| 12 | SQL Injection (V1/V2) | ✅ Behoben — hardcoded Tabellennamen in V3 |

---

## 🔴 V6-spezifische Schwachstellen

### 1. Angriffssimulation greift Gates, nicht Kanäle (BEHOBEN 2026-05-22)

**Schweregrad: Hoch (vor Fix: Kritisch — misleading)**

Vor dem Fix: `attack_simulator_v6.py` führte Mutationen über den regulären `self.cursor` aus, der durch SQLite-Trigger blockiert wurde. Alle 7 Angriffe schlugen fehl mit `"sys_cache writes require internal gate"`. Das Ergebnis — "0 successful attacks" — war irreführend, weil es die Stärke der Trigger und nicht die Robustheit der Steganographie-Kanäle maß.

**Fix:** `_bypass_gate()` entfernt Trigger via `DROP TRIGGER` und öffnet das Gate via direktem SQL auf einer separaten Verbindung. Jeder Angriff läuft auf sauberer Baseline. Report unterscheidet zwischen *executed* (Mutation angewendet) und *blocked* (Gate widerstand).

**Status:** ✅ Vollständig behoben — aktuelle Version zeigt 4 Angriffstypen mit 3 erfolgreichen Mutationen und 1 blockiertem HMAC-Versuch.

### 2. RS-Korrekturgrenze fälschlicherweise als "TAMPERING DETECTED" (BEHOBEN 2026-05-22)

**Schweregrad: Hoch**

_decode_slot_payload_bytes_ setzte bei JEDEM Manifest-Missbrauch oder Erasure ein _tampered=True_-Flag. Diese Information wurde in _recover_from_aux_ blind zusammen mit echtem Tampering kombiniert. Ergebnis: natürlich auftretende RS-Grenzen wurden als Manipulation gemeldet (False Positives), was _resilience_benchmark_v6.py_ durch die Prüfung _not in recovered[0]_ am ersten Eintrag teilweise ausglich.

**Fix:**
- _decode_slot_payload_bytes_ gibt keine Tamper-Flag mehr zurück, sondern nur _(bytes, erasure_pos)_.
- _recover_from_aux_ und _recover_fragmented_event_ unterscheiden drei Fälle:
  1. **RS-Fehler** → überspringen silently (nur bei echtem Slot-Tamper als _[TAMPERING DETECTED]_ markieren)
  2. **HMAC-Fehler** → definitiv _[TAMPERING DETECTED]_
  3. **Kompression/Decode-Fehler** → überspringen (fragmentierter Header-Randfall)

**Nachfolgend:** _resilience_benchmark_v6.py_ prüft nun _alle_ recovered Einträge auf _[TAMPERING DETECTET]_, nicht nur den ersten, wodurch false-negative-Ergebnisse verhindert werden.

### 3. Fragment-Header auf 15 Fragmente beschränkt (BEHOBEN 2026-05-22)

**Schweregrad: Mittel**

`_build_fragment_header` kodierte `fragment_index` und `fragment_count` in je 4 Bit → Maximum 15 Fragmente. Bei >15 Fragmenten brach die Fragmentierung.

**Fix:** Beide Felder auf 8 Bit erhöht → Maximum 255 Fragmente.

---

### 4. Write-Gate schützt vor externen Angriffen, nicht vor Insidern mit Key

**Schweregrad: Mittel**

Die internen SQLite-Trigger (`sys_cache_guard_*`) blockieren nur unvorbereitete Angreifer. Wer die DB-Datei direkt mit `sqlite3` öffnet, kann die Trigger mit `DROP TRIGGER` entfernen und das Gate öffnen. Das ist **kein Bug** — das Gate ist eine Defense-in-Depth-Maßnahme gegen zufällige oder uninformierte Zugriffe, kein kryptographisches Schutzschild.

---

### 5. Carrier-Daten sind synthetisch

**Schweregrad: Mittel**

Die 8000 `sys_cache`-Zeilen werden bei Setup mit 4 wiederkehrenden Templates generiert. In einem echten System wäre das auffällig. Für Forschung und Tests ist es akzeptabel, Produktionstauglichkeit erfordert echte heterogene Daten.

---

### 6. `secret_key`-Fallback ist deterministisch

**Schweregrad: Niedrig**

Wenn `GHOST_AUDIT_KEY` nicht gesetzt ist, wird `"dev-fallback-super-long-secure-key-123456789"` verwendet — derselbe Key für alle Installationen. Für Tests akzeptabel, in Produktion riskant.

---

### 7. Keine `.gitignore` (BEHOBEN 2026-05-22)

**Schweregrad: Niedrig (BEHOBEN)**

`.db`-Dateien, `__pycache__/` und temporäre Dateien sollten versioniert werden.

**Fix:** Umfassende `.gitignore` hinzugefügt, die alle Datenbanken (`*.db`), Cache-Verzeichnisse (`__pycache__/`), Benchmark-Reports und temporären Testdateien abdeckt.

---

## 📊 V6-Risikomatrix

| # | Schwachstelle | Schweregrad | Ausnutzbarkeit | Gegenmaßnahme |
|---|---|---|---|---|
| 1 | Write-Gate-Umgehung (Trigger-Drop) | Medium | Hoch bei DB-Admin-Zugriff | Gate ist Defense-in-Depth, keine kryptogr. Barriere |
| 2 | Carrier-Daten synthetisch | Medium | Hoch bei forensischer Prüfung | Echte heterogene Daten verwenden |
| 3 | Secret-Key-Fallback deterministisch | Low | Mittel bei versehentlichem Deploy | Env-Var erzwingen |
| 4 | Kanal-Korrelation durch bio-Feld | Low | Niedrig | Separate Felder pro Kanal |
| 5 | Float-LSB fragil bei Business-Logik-Updates | Low | Mittel | Float durch festen Integer ersetzen |

---

## ✅ V6 — Was gut funktioniert

1. **HMAC-SHA256** pro Payload — Manipulation wird zuverlässig erkannt
2. **Reed-Solomon ECC (max. 32 ECC-Symbole)** — nsym wird automatisch via SELECT_ECC optimiert (bevorzugt min_rep≥2), korrigiert bis zu `nsym/2` Bytefehler pro Kanal
3. **4-Kanal-Voting** bei Header und Payload — toleriert einzelne Kanalausfälle
4. **Fragmentierung** für lange Events — verteilt über mehrere Slots
5. **HMAC-Subkeys** für Shuffling und Payload-Integrität getrennt
6. **Manifest (`sys_cache_manifest`)** als Integritätsanker für sys_cache-Zeilen
7. **Keine Zerstörung bei wiederholtem Setup** — persistente DB mit Legacy-Rename
8. **Ringbuffer** 5 Slots — append-Semantik über Events hinweg
9. **`check_integrity()`** Methode in `GhostAuditV6` — Rückgabe von Tamper-Alerts zur kontinuierlichen Integritätsprüfung in Produktion
