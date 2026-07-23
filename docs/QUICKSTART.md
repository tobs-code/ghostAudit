# GhostAudit — Quickstart

Erster Audit-Event in Deiner App-Tabelle in 5 Minuten.

## Voraussetzungen

- Python 3.10+
- Eine SQLite-Datenbank mit einer Tabelle
- `pip install ghostaudit` (kommt — aktuell: `git clone` + `pip install -r requirements.txt`)

## Schritt 1 — Schema entdecken

```bash
python ghostaudit.py discover app.db users
```

Der Report zeigt Dir welche Felder als Carrier-Kanäle taugen und mit welcher Confidence:

```
  Feld                   Rolle                         Score  Bewertung
  --------------------   -------------------------   ------  ---------------
  ui_prefs               integer_channel_field           90  EMPFOHLEN
  trust_score            float_a_field                   85  EMPFOHLEN
  profile_score          float_b_field                   80  EMPFOHLEN
  created_at             timestamp_field                 80  EMPFOHLEN
  avatar_url             tilde_field                     80  EMPFOHLEN
  bio                    semantic_field                  70  MÖGLICH
```

- **≥ 80** → sicherer Carrier (App schreibt selten/nie auf das Feld)
- **50–79** → funktioniert, aber Risiko durch App-Überschreibungen
- **< 50** → zu hohes Carrier-Kill-Risiko, besser weglassen

Config schreiben + prüfen:

```bash
python ghostaudit.py discover app.db users --write config.json
# config.json ansehen — schema_version checken, Confidence < 80 manuell entscheiden
```

## Schritt 2 — Interceptor starten

```python
from core.ghost_audit_v9 import GhostAuditInterceptor
from core.carrier_config import CarrierConfig
import json

with open("config.json") as f:
    cfg = CarrierConfig.from_config_dict(json.load(f))
print(f"Config: table={cfg.table}, integer_ch={cfg.integer_channel_field}")
for ch, field in enumerate(cfg.all_field_names()):
    if field:
        print(f"  Ch{ch} ← {field}")

interceptor = GhostAuditInterceptor("app.db", carrier_config=cfg, verbose=True)

## Schritt 3 — Jeden UPDATE intercepten

```python
# Vor dem UPDATE: Interceptor embedet die nächsten Pending-Bits
modified = interceptor.intercept(row_id=user_id, fields={"bio": bio, "ui_prefs": ui_prefs})

# App führt das UPDATE mit den modifizierten Werten aus:
cursor.execute(
    "UPDATE users SET bio=?, trust_score=?, ui_prefs=? WHERE id=?",
    (modified["bio"], modified["trust_score"], modified["ui_prefs"], user_id)
)

# Nach dem UPDATE prüfen: Hat die App die Carrier-Felder überschrieben?
ok = interceptor.verify_write(user_id, modified)
if not ok:
    # Carrier weg — wird beim nächsten recover_events() als Erasure erkannt
    pass  # Counterpart zu erasure_total{} im Dashboard
```

> **API-Notiz:** `verify_write()` braucht die kompletten `fields_written`
> (die modifizierten Werte, nicht nur die Row-ID). Wer die `modified`-Dict
> nicht aufhebt, kann nicht prüfen. Das ist der häufigste API-Fehler.

## Schritt 4 — Audit-Event loggen

```python
seq = interceptor.log_structured_event(
    event_type="user.profile_update",
    actor_id=admin_id,
    target_id=user_id,
    payload={"field": "bio"},
)
print(f"Audit-Event #{seq} eingereiht")
```

Der Event liegt jetzt im Audit-Log (`audit_log`-Tabelle) **und** wird bei
den nächsten App-UPDATEs in die Carrier-Felder eingebettet.

Wer einen plain String loggen will, nutzt `interceptor.log_event(msg)` direkt.

Der Event liegt jetzt im Audit-Log (`audit_log`-Tabelle) **und** wird bei
den nächsten App-UPDATEs in die Carrier-Felder eingebettet.

## Schritt 5 — Recovery (z.B. beim App-Start)

```python
events = interceptor.recover_events()
for seq, msg in events:
    print(f"[#{seq}] {msg}")
    # → in Dein Audit-Log schreiben (Elastic, SIEM, ...)
```

`recover_events()` liest alle Carrier-Rows aus, decodiert per RS+RAID-6 und
gibt `[(seq, message), ...]` zurück — sortiert, dedupliziert, konsistent.
Messages sind JSON-Strings wenn mit `log_structured_event` geloggt.

## Schritt 6 — Metriken (optional, aber empfohlen)

```python
from core.metrics import PrometheusMetricRegistry

metrics = PrometheusMetricRegistry()
interceptor = GhostAuditInterceptor(
    "app.db",
    carrier_config=cfg,
    metric_registry=metrics,
)
```

Ohne `metric_registry` wird `NoopMetricRegistry` verwendet — null Overhead.

Die Metriken landen in `prometheus_client`-Registries und können in jeden
Prometheus- / OpenTelemetry-Endpoint gehängt werden:

```python
from prometheus_client import start_http_server
start_http_server(8000)  # /metrics mit ghostaudit_carrier_erasure_total u.a.
```

## Was jetzt?

| Topic | Wohin |
|---|---|
| Kanal-Architektur & Threat-Model | `README.md` |
| CarrierConfig alle 14 Felder | Docstring in `core/carrier_config.py` |
| Wie try_flush() funktioniert | `flush_headers()` + `try_flush()` Docstrings |
| RAID-6 / Erasure-Coding | `core/ghost_audit_v7.py: _encode_payload_per_channel_v7` |
| Legacy sys_cache-Modus | `README_GHOST_AUDIT.md` |
| Historische Feature-Chronik | `README.md` (V9.4–V9.12) |
