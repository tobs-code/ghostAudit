"""
Carrier Discovery — schlägt CarrierConfig aus einem existierenden DB-Schema vor.

Usage:
    from core.discovery import discover_carrier
    config = discover_carrier("app.db", "users")
    print(config.suggested_config)
    # → CarrierConfig(table="users", id_field="id", float_a_field="trust_score", ...)

CLI:
    python -m core.discovery app.db users
"""

from __future__ import annotations
import sqlite3
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ColumnInfo:
    name: str
    type: str
    notnull: bool
    dflt_value: Optional[str]
    pk: bool


@dataclass
class CarrierSuggestion:
    """Eine einzelne Rollenempfehlung für ein Feld."""

    role: str            # z.B. "id_field", "float_a_field", "integer_channel_field"
    field: str
    score: int           # 0-100: wie gut der Match ist
    reason: str          # Warum dieses Feld empfohlen wird (zur Anzeige)


@dataclass
class DiscoveryResult:
    """Kompletter Discovery-Report für eine Tabelle."""

    table: str
    columns: list[ColumnInfo]
    suggestions: list[CarrierSuggestion]
    warnings: list[str] = field(default_factory=list)

    @property
    def suggested_config(self) -> dict[str, str]:
        """Beste Vorschläge als flaches dict (role → field)."""
        best: dict[str, CarrierSuggestion] = {}
        for s in self.suggestions:
            if s.role not in best or s.score > best[s.role].score:
                best[s.role] = s
        return {s.role: s.field for s in best.values()}


# ---------------------------------------------------------------------------
# Whitelist-Patterns
# ---------------------------------------------------------------------------

_ID_PATTERNS = {"id", "user_id", "customer_id", "account_id", "pk"}
_FLOAT_A_PATTERNS = {"trust_score", "score", "rating", "average", "avg",
                     "percentage", "pct", "trust_score", "reputation"}
_FLOAT_B_PATTERNS = {"profile_score", "secondary_score", "bonus", "weight",
                     "confidence", "probability"}
_TIMESTAMP_PATTERNS = {"created_at", "updated_at", "created", "updated",
                       "timestamp", "date", "modified_at", "inserted_at"}
_TILDE_PATTERNS = {"avatar_url", "url", "image_url", "picture", "avatar",
                   "photo_url", "thumbnail", "link", "website"}
_INTEGER_CH_PATTERNS = {"notification_flags", "ui_prefs", "sync_version",
                        "cache_hint", "feature_flags", "settings_mask",
                        "preferences", "config_flags"}


def _score_id(col: ColumnInfo) -> Optional[CarrierSuggestion]:
    if col.type.upper() in ("INTEGER", "INT", "BIGINT") and col.pk:
        name_lower = col.name.lower()
        score = 100 if name_lower in _ID_PATTERNS else 80
        return CarrierSuggestion("id_field", col.name, score,
                                 f"INTEGER PRIMARY KEY — {'exakter Pattern-Match' if score == 100 else 'akzeptabel'}")
    return None


def _score_float(col: ColumnInfo) -> list[CarrierSuggestion]:
    if col.type.upper() not in ("REAL", "FLOAT", "DOUBLE", "NUMERIC"):
        return []
    name_lower = col.name.lower()
    results: list[CarrierSuggestion] = []
    if name_lower in _FLOAT_A_PATTERNS:
        results.append(CarrierSuggestion("float_a_field", col.name, 95,
                                         "REAL — exakter Pattern-Match für Float-A"))
    if name_lower in _FLOAT_B_PATTERNS:
        results.append(CarrierSuggestion("float_b_field", col.name, 95,
                                         "REAL — exakter Pattern-Match für Float-B"))
    # Generic float — slot into what's available
    results.append(CarrierSuggestion("float_a_field", col.name, 60,
                                     "REAL — generisches Float-Feld"))
    results.append(CarrierSuggestion("float_b_field", col.name, 50,
                                     "REAL — generisches Float-Feld (Sekundär)"))
    return results


def _score_timestamp(col: ColumnInfo) -> Optional[CarrierSuggestion]:
    name_lower = col.name.lower()
    if name_lower in _TIMESTAMP_PATTERNS:
        return CarrierSuggestion("timestamp_field", col.name, 95,
                                 f"{col.type} — Timestamp-Pattern erkannt ('{col.name}')")
    if col.type.upper() in ("INTEGER", "INT", "BIGINT") and "time" in name_lower:
        return CarrierSuggestion("timestamp_field", col.name, 70,
                                 "INTEGER — könnte Unix-Timestamp sein ('time' im Namen)")
    return None


def _score_tilde(col: ColumnInfo) -> Optional[CarrierSuggestion]:
    name_lower = col.name.lower()
    if name_lower in _TILDE_PATTERNS:
        return CarrierSuggestion("tilde_field", col.name, 95,
                                 f"TEXT — URL-Pattern erkannt ('{col.name}')")
    if col.type.upper() in ("TEXT", "VARCHAR", "CHAR") and any(t in name_lower for t in ("url", "avatar", "photo", "image", "picture", "link")):
        return CarrierSuggestion("tilde_field", col.name, 75,
                                 "TEXT — könnte URL sein")
    return None


def _score_integer_ch(col: ColumnInfo) -> Optional[CarrierSuggestion]:
    if col.type.upper() not in ("INTEGER", "INT", "BIGINT"):
        return None
    if col.pk:
        return None  # PK ist id_field, nicht Channel
    name_lower = col.name.lower()
    if name_lower in _INTEGER_CH_PATTERNS:
        return CarrierSuggestion("integer_channel_field", col.name, 95,
                                 f"INTEGER — Bitmask-Pattern ('{col.name}')")
    if col.dflt_value == "0":
        return CarrierSuggestion("integer_channel_field", col.name, 60,
                                 f"INTEGER DEFAULT 0 — brauchbares Bitmask-Kandidat")
    return None


def _score_semantic(col: ColumnInfo) -> Optional[CarrierSuggestion]:
    if col.type.upper() not in ("TEXT", "VARCHAR", "CHAR", "CLOB"):
        return None
    if col.name.lower() == "bio":
        return CarrierSuggestion("semantic_field", col.name, 50,
                                 "TEXT — bio-Feld, Synonym-Switching möglich (nur Fallback)")
    if col.name.lower() in ("description", "about", "notes", "comment", "text"):
        return CarrierSuggestion("semantic_field", col.name, 40,
                                 f"TEXT — '{col.name}' als Synonym-Fallback nutzbar")
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def discover_columns(db_path: str, table: str) -> list[ColumnInfo]:
    """Liest PRAGMA table_info und gibt ColumnInfo-Liste zurück."""
    with sqlite3.connect(db_path, timeout=10) as conn:
        cursor = conn.execute(f"PRAGMA table_info({table})")
        return [
            ColumnInfo(
                name=row[1],
                type=(row[2] or "TEXT").upper(),
                notnull=bool(row[3]),
                dflt_value=row[4],
                pk=bool(row[5]),
            )
            for row in cursor.fetchall()
        ]


def discover_carrier(db_path: str, table: str) -> DiscoveryResult:
    """Discovert verfügbare Carrier-Felder in einer Tabelle.

    Returns einen DiscoveryResult mit Column-Infos + Vorschlägen + Warnungen.
    """
    columns = discover_columns(db_path, table)
    suggestions: list[CarrierSuggestion] = []
    warnings: list[str] = []

    if not columns:
        warnings.append(f"Tabelle '{table}' existiert nicht oder hat keine Spalten.")
        return DiscoveryResult(table, columns, suggestions, warnings)

    for col in columns:
        for scorer in (_score_id, _score_timestamp, _score_tilde,
                       _score_integer_ch, _score_semantic):
            result = scorer(col)
            if result:
                suggestions.append(result)
        suggestions.extend(_score_float(col))

    # Konfigurierbarkeit prüfen
    roles_found = set(s.role for s in suggestions)
    float_count = len([s for s in suggestions if s.role in ("float_a_field", "float_b_field") and s.score >= 50])

    if "id_field" not in roles_found:
        warnings.append("Keine INTEGER PRIMARY KEY Spalte gefunden — id_field wird benötigt.")
    if float_count < 2:
        warnings.append("Weniger als 2 Float-Spalten gefunden — Float-LSB-Kanäle (Ch1/Ch3) stehen nicht zur Verfügung.")
    if "tilde_field" not in roles_found:
        warnings.append("Kein URL/Tilde-Feld (Ch4) erkannt — optional, aber reduziert Kanaltiefe.")
    if "integer_channel_field" not in roles_found:
        warnings.append("Kein Integer-Bitmask-Feld (Ch0) erkannt — Fallback auf Synonym-Switching in bio.")

    return DiscoveryResult(table, columns, suggestions, warnings)


def print_discovery_report(result: DiscoveryResult) -> None:
    """Gibt den Discovery-Report formatiert auf stdout aus."""
    print(f"\n=== Carrier-Discovery: {result.table} ===")
    print(f"\nSchema ({len(result.columns)} Spalten):")
    for col in result.columns:
        pk = " PK" if col.pk else ""
        nn = " NOT NULL" if col.notnull else ""
        dflt = f" DEFAULT {col.dflt_value}" if col.dflt_value else ""
        print(f"  {col.name:20s}  {col.type:10s}{pk}{nn}{dflt}")

    config = result.suggested_config
    if config:
        print(f"\nVorgeschlagene CarrierConfig:")
        for role in ["id_field", "integer_channel_field", "float_a_field",
                     "float_b_field", "timestamp_field", "tilde_field", "semantic_field"]:
            val = config.get(role, "— nicht gefunden —")
            print(f"  {role:25s} = {val}")

        print(f"\nPython-Code:")
        print(f"  from core.carrier_config import CarrierConfig")
        fields = ",\n        ".join(f'{role.replace("field", "field")}="{val}"'
                                     if val != "— nicht gefunden —" else f"#{role} leer lassen"
                                     for role, val in config.items())
        print(f"  cfg = CarrierConfig(")
        print(f"      table=\"{result.table}\",")
        for role in ["id_field", "integer_channel_field", "float_a_field",
                     "float_b_field", "timestamp_field", "tilde_field", "semantic_field"]:
            val = config.get(role)
            if val:
                print(f"      {role}={val!r},")
        print(f"  )")

    if result.warnings:
        print(f"\nWarnungen ({len(result.warnings)}):")
        for w in result.warnings:
            print(f"  ⚠ {w}")

    print(f"\n{len(result.suggestions)} Vorschläge, {len(result.warnings)} Warnungen\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import sys
    if len(sys.argv) < 3:
        print("Usage: python -m core.discovery <db_path> <table>")
        print("       python -m core.discovery app.db users")
        sys.exit(1)

    db_path = sys.argv[1]
    table = sys.argv[2]
    result = discover_carrier(db_path, table)
    print_discovery_report(result)
    sys.exit(1 if result.warnings else 0)


if __name__ == "__main__":
    main()
