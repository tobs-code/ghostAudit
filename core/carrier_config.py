"""
CarrierConfig — describes which fields of an existing application table
are used as steganographic carriers.

Design goals
------------
- Zero hardcoding: table name, field names, and value ranges are all
  supplied by the caller.
- Stateless: just a data container, no DB access.
- Validates at construction time so mistakes surface early.

Carrier roles
-------------
Each physical carrier maps to one field and one encoding method.
The logical-to-physical channel assignment is shuffled per-row via HMAC
(same as V7), so this config only describes the *physical* layer.

  slot 0  semantic      text field     — synonym switching
  slot 1  float_lsb_a   float field    — LSB ±1 encoding
  slot 2  timestamp_lsb timestamp field — LSB on Unix-ms (INTEGER) or parsed ISO-8601
  slot 3  float_lsb_b   float field    — LSB ±1 encoding (independent column)
  slot 4  tilde          text field     — tilde suffix (~)

Semantic (slot 0) and timestamp (slot 2) can live on different columns,
eliminating the shared-field SPOF that existed when both carriers shared
a single text column.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class CarrierConfig:
    """Configuration for a single carrier table.

    Parameters
    ----------
    table : str
        Name of the existing application table used as carrier.
    id_field : str
        Primary key column name (must be INTEGER or TEXT, unique per row).
    semantic_field : str
        Text column for synonym-switching and trailing-space encoding
        (carriers 0 and 2).
    float_a_field : str
        Float column for LSB encoding — carrier 1 (e.g. trust_score).
    float_b_field : str
        Float column for LSB encoding — carrier 3 (e.g. profile_score).
        Must be a *different* column from float_a_field.
    tilde_field : str
        Text column for tilde-suffix encoding — carrier 4 (e.g. avatar_url).
    float_a_range : tuple[float, float]
        Plausible value range for float_a_field, e.g. (0.0, 1.0).
        Used for sanity checks; encoding never moves values outside this range.
    float_b_range : tuple[float, float]
        Plausible value range for float_b_field.
    slot_size : int
        Number of rows per ECC slot.  Must divide evenly into the number of
        rows in the carrier table.  Default 1600 (same as V7).
    slot_count : int
        Number of ECC slots.  slot_size * slot_count <= total carrier rows.
        Default 5.
    """

    table: str
    id_field: str
    semantic_field: str
    float_a_field: str
    float_b_field: str
    tilde_field: str
    timestamp_field: str = ""
    integer_channel_field: str = ""
    float_a_range: tuple = (0.0, 1.0)
    float_b_range: tuple = (0.0, 1.0)
    slot_size: int = 1600
    slot_count: int = 5

    def __post_init__(self):
        # Basic sanity checks
        if not self.table:
            raise ValueError("CarrierConfig: table must not be empty")
        if self.float_a_field == self.float_b_field:
            raise ValueError(
                "CarrierConfig: float_a_field and float_b_field must be different columns"
            )
        if self.slot_size < 144:
            # 72 header rows + at least 72 payload rows
            raise ValueError("CarrierConfig: slot_size must be >= 144")
        if self.slot_count < 1:
            raise ValueError("CarrierConfig: slot_count must be >= 1")
        lo_a, hi_a = self.float_a_range
        if lo_a >= hi_a:
            raise ValueError("CarrierConfig: float_a_range must be (low, high) with low < high")
        lo_b, hi_b = self.float_b_range
        if lo_b >= hi_b:
            raise ValueError("CarrierConfig: float_b_range must be (low, high) with low < high")

    @classmethod
    def from_config_dict(cls, d: dict) -> "CarrierConfig":
        """Build from a discovery dict (schema_version + table werden ignoriert/extrahiert).

        ``d`` kann ``schema_version`` und ``table`` enthalten
        (z.B. aus ``ghostaudit discover --write config.json``),
        die werden vor der Konstruktion entfernt.
        """
        d = dict(d)
        d.pop("schema_version", None)
        table = d.pop("table", None) or "sys_cache"
        # Nur bekannte Felder übergeben
        known = {"table", "id_field", "semantic_field", "float_a_field",
                 "float_b_field", "tilde_field", "timestamp_field",
                 "integer_channel_field", "float_a_range", "float_b_range",
                 "slot_size", "slot_count"}
        kwargs = {k: v for k, v in d.items() if k in known}
        kwargs.setdefault("table", table)
        return cls(**kwargs)

    @property
    def total_carrier_rows(self) -> int:
        return self.slot_size * self.slot_count

    @property
    def header_row_count(self) -> int:
        """Header rows per slot (same as V7 HEADER_BIT_COUNT = 72)."""
        return 72

    @property
    def payload_rows_per_slot(self) -> int:
        return self.slot_size - self.header_row_count

    def all_field_names(self) -> list[str]:
        """Return deduplicated list of all carrier field names."""
        seen = {}
        result = []
        for f in [
            self.id_field,
            self.semantic_field,
            self.float_a_field,
            self.float_b_field,
            self.tilde_field,
            self.timestamp_field,
            self.integer_channel_field,
        ]:
            if f not in seen:
                seen[f] = True
                result.append(f)
        return result


# ---------------------------------------------------------------------------
# Convenience factory for the legacy sys_cache layout (V7 compatibility)
# ---------------------------------------------------------------------------

def v7_default_config() -> CarrierConfig:
    """Return a CarrierConfig matching the hard-coded V7 sys_cache layout."""
    return CarrierConfig(
        table="sys_cache",
        id_field="id",
        semantic_field="bio",
        float_a_field="trust_score",
        float_b_field="profile_score",
        tilde_field="avatar_url",
        timestamp_field="",
        float_a_range=(0.0, 1.0),
        float_b_range=(0.0, 1.0),
        slot_size=1600,
        slot_count=5,
    )
