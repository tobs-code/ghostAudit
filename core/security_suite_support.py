"""Shared helpers for GhostAudit V6 security test scripts."""

from __future__ import annotations

import argparse
from typing import Optional

from core.ghost_audit_v6 import GhostAuditV6


def add_mode_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--per-channel-rs",
        action="store_true",
        help="Enable GhostAuditV6.PER_CHANNEL_RS (independent RS per stego channel).",
    )
    group.add_argument(
        "--combined-rs",
        action="store_true",
        help="Force combined RS mode (overrides PER_CHANNEL_RS class default).",
    )


def add_per_channel_arg(parser: argparse.ArgumentParser) -> None:
    """Backward-compatible alias."""
    add_mode_args(parser)


def resolve_per_channel_rs(args: argparse.Namespace) -> bool:
    if getattr(args, "combined_rs", False):
        return False
    if getattr(args, "per_channel_rs", False):
        return True
    return GhostAuditV6.PER_CHANNEL_RS


def parse_per_channel_rs(argv: Optional[list[str]] = None) -> bool:
    parser = argparse.ArgumentParser(add_help=False)
    add_per_channel_arg(parser)
    args, _ = parser.parse_known_args(argv)
    return bool(args.per_channel_rs)


def report_suffix(per_channel_rs: bool) -> str:
    return "_per_channel" if per_channel_rs else ""


def attack_report_path(per_channel_rs: bool) -> str:
    return f"attack_simulation_report{report_suffix(per_channel_rs)}.json"


def metrics_report_path(per_channel_rs: bool) -> str:
    return f"resilience_metrics{report_suffix(per_channel_rs)}.json"


def mode_label(per_channel_rs: bool) -> str:
    return "per_channel_rs" if per_channel_rs else "combined_rs"


def create_ga(
    db_path: str,
    secret_key: str,
    *,
    per_channel_rs: bool = False,
    verbose: bool = False,
) -> GhostAuditV6:
    ga = GhostAuditV6(db_path=db_path, secret_key=secret_key, verbose=verbose)
    ga.PER_CHANNEL_RS = per_channel_rs
    return ga


def clear_visible_audit_trail(ga: GhostAuditV6) -> None:
    ga.conn.execute(f"DELETE FROM {GhostAuditV6.VISIBLE_LOG_TABLE}")
    ga.conn.execute(f"DELETE FROM {GhostAuditV6.DECOY_ARCHIVE_TABLE}")
    ga.conn.commit()


def open_sys_cache_raw(db_path: str) -> "sqlite3.Connection":
    """Return a sqlite3 connection with GhostAudit write-gate triggers disabled."""
    import sqlite3

    conn = sqlite3.connect(db_path)
    conn.execute("DROP TRIGGER IF EXISTS sys_cache_guard_update")
    conn.execute("DROP TRIGGER IF EXISTS sys_cache_guard_insert")
    conn.execute("DROP TRIGGER IF EXISTS sys_cache_guard_delete")
    conn.execute("DROP TRIGGER IF EXISTS sys_cache_block_null_bio")
    conn.execute("DROP TRIGGER IF EXISTS sys_cache_block_null_score")
    conn.execute("UPDATE sys_cache_write_gate SET allow_write=1 WHERE id=1")
    conn.commit()
    return conn
