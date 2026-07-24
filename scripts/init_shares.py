#!/usr/bin/env python3
"""
Initialize threshold-shared master key for GhostAudit.
Splits a master key into N shares and stores each in a separate SQLite DB.
Usage:
    python scripts/init_shares.py --shares 5 --threshold 3 --out share_?.db
    python scripts/init_shares.py --shares 3 --threshold 2 --out /mnt/usb1/share.db /mnt/usb2/share.db /mnt/usb3/share.db
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.shamir_secret_sharing import split_secret, create_share_db, write_share


def main():
    parser = argparse.ArgumentParser(description="Split a master key into threshold shares stored in SQLite DBs")
    parser.add_argument("--shares", type=int, default=5, help="Total number of shares (N)")
    parser.add_argument("--threshold", type=int, default=3, help="Minimum shares to reconstruct (K)")
    parser.add_argument("--key", type=str, default=None, help="Master key (if omitted, read from GHOST_AUDIT_KEY env or generate)")
    parser.add_argument("--key-file", type=str, default=None, help="Read master key from file")
    parser.add_argument("--out", type=str, nargs="+", required=True, help="Output SQLite database paths (one per share, or use {i} placeholder)")
    parser.add_argument("--table", type=str, default="shamir_shares", help="SQLite table name for shares")
    parser.add_argument("--key-bytes", type=int, default=32, help="Generated key length in bytes")

    args = parser.parse_args()

    if args.key:
        key = args.key.encode("utf-8")
    elif args.key_file:
        with open(args.key_file, "rb") as f:
            key = f.read().strip()
    elif os.environ.get("GHOST_AUDIT_KEY"):
        key = os.environ["GHOST_AUDIT_KEY"].encode("utf-8")
    else:
        import secrets
        key = secrets.token_bytes(args.key_bytes)
        print(f"[init_shares] Generated random {len(key)}-byte master key")

    n = args.shares
    k = args.threshold
    if k < 2:
        print("ERROR: threshold must be >= 2")
        sys.exit(1)
    if n < k:
        print("ERROR: n must be >= k")
        sys.exit(1)

    out_paths = []
    for p in args.out:
        out_paths.append(p)

    if len(out_paths) != n:
        print(f"ERROR: need exactly {n} output paths, got {len(out_paths)}")
        sys.exit(1)

    shares = split_secret(key, n, k)
    for i, (share_id, share_val) in enumerate(shares):
        db_path = out_paths[i]
        create_share_db(db_path)
        write_share(db_path, args.table, share_id, share_val)
        print(f"[init_shares] Share {share_id}/{n} written to {db_path} ({len(share_val)} bytes)")

    print(f"[init_shares] Done: {n} shares created, threshold={k}")
    print(f"[init_shares] To use: GhostAuditV7(shares=[")
    for i, db_path in enumerate(out_paths):
        print(f"    (\"{db_path}\", \"{args.table}\", {shares[i][0]}),")
    print(f"], share_threshold={k})")


if __name__ == "__main__":
    main()
