"""
GhostAudit CLI — Carrier-Discovery und Konfiguration.

Usage:
    python ghostaudit.py discover app.db users
    python ghostaudit.py discover app.db users --write config.json
"""

import sys
import json
import argparse
from core.discovery import discover_carrier, print_discovery_report


def main():
    parser = argparse.ArgumentParser(description="GhostAudit CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    discover = sub.add_parser("discover", help="Carrier-Felder in einer DB-Tabelle erkennen")
    discover.add_argument("db_path", help="Pfad zur SQLite-Datenbank")
    discover.add_argument("table", help="Tabellenname")
    discover.add_argument("--write", "-w", help="Config in JSON-Datei schreiben", default=None)

    args = parser.parse_args()

    if args.command == "discover":
        result = discover_carrier(args.db_path, args.table)
        print_discovery_report(result)

        if args.write:
            config = result.suggested_config
            config["table"] = args.table
            with open(args.write, "w") as f:
                json.dump(config, f, indent=2)
            print(f"Config geschrieben: {args.write}")

        sys.exit(1 if result.warnings else 0)


if __name__ == "__main__":
    main()
