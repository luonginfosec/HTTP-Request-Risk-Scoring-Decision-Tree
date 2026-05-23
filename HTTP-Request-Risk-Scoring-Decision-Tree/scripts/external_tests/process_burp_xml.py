"""CLI wrapper for converting any Burp Suite XML export into request CSV."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.burp_xml_converter import convert_burp_xml_to_csv


DEFAULT_OUTPUT = Path("data/processed/burp_external_requests.csv")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Process any Burp XML export into project request CSV.")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--label", choices=("0", "1"), default="0")
    parser.add_argument("--source", default=None)
    parser.add_argument("--notes", default="burp_external")
    parser.add_argument("--id-prefix", default="burp_external")
    parser.add_argument("--default-host", default="burp.local")
    parser.add_argument("--limit", type=int, default=5000)
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()
    count = convert_burp_xml_to_csv(
        args.input,
        args.output,
        label=args.label,
        source=args.source,
        notes=args.notes,
        id_prefix=args.id_prefix,
        default_host=args.default_host,
        limit=args.limit,
    )
    print(f"wrote {count} rows -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
