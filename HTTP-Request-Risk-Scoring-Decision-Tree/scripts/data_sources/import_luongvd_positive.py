"""Import positive request rows from the existing ../luongvd dataset.

The source CSV already contains attack-shaped request rows with label=1.
This script projects those rows into the project-wide schema used for later
training and merging with normal traffic.
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


DEFAULT_INPUT = Path("../luongvd/attack_requests.csv")
DEFAULT_OUTPUT = Path("data/raw/positive/luongvd_attack_requests.csv")

FIELDS = (
    "id",
    "label",
    "source",
    "source_url",
    "method",
    "url",
    "path",
    "query_string",
    "headers",
    "body",
    "raw_request",
    "notes",
)


def import_rows(input_path: Path, output_path: Path) -> int:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    count = 0

    with input_path.open(encoding="utf-8", errors="replace", newline="") as src:
        reader = csv.DictReader(src)
        with output_path.open("w", encoding="utf-8", newline="") as dst:
            writer = csv.DictWriter(dst, fieldnames=FIELDS, quoting=csv.QUOTE_ALL)
            writer.writeheader()

            for row in reader:
                count += 1
                writer.writerow(
                    {
                        "id": f"pos_luongvd_{count:06d}",
                        "label": "1",
                        "source": row.get("source", "luongvd"),
                        "source_url": row.get("evidence_link", ""),
                        "method": row.get("method", ""),
                        "url": row.get("url", ""),
                        "path": row.get("path", ""),
                        "query_string": row.get("query_string", ""),
                        "headers": row.get("headers", ""),
                        "body": row.get("body", ""),
                        "raw_request": row.get("raw_request", ""),
                        "notes": row.get("attack_type", ""),
                    }
                )

    return count


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Import positive attack request rows from ../luongvd."
    )
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()
    count = import_rows(args.input, args.output)
    print(f"wrote {count} rows -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
