"""Extract manual features from the deduplicated request dataset."""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.feature_extractor import FEATURE_NAMES, extract_features


DEFAULT_INPUT = Path("data/processed/requests_dataset_dedup.csv")
DEFAULT_OUTPUT = Path("data/processed/features.csv")


def run(input_path: Path, output_path: Path) -> int:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fields = ("id", "label", "source", "notes", *FEATURE_NAMES)
    count = 0
    with input_path.open(encoding="utf-8", errors="replace", newline="") as src:
        reader = csv.DictReader(src)
        with output_path.open("w", encoding="utf-8", newline="") as dst:
            writer = csv.DictWriter(dst, fieldnames=fields, quoting=csv.QUOTE_ALL)
            writer.writeheader()
            for row in reader:
                features = extract_features(row)
                writer.writerow(
                    {
                        "id": row.get("id", ""),
                        "label": row.get("label", ""),
                        "source": row.get("source", ""),
                        "notes": row.get("notes", ""),
                        **features,
                    }
                )
                count += 1
    return count


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Extract manual ML features.")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()
    count = run(args.input, args.output)
    print(f"wrote {count} rows -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
