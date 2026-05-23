"""Merge positive and normal request CSVs into one training dataset."""

from __future__ import annotations

import argparse
import csv
import random
from pathlib import Path


DEFAULT_POSITIVE = Path("data/raw/positive/luongvd_attack_requests.csv")
DEFAULT_MALICIOUS_POSITIVE = Path("data/raw/positive/malicious_requests.csv")
DEFAULT_CSIC_POSITIVE = Path("data/raw/positive/csic_attack_requests.csv")
DEFAULT_MODSEC_LEARN_POSITIVE = Path("data/raw/positive/modsec_learn_sqli_requests.csv")
DEFAULT_OWASP_POSITIVE = Path("data/raw/positive/owasp_modsec_requests.csv")
DEFAULT_NORMAL = Path("data/raw/normal/legitimate_normal_requests.csv")
DEFAULT_CSIC_NORMAL = Path("data/raw/normal/csic_normal_requests.csv")
DEFAULT_MODSEC_LEARN_NORMAL = Path("data/raw/normal/modsec_learn_legitimate_requests.csv")
DEFAULT_QLDT_NORMAL = None
DEFAULT_OUTPUT = Path("data/processed/requests_dataset.csv")

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


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        missing = [field for field in FIELDS if field not in (reader.fieldnames or [])]
        if missing:
            raise ValueError(f"{path} missing fields: {missing}")
        return [{field: row.get(field, "") for field in FIELDS} for row in reader]


def merge_rows(
    positive_rows: list[dict[str, str]],
    normal_rows: list[dict[str, str]],
    *,
    balance: bool,
    seed: int,
    normal_ratio: float,
) -> list[dict[str, str]]:
    rng = random.Random(seed)

    positives = [row for row in positive_rows if row["label"] == "1"]
    normals = [row for row in normal_rows if row["label"] == "0"]

    if balance:
        normal_count = min(len(normals), int(len(positives) * normal_ratio / (1 - normal_ratio)))
        positive_count = min(len(positives), int(normal_count * (1 - normal_ratio) / normal_ratio))
        positives = rng.sample(positives, positive_count)
        normals = rng.sample(normals, normal_count)

    rows = positives + normals
    rng.shuffle(rows)
    return rows


def write_rows(rows: list[dict[str, str]], output_path: Path) -> int:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Merge positive and normal request datasets."
    )
    parser.add_argument("--positive", type=Path, default=DEFAULT_POSITIVE)
    parser.add_argument("--malicious-positive", type=Path, default=DEFAULT_MALICIOUS_POSITIVE)
    parser.add_argument("--csic-positive", type=Path, default=DEFAULT_CSIC_POSITIVE)
    parser.add_argument("--modsec-learn-positive", type=Path, default=DEFAULT_MODSEC_LEARN_POSITIVE)
    parser.add_argument("--owasp-positive", type=Path, default=DEFAULT_OWASP_POSITIVE)
    parser.add_argument("--normal", type=Path, default=DEFAULT_NORMAL)
    parser.add_argument("--csic-normal", type=Path, default=DEFAULT_CSIC_NORMAL)
    parser.add_argument("--modsec-learn-normal", type=Path, default=DEFAULT_MODSEC_LEARN_NORMAL)
    parser.add_argument(
        "--qldt-normal",
        type=Path,
        default=DEFAULT_QLDT_NORMAL,
        help="Optional external QLDT normal log. Omitted from training by default.",
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--normal-ratio", type=float, default=0.7)
    parser.add_argument(
        "--no-balance",
        action="store_true",
        help="Keep all rows instead of downsampling to the configured normal/attack ratio.",
    )
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()
    positive_rows = read_rows(args.positive)
    if args.malicious_positive.exists():
        positive_rows.extend(read_rows(args.malicious_positive))
    if args.csic_positive.exists():
        positive_rows.extend(read_rows(args.csic_positive))
    if args.modsec_learn_positive.exists():
        positive_rows.extend(read_rows(args.modsec_learn_positive))
    if args.owasp_positive.exists():
        positive_rows.extend(read_rows(args.owasp_positive))
    normal_rows = read_rows(args.normal)
    if args.csic_normal.exists():
        normal_rows.extend(read_rows(args.csic_normal))
    if args.modsec_learn_normal.exists():
        normal_rows.extend(read_rows(args.modsec_learn_normal))
    if args.qldt_normal and args.qldt_normal.exists():
        normal_rows.extend(read_rows(args.qldt_normal))
    rows = merge_rows(
        positive_rows,
        normal_rows,
        balance=not args.no_balance,
        seed=args.seed,
        normal_ratio=args.normal_ratio,
    )
    count = write_rows(rows, args.output)
    print(f"positive input: {sum(1 for r in positive_rows if r['label'] == '1')}")
    print(f"normal input:   {sum(1 for r in normal_rows if r['label'] == '0')}")
    print(f"wrote {count} rows -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
