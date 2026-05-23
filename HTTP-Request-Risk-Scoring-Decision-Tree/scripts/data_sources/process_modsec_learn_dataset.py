"""Convert ModSec-Learn query-string dataset into project request CSVs."""

from __future__ import annotations

import argparse
import csv
import json
import random
from pathlib import Path
from urllib.parse import urlsplit


DEFAULT_INPUT_DIR = Path("data/external/modsec-learn-dataset")
DEFAULT_NORMAL_OUTPUT = Path("data/raw/normal/modsec_learn_legitimate_requests.csv")
DEFAULT_POSITIVE_OUTPUT = Path("data/raw/positive/modsec_learn_sqli_requests.csv")

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

NORMAL_HOST = "modsec-learn-normal.local"
SQLI_HOST = "modsec-learn-sqli.local"
SENSITIVE_QUERY_NAMES = {
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "authorization",
    "client_secret",
    "csrf",
    "key",
    "password",
    "secret",
    "sig",
    "signature",
    "token",
}


def load_json_strings(path: Path) -> list[str]:
    with path.open(encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    if not isinstance(data, list):
        return []
    return [str(item).strip() for item in data if str(item).strip()]


def read_normal_queries(input_dir: Path) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for path in sorted((input_dir / "legitimate" / "openappsec").glob("legitimate_*.json")):
        rows.extend((str(path.relative_to(input_dir)), query) for query in load_json_strings(path))
    return rows


def read_sqli_queries(input_dir: Path) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for path in sorted((input_dir / "malicious").glob("*/sqli_parsed.json")):
        rows.extend((str(path.relative_to(input_dir)), query) for query in load_json_strings(path))
    return rows


def sample_rows(rows: list[tuple[str, str]], limit: int, seed: int) -> list[tuple[str, str]]:
    unique_rows = sorted(set(rows))
    if limit <= 0 or len(unique_rows) <= limit:
        return unique_rows
    rng = random.Random(seed)
    return sorted(rng.sample(unique_rows, limit))


def redact_sensitive_query_values(query: str) -> str:
    parts = []
    for part in query.split("&"):
        name, separator, value = part.partition("=")
        name_l = name.lower()
        if separator and (name_l in SENSITIVE_QUERY_NAMES or "token" in name_l or "secret" in name_l):
            parts.append(f"{name}=PRESENT")
        else:
            parts.append(part)
    return "&".join(parts)


def make_request_row(
    *,
    row_id: str,
    label: str,
    source: str,
    source_url: str,
    host: str,
    query: str,
    notes: str,
) -> dict[str, str]:
    method = "GET"
    target = f"/?{query}" if query else "/"
    url = f"https://{host}{target}"
    parts = urlsplit(url)
    headers = {
        "Host": host,
        "User-Agent": "Mozilla/5.0",
        "Accept": "*/*",
    }
    raw_request = "\n".join(
        [
            f"{method} {target} HTTP/1.1",
            *(f"{key}: {value}" for key, value in headers.items()),
        ]
    )
    return {
        "id": row_id,
        "label": label,
        "source": source,
        "source_url": source_url,
        "method": method,
        "url": url,
        "path": parts.path or "/",
        "query_string": parts.query,
        "headers": json.dumps(headers, ensure_ascii=False),
        "body": "",
        "raw_request": raw_request,
        "notes": notes,
    }


def write_csv(rows: list[dict[str, str]], output_path: Path) -> int:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def build_normal_rows(input_dir: Path, limit: int, seed: int) -> list[dict[str, str]]:
    sampled = sample_rows(read_normal_queries(input_dir), limit, seed)
    return [
        make_request_row(
            row_id=f"norm_modsec_learn_{index:06d}",
            label="0",
            source="modsec_learn_legitimate",
            source_url=source_url,
            host=NORMAL_HOST,
            query=redact_sensitive_query_values(query),
            notes="modsec_learn_legitimate",
        )
        for index, (source_url, query) in enumerate(sampled, start=1)
    ]


def build_positive_rows(input_dir: Path, limit: int, seed: int) -> list[dict[str, str]]:
    sampled = sample_rows(read_sqli_queries(input_dir), limit, seed)
    return [
        make_request_row(
            row_id=f"pos_modsec_learn_sqli_{index:06d}",
            label="1",
            source="modsec_learn_sqli",
            source_url=source_url,
            host=SQLI_HOST,
            query=query,
            notes=f"modsec_learn_sqli:{Path(source_url).parts[1]}",
        )
        for index, (source_url, query) in enumerate(sampled, start=1)
    ]


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Process ModSec-Learn dataset into project CSV files.")
    parser.add_argument("--input-dir", type=Path, default=DEFAULT_INPUT_DIR)
    parser.add_argument("--normal-output", type=Path, default=DEFAULT_NORMAL_OUTPUT)
    parser.add_argument("--positive-output", type=Path, default=DEFAULT_POSITIVE_OUTPUT)
    parser.add_argument("--normal-limit", type=int, default=3000)
    parser.add_argument("--positive-limit", type=int, default=3000)
    parser.add_argument("--seed", type=int, default=42)
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()
    normal_rows = build_normal_rows(args.input_dir, args.normal_limit, args.seed)
    positive_rows = build_positive_rows(args.input_dir, args.positive_limit, args.seed)
    normal_count = write_csv(normal_rows, args.normal_output)
    positive_count = write_csv(positive_rows, args.positive_output)
    print(f"wrote {normal_count} normal rows -> {args.normal_output}")
    print(f"wrote {positive_count} positive rows -> {args.positive_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
