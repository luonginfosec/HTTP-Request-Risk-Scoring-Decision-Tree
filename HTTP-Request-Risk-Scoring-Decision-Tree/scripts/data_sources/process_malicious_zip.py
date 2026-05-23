"""Convert malicious request JSON zip into the project positive CSV schema."""

from __future__ import annotations

import argparse
import csv
import json
import zipfile
from pathlib import Path
from urllib.parse import urlsplit


DEFAULT_INPUT = Path("data/raw/positive/malicious.zip")
DEFAULT_OUTPUT = Path("data/raw/positive/malicious_requests.csv")

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

DEFAULT_PER_TYPE_LIMIT = 1000
HOST = "malicious.local"


def attack_type_from_name(name: str) -> str:
    return Path(name).stem.lower()


def raw_request(method: str, target: str, headers: dict[str, str], body: str) -> str:
    lines = [f"{method} {target} HTTP/1.1"]
    lines.extend(f"{key}: {value}" for key, value in headers.items())
    if body:
        return "\n".join(lines) + "\n\n" + body
    return "\n".join(lines)


def iter_rows(zip_path: Path, *, per_type_limit: int):
    emitted = 0
    with zipfile.ZipFile(zip_path) as archive:
        for name in sorted(n for n in archive.namelist() if n.endswith(".json")):
            attack_type = attack_type_from_name(name)
            with archive.open(name) as fh:
                records = json.load(fh)
            if not isinstance(records, list):
                continue

            seen: set[tuple[str, str, str]] = set()
            count_for_type = 0
            for record in records:
                if count_for_type >= per_type_limit:
                    break
                if not isinstance(record, dict):
                    continue

                method = str(record.get("method", "")).upper().strip()
                target = str(record.get("url", "")).strip()
                headers = record.get("headers") or {}
                body = str(record.get("data") or "")
                if not method or not target or not isinstance(headers, dict):
                    continue

                headers = {str(k): str(v) for k, v in headers.items()}
                headers.setdefault("Host", HOST)
                key = (method, target, body)
                if key in seen:
                    continue
                seen.add(key)

                absolute_url = target
                if target.startswith("/"):
                    absolute_url = f"https://{HOST}{target}"
                parts = urlsplit(absolute_url)
                emitted += 1
                count_for_type += 1

                yield {
                    "id": f"pos_malicious_{emitted:06d}",
                    "label": "1",
                    "source": "openappsec_malicious",
                    "source_url": name,
                    "method": method,
                    "url": absolute_url,
                    "path": parts.path or "/",
                    "query_string": parts.query,
                    "headers": json.dumps(headers, ensure_ascii=False),
                    "body": body,
                    "raw_request": raw_request(method, target, headers, body),
                    "notes": attack_type,
                }


def write_csv(rows, output_path: Path) -> int:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with output_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
            count += 1
    return count


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Process malicious.zip into positive request CSV.")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--per-type-limit", type=int, default=DEFAULT_PER_TYPE_LIMIT)
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()
    count = write_csv(
        iter_rows(args.input, per_type_limit=args.per_type_limit),
        args.output,
    )
    print(f"wrote {count} rows -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
