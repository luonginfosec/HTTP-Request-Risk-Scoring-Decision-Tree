"""Convert CSIC 2010 HTTP dataset CSV into the project request schema."""

from __future__ import annotations

import argparse
import csv
import json
import random
import re
from pathlib import Path
from urllib.parse import unquote_plus, urlsplit


DEFAULT_INPUT = Path("data/csic_database.csv")
DEFAULT_NORMAL_OUTPUT = Path("data/raw/normal/csic_normal_requests.csv")
DEFAULT_ATTACK_OUTPUT = Path("data/raw/positive/csic_attack_requests.csv")
SOURCE_NAME = "csic_2010"
DEFAULT_NORMAL_LIMIT = 3000
DEFAULT_ATTACK_LIMIT = 3000
DEFAULT_SEED = 42

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

HEADER_MAP = {
    "User-Agent": "User-Agent",
    "Pragma": "Pragma",
    "Cache-Control": "Cache-Control",
    "Accept": "Accept",
    "Accept-encoding": "Accept-Encoding",
    "Accept-charset": "Accept-Charset",
    "language": "Accept-Language",
    "host": "Host",
    "cookie": "Cookie",
    "content-type": "Content-Type",
    "connection": "Connection",
    "lenght": "Content-Length",
}

SQLI_RE = re.compile(
    r"(union\s+select|drop\s+table|insert\s+into|delete\s+from|select\s+.+\s+from|"
    r"\bor\s+\d+\s*=\s*\d+\b|\band\s+\d+\s*=\s*\d+\b)",
    re.IGNORECASE,
)
XSS_RE = re.compile(r"(<script|javascript:|onerror\s*=|onload\s*=|alert\s*\()", re.IGNORECASE)
TRAVERSAL_RE = re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|etc/passwd)", re.IGNORECASE)
CRLF_RE = re.compile(r"(%0d%0a|%0a%0d|\r\n|\n)", re.IGNORECASE)


def clean_url(raw_url: str, host: str) -> str:
    url = str(raw_url or "").strip()
    url = re.sub(r"\s+HTTP/\d(?:\.\d)?\s*$", "", url, flags=re.IGNORECASE)
    if url.startswith("/"):
        return f"http://{host}{url}" if host else f"http://localhost:8080{url}"
    return url


def clean_header_value(header_name: str, value: str) -> str:
    value = str(value or "").strip()
    prefix = f"{header_name}:"
    if value.lower().startswith(prefix.lower()):
        return value[len(prefix):].strip()
    return value


def build_headers(row: dict[str, str], *, redact_cookie: bool) -> dict[str, str]:
    headers: dict[str, str] = {}
    body = row.get("content", "") or ""

    for source_name, header_name in HEADER_MAP.items():
        value = clean_header_value(header_name, row.get(source_name, ""))
        if not value:
            continue
        if header_name == "Cookie" and redact_cookie:
            headers[header_name] = "PRESENT"
        else:
            headers[header_name] = value

    if body and "Content-Length" not in headers:
        headers["Content-Length"] = str(len(body.encode("utf-8", errors="replace")))
    return headers


def request_target(url: str) -> str:
    parts = urlsplit(url)
    target = parts.path or "/"
    if parts.query:
        target += f"?{parts.query}"
    return target


def make_raw_request(method: str, url: str, headers: dict[str, str], body: str) -> str:
    lines = [f"{method} {request_target(url)} HTTP/1.1"]
    lines.extend(f"{key}: {value}" for key, value in headers.items())
    if body:
        return "\n".join(lines) + "\n\n" + body
    return "\n".join(lines)


def infer_notes(label: str, url: str, body: str) -> str:
    if label == "0":
        return "csic_normal"

    raw_text = f"{url} {body}"
    decoded_text = unquote_plus(raw_text)
    text = f"{raw_text} {decoded_text}"
    if SQLI_RE.search(text):
        return "csic_sqli"
    if XSS_RE.search(text):
        return "csic_xss"
    if TRAVERSAL_RE.search(text):
        return "csic_traversal"
    if CRLF_RE.search(text):
        return "csic_crlf"
    if len(text) > 3000:
        return "csic_long_payload"
    return "csic_anomalous"


def convert_row(row: dict[str, str], *, row_id: str, redact_cookie: bool) -> dict[str, str] | None:
    label = str(row.get("classification", "")).strip()
    if label not in {"0", "1"}:
        return None

    method = str(row.get("Method", "") or "").upper().strip()
    host = str(row.get("host", "") or "").strip()
    url = clean_url(row.get("URL", ""), host)
    body = str(row.get("content", "") or "")
    if not method or not url:
        return None

    headers = build_headers(row, redact_cookie=redact_cookie)
    parts = urlsplit(url)

    return {
        "id": row_id,
        "label": label,
        "source": SOURCE_NAME,
        "source_url": "data/csic_database.csv",
        "method": method,
        "url": url,
        "path": parts.path or "/",
        "query_string": parts.query,
        "headers": json.dumps(headers, ensure_ascii=False),
        "body": body,
        "raw_request": make_raw_request(method, url, headers, body),
        "notes": infer_notes(label, url, body),
    }


def sample_rows(rows: list[dict[str, str]], limit: int | None, *, seed: int) -> list[dict[str, str]]:
    if limit is None or len(rows) <= limit:
        return rows
    rng = random.Random(seed)
    return rng.sample(rows, limit)


def renumber_rows(rows: list[dict[str, str]], prefix: str) -> None:
    for index, row in enumerate(rows, start=1):
        row["id"] = f"{prefix}_{index:06d}"


def write_csv(rows: list[dict[str, str]], output_path: Path) -> int:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def write_outputs(
    input_path: Path,
    normal_output: Path,
    attack_output: Path,
    *,
    redact_cookie: bool,
    normal_limit: int | None,
    attack_limit: int | None,
    seed: int,
) -> tuple[int, int]:
    normal_rows: list[dict[str, str]] = []
    attack_rows: list[dict[str, str]] = []
    normal_seen = 0
    attack_seen = 0

    with input_path.open(encoding="utf-8", errors="replace", newline="") as src:
        reader = csv.DictReader(src)
        for source_row in reader:
            label = str(source_row.get("classification", "")).strip()
            if label == "0":
                normal_seen += 1
                converted = convert_row(
                    source_row,
                    row_id=f"norm_csic_{normal_seen:06d}",
                    redact_cookie=redact_cookie,
                )
                if converted is not None:
                    normal_rows.append(converted)
            elif label == "1":
                attack_seen += 1
                converted = convert_row(
                    source_row,
                    row_id=f"pos_csic_{attack_seen:06d}",
                    redact_cookie=redact_cookie,
                )
                if converted is not None:
                    attack_rows.append(converted)

    normal_rows = sample_rows(normal_rows, normal_limit, seed=seed)
    attack_rows = sample_rows(attack_rows, attack_limit, seed=seed + 1)
    renumber_rows(normal_rows, "norm_csic")
    renumber_rows(attack_rows, "pos_csic")

    normal_count = write_csv(normal_rows, normal_output)
    attack_count = write_csv(attack_rows, attack_output)
    return normal_count, attack_count


def optional_limit(value: str) -> int | None:
    parsed = int(value)
    return None if parsed <= 0 else parsed


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Convert CSIC 2010 CSV into project request CSVs.")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--normal-output", type=Path, default=DEFAULT_NORMAL_OUTPUT)
    parser.add_argument("--attack-output", type=Path, default=DEFAULT_ATTACK_OUTPUT)
    parser.add_argument("--normal-limit", type=optional_limit, default=DEFAULT_NORMAL_LIMIT, help="0 means no limit.")
    parser.add_argument("--attack-limit", type=optional_limit, default=DEFAULT_ATTACK_LIMIT, help="0 means no limit.")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument(
        "--keep-cookie-values",
        action="store_true",
        help="Keep CSIC cookie values instead of replacing Cookie with PRESENT.",
    )
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()
    normal_count, attack_count = write_outputs(
        args.input,
        args.normal_output,
        args.attack_output,
        redact_cookie=not args.keep_cookie_values,
        normal_limit=args.normal_limit,
        attack_limit=args.attack_limit,
        seed=args.seed,
    )
    print(f"normal rows: {normal_count} -> {args.normal_output}")
    print(f"attack rows: {attack_count} -> {args.attack_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
