"""
doc file zip
loc static: js, css, image, font, video
loc request chua payload
convert schema to fixed type
label = 0
python3 scripts/data_sources/process_normal_legitimate.py --limit 3000
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import zipfile
from pathlib import Path
from urllib.parse import urlsplit


DEFAULT_INPUT = Path("data/raw/normal/legitimate.zip")
DEFAULT_OUTPUT = Path("data/raw/normal/legitimate_normal_requests.csv")

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

STATIC_EXTENSIONS = (
    ".css", ".js", ".mjs", ".map",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp4", ".webm", ".mp3", ".wav", ".avi",
)

ATTACK_LIKE_RE = re.compile(
    r"(union\s+select|<script\b|javascript:alert|"
    r"\bor\s+1\s*=\s*1\b|sleep\s*\(|/etc/passwd|"
    r"169\.254\.169\.254|(?:\.\./){2,})",
    re.IGNORECASE,
)


SENSITIVE_HEADER_NAMES = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-csrf-token",
    "x-xsrf-token",
}


def _redact_headers(headers: dict) -> dict:
    redacted = {}
    for key, value in headers.items():
        key_s = str(key)
        key_l = key_s.lower()
        if key_l in SENSITIVE_HEADER_NAMES or "token" in key_l or "secret" in key_l:
            redacted[key_s] = "PRESENT"
        else:
            redacted[key_s] = str(value)
    return redacted


def _header_value(headers: dict, name: str) -> str:
    name_l = name.lower()
    for key, value in headers.items():
        if str(key).lower() == name_l:
            return str(value)
    return ""


def _path_and_query(url: str) -> tuple[str, str]:
    parts = urlsplit(url)
    return parts.path or "/", parts.query


def _is_static(path: str) -> bool:
    path_l = path.lower()
    return any(path_l.endswith(ext) for ext in STATIC_EXTENSIONS)


def _is_interesting(method: str, url: str, body: str) -> bool:
    path, query = _path_and_query(url)
    path_l = path.lower()
    return (
        method != "GET"
        or bool(query)
        or bool(body)
        or "/api/" in path_l
        or path_l.startswith("/api")
        or "/rest/" in path_l
    )


def _has_attack_payload(row: dict, headers: dict) -> bool:
    text = " ".join(
        [
            str(row.get("method", "")),
            str(row.get("url", "")),
            str(row.get("data", "")),
            json.dumps(headers, ensure_ascii=False),
        ]
    )
    return bool(ATTACK_LIKE_RE.search(text))


def _raw_request(method: str, url: str, headers: dict, body: str) -> str:
    lines = [f"{method} {url} HTTP/1.1"]
    for key, value in headers.items():
        lines.append(f"{key}: {value}")
    if body:
        return "\n".join(lines) + "\n\n" + body
    return "\n".join(lines)


def iter_normal_rows(
    zip_path: Path,
    *,
    limit: int,
    per_host_limit: int,
    max_body_chars: int,
    max_headers_chars: int,
):
    seen: set[tuple[str, str, str]] = set()
    host_counts: dict[str, int] = {}
    emitted = 0

    with zipfile.ZipFile(zip_path) as archive:
        names = sorted(n for n in archive.namelist() if n.endswith(".json"))
        for name in names:
            with archive.open(name) as fh:
                try:
                    records = json.load(fh)
                except json.JSONDecodeError:
                    continue
            if not isinstance(records, list):
                continue

            for record in records:
                if emitted >= limit:
                    return
                if not isinstance(record, dict):
                    continue

                method = str(record.get("method", "")).upper().strip()
                url = str(record.get("url", "")).strip()
                headers = record.get("headers") or {}
                body = str(record.get("data") or "")

                if not method or not url or not isinstance(headers, dict):
                    continue
                if len(body) > max_body_chars:
                    continue
                headers = _redact_headers(headers)
                headers_json = json.dumps(headers, ensure_ascii=False)
                if len(headers_json) > max_headers_chars:
                    continue
                host = _header_value(headers, "host")
                if not host:
                    continue

                path, query = _path_and_query(url)
                if _is_static(path):
                    continue
                # Keep clean non-static GET pages too. They are important
                # negatives so the model learns that plain URLs like GET /
                # are normal, not automatically risky.
                if _has_attack_payload(record, headers):
                    continue
                if host_counts.get(host, 0) >= per_host_limit:
                    continue

                key = (method, host + url, body)
                if key in seen:
                    continue
                seen.add(key)
                host_counts[host] = host_counts.get(host, 0) + 1
                emitted += 1

                raw = _raw_request(method, url, headers, body)
                yield {
                    "id": f"norm_legitimate_{emitted:06d}",
                    "label": "0",
                    "source": "openappsec_legitimate",
                    "source_url": name,
                    "method": method,
                    "url": f"https://{host}{url}" if url.startswith("/") else url,
                    "path": path,
                    "query_string": query,
                    "headers": headers_json,
                    "body": body,
                    "raw_request": raw,
                    "notes": "normal",
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
    parser = argparse.ArgumentParser(
        description="Process legitimate browsing JSON zip into normal CSV rows."
    )
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--limit", type=int, default=3000)
    parser.add_argument("--per-host-limit", type=int, default=50)
    parser.add_argument("--max-body-chars", type=int, default=20_000)
    parser.add_argument("--max-headers-chars", type=int, default=20_000)
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()
    rows = iter_normal_rows(
        args.input,
        limit=args.limit,
        per_host_limit=args.per_host_limit,
        max_body_chars=args.max_body_chars,
        max_headers_chars=args.max_headers_chars,
    )
    count = write_csv(rows, args.output)
    print(f"wrote {count} rows -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
