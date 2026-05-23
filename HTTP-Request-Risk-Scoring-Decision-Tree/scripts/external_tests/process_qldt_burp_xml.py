"""Convert QLDT Burp Suite XML export into normal request CSV."""

from __future__ import annotations

import argparse
import base64
import csv
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlsplit


DEFAULT_INPUT = Path("data/raw/qldt-ptit.xml")
DEFAULT_OUTPUT = Path("data/raw/normal/qldt_ptit_normal_requests.csv")

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

SENSITIVE_HEADER_NAMES = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-csrf-token",
    "x-xsrf-token",
}

SENSITIVE_NAME_PARTS = (
    "authorization",
    "cookie",
    "csrf",
    "password",
    "secret",
    "token",
    "xsrf",
)


def decode_request_node(node: ET.Element | None) -> str:
    if node is None:
        return ""
    text = node.text or ""
    if node.attrib.get("base64", "").lower() == "true":
        return base64.b64decode(text).decode("utf-8", errors="replace")
    return text


def parse_raw_request(raw: str) -> tuple[str, str, str, dict[str, str], str]:
    header_part, body = split_headers_body(raw)
    lines = header_part.splitlines()
    if not lines:
        return "", "", "HTTP/1.1", {}, body

    request_line = lines[0].strip()
    pieces = request_line.split()
    method = pieces[0].upper() if pieces else ""
    target = pieces[1] if len(pieces) > 1 else ""
    version = pieces[2] if len(pieces) > 2 else "HTTP/1.1"
    headers = parse_headers(lines[1:])
    return method, target, version, headers, body


def split_headers_body(raw: str) -> tuple[str, str]:
    if "\r\n\r\n" in raw:
        return raw.split("\r\n\r\n", 1)
    if "\n\n" in raw:
        return raw.split("\n\n", 1)
    return raw, ""


def parse_headers(lines: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in lines:
        if not line.strip() or ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip()] = redact_header(name.strip(), value.strip())
    return headers


def redact_header(name: str, value: str) -> str:
    name_l = name.lower()
    if name_l in SENSITIVE_HEADER_NAMES or any(part in name_l for part in SENSITIVE_NAME_PARTS):
        return "PRESENT"
    return value


def redact_body(body: str) -> str:
    stripped = body.strip()
    if not stripped:
        return ""
    if stripped.startswith(("{", "[")):
        try:
            return json.dumps(redact_json(json.loads(stripped)), ensure_ascii=False, separators=(",", ":"))
        except json.JSONDecodeError:
            pass
    value = re.sub(
        r"(?i)([^=&\s]*(?:authorization|cookie|csrf|password|secret|token|xsrf)[^=&\s]*=)[^&\s]+",
        r"\1PRESENT",
        body,
    )
    value = re.sub(
        r"(?i)((?:authorization|cookie|csrf|password|secret|token|xsrf)[^:]{0,40}:\s*)[^\s,&}\]]+",
        r"\1PRESENT",
        value,
    )
    return value


def redact_json(value: object) -> object:
    if isinstance(value, dict):
        return {
            key: ("PRESENT" if is_sensitive_name(str(key)) else redact_json(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_json(item) for item in value]
    return value


def is_sensitive_name(name: str) -> bool:
    name_l = name.lower()
    return any(part in name_l for part in SENSITIVE_NAME_PARTS)


def header_value(headers: dict[str, str], name: str) -> str:
    name_l = name.lower()
    for key, value in headers.items():
        if key.lower() == name_l:
            return value
    return ""


def absolute_url(item_url: str, target: str, headers: dict[str, str]) -> str:
    if item_url:
        return item_url
    target_parts = urlsplit(target)
    if target_parts.scheme and target_parts.netloc:
        return target
    host = header_value(headers, "host") or "qldt.ptit.edu.vn"
    path = target if target.startswith("/") else f"/{target}"
    return f"https://{host}{path}"


def reconstruct_raw_request(
    method: str,
    url: str,
    version: str,
    headers: dict[str, str],
    body: str,
) -> str:
    parts = urlsplit(url)
    target = parts.path or "/"
    if parts.query:
        target = f"{target}?{parts.query}"
    lines = [f"{method} {target} {version}", *(f"{key}: {value}" for key, value in headers.items())]
    if body:
        return "\n".join(lines) + "\n\n" + body
    return "\n".join(lines)


def item_to_row(item: ET.Element, index: int) -> dict[str, str] | None:
    raw_request = decode_request_node(item.find("request"))
    method, target, version, headers, body = parse_raw_request(raw_request)
    method = method or (item.findtext("method") or "").upper()
    if not method or not target:
        return None

    body = redact_body(body)
    url = absolute_url(item.findtext("url") or "", target, headers)
    parts = urlsplit(url)
    safe_raw_request = reconstruct_raw_request(method, url, version, headers, body)
    return {
        "id": f"norm_qldt_ptit_{index:06d}",
        "label": "0",
        "source": "qldt_ptit_burp",
        "source_url": item.findtext("url") or "",
        "method": method,
        "url": url,
        "path": parts.path or "/",
        "query_string": parts.query,
        "headers": json.dumps(headers, ensure_ascii=False),
        "body": body,
        "raw_request": safe_raw_request,
        "notes": "qldt_ptit_normal",
    }


def read_rows(input_path: Path, limit: int) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for _, item in ET.iterparse(input_path, events=("end",)):
        if item.tag != "item":
            continue
        row = item_to_row(item, len(rows) + 1)
        item.clear()
        if row is None:
            continue
        key = (row["method"], row["url"], row["body"])
        if key in seen:
            continue
        seen.add(key)
        rows.append(row)
        if limit > 0 and len(rows) >= limit:
            break
    return rows


def write_rows(rows: list[dict[str, str]], output_path: Path) -> int:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Process QLDT Burp XML into project normal request CSV.")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--limit", type=int, default=5000)
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()
    rows = read_rows(args.input, args.limit)
    count = write_rows(rows, args.output)
    print(f"wrote {count} normal rows -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
