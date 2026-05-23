"""Convert OWASP ModSecurity audit logs into positive request CSV."""

from __future__ import annotations

import argparse
import csv
import json
import random
import re
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlsplit


DEFAULT_INPUT_DIR = Path("data/raw/owasp")
DEFAULT_OUTPUT = Path("data/raw/positive/owasp_modsec_requests.csv")

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

METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}
SECTION_RE = re.compile(r"(?m)^--[0-9A-Za-z]+-([A-Z])--\s*$")
ID_RE = re.compile(r'\[id "([^"]+)"\]')
MSG_RE = re.compile(r'\[msg "([^"]+)"\]')
TAG_RE = re.compile(r'\[tag "([^"]+)"\]')

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


def split_transactions(text: str) -> list[str]:
    return re.split(r"(?m)^--[0-9A-Za-z]+-Z--\s*$", text)


def parse_sections(transaction: str) -> dict[str, str]:
    matches = list(SECTION_RE.finditer(transaction))
    sections: dict[str, str] = {}
    for index, match in enumerate(matches):
        name = match.group(1)
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(transaction)
        sections[name] = transaction[start:end].strip("\r\n")
    return sections


def parse_request(section_b: str) -> tuple[str, str, str, dict[str, str], str]:
    header_part, body = split_headers_body(section_b)
    lines = header_part.splitlines()
    if not lines:
        return "", "", "HTTP/1.1", {}, body
    pieces = lines[0].strip().split()
    method = pieces[0].upper() if pieces else ""
    target = pieces[1] if len(pieces) > 1 else ""
    version = pieces[2] if len(pieces) > 2 else "HTTP/1.1"
    headers = parse_headers(lines[1:])
    return method, target, version, headers, redact_body(body)


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
    value = body or ""
    value = re.sub(
        r"(?i)([^=&\s]*(?:authorization|cookie|csrf|password|secret|token|xsrf)[^=&\s]*=)[^&\s]+",
        r"\1PRESENT",
        value,
    )
    value = re.sub(
        r"(?i)((?:authorization|cookie|csrf|password|secret|token|xsrf)[^:]{0,40}:\s*)[^\s,&}\]]+",
        r"\1PRESENT",
        value,
    )
    return value


def header_value(headers: dict[str, str], name: str) -> str:
    name_l = name.lower()
    for key, value in headers.items():
        if key.lower() == name_l:
            return value
    return ""


def scheme_from_a_section(section_a: str) -> str:
    first_line = next((line for line in section_a.splitlines() if line.strip()), "")
    parts = first_line.split()
    server_port = parts[-1] if parts else ""
    return "https" if server_port in {"443", "8443"} else "http"


def transaction_id(section_a: str) -> str:
    first_line = next((line for line in section_a.splitlines() if line.strip()), "")
    parts = first_line.split()
    return parts[1] if len(parts) > 1 else ""


def absolute_url(target: str, headers: dict[str, str], section_a: str) -> str:
    parts = urlsplit(target)
    if parts.scheme and parts.netloc:
        return target
    host = header_value(headers, "host") or "owasp-modsec.local"
    path = target if target.startswith("/") else f"/{target}"
    return f"{scheme_from_a_section(section_a)}://{host}{path}"


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


def classify_attack(section_h: str) -> tuple[str, str] | None:
    rule_ids = ID_RE.findall(section_h)
    messages = MSG_RE.findall(section_h)
    tags = TAG_RE.findall(section_h)
    text = " ".join([section_h, *rule_ids, *messages, *tags]).lower()

    categories = [
        ("owasp_sqli", ("attack-sqli", "sql_injection", "libinjection", "sql injection", "sqli"), ("942",)),
        ("owasp_xss", ("attack-xss", "web_attack/xss", "xss", "script"), ("941", "943")),
        ("owasp_rce", ("attack-rce", "command_injection", "remote command", "command execution"), ("932",)),
        ("owasp_php_injection", ("attack-injection-php", "php_injection", "php injection"), ("933",)),
        (
            "owasp_lfi_rfi",
            ("attack-lfi", "attack-rfi", "file_injection", "dir_traversal", "restricted file access", "path traversal", "os file access"),
            ("930", "931"),
        ),
        ("owasp_java_attack", ("log4j", "jndi", "java"), ("944",)),
    ]

    for category, words, prefixes in categories:
        if any(word in text for word in words) or any(rule_id.startswith(prefixes) for rule_id in rule_ids):
            rule_id = next((value for value in rule_ids if value), "")
            return category, rule_id
    return None


def transaction_to_row(sections: dict[str, str], source_url: str) -> dict[str, str] | None:
    if "B" not in sections or "H" not in sections:
        return None
    classified = classify_attack(sections["H"])
    if classified is None:
        return None

    method, target, version, headers, body = parse_request(sections["B"])
    if method not in METHODS or not target:
        return None

    note, rule_id = classified
    url = absolute_url(target, headers, sections.get("A", ""))
    parts = urlsplit(url)
    safe_raw_request = reconstruct_raw_request(method, url, version, headers, body)
    return {
        "id": "",
        "label": "1",
        "source": "owasp_modsecurity",
        "source_url": source_url,
        "method": method,
        "url": url,
        "path": parts.path or "/",
        "query_string": parts.query,
        "headers": json.dumps(headers, ensure_ascii=False),
        "body": body,
        "raw_request": safe_raw_request,
        "notes": f"{note}:{rule_id}" if rule_id else note,
    }


def read_rows(input_dir: Path, limit: int, per_category_limit: int, seed: int) -> list[dict[str, str]]:
    rng = random.Random(seed)
    buckets: dict[str, list[dict[str, str]]] = defaultdict(list)
    seen_by_category: dict[str, int] = defaultdict(int)

    for path in sorted(input_dir.glob("*/modsec_audit.anon.log")):
        text = path.read_text(encoding="utf-8", errors="replace")
        for transaction in split_transactions(text):
            sections = parse_sections(transaction)
            txid = transaction_id(sections.get("A", ""))
            source_url = f"{path.relative_to(input_dir)}#{txid}" if txid else str(path.relative_to(input_dir))
            row = transaction_to_row(sections, source_url)
            if row is None:
                continue
            category = row["notes"].split(":", 1)[0]
            seen_by_category[category] += 1
            seen = seen_by_category[category]
            bucket = buckets[category]
            if len(bucket) < per_category_limit:
                bucket.append(row)
            else:
                replace_index = rng.randrange(seen)
                if replace_index < per_category_limit:
                    bucket[replace_index] = row

    rows = [row for category in sorted(buckets) for row in buckets[category]]
    rng.shuffle(rows)
    if limit > 0:
        rows = rows[:limit]
    for index, row in enumerate(rows, start=1):
        row["id"] = f"pos_owasp_modsec_{index:06d}"
    return rows


def write_rows(rows: list[dict[str, str]], output_path: Path) -> int:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Process OWASP ModSecurity audit logs into project positive request CSV.")
    parser.add_argument("--input-dir", type=Path, default=DEFAULT_INPUT_DIR)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--limit", type=int, default=3000)
    parser.add_argument("--per-category-limit", type=int, default=800)
    parser.add_argument("--seed", type=int, default=42)
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()
    rows = read_rows(args.input_dir, args.limit, args.per_category_limit, args.seed)
    count = write_rows(rows, args.output)
    print(f"wrote {count} positive rows -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
