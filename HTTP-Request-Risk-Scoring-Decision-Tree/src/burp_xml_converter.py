"""Convert Burp Suite XML exports into the project request CSV schema."""

from __future__ import annotations

import base64
import csv
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlsplit


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


def convert_burp_xml_to_csv(
    input_path: str | Path,
    output_path: str | Path,
    *,
    label: str | int = "0",
    source: str | None = None,
    notes: str = "burp_external",
    id_prefix: str = "burp_external",
    default_host: str = "burp.local",
    limit: int = 5000,
) -> int:
    input_path = Path(input_path)
    output_path = Path(output_path)
    rows = convert_burp_xml_to_rows(
        input_path,
        label=str(label),
        source=source or f"burp_{input_path.stem}",
        notes=notes,
        id_prefix=id_prefix,
        default_host=default_host,
        limit=limit,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def convert_burp_xml_to_rows(
    input_path: str | Path,
    *,
    label: str,
    source: str,
    notes: str,
    id_prefix: str,
    default_host: str,
    limit: int,
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for _, item in ET.iterparse(input_path, events=("end",)):
        if item.tag != "item":
            continue
        row = _item_to_row(
            item,
            len(rows) + 1,
            label=label,
            source=source,
            notes=notes,
            id_prefix=id_prefix,
            default_host=default_host,
        )
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


def _item_to_row(
    item: ET.Element,
    index: int,
    *,
    label: str,
    source: str,
    notes: str,
    id_prefix: str,
    default_host: str,
) -> dict[str, str] | None:
    raw_request = _decode_request_node(item.find("request"))
    method, target, version, headers, body = _parse_raw_request(raw_request)
    method = method or (item.findtext("method") or "").upper()
    if not method or not target:
        return None

    url = _absolute_url(item.findtext("url") or "", target, headers, default_host)
    parts = urlsplit(url)
    return {
        "id": f"{id_prefix}_{index:06d}",
        "label": label,
        "source": source,
        "source_url": item.findtext("url") or "",
        "method": method,
        "url": url,
        "path": parts.path or "/",
        "query_string": parts.query,
        "headers": json.dumps(headers, ensure_ascii=False),
        "body": body,
        "raw_request": _reconstruct_raw_request(method, url, version, headers, body),
        "notes": notes,
    }


def _decode_request_node(node: ET.Element | None) -> str:
    if node is None:
        return ""
    text = node.text or ""
    if node.attrib.get("base64", "").lower() == "true":
        return base64.b64decode(text).decode("utf-8", errors="replace")
    return text


def _parse_raw_request(raw: str) -> tuple[str, str, str, dict[str, str], str]:
    header_part, body = _split_headers_body(raw)
    lines = header_part.splitlines()
    if not lines:
        return "", "", "HTTP/1.1", {}, body

    pieces = lines[0].strip().split()
    method = pieces[0].upper() if pieces else ""
    target = pieces[1] if len(pieces) > 1 else ""
    version = pieces[2] if len(pieces) > 2 else "HTTP/1.1"
    headers = _parse_headers(lines[1:])
    return method, target, version, headers, _redact_body(body)


def _split_headers_body(raw: str) -> tuple[str, str]:
    if "\r\n\r\n" in raw:
        return raw.split("\r\n\r\n", 1)
    if "\n\n" in raw:
        return raw.split("\n\n", 1)
    return raw, ""


def _parse_headers(lines: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in lines:
        if not line.strip() or ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip()] = _redact_header(name.strip(), value.strip())
    return headers


def _redact_header(name: str, value: str) -> str:
    return "PRESENT" if _is_sensitive_name(name) else value


def _redact_body(body: str) -> str:
    stripped = body.strip()
    if not stripped:
        return ""
    if stripped.startswith(("{", "[")):
        try:
            return json.dumps(_redact_json(json.loads(stripped)), ensure_ascii=False, separators=(",", ":"))
        except json.JSONDecodeError:
            pass
    value = re.sub(
        r"(?i)([^=&\s]*(?:authorization|cookie|csrf|password|secret|token|xsrf)[^=&\s]*=)[^&\s]+",
        r"\1PRESENT",
        body,
    )
    return re.sub(
        r"(?i)((?:authorization|cookie|csrf|password|secret|token|xsrf)[^:]{0,40}:\s*)[^\s,&}\]]+",
        r"\1PRESENT",
        value,
    )


def _redact_json(value: object) -> object:
    if isinstance(value, dict):
        return {
            key: ("PRESENT" if _is_sensitive_name(str(key)) else _redact_json(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_json(item) for item in value]
    return value


def _is_sensitive_name(name: str) -> bool:
    name_l = name.lower()
    return name_l in SENSITIVE_HEADER_NAMES or any(part in name_l for part in SENSITIVE_NAME_PARTS)


def _header_value(headers: dict[str, str], name: str) -> str:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return ""


def _absolute_url(item_url: str, target: str, headers: dict[str, str], default_host: str) -> str:
    if item_url:
        return item_url
    target_parts = urlsplit(target)
    if target_parts.scheme and target_parts.netloc:
        return target
    host = _header_value(headers, "host") or default_host
    path = target if target.startswith("/") else f"/{target}"
    return f"https://{host}{path}"


def _reconstruct_raw_request(
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
