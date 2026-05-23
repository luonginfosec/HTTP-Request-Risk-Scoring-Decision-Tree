"""Detect duplicates and leakage-prone request groups."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.request_canonicalizer import canonicalize_request


DEFAULT_INPUT = Path("data/processed/requests_dataset.csv")
DEFAULT_OUTPUT = Path("data/processed/requests_dataset_dedup.csv")
DEFAULT_REPORT_DIR = Path("data/reports")

BASE_FIELDS = (
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

HASH_FIELDS = (
    "canonical_raw_request_hash",
    "endpoint_shape_hash",
    "payload_family_hash",
)

TRAVERSAL_RE = re.compile(r"(?:\.\./|\.\.\\|/etc/passwd|\\etc\\passwd|boot\.ini|win\.ini)", re.I)
SQLI_RE = re.compile(
    r"(?:\bunion\s+(?:all\s+)?select\b|\bor\s+1\s*=\s*1\b|"
    r"\band\s+1\s*=\s*1\b|\binformation_schema\b|\bsleep\s*\(|"
    r"\bbenchmark\s*\(|\bdrop\s+table\b|\bselect\b.+\bfrom\b)",
    re.I | re.S,
)
XSS_RE = re.compile(r"(?:<\s*script\b|javascript\s*:|on[a-z]+\s*=|alert\s*\()", re.I | re.S)
PRIVATE_IP_RE = re.compile(
    r"(?:127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.169\.254|"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})",
    re.I,
)
COMMAND_RE = re.compile(r"(?:\|\s*\w+|;\s*\w+|`[^`]+`|\$\([^)]+\)|\b(?:cat|dir|whoami|id|wget|curl)\b)", re.I)
XXE_RE = re.compile(r"(?:<!doctype|<!entity|system\s+[\"']file:)", re.I)
LOG4SHELL_RE = re.compile(r"\$\{jndi:", re.I)
SHELLSHOCK_RE = re.compile(r"\(\)\s*\{\s*:\s*;\s*\}", re.I)
URL_RE = re.compile(r"https?://", re.I)
ENCODED_RE = re.compile(r"%[0-9a-fA-F]{2}")


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        missing = [field for field in BASE_FIELDS if field not in (reader.fieldnames or [])]
        if missing:
            raise ValueError(f"{path} missing fields: {missing}")
        return [dict(row) for row in reader]


def add_hashes(row: dict[str, str]) -> dict[str, str]:
    canonical = canonicalize_request(row)
    method = (row.get("method") or "").upper()
    host = _host(row)
    params = [
        (
            param.name.unicode_normalized.lower(),
            param.value.unicode_normalized,
        )
        for param in canonical.query_params
    ]
    sorted_params = sorted(params)
    sorted_param_names = sorted(name for name, _ in params)
    body = _collapse_space(canonical.body.unicode_normalized)
    decoded_text = _collapse_space(canonical.normalized_text.lower())

    canonical_raw_key = {
        "method": method,
        "host": host,
        "path": canonical.normalized_path.lower(),
        "params": sorted_params,
        "body": body,
    }
    endpoint_shape_key = {
        "method": method,
        "path": canonical.normalized_path.lower(),
        "param_names": sorted_param_names,
    }
    payload_family_key = {
        "families": _payload_families(decoded_text),
        "skeleton": _payload_skeleton(decoded_text),
    }

    out = dict(row)
    out["canonical_raw_request_hash"] = _hash(canonical_raw_key)
    out["endpoint_shape_hash"] = _hash(endpoint_shape_key)
    out["payload_family_hash"] = _hash(payload_family_key)
    return out


def deduplicate_rows(rows: list[dict[str, str]]) -> tuple[list[dict[str, str]], set[str]]:
    by_hash: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        by_hash[row["canonical_raw_request_hash"]].append(row)

    conflict_hashes = {
        value
        for value, group in by_hash.items()
        if len({row.get("label", "") for row in group}) > 1
    }

    deduped: list[dict[str, str]] = []
    for value, group in by_hash.items():
        if value in conflict_hashes:
            continue
        deduped.append(group[0])
    return deduped, conflict_hashes


def write_rows(rows: list[dict[str, str]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fields = (*BASE_FIELDS, *HASH_FIELDS)
    with output_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})


def write_reports(rows: list[dict[str, str]], report_dir: Path) -> dict[str, int]:
    report_dir.mkdir(parents=True, exist_ok=True)
    exact_groups = _groups(rows, "canonical_raw_request_hash", min_size=2)
    endpoint_groups = _groups(rows, "endpoint_shape_hash", min_size=2)
    payload_groups = _groups(rows, "payload_family_hash", min_size=2)

    label_conflicts = [
        group
        for group in exact_groups + endpoint_groups + payload_groups
        if _multi_value(group["labels"])
    ]
    source_overlaps = [
        group
        for group in exact_groups + endpoint_groups + payload_groups
        if _multi_value(group["sources"])
    ]

    _write_group_report(report_dir / "duplicate_report.csv", exact_groups)
    _write_group_report(report_dir / "endpoint_shape_report.csv", endpoint_groups)
    _write_group_report(report_dir / "payload_family_report.csv", payload_groups)
    _write_group_report(report_dir / "label_conflict_report.csv", label_conflicts)
    _write_group_report(report_dir / "source_overlap_report.csv", source_overlaps)

    return {
        "exact_duplicate_groups": len(exact_groups),
        "endpoint_shape_groups": len(endpoint_groups),
        "payload_family_groups": len(payload_groups),
        "label_conflict_groups": len(label_conflicts),
        "source_overlap_groups": len(source_overlaps),
    }


def _groups(rows: list[dict[str, str]], hash_field: str, min_size: int) -> list[dict[str, str]]:
    by_hash: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        by_hash[row[hash_field]].append(row)

    out: list[dict[str, str]] = []
    for value, group in by_hash.items():
        if len(group) < min_size:
            continue
        labels = sorted({row.get("label", "") for row in group})
        sources = sorted({row.get("source", "") for row in group})
        notes = sorted({row.get("notes", "") for row in group if row.get("notes", "")})
        ids = [row.get("id", "") for row in group[:10]]
        sample = group[0]
        out.append(
            {
                "hash_type": hash_field,
                "hash": value,
                "rows": str(len(group)),
                "labels": "|".join(labels),
                "sources": "|".join(sources),
                "notes": "|".join(notes[:10]),
                "sample_ids": "|".join(ids),
                "sample_method": sample.get("method", ""),
                "sample_path": sample.get("path", ""),
                "sample_query": sample.get("query_string", "")[:300],
            }
        )

    return sorted(out, key=lambda item: (-int(item["rows"]), item["hash_type"], item["hash"]))


def _write_group_report(path: Path, rows: list[dict[str, str]]) -> None:
    fields = (
        "hash_type",
        "hash",
        "rows",
        "labels",
        "sources",
        "notes",
        "sample_ids",
        "sample_method",
        "sample_path",
        "sample_query",
    )
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        writer.writerows(rows)


def _multi_value(value: str) -> bool:
    return len([part for part in value.split("|") if part]) > 1


def _payload_families(text: str) -> list[str]:
    families = []
    if TRAVERSAL_RE.search(text):
        families.append("traversal")
    if SQLI_RE.search(text):
        families.append("sqli")
    if XSS_RE.search(text):
        families.append("xss")
    if PRIVATE_IP_RE.search(text):
        families.append("private_ip")
    if URL_RE.search(text):
        families.append("url")
    if COMMAND_RE.search(text):
        families.append("command")
    if XXE_RE.search(text):
        families.append("xxe")
    if LOG4SHELL_RE.search(text):
        families.append("log4shell")
    if SHELLSHOCK_RE.search(text):
        families.append("shellshock")
    if ENCODED_RE.search(text):
        families.append("encoded")
    if not families:
        families.append("none")
    return sorted(set(families))


def _payload_skeleton(text: str) -> str:
    value = text.lower()
    value = re.sub(r"https?://[^\s&]+", "URL", value)
    value = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "IP", value)
    value = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "UUID", value)
    value = re.sub(r"\b\d+\b", "N", value)
    value = re.sub(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", "EMAIL", value)
    value = _collapse_space(value)
    return value[:240]


def _host(row: dict[str, str]) -> str:
    try:
        url_host = urlsplit(row.get("url") or "").netloc.lower()
    except ValueError:
        url_host = ""
    if url_host:
        return url_host
    try:
        headers = json.loads(row.get("headers") or "{}")
    except json.JSONDecodeError:
        return ""
    if isinstance(headers, dict):
        for key, value in headers.items():
            if str(key).lower() == "host":
                return str(value).lower()
    return ""


def _collapse_space(value: str) -> str:
    return re.sub(r"\s+", " ", value or "").strip()


def _hash(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:24]


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Deduplicate request dataset and write leakage reports.")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--report-dir", type=Path, default=DEFAULT_REPORT_DIR)
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()
    rows = [add_hashes(row) for row in read_rows(args.input)]
    deduped, conflict_hashes = deduplicate_rows(rows)
    write_rows(deduped, args.output)
    stats = write_reports(rows, args.report_dir)

    print(f"input rows:       {len(rows)}")
    print(f"deduped rows:     {len(deduped)}")
    print(f"removed rows:     {len(rows) - len(deduped)}")
    print(f"exact conflicts:  {len(conflict_hashes)}")
    for key, value in stats.items():
        print(f"{key}: {value}")
    print(f"output:           {args.output}")
    print(f"reports:          {args.report_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
