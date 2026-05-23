"""
- giữ raw value
- lowercase
- URL decode 1 lần
- URL decode recursive tối đa 3 lần
- HTML entity decode
- Unicode normalize
- normalize path
- parse query nhưng vẫn giữ duplicate params
"""

from __future__ import annotations

import html
import posixpath
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import SplitResult, unquote, unquote_plus, urlsplit


@dataclass(frozen=True)
class CanonicalValue:
    raw: str
    lowercase: str
    url_decoded_once: str
    url_decoded_recursive: str
    html_entity_decoded: str
    unicode_normalized: str


@dataclass(frozen=True)
class CanonicalQueryParam:
    raw_name: str
    raw_value: str
    name: CanonicalValue
    value: CanonicalValue


@dataclass(frozen=True)
class CanonicalRequest:
    raw_url: str
    path: CanonicalValue
    query: CanonicalValue
    body: CanonicalValue
    normalized_path: str
    query_params: list[CanonicalQueryParam]
    raw_text: str
    decoded_once_text: str
    decoded_recursive_text: str
    normalized_text: str


def canonicalize_request(row: dict[str, str]) -> CanonicalRequest:
    url = row.get("url") or ""
    parts = _safe_urlsplit(url)
    path = row.get("path") or parts.path or "/"
    query = row.get("query_string") or parts.query
    body = row.get("body") or ""

    path_value = canonicalize_value(path, plus_as_space=False)
    query_value = canonicalize_value(query, plus_as_space=True)
    body_value = canonicalize_value(body, plus_as_space=True)
    query_params = parse_query_preserving_duplicates(query)

    raw_items = (path_value.raw, query_value.raw, body_value.raw)
    decoded_once_items = (
        path_value.url_decoded_once,
        query_value.url_decoded_once,
        body_value.url_decoded_once,
    )
    decoded_recursive_items = (
        path_value.url_decoded_recursive,
        query_value.url_decoded_recursive,
        body_value.url_decoded_recursive,
    )
    normalized_items = (
        path_value.unicode_normalized,
        query_value.unicode_normalized,
        body_value.unicode_normalized,
    )

    return CanonicalRequest(
        raw_url=url,
        path=path_value,
        query=query_value,
        body=body_value,
        normalized_path=normalize_path(path),
        query_params=query_params,
        raw_text=" ".join(raw_items),
        decoded_once_text=" ".join(decoded_once_items),
        decoded_recursive_text=" ".join(decoded_recursive_items),
        normalized_text=" ".join(normalized_items),
    )


def canonicalize_value(value: str, plus_as_space: bool = True) -> CanonicalValue:
    raw = str(value or "")
    decoded_once = url_decode_once(raw, plus_as_space=plus_as_space)
    decoded_recursive = url_decode_recursive(raw, max_rounds=3, plus_as_space=plus_as_space)
    html_decoded = html.unescape(decoded_recursive)
    unicode_normalized = unicodedata.normalize("NFKC", html_decoded)
    return CanonicalValue(
        raw=raw,
        lowercase=raw.lower(),
        url_decoded_once=decoded_once,
        url_decoded_recursive=decoded_recursive,
        html_entity_decoded=html_decoded,
        unicode_normalized=unicode_normalized,
    )


def url_decode_once(value: str, plus_as_space: bool = True) -> str:
    if plus_as_space:
        return unquote_plus(value, errors="replace")
    return unquote(value, errors="replace")


def url_decode_recursive(value: str, max_rounds: int = 3, plus_as_space: bool = True) -> str:
    decoded = value
    for _ in range(max_rounds):
        next_decoded = url_decode_once(decoded, plus_as_space=plus_as_space)
        if next_decoded == decoded:
            break
        decoded = next_decoded
    return decoded


def normalize_path(path: str) -> str:
    value = canonicalize_value(path or "/", plus_as_space=False).unicode_normalized
    value = value.replace("\\", "/")
    value = re.sub(r"/{2,}", "/", value)
    if not value.startswith("/"):
        value = "/" + value
    normalized = posixpath.normpath(value)
    if normalized == ".":
        normalized = "/"
    if value.endswith("/") and normalized != "/":
        normalized += "/"
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    return normalized


def parse_query_preserving_duplicates(query: str) -> list[CanonicalQueryParam]:
    if not query:
        return []

    params: list[CanonicalQueryParam] = []
    for part in query.split("&"):
        if not part:
            continue
        raw_name, separator, raw_value = part.partition("=")
        if not separator:
            raw_value = ""
        params.append(
            CanonicalQueryParam(
                raw_name=raw_name,
                raw_value=raw_value,
                name=canonicalize_value(raw_name, plus_as_space=True),
                value=canonicalize_value(raw_value, plus_as_space=True),
            )
        )
    return params


def _safe_urlsplit(url: str) -> SplitResult:
    try:
        return urlsplit(url)
    except ValueError:
        return SplitResult("", "", "", "", "")
