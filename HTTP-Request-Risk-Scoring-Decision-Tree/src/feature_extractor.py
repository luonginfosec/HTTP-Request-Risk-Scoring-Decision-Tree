"""Manual feature extraction for HTTP request risk ranking."""

from __future__ import annotations

import json
import re
from collections import Counter

from src.request_canonicalizer import canonicalize_request


ID_PARAM_NAMES = {
    "id", "uid", "user_id", "userid", "account_id", "accountid",
    "tenant_id", "tenantid", "org_id", "organization_id",
    "document_id", "doc_id", "file_id", "order_id", "invoice_id",
    "customer_id", "profile_id", "item_id", "product_id", "post_id",
}

URL_PARAM_NAMES = {
    "url", "uri", "target", "dest", "destination", "redirect",
    "redirect_uri", "redirect_url", "return", "return_url", "return_to",
    "next", "continue", "callback", "callback_url", "webhook", "proxy",
    "fetch",
}

FILE_PARAM_NAMES = {
    "file", "filename", "path", "filepath", "download", "upload",
    "attachment", "image", "avatar", "template", "page",
}

BUSINESS_PARAM_NAMES = {
    "role", "admin", "is_admin", "price", "amount", "discount", "coupon",
    "balance", "plan", "tier", "permission", "scope",
}

SEARCH_PARAM_NAMES = {
    "q", "query", "search", "keyword", "filter", "sort", "order",
}

ADMIN_PATH_WORDS = {"admin", "internal", "debug", "manage", "management"}
DOCUMENT_PATH_WORDS = {"document", "documents", "doc", "file", "files"}
USER_PATH_WORDS = {"user", "users", "account", "accounts", "profile"}
PAYMENT_PATH_WORDS = {"payment", "payments", "billing", "invoice", "checkout"}
UPLOAD_PATH_WORDS = {"upload", "download", "import", "export", "attachment"}

PRIVATE_IP_RE = re.compile(
    r"(?:127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.169\.254|"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})",
    re.IGNORECASE,
)

UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)

BASE64_LIKE_RE = re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$")
ENCODED_RE = re.compile(r"%[0-9a-fA-F]{2}")
SPECIAL_CHARS_RE = re.compile(r"['\"<>;{}()|`$\\]")
HTML_ENTITY_RE = re.compile(r"&(?:#\d+|#x[0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]+);")
TRAVERSAL_RE = re.compile(r"(?:\.\./|\.\.\\|/etc/passwd|\\etc\\passwd|boot\.ini|win\.ini)", re.IGNORECASE)
SQLI_RE = re.compile(
    r"(?:\bunion\s+(?:all\s+)?select\b|\bor\s+1\s*=\s*1\b|"
    r"\band\s+1\s*=\s*1\b|\binformation_schema\b|\bsleep\s*\(|"
    r"\bbenchmark\s*\(|\bdrop\s+table\b|\bselect\b.+\bfrom\b)",
    re.IGNORECASE | re.DOTALL,
)
XSS_RE = re.compile(
    r"(?:<\s*script\b|javascript\s*:|on[a-z]+\s*=|<\s*img\b[^>]+onerror\s*=|alert\s*\()",
    re.IGNORECASE | re.DOTALL,
)
URL_RE = re.compile(r"https?://", re.IGNORECASE)

FEATURE_NAMES = (
    "method_get",
    "method_post",
    "method_put",
    "method_patch",
    "method_delete",
    "path_depth",
    "has_query",
    "num_params",
    "duplicate_param_count",
    "max_duplicate_param_name_count",
    "has_body",
    "body_length_bucket",
    "has_api_path",
    "has_admin_path",
    "has_internal_path",
    "has_debug_path",
    "has_document_path",
    "has_user_path",
    "has_payment_path",
    "has_upload_path",
    "has_id_param",
    "has_url_param",
    "has_file_param",
    "has_business_param",
    "has_search_param",
    "has_numeric_value",
    "has_uuid_value",
    "has_url_value",
    "has_private_ip_value",
    "has_base64_like_value",
    "has_encoded_value",
    "has_special_chars",
    "has_double_encoded_value",
    "decoded_changes_value",
    "raw_encoded_ratio",
    "has_html_entity_value",
    "has_unicode_normalized_change",
    "has_recursive_decoded_traversal",
    "has_recursive_decoded_sqli",
    "has_recursive_decoded_xss",
    "has_recursive_decoded_private_ip",
    "has_recursive_decoded_url",
    "has_authorization_header",
    "has_cookie_header",
    "has_content_type_json",
    "has_content_type_form",
    "has_content_type_xml",
    "has_tenant_header",
    "has_origin_header",
    "has_referer_header",
    "has_x_forwarded_for",
    "has_json_body",
    "has_xml_body",
    "has_form_body",
    "body_has_role",
    "body_has_admin_value",
    "body_has_id_field",
    "body_has_url_field",
    "body_has_file_field",
    "body_has_price_field",
    "has_admin_and_url",
    "has_document_and_id",
    "has_tenant_and_id",
    "has_auth_and_id",
    "has_write_method_and_id",
    "has_upload_and_file",
    "has_url_param_and_private_ip",
    "has_role_and_admin_value",
)


def extract_features(row: dict[str, str]) -> dict[str, int]:
    method = (row.get("method") or "").upper()
    canonical = canonicalize_request(row)
    path = canonical.path.raw or "/"
    query = canonical.query.raw
    body = canonical.body.raw
    headers = _parse_headers(row.get("headers") or "")

    path_l = " ".join([path, canonical.path.unicode_normalized, canonical.normalized_path]).lower()
    path_words = set(filter(None, re.split(r"[^a-z0-9_]+", path_l)))
    query_pairs = [(param.name.unicode_normalized, param.value.unicode_normalized) for param in canonical.query_params]
    param_names_list = [name.lower() for name, _ in query_pairs]
    param_name_counts = Counter(param_names_list)
    param_names = set(param_names_list)
    decoded_values = [value for _, value in query_pairs]
    joined_values = " ".join(decoded_values)
    body_l = canonical.body.unicode_normalized.lower()
    header_names = {name.lower() for name in headers}
    content_type = _header_value(headers, "content-type").lower()
    html_decoded_text = " ".join(
        [
            canonical.path.html_entity_decoded,
            canonical.query.html_entity_decoded,
            canonical.body.html_entity_decoded,
        ]
    )
    decoded_signal_text = canonical.normalized_text
    decoded_signal_text_l = decoded_signal_text.lower()
    raw_signal_text = canonical.raw_text
    duplicate_param_count = max(0, len(param_names_list) - len(param_names))
    max_duplicate_param_name_count = max(param_name_counts.values(), default=0)

    has_id_param = bool(param_names & ID_PARAM_NAMES)
    has_url_param = bool(param_names & URL_PARAM_NAMES)
    has_file_param = bool(param_names & FILE_PARAM_NAMES)
    has_business_param = bool(param_names & BUSINESS_PARAM_NAMES)
    has_search_param = bool(param_names & SEARCH_PARAM_NAMES)
    has_tenant_header = any("tenant" in name or "organization" in name for name in header_names)
    has_auth = "authorization" in header_names
    has_cookie = "cookie" in header_names

    has_admin_path = bool(path_words & ADMIN_PATH_WORDS)
    has_document_path = bool(path_words & DOCUMENT_PATH_WORDS)
    has_upload_path = bool(path_words & UPLOAD_PATH_WORDS)

    body_has_role = _contains_key_like(body_l, {"role", "permission", "scope"})
    body_has_admin_value = "admin" in body_l or '"is_admin":true' in body_l
    body_has_id_field = _contains_key_like(body_l, ID_PARAM_NAMES)
    body_has_url_field = _contains_key_like(body_l, URL_PARAM_NAMES)
    body_has_file_field = _contains_key_like(body_l, FILE_PARAM_NAMES)
    body_has_price_field = _contains_key_like(body_l, BUSINESS_PARAM_NAMES)

    values_and_body = " ".join([joined_values, canonical.body.unicode_normalized, canonical.path.unicode_normalized])
    feature_values = {
        "method_get": method == "GET",
        "method_post": method == "POST",
        "method_put": method == "PUT",
        "method_patch": method == "PATCH",
        "method_delete": method == "DELETE",
        "path_depth": min(10, len([p for p in path.split("/") if p])),
        "has_query": bool(query),
        "num_params": min(10, len(query_pairs)),
        "duplicate_param_count": min(10, duplicate_param_count),
        "max_duplicate_param_name_count": min(10, max_duplicate_param_name_count),
        "has_body": bool(body),
        "body_length_bucket": min(10, len(body) // 500),
        "has_api_path": "/api/" in path_l or path_l.startswith("/api") or "/rest/" in path_l,
        "has_admin_path": has_admin_path,
        "has_internal_path": "internal" in path_words,
        "has_debug_path": "debug" in path_words,
        "has_document_path": has_document_path,
        "has_user_path": bool(path_words & USER_PATH_WORDS),
        "has_payment_path": bool(path_words & PAYMENT_PATH_WORDS),
        "has_upload_path": has_upload_path,
        "has_id_param": has_id_param,
        "has_url_param": has_url_param,
        "has_file_param": has_file_param,
        "has_business_param": has_business_param,
        "has_search_param": has_search_param,
        "has_numeric_value": any(value.isdigit() for value in decoded_values),
        "has_uuid_value": bool(UUID_RE.search(values_and_body)),
        "has_url_value": "http://" in values_and_body.lower() or "https://" in values_and_body.lower(),
        "has_private_ip_value": bool(PRIVATE_IP_RE.search(values_and_body)),
        "has_base64_like_value": any(BASE64_LIKE_RE.match(value.strip()) for value in decoded_values),
        "has_encoded_value": bool(ENCODED_RE.search(raw_signal_text)),
        "has_special_chars": bool(SPECIAL_CHARS_RE.search(raw_signal_text + " " + decoded_signal_text)),
        "has_double_encoded_value": _has_double_encoding(raw_signal_text, canonical.decoded_once_text),
        "decoded_changes_value": raw_signal_text != canonical.decoded_recursive_text,
        "raw_encoded_ratio": _encoded_ratio_percent(raw_signal_text),
        "has_html_entity_value": bool(HTML_ENTITY_RE.search(raw_signal_text)),
        "has_unicode_normalized_change": html_decoded_text != decoded_signal_text,
        "has_recursive_decoded_traversal": bool(TRAVERSAL_RE.search(decoded_signal_text)),
        "has_recursive_decoded_sqli": bool(SQLI_RE.search(decoded_signal_text)),
        "has_recursive_decoded_xss": bool(XSS_RE.search(decoded_signal_text)),
        "has_recursive_decoded_private_ip": bool(PRIVATE_IP_RE.search(decoded_signal_text)),
        "has_recursive_decoded_url": bool(URL_RE.search(decoded_signal_text_l)),
        "has_authorization_header": has_auth,
        "has_cookie_header": has_cookie,
        "has_content_type_json": "json" in content_type,
        "has_content_type_form": "form" in content_type or "x-www-form-urlencoded" in content_type,
        "has_content_type_xml": "xml" in content_type,
        "has_tenant_header": has_tenant_header,
        "has_origin_header": "origin" in header_names,
        "has_referer_header": "referer" in header_names,
        "has_x_forwarded_for": "x-forwarded-for" in header_names,
        "has_json_body": body.strip().startswith(("{", "[")),
        "has_xml_body": body.lstrip().startswith("<"),
        "has_form_body": "=" in body and "&" in body,
        "body_has_role": body_has_role,
        "body_has_admin_value": body_has_admin_value,
        "body_has_id_field": body_has_id_field,
        "body_has_url_field": body_has_url_field,
        "body_has_file_field": body_has_file_field,
        "body_has_price_field": body_has_price_field,
        "has_admin_and_url": has_admin_path and (has_url_param or body_has_url_field),
        "has_document_and_id": has_document_path and (has_id_param or body_has_id_field),
        "has_tenant_and_id": has_tenant_header and (has_id_param or body_has_id_field),
        "has_auth_and_id": has_auth and (has_id_param or body_has_id_field),
        "has_write_method_and_id": method in {"POST", "PUT", "PATCH", "DELETE"} and (has_id_param or body_has_id_field),
        "has_upload_and_file": has_upload_path and (has_file_param or body_has_file_field),
        "has_url_param_and_private_ip": has_url_param and bool(PRIVATE_IP_RE.search(values_and_body)),
        "has_role_and_admin_value": body_has_role and body_has_admin_value,
    }
    return {name: int(feature_values[name]) for name in FEATURE_NAMES}


def _parse_headers(raw: str) -> dict[str, str]:
    raw = raw.strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if isinstance(parsed, dict):
        return {str(k): str(v) for k, v in parsed.items()}
    if isinstance(parsed, list):
        out = {}
        for item in parsed:
            if isinstance(item, list | tuple) and len(item) >= 2:
                out[str(item[0])] = str(item[1])
        return out
    return {}


def _header_value(headers: dict[str, str], name: str) -> str:
    name_l = name.lower()
    for key, value in headers.items():
        if key.lower() == name_l:
            return value
    return ""


def _contains_key_like(text: str, names: set[str]) -> bool:
    if not text:
        return False
    for name in names:
        if re.search(rf"['\"]?{re.escape(name)}['\"]?\s*[:=]", text):
            return True
    return False


def _has_double_encoding(raw_text: str, decoded_once_text: str) -> bool:
    return bool(re.search(r"%25[0-9a-fA-F]{2}", raw_text)) or (
        bool(ENCODED_RE.search(raw_text)) and bool(ENCODED_RE.search(decoded_once_text))
    )


def _encoded_ratio_percent(text: str) -> int:
    if not text:
        return 0
    encoded_chars = len(ENCODED_RE.findall(text)) * 3
    return min(100, round(encoded_chars * 100 / len(text)))
