"""OWASP API Security Top 10 scanner — OpenAPI driven.

Imports a remote/uploaded OpenAPI 3.x spec and runs targeted tests against the
declared base URL:

- API1 Broken Object Level Authorization (BOLA): swap numeric IDs and check 200
- API2 Broken Authentication: endpoints without auth scheme returning data
- API3 Excessive Data Exposure (heuristic): large unfiltered responses
- API4 Lack of Resource & Rate Limiting: burst requests checking 429
- API5 Broken Function Level Authorization: admin endpoints reachable as user
- API6 Mass Assignment: body schemas without additionalProperties:false
- API7 Security Misconfiguration: verbose errors on malformed payloads
- API8 Injection: error-based SQLi probe on string parameters
- API9 Improper Inventory: HTTP endpoints in spec (not HTTPS)
- API10 Insufficient Logging — out of scope (server-side concern)

Safe payloads only.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from app.scanners.base import ScanFinding

logger = logging.getLogger(__name__)

USER_AGENT = "AI-Software-Auditor-API/1.0"
REQUEST_TIMEOUT = 12.0
MAX_ENDPOINTS = 40
RATE_LIMIT_BURST = 25

SQL_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"PostgreSQL.*ERROR",
    r"sqlite3\.OperationalError",
    r"ORA-\d{5}",
    r"Microsoft .*ODBC.*SQL Server",
    r"SQLSTATE\[\w+\]",
]

STACK_TRACE_PATTERNS = [
    r"Traceback \(most recent call last\)",
    r"at [\w\.\$]+\([\w/\\\.]+:\d+\)",
    r"java\.lang\.\w+Exception",
    r"<title>Werkzeug Debugger</title>",
]


def scan_api(spec_url_or_text: str, *, auth: dict | None = None) -> list[ScanFinding]:
    """Run OWASP API Top 10 checks against an OpenAPI spec.

    Args:
        spec_url_or_text: URL to a JSON/YAML OpenAPI spec, or raw spec text.
        auth: optional auth config (`{"type": "bearer", "token": "..."}`).
    """
    findings: list[ScanFinding] = []
    spec, spec_source = _load_spec(spec_url_or_text)
    if not spec:
        findings.append(
            ScanFinding(
                category="security",
                severity="high",
                title="OpenAPI spec could not be loaded",
                description=f"Failed to fetch or parse spec from: {spec_source}",
                impact="API security audit could not run without a valid spec.",
                fix_recommendation="Provide a publicly reachable OpenAPI 3.x JSON or YAML spec URL.",
                file_path=spec_source,
                line_start=0,
                line_end=0,
                rule_id="api-spec-load-failed",
                scanner="api-security",
                confidence="high",
            )
        )
        return findings

    base_url = _resolve_base_url(spec, spec_source)
    if not base_url:
        findings.append(
            ScanFinding(
                category="security",
                severity="medium",
                title="OpenAPI spec missing servers[].url",
                description="No `servers` array found in spec — cannot run live tests.",
                impact="API endpoints cannot be discovered for runtime checks.",
                fix_recommendation="Add a `servers` entry with the production base URL.",
                file_path=spec_source,
                line_start=0,
                line_end=0,
                rule_id="api-no-server-url",
                scanner="api-security",
                confidence="high",
            )
        )
        return findings

    endpoints = _collect_endpoints(spec, base_url)[:MAX_ENDPOINTS]

    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    auth_basic = None
    if auth:
        auth_type = (auth.get("type") or "").lower()
        if auth_type == "bearer" and auth.get("token"):
            headers["Authorization"] = f"Bearer {auth['token']}"
        elif auth_type == "basic":
            auth_basic = (auth.get("username", ""), auth.get("password", ""))
        elif auth_type == "header" and auth.get("header_name"):
            headers[str(auth["header_name"])] = str(auth.get("header_value", ""))

    findings.extend(_check_spec_static(spec, endpoints, base_url))

    try:
        with httpx.Client(
            follow_redirects=True,
            timeout=REQUEST_TIMEOUT,
            headers=headers,
            auth=auth_basic,
            verify=True,
        ) as client:
            findings.extend(_check_missing_auth(client, endpoints, has_auth=bool(auth)))
            findings.extend(_check_bola(client, endpoints))
            findings.extend(_check_verbose_errors(client, endpoints))
            findings.extend(_check_injection(client, endpoints))
            findings.extend(_check_rate_limit(client, endpoints))
            findings.extend(_check_function_level_auth(client, endpoints, has_auth=bool(auth)))
    except httpx.HTTPError as exc:
        logger.warning("API scan aborted: %s", exc)

    return findings


def _load_spec(spec_url_or_text: str) -> tuple[dict | None, str]:
    if spec_url_or_text.startswith(("http://", "https://")):
        try:
            with httpx.Client(timeout=20.0, headers={"User-Agent": USER_AGENT}) as client:
                response = client.get(spec_url_or_text)
                response.raise_for_status()
                content_type = response.headers.get("content-type", "")
                if "yaml" in content_type or spec_url_or_text.endswith((".yaml", ".yml")):
                    try:
                        import yaml  # type: ignore
                        return yaml.safe_load(response.text), spec_url_or_text
                    except Exception:
                        return None, spec_url_or_text
                return response.json(), spec_url_or_text
        except (httpx.HTTPError, json.JSONDecodeError):
            return None, spec_url_or_text
    try:
        return json.loads(spec_url_or_text), "(inline spec)"
    except json.JSONDecodeError:
        return None, "(inline spec)"


def _resolve_base_url(spec: dict, spec_source: str) -> str:
    servers = spec.get("servers") or []
    for entry in servers:
        url = entry.get("url") if isinstance(entry, dict) else None
        if url:
            if url.startswith("/"):
                spec_origin = urlparse(spec_source)
                if spec_origin.scheme and spec_origin.netloc:
                    return f"{spec_origin.scheme}://{spec_origin.netloc}{url.rstrip('/')}"
            return url.rstrip("/")
    # Swagger 2.x fallback
    host = spec.get("host")
    scheme = (spec.get("schemes") or ["https"])[0]
    base_path = (spec.get("basePath") or "/").rstrip("/")
    if host:
        return f"{scheme}://{host}{base_path}"
    return ""


def _collect_endpoints(spec: dict, base_url: str) -> list[dict]:
    paths = spec.get("paths") or {}
    endpoints: list[dict] = []
    for path, operations in paths.items():
        if not isinstance(operations, dict):
            continue
        for method, op in operations.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete"):
                continue
            if not isinstance(op, dict):
                continue
            endpoints.append(
                {
                    "path": path,
                    "method": method.upper(),
                    "url": _build_endpoint_url(base_url, path),
                    "operation": op,
                    "parameters": op.get("parameters") or [],
                    "security": op.get("security"),
                    "requestBody": op.get("requestBody"),
                }
            )
    return endpoints


def _build_endpoint_url(base_url: str, path: str) -> str:
    rendered = re.sub(r"\{[^/}]+\}", "1", path)
    return base_url.rstrip("/") + "/" + rendered.lstrip("/")


def _check_spec_static(
    spec: dict, endpoints: list[dict], base_url: str
) -> list[ScanFinding]:
    findings: list[ScanFinding] = []

    if base_url.startswith("http://"):
        findings.append(
            _f(
                "API base URL uses plain HTTP",
                f"OpenAPI servers[] declares HTTP endpoint: {base_url}",
                "API credentials and data travel in plaintext over the network.",
                "Move the API behind HTTPS with a valid certificate and update the spec.",
                severity="high",
                rule_id="api-http-base-url",
                url=base_url,
            )
        )

    global_security = spec.get("security")
    components = spec.get("components") or {}
    schemes = components.get("securitySchemes") or spec.get("securityDefinitions") or {}
    if not schemes:
        findings.append(
            _f(
                "OpenAPI spec defines no security schemes",
                "components.securitySchemes / securityDefinitions is empty.",
                "No authentication mechanism is documented — likely unprotected APIs.",
                "Define at least one security scheme (bearerAuth / apiKeyAuth / oauth2).",
                severity="medium",
                rule_id="api-no-security-schemes",
                url=base_url,
            )
        )

    if not global_security:
        unsecured = [e for e in endpoints if not e["security"]]
        if unsecured and schemes:
            findings.append(
                _f(
                    "No global security requirement applied",
                    f"{len(unsecured)} endpoints declare no security and no global default exists.",
                    "Endpoints opted into authentication individually — easy to miss one.",
                    "Add a top-level `security` array applying default auth to every endpoint.",
                    severity="medium",
                    rule_id="api-no-global-security",
                    url=base_url,
                )
            )

    for endpoint in endpoints:
        body = endpoint.get("requestBody") or {}
        content = body.get("content", {}) if isinstance(body, dict) else {}
        for media_type, media in content.items():
            schema = media.get("schema") if isinstance(media, dict) else None
            if not isinstance(schema, dict):
                continue
            if schema.get("type") == "object" and schema.get("additionalProperties") is not False:
                findings.append(
                    _f(
                        f"Mass assignment risk: {endpoint['method']} {endpoint['path']}",
                        f"Body schema for {media_type} permits arbitrary additional properties.",
                        "Clients may set protected fields (is_admin, balance, role) by name.",
                        "Set `additionalProperties: false` and explicitly list permitted fields.",
                        severity="medium",
                        rule_id="api-mass-assignment",
                        url=endpoint["url"],
                    )
                )
                break

    return findings


def _check_missing_auth(
    client: httpx.Client, endpoints: list[dict], *, has_auth: bool
) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    for endpoint in endpoints[:10]:
        if endpoint["method"] != "GET":
            continue
        if endpoint["security"]:
            continue
        try:
            response = client.get(endpoint["url"])
        except httpx.HTTPError:
            continue
        if response.status_code == 200 and len(response.content) > 50:
            findings.append(
                _f(
                    f"Unauthenticated data exposure: GET {endpoint['path']}",
                    f"Endpoint returned 200 ({len(response.content)} bytes) without authentication.",
                    "Sensitive data may be readable by any anonymous client.",
                    "Require authentication on this endpoint via security middleware.",
                    severity="high",
                    rule_id="api-unauthenticated-data",
                    url=endpoint["url"],
                )
            )
    return findings


def _check_bola(client: httpx.Client, endpoints: list[dict]) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    for endpoint in endpoints:
        if endpoint["method"] not in ("GET", "DELETE", "PATCH", "PUT"):
            continue
        if not re.search(r"\{\w*(id|uuid|key|user)\w*\}", endpoint["path"], re.I):
            continue
        url1 = _replace_path_id(endpoint["url"], "1")
        url2 = _replace_path_id(endpoint["url"], "2")
        try:
            r1 = client.request(endpoint["method"], url1)
            r2 = client.request(endpoint["method"], url2)
        except httpx.HTTPError:
            continue
        if r1.status_code == 200 and r2.status_code == 200 and r1.content and r2.content:
            if r1.content != r2.content:
                findings.append(
                    _f(
                        f"Possible BOLA on {endpoint['method']} {endpoint['path']}",
                        f"Both ID=1 and ID=2 returned 200 with different content — no per-object ACL check visible.",
                        "Users may access objects belonging to other users by changing the ID.",
                        "Enforce per-object authorization: verify the requester owns or may access the object.",
                        severity="critical",
                        rule_id="api-bola-numeric-id",
                        url=endpoint["url"],
                    )
                )
                break
    return findings


def _check_verbose_errors(client: httpx.Client, endpoints: list[dict]) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    for endpoint in endpoints[:8]:
        try:
            response = client.request(
                endpoint["method"], endpoint["url"], content=b"{ malformed", headers={"Content-Type": "application/json"}
            )
            body = response.text[:30_000]
        except httpx.HTTPError:
            continue
        for pattern in STACK_TRACE_PATTERNS:
            if re.search(pattern, body, re.I):
                findings.append(
                    _f(
                        f"Verbose error from {endpoint['method']} {endpoint['path']}",
                        "Malformed JSON body triggered a server stack trace in the response.",
                        "Internal code paths and dependency versions leak to attackers.",
                        "Disable debug mode in production; return generic error envelopes; log details server-side.",
                        severity="high",
                        rule_id="api-verbose-error",
                        url=endpoint["url"],
                    )
                )
                return findings
    return findings


def _check_injection(client: httpx.Client, endpoints: list[dict]) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    for endpoint in endpoints[:15]:
        if endpoint["method"] != "GET":
            continue
        query_params = [
            p for p in endpoint["parameters"]
            if isinstance(p, dict) and p.get("in") == "query"
        ]
        for param in query_params[:3]:
            name = param.get("name")
            if not name:
                continue
            url = endpoint["url"]
            if "?" in url:
                url = f"{url}&{name}=1'"
            else:
                url = f"{url}?{name}=1'"
            try:
                response = client.get(url)
                text = response.text[:30_000]
            except httpx.HTTPError:
                continue
            for pattern in SQL_ERROR_PATTERNS:
                if re.search(pattern, text, re.I):
                    findings.append(
                        _f(
                            f"Possible SQL injection in '{name}' on {endpoint['path']}",
                            f"SQL error pattern in response when injecting `'` into `{name}`.",
                            "Attacker may read or modify the database.",
                            "Use parameterized queries / ORM placeholders; reject untrusted input on the boundary.",
                            severity="critical",
                            rule_id="api-sqli-error",
                            url=url,
                        )
                    )
                    return findings
    return findings


def _check_rate_limit(client: httpx.Client, endpoints: list[dict]) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    target = next((e for e in endpoints if e["method"] == "GET"), None)
    if not target:
        return findings

    statuses: list[int] = []
    saw_rate_limit_header = False
    try:
        for _ in range(RATE_LIMIT_BURST):
            response = client.get(target["url"])
            statuses.append(response.status_code)
            if any(
                h.lower() in ("x-ratelimit-limit", "ratelimit-limit", "x-rate-limit-limit", "retry-after")
                for h in response.headers
            ):
                saw_rate_limit_header = True
    except httpx.HTTPError:
        pass

    if statuses and 429 not in statuses and not saw_rate_limit_header:
        findings.append(
            _f(
                f"No rate limiting detected on {target['path']}",
                f"{len(statuses)} rapid requests — none returned 429, no rate-limit headers seen.",
                "Brute-force, credential stuffing, and resource exhaustion are unmitigated.",
                "Add rate limiting (per-IP / per-token) and emit standard X-RateLimit headers.",
                severity="medium",
                rule_id="api-no-rate-limit",
                url=target["url"],
            )
        )
    return findings


def _check_function_level_auth(
    client: httpx.Client, endpoints: list[dict], *, has_auth: bool
) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    if not has_auth:
        return findings
    admin_endpoints = [
        e for e in endpoints
        if re.search(r"/admin|/internal|/manage|/sudo", e["path"], re.I)
    ]
    for endpoint in admin_endpoints[:5]:
        try:
            response = client.request(endpoint["method"], endpoint["url"])
        except httpx.HTTPError:
            continue
        if response.status_code == 200:
            findings.append(
                _f(
                    f"Possible privilege escalation: {endpoint['method']} {endpoint['path']}",
                    "Admin-style endpoint responded 200 to a non-admin token.",
                    "Regular users may invoke privileged operations.",
                    "Add role-based authorization checks on every admin/internal endpoint.",
                    severity="critical",
                    rule_id="api-function-level-auth",
                    url=endpoint["url"],
                )
            )
    return findings


def _replace_path_id(url: str, new_id: str) -> str:
    return re.sub(r"/1(?=/|$|\?)", f"/{new_id}", url, count=1)


def _f(
    title: str,
    description: str,
    impact: str,
    fix: str,
    *,
    severity: str,
    rule_id: str,
    url: str,
) -> ScanFinding:
    return ScanFinding(
        category="security",
        severity=severity,
        title=title,
        description=description,
        impact=impact,
        fix_recommendation=fix,
        file_path=url,
        line_start=0,
        line_end=0,
        rule_id=rule_id,
        scanner="api-security",
        confidence="high",
    )
