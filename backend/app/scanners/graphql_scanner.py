"""GraphQL security scanner — introspection, batching, depth, field leaks.

Safe, read-only probes against discovered GraphQL HTTP endpoints:
- Introspection enabled in production
- GraphiQL / Playground / Voyager exposed
- Field-suggestion schema leaks (\"Did you mean\")
- GET query transport (CSRF vector)
- Unauthenticated batched / aliased queries
- Deep nested query acceptance (DoS indicator)
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Iterable
from urllib.parse import urljoin, urlparse

import httpx

from app.scanners.base import ScanFinding

logger = logging.getLogger(__name__)

USER_AGENT = "AI-Software-Auditor-GraphQL/1.0"
REQUEST_TIMEOUT = 12.0
MAX_ENDPOINTS = 6

COMMON_GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/query",
    "/gql",
    "/graph",
    "/graphiql",
    "/api/gql",
]

INTROSPECTION_QUERY = (
    "query AuditorIntrospection { __schema { queryType { name } "
    "mutationType { name } types { name kind } } }"
)
MINIMAL_INTROSPECTION = "{ __schema { types { name } } }"

FIELD_SUGGESTION_QUERY = "{ auditor_nonexistent_field_xyz { id } }"

PLAYGROUND_MARKERS = re.compile(
    r"(graphiql|altair|voyager|graphql-playground|apollo-studio|sandbox)",
    re.I,
)
FIELD_SUGGESTION_PATTERN = re.compile(
    r"did you mean|suggestions?|cannot query field|unknown field",
    re.I,
)
INTROSPECTION_PATTERN = re.compile(
    r'"__schema"|__schema|queryType|mutationType|"types"\s*:\s*\[',
    re.I,
)


def scan_graphql(
    base_url: str,
    *,
    auth: dict | None = None,
    extra_endpoints: Iterable[str] | None = None,
) -> list[ScanFinding]:
    """Probe GraphQL endpoints under a live base URL."""
    findings: list[ScanFinding] = []
    endpoints = _discover_endpoints(base_url, extra_endpoints)
    if not endpoints:
        return findings

    headers, auth_basic, cookies = _build_auth(auth)

    with httpx.Client(
        timeout=REQUEST_TIMEOUT,
        headers=headers,
        cookies=cookies,
        follow_redirects=True,
        verify=False,
    ) as client:
        for endpoint in endpoints[:MAX_ENDPOINTS]:
            try:
                findings.extend(_probe_endpoint(client, endpoint, auth_basic))
            except Exception as exc:
                logger.debug("GraphQL probe failed for %s: %s", endpoint, exc)

    return findings


def scan_graphql_static(project_dir) -> list[ScanFinding]:
    """Static hints: GraphQL schemas, Apollo config, introspection flags in code."""
    from pathlib import Path

    findings: list[ScanFinding] = []
    root = Path(project_dir)
    patterns = [
        (re.compile(r"introspection\s*:\s*true", re.I), "graphql-introspection-enabled-config"),
        (re.compile(r"playground\s*:\s*true", re.I), "graphql-playground-enabled-config"),
        (re.compile(r"graphiql\s*:\s*true", re.I), "graphql-graphiql-enabled-config"),
        (re.compile(r"csrfPrevention\s*:\s*false", re.I), "graphql-csrf-disabled"),
    ]
    exts = {".js", ".ts", ".tsx", ".py", ".go", ".yaml", ".yml", ".json", ".graphql", ".gql"}

    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in exts:
            continue
        if any(p in path.parts for p in ("node_modules", ".git", "dist", "build", ".next")):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")[:80_000]
        except OSError:
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        for pattern, rule_id in patterns:
            if pattern.search(text):
                findings.append(
                    ScanFinding(
                        category="security",
                        severity="medium",
                        title=f"GraphQL misconfiguration in source — {rule_id}",
                        description=f"Pattern `{pattern.pattern}` found in `{rel}`.",
                        impact="Production GraphQL may expose schema or CSRF protections may be disabled.",
                        fix_recommendation=(
                            "Disable introspection and playgrounds in production; enable CSRF prevention."
                        ),
                        file_path=rel,
                        line_start=0,
                        line_end=0,
                        rule_id=rule_id,
                        scanner="graphql-security",
                        confidence="medium",
                    )
                )
        if path.suffix.lower() in (".graphql", ".gql") and len(text) > 20:
            findings.append(
                ScanFinding(
                    category="security",
                    severity="low",
                    title=f"GraphQL schema file committed — {rel}",
                    description="A `.graphql` / `.gql` schema file is present in the repository.",
                    impact="Attackers can map your API surface without introspection.",
                    fix_recommendation="Avoid committing full schemas; generate types in CI instead.",
                    file_path=rel,
                    line_start=0,
                    line_end=0,
                    rule_id="graphql-schema-in-repo",
                    scanner="graphql-security",
                    confidence="high",
                )
            )
    return findings[:25]


def _discover_endpoints(base_url: str, extra: Iterable[str] | None) -> list[str]:
    parsed = urlparse(base_url if "://" in base_url else f"https://{base_url}")
    origin = f"{parsed.scheme}://{parsed.netloc}"
    candidates: list[str] = []

    for path in COMMON_GRAPHQL_PATHS:
        candidates.append(urljoin(origin + "/", path.lstrip("/")))

    if extra:
        for ep in extra:
            if ep.startswith("http"):
                candidates.append(ep)
            else:
                candidates.append(urljoin(origin + "/", ep.lstrip("/")))

    try:
        with httpx.Client(timeout=REQUEST_TIMEOUT, verify=False) as client:
            resp = client.get(origin, headers={"User-Agent": USER_AGENT})
            body = resp.text[:100_000]
            for match in re.finditer(r'["\'](/[^"\']*graphql[^"\']*)["\']', body, re.I):
                candidates.append(urljoin(origin, match.group(1)))
    except httpx.HTTPError:
        pass

    live: list[str] = []
    seen: set[str] = set()
    with httpx.Client(timeout=REQUEST_TIMEOUT, verify=False) as client:
        for url in candidates:
            if url in seen:
                continue
            seen.add(url)
            if _looks_like_graphql(client, url):
                live.append(url)
    return live


def _looks_like_graphql(client: httpx.Client, url: str) -> bool:
    headers = {"User-Agent": USER_AGENT, "Content-Type": "application/json"}
    try:
        resp = client.post(
            url,
            headers=headers,
            json={"query": "{ __typename }"},
        )
        if resp.status_code in (200, 400) and (
            "graphql" in (resp.headers.get("content-type") or "").lower()
            or "errors" in resp.text.lower()
            or "__typename" in resp.text
            or "data" in resp.text
        ):
            return True
        get_resp = client.get(url, params={"query": "{__typename}"}, headers={"User-Agent": USER_AGENT})
        return get_resp.status_code == 200 and ("data" in get_resp.text or "errors" in get_resp.text)
    except httpx.HTTPError:
        return False


def _probe_endpoint(
    client: httpx.Client,
    endpoint: str,
    auth_basic: tuple[str, str] | None,
) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    post_kw: dict = {}
    if auth_basic:
        post_kw["auth"] = auth_basic

    # Introspection
    resp = client.post(
        endpoint,
        json={"query": INTROSPECTION_QUERY},
        headers={"Content-Type": "application/json"},
        **post_kw,
    )
    body = resp.text[:50_000]
    introspection_hit = False
    if resp.status_code == 200:
        try:
            payload = resp.json()
            schema = (payload.get("data") or {}).get("__schema")
            if schema and (schema.get("types") or schema.get("queryType")):
                introspection_hit = True
        except (json.JSONDecodeError, TypeError, AttributeError):
            introspection_hit = '"__schema"' in body and '"types"' in body
    if introspection_hit:
        findings.append(
            _finding(
                rule_id="graphql-introspection-enabled",
                severity="high",
                title=f"GraphQL introspection enabled — {endpoint}",
                description="Full `__schema` introspection query returned type data.",
                impact="Attackers can dump the entire API schema, mutations, and sensitive fields.",
                fix_recommendation="Disable introspection in production (Apollo: introspection: false).",
                file_path=endpoint,
            )
        )

    # Playground / GraphiQL UI
    ui_resp = client.get(endpoint, headers={"User-Agent": USER_AGENT, "Accept": "text/html"}, **post_kw)
    if PLAYGROUND_MARKERS.search(ui_resp.text[:30_000]):
        findings.append(
            _finding(
                rule_id="graphql-playground-exposed",
                severity="medium",
                title=f"GraphQL IDE / Playground exposed — {endpoint}",
                description="Response contains GraphiQL, Voyager, or Playground markers.",
                impact="Interactive schema explorer lowers the bar for attacker reconnaissance.",
                fix_recommendation="Disable GraphQL playground in production builds.",
                file_path=endpoint,
            )
        )

    # Field suggestion leak
    suggest = client.post(
        endpoint,
        json={"query": FIELD_SUGGESTION_QUERY},
        headers={"Content-Type": "application/json"},
        **post_kw,
    )
    if FIELD_SUGGESTION_PATTERN.search(suggest.text[:10_000]):
        findings.append(
            _finding(
                rule_id="graphql-field-suggestion-leak",
                severity="medium",
                title=f"GraphQL field suggestions leak schema — {endpoint}",
                description="Invalid field query returned suggestion text (\"Did you mean ...\").",
                impact="Partial schema disclosure even when introspection is disabled.",
                fix_recommendation="Disable field suggestions in production error formatting.",
                file_path=endpoint,
            )
        )

    # GET transport (CSRF)
    get_resp = client.get(
        endpoint,
        params={"query": MINIMAL_INTROSPECTION},
        headers={"User-Agent": USER_AGENT},
        **post_kw,
    )
    if get_resp.status_code == 200 and ("data" in get_resp.text or "__schema" in get_resp.text):
        findings.append(
            _finding(
                rule_id="graphql-get-enabled",
                severity="medium",
                title=f"GraphQL accepts GET queries — {endpoint}",
                description="Schema/query data returned via HTTP GET — CSRF and cache poisoning risk.",
                impact="Cross-site request forgery can trigger state-changing queries if mutations allow GET.",
                fix_recommendation="Accept POST only; enable CSRF tokens for cookie-authenticated GraphQL.",
                file_path=endpoint,
            )
        )

    # Batched queries
    batch_body = [
        {"query": "{ __typename }"},
        {"query": "{ __typename }"},
    ]
    batch_resp = client.post(
        endpoint,
        json=batch_body,
        headers={"Content-Type": "application/json"},
        **post_kw,
    )
    if batch_resp.status_code == 200 and batch_resp.text.strip().startswith("["):
        findings.append(
            _finding(
                rule_id="graphql-batching-enabled",
                severity="low",
                title=f"GraphQL query batching accepted — {endpoint}",
                description="Server accepted an array of queries in one HTTP request.",
                impact="Batching can amplify brute-force or auth-bypass attempts in a single round-trip.",
                fix_recommendation="Limit batch size or require authentication for batched requests.",
                file_path=endpoint,
            )
        )

    # Alias depth (light DoS indicator)
    aliases = " ".join(f"a{i}: __typename" for i in range(12))
    deep_query = f"query {{ {aliases} }}"
    t0 = time.monotonic()
    deep_resp = client.post(
        endpoint,
        json={"query": deep_query},
        headers={"Content-Type": "application/json"},
        **post_kw,
    )
    elapsed = time.monotonic() - t0
    if deep_resp.status_code == 200 and elapsed > 2.0 and '"data"' in deep_resp.text:
        findings.append(
            _finding(
                rule_id="graphql-deep-query-accepted",
                severity="medium",
                title=f"GraphQL accepts deep aliased queries — {endpoint}",
                description=f"12-alias query completed in {elapsed:.1f}s without rejection.",
                impact="Attackers can craft deeply nested queries to cause denial of service.",
                fix_recommendation="Enforce query depth/complexity limits (maxDepth, maxAliases, cost analysis).",
                file_path=endpoint,
                metadata={"elapsed_s": round(elapsed, 2)},
            )
        )

    return findings


def _build_auth(auth: dict | None) -> tuple[dict, tuple[str, str] | None, dict]:
    headers = {"User-Agent": USER_AGENT}
    cookies: dict = {}
    auth_basic = None
    if not auth:
        return headers, auth_basic, cookies
    auth_type = (auth.get("type") or "").lower()
    if auth_type == "bearer" and auth.get("token"):
        headers["Authorization"] = f"Bearer {auth['token']}"
    elif auth_type == "basic":
        auth_basic = (auth.get("username", ""), auth.get("password", ""))
    elif auth_type == "cookie" and auth.get("cookies"):
        for line in str(auth["cookies"]).split(";"):
            if "=" in line:
                k, v = line.split("=", 1)
                cookies[k.strip()] = v.strip()
    elif auth_type == "header" and auth.get("header_name"):
        headers[str(auth["header_name"])] = str(auth.get("header_value", ""))
    return headers, auth_basic, cookies


def _finding(
    *,
    rule_id: str,
    severity: str,
    title: str,
    description: str,
    impact: str,
    fix_recommendation: str,
    file_path: str,
    metadata: dict | None = None,
) -> ScanFinding:
    return ScanFinding(
        category="security",
        severity=severity,
        title=title,
        description=description,
        impact=impact,
        fix_recommendation=fix_recommendation,
        file_path=file_path,
        line_start=0,
        line_end=0,
        rule_id=rule_id,
        scanner="graphql-security",
        confidence="high",
        metadata=metadata or {},
    )
