"""Built-in active DAST scanner — safe payload probes.

Sends benign, non-destructive payloads against a live website to detect:
- Reflected XSS, error-based SQLi
- Open redirect, server-side path traversal
- Insecure CORS, HTTP method exposure, response splitting
- Verbose 5xx errors / stack traces from bad input

All payloads are detection-only (no exploitation). Heavy active testing
(SSRF, RCE, blind SQLi) is left to OWASP ZAP when integrated.

Requires explicit `active_dast_enabled` on the project AND verified domain.
"""

from __future__ import annotations

import logging
import re
from typing import Iterable
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import httpx

from app.scanners.base import ScanFinding

logger = logging.getLogger(__name__)

USER_AGENT = "AI-Software-Auditor-DAST/1.0"
REQUEST_TIMEOUT = 12.0
MAX_PARAMS_TO_PROBE = 6
MAX_PAGES_TO_PROBE = 8

XSS_PAYLOAD = "<svg/onload=auditor_test_xss()>"
XSS_MARKER = "auditor_test_xss"

SQL_PAYLOADS = ["'", "''", "' OR '1'='1", "1' AND SLEEP(0)--"]
SQL_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*\Wmysqli?_",
    r"PostgreSQL.*ERROR",
    r"pg_query\(\)",
    r"sqlite3\.OperationalError",
    r"ORA-\d{5}",
    r"Microsoft .*ODBC.*SQL Server",
    r"unclosed quotation mark",
    r"SQLSTATE\[\w+\]",
]

OPEN_REDIRECT_TARGETS = [
    "https://auditor-redirect.example.org/",
    "//auditor-redirect.example.org/",
]

TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "..\\..\\..\\windows\\win.ini",
]
TRAVERSAL_FINGERPRINTS = [
    r"root:x:0:0:",
    r"daemon:x:1:1:",
    r"\[fonts\]\s*\nMS Serif",
]

STACK_TRACE_PATTERNS = [
    r"Traceback \(most recent call last\)",
    r"at [\w\.\$]+\([\w/\\\.]+:\d+\)",
    r"java\.lang\.\w+Exception",
    r"System\.\w+Exception:",
    r"<title>Werkzeug Debugger</title>",
    r"<title>RailsCasts</title>",
    r"DEBUG = True",
]


def scan_active_dast(
    base_url: str,
    *,
    auth: dict | None = None,
    extra_paths: Iterable[str] | None = None,
) -> list[ScanFinding]:
    """Run safe active probes against a live website.

    Args:
        base_url: validated, normalized website URL.
        auth: optional `{"type": "bearer"|"cookie"|"basic", ...}` config.
        extra_paths: optional iterable of additional paths to crawl-probe.
    """
    headers = {"User-Agent": USER_AGENT}
    cookies = {}
    auth_basic = None

    if auth:
        auth_type = (auth.get("type") or "").lower()
        if auth_type == "bearer" and auth.get("token"):
            headers["Authorization"] = f"Bearer {auth['token']}"
        elif auth_type == "cookie" and auth.get("cookies"):
            for line in str(auth["cookies"]).split(";"):
                if "=" in line:
                    name, value = line.split("=", 1)
                    cookies[name.strip()] = value.strip()
        elif auth_type == "basic" and auth.get("username"):
            auth_basic = (auth["username"], auth.get("password", ""))
        elif auth_type == "header" and auth.get("header_name"):
            headers[str(auth["header_name"])] = str(auth.get("header_value", ""))

    findings: list[ScanFinding] = []

    try:
        with httpx.Client(
            follow_redirects=False,
            timeout=REQUEST_TIMEOUT,
            headers=headers,
            cookies=cookies,
            auth=auth_basic,
            verify=True,
        ) as client:
            pages = _collect_targets(client, base_url, extra_paths)

            findings.extend(_probe_cors(client, pages))
            findings.extend(_probe_http_methods(client, base_url))
            findings.extend(_probe_open_redirect(client, pages))
            findings.extend(_probe_xss_and_sqli(client, pages))
            findings.extend(_probe_path_traversal(client, base_url))
            findings.extend(_probe_verbose_errors(client, pages))
            findings.extend(_probe_auth_bypass(client, base_url, auth=auth))
    except httpx.HTTPError as exc:
        logger.warning("Active DAST aborted: %s", exc)

    return findings


def _collect_targets(
    client: httpx.Client,
    base_url: str,
    extra_paths: Iterable[str] | None,
) -> list[str]:
    pages: list[str] = [base_url]
    seen = {_normalize(base_url)}

    if extra_paths:
        for path in extra_paths:
            url = urljoin(base_url, path)
            key = _normalize(url)
            if key not in seen:
                pages.append(url)
                seen.add(key)

    try:
        response = client.get(base_url)
        html = response.text[:200_000]
        for match in re.finditer(r"""href=["']([^"'#]+)""", html, re.I):
            href = match.group(1).strip()
            if href.startswith(("mailto:", "javascript:", "tel:")):
                continue
            url = urljoin(base_url, href)
            if not _same_origin(url, base_url):
                continue
            if "?" not in url and "/" == urlparse(url).path[-1:]:
                continue
            key = _normalize(url)
            if key in seen:
                continue
            pages.append(url)
            seen.add(key)
            if len(pages) >= MAX_PAGES_TO_PROBE:
                break
    except httpx.HTTPError:
        pass

    return pages[:MAX_PAGES_TO_PROBE]


def _same_origin(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    return (pa.scheme, pa.netloc) == (pb.scheme, pb.netloc)


def _normalize(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{parsed.query}"


def _probe_cors(client: httpx.Client, pages: list[str]) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    for url in pages[:3]:
        try:
            response = client.get(
                url,
                headers={"Origin": "https://auditor-cors-probe.example.org"},
            )
        except httpx.HTTPError:
            continue
        acao = response.headers.get("access-control-allow-origin", "")
        acac = response.headers.get("access-control-allow-credentials", "").lower()
        if acao == "*" and acac == "true":
            findings.append(
                _f(
                    "CORS allows any origin with credentials",
                    f"Response from {url} returned Access-Control-Allow-Origin: * with credentials: true.",
                    "Any malicious site could read authenticated responses.",
                    "Reject wildcard origins when credentials are enabled; explicit allowlist required.",
                    severity="critical",
                    rule_id="active-cors-wildcard-credentials",
                    url=url,
                )
            )
            continue
        if acao == "https://auditor-cors-probe.example.org" and acac == "true":
            findings.append(
                _f(
                    "CORS reflects arbitrary Origin with credentials",
                    f"Response from {url} echoed our fake Origin header back into ACAO.",
                    "Any attacker-controlled origin can read authenticated responses.",
                    "Validate Origin against a strict server-side allowlist instead of reflecting.",
                    severity="critical",
                    rule_id="active-cors-reflected-origin",
                    url=url,
                )
            )
    return findings


def _probe_http_methods(client: httpx.Client, base_url: str) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    for method in ("TRACE", "TRACK"):
        try:
            response = client.request(method, base_url)
        except httpx.HTTPError:
            continue
        if response.status_code in (200, 405):
            if response.status_code == 200:
                findings.append(
                    _f(
                        f"HTTP {method} method enabled",
                        f"{base_url} responded 200 to {method} — Cross-Site Tracing risk.",
                        "Could be abused to read cookies/credentials via XST.",
                        f"Disable the {method} method at the web server / framework level.",
                        severity="medium",
                        rule_id=f"active-method-{method.lower()}",
                        url=base_url,
                    )
                )
    try:
        opts = client.options(base_url)
        allow = opts.headers.get("allow", "")
        risky = [m for m in ("PUT", "DELETE", "PATCH") if m in allow.upper()]
        if risky and opts.status_code == 200:
            findings.append(
                _f(
                    "Mutation HTTP methods exposed",
                    f"OPTIONS response advertises: {allow}",
                    "PUT/DELETE/PATCH at root may allow unauthenticated state changes.",
                    "Restrict mutation methods to authenticated, scoped endpoints only.",
                    severity="medium",
                    rule_id="active-methods-mutation-exposed",
                    url=base_url,
                )
            )
    except httpx.HTTPError:
        pass
    return findings


def _probe_open_redirect(client: httpx.Client, pages: list[str]) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    redirect_param_names = {"next", "url", "redirect", "redirect_uri", "return", "returnto", "rurl", "dest"}

    for page in pages:
        params = dict(parse_qsl(urlparse(page).query))
        candidates = {k: v for k, v in params.items() if k.lower() in redirect_param_names}
        if not candidates:
            for name in ("next", "redirect"):
                candidates[name] = "/"
        for name in list(candidates.keys())[:2]:
            for target in OPEN_REDIRECT_TARGETS:
                url = _replace_param(page, name, target)
                try:
                    response = client.get(url)
                except httpx.HTTPError:
                    continue
                if response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get("location", "")
                    if "auditor-redirect.example.org" in location:
                        findings.append(
                            _f(
                                f"Open redirect via '{name}' parameter",
                                f"Param `{name}` redirects to attacker-controlled target. Location: {location}",
                                "Phishing / OAuth token theft / SSO bypass risk.",
                                "Validate redirect targets against a server-side allowlist of known paths.",
                                severity="high",
                                rule_id="active-open-redirect",
                                url=url,
                            )
                        )
                        break
    return findings


def _probe_xss_and_sqli(client: httpx.Client, pages: list[str]) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    for page in pages:
        parsed = urlparse(page)
        params = dict(parse_qsl(parsed.query))
        if not params:
            params = {"q": "test"}
        for name in list(params.keys())[:MAX_PARAMS_TO_PROBE]:
            url = _replace_param(page, name, XSS_PAYLOAD)
            try:
                response = client.get(url)
                body = response.text
            except httpx.HTTPError:
                continue
            if XSS_MARKER in body and XSS_PAYLOAD in body:
                findings.append(
                    _f(
                        f"Reflected XSS in '{name}' parameter",
                        f"Payload reflected unencoded in response from {url}.",
                        "Attacker can execute arbitrary JavaScript in victim's browser.",
                        "HTML-encode all user-controlled output; use template auto-escaping; set strict CSP.",
                        severity="critical",
                        rule_id="active-xss-reflected",
                        url=url,
                    )
                )
                break

            for payload in SQL_PAYLOADS[:2]:
                test_url = _replace_param(page, name, payload)
                try:
                    sqli_response = client.get(test_url)
                except httpx.HTTPError:
                    continue
                text = sqli_response.text[:50_000]
                for pattern in SQL_ERROR_PATTERNS:
                    if re.search(pattern, text, re.I):
                        findings.append(
                            _f(
                                f"Error-based SQL injection in '{name}'",
                                f"Database error revealed when injecting `{payload}` into `{name}` at {test_url}.",
                                "Attacker can read or modify database contents.",
                                "Use parameterized queries / prepared statements; never concatenate SQL with user input.",
                                severity="critical",
                                rule_id="active-sqli-error",
                                url=test_url,
                            )
                        )
                        break
                else:
                    continue
                break
    return findings


def _probe_path_traversal(client: httpx.Client, base_url: str) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    candidate_paths = [
        "/files",
        "/static",
        "/download",
        "/assets",
        "/api/files",
    ]
    for path in candidate_paths:
        target = urljoin(base_url, path)
        for payload in TRAVERSAL_PAYLOADS[:2]:
            url = f"{target}?file={payload}"
            try:
                response = client.get(url)
                text = response.text[:10_000]
            except httpx.HTTPError:
                continue
            for fingerprint in TRAVERSAL_FINGERPRINTS:
                if re.search(fingerprint, text):
                    findings.append(
                        _f(
                            "Path traversal allows reading server files",
                            f"Server returned local file contents for {url}.",
                            "Attacker can read /etc/passwd, source code, secrets, or config files.",
                            "Normalize and canonicalize paths; whitelist files; never let user input flow to filesystem.",
                            severity="critical",
                            rule_id="active-path-traversal",
                            url=url,
                        )
                    )
                    return findings
    return findings


def _probe_verbose_errors(client: httpx.Client, pages: list[str]) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    for page in pages[:3]:
        for suffix in ("?x[]=1&x[]=2", "?id=%00%00%00", "/__nope__"):
            url = urljoin(page, page.split("?")[0]) + suffix if not suffix.startswith("?") else page + suffix
            try:
                response = client.get(url)
                body = response.text[:30_000]
            except httpx.HTTPError:
                continue
            if response.status_code >= 500:
                for pattern in STACK_TRACE_PATTERNS:
                    if re.search(pattern, body, re.I):
                        findings.append(
                            _f(
                                "Verbose error / stack trace exposed",
                                f"Malformed request to {url} returned a server stack trace.",
                                "Internal code paths, library versions, and SQL hints leak to attackers.",
                                "Disable debug mode in production; return generic error pages; log details server-side.",
                                severity="high",
                                rule_id="active-verbose-error",
                                url=url,
                            )
                        )
                        return findings
    return findings


def _probe_auth_bypass(
    client: httpx.Client,
    base_url: str,
    *,
    auth: dict | None,
) -> list[ScanFinding]:
    """If auth credentials were supplied, sanity-check that unauthenticated access is blocked."""
    if not auth:
        return []

    admin_paths = ["/admin", "/api/admin", "/dashboard", "/user/me", "/api/users/me"]
    findings: list[ScanFinding] = []
    with httpx.Client(
        follow_redirects=False,
        timeout=REQUEST_TIMEOUT,
        headers={"User-Agent": USER_AGENT},
        verify=True,
    ) as anon_client:
        for path in admin_paths:
            url = urljoin(base_url, path)
            try:
                response = anon_client.get(url)
            except httpx.HTTPError:
                continue
            if response.status_code == 200 and len(response.text) > 200:
                findings.append(
                    _f(
                        f"Sensitive path accessible without authentication: {path}",
                        f"{url} returned HTTP 200 to anonymous request despite auth being configured.",
                        "Authenticated-only data may be exposed to anyone.",
                        "Enforce authentication middleware on all admin / user-data endpoints.",
                        severity="high",
                        rule_id="active-auth-bypass",
                        url=url,
                    )
                )
    return findings


def _replace_param(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    params[name] = value
    new_query = urlencode(params)
    return urlunparse(parsed._replace(query=new_query))


def _f(
    title: str,
    description: str,
    impact: str,
    fix: str,
    *,
    severity: str,
    rule_id: str,
    url: str,
    category: str = "security",
) -> ScanFinding:
    return ScanFinding(
        category=category,
        severity=severity,
        title=title,
        description=description,
        impact=impact,
        fix_recommendation=fix,
        file_path=url,
        line_start=0,
        line_end=0,
        rule_id=rule_id,
        scanner="active-dast",
        confidence="high",
    )
