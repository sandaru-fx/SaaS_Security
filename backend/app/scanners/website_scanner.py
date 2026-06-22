"""Passive live-website security scanner (DAST-lite).

Probes a deployed URL for security headers, TLS, cookies, exposed paths,
technology fingerprints, and information disclosure — without active exploitation.
"""

from __future__ import annotations

import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import httpx

from app.scanners.base import ScanFinding

USER_AGENT = "AI-Software-Auditor/1.0 (+https://github.com/sandaru-fx/SaaS_Security)"
REQUEST_TIMEOUT = 15.0
MAX_REDIRECTS = 5

SECURITY_HEADERS = {
    "strict-transport-security": {
        "title": "Missing Strict-Transport-Security (HSTS)",
        "severity": "high",
        "rule_id": "missing-hsts",
        "impact": "Browsers may connect over HTTP, enabling downgrade and MITM attacks.",
        "fix": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "content-security-policy": {
        "title": "Missing Content-Security-Policy (CSP)",
        "severity": "medium",
        "rule_id": "missing-csp",
        "impact": "No policy restricting script/style sources increases XSS blast radius.",
        "fix": "Define a Content-Security-Policy appropriate for your application.",
    },
    "x-frame-options": {
        "title": "Missing X-Frame-Options",
        "severity": "medium",
        "rule_id": "missing-x-frame-options",
        "impact": "Site may be embedded in iframes (clickjacking risk).",
        "fix": "Add X-Frame-Options: DENY or SAMEORIGIN, or use CSP frame-ancestors.",
    },
    "x-content-type-options": {
        "title": "Missing X-Content-Type-Options",
        "severity": "low",
        "rule_id": "missing-x-content-type-options",
        "impact": "Browsers may MIME-sniff responses, enabling content-type confusion attacks.",
        "fix": "Add X-Content-Type-Options: nosniff",
    },
    "referrer-policy": {
        "title": "Missing Referrer-Policy",
        "severity": "low",
        "rule_id": "missing-referrer-policy",
        "impact": "Full URLs may leak to third parties via Referer headers.",
        "fix": "Add Referrer-Policy: strict-origin-when-cross-origin (or stricter).",
    },
    "permissions-policy": {
        "title": "Missing Permissions-Policy",
        "severity": "low",
        "rule_id": "missing-permissions-policy",
        "impact": "Browser features (camera, mic, geolocation) are not restricted by policy.",
        "fix": "Add Permissions-Policy to disable unused browser capabilities.",
    },
}

# Also accept legacy header name
PERMISSIONS_POLICY_ALIASES = ("permissions-policy", "feature-policy")

EXPOSED_PATHS: list[tuple[str, str, str]] = [
    ("/.env", "critical", "Environment file may expose secrets and database credentials."),
    ("/.git/HEAD", "critical", "Git repository exposed — full source code may be downloadable."),
    ("/.git/config", "critical", "Git configuration exposed — repository metadata leak."),
    ("/wp-config.php.bak", "high", "WordPress backup config may contain database passwords."),
    ("/backup.zip", "high", "Backup archive may contain full application source and data."),
    ("/admin", "medium", "Admin panel reachable — ensure strong authentication and IP restrictions."),
    ("/phpinfo.php", "high", "PHP info page exposes server configuration and paths."),
    ("/server-status", "medium", "Server status page may reveal internal metrics and paths."),
    ("/.aws/credentials", "critical", "AWS credentials file may be publicly accessible."),
    ("/debug", "medium", "Debug endpoint may expose internal application state."),
    ("/api/docs", "low", "API documentation exposed — review for sensitive endpoint details."),
    ("/swagger", "low", "Swagger UI exposed — may reveal API surface area."),
]

TECH_SIGNATURES: list[tuple[str, str, str]] = [
    (r"wp-content|wordpress", "WordPress", "Popular CMS — keep plugins and core updated."),
    (r"drupal", "Drupal", "Drupal CMS detected — monitor security advisories."),
    (r"jquery[/-](\d+\.\d+)", "jQuery", "Check jQuery version for known CVEs."),
    (r"react(?:\.production)?\.min\.js", "React", "React SPA — review client-side secret handling."),
    (r"next\.js|__NEXT_DATA__", "Next.js", "Next.js application — verify SSR secrets are not leaked."),
    (r"laravel_session", "Laravel", "Laravel PHP framework detected."),
    (r"django", "Django", "Django application detected."),
]

INFO_LEAK_PATTERNS: list[tuple[str, str, str, str]] = [
    (r"traceback \(most recent call last\)", "Stack trace visible", "high", "stack-trace-exposed"),
    (r"SQL syntax.*MySQL|pg_query|sqlite3\.OperationalError", "Database error in response", "high", "db-error-exposed"),
    (r"Exception in thread|at [\w.]+\([\w/\\]+\.java", "Java exception in response", "medium", "java-exception-exposed"),
    (r"AWS_ACCESS_KEY_ID|AKIA[0-9A-Z]{16}", "AWS key in page content", "critical", "aws-key-in-page"),
]


def normalize_website_url(url: str) -> str:
    raw = url.strip()
    if not raw.startswith(("http://", "https://")):
        raw = f"https://{raw}"
    parsed = urlparse(raw)
    if not parsed.netloc:
        raise ValueError("Invalid website URL")
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError("Only http and https URLs are supported")
    path = parsed.path or "/"
    return f"{scheme}://{parsed.netloc}{path}"


def validate_website_url(url: str) -> None:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if not host:
        raise ValueError("Invalid website URL")
    blocked = ("localhost", "127.0.0.1", "0.0.0.0", "::1")
    if host in blocked or host.endswith(".local"):
        raise ValueError("Scanning localhost or local domains is not allowed")
    # Block private IP ranges (basic)
    if re.match(r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)", host):
        raise ValueError("Scanning private network addresses is not allowed")


def scan_website(url: str) -> list[ScanFinding]:
    """Run passive security checks against a live website URL."""
    normalized = normalize_website_url(url)
    validate_website_url(normalized)
    findings: list[ScanFinding] = []

    try:
        with httpx.Client(
            follow_redirects=True,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            verify=True,
        ) as client:
            response = client.get(normalized)
            final_url = str(response.url)
            findings.extend(_check_security_headers(response, final_url))
            findings.extend(_check_cookies(response, final_url))
            findings.extend(_check_server_disclosure(response, final_url))
            findings.extend(_check_tls(final_url))
            findings.extend(_check_mixed_content(response, final_url))
            findings.extend(_check_html_signals(response.text, final_url))
            findings.extend(_probe_exposed_paths(client, final_url))
    except httpx.HTTPError as exc:
        findings.append(
            ScanFinding(
                category="security",
                severity="high",
                title="Website unreachable",
                description=f"Could not fetch {normalized}: {exc}",
                impact="Audit could not complete — site may be down or blocking scanners.",
                fix_recommendation="Verify the URL is correct and publicly accessible.",
                file_path=normalized,
                line_start=0,
                line_end=0,
                rule_id="website-unreachable",
                scanner="website-security",
                confidence="high",
            )
        )
        return findings

    return findings


def _finding(
    *,
    title: str,
    description: str,
    impact: str,
    fix: str,
    severity: str,
    rule_id: str,
    url: str,
    path: str = "/",
    confidence: str = "high",
    category: str = "security",
) -> ScanFinding:
    return ScanFinding(
        category=category,
        severity=severity,
        title=title,
        description=description,
        impact=impact,
        fix_recommendation=fix,
        file_path=f"{url}{path}" if path != "/" else url,
        line_start=0,
        line_end=0,
        rule_id=rule_id,
        scanner="website-security",
        confidence=confidence,
    )


def _check_security_headers(response: httpx.Response, url: str) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    headers_lower = {k.lower(): v for k, v in response.headers.items()}
    parsed = urlparse(url)

    for header, meta in SECURITY_HEADERS.items():
        if header == "permissions-policy":
            if any(h in headers_lower for h in PERMISSIONS_POLICY_ALIASES):
                continue
        elif header in headers_lower:
            continue
        if header == "strict-transport-security" and parsed.scheme != "https":
            continue
        findings.append(
            _finding(
                title=meta["title"],
                description=f"Response from {url} does not include the {header} header.",
                impact=meta["impact"],
                fix=meta["fix"],
                severity=meta["severity"],
                rule_id=meta["rule_id"],
                url=url,
            )
        )

    csp = headers_lower.get("content-security-policy", "")
    if csp and "'unsafe-inline'" in csp and "'unsafe-eval'" in csp:
        findings.append(
            _finding(
                title="Weak Content-Security-Policy",
                description="CSP allows both unsafe-inline and unsafe-eval.",
                impact="XSS protections are significantly weakened.",
                fix="Remove unsafe-inline and unsafe-eval; use nonces or hashes.",
                severity="medium",
                rule_id="weak-csp",
                url=url,
            )
        )

    return findings


def _check_cookies(response: httpx.Response, url: str) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    parsed = urlparse(url)
    is_https = parsed.scheme == "https"

    for cookie_header in response.headers.get_list("set-cookie"):
        name = cookie_header.split("=", 1)[0].strip()
        lower = cookie_header.lower()
        if is_https and "secure" not in lower:
            findings.append(
                _finding(
                    title=f"Cookie '{name}' missing Secure flag",
                    description=f"Set-Cookie for {name} does not include Secure on HTTPS.",
                    impact="Cookie may be sent over unencrypted HTTP connections.",
                    fix="Add Secure attribute to sensitive cookies.",
                    severity="medium",
                    rule_id="cookie-missing-secure",
                    url=url,
                )
            )
        if "httponly" not in lower:
            findings.append(
                _finding(
                    title=f"Cookie '{name}' missing HttpOnly flag",
                    description=f"Cookie {name} is accessible to JavaScript (no HttpOnly).",
                    impact="Session cookies are vulnerable to theft via XSS.",
                    fix="Add HttpOnly to session and authentication cookies.",
                    severity="medium",
                    rule_id="cookie-missing-httponly",
                    url=url,
                )
            )
        if "samesite" not in lower:
            findings.append(
                _finding(
                    title=f"Cookie '{name}' missing SameSite attribute",
                    description=f"Cookie {name} has no SameSite policy.",
                    impact="Increased CSRF risk for state-changing requests.",
                    fix="Set SameSite=Lax or Strict on cookies.",
                    severity="low",
                    rule_id="cookie-missing-samesite",
                    url=url,
                )
            )
    return findings


def _check_server_disclosure(response: httpx.Response, url: str) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    server = response.headers.get("server", "")
    powered = response.headers.get("x-powered-by", "")
    if server and re.search(r"\d+\.\d+", server):
        findings.append(
            _finding(
                title="Server version disclosed",
                description=f"Server header reveals: {server}",
                impact="Attackers can target known vulnerabilities for this server version.",
                fix="Remove or genericize the Server header in production.",
                severity="low",
                rule_id="server-version-disclosure",
                url=url,
                confidence="high",
            )
        )
    if powered:
        findings.append(
            _finding(
                title="X-Powered-By header exposed",
                description=f"X-Powered-By: {powered}",
                impact="Technology stack disclosure aids targeted attacks.",
                fix="Disable X-Powered-By in your framework or reverse proxy.",
                severity="low",
                rule_id="x-powered-by-disclosure",
                url=url,
            )
        )
    return findings


def _check_tls(url: str) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    parsed = urlparse(url)
    if parsed.scheme != "https":
        findings.append(
            _finding(
                title="Site not served over HTTPS",
                description=f"{url} uses HTTP without TLS encryption.",
                impact="Traffic including credentials can be intercepted in transit.",
                fix="Enforce HTTPS with a valid TLS certificate and redirect HTTP to HTTPS.",
                severity="high",
                rule_id="no-https",
                url=url,
                category="devops",
            )
        )
        return findings

    host = parsed.hostname
    port = parsed.port or 443
    if not host:
        return findings

    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        if cert:
            not_after = cert.get("notAfter")
            if not_after:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=timezone.utc
                )
                days_left = (expiry - datetime.now(timezone.utc)).days
                if days_left < 0:
                    findings.append(
                        _finding(
                            title="TLS certificate expired",
                            description=f"Certificate expired on {not_after}.",
                            impact="Browsers will show security warnings; users may not trust the site.",
                            fix="Renew the TLS certificate immediately.",
                            severity="critical",
                            rule_id="tls-cert-expired",
                            url=url,
                            category="devops",
                        )
                    )
                elif days_left < 30:
                    findings.append(
                        _finding(
                            title="TLS certificate expiring soon",
                            description=f"Certificate expires in {days_left} days ({not_after}).",
                            impact="Unexpected expiry causes outage and trust warnings.",
                            fix="Renew the certificate before expiry.",
                            severity="medium",
                            rule_id="tls-cert-expiring",
                            url=url,
                            category="devops",
                        )
                    )
    except ssl.SSLError as exc:
        findings.append(
            _finding(
                title="TLS certificate problem",
                description=f"SSL error for {host}: {exc}",
                impact="Users may see browser security warnings.",
                fix="Install a valid certificate from a trusted CA.",
                severity="high",
                rule_id="tls-cert-invalid",
                url=url,
                category="devops",
            )
        )
    except OSError:
        pass
    return findings


def _check_mixed_content(response: httpx.Response, url: str) -> list[ScanFinding]:
    if urlparse(url).scheme != "https":
        return []
    body = response.text[:100_000]
    matches = re.findall(r"""<(script|img|iframe)[^>]+src=["']http://[^"']+""", body, re.I)
    if matches:
        return [
            _finding(
                title="Mixed content detected",
                description=f"HTTPS page loads {len(matches)} resource(s) over insecure HTTP.",
                impact="Mixed content can be modified in transit and weakens page security.",
                fix="Serve all assets over HTTPS or use protocol-relative URLs.",
                severity="medium",
                rule_id="mixed-content",
                url=url,
                category="quality",
            )
        ]
    return []


def _check_html_signals(html: str, url: str) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    sample = html[:150_000]

    for pattern, label, note in TECH_SIGNATURES:
        if re.search(pattern, sample, re.I):
            findings.append(
                _finding(
                    title=f"Technology detected: {label}",
                    description=f"Page content indicates {label} is in use. {note}",
                    impact="Known CVEs may affect this stack — keep dependencies patched.",
                    fix=f"Monitor security advisories for {label} and apply updates.",
                    severity="low",
                    rule_id=f"tech-{label.lower().replace('.', '')}",
                    url=url,
                    confidence="medium",
                )
            )

    for pattern, title, severity, rule_id in INFO_LEAK_PATTERNS:
        if re.search(pattern, sample, re.I):
            findings.append(
                _finding(
                    title=title,
                    description=f"Sensitive pattern found in public page content at {url}.",
                    impact="Internal errors or secrets may be visible to attackers.",
                    fix="Disable debug mode in production and use custom error pages.",
                    severity=severity,
                    rule_id=rule_id,
                    url=url,
                )
            )

    return findings


def _probe_exposed_paths(client: httpx.Client, base_url: str) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    base = base_url.rstrip("/") + "/"

    for path, severity, impact in EXPOSED_PATHS:
        target = urljoin(base, path.lstrip("/"))
        try:
            resp = client.head(target, timeout=8.0)
            if resp.status_code == 405:
                resp = client.get(target, timeout=8.0)
            if resp.status_code in (200, 403):
                title = f"Sensitive path accessible: {path}"
                if resp.status_code == 403:
                    title = f"Sensitive path exists (403): {path}"
                    severity = "low" if severity == "medium" else severity
                findings.append(
                    _finding(
                        title=title,
                        description=f"{target} returned HTTP {resp.status_code}.",
                        impact=impact,
                        fix=f"Block public access to {path} at the web server or application layer.",
                        severity=severity,
                        rule_id=f"exposed-path-{path.strip('/').replace('/', '-')}",
                        url=base_url,
                        path=path,
                        confidence="high" if resp.status_code == 200 else "medium",
                    )
                )
        except httpx.HTTPError:
            continue
    return findings
