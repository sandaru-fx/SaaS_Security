"""Attack Surface Management (ASM) + Recon Engine.

Discovers the external attack surface of a target domain:
- Subdomain enumeration via Certificate Transparency (crt.sh) + DNS bruteforce
- DNS hygiene (SPF / DMARC / DKIM, dangling-CNAME takeover candidates)
- TLS / certificate hygiene (expiry, weak protocols, hostname mismatch)
- HTTP fingerprinting (server / framework / CMS) + exposed admin panel probing
- Returns the discovered subdomains so the scan runner can feed them
  into the existing Active DAST queue.

Only performs read-only HTTPS GETs + DNS lookups. Rate-limited and
capped to keep runtime bounded for the SaaS backend.
"""

from __future__ import annotations

import logging
import re
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable
from urllib.parse import urlparse

import dns.resolver
import httpx

from app.scanners.base import ScanFinding

logger = logging.getLogger(__name__)

USER_AGENT = "AI-Software-Auditor-ASM/1.0"
HTTP_TIMEOUT = 8.0
DNS_TIMEOUT = 4.0
MAX_SUBDOMAINS = 200
MAX_PROBE_HOSTS = 60
MAX_ADMIN_PATHS_PER_HOST = 20
CT_LOG_URL = "https://crt.sh/?q=%25.{domain}&output=json"

DNS_WORDLIST = [
    "www", "api", "dev", "staging", "stage", "test", "qa", "uat", "prod",
    "admin", "portal", "dashboard", "app", "web", "mobile", "m",
    "mail", "smtp", "imap", "webmail", "exchange", "owa", "autodiscover",
    "vpn", "ssh", "ftp", "sftp", "git", "gitlab", "github", "bitbucket",
    "jira", "confluence", "wiki", "docs", "support", "help", "kb",
    "blog", "news", "shop", "store", "checkout", "billing", "pay", "payments",
    "auth", "sso", "login", "id", "account", "accounts", "user", "users",
    "internal", "intranet", "extranet", "office", "remote",
    "ci", "cd", "build", "jenkins", "drone", "argocd",
    "monitor", "monitoring", "grafana", "kibana", "prometheus", "metrics", "logs",
    "elasticsearch", "elastic", "kafka", "redis", "mongo", "db", "database", "sql",
    "s3", "cdn", "static", "assets", "media", "images", "img", "files", "upload",
    "demo", "sandbox", "old", "legacy", "beta", "alpha", "preview",
    "secure", "private", "client", "customer", "partners",
    "api-v1", "api-v2", "v1", "v2", "graphql", "rest",
    "webhook", "webhooks", "callback", "oauth",
    "status", "health", "ping",
]

ADMIN_PATHS = [
    ("/admin/", "Admin panel"),
    ("/admin/login", "Admin panel"),
    ("/administrator/", "Joomla admin"),
    ("/wp-admin/", "WordPress admin"),
    ("/wp-login.php", "WordPress login"),
    ("/phpmyadmin/", "phpMyAdmin"),
    ("/pma/", "phpMyAdmin"),
    ("/myadmin/", "phpMyAdmin"),
    ("/manager/html", "Tomcat manager"),
    ("/jmx-console/", "JBoss JMX console"),
    ("/jenkins/", "Jenkins"),
    ("/jenkins/login", "Jenkins"),
    ("/grafana/login", "Grafana"),
    ("/kibana/app/", "Kibana"),
    ("/_cat/indices", "Elasticsearch"),
    ("/_status", "Elasticsearch"),
    ("/.git/config", "Exposed .git directory"),
    ("/.git/HEAD", "Exposed .git directory"),
    ("/.env", "Exposed .env"),
    ("/.env.local", "Exposed .env"),
    ("/.aws/credentials", "Exposed AWS credentials"),
    ("/.npmrc", "Exposed .npmrc"),
    ("/.DS_Store", "Exposed .DS_Store"),
    ("/server-status", "Apache server-status"),
    ("/server-info", "Apache server-info"),
    ("/actuator/env", "Spring Actuator env"),
    ("/actuator/health", "Spring Actuator"),
    ("/swagger-ui/", "Swagger UI"),
    ("/swagger-ui.html", "Swagger UI"),
    ("/api-docs", "API docs"),
    ("/graphql", "GraphQL endpoint"),
    ("/.well-known/security.txt", "security.txt (info)"),
]

# CNAME suffix -> (service, fingerprint regex if body required, severity)
TAKEOVER_SIGNATURES: list[tuple[str, re.Pattern[str] | None]] = [
    (".s3.amazonaws.com", re.compile(r"NoSuchBucket", re.I)),
    (".s3-website", re.compile(r"NoSuchBucket", re.I)),
    (".cloudfront.net", re.compile(r"ERROR: The request could not be satisfied", re.I)),
    (".github.io", re.compile(r"There isn't a GitHub Pages site here", re.I)),
    (".herokuapp.com", re.compile(r"No such app", re.I)),
    (".herokussl.com", re.compile(r"No such app", re.I)),
    (".azurewebsites.net", re.compile(r"404 Web Site not found", re.I)),
    (".cloudapp.net", re.compile(r"<title>Page not found", re.I)),
    (".trafficmanager.net", re.compile(r"<title>Page not found", re.I)),
    (".fastly.net", re.compile(r"Fastly error: unknown domain", re.I)),
    (".surge.sh", re.compile(r"project not found", re.I)),
    (".wordpress.com", re.compile(r"Do you want to register", re.I)),
    (".readme.io", re.compile(r"Project doesnt exist", re.I)),
    (".bitbucket.io", re.compile(r"Repository not found", re.I)),
    (".helpjuice.com", re.compile(r"We could not find what you'?re looking for", re.I)),
    (".helpscoutdocs.com", re.compile(r"No settings were found for this company", re.I)),
    (".ghost.io", re.compile(r"The thing you were looking for", re.I)),
    (".pantheonsite.io", re.compile(r"The gods are wise", re.I)),
    (".tumblr.com", re.compile(r"Whatever you were looking for doesn't currently exist", re.I)),
    (".netlify.app", re.compile(r"Not Found - Request ID", re.I)),
    (".vercel.app", re.compile(r"DEPLOYMENT_NOT_FOUND", re.I)),
]

FINGERPRINT_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("WordPress", re.compile(r'<meta name="generator" content="WordPress ([\d.]+)', re.I), "high-risk"),
    ("Drupal", re.compile(r'<meta name="Generator" content="Drupal (\d+)', re.I), "high-risk"),
    ("Joomla", re.compile(r'<meta name="generator" content="Joomla! ([\d.]+)', re.I), "high-risk"),
    ("phpMyAdmin", re.compile(r"phpMyAdmin", re.I), "high-risk"),
    ("Jenkins", re.compile(r"<title>Dashboard \[Jenkins\]", re.I), "high-risk"),
    ("Grafana", re.compile(r"Grafana", re.I), "info"),
    ("Kibana", re.compile(r"<title>Kibana", re.I), "high-risk"),
    ("Spring Boot", re.compile(r"Whitelabel Error Page", re.I), "info"),
]


@dataclass
class AsmDiscovery:
    """Discovered assets returned to the scan runner."""
    subdomains: list[str]
    live_hosts: list[str]


def scan_asm(
    root_url_or_domain: str,
    *,
    feed_active_dast: bool = True,
) -> tuple[list[ScanFinding], AsmDiscovery]:
    """Run full ASM + recon against a root domain.

    Args:
        root_url_or_domain: e.g. "https://acme.io" or "acme.io"
        feed_active_dast: when True, live hosts are returned to be appended
                          to the Active DAST queue by the scan runner.
    """
    domain = _extract_domain(root_url_or_domain)
    findings: list[ScanFinding] = []
    if not domain:
        return findings, AsmDiscovery(subdomains=[], live_hosts=[])

    logger.info("[ASM] starting recon for %s", domain)

    findings.extend(_check_dns_hygiene(domain))

    subdomains = _enumerate_subdomains(domain)
    live_hosts = _probe_live_hosts(subdomains)

    findings.extend(_check_takeovers(subdomains))
    findings.extend(_check_tls_for_hosts(live_hosts))
    findings.extend(_fingerprint_hosts(live_hosts))
    findings.extend(_probe_admin_panels(live_hosts))

    findings.append(
        ScanFinding(
            category="security",
            severity="low",
            title=f"Attack surface mapped: {len(subdomains)} subdomains, {len(live_hosts)} live",
            description=(
                f"Discovered {len(subdomains)} subdomains via CT logs + DNS, "
                f"{len(live_hosts)} responded on HTTPS/HTTP. "
                "Review the Attack Surface panel for the full asset inventory."
            ),
            impact="Visibility into exposed infrastructure attackers see during reconnaissance.",
            fix_recommendation=(
                "Decommission unused subdomains, restrict staging/internal hosts "
                "behind a VPN, and add CAA records to limit cert issuance."
            ),
            file_path=f"asm://{domain}",
            line_start=0,
            line_end=0,
            rule_id="asm-surface-summary",
            scanner="asm",
            confidence="high",
            metadata={
                "domain": domain,
                "subdomain_count": len(subdomains),
                "live_host_count": len(live_hosts),
                "subdomains_preview": subdomains[:20],
                "live_hosts_preview": live_hosts[:20],
                "asm_summary": True,
            },
        )
    )

    return findings, AsmDiscovery(
        subdomains=subdomains,
        live_hosts=live_hosts if feed_active_dast else [],
    )


def _extract_domain(value: str) -> str:
    raw = (value or "").strip().lower()
    if not raw:
        return ""
    if "://" in raw:
        raw = urlparse(raw).hostname or ""
    raw = raw.strip(".")
    if raw.startswith("www."):
        raw = raw[4:]
    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", raw):
        return ""
    return raw


def _enumerate_subdomains(domain: str) -> list[str]:
    found: set[str] = {domain}
    found.update(_subdomains_from_ct(domain))
    if len(found) < MAX_SUBDOMAINS:
        found.update(_subdomains_from_dns_wordlist(domain))
    cleaned = sorted(
        {h for h in found if h.endswith(domain) and "*" not in h and " " not in h}
    )
    return cleaned[:MAX_SUBDOMAINS]


def _subdomains_from_ct(domain: str) -> Iterable[str]:
    url = CT_LOG_URL.format(domain=domain)
    try:
        with httpx.Client(timeout=HTTP_TIMEOUT, headers={"User-Agent": USER_AGENT}) as client:
            resp = client.get(url)
        if resp.status_code != 200:
            return []
        try:
            data = resp.json()
        except Exception:
            return []
    except httpx.HTTPError as exc:
        logger.debug("[ASM] crt.sh failed for %s: %s", domain, exc)
        return []

    hosts: set[str] = set()
    for row in data if isinstance(data, list) else []:
        name = (row.get("name_value") or "").lower()
        for line in name.split("\n"):
            line = line.strip().strip(".")
            if line and "." in line:
                hosts.add(line)
    return hosts


def _subdomains_from_dns_wordlist(domain: str) -> Iterable[str]:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT
    resolver.timeout = DNS_TIMEOUT
    found: set[str] = set()
    for word in DNS_WORDLIST:
        host = f"{word}.{domain}"
        try:
            answers = resolver.resolve(host, "A")
            if list(answers):
                found.add(host)
        except Exception:
            continue
        if len(found) >= 60:
            break
    return found


def _probe_live_hosts(hosts: list[str]) -> list[str]:
    live: list[str] = []
    headers = {"User-Agent": USER_AGENT}
    with httpx.Client(
        timeout=HTTP_TIMEOUT,
        headers=headers,
        follow_redirects=True,
        verify=False,  # we probe TLS separately
    ) as client:
        for host in hosts[:MAX_PROBE_HOSTS]:
            for scheme in ("https", "http"):
                url = f"{scheme}://{host}"
                try:
                    resp = client.head(url)
                    if resp.status_code in (405, 501):
                        resp = client.get(url)
                    if resp.status_code < 500:
                        live.append(url)
                        break
                except httpx.HTTPError:
                    continue
    return live


def _check_dns_hygiene(domain: str) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    spf, dmarc = _lookup_email_security(domain)

    if not spf:
        findings.append(
            _finding(
                rule_id="asm-missing-spf",
                severity="medium",
                title=f"Missing SPF record for {domain}",
                description=(
                    "No `v=spf1 ...` TXT record was found on the apex domain. "
                    "Attackers can spoof emails from this domain."
                ),
                impact="Phishing campaigns can impersonate your domain; deliverability suffers.",
                fix_recommendation=(
                    "Publish a TXT record like `v=spf1 include:_spf.google.com -all` "
                    "with `-all` to hard-fail unauthorized senders."
                ),
                file_path=f"dns://{domain}",
            )
        )
    if not dmarc:
        findings.append(
            _finding(
                rule_id="asm-missing-dmarc",
                severity="medium",
                title=f"Missing DMARC record for {domain}",
                description=(
                    "No DMARC policy at `_dmarc.{0}`. Even with SPF/DKIM, "
                    "receivers won't know what to do with failures.".format(domain)
                ),
                impact="Email spoofing protection is incomplete without DMARC.",
                fix_recommendation=(
                    "Add a TXT record at `_dmarc.{0}` such as "
                    "`v=DMARC1; p=reject; rua=mailto:dmarc@{0}`".format(domain)
                ),
                file_path=f"dns://_dmarc.{domain}",
            )
        )
    elif "p=none" in dmarc.lower():
        findings.append(
            _finding(
                rule_id="asm-dmarc-policy-none",
                severity="low",
                title=f"DMARC policy is `p=none` for {domain}",
                description="DMARC is in monitor-only mode; spoofed mail is still delivered.",
                impact="Anti-spoofing protection is not actively enforced.",
                fix_recommendation="Tighten to `p=quarantine` and then `p=reject` after monitoring reports.",
                file_path=f"dns://_dmarc.{domain}",
            )
        )
    return findings


def _lookup_email_security(domain: str) -> tuple[str | None, str | None]:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT
    resolver.timeout = DNS_TIMEOUT
    spf = None
    dmarc = None
    try:
        for r in resolver.resolve(domain, "TXT"):
            for part in r.strings:
                text = part.decode("utf-8", errors="ignore")
                if text.lower().startswith("v=spf1"):
                    spf = text
                    break
    except Exception:
        pass
    try:
        for r in resolver.resolve(f"_dmarc.{domain}", "TXT"):
            for part in r.strings:
                text = part.decode("utf-8", errors="ignore")
                if text.lower().startswith("v=dmarc1"):
                    dmarc = text
                    break
    except Exception:
        pass
    return spf, dmarc


def _check_takeovers(subdomains: list[str]) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT
    resolver.timeout = DNS_TIMEOUT

    for host in subdomains[:MAX_PROBE_HOSTS]:
        cname = _resolve_cname(resolver, host)
        if not cname:
            continue
        for suffix, body_pattern in TAKEOVER_SIGNATURES:
            if suffix not in cname:
                continue
            confirmed = True
            body_text = ""
            if body_pattern:
                body_text = _fetch_body(f"https://{host}") or _fetch_body(f"http://{host}") or ""
                confirmed = bool(body_pattern.search(body_text))
            if confirmed:
                findings.append(
                    _finding(
                        rule_id="asm-subdomain-takeover",
                        severity="critical",
                        title=f"Possible subdomain takeover — {host} → {cname}",
                        description=(
                            f"{host} CNAMEs to `{cname}` which matches a known takeover-prone "
                            f"service ({suffix}). The target appears unclaimed."
                        ),
                        impact=(
                            "An attacker can register the orphaned resource and serve content under "
                            "your domain — cookie theft, phishing, OAuth hijack."
                        ),
                        fix_recommendation=(
                            "Remove the dangling DNS record or re-claim the resource at the provider. "
                            "Subscribe to DNS monitoring (e.g. dnstwist, statix) to catch regressions."
                        ),
                        file_path=f"dns://{host}",
                        metadata={"cname": cname, "service_pattern": suffix},
                    )
                )
                break
    return findings


def _resolve_cname(resolver: dns.resolver.Resolver, host: str) -> str | None:
    try:
        answers = resolver.resolve(host, "CNAME")
        for rdata in answers:
            return str(rdata.target).rstrip(".").lower()
    except Exception:
        return None
    return None


def _fetch_body(url: str) -> str | None:
    try:
        with httpx.Client(
            timeout=HTTP_TIMEOUT, headers={"User-Agent": USER_AGENT}, follow_redirects=True, verify=False
        ) as client:
            resp = client.get(url)
            return resp.text[:30_000] if resp.text else None
    except httpx.HTTPError:
        return None


def _check_tls_for_hosts(live_hosts: list[str]) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    seen_hosts: set[str] = set()
    for url in live_hosts:
        if not url.startswith("https://"):
            continue
        host = urlparse(url).hostname or ""
        if not host or host in seen_hosts:
            continue
        seen_hosts.add(host)
        cert_info = _fetch_tls_cert(host)
        if not cert_info:
            continue
        not_after = cert_info.get("not_after")
        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (expiry - datetime.now(timezone.utc)).days
                if days_left < 0:
                    findings.append(
                        _finding(
                            rule_id="asm-tls-expired",
                            severity="high",
                            title=f"TLS certificate expired for {host}",
                            description=f"Certificate expired {-days_left} days ago.",
                            impact="Browsers block users; trust signals broken for crawlers and integrations.",
                            fix_recommendation="Renew via Let's Encrypt / your CA and automate renewal (certbot, ACM).",
                            file_path=f"tls://{host}",
                            metadata={"days_left": days_left, "not_after": not_after},
                        )
                    )
                elif days_left < 14:
                    findings.append(
                        _finding(
                            rule_id="asm-tls-expiring-soon",
                            severity="medium",
                            title=f"TLS certificate expires in {days_left} days for {host}",
                            description="Certificate will expire shortly.",
                            impact="Outage risk if renewal automation fails.",
                            fix_recommendation="Verify auto-renewal pipeline and CAA records.",
                            file_path=f"tls://{host}",
                            metadata={"days_left": days_left, "not_after": not_after},
                        )
                    )
            except Exception:
                pass

        protocol = cert_info.get("protocol", "")
        if protocol in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            findings.append(
                _finding(
                    rule_id="asm-weak-tls-version",
                    severity="high",
                    title=f"Weak TLS protocol ({protocol}) on {host}",
                    description=f"Server negotiated {protocol}, which is deprecated and vulnerable (BEAST, POODLE).",
                    impact="Man-in-the-middle attacks can downgrade and decrypt sessions.",
                    fix_recommendation="Disable TLS 1.0/1.1 at the load balancer; require TLS 1.2+ (1.3 preferred).",
                    file_path=f"tls://{host}",
                    metadata={"protocol": protocol},
                )
            )
    return findings


def _fetch_tls_cert(host: str) -> dict | None:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, 443), timeout=HTTP_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                return {
                    "not_after": cert.get("notAfter") if cert else None,
                    "protocol": protocol or "",
                }
    except Exception:
        return None


def _fingerprint_hosts(live_hosts: list[str]) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    seen: set[str] = set()
    for url in live_hosts:
        host = urlparse(url).hostname or url
        if host in seen:
            continue
        seen.add(host)
        body = _fetch_body(url) or ""
        for tech, pattern, severity_kind in FINGERPRINT_PATTERNS:
            m = pattern.search(body)
            if not m:
                continue
            version = m.group(1) if m.groups() else "unknown"
            severity = "low" if severity_kind == "info" else "medium"
            findings.append(
                _finding(
                    rule_id=f"asm-tech-{tech.lower().replace(' ', '-')}",
                    severity=severity,
                    title=f"{tech} detected on {host}" + (f" (v{version})" if version != "unknown" else ""),
                    description=(
                        f"Public banner / generator tag reveals {tech} on {host}. "
                        "Tech disclosure helps attackers select known CVEs."
                    ),
                    impact="Reduces attacker effort to find exploits; aids targeted attacks.",
                    fix_recommendation=(
                        "Strip `Server` / `X-Powered-By` headers and remove generator meta tags. "
                        "Keep the software patched to the latest minor version."
                    ),
                    file_path=f"http://{host}",
                    metadata={"technology": tech, "version": version},
                )
            )
    return findings


ADMIN_PANEL_BODY_HINTS = re.compile(
    r"(password|login|sign[- ]?in|admin|dashboard|jenkins|grafana|kibana|phpmyadmin|swagger|"
    r"actuator|joomla|wordpress|wp-login|webmin|csrf[_-]?token)",
    re.I,
)
SENSITIVE_FILE_PATHS = {
    "/.env", "/.env.local", "/.git/config", "/.git/HEAD",
    "/.aws/credentials", "/.npmrc", "/.DS_Store", "/actuator/env",
}
SENSITIVE_FILE_FINGERPRINTS = {
    "/.env": re.compile(r"^[A-Z][A-Z0-9_]+\s*=", re.M),
    "/.env.local": re.compile(r"^[A-Z][A-Z0-9_]+\s*=", re.M),
    "/.git/config": re.compile(r"\[core\]|\[remote", re.I),
    "/.git/HEAD": re.compile(r"^ref:\s*refs/", re.I),
    "/.aws/credentials": re.compile(r"aws_access_key_id|aws_secret_access_key", re.I),
    "/.npmrc": re.compile(r"_authToken|registry\s*=", re.I),
}
INFO_PATHS = {"/swagger-ui/", "/swagger-ui.html", "/api-docs", "/.well-known/security.txt"}


def _probe_admin_panels(live_hosts: list[str]) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    headers = {"User-Agent": USER_AGENT}
    with httpx.Client(
        timeout=HTTP_TIMEOUT,
        headers=headers,
        follow_redirects=False,
        verify=False,
    ) as client:
        for url in live_hosts[:MAX_PROBE_HOSTS]:
            baseline = _baseline_soft_404(client, url)
            for path, label in ADMIN_PATHS[:MAX_ADMIN_PATHS_PER_HOST]:
                target = url.rstrip("/") + path
                try:
                    resp = client.get(target)
                except httpx.HTTPError:
                    continue
                if resp.status_code not in (200, 401, 403):
                    continue

                body = resp.text[:30_000] if resp.text else ""
                is_sensitive_file = path in SENSITIVE_FILE_PATHS
                if is_sensitive_file:
                    fp = SENSITIVE_FILE_FINGERPRINTS.get(path)
                    if resp.status_code == 200 and (not fp or not fp.search(body)):
                        continue
                    severity = "critical" if resp.status_code == 200 else "medium"
                elif resp.status_code == 200:
                    if _is_soft_404(body, baseline):
                        continue
                    if not ADMIN_PANEL_BODY_HINTS.search(body):
                        continue
                    severity = "low" if path in INFO_PATHS else "medium"
                else:
                    severity = "medium"

                findings.append(
                    _finding(
                        rule_id=f"asm-exposed-{label.lower().replace(' ', '-').replace('.', '')}",
                        severity=severity,
                        title=f"{label} exposed at {target}",
                        description=(
                            f"HTTP {resp.status_code} response on `{path}` with content matching "
                            f"a known {label.lower()} fingerprint."
                        ),
                        impact=(
                            "Increases attack surface for credential stuffing, RCE in known CMS bugs, "
                            "or sensitive file disclosure."
                        ),
                        fix_recommendation=(
                            "Restrict to internal IPs / VPN / SSO, return 404 to anonymous traffic, "
                            "or remove the exposed file (.env, .git directories)."
                        ),
                        file_path=target,
                        metadata={"status_code": resp.status_code, "path": path},
                    )
                )
    return findings


def _baseline_soft_404(client: httpx.Client, url: str) -> dict | None:
    """Fetch a random non-existent path so we can detect catch-all 200 responses."""
    try:
        resp = client.get(url.rstrip("/") + "/_auditor-nonexistent-{}".format(id(client) % 99999))
        if resp.status_code == 200:
            return {"length": len(resp.text or ""), "preview": (resp.text or "")[:500]}
    except httpx.HTTPError:
        return None
    return None


def _is_soft_404(body: str, baseline: dict | None) -> bool:
    if not baseline:
        return False
    if abs(len(body) - baseline["length"]) < 50:
        return True
    if baseline["preview"] and baseline["preview"][:200] in body:
        return True
    return False


def _finding(
    *,
    rule_id: str,
    severity: str,
    title: str,
    description: str,
    impact: str = "",
    fix_recommendation: str = "",
    file_path: str = "",
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
        scanner="asm",
        confidence="medium",
        metadata=metadata or {},
    )
