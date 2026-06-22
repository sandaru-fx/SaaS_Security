"""Browser-based DAST — headless Chromium (Playwright).

Renders JavaScript SPAs and detects issues curl-based scanners miss:
- DOM / post-render XSS via form/input probing
- CSP misconfiguration (missing, unsafe-inline, unsafe-eval)
- Sensitive data in localStorage / sessionStorage
- Client-side route discovery (SPA link crawl)
- Prototype pollution URL reflection hints
- Console error / stack trace leakage

Requires Playwright + Chromium (`playwright install chromium`).
Opt-in via `browser_dast_enabled` + verified domain ownership.
"""

from __future__ import annotations

import logging
import re
from typing import Iterable
from urllib.parse import urljoin, urlparse

from app.scanners.base import ScanFinding

logger = logging.getLogger(__name__)

USER_AGENT = "AI-Software-Auditor-BrowserDAST/1.0"
MAX_PAGES = 10
MAX_FORMS_PER_PAGE = 4
NAV_TIMEOUT_MS = 15_000

XSS_PAYLOAD = '"><img src=x onerror="document.body.setAttribute(\'data-auditor-xss\',\'1\')">'
XSS_DOM_MARKER = 'data-auditor-xss="1"'

SENSITIVE_STORAGE_PATTERN = re.compile(
    r"(token|secret|password|api[_-]?key|auth|bearer|jwt|session)",
    re.I,
)
CONSOLE_LEAK_PATTERN = re.compile(
    r"(SyntaxError|TypeError|ReferenceError|at\s+[\w./]+:\d+:\d+|Traceback|SQLSTATE|"
    r"Uncaught\s+Error|stack\s+trace)",
    re.I,
)
PP_POLLUTION_URL_SUFFIX = "?__proto__[auditor_pp]=polluted&constructor[prototype][auditor_pp]=polluted"


def scan_browser_dast(
    base_url: str,
    *,
    auth: dict | None = None,
) -> list[ScanFinding]:
    """Run headless browser probes. Returns empty list if Playwright unavailable."""
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError:
        logger.warning("Playwright not installed — browser DAST skipped")
        return []

    parsed = urlparse(base_url if "://" in base_url else f"https://{base_url}")
    if not parsed.scheme.startswith("http"):
        return []

    origin = f"{parsed.scheme}://{parsed.netloc}"
    findings: list[ScanFinding] = []
    visited: set[str] = set()
    console_logs: list[str] = []

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = _build_context(browser, auth, origin)
            page = context.new_page()
            page.set_default_timeout(NAV_TIMEOUT_MS)

            page.on("console", lambda msg: console_logs.append(msg.text))

            try:
                response = page.goto(base_url, wait_until="domcontentloaded")
            except PlaywrightError as exc:
                logger.warning("Browser DAST navigation failed: %s", exc)
                context.close()
                browser.close()
                return findings

            if response:
                findings.extend(_check_csp(response.headers, base_url))

            visited.add(_normalize_url(page.url, origin))
            queue = _collect_same_origin_links(page, origin)
            findings.extend(_probe_dom_xss_on_page(page, base_url))
            findings.extend(_check_web_storage(page, base_url))
            findings.extend(_probe_prototype_pollution(page, base_url))

            pages_crawled = 1
            while queue and pages_crawled < MAX_PAGES:
                next_url = queue.pop(0)
                norm = _normalize_url(next_url, origin)
                if norm in visited:
                    continue
                visited.add(norm)
                try:
                    page.goto(next_url, wait_until="domcontentloaded")
                    pages_crawled += 1
                    findings.extend(_probe_dom_xss_on_page(page, next_url))
                    for link in _collect_same_origin_links(page, origin):
                        if _normalize_url(link, origin) not in visited:
                            queue.append(link)
                except PlaywrightError:
                    continue

            if len(visited) > 1:
                findings.append(
                    _finding(
                        rule_id="browser-spa-routes-crawled",
                        severity="low",
                        title=f"SPA browser crawl mapped {len(visited)} client-rendered routes",
                        description=(
                            f"Headless Chromium discovered {len(visited)} same-origin URLs "
                            "via DOM link extraction (JS-rendered navigation)."
                        ),
                        impact="Hidden SPA routes may lack auth or expose admin functionality.",
                        fix_recommendation=(
                            "Ensure all client-side routes enforce authentication and authorization."
                        ),
                        file_path=base_url,
                        metadata={"routes": list(visited)[:20], "route_count": len(visited)},
                    )
                )

            findings.extend(_check_console_leaks(console_logs, base_url))

            context.close()
            browser.close()
    except Exception as exc:
        logger.warning("Browser DAST failed: %s", exc)

    return findings


def _build_context(browser, auth: dict | None, origin: str):
    host = urlparse(origin).hostname or ""

    context_kwargs: dict = {
        "user_agent": USER_AGENT,
        "ignore_https_errors": True,
    }
    extra_headers: dict[str, str] = {}
    storage: list[dict] = []

    if auth:
        auth_type = (auth.get("type") or "").lower()
        if auth_type == "bearer" and auth.get("token"):
            extra_headers["Authorization"] = f"Bearer {auth['token']}"
        elif auth_type == "cookie" and auth.get("cookies"):
            for line in str(auth["cookies"]).split(";"):
                if "=" in line:
                    name, value = line.split("=", 1)
                    storage.append(
                        {
                            "name": name.strip(),
                            "value": value.strip(),
                            "domain": host,
                            "path": "/",
                        }
                    )
        elif auth_type == "header" and auth.get("header_name"):
            extra_headers[str(auth["header_name"])] = str(auth.get("header_value", ""))
        elif auth_type == "basic" and auth.get("username"):
            import base64

            cred = f"{auth['username']}:{auth.get('password', '')}"
            extra_headers["Authorization"] = "Basic " + base64.b64encode(cred.encode()).decode()

    if extra_headers:
        context_kwargs["extra_http_headers"] = extra_headers

    context = browser.new_context(**context_kwargs)
    if storage:
        try:
            context.add_cookies(storage)
        except Exception:
            pass
    return context


def _check_csp(headers: dict, url: str) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    csp = headers.get("content-security-policy") or headers.get("Content-Security-Policy")
    if not csp:
        findings.append(
            _finding(
                rule_id="browser-csp-missing",
                severity="medium",
                title="Content-Security-Policy header missing (browser verified)",
                description="No CSP header on the document response observed by Chromium.",
                impact="No defense-in-depth against XSS, clickjacking, and data exfiltration.",
                fix_recommendation="Add a strict CSP with nonce/hash-based script-src.",
                file_path=url,
            )
        )
        return findings

    csp_lower = csp.lower()
    if "unsafe-inline" in csp_lower:
        findings.append(
            _finding(
                rule_id="browser-csp-unsafe-inline",
                severity="medium",
                title="CSP allows unsafe-inline scripts",
                description=f"Content-Security-Policy contains `unsafe-inline`: {csp[:200]}",
                impact="Inline script XSS bypasses CSP protections.",
                fix_recommendation="Use nonces or hashes instead of unsafe-inline.",
                file_path=url,
            )
        )
    if "unsafe-eval" in csp_lower:
        findings.append(
            _finding(
                rule_id="browser-csp-unsafe-eval",
                severity="medium",
                title="CSP allows unsafe-eval",
                description=f"Content-Security-Policy contains `unsafe-eval`: {csp[:200]}",
                impact="eval() and similar sinks remain exploitable under CSP.",
                fix_recommendation="Remove unsafe-eval; refactor dynamic code generation.",
                file_path=url,
            )
        )
    return findings


def _probe_dom_xss_on_page(page, page_url: str) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    try:
        forms = page.locator("form").all()[:MAX_FORMS_PER_PAGE]
        for form in forms:
            inputs = form.locator(
                "input:not([type=hidden]):not([type=submit]):not([type=button]):not([type=checkbox])"
            ).all()
            textareas = form.locator("textarea").all()
            fields = inputs + textareas
            if not fields:
                continue
            for field in fields[:3]:
                try:
                    field.fill(XSS_PAYLOAD)
                except Exception:
                    continue
            try:
                form.evaluate("f => f.submit()")
                page.wait_for_timeout(800)
            except Exception:
                try:
                    form.locator("button[type=submit], input[type=submit]").first.click(timeout=2000)
                    page.wait_for_timeout(800)
                except Exception:
                    continue

            html = page.content()
            if XSS_DOM_MARKER in html or "data-auditor-xss" in html:
                findings.append(
                    _finding(
                        rule_id="browser-dom-xss",
                        severity="high",
                        title=f"DOM XSS — payload executed after form submit at {page_url}",
                        description=(
                            "Headless browser injected a marker payload into a form; "
                            "the onerror handler ran and set `data-auditor-xss` on the document body."
                        ),
                        impact="Attackers can execute arbitrary JavaScript in victims' browsers.",
                        fix_recommendation=(
                            "Encode all output contextually; use CSP; avoid innerHTML with user input."
                        ),
                        file_path=page_url,
                        confidence="high",
                    )
                )
                return findings
    except Exception as exc:
        logger.debug("DOM XSS probe error on %s: %s", page_url, exc)
    return findings


def _check_web_storage(page, url: str) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    try:
        data = page.evaluate(
            """() => {
                const out = [];
                for (const store of [localStorage, sessionStorage]) {
                    for (let i = 0; i < store.length; i++) {
                        const key = store.key(i);
                        const val = (store.getItem(key) || '').slice(0, 80);
                        out.push({ key, val, store: store === localStorage ? 'local' : 'session' });
                    }
                }
                return out;
            }"""
        )
        for item in data or []:
            key = str(item.get("key", ""))
            if SENSITIVE_STORAGE_PATTERN.search(key) or (
                len(str(item.get("val", ""))) > 20 and SENSITIVE_STORAGE_PATTERN.search(str(item.get("val", "")))
            ):
                findings.append(
                    _finding(
                        rule_id="browser-sensitive-web-storage",
                        severity="high",
                        title=f"Sensitive data in {item.get('store')}Storage — {key}",
                        description=(
                            f"Browser storage key `{key}` matches sensitive patterns on {url}."
                        ),
                        impact="XSS or physical access can steal tokens from web storage.",
                        fix_recommendation="Store tokens in HttpOnly Secure cookies; never localStorage for JWTs.",
                        file_path=url,
                        metadata={"storage": item.get("store"), "key": key},
                    )
                )
    except Exception:
        pass
    return findings


def _probe_prototype_pollution(page, base_url: str) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    test_url = base_url.rstrip("/") + PP_POLLUTION_URL_SUFFIX
    try:
        page.goto(test_url, wait_until="domcontentloaded")
        content = page.content()
        if "__proto__" in content or "auditor_pp" in content:
            polluted = page.evaluate(
                "() => ({ pp: Object.prototype.auditor_pp, own: ({}).auditor_pp })"
            )
            if polluted and (polluted.get("pp") or polluted.get("own")):
                findings.append(
                    _finding(
                        rule_id="browser-prototype-pollution",
                        severity="high",
                        title=f"Client-side prototype pollution — {base_url}",
                        description=(
                            "URL query parameters polluted Object.prototype in the browser context."
                        ),
                        impact="Attackers can inject properties affecting all objects — auth bypass, RCE chains.",
                        fix_recommendation=(
                            "Freeze Object.prototype; use safe merge libraries; validate query parsing."
                        ),
                        file_path=test_url,
                    )
                )
            elif "__proto__" in content:
                findings.append(
                    _finding(
                        rule_id="browser-prototype-pollution-reflected",
                        severity="medium",
                        title=f"__proto__ pollution params reflected in DOM — {base_url}",
                        description="Pollution query string appears in page HTML (review client-side merge logic).",
                        impact="May indicate unsafe URL parameter merging into application state.",
                        fix_recommendation="Never pass user input to Object.assign or deep merge without validation.",
                        file_path=test_url,
                    )
                )
    except Exception:
        pass
    return findings


def _check_console_leaks(logs: Iterable[str], url: str) -> list[ScanFinding]:
    for line in logs:
        if CONSOLE_LEAK_PATTERN.search(line):
            return [
                _finding(
                    rule_id="browser-console-verbose-error",
                    severity="low",
                    title="Verbose client-side error in browser console",
                    description=f"Console message: {line[:300]}",
                    impact="Stack traces and errors aid attackers mapping application internals.",
                    fix_recommendation="Disable verbose client errors in production builds.",
                    file_path=url,
                )
            ]
    return []


def _collect_same_origin_links(page, origin: str) -> list[str]:
    links: list[str] = []
    try:
        hrefs = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
        for href in hrefs or []:
            if href.startswith(origin):
                links.append(href.split("#")[0])
    except Exception:
        pass
    return list(dict.fromkeys(links))


def _normalize_url(url: str, origin: str) -> str:
    p = urlparse(url)
    if not p.scheme:
        return urljoin(origin + "/", url)
    return f"{p.scheme}://{p.netloc}{p.path}".rstrip("/") or origin


def _finding(
    *,
    rule_id: str,
    severity: str,
    title: str,
    description: str,
    impact: str,
    fix_recommendation: str,
    file_path: str,
    confidence: str = "medium",
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
        scanner="browser-dast",
        confidence=confidence,
        metadata=metadata or {},
    )
