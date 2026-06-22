"""WebSocket security scanner — origin validation, auth, message injection.

Probes discovered WebSocket endpoints via HTTP upgrade handshake and
optional sync message exchange:
- Missing / weak Origin validation (CSWSH)
- Unauthenticated upgrade on sensitive paths
- Reflected injection in JSON message responses
- cleartext ws:// on HTTPS sites
"""

from __future__ import annotations

import logging
import re
import ssl
from typing import Iterable
from urllib.parse import urljoin, urlparse

import httpx

from app.scanners.base import ScanFinding

logger = logging.getLogger(__name__)

USER_AGENT = "AI-Software-Auditor-WS/1.0"
REQUEST_TIMEOUT = 10.0
MAX_ENDPOINTS = 5

WS_PATHS = [
    "/ws",
    "/websocket",
    "/socket",
    "/socket.io/",
    "/api/ws",
    "/api/websocket",
    "/v1/ws",
    "/realtime",
    "/live",
    "/stream",
    "/graphql",
    "/subscriptions",
]

INJECTION_PAYLOADS = [
    '{"type":"ping","data":"<script>auditor_ws_xss</script>"}',
    '{"action":"subscribe","channel":"test\' OR 1=1--"}',
    '{"message":"{{7*7}}"}',
]
INJECTION_MARKERS = [
    re.compile(r"auditor_ws_xss", re.I),
    re.compile(r"SQL syntax|SQLSTATE|syntax error", re.I),
    re.compile(r"\b49\b"),  # SSTI 7*7
]


def scan_websocket(
    base_url: str,
    *,
    auth: dict | None = None,
    extra_endpoints: Iterable[str] | None = None,
) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    endpoints = _discover_ws_endpoints(base_url, extra_endpoints)
    if not endpoints:
        return findings

    headers, cookies = _build_auth_headers(auth)

    with httpx.Client(timeout=REQUEST_TIMEOUT, verify=False) as client:
        for ws_url in endpoints[:MAX_ENDPOINTS]:
            http_url = _ws_to_http_probe_url(ws_url)
            findings.extend(_probe_handshake(client, http_url, ws_url, headers, cookies))
            findings.extend(_probe_message_injection(ws_url, headers, cookies))

    # Cleartext ws:// when base is HTTPS
    parsed = urlparse(base_url if "://" in base_url else f"https://{base_url}")
    if parsed.scheme == "https":
        for ws_url in endpoints:
            if ws_url.startswith("ws://"):
                findings.append(
                    _finding(
                        rule_id="ws-cleartext",
                        severity="high",
                        title=f"Cleartext WebSocket (ws://) on HTTPS site — {ws_url}",
                        description="Site uses HTTPS but a ws:// endpoint was discovered.",
                        impact="Session tokens and messages can be intercepted via MITM.",
                        fix_recommendation="Use wss:// exclusively; redirect ws:// to wss://.",
                        file_path=ws_url,
                    )
                )
                break

    return findings


def scan_websocket_static(project_dir) -> list[ScanFinding]:
    """Static patterns: insecure WebSocket URLs, missing origin checks in code."""
    from pathlib import Path

    findings: list[ScanFinding] = []
    root = Path(project_dir)
    patterns = [
        (re.compile(r'new\s+WebSocket\s*\(\s*["\']ws://'), "ws-cleartext-in-code", "high"),
        (re.compile(r"verify_origin\s*=\s*False", re.I), "ws-origin-check-disabled", "medium"),
        (re.compile(r"check_origin\s*=\s*False", re.I), "ws-origin-check-disabled", "medium"),
        (re.compile(r"allowed_origins\s*=\s*\[\s*['\"]?\*['\"]?\s*\]"), "ws-wildcard-origin", "high"),
    ]
    exts = {".js", ".ts", ".tsx", ".py", ".go", ".rb", ".php"}

    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in exts:
            continue
        if any(p in path.parts for p in ("node_modules", ".git", "dist", "build")):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")[:60_000]
        except OSError:
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        for pattern, rule_id, severity in patterns:
            if pattern.search(text):
                findings.append(
                    _finding(
                        rule_id=rule_id,
                        severity=severity,
                        title=f"WebSocket misconfiguration in source — {rel}",
                        description=f"Insecure WebSocket pattern: `{pattern.pattern}`",
                        impact="Cross-site WebSocket hijacking or cleartext credential leak.",
                        fix_recommendation="Use wss://, validate Origin header, never use wildcard origins.",
                        file_path=rel,
                    )
                )
    return findings[:20]


def _discover_ws_endpoints(base_url: str, extra: Iterable[str] | None) -> list[str]:
    parsed = urlparse(base_url if "://" in base_url else f"https://{base_url}")
    scheme = "wss" if parsed.scheme == "https" else "ws"
    origin = f"{scheme}://{parsed.netloc}"
    candidates: list[str] = [urljoin(origin + "/", p.lstrip("/")) for p in WS_PATHS]

    if extra:
        for ep in extra:
            if ep.startswith(("ws://", "wss://")):
                candidates.append(ep)

    try:
        http_origin = f"{parsed.scheme}://{parsed.netloc}"
        with httpx.Client(timeout=REQUEST_TIMEOUT, verify=False) as client:
            resp = client.get(http_origin, headers={"User-Agent": USER_AGENT})
            for match in re.finditer(r'wss?://[^\s"\'<>]+', resp.text[:120_000], re.I):
                candidates.append(match.group(0).rstrip(".,;)"))
    except httpx.HTTPError:
        pass

    live: list[str] = []
    seen: set[str] = set()
    with httpx.Client(timeout=REQUEST_TIMEOUT, verify=False) as client:
        for ws_url in candidates:
            if ws_url in seen:
                continue
            seen.add(ws_url)
            http_probe = _ws_to_http_probe_url(ws_url)
            if _handshake_accepts(client, http_probe, origin_header="https://auditor-ws-probe.example"):
                live.append(ws_url)
    return live


def _ws_to_http_probe_url(ws_url: str) -> str:
    parsed = urlparse(ws_url)
    http_scheme = "https" if parsed.scheme == "wss" else "http"
    return f"{http_scheme}://{parsed.netloc}{parsed.path or '/'}"

def _handshake_accepts(
    client: httpx.Client,
    http_url: str,
    *,
    origin_header: str,
    extra_headers: dict | None = None,
) -> bool:
    headers = {
        "User-Agent": USER_AGENT,
        "Connection": "Upgrade",
        "Upgrade": "websocket",
        "Sec-WebSocket-Version": "13",
        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
        "Origin": origin_header,
    }
    if extra_headers:
        headers.update(extra_headers)
    try:
        resp = client.get(http_url, headers=headers)
        return resp.status_code == 101 or (
            resp.status_code in (200, 400, 426)
            and "upgrade" in (resp.headers.get("connection") or "").lower()
        )
    except httpx.HTTPError:
        return False


def _probe_handshake(
    client: httpx.Client,
    http_url: str,
    ws_url: str,
    headers: dict,
    cookies: dict,
) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    base_headers = {
        "User-Agent": USER_AGENT,
        "Connection": "Upgrade",
        "Upgrade": "websocket",
        "Sec-WebSocket-Version": "13",
        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
        **headers,
    }

    evil_origin = "https://evil-auditor-csrf.example"
    resp = client.get(
        http_url,
        headers={**base_headers, "Origin": evil_origin},
        cookies=cookies,
    )
    if resp.status_code == 101:
        findings.append(
            _finding(
                rule_id="ws-origin-not-validated",
                severity="high",
                title=f"WebSocket accepts cross-origin upgrade — {ws_url}",
                description=f"HTTP 101 Switching Protocols with Origin: {evil_origin}",
                impact="Cross-Site WebSocket Hijacking (CSWSH) — attacker sites can hijack sessions.",
                fix_recommendation="Validate Origin against an allowlist; reject unknown origins.",
                file_path=ws_url,
                metadata={"origin_tested": evil_origin},
            )
        )
    elif resp.status_code in (200, 403, 401) and "websocket" in resp.text.lower()[:500]:
        findings.append(
            _finding(
                rule_id="ws-endpoint-discovered",
                severity="low",
                title=f"WebSocket endpoint discovered — {ws_url}",
                description="Endpoint responds to WebSocket upgrade probes.",
                impact="Realtime channel is part of the attack surface — review auth and message validation.",
                fix_recommendation="Require authentication on upgrade; rate-limit connections.",
                file_path=ws_url,
            )
        )

    # Unauthenticated upgrade when auth headers omitted
    if not headers.get("Authorization") and not cookies:
        unauth = client.get(http_url, headers={**base_headers, "Origin": "https://localhost"})
        if unauth.status_code == 101:
            findings.append(
                _finding(
                    rule_id="ws-unauthenticated-upgrade",
                    severity="medium",
                    title=f"WebSocket upgrade without authentication — {ws_url}",
                    description="Server returned 101 without credentials.",
                    impact="Anyone can open a realtime connection and receive events or send messages.",
                    fix_recommendation="Require JWT/session token during the WebSocket handshake.",
                    file_path=ws_url,
                )
            )

    return findings


def _probe_message_injection(ws_url: str, headers: dict, cookies: dict) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    try:
        import websockets
        from websockets.sync.client import connect
    except ImportError:
        return findings

    extra_headers = {k: v for k, v in headers.items() if k.lower() != "user-agent"}
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    try:
        with connect(
            ws_url,
            additional_headers=extra_headers,
            open_timeout=REQUEST_TIMEOUT,
            ssl=ssl_ctx if ws_url.startswith("wss://") else None,
        ) as ws:
            for payload in INJECTION_PAYLOADS:
                try:
                    ws.send(payload)
                    reply = ws.recv(timeout=3)
                    text = reply if isinstance(reply, str) else reply.decode("utf-8", errors="ignore")
                    for marker in INJECTION_MARKERS:
                        if marker.search(text):
                            findings.append(
                                _finding(
                                    rule_id="ws-message-injection",
                                    severity="high",
                                    title=f"WebSocket reflects injected payload — {ws_url}",
                                    description=f"Server echoed probe content in response to: {payload[:80]}",
                                    impact="Possible XSS, SQLi, or SSTI via WebSocket message handling.",
                                    fix_recommendation="Sanitize and validate all inbound WS messages; never echo raw input.",
                                    file_path=ws_url,
                                )
                            )
                            return findings
                except Exception:
                    continue
    except Exception as exc:
        logger.debug("WS message probe failed for %s: %s", ws_url, exc)

    return findings


def _build_auth_headers(auth: dict | None) -> tuple[dict, dict]:
    headers: dict = {}
    cookies: dict = {}
    if not auth:
        return headers, cookies
    auth_type = (auth.get("type") or "").lower()
    if auth_type == "bearer" and auth.get("token"):
        headers["Authorization"] = f"Bearer {auth['token']}"
    elif auth_type == "cookie" and auth.get("cookies"):
        for line in str(auth["cookies"]).split(";"):
            if "=" in line:
                k, v = line.split("=", 1)
                cookies[k.strip()] = v.strip()
    elif auth_type == "header" and auth.get("header_name"):
        headers[str(auth["header_name"])] = str(auth.get("header_value", ""))
    return headers, cookies


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
        scanner="websocket-security",
        confidence="medium",
        metadata=metadata or {},
    )
