"""Domain ownership verification for website projects."""

from __future__ import annotations

import re
import secrets
from datetime import datetime, timezone
from urllib.parse import urlparse

import dns.resolver
import httpx

from app.models.project import Project

META_PATTERN = re.compile(
    r'<meta[^>]+name=["\']auditor-verification["\'][^>]+content=["\']([^"\']+)["\']',
    re.I,
)


def generate_verification_token() -> str:
    return f"auditor-verify-{secrets.token_hex(16)}"


def extract_domain(url: str) -> str:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower().strip(".")
    if host.startswith("www."):
        host = host[4:]
    return host


def verification_instructions(project: Project) -> dict[str, str]:
    domain = extract_domain(project.repo_url or "")
    token = project.domain_verification_token or ""
    return {
        "domain": domain,
        "token": token,
        "dns_record_name": f"_auditor-verification.{domain}",
        "dns_record_value": token,
        "meta_tag": f'<meta name="auditor-verification" content="{token}" />',
        "verified": str(bool(project.domain_verified)).lower(),
    }


def verify_domain_ownership(project: Project) -> tuple[bool, str]:
    """Check DNS TXT or HTML meta tag for the verification token."""
    if not project.domain_verification_token:
        return False, "Verification token is missing"
    domain = extract_domain(project.repo_url or "")
    if not domain:
        return False, "Invalid website URL"

    token = project.domain_verification_token
    if _check_dns_txt(domain, token):
        return True, f"DNS TXT record verified for {domain}"
    if _check_meta_tag(project.repo_url or "", token):
        return True, f"HTML meta tag verified for {domain}"
    return False, (
        f"Verification failed. Add DNS TXT `_auditor-verification.{domain}` = `{token}` "
        f"or add the meta tag to your homepage."
    )


def mark_domain_verified(project: Project) -> None:
    project.domain_verified = True
    project.domain_verified_at = datetime.now(timezone.utc)


def _check_dns_txt(domain: str, token: str) -> bool:
    record_name = f"_auditor-verification.{domain}"
    try:
        answers = dns.resolver.resolve(record_name, "TXT")
        for rdata in answers:
            for part in rdata.strings:
                value = part.decode("utf-8", errors="ignore").strip().strip('"')
                if value == token:
                    return True
    except Exception:
        return False
    return False


def _check_meta_tag(url: str, token: str) -> bool:
    try:
        with httpx.Client(follow_redirects=True, timeout=15.0) as client:
            response = client.get(url, headers={"User-Agent": "AI-Software-Auditor/1.0"})
            if response.status_code >= 400:
                return False
            match = META_PATTERN.search(response.text[:200_000])
            return bool(match and match.group(1).strip() == token)
    except httpx.HTTPError:
        return False
