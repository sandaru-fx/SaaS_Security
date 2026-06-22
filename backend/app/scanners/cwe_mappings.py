"""CWE and OWASP Top 10 mappings for scanner rule IDs."""

from __future__ import annotations

from app.scanners.base import ScanFinding

# rule_id -> (cwe_id, owasp_category)
RULE_TAGS: dict[str, tuple[str, str]] = {
    # security-patterns
    "sql-injection-concat": ("CWE-89", "A03:2021 - Injection"),
    "sql-injection-plus": ("CWE-89", "A03:2021 - Injection"),
    "xss-innerhtml": ("CWE-79", "A03:2021 - Injection"),
    "dangerous-eval": ("CWE-94", "A03:2021 - Injection"),
    "dangerous-exec": ("CWE-94", "A03:2021 - Injection"),
    "insecure-cors": ("CWE-942", "A05:2021 - Security Misconfiguration"),
    "missing-https": ("CWE-319", "A02:2021 - Cryptographic Failures"),
    "debug-enabled": ("CWE-489", "A05:2021 - Security Misconfiguration"),
    # secrets
    "aws-access-key": ("CWE-798", "A07:2021 - Identification and Authentication Failures"),
    "github-token": ("CWE-798", "A07:2021 - Identification and Authentication Failures"),
    "generic-api-key": ("CWE-798", "A07:2021 - Identification and Authentication Failures"),
    "password-in-code": ("CWE-259", "A07:2021 - Identification and Authentication Failures"),
    "private-key": ("CWE-321", "A02:2021 - Cryptographic Failures"),
    "jwt-secret": ("CWE-798", "A07:2021 - Identification and Authentication Failures"),
    # website scanner (sample)
    "missing-hsts": ("CWE-319", "A05:2021 - Security Misconfiguration"),
    "missing-csp": ("CWE-1021", "A05:2021 - Security Misconfiguration"),
    "missing-x-frame-options": ("CWE-1021", "A05:2021 - Security Misconfiguration"),
    "no-https": ("CWE-319", "A02:2021 - Cryptographic Failures"),
    "tls-cert-expired": ("CWE-295", "A02:2021 - Cryptographic Failures"),
    "mixed-content": ("CWE-319", "A05:2021 - Security Misconfiguration"),
}

DEFAULT_DEPENDENCY_OWASP = "A06:2021 - Vulnerable and Outdated Components"


def lookup_rule_tags(rule_id: str, scanner: str) -> dict[str, str]:
    """Return cwe_id / owasp_category for a rule, if known."""
    normalized = rule_id.split(".")[-1] if "." in rule_id else rule_id
    tags = RULE_TAGS.get(normalized) or RULE_TAGS.get(rule_id)
    if tags:
        return {"cwe_id": tags[0], "owasp_category": tags[1]}
    if scanner == "osv":
        return {"owasp_category": DEFAULT_DEPENDENCY_OWASP}
    return {}


def parse_semgrep_metadata(metadata: dict) -> dict[str, str]:
    """Extract CWE/OWASP from Semgrep rule metadata."""
    result: dict[str, str] = {}
    cwe = metadata.get("cwe")
    if isinstance(cwe, list) and cwe:
        cwe = cwe[0]
    if isinstance(cwe, str):
        result["cwe_id"] = cwe.split(":")[0].strip() if ":" in cwe else cwe.strip()
    owasp = metadata.get("owasp")
    if isinstance(owasp, list) and owasp:
        result["owasp_category"] = str(owasp[0])
    elif isinstance(owasp, str):
        result["owasp_category"] = owasp
    return result


def enrich_finding_tags(finding: ScanFinding) -> ScanFinding:
    """Attach CWE/OWASP tags to finding metadata when missing."""
    if finding.metadata.get("cwe_id") or finding.metadata.get("owasp_category"):
        return finding
    tags = lookup_rule_tags(finding.rule_id, finding.scanner)
    if tags:
        finding.metadata.update(tags)
    return finding
