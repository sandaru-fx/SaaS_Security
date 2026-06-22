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
    "high-entropy-secret": ("CWE-798", "A07:2021 - Identification and Authentication Failures"),
    "git-history-aws-access-key": ("CWE-798", "A07:2021 - Identification and Authentication Failures"),
    "missing-hsts": ("CWE-319", "A05:2021 - Security Misconfiguration"),
    "missing-csp": ("CWE-1021", "A05:2021 - Security Misconfiguration"),
    "missing-x-frame-options": ("CWE-1021", "A05:2021 - Security Misconfiguration"),
    "no-https": ("CWE-319", "A02:2021 - Cryptographic Failures"),
    "tls-cert-expired": ("CWE-295", "A02:2021 - Cryptographic Failures"),
    "mixed-content": ("CWE-319", "A05:2021 - Security Misconfiguration"),
    # IaC
    "tf-open-cidr": ("CWE-284", "A01:2021 - Broken Access Control"),
    "tf-s3-public-read": ("CWE-732", "A01:2021 - Broken Access Control"),
    "tf-hardcoded-secret": ("CWE-798", "A07:2021 - Identification and Authentication Failures"),
    "tf-encryption-disabled": ("CWE-311", "A02:2021 - Cryptographic Failures"),
    "k8s-privileged-container": ("CWE-250", "A05:2021 - Security Misconfiguration"),
    "k8s-run-as-root": ("CWE-250", "A05:2021 - Security Misconfiguration"),
    "k8s-host-namespace": ("CWE-653", "A05:2021 - Security Misconfiguration"),
    "k8s-unpinned-image": ("CWE-1104", "A06:2021 - Vulnerable and Outdated Components"),
    "k8s-loadbalancer-no-netpol": ("CWE-284", "A01:2021 - Broken Access Control"),
    # Active DAST
    "active-xss-reflected": ("CWE-79", "A03:2021 - Injection"),
    "active-sqli-error": ("CWE-89", "A03:2021 - Injection"),
    "active-open-redirect": ("CWE-601", "A01:2021 - Broken Access Control"),
    "active-path-traversal": ("CWE-22", "A01:2021 - Broken Access Control"),
    "active-cors-wildcard-credentials": ("CWE-942", "A05:2021 - Security Misconfiguration"),
    "active-cors-reflected-origin": ("CWE-942", "A05:2021 - Security Misconfiguration"),
    "active-method-trace": ("CWE-693", "A05:2021 - Security Misconfiguration"),
    "active-method-track": ("CWE-693", "A05:2021 - Security Misconfiguration"),
    "active-methods-mutation-exposed": ("CWE-650", "A05:2021 - Security Misconfiguration"),
    "active-verbose-error": ("CWE-209", "A05:2021 - Security Misconfiguration"),
    "active-auth-bypass": ("CWE-287", "A07:2021 - Identification and Authentication Failures"),
    # API security
    "api-spec-load-failed": ("CWE-693", "A05:2021 - Security Misconfiguration"),
    "api-no-server-url": ("CWE-693", "A05:2021 - Security Misconfiguration"),
    "api-no-security-schemes": ("CWE-306", "API2:2023 - Broken Authentication"),
    "api-no-global-security": ("CWE-306", "API2:2023 - Broken Authentication"),
    "api-mass-assignment": ("CWE-915", "API6:2023 - Mass Assignment"),
    "api-unauthenticated-data": ("CWE-306", "API2:2023 - Broken Authentication"),
    "api-bola-numeric-id": ("CWE-639", "API1:2023 - Broken Object Level Authorization"),
    "api-verbose-error": ("CWE-209", "API8:2023 - Security Misconfiguration"),
    "api-sqli-error": ("CWE-89", "API10:2023 - Unsafe Consumption of APIs"),
    "api-no-rate-limit": ("CWE-770", "API4:2023 - Unrestricted Resource Consumption"),
    "api-function-level-auth": ("CWE-285", "API5:2023 - Broken Function Level Authorization"),
    "api-http-base-url": ("CWE-319", "A02:2021 - Cryptographic Failures"),
    # Taint analysis (Python)
    "taint-py-sqli": ("CWE-89", "A03:2021 - Injection"),
    "taint-py-cmd-injection": ("CWE-78", "A03:2021 - Injection"),
    "taint-py-code-injection": ("CWE-94", "A03:2021 - Injection"),
    "taint-py-path-traversal": ("CWE-22", "A01:2021 - Broken Access Control"),
    "taint-py-ssrf": ("CWE-918", "A10:2021 - Server-Side Request Forgery"),
    "taint-py-open-redirect": ("CWE-601", "A01:2021 - Broken Access Control"),
    "taint-py-ssti": ("CWE-94", "A03:2021 - Injection"),
    "taint-py-pickle": ("CWE-502", "A08:2021 - Software and Data Integrity Failures"),
    "taint-py-yaml-load": ("CWE-502", "A08:2021 - Software and Data Integrity Failures"),
    # Taint analysis (JS/TS)
    "taint-js-xss-innerhtml": ("CWE-79", "A03:2021 - Injection"),
    "taint-js-xss-outerhtml": ("CWE-79", "A03:2021 - Injection"),
    "taint-js-react-dangerous-html": ("CWE-79", "A03:2021 - Injection"),
    "taint-js-document-write": ("CWE-79", "A03:2021 - Injection"),
    "taint-js-code-injection": ("CWE-94", "A03:2021 - Injection"),
    "taint-js-sqli": ("CWE-89", "A03:2021 - Injection"),
    "taint-js-cmd-injection": ("CWE-78", "A03:2021 - Injection"),
    "taint-js-open-redirect": ("CWE-601", "A01:2021 - Broken Access Control"),
    "taint-js-path-traversal": ("CWE-22", "A01:2021 - Broken Access Control"),
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
