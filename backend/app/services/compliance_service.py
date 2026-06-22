"""Map audit findings to compliance frameworks (PCI-DSS, GDPR, SOC2, HIPAA)."""

from __future__ import annotations

from dataclasses import dataclass

from app.models.issue import Issue

# Map CWE prefixes / categories to compliance controls
PCI_CONTROLS: dict[str, tuple[str, str]] = {
    "CWE-79": ("PCI 6.4.1", "Protect against injection attacks including XSS."),
    "CWE-89": ("PCI 6.4.1", "Protect against SQL injection."),
    "CWE-94": ("PCI 6.4.1", "Prevent code injection vulnerabilities."),
    "CWE-259": ("PCI 8.3.1", "Do not store passwords in code or config."),
    "CWE-798": ("PCI 8.3.1", "Protect authentication credentials and secrets."),
    "CWE-319": ("PCI 4.2.1", "Encrypt transmission of cardholder data over open networks."),
    "CWE-295": ("PCI 4.2.1", "Use strong cryptography for data in transit."),
    "dependencies": ("PCI 6.3.2", "Ensure system components have latest security patches."),
    "secrets": ("PCI 8.3.1", "Protect secret authentication data."),
    "security": ("PCI 6.4.1", "Address secure coding and vulnerability management."),
}

GDPR_CONTROLS: dict[str, tuple[str, str]] = {
    "CWE-319": ("Art. 32", "Implement encryption for personal data in transit."),
    "CWE-798": ("Art. 32", "Ensure confidentiality of credentials processing personal data."),
    "CWE-259": ("Art. 32", "Prevent credential exposure affecting data security."),
    "secrets": ("Art. 32", "Technical measures to protect personal data from breach."),
    "security": ("Art. 32", "Security of processing — risk-based technical measures."),
    "dependencies": ("Art. 32", "Maintain secure systems handling personal data."),
}

SOC2_CONTROLS: dict[str, tuple[str, str]] = {
    "CWE-798": ("CC6.1", "Logical access — protect credentials and secrets."),
    "CWE-259": ("CC6.1", "Logical access — prevent hardcoded authentication data."),
    "CWE-319": ("CC6.7", "Transmission security — encrypt data in transit."),
    "CWE-295": ("CC6.7", "Transmission security — validate TLS certificates."),
    "CWE-89": ("CC7.1", "System operations — detect and prevent injection flaws."),
    "CWE-79": ("CC7.1", "System operations — prevent XSS and injection attacks."),
    "dependencies": ("CC7.1", "Vulnerability management — patch vulnerable components."),
    "secrets": ("CC6.1", "Protect secret authentication data from unauthorized access."),
    "security": ("CC7.1", "Monitor and address security vulnerabilities."),
    "iac": ("CC6.6", "Infrastructure security — secure cloud and container configs."),
}

HIPAA_CONTROLS: dict[str, tuple[str, str]] = {
    "CWE-319": ("164.312(e)", "Transmission security — protect ePHI in transit."),
    "CWE-798": ("164.312(a)", "Access control — safeguard authentication credentials."),
    "CWE-259": ("164.312(a)", "Access control — no passwords in application code."),
    "CWE-311": ("164.312(a)", "Access control — encryption of ePHI at rest."),
    "secrets": ("164.312(a)", "Protect credentials that access systems with ePHI."),
    "security": ("164.308(a)", "Administrative safeguards — risk analysis and mitigation."),
    "dependencies": ("164.308(a)", "Address known vulnerabilities in systems handling ePHI."),
}


@dataclass
class ComplianceFinding:
    framework: str
    control_id: str
    title: str
    issue_count: int
    max_severity: str
    status: str  # pass | fail | review


def build_compliance_summary(issues: list[Issue]) -> list[ComplianceFinding]:
    """Aggregate issues into PCI-DSS, GDPR, SOC2, and HIPAA control status."""
    pci_counts: dict[str, dict] = {}
    gdpr_counts: dict[str, dict] = {}
    soc2_counts: dict[str, dict] = {}
    hipaa_counts: dict[str, dict] = {}

    for issue in issues:
        if issue.dismissed:
            continue
        extra = issue.extra_data or {}
        cwe = extra.get("cwe_id", "")
        keys = [cwe, issue.category]
        for key in keys:
            if not key:
                continue
            _accumulate(pci_counts, PCI_CONTROLS, key, issue)
            _accumulate(gdpr_counts, GDPR_CONTROLS, key, issue)
            _accumulate(soc2_counts, SOC2_CONTROLS, key, issue)
            _accumulate(hipaa_counts, HIPAA_CONTROLS, key, issue)

    findings: list[ComplianceFinding] = []
    findings.extend(_to_findings("PCI-DSS", pci_counts, PCI_CONTROLS))
    findings.extend(_to_findings("GDPR", gdpr_counts, GDPR_CONTROLS))
    findings.extend(_to_findings("SOC2", soc2_counts, SOC2_CONTROLS))
    findings.extend(_to_findings("HIPAA", hipaa_counts, HIPAA_CONTROLS))
    return sorted(findings, key=lambda f: (f.framework, f.control_id))


def _accumulate(
    bucket: dict[str, dict],
    controls: dict[str, tuple[str, str]],
    key: str,
    issue: Issue,
) -> None:
    match = controls.get(key)
    if not match:
        return
    control_id, title = match
    entry = bucket.setdefault(
        control_id,
        {"title": title, "count": 0, "max_severity": "low"},
    )
    entry["count"] += 1
    entry["max_severity"] = _max_severity(entry["max_severity"], issue.severity)


def _max_severity(current: str, new: str) -> str:
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    return new if rank.get(new, 0) > rank.get(current, 0) else current


def _to_findings(
    framework: str,
    bucket: dict[str, dict],
    controls: dict[str, tuple[str, str]],
) -> list[ComplianceFinding]:
    findings: list[ComplianceFinding] = []
    for control_id in sorted(set(bucket.keys())):
        entry = bucket[control_id]
        max_sev = entry["max_severity"]
        if max_sev in ("critical", "high"):
            status = "fail"
        elif entry["count"] > 0:
            status = "review"
        else:
            status = "pass"
        findings.append(
            ComplianceFinding(
                framework=framework,
                control_id=control_id,
                title=entry["title"],
                issue_count=entry["count"],
                max_severity=max_sev if entry["count"] else "none",
                status=status,
            )
        )
    return findings
