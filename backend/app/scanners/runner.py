from pathlib import Path

from app.scanners.architecture import scan_architecture
from app.scanners.base import ScanFinding
from app.scanners.dependencies import scan_dependencies
from app.scanners.devops import scan_devops
from app.scanners.performance import scan_performance
from app.scanners.quality import scan_quality
from app.scanners.secrets import scan_secrets
from app.scanners.security import scan_security_patterns
from app.scanners.semgrep_scanner import scan_semgrep


def run_all_scanners(project_dir: Path) -> tuple[list[ScanFinding], list[str]]:
    """Run all available scanners and return findings + scanners used."""
    scanners_used: list[str] = []
    all_findings: list[ScanFinding] = []

    secret_findings = scan_secrets(project_dir)
    if secret_findings is not None:
        scanners_used.append("secrets")
        all_findings.extend(secret_findings)

    security_findings = scan_security_patterns(project_dir)
    scanners_used.append("security-patterns")
    all_findings.extend(security_findings)

    semgrep_findings = scan_semgrep(project_dir)
    if semgrep_findings:
        scanners_used.append("semgrep")
        all_findings.extend(semgrep_findings)

    dep_findings = scan_dependencies(project_dir)
    if dep_findings:
        scanners_used.append("osv")
    all_findings.extend(dep_findings)

    arch_findings = scan_architecture(project_dir)
    scanners_used.append("architecture")
    all_findings.extend(arch_findings)

    perf_findings = scan_performance(project_dir)
    scanners_used.append("performance")
    all_findings.extend(perf_findings)

    quality_findings = scan_quality(project_dir)
    scanners_used.append("quality")
    all_findings.extend(quality_findings)

    devops_findings = scan_devops(project_dir)
    scanners_used.append("devops")
    all_findings.extend(devops_findings)

    return all_findings, scanners_used
