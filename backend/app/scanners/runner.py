from pathlib import Path

from app.scanners.architecture import scan_architecture
from app.scanners.bandit_scanner import scan_bandit
from app.scanners.base import ScanFinding
from app.scanners.crypto_weakness import scan_crypto
from app.scanners.cwe_mappings import enrich_finding_tags
from app.scanners.dedup import deduplicate_findings
from app.scanners.dependencies import scan_dependencies
from app.scanners.devops import scan_devops
from app.scanners.entropy_secrets import scan_entropy_secrets
from app.scanners.git_history import scan_git_history
from app.scanners.graphql_scanner import scan_graphql_static
from app.scanners.iac_scanner import scan_iac
from app.scanners.performance import scan_performance
from app.scanners.quality import scan_quality
from app.scanners.reachability import annotate_reachability
from app.scanners.secret_validator import is_validation_enabled, validate_secret_findings
from app.scanners.secrets import scan_secrets
from app.scanners.security import scan_security_patterns
from app.scanners.semgrep_scanner import scan_semgrep
from app.scanners.supply_chain import scan_supply_chain
from app.scanners.taint_analysis import scan_taint
from app.scanners.websocket_scanner import scan_websocket_static


def run_all_scanners(project_dir: Path) -> tuple[list[ScanFinding], list[str]]:
    """Run all available scanners and return findings + scanners used."""
    scanners_used: list[str] = []
    all_findings: list[ScanFinding] = []

    secret_findings = scan_secrets(project_dir)
    if secret_findings is not None:
        scanners_used.append("secrets")
        validated = validate_secret_findings(secret_findings)
        if is_validation_enabled() and any(
            f.metadata.get("validated") and f.metadata["validated"] not in ("skipped", "no_validator", "duplicate")
            for f in validated
        ):
            scanners_used.append("secret-validator")
        all_findings.extend(validated)

    entropy_findings = scan_entropy_secrets(project_dir)
    if entropy_findings:
        scanners_used.append("entropy-secrets")
        all_findings.extend(entropy_findings)

    git_findings = scan_git_history(project_dir)
    if git_findings:
        scanners_used.append("git-history")
        all_findings.extend(git_findings)

    bandit_findings = scan_bandit(project_dir)
    if bandit_findings:
        scanners_used.append("bandit")
        all_findings.extend(bandit_findings)

    security_findings = scan_security_patterns(project_dir)
    scanners_used.append("security-patterns")
    all_findings.extend(security_findings)

    semgrep_findings = scan_semgrep(project_dir)
    if semgrep_findings:
        scanners_used.append("semgrep")
        all_findings.extend(semgrep_findings)

    taint_findings = scan_taint(project_dir)
    if taint_findings:
        scanners_used.append("taint-analysis")
        all_findings.extend(taint_findings)

    dep_findings = scan_dependencies(project_dir)
    if dep_findings:
        scanners_used.append("osv")
        dep_findings = annotate_reachability(dep_findings, project_dir)
        if any(f.metadata.get("reachable") for f in dep_findings):
            scanners_used.append("reachability")
    all_findings.extend(dep_findings)

    supply_findings = scan_supply_chain(project_dir)
    if supply_findings:
        scanners_used.append("supply-chain")
        all_findings.extend(supply_findings)

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

    iac_findings = scan_iac(project_dir)
    if iac_findings:
        scanners_used.append("iac")
        all_findings.extend(iac_findings)

    crypto_findings = scan_crypto(project_dir)
    if crypto_findings:
        scanners_used.append("crypto-weakness")
        all_findings.extend(crypto_findings)

    gql_static = scan_graphql_static(project_dir)
    if gql_static:
        scanners_used.append("graphql-security")
        all_findings.extend(gql_static)

    ws_static = scan_websocket_static(project_dir)
    if ws_static:
        scanners_used.append("websocket-security")
        all_findings.extend(ws_static)

    all_findings = [
        enrich_finding_tags(f) for f in deduplicate_findings(all_findings)
    ]

    return all_findings, scanners_used
