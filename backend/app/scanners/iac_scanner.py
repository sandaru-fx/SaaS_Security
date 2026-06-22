"""Infrastructure-as-Code security scanner (Terraform, Kubernetes)."""

from __future__ import annotations

import re
from pathlib import Path

from app.scanners.base import ScanFinding
from app.scanners.utils import iter_files, read_lines, rel_path, should_skip

TERRAFORM_EXTENSIONS = {".tf", ".tfvars"}
K8S_EXTENSIONS = {".yaml", ".yml"}


def scan_iac(project_dir: Path) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    findings.extend(_scan_terraform(project_dir))
    findings.extend(_scan_kubernetes(project_dir))
    return findings


def _scan_terraform(project_dir: Path) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    files = [
        p
        for p in iter_files(project_dir, extensions=TERRAFORM_EXTENSIONS)
        if not should_skip(p)
    ]

    for file_path in files:
        lines = read_lines(file_path) or []
        rel = rel_path(file_path, project_dir)

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue

            if re.search(r'0\.0\.0\.0/0', line) and re.search(
                r"(?i)(cidr|ingress|security_group|source)", line
            ):
                findings.append(
                    _finding(
                        severity="high",
                        title="Terraform allows unrestricted network access",
                        description=f"Open CIDR `0.0.0.0/0` in `{rel}` at line {idx}.",
                        impact="Any host on the internet may reach protected resources.",
                        fix="Restrict ingress to known IP ranges or security groups.",
                        file_path=rel,
                        line_start=idx,
                        line_end=idx,
                        rule_id="tf-open-cidr",
                    )
                )

            if re.search(r'(?i)acl\s*=\s*"public-read"', line):
                findings.append(
                    _finding(
                        severity="critical",
                        title="Terraform S3 bucket configured as public-read",
                        description=f"Public-read ACL in `{rel}` at line {idx}.",
                        impact="Sensitive data may be exposed to the public internet.",
                        fix="Use private buckets with IAM policies and block public access.",
                        file_path=rel,
                        line_start=idx,
                        line_end=idx,
                        rule_id="tf-s3-public-read",
                    )
                )

            if re.search(r'(?i)(password|secret|api_key|token)\s*=\s*"[^$"{][^"]{3,}"', line):
                findings.append(
                    _finding(
                        severity="critical",
                        title="Hardcoded secret in Terraform",
                        description=f"Literal credential value in `{rel}` at line {idx}.",
                        impact="Secrets in IaC are committed to version control and shared broadly.",
                        fix="Use Terraform variables, AWS Secrets Manager, or SSM Parameter Store.",
                        file_path=rel,
                        line_start=idx,
                        line_end=idx,
                        rule_id="tf-hardcoded-secret",
                    )
                )

            if re.search(r'(?i)encrypted\s*=\s*false', line):
                findings.append(
                    _finding(
                        severity="high",
                        title="Terraform resource encryption disabled",
                        description=f"`encrypted = false` in `{rel}` at line {idx}.",
                        impact="Data at rest may be readable if storage is compromised.",
                        fix="Enable encryption at rest for databases, disks, and object storage.",
                        file_path=rel,
                        line_start=idx,
                        line_end=idx,
                        rule_id="tf-encryption-disabled",
                    )
                )

    return findings


def _scan_kubernetes(project_dir: Path) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    k8s_files = [
        p
        for p in iter_files(project_dir, extensions=K8S_EXTENSIONS)
        if not should_skip(p) and _looks_like_k8s(p)
    ]

    for file_path in k8s_files:
        lines = read_lines(file_path) or []
        rel = rel_path(file_path, project_dir)
        content = "\n".join(lines)

        for idx, line in enumerate(lines, start=1):
            if re.search(r'(?i)privileged:\s*true', line):
                findings.append(
                    _finding(
                        severity="critical",
                        title="Kubernetes container runs privileged",
                        description=f"`privileged: true` in `{rel}` at line {idx}.",
                        impact="Privileged containers can escape to the host node.",
                        fix="Remove privileged mode unless strictly required and isolate the workload.",
                        file_path=rel,
                        line_start=idx,
                        line_end=idx,
                        rule_id="k8s-privileged-container",
                    )
                )

            if re.search(r'(?i)runAsUser:\s*0\b', line):
                findings.append(
                    _finding(
                        severity="high",
                        title="Kubernetes pod runs as root",
                        description=f"`runAsUser: 0` in `{rel}` at line {idx}.",
                        impact="Root in a container increases blast radius on compromise.",
                        fix="Set securityContext.runAsNonRoot and a non-zero runAsUser.",
                        file_path=rel,
                        line_start=idx,
                        line_end=idx,
                        rule_id="k8s-run-as-root",
                    )
                )

            if re.search(r'(?i)(hostNetwork|hostPID|hostIPC):\s*true', line):
                findings.append(
                    _finding(
                        severity="high",
                        title="Kubernetes pod uses host namespace",
                        description=f"Host namespace enabled in `{rel}` at line {idx}.",
                        impact="Pods can access host network or processes, weakening isolation.",
                        fix="Disable hostNetwork/hostPID/hostIPC unless required for system daemons.",
                        file_path=rel,
                        line_start=idx,
                        line_end=idx,
                        rule_id="k8s-host-namespace",
                    )
                )

        if re.search(r'(?i)image:\s*["\']?[^:"\']+:(latest|)\s*["\']?', content):
            for idx, line in enumerate(lines, start=1):
                if re.search(r'(?i)image:\s*["\']?[^:"\']+:latest', line) or re.search(
                    r'(?i)image:\s*["\']?[^:"\']+["\']?\s*$', line
                ):
                    findings.append(
                        _finding(
                            severity="medium",
                            title="Kubernetes image tag not pinned",
                            description=f"Unpinned or `latest` image in `{rel}` at line {idx}.",
                            impact="Deployments may pull different image versions unpredictably.",
                            fix="Pin images to immutable tags or digests.",
                            file_path=rel,
                            line_start=idx,
                            line_end=idx,
                            rule_id="k8s-unpinned-image",
                        )
                    )
                    break

        if re.search(r'(?i)type:\s*LoadBalancer', content) and not re.search(
            r'(?i)(networkPolicy|NetworkPolicy)', content
        ):
            findings.append(
                _finding(
                    severity="medium",
                    title="Kubernetes LoadBalancer without network policy",
                    description=f"LoadBalancer service in `{rel}` without a NetworkPolicy reference.",
                    impact="Exposed services may accept traffic from any source.",
                    fix="Add NetworkPolicy rules to restrict ingress to the load balancer.",
                    file_path=rel,
                    line_start=1,
                    line_end=min(len(lines), 20),
                    rule_id="k8s-loadbalancer-no-netpol",
                )
            )

    return findings


def _looks_like_k8s(path: Path) -> bool:
    name = path.name.lower()
    if any(
        token in name
        for token in ("deployment", "service", "ingress", "configmap", "secret", "statefulset", "daemonset", "cronjob", "job", "helm")
    ):
        return True
    try:
        head = path.read_text(encoding="utf-8", errors="ignore")[:500]
    except OSError:
        return False
    return "apiVersion:" in head and "kind:" in head


def _finding(
    *,
    severity: str,
    title: str,
    description: str,
    impact: str,
    fix: str,
    file_path: str,
    line_start: int,
    line_end: int,
    rule_id: str,
) -> ScanFinding:
    return ScanFinding(
        category="iac",
        severity=severity,
        title=title,
        description=description,
        impact=impact,
        fix_recommendation=fix,
        file_path=file_path,
        line_start=line_start,
        line_end=line_end,
        rule_id=rule_id,
        scanner="iac",
        confidence="high",
    )
