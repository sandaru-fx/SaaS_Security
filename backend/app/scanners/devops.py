"""DevOps and deployment hygiene checks."""

from __future__ import annotations

import re
from pathlib import Path

from app.scanners.base import ScanFinding
from app.scanners.utils import iter_files, read_lines, rel_path, should_skip


def scan_devops(project_dir: Path) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    findings.extend(_scan_env_files(project_dir))
    findings.extend(_scan_gitignore(project_dir))
    findings.extend(_scan_ci_cd(project_dir))
    findings.extend(_scan_docker(project_dir))
    return findings


def _scan_env_files(project_dir: Path) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    risky_names = {".env", ".env.local", ".env.production", ".env.development"}

    for file_path in iter_files(project_dir, include_names=risky_names):
        if should_skip(file_path):
            continue
        name = file_path.name.lower()
        if name.endswith(".example") or "sample" in name:
            continue
        rel = rel_path(file_path, project_dir)
        lines = read_lines(file_path) or []
        secret_like = any(
            re.search(r"(?i)(password|secret|api[_-]?key|token)\s*=", line)
            for line in lines[:30]
        )
        findings.append(
            ScanFinding(
                category="devops",
                severity="critical" if secret_like else "high",
                title="Environment file committed to repository",
                description=(
                    f"`{rel}` appears to be a real environment file in the repo."
                ),
                impact="Secrets in version control can be leaked via Git history forever.",
                fix_recommendation=(
                    "Remove the file from Git, rotate any exposed secrets, "
                    "and use `.env.example` with placeholder values only."
                ),
                file_path=rel,
                line_start=1,
                line_end=min(len(lines), 5),
                rule_id="env-in-repo",
                scanner="devops",
                confidence="high" if secret_like else "medium",
            )
        )
    return findings


def _scan_gitignore(project_dir: Path) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    gitignore = project_dir / ".gitignore"
    if not gitignore.exists():
        findings.append(
            ScanFinding(
                category="devops",
                severity="medium",
                title="Missing .gitignore file",
                description="No `.gitignore` found at the project root.",
                impact="Build artifacts and secrets may be accidentally committed.",
                fix_recommendation=(
                    "Add a `.gitignore` covering dependencies, build output, "
                    "and environment files."
                ),
                file_path="",
                line_start=0,
                line_end=0,
                rule_id="missing-gitignore",
                scanner="devops",
                confidence="high",
            )
        )
        return findings

    content = "\n".join(read_lines(gitignore) or []).lower()
    required_entries = [".env", "node_modules", "__pycache__"]
    missing = [entry for entry in required_entries if entry not in content]
    if missing:
        findings.append(
            ScanFinding(
                category="devops",
                severity="low",
                title="Incomplete .gitignore",
                description=f"`.gitignore` is missing recommended entries: {', '.join(missing)}.",
                impact="Common sensitive or bulky paths may still be committed.",
                fix_recommendation=f"Add these entries to `.gitignore`: {', '.join(missing)}.",
                file_path=".gitignore",
                line_start=0,
                line_end=0,
                rule_id="incomplete-gitignore",
                scanner="devops",
                confidence="medium",
            )
        )
    return findings


def _scan_ci_cd(project_dir: Path) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    ci_paths = [
        project_dir / ".github" / "workflows",
        project_dir / ".gitlab-ci.yml",
        project_dir / "Jenkinsfile",
        project_dir / ".circleci",
    ]
    has_ci = any(
        (path.is_file() or (path.is_dir() and any(path.iterdir())))
        for path in ci_paths
        if path.exists()
    )
    if not has_ci:
        findings.append(
            ScanFinding(
                category="devops",
                severity="medium",
                title="No CI/CD pipeline detected",
                description=(
                    "No GitHub Actions, GitLab CI, Jenkins, or CircleCI config found."
                ),
                impact="Changes ship without automated tests or security checks.",
                fix_recommendation=(
                    "Add a CI workflow that runs tests, linting, and security "
                    "scans on every pull request."
                ),
                file_path="",
                line_start=0,
                line_end=0,
                rule_id="missing-ci",
                scanner="devops",
                confidence="medium",
            )
        )
    return findings


def _scan_docker(project_dir: Path) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    dockerfiles = list(project_dir.rglob("Dockerfile*"))
    dockerfiles = [p for p in dockerfiles if not should_skip(p)]

    for dockerfile in dockerfiles:
        rel = rel_path(dockerfile, project_dir)
        lines = read_lines(dockerfile) or []
        content = "\n".join(lines)
        lower = content.lower()

        if "user " not in lower and "user=" not in lower:
            findings.append(
                ScanFinding(
                    category="devops",
                    severity="medium",
                    title="Docker container may run as root",
                    description=f"`{rel}` does not set a non-root USER.",
                    impact="Container escape vulnerabilities have greater impact when running as root.",
                    fix_recommendation=(
                        "Add a non-root USER instruction before the container CMD/ENTRYPOINT."
                    ),
                    file_path=rel,
                    line_start=1,
                    line_end=len(lines),
                    rule_id="docker-root-user",
                    scanner="devops",
                    confidence="medium",
                )
            )

        if re.search(r"(?i)^\s*FROM\s+\w+\s*$", content, re.MULTILINE):
            findings.append(
                ScanFinding(
                    category="devops",
                    severity="low",
                    title="Docker base image without pinned tag",
                    description=f"`{rel}` uses an unpinned `FROM` image tag.",
                    impact="Builds may pull different image versions over time, causing drift.",
                    fix_recommendation="Pin base images to a specific version or digest.",
                    file_path=rel,
                    line_start=1,
                    line_end=3,
                    rule_id="docker-unpinned-base",
                    scanner="devops",
                    confidence="low",
                )
            )

        if "healthcheck" not in lower and "heathcheck" not in lower:
            findings.append(
                ScanFinding(
                    category="devops",
                    severity="low",
                    title="Dockerfile missing HEALTHCHECK",
                    description=f"No HEALTHCHECK instruction in `{rel}`.",
                    impact="Orchestrators cannot automatically detect unhealthy containers.",
                    fix_recommendation="Add a HEALTHCHECK that verifies the app responds correctly.",
                    file_path=rel,
                    line_start=0,
                    line_end=0,
                    rule_id="docker-no-healthcheck",
                    scanner="devops",
                    confidence="low",
                )
            )

    compose_files = [
        p for p in project_dir.rglob("docker-compose*.yml")
        if not should_skip(p)
    ] + [
        p for p in project_dir.rglob("docker-compose*.yaml")
        if not should_skip(p)
    ]
    for compose in compose_files:
        rel = rel_path(compose, project_dir)
        content = "\n".join(read_lines(compose) or [])
        if re.search(r"(?i)password\s*:\s*['\"]?(admin|password|secret|changeme)", content):
            findings.append(
                ScanFinding(
                    category="devops",
                    severity="high",
                    title="Weak default password in docker-compose",
                    description=f"Default credentials found in `{rel}`.",
                    impact="Weak passwords in compose files are often reused in production.",
                    fix_recommendation="Use environment variables and strong, unique secrets.",
                    file_path=rel,
                    line_start=0,
                    line_end=0,
                    rule_id="compose-weak-password",
                    scanner="devops",
                    confidence="high",
                )
            )

    return findings
