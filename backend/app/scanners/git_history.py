"""Scan git commit history for leaked secrets (when .git is present)."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from app.scanners.base import ScanFinding
from app.scanners.cwe_mappings import enrich_finding_tags
from app.scanners.secrets import SECRET_PATTERNS

MAX_COMMITS = 200
GIT_TIMEOUT = 90


def scan_git_history(project_dir: Path) -> list[ScanFinding]:
    git_dir = project_dir / ".git"
    if not git_dir.exists() or not shutil.which("git"):
        return []

    try:
        result = subprocess.run(
            [
                "git",
                "-C",
                str(project_dir),
                "log",
                "-p",
                "--all",
                f"-{MAX_COMMITS}",
                "--no-color",
            ],
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return []

    if result.returncode != 0 or not result.stdout:
        return []

    findings: list[ScanFinding] = []
    current_commit = "unknown"
    seen: set[tuple[str, str]] = set()

    for line in result.stdout.splitlines():
        if line.startswith("commit "):
            current_commit = line.split()[1][:12]
            continue
        if not (line.startswith("+") and not line.startswith("+++")):
            continue
        added = line[1:]
        for rule_id, pattern, severity, title in SECRET_PATTERNS:
            if re.search(pattern, added):
                key = (current_commit, rule_id)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    enrich_finding_tags(
                        ScanFinding(
                            category="secrets",
                            severity=severity,
                            title=f"Git history: {title}",
                            description=(
                                f"Secret pattern `{rule_id}` found in commit {current_commit} "
                                "history (added line in patch)."
                            ),
                            impact=(
                                "Secrets in git history remain accessible even after deletion "
                                "from current files. Attackers can recover them from clones."
                            ),
                            fix_recommendation=(
                                "Rotate the exposed credential immediately. "
                                "Use git filter-repo or BFG Repo-Cleaner to purge history, "
                                "then force-push with team coordination."
                            ),
                            file_path=f".git/log@{current_commit}",
                            line_start=0,
                            line_end=0,
                            rule_id=f"git-history-{rule_id}",
                            scanner="git-history",
                            confidence="high",
                            metadata={"commit": current_commit},
                        )
                    )
                )
                break
    return findings
