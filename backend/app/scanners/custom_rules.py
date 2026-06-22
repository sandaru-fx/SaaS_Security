"""Run user-defined custom regex rules during audits."""

from __future__ import annotations

import re
from pathlib import Path

from app.models.enterprise import CustomRule
from app.scanners.base import ScanFinding
from app.scanners.utils import iter_code_files, read_lines, rel_path


def scan_custom_rules(project_dir: Path, rules: list[CustomRule]) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    active = [rule for rule in rules if rule.enabled]

    for rule in active:
        try:
            pattern = re.compile(rule.pattern)
        except re.error:
            continue

        for file_path in iter_code_files(project_dir):
            lines = read_lines(file_path)
            if not lines:
                continue
            rel = rel_path(file_path, project_dir)
            for line_no, line in enumerate(lines, start=1):
                if pattern.search(line):
                    findings.append(
                        ScanFinding(
                            category=rule.category,
                            severity=rule.severity,
                            title=f"Custom rule: {rule.name}",
                            description=(
                                f"Custom rule `{rule.name}` matched in `{rel}` line {line_no}."
                            ),
                            impact="Violates your organization's custom audit policy.",
                            fix_recommendation="Review and remediate according to your custom rule.",
                            file_path=rel,
                            line_start=line_no,
                            line_end=line_no,
                            rule_id=f"custom-{rule.id}",
                            scanner="custom-rules",
                            confidence="high",
                        )
                    )
    return findings
