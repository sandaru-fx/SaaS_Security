"""Python AST security analysis via Bandit (optional CLI)."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from app.scanners.base import ScanFinding
from app.scanners.cwe_mappings import enrich_finding_tags, lookup_rule_tags


def scan_bandit(project_dir: Path) -> list[ScanFinding]:
    if not shutil.which("bandit"):
        return []

    try:
        result = subprocess.run(
            [
                "bandit",
                "-r",
                str(project_dir),
                "-f",
                "json",
                "-q",
                "--exclude",
                ".venv,venv,node_modules,.git",
            ],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return []

    if not result.stdout.strip():
        return []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    findings: list[ScanFinding] = []
    for item in data.get("results", []):
        rel_path = item.get("filename", "")
        try:
            rel_path = str(Path(rel_path).relative_to(project_dir))
        except ValueError:
            pass

        issue = item.get("issue_text", "Bandit security issue")
        severity = _map_severity(item.get("issue_severity", "MEDIUM"))
        cwe_id = None
        cwe_meta = item.get("issue_cwe", {})
        if isinstance(cwe_meta, dict) and cwe_meta.get("id"):
            cwe_id = f"CWE-{cwe_meta['id']}"

        finding = ScanFinding(
            category="security",
            severity=severity,
            title=f"Bandit: {item.get('test_name', 'security issue')}",
            description=issue,
            impact="Static AST analysis detected a potential security weakness in Python code.",
            fix_recommendation=item.get("issue_text", "Review Bandit recommendation."),
            file_path=rel_path,
            line_start=item.get("line_number", 0),
            line_end=item.get("line_number", 0),
            rule_id=f"bandit-{item.get('test_id', 'B000')}",
            scanner="bandit",
            confidence="high",
            metadata={"cwe_id": cwe_id} if cwe_id else {},
        )
        if cwe_id:
            finding.metadata["cwe_id"] = cwe_id
            tags = lookup_rule_tags(cwe_id, "bandit")
            if tags.get("owasp_category"):
                finding.metadata["owasp_category"] = tags["owasp_category"]
        findings.append(enrich_finding_tags(finding))

    return findings


def _map_severity(value: str) -> str:
    mapping = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    return mapping.get(str(value).upper(), "medium")
