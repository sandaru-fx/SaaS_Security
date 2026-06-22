import json
import shutil
import subprocess
from pathlib import Path

from app.scanners.base import ScanFinding
from app.scanners.secrets import SKIP_DIRS


def scan_semgrep(project_dir: Path) -> list[ScanFinding]:
    if not shutil.which("semgrep"):
        return []

    try:
        result = subprocess.run(
            [
                "semgrep",
                "--config", "auto",
                "--json",
                "--quiet",
                str(project_dir),
            ],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return []

    if result.returncode not in (0, 1) or not result.stdout.strip():
        return []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    findings: list[ScanFinding] = []
    for item in data.get("results", []):
        extra = item.get("extra", {})
        metadata = extra.get("metadata", {})
        severity = _map_severity(metadata.get("impact", extra.get("severity", "WARNING")))
        rel_path = item.get("path", "")
        try:
            rel_path = str(Path(rel_path).relative_to(project_dir))
        except ValueError:
            pass

        findings.append(
            ScanFinding(
                category="security",
                severity=severity,
                title=extra.get("message", "Semgrep security finding"),
                description=extra.get("message", "Security issue detected by Semgrep"),
                impact=metadata.get("impact", "Security vulnerability detected by static analysis."),
                fix_recommendation=metadata.get("fix", "Follow Semgrep remediation guidance."),
                file_path=rel_path,
                line_start=item.get("start", {}).get("line", 0),
                line_end=item.get("end", {}).get("line", 0),
                rule_id=item.get("check_id", "semgrep-rule"),
                scanner="semgrep",
                confidence="high",
            )
        )

    return findings


def _map_severity(value: str) -> str:
    mapping = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "WARNING": "medium",
        "ERROR": "high",
        "INFO": "low",
    }
    return mapping.get(str(value).upper(), "medium")
