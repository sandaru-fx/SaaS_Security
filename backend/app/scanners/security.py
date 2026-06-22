import re
from pathlib import Path

from app.scanners.base import ScanFinding
from app.scanners.secrets import SKIP_DIRS, TEXT_EXTENSIONS

SECURITY_PATTERNS: list[tuple[str, str, str, str]] = [
    (
        "sql-injection-concat",
        r"(?i)(execute|query|cursor\.execute)\s*\(\s*['\"][^'\"]*\{",
        "high",
        "Possible SQL injection via string formatting",
    ),
    (
        "sql-injection-plus",
        r"(?i)(SELECT|INSERT|UPDATE|DELETE).+['\"]\s*\+",
        "high",
        "SQL query built with string concatenation",
    ),
    (
        "xss-innerhtml",
        r"(?i)\.innerHTML\s*=",
        "medium",
        "Direct innerHTML assignment may cause XSS",
    ),
    (
        "dangerous-eval",
        r"(?i)\beval\s*\(",
        "high",
        "Use of eval() can lead to code injection",
    ),
    (
        "dangerous-exec",
        r"(?i)\bexec\s*\(",
        "high",
        "Use of exec() can lead to code injection",
    ),
    (
        "insecure-cors",
        r"(?i)Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]?\*",
        "medium",
        "Wildcard CORS policy detected",
    ),
    (
        "missing-https",
        r"(?i)http://(?!localhost|127\.0\.0\.1)",
        "low",
        "Insecure HTTP URL used (non-localhost)",
    ),
    (
        "debug-enabled",
        r"(?i)(DEBUG|debug)\s*[:=]\s*True",
        "medium",
        "Debug mode may be enabled in production config",
    ),
]


def scan_security_patterns(project_dir: Path) -> list[ScanFinding]:
    findings: list[ScanFinding] = []

    for file_path in _iter_files(project_dir):
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue

        rel_path = str(file_path.relative_to(project_dir))

        for line_no, line in enumerate(lines, start=1):
            for rule_id, pattern, severity, title in SECURITY_PATTERNS:
                if re.search(pattern, line):
                    findings.append(
                        ScanFinding(
                            category="security",
                            severity=severity,
                            title=title,
                            description=f"Security pattern `{rule_id}` matched in `{rel_path}` line {line_no}.",
                            impact=_impact_for_rule(rule_id),
                            fix_recommendation=_fix_for_rule(rule_id),
                            file_path=rel_path,
                            line_start=line_no,
                            line_end=line_no,
                            rule_id=rule_id,
                            scanner="security-patterns",
                            confidence="medium",
                        )
                    )

    return findings


def _iter_files(project_dir: Path):
    for path in project_dir.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in TEXT_EXTENSIONS:
            yield path


def _impact_for_rule(rule_id: str) -> str:
    impacts = {
        "sql-injection-concat": "Attackers could read or modify database data.",
        "sql-injection-plus": "Attackers could execute arbitrary SQL queries.",
        "xss-innerhtml": "Malicious scripts could run in user browsers.",
        "dangerous-eval": "Untrusted input could execute arbitrary code.",
        "dangerous-exec": "Untrusted input could execute arbitrary code.",
        "insecure-cors": "Cross-origin attacks from malicious websites become easier.",
        "missing-https": "Data may be intercepted in transit.",
        "debug-enabled": "Verbose errors can leak sensitive system information.",
    }
    return impacts.get(rule_id, "May introduce security vulnerabilities.")


def _fix_for_rule(rule_id: str) -> str:
    fixes = {
        "sql-injection-concat": "Use parameterized queries or an ORM instead of string formatting.",
        "sql-injection-plus": "Use parameterized queries with bound parameters.",
        "xss-innerhtml": "Use textContent or sanitize HTML with a trusted library.",
        "dangerous-eval": "Avoid eval(); use safe parsing alternatives.",
        "dangerous-exec": "Avoid exec(); use safe APIs with validated input.",
        "insecure-cors": "Restrict CORS to specific trusted origins.",
        "missing-https": "Use HTTPS URLs for all external communications.",
        "debug-enabled": "Disable debug mode in production environments.",
    }
    return fixes.get(rule_id, "Review and remediate according to security best practices.")
