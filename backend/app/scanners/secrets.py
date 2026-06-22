import re
from pathlib import Path

from app.scanners.base import ScanFinding

SKIP_DIRS = {
    "node_modules",
    ".git",
    ".next",
    "venv",
    ".venv",
    "dist",
    "build",
    "__pycache__",
}

SECRET_PATTERNS: list[tuple[str, str, str, str]] = [
    (
        "aws-access-key",
        r"(?i)(AKIA[0-9A-Z]{16})",
        "critical",
        "AWS Access Key ID exposed in source code",
    ),
    (
        "github-token",
        r"(ghp_[A-Za-z0-9]{36,})",
        "critical",
        "GitHub personal access token found",
    ),
    (
        "generic-api-key",
        r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]",
        "high",
        "Hardcoded API key assignment detected",
    ),
    (
        "password-in-code",
        r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{6,})['\"]",
        "high",
        "Hardcoded password found in source code",
    ),
    (
        "private-key",
        r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "critical",
        "Private key embedded in repository",
    ),
    (
        "jwt-secret",
        r"(?i)(jwt[_-]?secret|secret[_-]?key)\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
        "high",
        "JWT or application secret hardcoded",
    ),
]

TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".json", ".env", ".yaml", ".yml",
    ".toml", ".ini", ".cfg", ".conf", ".sql", ".sh", ".bash", ".ps1",
    ".java", ".go", ".rs", ".php", ".rb", ".cs", ".xml", ".html", ".css",
}


def scan_secrets(project_dir: Path) -> list[ScanFinding]:
    findings: list[ScanFinding] = []

    for file_path in _iter_files(project_dir):
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        if _is_probably_example(file_path, content):
            continue

        for line_no, line in enumerate(content.splitlines(), start=1):
            for rule_id, pattern, severity, title in SECRET_PATTERNS:
                if re.search(pattern, line):
                    rel_path = str(file_path.relative_to(project_dir))
                    findings.append(
                        ScanFinding(
                            category="secrets",
                            severity=severity,
                            title=title,
                            description=f"Potential secret detected in `{rel_path}` at line {line_no}.",
                            impact="Credentials in code can leak via Git history and enable unauthorized access.",
                            fix_recommendation=(
                                "Move secrets to environment variables or a secrets manager. "
                                "Rotate any exposed credentials immediately."
                            ),
                            file_path=rel_path,
                            line_start=line_no,
                            line_end=line_no,
                            rule_id=rule_id,
                            scanner="secrets",
                            confidence="high",
                        )
                    )
                    break

    return findings


def _iter_files(project_dir: Path):
    for path in project_dir.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in TEXT_EXTENSIONS or path.name in {".env", ".env.local"}:
            yield path


def _is_probably_example(file_path: Path, content: str) -> bool:
    lower_path = str(file_path).lower()
    if "example" in lower_path or "sample" in lower_path or ".env.example" in lower_path:
        return True
    if "your_key_here" in content or "changeme" in content.lower():
        return True
    return False
