import re
from pathlib import Path

from app.scanners.base import ScanFinding
from app.scanners.cwe_mappings import enrich_finding_tags

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
        r"(AKIA[0-9A-Z]{16})",
        "critical",
        "AWS Access Key ID exposed in source code",
    ),
    (
        "github-token",
        r"(ghp_[A-Za-z0-9]{36,255})",
        "critical",
        "GitHub personal access token found",
    ),
    (
        "github-fine-grained-token",
        r"(github_pat_[A-Za-z0-9_]{82})",
        "critical",
        "GitHub fine-grained PAT found",
    ),
    (
        "slack-bot-token",
        r"(xox[abpr]-[A-Za-z0-9-]{10,})",
        "critical",
        "Slack OAuth / bot token exposed",
    ),
    (
        "slack-webhook",
        r"(https://hooks\.slack\.com/services/[A-Z0-9/]+)",
        "high",
        "Slack incoming webhook URL exposed",
    ),
    (
        "discord-webhook",
        r"(https://(?:discord|discordapp)\.com/api/webhooks/\d+/[A-Za-z0-9_-]+)",
        "high",
        "Discord webhook URL exposed",
    ),
    (
        "stripe-secret-key",
        r"(sk_(?:live|test)_[A-Za-z0-9]{24,})",
        "critical",
        "Stripe secret API key exposed",
    ),
    (
        "stripe-restricted-key",
        r"(rk_(?:live|test)_[A-Za-z0-9]{24,})",
        "critical",
        "Stripe restricted key exposed",
    ),
    (
        "sendgrid-api-key",
        r"(SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})",
        "critical",
        "SendGrid API key exposed",
    ),
    (
        "mailgun-api-key",
        r"(key-[A-Za-z0-9]{32})",
        "critical",
        "Mailgun API key exposed",
    ),
    (
        "digitalocean-token",
        r"(dop_v1_[a-f0-9]{64})",
        "critical",
        "DigitalOcean personal access token exposed",
    ),
    (
        "npm-token",
        r"(npm_[A-Za-z0-9]{36})",
        "critical",
        "npm publish token exposed",
    ),
    (
        "openai-key",
        r"(sk-(?:proj-)?[A-Za-z0-9_-]{32,})",
        "critical",
        "OpenAI API key exposed",
    ),
    (
        "google-api-key",
        r"(AIza[0-9A-Za-z_-]{35})",
        "critical",
        "Google / Gemini API key exposed",
    ),
    (
        "generic-api-key",
        r"(?i)(?:api[_-]?key|apikey)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]",
        "high",
        "Hardcoded API key assignment detected",
    ),
    (
        "password-in-code",
        r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{6,})['\"]",
        "high",
        "Hardcoded password found in source code",
    ),
    (
        "private-key",
        r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----)",
        "critical",
        "Private key embedded in repository",
    ),
    (
        "jwt-secret",
        r"(?i)(?:jwt[_-]?secret|secret[_-]?key)\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
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
                match = re.search(pattern, line)
                if not match:
                    continue
                value = match.group(1) if match.groups() else match.group(0)
                if _looks_like_placeholder(value):
                    break
                rel_path = str(file_path.relative_to(project_dir))
                findings.append(
                    enrich_finding_tags(
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
                            metadata={
                                "_secret_value": value,
                                "secret_preview": _preview(value),
                            },
                        )
                    )
                )
                break

    return findings


def _preview(value: str) -> str:
    if len(value) <= 8:
        return value[:2] + "***"
    return value[:4] + "..." + value[-4:]


def _looks_like_placeholder(value: str) -> bool:
    lower = value.lower()
    return any(
        token in lower
        for token in (
            "your-",
            "your_",
            "example",
            "placeholder",
            "xxx",
            "fake",
            "changeme",
            "test_key",
            "dummy",
        )
    )


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
