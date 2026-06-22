"""High-entropy string detection for potential secrets."""

from __future__ import annotations

import math
import re
from pathlib import Path

from app.scanners.base import ScanFinding
from app.scanners.cwe_mappings import enrich_finding_tags
from app.scanners.secrets import SKIP_DIRS, TEXT_EXTENSIONS, _is_probably_example

ASSIGNMENT_PATTERN = re.compile(
    r"(?i)(?:api[_-]?key|secret|token|password|passwd|auth|credential)\s*[:=]\s*['\"]([^'\"]{12,})['\"]"
)
ENTROPY_THRESHOLD = 3.8
MIN_SECRET_LEN = 16


def scan_entropy_secrets(project_dir: Path) -> list[ScanFinding]:
    findings: list[ScanFinding] = []

    for file_path in _iter_files(project_dir):
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if _is_probably_example(file_path, content):
            continue

        rel_path = str(file_path.relative_to(project_dir))
        for line_no, line in enumerate(content.splitlines(), start=1):
            for match in ASSIGNMENT_PATTERN.finditer(line):
                value = match.group(1)
                if _looks_like_placeholder(value):
                    continue
                entropy = _shannon_entropy(value)
                if entropy >= ENTROPY_THRESHOLD and len(value) >= MIN_SECRET_LEN:
                    findings.append(
                        enrich_finding_tags(
                            ScanFinding(
                                category="secrets",
                                severity="high",
                                title="High-entropy secret-like value detected",
                                description=(
                                    f"Variable assignment in `{rel_path}` line {line_no} "
                                    f"contains a high-entropy string (entropy={entropy:.2f})."
                                ),
                                impact="High-entropy literals often indicate API keys or tokens embedded in code.",
                                fix_recommendation=(
                                    "Move secrets to environment variables or a secrets manager. "
                                    "Rotate credentials if this value was ever committed."
                                ),
                                file_path=rel_path,
                                line_start=line_no,
                                line_end=line_no,
                                rule_id="high-entropy-secret",
                                scanner="entropy-secrets",
                                confidence="medium",
                                metadata={"entropy": round(entropy, 2)},
                            )
                        )
                    )
    return findings


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _looks_like_placeholder(value: str) -> bool:
    lower = value.lower()
    placeholders = (
        "your_", "changeme", "example", "placeholder", "xxx", "todo",
        "insert_", "replace_", "dummy", "test_", "sample",
    )
    return any(p in lower for p in placeholders)


def _iter_files(project_dir: Path):
    for path in project_dir.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in TEXT_EXTENSIONS or path.name in {".env", ".env.local"}:
            yield path
