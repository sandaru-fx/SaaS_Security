"""Code quality heuristics — tech debt, long functions, debug noise."""

from __future__ import annotations

import re
from pathlib import Path

from app.scanners.base import ScanFinding
from app.scanners.utils import CODE_EXTENSIONS, iter_code_files, read_lines, rel_path

LONG_FUNCTION_LINES = 80
MAX_TODO_FINDINGS = 15

DEBUG_PATTERNS = [
    (r"(?i)console\.log\s*\(", "console.log left in code"),
    (r"(?i)print\s*\(\s*['\"]debug", "debug print statement"),
    (r"(?i)debugger\s*;", "debugger statement"),
    (r"(?i)pdb\.set_trace\s*\(", "Python debugger breakpoint"),
]


def scan_quality(project_dir: Path) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    findings.extend(_scan_todo_debt(project_dir))
    findings.extend(_scan_long_functions(project_dir))
    findings.extend(_scan_debug_statements(project_dir))
    findings.extend(_scan_duplicate_filenames(project_dir))
    return findings


def _scan_todo_debt(project_dir: Path) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    todo_pattern = re.compile(r"(?i)\b(TODO|FIXME|HACK|XXX)\b[:\s]?(.*)")

    for file_path in iter_code_files(project_dir):
        if file_path.suffix.lower() not in CODE_EXTENSIONS:
            continue
        rel = rel_path(file_path, project_dir)
        if "/test" in f"/{rel.lower()}" or rel.lower().startswith("test"):
            continue
        lines = read_lines(file_path)
        if not lines:
            continue

        for line_no, line in enumerate(lines, start=1):
            match = todo_pattern.search(line)
            if not match:
                continue
            label = match.group(1).upper()
            findings.append(
                ScanFinding(
                    category="quality",
                    severity="low" if label == "TODO" else "medium",
                    title=f"{label} comment — technical debt marker",
                    description=(
                        f"{label} found in `{rel}` line {line_no}: "
                        f"{match.group(2).strip()[:120] or '(no description)'}"
                    ),
                    impact="Unresolved debt accumulates and hides incomplete or risky implementations.",
                    fix_recommendation=(
                        "Create a ticket, implement the fix, or remove the marker "
                        "if no longer relevant."
                    ),
                    file_path=rel,
                    line_start=line_no,
                    line_end=line_no,
                    rule_id="tech-debt-marker",
                    scanner="quality",
                    confidence="high",
                )
            )
            if len(findings) >= MAX_TODO_FINDINGS:
                return findings
    return findings


def _scan_long_functions(project_dir: Path) -> list[ScanFinding]:
    findings: list[ScanFinding] = []

    for file_path in iter_code_files(project_dir):
        if file_path.suffix.lower() not in {".py", ".js", ".ts", ".tsx", ".jsx"}:
            continue
        rel = rel_path(file_path, project_dir)
        lines = read_lines(file_path)
        if not lines:
            continue

        func_starts = []
        for line_no, line in enumerate(lines, start=1):
            if re.match(r"(?i)^\s*(async\s+)?def\s+\w+\s*\(", line):
                func_starts.append((line_no, line.strip()))
            elif re.match(r"(?i)^\s*(export\s+)?(async\s+)?function\s+\w+\s*\(", line):
                func_starts.append((line_no, line.strip()))

        for idx, (start_line, signature) in enumerate(func_starts):
            end_line = func_starts[idx + 1][0] - 1 if idx + 1 < len(func_starts) else len(lines)
            length = end_line - start_line + 1
            if length > LONG_FUNCTION_LINES:
                findings.append(
                    ScanFinding(
                        category="quality",
                        severity="medium" if length < 150 else "high",
                        title=f"Long function ({length} lines)",
                        description=(
                            f"Function starting at `{rel}` line {start_line} spans "
                            f"{length} lines ({signature[:80]})."
                        ),
                        impact="Long functions are harder to test and usually mix multiple responsibilities.",
                        fix_recommendation=(
                            "Extract helper functions or move logic into smaller, "
                            "single-purpose units."
                        ),
                        file_path=rel,
                        line_start=start_line,
                        line_end=end_line,
                        rule_id="long-function",
                        scanner="quality",
                        confidence="medium",
                        metadata={"line_count": length},
                    )
                )
    return findings


def _scan_debug_statements(project_dir: Path) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    reported: set[tuple[str, int]] = set()

    for file_path in iter_code_files(project_dir):
        if file_path.suffix.lower() not in CODE_EXTENSIONS:
            continue
        rel = rel_path(file_path, project_dir)
        lower = rel.lower()
        if any(part in lower for part in ("test", "spec", "__tests__", "mock")):
            continue
        lines = read_lines(file_path)
        if not lines:
            continue

        for line_no, line in enumerate(lines, start=1):
            for pattern, title in DEBUG_PATTERNS:
                if re.search(pattern, line):
                    key = (rel, line_no)
                    if key in reported:
                        continue
                    reported.add(key)
                    findings.append(
                        ScanFinding(
                            category="quality",
                            severity="low",
                            title=title,
                            description=f"Debug statement in `{rel}` line {line_no}.",
                            impact="Debug output can leak data and add noise in production logs.",
                            fix_recommendation=(
                                "Remove debug statements or guard them behind a "
                                "development-only flag."
                            ),
                            file_path=rel,
                            line_start=line_no,
                            line_end=line_no,
                            rule_id="debug-statement",
                            scanner="quality",
                            confidence="high",
                        )
                    )
    return findings


def _scan_duplicate_filenames(project_dir: Path) -> list[ScanFinding]:
    by_name: dict[str, list[str]] = {}
    for file_path in iter_code_files(project_dir):
        if file_path.suffix.lower() not in CODE_EXTENSIONS:
            continue
        rel = rel_path(file_path, project_dir)
        by_name.setdefault(file_path.name.lower(), []).append(rel)

    findings: list[ScanFinding] = []
    for name, paths in by_name.items():
        if len(paths) < 3:
            continue
        if name in {"__init__.py", "index.ts", "index.js", "mod.rs"}:
            continue
        findings.append(
            ScanFinding(
                category="quality",
                severity="low",
                title=f"Duplicate filename `{name}` used {len(paths)} times",
                description=f"The filename `{name}` appears in: {', '.join(paths[:5])}.",
                impact="Duplicate names make navigation and imports confusing.",
                fix_recommendation="Use more specific names that reflect each module's responsibility.",
                file_path=paths[0],
                line_start=0,
                line_end=0,
                rule_id="duplicate-filename",
                scanner="quality",
                confidence="medium",
                metadata={"paths": paths},
            )
        )
    return findings
