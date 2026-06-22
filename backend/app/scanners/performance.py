"""Performance pattern heuristics."""

from __future__ import annotations

import re
from pathlib import Path

from app.scanners.base import ScanFinding
from app.scanners.utils import CODE_EXTENSIONS, is_route_file, iter_code_files, read_lines, rel_path

PERFORMANCE_PATTERNS: list[tuple[str, str, str, str]] = [
    (
        "n-plus-one-query",
        r"(?i)for\s+\w+\s+in\s+\w+.*:\s*$",
        "high",
        "Loop may trigger N+1 database queries",
    ),
    (
        "unbounded-fetch",
        r"(?i)\.(all|fetchall|find\(\))\s*\(",
        "medium",
        "Unbounded data fetch without pagination",
    ),
    (
        "sync-sleep-in-handler",
        r"(?i)(time\.sleep|Thread\.sleep)\s*\(",
        "high",
        "Blocking sleep in request path",
    ),
    (
        "large-payload-json",
        r"(?i)json\.loads?\s*\(\s*request\.(body|data|get_data)",
        "medium",
        "Parsing full request body in memory",
    ),
    (
        "missing-cache-header",
        r"(?i)@app\.route|@router\.(get|post)",
        "low",
        "HTTP route without obvious caching strategy",
    ),
]

IN_LOOP_DB_PATTERNS = [
    r"(?i)\.query\s*\(",
    r"(?i)\.execute\s*\(",
    r"(?i)session\.get\s*\(",
    r"(?i)findOne\s*\(",
    r"(?i)findById\s*\(",
]


def scan_performance(project_dir: Path) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    findings.extend(_scan_performance_patterns(project_dir))
    findings.extend(_scan_n_plus_one(project_dir))
    findings.extend(_scan_sync_in_async(project_dir))
    return findings


def _scan_performance_patterns(project_dir: Path) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    reported: set[tuple[str, str]] = set()

    for file_path in iter_code_files(project_dir):
        if file_path.suffix.lower() not in CODE_EXTENSIONS:
            continue
        rel = rel_path(file_path, project_dir)
        lines = read_lines(file_path)
        if not lines:
            continue

        for line_no, line in enumerate(lines, start=1):
            for rule_id, pattern, severity, title in PERFORMANCE_PATTERNS:
                if rule_id == "missing-cache-header" and not is_route_file(rel):
                    continue
                if rule_id == "unbounded-fetch" and not is_route_file(rel):
                    continue
                if not re.search(pattern, line):
                    continue
                key = (rel, rule_id)
                if key in reported:
                    continue
                reported.add(key)
                findings.append(
                    ScanFinding(
                        category="performance",
                        severity=severity,
                        title=title,
                        description=(
                            f"Performance pattern `{rule_id}` in `{rel}` line {line_no}."
                        ),
                        impact=_impact_for_rule(rule_id),
                        fix_recommendation=_fix_for_rule(rule_id),
                        file_path=rel,
                        line_start=line_no,
                        line_end=line_no,
                        rule_id=rule_id,
                        scanner="performance",
                        confidence="medium",
                    )
                )
    return findings


def _scan_n_plus_one(project_dir: Path) -> list[ScanFinding]:
    findings: list[ScanFinding] = []

    for file_path in iter_code_files(project_dir):
        if file_path.suffix.lower() not in {".py", ".js", ".ts", ".php"}:
            continue
        rel = rel_path(file_path, project_dir)
        lines = read_lines(file_path)
        if not lines:
            continue

        for line_no, line in enumerate(lines, start=1):
            if not re.search(r"(?i)^\s*for\s+\w+\s+in\s+", line):
                continue
            block = lines[line_no : min(line_no + 8, len(lines))]
            for inner in block:
                for pattern in IN_LOOP_DB_PATTERNS:
                    if re.search(pattern, inner):
                        findings.append(
                            ScanFinding(
                                category="performance",
                                severity="high",
                                title="Probable N+1 query inside loop",
                                description=(
                                    f"Database access inside a loop in `{rel}` "
                                    f"around line {line_no}."
                                ),
                                impact=(
                                    "Each iteration may hit the database, causing "
                                    "severe latency under load."
                                ),
                                fix_recommendation=(
                                    "Use eager loading, batch queries, or JOINs "
                                    "to fetch related data in one round-trip."
                                ),
                                file_path=rel,
                                line_start=line_no,
                                line_end=line_no + len(block),
                                rule_id="n-plus-one-in-loop",
                                scanner="performance",
                                confidence="medium",
                            )
                        )
                        break
                else:
                    continue
                break
    return findings


def _scan_sync_in_async(project_dir: Path) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    patterns = [
        (r"(?i)requests\.(get|post|put|delete)\s*\(", "sync HTTP client in async code"),
        (r"(?i)urllib\.request", "blocking urllib in async code"),
        (r"(?i)subprocess\.(run|call|Popen)", "subprocess call may block event loop"),
    ]

    for file_path in iter_code_files(project_dir):
        if file_path.suffix.lower() != ".py":
            continue
        rel = rel_path(file_path, project_dir)
        content = "\n".join(read_lines(file_path) or [])
        if "async def" not in content:
            continue
        lines = content.splitlines()
        for line_no, line in enumerate(lines, start=1):
            for pattern, title in patterns:
                if re.search(pattern, line):
                    findings.append(
                        ScanFinding(
                            category="performance",
                            severity="medium",
                            title=title,
                            description=f"Blocking call in async module `{rel}` line {line_no}.",
                            impact="Blocks the event loop and reduces concurrent request throughput.",
                            fix_recommendation=(
                                "Use async libraries (httpx.AsyncClient, aiohttp) "
                                "or run blocking work in a thread pool."
                            ),
                            file_path=rel,
                            line_start=line_no,
                            line_end=line_no,
                            rule_id="blocking-in-async",
                            scanner="performance",
                            confidence="medium",
                        )
                    )
    return findings


def _impact_for_rule(rule_id: str) -> str:
    return {
        "n-plus-one-query": "Database load grows linearly with collection size.",
        "unbounded-fetch": "Large result sets increase memory use and response times.",
        "sync-sleep-in-handler": "Request threads stay occupied, reducing capacity.",
        "large-payload-json": "Large bodies can exhaust memory on concurrent requests.",
        "missing-cache-header": "Repeated identical work on every request.",
    }.get(rule_id, "May degrade application performance under load.")


def _fix_for_rule(rule_id: str) -> str:
    return {
        "n-plus-one-query": "Batch related queries or use ORM eager loading.",
        "unbounded-fetch": "Add pagination (limit/offset or cursor-based).",
        "sync-sleep-in-handler": "Use async delays or move work to a background job.",
        "large-payload-json": "Stream large payloads or enforce size limits.",
        "missing-cache-header": "Add HTTP caching or application-level cache for read-heavy endpoints.",
    }.get(rule_id, "Profile the hot path and optimize based on measured bottlenecks.")
