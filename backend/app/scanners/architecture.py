"""Architecture heuristics — structure, size, layering, circular dependencies."""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

from app.scanners.base import ScanFinding
from app.scanners.utils import (
    CODE_EXTENSIONS,
    file_to_module_key,
    is_route_file,
    iter_code_files,
    iter_files,
    read_lines,
    rel_path,
)

LARGE_FILE_LINES = 500
MAX_FOLDER_DEPTH = 5

DB_IN_ROUTE_PATTERNS = [
    r"(?i)\.execute\s*\(",
    r"(?i)\.query\s*\(",
    r"(?i)session\.(get|add|delete|commit)\s*\(",
    r"(?i)db\.(execute|query|commit)\s*\(",
    r"(?i)SELECT\s+.+\s+FROM",
]

BUSINESS_LOGIC_IN_ROUTE_PATTERNS = [
    r"(?i)for\s+\w+\s+in\s+",
    r"(?i)if\s+.+\s+and\s+.+\s+and\s+",
    r"(?i)calculate_|compute_|process_order|validate_payment",
]


def scan_architecture(project_dir: Path) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    findings.extend(_scan_large_files(project_dir))
    findings.extend(_scan_deep_folders(project_dir))
    findings.extend(_scan_route_layering(project_dir))
    findings.extend(_scan_project_structure(project_dir))
    findings.extend(_scan_circular_dependencies(project_dir))
    return findings


def _scan_large_files(project_dir: Path) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    for file_path in iter_code_files(project_dir):
        if file_path.suffix.lower() not in CODE_EXTENSIONS:
            continue
        lines = read_lines(file_path)
        if not lines:
            continue
        count = len(lines)
        if count > LARGE_FILE_LINES:
            rel = rel_path(file_path, project_dir)
            findings.append(
                ScanFinding(
                    category="architecture",
                    severity="medium" if count < 800 else "high",
                    title=f"Oversized file ({count} lines)",
                    description=(
                        f"`{rel}` has {count} lines. Large files are harder to "
                        "maintain and often indicate a god-class or mixed responsibilities."
                    ),
                    impact="Changes become risky and onboarding slows as files grow without clear boundaries.",
                    fix_recommendation=(
                        "Split the file into smaller modules by responsibility "
                        "(services, models, utilities)."
                    ),
                    file_path=rel,
                    line_start=1,
                    line_end=count,
                    rule_id="large-file",
                    scanner="architecture",
                    confidence="high",
                    metadata={"line_count": count},
                )
            )
    return findings


def _scan_deep_folders(project_dir: Path) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    for file_path in iter_code_files(project_dir):
        rel = rel_path(file_path, project_dir)
        depth = len(rel.split("/")) - 1
        if depth > MAX_FOLDER_DEPTH:
            findings.append(
                ScanFinding(
                    category="architecture",
                    severity="low",
                    title="Deep folder nesting detected",
                    description=(
                        f"`{rel}` is nested {depth} levels deep. Deep trees make "
                        "navigation and imports harder to reason about."
                    ),
                    impact="Developers spend more time locating code; refactoring cost increases.",
                    fix_recommendation=(
                        "Flatten the folder structure or group by feature modules "
                        "instead of excessive sub-folders."
                    ),
                    file_path=rel,
                    line_start=0,
                    line_end=0,
                    rule_id="deep-folder",
                    scanner="architecture",
                    confidence="medium",
                    metadata={"depth": depth},
                )
            )
    return findings


def _scan_route_layering(project_dir: Path) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    for file_path in iter_code_files(project_dir):
        rel = rel_path(file_path, project_dir)
        if not is_route_file(rel):
            continue
        lines = read_lines(file_path)
        if not lines:
            continue

        for line_no, line in enumerate(lines, start=1):
            for pattern in DB_IN_ROUTE_PATTERNS:
                if re.search(pattern, line):
                    findings.append(
                        ScanFinding(
                            category="architecture",
                            severity="high",
                            title="Direct database access in route/controller layer",
                            description=(
                                f"Database call pattern found in `{rel}` line {line_no}. "
                                "Routes should delegate persistence to a service/repository layer."
                            ),
                            impact="Tight coupling makes testing hard and encourages duplicated query logic.",
                            fix_recommendation=(
                                "Move database access into a service or repository module "
                                "and keep routes thin."
                            ),
                            file_path=rel,
                            line_start=line_no,
                            line_end=line_no,
                            rule_id="db-in-route",
                            scanner="architecture",
                            confidence="medium",
                        )
                    )
                    break

            for pattern in BUSINESS_LOGIC_IN_ROUTE_PATTERNS:
                if re.search(pattern, line):
                    findings.append(
                        ScanFinding(
                            category="architecture",
                            severity="medium",
                            title="Business logic likely embedded in route/controller",
                            description=(
                                f"Complex logic pattern in `{rel}` line {line_no}. "
                                "Controllers should orchestrate, not implement domain rules."
                            ),
                            impact="Business rules scattered across HTTP handlers become hard to reuse and test.",
                            fix_recommendation=(
                                "Extract domain logic into dedicated service classes "
                                "or use-case modules."
                            ),
                            file_path=rel,
                            line_start=line_no,
                            line_end=line_no,
                            rule_id="logic-in-route",
                            scanner="architecture",
                            confidence="low",
                        )
                    )
                    break
    return findings


def _scan_project_structure(project_dir: Path) -> list[ScanFinding]:
    findings: list[ScanFinding] = []

    readme_exists = any(
        p.name.lower() in {"readme.md", "readme", "readme.txt"}
        for p in iter_files(project_dir)
        if p.parent == project_dir or p.parent.name.lower() == "docs"
    )
    if not readme_exists:
        findings.append(
            ScanFinding(
                category="architecture",
                severity="low",
                title="Missing README documentation",
                description="No README found at the project root.",
                impact="New contributors and auditors cannot quickly understand setup or architecture.",
                fix_recommendation="Add a README with setup, architecture overview, and run instructions.",
                file_path="",
                line_start=0,
                line_end=0,
                rule_id="missing-readme",
                scanner="architecture",
                confidence="high",
            )
        )

    test_dirs = {"test", "tests", "__tests__", "spec", "specs"}
    has_tests = any(
        part.lower() in test_dirs
        for path in iter_files(project_dir)
        for part in path.parts
    )
    if not has_tests:
        findings.append(
            ScanFinding(
                category="architecture",
                severity="medium",
                title="No tests folder detected",
                description="No `tests`, `test`, or `__tests__` directory was found.",
                impact="Without automated tests, regressions ship to production undetected.",
                fix_recommendation="Add a test suite and run it in CI before deployments.",
                file_path="",
                line_start=0,
                line_end=0,
                rule_id="missing-tests",
                scanner="architecture",
                confidence="medium",
            )
        )

    return findings


def _scan_circular_dependencies(project_dir: Path) -> list[ScanFinding]:
    module_files: dict[str, str] = {}
    for file_path in iter_code_files(project_dir):
        if file_path.suffix.lower() not in {".py", ".js", ".ts", ".tsx", ".jsx"}:
            continue
        rel = rel_path(file_path, project_dir)
        module_files[file_to_module_key(rel)] = rel

    graph: dict[str, set[str]] = defaultdict(set)
    for file_path in iter_code_files(project_dir):
        if file_path.suffix.lower() not in {".py", ".js", ".ts", ".tsx", ".jsx"}:
            continue
        rel = rel_path(file_path, project_dir)
        source_key = file_to_module_key(rel)
        lines = read_lines(file_path)
        if not lines:
            continue
        for target_key in _extract_import_targets("\n".join(lines), file_path.suffix):
            if target_key in module_files and target_key != source_key:
                graph[source_key].add(target_key)

    cycles = _find_cycles(graph)
    findings: list[ScanFinding] = []
    seen_cycles: set[str] = set()

    for cycle in cycles:
        cycle_key = " -> ".join(cycle)
        if cycle_key in seen_cycles:
            continue
        seen_cycles.add(cycle_key)
        first_file = module_files.get(cycle[0], cycle[0])
        findings.append(
            ScanFinding(
                category="architecture",
                severity="medium",
                title="Circular dependency detected",
                description=f"Import cycle: {' -> '.join(cycle)} -> {cycle[0]}",
                impact="Circular imports cause brittle modules, harder refactors, and runtime import errors.",
                fix_recommendation=(
                    "Break the cycle by extracting shared code into a neutral module "
                    "or applying dependency inversion."
                ),
                file_path=first_file,
                line_start=0,
                line_end=0,
                rule_id="circular-dependency",
                scanner="architecture",
                confidence="medium",
                metadata={"cycle": cycle},
            )
        )
    return findings


def _extract_import_targets(content: str, suffix: str) -> set[str]:
    targets: set[str] = set()
    if suffix == ".py":
        for match in re.finditer(
            r"^\s*(?:from|import)\s+([\w\.]+)",
            content,
            re.MULTILINE,
        ):
            mod = match.group(1)
            if mod.startswith("."):
                continue
            targets.add(mod)
            parts = mod.split(".")
            for i in range(1, len(parts) + 1):
                targets.add(".".join(parts[:i]))
    else:
        for match in re.finditer(
            r"""(?:import\s+.*?from\s+['"]([^'"]+)['"]|import\s+['"]([^'"]+)['"])""",
            content,
        ):
            mod = match.group(1) or match.group(2) or ""
            if mod.startswith("."):
                key = mod.lstrip("./").replace("/", ".")
                if key:
                    targets.add(key)
            elif mod.startswith("@/"):
                key = mod[2:].replace("/", ".")
                targets.add(key)
    return targets


def _find_cycles(graph: dict[str, set[str]]) -> list[list[str]]:
    cycles: list[list[str]] = []
    visited: set[str] = set()
    stack: list[str] = []
    on_stack: set[str] = set()

    def dfs(node: str) -> None:
        visited.add(node)
        on_stack.add(node)
        stack.append(node)

        for neighbor in graph.get(node, set()):
            if neighbor not in visited:
                dfs(neighbor)
            elif neighbor in on_stack:
                start = stack.index(neighbor)
                cycle = stack[start:]
                if len(cycle) >= 2:
                    cycles.append(cycle[:])

        stack.pop()
        on_stack.remove(node)

    for node in graph:
        if node not in visited:
            dfs(node)
    return cycles
