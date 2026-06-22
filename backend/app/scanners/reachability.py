"""CVE reachability analyzer.

After OSV reports vulnerable dependencies, this scanner walks the project
source to determine whether each vulnerable package is actually imported
or referenced. Findings are annotated with:

  - `metadata.reachable = "yes" | "no" | "unknown"`
  - `metadata.reachable_files = "path1, path2, ..."` (when yes)

Unreachable findings have their severity bumped down by one notch and a
disclaimer is appended to the description. This kills the bulk of the
"transitive dependency CVE" noise that overwhelms most SCA reports.

Supports Python (PyPI), Node (npm), Go modules, Rust (crates.io),
PHP (Packagist) and Ruby (RubyGems) ecosystems.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from app.scanners.base import ScanFinding
from app.scanners.secrets import SKIP_DIRS

logger = logging.getLogger(__name__)

PY_EXTS = {".py"}
JS_EXTS = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
GO_EXTS = {".go"}
RUST_EXTS = {".rs"}
PHP_EXTS = {".php"}
RUBY_EXTS = {".rb"}

MAX_FILE_BYTES = 600_000

SEVERITY_LADDER = ["critical", "high", "medium", "low"]


def annotate_reachability(
    findings: list[ScanFinding], project_dir: Path
) -> list[ScanFinding]:
    """Mutate findings in-place: add `reachable` metadata + maybe lower severity."""
    relevant = [
        f for f in findings
        if f.scanner == "osv" and (f.metadata.get("package"))
    ]
    if not relevant:
        return findings

    sources_by_lang = _collect_source_files(project_dir)

    for finding in relevant:
        package = finding.metadata.get("package", "").strip()
        ecosystem = finding.metadata.get("ecosystem", "")
        if not package:
            continue

        reachable_files = _find_imports(package, ecosystem, sources_by_lang, project_dir)

        if reachable_files:
            finding.metadata["reachable"] = "yes"
            finding.metadata["reachable_files"] = ", ".join(reachable_files[:5])
            finding.metadata["reachable_count"] = str(len(reachable_files))
        else:
            finding.metadata["reachable"] = "no"
            finding.severity = _demote(finding.severity)
            finding.description = (
                f"{finding.description}\n\n"
                f"Reachability: package `{package}` is declared in a lockfile but "
                "no import / require / use statement was found in the project source. "
                "This vulnerability is unlikely to be exploitable in your code paths."
            )
            finding.metadata["reachable_note"] = (
                "No import sites found — likely transitive dep with no direct call path."
            )

    return findings


def _demote(severity: str) -> str:
    try:
        idx = SEVERITY_LADDER.index(severity)
    except ValueError:
        return severity
    return SEVERITY_LADDER[min(idx + 1, len(SEVERITY_LADDER) - 1)]


def _collect_source_files(project_dir: Path) -> dict[str, list[tuple[Path, str]]]:
    out: dict[str, list[tuple[Path, str]]] = {
        "py": [], "js": [], "go": [], "rs": [], "php": [], "rb": [],
    }
    for path in project_dir.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        suffix = path.suffix.lower()
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if suffix in PY_EXTS:
            out["py"].append((path, text))
        elif suffix in JS_EXTS:
            out["js"].append((path, text))
        elif suffix in GO_EXTS:
            out["go"].append((path, text))
        elif suffix in RUST_EXTS:
            out["rs"].append((path, text))
        elif suffix in PHP_EXTS:
            out["php"].append((path, text))
        elif suffix in RUBY_EXTS:
            out["rb"].append((path, text))
    return out


def _find_imports(
    package: str,
    ecosystem: str,
    sources: dict[str, list[tuple[Path, str]]],
    project_dir: Path,
) -> list[str]:
    pkg_lower = package.lower()
    hits: list[str] = []

    if ecosystem == "PyPI":
        module = _pypi_module_name(package)
        candidates = {module, package.replace("-", "_").lower()}
        patterns = [
            re.compile(rf"^\s*import\s+({'|'.join(re.escape(c) for c in candidates)})\b", re.M),
            re.compile(rf"^\s*from\s+({'|'.join(re.escape(c) for c in candidates)})[\.\s]", re.M),
        ]
        hits.extend(_match_in_files(patterns, sources["py"], project_dir))

    elif ecosystem == "npm":
        bare = pkg_lower.lstrip("@")
        patterns = [
            re.compile(rf"""require\s*\(\s*['"]({re.escape(package)})(?:/[^'"]*)?['"]"""),
            re.compile(rf"""(?:from|import)\s+['"]({re.escape(package)})(?:/[^'"]*)?['"]"""),
            re.compile(rf"""import\(\s*['"]({re.escape(package)})(?:/[^'"]*)?['"]\s*\)"""),
        ]
        if bare != pkg_lower:
            patterns.append(re.compile(rf"""(?:from|import|require)\s*\(?\s*['"]({re.escape(bare)})(?:/[^'"]*)?['"]"""))
        hits.extend(_match_in_files(patterns, sources["js"], project_dir))

    elif ecosystem == "Go":
        patterns = [
            re.compile(rf"""['"]({re.escape(package)})(?:/[^'"]*)?['"]"""),
        ]
        hits.extend(_match_in_files(patterns, sources["go"], project_dir))

    elif ecosystem == "crates.io":
        module = package.replace("-", "_")
        patterns = [
            re.compile(rf"\buse\s+{re.escape(module)}\b", re.I),
            re.compile(rf"\bextern\s+crate\s+{re.escape(module)}\b"),
        ]
        hits.extend(_match_in_files(patterns, sources["rs"], project_dir))

    elif ecosystem == "Packagist":
        vendor_slash = package.replace("/", "\\\\")
        ns_root = package.split("/")[-1]
        patterns = [
            re.compile(rf"\\?(?:{vendor_slash}|{re.escape(ns_root)})\\\\?\b"),
            re.compile(rf"use\s+\\?(?:{vendor_slash}|{re.escape(ns_root)})\b"),
        ]
        hits.extend(_match_in_files(patterns, sources["php"], project_dir))

    elif ecosystem == "RubyGems":
        underscore = package.replace("-", "_")
        patterns = [
            re.compile(rf"""require\s+['"]({re.escape(package)}|{re.escape(underscore)})['"]"""),
        ]
        hits.extend(_match_in_files(patterns, sources["rb"], project_dir))

    return list(dict.fromkeys(hits))


def _pypi_module_name(package: str) -> str:
    """Convert PyPI distribution name to likely top-level module name."""
    overrides = {
        "pillow": "PIL",
        "pyyaml": "yaml",
        "beautifulsoup4": "bs4",
        "scikit-learn": "sklearn",
        "python-dateutil": "dateutil",
        "msgpack-python": "msgpack",
        "opencv-python": "cv2",
        "discord.py": "discord",
        "google-cloud-storage": "google.cloud.storage",
    }
    lower = package.lower().strip()
    if lower in overrides:
        return overrides[lower]
    return lower.replace("-", "_")


def _match_in_files(
    patterns: list[re.Pattern[str]],
    files: list[tuple[Path, str]],
    project_dir: Path,
) -> list[str]:
    hits: list[str] = []
    for path, text in files:
        for pattern in patterns:
            if pattern.search(text):
                try:
                    rel = str(path.relative_to(project_dir)).replace("\\", "/")
                except ValueError:
                    rel = str(path)
                hits.append(rel)
                break
    return hits
