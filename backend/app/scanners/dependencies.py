import json
import re
from pathlib import Path

import httpx

from app.scanners.base import ScanFinding
from app.scanners.secrets import SKIP_DIRS

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
MAX_PACKAGES = 100


def scan_dependencies(project_dir: Path) -> list[ScanFinding]:
    packages = _collect_packages(project_dir)
    if not packages:
        return []

    queries = [
        {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
        for name, version, ecosystem in packages[:MAX_PACKAGES]
    ]

    try:
        with httpx.Client(timeout=30.0) as client:
            response = client.post(OSV_BATCH_URL, json={"queries": queries})
            response.raise_for_status()
            data = response.json()
    except Exception:
        return []

    findings: list[ScanFinding] = []
    for pkg, result in zip(packages[:MAX_PACKAGES], data.get("results", [])):
        name, version, ecosystem = pkg
        for vuln in result.get("vulns", []):
            severity = _vuln_severity(vuln)
            vuln_id = vuln.get("id", "UNKNOWN")
            summary = vuln.get("summary", "Known vulnerability in dependency")
            findings.append(
                ScanFinding(
                    category="dependencies",
                    severity=severity,
                    title=f"Vulnerable dependency: {name}@{version}",
                    description=f"{summary} ({vuln_id})",
                    impact="Known CVE may allow exploitation depending on how the package is used.",
                    fix_recommendation=f"Upgrade {name} to a patched version. Check {vuln_id} for details.",
                    file_path=_package_file(project_dir, name, ecosystem),
                    line_start=0,
                    line_end=0,
                    rule_id=vuln_id,
                    scanner="osv",
                    confidence="high",
                    metadata={"ecosystem": ecosystem, "package": name, "version": version},
                )
            )

    return findings


def _collect_packages(project_dir: Path) -> list[tuple[str, str, str]]:
    packages: list[tuple[str, str, str]] = []

    for lock_file in project_dir.rglob("package-lock.json"):
        if any(part in SKIP_DIRS for part in lock_file.parts):
            continue
        packages.extend(_parse_package_lock(lock_file))

    for req_file in project_dir.rglob("requirements.txt"):
        if any(part in SKIP_DIRS for part in req_file.parts):
            continue
        packages.extend(_parse_requirements(req_file))

    seen: set[tuple[str, str, str]] = set()
    unique: list[tuple[str, str, str]] = []
    for pkg in packages:
        if pkg not in seen:
            seen.add(pkg)
            unique.append(pkg)
    return unique


def _parse_package_lock(path: Path) -> list[tuple[str, str, str]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []

    packages: list[tuple[str, str, str]] = []
    for name, info in data.get("packages", {}).items():
        if not name or name == "":
            continue
        version = info.get("version")
        if not version:
            continue
        clean_name = name.replace("node_modules/", "")
        if clean_name.startswith("@"):
            pkg_name = clean_name
        else:
            pkg_name = clean_name.split("node_modules/")[-1]
        packages.append((pkg_name, version, "npm"))
    return packages


def _parse_requirements(path: Path) -> list[tuple[str, str, str]]:
    packages: list[tuple[str, str, str]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)(?:[=<>!~]+)([A-Za-z0-9_.*+-]+)", line)
        if match:
            packages.append((match.group(1), match.group(2), "PyPI"))
    return packages


def _vuln_severity(vuln: dict) -> str:
    for item in vuln.get("severity", []):
        score = item.get("score", "")
        if "CRITICAL" in score.upper():
            return "critical"
        if "HIGH" in score.upper():
            return "high"
    if "CRITICAL" in vuln.get("id", "").upper():
        return "critical"
    return "high"


def _package_file(project_dir: Path, name: str, ecosystem: str) -> str:
    if ecosystem == "npm":
        return "package-lock.json"
    if ecosystem == "PyPI":
        return "requirements.txt"
    return ""
