import json
import re
import tomllib
from pathlib import Path

import httpx

from app.scanners.base import ScanFinding
from app.scanners.cwe_mappings import DEFAULT_DEPENDENCY_OWASP
from app.scanners.secrets import SKIP_DIRS

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
MAX_PACKAGES = 150

LOCKFILE_NAMES = {
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "requirements.txt": "PyPI",
    "pyproject.toml": "PyPI",
    "go.mod": "Go",
    "Cargo.lock": "crates.io",
}


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
            cwe_id = _extract_cwe(vuln)
            metadata: dict[str, str] = {
                "ecosystem": ecosystem,
                "package": name,
                "version": version,
                "owasp_category": DEFAULT_DEPENDENCY_OWASP,
            }
            if cwe_id:
                metadata["cwe_id"] = cwe_id
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
                    metadata=metadata,
                )
            )

    return findings


def _collect_packages(project_dir: Path) -> list[tuple[str, str, str]]:
    packages: list[tuple[str, str, str]] = []

    for lock_file in project_dir.rglob("package-lock.json"):
        if any(part in SKIP_DIRS for part in lock_file.parts):
            continue
        packages.extend(_parse_package_lock(lock_file))

    for yarn_file in project_dir.rglob("yarn.lock"):
        if any(part in SKIP_DIRS for part in yarn_file.parts):
            continue
        packages.extend(_parse_yarn_lock(yarn_file))

    for req_file in project_dir.rglob("requirements.txt"):
        if any(part in SKIP_DIRS for part in req_file.parts):
            continue
        packages.extend(_parse_requirements(req_file))

    for pyproject in project_dir.rglob("pyproject.toml"):
        if any(part in SKIP_DIRS for part in pyproject.parts):
            continue
        packages.extend(_parse_pyproject(pyproject))

    for go_mod in project_dir.rglob("go.mod"):
        if any(part in SKIP_DIRS for part in go_mod.parts):
            continue
        packages.extend(_parse_go_mod(go_mod))

    for cargo_lock in project_dir.rglob("Cargo.lock"):
        if any(part in SKIP_DIRS for part in cargo_lock.parts):
            continue
        packages.extend(_parse_cargo_lock(cargo_lock))

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


def _parse_yarn_lock(path: Path) -> list[tuple[str, str, str]]:
    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        return []

    packages: list[tuple[str, str, str]] = []
    # Yarn classic: "package@version:" blocks with version "x.y.z"
    for match in re.finditer(
        r'^"?(@?[^"\n]+?)@(?:npm:)?([^":\s]+)"?:\s*\n(?:[^\n]*\n)*?\s+version\s+"([^"]+)"',
        content,
        re.MULTILINE,
    ):
        name = match.group(1).strip().strip('"')
        packages.append((name, match.group(3), "npm"))
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


def _parse_pyproject(path: Path) -> list[tuple[str, str, str]]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return []

    packages: list[tuple[str, str, str]] = []
    project_deps = data.get("project", {}).get("dependencies", [])
    if isinstance(project_deps, list):
        for dep in project_deps:
            parsed = _parse_pep508_name_version(str(dep))
            if parsed:
                packages.append((*parsed, "PyPI"))

    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    if isinstance(poetry_deps, dict):
        for name, spec in poetry_deps.items():
            if name.lower() == "python":
                continue
            version = _poetry_version(spec)
            if version:
                packages.append((name, version, "PyPI"))
    return packages


def _parse_pep508_name_version(spec: str) -> tuple[str, str] | None:
    match = re.match(r"^([A-Za-z0-9_.-]+)\s*(?:\(([^)]+)\)|([=<>!~]+)\s*([^\s,;]+))?", spec)
    if not match:
        return None
    name = match.group(1)
    version = match.group(2) or match.group(4) or "*"
    return name, version.strip('"')


def _poetry_version(spec: object) -> str | None:
    if isinstance(spec, str):
        return spec
    if isinstance(spec, dict):
        return str(spec.get("version", "*"))
    return None


def _parse_go_mod(path: Path) -> list[tuple[str, str, str]]:
    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        return []

    packages: list[tuple[str, str, str]] = []
    in_require = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_require = True
            continue
        if in_require and stripped == ")":
            in_require = False
            continue
        if in_require or stripped.startswith("require "):
            match = re.match(r"require\s+(\S+)\s+(\S+)", stripped)
            if not match and in_require:
                match = re.match(r"(\S+)\s+(\S+)", stripped)
            if match:
                version = match.group(2)
                if version.startswith("v"):
                    version = version[1:]
                packages.append((match.group(1), version, "Go"))
    return packages


def _parse_cargo_lock(path: Path) -> list[tuple[str, str, str]]:
    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        return []

    packages: list[tuple[str, str, str]] = []
    name = version = None
    for line in content.splitlines():
        stripped = line.strip()
        if stripped == "[[package]]":
            if name and version:
                packages.append((name, version, "crates.io"))
            name = version = None
            continue
        if stripped.startswith("name = "):
            name = stripped.split("=", 1)[1].strip().strip('"')
        elif stripped.startswith("version = "):
            version = stripped.split("=", 1)[1].strip().strip('"')
    if name and version:
        packages.append((name, version, "crates.io"))
    return packages


def _extract_cwe(vuln: dict) -> str | None:
    for alias in vuln.get("aliases", []):
        if alias.upper().startswith("CWE-"):
            return alias.upper()
    db = vuln.get("database_specific", {})
    for key in ("cwe_ids", "CWE", "cwe"):
        val = db.get(key)
        if isinstance(val, list) and val:
            cwe = str(val[0])
            return cwe if cwe.upper().startswith("CWE") else f"CWE-{cwe}"
        if isinstance(val, str) and val:
            return val.split(":")[0].strip()
    return None


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
    for lock_name, eco in LOCKFILE_NAMES.items():
        if eco == ecosystem:
            for path in project_dir.rglob(lock_name):
                if any(part in SKIP_DIRS for part in path.parts):
                    continue
                return str(path.relative_to(project_dir)).replace("\\", "/")
    return ""
