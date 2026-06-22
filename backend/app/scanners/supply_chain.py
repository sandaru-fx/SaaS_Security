"""Supply chain hardening — typosquatting, Sigstore/SLSA, malicious package signals."""

from __future__ import annotations

import json
import re
from pathlib import Path

import httpx

from app.scanners.base import ScanFinding
from app.scanners.dependencies import collect_packages
from app.scanners.secrets import SKIP_DIRS
from app.scanners.supply_chain_data import (
    CONTAINER_PUBLISH_MARKERS,
    KNOWN_MALICIOUS,
    POPULAR_NPM,
    POPULAR_PYPI,
    RISKY_LIFECYCLE_SCRIPTS,
    SIGSTORE_MARKERS,
)
from app.scanners.utils import read_lines, rel_path, should_skip

MAX_TYPOSQUAT_REGISTRY_CHECKS = 25


def scan_supply_chain(project_dir: Path) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    findings.extend(_scan_typosquatting(project_dir))
    findings.extend(_scan_known_malicious(project_dir))
    findings.extend(_scan_sigstore_slsa(project_dir))
    findings.extend(_scan_lockfile_hygiene(project_dir))
    findings.extend(_scan_lifecycle_scripts(project_dir))
    findings.extend(_scan_unpinned_actions(project_dir))
    return findings


def _finding(
    *,
    rule_id: str,
    severity: str,
    title: str,
    description: str,
    impact: str,
    fix_recommendation: str,
    file_path: str,
    line_start: int = 0,
    line_end: int = 0,
    confidence: str = "medium",
    metadata: dict | None = None,
) -> ScanFinding:
    return ScanFinding(
        category="dependencies",
        severity=severity,
        title=title,
        description=description,
        impact=impact,
        fix_recommendation=fix_recommendation,
        file_path=file_path,
        line_start=line_start,
        line_end=line_end,
        rule_id=rule_id,
        scanner="supply-chain",
        confidence=confidence,
        metadata=metadata or {},
    )


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1]


def _base_name(name: str) -> str:
    if "/" in name:
        return name.rsplit("/", 1)[-1].lower()
    return name.lower()


def _popular_set(ecosystem: str) -> set[str]:
    if ecosystem == "npm":
        return POPULAR_NPM
    if ecosystem == "PyPI":
        return POPULAR_PYPI
    return set()


def _find_typosquat_candidate(name: str, ecosystem: str) -> tuple[str, str] | None:
    base = _base_name(name)
    popular = _popular_set(ecosystem)
    if not popular or base in popular or name.lower() in popular:
        return None

    best: tuple[str, str] | None = None
    for legit in popular:
        legit_base = _base_name(legit)
        if abs(len(base) - len(legit_base)) > 2:
            continue
        dist = _levenshtein(base, legit_base)
        if 0 < dist <= 2:
            if best is None or dist < _levenshtein(base, _base_name(best[0])):
                best = (legit, f"Levenshtein distance {dist} from `{legit}`")
        elif _is_substitution_typosquat(base, legit_base):
            best = (legit, f"Character substitution resembling `{legit}`")

    return best


def _is_substitution_typosquat(a: str, b: str) -> bool:
    if len(a) != len(b) or len(a) < 4:
        return False
    subs = sum(1 for x, y in zip(a, b) if x != y)
    if subs != 1:
        return False
    pairs = {("l", "1"), ("1", "l"), ("o", "0"), ("0", "o"), ("i", "1"), ("1", "i")}
    for x, y in zip(a, b):
        if x != y and (x, y) not in pairs:
            return False
    return True


def _scan_typosquatting(project_dir: Path) -> list[ScanFinding]:
    packages = collect_packages(project_dir)
    findings: list[ScanFinding] = []
    seen: set[str] = set()
    registry_checks = 0

    for name, version, ecosystem in packages:
        if ecosystem not in ("npm", "PyPI"):
            continue
        key = f"{ecosystem}:{name.lower()}"
        if key in seen:
            continue
        seen.add(key)

        match = _find_typosquat_candidate(name, ecosystem)
        if not match:
            continue

        legit, reason = match
        confidence = "medium"
        if registry_checks < MAX_TYPOSQUAT_REGISTRY_CHECKS and _registry_confirms_package(name, ecosystem):
            confidence = "high"
            registry_checks += 1

        rule_suffix = "npm" if ecosystem == "npm" else "pypi"
        findings.append(
            _finding(
                rule_id=f"supply-typosquat-{rule_suffix}",
                severity="high",
                title=f"Possible typosquat package: {name}",
                description=(
                    f"`{name}@{version}` resembles popular package `{legit}` ({reason}). "
                    "Typosquatting is a common supply-chain attack vector."
                ),
                impact="Malicious packages can steal secrets, backdoor builds, or run arbitrary code on install.",
                fix_recommendation=(
                    f"Verify you intended `{legit}` not `{name}`. "
                    "Remove suspicious packages and audit install scripts."
                ),
                file_path=_dep_file_for_package(project_dir, ecosystem),
                confidence=confidence,
                metadata={
                    "ecosystem": ecosystem,
                    "package": name,
                    "version": version,
                    "similar_to": legit,
                    "owasp_category": "A06:2021 - Vulnerable and Outdated Components",
                    "cwe_id": "CWE-1357",
                },
            )
        )

    return findings


def _registry_confirms_package(name: str, ecosystem: str) -> bool:
    try:
        with httpx.Client(timeout=8.0) as client:
            if ecosystem == "npm":
                enc = name.replace("/", "%2F")
                r = client.get(f"https://registry.npmjs.org/{enc}")
                return r.status_code == 200
            if ecosystem == "PyPI":
                r = client.get(f"https://pypi.org/pypi/{name}/json")
                return r.status_code == 200
    except Exception:
        return False
    return False


def _scan_known_malicious(project_dir: Path) -> list[ScanFinding]:
    packages = collect_packages(project_dir)
    findings: list[ScanFinding] = []
    seen: set[str] = set()

    for name, version, ecosystem in packages:
        base = _base_name(name)
        advisory = KNOWN_MALICIOUS.get(base) or KNOWN_MALICIOUS.get(name.lower())
        if not advisory:
            continue
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            _finding(
                rule_id="supply-malicious-package-known",
                severity="critical",
                title=f"Known malicious or compromised package: {name}",
                description=f"`{name}@{version}` matches a known supply-chain incident: {advisory}",
                impact="Compromised dependencies may execute malware during install or runtime.",
                fix_recommendation="Remove this package immediately, rotate secrets, and audit build logs.",
                file_path=_dep_file_for_package(project_dir, ecosystem),
                confidence="high",
                metadata={
                    "ecosystem": ecosystem,
                    "package": name,
                    "version": version,
                    "cwe_id": "CWE-1357",
                    "owasp_category": "A06:2021 - Vulnerable and Outdated Components",
                },
            )
        )

    return findings


def _scan_sigstore_slsa(project_dir: Path) -> list[ScanFinding]:
    findings: list[ScanFinding] = []

    for dockerfile in project_dir.rglob("Dockerfile*"):
        if should_skip(dockerfile):
            continue
        rel = rel_path(dockerfile, project_dir)
        lines = read_lines(dockerfile) or []
        for idx, line in enumerate(lines, 1):
            m = re.match(r"^\s*FROM\s+(\S+)", line, re.I)
            if not m:
                continue
            image = m.group(1)
            if "@sha256:" in image:
                continue
            if image.lower() in ("scratch", "alpine", "debian", "ubuntu"):
                continue
            findings.append(
                _finding(
                    rule_id="supply-docker-no-digest",
                    severity="medium",
                    title="Container image not pinned by digest",
                    description=f"`{rel}` line {idx} uses `FROM {image}` without `@sha256:` digest.",
                    impact="Unsigned or mutable image tags can be swapped in registry attacks.",
                    fix_recommendation=(
                        "Pin images to an immutable digest and verify with Cosign/Sigstore in CI."
                    ),
                    file_path=rel,
                    line_start=idx,
                    line_end=idx,
                    confidence="high",
                    metadata={"cwe_id": "CWE-494", "owasp_category": "A08:2021 - Software and Data Integrity Failures"},
                )
            )

    workflow_dir = project_dir / ".github" / "workflows"
    if workflow_dir.is_dir():
        for wf in workflow_dir.glob("*.yml"):
            findings.extend(_check_workflow_sigstore(wf, project_dir))
        for wf in workflow_dir.glob("*.yaml"):
            findings.extend(_check_workflow_sigstore(wf, project_dir))

    return findings


def _check_workflow_sigstore(wf: Path, project_dir: Path) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    rel = rel_path(wf, project_dir)
    content = "\n".join(read_lines(wf) or [])
    lower = content.lower()

    publishes_container = any(marker in lower for marker in CONTAINER_PUBLISH_MARKERS)
    has_sigstore = any(marker in lower for marker in SIGSTORE_MARKERS)

    if publishes_container and not has_sigstore:
        findings.append(
            _finding(
                rule_id="supply-sigstore-missing-ci",
                severity="high",
                title="CI publishes containers without Sigstore/Cosign verification",
                description=(
                    f"`{rel}` builds or pushes container images but has no Cosign, Sigstore, "
                    "or SLSA provenance verification step."
                ),
                impact="Unsigned images are vulnerable to registry substitution and supply-chain tampering.",
                fix_recommendation=(
                    "Add cosign sign/verify (Sigstore) and slsa-github-generator or slsa-verifier "
                    "to your release workflow."
                ),
                file_path=rel,
                confidence="medium",
                metadata={"cwe_id": "CWE-494", "owasp_category": "A08:2021 - Software and Data Integrity Failures"},
            )
        )

    if publishes_container and "slsa" not in lower and "provenance" not in lower:
        findings.append(
            _finding(
                rule_id="supply-slsa-provenance-missing",
                severity="medium",
                title="CI missing SLSA provenance attestation",
                description=(
                    f"`{rel}` publishes artifacts but does not generate SLSA provenance "
                    "(slsa-github-generator or equivalent)."
                ),
                impact="Without provenance, consumers cannot verify build integrity.",
                fix_recommendation="Enable SLSA Level 2+ provenance with slsa-github-generator on release builds.",
                file_path=rel,
                confidence="low",
                metadata={"cwe_id": "CWE-494", "owasp_category": "A08:2021 - Software and Data Integrity Failures"},
            )
        )

    return findings


def _scan_lockfile_hygiene(project_dir: Path) -> list[ScanFinding]:
    findings: list[ScanFinding] = []

    for pkg_json in project_dir.rglob("package.json"):
        if should_skip(pkg_json) or "node_modules" in pkg_json.parts:
            continue
        rel = rel_path(pkg_json, project_dir)
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue

        deps = data.get("dependencies") or {}
        dev_deps = data.get("devDependencies") or {}
        if not deps and not dev_deps:
            continue

        parent = pkg_json.parent
        has_lock = any(
            (parent / name).exists()
            for name in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml")
        )
        if not has_lock:
            findings.append(
                _finding(
                    rule_id="supply-missing-lockfile",
                    severity="high",
                    title="npm dependencies without lockfile",
                    description=f"`{rel}` declares dependencies but no lockfile exists alongside it.",
                    impact="Non-deterministic installs enable dependency confusion and typosquat injection.",
                    fix_recommendation="Commit package-lock.json (or yarn.lock / pnpm-lock.yaml) and use `npm ci` in CI.",
                    file_path=rel,
                    confidence="high",
                    metadata={"cwe_id": "CWE-1357", "owasp_category": "A06:2021 - Vulnerable and Outdated Components"},
                )
            )

        for dep_name in list(deps.keys()) + list(dev_deps.keys()):
            if dep_name.startswith("@") and "/" in dep_name:
                scope, pkg = dep_name.split("/", 1)
                if _looks_internal_scope(scope) and not _has_private_registry_hint(parent):
                    findings.append(
                        _finding(
                            rule_id="supply-dependency-confusion",
                            severity="medium",
                            title=f"Possible dependency confusion: {dep_name}",
                            description=(
                                f"Scoped package `{dep_name}` in `{rel}` may be resolved from the public "
                                "registry if a private registry is not configured."
                            ),
                            impact="Attackers can publish squatted internal package names to npm.",
                            fix_recommendation=(
                                "Configure `.npmrc` with your private registry scope and use lockfiles."
                            ),
                            file_path=rel,
                            confidence="low",
                            metadata={"package": dep_name, "cwe_id": "CWE-1357"},
                        )
                    )

    for req in project_dir.rglob("requirements.txt"):
        if should_skip(req):
            continue
        parent = req.parent
        has_poetry = (parent / "poetry.lock").exists()
        has_pipfile = (parent / "Pipfile.lock").exists()
        if not has_poetry and not has_pipfile:
            content = "\n".join(read_lines(req) or [])
            if content.strip() and not re.search(r"--hash=sha256:", content):
                findings.append(
                    _finding(
                        rule_id="supply-pip-no-hashes",
                        severity="low",
                        title="Python requirements without hash pinning",
                        description=f"`{rel_path(req, project_dir)}` has unpinned requirements without pip hashes.",
                        impact="Supply-chain attacks can swap package versions between environments.",
                        fix_recommendation="Use poetry.lock, pip-tools with hashes, or pip install --require-hashes.",
                        file_path=rel_path(req, project_dir),
                        confidence="low",
                        metadata={"cwe_id": "CWE-1357"},
                    )
                )

    return findings


def _looks_internal_scope(scope: str) -> bool:
    generic = {"@types", "@babel", "@aws-sdk", "@google-cloud", "@azure", "@nestjs", "@angular", "@vue"}
    if scope.lower() in generic:
        return False
    return scope.startswith("@") and len(scope) > 2


def _has_private_registry_hint(directory: Path) -> bool:
    npmrc = directory / ".npmrc"
    if npmrc.exists():
        content = npmrc.read_text(encoding="utf-8", errors="ignore").lower()
        if "registry" in content:
            return True
    return False


def _scan_lifecycle_scripts(project_dir: Path) -> list[ScanFinding]:
    findings: list[ScanFinding] = []

    for pkg_json in project_dir.rglob("package.json"):
        if should_skip(pkg_json) or "node_modules" in pkg_json.parts:
            continue
        rel = rel_path(pkg_json, project_dir)
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue

        scripts = data.get("scripts") or {}
        risky = [k for k in scripts if k in RISKY_LIFECYCLE_SCRIPTS]
        for script_name in risky:
            body = str(scripts[script_name])
            if re.search(r"(curl|wget|powershell|eval|base64|/dev/tcp)", body, re.I):
                findings.append(
                    _finding(
                        rule_id="supply-risky-lifecycle-script",
                        severity="high",
                        title=f"Risky npm lifecycle script: {script_name}",
                        description=f"`{rel}` script `{script_name}` runs suspicious commands on install.",
                        impact="Install-time scripts execute with developer/CI privileges.",
                        fix_recommendation="Audit scripts, prefer --ignore-scripts in CI, and pin dependencies.",
                        file_path=rel,
                        confidence="high",
                        metadata={"script": script_name, "cwe_id": "CWE-1357"},
                    )
                )

    for lock in project_dir.rglob("package-lock.json"):
        if should_skip(lock) or "node_modules" in lock.parts:
            continue
        rel = rel_path(lock, project_dir)
        try:
            data = json.loads(lock.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for pkg_path, info in (data.get("packages") or {}).items():
            if not isinstance(info, dict):
                continue
            scripts = info.get("scripts") or {}
            name = info.get("name") or pkg_path.replace("node_modules/", "")
            for script_name, body in scripts.items():
                if script_name not in RISKY_LIFECYCLE_SCRIPTS:
                    continue
                if re.search(r"(curl|wget|powershell|eval|base64|/dev/tcp|miner|crypto)", str(body), re.I):
                    findings.append(
                        _finding(
                            rule_id="supply-dependency-install-script",
                            severity="critical",
                            title=f"Dependency install script risk: {name}",
                            description=(
                                f"`{name}` in `{rel}` has `{script_name}` script with suspicious commands."
                            ),
                            impact="Malicious install scripts are a primary vector for supply-chain compromise.",
                            fix_recommendation="Remove the package, use npm audit, and enable install script blocking in CI.",
                            file_path=rel,
                            confidence="high",
                            metadata={"package": name, "script": script_name, "cwe_id": "CWE-1357"},
                        )
                    )

    return findings


def _scan_unpinned_actions(project_dir: Path) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    workflow_dir = project_dir / ".github" / "workflows"
    if not workflow_dir.is_dir():
        return findings

    action_re = re.compile(r"uses:\s*([^\s@]+)@([^\s#\n]+)", re.I)
    for wf in list(workflow_dir.glob("*.yml")) + list(workflow_dir.glob("*.yaml")):
        rel = rel_path(wf, project_dir)
        lines = read_lines(wf) or []
        for idx, line in enumerate(lines, 1):
            m = action_re.search(line)
            if not m:
                continue
            action = m.group(1)
            ref = m.group(2).strip()
            if ref.startswith("sha256:") or re.fullmatch(r"[0-9a-f]{40}", ref):
                continue
            if ref in ("main", "master", "develop"):
                findings.append(
                    _finding(
                        rule_id="supply-unpinned-github-action",
                        severity="high",
                        title=f"GitHub Action pinned to mutable branch: {action}",
                        description=f"`{rel}` line {idx} uses `{action}@{ref}` — branch refs are mutable.",
                        impact="Compromised action repos can inject malicious code into your CI pipeline.",
                        fix_recommendation="Pin actions to a full commit SHA (40-char) and verify with Sigstore.",
                        file_path=rel,
                        line_start=idx,
                        line_end=idx,
                        confidence="high",
                        metadata={"action": action, "ref": ref, "cwe_id": "CWE-1357"},
                    )
                )
            elif re.fullmatch(r"v\d+", ref):
                findings.append(
                    _finding(
                        rule_id="supply-unpinned-github-action-tag",
                        severity="medium",
                        title=f"GitHub Action pinned to floating tag: {action}@{ref}",
                        description=f"`{rel}` line {idx} uses tag `{ref}` which can be force-moved.",
                        impact="Tags are not immutable; prefer full commit SHAs for third-party actions.",
                        fix_recommendation=f"Pin `{action}` to a 40-character commit SHA.",
                        file_path=rel,
                        line_start=idx,
                        line_end=idx,
                        confidence="medium",
                        metadata={"action": action, "ref": ref, "cwe_id": "CWE-1357"},
                    )
                )

    return findings


def _dep_file_for_package(project_dir: Path, ecosystem: str) -> str:
    lock_map = {
        "npm": ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "package.json"),
        "PyPI": ("requirements.txt", "pyproject.toml", "poetry.lock"),
    }
    names = lock_map.get(ecosystem, ())
    for lock_name in names:
        for path in project_dir.rglob(lock_name):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            return str(path.relative_to(project_dir)).replace("\\", "/")
    return ""
