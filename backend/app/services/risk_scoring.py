"""Risk Scoring v2 — EPSS + CISA KEV + business-context weighted priority.

Computes a 0–100 risk score per finding so customers get a actionable
"fix now" queue instead of hundreds of equally-weighted alerts.

Signals:
- Base severity
- EPSS exploit probability (CVE findings via FIRST.org)
- CISA Known Exploited Vulnerabilities (KEV) catalog
- CVE reachability, taint verification, live-validated secrets
- Internet-exposed findings (Active DAST / ASM)
- AI triage false-positive demotion
"""

from __future__ import annotations

import logging
import re
import time
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from app.models.issue import Issue
    from app.models.project import Project

logger = logging.getLogger(__name__)

EPSS_API = "https://api.first.org/data/v1/epss"
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

SEVERITY_BASE = {
    "critical": 55,
    "high": 40,
    "medium": 25,
    "low": 10,
}

# In-process caches (refreshed periodically)
_kev_set: set[str] | None = None
_kev_loaded_at: float = 0.0
_epss_cache: dict[str, float] = {}
_CACHE_TTL = 3600 * 6  # 6 hours
_MAX_EPSS_LOOKUPS = 80


def apply_risk_scores(issues: list[Issue], project: Project | None = None) -> None:
    """Annotate each issue's extra_data with risk_score and related signals."""
    if not issues:
        return

    cve_ids = _collect_cve_ids(issues)
    epss_map = _fetch_epss_batch(cve_ids)
    kev = _load_kev_catalog()
    internet_exposed = _project_internet_exposed(project)

    for issue in issues:
        extra = dict(issue.extra_data or {})
        cve = _issue_cve(issue)
        epss = epss_map.get(cve.upper()) if cve else None
        kev_listed = bool(cve and cve.upper() in kev)

        score, factors = _compute_risk_score(
            issue,
            epss=epss,
            kev_listed=kev_listed,
            internet_exposed=internet_exposed,
        )

        extra["risk_score"] = score
        if epss is not None:
            extra["epss_score"] = round(epss, 4)
        extra["kev_listed"] = "true" if kev_listed else "false"
        extra["risk_factors"] = factors
        extra["fix_now"] = "true" if _is_fix_now(score, issue, kev_listed) else "false"

        adjusted = _maybe_adjust_severity(issue, score, kev_listed, extra)
        if adjusted:
            extra["severity_adjusted"] = adjusted
            issue.severity = adjusted

        issue.extra_data = extra


def get_risk_score(issue: Issue) -> int:
    extra = issue.extra_data or {}
    raw = extra.get("risk_score")
    if raw is not None:
        try:
            return int(raw)
        except (TypeError, ValueError):
            pass
    return _fallback_priority(issue)


def sort_issues_by_risk(issues: list[Issue]) -> list[Issue]:
    return sorted(issues, key=get_risk_score, reverse=True)


def _collect_cve_ids(issues: list[Issue]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for issue in issues:
        cve = _issue_cve(issue)
        if cve and cve.upper() not in seen:
            seen.add(cve.upper())
            result.append(cve.upper())
        if len(result) >= _MAX_EPSS_LOOKUPS:
            break
    return result


def _issue_cve(issue: Issue) -> str | None:
    extra = issue.extra_data or {}
    for candidate in (issue.rule_id, extra.get("cve_id"), issue.title, issue.description):
        if not candidate:
            continue
        match = CVE_PATTERN.search(str(candidate))
        if match:
            return match.group(0).upper()
    return None


def _fetch_epss_batch(cve_ids: list[str]) -> dict[str, float]:
    if not cve_ids:
        return {}

    missing = [c for c in cve_ids if c not in _epss_cache]
    if missing:
        try:
            with httpx.Client(timeout=20.0) as client:
                # FIRST.org supports comma-separated CVE list
                for chunk_start in range(0, len(missing), 30):
                    chunk = missing[chunk_start : chunk_start + 30]
                    resp = client.get(EPSS_API, params={"cve": ",".join(chunk)})
                    if resp.status_code != 200:
                        continue
                    payload = resp.json()
                    for row in payload.get("data", []):
                        cve = str(row.get("cve", "")).upper()
                        try:
                            _epss_cache[cve] = float(row.get("epss", 0))
                        except (TypeError, ValueError):
                            continue
        except httpx.HTTPError as exc:
            logger.warning("EPSS lookup failed: %s", exc)

    return {c: _epss_cache[c] for c in cve_ids if c in _epss_cache}


def _load_kev_catalog() -> set[str]:
    global _kev_set, _kev_loaded_at
    now = time.time()
    if _kev_set is not None and (now - _kev_loaded_at) < _CACHE_TTL:
        return _kev_set

    try:
        with httpx.Client(timeout=30.0, follow_redirects=True) as client:
            resp = client.get(KEV_URL)
            resp.raise_for_status()
            data = resp.json()
        catalog = {
            str(v.get("cveID", "")).upper()
            for v in data.get("vulnerabilities", [])
            if v.get("cveID")
        }
        _kev_set = catalog
        _kev_loaded_at = now
        logger.info("Loaded CISA KEV catalog: %d CVEs", len(catalog))
    except Exception as exc:
        logger.warning("KEV catalog load failed: %s", exc)
        if _kev_set is None:
            _kev_set = set()

    return _kev_set


def _project_internet_exposed(project: Project | None) -> bool:
    if not project:
        return False
    return project.source_type in ("website", "api") or bool(
        getattr(project, "asm_enabled", False)
    )


def _compute_risk_score(
    issue: Issue,
    *,
    epss: float | None,
    kev_listed: bool,
    internet_exposed: bool,
) -> tuple[int, str]:
    extra = issue.extra_data or {}
    factors: list[str] = []
    score = float(SEVERITY_BASE.get(issue.severity, 20))
    factors.append(f"severity:{issue.severity}")

    if epss is not None:
        epss_boost = int(epss * 25)
        score += epss_boost
        factors.append(f"epss:{epss:.2%}")
        if epss >= 0.5:
            factors.append("high_epss")

    if kev_listed:
        score += 20
        factors.append("cisa_kev")

    reachable = extra.get("reachable")
    if reachable == "yes":
        score += 12
        factors.append("reachable")
    elif reachable == "no":
        score -= 15
        factors.append("unreachable")

    if str(extra.get("taint_verified", "")).lower() == "true":
        score += 10
        factors.append("taint_verified")

    validated = extra.get("validated")
    if validated == "active":
        score += 25
        factors.append("secret_active")
    elif validated == "inactive":
        score -= 10
        factors.append("secret_revoked")

    if issue.scanner in ("active-dast", "asm"):
        score += 8
        factors.append("internet_exposed")
    elif issue.scanner == "browser-dast":
        score += 10
        factors.append("browser_verified")
    elif issue.scanner == "cloud-cspm":
        score += 12
        factors.append("cloud_misconfig")
    elif internet_exposed and issue.category in ("security", "secrets"):
        score += 4
        factors.append("live_target")

    if issue.rule_id.startswith("active-"):
        score += 5
        factors.append("dast_confirmed")

    if issue.rule_id == "asm-subdomain-takeover":
        score += 15
        factors.append("subdomain_takeover")

    if issue.rule_id in ("graphql-introspection-enabled", "ws-origin-not-validated", "ws-message-injection"):
        score += 12
        factors.append("api_realtime_critical")

    _CRITICAL_CLOUD_RULES = {
        "cloud-aws-root-access-keys",
        "cloud-aws-s3-public-policy",
        "cloud-aws-sg-open-sensitive-port",
        "cloud-aws-rds-public",
        "cloud-azure-storage-public-blob",
        "cloud-gcp-bucket-public-iam",
    }
    if issue.rule_id in _CRITICAL_CLOUD_RULES:
        score += 15
        factors.append("critical_cloud_exposure")

    if issue.scanner in ("graphql-security", "websocket-security"):
        score += 6
        factors.append("graphql_or_ws")

    if issue.confidence == "high":
        score += 3

    verdict = extra.get("ai_triage_verdict")
    if verdict == "likely_false_positive":
        score -= 25
        factors.append("likely_fp")

    return max(0, min(100, int(round(score)))), ",".join(factors)


def _is_fix_now(score: int, issue: Issue, kev_listed: bool) -> bool:
    extra = issue.extra_data or {}
    if extra.get("validated") == "active":
        return True
    if kev_listed and extra.get("reachable") != "no":
        return True
    if issue.rule_id == "asm-subdomain-takeover":
        return True
    if issue.rule_id in ("graphql-introspection-enabled", "ws-origin-not-validated", "ws-message-injection"):
        return True
    if issue.rule_id == "browser-dom-xss":
        return True
    if issue.rule_id in (
        "cloud-aws-root-access-keys",
        "cloud-aws-s3-public-policy",
        "cloud-aws-sg-open-sensitive-port",
        "cloud-aws-rds-public",
        "cloud-azure-storage-public-blob",
        "cloud-gcp-bucket-public-iam",
    ):
        return True
    if score >= 75:
        return True
    if issue.severity == "critical" and score >= 60:
        return True
    return False


def _maybe_adjust_severity(
    issue: Issue,
    score: int,
    kev_listed: bool,
    extra: dict,
) -> str | None:
    """Upgrade/downgrade severity when exploit intelligence strongly disagrees."""
    current = issue.severity
    if kev_listed and extra.get("reachable") == "yes" and current in ("high", "medium"):
        return "critical"
    if kev_listed and current == "medium":
        return "high"
    if score >= 85 and current == "high":
        return "critical"
    if score <= 15 and current in ("high", "medium") and extra.get("reachable") == "no":
        return "low"
    return None


def _fallback_priority(issue: Issue) -> int:
    return SEVERITY_BASE.get(issue.severity, 10)
