"""Health score and audit report generation."""

from __future__ import annotations

from dataclasses import dataclass

from app.models.issue import Issue
from app.models.scan import Scan

SEVERITY_PENALTY = {
    "critical": 10,
    "high": 5,
    "medium": 2,
    "low": 1,
}

PRIORITY_WEIGHT = {
    "critical": 40,
    "high": 30,
    "medium": 20,
    "low": 10,
}

CONFIDENCE_BONUS = {
    "high": 5,
    "medium": 2,
    "low": 0,
}

CATEGORY_WEIGHTS = {
    "security": 0.35,
    "architecture": 0.20,
    "performance": 0.15,
    "quality": 0.15,
    "devops": 0.15,
}

# Map raw issue categories to report categories
ISSUE_CATEGORY_MAP = {
    "security": "security",
    "secrets": "security",
    "dependencies": "quality",
    "architecture": "architecture",
    "performance": "performance",
    "quality": "quality",
    "devops": "devops",
    "iac": "devops",
}

AUDIT_CATEGORIES = ["security", "architecture", "performance", "quality", "devops"]


@dataclass
class CategoryScore:
    category: str
    score: int
    issue_count: int


def map_issue_category(raw_category: str) -> str:
    return ISSUE_CATEGORY_MAP.get(raw_category, "security")


def score_from_issues(issues: list[Issue]) -> int:
    penalty = sum(SEVERITY_PENALTY.get(issue.severity, 2) for issue in issues)
    return max(0, min(100, 100 - penalty))


def calculate_category_scores(issues: list[Issue]) -> list[CategoryScore]:
    grouped: dict[str, list[Issue]] = {cat: [] for cat in AUDIT_CATEGORIES}
    for issue in issues:
        bucket = map_issue_category(issue.category)
        grouped[bucket].append(issue)

    return [
        CategoryScore(
            category=cat,
            score=score_from_issues(grouped[cat]),
            issue_count=len(grouped[cat]),
        )
        for cat in AUDIT_CATEGORIES
    ]


def calculate_overall_score(categories: list[CategoryScore]) -> int:
    total = 0.0
    for cat_score in categories:
        weight = CATEGORY_WEIGHTS[cat_score.category]
        total += cat_score.score * weight
    return round(total)


def score_to_grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def issue_priority(issue: Issue) -> int:
    from app.services.risk_scoring import get_risk_score

    return get_risk_score(issue)


def sort_issues_by_priority(issues: list[Issue]) -> list[Issue]:
    from app.services.risk_scoring import sort_issues_by_risk

    return sort_issues_by_risk(issues)


def generate_executive_summary(overall: int, grade: str, scan: Scan) -> str:
    if scan.status != "completed":
        return "Audit is still in progress. Results will be available when the scan completes."

    if scan.total_issues == 0:
        return (
            f"Overall Health Score: {overall}/100 (Grade {grade}). "
            "No security issues were detected in this audit. "
            "Continue monitoring dependencies and re-scan after major changes."
        )

    if overall >= 80:
        risk = "low to moderate"
    elif overall >= 60:
        risk = "moderate"
    else:
        risk = "high"

    return (
        f"Overall Health Score: {overall}/100 (Grade {grade}). "
        f"This system has {risk} production risk with {scan.total_issues} findings "
        f"({scan.critical_count} critical, {scan.high_count} high). "
        f"Address critical and high severity items first to improve readiness."
    )


def generate_fix_plan(issues: list[Issue], limit: int = 5) -> list[str]:
    plan: list[str] = []
    for index, issue in enumerate(sort_issues_by_priority(issues)[:limit], start=1):
        location = issue.file_path or "project"
        line = f":{issue.line_start}" if issue.line_start > 0 else ""
        extra = issue.extra_data or {}
        risk = extra.get("risk_score")
        risk_note = f" · Risk {risk}/100" if risk is not None else ""
        plan.append(
            f"{index}. [{issue.severity.upper()}]{risk_note} {issue.title} — "
            f"Fix in `{location}{line}`: {issue.fix_recommendation}"
        )
    return plan


def apply_scores_to_scan(scan: Scan, issues: list[Issue]) -> None:
    categories = calculate_category_scores(issues)
    overall = calculate_overall_score(categories)

    scan.health_score = overall
    scan.grade = score_to_grade(overall)
    for cat in categories:
        setattr(scan, f"{cat.category}_score", cat.score)
