from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.issue import Issue
from app.models.scan import Scan
from app.schemas.scan import (
    AuditReportResponse,
    CategoryScoreResponse,
    ComplianceControlResponse,
    IssueResponse,
)
from app.services.compliance_service import build_compliance_summary
from app.services.ai_auditor import parse_recommendations
from app.services.autofix_service import is_autofixable
from app.services.risk_scoring import apply_risk_scores, get_risk_score
from app.services.report_service import (
    apply_scores_to_scan,
    calculate_category_scores,
    calculate_overall_score,
    generate_executive_summary,
    generate_fix_plan,
    issue_priority,
    map_issue_category,
    score_to_grade,
    sort_issues_by_priority,
)


def issue_to_response(issue: Issue) -> IssueResponse:
    extra = issue.extra_data or {}
    return IssueResponse(
        id=issue.id,
        scan_id=issue.scan_id,
        category=issue.category,
        severity=issue.severity,
        title=issue.title,
        description=issue.description,
        impact=issue.impact,
        fix_recommendation=issue.fix_recommendation,
        business_risk=issue.business_risk,
        file_path=issue.file_path,
        line_start=issue.line_start,
        line_end=issue.line_end,
        rule_id=issue.rule_id,
        scanner=issue.scanner,
        confidence=issue.confidence,
        priority=issue_priority(issue),
        report_category=map_issue_category(issue.category),
        dismissed=bool(issue.dismissed),
        dismissed_reason=issue.dismissed_reason,
        cwe_id=extra.get("cwe_id"),
        owasp_category=extra.get("owasp_category"),
        ai_triage_verdict=extra.get("ai_triage_verdict"),
        ai_triage_reason=extra.get("ai_triage_reason"),
        ai_fix_suggestion=extra.get("ai_fix_suggestion"),
        reachable=extra.get("reachable"),
        reachable_files=extra.get("reachable_files"),
        taint_verified=str(extra.get("taint_verified", "")).lower() == "true",
        validated=extra.get("validated"),
        validated_principal=extra.get("validated_principal"),
        validated_method=extra.get("validated_method"),
        secret_preview=extra.get("secret_preview"),
        risk_score=_int_or_none(extra.get("risk_score")),
        epss_score=_float_or_none(extra.get("epss_score")),
        kev_listed=str(extra.get("kev_listed", "")).lower() == "true",
        risk_factors=extra.get("risk_factors"),
        fix_now=str(extra.get("fix_now", "")).lower() == "true",
        severity_adjusted=extra.get("severity_adjusted"),
        autofixable=is_autofixable(issue),
        autofix_pr_url=extra.get("autofix_pr_url"),
        created_at=issue.created_at,
    )


def _int_or_none(value) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _float_or_none(value) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


async def build_audit_report(db: AsyncSession, scan: Scan) -> AuditReportResponse:
    result = await db.execute(select(Issue).where(Issue.scan_id == scan.id))
    issues = list(result.scalars().all())

    from app.models.project import Project

    project = await db.get(Project, scan.project_id)

    needs_commit = False
    if issues and any((i.extra_data or {}).get("risk_score") is None for i in issues):
        apply_risk_scores(issues, project)
        from app.services.scan_runner import _recount_severities

        _recount_severities(scan, issues)
        needs_commit = True

    if scan.health_score is None and issues:
        apply_scores_to_scan(scan, issues)
        needs_commit = True

    if scan.status == "completed" and scan.ai_summary is None:
        from app.models.user import User
        from app.services.ai_auditor import enrich_scan_with_ai
        from app.services.subscription_service import has_feature

        user = await db.get(User, scan.user_id)
        allow_deep = has_feature(user, "deep_audit") if user else False
        enrich_scan_with_ai(scan, issues, allow_deep_audit=allow_deep)
        from app.services.ai_triage import run_ai_triage

        run_ai_triage(scan, issues, project=project, allow_deep_audit=allow_deep)
        needs_commit = True

    if needs_commit:
        await db.commit()
        await db.refresh(scan)

    categories = calculate_category_scores(issues)
    overall = (
        scan.health_score
        if scan.health_score is not None
        else calculate_overall_score(categories)
    )
    grade = scan.grade or score_to_grade(overall)

    ranked = sort_issues_by_priority(issues)
    top_issues = ranked[:10]
    fix_now = [i for i in ranked if str((i.extra_data or {}).get("fix_now", "")).lower() == "true"][:12]
    fix_targets = fix_now[:5] if fix_now else [i for i in issues if i.severity in ("critical", "high")][:5]
    max_risk = max((get_risk_score(i) for i in issues), default=None)
    estimated = _estimate_score_after_fixes(issues, fix_targets)
    compliance = build_compliance_summary(issues)

    return AuditReportResponse(
        scan_id=scan.id,
        project_id=scan.project_id,
        status=scan.status,
        overall_score=overall,
        grade=grade,
        categories=[
            CategoryScoreResponse(
                category=c.category,
                score=getattr(scan, f"{c.category}_score", None) or c.score,
                issue_count=c.issue_count,
            )
            for c in categories
        ],
        severity_breakdown={
            "critical": scan.critical_count,
            "high": scan.high_count,
            "medium": scan.medium_count,
            "low": scan.low_count,
        },
        executive_summary=generate_executive_summary(overall, grade, scan),
        fix_plan=generate_fix_plan(issues),
        top_priority_issues=[issue_to_response(i) for i in top_issues],
        fix_now_issues=[issue_to_response(i) for i in fix_now],
        fix_now_count=len(fix_now),
        max_risk_score=max_risk,
        production_ready=overall >= 80 and scan.critical_count == 0,
        estimated_score_if_top_fixed=estimated,
        ai_summary=scan.ai_summary,
        ai_business_risk=scan.ai_business_risk,
        ai_recommendations=parse_recommendations(scan.ai_recommendations),
        ai_provider=scan.ai_provider,
        compliance=[
            ComplianceControlResponse(
                framework=c.framework,
                control_id=c.control_id,
                title=c.title,
                issue_count=c.issue_count,
                max_severity=c.max_severity,
                status=c.status,
            )
            for c in compliance
        ],
    )


def _estimate_score_after_fixes(all_issues: list[Issue], to_fix: list[Issue]) -> int | None:
    if not to_fix:
        return None

    fix_ids = {issue.id for issue in to_fix}
    remaining = [issue for issue in all_issues if issue.id not in fix_ids]
    categories = calculate_category_scores(remaining)
    return calculate_overall_score(categories)
