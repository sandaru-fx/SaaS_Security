"""AI Auditor Layer.

Turns raw scanner findings into professional, business-language audit
narratives in the signature format: Problem -> Impact -> Business Risk -> Fix
-> Priority.

When a Gemini or OpenAI API key is configured the layer uses an LLM for richer,
context-aware narratives. Without a key it falls back to a deterministic,
rule-based generator so the product works fully offline.
"""

from __future__ import annotations

import json
import logging

from app.config import get_settings
from app.models.issue import Issue
from app.models.scan import Scan
from app.services.cwe_knowledge import cwe_context
from app.services.report_service import (
    calculate_category_scores,
    map_issue_category,
    sort_issues_by_priority,
)

logger = logging.getLogger(__name__)

# Business-language risk templates keyed by report category.
CATEGORY_RISK = {
    "security": (
        "Attackers could exploit this to access systems or data, leading to "
        "breaches, regulatory penalties (GDPR/PCI), and loss of customer trust."
    ),
    "architecture": (
        "Weak structure increases the cost of every future change, slows "
        "delivery, and raises the chance of outages as the system grows."
    ),
    "performance": (
        "Slow or inefficient code degrades user experience and inflates "
        "infrastructure cost, directly hurting conversion and retention."
    ),
    "quality": (
        "Low code quality and unmanaged dependencies cause defects, harder "
        "maintenance, and unpredictable release timelines."
    ),
    "devops": (
        "Gaps in delivery and configuration make deployments risky and recovery "
        "from incidents slow, threatening uptime commitments."
    ),
}

SEVERITY_BUSINESS_TONE = {
    "critical": "an immediate, business-stopping",
    "high": "a serious",
    "medium": "a moderate",
    "low": "a minor",
}


def _issue_business_risk(issue: Issue) -> str:
    category = map_issue_category(issue.category)
    tone = SEVERITY_BUSINESS_TONE.get(issue.severity, "a")
    base = CATEGORY_RISK.get(category, CATEGORY_RISK["security"])
    return f"This is {tone} risk. {base}"


def _rule_based_summary(scan: Scan, issues: list[Issue]) -> str:
    score = scan.health_score if scan.health_score is not None else 0
    grade = scan.grade or "N/A"

    if not issues:
        return (
            f"This audit gives the project a health score of {score}/100 "
            f"(Grade {grade}). No issues were detected by the configured "
            "scanners. The codebase appears to follow safe practices, but "
            "continue re-auditing after major changes and dependency updates."
        )

    if score >= 80:
        posture = "in good shape but not flawless"
    elif score >= 60:
        posture = "carrying meaningful risk that should be addressed soon"
    else:
        posture = "in a high-risk state that needs urgent remediation"

    return (
        f"This audit gives the project a health score of {score}/100 "
        f"(Grade {grade}). The codebase is {posture}. We found "
        f"{scan.total_issues} findings: {scan.critical_count} critical, "
        f"{scan.high_count} high, {scan.medium_count} medium, and "
        f"{scan.low_count} low. Critical and high severity items concentrate "
        "the most business risk and should be resolved before the next release."
    )


def _rule_based_business_risk(scan: Scan, issues: list[Issue]) -> str:
    if not issues:
        return (
            "Current business risk is low. No exploitable issues were found, "
            "so the application can be operated with standard monitoring."
        )

    categories = calculate_category_scores(issues)
    weakest = min(categories, key=lambda c: c.score)

    if scan.critical_count > 0:
        headline = (
            f"Business risk is HIGH. {scan.critical_count} critical "
            "issue(s) could lead to a security breach, data loss, or outage "
            "with direct financial and reputational damage."
        )
    elif scan.high_count > 0:
        headline = (
            "Business risk is ELEVATED. High severity issues create a "
            "realistic path to incidents that could disrupt operations."
        )
    else:
        headline = (
            "Business risk is MODERATE. No critical paths were found, but "
            "unresolved issues will accumulate into future cost and instability."
        )

    return (
        f"{headline} The weakest area is {weakest.category} "
        f"({weakest.score}/100). {CATEGORY_RISK.get(weakest.category, '')}"
    )


def _rule_based_recommendations(scan: Scan, issues: list[Issue]) -> list[str]:
    recs: list[str] = []

    if scan.critical_count > 0:
        recs.append(
            f"Treat the {scan.critical_count} critical issue(s) as a release "
            "blocker and remediate them immediately."
        )
    if scan.high_count > 0:
        recs.append(
            f"Schedule the {scan.high_count} high severity issue(s) into the "
            "current sprint before shipping new features."
        )

    categories = calculate_category_scores(issues)
    for cat in sorted(categories, key=lambda c: c.score):
        if cat.score < 70 and cat.issue_count > 0:
            recs.append(
                f"Invest in {cat.category}: it scored {cat.score}/100 with "
                f"{cat.issue_count} finding(s). {CATEGORY_RISK.get(cat.category, '')}"
            )

    if not recs:
        recs.append(
            "Maintain current practices and re-audit after each significant "
            "change or dependency upgrade."
        )

    recs.append(
        "Add this audit to CI so regressions are caught automatically on every "
        "pull request."
    )
    return recs[:6]


def _build_ai_prompt(scan: Scan, issues: list[Issue]) -> str:
    top = sort_issues_by_priority(issues)[:15]
    lines = [
        f"Health score: {scan.health_score}/100 (Grade {scan.grade}).",
        f"Counts: critical={scan.critical_count}, high={scan.high_count}, "
        f"medium={scan.medium_count}, low={scan.low_count}.",
        "Top findings:",
    ]
    for i, issue in enumerate(top, start=1):
        location = issue.file_path or "project"
        extra = issue.extra_data or {}
        cwe = extra.get("cwe_id")
        cwe_line = f" CWE: {cwe_context(cwe)}" if cwe else ""
        lines.append(
            f"{i}. [{issue.severity}] {issue.title} "
            f"({map_issue_category(issue.category)}) in {location} — "
            f"{issue.description[:160]}{cwe_line}"
        )
    return "\n".join(lines)


def _generate_with_gemini(scan: Scan, issues: list[Issue]) -> dict | None:
    settings = get_settings()
    try:
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=settings.gemini_api_key)
        system = (
            "You are a senior software auditor writing for a non-technical "
            "executive. Convert technical findings into clear business "
            "language. Always respond as strict JSON with keys: "
            "summary (string), business_risk (string), recommendations "
            "(array of short strings, max 6)."
        )
        user = _build_ai_prompt(scan, issues)

        response = client.models.generate_content(
            model=settings.gemini_model,
            contents=f"{system}\n\n{user}",
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                temperature=0.3,
            ),
        )
        content = response.text or "{}"
        data = json.loads(content)
        return {
            "summary": str(data.get("summary", "")).strip(),
            "business_risk": str(data.get("business_risk", "")).strip(),
            "recommendations": [
                str(r).strip() for r in data.get("recommendations", []) if str(r).strip()
            ][:6],
        }
    except Exception as exc:  # pragma: no cover - network/SDK errors
        logger.warning("Gemini audit generation failed, using fallback: %s", exc)
        return None


def _generate_with_openai(scan: Scan, issues: list[Issue]) -> dict | None:
    settings = get_settings()
    try:
        from openai import OpenAI

        client_kwargs = {"api_key": settings.openai_api_key}
        if settings.openai_base_url:
            client_kwargs["base_url"] = settings.openai_base_url
        client = OpenAI(**client_kwargs)

        system = (
            "You are a senior software auditor writing for a non-technical "
            "executive. Convert technical findings into clear business "
            "language. Always respond as strict JSON with keys: "
            "summary (string), business_risk (string), recommendations "
            "(array of short strings, max 6)."
        )
        user = _build_ai_prompt(scan, issues)

        response = client.chat.completions.create(
            model=settings.openai_model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            response_format={"type": "json_object"},
            temperature=0.3,
            max_tokens=900,
        )
        content = response.choices[0].message.content or "{}"
        data = json.loads(content)
        return {
            "summary": str(data.get("summary", "")).strip(),
            "business_risk": str(data.get("business_risk", "")).strip(),
            "recommendations": [
                str(r).strip() for r in data.get("recommendations", []) if str(r).strip()
            ][:6],
        }
    except Exception as exc:  # pragma: no cover - network/SDK errors
        logger.warning("OpenAI audit generation failed, using fallback: %s", exc)
        return None


def enrich_scan_with_ai(scan: Scan, issues: list[Issue], *, allow_deep_audit: bool = True) -> None:
    """Populate AI narrative fields on the scan and per-issue business risk.

    Deep Audit (OpenAI) requires Pro/Team when ``allow_deep_audit`` is True.
    Never raises: a failure here must not break a completed scan.
    """
    try:
        for issue in issues:
            if not issue.business_risk:
                issue.business_risk = _issue_business_risk(issue)

        ai_result = None
        provider = "rule-based"
        if get_settings().ai_enabled and allow_deep_audit:
            settings = get_settings()
            if settings.gemini_api_key:
                ai_result = _generate_with_gemini(scan, issues)
                if ai_result and ai_result.get("summary"):
                    provider = "gemini"
            elif settings.openai_api_key:
                ai_result = _generate_with_openai(scan, issues)
                if ai_result and ai_result.get("summary"):
                    provider = "openai"

        if ai_result and provider in ("openai", "gemini"):
            scan.ai_summary = ai_result["summary"]
            scan.ai_business_risk = ai_result["business_risk"] or _rule_based_business_risk(
                scan, issues
            )
            recommendations = ai_result["recommendations"] or _rule_based_recommendations(
                scan, issues
            )
        else:
            scan.ai_summary = _rule_based_summary(scan, issues)
            scan.ai_business_risk = _rule_based_business_risk(scan, issues)
            recommendations = _rule_based_recommendations(scan, issues)

        scan.ai_recommendations = json.dumps(recommendations)
        scan.ai_provider = provider
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("AI enrichment failed: %s", exc)


def parse_recommendations(raw: str | None) -> list[str]:
    if not raw:
        return []
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return [str(item) for item in data]
    except (json.JSONDecodeError, TypeError):
        pass
    return []
