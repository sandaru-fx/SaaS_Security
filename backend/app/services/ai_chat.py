"""Chat with completed audit reports."""

from __future__ import annotations

import json
import logging

from app.config import get_settings
from app.models.issue import Issue
from app.models.scan import Scan
from app.services.ai_auditor import parse_recommendations
from app.services.cwe_knowledge import cwe_context
from app.services.report_service import sort_issues_by_priority

logger = logging.getLogger(__name__)


def _build_scan_context(scan: Scan, issues: list[Issue]) -> str:
    top = sort_issues_by_priority(issues)[:12]
    lines = [
        f"Health score: {scan.health_score}/100 (Grade {scan.grade}).",
        f"Findings: {scan.total_issues} total "
        f"(critical={scan.critical_count}, high={scan.high_count}, "
        f"medium={scan.medium_count}, low={scan.low_count}).",
    ]
    if scan.ai_summary:
        lines.append(f"Executive summary: {scan.ai_summary}")
    if scan.ai_business_risk:
        lines.append(f"Business risk: {scan.ai_business_risk}")
    recs = parse_recommendations(scan.ai_recommendations)
    if recs:
        lines.append("Recommendations: " + "; ".join(recs[:4]))

    lines.append("\nTop findings:")
    for i, issue in enumerate(top, start=1):
        extra = issue.extra_data or {}
        cwe = extra.get("cwe_id")
        lines.append(
            f"{i}. [{issue.severity}] {issue.title} — {issue.file_path or 'project'} "
            f"({extra.get('ai_triage_verdict', 'unreviewed')}) "
            f"{cwe_context(cwe) if cwe else ''}"
        )
    return "\n".join(lines)


def _rule_based_reply(scan: Scan, issues: list[Issue], message: str) -> str:
    lower = message.lower()
    top = sort_issues_by_priority(issues)

    if "critical" in lower or "urgent" in lower or "top" in lower:
        critical = [i for i in top if i.severity in ("critical", "high")][:5]
        if not critical:
            return "No critical or high severity findings in this audit. Focus on medium items for hardening."
        items = "\n".join(f"- [{i.severity}] {i.title} ({i.file_path or 'n/a'})" for i in critical)
        return f"Top priority items:\n{items}\n\nAddress critical/high findings before your next release."

    if "score" in lower or "grade" in lower or "ready" in lower:
        score = scan.health_score or 0
        ready = score >= 80 and scan.critical_count == 0
        return (
            f"Health score is {score}/100 (Grade {scan.grade or 'N/A'}). "
            f"{'The project looks production-ready from a scanner perspective.' if ready else 'Remediation is recommended before calling this production-ready.'}"
        )

    if "false positive" in lower:
        flagged = [
            i for i in top
            if (i.extra_data or {}).get("ai_triage_verdict") == "likely_false_positive"
        ]
        if not flagged:
            return "No findings were flagged as likely false positives. Review high-confidence items manually."
        items = "\n".join(f"- {i.title}: {(i.extra_data or {}).get('ai_triage_reason', '')}" for i in flagged[:5])
        return f"Likely false positives:\n{items}"

    if not top:
        return "This audit has no findings. Ask about score, compliance, or how to keep the project secure."

    sample = top[0]
    return (
        f"This audit has {scan.total_issues} findings. Highest priority: [{sample.severity}] "
        f"{sample.title}. Ask about 'top risks', 'score', or 'false positives' for more detail. "
        "Upgrade to Pro for full AI-powered chat."
    )


def chat_with_audit(
    scan: Scan,
    issues: list[Issue],
    message: str,
    history: list[dict[str, str]] | None = None,
    *,
    allow_deep_audit: bool = True,
) -> dict[str, str]:
    """Answer a user question about a completed audit."""
    settings = get_settings()
    history = history or []

    if settings.ai_enabled and allow_deep_audit:
        if settings.gemini_api_key:
            reply = _chat_gemini(scan, issues, message, history)
            if reply:
                return {"reply": reply, "provider": "gemini"}
        elif settings.openai_api_key:
            reply = _chat_openai(scan, issues, message, history)
            if reply:
                return {"reply": reply, "provider": "openai"}

    return {"reply": _rule_based_reply(scan, issues, message), "provider": "rule-based"}


def _chat_gemini(
    scan: Scan, issues: list[Issue], message: str, history: list[dict[str, str]]
) -> str | None:
    settings = get_settings()
    try:
        from google import genai

        client = genai.Client(api_key=settings.gemini_api_key)
        context = _build_scan_context(scan, issues)
        transcript = "\n".join(
            f"{m.get('role', 'user').upper()}: {m.get('content', '')}" for m in history[-6:]
        )
        prompt = (
            "You are an AI software auditor assistant. Answer using ONLY the audit context below. "
            "Be concise, actionable, and use business-friendly language.\n\n"
            f"AUDIT CONTEXT:\n{context}\n\n"
            f"{transcript}\nUSER: {message}\nASSISTANT:"
        )
        response = client.models.generate_content(
            model=settings.gemini_model,
            contents=prompt,
        )
        return (response.text or "").strip()
    except Exception as exc:
        logger.warning("Gemini chat failed: %s", exc)
        return None


def _chat_openai(
    scan: Scan, issues: list[Issue], message: str, history: list[dict[str, str]]
) -> str | None:
    settings = get_settings()
    try:
        from openai import OpenAI

        client_kwargs = {"api_key": settings.openai_api_key}
        if settings.openai_base_url:
            client_kwargs["base_url"] = settings.openai_base_url
        client = OpenAI(**client_kwargs)

        messages = [
            {
                "role": "system",
                "content": (
                    "You are an AI software auditor assistant. Answer using only the audit context. "
                    "Be concise and actionable.\n\n" + _build_scan_context(scan, issues)
                ),
            },
        ]
        for item in history[-6:]:
            role = item.get("role", "user")
            if role in ("user", "assistant"):
                messages.append({"role": role, "content": item.get("content", "")})
        messages.append({"role": "user", "content": message})

        response = client.chat.completions.create(
            model=settings.openai_model,
            messages=messages,
            temperature=0.3,
            max_tokens=700,
        )
        return (response.choices[0].message.content or "").strip()
    except Exception as exc:
        logger.warning("OpenAI chat failed: %s", exc)
        return None
