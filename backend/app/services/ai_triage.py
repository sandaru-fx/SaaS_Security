"""AI triage and auto-fix suggestions for audit findings."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from app.config import get_settings
from app.models.issue import Issue
from app.models.project import Project
from app.models.scan import Scan
from app.services.cwe_knowledge import cwe_context
from app.services.report_service import sort_issues_by_priority

logger = logging.getLogger(__name__)

MAX_TRIAGE_ISSUES = 10
SNIPPET_CONTEXT_LINES = 6


def run_ai_triage(
    scan: Scan,
    issues: list[Issue],
    *,
    project: Project | None = None,
    allow_deep_audit: bool = True,
) -> None:
    """Annotate top issues with triage verdicts and fix suggestions."""
    try:
        top = sort_issues_by_priority(issues)[:MAX_TRIAGE_ISSUES]
        if not top:
            return

        settings = get_settings()
        ai_result = None
        if settings.ai_enabled and allow_deep_audit:
            if settings.gemini_api_key:
                ai_result = _triage_with_gemini(scan, top, project)
            elif settings.openai_api_key:
                ai_result = _triage_with_openai(scan, top, project)

        if ai_result:
            _apply_triage_results(top, ai_result)
        else:
            _rule_based_triage(top)
    except Exception as exc:  # pragma: no cover
        logger.warning("AI triage failed: %s", exc)


def _read_snippet(project: Project | None, issue: Issue) -> str | None:
    if not project or not project.storage_path or not issue.file_path:
        return None
    if issue.file_path.startswith("http"):
        return None

    base = Path(project.storage_path)
    if not base.is_absolute():
        base = Path.cwd() / base
    file_path = base / issue.file_path.replace("/", "\\") if "\\" in str(base) else base / issue.file_path
    if not file_path.exists():
        return None

    try:
        lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return None

    if issue.line_start <= 0:
        return "\n".join(lines[:20])[:1200]

    start = max(0, issue.line_start - SNIPPET_CONTEXT_LINES - 1)
    end = min(len(lines), issue.line_start + SNIPPET_CONTEXT_LINES)
    snippet_lines = [f"{i + 1}: {lines[i]}" for i in range(start, end)]
    return "\n".join(snippet_lines)[:1500]


def _build_triage_prompt(scan: Scan, issues: list[Issue], project: Project | None) -> str:
    lines = [
        f"Audit score: {scan.health_score}/100, grade {scan.grade}.",
        f"Issues to triage ({len(issues)}):",
    ]
    for i, issue in enumerate(issues, start=1):
        extra = issue.extra_data or {}
        cwe = extra.get("cwe_id")
        cwe_note = cwe_context(cwe) if cwe else ""
        snippet = _read_snippet(project, issue)
        lines.append(
            f"\n{i}. [{issue.severity}] {issue.title}\n"
            f"   Scanner: {issue.scanner}, rule: {issue.rule_id}\n"
            f"   Location: {issue.file_path or 'n/a'}:{issue.line_start}\n"
            f"   Problem: {issue.description[:200]}\n"
            f"   Impact: {issue.impact[:160]}\n"
            f"   CWE context: {cwe_note or 'n/a'}"
        )
        if snippet:
            lines.append(f"   Code snippet:\n{snippet}")
    return "\n".join(lines)


def _triage_with_gemini(scan: Scan, issues: list[Issue], project: Project | None) -> list[dict] | None:
    settings = get_settings()
    try:
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=settings.gemini_api_key)
        system = (
            "You are a senior application security engineer triaging static analysis findings. "
            "For each numbered issue respond with verdict (confirmed, likely_false_positive, needs_review), "
            "a short reason, and a concrete fix_suggestion (code patch or clear remediation steps). "
            "Return strict JSON: {\"issues\": [{\"index\": 1, \"verdict\": \"...\", \"reason\": \"...\", "
            "\"fix_suggestion\": \"...\"}]}"
        )
        response = client.models.generate_content(
            model=settings.gemini_model,
            contents=f"{system}\n\n{_build_triage_prompt(scan, issues, project)}",
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                temperature=0.2,
            ),
        )
        data = json.loads(response.text or "{}")
        return data.get("issues", [])
    except Exception as exc:
        logger.warning("Gemini triage failed: %s", exc)
        return None


def _triage_with_openai(scan: Scan, issues: list[Issue], project: Project | None) -> list[dict] | None:
    settings = get_settings()
    try:
        from openai import OpenAI

        client_kwargs = {"api_key": settings.openai_api_key}
        if settings.openai_base_url:
            client_kwargs["base_url"] = settings.openai_base_url
        client = OpenAI(**client_kwargs)

        system = (
            "You are a senior application security engineer triaging static analysis findings. "
            "For each numbered issue respond with verdict (confirmed, likely_false_positive, needs_review), "
            "a short reason, and a concrete fix_suggestion. "
            "Return strict JSON: {\"issues\": [{\"index\": 1, \"verdict\": \"...\", \"reason\": \"...\", "
            "\"fix_suggestion\": \"...\"}]}"
        )
        response = client.chat.completions.create(
            model=settings.openai_model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": _build_triage_prompt(scan, issues, project)},
            ],
            response_format={"type": "json_object"},
            temperature=0.2,
            max_tokens=2000,
        )
        data = json.loads(response.choices[0].message.content or "{}")
        return data.get("issues", [])
    except Exception as exc:
        logger.warning("OpenAI triage failed: %s", exc)
        return None


def _apply_triage_results(issues: list[Issue], results: list[dict]) -> None:
    by_index = {int(r.get("index", 0)): r for r in results if r.get("index")}
    for i, issue in enumerate(issues, start=1):
        result = by_index.get(i, {})
        verdict = str(result.get("verdict", "needs_review")).strip().lower()
        if verdict not in ("confirmed", "likely_false_positive", "needs_review"):
            verdict = "needs_review"
        extra = dict(issue.extra_data or {})
        extra["ai_triage_verdict"] = verdict
        extra["ai_triage_reason"] = str(result.get("reason", "")).strip()[:500]
        fix = str(result.get("fix_suggestion", "")).strip()
        if fix:
            extra["ai_fix_suggestion"] = fix[:2000]
        issue.extra_data = extra


def _rule_based_triage(issues: list[Issue]) -> None:
    for issue in issues:
        extra = dict(issue.extra_data or {})
        path = (issue.file_path or "").lower()
        verdict = "needs_review"
        reason = "Manual review recommended to confirm exploitability in your context."

        if any(token in path for token in ("example", "sample", "test", "mock", ".md")):
            verdict = "likely_false_positive"
            reason = "Finding is in example, test, or documentation path — often intentional."
        elif issue.confidence == "high" and issue.severity in ("critical", "high"):
            verdict = "confirmed"
            reason = "High-confidence scanner match with elevated severity — treat as real risk."
        elif issue.scanner == "osv":
            verdict = "confirmed"
            reason = "Known CVE in a dependency — verify usage and upgrade path."
        elif issue.severity == "low":
            verdict = "needs_review"
            reason = "Low severity — prioritize against business context."

        extra["ai_triage_verdict"] = verdict
        extra["ai_triage_reason"] = reason
        extra["ai_fix_suggestion"] = issue.fix_recommendation[:2000]
        issue.extra_data = extra
