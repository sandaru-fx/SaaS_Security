"""GitHub Pull Request bot — scan PR branches, post comments, and commit status checks."""

from __future__ import annotations

import hashlib
import hmac
import logging
import tempfile
import threading
from pathlib import Path

import httpx
from sqlalchemy import select

from app.config import get_settings
from app.db_sync import get_sync_session
from app.models.project import Project
from app.models.user import User
from app.scanners.runner import run_all_scanners
from app.services.github import build_github_headers, build_github_zipball_url, parse_github_url
from app.services.storage import safe_extract_zip

logger = logging.getLogger(__name__)
settings = get_settings()

STATUS_CONTEXT = "ai-software-auditor/security"


def verify_github_signature(payload: bytes, signature_header: str | None) -> bool:
    secret = settings.github_webhook_secret
    if not secret:
        return True  # dev mode without secret
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature_header)


def handle_pull_request_event(payload: dict) -> None:
    action = payload.get("action", "")
    if action not in ("opened", "synchronize", "reopened"):
        return

    repo = payload.get("repository", {})
    full_name = repo.get("full_name", "")
    if not full_name:
        return

    pr = payload.get("pull_request", {})
    pr_number = pr.get("number")
    head_sha = pr.get("head", {}).get("sha")
    if not pr_number or not head_sha:
        return

    repo_url = f"https://github.com/{full_name}"
    session = get_sync_session()
    try:
        project = session.execute(
            select(Project).where(
                Project.repo_url == repo_url,
                Project.pr_checks_enabled.is_(True),
                Project.source_type == "github",
            )
        ).scalar_one_or_none()
        if not project:
            logger.info("No project with PR checks for %s", repo_url)
            return

        user = session.get(User, project.user_id)
        if not user or not user.github_pat:
            logger.warning("PR check skipped — GitHub PAT not configured for user %s", project.user_id)
            return

        threading.Thread(
            target=_run_pr_audit,
            args=(str(project.id), full_name, int(pr_number), head_sha, user.github_pat),
            daemon=True,
        ).start()
    finally:
        session.close()


def _run_pr_audit(
    project_id: str,
    full_name: str,
    pr_number: int,
    head_sha: str,
    github_pat: str,
) -> None:
    owner, repo = full_name.split("/", 1)
    url = build_github_zipball_url(owner, repo, head_sha)
    headers = build_github_headers(github_pat)

    try:
        with httpx.Client(follow_redirects=True, timeout=120.0) as client:
            _post_commit_status(
                client, full_name, head_sha, github_pat,
                state="pending",
                description="Security audit in progress…",
            )

            response = client.get(url, headers=headers)
            if response.status_code != 200:
                msg = f"Audit could not download PR code (HTTP {response.status_code})."
                _post_pr_comment(client, full_name, pr_number, github_pat, msg)
                _post_commit_status(
                    client, full_name, head_sha, github_pat,
                    state="error",
                    description="Could not download PR code",
                )
                return

            with tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp) / "pr.zip"
                tmp_path.write_bytes(response.content)
                extract_dir = Path(tmp) / "src"
                extract_dir.mkdir()
                safe_extract_zip(tmp_path, extract_dir)

                findings, scanners = run_all_scanners(extract_dir)
                body = _format_pr_comment(findings, scanners)
                _post_pr_comment(client, full_name, pr_number, github_pat, body)

                counts = _severity_counts(findings)
                if counts["critical"] > 0:
                    state, desc = "failure", f"{counts['critical']} critical issue(s) found"
                elif counts["high"] > 0:
                    state, desc = "failure", f"{counts['high']} high severity issue(s) found"
                else:
                    state, desc = "success", "No critical or high severity issues"

                _post_commit_status(
                    client, full_name, head_sha, github_pat,
                    state=state,
                    description=desc,
                    target_url=None,
                )
    except Exception as exc:
        logger.exception("PR audit failed for %s#%s", full_name, pr_number)
        try:
            with httpx.Client(timeout=30.0) as client:
                _post_pr_comment(
                    client, full_name, pr_number, github_pat,
                    f"Audit failed: {exc}",
                )
                _post_commit_status(
                    client, full_name, head_sha, github_pat,
                    state="error",
                    description="Audit failed",
                )
        except Exception:
            pass


def _severity_counts(findings: list) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
    return counts


def _format_pr_comment(findings: list, scanners: list[str]) -> str:
    if not findings:
        return (
            "## AI Software Auditor — PR Check\n\n"
            "✅ **Passed** — No issues detected.\n\n"
            f"Scanners: {', '.join(scanners)}."
        )

    counts = _severity_counts(findings)
    status_emoji = "❌" if counts["critical"] or counts["high"] else "⚠️"

    lines = [
        "## AI Software Auditor — PR Check",
        "",
        f"{status_emoji} **{'Failed' if counts['critical'] or counts['high'] else 'Warning'}**",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| Critical | {counts['critical']} |",
        f"| High | {counts['high']} |",
        f"| Medium | {counts['medium']} |",
        f"| Low | {counts['low']} |",
        "",
        "### Top findings",
    ]
    for finding in sorted(
        findings,
        key=lambda f: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(f.severity, 0),
        reverse=True,
    )[:8]:
        loc = finding.file_path or "project"
        if finding.line_start:
            loc += f":{finding.line_start}"
        lines.append(f"- **[{finding.severity.upper()}]** {finding.title} (`{loc}`)")

    lines.append("\n_Full audit available in the AI Software Auditor dashboard._")
    return "\n".join(lines)


def _post_commit_status(
    client: httpx.Client,
    full_name: str,
    sha: str,
    github_pat: str,
    *,
    state: str,
    description: str,
    target_url: str | None = None,
) -> None:
    owner, repo = full_name.split("/", 1)
    url = f"https://api.github.com/repos/{owner}/{repo}/statuses/{sha}"
    headers = build_github_headers(github_pat)
    payload: dict = {
        "state": state,
        "context": STATUS_CONTEXT,
        "description": description[:140],
    }
    if target_url:
        payload["target_url"] = target_url
    response = client.post(url, headers=headers, json=payload)
    if response.status_code not in (200, 201):
        logger.warning(
            "Failed to post commit status: HTTP %s %s",
            response.status_code,
            response.text[:200],
        )


def _post_pr_comment(
    client: httpx.Client,
    full_name: str,
    pr_number: int,
    github_pat: str,
    body: str,
) -> None:
    owner, repo = full_name.split("/", 1)
    url = f"https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments"
    headers = build_github_headers(github_pat)
    response = client.post(url, headers=headers, json={"body": body})
    if response.status_code not in (200, 201):
        logger.warning("Failed to post PR comment: HTTP %s %s", response.status_code, response.text[:200])
