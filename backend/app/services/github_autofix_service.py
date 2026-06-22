"""Create GitHub pull requests with automated security fixes."""

from __future__ import annotations

import base64
import logging
import re
from pathlib import Path
from uuid import UUID

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.issue import Issue
from app.models.project import Project
from app.models.scan import Scan
from app.models.user import User
from app.services.autofix_service import AutofixError, FilePatch, generate_patch, is_autofixable
from app.services.github import build_github_headers, parse_github_url
from app.services.scan_runner import _resolve_project_dir

logger = logging.getLogger(__name__)


async def create_autofix_pr(
    db: AsyncSession,
    user: User,
    scan: Scan,
    issue: Issue,
) -> dict:
    if not user.github_pat:
        raise AutofixError("GitHub Personal Access Token required. Set it in Enterprise settings.")
    if not is_autofixable(issue):
        raise AutofixError(f"Issue rule `{issue.rule_id}` cannot be auto-fixed safely.")

    project = await db.get(Project, scan.project_id)
    if not project or project.user_id != user.id:
        raise AutofixError("Project not found")
    if project.source_type != "github":
        raise AutofixError("Auto-fix PRs require a GitHub-connected project.")
    if not project.storage_path:
        raise AutofixError("Project source is not available on disk.")

    project_dir = _resolve_project_dir(project.storage_path)
    if not project_dir.exists():
        raise AutofixError("Project directory not found.")

    patch = generate_patch(issue, project_dir)
    if not patch:
        raise AutofixError("Could not generate a patch for this finding.")

    owner, repo = parse_github_url(project.repo_url or "")
    branch = project.repo_branch or "main"
    headers = build_github_headers(user.github_pat)

    with httpx.Client(timeout=60.0) as client:
        pr_url = _open_github_pr(
            client, headers, owner, repo, branch, issue, patch
        )

    extra = issue.extra_data or {}
    extra["autofix_pr_url"] = pr_url
    issue.extra_data = extra
    await db.commit()

    return {"pr_url": pr_url, "file_path": patch.file_path, "action": patch.action}


def _open_github_pr(
    client: httpx.Client,
    headers: dict[str, str],
    owner: str,
    repo: str,
    base_branch: str,
    issue: Issue,
    patch: FilePatch,
) -> str:
    repo_url = f"https://api.github.com/repos/{owner}/{repo}"

    ref_resp = client.get(f"{repo_url}/git/ref/heads/{base_branch}", headers=headers)
    if ref_resp.status_code != 200:
        raise AutofixError(f"Could not read branch `{base_branch}` (HTTP {ref_resp.status_code})")
    base_sha = ref_resp.json()["object"]["sha"]

    slug = re.sub(r"[^a-z0-9-]", "-", issue.rule_id.lower())[:40]
    fix_branch = f"auditor/fix-{slug}-{str(issue.id)[:8]}"

    create_ref = client.post(
        f"{repo_url}/git/refs",
        headers=headers,
        json={"ref": f"refs/heads/{fix_branch}", "sha": base_sha},
    )
    if create_ref.status_code not in (200, 201):
        if create_ref.status_code == 422 and "Reference already exists" in create_ref.text:
            pass
        else:
            raise AutofixError(f"Could not create branch (HTTP {create_ref.status_code})")

    _commit_file(client, headers, owner, repo, fix_branch, patch, issue)

    pr_title = f"fix(security): {issue.title[:72]}"
    pr_body = (
        f"## AI Software Auditor — Auto-fix\n\n"
        f"**Finding:** {issue.title}\n\n"
        f"**Rule:** `{issue.rule_id}`\n\n"
        f"**Severity:** {issue.severity}\n\n"
        f"### Recommendation\n{issue.fix_recommendation}\n\n"
        f"---\n_Automated patch — review before merging._"
    )
    pr_resp = client.post(
        f"{repo_url}/pulls",
        headers=headers,
        json={
            "title": pr_title,
            "head": fix_branch,
            "base": base_branch,
            "body": pr_body,
        },
    )
    if pr_resp.status_code not in (200, 201):
        raise AutofixError(f"Could not open pull request (HTTP {pr_resp.status_code})")

    return pr_resp.json().get("html_url", "")


def _commit_file(
    client: httpx.Client,
    headers: dict[str, str],
    owner: str,
    repo: str,
    branch: str,
    patch: FilePatch,
    issue: Issue,
) -> None:
    path = patch.file_path.lstrip("/")
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    existing_sha = None
    get_resp = client.get(url, headers=headers, params={"ref": branch})
    if get_resp.status_code == 200:
        existing_sha = get_resp.json().get("sha")
    elif patch.action == "update":
        raise AutofixError(f"File `{path}` not found on branch `{branch}`")

    payload: dict = {
        "message": f"fix(security): {issue.rule_id} — {issue.title[:60]}",
        "content": base64.b64encode(patch.content.encode("utf-8")).decode("ascii"),
        "branch": branch,
    }
    if existing_sha:
        payload["sha"] = existing_sha

    put_resp = client.put(url, headers=headers, json=payload)
    if put_resp.status_code not in (200, 201):
        raise AutofixError(f"Could not commit fix (HTTP {put_resp.status_code})")
