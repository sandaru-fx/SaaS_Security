"""Rule-based auto-fix patch generation for safe, deterministic remediations."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from app.models.issue import Issue

GITIGNORE_TEMPLATE = """# Added by AI Software Auditor auto-fix
node_modules/
.env
.env.local
__pycache__/
*.pyc
dist/
build/
.venv/
venv/
"""

GITIGNORE_RECOMMENDED = [".env", "node_modules", "__pycache__"]

AUTOFIXABLE_RULES = frozenset({
    "missing-gitignore",
    "incomplete-gitignore",
    "debug-enabled",
    "llm-langchain-verbose-leak",
    "llm-langchain-dangerous-code",
    "docker-root-user",
})


class AutofixError(Exception):
    pass


@dataclass
class FilePatch:
    file_path: str
    content: str
    action: str  # create | update


def is_autofixable(issue: Issue) -> bool:
    return issue.rule_id in AUTOFIXABLE_RULES and not issue.dismissed


def generate_patch(issue: Issue, project_dir: Path) -> FilePatch | None:
    if not is_autofixable(issue):
        return None

    rule = issue.rule_id
    rel = (issue.file_path or "").strip().replace("\\", "/")

    if rule == "missing-gitignore":
        target = project_dir / ".gitignore"
        if target.exists():
            return None
        return FilePatch(file_path=".gitignore", content=GITIGNORE_TEMPLATE, action="create")

    if rule == "incomplete-gitignore":
        if not rel:
            rel = ".gitignore"
        path = project_dir / rel
        if not path.exists():
            return None
        content = path.read_text(encoding="utf-8", errors="ignore")
        lower = content.lower()
        additions = [e for e in GITIGNORE_RECOMMENDED if e not in lower]
        if not additions:
            return None
        new_content = content.rstrip() + "\n" + "\n".join(additions) + "\n"
        return FilePatch(file_path=rel, content=new_content, action="update")

    if not rel:
        return None
    path = project_dir / rel
    if not path.exists():
        return None
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines(keepends=True)
    if not lines:
        return None

    if rule == "debug-enabled":
        return _patch_line(lines, rel, r"(?i)(DEBUG|debug)\s*[:=]\s*True", r"\1 = False")

    if rule == "llm-langchain-verbose-leak":
        return _patch_line(lines, rel, r"verbose\s*=\s*True", "verbose=False")

    if rule == "llm-langchain-dangerous-code":
        return _patch_line(lines, rel, r"allow_dangerous_code\s*=\s*True", "allow_dangerous_code=False")

    if rule == "docker-root-user":
        content = "".join(lines)
        if re.search(r"(?i)^\s*USER\s+", content, re.MULTILINE):
            return None
        insert = "\n# Non-root user added by AI Software Auditor\nUSER node\n"
        if content.rstrip().endswith("\n"):
            new_content = content.rstrip() + insert
        else:
            new_content = content + insert
        return FilePatch(file_path=rel, content=new_content, action="update")

    return None


def _patch_line(
    lines: list[str],
    rel: str,
    pattern: str,
    replacement: str,
) -> FilePatch | None:
    changed = False
    new_lines: list[str] = []
    start = max(0, 0)
    for i, line in enumerate(lines):
        if re.search(pattern, line):
            new_line = re.sub(pattern, replacement, line, count=1)
            if new_line != line:
                changed = True
                new_lines.append(new_line)
                start = i + 1
                continue
        new_lines.append(line)
    if not changed:
        return None
    return FilePatch(file_path=rel, content="".join(new_lines), action="update")
