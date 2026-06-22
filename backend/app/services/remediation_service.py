"""Remediation tracking — new, fixed, and recurring issues between scans."""

from __future__ import annotations

from dataclasses import dataclass

from app.models.issue import Issue


@dataclass
class RemediationItem:
    title: str
    severity: str
    rule_id: str
    file_path: str | None


@dataclass
class RemediationSummary:
    fixed_count: int
    new_count: int
    recurring_count: int
    fixed_issues: list[RemediationItem]
    new_issues: list[RemediationItem]


def issue_fingerprint(issue: Issue) -> str:
    return f"{issue.rule_id}|{issue.file_path or ''}|{issue.title}"


def compare_remediation(
    base_issues: list[Issue],
    target_issues: list[Issue],
    *,
    sample_limit: int = 15,
) -> RemediationSummary:
    base_active = {issue_fingerprint(i): i for i in base_issues if not i.dismissed}
    target_active = {issue_fingerprint(i): i for i in target_issues if not i.dismissed}

    base_keys = set(base_active)
    target_keys = set(target_active)

    fixed_keys = base_keys - target_keys
    new_keys = target_keys - base_keys
    recurring_keys = base_keys & target_keys

    def to_items(keys: set[str]) -> list[RemediationItem]:
        items: list[RemediationItem] = []
        for key in sorted(keys):
            issue = target_active.get(key) or base_active[key]
            items.append(
                RemediationItem(
                    title=issue.title,
                    severity=issue.severity,
                    rule_id=issue.rule_id,
                    file_path=issue.file_path,
                )
            )
        return items[:sample_limit]

    return RemediationSummary(
        fixed_count=len(fixed_keys),
        new_count=len(new_keys),
        recurring_count=len(recurring_keys),
        fixed_issues=to_items(fixed_keys),
        new_issues=to_items(new_keys),
    )
