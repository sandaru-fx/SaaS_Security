"""Deduplicate scan findings from overlapping scanners."""

from __future__ import annotations

from app.scanners.base import ScanFinding

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}


def _normalize_rule_id(rule_id: str) -> str:
    return rule_id.rsplit(".", 1)[-1].lower()


def _dedup_key(finding: ScanFinding) -> tuple:
    line_end = finding.line_end or finding.line_start
    return (
        (finding.file_path or "").replace("\\", "/").lower(),
        finding.line_start,
        line_end,
        _normalize_rule_id(finding.rule_id),
    )


def _is_better(candidate: ScanFinding, current: ScanFinding) -> bool:
    c_sev = SEVERITY_RANK.get(candidate.severity, 0)
    cur_sev = SEVERITY_RANK.get(current.severity, 0)
    if c_sev != cur_sev:
        return c_sev > cur_sev
    c_conf = CONFIDENCE_RANK.get(candidate.confidence, 0)
    cur_conf = CONFIDENCE_RANK.get(current.confidence, 0)
    return c_conf > cur_conf


def deduplicate_findings(findings: list[ScanFinding]) -> list[ScanFinding]:
    """Keep one finding per file/line/rule; prefer higher severity."""
    best: dict[tuple, ScanFinding] = {}
    for finding in findings:
        key = _dedup_key(finding)
        existing = best.get(key)
        if existing is None or _is_better(finding, existing):
            best[key] = finding
    return list(best.values())
