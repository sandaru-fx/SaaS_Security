from dataclasses import dataclass, field


@dataclass
class ScanFinding:
    category: str
    severity: str
    title: str
    description: str
    impact: str
    fix_recommendation: str
    file_path: str
    line_start: int
    line_end: int
    rule_id: str
    scanner: str
    confidence: str = "medium"
    metadata: dict = field(default_factory=dict)
