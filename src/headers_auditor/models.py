
from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    header: str
    severity: Severity
    message: str
    recommendation: str

    def __post_init__(self):
        if not isinstance(self.severity, Severity):
            raise ValueError(
                "severity must be a valid Severity value"
            )


@dataclass
class AuditResult:
    url: str
    status_code: int
    findings: list[Finding]
