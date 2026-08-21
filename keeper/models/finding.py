from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    MINOR = "Minor"


@dataclass(frozen=True, slots=True)
class Finding:
    finding_id: str
    severity: Severity
    title: str
    description: str
    file: str | None = None
    line: int | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        return cls(
            finding_id=str(data["finding_id"]),
            severity=Severity(data["severity"]),
            title=str(data["title"]),
            description=str(data["description"]),
            file=data.get("file"),
            line=data.get("line"),
        )

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["severity"] = self.severity.value
        return result
