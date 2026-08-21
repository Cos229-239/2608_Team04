from dataclasses import asdict, dataclass, field

from keeper.models.task import now_iso


@dataclass(frozen=True, slots=True)
class Decision:
    action: str
    reason: str
    task_id: str | None = None
    timestamp: str = field(default_factory=now_iso)

    def to_dict(self) -> dict[str, str | None]:
        return asdict(self)
