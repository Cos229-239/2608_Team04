from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any

from keeper.executive.enums import DelegationMode, ValueProvenance


@dataclass(frozen=True, slots=True)
class IntakeValue:
    value: Any
    provenance: str
    confidence: float
    source_excerpt: str

    def __post_init__(self) -> None:
        ValueProvenance(self.provenance)
        if not 0 <= self.confidence <= 1:
            raise ValueError("intake confidence must be between zero and one")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class IntakeResult:
    fields: dict[str, IntakeValue]
    unresolved_questions: tuple[str, ...]
    proposed_assumptions: tuple[str, ...]

    def explicit(self, field: str, default: Any = None) -> Any:
        item = self.fields.get(field)
        return item.value if item is not None else default

    def to_dict(self) -> dict[str, Any]:
        return {
            "fields": {key: item.to_dict() for key, item in self.fields.items()},
            "unresolved_questions": list(self.unresolved_questions),
            "proposed_assumptions": list(self.proposed_assumptions),
        }


class ConversationIntake:
    """Deterministic first-pass extraction with explicit provenance."""

    TYPE_MARKERS = {
        "software": ("app", "application", "software", "website", "api", "code"),
        "research": ("research", "study", "report", "sources", "investigate"),
        "video": ("video", "youtube", "storyboard", "film"),
        "music": ("music", "song", "album", "composition", "mix"),
        "writing": ("book", "article", "essay", "novel", "writing"),
        "design": ("design", "brand", "illustration", "prototype"),
        "marketing": ("marketing", "campaign", "audience growth"),
        "business_operations": ("operations", "process", "business plan"),
    }

    def extract(
        self, message: str, existing: IntakeResult | None = None
    ) -> IntakeResult:
        text = " ".join(message.strip().split())
        if not text:
            raise ValueError("intake message cannot be empty")
        lower = text.casefold()
        fields = dict(existing.fields) if existing else {}
        assumptions = list(existing.proposed_assumptions) if existing else []
        project_type = self._project_type(lower)
        if project_type:
            fields["project_type"] = self._value(project_type, "INFERRED_HIGH_CONFIDENCE", 0.9, text)
        elif "project_type" not in fields:
            fields["project_type"] = self._value("general", "PROPOSED_ASSUMPTION", 0.55, text)
            assumptions.append("Treat the work as a general project until its workload type is confirmed.")
        name = self._name(text)
        if name:
            fields["project_name"] = self._value(name, "EXPLICIT", 1.0, text)
        elif "project_name" not in fields:
            fields["project_name"] = self._value(self._fallback_name(text), "PROPOSED_ASSUMPTION", 0.6, text)
            assumptions.append("Use the working project name proposed from the desired outcome.")
        fields["problem_or_opportunity"] = self._value(text, "EXPLICIT", 1.0, text)
        fields["desired_outcome"] = self._value(self._desired_outcome(text), "INFERRED_HIGH_CONFIDENCE", 0.85, text)
        deliverables = self._deliverables(lower, project_type or str(fields["project_type"].value))
        if deliverables:
            fields["deliverables"] = self._value(deliverables, "INFERRED_HIGH_CONFIDENCE", 0.85, text)
        constraints = self._constraints(text)
        if constraints:
            fields["constraints"] = self._value(constraints, "EXPLICIT", 1.0, text)
        success_criteria = self._success_criteria(text)
        if success_criteria:
            fields["success_criteria"] = self._value(
                success_criteria, "EXPLICIT", 1.0, text
            )
        target_audience = self._target_audience(text)
        if target_audience:
            fields["target_audience"] = self._value(
                target_audience, "EXPLICIT", 1.0, text
            )
        approved_providers = self._approved_items(text, "providers?")
        if approved_providers:
            fields["approved_providers"] = self._value(
                approved_providers, "EXPLICIT", 1.0, text
            )
        approved_tools = self._approved_items(text, "tools?")
        if approved_tools:
            fields["approved_tools"] = self._value(
                approved_tools, "EXPLICIT", 1.0, text
            )
        if any(marker in lower for marker in ("no spending", "no purchases", "zero budget", "do not spend")):
            fields["budget_policy"] = self._value("spending prohibited", "EXPLICIT", 1.0, text)
            fields["budget_limit"] = self._value(0.0, "EXPLICIT", 1.0, text)
        elif "budget_policy" not in fields:
            fields["budget_policy"] = self._value("spending prohibited until approved", "PROPOSED_ASSUMPTION", 0.9, text)
            fields["budget_limit"] = self._value(0.0, "PROPOSED_ASSUMPTION", 0.9, text)
            assumptions.append("No spending is authorized unless the Founder states a budget.")
        delegation = self._delegation(lower)
        if delegation:
            fields["delegation_mode"] = self._value(delegation, "EXPLICIT", 1.0, text)
        elif "delegation_mode" not in fields:
            fields["delegation_mode"] = self._value(DelegationMode.ADVISORY.value, "PROPOSED_ASSUMPTION", 0.7, text)
            assumptions.append("Begin in Advisory mode until delegation is explicitly selected.")
        urgency = self._urgency(text)
        if urgency:
            fields["timeline"] = self._value(urgency, "EXPLICIT", 1.0, text)
        workspaces = self._windows_paths(text)
        if workspaces:
            fields["workspaces"] = self._value(workspaces, "EXPLICIT", 1.0, text)
        questions = self._questions(fields)
        return IntakeResult(fields, tuple(dict.fromkeys(questions)), tuple(dict.fromkeys(assumptions)))

    @staticmethod
    def revise(
        result: IntakeResult,
        *,
        replacements: dict[str, Any] | None = None,
        remove_deliverables: tuple[str, ...] = (),
    ) -> IntakeResult:
        fields = dict(result.fields)
        for key, value in (replacements or {}).items():
            fields[key] = IntakeValue(value, ValueProvenance.EXPLICIT.value, 1.0, "Founder revision")
        if remove_deliverables and "deliverables" in fields:
            current = tuple(str(item) for item in fields["deliverables"].value)
            fields["deliverables"] = IntakeValue(
                tuple(item for item in current if item not in remove_deliverables),
                ValueProvenance.EXPLICIT.value,
                1.0,
                "Founder removed deliverable",
            )
        return IntakeResult(fields, tuple(ConversationIntake._questions(fields)), result.proposed_assumptions)

    @classmethod
    def _project_type(cls, lower: str) -> str | None:
        scores = {
            project_type: sum(marker in lower for marker in markers)
            for project_type, markers in cls.TYPE_MARKERS.items()
        }
        selected = max(scores, key=lambda key: scores[key])
        return selected if scores[selected] else None

    @staticmethod
    def _name(text: str) -> str | None:
        match = re.search(r"(?:called|named)\s+[\"']?([^\"'.;,]+)", text, re.IGNORECASE)
        return match.group(1).strip() if match else None

    @staticmethod
    def _fallback_name(text: str) -> str:
        words = re.findall(r"[A-Za-z0-9]+", text)
        return " ".join(words[:6]).title() or "Untitled Project"

    @staticmethod
    def _desired_outcome(text: str) -> str:
        match = re.search(r"(?:want|need|goal is|outcome is)\s+(.*)", text, re.IGNORECASE)
        return (match.group(1) if match else text).rstrip(".")

    @staticmethod
    def _deliverables(lower: str, project_type: str) -> tuple[str, ...]:
        defaults = {
            "software": ("working application", "automated tests", "usage documentation"),
            "research": ("source register", "synthesis report", "contradiction analysis"),
            "video": ("approved script", "edited video", "export package"),
            "music": ("finished composition", "mixed master", "release package"),
            "writing": ("edited manuscript", "review notes", "final publication package"),
            "design": ("design artifacts", "review evidence", "delivery package"),
            "marketing": ("campaign plan", "campaign assets", "performance review"),
            "business_operations": ("operating plan", "process artifacts", "validation report"),
            "general": ("project deliverable", "verification evidence"),
        }
        explicit = re.search(r"deliverables?\s*(?:are|:)\s*(.+)", lower)
        if explicit:
            return tuple(item.strip(" .") for item in re.split(r",| and ", explicit.group(1)) if item.strip())
        return defaults.get(project_type, defaults["general"])

    @staticmethod
    def _constraints(text: str) -> tuple[str, ...]:
        lower = text.casefold()
        values: list[str] = []
        markers = {
            "no spending": "No spending",
            "do not push": "No push",
            "don't push": "No push",
            "local only": "Local execution only",
            "no publishing": "No external publishing",
            "no deployment": "No production deployment",
        }
        for marker, value in markers.items():
            if marker in lower:
                values.append(value)
        return tuple(values)

    @staticmethod
    def _success_criteria(text: str) -> tuple[str, ...]:
        match = re.search(
            r"success criteria\s*(?:are|:)\s*(.+?)(?:\.\s|$)",
            text,
            re.IGNORECASE,
        )
        if not match:
            return ()
        return tuple(
            item.strip(" .")
            for item in re.split(r";|,|\band\b", match.group(1))
            if item.strip(" .")
        )

    @staticmethod
    def _target_audience(text: str) -> str | None:
        match = re.search(
            r"(?:primary\s+)?(?:user|audience)\s*(?:is|:)\s*([^.;]+)",
            text,
            re.IGNORECASE,
        )
        return match.group(1).strip() if match else None

    @staticmethod
    def _approved_items(text: str, item_pattern: str) -> tuple[str, ...]:
        match = re.search(
            rf"approved {item_pattern}\s*(?:are|:)\s*(.+?)(?:\.\s|$)",
            text,
            re.IGNORECASE,
        )
        if not match:
            return ()
        return tuple(
            item.strip(" .").casefold()
            for item in re.split(r",|\band\b", match.group(1))
            if item.strip(" .")
        )


    @staticmethod
    def _delegation(lower: str) -> str | None:
        if "full delegation" in lower or "handle everything" in lower:
            return DelegationMode.FULL_DELEGATION.value
        if "delegated" in lower:
            return DelegationMode.DELEGATED.value
        if "advisory" in lower or "advice only" in lower:
            return DelegationMode.ADVISORY.value
        return None

    @staticmethod
    def _urgency(text: str) -> str | None:
        match = re.search(r"(?:by|before|deadline is)\s+([^,.;]+)", text, re.IGNORECASE)
        return match.group(1).strip() if match else None

    @staticmethod
    def _windows_paths(text: str) -> tuple[str, ...]:
        return tuple(dict.fromkeys(re.findall(r"[A-Za-z]:\\[^\s,;]+", text)))

    @staticmethod
    def _questions(fields: dict[str, IntakeValue]) -> list[str]:
        questions: list[str] = []
        if "success_criteria" not in fields:
            questions.append("What observable results will prove the project is successful?")
        if "target_audience" not in fields:
            questions.append("Who is the primary user or audience?")
        if "workspaces" not in fields and str(fields.get("project_type", IntakeValue("", "UNRESOLVED", 0, "")).value) == "software":
            questions.append("Which repository or workspace may Keeper use?")
        return questions

    @staticmethod
    def _value(value: Any, provenance: str, confidence: float, source: str) -> IntakeValue:
        return IntakeValue(value, provenance, confidence, source[:240])
