from __future__ import annotations

import hashlib
import json
import re
from typing import Any


PROVIDER_INPUT_SCHEMA_VERSION = 1
REVIEW_INPUT_SCHEMA_VERSION = 1

_BASE_FIELDS = {
    "schema_version",
    "project_id",
    "charter_id",
    "charter_revision",
    "workflow_id",
    "work_item_id",
    "producer_assignment_id",
    "producer_attempt_id",
    "reviewer_assignment_id",
    "reviewer_attempt_id",
    "references",
    "manifest_digest",
    "delivery_method",
    "delivered_at",
}
_TRANSPORT_FIELDS = {
    "composition_identity",
    "provider_id",
    "account_id",
    "session_id",
    "model_id",
    "workspace",
    "authority_attempt_id",
    "launch_authorization_id",
    "authorization_generation",
}
_FINAL_FIELDS = _BASE_FIELDS | _TRANSPORT_FIELDS | {"delivered_input_digest"}
_REFERENCE_FIELDS = {
    "reference_id",
    "reference_revision",
    "classification",
    "source_identity",
    "project_id",
    "charter_id",
    "charter_revision",
    "workflow_id",
    "work_item_id",
    "producer_assignment_id",
    "producer_attempt_id",
    "reviewed_assignment_id",
    "source_evidence_bundle_id",
    "sha256",
    "size_bytes",
    "validated_at",
    "local_or_remote",
}
_REVIEW_COPY_FIELD = "review_copy"
_REVIEW_DECLARATION_FIELDS = {
    "schema_version",
    "project_id",
    "charter_id",
    "charter_revision",
    "workflow_id",
    "work_item_id",
    "producer_assignment_id",
    "producer_attempt_id",
    "reviewer_assignment_id",
    "reviewer_attempt_id",
    "reviewer_provider_id",
    "reviewer_session_id",
    "delivered_input_digest",
    "provider_input_digest",
    "manifest_digest",
    "review_disposition",
    "references",
}
_DECLARATION_REFERENCE_FIELDS = {
    "reference_id",
    "reference_revision",
    "sha256",
    "source_evidence_bundle_id",
}
_REMOTE_IDENTITY = re.compile(
    r"^[A-Za-z][A-Za-z0-9+.-]*:[A-Za-z0-9][A-Za-z0-9._:-]*$"
)


def structured_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


def validate_provider_input_base(value: object) -> dict[str, Any]:
    item = _exact_object(value, _BASE_FIELDS, "provider input base")
    _validate_common_input(item)
    return item


def finalize_provider_input(
    base: object,
    *,
    composition_identity: str,
    provider_id: str,
    account_id: str,
    session_id: str,
    model_id: str,
    workspace: str,
    authority_attempt_id: str,
    launch_authorization_id: str,
    authorization_generation: int,
) -> tuple[dict[str, Any], str, str]:
    value = validate_provider_input_base(base)
    transport: dict[str, object] = {
        "composition_identity": composition_identity,
        "provider_id": provider_id,
        "account_id": account_id,
        "session_id": session_id,
        "model_id": model_id,
        "workspace": workspace,
        "authority_attempt_id": authority_attempt_id,
        "launch_authorization_id": launch_authorization_id,
        "authorization_generation": authorization_generation,
    }
    material = {**value, **transport}
    delivered_input_digest = structured_digest(material)
    finalized = {
        **material,
        "delivered_input_digest": delivered_input_digest,
    }
    validated = validate_provider_input(finalized)
    return (
        validated,
        delivered_input_digest,
        structured_digest(validated),
    )


def validate_provider_input(value: object) -> dict[str, Any]:
    item = _exact_object(value, _FINAL_FIELDS, "provider input")
    _validate_common_input(item)
    for name in _TRANSPORT_FIELDS - {"authorization_generation"}:
        _text(item.get(name), name)
    _positive_int(
        item.get("authorization_generation"), "authorization_generation"
    )
    if item["composition_identity"] not in {
        "PRODUCTION_AUTHORITY",
        "TEST_AUTHORITY",
    }:
        raise ValueError("provider input composition identity is invalid")
    material = {
        name: item[name] for name in sorted(_FINAL_FIELDS - {"delivered_input_digest"})
    }
    digest = _sha256(item.get("delivered_input_digest"), "delivered input digest")
    if structured_digest(material) != digest:
        raise ValueError("delivered input digest does not match provider input")
    return item


def review_input_declaration(
    provider_input: object,
    *,
    provider_input_digest: str,
    review_disposition: str,
) -> dict[str, Any]:
    if review_disposition not in {"ACCEPTED", "REPAIR_REQUIRED"}:
        raise ValueError("review disposition is invalid")
    return {
        **_review_input_binding(
            provider_input,
            provider_input_digest=provider_input_digest,
        ),
        "review_disposition": review_disposition,
    }


def _review_input_binding(
    provider_input: object,
    *,
    provider_input_digest: str,
) -> dict[str, Any]:
    item = validate_provider_input(provider_input)
    digest = _sha256(provider_input_digest, "provider input digest")
    if structured_digest(item) != digest:
        raise ValueError("provider input digest does not match payload")
    references = [
        {
            "reference_id": reference["reference_id"],
            "reference_revision": reference["reference_revision"],
            "sha256": reference["sha256"],
            "source_evidence_bundle_id": reference[
                "source_evidence_bundle_id"
            ],
        }
        for reference in item["references"]
    ]
    return {
        "schema_version": REVIEW_INPUT_SCHEMA_VERSION,
        "project_id": item["project_id"],
        "charter_id": item["charter_id"],
        "charter_revision": item["charter_revision"],
        "workflow_id": item["workflow_id"],
        "work_item_id": item["work_item_id"],
        "producer_assignment_id": item["producer_assignment_id"],
        "producer_attempt_id": item["producer_attempt_id"],
        "reviewer_assignment_id": item["reviewer_assignment_id"],
        "reviewer_attempt_id": item["reviewer_attempt_id"],
        "reviewer_provider_id": item["provider_id"],
        "reviewer_session_id": item["session_id"],
        "delivered_input_digest": item["delivered_input_digest"],
        "provider_input_digest": digest,
        "manifest_digest": item["manifest_digest"],
        "references": references,
    }


def validate_review_input_declaration(
    value: object,
    provider_input: object,
    *,
    provider_input_digest: str,
    review_disposition: str,
) -> dict[str, Any]:
    declaration = _exact_object(
        value, _REVIEW_DECLARATION_FIELDS, "review input declaration"
    )
    if declaration != review_input_declaration(
        provider_input,
        provider_input_digest=provider_input_digest,
        review_disposition=review_disposition,
    ):
        raise ValueError("review input declaration does not match delivered input")
    references = declaration.get("references")
    if not isinstance(references, list) or not references:
        raise ValueError("review input declaration references are invalid")
    for reference in references:
        _exact_object(
            reference,
            _DECLARATION_REFERENCE_FIELDS,
            "review declaration reference",
        )
    return declaration


def provider_prompt_context(
    provider_input: object,
    *,
    provider_input_digest: str,
) -> str:
    item = validate_provider_input(provider_input)
    digest = _sha256(provider_input_digest, "provider input digest")
    if structured_digest(item) != digest:
        raise ValueError("provider input digest does not match payload")
    envelope = {
        "keeper_typed_evidence_input": item,
        "keeper_typed_evidence_input_digest": digest,
        "required_review_input_binding": _review_input_binding(
            item,
            provider_input_digest=digest,
        ),
        "review_input_declaration_instruction": (
            "Return the required review input binding plus review_disposition "
            "matching the top-level review_disposition."
        ),
    }
    return json.dumps(
        envelope,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )

def validate_remote_source_identity(value: object) -> str:
    return _pathless_remote_identity(value)

def review_input_declaration_json_schema() -> dict[str, Any]:
    text_fields = {
        "project_id",
        "charter_id",
        "workflow_id",
        "work_item_id",
        "producer_assignment_id",
        "producer_attempt_id",
        "reviewer_assignment_id",
        "reviewer_attempt_id",
        "reviewer_provider_id",
        "reviewer_session_id",
        "delivered_input_digest",
        "provider_input_digest",
        "manifest_digest",
    }
    properties: dict[str, Any] = {
        "schema_version": {"type": "integer", "const": 1},
        "charter_revision": {"type": "integer"},
        "review_disposition": {
            "type": "string",
            "enum": ["ACCEPTED", "REPAIR_REQUIRED"],
        },
        **{name: {"type": "string"} for name in text_fields},
        "references": {
            "type": "array",
            "items": {
                "type": "object",
                "required": [
                    "reference_id",
                    "reference_revision",
                    "sha256",
                    "source_evidence_bundle_id",
                ],
                "properties": {
                    "reference_id": {"type": "string"},
                    "reference_revision": {"type": "integer"},
                    "sha256": {"type": "string"},
                    "source_evidence_bundle_id": {"type": "string"},
                },
                "additionalProperties": False,
            },
        },
    }
    return {
        "type": "object",
        "description": (
            "Exact Keeper-supplied binding plus the matching review disposition."
        ),
        "required": sorted(properties),
        "properties": properties,
        "additionalProperties": False,
    }


def _validate_common_input(item: dict[str, Any]) -> None:
    if item.get("schema_version") != PROVIDER_INPUT_SCHEMA_VERSION:
        raise ValueError("provider input schema version is invalid")
    for name in {
        "project_id",
        "charter_id",
        "workflow_id",
        "work_item_id",
        "producer_assignment_id",
        "producer_attempt_id",
        "reviewer_assignment_id",
        "reviewer_attempt_id",
        "manifest_digest",
        "delivery_method",
        "delivered_at",
    }:
        _text(item.get(name), name)
    _positive_int(item.get("charter_revision"), "charter_revision")
    _sha256(item.get("manifest_digest"), "manifest digest")
    references = item.get("references")
    if not isinstance(references, list) or not references:
        raise ValueError("provider input references are invalid")
    seen: set[str] = set()
    for reference in references:
        parsed = _validate_reference(reference)
        reference_id = str(parsed["reference_id"])
        if reference_id in seen:
            raise ValueError("provider input reference IDs must be unique")
        seen.add(reference_id)
        for name in {
            "project_id",
            "charter_id",
            "workflow_id",
            "work_item_id",
            "producer_assignment_id",
            "producer_attempt_id",
            "reviewed_assignment_id",
        }:
            expected = (
                item["producer_assignment_id"]
                if name == "reviewed_assignment_id"
                else item[name]
            )
            if parsed[name] != expected:
                raise ValueError(
                    f"provider input reference {name} binding is invalid"
                )
        if parsed["charter_revision"] != item["charter_revision"]:
            raise ValueError(
                "provider input reference charter revision is invalid"
            )


def _validate_reference(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("provider input reference must be an object")
    local_or_remote = value.get("local_or_remote")
    expected = (
        _REFERENCE_FIELDS | {_REVIEW_COPY_FIELD}
        if local_or_remote == "LOCAL"
        else _REFERENCE_FIELDS
    )
    reference = _exact_object(value, expected, "provider input reference")
    for name in _REFERENCE_FIELDS - {
        "reference_revision",
        "charter_revision",
        "size_bytes",
        "local_or_remote",
    }:
        _text(reference.get(name), name)
    _positive_int(reference.get("reference_revision"), "reference revision")
    _positive_int(reference.get("charter_revision"), "charter revision")
    _nonnegative_int(reference.get("size_bytes"), "reference size")
    _sha256(reference.get("sha256"), "reference digest")
    if local_or_remote == "LOCAL":
        review_copy = _text(reference.get("review_copy"), "review copy")
        if (
            review_copy.startswith(("/", "\\"))
            or re.match(r"^[A-Za-z]:", review_copy) is not None
            or ".." in re.split(r"[\\/]+", review_copy)
        ):
            raise ValueError("local review copy path is unsafe")
    elif local_or_remote == "REMOTE":
        _pathless_remote_identity(reference.get("source_identity"))
    else:
        raise ValueError("provider input reference classification is invalid")
    return reference


def _pathless_remote_identity(value: object) -> str:
    identity = _text(value, "remote source identity")
    if (
        identity.casefold().startswith("file:")
        or re.match(r"^[A-Za-z]:", identity) is not None
        or not _REMOTE_IDENTITY.fullmatch(identity)
        or "/" in identity
        or "\\" in identity
    ):
        raise ValueError("remote source identity must be pathless")
    return identity


def _exact_object(
    value: object, fields: set[str], label: str
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{label} fields are invalid")
    return dict(value)


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} is invalid")
    return value


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{label} is invalid")
    return value


def _nonnegative_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} is invalid")
    return value


def _sha256(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} is invalid")
    return value
