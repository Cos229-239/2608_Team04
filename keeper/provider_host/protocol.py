from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Callable, Mapping, Protocol, cast

from keeper.providers.codex_contract import CODEX_ALLOWED_SUBSCRIPTION_PLANS
from keeper.providers.claude_contract import CLAUDE_ALLOWED_SUBSCRIPTION_PLANS


HOST_PROTOCOL = "keeper-provider-host/1"
LAUNCH_PURPOSE = "keeper-provider-host-launch"
COMPLETION_PURPOSE = "keeper-provider-host-completion"
HELLO_PURPOSE = "keeper-provider-host-hello"
SETUP_PURPOSE = "keeper-provider-host-provider-setup"
SETUP_RESULT_PURPOSE = "keeper-provider-host-provider-setup-result"
REQUEST_PURPOSE = "keeper-provider-host-request"
RESPONSE_PURPOSE = "keeper-provider-host-response"
STARTED_PURPOSE = "keeper-provider-host-started"
STARTED_ACK_PURPOSE = "keeper-provider-host-started-ack"
LAUNCH_RECONCILIATION_PURPOSE = "keeper-provider-host-launch-reconciliation"
LAUNCH_RECONCILIATION_RESULT_PURPOSE = (
    "keeper-provider-host-launch-reconciliation-result"
)
MAX_FRAME_BYTES = 2 * 1024 * 1024


def canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ValueError("Provider Host value is not canonical JSON") from error


def structured_digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


class EnvelopeSigner(Protocol):
    @property
    def identity(self) -> str: ...

    @property
    def key_id(self) -> str: ...

    @property
    def production(self) -> bool: ...

    def sign(self, purpose: str, payload: Mapping[str, Any]) -> dict[str, Any]: ...


class EnvelopeVerifier(Protocol):
    @property
    def identity(self) -> str: ...

    @property
    def key_id(self) -> str: ...

    @property
    def production(self) -> bool: ...

    def verify(
        self, record: Mapping[str, Any], *, purpose: str
    ) -> dict[str, Any]: ...


@dataclass(frozen=True, slots=True)
class CallbackEnvelopeIdentity:
    """Purpose-bound asymmetric identity backed by an enrolled key provider."""

    identity: str
    key_id: str
    sign_digest: Callable[[bytes], bytes]
    verify_digest: Callable[[bytes, bytes], bool]
    production: bool = True

    def sign(self, purpose: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        unsigned = _unsigned(self.identity, self.key_id, purpose, payload)
        signature = self.sign_digest(_signature_digest(unsigned))
        if not isinstance(signature, bytes) or not signature:
            raise PermissionError("Provider Host signature was not produced")
        return {**unsigned, "signature": base64.b64encode(signature).decode("ascii")}

    def verify(
        self, record: Mapping[str, Any], *, purpose: str
    ) -> dict[str, Any]:
        unsigned, signature = _parse_signed(record, self.identity, self.key_id, purpose)
        if not self.verify_digest(_signature_digest(unsigned), signature):
            raise PermissionError("Provider Host signature is invalid")
        return dict(cast(dict[str, Any], unsigned["payload"]))


@dataclass(frozen=True, slots=True)
class TestEnvelopeIdentity:
    """Deterministic test identity; production gateways reject this type."""

    identity: str
    key: bytes
    production: bool = False

    @property
    def key_id(self) -> str:
        return "test-hmac:" + hashlib.sha256(self.key).hexdigest()

    def sign(self, purpose: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        unsigned = _unsigned(self.identity, self.key_id, purpose, payload)
        signature = hmac.new(self.key, _signature_digest(unsigned), hashlib.sha256).digest()
        return {**unsigned, "signature": base64.b64encode(signature).decode("ascii")}

    def verify(
        self, record: Mapping[str, Any], *, purpose: str
    ) -> dict[str, Any]:
        unsigned, signature = _parse_signed(record, self.identity, self.key_id, purpose)
        expected = hmac.new(
            self.key, _signature_digest(unsigned), hashlib.sha256
        ).digest()
        if not hmac.compare_digest(expected, signature):
            raise PermissionError("Provider Host test signature is invalid")
        return dict(cast(dict[str, Any], unsigned["payload"]))


def require_production_identity(identity: EnvelopeSigner | EnvelopeVerifier) -> None:
    if identity.production is not True or identity.key_id.startswith("test-"):
        raise PermissionError("test Provider Host identity cannot enter production")


_LAUNCH_FIELDS = {
    "account_id",
    "argv",
    "assignment_id",
    "authority_attempt_id",
    "authority_id",
    "cancellation",
    "charter_id",
    "charter_revision_id",
    "composition_identity",
    "effort",
    "environment",
    "executable",
    "expires_at",
    "host_id",
    "issued_at",
    "launch_claim_digest",
    "launch_id",
    "model_id",
    "network_policy",
    "nonce",
    "project_id",
    "provider_id",
    "provider_input_digest",
    "provider_qualification_id",
    "provider_registration_id",
    "provider_session_id",
    "resource_limits",
    "sequence",
    "usage",
    "user_binding",
    "work_item_id",
    "workflow_id",
    "workspace",
}

_SETUP_FIELDS = {
    "account_binding",
    "authority_id",
    "challenge",
    "composition_identity",
    "environment",
    "executable",
    "expires_at",
    "host_id",
    "issued_at",
    "model_id",
    "nonce",
    "operation",
    "provider_id",
    "provider_registration_id",
    "resource_limits",
    "sequence",
    "setup_id",
    "usage_policy_digest",
    "user_binding",
    "workspace",
}


def validate_setup_envelope(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _SETUP_FIELDS:
        raise PermissionError("Provider Host setup fields are invalid")
    result = cast(dict[str, Any], json.loads(canonical_json(value)))
    for name in _SETUP_FIELDS - {
        "account_binding",
        "environment",
        "executable",
        "resource_limits",
        "sequence",
        "user_binding",
        "workspace",
    }:
        _text(result.get(name), f"setup {name}")
    if result["provider_id"] not in {"codex", "claude"}:
        raise PermissionError("Provider Host setup provider is invalid")
    if result["operation"] not in {"REGISTER_PROBE", "QUALIFY"}:
        raise PermissionError("Provider Host setup operation is invalid")
    if result["composition_identity"] != "PRODUCTION":
        raise PermissionError("Provider Host setup composition is not production")
    if result["model_id"] == "" or result["model_id"].casefold() == "auto":
        raise PermissionError("Provider Host setup model is invalid")
    sequence = result.get("sequence")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence <= 0:
        raise PermissionError("Provider Host setup sequence is invalid")
    _exact_object(
        result["account_binding"],
        {"account_identity_digest", "authentication_method", "plan_type"},
        "setup account binding",
    )
    expected_method, allowed_plans = (
        ("chatgpt-subscription", CODEX_ALLOWED_SUBSCRIPTION_PLANS)
        if result["provider_id"] == "codex"
        else ("claude-ai-subscription", CLAUDE_ALLOWED_SUBSCRIPTION_PLANS)
    )
    if (
        result["account_binding"].get("authentication_method") != expected_method
        or result["account_binding"].get("plan_type") not in allowed_plans
    ):
        raise PermissionError("Provider Host setup account policy is invalid")
    account_digest = result["account_binding"].get("account_identity_digest")
    if not (
        result["operation"] == "REGISTER_PROBE"
        and account_digest == "DISCOVER"
    ):
        require_sha256(account_digest, "setup account identity digest")
    _exact_object(
        result["user_binding"],
        {"profile_path", "session_id", "user_sid"},
        "setup user binding",
    )
    session_id = result["user_binding"].get("session_id")
    if isinstance(session_id, bool) or not isinstance(session_id, int) or session_id < 0:
        raise PermissionError("Provider Host setup Windows session is invalid")
    _exact_object(
        result["executable"],
        {
            "authenticode_binding",
            "file_identity",
            "path",
            "publisher",
            "sha256",
            "size",
            "version",
        },
        "setup executable",
    )
    _exact_object(
        result["executable"]["file_identity"],
        {"device_id", "file_id", "modified_ns", "schema_version", "size"},
        "setup executable file identity",
    )
    if result["executable"]["file_identity"].get("schema_version") != 1:
        raise PermissionError("Provider Host setup file identity schema is invalid")
    for item in result["executable"]["file_identity"].values():
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise PermissionError("Provider Host setup file identity is invalid")
    if result["executable"].get("size") != result["executable"]["file_identity"].get("size"):
        raise PermissionError("Provider Host setup executable size differs")
    _exact_object(
        result["executable"]["authenticode_binding"],
        {"certificate_thumbprint", "publisher_subject", "source", "status"},
        "setup Authenticode binding",
    )
    authenticode = result["executable"]["authenticode_binding"]
    thumbprint = authenticode.get("certificate_thumbprint")
    if (
        authenticode.get("status") != "Valid"
        or authenticode.get("source") != "windows-authenticode"
        or not isinstance(thumbprint, str)
        or len(thumbprint) != 40
        or any(character not in "0123456789ABCDEF" for character in thumbprint)
    ):
        raise PermissionError("Provider Host setup Authenticode binding is invalid")
    _exact_object(
        result["environment"],
        {
            "allowlist", "digest", "preparation_nonce", "scrubbed_names",
            "tls_root_bundle",
        },
        "setup environment",
    )
    _validate_tls_root_bundle(result["environment"].get("tls_root_bundle"))
    allowlist = result["environment"].get("allowlist")
    scrubbed = result["environment"].get("scrubbed_names")
    if (
        not isinstance(allowlist, list)
        or not allowlist
        or allowlist != sorted(set(allowlist), key=str.upper)
        or not isinstance(scrubbed, list)
        or scrubbed != sorted(set(scrubbed), key=str.upper)
        or not all(isinstance(item, str) and item for item in allowlist + scrubbed)
    ):
        raise PermissionError("Provider Host setup environment is invalid")
    _exact_object(
        result["workspace"],
        {"canonical_path", "identity", "reservation_id"},
        "setup workspace",
    )
    _exact_object(
        result["resource_limits"],
        {
            "active_process_limit",
            "memory_bytes",
            "stderr_bytes",
            "stdout_bytes",
            "timeout_seconds",
        },
        "setup resource limits",
    )
    for item in result["resource_limits"].values():
        if isinstance(item, bool) or not isinstance(item, int) or item <= 0:
            raise PermissionError("Provider Host setup resource limit is invalid")
    issued = parse_utc(result["issued_at"])
    expires = parse_utc(result["expires_at"])
    if expires <= issued:
        raise PermissionError("Provider Host setup expiry is invalid")
    for value_name in ("usage_policy_digest",):
        require_sha256(result[value_name], value_name)
    for container, value_name in (
        (result["environment"], "digest"),
        (result["executable"], "sha256"),
    ):
        require_sha256(container[value_name], value_name)
    return result


def validate_setup_result(value: object) -> dict[str, Any]:
    fields = {
        "authority_id",
        "challenge",
        "environment_digest",
        "host_id",
        "observation",
        "operation",
        "provider_registration_id",
        "recorded_at",
        "setup_envelope_digest",
        "setup_id",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise PermissionError("Provider Host setup result fields are invalid")
    result = cast(dict[str, Any], json.loads(canonical_json(value)))
    for name in fields - {"observation"}:
        _text(result.get(name), f"setup result {name}")
    if result["operation"] not in {"REGISTER_PROBE", "QUALIFY"}:
        raise PermissionError("Provider Host setup result operation is invalid")
    if not isinstance(result["observation"], dict):
        raise PermissionError("Provider Host setup observation is invalid")
    process_result = result["observation"].get("process_result")
    if process_result is not None:
        _validate_setup_process_result(process_result)
    for name in ("environment_digest", "setup_envelope_digest"):
        require_sha256(result[name], name)
    parse_utc(result["recorded_at"])
    return result


def _validate_setup_process_result(value: object) -> None:
    fields = {
        "operation", "exit_code", "timed_out", "stdout_sha256",
        "stdout_bytes", "stderr_sha256", "stderr_bytes", "restricted",
        "job_confined", "started", "resumed",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise PermissionError("Provider Host setup process result fields are invalid")
    if value.get("operation") not in {"VERSION", "ACCOUNT_PROBE", "QUALIFICATION"}:
        raise PermissionError("Provider Host setup process result operation is invalid")
    exit_code = value.get("exit_code")
    if (
        isinstance(exit_code, bool)
        or not isinstance(exit_code, int)
        or not 0 <= exit_code <= 0xFFFFFFFF
    ):
        raise PermissionError("Provider Host setup process exit code is invalid")
    for name in ("stdout_bytes", "stderr_bytes"):
        count = value.get(name)
        if (
            isinstance(count, bool)
            or not isinstance(count, int)
            or not 0 <= count <= 1_048_576
        ):
            raise PermissionError("Provider Host setup process byte count is invalid")
    for name in ("stdout_sha256", "stderr_sha256"):
        require_sha256(value.get(name), name)
    for name in ("timed_out", "restricted", "job_confined", "started", "resumed"):
        if not isinstance(value.get(name), bool):
            raise PermissionError("Provider Host setup process flag is invalid")
    if any(value.get(name) is not True for name in ("restricted", "job_confined", "started", "resumed")):
        raise PermissionError("Provider Host setup process confinement is invalid")


def validate_launch_envelope(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _LAUNCH_FIELDS:
        raise PermissionError("Provider Host launch fields are invalid")
    result = cast(dict[str, Any], json.loads(canonical_json(value)))
    for name in _LAUNCH_FIELDS - {
        "argv",
        "cancellation",
        "environment",
        "executable",
        "network_policy",
        "resource_limits",
        "sequence",
        "usage",
        "user_binding",
        "workspace",
    }:
        _text(result.get(name), f"launch {name}")
    if result["provider_id"] not in {"codex", "claude"}:
        raise PermissionError("Provider Host launch provider is invalid")
    if result["effort"] not in {"medium", "high"}:
        raise PermissionError("Provider effort is outside the qualified contract")
    if result["composition_identity"] != "PRODUCTION":
        raise PermissionError("Provider Host launch composition is not production")
    sequence = result.get("sequence")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence <= 0:
        raise PermissionError("Provider Host launch sequence is invalid")
    argv = result.get("argv")
    if (
        not isinstance(argv, list)
        or not argv
        or not all(isinstance(item, str) and item and "\x00" not in item for item in argv)
    ):
        raise PermissionError("Provider Host argv is invalid")
    _validate_argv(argv)
    _exact_object(result["user_binding"], {"profile_path", "session_id", "user_sid"}, "user binding")
    session_id = result["user_binding"].get("session_id")
    if isinstance(session_id, bool) or not isinstance(session_id, int) or session_id < 0:
        raise PermissionError("Provider Host Windows session is invalid")
    _exact_object(
        result["executable"],
        {"authenticode_binding", "file_identity", "path", "publisher", "sha256", "size", "version"},
        "executable",
    )
    _exact_object(
        result["executable"]["file_identity"],
        {"device_id", "file_id", "modified_ns", "schema_version", "size"},
        "file identity",
    )
    file_identity = result["executable"]["file_identity"]
    if file_identity.get("schema_version") != 1:
        raise PermissionError("Provider Host executable identity schema is invalid")
    for name, item in file_identity.items():
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise PermissionError(f"Provider Host executable {name} is invalid")
    if result["executable"].get("size") != file_identity.get("size"):
        raise PermissionError("Provider Host executable size binding differs")
    _exact_object(
        result["executable"]["authenticode_binding"],
        {"certificate_thumbprint", "publisher_subject", "source", "status"},
        "Authenticode binding",
    )
    authenticode = result["executable"]["authenticode_binding"]
    thumbprint = authenticode.get("certificate_thumbprint")
    if (
        authenticode.get("status") != "Valid"
        or authenticode.get("source") != "windows-authenticode"
        or not isinstance(thumbprint, str)
        or len(thumbprint) != 40
        or any(character not in "0123456789ABCDEF" for character in thumbprint)
    ):
        raise PermissionError("Provider Host Authenticode binding is invalid")
    _exact_object(result["workspace"], {"canonical_path", "identity", "reservation_id"}, "workspace")
    _exact_object(
        result["environment"],
        {
            "allowlist", "digest", "preparation_nonce", "scrubbed_names",
            "tls_root_bundle",
        },
        "environment",
    )
    _validate_tls_root_bundle(result["environment"].get("tls_root_bundle"))
    allowlist = result["environment"].get("allowlist")
    scrubbed = result["environment"].get("scrubbed_names")
    if (
        not isinstance(allowlist, list)
        or not allowlist
        or allowlist != sorted(set(allowlist), key=str.upper)
        or not all(isinstance(item, str) and item for item in allowlist)
        or not isinstance(scrubbed, list)
        or scrubbed != sorted(set(scrubbed), key=str.upper)
        or not all(isinstance(item, str) and item for item in scrubbed)
    ):
        raise PermissionError("Provider Host environment declaration is invalid")
    _exact_object(result["network_policy"], {"allow_external", "policy_id"}, "network policy")
    if not isinstance(result["network_policy"].get("allow_external"), bool):
        raise PermissionError("Provider Host network policy is invalid")
    _exact_object(
        result["usage"],
        {"generation", "max_units", "pool_id", "reservation_id"},
        "usage reservation",
    )
    for name in ("generation", "max_units"):
        item = result["usage"].get(name)
        if isinstance(item, bool) or not isinstance(item, int) or item <= 0:
            raise PermissionError(f"Provider Host usage {name} is invalid")
    _exact_object(
        result["cancellation"],
        {"on_lock", "on_logoff", "token_digest"},
        "cancellation policy",
    )
    if (
        result["cancellation"].get("on_lock") != "CANCEL_EXISTING"
        or result["cancellation"].get("on_logoff") != "CANCEL_AND_EXIT"
    ):
        raise PermissionError("Provider Host cancellation policy is invalid")
    _exact_object(
        result["resource_limits"],
        {"active_process_limit", "memory_bytes", "stderr_bytes", "stdout_bytes", "timeout_seconds"},
        "resource limits",
    )
    for name, item in result["resource_limits"].items():
        if isinstance(item, bool) or not isinstance(item, int) or item <= 0:
            raise PermissionError(f"Provider Host resource limit {name} is invalid")
    issued = parse_utc(result["issued_at"])
    expires = parse_utc(result["expires_at"])
    if expires <= issued:
        raise PermissionError("Provider Host launch expiry is invalid")
    for name in (
        "launch_claim_digest",
        "provider_input_digest",
    ):
        require_sha256(result[name], name)
    for container, name in (
        (result["cancellation"], "token_digest"),
        (result["environment"], "digest"),
        (result["executable"], "sha256"),
    ):
        require_sha256(container[name], name)
    return result


def validate_completion(value: object) -> dict[str, Any]:
    fields = {
        "authority_attempt_id",
        "envelope_digest",
        "environment_digest",
        "evidence_digest",
        "host_id",
        "launch_id",
        "provider_input_digest",
        "provider_output",
        "recorded_at",
        "state",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise PermissionError("Provider Host completion fields are invalid")
    result = cast(dict[str, Any], json.loads(canonical_json(value)))
    for name in fields - {"provider_output"}:
        _text(result.get(name), f"completion {name}")
    if result["state"] not in {"COMPLETED", "FAILED", "CANCELLED", "UNCERTAIN"}:
        raise PermissionError("Provider Host completion state is invalid")
    for name in ("envelope_digest", "environment_digest", "evidence_digest", "provider_input_digest"):
        require_sha256(result[name], name)
    parse_utc(result["recorded_at"])
    if not isinstance(result["provider_output"], dict):
        raise PermissionError("Provider Host completion output is invalid")
    return result


def parse_utc(value: object) -> datetime:
    if not isinstance(value, str):
        raise PermissionError("Provider Host timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise PermissionError("Provider Host timestamp is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise PermissionError("Provider Host timestamp is not UTC-aware")
    return parsed.astimezone(UTC)


def require_sha256(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise PermissionError(f"Provider Host {label} is invalid")
    return value


def encode_frame(value: Mapping[str, Any]) -> bytes:
    payload = canonical_json(value)
    if not payload or len(payload) > MAX_FRAME_BYTES:
        raise ValueError("Provider Host frame length is invalid")
    return len(payload).to_bytes(4, "little") + payload


def decode_frame(read: Callable[[int], bytes]) -> dict[str, Any]:
    length_raw = _read_exact(read, 4)
    length = int.from_bytes(length_raw, "little")
    if length <= 0 or length > MAX_FRAME_BYTES:
        raise PermissionError("Provider Host frame length is invalid")
    try:
        value = json.loads(_read_exact(read, length).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PermissionError("Provider Host frame is invalid JSON") from error
    if not isinstance(value, dict):
        raise PermissionError("Provider Host frame is not an object")
    return cast(dict[str, Any], value)


def _read_exact(read: Callable[[int], bytes], length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = read(remaining)
        if not chunk:
            raise EOFError("Provider Host frame ended early")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _unsigned(
    identity: str, key_id: str, purpose: str, payload: Mapping[str, Any]
) -> dict[str, Any]:
    _text(identity, "identity")
    _text(key_id, "key ID")
    _text(purpose, "purpose")
    return {
        "identity": identity,
        "key_id": key_id,
        "payload": dict(payload),
        "protocol": HOST_PROTOCOL,
        "purpose": purpose,
    }


def _parse_signed(
    record: Mapping[str, Any], identity: str, key_id: str, purpose: str
) -> tuple[dict[str, Any], bytes]:
    if set(record) != {"identity", "key_id", "payload", "protocol", "purpose", "signature"}:
        raise PermissionError("Provider Host signed fields are invalid")
    if (
        record.get("identity") != identity
        or record.get("key_id") != key_id
        or record.get("protocol") != HOST_PROTOCOL
        or record.get("purpose") != purpose
        or not isinstance(record.get("payload"), dict)
        or not isinstance(record.get("signature"), str)
    ):
        raise PermissionError("Provider Host signed identity is invalid")
    unsigned = {name: record[name] for name in ("identity", "key_id", "payload", "protocol", "purpose")}
    try:
        signature = base64.b64decode(str(record["signature"]), validate=True)
    except ValueError as error:
        raise PermissionError("Provider Host signature encoding is invalid") from error
    if not signature:
        raise PermissionError("Provider Host signature is empty")
    return unsigned, signature


def _signature_digest(unsigned: Mapping[str, Any]) -> bytes:
    return hashlib.sha256(b"KeeperProviderHost\0" + canonical_json(unsigned)).digest()


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise PermissionError(f"Provider Host {label} is invalid")
    return value


def _exact_object(value: object, fields: set[str], label: str) -> None:
    if not isinstance(value, dict) or set(value) != fields:
        raise PermissionError(f"Provider Host {label} fields are invalid")


def _validate_tls_root_bundle(value: object) -> None:
    _exact_object(
        value,
        {
            "canonical_path", "certificate_count", "file_identity", "sha256",
            "size", "source",
        },
        "TLS root bundle",
    )
    if not isinstance(value, dict):
        raise PermissionError("Provider Host TLS root bundle is invalid")
    path = value.get("canonical_path")
    count = value.get("certificate_count")
    size = value.get("size")
    if (
        not isinstance(path, str)
        or not path
        or not isinstance(count, int)
        or isinstance(count, bool)
        or count <= 0
        or count > 4096
        or not isinstance(size, int)
        or isinstance(size, bool)
        or size <= 0
        or size > 4 * 1024 * 1024
        or value.get("source") != "windows-root-store"
    ):
        raise PermissionError("Provider Host TLS root bundle is invalid")
    require_sha256(value.get("sha256"), "TLS root bundle SHA-256")
    identity = value.get("file_identity")
    _exact_object(
        identity,
        {"device_id", "file_id", "modified_ns", "schema_version", "size"},
        "TLS root bundle file identity",
    )
    if not isinstance(identity, dict):
        raise PermissionError("Provider Host TLS root bundle identity is invalid")
    if identity.get("schema_version") != 1 or identity.get("size") != size:
        raise PermissionError("Provider Host TLS root bundle identity differs")
    if any(
        isinstance(item, bool) or not isinstance(item, int) or item < 0
        for item in identity.values()
    ):
        raise PermissionError("Provider Host TLS root bundle identity is invalid")


def _validate_argv(arguments: list[str]) -> None:
    forbidden = (
        "--with-api-key",
        "api_key",
        "access_token",
        "paid-fallback",
        "dangerously-bypass",
        "--model-provider",
    )
    for argument in arguments:
        folded = argument.casefold()
        if any(value in folded for value in forbidden):
            raise PermissionError("Provider Host argv requests prohibited authority")
