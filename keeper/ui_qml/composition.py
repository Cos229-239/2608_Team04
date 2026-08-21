from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

from keeper.authority_service.client import ProductionAuthorityServiceClient
from keeper.pass_b.application import PassBApplication
from keeper.pass_b.repository import validate_protected_workspace_tree
from keeper.ui.view_models import SETUP_STEPS


class ProductSetupController:
    """UI-neutral setup state with validation delegated to existing services."""

    def __init__(self, application: Any) -> None:
        self.application = application
        self.index = 0
        self.evidence_directory = str(application.data_directory / "evidence")
        self.repository = ""
        routing = application.store.get("settings", "routing") or {}
        self.provider_policy = str(
            routing.get("default_provider_policy") or "automatic"
        )

    @property
    def step(self) -> str:
        return SETUP_STEPS[self.index][0]

    def back(self) -> str:
        self.index = max(0, self.index - 1)
        return self.step

    def next(self) -> str:
        self._validate()
        self.index = min(len(SETUP_STEPS) - 1, self.index + 1)
        return self.step

    def finish(self) -> None:
        if self.index != len(SETUP_STEPS) - 1:
            raise ValueError("Complete every setup step before finishing")
        self._validate_storage()
        if self.repository:
            self.application.git.inspect(Path(self.repository))
            self.application.add_project(Path(self.repository))
        self.application.store.upsert(
            "settings", "routing", {"default_provider_policy": self.provider_policy}
        )
        self.application.finish_setup(Path(self.evidence_directory))

    def validate_evidence_directory(self, value: Path) -> Path:
        self.evidence_directory = str(value)
        self._validate_storage()
        return Path(self.evidence_directory).resolve()

    def _validate(self) -> None:
        if self.step == "storage":
            self._validate_storage()
        if self.step == "repository" and self.repository:
            self.application.git.inspect(Path(self.repository))

    def _validate_storage(self) -> None:
        selected = Path(self.evidence_directory)
        validate_protected_workspace_tree(selected, require_exists=False)
        target = selected.resolve()
        target.mkdir(parents=True, exist_ok=True)
        validate_protected_workspace_tree(target)
        probe: Path | None = None
        try:
            descriptor, probe_name = tempfile.mkstemp(
                prefix=".keeper-write-probe-", suffix=".tmp", dir=target
            )
            probe = Path(probe_name)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(b"keeper-write-probe")
                stream.flush()
                os.fsync(stream.fileno())
            if probe.read_bytes() != b"keeper-write-probe":
                raise OSError("evidence-directory write probe failed")
        finally:
            if probe is not None:
                try:
                    probe.unlink(missing_ok=True)
                except OSError:
                    pass


def desktop_pass_b_application(
    application: Any, *, authority_health_client: Any | None = None
) -> PassBApplication:
    data_directory = Path(application.data_directory)
    health_client = authority_health_client
    if health_client is None:
        health_client = ProductionAuthorityServiceClient(timeout_seconds=0.25)
        bindings = configured_authority_bindings(application)
        if bindings:
            from keeper.pass_b.provider_bridge import bridge_qualified_provider
            from keeper.pass_b.usage_authority import ProductionUsageResetVerifier

            result = PassBApplication(
                data_directory,
                authority_client=health_client,
                authority_health_client=health_client,
                provider_bindings=bindings,
                authority_exchange_root=data_directory / "authority-exchange",
                usage_reset_verifier=ProductionUsageResetVerifier.unavailable(),
            )
            for binding in bindings:
                bridge_qualified_provider(result.orchestration, health_client, binding)
            return result
    return PassBApplication(
        data_directory, authority_health_client=health_client
    )


def configured_authority_bindings(application: Any) -> tuple[Any, ...]:
    from keeper.executive.authority_gateway import AuthorityProviderBinding

    registrations = application.provider_registrations()
    evidence = application.qualification_evidence()
    bindings: list[AuthorityProviderBinding] = []
    for registration in registrations.values():
        registration_id = registration.get("trusted_registration_id")
        if not isinstance(registration_id, str) or not registration_id:
            continue
        matches = [
            item
            for item in evidence.values()
            if item.get("registration_id") == registration_id
            and item.get("qualification_result") == "qualified"
            and isinstance(item.get("id"), str)
        ]
        if len(matches) != 1:
            continue
        bindings.append(
            AuthorityProviderBinding(registration_id, str(matches[0]["id"]))
        )
    return tuple(bindings)


__all__ = [
    "ProductSetupController",
    "configured_authority_bindings",
    "desktop_pass_b_application",
]
