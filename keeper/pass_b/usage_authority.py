from __future__ import annotations

import hashlib
import hmac
import json
import math
import uuid
from dataclasses import asdict, dataclass
from datetime import timedelta, datetime
from types import MappingProxyType
from typing import Mapping, Protocol, final

from keeper.pass_b.models import UsagePoolRecord


@dataclass(frozen=True, slots=True)
class UsageResetObservation:
    observation_id: str
    pool_id: str
    provider_id: str
    account_id: str
    generation: int
    window_id: str
    capacity: float | None
    consumed: float
    remaining: float | None
    reset_at: str
    observed_at: str
    expires_at: str
    source: str
    confidence: str
    model_ids: tuple[str, ...]
    session_ids: tuple[str, ...]
    proof: str

    def digest(self) -> str:
        value = asdict(self)
        value.pop("proof")
        return hashlib.sha256(
            json.dumps(
                value, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()


class UsageResetVerifier(Protocol):
    def verify(
        self,
        pool: UsagePoolRecord,
        observation: UsageResetObservation,
        *,
        now: datetime,
    ) -> None: ...


class UnavailableUsageResetVerifier:
    def verify(
        self,
        pool: UsagePoolRecord,
        observation: UsageResetObservation,
        *,
        now: datetime,
    ) -> None:
        del pool, observation, now
        raise PermissionError(
            "authenticated provider usage reset observer is unavailable"
        )


@final
class ProductionUsageResetVerifier:
    """Exact HMAC verifier for provider/account reset observations."""

    def __init__(
        self,
        verification_keys: Mapping[tuple[str, str], bytes],
    ) -> None:
        keys: dict[tuple[str, str], bytes] = {}
        for identity, key in verification_keys.items():
            if (
                type(identity) is not tuple
                or len(identity) != 2
                or any(type(item) is not str or not item for item in identity)
                or type(key) is not bytes
                or len(key) < 32
            ):
                raise ValueError(
                    "usage observer keys require exact provider/account identities"
                )
            keys[identity] = key
        if not keys:
            raise ValueError("at least one production usage observer key is required")
        self.__verification_keys = MappingProxyType(keys)

    @classmethod
    def unavailable(cls) -> ProductionUsageResetVerifier:
        """Return an exact production verifier that rejects every reset.

        This permits production execution for unlimited/local pools while
        keeping usage-reset behavior fail closed until an authenticated
        provider/account observer key is explicitly configured.
        """
        verifier = object.__new__(cls)
        verifier.__verification_keys = MappingProxyType({})
        return verifier

    def verify(
        self,
        pool: UsagePoolRecord,
        observation: UsageResetObservation,
        *,
        now: datetime,
    ) -> None:
        _validate_observation(pool, observation, now)
        if not observation.source.startswith(
            "PROVIDER_AUTHENTICATED:"
        ):
            raise PermissionError(
                "production reset source is not provider authenticated"
            )
        key = self.__verification_keys.get(
            (observation.provider_id, observation.account_id)
        )
        if key is None:
            raise PermissionError("provider usage observer identity is not trusted")
        expected = "hmac-sha256:" + hmac.new(
            key, observation.digest().encode("ascii"), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, observation.proof):
            raise PermissionError(
                "provider usage reset proof is unauthenticated"
            )


@final
class TestUsageResetVerifier:
    """Explicit deterministic verifier for tests and the isolated pilot."""

    __test__ = False

    def __init__(self) -> None:
        self._issued: dict[str, str] = {}
        self._consumed: set[str] = set()

    def issue(
        self,
        pool: UsagePoolRecord,
        *,
        reset_at: str,
        observed_at: str,
        model_ids: tuple[str, ...],
        session_ids: tuple[str, ...],
        remaining: float | None = None,
    ) -> UsageResetObservation:
        observed = datetime.fromisoformat(observed_at)
        available = pool.capacity if remaining is None else remaining
        consumed = (
            0.0
            if pool.capacity is None or available is None
            else pool.capacity - available
        )
        observation = UsageResetObservation(
            observation_id=f"test-reset:{uuid.uuid4().hex}",
            pool_id=pool.pool_id,
            provider_id=pool.provider_id,
            account_id=pool.account_id,
            generation=pool.observation_generation + 1,
            window_id=(
                f"{pool.identity}:generation:{pool.observation_generation + 1}"
            ),
            capacity=pool.capacity,
            consumed=consumed,
            remaining=available,
            reset_at=reset_at,
            observed_at=observed_at,
            expires_at=(observed + timedelta(minutes=5)).isoformat(),
            source="TEST_AUTHENTICATED_USAGE_OBSERVER",
            confidence="HIGH",
            model_ids=tuple(sorted(model_ids)),
            session_ids=tuple(sorted(session_ids)),
            proof="pending",
        )
        digest = observation.digest()
        signed = UsageResetObservation(
            **{
                **asdict(observation),
                "proof": f"test-proof:{digest}",
            }
        )
        self._issued[signed.observation_id] = signed.digest()
        return signed

    def verify(
        self,
        pool: UsagePoolRecord,
        observation: UsageResetObservation,
        *,
        now: datetime,
    ) -> None:
        if observation.observation_id in self._consumed:
            raise PermissionError(
                "test usage reset observation was replayed"
            )
        _validate_observation(pool, observation, now)
        expected = self._issued.get(observation.observation_id)
        if (
            expected != observation.digest()
            or observation.proof
            != f"test-proof:{observation.digest()}"
        ):
            raise PermissionError(
                "test usage reset observation is invalid or replayed"
            )
        self._consumed.add(observation.observation_id)


def _validate_observation(
    pool: UsagePoolRecord,
    observation: UsageResetObservation,
    now: datetime,
) -> None:
    try:
        reset = datetime.fromisoformat(observation.reset_at)
        observed = datetime.fromisoformat(observation.observed_at)
        expires = datetime.fromisoformat(observation.expires_at)
    except ValueError as error:
        raise PermissionError(
            "usage reset observation timestamps are invalid"
        ) from error
    numeric = (
        observation.consumed,
        *(() if observation.capacity is None else (observation.capacity,)),
        *(() if observation.remaining is None else (observation.remaining,)),
    )
    capacity_consistent = (
        observation.capacity is None
        and observation.remaining is None
        and observation.consumed == 0
    ) or (
        observation.capacity is not None
        and observation.remaining is not None
        and math.isclose(
            observation.consumed + observation.remaining,
            observation.capacity,
            rel_tol=0,
            abs_tol=1e-9,
        )
    )
    if (
        reset.tzinfo is None
        or observed.tzinfo is None
        or expires.tzinfo is None
        or now.tzinfo is None
        or observation.pool_id != pool.pool_id
        or observation.provider_id != pool.provider_id
        or observation.account_id != pool.account_id
        or observation.generation != pool.observation_generation + 1
        or observation.capacity != pool.capacity
        or not observation.observation_id
        or not observation.window_id
        or not observation.source
        or observation.confidence != "HIGH"
        or not observation.model_ids
        or not observation.session_ids
        or len(set(observation.model_ids)) != len(observation.model_ids)
        or len(set(observation.session_ids)) != len(observation.session_ids)
        or any(not math.isfinite(item) or item < 0 for item in numeric)
        or not capacity_consistent
        or reset > observed
        or observed > now
        or expires < observed
        or now > expires
        or pool.reset_at is None
        or reset < datetime.fromisoformat(pool.reset_at)
    ):
        raise PermissionError(
            "usage reset observation is stale, incomplete, or mismatched"
        )