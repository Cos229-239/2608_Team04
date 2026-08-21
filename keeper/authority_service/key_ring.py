from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from keeper.authority import AUTHORITY_KEY_VERSION, AuthorityKey
from keeper.recovery import atomic_write_json


class ServiceKeyRing:
    """Versioned service-owned signing keys with historical verification."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.metadata_path = self.root / "key-ring.json"
        self._keys: dict[int, AuthorityKey] = {}
        self._lock = threading.RLock()
        self.current_version = self._load_or_initialize()

    @property
    def current_key_id(self) -> str:
        return self._key(self.current_version).key_id

    def sign(self, purpose: str, record: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            value = {
                **record,
                "service_key_version": self.current_version,
            }
            return self._key(self.current_version).sign(purpose, value)

    def verify(self, purpose: str, record: object) -> bool:
        if not isinstance(record, dict):
            return False
        version = record.get("service_key_version")
        if not isinstance(version, int) or version <= 0:
            return False
        with self._lock:
            try:
                key = self._key(version)
            except (FileNotFoundError, PermissionError, RuntimeError):
                return False
            return key.verify(purpose, record)

    def rotate(self) -> dict[str, Any]:
        with self._lock:
            next_version = self.current_version + 1
            key = self._key(next_version, create=True)
            atomic_write_json(
                self.metadata_path,
                {
                    "schema_version": 1,
                    "current_version": next_version,
                    "historical_versions": list(range(1, next_version)),
                },
            )
            self.current_version = next_version
            return {"key_version": next_version, "key_id": key.key_id}

    def _load_or_initialize(self) -> int:
        if not self.metadata_path.exists():
            self._key(1, create=True)
            atomic_write_json(
                self.metadata_path,
                {
                    "schema_version": 1,
                    "current_version": 1,
                    "historical_versions": [],
                },
            )
            return 1
        try:
            value = json.loads(self.metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise PermissionError("authority key-ring metadata is corrupt") from error
        if (
            not isinstance(value, dict)
            or value.get("schema_version") != 1
            or not isinstance(value.get("current_version"), int)
            or value["current_version"] <= 0
            or not isinstance(value.get("historical_versions"), list)
            or value["historical_versions"]
            != list(range(1, int(value["current_version"])))
        ):
            raise PermissionError("authority key-ring metadata is invalid")
        version = int(value["current_version"])
        self._key(version)
        return version

    def _key(self, version: int, *, create: bool = False) -> AuthorityKey:
        cached = self._keys.get(version)
        if cached is not None:
            return cached
        directory = self.root / f"key-v{version}"
        key_path = (
            directory
            / "authority"
            / f"authority-key-v{AUTHORITY_KEY_VERSION}.bin"
        )
        if not create and not key_path.is_file():
            raise FileNotFoundError(
                f"authority key version {version} is unavailable"
            )
        if not create and self.metadata_path.exists():
            metadata = json.loads(self.metadata_path.read_text(encoding="utf-8"))
            current = int(metadata.get("current_version", 0))
            historical = metadata.get("historical_versions", [])
            if version != current and version not in historical:
                raise FileNotFoundError("authority historical key is unavailable")
        key = AuthorityKey(directory)
        self._keys[version] = key
        return key

    def clear_cached_keys(self) -> None:
        for key in self._keys.values():
            material = getattr(key, "_key", None)
            if isinstance(material, bytes):
                setattr(key, "_key", b"\0" * len(material))
        self._keys.clear()
