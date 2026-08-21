from __future__ import annotations

import ctypes
import os
import time
from pathlib import Path
from types import TracebackType
from typing import BinaryIO, Literal


class DatabaseMaintenanceBusyError(RuntimeError):
    """The Executive database is held for restore maintenance."""


class DatabaseFileLock:
    """One-byte advisory lock shared by supported database users."""

    def __init__(
        self,
        database: Path,
        mode: Literal["shared", "exclusive"],
        *,
        timeout_seconds: float,
    ) -> None:
        self.path = database.with_name(f"{database.name}.keeper-lock")
        self.mode = mode
        self.timeout_seconds = timeout_seconds
        self._file: BinaryIO | None = None
        self._overlapped: object | None = None

    def __enter__(self) -> DatabaseFileLock:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        file = self.path.open("a+b")
        try:
            self._acquire(file)
        except BaseException:
            file.close()
            raise
        self._file = file
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        file = self._file
        self._file = None
        if file is None:
            return
        try:
            self._release(file)
        finally:
            file.close()

    def _acquire(self, file: BinaryIO) -> None:
        deadline = time.monotonic() + self.timeout_seconds
        while True:
            if self._try_acquire(file):
                return
            if time.monotonic() >= deadline:
                raise DatabaseMaintenanceBusyError(
                    "Executive database is busy with restore maintenance"
                )
            time.sleep(0.01)

    def _try_acquire(self, file: BinaryIO) -> bool:
        if os.name == "nt":
            return self._try_acquire_windows(file)
        fcntl = __import__("fcntl")

        operation = fcntl.LOCK_NB | (
            fcntl.LOCK_EX if self.mode == "exclusive" else fcntl.LOCK_SH
        )
        try:
            fcntl.flock(file.fileno(), operation)
        except BlockingIOError:
            return False
        return True

    def _release(self, file: BinaryIO) -> None:
        if os.name == "nt":
            import msvcrt

            overlapped = self._overlapped
            if not isinstance(overlapped, _Overlapped):
                raise RuntimeError("Windows database lock state is invalid")
            handle = ctypes.c_void_p(msvcrt.get_osfhandle(file.fileno()))
            if not ctypes.windll.kernel32.UnlockFileEx(
                handle, 0, 1, 0, ctypes.byref(overlapped)
            ):
                raise ctypes.WinError()
            self._overlapped = None
            return
        fcntl = __import__("fcntl")

        fcntl.flock(file.fileno(), fcntl.LOCK_UN)

    def _try_acquire_windows(self, file: BinaryIO) -> bool:
        import msvcrt

        overlapped = _Overlapped()
        flags = 0x00000001
        if self.mode == "exclusive":
            flags |= 0x00000002
        handle = ctypes.c_void_p(msvcrt.get_osfhandle(file.fileno()))
        if ctypes.windll.kernel32.LockFileEx(
            handle, flags, 0, 1, 0, ctypes.byref(overlapped)
        ):
            self._overlapped = overlapped
            return True
        error = int(ctypes.windll.kernel32.GetLastError())
        if error in {33, 36, 158}:
            return False
        raise ctypes.WinError(error)


class _Overlapped(ctypes.Structure):
    _fields_ = [
        ("Internal", ctypes.c_void_p),
        ("InternalHigh", ctypes.c_void_p),
        ("Offset", ctypes.c_uint32),
        ("OffsetHigh", ctypes.c_uint32),
        ("hEvent", ctypes.c_void_p),
    ]
