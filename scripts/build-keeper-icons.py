from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QImage


SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)


def build_icons(source: Path, destination: Path) -> dict[str, str]:
    source = source.resolve(strict=True)
    destination = destination.resolve()
    image = QImage(str(source))
    if image.isNull():
        raise ValueError("official Keeper icon source is not a readable image")
    if image.width() != image.height():
        raise ValueError("official Keeper icon source must be square")
    destination.mkdir(parents=True, exist_ok=True)
    pngs: list[tuple[int, bytes]] = []
    result: dict[str, str] = {}
    for size in SIZES:
        target = destination / f"keeper-{size}.png"
        scaled = image.scaled(
            size,
            size,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        if not scaled.save(str(target), "PNG"):
            raise OSError(f"could not create icon size {size}")
        data = target.read_bytes()
        pngs.append((size, data))
        result[target.name] = hashlib.sha256(data).hexdigest().upper()

    ico = destination / "keeper.ico"
    header_size = 6 + 16 * len(pngs)
    offset = header_size
    entries: list[bytes] = []
    payload = bytearray()
    for size, data in pngs:
        dimension = 0 if size == 256 else size
        entries.append(
            struct.pack(
                "<BBBBHHII",
                dimension,
                dimension,
                0,
                0,
                1,
                32,
                len(data),
                offset,
            )
        )
        payload.extend(data)
        offset += len(data)
    ico.write_bytes(
        struct.pack("<HHH", 0, 1, len(entries)) + b"".join(entries) + payload
    )
    result[ico.name] = hashlib.sha256(ico.read_bytes()).hexdigest().upper()
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Keeper Windows icon assets")
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    for name, digest in build_icons(args.source, args.destination).items():
        print(f"{digest}  {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
