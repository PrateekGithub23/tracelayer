"""
Safe reading of dataset archives.

Defences (each tested in tests/test_datasets.py):
  * Nothing is extracted to disk. Members are streamed into memory, so member names, including
    `../../etc/passwd`, absolute paths, and symlink entries, can never cause a write anywhere.
  * Member names are still validated, and suspicious archives are rejected outright.
  * Limits on member count, per-member and total *uncompressed* size, and compression ratio stop zip
    bombs. Sizes are enforced while reading (the header's declared size is not trusted).
  * Only the expected file types are read.
"""

import stat
import zipfile
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import BinaryIO


class ArchiveError(ValueError):
    pass


@dataclass(frozen=True)
class Limits:
    max_members: int = 16
    max_member_bytes: int = 200 * 1024 * 1024
    max_total_bytes: int = 400 * 1024 * 1024
    max_ratio: float = 120.0  # OTRF JSON compresses ~20-25x; classic bombs are 1000x+
    allowed_suffixes: tuple[str, ...] = (".json", ".jsonl", ".ndjson", ".log")


def _check_name(name: str) -> None:
    p = PurePosixPath(name.replace("\\", "/"))
    if p.is_absolute() or ".." in p.parts or name.startswith(("/", "\\")) or ":" in p.parts[0]:
        raise ArchiveError(f"unsafe member path: {name!r}")


def read_members(fileobj: BinaryIO, limits: Limits = Limits()) -> dict[str, bytes]:
    try:
        z = zipfile.ZipFile(fileobj)
    except zipfile.BadZipFile as exc:
        raise ArchiveError("not a valid zip archive") from exc
    infos = [i for i in z.infolist() if not i.is_dir()]
    if len(infos) > limits.max_members:
        raise ArchiveError(f"archive has {len(infos)} members; limit is {limits.max_members}")
    out: dict[str, bytes] = {}
    total = 0
    for info in infos:
        _check_name(info.filename)
        if stat.S_ISLNK(info.external_attr >> 16):
            raise ArchiveError(f"symlink member rejected: {info.filename!r}")
        if not info.filename.lower().endswith(limits.allowed_suffixes):
            continue  # e.g. __MACOSX metadata: ignored, never read
        if info.compress_size and info.file_size / info.compress_size > limits.max_ratio:
            raise ArchiveError(f"compression ratio of {info.filename!r} exceeds {limits.max_ratio:.0f}x")
        buf = bytearray()
        with z.open(info) as fh:
            while chunk := fh.read(1024 * 1024):
                buf += chunk
                if len(buf) > limits.max_member_bytes:
                    raise ArchiveError(f"{info.filename!r} expands beyond {limits.max_member_bytes} bytes")
                if total + len(buf) > limits.max_total_bytes:
                    raise ArchiveError("archive expands beyond the total size limit")
                if info.compress_size and len(buf) / max(info.compress_size, 1) > limits.max_ratio:
                    raise ArchiveError(f"compression ratio of {info.filename!r} exceeds {limits.max_ratio:.0f}x")
        total += len(buf)
        out[info.filename] = bytes(buf)
    if not out:
        raise ArchiveError("archive contains no readable event files")
    return out
