#!/usr/bin/env python3
"""Freeze the current source manifest and files into a reproducible tar.gz.

The source tree may be dirty, so Git HEAD alone is not a source identity.
Each packaged byte must match the manifest generated from that working tree.
Generated provenance is included in the archive but excluded from the
regenerated Git-less source manifest.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tempfile


MANIFEST_LINE = re.compile(r"([0-9a-f]{64})  (.+)\Z")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def add_bytes(archive: tarfile.TarFile, name: str, data: bytes, mode: int) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    info.uid = info.gid = info.mtime = 0
    info.uname = info.gname = "root"
    archive.addfile(info, io.BytesIO(data))


def package(root: Path, output: Path) -> tuple[str, str]:
    root = root.resolve(strict=True)
    output = output.absolute()
    if output.is_relative_to(root):
        raise ValueError("package destination must be outside the source tree")
    if output.exists() or output.is_symlink():
        raise ValueError(f"package destination already exists: {output}")
    if not (root / "tools/largefile_source_manifest.sh").is_file():
        raise ValueError("source-manifest generator is missing")
    with tempfile.TemporaryDirectory(prefix="clamav-source-freeze-",
                                     dir=output.parent) as work:
        temporary = Path(work)
        manifest = temporary / "source-content.sha256"
        subprocess.run(["sh", str(root / "tools/largefile_source_manifest.sh"),
                        str(root), str(manifest)], check=True)
        manifest_bytes = manifest.read_bytes()
        entries: list[tuple[str, str]] = []
        for line in manifest_bytes.decode("utf-8").splitlines():
            match = MANIFEST_LINE.fullmatch(line)
            if match is None:
                raise ValueError("source manifest has a malformed row")
            expected, name = match.groups()
            relative = PurePosixPath(name)
            if relative.is_absolute() or ".." in relative.parts or name == "":
                raise ValueError(f"source manifest has an unsafe path: {name}")
            entries.append((name, expected))
        if not entries or len({name for name, _ in entries}) != len(entries):
            raise ValueError("source manifest paths are empty or repeated")
        entries.sort(key=lambda entry: entry[0])
        staged = temporary / "source.tar.gz"
        with staged.open("wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw,
                               compresslevel=9, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w",
                                  format=tarfile.PAX_FORMAT) as archive:
                    for name, expected in entries:
                        source = root / name
                        if (source.is_symlink() or not source.is_file() or
                                not source.resolve().is_relative_to(root)):
                            raise ValueError(f"source is missing or symlinked: {name}")
                        data = source.read_bytes()
                        if sha256(data) != expected:
                            raise ValueError(f"source changed after manifest generation: {name}")
                        mode = 0o755 if source.stat().st_mode & 0o111 else 0o644
                        add_bytes(archive, name, data, mode)
                    add_bytes(archive, "provenance/source-content.sha256",
                              manifest_bytes, 0o644)
        package_hash = hashlib.sha256()
        with staged.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                package_hash.update(chunk)
        os.link(staged, output)
        return sha256(manifest_bytes), package_hash.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_root", type=Path)
    parser.add_argument("output_tar_gz", type=Path)
    args = parser.parse_args()
    manifest_hash, package_hash = package(args.source_root, args.output_tar_gz)
    print(f"source_manifest_sha256={manifest_hash}")
    print(f"package_sha256={package_hash}")
    print(f"package_bytes={args.output_tar_gz.stat().st_size}")


if __name__ == "__main__":
    main()
