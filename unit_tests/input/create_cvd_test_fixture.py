#!/usr/bin/env python3
"""Create a marker-complete unsigned CUD from the legacy CVD test fixture."""

import argparse
import gzip
import io
import pathlib
import tarfile


def build_fixture(source_path: pathlib.Path, output_path: pathlib.Path) -> None:
    source = source_path.read_bytes()
    if len(source) < 512 or not source[:11] == b"ClamAV-VDB:":
        raise ValueError("input is not a complete CVD fixture")

    archive = gzip.decompress(source[512:])
    output_archive = io.BytesIO()
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as source_tar:
        with tarfile.open(fileobj=output_archive, mode="w", format=tarfile.USTAR_FORMAT) as output_tar:
            for member in source_tar:
                if not member.isfile():
                    raise ValueError(f"unsupported non-file CVD member: {member.name}")
                data = source_tar.extractfile(member).read()
                if member.name == "test.info":
                    data = b"\n".join(
                        line for line in data.splitlines() if not line.startswith(b"DSIG:")
                    ) + b"\n"

                output_member = tarfile.TarInfo(member.name)
                output_member.mode = member.mode
                output_member.uid = member.uid
                output_member.gid = member.gid
                output_member.mtime = member.mtime
                output_member.uname = member.uname
                output_member.gname = member.gname
                output_member.size = len(data)
                output_tar.addfile(output_member, io.BytesIO(data))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(source[:512] + gzip.compress(output_archive.getvalue(), mtime=0))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    build_fixture(args.input, args.output)


if __name__ == "__main__":
    main()
