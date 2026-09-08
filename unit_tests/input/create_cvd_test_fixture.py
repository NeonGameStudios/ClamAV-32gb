#!/usr/bin/env python3
"""Create a marker-complete unsigned CUD from a legacy CVD test fixture."""

import argparse
import gzip
import io
import pathlib
import tarfile


def build_fixture(source_path: pathlib.Path, output_path: pathlib.Path, strip_dsig: bool = True) -> None:
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
                if strip_dsig and member.name.endswith(".info"):
                    data = b"\n".join(
                        line for line in data.splitlines() if not line.startswith(b"DSIG:")
                    ) + b"\n"

                output_member = tarfile.TarInfo(member.name)
                # sigtool's --run-cdiff and --build tests mutate extracted
                # database files.  Historical CVD members are often
                # read-only, so generated unsigned test fixtures must grant
                # the test owner write access while preserving other mode
                # bits from the source archive.
                output_member.mode = member.mode | 0o600
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
    parser.add_argument("--keep-dsig", action="store_true")
    args = parser.parse_args()
    build_fixture(args.input, args.output, strip_dsig=not args.keep_dsig)


if __name__ == "__main__":
    main()
