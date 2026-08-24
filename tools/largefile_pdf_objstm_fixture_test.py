#!/usr/bin/env python3
"""Self-test the deterministic PDF object-stream fixture generator."""

import hashlib
import os
import re
import tempfile
import zlib

import largefile_pdf_objstm_fixture as fixture


def read_stream(path, metadata):
    with open(path, "rb") as source:
        source.seek(metadata["stream_offset"])
        return source.read(metadata["encoded_size"])


def decode_stream(encoded, filter_name):
    if filter_name == "raw":
        return encoded
    if filter_name == "flate":
        return zlib.decompress(encoded)
    if filter_name == "asciihex-flate":
        assert encoded.endswith(b">")
        return zlib.decompress(bytes.fromhex(encoded[:-1].decode("ascii")))
    raise AssertionError(f"unexpected filter {filter_name}")


def verify_pdf(path, metadata, expected):
    with open(path, "rb") as source:
        data = source.read()
    assert data.startswith(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    assert len(data) == metadata["file_size"]
    assert hashlib.sha256(data).hexdigest() == metadata["sha256"]
    assert data[metadata["xref_offset"] :].startswith(b"4 0 obj\n<< /Type /XRef")
    assert data.endswith(f"startxref\n{metadata['xref_offset']}\n%%EOF\n".encode("ascii"))

    xref_header_end = data.index(b"\nstream\n", metadata["xref_offset"]) + len(b"\nstream\n")
    length_match = re.search(rb"/Length ([0-9]+)", data[metadata["xref_offset"] : xref_header_end])
    assert length_match is not None
    xref_length = int(length_match.group(1))
    xref = data[xref_header_end : xref_header_end + xref_length]
    assert len(xref) == 9 * 11
    compressed = xref[5 * 11 : 6 * 11]
    assert compressed[0] == 2
    assert int.from_bytes(compressed[1:9], "big") == 3
    assert int.from_bytes(compressed[9:11], "big") == 0
    content_stream = xref[6 * 11 : 7 * 11]
    assert content_stream[0] == 1

    decoded = decode_stream(read_stream(path, metadata), metadata["filter"])
    assert decoded == expected
    assert len(decoded) == metadata["decoded_size"]
    assert hashlib.sha256(read_stream(path, metadata)).hexdigest() == metadata["encoded_sha256"]


def main():
    cases = 0
    with tempfile.TemporaryDirectory(prefix="clamav-pdf-objstm-") as directory:
        for filter_name in ("raw", "flate", "asciihex-flate"):
            path = os.path.join(directory, f"valid-{filter_name}.pdf")
            layout = fixture.object_stream_layout("javascript", None, False)
            expected = b"".join(fixture.decoded_chunks(layout))
            metadata = fixture.build_fixture(path, filter_name=filter_name)
            verify_pdf(path, metadata, expected)
            assert metadata["first"] == len(layout[0])
            assert metadata["object_count"] == 1
            assert fixture.MARKER in expected
            cases += 1

        malformed_path = os.path.join(directory, "malformed.pdf")
        malformed_layout = fixture.object_stream_layout("javascript", None, True)
        malformed_expected = b"".join(fixture.decoded_chunks(malformed_layout))
        malformed = fixture.build_fixture(malformed_path, malformed=True)
        verify_pdf(malformed_path, malformed, malformed_expected)
        assert malformed["malformed"] == 1
        assert malformed["object_count"] == 3
        assert malformed["marker"] == fixture.MARKER.decode("ascii")
        assert fixture.MARKER in malformed_expected
        cases += 1

        large_path = os.path.join(directory, "materialized.pdf")
        decoded_size = 2 * fixture.CHUNK_SIZE + 123
        large_layout = fixture.object_stream_layout("opaque", decoded_size, False)
        large_expected = b"".join(fixture.decoded_chunks(large_layout))
        large = fixture.build_fixture(
            large_path,
            filter_name="raw",
            kind="opaque",
            decoded_size=decoded_size,
        )
        verify_pdf(large_path, large, large_expected)
        assert large["decoded_size"] == decoded_size
        assert os.stat(large_path).st_blocks * 512 >= os.path.getsize(large_path)
        cases += 1

        duplicate_path = os.path.join(directory, "duplicate.pdf")
        duplicate = fixture.build_fixture(duplicate_path, filter_name="asciihex-flate")
        assert duplicate["sha256"] == fixture.build_fixture(
            duplicate_path, filter_name="asciihex-flate"
        )["sha256"]
        cases += 1

        rejected_path = os.path.join(directory, "rejected.pdf")
        try:
            fixture.build_fixture(rejected_path, decoded_size=1)
        except ValueError:
            pass
        else:
            raise AssertionError("undersized object stream was accepted")
        assert not os.path.exists(rejected_path)
        cases += 1

    print(f"PDF object-stream fixture tests passed: {cases}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
