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


def decrypt_stream(encoded, metadata, object_number=3):
    if metadata["encryption"] == "none":
        return encoded
    assert metadata["encryption"] == "rc4-r2"
    security = fixture.standard_r2_security()
    assert metadata["file_id"] == security["file_id"].hex()
    assert metadata["file_key_sha256"] == hashlib.sha256(
        security["file_key"]
    ).hexdigest()
    return fixture.rc4(
        encoded,
        fixture.rc4_object_key(security["file_key"], object_number),
    )


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
    encryption_entry = xref[7 * 11 : 8 * 11]
    if metadata["encryption"] == "rc4-r2":
        assert encryption_entry[0] == 1
        assert b"/Encrypt 7 0 R" in data[metadata["xref_offset"] : xref_header_end]
        assert b"7 0 obj\n<< /Filter /Standard /V 1 /R 2 /Length 40" in data
    elif not metadata["malformed"]:
        assert encryption_entry[0] == 0

    encoded = read_stream(path, metadata)
    decoded = decode_stream(decrypt_stream(encoded, metadata), metadata["filter"])
    assert decoded == expected
    assert len(decoded) == metadata["decoded_size"]
    assert hashlib.sha256(encoded).hexdigest() == metadata["encoded_sha256"]


def main():
    cases = 0
    assert fixture.rc4(b"Plaintext", b"Key").hex() == "bbf316e8d940af0ad3"
    cases += 1
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

        for filter_name in ("raw", "flate", "asciihex-flate"):
            path = os.path.join(directory, f"encrypted-{filter_name}.pdf")
            layout = fixture.object_stream_layout("javascript", None, False)
            expected = b"".join(fixture.decoded_chunks(layout))
            metadata = fixture.build_fixture(
                path,
                filter_name=filter_name,
                encryption="rc4-r2",
            )
            verify_pdf(path, metadata, expected)
            assert metadata["encryption"] == "rc4-r2"
            assert fixture.MARKER not in read_stream(path, metadata)
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

        encrypted_large_path = os.path.join(directory, "encrypted-materialized.pdf")
        encrypted_large_layout = fixture.object_stream_layout(
            "opaque", decoded_size, False
        )
        encrypted_large_expected = b"".join(
            fixture.decoded_chunks(encrypted_large_layout)
        )
        encrypted_large = fixture.build_fixture(
            encrypted_large_path,
            filter_name="raw",
            kind="opaque",
            decoded_size=decoded_size,
            encryption="rc4-r2",
        )
        verify_pdf(
            encrypted_large_path,
            encrypted_large,
            encrypted_large_expected,
        )
        assert fixture.MARKER not in read_stream(
            encrypted_large_path, encrypted_large
        )
        assert os.stat(encrypted_large_path).st_blocks * 512 >= os.path.getsize(
            encrypted_large_path
        )
        cases += 1

        duplicate_path = os.path.join(directory, "duplicate.pdf")
        duplicate = fixture.build_fixture(duplicate_path, filter_name="asciihex-flate")
        assert duplicate["sha256"] == fixture.build_fixture(
            duplicate_path, filter_name="asciihex-flate"
        )["sha256"]
        cases += 1

        encrypted_duplicate_path = os.path.join(directory, "encrypted-duplicate.pdf")
        encrypted_duplicate = fixture.build_fixture(
            encrypted_duplicate_path,
            filter_name="asciihex-flate",
            encryption="rc4-r2",
        )
        assert encrypted_duplicate["sha256"] == fixture.build_fixture(
            encrypted_duplicate_path,
            filter_name="asciihex-flate",
            encryption="rc4-r2",
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

        rejected_encrypted_path = os.path.join(directory, "rejected-encrypted.pdf")
        try:
            fixture.build_fixture(
                rejected_encrypted_path,
                malformed=True,
                encryption="rc4-r2",
            )
        except ValueError:
            pass
        else:
            raise AssertionError("malformed encrypted object stream was accepted")
        assert not os.path.exists(rejected_encrypted_path)
        cases += 1

    print(f"PDF object-stream fixture tests passed: {cases}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
