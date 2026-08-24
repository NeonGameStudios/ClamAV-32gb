#!/usr/bin/env python3
"""Generate deterministic PDF 1.7 object-stream qualification fixtures."""

import argparse
import binascii
import hashlib
import os
import tempfile
import zlib


MARKER = b"CLAMAV-PDF-OBJSTM-TAIL-MARKER"
CHUNK_SIZE = 1024 * 1024


class HashedWriter:
    def __init__(self, output):
        self.output = output
        self.digest = hashlib.sha256()
        self.offset = 0

    def write(self, data):
        self.output.write(data)
        self.digest.update(data)
        self.offset += len(data)


def embedded_object_parts(kind):
    page = (
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 1 1] "
        b"/Resources << >> /Contents 6 0 R "
    )
    if kind == "javascript":
        return page + b"/AA << /O << /S /JavaScript /JS (", b") >> >> >>"
    return page + b"/Payload (", b") >>"


def object_stream_layout(kind, decoded_size, malformed):
    prefix, suffix = embedded_object_parts(kind)
    if malformed:
        first_object = prefix + MARKER + suffix
        second_offset = len(first_object) + 1
        index = f"5 0 7 {second_offset} 8 999 ".encode("ascii")
        body = first_object + b" " + b"<< /Payload (second-object) >>"
        if decoded_size is not None and decoded_size != len(index) + len(body):
            raise ValueError("--decoded-size is not supported with --malformed")
        return index, body, 0, b"", b"", 3

    index = b"5 0 "
    minimum = len(index) + len(prefix) + len(MARKER) + len(suffix)
    target = minimum if decoded_size is None else decoded_size
    if target < minimum:
        raise ValueError(f"--decoded-size must be at least {minimum}")
    return index, prefix, target - minimum, MARKER, suffix, 1


def decoded_chunks(layout):
    index, prefix, fill_length, marker, suffix, _ = layout
    yield index
    yield prefix
    fill = b"A" * CHUNK_SIZE
    while fill_length:
        length = min(fill_length, len(fill))
        yield fill[:length]
        fill_length -= length
    if marker:
        yield marker
    yield suffix


def spool_encoded(layout, filter_name):
    spool = tempfile.TemporaryFile()
    encoded_hash = hashlib.sha256()
    encoded_size = 0
    compressor = zlib.compressobj(level=9)

    def emit(data, encode=True):
        nonlocal encoded_size
        if filter_name == "asciihex-flate" and encode:
            data = binascii.hexlify(data).upper()
        if data:
            spool.write(data)
            encoded_hash.update(data)
            encoded_size += len(data)

    for chunk in decoded_chunks(layout):
        emit(compressor.compress(chunk))
    emit(compressor.flush())
    if filter_name == "asciihex-flate":
        emit(b">", encode=False)
    spool.seek(0)
    return spool, encoded_size, encoded_hash.hexdigest()


def write_indirect(writer, number, contents):
    offset = writer.offset
    writer.write(f"{number} 0 obj\n".encode("ascii"))
    writer.write(contents)
    writer.write(b"\nendobj\n")
    return offset


def xref_entry(entry_type, field2, field3):
    return bytes([entry_type]) + field2.to_bytes(8, "big") + field3.to_bytes(2, "big")


def build_fixture(path, filter_name="raw", kind="javascript", decoded_size=None, malformed=False):
    layout = object_stream_layout(kind, decoded_size, malformed)
    first = len(layout[0])
    actual_decoded_size = sum(len(chunk) for chunk in decoded_chunks(layout))
    object_count = layout[-1]
    encoded_spool = None

    if filter_name == "raw":
        encoded_size = actual_decoded_size
        raw_encoded_hash = hashlib.sha256()
        encoded_sha256 = None
        filter_dictionary = b""
    else:
        raw_encoded_hash = None
        encoded_spool, encoded_size, encoded_sha256 = spool_encoded(layout, filter_name)
        if filter_name == "flate":
            filter_dictionary = b" /Filter /FlateDecode"
        elif filter_name == "asciihex-flate":
            filter_dictionary = b" /Filter [/ASCIIHexDecode /FlateDecode]"
        else:
            raise ValueError(f"unsupported filter: {filter_name}")

    try:
        with open(path, "wb") as raw_output:
            writer = HashedWriter(raw_output)
            writer.write(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
            offsets = {}
            offsets[1] = write_indirect(writer, 1, b"<< /Type /Catalog /Pages 2 0 R >>")
            offsets[2] = write_indirect(writer, 2, b"<< /Type /Pages /Count 1 /Kids [5 0 R] >>")

            offsets[3] = writer.offset
            dictionary = (
                f"3 0 obj\n<< /Type /ObjStm /N {object_count} /First {first} "
                f"/Length {encoded_size}".encode("ascii")
                + filter_dictionary
                + b" >>\nstream\n"
            )
            writer.write(dictionary)
            stream_offset = writer.offset
            if encoded_spool is None:
                for chunk in decoded_chunks(layout):
                    writer.write(chunk)
                    raw_encoded_hash.update(chunk)
            else:
                while True:
                    chunk = encoded_spool.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    writer.write(chunk)
            writer.write(b"\nendstream\nendobj\n")
            if encoded_sha256 is None:
                encoded_sha256 = raw_encoded_hash.hexdigest()

            offsets[6] = write_indirect(writer, 6, b"<< /Length 4 >>\nstream\nq\nQ\nendstream")
            offsets[4] = writer.offset
            xref_entries = [xref_entry(0, 0, 65535)]
            xref_entries.extend(xref_entry(1, offsets[number], 0) for number in range(1, 5))
            xref_entries.append(xref_entry(2, 3, 0))
            xref_entries.append(xref_entry(1, offsets[6], 0))
            if malformed:
                xref_entries.extend((xref_entry(2, 3, 1), xref_entry(2, 3, 2)))
            else:
                xref_entries.extend((xref_entry(0, 0, 0), xref_entry(0, 0, 0)))
            xref = b"".join(xref_entries)
            xref_dictionary = (
                f"4 0 obj\n<< /Type /XRef /Size 9 /Root 1 0 R "
                f"/W [1 8 2] /Index [0 9] /Length {len(xref)} >>\nstream\n".encode("ascii")
            )
            writer.write(xref_dictionary)
            writer.write(xref)
            writer.write(b"\nendstream\nendobj\nstartxref\n")
            writer.write(f"{offsets[4]}\n%%EOF\n".encode("ascii"))

            result = {
                "decoded_size": actual_decoded_size,
                "encoded_sha256": encoded_sha256,
                "encoded_size": encoded_size,
                "file_size": writer.offset,
                "filter": filter_name,
                "first": first,
                "kind": kind,
                "malformed": int(malformed),
                "marker": MARKER.decode("ascii"),
                "object_count": object_count,
                "sha256": writer.digest.hexdigest(),
                "stream_offset": stream_offset,
                "xref_offset": offsets[4],
            }
    except Exception:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        raise
    finally:
        if encoded_spool is not None:
            encoded_spool.close()

    if os.path.getsize(path) != result["file_size"]:
        raise RuntimeError("fixture size changed after generation")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output")
    parser.add_argument("--filter", choices=("raw", "flate", "asciihex-flate"), default="raw")
    parser.add_argument("--kind", choices=("javascript", "opaque"), default="javascript")
    parser.add_argument("--decoded-size", type=int)
    parser.add_argument("--malformed", action="store_true")
    args = parser.parse_args()

    result = build_fixture(
        args.output,
        filter_name=args.filter,
        kind=args.kind,
        decoded_size=args.decoded_size,
        malformed=args.malformed,
    )
    for key in sorted(result):
        print(f"{key}={result[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
