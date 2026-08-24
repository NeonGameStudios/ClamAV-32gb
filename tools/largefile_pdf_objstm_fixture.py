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
PASSWORD_PADDING = bytes.fromhex(
    "28BF4E5E4E758A4164004E56FFFA0108"
    "2E2E00B6D0683E802F0CA9FE6453697A"
)
FILE_ID = hashlib.md5(b"ClamAV deterministic encrypted object stream").digest()


class RC4:
    def __init__(self, key):
        if not key:
            raise ValueError("RC4 key must not be empty")
        self.state = list(range(256))
        j = 0
        for i in range(256):
            j = (j + self.state[i] + key[i % len(key)]) & 0xFF
            self.state[i], self.state[j] = self.state[j], self.state[i]
        self.i = 0
        self.j = 0

    def apply(self, data):
        output = bytearray(data)
        for offset, value in enumerate(output):
            self.i = (self.i + 1) & 0xFF
            self.j = (self.j + self.state[self.i]) & 0xFF
            self.state[self.i], self.state[self.j] = (
                self.state[self.j],
                self.state[self.i],
            )
            key_byte = self.state[(self.state[self.i] + self.state[self.j]) & 0xFF]
            output[offset] = value ^ key_byte
        return bytes(output)


def rc4(data, key):
    return RC4(key).apply(data)


def standard_r2_security():
    permissions = -4
    owner_key = hashlib.md5(PASSWORD_PADDING).digest()[:5]
    owner = rc4(PASSWORD_PADDING, owner_key)
    key_input = (
        PASSWORD_PADDING
        + owner
        + (permissions & 0xFFFFFFFF).to_bytes(4, "little")
        + FILE_ID
    )
    file_key = hashlib.md5(key_input).digest()[:5]
    user = rc4(PASSWORD_PADDING, file_key)
    return {
        "file_id": FILE_ID,
        "file_key": file_key,
        "owner": owner,
        "permissions": permissions,
        "user": user,
    }


def rc4_object_key(file_key, object_number, generation=0):
    material = (
        file_key
        + object_number.to_bytes(3, "little")
        + generation.to_bytes(2, "little")
    )
    return hashlib.md5(material).digest()[: min(len(file_key) + 5, 16)]


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
    encoded_size = 0
    compressor = zlib.compressobj(level=9)

    def emit(data, encode=True):
        nonlocal encoded_size
        if filter_name == "asciihex-flate" and encode:
            data = binascii.hexlify(data).upper()
        if data:
            spool.write(data)
            encoded_size += len(data)

    for chunk in decoded_chunks(layout):
        emit(compressor.compress(chunk))
    emit(compressor.flush())
    if filter_name == "asciihex-flate":
        emit(b">", encode=False)
    spool.seek(0)
    return spool, encoded_size


def write_indirect(writer, number, contents):
    offset = writer.offset
    writer.write(f"{number} 0 obj\n".encode("ascii"))
    writer.write(contents)
    writer.write(b"\nendobj\n")
    return offset


def xref_entry(entry_type, field2, field3):
    return bytes([entry_type]) + field2.to_bytes(8, "big") + field3.to_bytes(2, "big")


def build_fixture(
    path,
    filter_name="raw",
    kind="javascript",
    decoded_size=None,
    malformed=False,
    encryption="none",
):
    if encryption not in ("none", "rc4-r2"):
        raise ValueError(f"unsupported encryption: {encryption}")
    if malformed and encryption != "none":
        raise ValueError("--malformed is not supported with encryption")
    layout = object_stream_layout(kind, decoded_size, malformed)
    first = len(layout[0])
    actual_decoded_size = sum(len(chunk) for chunk in decoded_chunks(layout))
    object_count = layout[-1]
    encoded_spool = None
    security = standard_r2_security() if encryption == "rc4-r2" else None

    if filter_name == "raw":
        encoded_size = actual_decoded_size
        filter_dictionary = b""
    else:
        encoded_spool, encoded_size = spool_encoded(layout, filter_name)
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
            encoded_hash = hashlib.sha256()
            stream_cipher = (
                RC4(rc4_object_key(security["file_key"], 3))
                if security is not None
                else None
            )

            def write_stream_chunk(chunk):
                if stream_cipher is not None:
                    chunk = stream_cipher.apply(chunk)
                writer.write(chunk)
                encoded_hash.update(chunk)

            if encoded_spool is None:
                for chunk in decoded_chunks(layout):
                    write_stream_chunk(chunk)
            else:
                while True:
                    chunk = encoded_spool.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    write_stream_chunk(chunk)
            writer.write(b"\nendstream\nendobj\n")
            encoded_sha256 = encoded_hash.hexdigest()

            content = b"q\nQ\n"
            if security is not None:
                content = rc4(
                    content, rc4_object_key(security["file_key"], 6)
                )
            offsets[6] = write_indirect(
                writer,
                6,
                f"<< /Length {len(content)} >>\nstream\n".encode("ascii")
                + content
                + b"\nendstream",
            )
            if security is not None:
                encryption_dictionary = (
                    b"<< /Filter /Standard /V 1 /R 2 /Length 40 "
                    + f"/O <{security['owner'].hex().upper()}> ".encode("ascii")
                    + f"/U <{security['user'].hex().upper()}> ".encode("ascii")
                    + f"/P {security['permissions']} >>".encode("ascii")
                )
                offsets[7] = write_indirect(writer, 7, encryption_dictionary)
            offsets[4] = writer.offset
            xref_entries = [xref_entry(0, 0, 65535)]
            xref_entries.extend(xref_entry(1, offsets[number], 0) for number in range(1, 5))
            xref_entries.append(xref_entry(2, 3, 0))
            xref_entries.append(xref_entry(1, offsets[6], 0))
            if malformed:
                xref_entries.extend((xref_entry(2, 3, 1), xref_entry(2, 3, 2)))
            elif security is not None:
                xref_entries.extend((xref_entry(1, offsets[7], 0), xref_entry(0, 0, 0)))
            else:
                xref_entries.extend((xref_entry(0, 0, 0), xref_entry(0, 0, 0)))
            xref = b"".join(xref_entries)
            trailer_dictionary = b""
            if security is not None:
                file_id_hex = security["file_id"].hex().upper()
                trailer_dictionary = (
                    f" /Encrypt 7 0 R /ID [<{file_id_hex}> <{file_id_hex}>]".encode(
                        "ascii"
                    )
                )
            xref_dictionary = (
                f"4 0 obj\n<< /Type /XRef /Size 9 /Root 1 0 R "
                f"/W [1 8 2] /Index [0 9] /Length {len(xref)}".encode("ascii")
                + trailer_dictionary
                + b" >>\nstream\n"
            )
            writer.write(xref_dictionary)
            writer.write(xref)
            writer.write(b"\nendstream\nendobj\nstartxref\n")
            writer.write(f"{offsets[4]}\n%%EOF\n".encode("ascii"))

            result = {
                "decoded_size": actual_decoded_size,
                "encoded_sha256": encoded_sha256,
                "encoded_size": encoded_size,
                "encryption": encryption,
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
            if security is not None:
                result["file_id"] = security["file_id"].hex()
                result["file_key_sha256"] = hashlib.sha256(
                    security["file_key"]
                ).hexdigest()
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
    parser.add_argument("--encryption", choices=("none", "rc4-r2"), default="none")
    args = parser.parse_args()

    result = build_fixture(
        args.output,
        filter_name=args.filter,
        kind=args.kind,
        decoded_size=args.decoded_size,
        malformed=args.malformed,
        encryption=args.encryption,
    )
    for key in sorted(result):
        print(f"{key}={result[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
