#!/usr/bin/env python3
"""Generate deterministic PDF 1.7 object-stream qualification fixtures."""

import argparse
import binascii
import hashlib
import os
import shutil
import subprocess
import tempfile
import zlib


MARKER = b"CLAMAV-PDF-OBJSTM-TAIL-MARKER"
CHUNK_SIZE = 1024 * 1024
PASSWORD_PADDING = bytes.fromhex(
    "28BF4E5E4E758A4164004E56FFFA0108"
    "2E2E00B6D0683E802F0CA9FE6453697A"
)
FILE_ID = hashlib.md5(b"ClamAV deterministic encrypted object stream").digest()
QUALIFICATION_PASSWORD = b"clamav-qualification-password"


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


def gf_multiply(left, right):
    result = 0
    for _ in range(8):
        if right & 1:
            result ^= left
        left = ((left << 1) ^ (0x11B if left & 0x80 else 0)) & 0xFF
        right >>= 1
    return result


def gf_power(value, exponent):
    result = 1
    while exponent:
        if exponent & 1:
            result = gf_multiply(result, value)
        value = gf_multiply(value, value)
        exponent >>= 1
    return result


def rotate_byte(value, count):
    return ((value << count) | (value >> (8 - count))) & 0xFF


def make_aes_sbox():
    values = []
    for value in range(256):
        inverse = gf_power(value, 254) if value else 0
        values.append(
            inverse
            ^ rotate_byte(inverse, 1)
            ^ rotate_byte(inverse, 2)
            ^ rotate_byte(inverse, 3)
            ^ rotate_byte(inverse, 4)
            ^ 0x63
        )
    return tuple(values)


AES_SBOX = make_aes_sbox()
AES_INV_SBOX = tuple(AES_SBOX.index(value) for value in range(256))
AES_MULTIPLY = {
    factor: tuple(gf_multiply(factor, value) for value in range(256))
    for factor in (2, 3, 9, 11, 13, 14)
}


class AES:
    def __init__(self, key):
        if len(key) not in (16, 32):
            raise ValueError("AES key must be exactly 16 or 32 bytes")
        key_words = len(key) // 4
        self.rounds = key_words + 6
        words = [list(key[offset : offset + 4]) for offset in range(0, len(key), 4)]
        rcon = 1
        for index in range(key_words, 4 * (self.rounds + 1)):
            temporary = words[index - 1][:]
            if index % key_words == 0:
                temporary = temporary[1:] + temporary[:1]
                temporary = [AES_SBOX[value] for value in temporary]
                temporary[0] ^= rcon
                rcon = gf_multiply(rcon, 2)
            elif key_words > 6 and index % key_words == 4:
                temporary = [AES_SBOX[value] for value in temporary]
            words.append(
                [
                    words[index - key_words][column] ^ temporary[column]
                    for column in range(4)
                ]
            )
        self.round_keys = [
            bytes(sum(words[round_number * 4 : round_number * 4 + 4], []))
            for round_number in range(self.rounds + 1)
        ]

    @staticmethod
    def add_round_key(state, round_key):
        return bytearray(value ^ key for value, key in zip(state, round_key))

    @staticmethod
    def substitute(state, table):
        return bytearray(table[value] for value in state)

    @staticmethod
    def shift_rows(state, inverse=False):
        output = bytearray(16)
        for row in range(4):
            for column in range(4):
                source_column = (column - row) % 4 if inverse else (column + row) % 4
                output[4 * column + row] = state[4 * source_column + row]
        return output

    @staticmethod
    def mix_columns(state, inverse=False):
        output = bytearray(16)
        matrix = (
            ((14, 11, 13, 9), (9, 14, 11, 13), (13, 9, 14, 11), (11, 13, 9, 14))
            if inverse
            else ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2))
        )
        for column in range(4):
            source = state[4 * column : 4 * column + 4]
            for row in range(4):
                value = 0
                for item in range(4):
                    factor = matrix[row][item]
                    value ^= (
                        source[item]
                        if factor == 1
                        else AES_MULTIPLY[factor][source[item]]
                    )
                output[4 * column + row] = value
        return output

    def encrypt_block(self, block):
        if len(block) != 16:
            raise ValueError("AES block must be exactly 16 bytes")
        state = self.add_round_key(bytearray(block), self.round_keys[0])
        for round_number in range(1, self.rounds):
            state = self.substitute(state, AES_SBOX)
            state = self.shift_rows(state)
            state = self.mix_columns(state)
            state = self.add_round_key(state, self.round_keys[round_number])
        state = self.substitute(state, AES_SBOX)
        state = self.shift_rows(state)
        return bytes(self.add_round_key(state, self.round_keys[self.rounds]))

    def decrypt_block(self, block):
        if len(block) != 16:
            raise ValueError("AES block must be exactly 16 bytes")
        state = self.add_round_key(bytearray(block), self.round_keys[self.rounds])
        for round_number in range(self.rounds - 1, 0, -1):
            state = self.shift_rows(state, inverse=True)
            state = self.substitute(state, AES_INV_SBOX)
            state = self.add_round_key(state, self.round_keys[round_number])
            state = self.mix_columns(state, inverse=True)
        state = self.shift_rows(state, inverse=True)
        state = self.substitute(state, AES_INV_SBOX)
        return bytes(self.add_round_key(state, self.round_keys[0]))


class AES128(AES):
    def __init__(self, key):
        if len(key) != 16:
            raise ValueError("AES-128 key must be exactly 16 bytes")
        super().__init__(key)


class AES256(AES):
    def __init__(self, key):
        if len(key) != 32:
            raise ValueError("AES-256 key must be exactly 32 bytes")
        super().__init__(key)


class AESCBCEncryptor:
    def __init__(self, key, iv):
        if len(iv) != 16:
            raise ValueError("AES CBC IV must be exactly 16 bytes")
        self.aes = AES128(key) if len(key) == 16 else AES256(key)
        self.previous = iv
        self.buffer = bytearray()

    def update(self, data):
        self.buffer.extend(data)
        output = bytearray()
        while len(self.buffer) >= 16:
            block = bytes(self.buffer[:16])
            del self.buffer[:16]
            block = bytes(value ^ previous for value, previous in zip(block, self.previous))
            self.previous = self.aes.encrypt_block(block)
            output.extend(self.previous)
        return bytes(output)

    def finalize(self):
        padding = 16 - len(self.buffer)
        return self.update(bytes([padding]) * padding)


def aes_cbc_decrypt(data, key, iv):
    output = aes_cbc_decrypt_no_padding(data, key, iv)
    if not output or output[-1] == 0 or output[-1] > 16:
        raise ValueError("AES CBC plaintext has invalid PKCS#7 padding")
    padding = output[-1]
    if output[-padding:] != bytes([padding]) * padding:
        raise ValueError("AES CBC plaintext has invalid PKCS#7 padding")
    return output[:-padding]


def aes_cbc_encrypt_no_padding(data, key, iv):
    if len(data) % 16:
        raise ValueError("AES CBC plaintext is not block aligned")
    encryptor = AESCBCEncryptor(key, iv)
    output = encryptor.update(data)
    if encryptor.buffer:
        raise RuntimeError("AES CBC no-padding encryptor retained input")
    return output


def aes_cbc_decrypt_no_padding(data, key, iv):
    if len(data) % 16:
        raise ValueError("AES CBC ciphertext is not block aligned")
    aes = AES128(key) if len(key) == 16 else AES256(key)
    previous = iv
    output = bytearray()
    for offset in range(0, len(data), 16):
        ciphertext = data[offset : offset + 16]
        plaintext = aes.decrypt_block(ciphertext)
        output.extend(value ^ prior for value, prior in zip(plaintext, previous))
        previous = ciphertext
    return bytes(output)


def pad_pdf_password(password):
    return (password + PASSWORD_PADDING)[:32]


def standard_r2_security(user_password=b""):
    permissions = -4
    owner_password = b"" if not user_password else b"ClamAV deterministic owner password"
    user_padded = pad_pdf_password(user_password)
    owner_key = hashlib.md5(pad_pdf_password(owner_password)).digest()[:5]
    owner = rc4(user_padded, owner_key)
    key_input = (
        user_padded
        + owner
        + (permissions & 0xFFFFFFFF).to_bytes(4, "little")
        + FILE_ID
    )
    file_key = hashlib.md5(key_input).digest()[:5]
    user = rc4(PASSWORD_PADDING, file_key)
    return {
        "cipher": "rc4",
        "file_id": FILE_ID,
        "file_key": file_key,
        "owner": owner,
        "permissions": permissions,
        "user": user,
    }


def standard_r4_security(user_password=b""):
    permissions = -4
    owner_password = b"" if not user_password else b"ClamAV deterministic owner password"
    user_padded = pad_pdf_password(user_password)
    digest = hashlib.md5(pad_pdf_password(owner_password)).digest()
    for _ in range(50):
        digest = hashlib.md5(digest).digest()
    owner_key = digest[:16]
    owner = rc4(user_padded, owner_key)
    for iteration in range(1, 20):
        owner = rc4(owner, bytes(value ^ iteration for value in owner_key))

    key_input = (
        user_padded
        + owner
        + (permissions & 0xFFFFFFFF).to_bytes(4, "little")
        + FILE_ID
    )
    digest = hashlib.md5(key_input).digest()
    for _ in range(50):
        digest = hashlib.md5(digest[:16]).digest()
    file_key = digest[:16]

    user = hashlib.md5(PASSWORD_PADDING + FILE_ID).digest()
    user = rc4(user, file_key)
    for iteration in range(1, 20):
        user = rc4(user, bytes(value ^ iteration for value in file_key))
    user += bytes(16)
    return {
        "cipher": "aesv2",
        "file_id": FILE_ID,
        "file_key": file_key,
        "owner": owner,
        "permissions": permissions,
        "user": user,
    }


def standard_r5_security(user_password=b""):
    permissions = -4
    file_key = hashlib.sha256(b"ClamAV deterministic AESV3 file key").digest()
    user_validation_salt = hashlib.sha256(
        b"ClamAV deterministic R5 user validation salt"
    ).digest()[:8]
    user_key_salt = hashlib.sha256(
        b"ClamAV deterministic R5 user key salt"
    ).digest()[:8]
    user = (
        hashlib.sha256(user_password + user_validation_salt).digest()
        + user_validation_salt
        + user_key_salt
    )
    user_encryption = aes_cbc_encrypt_no_padding(
        file_key,
        hashlib.sha256(user_password + user_key_salt).digest(),
        bytes(16),
    )

    owner_password = b"ClamAV deterministic owner password"
    owner_validation_salt = hashlib.sha256(
        b"ClamAV deterministic R5 owner validation salt"
    ).digest()[:8]
    owner_key_salt = hashlib.sha256(
        b"ClamAV deterministic R5 owner key salt"
    ).digest()[:8]
    owner = (
        hashlib.sha256(owner_password + owner_validation_salt + user).digest()
        + owner_validation_salt
        + owner_key_salt
    )
    owner_encryption = aes_cbc_encrypt_no_padding(
        file_key,
        hashlib.sha256(owner_password + owner_key_salt + user).digest(),
        bytes(16),
    )
    permissions_plaintext = (
        (permissions & 0xFFFFFFFF).to_bytes(4, "little")
        + bytes.fromhex("FFFFFFFF")
        + b"Tadb"
        + hashlib.sha256(b"ClamAV deterministic R5 permissions").digest()[:4]
    )
    encrypted_permissions = AES256(file_key).encrypt_block(permissions_plaintext)
    return {
        "cipher": "aesv3",
        "file_id": FILE_ID,
        "file_key": file_key,
        "owner": owner,
        "owner_encryption": owner_encryption,
        "permissions": permissions,
        "encrypted_permissions": encrypted_permissions,
        "user": user,
        "user_encryption": user_encryption,
    }


def rc4_object_key(file_key, object_number, generation=0):
    material = (
        file_key
        + object_number.to_bytes(3, "little")
        + generation.to_bytes(2, "little")
    )
    return hashlib.md5(material).digest()[: min(len(file_key) + 5, 16)]


def aesv2_object_key(file_key, object_number, generation=0):
    material = (
        file_key
        + object_number.to_bytes(3, "little")
        + generation.to_bytes(2, "little")
        + b"sAlT"
    )
    return hashlib.md5(material).digest()[: min(len(file_key) + 5, 16)]


def aesv2_iv(object_number, generation=0):
    return hashlib.sha256(
        b"ClamAV deterministic AESV2 IV"
        + object_number.to_bytes(4, "little")
        + generation.to_bytes(4, "little")
    ).digest()[:16]


def aesv2_encrypt(data, file_key, object_number, generation=0):
    iv = aesv2_iv(object_number, generation)
    encryptor = AESCBCEncryptor(
        aesv2_object_key(file_key, object_number, generation), iv
    )
    return iv + encryptor.update(data) + encryptor.finalize()


def aesv3_iv(object_number, generation=0):
    return hashlib.sha256(
        b"ClamAV deterministic AESV3 IV"
        + object_number.to_bytes(4, "little")
        + generation.to_bytes(4, "little")
    ).digest()[:16]


def aesv3_encrypt(data, file_key, object_number, generation=0):
    iv = aesv3_iv(object_number, generation)
    encryptor = AESCBCEncryptor(file_key, iv)
    return iv + encryptor.update(data) + encryptor.finalize()


def spool_aes_with_openssl(source, key, iv, cipher, plaintext_size, label):
    openssl = shutil.which("openssl")
    if openssl is None:
        return None
    destination = tempfile.TemporaryFile()
    source.seek(0)
    completed = subprocess.run(
        [
            openssl,
            "enc",
            cipher,
            "-e",
            "-nosalt",
            "-K",
            key.hex(),
            "-iv",
            iv.hex(),
        ],
        stdin=source,
        stdout=destination,
        stderr=subprocess.PIPE,
        check=False,
    )
    expected_size = ((plaintext_size // 16) + 1) * 16
    if completed.returncode != 0 or destination.tell() != expected_size:
        destination.close()
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"OpenSSL {label} fixture encryption failed: {detail}")
    destination.seek(0)
    return destination


def spool_aesv2_with_openssl(source, file_key, object_number, plaintext_size):
    return spool_aes_with_openssl(
        source,
        aesv2_object_key(file_key, object_number),
        aesv2_iv(object_number),
        "-aes-128-cbc",
        plaintext_size,
        "AESV2",
    )


def spool_aesv3_with_openssl(source, file_key, object_number, plaintext_size):
    return spool_aes_with_openssl(
        source,
        file_key,
        aesv3_iv(object_number),
        "-aes-256-cbc",
        plaintext_size,
        "AESV3",
    )


def spool_aes_with_python(source, key, iv):
    destination = tempfile.TemporaryFile()
    encryptor = AESCBCEncryptor(key, iv)
    source.seek(0)
    while True:
        chunk = source.read(CHUNK_SIZE)
        if not chunk:
            break
        destination.write(encryptor.update(chunk))
    destination.write(encryptor.finalize())
    destination.seek(0)
    return destination


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
    fault="none",
):
    if encryption not in (
        "none",
        "rc4-r2",
        "aesv2-r4",
        "aesv3-r5",
        "rc4-r2-password",
        "aesv2-r4-password",
        "aesv3-r5-password",
    ):
        raise ValueError(f"unsupported encryption: {encryption}")
    if malformed and encryption != "none":
        raise ValueError("--malformed is not supported with encryption")
    if fault not in ("none", "bad-cfm", "truncated-ciphertext", "bad-padding"):
        raise ValueError(f"unsupported fault: {fault}")
    if fault != "none" and (encryption != "aesv2-r4" or malformed):
        raise ValueError("encryption faults require a valid AESV2-R4 fixture")
    layout = object_stream_layout(kind, decoded_size, malformed)
    first = len(layout[0])
    actual_decoded_size = sum(len(chunk) for chunk in decoded_chunks(layout))
    object_count = layout[-1]
    encoded_spool = None
    aes_plaintext_spool = None
    aes_ciphertext_spool = None
    user_password = QUALIFICATION_PASSWORD if encryption.endswith("-password") else b""
    if encryption.startswith("rc4-r2"):
        security = standard_r2_security(user_password)
    elif encryption.startswith("aesv2-r4"):
        security = standard_r4_security(user_password)
    elif encryption.startswith("aesv3-r5"):
        security = standard_r5_security(user_password)
    else:
        security = None

    if filter_name == "raw":
        plaintext_encoded_size = actual_decoded_size
        filter_dictionary = b""
    else:
        encoded_spool, plaintext_encoded_size = spool_encoded(layout, filter_name)
        if filter_name == "flate":
            filter_dictionary = b" /Filter /FlateDecode"
        elif filter_name == "asciihex-flate":
            filter_dictionary = b" /Filter [/ASCIIHexDecode /FlateDecode]"
        else:
            raise ValueError(f"unsupported filter: {filter_name}")

    encoded_size = plaintext_encoded_size
    if security is not None and security["cipher"] in ("aesv2", "aesv3"):
        encoded_size = 16 + ((plaintext_encoded_size // 16) + 1) * 16
        aes_plaintext_spool = encoded_spool
        if aes_plaintext_spool is None:
            aes_plaintext_spool = tempfile.TemporaryFile()
            for chunk in decoded_chunks(layout):
                aes_plaintext_spool.write(chunk)
        if security["cipher"] == "aesv2":
            aes_ciphertext_spool = spool_aesv2_with_openssl(
                aes_plaintext_spool,
                security["file_key"],
                3,
                plaintext_encoded_size,
            )
        else:
            aes_ciphertext_spool = spool_aesv3_with_openssl(
                aes_plaintext_spool,
                security["file_key"],
                3,
                plaintext_encoded_size,
            )
        if fault in ("truncated-ciphertext", "bad-padding"):
            if aes_ciphertext_spool is None:
                stream_key = (
                    aesv2_object_key(security["file_key"], 3)
                    if security["cipher"] == "aesv2"
                    else security["file_key"]
                )
                stream_iv = (
                    aesv2_iv(3)
                    if security["cipher"] == "aesv2"
                    else aesv3_iv(3)
                )
                aes_ciphertext_spool = spool_aes_with_python(
                    aes_plaintext_spool, stream_key, stream_iv
                )
            ciphertext_size = encoded_size - 16
            if fault == "truncated-ciphertext":
                aes_ciphertext_spool.truncate(ciphertext_size - 1)
                encoded_size -= 1
            else:
                if ciphertext_size < 32:
                    raise ValueError("bad-padding fault requires two ciphertext blocks")
                corrupt_offset = ciphertext_size - 32 + 15
                aes_ciphertext_spool.seek(corrupt_offset)
                value = aes_ciphertext_spool.read(1)
                if len(value) != 1:
                    raise RuntimeError("AES padding fault offset is unavailable")
                aes_ciphertext_spool.seek(corrupt_offset)
                aes_ciphertext_spool.write(bytes([value[0] ^ 0xFF]))
            aes_ciphertext_spool.seek(0)

    try:
        with open(path, "wb") as raw_output:
            writer = HashedWriter(raw_output)
            writer.write(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
            offsets = {}
            catalog = b"<< /Type /Catalog /Pages 2 0 R >>"
            if security is not None and security["cipher"] == "aesv3":
                catalog = (
                    b"<< /Type /Catalog /Pages 2 0 R /Extensions "
                    b"<< /ADBE << /BaseVersion /1.7 /ExtensionLevel 3 >> >> >>"
                )
            offsets[1] = write_indirect(writer, 1, catalog)
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
                if security is not None and security["cipher"] == "rc4"
                else None
            )
            aes_encryptor = None
            if security is not None and security["cipher"] in ("aesv2", "aesv3"):
                stream_iv = (
                    aesv2_iv(3) if security["cipher"] == "aesv2" else aesv3_iv(3)
                )
                writer.write(stream_iv)
                encoded_hash.update(stream_iv)
                if aes_ciphertext_spool is None:
                    stream_key = (
                        aesv2_object_key(security["file_key"], 3)
                        if security["cipher"] == "aesv2"
                        else security["file_key"]
                    )
                    aes_encryptor = AESCBCEncryptor(
                        stream_key, stream_iv
                    )

            def write_stream_chunk(chunk):
                if stream_cipher is not None:
                    chunk = stream_cipher.apply(chunk)
                elif aes_encryptor is not None:
                    chunk = aes_encryptor.update(chunk)
                writer.write(chunk)
                encoded_hash.update(chunk)

            source_spool = aes_ciphertext_spool or encoded_spool
            if source_spool is None:
                for chunk in decoded_chunks(layout):
                    write_stream_chunk(chunk)
            else:
                while True:
                    chunk = source_spool.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    write_stream_chunk(chunk)
            if aes_encryptor is not None:
                final = aes_encryptor.finalize()
                writer.write(final)
                encoded_hash.update(final)
            writer.write(b"\nendstream\nendobj\n")
            encoded_sha256 = encoded_hash.hexdigest()

            content = b"q\nQ\n"
            if security is not None and security["cipher"] == "rc4":
                content = rc4(
                    content, rc4_object_key(security["file_key"], 6)
                )
            elif security is not None and security["cipher"] == "aesv2":
                content = aesv2_encrypt(content, security["file_key"], 6)
            elif security is not None and security["cipher"] == "aesv3":
                content = aesv3_encrypt(content, security["file_key"], 6)
            offsets[6] = write_indirect(
                writer,
                6,
                f"<< /Length {len(content)} >>\nstream\n".encode("ascii")
                + content
                + b"\nendstream",
            )
            if security is not None:
                if security["cipher"] == "rc4":
                    encryption_dictionary = (
                        b"<< /Filter /Standard /V 1 /R 2 /Length 40 "
                        + f"/O <{security['owner'].hex().upper()}> ".encode("ascii")
                        + f"/U <{security['user'].hex().upper()}> ".encode("ascii")
                        + f"/P {security['permissions']} >>".encode("ascii")
                    )
                elif security["cipher"] == "aesv2":
                    crypt_method = b"AESV2" if fault != "bad-cfm" else b"Bogus"
                    encryption_dictionary = (
                        b"<< /Filter /Standard /V 4 /R 4 /Length 128 "
                        + f"/O <{security['owner'].hex().upper()}> ".encode("ascii")
                        + f"/U <{security['user'].hex().upper()}> ".encode("ascii")
                        + f"/P {security['permissions']} /EncryptMetadata true ".encode("ascii")
                        + b"/CF << /StdCF << /Type /CryptFilter /CFM /"
                        + crypt_method
                        + b" "
                        + b"/AuthEvent /DocOpen /Length 16 >> >> "
                        + b"/StmF /StdCF /StrF /StdCF /EFF /StdCF >>"
                    )
                else:
                    encryption_dictionary = (
                        b"<< /Filter /Standard /V 5 /R 5 /Length 256 "
                        + f"/O <{security['owner'].hex().upper()}> ".encode("ascii")
                        + f"/U <{security['user'].hex().upper()}> ".encode("ascii")
                        + f"/OE <{security['owner_encryption'].hex().upper()}> ".encode("ascii")
                        + f"/UE <{security['user_encryption'].hex().upper()}> ".encode("ascii")
                        + f"/Perms <{security['encrypted_permissions'].hex().upper()}> ".encode("ascii")
                        + f"/P {security['permissions']} /EncryptMetadata true ".encode("ascii")
                        + b"/CF << /StdCF << /Type /CryptFilter /CFM /AESV3 "
                        + b"/AuthEvent /DocOpen /Length 32 >> >> "
                        + b"/StmF /StdCF /StrF /StdCF /EFF /StdCF >>"
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
                "credential": "nonempty" if user_password else "empty",
                "encoded_sha256": encoded_sha256,
                "encoded_size": encoded_size,
                "encryption": encryption,
                "fault": fault,
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
                if security["cipher"] == "aesv2":
                    result["object_stream_iv"] = aesv2_iv(3).hex()
                elif security["cipher"] == "aesv3":
                    result["object_stream_iv"] = aesv3_iv(3).hex()
                    result["perms_sha256"] = hashlib.sha256(
                        security["encrypted_permissions"]
                    ).hexdigest()
                else:
                    result["object_stream_iv"] = "none"
    except Exception:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        raise
    finally:
        if aes_ciphertext_spool is not None:
            aes_ciphertext_spool.close()
        if aes_plaintext_spool is not None and aes_plaintext_spool is not encoded_spool:
            aes_plaintext_spool.close()
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
    parser.add_argument(
        "--fault",
        choices=("none", "bad-cfm", "truncated-ciphertext", "bad-padding"),
        default="none",
    )
    parser.add_argument(
        "--encryption",
        choices=(
            "none",
            "rc4-r2",
            "aesv2-r4",
            "aesv3-r5",
            "rc4-r2-password",
            "aesv2-r4-password",
            "aesv3-r5-password",
        ),
        default="none",
    )
    args = parser.parse_args()

    result = build_fixture(
        args.output,
        filter_name=args.filter,
        kind=args.kind,
        decoded_size=args.decoded_size,
        malformed=args.malformed,
        encryption=args.encryption,
        fault=args.fault,
    )
    for key in sorted(result):
        print(f"{key}={result[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
