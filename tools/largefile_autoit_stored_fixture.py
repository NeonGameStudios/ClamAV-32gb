#!/usr/bin/env python3
"""Create a minimal stored EA05 member for bounded-output regression tests."""

import struct
import sys


class AutoItMT:
    def __init__(self, seed):
        self.mt = [0] * 624
        self.mt[0] = seed & 0xFFFFFFFF
        for i in range(1, 624):
            self.mt[i] = (i + 0x6C078965 * ((self.mt[i - 1] >> 30) ^ self.mt[i - 1])) & 0xFFFFFFFF
        self.items = 1
        self.index = 0

    def next_byte(self):
        self.items -= 1
        if self.items == 0:
            self.items = 624
            self.index = 0
            for i in range(227):
                self.mt[i] = ((((self.mt[i] ^ self.mt[i + 1]) & 0x7FFFFFFE) ^ self.mt[i]) >> 1) ^ (
                    (-(self.mt[i + 1] & 1)) & 0x9908B0DF
                ) ^ self.mt[i + 397]
            for i in range(227, 623):
                self.mt[i] = ((((self.mt[i] ^ self.mt[i + 1]) & 0x7FFFFFFE) ^ self.mt[i]) >> 1) ^ (
                    (-(self.mt[i + 1] & 1)) & 0x9908B0DF
                ) ^ self.mt[i - 227]
            self.mt[623] = ((((self.mt[623] ^ self.mt[0]) & 0x7FFFFFFE) ^ self.mt[623]) >> 1) ^ (
                (-(self.mt[0] & 1)) & 0x9908B0DF
            ) ^ self.mt[396]

        value = self.mt[self.index]
        self.index += 1
        value ^= value >> 11
        value ^= (value & 0xFF3A58AD) << 7
        value ^= (value & 0xFFFFDF8C) << 15
        value ^= value >> 18
        return (value >> 1) & 0xFF


def build_fixture(compressed):
    prefix = bytes(
        [
            0xA3,
            0x48,
            0x4B,
            0xBE,
            0x98,
            0x6C,
            0x4A,
            0xA9,
            0x99,
            0x4C,
            0x53,
            0x0A,
            0x86,
            0xD6,
            0x48,
            0x7D,
            0x41,
            0x55,
            0x33,
            0x21,
            0x45,
            0x41,
            0x30,
        ]
    )
    payload = b"ABCD"
    result = bytearray(prefix + bytes([0x35]) + bytes(16))
    result += struct.pack("<III", 0xCEB06DFF, 0x29BC, 0x29AC)
    if compressed:
        bits = []
        for value in payload:
            bits.append(0)
            bits.extend((value >> shift) & 1 for shift in range(7, -1, -1))
        bits.extend([0] * ((-len(bits)) % 16))
        compressed_bits = bytes(
            sum(bits[index + bit] << (7 - bit) for bit in range(8))
            for index in range(0, len(bits), 8)
        )
        decoded = b"EA05" + struct.pack(">I", len(payload)) + compressed_bits
        mt = AutoItMT(0x22AF)
        stored = bytes(value ^ mt.next_byte() for value in decoded)
    else:
        mt = AutoItMT(0x22AF)
        stored = bytes(value ^ mt.next_byte() for value in payload)

    metadata = bytearray(29)
    metadata[0] = 1 if compressed else 0
    struct.pack_into("<I", metadata, 1, len(stored) ^ 0x45AA)
    result += metadata
    result += stored
    return bytes(result)


if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[1] != "--compressed"):
    raise SystemExit(f"usage: {sys.argv[0]} [--compressed] OUTPUT")

with open(sys.argv[-1], "wb") as fixture:
    fixture.write(build_fixture(len(sys.argv) == 3))
