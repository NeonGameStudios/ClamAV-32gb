# Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""Exercise the production-linked UnRAR backend through clamscan."""

import binascii
import hashlib
import os
import struct
import sys
import unittest

sys.path.append('../unit_tests')
import testcase


def _rar_header(body):
    """Build a RAR 4.x header with the format's 16-bit header CRC."""
    # UnRAR's CRC32 helper starts from 0xffffffff and complements the
    # accumulator before retaining the low 16 bits.  binascii.crc32() already
    # applies that standard initialization/complement convention when called
    # without an explicit seed.
    crc = binascii.crc32(body) & 0xFFFF
    return struct.pack('<H', crc) + body


def _minimal_rar(payload):
    """Return a valid stored RAR 4.x archive containing one member."""
    signature = b'Rar!\x1a\x07\x00'
    main = struct.pack('<BHHHL', 0x73, 0, 13, 0, 0)
    name = b'child.bin'
    file_header = struct.pack(
        '<BHHIIBIIBBHI',
        0x74,
        0,
        32 + len(name),
        len(payload),
        len(payload),
        3,
        binascii.crc32(payload) & 0xFFFFFFFF,
        0,
        0x14,
        0x30,
        len(name),
        0,
    ) + name
    end = struct.pack('<BHH', 0x7B, 0, 7)
    return signature + _rar_header(main) + _rar_header(file_header) + payload + _rar_header(end)


class TC(testcase.TestCase):
    @classmethod
    def setUpClass(cls):
        super(TC, cls).setUpClass()
        if not os.environ.get('LIBCLAMUNRARIFACE'):
            raise unittest.SkipTest('UnRAR backend is not enabled in this build')

    @classmethod
    def tearDownClass(cls):
        super(TC, cls).tearDownClass()

    def setUp(self):
        super(TC, self).setUp()

    def tearDown(self):
        super(TC, self).tearDown()
        self.verify_valgrind_log()

    def test_rar_and_rarsfx_extract_nested_member(self):
        self.step_name('Verify production UnRAR extraction for RAR and RAR-SFX')

        payload = b'RarPayload'
        rar = TC.path_tmp / 'minimal.rar'
        rarsfx = TC.path_tmp / 'minimal-sfx.exe'
        database = TC.path_tmp / 'rar.hdb'
        archive = _minimal_rar(payload)
        rar.write_bytes(archive)
        rarsfx.write_bytes(b'SFX-STUB-QUALIFICATION\x00' + archive)
        database.write_text(
            '{}:{}:RarChild\n'.format(hashlib.sha256(payload).hexdigest(), len(payload))
        )

        command = '{valgrind} {valgrind_args} {clamscan} -d {database} --allmatch {rar} {rarsfx}'.format(
            valgrind=TC.valgrind,
            valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            database=database,
            rar=rar,
            rarsfx=rarsfx,
        )
        output = self.execute_command(command)

        assert output.ec == 1
        self.verify_output(
            output.out,
            expected=[
                'minimal.rar: RarChild.UNOFFICIAL FOUND',
                'minimal-sfx.exe: RarChild.UNOFFICIAL FOUND',
            ],
        )


if __name__ == '__main__':
    unittest.main()
