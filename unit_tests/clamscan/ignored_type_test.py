# Copyright (C) 2020-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run clamscan tests for classifier-only ignored file types.
"""

import sys

sys.path.append('../unit_tests')
import testcase


class TC(testcase.TestCase):
    @classmethod
    def setUpClass(cls):
        super(TC, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TC, cls).tearDownClass()

    def setUp(self):
        super(TC, self).setUp()

    def tearDown(self):
        super(TC, self).tearDown()
        self.verify_valgrind_log()

    def test_ignored_type_preserves_raw_matching_and_fail_visible_status(self):
        self.step_name('Test that an ignored classifier type keeps raw matching and never reports clean')

        signature_db = TC.path_tmp / 'ignored-type.ndb'
        signature_db.write_text(
            'Ignored.Raw:0:*:494433434c414d41562d49474e4f5245442d524157\n'
        )

        detected_file = TC.path_tmp / 'ignored-detected.mp3'
        detected_file.write_bytes(b'ID3CLAMAV-IGNORED-RAW')

        command = '{valgrind} {valgrind_args} {clamscan} -d {database} {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            database=signature_db,
            testfile=detected_file,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # raw virus detection takes precedence
        self.verify_output(
            output.out,
            expected=[
                'Ignored.Raw.UNOFFICIAL FOUND',
                'Scanned files: 1',
                'Infected files: 1',
            ],
        )
        self.verify_output(
            output.err,
            expected=['recognized ignored file type parser is unsupported'],
        )

        clean_file = TC.path_tmp / 'ignored-clean.mp3'
        clean_file.write_bytes(b'ID3CLAMAV-IGNORED-CLEAN')
        command = '{valgrind} {valgrind_args} {clamscan} -d {database} {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            database=signature_db,
            testfile=clean_file,
        )
        output = self.execute_command(command)

        assert output.ec == 2  # recognized unsupported input is not clean
        self.verify_output(
            output.out,
            expected=[
                "Can't parse data ERROR",
                'Scanned files: 0',
                'Infected files: 0',
                'Total errors: 1',
            ],
        )
        self.verify_output(
            output.err,
            expected=['recognized ignored file type parser is unsupported'],
        )

