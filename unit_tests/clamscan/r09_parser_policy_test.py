# Copyright (C) 2020-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run clamscan tests for recognized parser policy and raw-detection precedence.
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

    def test_recognized_parser_failures_keep_raw_detection_precedence(self):
        self.step_name('Test that recognized Python and AI-model parser failures stay visible without suppressing raw matches')

        signature_db = TC.path_tmp / 'r09-parser-policy.ndb'
        signature_db.write_text(
            'Python.Raw:0:8:50592d524157\n'
            'AI.Raw:0:13:41492d524157\n'
        )

        cases = [
            (
                'python',
                b'\x42\x0d\x0d\x0a\x00\x00\x00\x00',
                b'\x42\x0d\x0d\x0a\x00\x00\x00\x00PY-RAW',
                'Python.Raw.UNOFFICIAL FOUND',
                'Python compiled bytecode is malformed or unsupported',
            ),
            (
                'ai',
                b'\x08\x01\x12\x09onnx-tool',
                b'\x08\x01\x12\x09onnx-toolAI-RAW',
                'AI.Raw.UNOFFICIAL FOUND',
                'ONNX ModelProto is missing a required field',
            ),
        ]

        for label, clean_data, detected_data, detection, diagnostic in cases:
            clean_file = TC.path_tmp / '{}-clean'.format(label)
            clean_file.write_bytes(clean_data)
            command = '{valgrind} {valgrind_args} {clamscan} -d {database} {testfile}'.format(
                valgrind=TC.valgrind, valgrind_args=TC.valgrind_args,
                clamscan=TC.clamscan,
                database=signature_db,
                testfile=clean_file,
            )
            output = self.execute_command(command)

            assert output.ec == 2  # recognized malformed input is not clean
            self.verify_output(
                output.out,
                expected=[
                    "Can't parse data ERROR",
                    'Scanned files: 0',
                    'Infected files: 0',
                    'Total errors: 1',
                ],
            )
            self.verify_output(output.err, expected=[diagnostic])

            detected_file = TC.path_tmp / '{}-detected'.format(label)
            detected_file.write_bytes(detected_data)
            command = '{valgrind} {valgrind_args} {clamscan} -d {database} {testfile}'.format(
                valgrind=TC.valgrind, valgrind_args=TC.valgrind_args,
                clamscan=TC.clamscan,
                database=signature_db,
                testfile=detected_file,
            )
            output = self.execute_command(command)

            assert output.ec == 1  # raw detection takes precedence
            self.verify_output(
                output.out,
                expected=[
                    detection,
                    'Scanned files: 1',
                    'Infected files: 1',
                ],
            )

