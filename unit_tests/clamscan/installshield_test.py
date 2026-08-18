# Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""Focused InstallShield compatibility tests."""

import shutil
import sys

sys.path.append('../unit_tests')
import testcase


class TC(testcase.TestCase):
    @classmethod
    def setUpClass(cls):
        super(TC, cls).setUpClass()

        TC.testfiles = [
            TC.path_build / 'unit_tests' / 'input' / 'clamav_hdb_scanfiles' / 'clam_IScab_ext.exe',
            TC.path_build / 'unit_tests' / 'input' / 'clamav_hdb_scanfiles' / 'clam_IScab_int.exe',
        ]
        TC.path_db = TC.path_tmp / 'database'
        TC.path_db.mkdir(parents=True)
        shutil.copy(TC.path_build / 'unit_tests' / 'input' / 'clamav.hdb', TC.path_db)
        (TC.path_db / 'clamav.ign2').write_text('ClamAV-Test-File\n')

    @classmethod
    def tearDownClass(cls):
        super(TC, cls).tearDownClass()

    def tearDown(self):
        super(TC, self).tearDown()
        self.verify_valgrind_log()

    def test_known_filename_layout_flags_are_accepted(self):
        self.step_name('Test known InstallShield filename-layout flags')

        command = '{valgrind} {valgrind_args} {clamscan} -d {database} {testfiles}'.format(
            valgrind=TC.valgrind,
            valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            database=TC.path_db,
            testfiles=' '.join(str(testfile) for testfile in TC.testfiles),
        )
        output = self.execute_command(command)

        assert output.ec == 2
        self.verify_output(
            output.out,
            expected=[
                "Can't parse data ERROR",
                'Scanned files: 0',
                'Infected files: 0',
                'Total errors: 2',
            ],
            unexpected=[' FOUND'],
        )
