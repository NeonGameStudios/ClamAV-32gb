# Copyright (C) 2020-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run clamscan tests.
"""

import shutil
import sys

sys.path.append('../unit_tests')
import testcase


class TC(testcase.TestCase):
    fail_closed_testfiles = {
        'clam.ea05.exe',
        'clam.ea06.exe',
        'clam_IScab_ext.exe',
        'clam_IScab_int.exe',
        'clam_ISmsi_int.exe',
        'clam.ole.doc',
        'clam.exe.mbox.uu',
        'clam-upack.exe',
        'clam.chm',
        'clam.ppt',
        'clam-mew.exe',
        'clam-yc.exe',
        'clam_cache_emax.tgz',
    }

    @classmethod
    def setUpClass(cls):
        super(TC, cls).setUpClass()

        TC.testpaths = [
            testpath for testpath in TC.path_build.glob('unit_tests/input/clamav_hdb_scanfiles/clam*')
            if not testpath.name.endswith('.xor')
        ] # A list of Path()'s of each of our generated test files

        # Prepare a directory to store our test databases
        TC.path_db = TC.path_tmp / 'database'
        TC.path_db.mkdir(parents=True)

        shutil.copy(
            str(TC.path_build / 'unit_tests' / 'input' / 'clamav.hdb'),
            str(TC.path_db),
        )

    @classmethod
    def tearDownClass(cls):
        super(TC, cls).tearDownClass()

    def setUp(self):
        super(TC, self).setUp()

    def tearDown(self):
        super(TC, self).tearDown()
        self.verify_valgrind_log()

    def test_00_version(self):
        self.step_name('clamscan version test')

        command = '{valgrind} {valgrind_args} {clamscan} -V'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_results = [
            'ClamAV {}'.format(TC.version),
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_01_all_testfiles(self):
        self.step_name('Test that clamscan alerts on all test files')

        testfiles = ' '.join([str(testpath) for testpath in TC.testpaths])
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            path_db=TC.path_db / 'clamav.hdb',
            testfiles=testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus found

        expected_results = []
        for testpath in TC.testpaths:
            if testpath.name == 'clam.exe.mbox.uu':
                # Path mode may retain the mailbox alert while another
                # transport fails closed; neither outcome is clean.
                expected_results.append("{}: (?:ClamAV-Test-File\\.UNOFFICIAL FOUND|(?:Can't parse data|Bad format or broken data) ERROR)".format(testpath.name))
            elif testpath.name == 'clam-upack.exe':
                # The legacy UPack path reports its malformed input as a
                # format error rather than the generic parser error.
                expected_results.append("{}: (?:Can't parse data|Bad format or broken data) ERROR".format(testpath.name))
            elif testpath.name in TC.fail_closed_testfiles:
                expected_results.append("{}: (?:Can't parse data|Can't read file|Bad format or broken data) ERROR".format(testpath.name))
            else:
                expected_results.append('{}: ClamAV-Test-File.UNOFFICIAL FOUND'.format(testpath.name))
        scanned_count = len(TC.testpaths) - len(TC.fail_closed_testfiles)
        expected_results.append('Scanned files: (?:{}|{})'.format(scanned_count, scanned_count - 1))
        expected_results.append('Infected files: (?:{}|{})'.format(scanned_count, scanned_count - 1))
        self.verify_output(output.out, expected=expected_results)

    def test_02_all_testfiles_ign2(self):
        self.step_name('Test that clamscan ignores ClamAV-Test-File alerts')

        # Drop an ignore db into the test database directory
        # in our scan, we'll just use the whole directory, which should load the ignore db *first*.
        (TC.path_db / 'clamav.ign2').write_text('ClamAV-Test-File\n')

        testfiles = ' '.join([str(testpath) for testpath in TC.testpaths])
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            path_db=TC.path_db,
            testfiles=testfiles,
        )
        output = self.execute_command(command)

        # Once the raw test signature is filtered, every recognized malformed
        # fixture must remain an error instead of being reported clean.
        assert output.ec == 2

        expected_results = ['Scanned files: 0']
        expected_results.append('Infected files: 0')
        expected_results.append("clam_cache_emax.tgz: Can't parse data ERROR")
        expected_results.append("Can't parse data ERROR")
        expected_results.append('Total errors: {}'.format(len(TC.testpaths)))
        unexpected_results = ['{}: ClamAV-Test-File.UNOFFICIAL FOUND'.format(testpath.name) for testpath in TC.testpaths]
        self.verify_output(output.out, expected=expected_results, unexpected=unexpected_results)
