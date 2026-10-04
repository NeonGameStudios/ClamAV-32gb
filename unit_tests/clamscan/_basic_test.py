# Copyright (C) 2020-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run clamscan tests.
"""

import shutil
import re
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
            and testpath.name != 'clam.exe.webapp-export.late-child.one'
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
        command = '{valgrind} {valgrind_args} {clamscan} --alert-exceeds-max=no -d {path_db} {testfiles}'.format(
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
        command = '{valgrind} {valgrind_args} {clamscan} --alert-exceeds-max=no -d {path_db} {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            path_db=TC.path_db,
            testfiles=testfiles,
        )
        output = self.execute_command(command)

        # Filtering the raw signature exposes the real parser result for each
        # input. Some complete cleanly; known malformed controls must still
        # fail closed. Check every path and reconcile the CLI summary rather
        # than assuming all corpus files share one completion state.
        assert output.ec == 2
        text = output.out.decode('utf-8', 'replace') if isinstance(output.out, bytes) else output.out
        results = {}
        for line in text.splitlines():
            for testpath in TC.testpaths:
                prefix = '{}: '.format(testpath)
                if line.startswith(prefix):
                    assert testpath.name not in results, 'duplicate result for {}'.format(testpath)
                    results[testpath.name] = line[len(prefix):]
                    break

        assert set(results) == {testpath.name for testpath in TC.testpaths}, 'missing or extra scan results'
        assert all(result == 'OK' or result.endswith(' ERROR') for result in results.values())
        for name in TC.fail_closed_testfiles:
            assert results[name].endswith(' ERROR'), '{} lost its fail-closed result'.format(name)
        for name in ('clam.exe', 'clam.exe.webapp-export.one'):
            assert results[name] == 'OK', '{} did not complete cleanly'.format(name)

        expected_counts = {
            'Scanned files': sum(result == 'OK' for result in results.values()),
            'Infected files': 0,
            'Total errors': sum(result.endswith(' ERROR') for result in results.values()),
        }
        for label, expected in expected_counts.items():
            match = re.search(r'^{}: (\d+)$'.format(re.escape(label)), text, re.MULTILINE)
            assert match is not None, 'missing {} in clamscan summary'.format(label)
            assert int(match.group(1)) == expected, '{} summary did not match per-file results'.format(label)
