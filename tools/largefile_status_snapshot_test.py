#!/usr/bin/env python3
"""Deterministic controls using the real shared gate on tiny test manifests."""

import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock
import sys

sys.dont_write_bytecode = True
import largefile_status_snapshot as snapshot

SOURCE_REPO = Path(__file__).resolve().parents[1]
HEADER = "kind\tid\tstatus\tsource\tevidence_or_required_work\n"


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="snapshot-test-")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        (self.root / "tools").mkdir()
        for name in ("largefile_release_readiness.sh", "largefile_unsupported_allowlist.sh"):
            shutil.copyfile(SOURCE_REPO / "tools" / name, self.root / "tools" / name)
        self.manifest = self.root / "manifest.tsv"

    def status(self, body):
        self.manifest.write_text(HEADER + body, encoding="utf-8")
        return snapshot.read_status(self.root, self.manifest)

    def mixed(self):
        return self.status(
            "library\tqualified-example\tqualified\tx.c\trelease_evidence=test:/unused source_manifest_sha256=" + "0" * 64 + "\n"
            "parser\tenabled\tpending\tx.c\twork\n"
            "parser\trequired\tunsupported\tx.c\twork\n"
            "matcher\tbounded-example\tbounded\tx.c\twork\n"
            "unsupported\tmacos-first-release\tunsupported\tx.c\tout of first target\n"
        )

    def test_mixed_statuses_use_shared_semantics(self):
        counts = self.mixed()
        self.assertEqual([counts[key] for key in snapshot.COUNT_KEYS], [5, 1, 1, 1, 2, 1, 3, 2])
        self.assertEqual(counts["parser_total"], 2)
        self.assertEqual(counts["parser_unsupported"], 1)
        self.assertEqual(counts["release_readiness"], "blocked")

    def test_unknown_deliberate_exclusion_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "unapproved deliberate unsupported"):
            self.status("unsupported\tarbitrary-parser\tunsupported\tx.c\twork\n")

    def test_allowlisted_id_does_not_exclude_required_kind(self):
        counts = self.status("parser\tmacos-first-release\tunsupported\tx.c\twork\n")
        self.assertEqual(counts["capability_blocked"], 1)
        self.assertEqual(counts["capability_unsupported_required"], 1)

    def test_malformed_manifest_rejected(self):
        for body in ("", "parser\tx\tunknown\tx.c\twork\n", "parser\tx\tpending\tx.c\n",
                     "parser\tx\tpending\tx.c\twork\n" * 2,
                     "library\tx\tqualified\tx.c\tno-bound-evidence\n"):
            with self.subTest(body=body), self.assertRaises(RuntimeError):
                self.status(body)

    def test_status_count_reader_rejects_wrong_row_width(self):
        fields = {
            "capability_total": "1",
            "capability_qualified": "0",
            "capability_bounded": "0",
            "capability_pending": "1",
            "capability_unsupported": "0",
            "capability_unsupported_required": "0",
            "capability_blocked": "1",
            "parser_blocked": "1",
            "release_readiness": "blocked",
        }
        result = mock.Mock(
            returncode=1,
            stdout="\n".join(f"{key}={value}" for key, value in fields.items()),
            stderr="",
        )
        self.manifest.write_text(
            HEADER + "parser\tx\tpending\tx.c\twork\textra\n", encoding="utf-8"
        )
        with mock.patch.object(snapshot.subprocess, "run", return_value=result), \
                self.assertRaisesRegex(ValueError, "expected 5"):
            snapshot.read_status(self.root, self.manifest)

    def test_invalid_header_rejected(self):
        self.manifest.write_text("invalid\nparser\tx\tpending\tx.c\twork\n")
        with self.assertRaises(RuntimeError):
            snapshot.read_status(self.root, self.manifest)

    def test_short_deterministic_render_distinguishes_enabled_parsers(self):
        counts = self.mixed()
        hashes = {name: "a" * 64 for name in snapshot.INPUT_PATHS}
        first = snapshot.render_snapshot(counts, hashes)
        self.assertEqual(first, snapshot.render_snapshot(counts, hashes))
        self.assertLessEqual(len(first.splitlines()), 80)
        self.assertIn("All parser rows blocked / total | 2 / 2", first)
        self.assertIn("Enabled parser rows blocked / total | 1 / 1", first)
        self.assertIn("Deliberate unsupported exclusions (allowlisted) | 1", first)
        self.assertIn("Counts alone do not establish release qualification", first)
        self.assertIn("maintained text, not generated findings", first)

    def test_freshness_check_and_output(self):
        saved = self.root / "snapshot.md"
        with mock.patch.object(snapshot, "generate", return_value="stable snapshot\n"), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(snapshot.main(["--check", str(saved)]), 1)
            self.assertEqual(snapshot.main(["--output", str(saved)]), 0)
            self.assertEqual(snapshot.main(["--check", str(saved)]), 0)
            saved.write_text("stale snapshot\n")
            self.assertEqual(snapshot.main(["--check", str(saved)]), 1)

    def test_provenance_changes_make_generation_fail(self):
        counts = self.mixed()
        hashes = {name: "a" * 64 for name in snapshot.INPUT_PATHS}
        with mock.patch.object(snapshot, "head_revision", side_effect=["a" * 40, "b" * 40]), \
                mock.patch.object(snapshot, "input_hashes", return_value=hashes), \
                mock.patch.object(snapshot, "read_status", return_value=counts):
            with self.assertRaisesRegex(RuntimeError, "inputs changed"):
                snapshot.generate(self.root)

    def test_gate_failure_is_not_rendered_as_a_status(self):
        self.manifest.write_text(HEADER + "parser\tx\tpending\tx.c\twork\n")
        failed = mock.Mock(returncode=2, stdout="capability_total=1\n", stderr="invalid capability")
        with mock.patch.object(snapshot.subprocess, "run", return_value=failed):
            with self.assertRaisesRegex(RuntimeError, "invalid capability"):
                snapshot.read_status(self.root, self.manifest)

    def test_commit_after_generation_does_not_stale_dashboard(self):
        """Tracked status text must not self-invalidate when Git HEAD advances."""
        repo = self.root / "git-repo"
        (repo / "tools").mkdir(parents=True)
        (repo / "docs").mkdir()
        (repo / "docs" / "largefile-capabilities.tsv").write_text(
            HEADER + "parser\tenabled\tpending\tx.c\twork\n", encoding="utf-8"
        )
        for name in ("largefile_release_readiness.sh", "largefile_unsupported_allowlist.sh"):
            (repo / "tools" / name).write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' "
                "'capability_total=1' 'capability_qualified=0' 'capability_bounded=0' "
                "'capability_pending=1' 'capability_unsupported=0' "
                "'capability_unsupported_required=0' 'capability_blocked=1' "
                "'parser_blocked=1' 'release_readiness=blocked'\n"
                "exit 1\n",
                encoding="utf-8",
            )
        for path in (repo / "tools").iterdir():
            path.chmod(0o755)
        environment = os.environ | {
            "GIT_AUTHOR_NAME": "snapshot-test",
            "GIT_AUTHOR_EMAIL": "snapshot-test@example.invalid",
            "GIT_COMMITTER_NAME": "snapshot-test",
            "GIT_COMMITTER_EMAIL": "snapshot-test@example.invalid",
        }
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "add", "."], cwd=repo, check=True, env=environment)
        subprocess.run(["git", "commit", "-q", "-m", "initial"], cwd=repo, check=True, env=environment)

        saved = repo / "snapshot.md"
        self.assertEqual(snapshot.main(["--repo", str(repo), "--output", str(saved)]), 0)
        subprocess.run(["git", "add", "snapshot.md"], cwd=repo, check=True, env=environment)
        subprocess.run(["git", "commit", "-q", "-m", "dashboard"], cwd=repo, check=True, env=environment)
        self.assertEqual(snapshot.main(["--repo", str(repo), "--check", str(saved)]), 0)

    def test_external_provenance_records_revision_without_polluting_dashboard(self):
        counts = self.mixed()
        hashes = {name: "a" * 64 for name in snapshot.INPUT_PATHS}
        with mock.patch.object(snapshot, "head_revision", return_value="b" * 40), \
                mock.patch.object(snapshot, "input_hashes", return_value=hashes), \
                mock.patch.object(snapshot, "read_status", return_value=counts):
            text, provenance = snapshot.collect(self.root)
        self.assertNotIn("b" * 40, text)
        self.assertEqual(provenance["source_revision"], "b" * 40)
        self.assertEqual(provenance["snapshot_sha256"], snapshot.hashlib.sha256(text.encode()).hexdigest())
        json.dumps(provenance)

    def test_generated_metadata_is_not_source_manifest_identity(self):
        """Promotion metadata must not create a source-manifest fixed point."""
        repo = self.root / "manifest-repo"
        (repo / "tools").mkdir(parents=True)
        (repo / "docs").mkdir()
        shutil.copyfile(
            SOURCE_REPO / "tools" / "largefile_source_manifest.sh",
            repo / "tools" / "largefile_source_manifest.sh",
        )
        (repo / "runtime.c").write_text("int runtime = 1;\n", encoding="utf-8")
        (repo / "32gb-current-snapshot.md").write_text("status one\n", encoding="utf-8")
        (repo / "docs" / "largefile-task-ledger.md").write_text("task one\n", encoding="utf-8")
        receipt_dir = repo / "docs" / "largefile-task-receipts"
        receipt_dir.mkdir()
        (receipt_dir / "task-one.md").write_text("receipt one\n", encoding="utf-8")
        environment = os.environ | {
            "GIT_AUTHOR_NAME": "snapshot-test",
            "GIT_AUTHOR_EMAIL": "snapshot-test@example.invalid",
            "GIT_COMMITTER_NAME": "snapshot-test",
            "GIT_COMMITTER_EMAIL": "snapshot-test@example.invalid",
        }
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "add", "."], cwd=repo, check=True, env=environment)
        subprocess.run(["git", "commit", "-q", "-m", "initial"], cwd=repo, check=True, env=environment)
        first = self.root / "manifest-one.txt"
        subprocess.run(
            ["sh", "tools/largefile_source_manifest.sh", str(repo), str(first)],
            cwd=repo,
            check=True,
        )
        (repo / "32gb-current-snapshot.md").write_text("status two\n", encoding="utf-8")
        (repo / "docs" / "largefile-task-ledger.md").write_text("task two\n", encoding="utf-8")
        (receipt_dir / "task-one.md").write_text("receipt two\n", encoding="utf-8")
        second = self.root / "manifest-two.txt"
        subprocess.run(
            ["sh", "tools/largefile_source_manifest.sh", str(repo), str(second)],
            cwd=repo,
            check=True,
        )
        self.assertEqual(first.read_text(encoding="utf-8"), second.read_text(encoding="utf-8"))
        (repo / "runtime.c").write_text("int runtime = 2;\n", encoding="utf-8")
        third = self.root / "manifest-three.txt"
        subprocess.run(
            ["sh", "tools/largefile_source_manifest.sh", str(repo), str(third)],
            cwd=repo,
            check=True,
        )
        self.assertNotEqual(second.read_text(encoding="utf-8"), third.read_text(encoding="utf-8"))

        (repo / "untracked-source.c").write_text("int untracked_source = 1;\n", encoding="utf-8")
        fourth = self.root / "manifest-four.txt"
        subprocess.run(
            ["sh", "tools/largefile_source_manifest.sh", str(repo), str(fourth)],
            cwd=repo,
            check=True,
        )
        self.assertNotEqual(third.read_text(encoding="utf-8"), fourth.read_text(encoding="utf-8"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--repo", type=Path, default=SOURCE_REPO)
    args, remaining = parser.parse_known_args()
    SOURCE_REPO = args.repo.resolve()
    unittest.main(argv=[sys.argv[0], *remaining], verbosity=2)
