#!/usr/bin/env python3
"""Render a short deterministic roadmap snapshot using the existing release gate.

Counts are labels from the capability manifest, not independent qualification.
The command exposes no test-manifest or release-policy override. Tests exercise
the gate's existing --test-manifest interface through read_status directly.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import largefile_acceptance_cases as acceptance_cases

COUNT_KEYS = (
    "capability_total", "capability_qualified", "capability_bounded",
    "capability_pending", "capability_unsupported", "capability_unsupported_required",
    "capability_blocked", "parser_blocked",
)
INPUT_PATHS = (
    "docs/largefile-capabilities.tsv",
    "tools/largefile_release_readiness.sh",
    "tools/largefile_unsupported_allowlist.sh",
)


def read_status(repo: Path, test_manifest: Path | None = None) -> dict:
    """Delegate manifest validation and exclusion semantics to the shared gate."""
    command = ["sh", str(repo / "tools/largefile_release_readiness.sh"), "--status"]
    manifest = repo / INPUT_PATHS[0]
    if test_manifest is not None:
        manifest = test_manifest
        command += ["--test-manifest", str(test_manifest)]
    manifest_bytes = manifest.read_bytes()
    result = subprocess.run(command, capture_output=True, text=True, cwd=repo)
    fields = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in fields:
            raise RuntimeError("release readiness returned malformed or duplicate status fields")
        fields[key] = value
    readiness = fields.get("release_readiness")
    accepted = result.returncode == 1 and readiness == "blocked"
    accepted |= result.returncode == 0 and readiness in {"pass", "test-manifest-pass"}
    if not accepted:
        detail = result.stderr.strip() or f"exit {result.returncode} without a valid readiness result"
        raise RuntimeError(f"release readiness failed: {detail}")
    if set(fields) != {*COUNT_KEYS, "release_readiness"}:
        raise RuntimeError("release readiness returned unexpected or missing status fields")
    counts = {}
    for key in COUNT_KEYS:
        if not re.fullmatch(r"[0-9]+", fields[key]):
            raise RuntimeError(f"release readiness returned an invalid count: {key}")
        counts[key] = int(fields[key])
    if manifest.read_bytes() != manifest_bytes:
        raise RuntimeError("capability manifest changed while collecting status")
    # The gate already validated every row. These two counts only distinguish
    # enabled parser rows from required parser rows explicitly unsupported.
    rows = acceptance_cases.read_tsv(manifest, acceptance_cases.MANIFEST_HEADER)
    parsers = [row for row in rows if row["kind"] == "parser"]
    counts["parser_total"] = len(parsers)
    counts["parser_unsupported"] = sum(row["status"] == "unsupported" for row in parsers)
    counts["release_readiness"] = readiness
    return counts


def head_revision(repo: Path) -> str:
    result = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                            capture_output=True, text=True, check=True)
    revision = result.stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", revision):
        raise RuntimeError("git returned an invalid HEAD revision")
    return revision


def input_hashes(repo: Path) -> dict[str, str]:
    return {name: hashlib.sha256((repo / name).read_bytes()).hexdigest() for name in INPUT_PATHS}


def render_snapshot(counts: dict, hashes: dict[str, str]) -> str:
    excluded = counts["capability_unsupported"] - counts["capability_unsupported_required"]
    parser_enabled = counts["parser_total"] - counts["parser_unsupported"]
    enabled_blocked = counts["parser_blocked"] - counts["parser_unsupported"]
    rows = [
        ("Total capability rows", counts["capability_total"]),
        ("Labeled qualified", counts["capability_qualified"]),
        ("Bounded", counts["capability_bounded"]),
        ("Pending", counts["capability_pending"]),
        ("Unsupported (all kinds)", counts["capability_unsupported"]),
        ("Unsupported required rows (still blockers)", counts["capability_unsupported_required"]),
        ("Deliberate unsupported exclusions (allowlisted)", excluded),
        ("Release-blocking rows", counts["capability_blocked"]),
        ("All parser rows blocked / total", f'{counts["parser_blocked"]} / {counts["parser_total"]}'),
        ("Enabled parser rows blocked / total", f"{enabled_blocked} / {parser_enabled}"),
        ("Unsupported required parser rows", counts["parser_unsupported"]),
    ]
    lines = [
        "# Current 32 GiB roadmap snapshot", "",
        "Generated from the working-tree capability manifest and the existing release-readiness gate.",
        "Regenerate with `python3 tools/largefile_status_snapshot.py --output 32gb-current-snapshot.md`.",
        "Check freshness with `python3 tools/largefile_status_snapshot.py --check 32gb-current-snapshot.md`.", "",
        f'**Release-readiness result: {counts["release_readiness"]}.**',
        "Counts alone do not establish release qualification. In a blocked snapshot, qualified labels",
        "have not undergone the gate's final evidence verification. Focused tests are not full-size qualification.", "",
        "| Generated measure | Value |", "| --- | ---: |",
        *[f"| {label} | {value} |" for label, value in rows], "",
        "Enabled parser rows exclude parser rows labeled unsupported; all parser rows include them.",
        "Required unsupported rows remain blockers. Only allowlisted `kind=unsupported` rows are exclusions.", "",
        "## Roadmap reminders — maintained text, not generated findings", "",
        "These reminders require human review as implementation and evidence change:", "",
        "- Implementation: the bounded modern OneNote reader path is implemented; finish any remaining parser-family gaps and independent format-8 bytecode fixtures.",
        "- Evidence: qualify current-source Linux x86-64 Release and ASan/UBSan builds with production databases.",
        "- Acceptance: run the oversized descriptor probe on the certified runner; complete materialized edges, ingress/on-access parity, and resource measurements.",
        "- Release: obtain revision-bound evidence for each required capability and run the full release gate.", "",
        "See [PLAN.md](PLAN.md), [audit1.md](audit1.md), and [32gb-status-summary.md](32gb-status-summary.md) for requirements and history.", "",
        "## Snapshot provenance", "",
        f'- Capability manifest SHA-256: `{hashes[INPUT_PATHS[0]]}`',
        f'- Readiness gate SHA-256: `{hashes[INPUT_PATHS[1]]}`',
        f'- Unsupported allowlist SHA-256: `{hashes[INPUT_PATHS[2]]}`',
        "- This tracked dashboard intentionally excludes Git HEAD; source/build identity belongs to external run provenance.",
        "- Freshness compares this generated text and the inputs above; it does not certify the entire source tree or external evidence.",
    ]
    return "\n".join(lines) + "\n"


def collect(repo: Path) -> tuple[str, dict]:
    repo = repo.resolve()
    revision = head_revision(repo)
    hashes = input_hashes(repo)
    counts = read_status(repo)
    if head_revision(repo) != revision or input_hashes(repo) != hashes:
        raise RuntimeError("snapshot inputs changed while collecting status; retry")
    text = render_snapshot(counts, hashes)
    provenance = {
        "schema": "largefile-status-snapshot-provenance-v1",
        "source_revision": revision,
        "input_hashes": hashes,
        "snapshot_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "release_readiness": counts["release_readiness"],
    }
    return text, provenance


def generate(repo: Path) -> str:
    return collect(repo)[0]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    destination = parser.add_mutually_exclusive_group()
    destination.add_argument("--output", type=Path, help="write the generated Markdown instead of stdout")
    destination.add_argument("--check", type=Path, help="exit 1 when a saved snapshot is missing or stale")
    parser.add_argument(
        "--provenance-output",
        type=Path,
        help="write Git/source run provenance as JSON (requires --output)",
    )
    args = parser.parse_args(argv)
    try:
        if args.provenance_output is not None and args.output is None:
            parser.error("--provenance-output requires --output")
        if args.provenance_output is not None:
            text, provenance = collect(args.repo)
        else:
            text = generate(args.repo)
            provenance = None
        if args.check is not None:
            if not args.check.is_file() or args.check.read_text(encoding="utf-8") != text:
                print(f"snapshot is missing or stale: {args.check}", file=sys.stderr)
                return 1
        elif args.output is not None:
            args.output.write_text(text, encoding="utf-8")
            if provenance is not None:
                args.provenance_output.write_text(
                    json.dumps(provenance, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
        else:
            print(text, end="")
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"status snapshot failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
