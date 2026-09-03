#!/bin/sh

set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
gate="$root/tools/largefile_release_readiness.sh"
work=$(mktemp -d "${TMPDIR:-/tmp}/clamav-release-readiness.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM

write_header()
{
    printf 'kind\tid\tstatus\tsource\tevidence_or_required_work\n'
}

hash_fixture()
{
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{ print $1 }'
    else
        shasum -a 256 "$1" | awk '{ print $1 }'
    fi
}

mkdir -p "$work/evidence/provenance"
printf 'synthetic release source manifest\n' > "$work/evidence/provenance/source-manifest.txt"
source_manifest_sha256=$(hash_fixture "$work/evidence/provenance/source-manifest.txt")
mkdir -p "$work/evidence/proof"
printf 'capability-specific synthetic proof\n' > "$work/evidence/proof/library-path.txt"
proof_sha256=$(hash_fixture "$work/evidence/proof/library-path.txt")
printf 'kind\tid\tstatus\tsource_manifest_sha256\tproof\tproof_sha256\n' \
    > "$work/evidence/provenance/capability-bindings.tsv"
printf 'library\tpath\tqualified\t%s\tproof/library-path.txt\t%s\n' \
    "$source_manifest_sha256" "$proof_sha256" \
    >> "$work/evidence/provenance/capability-bindings.tsv"

expect_rejected()
{
    label=$1
    expected=$2
    candidate=$3

    if "$gate" --manifest "$candidate" --status > "$work/rejected.out" 2> "$work/rejected.err"; then
        echo "release gate accepted $label" >&2
        exit 1
    fi
    grep -F "$expected" "$work/rejected.err" >/dev/null
}

{
    write_header
    printf 'library\tpath\tqualified\tlibclamav/scanners.c\trelease_evidence=test:%s source_manifest_sha256=%s\n' \
        "$work/evidence" "$source_manifest_sha256"
    printf 'unsupported\tnative-windows-memory-scan\tunsupported\tCMakeLists.txt\texplicit incomplete\n'
} > "$work/ready.tsv"

"$gate" --manifest "$work/ready.tsv" > "$work/ready.out"
grep -F 'release_readiness=test-manifest-pass' "$work/ready.out" >/dev/null

{
    write_header
    printf 'library\tpath\tqualified\tlibclamav/scanners.c\trelease_evidence=test:%s source_manifest_sha256=%s\n' \
        "$work/evidence" "$source_manifest_sha256"
    printf 'library\tother\tqualified\tlibclamav/others.c\trelease_evidence=test:%s source_manifest_sha256=%s\n' \
        "$work/evidence" "$source_manifest_sha256"
    printf 'unsupported\tnative-windows-memory-scan\tunsupported\tCMakeLists.txt\texplicit incomplete\n'
} > "$work/reused-evidence.tsv"
expect_rejected 'generic evidence reused for a different capability' \
    'no unique valid binding for library:other' "$work/reused-evidence.tsv"

for blocked_status in bounded pending unsupported; do
    {
        write_header
        printf 'parser\tCL_TYPE_PDF\t%s\tlibclamav/pdf.c\trelease evidence required\n' "$blocked_status"
    } > "$work/blocked.tsv"

    if "$gate" --manifest "$work/blocked.tsv" > "$work/blocked.out" 2> "$work/blocked.err"; then
        echo "release gate accepted a $blocked_status capability" >&2
        exit 1
    fi
    grep -F 'release_readiness=blocked' "$work/blocked.out" >/dev/null
    if [ "$blocked_status" = unsupported ]; then
        grep -F 'unsupported required capability' "$work/blocked.err" >/dev/null
    else
        grep -F "$blocked_status" "$work/blocked.err" >/dev/null
    fi
    if "$gate" --manifest "$work/blocked.tsv" --status > "$work/status.out"; then
        echo "release gate status mode accepted a $blocked_status capability" >&2
        exit 1
    fi
    grep -F 'capability_blocked=1' "$work/status.out" >/dev/null
done

{
    write_header
    printf 'parser\tCL_TYPE_PDF\tunknown\tlibclamav/pdf.c\tinvalid\n'
} > "$work/invalid.tsv"

if "$gate" --manifest "$work/invalid.tsv" --status >/dev/null 2>&1; then
    echo 'release gate accepted an unknown capability status' >&2
    exit 1
fi

{
    write_header
    printf 'unknown\tpath\tunsupported\tsource.c\texplicit incomplete\n'
} > "$work/invalid-kind.tsv"
expect_rejected 'an unknown capability kind' 'invalid capability kind' "$work/invalid-kind.tsv"

{
    write_header
    printf 'unsupported\tnative-windows-memory-scan\tpending\tsource.c\trelease evidence required\n'
} > "$work/invalid-unsupported.tsv"
expect_rejected 'a pending deliberate-unsupported capability' 'invalid unsupported capability status' "$work/invalid-unsupported.tsv"

{
    write_header
    printf 'unsupported\tCL_TYPE_PDF\tunsupported\tsource.c\trelease evidence not required\n'
} > "$work/relabelled-unsupported.tsv"
expect_rejected 'a required parser relabelled as deliberate unsupported' \
    'unapproved deliberate unsupported capability CL_TYPE_PDF' \
    "$work/relabelled-unsupported.tsv"

{
    write_header
    printf 'library\tpath\tbounded\tsource.c\trelease evidence required\n'
    printf 'library\tpath\tpending\tsource.c\trelease evidence required\n'
} > "$work/duplicate.tsv"
expect_rejected 'a duplicate capability' 'duplicate capability' "$work/duplicate.tsv"

for invalid_evidence in \
    'source_manifest_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
    'release_evidence=evidence/path source_manifest_sha256=aaaa' \
    'release_evidence=evidence/path source_manifest_sha256=gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg' \
    'release_evidence=evidence/one release_evidence=evidence/two source_manifest_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
    'release_evidence=evidence/path source_manifest_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa source_manifest_sha256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'; do
    {
        write_header
        printf 'library\tpath\tqualified\tsource.c\t%s\n' "$invalid_evidence"
    } > "$work/invalid-evidence.tsv"
    expect_rejected 'malformed qualified evidence' 'lacks exact revision-bound release evidence' "$work/invalid-evidence.tsv"
done

{
    write_header
    printf 'library\tpath\tqualified\tsource.c\trelease_evidence=test:%s source_manifest_sha256=%s\n' \
        "$work/missing-evidence" "$source_manifest_sha256"
} > "$work/missing-evidence.tsv"
expect_rejected 'a nonexistent release evidence path' 'has no source manifest' "$work/missing-evidence.tsv"

{
    write_header
    printf 'library\tpath\tqualified\tsource.c\trelease_evidence=test:%s source_manifest_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
        "$work/evidence"
} > "$work/wrong-evidence-hash.tsv"
expect_rejected 'a release evidence hash mismatch' 'source manifest hash does not match' "$work/wrong-evidence-hash.tsv"

{
    write_header
    printf 'library\tpath\tqualified\tsource.c\trelease_evidence=unknown:%s source_manifest_sha256=%s\n' \
        "$work/evidence" "$source_manifest_sha256"
} > "$work/unknown-evidence-verifier.tsv"
expect_rejected 'an unknown release evidence verifier' 'unknown qualified release evidence verifier' "$work/unknown-evidence-verifier.tsv"

if "$gate" --unknown >/dev/null 2>&1; then
    echo 'release gate accepted an unknown option' >&2
    exit 1
fi

echo 'large-file release readiness tests passed'
