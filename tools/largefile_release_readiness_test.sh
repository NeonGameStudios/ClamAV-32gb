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
printf 'proof_format_version=1\ncapability_kind=library\ncapability_id=path\nsource_manifest_sha256=%s\nevidence_type=test\nqualification_result=pass\ncapability-specific synthetic proof\n' \
    "$source_manifest_sha256" > "$work/evidence/proof/library-path.txt"
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

    if "$gate" --test-manifest "$candidate" --status > "$work/rejected.out" 2> "$work/rejected.err"; then
        echo "release gate accepted $label" >&2
        exit 1
    fi
    grep -F "$expected" "$work/rejected.err" >/dev/null
}

printf 'proof_format_version=1\ncapability_kind=library\ncapability_id=other\nsource_manifest_sha256=%s\nevidence_type=test\nqualification_result=pass\n' \
    "$source_manifest_sha256" > "$work/evidence/proof/wrong-capability.txt"
wrong_capability_proof_sha256=$(hash_fixture "$work/evidence/proof/wrong-capability.txt")
cp "$work/evidence/provenance/capability-bindings.tsv" \
    "$work/evidence/provenance/capability-bindings.good.tsv"
{
    printf 'kind\tid\tstatus\tsource_manifest_sha256\tproof\tproof_sha256\n'
    printf 'library\tpath\tqualified\t%s\tproof/wrong-capability.txt\t%s\n' \
        "$source_manifest_sha256" "$wrong_capability_proof_sha256"
} > "$work/evidence/provenance/capability-bindings.tsv"
{
    write_header
    printf 'library\tpath\tqualified\tlibclamav/scanners.c\trelease_evidence=test:%s source_manifest_sha256=%s\n' \
        "$work/evidence" "$source_manifest_sha256"
} > "$work/wrong-capability-binding.tsv"
expect_rejected 'a proof bound to a different capability ID' \
    'proof is not self-bound to test:library:path' "$work/wrong-capability-binding.tsv"
mv "$work/evidence/provenance/capability-bindings.good.tsv" \
    "$work/evidence/provenance/capability-bindings.tsv"

{
    write_header
    printf 'library\tpath\tqualified\tlibclamav/scanners.c\trelease_evidence=test:%s source_manifest_sha256=%s\n' \
        "$work/evidence" "$source_manifest_sha256"
    printf 'unsupported\tnative-windows-memory-scan\tunsupported\tCMakeLists.txt\texplicit incomplete\n'
} > "$work/ready.tsv"

"$gate" --test-manifest "$work/ready.tsv" > "$work/ready.out"
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

    if "$gate" --test-manifest "$work/blocked.tsv" > "$work/blocked.out" 2> "$work/blocked.err"; then
        echo "release gate accepted a $blocked_status capability" >&2
        exit 1
    fi
    grep -F 'release_readiness=blocked' "$work/blocked.out" >/dev/null
    if [ "$blocked_status" = unsupported ]; then
        grep -F 'unsupported required capability' "$work/blocked.err" >/dev/null
    else
        grep -F "$blocked_status" "$work/blocked.err" >/dev/null
    fi
    if "$gate" --test-manifest "$work/blocked.tsv" --status > "$work/status.out"; then
        echo "release gate status mode accepted a $blocked_status capability" >&2
        exit 1
    fi
    grep -F 'capability_blocked=1' "$work/status.out" >/dev/null
done

{
    write_header
    printf 'parser\tCL_TYPE_PDF\tunknown\tlibclamav/pdf.c\tinvalid\n'
} > "$work/invalid.tsv"

if "$gate" --test-manifest "$work/invalid.tsv" --status >/dev/null 2>&1; then
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

if "$gate" --manifest "$work/ready.tsv" >/dev/null 2> "$work/legacy-option.err"; then
    echo 'release gate accepted the old synthetic-manifest option' >&2
    exit 1
fi
grep -F 'usage:' "$work/legacy-option.err" >/dev/null

# A generic self-bound proof is not enough for on-access: the release gate
# must require the retained Linux fanotify permission-event proof as well.
mkdir -p "$work/onaccess-evidence/provenance" "$work/onaccess-evidence/proof"
cp "$work/evidence/provenance/source-manifest.txt" \
    "$work/onaccess-evidence/provenance/source-manifest.txt"
onaccess_source_hash=$(hash_fixture "$work/onaccess-evidence/provenance/source-manifest.txt")
printf 'proof_format_version=1\ncapability_kind=on-access\ncapability_id=permission\nsource_manifest_sha256=%s\nevidence_type=test\nqualification_result=pass\n' \
    "$onaccess_source_hash" > "$work/onaccess-evidence/proof/onaccess.txt"
onaccess_proof_hash=$(hash_fixture "$work/onaccess-evidence/proof/onaccess.txt")
printf 'kind\tid\tstatus\tsource_manifest_sha256\tproof\tproof_sha256\n' \
    > "$work/onaccess-evidence/provenance/capability-bindings.tsv"
printf 'on-access\tpermission\tqualified\t%s\tproof/onaccess.txt\t%s\n' \
    "$onaccess_source_hash" "$onaccess_proof_hash" \
    >> "$work/onaccess-evidence/provenance/capability-bindings.tsv"
{
    write_header
    printf 'on-access\tpermission\tqualified\tclamonacc/client/client.c\trelease_evidence=test:%s source_manifest_sha256=%s\n' \
        "$work/onaccess-evidence" "$onaccess_source_hash"
} > "$work/onaccess-missing-fanotify.tsv"
expect_rejected 'on-access evidence without a fanotify permission proof' \
    'has no fanotify permission proof' "$work/onaccess-missing-fanotify.tsv"

{
    write_header
    mkdir -p "$work/pcre-evidence/provenance" "$work/pcre-evidence/proof"
    cp "$work/evidence/provenance/source-manifest.txt" \
        "$work/pcre-evidence/provenance/source-manifest.txt"
    pcre_source_hash=$(hash_fixture "$work/pcre-evidence/provenance/source-manifest.txt")
    printf 'proof_format_version=1\ncapability_kind=matcher\ncapability_id=pcre\nsource_manifest_sha256=%s\nevidence_type=test\nqualification_result=pass\n' \
        "$pcre_source_hash" > "$work/pcre-evidence/proof/pcre.txt"
    pcre_proof_hash=$(hash_fixture "$work/pcre-evidence/proof/pcre.txt")
    printf 'kind\tid\tstatus\tsource_manifest_sha256\tproof\tproof_sha256\n' \
        > "$work/pcre-evidence/provenance/capability-bindings.tsv"
    printf 'matcher\tpcre\tqualified\t%s\tproof/pcre.txt\t%s\n' \
        "$pcre_source_hash" "$pcre_proof_hash" \
        >> "$work/pcre-evidence/provenance/capability-bindings.tsv"
    printf 'matcher\tpcre\tqualified\tlibclamav/matcher-pcre.c\trelease_evidence=test:%s source_manifest_sha256=%s\n' \
        "$work/pcre-evidence" "$pcre_source_hash"
} > "$work/pcre-missing-phase.tsv"
expect_rejected 'PCRE evidence without phase RSS proof' \
    'has no phase RSS proof' "$work/pcre-missing-phase.tsv"

echo 'large-file release readiness tests passed'
