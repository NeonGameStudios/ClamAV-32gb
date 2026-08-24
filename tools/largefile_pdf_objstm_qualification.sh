#!/bin/sh

# Qualify production PDF object-stream discovery and file-backed ownership
# without configuring or building ClamAV. The caller supplies an existing
# scanner and database. The decoded-size range matches the nightly roadmap.
#
# Usage:
#   tools/largefile_pdf_objstm_qualification.sh \
#       CLAMSCAN DATABASE OUTPUT_DIRECTORY DECODED_SIZE RSS_BUDGET_KB

set -eu

if [ "$#" -ne 5 ]; then
    echo "usage: $0 CLAMSCAN DATABASE OUTPUT_DIRECTORY DECODED_SIZE RSS_BUDGET_KB" >&2
    exit 2
fi

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
scanner=$1
database=$2
requested_out=$3
decoded_size=$4
rss_budget_kb=$5
max_scan_time_ms=${CLAMAV_MAX_SCAN_TIME_MS:-14400000}

case "$requested_out" in
    /*) out=$requested_out ;;
    *) out=$(CDPATH= cd -- "$(dirname "$requested_out")" && pwd)/$(basename "$requested_out") ;;
esac
case "$out" in
    "$root"|"$root"/*)
        echo "PDF object-stream evidence must be written outside the source tree" >&2
        exit 2
        ;;
esac
if [ ! -x "$scanner" ]; then
    echo "CLAMSCAN is not executable: $scanner" >&2
    exit 2
fi
if [ ! -e "$database" ]; then
    echo "DATABASE does not exist: $database" >&2
    exit 2
fi
case "$decoded_size" in
    ''|*[!0-9]*) echo "DECODED_SIZE must be a non-negative integer" >&2; exit 2 ;;
esac
case "$rss_budget_kb" in
    ''|*[!0-9]*) echo "RSS_BUDGET_KB must be a non-negative integer" >&2; exit 2 ;;
esac
case "$max_scan_time_ms" in
    ''|*[!0-9]*) echo "CLAMAV_MAX_SCAN_TIME_MS must be a non-negative integer" >&2; exit 2 ;;
esac
if [ "$decoded_size" -lt 67108864 ] || [ "$decoded_size" -gt 4294967296 ]; then
    echo "DECODED_SIZE must be from 64 MiB through 4 GiB" >&2
    exit 2
fi
if [ "$rss_budget_kb" -eq 0 ] || [ "$rss_budget_kb" -gt 41943040 ]; then
    echo "RSS_BUDGET_KB must be from 1 through the 40 GiB release ceiling" >&2
    exit 2
fi
if [ "$max_scan_time_ms" -eq 0 ] || [ "$max_scan_time_ms" -gt 4294967295 ]; then
    echo "CLAMAV_MAX_SCAN_TIME_MS must be from 1 through 4294967295" >&2
    exit 2
fi
if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then
    echo "PDF object-stream qualification requires Linux x86-64" >&2
    exit 2
fi
if [ ! -x /usr/bin/time ] || ! /usr/bin/time -v true >/dev/null 2>&1; then
    echo "GNU /usr/bin/time -v is required" >&2
    exit 2
fi
for command_name in python3 sha256sum stat awk grep find du sleep cp file ldd openssl; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "required command is unavailable: $command_name" >&2
        exit 2
    }
done

if [ -d "$out" ] && [ -n "$(find "$out" -mindepth 1 -print -quit)" ]; then
    echo "PDF object-stream evidence directory is not empty: $out" >&2
    exit 2
fi
mkdir -p "$out/corpus" "$out/logs" "$out/reports" "$out/tmp" "$out/database" "$out/provenance"
openssl version > "$out/provenance/openssl-version.txt" 2>&1
openssl_version_sha256=$(sha256sum "$out/provenance/openssl-version.txt" | awk '{ print $1 }')
python3 "$root/tools/largefile_pdf_objstm_fixture_test.py" > "$out/generator-test.log" 2>&1

"$root/tools/largefile_source_manifest.sh" "$root" "$out/provenance/source-manifest.txt"
source_manifest_sha256=$(sha256sum "$out/provenance/source-manifest.txt" | awk '{ print $1 }')
source_revision_type=content-manifest
source_commit=$source_manifest_sha256
source_tree=$source_manifest_sha256
source_tree_status=snapshot
if command -v git >/dev/null 2>&1 &&
    [ "$(git -C "$root" rev-parse --show-toplevel 2>/dev/null || true)" = "$root" ]; then
    source_revision_type=git-commit
    source_commit=$(git -C "$root" rev-parse --verify HEAD)
    source_tree=$(git -C "$root" rev-parse --verify 'HEAD^{tree}')
    if [ -n "$(git -C "$root" status --porcelain --untracked-files=normal)" ]; then
        source_tree_status=dirty-manifest-bound
    else
        source_tree_status=clean
    fi
fi

cp "$scanner" "$out/provenance/clamscan"
scanner_sha256=$(sha256sum "$out/provenance/clamscan" | awk '{ print $1 }')
file -b "$scanner" > "$out/provenance/scanner-type.txt"
if ! grep -E 'ELF 64-bit .* x86-64' "$out/provenance/scanner-type.txt" >/dev/null 2>&1; then
    echo "CLAMSCAN is not a Linux x86-64 ELF executable" >&2
    exit 2
fi
scanner_type_sha256=$(sha256sum "$out/provenance/scanner-type.txt" | awk '{ print $1 }')
if ! ldd "$scanner" > "$out/provenance/ldd-clamscan.txt" 2>&1 ||
    grep -F 'not found' "$out/provenance/ldd-clamscan.txt" >/dev/null 2>&1; then
    echo "CLAMSCAN runtime dependency resolution failed" >&2
    exit 2
fi
ldd_sha256=$(sha256sum "$out/provenance/ldd-clamscan.txt" | awk '{ print $1 }')
python3 - "$out/provenance/ldd-clamscan.txt" "$out/provenance" <<'PY'
import hashlib
import pathlib
import re
import shutil
import sys

ldd_output = pathlib.Path(sys.argv[1])
provenance = pathlib.Path(sys.argv[2])
components = provenance / "runtime-components"
components.mkdir()
paths = sorted({
    pathlib.Path(match)
    for match in re.findall(r"(?:=>\s+)?(/[^\s(]+)", ldd_output.read_text(encoding="utf-8"))
})
if not paths:
    raise SystemExit("scanner dependency list is empty")
with (provenance / "runtime-dependencies.tsv").open("w", encoding="utf-8", newline="\n") as output:
    output.write("source\tartifact\tsize\tsha256\n")
    for index, path in enumerate(paths):
        if not path.is_file():
            raise SystemExit(f"scanner dependency is not a regular file: {path}")
        artifact = components / f"{index:04d}-{path.name}"
        shutil.copy2(path, artifact)
        digest = hashlib.sha256()
        with artifact.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        output.write(
            f"{path}\tprovenance/runtime-components/{artifact.name}\t"
            f"{artifact.stat().st_size}\t{digest.hexdigest()}\n"
        )
PY
runtime_dependencies_manifest_sha256=$(sha256sum "$out/provenance/runtime-dependencies.tsv" | awk '{ print $1 }')
"$scanner" --version > "$out/provenance/scanner-version.txt" 2>&1
scanner_version_sha256=$(sha256sum "$out/provenance/scanner-version.txt" | awk '{ print $1 }')

python3 - "$database" "$out/provenance/database-manifest.tsv" <<'PY'
import hashlib
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
if source.is_file():
    entries = [(source.name, source)]
elif source.is_dir():
    entries = sorted(
        (path.relative_to(source).as_posix(), path)
        for path in source.rglob("*")
        if path.is_file()
    )
else:
    raise SystemExit("database is not a regular file or directory")
if not entries:
    raise SystemExit("database contains no regular files")
with destination.open("w", encoding="utf-8", newline="\n") as output:
    output.write("path\tsize\tsha256\n")
    for relative, path in entries:
        if "\t" in relative or "\n" in relative or "\r" in relative:
            raise SystemExit("database path is not manifest-safe")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        output.write(f"{relative}\t{path.stat().st_size}\t{digest.hexdigest()}\n")
PY
database_manifest_sha256=$(sha256sum "$out/provenance/database-manifest.tsv" | awk '{ print $1 }')

marker_hex=$(python3 -c 'import binascii, sys; print(binascii.hexlify(sys.argv[1].encode()).decode())' \
    'CLAMAV-PDF-OBJSTM-TAIL-MARKER')
signature_name=LargeFile.PDF.ObjStm.Tail
printf '%s:0:*:%s\n' "$signature_name" "$marker_hex" > "$out/database/pdf-objstm.ndb"
custom_signature_sha256=$(sha256sum "$out/database/pdf-objstm.ndb" | awk '{ print $1 }')

manifest=$out/corpus-manifest.tsv
printf 'case\tpath\tfilter\tencryption\tcredential\tdecoded_size\tencoded_size\tfile_size\tsha256\tallocated_bytes\tmetadata_sha256\n' > "$manifest"
results=$out/results.tsv
printf 'case\tstatus\trss_kb\ttemporary_peak_bytes\tminor_faults\tmajor_faults\tfs_inputs\tfs_outputs\tlog_sha256\treport_sha256\tresult\n' > "$results"
failures=0

generate_fixture()
{
    case_name=$1
    shift
    path=$out/corpus/$case_name.pdf
    metadata=$out/corpus/$case_name.metadata
    if ! python3 "$root/tools/largefile_pdf_objstm_fixture.py" "$@" "$path" > "$metadata"; then
        echo "fixture generation failed: $case_name" >&2
        return 1
    fi
    recorded_sha=$(sed -n 's/^sha256=//p' "$metadata")
    actual_sha=$(sha256sum "$path" | awk '{ print $1 }')
    metadata_sha256=$(sha256sum "$metadata" | awk '{ print $1 }')
    [ -n "$recorded_sha" ] && [ "$recorded_sha" = "$actual_sha" ] || return 1
    filter=$(sed -n 's/^filter=//p' "$metadata")
    encryption=$(sed -n 's/^encryption=//p' "$metadata")
    credential=$(sed -n 's/^credential=//p' "$metadata")
    fixture_decoded_size=$(sed -n 's/^decoded_size=//p' "$metadata")
    encoded_size=$(sed -n 's/^encoded_size=//p' "$metadata")
    file_size=$(stat -c %s "$path")
    blocks=$(stat -c %b "$path")
    block_size=$(stat -c %B "$path")
    allocated_bytes=$((blocks * block_size))
    printf '%s\tcorpus/%s.pdf\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$case_name" "$case_name" "$filter" "$encryption" "$credential" "$fixture_decoded_size" \
        "$encoded_size" "$file_size" "$actual_sha" "$allocated_bytes" \
        "$metadata_sha256" >> "$manifest"
    if [ "$case_name" = materialized ] && [ "$allocated_bytes" -lt "$file_size" ]; then
        echo "materialized fixture contains holes: allocated=$allocated_bytes size=$file_size" >&2
        return 1
    fi
}

generate_fixture raw --filter raw || failures=$((failures + 1))
generate_fixture flate --filter flate || failures=$((failures + 1))
generate_fixture filter-chain --filter asciihex-flate || failures=$((failures + 1))
generate_fixture malformed --filter flate --malformed || failures=$((failures + 1))
generate_fixture materialized --filter raw --kind opaque --decoded-size "$decoded_size" || failures=$((failures + 1))
generate_fixture rc4-raw --filter raw --encryption rc4-r2 || failures=$((failures + 1))
generate_fixture rc4-flate --filter flate --encryption rc4-r2 || failures=$((failures + 1))
generate_fixture rc4-filter-chain --filter asciihex-flate --encryption rc4-r2 || failures=$((failures + 1))
generate_fixture aesv2-raw --filter raw --encryption aesv2-r4 || failures=$((failures + 1))
generate_fixture aesv2-flate --filter flate --encryption aesv2-r4 || failures=$((failures + 1))
generate_fixture aesv2-filter-chain --filter asciihex-flate --encryption aesv2-r4 || failures=$((failures + 1))
generate_fixture aesv3-raw --filter raw --encryption aesv3-r5 || failures=$((failures + 1))
generate_fixture aesv3-flate --filter flate --encryption aesv3-r5 || failures=$((failures + 1))
generate_fixture aesv3-filter-chain --filter asciihex-flate --encryption aesv3-r5 || failures=$((failures + 1))
generate_fixture password-rc4 --filter raw --encryption rc4-r2-password || failures=$((failures + 1))
generate_fixture password-aesv2 --filter raw --encryption aesv2-r4-password || failures=$((failures + 1))
generate_fixture password-aesv3 --filter raw --encryption aesv3-r5-password || failures=$((failures + 1))

run_fixture()
{
    case_name=$1
    expect_malformed=$2
    expect_encryption=$3
    expect_outcome=$4
    path=$out/corpus/$case_name.pdf
    log=$out/logs/$case_name.log
    report=$out/reports/$case_name.jsonl
    temp=$out/tmp/$case_name
    mkdir -p "$temp"
    status=0
    temporary_peak=0
    /usr/bin/time -v "$scanner" \
        --database="$database" \
        --database="$out/database/pdf-objstm.ndb" \
        --max-filesize=32G \
        --max-scansize=64G \
        --max-temporary-size=64G \
        --max-contiguous-size=32G \
        --pcre-max-filesize=32G \
        --max-scantime="$max_scan_time_ms" \
        --allmatch=yes \
        --debug \
        --no-summary \
        --report-json="$report" \
        --tempdir="$temp" \
        "$path" > "$log" 2>&1 &
    scanner_pid=$!
    while kill -0 "$scanner_pid" >/dev/null 2>&1; do
        temporary_now=$(du -s -B1 "$temp" | awk '{ print $1 }')
        if [ "$temporary_now" -gt "$temporary_peak" ]; then
            temporary_peak=$temporary_now
        fi
        sleep 0.1
    done
    if wait "$scanner_pid"; then
        status=0
    else
        status=$?
    fi
    temporary_now=$(du -s -B1 "$temp" | awk '{ print $1 }')
    if [ "$temporary_now" -gt "$temporary_peak" ]; then
        temporary_peak=$temporary_now
    fi

    rss=$(sed -n 's/^[[:space:]]*Maximum resident set size (kbytes):[[:space:]]*//p' "$log" | tail -1)
    minor=$(sed -n 's/^[[:space:]]*Minor (reclaiming a frame) page faults:[[:space:]]*//p' "$log" | tail -1)
    major=$(sed -n 's/^[[:space:]]*Major (requiring I\/O) page faults:[[:space:]]*//p' "$log" | tail -1)
    fs_inputs=$(sed -n 's/^[[:space:]]*File system inputs:[[:space:]]*//p' "$log" | tail -1)
    fs_outputs=$(sed -n 's/^[[:space:]]*File system outputs:[[:space:]]*//p' "$log" | tail -1)
    log_sha256=$(sha256sum "$log" | awk '{ print $1 }')
    report_sha256=missing
    if [ -f "$report" ]; then
        report_sha256=$(sha256sum "$report" | awk '{ print $1 }')
    fi
    result=pass
    case "$rss:$minor:$major:$fs_inputs:$fs_outputs" in
        *[!0-9:]*|:*|*::*) result=fail ;;
    esac
    if [ -z "$rss" ] || [ "$rss" -gt "$rss_budget_kb" ] ||
        [ "$temporary_peak" -gt 68719476736 ] ||
        ! grep -F 'pdf_extract_obj: Found /Type/ObjStm' "$log" >/dev/null 2>&1 ||
        [ ! -s "$report" ] ||
        [ -n "$(find "$temp" -mindepth 1 -print -quit)" ]; then
        result=fail
    fi
    if [ "$expect_outcome" = detection ]; then
        if [ "$status" -ne 1 ] ||
            ! grep -E "$signature_name(\.UNOFFICIAL)? .*FOUND" "$log" >/dev/null 2>&1 ||
            ! grep -F 'pdf_objstm_attach_file: retained ' "$log" >/dev/null 2>&1 ||
            ! grep -F 'quota-accounted file-backed object stream' "$log" >/dev/null 2>&1 ||
            ! grep -F 'pdf_find_and_parse_objs_in_objstm: Found object 5 0' "$log" >/dev/null 2>&1 ||
            ! grep -F 'pdf_objstm_cleanup: releasing ' "$log" >/dev/null 2>&1; then
            result=fail
        fi
    elif [ "$expect_outcome" = password ]; then
        if [ "$status" -ne 2 ] ||
            grep -E "$signature_name(\.UNOFFICIAL)? .*FOUND" "$log" >/dev/null 2>&1 ||
            grep -F ': OK' "$log" >/dev/null 2>&1 ||
            grep -F 'pdf_objstm_attach_file: retained ' "$log" >/dev/null 2>&1 ||
            grep -F 'pdf_find_and_parse_objs_in_objstm: Found object 5 0' "$log" >/dev/null 2>&1 ||
            ! grep -F 'encrypted PDF found, user password is NOT empty, cannot decrypt!' "$log" >/dev/null 2>&1 ||
            ! grep -F 'pdf_find_and_extract_objs: encrypted pdf found, not decryptable' "$log" >/dev/null 2>&1 ||
            ! grep -F 'PDF object-stream parsing did not complete' "$log" >/dev/null 2>&1; then
            result=fail
        fi
    else
        result=fail
    fi
    if [ "$expect_malformed" -eq 1 ] || [ "$expect_outcome" = password ]; then
        if ! grep -F 'PDF object-stream parsing did not complete' "$log" >/dev/null 2>&1; then
            result=fail
        fi
    elif grep -F 'PDF object-stream parsing did not complete' "$log" >/dev/null 2>&1; then
        result=fail
    fi
    case "$expect_encryption" in
        none)
            if grep -F 'pdf_stream_decrypt_reader: decrypting RC4 stream in bounded windows' "$log" >/dev/null 2>&1 ||
                grep -F 'pdf_stream_decrypt_reader: decrypting AESV2 stream in bounded CBC blocks' "$log" >/dev/null 2>&1 ||
                grep -F 'pdf_stream_decrypt_reader: decrypting AESV3 stream in bounded CBC blocks' "$log" >/dev/null 2>&1 ||
                grep -F 'encrypted PDF found, user password is empty, will attempt to decrypt' "$log" >/dev/null 2>&1; then
                result=fail
            fi
            ;;
        rc4-r2)
            if ! grep -F 'encrypted PDF found, user password is empty, will attempt to decrypt' "$log" >/dev/null 2>&1 ||
                ! grep -F 'pdf_stream_decrypt_reader: decrypting RC4 stream in bounded windows' "$log" >/dev/null 2>&1 ||
                grep -F 'pdf_stream_decrypt_reader: decrypting AESV2 stream in bounded CBC blocks' "$log" >/dev/null 2>&1 ||
                grep -F 'pdf_stream_decrypt_reader: decrypting AESV3 stream in bounded CBC blocks' "$log" >/dev/null 2>&1; then
                result=fail
            fi
            ;;
        aesv2-r4)
            if ! grep -F 'encrypted PDF found, user password is empty, will attempt to decrypt' "$log" >/dev/null 2>&1 ||
                ! grep -F 'pdf_stream_decrypt_reader: decrypting AESV2 stream in bounded CBC blocks' "$log" >/dev/null 2>&1 ||
                grep -F 'pdf_stream_decrypt_reader: decrypting RC4 stream in bounded windows' "$log" >/dev/null 2>&1 ||
                grep -F 'pdf_stream_decrypt_reader: decrypting AESV3 stream in bounded CBC blocks' "$log" >/dev/null 2>&1; then
                result=fail
            fi
            ;;
        aesv3-r5)
            if ! grep -F 'encrypted PDF found, user password is empty, will attempt to decrypt' "$log" >/dev/null 2>&1 ||
                ! grep -F 'pdf_stream_decrypt_reader: decrypting AESV3 stream in bounded CBC blocks' "$log" >/dev/null 2>&1 ||
                grep -F 'pdf_stream_decrypt_reader: decrypting RC4 stream in bounded windows' "$log" >/dev/null 2>&1 ||
                grep -F 'pdf_stream_decrypt_reader: decrypting AESV2 stream in bounded CBC blocks' "$log" >/dev/null 2>&1; then
                result=fail
            fi
            ;;
        rc4-r2-password|aesv2-r4-password|aesv3-r5-password)
            if ! grep -F 'encrypted PDF found, user password is NOT empty, cannot decrypt!' "$log" >/dev/null 2>&1 ||
                grep -F 'encrypted PDF found, user password is empty, will attempt to decrypt' "$log" >/dev/null 2>&1 ||
                grep -F 'pdf_stream_decrypt_reader: decrypting RC4 stream in bounded windows' "$log" >/dev/null 2>&1 ||
                grep -F 'pdf_stream_decrypt_reader: decrypting AESV2 stream in bounded CBC blocks' "$log" >/dev/null 2>&1 ||
                grep -F 'pdf_stream_decrypt_reader: decrypting AESV3 stream in bounded CBC blocks' "$log" >/dev/null 2>&1; then
                result=fail
            fi
            ;;
        *) result=fail ;;
    esac
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$case_name" "$status" "${rss:-missing}" "$temporary_peak" \
        "${minor:-missing}" "${major:-missing}" "${fs_inputs:-missing}" \
        "${fs_outputs:-missing}" "$log_sha256" "$report_sha256" "$result" >> "$results"
    [ "$result" = pass ]
}

if [ "$failures" -eq 0 ]; then
    run_fixture raw 0 none detection || failures=$((failures + 1))
    run_fixture flate 0 none detection || failures=$((failures + 1))
    run_fixture filter-chain 0 none detection || failures=$((failures + 1))
    run_fixture malformed 1 none detection || failures=$((failures + 1))
    run_fixture materialized 0 none detection || failures=$((failures + 1))
    run_fixture rc4-raw 0 rc4-r2 detection || failures=$((failures + 1))
    run_fixture rc4-flate 0 rc4-r2 detection || failures=$((failures + 1))
    run_fixture rc4-filter-chain 0 rc4-r2 detection || failures=$((failures + 1))
    run_fixture aesv2-raw 0 aesv2-r4 detection || failures=$((failures + 1))
    run_fixture aesv2-flate 0 aesv2-r4 detection || failures=$((failures + 1))
    run_fixture aesv2-filter-chain 0 aesv2-r4 detection || failures=$((failures + 1))
    run_fixture aesv3-raw 0 aesv3-r5 detection || failures=$((failures + 1))
    run_fixture aesv3-flate 0 aesv3-r5 detection || failures=$((failures + 1))
    run_fixture aesv3-filter-chain 0 aesv3-r5 detection || failures=$((failures + 1))
    run_fixture password-rc4 1 rc4-r2-password password || failures=$((failures + 1))
    run_fixture password-aesv2 1 aesv2-r4-password password || failures=$((failures + 1))
    run_fixture password-aesv3 1 aesv3-r5-password password || failures=$((failures + 1))
fi

if [ "$failures" -ne 0 ]; then
    echo "PDF object-stream qualification failed: $failures case(s); see $out" >&2
    exit 1
fi
corpus_manifest_sha256=$(sha256sum "$manifest" | awk '{ print $1 }')
results_sha256=$(sha256sum "$results" | awk '{ print $1 }')
generator_sha256=$(sha256sum "$root/tools/largefile_pdf_objstm_fixture.py" | awk '{ print $1 }')
qualification_sha256=$(sha256sum "$root/tools/largefile_pdf_objstm_qualification.sh" | awk '{ print $1 }')
evidence_checker_sha256=$(sha256sum "$root/tools/largefile_pdf_objstm_evidence_check.py" | awk '{ print $1 }')
generator_test_sha256=$(sha256sum "$out/generator-test.log" | awk '{ print $1 }')
cat > "$out/evidence-metadata.txt" <<EOF
schema_version=5
source_revision_type=$source_revision_type
source_commit=$source_commit
source_tree=$source_tree
source_tree_status=$source_tree_status
source_manifest_sha256=$source_manifest_sha256
scanner_sha256=$scanner_sha256
scanner_type_sha256=$scanner_type_sha256
scanner_version_sha256=$scanner_version_sha256
openssl_version_sha256=$openssl_version_sha256
ldd_sha256=$ldd_sha256
runtime_dependencies_manifest_sha256=$runtime_dependencies_manifest_sha256
database_manifest_sha256=$database_manifest_sha256
custom_signature_sha256=$custom_signature_sha256
generator_sha256=$generator_sha256
qualification_sha256=$qualification_sha256
evidence_checker_sha256=$evidence_checker_sha256
generator_test_sha256=$generator_test_sha256
decoded_size=$decoded_size
rss_budget_kb=$rss_budget_kb
temporary_budget_bytes=68719476736
max_scan_time_ms=$max_scan_time_ms
corpus_manifest_sha256=$corpus_manifest_sha256
results_sha256=$results_sha256
qualification_status=pass
EOF
echo "PDF object-stream qualification passed; evidence: $out"
