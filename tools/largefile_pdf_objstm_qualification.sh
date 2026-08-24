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
for command_name in python3 sha256sum stat awk grep find; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "required command is unavailable: $command_name" >&2
        exit 2
    }
done

mkdir -p "$out/corpus" "$out/logs" "$out/tmp" "$out/database"
python3 "$root/tools/largefile_pdf_objstm_fixture_test.py" > "$out/generator-test.log" 2>&1

marker_hex=$(python3 -c 'import binascii, sys; print(binascii.hexlify(sys.argv[1].encode()).decode())' \
    'CLAMAV-PDF-OBJSTM-TAIL-MARKER')
signature_name=LargeFile.PDF.ObjStm.Tail
printf '%s:0:*:%s\n' "$signature_name" "$marker_hex" > "$out/database/pdf-objstm.ndb"

manifest=$out/corpus-manifest.tsv
printf 'case\tpath\tfilter\tdecoded_size\tencoded_size\tfile_size\tsha256\tallocated_bytes\n' > "$manifest"
results=$out/results.tsv
printf 'case\tstatus\trss_kb\tminor_faults\tmajor_faults\tfs_inputs\tfs_outputs\tresult\n' > "$results"
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
    [ -n "$recorded_sha" ] && [ "$recorded_sha" = "$actual_sha" ] || return 1
    filter=$(sed -n 's/^filter=//p' "$metadata")
    fixture_decoded_size=$(sed -n 's/^decoded_size=//p' "$metadata")
    encoded_size=$(sed -n 's/^encoded_size=//p' "$metadata")
    file_size=$(stat -c %s "$path")
    blocks=$(stat -c %b "$path")
    block_size=$(stat -c %B "$path")
    allocated_bytes=$((blocks * block_size))
    printf '%s\tcorpus/%s.pdf\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$case_name" "$case_name" "$filter" "$fixture_decoded_size" \
        "$encoded_size" "$file_size" "$actual_sha" "$allocated_bytes" >> "$manifest"
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

run_fixture()
{
    case_name=$1
    expect_malformed=$2
    path=$out/corpus/$case_name.pdf
    log=$out/logs/$case_name.log
    temp=$out/tmp/$case_name
    mkdir -p "$temp"
    status=0
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
        --tempdir="$temp" \
        "$path" > "$log" 2>&1 || status=$?

    rss=$(sed -n 's/^[[:space:]]*Maximum resident set size (kbytes):[[:space:]]*//p' "$log" | tail -1)
    minor=$(sed -n 's/^[[:space:]]*Minor (reclaiming a frame) page faults:[[:space:]]*//p' "$log" | tail -1)
    major=$(sed -n 's/^[[:space:]]*Major (requiring I\/O) page faults:[[:space:]]*//p' "$log" | tail -1)
    fs_inputs=$(sed -n 's/^[[:space:]]*File system inputs:[[:space:]]*//p' "$log" | tail -1)
    fs_outputs=$(sed -n 's/^[[:space:]]*File system outputs:[[:space:]]*//p' "$log" | tail -1)
    result=pass
    case "$rss:$minor:$major:$fs_inputs:$fs_outputs" in
        *[!0-9:]*|:*|*::*) result=fail ;;
    esac
    if [ "$status" -ne 1 ] || [ -z "$rss" ] || [ "$rss" -gt "$rss_budget_kb" ] ||
        ! grep -E "$signature_name(\.UNOFFICIAL)? .*FOUND" "$log" >/dev/null 2>&1 ||
        ! grep -F 'pdf_extract_obj: Found /Type/ObjStm' "$log" >/dev/null 2>&1 ||
        ! grep -F 'pdf_objstm_attach_file: retained ' "$log" >/dev/null 2>&1 ||
        ! grep -F 'quota-accounted file-backed object stream' "$log" >/dev/null 2>&1 ||
        ! grep -F 'pdf_find_and_parse_objs_in_objstm: Found object 5 0' "$log" >/dev/null 2>&1 ||
        ! grep -F 'pdf_objstm_cleanup: releasing ' "$log" >/dev/null 2>&1 ||
        [ -n "$(find "$temp" -mindepth 1 -print -quit)" ]; then
        result=fail
    fi
    if [ "$expect_malformed" -eq 1 ]; then
        if ! grep -F 'PDF object-stream parsing did not complete' "$log" >/dev/null 2>&1; then
            result=fail
        fi
    elif grep -F 'PDF object-stream parsing did not complete' "$log" >/dev/null 2>&1; then
        result=fail
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$case_name" "$status" "${rss:-missing}" "${minor:-missing}" \
        "${major:-missing}" "${fs_inputs:-missing}" "${fs_outputs:-missing}" "$result" >> "$results"
    [ "$result" = pass ]
}

if [ "$failures" -eq 0 ]; then
    run_fixture raw 0 || failures=$((failures + 1))
    run_fixture flate 0 || failures=$((failures + 1))
    run_fixture filter-chain 0 || failures=$((failures + 1))
    run_fixture malformed 1 || failures=$((failures + 1))
    run_fixture materialized 0 || failures=$((failures + 1))
fi

if [ "$failures" -ne 0 ]; then
    echo "PDF object-stream qualification failed: $failures case(s); see $out" >&2
    exit 1
fi
echo "PDF object-stream qualification passed; evidence: $out"
