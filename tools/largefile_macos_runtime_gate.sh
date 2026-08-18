#!/bin/sh

# Run the first local macOS large-file acceptance slice against an existing
# clamscan binary. The script does not build or install anything.
#
# Usage:
#   tools/largefile_macos_runtime_gate.sh CLAMSCAN OUTPUT_DIRECTORY
#
# The output directory must be outside the source tree. By default this gate
# requires 48 GiB of reclaimable/available memory, matching the dedicated
# 64-GiB host budget used by the large-file release plan. Override only for
# exploratory runs with CLAMAV_MACOS_MIN_AVAILABLE_KB=0.

set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 CLAMSCAN OUTPUT_DIRECTORY" >&2
    exit 2
fi

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
clamscan=$1
requested_out=$2
min_available_kb=${CLAMAV_MACOS_MIN_AVAILABLE_KB:-50331648}
max_scan_time_ms=${CLAMAV_MAX_SCAN_TIME_MS:-900000}
cert_arg=
if [ -n "${CLAMAV_CVD_CERTS_DIR:-}" ]; then
    cert_arg="--cvdcertsdir=$CLAMAV_CVD_CERTS_DIR"
fi

case "$requested_out" in
    /*) out=$requested_out ;;
    *) out=$(CDPATH= cd -- "$(dirname "$requested_out")" && pwd)/$(basename "$requested_out") ;;
esac
case "$out" in
    "$root"|"$root"/*)
        echo "runtime output must be outside the source tree: $out" >&2
        exit 2
        ;;
esac

case "$min_available_kb" in
    ''|*[!0-9]*)
        echo "CLAMAV_MACOS_MIN_AVAILABLE_KB must be a non-negative integer" >&2
        exit 2
        ;;
esac
case "$max_scan_time_ms" in
    ''|*[!0-9]*|0*)
        echo "CLAMAV_MAX_SCAN_TIME_MS must be a positive integer" >&2
        exit 2
        ;;
esac
if [ "${#max_scan_time_ms}" -gt 10 ] ||
    { [ "${#max_scan_time_ms}" -eq 10 ] && [ "$max_scan_time_ms" -gt 4294967295 ]; }; then
    echo "CLAMAV_MAX_SCAN_TIME_MS must fit uint32 milliseconds" >&2
    exit 2
fi

if [ "$(uname -s)" != Darwin ]; then
    echo "macOS runtime gate requires Darwin (found $(uname -s))" >&2
    exit 1
fi
if [ ! -x "$clamscan" ]; then
    echo "CLAMSCAN is not executable: $clamscan" >&2
    exit 2
fi
if [ ! -x /usr/bin/time ]; then
    echo "macOS /usr/bin/time is required for resource evidence" >&2
    exit 2
fi

mkdir -p "$out"
if ! "$root/tools/largefile_macos_host_preflight.sh" "$out/host-preflight" "$min_available_kb" > "$out/host-preflight.log" 2>&1; then
    echo "macOS host preflight failed; see $out/host-preflight.log" >&2
    exit 1
fi

corpus=$out/corpus
logs=$out/logs
metrics=$out/metrics
tmp=$out/tmp
sigdir=$out/db
mkdir -p "$logs" "$metrics" "$tmp" "$sigdir"
"$root/tools/largefile_boundary_corpus.sh" "$corpus" > "$out/corpus.log" 2>&1

sigdb=$sigdir/largefile-poc.ndb
: > "$sigdb"
while IFS="$(printf '\t')" read -r file marker expected_offset expected_size kind; do
    if [ "$file" = file ]; then
        continue
    fi
    hex=$(printf '%s' "$marker" | od -An -tx1 | tr -d ' \n')
    printf 'LargeFile.POC.%s:0:*:%s00\n' "$(basename "$file" .bin)" "$hex" >> "$sigdb"
done < "$corpus/manifest.tsv"

file_size() {
    if size=$(stat -f '%z' "$1" 2>/dev/null); then
        printf '%s\n' "$size"
    else
        stat -c '%s' "$1"
    fi
}

time_metric() {
    metric=$1
    file=$2
    awk -v wanted="$metric" '$0 ~ wanted { print $1; exit }' "$file"
}

bytes_to_kb() {
    value=$1
    case "$value" in
        ''|*[!0-9]*) printf 'unavailable\n' ;;
        *) awk -v bytes="$value" 'BEGIN { printf "%.0f\n", bytes / 1024 }' ;;
    esac
}

run_scan() {
    input=$1
    log=$2
    metric=$3
    work=$4
    status=0
    mkdir -p "$work"
    if [ -n "$cert_arg" ]; then
        /usr/bin/time -l -o "$metric" "$clamscan" "$cert_arg" \
            --database="$sigdir" --max-filesize=32G --max-scansize=32G \
            --max-scantime="$max_scan_time_ms" --debug --no-summary \
            --tempdir="$work" "$input" > "$log" 2>&1 || status=$?
    else
        /usr/bin/time -l -o "$metric" "$clamscan" \
            --database="$sigdir" --max-filesize=32G --max-scansize=32G \
            --max-scantime="$max_scan_time_ms" --debug --no-summary \
            --tempdir="$work" "$input" > "$log" 2>&1 || status=$?
    fi
    printf '%s\n' "$status"
}

results=$out/results.tsv
printf 'file\texpected_offset\texpected_size\tactual_size\tscan_status\tdetected\tsignature_matches\tmarker_at_expected\tengine_offset\toffset_matches\ttmp_bytes\tpeak_rss_kb\tpage_faults\tswaps\tblock_in\tblock_out\treal_seconds\tuser_seconds\tsys_seconds\n' > "$results"

failures=0
while IFS="$(printf '\t')" read -r file marker expected_offset expected_size kind; do
    if [ "$file" = file ]; then
        continue
    fi

    input=$corpus/$file
    row_signature="LargeFile.POC.$(basename "$file" .bin)"
    log=$logs/$file.log
    metric=$metrics/$file.time
    work=$tmp/${file%.bin}
    scan_status=$(run_scan "$input" "$log" "$metric" "$work")

    actual_size=$(file_size "$input")
    detected=no
    signature_matches=no
    if grep -q 'FOUND' "$log"; then
        detected=yes
    fi
    if grep -F "$row_signature" "$log" | grep -F 'FOUND' >/dev/null 2>&1; then
        signature_matches=yes
    fi

    expected_hex=$(printf '%s' "$marker" | od -An -tx1 | tr -d ' \n')
    marker_hex=$(dd if="$input" bs=1 skip="$expected_offset" count=$((${#marker} + 1)) 2>/dev/null | od -An -tx1 | tr -d ' \n')
    marker_at_expected=no
    if [ "${marker_hex}" = "${expected_hex}00" ]; then
        marker_at_expected=yes
    fi

    actual_offset=$(awk \
        -v signed="signature $row_signature matched at " \
        -v unsigned="signature $row_signature.UNOFFICIAL matched at " '
        (index($0, signed) || index($0, unsigned)) && match($0, /matched at [0-9][0-9]*/) {
            print substr($0, RSTART + 11, RLENGTH - 11)
            exit
        }
    ' "$log")
    if [ -z "$actual_offset" ]; then
        actual_offset=missing
    fi

    offset_matches=no
    if [ "$actual_offset" = "$expected_offset" ]; then
        offset_matches=yes
    fi

    peak_rss_kb=$(bytes_to_kb "$(time_metric 'maximum resident set size' "$metric")")
    page_faults=$(time_metric 'page faults' "$metric")
    swaps=$(time_metric 'swaps' "$metric")
    block_in=$(time_metric 'block input operations' "$metric")
    block_out=$(time_metric 'block output operations' "$metric")
    real_seconds=$(time_metric 'real$' "$metric")
    user_seconds=$(time_metric 'user$' "$metric")
    sys_seconds=$(time_metric 'sys$' "$metric")
    tmp_bytes=$(du -sk "$work" 2>/dev/null | awk '{ print $1 * 1024 }')

    row_ok=yes
    if [ "$actual_size" != "$expected_size" ] || [ "$scan_status" -ne 1 ] ||
        [ "$detected" != yes ] || [ "$signature_matches" != yes ] ||
        [ "$marker_at_expected" != yes ] || [ "$offset_matches" != yes ]; then
        row_ok=no
        failures=$((failures + 1))
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$file" "$expected_offset" "$expected_size" "$actual_size" "$scan_status" \
        "$detected" "$signature_matches" "$marker_at_expected" "$actual_offset" \
        "$offset_matches" "$tmp_bytes" "$peak_rss_kb" "$page_faults" "$swaps" \
        "$block_in" "$block_out" "$real_seconds" "$user_seconds" "$sys_seconds" >> "$results"
    printf '%s: %s log=%s metrics=%s\n' "$file" "$row_ok" "$log" "$metric"
done < "$corpus/manifest.tsv"

policy_file=$corpus/32g-plus-one.bin
policy_log=$out/32g-plus-one.log
policy_metric=$out/32g-plus-one.time
truncate -s 34359738369 "$policy_file"
policy_status=$(run_scan "$policy_file" "$policy_log" "$policy_metric" "$tmp/policy")
if [ "$policy_status" -eq 1 ] &&
    grep -E 'MaxFileSize|Max file size|exceeds the maximum file size' "$policy_log" >/dev/null 2>&1; then
    printf 'policy_32g_plus_one=pass\n' > "$out/policy-result.txt"
else
    printf 'policy_32g_plus_one=fail status=%s\n' "$policy_status" > "$out/policy-result.txt"
    failures=$((failures + 1))
fi

printf 'clamscan=%s\nresults=%s\npolicy=%s\n' "$clamscan" "$results" "$out/policy-result.txt" > "$out/metadata.txt"
if [ "$failures" -ne 0 ]; then
    echo "macOS large-file runtime gate failed: $failures case(s); see $out" >&2
    exit 1
fi

echo "macOS large-file runtime gate passed; evidence is in $out"
