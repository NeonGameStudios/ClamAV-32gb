#!/bin/sh

# Run the raw-signature large-file proof of concept against a built clamscan.
# Usage: tools/largefile_poc.sh CLAMSCAN BOUNDARY_CORPUS OUTPUT_DIRECTORY

set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: $0 CLAMSCAN BOUNDARY_CORPUS OUTPUT_DIRECTORY" >&2
    exit 2
fi

clamscan=$1
corpus=$2
out=$3
manifest=$corpus/manifest.tsv
sigdir=$out/db
sigdb=$sigdir/largefile-poc.ndb
logs=$out/logs
tmp=$out/tmp
results=$out/results.tsv
cert_arg=
if [ -n "${CLAMAV_CVD_CERTS_DIR:-}" ]; then
    cert_arg="--cvdcertsdir=$CLAMAV_CVD_CERTS_DIR"
fi
verbose_time=no
if /usr/bin/time -v true >/dev/null 2>&1; then
    verbose_time=yes
fi

if [ ! -x "$clamscan" ]; then
    echo "CLAMSCAN is not executable: $clamscan" >&2
    exit 2
fi
if [ ! -f "$manifest" ]; then
    echo "Boundary corpus manifest not found: $manifest" >&2
    exit 2
fi

mkdir -p "$out" "$logs" "$tmp" "$sigdir"
: > "$sigdb"

while IFS="$(printf '\t')" read -r file marker expected_offset expected_size kind; do
    if [ "$file" = file ]; then
        continue
    fi
    hex=$(printf '%s' "$marker" | od -An -tx1 | tr -d ' \n')
    # The trailing NUL prevents a shorter marker (for example 4g) from
    # matching the prefix of a longer marker (for example 4g-plus).
    hex=${hex}00
    signature="LargeFile.POC.$(basename "$file" .bin)"
    printf '%s:0:*:%s\n' "$signature" "$hex" >> "$sigdb"
done < "$manifest"

file_size() {
    if size=$(stat -c '%s' "$1" 2>/dev/null); then
        printf '%s\n' "$size"
    else
        stat -f '%z' "$1"
    fi
}

printf 'file\texpected_offset\texpected_size\tactual_size\tsize_matches\tscan_status\tdetected\tsignature_matches\tmarker_at_expected\tengine_offset\toffset_matches\ttmp_bytes\n' > "$results"

failures=0

mem_snapshot() {
    if [ -r /proc/meminfo ]; then
        awk '/^(MemAvailable|Cached|SwapFree):/ { printf "%s=%sKB ", $1, $2 }' /proc/meminfo
    else
        printf 'meminfo=unavailable '
    fi
}

while IFS="$(printf '\t')" read -r file marker expected_offset expected_size kind; do
    if [ "$file" = file ]; then
        continue
    fi

    input=$corpus/$file
    row_signature="LargeFile.POC.$(basename "$file" .bin)"
    log=$logs/$file.log
    work=$tmp/${file%.bin}
    mkdir -p "$work"

    actual_size=$(file_size "$input")
    size_matches=no
    if [ "$actual_size" = "$expected_size" ]; then
        size_matches=yes
    fi

    before=$(mem_snapshot)
    scan_status=0
    if [ -n "$cert_arg" ]; then
        if [ "$verbose_time" = yes ]; then
            /usr/bin/time -v "$clamscan" "$cert_arg" \
                --database="$sigdir" \
                --max-filesize=32G \
                --max-scansize=32G \
                --debug \
                --no-summary \
                --tempdir="$work" \
                "$input" > "$log" 2>&1 || scan_status=$?
        else
            "$clamscan" "$cert_arg" \
                --database="$sigdir" \
                --max-filesize=32G \
                --max-scansize=32G \
                --debug \
                --no-summary \
                --tempdir="$work" \
                "$input" > "$log" 2>&1 || scan_status=$?
        fi
    else
        if [ "$verbose_time" = yes ]; then
            /usr/bin/time -v "$clamscan" \
                --database="$sigdir" \
                --max-filesize=32G \
                --max-scansize=32G \
                --debug \
                --no-summary \
                --tempdir="$work" \
                "$input" > "$log" 2>&1 || scan_status=$?
        else
            "$clamscan" \
                --database="$sigdir" \
                --max-filesize=32G \
                --max-scansize=32G \
                --debug \
                --no-summary \
                --tempdir="$work" \
                "$input" > "$log" 2>&1 || scan_status=$?
        fi
    fi
    after=$(mem_snapshot)

    detected=no
    signature_matches=no
    actual_offset=missing
    if grep -q 'FOUND' "$log"; then
        detected=yes
    fi
    if grep -F "$row_signature" "$log" | grep -F 'FOUND' >/dev/null 2>&1; then
        signature_matches=yes
    fi

    expected_hex=$(printf '%s' "$marker" | od -An -tx1 | tr -d ' \n')
    expected_hex=${expected_hex}00
    marker_hex=$(dd if="$input" bs=1 skip="$expected_offset" count=$((${#marker} + 1)) 2>/dev/null | od -An -tx1 | tr -d ' \n')
    marker_at_expected=no
    if [ "$marker_hex" = "$expected_hex" ]; then
        marker_at_expected=yes
    fi

    # Only report an offset printed by the engine. The marker check above is
    # independent fixture validation and must not be relabeled as an engine
    # match offset when debug logging does not emit one.
    actual_offset=$(grep -F "signature $row_signature matched at " "$log" | sed -n 's/.* matched at \([0-9][0-9]*\).*/\1/p' | head -1)
    if [ -z "$actual_offset" ]; then
        actual_offset=missing
    fi

    offset_matches=no
    if [ "$actual_offset" = "$expected_offset" ]; then
        offset_matches=yes
    fi

    row_ok=yes
    if [ "$actual_size" != "$expected_size" ] ||
        [ "$scan_status" -ne 1 ] ||
        [ "$detected" != yes ] ||
        [ "$signature_matches" != yes ] ||
        [ "$marker_at_expected" != yes ] ||
        [ "$offset_matches" != yes ]; then
        row_ok=no
        failures=$((failures + 1))
    fi

    tmp_bytes=$(du -sk "$work" 2>/dev/null | awk '{ print $1 * 1024 }')
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$file" "$expected_offset" "$expected_size" "$actual_size" "$size_matches" "$scan_status" "$detected" "$signature_matches" "$marker_at_expected" "$actual_offset" "$offset_matches" "$tmp_bytes" >> "$results"
    printf '%s: %s before{%s} after{%s} log=%s\n' "$file" "$row_ok" "$before" "$after" "$log"
done < "$manifest"

echo "Signature database: $sigdb"
echo "Results: $results"
echo "Logs: $logs"

if [ "$failures" -ne 0 ]; then
    echo "Large-file POC failed: $failures case(s) did not meet the expected detection, size, or offset checks." >&2
    exit 1
fi

echo "Large-file POC passed all cases."
