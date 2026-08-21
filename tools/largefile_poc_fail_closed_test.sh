#!/bin/sh

# Regression test for the large-file harness: executable positive and negative
# scanner stubs must both be invoked, and a clean result must fail the test.

set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/clamav-largefile-harness.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

corpus=$tmp/corpus
out=$tmp/out
mkdir -p "$corpus"
printf 'file\tmarker\toffset\tsize\tkind\n' > "$corpus/manifest.tsv"
printf 'CLAMAV-LF-TEST\0' > "$corpus/test.bin"
printf 'test.bin\tCLAMAV-LF-TEST\t0\t15\tsynthetic\n' >> "$corpus/manifest.tsv"
printf 'SECOND\0' > "$corpus/other.bin"
printf 'other.bin\tSECOND\t0\t7\tsynthetic\n' >> "$corpus/manifest.tsv"

positive_log=$tmp/positive.invoked
if ! CLAMAV_LARGEFILE_STUB_MODE=positive \
    CLAMAV_LARGEFILE_STUB_LOG="$positive_log" \
    "$root/tools/largefile_poc.sh" "$root/tools/largefile_poc_test_scanner.sh" "$corpus" "$out" >/dev/null 2>&1; then
    echo "largefile_poc.sh rejected the positive scanner stub" >&2
    exit 1
fi
if [ ! -s "$positive_log" ]; then
    echo "largefile_poc.sh did not invoke the positive scanner stub" >&2
    exit 1
fi

negative_log=$tmp/negative.invoked
if CLAMAV_LARGEFILE_STUB_MODE=negative \
    CLAMAV_LARGEFILE_STUB_LOG="$negative_log" \
    "$root/tools/largefile_poc.sh" "$root/tools/largefile_poc_test_scanner.sh" "$corpus" "$tmp/negative-out" >/dev/null 2>&1; then
    echo "largefile_poc.sh accepted a scanner with no detection" >&2
    exit 1
fi
if [ ! -s "$negative_log" ]; then
    echo "largefile_poc.sh did not invoke the negative scanner stub" >&2
    exit 1
fi

for invalid_deadline in 0001 4294967296 999999999999999999999999; do
    invalid_log=$tmp/invalid-deadline-$invalid_deadline.invoked
    if CLAMAV_MAX_SCAN_TIME_MS=$invalid_deadline \
        CLAMAV_LARGEFILE_STUB_MODE=positive \
        CLAMAV_LARGEFILE_STUB_LOG="$invalid_log" \
        "$root/tools/largefile_poc.sh" "$root/tools/largefile_poc_test_scanner.sh" \
        "$corpus" "$tmp/invalid-deadline-$invalid_deadline" >/dev/null 2>&1; then
        echo "largefile_poc.sh accepted invalid scan deadline $invalid_deadline" >&2
        exit 1
    fi
    if [ -e "$invalid_log" ]; then
        echo "largefile_poc.sh invoked the scanner before rejecting deadline $invalid_deadline" >&2
        exit 1
    fi

    if CLAMAV_MAX_SCAN_TIME_MS=$invalid_deadline \
        "$root/tools/largefile_runtime_gate.sh" "$root/tools/largefile_poc_test_scanner.sh" \
        "$tmp/invalid-gate-$invalid_deadline" 1234 >/dev/null 2>&1; then
        echo "largefile_runtime_gate.sh accepted invalid scan deadline $invalid_deadline" >&2
        exit 1
    fi
done

for invalid_sanitizer_deadline in 0001 4294967296 999999999999999999999999; do
    if CLAMAV_SANITIZER_MAX_SCAN_TIME_MS=$invalid_sanitizer_deadline \
        CLAMAV_MAX_SCAN_TIME_MS=14400000 \
        "$root/tools/largefile_runtime_gate.sh" "$root/tools/largefile_poc_test_scanner.sh" \
        "$tmp/invalid-sanitizer-gate-$invalid_sanitizer_deadline" 1234 >/dev/null 2>&1; then
        echo "largefile_runtime_gate.sh accepted invalid sanitizer deadline $invalid_sanitizer_deadline" >&2
        exit 1
    fi
done

if CLAMAV_MAX_SCAN_TIME_MS=14400000 \
    CLAMAV_SANITIZER_MAX_SCAN_TIME_MS=14399999 \
    "$root/tools/largefile_runtime_gate.sh" "$root/tools/largefile_poc_test_scanner.sh" \
    "$tmp/short-sanitizer-deadline" 1234 >/dev/null 2>&1; then
    echo 'largefile_runtime_gate.sh accepted a sanitizer deadline below the release deadline' >&2
    exit 1
fi

echo "largefile_poc.sh positive/fail-closed regression passed"
