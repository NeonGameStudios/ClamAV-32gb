#!/bin/sh

# Tiny executable scanner double used only by the harness regression test. It
# intentionally accepts clamscan-like options and treats the final argument as
# the input path. It is not a scanner and must never be used for release proof.

set -eu

input=
for arg do
    case "$arg" in
        --*) ;;
        *) input=$arg ;;
    esac
done

if [ -z "$input" ]; then
    echo "largefile_poc_test_scanner.sh: missing input" >&2
    exit 2
fi

if [ -n "${CLAMAV_LARGEFILE_STUB_LOG:-}" ]; then
    printf '%s\n' "$input" >> "$CLAMAV_LARGEFILE_STUB_LOG"
fi

if [ "${CLAMAV_LARGEFILE_STUB_MODE:-negative}" = positive ]; then
    signature="LargeFile.POC.$(basename "$input" .bin)"
    printf '%s: %s: FOUND\n' "$signature" "$input"
    printf 'cli_bm_scanbuff: signature %s matched at 0\n' "$signature"
    exit 1
fi

exit 0
