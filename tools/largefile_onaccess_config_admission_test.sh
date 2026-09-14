#!/bin/sh

# Exercise clamonacc's configuration admission before it attempts daemon or
# privileged fanotify setup. The invalid worker count must fail immediately;
# otherwise the queue could accept permission events with no worker.

set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 CLAMONACC" >&2
    exit 2
fi

clamonacc=$1
tmp=$(mktemp -d "${TMPDIR:-/tmp}/clamav-onaccess-config.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

set +e
help_output=$($clamonacc --help 2>&1)
help_status=$?
set -e
if [ "$help_status" -ne 0 ]; then
    echo "clamonacc --help failed (exit $help_status)" >&2
    printf '%s\n' "$help_output" >&2
    exit 1
fi
case "$help_output" in
    *'ClamAV: On Access Scanning Application and Client'*)
        ;;
    *)
        echo "clamonacc --help returned unexpected output" >&2
        printf '%s\n' "$help_output" >&2
        exit 1
        ;;
esac

for worker_count in 0 2147483648; do
    printf '%s\n' \
        "OnAccessMaxThreads $worker_count" \
        'LocalSocket /tmp/clamav-onaccess-config-test.sock' \
        'OnAccessExcludeRootUID yes' > "$tmp/clamd.conf"

    set +e
    output=$($clamonacc --foreground --config-file "$tmp/clamd.conf" 2>&1)
    status=$?
    set -e

    if [ "$status" -ne 2 ]; then
        echo "clamonacc accepted an invalid OnAccessMaxThreads value: $worker_count (exit $status)" >&2
        printf '%s\n' "$output" >&2
        exit 1
    fi

    case "$output" in
        *'OnAccessMaxThreads must be between 1 and '*)
            ;;
        *)
            echo "clamonacc rejected the invalid value for an unexpected reason: $worker_count" >&2
            printf '%s\n' "$output" >&2
            exit 1
            ;;
    esac
done
