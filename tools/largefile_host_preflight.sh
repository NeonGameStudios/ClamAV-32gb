#!/bin/sh

# Capture the Linux host and resource environment used for a large-file run.
# This is intentionally separate from the scanner build and creates no binary.
#
# Usage:
#   tools/largefile_host_preflight.sh OUTPUT_DIRECTORY [MIN_AVAILABLE_KB]

set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "usage: $0 OUTPUT_DIRECTORY [MIN_AVAILABLE_KB]" >&2
    exit 2
fi

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
requested_out=$1
min_available_kb=${2:-0}

case "$min_available_kb" in
    ''|*[!0-9]*)
        echo "MIN_AVAILABLE_KB must be a non-negative integer" >&2
        exit 2
        ;;
esac

case "$requested_out" in
    /*) out=$requested_out ;;
    *) out=$(CDPATH= cd -- "$(dirname "$requested_out")" && pwd)/$(basename "$requested_out") ;;
esac
case "$out" in
    "$root"|"$root"/*)
        echo "host preflight output must be outside the source tree: $out" >&2
        exit 2
        ;;
esac

if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then
    echo "host preflight requires Linux x86-64 (found $(uname -s)/$(uname -m))" >&2
    exit 1
fi
if [ ! -r /proc/meminfo ]; then
    echo "host preflight requires readable /proc/meminfo" >&2
    exit 1
fi

mkdir -p "$out"

meminfo_value() {
    awk -v key="$1" '$1 == key ":" { print $2; exit }' /proc/meminfo
}

mem_total_kb=$(meminfo_value MemTotal)
mem_available_kb=$(meminfo_value MemAvailable)
case "$mem_total_kb:$mem_available_kb" in
    ''|*[!0-9:]*|*:)
        echo "could not read MemTotal and MemAvailable from /proc/meminfo" >&2
        exit 1
        ;;
esac

read_optional_file() {
    file=$1
    if [ -r "$file" ]; then
        sed -n '1p' "$file"
    else
        printf 'unavailable\n'
    fi
}

cgroup_memory_limit_bytes=unavailable
cgroup_memory_current_bytes=unavailable
if [ -r /sys/fs/cgroup/memory.max ]; then
    cgroup_memory_limit_bytes=$(read_optional_file /sys/fs/cgroup/memory.max)
    cgroup_memory_current_bytes=$(read_optional_file /sys/fs/cgroup/memory.current)
elif [ -r /sys/fs/cgroup/memory/memory.limit_in_bytes ]; then
    cgroup_memory_limit_bytes=$(read_optional_file /sys/fs/cgroup/memory/memory.limit_in_bytes)
    cgroup_memory_current_bytes=$(read_optional_file /sys/fs/cgroup/memory/memory.usage_in_bytes)
fi

# /proc/meminfo describes the host on some container runtimes. A finite cgroup
# limit can therefore be the tighter constraint and must participate in the
# admission decision. Treat the near-LONG_MAX cgroup-v1 "unlimited" sentinel
# as unlimited; a numeric limit within 1024 times physical memory is finite.
cgroup_limit_finite=no
cgroup_available_kb=unlimited
effective_memory_available_kb=$mem_available_kb
case "$cgroup_memory_limit_bytes:$cgroup_memory_current_bytes" in
    *[!0-9:]*|:*|*:)
        ;;
    *)
        if awk -v limit="$cgroup_memory_limit_bytes" -v total_kb="$mem_total_kb" \
            'BEGIN { exit !(limit < total_kb * 1048576) }'; then
            cgroup_limit_finite=yes
            cgroup_available_kb=$(awk \
                -v limit="$cgroup_memory_limit_bytes" \
                -v current="$cgroup_memory_current_bytes" '
                BEGIN {
                    available = limit - current
                    if (available < 0)
                        available = 0
                    printf "%.0f\n", int(available / 1024)
                }')
            if [ "$cgroup_available_kb" -lt "$effective_memory_available_kb" ]; then
                effective_memory_available_kb=$cgroup_available_kb
            fi
        fi
        ;;
esac

cpu_count=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf 'unknown')
page_size_bytes=$(getconf PAGE_SIZE 2>/dev/null || printf 'unknown')
ulimit_virtual_kb=$(ulimit -v 2>/dev/null || true)
ulimit_rss_kb=$(ulimit -m 2>/dev/null || true)
ulimit_open_files=$(ulimit -n 2>/dev/null || true)

if [ "$effective_memory_available_kb" -ge "$min_available_kb" ]; then
    available_check=pass
else
    available_check=fail
fi

{
    printf 'utc='; date -u '+%Y-%m-%dT%H:%M:%SZ'
    printf 'kernel='; uname -a
    printf 'arch=%s\n' "$(uname -m)"
    printf 'memory_total_kb=%s\n' "$mem_total_kb"
    printf 'memory_available_kb=%s\n' "$mem_available_kb"
    printf 'effective_memory_available_kb=%s\n' "$effective_memory_available_kb"
    printf 'minimum_available_kb=%s\n' "$min_available_kb"
    printf 'available_memory_check=%s\n' "$available_check"
    printf 'cgroup_memory_limit_bytes=%s\n' "$cgroup_memory_limit_bytes"
    printf 'cgroup_memory_current_bytes=%s\n' "$cgroup_memory_current_bytes"
    printf 'cgroup_limit_finite=%s\n' "$cgroup_limit_finite"
    printf 'cgroup_available_kb=%s\n' "$cgroup_available_kb"
    printf 'cpu_count=%s\n' "$cpu_count"
    printf 'page_size_bytes=%s\n' "$page_size_bytes"
    printf 'ulimit_virtual_kb=%s\n' "$ulimit_virtual_kb"
    printf 'ulimit_rss_kb=%s\n' "$ulimit_rss_kb"
    printf 'ulimit_open_files=%s\n' "$ulimit_open_files"
    printf 'filesystem:\n'
    df -Pk "$out"
    printf 'toolchain:\n'
    for command_name in cmake cargo gcc clang file sha256sum timeout; do
        command_path=$(command -v "$command_name" 2>/dev/null || true)
        if [ -n "$command_path" ]; then
            command_version=$("$command_name" --version 2>&1 | sed -n '1p' || true)
            printf '%s_path=%s\n' "$command_name" "$command_path"
            printf '%s_version=%s\n' "$command_name" "$command_version"
        else
            printf '%s_path=missing\n' "$command_name"
        fi
    done
} > "$out/host-preflight.txt"

if [ "$available_check" != pass ]; then
    echo "available memory is below the requested minimum; see $out/host-preflight.txt" >&2
    exit 1
fi

echo "host preflight passed; evidence is in $out/host-preflight.txt"
