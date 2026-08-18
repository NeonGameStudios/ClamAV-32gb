#!/bin/sh

# Capture the macOS host and resource environment for a large-file run.
# This is the macOS counterpart to largefile_host_preflight.sh and deliberately
# does not build, install, or run ClamAV.
#
# Usage:
#   tools/largefile_macos_host_preflight.sh OUTPUT_DIRECTORY [MIN_AVAILABLE_KB]

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

if [ "$(uname -s)" != Darwin ]; then
    echo "macOS host preflight requires Darwin (found $(uname -s))" >&2
    exit 1
fi

mkdir -p "$out"

sysctl_value() {
    key=$1
    value=$(/usr/sbin/sysctl -n "$key" 2>/dev/null || true)
    if [ -n "$value" ]; then
        printf '%s\n' "$value"
    else
        printf 'unavailable\n'
    fi
}

tool_record() {
    command_name=$1
    command_path=$(command -v "$command_name" 2>/dev/null || true)
    if [ -z "$command_path" ]; then
        printf '%s_path=missing\n' "$command_name"
        return
    fi
    printf '%s_path=%s\n' "$command_name" "$command_path"
    case "$command_name" in
        sh|bash|zsh)
            command_version=$($command_name --version 2>&1 | sed -n '1p' || true)
            ;;
        *)
            command_version=$($command_name --version 2>&1 | sed -n '1p' || true)
            ;;
    esac
    printf '%s_version=%s\n' "$command_name" "$command_version"
}

page_size=$(sysctl_value hw.pagesize)
memory_total_bytes=$(sysctl_value hw.memsize)
vm_stat_output=$(vm_stat 2>/dev/null || true)
vm_page_size=$(printf '%s\n' "$vm_stat_output" | awk '/page size of/ { print $(NF - 1); exit }')
case "$page_size" in
    ''|unavailable)
        page_size=${vm_page_size:-unavailable}
        ;;
esac
memory_pressure_output=$(memory_pressure -Q 2>/dev/null || true)

vm_pages() {
    label=$1
    printf '%s\n' "$vm_stat_output" | awk -v wanted="$label" '
        index($0, wanted) == 1 {
            value = $NF
            gsub(/\./, "", value)
            if (value ~ /^[0-9]+$/) {
                print value
                exit
            }
        }'
}

free_pages=$(vm_pages 'Pages free:' || true)
inactive_pages=$(vm_pages 'Pages inactive:' || true)
speculative_pages=$(vm_pages 'Pages speculative:' || true)
purgeable_pages=$(vm_pages 'Pages purgeable:' || true)

case "$page_size:$free_pages:$inactive_pages:$speculative_pages:$purgeable_pages" in
    *[!0-9:]*|:*|*::*)
        available_memory_kb=unavailable
        ;;
    *)
        available_memory_kb=$((
            (free_pages + inactive_pages + speculative_pages + purgeable_pages) *
            page_size / 1024
        ))
        ;;
esac

available_check=unavailable
case "$available_memory_kb" in
    ''|*[!0-9]*) ;;
    *)
        if [ "$available_memory_kb" -ge "$min_available_kb" ]; then
            available_check=pass
        else
            available_check=fail
        fi
        ;;
esac

{
    printf 'utc='; date -u '+%Y-%m-%dT%H:%M:%SZ'
    printf 'kernel='; uname -a
    printf 'os=%s\n' "$(uname -s)"
    printf 'arch=%s\n' "$(uname -m)"
    printf 'memory_total_bytes=%s\n' "$memory_total_bytes"
    printf 'memory_available_kb=%s\n' "$available_memory_kb"
    printf 'minimum_available_kb=%s\n' "$min_available_kb"
    printf 'available_memory_check=%s\n' "$available_check"
    printf 'page_size_bytes=%s\n' "$page_size"
    printf 'cpu_count=%s\n' "$(sysctl_value hw.ncpu)"
    printf 'physical_cpu_count=%s\n' "$(sysctl_value hw.physicalcpu)"
    printf 'performance_cpu_count=%s\n' "$(sysctl_value hw.perflevel0.physicalcpu)"
    printf 'efficiency_cpu_count=%s\n' "$(sysctl_value hw.perflevel1.physicalcpu)"
    printf 'vm_swapusage=%s\n' "$(sysctl_value vm.swapusage)"
    printf 'memory_pressure_quick:\n%s\n' "$memory_pressure_output"
    printf 'ulimit_virtual_kb=%s\n' "$(ulimit -v 2>/dev/null || true)"
    printf 'ulimit_rss_kb=%s\n' "$(ulimit -m 2>/dev/null || true)"
    printf 'ulimit_open_files=%s\n' "$(ulimit -n 2>/dev/null || true)"
    printf 'vm_stat:\n%s\n' "$vm_stat_output"
    printf 'filesystem:\n'
    df -Pk "$out"
    printf 'toolchain:\n'
    for command_name in cmake ninja make clang cc cargo rustc file shasum otool; do
        tool_record "$command_name"
    done
} > "$out/host-preflight.txt"

if [ "$available_check" = fail ]; then
    echo "available memory is below the requested minimum; see $out/host-preflight.txt" >&2
    exit 1
fi

echo "macOS host preflight passed; evidence is in $out/host-preflight.txt"
