#!/bin/sh

# Exercise the process-tree sampler against a real Linux parent/child pair.
# This is a harness regression only; its small processes are not qualification
# evidence.

set -eu

if [ "$(uname -s)" != Linux ]; then
    echo 'large-file procfs tree RSS test skipped: Linux procfs is unavailable'
    exit 0
fi

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/clamav-largefile-procfs-tree.XXXXXX")
child_pid_file=$tmp/child.pid
root_pid=
child_pid=
cleanup()
{
    if [ -n "${child_pid:-}" ]; then
        kill "$child_pid" 2>/dev/null || true
        wait "$child_pid" 2>/dev/null || true
    fi
    if [ -n "${root_pid:-}" ]; then
        kill "$root_pid" 2>/dev/null || true
        wait "$root_pid" 2>/dev/null || true
    fi
    rm -rf "$tmp"
}
trap cleanup EXIT HUP INT TERM

sh -c 'sleep 10 & printf "%s\n" "$!" > "$1"; wait' sh "$child_pid_file" &
root_pid=$!
i=0
while [ ! -s "$child_pid_file" ] && [ "$i" -lt 50 ]; do
    sleep 0.01
    i=$((i + 1))
done
[ -s "$child_pid_file" ] || {
    echo 'procfs tree test child did not start' >&2
    exit 1
}
child_pid=$(sed -n '1p' "$child_pid_file")
case "$child_pid" in
    ''|*[!0-9]*) echo 'procfs tree test child PID is malformed' >&2; exit 1 ;;
esac

sample=$(sh "$root/tools/largefile_procfs_tree_rss.sh" "$root_pid")
sample_rss=$(printf '%s\n' "$sample" | awk -F '\t' 'NF == 3 { print $1 }')
sample_count=$(printf '%s\n' "$sample" | awk -F '\t' 'NF == 3 { print $2 }')
sample_pids=$(printf '%s\n' "$sample" | awk -F '\t' 'NF == 3 { print $3 }')
case "$sample_rss:$sample_count" in
    ''|*[!0-9:]*) echo 'procfs tree test returned malformed RSS/count' >&2; exit 1 ;;
esac
[ "$sample_rss" -gt 0 ] || {
    echo 'procfs tree test returned zero RSS' >&2
    exit 1
}
[ "$sample_count" -ge 2 ] || {
    echo 'procfs tree test did not include the child process' >&2
    exit 1
}
case ",$sample_pids," in
    *",$root_pid,"*) ;;
    *) echo 'procfs tree test omitted the root process' >&2; exit 1 ;;
esac
case ",$sample_pids," in
    *",$child_pid,"*) ;;
    *) echo 'procfs tree test omitted the child process' >&2; exit 1 ;;
esac

duplicate_sample=$(sh "$root/tools/largefile_procfs_tree_rss.sh" \
    "$root_pid" "$child_pid")
[ "$sample" = "$duplicate_sample" ] || {
    echo 'procfs tree sampler double-counted a descendant root' >&2
    exit 1
}

if sh "$root/tools/largefile_procfs_tree_rss.sh" invalid >/dev/null 2>&1; then
    echo 'procfs tree sampler accepted a non-numeric PID' >&2
    exit 1
fi

echo 'large-file procfs tree RSS test passed'
