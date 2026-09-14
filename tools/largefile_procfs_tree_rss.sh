#!/bin/sh

# Return one process-tree RSS sample for the supplied Linux process roots.
# Output is: tree_rss_kb<TAB>process_count<TAB>pid,pid,...
#
# The sampler deliberately reads /proc status files directly.  `time` reports
# one command's maximum RSS and does not establish the combined daemon,
# client, and helper-process budget required by the qualification plan.

set -eu

if [ "$#" -lt 1 ]; then
    echo "usage: $0 ROOT_PID..." >&2
    exit 2
fi

roots=
for root_pid in "$@"; do
    case "$root_pid" in
        ''|*[!0-9]*)
            echo "invalid process root PID: $root_pid" >&2
            exit 2
            ;;
    esac
    roots="$roots $root_pid"
done

set -- /proc/[0-9]*/status
if [ "$1" = '/proc/[0-9]*/status' ] && [ ! -e "$1" ]; then
    echo 'procfs has no readable process status files' >&2
    exit 3
fi

awk -v roots="$roots" '
function emit() {
    if (pid ~ /^[0-9]+$/ && ppid ~ /^[0-9]+$/ && rss ~ /^[0-9]+$/) {
        parent[pid] = ppid
        resident[pid] = rss
    }
}

FNR == 1 {
    if (NR != 1) {
        emit()
    }
    pid = ""
    ppid = ""
    rss = ""
}

$1 == "Pid:" { pid = $2 }
$1 == "PPid:" { ppid = $2 }
$1 == "VmRSS:" { rss = $2 }

END {
    emit()

    root_count = split(roots, root_list, /[[:space:]]+/)
    for (i = 1; i <= root_count; i++) {
        candidate = root_list[i]
        if (candidate ~ /^[0-9]+$/ && candidate in parent) {
            selected[candidate] = 1
        }
    }

    changed = 1
    while (changed) {
        changed = 0
        for (candidate in parent) {
            if (!(candidate in selected) && parent[candidate] in selected) {
                selected[candidate] = 1
                changed = 1
            }
        }
    }

    total = 0
    selected_count = 0
    selected_list = ""
    for (candidate in selected) {
        total += resident[candidate]
        selected_count++
        if (selected_list == "") {
            selected_list = candidate
        } else {
            selected_list = selected_list "," candidate
        }
    }
    if (selected_count == 0) {
        exit 3
    }
    printf "%d\t%d\t%s\n", total, selected_count, selected_list
}
' /proc/[0-9]*/status
