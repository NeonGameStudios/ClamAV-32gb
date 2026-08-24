#!/bin/sh

# GNU-time output stub used only by the qualification orchestrator self-test.
# Production qualification requires the host's /usr/bin/time -v.

set -u

if [ "$#" -lt 2 ] || [ "$1" != -v ]; then
    exit 2
fi
shift
status=0
"$@" || status=$?
cat >&2 <<'METRICS'
	Maximum resident set size (kbytes): 4096
	Minor (reclaiming a frame) page faults: 8
	Major (requiring I/O) page faults: 1
	File system inputs: 16
	File system outputs: 32
METRICS
exit "$status"
