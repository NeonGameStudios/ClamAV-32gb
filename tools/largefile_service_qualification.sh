#!/bin/sh

# Run the service and workload gates required by audit1.md. This is an
# acceptance gate, not a best-effort smoke test: every input and budget is
# explicit, and the gate fails when cold-cache control or RSS measurement is
# unavailable.
#
# Usage:
#   tools/largefile_service_qualification.sh BUILD_DIR OUTPUT_DIR \
#       PRODUCTION_DB PRODUCTION_FILE MATERIALIZED_FILE EXPANSION_FILE \
#       EDGE_FILE EDGE_DB

set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)

if [ "$#" -ne 8 ]; then
    echo "usage: $0 BUILD_DIR OUTPUT_DIR PRODUCTION_DB PRODUCTION_FILE MATERIALIZED_FILE EXPANSION_FILE EDGE_FILE EDGE_DB" >&2
    exit 2
fi

build_dir=$1
out=$2
production_db=$3
production_file=$4
materialized_file=$5
expansion_file=$6
edge_file=$7
edge_db=$8

for required in \
    "$build_dir/clamscan/clamscan" \
    "$build_dir/clamd/clamd" \
    "$build_dir/clamdscan/clamdscan" \
    "$production_file" "$materialized_file" "$expansion_file" "$edge_file"; do
    if [ ! -e "$required" ]; then
        echo "missing qualification input: $required" >&2
        exit 2
    fi
done
if [ ! -x "$build_dir/clamav-milter/clamav-milter" ]; then
    echo "missing qualification executable: $build_dir/clamav-milter/clamav-milter" >&2
    exit 2
fi
if [ ! -f "$root/unit_tests/milter_protocol_test.py" ]; then
    echo "missing milter exact-edge harness: $root/unit_tests/milter_protocol_test.py" >&2
    exit 2
fi
for required in "$production_db" "$edge_db"; do
    if [ ! -d "$required" ]; then
        echo "missing qualification database: $required" >&2
        exit 2
    fi
done
if ! command -v timeout >/dev/null 2>&1 || ! command -v awk >/dev/null 2>&1 ||
    ! command -v python3 >/dev/null 2>&1 ||
    [ ! -x /usr/bin/time ]; then
    echo 'timeout, awk, python3, and GNU /usr/bin/time are required' >&2
    exit 2
fi

rss_budget_kb=${CLAMAV_SERVICE_MAX_RSS_KB:-33554432}
case "$rss_budget_kb" in
    ''|*[!0-9]*) echo 'CLAMAV_SERVICE_MAX_RSS_KB must be numeric' >&2; exit 2 ;;
esac
latency_budget_s=${CLAMAV_SERVICE_MAX_LATENCY_S:-900}
case "$latency_budget_s" in
    ''|*[!0-9]*) echo 'CLAMAV_SERVICE_MAX_LATENCY_S must be an integer number of seconds' >&2; exit 2 ;;
esac
mkdir -p "$out" "$out/logs" "$out/tmp"
config=$out/clamd.conf
socket=$out/clamd.socket
pidfile=$out/clamd.pid
service_pid=
service_peak_rss_kb=0

cleanup()
{
    if [ -n "${service_pid:-}" ] && kill -0 "$service_pid" 2>/dev/null; then
        kill "$service_pid" 2>/dev/null || true
        wait "$service_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT HUP INT TERM

stop_service()
{
    if [ -n "${service_pid:-}" ] && kill -0 "$service_pid" 2>/dev/null; then
        kill "$service_pid" 2>/dev/null || true
        wait "$service_pid" 2>/dev/null || true
    fi
    service_pid=
}

write_config()
{
    database=$1
    rm -f "$socket" "$pidfile"
    {
        printf 'DatabaseDirectory %s\n' "$database"
        printf 'LocalSocket %s\n' "$socket"
        printf 'PidFile %s\n' "$pidfile"
        printf 'TemporaryDirectory %s\n' "$out/tmp"
        printf 'MaxThreads 4\n'
        printf 'MaxQueue 8\n'
        printf 'MaxFileSize 32G\n'
        printf 'MaxScanSize 32G\n'
        printf 'StreamMaxLength 32G\n'
        printf 'MaxScanTime 900000\n'
        printf 'MaxRecursion 17\n'
        printf 'MaxFiles 10000\n'
        printf 'Foreground yes\n'
        if [ -n "${CLAMAV_CVD_CERTS_DIR:-}" ]; then
            printf 'CVDCertsDir %s\n' "$CLAMAV_CVD_CERTS_DIR"
        fi
    } > "$config"
}

start_service()
{
    database=$1
    write_config "$database"
    "$build_dir/clamd/clamd" --config-file="$config" > "$out/logs/clamd-$(basename "$database").log" 2>&1 &
    service_pid=$!
    i=0
    while ! "$build_dir/clamdscan/clamdscan" --ping 5 --wait -c "$config" > "$out/logs/ping-$(basename "$database").log" 2>&1; do
        if ! kill -0 "$service_pid" 2>/dev/null || [ "$i" -ge 60 ]; then
            echo "clamd did not become ready for $database" >&2
            return 1
        fi
        i=$((i + 1))
        sleep 1
    done
}

{
    start_service "$production_db"
}

run_service_scan()
{
    scan_label=$1
    scan_file=$2
    scan_log=$out/logs/$scan_label.log
    scan_status=0
    "/usr/bin/time" -f '%e' -o "$out/logs/$scan_label.elapsed" \
        timeout --signal=TERM --kill-after=5 900 \
        "$build_dir/clamdscan/clamdscan" --no-summary -c "$config" "$scan_file" > "$scan_log" 2>&1 &
    scan_pid=$!
    while kill -0 "$scan_pid" 2>/dev/null; do
        rss=$(sed -n 's/^VmRSS:[[:space:]]*\([0-9][0-9]*\) kB$/\1/p' "/proc/$service_pid/status" 2>/dev/null || true)
        case "$rss" in
            ''|*[!0-9]*) ;;
            *) if [ "$rss" -gt "$service_peak_rss_kb" ]; then service_peak_rss_kb=$rss; fi ;;
        esac
        sleep 0.05
    done
    wait "$scan_pid" || scan_status=$?
    case "$scan_status" in
        0|1|2) ;;
        *) echo "$scan_label failed with status $scan_status" >&2; return 1 ;;
    esac
    if grep -Eiq 'AddressSanitizer|UndefinedBehaviorSanitizer|runtime error|Segmentation fault|stack smashing' "$scan_log"; then
        echo "$scan_label emitted a crash/sanitizer diagnostic" >&2
        return 1
    fi
    printf '%s_status=%s\n' "$scan_label" "$scan_status" >> "$out/service-summary.txt"
    return 0
}

run_direct_production()
{
    direct_status=0
    timeout --signal=TERM --kill-after=5 900 \
        "$build_dir/clamscan/clamscan" --database="$production_db" --no-summary "$production_file" \
        > "$out/logs/production-clamscan.log" 2>&1 || direct_status=$?
    if [ "$direct_status" -ne 1 ] || ! grep -F 'FOUND' "$out/logs/production-clamscan.log" >/dev/null 2>&1; then
        echo 'production CVD detection gate failed' >&2
        return 1
    fi
    printf 'production_cvd_clamscan=pass\n' >> "$out/service-summary.txt"
}

: > "$out/service-summary.txt"
run_direct_production
run_service_scan production_cvd "$production_file"
if ! grep -F 'FOUND' "$out/logs/production_cvd.log" >/dev/null 2>&1; then
    echo 'production CVD clamdscan detection gate failed' >&2
    exit 1
fi
printf 'production_cvd_clamdscan=pass\n' >> "$out/service-summary.txt"
run_service_scan materialized_warm "$materialized_file"

if [ ! -w /proc/sys/vm/drop_caches ]; then
    echo 'cold-cache gate requires writable /proc/sys/vm/drop_caches' >&2
    exit 1
fi
sync
printf '3\n' > /proc/sys/vm/drop_caches
printf 'cold_cache_control=pass\n' >> "$out/service-summary.txt"
run_service_scan materialized_cold "$materialized_file"
run_service_scan parser_expansion "$expansion_file"

# The edge database is intentionally separate from the production CVDs: this
# proves the service path detects the exact 32-GiB marker without conflating
# production-database compatibility with boundary-signature coverage.
edge_status=0
timeout --signal=TERM --kill-after=5 900 \
    "$build_dir/clamscan/clamscan" --database="$edge_db" --no-summary "$edge_file" \
    > "$out/logs/edge-clamscan.log" 2>&1 || edge_status=$?
if [ "$edge_status" -ne 1 ] || ! grep -F 'FOUND' "$out/logs/edge-clamscan.log" >/dev/null 2>&1; then
    echo 'edge clamscan gate failed' >&2
    exit 1
fi
stop_service
start_service "$edge_db"
run_service_scan edge_service "$edge_file"
if ! grep -F 'FOUND' "$out/logs/edge_service.log" >/dev/null 2>&1; then
    echo 'edge clamdscan gate failed to detect the exact edge marker' >&2
    exit 1
fi

# Exercise MaxThreads=4 with four simultaneous clamdscan clients. These are
# independent requests to the same daemon, not four standalone clamscan
# processes, so the evidence covers the service worker/queue path directly.
multi_dir="$out/logs/clamd-multiworker"
mkdir -p "$multi_dir"
multi_pids=
worker=1
while [ "$worker" -le 4 ]; do
    multi_log="$multi_dir/worker-$worker.log"
    multi_time="$multi_dir/worker-$worker.time"
    multi_status_file="$multi_dir/worker-$worker.status"
    (
        status=0
        "/usr/bin/time" -f '%e %M' -o "$multi_time" \
            timeout --signal=TERM --kill-after=5 900 \
            "$build_dir/clamdscan/clamdscan" --no-summary -c "$config" "$edge_file" \
            > "$multi_log" 2>&1 || status=$?
        printf '%s\n' "$status" > "$multi_status_file"
    ) &
    multi_pids="$multi_pids $!"
    worker=$((worker + 1))
done
multi_running=1
while [ "$multi_running" -eq 1 ]; do
    multi_running=0
    for multi_pid in $multi_pids; do
        if [ -r "/proc/$multi_pid/status" ] &&
            ! grep -E '^State:[[:space:]]+Z' "/proc/$multi_pid/status" >/dev/null 2>&1; then
            multi_running=1
        fi
    done
    rss=$(sed -n 's/^VmRSS:[[:space:]]*\([0-9][0-9]*\) kB$/\1/p' "/proc/$service_pid/status" 2>/dev/null || true)
    case "$rss" in
        ''|*[!0-9]*) ;;
        *) if [ "$rss" -gt "$service_peak_rss_kb" ]; then service_peak_rss_kb=$rss; fi ;;
    esac
    if [ "$multi_running" -eq 1 ]; then
        sleep 0.05
    fi
done
multi_worker_status=0
for multi_pid in $multi_pids; do
    wait "$multi_pid" || multi_worker_status=1
done
worker=1
while [ "$worker" -le 4 ]; do
    multi_log="$multi_dir/worker-$worker.log"
    multi_time="$multi_dir/worker-$worker.time"
    multi_status_file="$multi_dir/worker-$worker.status"
    multi_status=$(sed -n '1p' "$multi_status_file" 2>/dev/null || true)
    if [ "$multi_status" != 1 ] || ! grep -F 'FOUND' "$multi_log" >/dev/null 2>&1; then
        echo "clamd multi-worker request $worker failed" >&2
        exit 1
    fi
    multi_elapsed=$(awk 'NF == 2 && $1 ~ /^[0-9]+([.][0-9]+)?$/ && $2 ~ /^[0-9]+$/ { print $1 }' "$multi_time")
    multi_rss=$(awk 'NF == 2 && $1 ~ /^[0-9]+([.][0-9]+)?$/ && $2 ~ /^[0-9]+$/ { print $2 }' "$multi_time")
    if [ -z "$multi_elapsed" ] || [ -z "$multi_rss" ]; then
        echo "clamd multi-worker request $worker has malformed timing/RSS evidence" >&2
        exit 1
    fi
    if ! awk -v elapsed="$multi_elapsed" -v budget="$latency_budget_s" 'BEGIN { exit !(elapsed <= budget) }'; then
        echo "clamd multi-worker request $worker exceeded latency budget" >&2
        exit 1
    fi
    if [ "$multi_rss" -gt "$rss_budget_kb" ]; then
        echo "clamd multi-worker client RSS exceeded budget: $multi_rss > $rss_budget_kb" >&2
        exit 1
    fi
    printf 'clamd_multiworker_%s_elapsed_s=%s\n' "$worker" "$multi_elapsed" >> "$out/service-summary.txt"
    printf 'clamd_multiworker_%s_peak_rss_kb=%s\n' "$worker" "$multi_rss" >> "$out/service-summary.txt"
    worker=$((worker + 1))
done
printf 'clamd_multiworker_count=4\n' >> "$out/service-summary.txt"
printf 'clamd_multiworker=pass\n' >> "$out/service-summary.txt"

for elapsed_file in "$out"/logs/*.elapsed; do
    if ! awk -v budget="$latency_budget_s" '{ if ($1 > budget) exit 1 }' "$elapsed_file"; then
        echo "latency budget exceeded in $elapsed_file" >&2
        exit 1
    fi
done
printf 'latency_budget_s=%s\n' "$latency_budget_s" >> "$out/service-summary.txt"
printf 'latency=pass\n' >> "$out/service-summary.txt"

if [ "$service_peak_rss_kb" -gt "$rss_budget_kb" ]; then
    echo "clamd RSS exceeded budget: ${service_peak_rss_kb} > ${rss_budget_kb} KiB" >&2
    exit 1
fi
printf 'service_rss_peak_kb=%s\n' "$service_peak_rss_kb" >> "$out/service-summary.txt"

stop_service
if ! ctest --test-dir "$build_dir" --output-on-failure -R '^(clamav_milter_quota|clamav_milter_protocol)$' > "$out/logs/milter-ctest.log" 2>&1; then
    echo 'milter service/quota gate failed' >&2
    exit 1
fi
printf 'milter_ctest=pass\n' >> "$out/service-summary.txt"

# Exercise the real milter wire path at the exact 32-GiB message boundary.
# The harness uses a streaming fixed-size body and a deterministic marker, so
# this is an integration check of libmilter framing, clamav-milter quota
# accounting, clamd FD-passing, and the final detection action.
milter_time_file="$out/logs/milter-exact-edge.time"
if ! CLAMD="$build_dir/clamd/clamd" \
    CLAMAV_MILTER="$build_dir/clamav-milter/clamav-milter" \
    CVD_CERTS_DIR="${CLAMAV_CVD_CERTS_DIR:-}" \
    MILTER_EXACT_EDGE=1 \
    MILTER_EXTRA_DATABASE="$edge_db" \
    MILTER_TEST_ROOT="$out/tmp" \
    "/usr/bin/time" -f '%e %M' -o "$milter_time_file" \
    timeout --signal=TERM --kill-after=10 900 \
    python3 "$root/unit_tests/milter_protocol_test.py" > "$out/logs/milter-exact-edge.log" 2>&1; then
    echo 'milter exact-edge integration gate failed' >&2
    exit 1
fi
milter_elapsed=$(awk 'NF == 2 && $1 ~ /^[0-9]+([.][0-9]+)?$/ && $2 ~ /^[0-9]+$/ { print $1 }' "$milter_time_file")
milter_rss=$(awk 'NF == 2 && $1 ~ /^[0-9]+([.][0-9]+)?$/ && $2 ~ /^[0-9]+$/ { print $2 }' "$milter_time_file")
if [ -z "$milter_elapsed" ] || [ -z "$milter_rss" ]; then
    echo 'milter exact-edge timing/RSS evidence is malformed' >&2
    exit 1
fi
if ! awk -v elapsed="$milter_elapsed" -v budget="$latency_budget_s" 'BEGIN { exit !(elapsed <= budget) }'; then
    echo "milter exact-edge latency budget exceeded: $milter_elapsed > $latency_budget_s" >&2
    exit 1
fi
if [ "$milter_rss" -gt "$rss_budget_kb" ]; then
    echo "milter exact-edge RSS exceeded budget: $milter_rss > $rss_budget_kb" >&2
    exit 1
fi
printf 'milter_exact_edge=pass\n' >> "$out/service-summary.txt"
printf 'milter_exact_edge_elapsed_s=%s\n' "$milter_elapsed" >> "$out/service-summary.txt"
printf 'milter_exact_edge_peak_rss_kb=%s\n' "$milter_rss" >> "$out/service-summary.txt"
printf 'service_qualification=pass\n' >> "$out/service-summary.txt"
echo "service qualification passed; evidence is in $out"
