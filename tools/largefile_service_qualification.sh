#!/bin/sh

# Run the service and workload gates required by audit1.md. This is an
# acceptance gate, not a best-effort smoke test: every input and budget is
# explicit, and the gate fails when cold-cache control or RSS measurement is
# unavailable.
#
# Usage:
#   tools/largefile_service_qualification.sh BUILD_DIR OUTPUT_DIR \
#       PRODUCTION_DB PRODUCTION_FILE MATERIALIZED_FILE EXPANSION_FILE \
#       EDGE_FILE EDGE_DB ORACLE_MANIFEST

set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)

if [ "$#" -ne 9 ]; then
    echo "usage: $0 BUILD_DIR OUTPUT_DIR PRODUCTION_DB PRODUCTION_FILE MATERIALIZED_FILE EXPANSION_FILE EDGE_FILE EDGE_DB ORACLE_MANIFEST" >&2
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
oracle_manifest=$9

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
if [ ! -f "$oracle_manifest" ]; then
    echo "missing qualification oracle manifest: $oracle_manifest" >&2
    exit 2
fi
if ! command -v timeout >/dev/null 2>&1 || ! command -v awk >/dev/null 2>&1 ||
    ! command -v python3 >/dev/null 2>&1 ||
    ! command -v sha256sum >/dev/null 2>&1 ||
    [ ! -x /usr/bin/time ]; then
    echo 'timeout, awk, python3, sha256sum, and GNU /usr/bin/time are required' >&2
    exit 2
fi

# The oracle is deliberately separate from the source tree. It binds every
# materialized input to its expected size/hash/status/completion/type and, for
# detections, the exact signature token and engine offset. A bare FOUND check
# is not sufficient evidence for a release decision.
if ! awk -F '\t' '
    NR == 1 {
        if (NF != 8 || $1 != "role" || $2 != "expected_size" ||
            $3 != "expected_sha256" || $4 != "expected_exit" ||
            $5 != "expected_completion" || $6 != "expected_signature" ||
            $7 != "expected_offset" || $8 != "expected_type") {
            print "invalid qualification oracle header" > "/dev/stderr"
            bad = 1
        }
        next
    }
    {
        if (NF != 8 || ($1 != "production" && $1 != "materialized" &&
            $1 != "expansion" && $1 != "edge")) {
            print "invalid qualification oracle row at line " NR > "/dev/stderr"
            bad = 1
        }
        if ($2 !~ /^[0-9]+$/ || $3 !~ /^[0-9a-fA-F]{64}$/ ||
            $4 !~ /^[012]$/ ||
            $5 !~ /^(COMPLETE|DETECTION_TERMINATED|LIMIT_INCOMPLETE|UNSUPPORTED|MALFORMED_CONFIRMED|RESOURCE_FAILURE|APPLICATION_ABORT)$/ ||
            $6 == "" || $7 !~ /^([0-9]+|-)$/ ||
            ($6 == "-" && $7 != "-") || ($6 != "-" && $7 == "-") ||
            $8 !~ /^CL_TYPE_[A-Z0-9_]+$/) {
            print "invalid qualification oracle value at line " NR > "/dev/stderr"
            bad = 1
        }
        seen[$1]++
    }
    END {
        for (role in seen)
            if (seen[role] != 1) bad = 1
        if (seen["production"] != 1 || seen["materialized"] != 1 ||
            seen["expansion"] != 1 || seen["edge"] != 1) bad = 1
        exit bad
    }
' "$oracle_manifest"; then
    echo "qualification oracle manifest is invalid: $oracle_manifest" >&2
    exit 2
fi

file_size()
{
    stat -c '%s' "$1" 2>/dev/null || stat -f '%z' "$1"
}

oracle_load()
{
    oracle_role=$1
    oracle_file=$2
    oracle_row=$(awk -F '\t' -v role="$oracle_role" '$1 == role { print; exit }' "$oracle_manifest")
    IFS="$(printf '\t')" read -r expected_role expected_size expected_sha256 expected_exit expected_completion expected_signature expected_offset expected_type <<EOF
$oracle_row
EOF
    actual_size=$(file_size "$oracle_file")
    actual_sha256=$(sha256sum "$oracle_file" | awk '{ print $1 }')
    if [ "$actual_size" != "$expected_size" ] ||
        [ "$(printf '%s' "$actual_sha256" | tr '[:upper:]' '[:lower:]')" != "$(printf '%s' "$expected_sha256" | tr '[:upper:]' '[:lower:]')" ]; then
        echo "$oracle_role input does not match its size/hash oracle" >&2
        return 1
    fi
}

check_oracle_output()
{
    oracle_label=$1
    oracle_log=$2
    oracle_report=${3:-}
    oracle_check_report=${4:-no}
    oracle_check_offset=${5:-no}

    if [ "$oracle_status" -ne "$expected_exit" ]; then
        echo "$oracle_label returned $oracle_status; expected $expected_exit" >&2
        return 1
    fi

    if [ "$expected_signature" = "-" ]; then
        if grep -F 'FOUND' "$oracle_log" >/dev/null 2>&1; then
            echo "$oracle_label produced an unexpected detection" >&2
            return 1
        fi
    else
        if ! grep -F "$expected_signature" "$oracle_log" >/dev/null 2>&1 ||
            ! grep -F 'FOUND' "$oracle_log" >/dev/null 2>&1; then
            echo "$oracle_label did not produce the expected signature oracle" >&2
            return 1
        fi
        if [ "$oracle_check_offset" = yes ] && [ "$expected_offset" != "-" ]; then
            oracle_actual_offset=$(awk \
                -v signed="signature $expected_signature matched at " \
                -v unsigned="signature $expected_signature.UNOFFICIAL matched at " '
                (index($0, signed) || index($0, unsigned)) && match($0, /matched at [0-9][0-9]*/) {
                    print substr($0, RSTART + 11, RLENGTH - 11)
                    exit
                }
            ' "$oracle_log")
            if [ "$oracle_actual_offset" != "$expected_offset" ]; then
                echo "$oracle_label matched at ${oracle_actual_offset:-missing}; expected $expected_offset" >&2
                return 1
            fi
        fi
    fi

    if [ "$oracle_check_report" = yes ]; then
        if [ ! -s "$oracle_report" ]; then
            echo "$oracle_label did not produce a structured report" >&2
            return 1
        fi
        if ! python3 - "$oracle_report" "$expected_completion" "$expected_signature" "$expected_type" <<'PY'
import json
import sys

report_path, expected_completion, expected_signature, expected_type = sys.argv[1:]
with open(report_path, "r", encoding="utf-8") as stream:
    rows = [json.loads(line) for line in stream if line.strip()]
if len(rows) != 1:
    raise SystemExit("structured report must contain exactly one JSON object")
report = rows[0]
if report.get("completion") != expected_completion:
    raise SystemExit("structured report completion does not match oracle")
if report.get("file_type") != expected_type:
    raise SystemExit("structured report file type does not match oracle")
if expected_signature != "-" and expected_signature not in (report.get("last_alert") or ""):
    raise SystemExit("structured report alert does not match oracle")
if expected_signature == "-" and report.get("verdict") not in (0, None):
    raise SystemExit("structured report contains an unexpected verdict")
PY
        then
            echo "$oracle_label structured report did not match its oracle" >&2
            return 1
        fi
    fi
}

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
        printf 'MaxScanSize 64G\n'
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

mkdir -p "$out" "$out/logs" "$out/reports" "$out/tmp"
oracle_load production "$production_file"
oracle_production_size=$expected_size
oracle_production_sha256=$expected_sha256
oracle_production_exit=$expected_exit
oracle_production_completion=$expected_completion
oracle_production_signature=$expected_signature
oracle_production_offset=$expected_offset
oracle_production_type=$expected_type
oracle_load materialized "$materialized_file"
oracle_materialized_size=$expected_size
oracle_materialized_sha256=$expected_sha256
oracle_materialized_exit=$expected_exit
oracle_materialized_completion=$expected_completion
oracle_materialized_signature=$expected_signature
oracle_materialized_offset=$expected_offset
oracle_materialized_type=$expected_type
oracle_load expansion "$expansion_file"
oracle_expansion_size=$expected_size
oracle_expansion_sha256=$expected_sha256
oracle_expansion_exit=$expected_exit
oracle_expansion_completion=$expected_completion
oracle_expansion_signature=$expected_signature
oracle_expansion_offset=$expected_offset
oracle_expansion_type=$expected_type
oracle_load edge "$edge_file"
oracle_edge_size=$expected_size
oracle_edge_sha256=$expected_sha256
oracle_edge_exit=$expected_exit
oracle_edge_completion=$expected_completion
oracle_edge_signature=$expected_signature
oracle_edge_offset=$expected_offset
oracle_edge_type=$expected_type

{
    printf 'oracle_manifest=%s\n' "$oracle_manifest"
    printf 'oracle_production_size=%s\n' "$oracle_production_size"
    printf 'oracle_production_sha256=%s\n' "$oracle_production_sha256"
    printf 'oracle_production_exit=%s\n' "$oracle_production_exit"
    printf 'oracle_production_completion=%s\n' "$oracle_production_completion"
    printf 'oracle_production_signature=%s\n' "$oracle_production_signature"
    printf 'oracle_production_offset=%s\n' "$oracle_production_offset"
    printf 'oracle_production_type=%s\n' "$oracle_production_type"
    printf 'oracle_materialized_size=%s\n' "$oracle_materialized_size"
    printf 'oracle_materialized_sha256=%s\n' "$oracle_materialized_sha256"
    printf 'oracle_materialized_exit=%s\n' "$oracle_materialized_exit"
    printf 'oracle_materialized_completion=%s\n' "$oracle_materialized_completion"
    printf 'oracle_materialized_signature=%s\n' "$oracle_materialized_signature"
    printf 'oracle_materialized_offset=%s\n' "$oracle_materialized_offset"
    printf 'oracle_materialized_type=%s\n' "$oracle_materialized_type"
    printf 'oracle_expansion_size=%s\n' "$oracle_expansion_size"
    printf 'oracle_expansion_sha256=%s\n' "$oracle_expansion_sha256"
    printf 'oracle_expansion_exit=%s\n' "$oracle_expansion_exit"
    printf 'oracle_expansion_completion=%s\n' "$oracle_expansion_completion"
    printf 'oracle_expansion_signature=%s\n' "$oracle_expansion_signature"
    printf 'oracle_expansion_offset=%s\n' "$oracle_expansion_offset"
    printf 'oracle_expansion_type=%s\n' "$oracle_expansion_type"
    printf 'oracle_edge_size=%s\n' "$oracle_edge_size"
    printf 'oracle_edge_sha256=%s\n' "$oracle_edge_sha256"
    printf 'oracle_edge_exit=%s\n' "$oracle_edge_exit"
    printf 'oracle_edge_completion=%s\n' "$oracle_edge_completion"
    printf 'oracle_edge_signature=%s\n' "$oracle_edge_signature"
    printf 'oracle_edge_offset=%s\n' "$oracle_edge_offset"
    printf 'oracle_edge_type=%s\n' "$oracle_edge_type"
} > "$out/oracle-binding.txt"

{
    start_service "$production_db"
}

run_service_scan()
{
    oracle_role=$1
    scan_label=$2
    scan_file=$3
    shift 3
    oracle_load "$oracle_role" "$scan_file"
    scan_log=$out/logs/$scan_label.log
    scan_report=$out/reports/$scan_label.jsonl
    scan_status=0
    "/usr/bin/time" -f '%e' -o "$out/logs/$scan_label.elapsed" \
        timeout --signal=TERM --kill-after=5 900 \
        "$build_dir/clamdscan/clamdscan" --no-summary --report-json="$scan_report" "$@" -c "$config" "$scan_file" > "$scan_log" 2>&1 &
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
    oracle_status=$scan_status
    check_oracle_output "$scan_label" "$scan_log" "$scan_report" yes no
    printf '%s_status=%s\n' "$scan_label" "$scan_status" >> "$out/service-summary.txt"
    return 0
}

run_direct_production()
{
    oracle_load production "$production_file"
    direct_status=0
    report="$out/reports/production-clamscan.jsonl"
    timeout --signal=TERM --kill-after=5 900 \
        "$build_dir/clamscan/clamscan" --database="$production_db" --no-summary --debug --report-json="$report" "$production_file" \
        > "$out/logs/production-clamscan.log" 2>&1 || direct_status=$?
    oracle_status=$direct_status
    if ! check_oracle_output production-clamscan "$out/logs/production-clamscan.log" "$report" yes yes; then
        return 1
    fi
    printf 'production_cvd_clamscan=pass\n' >> "$out/service-summary.txt"
}

: > "$out/service-summary.txt"
run_direct_production
run_service_scan production production_cvd "$production_file"
printf 'production_cvd_clamdscan=pass\n' >> "$out/service-summary.txt"
run_service_scan production production_cvd_fildes "$production_file" --fdpass
printf 'production_cvd_clamdscan_fildes=pass\n' >> "$out/service-summary.txt"
run_service_scan production production_cvd_instream "$production_file" --stream
printf 'production_cvd_clamdscan_instream=pass\n' >> "$out/service-summary.txt"
run_service_scan materialized materialized_warm "$materialized_file"

if [ ! -w /proc/sys/vm/drop_caches ]; then
    echo 'cold-cache gate requires writable /proc/sys/vm/drop_caches' >&2
    exit 1
fi
sync
printf '3\n' > /proc/sys/vm/drop_caches
printf 'cold_cache_control=pass\n' >> "$out/service-summary.txt"
run_service_scan materialized materialized_cold "$materialized_file"
run_service_scan expansion parser_expansion "$expansion_file"

# The edge database is intentionally separate from the production CVDs: this
# proves the service path detects the exact 32-GiB marker without conflating
# production-database compatibility with boundary-signature coverage.
edge_status=0
oracle_load edge "$edge_file"
edge_report="$out/reports/edge-clamscan.jsonl"
timeout --signal=TERM --kill-after=5 900 \
    "$build_dir/clamscan/clamscan" --database="$edge_db" --no-summary --debug --report-json="$edge_report" "$edge_file" \
    > "$out/logs/edge-clamscan.log" 2>&1 || edge_status=$?
oracle_status=$edge_status
if ! check_oracle_output edge-clamscan "$out/logs/edge-clamscan.log" "$edge_report" yes yes; then
    echo 'edge clamscan oracle failed' >&2
    exit 1
fi
stop_service
start_service "$edge_db"
run_service_scan edge edge_contscan "$edge_file"
printf 'edge_clamdscan_contscan=pass\n' >> "$out/service-summary.txt"
run_service_scan edge edge_multiscan "$edge_file" --multiscan
printf 'edge_clamdscan_multiscan=pass\n' >> "$out/service-summary.txt"
run_service_scan edge edge_allmatch "$edge_file" --allmatch
printf 'edge_clamdscan_allmatchscan=pass\n' >> "$out/service-summary.txt"
run_service_scan edge edge_fildes "$edge_file" --fdpass
printf 'edge_clamdscan_fildes=pass\n' >> "$out/service-summary.txt"
run_service_scan edge edge_instream "$edge_file" --stream
printf 'edge_clamdscan_instream=pass\n' >> "$out/service-summary.txt"

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
        multi_report="$out/reports/clamd-multiworker-$worker.jsonl"
        (
            status=0
            "/usr/bin/time" -f '%e %M' -o "$multi_time" \
                timeout --signal=TERM --kill-after=5 900 \
            "$build_dir/clamdscan/clamdscan" --no-summary --report-json="$multi_report" -c "$config" "$edge_file" \
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
    multi_report="$out/reports/clamd-multiworker-$worker.jsonl"
    multi_status=$(sed -n '1p' "$multi_status_file" 2>/dev/null || true)
    oracle_load edge "$edge_file"
    oracle_status=$multi_status
    if ! check_oracle_output "clamd multi-worker request $worker" "$multi_log" "$multi_report" yes no; then
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
