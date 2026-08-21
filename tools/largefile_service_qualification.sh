#!/bin/sh

# Run the service and workload gates required by audit1.md. This is an
# acceptance gate, not a best-effort smoke test: every input and budget is
# explicit, and the gate fails when cold-cache control or resource measurement is
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
production_db_real=$(CDPATH= cd -- "$production_db" && pwd)
edge_db_real=$(CDPATH= cd -- "$edge_db" && pwd)
if [ "$production_db_real" = "$edge_db_real" ]; then
    echo 'production and edge qualification databases must be separate directories' >&2
    exit 2
fi
if [ ! -f "$oracle_manifest" ]; then
    echo "missing qualification oracle manifest: $oracle_manifest" >&2
    exit 2
fi
if ! command -v timeout >/dev/null 2>&1 || ! command -v awk >/dev/null 2>&1 ||
    ! command -v python3 >/dev/null 2>&1 ||
    ! command -v sha256sum >/dev/null 2>&1 || ! command -v du >/dev/null 2>&1 ||
    [ ! -x /usr/bin/time ]; then
    echo 'timeout, awk, python3, sha256sum, du, and GNU /usr/bin/time are required' >&2
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

write_database_manifest()
{
    database_role=$1
    database_dir=$2
    database_manifest_file=$3
    database_files=$(find "$database_dir" -type f -print | LC_ALL=C sort)
    if [ -z "$database_files" ]; then
        echo "$database_role qualification database contains no regular files" >&2
        return 1
    fi
    if find "$database_dir" -type l -print -quit | grep . >/dev/null 2>&1; then
        echo "$database_role qualification database contains symlinks" >&2
        return 1
    fi
    : > "$database_manifest_file"
    while IFS= read -r database_file; do
        [ -n "$database_file" ] || continue
        database_relative=${database_file#"$database_dir"/}
        database_size=$(file_size "$database_file")
        case "$database_size" in
            ''|*[!0-9]*)
                echo "$database_role qualification database has an invalid size: $database_file" >&2
                return 1
                ;;
        esac
        database_sha256=$(sha256sum "$database_file" | awk '{ print $1 }')
        case "$database_sha256" in
            ''|*[!0-9a-fA-F]*)
                echo "$database_role qualification database hash failed: $database_file" >&2
                return 1
                ;;
        esac
        printf '%s\t%s\t%s\n' "$database_relative" "$database_size" "$database_sha256" >> "$database_manifest_file"
    done <<EOF
$database_files
EOF
}

verify_database_manifest()
{
    database_role=$1
    database_dir=$2
    database_before=$3
    database_after=$out/database-manifest-$database_role-after.txt
    write_database_manifest "$database_role" "$database_dir" "$database_after"
    if ! cmp -s "$database_before" "$database_after"; then
        echo "$database_role qualification database changed during the gate" >&2
        return 1
    fi
    printf '%s_database_unchanged=pass\n' "$database_role" >> "$out/service-summary.txt"
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
        if ! python3 - "$oracle_report" "$expected_completion" "$expected_signature" "$expected_type" "$expected_size" <<'PY'
import json
import sys

report_path, expected_completion, expected_signature, expected_type, expected_size = sys.argv[1:]
with open(report_path, "r", encoding="utf-8") as stream:
    rows = [json.loads(line) for line in stream if line.strip()]
if len(rows) != 1:
    raise SystemExit("structured report must contain exactly one JSON object")
report = rows[0]
if report.get("version") != 1:
    raise SystemExit("structured report schema version is not 1")
if report.get("completion") != expected_completion:
    raise SystemExit("structured report completion does not match oracle")
if report.get("file_type") != expected_type:
    raise SystemExit("structured report file type does not match oracle")
for field in (
    "status", "verdict", "root_size", "logical_bytes", "matcher_bytes",
    "contiguous_bytes", "temporary_bytes", "files_scanned",
    "max_recursion_depth", "elapsed_ms", "parser_operations",
    "detector_operations", "skipped_operations",
):
    value = report.get(field)
    if type(value) is not int or value < 0:
        raise SystemExit(f"structured report field {field} is not a non-negative integer")
if report["root_size"] != int(expected_size):
    raise SystemExit("structured report root size does not match oracle")
if expected_signature != "-" and expected_signature not in (report.get("last_alert") or ""):
    raise SystemExit("structured report alert does not match oracle")
if expected_signature == "-" and report.get("verdict") not in (0, 1):
    raise SystemExit("structured report contains an unexpected verdict")
if expected_completion == "COMPLETE":
    if report["status"] != 0:
        raise SystemExit("complete structured report has a non-success status")
    if report["verdict"] not in (0, 1):
        raise SystemExit("complete structured report has a non-clean verdict")
    if report["skipped_operations"] != 0:
        raise SystemExit("complete structured report contains skipped operations")
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
temporary_budget_bytes=68719476736
mkdir -p "$out" "$out/logs" "$out/tmp"
config=$out/clamd.conf
socket=$out/clamd.socket
pidfile=$out/clamd.pid
service_pid=
service_peak_rss_kb=0
service_peak_temp_bytes=0
service_rss_samples=0
service_temp_samples=0
service_resource_measurement_failed=0

measure_service_resources()
{
    if [ -n "${service_pid:-}" ]; then
        if [ ! -r "/proc/$service_pid/status" ]; then
            if kill -0 "$service_pid" 2>/dev/null; then
                service_resource_measurement_failed=1
            fi
        else
            rss=$(sed -n 's/^VmRSS:[[:space:]]*\([0-9][0-9]*\) kB$/\1/p' "/proc/$service_pid/status" 2>/dev/null || true)
            case "$rss" in
                ''|*[!0-9]*) service_resource_measurement_failed=1 ;;
                *)
                    service_rss_samples=$((service_rss_samples + 1))
                    if [ "$rss" -gt "$service_peak_rss_kb" ]; then service_peak_rss_kb=$rss; fi
                    ;;
            esac
        fi
    fi
    current_tmp_bytes=$(du -s -B1 "$out/tmp" 2>/dev/null | awk 'NF >= 1 && $1 ~ /^[0-9]+$/ { print $1; exit }')
    case "$current_tmp_bytes" in
        ''|*[!0-9]*) service_resource_measurement_failed=1 ;;
        *)
            service_temp_samples=$((service_temp_samples + 1))
            if [ "$current_tmp_bytes" -gt "$service_peak_temp_bytes" ]; then service_peak_temp_bytes=$current_tmp_bytes; fi
            ;;
    esac
}

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
    max_threads=$2
    max_queue=$3
    rm -f "$socket" "$pidfile"
    {
        printf 'DatabaseDirectory %s\n' "$database"
        printf 'LocalSocket %s\n' "$socket"
        printf 'PidFile %s\n' "$pidfile"
        printf 'TemporaryDirectory %s\n' "$out/tmp"
        printf 'MaxThreads %s\n' "$max_threads"
        printf 'MaxQueue %s\n' "$max_queue"
        printf 'MaxFileSize 32G\n'
        printf 'MaxScanSize 64G\n'
        printf 'MaxMatcherWork 256G\n'
        printf 'MaxTemporarySize 64G\n'
        printf 'MaxContiguousSize 32G\n'
        printf 'PCREMaxFileSize 32G\n'
        printf 'StreamMaxLength 32G\n'
        printf 'MaxScanTime 900000\n'
        printf 'MaxRecursion 17\n'
        printf 'MaxFiles 10000\n'
        # Keep worker contention visible in the daemon log. The serial queue
        # gate below requires proof that the second request waited for the
        # single certified worker instead of merely completing sequentially
        # by chance in two independent clients.
        printf 'Debug yes\n'
        printf 'LogVerbose yes\n'
        printf 'Foreground yes\n'
        if [ -n "${CLAMAV_CVD_CERTS_DIR:-}" ]; then
            printf 'CVDCertsDir %s\n' "$CLAMAV_CVD_CERTS_DIR"
        fi
    } > "$config"
}

start_service()
{
    database=$1
    max_threads=${2:-1}
    max_queue=${3:-2}
    write_config "$database" "$max_threads" "$max_queue"
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

production_database_manifest=$out/database-manifest-production-before.txt
edge_database_manifest=$out/database-manifest-edge-before.txt
write_database_manifest production "$production_db" "$production_database_manifest"
write_database_manifest edge "$edge_db" "$edge_database_manifest"
production_database_manifest_sha256=$(sha256sum "$production_database_manifest" | awk '{ print $1 }')
edge_database_manifest_sha256=$(sha256sum "$edge_database_manifest" | awk '{ print $1 }')

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
    printf 'production_database_manifest=%s\n' "$(basename "$production_database_manifest")"
    printf 'production_database_manifest_sha256=%s\n' "$production_database_manifest_sha256"
    printf 'edge_database_manifest=%s\n' "$(basename "$edge_database_manifest")"
    printf 'edge_database_manifest_sha256=%s\n' "$edge_database_manifest_sha256"
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
        measure_service_resources
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

run_serial_queue()
{
    queue_dir="$out/logs/clamd-serial-queue"
    mkdir -p "$queue_dir"
    queue_pids=
    worker=1
    while [ "$worker" -le 2 ]; do
        queue_log="$queue_dir/worker-$worker.log"
        queue_report="$out/reports/clamd-serial-queue-$worker.jsonl"
        queue_status_file="$queue_dir/worker-$worker.status"
        (
            status=0
            timeout --signal=TERM --kill-after=5 900 \
                "$build_dir/clamdscan/clamdscan" --no-summary \
                --report-json="$queue_report" -c "$config" "$materialized_file" \
                > "$queue_log" 2>&1 || status=$?
            printf '%s\n' "$status" > "$queue_status_file"
        ) &
        queue_pids="$queue_pids $!"
        # Give the first request a chance to enter the sole worker before the
        # second client is submitted. The daemon log remains the acceptance
        # oracle, so a fast fixture cannot silently satisfy this gate.
        if [ "$worker" -eq 1 ]; then
            sleep 0.1
        fi
        worker=$((worker + 1))
    done

    queue_running=1
    while [ "$queue_running" -eq 1 ]; do
        queue_running=0
        for queue_pid in $queue_pids; do
            if kill -0 "$queue_pid" 2>/dev/null; then
                queue_running=1
            fi
        done
        measure_service_resources
        if [ "$queue_running" -eq 1 ]; then
            sleep 0.05
        fi
    done
    queue_status=0
    for queue_pid in $queue_pids; do
        wait "$queue_pid" || queue_status=1
    done
    if [ "$queue_status" -ne 0 ]; then
        echo 'serial clamd queue clients did not complete' >&2
        return 1
    fi

    worker=1
    while [ "$worker" -le 2 ]; do
        queue_log="$queue_dir/worker-$worker.log"
        queue_report="$out/reports/clamd-serial-queue-$worker.jsonl"
        queue_status_file="$queue_dir/worker-$worker.status"
        if [ ! -s "$queue_log" ] || [ ! -s "$queue_report" ] ||
            [ ! -s "$queue_status_file" ]; then
            echo "serial clamd queue evidence is incomplete for worker $worker" >&2
            return 1
        fi
        oracle_load materialized "$materialized_file"
        oracle_status=$(sed -n '1p' "$queue_status_file")
        check_oracle_output "serial clamd queue request $worker" \
            "$queue_log" "$queue_report" yes no
        worker=$((worker + 1))
    done

    if ! grep -F 'THRMGR: contended, sleeping' \
        "$out/logs/clamd-$(basename "$production_db").log" >/dev/null 2>&1; then
        echo 'serial clamd queue did not record worker contention' >&2
        return 1
    fi
    printf 'serial_worker_count=1\n' >> "$out/service-summary.txt"
    printf 'serial_queue_count=2\n' >> "$out/service-summary.txt"
    printf 'serial_queue=pass\n' >> "$out/service-summary.txt"
}

: > "$out/service-summary.txt"
run_direct_report()
{
    report_label=$1
    report_mode=$2
    python3 "$root/tools/largefile_clamd_report_protocol.py" \
        "$socket" "$production_file" "$oracle_manifest" production "$report_mode" \
        "$out/reports/production_cvd_${report_label}.jsonl"
    printf 'production_cvd_clamdscan_%s=pass\n' "$report_label" >> "$out/service-summary.txt"
}

run_direct_report scanreport scan
run_direct_report contscanreport contscan
run_direct_report multiscanreport multiscan
run_direct_report allmatchscanreport allmatchscan
run_direct_report fildesreport fildes
run_direct_report instreamreport instream
run_direct_production
run_serial_queue
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
start_service "$edge_db" 1 2
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

# Exercise MaxThreads=4 with four simultaneous clamdscan clients. This is a
# separate explicit service profile from the certified one-worker/2-queue
# profile above. These are independent requests to the same daemon, not four
# standalone clamscan processes, so the evidence covers the service
# worker/queue path directly.
stop_service
start_service "$edge_db" 4 8
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
    measure_service_resources
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

if [ "$service_resource_measurement_failed" -ne 0 ]; then
    echo 'service resource measurement failed or produced malformed evidence' >&2
    exit 1
fi
if [ "$service_rss_samples" -eq 0 ]; then
    echo 'service RSS measurement produced no samples' >&2
    exit 1
fi
if [ "$service_temp_samples" -eq 0 ]; then
    echo 'service temporary-space measurement produced no samples' >&2
    exit 1
fi
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
milter_status=0
(
    CLAMD="$build_dir/clamd/clamd" \
        CLAMAV_MILTER="$build_dir/clamav-milter/clamav-milter" \
        CVD_CERTS_DIR="${CLAMAV_CVD_CERTS_DIR:-}" \
        MILTER_EXACT_EDGE=1 \
        MILTER_EXTRA_DATABASE="$edge_db" \
        MILTER_TEST_ROOT="$out/tmp" \
        "/usr/bin/time" -f '%e %M' -o "$milter_time_file" \
        timeout --signal=TERM --kill-after=10 900 \
        python3 "$root/unit_tests/milter_protocol_test.py" > "$out/logs/milter-exact-edge.log" 2>&1 || exit $?
) &
milter_pid=$!
while kill -0 "$milter_pid" 2>/dev/null; do
    measure_service_resources
    sleep 0.05
done
wait "$milter_pid" || milter_status=$?
if [ "$milter_status" -ne 0 ]; then
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
measure_service_resources
verify_database_manifest production "$production_db" "$production_database_manifest"
verify_database_manifest edge "$edge_db" "$edge_database_manifest"
if [ "$service_peak_temp_bytes" -gt "$temporary_budget_bytes" ]; then
    echo "service temporary storage exceeded budget: $service_peak_temp_bytes > $temporary_budget_bytes" >&2
    exit 1
fi
printf 'milter_exact_edge=pass\n' >> "$out/service-summary.txt"
printf 'milter_exact_edge_elapsed_s=%s\n' "$milter_elapsed" >> "$out/service-summary.txt"
printf 'milter_exact_edge_peak_rss_kb=%s\n' "$milter_rss" >> "$out/service-summary.txt"
printf 'service_temp_peak_bytes=%s\n' "$service_peak_temp_bytes" >> "$out/service-summary.txt"
printf 'service_temp_budget_bytes=%s\n' "$temporary_budget_bytes" >> "$out/service-summary.txt"
printf 'service_temp_budget=pass\n' >> "$out/service-summary.txt"
printf 'service_qualification=pass\n' >> "$out/service-summary.txt"
echo "service qualification passed; evidence is in $out"
