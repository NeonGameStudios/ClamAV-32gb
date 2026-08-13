#!/bin/sh

# Execute the large-file release gates against an externally built clamscan.
# The output directory must be outside the source tree so evidence and build
# products cannot be accidentally committed.
#
# Usage:
#   tools/largefile_runtime_gate.sh CLAMSCAN OUTPUT_DIRECTORY RSS_BUDGET_KB
#
# Optional environment:
#   CLAMAV_SANITIZER_CLAMSCAN  ASan/UBSan clamscan to run through the same POC
#   CLAMAV_CONCURRENCY_LEVELS  whitespace-separated worker counts (default 1 2 4)
#   CLAMAV_CONCURRENCY_FILE    must remain 32g-edge.bin for release evidence
#   CLAMAV_MAX_TEMP_BYTES      fail if a POC case exceeds this temp footprint
#   CLAMAV_RUN_CANCELLATION    run the one-second TERM cancellation gate (default 1)
#   CLAMAV_MIN_AVAILABLE_KB    require this much effective host/cgroup headroom
#   CLAMAV_MAX_SCAN_TIME_MS    uint32 per-file deadline in milliseconds (default 900000)
#   CLAMAV_SOURCE_REPOSITORY   immutable source repository identifier for non-GitHub runs
#   CLAMAV_CVD_CERTS_DIR       CA directory for a build-tree scanner

set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: $0 CLAMSCAN OUTPUT_DIRECTORY RSS_BUDGET_KB" >&2
    exit 2
fi

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
clamscan=$1
requested_out=$2
rss_budget_kb=$3
sanitizer_clamscan=${CLAMAV_SANITIZER_CLAMSCAN:-}
require_sanitizer=${CLAMAV_REQUIRE_SANITIZER:-1}
concurrency_levels=${CLAMAV_CONCURRENCY_LEVELS:-"1 2 4"}
concurrency_file=${CLAMAV_CONCURRENCY_FILE:-32g-edge.bin}
run_cancellation=${CLAMAV_RUN_CANCELLATION:-1}
min_available_kb=${CLAMAV_MIN_AVAILABLE_KB:-0}
max_scan_time_ms=${CLAMAV_MAX_SCAN_TIME_MS:-900000}
cvd_certs_dir=${CLAMAV_CVD_CERTS_DIR:-${CVD_CERTS_DIR:-}}

case "$rss_budget_kb" in
    ''|*[!0-9]*)
        echo "RSS_BUDGET_KB must be a non-negative integer" >&2
        exit 2
        ;;
esac
case "$require_sanitizer" in
    0|1) ;;
    *)
        echo "CLAMAV_REQUIRE_SANITIZER must be 0 or 1" >&2
        exit 2
        ;;
esac
case "$run_cancellation" in
    0|1) ;;
    *)
        echo "CLAMAV_RUN_CANCELLATION must be 0 or 1" >&2
        exit 2
        ;;
esac
case "$min_available_kb" in
    ''|*[!0-9]*)
        echo "CLAMAV_MIN_AVAILABLE_KB must be a non-negative integer" >&2
        exit 2
        ;;
esac
case "$max_scan_time_ms" in
    ''|*[!0-9]*|0*)
        echo "CLAMAV_MAX_SCAN_TIME_MS must be a canonical integer from 1 through 4294967295" >&2
        exit 2
        ;;
esac
if [ "${#max_scan_time_ms}" -gt 10 ] ||
    { [ "${#max_scan_time_ms}" -eq 10 ] && [ "$max_scan_time_ms" -gt 4294967295 ]; }; then
    echo "CLAMAV_MAX_SCAN_TIME_MS must be a canonical integer from 1 through 4294967295" >&2
    exit 2
fi
if [ "$concurrency_file" != 32g-edge.bin ]; then
    echo "release concurrency evidence must use 32g-edge.bin (requested $concurrency_file)" >&2
    exit 2
fi
if [ -n "$cvd_certs_dir" ]; then
    if [ ! -d "$cvd_certs_dir" ]; then
        echo "CLAMAV_CVD_CERTS_DIR is not a directory: $cvd_certs_dir" >&2
        exit 2
    fi
    # The POC consumes CLAMAV_CVD_CERTS_DIR and direct scanner invocations
    # consume CVD_CERTS_DIR. Keep every gate invocation on the same trust
    # configuration.
    CLAMAV_CVD_CERTS_DIR=$cvd_certs_dir
    CVD_CERTS_DIR=$cvd_certs_dir
    export CLAMAV_CVD_CERTS_DIR CVD_CERTS_DIR
fi
CLAMAV_MAX_SCAN_TIME_MS=$max_scan_time_ms
export CLAMAV_MAX_SCAN_TIME_MS

if [ ! -x "$clamscan" ]; then
    echo "CLAMSCAN is not executable: $clamscan" >&2
    exit 2
fi
if [ -n "$sanitizer_clamscan" ] && [ ! -x "$sanitizer_clamscan" ]; then
    echo "CLAMAV_SANITIZER_CLAMSCAN is not executable: $sanitizer_clamscan" >&2
    exit 2
fi

case "$requested_out" in
    /*) out=$requested_out ;;
    *) out=$(CDPATH= cd -- "$(dirname "$requested_out")" && pwd)/$(basename "$requested_out") ;;
esac
case "$out" in
    "$root"|"$root"/*)
        echo "runtime-gate output must be outside the source tree: $out" >&2
        exit 2
        ;;
esac
mkdir -p "$out"

if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then
    echo "runtime-gate requires Linux x86-64 (found $(uname -s)/$(uname -m))" >&2
    exit 1
fi

if ! command -v file >/dev/null 2>&1 || ! command -v sha256sum >/dev/null 2>&1 ||
    ! command -v git >/dev/null 2>&1; then
    echo "runtime-gate requires file, sha256sum, and git for build/source identity evidence" >&2
    exit 2
fi

if ! source_commit=$(git -C "$root" rev-parse --verify HEAD 2>/dev/null); then
    echo "runtime-gate requires a Git checkout with an immutable source commit" >&2
    exit 2
fi
case "$source_commit" in
    *[!0-9a-fA-F]*|'')
        echo "runtime-gate obtained an invalid source commit: $source_commit" >&2
        exit 2
        ;;
esac
if [ "${#source_commit}" -ne 40 ] && [ "${#source_commit}" -ne 64 ]; then
    echo "runtime-gate obtained an invalid source commit length: ${#source_commit}" >&2
    exit 2
fi
if [ -n "$(git -C "$root" status --porcelain --untracked-files=normal)" ]; then
    echo "runtime-gate refuses a dirty source tree" >&2
    exit 2
fi
if [ -n "${GITHUB_SHA:-}" ] && [ "$GITHUB_SHA" != "$source_commit" ]; then
    echo "runtime-gate source commit does not match GITHUB_SHA" >&2
    exit 2
fi

scanner_dir=$(CDPATH= cd -- "$(dirname "$clamscan")" && pwd)
build_dir=$(CDPATH= cd -- "$scanner_dir/.." && pwd)
cmake_cache=$build_dir/CMakeCache.txt
if [ ! -s "$cmake_cache" ]; then
    echo "runtime-gate requires the scanner's CMakeCache.txt: $cmake_cache" >&2
    exit 2
fi

artifacts=$out/artifacts
provenance=$out/provenance
mkdir -p "$artifacts" "$provenance"
cp "$clamscan" "$artifacts/clamscan"
cp "$cmake_cache" "$provenance/CMakeCache.txt"
cp "$root/Cargo.lock" "$provenance/Cargo.lock"
for provenance_file in \
    largefile_runtime_gate.sh \
    largefile_runtime_evidence_check.sh \
    largefile_host_preflight.sh \
    largefile_boundary_corpus.sh \
    largefile_poc.sh; do
    cp "$root/tools/$provenance_file" "$provenance/$provenance_file"
done
if [ -n "$sanitizer_clamscan" ]; then
    cp "$sanitizer_clamscan" "$artifacts/clamscan-sanitizer"
fi

scanner_sha256=$(sha256sum "$artifacts/clamscan" | awk '{ print $1 }')
cargo_lock_sha256=$(sha256sum "$provenance/Cargo.lock" | awk '{ print $1 }')
cmake_cache_sha256=$(sha256sum "$provenance/CMakeCache.txt" | awk '{ print $1 }')
source_repository=${CLAMAV_SOURCE_REPOSITORY:-${GITHUB_REPOSITORY:-unavailable}}
if [ "$source_repository" = unavailable ]; then
    echo "runtime-gate requires GITHUB_REPOSITORY or CLAMAV_SOURCE_REPOSITORY" >&2
    exit 2
fi

metadata=$out/build-identity.txt
{
    printf 'utc='; date -u '+%Y-%m-%dT%H:%M:%SZ'
    printf 'uname='; uname -a
    printf 'arch='; uname -m
    printf 'rss_budget_kb=%s\n' "$rss_budget_kb"
    printf 'min_available_kb=%s\n' "$min_available_kb"
    printf 'max_scan_time_ms=%s\n' "$max_scan_time_ms"
    printf 'concurrency_levels=%s\n' "$concurrency_levels"
    printf 'concurrency_file=%s\n' "$concurrency_file"
    printf 'source_commit=%s\n' "$source_commit"
    printf 'source_tree_clean=yes\n'
    printf 'source_repository=%s\n' "$source_repository"
    printf 'cvd_certs_dir=%s\n' "${cvd_certs_dir:-default}"
    printf 'github_sha=%s\n' "${GITHUB_SHA:-unavailable}"
    printf 'github_ref=%s\n' "${GITHUB_REF:-unavailable}"
    printf 'github_run_id=%s\n' "${GITHUB_RUN_ID:-unavailable}"
    printf 'github_run_attempt=%s\n' "${GITHUB_RUN_ATTEMPT:-unavailable}"
    printf 'scanner_path=artifacts/clamscan\n'
    printf 'scanner_sha256=%s\n' "$scanner_sha256"
    printf 'cargo_lock_sha256=%s\n' "$cargo_lock_sha256"
    printf 'cmake_cache_sha256=%s\n' "$cmake_cache_sha256"
    file "$artifacts/clamscan"
    "$artifacts/clamscan" --version
    if [ -n "$sanitizer_clamscan" ]; then
        sanitizer_scanner_sha256=$(sha256sum "$artifacts/clamscan-sanitizer" | awk '{ print $1 }')
        printf 'sanitizer_scanner_path=artifacts/clamscan-sanitizer\n'
        printf 'sanitizer_scanner_sha256=%s\n' "$sanitizer_scanner_sha256"
        file "$artifacts/clamscan-sanitizer"
        "$artifacts/clamscan-sanitizer" --version
    fi
} > "$metadata" 2>&1

preflight_dir=$out/host-preflight
if "$root/tools/largefile_host_preflight.sh" "$preflight_dir" "$min_available_kb" > "$out/host-preflight.log" 2>&1; then
    printf 'host_preflight=pass\n' >> "$metadata"
else
    printf 'host_preflight=fail\n' >> "$metadata"
    echo "host preflight failed; see $out/host-preflight.log and $preflight_dir/host-preflight.txt" >&2
    exit 1
fi

if ! file "$clamscan" | grep -E 'ELF .*x86-64' >/dev/null 2>&1; then
    echo "scanner is not an x86-64 ELF executable; see $metadata" >&2
    exit 1
fi

corpus=$out/corpus
mkdir -p "$corpus"
"$root/tools/largefile_boundary_corpus.sh" "$corpus" > "$out/corpus.log" 2>&1

failures=0
poc_out=$out/poc
if "$root/tools/largefile_poc.sh" "$clamscan" "$corpus" "$poc_out" > "$out/poc.log" 2>&1; then
    printf 'largefile_poc=pass\n' >> "$metadata"
else
    printf 'largefile_poc=fail\n' >> "$metadata"
    failures=$((failures + 1))
fi

results=$poc_out/results.tsv
if [ -n "${CLAMAV_MAX_TEMP_BYTES:-}" ] && [ -f "$results" ]; then
    case "$CLAMAV_MAX_TEMP_BYTES" in
        ''|*[!0-9]*)
            echo "CLAMAV_MAX_TEMP_BYTES must be a non-negative integer" >&2
            exit 2
            ;;
    esac
    if awk -F '\t' -v budget="$CLAMAV_MAX_TEMP_BYTES" 'NR > 1 && $12 > budget { bad = 1 } END { exit bad }' "$results"; then
        printf 'temp_budget=pass\n' >> "$metadata"
    else
        printf 'temp_budget=fail\n' >> "$metadata"
        failures=$((failures + 1))
    fi
fi

if [ "$run_cancellation" -eq 1 ]; then
    cancellation_log=$out/cancellation.log
    cancellation_status=0
    if command -v timeout >/dev/null 2>&1; then
        timeout --signal=TERM --kill-after=5 1 \
            "$clamscan" \
            --database="$poc_out/db" \
            --max-filesize=32G \
            --max-scansize=32G \
            --max-scantime="$max_scan_time_ms" \
            --debug \
            --no-summary \
            "$corpus/32g-edge.bin" > "$cancellation_log" 2>&1 || cancellation_status=$?
    else
        cancellation_status=127
        echo 'timeout command is required for the cancellation gate' > "$cancellation_log"
    fi
    case "$cancellation_status" in
        124|137|143) printf 'cancellation=pass status=%s\n' "$cancellation_status" >> "$metadata" ;;
        *)
            printf 'cancellation=fail status=%s\n' "$cancellation_status" >> "$metadata"
            failures=$((failures + 1))
            ;;
    esac
else
    printf 'cancellation=not-required\n' >> "$metadata"
fi

# A file one byte above the policy ceiling must be rejected as an oversized
# input. This is separate from the positive POC because it must not be
# expected to produce a signature match.
policy_file=$corpus/32g-plus-one.bin
policy_log=$out/32g-plus-one.log
truncate -s 34359738369 "$policy_file"
policy_status=0
"$clamscan" \
    --database="$poc_out/db" \
    --max-filesize=32G \
    --max-scansize=32G \
    --max-scantime="$max_scan_time_ms" \
    --alert-exceeds-max \
    --debug \
    --no-summary \
    "$policy_file" > "$policy_log" 2>&1 || policy_status=$?
if [ "$policy_status" -eq 1 ] && grep -E 'MaxFileSize|Max file size|exceeds the maximum file size' "$policy_log" >/dev/null 2>&1; then
    printf 'policy_32g_plus_one=pass\n' >> "$metadata"
else
    printf 'policy_32g_plus_one=fail status=%s\n' "$policy_status" >> "$metadata"
    failures=$((failures + 1))
fi

concurrency_input=$corpus/$concurrency_file
if [ ! -f "$concurrency_input" ]; then
    echo "concurrency input not found: $concurrency_input" >&2
    exit 2
fi

concurrency_db=$poc_out/db
concurrency_failures=0
if [ ! -x /usr/bin/time ] || ! /usr/bin/time -v true >/dev/null 2>&1; then
    echo "GNU /usr/bin/time -v is required for auditable concurrency RSS evidence" >&2
    exit 2
fi
for level in $concurrency_levels; do
    case "$level" in
        ''|*[!0-9]*)
            echo "invalid concurrency level: $level" >&2
            exit 2
            ;;
    esac
    if [ "$level" -lt 1 ]; then
        echo "concurrency levels must be positive: $level" >&2
        exit 2
    fi
    level_dir=$out/concurrency/$level
    mkdir -p "$level_dir"
    pids=
    worker=1
    while [ "$worker" -le "$level" ]; do
        log=$level_dir/worker-$worker.log
        rss_record=$level_dir/worker-$worker.rss-kb
        (
            status=0
            /usr/bin/time -v "$clamscan" \
                --database="$concurrency_db" \
                --max-filesize=32G \
                --max-scansize=32G \
                --max-scantime="$max_scan_time_ms" \
                --no-summary \
                "$concurrency_input" > "$log" 2>&1 || status=$?
            rss=$(sed -n 's/^[[:space:]]*Maximum resident set size (kbytes): \([0-9][0-9]*\)$/\1/p' "$log" | tail -1)
            case "$rss" in
                ''|*[!0-9]*) exit 1 ;;
            esac
            printf '%s\n' "$rss" > "$rss_record"
            if [ "$status" -ne 1 ] || ! grep -F 'FOUND' "$log" >/dev/null 2>&1; then
                exit 1
            fi
        ) &
        pids="$pids $!"
        worker=$((worker + 1))
    done

    level_status=0
    for pid in $pids; do
        if ! wait "$pid"; then
            level_status=1
        fi
    done

    level_rss=0
    worker=1
    while [ "$worker" -le "$level" ]; do
        log=$level_dir/worker-$worker.log
        rss_record=$level_dir/worker-$worker.rss-kb
        if [ ! -s "$log" ] || [ ! -s "$rss_record" ]; then
            level_status=1
        else
            rss=$(sed -n '1p' "$rss_record")
            case "$rss" in
                ''|*[!0-9]*) level_status=1 ;;
                *) level_rss=$((level_rss + rss)) ;;
            esac
        fi
        worker=$((worker + 1))
    done
    log_count=$(find "$level_dir" -maxdepth 1 -type f -name 'worker-*.log' | wc -l | tr -d '[:space:]')
    record_count=$(find "$level_dir" -maxdepth 1 -type f -name 'worker-*.rss-kb' | wc -l | tr -d '[:space:]')
    if [ "$log_count" -ne "$level" ] || [ "$record_count" -ne "$level" ]; then
        level_status=1
    fi
    if [ "$level_rss" -gt "$rss_budget_kb" ]; then
        level_status=1
    fi
    printf 'concurrency_%s=%s rss_sum_kb=%s\n' "$level" "$( [ "$level_status" -eq 0 ] && printf pass || printf fail )" "$level_rss" >> "$metadata"
    if [ "$level_status" -ne 0 ]; then
        concurrency_failures=$((concurrency_failures + 1))
    fi
done
if [ "$concurrency_failures" -ne 0 ]; then
    failures=$((failures + concurrency_failures))
fi

if [ -n "$sanitizer_clamscan" ]; then
    sanitizer_out=$out/sanitizer
    sanitizer_status=0
    ASAN_OPTIONS=${ASAN_OPTIONS:-detect_leaks=1:halt_on_error=1} \
    UBSAN_OPTIONS=${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1} \
        "$root/tools/largefile_poc.sh" "$sanitizer_clamscan" "$corpus" "$sanitizer_out" > "$out/sanitizer.log" 2>&1 || sanitizer_status=$?
    if [ "$sanitizer_status" -eq 0 ] && ! grep -REiq 'AddressSanitizer|UndefinedBehaviorSanitizer|runtime error|SUMMARY:' "$sanitizer_out" >/dev/null 2>&1; then
        printf 'sanitizer=pass\n' >> "$metadata"
    else
        printf 'sanitizer=fail status=%s\n' "$sanitizer_status" >> "$metadata"
        failures=$((failures + 1))
    fi
else
    if [ "$require_sanitizer" -eq 1 ]; then
        printf 'sanitizer=not-run (set CLAMAV_SANITIZER_CLAMSCAN)\n' >> "$metadata"
        failures=$((failures + 1))
    else
        printf 'sanitizer=not-required\n' >> "$metadata"
    fi
fi

if [ "$failures" -ne 0 ]; then
    echo "large-file runtime gates failed: $failures gate(s); evidence is in $out" >&2
    exit 1
fi

printf 'runtime_gate=pass\n' >> "$metadata"
printf 'evidence_manifest=SHA256SUMS\n' >> "$metadata"
(
    cd "$out"
    find . -type f ! -path './corpus/*' ! -name SHA256SUMS -print |
        LC_ALL=C sort |
        while IFS= read -r evidence_file; do
            sha256sum "$evidence_file"
        done
) > "$out/SHA256SUMS"
echo "large-file runtime gates passed; evidence is in $out"
