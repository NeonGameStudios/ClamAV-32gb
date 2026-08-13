#!/bin/sh

# Verify a completed large-file runtime-gate artifact directory.
#
# Usage:
#   tools/largefile_runtime_evidence_check.sh OUTPUT_DIRECTORY [sanitizer-required] [levels] RSS_BUDGET_KB

set -eu

if [ "$#" -ne 4 ]; then
    echo "usage: $0 OUTPUT_DIRECTORY [sanitizer-required] [levels] RSS_BUDGET_KB" >&2
    exit 2
fi

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
requested_out=$1
require_sanitizer=${2:-no}
levels=${3:-"1 2 4"}
rss_budget_kb=$4

case "$rss_budget_kb" in
    ''|*[!0-9]*)
        echo "RSS_BUDGET_KB must be a non-negative integer" >&2
        exit 2
        ;;
esac

case "$requested_out" in
    /*) out=$requested_out ;;
    *) out=$(CDPATH= cd -- "$(dirname "$requested_out")" && pwd)/$(basename "$requested_out") ;;
esac
case "$out" in
    "$root"|"$root"/*)
        echo "evidence directory must be outside the source tree: $out" >&2
        exit 2
        ;;
esac

case "$require_sanitizer" in
    yes|no) ;;
    *)
        echo "sanitizer-required must be yes or no" >&2
        exit 2
        ;;
esac

metadata=$out/build-identity.txt
host_preflight=$out/host-preflight/host-preflight.txt
results=$out/poc/results.tsv
policy_log=$out/32g-plus-one.log
cancellation_log=$out/cancellation.log
manifest=$out/SHA256SUMS
scanner_copy=$out/artifacts/clamscan
cmake_cache=$out/provenance/CMakeCache.txt
cargo_lock=$out/provenance/Cargo.lock
for required in "$metadata" "$host_preflight" "$results" "$policy_log" "$cancellation_log" \
    "$manifest" "$scanner_copy" "$cmake_cache" "$cargo_lock"; do
    if [ ! -s "$required" ]; then
        echo "missing runtime evidence: $required" >&2
        exit 1
    fi
done

if ! command -v sha256sum >/dev/null 2>&1; then
    echo 'sha256sum is required to verify runtime evidence' >&2
    exit 2
fi
(
    cd "$out"
    sha256sum -c SHA256SUMS >/dev/null
) || {
    echo 'runtime evidence checksum manifest does not verify' >&2
    exit 1
}
manifest_count=$(awk 'NF == 2 { count++ } END { print count + 0 }' "$manifest")
actual_count=$(find "$out" -type f ! -path "$out/corpus/*" ! -name SHA256SUMS | wc -l | tr -d '[:space:]')
if [ "$manifest_count" -ne "$actual_count" ]; then
    echo "runtime evidence manifest is incomplete: manifest=$manifest_count files=$actual_count" >&2
    exit 1
fi
for provenance_script in \
    largefile_runtime_gate.sh \
    largefile_runtime_evidence_check.sh \
    largefile_host_preflight.sh \
    largefile_boundary_corpus.sh \
    largefile_poc.sh; do
    if [ ! -s "$out/provenance/$provenance_script" ]; then
        echo "missing verifier provenance script: $provenance_script" >&2
        exit 1
    fi
done

grep -F 'host_preflight=pass' "$metadata" >/dev/null 2>&1 || {
    echo 'host preflight did not pass' >&2
    exit 1
}
grep -Fx 'runtime_gate=pass' "$metadata" >/dev/null 2>&1 || {
    echo 'runtime gate does not have an explicit pass marker' >&2
    exit 1
}
grep -E '^memory_total_kb=[1-9][0-9]*$' "$host_preflight" >/dev/null 2>&1 || {
    echo 'host preflight does not record total memory' >&2
    exit 1
}
grep -E '^memory_available_kb=[0-9][0-9]*$' "$host_preflight" >/dev/null 2>&1 || {
    echo 'host preflight does not record available memory' >&2
    exit 1
}
grep -F 'available_memory_check=pass' "$host_preflight" >/dev/null 2>&1 || {
    echo 'host preflight available-memory check did not pass' >&2
    exit 1
}
grep -E '^cgroup_memory_limit_bytes=' "$host_preflight" >/dev/null 2>&1 || {
    echo 'host preflight does not record cgroup memory limit' >&2
    exit 1
}
grep -E '^cgroup_memory_current_bytes=' "$host_preflight" >/dev/null 2>&1 || {
    echo 'host preflight does not record cgroup memory usage' >&2
    exit 1
}
awk -F= '
    $1 == "memory_total_kb" { total = $2; seen_total++ }
    $1 == "memory_available_kb" { available = $2; seen_available++ }
    $1 == "effective_memory_available_kb" { effective = $2; seen_effective++ }
    $1 == "minimum_available_kb" { minimum = $2; seen_minimum++ }
    $1 == "available_memory_check" { check = $2; seen_check++ }
    $1 == "cgroup_memory_limit_bytes" { limit = $2; seen_limit++ }
    $1 == "cgroup_memory_current_bytes" { current = $2; seen_current++ }
    $1 == "cgroup_limit_finite" { finite_reported = $2; seen_finite++ }
    $1 == "cgroup_available_kb" { cgroup_available = $2; seen_cgroup_available++ }
    END {
        if (seen_total != 1 || seen_available != 1 || seen_effective != 1 ||
            seen_minimum != 1 || seen_check != 1 || seen_limit != 1 ||
            seen_current != 1 || seen_finite != 1 ||
            seen_cgroup_available != 1)
            exit 1
        if (total !~ /^[0-9]+$/ || available !~ /^[0-9]+$/ ||
            effective !~ /^[0-9]+$/ || minimum !~ /^[0-9]+$/)
            exit 1

        finite = (limit ~ /^[0-9]+$/ && current ~ /^[0-9]+$/ &&
                  (limit + 0) < (total + 0) * 1048576)
        expected = available + 0
        if (finite) {
            headroom = (limit + 0) - (current + 0)
            if (headroom < 0)
                headroom = 0
            headroom_kb = int(headroom / 1024)
            if (finite_reported != "yes" || cgroup_available !~ /^[0-9]+$/ ||
                (cgroup_available + 0) != headroom_kb)
                exit 1
            if (headroom_kb < expected)
                expected = headroom_kb
        } else if (finite_reported != "no" || cgroup_available != "unlimited") {
            exit 1
        }
        if ((effective + 0) != expected)
            exit 1
        expected_check = (expected >= (minimum + 0)) ? "pass" : "fail"
        if (check != expected_check || check != "pass")
            exit 1
    }
' "$host_preflight" || {
    echo 'host preflight memory and cgroup headroom evidence is inconsistent' >&2
    exit 1
}

grep -F 'arch=x86_64' "$metadata" >/dev/null 2>&1 || {
    echo 'evidence does not identify an x86-64 runner' >&2
    exit 1
}
grep -E 'ELF .*x86-64' "$metadata" >/dev/null 2>&1 || {
    echo 'evidence does not identify an x86-64 scanner' >&2
    exit 1
}
source_commit=$(sed -n 's/^source_commit=//p' "$metadata")
case "$source_commit" in
    ''|*[!0-9a-fA-F]*)
        echo 'evidence does not contain a valid immutable source commit' >&2
        exit 1
        ;;
esac
if [ "${#source_commit}" -ne 40 ] && [ "${#source_commit}" -ne 64 ]; then
    echo 'evidence source commit has an invalid length' >&2
    exit 1
fi
grep -Fx 'source_tree_clean=yes' "$metadata" >/dev/null 2>&1 || {
    echo 'evidence was not produced from a clean source tree' >&2
    exit 1
}
source_repository=$(sed -n 's/^source_repository=//p' "$metadata")
case "$source_repository" in
    ''|unavailable|*[[:space:]]*)
        echo 'evidence does not identify the source repository' >&2
        exit 1
        ;;
esac
grep -E '^source_repository=[^[:space:]]+$' "$metadata" >/dev/null 2>&1 || {
    echo 'evidence does not identify the source repository' >&2
    exit 1
}
github_sha=$(sed -n 's/^github_sha=//p' "$metadata")
if [ "$github_sha" != unavailable ] && [ "$github_sha" != "$source_commit" ]; then
    echo 'evidence GitHub SHA does not match the source commit' >&2
    exit 1
fi
grep -Fx 'scanner_path=artifacts/clamscan' "$metadata" >/dev/null 2>&1 || {
    echo 'evidence scanner path is missing or unexpected' >&2
    exit 1
}
scanner_sha256=$(sha256sum "$scanner_copy" | awk '{ print $1 }')
cargo_lock_sha256=$(sha256sum "$cargo_lock" | awk '{ print $1 }')
cmake_cache_sha256=$(sha256sum "$cmake_cache" | awk '{ print $1 }')
grep -Fx "scanner_sha256=$scanner_sha256" "$metadata" >/dev/null 2>&1 || {
    echo 'copied scanner hash does not match build identity' >&2
    exit 1
}
grep -Fx "cargo_lock_sha256=$cargo_lock_sha256" "$metadata" >/dev/null 2>&1 || {
    echo 'Cargo.lock hash does not match build identity' >&2
    exit 1
}
grep -Fx "cmake_cache_sha256=$cmake_cache_sha256" "$metadata" >/dev/null 2>&1 || {
    echo 'CMake cache hash does not match build identity' >&2
    exit 1
}
grep -F "rss_budget_kb=$rss_budget_kb" "$metadata" >/dev/null 2>&1 || {
    echo 'evidence RSS budget does not match the verifier budget' >&2
    exit 1
}
grep -E '^max_scan_time_ms=[1-9][0-9]*$' "$metadata" >/dev/null 2>&1 || {
    echo 'evidence does not record a positive per-file scan deadline' >&2
    exit 1
}
grep -Fx 'concurrency_file=32g-edge.bin' "$metadata" >/dev/null 2>&1 || {
    echo 'release evidence did not use 32g-edge.bin for concurrency' >&2
    exit 1
}
grep -F 'largefile_poc=pass' "$metadata" >/dev/null 2>&1 || {
    echo 'large-file POC did not pass' >&2
    exit 1
}
grep -F 'policy_32g_plus_one=pass' "$metadata" >/dev/null 2>&1 || {
    echo '32 GiB+1 policy rejection did not pass' >&2
    exit 1
}
grep -E '^cancellation=pass status=(124|137|143)$' "$metadata" >/dev/null 2>&1 || {
    echo 'cancellation gate did not pass' >&2
    exit 1
}
if [ "$require_sanitizer" = yes ]; then
    if [ ! -d "$out/sanitizer" ]; then
        echo 'sanitizer evidence directory is missing' >&2
        exit 1
    fi
    sanitizer_scanner_copy=$out/artifacts/clamscan-sanitizer
    if [ ! -s "$sanitizer_scanner_copy" ]; then
        echo 'copied sanitizer scanner is missing' >&2
        exit 1
    fi
    grep -Fx 'sanitizer_scanner_path=artifacts/clamscan-sanitizer' "$metadata" >/dev/null 2>&1 || {
        echo 'sanitizer scanner identity is missing' >&2
        exit 1
    }
    sanitizer_scanner_sha256=$(sha256sum "$sanitizer_scanner_copy" | awk '{ print $1 }')
    grep -Fx "sanitizer_scanner_sha256=$sanitizer_scanner_sha256" "$metadata" >/dev/null 2>&1 || {
        echo 'copied sanitizer scanner hash does not match build identity' >&2
        exit 1
    }
    grep -F 'sanitizer=pass' "$metadata" >/dev/null 2>&1 || {
        echo 'sanitizer gate did not pass' >&2
        exit 1
    }
    if grep -REiq 'AddressSanitizer|UndefinedBehaviorSanitizer|runtime error|SUMMARY:' "$out/sanitizer" >/dev/null 2>&1; then
        echo 'sanitizer evidence contains a diagnostic' >&2
        exit 1
    fi
else
    grep -E 'sanitizer=(pass|not-required)' "$metadata" >/dev/null 2>&1 || {
        echo 'ordinary evidence has no sanitizer disposition' >&2
        exit 1
    }
fi

awk -F '\t' '
    BEGIN {
        file[1] = "2g-minus.bin"; off[1] = 2147483647; size[1] = 2147483711
        file[2] = "2g.bin";       off[2] = 2147483648; size[2] = 2147483712
        file[3] = "2g-plus.bin";  off[3] = 2147483649; size[3] = 2147483713
        file[4] = "4g-minus-two.bin"; off[4] = 4294967294; size[4] = 4294967358
        file[5] = "4g-minus.bin"; off[5] = 4294967295; size[5] = 4294967359
        file[6] = "4g.bin";       off[6] = 4294967296; size[6] = 4294967360
        file[7] = "4g-plus.bin";  off[7] = 4294967297; size[7] = 4294967361
        file[8] = "8g.bin";       off[8] = 8589934592; size[8] = 8589934656
        file[9] = "16g.bin";      off[9] = 17179869184; size[9] = 17179869248
        file[10] = "32g-head.bin"; off[10] = 4096; size[10] = 34359738368
        file[11] = "32g-edge.bin"; off[11] = 34359738304; size[11] = 34359738368
    }
    NR == 1 {
        if ($1 != "file" || $10 != "engine_offset" || $11 != "offset_matches")
            exit 2
        next
    }
    {
        row = NR - 1
        if (NF != 12 || row > 11 || $1 != file[row] || $2 != off[row] ||
            $3 != size[row] || $4 != $3 + 0 || $5 != "yes" || $6 != 1 ||
            $7 != "yes" || $8 != "yes" || $9 != "yes" ||
            $10 !~ /^[0-9][0-9]*$/ || $10 != off[row] || $11 != "yes") bad = 1
    }
    END {
        if (NR != 12 || bad) exit 1
    }
' "$results" || {
    echo 'POC results do not contain eleven passing exact-size/offset rows' >&2
    exit 1
}

for level in $levels; do
    case "$level" in
        ''|*[!0-9]*)
            echo "invalid concurrency level: $level" >&2
            exit 2
            ;;
    esac
    level_dir=$out/concurrency/$level
    log_count=$(find "$level_dir" -maxdepth 1 -type f -name 'worker-*.log' 2>/dev/null | wc -l | tr -d '[:space:]')
    record_count=$(find "$level_dir" -maxdepth 1 -type f -name 'worker-*.rss-kb' 2>/dev/null | wc -l | tr -d '[:space:]')
    if [ "$log_count" -ne "$level" ] || [ "$record_count" -ne "$level" ]; then
        echo "concurrency level $level does not contain exactly $level worker logs and RSS records" >&2
        exit 1
    fi

    recomputed_rss=0
    worker=1
    while [ "$worker" -le "$level" ]; do
        log=$level_dir/worker-$worker.log
        rss_record=$level_dir/worker-$worker.rss-kb
        if [ ! -s "$log" ] || [ ! -s "$rss_record" ]; then
            echo "missing auditable worker evidence for concurrency level $level worker $worker" >&2
            exit 1
        fi
        grep -F 'FOUND' "$log" >/dev/null 2>&1 || {
            echo "worker $worker at concurrency level $level has no detection" >&2
            exit 1
        }
        log_rss=$(awk '
            /^[[:space:]]*Maximum resident set size \(kbytes\): [0-9][0-9]*$/ {
                count++
                value = $NF
            }
            END { if (count == 1) print value; else print "invalid" }
        ' "$log")
        record_rss=$(awk '
            { count++ }
            NR == 1 && /^[0-9][0-9]*$/ { value = $0 }
            END { if (count == 1 && value != "") print value; else print "invalid" }
        ' "$rss_record")
        case "$log_rss:$record_rss" in
            *[!0-9:]*)
                echo "invalid RSS evidence for concurrency level $level worker $worker" >&2
                exit 1
                ;;
        esac
        if [ "$log_rss" != "$record_rss" ]; then
            echo "worker RSS record does not match GNU time log at concurrency level $level worker $worker" >&2
            exit 1
        fi
        recomputed_rss=$((recomputed_rss + record_rss))
        worker=$((worker + 1))
    done

    metadata_rss=$(awk -v key="concurrency_${level}=pass" '
        $1 == key && $2 ~ /^rss_sum_kb=[0-9][0-9]*$/ {
            count++
            sub(/^rss_sum_kb=/, "", $2)
            value = $2
        }
        END { if (count == 1) print value; else print "invalid" }
    ' "$metadata")
    case "$metadata_rss" in
        ''|*[!0-9]*)
            echo "concurrency level did not pass: $level" >&2
            exit 1
            ;;
    esac
    if [ "$metadata_rss" -ne "$recomputed_rss" ]; then
        echo "concurrency RSS total is inconsistent at level $level: metadata=$metadata_rss recomputed=$recomputed_rss" >&2
        exit 1
    fi
    if [ "$recomputed_rss" -gt "$rss_budget_kb" ]; then
        echo "concurrency RSS exceeds budget at level $level: $recomputed_rss > $rss_budget_kb" >&2
        exit 1
    fi
done

grep -E 'MaxFileSize|Max file size|exceeds the maximum file size' "$policy_log" >/dev/null 2>&1 || {
    echo 'policy log does not show the expected maximum-file-size rejection' >&2
    exit 1
}

echo "large-file runtime evidence verified: $out"
