#!/bin/sh

# Control test for the post-run evidence verifier. The fixture is synthetic;
# it validates the verifier's acceptance and fail-closed rejection paths and
# is never release evidence.

set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/clamav-largefile-evidence.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

out=$tmp/evidence
mkdir -p "$out/host-preflight" "$out/poc" "$out/concurrency/1" \
    "$out/sanitizer/logs" "$out/artifacts" "$out/provenance"
hash=$(printf '%064d' 0)
source_commit=$(printf '%040d' 1)
printf 'synthetic scanner\n' > "$out/artifacts/clamscan"
printf 'synthetic sanitizer scanner\n' > "$out/artifacts/clamscan-sanitizer"
printf 'CMAKE_BUILD_TYPE:STRING=Release\n' > "$out/provenance/CMakeCache.txt"
printf 'version = 4\n' > "$out/provenance/Cargo.lock"
for provenance_script in \
    largefile_runtime_gate.sh \
    largefile_runtime_evidence_check.sh \
    largefile_host_preflight.sh \
    largefile_boundary_corpus.sh \
    largefile_poc.sh; do
    printf 'synthetic provenance for %s\n' "$provenance_script" > "$out/provenance/$provenance_script"
done
scanner_hash=$(sha256sum "$out/artifacts/clamscan" | awk '{ print $1 }')
sanitizer_hash=$(sha256sum "$out/artifacts/clamscan-sanitizer" | awk '{ print $1 }')
cargo_hash=$(sha256sum "$out/provenance/Cargo.lock" | awk '{ print $1 }')
cmake_hash=$(sha256sum "$out/provenance/CMakeCache.txt" | awk '{ print $1 }')
{
    printf 'utc=2026-08-11T00:00:00Z\n'
    printf 'arch=x86_64\n'
    printf 'ELF 64-bit LSB pie executable, x86-64\n'
    printf 'rss_budget_kb=1234\n'
    printf 'min_available_kb=0\n'
    printf 'max_scan_time_ms=900000\n'
    printf 'concurrency_file=32g-edge.bin\n'
    printf 'source_commit=%s\n' "$source_commit"
    printf 'source_tree_clean=yes\n'
    printf 'source_repository=example/clamav-largefile\n'
    printf 'github_sha=%s\n' "$source_commit"
    printf 'github_ref=refs/heads/main\n'
    printf 'github_run_id=1\n'
    printf 'github_run_attempt=1\n'
    printf 'scanner_path=artifacts/clamscan\n'
    printf 'scanner_sha256=%s\n' "$scanner_hash"
    printf 'cargo_lock_sha256=%s\n' "$cargo_hash"
    printf 'cmake_cache_sha256=%s\n' "$cmake_hash"
    printf 'host_preflight=pass\n'
    printf 'runtime_gate=pass\n'
    printf 'evidence_manifest=SHA256SUMS\n'
    printf 'sanitizer_scanner_path=artifacts/clamscan-sanitizer\n'
    printf 'sanitizer_scanner_sha256=%s\n' "$sanitizer_hash"
    printf 'largefile_poc=pass\n'
    printf 'policy_32g_plus_one=pass\n'
    printf 'cancellation=pass status=124\n'
    printf 'sanitizer=pass\n'
    printf 'concurrency_1=pass rss_sum_kb=1234\n'
} > "$out/build-identity.txt"
{
    printf 'arch=x86_64\n'
    printf 'memory_total_kb=65536000\n'
    printf 'memory_available_kb=60000000\n'
    printf 'effective_memory_available_kb=524288\n'
    printf 'minimum_available_kb=0\n'
    printf 'available_memory_check=pass\n'
    printf 'cgroup_memory_limit_bytes=1073741824\n'
    printf 'cgroup_memory_current_bytes=536870912\n'
    printf 'cgroup_limit_finite=yes\n'
    printf 'cgroup_available_kb=524288\n'
} > "$out/host-preflight/host-preflight.txt"
printf 'MaxFileSize exceeded\n' > "$out/32g-plus-one.log"
printf 'terminated by timeout\n' > "$out/cancellation.log"
printf 'sanitizer clean\n' > "$out/sanitizer/logs/clean.log"
{
    printf 'LargeFile.POC.32g-edge: /external/32g-edge.bin: FOUND\n'
    printf 'Maximum resident set size (kbytes): 1234\n'
} > "$out/concurrency/1/worker-1.log"
printf '1234\n' > "$out/concurrency/1/worker-1.rss-kb"
printf 'file\texpected_offset\texpected_size\tactual_size\tsize_matches\tscan_status\tdetected\tsignature_matches\tmarker_at_expected\tengine_offset\toffset_matches\ttmp_bytes\n' > "$out/poc/results.tsv"
printf '2g-minus.bin\t2147483647\t2147483711\t2147483711\tyes\t1\tyes\tyes\tyes\t2147483647\tyes\t0\n' >> "$out/poc/results.tsv"
printf '2g.bin\t2147483648\t2147483712\t2147483712\tyes\t1\tyes\tyes\tyes\t2147483648\tyes\t0\n' >> "$out/poc/results.tsv"
printf '2g-plus.bin\t2147483649\t2147483713\t2147483713\tyes\t1\tyes\tyes\tyes\t2147483649\tyes\t0\n' >> "$out/poc/results.tsv"
printf '4g-minus-two.bin\t4294967294\t4294967358\t4294967358\tyes\t1\tyes\tyes\tyes\t4294967294\tyes\t0\n' >> "$out/poc/results.tsv"
printf '4g-minus.bin\t4294967295\t4294967359\t4294967359\tyes\t1\tyes\tyes\tyes\t4294967295\tyes\t0\n' >> "$out/poc/results.tsv"
printf '4g.bin\t4294967296\t4294967360\t4294967360\tyes\t1\tyes\tyes\tyes\t4294967296\tyes\t0\n' >> "$out/poc/results.tsv"
printf '4g-plus.bin\t4294967297\t4294967361\t4294967361\tyes\t1\tyes\tyes\tyes\t4294967297\tyes\t0\n' >> "$out/poc/results.tsv"
printf '8g.bin\t8589934592\t8589934656\t8589934656\tyes\t1\tyes\tyes\tyes\t8589934592\tyes\t0\n' >> "$out/poc/results.tsv"
printf '16g.bin\t17179869184\t17179869248\t17179869248\tyes\t1\tyes\tyes\tyes\t17179869184\tyes\t0\n' >> "$out/poc/results.tsv"
printf '32g-head.bin\t4096\t34359738368\t34359738368\tyes\t1\tyes\tyes\tyes\t4096\tyes\t0\n' >> "$out/poc/results.tsv"
printf '32g-edge.bin\t34359738304\t34359738368\t34359738368\tyes\t1\tyes\tyes\tyes\t34359738304\tyes\t0\n' >> "$out/poc/results.tsv"

refresh_manifest()
{
    (
        cd "$out"
        find . -type f ! -path './corpus/*' ! -name SHA256SUMS -print |
            LC_ALL=C sort |
            while IFS= read -r evidence_file; do
                sha256sum "$evidence_file"
            done
    ) > "$out/SHA256SUMS"
}

refresh_manifest
"$root/tools/largefile_runtime_evidence_check.sh" "$out" yes '1' 1234

grep -v '^runtime_gate=pass$' "$out/build-identity.txt" > "$out/build-identity.no-pass"
mv "$out/build-identity.txt" "$out/build-identity.with-pass"
mv "$out/build-identity.no-pass" "$out/build-identity.txt"
refresh_manifest
if "$root/tools/largefile_runtime_evidence_check.sh" "$out" yes '1' 1234 >/dev/null 2>&1; then
    echo 'evidence checker accepted evidence without an explicit runtime pass marker' >&2
    exit 1
fi
mv "$out/build-identity.with-pass" "$out/build-identity.txt"

mv "$out/host-preflight/host-preflight.txt" "$out/host-preflight/host-preflight.missing"
refresh_manifest
if "$root/tools/largefile_runtime_evidence_check.sh" "$out" yes '1' 1234 >/dev/null 2>&1; then
    echo 'evidence checker accepted missing host preflight' >&2
    exit 1
fi
mv "$out/host-preflight/host-preflight.missing" "$out/host-preflight/host-preflight.txt"

cp "$out/poc/results.tsv" "$out/poc/results.good"
awk -F '\t' 'BEGIN { OFS = "\t" } NR == 2 { $10 = $10 + 1 } { print }' \
    "$out/poc/results.good" > "$out/poc/results.mutated"
mv "$out/poc/results.mutated" "$out/poc/results.tsv"
refresh_manifest
if "$root/tools/largefile_runtime_evidence_check.sh" "$out" yes '1' 1234 >/dev/null 2>&1; then
    echo 'evidence checker accepted a wrong numeric engine offset' >&2
    exit 1
fi
cp "$out/poc/results.good" "$out/poc/results.tsv"

mv "$out/concurrency/1/worker-1.log" "$out/concurrency/1/worker-1.missing"
refresh_manifest
if "$root/tools/largefile_runtime_evidence_check.sh" "$out" yes '1' 1234 >/dev/null 2>&1; then
    echo 'evidence checker accepted a missing worker log' >&2
    exit 1
fi
mv "$out/concurrency/1/worker-1.missing" "$out/concurrency/1/worker-1.log"

printf '1233\n' > "$out/concurrency/1/worker-1.rss-kb"
refresh_manifest
if "$root/tools/largefile_runtime_evidence_check.sh" "$out" yes '1' 1234 >/dev/null 2>&1; then
    echo 'evidence checker accepted an RSS record that disagrees with the worker log' >&2
    exit 1
fi
printf '1234\n' > "$out/concurrency/1/worker-1.rss-kb"

cp "$out/build-identity.txt" "$out/build-identity.good"
sed 's/^concurrency_1=pass rss_sum_kb=1234$/concurrency_1=pass rss_sum_kb=1233/' \
    "$out/build-identity.good" > "$out/build-identity.txt"
refresh_manifest
if "$root/tools/largefile_runtime_evidence_check.sh" "$out" yes '1' 1234 >/dev/null 2>&1; then
    echo 'evidence checker accepted a false concurrency RSS total' >&2
    exit 1
fi
cp "$out/build-identity.good" "$out/build-identity.txt"

sed 's/^max_scan_time_ms=900000$/max_scan_time_ms=0/' \
    "$out/build-identity.good" > "$out/build-identity.txt"
refresh_manifest
if "$root/tools/largefile_runtime_evidence_check.sh" "$out" yes '1' 1234 >/dev/null 2>&1; then
    echo 'evidence checker accepted an unbounded or invalid per-file scan deadline' >&2
    exit 1
fi
cp "$out/build-identity.good" "$out/build-identity.txt"

sed 's/^concurrency_file=32g-edge.bin$/concurrency_file=16g.bin/' \
    "$out/build-identity.good" > "$out/build-identity.txt"
refresh_manifest
if "$root/tools/largefile_runtime_evidence_check.sh" "$out" yes '1' 1234 >/dev/null 2>&1; then
    echo 'evidence checker accepted non-edge release concurrency evidence' >&2
    exit 1
fi
cp "$out/build-identity.good" "$out/build-identity.txt"

cp "$out/host-preflight/host-preflight.txt" "$out/host-preflight/host-preflight.good"
sed 's/^effective_memory_available_kb=524288$/effective_memory_available_kb=60000000/' \
    "$out/host-preflight/host-preflight.good" > "$out/host-preflight/host-preflight.txt"
refresh_manifest
if "$root/tools/largefile_runtime_evidence_check.sh" "$out" yes '1' 1234 >/dev/null 2>&1; then
    echo 'evidence checker accepted host memory that ignored finite cgroup headroom' >&2
    exit 1
fi
cp "$out/host-preflight/host-preflight.good" "$out/host-preflight/host-preflight.txt"

refresh_manifest
printf 'tampered scanner\n' >> "$out/artifacts/clamscan"
if "$root/tools/largefile_runtime_evidence_check.sh" "$out" yes '1' 1234 >/dev/null 2>&1; then
    echo 'evidence checker accepted a scanner modified after manifest creation' >&2
    exit 1
fi

echo 'large-file runtime evidence verifier regression passed'
