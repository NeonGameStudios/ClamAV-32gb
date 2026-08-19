#!/bin/sh

# Control test for the post-run evidence verifier. The fixture is synthetic;
# it validates the verifier's acceptance and fail-closed rejection paths and
# is never release evidence.

set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/clamav-largefile-evidence.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

# Keep the workflow/verifier deadline contract executable. The release
# deadline is intentionally independent from the longer sanitizer deadline.
grep -F "CLAMAV_MAX_SCAN_TIME_MS: '900000'" "$root/.github/workflows/cmake.yml" >/dev/null
grep -F "CLAMAV_SANITIZER_MAX_SCAN_TIME_MS: '3600000'" "$root/.github/workflows/cmake.yml" >/dev/null
workflow_release_deadlines=$(grep -F 'CLAMAV_MAX_SCAN_TIME_MS:' "$root/.github/workflows/cmake.yml" |
    sed -n "s/.*: '\([0-9][0-9]*\)'.*/\1/p" | sort -u)
workflow_sanitizer_deadlines=$(grep -F 'CLAMAV_SANITIZER_MAX_SCAN_TIME_MS:' "$root/.github/workflows/cmake.yml" |
    sed -n "s/.*: '\([0-9][0-9]*\)'.*/\1/p" | sort -u)
verifier_release_deadline=$(sed -n 's/^fixed_release_scan_time_ms=//p' \
    "$root/tools/largefile_runtime_evidence_check.sh")
verifier_sanitizer_deadline=$(sed -n 's/^fixed_sanitizer_scan_time_ms=//p' \
    "$root/tools/largefile_runtime_evidence_check.sh")
[ "$workflow_release_deadlines" = "$verifier_release_deadline" ]
[ "$workflow_sanitizer_deadlines" = "$verifier_sanitizer_deadline" ]
for workflow_input in production_database production_file materialized_file expansion_fixture; do
    grep -F "${workflow_input}:" "$root/.github/workflows/cmake.yml" >/dev/null
done
grep -F "run: ctest -C RelWithDebInfo -V -E '_valgrind$'" "$root/.github/workflows/cmake.yml" >/dev/null
grep -F 'Install Rust sanitizer toolchain' "$root/.github/workflows/cmake.yml" >/dev/null
grep -F 'RUSTUP_TOOLCHAIN: nightly' "$root/.github/workflows/cmake.yml" >/dev/null
grep -F 'RUSTFLAGS: -Zsanitizer=address' "$root/.github/workflows/cmake.yml" >/dev/null
grep -F "CLAMAV_SANITIZER_RUSTFLAGS: '-Zsanitizer=address'" "$root/.github/workflows/cmake.yml" >/dev/null
if grep -E 'ctest[^\n]*-E[^\n]*libclamav_rust|ctest[^\n]*libclamav_rust[^\n]*-E' \
    "$root/.github/workflows/cmake.yml" >/dev/null 2>&1; then
    echo 'sanitizer workflow still excludes the Rust CTest target' >&2
    exit 1
fi

out=$tmp/evidence
mkdir -p "$out/host-preflight" "$out/poc" "$out/concurrency/1" \
    "$out/concurrency/2" "$out/concurrency/4" \
    "$out/sanitizer/logs" "$out/artifacts/runtime-components" \
    "$out/artifacts/runtime-components-sanitizer" "$out/provenance"
hash=$(printf '%064d' 0)
printf 'synthetic source manifest\n' > "$out/provenance/source-manifest.txt"
cp "$out/provenance/source-manifest.txt" "$out/provenance/build-source-manifest.txt"
source_manifest_hash=$(sha256sum "$out/provenance/source-manifest.txt" | awk '{ print $1 }')
source_commit=$source_manifest_hash
printf 'synthetic scanner\n' > "$out/artifacts/clamscan"
printf 'synthetic sanitizer scanner\n' > "$out/artifacts/clamscan-sanitizer"
printf 'synthetic runtime component\n' > "$out/artifacts/runtime-components/libclamav.so"
printf 'synthetic sanitizer runtime component\n' > "$out/artifacts/runtime-components-sanitizer/libclamav.so"
printf 'synthetic Rust archive\n' > "$out/artifacts/clamav_rust.a"
printf 'CMAKE_BUILD_TYPE:STRING=Release\nCMAKE_HOME_DIRECTORY:INTERNAL=%s\n' "$root" > "$out/provenance/CMakeCache.txt"
printf 'CLAMAV_SOURCE_COMMIT:INTERNAL=%s\n' "$source_commit" >> "$out/provenance/CMakeCache.txt"
printf 'CLAMAV_SOURCE_MANIFEST_SHA256:INTERNAL=%s\n' "$source_manifest_hash" >> "$out/provenance/CMakeCache.txt"
printf '[{"directory":"%s","command":"cc -fsanitize=address,undefined -c synthetic.c","file":"synthetic.c"}]\n' "$root" > "$out/provenance/compile_commands.json"
cp "$out/provenance/CMakeCache.txt" "$out/provenance/CMakeCache-sanitizer.txt"
cp "$out/provenance/source-manifest.txt" "$out/provenance/build-source-manifest-sanitizer.txt"
cp "$out/provenance/compile_commands.json" "$out/provenance/compile_commands-sanitizer.json"
printf 'version = 4\n' > "$out/provenance/Cargo.lock"
printf '100644 blob %s\tCargo.lock\n' "$hash" > "$out/provenance/repository-tree.txt"
printf '100644 %s 0\tCargo.lock\n' "$hash" > "$out/provenance/repository-index.txt"
for provenance_script in \
    largefile_runtime_gate.sh \
    largefile_runtime_evidence_check.sh \
    largefile_host_preflight.sh \
    largefile_boundary_corpus.sh \
    largefile_poc.sh \
    largefile_source_manifest.sh; do
    printf 'synthetic provenance for %s\n' "$provenance_script" > "$out/provenance/$provenance_script"
done
scanner_hash=$(sha256sum "$out/artifacts/clamscan" | awk '{ print $1 }')
sanitizer_hash=$(sha256sum "$out/artifacts/clamscan-sanitizer" | awk '{ print $1 }')
cargo_hash=$(sha256sum "$out/provenance/Cargo.lock" | awk '{ print $1 }')
cmake_hash=$(sha256sum "$out/provenance/CMakeCache.txt" | awk '{ print $1 }')
compile_commands_hash=$(sha256sum "$out/provenance/compile_commands.json" | awk '{ print $1 }')
sanitizer_cmake_hash=$(sha256sum "$out/provenance/CMakeCache-sanitizer.txt" | awk '{ print $1 }')
sanitizer_compile_commands_hash=$(sha256sum "$out/provenance/compile_commands-sanitizer.json" | awk '{ print $1 }')
sanitizer_build_manifest_hash=$(sha256sum "$out/provenance/build-source-manifest-sanitizer.txt" | awk '{ print $1 }')
repository_tree_hash=$(sha256sum "$out/provenance/repository-tree.txt" | awk '{ print $1 }')
repository_index_hash=$(sha256sum "$out/provenance/repository-index.txt" | awk '{ print $1 }')
printf 'metadata_version=1\nworktree_root=%s\nsource_commit=%s\nsource_tree=%s\nsource_repository=example/clamav-largefile\nsource_manifest_sha256=%s\ntracked_file_count=1\nsource_tree_manifest=provenance/repository-tree.txt\nsource_tree_manifest_sha256=%s\nsource_index_manifest=provenance/repository-index.txt\nsource_index_manifest_sha256=%s\nsource_tree_status=clean\n' \
    "$root" "$source_commit" "$source_commit" "$source_manifest_hash" "$repository_tree_hash" "$repository_index_hash" > "$out/provenance/repository-metadata.txt"
printf 'source_manifest=provenance/source-manifest.txt\n' >> "$out/provenance/repository-metadata.txt"
repository_metadata_hash=$(sha256sum "$out/provenance/repository-metadata.txt" | awk '{ print $1 }')
printf '/build/libclamav.so\n' > "$out/provenance/runtime-dependencies.txt"
printf '/build-sanitizer/libclamav.so\n' > "$out/provenance/runtime-dependencies-sanitizer.txt"
printf '%s -> artifacts/runtime-components/libclamav.so\n' "$out/artifacts/runtime-components/libclamav.so" > "$out/provenance/runtime-dependency-artifacts.txt"
printf '%s -> artifacts/runtime-components-sanitizer/libclamav.so\n' "$out/artifacts/runtime-components-sanitizer/libclamav.so" > "$out/provenance/runtime-dependency-artifacts-sanitizer.txt"
(cd "$out" && sha256sum artifacts/runtime-components/libclamav.so) > "$out/provenance/runtime-dependency-hashes.txt"
(cd "$out" && sha256sum artifacts/runtime-components-sanitizer/libclamav.so) > "$out/provenance/runtime-dependency-hashes-sanitizer.txt"
printf 'synthetic ldd output\n' > "$out/provenance/ldd-clamscan.txt"
printf 'synthetic ldd output\n' > "$out/provenance/ldd-clamscan-sanitizer.txt"
printf 'libclamav.so => %s/artifacts/runtime-components/libclamav.so (0x0)\n' "$out" > "$out/provenance/loaded-dependencies.txt"
printf 'libclamav.so => %s/artifacts/runtime-components-sanitizer/libclamav.so (0x0)\n' "$out" > "$out/provenance/loaded-dependencies-sanitizer.txt"
printf 'search path=%s\n' "$out/artifacts/runtime-components" > "$out/provenance/loader-clamscan.txt"
printf 'search path=%s\n' "$out/artifacts/runtime-components-sanitizer" > "$out/provenance/loader-clamscan-sanitizer.txt"
printf 'ClamAV synthetic release\n' > "$out/provenance/scanner-version.txt"
printf 'ClamAV synthetic sanitizer\n' > "$out/provenance/scanner-version-sanitizer.txt"
printf '  1: __asan_init\n' > "$out/provenance/sanitizer-symbols.txt"
printf '                 U __asan_init\n' > "$out/provenance/rust-sanitizer-symbols.txt"
{
    printf 'utc=2026-08-11T00:00:00Z\n'
    printf 'arch=x86_64\n'
    printf 'ELF 64-bit LSB pie executable, x86-64\n'
    printf 'rss_budget_kb=33554432\n'
    printf 'min_available_kb=50331648\n'
    printf 'max_temp_bytes=68719476736\n'
    printf 'max_scan_time_ms=900000\n'
    printf 'sanitizer_max_scan_time_ms=3600000\n'
    printf 'sanitizer_rust_suite=pass\n'
    printf 'sanitizer_toolchain=nightly\n'
    printf 'sanitizer_rustflags=-Zsanitizer=address\n'
    printf 'concurrency_levels=1 2 4\n'
    printf 'concurrency_file=32g-edge.bin\n'
    printf 'source_commit=%s\n' "$source_commit"
    printf 'source_tree=%s\n' "$source_commit"
    printf 'source_manifest_sha256=%s\n' "$source_manifest_hash"
    printf 'build_source_manifest_sha256=%s\n' "$source_manifest_hash"
    printf 'source_revision_type=content-manifest\n'
    printf 'source_tree_clean=yes\n'
    printf 'source_repository=example/clamav-largefile\n'
    printf 'repository_metadata=provenance/repository-metadata.txt\n'
    printf 'repository_metadata_sha256=%s\n' "$repository_metadata_hash"
    printf 'repository_tree_manifest=provenance/repository-tree.txt\n'
    printf 'repository_tree_manifest_sha256=%s\n' "$repository_tree_hash"
    printf 'repository_index_manifest=provenance/repository-index.txt\n'
    printf 'repository_index_manifest_sha256=%s\n' "$repository_index_hash"
    printf 'tracked_file_count=1\n'
    printf 'cmake_source=%s\n' "$root"
    printf 'github_sha=%s\n' "$source_commit"
    printf 'github_ref=refs/heads/main\n'
    printf 'github_run_id=1\n'
    printf 'github_run_attempt=1\n'
    printf 'scanner_path=artifacts/clamscan\n'
    printf 'scanner_sha256=%s\n' "$scanner_hash"
    printf 'cargo_lock_sha256=%s\n' "$cargo_hash"
    printf 'cmake_cache_sha256=%s\n' "$cmake_hash"
    printf 'compile_commands_sha256=%s\n' "$compile_commands_hash"
    printf 'sanitizer_cmake_cache_sha256=%s\n' "$sanitizer_cmake_hash"
    printf 'sanitizer_compile_commands_sha256=%s\n' "$sanitizer_compile_commands_hash"
    printf 'sanitizer_build_source_manifest_sha256=%s\n' "$sanitizer_build_manifest_hash"
    printf 'runtime_dependency_hashes=provenance/runtime-dependency-hashes.txt\n'
    printf 'runtime_dependency_artifacts=provenance/runtime-dependency-artifacts.txt\n'
    printf 'runtime_component_dir=artifacts/runtime-components\n'
    printf 'loaded_dependencies=provenance/loaded-dependencies.txt\n'
    printf 'loader_trace=provenance/loader-clamscan.txt\n'
    printf 'sanitizer_dependency_hashes=provenance/runtime-dependency-hashes-sanitizer.txt\n'
    printf 'sanitizer_dependency_artifacts=provenance/runtime-dependency-artifacts-sanitizer.txt\n'
    printf 'sanitizer_component_dir=artifacts/runtime-components-sanitizer\n'
    printf 'sanitizer_loaded_dependencies=provenance/loaded-dependencies-sanitizer.txt\n'
    printf 'sanitizer_loader_trace=provenance/loader-clamscan-sanitizer.txt\n'
    rust_library_hash=$(sha256sum "$out/artifacts/clamav_rust.a" | awk '{ print $1 }')
    printf 'sanitizer_rust_library_path=artifacts/clamav_rust.a\n'
    printf 'sanitizer_rust_library_sha256=%s\n' "$rust_library_hash"
    printf 'sanitizer_rust_symbols=provenance/rust-sanitizer-symbols.txt\n'
    printf 'sanitizer_compile_graph=pass\n'
    printf 'sanitizer_rust_instrumentation=pass\n'
    printf 'sanitizer_instrumentation=pass\n'
    printf 'host_preflight=pass\n'
    printf 'runtime_gate=pass\n'
    printf 'evidence_manifest=SHA256SUMS\n'
    printf 'sanitizer_scanner_path=artifacts/clamscan-sanitizer\n'
    printf 'sanitizer_scanner_sha256=%s\n' "$sanitizer_hash"
    printf 'largefile_poc=pass\n'
    printf 'temp_budget=pass\n'
    printf 'policy_32g_plus_one=pass\n'
    printf 'cancellation=pass status=124\n'
    printf 'sanitizer=pass\n'
    printf 'concurrency_1=pass rss_sum_kb=1\n'
    printf 'concurrency_2=pass rss_sum_kb=2\n'
    printf 'concurrency_4=pass rss_sum_kb=4\n'
} > "$out/build-identity.txt"
{
    printf 'arch=x86_64\n'
    printf 'memory_total_kb=65536000\n'
    printf 'memory_available_kb=60000000\n'
    printf 'effective_memory_available_kb=60000000\n'
    printf 'minimum_available_kb=50331648\n'
    printf 'available_memory_check=pass\n'
    printf 'cgroup_memory_limit_bytes=max\n'
    printf 'cgroup_memory_current_bytes=0\n'
    printf 'cgroup_limit_finite=no\n'
    printf 'cgroup_available_kb=unlimited\n'
} > "$out/host-preflight/host-preflight.txt"
printf 'MaxFileSize exceeded\n' > "$out/32g-plus-one.log"
printf 'terminated by timeout\n' > "$out/cancellation.log"
printf 'sanitizer clean\n' > "$out/sanitizer/logs/clean.log"
for level in 1 2 4; do
    worker=1
    while [ "$worker" -le "$level" ]; do
        {
            printf 'LargeFile.POC.32g-edge: /external/32g-edge.bin: FOUND\n'
            printf 'Maximum resident set size (kbytes): 1\n'
        } > "$out/concurrency/$level/worker-$worker.log"
        printf '1\n' > "$out/concurrency/$level/worker-$worker.rss-kb"
        worker=$((worker + 1))
    done
done
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
"$root/tools/largefile_runtime_evidence_check.sh" "$out" yes '1 2 4' 33554432

grep -v '^runtime_gate=pass$' "$out/build-identity.txt" > "$out/build-identity.no-pass"
mv "$out/build-identity.txt" "$out/build-identity.with-pass"
mv "$out/build-identity.no-pass" "$out/build-identity.txt"
refresh_manifest
if "$root/tools/largefile_runtime_evidence_check.sh" "$out" yes '1 2 4' 33554432 >/dev/null 2>&1; then
    echo 'evidence checker accepted evidence without an explicit runtime pass marker' >&2
    exit 1
fi
mv "$out/build-identity.with-pass" "$out/build-identity.txt"

mv "$out/host-preflight/host-preflight.txt" "$out/host-preflight/host-preflight.missing"
refresh_manifest
if "$root/tools/largefile_runtime_evidence_check.sh" "$out" yes '1 2 4' 33554432 >/dev/null 2>&1; then
    echo 'evidence checker accepted missing host preflight' >&2
    exit 1
fi
mv "$out/host-preflight/host-preflight.missing" "$out/host-preflight/host-preflight.txt"

cp "$out/poc/results.tsv" "$out/poc/results.good"
awk -F '\t' 'BEGIN { OFS = "\t" } NR == 2 { $10 = $10 + 1 } { print }' \
    "$out/poc/results.good" > "$out/poc/results.mutated"
mv "$out/poc/results.mutated" "$out/poc/results.tsv"
refresh_manifest
if "$root/tools/largefile_runtime_evidence_check.sh" "$out" yes '1 2 4' 33554432 >/dev/null 2>&1; then
    echo 'evidence checker accepted a wrong numeric engine offset' >&2
    exit 1
fi
cp "$out/poc/results.good" "$out/poc/results.tsv"

awk -F '\t' 'BEGIN { OFS = "\t" } NR == 2 { $12 = 68719476737 } { print }' \
    "$out/poc/results.good" > "$out/poc/results.mutated"
mv "$out/poc/results.mutated" "$out/poc/results.tsv"
refresh_manifest
if "$root/tools/largefile_runtime_evidence_check.sh" "$out" yes '1 2 4' 33554432 >/dev/null 2>&1; then
    echo 'evidence checker accepted temporary usage above the fixed budget' >&2
    exit 1
fi
cp "$out/poc/results.good" "$out/poc/results.tsv"

mv "$out/concurrency/1/worker-1.log" "$out/concurrency/1/worker-1.missing"
refresh_manifest
if "$root/tools/largefile_runtime_evidence_check.sh" "$out" yes '1 2 4' 33554432 >/dev/null 2>&1; then
    echo 'evidence checker accepted a missing worker log' >&2
    exit 1
fi
mv "$out/concurrency/1/worker-1.missing" "$out/concurrency/1/worker-1.log"

printf '0\n' > "$out/concurrency/1/worker-1.rss-kb"
refresh_manifest
if "$root/tools/largefile_runtime_evidence_check.sh" "$out" yes '1 2 4' 33554432 >/dev/null 2>&1; then
    echo 'evidence checker accepted an RSS record that disagrees with the worker log' >&2
    exit 1
fi
printf '1\n' > "$out/concurrency/1/worker-1.rss-kb"

cp "$out/build-identity.txt" "$out/build-identity.good"
sed 's/^concurrency_1=pass rss_sum_kb=1$/concurrency_1=pass rss_sum_kb=0/' \
    "$out/build-identity.good" > "$out/build-identity.txt"
refresh_manifest
if "$root/tools/largefile_runtime_evidence_check.sh" "$out" yes '1 2 4' 33554432 >/dev/null 2>&1; then
    echo 'evidence checker accepted a false concurrency RSS total' >&2
    exit 1
fi
cp "$out/build-identity.good" "$out/build-identity.txt"

sed 's/^max_scan_time_ms=900000$/max_scan_time_ms=0/' \
    "$out/build-identity.good" > "$out/build-identity.txt"
refresh_manifest
if "$root/tools/largefile_runtime_evidence_check.sh" "$out" yes '1 2 4' 33554432 >/dev/null 2>&1; then
    echo 'evidence checker accepted an unbounded or invalid per-file scan deadline' >&2
    exit 1
fi
cp "$out/build-identity.good" "$out/build-identity.txt"

sed 's/^sanitizer_max_scan_time_ms=3600000$/sanitizer_max_scan_time_ms=0/' \
    "$out/build-identity.good" > "$out/build-identity.txt"
refresh_manifest
if "$root/tools/largefile_runtime_evidence_check.sh" "$out" yes '1 2 4' 33554432 >/dev/null 2>&1; then
    echo 'evidence checker accepted an unbounded or invalid sanitizer scan deadline' >&2
    exit 1
fi
cp "$out/build-identity.good" "$out/build-identity.txt"

sed 's/^sanitizer_max_scan_time_ms=3600000$/sanitizer_max_scan_time_ms=899999/' \
    "$out/build-identity.good" > "$out/build-identity.txt"
refresh_manifest
if "$root/tools/largefile_runtime_evidence_check.sh" "$out" yes '1 2 4' 33554432 >/dev/null 2>&1; then
    echo 'evidence checker accepted a sanitizer deadline below the release deadline' >&2
    exit 1
fi
cp "$out/build-identity.good" "$out/build-identity.txt"

sed 's/^concurrency_file=32g-edge.bin$/concurrency_file=16g.bin/' \
    "$out/build-identity.good" > "$out/build-identity.txt"
refresh_manifest
if "$root/tools/largefile_runtime_evidence_check.sh" "$out" yes '1 2 4' 33554432 >/dev/null 2>&1; then
    echo 'evidence checker accepted non-edge release concurrency evidence' >&2
    exit 1
fi
cp "$out/build-identity.good" "$out/build-identity.txt"

cp "$out/host-preflight/host-preflight.txt" "$out/host-preflight/host-preflight.good"
sed 's/^effective_memory_available_kb=60000000$/effective_memory_available_kb=524288/' \
    "$out/host-preflight/host-preflight.good" > "$out/host-preflight/host-preflight.txt"
refresh_manifest
if "$root/tools/largefile_runtime_evidence_check.sh" "$out" yes '1 2 4' 33554432 >/dev/null 2>&1; then
    echo 'evidence checker accepted host memory that ignored finite cgroup headroom' >&2
    exit 1
fi
cp "$out/host-preflight/host-preflight.good" "$out/host-preflight/host-preflight.txt"

cp "$out/provenance/repository-tree.txt" "$out/provenance/repository-tree.good"
printf '100644 blob %s\tunexpected-extra-file\n' "$hash" >> "$out/provenance/repository-tree.txt"
refresh_manifest
if "$root/tools/largefile_runtime_evidence_check.sh" "$out" yes '1 2 4' 33554432 >/dev/null 2>&1; then
    echo 'evidence checker accepted a repository tree manifest changed after identity creation' >&2
    exit 1
fi
mv "$out/provenance/repository-tree.good" "$out/provenance/repository-tree.txt"

mv "$out/provenance/repository-index.txt" "$out/provenance/repository-index.missing"
refresh_manifest
if "$root/tools/largefile_runtime_evidence_check.sh" "$out" yes '1 2 4' 33554432 >/dev/null 2>&1; then
    echo 'evidence checker accepted missing repository index metadata' >&2
    exit 1
fi
mv "$out/provenance/repository-index.missing" "$out/provenance/repository-index.txt"

cp "$out/provenance/loaded-dependencies.txt" "$out/provenance/loaded-dependencies.good"
printf 'libclamav.so => /build/libclamav.so (0x0)\n' > "$out/provenance/loaded-dependencies.txt"
refresh_manifest
if "$root/tools/largefile_runtime_evidence_check.sh" "$out" yes '1 2 4' 33554432 >/dev/null 2>&1; then
    echo 'evidence checker accepted a loader-selected build-tree dependency' >&2
    exit 1
fi
mv "$out/provenance/loaded-dependencies.good" "$out/provenance/loaded-dependencies.txt"

cp "$out/provenance/loaded-dependencies-sanitizer.txt" \
    "$out/provenance/loaded-dependencies-sanitizer.good"
printf 'libclamav.so => /build-sanitizer/libclamav.so (0x0)\n' \
    > "$out/provenance/loaded-dependencies-sanitizer.txt"
refresh_manifest
if "$root/tools/largefile_runtime_evidence_check.sh" "$out" yes '1 2 4' 33554432 >/dev/null 2>&1; then
    echo 'evidence checker accepted a sanitizer build-tree dependency' >&2
    exit 1
fi
mv "$out/provenance/loaded-dependencies-sanitizer.good" \
    "$out/provenance/loaded-dependencies-sanitizer.txt"

refresh_manifest
printf 'tampered scanner\n' >> "$out/artifacts/clamscan"
if "$root/tools/largefile_runtime_evidence_check.sh" "$out" yes '1 2 4' 33554432 >/dev/null 2>&1; then
    echo 'evidence checker accepted a scanner modified after manifest creation' >&2
    exit 1
fi

echo 'large-file runtime evidence verifier regression passed'
