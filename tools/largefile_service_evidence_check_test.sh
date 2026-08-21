#!/bin/sh

# Regression test for the post-workload service-evidence verifier.  The
# fixture is synthetic and is never release evidence.

set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/clamav-largefile-service-evidence.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

out=$tmp/service
build=$tmp/build
mkdir -p "$out/provenance" "$build/clamscan" "$build/clamd" \
    "$build/clamdscan" "$build/clamav-milter"

for relative_binary in \
    clamscan/clamscan clamd/clamd clamdscan/clamdscan clamav-milter/clamav-milter; do
    printf 'synthetic service binary %s\n' "$relative_binary" > "$build/$relative_binary"
    chmod 755 "$build/$relative_binary"
done
printf 'synthetic runtime dependency\n' > "$tmp/libclamav.so"
printf 'synthetic source manifest\n' > "$out/provenance/source-manifest.txt"
source_manifest_sha256=$(sha256sum "$out/provenance/source-manifest.txt" | awk '{ print $1 }')
source_commit=$source_manifest_sha256
source_tree=$source_manifest_sha256
printf 'MaxScanTime 14400000\n' > "$out/clamd.conf"
printf 'CMAKE_HOME_DIRECTORY:INTERNAL=%s\n' "$root" > "$out/provenance/CMakeCache.txt"
printf 'CLAMAV_SOURCE_COMMIT:INTERNAL=%s\n' "$source_commit" >> "$out/provenance/CMakeCache.txt"
printf 'CLAMAV_SOURCE_MANIFEST_SHA256:INTERNAL=%s\n' "$source_manifest_sha256" >> "$out/provenance/CMakeCache.txt"
printf '[{"directory":"%s","command":"cc -c synthetic.c","file":"synthetic.c"}]\n' "$root" > \
    "$out/provenance/compile_commands.json"

binary_list=$out/provenance/service-binary-hashes-before.txt
binary_after=$out/provenance/service-binary-hashes-after.txt
: > "$binary_list"
for relative_binary in \
    clamscan/clamscan clamd/clamd clamdscan/clamdscan clamav-milter/clamav-milter; do
    printf '%s\t%s\n' "$relative_binary" \
        "$(sha256sum "$build/$relative_binary" | awk '{ print $1 }')" >> "$binary_list"
done
cp "$binary_list" "$binary_after"
dependency_hashes=$out/provenance/service-runtime-dependency-hashes.txt
printf '%s\t%s\n' "$tmp/libclamav.so" \
    "$(sha256sum "$tmp/libclamav.so" | awk '{ print $1 }')" > "$dependency_hashes"

cmake_cache_sha256=$(sha256sum "$out/provenance/CMakeCache.txt" | awk '{ print $1 }')
compile_commands_sha256=$(sha256sum "$out/provenance/compile_commands.json" | awk '{ print $1 }')
binary_hashes_sha256=$(sha256sum "$binary_list" | awk '{ print $1 }')
dependency_hashes_sha256=$(sha256sum "$dependency_hashes" | awk '{ print $1 }')
{
    printf 'source_commit=%s\n' "$source_commit"
    printf 'source_tree=%s\n' "$source_tree"
    printf 'source_manifest_sha256=%s\n' "$source_manifest_sha256"
    printf 'cmake_cache_sha256=%s\n' "$cmake_cache_sha256"
    printf 'compile_commands_sha256=%s\n' "$compile_commands_sha256"
    printf 'service_binary_hashes=provenance/service-binary-hashes-before.txt\n'
    printf 'service_binary_hashes_sha256=%s\n' "$binary_hashes_sha256"
    printf 'service_runtime_dependency_hashes=provenance/service-runtime-dependency-hashes.txt\n'
    printf 'service_runtime_dependency_hashes_sha256=%s\n' "$dependency_hashes_sha256"
    printf 'max_scan_time_ms=14400000\n'
    printf 'service_timeout_s=14400\n'
} > "$out/provenance/service-build-identity.txt"
{
    printf 'service_resource_measurement_failed=0\n'
    printf 'service_build_identity=pass\n'
    printf 'service_qualification=pass\n'
} > "$out/service-summary.txt"
(
    cd "$out"
    find . -type f ! -name SHA256SUMS -print | LC_ALL=C sort |
        while IFS= read -r evidence_file; do
            sha256sum "$evidence_file"
        done
) > "$out/SHA256SUMS"

sh "$root/tools/largefile_service_evidence_check.sh" "$out" "$build" >/dev/null

printf 'mutated after qualification\n' >> "$build/clamscan/clamscan"
if sh "$root/tools/largefile_service_evidence_check.sh" "$out" "$build" >/dev/null 2>&1; then
    echo 'service evidence verifier accepted a mutated service executable' >&2
    exit 1
fi

grep -F 'largefile_service_evidence_check.sh' "$root/.github/workflows/cmake.yml" >/dev/null
echo 'service runtime evidence verifier regression passed'
