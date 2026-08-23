#!/bin/sh

# Verify the self-contained evidence produced by the mandatory service gate.
#
# Usage:
#   tools/largefile_service_evidence_check.sh SERVICE_OUTPUT BUILD_DIR

set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 SERVICE_OUTPUT BUILD_DIR" >&2
    exit 2
fi

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
requested_out=$1
build_dir=$(CDPATH= cd -- "$2" && pwd)
case "$requested_out" in
    /*) out=$requested_out ;;
    *) out=$(CDPATH= cd -- "$(dirname "$requested_out")" && pwd)/$(basename "$requested_out") ;;
esac
case "$out" in
    "$root"|"$root"/*)
        echo "service evidence must be outside the source tree: $out" >&2
        exit 2
        ;;
esac

fail()
{
    echo "$1" >&2
    exit 1
}

if ! command -v sha256sum >/dev/null 2>&1 ||
    ! command -v awk >/dev/null 2>&1 ||
    ! command -v find >/dev/null 2>&1 ||
    ! command -v cmp >/dev/null 2>&1 ||
    ! command -v python3 >/dev/null 2>&1; then
    echo 'sha256sum, awk, find, cmp, and python3 are required to verify service evidence' >&2
    exit 2
fi

summary=$out/service-summary.txt
oracle_binding=$out/oracle-binding.txt
identity=$out/provenance/service-build-identity.txt
qualification_oracle=$out/provenance/qualification-oracle.tsv
workload_results=$out/provenance/service-workload-results.tsv
config=$out/clamd.conf
source_manifest=$out/provenance/source-manifest.txt
cmake_cache=$out/provenance/CMakeCache.txt
compile_commands=$out/provenance/compile_commands.json
binary_before=$out/provenance/service-binary-hashes-before.txt
binary_after=$out/provenance/service-binary-hashes-after.txt
dependency_hashes=$out/provenance/service-runtime-dependency-hashes.txt
dependency_hashes_after=$out/provenance/service-runtime-dependency-hashes-after.txt
checksum_manifest=$out/SHA256SUMS

for required in "$summary" "$oracle_binding" "$qualification_oracle" "$workload_results" \
    "$identity" "$config" "$source_manifest" "$cmake_cache" \
    "$compile_commands" "$binary_before" "$binary_after" \
    "$dependency_hashes" "$dependency_hashes_after" "$checksum_manifest"; do
    [ -s "$required" ] || fail "missing service evidence: $required"
done

(
    cd "$out"
    sha256sum -c SHA256SUMS >/dev/null
) || fail 'service evidence checksum manifest does not verify'
manifest_count=$(awk 'NF == 2 { count++ } END { print count + 0 }' "$checksum_manifest")
actual_count=$(find "$out" -type f ! -name SHA256SUMS | wc -l | tr -d '[:space:]')
[ "$manifest_count" = "$actual_count" ] ||
    fail "service evidence manifest is incomplete: manifest=$manifest_count files=$actual_count"

grep -Fx 'service_build_identity=pass' "$summary" >/dev/null 2>&1 ||
    fail 'service evidence has no build-identity pass marker'
grep -Fx 'service_qualification=pass' "$summary" >/dev/null 2>&1 ||
    fail 'service evidence has no qualification pass marker'
grep -Fx 'service_resource_measurement_failed=0' "$summary" >/dev/null 2>&1 ||
    fail 'service evidence has no clean resource-measurement marker'
grep -Fx 'service_runtime_dependencies_unchanged=pass' "$summary" >/dev/null 2>&1 ||
    fail 'service evidence has no runtime-dependency immutability marker'

identity_field()
{
    key=$1
    value=$(awk -F= -v expected_key="$key" '
        $1 == expected_key {
            count++
            value = substr($0, index($0, "=") + 1)
        }
        END {
            if (count != 1)
                exit 1
            print value
        }
    ' "$identity") || fail "service build identity field is missing or duplicated: $key"
    printf '%s\n' "$value"
}

is_hash()
{
    case "$1" in
        ''|*[!0-9a-fA-F]*) return 1 ;;
    esac
    [ "${#1}" -eq 40 ] || [ "${#1}" -eq 64 ]
}

source_commit=$(identity_field source_commit)
source_tree=$(identity_field source_tree)
source_manifest_sha256=$(identity_field source_manifest_sha256)
cmake_cache_sha256=$(identity_field cmake_cache_sha256)
compile_commands_sha256=$(identity_field compile_commands_sha256)
binary_reference=$(identity_field service_binary_hashes)
binary_hashes_sha256=$(identity_field service_binary_hashes_sha256)
dependency_reference=$(identity_field service_runtime_dependency_hashes)
dependency_hashes_sha256=$(identity_field service_runtime_dependency_hashes_sha256)
dependency_after_reference=$(identity_field service_runtime_dependency_hashes_after)
dependency_after_hashes_sha256=$(identity_field service_runtime_dependency_hashes_after_sha256)
loader_injection=$(identity_field loader_injection)
max_scan_time_ms=$(identity_field max_scan_time_ms)
service_timeout_s=$(identity_field service_timeout_s)

[ "$loader_injection" = disabled ] || fail 'service evidence does not prove inherited loader injection was disabled'

case "$max_scan_time_ms" in
    ''|*[!0-9]*|0*) fail 'service MaxScanTime identity is not a positive integer' ;;
esac
if [ "${#max_scan_time_ms}" -gt 10 ] ||
    { [ "${#max_scan_time_ms}" -eq 10 ] && [ "$max_scan_time_ms" -gt 4294967295 ]; }; then
    fail 'service MaxScanTime identity exceeds the supported uint32 range'
fi
case "$service_timeout_s" in
    ''|*[!0-9]*|0*) fail 'service timeout identity is not a positive integer' ;;
esac
if [ "$service_timeout_s" -lt 14400 ]; then
    fail 'service timeout identity does not cover the four-hour deadline'
fi
if ! awk -v timeout_s="$service_timeout_s" -v scan_time_ms="$max_scan_time_ms" \
    'BEGIN { exit !((timeout_s * 1000) >= scan_time_ms) }'; then
    fail 'service timeout identity is shorter than the MaxScanTime identity'
fi
configured_max_scan_time=$(awk '$1 == "MaxScanTime" { count++; value = $2 } END { if (count != 1) exit 1; print value }' "$config") ||
    fail 'service configuration has no unique MaxScanTime entry'
[ "$configured_max_scan_time" = "$max_scan_time_ms" ] ||
    fail 'service configuration MaxScanTime does not match service identity'

is_hash "$source_commit" || fail 'service source commit is not a 40- or 64-character hash'
is_hash "$source_tree" || fail 'service source tree is not a 40- or 64-character hash'
is_hash "$source_manifest_sha256" || fail 'service source manifest hash is invalid'
is_hash "$cmake_cache_sha256" || fail 'service CMake cache hash is invalid'
is_hash "$compile_commands_sha256" || fail 'service compile-commands hash is invalid'
is_hash "$binary_hashes_sha256" || fail 'service binary-list hash is invalid'
is_hash "$dependency_hashes_sha256" || fail 'service dependency-list hash is invalid'
[ "$binary_reference" = provenance/service-binary-hashes-before.txt ] ||
    fail 'service build identity references the wrong binary hash list'
[ "$dependency_reference" = provenance/service-runtime-dependency-hashes.txt ] ||
    fail 'service build identity references the wrong dependency hash list'
[ "$dependency_after_reference" = provenance/service-runtime-dependency-hashes-after.txt ] ||
    fail 'service build identity references the wrong after dependency hash list'

cache_source=$(sed -n 's#^CMAKE_HOME_DIRECTORY:INTERNAL=##p' "$cmake_cache")
[ "$cache_source" = "$root" ] || fail 'service CMake cache is bound to a different source root'
cache_commit=$(sed -n 's/^CLAMAV_SOURCE_COMMIT:INTERNAL=//p' "$cmake_cache")
cache_manifest=$(sed -n 's/^CLAMAV_SOURCE_MANIFEST_SHA256:INTERNAL=//p' "$cmake_cache")
[ "$cache_commit" = "$source_commit" ] || fail 'service CMake cache source commit does not match evidence'
[ "$cache_manifest" = "$source_manifest_sha256" ] ||
    fail 'service CMake cache source manifest does not match evidence'

actual_source_manifest_sha256=$(sha256sum "$source_manifest" | awk '{ print $1 }')
[ "$actual_source_manifest_sha256" = "$source_manifest_sha256" ] ||
    fail 'service source manifest hash does not verify'
actual_cmake_cache_sha256=$(sha256sum "$cmake_cache" | awk '{ print $1 }')
actual_compile_commands_sha256=$(sha256sum "$compile_commands" | awk '{ print $1 }')
[ "$actual_cmake_cache_sha256" = "$cmake_cache_sha256" ] ||
    fail 'service CMake cache hash does not verify'
[ "$actual_compile_commands_sha256" = "$compile_commands_sha256" ] ||
    fail 'service compile-commands hash does not verify'
actual_binary_hashes_sha256=$(sha256sum "$binary_before" | awk '{ print $1 }')
actual_dependency_hashes_sha256=$(sha256sum "$dependency_hashes" | awk '{ print $1 }')
actual_dependency_after_hashes_sha256=$(sha256sum "$dependency_hashes_after" | awk '{ print $1 }')
[ "$actual_binary_hashes_sha256" = "$binary_hashes_sha256" ] ||
    fail 'service binary-list hash does not verify'
[ "$actual_dependency_hashes_sha256" = "$dependency_hashes_sha256" ] ||
    fail 'service dependency-list hash does not verify'
[ "$actual_dependency_after_hashes_sha256" = "$dependency_after_hashes_sha256" ] ||
    fail 'service after dependency-list hash does not verify'

cmp -s "$binary_before" "$binary_after" ||
    fail 'service executable hashes changed during qualification'
cmp -s "$dependency_hashes" "$dependency_hashes_after" ||
    fail 'service runtime dependency hashes changed during qualification'

expected_binaries='clamscan/clamscan
clamd/clamd
clamdscan/clamdscan
clamav-milter/clamav-milter'
check_binary_list()
{
    list=$1
    while IFS= read -r relative_binary; do
        [ -n "$relative_binary" ] || continue
        line=$(awk -F '\t' -v path="$relative_binary" \
            '$1 == path { count++; value=$0 } END { if (count != 1) exit 1; print value }' "$list") ||
            fail "service binary hash list has a missing or duplicate entry: $relative_binary"
        expected_hash=$(printf '%s\n' "$line" | awk -F '\t' '{ print $2 }')
        is_hash "$expected_hash" || fail "service binary hash is invalid: $relative_binary"
        service_binary=$build_dir/$relative_binary
        [ -x "$service_binary" ] || fail "service qualification executable is missing: $service_binary"
        actual_hash=$(sha256sum "$service_binary" | awk '{ print $1 }')
        [ "$actual_hash" = "$expected_hash" ] ||
            fail "service executable hash does not match evidence: $relative_binary"
    done <<EOF
$expected_binaries
EOF
}
check_binary_list "$binary_before"
check_binary_list "$binary_after"

if ! LC_ALL=C sort -u "$dependency_hashes" | cmp -s - "$dependency_hashes"; then
    fail 'service runtime dependency hash list is not canonicalized'
fi
while IFS="$(printf '\t')" read -r dependency expected_hash; do
    [ -n "$dependency" ] || fail 'service runtime dependency hash list has an empty path'
    is_hash "$expected_hash" || fail "service runtime dependency hash is invalid: $dependency"
    [ -f "$dependency" ] || fail "service runtime dependency is missing: $dependency"
    actual_hash=$(sha256sum "$dependency" | awk '{ print $1 }')
    [ "$actual_hash" = "$expected_hash" ] ||
        fail "service runtime dependency hash does not match evidence: $dependency"
done < "$dependency_hashes"

python3 "$root/tools/largefile_service_workload_check.py" "$out" ||
    fail 'service workload oracle/report verification failed'

echo 'service runtime evidence passed'
