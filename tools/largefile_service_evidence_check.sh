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
interpreter_records=$out/provenance/service-interpreter-records-before.txt
interpreter_records_after=$out/provenance/service-interpreter-records-after.txt
dependency_hashes=$out/provenance/service-runtime-dependency-hashes.txt
dependency_hashes_after=$out/provenance/service-runtime-dependency-hashes-after.txt
runtime_component_dir=$out/artifacts/service-runtime-components
runtime_component_artifacts=$out/provenance/service-runtime-component-artifacts.txt
runtime_component_hashes=$out/provenance/service-runtime-component-hashes-before.txt
runtime_component_hashes_after=$out/provenance/service-runtime-component-hashes-after.txt
loaded_dependencies=$out/provenance/service-loaded-dependencies.txt
parallel_profile=$out/provenance/parallel-client-clamd.conf
checksum_manifest=$out/SHA256SUMS

for required in "$summary" "$oracle_binding" "$qualification_oracle" "$workload_results" \
    "$identity" "$config" "$source_manifest" "$cmake_cache" \
    "$compile_commands" "$binary_before" "$binary_after" \
    "$interpreter_records" "$interpreter_records_after" \
    "$dependency_hashes" "$dependency_hashes_after" \
    "$runtime_component_artifacts" "$runtime_component_hashes" \
    "$runtime_component_hashes_after" "$loaded_dependencies" "$parallel_profile" \
    "$checksum_manifest"; do
    [ -s "$required" ] || fail "missing service evidence: $required"
done
[ -d "$runtime_component_dir" ] || fail 'service runtime component directory is missing'

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
grep -Fx 'service_runtime_loader_binding=pass' "$summary" >/dev/null 2>&1 ||
    fail 'service evidence has no runtime-loader binding marker'
grep -Fx 'service_runtime_components_unchanged=pass' "$summary" >/dev/null 2>&1 ||
    fail 'service evidence has no runtime-component immutability marker'
grep -Fx 'service_interpreters_unchanged=pass' "$summary" >/dev/null 2>&1 ||
    fail 'service evidence has no ELF-interpreter immutability marker'
grep -Fx 'clamd_parallel_clients=pass' "$summary" >/dev/null 2>&1 ||
    fail 'service evidence has no parallel-client pass marker'
grep -Fx 'parallel_worker_count=1' "$summary" >/dev/null 2>&1 ||
    fail 'service evidence does not prove the parallel-client test used one worker'
grep -Fx 'parallel_client_count=2' "$summary" >/dev/null 2>&1 ||
    fail 'service evidence does not prove the two required parallel clients were exercised'
grep -Fx 'parallel_test_max_queue=2' "$summary" >/dev/null 2>&1 ||
    fail 'service evidence does not identify the certified parallel-client queue'
grep -Fx 'parallel_profile=provenance/parallel-client-clamd.conf' "$summary" >/dev/null 2>&1 ||
    fail 'service evidence does not bind the parallel-client stress profile'
grep -Fx 'parallel_queue=pass' "$summary" >/dev/null 2>&1 ||
    fail 'service evidence has no parallel queue pass marker'

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
runtime_component_dir_reference=$(identity_field service_runtime_component_dir)
runtime_component_artifacts_reference=$(identity_field service_runtime_component_artifacts)
runtime_component_artifacts_sha256=$(identity_field service_runtime_component_artifacts_sha256)
runtime_component_hashes_reference=$(identity_field service_runtime_component_hashes)
runtime_component_hashes_sha256=$(identity_field service_runtime_component_hashes_sha256)
runtime_component_hashes_after_reference=$(identity_field service_runtime_component_hashes_after)
runtime_component_hashes_after_sha256=$(identity_field service_runtime_component_hashes_after_sha256)
loaded_dependencies_reference=$(identity_field service_loaded_dependencies)
loaded_dependencies_sha256=$(identity_field service_loaded_dependencies_sha256)
service_loader_path=$(identity_field service_loader_path)
interpreter_reference=$(identity_field service_interpreter_records)
interpreter_hashes_sha256=$(identity_field service_interpreter_records_sha256)
interpreter_after_reference=$(identity_field service_interpreter_records_after)
interpreter_after_hashes_sha256=$(identity_field service_interpreter_records_after_sha256)
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
configured_max_threads=$(awk '$1 == "MaxThreads" { count++; value = $2 } END { if (count != 1) exit 1; print value }' "$config") ||
    fail 'service configuration has no unique MaxThreads entry'
[ "$configured_max_threads" = 1 ] ||
    fail 'service configuration MaxThreads is outside the certified single-worker profile'
configured_max_queue=$(awk '$1 == "MaxQueue" { count++; value = $2 } END { if (count != 1) exit 1; print value }' "$config") ||
    fail 'service configuration has no unique MaxQueue entry'
[ "$configured_max_queue" = 2 ] ||
    fail 'service configuration MaxQueue is outside the certified release profile'
configured_alert_exceeds_max=$(awk '$1 == "AlertExceedsMax" { count++; value = $2 } END { if (count != 1) exit 1; print value }' "$config") ||
    fail 'service configuration has no unique AlertExceedsMax entry'
[ "$configured_alert_exceeds_max" = yes ] ||
    fail 'service configuration AlertExceedsMax is not enabled'
parallel_profile_max_threads=$(awk '$1 == "MaxThreads" { count++; value = $2 } END { if (count != 1) exit 1; print value }' "$parallel_profile") ||
    fail 'parallel-client stress profile has no unique MaxThreads entry'
[ "$parallel_profile_max_threads" = 1 ] ||
    fail 'parallel-client stress profile is outside the certified single-worker profile'
parallel_profile_max_queue=$(awk '$1 == "MaxQueue" { count++; value = $2 } END { if (count != 1) exit 1; print value }' "$parallel_profile") ||
    fail 'parallel-client stress profile has no unique MaxQueue entry'
[ "$parallel_profile_max_queue" = 2 ] ||
    fail 'parallel-client stress profile is outside the certified two-entry queue'
parallel_profile_alert=$(awk '$1 == "AlertExceedsMax" { count++; value = $2 } END { if (count != 1) exit 1; print value }' "$parallel_profile") ||
    fail 'parallel-client stress profile has no unique AlertExceedsMax entry'
[ "$parallel_profile_alert" = yes ] ||
    fail 'parallel-client stress profile does not enable AlertExceedsMax'

is_hash "$source_commit" || fail 'service source commit is not a 40- or 64-character hash'
is_hash "$source_tree" || fail 'service source tree is not a 40- or 64-character hash'
is_hash "$source_manifest_sha256" || fail 'service source manifest hash is invalid'
is_hash "$cmake_cache_sha256" || fail 'service CMake cache hash is invalid'
is_hash "$compile_commands_sha256" || fail 'service compile-commands hash is invalid'
is_hash "$binary_hashes_sha256" || fail 'service binary-list hash is invalid'
is_hash "$interpreter_hashes_sha256" || fail 'service interpreter-list hash is invalid'
is_hash "$interpreter_after_hashes_sha256" || fail 'service after interpreter-list hash is invalid'
is_hash "$dependency_hashes_sha256" || fail 'service dependency-list hash is invalid'
is_hash "$runtime_component_artifacts_sha256" || fail 'service runtime-component manifest hash is invalid'
is_hash "$runtime_component_hashes_sha256" || fail 'service runtime-component hash-list hash is invalid'
is_hash "$runtime_component_hashes_after_sha256" || fail 'service after runtime-component hash-list hash is invalid'
is_hash "$loaded_dependencies_sha256" || fail 'service loaded-dependency evidence hash is invalid'
[ "$binary_reference" = provenance/service-binary-hashes-before.txt ] ||
    fail 'service build identity references the wrong binary hash list'
[ "$dependency_reference" = provenance/service-runtime-dependency-hashes.txt ] ||
    fail 'service build identity references the wrong dependency hash list'
[ "$dependency_after_reference" = provenance/service-runtime-dependency-hashes-after.txt ] ||
    fail 'service build identity references the wrong after dependency hash list'
[ "$runtime_component_dir_reference" = artifacts/service-runtime-components ] ||
    fail 'service build identity references the wrong runtime component directory'
[ "$runtime_component_artifacts_reference" = provenance/service-runtime-component-artifacts.txt ] ||
    fail 'service build identity references the wrong runtime component manifest'
[ "$runtime_component_hashes_reference" = provenance/service-runtime-component-hashes-before.txt ] ||
    fail 'service build identity references the wrong runtime component hash list'
[ "$runtime_component_hashes_after_reference" = provenance/service-runtime-component-hashes-after.txt ] ||
    fail 'service build identity references the wrong after runtime component hash list'
[ "$loaded_dependencies_reference" = provenance/service-loaded-dependencies.txt ] ||
    fail 'service build identity references the wrong loaded-dependency evidence'
[ "$service_loader_path" = artifacts/service-runtime-components ] ||
    fail 'service build identity references the wrong service loader path'
[ "$interpreter_reference" = provenance/service-interpreter-records-before.txt ] ||
    fail 'service build identity references the wrong interpreter record list'
[ "$interpreter_after_reference" = provenance/service-interpreter-records-after.txt ] ||
    fail 'service build identity references the wrong after interpreter record list'

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
actual_interpreter_hashes_sha256=$(sha256sum "$interpreter_records" | awk '{ print $1 }')
actual_interpreter_after_hashes_sha256=$(sha256sum "$interpreter_records_after" | awk '{ print $1 }')
actual_dependency_hashes_sha256=$(sha256sum "$dependency_hashes" | awk '{ print $1 }')
actual_dependency_after_hashes_sha256=$(sha256sum "$dependency_hashes_after" | awk '{ print $1 }')
actual_runtime_component_artifacts_sha256=$(sha256sum "$runtime_component_artifacts" | awk '{ print $1 }')
actual_runtime_component_hashes_sha256=$(sha256sum "$runtime_component_hashes" | awk '{ print $1 }')
actual_runtime_component_hashes_after_sha256=$(sha256sum "$runtime_component_hashes_after" | awk '{ print $1 }')
actual_loaded_dependencies_sha256=$(sha256sum "$loaded_dependencies" | awk '{ print $1 }')
[ "$actual_binary_hashes_sha256" = "$binary_hashes_sha256" ] ||
    fail 'service binary-list hash does not verify'
[ "$actual_interpreter_hashes_sha256" = "$interpreter_hashes_sha256" ] ||
    fail 'service interpreter-list hash does not verify'
[ "$actual_interpreter_after_hashes_sha256" = "$interpreter_after_hashes_sha256" ] ||
    fail 'service after interpreter-list hash does not verify'
[ "$actual_dependency_hashes_sha256" = "$dependency_hashes_sha256" ] ||
    fail 'service dependency-list hash does not verify'
[ "$actual_dependency_after_hashes_sha256" = "$dependency_after_hashes_sha256" ] ||
    fail 'service after dependency-list hash does not verify'
[ "$actual_runtime_component_artifacts_sha256" = "$runtime_component_artifacts_sha256" ] ||
    fail 'service runtime-component manifest hash does not verify'
[ "$actual_runtime_component_hashes_sha256" = "$runtime_component_hashes_sha256" ] ||
    fail 'service runtime-component hash-list hash does not verify'
[ "$actual_runtime_component_hashes_after_sha256" = "$runtime_component_hashes_after_sha256" ] ||
    fail 'service after runtime-component hash-list hash does not verify'
[ "$actual_loaded_dependencies_sha256" = "$loaded_dependencies_sha256" ] ||
    fail 'service loaded-dependency evidence hash does not verify'

cmp -s "$binary_before" "$binary_after" ||
    fail 'service executable hashes changed during qualification'
cmp -s "$dependency_hashes" "$dependency_hashes_after" ||
    fail 'service runtime dependency hashes changed during qualification'
cmp -s "$interpreter_records" "$interpreter_records_after" ||
    fail 'service ELF interpreter records changed during qualification'
cmp -s "$runtime_component_hashes" "$runtime_component_hashes_after" ||
    fail 'service copied runtime components changed during qualification'

python3 - "$dependency_hashes" "$runtime_component_artifacts" "$runtime_component_hashes" \
    "$loaded_dependencies" "$out" "$runtime_component_dir" <<'PY' ||
import hashlib
import sys
from pathlib import Path, PurePosixPath

dependency_file, artifact_file, hash_file, loaded_file, out_name, component_name = sys.argv[1:]
out = Path(out_name)
component_dir = Path(component_name)

def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()

def rows(path, columns):
    result = []
    for line_number, raw in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        fields = raw.split("\t")
        if len(fields) != columns or any(field == "" for field in fields):
            raise SystemExit(f"malformed service runtime evidence row: {path}:{line_number}")
        result.append(fields)
    return result

dependencies = rows(dependency_file, 2)
dependency_map = {}
for source, expected in dependencies:
    if source in dependency_map:
        raise SystemExit(f"duplicate service dependency: {source}")
    dependency_map[source] = expected
    source_path = Path(source)
    if not source_path.is_file() or digest(source_path) != expected:
        raise SystemExit(f"service dependency hash does not verify: {source}")

artifacts = rows(artifact_file, 3)
artifact_map = {}
artifact_relatives = set()
for source, relative, expected in artifacts:
    if source in artifact_map or relative in artifact_relatives:
        raise SystemExit(f"duplicate service runtime component mapping: {source}")
    if source not in dependency_map or dependency_map[source] != expected:
        raise SystemExit(f"runtime component is not bound to dependency evidence: {source}")
    relative_path = PurePosixPath(relative)
    if relative_path.is_absolute() or ".." in relative_path.parts or not relative.startswith("artifacts/service-runtime-components/"):
        raise SystemExit(f"unsafe service runtime component path: {relative}")
    artifact_path = out / relative
    if not artifact_path.is_file() or artifact_path.is_symlink() or digest(artifact_path) != expected:
        raise SystemExit(f"service runtime component hash does not verify: {relative}")
    artifact_map[source] = relative
    artifact_relatives.add(relative)
if set(artifact_map) != set(dependency_map):
    raise SystemExit("service runtime component mapping does not cover every dependency")

component_files = {
    path.relative_to(out).as_posix(): digest(path)
    for path in component_dir.rglob("*")
    if path.is_file() and not path.is_symlink()
}
hash_rows = rows(hash_file, 2)
hash_map = {}
for relative, expected in hash_rows:
    if relative in hash_map:
        raise SystemExit(f"duplicate service runtime component hash: {relative}")
    if relative not in component_files or component_files[relative] != expected:
        raise SystemExit(f"service runtime component hash list does not verify: {relative}")
    hash_map[relative] = expected
if hash_map != component_files:
    raise SystemExit("service runtime component hash list does not cover the component directory")

loaded = Path(loaded_file).read_text(encoding="utf-8")
loaded_absolute_paths = set()
for line in loaded.splitlines():
    if "=>" not in line:
        continue
    for token in line.split():
        if token.startswith("/"):
            resolved = str(Path(token).resolve())
            loaded_absolute_paths.add(resolved)
            if not resolved.startswith(str(component_dir.resolve()) + "/"):
                raise SystemExit(f"loaded-dependency evidence selects an external component: {token}")
for relative_binary in ("clamscan/clamscan", "clamd/clamd", "clamdscan/clamdscan", "clamav-milter/clamav-milter"):
    if f"service={relative_binary}\n" not in loaded:
        raise SystemExit(f"loaded-dependency evidence is missing: {relative_binary}")
for relative in component_files:
    selected = str((out / relative).resolve())
    if selected not in loaded_absolute_paths:
        raise SystemExit(f"loaded-dependency evidence does not select copied component: {relative}")
PY
    fail 'service runtime component or loader evidence is invalid'

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

service_elf_interpreter()
{
    # Parse PT_INTERP directly so verification binds each service executable to
    # its selected loader without requiring a host-specific readelf utility.
    python3 - "$1" <<'PY'
import struct
import sys

path = sys.argv[1]
try:
    with open(path, "rb") as stream:
        header = stream.read(64)
        if len(header) != 64 or header[:7] != b"\x7fELF\x02\x01\x01":
            raise ValueError("not an ELF64 little-endian x86 executable")
        e_phoff = struct.unpack_from("<Q", header, 32)[0]
        e_phentsize = struct.unpack_from("<H", header, 54)[0]
        e_phnum = struct.unpack_from("<H", header, 56)[0]
        if e_phentsize < 56:
            raise ValueError("invalid program-header size")
        stream.seek(0, 2)
        file_size = stream.tell()
        if e_phoff > file_size or e_phnum > (file_size - e_phoff) // e_phentsize:
            raise ValueError("program-header table is outside the file")
        for index in range(e_phnum):
            entry_offset = e_phoff + index * e_phentsize
            stream.seek(entry_offset)
            entry = stream.read(56)
            if len(entry) != 56:
                raise ValueError("short program header")
            p_type, _p_flags, p_offset, _p_vaddr, _p_paddr, p_filesz, _p_memsz, _p_align = struct.unpack(
                "<IIQQQQQQ", entry
            )
            if p_type != 3:
                continue
            if p_filesz == 0 or p_filesz > 4096 or p_offset > file_size or p_filesz > file_size - p_offset:
                raise ValueError("invalid PT_INTERP range")
            stream.seek(p_offset)
            raw = stream.read(p_filesz)
            if len(raw) != p_filesz:
                raise ValueError("short PT_INTERP payload")
            interpreter = raw.split(b"\0", 1)[0]
            if not interpreter.startswith(b"/"):
                raise ValueError("PT_INTERP is not an absolute path")
            print(interpreter.decode("ascii"))
            break
        else:
            raise ValueError("ELF has no PT_INTERP")
except (OSError, ValueError, UnicodeDecodeError, struct.error):
    raise SystemExit(1)
PY
}

check_interpreter_list()
{
    list=$1
    if ! awk -F '\t' '
        BEGIN {
            expected["clamscan/clamscan"] = 1
            expected["clamd/clamd"] = 1
            expected["clamdscan/clamdscan"] = 1
            expected["clamav-milter/clamav-milter"] = 1
        }
        NF != 3 || !($1 in expected) || seen[$1]++ { bad = 1 }
        END {
            for (path in expected)
                if (!seen[path]) bad = 1
            exit bad
        }
    ' "$list"; then
        fail 'service interpreter record list is missing, duplicated, or malformed'
    fi
    while IFS= read -r relative_binary; do
        [ -n "$relative_binary" ] || continue
        line=$(awk -F '\t' -v path="$relative_binary" \
            '$1 == path { count++; value=$0 } END { if (count != 1) exit 1; print value }' "$list") ||
            fail "service interpreter record is missing or duplicated: $relative_binary"
        interpreter_path=$(printf '%s\n' "$line" | awk -F '\t' '{ print $2 }')
        expected_hash=$(printf '%s\n' "$line" | awk -F '\t' '{ print $3 }')
        case "$interpreter_path" in
            /*) ;;
            *) fail "service interpreter path is not absolute: $relative_binary" ;;
        esac
        is_hash "$expected_hash" || fail "service interpreter hash is invalid: $relative_binary"
        [ -f "$interpreter_path" ] || fail "service ELF interpreter is missing: $interpreter_path"
        actual_hash=$(sha256sum "$interpreter_path" | awk '{ print $1 }')
        [ "$actual_hash" = "$expected_hash" ] ||
            fail "service ELF interpreter hash does not match evidence: $relative_binary"
        actual_path=$(service_elf_interpreter "$build_dir/$relative_binary") ||
            fail "service executable has no valid ELF PT_INTERP: $relative_binary"
        [ "$actual_path" = "$interpreter_path" ] ||
            fail "service executable PT_INTERP does not match evidence: $relative_binary"
    done <<EOF
$expected_binaries
EOF
}
check_interpreter_list "$interpreter_records"
check_interpreter_list "$interpreter_records_after"

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
