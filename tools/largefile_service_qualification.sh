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

# Keep service binaries and dependency evidence bound to the qualified build;
# inherited loader hooks could inject code into clamd or any frontend.
unset LD_PRELOAD LD_AUDIT LD_LIBRARY_PATH

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)

if [ "$#" -ne 9 ]; then
    echo "usage: $0 BUILD_DIR OUTPUT_DIR PRODUCTION_DB PRODUCTION_FILE MATERIALIZED_FILE EXPANSION_FILE EDGE_FILE EDGE_DB ORACLE_MANIFEST" >&2
    exit 2
fi

build_dir=$(CDPATH= cd -- "$1" && pwd)
out=$2
production_db=$3
production_file=$4
materialized_file=$5
expansion_file=$6
edge_file=$7
edge_db=$8
oracle_manifest=$9

case "$out" in
    /*) ;;
    *) out=$(CDPATH= cd -- "$(dirname "$out")" && pwd)/$(basename "$out") ;;
esac
case "$out" in
    "$root"|"$root"/*)
        echo "service qualification output must be outside the source tree: $out" >&2
        exit 2
        ;;
esac

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

# Record stable absolute input names in the workload manifest. The oracle
# hashes, rather than the names, remain the authoritative input binding.
production_file=$(CDPATH= cd -- "$(dirname "$production_file")" && pwd)/$(basename "$production_file")
materialized_file=$(CDPATH= cd -- "$(dirname "$materialized_file")" && pwd)/$(basename "$materialized_file")
expansion_file=$(CDPATH= cd -- "$(dirname "$expansion_file")" && pwd)/$(basename "$expansion_file")
edge_file=$(CDPATH= cd -- "$(dirname "$edge_file")" && pwd)/$(basename "$edge_file")
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
    ! command -v ldd >/dev/null 2>&1 ||
    [ ! -x /usr/bin/time ]; then
    echo 'timeout, awk, python3, sha256sum, du, ldd, and GNU /usr/bin/time are required' >&2
    exit 2
fi
if [ ! -f "$root/tools/largefile_clamd_legacy_protocol.py" ]; then
    echo 'missing direct legacy clamd protocol probe' >&2
    exit 2
fi

mkdir -p "$out/provenance"

service_oracle_copy=$out/provenance/qualification-oracle.tsv
service_workload_results=$out/provenance/service-workload-results.tsv
cp "$oracle_manifest" "$service_oracle_copy"
# Reject undersized edge inputs and sparse materialized fixtures before any
# service is started. The same helper independently checks the final evidence.
python3 "$root/tools/largefile_service_workload_check.py" --check-inputs \
    "$service_oracle_copy" "$production_file" "$materialized_file" \
    "$expansion_file" "$edge_file" > "$out/provenance/service-inputs-before.json"
printf 'label\tkind\trole\tinput\tlog\treport\tstatus\tcheck_offset\n' > \
    "$service_workload_results"

# Bind every service process to the same immutable source/build identity as
# the clamscan runtime gate. The service gate executes build-tree binaries
# directly, so recording only their paths is insufficient: a stale binary or
# shared library with the same basename could otherwise satisfy the workload
# checks while the evidence describes a different revision.
service_cmake_cache=$build_dir/CMakeCache.txt
service_compile_commands=$build_dir/compile_commands.json
service_source_manifest=$out/provenance/source-manifest.txt
service_binary_hashes_before=$out/provenance/service-binary-hashes-before.txt
service_binary_hashes_after=$out/provenance/service-binary-hashes-after.txt
service_interpreter_records_before=$out/provenance/service-interpreter-records-before.txt
service_interpreter_records_after=$out/provenance/service-interpreter-records-after.txt
service_dependency_hashes=$out/provenance/service-runtime-dependency-hashes.txt
service_dependency_hashes_after=$out/provenance/service-runtime-dependency-hashes-after.txt
service_runtime_component_dir=$out/artifacts/service-runtime-components
service_runtime_component_artifacts=$out/provenance/service-runtime-component-artifacts.txt
service_runtime_component_hashes_before=$out/provenance/service-runtime-component-hashes-before.txt
service_runtime_component_hashes_after=$out/provenance/service-runtime-component-hashes-after.txt
service_loaded_dependencies=$out/provenance/service-loaded-dependencies.txt
service_build_identity=$out/provenance/service-build-identity.txt
service_parallel_profile=$out/provenance/parallel-client-clamd.conf
service_resource_samples=$out/provenance/service-resource-samples.tsv
service_case_resource_sidecar=$out/provenance/acceptance-case-resources.tsv

printf 'sequence\trss_kb\tpss_kb\tvas_kb\tswap_kb\tminor_faults\tmajor_faults\tread_bytes\twrite_bytes\tcancelled_write_bytes\tprocess_count\ttemporary_bytes\toom_events\toom_kill_events\toom_cgroup_digest\tsampled_pids\n' > \
    "$service_resource_samples"
printf 'kind\tid\tcase_id\tsource_manifest_sha256\tbuild_identity_sha256\tconfig_sha256\tplatform\tsample_source\tsample_count\trss_peak_kb\tpss_peak_kb\tvas_peak_kb\tswap_peak_kb\tminor_faults_peak\tmajor_faults_peak\tread_bytes_peak\twrite_bytes_peak\tcancelled_write_bytes_peak\ttemporary_peak_bytes\toom_events_peak\toom_kill_events_peak\toom_cgroup_count\toom_cgroup_digest\tpcre_rss_peak_kb\tpost_pcre_rss_peak_kb\n' > \
    "$service_case_resource_sidecar"
service_resource_sample_sequence=0

if [ ! -s "$service_cmake_cache" ] || [ ! -s "$service_compile_commands" ]; then
    echo "service qualification requires CMakeCache.txt and compile_commands.json in $build_dir" >&2
    exit 2
fi
service_cmake_source=$(sed -n 's#^CMAKE_HOME_DIRECTORY:INTERNAL=##p' "$service_cmake_cache")
if [ "$service_cmake_source" != "$root" ]; then
    echo "service build was configured from $service_cmake_source, not the audited source root $root" >&2
    exit 2
fi

service_git_checkout=no
if command -v git >/dev/null 2>&1 &&
    [ "$(git -C "$root" rev-parse --is-inside-work-tree 2>/dev/null || true)" = true ] &&
    [ "$(git -C "$root" rev-parse --show-toplevel 2>/dev/null || true)" = "$root" ]; then
    service_git_checkout=yes
    if [ -n "$(git -C "$root" status --porcelain --untracked-files=normal)" ]; then
        echo 'service qualification refuses a dirty source tree' >&2
        exit 2
    fi
    service_source_commit=$(git -C "$root" rev-parse --verify HEAD)
    service_source_tree=$(git -C "$root" rev-parse --verify "$service_source_commit^{tree}")
else
    service_source_commit=content-manifest
    service_source_tree=content-manifest
fi
"$root/tools/largefile_source_manifest.sh" "$root" "$service_source_manifest"
service_source_manifest_sha256=$(sha256sum "$service_source_manifest" | awk '{ print $1 }')
if [ "$service_git_checkout" = no ]; then
    service_source_commit=$service_source_manifest_sha256
    service_source_tree=$service_source_manifest_sha256
fi
service_cmake_commit=$(sed -n 's/^CLAMAV_SOURCE_COMMIT:INTERNAL=//p' "$service_cmake_cache")
service_cmake_manifest=$(sed -n 's/^CLAMAV_SOURCE_MANIFEST_SHA256:INTERNAL=//p' "$service_cmake_cache")
if [ "$service_cmake_commit" != "$service_source_commit" ] ||
    [ "$service_cmake_manifest" != "$service_source_manifest_sha256" ]; then
    echo 'service build provenance does not match the immutable source revision' >&2
    exit 2
fi
service_cmake_hash=$(sha256sum "$service_cmake_cache" | awk '{ print $1 }')
service_compile_commands_hash=$(sha256sum "$service_compile_commands" | awk '{ print $1 }')
cp "$service_cmake_cache" "$out/provenance/CMakeCache.txt"
cp "$service_compile_commands" "$out/provenance/compile_commands.json"

service_binaries="clamscan/clamscan clamd/clamd clamdscan/clamdscan clamav-milter/clamav-milter"
service_elf_interpreter()
{
    # Parse PT_INTERP directly so this gate does not depend on a host-specific
    # readelf installation or confuse the executable loader with LD_LIBRARY_PATH
    # resolved shared libraries.
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

record_service_binary_hashes()
{
    destination=$1
    : > "$destination"
    for relative_binary in $service_binaries; do
        service_binary="$build_dir/$relative_binary"
        if [ ! -x "$service_binary" ]; then
            echo "service qualification executable is not executable: $service_binary" >&2
            return 1
        fi
        service_binary_real=$(CDPATH= cd -- "$(dirname "$service_binary")" && pwd)/$(basename "$service_binary")
        case "$service_binary_real" in
            "$build_dir"/*) ;;
            *)
                echo "service executable escaped the configured build tree: $service_binary_real" >&2
                return 1
                ;;
        esac
        printf '%s\t%s\n' "$relative_binary" "$(sha256sum "$service_binary" | awk '{ print $1 }')" >> "$destination"
    done
}

record_service_binary_hashes "$service_binary_hashes_before"

record_service_interpreter_records()
{
    destination=$1
    : > "$destination"
    for relative_binary in $service_binaries; do
        service_binary="$build_dir/$relative_binary"
        interpreter=$(service_elf_interpreter "$service_binary") || {
            echo "service executable has no valid ELF PT_INTERP: $service_binary" >&2
            return 1
        }
        [ -f "$interpreter" ] || {
            echo "service ELF interpreter is not a regular file: $interpreter" >&2
            return 1
        }
        printf '%s\t%s\t%s\n' "$relative_binary" "$interpreter" \
            "$(sha256sum "$interpreter" | awk '{ print $1 }')" >> "$destination"
    done
}

record_service_interpreter_records "$service_interpreter_records_before"

record_service_dependency_hashes()
{
    destination=$1
    phase=$2
    : > "$destination"
    for relative_binary in $service_binaries; do
        service_binary="$build_dir/$relative_binary"
        service_ldd="$out/provenance/ldd-${phase}-${relative_binary%%/*}.txt"
        service_dependency_paths="$out/provenance/service-dependency-paths-${phase}-${relative_binary%%/*}.txt"
        # The before/after dependency manifests describe the build tree, not
        # the copied runtime directory used by the workload.  Keep this
        # probe independent of the workload's intentional LD_LIBRARY_PATH.
        (
            unset LD_LIBRARY_PATH
            ldd "$service_binary"
        ) > "$service_ldd" 2>&1
        if grep -F 'not found' "$service_ldd" >/dev/null 2>&1; then
            echo "service executable has unresolved runtime dependencies: $service_binary" >&2
            return 1
        fi
        awk '$0 ~ /=>/ { for (i = 1; i <= NF; i++) if ($i ~ /^\//) print $i }' "$service_ldd" |
            LC_ALL=C sort -u > "$service_dependency_paths"
        while IFS= read -r dependency; do
            [ -n "$dependency" ] || continue
            [ -f "$dependency" ] || {
                echo "service runtime dependency is not a regular file: $dependency" >&2
                return 1
            }
            printf '%s\t%s\n' "$dependency" "$(sha256sum "$dependency" | awk '{ print $1 }')" >> "$destination"
        done < "$service_dependency_paths"
    done
    LC_ALL=C sort -u "$destination" -o "$destination"
}

record_service_dependency_hashes "$service_dependency_hashes" before
service_dependency_hashes_sha256=$(sha256sum "$service_dependency_hashes" | awk '{ print $1 }')

materialize_service_runtime_components()
{
    mkdir -p "$service_runtime_component_dir"
    : > "$service_runtime_component_artifacts"
    while IFS="$(printf '\t')" read -r dependency expected_hash; do
        [ -n "$dependency" ] || continue
        dependency_name=$(basename "$dependency")
        case "$dependency_name" in
            ''|.|..)
                echo "service runtime dependency has no safe basename: $dependency" >&2
                return 1
                ;;
        esac
        artifact_rel="artifacts/service-runtime-components/$dependency_name"
        artifact="$out/$artifact_rel"
        if [ -e "$artifact" ]; then
            artifact_hash=$(sha256sum "$artifact" | awk '{ print $1 }')
            if [ "$artifact_hash" != "$expected_hash" ]; then
                echo "service runtime dependency basename collision: $dependency" >&2
                return 1
            fi
        else
            cp -L "$dependency" "$artifact"
        fi
        artifact_hash=$(sha256sum "$artifact" | awk '{ print $1 }')
        if [ "$artifact_hash" != "$expected_hash" ]; then
            echo "copied service runtime dependency hash mismatch: $dependency" >&2
            return 1
        fi
        printf '%s\t%s\t%s\n' "$dependency" "$artifact_rel" "$expected_hash" >> \
            "$service_runtime_component_artifacts"
    done < "$service_dependency_hashes"
    LC_ALL=C sort -u "$service_runtime_component_artifacts" -o "$service_runtime_component_artifacts"
}

record_service_runtime_component_hashes()
{
    destination=$1
    : > "$destination"
    find "$service_runtime_component_dir" -type f -print |
        LC_ALL=C sort |
        while IFS= read -r artifact; do
            artifact_rel=${artifact#"$out/"}
            printf '%s\t%s\n' "$artifact_rel" "$(sha256sum "$artifact" | awk '{ print $1 }')"
        done > "$destination"
}

record_service_loaded_dependencies()
{
    destination=$1
    : > "$destination"
    for relative_binary in $service_binaries; do
        service_binary="$build_dir/$relative_binary"
        service_ldd="$out/provenance/loaded-dependencies-${relative_binary%%/*}.txt"
        printf 'service=%s\n' "$relative_binary" >> "$destination"
        LD_LIBRARY_PATH="$service_runtime_component_dir" ldd "$service_binary" > \
            "$service_ldd" 2>&1
        cat "$service_ldd" >> "$destination"
        if grep -F 'not found' "$service_ldd" >/dev/null 2>&1; then
            echo "service executable has unresolved copied runtime dependencies: $service_binary" >&2
            return 1
        fi
        if ! awk -v component_dir="$service_runtime_component_dir/" '
            $0 ~ /=>/ {
                for (i = 1; i <= NF; i++)
                    if ($i ~ /^\// && index($i, component_dir) != 1)
                        bad = 1
            }
            END { exit bad }
        ' "$service_ldd"; then
            echo "service loader selected a dependency outside the copied runtime directory: $service_binary" >&2
            return 1
        fi
        while IFS= read -r dependency; do
            [ -n "$dependency" ] || continue
            dependency_name=$(basename "$dependency")
            grep -F "$service_runtime_component_dir/$dependency_name" "$service_ldd" >/dev/null 2>&1 || {
                echo "service loader did not select the copied dependency: $dependency" >&2
                return 1
            }
        done < "$out/provenance/service-dependency-paths-before-${relative_binary%%/*}.txt"
    done
}

materialize_service_runtime_components
record_service_runtime_component_hashes "$service_runtime_component_hashes_before"
record_service_loaded_dependencies "$service_loaded_dependencies"
service_runtime_component_artifacts_sha256=$(sha256sum "$service_runtime_component_artifacts" | awk '{ print $1 }')
service_runtime_component_hashes_before_sha256=$(sha256sum "$service_runtime_component_hashes_before" | awk '{ print $1 }')
service_loaded_dependencies_sha256=$(sha256sum "$service_loaded_dependencies" | awk '{ print $1 }')
# Every daemon, frontend, and milter process started below inherits this exact
# directory.  The ldd records above prove that the selected files, rather than
# merely the build-tree files, satisfy the runtime links.
export LD_LIBRARY_PATH="$service_runtime_component_dir"
{
    printf 'source_commit=%s\n' "$service_source_commit"
    printf 'source_tree=%s\n' "$service_source_tree"
    printf 'source_manifest_sha256=%s\n' "$service_source_manifest_sha256"
    printf 'cmake_cache_sha256=%s\n' "$service_cmake_hash"
    printf 'compile_commands_sha256=%s\n' "$service_compile_commands_hash"
    printf 'service_binary_hashes=provenance/service-binary-hashes-before.txt\n'
    printf 'service_binary_hashes_sha256=%s\n' "$(sha256sum "$service_binary_hashes_before" | awk '{ print $1 }')"
    printf 'service_interpreter_records=provenance/service-interpreter-records-before.txt\n'
    printf 'service_interpreter_records_sha256=%s\n' "$(sha256sum "$service_interpreter_records_before" | awk '{ print $1 }')"
    printf 'service_runtime_dependency_hashes=provenance/service-runtime-dependency-hashes.txt\n'
    printf 'service_runtime_dependency_hashes_sha256=%s\n' "$service_dependency_hashes_sha256"
    printf 'service_runtime_component_dir=artifacts/service-runtime-components\n'
    printf 'service_runtime_component_artifacts=provenance/service-runtime-component-artifacts.txt\n'
    printf 'service_runtime_component_artifacts_sha256=%s\n' "$service_runtime_component_artifacts_sha256"
    printf 'service_runtime_component_hashes=provenance/service-runtime-component-hashes-before.txt\n'
    printf 'service_runtime_component_hashes_sha256=%s\n' "$service_runtime_component_hashes_before_sha256"
    printf 'service_loaded_dependencies=provenance/service-loaded-dependencies.txt\n'
    printf 'service_loaded_dependencies_sha256=%s\n' "$service_loaded_dependencies_sha256"
    printf 'service_loader_path=artifacts/service-runtime-components\n'
    printf 'loader_injection=disabled\n'
} > "$service_build_identity"

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

workload_evidence_path()
{
    workload_path=$1
    case "$workload_path" in
        "$out"/*) printf '%s\n' "${workload_path#"$out"/}" ;;
        *)
            echo "workload evidence path is outside the service output: $workload_path" >&2
            return 1
            ;;
    esac
}

record_workload()
{
    workload_label=$1
    workload_kind=$2
    workload_role=$3
    workload_input=$4
    workload_log=$5
    workload_report=$6
    workload_status=$7
    workload_check_offset=$8
    workload_log_relative=$(workload_evidence_path "$workload_log")
    if [ "$workload_report" = - ]; then
        workload_report_relative=-
    else
        workload_report_relative=$(workload_evidence_path "$workload_report")
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$workload_label" "$workload_kind" "$workload_role" "$workload_input" \
        "$workload_log_relative" "$workload_report_relative" "$workload_status" \
        "$workload_check_offset" >> "$service_workload_results"
}

check_oracle_output()
{
    oracle_label=$1
    oracle_log=$2
    oracle_report=${3:-}
    oracle_check_report=${4:-no}
    oracle_check_offset=${5:-no}
    workload_kind=${6:-}
    workload_input=${7:-}

    case "$expected_exit" in
        0|1|2) ;;
        *)
            echo "$oracle_label has an unsupported expected exit status: $expected_exit" >&2
            return 1
            ;;
    esac
    if [ "$oracle_status" -ne "$expected_exit" ]; then
        echo "$oracle_label returned $oracle_status; expected $expected_exit" >&2
        return 1
    fi

    # Reuse the post-run signature-field parser so producer and verifier
    # cannot disagree about a substring or a name mentioned in a filename.
    if ! python3 - "$root/tools" "$service_oracle_copy" "$oracle_role" \
        "$oracle_label" "$oracle_log" "$oracle_check_offset" <<'PYLOG'
from pathlib import Path
import sys

sys.path.insert(0, sys.argv[1])
from largefile_service_workload_check import load_oracle, validate_log

oracle = load_oracle(Path(sys.argv[2]))
validate_log(Path(sys.argv[5]), sys.argv[4], oracle[sys.argv[3]], sys.argv[6] == "yes")
PYLOG
    then
        echo "$oracle_label did not produce the expected signature oracle" >&2
        return 1
    fi

    if [ "$oracle_check_report" = yes ]; then
        if [ ! -s "$oracle_report" ]; then
            echo "$oracle_label did not produce a structured report" >&2
            return 1
        fi
        if ! python3 - "$oracle_report" "$expected_completion" "$expected_signature" "$expected_offset" "$expected_type" "$expected_size" "$expected_exit" <<'PY'
import json
import sys

report_path, expected_completion, expected_signature, expected_offset, expected_type, expected_size, expected_exit = sys.argv[1:]
expected_exit = int(expected_exit)
if expected_exit not in (0, 1, 2):
    raise SystemExit("structured report oracle has an unsupported expected exit status")
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
if report.get("max_scan_size") != 68719476736:
    raise SystemExit("structured report max scan size is not the certified 64-GiB logical budget")
if report["logical_bytes"] > report["max_scan_size"]:
    raise SystemExit("structured report exceeds its declared logical-byte budget")
last_alert = report.get("last_alert")
if expected_signature == "-":
    if last_alert not in (None, ""):
        raise SystemExit("structured report contains an unexpected alert")
    if report.get("last_alert_offset") is not None:
        raise SystemExit("structured report contains an unexpected alert offset")
    if report.get("verdict") not in (0, 1):
        raise SystemExit("structured report contains an unexpected verdict")
elif last_alert not in (expected_signature, expected_signature + ".UNOFFICIAL"):
    raise SystemExit("structured report alert does not exactly match the oracle")
elif report.get("verdict") not in (2, 3):
    raise SystemExit("structured report detection does not carry a non-clean verdict")
elif type(report.get("last_alert_offset")) is not int or report["last_alert_offset"] < 0:
    raise SystemExit("structured report detection does not carry a native-width alert offset")
elif report["last_alert_offset"] != int(expected_offset):
    raise SystemExit("structured report alert offset does not exactly match the oracle")
if expected_exit in (0, 1) and report["status"] != 0:
    raise SystemExit("structured report status is non-success for expected exit")
if expected_exit == 2 and report["status"] == 0:
    raise SystemExit("structured report status is clean for expected error exit")
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
    if [ -n "$workload_kind" ]; then
        record_workload "$oracle_label" "$workload_kind" "$oracle_role" \
            "$workload_input" "$oracle_log" "$oracle_report" "$oracle_status" \
            "$oracle_check_offset"
    fi
}

rss_budget_kb=${CLAMAV_SERVICE_MAX_RSS_KB:-33554432}
pcre_rss_budget_kb=41943040
post_pcre_rss_budget_kb=12582912
case "$rss_budget_kb" in
    ''|*[!0-9]*) echo 'CLAMAV_SERVICE_MAX_RSS_KB must be numeric' >&2; exit 2 ;;
esac
if [ "$rss_budget_kb" -gt "$pcre_rss_budget_kb" ]; then
    echo 'CLAMAV_SERVICE_MAX_RSS_KB exceeds the PLAN PCRE-phase RSS ceiling' >&2
    exit 2
fi
latency_budget_s=${CLAMAV_SERVICE_MAX_LATENCY_S:-14400}
case "$latency_budget_s" in
    ''|*[!0-9]*) echo 'CLAMAV_SERVICE_MAX_LATENCY_S must be an integer number of seconds' >&2; exit 2 ;;
esac
service_timeout_s=${CLAMAV_SERVICE_TIMEOUT_S:-14400}
max_scan_time_ms=${CLAMAV_MAX_SCAN_TIME_MS:-14400000}
temporary_budget_bytes=68719476736
mkdir -p "$out" "$out/logs" "$out/tmp"
config=$out/clamd.conf
socket=$out/clamd.socket
pidfile=$out/clamd.pid
service_pid=
service_peak_rss_kb=0
service_peak_rss_process_count=0
service_peak_pss_kb=0
service_peak_vas_kb=0
service_peak_swap_kb=0
service_peak_minor_faults=0
service_peak_major_faults=0
service_peak_read_bytes=0
service_peak_write_bytes=0
service_peak_cancelled_write_bytes=0
service_peak_temp_bytes=0
service_rss_samples=0
service_peak_oom_events=0
service_peak_oom_kill_events=0
service_oom_samples=0
service_temp_samples=0
service_resource_measurement_failed=0
service_resource_roots=
service_rss_measurement=procfs-process-tree-vmrss
service_memory_metrics=procfs-process-tree-status-smaps-rollup-stat-io
service_oom_measurement=procfs-cgroup-v2-memory-events
service_case_resource_active=no
service_case_resource_kind=
service_case_resource_id=
service_case_resource_case_id=
service_case_resource_sample_count=0
service_case_resource_rss_peak_kb=0
service_case_resource_pss_peak_kb=0
service_case_resource_vas_peak_kb=0
service_case_resource_swap_peak_kb=0
service_case_resource_minor_faults_peak=0
service_case_resource_major_faults_peak=0
service_case_resource_read_bytes_peak=0
service_case_resource_write_bytes_peak=0
service_case_resource_cancelled_write_bytes_peak=0
service_case_resource_temporary_peak_bytes=0
service_case_resource_oom_events_peak=0
service_case_resource_oom_kill_events_peak=0
service_case_resource_oom_cgroup_count=0
service_case_resource_oom_cgroup_digest=
service_lifecycle=$out/provenance/service-lifecycle.tsv
printf 'generation\tevent\tresult\n' > "$service_lifecycle"
service_generation=0

case "$service_timeout_s" in
    ''|*[!0-9]*|0*)
        echo 'CLAMAV_SERVICE_TIMEOUT_S must be a positive integer' >&2
        exit 2
        ;;
esac
if [ "$service_timeout_s" -lt 14400 ]; then
    echo 'CLAMAV_SERVICE_TIMEOUT_S must cover the four-hour MaxScanTime deadline' >&2
    exit 2
fi
case "$max_scan_time_ms" in
    ''|*[!0-9]*|0*)
        echo 'CLAMAV_MAX_SCAN_TIME_MS must be a canonical positive integer' >&2
        exit 2
        ;;
esac
if [ "${#max_scan_time_ms}" -gt 10 ] ||
    { [ "${#max_scan_time_ms}" -eq 10 ] && [ "$max_scan_time_ms" -gt 4294967295 ]; }; then
    echo 'CLAMAV_MAX_SCAN_TIME_MS must be a canonical integer from 1 through 4294967295' >&2
    exit 2
fi
if ! awk -v timeout_s="$service_timeout_s" -v scan_time_ms="$max_scan_time_ms" \
    'BEGIN { exit !((timeout_s * 1000) >= scan_time_ms) }'; then
    echo 'CLAMAV_SERVICE_TIMEOUT_S is shorter than CLAMAV_MAX_SCAN_TIME_MS' >&2
    exit 2
fi

service_oom_baseline_sample=$(python3 "$root/tools/largefile_procfs_tree_oom.py" "$$" 2>/dev/null || true)
service_oom_baseline=$(printf '%s\n' "$service_oom_baseline_sample" |
    awk -F '\t' 'NF == 4 && $1 ~ /^[0-9]+$/ { print $1; exit }')
service_oom_kill_baseline=$(printf '%s\n' "$service_oom_baseline_sample" |
    awk -F '\t' 'NF == 4 && $2 ~ /^[0-9]+$/ { print $2; exit }')
service_oom_cgroup_count=$(printf '%s\n' "$service_oom_baseline_sample" |
    awk -F '\t' 'NF == 4 && $3 ~ /^[0-9]+$/ { print $3; exit }')
service_oom_cgroup_digest=$(printf '%s\n' "$service_oom_baseline_sample" |
    awk -F '\t' 'NF == 4 && $4 ~ /^[0-9a-fA-F]{64}$/ { print $4; exit }')
case "$service_oom_baseline:$service_oom_kill_baseline:$service_oom_cgroup_count" in
    ''|*[!0-9:]*)
        echo 'service qualification requires readable cgroup-v2 OOM counters' >&2
        exit 2
        ;;
esac
case "$service_oom_cgroup_digest" in
    ''|*[!0-9a-fA-F]*)
        echo 'service qualification received an invalid cgroup-v2 identity digest' >&2
        exit 2
        ;;
esac
if [ "${#service_oom_cgroup_digest}" -ne 64 ] || [ "$service_oom_cgroup_count" -lt 1 ]; then
    echo 'service qualification received an incomplete cgroup-v2 identity' >&2
    exit 2
fi
service_peak_oom_events=$service_oom_baseline
service_peak_oom_kill_events=$service_oom_kill_baseline

resource_root_add()
{
    resource_root_pid=$1
    case " $service_resource_roots " in
        *" $resource_root_pid "*) ;;
        *) service_resource_roots="$service_resource_roots $resource_root_pid" ;;
    esac
}

resource_root_remove()
{
    resource_root_pid=$1
    retained_resource_roots=
    for existing_resource_root in $service_resource_roots; do
        if [ "$existing_resource_root" != "$resource_root_pid" ]; then
            retained_resource_roots="$retained_resource_roots $existing_resource_root"
        fi
    done
    service_resource_roots=$retained_resource_roots
}

service_case_resource_begin()
{
    if [ "$service_case_resource_active" = yes ]; then
        echo 'service per-case resource capture is already active' >&2
        return 1
    fi
    service_case_resource_kind=$1
    service_case_resource_id=$2
    service_case_resource_case_id=$3
    service_case_resource_active=yes
    service_case_resource_sample_count=0
    service_case_resource_rss_peak_kb=0
    service_case_resource_pss_peak_kb=0
    service_case_resource_vas_peak_kb=0
    service_case_resource_swap_peak_kb=0
    service_case_resource_minor_faults_peak=0
    service_case_resource_major_faults_peak=0
    service_case_resource_read_bytes_peak=0
    service_case_resource_write_bytes_peak=0
    service_case_resource_cancelled_write_bytes_peak=0
    service_case_resource_temporary_peak_bytes=0
    service_case_resource_oom_events_peak=0
    service_case_resource_oom_kill_events_peak=0
    service_case_resource_oom_cgroup_count=0
    service_case_resource_oom_cgroup_digest=
}

service_case_resource_begin_for_role()
{
    service_case_kind=$1
    service_case_id=$2
    service_case_role=$3
    case "$service_case_role" in
        production) service_case_completion=$oracle_production_completion ;;
        edge) service_case_completion=$oracle_edge_completion ;;
        *)
            echo "unknown service resource role: $service_case_role" >&2
            return 1
            ;;
    esac
    case "$service_case_completion" in
        COMPLETE) service_case_suffix=clean-edge ;;
        DETECTION_TERMINATED) service_case_suffix=detection-edge ;;
        LIMIT_INCOMPLETE) service_case_suffix=limit-edge ;;
        *)
            echo "service resource role has no acceptance case completion: $service_case_role:$service_case_completion" >&2
            return 1
            ;;
    esac
    service_case_resource_begin "$service_case_kind" "$service_case_id" \
        "$service_case_kind:$service_case_id:$service_case_suffix"
}

service_case_resource_end()
{
    if [ "$service_case_resource_active" != yes ]; then
        return 0
    fi
    if [ "$service_case_resource_sample_count" -lt 1 ] ||
        [ -z "$service_case_resource_oom_cgroup_digest" ] ||
        [ "$service_case_resource_oom_cgroup_count" -lt 1 ]; then
        echo "service per-case resource capture has no complete sample: $service_case_resource_case_id" >&2
        return 1
    fi
    if awk -F '\t' -v kind="$service_case_resource_kind" \
        -v identifier="$service_case_resource_id" \
        -v case_id="$service_case_resource_case_id" \
        'NR > 1 && $1 == kind && $2 == identifier && $3 == case_id { found = 1 } END { exit found }' \
        "$service_case_resource_sidecar"; then
        :
    else
        echo "service per-case resource capture duplicated a case: $service_case_resource_case_id" >&2
        return 1
    fi
    printf '%s\t%s\t%s\tpending\tpending\tpending\t%s-%s\tprocfs-process-tree\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t-\t-\n' \
        "$service_case_resource_kind" "$service_case_resource_id" \
        "$service_case_resource_case_id" "$(uname -s)" "$(uname -m)" \
        "$service_case_resource_sample_count" \
        "$service_case_resource_rss_peak_kb" "$service_case_resource_pss_peak_kb" \
        "$service_case_resource_vas_peak_kb" "$service_case_resource_swap_peak_kb" \
        "$service_case_resource_minor_faults_peak" "$service_case_resource_major_faults_peak" \
        "$service_case_resource_read_bytes_peak" "$service_case_resource_write_bytes_peak" \
        "$service_case_resource_cancelled_write_bytes_peak" \
        "$service_case_resource_temporary_peak_bytes" \
        "$service_case_resource_oom_events_peak" "$service_case_resource_oom_kill_events_peak" \
        "$service_case_resource_oom_cgroup_count" "$service_case_resource_oom_cgroup_digest" \
        >> "$service_case_resource_sidecar"
    service_case_resource_active=no
}

finalize_service_case_resources()
{
    if [ "$service_case_resource_active" = yes ]; then
        echo "service per-case resource capture was not closed: $service_case_resource_case_id" >&2
        return 1
    fi
    python3 - "$service_case_resource_sidecar" "$service_build_identity" \
        "$out/provenance/CMakeCache.txt" "$root/tools" \
        "$service_source_manifest_sha256" <<'PY'
from pathlib import Path
import csv
import os
import sys

sidecar, build_identity, config, tools = map(Path, sys.argv[1:5])
source_hash = sys.argv[5]
sys.path.insert(0, str(tools))
import largefile_acceptance_resources as resources

rows = resources.read_resources(sidecar)
if not rows:
    raise SystemExit("service per-case resource sidecar is empty")
build_hash = resources.sha256(build_identity)
config_hash = resources.sha256(config)
if len(source_hash) != 64:
    raise SystemExit("service source manifest hash is unavailable for per-case resources")
for row in rows:
    if any(row[field] != "pending" for field in resources.HASH_FIELDS):
        raise SystemExit("service per-case resource sidecar has pre-filled identity hashes")
    row["source_manifest_sha256"] = source_hash
    row["build_identity_sha256"] = build_hash
    row["config_sha256"] = config_hash
staging = sidecar.with_name(f".{sidecar.name}.identity-staging")
try:
    with staging.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(
            stream, fieldnames=resources.RESOURCE_HEADER,
            delimiter="\t", lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(rows)
    os.replace(staging, sidecar)
finally:
    if staging.exists():
        staging.unlink()
PY
}

measure_service_resources()
{
    resource_sample_valid=no
    oom_sample_valid=no
    temp_sample_valid=no
    rss=
    pss=
    vas=
    swap=
    minor_faults=
    major_faults=
    read_bytes=
    write_bytes=
    cancelled_write_bytes=
    process_count=
    oom_events=
    oom_kill_events=
    oom_cgroup_count=
    oom_cgroup_digest=
    sampled_pids=
    if [ -n "$service_resource_roots" ]; then
        resource_root_live=no
        for resource_root_pid in $service_resource_roots; do
            if [ -r "/proc/$resource_root_pid/status" ]; then
                resource_root_live=yes
                break
            fi
        done
        if [ "$resource_root_live" = yes ]; then
            resource_sample=$(python3 "$root/tools/largefile_procfs_tree_metrics.py" \
                $service_resource_roots 2>/dev/null || true)
            rss=$(printf '%s\n' "$resource_sample" |
                awk -F '\t' 'NF == 11 && $1 ~ /^[0-9]+$/ { print $1; exit }')
            pss=$(printf '%s\n' "$resource_sample" |
                awk -F '\t' 'NF == 11 && $2 ~ /^[0-9]+$/ { print $2; exit }')
            vas=$(printf '%s\n' "$resource_sample" |
                awk -F '\t' 'NF == 11 && $3 ~ /^[0-9]+$/ { print $3; exit }')
            swap=$(printf '%s\n' "$resource_sample" |
                awk -F '\t' 'NF == 11 && $4 ~ /^[0-9]+$/ { print $4; exit }')
            minor_faults=$(printf '%s\n' "$resource_sample" |
                awk -F '\t' 'NF == 11 && $5 ~ /^[0-9]+$/ { print $5; exit }')
            major_faults=$(printf '%s\n' "$resource_sample" |
                awk -F '\t' 'NF == 11 && $6 ~ /^[0-9]+$/ { print $6; exit }')
            read_bytes=$(printf '%s\n' "$resource_sample" |
                awk -F '\t' 'NF == 11 && $7 ~ /^[0-9]+$/ { print $7; exit }')
            write_bytes=$(printf '%s\n' "$resource_sample" |
                awk -F '\t' 'NF == 11 && $8 ~ /^[0-9]+$/ { print $8; exit }')
            cancelled_write_bytes=$(printf '%s\n' "$resource_sample" |
                awk -F '\t' 'NF == 11 && $9 ~ /^[0-9]+$/ { print $9; exit }')
            process_count=$(printf '%s\n' "$resource_sample" |
                awk -F '\t' 'NF == 11 && $10 ~ /^[0-9]+$/ { print $10; exit }')
            sampled_pids=$(printf '%s\n' "$resource_sample" |
                awk -F '\t' 'NF == 11 && $11 ~ /^[0-9][0-9,]*$/ { print $11; exit }')
            case "$rss:$pss:$vas:$swap:$minor_faults:$major_faults:$read_bytes:$write_bytes:$cancelled_write_bytes:$process_count" in
                ''|*[!0-9:]*) service_resource_measurement_failed=1 ;;
                *)
                    case "$sampled_pids" in
                        ''|*[!0-9,]*) service_resource_measurement_failed=1 ;;
                        *)
                            sampled_pid_count=$(printf '%s\n' "$sampled_pids" | awk -F ',' '{ print NF }')
                            if [ "$process_count" -lt 1 ] || [ "$sampled_pid_count" -ne "$process_count" ] ||
                                [ "$pss" -gt "$rss" ] || [ "$vas" -lt "$rss" ]; then
                                service_resource_measurement_failed=1
                            else
                                resource_sample_valid=yes
                            fi
                            ;;
                    esac
                    if [ "$resource_sample_valid" = yes ]; then
                        if [ "$rss" -gt "$service_peak_rss_kb" ]; then
                            service_peak_rss_kb=$rss
                            service_peak_rss_process_count=$process_count
                        elif [ "$rss" -eq "$service_peak_rss_kb" ] &&
                            [ "$process_count" -gt "$service_peak_rss_process_count" ]; then
                            service_peak_rss_process_count=$process_count
                        fi
                        if [ "$pss" -gt "$service_peak_pss_kb" ]; then service_peak_pss_kb=$pss; fi
                        if [ "$vas" -gt "$service_peak_vas_kb" ]; then service_peak_vas_kb=$vas; fi
                        if [ "$swap" -gt "$service_peak_swap_kb" ]; then service_peak_swap_kb=$swap; fi
                        if [ "$minor_faults" -gt "$service_peak_minor_faults" ]; then service_peak_minor_faults=$minor_faults; fi
                        if [ "$major_faults" -gt "$service_peak_major_faults" ]; then service_peak_major_faults=$major_faults; fi
                        if [ "$read_bytes" -gt "$service_peak_read_bytes" ]; then service_peak_read_bytes=$read_bytes; fi
                        if [ "$write_bytes" -gt "$service_peak_write_bytes" ]; then service_peak_write_bytes=$write_bytes; fi
                        if [ "$cancelled_write_bytes" -gt "$service_peak_cancelled_write_bytes" ]; then service_peak_cancelled_write_bytes=$cancelled_write_bytes; fi
                    fi
                    ;;
            esac
            oom_sample=$(python3 "$root/tools/largefile_procfs_tree_oom.py" \
                $service_resource_roots 2>/dev/null || true)
            oom_events=$(printf '%s\n' "$oom_sample" |
                awk -F '\t' 'NF == 4 && $1 ~ /^[0-9]+$/ { print $1; exit }')
            oom_kill_events=$(printf '%s\n' "$oom_sample" |
                awk -F '\t' 'NF == 4 && $2 ~ /^[0-9]+$/ { print $2; exit }')
            oom_cgroup_count=$(printf '%s\n' "$oom_sample" |
                awk -F '\t' 'NF == 4 && $3 ~ /^[0-9]+$/ { print $3; exit }')
            oom_cgroup_digest=$(printf '%s\n' "$oom_sample" |
                awk -F '\t' 'NF == 4 && $4 ~ /^[0-9a-fA-F]{64}$/ { print $4; exit }')
            case "$oom_events:$oom_kill_events:$oom_cgroup_count" in
                ''|*[!0-9:]*) service_resource_measurement_failed=1 ;;
                *)
                    case "$oom_cgroup_digest" in
                        ''|*[!0-9a-fA-F]*) service_resource_measurement_failed=1 ;;
                        *)
                            if [ "${#oom_cgroup_digest}" -ne 64 ] ||
                                [ "$oom_cgroup_count" -ne "$service_oom_cgroup_count" ] ||
                                [ "$oom_cgroup_digest" != "$service_oom_cgroup_digest" ] ||
                                [ "$oom_events" -lt "$service_oom_baseline" ] ||
                                [ "$oom_kill_events" -lt "$service_oom_kill_baseline" ]; then
                                service_resource_measurement_failed=1
                            else
                                oom_sample_valid=yes
                                if [ "$oom_events" -gt "$service_peak_oom_events" ]; then service_peak_oom_events=$oom_events; fi
                                if [ "$oom_kill_events" -gt "$service_peak_oom_kill_events" ]; then service_peak_oom_kill_events=$oom_kill_events; fi
                            fi
                            ;;
                    esac
                    ;;
            esac
        fi
    fi
    current_tmp_bytes=$(du -s -B1 "$out/tmp" 2>/dev/null | awk 'NF >= 1 && $1 ~ /^[0-9]+$/ { print $1; exit }')
    case "$current_tmp_bytes" in
        ''|*[!0-9]*) service_resource_measurement_failed=1 ;;
        *)
            temp_sample_valid=yes
            service_temp_samples=$((service_temp_samples + 1))
            if [ "$current_tmp_bytes" -gt "$service_peak_temp_bytes" ]; then service_peak_temp_bytes=$current_tmp_bytes; fi
            ;;
    esac
    if [ "$resource_sample_valid" = yes ] && [ "$oom_sample_valid" = yes ] &&
        [ "$temp_sample_valid" = yes ] && [ "$service_case_resource_active" = yes ]; then
        service_case_resource_sample_count=$((service_case_resource_sample_count + 1))
        if [ "$rss" -gt "$service_case_resource_rss_peak_kb" ]; then service_case_resource_rss_peak_kb=$rss; fi
        if [ "$pss" -gt "$service_case_resource_pss_peak_kb" ]; then service_case_resource_pss_peak_kb=$pss; fi
        if [ "$vas" -gt "$service_case_resource_vas_peak_kb" ]; then service_case_resource_vas_peak_kb=$vas; fi
        if [ "$swap" -gt "$service_case_resource_swap_peak_kb" ]; then service_case_resource_swap_peak_kb=$swap; fi
        if [ "$minor_faults" -gt "$service_case_resource_minor_faults_peak" ]; then service_case_resource_minor_faults_peak=$minor_faults; fi
        if [ "$major_faults" -gt "$service_case_resource_major_faults_peak" ]; then service_case_resource_major_faults_peak=$major_faults; fi
        if [ "$read_bytes" -gt "$service_case_resource_read_bytes_peak" ]; then service_case_resource_read_bytes_peak=$read_bytes; fi
        if [ "$write_bytes" -gt "$service_case_resource_write_bytes_peak" ]; then service_case_resource_write_bytes_peak=$write_bytes; fi
        if [ "$cancelled_write_bytes" -gt "$service_case_resource_cancelled_write_bytes_peak" ]; then service_case_resource_cancelled_write_bytes_peak=$cancelled_write_bytes; fi
        if [ "$current_tmp_bytes" -gt "$service_case_resource_temporary_peak_bytes" ]; then service_case_resource_temporary_peak_bytes=$current_tmp_bytes; fi
        case_oom_events_delta=$((oom_events - service_oom_baseline))
        case_oom_kill_events_delta=$((oom_kill_events - service_oom_kill_baseline))
        if [ "$case_oom_events_delta" -gt "$service_case_resource_oom_events_peak" ]; then service_case_resource_oom_events_peak=$case_oom_events_delta; fi
        if [ "$case_oom_kill_events_delta" -gt "$service_case_resource_oom_kill_events_peak" ]; then service_case_resource_oom_kill_events_peak=$case_oom_kill_events_delta; fi
        service_case_resource_oom_cgroup_count=$oom_cgroup_count
        service_case_resource_oom_cgroup_digest=$oom_cgroup_digest
    fi
    if [ "$resource_sample_valid" = yes ] && [ "$oom_sample_valid" = yes ] &&
        [ "$temp_sample_valid" = yes ]; then
        service_resource_sample_sequence=$((service_resource_sample_sequence + 1))
        service_rss_samples=$((service_rss_samples + 1))
        service_oom_samples=$((service_oom_samples + 1))
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$service_resource_sample_sequence" "$rss" "$pss" "$vas" "$swap" \
            "$minor_faults" "$major_faults" "$read_bytes" "$write_bytes" \
            "$cancelled_write_bytes" "$process_count" "$current_tmp_bytes" \
            "$oom_events" "$oom_kill_events" "$oom_cgroup_digest" \
            "$sampled_pids" >> "$service_resource_samples"
    fi
}

cleanup()
{
    if [ -n "${service_pid:-}" ] && kill -0 "$service_pid" 2>/dev/null; then
        kill "$service_pid" 2>/dev/null || true
        wait "$service_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT HUP INT TERM

record_service_lifecycle()
{
    printf '%s\t%s\t%s\n' "$service_generation" "$1" "$2" >> "$service_lifecycle"
}

stop_service()
{
    if [ -z "${service_pid:-}" ]; then
        return 0
    fi

    ping_before_stop=fail
    ping_before_stop_log="$out/logs/ping-before-stop-$service_generation.log"
    if "$build_dir/clamdscan/clamdscan" --ping 5 -c "$config" > "$ping_before_stop_log" 2>&1 &&
        grep -Fx 'PONG' "$ping_before_stop_log" >/dev/null 2>&1; then
        ping_before_stop=pass
    fi
    record_service_lifecycle ping_before_stop "$ping_before_stop"

    service_was_running=no
    if kill -0 "$service_pid" 2>/dev/null; then
        service_was_running=yes
        kill "$service_pid" 2>/dev/null || true
        wait "$service_pid" 2>/dev/null || true
    fi
    record_service_lifecycle daemon_running_before_stop "$service_was_running"

    service_exited_after_stop=no
    if ! kill -0 "$service_pid" 2>/dev/null; then
        service_exited_after_stop=yes
    fi
    record_service_lifecycle daemon_exited_after_stop "$service_exited_after_stop"

    socket_absent_after_stop=no
    if [ ! -e "$socket" ] && [ ! -L "$socket" ]; then
        socket_absent_after_stop=yes
    fi
    record_service_lifecycle socket_absent_after_stop "$socket_absent_after_stop"

    pidfile_absent_after_stop=no
    if [ ! -e "$pidfile" ] && [ ! -L "$pidfile" ]; then
        pidfile_absent_after_stop=yes
    fi
    record_service_lifecycle pidfile_absent_after_stop "$pidfile_absent_after_stop"

    resource_root_remove "$service_pid"
    service_pid=
    if [ "$ping_before_stop" != pass ] ||
        [ "$service_was_running" != yes ] ||
        [ "$service_exited_after_stop" != yes ] ||
        [ "$socket_absent_after_stop" != yes ] ||
        [ "$pidfile_absent_after_stop" != yes ]; then
        echo "clamd lifecycle cleanup failed for generation $service_generation" >&2
        return 1
    fi
}

write_config()
{
    database=$1
    max_threads=$2
    max_queue=$3
    alert_exceeds_max=${4:-yes}
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
        # Keep daemon engine-side large-file caps aligned with the direct
        # clamscan qualification path.  These options are separate from the
        # shared scan-resource budgets above and otherwise retain small legacy
        # defaults even when the 32-GiB service profile is enabled.
        printf 'MaxHTMLNormalize 32G\n'
        printf 'MaxHTMLNoTags 32G\n'
        printf 'MaxScriptNormalize 32G\n'
        printf 'MaxZipTypeRcg 32G\n'
        printf 'MaxScanTime %s\n' "$max_scan_time_ms"
        printf 'AlertExceedsMax %s\n' "$alert_exceeds_max"
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
            printf 'CVDCertsDirectory %s\n' "$CLAMAV_CVD_CERTS_DIR"
        fi
    } > "$config"
}

start_service()
{
    database=$1
    max_threads=${2:-1}
    max_queue=${3:-2}
    alert_exceeds_max=${4:-yes}
    service_generation=$((service_generation + 1))
    write_config "$database" "$max_threads" "$max_queue" "$alert_exceeds_max"
    "$build_dir/clamd/clamd" --config-file="$config" > "$out/logs/clamd-$(basename "$database").log" 2>&1 &
    service_pid=$!
    resource_root_add "$service_pid"
    i=0
    # --wait intentionally enters the normal client path after a successful
    # ping, which scans the current directory when no input was supplied.
    # The qualification startup loop already owns the retry policy, so use
    # ping-only mode here to prove PONG without accidentally scanning $PWD.
    ping_log="$out/logs/ping-$(basename "$database")-$service_generation.log"
    while ! "$build_dir/clamdscan/clamdscan" --ping 5 -c "$config" > "$ping_log" 2>&1; do
        if ! kill -0 "$service_pid" 2>/dev/null || [ "$i" -ge 60 ]; then
            echo "clamd did not become ready for $database" >&2
            return 1
        fi
        i=$((i + 1))
        sleep 1
    done
    if ! grep -Fx 'PONG' "$ping_log" >/dev/null 2>&1; then
        echo "clamd startup PING did not produce an exact PONG for $database" >&2
        return 1
    fi
    record_service_lifecycle ping_after_start pass
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
    case "$scan_label" in
        production_cvd_fildes)
            service_case_resource_begin_for_role clamdscan fdpass production
            ;;
        *) ;;
    esac
    "/usr/bin/time" -f '%e' -o "$out/logs/$scan_label.elapsed" \
        timeout --signal=TERM --kill-after=5 "$service_timeout_s" \
        "$build_dir/clamdscan/clamdscan" --infected --no-summary --report-json="$scan_report" "$@" -c "$config" "$scan_file" > "$scan_log" 2>&1 &
    scan_pid=$!
    resource_root_add "$scan_pid"
    while kill -0 "$scan_pid" 2>/dev/null; do
        measure_service_resources
        sleep 0.05
    done
    wait "$scan_pid" || scan_status=$?
    resource_root_remove "$scan_pid"
    service_case_resource_end
    case "$scan_status" in
        0|1|2) ;;
        *) echo "$scan_label failed with status $scan_status" >&2; return 1 ;;
    esac
    if grep -Eiq 'AddressSanitizer|UndefinedBehaviorSanitizer|runtime error|Segmentation fault|stack smashing' "$scan_log"; then
        echo "$scan_label emitted a crash/sanitizer diagnostic" >&2
        return 1
    fi
    oracle_status=$scan_status
    check_oracle_output "$scan_label" "$scan_log" "$scan_report" yes no service "$scan_file"
    printf '%s_status=%s\n' "$scan_label" "$scan_status" >> "$out/service-summary.txt"
    return 0
}

run_service_stdin()
{
    scan_label=edge-clamdscan-stdin
    oracle_load edge "$edge_file"
    service_case_resource_begin_for_role clamdscan stream edge
    scan_log=$out/logs/$scan_label.log
    scan_report=$out/reports/$scan_label.jsonl
    scan_status=0
    (
        "/usr/bin/time" -f '%e' -o "$out/logs/$scan_label.elapsed" \
            sh -c 'cat "$1" | timeout --signal=TERM --kill-after=5 "$3" "$2" \
                --infected --no-summary --report-json="$4" -c "$5" -' sh \
                "$edge_file" "$build_dir/clamdscan/clamdscan" "$service_timeout_s" \
                "$scan_report" "$config"
    ) > "$scan_log" 2>&1 &
    scan_pid=$!
    resource_root_add "$scan_pid"
    while kill -0 "$scan_pid" 2>/dev/null; do
        measure_service_resources
        sleep 0.05
    done
    wait "$scan_pid" || scan_status=$?
    resource_root_remove "$scan_pid"
    service_case_resource_end
    case "$scan_status" in
        0|1|2) ;;
        *) echo "$scan_label failed with status $scan_status" >&2; return 1 ;;
    esac
    if grep -Eiq 'AddressSanitizer|UndefinedBehaviorSanitizer|runtime error|Segmentation fault|stack smashing' "$scan_log"; then
        echo "$scan_label emitted a crash/sanitizer diagnostic" >&2
        return 1
    fi
    oracle_status=$scan_status
    check_oracle_output "$scan_label" "$scan_log" "$scan_report" yes no service "$edge_file"
    printf '%s_status=%s\n' "$scan_label" "$scan_status" >> "$out/service-summary.txt"
    return 0
}

run_direct_production()
{
    oracle_load production "$production_file"
    service_case_resource_begin_for_role clamscan file production
    direct_status=0
    report="$out/reports/production-clamscan.jsonl"
    (
        "/usr/bin/time" -f '%e' -o "$out/logs/production-clamscan.elapsed" \
            timeout --signal=TERM --kill-after=5 "$service_timeout_s" \
            "$build_dir/clamscan/clamscan" --database="$production_db" \
            --max-filesize=32G --max-scansize=64G --max-matcher-work=256G \
            --max-temporary-size=64G --max-contiguous-size=32G \
            --max-htmlnormalize=32G --max-htmlnotags=32G \
            --max-scriptnormalize=32G --max-ziptypercg=32G \
            --pcre-max-filesize=32G --max-scantime="$max_scan_time_ms" \
            --no-summary --debug --report-json="$report" "$production_file" \
            > "$out/logs/production-clamscan.log" 2>&1 || exit $?
    ) &
    direct_pid=$!
    resource_root_add "$direct_pid"
    while kill -0 "$direct_pid" 2>/dev/null; do
        measure_service_resources
        sleep 0.05
    done
    wait "$direct_pid" || direct_status=$?
    resource_root_remove "$direct_pid"
    service_case_resource_end
    oracle_status=$direct_status
    if ! check_oracle_output production-clamscan "$out/logs/production-clamscan.log" "$report" yes yes cli "$production_file"; then
        return 1
    fi
    printf 'production_cvd_clamscan=pass\n' >> "$out/service-summary.txt"
}

run_direct_stdin()
{
    oracle_load edge "$edge_file"
    service_case_resource_begin_for_role clamscan stdin edge
    stdin_status=0
    stdin_report="$out/reports/edge-clamscan-stdin.jsonl"
    (
        "/usr/bin/time" -f '%e' -o "$out/logs/edge-clamscan-stdin.elapsed" \
            timeout --signal=TERM --kill-after=5 "$service_timeout_s" \
            "$build_dir/clamscan/clamscan" --database="$edge_db" \
            --max-filesize=32G --max-scansize=64G --max-matcher-work=256G \
            --max-temporary-size=64G --max-contiguous-size=32G \
            --max-htmlnormalize=32G --max-htmlnotags=32G \
            --max-scriptnormalize=32G --max-ziptypercg=32G \
            --pcre-max-filesize=32G --max-scantime="$max_scan_time_ms" \
            --tempdir="$out/tmp" --no-summary --debug \
            --report-json="$stdin_report" - < "$edge_file" \
            > "$out/logs/edge-clamscan-stdin.log" 2>&1 || exit $?
    ) &
    stdin_pid=$!
    resource_root_add "$stdin_pid"
    while kill -0 "$stdin_pid" 2>/dev/null; do
        measure_service_resources
        sleep 0.05
    done
    wait "$stdin_pid" || stdin_status=$?
    resource_root_remove "$stdin_pid"
    service_case_resource_end
    oracle_status=$stdin_status
    if ! check_oracle_output edge-clamscan-stdin \
        "$out/logs/edge-clamscan-stdin.log" "$stdin_report" yes yes cli "$edge_file"; then
        echo 'edge clamscan stdin oracle failed' >&2
        exit 1
    fi
    printf 'edge_clamscan_stdin=pass\n' >> "$out/service-summary.txt"
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
            timeout --signal=TERM --kill-after=5 "$service_timeout_s" \
                "$build_dir/clamdscan/clamdscan" --infected --no-summary \
                --stream --report-json="$queue_report" -c "$config" "$materialized_file" \
                > "$queue_log" 2>&1 || status=$?
        printf '%s\n' "$status" > "$queue_status_file"
        ) &
        queue_pids="$queue_pids $!"
        resource_root_add "$!"
        # Give the first request a chance to enter the sole worker before the
        # second streaming client is submitted. The daemon log remains the
        # acceptance oracle, so a fast fixture cannot silently satisfy this
        # gate.
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
        resource_root_remove "$queue_pid"
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
        check_oracle_output "clamd-serial-queue-$worker" \
            "$queue_log" "$queue_report" yes no service "$materialized_file"
        worker=$((worker + 1))
    done

    if ! grep -F 'INSTREAM admission pending: waiting for an available scan worker' \
        "$out/logs/clamd-$(basename "$production_db").log" >/dev/null 2>&1; then
        echo 'serial clamd stream queue did not defer staging before worker admission' >&2
        return 1
    fi
    if ! grep -F 'INSTREAM admission available: mode -> MODE_COMMAND' \
        "$out/logs/clamd-$(basename "$production_db").log" >/dev/null 2>&1; then
        echo 'serial clamd stream queue did not resume after worker admission' >&2
        return 1
    fi
    printf 'serial_worker_count=1\n' >> "$out/service-summary.txt"
    printf 'serial_queue_count=2\n' >> "$out/service-summary.txt"
    printf 'serial_stream_admission=pass\n' >> "$out/service-summary.txt"
    printf 'serial_queue=pass\n' >> "$out/service-summary.txt"
}

: > "$out/service-summary.txt"
run_direct_report()
{
    report_label=$1
    report_mode=$2
    oracle_load production "$production_file"
    case "$report_mode" in
        scan) report_case_id=SCANREPORT ;;
        contscan) report_case_id=CONTSCANREPORT ;;
        multiscan) report_case_id=MULTISCANREPORT ;;
        allmatchscan) report_case_id=ALLMATCHSCANREPORT ;;
        fildes) report_case_id=FILDESREPORT ;;
        instream) report_case_id=INSTREAMREPORT ;;
        *)
            echo "unsupported report mode for per-case resource capture: $report_mode" >&2
            return 1
            ;;
    esac
    service_case_resource_begin_for_role clamd "$report_case_id" production
    report_log="$out/logs/production_cvd_${report_label}.log"
    report_path="$out/reports/production_cvd_${report_label}.jsonl"
    report_status=0
    (
        "/usr/bin/time" -f '%e' -o "$out/logs/production_cvd_${report_label}.elapsed" \
            timeout --signal=TERM --kill-after=5 "$service_timeout_s" \
            python3 "$root/tools/largefile_clamd_report_protocol.py" \
            "$socket" "$production_file" "$oracle_manifest" production "$report_mode" \
            "$report_path" "$service_timeout_s" > "$report_log" 2>&1 || exit $?
    ) &
    report_pid=$!
    resource_root_add "$report_pid"
    while kill -0 "$report_pid" 2>/dev/null; do
        measure_service_resources
        sleep 0.05
    done
    wait "$report_pid" || report_status=$?
    resource_root_remove "$report_pid"
    service_case_resource_end
    if [ "$report_status" -ne 0 ]; then
        cat "$report_log" >&2
        return 1
    fi
    record_workload "production_cvd_${report_label}" report production "$production_file" \
        "$report_log" "$report_path" "$report_status" no
    printf 'production_cvd_clamdscan_%s=pass\n' "$report_label" >> "$out/service-summary.txt"
}

run_direct_legacy()
{
    legacy_label=$1
    legacy_mode=$2
    oracle_load edge "$edge_file"
    legacy_log="$out/logs/$legacy_label.log"
    legacy_status=0
    timeout --signal=TERM --kill-after=5 "$service_timeout_s" \
        python3 "$root/tools/largefile_clamd_legacy_protocol.py" \
        "$socket" "$edge_file" "$oracle_manifest" edge "$legacy_mode" \
        "$service_timeout_s" > "$legacy_log" 2>&1 || legacy_status=$?
    oracle_status=$legacy_status
    if ! check_oracle_output "$legacy_label" "$legacy_log" - no no legacy "$edge_file"; then
        echo "$legacy_label legacy-wire oracle failed" >&2
        return 1
    fi
    printf '%s=pass\n' "${legacy_label}_legacy_wire" >> "$out/service-summary.txt"
    # Keep the historical workflow markers while the direct-wire workload
    # names are consumed by the stricter verifier.  These aliases are status
    # compatibility only; the workload record above is the authoritative
    # binding and is explicitly typed as legacy rather than clamdscan report.
    case "$legacy_label" in
        edge_contscan) printf 'edge_clamdscan_contscan=pass\n' >> "$out/service-summary.txt" ;;
        edge_multiscan) printf 'edge_clamdscan_multiscan=pass\n' >> "$out/service-summary.txt" ;;
        edge_allmatch) printf 'edge_clamdscan_allmatchscan=pass\n' >> "$out/service-summary.txt" ;;
        edge_fildes) printf 'edge_clamdscan_fildes=pass\n' >> "$out/service-summary.txt" ;;
        edge_instream) printf 'edge_clamdscan_instream=pass\n' >> "$out/service-summary.txt" ;;
    esac
}

# A separate negative control proves that size admission rejects 32 GiB + 1
# with both AlertExceedsMax settings. Each probe creates and removes its own
# sparse descriptor fixture; this is not materialized scan qualification.
oversize_alert_off_report=$out/reports/oversize-fildesreport-alert-off.json
oversize_alert_on_report=$out/reports/oversize-fildesreport-alert-on.json
oversize_report=$out/reports/oversize-fildesreport.json
oversize_log=$out/logs/oversize-fildesreport.log
: > "$oversize_log"
python3 "$root/tools/largefile_service_oversize.py" "$socket" \
    "$oversize_alert_on_report" "$out/tmp" 60 on \
    > "$out/logs/oversize-fildesreport-alert-on.log" 2>&1
stop_service
start_service "$production_db" 1 2 no
python3 "$root/tools/largefile_service_oversize.py" "$socket" \
    "$oversize_alert_off_report" "$out/tmp" 60 off \
    > "$out/logs/oversize-fildesreport-alert-off.log" 2>&1
stop_service
start_service "$production_db" 1 2
python3 "$root/tools/largefile_service_oversize.py" --combine \
    "$oversize_report" "$oversize_alert_off_report" "$oversize_alert_on_report" \
    > "$out/logs/oversize-fildesreport-combine.log" 2>&1
record_workload oversize-fildesreport oversize - - \
    "$oversize_log" "$oversize_report" 0 no
printf 'oversize_fildesreport=pass\n' >> "$out/service-summary.txt"

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
"/usr/bin/time" -f '%e' -o "$out/logs/edge-clamscan.elapsed" \
    timeout --signal=TERM --kill-after=5 "$service_timeout_s" \
    "$build_dir/clamscan/clamscan" --database="$edge_db" \
    --max-filesize=32G --max-scansize=64G --max-matcher-work=256G \
    --max-temporary-size=64G --max-contiguous-size=32G \
    --pcre-max-filesize=32G --max-scantime="$max_scan_time_ms" \
    --no-summary --debug --report-json="$edge_report" "$edge_file" \
    > "$out/logs/edge-clamscan.log" 2>&1 || edge_status=$?
oracle_status=$edge_status
if ! check_oracle_output edge-clamscan "$out/logs/edge-clamscan.log" "$edge_report" yes yes cli "$edge_file"; then
    echo 'edge clamscan oracle failed' >&2
    exit 1
fi
run_direct_stdin
stop_service
start_service "$edge_db" 1 2
run_direct_legacy edge_contscan contscan
run_direct_legacy edge_multiscan multiscan
run_direct_legacy edge_allmatch allmatchscan
run_direct_legacy edge_fildes fildes
run_direct_legacy edge_instream instream
run_service_stdin
printf 'edge_clamdscan_stdin=pass\n' >> "$out/service-summary.txt"
# Bind the client-side mode combinations separately from the direct legacy
# wire probes above.  These are distinct ingress paths and the report-backed
# records are required by the R10 matrix.
run_service_scan edge edge-clamdscan-multiscan "$edge_file" --multiscan
run_service_scan edge edge-clamdscan-stream-multiscan "$edge_file" --stream --multiscan
run_service_scan edge edge-clamdscan-fdpass-multiscan "$edge_file" --fdpass --multiscan

# Exercise the two simultaneous clamdscan clients required by PLAN.md against
# the actual certified single-worker/two-entry profile. The first request must
# occupy the sole worker while the second remains queued; the configuration
# copied into evidence is the configuration consumed by both requests.
stop_service
start_service "$edge_db" 1 2
cp "$config" "$service_parallel_profile"
parallel_profile_max_threads=$(awk '$1 == "MaxThreads" { count++; value = $2 } END { if (count != 1) exit 1; print value }' "$service_parallel_profile") || {
    echo 'parallel-client stress profile has no unique MaxThreads entry' >&2
    exit 1
}
[ "$parallel_profile_max_threads" = 1 ] || {
    echo 'parallel-client stress profile is not single-worker' >&2
    exit 1
}
parallel_profile_max_queue=$(awk '$1 == "MaxQueue" { count++; value = $2 } END { if (count != 1) exit 1; print value }' "$service_parallel_profile") || {
    echo 'parallel-client stress profile has no unique MaxQueue entry' >&2
    exit 1
}
[ "$parallel_profile_max_queue" = 2 ] || {
    echo 'parallel-client stress profile is not the certified two-entry queue' >&2
    exit 1
}
parallel_profile_alert=$(awk '$1 == "AlertExceedsMax" { count++; value = $2 } END { if (count != 1) exit 1; print value }' "$service_parallel_profile") || {
    echo 'parallel-client stress profile has no unique AlertExceedsMax entry' >&2
    exit 1
}
[ "$parallel_profile_alert" = yes ] || {
    echo 'parallel-client stress profile does not enable AlertExceedsMax' >&2
    exit 1
}
multi_dir="$out/logs/clamd-parallel-client"
mkdir -p "$multi_dir"
multi_pids=
client=1
while [ "$client" -le 2 ]; do
        multi_log="$multi_dir/client-$client.log"
        multi_time="$multi_dir/client-$client.time"
        multi_status_file="$multi_dir/client-$client.status"
        multi_report="$out/reports/clamd-parallel-client-$client.jsonl"
        (
            status=0
            "/usr/bin/time" -f '%e %M' -o "$multi_time" \
                timeout --signal=TERM --kill-after=5 "$service_timeout_s" \
            "$build_dir/clamdscan/clamdscan" --infected --no-summary --report-json="$multi_report" -c "$config" "$edge_file" \
                > "$multi_log" 2>&1 || status=$?
        printf '%s\n' "$status" > "$multi_status_file"
    ) &
    multi_pids="$multi_pids $!"
    resource_root_add "$!"
    client=$((client + 1))
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
    resource_root_remove "$multi_pid"
done
parallel_service_log="$out/logs/clamd-$(basename "$edge_db").log"
if [ ! -r "$parallel_service_log" ]; then
    echo "clamd parallel-client log is missing: $parallel_service_log" >&2
    exit 1
fi
parallel_queue_observation_count=$(grep -Ec \
    'THRMGR: dispatch accepted: (active=1 queued=1|active=0 queued=2) max_threads=1 max_queue=2' \
    "$parallel_service_log" || true)
if [ "$parallel_queue_observation_count" -lt 1 ]; then
    echo 'clamd parallel-client run did not observe an accepted queued item in the certified one-worker profile' >&2
    exit 1
fi
client=1
while [ "$client" -le 2 ]; do
    multi_log="$multi_dir/client-$client.log"
    multi_time="$multi_dir/client-$client.time"
    multi_status_file="$multi_dir/client-$client.status"
    multi_report="$out/reports/clamd-parallel-client-$client.jsonl"
    multi_status=$(sed -n '1p' "$multi_status_file" 2>/dev/null || true)
    oracle_load edge "$edge_file"
    oracle_status=$multi_status
    if ! check_oracle_output "clamd-parallel-client-$client" "$multi_log" "$multi_report" yes no service "$edge_file"; then
        echo "clamd parallel-client request $client failed" >&2
        exit 1
    fi
    multi_elapsed=$(awk 'NF == 2 && $1 ~ /^[0-9]+([.][0-9]+)?$/ && $2 ~ /^[0-9]+$/ { print $1 }' "$multi_time")
    multi_rss=$(awk 'NF == 2 && $1 ~ /^[0-9]+([.][0-9]+)?$/ && $2 ~ /^[0-9]+$/ { print $2 }' "$multi_time")
    if [ -z "$multi_elapsed" ] || [ -z "$multi_rss" ]; then
        echo "clamd parallel-client request $client has malformed timing/RSS evidence" >&2
        exit 1
    fi
    if ! awk -v elapsed="$multi_elapsed" -v budget="$latency_budget_s" 'BEGIN { exit !(elapsed <= budget) }'; then
        echo "clamd parallel-client request $client exceeded latency budget" >&2
        exit 1
    fi
    if [ "$multi_rss" -gt "$rss_budget_kb" ]; then
        echo "clamd parallel-client RSS exceeded budget: $multi_rss > $rss_budget_kb" >&2
        exit 1
    fi
    printf 'clamd_parallel_client_%s_elapsed_s=%s\n' "$client" "$multi_elapsed" >> "$out/service-summary.txt"
    printf 'clamd_parallel_client_%s_peak_rss_kb=%s\n' "$client" "$multi_rss" >> "$out/service-summary.txt"
    client=$((client + 1))
done
printf 'clamd_parallel_client_count=2\n' >> "$out/service-summary.txt"
printf 'clamd_parallel_clients=pass\n' >> "$out/service-summary.txt"
printf 'parallel_worker_count=1\n' >> "$out/service-summary.txt"
printf 'parallel_client_count=2\n' >> "$out/service-summary.txt"
printf 'parallel_test_max_queue=2\n' >> "$out/service-summary.txt"
printf 'parallel_profile=provenance/parallel-client-clamd.conf\n' >> "$out/service-summary.txt"
printf 'parallel_queue_log=logs/clamd-%s.log\n' "$(basename "$edge_db")" >> "$out/service-summary.txt"
printf 'parallel_queue_observation_count=%s\n' "$parallel_queue_observation_count" >> "$out/service-summary.txt"
printf 'parallel_queue=pass\n' >> "$out/service-summary.txt"

# Stop the run only after the certified profile has been exercised. The
# configuration consumed by the evidence verifier and release gate is the same
# one-worker/two-queue profile captured before the two-client test.
stop_service
printf 'service_lifecycle=provenance/service-lifecycle.tsv\n' >> "$service_build_identity"
printf 'service_lifecycle_sha256=%s\n' \
    "$(sha256sum "$service_lifecycle" | awk '{ print $1 }')" >> "$service_build_identity"
printf 'service_resource_samples=provenance/service-resource-samples.tsv\n' >> "$service_build_identity"
printf 'service_resource_samples_sha256=%s\n' \
    "$(sha256sum "$service_resource_samples" | awk '{ print $1 }')" >> "$service_build_identity"
printf 'service_lifecycle=pass\n' >> "$out/service-summary.txt"

for elapsed_file in "$out"/logs/*.elapsed; do
    if ! awk -v budget="$latency_budget_s" '{ if ($1 > budget) exit 1 }' "$elapsed_file"; then
        echo "latency budget exceeded in $elapsed_file" >&2
        exit 1
    fi
done
printf 'latency_budget_s=%s\n' "$latency_budget_s" >> "$out/service-summary.txt"
printf 'latency=pass\n' >> "$out/service-summary.txt"

final_oom_sample=$(python3 "$root/tools/largefile_procfs_tree_oom.py" "$$" 2>/dev/null || true)
final_oom_events=$(printf '%s\n' "$final_oom_sample" |
    awk -F '\t' 'NF == 4 && $1 ~ /^[0-9]+$/ { print $1; exit }')
final_oom_kill_events=$(printf '%s\n' "$final_oom_sample" |
    awk -F '\t' 'NF == 4 && $2 ~ /^[0-9]+$/ { print $2; exit }')
final_oom_cgroup_count=$(printf '%s\n' "$final_oom_sample" |
    awk -F '\t' 'NF == 4 && $3 ~ /^[0-9]+$/ { print $3; exit }')
final_oom_cgroup_digest=$(printf '%s\n' "$final_oom_sample" |
    awk -F '\t' 'NF == 4 && $4 ~ /^[0-9a-fA-F]{64}$/ { print $4; exit }')
if [ -z "$final_oom_events" ] || [ -z "$final_oom_kill_events" ] ||
    [ -z "$final_oom_cgroup_count" ] || [ -z "$final_oom_cgroup_digest" ] ||
    [ "$final_oom_cgroup_count" -ne "$service_oom_cgroup_count" ] ||
    [ "$final_oom_cgroup_digest" != "$service_oom_cgroup_digest" ] ||
    [ "$final_oom_events" -ne "$service_oom_baseline" ] ||
    [ "$final_oom_kill_events" -ne "$service_oom_kill_baseline" ] ||
    [ "$service_peak_oom_events" -ne "$service_oom_baseline" ] ||
    [ "$service_peak_oom_kill_events" -ne "$service_oom_kill_baseline" ]; then
    echo 'service cgroup-v2 OOM counters changed or could not be verified' >&2
    exit 1
fi
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
if [ "$service_peak_swap_kb" -ne 0 ]; then
    echo "service process tree used swap: ${service_peak_swap_kb} KiB" >&2
    exit 1
fi
printf 'service_rss_peak_kb=%s\n' "$service_peak_rss_kb" >> "$out/service-summary.txt"
printf 'service_rss_peak_process_count=%s\n' "$service_peak_rss_process_count" >> "$out/service-summary.txt"
printf 'service_rss_samples=%s\n' "$service_rss_samples" >> "$out/service-summary.txt"
printf 'service_rss_measurement=%s\n' "$service_rss_measurement" >> "$out/service-summary.txt"
printf 'service_rss_process_tree=pass\n' >> "$out/service-summary.txt"
printf 'service_rss_sampler=tools/largefile_procfs_tree_rss.sh\n' >> "$out/service-summary.txt"
printf 'service_memory_metrics=%s\n' "$service_memory_metrics" >> "$out/service-summary.txt"
printf 'service_oom_measurement=%s\n' "$service_oom_measurement" >> "$out/service-summary.txt"
printf 'service_oom_baseline=%s\n' "$service_oom_baseline" >> "$out/service-summary.txt"
printf 'service_oom_kill_baseline=%s\n' "$service_oom_kill_baseline" >> "$out/service-summary.txt"
printf 'service_oom_peak=%s\n' "$service_peak_oom_events" >> "$out/service-summary.txt"
printf 'service_oom_kill_peak=%s\n' "$service_peak_oom_kill_events" >> "$out/service-summary.txt"
printf 'service_oom_samples=%s\n' "$service_oom_samples" >> "$out/service-summary.txt"
printf 'service_oom_cgroup_count=%s\n' "$service_oom_cgroup_count" >> "$out/service-summary.txt"
printf 'service_oom_cgroup_digest=%s\n' "$service_oom_cgroup_digest" >> "$out/service-summary.txt"
printf 'service_oom_events=pass\n' >> "$out/service-summary.txt"
printf 'service_oom_kills=pass\n' >> "$out/service-summary.txt"
printf 'service_pss_peak_kb=%s\n' "$service_peak_pss_kb" >> "$out/service-summary.txt"
printf 'service_vas_peak_kb=%s\n' "$service_peak_vas_kb" >> "$out/service-summary.txt"
printf 'service_swap_peak_kb=%s\n' "$service_peak_swap_kb" >> "$out/service-summary.txt"
printf 'service_swap=pass\n' >> "$out/service-summary.txt"
printf 'service_minor_faults_peak=%s\n' "$service_peak_minor_faults" >> "$out/service-summary.txt"
printf 'service_major_faults_peak=%s\n' "$service_peak_major_faults" >> "$out/service-summary.txt"
printf 'service_read_bytes_peak=%s\n' "$service_peak_read_bytes" >> "$out/service-summary.txt"
printf 'service_write_bytes_peak=%s\n' "$service_peak_write_bytes" >> "$out/service-summary.txt"
printf 'service_cancelled_write_bytes_peak=%s\n' "$service_peak_cancelled_write_bytes" >> "$out/service-summary.txt"
printf 'service_resource_samples=provenance/service-resource-samples.tsv\n' >> "$out/service-summary.txt"
printf 'service_temp_samples=%s\n' "$service_temp_samples" >> "$out/service-summary.txt"
printf 'rss_budget_kb=%s\n' "$rss_budget_kb" >> "$out/service-summary.txt"
printf 'pcre_rss_budget_kb=%s\n' "$pcre_rss_budget_kb" >> "$out/service-summary.txt"
printf 'post_pcre_rss_budget_kb=%s\n' "$post_pcre_rss_budget_kb" >> "$out/service-summary.txt"
printf 'rss_budget_contract=overall-stricter-than-pcre-phase\n' >> "$out/service-summary.txt"

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
        MILTER_WIRE_TIMEOUT_S="$service_timeout_s" \
        MILTER_MAX_SCAN_TIME_MS="$max_scan_time_ms" \
        MILTER_EXACT_EDGE=1 \
        MILTER_EXTRA_DATABASE="$edge_db" \
        MILTER_TEST_ROOT="$out/tmp" \
        "/usr/bin/time" -f '%e %M' -o "$milter_time_file" \
        timeout --signal=TERM --kill-after=10 "$service_timeout_s" \
        python3 "$root/unit_tests/milter_protocol_test.py" > "$out/logs/milter-exact-edge.log" 2>&1 || exit $?
) &
milter_pid=$!
resource_root_add "$milter_pid"
while kill -0 "$milter_pid" 2>/dev/null; do
    measure_service_resources
    sleep 0.05
done
wait "$milter_pid" || milter_status=$?
resource_root_remove "$milter_pid"
if [ "$milter_status" -ne 0 ]; then
    echo 'milter exact-edge integration gate failed' >&2
    exit 1
fi
record_workload milter-exact-edge milter - - "$out/logs/milter-exact-edge.log" - \
    "$milter_status" no
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
printf 'max_scan_time_ms=%s\n' "$max_scan_time_ms" >> "$service_build_identity"
printf 'service_timeout_s=%s\n' "$service_timeout_s" >> "$service_build_identity"
printf 'service_memory_metrics=%s\n' "$service_memory_metrics" >> "$service_build_identity"
printf 'service_oom_measurement=%s\n' "$service_oom_measurement" >> "$service_build_identity"
printf 'service_oom_baseline=%s\n' "$service_oom_baseline" >> "$service_build_identity"
printf 'service_oom_kill_baseline=%s\n' "$service_oom_kill_baseline" >> "$service_build_identity"
printf 'service_oom_cgroup_count=%s\n' "$service_oom_cgroup_count" >> "$service_build_identity"
printf 'service_oom_cgroup_digest=%s\n' "$service_oom_cgroup_digest" >> "$service_build_identity"
printf 'max_scan_time_ms=%s\n' "$max_scan_time_ms" >> "$out/service-summary.txt"
printf 'service_timeout_s=%s\n' "$service_timeout_s" >> "$out/service-summary.txt"
record_service_binary_hashes "$service_binary_hashes_after"
python3 "$root/tools/largefile_service_workload_check.py" --check-inputs \
    "$service_oracle_copy" "$production_file" "$materialized_file" \
    "$expansion_file" "$edge_file" > "$out/provenance/service-inputs-after.json"
if ! cmp -s "$out/provenance/service-inputs-before.json" "$out/provenance/service-inputs-after.json"; then
    echo 'service input allocation/content evidence changed during qualification' >&2
    exit 1
fi
if ! cmp -s "$service_binary_hashes_before" "$service_binary_hashes_after"; then
    echo 'service executable changed during qualification' >&2
    exit 1
fi
record_service_interpreter_records "$service_interpreter_records_after"
if ! cmp -s "$service_interpreter_records_before" "$service_interpreter_records_after"; then
    echo 'service ELF interpreter set changed during qualification' >&2
    exit 1
fi
record_service_dependency_hashes "$service_dependency_hashes_after" after
if ! cmp -s "$service_dependency_hashes" "$service_dependency_hashes_after"; then
    echo 'service runtime dependency set changed during qualification' >&2
    exit 1
fi
printf 'service_runtime_dependency_hashes_after=provenance/service-runtime-dependency-hashes-after.txt\n' >> "$service_build_identity"
printf 'service_runtime_dependency_hashes_after_sha256=%s\n' \
    "$(sha256sum "$service_dependency_hashes_after" | awk '{ print $1 }')" >> "$service_build_identity"
record_service_runtime_component_hashes "$service_runtime_component_hashes_after"
if ! cmp -s "$service_runtime_component_hashes_before" "$service_runtime_component_hashes_after"; then
    echo 'service copied runtime components changed during qualification' >&2
    exit 1
fi
printf 'service_runtime_component_hashes_after=provenance/service-runtime-component-hashes-after.txt\n' >> "$service_build_identity"
printf 'service_runtime_component_hashes_after_sha256=%s\n' \
    "$(sha256sum "$service_runtime_component_hashes_after" | awk '{ print $1 }')" >> "$service_build_identity"
printf 'service_interpreter_records_after=provenance/service-interpreter-records-after.txt\n' >> "$service_build_identity"
printf 'service_interpreter_records_after_sha256=%s\n' \
    "$(sha256sum "$service_interpreter_records_after" | awk '{ print $1 }')" >> "$service_build_identity"
printf 'service_runtime_dependencies_unchanged=pass\n' >> "$out/service-summary.txt"
printf 'service_runtime_loader_binding=pass\n' >> "$out/service-summary.txt"
printf 'service_runtime_components_unchanged=pass\n' >> "$out/service-summary.txt"
printf 'service_interpreters_unchanged=pass\n' >> "$out/service-summary.txt"
printf 'service_build_identity=pass\n' >> "$out/service-summary.txt"
printf 'service_qualification=pass\n' >> "$out/service-summary.txt"
finalize_service_case_resources
printf 'acceptance_resource_sidecar=provenance/acceptance-case-resources.tsv\n' >> "$out/service-summary.txt"
# Convert only explicitly mapped, already-validated service workloads into
# capability-bound R04 records. Unmapped cases remain absent and therefore
# continue to block authoritative release readiness.
python3 "$root/tools/largefile_acceptance_case_producer.py" "$out" \
    --manifest "$root/docs/largefile-capabilities.tsv" \
    --map "$root/docs/largefile-capability-case-map.tsv" \
    --require-resource-sidecar
printf 'qualification_oracle=provenance/qualification-oracle.tsv\n' >> "$out/oracle-binding.txt"
printf 'qualification_oracle_sha256=%s\n' \
    "$(sha256sum "$service_oracle_copy" | awk '{ print $1 }')" >> "$out/oracle-binding.txt"
printf 'workload_results=provenance/service-workload-results.tsv\n' >> "$out/oracle-binding.txt"
printf 'workload_results_sha256=%s\n' \
    "$(sha256sum "$service_workload_results" | awk '{ print $1 }')" >> "$out/oracle-binding.txt"
(
    cd "$out"
    find . -type f ! -name SHA256SUMS -print |
        LC_ALL=C sort |
        while IFS= read -r evidence_file; do
            sha256sum "$evidence_file"
        done
) > "$out/SHA256SUMS"
echo "service qualification passed; evidence is in $out"
