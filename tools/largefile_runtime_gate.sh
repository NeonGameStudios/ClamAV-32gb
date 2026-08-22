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
#   CLAMAV_MAX_SCAN_TIME_MS    uint32 per-file deadline in milliseconds (default 14400000)
#   CLAMAV_SANITIZER_MAX_SCAN_TIME_MS
#                              sanitizer-only deadline; defaults to the release deadline
#   CLAMAV_SANITIZER_TOOLCHAIN  sanitizer Rust toolchain (must be nightly)
#   CLAMAV_SANITIZER_RUSTFLAGS  sanitizer Rust flags (must include address instrumentation)
#   CLAMAV_SOURCE_REPOSITORY   immutable source repository identifier for non-GitHub runs
#   CLAMAV_CVD_CERTS_DIR       CA directory for a build-tree scanner

set -eu

verify_native_sanitizer_compile_graph()
{
    command -v python3 >/dev/null 2>&1 || return 1
    python3 - "$1" <<'PY'
import json
import shlex
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        entries = json.load(stream)
except (OSError, ValueError):
    raise SystemExit(1)

if not isinstance(entries, list) or not entries:
    raise SystemExit(1)
for entry in entries:
    if not isinstance(entry, dict) or not isinstance(entry.get("command"), str):
        raise SystemExit(1)
    try:
        tokens = shlex.split(entry["command"])
    except ValueError:
        raise SystemExit(1)
    sanitizers = []
    for token in tokens:
        if token.startswith("-fsanitize="):
            sanitizers.extend(token.split("=", 1)[1].split(","))
    if "address" not in sanitizers or "undefined" not in sanitizers:
        raise SystemExit(1)
PY
}

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
max_scan_time_ms=${CLAMAV_MAX_SCAN_TIME_MS:-14400000}
sanitizer_max_scan_time_ms=${CLAMAV_SANITIZER_MAX_SCAN_TIME_MS:-$max_scan_time_ms}
sanitizer_rust_suite=${CLAMAV_SANITIZER_RUST_SUITE:-not-run}
sanitizer_toolchain=${CLAMAV_SANITIZER_TOOLCHAIN:-not-set}
sanitizer_rustflags=${CLAMAV_SANITIZER_RUSTFLAGS:-not-set}
cvd_certs_dir=${CLAMAV_CVD_CERTS_DIR:-${CVD_CERTS_DIR:-}}
fixed_rss_budget_kb=33554432
fixed_min_available_kb=50331648
fixed_max_temp_bytes=68719476736

case "$rss_budget_kb" in
    ''|*[!0-9]*)
        echo "RSS_BUDGET_KB must be a non-negative integer" >&2
        exit 2
        ;;
esac
if [ "$rss_budget_kb" != "$fixed_rss_budget_kb" ]; then
    echo "release acceptance requires the fixed RSS budget of $fixed_rss_budget_kb KiB" >&2
    exit 2
fi
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
if [ "$min_available_kb" != "$fixed_min_available_kb" ]; then
    echo "release acceptance requires the fixed memory-headroom budget of $fixed_min_available_kb KiB" >&2
    exit 2
fi
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
case "$sanitizer_max_scan_time_ms" in
    ''|*[!0-9]*|0*)
        echo "CLAMAV_SANITIZER_MAX_SCAN_TIME_MS must be a canonical integer from 1 through 4294967295" >&2
        exit 2
        ;;
esac
if [ "${#sanitizer_max_scan_time_ms}" -gt 10 ] ||
    { [ "${#sanitizer_max_scan_time_ms}" -eq 10 ] && [ "$sanitizer_max_scan_time_ms" -gt 4294967295 ]; }; then
    echo "CLAMAV_SANITIZER_MAX_SCAN_TIME_MS must be a canonical integer from 1 through 4294967295" >&2
    exit 2
fi
if [ "$sanitizer_max_scan_time_ms" -lt "$max_scan_time_ms" ]; then
    echo "CLAMAV_SANITIZER_MAX_SCAN_TIME_MS must be at least CLAMAV_MAX_SCAN_TIME_MS" >&2
    exit 2
fi
case "$sanitizer_rust_suite" in
    pass|not-run) ;;
    *)
        echo "CLAMAV_SANITIZER_RUST_SUITE must be pass or not-run" >&2
        exit 2
        ;;
esac
if [ "$concurrency_file" != 32g-edge.bin ]; then
    echo "release concurrency evidence must use 32g-edge.bin (requested $concurrency_file)" >&2
    exit 2
fi
if [ "$concurrency_levels" != "1 2 4" ]; then
    echo "release acceptance evidence requires canonical concurrency levels: 1 2 4" >&2
    exit 2
fi
if [ -z "${CLAMAV_MAX_TEMP_BYTES+x}" ]; then
    echo "CLAMAV_MAX_TEMP_BYTES is required for release acceptance evidence" >&2
    exit 2
fi
case "$CLAMAV_MAX_TEMP_BYTES" in
    ''|*[!0-9]*)
        echo "CLAMAV_MAX_TEMP_BYTES must be a non-negative integer" >&2
        exit 2
        ;;
esac
if [ "$CLAMAV_MAX_TEMP_BYTES" != "$fixed_max_temp_bytes" ]; then
    echo "release acceptance requires the fixed temporary-space budget of $fixed_max_temp_bytes bytes" >&2
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
if [ -n "$sanitizer_clamscan" ]; then
    if [ "$sanitizer_toolchain" != nightly ]; then
        echo "sanitizer evidence requires the nightly Rust toolchain (got $sanitizer_toolchain)" >&2
        exit 2
    fi
    case " $sanitizer_rustflags " in
        *" -Zsanitizer=address "*) ;;
        *)
            echo 'sanitizer evidence requires Rust address instrumentation via -Zsanitizer=address' >&2
            exit 2
            ;;
    esac
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
    [ ! -x "$root/tools/largefile_source_manifest.sh" ]; then
    echo "runtime-gate requires file, sha256sum, and the source-manifest control" >&2
    exit 2
fi

artifacts=$out/artifacts
provenance=$out/provenance
mkdir -p "$artifacts" "$provenance"
"$root/tools/largefile_source_manifest.sh" "$root" "$provenance/source-manifest.txt"
source_manifest_sha256=$(sha256sum "$provenance/source-manifest.txt" | awk '{ print $1 }')

git_checkout=no
if command -v git >/dev/null 2>&1 &&
    [ "$(git -C "$root" rev-parse --is-inside-work-tree 2>/dev/null || true)" = true ] &&
    [ "$(git -C "$root" rev-parse --show-toplevel 2>/dev/null || true)" = "$root" ]; then
    git_checkout=yes
fi

if [ "$git_checkout" = yes ]; then
    source_commit=$(git -C "$root" rev-parse --verify HEAD)
    if [ -n "$(git -C "$root" status --porcelain --untracked-files=normal)" ]; then
        echo "runtime-gate refuses a dirty source tree" >&2
        exit 2
    fi
source_tree=$(git -C "$root" rev-parse --verify "$source_commit^{tree}")
    source_repository=${CLAMAV_SOURCE_REPOSITORY:-${GITHUB_REPOSITORY:-}}
    if [ -z "$source_repository" ]; then
        source_repository=$(git -C "$root" remote get-url origin 2>/dev/null || true)
    fi
    source_tree_status=clean
    source_revision_type=git-commit
else
    # The source manifest is the immutable revision for Git-less snapshots.
    source_commit=$source_manifest_sha256
    source_tree=$source_manifest_sha256
    source_repository=${CLAMAV_SOURCE_REPOSITORY:-local-source-snapshot}
    source_tree_status=clean
    source_revision_type=content-manifest
fi
case "$source_repository" in
    ''|*[[:space:]]*)
        echo "runtime-gate requires a non-empty source repository identity" >&2
        exit 2
        ;;
esac
if [ "$git_checkout" = yes ] && [ -n "${GITHUB_SHA:-}" ] && [ "$GITHUB_SHA" != "$source_commit" ]; then
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
cmake_source=$(sed -n 's#^CMAKE_HOME_DIRECTORY:INTERNAL=##p' "$cmake_cache")
if [ "$cmake_source" != "$root" ]; then
    echo "scanner build was configured from $cmake_source, not the audited source root $root" >&2
    exit 2
fi
cmake_source_commit=$(sed -n 's/^CLAMAV_SOURCE_COMMIT:INTERNAL=//p' "$cmake_cache")
if [ "$cmake_source_commit" != "$source_commit" ]; then
    echo "scanner build was configured from source commit $cmake_source_commit, not $source_commit" >&2
    exit 2
fi
cmake_source_manifest_sha256=$(sed -n 's/^CLAMAV_SOURCE_MANIFEST_SHA256:INTERNAL=//p' "$cmake_cache")
if [ "$cmake_source_manifest_sha256" != "$source_manifest_sha256" ]; then
    echo "scanner build was configured from source manifest $cmake_source_manifest_sha256, not $source_manifest_sha256" >&2
    exit 2
fi
build_source_manifest=$build_dir/source-manifest.txt
if [ ! -s "$build_source_manifest" ] || ! cmp -s "$build_source_manifest" "$provenance/source-manifest.txt"; then
    echo "scanner build source manifest does not match the immutable source revision" >&2
    exit 2
fi
compile_commands=$build_dir/compile_commands.json
if [ ! -s "$compile_commands" ]; then
    echo "runtime-gate requires compile_commands.json for native build-graph evidence: $compile_commands" >&2
    exit 2
fi
san_compile_commands=
san_cmake_cache=
san_build_source_manifest=
if [ -n "$sanitizer_clamscan" ]; then
    san_scanner_dir=$(CDPATH= cd -- "$(dirname "$sanitizer_clamscan")" && pwd)
    san_build_dir=$(CDPATH= cd -- "$san_scanner_dir/.." && pwd)
    san_cmake_cache=$san_build_dir/CMakeCache.txt
    san_compile_commands=$san_build_dir/compile_commands.json
    san_build_source_manifest=$san_build_dir/source-manifest.txt
    if [ ! -s "$san_cmake_cache" ] || [ ! -s "$san_compile_commands" ]; then
        echo "runtime-gate requires sanitizer CMakeCache.txt and compile_commands.json: $san_build_dir" >&2
        exit 2
    fi
    san_cmake_source=$(sed -n 's#^CMAKE_HOME_DIRECTORY:INTERNAL=##p' "$san_cmake_cache")
    if [ "$san_cmake_source" != "$root" ]; then
        echo "sanitizer build was configured from $san_cmake_source, not the audited source root $root" >&2
        exit 2
    fi
    san_cmake_source_commit=$(sed -n 's/^CLAMAV_SOURCE_COMMIT:INTERNAL=//p' "$san_cmake_cache")
    if [ "$san_cmake_source_commit" != "$source_commit" ]; then
        echo "sanitizer build was configured from source commit $san_cmake_source_commit, not $source_commit" >&2
        exit 2
    fi
    san_cmake_source_manifest_sha256=$(sed -n 's/^CLAMAV_SOURCE_MANIFEST_SHA256:INTERNAL=//p' "$san_cmake_cache")
    if [ "$san_cmake_source_manifest_sha256" != "$source_manifest_sha256" ]; then
        echo "sanitizer build was configured from source manifest $san_cmake_source_manifest_sha256, not $source_manifest_sha256" >&2
        exit 2
    fi
    if [ ! -s "$san_build_source_manifest" ] || ! cmp -s "$san_build_source_manifest" "$provenance/source-manifest.txt"; then
        echo "sanitizer build source manifest does not match the immutable source revision" >&2
        exit 2
    fi
fi

cp "$clamscan" "$artifacts/clamscan"
cp "$cmake_cache" "$provenance/CMakeCache.txt"
cp "$compile_commands" "$provenance/compile_commands.json"
cp "$build_source_manifest" "$provenance/build-source-manifest.txt"
if [ -n "$sanitizer_clamscan" ]; then
    cp "$san_cmake_cache" "$provenance/CMakeCache-sanitizer.txt"
    cp "$san_compile_commands" "$provenance/compile_commands-sanitizer.json"
    cp "$san_build_source_manifest" "$provenance/build-source-manifest-sanitizer.txt"
fi
cp "$root/Cargo.lock" "$provenance/Cargo.lock"

# Rust and optional UnRAR are not reliably visible in the clamscan ldd graph:
# Rust is normally linked through the libclamav target and UnRAR may be
# loaded through its private interface at runtime. Preserve the exact build
# outputs as evidence instead of treating ldd as a complete component list.
release_rust_library=$(find "$build_dir" -type f -name 'libclamav_rust.a' -print |
    LC_ALL=C sort | head -n 1)
if [ -z "$release_rust_library" ] || [ ! -s "$release_rust_library" ]; then
    echo 'release Rust static library is missing from the build graph' >&2
    exit 2
fi
cp "$release_rust_library" "$artifacts/clamav_rust-release.a"
release_rust_library_sha256=$(sha256sum "$artifacts/clamav_rust-release.a" | awk '{ print $1 }')

enable_unrar=$(sed -n 's/^ENABLE_UNRAR:BOOL=//p' "$cmake_cache")
case "$enable_unrar" in
    ON|OFF) ;;
    *)
        echo 'runtime-gate requires an explicit ENABLE_UNRAR CMake setting' >&2
        exit 2
        ;;
esac
unrar_library_path=none
unrar_library_sha256=none
unrar_backend_path=none
unrar_backend_sha256=none
unrar_component_dir=
if [ "$enable_unrar" = ON ]; then
    unrar_library=$(find "$build_dir" -type f \( \
        -name 'libclamunrar_iface.so' -o -name 'libclamunrar_iface.so.*' \
        -o -name 'libclamunrar_iface_static.a' -o -name 'libclamunrar_iface.a' \
        \) -print | LC_ALL=C sort | head -n 1)
    if [ -z "$unrar_library" ] || [ ! -s "$unrar_library" ]; then
        echo 'ENABLE_UNRAR is ON but the UnRAR interface artifact is missing' >&2
        exit 2
    fi
    unrar_component_dir=$artifacts/optional-components
    mkdir -p "$unrar_component_dir"
    unrar_basename=$(basename "$unrar_library")
    cp -L "$unrar_library" "$unrar_component_dir/$unrar_basename"
    unrar_library_path="artifacts/optional-components/$unrar_basename"
    unrar_library_sha256=$(sha256sum "$out/$unrar_library_path" | awk '{ print $1 }')
    unrar_backend=$(find "$build_dir" -type f \( \
        -name 'libclamunrar.so' -o -name 'libclamunrar.so.*' \
        -o -name 'libclamunrar_static.a' -o -name 'libclamunrar.a' \
        \) -print | LC_ALL=C sort | head -n 1)
    case "$unrar_basename" in
        *.a) ;;
        *)
            if [ -z "$unrar_backend" ] || [ ! -s "$unrar_backend" ]; then
                echo 'shared UnRAR interface is missing its backend artifact' >&2
                exit 2
            fi
            ;;
    esac
    if [ -n "$unrar_backend" ] && [ -s "$unrar_backend" ]; then
        unrar_backend_basename=$(basename "$unrar_backend")
        cp -L "$unrar_backend" "$unrar_component_dir/$unrar_backend_basename"
        unrar_backend_path="artifacts/optional-components/$unrar_backend_basename"
        unrar_backend_sha256=$(sha256sum "$out/$unrar_backend_path" | awk '{ print $1 }')
    fi
fi

if [ "$git_checkout" = yes ]; then
    git -C "$root" ls-tree -r --full-tree "$source_commit" > "$provenance/repository-tree.txt"
    git -C "$root" ls-files --stage > "$provenance/repository-index.txt"
else
    cp "$provenance/source-manifest.txt" "$provenance/repository-tree.txt"
    cp "$provenance/source-manifest.txt" "$provenance/repository-index.txt"
fi
tracked_file_count=$(wc -l < "$provenance/source-manifest.txt" | tr -d '[:space:]')
for provenance_file in \
    largefile_runtime_gate.sh \
    largefile_runtime_evidence_check.sh \
    largefile_host_preflight.sh \
    largefile_boundary_corpus.sh \
    largefile_poc.sh \
    largefile_source_manifest.sh; do
    cp "$root/tools/$provenance_file" "$provenance/$provenance_file"
done
if [ -n "$sanitizer_clamscan" ]; then
    cp "$sanitizer_clamscan" "$artifacts/clamscan-sanitizer"
fi

runtime_clamscan=$artifacts/clamscan
runtime_sanitizer_clamscan=$artifacts/clamscan-sanitizer
runtime_library_path="$runtime_component_dir"
if [ -n "$unrar_component_dir" ]; then
    runtime_library_path="$runtime_library_path:$unrar_component_dir"
fi
runtime_library_path="$runtime_library_path:$scanner_dir:$build_dir:$build_dir/libclamav:$build_dir/libclamav_rust:$build_dir/libclammspack:$build_dir/libclamunrar_iface"
if [ -n "${LD_LIBRARY_PATH:-}" ]; then
    runtime_library_path="$runtime_library_path:$LD_LIBRARY_PATH"
fi
export LD_LIBRARY_PATH=$runtime_library_path

ldd "$runtime_clamscan" > "$provenance/ldd-clamscan.txt" 2>&1
if grep -F 'not found' "$provenance/ldd-clamscan.txt" >/dev/null 2>&1; then
    echo "release scanner has unresolved runtime dependencies" >&2
    exit 2
fi
awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^\//) print $i }' \
    "$provenance/ldd-clamscan.txt" | LC_ALL=C sort -u > "$provenance/runtime-dependencies.txt"
runtime_component_dir=$artifacts/runtime-components
mkdir -p "$runtime_component_dir"
: > "$provenance/runtime-dependency-artifacts.txt"
: > "$provenance/runtime-dependency-hashes.txt"
while IFS= read -r dependency; do
    [ -f "$dependency" ] || {
        echo "runtime dependency is not a regular file: $dependency" >&2
        exit 2
    }
    dependency_name=$(basename "$dependency")
    if [ -e "$runtime_component_dir/$dependency_name" ]; then
        if ! cmp -s "$dependency" "$runtime_component_dir/$dependency_name"; then
            echo "runtime dependencies collide on basename: $dependency_name" >&2
            exit 2
        fi
    else
        cp -L "$dependency" "$runtime_component_dir/$dependency_name"
    fi
    dependency_artifact="artifacts/runtime-components/$dependency_name"
    printf '%s -> %s\n' "$dependency" "$dependency_artifact" >> "$provenance/runtime-dependency-artifacts.txt"
    (cd "$out" && sha256sum "$dependency_artifact") >> "$provenance/runtime-dependency-hashes.txt"
done < "$provenance/runtime-dependencies.txt"

# Resolve the scanner again with the copied component directory first and
# record the paths the dynamic loader would actually select.  The earlier ldd
# capture intentionally records the build-tree dependency set; this second
# capture is the binding check that prevents a later workload from silently
# using a stale build-tree library with the same basename.
runtime_loader_path="$runtime_component_dir:$scanner_dir:$build_dir:$build_dir/libclamav:$build_dir/libclamav_rust:$build_dir/libclammspack:$build_dir/libclamunrar_iface"
LD_LIBRARY_PATH="$runtime_loader_path" ldd "$runtime_clamscan" > "$provenance/loaded-dependencies.txt" 2>&1
if grep -F 'not found' "$provenance/loaded-dependencies.txt" >/dev/null 2>&1; then
    echo "copied release dependencies do not resolve: $provenance/loaded-dependencies.txt" >&2
    exit 2
fi
while IFS= read -r dependency; do
    dependency_name=${dependency##*/}
    if ! grep -F "$runtime_component_dir/$dependency_name" "$provenance/loaded-dependencies.txt" >/dev/null 2>&1; then
        echo "loader did not select copied release dependency: $dependency_name" >&2
        exit 2
    fi
done < "$provenance/runtime-dependencies.txt"

if [ -n "$sanitizer_clamscan" ]; then
    sanitizer_unrar_component_dir=
    ldd "$runtime_sanitizer_clamscan" > "$provenance/ldd-clamscan-sanitizer.txt" 2>&1
    if grep -F 'not found' "$provenance/ldd-clamscan-sanitizer.txt" >/dev/null 2>&1; then
        echo "sanitizer scanner has unresolved runtime dependencies" >&2
        exit 2
    fi
    awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^\//) print $i }' \
        "$provenance/ldd-clamscan-sanitizer.txt" | LC_ALL=C sort -u > "$provenance/runtime-dependencies-sanitizer.txt"
    sanitizer_component_dir=$artifacts/runtime-components-sanitizer
    mkdir -p "$sanitizer_component_dir"
    : > "$provenance/runtime-dependency-artifacts-sanitizer.txt"
    : > "$provenance/runtime-dependency-hashes-sanitizer.txt"
    while IFS= read -r dependency; do
        [ -f "$dependency" ] || {
            echo "sanitizer runtime dependency is not a regular file: $dependency" >&2
            exit 2
        }
        dependency_name=$(basename "$dependency")
        if [ -e "$sanitizer_component_dir/$dependency_name" ]; then
            if ! cmp -s "$dependency" "$sanitizer_component_dir/$dependency_name"; then
                echo "sanitizer runtime dependencies collide on basename: $dependency_name" >&2
                exit 2
            fi
        else
            cp -L "$dependency" "$sanitizer_component_dir/$dependency_name"
        fi
        dependency_artifact="artifacts/runtime-components-sanitizer/$dependency_name"
        printf '%s -> %s\n' "$dependency" "$dependency_artifact" >> "$provenance/runtime-dependency-artifacts-sanitizer.txt"
        (cd "$out" && sha256sum "$dependency_artifact") >> "$provenance/runtime-dependency-hashes-sanitizer.txt"
    done < "$provenance/runtime-dependencies-sanitizer.txt"
    sanitizer_loader_path="$sanitizer_component_dir"
    if [ -n "$sanitizer_unrar_component_dir" ]; then
        sanitizer_loader_path="$sanitizer_loader_path:$sanitizer_unrar_component_dir"
    fi
    sanitizer_loader_path="$sanitizer_loader_path:$scanner_dir:$build_dir:$build_dir/libclamav:$build_dir/libclamav_rust:$build_dir/libclammspack:$build_dir/libclamunrar_iface"
    LD_LIBRARY_PATH="$sanitizer_loader_path" ldd "$runtime_sanitizer_clamscan" > "$provenance/loaded-dependencies-sanitizer.txt" 2>&1
    if grep -F 'not found' "$provenance/loaded-dependencies-sanitizer.txt" >/dev/null 2>&1; then
        echo "copied sanitizer dependencies do not resolve: $provenance/loaded-dependencies-sanitizer.txt" >&2
        exit 2
    fi
    while IFS= read -r dependency; do
        dependency_name=${dependency##*/}
        if ! grep -F "$sanitizer_component_dir/$dependency_name" "$provenance/loaded-dependencies-sanitizer.txt" >/dev/null 2>&1; then
            echo "loader did not select copied sanitizer dependency: $dependency_name" >&2
            exit 2
        fi
    done < "$provenance/runtime-dependencies-sanitizer.txt"
    if command -v readelf >/dev/null 2>&1; then
        readelf -Ws "$runtime_sanitizer_clamscan" > "$provenance/sanitizer-symbols.txt" 2>&1
        for dependency in "$sanitizer_component_dir"/*; do
            readelf -Ws "$dependency" >> "$provenance/sanitizer-symbols.txt" 2>&1 || true
        done
    else
        echo 'readelf is required to prove sanitizer instrumentation' >&2
        exit 2
    fi
    if ! grep -E '__asan|__ubsan|libasan|libubsan' \
        "$provenance/sanitizer-symbols.txt" "$provenance/ldd-clamscan-sanitizer.txt" >/dev/null 2>&1; then
        echo 'sanitizer scanner has no ASan/UBSan instrumentation evidence' >&2
        exit 2
    fi
    if ! verify_native_sanitizer_compile_graph "$provenance/compile_commands-sanitizer.json"; then
        echo 'sanitizer compile graph contains an uninstrumented native compile command' >&2
        exit 2
    fi
    sanitizer_rust_library=$(find "$san_build_dir" -type f -name 'libclamav_rust.a' -print |
        LC_ALL=C sort | head -n 1)
    if [ -z "$sanitizer_rust_library" ] || [ ! -s "$sanitizer_rust_library" ]; then
        echo 'sanitizer Rust static library is missing from the build graph' >&2
        exit 2
    fi
    cp "$sanitizer_rust_library" "$artifacts/clamav_rust-sanitizer.a"
    sanitizer_rust_library_sha256=$(sha256sum "$artifacts/clamav_rust-sanitizer.a" | awk '{ print $1 }')
    if ! nm -u "$sanitizer_rust_library" > "$provenance/rust-sanitizer-symbols.txt" 2>&1 ||
        ! grep -E '__asan' "$provenance/rust-sanitizer-symbols.txt" >/dev/null 2>&1; then
        echo 'sanitizer Rust archive does not prove address instrumentation' >&2
        exit 2
    fi
    sanitizer_enable_unrar=$(sed -n 's/^ENABLE_UNRAR:BOOL=//p' "$san_cmake_cache")
    if [ "$sanitizer_enable_unrar" != "$enable_unrar" ]; then
        echo 'release and sanitizer builds disagree on ENABLE_UNRAR' >&2
        exit 2
    fi
    sanitizer_unrar_library_path=none
    sanitizer_unrar_library_sha256=none
    sanitizer_unrar_backend_path=none
    sanitizer_unrar_backend_sha256=none
    sanitizer_unrar_component_dir=
    if [ "$sanitizer_enable_unrar" = ON ]; then
        sanitizer_unrar_library=$(find "$san_build_dir" -type f \( \
            -name 'libclamunrar_iface.so' -o -name 'libclamunrar_iface.so.*' \
            -o -name 'libclamunrar_iface_static.a' -o -name 'libclamunrar_iface.a' \
            \) -print | LC_ALL=C sort | head -n 1)
        if [ -z "$sanitizer_unrar_library" ] || [ ! -s "$sanitizer_unrar_library" ]; then
            echo 'sanitizer ENABLE_UNRAR is ON but the UnRAR interface artifact is missing' >&2
            exit 2
        fi
        sanitizer_unrar_component_dir=$artifacts/optional-components-sanitizer
        mkdir -p "$sanitizer_unrar_component_dir"
        sanitizer_unrar_basename=$(basename "$sanitizer_unrar_library")
        cp -L "$sanitizer_unrar_library" "$sanitizer_unrar_component_dir/$sanitizer_unrar_basename"
        sanitizer_unrar_library_path="artifacts/optional-components-sanitizer/$sanitizer_unrar_basename"
        sanitizer_unrar_library_sha256=$(sha256sum "$out/$sanitizer_unrar_library_path" | awk '{ print $1 }')
        sanitizer_unrar_backend=$(find "$san_build_dir" -type f \( \
            -name 'libclamunrar.so' -o -name 'libclamunrar.so.*' \
            -o -name 'libclamunrar_static.a' -o -name 'libclamunrar.a' \
            \) -print | LC_ALL=C sort | head -n 1)
        case "$sanitizer_unrar_basename" in
            *.a) ;;
            *)
                if [ -z "$sanitizer_unrar_backend" ] || [ ! -s "$sanitizer_unrar_backend" ]; then
                    echo 'sanitizer shared UnRAR interface is missing its backend artifact' >&2
                    exit 2
                fi
                ;;
        esac
        if [ -n "$sanitizer_unrar_backend" ] && [ -s "$sanitizer_unrar_backend" ]; then
            sanitizer_unrar_backend_basename=$(basename "$sanitizer_unrar_backend")
            cp -L "$sanitizer_unrar_backend" "$sanitizer_unrar_component_dir/$sanitizer_unrar_backend_basename"
            sanitizer_unrar_backend_path="artifacts/optional-components-sanitizer/$sanitizer_unrar_backend_basename"
            sanitizer_unrar_backend_sha256=$(sha256sum "$out/$sanitizer_unrar_backend_path" | awk '{ print $1 }')
        fi
    fi
fi

# Run both scanners with the copied component set first in the loader path so
# the evidence records and exercises the same engine artifacts it verifies.
runtime_library_path="$runtime_component_dir"
if [ -n "$unrar_component_dir" ]; then
    runtime_library_path="$runtime_library_path:$unrar_component_dir"
fi
runtime_library_path="$runtime_library_path:$scanner_dir:$build_dir:$build_dir/libclamav:$build_dir/libclamav_rust:$build_dir/libclammspack:$build_dir/libclamunrar_iface"
export LD_LIBRARY_PATH=$runtime_library_path

# Capture the dynamic-loader decision before the workload starts. Hashing a
# copied dependency is not enough if the scanner later resolves a different
# build-tree library; the loader trace must show the copied component directory
# as an active search path for the executable that is actually exercised.
loader_trace=$provenance/loader-clamscan.txt
if ! LD_DEBUG=libs "$runtime_clamscan" --version > "$provenance/scanner-version.txt" 2> "$loader_trace"; then
    echo 'release scanner could not produce a loader-bound version trace' >&2
    exit 2
fi
if ! grep -F "$runtime_component_dir" "$loader_trace" >/dev/null 2>&1 ||
    grep -F 'not found' "$loader_trace" >/dev/null 2>&1; then
    echo 'release loader trace does not bind the scanner to copied runtime components' >&2
    exit 2
fi
sanitizer_loader_trace=
if [ -n "$sanitizer_clamscan" ]; then
    sanitizer_loader_trace=$provenance/loader-clamscan-sanitizer.txt
    sanitizer_loader_path="$sanitizer_component_dir"
    if [ -n "$sanitizer_unrar_component_dir" ]; then
        sanitizer_loader_path="$sanitizer_loader_path:$sanitizer_unrar_component_dir"
    fi
    sanitizer_loader_path="$sanitizer_loader_path:$scanner_dir:$build_dir:$build_dir/libclamav:$build_dir/libclamav_rust:$build_dir/libclammspack:$build_dir/libclamunrar_iface"
    if ! LD_LIBRARY_PATH="$sanitizer_loader_path" LD_DEBUG=libs \
        "$runtime_sanitizer_clamscan" --version > "$provenance/scanner-version-sanitizer.txt" 2> "$sanitizer_loader_trace"; then
        echo 'sanitizer scanner could not produce a loader-bound version trace' >&2
        exit 2
    fi
    if ! grep -F "$sanitizer_component_dir" "$sanitizer_loader_trace" >/dev/null 2>&1 ||
        grep -F 'not found' "$sanitizer_loader_trace" >/dev/null 2>&1; then
        echo 'sanitizer loader trace does not bind the scanner to copied runtime components' >&2
        exit 2
    fi
fi

scanner_sha256=$(sha256sum "$artifacts/clamscan" | awk '{ print $1 }')
cargo_lock_sha256=$(sha256sum "$provenance/Cargo.lock" | awk '{ print $1 }')
cmake_cache_sha256=$(sha256sum "$provenance/CMakeCache.txt" | awk '{ print $1 }')
compile_commands_sha256=$(sha256sum "$provenance/compile_commands.json" | awk '{ print $1 }')
sanitizer_cmake_cache_sha256=
sanitizer_compile_commands_sha256=
sanitizer_build_source_manifest_sha256=
if [ -n "$sanitizer_clamscan" ]; then
    sanitizer_cmake_cache_sha256=$(sha256sum "$provenance/CMakeCache-sanitizer.txt" | awk '{ print $1 }')
    sanitizer_compile_commands_sha256=$(sha256sum "$provenance/compile_commands-sanitizer.json" | awk '{ print $1 }')
    sanitizer_build_source_manifest_sha256=$(sha256sum "$provenance/build-source-manifest-sanitizer.txt" | awk '{ print $1 }')
fi
build_source_manifest_sha256=$(sha256sum "$provenance/build-source-manifest.txt" | awk '{ print $1 }')
repository_metadata=$provenance/repository-metadata.txt
repository_tree_sha256=$(sha256sum "$provenance/repository-tree.txt" | awk '{ print $1 }')
repository_index_sha256=$(sha256sum "$provenance/repository-index.txt" | awk '{ print $1 }')
{
    printf 'metadata_version=1\n'
    printf 'worktree_root=%s\n' "$root"
    printf 'source_commit=%s\n' "$source_commit"
    printf 'source_tree=%s\n' "$source_tree"
    printf 'source_repository=%s\n' "$source_repository"
    printf 'source_manifest_sha256=%s\n' "$source_manifest_sha256"
    printf 'source_revision_type=%s\n' "$source_revision_type"
    printf 'source_manifest=provenance/source-manifest.txt\n'
    printf 'tracked_file_count=%s\n' "$tracked_file_count"
    printf 'source_tree_manifest=provenance/repository-tree.txt\n'
    printf 'source_tree_manifest_sha256=%s\n' "$repository_tree_sha256"
    printf 'source_index_manifest=provenance/repository-index.txt\n'
    printf 'source_index_manifest_sha256=%s\n' "$repository_index_sha256"
    printf 'source_tree_status=%s\n' "$source_tree_status"
} > "$repository_metadata"
repository_metadata_sha256=$(sha256sum "$repository_metadata" | awk '{ print $1 }')

metadata=$out/build-identity.txt
{
    printf 'utc='; date -u '+%Y-%m-%dT%H:%M:%SZ'
    printf 'uname='; uname -a
    printf 'arch='; uname -m
    printf 'rss_budget_kb=%s\n' "$rss_budget_kb"
    printf 'min_available_kb=%s\n' "$min_available_kb"
    printf 'max_temp_bytes=%s\n' "$CLAMAV_MAX_TEMP_BYTES"
    printf 'max_scan_time_ms=%s\n' "$max_scan_time_ms"
    printf 'sanitizer_max_scan_time_ms=%s\n' "$sanitizer_max_scan_time_ms"
    printf 'sanitizer_rust_suite=%s\n' "$sanitizer_rust_suite"
    printf 'sanitizer_toolchain=%s\n' "$sanitizer_toolchain"
    printf 'sanitizer_rustflags=%s\n' "$sanitizer_rustflags"
    printf 'concurrency_levels=%s\n' "$concurrency_levels"
    printf 'concurrency_file=%s\n' "$concurrency_file"
    printf 'source_commit=%s\n' "$source_commit"
    printf 'source_tree=%s\n' "$source_tree"
    printf 'source_manifest_sha256=%s\n' "$source_manifest_sha256"
    printf 'build_source_manifest_sha256=%s\n' "$build_source_manifest_sha256"
    printf 'source_revision_type=%s\n' "$source_revision_type"
    printf 'source_tree_clean=yes\n'
    printf 'source_repository=%s\n' "$source_repository"
    printf 'repository_metadata=provenance/repository-metadata.txt\n'
    printf 'repository_metadata_sha256=%s\n' "$repository_metadata_sha256"
    printf 'repository_tree_manifest=provenance/repository-tree.txt\n'
    printf 'repository_tree_manifest_sha256=%s\n' "$repository_tree_sha256"
    printf 'repository_index_manifest=provenance/repository-index.txt\n'
    printf 'repository_index_manifest_sha256=%s\n' "$repository_index_sha256"
    printf 'tracked_file_count=%s\n' "$tracked_file_count"
    printf 'cmake_source=%s\n' "$cmake_source"
    printf 'cvd_certs_dir=%s\n' "${cvd_certs_dir:-default}"
    printf 'github_sha=%s\n' "${GITHUB_SHA:-unavailable}"
    printf 'github_ref=%s\n' "${GITHUB_REF:-unavailable}"
    printf 'github_run_id=%s\n' "${GITHUB_RUN_ID:-unavailable}"
    printf 'github_run_attempt=%s\n' "${GITHUB_RUN_ATTEMPT:-unavailable}"
    printf 'scanner_path=artifacts/clamscan\n'
    printf 'scanner_sha256=%s\n' "$scanner_sha256"
    printf 'cargo_lock_sha256=%s\n' "$cargo_lock_sha256"
    printf 'cmake_cache_sha256=%s\n' "$cmake_cache_sha256"
    printf 'compile_commands_sha256=%s\n' "$compile_commands_sha256"
    if [ -n "$sanitizer_clamscan" ]; then
        printf 'sanitizer_cmake_cache_sha256=%s\n' "$sanitizer_cmake_cache_sha256"
        printf 'sanitizer_compile_commands_sha256=%s\n' "$sanitizer_compile_commands_sha256"
        printf 'sanitizer_build_source_manifest_sha256=%s\n' "$sanitizer_build_source_manifest_sha256"
    fi
    printf 'runtime_dependency_hashes=provenance/runtime-dependency-hashes.txt\n'
    printf 'runtime_dependency_artifacts=provenance/runtime-dependency-artifacts.txt\n'
    printf 'runtime_component_dir=artifacts/runtime-components\n'
    printf 'release_rust_library_path=artifacts/clamav_rust-release.a\n'
    printf 'release_rust_library_sha256=%s\n' "$release_rust_library_sha256"
    printf 'unrar_status=%s\n' "$( [ "$enable_unrar" = ON ] && printf enabled || printf disabled )"
    printf 'unrar_library_path=%s\n' "$unrar_library_path"
    printf 'unrar_library_sha256=%s\n' "$unrar_library_sha256"
    printf 'unrar_backend_path=%s\n' "$unrar_backend_path"
    printf 'unrar_backend_sha256=%s\n' "$unrar_backend_sha256"
    printf 'loaded_dependencies=provenance/loaded-dependencies.txt\n'
    printf 'loader_trace=provenance/loader-clamscan.txt\n'
    cat "$provenance/scanner-version.txt"
    file "$artifacts/clamscan"
    if [ -n "$sanitizer_clamscan" ]; then
        sanitizer_scanner_sha256=$(sha256sum "$artifacts/clamscan-sanitizer" | awk '{ print $1 }')
        printf 'sanitizer_scanner_path=artifacts/clamscan-sanitizer\n'
        printf 'sanitizer_scanner_sha256=%s\n' "$sanitizer_scanner_sha256"
        file "$artifacts/clamscan-sanitizer"
        LD_LIBRARY_PATH="$sanitizer_loader_path" "$runtime_sanitizer_clamscan" --version
        printf 'sanitizer_dependency_hashes=provenance/runtime-dependency-hashes-sanitizer.txt\n'
        printf 'sanitizer_dependency_artifacts=provenance/runtime-dependency-artifacts-sanitizer.txt\n'
        printf 'sanitizer_component_dir=artifacts/runtime-components-sanitizer\n'
        printf 'sanitizer_loaded_dependencies=provenance/loaded-dependencies-sanitizer.txt\n'
        printf 'sanitizer_loader_trace=provenance/loader-clamscan-sanitizer.txt\n'
        cat "$provenance/scanner-version-sanitizer.txt"
        printf 'sanitizer_rust_library_path=artifacts/clamav_rust-sanitizer.a\n'
        printf 'sanitizer_rust_library_sha256=%s\n' "$sanitizer_rust_library_sha256"
        printf 'sanitizer_rust_symbols=provenance/rust-sanitizer-symbols.txt\n'
        printf 'sanitizer_unrar_status=%s\n' "$( [ "$sanitizer_enable_unrar" = ON ] && printf enabled || printf disabled )"
        printf 'sanitizer_unrar_library_path=%s\n' "$sanitizer_unrar_library_path"
        printf 'sanitizer_unrar_library_sha256=%s\n' "$sanitizer_unrar_library_sha256"
        printf 'sanitizer_unrar_backend_path=%s\n' "$sanitizer_unrar_backend_path"
        printf 'sanitizer_unrar_backend_sha256=%s\n' "$sanitizer_unrar_backend_sha256"
        printf 'sanitizer_compile_graph=pass\n'
        printf 'sanitizer_rust_instrumentation=pass\n'
        printf 'sanitizer_instrumentation=pass\n'
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

if ! file "$runtime_clamscan" | grep -E 'ELF .*x86-64' >/dev/null 2>&1; then
    echo "scanner is not an x86-64 ELF executable; see $metadata" >&2
    exit 1
fi

corpus=$out/corpus
mkdir -p "$corpus"
"$root/tools/largefile_boundary_corpus.sh" "$corpus" > "$out/corpus.log" 2>&1

failures=0
poc_out=$out/poc
if "$root/tools/largefile_poc.sh" "$runtime_clamscan" "$corpus" "$poc_out" > "$out/poc.log" 2>&1; then
    printf 'largefile_poc=pass\n' >> "$metadata"
else
    printf 'largefile_poc=fail\n' >> "$metadata"
    failures=$((failures + 1))
fi

results=$poc_out/results.tsv
if [ -f "$results" ]; then
    if awk -F '\t' -v budget="$CLAMAV_MAX_TEMP_BYTES" 'NR > 1 && $12 > budget { bad = 1 } END { exit bad }' "$results"; then
        printf 'temp_budget=pass\n' >> "$metadata"
    else
        printf 'temp_budget=fail\n' >> "$metadata"
        failures=$((failures + 1))
    fi
else
    printf 'temp_budget=fail\n' >> "$metadata"
    failures=$((failures + 1))
fi

if [ "$run_cancellation" -eq 1 ]; then
    cancellation_log=$out/cancellation.log
    cancellation_status=0
    if command -v timeout >/dev/null 2>&1; then
        timeout --signal=TERM --kill-after=5 1 \
            "$runtime_clamscan" \
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
"$runtime_clamscan" \
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

# Exercise the same 32-GiB-plus-one policy through unknown-length stdin. The
# front end must read through the boundary, reject the input, and never
# report a clean prefix as OK.
policy_stdin_log=$out/32g-plus-one-stdin.log
policy_stdin_status=0
"$runtime_clamscan" \
    --database="$poc_out/db" \
    --max-filesize=32G \
    --max-scansize=32G \
    --max-temporary-size=64G \
    --max-contiguous-size=32G \
    --pcre-max-filesize=32G \
    --max-scantime="$max_scan_time_ms" \
    --alert-exceeds-max \
    --debug \
    --no-summary \
    - < "$policy_file" > "$policy_stdin_log" 2>&1 || policy_stdin_status=$?
if [ "$policy_stdin_status" -eq 1 ] &&
    grep -E 'MaxFileSize|Max file size|exceeds the maximum file size|stdin exceeds MaxFileSize' \
        "$policy_stdin_log" >/dev/null 2>&1 &&
    ! grep -E '(^|[[:space:]])OK([[:space:]]|$)' "$policy_stdin_log" >/dev/null 2>&1; then
    printf 'policy_32g_plus_one_stdin=pass\n' >> "$metadata"
else
    printf 'policy_32g_plus_one_stdin=fail status=%s\n' "$policy_stdin_status" >> "$metadata"
    failures=$((failures + 1))
fi

# The positive stdin boundary must also be exercised: an unknown-length
# stream exactly 32 GiB long must reach the final marker and return the same
# detection/offset as the path-based edge case.  Keep this separate from the
# 32-GiB+1 rejection so a clean prefix cannot satisfy either policy check.
edge_stdin_log=$out/32g-edge-stdin.log
edge_stdin_status=0
mkdir -p "$poc_out/tmp/edge-stdin"
"$runtime_clamscan" \
    --database="$poc_out/db" \
    --max-filesize=32G \
    --max-scansize=32G \
    --max-temporary-size=64G \
    --max-contiguous-size=32G \
    --pcre-max-filesize=32G \
    --max-scantime="$max_scan_time_ms" \
    --debug \
    --no-summary \
    --tempdir="$poc_out/tmp/edge-stdin" \
    - < "$corpus/32g-edge.bin" > "$edge_stdin_log" 2>&1 || edge_stdin_status=$?
if [ "$edge_stdin_status" -eq 1 ] &&
    grep -E 'LargeFile\.POC\.32g-edge(\.UNOFFICIAL)?.*FOUND' \
        "$edge_stdin_log" >/dev/null 2>&1 &&
    grep -E 'signature LargeFile\.POC\.32g-edge(\.UNOFFICIAL)? matched at 34359738304' \
        "$edge_stdin_log" >/dev/null 2>&1; then
    printf 'policy_32g_edge_stdin=pass\n' >> "$metadata"
else
    printf 'policy_32g_edge_stdin=fail status=%s\n' "$edge_stdin_status" >> "$metadata"
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
            /usr/bin/time -v "$runtime_clamscan" \
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
    if [ "$sanitizer_rust_suite" != pass ]; then
        echo 'sanitizer evidence requires the supported Rust CTest suite to pass' >&2
        exit 2
    fi
    sanitizer_out=$out/sanitizer
    sanitizer_status=0
    sanitizer_library_path="$sanitizer_component_dir:$runtime_library_path"
    CLAMAV_MAX_SCAN_TIME_MS=$sanitizer_max_scan_time_ms \
    ASAN_OPTIONS=${ASAN_OPTIONS:-detect_leaks=1:halt_on_error=1} \
    UBSAN_OPTIONS=${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1} \
    LD_LIBRARY_PATH=$sanitizer_library_path \
        "$root/tools/largefile_poc.sh" "$runtime_sanitizer_clamscan" "$corpus" "$sanitizer_out" > "$out/sanitizer.log" 2>&1 || sanitizer_status=$?
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
