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
    "$build/clamdscan" "$build/clamav-milter" "$out/logs" "$out/reports"

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

workload_input=$tmp/workload-input.bin
printf 'synthetic workload input\n' > "$workload_input"
workload_size=$(stat -c '%s' "$workload_input" 2>/dev/null || stat -f '%z' "$workload_input")
workload_hash=$(sha256sum "$workload_input" | awk '{ print $1 }')
qualification_oracle=$out/provenance/qualification-oracle.tsv
printf 'role\texpected_size\texpected_sha256\texpected_exit\texpected_completion\texpected_signature\texpected_offset\texpected_type\n' > "$qualification_oracle"
for role in production materialized expansion edge; do
    if [ "$role" = edge ]; then
        printf '%s\t%s\t%s\t1\tDETECTION_TERMINATED\tSynthetic.Detection\t123\tCL_TYPE_DATA\n' \
            "$role" "$workload_size" "$workload_hash" >> "$qualification_oracle"
    else
        printf '%s\t%s\t%s\t0\tCOMPLETE\t-\t-\tCL_TYPE_DATA\n' \
            "$role" "$workload_size" "$workload_hash" >> "$qualification_oracle"
    fi
done
workload_results=$out/provenance/service-workload-results.tsv
printf 'label\tkind\trole\tinput\tlog\treport\tstatus\tcheck_offset\n' > "$workload_results"
clean_report_json=$(printf '{"version":1,"completion":"COMPLETE","file_type":"CL_TYPE_DATA","status":0,"verdict":0,"root_size":%s,"logical_bytes":%s,"matcher_bytes":0,"contiguous_bytes":0,"temporary_bytes":0,"files_scanned":1,"max_recursion_depth":0,"elapsed_ms":1,"parser_operations":1,"detector_operations":1,"skipped_operations":0}\n' "$workload_size" "$workload_size")
detection_report_json=$(printf '{"version":1,"completion":"DETECTION_TERMINATED","file_type":"CL_TYPE_DATA","status":0,"verdict":2,"last_alert":"Synthetic.Detection","root_size":%s,"logical_bytes":%s,"matcher_bytes":0,"contiguous_bytes":0,"temporary_bytes":0,"files_scanned":1,"max_recursion_depth":0,"elapsed_ms":1,"parser_operations":1,"detector_operations":1,"skipped_operations":0}\n' "$workload_size" "$workload_size")
report_json=$clean_report_json
workload_labels='production_cvd_scanreport production_cvd_contscanreport production_cvd_multiscanreport production_cvd_allmatchscan production_cvd_fildesreport production_cvd_instreamreport production-clamscan clamd-serial-queue-1 clamd-serial-queue-2 production_cvd production_cvd_fildes production_cvd_instream materialized_warm materialized_cold parser_expansion edge-clamscan edge-clamscan-stdin edge-clamdscan-stdin edge_contscan edge_multiscan edge_allmatch edge_fildes edge_instream clamd-multiworker-1 clamd-multiworker-2 clamd-multiworker-3 clamd-multiworker-4'
for label in $workload_labels; do
    case "$label" in
        production_cvd_scanreport|production_cvd_contscanreport|production_cvd_multiscanreport|production_cvd_allmatchscan|production_cvd_fildesreport|production_cvd_instreamreport)
            kind=report
            role=production
            check_offset=no
            ;;
        production-clamscan)
            kind=cli
            role=production
            check_offset=yes
            ;;
        clamd-serial-queue-*)
            kind=service
            role=materialized
            check_offset=no
            ;;
        materialized_warm|materialized_cold)
            kind=service
            role=materialized
            check_offset=no
            ;;
        parser_expansion)
            kind=service
            role=expansion
            check_offset=no
            ;;
        production_cvd|production_cvd_fildes|production_cvd_instream)
            kind=service
            role=production
            check_offset=no
            ;;
        edge-clamscan|edge-clamscan-stdin)
            kind=cli
            role=edge
            check_offset=yes
            ;;
        *)
            kind=service
            role=edge
            check_offset=no
            ;;
    esac
    log_rel="logs/$label.log"
    report_rel="reports/$label.jsonl"
    workload_status=0
    report_for_role=$clean_report_json
    if [ "$role" = edge ]; then
        printf 'Synthetic.Detection: %s: FOUND\n' "$workload_input" > "$out/$log_rel"
        printf 'signature Synthetic.Detection matched at 123\n' >> "$out/$log_rel"
        report_for_role=$detection_report_json
        workload_status=1
    else
        printf 'clean\n' > "$out/$log_rel"
    fi
    printf '%s' "$report_for_role" > "$out/$report_rel"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$label" "$kind" "$role" "$workload_input" "$log_rel" "$report_rel" \
        "$workload_status" "$check_offset" >> "$workload_results"
done
printf 'milter manual wire: body_bytes=1 message_bytes=1 limit_bytes=34359738368 result=r chunk_bytes=1 fill_byte=65\n' > \
    "$out/logs/milter-exact-edge.log"
printf 'milter-exact-edge\tmilter\t-\t-\tlogs/milter-exact-edge.log\t-\t0\tno\n' >> "$workload_results"

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
oracle_hash=$(sha256sum "$qualification_oracle" | awk '{ print $1 }')
workload_hash_manifest=$(sha256sum "$workload_results" | awk '{ print $1 }')
{
    printf 'qualification_oracle=provenance/qualification-oracle.tsv\n'
    printf 'qualification_oracle_sha256=%s\n' "$oracle_hash"
    printf 'workload_results=provenance/service-workload-results.tsv\n'
    printf 'workload_results_sha256=%s\n' "$workload_hash_manifest"
} > "$out/oracle-binding.txt"
(
    cd "$out"
    find . -type f ! -name SHA256SUMS -print | LC_ALL=C sort |
        while IFS= read -r evidence_file; do
            sha256sum "$evidence_file"
        done
) > "$out/SHA256SUMS"

sh "$root/tools/largefile_service_evidence_check.sh" "$out" "$build" >/dev/null

cp "$out/reports/edge-clamscan.jsonl" "$out/reports/edge-clamscan.good"
sed 's/"verdict":2/"verdict":0/' "$out/reports/edge-clamscan.good" > \
    "$out/reports/edge-clamscan.jsonl"
if python3 "$root/tools/largefile_service_workload_check.py" "$out" >/dev/null 2>&1; then
    echo 'service workload verifier accepted a detection report with a clean verdict' >&2
    exit 1
fi
mv "$out/reports/edge-clamscan.good" "$out/reports/edge-clamscan.jsonl"

printf '%s' "$report_json" > "$out/reports/production_cvd_scanreport.jsonl"
printf 'mutated structured report\n' >> "$out/reports/production_cvd_scanreport.jsonl"
if python3 "$root/tools/largefile_service_workload_check.py" "$out" >/dev/null 2>&1; then
    echo 'service workload verifier accepted a mutated structured report' >&2
    exit 1
fi
printf '%s' "$report_json" > "$out/reports/production_cvd_scanreport.jsonl"
printf 'mutated workload input\n' >> "$workload_input"
if python3 "$root/tools/largefile_service_workload_check.py" "$out" >/dev/null 2>&1; then
    echo 'service workload verifier accepted a mutated input' >&2
    exit 1
fi

printf 'mutated after qualification\n' >> "$build/clamscan/clamscan"
if sh "$root/tools/largefile_service_evidence_check.sh" "$out" "$build" >/dev/null 2>&1; then
    echo 'service evidence verifier accepted a mutated service executable' >&2
    exit 1
fi

grep -F 'largefile_service_evidence_check.sh' "$root/.github/workflows/cmake.yml" >/dev/null
echo 'service runtime evidence verifier regression passed'
