#!/bin/sh

# Regression test for the post-workload service-evidence verifier.  The
# fixture is synthetic and is never release evidence.

set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/clamav-largefile-service-evidence.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

# The full evidence controls use an isolated, scaled copy of the verifier.
# Production has no synthetic-size CLI or environment override. Its unchanged
# entry point is checked below to ensure these tiny fixtures cannot qualify.
control_root=$tmp/control-source
mkdir -p "$control_root/tools" "$control_root/docs"
control_root=$(CDPATH= cd -- "$control_root" && pwd)
cp "$root/tools/largefile_service_evidence_check.sh" "$root/tools/largefile_service_oversize.py" "$control_root/tools/"
cp "$root/tools/largefile_service_workload_check.py" "$root/tools/largefile_acceptance_cases.py" "$control_root/tools/"
cp "$root/docs/largefile-capabilities.tsv" "$root/docs/largefile-capability-case-map.tsv" "$control_root/docs/"
python3 "$root/tools/largefile_service_workload_check_test.py"
python3 "$root/tools/largefile_service_result_check_test.py"
python3 -B "$root/tools/largefile_service_oversize_test.py"

out=$tmp/service
build=$tmp/build
mkdir -p "$out/provenance" "$build/clamscan" "$build/clamd" \
    "$build/clamdscan" "$build/clamav-milter" "$out/logs" "$out/reports" \
    "$out/artifacts/service-runtime-components"

interpreter=$(CDPATH= cd -- "$tmp" && pwd)/ld-linux-synthetic.so
printf 'synthetic ELF interpreter\n' > "$interpreter"

write_synthetic_elf()
{
    python3 - "$1" "$2" <<'PY'
from pathlib import Path
import struct
import sys

binary, interpreter = map(Path, sys.argv[1:])
payload = interpreter.as_posix().encode("ascii") + b"\0"
ident = b"\x7fELF\x02\x01\x01" + b"\0" * 9
header = struct.pack("<HHIQQQIHHHHHH", 3, 62, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0)
program = struct.pack("<IIQQQQQQ", 3, 4, 120, 0, 0, len(payload), len(payload), 1)
binary.write_bytes(ident + header + program + payload)
PY
}

for relative_binary in \
    clamscan/clamscan clamd/clamd clamdscan/clamdscan clamav-milter/clamav-milter; do
    write_synthetic_elf "$build/$relative_binary" "$interpreter"
    chmod 755 "$build/$relative_binary"
done
printf 'synthetic runtime dependency\n' > "$tmp/libclamav.so"
printf 'synthetic source manifest\n' > "$out/provenance/source-manifest.txt"
lifecycle=$out/provenance/service-lifecycle.tsv
printf 'generation\tevent\tresult\n' > "$lifecycle"
for lifecycle_event in \
    'ping_after_start	pass' \
    'ping_before_stop	pass' \
    'daemon_running_before_stop	yes' \
    'daemon_exited_after_stop	yes' \
    'socket_absent_after_stop	yes' \
    'pidfile_absent_after_stop	yes'; do
    printf '1\t%s\n' "$lifecycle_event" >> "$lifecycle"
done
source_manifest_sha256=$(sha256sum "$out/provenance/source-manifest.txt" | awk '{ print $1 }')
source_commit=$source_manifest_sha256
source_tree=$source_manifest_sha256
printf 'MaxThreads 1\nMaxQueue 2\nMaxScanTime 14400000\nAlertExceedsMax yes\n' > "$out/clamd.conf"
printf 'MaxThreads 1\nMaxQueue 2\nMaxScanTime 14400000\nAlertExceedsMax yes\n' > \
    "$out/provenance/parallel-client-clamd.conf"
parallel_profile=$out/provenance/parallel-client-clamd.conf
printf 'CMAKE_HOME_DIRECTORY:INTERNAL=%s\n' "$control_root" > "$out/provenance/CMakeCache.txt"
printf 'CLAMAV_SOURCE_COMMIT:INTERNAL=%s\n' "$source_commit" >> "$out/provenance/CMakeCache.txt"
printf 'CLAMAV_SOURCE_MANIFEST_SHA256:INTERNAL=%s\n' "$source_manifest_sha256" >> "$out/provenance/CMakeCache.txt"
printf '[{"directory":"%s","command":"cc -c synthetic.c","file":"synthetic.c"}]\n' "$control_root" > \
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
interpreter_records=$out/provenance/service-interpreter-records-before.txt
: > "$interpreter_records"
for relative_binary in \
    clamscan/clamscan clamd/clamd clamdscan/clamdscan clamav-milter/clamav-milter; do
    printf '%s\t%s\t%s\n' "$relative_binary" "$interpreter" \
        "$(sha256sum "$interpreter" | awk '{ print $1 }')" >> "$interpreter_records"
done
interpreter_records_after=$out/provenance/service-interpreter-records-after.txt
cp "$interpreter_records" "$interpreter_records_after"
dependency_hashes=$out/provenance/service-runtime-dependency-hashes.txt
printf '%s\t%s\n' "$tmp/libclamav.so" \
    "$(sha256sum "$tmp/libclamav.so" | awk '{ print $1 }')" > "$dependency_hashes"
dependency_hashes_after=$out/provenance/service-runtime-dependency-hashes-after.txt
cp "$dependency_hashes" "$dependency_hashes_after"
runtime_component_dir=$out/artifacts/service-runtime-components
runtime_component_artifacts=$out/provenance/service-runtime-component-artifacts.txt
runtime_component_hashes=$out/provenance/service-runtime-component-hashes-before.txt
runtime_component_hashes_after=$out/provenance/service-runtime-component-hashes-after.txt
loaded_dependencies=$out/provenance/service-loaded-dependencies.txt
cp "$tmp/libclamav.so" "$runtime_component_dir/libclamav.so"
runtime_component_hash=$(sha256sum "$runtime_component_dir/libclamav.so" | awk '{ print $1 }')
printf '%s\tartifacts/service-runtime-components/libclamav.so\t%s\n' \
    "$tmp/libclamav.so" "$runtime_component_hash" > "$runtime_component_artifacts"
printf 'artifacts/service-runtime-components/libclamav.so\t%s\n' "$runtime_component_hash" > \
    "$runtime_component_hashes"
cp "$runtime_component_hashes" "$runtime_component_hashes_after"
: > "$loaded_dependencies"
for relative_binary in \
    clamscan/clamscan clamd/clamd clamdscan/clamdscan clamav-milter/clamav-milter; do
    printf 'service=%s\n' "$relative_binary" >> "$loaded_dependencies"
    printf 'libclamav.so => %s (0x0)\n' "$runtime_component_dir/libclamav.so" >> "$loaded_dependencies"
done

workload_input=$tmp/workload-input.bin
printf 'synthetic workload input\n' > "$workload_input"
workload_size=$(stat -c '%s' "$workload_input" 2>/dev/null || stat -f '%z' "$workload_input")
workload_hash=$(sha256sum "$workload_input" | awk '{ print $1 }')
python3 - "$root/tools/largefile_service_workload_check.py" \
    "$control_root/tools/largefile_service_workload_check.py" "$workload_size" <<'PYCONTROL'
from pathlib import Path
import sys

source, target = map(Path, sys.argv[1:3])
size = int(sys.argv[3])
text = source.read_text(encoding="utf-8")
constant = "EXACT_EDGE_BYTES = 32 * 1024 * 1024 * 1024"
assert text.count(constant) == 1
text = text.replace(constant, f"EXACT_EDGE_BYTES = {size}")
target.write_text(text, encoding="utf-8")
PYCONTROL
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
# The unmodified qualification CLI must reject the scaled oracle before
# hashing/scanning any input. Never present the following controls as proof.
if python3 "$root/tools/largefile_service_workload_check.py" --check-inputs \
    "$qualification_oracle" "$workload_input" "$workload_input" \
    "$workload_input" "$workload_input" > "$tmp/strict.out" 2> "$tmp/strict.err"; then
    echo 'production input preflight accepted a synthetic edge fixture' >&2
    exit 1
fi
grep -F 'edge input must be exactly 34359738368 bytes' "$tmp/strict.err" >/dev/null
python3 "$control_root/tools/largefile_service_workload_check.py" --check-inputs \
    "$qualification_oracle" "$workload_input" "$workload_input" \
    "$workload_input" "$workload_input" > "$out/provenance/service-inputs-before.json"
cp "$out/provenance/service-inputs-before.json" "$out/provenance/service-inputs-after.json"

workload_results=$out/provenance/service-workload-results.tsv
printf 'label\tkind\trole\tinput\tlog\treport\tstatus\tcheck_offset\n' > "$workload_results"
acceptance_records=$out/provenance/acceptance-cases.tsv
printf 'kind\tid\tcase_id\tsource_manifest_sha256\tbuild_identity_sha256\tconfig_sha256\tplatform\tfixture_role\tfixture_sha256\toracle_sha256\tdatabase_sha256\texit_code\tverdict\tcompletion\treason\talert_signature\talert_offset\tlogical_bytes\tmatcher_bytes\tcontiguous_bytes\ttemporary_bytes\tfiles_scanned\tmax_recursion_depth\telapsed_ms\tparser_operations\tdetector_operations\tskipped_operations\tsanitizer\tresource_phase\thealth\tcleanup\tartifacts\n' > "$acceptance_records"
clean_report_json=$(printf '{"version":1,"completion":"COMPLETE","file_type":"CL_TYPE_DATA","status":0,"verdict":0,"root_size":%s,"logical_bytes":%s,"max_scan_size":68719476736,"matcher_bytes":0,"contiguous_bytes":0,"temporary_bytes":0,"files_scanned":1,"max_recursion_depth":0,"elapsed_ms":1,"parser_operations":1,"detector_operations":1,"skipped_operations":0}\n' "$workload_size" "$workload_size")
detection_report_json=$(printf '{"version":1,"completion":"DETECTION_TERMINATED","file_type":"CL_TYPE_DATA","status":0,"verdict":2,"last_alert":"Synthetic.Detection","last_alert_offset":123,"root_size":%s,"logical_bytes":%s,"max_scan_size":68719476736,"matcher_bytes":0,"contiguous_bytes":0,"temporary_bytes":0,"files_scanned":1,"max_recursion_depth":0,"elapsed_ms":1,"parser_operations":1,"detector_operations":1,"skipped_operations":0}\n' "$workload_size" "$workload_size")
report_json=$clean_report_json
workload_labels='production_cvd_scanreport production_cvd_contscanreport production_cvd_multiscanreport production_cvd_allmatchscan production_cvd_fildesreport production_cvd_instreamreport production-clamscan clamd-serial-queue-1 clamd-serial-queue-2 production_cvd production_cvd_fildes production_cvd_instream materialized_warm materialized_cold parser_expansion edge-clamscan edge-clamscan-stdin edge-clamdscan-stdin edge-clamdscan-multiscan edge-clamdscan-stream-multiscan edge-clamdscan-fdpass-multiscan edge_contscan edge_multiscan edge_allmatch edge_fildes edge_instream clamd-parallel-client-1 clamd-parallel-client-2'
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
        edge_contscan|edge_multiscan|edge_allmatch|edge_fildes|edge_instream)
            kind=legacy
            role=edge
            check_offset=no
            ;;
        *)
            kind=service
            role=edge
            check_offset=no
            ;;
    esac
    log_rel="logs/$label.log"
    if [ "$kind" = legacy ]; then
        report_rel=-
    else
        report_rel="reports/$label.jsonl"
    fi
    workload_status=0
    report_for_role=$clean_report_json
    if [ "$kind" = legacy ]; then
        case "$label" in
            edge_contscan) legacy_mode=CONTSCAN ;;
            edge_multiscan) legacy_mode=MULTISCAN ;;
            edge_allmatch) legacy_mode=ALLMATCHSCAN ;;
            edge_fildes) legacy_mode=FILDES ;;
            edge_instream) legacy_mode=INSTREAM ;;
        esac
        printf 'protocol_mode=%s\n' "$legacy_mode" > "$out/$log_rel"
        printf '%s: Synthetic.Detection FOUND\n' "$workload_input" >> "$out/$log_rel"
        report_for_role=$detection_report_json
        workload_status=1
    elif [ "$role" = edge ]; then
        printf '%s: Synthetic.Detection FOUND\n' "$workload_input" > "$out/$log_rel"
        printf 'signature Synthetic.Detection matched at 123\n' >> "$out/$log_rel"
        report_for_role=$detection_report_json
        workload_status=1
    else
        printf 'clean\n' > "$out/$log_rel"
    fi
    if [ "$report_rel" != - ]; then
        printf '%s' "$report_for_role" > "$out/$report_rel"
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$label" "$kind" "$role" "$workload_input" "$log_rel" "$report_rel" \
        "$workload_status" "$check_offset" >> "$workload_results"
done
printf 'milter manual wire: body_bytes=34359738316 message_bytes=34359738368 limit_bytes=34359738368 result=r signature=Milter.Protocol.Test offset=34359738349 sha256=7ec57c684966d38ba3db215be49cffa732317898dc8868439be681ba6ed6d50e completion=DETECTION_TERMINATED root_size=34359738368 logical_bytes=34359738368 max_scan_size=68719476736 skipped_operations=0 last_alert_offset=34359738349\n' > \
    "$out/logs/milter-exact-edge.log"
printf 'THRMGR: dispatch accepted: active=1 queued=1 max_threads=1 max_queue=2\n' > \
    "$out/logs/clamd-parallel-queue.log"
printf 'milter-exact-edge\tmilter\t-\t-\tlogs/milter-exact-edge.log\t-\t0\tno\n' >> "$workload_results"
python3 -B - "$root/tools" "$out/reports/oversize-fildesreport.json" <<'PYOVERSIZE'
import json
from pathlib import Path
import sys

sys.path.insert(0, sys.argv[1])
from largefile_service_oversize_test import both_mode_evidence
Path(sys.argv[2]).write_text(json.dumps(both_mode_evidence(), sort_keys=True))
PYOVERSIZE
: > "$out/logs/oversize-fildesreport.log"
printf 'oversize-fildesreport\toversize\t-\t-\tlogs/oversize-fildesreport.log\treports/oversize-fildesreport.json\t0\tno\n' >> "$workload_results"

cmake_cache_sha256=$(sha256sum "$out/provenance/CMakeCache.txt" | awk '{ print $1 }')
compile_commands_sha256=$(sha256sum "$out/provenance/compile_commands.json" | awk '{ print $1 }')
binary_hashes_sha256=$(sha256sum "$binary_list" | awk '{ print $1 }')
interpreter_hashes_sha256=$(sha256sum "$interpreter_records" | awk '{ print $1 }')
dependency_hashes_sha256=$(sha256sum "$dependency_hashes" | awk '{ print $1 }')
runtime_component_artifacts_sha256=$(sha256sum "$runtime_component_artifacts" | awk '{ print $1 }')
runtime_component_hashes_sha256=$(sha256sum "$runtime_component_hashes" | awk '{ print $1 }')
loaded_dependencies_sha256=$(sha256sum "$loaded_dependencies" | awk '{ print $1 }')
{
    printf 'source_commit=%s\n' "$source_commit"
    printf 'source_tree=%s\n' "$source_tree"
    printf 'source_manifest_sha256=%s\n' "$source_manifest_sha256"
    printf 'cmake_cache_sha256=%s\n' "$cmake_cache_sha256"
    printf 'compile_commands_sha256=%s\n' "$compile_commands_sha256"
    printf 'service_binary_hashes=provenance/service-binary-hashes-before.txt\n'
    printf 'service_binary_hashes_sha256=%s\n' "$binary_hashes_sha256"
    printf 'service_interpreter_records=provenance/service-interpreter-records-before.txt\n'
    printf 'service_interpreter_records_sha256=%s\n' "$interpreter_hashes_sha256"
    printf 'service_runtime_dependency_hashes=provenance/service-runtime-dependency-hashes.txt\n'
    printf 'service_runtime_dependency_hashes_sha256=%s\n' "$dependency_hashes_sha256"
    printf 'service_runtime_dependency_hashes_after=provenance/service-runtime-dependency-hashes-after.txt\n'
    printf 'service_runtime_dependency_hashes_after_sha256=%s\n' "$(sha256sum "$dependency_hashes_after" | awk '{ print $1 }')"
    printf 'service_runtime_component_dir=artifacts/service-runtime-components\n'
    printf 'service_runtime_component_artifacts=provenance/service-runtime-component-artifacts.txt\n'
    printf 'service_runtime_component_artifacts_sha256=%s\n' "$runtime_component_artifacts_sha256"
    printf 'service_runtime_component_hashes=provenance/service-runtime-component-hashes-before.txt\n'
    printf 'service_runtime_component_hashes_sha256=%s\n' "$runtime_component_hashes_sha256"
    printf 'service_runtime_component_hashes_after=provenance/service-runtime-component-hashes-after.txt\n'
    printf 'service_runtime_component_hashes_after_sha256=%s\n' "$(sha256sum "$runtime_component_hashes_after" | awk '{ print $1 }')"
    printf 'service_loaded_dependencies=provenance/service-loaded-dependencies.txt\n'
    printf 'service_loaded_dependencies_sha256=%s\n' "$loaded_dependencies_sha256"
    printf 'service_loader_path=artifacts/service-runtime-components\n'
    printf 'service_interpreter_records_after=provenance/service-interpreter-records-after.txt\n'
    printf 'service_interpreter_records_after_sha256=%s\n' "$(sha256sum "$interpreter_records_after" | awk '{ print $1 }')"
    printf 'service_lifecycle=provenance/service-lifecycle.tsv\n'
    printf 'service_lifecycle_sha256=%s\n' "$(sha256sum "$lifecycle" | awk '{ print $1 }')"
    printf 'loader_injection=disabled\n'
    printf 'max_scan_time_ms=14400000\n'
    printf 'service_timeout_s=14400\n'
} > "$out/provenance/service-build-identity.txt"
{
    printf 'service_resource_measurement_failed=0\n'
    printf 'rss_budget_kb=33554432\n'
    printf 'pcre_rss_budget_kb=41943040\n'
    printf 'post_pcre_rss_budget_kb=12582912\n'
    printf 'rss_budget_contract=overall-stricter-than-pcre-phase\n'
    printf 'service_runtime_dependencies_unchanged=pass\n'
    printf 'service_runtime_loader_binding=pass\n'
    printf 'service_runtime_components_unchanged=pass\n'
    printf 'service_interpreters_unchanged=pass\n'
    printf 'clamd_parallel_clients=pass\n'
    printf 'parallel_worker_count=1\n'
    printf 'parallel_client_count=2\n'
    printf 'parallel_test_max_queue=2\n'
    printf 'parallel_profile=provenance/parallel-client-clamd.conf\n'
    printf 'parallel_queue_log=logs/clamd-parallel-queue.log\n'
    printf 'parallel_queue_observation_count=1\n'
    printf 'parallel_queue=pass\n'
    printf 'service_lifecycle=pass\n'
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

sh "$control_root/tools/largefile_service_evidence_check.sh" "$out" "$build" >/dev/null

write_checksum_manifest()
{
    (
        cd "$out"
        find . -type f ! -name SHA256SUMS -print | LC_ALL=C sort |
            while IFS= read -r evidence_file; do
                sha256sum "$evidence_file"
            done
    ) > "$out/SHA256SUMS"
}

cp "$lifecycle" "$tmp/service-lifecycle.good"
sed 's/^1\tsocket_absent_after_stop\tyes$/1\tsocket_absent_after_stop\tno/' \
    "$tmp/service-lifecycle.good" > "$lifecycle"
write_checksum_manifest
if sh "$control_root/tools/largefile_service_evidence_check.sh" "$out" "$build" > "$tmp/lifecycle.out" 2> "$tmp/lifecycle.err"; then
    echo 'service evidence verifier accepted failed lifecycle cleanup' >&2
    exit 1
fi
grep -F 'service lifecycle evidence is incomplete or failed' "$tmp/lifecycle.err" >/dev/null
mv "$tmp/service-lifecycle.good" "$lifecycle"
write_checksum_manifest

# Rehash the tampered evidence so rejection must come from the semantic
# allocation checks, rather than the outer checksum manifest.
cp "$out/provenance/service-inputs-before.json" "$tmp/service-inputs.good"
python3 - "$out/provenance/service-inputs-after.json" <<'PYINPUT'
import json
from pathlib import Path
import sys

path = Path(sys.argv[1])
record = json.loads(path.read_text())
record["inputs"]["materialized"]["allocated_bytes"] = 0
path.write_text(json.dumps(record, sort_keys=True))
PYINPUT
write_checksum_manifest
if sh "$control_root/tools/largefile_service_evidence_check.sh" "$out" "$build" > "$tmp/input.out" 2> "$tmp/input.err"; then
    echo 'service evidence verifier accepted changed input allocation evidence' >&2
    exit 1
fi
grep -F 'service input allocation/content evidence changed during qualification' "$tmp/input.err" >/dev/null
cp "$out/provenance/service-inputs-after.json" "$out/provenance/service-inputs-before.json"
write_checksum_manifest
if sh "$control_root/tools/largefile_service_evidence_check.sh" "$out" "$build" > "$tmp/input.out" 2> "$tmp/input.err"; then
    echo 'service evidence verifier accepted matching but forged input allocation evidence' >&2
    exit 1
fi
grep -F 'input does not match its recorded allocation/content evidence' "$tmp/input.err" >/dev/null
cp "$tmp/service-inputs.good" "$out/provenance/service-inputs-before.json"
cp "$tmp/service-inputs.good" "$out/provenance/service-inputs-after.json"
write_checksum_manifest

cp "$out/reports/oversize-fildesreport.json" "$tmp/oversize.good"
python3 - "$out/reports/oversize-fildesreport.json" <<'PYOVERSIZE'
import json
from pathlib import Path
import sys

path = Path(sys.argv[1])
record = json.loads(path.read_text())
record["alert_on"]["report"]["reason"] = "Heuristics.Limits.Exceeded.MaxScanSize"
path.write_text(json.dumps(record))
PYOVERSIZE
write_checksum_manifest
if sh "$control_root/tools/largefile_service_evidence_check.sh" "$out" "$build" > "$tmp/oversize.out" 2> "$tmp/oversize.err"; then
    echo 'service verifier accepted the wrong oversized rejection reason' >&2
    exit 1
fi
grep -F 'exact MaxFileSize reason' "$tmp/oversize.err" >/dev/null
cp "$tmp/oversize.good" "$out/reports/oversize-fildesreport.json"
write_checksum_manifest
cp "$workload_results" "$tmp/workloads.good"
sed '/^oversize-fildesreport/d' "$tmp/workloads.good" > "$workload_results"
new_workload_hash=$(sha256sum "$workload_results" | awk '{ print $1 }')
cp "$out/oracle-binding.txt" "$tmp/oracle-binding.good"
sed "s/^workload_results_sha256=.*/workload_results_sha256=$new_workload_hash/" \
    "$tmp/oracle-binding.good" > "$out/oracle-binding.txt"
write_checksum_manifest
if sh "$control_root/tools/largefile_service_evidence_check.sh" "$out" "$build" > "$tmp/oversize.out" 2> "$tmp/oversize.err"; then
    echo 'service verifier accepted a missing oversized rejection workload' >&2
    exit 1
fi
grep -F 'missing required records: oversize-fildesreport' "$tmp/oversize.err" >/dev/null
cp "$tmp/workloads.good" "$workload_results"
cp "$tmp/oracle-binding.good" "$out/oracle-binding.txt"
write_checksum_manifest

cp "$out/logs/milter-exact-edge.log" "$tmp/milter-exact-edge.good"
sed 's/7ec57c684966d38ba3db215be49cffa732317898dc8868439be681ba6ed6d50e/0000000000000000000000000000000000000000000000000000000000000000/' \
    "$tmp/milter-exact-edge.good" > "$out/logs/milter-exact-edge.log"
write_checksum_manifest
if sh "$control_root/tools/largefile_service_evidence_check.sh" "$out" "$build" >/dev/null 2>&1; then
    echo 'service evidence verifier accepted a non-oracle milter stream digest' >&2
    exit 1
fi
cp "$tmp/milter-exact-edge.good" "$out/logs/milter-exact-edge.log"

sed 's/skipped_operations=0/skipped_operations=1/' \
    "$tmp/milter-exact-edge.good" > "$out/logs/milter-exact-edge.log"
write_checksum_manifest
if sh "$control_root/tools/largefile_service_evidence_check.sh" "$out" "$build" >/dev/null 2>&1; then
    echo 'service evidence verifier accepted a milter workload with a skipped operation' >&2
    exit 1
fi
cp "$tmp/milter-exact-edge.good" "$out/logs/milter-exact-edge.log"
write_checksum_manifest

cp "$loaded_dependencies" "$tmp/loaded-dependencies.good"
cp "$out/provenance/service-build-identity.txt" "$tmp/service-build-identity.loader-good"
python3 - "$loaded_dependencies" "$tmp/loaded-dependencies.external" <<'PY'
from pathlib import Path
import sys

source, destination = map(Path, sys.argv[1:])
contents = source.read_text(encoding="utf-8")
contents = contents.replace(
    "artifacts/service-runtime-components/libclamav.so",
    "external/libclamav.so",
)
destination.write_text(contents, encoding="utf-8")
PY
mv "$tmp/loaded-dependencies.external" "$loaded_dependencies"
new_loaded_dependencies_sha256=$(sha256sum "$loaded_dependencies" | awk '{ print $1 }')
sed "s#^service_loaded_dependencies_sha256=.*#service_loaded_dependencies_sha256=$new_loaded_dependencies_sha256#" \
    "$tmp/service-build-identity.loader-good" > "$out/provenance/service-build-identity.txt"
write_checksum_manifest
if sh "$control_root/tools/largefile_service_evidence_check.sh" "$out" "$build" >/dev/null 2>&1; then
    echo 'service evidence verifier accepted a loader record outside the copied runtime directory' >&2
    exit 1
fi
mv "$tmp/loaded-dependencies.good" "$loaded_dependencies"
mv "$tmp/service-build-identity.loader-good" "$out/provenance/service-build-identity.txt"
write_checksum_manifest

cp "$parallel_profile" "$tmp/parallel-profile.good"
sed 's/^MaxThreads 1$/MaxThreads 4/' "$tmp/parallel-profile.good" > "$parallel_profile"
write_checksum_manifest
if sh "$control_root/tools/largefile_service_evidence_check.sh" "$out" "$build" >/dev/null 2>&1; then
    echo 'service evidence verifier accepted a multi-worker parallel stress profile' >&2
    exit 1
fi
mv "$tmp/parallel-profile.good" "$parallel_profile"
write_checksum_manifest

wrong_interpreter=$(CDPATH= cd -- "$tmp" && pwd)/ld-linux-other-synthetic.so
printf 'other synthetic ELF interpreter\n' > "$wrong_interpreter"
cp "$build/clamscan/clamscan" "$tmp/clamscan.good"
cp "$binary_list" "$tmp/binary-list.good"
cp "$binary_after" "$tmp/binary-after.good"
cp "$out/provenance/service-build-identity.txt" "$tmp/service-build-identity.good"
write_synthetic_elf "$build/clamscan/clamscan" "$wrong_interpreter"
new_binary_hash=$(sha256sum "$build/clamscan/clamscan" | awk '{ print $1 }')
tab=$(printf '\t')
sed "s#^clamscan/clamscan${tab}.*#clamscan/clamscan${tab}$new_binary_hash#" \
    "$tmp/binary-list.good" > "$binary_list"
cp "$binary_list" "$binary_after"
new_binary_hashes_sha256=$(sha256sum "$binary_list" | awk '{ print $1 }')
sed "s#^service_binary_hashes_sha256=.*#service_binary_hashes_sha256=$new_binary_hashes_sha256#" \
    "$tmp/service-build-identity.good" > "$out/provenance/service-build-identity.txt"
write_checksum_manifest
if sh "$control_root/tools/largefile_service_evidence_check.sh" "$out" "$build" >/dev/null 2>&1; then
    echo 'service evidence verifier accepted a service ELF PT_INTERP mismatch' >&2
    exit 1
fi
mv "$tmp/clamscan.good" "$build/clamscan/clamscan"
mv "$tmp/binary-list.good" "$binary_list"
mv "$tmp/binary-after.good" "$binary_after"
mv "$tmp/service-build-identity.good" "$out/provenance/service-build-identity.txt"
write_checksum_manifest

printf '%s\n' 'tampered dependency manifest' > "$dependency_hashes_after"
if sh "$control_root/tools/largefile_service_evidence_check.sh" "$out" "$build" >/dev/null 2>&1; then
    echo 'service evidence verifier accepted changed runtime dependency evidence' >&2
    exit 1
fi
cp "$dependency_hashes" "$dependency_hashes_after"

cp "$interpreter_records" "$out/provenance/service-interpreter-records.good"
sed 's#\([0-9a-fA-F]\{64\}\)$#0000000000000000000000000000000000000000000000000000000000000000#' \
    "$out/provenance/service-interpreter-records.good" > "$interpreter_records"
if sh "$control_root/tools/largefile_service_evidence_check.sh" "$out" "$build" >/dev/null 2>&1; then
    echo 'service evidence verifier accepted a tampered ELF interpreter record' >&2
    exit 1
fi
mv "$out/provenance/service-interpreter-records.good" "$interpreter_records"

python3 - "$qualification_oracle" "$tmp/invalid-oracle.tsv" <<'PY'
from pathlib import Path
import sys

source, destination = map(Path, sys.argv[1:])
contents = source.read_text(encoding="utf-8")
contents = contents.replace(
    "\tCOMPLETE\t-\t-\tCL_TYPE_DATA",
    "\tCOMPLETE\t-\t1\tCL_TYPE_DATA",
    1,
)
destination.write_text(contents, encoding="utf-8")
PY
if ! python3 - "$root" "$tmp/invalid-oracle.tsv" <<'PY'
import sys

sys.path.insert(0, sys.argv[1] + "/tools")
from largefile_clamd_report_protocol import load_oracle

try:
    load_oracle(sys.argv[2], "production")
except RuntimeError:
    pass
else:
    raise SystemExit("direct clamd report probe accepted a malformed oracle")
PY
then
    echo 'direct clamd report probe accepted a malformed oracle' >&2
    exit 1
fi

cp "$out/reports/edge-clamscan.jsonl" "$out/reports/edge-clamscan.good"
sed 's/"verdict":2/"verdict":0/' "$out/reports/edge-clamscan.good" > \
    "$out/reports/edge-clamscan.jsonl"
if python3 "$control_root/tools/largefile_service_workload_check.py" "$out" >/dev/null 2>&1; then
    echo 'service workload verifier accepted a detection report with a clean verdict' >&2
    exit 1
fi
mv "$out/reports/edge-clamscan.good" "$out/reports/edge-clamscan.jsonl"

cp "$out/reports/edge-clamscan.jsonl" "$out/reports/edge-clamscan.good"
sed 's/"last_alert_offset":123/"last_alert_offset":122/' "$out/reports/edge-clamscan.good" > \
    "$out/reports/edge-clamscan.jsonl"
if python3 "$control_root/tools/largefile_service_workload_check.py" "$out" >/dev/null 2>&1; then
    echo 'service workload verifier accepted a mismatched detection offset' >&2
    exit 1
fi
mv "$out/reports/edge-clamscan.good" "$out/reports/edge-clamscan.jsonl"

printf '%s' "$report_json" > "$out/reports/production_cvd_scanreport.jsonl"
printf 'mutated structured report\n' >> "$out/reports/production_cvd_scanreport.jsonl"
if python3 "$control_root/tools/largefile_service_workload_check.py" "$out" >/dev/null 2>&1; then
    echo 'service workload verifier accepted a mutated structured report' >&2
    exit 1
fi
printf '%s' "$report_json" > "$out/reports/production_cvd_scanreport.jsonl"
printf 'mutated workload input\n' >> "$workload_input"
if python3 "$control_root/tools/largefile_service_workload_check.py" "$out" >/dev/null 2>&1; then
    echo 'service workload verifier accepted a mutated input' >&2
    exit 1
fi

printf 'mutated after qualification\n' >> "$build/clamscan/clamscan"
if sh "$control_root/tools/largefile_service_evidence_check.sh" "$out" "$build" >/dev/null 2>&1; then
    echo 'service evidence verifier accepted a mutated service executable' >&2
    exit 1
fi

grep -F 'largefile_service_evidence_check.sh' "$root/.github/workflows/cmake.yml" >/dev/null
echo 'service runtime evidence verifier regression passed'
