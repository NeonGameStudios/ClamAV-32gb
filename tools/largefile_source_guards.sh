#!/bin/sh

# Source-level regression guards for the large-file audit fixes. These checks
# intentionally require no compiler, scanner binary, or generated build tree.

set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)

contains() {
    file=$1
    text=$2
    if ! grep -F "$text" "$root/$file" >/dev/null 2>&1; then
        echo "large-file source guard failed: $file does not contain: $text" >&2
        exit 1
    fi
}

not_contains() {
    file=$1
    text=$2
    if grep -F "$text" "$root/$file" >/dev/null 2>&1; then
        echo "large-file source guard failed: $file still contains: $text" >&2
        exit 1
    fi
}

if grep -E '^[[:space:]]*uses:[[:space:]]*[^#[:space:]]+@[^0-9a-f]|^[[:space:]]*uses:[[:space:]]*[^#[:space:]]+@[0-9a-f]{1,39}([[:space:]#]|$)' \
    "$root/.github/workflows/cmake.yml" >/dev/null 2>&1; then
    echo 'large-file source guard failed: workflow action is not pinned to an immutable 40-character commit' >&2
    exit 1
fi

contains libclamav/matcher-bm.c 'sizeof(uint64_t), cli_bm_uint64_cmp'
contains libclamav/matcher.h 'CLI_OFF_ANY64'
contains libclamav/matcher.h 'CLI_OFF_NONE64'
contains libclamav/matcher-hash.c 'size >= UINT32_MAX'
contains clamav-milter/clamfi.c 'uint64_t totsz;'
contains clamav-milter/clamfi.c 'unsigned int stream_started;'
contains clamav-milter/clamfi.c 'unsigned int over_limit;'
contains clamav-milter/clamfi.c 'Message exceeds MaxFileSize; refusing a partial scan'
contains clamav-milter/clamfi.c 'clamfi_quota_add(cf->totsz, maxfilesize, len, &next_size)'
not_contains clamav-milter/clamfi.c 'len = (size_t)(maxfilesize - cf->totsz)'
contains clamav-milter/clamfi_quota.c 'configured = CLI_MAX_LARGE_FILESIZE;'
contains clamav-milter/clamfi_quota.c 'requested64 > UINT64_MAX - current'
contains clamav-milter/clamav-milter.c 'clamfi_normalize_maxfilesize'
contains unit_tests/CMakeLists.txt 'add_test(NAME clamav_milter_quota COMMAND check_clamfi_quota)'
contains common/clamdcom.c 'return send_stream_fd_common(sockd, fd, display_filename, clamdopts, true);'
not_contains common/clamdcom.c 'return send_stream_fd_common(sockd, fd, display_filename, clamdopts, false);'
contains libclamav/scanners.c 'ctx->scan_incomplete'
contains libclamav/scanners.c 'status = CL_EMAXSIZE;'
contains libclamav/scanners.c '*result_out = CL_ETIMEOUT;'
contains libclamav/scanners.c 'emax_reached(ctx);'
contains libclamav/scanners.c 'nested fmap range is outside the containing map'
contains libclamav/scanners.c 'nested fmap could not be read completely while forcing it to disk'
contains libclamav/scanners.c 'while (copied < length)'
not_contains libclamav/scanners.c 'mapdata = fmap_need_off_once_len(map, offset, length'
contains unit_tests/check_clamav.c 'test_nested_fmap_ranges_and_force_to_disk_are_fail_visible'
contains libclamav/matcher.c 'cli_pcre_check_size_limit(ctx, maxfilesize, map->len)'
contains libclamav/matcher.c 'effective_limit > (uint64_t)CLI_MAX_ALLOCATION'
contains libclamav/matcher.c 'PCRE signatures require an oversized contiguous subject'
contains libclamav/others.c 'cli_validate_pcre_maxfilesize'
contains libclamav/others.c '*validated = (uint64_t)CLI_MAX_ALLOCATION;'
contains libclamav/scanners.c 'legacy file-inspection callback requires an oversized contiguous buffer'
contains libclamav/scanners.c 'image fuzzy hash requires an oversized contiguous buffer'
contains libclamav/scanners.c 'fmap_unneed_off(ctx->fmap, 0, image_size);'
contains libclamav/cache.c 'uint64_t size;'
contains libclamav/cache.c 'static inline int cmp(int64_t *a, uint64_t sa, int64_t *b, uint64_t sb)'
contains libclamav/others.h 'uint64_t size; /* A size of zero means size is unavailable'
contains libclamav/stats_json.c 'snprintf(md5, sizeof(md5), STDu64, sample->size);'
contains unit_tests/check_clamav.c 'test_clean_cache_distinguishes_large_sizes'
contains unit_tests/check_clamav.c 'test_stats_preserves_large_sample_size'
contains unit_tests/check_clamav.c 'test_top_level_maxfilesize_is_fail_visible'
contains unit_tests/check_clamav.c 'test_top_level_maxfilesize_descriptor_is_fail_visible'
contains unit_tests/check_clamav.c 'test_timeout_policy_is_fail_visible'
contains unit_tests/check_matchers.c 'test_pcre_subject_limit_is_fail_visible'
contains libclamav/bytecode.c 'no applicable bytecode registered for hook'
contains unit_tests/check_bytecode.c 'test_bytecode_large_map_hook_gates_only_applicable_bytecode'
not_contains common/optparser.c 'Setting this value to zero disables the limit.'
not_contains etc/clamd.conf.sample 'Setting this value to zero disables the limit.'
not_contains docs/man/clamd.conf.5.in 'Setting this value to zero disables the limit.'
not_contains win32/conf_examples/clamd.conf.sample 'Setting this value to zero disables the limit.'
contains libclamav/scanners.c 'VBA decompressed content exceeds the legacy matcher ABI'
contains libclamav/ole2_extract.c 'OLE2 sector chain exceeds the deep-parser ABI'
contains libclamav/libmspack.c 'refusing to scan partial member'
contains libclamav/libmspack.c 'limit_exceeded'
contains libclamav/libmspack.c 'Unlimited still means that the bytes must actually be written.'
contains libclamav/libmspack.c 'max_size = (uint64_t)bytes;'
not_contains libclamav/libmspack.c 'return bytes;'
contains libclamav/ishield.c 'InstallShield MSI member output exceeds configured scan limits'
contains libclamav/ishield.c 'InstallShield CAB output size disagrees with member metadata'
contains libclamav/ishield.c 'Only pin the structure currently being read.'
not_contains libclamav/ishield.c 'fmap_need_off(map, c->hdr, c->hdrsz)'
contains unit_tests/check_clamav.c 'test_ishield_msi_partial_limit_and_decode_failures_are_visible'
contains libclammspack/mspack/cabd.c 'report an error even in salvage mode'
contains libclamav/unzip.c 'ZIP_EOCD_MAX_SEARCH_SIZE'
contains libclamav/unzip.c 'ZIP_MAGIC_ZIP64_END'
contains libclamav/unzip.c 'struct zip_central_values {'
contains libclamav/unzip.c 'uint64_t compressed_size;'
contains libclamav/unzip.c 'ALG_DEFLATE64 == method || ALG_BZIP2 == method'
contains libclamav/unzip.c 'strm.state == EXPLODE'
contains libclamav/unzip.c 'output_crc32 != expected_crc32'
contains libclamav/unzip.c 'ZIP encrypted member could not be decrypted with a configured password'
contains libclamav/unzip.c 'ZIP compression method is unsupported by a bounded decoder'
contains libclamav/unzip.c 'if (ctx->scan_incomplete) {'
contains libclamav/unzip.c 'Preserve fallback failures such as timeout and allocation errors.'
contains libclamav/unzip.c 'ret = zip_input_refill(&input, &data, &length);'
contains libclamav/unzip.c 'status = unz_from_fmap('
not_contains libclamav/unzip.c 'compressed_data = fmap_need_off_once('
not_contains libclamav/unzip.c 'fmap_need_ptr_once(ctx->fmap, zip, csize)'
contains libclamav/unzip.c 'ZIP local header could not be mapped for decryption'
contains libclamav/unzip.c 'ZIP member extraction or scanning failed'
contains libclamav/scanners.c 'Re-apply the invariant to the final return value.'
contains libclamav/xdp.h 'XDP_DEEP_PARSE_MAX_SIZE'
contains libclamav/xdp.c 'xmlReaderForIO(msxml_read_cb'
contains libclamav/xdp.c 'XDP layer exceeds the 64 MiB libxml2 deep-parser limit'
not_contains libclamav/xdp.c 'xmlReaderForMemory('
not_contains libclamav/xdp.c 'fmap_need_off_once(ctx->fmap, 0, ctx->fmap->len)'
contains libclamav/hwp.h 'HWPML_BASE64_IO_SIZE 16381'
contains libclamav/hwp.c 'cli_hwpml_decode_base64_fd'
contains libclamav/hwp.c 'HWPML layer exceeds the 64 MiB libxml2 deep-parser limit'
not_contains libclamav/hwp.c 'fmap_need_off_once(input, 0, input->len)'
contains libclamav/pdf.h 'PDF_DEEP_PARSE_MAX_SIZE'
contains libclamav/pdf.c 'PDF layer exceeds the 64 MiB legacy deep-parser limit'
contains libclamav/pdf.c 'fmap_readn(map, pdf_input + copied'
not_contains libclamav/pdf.c 'fmap_need_off(map, offset, size)'
contains unit_tests/check_clamav.c 'test_large_document_parser_caps_are_fail_visible'
contains unit_tests/check_clamav.c 'test_hwpml_base64_decoder_is_bounded_and_fail_visible'
contains libclamav/dmg.h 'DMG_XML_PARSE_MAX_SIZE'
contains libclamav/dmg.c 'xmlReaderForIO(dmg_xml_read_cb'
contains libclamav/dmg.c 'DMG deflate stripe output does not match its declared sector count'
contains libclamav/dmg.c 'DMG bzip2 stripe did not reach stream completion'
contains libclamav/dmg.c 'DMG contains invalid or unsupported non-empty stripe metadata'
contains libclamav/dmg.c 'hdr.dataForkOffset, hdr.dataForkLength'
contains libclamav/dmg.c 'mish_set->mish->dataOffset + blocklist[i].dataOffset'
contains libclamav/dmg.c 'DMG stripe geometry has a gap, overlap, or out-of-range sector span'
contains libclamav/dmg.c 'multi-segment DMG images require data from another file'
contains libclamav/dmg.c 'DMG XML parsing reached the configured time limit'
contains libclamav/dmg.c 'contains invalid Base64 syntax'
contains libclamav/dmg.c 'has no terminal END stripe'
not_contains libclamav/dmg.c 'xmlReaderForMemory('
not_contains libclamav/dmg.c 'strm.next_in = (void *)fmap_need_off_once(ctx->fmap, off, len)'
contains unit_tests/check_clamav.c 'test_dmg_malformed_metadata_is_fail_visible'
contains unit_tests/check_clamav.c 'test_dmg_xml_limit_is_fail_visible_without_materializing_payload'
contains unit_tests/check_clamav.c 'test_dmg_strict_base64_and_terminal_end_validation'
contains libclamav/asn1.h 'size_t offset;'
contains libclamav/asn1.h 'size_t size;'
contains libclamav/asn1.c 'cli_hash_mapped_regions('
contains libclamav/asn1.c 'CLI_AUTHENTICODE_HASH_CHUNK_SIZE'
contains libclamav/asn1.c 'Authenticode hash region could not be read completely'
not_contains libclamav/asn1.c 'fmap_need_off_once(map, regions[i].offset, regions[i].size)'
contains libclamav/pe.c 'ret = cli_hash_mapped_regions(map, hashctx, regions, nregions, ctx);'
contains libclamav/pe.c 'status = cli_hash_mapped_regions(ctx->fmap, hash_ctx, &region, 1, ctx);'
not_contains libclamav/pe.c 's->rsz > CLI_MAX_ALLOCATION'
contains libclamav/execs.h 'size_t overlay_start;'
contains libclamav/execs.h 'size_t overlay_size;'
contains libclamav/pe.c 'PE bytecode overlay metadata requires 32-bit coordinates'
contains libclamav/pe.c 'cli_pe_calculate_overlay_range('
contains unit_tests/check_clamav.c 'test_authenticode_hash_regions_are_native_and_bounded'
contains unit_tests/check_clamav.c 'test_authenticode_hash_failure_is_fail_visible'
contains unit_tests/check_clamav.c 'test_pe_overlay_range_preserves_native_size'
contains libclamav/udf.c 'UDF_COPY_CHUNK_SIZE'
contains libclamav/udf.c 'UDF file extent exceeds configured scan limits'
not_contains libclamav/udf.c 'fmap_need_off(ctx->fmap, offset, length)'
contains libclamav/gpt.c 'gpt_crc32_fmap'
contains libclamav/gpt.c 'GPT partition count exceeds the configured inspection limit'
not_contains libclamav/gpt.c 'fmap_need_off_once(ctx->fmap, ptable_start, ptable_len)'
contains libclamav/autoit.c 'bb == 0 || bb > UNP.cur_output'
contains libclamav/autoit.c 'chars > UINT32_MAX / 2'
contains libclamav/autoit.c 'AutoIt EA06 script decompilation was incomplete'
not_contains libclamav/autoit.c 'return CL_VIRUS;'
contains libclamav/xar.c 'XAR_TOC_DEEP_PARSE_MAX_SIZE'
contains libclamav/xar.c 'XAR gzip member ended before the decoder reached stream end'
not_contains libclamav/xar.c 'writelen = MIN((size_t)(ctx->engine->maxfilesize), writelen)'
contains libclamav/nsis/nulsft.c 'NSIS_CONTIGUOUS_INPUT_MAX'
contains libclamav/nsis/nulsft.c 'NSIS decompression produced only a partial member'
not_contains libclamav/nsis/nulsft.c 'ret = nsist.solid ? CL_BREAK : CL_SUCCESS'
contains libclamav/egg.c 'compressedDataOffset'
contains libclamav/egg.c 'block exceeds the bounded contiguous decoder limit'
contains libclamav/scanners.c 'EGG member extraction failed before content scanning'
contains libclamav/blob.c 'overlap adjacent windows'
contains libclamav/blob.c 'deferring early scan to preserve multipart/logical matcher state'
contains libclamav/matcher-byte-comp.c 'buffer_offset'
contains libclamav_rust/src/sys.rs 'filesize_range: *mut u64'
contains libclamav_rust/build.rs '.layout_tests(true)'
contains tools/largefile_poc.sh 'row_signature='
contains tools/largefile_poc_fail_closed_test.sh 'positive scanner stub'
contains tools/largefile_runtime_gate.sh 'runtime-gate requires Linux x86-64'
contains tools/largefile_runtime_gate.sh 'CLAMAV_SANITIZER_CLAMSCAN'
contains tools/largefile_runtime_gate.sh 'policy_32g_plus_one'
contains tools/largefile_runtime_gate.sh 'cancellation=pass'
contains tools/largefile_runtime_gate.sh 'CLAMAV_CONCURRENCY_FILE:-32g-edge.bin'
contains tools/largefile_runtime_gate.sh 'CLAMAV_MIN_AVAILABLE_KB'
contains tools/largefile_runtime_gate.sh 'host preflight failed'
contains tools/largefile_runtime_gate.sh 'runtime_gate=pass'
contains tools/largefile_host_preflight.sh 'memory_total_kb='
contains tools/largefile_host_preflight.sh 'cgroup_memory_limit_bytes='
contains tools/largefile_host_preflight.sh 'effective_memory_available_kb='
contains .github/workflows/cmake.yml 'min_available_kb:'
contains .github/workflows/cmake.yml 'CLAMAV_MIN_AVAILABLE_KB'
contains .github/workflows/cmake.yml 'build-largefile/clamscan/clamscan'
contains .github/workflows/cmake.yml 'build-sanitizer/clamscan/clamscan'
contains .github/workflows/cmake.yml 'clamav-largefile-64gb'
contains .github/workflows/cmake.yml 'actions/attest-build-provenance@e8998f949152b193b063cb0ec769d69d929409be'
contains tools/largefile_runtime_gate.sh 'source_commit='
contains tools/largefile_runtime_gate.sh 'SHA256SUMS'
contains tools/largefile_runtime_evidence_check.sh 'sha256sum -c'
contains CMakeLists.txt 'does not support native Windows'
contains tools/largefile_runtime_evidence_check.sh 'large-file runtime evidence verified'
contains tools/largefile_runtime_evidence_check.sh 'POC results do not contain eleven passing exact-size/offset rows'
contains tools/largefile_runtime_evidence_check.sh 'runtime gate does not have an explicit pass marker'
contains tools/largefile_boundary_corpus.sh 'make_marker 4g-minus-two 4294967294'
contains tools/largefile_runtime_evidence_check.sh '32g-edge.bin'
contains tools/largefile_runtime_evidence_check.sh 'host preflight does not record total memory'
contains tools/largefile_runtime_evidence_check.sh '$10 != off[row]'
contains tools/largefile_runtime_evidence_check.sh 'worker-$worker.rss-kb'
contains tools/largefile_runtime_evidence_check_test.sh 'evidence checker accepted a wrong numeric engine offset'
contains tools/largefile_runtime_evidence_check_test.sh 'evidence checker accepted an RSS record that disagrees with the worker log'
contains common/optparser.c 'MaxFileSize cannot exceed 32G in this build'
contains CMakeLists.txt 'CLAMAV_LARGE_FILE_SUPPORT 1'

if grep -F 'Technical design limitations prevent ClamAV from scanning files greater than' "$root/etc/clamd.conf.sample" >/dev/null 2>&1; then
    echo 'large-file source guard failed: stale clamd.conf size limit documentation' >&2
    exit 1
fi

awk -F '\t' '
    NR == 1 { next }
    $2 ~ /^\.\// { exit 1 }
    seen[$0]++
    END {
        for (row in seen)
            if (seen[row] != 1)
                exit 2
    }
' "$root/docs/largefile-inventory.tsv"

echo 'large-file source guards passed'
