#!/bin/sh

# Exercise the no-build qualification orchestrator with a deterministic scanner
# stub. This validates evidence binding and rejection logic, not ClamAV itself.

set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/clamav-pdf-qualification.XXXXXX")
cleanup()
{
    status=$?
    trap - EXIT HUP INT TERM
    if [ "$status" -ne 0 ] && [ -f "$work/qualification.log" ]; then
        cat "$work/qualification.log" >&2
    fi
    rm -rf "$work"
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$work/database"
printf 'stub database\n' > "$work/database/stub.cvd"

stub=$work/clamscan
cat > "$stub.c" <<'STUB'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    const char *input   = NULL;
    const char *tempdir = NULL;
    const char *report  = NULL;
    const char *mode    = getenv("PDF_STUB_MODE");
    int i;

    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        puts("ClamAV qualification scanner stub 1");
        return 0;
    }
    for (i = 1; i < argc; i++) {
        size_t length = strlen(argv[i]);
        if (length >= 4 && strcmp(argv[i] + length - 4, ".pdf") == 0)
            input = argv[i];
        if (strncmp(argv[i], "--tempdir=", 10) == 0)
            tempdir = argv[i] + 10;
        if (strncmp(argv[i], "--report-json=", 14) == 0)
            report = argv[i] + 14;
    }
    if (input == NULL || tempdir == NULL || report == NULL)
        return 2;

    puts("pdf_extract_obj: Found /Type/ObjStm");
    if (strstr(input, "rc4-") != NULL) {
        puts("check_user_password: encrypted PDF found, user password is empty, will attempt to decrypt");
        puts("pdf_stream_decrypt_reader: decrypting RC4 stream in bounded windows");
    }
    if (strstr(input, "aesv2-") != NULL) {
        puts("check_user_password: encrypted PDF found, user password is empty, will attempt to decrypt");
        puts("pdf_stream_decrypt_reader: decrypting AESV2 stream in bounded CBC blocks");
    }
    if (strstr(input, "aesv3-") != NULL) {
        puts("check_user_password: encrypted PDF found, user password is empty, will attempt to decrypt");
        puts("pdf_stream_decrypt_reader: decrypting AESV3 stream in bounded CBC blocks");
    }
    if (strstr(input, "password-") != NULL) {
        FILE *json;
        puts("check_owner_password: encrypted PDF found but cannot decrypt with empty owner password");
        puts("check_user_password: encrypted PDF found, user password is NOT empty, cannot decrypt!");
        puts("pdf_find_and_extract_objs: encrypted pdf found, not decryptable, stream will probably fail to decompress!");
        puts("PDF object-stream parsing did not complete");
        json = fopen(report, "wb");
        if (json == NULL)
            return 2;
        fprintf(json,
                "{\"version\":1,\"status\":30,\"verdict\":0,"
                "\"completion\":\"UNSUPPORTED\",\"target\":\"%s\","
                "\"reason\":\"PDF encrypted stream uses unsupported encryption or has no usable key\","
                "\"skipped_operations\":1}\n",
                input);
        if (fclose(json) != 0)
            return 2;
        return 2;
    }
    if (strstr(input, "fault-bad-cfm") != NULL) {
        FILE *json;
        puts("check_user_password: encrypted PDF found, user password is empty, will attempt to decrypt");
        puts("parse_enc_method: StdCF CFM: Bogus");
        puts("PDF object-stream parsing did not complete");
        json = fopen(report, "wb");
        if (json == NULL)
            return 2;
        fprintf(json,
                "{\"version\":1,\"status\":30,\"verdict\":0,"
                "\"completion\":\"UNSUPPORTED\",\"target\":\"%s\","
                "\"reason\":\"PDF encrypted stream uses unsupported encryption or has no usable key\","
                "\"skipped_operations\":1}\n",
                input);
        if (fclose(json) != 0)
            return 2;
        return 2;
    }
    if (strstr(input, "fault-duplicate-filter") != NULL ||
        strstr(input, "fault-scalar-filter") != NULL ||
        strstr(input, "fault-missing-filter") != NULL ||
        strstr(input, "fault-missing-cfm") != NULL ||
        strstr(input, "fault-duplicate-cfm") != NULL ||
        strstr(input, "fault-scalar-cfm") != NULL) {
        FILE *json;
        puts("check_user_password: encrypted PDF found, user password is empty, will attempt to decrypt");
        puts("PDF object-stream parsing did not complete");
        json = fopen(report, "wb");
        if (json == NULL)
            return 2;
        fprintf(json,
                "{\"version\":1,\"status\":30,\"verdict\":0,"
                "\"completion\":\"UNSUPPORTED\",\"target\":\"%s\","
                "\"reason\":\"PDF encrypted stream uses unsupported encryption or has no usable key\","
                "\"skipped_operations\":1}\n",
                input);
        if (fclose(json) != 0)
            return 2;
        return 2;
    }
    if (strstr(input, "fault-truncated-ciphertext") != NULL ||
        strstr(input, "fault-bad-padding") != NULL) {
        const char *reason = strstr(input, "fault-truncated-ciphertext") != NULL
                                 ? "PDF AES stream has an invalid IV or ciphertext length"
                                 : "PDF AES stream has invalid PKCS#7 padding";
        FILE *json;
        puts("check_user_password: encrypted PDF found, user password is empty, will attempt to decrypt");
        puts("pdf_stream_decrypt_reader: decrypting AESV2 stream in bounded CBC blocks");
        puts(reason);
        puts("PDF object-stream parsing did not complete");
        json = fopen(report, "wb");
        if (json == NULL)
            return 2;
        fprintf(json,
                "{\"version\":1,\"status\":24,\"verdict\":0,"
                "\"completion\":\"MALFORMED_CONFIRMED\",\"target\":\"%s\","
                "\"reason\":\"%s\",\"skipped_operations\":1}\n",
                input, reason);
        if (fclose(json) != 0)
            return 2;
        return 2;
    }
    if (mode != NULL && strcmp(mode, "reject") == 0) {
        char path[4096];
        FILE *leak;
        if (snprintf(path, sizeof(path), "%s/leaked-child", tempdir) < 0)
            return 2;
        leak = fopen(path, "wb");
        if (leak == NULL)
            return 2;
        fclose(leak);
    } else {
        puts("pdf_objstm_attach_file: retained 1-byte quota-accounted file-backed object stream");
    }
    puts("pdf_find_and_parse_objs_in_objstm: Found object 5 0 in object stream at offset: 1");
    if (strstr(input, "malformed.pdf") != NULL)
        puts("PDF object-stream parsing did not complete");
    puts("pdf_objstm_cleanup: releasing 1-byte file-backed object stream");
    printf("%s: LargeFile.PDF.ObjStm.Tail.UNOFFICIAL FOUND\n", input);
    {
        FILE *json = fopen(report, "wb");
        if (json == NULL)
            return 2;
        fprintf(json,
                "{\"version\":1,\"status\":0,\"verdict\":2,"
                "\"completion\":\"DETECTION_TERMINATED\","
                "\"target\":\"%s\",\"skipped_operations\":0}\n",
                input);
        if (fclose(json) != 0)
            return 2;
    }
    return (mode != NULL && strcmp(mode, "reject") == 0) ? 0 : 1;
}
STUB
gcc -O2 -o "$stub" "$stub.c"

"$root/tools/largefile_pdf_objstm_qualification.sh" \
    "$stub" "$work/database" "$work/evidence" 67108864 41943040 \
    > "$work/qualification.log" 2>&1

[ "$(awk -F '\t' 'NR > 1 && $11 == "pass" { count++ } END { print count + 0 }' \
    "$work/evidence/results.tsv")" -eq 26 ]
awk -F '\t' 'NR > 1 && $1 == "materialized" { found = 1; if ($11 < $9) exit 1 } END { exit !found }' \
    "$work/evidence/corpus-manifest.tsv"
grep -F 'PDF object-stream qualification passed' "$work/qualification.log" >/dev/null
grep -F 'qualification_status=pass' "$work/evidence/evidence-metadata.txt" >/dev/null
grep -E '^database_manifest_sha256=[0-9a-f]{64}$' "$work/evidence/evidence-metadata.txt" >/dev/null
source_status=$(sed -n 's/^source_tree_status=//p' "$work/evidence/evidence-metadata.txt")
if [ "$source_status" = clean ]; then
    python3 "$root/tools/largefile_pdf_objstm_evidence_check.py" \
        "$work/evidence" > "$work/evidence-check.log"
else
    python3 "$root/tools/largefile_pdf_objstm_evidence_check.py" \
        --allow-dirty-source "$work/evidence" > "$work/evidence-check.log"
fi
cp "$work/evidence/evidence-metadata.txt" "$work/evidence-metadata.clean"
sed 's/^source_tree_status=.*/source_tree_status=dirty-manifest-bound/' \
    "$work/evidence-metadata.clean" > "$work/evidence/evidence-metadata.txt"
if python3 "$root/tools/largefile_pdf_objstm_evidence_check.py" \
    "$work/evidence" > "$work/dirty-source-check.log" 2>&1; then
    echo 'evidence checker accepted dirty release source without an explicit test override' >&2
    exit 1
fi
cp "$work/evidence-metadata.clean" "$work/evidence/evidence-metadata.txt"
printf 'unbound\n' > "$work/evidence/provenance/unbound.txt"
if python3 "$root/tools/largefile_pdf_objstm_evidence_check.py" \
    --allow-dirty-source "$work/evidence" > "$work/unbound-check.log" 2>&1; then
    echo 'evidence checker accepted an unbound provenance artifact' >&2
    exit 1
fi
rm "$work/evidence/provenance/unbound.txt"
cp "$work/evidence/reports/password-aesv3.jsonl" "$work/password-aesv3-report.clean"
printf '{"unbound":true}\n' > "$work/evidence/reports/password-aesv3.jsonl"
if python3 "$root/tools/largefile_pdf_objstm_evidence_check.py" \
    --allow-dirty-source "$work/evidence" > "$work/tampered-report-check.log" 2>&1; then
    echo 'evidence checker accepted a modified structured report' >&2
    exit 1
fi
cp "$work/password-aesv3-report.clean" "$work/evidence/reports/password-aesv3.jsonl"
printf 'tampered\n' >> "$work/evidence/logs/raw.log"
if python3 "$root/tools/largefile_pdf_objstm_evidence_check.py" \
    --allow-dirty-source "$work/evidence" > "$work/tampered-check.log" 2>&1; then
    echo 'evidence checker accepted a modified scanner log' >&2
    exit 1
fi

if PDF_STUB_MODE=reject "$root/tools/largefile_pdf_objstm_qualification.sh" \
    "$stub" "$work/database" "$work/rejected-evidence" 67108864 41943040 \
    > "$work/rejected.log" 2>&1; then
    echo 'qualification accepted false-clean, unmapped, residue-bearing evidence' >&2
    exit 1
fi
grep -F 'PDF object-stream qualification failed' "$work/rejected.log" >/dev/null

echo 'PDF object-stream qualification orchestrator test passed'
