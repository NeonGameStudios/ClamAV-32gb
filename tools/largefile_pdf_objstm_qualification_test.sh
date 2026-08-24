#!/bin/sh

# Exercise the no-build qualification orchestrator with a deterministic scanner
# stub. This validates evidence binding and rejection logic, not ClamAV itself.

set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/clamav-pdf-qualification.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM

mkdir -p "$work/database"
printf 'stub database\n' > "$work/database/stub.cvd"

stub=$work/clamscan
cat > "$stub" <<'STUB'
#!/bin/sh
input=
tempdir=
for argument in "$@"; do
    case "$argument" in
        *.pdf) input=$argument ;;
        --tempdir=*) tempdir=${argument#--tempdir=} ;;
    esac
done
[ -n "$input" ] || exit 2
echo "pdf_extract_obj: Found /Type/ObjStm"
if [ "${PDF_STUB_MODE:-pass}" = reject ]; then
    : > "$tempdir/leaked-child"
else
    echo "pdf_objstm_attach_file: retained 1-byte quota-accounted file-backed object stream"
fi
echo "pdf_find_and_parse_objs_in_objstm: Found object 5 0 in object stream at offset: 1"
case "$input" in
    *malformed.pdf) echo "PDF object-stream parsing did not complete" ;;
esac
echo "pdf_objstm_cleanup: releasing 1-byte file-backed object stream"
echo "$input: LargeFile.PDF.ObjStm.Tail.UNOFFICIAL FOUND"
[ "${PDF_STUB_MODE:-pass}" = reject ] && exit 0
exit 1
STUB
chmod +x "$stub"

"$root/tools/largefile_pdf_objstm_qualification.sh" \
    "$stub" "$work/database" "$work/evidence" 67108864 41943040 \
    > "$work/qualification.log" 2>&1

[ "$(awk -F '\t' 'NR > 1 && $8 == "pass" { count++ } END { print count + 0 }' \
    "$work/evidence/results.tsv")" -eq 5 ]
awk -F '\t' 'NR > 1 && $1 == "materialized" { found = 1; if ($8 < $6) exit 1 } END { exit !found }' \
    "$work/evidence/corpus-manifest.tsv"
grep -F 'PDF object-stream qualification passed' "$work/qualification.log" >/dev/null

if PDF_STUB_MODE=reject "$root/tools/largefile_pdf_objstm_qualification.sh" \
    "$stub" "$work/database" "$work/rejected-evidence" 67108864 41943040 \
    > "$work/rejected.log" 2>&1; then
    echo 'qualification accepted false-clean, unmapped, residue-bearing evidence' >&2
    exit 1
fi
grep -F 'PDF object-stream qualification failed' "$work/rejected.log" >/dev/null

echo 'PDF object-stream qualification orchestrator test passed'
