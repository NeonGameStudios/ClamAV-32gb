#!/bin/sh

# Validate the authoritative large-file capability manifest.
# The manifest is deliberately allowed to contain pending entries; it is a
# coverage contract, not a claim that every parser has already qualified.

set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
manifest=$root/docs/largefile-capabilities.tsv

if [ ! -f "$manifest" ]; then
    echo "capability manifest is missing: $manifest" >&2
    exit 1
fi

awk -F '\t' '
    NR == 1 {
        if (NF != 5 || $1 != "kind" || $2 != "id" || $3 != "status" ||
            $4 != "source" || $5 != "evidence_or_required_work") {
            print "invalid capability manifest header" > "/dev/stderr"
            bad = 1
        }
        next
    }
    {
        if (NF != 5) {
            print "capability manifest row does not have five columns at line " NR > "/dev/stderr"
            bad = 1
            next
        }
        if ($1 != "library" && $1 != "clamscan" && $1 != "clamd" &&
            $1 != "clamdscan" && $1 != "milter" && $1 != "on-access" &&
            $1 != "parser" && $1 != "matcher" && $1 != "feature" &&
            $1 != "unsupported") {
            print "unknown capability kind at line " NR > "/dev/stderr"
            bad = 1
        }
        if ($3 != "qualified" && $3 != "bounded" && $3 != "pending" &&
            $3 != "unsupported") {
            print "unknown capability status at line " NR > "/dev/stderr"
            bad = 1
        }
        if ($2 == "" || $4 == "" || $5 == "") {
            print "empty capability field at line " NR > "/dev/stderr"
            bad = 1
        }
        if ($1 == "unsupported" && $3 != "unsupported") {
            print "unsupported capability must use unsupported status at line " NR > "/dev/stderr"
            bad = 1
        }
        key = $1 SUBSEP $2
        seen[key] += 1
        if (seen[key] != 1) {
            print "duplicate capability entry: " $1 ":" $2 > "/dev/stderr"
            bad = 1
        }
        count++
    }
    END {
        if (NR < 2 || count == 0)
            bad = 1
        exit bad
    }
' "$manifest"

required_ingress='library:path library:fd library:fmap clamscan:file clamscan:stdin clamd:SCAN clamd:FILDES clamd:INSTREAM clamd:SCANREPORT clamd:CONTSCANREPORT clamd:MULTISCANREPORT clamd:ALLMATCHSCANREPORT clamd:FILDESREPORT clamd:INSTREAMREPORT clamdscan:fdpass clamdscan:stream clamd:MULTISCAN milter:message on-access:permission'
for entry in $required_ingress; do
    kind=${entry%%:*}
    id=${entry#*:}
    if ! awk -F '\t' -v wanted_kind="$kind" -v wanted_id="$id" \
        '$1 == wanted_kind && $2 == wanted_id { found = 1 } END { exit !found }' "$manifest"; then
        echo "capability manifest is missing ingress ${kind}:${id}" >&2
        exit 1
    fi
done

required_matchers='ac bm byte-compare hash pcre logical yara bytecode fuzzy-image'
for id in $required_matchers; do
    if ! awk -F '\t' -v wanted_id="$id" \
        '$1 == "matcher" && $2 == wanted_id { found = 1 } END { exit !found }' "$manifest"; then
        echo "capability manifest is missing matcher ${id}" >&2
        exit 1
    fi
done

# These are the build switches that can change which large-file ingress,
# parser, matcher, or resource policy is present in the resulting binary.
required_features='BYTECODE_RUNTIME LARGE_FILE_DEFAULTS MMAP_FOR_CROSSCOMPILING DISABLE_MPOOL ENABLE_FUZZ ENABLE_EXTERNAL_MSPACK ENABLE_JSON_SHARED ENABLE_APP ENABLE_MILTER ENABLE_CLAMONACC ENABLE_MAN_PAGES ENABLE_DOXYGEN ENABLE_EXAMPLES ENABLE_TESTS ENABLE_LIBCLAMAV_ONLY ENABLE_STATIC_LIB ENABLE_SHARED_LIB ENABLE_UNRAR ENABLE_SYSTEMD ENABLE_WERROR ENABLE_ALL_THE_WARNINGS ENABLE_DEBUG ENABLE_EXPERIMENTAL ENABLE_FRESHCLAM_DNS_FIX ENABLE_FRESHCLAM_NO_CACHE ENABLE_STRN_INTERNAL MAINTAINER_MODE OPTIMIZE'
for id in $required_features; do
    if ! awk -F '\t' -v wanted_id="$id" \
        '$1 == "feature" && $2 == wanted_id { found = 1 } END { exit !found }' "$manifest"; then
        echo "capability manifest is missing feature ${id}" >&2
        exit 1
    fi
done

required_unsupported='macos-first-release aarch64-first-release autoit-ea06-script-over-1g autoit-ea05-output-over-4g bytecode-v1-over-4g dmg-blkx-metadata-over-64m egg-compat-member-over-1g egg-extra-field-over-1g legacy-callback-over-1g image-fuzzy-over-contiguous-limit pdf-stream-over-4g script-normalization-over-4g vba-over-4g'
for id in $required_unsupported; do
    if ! awk -F '\t' -v wanted_id="$id" \
        '$1 == "unsupported" && $2 == wanted_id && $3 == "unsupported" { found = 1 } END { exit !found }' "$manifest"; then
        echo "capability manifest is missing deliberate unsupported feature ${id}" >&2
        exit 1
    fi
done

dispatch_tmp=$(mktemp "${TMPDIR:-/tmp}/clamav-capabilities.XXXXXX")
manifest_tmp=$(mktemp "${TMPDIR:-/tmp}/clamav-capabilities-manifest.XXXXXX")
cleanup()
{
    rm -f "$dispatch_tmp" "$manifest_tmp"
}
trap cleanup EXIT HUP INT TERM

awk '$1 == "case" && $2 ~ /^CL_TYPE_[A-Z0-9_]*:/ { sub(/:.*/, "", $2); print $2 }' \
    "$root/libclamav/scanners.c" | sort -u > "$dispatch_tmp"
awk -F '\t' '$1 == "parser" { print $2 }' "$manifest" | sort -u > "$manifest_tmp"

if ! missing=$(comm -23 "$dispatch_tmp" "$manifest_tmp"); then
    echo 'failed to compare parser dispatch coverage' >&2
    exit 1
fi
if [ -n "$missing" ]; then
    echo "capability manifest is missing parser dispatch branches:" >&2
    printf '%s\n' "$missing" >&2
    exit 1
fi

if ! stale=$(comm -13 "$dispatch_tmp" "$manifest_tmp"); then
    echo 'failed to compare parser manifest entries' >&2
    exit 1
fi
if [ -n "$stale" ]; then
    echo "capability manifest contains stale parser entries:" >&2
    printf '%s\n' "$stale" >&2
    exit 1
fi

while IFS="$(printf '\t')" read -r kind id status source evidence; do
    [ "$kind" = kind ] && continue
    case "$source" in
        /*) source_path=$source ;;
        *) source_path=$root/$source ;;
    esac
    if [ ! -f "$source_path" ]; then
        echo "capability source does not exist for ${kind}:${id}: $source" >&2
        exit 1
    fi
done < "$manifest"

printf 'large-file capability manifest passed (%s entries)\n' "$(awk 'NR > 1 { count++ } END { print count + 0 }' "$manifest")"
