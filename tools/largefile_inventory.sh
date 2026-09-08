#!/bin/sh

# Produce a deterministic Phase 0 inventory of integer, offset, parsing, and
# formatting sites that require semantic review for large-file support.
# Usage: tools/largefile_inventory.sh [source-root]

set -eu

root=${1:-.}

printf 'category\tfile\tline\ttext\n'

emit() {
    category=$1
    pattern=$2
    shift 2
    if command -v rg >/dev/null 2>&1; then
        rg -n --no-heading --color never \
            --glob '*.c' --glob '*.h' --glob '*.cc' --glob '*.cpp' --glob '*.rs' \
            "$pattern" "$@" "$root" 2>/dev/null \
            | awk -F: -v category="$category" 'BEGIN { OFS="\t" } {
                file=$1; line=$2; text=$0;
                sub(/^\.\/+/, "", file);
                sub(/^[^:]*:[^:]*:/, "", text);
                sub(/[ \t\r]+$/, "", text);
                print category, file, line, text;
            }' \
            | LC_ALL=C sort -u || true
    else
        python3 - "$category" "$pattern" "$root" <<'PY' | LC_ALL=C sort -u || true
import os
import re
import sys

category, pattern, search_root = sys.argv[1:]
pattern = pattern.replace("[[:space:]]", r"\s")
matcher = re.compile(pattern)
suffixes = (".c", ".h", ".cc", ".cpp", ".rs")
skip_dirs = {".git", ".hg", ".svn", "target"}

for directory, directories, filenames in os.walk(search_root):
    directories[:] = sorted(name for name in directories if name not in skip_dirs)
    for filename in sorted(filenames):
        if not filename.endswith(suffixes):
            continue
        path = os.path.join(directory, filename)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as source:
                for line_number, line in enumerate(source, 1):
                    text = line.rstrip(" \t\r\n")
                    if matcher.search(text):
                        relative = os.path.relpath(path, search_root)
                        print(f"{category}\t{relative}\t{line_number}\t{text}")
        except (OSError, UnicodeError):
            continue
PY
    fi
}

emit 'fixed-width-integer' '\b(uint16_t|uint32_t|uint64_t|int16_t|int32_t|int64_t)\b' \
    "$root"

emit 'native-width-integer' '\b(unsigned[[:space:]]+int|unsigned[[:space:]]+long|long[[:space:]]+long|long|int|size_t|ssize_t|off_t)\b' \
    "$root"

emit 'boundary-constant' '\b(INT_MAX|UINT_MAX|UINT32_MAX|ULONG_MAX|LLONG_MAX|SIZE_MAX)\b' \
    "$root"

emit 'quantity-parser' '\b(atoi|atol|atoll|strtol|strtoul|strtoll|strtoull)\s*\(' \
    "$root"

emit 'narrowing-cast' '\([[:space:]]*(int|unsigned[[:space:]]+int|long|unsigned[[:space:]]+long|uint32_t|uint16_t)[[:space:]]*\)[[:space:]]*(offset|off|pos|position|size|len|length|filesize|scanned|map->len|ctx->scansize)' \
    "$root"

emit 'format-width' '%(u|d|i|lu|ld|llu|lld|zu|zd)' \
    "$root"

emit 'offset-size-arithmetic' '(offset|off|pos|position|size|len|length|filesize|end|start|raw|compressed|uncompressed|seek|scanned)[^;\n]*(\+|-|\*|/|<<|>>)' \
    "$root"

emit 'large-file-option' '(MaxFileSize|MaxScanSize|PCREMaxFileSize|CL_ENGINE_MAX_FILESIZE|CL_ENGINE_MAX_SCANSIZE)' \
    "$root"
