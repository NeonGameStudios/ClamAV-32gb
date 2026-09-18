#!/bin/sh

# Compile the exact production UTF-8 boundary helper extracted from
# clamonacc/scan/thread.c.  This is intentionally separate from the
# no-compiler source-guard suite: it is a focused development regression when
# a local C compiler is available.

set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
source_file="$root/clamonacc/scan/thread.c"
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/clamav-clamonacc-utf8.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT INT TERM

if command -v cc >/dev/null 2>&1; then
    compiler=$(command -v cc)
elif command -v clang >/dev/null 2>&1; then
    compiler=$(command -v clang)
else
    echo "large-file clamonacc UTF-8 regression requires cc or clang" >&2
    exit 77
fi

extract_helper() {
    awk -v target="$1" '
        $0 ~ target { in_function = 1 }
        in_function {
            print
            opens = gsub(/\{/, "")
            closes = gsub(/\}/, "")
            depth += opens - closes
            if (opens > 0)
                saw_open = 1
            if (saw_open && depth == 0)
                exit
        }
    ' "$source_file"
}

{
    printf '%s\n' '#include <stddef.h>' '#include <stdio.h>' '#include <stdlib.h>' '#include <string.h>'
    extract_helper '^static size_t onas_valid_utf8_length'
    extract_helper '^static int onas_write_json_string'
    printf '%s\n' \
        'static void check(const unsigned char *value, size_t length, size_t expected)' \
        '{' \
        '    size_t actual = onas_valid_utf8_length(value, length);' \
        '    if (actual != expected) {' \
        '        fprintf(stderr, "expected %zu, got %zu\n", expected, actual);' \
        '        exit(1);' \
        '    }' \
        '}' \
        'static void check_json(const unsigned char *value, size_t length, const unsigned char *expected, size_t expected_length)' \
        '{' \
        '    unsigned char buffer[128];' \
        '    FILE *stream = tmpfile();' \
        '    size_t actual;' \
        '    (void)length;' \
        '    if (stream == NULL || onas_write_json_string(stream, (const char *)value) != 0 || fflush(stream) != 0 || fseek(stream, 0, SEEK_SET) != 0)' \
        '        exit(1);' \
        '    actual = fread(buffer, 1, sizeof(buffer), stream);' \
        '    if (actual != expected_length || memcmp(buffer, expected, expected_length) != 0) {' \
        '        size_t index;' \
        '        fprintf(stderr, "JSON mismatch: actual=%zu expected=%zu\n", actual, expected_length);' \
        '        for (index = 0; index < actual; index++) fprintf(stderr, "%02x", buffer[index]);' \
        '        fputc(10, stderr);' \
        '        for (index = 0; index < expected_length; index++) fprintf(stderr, "%02x", expected[index]);' \
        '        fputc(10, stderr);' \
        '        exit(1);' \
        '    }' \
        '    fclose(stream);' \
        '}' \
        'int main(void)' \
        '{' \
        '    static const unsigned char four[] = {0xF0, 0x9F, 0x98, 0x80};' \
        '    static const unsigned char max_four[] = {0xF4, 0x8F, 0xBF, 0xBF};' \
        '    static const unsigned char three[] = {0xE2, 0x82, 0xAC};' \
        '    static const unsigned char overlong[] = {0xF0, 0x80, 0x80, 0x80};' \
        '    static const unsigned char surrogate[] = {0xED, 0xA0, 0x80};' \
        '    static const unsigned char out_of_range[] = {0xF4, 0x90, 0x80, 0x80};' \
        '    static const unsigned char truncated[] = {0xF0, 0x9F, 0x98};' \
        '    static const unsigned char valid_path[] = "prefix\xF0\x9F\x98\x80";' \
        '    static const unsigned char valid_json[] = "\"prefix\xF0\x9F\x98\x80\"";' \
        '    static const unsigned char invalid_path[] = {0x70, 0x72, 0x65, 0x66, 0x69, 0x78, 0xFF, 0x00};' \
        '    static const unsigned char invalid_json[] = "\"prefix\\u00ff\"";' \
        '    check(four, sizeof(four), 4);' \
        '    check(max_four, sizeof(max_four), 4);' \
        '    check(three, sizeof(three), 3);' \
        '    check(overlong, sizeof(overlong), 0);' \
        '    check(surrogate, sizeof(surrogate), 0);' \
        '    check(out_of_range, sizeof(out_of_range), 0);' \
        '    check(truncated, sizeof(truncated), 0);' \
        '    check_json(valid_path, sizeof(valid_path) - 1, valid_json, sizeof(valid_json) - 1);' \
        '    check_json(invalid_path, sizeof(invalid_path) - 1, invalid_json, sizeof(invalid_json) - 1);' \
        '    puts("clamonacc UTF-8 boundary regression passed");' \
        '    return 0;' \
        '}'
} | "$compiler" -x c -std=c11 -Wall -Wextra -Werror -o "$tmpdir/test" -

"$tmpdir/test"
