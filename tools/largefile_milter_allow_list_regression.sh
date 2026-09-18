#!/bin/sh

# Compile the exact production milter allow-list implementation together with
# its focused test. The local stubs replace only the unavailable full ClamAV
# regex/logging link dependencies; the production parser and cleanup paths are
# compiled unchanged.

set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/clamav-milter-allow-list.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT INT TERM

if command -v cc >/dev/null 2>&1; then
    compiler=$(command -v cc)
elif command -v clang >/dev/null 2>&1; then
    compiler=$(command -v clang)
else
    echo "large-file milter allow-list regression requires cc or clang" >&2
    exit 77
fi

build_and_run() {
    output=$1
    shift
    {
        printf '%s\n' \
            '#define HAVE_CONFIG_H 0' \
            '#define HAVE_STDLIB_H 1' \
            '#define HAVE_SYS_TYPES_H 1' \
            '#include <stdlib.h>' \
            '#include <string.h>' \
            "#include \"$root/libclamav/regex/regex.h\"" \
            "#include \"$root/common/output.h\"" \
            'static char *copy_pattern(const char *pattern)' \
            '{' \
            '    size_t length = strlen(pattern) + 1U;' \
            '    char *copy = malloc(length);' \
            '    if (copy != NULL) memcpy(copy, pattern, length);' \
            '    return copy;' \
            '}' \
            'int cli_regcomp(regex_t *preg, const char *pattern, int flags)' \
            '{' \
            '    (void)flags;' \
            '    if (preg == NULL || pattern == NULL || strcmp(pattern, "[") == 0)' \
            '        return 1;' \
            '    preg->re_endp = copy_pattern(pattern);' \
            '    return preg->re_endp == NULL ? 12 : 0;' \
            '}' \
            'int cli_regexec(const regex_t *preg, const char *string, size_t nmatch, regmatch_t pmatch[], int eflags)' \
            '{' \
            '    const char *pattern;' \
            '    size_t expected = 0;' \
            '    size_t index;' \
            '    (void)nmatch;' \
            '    (void)pmatch;' \
            '    (void)eflags;' \
            '    if (preg == NULL || string == NULL || (pattern = preg->re_endp) == NULL)' \
            '        return 1;' \
            '    if (pattern[0] == '\''^'\'' && pattern[1] == '\''('\'') {' \
            '        for (index = 0; pattern[index] != 0; index++)' \
            '            if (pattern[index] == '\'']'\'') expected++;' \
            '        if (strlen(string) != expected) return 1;' \
            '        for (index = 0; index < expected; index++)' \
            '            if (string[index] != '\''+'\'') return 1;' \
            '        return 0;' \
            '    }' \
            '    return strcmp(pattern, string) == 0 ? 0 : 1;' \
            '}' \
            'void cli_regfree(regex_t *preg)' \
            '{' \
            '    if (preg != NULL) {' \
            '        free((void *)preg->re_endp);' \
            '        preg->re_endp = NULL;' \
            '    }' \
            '}' \
            'int logg(loglevel_t level, const char *format, ...)' \
            '{' \
            '    (void)level;' \
            '    (void)format;' \
            '    return 0;' \
            '}'
        printf '%s\n' "#include \"$root/clamav-milter/allow_list.c\""
        printf '%s\n' "#include \"$root/unit_tests/check_milter_skipauth.c\""
    } | "$compiler" -x c -std=c11 -Wall -Wextra -Werror \
        -I"$root/clamav-milter" -I"$root/common" -I"$root/libclamav" \
        "$@" -o "$output" -
    "$output"
}

build_and_run "$tmpdir/normal"
build_and_run "$tmpdir/sanitized" -fsanitize=address,undefined -fno-omit-frame-pointer
echo "large-file milter allow-list regression passed"
