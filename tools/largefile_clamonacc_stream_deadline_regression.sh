#!/bin/sh

# Compile the exact production source-read deadline helpers extracted from
# clamonacc/client/protocol.c. This is a bounded development regression for
# unknown-size pipe/FIFO ingress; it does not claim a full clamonacc build.

set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
source_file="$root/clamonacc/client/protocol.c"
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/clamav-clamonacc-stream.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT INT TERM

if command -v cc >/dev/null 2>&1; then
    compiler=$(command -v cc)
elif command -v clang >/dev/null 2>&1; then
    compiler=$(command -v clang)
else
    echo "large-file clamonacc stream deadline regression requires cc or clang" >&2
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
    printf '%s\n' \
        '#include <errno.h>' \
        '#include <signal.h>' \
        '#include <stdint.h>' \
        '#include <stdio.h>' \
        '#include <stdlib.h>' \
        '#include <string.h>' \
        '#include <sys/select.h>' \
        '#include <sys/time.h>' \
        '#include <sys/wait.h>' \
        '#include <unistd.h>'
    extract_helper '^static int onas_source_now_ms'
    extract_helper '^static int onas_source_deadline'
    extract_helper '^static int onas_source_wait_readable'
    printf '%s\n' \
        'static void fail(const char *message)' \
        '{' \
        '    perror(message);' \
        '    exit(1);' \
        '}' \
        'static void check_zero_timeout(void)' \
        '{' \
        '    int fds[2];' \
        '    if (pipe(fds) != 0)' \
        '        fail("pipe");' \
        '    if (onas_source_wait_readable(fds[0], 0) != 0) {' \
        '        fprintf(stderr, "zero timeout did not preserve immediate polling\\n");' \
        '        exit(1);' \
        '    }' \
        '    close(fds[0]);' \
        '    close(fds[1]);' \
        '}' \
        'static void check_timeout(void)' \
        '{' \
        '    int fds[2];' \
        '    uint64_t deadline = 0;' \
        '    if (pipe(fds) != 0 || onas_source_deadline(50, &deadline) != 0)' \
        '        fail("pipe/deadline");' \
        '    if (onas_source_wait_readable(fds[0], deadline) != 0) {' \
        '        fprintf(stderr, "an idle source did not time out\\n");' \
        '        exit(1);' \
        '    }' \
        '    close(fds[0]);' \
        '    close(fds[1]);' \
        '}' \
        'static void check_eof(void)' \
        '{' \
        '    int fds[2];' \
        '    uint64_t deadline = 0;' \
        '    if (pipe(fds) != 0 || onas_source_deadline(1000, &deadline) != 0)' \
        '        fail("pipe/deadline");' \
        '    close(fds[1]);' \
        '    if (onas_source_wait_readable(fds[0], deadline) <= 0) {' \
        '        fprintf(stderr, "EOF was not reported as readable\\n");' \
        '        exit(1);' \
        '    }' \
        '    close(fds[0]);' \
        '}' \
        'static void check_absolute_deadline(void)' \
        '{' \
        '    int fds[2];' \
        '    int status = 0;' \
        '    int bytes = 0;' \
        '    int result;' \
        '    pid_t child;' \
        '    uint64_t deadline = 0;' \
        '    struct timespec pause = {0, 10000000L};' \
        '    if (pipe(fds) != 0 || onas_source_deadline(60, &deadline) != 0)' \
        '        fail("pipe/deadline");' \
        '    child = fork();' \
        '    if (child < 0)' \
        '        fail("fork");' \
        '    if (child == 0) {' \
        '        int index;' \
        '        close(fds[0]);' \
        '        for (index = 0; index < 20; index++) {' \
        '            if (write(fds[1], "x", 1) != 1)' \
        '                _exit(2);' \
        '            nanosleep(&pause, NULL);' \
        '        }' \
        '        close(fds[1]);' \
        '        _exit(0);' \
        '    }' \
        '    close(fds[1]);' \
        '    for (;;) {' \
        '        char value;' \
        '        result = onas_source_wait_readable(fds[0], deadline);' \
        '        if (result == 0)' \
        '            break;' \
        '        if (result < 0 || read(fds[0], &value, 1) != 1)' \
        '            fail("steady source read");' \
        '        bytes++;' \
        '    }' \
        '    if (bytes == 0) {' \
        '        fprintf(stderr, "steady source produced no data before timeout\\n");' \
        '        exit(1);' \
        '    }' \
        '    kill(child, SIGTERM);' \
        '    if (waitpid(child, &status, 0) < 0)' \
        '        fail("waitpid");' \
        '    close(fds[0]);' \
        '    if (!WIFSIGNALED(status)) {' \
        '        fprintf(stderr, "steady source child outlived its deadline\\n");' \
        '        exit(1);' \
        '    }' \
        '}' \
        'static void check_data(void)' \
        '{' \
        '    int fds[2];' \
        '    uint64_t deadline = 0;' \
        '    char value = 0;' \
        '    if (pipe(fds) != 0 || onas_source_deadline(1000, &deadline) != 0)' \
        '        fail("pipe/deadline");' \
        '    if (write(fds[1], "x", 1) != 1)' \
        '        fail("write");' \
        '    if (onas_source_wait_readable(fds[0], deadline) <= 0 || read(fds[0], &value, 1) != 1 || value != '\''x'\'') {' \
        '        fprintf(stderr, "available source data was not admitted\\n");' \
        '        exit(1);' \
        '    }' \
        '    close(fds[0]);' \
        '    close(fds[1]);' \
        '}' \
        'int main(void)' \
        '{' \
        '    check_zero_timeout();' \
        '    check_timeout();' \
        '    check_eof();' \
        '    check_absolute_deadline();' \
        '    check_data();' \
        '    puts("clamonacc stream deadline regression passed");' \
        '    return 0;' \
        '}'
} | "$compiler" -x c -std=c11 -Wall -Wextra -Werror -o "$tmpdir/test" -

"$tmpdir/test"
