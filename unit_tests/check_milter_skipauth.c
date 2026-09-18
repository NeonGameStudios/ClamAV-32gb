/* Regression coverage for file-backed SkipAuthenticated list construction. */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "allow_list.h"

#define CHECK(condition, message)       \
    do {                                \
        if (!(condition)) {             \
            fprintf(stderr, "%s\n", message); \
            return 1;                   \
        }                               \
    } while (0)

static int write_all(int fd, const char *data, size_t length)
{
    while (length != 0) {
        ssize_t written = write(fd, data, length);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return 0;
        data += written;
        length -= (size_t)written;
    }
    return 1;
}

static int check_empty_case(const char *contents)
{
    char path[] = "/tmp/clamav-milter-skipauth-XXXXXX";
    char option[sizeof(path) + sizeof("file:") - 1];
    int fd = mkstemp(path);
    int result;

    if (fd < 0) return 0;
    result = write_all(fd, contents, strlen(contents)) && close(fd) == 0;
    if (!result) {
        close(fd);
        unlink(path);
        return 0;
    }
    snprintf(option, sizeof(option), "file:%s", path);
    result = smtpauth_init(option) == 0 && smtpauthed("user@example.com") == 0;
    unlink(path);
    return result;
}

static int check_allow_list_case(const char *contents, const char *address)
{
    char path[] = "/tmp/clamav-milter-allowlist-XXXXXX";
    int fd = mkstemp(path);
    int result;

    if (fd < 0) return 0;
    result = write_all(fd, contents, strlen(contents)) && close(fd) == 0;
    if (!result) {
        close(fd);
        unlink(path);
        return 0;
    }
    result = allow_list_init(path) == 0 && allowed(address, 0) == 1;
    allow_list_free();
    unlink(path);
    return result;
}

static int check_invalid_allow_list_case(void)
{
    char path[] = "/tmp/clamav-milter-invalid-allowlist-XXXXXX";
    int fd = mkstemp(path);
    int result;

    if (fd < 0) return 0;
    result = write_all(fd, "[", 1) && close(fd) == 0;
    if (!result) {
        close(fd);
        unlink(path);
        return 0;
    }
    result = allow_list_init(path) == 1;
    allow_list_free();
    unlink(path);
    return result;
}

int main(void)
{
    char path[] = "/tmp/clamav-milter-skipauth-XXXXXX";
    char option[sizeof(path) + sizeof("file:") - 1];
    char long_login[2048];
    int fd;

    CHECK(check_empty_case(""), "empty SkipAuthenticated file was not accepted safely");
    CHECK(check_empty_case("# comment\n\n: ignored\n! disabled\n"),
          "comment-only SkipAuthenticated file was not accepted safely");
    CHECK(check_allow_list_case("x", "x"),
          "one-character final allow-list entry without newline was discarded");
    CHECK(check_invalid_allow_list_case(),
          "malformed allow-list regex did not fail safely during cleanup");

    memset(long_login, '+', sizeof(long_login) - 1);
    long_login[sizeof(long_login) - 1] = '\0';
    fd = mkstemp(path);
    CHECK(fd >= 0, "could not create long SkipAuthenticated fixture");
    CHECK(write_all(fd, long_login, sizeof(long_login) - 1) && write_all(fd, "\n", 1) && close(fd) == 0,
          "could not write long SkipAuthenticated fixture");
    snprintf(option, sizeof(option), "file:%s", path);
    CHECK(smtpauth_init(option) == 0, "long SkipAuthenticated entry was rejected");
    CHECK(smtpauthed(long_login) == 1, "long SkipAuthenticated entry did not match");
    CHECK(smtpauthed("short") == 0, "long SkipAuthenticated entry matched the wrong login");
    unlink(path);
    return 0;
}
