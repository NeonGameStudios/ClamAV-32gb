/* Small, allocation-free regression tests for clamav-milter size policy. */

#include <stdint.h>
#include <stdio.h>

#include "default.h"
#include "others.h"
#include "clamfi_quota.h"

#define CHECK(condition, message)       \
    do {                                \
        if (!(condition)) {             \
            fprintf(stderr, "%s\n", message); \
            return 1;                   \
        }                               \
    } while (0)

int main(void)
{
    uint64_t effective = 0;
    uint64_t next      = 0;
    size_t reject_size = 0;
    uint64_t four_gib  = (uint64_t)4 * 1024 * 1024 * 1024;
    uint64_t thirty_two_gib = CLI_MAX_LARGE_FILESIZE;

    CHECK(clamfi_normalize_maxfilesize(0, &effective), "zero MaxFileSize was rejected");
    CHECK(effective == thirty_two_gib, "zero MaxFileSize did not select 32 GiB");
    CHECK(clamfi_normalize_maxfilesize(four_gib, &effective), "4 GiB MaxFileSize was rejected");
    CHECK(effective == four_gib, "4 GiB MaxFileSize changed during normalization");
    CHECK(!clamfi_normalize_maxfilesize(thirty_two_gib + 1, &effective), "32 GiB+1 MaxFileSize was accepted");

    CHECK(CLAMFI_QUOTA_OK == clamfi_quota_add(four_gib - 1, four_gib, 1, &next), "exact 4 GiB quota was rejected");
    CHECK(next == four_gib, "exact 4 GiB quota produced the wrong total");
    CHECK(CLAMFI_QUOTA_EXCEEDED == clamfi_quota_add(four_gib - 1, four_gib, 2, &next), "4 GiB crossing was truncated or accepted");
    CHECK(CLAMFI_QUOTA_OK == clamfi_quota_add(thirty_two_gib - 1, thirty_two_gib, 1, &next), "exact 32 GiB quota was rejected");
    CHECK(next == thirty_two_gib, "exact 32 GiB quota produced the wrong total");
    CHECK(CLAMFI_QUOTA_EXCEEDED == clamfi_quota_add(thirty_two_gib, thirty_two_gib, 1, &next), "32 GiB+1 crossing was truncated or accepted");
    CHECK(CLAMFI_QUOTA_EXCEEDED == clamfi_quota_add(UINT64_MAX, UINT64_MAX, 1, &next), "uint64 overflow was accepted");

    CHECK(clamfi_reject_message_size(0, &reject_size), "empty RejectMsg was rejected");
    CHECK(reject_size == 1, "empty RejectMsg size is incorrect");
    CHECK(clamfi_reject_message_size(4, &reject_size), "small RejectMsg was rejected");
    CHECK(reject_size == 17, "small RejectMsg size is incorrect");
    CHECK(!clamfi_reject_message_size((SIZE_MAX - 1U) / 4U + 1U, &reject_size), "RejectMsg size overflow was accepted");
    CHECK(!clamfi_reject_message_size((size_t)CLI_MAX_ALLOCATION, &reject_size), "over-limit RejectMsg was accepted");
    CHECK(!clamfi_reject_message_size(1, NULL), "NULL RejectMsg size output was accepted");

    return 0;
}
