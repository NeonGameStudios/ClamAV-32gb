/*
 * Pure message-size policy used by clamav-milter and its unit tests.
 */

#include <limits.h>
#include <stdint.h>

#include "default.h"
#include "others.h"
#include "clamfi_quota.h"

int clamfi_normalize_maxfilesize(uint64_t configured, uint64_t *effective)
{
    if (NULL == effective)
        return 0;

    if (0 == configured)
        configured = CLI_MAX_LARGE_FILESIZE;

    if (configured > CLI_MAX_LARGE_FILESIZE)
        return 0;

    *effective = configured;
    return 1;
}

enum clamfi_quota_result clamfi_quota_add(uint64_t current, uint64_t limit, size_t requested, uint64_t *next)
{
    uint64_t requested64 = (uint64_t)requested;

    if (NULL == next)
        return CLAMFI_QUOTA_INVALID;

    *next = current;

    if (current > limit)
        return CLAMFI_QUOTA_EXCEEDED;
    if (requested64 > UINT64_MAX - current)
        return CLAMFI_QUOTA_EXCEEDED;
    if (requested64 > limit - current)
        return CLAMFI_QUOTA_EXCEEDED;

    *next = current + requested64;
    return CLAMFI_QUOTA_OK;
}

int clamfi_reject_message_size(size_t source_length, size_t *output_size)
{
    if (NULL == output_size || source_length > (SIZE_MAX - 1U) / 4U)
        return 0;

    *output_size = source_length * 4U + 1U;
    return *output_size <= (size_t)CLI_MAX_ALLOCATION;
}
