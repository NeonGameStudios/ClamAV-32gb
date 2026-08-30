/*
 * Pure message-size policy used by clamav-milter and its unit tests.
 * This file deliberately has no libmilter dependency.
 */

#ifndef __CLAMFI_QUOTA_H
#define __CLAMFI_QUOTA_H

#include <stddef.h>
#include <stdint.h>

enum clamfi_quota_result {
    CLAMFI_QUOTA_OK = 0,
    CLAMFI_QUOTA_EXCEEDED,
    CLAMFI_QUOTA_INVALID
};

int clamfi_normalize_maxfilesize(uint64_t configured, uint64_t *effective);
enum clamfi_quota_result clamfi_quota_add(uint64_t current, uint64_t limit, size_t requested, uint64_t *next);
int clamfi_reject_message_size(size_t source_length, size_t *output_size);

#endif
