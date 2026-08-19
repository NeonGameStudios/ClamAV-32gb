/*
 * Large-file daemon admission checks.
 */

#ifndef CLAMD_LARGEFILE_ADMISSION_H
#define CLAMD_LARGEFILE_ADMISSION_H

#include <stddef.h>

struct cl_engine;

/*
 * Return nonzero when the configured large-file daemon can safely start.
 * On failure, write a concise reason into reason when it is non-NULL.
 */
int clamd_largefile_admission_check(
    const struct cl_engine *engine,
    const char *temporary_directory,
    char *reason,
    size_t reason_size);

#endif
