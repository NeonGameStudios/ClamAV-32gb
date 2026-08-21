/*
 * Large-file daemon admission checks.
 */

#ifndef CLAMD_LARGEFILE_ADMISSION_H
#define CLAMD_LARGEFILE_ADMISSION_H

#include <stddef.h>

struct cl_engine;
struct optstruct;

/*
 * Return nonzero when the configured large-file daemon can safely start.
 * On failure, write a concise reason into reason when it is non-NULL.
 */
int clamd_largefile_admission_check(
    const struct cl_engine *engine,
    const struct optstruct *opts,
    const char *temporary_directory,
    char *reason,
    size_t reason_size);

/* Emit the compiled and configured large-file capability manifest once the
 * engine has been initialized. The manifest describes capability boundaries;
 * it is not a parser or service qualification claim. */
void clamd_largefile_log_capabilities(const struct cl_engine *engine);

#endif
