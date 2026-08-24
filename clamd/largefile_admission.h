/*
 * Large-file daemon admission checks.
 */

#ifndef CLAMD_LARGEFILE_ADMISSION_H
#define CLAMD_LARGEFILE_ADMISSION_H

#include <stddef.h>
#include <stdint.h>

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

/* Validate the compile-time capabilities required by the certified profile.
 * The explicit inputs keep each release-policy boundary independently
 * testable; production admission passes the corresponding build constants. */
int clamd_largefile_build_profile_check(
    int build_support,
    int certified_platform,
    int fd_passing,
    int file_backed_mapping,
    char *reason,
    size_t reason_size);

/* Validate an observed RLIMIT_FSIZE against the largest configured ingress.
 * Explicit observation inputs keep finite, infinite, and query-failure cases
 * deterministic in unit tests. */
int clamd_largefile_fsize_limit_check(
    int query_succeeded,
    int limit_is_infinite,
    uint64_t limit_bytes,
    uint64_t required_bytes,
    char *reason,
    size_t reason_size);

/* Validate the certified one-worker daemon profile. The admission resource
 * calculation is intentionally for one active scan; additional requests must
 * remain queued rather than consuming a second scan budget. */
int clamd_largefile_worker_count_check(
    int query_succeeded,
    uint64_t max_threads,
    char *reason,
    size_t reason_size);

/* Resolve the process cgroup and its mounted hierarchy, then return the
 * smallest finite memory headroom across the current cgroup and visible
 * ancestors. Explicit proc paths support deterministic hierarchy fixtures. */
int clamd_largefile_cgroup_headroom_from_files(
    const char *proc_cgroup_path,
    const char *proc_mountinfo_path,
    uint64_t *headroom,
    int *bounded);

/* Validate a Linux filesystem magic value for temporary staging. The explicit
 * observation inputs avoid requiring tests to alter or provision mounts. */
int clamd_largefile_temporary_filesystem_check(
    int query_succeeded,
    uint64_t filesystem_magic,
    char *reason,
    size_t reason_size);

/* Emit the compiled and configured large-file capability manifest once the
 * engine has been initialized. The manifest describes capability boundaries;
 * it is not a parser or service qualification claim. */
void clamd_largefile_log_capabilities(const struct cl_engine *engine);

#endif
