/*
 * Large-file daemon admission checks.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "largefile_admission.h"

#include "clamav.h"
#include "default.h"

// common
#include "output.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <sys/statvfs.h>
#include <sys/types.h>
#endif

#define LARGEFILE_GIB (1024ULL * 1024ULL * 1024ULL)
#define LARGEFILE_MIN_AVAILABLE (48ULL * LARGEFILE_GIB)
#define LARGEFILE_MIN_TEMPORARY (68ULL * LARGEFILE_GIB)
#define LARGEFILE_MEMORY_HEADROOM (16ULL * LARGEFILE_GIB)
#define LARGEFILE_TEMP_HEADROOM (4ULL * LARGEFILE_GIB)

#if defined(C_LINUX) && (defined(__x86_64__) || defined(_M_X64))
#define LARGEFILE_PLATFORM "linux-x86_64"
#elif defined(C_LINUX)
#define LARGEFILE_PLATFORM "linux-other"
#elif defined(__APPLE__)
#define LARGEFILE_PLATFORM "macos"
#elif defined(_WIN32)
#define LARGEFILE_PLATFORM "windows"
#else
#define LARGEFILE_PLATFORM "other"
#endif

#ifdef CLAMAV_LARGE_FILE_SUPPORT
#define LARGEFILE_BUILD_SUPPORT 1
#else
#define LARGEFILE_BUILD_SUPPORT 0
#endif

#ifdef HAVE_FD_PASSING
#define LARGEFILE_FD_PASSING 1
#else
#define LARGEFILE_FD_PASSING 0
#endif

static void set_reason(char *reason, size_t reason_size, const char *message)
{
    if ((NULL != reason) && (reason_size > 0))
        (void)snprintf(reason, reason_size, "%s", message);
}

static void set_reason_value(
    char *reason,
    size_t reason_size,
    const char *label,
    uint64_t actual,
    uint64_t required,
    const char *unit)
{
    if ((NULL != reason) && (reason_size > 0))
        (void)snprintf(reason, reason_size, "%s=%" PRIu64 "%s is below required=%" PRIu64 "%s", label, actual, unit, required, unit);
}

static int read_u64_file(const char *path, uint64_t *value, int *unlimited)
{
    FILE *stream;
    char buffer[128];
    char *end;
    unsigned long long parsed;

    if ((NULL == path) || (NULL == value) || (NULL == unlimited))
        return 0;

    stream = fopen(path, "r");
    if (NULL == stream)
        return 0;

    if (NULL == fgets(buffer, sizeof(buffer), stream)) {
        fclose(stream);
        return 0;
    }
    fclose(stream);

    if (0 == strncmp(buffer, "max", 3) &&
        (buffer[3] == '\0' || buffer[3] == '\n' || buffer[3] == '\r' || buffer[3] == ' ' || buffer[3] == '\t')) {
        *value     = UINT64_MAX;
        *unlimited = 1;
        return 1;
    }

    errno  = 0;
    parsed = strtoull(buffer, &end, 10);
    if ((errno == ERANGE) || (end == buffer))
        return 0;
    while (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')
        end++;
    if (*end != '\0')
        return 0;

    *value     = (uint64_t)parsed;
    *unlimited = 0;
    return 1;
}

#if defined(C_LINUX)
static int read_mem_available(uint64_t *available_bytes)
{
    FILE *stream;
    char line[256];
    uint64_t available_kib;

    if (NULL == available_bytes)
        return 0;

    stream = fopen("/proc/meminfo", "r");
    if (NULL == stream)
        return 0;

    available_kib = 0;
    while (fgets(line, sizeof(line), stream) != NULL) {
        if (sscanf(line, "MemAvailable: %" SCNu64 " kB", &available_kib) == 1)
            break;
    }
    fclose(stream);

    if (available_kib == 0 || available_kib > UINT64_MAX / 1024ULL)
        return 0;

    *available_bytes = available_kib * 1024ULL;
    return 1;
}

static int cgroup_headroom(uint64_t *headroom, int *bounded)
{
    static const char *const v2_limit = "/sys/fs/cgroup/memory.max";
    static const char *const v2_current = "/sys/fs/cgroup/memory.current";
    static const char *const v1_limit = "/sys/fs/cgroup/memory/memory.limit_in_bytes";
    static const char *const v1_current = "/sys/fs/cgroup/memory/memory.usage_in_bytes";
    const char *current_path = NULL;
    uint64_t limit = 0;
    uint64_t current = 0;
    int limit_unlimited = 0;
    int current_unlimited = 0;

    if ((NULL == headroom) || (NULL == bounded))
        return 0;

    if (read_u64_file(v2_limit, &limit, &limit_unlimited)) {
        current_path = v2_current;
    } else if (read_u64_file(v1_limit, &limit, &limit_unlimited)) {
        current_path = v1_current;
    } else {
        *headroom = UINT64_MAX;
        *bounded  = 0;
        return 1;
    }

    if (limit_unlimited) {
        *headroom = UINT64_MAX;
        *bounded  = 0;
        return 1;
    }

    if (!read_u64_file(current_path, &current, &current_unlimited) || current_unlimited) {
        return 0;
    }

    *headroom = (current >= limit) ? 0 : limit - current;
    *bounded  = 1;
    return 1;
}

static int effective_memory_available(uint64_t *available_bytes)
{
    uint64_t available;
    uint64_t cgroup_available;
    int cgroup_bounded;

    if (!read_mem_available(&available) ||
        !cgroup_headroom(&cgroup_available, &cgroup_bounded))
        return 0;

    if (cgroup_bounded && cgroup_available < available)
        available = cgroup_available;

    *available_bytes = available;
    return 1;
}
#endif

static int temporary_free_bytes(const char *temporary_directory, uint64_t *free_bytes)
{
#if !defined(_WIN32)
    struct statvfs stats;

    if ((NULL == temporary_directory) || (NULL == free_bytes) ||
        (statvfs(temporary_directory, &stats) != 0) ||
        (stats.f_frsize == 0) ||
        (stats.f_bavail > UINT64_MAX / (uint64_t)stats.f_frsize))
        return 0;

    *free_bytes = (uint64_t)stats.f_bavail * (uint64_t)stats.f_frsize;
    return 1;
#else
    (void)temporary_directory;
    (void)free_bytes;
    return 0;
#endif
}

static int engine_u64(
    const struct cl_engine *engine,
    enum cl_engine_field field,
    uint64_t *value)
{
    int status = CL_ERROR;
    long long result;

    if ((NULL == engine) || (NULL == value))
        return 0;

    result = cl_engine_get_num(engine, field, &status);
    if (status != CL_SUCCESS || result < 0)
        return 0;

    *value = (uint64_t)result;
    return 1;
}

void clamd_largefile_log_capabilities(const struct cl_engine *engine)
{
    uint64_t max_file_size = 0;
    uint64_t max_scan_size = 0;
    uint64_t max_matcher_work = 0;
    uint64_t max_temporary_size = 0;
    uint64_t max_contiguous_size = 0;
    uint64_t pcre_max_file_size = 0;
    uint64_t max_scan_time = 0;
    uint64_t max_files = 0;
    uint64_t max_recursion = 0;

    (void)engine_u64(engine, CL_ENGINE_MAX_FILESIZE, &max_file_size);
    (void)engine_u64(engine, CL_ENGINE_MAX_SCANSIZE, &max_scan_size);
    (void)engine_u64(engine, CL_ENGINE_MAX_MATCHER_WORK, &max_matcher_work);
    (void)engine_u64(engine, CL_ENGINE_MAX_TEMPORARY_SIZE, &max_temporary_size);
    (void)engine_u64(engine, CL_ENGINE_MAX_CONTIGUOUS_SIZE, &max_contiguous_size);
    (void)engine_u64(engine, CL_ENGINE_PCRE_MAX_FILESIZE, &pcre_max_file_size);
    (void)engine_u64(engine, CL_ENGINE_MAX_SCANTIME, &max_scan_time);
    (void)engine_u64(engine, CL_ENGINE_MAX_FILES, &max_files);
    (void)engine_u64(engine, CL_ENGINE_MAX_RECURSION, &max_recursion);

    logg(LOGG_INFO,
         "Large-file capability manifest: schema=1 platform=%s build_support=%d pointer_bits=%u size_t_bits=%u off_t_bits=%u large_file_ceiling=%" PRIu64 " logical_scan_ceiling=%" PRIu64 " matcher_work_ceiling=%" PRIu64 " temporary_ceiling=%" PRIu64 " contiguous_ceiling=%" PRIu64 " configured_max_file=%" PRIu64 " configured_max_scan=%" PRIu64 " configured_pcre_max_file=%" PRIu64 " configured_matcher_work=%" PRIu64 " configured_temporary=%" PRIu64 " configured_contiguous=%" PRIu64 " configured_scan_time_ms=%" PRIu64 " configured_max_files=%" PRIu64 " configured_max_recursion=%" PRIu64 " structured_reports=1 bytecode_abi_v2=8 fd_passing=%d parser_qualification=unclaimed\n",
         LARGEFILE_PLATFORM,
         LARGEFILE_BUILD_SUPPORT,
         (unsigned)(sizeof(void *) * CHAR_BIT),
         (unsigned)(sizeof(size_t) * CHAR_BIT),
#if !defined(_WIN32)
         (unsigned)(sizeof(off_t) * CHAR_BIT),
#else
         (unsigned)(sizeof(long long) * CHAR_BIT),
#endif
         (uint64_t)CLI_MAX_LARGE_FILESIZE,
         (uint64_t)CLI_MAX_LOGICAL_SCAN_SIZE,
         (uint64_t)CLI_MAX_MATCHER_WORK,
         (uint64_t)CLI_MAX_TEMPORARY_SIZE,
         (uint64_t)CLI_MAX_CONTIGUOUS_SIZE,
         max_file_size,
         max_scan_size,
         pcre_max_file_size,
         max_matcher_work,
         max_temporary_size,
         max_contiguous_size,
         max_scan_time,
         max_files,
         max_recursion,
         LARGEFILE_FD_PASSING);
}

int clamd_largefile_admission_check(
    const struct cl_engine *engine,
    const char *temporary_directory,
    char *reason,
    size_t reason_size)
{
    uint64_t max_file_size;
    uint64_t max_scan_size;
    uint64_t max_temporary_size;
    uint64_t max_contiguous_size;
    uint64_t required_memory;
    uint64_t required_temporary;
    uint64_t available_memory;
    uint64_t free_temporary;
    uint64_t memory_basis;
    uint64_t temporary_basis;
    const uint64_t legacy_file_size = (uint64_t)CLI_DEFAULT_MAXFILESIZE;
    const uint64_t legacy_scan_size = (uint64_t)CLI_DEFAULT_MAXSCANSIZE;

    if (NULL != reason && reason_size > 0)
        reason[0] = '\0';

    if (!engine_u64(engine, CL_ENGINE_MAX_FILESIZE, &max_file_size) ||
        !engine_u64(engine, CL_ENGINE_MAX_SCANSIZE, &max_scan_size) ||
        !engine_u64(engine, CL_ENGINE_MAX_TEMPORARY_SIZE, &max_temporary_size) ||
        !engine_u64(engine, CL_ENGINE_MAX_CONTIGUOUS_SIZE, &max_contiguous_size)) {
        set_reason(reason, reason_size, "large-file engine limits could not be read");
        return 0;
    }

    /* Ordinary ClamAV configurations retain their historical startup path.
     * The admission contract applies when a caller actually enables the
     * large-file scan envelope. */
    if (max_file_size <= legacy_file_size && max_scan_size <= legacy_scan_size)
        return 1;

    if ((sizeof(void *) < 8) || (sizeof(size_t) < 8) ||
#if !defined(_WIN32)
        (sizeof(off_t) < 8) ||
#endif
        (max_file_size > (uint64_t)SIZE_MAX) ||
        (max_scan_size > (uint64_t)SIZE_MAX) ||
        (max_temporary_size > (uint64_t)SIZE_MAX) ||
        (max_contiguous_size > (uint64_t)SIZE_MAX)) {
        set_reason(reason, reason_size, "large-file configuration requires 64-bit address and file-size types");
        return 0;
    }

    memory_basis = max_file_size;
    if (max_scan_size / 2 > memory_basis)
        memory_basis = max_scan_size / 2;
    if (memory_basis > LARGEFILE_MIN_AVAILABLE - LARGEFILE_MEMORY_HEADROOM)
        required_memory = LARGEFILE_MIN_AVAILABLE;
    else
        required_memory = memory_basis + LARGEFILE_MEMORY_HEADROOM;

    temporary_basis = max_temporary_size;
    if (temporary_basis > LARGEFILE_MIN_TEMPORARY - LARGEFILE_TEMP_HEADROOM)
        required_temporary = LARGEFILE_MIN_TEMPORARY;
    else
        required_temporary = temporary_basis + LARGEFILE_TEMP_HEADROOM;

#if defined(C_LINUX)
    if (!effective_memory_available(&available_memory)) {
        set_reason(reason, reason_size, "effective Linux/cgroup memory availability could not be measured");
        return 0;
    }
    if (available_memory < required_memory) {
        set_reason_value(reason, reason_size, "available_memory", available_memory, required_memory, " bytes");
        return 0;
    }
#else
    (void)available_memory;
    (void)required_memory;
    set_reason(reason, reason_size, "large-file daemon admission requires a measurable Linux/cgroup memory budget");
    return 0;
#endif

    if (!temporary_free_bytes(temporary_directory, &free_temporary)) {
        set_reason(reason, reason_size, "temporary-directory free space could not be measured");
        return 0;
    }
    if (free_temporary < required_temporary) {
        set_reason_value(reason, reason_size, "temporary_free", free_temporary, required_temporary, " bytes");
        return 0;
    }

    return 1;
}
