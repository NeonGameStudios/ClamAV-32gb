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
#include "optparser.h"

#include "output.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#if defined(C_LINUX)
#include <sys/resource.h>
#include <sys/vfs.h>
#endif

#define LARGEFILE_GIB (1024ULL * 1024ULL * 1024ULL)
#define LARGEFILE_LEGACY_MAX_FILE_SIZE (100ULL * 1024ULL * 1024ULL)
#define LARGEFILE_LEGACY_MAX_SCAN_SIZE (400ULL * 1024ULL * 1024ULL)
#define LARGEFILE_MIN_AVAILABLE (48ULL * LARGEFILE_GIB)
#define LARGEFILE_MIN_TEMPORARY (68ULL * LARGEFILE_GIB)
#define LARGEFILE_MEMORY_HEADROOM (16ULL * LARGEFILE_GIB)
#define LARGEFILE_TEMP_HEADROOM (4ULL * LARGEFILE_GIB)

/* Linux filesystem magic values are stable ABI values, but the headers which
 * name them are not available on every supported build environment. */
#define LARGEFILE_TMPFS_MAGIC 0x01021994ULL
#define LARGEFILE_RAMFS_MAGIC 0x858458f6ULL
#define LARGEFILE_PATH_BUFFER 4096
#define LARGEFILE_MOUNTINFO_BUFFER 16384

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

#if defined(HAVE_MMAP) && defined(HAVE_SYS_MMAN_H)
#define LARGEFILE_FILE_BACKED_MAPPING 1
#else
#define LARGEFILE_FILE_BACKED_MAPPING 0
#endif

#if defined(C_LINUX) && (defined(__x86_64__) || defined(_M_X64))
#define LARGEFILE_CERTIFIED_PLATFORM 1
#else
#define LARGEFILE_CERTIFIED_PLATFORM 0
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

int clamd_largefile_build_profile_check(
    int build_support,
    int certified_platform,
    int fd_passing,
    int file_backed_mapping,
    char *reason,
    size_t reason_size)
{
    if (NULL != reason && reason_size > 0)
        reason[0] = '\0';

    if (!build_support) {
        set_reason(reason, reason_size, "build does not provide certified large-file support");
        return 0;
    }
    if (!certified_platform) {
        set_reason(reason, reason_size, "certified large-file daemon admission is limited to Linux x86-64");
        return 0;
    }
    if (!file_backed_mapping) {
        set_reason(reason, reason_size, "build does not provide certified file-backed mapping support");
        return 0;
    }
    if (!fd_passing) {
        set_reason(reason, reason_size, "build does not provide the certified FILDES descriptor-passing path");
        return 0;
    }
    return 1;
}

int clamd_largefile_fsize_limit_check(
    int query_succeeded,
    int limit_is_infinite,
    uint64_t limit_bytes,
    uint64_t required_bytes,
    char *reason,
    size_t reason_size)
{
    if (!query_succeeded) {
        set_reason(reason, reason_size, "RLIMIT_FSIZE could not be read");
        return 0;
    }
    if (!limit_is_infinite && limit_bytes < required_bytes) {
        set_reason_value(reason, reason_size, "RLIMIT_FSIZE", limit_bytes, required_bytes, " bytes");
        return 0;
    }
    return 1;
}

int clamd_largefile_worker_count_check(
    int query_succeeded,
    uint64_t max_threads,
    char *reason,
    size_t reason_size)
{
    if (!query_succeeded) {
        set_reason(reason, reason_size, "MaxThreads could not be read");
        return 0;
    }
    if (max_threads != 1) {
        if ((NULL != reason) && (reason_size > 0))
            (void)snprintf(reason, reason_size, "MaxThreads=%" PRIu64 " is outside the certified single-worker profile", max_threads);
        return 0;
    }
    return 1;
}

int clamd_queue_limit_calculate(
    uint64_t nofile_limit,
    uint64_t max_recursion,
    uint64_t max_threads,
    uint64_t configured_queue,
    uint64_t *max_queue_limit,
    uint64_t *effective_queue)
{
    const uint64_t clamdfiles = 6;
    uint64_t recursion_fds;
    uint64_t required_fds;
    uint64_t queue_limit;
    uint64_t desired_queue;

    if ((NULL == max_queue_limit) || (NULL == effective_queue) ||
        (max_threads == 0) || (max_threads > (uint64_t)INT_MAX) ||
        (configured_queue == 0) || (configured_queue > (uint64_t)INT_MAX))
        return 0;

    if (max_recursion > UINT64_MAX / max_threads)
        return 0;
    recursion_fds = max_recursion * max_threads;
    if (recursion_fds > UINT64_MAX - clamdfiles)
        return 0;
    required_fds = recursion_fds + clamdfiles;

    /* RLIM_INFINITY is represented as the maximum unsigned value on the
     * supported Unix targets. A finite limit below the required descriptor
     * floor still leaves the one-worker queue floor, matching the legacy
     * clamd policy without allowing unsigned subtraction to wrap. */
    if (nofile_limit <= required_fds) {
        queue_limit = max_threads;
    } else {
        uint64_t available = nofile_limit - required_fds;

        if (available > UINT64_MAX - max_threads)
            queue_limit = UINT64_MAX;
        else
            queue_limit = available + max_threads;
        if (queue_limit < max_threads)
            queue_limit = max_threads;
    }
    if (queue_limit > (uint64_t)INT_MAX)
        queue_limit = (uint64_t)INT_MAX;

    *max_queue_limit = queue_limit;

    if (configured_queue < max_threads)
        configured_queue = max_threads;
    if (configured_queue > queue_limit) {
        configured_queue = queue_limit;
    } else {
        desired_queue = (max_threads > UINT64_MAX / 2) ? UINT64_MAX : max_threads * 2;
        if (configured_queue < desired_queue && configured_queue < queue_limit)
            configured_queue = (desired_queue < queue_limit) ? desired_queue : queue_limit;
    }

    *effective_queue = configured_queue;
    return 1;
}

int clamd_largefile_temporary_filesystem_check(
    int query_succeeded,
    uint64_t filesystem_magic,
    char *reason,
    size_t reason_size)
{
    if (!query_succeeded) {
        set_reason(reason, reason_size, "temporary-directory filesystem type could not be measured");
        return 0;
    }
    if (filesystem_magic == LARGEFILE_TMPFS_MAGIC) {
        set_reason(reason, reason_size, "temporary directory is hosted on tmpfs");
        return 0;
    }
    if (filesystem_magic == LARGEFILE_RAMFS_MAGIC) {
        set_reason(reason, reason_size, "temporary directory is hosted on ramfs");
        return 0;
    }
    return 1;
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
    if (fclose(stream) != 0)
        return 0;

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
    if (fclose(stream) != 0)
        return 0;

    if (available_kib == 0 || available_kib > UINT64_MAX / 1024ULL)
        return 0;

    *available_bytes = available_kib * 1024ULL;
    return 1;
}

static int token_list_contains(const char *list, const char *token)
{
    const char *cursor;
    size_t token_length;

    if ((NULL == list) || (NULL == token) || (token[0] == '\0'))
        return 0;

    cursor       = list;
    token_length = strlen(token);
    while (*cursor != '\0') {
        const char *end = strchr(cursor, ',');
        size_t length   = (NULL == end) ? strlen(cursor) : (size_t)(end - cursor);

        if ((length == token_length) && (0 == strncmp(cursor, token, length)))
            return 1;
        if (NULL == end)
            break;
        cursor = end + 1;
    }
    return 0;
}

static int decode_mountinfo_path(char *path)
{
    char *source;
    char *destination;

    if (NULL == path)
        return 0;

    source      = path;
    destination = path;
    while (*source != '\0') {
        if ((source[0] == '\\') &&
            (source[1] >= '0') && (source[1] <= '7') &&
            (source[2] >= '0') && (source[2] <= '7') &&
            (source[3] >= '0') && (source[3] <= '7')) {
            unsigned value = (unsigned)(source[1] - '0') * 64U +
                             (unsigned)(source[2] - '0') * 8U +
                             (unsigned)(source[3] - '0');

            if (value == 0U)
                return 0;
            *destination++ = (char)value;
            source += 4;
        } else {
            *destination++ = *source++;
        }
    }
    *destination = '\0';
    return 1;
}

/* Return 1 for the broadest visible matching mount, so ancestor limits are not
 * hidden by a second subtree bind mount. Return 0 when the controller is not
 * mounted for this membership and -1 when mount information is unreadable or
 * malformed. */
static int find_cgroup_mount(
    const char *mountinfo_path,
    int unified,
    const char *membership,
    char *mount_root,
    size_t mount_root_size,
    char *mount_point,
    size_t mount_point_size)
{
    FILE *stream;
    char line[LARGEFILE_MOUNTINFO_BUFFER];
    int found = 0;
    size_t selected_root_length = 0;

    if ((NULL == mountinfo_path) || (NULL == membership) ||
        (membership[0] != '/') || (NULL == mount_root) ||
        (mount_root_size == 0) || (NULL == mount_point) ||
        (mount_point_size == 0))
        return -1;

    stream = fopen(mountinfo_path, "r");
    if (NULL == stream)
        return -1;

    while (NULL != fgets(line, sizeof(line), stream)) {
        char root[LARGEFILE_PATH_BUFFER];
        char point[LARGEFILE_PATH_BUFFER];
        char filesystem[32];
        char options[LARGEFILE_PATH_BUFFER];
        char *separator;
        int matches;
        size_t root_length;

        if ((NULL == strchr(line, '\n')) && !feof(stream)) {
            fclose(stream);
            return -1;
        }
        separator = strstr(line, " - ");
        if (NULL == separator)
            continue;
        if (2 != sscanf(line, "%*s %*s %*s %4095s %4095s", root, point))
            continue;
        if (2 != sscanf(separator + 3, "%31s %*s %4095s", filesystem, options))
            continue;

        matches = unified ? (0 == strcmp(filesystem, "cgroup2")) :
                            ((0 == strcmp(filesystem, "cgroup")) && token_list_contains(options, "memory"));
        if (!matches)
            continue;
        if (!decode_mountinfo_path(root) || !decode_mountinfo_path(point) ||
            (root[0] != '/') || (point[0] != '/') ||
            (strlen(root) >= mount_root_size) ||
            (strlen(point) >= mount_point_size)) {
            fclose(stream);
            return -1;
        }
        root_length = strlen(root);
        if ((0 != strcmp(root, "/")) &&
            (0 != strcmp(root, membership)) &&
            ((0 != strncmp(root, membership, root_length)) ||
             (membership[root_length] != '/')))
            continue;
        if (found && (root_length >= selected_root_length))
            continue;
        (void)snprintf(mount_root, mount_root_size, "%s", root);
        (void)snprintf(mount_point, mount_point_size, "%s", point);
        selected_root_length = root_length;
        found                = 1;
    }

    if (ferror(stream)) {
        fclose(stream);
        return -1;
    }
    if (fclose(stream) != 0)
        return -1;
    return found;
}

/* Return 1 for one matching membership, 0 when the controller is absent, and
 * -1 when proc membership data is unreadable, malformed, or ambiguous. */
static int find_cgroup_membership(
    const char *cgroup_path,
    int unified,
    char *membership,
    size_t membership_size)
{
    FILE *stream;
    char line[LARGEFILE_MOUNTINFO_BUFFER];
    int found = 0;

    if ((NULL == cgroup_path) || (NULL == membership) || (membership_size == 0))
        return -1;

    stream = fopen(cgroup_path, "r");
    if (NULL == stream)
        return -1;

    while (NULL != fgets(line, sizeof(line), stream)) {
        char *first;
        char *second;
        char *controllers;
        char *group;
        size_t length;
        int matches;

        if ((NULL == strchr(line, '\n')) && !feof(stream)) {
            fclose(stream);
            return -1;
        }
        first = strchr(line, ':');
        if (NULL == first)
            continue;
        second = strchr(first + 1, ':');
        if (NULL == second)
            continue;
        *second      = '\0';
        controllers = first + 1;
        group        = second + 1;
        length       = strcspn(group, "\r\n");
        group[length] = '\0';
        matches = unified ? (controllers[0] == '\0') : token_list_contains(controllers, "memory");
        if (!matches)
            continue;
        if (found || (group[0] != '/') || (strlen(group) >= membership_size)) {
            fclose(stream);
            return -1;
        }
        (void)snprintf(membership, membership_size, "%s", group);
        found = 1;
    }

    if (ferror(stream)) {
        fclose(stream);
        return -1;
    }
    if (fclose(stream) != 0)
        return -1;
    return found;
}

static int join_cgroup_membership(
    const char *mount_root,
    const char *mount_point,
    const char *membership,
    char *resolved,
    size_t resolved_size)
{
    const char *relative;
    size_t root_length;
    size_t point_length;
    int written;

    if ((NULL == mount_root) || (NULL == mount_point) ||
        (NULL == membership) || (NULL == resolved) ||
        (resolved_size == 0) || (mount_root[0] != '/') ||
        (mount_point[0] != '/') || (membership[0] != '/'))
        return 0;

    root_length = strlen(mount_root);
    if (0 == strcmp(mount_root, "/"))
        relative = membership;
    else if (0 == strcmp(mount_root, membership))
        relative = "";
    else if ((0 == strncmp(mount_root, membership, root_length)) &&
             (membership[root_length] == '/'))
        relative = membership + root_length;
    else
        return 0;

    point_length = strlen(mount_point);
    while ((point_length > 1) && (mount_point[point_length - 1] == '/'))
        point_length--;

    if ((point_length == 1) && (mount_point[0] == '/')) {
        if (relative[0] == '/')
            relative++;
        written = snprintf(resolved, resolved_size, "/%s", relative);
    } else {
        written = snprintf(resolved, resolved_size, "%.*s%s", (int)point_length, mount_point, relative);
    }
    return (written >= 0) && ((size_t)written < resolved_size);
}

static int path_file_state(const char *path)
{
    struct stat status;

    if (stat(path, &status) == 0)
        return S_ISREG(status.st_mode) ? 1 : -1;
    if ((errno == ENOENT) || (errno == ENOTDIR))
        return 0;
    return -1;
}

static int cgroup_hierarchy_headroom(
    const char *membership_path,
    const char *mount_point,
    int unified,
    uint64_t *headroom,
    int *bounded,
    int *controller_present)
{
    char directory[LARGEFILE_PATH_BUFFER];
    char mount[LARGEFILE_PATH_BUFFER];
    size_t mount_length;
    uint64_t minimum = UINT64_MAX;
    int finite = 0;
    int present = 0;

    if ((NULL == membership_path) || (NULL == mount_point) ||
        (NULL == headroom) || (NULL == bounded) ||
        (NULL == controller_present) ||
        (strlen(membership_path) >= sizeof(directory)) ||
        (strlen(mount_point) >= sizeof(mount)))
        return 0;

    (void)snprintf(directory, sizeof(directory), "%s", membership_path);
    (void)snprintf(mount, sizeof(mount), "%s", mount_point);
    mount_length = strlen(mount);
    while ((mount_length > 1) && (mount[mount_length - 1] == '/'))
        mount[--mount_length] = '\0';

    if ((0 != strncmp(directory, mount, mount_length)) ||
        ((strlen(directory) > mount_length) && (mount_length > 1) &&
         (directory[mount_length] != '/')))
        return 0;

    for (;;) {
        char limit_path[LARGEFILE_PATH_BUFFER];
        char current_path[LARGEFILE_PATH_BUFFER];
        const char *limit_name   = unified ? "memory.max" : "memory.limit_in_bytes";
        const char *current_name = unified ? "memory.current" : "memory.usage_in_bytes";
        uint64_t limit;
        uint64_t current;
        int limit_unlimited;
        int current_unlimited;
        int limit_state;
        int current_state;
        int limit_written;
        int current_written;

        limit_written = snprintf(limit_path, sizeof(limit_path), "%s/%s", directory, limit_name);
        current_written = snprintf(current_path, sizeof(current_path), "%s/%s", directory, current_name);
        if ((limit_written < 0) || ((size_t)limit_written >= sizeof(limit_path)) ||
            (current_written < 0) || ((size_t)current_written >= sizeof(current_path)))
            return 0;

        limit_state   = path_file_state(limit_path);
        current_state = path_file_state(current_path);
        if ((limit_state < 0) || (current_state < 0) ||
            ((limit_state == 0) != (current_state == 0)))
            return 0;
        if (limit_state == 1) {
            present = 1;
            if (!read_u64_file(limit_path, &limit, &limit_unlimited) ||
                !read_u64_file(current_path, &current, &current_unlimited) ||
                current_unlimited)
                return 0;
            if (!limit_unlimited) {
                uint64_t available = (current >= limit) ? 0 : limit - current;

                if (!finite || (available < minimum))
                    minimum = available;
                finite = 1;
            }
        }

        if (0 == strcmp(directory, mount))
            break;
        {
            char *separator = strrchr(directory, '/');

            if (NULL == separator)
                return 0;
            if (separator == directory)
                directory[1] = '\0';
            else
                *separator = '\0';
            if ((0 != strncmp(directory, mount, mount_length)) ||
                ((strlen(directory) > mount_length) && (mount_length > 1) &&
                 (directory[mount_length] != '/')))
                return 0;
        }
    }

    *headroom = finite ? minimum : UINT64_MAX;
    *bounded  = finite;
    *controller_present = present;
    return 1;
}

int clamd_largefile_cgroup_headroom_from_files(
    const char *proc_cgroup_path,
    const char *proc_mountinfo_path,
    uint64_t *headroom,
    int *bounded)
{
    char mount_root[LARGEFILE_PATH_BUFFER];
    char mount_point[LARGEFILE_PATH_BUFFER];
    char membership[LARGEFILE_PATH_BUFFER];
    char resolved[LARGEFILE_PATH_BUFFER];
    int unified;

    if ((NULL == headroom) || (NULL == bounded))
        return 0;

    for (unified = 1; unified >= 0; unified--) {
        int mount_status;
        int membership_status;
        int controller_present;

        membership_status = find_cgroup_membership(
            proc_cgroup_path,
            unified,
            membership,
            sizeof(membership));
        if (membership_status < 0)
            return 0;
        if (membership_status == 0)
            continue;

        mount_status = find_cgroup_mount(
            proc_mountinfo_path,
            unified,
            membership,
            mount_root,
            sizeof(mount_root),
            mount_point,
            sizeof(mount_point));
        if (mount_status < 0)
            return 0;
        if (mount_status == 0)
            continue;
        if (!join_cgroup_membership(
                mount_root,
                mount_point,
                membership,
                resolved,
                sizeof(resolved)))
            return 0;
        if (!cgroup_hierarchy_headroom(
                resolved,
                mount_point,
                unified,
                headroom,
                bounded,
                &controller_present))
            return 0;
        if (controller_present)
            return 1;
    }

    *headroom = UINT64_MAX;
    *bounded  = 0;
    return 1;
}

static int cgroup_headroom(uint64_t *headroom, int *bounded)
{
    return clamd_largefile_cgroup_headroom_from_files(
        "/proc/self/cgroup",
        "/proc/self/mountinfo",
        headroom,
        bounded);
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

#if defined(C_LINUX)
static int current_fsize_limit(uint64_t *limit_bytes, int *limit_is_infinite)
{
    struct rlimit limit;

    if ((NULL == limit_bytes) || (NULL == limit_is_infinite) ||
        (getrlimit(RLIMIT_FSIZE, &limit) != 0))
        return 0;

    if (limit.rlim_cur == RLIM_INFINITY) {
        *limit_bytes       = UINT64_MAX;
        *limit_is_infinite = 1;
    } else {
        *limit_bytes       = (uint64_t)limit.rlim_cur;
        *limit_is_infinite = 0;
    }
    return 1;
}

static int temporary_filesystem_type(const char *temporary_directory, uint64_t *filesystem_magic)
{
    struct statfs stats;

    if ((NULL == temporary_directory) || (NULL == filesystem_magic) ||
        (statfs(temporary_directory, &stats) != 0))
        return 0;

    *filesystem_magic = (uint64_t)(unsigned long)stats.f_type;
    return 1;
}
#endif

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

static int option_u64(const struct optstruct *opts, const char *name, uint64_t *value)
{
    const struct optstruct *option;

    if ((NULL == opts) || (NULL == name) || (NULL == value))
        return 0;

    option = optget(opts, name);
    if ((NULL == option) || (option->numarg < 0))
        return 0;

    *value = (uint64_t)option->numarg;
    return 1;
}

void clamd_largefile_log_capabilities(const struct cl_engine *engine)
{
    uint64_t max_file_size       = 0;
    uint64_t max_scan_size       = 0;
    uint64_t max_matcher_work    = 0;
    uint64_t max_temporary_size  = 0;
    uint64_t max_contiguous_size = 0;
    uint64_t pcre_max_file_size  = 0;
    uint64_t max_scan_time       = 0;
    uint64_t max_files           = 0;
    uint64_t max_recursion       = 0;

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
         "Large-file capability manifest: schema=2 platform=%s build_support=%d pointer_bits=%u size_t_bits=%u off_t_bits=%u large_file_ceiling=%" PRIu64 " logical_scan_ceiling=%" PRIu64 " matcher_work_ceiling=%" PRIu64 " temporary_ceiling=%" PRIu64 " contiguous_ceiling=%" PRIu64 " configured_max_file=%" PRIu64 " configured_max_scan=%" PRIu64 " configured_pcre_max_file=%" PRIu64 " configured_matcher_work=%" PRIu64 " configured_temporary=%" PRIu64 " configured_contiguous=%" PRIu64 " configured_scan_time_ms=%" PRIu64 " configured_max_files=%" PRIu64 " configured_max_recursion=%" PRIu64 " structured_reports=1 bytecode_abi_v2=8 fd_passing=%d file_backed_mapping=%d parser_qualification=unclaimed\n",
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
         LARGEFILE_FD_PASSING,
         LARGEFILE_FILE_BACKED_MAPPING);
}

int clamd_largefile_admission_check(
    const struct cl_engine *engine,
    const struct optstruct *opts,
    const char *temporary_directory,
    char *reason,
    size_t reason_size)
{
    uint64_t max_file_size;
    uint64_t max_scan_size;
    uint64_t max_matcher_work;
    uint64_t max_temporary_size;
    uint64_t max_contiguous_size;
    uint64_t pcre_max_file_size;
    uint64_t stream_max_length = 0;
    uint64_t onaccess_max_file_size = 0;
    uint64_t max_threads;
    uint64_t max_ingress_size;
    uint64_t required_memory;
    uint64_t required_temporary;
    uint64_t available_memory;
    uint64_t free_temporary;
    uint64_t fsize_limit;
    uint64_t filesystem_magic;
    uint64_t memory_basis;
    uint64_t temporary_basis;
    int fsize_limit_is_infinite;
    const uint64_t legacy_file_size = LARGEFILE_LEGACY_MAX_FILE_SIZE;
    const uint64_t legacy_scan_size = LARGEFILE_LEGACY_MAX_SCAN_SIZE;

    if (NULL != reason && reason_size > 0)
        reason[0] = '\0';

    if (!engine_u64(engine, CL_ENGINE_MAX_FILESIZE, &max_file_size) ||
        !engine_u64(engine, CL_ENGINE_MAX_SCANSIZE, &max_scan_size) ||
        !engine_u64(engine, CL_ENGINE_MAX_MATCHER_WORK, &max_matcher_work) ||
        !engine_u64(engine, CL_ENGINE_MAX_TEMPORARY_SIZE, &max_temporary_size) ||
        !engine_u64(engine, CL_ENGINE_MAX_CONTIGUOUS_SIZE, &max_contiguous_size) ||
        !engine_u64(engine, CL_ENGINE_PCRE_MAX_FILESIZE, &pcre_max_file_size)) {
        set_reason(reason, reason_size, "large-file engine limits could not be read");
        return 0;
    }

    /* Stream and on-access limits are front-end admission controls rather
     * than engine fields. They can still authorize large disk-backed input,
     * so they must participate in the daemon's large-file startup decision. */
    if (!option_u64(opts, "StreamMaxLength", &stream_max_length))
        stream_max_length = max_file_size;
    else if (stream_max_length == 0)
        /* Zero selects the certified ceiling for this front-end option. */
        stream_max_length = CLI_MAX_LARGE_FILESIZE;
    if (!option_u64(opts, "OnAccessMaxFileSize", &onaccess_max_file_size))
        onaccess_max_file_size = max_file_size;
    else if (onaccess_max_file_size == 0)
        /* Zero selects the certified ceiling for this front-end option. */
        onaccess_max_file_size = CLI_MAX_LARGE_FILESIZE;

    max_ingress_size = max_file_size;
    if (stream_max_length > max_ingress_size)
        max_ingress_size = stream_max_length;
    if (onaccess_max_file_size > max_ingress_size)
        max_ingress_size = onaccess_max_file_size;

    if (max_scan_size == 0) {
        set_reason(reason, reason_size, "MaxScanSize=0 disables the certified 64 GiB logical scan budget");
        return 0;
    }

    /* Ordinary ClamAV configurations retain their historical startup path.
     * The admission contract applies when a caller actually enables the
     * large-file scan envelope. */
    if (max_ingress_size <= legacy_file_size && max_scan_size <= legacy_scan_size &&
        pcre_max_file_size <= legacy_file_size)
        return 1;

    if (!clamd_largefile_build_profile_check(
            LARGEFILE_BUILD_SUPPORT,
            LARGEFILE_CERTIFIED_PLATFORM,
            LARGEFILE_FD_PASSING,
            LARGEFILE_FILE_BACKED_MAPPING,
            reason,
            reason_size)) {
        return 0;
    }

    if (!option_u64(opts, "MaxThreads", &max_threads)) {
        (void)clamd_largefile_worker_count_check(0, 0, reason, reason_size);
        return 0;
    }
    if (!clamd_largefile_worker_count_check(1, max_threads, reason, reason_size))
        return 0;

    if ((sizeof(void *) < 8) || (sizeof(size_t) < 8) ||
#if !defined(_WIN32)
        (sizeof(off_t) < 8) ||
#endif
        (max_file_size > (uint64_t)SIZE_MAX) ||
        (max_scan_size > (uint64_t)SIZE_MAX) ||
        (max_matcher_work > (uint64_t)SIZE_MAX) ||
        (max_temporary_size > (uint64_t)SIZE_MAX) ||
        (max_contiguous_size > (uint64_t)SIZE_MAX) ||
        (pcre_max_file_size > (uint64_t)SIZE_MAX)) {
        set_reason(reason, reason_size, "large-file configuration requires 64-bit address and file-size types");
        return 0;
    }

#if defined(C_LINUX)
    if (!current_fsize_limit(&fsize_limit, &fsize_limit_is_infinite)) {
        (void)clamd_largefile_fsize_limit_check(0, 0, 0, max_ingress_size, reason, reason_size);
        return 0;
    }
    if (!clamd_largefile_fsize_limit_check(
            1,
            fsize_limit_is_infinite,
            fsize_limit,
            max_ingress_size,
            reason,
            reason_size)) {
        return 0;
    }

    if (!temporary_filesystem_type(temporary_directory, &filesystem_magic)) {
        (void)clamd_largefile_temporary_filesystem_check(0, 0, reason, reason_size);
        return 0;
    }
    if (!clamd_largefile_temporary_filesystem_check(1, filesystem_magic, reason, reason_size))
        return 0;
#else
    (void)fsize_limit;
    (void)filesystem_magic;
    (void)fsize_limit_is_infinite;
#endif

    memory_basis = max_file_size;
    if (max_scan_size / 2 > memory_basis)
        memory_basis = max_scan_size / 2;
    if (max_contiguous_size > memory_basis)
        memory_basis = max_contiguous_size;
    if (pcre_max_file_size > memory_basis)
        memory_basis = pcre_max_file_size;
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
