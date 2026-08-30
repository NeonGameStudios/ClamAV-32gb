/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009-2013 Sourcefire, Inc.
 *
 *  Authors: aCaB <acab@clamav.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

/* an mmap "replacement" which doesn't suck */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <libgen.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef ANONYMOUS_MAP
#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif
#endif
#include <errno.h>

#ifdef C_LINUX
#include <pthread.h>
#endif

#include "clamav.h"
#include "others.h"
#include "str.h"

#define FM_MASK_COUNT 0x3fffffff
#define FM_MASK_PAGED 0x40000000
#define FM_MASK_SEEN 0x80000000
#define FM_MASK_LOCKED FM_MASK_SEEN
/* 2 high bits:
00 - not seen - not paged - N/A
01 -    N/A   -   paged   - not locked
10 -   seen   - not paged - N/A
11 -    N/A   -   paged   - locked
*/

/* FIXME: tune this stuff */
#define UNPAGE_THRSHLD_LO 4 * 1024 * 1024
#define UNPAGE_THRSHLD_HI 8 * 1024 * 1024
#define FMAP_AGING_SCAN_BUDGET 8192
#define FMAP_AGING_FREE_BUDGET 4096
#define READAHEAD_PAGES 8

#if defined(ANONYMOUS_MAP) && defined(C_LINUX) && defined(CL_THREAD_SAFE)
/*
   WORKAROUND
   Relieve some stress on mmap_sem.
   When mmap_sem is heavily hammered, the scheduler
   tends to fail to wake us up properly.
*/
pthread_mutex_t fmap_mutex = PTHREAD_MUTEX_INITIALIZER;
#define fmap_lock pthread_mutex_lock(&fmap_mutex)
#define fmap_unlock pthread_mutex_unlock(&fmap_mutex);
#else
#define fmap_lock
#define fmap_unlock
#endif

#ifndef MADV_DONTFORK
#define MADV_DONTFORK 0
#endif

#define fmap_bitmap (m->bitmap)

static inline uint64_t fmap_align_items(uint64_t sz, uint64_t al);
static inline uint64_t fmap_align_to(uint64_t sz, uint64_t al);
static inline uint64_t fmap_which_page(fmap_t *m, size_t at);
static inline fmap_t *fmap_aging_owner(fmap_t *m);

/* The public handle fmap stores its source position as size_t but passes it
 * to a callback whose coordinate type is off_t.  Require a round-trip so an
 * unrepresentable positive size_t cannot become a different, valid-looking
 * off_t coordinate on a narrower or differently signed build. */
static int fmap_offset_fits_off_t(size_t offset)
{
    off_t converted = (off_t)offset;

    return converted >= 0 && (size_t)converted == offset;
}

#ifdef ANONYMOUS_MAP
static void fmap_release_gets_pages(fmap_t *m, uint64_t first_page, uint64_t last_page);
#endif

static const void *handle_need(fmap_t *m, size_t at, size_t len, int lock);
static void handle_unneed_off(fmap_t *m, size_t at, size_t len);
static const void *handle_need_offstr(fmap_t *m, size_t at, size_t len_hint);
static const void *handle_gets(fmap_t *m, char *dst, size_t *at, size_t max_len);

static void unmap_mmap(fmap_t *m);
static void unmap_malloc(fmap_t *m);

#ifndef _WIN32
/* pread proto here in order to avoid the use of XOPEN and BSD_SOURCE
   which may in turn prevent some mmap constants to be defined */
ssize_t pread(int fd, void *buf, size_t count, off_t offset);

/* vvvvv POSIX STUFF BELOW vvvvv */
static off_t pread_cb(void *handle, void *buf, size_t count, off_t offset)
{
    return pread((int)(ssize_t)handle, buf, count, offset);
}

fmap_t *fmap_check_empty(int fd, off_t offset, size_t len, int *empty, const char *name, const char *path)
{
    STATBUF st;
    fmap_t *m = NULL;

    *empty = 0;
    if (FSTAT(fd, &st)) {
        cli_warnmsg("fmap: fstat failed\n");
        return NULL;
    }

    if (!len) len = st.st_size - offset; /* bound checked later */
    if (!len) {
        cli_dbgmsg("fmap: attempted void mapping\n");
        *empty = 1;
        return NULL;
    }
    if (!CLI_ISCONTAINED_0_TO(st.st_size, offset, len)) {
        cli_warnmsg("fmap: attempted oof mapping\n");
        return NULL;
    }
    m = cl_fmap_open_handle((void *)(ssize_t)fd, offset, len, pread_cb, 1);
    if (!m)
        return NULL;
    m->handle_is_fd = true;
    m->mtime        = (uint64_t)st.st_mtime;

    if (NULL != name) {
        m->name = cli_safer_strdup(name);
        if (NULL == m->name) {
            fmap_free(m);
            return NULL;
        }
    }

    if (NULL != path) {
        m->path = cli_safer_strdup(path);
        if (NULL == m->path) {
            fmap_free(m);
            return NULL;
        }
    }

    return m;
}
#else
/* vvvvv WIN32 STUFF BELOW vvvvv */
static void unmap_win32(fmap_t *m)
{
    if (NULL != m) {
        if (NULL != m->data) {
            UnmapViewOfFile(m->data);
        }
        if (NULL != m->windows_map_handle) {
            CloseHandle(m->windows_map_handle);
        }
        if (NULL != m->name) {
            free(m->name);
        }
        if (NULL != m->path) {
            free(m->path);
        }
        free((void *)m);
    }
}

fmap_t *fmap_check_empty(int fd, off_t offset, size_t len, int *empty, const char *name, const char *path)
{ /* WIN32 */
    uint64_t pages, mapsz;
    int pgsz = cli_getpagesize();
    STATBUF st;
    fmap_t *m = NULL;
    const void *data;
    HANDLE windows_file_handle;
    HANDLE windows_map_handle;

    *empty = 0;
    if (FSTAT(fd, &st)) {
        cli_warnmsg("fmap: fstat failed\n");
        return NULL;
    }
    if (offset < 0 || offset != fmap_align_to(offset, pgsz)) {
        cli_warnmsg("fmap: attempted mapping with unaligned offset\n");
        return NULL;
    }
    if (!len) len = st.st_size - offset; /* bound checked later */
    if (!len) {
        cli_dbgmsg("fmap: attempted void mapping\n");
        *empty = 1;
        return NULL;
    }
    if (!CLI_ISCONTAINED_0_TO(st.st_size, offset, len)) {
        cli_warnmsg("fmap: attempted oof mapping\n");
        return NULL;
    }

    pages = fmap_align_items(len, pgsz);

    if ((windows_file_handle = (HANDLE)_get_osfhandle(fd)) == INVALID_HANDLE_VALUE) {
        cli_errmsg("fmap: cannot get a valid handle for descriptor %d\n", fd);
        return NULL;
    }
    if (!(windows_map_handle = CreateFileMapping(windows_file_handle, NULL, PAGE_READONLY, (DWORD)((len >> 31) >> 1), (DWORD)len, NULL))) {
        cli_errmsg("fmap: cannot create a map of descriptor %d\n", fd);
        return NULL;
    }
    if (!(data = MapViewOfFile(windows_map_handle, FILE_MAP_READ, (DWORD)((offset >> 31) >> 1), (DWORD)(offset), len))) {
        cli_errmsg("fmap: cannot map file descriptor %d\n", fd);
        CloseHandle(windows_map_handle);
        return NULL;
    }
    if (!(m = cl_fmap_open_memory(data, len))) {
        cli_errmsg("fmap: cannot allocate fmap_t\n", fd);
        UnmapViewOfFile(data);
        CloseHandle(windows_map_handle);
        return NULL;
    }
    m->handle              = (void *)(size_t)fd;
    m->handle_is_fd        = true;
    m->windows_file_handle = (void *)windows_file_handle;
    m->windows_map_handle  = (void *)windows_map_handle;
    m->unmap               = unmap_win32;

    if (NULL != name) {
        m->name = cli_safer_strdup(name);
        if (NULL == m->name) {
            fmap_free(m);
            return NULL;
        }
    }

    if (NULL != path) {
        m->path = cli_safer_strdup(path);
        if (NULL == m->path) {
            fmap_free(m);
            return NULL;
        }
    }

    return m;
}
#endif /* _WIN32 */

/* vvvvv SHARED STUFF BELOW vvvvv */

static bool fmap_add_size(size_t left, size_t right, size_t *result)
{
    if (NULL == result || right > SIZE_MAX - left)
        return false;

    *result = left + right;
    return true;
}

static bool fmap_range_contained(
    size_t base,
    size_t extent,
    size_t sub,
    size_t length,
    bool allow_empty)
{
    size_t end;

    if (extent == 0 || sub < base || base > SIZE_MAX - extent)
        return false;

    end = base + extent;
    if (length == 0)
        return allow_empty && sub <= end;

    if (length > extent || sub > SIZE_MAX - length)
        return false;

    return sub - base <= extent - length;
}

fmap_t *fmap_duplicate(cl_fmap_t *map, size_t offset, size_t length, const char *name)
{
    cl_error_t status        = CL_ERROR;
    cl_fmap_t *duplicate_map = NULL;
    size_t nested_offset;
    size_t real_len;

    if (NULL == map) {
        cli_warnmsg("fmap_duplicate: map is NULL!\n");
        goto done;
    }

    duplicate_map = malloc(sizeof(cl_fmap_t));
    if (!duplicate_map) {
        cli_warnmsg("fmap_duplicate: map allocation failed\n");
        goto done;
    }

    /* Duplicate the state of the original map */
    memcpy(duplicate_map, map, sizeof(cl_fmap_t));
    if (NULL == duplicate_map->aging_owner)
        duplicate_map->aging_owner = map;
    /* Clear the pointers that need to be unique pointers. */
    duplicate_map->name = NULL;
    duplicate_map->path = NULL;

    if (offset > map->len) {
        /* invalid offset, exceeds length of map */
        cli_warnmsg("fmap_duplicate: requested offset exceeds end of map\n");
        goto done;
    }

    if (!fmap_add_size(map->nested_offset, map->len, &real_len)) {
        cli_warnmsg("fmap_duplicate: source nested length overflow\n");
        goto done;
    }
    duplicate_map->real_len = real_len;

    if (offset > 0 || length < map->len) {
        /*
         * Caller requested a window into the current map, not the whole map.
         */

        /* Set the new nested offset and (nested) length for the new map */
        /* Note: We can't change offset because then we'd have to discard/move cached
         * data, instead use nested_offset to reuse the already cached data */
        if (!fmap_add_size(duplicate_map->nested_offset, offset, &nested_offset)) {
            cli_warnmsg("fmap_duplicate: nested offset overflow\n");
            goto done;
        }
        duplicate_map->nested_offset = nested_offset;
        duplicate_map->len           = MIN(length, map->len - offset);

        /* The real_len is the nested_offset + the len of the nested fmap.
           real_len is mostly just a shorthand for when doing bounds checking.
           We do not need to keep track of the original length of the OG fmap */
        if (!fmap_add_size(duplicate_map->nested_offset, duplicate_map->len, &real_len)) {
            cli_warnmsg("fmap_duplicate: nested length overflow\n");
            goto done;
        }
        duplicate_map->real_len = real_len;

        if (!fmap_range_contained(map->nested_offset, map->len,
                                  duplicate_map->nested_offset, duplicate_map->len, true)) {
            cli_warnmsg("fmap_duplicate: internal map error: %zu, %zu; %zu, %zu\n",
                        map->nested_offset, map->real_len,
                        duplicate_map->nested_offset, duplicate_map->real_len);
        }

        /* This also means the hash will be different.
         * Clear the have_<hash> flags.
         * It will be calculated when next it is needed. */
        memset(duplicate_map->will_need_hash, 0, sizeof(duplicate_map->will_need_hash));
        memset(duplicate_map->have_hash, 0, sizeof(duplicate_map->have_hash));
    }

    if (NULL != name) {
        duplicate_map->name = cli_safer_strdup(name);
        if (NULL == duplicate_map->name) {
            status = CL_EMEM;
            goto done;
        }
    } else {
        duplicate_map->name = NULL;
    }

    /* Duplicate the path if it exists */
    if (NULL != map->path) {
        duplicate_map->path = cli_safer_strdup(map->path);
        if (NULL == duplicate_map->path) {
            status = CL_EMEM;
            goto done;
        }
    } else {
        duplicate_map->path = NULL;
    }

    status = CL_SUCCESS;

done:
    if (CL_SUCCESS != status) {
        if (NULL != duplicate_map) {
            if (NULL != duplicate_map->name) {
                free(duplicate_map->name);
                duplicate_map->name = NULL;
            }
            if (NULL != duplicate_map->path) {
                free(duplicate_map->path);
                duplicate_map->path = NULL;
            }
            free(duplicate_map);
            duplicate_map = NULL;
        }
    }

    return duplicate_map;
}

void free_duplicate_fmap(cl_fmap_t *map)
{
    if (NULL != map) {
        if (NULL != map->name) {
            free(map->name);
            map->name = NULL;
        }
        if (NULL != map->path) {
            free(map->path);
            map->path = NULL;
        }
        free(map);
    }
}

static void unmap_handle(fmap_t *m)
{
    if (NULL != m) {
        if (NULL != m->data) {
            if (m->aging) {
                unmap_mmap(m);
            } else {
                free((void *)m->data);
            }
            m->data = NULL;
        }
        if (NULL != m->bitmap) {
            free(m->bitmap);
            m->bitmap = NULL;
        }
        if (NULL != m->name) {
            free(m->name);
        }
        if (NULL != m->path) {
            free(m->path);
        }
        free((void *)m);
    }
}

cl_fmap_t *fmap_open_handle(void *handle, size_t offset, size_t len,
                            clcb_pread pread_cb, int use_aging)
{
    cl_error_t status = CL_EMEM;
    uint64_t pages;
    size_t mapsz, bitmap_size;
    cl_fmap_t *m = NULL;
    int pgsz     = cli_getpagesize();

    if (pgsz <= 0) {
        cli_warnmsg("fmap: invalid page size\n");
        goto done;
    }
    if (pread_cb == NULL) {
        cli_warnmsg("fmap: attempted mapping without a read callback\n");
        goto done;
    }
    if (!fmap_offset_fits_off_t(offset)) {
        cli_warnmsg("fmap: source offset is not representable by off_t\n");
        goto done;
    }
    if (offset % (size_t)pgsz != 0) {
        cli_warnmsg("fmap: attempted mapping with unaligned offset\n");
        goto done;
    }
    if (!len) {
        cli_dbgmsg("fmap: attempted void mapping\n");
        goto done;
    }
    /* offset is the source-file position, while len is the amount exposed
     * through this fmap.  A valid tail window can therefore have
     * offset >= len (for example, a 4 KiB map at a 32 GiB source offset).
     * Only reject arithmetic that would make the source range wrap. */
    if (len > SIZE_MAX - offset) {
        cli_warnmsg("fmap: mapping range arithmetic overflow\n");
        goto done;
    }

    pages = fmap_align_items(len, pgsz);

    if (pages > SIZE_MAX / sizeof(uint64_t) || pages > SIZE_MAX / (uint64_t)pgsz) {
        cli_warnmsg("fmap: map size arithmetic overflow\n");
        goto done;
    }

    bitmap_size = pages * sizeof(uint64_t);
    mapsz       = pages * pgsz;

    m = calloc(1, sizeof(fmap_t));
    if (!m) {
        cli_warnmsg("fmap: map header allocation failed\n");
        goto done;
    }

    m->bitmap = cli_max_calloc(1, bitmap_size);
    if (!m->bitmap) {
        cli_warnmsg("fmap: map header allocation failed\n");
        goto done;
    }

#ifndef ANONYMOUS_MAP
    use_aging = 0;
#endif
#ifdef ANONYMOUS_MAP
    if (use_aging) {
        fmap_lock;
        if ((m->data = (fmap_t *)mmap(NULL,
                                      mapsz,
                                      PROT_READ | PROT_WRITE, MAP_PRIVATE | /* FIXME: MAP_POPULATE is ~8% faster but more memory intensive */ ANONYMOUS_MAP,
                                      -1,
                                      0)) == MAP_FAILED) {
            m->data = NULL;
        } else {
#if HAVE_MADVISE
            madvise((void *)m->data, mapsz, MADV_RANDOM | MADV_DONTFORK);
#endif /* madvise */
        }
        fmap_unlock;
    }
#endif /* ANONYMOUS_MAP */
    if (!use_aging) {
        m->data = (fmap_t *)cli_max_malloc(mapsz);
    }
    if (!m->data) {
        cli_warnmsg("fmap: map allocation failed\n");
        goto done;
    }
    m->handle          = handle;
    m->pread_cb        = pread_cb;
    m->aging           = use_aging != 0 ? true : false;
    m->offset          = offset;
    m->nested_offset   = 0;
    m->len             = len; /* m->nested_offset + m->len = m->real_len */
    m->real_len        = len;
    m->pages           = pages;
    m->pgsz            = pgsz;
    m->paged           = 0;
    m->aging_owner     = m;
    m->dont_cache_flag = false;
    m->unmap           = unmap_handle;
    m->need            = handle_need;
    m->need_offstr     = handle_need_offstr;
    m->gets            = handle_gets;
    m->unneed_off      = handle_unneed_off;
    m->handle_is_fd    = false;

    memset(m->will_need_hash, 0, sizeof(m->will_need_hash));
    memset(m->have_hash, 0, sizeof(m->have_hash));

    status = CL_SUCCESS;

done:
    if (CL_SUCCESS != status) {
        unmap_handle(m);
        m = NULL;
    }
    return m;
}

#ifdef ANONYMOUS_MAP
static int fmap_unpage_range(fmap_t *m, uint64_t first_page, uint64_t last_page)
{
    char *first;
    size_t len;
    uint64_t page_count;
    uint64_t page;
    void *replacement;

    if (!m->pgsz || last_page < first_page || last_page >= m->pages)
        return -1;
    page_count = last_page - first_page + 1;
    if (first_page > SIZE_MAX / m->pgsz || page_count > SIZE_MAX / m->pgsz)
        return -1;
    if (page_count > m->paged) {
        cli_errmsg("fmap_aging: resident page accounting is inconsistent\n");
        return -1;
    }

    first = (char *)m->data + first_page * m->pgsz;
    len   = (size_t)(page_count * m->pgsz);

    fmap_lock;
    replacement = mmap(first, len, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | ANONYMOUS_MAP, -1, 0);
    if (replacement == MAP_FAILED)
        cli_dbgmsg("fmap_aging: unable to release an anonymous page range\n");
    fmap_unlock;

    if (replacement == MAP_FAILED)
        return -1;

    for (page = 0; page < page_count; page++)
        fmap_bitmap[first_page + page] = FM_MASK_SEEN;
    m->paged -= page_count;
    return 0;
}

/*
 * fmap_gets() copies its result into caller-owned storage before returning.
 * Release the pages that were only needed for that copy instead of waiting
 * for the normal scan-window aging high-water mark. This matters for
 * line-oriented consumers such as the mail parser: a multi-gigabyte message
 * can otherwise keep every page resident even though it retains no fmap
 * pointer after each call.
 */
static void fmap_release_gets_pages(fmap_t *m, uint64_t first_page, uint64_t last_page)
{
    fmap_t *owner = fmap_aging_owner(m);
    uint64_t page;
    uint64_t range_first = 0;
    uint64_t range_last  = 0;
    int have_range       = 0;

    if (!owner->aging || first_page > last_page || last_page >= owner->pages)
        return;

    for (page = first_page;; page++) {
        uint64_t state = owner->bitmap[page];

        if ((state & (FM_MASK_PAGED | FM_MASK_LOCKED)) == FM_MASK_PAGED) {
            if (have_range && page != range_last + 1) {
                if (fmap_unpage_range(owner, range_first, range_last) != 0)
                    return;
                have_range = 0;
            }
            if (!have_range)
                range_first = page;
            range_last = page;
            have_range = 1;
        } else if (have_range) {
            if (fmap_unpage_range(owner, range_first, range_last) != 0)
                return;
            have_range = 0;
        }

        if (page == last_page)
            break;
    }

    if (have_range)
        (void)fmap_unpage_range(owner, range_first, range_last);
}
#endif

static void fmap_aging(fmap_t *m)
{
#ifdef ANONYMOUS_MAP
    fmap_t *owner = fmap_aging_owner(m);
    uint64_t target_pages;
    uint64_t pages_to_free;
    uint64_t scan_limit;
    uint64_t scanned     = 0;
    uint64_t selected    = 0;
    uint64_t released    = 0;
    uint64_t range_first = 0;
    uint64_t range_last  = 0;
    uint64_t page;
    uint64_t state;
    uint64_t range_count;
    int have_range = 0;

    owner->aging_scanned_last  = 0;
    owner->aging_released_last = 0;

    if (!owner->aging || !owner->pages || !owner->pgsz)
        return;
    if (owner->paged <= UNPAGE_THRSHLD_HI / owner->pgsz)
        return;

    target_pages = UNPAGE_THRSHLD_LO / owner->pgsz;
    if (!target_pages)
        target_pages = 1;
    if (owner->paged <= target_pages)
        return;

    pages_to_free = MIN(owner->paged - target_pages, (uint64_t)FMAP_AGING_FREE_BUDGET);

    /* Both work limits are constants. The prior implementation walked every
     * page in the fmap on every request, making a sequential large-file scan
     * quadratic in the file size. */
    scan_limit = MIN(owner->pages, (uint64_t)FMAP_AGING_SCAN_BUDGET);

    if (owner->aging_cursor >= owner->pages)
        owner->aging_cursor = 0;

    while (scanned < scan_limit && selected < pages_to_free) {
        page = owner->aging_cursor;

        owner->aging_cursor++;
        if (owner->aging_cursor == owner->pages)
            owner->aging_cursor = 0;
        scanned++;

        state = owner->bitmap[page];
        if ((state & (FM_MASK_PAGED | FM_MASK_LOCKED)) == FM_MASK_PAGED) {
            if (have_range && (range_last == UINT64_MAX || page != range_last + 1)) {
                range_count = range_last - range_first + 1;
                if (fmap_unpage_range(owner, range_first, range_last) != 0) {
                    have_range = 0;
                    break;
                }
                released += range_count;
                have_range = 0;
            }
            if (!have_range) {
                range_first = page;
                have_range  = 1;
            }
            range_last = page;
            selected++;
        } else if (have_range) {
            range_count = range_last - range_first + 1;
            if (fmap_unpage_range(owner, range_first, range_last) != 0) {
                have_range = 0;
                break;
            }
            released += range_count;
            have_range = 0;
        }
    }

    if (have_range) {
        range_count = range_last - range_first + 1;
        if (fmap_unpage_range(owner, range_first, range_last) == 0)
            released += range_count;
    }

    owner->aging_scanned_last  = scanned;
    owner->aging_released_last = released;
#else
    UNUSEDPARAM(m);
#endif
}

void fmap_release_unlocked(fmap_t *m)
{
#ifdef ANONYMOUS_MAP
    fmap_t *owner;

    if (NULL == m) {
        return;
    }

    owner = fmap_aging_owner(m);
    if (!owner->aging || owner->pages == 0) {
        return;
    }

    /* Unlike normal aging, this pass intentionally scans the complete
     * bitmap. It is called only after a whole-subject consumer has released
     * its pointer, so retaining those unlocked pages would defeat the
     * contiguous-subject residency contract. */
    fmap_release_gets_pages(owner, 0, owner->pages - 1);
#else
    UNUSEDPARAM(m);
#endif
}

static void fmap_readpage_rollback(fmap_t *owner, uint64_t first_page, uint64_t end_page)
{
    uint64_t page_count;
    uint64_t page;

    if (end_page <= first_page)
        return;

    page_count = end_page - first_page;
#ifdef ANONYMOUS_MAP
    if (owner->aging && fmap_unpage_range(owner, first_page, end_page - 1) == 0)
        return;
#endif

    for (page = first_page; page < end_page; page++)
        owner->bitmap[page] = FM_MASK_SEEN;
    if (page_count > owner->paged) {
        cli_errmsg("fmap_readpage: resident page accounting underflow after a read failure\n");
        owner->paged = 0;
    } else {
        owner->paged -= page_count;
    }
}

static int fmap_readpage(fmap_t *m, uint64_t first_page, uint64_t count, uint64_t lock_count)
{
    size_t readsz = 0, eintr_off;
    char *pptr    = NULL, errtxt[256];
    uint64_t sbitmap;
    uint64_t i, page = first_page, force_read = 0;
    fmap_t *owner = fmap_aging_owner(m);

    if (!m->pgsz || fmap_align_items((uint64_t)m->real_len, m->pgsz) > m->pages) {
        cli_dbgmsg("fmap_readpage: size of file exceeds total prefaultible page size (unpacked file is too large)\n");
        return 1;
    }

    fmap_lock;
    for (i = 0; i < count; i++) { /* prefault */
        /* Not worth checking if the page is already paged, just ping each */
        /* Also not worth reusing the loop below */
        volatile char faultme;
        faultme = ((char *)m->data)[(first_page + i) * m->pgsz];
        (void)faultme; // silence "warning: variable ‘faultme’ set but not used"
    }
    fmap_unlock;
    for (i = 0; i <= count; i++, page++) {
        int lock;
        if (lock_count) {
            lock_count--;
            lock = 1;
        } else
            lock = 0;
        if (i == count) {
            /* we count one page too much to flush pending reads */
            if (!pptr) return 0; /* if we have any */
            force_read = 1;
        } else if ((sbitmap = fmap_bitmap[page]) & FM_MASK_PAGED) {
            /* page already paged */
            if (lock) {
                /* we want locking */
                if (sbitmap & FM_MASK_LOCKED) {
                    /* page already locked */
                    sbitmap &= FM_MASK_COUNT;
                    if (sbitmap == FM_MASK_COUNT) { /* lock count already at max: fial! */
                        cli_errmsg("fmap_readpage: lock count exceeded\n");
                        return 1;
                    }
                    /* acceptable lock count: inc lock count */
                    fmap_bitmap[page]++;
                } else /* page not currently locked: set lock count = 1 */
                    fmap_bitmap[page] = 1 | FM_MASK_LOCKED | FM_MASK_PAGED;
            } else {
                /* we don't want locking */
                if (!(sbitmap & FM_MASK_LOCKED)) {
                    /* page is not locked: we reset aging to max */
                    fmap_bitmap[page] = FM_MASK_PAGED | FM_MASK_COUNT;
                }
            }
            if (!pptr) continue;
            force_read = 1;
        }

        if (force_read) {
            /* we have some pending reads to perform */
            if (m->handle_is_fd) {
                uint64_t j;
                int _fd = (int)(ptrdiff_t)m->handle;
                for (j = first_page; j < page; j++) {
                    if (fmap_bitmap[j] & FM_MASK_SEEN) {
                        /* page we've seen before: check mtime */
                        STATBUF st;
                        if (FSTAT(_fd, &st)) {
                            cli_strerror(errno, errtxt, sizeof(errtxt));
                            cli_warnmsg("fmap_readpage: fstat failed: %s\n", errtxt);
                            fmap_readpage_rollback(owner, first_page, page);
                            return 1;
                        }
                        if (m->mtime != (uint64_t)st.st_mtime) {
                            cli_warnmsg("fmap_readpage: file changed as we read it\n");
                            fmap_readpage_rollback(owner, first_page, page);
                            return 1;
                        }
                        break;
                    }
                }
            }

            eintr_off = 0;
            while (readsz) {
                ssize_t got;
                uint64_t page_offset;
                uint64_t target_offset;

                if (first_page > UINT64_MAX / m->pgsz) {
                    cli_errmsg("fmap_readpage: page offset overflow\n");
                    fmap_readpage_rollback(owner, first_page, page);
                    return 1;
                }
                page_offset = first_page * m->pgsz;
                if ((uint64_t)m->offset > UINT64_MAX - page_offset ||
                    eintr_off > UINT64_MAX - page_offset - (uint64_t)m->offset) {
                    cli_errmsg("fmap_readpage: read offset overflow\n");
                    fmap_readpage_rollback(owner, first_page, page);
                    return 1;
                }
                target_offset = page_offset + (uint64_t)m->offset + eintr_off;
                if ((off_t)target_offset < 0 || (uint64_t)(off_t)target_offset != target_offset) {
                    cli_errmsg("fmap_readpage: read offset is not representable by off_t\n");
                    fmap_readpage_rollback(owner, first_page, page);
                    return 1;
                }
                got = m->pread_cb(m->handle, pptr, readsz, (off_t)target_offset);

                if (got < 0 && errno == EINTR)
                    continue;

                if (got > 0) {
                    pptr += got;
                    eintr_off += got;
                    readsz -= got;
                    continue;
                }

                if (got < 0) {
                    cli_strerror(errno, errtxt, sizeof(errtxt));
                    cli_errmsg("fmap_readpage: pread error: %s\n", errtxt);
                } else {
                    cli_warnmsg("fmap_readpage: pread fail: asked for %zu bytes @ offset " STDu64 ", got %zd\n", readsz, target_offset, got);
                }
                fmap_readpage_rollback(owner, first_page, page);
                return 1;
            }

            pptr       = NULL;
            force_read = 0;
            readsz     = 0;
            continue;
        }

        /* page is not already paged */
        if (!pptr) {
            /* set a new start for pending reads if we don't have one */
            pptr       = (char *)m->data + page * m->pgsz;
            first_page = page;
        }
        if ((page == m->pages - 1) && (m->real_len % m->pgsz))
            readsz += m->real_len % m->pgsz;
        else
            readsz += m->pgsz;
        if (lock) /* lock requested: set paged, lock page and set lock count to 1 */
            fmap_bitmap[page] = FM_MASK_PAGED | FM_MASK_LOCKED | 1;
        else /* no locking: set paged and set aging to max */
            fmap_bitmap[page] = FM_MASK_PAGED | FM_MASK_COUNT;
        owner->paged++;
    }
    return 0;
}

static const void *handle_need(fmap_t *m, size_t at, size_t len, int lock)
{
    uint64_t first_page, last_page, lock_count;
    char *ret;

    if (!len)
        return NULL;

    if (!fmap_add_size(at, m->nested_offset, &at) ||
        !fmap_range_contained(m->nested_offset, m->len, at, len, false))
        return NULL;

    fmap_aging(m);

    first_page = fmap_which_page(m, at);
    last_page  = fmap_which_page(m, at + (len - 1));
    lock_count = (lock != 0) * (last_page - first_page + 1);
#ifdef READAHED_PAGES
    last_page += READAHED_PAGES;
    if (last_page >= m->pages) last_page = m->pages - 1;
#endif

    if (fmap_readpage(m, first_page, last_page - first_page + 1, lock_count))
        return NULL;

    ret = (char *)m->data + at;
    return (void *)ret;
}

static void fmap_unneed_page(fmap_t *m, uint64_t page)
{
    uint64_t s = fmap_bitmap[page];

    if ((s & (FM_MASK_PAGED | FM_MASK_LOCKED)) == (FM_MASK_PAGED | FM_MASK_LOCKED)) {
        /* page is paged and locked: check lock count */
        s &= FM_MASK_COUNT;
        if (s > 1) /* locked more than once: dec lock count */
            fmap_bitmap[page]--;
        else if (s == 1) /* only one lock left: unlock and begin aging */
            fmap_bitmap[page] = FM_MASK_COUNT | FM_MASK_PAGED;
        else
            cli_errmsg("fmap_unneed: inconsistent map state\n");
        return;
    }
    cli_warnmsg("fmap_unneed: unneed on a unlocked page\n");
    return;
}

static void handle_unneed_off(fmap_t *m, size_t at, size_t len)
{
    uint64_t i, first_page, last_page;
    if (!m->aging) return;
    if (!len) {
        cli_warnmsg("fmap_unneed: attempted void unneed\n");
        return;
    }

    if (!fmap_add_size(at, m->nested_offset, &at) ||
        !fmap_range_contained(m->nested_offset, m->len, at, len, false)) {
        cli_warnmsg("fmap: attempted oof unneed\n");
        return;
    }

    first_page = fmap_which_page(m, at);
    last_page  = fmap_which_page(m, at + (len - 1));

    for (i = first_page; i <= last_page; i++) {
        fmap_unneed_page(m, i);
    }
}

static void unmap_mmap(fmap_t *m)
{
#ifdef ANONYMOUS_MAP
    size_t len = m->pages * m->pgsz;
    fmap_lock;
    if (munmap((void *)m->data, len) == -1) /* munmap() failed */
        cli_warnmsg("fmap_free: unable to unmap memory segment at address: %p with length: %zu\n", (void *)m->data, len);
    fmap_unlock;
#else
    UNUSEDPARAM(m);
#endif
}

static void unmap_malloc(fmap_t *m)
{
    if (NULL != m) {
        if (NULL != m->name) {
            free(m->name);
        }
        if (NULL != m->path) {
            free(m->path);
        }
        free((void *)m);
    }
}

static const void *handle_need_offstr(fmap_t *m, size_t at, size_t len_hint)
{
    uint64_t i, first_page, last_page;
    void *ptr;

    if (!fmap_add_size(at, m->nested_offset, &at) || at > m->real_len)
        return NULL;

    if (!len_hint || len_hint > m->real_len - at)
        len_hint = m->real_len - at;

    if (!fmap_range_contained(m->nested_offset, m->len, at, len_hint, false))
        return NULL;

    ptr = (void *)((char *)m->data + at);

    fmap_aging(m);

    first_page = fmap_which_page(m, at);
    last_page  = fmap_which_page(m, at + (len_hint - 1));

    for (i = first_page; i <= last_page; i++) {
        char *thispage = (char *)m->data + i * m->pgsz;
        uint64_t scanat, scansz;

        if (fmap_readpage(m, i, 1, 1)) {
            last_page = i - 1;
            break;
        }
        if (i == first_page) {
            scanat = at % m->pgsz;
            scansz = MIN(len_hint, m->pgsz - scanat);
        } else {
            scanat = 0;
            scansz = MIN(len_hint, m->pgsz);
        }
        len_hint -= scansz;
        if (memchr(&thispage[scanat], 0, scansz))
            return ptr;
    }
    for (i = first_page; i <= last_page; i++)
        fmap_unneed_page(m, i);
    return NULL;
}

static const void *handle_gets(fmap_t *m, char *dst, size_t *at, size_t max_len)
{
    uint64_t i, first_page, last_page;
    size_t start_at;
    size_t real_start;
    char *src;
    char *endptr = NULL;
    size_t len;
    size_t fullen;

    if (NULL == m || NULL == dst || NULL == at || max_len == 0 ||
        *at > m->len || *at == m->len ||
        !fmap_add_size(*at, m->nested_offset, &real_start))
        return NULL;

    len = MIN(max_len - 1, m->len - *at);
    if (!fmap_range_contained(m->nested_offset, m->len, real_start, len, false))
        return NULL;

    start_at = *at;
    fullen   = len;
    src      = (char *)m->data + real_start;

    fmap_aging(m);

    first_page = fmap_which_page(m, real_start);
    last_page  = fmap_which_page(m, real_start + (len - 1));

    for (i = first_page; i <= last_page; i++) {
        char *thispage = (char *)m->data + i * m->pgsz;
        uint64_t scanat, scansz;

        if (fmap_readpage(m, i, 1, 0))
            return NULL;

        if (i == first_page) {
            scanat = real_start % m->pgsz;
            scansz = MIN(len, m->pgsz - scanat);
        } else {
            scanat = 0;
            scansz = MIN(len, m->pgsz);
        }
        len -= scansz;

        if ((endptr = memchr(&thispage[scanat], '\n', scansz))) {
            endptr++;
            break;
        }
    }
    if (endptr) {
        memcpy(dst, src, endptr - src);
        dst[endptr - src] = '\0';
        *at += endptr - src;
    } else {
        memcpy(dst, src, fullen);
        dst[fullen] = '\0';
        *at += fullen;
    }

#ifdef ANONYMOUS_MAP
    if (m->aging && *at > start_at) {
        size_t release_start;
        size_t release_end;

        if (fmap_add_size(start_at, m->nested_offset, &release_start) &&
            fmap_add_size(*at, m->nested_offset, &release_end)) {
            uint64_t release_first = fmap_which_page(m, release_start);
            uint64_t release_last  = fmap_which_page(m, release_end - 1);

            fmap_release_gets_pages(m, release_first, release_last);
        }
    }
#endif

    return dst;
}

/* vvvvv MEMORY STUFF BELOW vvvvv */

static const void *mem_need(fmap_t *m, size_t at, size_t len, int lock);
static void mem_unneed_off(fmap_t *m, size_t at, size_t len);
static const void *mem_need_offstr(fmap_t *m, size_t at, size_t len_hint);
static const void *mem_gets(fmap_t *m, char *dst, size_t *at, size_t max_len);

fmap_t *fmap_open_memory(const void *start, size_t len, const char *name)
{
    cl_error_t status = CL_ERROR;

    int pgsz     = cli_getpagesize();
    cl_fmap_t *m = calloc(1, sizeof(*m));
    if (!m) {
        cli_warnmsg("fmap: map allocation failed\n");
        goto done;
    }
    m->data        = start;
    m->len         = len;
    m->real_len    = len;
    m->pgsz        = pgsz;
    m->pages       = fmap_align_items(len, pgsz);
    m->aging_owner = m;
    m->unmap       = unmap_malloc;
    m->need        = mem_need;
    m->need_offstr = mem_need_offstr;
    m->gets        = mem_gets;
    m->unneed_off  = mem_unneed_off;

    if (NULL != name) {
        /* Copy the name, if one is given */
        m->name = cli_safer_strdup(name);
        if (NULL == m->name) {
            cli_warnmsg("fmap: failed to duplicate map name\n");
            goto done;
        }
    }

    status = CL_SUCCESS;

done:
    if (CL_SUCCESS != status) {
        if (NULL != m) {
            if (NULL != m->name) {
                free(m->name);
            }
            free(m);
            m = NULL;
        }
    }

    return m;
}

static const void *mem_need(fmap_t *m, size_t at, size_t len, int lock)
{
    UNUSEDPARAM(lock);
    if (!len) {
        return NULL;
    }
    if (!fmap_add_size(at, m->nested_offset, &at) ||
        !fmap_range_contained(m->nested_offset, m->len, at, len, false)) {
        return NULL;
    }

    return (void *)((char *)m->data + at);
}

static void mem_unneed_off(fmap_t *m, size_t at, size_t len)
{
    UNUSEDPARAM(m);
    UNUSEDPARAM(at);
    UNUSEDPARAM(len);
}

static const void *mem_need_offstr(fmap_t *m, size_t at, size_t len_hint)
{
    char *ptr;

    if (!fmap_add_size(at, m->nested_offset, &at) || at > m->real_len)
        return NULL;

    if (!len_hint || len_hint > m->real_len - at)
        len_hint = m->real_len - at;

    if (!fmap_range_contained(m->nested_offset, m->len, at, len_hint, false))
        return NULL;

    ptr = (char *)m->data + at;

    if (memchr(ptr, 0, len_hint))
        return (void *)ptr;
    return NULL;
}

static const void *mem_gets(fmap_t *m, char *dst, size_t *at, size_t max_len)
{
    size_t real_start;
    char *src;
    char *endptr = NULL;
    size_t len;

    if (NULL == m || NULL == dst || NULL == at || max_len == 0 ||
        *at > m->len || *at == m->len ||
        !fmap_add_size(*at, m->nested_offset, &real_start))
        return NULL;

    len = MIN(max_len - 1, m->len - *at);
    if (!fmap_range_contained(m->nested_offset, m->len, real_start, len, false))
        return NULL;

    src = (char *)m->data + real_start;

    if ((endptr = memchr(src, '\n', len))) {
        endptr++;
        memcpy(dst, src, endptr - src);
        dst[endptr - src] = '\0';
        *at += endptr - src;
    } else {
        memcpy(dst, src, len);
        dst[len] = '\0';
        *at += len;
    }
    return dst;
}

fmap_t *fmap_new(int fd, off_t offset, size_t len, const char *name, const char *path)
{
    int unused;
    return fmap_check_empty(fd, offset, len, &unused, name, path);
}

static inline uint64_t fmap_align_items(uint64_t sz, uint64_t al)
{
    return sz / al + (sz % al != 0);
}

static inline uint64_t fmap_align_to(uint64_t sz, uint64_t al)
{
    return al * fmap_align_items(sz, al);
}

static inline fmap_t *fmap_aging_owner(fmap_t *m)
{
    return m->aging_owner ? m->aging_owner : m;
}

static inline uint64_t fmap_which_page(fmap_t *m, size_t at)
{
    return at / m->pgsz;
}

static cl_error_t fmap_dump_cleanup(int *tmpfd, char **tmpname, cl_error_t status)
{
    cl_error_t cleanup_status = CL_SUCCESS;

    if (tmpfd != NULL && *tmpfd >= 0) {
        if (close(*tmpfd) == -1)
            cleanup_status = CL_EWRITE;
        *tmpfd = -1;
    }

    if (tmpname != NULL && *tmpname != NULL) {
        if (cli_unlink(*tmpname) != 0 && cleanup_status == CL_SUCCESS)
            cleanup_status = CL_EUNLINK;
        free(*tmpname);
        *tmpname = NULL;
    }

    if (cleanup_status == CL_SUCCESS)
        return status;
    if (status == CL_SUCCESS || status == CL_VERIFIED || status == CL_BREAK)
        return cleanup_status;
    return status;
}

cl_error_t fmap_dump_to_file(fmap_t *map, const char *filepath, const char *tmpdir, char **outname, int *outfd, size_t start_offset, size_t end_offset)
{
    cl_error_t ret = CL_EARG;

    char *filebase = NULL;
    char *prefix   = NULL;

    char *tmpname = NULL;
    int tmpfd     = -1;

    size_t pos = 0, len = 0, bytes_remaining = 0, write_size = 0;

    /* The public offsets are relative to the accessible fmap.  Use map->len
     * so nested and sliced maps cannot stage bytes outside their visible range. */
    if ((start_offset > map->len) || (end_offset < start_offset)) {
        cli_dbgmsg("fmap_dump_to_file: Invalid offset arguments: start %zu, end %zu\n", start_offset, end_offset);
        return ret;
    }

    pos = start_offset;
    if (end_offset == SIZE_MAX)
        end_offset = map->len;
    else
        end_offset = MIN(end_offset, map->len);
    bytes_remaining = end_offset - start_offset;

    /* Create a filename prefix that includes the original filename, if available */
    if (filepath != NULL) {
        if (CL_SUCCESS != cli_basename(filepath, strlen(filepath), &filebase, true /* posix_support_backslash_pathsep */)) {
            cli_dbgmsg("fmap_dump_to_file: Unable to determine basename from filepath.\n");
        } else if ((start_offset != 0) && (end_offset != map->len)) {
            /* If we're only dumping a portion of the file, include the offsets in the prefix,...
             * e.g. tmp filename will become something like:  filebase.500-1200.<randhex> */
            size_t prefix_len = strlen(filebase) + 1 + SIZE_T_CHARLEN + 1 + SIZE_T_CHARLEN + 1;
            prefix            = malloc(prefix_len);
            if (NULL == prefix) {
                cli_errmsg("fmap_dump_to_file: Failed to allocate memory for tempfile prefix.\n");
                free(filebase);
                return CL_EMEM;
            }
            snprintf(prefix, prefix_len, "%s.%zu-%zu", filebase, start_offset, end_offset);

            free(filebase);
            filebase = NULL;
        } else {
            /* Else if we're dumping the whole thing, use the filebase as the prefix */
            prefix   = filebase;
            filebase = NULL;
        }
    }

    cli_dbgmsg("fmap_dump_to_file: dumping fmap not backed by file...\n");
    ret = cli_gentempfd_with_prefix(tmpdir, prefix, &tmpname, &tmpfd);
    if (ret != CL_SUCCESS) {
        cli_dbgmsg("fmap_dump_to_file: failed to generate temporary file.\n");
        if (NULL != prefix) {
            free(prefix);
            prefix = NULL;
        }
        return ret;
    }

    if (NULL != prefix) {
        free(prefix);
        prefix = NULL;
    }

    do {
        const char *b;
        len        = 0;
        write_size = MIN(BUFSIZ, bytes_remaining);

        b = fmap_need_off_once_len(map, pos, write_size, &len);
        pos += len;
        if (b && (len > 0)) {
            if (cli_writen(tmpfd, b, len) != len) {
                cli_warnmsg("fmap_dump_to_file: write failed to %s!\n", tmpname);
                return fmap_dump_cleanup(&tmpfd, &tmpname, CL_EWRITE);
            }
        }
        if (len <= bytes_remaining) {
            bytes_remaining -= len;
        } else {
            bytes_remaining = 0;
        }
    } while ((len > 0) && (bytes_remaining > 0));

    if (bytes_remaining != 0) {
        cli_warnmsg("fmap_dump_to_file: mapped read ended before the requested range was copied\n");
        return fmap_dump_cleanup(&tmpfd, &tmpname, CL_EREAD);
    }

    if (lseek(tmpfd, 0, SEEK_SET) == -1) {
        cli_warnmsg("fmap_dump_to_file: lseek failed for staged fmap %s\n", tmpname);
        return fmap_dump_cleanup(&tmpfd, &tmpname, CL_ESEEK);
    }

    *outname = tmpname;
    *outfd   = tmpfd;
    return CL_SUCCESS;
}

int fmap_fd(fmap_t *m)
{
    int fd;
    if (NULL == m) {
        cli_errmsg("fmap_fd: Attempted to get fd for NULL fmap\n");
        return -1;
    }
    if (!m->handle_is_fd) {
        return -1;
    }
    fd = (int)(ptrdiff_t)m->handle;
    lseek(fd, 0, SEEK_SET);
    return fd;
}

cl_error_t fmap_set_hash(fmap_t *map, const uint8_t *hash, cli_hash_type_t type)
{
    cl_error_t status = CL_ERROR;

    if (NULL == map) {
        cli_errmsg("fmap_set_hash: Attempted to set hash for NULL fmap\n");
        status = CL_EARG;
        goto done;
    }
    if (NULL == hash) {
        cli_errmsg("fmap_set_hash: Attempted to set hash to NULL\n");
        status = CL_EARG;
        goto done;
    }

    if (type >= CLI_HASH_AVAIL_TYPES) {
        cli_errmsg("fmap_set_hash: Unsupported hash type %u\n", type);
        status = CL_EARG;
        goto done;
    }

    memcpy(map->hash[type], hash, cli_hash_len(type));
    map->have_hash[type] = true;
    status               = CL_SUCCESS;

    if (cli_debug_flag) {
        // Convert the hash to a hex string for logging
        char hash_string[CLI_HASHLEN_MAX * 2 + 1] = {0};
        size_t hash_len                           = cli_hash_len(type);

        // Convert hash to string.
        size_t i;
        for (i = 0; i < hash_len; i++) {
            sprintf(hash_string + i * 2, "%02x", map->hash[type][i]);
        }
        hash_string[hash_len * 2] = 0;

        cli_dbgmsg("fmap_set_hash: set %s hash: %s\n", cli_hash_name(type), hash_string);
    }

done:
    return status;
}

cl_error_t fmap_will_need_hash_later(fmap_t *map, cli_hash_type_t type)
{
    cl_error_t status = CL_ERROR;

    if (NULL == map) {
        cli_errmsg("fmap_will_need_hash_later: Attempted to set hash for NULL fmap\n");
        status = CL_EARG;
        goto done;
    }

    if (type >= CLI_HASH_AVAIL_TYPES) {
        cli_errmsg("fmap_will_need_hash_later: Unsupported hash type %u\n", type);
        status = CL_EARG;
        goto done;
    }

    /* set flags */
    map->will_need_hash[type] = true;
    status                    = CL_SUCCESS;

done:
    return status;
}

cl_error_t fmap_get_hash_ctx(fmap_t *map, unsigned char **hash, cli_hash_type_t type, cli_ctx *ctx)
{
    cl_error_t status = CL_ERROR;
    size_t todo, at = 0;
    void *hashctx[CLI_HASH_AVAIL_TYPES] = {NULL};
    cli_hash_type_t hash_type;

    if (NULL == map || NULL == hash) {
        cli_errmsg("fmap_get_hash: NULL argument\n");
        return CL_ENULLARG;
    }

    if (type >= CLI_HASH_AVAIL_TYPES) {
        cli_errmsg("fmap_get_hash: Unsupported hash type %u\n", type);
        status = CL_EARG;
        goto done;
    }

    if (ctx && cli_checktimelimit(ctx) != CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, "fmap hash calculation reached the configured time limit");
        status = CL_ETIMEOUT;
        goto done;
    }

    /* If we already have the hash, just return it */
    if (map->have_hash[type]) {
        goto complete;
    }

    /* Metadata-only maps are used for fail-closed preflight results. They
     * carry the subject size but intentionally have no data-access callback,
     * so hashing them would otherwise call through a NULL function pointer. */
    if (NULL == map->need) {
        cli_dbgmsg("fmap_get_hash: map has no data-access callback\n");
        cli_mark_scan_incomplete(ctx, "fmap hash input could not be read completely");
        return CL_EREAD;
    }

    todo = map->len;

    map->will_need_hash[type] = true;

    /*
     * Need to calculate the requested hash and maybe others, as well.
     */

    /* Initialize hash contexts for all needed hash types */
    for (hash_type = CLI_HASH_MD5; hash_type < CLI_HASH_AVAIL_TYPES; hash_type++) {
        if (map->will_need_hash[hash_type] && !map->have_hash[hash_type]) {
            const char *hash_name = cli_hash_name(hash_type);

            hashctx[hash_type] = cl_hash_init(hash_name);
            if (NULL == hashctx[hash_type]) {
                cli_errmsg("fmap_get_hash: error initializing %s hash context\n", hash_name);
                cli_mark_scan_incomplete(ctx, "fmap hash digest could not be initialized");
                status = CL_EARG;
                goto done;
            }
        }
    }

    while (todo) {
        const void *buf;
        size_t readme = todo < 1024 * 1024 * 10 ? todo : 1024 * 1024 * 10;

        if (ctx && cli_checktimelimit(ctx) != CL_SUCCESS) {
            cli_mark_scan_incomplete(ctx, "fmap hash calculation reached the configured time limit");
            status = CL_ETIMEOUT;
            goto done;
        }

        if (!(buf = fmap_need_off_once(map, at, readme))) {
            cli_errmsg("fmap_get_hash: error reading while generating hash!\n");
            cli_mark_scan_incomplete(ctx, "fmap hash input could not be read completely");
            status = CL_EREAD;
            goto done;
        }

        todo -= readme;
        at += readme;

        for (hash_type = CLI_HASH_MD5; hash_type < CLI_HASH_AVAIL_TYPES; hash_type++) {
            if (map->will_need_hash[hash_type] && !map->have_hash[hash_type]) {
                if (cl_update_hash(hashctx[hash_type], buf, readme)) {
                    const char *hash_name = cli_hash_name(hash_type);
                    cli_errmsg("fmap_get_hash: error calculating %s hash!\n", hash_name);
                    cli_mark_scan_incomplete(ctx, "fmap hash digest could not be calculated completely");
                    status = CL_EREAD;
                    goto done;
                }
            }
        }
    }

    for (hash_type = CLI_HASH_MD5; hash_type < CLI_HASH_AVAIL_TYPES; hash_type++) {
        if (map->will_need_hash[hash_type] && !map->have_hash[hash_type]) {
            cl_finish_hash(hashctx[hash_type], map->hash[hash_type]);
            map->have_hash[hash_type] = true;

            /* hashctx is finished, don't need to destroy it later */
            hashctx[hash_type] = NULL;

            if (cli_debug_flag) {
                // Convert the hash to a hex string for logging
                char hash_string[CLI_HASHLEN_MAX * 2 + 1] = {0};
                size_t hash_len                           = cli_hash_len(hash_type);

                // Convert hash to string.
                size_t i;
                for (i = 0; i < hash_len; i++) {
                    sprintf(hash_string + i * 2, "%02x", map->hash[hash_type][i]);
                }
                hash_string[hash_len * 2] = 0;

                cli_dbgmsg("fmap_get_hash: calculated %s hash: %s\n", cli_hash_name(hash_type), hash_string);
            }
        }
    }

complete:

    *hash  = map->hash[type];
    status = CL_SUCCESS;

done:

    for (hash_type = CLI_HASH_MD5; hash_type < CLI_HASH_AVAIL_TYPES; hash_type++) {
        if (NULL != hashctx[hash_type]) {
            cl_hash_destroy(hashctx[hash_type]);
        }
    }

    return status;
}

cl_error_t fmap_get_hash(fmap_t *map, unsigned char **hash, cli_hash_type_t type)
{
    return fmap_get_hash_ctx(map, hash, type, NULL);
}

/*
 * Public API functions.
 */

extern cl_fmap_t *cl_fmap_open_handle(
    void *handle,
    size_t offset,
    size_t len,
    clcb_pread pread_cb,
    int use_aging)
{
    return fmap_open_handle(handle, offset, len, pread_cb, use_aging);
}

extern cl_fmap_t *cl_fmap_open_memory(const void *start, size_t len)
{
    return (cl_fmap_t *)fmap_open_memory(start, len, NULL);
}

extern cl_error_t cl_fmap_set_name(cl_fmap_t *map, const char *name)
{
    cl_error_t status = CL_ERROR;

    if (!map || !name) {
        status = CL_ENULLARG;
        goto done;
    }

    free(map->name);

    map->name = cli_safer_strdup(name);
    if (!map->name) {
        status = CL_EMEM;
        goto done;
    }

    status = CL_SUCCESS;

done:
    return status;
}

extern cl_error_t cl_fmap_get_name(cl_fmap_t *map, const char **name_out)
{
    cl_error_t status = CL_ERROR;

    if (!map || !name_out) {
        status = CL_ENULLARG;
        goto done;
    }

    *name_out = map->name;
    status    = CL_SUCCESS;

done:
    return status;
}

extern cl_error_t cl_fmap_set_path(cl_fmap_t *map, const char *path)
{
    cl_error_t status = CL_ERROR;

    if (!map || !path) {
        status = CL_ENULLARG;
        goto done;
    }

    free(map->path);

    map->path = cli_safer_strdup(path);
    if (!map->path) {
        status = CL_EMEM;
        goto done;
    }

    status = CL_SUCCESS;

done:
    return status;
}

extern cl_error_t cl_fmap_get_path(cl_fmap_t *map, const char **path_out, size_t *offset_out, size_t *len_out)
{
    cl_error_t status = CL_ERROR;

    if (!map || !path_out) {
        status = CL_ENULLARG;
        goto done;
    }

    *path_out = map->path;
    if (NULL == *path_out) {
        status = CL_EACCES;
        goto done;
    }

    if (offset_out) {
        *offset_out = map->offset;
    }

    if (len_out) {
        *len_out = map->len;
    }

    status = CL_SUCCESS;

done:
    return status;
}

extern cl_error_t cl_fmap_get_fd(const cl_fmap_t *map, int *fd_out, size_t *offset_out, size_t *len_out)
{
    cl_error_t status = CL_ERROR;

    if (!map || !fd_out) {
        status = CL_ENULLARG;
        goto done;
    }

    *fd_out = fmap_fd((fmap_t *)map);
    if (*fd_out == -1) {
        status = CL_EACCES;
        goto done;
    }

    if (offset_out) {
        *offset_out = map->offset;
    }

    if (len_out) {
        *len_out = map->len;
    }

    status = CL_SUCCESS;

done:
    return status;
}

extern cl_error_t cl_fmap_get_size(const cl_fmap_t *map, size_t *size_out)
{
    cl_error_t status = CL_ERROR;

    if (!map || !size_out) {
        status = CL_ENULLARG;
        goto done;
    }

    *size_out = map->len;
    status    = CL_SUCCESS;

done:
    return status;
}

extern cl_error_t cl_fmap_set_hash(const cl_fmap_t *map, const char *hash_alg, const unsigned char *hash)
{
    cl_error_t status = CL_ERROR;
    cli_hash_type_t type;

    if (!map || !hash_alg) {
        status = CL_ENULLARG;
        goto done;
    }

    status = cli_hash_type_from_name(hash_alg, &type);
    if (status != CL_SUCCESS) {
        cli_errmsg("cl_fmap_set_hash: Unknown hash algorithm: %s\n", hash_alg);
        goto done;
    }

    if (type >= CLI_HASH_AVAIL_TYPES) {
        cli_errmsg("cl_fmap_set_hash: Unsupported hash algorithm: %s\n", hash_alg);
        status = CL_EARG;
        goto done;
    }

    status = fmap_set_hash((fmap_t *)map, hash, type);
    if (status != CL_SUCCESS) {
        cli_errmsg("cl_fmap_set_hash: Failed to set hash for algorithm: %s\n", hash_alg);
        goto done;
    }

done:
    return status;
}

extern cl_error_t cl_fmap_have_hash(const cl_fmap_t *map, const char *hash_alg, bool *have_hash_out)
{
    cl_error_t status = CL_ERROR;
    cli_hash_type_t type;

    if (!map || !hash_alg || !have_hash_out) {
        status = CL_ENULLARG;
        goto done;
    }

    status = cli_hash_type_from_name(hash_alg, &type);
    if (status != CL_SUCCESS) {
        cli_errmsg("cl_fmap_have_hash: Unknown hash algorithm: %s\n", hash_alg);
        goto done;
    }

    if (type >= CLI_HASH_AVAIL_TYPES) {
        cli_errmsg("cl_fmap_have_hash: Unsupported hash algorithm: %s\n", hash_alg);
        status = CL_EARG;
        goto done;
    }

    *have_hash_out = map->have_hash[type];
    status         = CL_SUCCESS;

done:
    return status;
}

extern cl_error_t cl_fmap_will_need_hash_later(const cl_fmap_t *map, const char *hash_alg)
{
    cl_error_t status = CL_ERROR;
    cli_hash_type_t type;

    if (!map || !hash_alg) {
        status = CL_ENULLARG;
        goto done;
    }

    status = cli_hash_type_from_name(hash_alg, &type);
    if (status != CL_SUCCESS) {
        cli_errmsg("cl_fmap_will_need_hash_later: Unknown hash algorithm: %s\n", hash_alg);
        goto done;
    }

    if (type >= CLI_HASH_AVAIL_TYPES) {
        cli_errmsg("cl_fmap_will_need_hash_later: Unsupported hash algorithm: %s\n", hash_alg);
        status = CL_EARG;
        goto done;
    }

    status = fmap_will_need_hash_later((fmap_t *)map, type);
    if (status != CL_SUCCESS) {
        cli_errmsg("cl_fmap_will_need_hash_later: Failed to indicate need for hash algorithm: %s\n", hash_alg);
        goto done;
    }

    status = CL_SUCCESS;

done:
    return status;
}

extern cl_error_t cl_fmap_get_hash(const cl_fmap_t *map, const char *hash_alg, char **hash_out)
{
    cl_error_t status = CL_ERROR;
    cli_hash_type_t type;
    unsigned char *hash;
    char *hash_string = NULL;
    size_t hash_len;
    size_t i;

    if (!map || !hash_alg || !hash_out) {
        status = CL_ENULLARG;
        goto done;
    }

    status = cli_hash_type_from_name(hash_alg, &type);
    if (status != CL_SUCCESS) {
        cli_errmsg("cl_fmap_get_hash: Unknown hash algorithm: %s\n", hash_alg);
        goto done;
    }

    if (type >= CLI_HASH_AVAIL_TYPES) {
        cli_errmsg("cl_fmap_get_hash: Unsupported hash algorithm: %s\n", hash_alg);
        status = CL_EARG;
        goto done;
    }

    status = fmap_get_hash((fmap_t *)map, &hash, type);
    if (status != CL_SUCCESS) {
        cli_errmsg("cl_fmap_get_hash: Failed to get hash for algorithm: %s\n", hash_alg);
        goto done;
    }

    hash_len = cli_hash_len(type);

    /* Convert hash to string */
    hash_string = malloc(hash_len * 2 + 1);
    if (!hash_string) {
        cli_errmsg("cl_fmap_get_hash: Failed to allocate memory for hash string\n");
        status = CL_EMEM;
        goto done;
    }

    for (i = 0; i < hash_len; i++) {
        sprintf(hash_string + i * 2, "%02x", hash[i]);
    }
    hash_string[hash_len * 2] = 0;

    *hash_out   = hash_string;
    hash_string = NULL; /* transfer ownership to *hash_out */

    status = CL_SUCCESS;

done:
    if (NULL != hash_string) {
        free(hash_string);
        hash_string = NULL;
    }

    return status;
}

extern cl_error_t cl_fmap_get_data(const cl_fmap_t *map, size_t offset, size_t len, const uint8_t **data_out, size_t *data_len_out)
{
    cl_error_t status = CL_ERROR;
    const uint8_t *data;

    if (!map || !data_out) {
        status = CL_ENULLARG;
        goto done;
    }

    if (offset > map->len) {
        cli_errmsg("cl_fmap_get_data: Offset %zu is beyond end of file (file length %zu)\n", offset, map->len);
        status = CL_EARG;
        goto done;
    }

    if (len == 0) {
        // If len is 0, we want to read to the end of the file.
        len = map->len - offset;
    }

    if (len > map->len - offset) {
        // Adjust len to read only to the end of the file if they asked for too much.
        len = map->len - offset;
    }

    data = fmap_need_off_once_len((fmap_t *)map, offset, len, &len);
    if (!data) {
        cli_errmsg("cl_fmap_get_data: Failed to get data from fmap\n");
        status = CL_EREAD;
        goto done;
    }

    *data_out = data;
    if (data_len_out) {
        *data_len_out = len;
    }

    status = CL_SUCCESS;

done:
    return status;
}

extern void cl_fmap_close(cl_fmap_t *map)
{
    fmap_free(map);
}
