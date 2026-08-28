/*
 * Author: 웃 Sebastian Andrzej Siewior
 * Summary: Glue code for libmspack handling.
 *
 * Acknowledgements: ClamAV uses Stuart Caie's libmspack to parse as number of
 *                   Microsoft file formats.
 * ✉ sebastian @ breakpoint ̣cc
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>

#include <mspack.h>

#include "clamav.h"
#include "fmap.h"
#include "scanners.h"
#include "others.h"
#include "clamav_rust.h"

enum mspack_type {
    FILETYPE_DUNNO,
    FILETYPE_FMAP,
    FILETYPE_FILENAME,
};

struct mspack_name {
    fmap_t *fmap;
    off_t org;
};

struct mspack_system_ex {
    struct mspack_system ops;
    uint64_t max_size;
    cli_ctx *ctx;
    bool time_limit_exceeded;
    bool read_failure;
    bool close_failure;
    const char *time_limit_reason;
};

struct mspack_handle {
    enum mspack_type type;

    fmap_t *fmap;
    off_t org;
    off_t offset;

    FILE *f;
    uint64_t max_size;
    bool limit_exceeded;
    struct mspack_system_ex *system_ex;
};

static bool mspack_deadline_ok(struct mspack_system_ex *system_ex)
{
    if (system_ex == NULL || system_ex->ctx == NULL)
        return true;

    if (cli_checktimelimit(system_ex->ctx) == CL_SUCCESS)
        return true;

    system_ex->time_limit_exceeded = true;
    cli_mark_scan_incomplete(system_ex->ctx,
                             system_ex->time_limit_reason ? system_ex->time_limit_reason : "MSPack decoder reached the configured time limit");
    return false;
}

static cl_error_t mspack_decoder_failure(const struct mspack_system_ex *system_ex,
                                         cl_error_t fallback)
{
    if (system_ex->time_limit_exceeded)
        return CL_ETIMEOUT;
    if (system_ex->read_failure)
        return CL_EREAD;
    return fallback;
}

static int mspack_fmap_length(const fmap_t *map, off_t *length)
{
    off_t map_length;

    if (map == NULL || length == NULL)
        return -1;

    map_length = (off_t)map->len;
    if (map_length < 0 || (uintmax_t)map_length != (uintmax_t)map->len)
        return -1;

    *length = map_length;
    return 0;
}

static int mspack_fmap_absolute_offset(const struct mspack_handle *handle, size_t *offset)
{
    off_t map_length;

    if (handle == NULL || handle->fmap == NULL || offset == NULL ||
        handle->org < 0 || handle->offset < 0 ||
        mspack_fmap_length(handle->fmap, &map_length) != 0 ||
        (uintmax_t)handle->org > (uintmax_t)map_length ||
        (uintmax_t)handle->offset > (uintmax_t)map_length - (uintmax_t)handle->org)
        return -1;

    *offset = (size_t)handle->org + (size_t)handle->offset;
    return 0;
}

static struct mspack_file *mspack_fmap_open(struct mspack_system *self,
                                            const char *filename, int mode)
{
    struct mspack_name *mspack_name;
    struct mspack_handle *mspack_handle;
    struct mspack_system_ex *self_ex;
    const char *fmode;
    const struct mspack_system *mptr = self;

    if (!filename) {
        cli_dbgmsg("%s() failed at %d\n", __func__, __LINE__);
        return NULL;
    }
    self_ex = (struct mspack_system_ex *)((char *)mptr - offsetof(struct mspack_system_ex, ops));
    mspack_handle = malloc(sizeof(*mspack_handle));
    if (!mspack_handle) {
        cli_dbgmsg("%s() failed at %d\n", __func__, __LINE__);
        return NULL;
    }
    memset(mspack_handle, 0, sizeof(*mspack_handle));

    switch (mode) {
        case MSPACK_SYS_OPEN_READ:
            mspack_handle->type = FILETYPE_FMAP;

            mspack_name           = (struct mspack_name *)filename;
            mspack_handle->fmap   = mspack_name->fmap;
            mspack_handle->org    = mspack_name->org;
            mspack_handle->offset = 0;
            mspack_handle->system_ex = self_ex;

            return (struct mspack_file *)mspack_handle;

        case MSPACK_SYS_OPEN_WRITE:
            fmode = "wb";
            break;
        case MSPACK_SYS_OPEN_UPDATE:
            fmode = "r+b";
            break;
        case MSPACK_SYS_OPEN_APPEND:
            fmode = "ab";
            break;
        default:
            cli_dbgmsg("%s() wrong mode\n", __func__);
            goto out_err;
    }

    mspack_handle->type = FILETYPE_FILENAME;

    mspack_handle->f = fopen(filename, fmode);
    if (!mspack_handle->f) {
        cli_dbgmsg("%s() failed %d\n", __func__, __LINE__);
        goto out_err;
    }

    mspack_handle->max_size = self_ex->max_size;
    mspack_handle->system_ex = self_ex;
    return (struct mspack_file *)mspack_handle;

out_err:
    memset(mspack_handle, 0, (sizeof(*mspack_handle)));
    free(mspack_handle);
    mspack_handle = NULL;
    return NULL;
}

static void mspack_fmap_close(struct mspack_file *file)
{
    struct mspack_handle *mspack_handle = (struct mspack_handle *)file;

    if (!mspack_handle)
        return;

    if (mspack_handle->type == FILETYPE_FILENAME && mspack_handle->f) {
        if (fclose(mspack_handle->f) != 0 && mspack_handle->system_ex != NULL)
            mspack_handle->system_ex->close_failure = true;
    }

    memset(mspack_handle, 0, (sizeof(*mspack_handle)));
    free(mspack_handle);
    mspack_handle = NULL;
    return;
}

static int mspack_fmap_read(struct mspack_file *file, void *buffer, int bytes)
{
    struct mspack_handle *mspack_handle = (struct mspack_handle *)file;
    size_t offset;
    size_t count;
    int ret;

    if (bytes < 0) {
        cli_dbgmsg("%s() %d\n", __func__, __LINE__);
        return -1;
    }
    if (!mspack_handle) {
        cli_dbgmsg("%s() %d\n", __func__, __LINE__);
        return -1;
    }
    if (!mspack_deadline_ok(mspack_handle->system_ex))
        return -1;

    if (mspack_handle->type == FILETYPE_FMAP) {
        /* Use fmap */
        if (mspack_fmap_absolute_offset(mspack_handle, &offset) != 0) {
            cli_dbgmsg("%s() fmap offset could not be represented or remained within the input map\n", __func__);
            return -1;
        }

        /* fmap_readn() clips requests that cross the end of the map. Keep
         * that distinction: a callback failure for the clipped prefix is
         * decoder EOF/truncation, while a failure for a fully contained
         * request is an operational read failure. */
        bool request_in_range = offset <= mspack_handle->fmap->len &&
                                (size_t)bytes <= mspack_handle->fmap->len - offset;

        count = fmap_readn(mspack_handle->fmap, buffer, offset, (size_t)bytes);
        if (count == (size_t)-1) {
            if (request_in_range && mspack_handle->system_ex != NULL)
                mspack_handle->system_ex->read_failure = true;
            cli_dbgmsg("%s() %d requested %d bytes, read failed (-1)\n", __func__, __LINE__, bytes);
            return request_in_range ? -1 : 0;
        } else if ((int)count < bytes) {
            cli_dbgmsg("%s() %d requested %d bytes, read %zu bytes\n", __func__, __LINE__, bytes, count);
        }

        mspack_handle->offset += (off_t)count;

        return (int)count;
    } else {
        /* Use file descriptor */
        count = fread(buffer, (size_t)bytes, 1, mspack_handle->f);
        if (count < 1) {
            cli_dbgmsg("%s() %d requested %d bytes, read failed (%zu)\n", __func__, __LINE__, bytes, count);
            return -1;
        }

        ret = (int)count;

        return ret;
    }
}

static int mspack_fmap_write(struct mspack_file *file, void *buffer, int bytes)
{
    struct mspack_handle *mspack_handle = (struct mspack_handle *)file;
    size_t count;
    uint64_t max_size;

    if (bytes < 0 || !mspack_handle) {
        cli_dbgmsg("%s() err %d\n", __func__, __LINE__);
        return -1;
    }
    if (!mspack_deadline_ok(mspack_handle->system_ex))
        return -1;

    if (mspack_handle->type == FILETYPE_FMAP) {
        cli_dbgmsg("%s() err %d\n", __func__, __LINE__);
        return -1;
    }

    if (!bytes)
        return 0;

    max_size = mspack_handle->max_size;
    if (max_size == UINT64_MAX) {
        /* Unlimited still means that the bytes must actually be written. */
        max_size = (uint64_t)bytes;
    } else {
        if (!max_size) {
            mspack_handle->limit_exceeded = true;
            cli_dbgmsg("%s() extraction limit exhausted\n", __func__);
            return -1;
        }

        if (max_size < (uint64_t)bytes)
            mspack_handle->limit_exceeded = true;

        max_size = max_size < (uint64_t)bytes ? max_size : (uint64_t)bytes;

        mspack_handle->max_size -= max_size;
    }

    /* Re-check after output-budget admission and immediately before
     * materializing decoder output. */
    if (!mspack_deadline_ok(mspack_handle->system_ex))
        return -1;

    count = fwrite(buffer, max_size, 1, mspack_handle->f);
    if (count < 1) {
        cli_dbgmsg("%s() err %d <%zu %d>\n", __func__, __LINE__, count, bytes);
        return -1;
    }

    if (mspack_handle->limit_exceeded) {
        cli_dbgmsg("%s() extraction limit reached during write\n", __func__);
        return -1;
    }

    /* Report the number of bytes actually written. */
    return (int)max_size;
}

static int mspack_fmap_seek(struct mspack_file *file, off_t offset, int mode)
{
    struct mspack_handle *mspack_handle = (struct mspack_handle *)file;

    if (!mspack_handle) {
        cli_dbgmsg("%s() err %d\n", __func__, __LINE__);
        return -1;
    }
    if (!mspack_deadline_ok(mspack_handle->system_ex))
        return -1;

    if (mspack_handle->type == FILETYPE_FMAP) {
        off_t base;
        off_t map_length;
        off_t new_pos;
        uintmax_t magnitude;

        if (mspack_fmap_length(mspack_handle->fmap, &map_length) != 0 ||
            mspack_handle->offset < 0 || mspack_handle->offset > map_length) {
            cli_dbgmsg("%s() err %d\n", __func__, __LINE__);
            return -1;
        }

        switch (mode) {
            case MSPACK_SYS_SEEK_START:
                base = 0;
                break;
            case MSPACK_SYS_SEEK_CUR:
                base = mspack_handle->offset;
                break;
            case MSPACK_SYS_SEEK_END:
                base = map_length;
                break;
            default:
                cli_dbgmsg("%s() err %d\n", __func__, __LINE__);
                return -1;
        }

        if (offset >= 0) {
            if (offset > map_length - base)
                return -1;
            new_pos = base + offset;
        } else {
            /* Avoid negating the minimum representable off_t. */
            magnitude = (uintmax_t)(-(offset + 1)) + 1;
            if ((uintmax_t)base < magnitude)
                return -1;
            new_pos = base - (off_t)magnitude;
        }

        mspack_handle->offset = new_pos;
        return 0;
    }

    switch (mode) {
        case MSPACK_SYS_SEEK_START:
            mode = SEEK_SET;
            break;
        case MSPACK_SYS_SEEK_CUR:
            mode = SEEK_CUR;
            break;
        case MSPACK_SYS_SEEK_END:
            mode = SEEK_END;
            break;
        default:
            cli_dbgmsg("%s() err %d\n", __func__, __LINE__);
            return -1;
    }

    return fseek(mspack_handle->f, offset, mode);
}

static off_t mspack_fmap_tell(struct mspack_file *file)
{
    struct mspack_handle *mspack_handle = (struct mspack_handle *)file;

    if (!mspack_handle)
        return -1;

    if (mspack_handle->type == FILETYPE_FMAP)
        return mspack_handle->offset;

    return (off_t)ftell(mspack_handle->f);
}

static void mspack_fmap_message(struct mspack_file *file, const char *fmt, ...)
{
    UNUSEDPARAM(file);

    if (UNLIKELY(cli_debug_flag)) {
        va_list args;
        char buff[BUFSIZ];
        size_t len = sizeof("LibClamAV debug: ") - 1;

        memset(buff, 0, BUFSIZ);

        /* Add the prefix */
        memcpy(buff, "LibClamAV debug: ", len);

        va_start(args, fmt);
        vsnprintf(buff + len, sizeof(buff) - len - 2, fmt, args);
        va_end(args);

        /* Add a newline and a null terminator */
        buff[strlen(buff)]     = '\n';
        buff[strlen(buff) + 1] = '\0';

        clrs_eprint(buff);
    }
}

static void *mspack_fmap_alloc(struct mspack_system *self, size_t num)
{
    UNUSEDPARAM(self);
    void *addr = cli_max_malloc(num);
    if (addr) {
        memset(addr, 0, num);
    }
    return addr;
}

static void mspack_fmap_free(void *mem)
{
    if (mem) {
        free(mem);
        mem = NULL;
    }
    return;
}

static void mspack_fmap_copy(void *src, void *dst, size_t num)
{
    memcpy(dst, src, num);
}

static struct mspack_system mspack_sys_fmap_ops = {
    .open    = mspack_fmap_open,
    .close   = mspack_fmap_close,
    .read    = mspack_fmap_read,
    .write   = mspack_fmap_write,
    .seek    = mspack_fmap_seek,
    .tell    = mspack_fmap_tell,
    .message = mspack_fmap_message,
    .alloc   = mspack_fmap_alloc,
    .free    = mspack_fmap_free,
    .copy    = mspack_fmap_copy,
};

static void mspack_cleanup_temp(cli_ctx *ctx, char **tmp_fname, bool *tempfile_exists,
                                uint64_t *temporary_reserved, cl_error_t *status,
                                const char *unlink_reason)
{
    if (tmp_fname != NULL && *tmp_fname != NULL) {
        if (!ctx->engine->keeptmp && (tempfile_exists == NULL || *tempfile_exists) &&
            cli_unlink(*tmp_fname)) {
            cli_mark_scan_incomplete(ctx, unlink_reason);
            *status = cli_merge_cleanup_status(*status, CL_EUNLINK);
        }
        free(*tmp_fname);
        *tmp_fname = NULL;
    }
    if (tempfile_exists != NULL)
        *tempfile_exists = false;
    if (temporary_reserved != NULL) {
        cli_scan_release_temporary(ctx, *temporary_reserved);
        *temporary_reserved = 0;
    }
}

bool cli_mspack_output_matches_declared(const char *path, uint64_t declared_size)
{
    STATBUF output_stat;

    if (path == NULL || CLAMSTAT(path, &output_stat) != 0 || output_stat.st_size < 0 ||
        !S_ISREG(output_stat.st_mode))
        return false;

    return (uint64_t)output_stat.st_size == declared_size;
}

cl_error_t cli_mscab_header_check(cli_ctx *ctx, size_t offset, size_t *size)
{
    static const size_t cab_header_size = 36;
    cl_error_t status = CL_EFORMAT;

    struct mscab_decompressor *cab_d = NULL;
    struct mscabd_cabinet *cab_h     = NULL;
    struct mspack_name mspack_fmap   = {0};
    struct mspack_system_ex ops_ex   = {0};
    unsigned char header[36];
    uint64_t remaining;
    uint32_t cabinet_size;
    uint32_t files_offset;

    if (NULL == ctx || NULL == size) {
        cli_dbgmsg("%s() invalid argument\n", __func__);
        status = CL_EARG;
        goto done;
    }

    *size            = 0;
    if (NULL == ctx->fmap) {
        cli_mark_scan_incomplete(ctx, "MSPack CAB header input map is unavailable");
        status = CL_EPARSE;
        goto done;
    }
    mspack_fmap.fmap = ctx->fmap;

    /* File-type recognition proves only the four-byte MSCF marker. Require
     * the complete fixed CAB header before treating a candidate as a
     * confirmed archive. A complete header whose declared extent is outside
     * the containing map is malformed/truncated, not a disproven signature. */
    remaining = (offset <= ctx->fmap->len) ? (uint64_t)(ctx->fmap->len - offset) : 0;
    if (remaining < cab_header_size)
        goto done;
    if (fmap_readn(ctx->fmap, header, offset, cab_header_size) != cab_header_size) {
        cli_mark_scan_incomplete(ctx, "CAB fixed header could not be read completely");
        status = CL_EREAD;
        goto done;
    }
    if (memcmp(header, "MSCF", 4) != 0)
        goto done;

    cabinet_size = cli_readint32(header + 8);
    files_offset = cli_readint32(header + 16);
    if (cabinet_size < cab_header_size || (uint64_t)cabinet_size > remaining ||
        files_offset < cab_header_size || files_offset > cabinet_size) {
        cli_mark_scan_incomplete(ctx, "CAB fixed header is malformed or truncated");
        status = CL_EPARSE;
        goto done;
    }

    if ((off_t)offset < 0 || (uint64_t)(off_t)offset != (uint64_t)offset) {
        cli_dbgmsg("%s() offset cannot be represented by off_t: %zu\n", __func__, offset);
        status = CL_EFORMAT;
        goto done;
    }

    mspack_fmap.org = (off_t)offset;

    ops_ex.ops = mspack_sys_fmap_ops;
    ops_ex.ctx = ctx;
    ops_ex.time_limit_reason = "CAB header inspection reached the configured time limit";
    if (!mspack_deadline_ok(&ops_ex)) {
        status = CL_ETIMEOUT;
        goto done;
    }

    cab_d = mspack_create_cab_decompressor(&ops_ex.ops);
    if (NULL == cab_d) {
        cli_dbgmsg("%s() failed at %d\n", __func__, __LINE__);
        cli_mark_scan_incomplete(ctx, "CAB decompressor could not be constructed");
        status = CL_EUNPACK;
        goto done;
    }

    cab_h = cab_d->open(cab_d, (char *)&mspack_fmap);
    if (NULL == cab_h) {
        cli_dbgmsg("%s() failed at %d\n", __func__, __LINE__);
        cli_mark_scan_incomplete(ctx, "CAB archive header could not be inspected completely");
        status = mspack_decoder_failure(&ops_ex, CL_EPARSE);
        goto done;
    }
    if (ops_ex.time_limit_exceeded) {
        status = CL_ETIMEOUT;
        goto done;
    }
    if (ops_ex.read_failure) {
        cli_mark_scan_incomplete(ctx, "CAB archive header could not be read completely");
        status = CL_EREAD;
        goto done;
    }

    *size = (size_t)cab_h->length;

    cli_dbgmsg("%s(): Successfully read CAB header for CAB of size %zu\n", __func__, *size);
    status = CL_SUCCESS;

done:
    if (NULL != cab_d) {
        if (NULL != cab_h) {
            cab_d->close(cab_d, cab_h);
        }
        mspack_destroy_cab_decompressor(cab_d);
    }

    return status;
}

cl_error_t cli_scanmscab(cli_ctx *ctx, size_t sfx_offset)
{
    cl_error_t ret                   = CL_SUCCESS;
    struct mscab_decompressor *cab_d = NULL;
    struct mscabd_cabinet *cab_h     = NULL;
    struct mscabd_file *cab_f        = NULL;
    int files;
    struct mspack_name mspack_fmap = {0};
    struct mspack_system_ex ops_ex = {0};

    char *tmp_fname      = NULL;
    bool tempfile_exists = false;
    uint64_t temporary_reserved = 0;

    if (NULL == ctx)
        return CL_ENULLARG;
    if (NULL == ctx->fmap) {
        cli_mark_scan_incomplete(ctx, "MSPack CAB input map is unavailable");
        return CL_EPARSE;
    }
    if (NULL == ctx->engine)
        return CL_ENULLARG;

    mspack_fmap.fmap = ctx->fmap;

    if ((off_t)sfx_offset < 0 || (uint64_t)(off_t)sfx_offset != (uint64_t)sfx_offset) {
        cli_dbgmsg("%s() offset cannot be represented by off_t: %zu\n", __func__, sfx_offset);
        ret = CL_EFORMAT;
        goto done;
    }

    mspack_fmap.org = (off_t)sfx_offset;

    memset(&ops_ex, 0, sizeof(struct mspack_system_ex));
    ops_ex.ops = mspack_sys_fmap_ops;
    ops_ex.ctx = ctx;
    ops_ex.time_limit_reason = "CAB decoder reached the configured time limit";
    if (!mspack_deadline_ok(&ops_ex)) {
        ret = CL_ETIMEOUT;
        goto done;
    }

    cab_d = mspack_create_cab_decompressor(&ops_ex.ops);
    if (!cab_d) {
        cli_dbgmsg("%s() failed at %d\n", __func__, __LINE__);
        cli_mark_scan_incomplete(ctx, "CAB decompressor could not be constructed");
        ret = CL_EUNPACK;
        goto done;
    }

    cab_d->set_param(cab_d, MSCABD_PARAM_FIXMSZIP, 1);
#if MSCABD_PARAM_SALVAGE
    cab_d->set_param(cab_d, MSCABD_PARAM_SALVAGE, 1);
#endif

    cab_h = cab_d->open(cab_d, (char *)&mspack_fmap);
    if (NULL == cab_h) {
        cli_dbgmsg("%s() failed at %d\n", __func__, __LINE__);
        cli_mark_scan_incomplete(ctx, "CAB archive could not be opened for inspection");
        ret = mspack_decoder_failure(&ops_ex, CL_EFORMAT);
        goto done;
    }
    if (ops_ex.time_limit_exceeded) {
        ret = CL_ETIMEOUT;
        goto done;
    }
    if (ops_ex.read_failure) {
        cli_mark_scan_incomplete(ctx, "CAB archive could not be read completely");
        ret = CL_EREAD;
        goto done;
    }

    files = 0;
    for (cab_f = cab_h->files; cab_f; cab_f = cab_f->next) {
        uint64_t member_size;
        uint64_t max_size;

        member_size = (uint64_t)cab_f->length;

        ret = cli_matchmeta(ctx, cab_f->filename, 0, member_size, 0,
                            files, 0);
        if (CL_SUCCESS != ret) {
            goto done;
        }

        if (ctx->engine->maxscansize) {
            if (ctx->scansize >= ctx->engine->maxscansize) {
                cli_mark_scan_incomplete(ctx, "CAB archive inspection reached MaxScanSize");
                ret = CL_EMAXSIZE;
                goto done;
            }
        }

        if (ctx->engine->maxscansize > 0) {
            uint64_t remaining = ctx->engine->maxscansize - ctx->scansize;
            max_size           = ctx->engine->maxfilesize ? ctx->engine->maxfilesize : UINT64_MAX;
            if (max_size > remaining)
                max_size = remaining;
        } else {
            max_size = ctx->engine->maxfilesize ? ctx->engine->maxfilesize : UINT64_MAX;
        }
        if (max_size > member_size)
            max_size = member_size;

        if (!mspack_deadline_ok(&ops_ex)) {
            ret = CL_ETIMEOUT;
            goto done;
        }
        ret = cli_scan_reserve_temporary(ctx, member_size);
        if (ret != CL_SUCCESS)
            goto done;
        temporary_reserved = member_size;

        if (!mspack_deadline_ok(&ops_ex)) {
            ret = CL_ETIMEOUT;
            goto done;
        }

        tmp_fname = cli_gentemp(ctx->this_layer_tmpdir);
        if (!tmp_fname) {
            cli_mark_scan_incomplete(ctx, "CAB temporary output could not be created");
            ret = CL_EMEM;
            cli_scan_release_temporary(ctx, temporary_reserved);
            temporary_reserved = 0;
            goto done;
        }
        tempfile_exists = false;

        ops_ex.max_size = max_size;

        /* scan */
        ret             = cab_d->extract(cab_d, cab_f, tmp_fname);
        tempfile_exists = (access(tmp_fname, F_OK) == 0);
        if (ops_ex.time_limit_exceeded) {
            ret = CL_ETIMEOUT;
            goto done;
        }
    if (ops_ex.read_failure) {
        cli_mark_scan_incomplete(ctx, "CAB member input could not be read completely");
        ret = CL_EREAD;
        goto done;
    }
    if (ops_ex.close_failure) {
        cli_mark_scan_incomplete(ctx, "CAB member output could not be closed");
        ret = cli_merge_cleanup_status(ret, CL_EWRITE);
        goto done;
    }
    if (ret) {
            /* Salvage mode may leave a truncated member on disk. Never let
             * that partial object replace an extraction failure: content
             * beyond the truncation point would otherwise be reported clean. */
            cli_dbgmsg("%s() failed to extract %d; refusing to scan partial member\n", __func__, ret);
            cli_mark_scan_incomplete(ctx, "CAB member extraction was incomplete");
            ret = CL_EPARSE;
            goto done;
        }

        if (tempfile_exists && !cli_mspack_output_matches_declared(tmp_fname, member_size)) {
            cli_mark_scan_incomplete(ctx, "CAB extracted member size or type did not match its declaration");
            ret = CL_EPARSE;
            goto done;
        }
        if (!tempfile_exists && member_size != 0) {
            cli_mark_scan_incomplete(ctx, "CAB extracted member output was not materialized");
            ret = CL_EPARSE;
            goto done;
        }

        if (!mspack_deadline_ok(&ops_ex)) {
            ret = CL_ETIMEOUT;
            goto done;
        }

        ret = cli_magic_scan_file(tmp_fname, ctx, cab_f->filename, LAYER_ATTRIBUTES_NONE);
        if (CL_EOPEN == ret && !tempfile_exists) {
            /* A successful extractor may report no output for an empty or
             * unsupported member. Only that no-file case is optional; an
             * existing extracted file that cannot be opened is incomplete. */
            ret = CL_SUCCESS;
        } else if (CL_SUCCESS != ret) {
            if (CL_EOPEN == ret) {
                cli_mark_scan_incomplete(ctx, "CAB extracted member could not be opened");
                ret = CL_EPARSE;
            }
            goto done;
        }

        mspack_cleanup_temp(ctx, &tmp_fname, &tempfile_exists, &temporary_reserved,
                            &ret, "CAB temporary output could not be removed");
        if (ret != CL_SUCCESS)
            goto done;

        files++;
    }

done:

    mspack_cleanup_temp(ctx, &tmp_fname, &tempfile_exists, &temporary_reserved,
                        &ret, "CAB temporary output could not be removed");

    if (NULL != cab_d) {
        if (NULL != cab_h) {
            cab_d->close(cab_d, cab_h);
        }
        mspack_destroy_cab_decompressor(cab_d);
    }

    return ret;
}

cl_error_t cli_scanmschm(cli_ctx *ctx)
{
    cl_error_t ret                     = CL_SUCCESS;
    struct mschm_decompressor *mschm_d = NULL;
    struct mschmd_header *mschm_h      = NULL;
    struct mschmd_file *mschm_f        = NULL;
    int files;
    struct mspack_name mspack_fmap = {0};
    struct mspack_system_ex ops_ex;

    char *tmp_fname      = NULL;
    bool tempfile_exists = false;
    uint64_t temporary_reserved = 0;

    if (NULL == ctx)
        return CL_ENULLARG;
    if (NULL == ctx->fmap) {
        cli_mark_scan_incomplete(ctx, "MSPack CHM input map is unavailable");
        return CL_EPARSE;
    }
    if (NULL == ctx->engine)
        return CL_ENULLARG;
    mspack_fmap.fmap = ctx->fmap;

    memset(&ops_ex, 0, sizeof(struct mspack_system_ex));
    ops_ex.ops = mspack_sys_fmap_ops;
    ops_ex.ctx = ctx;
    ops_ex.time_limit_reason = "CHM decoder reached the configured time limit";
    if (!mspack_deadline_ok(&ops_ex)) {
        ret = CL_ETIMEOUT;
        goto done;
    }

    mschm_d = mspack_create_chm_decompressor(&ops_ex.ops);
    if (!mschm_d) {
        cli_dbgmsg("%s() failed at %d\n", __func__, __LINE__);
        cli_mark_scan_incomplete(ctx, "CHM decompressor could not be constructed");
        ret = CL_EUNPACK;
        goto done;
    }

    mschm_h = mschm_d->open(mschm_d, (char *)&mspack_fmap);
    if (!mschm_h) {
        cli_dbgmsg("%s() failed at %d\n", __func__, __LINE__);
        cli_mark_scan_incomplete(ctx, "CHM archive could not be opened for inspection");
        ret = mspack_decoder_failure(&ops_ex, CL_EFORMAT);
        goto done;
    }
    if (ops_ex.time_limit_exceeded) {
        ret = CL_ETIMEOUT;
        goto done;
    }
    if (ops_ex.read_failure) {
        cli_mark_scan_incomplete(ctx, "CHM archive could not be read completely");
        ret = CL_EREAD;
        goto done;
    }

    files = 0;
    for (mschm_f = mschm_h->files; mschm_f; mschm_f = mschm_f->next) {
        uint64_t member_size;
        uint64_t max_size;

        if (mschm_f->length < 0) {
            cli_mark_scan_incomplete(ctx, "CHM member length is not representable");
            ret = CL_EFORMAT;
            goto done;
        }
        member_size = (uint64_t)mschm_f->length;

        ret = cli_matchmeta(ctx, mschm_f->filename, 0, member_size,
                            0, files, 0);
        if (CL_SUCCESS != ret) {
            goto done;
        }

        if (ctx->engine->maxscansize) {
            if (ctx->scansize >= ctx->engine->maxscansize) {
                cli_mark_scan_incomplete(ctx, "CHM archive inspection reached MaxScanSize");
                ret = CL_EMAXSIZE;
                goto done;
            }
        }

        if (ctx->engine->maxscansize > 0) {
            uint64_t remaining = ctx->engine->maxscansize - ctx->scansize;
            max_size           = ctx->engine->maxfilesize ? ctx->engine->maxfilesize : UINT64_MAX;
            if (max_size > remaining)
                max_size = remaining;
        } else {
            max_size = ctx->engine->maxfilesize ? ctx->engine->maxfilesize : UINT64_MAX;
        }
        if (max_size > member_size)
            max_size = member_size;

        if (!mspack_deadline_ok(&ops_ex)) {
            ret = CL_ETIMEOUT;
            goto done;
        }
        ret = cli_scan_reserve_temporary(ctx, member_size);
        if (ret != CL_SUCCESS)
            goto done;
        temporary_reserved = member_size;

        if (!mspack_deadline_ok(&ops_ex)) {
            ret = CL_ETIMEOUT;
            goto done;
        }

        tmp_fname = cli_gentemp(ctx->this_layer_tmpdir);
        if (!tmp_fname) {
            cli_mark_scan_incomplete(ctx, "CHM temporary output could not be created");
            ret = CL_EMEM;
            cli_scan_release_temporary(ctx, temporary_reserved);
            temporary_reserved = 0;
            break;
        }
        tempfile_exists = false;

        ops_ex.max_size = max_size;

        /* scan */
        ret             = mschm_d->extract(mschm_d, mschm_f, tmp_fname);
        tempfile_exists = (access(tmp_fname, F_OK) == 0);
        if (ops_ex.time_limit_exceeded) {
            ret = CL_ETIMEOUT;
            goto done;
        }
        if (ops_ex.read_failure) {
            cli_mark_scan_incomplete(ctx, "CHM member input could not be read completely");
            ret = CL_EREAD;
            goto done;
        }
        if (ops_ex.close_failure) {
            cli_mark_scan_incomplete(ctx, "CHM member output could not be closed");
            ret = cli_merge_cleanup_status(ret, CL_EWRITE);
            goto done;
        }
        if (ret) {
            /* Failed to extract. Never scan the partial output. */
            cli_dbgmsg("%s() failed to extract %d; refusing to scan partial member\n", __func__, ret);
            cli_mark_scan_incomplete(ctx, "CHM member extraction was incomplete");
            ret = CL_EPARSE;
            goto done;
        }

        if (tempfile_exists && !cli_mspack_output_matches_declared(tmp_fname, member_size)) {
            cli_mark_scan_incomplete(ctx, "CHM extracted member size or type did not match its declaration");
            ret = CL_EPARSE;
            goto done;
        }
        if (!tempfile_exists && member_size != 0) {
            cli_mark_scan_incomplete(ctx, "CHM extracted member output was not materialized");
            ret = CL_EPARSE;
            goto done;
        }

        if (!mspack_deadline_ok(&ops_ex)) {
            ret = CL_ETIMEOUT;
            goto done;
        }

        ret = cli_magic_scan_file(tmp_fname, ctx, mschm_f->filename, LAYER_ATTRIBUTES_NONE);
        if (CL_EOPEN == ret && !tempfile_exists) {
            /* Only a missing extracted output is optional. Preserve a
             * failure to open an output that actually exists. */
            ret = CL_SUCCESS;
        } else if (CL_SUCCESS != ret) {
            if (CL_EOPEN == ret) {
                cli_mark_scan_incomplete(ctx, "CHM extracted member could not be opened");
                ret = CL_EPARSE;
            }
            goto done;
        }

        mspack_cleanup_temp(ctx, &tmp_fname, &tempfile_exists, &temporary_reserved,
                            &ret, "CHM temporary output could not be removed");
        if (ret != CL_SUCCESS)
            goto done;

        files++;
    }

done:

    mspack_cleanup_temp(ctx, &tmp_fname, &tempfile_exists, &temporary_reserved,
                        &ret, "CHM temporary output could not be removed");

    if (NULL != mschm_d) {
        if (NULL != mschm_h) {
            mschm_d->close(mschm_d, mschm_h);
        }
        mspack_destroy_chm_decompressor(mschm_d);
    }

    return ret;
}
