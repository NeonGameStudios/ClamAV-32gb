/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Nigel Horne
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

#include "clamav.h"

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdio.h>
#include <memory.h>
#include <sys/stat.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include "others.h"
#include "str.h"

#include "mbox.h"
#include "uuencode.h"

/* Maximum line length according to RFC821 */
#define RFC2821LENGTH 1000

static cl_error_t uuencode_checktimelimit(cli_ctx *ctx, const char *reason)
{
    cl_error_t ret = cli_checktimelimit(ctx);

    if (ret != CL_SUCCESS)
        cli_mark_scan_incomplete_specific(ctx, reason);

    return ret;
}

static cl_error_t uuencode_reconcile_status(cli_ctx *ctx, cl_error_t status)
{
    if ((status == CL_CLEAN || status == CL_SUCCESS) && ctx->scan_incomplete)
        return CL_EPARSE;

    return status;
}

static cl_error_t uuencode_fileblob_status(const fileblob *fb)
{
    if (fb == NULL)
        return CL_ERESOURCE;
    if (!fb->isIncomplete && (fb->fp == NULL || fb->fullname == NULL))
        return CL_ERESOURCE;
    return fb->incomplete_status != CL_SUCCESS ? fb->incomplete_status : CL_ERESOURCE;
}

int cli_uuencode(cli_ctx *ctx, const char *dir, fmap_t *map)
{
    cl_error_t status;
    int decode_status;
    cl_error_t decode_failure = CL_SUCCESS;
    message *m;
    char buffer[RFC2821LENGTH + 1];
    size_t at = 0;

    if (ctx == NULL)
        return CL_ENULLARG;
    if (map == NULL) {
        cli_mark_scan_incomplete(ctx, "UUencoded input map is unavailable");
        return CL_EPARSE;
    }
    /* The map is passed explicitly because this helper is also used by the
     * mail parser. Bind it to the context before any required-path failure so
     * sticky incomplete reporting marks the map being inspected. */
    ctx->fmap = map;
    if (ctx->engine == NULL)
        return CL_ENULLARG;

    status = uuencode_checktimelimit(ctx, "UUencoded inspection reached the configured time limit");
    if (status != CL_SUCCESS)
        return status;

    if (!fmap_gets(map, buffer, &at, sizeof(buffer) - 1)) {
        /* EOF at the end of the map is an empty message. A nonempty map that
         * could not yield its first line indicates an incomplete read or
         * invalid fmap range and must not be normalized to clean. */
        if (at < map->len) {
            cli_mark_scan_incomplete(ctx, "UUencoded input could not be read completely");
            return CL_EREAD;
        }
        return uuencode_reconcile_status(ctx, CL_CLEAN);
    }
    if (!isuuencodebegin(buffer)) {
        cli_dbgmsg("Message is not in uuencoded format\n");
        return CL_EFORMAT;
    }

    m = messageCreate();
    if (m == NULL) {
        cli_mark_scan_incomplete(ctx, "UUencoded message state could not be allocated");
        return CL_EMEM;
    }

    messageSetCTX(m, ctx);

    cli_dbgmsg("found uuencode file\n");

    /* uudecodeFile() retains private negative statuses for read failures and
     * incomplete materialization. Keep that result in an int; storing it in
     * cl_error_t lets optimizing compilers assume the enum is non-negative. */
    decode_status = uudecodeFile(m, buffer, dir, map, &at, &decode_failure);
    if (decode_status < 0) {
        messageDestroy(m);
        if (decode_failure != CL_SUCCESS)
            return decode_failure;
        if (ctx->scan_timed_out)
            return CL_ETIMEOUT;
        if (decode_status == UUDECODE_READ_ERROR)
            return CL_EREAD;
        cli_dbgmsg("UUencoded attachment ended before its terminator or contained invalid data\n");
        cli_mark_scan_incomplete(ctx, "UUencoded attachment was not terminated or decoded completely");
        return CL_EPARSE;
    }
    messageDestroy(m);

    return uuencode_reconcile_status(ctx, CL_CLEAN);
}

/*
 * Save the uuencoded part of the file as it is read in since there's no need
 * to include it in the parse tree. Saves memory and parse time.
 * Return < 0 for failure
 */
int uudecodeFile(message *m, const char *firstline, const char *dir, fmap_t *map, size_t *at,
                 cl_error_t *failure_status)
{
    fileblob *fb;
    char buffer[RFC2821LENGTH + 1];
    char *filename = cli_strtok(firstline, 2, " ");
    bool saw_end                = false;
    bool data_block_ended       = false;
    bool materialization_failed = false;
    bool read_failed            = false;

    if (failure_status)
        *failure_status = CL_SUCCESS;

    if (filename == NULL)
        return -1;

    fb = fileblobCreate();
    if (fb == NULL) {
        cli_mark_scan_incomplete(m->ctx, "UUencoded attachment output blob could not be allocated");
        if (failure_status)
            *failure_status = CL_EMEM;
        free(filename);
        return -1;
    }

    fileblobSetCTX(fb, m->ctx);
    fileblobSetFilename(fb, dir, filename);
    if (fb->isIncomplete || fb->fp == NULL || fb->fullname == NULL) {
        if (failure_status)
            *failure_status = uuencode_fileblob_status(fb);
        cli_mark_scan_incomplete(m->ctx, "UUencoded attachment output blob could not be initialized");
        free(filename);
        fileblobDestroy(fb);
        return -1;
    }
    cli_dbgmsg("uudecode %s\n", filename);
    free(filename);

    while (1) {
        unsigned char data[1024];
        const unsigned char *uptr;
        size_t len;

        cl_error_t limit_status = uuencode_checktimelimit(
            m->ctx, "UUencoded attachment traversal reached the configured time limit");
        if (limit_status != CL_SUCCESS) {
            if (failure_status)
                *failure_status = limit_status;
            materialization_failed = true;
            break;
        }

        if (!fmap_gets(map, buffer, at, sizeof(buffer) - 1)) {
            if (*at < map->len) {
                cli_mark_scan_incomplete(m->ctx, "UUencoded input could not be read completely");
                if (failure_status)
                    *failure_status = CL_EREAD;
                read_failed = true;
            }
            break;
        }

        cli_chomp(buffer);
        if (data_block_ended) {
            if (strcasecmp(buffer, "end") == 0) {
                saw_end = true;
                break;
            }
            cli_mark_scan_incomplete(m->ctx, "UUencoded attachment was not terminated or decoded completely");
            materialization_failed = true;
            break;
        }
        if (strcasecmp(buffer, "end") == 0) {
            saw_end = true;
            break;
        }
        if (buffer[0] == '\0')
            break;

        uptr = decodeLine(m, UUENCODE, buffer, data, sizeof(data));
        if (uptr == NULL)
            break;

        len = (size_t)(uptr - data);
        if (len == 0 && ((buffer[0] & 0x3F) == ' ')) {
            data_block_ended = true;
            continue;
        }
        if ((len > 62) || (len == 0))
            break;

        if (fileblobAddData(fb, data, len) < 0) {
            if (failure_status)
                *failure_status = uuencode_fileblob_status(fb);
            cli_mark_scan_incomplete(m->ctx, "UUencoded attachment could not be materialized completely");
            materialization_failed = true;
            break;
        }
    }

    fileblobDestroy(fb);

    if (read_failed)
        return UUDECODE_READ_ERROR;
    return saw_end && !materialization_failed ? 1 : -1;
}
