/*
 *  Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 *
 *  Author: Shawn Webb
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
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL.  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so.  If you
 *  do not wish to do so, delete this exception statement from your
 *  version.  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#if !defined(_WIN32)
#include <unistd.h>
#endif
#include "xar.h"
#include "fmap.h"

#include "clamav.h"
#include "xdp.h"
#include "msxml_parser.h"

static cl_error_t xdp_checktimelimit(cli_ctx *ctx, const char *reason)
{
    cl_error_t ret = cli_checktimelimit(ctx);

    if (ret != CL_SUCCESS)
        cli_mark_scan_incomplete(ctx, reason);

    return ret;
}

static cl_error_t dump_xdp(cli_ctx *ctx, fmap_t *map, char **filename,
                           uint64_t *temporary_reserved);

static const struct key_entry xdp_keys[] = {
    {"chunk", "XDPChunk", MSXML_SCAN_B64}};

static cl_error_t dump_xdp(cli_ctx *ctx, fmap_t *map, char **filename,
                           uint64_t *temporary_reserved)
{
    int fd = -1;
    cl_error_t ret;
    unsigned char buffer[FILEBUFF];
    size_t offset = 0;
    size_t wanted;
    size_t nread;

    if (!ctx || !map || !filename || !temporary_reserved)
        return CL_ENULLARG;

    *filename           = NULL;
    *temporary_reserved = 0;

    ret = xdp_checktimelimit(ctx, "XDP temporary dump reached the configured time limit");
    if (ret != CL_SUCCESS)
        return ret;

    ret = cli_gentempfd(ctx->this_layer_tmpdir, filename, &fd);
    if (ret != CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, "XDP temporary output could not be created");
        return ret;
    }

    while (offset < map->len) {
        ret = xdp_checktimelimit(ctx, "XDP temporary dump reached the configured time limit");
        if (ret != CL_SUCCESS)
            goto fail;

        wanted = MIN(sizeof(buffer), map->len - offset);
        nread  = fmap_readn(map, buffer, offset, wanted);
        if (nread != wanted) {
            cli_errmsg("dump_xdp: failed to read XDP input at offset %zu\n", offset);
            cli_mark_scan_incomplete(ctx, "XDP temporary dump input could not be read completely");
            ret = CL_EREAD;
            goto fail;
        }

        if (UINT64_MAX - *temporary_reserved < (uint64_t)nread) {
            cli_mark_scan_incomplete(ctx, "XDP temporary dump accounting overflowed");
            ret = CL_ERESOURCE;
            goto fail;
        }
        ret = cli_scan_reserve_temporary(ctx, (uint64_t)nread);
        if (ret != CL_SUCCESS) {
            cli_mark_scan_incomplete(ctx, "XDP temporary dump exceeded temporary storage limits");
            goto fail;
        }
        *temporary_reserved += (uint64_t)nread;
        ret = xdp_checktimelimit(ctx, "XDP temporary dump reached the configured time limit");
        if (ret != CL_SUCCESS)
            goto fail;
        if (cli_writen(fd, buffer, nread) != nread) {
            cli_mark_scan_incomplete(ctx, "XDP temporary dump could not be written completely");
            ret = CL_EWRITE;
            goto fail;
        }
        offset += nread;
    }

    cli_dbgmsg("dump_xdp: Dumped payload to %s\n", *filename);

    if (close(fd) != 0) {
        fd = -1;
        cli_mark_scan_incomplete(ctx, "XDP temporary dump could not be closed");
        ret = CL_EWRITE;
        goto fail;
    }
    fd = -1;

    return CL_SUCCESS;

fail:
    if (fd >= 0 && close(fd) != 0)
        cli_mark_scan_incomplete(ctx, "XDP temporary dump could not be closed");
    if (*filename != NULL) {
        if (cli_unlink(*filename) != 0)
            cli_mark_scan_incomplete(ctx, "XDP partial temporary dump could not be removed");
        free(*filename);
        *filename = NULL;
    }
    if (*temporary_reserved != 0) {
        cli_scan_release_temporary(ctx, *temporary_reserved);
        *temporary_reserved = 0;
    }
    return ret;
}

cl_error_t cli_scanxdp(cli_ctx *ctx)
{
    char *dumpname = NULL;
    cl_error_t ret;
    uint64_t dump_reserved = 0;

    if (!ctx || !ctx->fmap)
        return CL_ENULLARG;

    if (ctx->engine && ctx->engine->keeptmp) {
        ret = dump_xdp(ctx, ctx->fmap, &dumpname, &dump_reserved);
        if (ret != CL_SUCCESS)
            return ret;
    }

    ret = cli_msxml_parse_document_streaming(ctx, ctx->fmap, xdp_keys, sizeof(xdp_keys) / sizeof(xdp_keys[0]),
                                             MSXML_FLAG_FAIL_INCOMPLETE, NULL);

    if (dump_reserved != 0)
        cli_scan_release_temporary(ctx, dump_reserved);
    free(dumpname);

    return ret;
}
