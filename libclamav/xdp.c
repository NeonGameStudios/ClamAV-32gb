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

static char *dump_xdp(cli_ctx *ctx, fmap_t *map);

static const struct key_entry xdp_keys[] = {
    {"chunk", "XDPChunk", MSXML_SCAN_B64}};

static char *dump_xdp(cli_ctx *ctx, fmap_t *map)
{
    int fd;
    char *filename;
    unsigned char buffer[FILEBUFF];
    size_t offset = 0;
    size_t wanted;
    size_t nread;

    if (cli_gentempfd(ctx->this_layer_tmpdir, &filename, &fd) != CL_SUCCESS)
        return NULL;

    while (offset < map->len) {
        wanted = MIN(sizeof(buffer), map->len - offset);
        nread  = fmap_readn(map, buffer, offset, wanted);
        if (nread != wanted) {
            cli_errmsg("dump_xdp: failed to read XDP input at offset %zu\n", offset);
            close(fd);
            cli_unlink(filename);
            free(filename);
            return NULL;
        }

        if (cli_scan_reserve_temporary(ctx, (uint64_t)nread) != CL_SUCCESS) {
            close(fd);
            cli_unlink(filename);
            free(filename);
            return NULL;
        }
        if (cli_writen(fd, buffer, nread) != nread) {
            cli_scan_release_temporary(ctx, (uint64_t)nread);
            close(fd);
            cli_unlink(filename);
            free(filename);
            return NULL;
        }
        cli_scan_release_temporary(ctx, (uint64_t)nread);
        offset += nread;
    }

    cli_dbgmsg("dump_xdp: Dumped payload to %s\n", filename);

    close(fd);

    return filename;
}

cl_error_t cli_scanxdp(cli_ctx *ctx)
{
    char *dumpname;

    if (!ctx || !ctx->fmap)
        return CL_ENULLARG;

    if (ctx->engine && ctx->engine->keeptmp) {
        dumpname = dump_xdp(ctx, ctx->fmap);
        if (dumpname)
            free(dumpname);
    }

    return cli_msxml_parse_document_streaming(ctx, ctx->fmap, xdp_keys, sizeof(xdp_keys) / sizeof(xdp_keys[0]),
                                              MSXML_FLAG_FAIL_INCOMPLETE, NULL);
}
