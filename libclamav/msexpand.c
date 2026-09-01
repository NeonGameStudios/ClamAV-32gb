/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm
 *
 *  Acknowledgements: Decompression scheme by M. Winterhoff.
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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#include "clamav.h"
#include "others.h"
#include "msexpand.h"
#include "fmap.h"

#ifndef HAVE_ATTRIB_PACKED
#define __attribute__(x)
#endif

#ifdef HAVE_PRAGMA_PACK
#pragma pack(1)
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack 1
#endif

#define EC32(x) le32_to_host(x)
#define EC16(x) le16_to_host(x)

#define MAGIC1 0x44445a53
#define MAGIC2 0x3327f088
#define MAGIC3 0x0041

struct msexp_hdr {
    uint32_t magic1;
    uint32_t magic2;
    uint16_t magic3;
    uint32_t fsize;
} __attribute__((packed));

#ifdef HAVE_PRAGMA_PACK
#pragma pack()
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack
#endif

static cl_error_t msexpand_reconcile_status(cli_ctx *ctx, cl_error_t status)
{
    if ((status == CL_SUCCESS || status == CL_CLEAN) && ctx->scan_incomplete)
        return CL_EPARSE;

    return status;
}

#define B_SIZE 4096
#define RW_SIZE 2048

#define READBYTES                                                                     \
    rbytes = MIN(RW_SIZE, map->len - cur_off);                                        \
    if (!rbytes)                                                                      \
        break;                                                                        \
    rbuff = fmap_need_off_once(map, cur_off, rbytes);                                 \
    if (!rbuff) {                                                                     \
        cli_mark_scan_incomplete(ctx, "MSEXPAND input could not be read completely"); \
        return CL_EREAD;                                                              \
    }                                                                                 \
    cur_off += rbytes;                                                                \
    r = 0;

#define WRITEBYTES                                                                            \
    if ((uint64_t)wbytes > (uint64_t)fsize || (uint64_t)w > (uint64_t)fsize - (uint64_t)wbytes) { \
        cli_mark_scan_incomplete(ctx, "MSEXPAND output exceeded its declared size");          \
        return CL_EFORMAT;                                                                     \
    }                                                                                         \
    status = msexpand_checktimelimit(ctx, "MSEXPAND output reached the configured time limit"); \
    if (status != CL_SUCCESS)                                                                   \
        return status;                                                                          \
    ret = cli_writen(ofd, wbuff, w);                                                          \
    if (ret == (size_t)-1 || (unsigned int)ret != w) {                                        \
        cli_mark_scan_incomplete(ctx, "MSEXPAND output could not be written completely");     \
        return CL_EWRITE;                                                                     \
    }                                                                                         \
    wbytes += w;                                                                              \
    if (wbytes == fsize)                                                                      \
        return msexpand_reconcile_status(ctx, CL_SUCCESS);                                    \
    w = 0;

static cl_error_t msexpand_checktimelimit(cli_ctx *ctx, const char *reason)
{
    cl_error_t status = cli_checktimelimit(ctx);

    if (status != CL_SUCCESS)
        cli_mark_scan_incomplete(ctx, reason);

    return status;
}

cl_error_t cli_msexpand(cli_ctx *ctx, int ofd, uint64_t *temporary_reserved)
{
    const struct msexp_hdr *hdr;
    uint8_t i, mask, bits;
    unsigned char buff[B_SIZE], wbuff[RW_SIZE];
    const unsigned char *rbuff = NULL; // rbuff will be set to a real address by READBYTES
                                       // in the first iteration of the loop.
    unsigned int j = B_SIZE - 16, k, l, r = 0, w = 0, rbytes = 0, wbytes = 0;
    fmap_t *map;
    size_t cur_off = sizeof(*hdr);
    unsigned int fsize;
    cl_error_t status;
    size_t ret;

    if (ctx == NULL) {
        cli_dbgmsg("MSEXPAND: passed context was NULL\n");
        return CL_ENULLARG;
    }
    map = ctx->fmap;
    if (map == NULL) {
        cli_mark_scan_incomplete(ctx, "MSEXPAND input map is unavailable");
        return CL_EPARSE;
    }
    if (ctx->engine == NULL) {
        cli_dbgmsg("MSEXPAND: owning engine was NULL\n");
        return CL_ENULLARG;
    }

    status = msexpand_checktimelimit(ctx, "MSEXPAND inspection reached the configured time limit");
    if (status != CL_SUCCESS)
        return status;

    if (map->len < sizeof(*hdr)) {
        cli_mark_scan_incomplete(ctx, "MSEXPAND header is truncated");
        return CL_EPARSE;
    }
    if (!(hdr = fmap_need_off_once(map, 0, sizeof(*hdr)))) {
        cli_mark_scan_incomplete(ctx, "MSEXPAND header could not be read completely");
        return CL_EREAD;
    }

    if (EC32(hdr->magic1) != MAGIC1 || EC32(hdr->magic2) != MAGIC2 || EC16(hdr->magic3) != MAGIC3) {
        cli_dbgmsg("MSEXPAND: Not supported file format\n");
        cli_mark_scan_incomplete(ctx, "MSEXPAND header has invalid magic");
        return CL_EFORMAT;
    }

    fsize = EC32(hdr->fsize);
    cli_dbgmsg("MSEXPAND: File size from header: %u\n", fsize);

    if ((status = cli_checklimits("MSEXPAND", ctx, fsize, 0, 0)) != CL_CLEAN)
        return status;

    if (NULL == temporary_reserved) {
        cli_mark_scan_incomplete(ctx, "MSEXPAND temporary quota state was not provided");
        return CL_ENULLARG;
    }
    if ((status = cli_scan_reserve_temporary(ctx, (uint64_t)fsize)) != CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, "MSEXPAND output exceeds temporary storage limits");
        return status;
    }
    *temporary_reserved = (uint64_t)fsize;

    memset(buff, 0, B_SIZE);
    while (1) {
        status = msexpand_checktimelimit(ctx, "MSEXPAND traversal reached the configured time limit");
        if (status != CL_SUCCESS)
            return status;

        if (!rbytes || (r == rbytes)) {
            READBYTES;
        }

        bits = rbuff[r];
        r++;

        mask = 1;
        for (i = 0; i < 8; i++) {
            if (bits & mask) {
                if (r == rbytes) {
                    READBYTES;
                }

                if (w == RW_SIZE) {
                    WRITEBYTES;
                }

                wbuff[w] = buff[j] = rbuff[r];
                r++;
                w++;
                j++;
                j %= B_SIZE;
            } else {
                if (r == rbytes) {
                    READBYTES;
                }
                k = rbuff[r];
                r++;

                if (r == rbytes) {
                    READBYTES;
                }
                l = rbuff[r];
                r++;

                k += (l & 0xf0) << 4;
                l = (l & 0x0f) + 3;
                while (l--) {
                    status = msexpand_checktimelimit(ctx, "MSEXPAND back-reference traversal reached the configured time limit");
                    if (status != CL_SUCCESS)
                        return status;
                    if (w == RW_SIZE) {
                        WRITEBYTES;
                    }
                    wbuff[w] = buff[j] = buff[k];
                    w++;
                    k++;
                    k %= B_SIZE;
                    j++;
                    j %= B_SIZE;
                }
            }
            mask *= 2;
        }
    }

    if (w) {
        WRITEBYTES;
    }

    if (wbytes < fsize) {
        cli_mark_scan_incomplete(ctx, "MSEXPAND input ended before the declared output was produced");
        return CL_EPARSE;
    }

    return msexpand_reconcile_status(ctx, CL_SUCCESS);
}
