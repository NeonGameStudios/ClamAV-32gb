/*
 *  Copyright (C) 2014-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Kevin Lin <kevlin2@cisco.com>
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
#include <errno.h>
#if HAVE_STRING_H
#include <string.h>
#endif
#include <ctype.h>
#include <fcntl.h>

#include "clamav-types.h"
#include "others.h"
#include "apm.h"
#include "partition_intersection.h"
#include "scanners.h"
#include "dconf.h"

// #define DEBUG_APM_PARSE

#ifdef DEBUG_APM_PARSE
#define apm_parsemsg(...) cli_dbgmsg(__VA_ARGS__)
#else
#define apm_parsemsg(...) ;
#endif

static cl_error_t apm_partition_intersection(cli_ctx *ctx, struct apm_partition_info *aptable, size_t sectorsize,
                                             bool old_school, size_t tableoff, size_t tableend);

static bool apm_scale_blocks(uint64_t blocks, size_t sectorsize, size_t *bytes)
{
    if ((NULL == bytes) || (0 == sectorsize) || (blocks > SIZE_MAX / sectorsize))
        return false;

    *bytes = (size_t)blocks * sectorsize;
    return true;
}

static cl_error_t apm_read(cli_ctx *ctx, void *dst, size_t at, size_t len, const char *reason)
{
    if (at > ctx->fmap->len || len > ctx->fmap->len - at)
        return CL_EFORMAT;

    size_t got = fmap_readn(ctx->fmap, dst, at, len);

    if (got == len)
        return CL_SUCCESS;
    if (got == (size_t)-1) {
        cli_mark_scan_incomplete(ctx, reason);
        return CL_EREAD;
    }
    return CL_EFORMAT;
}

cl_error_t cli_scanapm(cli_ctx *ctx)
{
    cl_error_t status = CL_SUCCESS;
    struct apm_driver_desc_map ddm;
    struct apm_partition_info aptable, apentry;
    bool old_school = false;
    size_t sectorsize, maplen, partsize, described_size;
    size_t tableoff = 0, tablesize = 0;
    size_t tableend = 0;
    size_t pos = 0, partoff = 0;
    unsigned i;
    uint32_t max_prtns = 0;

    if (!ctx)
        return CL_ENULLARG;
    if (!ctx->fmap) {
        cli_errmsg("cli_scanapm: Invalid context\n");
        cli_mark_scan_incomplete(ctx, "APM input map is unavailable");
        status = CL_EPARSE;
        goto done;
    }

    status = cli_checktimelimit(ctx);
    if (status != CL_SUCCESS)
        goto done;

    /* read driver description map at sector 0  */
    status = apm_read(ctx, &ddm, pos, sizeof(ddm), "APM driver description map could not be read completely");
    if (status != CL_SUCCESS) {
        cli_dbgmsg("cli_scanapm: Invalid Apple driver description map\n");
        goto done;
    }

    /* convert driver description map big-endian to host */
    ddm.signature  = be16_to_host(ddm.signature);
    ddm.blockSize  = be16_to_host(ddm.blockSize);
    ddm.blockCount = be32_to_host(ddm.blockCount);

    /* check DDM signature */
    if (ddm.signature != DDM_SIGNATURE) {
        cli_dbgmsg("cli_scanapm: Apple driver description map signature mismatch\n");
        status = CL_EFORMAT;
        goto done;
    }

    /* sector size is determined by the ddm */
    sectorsize = ddm.blockSize;

    /* size of total file must be described by the ddm. Promote before
     * multiplying so a 32-bit field product cannot wrap on a large image. */
    maplen = ctx->fmap->len;
    if (ddm.blockSize != 0 && ddm.blockCount > SIZE_MAX / ddm.blockSize) {
        cli_mark_scan_incomplete(ctx, "APM declared image size overflowed");
        status = CL_EFORMAT;
        goto done;
    }
    described_size = (size_t)ddm.blockSize * ddm.blockCount;
    if (described_size != maplen) {
        cli_dbgmsg("cli_scanapm: File described %zu size does not match %lu actual size\n",
                   described_size, (unsigned long)maplen);
        status = CL_EFORMAT;
        goto done;
    }

    /* check for old-school partition map */
    if (sectorsize == 2048) {
        status = apm_read(ctx, &aptable, APM_FALLBACK_SECTOR_SIZE, sizeof(aptable),
                          "APM fallback partition entry could not be read completely");
        if (status != CL_SUCCESS) {
            cli_dbgmsg("cli_scanapm: Invalid Apple partition entry\n");
            goto done;
        }

        aptable.signature = be16_to_host(aptable.signature);
        if (aptable.signature == APM_SIGNATURE) {
            sectorsize = APM_FALLBACK_SECTOR_SIZE;
            old_school = true;
        }
    }

    /* read partition table at sector 1 (or after the ddm if old-school) */
    if (!apm_scale_blocks(APM_PTABLE_BLOCK, sectorsize, &pos)) {
        cli_mark_scan_incomplete(ctx, "APM partition-table offset overflowed");
        status = CL_EFORMAT;
        goto done;
    }

    status = apm_read(ctx, &aptable, pos, sizeof(aptable), "APM partition table could not be read completely");
    if (status != CL_SUCCESS) {
        cli_dbgmsg("cli_scanapm: Invalid Apple partition table\n");
        goto done;
    }

    /* convert partition table big endian to host */
    aptable.signature     = be16_to_host(aptable.signature);
    aptable.numPartitions = be32_to_host(aptable.numPartitions);
    aptable.pBlockStart   = be32_to_host(aptable.pBlockStart);
    aptable.pBlockCount   = be32_to_host(aptable.pBlockCount);

    /* check the partition entry signature */
    if (aptable.signature != APM_SIGNATURE) {
        cli_dbgmsg("cli_scanapm: Apple partition table signature mismatch\n");
        status = CL_EFORMAT;
        goto done;
    }

    /* check if partition table partition */
    if (strncmp((char *)aptable.type, "Apple_Partition_Map", 32) &&
        strncmp((char *)aptable.type, "Apple_partition_map", 32) &&
        strncmp((char *)aptable.type, "Apple_patition_map", 32)) {
        cli_dbgmsg("cli_scanapm: Initial Apple Partition Map partition is not detected\n");
        status = CL_EFORMAT;
        goto done;
    }

    if (!apm_scale_blocks(aptable.pBlockStart, sectorsize, &tableoff) ||
        !apm_scale_blocks(aptable.pBlockCount, sectorsize, &tablesize)) {
        cli_mark_scan_incomplete(ctx, "APM partition table coordinate overflowed");
        status = CL_EFORMAT;
        goto done;
    }
    if (tableoff > maplen || tablesize > maplen - tableoff) {
        cli_mark_scan_incomplete(ctx, "APM partition table is outside the input map");
        status = CL_EFORMAT;
        goto done;
    }
    tableend = tableoff + tablesize;

    /* check that the partition table fits in the space specified - HEURISTICS */
    if (SCAN_HEURISTIC_PARTITION_INTXN && (ctx->dconf->other & OTHER_CONF_PRTNINTXN)) {
        status = apm_partition_intersection(ctx, &aptable, sectorsize, old_school, tableoff, tableend);
        if (status != CL_SUCCESS) {
            goto done;
        }
    }

    /* print debugging info on partition tables */
    cli_dbgmsg("APM Partition Table:\n");
    cli_dbgmsg("Name: %s\n", (char *)aptable.name);
    cli_dbgmsg("Type: %s\n", (char *)aptable.type);
    cli_dbgmsg("Signature: %x\n", aptable.signature);
    cli_dbgmsg("Partition Count: %u\n", aptable.numPartitions);
    cli_dbgmsg("Blocks: [%u, +%u), ([%lu, +%lu))\n",
               aptable.pBlockStart, aptable.pBlockCount,
               (unsigned long)tableoff, (unsigned long)tablesize);

    /* check engine maxpartitions limit */
    if (aptable.numPartitions < ctx->engine->maxpartitions) {
        max_prtns = aptable.numPartitions;
    } else {
        max_prtns = ctx->engine->maxpartitions;
    }

    /* partition table is a partition [at index 1], so skip it */
    for (i = 2; i <= max_prtns; ++i) {
        status = cli_checktimelimit(ctx);
        if (status != CL_SUCCESS)
            goto done;

        /* read partition table entry */
        if (!apm_scale_blocks(i, sectorsize, &pos)) {
            cli_mark_scan_incomplete(ctx, "APM partition entry offset overflowed");
            status = CL_EFORMAT;
            goto done;
        }
        if (pos < tableoff || pos > tableend || sizeof(apentry) > tableend - pos) {
            cli_mark_scan_incomplete(ctx, "APM partition entry is outside the declared partition table");
            status = CL_EFORMAT;
            goto done;
        }
        status = apm_read(ctx, &apentry, pos, sizeof(apentry), "APM partition entry could not be read completely");
        if (status != CL_SUCCESS) {
            cli_dbgmsg("cli_scanapm: Invalid Apple partition entry\n");
            goto done;
        }

        /* convert partition entry big endian to host */
        apentry.signature     = be16_to_host(apentry.signature);
        apentry.reserved      = be16_to_host(apentry.reserved);
        apentry.numPartitions = be32_to_host(apentry.numPartitions);
        apentry.pBlockStart   = be32_to_host(apentry.pBlockStart);
        apentry.pBlockCount   = be32_to_host(apentry.pBlockCount);

        /* check the partition entry signature */
        if (apentry.signature != APM_SIGNATURE) {
            cli_dbgmsg("cli_scanapm: Apple partition entry signature mismatch\n");
            status = CL_EFORMAT;
            goto done;
        }

        /* check if an out-of-order partition map */
        if (!strncmp((char *)apentry.type, "Apple_Partition_Map", 32) ||
            !strncmp((char *)apentry.type, "Apple_partition_map", 32) ||
            !strncmp((char *)apentry.type, "Apple_patition_map", 32)) {

            cli_dbgmsg("cli_scanapm: Out of order Apple Partition Map partition\n");
            continue;
        }

        if (!apm_scale_blocks(apentry.pBlockStart, sectorsize, &partoff) ||
            !apm_scale_blocks(apentry.pBlockCount, sectorsize, &partsize)) {
            cli_mark_scan_incomplete(ctx, "APM partition coordinate overflowed");
            status = CL_EFORMAT;
            goto done;
        }
        /* re-calculate if old_school and aligned [512 * 4 => 2048] */
        if (old_school && ((i % 4) == 0)) {
            if (!strncmp((char *)apentry.type, "Apple_Driver", 32) ||
                !strncmp((char *)apentry.type, "Apple_Driver43", 32) ||
                !strncmp((char *)apentry.type, "Apple_Driver43_CD", 32) ||
                !strncmp((char *)apentry.type, "Apple_Driver_ATA", 32) ||
                !strncmp((char *)apentry.type, "Apple_Driver_ATAPI", 32) ||
                !strncmp((char *)apentry.type, "Apple_Patches", 32)) {

                if (!apm_scale_blocks(apentry.pBlockCount, 4U * APM_FALLBACK_SECTOR_SIZE, &partsize)) {
                    cli_mark_scan_incomplete(ctx, "APM old-school partition coordinate overflowed");
                    status = CL_EFORMAT;
                    goto done;
                }
            }
        }

        /* check if invalid partition */
        if ((partoff == 0) || (partoff > maplen) || (partsize > maplen - partoff)) {
            cli_dbgmsg("cli_scanapm: Detected invalid Apple partition entry\n");
            cli_mark_scan_incomplete(ctx, "APM partition entry is outside the input map");
            status = CL_EFORMAT;
            goto done;
        }

        /* print debugging info on partition */
        cli_dbgmsg("APM Partition Entry %u:\n", i);
        cli_dbgmsg("Name: %s\n", (char *)apentry.name);
        cli_dbgmsg("Type: %s\n", (char *)apentry.type);
        cli_dbgmsg("Signature: %x\n", apentry.signature);
        cli_dbgmsg("Partition Count: %u\n", apentry.numPartitions);
        cli_dbgmsg("Blocks: [%u, +%u), ([%zu, +%zu))\n",
                   apentry.pBlockStart, apentry.pBlockCount, partoff, partsize);

        /* send the partition to cli_magic_scan_nested_fmap_type */
        status = cli_magic_scan_nested_fmap_type(ctx->fmap, partoff, partsize, ctx, CL_TYPE_PART_ANY, (const char *)apentry.name, LAYER_ATTRIBUTES_NONE);
        if (status != CL_SUCCESS) {
            goto done;
        }
    }

    if (max_prtns < aptable.numPartitions) {
        cli_dbgmsg("cli_scanapm: max partitions reached\n");
        cli_mark_scan_incomplete(ctx, "APM partition count limit left a partition uninspected");
        if (status == CL_SUCCESS || status == CL_CLEAN)
            status = CL_EMAXFILES;
    }

done:

    if (ctx && status != CL_SUCCESS && status != CL_VIRUS && status != CL_BREAK && !ctx->scan_incomplete)
        cli_mark_scan_incomplete(ctx, "APM inspection ended before completion");

    return status;
}

static cl_error_t apm_partition_intersection(cli_ctx *ctx, struct apm_partition_info *aptable, size_t sectorsize,
                                              bool old_school, size_t tableoff, size_t tableend)
{
    cl_error_t status = CL_SUCCESS;
    cl_error_t ret;
    partition_intersection_list_t prtncheck;
    struct apm_partition_info apentry;
    unsigned i, pitxn;
    size_t pos;
    uint32_t max_prtns = 0;

    partition_intersection_list_init(&prtncheck);

    /* check engine maxpartitions limit */
    if (aptable->numPartitions < ctx->engine->maxpartitions) {
        max_prtns = aptable->numPartitions;
    } else {
        max_prtns = ctx->engine->maxpartitions;
    }

    for (i = 1; i <= max_prtns; ++i) {
        status = cli_checktimelimit(ctx);
        if (status != CL_SUCCESS)
            goto done;

        /* read partition table entry */
        if (!apm_scale_blocks(i, sectorsize, &pos)) {
            cli_mark_scan_incomplete(ctx, "APM intersection entry offset overflowed");
            status = CL_EFORMAT;
            goto done;
        }
        if (pos < tableoff || pos > tableend || sizeof(apentry) > tableend - pos) {
            cli_mark_scan_incomplete(ctx, "APM intersection entry is outside the declared partition table");
            status = CL_EFORMAT;
            goto done;
        }
        status = apm_read(ctx, &apentry, pos, sizeof(apentry), "APM partition intersection entry could not be read completely");
        if (status != CL_SUCCESS) {
            cli_dbgmsg("cli_scanapm: Invalid Apple partition entry\n");
            partition_intersection_list_free(&prtncheck);
            goto done;
        }

        /* convert necessary info big endian to host */
        apentry.pBlockStart = be32_to_host(apentry.pBlockStart);
        apentry.pBlockCount = be32_to_host(apentry.pBlockCount);
        /* re-calculate if old_school and aligned [512 * 4 => 2048] */
        if (old_school && ((i % 4) == 0)) {
            if (!strncmp((char *)apentry.type, "Apple_Driver", 32) ||
                !strncmp((char *)apentry.type, "Apple_Driver43", 32) ||
                !strncmp((char *)apentry.type, "Apple_Driver43_CD", 32) ||
                !strncmp((char *)apentry.type, "Apple_Driver_ATA", 32) ||
                !strncmp((char *)apentry.type, "Apple_Driver_ATAPI", 32) ||
                !strncmp((char *)apentry.type, "Apple_Patches", 32)) {

                if (apentry.pBlockCount > UINT32_MAX / 4U) {
                    cli_mark_scan_incomplete(ctx, "APM intersection block count overflowed");
                    status = CL_EFORMAT;
                    goto done;
                }
                apentry.pBlockCount *= 4U;
            }
        }

        ret = partition_intersection_list_check(&prtncheck, &pitxn, apentry.pBlockStart, apentry.pBlockCount);
        if (ret != CL_CLEAN) {
            if (ret == CL_VIRUS) {
                apm_parsemsg("Name: %s\n", (char *)aptable.name);
                apm_parsemsg("Type: %s\n", (char *)aptable.type);

                cli_dbgmsg("cli_scanapm: detected intersection with partitions "
                           "[%u, %u]\n",
                           pitxn, i);
                status = cli_append_potentially_unwanted(ctx, "Heuristics.APMPartitionIntersection");
                if (status != CL_SUCCESS) {
                    goto done;
                }
            } else {
                if (ret == CL_EMEM)
                    cli_mark_scan_incomplete(ctx, "APM partition intersection tracking could not be allocated");
                status = ret;
                goto done;
            }
        }

        /* increment the offsets to next partition entry */
        pos += sectorsize;
    }

done:
    partition_intersection_list_free(&prtncheck);

    return status;
}
