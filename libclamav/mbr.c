/*
 *  Copyright (C) 2014-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Kevin Lin <klin@sourcefire.com>
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
#include <zlib.h>

#include "clamav.h"
#include "others.h"
#include "mbr.h"
#include "partition_intersection.h"
#include "scanners.h"
#include "dconf.h"

// #define DEBUG_MBR_PARSE
// #define DEBUG_EBR_PARSE

#ifdef DEBUG_MBR_PARSE
#define mbr_parsemsg(...) cli_dbgmsg(__VA_ARGS__)
#else
#define mbr_parsemsg(...) ;
#endif

#ifdef DEBUG_EBR_PARSE
#define ebr_parsemsg(...) cli_dbgmsg(__VA_ARGS__)
#else
#define ebr_parsemsg(...) ;
#endif

enum MBR_STATE {
    SEEN_NOTHING,
    SEEN_PARTITION,
    SEEN_EXTENDED,
    SEEN_EMPTY
};

static cl_error_t mbr_scanextprtn(cli_ctx *ctx, unsigned *prtncount, size_t extlba,
                                  size_t extlbasize, size_t sectorsize);
static cl_error_t mbr_check_mbr(struct mbr_boot_record *record, size_t maplen, size_t sectorsize);
static cl_error_t mbr_check_ebr(struct mbr_boot_record *record);
static cl_error_t mbr_primary_partition_intersection(cli_ctx *ctx, struct mbr_boot_record mbr, size_t sectorsize);
static cl_error_t mbr_extended_partition_intersection(cli_ctx *ctx, unsigned *prtncount, size_t extlba, size_t sectorsize);

static bool mbr_scale_lba(uint64_t lba, size_t sectorsize, size_t *offset)
{
    if (!offset || sectorsize == 0 || lba > SIZE_MAX / sectorsize)
        return false;

    *offset = (size_t)lba * sectorsize;
    return true;
}

static bool mbr_add_lba(uint64_t left, uint64_t right, uint64_t *sum)
{
    if (!sum || left > UINT64_MAX - right)
        return false;

    *sum = left + right;
    return true;
}

static bool mbr_boot_record_offset(uint64_t lba, size_t sectorsize, size_t *offset)
{
    size_t base;

    if (sectorsize < sizeof(struct mbr_boot_record) ||
        !mbr_scale_lba(lba, sectorsize, offset))
        return false;

    base = sectorsize - sizeof(struct mbr_boot_record);
    if (*offset > SIZE_MAX - base)
        return false;
    *offset += base;
    return true;
}

static bool mbr_partition_range(uint64_t lba, uint64_t count, size_t sectorsize,
                                size_t *offset, size_t *length)
{
    return mbr_scale_lba(lba, sectorsize, offset) &&
           mbr_scale_lba(count, sectorsize, length);
}

static bool mbr_partition_extent_is_valid(const struct mbr_partition_entry *entry)
{
    /* A typed partition with no sectors cannot describe content.  Letting it
     * through would create a zero-length nested scan and could make a
     * structurally confirmed MBR appear complete without inspecting a real
     * partition. Empty entries may retain stale coordinates and are allowed
     * to follow the format's compatibility rules. */
    return entry != NULL && (entry->type == MBR_EMPTY || entry->numLBA != 0);
}

static cl_error_t mbr_read(cli_ctx *ctx, void *dst, size_t at, size_t len, const char *reason)
{
    size_t got;

    if (at > ctx->fmap->len || len > ctx->fmap->len - at)
        return CL_EFORMAT;

    got = fmap_readn(ctx->fmap, dst, at, len);
    if (got == len)
        return CL_SUCCESS;
    if (got == (size_t)-1) {
        cli_mark_scan_incomplete(ctx, reason);
        return CL_EREAD;
    }
    return CL_EFORMAT;
}

cl_error_t cli_mbr_check(const unsigned char *buff, size_t len, size_t maplen)
{
    struct mbr_boot_record mbr;
    size_t mbr_base   = 0;
    size_t sectorsize = 512;

    if (len < sectorsize) {
        return CL_EFORMAT;
    }

    mbr_base = sectorsize - sizeof(struct mbr_boot_record);
    memcpy(&mbr, buff + mbr_base, sizeof(mbr));
    mbr_convert_to_host(&mbr);

    if ((mbr.entries[0].type == MBR_PROTECTIVE) || (mbr.entries[0].type == MBR_HYBRID))
        return CL_TYPE_GPT;

    return mbr_check_mbr(&mbr, maplen, sectorsize);
}

cl_error_t cli_mbr_check2(cli_ctx *ctx, size_t sectorsize)
{
    struct mbr_boot_record mbr;
    cl_error_t read_status;
    size_t pos = 0;
    size_t maplen;

    if (!ctx)
        return CL_ENULLARG;
    if (!ctx->fmap) {
        cli_errmsg("cli_scanmbr: Invalid context\n");
        cli_mark_scan_incomplete(ctx, "MBR input map is unavailable");
        return CL_EPARSE;
    }

    /* sector size calculation, actual value is OS dependent */
    if (sectorsize == 0)
        sectorsize = MBR_SECTOR_SIZE;

    if (sectorsize < sizeof(struct mbr_boot_record)) {
        cli_mark_scan_incomplete(ctx, "MBR sector size is too small for a boot record");
        return CL_EFORMAT;
    }

    /* size of total file must be a multiple of the sector size */
    maplen = ctx->fmap->len;
    if ((maplen % sectorsize) != 0) {
        cli_dbgmsg("cli_scanmbr: File sized %lu is not a multiple of sector size %lu\n",
                   (unsigned long)maplen, (unsigned long)sectorsize);
        return CL_EFORMAT;
    }

    /* sector 0 (first sector) is the master boot record */
    if (!mbr_boot_record_offset(MBR_SECTOR, sectorsize, &pos)) {
        cli_mark_scan_incomplete(ctx, "MBR master boot record coordinate overflowed");
        return CL_EFORMAT;
    }

    /* read the master boot record */
    read_status = mbr_read(ctx, &mbr, pos, sizeof(mbr), "MBR master boot record could not be read completely");
    if (read_status != CL_SUCCESS) {
        cli_dbgmsg("cli_scanmbr: Invalid master boot record\n");
        return read_status;
    }

    /* convert the little endian to host, include the internal  */
    mbr_convert_to_host(&mbr);

    if ((mbr.entries[0].type == MBR_PROTECTIVE) || (mbr.entries[0].type == MBR_HYBRID))
        return CL_TYPE_GPT;

    cl_error_t status = mbr_check_mbr(&mbr, maplen, sectorsize);
    if ((status == CL_SUCCESS || status == CL_CLEAN) && ctx->scan_incomplete)
        status = CL_EPARSE;

    return status;
}

/* sets sectorsize to default value if specified to be 0 */
cl_error_t cli_scanmbr(cli_ctx *ctx, size_t sectorsize)
{
    cl_error_t status = CL_SUCCESS;
    struct mbr_boot_record mbr;
    enum MBR_STATE state = SEEN_NOTHING;
    size_t pos = 0, partoff = 0;
    unsigned i = 0, prtncount = 0;
    size_t maplen, partsize;

    mbr_parsemsg("The start of something magnificent: MBR parsing\n");

    if (!ctx)
        return CL_ENULLARG;
    if (!ctx->fmap) {
        cli_errmsg("cli_scanmbr: Invalid context\n");
        cli_mark_scan_incomplete(ctx, "MBR input map is unavailable");
        status = CL_EPARSE;
        goto done;
    }
    if (!ctx->engine)
        return CL_ENULLARG;
    if (!ctx->options)
        return CL_ENULLARG;
    if (SCAN_HEURISTIC_PARTITION_INTXN && ctx->dconf == NULL)
        return CL_ENULLARG;

    status = cli_checktimelimit(ctx);
    if (status != CL_SUCCESS)
        goto done;

    /* sector size calculation, actual value is OS dependent */
    if (sectorsize == 0)
        sectorsize = MBR_SECTOR_SIZE;

    if (sectorsize < sizeof(struct mbr_boot_record)) {
        cli_mark_scan_incomplete(ctx, "MBR sector size is too small for a boot record");
        status = CL_EFORMAT;
        goto done;
    }

    /* size of total file must be a multiple of the sector size */
    maplen = ctx->fmap->len;
    if ((maplen % sectorsize) != 0) {
        cli_dbgmsg("cli_scanmbr: File sized %lu is not a multiple of sector size %lu\n",
                   (unsigned long)maplen, (unsigned long)sectorsize);
        status = CL_EFORMAT;
        goto done;
    }

    /* sector 0 (first sector) is the master boot record */
    if (!mbr_boot_record_offset(MBR_SECTOR, sectorsize, &pos)) {
        cli_mark_scan_incomplete(ctx, "MBR master boot record coordinate overflowed");
        status = CL_EFORMAT;
        goto done;
    }

    /* read the master boot record */
    status = mbr_read(ctx, &mbr, pos, sizeof(mbr), "MBR master boot record could not be read completely");
    if (status != CL_SUCCESS) {
        cli_dbgmsg("cli_scanmbr: Invalid master boot record\n");
        goto done;
    }

    /* convert the little endian to host, include the internal  */
    mbr_convert_to_host(&mbr);

    /* MBR checks */
    status = mbr_check_mbr(&mbr, maplen, sectorsize);
    if (status != CL_SUCCESS) {
        goto done;
    }

    /* MBR is valid, examine bootstrap code */
    status = cli_magic_scan_nested_fmap_type(ctx->fmap, 0, sectorsize, ctx, CL_TYPE_ANY, NULL, LAYER_ATTRIBUTES_NONE);
    if (status != CL_SUCCESS) {
        goto done;
    }

    /* check that the partition table has no intersections - HEURISTICS */
    if (SCAN_HEURISTIC_PARTITION_INTXN && (ctx->dconf->other & OTHER_CONF_PRTNINTXN)) {
        status = mbr_primary_partition_intersection(ctx, mbr, sectorsize);
        if (status != CL_SUCCESS) {
            goto done;
        }
    }

    /* MBR is valid, examine partitions */
    prtncount = 0;
    cli_dbgmsg("MBR Signature: %x\n", mbr.signature);
    for (i = 0; i < MBR_MAX_PARTITION_ENTRIES && prtncount < ctx->engine->maxpartitions; ++i) {
        status = cli_checktimelimit(ctx);
        if (status != CL_SUCCESS)
            goto done;

        cli_dbgmsg("MBR Partition Entry %u:\n", i);
        cli_dbgmsg("Status: %u\n", mbr.entries[i].status);
        cli_dbgmsg("Type: %x\n", mbr.entries[i].type);
        if (!mbr_partition_range(mbr.entries[i].firstLBA, mbr.entries[i].numLBA,
                                 sectorsize, &partoff, &partsize)) {
            cli_mark_scan_incomplete(ctx, "MBR partition coordinate overflowed");
            status = CL_EFORMAT;
            goto done;
        }
        cli_dbgmsg("Blocks: [%u, +%u), ([%zu, +%zu))\n",
                   mbr.entries[i].firstLBA, mbr.entries[i].numLBA, partoff, partsize);

        /* Handle MBR entry based on type */
        if (mbr.entries[i].type == MBR_EMPTY) {
            /* empty partition entry */
            prtncount++;
        } else if (mbr.entries[i].type == MBR_EXTENDED) {
            if (state == SEEN_EXTENDED) {
                cli_dbgmsg("cli_scanmbr: detected a master boot record "
                           "with multiple extended partitions\n");
            }
            state = SEEN_EXTENDED; /* used only to detect multiple extended partitions */

            status = mbr_scanextprtn(ctx, &prtncount, mbr.entries[i].firstLBA,
                                     mbr.entries[i].numLBA, sectorsize);
            if (status != CL_SUCCESS) {
                goto done;
            }
        } else {
            prtncount++;

            mbr_parsemsg("cli_magic_scan_nested_fmap_type: [%u, +%u)\n", partoff, partsize);
            status = cli_magic_scan_nested_fmap_type(ctx->fmap, partoff, partsize, ctx, CL_TYPE_PART_ANY, NULL, LAYER_ATTRIBUTES_NONE);
            if (status != CL_SUCCESS) {
                goto done;
            }
        }
    }

    if (i < MBR_MAX_PARTITION_ENTRIES && prtncount >= ctx->engine->maxpartitions) {
        unsigned remaining;

        /* The loop stopped at the configured ceiling. Only make this
         * incomplete when a later non-empty table entry remains; a table
         * whose remaining entries are empty was fully inspected. */
        for (remaining = i; remaining < MBR_MAX_PARTITION_ENTRIES; remaining++) {
            if (mbr.entries[remaining].type != MBR_EMPTY) {
                cli_dbgmsg("cli_scanmbr: maximum partitions reached\n");
                cli_mark_scan_incomplete(ctx, "MBR partition count limit left a partition uninspected");
                if (status == CL_SUCCESS || status == CL_CLEAN)
                    status = CL_EMAXFILES;
                break;
            }
        }
    }

done:

    if (ctx && status != CL_SUCCESS && status != CL_VIRUS && status != CL_BREAK && !ctx->scan_incomplete)
        cli_mark_scan_incomplete(ctx, "MBR inspection ended before completion");
    if (ctx && (status == CL_SUCCESS || status == CL_CLEAN) && ctx->scan_incomplete)
        status = CL_EPARSE;

    return status;
}

static cl_error_t mbr_scanextprtn(cli_ctx *ctx, unsigned *prtncount, size_t extlba, size_t extlbasize, size_t sectorsize)
{
    cl_error_t status = CL_CLEAN;
    struct mbr_boot_record ebr;
    enum MBR_STATE state = SEEN_NOTHING;
    size_t pos = 0, logiclba = 0, extoff = 0, partoff = 0;
    size_t partsize, extsize;
    size_t extend;
    uint64_t record_lba, part_lba;
    unsigned i = 0, j = 0;

    ebr_parsemsg("The start of something exhausting: EBR parsing\n");

    logiclba = 0;
    if (!mbr_partition_range(extlba, extlbasize, sectorsize, &extoff, &extsize) ||
        extoff > SIZE_MAX - extsize) {
        cli_mark_scan_incomplete(ctx, "MBR extended partition coordinate overflowed");
        return CL_EFORMAT;
    }
    extend = extoff + extsize;
    do {
        status = cli_checktimelimit(ctx);
        if (status != CL_SUCCESS)
            goto done;

        if (!mbr_add_lba(extlba, logiclba, &record_lba) ||
            !mbr_boot_record_offset(record_lba, sectorsize, &pos)) {
            cli_mark_scan_incomplete(ctx, "MBR extended boot record coordinate overflowed");
            status = CL_EFORMAT;
            goto done;
        }

        /* read the extended boot record */
        status = mbr_read(ctx, &ebr, pos, sizeof(ebr), "MBR extended boot record could not be read completely");
        if (status != CL_SUCCESS) {
            cli_dbgmsg("cli_scanebr: Invalid extended boot record\n");
            goto done;
        }

        /* convert the little endian to host */
        mbr_convert_to_host(&ebr);

        /* EBR checks */
        status = mbr_check_ebr(&ebr);
        if (status != CL_SUCCESS) {
            goto done;
        }

        /* update state */
        state = SEEN_NOTHING;
        (*prtncount)++;

        /* EBR is valid, examine partitions */
        cli_dbgmsg("EBR Partition Entry %u:\n", i++);
        cli_dbgmsg("EBR Signature: %x\n", ebr.signature);
        for (j = 0; j < MBR_MAX_PARTITION_ENTRIES; ++j) {
            if (j < 2) {
                size_t entry_offset, entry_length;

                cli_dbgmsg("Logical Partition Entry %u:\n", j);
                cli_dbgmsg("Status: %u\n", ebr.entries[j].status);
                cli_dbgmsg("Type: %x\n", ebr.entries[j].type);
                if (!mbr_partition_range(ebr.entries[j].firstLBA, ebr.entries[j].numLBA,
                                         sectorsize, &entry_offset, &entry_length)) {
                    cli_mark_scan_incomplete(ctx, "MBR logical partition coordinate overflowed");
                    status = CL_EFORMAT;
                    goto done;
                }
                cli_dbgmsg("Blocks: [%u, +%u), ([%lu, +%lu))\n",
                           ebr.entries[j].firstLBA, ebr.entries[j].numLBA,
                           (unsigned long)entry_offset, (unsigned long)entry_length);

                if (ebr.entries[j].type == MBR_EMPTY) {
                    /* empty partition entry */
                    switch (state) {
                        case SEEN_NOTHING:
                            state = SEEN_EMPTY;
                            break;
                        case SEEN_PARTITION:
                            logiclba = 0;
                            break;
                        case SEEN_EMPTY:
                            logiclba = 0;
                            /* fall-through */
                        case SEEN_EXTENDED:
                            cli_warnmsg("cli_scanebr: detected a logical boot record "
                                        "without a partition record\n");
                            break;
                        default:
                            cli_warnmsg("cli_scanebr: undefined state for EBR parsing\n");
                            status = CL_EPARSE;
                            goto done;
                    }
                } else if (ebr.entries[j].type == MBR_EXTENDED) {
                    switch (state) {
                        case SEEN_NOTHING:
                            state = SEEN_EXTENDED;
                            break;
                        case SEEN_PARTITION:
                            break;
                        case SEEN_EMPTY:
                            cli_warnmsg("cli_scanebr: detected a logical boot record "
                                        "without a partition record\n");
                            break;
                        case SEEN_EXTENDED:
                            cli_warnmsg("cli_scanebr: detected a logical boot record "
                                        "with multiple extended partition records\n");
                            status = CL_EFORMAT;
                            goto done;
                        default:
                            cli_dbgmsg("cli_scanebr: undefined state for EBR parsing\n");
                            status = CL_EPARSE;
                            goto done;
                    }

                    logiclba = ebr.entries[j].firstLBA;
                } else {
                    switch (state) {
                        case SEEN_NOTHING:
                            state = SEEN_PARTITION;
                            break;
                        case SEEN_PARTITION:
                            cli_warnmsg("cli_scanebr: detected a logical boot record "
                                        "with multiple partition records\n");
                            logiclba = 0; /* no extended partitions are possible */
                            break;
                        case SEEN_EXTENDED:
                            cli_warnmsg("cli_scanebr: detected a logical boot record "
                                        "with extended partition record first\n");
                            break;
                        case SEEN_EMPTY:
                            cli_warnmsg("cli_scanebr: detected a logical boot record "
                                        "with empty partition record first\n");
                            logiclba = 0; /* no extended partitions are possible */
                            break;
                        default:
                            cli_dbgmsg("cli_scanebr: undefined state for EBR parsing\n");
                            status = CL_EPARSE;
                            goto done;
                    }

                    if (!mbr_add_lba(extlba, logiclba, &part_lba) ||
                        !mbr_add_lba(part_lba, ebr.entries[j].firstLBA, &part_lba) ||
                        !mbr_partition_range(part_lba, ebr.entries[j].numLBA, sectorsize,
                                             &partoff, &partsize) ||
                        partoff < extoff || partoff > extend ||
                        partsize > extend - partoff) {
                        cli_dbgmsg("cli_scanebr: Invalid extended partition entry\n");
                        cli_mark_scan_incomplete(ctx, "MBR extended partition coordinate overflowed");
                        status = CL_EFORMAT;
                        goto done;
                    }

                    status = cli_magic_scan_nested_fmap_type(ctx->fmap, partoff, partsize, ctx, CL_TYPE_PART_ANY, NULL, LAYER_ATTRIBUTES_NONE);
                    if (status != CL_SUCCESS) {
                        goto done;
                    }
                }
            } else {
                /* check the last two entries to be empty */
                if (ebr.entries[j].type != MBR_EMPTY) {
                    cli_dbgmsg("cli_scanebr: detected a non-empty partition "
                               "entry at index %u\n",
                               j);
                    /* should we attempt to use these entries? */
                    status = CL_EFORMAT;
                    goto done;
                }
            }
        }
    } while (logiclba != 0 && (*prtncount) < ctx->engine->maxpartitions);

    if (logiclba != 0 && ctx->engine->maxpartitions &&
        *prtncount >= ctx->engine->maxpartitions) {
        cli_dbgmsg("cli_scanebr: maximum partitions reached\n");
        cli_mark_scan_incomplete(ctx, "MBR logical partition count limit left a partition uninspected");
        status = CL_EMAXFILES;
    }

    cli_dbgmsg("cli_scanmbr: examined %u logical partitions\n", i);

done:

    return status;
}

void mbr_convert_to_host(struct mbr_boot_record *record)
{
    struct mbr_partition_entry *entry;
    unsigned i;

    for (i = 0; i < MBR_MAX_PARTITION_ENTRIES; ++i) {
        entry = &record->entries[i];

        entry->firstLBA = le32_to_host(entry->firstLBA);
        entry->numLBA   = le32_to_host(entry->numLBA);
    }
    record->signature = be16_to_host(record->signature);
}

static cl_error_t mbr_check_mbr(struct mbr_boot_record *record, size_t maplen, size_t sectorsize)
{
    cl_error_t status = CL_SUCCESS;
    unsigned i        = 0;
    size_t partoff    = 0;
    size_t partsize   = 0;

    for (i = 0; i < MBR_MAX_PARTITION_ENTRIES; ++i) {
        /* check status */
        if ((record->entries[i].status != MBR_STATUS_INACTIVE) &&
            (record->entries[i].status != MBR_STATUS_ACTIVE)) {
            cli_dbgmsg("cli_scanmbr: Invalid boot record status\n");
            status = CL_EFORMAT;
            goto done;
        }

        if (!mbr_partition_extent_is_valid(&record->entries[i])) {
            cli_dbgmsg("cli_scanmbr: Non-empty partition has zero length\n");
            status = CL_EFORMAT;
            goto done;
        }

        if (!mbr_partition_range(record->entries[i].firstLBA, record->entries[i].numLBA,
                                 sectorsize, &partoff, &partsize) ||
            partoff > maplen || partsize > maplen - partoff) {
            cli_dbgmsg("cli_scanmbr: Invalid partition entry\n");
            status = CL_EFORMAT;
            goto done;
        }
    }

    /* check the signature */
    if (record->signature != MBR_SIGNATURE) {
        cli_dbgmsg("cli_scanmbr: Invalid boot record signature\n");
        status = CL_EFORMAT;
        goto done;
    }

    /* check the maplen */
    if ((maplen / sectorsize) < 2) {
        cli_dbgmsg("cli_scanmbr: bootstrap code or file is too small to hold disk image\n");
        status = CL_EFORMAT;
        goto done;
    }

done:

    return status;
}

static cl_error_t mbr_check_ebr(struct mbr_boot_record *record)
{
    cl_error_t status = CL_SUCCESS;
    unsigned i        = 0;

    for (i = 0; i < MBR_MAX_PARTITION_ENTRIES - 2; ++i) {
        /* check status */
        if ((record->entries[i].status != MBR_STATUS_INACTIVE) &&
            (record->entries[i].status != MBR_STATUS_ACTIVE)) {
            cli_dbgmsg("cli_scanmbr: Invalid boot record status\n");
            status = CL_EFORMAT;
            goto done;
        }
    }

    for (i = 0; i < MBR_MAX_PARTITION_ENTRIES; ++i) {
        if (!mbr_partition_extent_is_valid(&record->entries[i])) {
            cli_dbgmsg("cli_scanmbr: Non-empty logical partition has zero length\n");
            status = CL_EFORMAT;
            goto done;
        }
    }

    /* check the signature */
    if (record->signature != MBR_SIGNATURE) {
        cli_dbgmsg("cli_scanmbr: Invalid boot record signature\n");
        status = CL_EFORMAT;
        goto done;
    }

done:

    return status;
}

/* this includes the overall bounds of extended partitions */
static cl_error_t mbr_primary_partition_intersection(cli_ctx *ctx, struct mbr_boot_record mbr, size_t sectorsize)
{
    cl_error_t status = CL_CLEAN;
    cl_error_t ret;
    partition_intersection_list_t prtncheck;
    unsigned i = 0, pitxn = 0, prtncount = 0;

    partition_intersection_list_init(&prtncheck);

    for (i = 0; i < MBR_MAX_PARTITION_ENTRIES && prtncount < ctx->engine->maxpartitions; ++i) {
        status = cli_checktimelimit(ctx);
        if (status != CL_SUCCESS)
            goto done;

        if (mbr.entries[i].type == MBR_EMPTY) {
            /* empty partition entry */
            prtncount++;
        } else {
            ret = partition_intersection_list_check(&prtncheck, &pitxn, mbr.entries[i].firstLBA,
                                                    mbr.entries[i].numLBA);
            if (ret != CL_CLEAN) {
                if (ret == CL_VIRUS) {
                    cli_dbgmsg("cli_scanmbr: detected intersection with partitions "
                               "[%u, %u]\n",
                               pitxn, i);
                    status = cli_append_potentially_unwanted(ctx, "Heuristics.MBRPartitionnIntersect");
                    if (status != CL_SUCCESS) {
                        goto done;
                    }
                } else {
                    if (ret == CL_EMEM)
                        cli_mark_scan_incomplete(ctx, "MBR partition intersection tracking could not be allocated");
                    status = ret;
                    goto done;
                }
            }

            if (mbr.entries[i].type == MBR_EXTENDED) {
                /* check the logical partitions */
                ret = mbr_extended_partition_intersection(ctx, &prtncount,
                                                          mbr.entries[i].firstLBA, sectorsize);
                if (ret != CL_SUCCESS) {
                    status = ret;
                    goto done;
                }
            } else {
                prtncount++;
            }
        }
    }

done:
    partition_intersection_list_free(&prtncheck);
    return status;
}

/* checks internal logical partitions */
static cl_error_t mbr_extended_partition_intersection(cli_ctx *ctx, unsigned *prtncount, size_t extlba, size_t sectorsize)
{
    cl_error_t status = CL_CLEAN;
    cl_error_t ret;
    struct mbr_boot_record ebr;
    partition_intersection_list_t prtncheck;
    unsigned i, pitxn;
    size_t pos = 0, logiclba = 0;
    uint64_t record_lba;

    partition_intersection_list_init(&prtncheck);

    logiclba = 0;
    i        = 0;
    do {
        status = cli_checktimelimit(ctx);
        if (status != CL_SUCCESS)
            goto done;

        if (!mbr_add_lba(extlba, logiclba, &record_lba) ||
            !mbr_boot_record_offset(record_lba, sectorsize, &pos)) {
            cli_mark_scan_incomplete(ctx, "MBR extended intersection coordinate overflowed");
            status = CL_EFORMAT;
            goto done;
        }

        /* read the extended boot record */
        status = mbr_read(ctx, &ebr, pos, sizeof(ebr), "MBR extended intersection record could not be read completely");
        if (status != CL_SUCCESS) {
            cli_dbgmsg("cli_scanebr: Invalid extended boot record\n");
            partition_intersection_list_free(&prtncheck);
            goto done;
        }

        /* convert the little endian to host */
        mbr_convert_to_host(&ebr);

        /* update state */
        (*prtncount)++;

        /* assume that logical record is first and extended is second */
        ret = partition_intersection_list_check(&prtncheck, &pitxn, logiclba, ebr.entries[0].numLBA);
        if (ret != CL_CLEAN) {
            if (ret == CL_VIRUS) {
                cli_dbgmsg("cli_scanebr: detected intersection with partitions "
                           "[%u, %u]\n",
                           pitxn, i);
                status = cli_append_potentially_unwanted(ctx, "Heuristics.MBRPartitionnIntersect");
                /* Preserve every non-clean alert-recording result before
                 * following the extended-partition chain. */
                if (status != CL_SUCCESS) {
                    goto done;
                }
            } else {
                if (ret == CL_EMEM)
                    cli_mark_scan_incomplete(ctx, "MBR partition intersection tracking could not be allocated");
                status = ret;
                goto done;
            }
        }

        /* assume extended is second entry */
        if (ebr.entries[1].type != MBR_EXTENDED) {
            cli_dbgmsg("cli_scanebr: second entry for EBR is not an extended partition\n");
            break;
        }

        logiclba = ebr.entries[1].firstLBA;

        ++i;
    } while (logiclba != 0 && (*prtncount) < ctx->engine->maxpartitions);

done:
    partition_intersection_list_free(&prtncheck);

    return status;
}
