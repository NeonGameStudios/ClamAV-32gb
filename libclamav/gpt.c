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
#include "gpt.h"
#include "mbr.h"
#include "str.h"
#include "entconv.h"
#include "partition_intersection.h"
#include "scanners.h"
#include "dconf.h"

#define GPT_CRC_CHUNK_SIZE (64U * 1024U)

static cl_error_t gpt_read(cli_ctx *ctx, void *dst, size_t at, size_t len, const char *reason)
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

static cl_error_t gpt_crc32_fmap(cli_ctx *ctx, size_t offset, size_t length, uint32_t *result)
{
    unsigned char buffer[GPT_CRC_CHUNK_SIZE];
    size_t done       = 0;
    uint32_t checksum = crc32(0, NULL, 0);

    if (result == NULL || offset > ctx->fmap->len || length > ctx->fmap->len - offset)
        return CL_EARG;

    while (done < length) {
        size_t chunk = MIN(sizeof(buffer), length - done);
        cl_error_t time_status = cli_checktimelimit(ctx);

        if (time_status != CL_SUCCESS)
            return time_status;

        if (fmap_readn(ctx->fmap, buffer, offset + done, chunk) != chunk) {
            cli_mark_scan_incomplete(ctx, "GPT partition table could not be read completely");
            return CL_EREAD;
        }
        checksum = crc32(checksum, buffer, (uInt)chunk);
        done += chunk;
    }

    *result = checksum;
    return CL_SUCCESS;
}
// #define DEBUG_GPT_PARSE
// #define DEBUG_GPT_PRINT

#ifdef DEBUG_GPT_PARSE
#define gpt_parsemsg(...) cli_dbgmsg(__VA_ARGS__)
#else
#define gpt_parsemsg(...) ;
#endif

#ifdef DEBUG_GPT_PRINT
#define gpt_printmsg(...) cli_dbgmsg(__VA_ARGS__)
#else
#define gpt_printmsg(...) ;
#endif

enum GPT_SCANSTATE {
    INVALID,
    PRIMARY_ONLY,
    SECONDARY_ONLY,
    BOTH
};

static cl_error_t gpt_scan_partitions(cli_ctx *ctx, struct gpt_header hdr, size_t sectorsize);
static cl_error_t gpt_validate_header(cli_ctx *ctx, struct gpt_header hdr, size_t sectorsize,
                                      uint64_t expected_current_lba);
static cl_error_t gpt_check_mbr(cli_ctx *ctx, size_t sectorsize);
static void gpt_printSectors(cli_ctx *ctx, size_t sectorsize);
static void gpt_printGUID(uint8_t GUID[], const char *msg);
static cl_error_t gpt_partition_intersection(cli_ctx *ctx, struct gpt_header hdr, size_t sectorsize);

/* returns 0 on failing to detect sectorsize */
static cl_error_t gpt_detect_size_read(fmap_t *map, size_t *detected_size, cli_ctx *ctx)
{
    static const size_t candidates[] = {512, 1024, 2048, 4096};
    unsigned char signature[sizeof(GPT_SIGNATURE_STR) - 1];
    size_t i;

    if (map == NULL || detected_size == NULL)
        return CL_EARG;

    *detected_size = 0;
    for (i = 0; i < sizeof(candidates) / sizeof(candidates[0]); ++i) {
        size_t offset = candidates[i];
        size_t bytes_read;

        /* An unavailable candidate is ordinary non-GPT input. Once the
         * complete candidate range is inside the map, however, a failed
         * backing read is an operational error and must remain visible. */
        if (offset > map->len || sizeof(signature) > map->len - offset)
            continue;

        bytes_read = fmap_readn(map, signature, offset, sizeof(signature));
        if (bytes_read == (size_t)-1) {
            if (ctx)
                cli_mark_scan_incomplete(ctx, "GPT sector-size probe could not be read completely");
            return CL_EREAD;
        }
        if (bytes_read != sizeof(signature)) {
            if (ctx)
                cli_mark_scan_incomplete(ctx, "GPT sector-size probe was truncated");
            return CL_EFORMAT;
        }
        if (memcmp(signature, GPT_SIGNATURE_STR, sizeof(signature)) == 0) {
            *detected_size = offset;
            return CL_SUCCESS;
        }
    }

    return CL_EFORMAT;
}

size_t gpt_detect_size(fmap_t *map)
{
    size_t detected_size = 0;

    if (gpt_detect_size_read(map, &detected_size, NULL) != CL_SUCCESS)
        return 0;

    return detected_size;
}

/* attempts to detect sector size is input as 0 */
cl_error_t cli_scangpt(cli_ctx *ctx, size_t sectorsize)
{
    cl_error_t status = CL_SUCCESS;
    struct gpt_header phdr, shdr;
    enum GPT_SCANSTATE state = INVALID;
    cl_error_t secondary_status;
    cl_error_t header_status;
    bool secondary_header_incomplete = false;
    size_t maplen;
    size_t pos = 0;

    gpt_parsemsg("The beginning of something big: GPT parsing\n");

    if (!ctx)
        return CL_ENULLARG;
    if (!ctx->fmap) {
        cli_errmsg("cli_scangpt: Invalid context\n");
        cli_mark_scan_incomplete(ctx, "GPT input map is unavailable");
        status = CL_EPARSE;
        goto done;
    }
    if (!ctx->engine)
        return CL_ENULLARG;

    status = cli_checktimelimit(ctx);
    if (status != CL_SUCCESS)
        goto done;

    /* sector size calculation */
    if (sectorsize == 0) {
        status = gpt_detect_size_read(ctx->fmap, &sectorsize, ctx);
        if (status != CL_SUCCESS)
            goto done;
        cli_dbgmsg("cli_scangpt: detected %lu sector size\n", (unsigned long)sectorsize);
    }
    if (sectorsize == 0) {
        cli_dbgmsg("cli_scangpt: could not determine sector size\n");
        status = CL_EFORMAT;
        goto done;
    }

    /* size of total file must be a multiple of the sector size */
    maplen = ctx->fmap->len;
    if (sectorsize < sizeof(struct mbr_boot_record) || sectorsize > SIZE_MAX / 2 ||
        maplen < sectorsize * 2) {
        cli_dbgmsg("cli_scangpt: Sector size or input map is too small for GPT headers\n");
        status = CL_EFORMAT;
        goto done;
    }
    if ((maplen % sectorsize) != 0) {
        cli_dbgmsg("cli_scangpt: File sized %lu is not a multiple of sector size %lu\n",
                   (unsigned long)maplen, (unsigned long)sectorsize);
        status = CL_EFORMAT;
        goto done;
    }

    /* check the protective mbr */
    status = gpt_check_mbr(ctx, sectorsize);
    if (status != CL_SUCCESS) {
        goto done;
    }

    pos = GPT_PRIMARY_HDR_LBA * sectorsize; /* sector 1 (second sector) is the primary gpt header */

    /* read primary gpt header */
    cli_dbgmsg("cli_scangpt: Using primary GPT header\n");
    status = gpt_read(ctx, &phdr, pos, sizeof(phdr), "GPT primary header could not be read completely");
    if (status != CL_SUCCESS) {
        cli_dbgmsg("cli_scangpt: Invalid primary GPT header\n");
        goto done;
    }

    pos = maplen - sectorsize; /* last sector is the secondary gpt header */

    header_status = gpt_validate_header(ctx, phdr, sectorsize, GPT_PRIMARY_HDR_LBA);
    if (header_status != CL_SUCCESS) {
        /* A malformed primary header can legitimately fall back to the
         * secondary copy. An operational failure while validating its
         * partition table cannot: treating that failure as mere corruption
         * would allow a successful secondary scan to hide an incomplete
         * primary inspection. */
        if (header_status != CL_EFORMAT) {
            status = header_status;
            goto done;
        }
        cli_dbgmsg("cli_scangpt: Primary GPT header is invalid\n");
        cli_dbgmsg("cli_scangpt: Using secondary GPT header\n");

        state = SECONDARY_ONLY;

        /* read secondary gpt header */
        status = gpt_read(ctx, &shdr, pos, sizeof(shdr), "GPT secondary header could not be read completely");
        if (status != CL_SUCCESS) {
            cli_dbgmsg("cli_scangpt: Invalid secondary GPT header\n");
            goto done;
        }

        header_status = gpt_validate_header(ctx, shdr, sectorsize, maplen / sectorsize - 1);
        if (header_status != CL_SUCCESS) {
            cli_dbgmsg("cli_scangpt: Secondary GPT header is invalid\n");
            cli_dbgmsg("cli_scangpt: Disk is unusable\n");
            status = header_status;
            goto done;
        }
    } else {
        cli_dbgmsg("cli_scangpt: Checking secondary GPT header\n");

        state = PRIMARY_ONLY;

        /* check validity of secondary header; still using the primary */
        secondary_status = gpt_read(ctx, &shdr, pos, sizeof(shdr), "GPT secondary header could not be read completely");
        if (secondary_status != CL_SUCCESS) {
            cli_dbgmsg("cli_scangpt: Invalid secondary GPT header\n");
            if (secondary_status == CL_EREAD) {
                status = secondary_status;
                goto done;
            }
        } else {
            header_status = gpt_validate_header(ctx, shdr, sectorsize, maplen / sectorsize - 1);
            if (header_status != CL_SUCCESS) {
                cli_dbgmsg("cli_scangpt: Secondary GPT header is invalid\n");
                if (header_status != CL_EFORMAT) {
                    status = header_status;
                    goto done;
                }
                cli_mark_scan_incomplete(ctx, "GPT secondary header was invalid");
                secondary_header_incomplete = true;
            }
        }
        /* check that the two partition table crc32 checksum match,
         * may want a different hashing function */
        if (secondary_status == CL_SUCCESS && header_status == CL_SUCCESS &&
            phdr.tableCRC32 != shdr.tableCRC32) {
            cli_dbgmsg("cli_scangpt: Primary and secondary GPT header table CRC32 differ\n");
            cli_dbgmsg("cli_scangpt: Set to scan primary and secondary partition tables\n");

            state = BOTH;
        } else if (secondary_status == CL_SUCCESS && header_status == CL_SUCCESS) {
            cli_dbgmsg("cli_scangpt: Secondary GPT header check OK\n");
        }
    }

    /* check that the partition table has no intersections - HEURISTICS */
    if (SCAN_HEURISTIC_PARTITION_INTXN && (ctx->dconf->other & OTHER_CONF_PRTNINTXN)) {
        if (state == PRIMARY_ONLY || state == BOTH) {
            status = gpt_partition_intersection(ctx, phdr, sectorsize);
            if (status != CL_SUCCESS)
                goto done;
        }
        if (state == SECONDARY_ONLY || state == BOTH) {
            status = gpt_partition_intersection(ctx, shdr, sectorsize);
            if (status != CL_SUCCESS)
                goto done;
        }
    }

    /* scanning partitions */
    switch (state) {
        case PRIMARY_ONLY:
            cli_dbgmsg("cli_scangpt: Scanning primary GPT partitions only\n");
            status = gpt_scan_partitions(ctx, phdr, sectorsize);
            if (status != CL_SUCCESS) {
                goto done;
            }
            break;
        case SECONDARY_ONLY:
            cli_dbgmsg("cli_scangpt: Scanning secondary GPT partitions only\n");
            status = gpt_scan_partitions(ctx, shdr, sectorsize);
            if (status != CL_SUCCESS) {
                goto done;
            }
            break;
        case BOTH:
            cli_dbgmsg("cli_scangpt: Scanning primary GPT partitions\n");
            status = gpt_scan_partitions(ctx, phdr, sectorsize);
            if (status != CL_SUCCESS) {
                goto done;
            }
            cli_dbgmsg("cli_scangpt: Scanning secondary GPT partitions\n");
            status = gpt_scan_partitions(ctx, shdr, sectorsize);
            if (status != CL_SUCCESS) {
                goto done;
            }
            break;
        default:
            cli_dbgmsg("cli_scangpt: State is invalid\n");
    }

    if (secondary_header_incomplete && status == CL_SUCCESS)
        status = CL_EPARSE;

done:
    if (ctx && status != CL_SUCCESS && status != CL_VIRUS && status != CL_BREAK && !ctx->scan_incomplete)
        cli_mark_scan_incomplete(ctx, "GPT inspection ended before completion");
    if (ctx && (status == CL_SUCCESS || status == CL_CLEAN) && ctx->scan_incomplete)
        status = CL_EPARSE;

    return status;
}

static cl_error_t gpt_scan_partitions(cli_ctx *ctx, struct gpt_header hdr, size_t sectorsize)
{
    cl_error_t status = CL_SUCCESS;
    struct gpt_partition_entry gpe;
    size_t maplen, part_size = 0;
    size_t pos = 0, part_off = 0;
    unsigned i = 0, j = 0;
    uint32_t max_prtns = 0;

    char *namestr = NULL;

    /* convert endian to host */
    hdr.signature       = be64_to_host(hdr.signature);
    hdr.revision        = be32_to_host(hdr.revision);
    hdr.headerSize      = le32_to_host(hdr.headerSize);
    hdr.headerCRC32     = le32_to_host(hdr.headerCRC32);
    hdr.reserved        = le32_to_host(hdr.reserved);
    hdr.currentLBA      = le64_to_host(hdr.currentLBA);
    hdr.backupLBA       = le64_to_host(hdr.backupLBA);
    hdr.firstUsableLBA  = le64_to_host(hdr.firstUsableLBA);
    hdr.lastUsableLBA   = le64_to_host(hdr.lastUsableLBA);
    hdr.tableStartLBA   = le64_to_host(hdr.tableStartLBA);
    hdr.tableNumEntries = le32_to_host(hdr.tableNumEntries);
    hdr.tableEntrySize  = le32_to_host(hdr.tableEntrySize);
    hdr.tableCRC32      = le32_to_host(hdr.tableCRC32);

    /* print header info for the debug */
    cli_dbgmsg("GPT Header:\n");
    cli_dbgmsg("Signature: 0x%llx\n", (long long unsigned)hdr.signature);
    cli_dbgmsg("Revision: %x\n", hdr.revision);
    gpt_printGUID(hdr.DiskGUID, "DISK GUID");
    cli_dbgmsg("Partition Entry Count: %u\n", hdr.tableNumEntries);
    cli_dbgmsg("Partition Entry Size: %u\n", hdr.tableEntrySize);

    maplen = ctx->fmap->len;

    /* check engine maxpartitions limit */
    if (hdr.tableNumEntries < ctx->engine->maxpartitions) {
        max_prtns = hdr.tableNumEntries;
    } else {
        max_prtns = ctx->engine->maxpartitions;
    }
    /* use the partition tables to pass partitions to cli_magic_scan_nested_fmap_type */
    if (hdr.tableStartLBA > SIZE_MAX / sectorsize) {
        cli_dbgmsg("cli_scangpt: partition table offset exceeds native fmap range\n");
        return CL_EFORMAT;
    }
    pos = (size_t)hdr.tableStartLBA * sectorsize;
    if (pos > maplen) {
        cli_dbgmsg("cli_scangpt: partition table starts outside the fmap\n");
        return CL_EFORMAT;
    }
    for (i = 0; i < max_prtns; ++i) {
        status = cli_checktimelimit(ctx);
        if (status != CL_SUCCESS)
            goto done;

        /* read in partition entry */
        status = gpt_read(ctx, &gpe, pos, sizeof(gpe), "GPT partition entry could not be read completely");
        if (status != CL_SUCCESS) {
            cli_dbgmsg("cli_scangpt: Invalid GPT partition entry\n");
            goto done;
        }

        /* convert the endian to host */
        gpe.firstLBA   = le64_to_host(gpe.firstLBA);
        gpe.lastLBA    = le64_to_host(gpe.lastLBA);
        gpe.attributes = le64_to_host(gpe.attributes);
        for (j = 0; j < 36; ++j) {
            gpe.name[j] = le16_to_host(gpe.name[j]);
        }

        /* check that partition is not empty and within a valid location */
        if (gpe.firstLBA == 0) {
            /* empty partition, invalid */
        } else if ((gpe.firstLBA > gpe.lastLBA) ||
                   (gpe.firstLBA < hdr.firstUsableLBA) || (gpe.lastLBA > hdr.lastUsableLBA)) {
            cli_dbgmsg("cli_scangpt: GPT partition exists outside specified bounds\n");
            gpt_parsemsg("%llu < %llu, %llu > %llu\n", gpe.firstLBA, hdr.firstUsableLBA,
                         gpe.lastLBA, hdr.lastUsableLBA);
            cli_mark_scan_incomplete(ctx, "GPT partition entry is outside the usable range");
            status = CL_EFORMAT;
            goto done;
        } else if (gpe.lastLBA == UINT64_MAX ||
                   gpe.lastLBA + 1 > (uint64_t)maplen / sectorsize) {
            cli_mark_scan_incomplete(ctx, "GPT partition entry is outside the input map");
            status = CL_EFORMAT;
            goto done;
        } else {
            namestr = (char *)cli_utf16toascii((char *)gpe.name, 72);
            // It's okay if namestr is NULL.

            /* print partition entry data for debug */
            cli_dbgmsg("GPT Partition Entry %u:\n", i);
            cli_dbgmsg("Name: %s\n", namestr ? namestr : "");
            gpt_printGUID(gpe.typeGUID, "Type GUID");
            gpt_printGUID(gpe.uniqueGUID, "Unique GUID");
            cli_dbgmsg("Attributes: %llx\n", (long long unsigned)gpe.attributes);
            cli_dbgmsg("Blocks: [%llu(%llu) -> %llu(%llu)]\n",
                       (long long unsigned)gpe.firstLBA, (long long unsigned)(gpe.firstLBA * sectorsize),
                       (long long unsigned)gpe.lastLBA, (long long unsigned)((gpe.lastLBA + 1) * sectorsize));

            /* send the partition to cli_magic_scan_nested_fmap_type */
            part_off  = (size_t)gpe.firstLBA * sectorsize;
            part_size = (size_t)(gpe.lastLBA - gpe.firstLBA + 1) * sectorsize;
            status    = cli_magic_scan_nested_fmap_type(ctx->fmap, part_off, part_size, ctx, CL_TYPE_PART_ANY, namestr, LAYER_ATTRIBUTES_NONE);
            if (status != CL_SUCCESS) {
                goto done;
            }

            if (NULL != namestr) {
                free(namestr);
                namestr = NULL;
            }
        }

        /* increment the offsets to next partition entry */
        if (pos > maplen || hdr.tableEntrySize > maplen - pos) {
            status = CL_EFORMAT;
            goto done;
        }
        pos += hdr.tableEntrySize;
    }

    if (max_prtns < hdr.tableNumEntries) {
        cli_dbgmsg("cli_scangpt: max partitions reached\n");
        cli_mark_scan_incomplete(ctx, "GPT partition count limit left a partition uninspected");
        if (status == CL_SUCCESS || status == CL_CLEAN)
            status = CL_EMAXFILES;
    }

done:

    if (NULL != namestr) {
        free(namestr);
    }
    return status;
}

static cl_error_t gpt_validate_header(cli_ctx *ctx, struct gpt_header hdr, size_t sectorsize,
                                      uint64_t expected_current_lba)
{
    cl_error_t status = CL_SUCCESS;
    uint32_t crc32_calc, crc32_ref;
    uint64_t tableLastLBA, lastLBA;
    size_t maplen, ptable_start, ptable_len;
    cl_error_t crc_status;

    maplen = ctx->fmap->len;

    /* checking header crc32 checksum */
    crc32_ref       = le32_to_host(hdr.headerCRC32);
    hdr.headerCRC32 = 0; /* checksum is calculated with field = 0 */
    crc32_calc      = crc32(0, (unsigned char *)&hdr, sizeof(hdr));
    if (crc32_calc != crc32_ref) {
        cli_dbgmsg("cli_scangpt: GPT header checksum mismatch\n");
        gpt_parsemsg("%x != %x\n", crc32_calc, crc32_ref);
        status = CL_EFORMAT;
        goto done;
    }

    /* convert endian to host to check partition table */
    hdr.signature       = be64_to_host(hdr.signature);
    hdr.revision        = be32_to_host(hdr.revision);
    hdr.headerSize      = le32_to_host(hdr.headerSize);
    hdr.headerCRC32     = crc32_ref;
    hdr.reserved        = le32_to_host(hdr.reserved);
    hdr.currentLBA      = le64_to_host(hdr.currentLBA);
    hdr.backupLBA       = le64_to_host(hdr.backupLBA);
    hdr.firstUsableLBA  = le64_to_host(hdr.firstUsableLBA);
    hdr.lastUsableLBA   = le64_to_host(hdr.lastUsableLBA);
    hdr.tableStartLBA   = le64_to_host(hdr.tableStartLBA);
    hdr.tableNumEntries = le32_to_host(hdr.tableNumEntries);
    hdr.tableEntrySize  = le32_to_host(hdr.tableEntrySize);
    hdr.tableCRC32      = le32_to_host(hdr.tableCRC32);

    if (sectorsize == 0 || maplen < sectorsize || hdr.tableNumEntries == 0 ||
        hdr.tableEntrySize != sizeof(struct gpt_partition_entry) ||
        hdr.tableStartLBA > SIZE_MAX / sectorsize ||
        hdr.tableNumEntries > SIZE_MAX / hdr.tableEntrySize) {
        cli_dbgmsg("cli_scangpt: GPT partition table arithmetic overflow\n");
        status = CL_EFORMAT;
        goto done;
    }
    ptable_start = (size_t)hdr.tableStartLBA * sectorsize;
    ptable_len   = (size_t)hdr.tableNumEntries * hdr.tableEntrySize;
    if (ptable_len == 0 || ptable_start > maplen || ptable_len > maplen - ptable_start) {
        cli_dbgmsg("cli_scangpt: GPT partition table extends over fmap limit\n");
        status = CL_EFORMAT;
        goto done;
    }
    tableLastLBA = hdr.tableStartLBA + ((ptable_len - 1) / sectorsize);
    if (tableLastLBA < hdr.tableStartLBA) {
        cli_dbgmsg("cli_scangpt: GPT partition table LBA overflow\n");
        status = CL_EFORMAT;
        goto done;
    }
    lastLBA = (maplen / sectorsize) - 1;

    /** HEADER CHECKS **/
    gpt_printSectors(ctx, sectorsize);

    /* check signature */
    if (hdr.signature != GPT_SIGNATURE) {
        cli_dbgmsg("cli_scangpt: Invalid GPT header signature %llx\n",
                   (long long unsigned)hdr.signature);
        status = CL_EFORMAT;
        goto done;
    }

    /* check header size */
    if (hdr.headerSize != sizeof(hdr)) {
        cli_dbgmsg("cli_scangpt: GPT header size does not match stated size\n");
        status = CL_EFORMAT;
        goto done;
    }

    /* check reserved value == 0 */
    if (hdr.reserved != GPT_HDR_RESERVED) {
        cli_dbgmsg("cli_scangpt: GPT header reserved is not expected value\n");
        status = CL_EFORMAT;
        goto done;
    }

    /* check that sectors are in a valid configuration */
    if (hdr.currentLBA != expected_current_lba ||
        hdr.backupLBA != (expected_current_lba == GPT_PRIMARY_HDR_LBA ? lastLBA : GPT_PRIMARY_HDR_LBA)) {
        cli_dbgmsg("cli_scangpt: GPT header location does not match its physical copy\n");
        status = CL_EFORMAT;
        goto done;
    }
    if (hdr.firstUsableLBA > hdr.lastUsableLBA) {
        cli_dbgmsg("cli_scangpt: GPT first usable sectors is after last usable sector\n");
        status = CL_EFORMAT;
        goto done;
    }
    if (hdr.firstUsableLBA <= GPT_PRIMARY_HDR_LBA || hdr.lastUsableLBA >= lastLBA) {
        cli_dbgmsg("cli_scangpt: GPT usable sectors intersects header sector\n");
        status = CL_EFORMAT;
        goto done;
    }
    if ((hdr.tableStartLBA <= hdr.firstUsableLBA && tableLastLBA >= hdr.firstUsableLBA) ||
        (hdr.tableStartLBA >= hdr.firstUsableLBA && hdr.tableStartLBA <= hdr.lastUsableLBA)) {
        cli_dbgmsg("cli_scangpt: GPT usable sectors intersects partition table\n");
        status = CL_EFORMAT;
        goto done;
    }
    if (hdr.tableStartLBA <= GPT_PRIMARY_HDR_LBA || tableLastLBA >= lastLBA) {
        cli_dbgmsg("cli_scangpt: GPT partition table intersects header sector\n");
        status = CL_EFORMAT;
        goto done;
    }

    /** END HEADER CHECKS **/

    /* Check the table incrementally so a valid but large table does not have to
     * be resident as one contiguous fmap request. */
    crc_status = gpt_crc32_fmap(ctx, ptable_start, ptable_len, &crc32_calc);
    if (crc_status != CL_SUCCESS) {
        cli_dbgmsg("cli_scangpt: unable to checksum the complete GPT partition table\n");
        status = crc_status;
        goto done;
    }
    if (crc32_calc != hdr.tableCRC32) {
        cli_dbgmsg("cli_scangpt: GPT partition table checksum mismatch\n");
        gpt_parsemsg("%x != %x\n", crc32_calc, hdr.tableCRC32);
        status = CL_EFORMAT;
        goto done;
    }

done:

    return status;
}

static cl_error_t gpt_check_mbr(cli_ctx *ctx, size_t sectorsize)
{
    cl_error_t status = CL_SUCCESS;
    struct mbr_boot_record pmbr;
    size_t pos = 0, mbr_base = 0;
    unsigned i = 0;

    /* read the mbr */
    mbr_base = sectorsize - sizeof(struct mbr_boot_record);
    pos      = (MBR_SECTOR * sectorsize) + mbr_base;

    status = gpt_read(ctx, &pmbr, pos, sizeof(pmbr), "GPT protective MBR could not be read completely");
    if (status != CL_SUCCESS) {
        cli_dbgmsg("cli_scangpt: Invalid primary MBR header\n");
        goto done;
    }

    /* convert mbr */
    mbr_convert_to_host(&pmbr);

    /* check the protective mbr - warning */
    if (pmbr.entries[0].type == MBR_PROTECTIVE) {
        /* check the efi partition matches the gpt spec */
        if (pmbr.entries[0].firstLBA != GPT_PRIMARY_HDR_LBA) {
            cli_warnmsg("cli_scangpt: protective MBR first LBA is incorrect %u\n",
                        pmbr.entries[0].firstLBA);
        }

        /* other entries are empty */
        for (i = 1; i < MBR_MAX_PARTITION_ENTRIES; ++i) {
            if (pmbr.entries[i].type != MBR_EMPTY) {
                cli_warnmsg("cli_scangpt: protective MBR has non-empty partition\n");
                break;
            }
        }
    } else if (pmbr.entries[0].type == MBR_HYBRID) {
        /* hybrid mbr detected */
        cli_warnmsg("cli_scangpt: detected a hybrid MBR\n");
    } else {
        /* non-protective mbr detected */
        cli_warnmsg("cli_scangpt: detected a non-protective MBR\n");
    }

    /* scan the bootloader segment - pushed to scanning mbr */
    /* check if MBR size matches GPT size */
    /* check if the MBR and GPT partitions align - heuristic */
    /* scan the MBR partitions - additional scans */

done:

    return status;
}

static void gpt_printSectors(cli_ctx *ctx, size_t sectorsize)
{
#ifdef DEBUG_GPT_PARSE
    struct gpt_header phdr, shdr;
    size_t ppos = 0, spos = 0;
    size_t pptable_len, sptable_len, maplen;
    uint64_t ptableLastLBA, stableLastLBA;

    /* sector size calculation */
    sectorsize = GPT_DEFAULT_SECTOR_SIZE;

    maplen = ctx->fmap->len;

    ppos = 1 * sectorsize;      /* sector 1 (second sector) is the primary gpt header */
    spos = maplen - sectorsize; /* last sector is the secondary gpt header */

    /* read in the primary and secondary gpt headers */
    if (fmap_readn(ctx->fmap, &phdr, ppos, sizeof(phdr)) != sizeof(phdr)) {
        cli_dbgmsg("cli_scangpt: Invalid primary GPT header\n");
        return;
    }
    if (fmap_readn(ctx->fmap, &shdr, spos, sizeof(shdr)) != sizeof(shdr)) {
        cli_dbgmsg("cli_scangpt: Invalid secondary GPT header\n");
        return;
    }

    pptable_len   = phdr.tableNumEntries * phdr.tableEntrySize;
    sptable_len   = shdr.tableNumEntries * shdr.tableEntrySize;
    ptableLastLBA = (phdr.tableStartLBA + (pptable_len / sectorsize)) - 1;
    stableLastLBA = (shdr.tableStartLBA + (sptable_len / sectorsize)) - 1;

    gpt_parsemsg("0: MBR\n");
    gpt_parsemsg("%llu: Primary GPT Header\n", phdr.currentLBA);
    gpt_parsemsg("%llu-%llu: Primary GPT Partition Table\n", phdr.tableStartLBA, ptableLastLBA);
    gpt_parsemsg("%llu-%llu: Usable LBAs\n", phdr.firstUsableLBA, phdr.lastUsableLBA);
    gpt_parsemsg("%llu-%llu: Secondary GPT Partition Table\n", shdr.tableStartLBA, stableLastLBA);
    gpt_parsemsg("%llu: Secondary GPT Header\n", phdr.backupLBA);
#else
    UNUSEDPARAM(ctx);
    UNUSEDPARAM(sectorsize);
    return;
#endif
}

static void gpt_printGUID(uint8_t GUID[], const char *msg)
{
    cli_dbgmsg("%s: %02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n",
               msg, GUID[0], GUID[1], GUID[2], GUID[3], GUID[4], GUID[5], GUID[6], GUID[7],
               GUID[8], GUID[9], GUID[10], GUID[11], GUID[12], GUID[13], GUID[14], GUID[15]);
}

static cl_error_t gpt_partition_intersection(cli_ctx *ctx, struct gpt_header hdr, size_t sectorsize)
{
    cl_error_t status = CL_SUCCESS;
    cl_error_t ret;
    partition_intersection_list_t prtncheck;
    struct gpt_partition_entry gpe;
    unsigned i, pitxn;
    size_t pos;
    size_t maplen;
    uint32_t max_prtns = 0;

    maplen = ctx->fmap->len;

    /* convert endian to host to check partition table */
    hdr.tableStartLBA   = le64_to_host(hdr.tableStartLBA);
    hdr.tableNumEntries = le32_to_host(hdr.tableNumEntries);
    hdr.tableEntrySize  = le32_to_host(hdr.tableEntrySize);
    hdr.firstUsableLBA  = le64_to_host(hdr.firstUsableLBA);
    hdr.lastUsableLBA   = le64_to_host(hdr.lastUsableLBA);

    partition_intersection_list_init(&prtncheck);

    /* check engine maxpartitions limit */
    if (hdr.tableNumEntries < ctx->engine->maxpartitions) {
        max_prtns = hdr.tableNumEntries;
    } else {
        max_prtns = ctx->engine->maxpartitions;
    }
    if (max_prtns < hdr.tableNumEntries)
        cli_mark_scan_incomplete(ctx, "GPT intersection analysis reached the configured partition limit");

    if (sectorsize == 0 || hdr.tableEntrySize != sizeof(struct gpt_partition_entry) ||
        hdr.tableStartLBA > SIZE_MAX / sectorsize) {
        status = CL_EFORMAT;
        goto done;
    }
    pos = (size_t)hdr.tableStartLBA * sectorsize;
    if (pos > maplen) {
        status = CL_EFORMAT;
        goto done;
    }
    for (i = 0; i < max_prtns; ++i) {
        status = cli_checktimelimit(ctx);
        if (status != CL_SUCCESS)
            goto done;

        /* read in partition entry */
        status = gpt_read(ctx, &gpe, pos, sizeof(gpe), "GPT intersection entry could not be read completely");
        if (status != CL_SUCCESS) {
            cli_dbgmsg("cli_scangpt: Invalid GPT partition entry\n");
            goto done;
        }

        /* convert the endian to host */
        gpe.firstLBA = le64_to_host(gpe.firstLBA);
        gpe.lastLBA  = le64_to_host(gpe.lastLBA);

        if (gpe.firstLBA == 0) {
            /* empty partition, invalid */
        } else if ((gpe.firstLBA > gpe.lastLBA) ||
                   (gpe.firstLBA < hdr.firstUsableLBA) || (gpe.lastLBA > hdr.lastUsableLBA)) {
            /* partition exists outside bounds specified by header or invalid */
        } else if (gpe.lastLBA == UINT64_MAX ||
                   gpe.lastLBA + 1 > (uint64_t)maplen / sectorsize) {
            /* partition exists outside bounds of the file map */
        } else {
            ret = partition_intersection_list_check(&prtncheck, &pitxn, gpe.firstLBA, gpe.lastLBA - gpe.firstLBA + 1);
            if (ret != CL_SUCCESS) {
                if (ret == CL_VIRUS) {
                    cli_dbgmsg("cli_scangpt: detected intersection with partitions "
                               "[%u, %u]\n",
                               pitxn, i);
                    status = cli_append_potentially_unwanted(ctx, "Heuristics.GPTPartitionIntersection");
                    if (status != CL_SUCCESS) {
                        goto done;
                    }
                } else {
                    if (ret == CL_EMEM)
                        cli_mark_scan_incomplete(ctx, "GPT partition intersection tracking could not be allocated");
                    status = ret;
                    goto done;
                }
            }
        }

        /* increment the offsets to next partition entry */
        if (pos > maplen || hdr.tableEntrySize > maplen - pos) {
            status = CL_EFORMAT;
            goto done;
        }
        pos += hdr.tableEntrySize;
    }

done:

    partition_intersection_list_free(&prtncheck);
    return status;
}
