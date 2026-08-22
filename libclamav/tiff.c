/*
 *  Copyright (C) 2015-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

#include "others.h"
#include "tiff.h"

#define tiff32_to_host(be, x) (be ? be32_to_host(x) : le32_to_host(x))
#define tiff16_to_host(be, x) (be ? be16_to_host(x) : le16_to_host(x))

struct tiff_ifd {
    uint16_t tag;
    uint16_t type;
    uint32_t numval;
    uint32_t value;
};

static cl_error_t tiff_parse_error(cli_ctx *ctx, const char *reason)
{
    cli_mark_scan_incomplete(ctx, reason);

    /* Direct parser callers used by the library tests may not have built an
     * evidence object yet. Keep malformed TIFF input fail-visible there;
     * complete scan contexts retain the existing heuristic reporting path. */
    if (ctx == NULL || ctx->this_layer_evidence == NULL)
        return CL_EPARSE;

    return cli_append_potentially_unwanted(ctx, reason);
}

static cl_error_t tiff_read_error(cli_ctx *ctx, const char *reason)
{
    cli_mark_scan_incomplete(ctx, reason);
    return CL_EREAD;
}

static size_t tiff_readn(fmap_t *map, void *dst, size_t at, size_t len)
{
    /* fmap_readn() uses (size_t)-1 for both callback failures and an offset
     * beyond the map. Keep an impossible TIFF coordinate as a parser error;
     * only an in-range callback failure is an operational read error. */
    if (at > map->len)
        return 0;
    return fmap_readn(map, dst, at, len);
}

static int tiff_value_size(uint32_t count, size_t width, size_t *value_size)
{
    if (NULL == value_size)
        return 0;

    if (width != 0 && (uint64_t)count > (uint64_t)(SIZE_MAX / width))
        return 0;

    *value_size = (size_t)count * width;
    return 1;
}

cl_error_t cli_parsetiff(cli_ctx *ctx)
{
    cl_error_t status = CL_ERROR;

    fmap_t *map = NULL;
    unsigned char magic[4];
    int big_endian;
    size_t offset = 0;
    uint32_t ifd_count = 0, offset32 = 0, next_offset32 = 0;
    uint16_t i, num_entries;
    struct tiff_ifd entry;
    size_t value_size;
    size_t value_width;
    size_t last_offset = 0;

    cli_dbgmsg("in cli_parsetiff()\n");

    if (NULL == ctx) {
        cli_dbgmsg("TIFF: passed context was NULL\n");
        status = CL_EARG;
        goto done;
    }
    map = ctx->fmap;

    /* A map shorter than the fixed magic cannot be a confirmed TIFF. Once
     * those bytes are present, however, a failed fmap read is an operational
     * error, not evidence that the file is simply another type. */
    if (map->len < sizeof(magic)) {
        status = CL_CLEAN;
        goto done;
    }
    {
        size_t bytes_read = tiff_readn(map, magic, offset, sizeof(magic));

        if (bytes_read != sizeof(magic)) {
            status = (bytes_read == (size_t)-1)
                         ? tiff_read_error(ctx, "TIFF magic could not be read completely")
                         : tiff_parse_error(ctx, "Heuristics.Broken.Media.TIFF.EOFReadingMagic");
            goto done;
        }
    }
    offset += 4;

    if (!memcmp(magic, "\x4d\x4d\x00\x2a", 4))
        big_endian = 1;
    else if (!memcmp(magic, "\x49\x49\x2a\x00", 4))
        big_endian = 0;
    else {
        status = CL_CLEAN; /* Not a TIFF file */
        goto done;
    }

    cli_dbgmsg("cli_parsetiff: %s-endian tiff file\n", big_endian ? "big" : "little");

    /* acquire offset of first IFD */
    {
        size_t bytes_read = tiff_readn(map, &offset32, offset, 4);

        if (bytes_read != 4) {
            cli_dbgmsg("cli_parsetiff: Failed to acquire offset of first IFD, file appears to be truncated.\n");
            status = (bytes_read == (size_t)-1)
                         ? tiff_read_error(ctx, "TIFF first IFD offset could not be read completely")
                         : tiff_parse_error(ctx, "Heuristics.Broken.Media.TIFF.EOFReadingFirstIFDOffset");
            goto done;
        }
    }
    /* offset of the first IFD */
    offset = (size_t)tiff32_to_host(big_endian, offset32);

    cli_dbgmsg("cli_parsetiff: first IFD located @ offset %zu\n", offset);

    if (!offset) {
        cli_errmsg("cli_parsetiff: Invalid offset for first IFD\n");
        status = tiff_parse_error(ctx, "Heuristics.Broken.Media.TIFF.InvalidIFDOffset");
        goto done;
    }

    /* each IFD represents a subfile, though only the first one normally matters */
    do {
        status = cli_checktimelimit(ctx);
        if (status != CL_SUCCESS) {
            cli_mark_scan_incomplete(ctx, "TIFF IFD traversal reached the configured time limit");
            goto done;
        }

        /* acquire number of directory entries in current IFD */
        {
            size_t bytes_read = tiff_readn(map, &num_entries, offset, 2);

            if (bytes_read != 2) {
                cli_dbgmsg("cli_parsetiff: Failed to acquire number of directory entries in current IFD, file appears to be truncated.\n");
                status = (bytes_read == (size_t)-1)
                             ? tiff_read_error(ctx, "TIFF directory-entry count could not be read completely")
                             : tiff_parse_error(ctx, "Heuristics.Broken.Media.TIFF.EOFReadingNumIFDDirectoryEntries");
                goto done;
            }
        }
        offset += 2;
        num_entries = tiff16_to_host(big_endian, num_entries);

        cli_dbgmsg("cli_parsetiff: IFD %u declared %u directory entries\n", ifd_count, num_entries);

        /* transverse IFD entries */
        for (i = 0; i < num_entries; i++) {
            {
                size_t bytes_read = tiff_readn(map, &entry, offset, sizeof(entry));

                if (bytes_read != sizeof(entry)) {
                    cli_dbgmsg("cli_parsetiff: Failed to read next IFD entry, file appears to be truncated.\n");
                    status = (bytes_read == (size_t)-1)
                                 ? tiff_read_error(ctx, "TIFF IFD entry could not be read completely")
                                 : tiff_parse_error(ctx, "Heuristics.Broken.Media.TIFF.EOFReadingIFDEntry");
                    goto done;
                }
            }
            offset += sizeof(entry);

            entry.tag    = tiff16_to_host(big_endian, entry.tag);
            entry.type   = tiff16_to_host(big_endian, entry.type);
            entry.numval = tiff32_to_host(big_endian, entry.numval);
            entry.value  = tiff32_to_host(big_endian, entry.value);

            // cli_dbgmsg("%02u: %u %u %u %u\n", i, entry.tag, entry.type, entry.numval, entry.value);

            switch (entry.type) {
                case 1: /* BYTE */
                    value_width = 1;
                    break;
                case 2: /* ASCII */
                    value_width = 1;
                    break;
                case 3: /* SHORT */
                    value_width = 2;
                    break;
                case 4: /* LONG */
                    value_width = 4;
                    break;
                case 5: /* RATIONAL (LONG/LONG) */
                    value_width = 8;
                    break;

                    /* TIFF 6.0 Types */
                case 6: /* SBYTE */
                    value_width = 1;
                    break;
                case 7: /* UNDEFINED */
                    value_width = 1;
                    break;
                case 8: /* SSHORT */
                    value_width = 2;
                    break;
                case 9: /* SLONG */
                    value_width = 4;
                    break;
                case 10: /* SRATIONAL (SLONG/SLONG) */
                    value_width = 8;
                    break;
                case 11: /* FLOAT */
                    value_width = 4;
                    break;
                case 12: /* DOUBLE */
                    value_width = 8;
                    break;

                default: /* INVALID or NEW Type */
                    value_width = 0;
                    break;
            }

            if (!tiff_value_size(entry.numval, value_width, &value_size)) {
                cli_warnmsg("cli_parsetiff: TFD entry field %u has an unrepresentable value size\n", i);
                status = tiff_parse_error(ctx, "Heuristics.Broken.Media.TIFF.ValueSizeOverflow");
                goto done;
            }

            if (value_size > sizeof(entry.value)) {
                if ((uint64_t)entry.value > (uint64_t)map->len ||
                    value_size > map->len - (size_t)entry.value) {
                    cli_warnmsg("cli_parsetiff: TFD entry field %u exceeds bounds of TIFF file [offset=%u size=%zu map=%zu]\n",
                                i, entry.value, value_size, map->len);
                    status = tiff_parse_error(ctx, "Heuristics.Broken.Media.TIFF.OutOfBoundsAccess");
                    goto done;
                }
            }
        }

        ifd_count++;

        last_offset = offset;

        /* acquire next IFD location, gets 0 if last IFD */
        {
            size_t bytes_read = tiff_readn(map, &next_offset32, offset, sizeof(next_offset32));

            if (bytes_read != sizeof(next_offset32)) {
                cli_dbgmsg("cli_parsetiff: Failed to acquire next IFD location, file appears to be truncated.\n");
                status = (bytes_read == (size_t)-1)
                             ? tiff_read_error(ctx, "TIFF next IFD offset could not be read completely")
                             : tiff_parse_error(ctx, "Heuristics.Broken.Media.TIFF.EOFReadingChunkCRC");
                goto done;
            }
        }
        offset = (size_t)tiff32_to_host(big_endian, next_offset32);

        if (offset) {
            /*If the offsets are not in order, that is suspicious.*/
            if (last_offset >= offset) {
                cli_dbgmsg("cli_parsetiff: Next offset is before current offset, file appears to be malformed.\n");
                status = tiff_parse_error(ctx, "Heuristics.Broken.Media.TIFF.OutOfOrderIFDOffset");
                goto done;
            }
        }
    } while (offset);

    cli_dbgmsg("cli_parsetiff: examined %u IFD(s)\n", ifd_count);

    status = CL_CLEAN;

done:

    return status;
}
