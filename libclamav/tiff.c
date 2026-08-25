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
#define tiff64_to_host(be, x) (be ? be64_to_host(x) : le64_to_host(x))

#define TIFF_CLASSIC_ENTRY_SIZE 12U
#define TIFF_BIG_ENTRY_SIZE 20U
#define TIFF_ENTRY_DEADLINE_INTERVAL 4096U

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
     * beyond the map. Keep an impossible or incomplete TIFF structure as a
     * parser error; only an in-range callback failure for a fully available
     * structure is an operational read error. */
    if (at > map->len || len > map->len - at)
        return 0;
    return fmap_readn(map, dst, at, len);
}

static uint16_t tiff_read_u16(int big_endian, const unsigned char *data)
{
    uint16_t value;

    memcpy(&value, data, sizeof(value));
    return tiff16_to_host(big_endian, value);
}

static uint32_t tiff_read_u32(int big_endian, const unsigned char *data)
{
    uint32_t value;

    memcpy(&value, data, sizeof(value));
    return tiff32_to_host(big_endian, value);
}

static uint64_t tiff_read_u64(int big_endian, const unsigned char *data)
{
    uint64_t value;

    memcpy(&value, data, sizeof(value));
    return tiff64_to_host(big_endian, value);
}

static int tiff_value_size(uint64_t count, size_t width, size_t *value_size)
{
    if (NULL == value_size)
        return 0;

    if (width != 0 && count > (uint64_t)(SIZE_MAX / width))
        return 0;

    *value_size = (size_t)count * width;
    return 1;
}

static int tiff_offset_to_size(uint64_t disk_offset, size_t *offset)
{
    if (offset == NULL || disk_offset > (uint64_t)SIZE_MAX)
        return 0;

    *offset = (size_t)disk_offset;
    return 1;
}

cl_error_t cli_parsetiff(cli_ctx *ctx)
{
    cl_error_t status = CL_ERROR;

    fmap_t *map = NULL;
    unsigned char magic[4];
    unsigned char entry_data[TIFF_BIG_ENTRY_SIZE];
    int big_endian;
    bool big_tiff = false;
    size_t offset = 0;
    size_t entry_size;
    size_t inline_value_size;
    size_t next_offset_size;
    uint64_t disk_offset;
    uint64_t next_disk_offset;
    uint64_t ifd_count = 0;
    uint64_t i;
    uint64_t num_entries;
    uint64_t entry_numval;
    uint64_t entry_value;
    uint16_t entry_type;
    size_t value_size;
    size_t value_width;
    size_t last_offset = 0;
    bool value_type_known;

    cli_dbgmsg("in cli_parsetiff()\n");

    if (NULL == ctx) {
        cli_dbgmsg("TIFF: passed context was NULL\n");
        status = CL_EARG;
        goto done;
    }
    map = ctx->fmap;
    if (map == NULL) {
        cli_mark_scan_incomplete(ctx, "TIFF input map is unavailable");
        status = CL_EPARSE;
        goto done;
    }

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

    if (!memcmp(magic, "\x4d\x4d\x00\x2a", 4)) {
        big_endian = 1;
    } else if (!memcmp(magic, "\x49\x49\x2a\x00", 4)) {
        big_endian = 0;
    } else if (!memcmp(magic, "\x4d\x4d\x00\x2b", 4)) {
        big_endian = 1;
        big_tiff   = true;
    } else if (!memcmp(magic, "\x49\x49\x2b\x00", 4)) {
        big_endian = 0;
        big_tiff   = true;
    } else {
        status = CL_CLEAN; /* Not a TIFF file */
        goto done;
    }

    cli_dbgmsg("cli_parsetiff: %s-endian %sTIFF file\n",
               big_endian ? "big" : "little", big_tiff ? "Big" : "classic ");

    if (big_tiff) {
        unsigned char extension[4];
        size_t bytes_read = tiff_readn(map, extension, offset, sizeof(extension));

        if (bytes_read != sizeof(extension)) {
            status = (bytes_read == (size_t)-1)
                         ? tiff_read_error(ctx, "BigTIFF header extension could not be read completely")
                         : tiff_parse_error(ctx, "Heuristics.Broken.Media.TIFF.EOFReadingBigTIFFHeader");
            goto done;
        }
        if (tiff_read_u16(big_endian, extension) != 8 ||
            tiff_read_u16(big_endian, extension + sizeof(uint16_t)) != 0) {
            status = tiff_parse_error(ctx, "Heuristics.Broken.Media.TIFF.InvalidBigTIFFHeader");
            goto done;
        }
        offset += sizeof(extension);
        entry_size       = TIFF_BIG_ENTRY_SIZE;
        inline_value_size = sizeof(uint64_t);
        next_offset_size  = sizeof(uint64_t);
    } else {
        entry_size        = TIFF_CLASSIC_ENTRY_SIZE;
        inline_value_size = sizeof(uint32_t);
        next_offset_size  = sizeof(uint32_t);
    }

    /* acquire offset of first IFD */
    if (big_tiff) {
        unsigned char offset_data[sizeof(uint64_t)];
        size_t bytes_read = tiff_readn(map, offset_data, offset, sizeof(offset_data));

        if (bytes_read != sizeof(offset_data)) {
            cli_dbgmsg("cli_parsetiff: Failed to acquire offset of first IFD, file appears to be truncated.\n");
            status = (bytes_read == (size_t)-1)
                         ? tiff_read_error(ctx, "TIFF first IFD offset could not be read completely")
                         : tiff_parse_error(ctx, "Heuristics.Broken.Media.TIFF.EOFReadingFirstIFDOffset");
            goto done;
        }
        disk_offset = tiff_read_u64(big_endian, offset_data);
    } else {
        unsigned char offset_data[sizeof(uint32_t)];
        size_t bytes_read = tiff_readn(map, offset_data, offset, sizeof(offset_data));

        if (bytes_read != sizeof(offset_data)) {
            cli_dbgmsg("cli_parsetiff: Failed to acquire offset of first IFD, file appears to be truncated.\n");
            status = (bytes_read == (size_t)-1)
                         ? tiff_read_error(ctx, "TIFF first IFD offset could not be read completely")
                         : tiff_parse_error(ctx, "Heuristics.Broken.Media.TIFF.EOFReadingFirstIFDOffset");
            goto done;
        }
        disk_offset = tiff_read_u32(big_endian, offset_data);
    }

    if (!tiff_offset_to_size(disk_offset, &offset)) {
        status = tiff_parse_error(ctx, "Heuristics.Broken.Media.TIFF.UnrepresentableIFDOffset");
        goto done;
    }

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

        /* Acquire the number of directory entries. BigTIFF widens this field
         * from 16 to 64 bits but still permits traversal one fixed entry at a
         * time, so an attacker-controlled count never becomes an allocation. */
        if (big_tiff) {
            unsigned char count_data[sizeof(uint64_t)];
            size_t bytes_read = tiff_readn(map, count_data, offset, sizeof(count_data));

            if (bytes_read != sizeof(count_data)) {
                cli_dbgmsg("cli_parsetiff: Failed to acquire number of directory entries in current IFD, file appears to be truncated.\n");
                status = (bytes_read == (size_t)-1)
                             ? tiff_read_error(ctx, "TIFF directory-entry count could not be read completely")
                             : tiff_parse_error(ctx, "Heuristics.Broken.Media.TIFF.EOFReadingNumIFDDirectoryEntries");
                goto done;
            }
            num_entries = tiff_read_u64(big_endian, count_data);
            offset += sizeof(count_data);
        } else {
            unsigned char count_data[sizeof(uint16_t)];
            size_t bytes_read = tiff_readn(map, count_data, offset, sizeof(count_data));

            if (bytes_read != sizeof(count_data)) {
                cli_dbgmsg("cli_parsetiff: Failed to acquire number of directory entries in current IFD, file appears to be truncated.\n");
                status = (bytes_read == (size_t)-1)
                             ? tiff_read_error(ctx, "TIFF directory-entry count could not be read completely")
                             : tiff_parse_error(ctx, "Heuristics.Broken.Media.TIFF.EOFReadingNumIFDDirectoryEntries");
                goto done;
            }
            num_entries = tiff_read_u16(big_endian, count_data);
            offset += sizeof(count_data);
        }

        cli_dbgmsg("cli_parsetiff: IFD %" PRIu64 " declared %" PRIu64 " directory entries\n",
                   ifd_count, num_entries);

        if (num_entries > (uint64_t)(SIZE_MAX / entry_size) ||
            (size_t)num_entries * entry_size > map->len - offset) {
            status = tiff_parse_error(ctx, "Heuristics.Broken.Media.TIFF.EOFReadingIFDEntry");
            goto done;
        }

        /* Traverse each fixed-size entry without retaining the directory. */
        for (i = 0; i < num_entries; i++) {
            size_t bytes_read;

            if (i != 0 && i % TIFF_ENTRY_DEADLINE_INTERVAL == 0) {
                status = cli_checktimelimit(ctx);
                if (status != CL_SUCCESS) {
                    cli_mark_scan_incomplete(ctx, "TIFF IFD traversal reached the configured time limit");
                    goto done;
                }
            }

            bytes_read = tiff_readn(map, entry_data, offset, entry_size);
            if (bytes_read != entry_size) {
                cli_dbgmsg("cli_parsetiff: Failed to read next IFD entry, file appears to be truncated.\n");
                status = (bytes_read == (size_t)-1)
                             ? tiff_read_error(ctx, "TIFF IFD entry could not be read completely")
                             : tiff_parse_error(ctx, "Heuristics.Broken.Media.TIFF.EOFReadingIFDEntry");
                goto done;
            }
            offset += entry_size;

            entry_type = tiff_read_u16(big_endian, entry_data + sizeof(uint16_t));
            if (big_tiff) {
                entry_numval = tiff_read_u64(big_endian, entry_data + 2U * sizeof(uint16_t));
                entry_value  = tiff_read_u64(big_endian, entry_data + 2U * sizeof(uint16_t) + sizeof(uint64_t));
            } else {
                entry_numval = tiff_read_u32(big_endian, entry_data + 2U * sizeof(uint16_t));
                entry_value  = tiff_read_u32(big_endian, entry_data + 2U * sizeof(uint16_t) + sizeof(uint32_t));
            }

            value_type_known = true;
            switch (entry_type) {
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
                case 13: /* IFD */
                    value_width = 4;
                    break;
                case 16: /* LONG8 (BigTIFF) */
                case 17: /* SLONG8 (BigTIFF) */
                case 18: /* IFD8 (BigTIFF) */
                    value_width      = 8;
                    value_type_known = big_tiff;
                    break;

                default: /* INVALID or NEW Type */
                    value_width      = 0;
                    value_type_known = false;
                    break;
            }

            if (!value_type_known) {
                cli_warnmsg("cli_parsetiff: TIFF entry field %" PRIu64 " has an unsupported type %u\n",
                            i, entry_type);
                status = tiff_parse_error(ctx, "Heuristics.Broken.Media.TIFF.UnsupportedType");
                goto done;
            }

            if (!tiff_value_size(entry_numval, value_width, &value_size)) {
                cli_warnmsg("cli_parsetiff: TIFF entry field %" PRIu64 " has an unrepresentable value size\n", i);
                status = tiff_parse_error(ctx, "Heuristics.Broken.Media.TIFF.ValueSizeOverflow");
                goto done;
            }

            if (value_size > inline_value_size) {
                if (entry_value > (uint64_t)map->len ||
                    value_size > map->len - (size_t)entry_value) {
                    cli_warnmsg("cli_parsetiff: TIFF entry field %" PRIu64 " exceeds bounds of TIFF file [offset=%" PRIu64 " size=%zu map=%zu]\n",
                                i, entry_value, value_size, map->len);
                    status = tiff_parse_error(ctx, "Heuristics.Broken.Media.TIFF.OutOfBoundsAccess");
                    goto done;
                }
            }
        }

        ifd_count++;

        last_offset = offset;

        /* Acquire the next IFD location, which is zero for the final IFD. */
        {
            unsigned char next_offset_data[sizeof(uint64_t)];
            size_t bytes_read = tiff_readn(map, next_offset_data, offset, next_offset_size);

            if (bytes_read != next_offset_size) {
                cli_dbgmsg("cli_parsetiff: Failed to acquire next IFD location, file appears to be truncated.\n");
                status = (bytes_read == (size_t)-1)
                             ? tiff_read_error(ctx, "TIFF next IFD offset could not be read completely")
                             : tiff_parse_error(ctx, "Heuristics.Broken.Media.TIFF.EOFReadingChunkCRC");
                goto done;
            }
            next_disk_offset = big_tiff ? tiff_read_u64(big_endian, next_offset_data)
                                        : tiff_read_u32(big_endian, next_offset_data);
        }
        if (!tiff_offset_to_size(next_disk_offset, &offset)) {
            status = tiff_parse_error(ctx, "Heuristics.Broken.Media.TIFF.UnrepresentableIFDOffset");
            goto done;
        }

        if (offset) {
            /*If the offsets are not in order, that is suspicious.*/
            if (last_offset >= offset) {
                cli_dbgmsg("cli_parsetiff: Next offset is before current offset, file appears to be malformed.\n");
                status = tiff_parse_error(ctx, "Heuristics.Broken.Media.TIFF.OutOfOrderIFDOffset");
                goto done;
            }
        }
    } while (offset);

    cli_dbgmsg("cli_parsetiff: examined %" PRIu64 " IFD(s)\n", ifd_count);

    status = CL_CLEAN;

done:

    return status;
}
