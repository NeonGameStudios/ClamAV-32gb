/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm <tkojm@clamav.net>
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
#include <string.h>
#include <ctype.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "clamav.h"
#include "others.h"
#include "cpio.h"
#include "scanners.h"
#include "matcher.h"

struct cpio_hdr_old {
    uint16_t magic;
    uint16_t dev;
    uint16_t ino;
    uint16_t mode;
    uint16_t uid;
    uint16_t gid;
    uint16_t nlink;
    uint16_t rdev;
    uint16_t mtime[2];
    uint16_t namesize;
    uint16_t filesize[2];
};

struct cpio_hdr_odc {
    char magic[6];
    char dev[6];
    char ino[6];
    char mode[6];
    char uid[6];
    char gid[6];
    char nlink[6];
    char rdev[6];
    char mtime[11];
    char namesize[6];
    char filesize[11];
};

struct cpio_hdr_newc {
    char magic[6];
    char ino[8];
    char mode[8];
    char uid[8];
    char gid[8];
    char nlink[8];
    char mtime[8];
    char filesize[8];
    char devmajor[8];
    char devminor[8];
    char rdevmajor[8];
    char rdevminor[8];
    char namesize[8];
    char check[8];
};

#define EC16(v, conv) (conv ? cbswap16(v) : v)
#define CPIO_CHECKSUM_WINDOW (64U * 1024U)

static size_t cpio_readn(fmap_t *map, void *dst, size_t at, size_t len)
{
    /* fmap_readn() uses (size_t)-1 for both callback failures and an offset
     * beyond the map. A CPIO structure that extends past the input is a
     * malformed/truncated archive, not an operational read failure; only a
     * fully in-range callback failure should become CL_EREAD. */
    if (map == NULL || at > map->len || len > map->len - at)
        return 0;
    return fmap_readn(map, dst, at, len);
}

static int cpio_align_size(size_t value, size_t alignment, size_t *aligned)
{
    size_t padding;

    if (!alignment)
        return -1;
    padding = (alignment - (value % alignment)) % alignment;
    if (value > SIZE_MAX - padding)
        return -1;
    *aligned = value + padding;
    return 0;
}

static int cpio_advance(size_t *position, size_t amount)
{
    if (NULL == position || amount > SIZE_MAX - *position)
        return -1;

    *position += amount;
    return 0;
}

static cl_error_t cpio_validate_name_terminator(cli_ctx *ctx, size_t offset, size_t length)
{
    unsigned char terminator;
    size_t nread;

    if (ctx == NULL || ctx->fmap == NULL || length == 0)
        return CL_ENULLARG;

    if (cpio_advance(&offset, length - 1) < 0) {
        cli_mark_scan_incomplete(ctx, "CPIO member name exceeds the coordinate range");
        return CL_EPARSE;
    }

    nread = cpio_readn(ctx->fmap, &terminator, offset, 1);
    if (nread != 1) {
        cli_mark_scan_incomplete(ctx, "CPIO member name terminator could not be read");
        return (nread == (size_t)-1) ? CL_EREAD : CL_EPARSE;
    }
    if (terminator != '\0') {
        cli_mark_scan_incomplete(ctx, "CPIO member name was not NUL terminated");
        return CL_EPARSE;
    }

    return CL_SUCCESS;
}

static cl_error_t cpio_checktimelimit(cli_ctx *ctx)
{
    cl_error_t status = cli_checktimelimit(ctx);

    if (status != CL_SUCCESS)
        cli_mark_scan_incomplete(ctx, "CPIO member traversal reached the configured time limit");

    return status;
}

static cl_error_t cpio_validate_context(cli_ctx *ctx)
{
    if (ctx == NULL)
        return CL_ENULLARG;
    if (ctx->fmap == NULL) {
        cli_mark_scan_incomplete(ctx, "CPIO input map is unavailable");
        return CL_EPARSE;
    }
    return CL_SUCCESS;
}

static int cpio_parse_hex_u32(const char field[8], uint32_t *value)
{
    uint32_t parsed = 0;
    size_t i;

    if (field == NULL || value == NULL)
        return -1;

    for (i = 0; i < 8; i++) {
        unsigned int digit;

        if (field[i] >= '0' && field[i] <= '9')
            digit = (unsigned int)(field[i] - '0');
        else if (field[i] >= 'a' && field[i] <= 'f')
            digit = (unsigned int)(field[i] - 'a') + 10U;
        else if (field[i] >= 'A' && field[i] <= 'F')
            digit = (unsigned int)(field[i] - 'A') + 10U;
        else
            return -1;

        parsed = (parsed << 4) | digit;
    }

    *value = parsed;
    return 0;
}

static int cpio_parse_octal_u32(const char *field, size_t width, uint32_t *value)
{
    uint32_t parsed = 0;
    size_t i;

    if (field == NULL || value == NULL || width == 0)
        return -1;

    for (i = 0; i < width; i++) {
        uint32_t digit;

        if (field[i] < '0' || field[i] > '7')
            return -1;
        digit = (uint32_t)(field[i] - '0');
        if (parsed > (UINT32_MAX - digit) / 8U)
            return -1;
        parsed = (parsed * 8U) + digit;
    }

    *value = parsed;
    return 0;
}

static cl_error_t cpio_validate_newc_checksum(cli_ctx *ctx, const char field[8], size_t offset, size_t length)
{
    uint32_t expected;
    uint32_t actual = 0;
    size_t consumed = 0;

    if (ctx == NULL || ctx->fmap == NULL || field == NULL)
        return CL_ENULLARG;

    if (cpio_parse_hex_u32(field, &expected) < 0) {
        cli_mark_scan_incomplete(ctx, "CPIO CRC checksum field was malformed");
        return CL_EPARSE;
    }

    if (offset > ctx->fmap->len || length > ctx->fmap->len - offset) {
        cli_mark_scan_incomplete(ctx, "CPIO CRC member data was truncated");
        return CL_EPARSE;
    }

    while (consumed < length) {
        const unsigned char *data;
        size_t chunk = MIN(length - consumed, (size_t)CPIO_CHECKSUM_WINDOW);
        size_t nread = 0;
        size_t i;
        cl_error_t status;

        status = cpio_checktimelimit(ctx);
        if (status != CL_SUCCESS)
            return status;

        data = fmap_need_off_once_len(ctx->fmap, offset + consumed, chunk, &nread);
        if (data == NULL || nread != chunk) {
            cli_mark_scan_incomplete(ctx, "CPIO CRC member data could not be read completely");
            return CL_EREAD;
        }

        for (i = 0; i < chunk; i++)
            actual += data[i];
        consumed += chunk;
    }

    if (actual != expected) {
        cli_dbgmsg("cli_scancpio_newc: CRC checksum mismatch: %08x != %08x\n", actual, expected);
        cli_mark_scan_incomplete(ctx, "CPIO CRC member checksum did not match");
        return CL_EPARSE;
    }

    return CL_SUCCESS;
}

static void sanitname(char *name)
{
    while (*name) {
        if (!isascii(*name) || strchr("%\\\t\n\r", *name))
            *name = '_';
        name++;
    }
}

cl_error_t cli_scancpio_old(cli_ctx *ctx)
{
    cl_error_t status = CL_SUCCESS;
    struct cpio_hdr_old hdr_old;
    char *fmap_name = NULL;
    char name[513];
    unsigned int file = 0, trailer = 0;
    size_t filesize, namesize, hdr_namesize;
    uint32_t parsed_filesize;
    int conv;
    int complete = 0;
    size_t hdr_read = 0;
    size_t pos = 0;

    status = cpio_validate_context(ctx);
    if (status != CL_SUCCESS)
        return status;

    memset(name, 0, sizeof(name));

    while (1) {
        status = cpio_checktimelimit(ctx);
        if (status != CL_SUCCESS)
            goto done;

        hdr_read = cpio_readn(ctx->fmap, &hdr_old, pos, sizeof(hdr_old));
        if (hdr_read != sizeof(hdr_old))
            break;

        if (cpio_advance(&pos, sizeof(hdr_old)) < 0) {
            cli_mark_scan_incomplete(ctx, "CPIO coordinate arithmetic overflowed");
            status = CL_EPARSE;
            goto done;
        }
        if (!hdr_old.magic && trailer) {
            complete = 1;
            status   = CL_SUCCESS;
            goto done;
        }

        if (hdr_old.magic == 070707) {
            conv = 0;
        } else if (hdr_old.magic == 0143561) {
            conv = 1;
        } else {
            cli_dbgmsg("cli_scancpio_old: Invalid magic number\n");
            status = CL_EFORMAT;
            goto done;
        }

        cli_dbgmsg("CPIO: -- File %u --\n", ++file);

        hdr_namesize = EC16(hdr_old.namesize, conv);
        if (!hdr_namesize) {
            cli_mark_scan_incomplete(ctx, "CPIO member name size was zero");
            status = CL_EPARSE;
            goto done;
        }
        namesize = MIN(sizeof(name), hdr_namesize);
        hdr_read = cpio_readn(ctx->fmap, &name, pos, namesize);
        if (hdr_read != namesize) {
            cli_dbgmsg("cli_scancpio_old: Can't read file name\n");
            cli_mark_scan_incomplete(ctx, "CPIO member name could not be read completely");
            status = (hdr_read == (size_t)-1) ? CL_EREAD : CL_EPARSE;
            goto done;
        }
        status = cpio_validate_name_terminator(ctx, pos, hdr_namesize);
        if (status != CL_SUCCESS)
            goto done;
        if (cpio_advance(&pos, namesize) < 0) {
            cli_mark_scan_incomplete(ctx, "CPIO coordinate arithmetic overflowed");
            status = CL_EPARSE;
            goto done;
        }
        name[namesize - 1] = 0;
        sanitname(name);
        cli_dbgmsg("CPIO: Name: %s\n", name);
        if (!strcmp(name, "TRAILER!!!")) {
            trailer = 1;
        }

        if (namesize < hdr_namesize) {
            if (hdr_namesize % 2) {
                hdr_namesize++;
            }
            if (cpio_advance(&pos, hdr_namesize - namesize) < 0) {
                cli_mark_scan_incomplete(ctx, "CPIO coordinate arithmetic overflowed");
                status = CL_EPARSE;
                goto done;
            }
        } else if (hdr_namesize % 2) {
            if (cpio_advance(&pos, 1) < 0) {
                cli_mark_scan_incomplete(ctx, "CPIO coordinate arithmetic overflowed");
                status = CL_EPARSE;
                goto done;
            }
        }

        fmap_name = name;
        parsed_filesize = (uint32_t)((uint32_t)EC16(hdr_old.filesize[0], conv) << 16 | EC16(hdr_old.filesize[1], conv));
        filesize        = (size_t)parsed_filesize;
        cli_dbgmsg("CPIO: Filesize: %zu\n", filesize);
        if (!filesize) {
            if (trailer)
                complete = 1;
            continue;
        }

        status = cli_matchmeta(ctx, name, filesize, filesize, 0, file, 0);
        if (status != CL_SUCCESS) {
            goto done;
        }

        if ((EC16(hdr_old.mode, conv) & 0170000) != 0100000) {
            cli_dbgmsg("CPIO: Not a regular file, skipping\n");
        } else {
            status = cli_magic_scan_nested_fmap_type(ctx->fmap, pos, filesize, ctx, CL_TYPE_ANY, fmap_name, LAYER_ATTRIBUTES_NONE);
            if (status != CL_SUCCESS) {
                goto done;
            }
        }
        if (cpio_align_size(filesize, 2, &filesize) < 0) {
            cli_mark_scan_incomplete(ctx, "CPIO member size exceeds the coordinate range");
            status = CL_EPARSE;
            goto done;
        }

        if (cpio_advance(&pos, filesize) < 0) {
            cli_mark_scan_incomplete(ctx, "CPIO coordinate arithmetic overflowed");
            status = CL_EPARSE;
            goto done;
        }
    }

done:
    if ((status == CL_SUCCESS) && !complete) {
        if (hdr_read == (size_t)-1) {
            cli_mark_scan_incomplete(ctx, "CPIO header could not be read");
            status = CL_EREAD;
        } else {
            cli_mark_scan_incomplete(ctx, "CPIO archive ended before a complete trailer");
            status = CL_EPARSE;
        }
    }

    return status;
}

cl_error_t cli_scancpio_odc(cli_ctx *ctx)
{
    cl_error_t status = CL_SUCCESS;
    struct cpio_hdr_odc hdr_odc;
    char name[513] = {0};
    unsigned int file = 0, trailer = 0;
    size_t filesize = 0, namesize = 0, hdr_namesize = 0;
    uint32_t parsed_filesize = 0, parsed_namesize = 0;
    int complete = 0;
    size_t hdr_read = 0;
    size_t pos = 0;

    status = cpio_validate_context(ctx);
    if (status != CL_SUCCESS)
        return status;

    memset(&hdr_odc, 0, sizeof(hdr_odc));

    while (1) {
        status = cpio_checktimelimit(ctx);
        if (status != CL_SUCCESS)
            goto done;

        hdr_read = cpio_readn(ctx->fmap, &hdr_odc, pos, sizeof(hdr_odc));
        if (hdr_read != sizeof(hdr_odc))
            break;

        if (cpio_advance(&pos, sizeof(hdr_odc)) < 0) {
            cli_mark_scan_incomplete(ctx, "CPIO coordinate arithmetic overflowed");
            status = CL_EPARSE;
            goto done;
        }
        if (!hdr_odc.magic[0] && trailer) {
            complete = 1;
            status   = CL_SUCCESS;
            goto done;
        }

        if (strncmp(hdr_odc.magic, "070707", 6)) {
            cli_dbgmsg("cli_scancpio_odc: Invalid magic string\n");
            status = CL_EFORMAT;
            goto done;
        }

        cli_dbgmsg("CPIO: -- File %u --\n", ++file);

        if (cpio_parse_octal_u32(hdr_odc.namesize, sizeof(hdr_odc.namesize), &parsed_namesize) < 0) {
            cli_dbgmsg("cli_scancpio_odc: Can't convert name size\n");
            cli_mark_scan_incomplete(ctx, "CPIO ODC name-size field was malformed");
            status = CL_EPARSE;
            goto done;
        }
        if (!parsed_namesize) {
            cli_mark_scan_incomplete(ctx, "CPIO ODC member name size was zero");
            status = CL_EPARSE;
            goto done;
        }
        hdr_namesize = (size_t)parsed_namesize;
        namesize = MIN(sizeof(name), hdr_namesize);
        hdr_read = cpio_readn(ctx->fmap, &name, pos, namesize);
        if (hdr_read != namesize) {
            cli_dbgmsg("cli_scancpio_odc: Can't read file name\n");
            cli_mark_scan_incomplete(ctx, "CPIO member name could not be read completely");
            status = (hdr_read == (size_t)-1) ? CL_EREAD : CL_EPARSE;
            goto done;
        }
        status = cpio_validate_name_terminator(ctx, pos, hdr_namesize);
        if (status != CL_SUCCESS)
            goto done;
        if (cpio_advance(&pos, namesize) < 0) {
            cli_mark_scan_incomplete(ctx, "CPIO coordinate arithmetic overflowed");
            status = CL_EPARSE;
            goto done;
        }
        name[namesize - 1] = 0;
        sanitname(name);
        cli_dbgmsg("CPIO: Name: %s\n", name);
        if (!strcmp(name, "TRAILER!!!")) {
            trailer = 1;
        }

        if (namesize < hdr_namesize) {
            if (cpio_advance(&pos, hdr_namesize - namesize) < 0) {
                cli_mark_scan_incomplete(ctx, "CPIO coordinate arithmetic overflowed");
                status = CL_EPARSE;
                goto done;
            }
        }

        if (cpio_parse_octal_u32(hdr_odc.filesize, sizeof(hdr_odc.filesize), &parsed_filesize) < 0) {
            cli_dbgmsg("cli_scancpio_odc: Can't convert file size\n");
            cli_mark_scan_incomplete(ctx, "CPIO ODC file-size field was malformed");
            status = CL_EPARSE;
            goto done;
        }
        filesize = (size_t)parsed_filesize;
        cli_dbgmsg("CPIO: Filesize: %zu\n", filesize);
        if (!filesize) {
            if (trailer)
                complete = 1;
            continue;
        }

        status = cli_matchmeta(ctx, name, filesize, filesize, 0, file, 0);
        if (status != CL_SUCCESS) {
            goto done;
        }

        status = cli_magic_scan_nested_fmap_type(ctx->fmap, pos, filesize, ctx, CL_TYPE_ANY, name, LAYER_ATTRIBUTES_NONE);
        if (status != CL_SUCCESS) {
            goto done;
        }

        if (cpio_advance(&pos, filesize) < 0) {
            cli_mark_scan_incomplete(ctx, "CPIO coordinate arithmetic overflowed");
            status = CL_EPARSE;
            goto done;
        }
    }

done:
    if ((status == CL_SUCCESS) && !complete) {
        if (hdr_read == (size_t)-1) {
            cli_mark_scan_incomplete(ctx, "CPIO header could not be read");
            status = CL_EREAD;
        } else {
            cli_mark_scan_incomplete(ctx, "CPIO archive ended before a complete trailer");
            status = CL_EPARSE;
        }
    }

    return status;
}

cl_error_t cli_scancpio_newc(cli_ctx *ctx, int crc)
{
    cl_error_t status = CL_SUCCESS;
    struct cpio_hdr_newc hdr_newc;
    char name[513];
    unsigned int file = 0, trailer = 0;
    size_t filesize, namesize, hdr_namesize, pad;
    uint32_t parsed_filesize, parsed_namesize;
    int complete = 0;
    size_t hdr_read = 0;
    size_t pos = 0;

    status = cpio_validate_context(ctx);
    if (status != CL_SUCCESS)
        return status;

    memset(name, 0, 513);

    while (1) {
        cl_error_t checksum_status = CL_SUCCESS;

        status = cpio_checktimelimit(ctx);
        if (status != CL_SUCCESS)
            goto done;

        hdr_read = cpio_readn(ctx->fmap, &hdr_newc, pos, sizeof(hdr_newc));
        if (hdr_read != sizeof(hdr_newc))
            break;

        if (cpio_advance(&pos, sizeof(hdr_newc)) < 0) {
            cli_mark_scan_incomplete(ctx, "CPIO coordinate arithmetic overflowed");
            status = CL_EPARSE;
            goto done;
        }
        if (!hdr_newc.magic[0] && trailer) {
            complete = 1;
            status   = CL_SUCCESS;
            goto done;
        }

        if ((!crc && strncmp(hdr_newc.magic, "070701", 6)) || (crc && strncmp(hdr_newc.magic, "070702", 6))) {
            cli_dbgmsg("cli_scancpio_newc: Invalid magic string\n");
            status = CL_EFORMAT;
            goto done;
        }

        cli_dbgmsg("CPIO: -- File %u --\n", ++file);

        if (cpio_parse_hex_u32(hdr_newc.namesize, &parsed_namesize) < 0) {
            cli_dbgmsg("cli_scancpio_newc: Can't convert name size\n");
            cli_mark_scan_incomplete(ctx, "CPIO newc name-size field was malformed");
            status = CL_EPARSE;
            goto done;
        }
        if (!parsed_namesize) {
            cli_mark_scan_incomplete(ctx, "CPIO newc member name size was zero");
            status = CL_EPARSE;
            goto done;
        }
        hdr_namesize = (size_t)parsed_namesize;
        namesize = MIN(sizeof(name), hdr_namesize);
        hdr_read = cpio_readn(ctx->fmap, &name, pos, namesize);
        if (hdr_read != namesize) {
            cli_dbgmsg("cli_scancpio_newc: Can't read file name\n");
            cli_mark_scan_incomplete(ctx, "CPIO member name could not be read completely");
            status = (hdr_read == (size_t)-1) ? CL_EREAD : CL_EPARSE;
            goto done;
        }
        status = cpio_validate_name_terminator(ctx, pos, hdr_namesize);
        if (status != CL_SUCCESS)
            goto done;
        if (cpio_advance(&pos, namesize) < 0) {
            cli_mark_scan_incomplete(ctx, "CPIO coordinate arithmetic overflowed");
            status = CL_EPARSE;
            goto done;
        }
        name[namesize - 1] = 0;
        sanitname(name);
        cli_dbgmsg("CPIO: Name: %s\n", name);
        if (!strcmp(name, "TRAILER!!!")) {
            trailer = 1;
        }

        if (hdr_namesize > SIZE_MAX - sizeof(hdr_newc)) {
            cli_mark_scan_incomplete(ctx, "CPIO member name exceeds the coordinate range");
            status = CL_EPARSE;
            goto done;
        }
        pad = (4 - (sizeof(hdr_newc) + hdr_namesize) % 4) % 4;
        if (namesize < hdr_namesize) {
            if (cpio_align_size(hdr_namesize, 4, &hdr_namesize) < 0) {
                cli_mark_scan_incomplete(ctx, "CPIO member name exceeds the coordinate range");
                status = CL_EPARSE;
                goto done;
            }
            if (cpio_advance(&pos, hdr_namesize - namesize) < 0) {
                cli_mark_scan_incomplete(ctx, "CPIO coordinate arithmetic overflowed");
                status = CL_EPARSE;
                goto done;
            }
        } else if (pad) {
            if (cpio_advance(&pos, pad) < 0) {
                cli_mark_scan_incomplete(ctx, "CPIO coordinate arithmetic overflowed");
                status = CL_EPARSE;
                goto done;
            }
        }

        if (cpio_parse_hex_u32(hdr_newc.filesize, &parsed_filesize) < 0) {
            cli_dbgmsg("cli_scancpio_newc: Can't convert file size\n");
            cli_mark_scan_incomplete(ctx, "CPIO newc file-size field was malformed");
            status = CL_EPARSE;
            goto done;
        }
        filesize = (size_t)parsed_filesize;
        cli_dbgmsg("CPIO: Filesize: %zu\n", filesize);
        if (crc) {
            checksum_status = cpio_validate_newc_checksum(ctx, hdr_newc.check, pos, filesize);
            if (checksum_status == CL_ETIMEOUT)
                goto done;
        }
        if (!filesize) {
            if (checksum_status != CL_SUCCESS) {
                status = checksum_status;
                goto done;
            }
            if (trailer)
                complete = 1;
            continue;
        }

        status = cli_matchmeta(ctx, name, filesize, filesize, 0, file, 0);
        if (status != CL_SUCCESS) {
            goto done;
        }

        status = cli_magic_scan_nested_fmap_type(ctx->fmap, pos, filesize, ctx, CL_TYPE_ANY, name, LAYER_ATTRIBUTES_NONE);
        status = cli_merge_scan_status(checksum_status, status);
        if (status != CL_SUCCESS) {
            goto done;
        }

        if (cpio_align_size(filesize, 4, &filesize) < 0) {
            cli_mark_scan_incomplete(ctx, "CPIO member size exceeds the coordinate range");
            status = CL_EPARSE;
            goto done;
        }

        if (cpio_advance(&pos, filesize) < 0) {
            cli_mark_scan_incomplete(ctx, "CPIO coordinate arithmetic overflowed");
            status = CL_EPARSE;
            goto done;
        }
    }

done:
    if ((status == CL_SUCCESS) && !complete) {
        if (hdr_read == (size_t)-1) {
            cli_mark_scan_incomplete(ctx, "CPIO header could not be read");
            status = CL_EREAD;
        } else {
            cli_mark_scan_incomplete(ctx, "CPIO archive ended before a complete trailer");
            status = CL_EPARSE;
        }
    }

    return status;
}
