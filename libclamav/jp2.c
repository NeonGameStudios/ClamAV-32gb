/*
 *  Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdint.h>
#include <string.h>

#include "jp2.h"
#include "scanners.h"

#define JP2_SIGNATURE_SIZE 12U
#define JP2_BOX_HEADER_SIZE 8U
#define JP2_EXTENDED_BOX_HEADER_SIZE 16U

static const uint8_t jp2_signature[JP2_SIGNATURE_SIZE] = {
    0x00, 0x00, 0x00, 0x0c, 0x6a, 0x50,
    0x20, 0x20, 0x0d, 0x0a, 0x87, 0x0a};

static uint32_t jp2_read_be32(const uint8_t *data)
{
    return ((uint32_t)data[0] << 24) |
           ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) |
           (uint32_t)data[3];
}

static uint64_t jp2_read_be64(const uint8_t *data)
{
    return ((uint64_t)jp2_read_be32(data) << 32) |
           (uint64_t)jp2_read_be32(data + 4);
}

static cl_error_t jp2_parse_error(cli_ctx *ctx, const char *reason)
{
    cli_mark_scan_incomplete(ctx, reason);
    return CL_EPARSE;
}

static cl_error_t jp2_read_exact(cli_ctx *ctx, void *dst, size_t offset, size_t length, const char *reason)
{
    size_t got = fmap_readn(ctx->fmap, dst, offset, length);

    if (got == length)
        return CL_SUCCESS;
    if (got == (size_t)-1) {
        cli_mark_scan_incomplete(ctx, reason);
        return CL_EREAD;
    }

    return jp2_parse_error(ctx, reason);
}

static bool jp2_box_is(const uint8_t *type, const char *name)
{
    return 0 == memcmp(type, name, 4);
}

static cl_error_t jp2_unsupported(cli_ctx *ctx, const char *reason)
{
    cli_mark_scan_incomplete(ctx, reason);
    return CL_EUNPACK;
}

static cl_error_t jp2_checktimelimit(cli_ctx *ctx, const char *reason)
{
    cl_error_t status = cli_checktimelimit(ctx);

    if (status != CL_SUCCESS)
        cli_mark_scan_incomplete(ctx, reason);

    return status;
}

cl_error_t cli_scanjp2(cli_ctx *ctx)
{
    uint8_t signature[JP2_SIGNATURE_SIZE];
    uint8_t box_header[JP2_EXTENDED_BOX_HEADER_SIZE];
    uint8_t codestream_marker[2];
    uint8_t box_type[4];
    uint64_t offset;
    uint64_t map_length;
    uint64_t box_length;
    uint64_t box_header_length;
    uint64_t box_end;
    bool saw_file_type = false;
    bool saw_header = false;
    bool saw_codestream = false;
    bool box_to_end;
    cl_error_t status;

    if ((NULL == ctx) || (NULL == ctx->fmap))
        return CL_ENULLARG;

    status = jp2_checktimelimit(ctx, "JP2 inspection reached the configured time limit");
    if (status != CL_SUCCESS)
        return status;

    status = jp2_read_exact(ctx, signature, 0, sizeof(signature),
                            "JP2 signature could not be read completely");
    if (status != CL_SUCCESS)
        return status;
    if (0 != memcmp(signature, jp2_signature, sizeof(signature)))
        return CL_EFORMAT;

    map_length = (uint64_t)ctx->fmap->len;
    offset     = JP2_SIGNATURE_SIZE;

    while (offset < map_length) {
        status = jp2_checktimelimit(ctx, "JP2 box traversal reached the configured time limit");
        if (status != CL_SUCCESS)
            return status;

        if (map_length - offset < JP2_BOX_HEADER_SIZE)
            return jp2_parse_error(ctx, "JP2 box header is truncated");
        if (offset > (uint64_t)SIZE_MAX)
            return jp2_parse_error(ctx, "JP2 box offset is not representable");

        status = jp2_read_exact(ctx, box_header, (size_t)offset, JP2_BOX_HEADER_SIZE,
                                "JP2 box header could not be read completely");
        if (status != CL_SUCCESS)
            return status;

        memcpy(box_type, box_header + 4, sizeof(box_type));
        box_length        = jp2_read_be32(box_header);
        box_header_length = JP2_BOX_HEADER_SIZE;
        box_to_end        = (box_length == 0);

        if (box_length == 1) {
            if (map_length - offset < JP2_EXTENDED_BOX_HEADER_SIZE)
                return jp2_parse_error(ctx, "JP2 extended box header is truncated");
            if (offset > (uint64_t)SIZE_MAX - JP2_BOX_HEADER_SIZE)
                return jp2_parse_error(ctx, "JP2 extended box offset is not representable");

            status = jp2_read_exact(ctx, box_header + JP2_BOX_HEADER_SIZE,
                                    (size_t)(offset + JP2_BOX_HEADER_SIZE), sizeof(uint64_t),
                                    "JP2 extended box length could not be read completely");
            if (status != CL_SUCCESS)
                return status;

            box_length        = jp2_read_be64(box_header + JP2_BOX_HEADER_SIZE);
            box_header_length = JP2_EXTENDED_BOX_HEADER_SIZE;
            box_to_end        = false;
        } else if (box_to_end) {
            box_length = map_length - offset;
        }

        if ((box_length < box_header_length) || (box_length > map_length - offset))
            return jp2_parse_error(ctx, "JP2 box range is outside the mapped input");

        box_end = offset + box_length;

        if (jp2_box_is(box_type, "ftyp")) {
            if (box_length < 16U)
                return jp2_parse_error(ctx, "JP2 file-type box is truncated");
            saw_file_type = true;
        } else if (jp2_box_is(box_type, "jp2h")) {
            if (box_length <= JP2_BOX_HEADER_SIZE)
                return jp2_parse_error(ctx, "JP2 header box is empty");
            saw_header = true;
        } else if (jp2_box_is(box_type, "jp2c")) {
            if (box_length - box_header_length < sizeof(codestream_marker))
                return jp2_parse_error(ctx, "JP2 codestream box is empty");
            if (offset > (uint64_t)SIZE_MAX - box_header_length)
                return jp2_parse_error(ctx, "JP2 codestream offset is not representable");

            status = jp2_read_exact(ctx, codestream_marker,
                                    (size_t)(offset + box_header_length),
                                    sizeof(codestream_marker),
                                    "JP2 codestream marker could not be read completely");
            if (status != CL_SUCCESS)
                return status;
            if ((codestream_marker[0] != 0xff) || (codestream_marker[1] != 0x4f))
                return jp2_parse_error(ctx, "JP2 codestream does not start with SOC");
            saw_codestream = true;
        }

        offset = box_end;
        if (box_to_end)
            break;
    }

    if (!saw_file_type || !saw_header || !saw_codestream)
        return jp2_parse_error(ctx, "JP2 required boxes are missing");

    return jp2_unsupported(ctx, "JP2 codestream decoding is unsupported by the bounded parser");
}
