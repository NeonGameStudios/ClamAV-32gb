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

#include "bmp.h"
#include "scanners.h"

#define BMP_FILE_HEADER_SIZE 14U
#define BMP_CORE_HEADER_SIZE 12U
#define BMP_INFO_HEADER_SIZE 40U

#define BMP_BI_RGB        0U
#define BMP_BI_RLE8       1U
#define BMP_BI_RLE4       2U
#define BMP_BI_BITFIELDS  3U
#define BMP_BI_JPEG       4U
#define BMP_BI_PNG        5U
#define BMP_BI_ALPHABITFIELDS 6U
#define BMP_BI_CMYK       11U
#define BMP_BI_CMYKRLE8   12U
#define BMP_BI_CMYKRLE4   13U

static uint16_t bmp_read_u16(const uint8_t *data)
{
    return (uint16_t)data[0] | ((uint16_t)data[1] << 8);
}

static uint32_t bmp_read_u32(const uint8_t *data)
{
    return (uint32_t)data[0] |
           ((uint32_t)data[1] << 8) |
           ((uint32_t)data[2] << 16) |
           ((uint32_t)data[3] << 24);
}

static cl_error_t bmp_parse_error(cli_ctx *ctx, const char *reason)
{
    cli_mark_scan_incomplete(ctx, reason);
    return CL_EPARSE;
}

static cl_error_t bmp_read_exact(cli_ctx *ctx, void *dst, size_t offset, size_t length, const char *reason)
{
    if (offset > ctx->fmap->len || length > ctx->fmap->len - offset)
        return bmp_parse_error(ctx, reason);

    size_t got = fmap_readn(ctx->fmap, dst, offset, length);

    if (got == length)
        return CL_SUCCESS;
    if (got == (size_t)-1) {
        cli_mark_scan_incomplete(ctx, reason);
        return CL_EREAD;
    }

    return bmp_parse_error(ctx, reason);
}

static bool bmp_compression_is_known(uint32_t compression)
{
    switch (compression) {
        case BMP_BI_RGB:
        case BMP_BI_RLE8:
        case BMP_BI_RLE4:
        case BMP_BI_BITFIELDS:
        case BMP_BI_JPEG:
        case BMP_BI_PNG:
        case BMP_BI_ALPHABITFIELDS:
        case BMP_BI_CMYK:
        case BMP_BI_CMYKRLE8:
        case BMP_BI_CMYKRLE4:
            return true;
        default:
            return false;
    }
}

static bool bmp_compression_has_raw_rows(uint32_t compression)
{
    switch (compression) {
        case BMP_BI_RGB:
        case BMP_BI_BITFIELDS:
        case BMP_BI_ALPHABITFIELDS:
        case BMP_BI_CMYK:
            return true;
        default:
            return false;
    }
}

static bool bmp_bpp_is_known(uint16_t bits_per_pixel)
{
    switch (bits_per_pixel) {
        case 1:
        case 2:
        case 4:
        case 8:
        case 16:
        case 24:
        case 32:
            return true;
        default:
            return false;
    }
}

static cl_error_t bmp_unsupported(cli_ctx *ctx, const char *reason)
{
    cli_mark_scan_incomplete(ctx, reason);
    return CL_EUNPACK;
}

cl_error_t cli_scanbmp(cli_ctx *ctx)
{
    uint8_t signature[2];
    uint8_t file_header[BMP_FILE_HEADER_SIZE];
    uint8_t dib_prefix[4];
    uint8_t dib_header[BMP_INFO_HEADER_SIZE];
    uint32_t declared_file_size;
    uint32_t pixel_offset;
    uint32_t dib_size;
    uint32_t compression = BMP_BI_RGB;
    uint32_t image_size = 0;
    uint16_t planes;
    uint16_t bits_per_pixel;
    uint32_t width_raw;
    uint32_t height_raw;
    uint64_t dib_end;
    uint64_t available_end;
    uint64_t map_length;
    uint64_t required_pixel_bytes;
    uint64_t row_bits;
    uint64_t row_bytes;
    uint64_t height;
    bool top_down = false;
    cl_error_t status;

    if ((NULL == ctx) || (NULL == ctx->fmap))
        return CL_ENULLARG;

    status = bmp_read_exact(ctx, signature, 0, sizeof(signature),
                            "BMP signature could not be read completely");
    if (status != CL_SUCCESS)
        return status;

    if ((signature[0] != 'B') || (signature[1] != 'M'))
        return CL_EFORMAT;

    status = bmp_read_exact(ctx, file_header, 0, sizeof(file_header),
                            "BMP file header could not be read completely");
    if (status != CL_SUCCESS)
        return status;

    declared_file_size = bmp_read_u32(file_header + 2);
    pixel_offset       = bmp_read_u32(file_header + 10);
    map_length         = (uint64_t)ctx->fmap->len;

    status = bmp_read_exact(ctx, dib_prefix, BMP_FILE_HEADER_SIZE, sizeof(dib_prefix),
                            "BMP DIB header size could not be read completely");
    if (status != CL_SUCCESS)
        return status;

    dib_size = bmp_read_u32(dib_prefix);
    if (dib_size < BMP_CORE_HEADER_SIZE)
        return bmp_parse_error(ctx, "BMP DIB header size is invalid");

    dib_end = (uint64_t)BMP_FILE_HEADER_SIZE + (uint64_t)dib_size;
    if ((dib_end > map_length) || (dib_end > (uint64_t)SIZE_MAX))
        return bmp_parse_error(ctx, "BMP DIB header is truncated");

    if (declared_file_size != 0 &&
        (((uint64_t)declared_file_size < (uint64_t)pixel_offset) ||
         ((uint64_t)declared_file_size > map_length)))
        return bmp_parse_error(ctx, "BMP declared file size is outside the mapped input");

    if (((uint64_t)pixel_offset < dib_end) || ((uint64_t)pixel_offset > map_length))
        return bmp_parse_error(ctx, "BMP pixel offset is outside the mapped input");

    available_end = map_length;
    if ((declared_file_size != 0) && ((uint64_t)declared_file_size < available_end))
        available_end = declared_file_size;

    if (dib_size == BMP_CORE_HEADER_SIZE) {
        status = bmp_read_exact(ctx, dib_header, BMP_FILE_HEADER_SIZE, BMP_CORE_HEADER_SIZE,
                                "BMP core header could not be read completely");
        if (status != CL_SUCCESS)
            return status;

        width_raw      = (uint32_t)bmp_read_u16(dib_header + 4);
        height_raw     = (uint32_t)bmp_read_u16(dib_header + 6);
        planes         = bmp_read_u16(dib_header + 8);
        bits_per_pixel = bmp_read_u16(dib_header + 10);
    } else if (dib_size < BMP_INFO_HEADER_SIZE) {
        return bmp_unsupported(ctx, "BMP DIB header variant is unsupported by the bounded parser");
    } else {
        status = bmp_read_exact(ctx, dib_header, BMP_FILE_HEADER_SIZE, sizeof(dib_header),
                                "BMP information header could not be read completely");
        if (status != CL_SUCCESS)
            return status;

        width_raw      = bmp_read_u32(dib_header + 4);
        height_raw     = bmp_read_u32(dib_header + 8);
        planes         = bmp_read_u16(dib_header + 12);
        bits_per_pixel = bmp_read_u16(dib_header + 14);
        compression    = bmp_read_u32(dib_header + 16);
        image_size     = bmp_read_u32(dib_header + 20);
        top_down       = (height_raw > INT32_MAX);

        if ((width_raw == 0) || (width_raw > INT32_MAX) ||
            (height_raw == 0) || (height_raw == UINT32_C(0x80000000)))
            return bmp_parse_error(ctx, "BMP dimensions are invalid");
    }

    if ((width_raw == 0) || (height_raw == 0) || (planes != 1) ||
        !bmp_bpp_is_known(bits_per_pixel))
        return bmp_parse_error(ctx, "BMP dimensions or pixel format are invalid");

    if (!bmp_compression_is_known(compression))
        return bmp_unsupported(ctx, "BMP compression is unsupported by the bounded parser");

    if (top_down && ((compression == BMP_BI_RLE4) || (compression == BMP_BI_RLE8) ||
                     (compression == BMP_BI_CMYKRLE4) || (compression == BMP_BI_CMYKRLE8)))
        return bmp_parse_error(ctx, "BMP top-down compressed image is invalid");

    if ((image_size != 0) &&
        ((uint64_t)image_size > (available_end - (uint64_t)pixel_offset)))
        return bmp_parse_error(ctx, "BMP pixel data range is truncated");

    /* BI_RGB and the raw bitfield/CMYK variants may legally leave
     * biSizeImage at zero. Derive their row-stride range so a header-only
     * mapping cannot be treated as a structurally admitted image. */
    if (bmp_compression_has_raw_rows(compression)) {
        height = top_down ? (UINT64_C(0x100000000) - (uint64_t)height_raw) : (uint64_t)height_raw;
        if ((uint64_t)width_raw > UINT64_MAX / (uint64_t)bits_per_pixel)
            return bmp_parse_error(ctx, "BMP row-size arithmetic overflowed");
        row_bits = (uint64_t)width_raw * (uint64_t)bits_per_pixel;
        if (row_bits > UINT64_MAX - 31U)
            return bmp_parse_error(ctx, "BMP row-size arithmetic overflowed");
        row_bytes = (row_bits + 31U) / 32U;
        if (row_bytes > UINT64_MAX / 4U)
            return bmp_parse_error(ctx, "BMP row-size arithmetic overflowed");
        row_bytes *= 4U;
        if ((height != 0) && (row_bytes > UINT64_MAX / height))
            return bmp_parse_error(ctx, "BMP pixel-size arithmetic overflowed");
        required_pixel_bytes = row_bytes * height;
        if (required_pixel_bytes > (available_end - (uint64_t)pixel_offset))
            return bmp_parse_error(ctx, "BMP derived pixel data range is truncated");
        if ((image_size != 0) && ((uint64_t)image_size < required_pixel_bytes))
            return bmp_parse_error(ctx, "BMP declared pixel data size is too small");
    }

    /* Header admission is deliberately not a clean result. The bounded
     * parser does not decode pixels or inspect embedded compressed payloads. */
    return bmp_unsupported(ctx, "BMP pixel decoding is unsupported by the bounded parser");
}
