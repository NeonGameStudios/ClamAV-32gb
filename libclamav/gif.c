/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2011-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm <tkojm@clamav.net>, Aldo Mazzeo, Valerie Snyder
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

/*
 *  GIF Format
 *  ----------
 *
 *  1. Signature: 3 bytes  ("GIF")
 *
 *  2. Version: 3 bytes  ("87a" or "89a")
 *
 *  3. Logical Screen Descriptor: 7 bytes (see `struct gif_screen_descriptor`)
 *     (Opt.) Global Color Table: n bytes (defined in the Logical Screen Descriptor flags)
 *
 *  4. All subsequent blocks are preceded by the following 1-byte labels...
 *
 *     0x21:  Extension Introducer
 *        0x01:  Opt. (0+) Plain Text Extension
 *        0xF9:  Opt. (0+) Graphic Control Extension
 *        0xFE:  Opt. (0+) Comment Extension
 *        0xFF:  Opt. (0+) Application Extension
 *
 *        Note: Each extension has a size field followed by some data. After the
 *              data may be a series of sub-blocks, each with a block size.
 *              If there are no more sub-blocks, the size will be 0x00, meaning
 *              there's no more blocks.
 *              The Graphic Control Extension never has any sub-blocks.
 *
 *     0x2C:  Image Descriptor  (1 per image, unlimited images)
 *        (Opt.) Local Color Table: n bytes (defined in the Image Descriptor flags)
 *        (Req.) Table-based Image Data Block*
 *
 *        Note: Each image a series of data blocks of size 0-255 bytes each where
 *              the first byte is the size of the data-block.
 *              If there are no more data-blocks, the size will be 0x00, meaning
 *              there's no more data.
 *
 *     0x3B:  Trailer (1 located at end of data stream)
 *
 *  Reference https://www.w3.org/Graphics/GIF/spec-gif89a.txt for the GIF spec.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <math.h>
#include <stdbool.h>

#include "gif.h"
#include "scanners.h"
#include "clamav.h"

/* clang-format off */
#ifndef HAVE_ATTRIB_PACKED
#define __attribute__(x)
#endif
#ifdef HAVE_PRAGMA_PACK
#pragma pack(1)
#endif
#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack 1
#endif

/**
 * @brief Logical Screen Descriptor
 *
 * This block immediately follows the  "GIF89a" magic bytes

 * Flags contains packed fields which are as follows:
 *  Global Color Table Flag     - 1 Bit
 *  Color Resolution            - 3 Bits
 *  Sort Flag                   - 1 Bit
 *  Size of Global Color Table  - 3 Bits
 */
struct gif_screen_descriptor {
    uint16_t width;
    uint16_t height;
    uint8_t flags;
    uint8_t bg_color_idx;
    uint8_t pixel_aspect_ratio;
} __attribute__((packed));

#define GIF_SCREEN_DESC_FLAGS_MASK_HAVE_GLOBAL_COLOR_TABLE    0x80 /* If set, a Global Color Table will follow the Logical Screen Descriptor */
#define GIF_SCREEN_DESC_FLAGS_MASK_COLOR_RESOLUTION           0x70 /* Number of bits per primary color available to the original image, minus 1. */
#define GIF_SCREEN_DESC_FLAGS_MASK_SORT_FLAG                  0x08 /* Indicates whether the Global Color Table is sorted. */
#define GIF_SCREEN_DESC_FLAGS_MASK_SIZE_OF_GLOBAL_COLOR_TABLE 0x07 /* If exists, the size = 3 * pow(2, this_field + 1), or: 3 * (1 << (this_field + 1)) */

/**
 * @brief Graphic Control Extension
 *
 */
struct gif_graphic_control_extension {
    uint8_t block_size;
    uint8_t flags;
    uint16_t delaytime;
    uint8_t transparent_color_idx;
    uint8_t block_terminator;
} __attribute__((packed));

/**
 * @brief Image Descriptor
 *
 * Flags contains packed fields which are as follows:
 *  Local Color Table Flag      - 1 Bit
 *  Interlace Flag              - 1 Bit
 *  Sort Flag                   - 1 Bit
 *  Reserved                    - 2 Bits
 *  Size of Local Color Table   - 3 Bits
 */
struct gif_image_descriptor {
    uint16_t leftpos;
    uint16_t toppos;
    uint16_t width;
    uint16_t height;
    uint8_t flags;
} __attribute__((packed));

#define GIF_IMAGE_DESC_FLAGS_MASK_HAVE_LOCAL_COLOR_TABLE    0x80 /* If set, a Global Color Table will follow the Logical Screen Descriptor */
#define GIF_IMAGE_DESC_FLAGS_MASK_IS_INTERLACED             0x40 /* Indicates if the image is interlaced */
#define GIF_IMAGE_DESC_FLAGS_MASK_SORT_FLAG                 0x20 /* Indicates whether the Local Color Table is sorted. */
#define GIF_IMAGE_DESC_FLAGS_MASK_SIZE_OF_LOCAL_COLOR_TABLE 0x07 /* If exists, the size = 3 * pow(2, this_field + 1), or: 3 * (1 << (this_field + 1)) */

/* Main labels */
#define GIF_LABEL_EXTENSION_INTRODUCER                  0x21
#define GIF_LABEL_GRAPHIC_IMAGE_DESCRIPTOR              0x2C
#define GIF_LABEL_SPECIAL_TRAILER                       0x3B

/* Extension labels (found after the Extension Introducer) */
#define GIF_LABEL_GRAPHIC_PLAIN_TEXT_EXTENSION          0x01
#define GIF_LABEL_CONTROL_GRAPHIC_CONTROL_EXTENSION     0xF9
#define GIF_LABEL_SPECIAL_COMMENT_EXTENSION             0xFE
#define GIF_LABEL_SPECIAL_APP_EXTENSION                 0xFF

#define GIF_BLOCK_TERMINATOR 0x00 /* Used to indicate end of image data and also for end of extension sub-blocks */

#ifdef HAVE_PRAGMA_PACK
#pragma pack()
#endif
#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack
#endif
/* clang-format on */

static cl_error_t gif_parse_error(cli_ctx *ctx, const char *reason)
{
    cli_mark_scan_incomplete(ctx, reason);

    /* Direct parser callers used by the library tests may not have built an
     * evidence object yet. The parser error must remain fail-visible even in
     * that minimal context; full scan contexts retain the existing heuristic
     * reporting behavior. */
    if (ctx == NULL || ctx->this_layer_evidence == NULL)
        return CL_EPARSE;

    return cli_append_potentially_unwanted(ctx, reason);
}

static cl_error_t gif_read_status(cli_ctx *ctx, size_t bytes_read, size_t expected, const char *reason)
{
    if (bytes_read == expected)
        return CL_SUCCESS;
    if (bytes_read == (size_t)-1) {
        cli_mark_scan_incomplete(ctx, reason);
        return CL_EREAD;
    }
    return gif_parse_error(ctx, reason);
}

static bool gif_range_within_map(const fmap_t *map, size_t offset, size_t length)
{
    return map != NULL && offset <= map->len && length <= map->len - offset;
}

static size_t gif_readn(fmap_t *map, void *dst, size_t offset, size_t length)
{
    /* A fixed GIF structure that extends past EOF is malformed input, not an
     * operational callback failure. Preserve CL_EREAD only when the complete
     * requested range is available to the fmap callback. */
    if (!gif_range_within_map(map, offset, length))
        return 0;
    return fmap_readn(map, dst, offset, length);
}

cl_error_t cli_parsegif(cli_ctx *ctx)
{
    cl_error_t status = CL_SUCCESS;
    bool parse_error  = false;

    fmap_t *map   = NULL;
    size_t offset = 0;

    const char *signature = NULL;
    char version[4];
    struct gif_screen_descriptor screen_desc;
    size_t global_color_table_size = 0;
    bool have_image_data           = false;

    cli_dbgmsg("in cli_parsegif()\n");

    if (NULL == ctx) {
        cli_dbgmsg("GIF: passed context was NULL\n");
        status = CL_ENULLARG;
        goto done;
    }
    map = ctx->fmap;

    if (map == NULL) {
        status      = gif_parse_error(ctx, "GIF input map is unavailable");
        parse_error = true;
        goto done;
    }

    /* A map shorter than the signature cannot be a confirmed GIF. Once the
     * signature-sized range exists, a failed fmap read is an operational
     * failure and must not become a clean non-GIF result. */
    if (map->len < strlen("GIF"))
        goto done;
    /* The signature is consumed immediately and is not retained across any
     * later fmap operation, so do not pin its page for the whole parser. */
    if (NULL == (signature = fmap_need_off_once(map, offset, strlen("GIF")))) {
        cli_dbgmsg("GIF: Can't read GIF magic bytes completely\n");
        status      = gif_read_status(ctx, (size_t)-1, strlen("GIF"), "Heuristics.Broken.Media.GIF.CantReadMagic");
        parse_error = true;
        goto scan_overlay;
    }
    offset += strlen("GIF");

    if (0 != strncmp("GIF", signature, 3)) {
        cli_dbgmsg("GIF: First 3 bytes not 'GIF', not a GIF\n");
        goto done;
    }

    if (!gif_range_within_map(map, offset, strlen("89a"))) {
        cli_dbgmsg("GIF: Can't read GIF format version completely\n");
        status      = gif_parse_error(ctx, "Heuristics.Broken.Media.GIF.TruncatedVersion");
        parse_error = true;
        goto scan_overlay;
    }
    {
        size_t bytes_read = gif_readn(map, &version, offset, strlen("89a"));
        if (bytes_read != strlen("89a")) {
            cli_dbgmsg("GIF: Can't read GIF format version completely\n");
            status      = gif_read_status(ctx, bytes_read, strlen("89a"), "Heuristics.Broken.Media.GIF.TruncatedVersion");
            parse_error = true;
            goto scan_overlay;
        }
    }
    offset += strlen("89a");

    version[3] = '\0';
    cli_dbgmsg("GIF: Version: %s\n", version);

    if (memcmp(version, "87a", 3) != 0 && memcmp(version, "89a", 3) != 0) {
        status      = gif_parse_error(ctx, "Heuristics.Broken.Media.GIF.InvalidVersion");
        parse_error = true;
        goto scan_overlay;
    }

    /*
     * Read the Logical Screen Descriptor
     */
    {
        size_t bytes_read = gif_readn(map, &screen_desc, offset, sizeof(screen_desc));
        if (bytes_read != sizeof(screen_desc)) {
            cli_errmsg("GIF: Can't read logical screen description, file truncated?\n");
            status      = gif_read_status(ctx, bytes_read, sizeof(screen_desc), "Heuristics.Broken.Media.GIF.TruncatedScreenDescriptor");
            parse_error = true;
            goto scan_overlay;
        }
    }
    offset += sizeof(screen_desc);

    cli_dbgmsg("GIF: Screen Size: %u width x %u height.\n",
               le16_to_host(screen_desc.width),
               le16_to_host(screen_desc.height));

    if (screen_desc.flags & GIF_SCREEN_DESC_FLAGS_MASK_HAVE_GLOBAL_COLOR_TABLE) {
        global_color_table_size = 3 * (1 << ((screen_desc.flags & GIF_SCREEN_DESC_FLAGS_MASK_SIZE_OF_GLOBAL_COLOR_TABLE) + 1));
        cli_dbgmsg("GIF: Global Color Table size: %zu\n", global_color_table_size);

        if (!gif_range_within_map(map, offset, global_color_table_size)) {
            cli_errmsg("GIF: EOF in the middle of the global color table, file truncated?\n");
            status      = gif_parse_error(ctx, "Heuristics.Broken.Media.GIF.TruncatedGlobalColorTable");
            parse_error = true;
            goto scan_overlay;
        }
        offset += global_color_table_size;
    } else {
        cli_dbgmsg("GIF: No Global Color Table.\n");
    }

    while (1) {
        uint8_t block_label = 0;

        status = cli_checktimelimit(ctx);
        if (status != CL_SUCCESS) {
            cli_mark_scan_incomplete(ctx, "GIF block traversal reached the configured time limit");
            goto scan_overlay;
        }

        /*
         * Get the block label
         */
        {
            size_t bytes_read = gif_readn(map, &block_label, offset, sizeof(block_label));
            if (bytes_read != sizeof(block_label)) {
                if (have_image_data) {
                    cli_errmsg("GIF: Missing GIF trailer, file inspection is incomplete.\n");
                    status = gif_read_status(ctx, bytes_read, sizeof(block_label), "Heuristics.Broken.Media.GIF.MissingTrailer");
                } else {
                    cli_errmsg("GIF: Can't read block label, EOF before image data. File truncated?\n");
                    status = gif_read_status(ctx, bytes_read, sizeof(block_label), "Heuristics.Broken.Media.GIF.MissingImageData");
                }
                parse_error = true;
                goto scan_overlay;
            }
        }
        offset += sizeof(block_label);

        if (block_label == GIF_LABEL_SPECIAL_TRAILER) {
            /*
             * Trailer (end of data stream)
             */
            cli_dbgmsg("GIF: Trailer (End of stream)\n");
            goto scan_overlay;
        }

        switch (block_label) {
            case GIF_LABEL_EXTENSION_INTRODUCER: {
                uint8_t extension_label = 0;
                cli_dbgmsg("GIF: Extension introducer:\n");

                {
                    size_t bytes_read = gif_readn(map, &extension_label, offset, sizeof(extension_label));
                    if (bytes_read != sizeof(extension_label)) {
                        cli_errmsg("GIF: Failed to read the extension block label, file truncated?\n");
                        status      = gif_read_status(ctx, bytes_read, sizeof(extension_label), "Heuristics.Broken.Media.GIF.TruncatedExtension");
                        parse_error = true;
                        goto scan_overlay;
                    }
                }
                offset += sizeof(extension_label);

                if (extension_label == GIF_LABEL_CONTROL_GRAPHIC_CONTROL_EXTENSION) {
                    cli_dbgmsg("GIF:   Graphic control extension!\n");

                    /* The size of a graphic control extension block is fixed. */
                    struct gif_graphic_control_extension graphic_control_extension;
                    {
                        size_t bytes_read = gif_readn(map, &graphic_control_extension, offset, sizeof(graphic_control_extension));
                        if (bytes_read != sizeof(graphic_control_extension)) {
                            cli_errmsg("GIF: EOF in the graphic control extension, file truncated?\n");
                            status      = gif_read_status(ctx, bytes_read, sizeof(graphic_control_extension), "Heuristics.Broken.Media.GIF.TruncatedGraphicControlExtension");
                            parse_error = true;
                            goto scan_overlay;
                        }
                    }

                    /* The fixed payload is structurally confirmed only when
                     * its declared data length and terminator agree with the
                     * GIF grammar. Otherwise the following bytes cannot be
                     * trusted as the next block boundary. */
                    if (graphic_control_extension.block_size != 4) {
                        status = gif_parse_error(ctx, "Heuristics.Broken.Media.GIF.InvalidGraphicControlBlockSize");
                        parse_error = true;
                        goto scan_overlay;
                    }
                    if (graphic_control_extension.block_terminator != GIF_BLOCK_TERMINATOR) {
                        status = gif_parse_error(ctx, "Heuristics.Broken.Media.GIF.InvalidGraphicControlTerminator");
                        parse_error = true;
                        goto scan_overlay;
                    }
                    offset += sizeof(graphic_control_extension);
                } else {
                    switch (extension_label) {
                        case GIF_LABEL_GRAPHIC_PLAIN_TEXT_EXTENSION:
                            cli_dbgmsg("GIF:   Plain text extension\n");
                            break;
                        case GIF_LABEL_SPECIAL_COMMENT_EXTENSION:
                            cli_dbgmsg("GIF:   Special comment extension\n");
                            break;
                        case GIF_LABEL_SPECIAL_APP_EXTENSION:
                            cli_dbgmsg("GIF:   Special app extension\n");
                            break;
                        default:
                            cli_dbgmsg("GIF:   Unfamiliar extension, label: 0x%x\n", extension_label);
                    }

                    while (1) {
                        status = cli_checktimelimit(ctx);
                        if (status != CL_SUCCESS) {
                            cli_mark_scan_incomplete(ctx, "GIF extension traversal reached the configured time limit");
                            goto scan_overlay;
                        }

                        /*
                         * Skip over the extension and any sub-blocks,
                         * Try to read the block size for each sub-block to skip them.
                         */
                        uint8_t extension_block_size = 0;
                        {
                            size_t bytes_read = gif_readn(map, &extension_block_size, offset, sizeof(extension_block_size));
                            if (bytes_read != sizeof(extension_block_size)) {
                                cli_errmsg("GIF: EOF while attempting to read the block size for an extension, file truncated?\n");
                                status      = gif_read_status(ctx, bytes_read, sizeof(extension_block_size), "Heuristics.Broken.Media.GIF.TruncatedExtension");
                                parse_error = true;
                                goto scan_overlay;
                            }
                        }
                        offset += sizeof(extension_block_size);
                        if (extension_block_size == GIF_BLOCK_TERMINATOR) {
                            cli_dbgmsg("GIF:     No more sub-blocks for this extension.\n");
                            break;
                        } else {
                            cli_dbgmsg("GIF:     Found sub-block of size %d\n", extension_block_size);
                        }

                        if (!gif_range_within_map(map, offset, extension_block_size)) {
                            cli_errmsg("GIF: EOF in the middle of a graphic control extension sub-block, file truncated?\n");
                            status      = gif_parse_error(ctx, "Heuristics.Broken.Media.GIF.TruncatedExtensionSubBlock");
                            parse_error = true;
                            goto scan_overlay;
                        }
                        offset += extension_block_size;
                    }
                }
                break;
            }
            case GIF_LABEL_GRAPHIC_IMAGE_DESCRIPTOR: {
                struct gif_image_descriptor image_desc;
                size_t local_color_table_size = 0;
                uint8_t lzw_minimum_code_size = 0;

                cli_dbgmsg("GIF: Found an image descriptor.\n");
                {
                    size_t bytes_read = gif_readn(map, &image_desc, offset, sizeof(image_desc));
                    if (bytes_read != sizeof(image_desc)) {
                        cli_errmsg("GIF: Can't read image descriptor, file truncated?\n");
                        status      = gif_read_status(ctx, bytes_read, sizeof(image_desc), "Heuristics.Broken.Media.GIF.TruncatedImageDescriptor");
                        parse_error = true;
                        goto scan_overlay;
                    }
                }
                offset += sizeof(image_desc);
                cli_dbgmsg("GIF:   Image size: %u width x %u height, left pos: %u, top pos: %u\n",
                           le16_to_host(image_desc.width),
                           le16_to_host(image_desc.height),
                           le16_to_host(image_desc.leftpos),
                           le16_to_host(image_desc.toppos));

                if (image_desc.flags & GIF_IMAGE_DESC_FLAGS_MASK_HAVE_LOCAL_COLOR_TABLE) {
                    local_color_table_size = 3 * (1 << ((image_desc.flags & GIF_IMAGE_DESC_FLAGS_MASK_SIZE_OF_LOCAL_COLOR_TABLE) + 1));
                    cli_dbgmsg("GIF:     Found a Local Color Table (size: %zu)\n", local_color_table_size);
                    if (!gif_range_within_map(map, offset, local_color_table_size)) {
                        cli_errmsg("GIF: EOF in the middle of the local color table, file truncated?\n");
                        status      = gif_parse_error(ctx, "Heuristics.Broken.Media.GIF.TruncatedLocalColorTable");
                        parse_error = true;
                        goto scan_overlay;
                    }
                    offset += local_color_table_size;
                } else {
                    cli_dbgmsg("GIF:     No Local Color Table.\n");
                }

                /*
                 * Parse the image data.
                 */
                {
                    size_t bytes_read = gif_readn(map, &lzw_minimum_code_size, offset, sizeof(lzw_minimum_code_size));
                    if (bytes_read != sizeof(lzw_minimum_code_size)) {
                        cli_errmsg("GIF: Can't read the LZW minimum code size, file truncated?\n");
                        status      = gif_read_status(ctx, bytes_read, sizeof(lzw_minimum_code_size), "Heuristics.Broken.Media.GIF.TruncatedLzwMinimumCodeSize");
                        parse_error = true;
                        goto scan_overlay;
                    }
                }
                if (lzw_minimum_code_size < 2 || lzw_minimum_code_size > 8) {
                    cli_errmsg("GIF: Invalid LZW minimum code size: %u\n", (unsigned int)lzw_minimum_code_size);
                    status      = gif_parse_error(ctx, "Heuristics.Broken.Media.GIF.InvalidLzwMinimumCodeSize");
                    parse_error = true;
                    goto scan_overlay;
                }
                offset += sizeof(lzw_minimum_code_size);

                while (1) {
                    status = cli_checktimelimit(ctx);
                    if (status != CL_SUCCESS) {
                        cli_mark_scan_incomplete(ctx, "GIF image-data traversal reached the configured time limit");
                        goto scan_overlay;
                    }

                    /*
                     * Skip over the image data block(s).
                     * Try to read the block size for each image data sub-block to skip them.
                     */
                    uint8_t image_data_block_size = 0;
                    {
                        size_t bytes_read = gif_readn(map, &image_data_block_size, offset, sizeof(image_data_block_size));
                        if (bytes_read != sizeof(image_data_block_size)) {
                            cli_errmsg("GIF: EOF while attempting to read the block size for an image data block, file truncated?\n");
                            status      = gif_read_status(ctx, bytes_read, sizeof(image_data_block_size), "Heuristics.Broken.Media.GIF.TruncatedImageDataBlock");
                            parse_error = true;
                            goto scan_overlay;
                        }
                    }
                    offset += sizeof(image_data_block_size);
                    if (image_data_block_size == GIF_BLOCK_TERMINATOR) {
                        cli_dbgmsg("GIF:     No more data sub-blocks for this image.\n");
                        break;
                    } else {
                        cli_dbgmsg("GIF:     Found a sub-block of size %d\n", image_data_block_size);
                    }

                    if (!gif_range_within_map(map, offset, image_data_block_size)) {
                        cli_errmsg("GIF: EOF in the middle of an image data sub-block, file truncated?\n");
                        status      = gif_parse_error(ctx, "Heuristics.Broken.Media.GIF.TruncatedImageDataBlock");
                        parse_error = true;
                        goto scan_overlay;
                    }
                    offset += image_data_block_size;
                }
                have_image_data = true;
                break;
            }
            default: {
                // An unknown code: break.
                cli_errmsg("GIF: Found an unfamiliar block label: 0x%x\n", block_label);
                status      = gif_parse_error(ctx, "Heuristics.Broken.Media.GIF.UnknownBlockLabel");
                parse_error = true;
                goto scan_overlay;
            }
        }
    }

scan_overlay:

    if (CL_SUCCESS == status) {
        if (parse_error) {
            // Some recovery (I saw some "GIF89a;" or things like this)
            if (offset == (strlen("GIF89a") + sizeof(screen_desc) + 1)) {
                offset = strlen("GIF89a");
            }
        }

        // Is there an overlay?
        if (offset < map->len) {
            cli_dbgmsg("GIF: Found extra data after the end of the GIF data stream: %zu bytes, we'll scan it!\n", map->len - offset);
            if (ctx->engine == NULL) {
                cli_mark_scan_incomplete(ctx, "GIF overlay scan requires an owning engine");
                status = CL_ENULLARG;
                goto done;
            }
            status = cli_magic_scan_nested_fmap_type(map, offset, map->len - offset, ctx, CL_TYPE_ANY, NULL, LAYER_ATTRIBUTES_NONE);
            goto done;
        }
    }

done:
    if (parse_error && (status == CL_SUCCESS))
        status = CL_EPARSE;

    return status;
}
