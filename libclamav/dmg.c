/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2013 Sourcefire, Inc.
 *
 *  Authors: David Raynor <draynor@sourcefire.com>
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
#include <fcntl.h>
#if HAVE_SYS_PARAM_H
#include <sys/param.h> /* for NAME_MAX */
#endif

#include <zlib.h>
#include <bzlib.h>
#ifdef NOBZ2PREFIX
#define BZ2_bzDecompress bzDecompress
#define BZ2_bzDecompressEnd bzDecompressEnd
#define BZ2_bzDecompressInit bzDecompressInit
#endif

#include "clamav.h"
#include "others.h"
#include "dmg.h"
#include "scanners.h"
#include "adc.h"
#include "msxml_parser.h"

/* #define DEBUG_DMG_PARSE */
/* #define DEBUG_DMG_BZIP */

#ifdef DEBUG_DMG_PARSE
#define dmg_parsemsg(...) cli_dbgmsg(__VA_ARGS__)
#else
#define dmg_parsemsg(...) ;
#endif

#ifdef DEBUG_DMG_BZIP
#define dmg_bzipmsg(...) cli_dbgmsg(__VA_ARGS__)
#else
#define dmg_bzipmsg(...) ;
#endif

#define DMG_STREAM_CHUNK_SIZE (64U * 1024U)

struct dmg_xml_scan_state {
    unsigned int mishblocknum;
    struct dmg_mish_with_stripes *mish_list;
    struct dmg_mish_with_stripes *mish_list_tail;
};

static int dmg_extract_xml(cli_ctx *, char *, struct dmg_koly_block *);
static int dmg_parse_mish_bytes(cli_ctx *, unsigned int *, uint8_t *, size_t,
                                struct dmg_mish_with_stripes *);
static int dmg_decode_mish_fd(cli_ctx *, unsigned int *, int, struct dmg_mish_with_stripes *);
static cl_error_t dmg_mish_decoded_cb(int, const char *, cli_ctx *, void *);
static int cmp_mish_stripes(const void *stripe_a, const void *stripe_b);
static int dmg_track_sectors(uint64_t *, uint8_t *, uint32_t, uint32_t, uint64_t);
static int dmg_handle_mish(cli_ctx *, unsigned int, char *, uint64_t, uint64_t,
                           struct dmg_mish_with_stripes *);
static const uint8_t *dmg_map_window(cli_ctx *ctx, uint64_t offset, uint64_t remaining, size_t *window_len)
{
    const uint8_t *window;

    if (!ctx || !ctx->fmap || !window_len || remaining == 0 || offset > (uint64_t)SIZE_MAX) {
        if (window_len)
            *window_len = 0;
        return NULL;
    }

    *window_len = (size_t)MIN(remaining, (uint64_t)DMG_STREAM_CHUNK_SIZE);
    window      = fmap_need_off_once(ctx->fmap, (size_t)offset, *window_len);
    if (!window)
        *window_len = 0;
    return window;
}

static int dmg_expected_output(cli_ctx *ctx, uint32_t index, uint64_t sector_count, uint64_t *expected)
{
    if (!expected || sector_count > UINT64_MAX / DMG_SECTOR_SIZE) {
        cli_mark_scan_incomplete(ctx, "DMG stripe output size overflowed");
        cli_dbgmsg("dmg: stripe " STDu32 " output size overflowed\n", index);
        return CL_EPARSE;
    }

    *expected = sector_count * DMG_SECTOR_SIZE;
    return CL_CLEAN;
}

static int dmg_write_checked(cli_ctx *ctx, int fd, const uint8_t *buffer, size_t length,
                             uint64_t *written, uint64_t expected, const char *reason)
{
    if (!written || !buffer || *written > expected || (uint64_t)length > expected - *written) {
        cli_mark_scan_incomplete(ctx, reason);
        return CL_EPARSE;
    }
    if (length != 0 && cli_writen(fd, buffer, length) != length) {
        cli_mark_scan_incomplete(ctx, "DMG reconstructed output could not be written completely");
        return CL_EWRITE;
    }

    *written += length;
    return CL_CLEAN;
}

int cli_scandmg(cli_ctx *ctx)
{
    struct dmg_koly_block hdr;
    struct dmg_xml_scan_state xml_state;
    struct msxml_ctx mxctx;
    fmap_t *xml_map;
    int ret;
    size_t maplen;
    size_t pos = 0;
    char *dirname;
    unsigned int file = 0;
    struct dmg_mish_with_stripes *mish_list;
    static const struct key_entry dmg_xml_keys[] = {
        {"data", "DMGData", MSXML_SCAN_B64}};

    if (!ctx || !ctx->fmap) {
        cli_errmsg("cli_scandmg: Invalid context\n");
        return CL_ENULLARG;
    }

    maplen = ctx->fmap->len;
    if (maplen <= 512) {
        cli_dbgmsg("cli_scandmg: DMG smaller than DMG koly block!\n");
        cli_mark_scan_incomplete(ctx, "DMG input is too small to contain a complete koly trailer");
        return CL_EPARSE;
    }
    pos = maplen - 512;

    /* Grab koly block. */
    if (fmap_readn(ctx->fmap, &hdr, pos, sizeof(hdr)) != sizeof(hdr)) {
        cli_dbgmsg("cli_scandmg: Invalid DMG trailer block\n");
        cli_mark_scan_incomplete(ctx, "DMG trailer block is incomplete");
        return CL_EPARSE;
    }

    hdr.magic = be32_to_host(hdr.magic);
    if (hdr.magic != 0x6b6f6c79) {
        cli_dbgmsg("cli_scandmg: No koly magic, %8x\n", hdr.magic);
        cli_mark_scan_incomplete(ctx, "DMG trailer block has invalid magic");
        return CL_EPARSE;
    }
    cli_dbgmsg("cli_scandmg: Found koly block @ %zu\n", pos);

    hdr.dataForkOffset = be64_to_host(hdr.dataForkOffset);
    hdr.dataForkLength = be64_to_host(hdr.dataForkLength);
    cli_dbgmsg("cli_scandmg: data offset " STDu64 " len " STDu64 "\n", hdr.dataForkOffset, hdr.dataForkLength);
    if (hdr.dataForkOffset > (uint64_t)maplen ||
        hdr.dataForkLength > (uint64_t)maplen - hdr.dataForkOffset) {
        cli_mark_scan_incomplete(ctx, "DMG data fork is outside the input map");
        return CL_EPARSE;
    }

    hdr.segment      = be32_to_host(hdr.segment);
    hdr.segmentCount = be32_to_host(hdr.segmentCount);
    if (hdr.segmentCount > 1 || hdr.segment > 1) {
        cli_mark_scan_incomplete(ctx, "multi-segment DMG images require data from another file");
        return CL_EPARSE;
    }

    hdr.xmlOffset = be64_to_host(hdr.xmlOffset);
    hdr.xmlLength = be64_to_host(hdr.xmlLength);
    /*
     * Keep the XML range check in subtraction form. The root resource fork is
     * streamed through an fmap view, so its length is not an allocation limit.
     */
    if (hdr.xmlOffset > (uint64_t)maplen || hdr.xmlLength > (uint64_t)maplen ||
        hdr.xmlOffset > (uint64_t)maplen - hdr.xmlLength) {
        cli_dbgmsg("cli_scandmg: XML out of range for this file\n");
        cli_mark_scan_incomplete(ctx, "DMG XML resource fork is outside the input map");
        return CL_EPARSE;
    }
    cli_dbgmsg("cli_scandmg: XML offset " STDu64 " len " STDu64 "\n", hdr.xmlOffset, hdr.xmlLength);
    if (hdr.xmlLength == 0) {
        cli_dbgmsg("cli_scandmg: Embedded XML length is zero.\n");
        cli_mark_scan_incomplete(ctx, "DMG XML resource fork is empty");
        return CL_EPARSE;
    }

    if (!(dirname = cli_gentemp_with_prefix(ctx->this_layer_tmpdir, "dmg-tmp"))) {
        cli_mark_scan_incomplete(ctx, "DMG temporary directory could not be created");
        return CL_ETMPDIR;
    }
    if (mkdir(dirname, 0700)) {
        cli_errmsg("cli_scandmg: Cannot create temporary directory %s\n", dirname);
        cli_mark_scan_incomplete(ctx, "DMG temporary directory could not be created");
        free(dirname);
        return CL_ETMPDIR;
    }
    cli_dbgmsg("cli_scandmg: Extracting into %s\n", dirname);

    /* Dump XML to tempfile, if requested, using bounded writes. */
    if (ctx->engine->keeptmp && !(ctx->engine->engine_options & ENGINE_OPTIONS_FORCE_TO_DISK)) {
        ret = dmg_extract_xml(ctx, dirname, &hdr);
        if (ret != CL_SUCCESS) {
            if (!ctx->engine->keeptmp)
                cli_rmdirs(dirname);
            free(dirname);
            return ret;
        }
    }

    /* Always scan the complete XML range with the outer raw matchers. */
    ret = cli_magic_scan_nested_fmap_type(ctx->fmap, (size_t)hdr.xmlOffset, (size_t)hdr.xmlLength,
                                          ctx, CL_TYPE_ANY, NULL, LAYER_ATTRIBUTES_NONE);
    if (ret != CL_CLEAN) {
        cli_dbgmsg("cli_scandmg: retcode from scanning TOC xml: %s\n", cl_strerror(ret));
        if (ret != CL_VIRUS)
            cli_mark_scan_incomplete(ctx, "DMG XML nested scan did not complete successfully");
        if (!ctx->engine->keeptmp)
            cli_rmdirs(dirname);
        free(dirname);
        return ret;
    }

    /*
     * Parse the same range through the bounded SAX reader. The generic MSXML
     * decoder writes each <data> value into a quota-accounted spool, then the
     * callback reads one completed mish metadata block at a time.
     */
    xml_map = fmap_duplicate(ctx->fmap, (size_t)hdr.xmlOffset, (size_t)hdr.xmlLength, "toc.xml");
    if (!xml_map) {
        cli_mark_scan_incomplete(ctx, "DMG XML fmap view could not be created");
        if (!ctx->engine->keeptmp)
            cli_rmdirs(dirname);
        free(dirname);
        return CL_EMAP;
    }

    memset(&xml_state, 0, sizeof(xml_state));
    memset(&mxctx, 0, sizeof(mxctx));
    mxctx.decoded_cb       = dmg_mish_decoded_cb;
    mxctx.decoded_max_size = DMG_XML_PARSE_MAX_SIZE;
    mxctx.scan_data        = &xml_state;
    ret                    = cli_msxml_parse_document_streaming(ctx, xml_map, dmg_xml_keys,
                                                                sizeof(dmg_xml_keys) / sizeof(dmg_xml_keys[0]),
                                                                MSXML_FLAG_FAIL_INCOMPLETE, &mxctx);
    free_duplicate_fmap(xml_map);

    mish_list = xml_state.mish_list;
    if (ret == CL_CLEAN && mish_list == NULL) {
        cli_mark_scan_incomplete(ctx, "DMG XML did not provide any decodable blkx metadata");
        ret = CL_EPARSE;
    }

    /* Reconstruct and scan each parsed partition. */
    while (ret == CL_CLEAN && mish_list != NULL) {
        struct dmg_mish_with_stripes *next = mish_list->next;

        ret = dmg_handle_mish(ctx, file++, dirname, hdr.dataForkOffset,
                              hdr.dataForkLength, mish_list);
        free(mish_list->mish);
        free(mish_list);
        mish_list = next;
    }

    /* Free parsed metadata that was not reached after a failure or detection. */
    while (mish_list != NULL) {
        struct dmg_mish_with_stripes *next = mish_list->next;

        free(mish_list->mish);
        free(mish_list);
        mish_list = next;
    }

    if (!ctx->engine->keeptmp)
        cli_rmdirs(dirname);
    free(dirname);
    return ret;
}
/* Validate one completed, bounded decoded blkx metadata spool. Ownership of
 * decoded transfers to this function and is released on every failure. */
static int dmg_parse_mish_bytes(cli_ctx *ctx, unsigned int *mishblocknum, uint8_t *decoded,
                                size_t decoded_len, struct dmg_mish_with_stripes *mish_set)
{
    const uint8_t mish_magic[4] = {0x6d, 0x69, 0x73, 0x68};
    uint64_t expected_len;
    uint32_t i;
    unsigned int end_count = 0;

    if (!ctx || !mishblocknum || !decoded || !mish_set)
        return CL_ENULLARG;

    mish_set->mish    = NULL;
    mish_set->stripes = NULL;
    mish_set->next    = NULL;
    (*mishblocknum)++;

    dmg_parsemsg("dmg_parse_mish_bytes: decoded block %u is %lu bytes\n",
                 *mishblocknum, (unsigned long)decoded_len);
    if (decoded_len < sizeof(struct dmg_mish_block)) {
        cli_dbgmsg("dmg_parse_mish_bytes: block %u too short for valid mish block\n", *mishblocknum);
        free(decoded);
        return CL_EFORMAT;
    }
    if (memcmp(decoded, mish_magic, sizeof(mish_magic)) != 0) {
        cli_dbgmsg("dmg_parse_mish_bytes: block %u does not have mish magic\n", *mishblocknum);
        free(decoded);
        return CL_EFORMAT;
    }

    mish_set->mish                 = (struct dmg_mish_block *)decoded;
    mish_set->mish->startSector    = be64_to_host(mish_set->mish->startSector);
    mish_set->mish->sectorCount    = be64_to_host(mish_set->mish->sectorCount);
    mish_set->mish->dataOffset     = be64_to_host(mish_set->mish->dataOffset);
    mish_set->mish->blockDataCount = be32_to_host(mish_set->mish->blockDataCount);
    if (mish_set->mish->blockDataCount == 0) {
        cli_dbgmsg("dmg_parse_mish_bytes: block %u has no stripe records\n", *mishblocknum);
        free(decoded);
        mish_set->mish = NULL;
        return CL_EFORMAT;
    }

    cli_dbgmsg("dmg_parse_mish_bytes: startSector = " STDu64 " sectorCount = " STDu64
               " dataOffset = " STDu64 " stripeCount = " STDu32 "\n",
               mish_set->mish->startSector, mish_set->mish->sectorCount,
               mish_set->mish->dataOffset, mish_set->mish->blockDataCount);

    expected_len = (uint64_t)sizeof(struct dmg_mish_block) +
                   (uint64_t)mish_set->mish->blockDataCount * (uint64_t)sizeof(struct dmg_block_data);
    if ((uint64_t)decoded_len < expected_len) {
        cli_dbgmsg("dmg_parse_mish_bytes: block %u is too small\n", *mishblocknum);
        free(decoded);
        mish_set->mish = NULL;
        return CL_EFORMAT;
    }
    if ((uint64_t)decoded_len > expected_len) {
        cli_dbgmsg("dmg_parse_mish_bytes: block %u contains trailing decoded metadata\n", *mishblocknum);
        free(decoded);
        mish_set->mish = NULL;
        return CL_EFORMAT;
    }

    mish_set->stripes = (struct dmg_block_data *)(decoded + sizeof(struct dmg_mish_block));
    for (i = 0; i < mish_set->mish->blockDataCount; i++) {
        struct dmg_block_data *stripe = &mish_set->stripes[i];
        uint32_t type                 = be32_to_host(stripe->type);

        if ((i & 0xfffU) == 0) {
            int time_ret = cli_checktimelimit(ctx);

            if (time_ret != CL_CLEAN) {
                cli_mark_scan_incomplete(ctx, "DMG blkx terminator validation reached the configured time limit");
                free(decoded);
                mish_set->mish    = NULL;
                mish_set->stripes = NULL;
                return time_ret;
            }
        }
        if (type != DMG_STRIPE_END)
            continue;

        end_count++;
        if (end_count != 1 || i + 1 != mish_set->mish->blockDataCount ||
            be64_to_host(stripe->sectorCount) != 0 || be64_to_host(stripe->dataLength) != 0) {
            cli_dbgmsg("dmg_parse_mish_bytes: block %u has an invalid or non-terminal END stripe\n", *mishblocknum);
            free(decoded);
            mish_set->mish    = NULL;
            mish_set->stripes = NULL;
            return CL_EFORMAT;
        }
    }

    if (end_count != 1) {
        cli_dbgmsg("dmg_parse_mish_bytes: block %u has no terminal END stripe\n", *mishblocknum);
        free(decoded);
        mish_set->mish    = NULL;
        mish_set->stripes = NULL;
        return CL_EFORMAT;
    }

    return CL_CLEAN;
}

static int dmg_decode_mish_fd(cli_ctx *ctx, unsigned int *mishblocknum, int fd,
                              struct dmg_mish_with_stripes *mish_set)
{
    STATBUF statbuf;
    uint8_t *decoded;
    size_t decoded_len;
    size_t nread;

    if (!ctx || !mishblocknum || fd < 0 || !mish_set)
        return CL_ENULLARG;
    if (FSTAT(fd, &statbuf) == -1 || statbuf.st_size < 0) {
        cli_mark_scan_incomplete(ctx, "DMG decoded mish spool could not be sized");
        return CL_ESTAT;
    }
    if (statbuf.st_size == 0 || (uint64_t)statbuf.st_size > DMG_XML_PARSE_MAX_SIZE) {
        cli_mark_scan_incomplete(ctx, "DMG decoded mish metadata exceeds its 64 MiB per-block limit");
        return CL_EFORMAT;
    }

    decoded_len = (size_t)statbuf.st_size;
    decoded     = cli_max_malloc(decoded_len);
    if (!decoded) {
        cli_mark_scan_incomplete(ctx, "DMG decoded mish metadata could not be allocated");
        return CL_EMEM;
    }

    if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
        free(decoded);
        cli_mark_scan_incomplete(ctx, "DMG decoded mish spool could not be rewound");
        return CL_ESEEK;
    }
    nread = cli_readn(fd, decoded, decoded_len);
    if (nread == (size_t)-1 || nread != decoded_len) {
        free(decoded);
        cli_mark_scan_incomplete(ctx, "DMG decoded mish spool could not be read completely");
        return CL_EREAD;
    }

    return dmg_parse_mish_bytes(ctx, mishblocknum, decoded, decoded_len, mish_set);
}

static cl_error_t dmg_mish_decoded_cb(int fd, const char *filepath, cli_ctx *ctx, void *cbdata)
{
    struct dmg_xml_scan_state *state = cbdata;
    struct dmg_mish_with_stripes *mish_set;
    cl_error_t ret;

    UNUSEDPARAM(filepath);

    if (!state || !ctx || fd < 0)
        return CL_ENULLARG;

    mish_set = calloc(1, sizeof(*mish_set));
    if (!mish_set) {
        cli_mark_scan_incomplete(ctx, "DMG mish metadata could not be allocated");
        return CL_EMEM;
    }

    ret = dmg_decode_mish_fd(ctx, &state->mishblocknum, fd, mish_set);
    if (ret == CL_EFORMAT) {
        cli_mark_scan_incomplete(ctx, "DMG blkx mish metadata is malformed or unsupported");
        free(mish_set);
        return CL_EPARSE;
    }
    if (ret != CL_CLEAN) {
        free(mish_set);
        return ret;
    }

    if (state->mish_list_tail) {
        state->mish_list_tail->next = mish_set;
        state->mish_list_tail       = mish_set;
    } else {
        state->mish_list      = mish_set;
        state->mish_list_tail = mish_set;
    }
    return CL_SUCCESS;
}
static int cmp_mish_stripes(const void *stripe_a, const void *stripe_b)
{
    const struct dmg_block_data *a = stripe_a, *b = stripe_b;
    if (a->startSector < b->startSector)
        return -1;
    if (a->startSector > b->startSector)
        return 1;
    return 0;
}

/* Safely track sector sizes for output estimate */
static int dmg_track_sectors(uint64_t *total, uint8_t *data_to_write,
                             uint32_t stripeNum, uint32_t stripeType, uint64_t stripeCount)
{
    int ret = CL_CLEAN, usable = 0;

    switch (stripeType) {
        case DMG_STRIPE_STORED:
        case DMG_STRIPE_ADC:
        case DMG_STRIPE_DEFLATE:
        case DMG_STRIPE_BZ:
            if (stripeCount == 0) {
                cli_dbgmsg("dmg_track_sectors: data stripe " STDu32 " declares zero sectors\n", stripeNum);
                return CL_EFORMAT;
            }
            *data_to_write = 1;
            usable         = 1;
            break;
        case DMG_STRIPE_EMPTY:
        case DMG_STRIPE_ZEROES:
            /* Usable, but only zeroes is not worth scanning on its own */
            usable = 1;
            break;
        case DMG_STRIPE_SKIP:
        case DMG_STRIPE_END:
            if (stripeCount != 0) {
                cli_dbgmsg("dmg_track_sectors: control stripe " STDu32 " declares data sectors\n", stripeNum);
                return CL_EFORMAT;
            }
            break;
        default:
            if (stripeCount) {
                cli_dbgmsg("dmg_track_sectors: unsupported non-empty stripe " STDu32 "\n", stripeNum);
                return CL_EFORMAT;
            } else {
                cli_dbgmsg("dmg_track_sectors: unknown type on empty stripe " STDu32 "\n", stripeNum);
            }
            break;
    }

    if (usable) {
        if (stripeCount > UINT64_MAX - *total) {
            cli_dbgmsg("dmg_track_sectors: *total would wrap uint64, suspicious\n");
            ret = CL_EFORMAT;
        } else {
            *total += stripeCount;
        }
    }

    return ret;
}

/* Stripe handling: zero block (type 0x0 or 0x2) */
static int dmg_stripe_zeroes(cli_ctx *ctx, int fd, uint32_t index, struct dmg_mish_with_stripes *mish_set)
{
    int ret;
    uint64_t expected;
    uint64_t written = 0;
    uint8_t obuf[BUFSIZ];

    cli_dbgmsg("dmg_stripe_zeroes: stripe " STDu32 "\n", index);
    ret = dmg_expected_output(ctx, index, mish_set->stripes[index].sectorCount, &expected);
    if (ret != CL_CLEAN)
        return ret;

    memset(obuf, 0, sizeof(obuf));
    while (written < expected) {
        size_t next_write = (size_t)MIN(expected - written, (uint64_t)sizeof(obuf));
        ret               = cli_checktimelimit(ctx);
        if (ret != CL_CLEAN) {
            cli_mark_scan_incomplete(ctx, "DMG zero stripe reached the configured time limit");
            return ret;
        }
        ret = dmg_write_checked(ctx, fd, obuf, next_write, &written, expected,
                                "DMG zero stripe exceeded its declared output size");
        if (ret != CL_CLEAN) {
            if (ret == CL_EWRITE)
                cli_errmsg("dmg_stripe_zeroes: error writing bytes to file (out of disk space?)\n");
            return ret;
        }
    }
    return CL_CLEAN;
}

/* Stripe handling: stored block (type 0x1) */
static int dmg_stripe_store(cli_ctx *ctx, int fd, uint32_t index, struct dmg_mish_with_stripes *mish_set)
{
    const uint8_t *input;
    uint64_t off       = mish_set->stripes[index].dataOffset;
    uint64_t remaining = mish_set->stripes[index].dataLength;
    uint64_t expected;
    uint64_t written = 0;
    int ret;

    cli_dbgmsg("dmg_stripe_store: stripe " STDu32 "\n", index);
    ret = dmg_expected_output(ctx, index, mish_set->stripes[index].sectorCount, &expected);
    if (ret != CL_CLEAN)
        return ret;
    if (remaining != expected) {
        cli_mark_scan_incomplete(ctx, "DMG stored stripe length does not match its declared sector count");
        return CL_EPARSE;
    }

    while (remaining != 0) {
        size_t window_len;

        ret = cli_checktimelimit(ctx);
        if (ret != CL_CLEAN) {
            cli_mark_scan_incomplete(ctx, "DMG stored stripe reached the configured time limit");
            return ret;
        }

        input = dmg_map_window(ctx, off, remaining, &window_len);
        if (!input || window_len == 0) {
            cli_mark_scan_incomplete(ctx, "DMG stored stripe could not be read completely");
            return CL_EPARSE;
        }

        ret = dmg_write_checked(ctx, fd, input, window_len, &written, expected,
                                "DMG stored stripe exceeded its declared output size");
        if (ret != CL_CLEAN) {
            if (ret == CL_EWRITE)
                cli_errmsg("dmg_stripe_store: error writing bytes to file (out of disk space?)\n");
            return ret;
        }
        off += window_len;
        remaining -= window_len;
    }
    return CL_CLEAN;
}

/* Stripe handling: ADC block (type 0x80000004) */
static int dmg_stripe_adc(cli_ctx *ctx, int fd, uint32_t index, struct dmg_mish_with_stripes *mish_set)
{
    int adcret;
    int ret;
    adc_stream strm;
    uint64_t off       = mish_set->stripes[index].dataOffset;
    uint64_t remaining = mish_set->stripes[index].dataLength;
    uint64_t expected_len;
    uint64_t size_so_far = 0;
    uint8_t obuf[BUFSIZ];

    ret = dmg_expected_output(ctx, index, mish_set->stripes[index].sectorCount, &expected_len);
    if (ret != CL_CLEAN)
        return ret;
    cli_dbgmsg("dmg_stripe_adc: stripe " STDu32 " initial len " STDu64 " expected len " STDu64 "\n",
               index, remaining, expected_len);
    if (remaining == 0) {
        cli_mark_scan_incomplete(ctx, "DMG ADC stripe has no compressed stream");
        return CL_EPARSE;
    }

    memset(&strm, 0, sizeof(strm));
    adcret = adc_decompressInit(&strm);
    if (adcret != ADC_OK) {
        cli_warnmsg("dmg_stripe_adc: adc_decompressInit failed\n");
        if (adcret == ADC_MEM_ERROR) {
            cli_mark_scan_incomplete(ctx, "DMG ADC decompressor could not be allocated");
            return CL_EMEM;
        }
        cli_mark_scan_incomplete(ctx, "DMG ADC decompressor could not be initialized");
        return CL_EPARSE;
    }

    ret = CL_CLEAN;
    for (;;) {
        size_t before_in;
        size_t produced;
        uint16_t before_state;

        ret = cli_checktimelimit(ctx);
        if (ret != CL_CLEAN) {
            cli_mark_scan_incomplete(ctx, "DMG ADC stripe reached the configured time limit");
            break;
        }

        if (strm.avail_in == 0 && remaining != 0) {
            size_t window_len;
            const uint8_t *input = dmg_map_window(ctx, off, remaining, &window_len);
            if (!input || window_len == 0) {
                cli_mark_scan_incomplete(ctx, "DMG ADC compressed stream could not be read completely");
                ret = CL_EPARSE;
                break;
            }
            strm.next_in  = (uint8_t *)input;
            strm.avail_in = window_len;
            off += window_len;
            remaining -= window_len;
        }

        strm.next_out  = obuf;
        strm.avail_out = sizeof(obuf);
        before_in      = strm.avail_in;
        before_state   = strm.state;
        adcret         = adc_decompress(&strm);
        produced       = sizeof(obuf) - strm.avail_out;

        if (produced != 0) {
            ret = dmg_write_checked(ctx, fd, obuf, produced, &size_so_far, expected_len,
                                    "DMG ADC stripe exceeded its declared output size");
            if (ret != CL_CLEAN) {
                if (ret == CL_EWRITE)
                    cli_errmsg("dmg_stripe_adc: failed write to output file\n");
                break;
            }
        }

        if (adcret == ADC_STREAM_END) {
            if (remaining != 0 || strm.avail_in != 0) {
                cli_mark_scan_incomplete(ctx, "DMG ADC stripe has trailing compressed data");
                ret = CL_EPARSE;
            } else if (size_so_far != expected_len) {
                cli_mark_scan_incomplete(ctx, "DMG ADC stripe output does not match its declared sector count");
                ret = CL_EPARSE;
            }
            break;
        }
        if (adcret != ADC_OK) {
            cli_dbgmsg("dmg_stripe_adc: after writing " STDu64 " bytes, got error %d decompressing stripe " STDu32 "\n",
                       size_so_far, adcret, index);
            cli_mark_scan_incomplete(ctx, "DMG ADC stripe did not reach a complete decoder state");
            ret = CL_EPARSE;
            break;
        }
        if (before_in == strm.avail_in && produced == 0 && before_state == strm.state) {
            cli_mark_scan_incomplete(ctx, "DMG ADC decompressor made no progress");
            ret = CL_EPARSE;
            break;
        }
    }

    adc_decompressEnd(&strm);
    cli_dbgmsg("dmg_stripe_adc: stripe " STDu32 " actual len " STDu64 " expected len " STDu64 "\n",
               index, size_so_far, expected_len);
    return ret;
}

/* Stripe handling: deflate block (type 0x80000005) */
static int dmg_stripe_inflate(cli_ctx *ctx, int fd, uint32_t index, struct dmg_mish_with_stripes *mish_set)
{
    int zstat;
    int ret;
    z_stream strm;
    uint64_t off         = mish_set->stripes[index].dataOffset;
    uint64_t remaining   = mish_set->stripes[index].dataLength;
    uint64_t size_so_far = 0;
    uint64_t expected_len;
    uint8_t obuf[BUFSIZ];

    cli_dbgmsg("dmg_stripe_inflate: stripe " STDu32 "\n", index);
    ret = dmg_expected_output(ctx, index, mish_set->stripes[index].sectorCount, &expected_len);
    if (ret != CL_CLEAN)
        return ret;
    if (remaining == 0) {
        cli_mark_scan_incomplete(ctx, "DMG deflate stripe has no compressed stream");
        return CL_EPARSE;
    }

    memset(&strm, 0, sizeof(strm));
    zstat = inflateInit(&strm);
    if (zstat != Z_OK) {
        cli_warnmsg("dmg_stripe_inflate: inflateInit failed\n");
        if (zstat == Z_MEM_ERROR) {
            cli_mark_scan_incomplete(ctx, "DMG deflate decompressor could not be allocated");
            return CL_EMEM;
        }
        cli_mark_scan_incomplete(ctx, "DMG deflate decompressor could not be initialized");
        return CL_EPARSE;
    }

    ret = CL_CLEAN;
    for (;;) {
        uInt before_in;
        size_t produced;

        ret = cli_checktimelimit(ctx);
        if (ret != CL_CLEAN) {
            cli_mark_scan_incomplete(ctx, "DMG deflate stripe reached the configured time limit");
            break;
        }

        if (strm.avail_in == 0 && remaining != 0) {
            size_t window_len;
            const uint8_t *input = dmg_map_window(ctx, off, remaining, &window_len);
            if (!input || window_len == 0) {
                cli_mark_scan_incomplete(ctx, "DMG deflate stream could not be read completely");
                ret = CL_EPARSE;
                break;
            }
            strm.next_in  = (Bytef *)input;
            strm.avail_in = (uInt)window_len;
            off += window_len;
            remaining -= window_len;
        }

        strm.next_out  = obuf;
        strm.avail_out = sizeof(obuf);
        before_in      = strm.avail_in;
        zstat          = inflate(&strm, Z_NO_FLUSH); /* zlib */
        produced       = sizeof(obuf) - strm.avail_out;

        if (produced != 0) {
            ret = dmg_write_checked(ctx, fd, obuf, produced, &size_so_far, expected_len,
                                    "DMG deflate stripe exceeded its declared output size");
            if (ret != CL_CLEAN) {
                if (ret == CL_EWRITE)
                    cli_errmsg("dmg_stripe_inflate: failed write to output file\n");
                break;
            }
        }

        if (zstat == Z_STREAM_END) {
            if (remaining != 0 || strm.avail_in != 0) {
                cli_mark_scan_incomplete(ctx, "DMG deflate stripe has trailing compressed data");
                ret = CL_EPARSE;
            } else if (size_so_far != expected_len) {
                cli_mark_scan_incomplete(ctx, "DMG deflate stripe output does not match its declared sector count");
                ret = CL_EPARSE;
            }
            break;
        }
        if (zstat != Z_OK) {
            if (strm.msg)
                cli_dbgmsg("dmg_stripe_inflate: after writing " STDu64 " bytes, got error \"%s\" inflating stripe " STDu32 "\n",
                           size_so_far, strm.msg, index);
            else
                cli_dbgmsg("dmg_stripe_inflate: after writing " STDu64 " bytes, got error %d inflating stripe " STDu32 "\n",
                           size_so_far, zstat, index);
            cli_mark_scan_incomplete(ctx, "DMG deflate stripe did not reach stream completion");
            ret = CL_EPARSE;
            break;
        }
        if (before_in == strm.avail_in && produced == 0) {
            cli_mark_scan_incomplete(ctx, "DMG deflate decompressor made no progress");
            ret = CL_EPARSE;
            break;
        }
    }

    inflateEnd(&strm);
    return ret;
}

/* Stripe handling: bzip block (type 0x80000006) */
static int dmg_stripe_bzip(cli_ctx *ctx, int fd, uint32_t index, struct dmg_mish_with_stripes *mish_set)
{
    int ret;
    uint64_t off         = mish_set->stripes[index].dataOffset;
    uint64_t remaining   = mish_set->stripes[index].dataLength;
    uint64_t size_so_far = 0;
    uint64_t expected_len;
    int rc;
    bz_stream strm;
    uint8_t obuf[BUFSIZ];

    ret = dmg_expected_output(ctx, index, mish_set->stripes[index].sectorCount, &expected_len);
    if (ret != CL_CLEAN)
        return ret;
    cli_dbgmsg("dmg_stripe_bzip: stripe " STDu32 " initial len " STDu64 " expected len " STDu64 "\n",
               index, remaining, expected_len);
    if (remaining == 0) {
        cli_mark_scan_incomplete(ctx, "DMG bzip2 stripe has no compressed stream");
        return CL_EPARSE;
    }

    memset(&strm, 0, sizeof(strm));
    rc = BZ2_bzDecompressInit(&strm, 0, 0);
    if (rc != BZ_OK) {
        cli_dbgmsg("dmg_stripe_bzip: bzDecompressInit failed\n");
        if (rc == BZ_MEM_ERROR) {
            cli_mark_scan_incomplete(ctx, "DMG bzip2 decompressor could not be allocated");
            return CL_EMEM;
        }
        cli_mark_scan_incomplete(ctx, "DMG bzip2 decompressor could not be initialized");
        return CL_EPARSE;
    }

    ret = CL_CLEAN;
    for (;;) {
        unsigned int before_in;
        size_t produced;

        ret = cli_checktimelimit(ctx);
        if (ret != CL_CLEAN) {
            cli_mark_scan_incomplete(ctx, "DMG bzip2 stripe reached the configured time limit");
            break;
        }

        if (strm.avail_in == 0 && remaining != 0) {
            size_t window_len;
            const uint8_t *input = dmg_map_window(ctx, off, remaining, &window_len);
            if (!input || window_len == 0) {
                cli_mark_scan_incomplete(ctx, "DMG bzip2 stream could not be read completely");
                ret = CL_EPARSE;
                break;
            }
            strm.next_in  = (char *)input;
            strm.avail_in = (unsigned int)window_len;
            off += window_len;
            remaining -= window_len;
        }

        strm.next_out  = (char *)obuf;
        strm.avail_out = sizeof(obuf);
        before_in      = strm.avail_in;
        rc             = BZ2_bzDecompress(&strm);
        produced       = sizeof(obuf) - strm.avail_out;

        if (produced != 0) {
            ret = dmg_write_checked(ctx, fd, obuf, produced, &size_so_far, expected_len,
                                    "DMG bzip2 stripe exceeded its declared output size");
            if (ret != CL_CLEAN) {
                if (ret == CL_EWRITE)
                    cli_dbgmsg("dmg_stripe_bzip: error writing to tmpfile\n");
                break;
            }
        }

        if (rc == BZ_STREAM_END) {
            if (remaining != 0 || strm.avail_in != 0) {
                cli_mark_scan_incomplete(ctx, "DMG bzip2 stripe has trailing compressed data");
                ret = CL_EPARSE;
            } else if (size_so_far != expected_len) {
                cli_mark_scan_incomplete(ctx, "DMG bzip2 stripe output does not match its declared sector count");
                ret = CL_EPARSE;
            }
            break;
        }
        if (rc != BZ_OK) {
            cli_dbgmsg("dmg_stripe_bzip: decompress error: %d\n", rc);
            cli_mark_scan_incomplete(ctx, "DMG bzip2 stripe did not reach stream completion");
            ret = CL_EPARSE;
            break;
        }
        if (before_in == strm.avail_in && produced == 0) {
            cli_mark_scan_incomplete(ctx, "DMG bzip2 decompressor made no progress");
            ret = CL_EPARSE;
            break;
        }
    }

    BZ2_bzDecompressEnd(&strm);
    return ret;
}

/* Given mish data, reconstruct the partition details */
static int dmg_handle_mish(cli_ctx *ctx, unsigned int mishblocknum, char *dir,
                           uint64_t dataForkOffset, uint64_t dataForkLength,
                           struct dmg_mish_with_stripes *mish_set)
{
    struct dmg_block_data *blocklist = mish_set->stripes;
    uint64_t totalSectors            = 0;
    uint64_t outputEnd               = 0;
    uint64_t sourceBase;
    uint32_t i;
    uint64_t projected_size;
    uint64_t temporary_reserved = 0;
    int ret                     = CL_CLEAN, ofd;
    uint8_t sorted = 1, writeable_data = 0;
    char outfile[PATH_MAX + 1];

    /* First loop, fix endian-ness and check if already sorted */
    for (i = 0; i < mish_set->mish->blockDataCount; i++) {
        blocklist[i].type = be32_to_host(blocklist[i].type);
        // blocklist[i].reserved = be32_to_host(blocklist[i].reserved);
        blocklist[i].startSector = be64_to_host(blocklist[i].startSector);
        blocklist[i].sectorCount = be64_to_host(blocklist[i].sectorCount);
        blocklist[i].dataOffset  = be64_to_host(blocklist[i].dataOffset);
        blocklist[i].dataLength  = be64_to_host(blocklist[i].dataLength);
        cli_dbgmsg("mish %u stripe " STDu32 " type " STDx32 " start " STDu64
                   " count " STDu64 " source " STDu64 " length " STDu64 "\n",
                   mishblocknum, i, blocklist[i].type, blocklist[i].startSector, blocklist[i].sectorCount,
                   blocklist[i].dataOffset, blocklist[i].dataLength);
        /* UDIF chunk offsets are relative to both the koly data-fork offset
         * and this mish block's dataOffset. Resolve the native file coordinate
         * once, using subtraction-form bounds against the declared data fork.
         */
        if (mish_set->mish->dataOffset > dataForkLength ||
            blocklist[i].dataOffset > dataForkLength - mish_set->mish->dataOffset) {
            cli_mark_scan_incomplete(ctx, "DMG stripe source base is outside the declared data fork");
            return CL_EPARSE;
        }
        sourceBase = mish_set->mish->dataOffset + blocklist[i].dataOffset;
        if (blocklist[i].dataLength > dataForkLength - sourceBase ||
            dataForkOffset > UINT64_MAX - sourceBase) {
            cli_mark_scan_incomplete(ctx, "DMG stripe data is outside the declared data fork");
            return CL_EPARSE;
        }
        blocklist[i].dataOffset = dataForkOffset + sourceBase;
        if ((blocklist[i].type == DMG_STRIPE_SKIP || blocklist[i].type == DMG_STRIPE_END ||
             (blocklist[i].type != DMG_STRIPE_EMPTY && blocklist[i].type != DMG_STRIPE_ZEROES &&
              blocklist[i].type != DMG_STRIPE_STORED && blocklist[i].type != DMG_STRIPE_ADC &&
              blocklist[i].type != DMG_STRIPE_DEFLATE && blocklist[i].type != DMG_STRIPE_BZ)) &&
            blocklist[i].dataLength != 0) {
            cli_mark_scan_incomplete(ctx, "DMG unsupported or control stripe references uninspected data");
            return CL_EPARSE;
        }
        if ((i > 0) && sorted && (blocklist[i].startSector < blocklist[i - 1].startSector)) {
            cli_dbgmsg("dmg_handle_mish: stripes not in order, will have to sort\n");
            sorted = 0;
        }
        if (dmg_track_sectors(&totalSectors, &writeable_data, i, blocklist[i].type, blocklist[i].sectorCount)) {
            /* reason was logged from dmg_track_sector_count */
            cli_mark_scan_incomplete(ctx, "DMG contains invalid or unsupported non-empty stripe metadata");
            return CL_EPARSE;
        }
    }

    if (!sorted) {
        cli_qsort(blocklist, mish_set->mish->blockDataCount, sizeof(struct dmg_block_data), cmp_mish_stripes);
    }
    cli_dbgmsg("dmg_handle_mish: stripes in order!\n");

    /* A blkx describes one reconstructed partition. Reject gaps, overlaps,
     * and ranges outside the mish sector span instead of concatenating chunks
     * into a different byte stream and scanning it as if it were complete.
     */
    for (i = 0; i < mish_set->mish->blockDataCount; i++) {
        if (blocklist[i].type == DMG_STRIPE_SKIP || blocklist[i].type == DMG_STRIPE_END)
            continue;
        if (outputEnd > mish_set->mish->sectorCount ||
            blocklist[i].startSector != outputEnd ||
            blocklist[i].sectorCount > mish_set->mish->sectorCount - outputEnd) {
            cli_mark_scan_incomplete(ctx, "DMG stripe geometry has a gap, overlap, or out-of-range sector span");
            return CL_EPARSE;
        }
        outputEnd += blocklist[i].sectorCount;
    }
    if (outputEnd != mish_set->mish->sectorCount) {
        cli_mark_scan_incomplete(ctx, "DMG stripe geometry does not cover the declared mish sector span");
        return CL_EPARSE;
    }

    /* Size checks */
    if ((writeable_data == 0) || (totalSectors == 0)) {
        cli_dbgmsg("dmg_handle_mish: no data to output\n");
        return CL_CLEAN;
    } else if (totalSectors > (UINT64_MAX / DMG_SECTOR_SIZE)) {
        cli_warnmsg("dmg_handle_mish: mish block %u output size overflowed\n", mishblocknum);
        cli_mark_scan_incomplete(ctx, "DMG reconstructed partition size overflowed");
        return CL_EPARSE;
    }
    projected_size = totalSectors * DMG_SECTOR_SIZE;
    ret            = cli_checklimits("cli_scandmg", ctx, projected_size, 0, 0);
    if (ret != CL_CLEAN) {
        /* limits exceeded */
        cli_dbgmsg("dmg_handle_mish: skipping block %u, limits exceeded\n", mishblocknum);
        cli_mark_scan_incomplete(ctx, "DMG reconstructed partition exceeds configured scan limits");
        return ret;
    }

    /* Keep the reconstructed partition charged while its nested scan runs.
     * This prevents a large DMG member from bypassing the shared temporary
     * storage budget merely because it is written incrementally. */
    ret = cli_scan_reserve_temporary(ctx, projected_size);
    if (ret != CL_CLEAN) {
        cli_mark_scan_incomplete(ctx, "DMG reconstructed partition exceeds temporary storage limits");
        return ret;
    }
    temporary_reserved = projected_size;

    /* Prepare for file */
    snprintf(outfile, sizeof(outfile) - 1, "%s" PATHSEP "dmg%02u", dir, mishblocknum);
    outfile[sizeof(outfile) - 1] = '\0';
    ofd                          = open(outfile, O_RDWR | O_CREAT | O_EXCL | O_TRUNC | O_BINARY, 0600);
    if (ofd < 0) {
        char err[128];
        cli_errmsg("cli_scandmg: Can't create temporary file %s: %s\n",
                   outfile, cli_strerror(errno, err, sizeof(err)));
        cli_scan_release_temporary(ctx, temporary_reserved);
        cli_mark_scan_incomplete(ctx, "DMG reconstructed partition temporary file could not be opened");
        return CL_ETMPFILE;
    }
    cli_dbgmsg("dmg_handle_mish: extracting block %u to %s\n", mishblocknum, outfile);

    /* Push data, stripe by stripe */
    for (i = 0; i < mish_set->mish->blockDataCount && ret == CL_CLEAN; i++) {
        switch (blocklist[i].type) {
            case DMG_STRIPE_EMPTY:
            case DMG_STRIPE_ZEROES:
                ret = dmg_stripe_zeroes(ctx, ofd, i, mish_set);
                break;
            case DMG_STRIPE_STORED:
                ret = dmg_stripe_store(ctx, ofd, i, mish_set);
                break;
            case DMG_STRIPE_ADC:
                ret = dmg_stripe_adc(ctx, ofd, i, mish_set);
                break;
            case DMG_STRIPE_DEFLATE:
                ret = dmg_stripe_inflate(ctx, ofd, i, mish_set);
                break;
            case DMG_STRIPE_BZ:
                ret = dmg_stripe_bzip(ctx, ofd, i, mish_set);
                break;
            case DMG_STRIPE_SKIP:
            case DMG_STRIPE_END:
            default:
                cli_dbgmsg("dmg_handle_mish: stripe " STDu32 ", skipped\n", i);
                break;
        }
    }

    /* If okay so far, scan rebuilt partition */
    if (ret == CL_CLEAN) {
        /* Have to keep partition typing separate */
        ret = cli_magic_scan_desc_type(ofd, outfile, ctx, CL_TYPE_PART_ANY, NULL, LAYER_ATTRIBUTES_NONE);
    }

    if (close(ofd) == -1 && ret == CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, "DMG reconstructed partition could not be closed completely");
        ret = CL_EWRITE;
    }
    cli_scan_release_temporary(ctx, temporary_reserved);
    if (!ctx->engine->keeptmp && cli_unlink(outfile)) {
        cli_mark_scan_incomplete(ctx, "DMG reconstructed partition temporary file could not be removed");
        if (ret == CL_SUCCESS)
            ret = CL_EUNLINK;
    }

    return ret;
}

static int dmg_extract_xml(cli_ctx *ctx, char *dir, struct dmg_koly_block *hdr)
{
    char *xmlfile;
    uint8_t buffer[DMG_STREAM_CHUNK_SIZE];
    uint64_t offset, remaining;
    size_t namelen;
    int ofd;

    namelen = strlen(dir) + 1 + 7 + 1;
    if (!(xmlfile = cli_max_malloc(namelen))) {
        cli_mark_scan_incomplete(ctx, "DMG XML temporary path could not be allocated");
        return CL_EMEM;
    }
    snprintf(xmlfile, namelen, "%s" PATHSEP "toc.xml", dir);
    cli_dbgmsg("cli_scandmg: Extracting XML as %s\n", xmlfile);

    /* Write out TOC XML in bounded windows. */
    if ((ofd = open(xmlfile, O_CREAT | O_RDWR | O_EXCL | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR)) < 0) {
        char err[128];
        cli_errmsg("cli_scandmg: Can't create temporary file %s: %s\n",
                   xmlfile, cli_strerror(errno, err, sizeof(err)));
        cli_mark_scan_incomplete(ctx, "DMG XML temporary file could not be opened");
        free(xmlfile);
        return CL_ETMPFILE;
    }

    offset    = hdr->xmlOffset;
    remaining = hdr->xmlLength;
    while (remaining != 0) {
        size_t wanted = (size_t)MIN(remaining, (uint64_t)sizeof(buffer));
        if (offset > (uint64_t)SIZE_MAX || fmap_readn(ctx->fmap, buffer, (size_t)offset, wanted) != wanted) {
            cli_errmsg("cli_scandmg: Failed reading XML at offset " STDu64 "\n", offset);
            close(ofd);
            free(xmlfile);
            cli_mark_scan_incomplete(ctx, "DMG XML resource fork could not be read completely");
            return CL_EPARSE;
        }
        if (cli_scan_reserve_temporary(ctx, (uint64_t)wanted) != CL_SUCCESS) {
            close(ofd);
            free(xmlfile);
            cli_mark_scan_incomplete(ctx, "DMG XML retained copy exceeds temporary storage limits");
            return CL_ERESOURCE;
        }
        if (cli_writen(ofd, buffer, wanted) != wanted) {
            cli_scan_release_temporary(ctx, (uint64_t)wanted);
            cli_errmsg("cli_scandmg: Not all XML bytes were written!\n");
            cli_mark_scan_incomplete(ctx, "DMG XML temporary file could not be written completely");
            close(ofd);
            free(xmlfile);
            return CL_EWRITE;
        }
        cli_scan_release_temporary(ctx, (uint64_t)wanted);
        offset += wanted;
        remaining -= wanted;
    }

    if (close(ofd) == -1) {
        cli_mark_scan_incomplete(ctx, "DMG XML temporary file could not be closed completely");
        free(xmlfile);
        return CL_EWRITE;
    }
    free(xmlfile);
    return CL_SUCCESS;
}
