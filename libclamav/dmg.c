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
#define DMG_SORT_RUN_BYTES (4U * 1024U * 1024U)
#define DMG_SORT_IO_RECORDS 256U

struct dmg_xml_scan_state {
    unsigned int mishblocknum;
    unsigned int file;
    char *dirname;
    uint64_t dataForkOffset;
    uint64_t dataForkLength;
};

struct dmg_sort_reader {
    fmap_t *map;
    uint64_t base;
    uint64_t next;
    uint64_t end;
    size_t position;
    size_t count;
    struct dmg_block_data records[DMG_SORT_IO_RECORDS];
};

struct dmg_sort_writer {
    cli_ctx *ctx;
    int fd;
    size_t count;
    uint64_t total;
    struct dmg_block_data records[DMG_SORT_IO_RECORDS];
};

static int dmg_extract_xml(cli_ctx *, char *, struct dmg_koly_block *);
static int dmg_parse_mish_bytes(cli_ctx *, unsigned int *, uint8_t *, size_t,
                                struct dmg_mish_with_stripes *);
static int dmg_parse_mish_stream(cli_ctx *, unsigned int *, int, size_t,
                                 struct dmg_mish_with_stripes *);
static int dmg_decode_mish_fd(cli_ctx *, unsigned int *, int, struct dmg_mish_with_stripes *);
static cl_error_t dmg_mish_decoded_cb(int, const char *, cli_ctx *, void *);
static int cmp_mish_stripes(const void *stripe_a, const void *stripe_b);
static int cmp_mish_stripes_be(const void *stripe_a, const void *stripe_b);
int cli_dmg_external_sort_stripes(cli_ctx *, struct dmg_mish_with_stripes *);
static int dmg_track_sectors(uint64_t *, uint8_t *, uint32_t, uint32_t, uint64_t);
static int dmg_prepare_stripe(cli_ctx *, struct dmg_mish_with_stripes *, uint32_t,
                              struct dmg_block_data *, uint64_t, uint64_t);
static int dmg_handle_mish(cli_ctx *, unsigned int, char *, uint64_t, uint64_t,
                           struct dmg_mish_with_stripes *);
static int dmg_read_stream_stripe(cli_ctx *, struct dmg_mish_with_stripes *, uint32_t,
                                  struct dmg_block_data *);
static const struct dmg_block_data *dmg_current_stripe(const struct dmg_mish_with_stripes *, uint32_t);
static void dmg_release_mish(struct dmg_mish_with_stripes *);

static int dmg_cleanup_temp_dir(cli_ctx *ctx, char **dirname, int status)
{
    if (dirname == NULL || *dirname == NULL)
        return status;

    if (!ctx->engine->keeptmp && cli_rmdirs(*dirname) != 0) {
        cli_mark_scan_incomplete(ctx, "DMG temporary directory could not be removed");
        status = cli_merge_cleanup_status(status, CL_EUNLINK);
    }

    /* A required DMG operation may have preserved a sticky incomplete state
     * while the outer parser continued far enough to reach cleanup. Direct
     * callers must not observe a clean result after that partial inspection. */
    if ((status == CL_SUCCESS || status == CL_CLEAN) && ctx->scan_incomplete)
        status = CL_EPARSE;

    free(*dirname);
    *dirname = NULL;
    return status;
}

static const uint8_t *dmg_map_window(cli_ctx *ctx, uint64_t offset, uint64_t remaining,
                                     size_t *window_len, int *read_failed)
{
    const uint8_t *window;

    if (read_failed)
        *read_failed = 0;
    if (!ctx || !ctx->fmap || !window_len || remaining == 0 || offset > (uint64_t)SIZE_MAX) {
        if (window_len)
            *window_len = 0;
        return NULL;
    }

    *window_len = (size_t)MIN(remaining, (uint64_t)DMG_STREAM_CHUNK_SIZE);
    if ((size_t)offset > ctx->fmap->len || *window_len > ctx->fmap->len - (size_t)offset) {
        *window_len = 0;
        return NULL;
    }
    window      = fmap_need_off_once(ctx->fmap, (size_t)offset, *window_len);
    if (!window) {
        if (read_failed)
            *read_failed = 1;
        *window_len = 0;
    }
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
    if (cli_checktimelimit(ctx) != CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, "DMG reconstructed output reached the configured time limit");
        return CL_ETIMEOUT;
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
    size_t trailer_read;
    char *dirname;
    static const struct key_entry dmg_xml_keys[] = {
        {"data", "DMGData", MSXML_SCAN_B64}};

    if (!ctx)
        return CL_ENULLARG;
    if (!ctx->fmap) {
        cli_errmsg("cli_scandmg: Invalid context\n");
        cli_mark_scan_incomplete(ctx, "DMG input map is unavailable");
        return CL_EPARSE;
    }
    if (!ctx->engine)
        return CL_ENULLARG;

    maplen = ctx->fmap->len;
    if (maplen <= 512) {
        cli_dbgmsg("cli_scandmg: DMG smaller than DMG koly block!\n");
        cli_mark_scan_incomplete(ctx, "DMG input is too small to contain a complete koly trailer");
        return CL_EPARSE;
    }
    pos = maplen - 512;

    /* Grab koly block. */
    trailer_read = fmap_readn(ctx->fmap, &hdr, pos, sizeof(hdr));
    if (trailer_read != sizeof(hdr)) {
        cli_dbgmsg("cli_scandmg: Invalid DMG trailer block\n");
        cli_mark_scan_incomplete(ctx, "DMG trailer block is incomplete");
        return trailer_read == (size_t)-1 ? CL_EREAD : CL_EPARSE;
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
            return dmg_cleanup_temp_dir(ctx, &dirname, ret);
        }
    }

    /* Always scan the complete XML range with the outer raw matchers. */
    ret = cli_magic_scan_nested_fmap_type(ctx->fmap, (size_t)hdr.xmlOffset, (size_t)hdr.xmlLength,
                                          ctx, CL_TYPE_ANY, NULL, LAYER_ATTRIBUTES_NONE);
    if (ret != CL_CLEAN) {
        cli_dbgmsg("cli_scandmg: retcode from scanning TOC xml: %s\n", cl_strerror(ret));
        if (ret != CL_VIRUS)
            cli_mark_scan_incomplete(ctx, "DMG XML nested scan did not complete successfully");
        return dmg_cleanup_temp_dir(ctx, &dirname, ret);
    }

    /*
     * Parse the same range through the bounded SAX reader. The generic MSXML
     * decoder writes each <data> value into a quota-accounted spool, then the
     * callback reads one completed mish metadata block at a time.
     */
    xml_map = fmap_duplicate(ctx->fmap, (size_t)hdr.xmlOffset, (size_t)hdr.xmlLength, "toc.xml");
    if (!xml_map) {
        cli_mark_scan_incomplete(ctx, "DMG XML fmap view could not be created");
        return dmg_cleanup_temp_dir(ctx, &dirname, CL_EMAP);
    }

    memset(&xml_state, 0, sizeof(xml_state));
    xml_state.dirname        = dirname;
    xml_state.dataForkOffset = hdr.dataForkOffset;
    xml_state.dataForkLength = hdr.dataForkLength;
    memset(&mxctx, 0, sizeof(mxctx));
    mxctx.decoded_cb       = dmg_mish_decoded_cb;
    /* The decoded value is written to a temporary spool and admitted against
     * the shared temporary quota. DMG validates its fixed-width blkx records
     * from that spool instead of imposing an independent small cap. */
    mxctx.decoded_max_size = 0;
    mxctx.scan_data        = &xml_state;
    ret                    = cli_msxml_parse_document_streaming(ctx, xml_map, dmg_xml_keys,
                                                                sizeof(dmg_xml_keys) / sizeof(dmg_xml_keys[0]),
                                                                MSXML_FLAG_FAIL_INCOMPLETE, &mxctx);
    free_duplicate_fmap(xml_map);

    if (ret == CL_CLEAN && xml_state.mishblocknum == 0) {
        cli_mark_scan_incomplete(ctx, "DMG XML did not provide any decodable blkx metadata");
        ret = CL_EPARSE;
    }

    return dmg_cleanup_temp_dir(ctx, &dirname, ret);
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

    mish_set->mish          = NULL;
    mish_set->stripes       = NULL;
    mish_set->next          = NULL;
    mish_set->metadata_map  = NULL;
    mish_set->metadata_fd   = -1;
    mish_set->metadata_len  = 0;
    mish_set->current_valid = 0;
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

    /* Keep the retained legacy array in host order.  dmg_handle_mish()
     * traverses it more than once (ordering, geometry, and reconstruction),
     * so converting in the traversal helper would byte-swap valid values on
     * every pass after the first.  Streamed metadata is converted by
     * dmg_read_stream_stripe() as each record is read instead. */
    for (i = 0; i < mish_set->mish->blockDataCount; i++) {
        struct dmg_block_data *stripe = &mish_set->stripes[i];

        stripe->type        = be32_to_host(stripe->type);
        stripe->startSector = be64_to_host(stripe->startSector);
        stripe->sectorCount = be64_to_host(stripe->sectorCount);
        stripe->dataOffset  = be64_to_host(stripe->dataOffset);
        stripe->dataLength  = be64_to_host(stripe->dataLength);
    }

    return CL_CLEAN;
}

static int dmg_read_stream_stripe(cli_ctx *ctx, struct dmg_mish_with_stripes *mish_set,
                                  uint32_t index, struct dmg_block_data *stripe)
{
    uint64_t offset;
    size_t read_result;

    if (!ctx || !mish_set || !mish_set->metadata_map || !mish_set->mish || !stripe ||
        index >= mish_set->mish->blockDataCount)
        return CL_ENULLARG;

    if ((uint64_t)sizeof(struct dmg_mish_block) > UINT64_MAX -
                                                    (uint64_t)index * sizeof(struct dmg_block_data)) {
        cli_mark_scan_incomplete(ctx, "DMG blkx stripe offset overflowed");
        return CL_EPARSE;
    }
    offset = (uint64_t)sizeof(struct dmg_mish_block) +
             (uint64_t)index * (uint64_t)sizeof(struct dmg_block_data);
    if (offset > (uint64_t)SIZE_MAX) {
        cli_mark_scan_incomplete(ctx, "DMG blkx stripe metadata offset is not addressable");
        return CL_EPARSE;
    }
    read_result = fmap_readn_full(mish_set->metadata_map, stripe, (size_t)offset, sizeof(*stripe));
    if (read_result != sizeof(*stripe)) {
        cli_mark_scan_incomplete(ctx, "DMG blkx stripe metadata could not be read completely");
        return read_result == (size_t)-1 ? CL_EREAD : CL_EPARSE;
    }

    stripe->type        = be32_to_host(stripe->type);
    stripe->startSector = be64_to_host(stripe->startSector);
    stripe->sectorCount = be64_to_host(stripe->sectorCount);
    stripe->dataOffset  = be64_to_host(stripe->dataOffset);
    stripe->dataLength  = be64_to_host(stripe->dataLength);
    return CL_CLEAN;
}

static int dmg_parse_mish_stream(cli_ctx *ctx, unsigned int *mishblocknum, int fd,
                                 size_t decoded_len, struct dmg_mish_with_stripes *mish_set)
{
    static const uint8_t mish_magic[4] = {0x6d, 0x69, 0x73, 0x68};
    struct dmg_mish_block header;
    struct dmg_block_data stripe;
    uint64_t expected_len;
    uint32_t i;
    unsigned int end_count = 0;
    int ret;

    if (!ctx || !mishblocknum || fd < 0 || !mish_set || decoded_len < sizeof(header))
        return CL_ENULLARG;

    memset(mish_set, 0, sizeof(*mish_set));
    mish_set->metadata_fd  = fd;
    mish_set->metadata_len = decoded_len;
    mish_set->metadata_map = fmap_new(fd, 0, decoded_len, "dmg-mish", NULL);
    if (!mish_set->metadata_map) {
        cli_mark_scan_incomplete(ctx, "DMG decoded mish spool could not be exposed through a bounded fmap");
        return CL_ERESOURCE;
    }
    if (fmap_readn(mish_set->metadata_map, &header, 0, sizeof(header)) != sizeof(header)) {
        cli_mark_scan_incomplete(ctx, "DMG decoded mish header could not be read completely");
        dmg_release_mish(mish_set);
        return CL_EREAD;
    }

    (*mishblocknum)++;
    if (memcmp(&header.magic, mish_magic, sizeof(mish_magic)) != 0) {
        cli_dbgmsg("dmg_parse_mish_stream: block %u does not have mish magic\n", *mishblocknum);
        dmg_release_mish(mish_set);
        return CL_EFORMAT;
    }

    header.startSector    = be64_to_host(header.startSector);
    header.sectorCount    = be64_to_host(header.sectorCount);
    header.dataOffset     = be64_to_host(header.dataOffset);
    header.blockDataCount = be32_to_host(header.blockDataCount);
    if (header.blockDataCount == 0) {
        cli_dbgmsg("dmg_parse_mish_stream: block %u has no stripe records\n", *mishblocknum);
        dmg_release_mish(mish_set);
        return CL_EFORMAT;
    }

    expected_len = (uint64_t)sizeof(struct dmg_mish_block) +
                   (uint64_t)header.blockDataCount * (uint64_t)sizeof(struct dmg_block_data);
    if (expected_len != (uint64_t)decoded_len) {
        cli_dbgmsg("dmg_parse_mish_stream: block %u has an invalid decoded length\n", *mishblocknum);
        dmg_release_mish(mish_set);
        return CL_EFORMAT;
    }

    mish_set->mish = cli_max_malloc(sizeof(header));
    if (!mish_set->mish) {
        cli_mark_scan_incomplete(ctx, "DMG decoded mish header could not be allocated");
        dmg_release_mish(mish_set);
        return CL_EMEM;
    }
    *mish_set->mish = header;

    for (i = 0; i < header.blockDataCount; i++) {
        if ((i & 0xfffU) == 0 && cli_checktimelimit(ctx) != CL_SUCCESS) {
            cli_mark_scan_incomplete(ctx, "DMG blkx metadata validation reached the configured time limit");
            dmg_release_mish(mish_set);
            return CL_ETIMEOUT;
        }

        ret = dmg_read_stream_stripe(ctx, mish_set, i, &stripe);
        if (ret != CL_CLEAN) {
            dmg_release_mish(mish_set);
            return ret;
        }
        if (stripe.type != DMG_STRIPE_END)
            continue;

        end_count++;
        if (end_count != 1 || i + 1 != header.blockDataCount || stripe.sectorCount != 0 ||
            stripe.dataLength != 0) {
            cli_dbgmsg("dmg_parse_mish_stream: block %u has an invalid or non-terminal END stripe\n", *mishblocknum);
            dmg_release_mish(mish_set);
            return CL_EFORMAT;
        }
    }

    if (end_count != 1) {
        cli_dbgmsg("dmg_parse_mish_stream: block %u has no terminal END stripe\n", *mishblocknum);
        dmg_release_mish(mish_set);
        return CL_EFORMAT;
    }

    fmap_release_unlocked(mish_set->metadata_map);
    return CL_CLEAN;
}

static const struct dmg_block_data *dmg_current_stripe(const struct dmg_mish_with_stripes *mish_set,
                                                       uint32_t index)
{
    if (!mish_set)
        return NULL;
    if (mish_set->stripes)
        return &mish_set->stripes[index];
    if (mish_set->current_valid && mish_set->current_index == index)
        return &mish_set->current_stripe;
    return NULL;
}

static void dmg_release_mish(struct dmg_mish_with_stripes *mish_set)
{
    if (!mish_set)
        return;
    if (mish_set->metadata_map) {
        fmap_free(mish_set->metadata_map);
        mish_set->metadata_map = NULL;
    }
    free(mish_set->mish);
    mish_set->mish          = NULL;
    mish_set->stripes       = NULL;
    mish_set->metadata_fd   = -1;
    mish_set->metadata_len  = 0;
    mish_set->current_valid = 0;
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
    if (statbuf.st_size == 0) {
        cli_mark_scan_incomplete(ctx, "DMG decoded mish metadata is empty");
        return CL_EFORMAT;
    }
    if ((uint64_t)statbuf.st_size > (uint64_t)SIZE_MAX) {
        cli_mark_scan_incomplete(ctx, "DMG decoded mish metadata exceeds the addressable fmap range");
        return CL_ERESOURCE;
    }

    decoded_len = (size_t)statbuf.st_size;
    if ((uint64_t)decoded_len > (uint64_t)DMG_MISH_SORT_MAX_SIZE)
        return dmg_parse_mish_stream(ctx, mishblocknum, fd, decoded_len, mish_set);

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
    struct dmg_mish_with_stripes mish_set;
    cl_error_t ret;

    UNUSEDPARAM(filepath);

    if (!state || !ctx || fd < 0 || !state->dirname)
        return CL_ENULLARG;

    memset(&mish_set, 0, sizeof(mish_set));
    ret = dmg_decode_mish_fd(ctx, &state->mishblocknum, fd, &mish_set);
    if (ret == CL_EFORMAT) {
        cli_mark_scan_incomplete(ctx, "DMG blkx mish metadata is malformed or unsupported");
        return CL_EPARSE;
    }
    if (ret != CL_CLEAN)
        return ret;

    /* Process one completed blkx block before the streaming XML parser can
     * decode the next one. This keeps decoded metadata bounded to one block
     * instead of retaining the entire DMG XML resource fork in heap memory. */
    if (cli_checktimelimit(ctx) != CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, "DMG partition reconstruction reached the configured time limit");
        ret = CL_ETIMEOUT;
    } else if (state->file == UINT_MAX) {
        cli_mark_scan_incomplete(ctx, "DMG partition file numbering exceeded its native limit");
        ret = CL_ERESOURCE;
    } else {
        ret = dmg_handle_mish(ctx, state->file++, state->dirname, state->dataForkOffset,
                              state->dataForkLength, &mish_set);
    }

    dmg_release_mish(&mish_set);
    return ret == CL_CLEAN ? CL_SUCCESS : ret;
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

static int cmp_mish_stripes_be(const void *stripe_a, const void *stripe_b)
{
    const struct dmg_block_data *a = stripe_a, *b = stripe_b;
    uint64_t a_start               = be64_to_host(a->startSector);
    uint64_t b_start               = be64_to_host(b->startSector);
    uint32_t a_type;
    uint32_t b_type;

    if (a_start < b_start)
        return -1;
    if (a_start > b_start)
        return 1;

    a_type = be32_to_host(a->type);
    b_type = be32_to_host(b->type);
    if (a_type < b_type)
        return -1;
    if (a_type > b_type)
        return 1;
    return 0;
}

static int dmg_sort_reader_peek(cli_ctx *ctx, struct dmg_sort_reader *reader,
                                const struct dmg_block_data **stripe)
{
    uint64_t offset;
    size_t records;
    size_t bytes;
    size_t read_result;

    if (!ctx || !reader || !reader->map || !stripe)
        return CL_ENULLARG;
    *stripe = NULL;

    if (reader->position < reader->count) {
        *stripe = &reader->records[reader->position];
        return CL_CLEAN;
    }
    if (reader->next >= reader->end)
        return CL_CLEAN;

    if (cli_checktimelimit(ctx) != CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, "DMG external metadata sort reached the configured time limit");
        return CL_ETIMEOUT;
    }

    records = (size_t)MIN(reader->end - reader->next, (uint64_t)DMG_SORT_IO_RECORDS);
    bytes   = records * sizeof(struct dmg_block_data);
    if (reader->next > (UINT64_MAX - reader->base) / sizeof(struct dmg_block_data)) {
        cli_mark_scan_incomplete(ctx, "DMG external metadata sort input offset overflowed");
        return CL_EPARSE;
    }
    offset = reader->base + reader->next * (uint64_t)sizeof(struct dmg_block_data);
    if (offset > (uint64_t)SIZE_MAX) {
        cli_mark_scan_incomplete(ctx, "DMG external metadata sort input offset is not addressable");
        return CL_EPARSE;
    }
    read_result = fmap_readn_full(reader->map, reader->records, (size_t)offset, bytes);
    if (read_result != bytes) {
        cli_mark_scan_incomplete(ctx, "DMG external metadata sort input could not be read completely");
        return read_result == (size_t)-1 ? CL_EREAD : CL_EPARSE;
    }

    reader->next += records;
    reader->position = 0;
    reader->count    = records;
    *stripe          = &reader->records[0];
    return CL_CLEAN;
}

static void dmg_sort_reader_advance(struct dmg_sort_reader *reader)
{
    if (reader && reader->position < reader->count)
        reader->position++;
}

static int dmg_sort_writer_flush(struct dmg_sort_writer *writer)
{
    size_t bytes;

    if (!writer || !writer->ctx || writer->fd < 0)
        return CL_ENULLARG;
    if (writer->count == 0)
        return CL_CLEAN;
    if (cli_checktimelimit(writer->ctx) != CL_SUCCESS) {
        cli_mark_scan_incomplete(writer->ctx, "DMG external metadata sort reached the configured time limit");
        return CL_ETIMEOUT;
    }

    bytes = writer->count * sizeof(struct dmg_block_data);
    if (cli_writen(writer->fd, writer->records, bytes) != bytes) {
        cli_mark_scan_incomplete(writer->ctx, "DMG external metadata sort output could not be written completely");
        return CL_EWRITE;
    }
    writer->count = 0;
    return CL_CLEAN;
}

static int dmg_sort_writer_put(struct dmg_sort_writer *writer, const struct dmg_block_data *stripe)
{
    int ret;

    if (!writer || !stripe)
        return CL_ENULLARG;
    if (writer->count == DMG_SORT_IO_RECORDS) {
        ret = dmg_sort_writer_flush(writer);
        if (ret != CL_CLEAN)
            return ret;
    }
    writer->records[writer->count++] = *stripe;
    writer->total++;
    return CL_CLEAN;
}

static int dmg_sort_merge_pair(cli_ctx *ctx, fmap_t *source, uint64_t source_base,
                               uint64_t start, uint64_t middle, uint64_t end,
                               struct dmg_sort_writer *writer)
{
    struct dmg_sort_reader left;
    struct dmg_sort_reader right;
    const struct dmg_block_data *left_stripe;
    const struct dmg_block_data *right_stripe;
    int ret;

    memset(&left, 0, sizeof(left));
    memset(&right, 0, sizeof(right));
    left.map   = source;
    left.base  = source_base;
    left.next  = start;
    left.end   = middle;
    right.map  = source;
    right.base = source_base;
    right.next = middle;
    right.end  = end;

    for (;;) {
        ret = dmg_sort_reader_peek(ctx, &left, &left_stripe);
        if (ret != CL_CLEAN)
            return ret;
        ret = dmg_sort_reader_peek(ctx, &right, &right_stripe);
        if (ret != CL_CLEAN)
            return ret;
        if (!left_stripe && !right_stripe)
            return CL_CLEAN;

        if (!right_stripe || (left_stripe && cmp_mish_stripes_be(left_stripe, right_stripe) <= 0)) {
            ret = dmg_sort_writer_put(writer, left_stripe);
            dmg_sort_reader_advance(&left);
        } else {
            ret = dmg_sort_writer_put(writer, right_stripe);
            dmg_sort_reader_advance(&right);
        }
        if (ret != CL_CLEAN)
            return ret;
    }
}

static int dmg_sort_merge_pass(cli_ctx *ctx, fmap_t *source, uint64_t source_base,
                               int destination_fd, uint64_t destination_base,
                               uint64_t count, uint64_t width)
{
    struct dmg_sort_writer writer;
    uint64_t start = 0;
    off_t seek_offset;
    int ret;

    if (!ctx || !source || destination_fd < 0 || width == 0)
        return CL_ENULLARG;
    seek_offset = (off_t)destination_base;
    if (seek_offset < 0 || (uint64_t)seek_offset != destination_base ||
        lseek(destination_fd, seek_offset, SEEK_SET) == (off_t)-1) {
        cli_mark_scan_incomplete(ctx, "DMG external metadata sort output could not be positioned");
        return CL_ESEEK;
    }

    memset(&writer, 0, sizeof(writer));
    writer.ctx = ctx;
    writer.fd  = destination_fd;
    while (start < count) {
        uint64_t middle = start + MIN(width, count - start);
        uint64_t end    = middle + MIN(width, count - middle);

        ret = dmg_sort_merge_pair(ctx, source, source_base, start, middle, end, &writer);
        if (ret != CL_CLEAN)
            return ret;
        start = end;
    }
    ret = dmg_sort_writer_flush(&writer);
    if (ret != CL_CLEAN)
        return ret;
    if (writer.total != count) {
        cli_mark_scan_incomplete(ctx, "DMG external metadata sort produced an incomplete record set");
        return CL_EPARSE;
    }
    return CL_CLEAN;
}

int cli_dmg_external_sort_stripes(cli_ctx *ctx, struct dmg_mish_with_stripes *mish_set)
{
    struct dmg_block_data *run   = NULL;
    fmap_t *source_map           = NULL;
    char *auxiliary_name         = NULL;
    uint64_t auxiliary_reserved  = 0;
    uint64_t contiguous_reserved = 0;
    uint64_t count;
    uint64_t stripe_bytes;
    uint64_t start;
    uint64_t width;
    size_t run_records;
    int auxiliary_fd = -1;
    int source_fd;
    int destination_fd;
    uint64_t source_base;
    uint64_t destination_base;
    size_t source_length;
    int ret            = CL_CLEAN;
    cl_error_t cleanup_status = CL_SUCCESS;

    if (!ctx || !ctx->engine || !mish_set || !mish_set->mish || !mish_set->metadata_map ||
        mish_set->metadata_fd < 0 || mish_set->metadata_len < sizeof(struct dmg_mish_block))
        return CL_ENULLARG;

    count        = mish_set->mish->blockDataCount;
    stripe_bytes = count * (uint64_t)sizeof(struct dmg_block_data);
    if (count == 0 || stripe_bytes > (uint64_t)SIZE_MAX ||
        stripe_bytes != (uint64_t)mish_set->metadata_len - sizeof(struct dmg_mish_block)) {
        cli_mark_scan_incomplete(ctx, "DMG external metadata sort size is inconsistent");
        return CL_EPARSE;
    }

    run_records = DMG_SORT_RUN_BYTES / sizeof(struct dmg_block_data);
    if (run_records == 0)
        return CL_EARG;
    contiguous_reserved = run_records * sizeof(struct dmg_block_data);
    ret = cli_scan_reserve_contiguous(ctx, contiguous_reserved);
    if (ret != CL_CLEAN) {
        cli_mark_scan_incomplete(ctx, "DMG external metadata sort exceeds contiguous memory limits");
        return ret;
    }
    run = cli_max_malloc(run_records * sizeof(struct dmg_block_data));
    if (!run) {
        cli_mark_scan_incomplete(ctx, "DMG external metadata sort run could not be allocated");
        ret = CL_EMEM;
        goto done;
    }

    ret = cli_scan_reserve_temporary(ctx, stripe_bytes);
    if (ret != CL_CLEAN) {
        cli_mark_scan_incomplete(ctx, "DMG external metadata sort exceeds temporary storage limits");
        goto done;
    }
    auxiliary_reserved = stripe_bytes;
    ret = cli_gentempfd_with_prefix(ctx->this_layer_tmpdir, "dmg-sort", &auxiliary_name, &auxiliary_fd);
    if (ret != CL_CLEAN) {
        cli_mark_scan_incomplete(ctx, "DMG external metadata sort spool could not be created");
        goto done;
    }

    for (start = 0; start < count;) {
        size_t records = (size_t)MIN((uint64_t)run_records, count - start);
        size_t bytes   = records * sizeof(struct dmg_block_data);
        uint64_t offset;
        size_t read_result;

        if (cli_checktimelimit(ctx) != CL_SUCCESS) {
            cli_mark_scan_incomplete(ctx, "DMG external metadata sort reached the configured time limit");
            ret = CL_ETIMEOUT;
            goto done;
        }
        offset = sizeof(struct dmg_mish_block) + start * (uint64_t)sizeof(struct dmg_block_data);
        if (offset > (uint64_t)SIZE_MAX) {
            cli_mark_scan_incomplete(ctx, "DMG external metadata sort run offset is not addressable");
            ret = CL_EPARSE;
            goto done;
        }
        read_result = fmap_readn_full(mish_set->metadata_map, run, (size_t)offset, bytes);
        if (read_result != bytes) {
            cli_mark_scan_incomplete(ctx, "DMG external metadata sort run could not be read completely");
            ret = read_result == (size_t)-1 ? CL_EREAD : CL_EPARSE;
            goto done;
        }
        cli_qsort(run, records, sizeof(struct dmg_block_data), cmp_mish_stripes_be);
        if (cli_checktimelimit(ctx) != CL_SUCCESS) {
            cli_mark_scan_incomplete(ctx, "DMG external metadata sort reached the configured time limit");
            ret = CL_ETIMEOUT;
            goto done;
        }
        if (cli_writen(auxiliary_fd, run, bytes) != bytes) {
            cli_mark_scan_incomplete(ctx, "DMG external metadata sort run could not be written completely");
            ret = CL_EWRITE;
            goto done;
        }
        start += records;
    }
    free(run);
    run = NULL;
    cli_scan_release_contiguous(ctx, contiguous_reserved);
    contiguous_reserved = 0;
    fmap_release_unlocked(mish_set->metadata_map);
    fmap_free(mish_set->metadata_map);
    mish_set->metadata_map = NULL;

    source_fd        = auxiliary_fd;
    source_base      = 0;
    source_length    = (size_t)stripe_bytes;
    destination_fd   = mish_set->metadata_fd;
    destination_base = sizeof(struct dmg_mish_block);
    width             = run_records;
    while (width < count) {
        int next_source_fd;
        uint64_t next_source_base;
        size_t next_source_length;

        source_map = fmap_new(source_fd, 0, source_length, "dmg-sort-source", NULL);
        if (!source_map) {
            cli_mark_scan_incomplete(ctx, "DMG external metadata sort source could not be mapped");
            ret = CL_ERESOURCE;
            goto done;
        }
        ret = dmg_sort_merge_pass(ctx, source_map, source_base, destination_fd, destination_base,
                                  count, width);
        fmap_free(source_map);
        source_map = NULL;
        if (ret != CL_CLEAN)
            goto done;

        next_source_fd     = destination_fd;
        next_source_base   = destination_base;
        next_source_length = destination_fd == mish_set->metadata_fd
                                 ? mish_set->metadata_len
                                 : (size_t)stripe_bytes;
        destination_fd     = source_fd;
        destination_base   = source_base;
        source_fd          = next_source_fd;
        source_base        = next_source_base;
        source_length      = next_source_length;
        width              = width > count - width ? count : width * 2;
    }

    if (source_fd != mish_set->metadata_fd) {
        source_map = fmap_new(source_fd, 0, source_length, "dmg-sort-final", NULL);
        if (!source_map) {
            cli_mark_scan_incomplete(ctx, "DMG external metadata sort final source could not be mapped");
            ret = CL_ERESOURCE;
            goto done;
        }
        ret = dmg_sort_merge_pass(ctx, source_map, source_base, mish_set->metadata_fd,
                                  sizeof(struct dmg_mish_block), count, count);
        fmap_free(source_map);
        source_map = NULL;
        if (ret != CL_CLEAN)
            goto done;
    }

    mish_set->metadata_map = fmap_new(mish_set->metadata_fd, 0, mish_set->metadata_len,
                                      "dmg-mish-sorted", NULL);
    if (!mish_set->metadata_map) {
        cli_mark_scan_incomplete(ctx, "DMG sorted metadata spool could not be mapped");
        ret = CL_ERESOURCE;
        goto done;
    }
    mish_set->current_valid = 0;

done:
    free(run);
    if (contiguous_reserved)
        cli_scan_release_contiguous(ctx, contiguous_reserved);
    if (source_map)
        fmap_free(source_map);
    if (auxiliary_fd >= 0 && close(auxiliary_fd) != 0) {
        cli_mark_scan_incomplete(ctx, "DMG external metadata sort spool could not be closed");
        cleanup_status = cli_merge_cleanup_status(cleanup_status, CL_EWRITE);
    }
    if (auxiliary_name) {
        if (!ctx->engine->keeptmp && cli_unlink(auxiliary_name) != 0) {
            cli_mark_scan_incomplete(ctx, "DMG external metadata sort spool could not be removed");
            cleanup_status = cli_merge_cleanup_status(cleanup_status, CL_EUNLINK);
        }
        free(auxiliary_name);
    }
    if (auxiliary_reserved)
        cli_scan_release_temporary(ctx, auxiliary_reserved);
    ret = cli_merge_cleanup_status(ret, cleanup_status);
    return ret;
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
    ret = dmg_expected_output(ctx, index, dmg_current_stripe(mish_set, index)->sectorCount, &expected);
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
    uint64_t off       = dmg_current_stripe(mish_set, index)->dataOffset;
    uint64_t remaining = dmg_current_stripe(mish_set, index)->dataLength;
    uint64_t expected;
    uint64_t written = 0;
    int read_failed;
    int ret;

    cli_dbgmsg("dmg_stripe_store: stripe " STDu32 "\n", index);
    ret = dmg_expected_output(ctx, index, dmg_current_stripe(mish_set, index)->sectorCount, &expected);
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

        input = dmg_map_window(ctx, off, remaining, &window_len, &read_failed);
        if (!input || window_len == 0) {
            cli_mark_scan_incomplete(ctx, "DMG stored stripe could not be read completely");
            return read_failed ? CL_EREAD : CL_EPARSE;
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
    uint64_t off       = dmg_current_stripe(mish_set, index)->dataOffset;
    uint64_t remaining = dmg_current_stripe(mish_set, index)->dataLength;
    uint64_t expected_len;
    uint64_t size_so_far = 0;
    uint8_t obuf[BUFSIZ];
    int read_failed;

    ret = dmg_expected_output(ctx, index, dmg_current_stripe(mish_set, index)->sectorCount, &expected_len);
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
            const uint8_t *input = dmg_map_window(ctx, off, remaining, &window_len, &read_failed);
            if (!input || window_len == 0) {
                cli_mark_scan_incomplete(ctx, "DMG ADC compressed stream could not be read completely");
                ret = read_failed ? CL_EREAD : CL_EPARSE;
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
    uint64_t off         = dmg_current_stripe(mish_set, index)->dataOffset;
    uint64_t remaining   = dmg_current_stripe(mish_set, index)->dataLength;
    uint64_t size_so_far = 0;
    uint64_t expected_len;
    uint8_t obuf[BUFSIZ];
    int read_failed;

    cli_dbgmsg("dmg_stripe_inflate: stripe " STDu32 "\n", index);
    ret = dmg_expected_output(ctx, index, dmg_current_stripe(mish_set, index)->sectorCount, &expected_len);
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
            const uint8_t *input = dmg_map_window(ctx, off, remaining, &window_len, &read_failed);
            if (!input || window_len == 0) {
                cli_mark_scan_incomplete(ctx, "DMG deflate stream could not be read completely");
                ret = read_failed ? CL_EREAD : CL_EPARSE;
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
    uint64_t off         = dmg_current_stripe(mish_set, index)->dataOffset;
    uint64_t remaining   = dmg_current_stripe(mish_set, index)->dataLength;
    uint64_t size_so_far = 0;
    uint64_t expected_len;
    int rc;
    bz_stream strm;
    uint8_t obuf[BUFSIZ];
    int read_failed;

    ret = dmg_expected_output(ctx, index, dmg_current_stripe(mish_set, index)->sectorCount, &expected_len);
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
            const uint8_t *input = dmg_map_window(ctx, off, remaining, &window_len, &read_failed);
            if (!input || window_len == 0) {
                cli_mark_scan_incomplete(ctx, "DMG bzip2 stream could not be read completely");
                ret = read_failed ? CL_EREAD : CL_EPARSE;
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

static int dmg_prepare_stripe(cli_ctx *ctx, struct dmg_mish_with_stripes *mish_set, uint32_t index,
                              struct dmg_block_data *stripe, uint64_t dataForkOffset,
                              uint64_t dataForkLength)
{
    uint64_t sourceBase;
    int ret;

    if (!ctx || !mish_set || !mish_set->mish || !stripe)
        return CL_ENULLARG;

    if (!mish_set->stripes) {
        ret = dmg_read_stream_stripe(ctx, mish_set, index, stripe);
        if (ret != CL_CLEAN)
            return ret;
    }

    /* UDIF chunk offsets are relative to both the koly data-fork offset and
     * this mish block's dataOffset. Resolve them once for the current view. */
    if (mish_set->mish->dataOffset > dataForkLength ||
        stripe->dataOffset > dataForkLength - mish_set->mish->dataOffset) {
        cli_mark_scan_incomplete(ctx, "DMG stripe source base is outside the declared data fork");
        return CL_EPARSE;
    }
    sourceBase = mish_set->mish->dataOffset + stripe->dataOffset;
    if (stripe->dataLength > dataForkLength - sourceBase ||
        dataForkOffset > UINT64_MAX - sourceBase) {
        cli_mark_scan_incomplete(ctx, "DMG stripe data is outside the declared data fork");
        return CL_EPARSE;
    }
    stripe->dataOffset = dataForkOffset + sourceBase;
    if ((stripe->type == DMG_STRIPE_SKIP || stripe->type == DMG_STRIPE_END ||
         (stripe->type != DMG_STRIPE_EMPTY && stripe->type != DMG_STRIPE_ZEROES &&
          stripe->type != DMG_STRIPE_STORED && stripe->type != DMG_STRIPE_ADC &&
          stripe->type != DMG_STRIPE_DEFLATE && stripe->type != DMG_STRIPE_BZ)) &&
        stripe->dataLength != 0) {
        cli_mark_scan_incomplete(ctx, "DMG unsupported or control stripe references uninspected data");
        return CL_EPARSE;
    }

    if (!mish_set->stripes) {
        mish_set->current_stripe = *stripe;
        mish_set->current_index  = index;
        mish_set->current_valid  = 1;
    }
    return CL_CLEAN;
}

/* Given mish data, reconstruct the partition details */
static int dmg_handle_mish(cli_ctx *ctx, unsigned int mishblocknum, char *dir,
                           uint64_t dataForkOffset, uint64_t dataForkLength,
                           struct dmg_mish_with_stripes *mish_set)
{
    struct dmg_block_data *blocklist = mish_set->stripes;
    struct dmg_block_data streamed_stripe;
    uint64_t previous_start = 0;
    uint64_t totalSectors            = 0;
    uint64_t outputEnd               = 0;
    uint32_t i;
    uint64_t projected_size;
    uint64_t temporary_reserved = 0;
    int ret                     = CL_CLEAN, ofd;
    uint8_t sorted = 1, have_previous_start = 0, writeable_data = 0;
    char outfile[PATH_MAX + 1];

    /* First loop, fix endian-ness and check if already sorted. A large
     * metadata spool is read one fixed-width stripe at a time; only the
     * legacy bounded path retains a sortable in-memory array. */
    for (i = 0; i < mish_set->mish->blockDataCount; i++) {
        struct dmg_block_data *stripe = blocklist ? &blocklist[i] : &streamed_stripe;

        if ((i & 0xfffU) == 0 && cli_checktimelimit(ctx) != CL_SUCCESS) {
            cli_mark_scan_incomplete(ctx, "DMG blkx metadata traversal reached the configured time limit");
            return CL_ETIMEOUT;
        }
        ret = dmg_prepare_stripe(ctx, mish_set, i, stripe, dataForkOffset, dataForkLength);
        if (ret != CL_CLEAN)
            return ret;
        cli_dbgmsg("mish %u stripe " STDu32 " type " STDx32 " start " STDu64
                   " count " STDu64 " source " STDu64 " length " STDu64 "\n",
                   mishblocknum, i, stripe->type, stripe->startSector, stripe->sectorCount,
                   stripe->dataOffset, stripe->dataLength);
        if (stripe->type != DMG_STRIPE_SKIP && stripe->type != DMG_STRIPE_END) {
            if (have_previous_start && sorted && stripe->startSector < previous_start) {
                cli_dbgmsg("dmg_handle_mish: data stripes not in order, will have to sort\n");
                sorted = 0;
            }
            previous_start      = stripe->startSector;
            have_previous_start = 1;
        }
        if (dmg_track_sectors(&totalSectors, &writeable_data, i, stripe->type, stripe->sectorCount)) {
            /* reason was logged from dmg_track_sector_count */
            cli_mark_scan_incomplete(ctx, "DMG contains invalid or unsupported non-empty stripe metadata");
            return CL_EPARSE;
        }
    }

    if (!blocklist)
        fmap_release_unlocked(mish_set->metadata_map);

    if (!sorted && !blocklist) {
        cli_dbgmsg("dmg_handle_mish: sorting large metadata through a quota-accounted spool\n");
        ret = cli_dmg_external_sort_stripes(ctx, mish_set);
        if (ret != CL_CLEAN)
            return ret;
        sorted = 1;
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
        const struct dmg_block_data *stripe;

        if ((i & 0xfffU) == 0 && cli_checktimelimit(ctx) != CL_SUCCESS) {
            cli_mark_scan_incomplete(ctx, "DMG blkx geometry validation reached the configured time limit");
            return CL_ETIMEOUT;
        }
        if (blocklist) {
            stripe = &blocklist[i];
        } else {
            ret = dmg_prepare_stripe(ctx, mish_set, i, &streamed_stripe, dataForkOffset, dataForkLength);
            if (ret != CL_CLEAN)
                return ret;
            stripe = &streamed_stripe;
        }
        if (stripe->type == DMG_STRIPE_SKIP || stripe->type == DMG_STRIPE_END)
            continue;
        if (outputEnd > mish_set->mish->sectorCount ||
            stripe->startSector != outputEnd ||
            stripe->sectorCount > mish_set->mish->sectorCount - outputEnd) {
            cli_mark_scan_incomplete(ctx, "DMG stripe geometry has a gap, overlap, or out-of-range sector span");
            return CL_EPARSE;
        }
        outputEnd += stripe->sectorCount;
    }
    if (!blocklist)
        fmap_release_unlocked(mish_set->metadata_map);
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
        const struct dmg_block_data *stripe;

        if ((i & 0xfffU) == 0 && cli_checktimelimit(ctx) != CL_SUCCESS) {
            cli_mark_scan_incomplete(ctx, "DMG blkx reconstruction reached the configured time limit");
            ret = CL_ETIMEOUT;
            break;
        }
        if (blocklist) {
            stripe = &blocklist[i];
        } else {
            ret = dmg_prepare_stripe(ctx, mish_set, i, &streamed_stripe, dataForkOffset, dataForkLength);
            if (ret != CL_CLEAN)
                break;
            stripe = &streamed_stripe;
        }
        switch (stripe->type) {
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
        ret = cli_magic_scan_desc_type_reserved(ofd, outfile, ctx, CL_TYPE_PART_ANY, NULL, LAYER_ATTRIBUTES_NONE);
    }

    if (close(ofd) == -1) {
        cli_mark_scan_incomplete(ctx, "DMG reconstructed partition could not be closed completely");
        ret = cli_merge_cleanup_status(ret, CL_EWRITE);
    }
    cli_scan_release_temporary(ctx, temporary_reserved);
    if (!ctx->engine->keeptmp && cli_unlink(outfile)) {
        cli_mark_scan_incomplete(ctx, "DMG reconstructed partition temporary file could not be removed");
        ret = cli_merge_cleanup_status(ret, CL_EUNLINK);
    }

    return ret;
}

static int dmg_extract_xml(cli_ctx *ctx, char *dir, struct dmg_koly_block *hdr)
{
    char *xmlfile = NULL;
    uint8_t buffer[DMG_STREAM_CHUNK_SIZE];
    uint64_t offset, remaining;
    size_t namelen;
    int ofd = -1;
    int ret = CL_SUCCESS;
    size_t read_result;

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
        ret = CL_ETMPFILE;
        goto done;
    }

    offset    = hdr->xmlOffset;
    remaining = hdr->xmlLength;
    while (remaining != 0) {
        size_t wanted = (size_t)MIN(remaining, (uint64_t)sizeof(buffer));

        if (cli_checktimelimit(ctx) != CL_SUCCESS) {
            cli_mark_scan_incomplete(ctx, "DMG XML staging reached the configured time limit");
            ret = CL_ETIMEOUT;
            goto done;
        }

        read_result = offset > (uint64_t)SIZE_MAX
                          ? (size_t)-1
                          : fmap_readn(ctx->fmap, buffer, (size_t)offset, wanted);
        if (read_result != wanted) {
            cli_errmsg("cli_scandmg: Failed reading XML at offset " STDu64 "\n", offset);
            cli_mark_scan_incomplete(ctx, "DMG XML resource fork could not be read completely");
            ret = read_result == (size_t)-1 ? CL_EREAD : CL_EPARSE;
            goto done;
        }
        if (cli_scan_reserve_temporary(ctx, (uint64_t)wanted) != CL_SUCCESS) {
            cli_mark_scan_incomplete(ctx, "DMG XML retained copy exceeds temporary storage limits");
            ret = CL_ERESOURCE;
            goto done;
        }
        if (cli_writen(ofd, buffer, wanted) != wanted) {
            cli_scan_release_temporary(ctx, (uint64_t)wanted);
            cli_errmsg("cli_scandmg: Not all XML bytes were written!\n");
            cli_mark_scan_incomplete(ctx, "DMG XML temporary file could not be written completely");
            ret = CL_EWRITE;
            goto done;
        }
        cli_scan_release_temporary(ctx, (uint64_t)wanted);
        offset += wanted;
        remaining -= wanted;
    }

done:
    if (ofd >= 0 && close(ofd) == -1) {
        cli_mark_scan_incomplete(ctx, "DMG XML temporary file could not be closed completely");
        ret = cli_merge_cleanup_status(ret, CL_EWRITE);
    }
    free(xmlfile);
    return ret;
}
