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
#include <ctype.h>
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

#include <libxml/xmlreader.h>

#include "clamav.h"
#include "others.h"
#include "dmg.h"
#include "scanners.h"
#include "sf_base64decode.h"
#include "adc.h"

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

enum dmgReadState {
    DMG_FIND_BASE_PLIST         = 0,
    DMG_FIND_BASE_DICT          = 1,
    DMG_FIND_KEY_RESOURCE_FORK  = 2,
    DMG_FIND_DICT_RESOURCE_FORK = 3,
    DMG_FIND_KEY_BLKX           = 4,
    DMG_FIND_BLKX_CONTAINER     = 5,
    DMG_FIND_KEY_DATA           = 6,
    DMG_FIND_DATA_MISH          = 7,
    DMG_MAX_STATE               = 8
};

/*
 * libxml2's pull reader is incremental, but materializing an arbitrarily large
 * DMG resource fork still gives an attacker a straightforward memory/CPU
 * denial of service.  The image itself may be tens of GiB; the metadata needed
 * to describe it may not.  Keep this legacy deep-parser limit explicit and
 * fail visible when it is exceeded.
 */
#define DMG_STREAM_CHUNK_SIZE (64U * 1024U)

struct dmg_xml_reader {
    fmap_t *map;
    uint64_t offset;
    uint64_t remaining;
    int failed;
};

static int dmg_extract_xml(cli_ctx *, char *, struct dmg_koly_block *);
static int dmg_read_data_text(cli_ctx *, xmlTextReaderPtr, int, xmlChar **);
static int dmg_validate_base64(const xmlChar *, size_t, size_t *);
static int dmg_decode_mish(cli_ctx *, unsigned int *, xmlChar *, struct dmg_mish_with_stripes *);
static int cmp_mish_stripes(const void *stripe_a, const void *stripe_b);
static int dmg_track_sectors(uint64_t *, uint8_t *, uint32_t, uint32_t, uint64_t);
static int dmg_handle_mish(cli_ctx *, unsigned int, char *, uint64_t, uint64_t,
                           struct dmg_mish_with_stripes *);

static int dmg_xml_read_cb(void *opaque, char *buffer, int buffer_len)
{
    struct dmg_xml_reader *reader = opaque;
    size_t wanted;

    if (!reader || !buffer || buffer_len < 0) {
        if (reader)
            reader->failed = 1;
        return -1;
    }
    if (buffer_len == 0 || reader->remaining == 0)
        return 0;
    if (reader->offset > (uint64_t)SIZE_MAX) {
        reader->failed = 1;
        return -1;
    }

    wanted = (size_t)MIN(reader->remaining, (uint64_t)(unsigned int)buffer_len);
    if (fmap_readn(reader->map, buffer, (size_t)reader->offset, wanted) != wanted) {
        reader->failed = 1;
        return -1;
    }

    reader->offset += wanted;
    reader->remaining -= wanted;
    return (int)wanted;
}

/* XML permits Base64 data to be split across text, CDATA, and whitespace
 * nodes. Collect the complete value, but keep it under the same explicit
 * metadata cap as the containing resource fork and require the matching
 * closing data element. */
static int dmg_read_data_text(cli_ctx *ctx, xmlTextReaderPtr reader, int data_depth, xmlChar **text_out)
{
    xmlChar *text;
    size_t text_len = 0;
    int read_status;

    if (!ctx || !reader || !text_out || data_depth < 0)
        return CL_ENULLARG;
    *text_out = NULL;

    text = cli_max_malloc(1);
    if (!text)
        return CL_EMEM;
    text[0] = '\0';

    while ((read_status = xmlTextReaderRead(reader)) == 1) {
        xmlReaderTypes node_type;
        int depth;
        int ret;

        ret = cli_checktimelimit(ctx);
        if (ret != CL_CLEAN) {
            cli_mark_scan_incomplete(ctx, "DMG blkx data parsing reached the configured time limit");
            free(text);
            return ret;
        }

        node_type = xmlTextReaderNodeType(reader);
        depth     = xmlTextReaderDepth(reader);
        if (depth < 0) {
            free(text);
            return CL_EFORMAT;
        }

        if (node_type == XML_READER_TYPE_END_ELEMENT && depth == data_depth) {
            const xmlChar *name = xmlTextReaderConstLocalName(reader);

            if (!name || xmlStrcmp(name, (const xmlChar *)"data") != 0) {
                free(text);
                return CL_EFORMAT;
            }
            *text_out = text;
            return CL_CLEAN;
        }
        if (depth <= data_depth) {
            free(text);
            return CL_EFORMAT;
        }

        if (node_type == XML_READER_TYPE_TEXT || node_type == XML_READER_TYPE_CDATA ||
            node_type == XML_READER_TYPE_WHITESPACE || node_type == XML_READER_TYPE_SIGNIFICANT_WHITESPACE) {
            const xmlChar *value = xmlTextReaderConstValue(reader);
            int value_len;
            size_t new_len;
            xmlChar *resized;

            if (!value) {
                free(text);
                return CL_EFORMAT;
            }
            value_len = xmlStrlen(value);
            if (value_len < 0 || (size_t)value_len > DMG_XML_PARSE_MAX_SIZE - text_len) {
                free(text);
                return CL_EFORMAT;
            }
            new_len = text_len + (size_t)value_len;
            resized = cli_max_realloc(text, new_len + 1);
            if (!resized) {
                free(text);
                return CL_EMEM;
            }
            text = resized;
            memcpy(text + text_len, value, (size_t)value_len);
            text_len       = new_len;
            text[text_len] = '\0';
        } else if (node_type != XML_READER_TYPE_COMMENT && node_type != XML_READER_TYPE_PROCESSING_INSTRUCTION) {
            /* Nested markup is not character content and must not be silently
             * ignored while assembling security-sensitive blkx metadata. */
            free(text);
            return CL_EFORMAT;
        }
    }

    free(text);
    return CL_EFORMAT;
}

static int dmg_base64_alphabet(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '+' || c == '/';
}

/* sf_base64decode() deliberately tolerates non-alphabet input. DMG blkx
 * metadata is security-sensitive, so validate the complete lexical form
 * first: XML whitespace is allowed, but quartets and terminal padding must be
 * canonical enough that no suffix can be skipped by the decoder. */
static int dmg_validate_base64(const xmlChar *input, size_t input_len, size_t *encoded_chars)
{
    size_t significant = 0;
    unsigned int quartet_pos = 0;
    unsigned int padding     = 0;
    int finished             = 0;
    size_t i;

    if (!input || !encoded_chars)
        return CL_ENULLARG;

    for (i = 0; i < input_len; i++) {
        unsigned char c = input[i];

        if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
            continue;
        significant++;

        if (dmg_base64_alphabet(c)) {
            if (finished || padding != 0)
                return CL_EFORMAT;
            quartet_pos++;
            if (quartet_pos == 4)
                quartet_pos = 0;
        } else if (c == '=') {
            if (finished)
                return CL_EFORMAT;
            if (quartet_pos == 2 && padding == 0) {
                padding = 1;
                quartet_pos++;
            } else if (quartet_pos == 3) {
                quartet_pos = 0;
                finished    = 1;
            } else {
                return CL_EFORMAT;
            }
        } else {
            return CL_EFORMAT;
        }
    }

    if (significant == 0 || quartet_pos != 0)
        return CL_EFORMAT;

    *encoded_chars = significant;
    return CL_CLEAN;
}

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
    if (length != 0 && cli_writen(fd, buffer, length) != length)
        return CL_EWRITE;

    *written += length;
    return CL_CLEAN;
}

int cli_scandmg(cli_ctx *ctx)
{
    struct dmg_koly_block hdr;
    int ret;
    int read_status = 0;
    size_t maplen;
    size_t pos = 0;
    char *dirname;
    unsigned int file                       = 0;
    struct dmg_mish_with_stripes *mish_list = NULL, *mish_list_tail = NULL;
    enum dmgReadState state = DMG_FIND_BASE_PLIST;
    int stateDepth[DMG_MAX_STATE];
    xmlTextReaderPtr reader;
    struct dmg_xml_reader xml_input;

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

    /* Grab koly block */
    if (fmap_readn(ctx->fmap, &hdr, pos, sizeof(hdr)) != sizeof(hdr)) {
        cli_dbgmsg("cli_scandmg: Invalid DMG trailer block\n");
        cli_mark_scan_incomplete(ctx, "DMG trailer block is incomplete");
        return CL_EPARSE;
    }

    /* Check magic */
    hdr.magic = be32_to_host(hdr.magic);
    if (hdr.magic == 0x6b6f6c79) {
        cli_dbgmsg("cli_scandmg: Found koly block @ %zu\n", pos);
    } else {
        cli_dbgmsg("cli_scandmg: No koly magic, %8x\n", hdr.magic);
        cli_mark_scan_incomplete(ctx, "DMG trailer block has invalid magic");
        return CL_EPARSE;
    }

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
     * Keep the XML range check in subtraction form. Once offset and length are
     * each known to be no larger than the map, `offset <= maplen - length`
     * proves that the full range is contained without ever forming a possibly
     * overflowing offset + length sum.
     */
    if ((hdr.xmlOffset > (uint64_t)maplen) || (hdr.xmlLength > (uint64_t)maplen) || (hdr.xmlOffset > (uint64_t)maplen - hdr.xmlLength)) {
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
    if (hdr.xmlLength > DMG_XML_PARSE_MAX_SIZE) {
        cli_mark_scan_incomplete(ctx, "DMG XML resource fork exceeds the 64 MiB deep-parser limit");
        return CL_EPARSE;
    }

    /* Create temp folder for contents */
    if (!(dirname = cli_gentemp_with_prefix(ctx->this_layer_tmpdir, "dmg-tmp"))) {
        return CL_ETMPDIR;
    }
    if (mkdir(dirname, 0700)) {
        cli_errmsg("cli_scandmg: Cannot create temporary directory %s\n", dirname);
        free(dirname);
        return CL_ETMPDIR;
    }
    cli_dbgmsg("cli_scandmg: Extracting into %s\n", dirname);

    /* Dump XML to tempfile, if needed */
    if (ctx->engine->keeptmp && !(ctx->engine->engine_options & ENGINE_OPTIONS_FORCE_TO_DISK)) {
        int xret;
        xret = dmg_extract_xml(ctx, dirname, &hdr);

        if (xret != CL_SUCCESS) {
            /* Printed err detail inside dmg_extract_xml */
            free(dirname);
            return xret;
        }
    }

    /* scan XML with cli_magic_scan_nested_fmap_type */
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

    /* time to walk the tree */
    /* plist -> dict -> (key:resource_fork) dict -> (key:blkx) array -> dict */
    /* each of those bottom level dict should have 4 parts */
    /* [ Attributes, Data, ID, Name ], where Data is Base64 mish block */

#define DMG_XML_PARSE_OPTS ((XML_PARSE_NONET | XML_PARSE_COMPACT) | CLAMAV_MIN_XMLREADER_FLAGS)

    memset(&xml_input, 0, sizeof(xml_input));
    xml_input.map       = ctx->fmap;
    xml_input.offset    = hdr.xmlOffset;
    xml_input.remaining = hdr.xmlLength;
    reader = xmlReaderForIO(dmg_xml_read_cb, NULL, &xml_input, "toc.xml", NULL, DMG_XML_PARSE_OPTS);
    if (!reader) {
        cli_dbgmsg("cli_scandmg: Failed parsing XML!\n");
        cli_mark_scan_incomplete(ctx, "DMG streaming XML reader could not be initialized");
        if (!ctx->engine->keeptmp)
            cli_rmdirs(dirname);
        free(dirname);
        return CL_EPARSE;
    }

    stateDepth[DMG_FIND_BASE_PLIST] = -1;

    // May need to check for (xmlTextReaderIsEmptyElement(reader) == 0)

    /* Break loop if have return code or reader can't read any more */
    while ((ret == CL_CLEAN) && ((read_status = xmlTextReaderRead(reader)) == 1)) {
        xmlReaderTypes nodeType;

        ret = cli_checktimelimit(ctx);
        if (ret != CL_CLEAN) {
            cli_mark_scan_incomplete(ctx, "DMG XML parsing reached the configured time limit");
            break;
        }
        nodeType = xmlTextReaderNodeType(reader);

        if (nodeType == XML_READER_TYPE_ELEMENT) {
            // New element, do name check
            xmlChar *nodeName;
            int depth;

            depth = xmlTextReaderDepth(reader);
            if (depth < 0) {
                cli_mark_scan_incomplete(ctx, "DMG XML reader returned an invalid element depth");
                ret = CL_EPARSE;
                break;
            }
            if (depth > 50) {
                cli_dbgmsg("cli_scandmg: Excessive nesting in DMG TOC.\n");
                cli_mark_scan_incomplete(ctx, "DMG XML resource fork exceeds the nesting limit");
                ret = CL_EPARSE;
                break;
            }
            nodeName = xmlTextReaderLocalName(reader);
            if (!nodeName) {
                cli_mark_scan_incomplete(ctx, "DMG XML element name could not be materialized");
                ret = CL_EPARSE;
                break;
            }
            dmg_parsemsg("read: name %s depth %d\n", nodeName, depth);

            if ((state == DMG_FIND_DATA_MISH) && (depth == stateDepth[state - 1])) {
                xmlChar *textValue;
                struct dmg_mish_with_stripes *mish_set;
                int dataDepth = depth;
                /* Reset state early, for continue cases */
                stateDepth[DMG_FIND_KEY_DATA] = -1;
                state--;
                if (xmlStrcmp(nodeName, (const xmlChar *)"data") != 0) {
                    cli_dbgmsg("cli_scandmg: Not blkx data element\n");
                    xmlFree(nodeName);
                    continue;
                }
                dmg_parsemsg("read: Found blkx data element\n");
                /* Pull out data content from text */
                if (xmlTextReaderIsEmptyElement(reader)) {
                    cli_dbgmsg("cli_scandmg: blkx data element is empty\n");
                    cli_mark_scan_incomplete(ctx, "DMG blkx data element is empty");
                    ret = CL_EPARSE;
                    xmlFree(nodeName);
                    break;
                }
                ret = dmg_read_data_text(ctx, reader, dataDepth, &textValue);
                if (ret != CL_CLEAN) {
                    if (ret == CL_EFORMAT) {
                        cli_mark_scan_incomplete(ctx, "DMG blkx data content is malformed or truncated");
                        ret = CL_EPARSE;
                    }
                    xmlFree(nodeName);
                    break;
                }
                /* Have encoded mish block */
                mish_set = malloc(sizeof(struct dmg_mish_with_stripes));
                if (mish_set == NULL) {
                    ret = CL_EMEM;
                    free(textValue);
                    xmlFree(nodeName);
                    break;
                }
                ret = dmg_decode_mish(ctx, &file, textValue, mish_set);
                free(textValue);
                if (ret == CL_EFORMAT) {
                    cli_mark_scan_incomplete(ctx, "DMG blkx mish metadata is malformed or unsupported");
                    ret = CL_EPARSE;
                    free(mish_set);
                    xmlFree(nodeName);
                    break;
                } else if (ret != CL_CLEAN) {
                    xmlFree(nodeName);
                    free(mish_set);
                    break;
                }
                /* Add mish block to list */
                if (mish_list_tail != NULL) {
                    mish_list_tail->next = mish_set;
                    mish_list_tail       = mish_set;
                } else {
                    mish_list      = mish_set;
                    mish_list_tail = mish_set;
                }
                mish_list_tail->next = NULL;
            }
            if ((state == DMG_FIND_KEY_DATA) && (depth > stateDepth[state - 1]) && (xmlStrcmp(nodeName, (const xmlChar *)"key") == 0)) {
                xmlChar *textValue;
                dmg_parsemsg("read: Found key - checking for Data\n");
                if (xmlTextReaderRead(reader) != 1) {
                    cli_mark_scan_incomplete(ctx, "DMG XML ended inside a key element");
                    ret = CL_EPARSE;
                    xmlFree(nodeName);
                    break;
                }
                if (xmlTextReaderNodeType(reader) != XML_READER_TYPE_TEXT) {
                    cli_dbgmsg("cli_scandmg: Key node no text\n");
                    cli_mark_scan_incomplete(ctx, "DMG XML key does not contain text");
                    ret = CL_EPARSE;
                    xmlFree(nodeName);
                    break;
                }
                textValue = xmlTextReaderValue(reader);
                if (textValue == NULL) {
                    cli_dbgmsg("cli_scandmg: no value from xmlTextReaderValue\n");
                    cli_mark_scan_incomplete(ctx, "DMG XML key value could not be materialized");
                    ret = CL_EPARSE;
                    xmlFree(nodeName);
                    break;
                }
                if (xmlStrcmp(textValue, (const xmlChar *)"Data") == 0) {
                    dmg_parsemsg("read: Matched data\n");
                    stateDepth[DMG_FIND_KEY_DATA] = depth;
                    state++;
                } else {
                    dmg_parsemsg("read: text value is %s\n", textValue);
                }
                xmlFree(textValue);
            }
            if ((state == DMG_FIND_BLKX_CONTAINER) && (depth == stateDepth[state - 1])) {
                if (xmlStrcmp(nodeName, (const xmlChar *)"array") == 0) {
                    dmg_parsemsg("read: Found array blkx\n");
                    stateDepth[DMG_FIND_BLKX_CONTAINER] = depth;
                    state++;
                } else if (xmlStrcmp(nodeName, (const xmlChar *)"dict") == 0) {
                    dmg_parsemsg("read: Found dict blkx\n");
                    stateDepth[DMG_FIND_BLKX_CONTAINER] = depth;
                    state++;
                } else {
                    cli_dbgmsg("cli_scandmg: Bad blkx, not container\n");
                    cli_mark_scan_incomplete(ctx, "DMG blkx value is not a supported container");
                    ret = CL_EPARSE;
                }
            }
            if ((state == DMG_FIND_KEY_BLKX) && (depth == stateDepth[state - 1] + 1) && (xmlStrcmp(nodeName, (const xmlChar *)"key") == 0)) {
                xmlChar *textValue;
                dmg_parsemsg("read: Found key - checking for blkx\n");
                if (xmlTextReaderRead(reader) != 1) {
                    cli_mark_scan_incomplete(ctx, "DMG XML ended inside a key element");
                    ret = CL_EPARSE;
                    xmlFree(nodeName);
                    break;
                }
                if (xmlTextReaderNodeType(reader) != XML_READER_TYPE_TEXT) {
                    cli_dbgmsg("cli_scandmg: Key node no text\n");
                    cli_mark_scan_incomplete(ctx, "DMG XML key does not contain text");
                    ret = CL_EPARSE;
                    xmlFree(nodeName);
                    break;
                }
                textValue = xmlTextReaderValue(reader);
                if (textValue == NULL) {
                    cli_dbgmsg("cli_scandmg: no value from xmlTextReaderValue\n");
                    cli_mark_scan_incomplete(ctx, "DMG XML key value could not be materialized");
                    ret = CL_EPARSE;
                    xmlFree(nodeName);
                    break;
                }
                if (xmlStrcmp(textValue, (const xmlChar *)"blkx") == 0) {
                    cli_dbgmsg("cli_scandmg: Matched blkx\n");
                    stateDepth[DMG_FIND_KEY_BLKX] = depth;
                    state++;
                } else {
                    cli_dbgmsg("cli_scandmg: wanted blkx, text value is %s\n", textValue);
                }
                xmlFree(textValue);
            }
            if ((state == DMG_FIND_DICT_RESOURCE_FORK) && (depth == stateDepth[state - 1])) {
                if (xmlStrcmp(nodeName, (const xmlChar *)"dict") == 0) {
                    dmg_parsemsg("read: Found resource-fork dict\n");
                    stateDepth[DMG_FIND_DICT_RESOURCE_FORK] = depth;
                    state++;
                } else {
                    dmg_parsemsg("read: Not resource-fork dict\n");
                    stateDepth[DMG_FIND_KEY_RESOURCE_FORK] = -1;
                    state--;
                }
            }
            if ((state == DMG_FIND_KEY_RESOURCE_FORK) && (depth == stateDepth[state - 1] + 1) && (xmlStrcmp(nodeName, (const xmlChar *)"key") == 0)) {
                xmlChar *textValue;

                dmg_parsemsg("read: Found resource-fork key\n");
                if (xmlTextReaderRead(reader) != 1 ||
                    xmlTextReaderNodeType(reader) != XML_READER_TYPE_TEXT) {
                    cli_mark_scan_incomplete(ctx, "DMG resource-fork key is malformed");
                    ret = CL_EPARSE;
                    xmlFree(nodeName);
                    break;
                }
                textValue = xmlTextReaderValue(reader);
                if (textValue == NULL ||
                    xmlStrcmp(textValue, (const xmlChar *)"resource-fork") != 0) {
                    if (textValue != NULL)
                        xmlFree(textValue);
                    xmlFree(nodeName);
                    continue;
                }
                xmlFree(textValue);
                stateDepth[DMG_FIND_KEY_RESOURCE_FORK] = depth;
                state++;
            }
            if ((state == DMG_FIND_BASE_DICT) && (depth == stateDepth[state - 1] + 1) && (xmlStrcmp(nodeName, (const xmlChar *)"dict") == 0)) {
                dmg_parsemsg("read: Found dict start\n");
                stateDepth[DMG_FIND_BASE_DICT] = depth;
                state++;
            }
            if ((state == DMG_FIND_BASE_PLIST) && (xmlStrcmp(nodeName, (const xmlChar *)"plist") == 0)) {
                dmg_parsemsg("read: Found plist start\n");
                stateDepth[DMG_FIND_BASE_PLIST] = depth;
                state++;
            }
            xmlFree(nodeName);
        } else if ((nodeType == XML_READER_TYPE_END_ELEMENT) && (state > DMG_FIND_BASE_PLIST)) {
            int significantEnd = 0;
            int depth          = xmlTextReaderDepth(reader);
            if (depth < 0) {
                cli_mark_scan_incomplete(ctx, "DMG XML reader returned an invalid closing depth");
                ret = CL_EPARSE;
                break;
            } else if (depth < stateDepth[state - 1]) {
                significantEnd = 1;
            } else if ((depth == stateDepth[state - 1]) && (state - 1 == DMG_FIND_BLKX_CONTAINER)) {
                /* Special case, ending blkx container */
                significantEnd = 1;
            }
            if (significantEnd) {
                dmg_parsemsg("read: significant end tag, state %d\n", state);
                stateDepth[state - 1] = -1;
                state--;
                if ((state - 1 == DMG_FIND_KEY_RESOURCE_FORK) || (state - 1 == DMG_FIND_KEY_BLKX)) {
                    /* Keys end their own tag (validly) and the next state depends on the following tag */
                    // cli_dbgmsg("read: significant end tag ending prior key state\n");
                    stateDepth[state - 1] = -1;
                    state--;
                }
            } else {
                dmg_parsemsg("read: not significant end tag, state %d depth %d prior depth %d\n", state, depth, stateDepth[state - 1]);
            }
        }
    }

    if (ret == CL_CLEAN && (read_status < 0 || xml_input.failed || xml_input.remaining != 0)) {
        cli_mark_scan_incomplete(ctx, "DMG XML parsing ended before the resource fork was fully inspected");
        ret = CL_EPARSE;
    }
    if (xmlTextReaderClose(reader) != 0 && ret == CL_CLEAN) {
        cli_mark_scan_incomplete(ctx, "DMG streaming XML reader did not close cleanly");
        ret = CL_EPARSE;
    }
    xmlFreeTextReader(reader);

    if (ret == CL_CLEAN && mish_list == NULL) {
        cli_mark_scan_incomplete(ctx, "DMG XML did not provide any decodable blkx metadata");
        ret = CL_EPARSE;
    }

    /* Loop over mish array */
    file = 0;
    while ((ret == CL_CLEAN) && (mish_list != NULL)) {
        /* Handle & scan mish block */
        ret = dmg_handle_mish(ctx, file++, dirname, hdr.dataForkOffset,
                              hdr.dataForkLength, mish_list);
        free(mish_list->mish);
        mish_list_tail = mish_list;
        mish_list      = mish_list->next;
        free(mish_list_tail);
    }

    /* Cleanup */
    /* If error occurred, need to free mish items and mish blocks */
    while (mish_list != NULL) {
        free(mish_list->mish);
        mish_list_tail = mish_list;
        mish_list      = mish_list->next;
        free(mish_list_tail);
    }
    if (!ctx->engine->keeptmp)
        cli_rmdirs(dirname);
    free(dirname);
    return ret;
}

/* Transform the base64-encoded string into the binary structure
 * After this, the base64 string (from xml) can be released
 * If mish_set->mish is set by this function, it must be freed by the caller */
static int dmg_decode_mish(cli_ctx *ctx, unsigned int *mishblocknum, xmlChar *mish_base64,
                           struct dmg_mish_with_stripes *mish_set)
{
    size_t base64_len, encoded_chars, buff_size, decoded_len;
    uint8_t *decoded;
    const uint8_t mish_magic[4] = {0x6d, 0x69, 0x73, 0x68};
    uint64_t expected_len;
    uint32_t i;
    unsigned int end_count = 0;

    (*mishblocknum)++;
    base64_len = strlen((const char *)mish_base64);
    dmg_parsemsg("dmg_decode_mish: len of encoded block %u is %lu\n", *mishblocknum, base64_len);
    if (base64_len == 0 || base64_len > DMG_XML_PARSE_MAX_SIZE) {
        cli_dbgmsg("dmg_decode_mish: encoded block %u exceeds the bounded metadata size\n", *mishblocknum);
        return CL_EFORMAT;
    }
    if (dmg_validate_base64(mish_base64, base64_len, &encoded_chars) != CL_CLEAN) {
        cli_dbgmsg("dmg_decode_mish: block %u contains invalid Base64 syntax\n", *mishblocknum);
        return CL_EFORMAT;
    }

    /* The strict pass counted only significant Base64 characters, so XML
     * formatting whitespace cannot inflate the decoded allocation. */
    buff_size = (encoded_chars / 4) * 3 + 4;
    dmg_parsemsg("dmg_decode_mish: buffer for mish block %u is %lu\n", *mishblocknum, (unsigned long)buff_size);
    decoded = cli_max_malloc(buff_size);
    if (!decoded)
        return CL_EMEM;

    if (sf_base64decode((uint8_t *)mish_base64, base64_len, decoded, buff_size - 1, &decoded_len)) {
        cli_dbgmsg("dmg_decode_mish: failed base64 decoding on mish block %u\n", *mishblocknum);
        free(decoded);
        return CL_EFORMAT;
    }
    dmg_parsemsg("dmg_decode_mish: len of decoded mish block %u is %lu\n", *mishblocknum, (unsigned long)decoded_len);

    if (decoded_len < sizeof(struct dmg_mish_block)) {
        cli_dbgmsg("dmg_decode_mish: block %u too short for valid mish block\n", *mishblocknum);
        free(decoded);
        return CL_EFORMAT;
    }
    /* mish check: magic is mish, have to check after conversion from base64
     * mish base64 is bWlzaA [but last character can change last two bytes]
     * won't see that in practice much (affects value of version field) */
    if (memcmp(decoded, mish_magic, 4)) {
        cli_dbgmsg("dmg_decode_mish: block %u does not have mish magic\n", *mishblocknum);
        free(decoded);
        return CL_EFORMAT;
    }

    mish_set->mish              = (struct dmg_mish_block *)decoded;
    mish_set->mish->startSector = be64_to_host(mish_set->mish->startSector);
    mish_set->mish->sectorCount = be64_to_host(mish_set->mish->sectorCount);
    mish_set->mish->dataOffset  = be64_to_host(mish_set->mish->dataOffset);
    // mish_set->mish->bufferCount = be32_to_host(mish_set->mish->bufferCount);
    mish_set->mish->blockDataCount = be32_to_host(mish_set->mish->blockDataCount);
    if (mish_set->mish->blockDataCount == 0) {
        cli_dbgmsg("dmg_decode_mish: mish block %u has no stripe records\n", *mishblocknum);
        free(decoded);
        mish_set->mish = NULL;
        return CL_EFORMAT;
    }

    cli_dbgmsg("dmg_decode_mish: startSector = " STDu64 " sectorCount = " STDu64
               " dataOffset = " STDu64 " stripeCount = " STDu32 "\n",
               mish_set->mish->startSector, mish_set->mish->sectorCount,
               mish_set->mish->dataOffset, mish_set->mish->blockDataCount);

    /*
     * The decoded mish block must contain the fixed header followed by one
     * stripe record per blockDataCount. Calculate this requirement in a wide
     * integer domain, then compare decoded_len against that exact byte count.
     */
    expected_len = (uint64_t)sizeof(struct dmg_mish_block) +
                   (uint64_t)mish_set->mish->blockDataCount * (uint64_t)sizeof(struct dmg_block_data);
    if ((uint64_t)decoded_len < expected_len) {
        cli_dbgmsg("dmg_decode_mish: mish block %u too small\n", *mishblocknum);
        free(decoded);
        mish_set->mish = NULL;
        return CL_EFORMAT;
    } else if ((uint64_t)decoded_len > expected_len) {
        cli_dbgmsg("dmg_decode_mish: mish block %u contains trailing decoded metadata\n", *mishblocknum);
        free(decoded);
        mish_set->mish = NULL;
        return CL_EFORMAT;
    }

    mish_set->stripes = (struct dmg_block_data *)(decoded + sizeof(struct dmg_mish_block));

    /* A blkx table is terminated by exactly one END descriptor. Validate it
     * before any sorting can obscure its declared position. Control records
     * do not describe sectors or compressed input. */
    for (i = 0; i < mish_set->mish->blockDataCount; i++) {
        struct dmg_block_data *stripe = &mish_set->stripes[i];
        uint32_t type                 = be32_to_host(stripe->type);

        if ((i & 0xfffU) == 0) {
            int time_ret = cli_checktimelimit(ctx);

            if (time_ret != CL_CLEAN) {
                cli_mark_scan_incomplete(ctx, "DMG blkx terminator validation reached the configured time limit");
                free(decoded);
                mish_set->mish = NULL;
                return time_ret;
            }
        }
        if (type != DMG_STRIPE_END)
            continue;
        end_count++;
        if (end_count != 1 || i + 1 != mish_set->mish->blockDataCount ||
            be64_to_host(stripe->sectorCount) != 0 || be64_to_host(stripe->dataLength) != 0) {
            cli_dbgmsg("dmg_decode_mish: mish block %u has an invalid or non-terminal END stripe\n", *mishblocknum);
            free(decoded);
            mish_set->mish = NULL;
            return CL_EFORMAT;
        }
    }
    if (end_count != 1) {
        cli_dbgmsg("dmg_decode_mish: mish block %u has no terminal END stripe\n", *mishblocknum);
        free(decoded);
        mish_set->mish = NULL;
        return CL_EFORMAT;
    }
    return CL_CLEAN;
}

/**
 * @brief Compare DMG stripe entries by start sector for sorting.
 *
 * The sort only needs the sign of the comparison result, so compare the
 * 64-bit sector numbers directly and return -1, 0, or 1. This preserves the
 * full ordering across the entire uint64_t range: no intermediate subtraction
 * is needed, so there is no unsigned wrap and no truncation to the comparator's
 * int return type.
 *
 * @param stripe_a First DMG stripe entry.
 * @param stripe_b Second DMG stripe entry.
 * @return Negative if `stripe_a` starts first, positive if `stripe_b` starts
 * first, or zero if both start at the same sector.
 */
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
        ret = cli_checktimelimit(ctx);
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
        if (adcret == ADC_MEM_ERROR)
            return CL_EMEM;
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
            strm.next_in = (uint8_t *)input;
            strm.avail_in = window_len;
            off += window_len;
            remaining -= window_len;
        }

        strm.next_out  = obuf;
        strm.avail_out = sizeof(obuf);
        before_in      = strm.avail_in;
        before_state   = strm.state;
        adcret = adc_decompress(&strm);
        produced = sizeof(obuf) - strm.avail_out;

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
    uint64_t off       = mish_set->stripes[index].dataOffset;
    uint64_t remaining = mish_set->stripes[index].dataLength;
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
        if (zstat == Z_MEM_ERROR)
            return CL_EMEM;
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
        zstat = inflate(&strm, Z_NO_FLUSH); /* zlib */
        produced = sizeof(obuf) - strm.avail_out;

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
    uint64_t off       = mish_set->stripes[index].dataOffset;
    uint64_t remaining = mish_set->stripes[index].dataLength;
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
        if (rc == BZ_MEM_ERROR)
            return CL_EMEM;
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
        rc = BZ2_bzDecompress(&strm);
        produced = sizeof(obuf) - strm.avail_out;

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
    int ret        = CL_CLEAN, ofd;
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

    /* Prepare for file */
    snprintf(outfile, sizeof(outfile) - 1, "%s" PATHSEP "dmg%02u", dir, mishblocknum);
    outfile[sizeof(outfile) - 1] = '\0';
    ofd                          = open(outfile, O_RDWR | O_CREAT | O_EXCL | O_TRUNC | O_BINARY, 0600);
    if (ofd < 0) {
        char err[128];
        cli_errmsg("cli_scandmg: Can't create temporary file %s: %s\n",
                   outfile, cli_strerror(errno, err, sizeof(err)));
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

    close(ofd);
    if (!ctx->engine->keeptmp)
        if (cli_unlink(outfile)) return CL_EUNLINK;

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
        return CL_EMEM;
    }
    snprintf(xmlfile, namelen, "%s" PATHSEP "toc.xml", dir);
    cli_dbgmsg("cli_scandmg: Extracting XML as %s\n", xmlfile);

    /* Write out TOC XML in bounded windows. */
    if ((ofd = open(xmlfile, O_CREAT | O_RDWR | O_EXCL | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR)) < 0) {
        char err[128];
        cli_errmsg("cli_scandmg: Can't create temporary file %s: %s\n",
                   xmlfile, cli_strerror(errno, err, sizeof(err)));
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
        if (cli_writen(ofd, buffer, wanted) != wanted) {
            cli_errmsg("cli_scandmg: Not all XML bytes were written!\n");
            close(ofd);
            free(xmlfile);
            return CL_EWRITE;
        }
        offset += wanted;
        remaining -= wanted;
    }

    close(ofd);
    free(xmlfile);
    return CL_SUCCESS;
}
