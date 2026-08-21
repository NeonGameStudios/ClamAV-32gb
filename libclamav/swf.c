/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2011-2013 Sourcefire, Inc.
 *
 *  The code is based on Flasm, command line assembler & disassembler of Flash
 *  ActionScript bytecode Copyright (c) 2001 Opaque Industries, (c) 2002-2007
 *  Igor Kogan, (c) 2005 Wang Zhen. All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without modification,
 *  are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice, this list
 *  of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright notice, this
 *  list of conditions and the following disclaimer in the documentation and/or other
 *  materials provided with the distribution.
 *  - Neither the name of the Opaque Industries nor the names of its contributors may
 *  be used to endorse or promote products derived from this software without specific
 *  prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 *  EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 *  OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 *  SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 *  TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 *  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
 *  WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <time.h>
#include <zlib.h>

#include "swf.h"
#include "clamav.h"
#include "scanners.h"
#include "lzma_iface.h"

#define EC16(v) le16_to_host(v)
#define EC32(v) le32_to_host(v)

#define INITBITS                                                                       \
    {                                                                                  \
        if (fmap_readn(map, &get_c, offset, sizeof(get_c)) == sizeof(get_c)) {         \
            bitpos = 8;                                                                \
            bitbuf = (unsigned int)get_c;                                              \
            offset += sizeof(get_c);                                                   \
        } else {                                                                       \
            cli_warnmsg("cli_scanswf: INITBITS: Can't read file or file truncated\n"); \
            cli_mark_scan_incomplete(ctx, "SWF frame metadata was truncated");         \
            return CL_EFORMAT;                                                         \
        }                                                                              \
    }

#define GETBITS(v, n)                                                                     \
    {                                                                                     \
        getbits_n = n;                                                                    \
        bits      = 0;                                                                    \
        while (getbits_n > bitpos) {                                                      \
            getbits_n -= bitpos;                                                          \
            bits |= bitbuf << getbits_n;                                                  \
            if (fmap_readn(map, &get_c, offset, sizeof(get_c)) == sizeof(get_c)) {        \
                bitbuf = (unsigned int)get_c;                                             \
                bitpos = 8;                                                               \
                offset += sizeof(get_c);                                                  \
            } else {                                                                      \
                cli_warnmsg("cli_scanswf: GETBITS: Can't read file or file truncated\n"); \
                cli_mark_scan_incomplete(ctx, "SWF frame metadata was truncated");        \
                return CL_EFORMAT;                                                        \
            }                                                                             \
        }                                                                                 \
        bitpos -= getbits_n;                                                              \
        bits |= bitbuf >> bitpos;                                                         \
        bitbuf &= 0xff >> (8 - bitpos);                                                   \
        v = bits & 0xffff;                                                                \
    }

#define GETWORD(v)                                                                    \
    {                                                                                 \
        if (fmap_readn(map, &get_c, offset, sizeof(get_c)) == sizeof(get_c)) {        \
            getword_1 = (unsigned int)get_c;                                          \
            offset += sizeof(get_c);                                                  \
        } else {                                                                      \
            cli_warnmsg("cli_scanswf: GETWORD: Can't read file or file truncated\n"); \
            cli_mark_scan_incomplete(ctx, "SWF frame metadata was truncated");        \
            return CL_EFORMAT;                                                        \
        }                                                                             \
        if (fmap_readn(map, &get_c, offset, sizeof(get_c)) == sizeof(get_c)) {        \
            getword_2 = (unsigned int)get_c;                                          \
            offset += sizeof(get_c);                                                  \
        } else {                                                                      \
            cli_warnmsg("cli_scanswf: GETWORD: Can't read file or file truncated\n"); \
            cli_mark_scan_incomplete(ctx, "SWF frame metadata was truncated");        \
            return CL_EFORMAT;                                                        \
        }                                                                             \
        v = (uint16_t)(getword_1 & 0xff) | ((getword_2 & 0xff) << 8);                 \
    }

#define GETDWORD(v)                                      \
    {                                                    \
        GETWORD(getdword_1);                             \
        GETWORD(getdword_2);                             \
        v = (uint32_t)(getdword_1 | (getdword_2 << 16)); \
    }

struct swf_file_hdr {
    char signature[3];
    uint8_t version;
    uint32_t filesize;
};

static cl_error_t swf_cleanup_temp(cli_ctx *ctx, int fd, char *tmpname, cl_error_t status,
                                   uint64_t temporary_reserved)
{
    if (close(fd) == -1) {
        cli_mark_scan_incomplete(ctx, "SWF temporary output could not be closed");
        if ((status == CL_SUCCESS) || (status == CL_BREAK))
            status = CL_EUNLINK;
    }
    if (!ctx->engine->keeptmp && cli_unlink(tmpname)) {
        cli_mark_scan_incomplete(ctx, "SWF temporary output could not be removed");
        if ((status == CL_SUCCESS) || (status == CL_BREAK))
            status = CL_EUNLINK;
    }
    if (temporary_reserved)
        cli_scan_release_temporary(ctx, temporary_reserved);
    free(tmpname);
    return status;
}

static cl_error_t swf_reserve_output(cli_ctx *ctx, uint64_t *reserved, size_t bytes)
{
    cl_error_t status;

    if (bytes == 0)
        return CL_SUCCESS;
    if (NULL == reserved || UINT64_MAX - *reserved < (uint64_t)bytes) {
        cli_mark_scan_incomplete(ctx, "SWF output size overflowed temporary quota accounting");
        return CL_ERESOURCE;
    }
    status = cli_scan_reserve_temporary(ctx, (uint64_t)bytes);
    if (status != CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, "SWF output exceeds temporary storage limits");
        return status;
    }
    *reserved += (uint64_t)bytes;
    return CL_SUCCESS;
}

static cl_error_t scanzws(cli_ctx *ctx, struct swf_file_hdr *hdr)
{
    struct CLI_LZMA lz;
    unsigned char inbuff[FILEBUFF], outbuff[FILEBUFF];
    fmap_t *map = ctx->fmap;
    /* strip off header */
    size_t offset = 8;
    uint32_t d_insize;
    size_t outsize = 8;
    cl_error_t ret;
    cl_error_t decode_status = CL_SUCCESS;
    int lret;
    size_t count;
    char *tmpname;
    int fd;
    size_t n_read;
    uint64_t temporary_reserved = 0;

    if ((ret = cli_gentempfd(ctx->this_layer_tmpdir, &tmpname, &fd)) != CL_SUCCESS) {
        cli_errmsg("scanzws: Can't generate temporary file\n");
        return ret;
    }

    if ((ret = swf_reserve_output(ctx, &temporary_reserved, sizeof(struct swf_file_hdr))) != CL_SUCCESS) {
        return swf_cleanup_temp(ctx, fd, tmpname, ret, 0);
    }

    hdr->signature[0] = 'F';
    if (cli_writen(fd, hdr, sizeof(struct swf_file_hdr)) != sizeof(struct swf_file_hdr)) {
        cli_errmsg("scanzws: Can't write to file %s\n", tmpname);
        return swf_cleanup_temp(ctx, fd, tmpname, CL_EWRITE, temporary_reserved);
    }

    /* read 4 bytes (for compressed 32-bit filesize) [not used for LZMA] */
    if (fmap_readn(map, &d_insize, offset, sizeof(d_insize)) != sizeof(d_insize)) {
        cli_errmsg("scanzws: Error reading SWF file\n");
        return swf_cleanup_temp(ctx, fd, tmpname, CL_EREAD, temporary_reserved);
    }
    offset += sizeof(d_insize);

    /* check if declared input size matches actual output size */
    /* map->len = header (8 bytes) + d_insize (4 bytes) + flags (5 bytes) + compressed stream */
    if (d_insize != (map->len - 17)) {
        cli_warnmsg("SWF: declared input length != compressed stream size, %u != %llu\n",
                    d_insize, (long long unsigned)(map->len - 17));
    } else {
        cli_dbgmsg("SWF: declared input length == compressed stream size, %u == %llu\n",
                   d_insize, (long long unsigned)(map->len - 17));
    }

    /* first buffer required for initializing LZMA */
    n_read = fmap_readn(map, inbuff, offset, FILEBUFF);
    if (n_read == (size_t)-1) {
        cli_errmsg("scanzws: Error reading SWF file\n");
        return swf_cleanup_temp(ctx, fd, tmpname, CL_EUNPACK, temporary_reserved);
    }
    /* nothing written, likely truncated */
    if (0 == n_read) {
        cli_errmsg("scanzws: possibly truncated file\n");
        return swf_cleanup_temp(ctx, fd, tmpname, CL_EFORMAT, temporary_reserved);
    }
    offset += n_read;

    memset(&lz, 0, sizeof(lz));
    lz.next_in   = inbuff;
    lz.next_out  = outbuff;
    lz.avail_in  = n_read;
    lz.avail_out = FILEBUFF;

    lret = cli_LzmaInit(&lz, hdr->filesize);
    if (lret != LZMA_RESULT_OK) {
        cli_errmsg("scanzws: LzmaInit() failed\n");
        return swf_cleanup_temp(ctx, fd, tmpname, CL_EUNPACK, temporary_reserved);
    }

    while (lret == LZMA_RESULT_OK) {
        if (lz.avail_in == 0) {
            lz.next_in = inbuff;

            n_read = fmap_readn(map, inbuff, offset, FILEBUFF);
            if ((size_t)-1 == n_read) {
                cli_errmsg("scanzws: Error reading SWF file\n");
                cli_LzmaShutdown(&lz);
                return swf_cleanup_temp(ctx, fd, tmpname, CL_EUNPACK, temporary_reserved);
            }
            if (0 == n_read)
                break;
            lz.avail_in = n_read;
            offset += n_read;
        }
        lret  = cli_LzmaDecode(&lz);
        count = FILEBUFF - lz.avail_out;
        if (count) {
            if ((decode_status = cli_checklimits("SWF", ctx, outsize + count, 0, 0)) != CL_SUCCESS)
                break;
            if ((decode_status = swf_reserve_output(ctx, &temporary_reserved, count)) != CL_SUCCESS)
                break;
            if (cli_writen(fd, outbuff, count) != count) {
                cli_errmsg("scanzws: Can't write to file %s\n", tmpname);
                cli_mark_scan_incomplete(ctx, "SWF LZMA output could not be written completely");
                decode_status = CL_EWRITE;
                cli_LzmaShutdown(&lz);
                return swf_cleanup_temp(ctx, fd, tmpname, CL_EWRITE, temporary_reserved);
            }
            outsize += count;
        }
        lz.next_out  = outbuff;
        lz.avail_out = FILEBUFF;
    }

    cli_LzmaShutdown(&lz);

    /* A ZWS decoder must reach its terminal state before any decompressed
     * bytes are handed to the nested scanner. EOF, decoder errors, and
     * configured limits leave only a partial temporary member. */
    if (decode_status != CL_SUCCESS || lret != LZMA_STREAM_END) {
        if (decode_status == CL_SUCCESS) {
            cli_mark_scan_incomplete(ctx, "SWF LZMA stream ended before decompression completed");
            decode_status = CL_EUNPACK;
        }
        return swf_cleanup_temp(ctx, fd, tmpname, decode_status, temporary_reserved);
    }
    cli_dbgmsg("SWF: Decompressed[LZMA] to %s, size %llu\n", tmpname, (long long unsigned)outsize);

    /* check if declared output size matches actual output size */
    if (hdr->filesize != outsize) {
        cli_warnmsg("SWF: declared output length != inflated stream size, %u != %llu\n",
                    hdr->filesize, (long long unsigned)outsize);
        cli_mark_scan_incomplete(ctx, "SWF LZMA output length disagrees with its header");
        return swf_cleanup_temp(ctx, fd, tmpname, CL_EPARSE, temporary_reserved);
    }
    cli_dbgmsg("SWF: declared output length == inflated stream size, %u == %llu\n",
               hdr->filesize, (long long unsigned)outsize);

    ret = cli_magic_scan_desc_type_reserved(fd, tmpname, ctx, CL_TYPE_ANY, NULL, LAYER_ATTRIBUTES_NONE);
    return swf_cleanup_temp(ctx, fd, tmpname, ret, temporary_reserved);
}

static cl_error_t scancws(cli_ctx *ctx, struct swf_file_hdr *hdr)
{
    z_stream stream;
    char inbuff[FILEBUFF], outbuff[FILEBUFF];
    fmap_t *map   = ctx->fmap;
    size_t offset = 8;
    int zret      = Z_OK, zend;
    cl_error_t ret;
    cl_error_t decode_status = CL_SUCCESS;
    size_t outsize           = 8;
    size_t count;
    size_t n_read;
    char *tmpname;
    int fd;
    uint64_t temporary_reserved = 0;

    if ((ret = cli_gentempfd(ctx->this_layer_tmpdir, &tmpname, &fd)) != CL_SUCCESS) {
        cli_errmsg("scancws: Can't generate temporary file\n");
        return ret;
    }

    if ((ret = swf_reserve_output(ctx, &temporary_reserved, sizeof(struct swf_file_hdr))) != CL_SUCCESS) {
        return swf_cleanup_temp(ctx, fd, tmpname, ret, 0);
    }

    hdr->signature[0] = 'F';
    if (cli_writen(fd, hdr, sizeof(struct swf_file_hdr)) != sizeof(struct swf_file_hdr)) {
        cli_errmsg("scancws: Can't write to file %s\n", tmpname);
        return swf_cleanup_temp(ctx, fd, tmpname, CL_EWRITE, temporary_reserved);
    }

    stream.avail_in  = 0;
    stream.next_in   = (Bytef *)inbuff;
    stream.next_out  = (Bytef *)outbuff;
    stream.zalloc    = (alloc_func)NULL;
    stream.zfree     = (free_func)NULL;
    stream.opaque    = (voidpf)0;
    stream.avail_out = FILEBUFF;

    zret = inflateInit(&stream);
    if (zret != Z_OK) {
        cli_errmsg("scancws: inflateInit() failed\n");
        return swf_cleanup_temp(ctx, fd, tmpname, CL_EUNPACK, temporary_reserved);
    }

    do {
        if (stream.avail_in == 0) {
            stream.next_in = (Bytef *)inbuff;
            n_read         = fmap_readn(map, inbuff, offset, FILEBUFF);
            if (n_read == (size_t)-1) {
                cli_errmsg("scancws: Error reading SWF file\n");
                inflateEnd(&stream);
                return swf_cleanup_temp(ctx, fd, tmpname, CL_EUNPACK, temporary_reserved);
            }
            if (0 == n_read)
                break;
            stream.avail_in = n_read;
            offset += n_read;
        }
        zret  = inflate(&stream, Z_SYNC_FLUSH);
        count = FILEBUFF - stream.avail_out;
        if (count) {
            if ((decode_status = cli_checklimits("SWF", ctx, outsize + count, 0, 0)) != CL_SUCCESS)
                break;
            if ((decode_status = swf_reserve_output(ctx, &temporary_reserved, count)) != CL_SUCCESS)
                break;
            if (cli_writen(fd, outbuff, count) != count) {
                cli_errmsg("scancws: Can't write to file %s\n", tmpname);
                cli_mark_scan_incomplete(ctx, "SWF zlib output could not be written completely");
                decode_status = CL_EWRITE;
                inflateEnd(&stream);
                return swf_cleanup_temp(ctx, fd, tmpname, CL_EWRITE, temporary_reserved);
            }
            outsize += count;
        }
        stream.next_out  = (Bytef *)outbuff;
        stream.avail_out = FILEBUFF;
    } while (zret == Z_OK);

    zend = inflateEnd(&stream);

    /* A CWS decoder must reach Z_STREAM_END; scanning output after a
     * truncated/error stream would turn a partial SWF into an apparent clean
     * result. */
    if (decode_status != CL_SUCCESS || zret != Z_STREAM_END || zend != Z_OK) {
        if (decode_status == CL_SUCCESS) {
            cli_mark_scan_incomplete(ctx, "SWF zlib stream ended before decompression completed");
            decode_status = CL_EUNPACK;
        }
        return swf_cleanup_temp(ctx, fd, tmpname, decode_status, temporary_reserved);
    }
    cli_dbgmsg("SWF: Decompressed[zlib] to %s, size %zu\n", tmpname, outsize);

    /* check if declared output size matches actual output size */
    if (hdr->filesize != outsize) {
        cli_warnmsg("SWF: declared output length != inflated stream size, %u != %zu\n",
                    hdr->filesize, outsize);
        cli_mark_scan_incomplete(ctx, "SWF zlib output length disagrees with its header");
        return swf_cleanup_temp(ctx, fd, tmpname, CL_EPARSE, temporary_reserved);
    }
    cli_dbgmsg("SWF: declared output length == inflated stream size, %u == %zu\n",
               hdr->filesize, outsize);

    ret = cli_magic_scan_desc_type_reserved(fd, tmpname, ctx, CL_TYPE_ANY, NULL, LAYER_ATTRIBUTES_NONE);
    return swf_cleanup_temp(ctx, fd, tmpname, ret, temporary_reserved);
}

static const char *tagname(tag_id id)
{
    unsigned int i;

    for (i = 0; tag_names[i].name; i++)
        if (tag_names[i].id == id)
            return tag_names[i].name;
    return NULL;
}

cl_error_t cli_scanswf(cli_ctx *ctx)
{
    struct swf_file_hdr file_hdr;
    fmap_t *map = ctx->fmap;
    unsigned int bitpos, bitbuf, getbits_n, nbits, getword_1, getword_2, getdword_1, getdword_2;
    const char *pt;
    unsigned char get_c;
    size_t offset = 0;
    unsigned int val, foo, tag_hdr, tag_type, tag_len;
    unsigned long int bits;

    cli_dbgmsg("in cli_scanswf()\n");

    if (fmap_readn(map, &file_hdr, offset, sizeof(file_hdr)) != sizeof(file_hdr)) {
        cli_mark_scan_incomplete(ctx, "SWF file header was truncated");
        cli_dbgmsg("SWF: Can't read file header\n");
        return CL_EPARSE;
    }
    offset += sizeof(file_hdr);
    /*
    **  SWF stores the integer bytes with the least significate byte first
    */

    file_hdr.filesize = le32_to_host(file_hdr.filesize);

    cli_dbgmsg("SWF: Version: %u\n", file_hdr.version);
    cli_dbgmsg("SWF: File size: %u\n", file_hdr.filesize);

    if (!strncmp(file_hdr.signature, "CWS", 3)) {
        cli_dbgmsg("SWF: zlib compressed file\n");
        return scancws(ctx, &file_hdr);
    } else if (!strncmp(file_hdr.signature, "ZWS", 3)) {
        cli_dbgmsg("SWF: LZMA compressed file\n");
        return scanzws(ctx, &file_hdr);
    } else if (!strncmp(file_hdr.signature, "FWS", 3)) {
        cli_dbgmsg("SWF: Uncompressed file\n");
        if (file_hdr.filesize < sizeof(file_hdr) || file_hdr.filesize > map->len) {
            cli_mark_scan_incomplete(ctx, "SWF uncompressed file was shorter than its declared size");
            return CL_EPARSE;
        }
    } else {
        cli_dbgmsg("SWF: Not a SWF file\n");
        return CL_CLEAN;
    }

    INITBITS;

    GETBITS(nbits, 5);
    cli_dbgmsg("SWF: FrameSize RECT size bits: %u\n", nbits);
    {
        uint32_t xMin = 0, xMax = 0, yMin = 0, yMax = 0;
        GETBITS(xMin, nbits); /* Should be zero */
        GETBITS(xMax, nbits);
        GETBITS(yMin, nbits); /* Should be zero */
        GETBITS(yMax, nbits);
        cli_dbgmsg("SWF: FrameSize xMin %u xMax %u yMin %u yMax %u\n", xMin, xMax, yMin, yMax);
    }

    /* We don't need the value from foo, we're just reading to increment the offset safely. */
    GETWORD(foo);
    UNUSEDPARAM(foo);

    GETWORD(val);
    cli_dbgmsg("SWF: Frames total: %d\n", val);

    /* Skip Flash tag walk unless debug mode */
    if (!cli_debug_flag) {
        return CL_CLEAN;
    }

    while (offset < map->len) {
        GETWORD(tag_hdr);
        tag_type = tag_hdr >> 6;
        if (tag_type == 0)
            break;
        tag_len = tag_hdr & 0x3f;
        if (tag_len == 0x3f)
            GETDWORD(tag_len);

        pt = tagname(tag_type);
        cli_dbgmsg("SWF: %s\n", pt ? pt : "UNKNOWN TAG");
        cli_dbgmsg("SWF: Tag length: %u\n", tag_len);
        if ((size_t)tag_len > map->len - offset) {
            cli_warnmsg("SWF: Tag payload is truncated or its length is too large.\n");
            cli_mark_scan_incomplete(ctx, "SWF tag payload was truncated");
            return CL_EPARSE;
        }
        if (!pt) {
            offset += tag_len;
            continue;
        }

        switch (tag_type) {
            case TAG_SCRIPTLIMITS: {
                unsigned int recursion, timeout;
                GETWORD(recursion);
                GETWORD(timeout);
                cli_dbgmsg("SWF: scriptLimits recursion %u timeout %u\n", recursion, timeout);
                break;
            }

            case TAG_FILEATTRIBUTES:
                GETDWORD(val);
                cli_dbgmsg("SWF: File attributes:\n");
                if (val & SWF_ATTR_USENETWORK)
                    cli_dbgmsg("    * Use network\n");
                if (val & SWF_ATTR_RELATIVEURLS)
                    cli_dbgmsg("    * Relative URLs\n");
                if (val & SWF_ATTR_SUPPRESSCROSSDOMAINCACHE)
                    cli_dbgmsg("    * Suppress cross domain cache\n");
                if (val & SWF_ATTR_ACTIONSCRIPT3)
                    cli_dbgmsg("    * ActionScript 3.0\n");
                if (val & SWF_ATTR_HASMETADATA)
                    cli_dbgmsg("    * Has metadata\n");
                if (val & SWF_ATTR_USEDIRECTBLIT)
                    cli_dbgmsg("    * Use hardware acceleration\n");
                if (val & SWF_ATTR_USEGPU)
                    cli_dbgmsg("    * Use GPU\n");
                break;

            default:
                offset += tag_len;
                continue;
        }
    }

    return CL_CLEAN;
}
