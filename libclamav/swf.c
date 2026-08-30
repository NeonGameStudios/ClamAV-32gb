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

static cl_error_t swf_read_exact(fmap_t *map, void *dst, size_t offset, size_t length, size_t end)
{
    size_t nread;

    if (offset > end || length > end - offset)
        return CL_EFORMAT;

    nread = fmap_readn(map, dst, offset, length);

    if (nread == length)
        return CL_SUCCESS;
    if (nread == (size_t)-1 && offset <= map->len && length <= map->len - offset)
        return CL_EREAD;
    return CL_EFORMAT;
}

static cl_error_t swf_read_chunk(fmap_t *map, void *dst, size_t offset, size_t length, size_t *nread)
{
    *nread = fmap_readn(map, dst, offset, length);
    if (*nread != (size_t)-1)
        return CL_SUCCESS;
    /* fmap_readn() clips a request that crosses EOF before asking the
     * backing map for data. A callback failure in that clipped prefix is
     * therefore still a truncated compressed stream, not an in-range read
     * failure for the caller's original request. */
    if (offset > map->len || length > map->len - offset)
        return CL_EFORMAT;
    return CL_EREAD;
}

static cl_error_t swf_read_failure(cli_ctx *ctx, cl_error_t status, const char *truncated_reason,
                                   const char *read_failure_reason)
{
    cli_mark_scan_incomplete(ctx, status == CL_EREAD ? read_failure_reason : truncated_reason);
    return status;
}

static cl_error_t swf_checktimelimit(cli_ctx *ctx, const char *reason)
{
    cl_error_t status = cli_checktimelimit(ctx);

    if (status != CL_SUCCESS)
        cli_mark_scan_incomplete(ctx, reason);

    return status;
}

cl_error_t cli_swf_output_size_add(size_t current, size_t amount, size_t *next)
{
    if (next == NULL)
        return CL_EARG;
    if (amount > SIZE_MAX - current)
        return CL_ERESOURCE;
    *next = current + amount;
    return CL_SUCCESS;
}

static cl_error_t swf_scan_overlay(cli_ctx *ctx, fmap_t *map, size_t offset)
{
    if (map->len <= offset)
        return CL_SUCCESS;

    cli_dbgmsg("SWF: Found %zu additional bytes after the declared file; scanning as a nested file.\n",
               map->len - offset);
    if (ctx->engine == NULL) {
        cli_mark_scan_incomplete(ctx, "SWF overlay scan requires an owning engine");
        return CL_ENULLARG;
    }
    return cli_magic_scan_nested_fmap_type(map, offset, map->len - offset, ctx, CL_TYPE_ANY, NULL,
                                           LAYER_ATTRIBUTES_NONE);
}

#define INITBITS                                                                       \
    {                                                                                  \
        cl_error_t read_status = swf_read_exact(map, &get_c, offset, sizeof(get_c), parse_end); \
        if (read_status == CL_SUCCESS) {                                               \
            bitpos = 8;                                                                \
            bitbuf = (unsigned int)get_c;                                              \
            offset += sizeof(get_c);                                                   \
        } else {                                                                       \
            cli_warnmsg("cli_scanswf: INITBITS: Can't read file or file truncated\n"); \
            return swf_read_failure(ctx, read_status, "SWF frame metadata was truncated", \
                                    "SWF frame metadata could not be read completely"); \
        }                                                                              \
    }

#define GETBITS(v, n)                                                                     \
    {                                                                                     \
        getbits_n = n;                                                                    \
        bits      = 0;                                                                    \
        while (getbits_n > bitpos) {                                                      \
            getbits_n -= bitpos;                                                          \
            bits |= bitbuf << getbits_n;                                                  \
            read_status = swf_read_exact(map, &get_c, offset, sizeof(get_c), parse_end); \
            if (read_status == CL_SUCCESS) {                                             \
                bitbuf = (unsigned int)get_c;                                             \
                bitpos = 8;                                                               \
                offset += sizeof(get_c);                                                  \
            } else {                                                                      \
                cli_warnmsg("cli_scanswf: GETBITS: Can't read file or file truncated\n"); \
                return swf_read_failure(ctx, read_status, "SWF frame metadata was truncated", \
                                        "SWF frame metadata could not be read completely"); \
            }                                                                             \
        }                                                                                 \
        bitpos -= getbits_n;                                                              \
        bits |= bitbuf >> bitpos;                                                         \
        bitbuf &= 0xff >> (8 - bitpos);                                                   \
        v = bits & 0xffff;                                                                \
    }

#define GETWORD(v)                                                                    \
    {                                                                                 \
        read_status = swf_read_exact(map, &get_c, offset, sizeof(get_c), parse_end);   \
        if (read_status == CL_SUCCESS) {                                              \
            getword_1 = (unsigned int)get_c;                                          \
            offset += sizeof(get_c);                                                  \
        } else {                                                                      \
            cli_warnmsg("cli_scanswf: GETWORD: Can't read file or file truncated\n"); \
            return swf_read_failure(ctx, read_status, "SWF frame metadata was truncated", \
                                    "SWF frame metadata could not be read completely"); \
        }                                                                             \
        read_status = swf_read_exact(map, &get_c, offset, sizeof(get_c), parse_end);   \
        if (read_status == CL_SUCCESS) {                                              \
            getword_2 = (unsigned int)get_c;                                          \
            offset += sizeof(get_c);                                                  \
        } else {                                                                      \
            cli_warnmsg("cli_scanswf: GETWORD: Can't read file or file truncated\n"); \
            return swf_read_failure(ctx, read_status, "SWF frame metadata was truncated", \
                                    "SWF frame metadata could not be read completely"); \
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
        status = cli_merge_cleanup_status(status, CL_EWRITE);
    }
    if (!ctx->engine->keeptmp && cli_unlink(tmpname)) {
        cli_mark_scan_incomplete(ctx, "SWF temporary output could not be removed");
        status = cli_merge_cleanup_status(status, CL_EUNLINK);
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
    status = swf_checktimelimit(ctx, "SWF temporary output reached the configured time limit");
    if (status != CL_SUCCESS)
        return status;
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

static cl_error_t swf_write_output(cli_ctx *ctx, int fd, const void *data, size_t bytes,
                                   uint64_t *reserved, const char *failure_reason)
{
    cl_error_t status;

    status = swf_reserve_output(ctx, reserved, bytes);
    if (status != CL_SUCCESS)
        return status;

    status = swf_checktimelimit(ctx, "SWF output write reached the configured time limit");
    if (status != CL_SUCCESS) {
        if (reserved != NULL && *reserved >= (uint64_t)bytes) {
            cli_scan_release_temporary(ctx, (uint64_t)bytes);
            *reserved -= (uint64_t)bytes;
        }
        return status;
    }

    if (cli_writen(fd, data, bytes) != bytes) {
        if (reserved != NULL && *reserved >= (uint64_t)bytes) {
            cli_scan_release_temporary(ctx, (uint64_t)bytes);
            *reserved -= (uint64_t)bytes;
        }
        cli_mark_scan_incomplete(ctx, failure_reason);
        return CL_EWRITE;
    }

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
    size_t next_outsize;
    char *tmpname;
    int fd;
    size_t n_read;
    uint64_t temporary_reserved = 0;

    if ((ret = cli_gentempfd(ctx->this_layer_tmpdir, &tmpname, &fd)) != CL_SUCCESS) {
        cli_errmsg("scanzws: Can't generate temporary file\n");
        cli_mark_scan_incomplete(ctx, "SWF LZMA temporary output could not be created");
        return ret;
    }

    hdr->signature[0] = 'F';
    if ((ret = swf_write_output(ctx, fd, hdr, sizeof(struct swf_file_hdr), &temporary_reserved,
                                "SWF LZMA header could not be written completely")) != CL_SUCCESS) {
        return swf_cleanup_temp(ctx, fd, tmpname, ret, 0);
    }

    /* read 4 bytes (for compressed 32-bit filesize) [not used for LZMA] */
    ret = swf_read_exact(map, &d_insize, offset, sizeof(d_insize), map->len);
    if (ret != CL_SUCCESS) {
        cli_errmsg("scanzws: Error reading SWF file\n");
        ret = swf_read_failure(ctx, ret, "SWF LZMA input-length field was truncated",
                               "SWF LZMA input-length field could not be read completely");
        return swf_cleanup_temp(ctx, fd, tmpname, ret, temporary_reserved);
    }
    offset += sizeof(d_insize);

    /* map->len = header (8 bytes) + d_insize (4 bytes) + flags (5 bytes) + compressed stream */
    if (map->len < 17) {
        cli_mark_scan_incomplete(ctx, "SWF LZMA compressed length header was truncated");
        return swf_cleanup_temp(ctx, fd, tmpname, CL_EPARSE, temporary_reserved);
    }
    if ((uint64_t)d_insize != (uint64_t)(map->len - 17)) {
        cli_warnmsg("SWF: declared input length != compressed stream size, %u != %llu\n",
                    d_insize, (long long unsigned)(map->len - 17));
        cli_mark_scan_incomplete(ctx, "SWF LZMA compressed length disagreed with input");
        return swf_cleanup_temp(ctx, fd, tmpname, CL_EPARSE, temporary_reserved);
    }
    cli_dbgmsg("SWF: declared input length == compressed stream size, %u == %llu\n",
               d_insize, (long long unsigned)(map->len - 17));

    /* first buffer required for initializing LZMA */
    ret = swf_read_chunk(map, inbuff, offset, FILEBUFF, &n_read);
    if (ret != CL_SUCCESS) {
        cli_errmsg("scanzws: Error reading SWF file\n");
        ret = swf_read_failure(ctx, ret, "SWF LZMA compressed input was truncated",
                               "SWF LZMA compressed input could not be read completely");
        return swf_cleanup_temp(ctx, fd, tmpname, ret, temporary_reserved);
    }
    /* nothing written, likely truncated */
    if (0 == n_read) {
        cli_errmsg("scanzws: possibly truncated file\n");
        ret = swf_read_failure(ctx, CL_EFORMAT, "SWF LZMA compressed input was truncated",
                               "SWF LZMA compressed input could not be read completely");
        return swf_cleanup_temp(ctx, fd, tmpname, ret, temporary_reserved);
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
        cli_mark_scan_incomplete(ctx, "SWF LZMA decoder could not be initialized");
        return swf_cleanup_temp(ctx, fd, tmpname, CL_EUNPACK, temporary_reserved);
    }

    while (lret == LZMA_RESULT_OK) {
        ret = swf_checktimelimit(ctx, "SWF LZMA traversal reached the configured time limit");
        if (ret != CL_SUCCESS) {
            cli_LzmaShutdown(&lz);
            return swf_cleanup_temp(ctx, fd, tmpname, ret, temporary_reserved);
        }

        if (lz.avail_in == 0) {
            lz.next_in = inbuff;

            ret = swf_read_chunk(map, inbuff, offset, FILEBUFF, &n_read);
            if (ret != CL_SUCCESS) {
                cli_errmsg("scanzws: Error reading SWF file\n");
                cli_LzmaShutdown(&lz);
                ret = swf_read_failure(ctx, ret, "SWF LZMA compressed input was truncated",
                                       "SWF LZMA compressed input could not be read completely");
                return swf_cleanup_temp(ctx, fd, tmpname, ret, temporary_reserved);
            }
            if (0 == n_read)
                break;
            lz.avail_in = n_read;
            offset += n_read;
        }
        lret  = cli_LzmaDecode(&lz);
        count = FILEBUFF - lz.avail_out;
        if (count) {
            if ((decode_status = cli_swf_output_size_add(outsize, count, &next_outsize)) != CL_SUCCESS) {
                cli_mark_scan_incomplete(ctx, "SWF decompressed output size overflowed");
                break;
            }
            if ((decode_status = cli_checklimits("SWF", ctx, next_outsize, 0, 0)) != CL_SUCCESS)
                break;
            if ((decode_status = swf_write_output(ctx, fd, outbuff, count, &temporary_reserved,
                                                  "SWF LZMA output could not be written completely")) != CL_SUCCESS) {
                cli_errmsg("scanzws: Can't write to file %s\n", tmpname);
                cli_LzmaShutdown(&lz);
                return swf_cleanup_temp(ctx, fd, tmpname, decode_status, temporary_reserved);
            }
            outsize = next_outsize;
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
    size_t next_outsize;
    size_t n_read;
    char *tmpname;
    int fd;
    uint64_t temporary_reserved = 0;

    if ((ret = cli_gentempfd(ctx->this_layer_tmpdir, &tmpname, &fd)) != CL_SUCCESS) {
        cli_errmsg("scancws: Can't generate temporary file\n");
        cli_mark_scan_incomplete(ctx, "SWF zlib temporary output could not be created");
        return ret;
    }

    hdr->signature[0] = 'F';
    if ((ret = swf_write_output(ctx, fd, hdr, sizeof(struct swf_file_hdr), &temporary_reserved,
                                "SWF zlib header could not be written completely")) != CL_SUCCESS) {
        return swf_cleanup_temp(ctx, fd, tmpname, ret, 0);
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
        cli_mark_scan_incomplete(ctx, "SWF zlib decoder could not be initialized");
        return swf_cleanup_temp(ctx, fd, tmpname, CL_EUNPACK, temporary_reserved);
    }

    do {
        ret = swf_checktimelimit(ctx, "SWF zlib traversal reached the configured time limit");
        if (ret != CL_SUCCESS) {
            inflateEnd(&stream);
            return swf_cleanup_temp(ctx, fd, tmpname, ret, temporary_reserved);
        }

        if (stream.avail_in == 0) {
            stream.next_in = (Bytef *)inbuff;
            ret = swf_read_chunk(map, inbuff, offset, FILEBUFF, &n_read);
            if (ret != CL_SUCCESS) {
                cli_errmsg("scancws: Error reading SWF file\n");
                inflateEnd(&stream);
                ret = swf_read_failure(ctx, ret, "SWF zlib compressed input was truncated",
                                       "SWF zlib compressed input could not be read completely");
                return swf_cleanup_temp(ctx, fd, tmpname, ret, temporary_reserved);
            }
            if (0 == n_read)
                break;
            stream.avail_in = n_read;
            offset += n_read;
        }
        zret  = inflate(&stream, Z_SYNC_FLUSH);
        count = FILEBUFF - stream.avail_out;
        if (count) {
            if ((decode_status = cli_swf_output_size_add(outsize, count, &next_outsize)) != CL_SUCCESS) {
                cli_mark_scan_incomplete(ctx, "SWF decompressed output size overflowed");
                break;
            }
            if ((decode_status = cli_checklimits("SWF", ctx, next_outsize, 0, 0)) != CL_SUCCESS)
                break;
            if ((decode_status = swf_write_output(ctx, fd, outbuff, count, &temporary_reserved,
                                                  "SWF zlib output could not be written completely")) != CL_SUCCESS) {
                cli_errmsg("scancws: Can't write to file %s\n", tmpname);
                inflateEnd(&stream);
                return swf_cleanup_temp(ctx, fd, tmpname, decode_status, temporary_reserved);
            }
            outsize = next_outsize;
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
    fmap_t *map;
    unsigned int bitpos, bitbuf, getbits_n, nbits, getword_1, getword_2, getdword_1, getdword_2;
    const char *pt;
    unsigned char get_c;
    size_t offset = 0;
    unsigned int val, foo, tag_hdr, tag_type, tag_len;
    unsigned long int bits;
    cl_error_t read_status;
    size_t parse_end = 0;
    size_t tag_payload_end;

    cli_dbgmsg("in cli_scanswf()\n");

    if (ctx == NULL) {
        cli_dbgmsg("SWF: passed context was NULL\n");
        return CL_ENULLARG;
    }
    map = ctx->fmap;
    if (map == NULL) {
        cli_mark_scan_incomplete(ctx, "SWF input map is unavailable");
        return CL_EPARSE;
    }

    read_status = swf_checktimelimit(ctx, "SWF inspection reached the configured time limit");
    if (read_status != CL_SUCCESS)
        return read_status;

    read_status = swf_read_exact(map, &file_hdr, offset, sizeof(file_hdr), map->len);
    if (read_status != CL_SUCCESS) {
        cli_dbgmsg("SWF: Can't read file header\n");
        if (read_status != CL_EREAD) {
            cli_mark_scan_incomplete(ctx, "SWF file header was truncated");
            return CL_EPARSE;
        }
        return swf_read_failure(ctx, read_status, "SWF file header was truncated",
                                "SWF file header could not be read completely");
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
        if (ctx->engine == NULL) {
            cli_errmsg("SWF compressed input requires a scan engine\n");
            cli_mark_scan_incomplete(ctx, "SWF compressed input requires an owning engine");
            return CL_ENULLARG;
        }
        return scancws(ctx, &file_hdr);
    } else if (!strncmp(file_hdr.signature, "ZWS", 3)) {
        cli_dbgmsg("SWF: LZMA compressed file\n");
        if (ctx->engine == NULL) {
            cli_errmsg("SWF compressed input requires a scan engine\n");
            cli_mark_scan_incomplete(ctx, "SWF compressed input requires an owning engine");
            return CL_ENULLARG;
        }
        return scanzws(ctx, &file_hdr);
    } else if (!strncmp(file_hdr.signature, "FWS", 3)) {
        cli_dbgmsg("SWF: Uncompressed file\n");
        if (file_hdr.filesize < sizeof(file_hdr) || file_hdr.filesize > map->len) {
            cli_mark_scan_incomplete(ctx, "SWF uncompressed file was shorter than its declared size");
            return CL_EPARSE;
        }
        parse_end = (size_t)file_hdr.filesize;
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
        return swf_scan_overlay(ctx, map, parse_end);
    }

    while (offset < parse_end) {
        read_status = swf_checktimelimit(ctx, "SWF tag traversal reached the configured time limit");
        if (read_status != CL_SUCCESS)
            return read_status;

        GETWORD(tag_hdr);
        tag_type = tag_hdr >> 6;
        if (tag_type == 0)
            break;
        tag_len = tag_hdr & 0x3f;
        if (tag_len == 0x3f)
            GETDWORD(tag_len);

        tag_payload_end = offset;
        if ((size_t)tag_len > parse_end - offset) {
            cli_warnmsg("SWF: Tag payload is truncated or its length is too large.\n");
            cli_mark_scan_incomplete(ctx, "SWF tag payload was truncated");
            return CL_EPARSE;
        }
        tag_payload_end += tag_len;

        if ((tag_type == TAG_SCRIPTLIMITS || tag_type == TAG_FILEATTRIBUTES) && tag_len < 4) {
            cli_mark_scan_incomplete(ctx, "SWF fixed tag payload was shorter than its contents");
            return CL_EPARSE;
        }

        pt = tagname(tag_type);
        cli_dbgmsg("SWF: %s\n", pt ? pt : "UNKNOWN TAG");
        cli_dbgmsg("SWF: Tag length: %u\n", tag_len);
        if (!pt) {
            offset = tag_payload_end;
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
                offset = tag_payload_end;
                continue;
        }

        if (offset < tag_payload_end)
            offset = tag_payload_end;
    }

    return swf_scan_overlay(ctx, map, parse_end);
}
