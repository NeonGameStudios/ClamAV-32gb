/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Alberto Wu
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

/* FIXME: get a clue about masked stuff */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#include <stdlib.h>
#include <stdio.h>

#include <zlib.h>
#include "inflate64.h"

#include <bzlib.h>

#ifdef NOBZ2PREFIX
#define BZ2_bzDecompress bzDecompress
#define BZ2_bzDecompressEnd bzDecompressEnd
#define BZ2_bzDecompressInit bzDecompressInit
#endif

#include "explode.h"
#include "others.h"
#include "clamav.h"
#include "scanners.h"
#include "matcher.h"
#include "fmap.h"
#include "json_api.h"
#include "str.h"

#define UNZIP_PRIVATE
#define UNZIP_STREAM_PRIVATE
#include "unzip.h"

// clang-format off
#define ZIP_MAGIC_CENTRAL_DIRECTORY_RECORD_BEGIN    (0x02014b50)
#define ZIP_MAGIC_CENTRAL_DIRECTORY_RECORD_END      (0x06054b50)
#define ZIP_MAGIC_LOCAL_FILE_HEADER                 (0x04034b50)
#define ZIP_MAGIC_FILE_BEGIN_SPLIT_OR_SPANNED       (0x08074b50)
#define ZIP_MAGIC_ZIP64_END                         (0x06064b50)
#define ZIP_MAGIC_ZIP64_LOCATOR                     (0x07064b50)
// clang-format on

// Non-malicious zips in enterprise critical JAR-ZIPs have been observed with a 1-byte overlap.
// The goal with overlap detection is to alert on non-recursive zip bombs, so this tiny overlap isn't a concern.
// We'll allow a 2-byte overlap so we don't alert on such zips.
#define ZIP_RECORD_OVERLAP_FUDGE_FACTOR 2
#define ZIP_MAX_NUM_OVERLAPPING_FILES 5
#define ZIP_EOCD_MAX_SEARCH_SIZE (SIZEOF_END_OF_CENTRAL + UINT16_MAX)
#define ZIP64_END_RECORD_SIZE 56
#define ZIP64_LOCATOR_SIZE 20

/* All supported member decoders consume bounded fmap chunks.  Implode uses
 * its explicit state enum plus declared input/output exhaustion to
 * disambiguate EXPLODE_EBUFF (the API's shared need-input/need-output code). */

#define ZIP_CRC32(r, c, b, l) \
    do {                      \
        r = crc32(~c, b, l);  \
        r = ~r;               \
    } while (0)

#define ZIP_RECORDS_CHECK_BLOCKSIZE 100
struct zip_record {
    size_t local_header_offset;
    uint32_t local_header_size;
    uint64_t compressed_size;
    uint64_t uncompressed_size;
    uint32_t crc32;
    uint16_t method;
    uint16_t flags;
    int encrypted;
    char *original_filename;
};

struct zip_central_values {
    uint64_t compressed_size;
    uint64_t uncompressed_size;
    size_t local_header_offset;
    bool zip64_sizes;
};

static bool zip_record_end_checked(const struct zip_record *record, size_t *end)
{
    size_t member_size;

    if (!record || !end || record->compressed_size > SIZE_MAX)
        return false;
    if ((size_t)record->compressed_size > SIZE_MAX - (size_t)record->local_header_size)
        return false;
    member_size = (size_t)record->local_header_size + (size_t)record->compressed_size;
    if (record->local_header_offset > SIZE_MAX - member_size)
        return false;

    *end = record->local_header_offset + member_size;
    return true;
}

static bool zip_data_descriptor_matches(
    const uint8_t *descriptor,
    bool zip64_sizes,
    uint32_t expected_crc32,
    uint64_t expected_csize,
    uint64_t expected_usize)
{
    if (!descriptor || (uint32_t)cli_readint32(descriptor) != expected_crc32)
        return false;

    if (zip64_sizes) {
        return (uint64_t)cli_readint64(descriptor + 4) == expected_csize &&
               (uint64_t)cli_readint64(descriptor + 12) == expected_usize;
    }

    return (uint64_t)cli_readint32(descriptor + 4) == expected_csize &&
           (uint64_t)cli_readint32(descriptor + 8) == expected_usize;
}

static cl_error_t zip_validate_data_descriptor(
    cli_ctx *ctx,
    const uint8_t *central_header,
    size_t descriptor_offset,
    size_t available,
    bool zip64_sizes,
    uint64_t csize,
    uint64_t usize,
    size_t *consumed)
{
    const size_t payload_size = zip64_sizes ? 20U : 12U;
    const uint8_t *descriptor;

    if (!ctx || !central_header || !consumed)
        return CL_ENULLARG;
    *consumed = 0;

    if (available < payload_size) {
        cli_mark_scan_incomplete(ctx, "ZIP data descriptor is truncated");
        return CL_EPARSE;
    }

    descriptor = fmap_need_off_once(ctx->fmap, descriptor_offset, 4U);
    if (!descriptor) {
        cli_mark_scan_incomplete(ctx, "ZIP data descriptor is outside the archive map");
        return CL_EPARSE;
    }

    if (cli_readint32(descriptor) == ZIP_MAGIC_FILE_BEGIN_SPLIT_OR_SPANNED &&
        available >= payload_size + 4U) {
        const uint8_t *signed_payload = fmap_need_off_once(
            ctx->fmap, descriptor_offset + 4U, payload_size);

        /* The optional signature is numerically indistinguishable from a
         * CRC32 with the same value.  Treat it as a signature only when the
         * following payload agrees with the authoritative catalogue. */
        if (zip_data_descriptor_matches(signed_payload, zip64_sizes,
                                        CENTRAL_HEADER_crc32, csize, usize)) {
            descriptor_offset += 4U;
            available -= 4U;
            *consumed += 4U;
        }
    }

    if (available < payload_size) {
        cli_mark_scan_incomplete(ctx, "ZIP data descriptor payload is truncated");
        return CL_EPARSE;
    }
    descriptor = fmap_need_off_once(ctx->fmap, descriptor_offset, payload_size);
    if (!zip_data_descriptor_matches(descriptor, zip64_sizes,
                                     CENTRAL_HEADER_crc32, csize, usize)) {
        cli_mark_scan_incomplete(ctx, "ZIP data descriptor disagrees with the central directory");
        return CL_EFORMAT;
    }

    *consumed += payload_size;
    return CL_SUCCESS;
}

/* Resolve the ZIP64 extra-field values needed by the catalogue without
 * narrowing member sizes.  fmap offsets remain native size_t coordinates,
 * so only a local-header offset that cannot be represented by this process is
 * rejected here.  Extraction and configured-size limits are checked later. */
static bool zip64_read_catalogue_values(
    cli_ctx *ctx,
    const uint8_t *extra,
    size_t extra_len,
    uint32_t compressed_size32,
    uint32_t uncompressed_size32,
    uint32_t local_header_offset32,
    struct zip_central_values *values)
{
    size_t pos = 0;
    uint64_t compressed_size;
    uint64_t uncompressed_size;
    uint64_t local_header_offset;
    bool need_zip64 = compressed_size32 == UINT32_MAX || uncompressed_size32 == UINT32_MAX || local_header_offset32 == UINT32_MAX;

    (void)ctx;

    if (!values)
        return false;
    if (extra_len && !extra)
        return false;

    values->compressed_size     = compressed_size32;
    values->uncompressed_size   = uncompressed_size32;
    values->local_header_offset = local_header_offset32;
    values->zip64_sizes         = compressed_size32 == UINT32_MAX || uncompressed_size32 == UINT32_MAX;

    if (!need_zip64)
        return true;

    compressed_size     = compressed_size32;
    uncompressed_size   = uncompressed_size32;
    local_header_offset = local_header_offset32;

    while (extra_len - pos >= 4) {
        uint16_t field_id  = cli_readint16(extra + pos);
        uint16_t field_len = cli_readint16(extra + pos + 2);
        size_t field_pos   = pos + 4;
        size_t field_end;

        if (field_len > extra_len - field_pos)
            return false;
        field_end = field_pos + field_len;

        if (field_id == 0x0001) { /* ZIP64 extended information */
            if (uncompressed_size32 == UINT32_MAX) {
                if (field_end - field_pos < sizeof(uint64_t))
                    return false;
                uncompressed_size = (uint64_t)cli_readint64(extra + field_pos);
                field_pos += sizeof(uint64_t);
            }
            if (compressed_size32 == UINT32_MAX) {
                if (field_end - field_pos < sizeof(uint64_t))
                    return false;
                compressed_size = (uint64_t)cli_readint64(extra + field_pos);
                field_pos += sizeof(uint64_t);
            }
            if (local_header_offset32 == UINT32_MAX) {
                if (field_end - field_pos < sizeof(uint64_t))
                    return false;
                local_header_offset = (uint64_t)cli_readint64(extra + field_pos);
                field_pos += sizeof(uint64_t);
            }

            if (local_header_offset > SIZE_MAX)
                return false;

            values->compressed_size     = compressed_size;
            values->uncompressed_size   = uncompressed_size;
            values->local_header_offset = (size_t)local_header_offset;
            return true;
        }

        pos = field_end;
    }

    return false;
}

static int wrap_inflateinit2(void *a, int b)
{
    return inflateInit2(a, b);
}

static cl_error_t zip_check_output_limit(cli_ctx *ctx, uint64_t needed)
{
    cl_error_t ret = cli_checklimits("ZIP", ctx, needed, 0, 0);

    if (CL_EMAXSIZE == ret)
        cli_mark_scan_incomplete(ctx, "ZIP member exceeds the configured scan or file-size limit");

    return ret;
}

static cl_error_t zip_write_output(int out_file, const void *buffer, size_t length, uint64_t *written, cli_ctx *ctx)
{
    cl_error_t ret;

    if (NULL == written)
        return CL_ENULLARG;

    if ((uint64_t)length > UINT64_MAX - *written) {
        cli_mark_scan_incomplete(ctx, "ZIP member output size overflowed");
        return CL_EUNPACK;
    }

    ret = zip_check_output_limit(ctx, *written + (uint64_t)length);
    if (CL_SUCCESS != ret)
        return ret;

    if (length && cli_writen(out_file, buffer, length) != length) {
        cli_mark_scan_incomplete(ctx, "ZIP member output could not be written completely");
        return CL_EWRITE;
    }

    *written += (uint64_t)length;
    return CL_SUCCESS;
}

static cl_error_t zip_scan_output(int fd, const char *filepath, cli_ctx *ctx, const char *name,
                                  uint32_t attributes, zip_cb zcb)
{
    if (zcb == cli_magic_scan_desc)
        return cli_magic_scan_desc_type_reserved(fd, filepath, ctx, CL_TYPE_ANY, name, attributes);

    return zcb(fd, filepath, ctx, name, attributes);
}

static bool zip_extraction_error_is_incomplete(cl_error_t ret)
{
    switch (ret) {
        case CL_EUNPACK:
        case CL_EOPEN:
        case CL_ECREAT:
        case CL_EUNLINK:
        case CL_ESTAT:
        case CL_EREAD:
        case CL_ESEEK:
        case CL_EWRITE:
        case CL_ETMPFILE:
        case CL_ETMPDIR:
        case CL_EMAP:
        case CL_EMEM:
        case CL_EMAXSIZE:
        case CL_EPARSE:
        case CL_ERESOURCE:
            return true;
        default:
            return false;
    }
}

/**
 * Extract members from an fmap without acquiring a view of the whole
 * compressed member.  The callback is invoked only after all declared input
 * has been consumed, the decoder reports its terminal state, and the exact
 * declared output size has been produced.
 */
static cl_error_t unz_stream(
    fmap_t *map,
    size_t data_offset,
    uint64_t csize,
    uint64_t usize,
    uint16_t method,
    uint16_t flags,
    uint32_t expected_crc32,
    size_t *num_files_unzipped,
    cli_ctx *ctx,
    char *tmpd,
    zip_cb zcb,
    const char *original_filename,
    bool decrypted)
{
    struct zip_input input;
    uint8_t obuf[BUFSIZ];
    char *tempfile        = NULL;
    int out_file          = -1;
    uint64_t written            = 0;
    uint32_t output_crc32       = 0;
    uint64_t temporary_reserved = 0;
    uint64_t temporary_size     = 0;
    cl_error_t ret;
    bool complete = false;

    if (NULL == map || NULL == num_files_unzipped || NULL == ctx || NULL == ctx->engine || NULL == zcb)
        return CL_ENULLARG;

    if (ALG_STORED != method && ALG_DEFLATE != method &&
        ALG_DEFLATE64 != method && ALG_BZIP2 != method &&
        ALG_IMPLODE != method) {
        cli_mark_scan_incomplete(ctx, "ZIP method is not implemented by the bounded reader");
        return CL_EUNPACK;
    }

    ret = zip_input_init(&input, map, data_offset, csize);
    if (CL_SUCCESS != ret) {
        cli_mark_scan_incomplete(ctx, "ZIP member data is outside the archive map");
        return ret;
    }

    /* Stored members have no expansion; for compressed methods, the header
     * value is a useful preflight only.  Runtime checks below remain
     * authoritative because malicious archives may lie about usize. */
    ret = zip_check_output_limit(ctx, ALG_STORED == method ? csize : usize);
    if (CL_SUCCESS != ret)
        return ret;

    temporary_size = ALG_STORED == method ? csize : usize;
    ret = cli_scan_reserve_temporary(ctx, temporary_size);
    if (CL_SUCCESS != ret) {
        cli_mark_scan_incomplete(ctx, "ZIP member temporary output exceeded the configured limit");
        return ret;
    }
    temporary_reserved = temporary_size;

    if (tmpd) {
        if (ctx->engine->keeptmp && (NULL != original_filename)) {
            tempfile = cli_gentemp_with_prefix(tmpd, original_filename);
        } else {
            tempfile = cli_gentemp(tmpd);
        }
    } else {
        if (ctx->engine->keeptmp && (NULL != original_filename)) {
            tempfile = cli_gentemp_with_prefix(ctx->this_layer_tmpdir, original_filename);
        } else {
            tempfile = cli_gentemp(ctx->this_layer_tmpdir);
        }
    }
    if (NULL == tempfile) {
        cli_mark_scan_incomplete(ctx, "ZIP member temporary output could not be allocated");
        if (temporary_reserved)
            cli_scan_release_temporary(ctx, temporary_reserved);
        return CL_EMEM;
    }

    out_file = open(tempfile, O_RDWR | O_CREAT | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR);
    if (-1 == out_file) {
        cli_warnmsg("cli_unzip: failed to create temporary file %s\n", tempfile);
        cli_mark_scan_incomplete(ctx, "ZIP member temporary output could not be opened");
        free(tempfile);
        if (temporary_reserved)
            cli_scan_release_temporary(ctx, temporary_reserved);
        return CL_ETMPFILE;
    }

    ret = CL_EUNPACK;
    if (ALG_STORED == method) {
        while (input.remaining) {
            const uint8_t *data;
            unsigned int length;

            ret = cli_checktimelimit(ctx);
            if (CL_SUCCESS != ret)
                break;

            ret = zip_input_refill(&input, &data, &length);
            if (CL_SUCCESS != ret)
                break;
            if (0 == length) {
                ret = CL_EREAD;
                break;
            }

            ret = zip_write_output(out_file, data, length, &written, ctx);
            if (CL_SUCCESS != ret)
                break;
            output_crc32 = (uint32_t)crc32(output_crc32, data, length);
        }

        if (CL_SUCCESS == ret && 0 == input.remaining) {
            if (usize != csize) {
                cli_dbgmsg("cli_unzip: stored member size mismatch (compressed " STDu64 ", reported output " STDu64 ")\n", csize, usize);
                ret = CL_EUNPACK;
            } else {
                complete = true;
            }
        }
    } else if (ALG_DEFLATE == method || ALG_DEFLATE64 == method) {
        union {
            z_stream64 strm64;
            z_stream strm;
        } strm;
        typedef int (*unz_init_)(void *, int);
        typedef int (*unz_unz_)(void *, int);
        typedef int (*unz_end_)(void *);
        unz_init_ unz_init;
        unz_unz_ unz_unz;
        unz_end_ unz_end;
        void **next_in;
        void **next_out;
        unsigned int *avail_in;
        unsigned int *avail_out;
        int wbits;
        int zret;
        bool initialized = false;

        memset(&strm, 0, sizeof(strm));
        if (ALG_DEFLATE64 == method) {
            unz_init  = (unz_init_)inflate64Init2;
            unz_unz   = (unz_unz_)inflate64;
            unz_end   = (unz_end_)inflate64End;
            next_in   = (void **)&strm.strm64.next_in;
            next_out  = (void **)&strm.strm64.next_out;
            avail_in  = &strm.strm64.avail_in;
            avail_out = &strm.strm64.avail_out;
            wbits     = MAX_WBITS64;
        } else {
            unz_init  = (unz_init_)wrap_inflateinit2;
            unz_unz   = (unz_unz_)inflate;
            unz_end   = (unz_end_)inflateEnd;
            next_in   = (void **)&strm.strm.next_in;
            next_out  = (void **)&strm.strm.next_out;
            avail_in  = &strm.strm.avail_in;
            avail_out = &strm.strm.avail_out;
            wbits     = MAX_WBITS;
        }
        *next_out  = obuf;
        *avail_out = sizeof(obuf);

        zret = unz_init(&strm, -wbits);
        if (Z_OK != zret) {
            cli_dbgmsg("cli_unzip: bounded inflate initialization failed for method %u\n", method);
            ret = CL_EUNPACK;
        } else {
            initialized = true;
            ret         = CL_SUCCESS;
        }

        while (initialized && !complete && CL_SUCCESS == ret) {
            unsigned int input_before;
            size_t produced;

            ret = cli_checktimelimit(ctx);
            if (CL_SUCCESS != ret)
                break;

            if (0 == *avail_in) {
                const uint8_t *data;
                unsigned int length;

                if (0 == input.remaining) {
                    ret = CL_EUNPACK;
                    break;
                }

                ret = zip_input_refill(&input, &data, &length);
                if (CL_SUCCESS != ret)
                    break;
                if (0 == length) {
                    ret = CL_EREAD;
                    break;
                }
                *next_in  = (void *)data;
                *avail_in = length;
            }

            input_before = *avail_in;
            zret         = unz_unz(&strm, Z_NO_FLUSH);
            produced     = sizeof(obuf) - *avail_out;

            if (produced) {
                ret = zip_write_output(out_file, obuf, produced, &written, ctx);
                if (CL_SUCCESS != ret)
                    break;
                output_crc32 = (uint32_t)crc32(output_crc32, obuf, (uInt)produced);
                *next_out    = obuf;
                *avail_out   = sizeof(obuf);
            }

            if (Z_STREAM_END == zret) {
                if (0 != *avail_in || 0 != input.remaining) {
                    cli_dbgmsg("cli_unzip: method %u stream ended before the declared compressed size\n", method);
                    ret = CL_EUNPACK;
                } else if (written != usize) {
                    cli_dbgmsg("cli_unzip: method %u member produced " STDu64 " bytes, expected " STDu64 "\n", method, written, usize);
                    ret = CL_EUNPACK;
                } else {
                    complete = true;
                }
                break;
            }

            if (Z_OK != zret && !(Z_BUF_ERROR == zret && produced)) {
                cli_dbgmsg("cli_unzip: method %u stream failed with status %d\n", method, zret);
                ret = CL_EUNPACK;
                break;
            }

            if (input_before == *avail_in && 0 == produced) {
                cli_dbgmsg("cli_unzip: method %u stream made no progress\n", method);
                ret = CL_EUNPACK;
                break;
            }
        }

        if (initialized)
            unz_end(&strm);
    } else if (ALG_BZIP2 == method) {
        bz_stream strm;
        int bzret;
        bool initialized = false;

        memset(&strm, 0, sizeof(strm));
        strm.next_out  = (char *)obuf;
        strm.avail_out = sizeof(obuf);

        bzret = BZ2_bzDecompressInit(&strm, 0, 0);
        if (BZ_OK != bzret) {
            cli_dbgmsg("cli_unzip: bounded BZIP2 initialization failed\n");
            ret = CL_EUNPACK;
        } else {
            initialized = true;
            ret         = CL_SUCCESS;
        }

        while (initialized && !complete && CL_SUCCESS == ret) {
            unsigned int input_before;
            size_t produced;

            ret = cli_checktimelimit(ctx);
            if (CL_SUCCESS != ret)
                break;

            if (0 == strm.avail_in) {
                const uint8_t *data;
                unsigned int length;

                if (0 == input.remaining) {
                    ret = CL_EUNPACK;
                    break;
                }

                ret = zip_input_refill(&input, &data, &length);
                if (CL_SUCCESS != ret)
                    break;
                if (0 == length) {
                    ret = CL_EREAD;
                    break;
                }
                strm.next_in  = (char *)data;
                strm.avail_in = length;
            }

            input_before = strm.avail_in;
            bzret        = BZ2_bzDecompress(&strm);
            produced     = sizeof(obuf) - strm.avail_out;

            if (produced) {
                ret = zip_write_output(out_file, obuf, produced, &written, ctx);
                if (CL_SUCCESS != ret)
                    break;
                output_crc32   = (uint32_t)crc32(output_crc32, obuf, (uInt)produced);
                strm.next_out  = (char *)obuf;
                strm.avail_out = sizeof(obuf);
            }

            if (BZ_STREAM_END == bzret) {
                if (0 != strm.avail_in || 0 != input.remaining) {
                    cli_dbgmsg("cli_unzip: BZIP2 stream ended before the declared compressed size\n");
                    ret = CL_EUNPACK;
                } else if (written != usize) {
                    cli_dbgmsg("cli_unzip: BZIP2 member produced " STDu64 " bytes, expected " STDu64 "\n", written, usize);
                    ret = CL_EUNPACK;
                } else {
                    complete = true;
                }
                break;
            }

            if (BZ_OK != bzret) {
                cli_dbgmsg("cli_unzip: BZIP2 stream failed with status %d\n", bzret);
                ret = CL_EUNPACK;
                break;
            }

            if (input_before == strm.avail_in && 0 == produced) {
                cli_dbgmsg("cli_unzip: BZIP2 stream made no progress\n");
                ret = CL_EUNPACK;
                break;
            }
        }

        if (initialized)
            BZ2_bzDecompressEnd(&strm);
    } else {
        struct xplstate strm;
        bool initialized = false;
        int xret;

        memset(&strm, 0, sizeof(strm));
        strm.next_out  = obuf;
        strm.avail_out = sizeof(obuf);
        xret           = explode_init(&strm, flags);
        if (EXPLODE_OK != xret) {
            cli_dbgmsg("cli_unzip: bounded Implode initialization failed\n");
            ret = CL_EUNPACK;
        } else {
            initialized = true;
            ret         = CL_SUCCESS;
        }

        while (initialized && !complete && CL_SUCCESS == ret) {
            uint32_t input_before;
            uint32_t output_before;
            size_t produced;

            ret = cli_checktimelimit(ctx);
            if (CL_SUCCESS != ret)
                break;

            if (0 == strm.avail_in && input.remaining) {
                const uint8_t *data;
                unsigned int length;

                ret = zip_input_refill(&input, &data, &length);
                if (CL_SUCCESS != ret)
                    break;
                if (0 == length) {
                    ret = CL_EREAD;
                    break;
                }
                strm.next_in  = (uint8_t *)data;
                strm.avail_in = length;
            }

            input_before  = strm.avail_in;
            output_before = strm.avail_out;
            xret          = explode(&strm);
            produced      = sizeof(obuf) - strm.avail_out;

            if (produced) {
                ret = zip_write_output(out_file, obuf, produced, &written, ctx);
                if (CL_SUCCESS != ret)
                    break;
                output_crc32   = (uint32_t)crc32(output_crc32, obuf, (uInt)produced);
                strm.next_out  = obuf;
                strm.avail_out = sizeof(obuf);
            }

            if (EXPLODE_ESTREAM == xret) {
                cli_dbgmsg("cli_unzip: Implode decoder rejected the stream\n");
                ret = CL_EUNPACK;
                break;
            }

            if (EXPLODE_EBUFF != xret) {
                cli_dbgmsg("cli_unzip: Implode decoder returned unexpected status %d\n", xret);
                ret = CL_EUNPACK;
                break;
            }

            if (0 == strm.avail_in && 0 == input.remaining &&
                strm.state == EXPLODE && strm.avail_out != 0) {
                if (written != usize) {
                    cli_dbgmsg("cli_unzip: Implode member produced " STDu64 " bytes, expected " STDu64 "\n", written, usize);
                    ret = CL_EUNPACK;
                } else {
                    complete = true;
                }
                break;
            }

            if (input_before == strm.avail_in &&
                output_before == strm.avail_out && 0 == produced) {
                cli_dbgmsg("cli_unzip: Implode stream made no progress\n");
                ret = CL_EUNPACK;
                break;
            }
        }
    }

    if (complete && output_crc32 != expected_crc32) {
        cli_dbgmsg("cli_unzip: extracted CRC32 %08x does not match declared CRC32 %08x\n",
                   output_crc32, expected_crc32);
        complete = false;
        ret      = CL_EUNPACK;
    }

    if (complete && CL_SUCCESS == ret) {
        (*num_files_unzipped)++;
        cli_dbgmsg("cli_unzip: extracted " STDu64 " bytes to %s\n", written, tempfile);
        if (lseek(out_file, 0, SEEK_SET) == -1) {
            cli_mark_scan_incomplete(ctx, "ZIP member temporary output could not be rewound");
            ret = CL_ESEEK;
        } else {
            ret = zip_scan_output(out_file, tempfile, ctx, original_filename, decrypted, zcb);
        }
    } else if (zip_extraction_error_is_incomplete(ret)) {
        cli_mark_scan_incomplete(ctx, "ZIP member did not reach a complete extraction state");
    }

    if (close(out_file) == -1) {
        cli_mark_scan_incomplete(ctx, "ZIP member temporary output could not be closed");
        if (CL_SUCCESS == ret || CL_VERIFIED == ret)
            ret = CL_EWRITE;
    }
    if (!ctx->engine->keeptmp && cli_unlink(tempfile)) {
        cli_mark_scan_incomplete(ctx, "ZIP member temporary output could not be removed");
        if (CL_SUCCESS == ret || CL_VERIFIED == ret)
            ret = CL_EUNLINK;
    }
    if (temporary_reserved)
        cli_scan_release_temporary(ctx, temporary_reserved);
    free(tempfile);
    return ret;
}

/**
 * @brief uncompress file from zip
 *
 * @param src                           pointer to compressed data
 * @param csize                         size of compressed data
 * @param usize                         expected size of uncompressed data
 * @param method                        compression method
 * @param flags                         local header flags
 * @param[in,out] num_files_unzipped    current number of files that have been unzipped
 * @param[in,out] ctx                   scan context
 * @param tmpd                          temp directory path name
 * @param zcb                           callback function to invoke after extraction (default: scan)
 * @return cl_error_t                   CL_EPARSE = could not apply a password
 */
static cl_error_t unz_legacy(
    const uint8_t *src,
    uint64_t csize,
    uint64_t usize,
    uint16_t method,
    uint16_t flags,
    size_t *num_files_unzipped,
    cli_ctx *ctx,
    char *tmpd,
    zip_cb zcb,
    const char *original_filename,
    bool decrypted)
{
    char obuf[BUFSIZ] = {0};
    char *tempfile    = NULL;
    int out_file, ret = CL_EUNPACK;
    int res          = 1;
    uint64_t written            = 0;
    uint64_t temporary_reserved = 0;
    uint64_t temporary_size     = 0;

    if (NULL == src || NULL == num_files_unzipped || NULL == ctx || NULL == ctx->engine || NULL == zcb)
        return CL_ENULLARG;

    ret = zip_check_output_limit(ctx, ALG_STORED == method ? csize : usize);
    if (CL_SUCCESS != ret)
        return ret;
    temporary_size = ALG_STORED == method ? csize : usize;
    ret = cli_scan_reserve_temporary(ctx, temporary_size);
    if (CL_SUCCESS != ret) {
        cli_mark_scan_incomplete(ctx, "ZIP legacy member temporary output exceeded the configured limit");
        return ret;
    }
    temporary_reserved = temporary_size;
    ret = CL_EUNPACK;

    if (tmpd) {
        if (ctx->engine->keeptmp && (NULL != original_filename)) {
            if (!(tempfile = cli_gentemp_with_prefix(tmpd, original_filename))) {
                cli_mark_scan_incomplete(ctx, "ZIP legacy member temporary output could not be allocated");
                if (temporary_reserved)
                    cli_scan_release_temporary(ctx, temporary_reserved);
                return CL_EMEM;
            }
        } else {
            if (!(tempfile = cli_gentemp(tmpd))) {
                cli_mark_scan_incomplete(ctx, "ZIP legacy member temporary output could not be allocated");
                if (temporary_reserved)
                    cli_scan_release_temporary(ctx, temporary_reserved);
                return CL_EMEM;
            }
        }
    } else {
        if (ctx->engine->keeptmp && (NULL != original_filename)) {
            if (!(tempfile = cli_gentemp_with_prefix(ctx->this_layer_tmpdir, original_filename))) {
                cli_mark_scan_incomplete(ctx, "ZIP legacy member temporary output could not be allocated");
                if (temporary_reserved)
                    cli_scan_release_temporary(ctx, temporary_reserved);
                return CL_EMEM;
            }
        } else {
            if (!(tempfile = cli_gentemp(ctx->this_layer_tmpdir))) {
                cli_mark_scan_incomplete(ctx, "ZIP legacy member temporary output could not be allocated");
                if (temporary_reserved)
                    cli_scan_release_temporary(ctx, temporary_reserved);
                return CL_EMEM;
            }
        }
    }
    if ((out_file = open(tempfile, O_RDWR | O_CREAT | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR)) == -1) {
        cli_warnmsg("cli_unzip: failed to create temporary file %s\n", tempfile);
        cli_mark_scan_incomplete(ctx, "ZIP legacy member temporary output could not be opened");
        free(tempfile);
        if (temporary_reserved)
            cli_scan_release_temporary(ctx, temporary_reserved);
        return CL_ETMPFILE;
    }
    switch (method) {
        case ALG_STORED:
            ret = zip_write_output(out_file, src, (size_t)csize, &written, ctx);
            if (CL_SUCCESS == ret)
                res = 0;
            break;

        case ALG_DEFLATE:
        case ALG_DEFLATE64: {
            union {
                z_stream64 strm64;
                z_stream strm;
            } strm;
            typedef int (*unz_init_)(void *, int);
            typedef int (*unz_unz_)(void *, int);
            typedef int (*unz_end_)(void *);
            unz_init_ unz_init;
            unz_unz_ unz_unz;
            unz_end_ unz_end;
            int wbits;
            void **next_in;
            void **next_out;
            unsigned int *avail_in;
            unsigned int *avail_out;

            if (method == ALG_DEFLATE64) {
                unz_init  = (unz_init_)inflate64Init2;
                unz_unz   = (unz_unz_)inflate64;
                unz_end   = (unz_end_)inflate64End;
                next_in   = (void *)&strm.strm64.next_in;
                next_out  = (void *)&strm.strm64.next_out;
                avail_in  = &strm.strm64.avail_in;
                avail_out = &strm.strm64.avail_out;
                wbits     = MAX_WBITS64;
            } else {
                unz_init  = (unz_init_)wrap_inflateinit2;
                unz_unz   = (unz_unz_)inflate;
                unz_end   = (unz_end_)inflateEnd;
                next_in   = (void *)&strm.strm.next_in;
                next_out  = (void *)&strm.strm.next_out;
                avail_in  = &strm.strm.avail_in;
                avail_out = &strm.strm.avail_out;
                wbits     = MAX_WBITS;
            }

            memset(&strm, 0, sizeof(strm));

            *next_in   = (void *)src;
            *next_out  = obuf;
            *avail_in  = (unsigned int)csize;
            *avail_out = sizeof(obuf);
            if (unz_init(&strm, -wbits) != Z_OK) {
                cli_dbgmsg("cli_unzip: zinit failed\n");
                break;
            }
            while (1) {
                size_t produced;

                res      = unz_unz(&strm, Z_NO_FLUSH);
                produced = sizeof(obuf) - *avail_out;
                if (*avail_out != sizeof(obuf)) {
                    ret = zip_write_output(out_file, obuf, produced, &written, ctx);
                    if (CL_SUCCESS != ret) {
                        cli_warnmsg("cli_unzip: failed to write or account for %zu inflated bytes\n", produced);
                        res = 100;
                        break;
                    }
                    *next_out  = obuf;
                    *avail_out = sizeof(obuf);
                }

                if (Z_STREAM_END == res)
                    break;
                if (Z_OK == res || (Z_BUF_ERROR == res && produced))
                    continue;
                break;
            }
            unz_end(&strm);
            if (res == Z_STREAM_END && 0 == *avail_in)
                res = 0;
            break;
        }

        case ALG_BZIP2: {
            bz_stream strm;
            memset(&strm, 0, sizeof(strm));
            strm.next_in   = (char *)src;
            strm.next_out  = obuf;
            strm.avail_in  = (unsigned int)csize;
            strm.avail_out = sizeof(obuf);
            if (BZ2_bzDecompressInit(&strm, 0, 0) != BZ_OK) {
                cli_dbgmsg("cli_unzip: bzinit failed\n");
                break;
            }
            while ((res = BZ2_bzDecompress(&strm)) == BZ_OK || res == BZ_STREAM_END) {
                if (strm.avail_out != sizeof(obuf)) {
                    size_t produced = sizeof(obuf) - strm.avail_out;

                    ret = zip_write_output(out_file, obuf, produced, &written, ctx);
                    if (CL_SUCCESS != ret) {
                        cli_warnmsg("cli_unzip: failed to write or account for %zu bunzipped bytes\n", produced);
                        res = 100;
                        break;
                    }
                    strm.next_out  = obuf;
                    strm.avail_out = sizeof(obuf);
                    if (res == BZ_OK) continue; /* after returning BZ_STREAM_END once, decompress returns an error */
                }
                break;
            }
            BZ2_bzDecompressEnd(&strm);
            if (res == BZ_STREAM_END && 0 == strm.avail_in)
                res = 0;
            break;
        }

        case ALG_IMPLODE: {
            struct xplstate strm;
            strm.next_in   = (void *)src;
            strm.next_out  = (uint8_t *)obuf;
            strm.avail_in  = (uint32_t)csize;
            strm.avail_out = sizeof(obuf);
            if (explode_init(&strm, flags) != EXPLODE_OK) {
                cli_dbgmsg("cli_unzip: explode_init() failed\n");
                break;
            }
            while (1) {
                bool output_full;

                res         = explode(&strm);
                output_full = (0 == strm.avail_out);
                if (strm.avail_out != sizeof(obuf)) {
                    size_t produced = sizeof(obuf) - strm.avail_out;

                    ret = zip_write_output(out_file, obuf, produced, &written, ctx);
                    if (CL_SUCCESS != ret) {
                        cli_warnmsg("cli_unzip: failed to write or account for %zu exploded bytes\n", produced);
                        res = 100;
                        break;
                    }
                    strm.next_out  = (uint8_t *)obuf;
                    strm.avail_out = sizeof(obuf);
                }

                if (EXPLODE_EBUFF == res && output_full)
                    continue;
                if (EXPLODE_EBUFF == res && 0 == strm.avail_in) {
                    res = 0;
                    break;
                }
                if (EXPLODE_OK == res)
                    continue;
                break;
            }
            break;
        }

        case ALG_LZMA:
            /* easy but there's not a single sample in the zoo */

        case ALG_SHRUNK:
        case ALG_REDUCE1:
        case ALG_REDUCE2:
        case ALG_REDUCE3:
        case ALG_REDUCE4:
        case ALG_TOKENZD:
        case ALG_OLDTERSE:
        case ALG_RSVD1:
        case ALG_RSVD2:
        case ALG_RSVD3:
        case ALG_RSVD4:
        case ALG_RSVD5:
        case ALG_NEWTERSE:
        case ALG_LZ77:
        case ALG_WAVPACK:
        case ALG_PPMD:
            cli_dbgmsg("cli_unzip: unsupported method (%d)\n", method);
            break;
        default:
            cli_dbgmsg("cli_unzip: unknown method (%d)\n", method);
            break;
    }

    if (!res && written != usize) {
        cli_dbgmsg("cli_unzip: legacy member produced " STDu64 " bytes, expected " STDu64 "\n", written, usize);
        ret = CL_EUNPACK;
        res = 1;
    }

    if (!res) {
        (*num_files_unzipped)++;
        cli_dbgmsg("cli_unzip: extracted to %s\n", tempfile);
        if (lseek(out_file, 0, SEEK_SET) == -1) {
            cli_dbgmsg("cli_unzip: call to lseek() failed\n");
            cli_mark_scan_incomplete(ctx, "ZIP legacy member temporary output could not be rewound");
            free(tempfile);
            close(out_file);
            if (temporary_reserved)
                cli_scan_release_temporary(ctx, temporary_reserved);
            return CL_ESEEK;
        }
        ret = zip_scan_output(out_file, tempfile, ctx, original_filename, decrypted, zcb);
        if (close(out_file) == -1) {
            cli_mark_scan_incomplete(ctx, "ZIP legacy member temporary output could not be closed");
            if (CL_SUCCESS == ret || CL_VERIFIED == ret)
                ret = CL_EWRITE;
        }
        if (!ctx->engine->keeptmp && cli_unlink(tempfile)) {
            cli_mark_scan_incomplete(ctx, "ZIP legacy member temporary output could not be removed");
            if (CL_SUCCESS == ret || CL_VERIFIED == ret)
                ret = CL_EUNLINK;
        }
        free(tempfile);
        if (temporary_reserved)
            cli_scan_release_temporary(ctx, temporary_reserved);
        return ret;
    }

    if (CL_SUCCESS == ret)
        ret = CL_EUNPACK;

    if (close(out_file) == -1) {
        cli_mark_scan_incomplete(ctx, "ZIP legacy member temporary output could not be closed");
        if (CL_SUCCESS == ret || CL_VERIFIED == ret)
            ret = CL_EWRITE;
    }
    if (!ctx->engine->keeptmp && cli_unlink(tempfile)) {
        cli_mark_scan_incomplete(ctx, "ZIP legacy member temporary output could not be removed");
        if (CL_SUCCESS == ret || CL_VERIFIED == ret)
            ret = CL_EUNLINK;
    }
    free(tempfile);
    if (temporary_reserved)
        cli_scan_release_temporary(ctx, temporary_reserved);
    cli_dbgmsg("cli_unzip: extraction failed\n");
    if (zip_extraction_error_is_incomplete(ret))
        cli_mark_scan_incomplete(ctx, "ZIP legacy member did not reach a complete extraction state");
    return ret;
}

/* zip update keys, taken from zip specification */
static inline void zupdatekey(uint32_t key[3], unsigned char input)
{
    unsigned char tmp[1];

    tmp[0] = input;
    ZIP_CRC32(key[0], key[0], tmp, 1);

    key[1] = key[1] + (key[0] & 0xff);
    key[1] = key[1] * 134775813 + 1;

    tmp[0] = key[1] >> 24;
    ZIP_CRC32(key[2], key[2], tmp, 1);
}

/* zip init keys */
static inline void zinitkey(uint32_t key[3], struct cli_pwdb *password)
{
    int i;

    /* initialize keys, these are specified but the zip specification */
    key[0] = 305419896L;
    key[1] = 591751049L;
    key[2] = 878082192L;

    /* update keys with password  */
    for (i = 0; i < password->length; i++)
        zupdatekey(key, password->passwd[i]);
}

/* zip decrypt byte */
static inline unsigned char zdecryptbyte(uint32_t key[3])
{
    /* Preserve the specified 16-bit ZipCrypto arithmetic without relying on
     * signed-int promotion for the multiplication.  The maximum product is
     * larger than INT_MAX and was undefined under UBSan on LP64 targets. */
    uint32_t temp = (key[2] & 0xffffU) | 2U;
    return (unsigned char)((temp * (temp ^ 1U)) >> 8);
}

static cl_error_t unz_from_fmap(
    fmap_t *map,
    size_t data_offset,
    uint64_t csize,
    uint64_t usize,
    uint16_t method,
    uint16_t flags,
    uint32_t expected_crc32,
    size_t *num_files_unzipped,
    cli_ctx *ctx,
    char *tmpd,
    zip_cb zcb,
    const char *original_filename,
    bool decrypted);

/* Traditional ZipCrypto is byte-oriented and has no reason to map the whole
 * member.  Decrypt into a temporary fmap in bounded chunks, then feed that
 * fmap through the same bounded decompressor used for unencrypted members.
 * The intermediate file may be large, but resident input remains bounded and
 * no scan callback is possible until decryption and decompression complete.
 * Strong-encryption extra field 0x0017 is not supported; those members fail
 * password/decode validation and are marked scan-incomplete. */
static cl_error_t zdecrypt_from_fmap(
    fmap_t *map,
    size_t data_offset,
    uint64_t csize,
    uint64_t usize,
    uint32_t expected_crc32,
    const uint8_t *local_header,
    size_t *num_files_unzipped,
    cli_ctx *ctx,
    char *tmpd,
    zip_cb zcb,
    const char *original_filename)
{
    struct cli_pwdb *password;
    struct cli_pwdb *pass_any;
    struct cli_pwdb *pass_zip;
    uint16_t version;
    uint16_t flags;
    uint16_t method;
    uint32_t mtime;
    uint32_t member_crc32;

    if (!map || !local_header || !num_files_unzipped || !ctx || !ctx->engine || !zcb)
        return CL_ENULLARG;

    if (csize < SIZEOF_ENCRYPTION_HEADER) {
        cli_mark_scan_incomplete(ctx, "ZIP encrypted member is shorter than its encryption header");
        return CL_EPARSE;
    }

    version      = LOCAL_HEADER_version;
    flags        = LOCAL_HEADER_flags;
    method       = LOCAL_HEADER_method;
    mtime        = LOCAL_HEADER_mtime;
    member_crc32 = LOCAL_HEADER_crc32;

    if (ctx->dconf && !(ctx->dconf->archive & ARCH_CONF_PASSWD)) {
        cli_dbgmsg("cli_unzip: password attempts are disabled for an encrypted ZIP member\n");
        cli_mark_scan_incomplete(ctx, "ZIP encrypted member was not decrypted because password attempts are disabled");
        return CL_EUNPACK;
    }

    pass_any = ctx->engine->pwdbs ? ctx->engine->pwdbs[CLI_PWDB_ANY] : NULL;
    pass_zip = ctx->engine->pwdbs ? ctx->engine->pwdbs[CLI_PWDB_ZIP] : NULL;

    while (pass_any || pass_zip) {
        struct zip_input input;
        const uint8_t *data = NULL;
        unsigned int length = 0;
        uint8_t encryption_header[SIZEOF_ENCRYPTION_HEADER];
        uint32_t key[3];
        unsigned int i;
        bool password_matches = false;
        cl_error_t ret;

        password = pass_zip ? pass_zip : pass_any;
        zinitkey(key, password);

        ret = zip_input_init(&input, map, data_offset, csize);
        if (CL_SUCCESS != ret) {
            cli_mark_scan_incomplete(ctx, "ZIP encrypted member data is outside the archive map");
            return ret;
        }
        ret = zip_input_refill(&input, &data, &length);
        if (CL_SUCCESS != ret || length < SIZEOF_ENCRYPTION_HEADER) {
            cli_mark_scan_incomplete(ctx, "ZIP encryption header could not be read completely");
            return CL_SUCCESS == ret ? CL_EREAD : ret;
        }

        memcpy(encryption_header, data, SIZEOF_ENCRYPTION_HEADER);
        for (i = 0; i < SIZEOF_ENCRYPTION_HEADER; i++) {
            encryption_header[i] ^= zdecryptbyte(key);
            zupdatekey(key, encryption_header[i]);
        }

        if (version > 20) {
            uint8_t check    = encryption_header[SIZEOF_ENCRYPTION_HEADER - 1];
            uint8_t want     = (uint8_t)(((flags & F_USEDD) ? mtime : member_crc32) >> ((flags & F_USEDD) ? 8 : 24));
            password_matches = check == want;
        } else {
            uint16_t check = (uint16_t)encryption_header[SIZEOF_ENCRYPTION_HEADER - 2] |
                             (uint16_t)((uint16_t)encryption_header[SIZEOF_ENCRYPTION_HEADER - 1] << 8);
            uint16_t want    = (uint16_t)((flags & F_USEDD) ? mtime : (member_crc32 >> 16));
            password_matches = check == want;
        }

        if (password_matches) {
            char name[1024];
            char obuf[BUFSIZ];
            char *tempfile          = name;
            bool allocated_tempfile = false;
            uint64_t temporary_reserved = 0;
            size_t buffered         = 0;
            uint64_t total          = 0;
            unsigned int input_pos  = SIZEOF_ENCRYPTION_HEADER;
            fmap_t *decrypted_map   = NULL;
            int out_file            = -1;

            cli_dbgmsg("cli_unzip: ZipCrypto password [%s] matches\n", password->name ? password->name : "(unnamed)");

            ret = cli_scan_reserve_temporary(ctx, csize - SIZEOF_ENCRYPTION_HEADER);
            if (CL_SUCCESS != ret) {
                cli_mark_scan_incomplete(ctx, "ZIP encrypted member temporary output exceeded the configured limit");
                return ret;
            }
            temporary_reserved = csize - SIZEOF_ENCRYPTION_HEADER;

            if (tmpd) {
                snprintf(name, sizeof(name), "%s" PATHSEP "zip.decrypt.%03zu", tmpd, *num_files_unzipped);
                name[sizeof(name) - 1] = '\0';
            } else {
                tempfile = cli_gentemp_with_prefix(ctx->this_layer_tmpdir, "zip-decrypt");
                if (!tempfile) {
                    cli_mark_scan_incomplete(ctx, "ZIP encrypted member temporary output could not be allocated");
                    if (temporary_reserved)
                        cli_scan_release_temporary(ctx, temporary_reserved);
                    return CL_EMEM;
                }
                allocated_tempfile = true;
            }

            out_file = open(tempfile, O_RDWR | O_CREAT | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR);
            if (-1 == out_file) {
                cli_warnmsg("cli_unzip: decrypt - failed to create temporary file %s\n", tempfile);
                cli_mark_scan_incomplete(ctx, "ZIP encrypted member temporary output could not be opened");
                if (allocated_tempfile)
                    free(tempfile);
                if (temporary_reserved)
                    cli_scan_release_temporary(ctx, temporary_reserved);
                return CL_ETMPFILE;
            }

            ret = CL_SUCCESS;
            for (;;) {
                ret = cli_checktimelimit(ctx);
                if (CL_SUCCESS != ret)
                    break;

                while (input_pos < length) {
                    uint8_t plain = data[input_pos++] ^ zdecryptbyte(key);
                    zupdatekey(key, plain);
                    obuf[buffered++] = (char)plain;

                    if (buffered == sizeof(obuf)) {
                        if (cli_writen(out_file, obuf, buffered) != buffered) {
                            cli_mark_scan_incomplete(ctx, "ZIP encrypted member could not be staged completely");
                            ret = CL_EWRITE;
                            break;
                        }
                        if ((uint64_t)buffered > UINT64_MAX - total) {
                            ret = CL_EUNPACK;
                            break;
                        }
                        total += buffered;
                        buffered = 0;
                    }
                }
                if (CL_SUCCESS != ret || 0 == input.remaining)
                    break;

                ret = zip_input_refill(&input, &data, &length);
                if (CL_SUCCESS != ret || 0 == length) {
                    if (CL_SUCCESS == ret)
                        ret = CL_EREAD;
                    break;
                }
                input_pos = 0;
            }

            if (CL_SUCCESS == ret && buffered) {
                if (cli_writen(out_file, obuf, buffered) != buffered) {
                    cli_mark_scan_incomplete(ctx, "ZIP encrypted member could not be staged completely");
                    ret = CL_EWRITE;
                } else {
                    total += buffered;
                }
            }

            if (CL_SUCCESS == ret && total != csize - SIZEOF_ENCRYPTION_HEADER) {
                cli_dbgmsg("cli_unzip: ZipCrypto produced " STDu64 " compressed bytes, expected " STDu64 "\n",
                           total, csize - SIZEOF_ENCRYPTION_HEADER);
                ret = CL_EUNPACK;
            }

            if (CL_SUCCESS == ret) {
                if (total > SIZE_MAX) {
                    cli_mark_scan_incomplete(ctx, "ZIP decrypted member cannot be represented by this process");
                    ret = CL_EUNPACK;
                }
            }

            if (CL_SUCCESS == ret) {
                decrypted_map = fmap_new(out_file, 0, (size_t)total, NULL, tempfile);
                if (!decrypted_map) {
                    cli_warnmsg("cli_unzip: decrypt - failed to create bounded fmap on %s\n", tempfile);
                    cli_mark_scan_incomplete(ctx, "ZIP encrypted member temporary map could not be created");
                    ret = CL_EMAP;
                }
            }

            if (CL_SUCCESS == ret) {
                ret = unz_from_fmap(decrypted_map, 0, total, usize, method, flags,
                                    expected_crc32,
                                    num_files_unzipped, ctx, tmpd, zcb,
                                    original_filename, true);
            }

            if (decrypted_map)
                fmap_free(decrypted_map);
            if (close(out_file) == -1) {
                cli_mark_scan_incomplete(ctx, "ZIP encrypted member temporary output could not be closed");
                if (CL_SUCCESS == ret || CL_VERIFIED == ret)
                    ret = CL_EWRITE;
            }
            if (!ctx->engine->keeptmp && cli_unlink(tempfile)) {
                cli_mark_scan_incomplete(ctx, "ZIP encrypted member temporary output could not be removed");
                if (CL_SUCCESS == ret || CL_VERIFIED == ret)
                    ret = CL_EUNLINK;
            }
            if (allocated_tempfile)
                free(tempfile);

            if (temporary_reserved)
                cli_scan_release_temporary(ctx, temporary_reserved);

            if (zip_extraction_error_is_incomplete(ret))
                cli_mark_scan_incomplete(ctx, "ZIP encrypted member did not reach a complete extraction state");
            return ret;
        }

        if (pass_zip)
            pass_zip = pass_zip->next;
        else
            pass_any = pass_any->next;
    }

    cli_dbgmsg("cli_unzip: no configured password decrypted the ZipCrypto member\n");
    cli_mark_scan_incomplete(ctx, "ZIP encrypted member could not be decrypted with a configured password");
    return CL_EUNPACK;
}

static cl_error_t unz_from_fmap(
    fmap_t *map,
    size_t data_offset,
    uint64_t csize,
    uint64_t usize,
    uint16_t method,
    uint16_t flags,
    uint32_t expected_crc32,
    size_t *num_files_unzipped,
    cli_ctx *ctx,
    char *tmpd,
    zip_cb zcb,
    const char *original_filename,
    bool decrypted)
{
    if (ALG_STORED == method || ALG_DEFLATE == method ||
        ALG_DEFLATE64 == method || ALG_BZIP2 == method ||
        ALG_IMPLODE == method) {
        return unz_stream(map, data_offset, csize, usize, method, flags,
                          expected_crc32, num_files_unzipped,
                          ctx, tmpd, zcb, original_filename, decrypted);
    }

    cli_dbgmsg("cli_unzip: unsupported method (%u)\n", method);
    cli_mark_scan_incomplete(ctx, "ZIP compression method is unsupported by a bounded decoder");
    /* Keep the former contiguous decoder compiled until it is removed in a
     * cleanup-only change, but never dispatch archive input to it. */
    (void)unz_legacy;
    return CL_EUNPACK;
}

/**
 * @brief Parse, extract, and scan a file using the local file header.
 *
 * Usage of the `record` parameter will alter behavior so it only collect file record metadata and does not extract or scan any files.
 *
 * @param[in,out] ctx                   scan context
 * @param loff                          offset of the local file header
 * @param[in,out] num_files_unzipped    current number of files that have been unzipped
 * @param file_count                    current number of files that have been discovered
 * @param central_header                pointer to central directory header
 * @param tmpd                          temp directory path name
 * @param detect_encrypted              bool: if encrypted files should raise heuristic alert
 * @param zcb                           callback function to invoke after extraction (default: scan)
 * @param record                        (optional) a pointer to a struct to store file record information.
 * @param[out] file_record_size         (optional) if not NULL, will be set to the size of the file header + file data.
 * @return cl_error_t                   CL_SUCCESS on success, or an error code on failure.
 */
static cl_error_t parse_local_file_header(
    cli_ctx *ctx,
    size_t loff,
    size_t *num_files_unzipped,
    size_t file_count,
    const uint8_t *central_header,
    char *tmpd,
    int detect_encrypted,
    zip_cb zcb,
    const struct zip_central_values *central_values,
    struct zip_record *record,
    size_t *file_record_size)
{
    cl_error_t status = CL_ERROR;
    cl_error_t ret;
    const uint8_t *local_header = NULL;
    char name[256]              = {0};
    char *original_filename     = NULL;
    uint64_t csize = 0, usize = 0;
    struct zip_central_values local_values;

    uint32_t name_size = 0;
    const char *src    = NULL;

    const uint8_t *zip       = NULL;
    size_t bytes_remaining   = 0;
    size_t data_offset       = 0;
    size_t after_data_offset = 0;
    size_t descriptor_size   = 0;
    bool zip64_sizes         = false;
    bool masked_local_values = false;
    uint32_t expected_crc32  = 0;
    uint32_t metadata_crc32  = 0;

    if (NULL != file_record_size) {
        *file_record_size = 0;
    }

    local_header = fmap_need_off(ctx->fmap, loff, SIZEOF_LOCAL_HEADER);
    if (NULL == local_header) {
        cli_dbgmsg("cli_unzip: local header - out of file or work complete\n");
        status = CL_EPARSE;
        goto done;
    }
    if (LOCAL_HEADER_magic != ZIP_MAGIC_LOCAL_FILE_HEADER) {
        cli_dbgmsg("cli_unzip: local header - bad magic\n");
        status = CL_EFORMAT;
        goto done;
    }
    masked_local_values = (LOCAL_HEADER_flags & F_MSKED) != 0;
    bytes_remaining     = ctx->fmap->len - loff;

    zip = local_header + SIZEOF_LOCAL_HEADER;
    bytes_remaining -= SIZEOF_LOCAL_HEADER;

    if (bytes_remaining < LOCAL_HEADER_flen) {
        cli_dbgmsg("cli_unzip: local header - fname out of file\n");
        cli_mark_scan_incomplete(ctx, "ZIP local filename field is outside the archive map");
        status = CL_EPARSE;
        goto done;
    }

    name_size = LOCAL_HEADER_flen >= (sizeof(name) - 1) ? sizeof(name) - 1 : LOCAL_HEADER_flen;
    cli_dbgmsg("cli_unzip: name_size %u\n", name_size);
    src = fmap_need_ptr_once(ctx->fmap, zip, name_size);
    if (name_size && (NULL == src)) {
        cli_mark_scan_incomplete(ctx, "ZIP local filename field could not be read completely");
        status = CL_EREAD;
        goto done;
    }
    if (name_size) {
        memcpy(name, src, name_size);
        if (CL_SUCCESS != cli_basename(name, name_size, &original_filename, true /* posix_support_backslash_pathsep */)) {
            original_filename = NULL;
        }
    }

    zip += LOCAL_HEADER_flen;
    bytes_remaining -= LOCAL_HEADER_flen;

    if (central_header) {
        if (LOCAL_HEADER_method != CENTRAL_HEADER_method ||
            LOCAL_HEADER_flags != CENTRAL_HEADER_flags) {
            cli_mark_scan_incomplete(ctx, "ZIP local and central headers disagree on method or flags");
            status = CL_EFORMAT;
            goto done;
        }

        if (!(LOCAL_HEADER_flags & F_USEDD) && !masked_local_values) {
            uint64_t local_csize = LOCAL_HEADER_csize;
            uint64_t local_usize = LOCAL_HEADER_usize;

            if (LOCAL_HEADER_elen > bytes_remaining) {
                cli_mark_scan_incomplete(ctx, "ZIP local extra field is outside the archive map");
                status = CL_EPARSE;
                goto done;
            }
            if (local_csize == UINT32_MAX || local_usize == UINT32_MAX) {
                const uint8_t *extra = fmap_need_off_once(
                    ctx->fmap,
                    loff + SIZEOF_LOCAL_HEADER + LOCAL_HEADER_flen,
                    LOCAL_HEADER_elen);

                if (!zip64_read_catalogue_values(ctx, extra, LOCAL_HEADER_elen,
                                                 (uint32_t)local_csize,
                                                 (uint32_t)local_usize,
                                                 0, &local_values)) {
                    cli_mark_scan_incomplete(ctx, "ZIP64 local header has an invalid extended-information field");
                    status = CL_EFORMAT;
                    goto done;
                }
                local_csize = local_values.compressed_size;
                local_usize = local_values.uncompressed_size;
            }

            if (!central_values || local_csize != central_values->compressed_size ||
                local_usize != central_values->uncompressed_size ||
                LOCAL_HEADER_crc32 != CENTRAL_HEADER_crc32) {
                cli_mark_scan_incomplete(ctx, "ZIP local and central headers disagree on member sizes or CRC");
                status = CL_EFORMAT;
                goto done;
            }
        }
    }

    if (central_header && central_values) {
        csize          = central_values->compressed_size;
        usize          = central_values->uncompressed_size;
        zip64_sizes    = central_values->zip64_sizes;
        expected_crc32 = CENTRAL_HEADER_crc32;
    } else {
        csize          = LOCAL_HEADER_csize;
        usize          = LOCAL_HEADER_usize;
        expected_crc32 = LOCAL_HEADER_crc32;

        if (csize == UINT32_MAX || usize == UINT32_MAX) {
            const uint8_t *extra = NULL;

            if (LOCAL_HEADER_elen > bytes_remaining) {
                cli_dbgmsg("cli_unzip: local header - extra out of file\n");
                cli_mark_scan_incomplete(ctx, "ZIP64 local extra field is outside the archive map");
                status = CL_EPARSE;
                goto done;
            }
            extra = fmap_need_off_once(ctx->fmap, loff + SIZEOF_LOCAL_HEADER + LOCAL_HEADER_flen, LOCAL_HEADER_elen);
            /* The local header has no catalogue offset field to resolve. */
            if (!zip64_read_catalogue_values(ctx, extra, LOCAL_HEADER_elen, csize, usize, 0, &local_values)) {
                cli_dbgmsg("cli_unzip: local header - invalid ZIP64 extra field\n");
                cli_mark_scan_incomplete(ctx, "ZIP64 local header has an invalid extended-information field");
                status = CL_EFORMAT;
                goto done;
            }
            csize       = local_values.compressed_size;
            usize       = local_values.uncompressed_size;
            zip64_sizes = local_values.zip64_sizes;
        }
    }

    if (masked_local_values && (!central_header || !central_values)) {
        /* A standalone local header cannot establish the member extent when
         * bit 13 masks its CRC and size fields.  It remains fail-visible
         * rather than treating the masked prefix as a complete archive. */
        cli_mark_scan_incomplete(ctx, "ZIP masked local-header values require a central directory");
        status = CL_EPARSE;
        goto done;
    }

    metadata_crc32 = central_header && central_values ? CENTRAL_HEADER_crc32 : LOCAL_HEADER_crc32;

    /* Print ZMD container metadata signature and try matching the metadata AFTER we have all the metadata. */
    cli_dbgmsg("cli_unzip: local header - ZMDNAME:%d:%s:" STDu64 ":" STDu64 ":%x:%u:%zu:%u\n",
               ((LOCAL_HEADER_flags & F_ENCR) != 0), name, usize, csize, metadata_crc32, LOCAL_HEADER_method, file_count, ctx->recursion_level);
    /* ZMDfmt virname:encrypted(0-1):filename(exact|*):usize(exact|*):csize(exact|*):crc32(exact|*):method(exact|*):fileno(exact|*):maxdepth(exact|*) */

    /* Scan file header metadata. */
    if (csize > SIZE_MAX || usize > SIZE_MAX) {
        cli_mark_scan_incomplete(ctx, "ZIP64 member size cannot be represented by the metadata matcher");
        status = CL_EFORMAT;
        goto done;
    }
    ret = cli_matchmeta(ctx, name, (size_t)csize, (size_t)usize,
                        (LOCAL_HEADER_flags & F_ENCR) != 0, file_count, metadata_crc32);
    if (ret != CL_SUCCESS) {
        status = ret;
        goto done;
    }

    /* General-purpose bit 6 selects strong encryption.  Do not infer the
     * encryption scheme solely from F_ENCR: hostile archives can set the bits
     * inconsistently, and feeding opaque ciphertext to a normal decoder can
     * otherwise produce an apparent clean scan. */
    if (LOCAL_HEADER_flags & F_STRNG) {
        cli_mark_scan_incomplete(ctx, "ZIP strong encryption is unsupported");
        status = CL_EUNPACK;
        goto done;
    }

    if (detect_encrypted && (LOCAL_HEADER_flags & F_ENCR) && SCAN_HEURISTIC_ENCRYPTED_ARCHIVE) {
        cli_dbgmsg("cli_unzip: Encrypted files found in archive.\n");
        ret = cli_append_potentially_unwanted(ctx, "Heuristics.Encrypted.Zip");
        if (ret != CL_SUCCESS) {
            status = ret;
            goto done;
        }
    }

    if (LOCAL_HEADER_flags & F_USEDD) {
        cli_dbgmsg("cli_unzip: local header - has data desc\n");
        if (!central_header) {
            /* Without an authoritative central-directory size there is no
             * bounded way to distinguish compressed bytes from the optional
             * descriptor signature.  Fail visibly instead of guessing. */
            cli_mark_scan_incomplete(ctx, "ZIP local-only data descriptors are unsupported");
            status = CL_EPARSE;
            goto done;
        }

        if (!central_values) {
            status = CL_EFORMAT;
            goto done;
        }
    }

    if (bytes_remaining < LOCAL_HEADER_elen) {
        cli_dbgmsg("cli_unzip: local header - extra out of file\n");
        cli_mark_scan_incomplete(ctx, "ZIP local extra field is outside the archive map");
        status = CL_EPARSE;
        goto done;
    }

    zip += LOCAL_HEADER_elen;
    bytes_remaining -= LOCAL_HEADER_elen;
    data_offset = loff + (size_t)(zip - local_header);

    if (csize > (uint64_t)bytes_remaining) {
        cli_dbgmsg("cli_unzip: local header - stream out of file\n");
        cli_mark_scan_incomplete(ctx, "ZIP member data is truncated or outside the archive map");
        status = CL_EPARSE;
        goto done;
    }
    after_data_offset = data_offset + (size_t)csize;

    /* Validate the complete trailing descriptor before extraction so no
     * callback can observe a member whose terminal metadata is malformed. */
    if (LOCAL_HEADER_flags & F_USEDD) {
        ret = zip_validate_data_descriptor(ctx, central_header,
                                           after_data_offset,
                                           bytes_remaining - (size_t)csize,
                                           zip64_sizes, csize, usize,
                                           &descriptor_size);
        if (CL_SUCCESS != ret) {
            status = ret;
            goto done;
        }
    }

    if (0 == csize && 0 == usize && expected_crc32) {
        cli_mark_scan_incomplete(ctx, "ZIP empty member has a non-empty CRC32");
        status = CL_EFORMAT;
        goto done;
    }

    if (NULL != record) {
        /* Don't actually unzip if we're just collecting the file record information (offset, sizes) */
        if (NULL == original_filename) {
            record->original_filename = NULL;
        } else {
            record->original_filename = CLI_STRNDUP(original_filename, strlen(original_filename));
        }
        record->local_header_offset = loff;
        record->local_header_size   = zip - local_header;
        record->compressed_size     = csize;
        record->uncompressed_size   = usize;
        record->crc32               = expected_crc32;
        record->method              = LOCAL_HEADER_method;
        record->flags               = LOCAL_HEADER_flags;
        record->encrypted           = (LOCAL_HEADER_flags & F_ENCR) ? 1 : 0;

        status = CL_SUCCESS;
    } else {
        /*
         * Unzip or decompress & then unzip.
         */
        if (!csize) {
            if (usize) {
                cli_mark_scan_incomplete(ctx, "ZIP member reports output but has no compressed data");
                status = CL_EPARSE;
                goto done;
            }
            cli_dbgmsg("cli_unzip: local header - skipping empty file\n");
        } else {
            if (LOCAL_HEADER_flags & F_ENCR) {
                ret = zdecrypt_from_fmap(ctx->fmap, data_offset, csize, usize,
                                         expected_crc32, local_header,
                                         num_files_unzipped, ctx, tmpd, zcb, original_filename);
                if (ret != CL_SUCCESS) {
                    cli_dbgmsg("cli_unzip: local header - zdecrypt failed with %d\n", ret);
                    status = ret;
                    goto done;
                }
            } else {
                ret = unz_from_fmap(ctx->fmap, data_offset, csize, usize, LOCAL_HEADER_method,
                                    LOCAL_HEADER_flags, expected_crc32,
                                    num_files_unzipped, ctx, tmpd, zcb,
                                    original_filename, false);
                if (ret != CL_SUCCESS) {
                    cli_dbgmsg("cli_unzip: local header - unz failed with %d\n", ret);
                    status = ret;
                    goto done;
                }
            }
        }
    }

    bytes_remaining -= (size_t)csize;
    if (descriptor_size > bytes_remaining) {
        cli_mark_scan_incomplete(ctx, "ZIP descriptor accounting exceeded the archive map");
        status = CL_EPARSE;
        goto done;
    }
    after_data_offset += descriptor_size;
    bytes_remaining -= descriptor_size;

    /* Success */
    if (file_record_size) {
        *file_record_size = after_data_offset - loff;
    }
    status = CL_SUCCESS;

done:
    if (NULL != local_header) {
        fmap_unneed_off(ctx->fmap, loff, SIZEOF_LOCAL_HEADER);
    }

    if (NULL != original_filename) {
        free(original_filename);
    }

    return status;
}

cl_error_t cli_unzip_single_header_check(
    cli_ctx *ctx,
    size_t offset,
    size_t *size)
{
    cl_error_t status             = CL_ERROR;
    struct zip_record file_record = {0};
    cl_error_t ret;
    const uint8_t *local_header;

    if (NULL == ctx || NULL == ctx->fmap)
        return CL_ENULLARG;

    local_header = fmap_need_off(ctx->fmap, offset, SIZEOF_LOCAL_HEADER);
    if (NULL == local_header) {
        cli_dbgmsg("cli_unzip: single header check - local header is truncated\n");
        return CL_EPARSE;
    }
    if (LOCAL_HEADER_flags & F_MSKED) {
        /* A SFX admission probe has no central directory to supply the
         * masked extent.  Reject this weak candidate without marking the
         * containing file incomplete; ordinary local-only scanning goes
         * through parse_local_file_header() and remains fail-visible. */
        fmap_unneed_off(ctx->fmap, offset, SIZEOF_LOCAL_HEADER);
        cli_dbgmsg("cli_unzip: single header check - masked local header is not a confirmed ZIP candidate\n");
        return CL_EFORMAT;
    }
    fmap_unneed_off(ctx->fmap, offset, SIZEOF_LOCAL_HEADER);

    ret = parse_local_file_header(
        ctx,
        offset,
        NULL,  /* num_files_unzipped */
        0,     /* file_count */
        NULL,  /* central_header */
        NULL,  /* tmpd */
        false, /* detect_encrypted */
        NULL,  /* zcb */
        NULL,  /* central_values */
        &file_record,
        size);
    if (ret != CL_SUCCESS) {
        cli_dbgmsg("cli_unzip: single header check - failed to parse local file header: %s (%d)\n", cl_strerror(ret), ret);
        status = ret;
        goto done;
    }

    if (file_record.compressed_size == 0 || file_record.uncompressed_size == 0) {
        cli_dbgmsg("cli_unzip: single header check - empty file\n");
        status = CL_EFORMAT;
        goto done;
    }

    status = CL_SUCCESS;

done:
    if (file_record.original_filename) {
        free(file_record.original_filename);
    }

    return status;
}

/**
 * @brief Parse, extract, and scan a file by iterating the central directory.
 *
 * Usage of the `record` parameter will alter behavior so it only collect file record metadata and does not extract or scan any files.
 *
 * @param[in,out] ctx                   scan context
 * @param central_file_header_offset    offset of the file header in the central directory
 * @param[in,out] num_files_unzipped    current number of files that have been unzipped
 * @param file_count                    current number of files that have been discovered
 * @param tmpd                          temp directory path name
 * @param requests                      (optional) structure use to search the zip for files by name
 * @param record                        (optional) a pointer to a struct to store file record information.
 * @param[out] file_record_size         A pointer to a variable to store the size of the file record.
 * @return cl_error_t                   CL_SUCCESS on success, or an error code on failure.
 */
static cl_error_t parse_central_directory_file_header(
    cli_ctx *ctx,
    size_t central_file_header_offset,
    size_t *num_files_unzipped,
    size_t file_count,
    char *tmpd,
    struct zip_requests *requests,
    struct zip_record *record,
    size_t *file_record_size)
{
    cl_error_t status = CL_ERROR;
    cl_error_t ret;

    char name[256] = {0};

    const uint8_t *central_header = NULL;
    const uint8_t *central_magic  = NULL;
    const uint8_t *central_extra  = NULL;
    struct zip_central_values central_values;
    size_t index;
    uint32_t magic;

    *file_record_size = 0;

    if (cli_checktimelimit(ctx) != CL_SUCCESS) {
        cli_dbgmsg("cli_unzip: central header - Time limit reached (max: %u)\n", ctx->engine->maxscantime);
        status = CL_ETIMEOUT;
        goto done;
    }

    central_magic = fmap_need_off_once(ctx->fmap, central_file_header_offset, sizeof(uint32_t));
    if (NULL == central_magic) {
        cli_mark_scan_incomplete(ctx, "ZIP central-directory record signature is truncated");
        status = CL_EPARSE;
        goto done;
    }
    magic = cli_readint32(central_magic);

    if (magic == ZIP_MAGIC_CENTRAL_DIRECTORY_RECORD_END || magic == ZIP_MAGIC_ZIP64_END) {
        cli_dbgmsg("cli_unzip: central header - reached end of central directory.\n");
        /* A zero-sized successful record is the iterator sentinel.  Reserve
         * CL_BREAK for an application callback so cancellation cannot be
         * mistaken for an ordinary end-of-directory condition. */
        status = CL_SUCCESS;
        goto done;
    }

    if (magic != ZIP_MAGIC_CENTRAL_DIRECTORY_RECORD_BEGIN) {
        cli_dbgmsg("cli_unzip: central header - file header offset has wrong magic\n");
        status = CL_EPARSE;
        goto done;
    }

    central_header = fmap_need_off(ctx->fmap, central_file_header_offset, SIZEOF_CENTRAL_HEADER);
    if (NULL == central_header) {
        cli_mark_scan_incomplete(ctx, "ZIP central-directory record is truncated");
        status = CL_EPARSE;
        goto done;
    }

    if (central_file_header_offset > ctx->fmap->len ||
        SIZEOF_CENTRAL_HEADER > ctx->fmap->len - central_file_header_offset) {
        cli_dbgmsg("cli_unzip: central header - fixed header out of file\n");
        status = CL_EPARSE;
        goto done;
    }
    index = central_file_header_offset + SIZEOF_CENTRAL_HEADER;

    cli_dbgmsg("cli_unzip: central header - flags %x - method %x - csize %x - usize %x - flen %x - elen %x - clen %x - disk %x - off %x\n",
               CENTRAL_HEADER_flags, CENTRAL_HEADER_method, CENTRAL_HEADER_csize, CENTRAL_HEADER_usize, CENTRAL_HEADER_flen, CENTRAL_HEADER_extra_len, CENTRAL_HEADER_comment_len, CENTRAL_HEADER_disk_num, CENTRAL_HEADER_off);

    if (CENTRAL_HEADER_flen > ctx->fmap->len - index) {
        cli_dbgmsg("cli_unzip: central header - fname out of file\n");
        status = CL_EPARSE;
        goto done;
    }

    size_t size     = (CENTRAL_HEADER_flen >= sizeof(name)) ? sizeof(name) - 1 : CENTRAL_HEADER_flen;
    const char *src = fmap_need_off_once(ctx->fmap, index, size);
    if (size && (NULL == src)) {
        cli_mark_scan_incomplete(ctx, "ZIP central filename field could not be read completely");
        status = CL_EREAD;
        goto done;
    }
    if (size) {
        memcpy(name, src, size);
        name[size] = '\0';
        cli_dbgmsg("cli_unzip: central header - fname: %s\n", name);
    }
    index += CENTRAL_HEADER_flen;

    if (CENTRAL_HEADER_extra_len > ctx->fmap->len - index) {
        cli_dbgmsg("cli_unzip: central header - extra out of file\n");
        status = CL_EPARSE;
        goto done;
    }
    central_extra = fmap_need_off_once(ctx->fmap, index, CENTRAL_HEADER_extra_len);
    if (!zip64_read_catalogue_values(ctx,
                                     central_extra,
                                     CENTRAL_HEADER_extra_len,
                                     CENTRAL_HEADER_csize,
                                     CENTRAL_HEADER_usize,
                                     CENTRAL_HEADER_off,
                                     &central_values)) {
        cli_dbgmsg("cli_unzip: central header - invalid ZIP64 extra field\n");
        cli_mark_scan_incomplete(ctx, "ZIP64 central header has an invalid extended-information field");
        status = CL_EFORMAT;
        goto done;
    }

    /* requests do not supply a ctx; also prevent multiple scans */
    if (central_values.compressed_size > SIZE_MAX || central_values.uncompressed_size > SIZE_MAX) {
        cli_mark_scan_incomplete(ctx, "ZIP64 member size cannot be represented by the metadata matcher");
        status = CL_EFORMAT;
        goto done;
    }
    ret = cli_matchmeta(ctx, name,
                        (size_t)central_values.compressed_size,
                        (size_t)central_values.uncompressed_size,
                        (CENTRAL_HEADER_flags & F_ENCR) != 0,
                        file_count,
                        CENTRAL_HEADER_crc32);
    if (CL_SUCCESS != ret) {
        /* Metadata and application callbacks may return cancellation, trust,
         * detection, or a critical error.  None may be discarded merely
         * because this is the catalogue pass. */
        status = ret;
        goto done;
    }

    index += CENTRAL_HEADER_extra_len;

    if (CENTRAL_HEADER_comment_len > ctx->fmap->len - index) {
        cli_dbgmsg("cli_unzip: central header - comment out of file\n");
        status = CL_EPARSE;
        goto done;
    }
    index += CENTRAL_HEADER_comment_len;

    *file_record_size = index - central_file_header_offset;

    if (!requests) {
        // Parse the local file header.
        // We'll verify enough bytes available for a local file header when we parse it.

        status = parse_local_file_header(
            ctx,
            central_values.local_header_offset,
            num_files_unzipped,
            file_count,
            central_header,
            tmpd,
            1, /* detect_encrypted */
            zip_scan_cb,
            &central_values,
            record,
            NULL); /* file_record_size */
    } else {
        int i;
        size_t len;

        for (i = 0; i < requests->namecnt; ++i) {
            cli_dbgmsg("cli_unzip: central header - checking for %i: %s\n", i, requests->names[i]);

            len = MIN(sizeof(name) - 1, requests->namelens[i]);
            if (!strncmp(requests->names[i], name, len)) {
                requests->match = 1;
                requests->found = i;
                requests->loff  = central_values.local_header_offset;
            }
        }

        status = CL_SUCCESS;
    }

done:
    if (NULL != central_header) {
        fmap_unneed_ptr(ctx->fmap, central_header, SIZEOF_CENTRAL_HEADER);
    }

    return status;
}

/**
 * @brief Sort zip_record structures based on local file offset.
 *
 * @param first
 * @param second
 * @return int 1 if first record's offset is higher than second's.
 * @return int 0 if first and second record offsets are equal.
 * @return int -1 if first record's offset is less than second's.
 */
static int sort_by_file_offset(const void *first, const void *second)
{
    const struct zip_record *a = (const struct zip_record *)first;
    const struct zip_record *b = (const struct zip_record *)second;

    /* Avoid return x - y, which can cause undefined behaviour
       because of signed integer overflow. */
    if (a->local_header_offset < b->local_header_offset)
        return -1;
    else if (a->local_header_offset > b->local_header_offset)
        return 1;

    return 0;
}

/**
 * @brief Create a catalogue of the central directory.
 *
 * This function indexes every file in the central directory.
 * It creates a zip record catalogue and sorts them by file entry offset.
 * Then it iterates the sorted file records looking for overlapping files.
 *
 * The caller is responsible for freeing the catalogue.
 * The catalogue may contain duplicate items, which should be skipped.
 *
 * @param ctx               The scanning context
 * @param coff              The central directory offset
 * @param[out] catalogue    A catalogue of zip_records found in the central directory.
 * @param[out] num_records  The number of records in the catalogue.
 * @return cl_error_t  CL_SUCCESS if no overlapping files
 * @return cl_error_t  CL_VIRUS if overlapping files and heuristic alerts are enabled
 * @return cl_error_t  CL_EFORMAT if overlapping files and heuristic alerts are disabled
 * @return cl_error_t  CL_ETIMEOUT if the scan time limit is exceeded.
 * @return cl_error_t  CL_EMEM for memory allocation errors.
 */
cl_error_t index_the_central_directory(
    cli_ctx *ctx,
    size_t coff,
    struct zip_record **catalogue,
    size_t *num_records)
{
    cl_error_t status = CL_ERROR;
    cl_error_t ret;

    size_t num_record_blocks = 0;
    size_t index             = 0;

    struct zip_record *zip_catalogue = NULL;
    size_t records_count             = 0;
    struct zip_record *curr_record   = NULL;
    struct zip_record *prev_record   = NULL;
    uint32_t num_overlapping_files   = 0;
    bool keep_catalogue_on_limit     = false;
    bool maxfiles_exceeded           = false;

    size_t record_size   = 0;
    size_t record_offset = coff;

    if (NULL == catalogue || NULL == num_records) {
        cli_errmsg("index_the_central_directory: Invalid NULL arguments\n");
        goto done;
    }

    *catalogue   = NULL;
    *num_records = 0;

    CLI_CALLOC_OR_GOTO_DONE(
        zip_catalogue,
        1,
        sizeof(struct zip_record) * ZIP_RECORDS_CHECK_BLOCKSIZE,
        status = CL_EMEM);

    num_record_blocks = 1;

    cli_dbgmsg("cli_unzip: checking for non-recursive zip bombs...\n");

    do {
        ret = parse_central_directory_file_header(
            ctx,
            record_offset,
            NULL, // num_files_unzipped not required
            records_count + 1,
            NULL, // tmpd not required
            NULL,
            &(zip_catalogue[records_count]),
            &record_size);

        if (ret != CL_SUCCESS) {
            /* Every callback/error result is terminal.  Ordinary iteration
             * completion is CL_SUCCESS with a zero-sized record. */
            status = ret;
            goto done;
        }

        if (record_size == 0) {
            // No more files (previous was last).
            break;
        }

        // Found a record.
        records_count++;

        if (record_offset > ctx->fmap->len || record_size > ctx->fmap->len - record_offset) {
            cli_dbgmsg("cli_unzip: central directory record exceeds the mapped file\n");
            status = CL_EFORMAT;
            goto done;
        }

        // Increment the record offset by the size of the record for the next iteration.
        record_offset += record_size;

        if (cli_checktimelimit(ctx) != CL_SUCCESS) {
            cli_dbgmsg("cli_unzip: Time limit reached (max: %u)\n", ctx->engine->maxscantime);
            status = CL_ETIMEOUT;
            goto done;
        }

        /* The configured count is inclusive: scan exactly MaxFiles records,
         * and fail visibly only after discovering one additional record. */
        if (ctx->engine->maxfiles && records_count > ctx->engine->maxfiles) {
            cli_dbgmsg("cli_unzip: Files limit reached (max: %u)\n", ctx->engine->maxfiles);
            cli_append_potentially_unwanted_if_heur_exceedsmax(ctx, "Heuristics.Limits.Exceeded.MaxFiles", CL_EMAXFILES);
            if (ctx->abort_scan) {
                status = ctx->scan_timed_out ? CL_ETIMEOUT : CL_BREAK;
                goto done;
            }
            /* Keep the permitted prefix so the caller can still scan it. */
            records_count--;
            free(zip_catalogue[records_count].original_filename);
            memset(&zip_catalogue[records_count], 0, sizeof(zip_catalogue[records_count]));
            maxfiles_exceeded = true;
            break;
        }

        if (num_record_blocks * ZIP_RECORDS_CHECK_BLOCKSIZE == records_count + 1) {
            cli_dbgmsg("cli_unzip: Filled a block of zip records. Allocating an additional block for more zip records...\n");

            CLI_MAX_REALLOC_OR_GOTO_DONE(
                zip_catalogue,
                sizeof(struct zip_record) * ZIP_RECORDS_CHECK_BLOCKSIZE * (num_record_blocks + 1),
                status = CL_EMEM);

            num_record_blocks++;
            /* zero out the memory for the new records */
            memset(&(zip_catalogue[records_count]), 0,
                   sizeof(struct zip_record) * (ZIP_RECORDS_CHECK_BLOCKSIZE * num_record_blocks - records_count));
        }
    } while (1);

    if (records_count > 1) {
        /*
         * Sort the records by local file offset
         */
        cli_qsort(zip_catalogue, records_count, sizeof(struct zip_record), sort_by_file_offset);

        /*
         * Detect overlapping files.
         */
        for (index = 1; index < records_count; index++) {
            prev_record = &(zip_catalogue[index - 1]);
            curr_record = &(zip_catalogue[index]);

            size_t prev_record_end;
            size_t curr_record_end;

            /* Check for integer overflow in native catalogue coordinates. */
            if (!zip_record_end_checked(prev_record, &prev_record_end) ||
                !zip_record_end_checked(curr_record, &curr_record_end)) {
                cli_dbgmsg("cli_unzip: Integer overflow detected; invalid data sizes in zip file headers.\n");
                status = CL_EFORMAT;
                goto done;
            }

            if ((curr_record->local_header_offset >= prev_record->local_header_offset &&
                 prev_record_end >= ZIP_RECORD_OVERLAP_FUDGE_FACTOR &&
                 curr_record->local_header_offset < prev_record_end - ZIP_RECORD_OVERLAP_FUDGE_FACTOR) ||
                (prev_record->local_header_offset >= curr_record->local_header_offset &&
                 curr_record_end >= ZIP_RECORD_OVERLAP_FUDGE_FACTOR &&
                 prev_record->local_header_offset < curr_record_end - ZIP_RECORD_OVERLAP_FUDGE_FACTOR)) {
                /* Overlapping file detected */
                num_overlapping_files++;

                if ((curr_record->local_header_offset == prev_record->local_header_offset) &&
                    (curr_record->local_header_size == prev_record->local_header_size) &&
                    (curr_record->compressed_size == prev_record->compressed_size)) {
                    cli_dbgmsg("cli_unzip: Ignoring duplicate file entry at offset: 0x%zx.\n", curr_record->local_header_offset);
                } else {
                    cli_dbgmsg("cli_unzip: Overlapping files detected.\n");
                    cli_dbgmsg("    previous file end:  %zu\n", prev_record_end);
                    cli_dbgmsg("    current file start: %zu\n", curr_record->local_header_offset);

                    if (ZIP_MAX_NUM_OVERLAPPING_FILES < num_overlapping_files) {
                        status = CL_EFORMAT;

                        if (SCAN_HEURISTICS) {
                            ret = cli_append_potentially_unwanted(ctx, "Heuristics.Zip.OverlappingFiles");
                            if (CL_SUCCESS != ret) {
                                status = ret;
                            }
                        }

                        goto done;
                    }
                }
            }

            if (cli_checktimelimit(ctx) != CL_SUCCESS) {
                cli_dbgmsg("cli_unzip: Time limit reached (max: %u)\n", ctx->engine->maxscantime);
                status = CL_ETIMEOUT;
                goto done;
            }
        }
    }

    *catalogue   = zip_catalogue;
    *num_records = records_count;
    if (maxfiles_exceeded) {
        keep_catalogue_on_limit = true;
        status                  = CL_EMAXFILES;
    } else {
        status = CL_SUCCESS;
    }

done:

    if (CL_SUCCESS != status && !keep_catalogue_on_limit) {
        if (NULL != zip_catalogue) {
            size_t i;
            for (i = 0; i < records_count; i++) {
                if (NULL != zip_catalogue[i].original_filename) {
                    free(zip_catalogue[i].original_filename);
                    zip_catalogue[i].original_filename = NULL;
                }
            }
            free(zip_catalogue);
            zip_catalogue = NULL;
        }
    }

    return status;
}

/**
 * @brief Index local file headers between two file offsets
 *
 * This function indexes every file within certain file offsets in a zip file.
 * It places the indexed local file headers into a catalogue. If there are
 * already elements in the catalogue, it appends the found files to the
 * catalogue.
 *
 * The caller is responsible for freeing the catalogue.
 * The catalogue may contain duplicate items, which should be skipped.
 *
 * @param ctx               The scanning context
 * @param map               The file map
 * @param fsize             The file size
 * @param start_offset      The start file offset
 * @param end_offset        The end file offset
 * @param file_count        The number of files extracted from the zip file thus far
 * @param[out] temp_catalogue    A catalogue of zip_records. Found files between the two offset bounds will be appended to this list.
 * @param[out] num_records  The number of records in the catalogue.
 * @return cl_error_t  CL_SUCCESS if no overlapping files
 * @return cl_error_t  CL_VIRUS if overlapping files and heuristic alerts are enabled
 * @return cl_error_t  CL_EFORMAT if overlapping files and heuristic alerts are disabled
 * @return cl_error_t  CL_ETIMEOUT if the scan time limit is exceeded.
 * @return cl_error_t  CL_BREAK if the application requested scan cancellation.
 * @return cl_error_t  CL_EMEM for memory allocation errors.
 */
cl_error_t index_local_file_headers_within_bounds(
    cli_ctx *ctx,
    fmap_t *map,
    size_t fsize,
    size_t start_offset,
    size_t end_offset,
    size_t file_count,
    struct zip_record **temp_catalogue,
    size_t *num_records)
{
    cl_error_t status = CL_ERROR;
    cl_error_t ret;

    size_t num_record_blocks = 0;
    size_t index             = 0;

    size_t search_offset             = 0;
    size_t total_file_count          = file_count;
    struct zip_record *zip_catalogue = NULL;
    bool keep_catalogue_on_limit     = false;

    if (NULL == temp_catalogue || NULL == num_records) {
        cli_errmsg("index_local_file_headers_within_bounds: Invalid NULL arguments\n");
        goto done;
    }

    zip_catalogue = *temp_catalogue;

    /*
     * Allocate zip_record if it is empty. If not empty, we will append file headers to the list
     */
    if (NULL == zip_catalogue) {
        CLI_CALLOC_OR_GOTO_DONE(
            zip_catalogue,
            1,
            sizeof(struct zip_record) * ZIP_RECORDS_CHECK_BLOCKSIZE,
            status = CL_EMEM);

        *num_records = 0;
    }

    num_record_blocks = (*num_records / ZIP_RECORDS_CHECK_BLOCKSIZE) + 1;
    index             = *num_records;

    if (start_offset > fsize || end_offset > fsize || start_offset > end_offset) {
        cli_errmsg("index_local_file_headers_within_bounds: Invalid offset arguments: start_offset=%zu, end_offset=%zu, fsize=%zu\n",
                   start_offset, end_offset, fsize);
        status = CL_EPARSE;
        goto done;
    }

    /*
     * Search for local file headers between the start and end offsets. Append found file headers to zip_catalogue
     */
    for (search_offset = start_offset; search_offset < end_offset; search_offset++) {
        /* Malformed padding may contain no header magic at all. Check the
         * deadline independently of header recognition so a large sparse ZIP
         * cannot spend its entire budget in one-byte probes. */
        if (((search_offset - start_offset) & 0x3ff) == 0) {
            if (ctx && cli_checktimelimit(ctx) != CL_SUCCESS) {
                status = CL_ETIMEOUT;
                goto done;
            }
            if (ctx && ctx->abort_scan) {
                status = ctx->scan_timed_out ? CL_ETIMEOUT : CL_BREAK;
                goto done;
            }
        }

        const char *local_file_header = fmap_need_off_once(map, search_offset, SIZEOF_LOCAL_HEADER);
        if (NULL == local_file_header) {
            break; // Reached the end of the file.
        }

        if (cli_readint32(local_file_header) == ZIP_MAGIC_LOCAL_FILE_HEADER) {
            size_t local_file_header_offset = search_offset;
            size_t file_record_size         = 0;

            ret = parse_local_file_header(
                ctx,
                local_file_header_offset,
                NULL,                    /* num_files_unzipped */
                total_file_count + 1,    /* file_count */
                NULL,                    /* central_header */
                NULL,                    /* tmpd */
                1,                       /* detect_encrypted */
                NULL,                    /* zcb */
                NULL,                    /* central_values */
                &(zip_catalogue[index]), /* record */
                &file_record_size);      /* file_record_size */

            /* Only malformed candidate headers are recoverable while probing
             * byte-by-byte. Cancellation, timeout, detections, and resource or
             * I/O failures must escape before this candidate is counted. */
            if (ret != CL_SUCCESS && ret != CL_EPARSE && ret != CL_EFORMAT) {
                status = ret;
                goto done;
            }

            /* A malformed or truncated candidate may follow complete local
             * records.  Preserve those records so cli_unzip() can still scan
             * their independently validated contents.  The sticky incomplete
             * result remains set and is deferred there only while those
             * complete records are scanned. */

            if (file_record_size != 0 && CL_EPARSE != ret) {
                /* The configured count is inclusive.  This parsed candidate
                 * is the first disallowed record when the permitted prefix is
                 * already full.  Discard only the candidate and return the
                 * prefix to the caller for scanning. */
                if (ctx->engine->maxfiles && total_file_count >= ctx->engine->maxfiles) {
                    cli_dbgmsg("cli_unzip: Files limit reached (max: %u)\n", ctx->engine->maxfiles);
                    free(zip_catalogue[index].original_filename);
                    memset(&zip_catalogue[index], 0, sizeof(zip_catalogue[index]));
                    cli_append_potentially_unwanted_if_heur_exceedsmax(ctx, "Heuristics.Limits.Exceeded.MaxFiles", CL_EMAXFILES);
                    if (ctx->abort_scan) {
                        status = ctx->scan_timed_out ? CL_ETIMEOUT : CL_BREAK;
                        goto done;
                    }
                    *temp_catalogue         = zip_catalogue;
                    *num_records            = index;
                    keep_catalogue_on_limit = true;
                    status                  = CL_EMAXFILES;
                    goto done;
                }

                // Found a record.
                cli_dbgmsg("cli_unzip: Found a record\n");
                index++;
                total_file_count++;

                // increment search_offset by the size of the found local file header + file data
                // but decrement by 1 to account for the increment at the end of the loop
                if (file_record_size > end_offset - search_offset) {
                    search_offset = end_offset;
                } else {
                    search_offset += file_record_size - 1;
                }
            }

            if (cli_checktimelimit(ctx) != CL_SUCCESS) {
                cli_dbgmsg("cli_unzip: Time limit reached (max: %u)\n", ctx->engine->maxscantime);
                status = CL_ETIMEOUT;
                goto done;
            }

            if (num_record_blocks * ZIP_RECORDS_CHECK_BLOCKSIZE == index + 1) {
                // Filled up the current block of zip records, need to allocate more space to fit additional records.
                cli_dbgmsg("cli_unzip: Filled a zip record block. Allocating an additional block for more zip records...\n");

                CLI_MAX_REALLOC_OR_GOTO_DONE(
                    zip_catalogue,
                    sizeof(struct zip_record) * ZIP_RECORDS_CHECK_BLOCKSIZE * (num_record_blocks + 1),
                    status = CL_EMEM);

                num_record_blocks++;
                /* zero out the memory for the new records */
                memset(&(zip_catalogue[index]), 0,
                       sizeof(struct zip_record) * (ZIP_RECORDS_CHECK_BLOCKSIZE * num_record_blocks - index));
            }
        }
    }

    *temp_catalogue = zip_catalogue;
    *num_records    = index;
    status          = CL_SUCCESS;

done:
    if (CL_SUCCESS != status && !keep_catalogue_on_limit) {
        if (NULL != zip_catalogue) {
            size_t i;
            for (i = 0; i < index; i++) {
                if (NULL != zip_catalogue[i].original_filename) {
                    free(zip_catalogue[i].original_filename);
                    zip_catalogue[i].original_filename = NULL;
                }
            }
            free(zip_catalogue);
            zip_catalogue   = NULL;
            *temp_catalogue = NULL; // zip_catalogue and *temp_catalogue have the same value. Set temp_catalogue to NULL to ensure no use after free
        }
    }

    return status;
}

/**
 * @brief Add files not present in the central directory to the catalogue
 *
 * This function indexes every file not present in the central directory.
 * It searches through all the local file headers in the zip file and
 * adds any that are found that were not already in the catalogue.
 *
 * The caller is responsible for freeing the catalogue.
 * The catalogue may contain duplicate items, which should be skipped.
 *
 * @param ctx               The scanning context
 * @param map               The file map
 * @param fsize             The file size
 * @param[in, out] catalogue    A catalogue of zip_records found in the central directory.
 * @param[in, out] num_records  The number of records in the catalogue.
 * @return cl_error_t  CL_SUCCESS if no overlapping files
 * @return cl_error_t  CL_VIRUS if overlapping files and heuristic alerts are enabled
 * @return cl_error_t  CL_EFORMAT if overlapping files and heuristic alerts are disabled
 * @return cl_error_t  CL_ETIMEOUT if the scan time limit is exceeded.
 * @return cl_error_t  CL_EMEM for memory allocation errors.
 */
cl_error_t index_local_file_headers(
    cli_ctx *ctx,
    fmap_t *map,
    size_t fsize,
    struct zip_record **catalogue,
    size_t *num_records)
{
    cl_error_t status = CL_ERROR;
    cl_error_t ret;

    size_t i                 = 0;
    size_t start_offset      = 0;
    size_t end_offset        = 0;
    size_t total_files_found = 0;

    struct zip_record *temp_catalogue     = NULL;
    struct zip_record *combined_catalogue = NULL;
    struct zip_record *curr_record        = NULL;
    struct zip_record *next_record        = NULL;
    struct zip_record *prev_record        = NULL;
    size_t local_file_headers_count       = 0;
    uint32_t num_overlapping_files        = 0;
    bool limit_crossed                    = false;
    bool keep_catalogue_on_limit          = false;

    if (NULL == catalogue || NULL == num_records || NULL == *catalogue) {
        cli_dbgmsg("index_local_file_headers: Invalid NULL arguments\n");
        goto done;
    }

    total_files_found = *num_records;

    /*
     * Generate a list of zip records found before, between, and after the zip records already in catalogue
     * First, scan between the start of the file and the first zip_record offset (or the end of the file if no zip_records have been found)
     */
    if (*num_records == 0) {
        end_offset = fsize;
    } else {
        end_offset = (*catalogue)[0].local_header_offset;
    }

    ret = index_local_file_headers_within_bounds(
        ctx,
        map,
        fsize,
        start_offset,
        end_offset,
        total_files_found,
        &temp_catalogue,
        &local_file_headers_count);
    if (CL_EMAXFILES == ret) {
        limit_crossed = true;
    } else if (CL_SUCCESS != ret) {
        /* Preserve fallback failures such as timeout and allocation errors. */
        status = ret;
        goto done;
    }

    total_files_found = *num_records + local_file_headers_count;

    /*
     * Search for zip records between the zip records already in the catalogue
     */
    for (i = 0; !limit_crossed && i < *num_records; i++) {
        size_t current_record_end;

        curr_record = &((*catalogue)[i]);
        if (!zip_record_end_checked(curr_record, &current_record_end) || current_record_end > fsize) {
            cli_dbgmsg("index_local_file_headers: catalogue record exceeds the mapped file\n");
            status = CL_EFORMAT;
            goto done;
        }
        start_offset = current_record_end;
        if (i + 1 == *num_records) {
            end_offset = fsize;
        } else {
            next_record = &((*catalogue)[i + 1]);
            end_offset  = next_record->local_header_offset;
        }

        ret = index_local_file_headers_within_bounds(
            ctx,
            map,
            fsize,
            start_offset,
            end_offset,
            total_files_found,
            &temp_catalogue,
            &local_file_headers_count);
        if (CL_EMAXFILES == ret) {
            limit_crossed = true;
        } else if (CL_SUCCESS != ret) {
            status = ret;
            goto done;
        }

        total_files_found = *num_records + local_file_headers_count;

        if (cli_checktimelimit(ctx) != CL_SUCCESS) {
            cli_dbgmsg("cli_unzip: Time limit reached (max: %u)\n", ctx->engine->maxscantime);
            status = CL_ETIMEOUT;
            goto done;
        }
    }

    /*
     * Combine the zip records already in the catalogue with the recently found zip records
     * Only do this if new zip records were found
     */
    if (local_file_headers_count > 0) {
        CLI_MAX_CALLOC_OR_GOTO_DONE(
            combined_catalogue,
            total_files_found,
            sizeof(struct zip_record),
            status = CL_EMEM);

        // *num_records is the number of already found files
        // local_file_headers_count is the number of new files found
        // total_files_found is the sum of both of the above
        size_t temp_catalogue_offset = 0;
        size_t catalogue_offset      = 0;

        for (i = 0; i < total_files_found; i++) {
            // Conditions in which we add from temp_catalogue: it is the only one left OR
            if (catalogue_offset >= *num_records ||
                (temp_catalogue_offset < local_file_headers_count &&
                 temp_catalogue[temp_catalogue_offset].local_header_offset < (*catalogue)[catalogue_offset].local_header_offset)) {
                // add entry from temp_catalogue into the list
                combined_catalogue[i] = temp_catalogue[temp_catalogue_offset];
                temp_catalogue_offset++;
            } else {
                // add entry from the catalogue into the list
                combined_catalogue[i] = (*catalogue)[catalogue_offset];
                catalogue_offset++;
            }

            /*
             * Detect overlapping files.
             */
            if (i > 0) {
                prev_record = &(combined_catalogue[i - 1]);
                curr_record = &(combined_catalogue[i]);

                size_t prev_record_end;
                size_t curr_record_end;

                /* Check for integer overflow in native catalogue coordinates. */
                if (!zip_record_end_checked(prev_record, &prev_record_end) ||
                    !zip_record_end_checked(curr_record, &curr_record_end)) {
                    cli_dbgmsg("cli_unzip: Integer overflow detected; invalid data sizes in zip file headers.\n");
                    status = CL_EFORMAT;
                    goto done;
                }

                if ((curr_record->local_header_offset >= prev_record->local_header_offset &&
                     prev_record_end >= ZIP_RECORD_OVERLAP_FUDGE_FACTOR &&
                     curr_record->local_header_offset < prev_record_end - ZIP_RECORD_OVERLAP_FUDGE_FACTOR) ||
                    (prev_record->local_header_offset >= curr_record->local_header_offset &&
                     curr_record_end >= ZIP_RECORD_OVERLAP_FUDGE_FACTOR &&
                     prev_record->local_header_offset < curr_record_end - ZIP_RECORD_OVERLAP_FUDGE_FACTOR)) {
                    /* Overlapping file detected */
                    num_overlapping_files++;

                    if ((curr_record->local_header_offset == prev_record->local_header_offset) &&
                        (curr_record->local_header_size == prev_record->local_header_size) &&
                        (curr_record->compressed_size == prev_record->compressed_size)) {
                        cli_dbgmsg("cli_unzip: Ignoring duplicate file entry at offset: 0x%zx.\n", curr_record->local_header_offset);
                    } else {
                        cli_dbgmsg("cli_unzip: Overlapping files detected.\n");
                        cli_dbgmsg("    previous file end:  %zu\n", prev_record_end);
                        cli_dbgmsg("    current file start: %zu\n", curr_record->local_header_offset);

                        if (ZIP_MAX_NUM_OVERLAPPING_FILES < num_overlapping_files) {
                            status = CL_EFORMAT;
                            if (SCAN_HEURISTICS) {
                                ret = cli_append_potentially_unwanted(ctx, "Heuristics.Zip.OverlappingFiles");
                                if (CL_SUCCESS != ret) {
                                    status = ret;
                                }
                            }
                            goto done;
                        }
                    }
                }
            }

            if (cli_checktimelimit(ctx) != CL_SUCCESS) {
                cli_dbgmsg("cli_unzip: Time limit reached (max: %u)\n", ctx->engine->maxscantime);
                status = CL_ETIMEOUT;
                goto done;
            }
        }

        free(temp_catalogue);
        temp_catalogue = NULL;

        free(*catalogue);
        *catalogue         = combined_catalogue;
        combined_catalogue = NULL;

        *num_records = total_files_found;
    } else {
        free(temp_catalogue);
        temp_catalogue = NULL;
    }

    if (limit_crossed) {
        /* The bounded search retained only the inclusive permitted prefix.
         * Return it to cli_unzip() so those members can still be scanned before
         * the configured-limit result is restored. */
        keep_catalogue_on_limit = true;
        status                  = CL_EMAXFILES;
    } else {
        status = CL_SUCCESS;
    }

done:
    if (CL_SUCCESS != status && !keep_catalogue_on_limit) {
        if (NULL != *catalogue) {
            size_t i;
            for (i = 0; i < *num_records; i++) {
                if (NULL != (*catalogue)[i].original_filename) {
                    free((*catalogue)[i].original_filename);
                    (*catalogue)[i].original_filename = NULL;
                }
            }
            free(*catalogue);
            *catalogue = NULL;
        }
    }

    if (NULL != temp_catalogue) {
        size_t i;
        for (i = 0; i < local_file_headers_count; i++) {
            if (NULL != temp_catalogue[i].original_filename) {
                free(temp_catalogue[i].original_filename);
                temp_catalogue[i].original_filename = NULL;
            }
        }
        free(temp_catalogue);
        temp_catalogue = NULL;
    }

    if (NULL != combined_catalogue) {
        /* Until the successful ownership hand-off above, these are shallow
         * copies whose filename pointers remain owned by the source arrays. */
        free(combined_catalogue);
        combined_catalogue = NULL;
    }

    return status;
}

/**
 * @brief Find the central directory header in a zip file.
 *
 * Find the central directory header, first by finding the End Of Central Directory header.
 *
 * The End Of Central Directory header is located at the end of the zip file and contains the offset of the central
 * directory and ends with a variable length comment.
 * We'll start searching for the magic bytes SIZEOF_END_OF_CENTRAL bytes from the end of the file, and work our way
 * backwards until we find the End Of Central Directory header magic bytes.
 *
 * @param map          The file map
 * @param fsize        The file size
 * @param[out] coff    The central directory offset
 * @return cl_error_t CL_SUCCESS if found, CL_EPARSE if absent or malformed,
 *                    CL_ETIMEOUT on deadline expiry, or CL_BREAK when the
 *                    application requested scan cancellation.
 */
static cl_error_t find_central_directory_header(
    cli_ctx *ctx,
    fmap_t *map,
    size_t fsize,
    size_t *coff)
{
    cl_error_t status = CL_ERROR;
    size_t eocoff     = 0;
    size_t min_eocoff;
    size_t probes = 0;

    cli_dbgmsg("find_central_directory_header: Searching for End Of Central Directory header...\n");

    /*
     * Find the End Of Central Directory header.
     */
    if (fsize < SIZEOF_END_OF_CENTRAL)
        return CL_EPARSE;

    min_eocoff = fsize > ZIP_EOCD_MAX_SEARCH_SIZE ? fsize - ZIP_EOCD_MAX_SEARCH_SIZE : 0;
    for (eocoff = fsize - SIZEOF_END_OF_CENTRAL;; eocoff--) {
        if ((probes++ & 0x3ff) == 0) {
            if (ctx && cli_checktimelimit(ctx) != CL_SUCCESS) {
                cli_dbgmsg("find_central_directory_header: Time limit reached while searching for EOCD\n");
                return CL_ETIMEOUT;
            }
            if (ctx && ctx->abort_scan)
                return ctx->scan_timed_out ? CL_ETIMEOUT : CL_BREAK;
        }

        const char *eocptr = fmap_need_off_once(
            map,
            eocoff,
            SIZEOF_END_OF_CENTRAL - 2 /* -2 because don't need to read the comment length */);
        if (!eocptr) {
            // Failed to get a pointer within the file at that offset and size.
            continue;
        }

        if (cli_readint32(eocptr) == ZIP_MAGIC_CENTRAL_DIRECTORY_RECORD_END) {
            // Found the End Of Central Directory header.
            // Use it to find the central directory offset.
            cli_dbgmsg("find_central_directory_header: Found End Of Central Directory header at offset: 0x%zx. "
                       "Searching for Central Directory header...\n",
                       eocoff);

            // The offset for the Central Directory header is stored at offset 16 in the End Of Central Directory header.
            uint32_t classic_entries = cli_readint16(&eocptr[10]);
            uint32_t classic_coff    = cli_readint32(&eocptr[16]);
            uint32_t classic_cdsize  = cli_readint32(&eocptr[12]);
            uint64_t cd_offset       = classic_coff;
            uint64_t cd_size         = classic_cdsize;

            /* A ZIP64 archive stores the real central-directory placement in
             * the ZIP64 EOCD record referenced by the locator immediately
             * before the classic EOCD. */
            if (classic_entries == UINT16_MAX || classic_coff == UINT32_MAX || classic_cdsize == UINT32_MAX) {
                const char *locator;
                const char *zip64_eocd;
                uint64_t zip64_offset;

                if (eocoff < ZIP64_LOCATOR_SIZE)
                    goto next_eocd;

                locator = fmap_need_off_once(map, eocoff - ZIP64_LOCATOR_SIZE, ZIP64_LOCATOR_SIZE);
                if (!locator || cli_readint32(locator) != ZIP_MAGIC_ZIP64_LOCATOR)
                    goto next_eocd;

                zip64_offset = cli_readint64(locator + 8);
                if (fsize < ZIP64_END_RECORD_SIZE || zip64_offset > SIZE_MAX || zip64_offset > fsize - ZIP64_END_RECORD_SIZE)
                    goto next_eocd;

                zip64_eocd = fmap_need_off_once(map, (size_t)zip64_offset, ZIP64_END_RECORD_SIZE);
                if (!zip64_eocd || cli_readint32(zip64_eocd) != ZIP_MAGIC_ZIP64_END)
                    goto next_eocd;

                cd_size   = cli_readint64(zip64_eocd + 40);
                cd_offset = cli_readint64(zip64_eocd + 48);
            }

            if (cd_offset > SIZE_MAX || cd_size > SIZE_MAX - (size_t)cd_offset)
                goto next_eocd;

            if (!CLI_ISCONTAINED_0_TO(fsize, (size_t)cd_offset, (size_t)cd_size))
                goto next_eocd;

            {
                size_t maybe_coff = (size_t)cd_offset;

                if (!CLI_ISCONTAINED_0_TO(fsize, maybe_coff, SIZEOF_CENTRAL_HEADER))
                    goto next_eocd;

                /* Found it. */
                cli_dbgmsg("find_central_directory_header: Found Central Directory header at offset: 0x%zx\n", maybe_coff);
                *coff  = maybe_coff;
                status = CL_SUCCESS;
                break;
            }
        }

    next_eocd:
        if (eocoff == min_eocoff)
            break;
    }

    if (CL_SUCCESS != status) {
        cli_dbgmsg("find_central_directory_header: Central directory header not found.\n");
        status = CL_EPARSE;
    }

    return status;
}

cl_error_t cli_unzip(cli_ctx *ctx)
{
    cl_error_t status = CL_ERROR;
    cl_error_t ret;

    size_t num_files_unzipped = 0;
    size_t fsize;
    size_t coff = 0;

    fmap_t *map = ctx->fmap;

    char *tmpd = NULL;

    int toval                        = 0;
    struct zip_record *zip_catalogue = NULL;
    size_t records_count             = 0;
    size_t i;
    bool scan_incomplete_before_index = false;
    bool deferred_index_incomplete    = false;
    cl_error_t deferred_index_result  = CL_SUCCESS;

    cli_dbgmsg("in cli_unzip\n");
    fsize = map->len;
    if (fsize < SIZEOF_CENTRAL_HEADER) {
        cli_dbgmsg("cli_unzip: file too short\n");
        cli_mark_scan_incomplete(ctx, "ZIP archive ended before a complete central header");
        status = CL_EPARSE;
        goto done;
    }

    /*
     * Find the central directory header
     */
    ret = find_central_directory_header(
        ctx,
        map,
        fsize,
        &coff);
    if (CL_SUCCESS == ret) {
        cli_dbgmsg("cli_unzip: central directory header offset: 0x%zx\n", coff);

        /*
         * Index the central directory.
         */
        scan_incomplete_before_index = ctx->scan_incomplete;
        ret                          = index_the_central_directory(
            ctx,
            coff,
            &zip_catalogue,
            &records_count);
        if (CL_SUCCESS != ret) {
            if (CL_EMAXFILES == ret && NULL != zip_catalogue) {
                /* The indexer retained the inclusive permitted prefix.  Scan
                 * it before restoring the limit as the archive result. */
                deferred_index_result = CL_EMAXFILES;
                if (!scan_incomplete_before_index && ctx->scan_incomplete) {
                    deferred_index_incomplete = true;
                    ctx->scan_incomplete      = false;
                }
                status = CL_SUCCESS;
                goto scan_catalogue;
            }

            /* Fall back only when the catalogue itself is malformed.  A
             * detection, callback decision, deadline, limit, or critical
             * resource failure is authoritative and must not be replayed by
             * local-header discovery. */
            if (ret != CL_EPARSE && ret != CL_EFORMAT) {
                status = ret;
                goto done;
            }

            if (ctx->scan_incomplete) {
                status = CL_EPARSE;
                goto done;
            }

            cli_dbgmsg("index_central_dir_failed, must rely purely on local file headers\n");

            CLI_CALLOC_OR_GOTO_DONE(
                zip_catalogue,
                1,
                sizeof(struct zip_record) * ZIP_RECORDS_CHECK_BLOCKSIZE,
                status = CL_EMEM);

            records_count = 0;
        }
    } else if (CL_ETIMEOUT == ret || CL_BREAK == ret) {
        status = ret;
        goto done;
    } else {
        cli_dbgmsg("cli_unzip: central directory header not found, must rely purely on local file headers\n");

        CLI_CALLOC_OR_GOTO_DONE(
            zip_catalogue,
            1,
            sizeof(struct zip_record) * ZIP_RECORDS_CHECK_BLOCKSIZE,
            status = CL_EMEM);

        records_count = 0;
    }

    /*
     * Add local file headers not referenced by the central directory.
     */
    scan_incomplete_before_index = ctx->scan_incomplete;
    ret                          = index_local_file_headers(
        ctx,
        map,
        fsize,
        &zip_catalogue,
        &records_count);

    /* A split archive segment can contain complete, independently decodable
     * members followed by a member that continues in the next segment.  The
     * incomplete marker has already made the parent non-cacheable.  Defer only
     * a marker newly raised by this indexing pass so the complete records can
     * still reach their scan callbacks.  Pre-existing incomplete state is
     * never cleared. */
    if (!scan_incomplete_before_index && ctx->scan_incomplete) {
        deferred_index_incomplete = true;
        ctx->scan_incomplete      = false;
        deferred_index_result     = (CL_EMAXFILES == ret) ? CL_EMAXFILES : CL_EPARSE;
    }

    if (CL_EMAXFILES == ret && NULL != zip_catalogue) {
        deferred_index_result = CL_EMAXFILES;
    } else if (CL_SUCCESS != ret) {
        cli_dbgmsg("index_local_file_headers_failed\n");
        status = ret;
        goto done;
    }

scan_catalogue:
    status = CL_SUCCESS;
    if (ctx->abort_scan) {
        /* An indexing-time alert callback may have requested cancellation.
         * Do not start member extraction after that decision. */
        status = ctx->scan_timed_out ? CL_ETIMEOUT : CL_BREAK;
        goto done;
    }

    /*
     * Then decrypt/unzip & scan each unique file entry.
     */
    for (i = 0; i < records_count; i++) {
        const uint8_t *local_header = NULL;
        size_t data_offset;

        if ((i > 0) &&
            (zip_catalogue[i].local_header_offset == zip_catalogue[i - 1].local_header_offset) &&
            (zip_catalogue[i].local_header_size == zip_catalogue[i - 1].local_header_size) &&
            (zip_catalogue[i].compressed_size == zip_catalogue[i - 1].compressed_size)) {

            /* Duplicate file entry, skip. */
            cli_dbgmsg("cli_unzip: Skipping unzipping of duplicate file entry at offset: 0x%zx\n", zip_catalogue[i].local_header_offset);
            continue;
        }

        if (zip_catalogue[i].compressed_size == 0 && zip_catalogue[i].uncompressed_size == 0) {
            continue;
        }
        if (zip_catalogue[i].compressed_size == 0) {
            cli_mark_scan_incomplete(ctx, "ZIP member reports output but has no compressed data");
            status = CL_EPARSE;
            goto done;
        }

        if (zip_catalogue[i].local_header_size > SIZE_MAX - zip_catalogue[i].local_header_offset) {
            cli_mark_scan_incomplete(ctx, "ZIP member data offset overflowed");
            status = CL_EPARSE;
            goto done;
        }
        data_offset = zip_catalogue[i].local_header_offset + zip_catalogue[i].local_header_size;

        if (zip_catalogue[i].encrypted) {
            /* ZipCrypto still consumes local-header fields through macros.
             * Keep this small view locked while bounded streaming may age
             * other fmap pages, then release it immediately. */
            local_header = fmap_need_off(map, zip_catalogue[i].local_header_offset, SIZEOF_LOCAL_HEADER);
            if (NULL == local_header) {
                cli_mark_scan_incomplete(ctx, "ZIP local header could not be mapped for decryption");
                status = CL_EPARSE;
                goto done;
            }

            status = zdecrypt_from_fmap(
                map,
                data_offset,
                zip_catalogue[i].compressed_size,
                zip_catalogue[i].uncompressed_size,
                zip_catalogue[i].crc32,
                local_header,
                &num_files_unzipped,
                ctx,
                tmpd,
                zip_scan_cb,
                zip_catalogue[i].original_filename);
            fmap_unneed_off(map, zip_catalogue[i].local_header_offset, SIZEOF_LOCAL_HEADER);
            local_header = NULL;
        } else {
            status = unz_from_fmap(
                map,
                data_offset,
                zip_catalogue[i].compressed_size,
                zip_catalogue[i].uncompressed_size,
                zip_catalogue[i].method,
                zip_catalogue[i].flags,
                zip_catalogue[i].crc32,
                &num_files_unzipped,
                ctx,
                tmpd,
                zip_scan_cb,
                zip_catalogue[i].original_filename,
                false);
        }

        if (status == CL_VERIFIED) {
            /* A child layer trusted by its own callback is clean for this
             * member only; it must not trust or stop the containing ZIP. */
            status = CL_SUCCESS;
        } else if (status != CL_SUCCESS && status != CL_VIRUS) {
            /* Do not replace terminal application, resource, I/O, timeout, or
             * configured-limit results with a generic parse error. */
            switch (status) {
                case CL_BREAK:
                case CL_EUNLINK:
                case CL_ESTAT:
                case CL_ESEEK:
                case CL_EWRITE:
                case CL_EDUP:
                case CL_ETMPFILE:
                case CL_ETMPDIR:
                case CL_EMEM:
                case CL_ETIMEOUT:
                case CL_EMAXREC:
                case CL_EMAXSIZE:
                case CL_EMAXFILES:
                    goto done;
                case CL_EUNPACK:
                case CL_EREAD:
                case CL_EFORMAT:
                case CL_EPARSE:
                    break;
                default:
                    cli_mark_scan_incomplete(ctx, "ZIP member scanning returned an operational error");
                    goto done;
            }

            if (!ctx->abort_scan) {
                cli_mark_scan_incomplete(ctx, "ZIP member extraction or scanning failed");
                status = CL_EPARSE;
                goto done;
            }
        }

        if (cli_checktimelimit(ctx) != CL_SUCCESS) {
            cli_dbgmsg("cli_unzip: Time limit reached (max: %u)\n", ctx->engine->maxscantime);
            status = CL_ETIMEOUT;
            goto done;
        }

        if (cli_json_timeout_cycle_check(ctx, &toval) != CL_SUCCESS) {
            status = CL_ETIMEOUT;
            goto done;
        }

        if (ctx->abort_scan) {
            // The scan was aborted, stop processing files.
            // This also takes into account CL_VIRUS status (to abort on detection when not in allmatch mode).
            break;
        }

        // Continue to the next file entry even if the current one failed.
    }

done:

    if (deferred_index_incomplete) {
        /* Restore fail-visible state after scanning the valid prefix.  In
         * all-match mode a detection is carried by evidence and remains the
         * public verdict even though the underlying scan was incomplete. */
        ctx->scan_incomplete = true;
    }
    if (CL_SUCCESS == status && CL_SUCCESS != deferred_index_result)
        status = deferred_index_result;

    if (NULL != zip_catalogue) {
        /* Clean up zip record resources */
        for (i = 0; i < records_count; i++) {
            if (NULL != zip_catalogue[i].original_filename) {
                free(zip_catalogue[i].original_filename);
                zip_catalogue[i].original_filename = NULL;
            }
        }
        free(zip_catalogue);
        zip_catalogue = NULL;
    }

    if (NULL != tmpd) {
        if (!ctx->engine->keeptmp && cli_rmdirs(tmpd) != 0) {
            cli_mark_scan_incomplete(ctx, "ZIP temporary directory could not be removed");
            if (status == CL_SUCCESS || status == CL_CLEAN || status == CL_VERIFIED || status == CL_BREAK)
                status = CL_EUNLINK;
        }
        free(tmpd);
    }

    return status;
}

cl_error_t unzip_single_internal(cli_ctx *ctx, size_t local_header_offset, zip_cb zcb)
{
    cl_error_t ret = CL_SUCCESS;

    size_t num_files_unzipped = 0;

    cli_dbgmsg("in cli_unzip_single\n");

    if (NULL == ctx || NULL == ctx->fmap) {
        cli_dbgmsg("cli_unzip_single: Invalid NULL arguments\n");
        return CL_ENULLARG;
    }

    if (local_header_offset > ctx->fmap->len ||
        SIZEOF_LOCAL_HEADER > ctx->fmap->len - local_header_offset) {
        cli_dbgmsg("cli_unzip: file too short\n");
        cli_mark_scan_incomplete(ctx, "ZIP local header was truncated");
        return CL_EPARSE;
    }

    ret = parse_local_file_header(
        ctx,
        local_header_offset,
        &num_files_unzipped,
        0,    /* file_count */
        NULL, /* central_header*/
        NULL, /* tmpd */
        0,    /* detect_encrypted */
        zcb,
        NULL,  /* central_values */
        NULL,  /* record */
        NULL); /* file_record_size */

    return ret;
}

cl_error_t cli_unzip_single(cli_ctx *ctx, size_t local_header_offset)
{
    return unzip_single_internal(ctx, local_header_offset, zip_scan_cb);
}

cl_error_t unzip_search_add(struct zip_requests *requests, const char *name, size_t nlen)
{
    cli_dbgmsg("in unzip_search_add\n");

    if (requests->namecnt >= MAX_ZIP_REQUESTS) {
        cli_dbgmsg("DEBUGGING MESSAGE GOES HERE!\n");
        return CL_BREAK;
    }

    cli_dbgmsg("unzip_search_add: adding %s (len %llu)\n", name, (long long unsigned)nlen);

    requests->names[requests->namecnt]    = name;
    requests->namelens[requests->namecnt] = nlen;
    requests->namecnt++;

    return CL_SUCCESS;
}

cl_error_t unzip_search(cli_ctx *ctx, struct zip_requests *requests)
{
    cl_error_t status = CL_ERROR;
    cl_error_t ret;
    size_t file_count = 0;
    size_t coff       = 0;
    uint32_t toval    = 0;

    size_t file_record_size = 0;

    cli_dbgmsg("in unzip_search\n");

    if (NULL == ctx || NULL == ctx->fmap) {
        return CL_ENULLARG;
    }

    if (ctx->fmap->len < SIZEOF_CENTRAL_HEADER) {
        cli_dbgmsg("unzip_search: file too short\n");
        cli_mark_scan_incomplete(ctx, "ZIP archive ended before a complete central header");
        status = CL_EPARSE;
        goto done;
    }

    /*
     * Find the central directory header
     */
    ret = find_central_directory_header(
        ctx,
        ctx->fmap,
        ctx->fmap->len,
        &coff);
    if (CL_SUCCESS == ret) {
        size_t central_file_header_offset = coff;
        cli_dbgmsg("unzip_search: central directory header offset: 0x%zx\n", central_file_header_offset);
        do {
            ret = parse_central_directory_file_header(
                ctx,
                central_file_header_offset,
                NULL, /* num_files_unzipped */
                file_count + 1,
                NULL, /* tmpd */
                requests,
                NULL, /* record */
                &file_record_size);

            if (CL_SUCCESS != ret) {
                status = ret;
                goto done;
            }

            if (0 == file_record_size) {
                status = CL_SUCCESS;
                break;
            }

            if (ctx->scan_incomplete) {
                status = CL_EPARSE;
                goto done;
            }

            if (requests->match) {
                // Found a match.
                status = CL_VIRUS;
                goto done;
            }

            /* MaxFiles is inclusive.  Parsing this record proves there is one
             * more entry only when the permitted count was already full. */
            if (ctx->engine->maxfiles && file_count >= ctx->engine->maxfiles) {
                // Note: this check piggybacks on the MaxFiles setting, but is not actually
                //   scanning these files or incrementing the ctx->scannedfiles count
                cli_dbgmsg("cli_unzip: Files limit reached (max: %u)\n", ctx->engine->maxfiles);
                cli_append_potentially_unwanted_if_heur_exceedsmax(ctx, "Heuristics.Limits.Exceeded.MaxFiles", CL_EMAXFILES);
                if (ctx->abort_scan) {
                    status = ctx->scan_timed_out ? CL_ETIMEOUT : CL_BREAK;
                    goto done;
                }
                status = CL_EMAXFILES;
                goto done;
            }
            file_count++;

            if (ctx && cli_json_timeout_cycle_check(ctx, (int *)(&toval)) != CL_SUCCESS) {
                status = CL_ETIMEOUT;
                goto done;
            }

            // Increment to the next central file header.
            if (central_file_header_offset > ctx->fmap->len ||
                file_record_size > ctx->fmap->len - central_file_header_offset) {
                cli_dbgmsg("unzip_search: central directory record exceeds the mapped file\n");
                status = CL_EPARSE;
                goto done;
            }
            central_file_header_offset += file_record_size;
        } while (1);
    } else if (CL_ETIMEOUT == ret || CL_BREAK == ret) {
        status = ret;
        goto done;
    } else {
        cli_dbgmsg("unzip_search: Cannot locate central directory. unzip_search failed.\n");
        status = CL_EPARSE;
        goto done;
    }

done:
    return status;
}

cl_error_t unzip_search_single(cli_ctx *ctx, const char *name, size_t nlen, size_t *loff)
{
    cl_error_t status            = CL_ERROR;
    struct zip_requests requests = {0};

    cli_dbgmsg("in unzip_search_single\n");
    if (!ctx) {
        status = CL_ENULLARG;
        goto done;
    }

    // Add the file name to the requests.
    status = unzip_search_add(&requests, name, nlen);
    if (CL_SUCCESS != status) {
        cli_dbgmsg("unzip_search_single: Failed to add file name to requests\n");
        goto done;
    }

    // Search for the zip file entry in the current layer.
    status = unzip_search(ctx, &requests);
    if (CL_VIRUS == status) {
        *loff = requests.loff;
    }

done:
    return status;
}
