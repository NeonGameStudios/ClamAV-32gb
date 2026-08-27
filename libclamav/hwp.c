/*
 * HWP Stuff
 *
 * Copyright (C) 2015-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 * Authors: Kevin Lin
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License version 2 as published by the
 * Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <zlib.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#if HAVE_ICONV
#include <iconv.h>
#endif

#include "clamav.h"
#include "fmap.h"
#include "str.h"
#include "conv.h"
#include "others.h"
#include "scanners.h"
#include "msxml_parser.h"
#include "json_api.h"
#include "hwp.h"
#include "msdoc.h"

#define HWP5_DEBUG 0
#define HWP3_DEBUG 0
#define HWP3_VERIFY 0
#define HWPML_DEBUG 0
#if HWP5_DEBUG
#define hwp5_debug(...) cli_dbgmsg(__VA_ARGS__)
#else
#define hwp5_debug(...) {};
#endif
#if HWP3_DEBUG
#define hwp3_debug(...) cli_dbgmsg(__VA_ARGS__)
#else
#define hwp3_debug(...) {};
#endif
#if HWPML_DEBUG
#define hwpml_debug(...) cli_dbgmsg(__VA_ARGS__)
#else
#define hwpml_debug(...) {};
#endif

typedef cl_error_t (*hwp_cb)(void *cbdata, int fd, const char *filepath, cli_ctx *ctx, uint64_t temporary_reserved);

static cl_error_t decompress_and_callback(cli_ctx *ctx, fmap_t *input, size_t at, size_t len, const char *parent, hwp_cb cb, void *cbdata)
{
    cl_error_t ret = CL_SUCCESS;
    int zret, ofd;
    size_t in;
    size_t off_in = at;
    size_t count, remain = 1, outsize = 0;
    uint64_t temporary_reserved = 0;
    z_stream zstrm;
    char *tmpname;
    unsigned char inbuf[FILEBUFF], outbuf[FILEBUFF];

    if (!ctx || !input || !cb)
        return CL_ENULLARG;

    if (len)
        remain = len;

    /* reserve tempfile for output and callback */
    if ((ret = cli_gentempfd(ctx->this_layer_tmpdir, &tmpname, &ofd)) != CL_SUCCESS) {
        cli_errmsg("%s: Can't generate temporary file\n", parent);
        cli_mark_scan_incomplete(ctx, "HWP decompression temporary output could not be created");
        return ret;
    }

    /* initialize zlib inflation stream */
    memset(&zstrm, 0, sizeof(zstrm));
    zstrm.zalloc    = Z_NULL;
    zstrm.zfree     = Z_NULL;
    zstrm.opaque    = Z_NULL;
    zstrm.next_in   = inbuf;
    zstrm.next_out  = outbuf;
    zstrm.avail_in  = 0;
    zstrm.avail_out = FILEBUFF;

    zret = inflateInit2(&zstrm, -15);
    if (zret != Z_OK) {
        cli_errmsg("%s: Can't initialize zlib inflation stream\n", parent);
        ret = CL_EUNPACK;
        goto dc_end;
    }

    /* inflation loop */
    do {
        if (zstrm.avail_in == 0) {
            size_t requested = FILEBUFF;
            bool request_in_range;

            zstrm.next_in = inbuf;

            /* Do not read past a declared compressed stream into the next
             * OLE2 stream. A request that is fully contained in the fmap can
             * still fail at the backing callback, which must remain distinct
             * from truncation. */
            if (len && remain < requested)
                requested = remain;
            request_in_range = off_in <= input->len && requested <= input->len - off_in;
            if (!request_in_range) {
                if (off_in > input->len)
                    break;
                requested = input->len - off_in;
            }
            if (!requested)
                break;

            in = fmap_readn(input, inbuf, off_in, requested);
            if (in == (size_t)-1) {
                cli_errmsg("%s: Error reading stream\n", parent);
                cli_mark_scan_incomplete(ctx, request_in_range
                                                    ? "HWP compressed input could not be read completely"
                                                    : "HWP compressed input is truncated");
                ret = request_in_range ? CL_EREAD : CL_EPARSE;
                goto dc_end;
            }
            if (!in)
                break;

            if (len)
                remain -= in;
            zstrm.avail_in = in;
            off_in += in;
        }
        zret  = inflate(&zstrm, Z_SYNC_FLUSH);
        count = FILEBUFF - zstrm.avail_out;
        if (count) {
            ret = cli_checktimelimit(ctx);
            if (ret != CL_SUCCESS) {
                cli_mark_scan_incomplete(ctx, "HWP decompressed output reached the configured time limit");
                goto dc_end;
            }
            if (outsize > SIZE_MAX - count) {
                cli_mark_scan_incomplete(ctx, "HWP decompressed output size overflowed");
                ret = CL_ERESOURCE;
                goto dc_end;
            }
            if ((ret = cli_checklimits("HWP", ctx, outsize + count, 0, 0)) != CL_SUCCESS)
                break;

            if (UINT64_MAX - temporary_reserved < (uint64_t)count ||
                cli_scan_reserve_temporary(ctx, (uint64_t)count) != CL_SUCCESS) {
                cli_mark_scan_incomplete(ctx, "HWP decompressed output exceeds temporary storage limits");
                ret = CL_ERESOURCE;
                goto dc_end;
            }
            temporary_reserved += (uint64_t)count;
            ret = cli_checktimelimit(ctx);
            if (ret != CL_SUCCESS) {
                cli_scan_release_temporary(ctx, (uint64_t)count);
                temporary_reserved -= (uint64_t)count;
                cli_mark_scan_incomplete(ctx, "HWP decompressed output reached the configured time limit");
                goto dc_end;
            }
            if (cli_writen(ofd, outbuf, count) != count) {
                cli_errmsg("%s: Can't write to file %s\n", parent, tmpname);
                cli_mark_scan_incomplete(ctx, "HWP decompressed temporary output could not be written completely");
                ret = CL_EWRITE;
                goto dc_end;
            }
            outsize += count;
        }
        zstrm.next_out  = outbuf;
        zstrm.avail_out = FILEBUFF;
    } while (zret == Z_OK && remain);

    cli_dbgmsg("%s: Decompressed %zu bytes to %s\n", parent, outsize, tmpname);

    /* A raw-deflate stream is not complete until zlib reports its terminal
     * state. Never scan a partial prefix as though it were the complete
     * HWP/HWPML payload. */
    if (zret != Z_STREAM_END) {
        cli_infomsg(ctx, "%s: Error decompressing stream before the decoder reached Z_STREAM_END\n", parent);
        cli_mark_scan_incomplete(ctx, "HWP compressed content was not completely decompressed");
        if (ret == CL_SUCCESS)
            ret = CL_EUNPACK;
        goto dc_end;
    }

    if (ret == CL_SUCCESS)
        ret = cb(cbdata, ofd, tmpname, ctx, temporary_reserved);

    /* clean-up */
dc_end:
    zret = inflateEnd(&zstrm);
    if (zret != Z_OK) {
        cli_errmsg("%s: Error closing zlib inflation stream\n", parent);
        if (ret == CL_SUCCESS)
            ret = CL_EUNPACK;
    }
    if (close(ofd) != 0) {
        cli_mark_scan_incomplete(ctx, "HWP decompressed temporary output could not be closed");
        if (ret == CL_SUCCESS || ret == CL_VERIFIED)
            ret = CL_EWRITE;
    }
    if (!ctx->engine->keeptmp) {
        if (cli_unlink(tmpname)) {
            cli_mark_scan_incomplete(ctx, "HWP decompressed temporary output could not be removed");
            if (ret == CL_SUCCESS || ret == CL_VERIFIED)
                ret = CL_EUNLINK;
        }
    }
    free(tmpname);
    if (temporary_reserved)
        cli_scan_release_temporary(ctx, temporary_reserved);
    return ret;
}

/* convert HANGUL_NUMERICAL to UTF-8 encoding using iconv library, converts to base64 encoding if no iconv or failure */
#define HANGUL_NUMERICAL 0
static char *convert_hstr_to_utf8(const char *begin, size_t sz, const char *parent, cl_error_t *ret)
{
    cl_error_t rc = CL_SUCCESS;
    char *res     = NULL;
#if HANGUL_NUMERICAL && HAVE_ICONV
    char *p1, *p2, *inbuf = NULL, *outbuf = NULL;
    size_t inlen, outlen;
    iconv_t cd;

    do {
        p1 = inbuf = cli_max_calloc(1, sz + 1);
        if (!inbuf) {
            cli_errmsg("%s: Failed to allocate memory for encoding conversion buffer\n", parent);
            rc = CL_EMEM;
            break;
        }
        memcpy(inbuf, begin, sz);
        p2 = outbuf = cli_max_calloc(1, sz + 1);
        if (!outbuf) {
            cli_errmsg("%s: Failed to allocate memory for encoding conversion buffer\n", parent);
            rc = CL_EMEM;
            break;
        }
        inlen = outlen = sz;

        cd = iconv_open("UTF-8", "UNICODE");
        if (cd == (iconv_t)(-1)) {
            char errbuf[128];
            cli_strerror(errno, errbuf, sizeof(errbuf));
            cli_errmsg("%s: Failed to initialize iconv for encoding %s: %s\n", parent, HANGUL_NUMERICAL, errbuf);
            break;
        }

        iconv(cd, (char **)(&p1), &inlen, &p2, &outlen);
        iconv_close(cd);

        /* no data was converted */
        if (outlen == sz)
            break;

        outbuf[sz - outlen] = '\0';

        if (!(res = strdup(outbuf))) {
            cli_errmsg("%s: Failed to allocate memory for encoding conversion buffer\n", parent);
            rc = CL_EMEM;
            break;
        }
    } while (0);

    if (inbuf)
        free(inbuf);
    if (outbuf)
        free(outbuf);
#endif
    /* safety base64 encoding */
    if (!res && (rc == CL_SUCCESS)) {
        char *tmpbuf;

        tmpbuf = cli_max_calloc(1, sz + 1);
        if (tmpbuf) {
            memcpy(tmpbuf, begin, sz);

            res = (char *)cl_base64_encode(tmpbuf, sz);
            if (res)
                rc = CL_VIRUS; /* used as placeholder */
            else
                rc = CL_EMEM;

            free(tmpbuf);
        } else {
            cli_errmsg("%s: Failed to allocate memory for temporary buffer\n", parent);
            rc = CL_EMEM;
        }
    }

    (*ret) = rc;
    return res;
}

/*** HWPOLE2 ***/
cl_error_t cli_scanhwpole2(cli_ctx *ctx)
{
    fmap_t *map;
    uint32_t usize, asize;
    size_t payload_size;

    if (!ctx)
        return CL_ENULLARG;
    if (!ctx->fmap) {
        cli_mark_scan_incomplete(ctx, "HWPOLE2 input map is unavailable");
        return CL_EPARSE;
    }

    map = ctx->fmap;

    if (map->len < sizeof(usize)) {
        cli_mark_scan_incomplete(ctx, "HWPOLE2 header is truncated");
        return CL_EPARSE;
    }

    /* The wrapper's payload-size field is only 32 bits. Do not narrow a
     * native map length and then scan an unbounded, structurally incompatible
     * payload as though the prefix described it. */
    payload_size = map->len - sizeof(usize);
    if (payload_size > UINT32_MAX) {
        cli_warnmsg("HWPOLE2: payload exceeds its 32-bit size field (%zu bytes)\n", payload_size);
        cli_mark_scan_incomplete(ctx, "HWPOLE2 payload exceeds its 32-bit size field");
        return CL_EPARSE;
    }

    asize = (uint32_t)payload_size;

    {
        size_t nread = fmap_readn_full(map, &usize, 0, sizeof(usize));

        if (nread != sizeof(usize)) {
            cli_errmsg("HWPOLE2: Failed to read uncompressed ole2 filesize\n");
            cli_mark_scan_incomplete(ctx, "HWPOLE2 size prefix could not be read completely");
            return nread == (size_t)-1 ? CL_EREAD : CL_EPARSE;
        }
    }

    if (usize != asize) {
        cli_warnmsg("HWPOLE2: Mismatched uncompressed prefix and size: %u != %u\n", usize, asize);
        cli_mark_scan_incomplete(ctx, "HWPOLE2 uncompressed prefix disagreed with payload size");
        return CL_EPARSE;
    }
    cli_dbgmsg("HWPOLE2: Matched uncompressed prefix and size: %u == %u\n", usize, asize);

    return cli_magic_scan_nested_fmap_type(map, 4, 0, ctx,
                                           CL_TYPE_ANY, NULL, LAYER_ATTRIBUTES_NONE);
}

/*** HWP5 ***/

cl_error_t cli_hwp5header(cli_ctx *ctx, hwp5_header_t *hwp5)
{
    if (!ctx || !hwp5)
        return CL_ENULLARG;

    if (SCAN_COLLECT_METADATA) {
        json_object *header, *flags;

        header = cli_jsonobj(ctx->this_layer_metadata_json, "Hwp5Header");
        if (!header) {
            cli_errmsg("HWP5.x: No memory for Hwp5Header object\n");
            cli_mark_scan_incomplete(ctx, "HWP5 header metadata could not be allocated");
            return CL_EMEM;
        }

        /* version */
        cli_jsonint(header, "RawVersion", hwp5->version);

        /* flags */
        cli_jsonint(header, "RawFlags", hwp5->flags);

        flags = cli_jsonarray(header, "Flags");
        if (!flags) {
            cli_errmsg("HWP5.x: No memory for Hwp5Header/Flags array\n");
            cli_mark_scan_incomplete(ctx, "HWP5 header flags metadata could not be allocated");
            return CL_EMEM;
        }

        if (hwp5->flags & HWP5_COMPRESSED) {
            cli_jsonstr(flags, NULL, "HWP5_COMPRESSED");
        }
        if (hwp5->flags & HWP5_PASSWORD) {
            cli_jsonstr(flags, NULL, "HWP5_PASSWORD");
        }
        if (hwp5->flags & HWP5_DISTRIBUTABLE) {
            cli_jsonstr(flags, NULL, "HWP5_DISTRIBUTABLE");
        }
        if (hwp5->flags & HWP5_SCRIPT) {
            cli_jsonstr(flags, NULL, "HWP5_SCRIPT");
        }
        if (hwp5->flags & HWP5_DRM) {
            cli_jsonstr(flags, NULL, "HWP5_DRM");
        }
        if (hwp5->flags & HWP5_XMLTEMPLATE) {
            cli_jsonstr(flags, NULL, "HWP5_XMLTEMPLATE");
        }
        if (hwp5->flags & HWP5_HISTORY) {
            cli_jsonstr(flags, NULL, "HWP5_HISTORY");
        }
        if (hwp5->flags & HWP5_CERT_SIGNED) {
            cli_jsonstr(flags, NULL, "HWP5_CERT_SIGNED");
        }
        if (hwp5->flags & HWP5_CERT_ENCRYPTED) {
            cli_jsonstr(flags, NULL, "HWP5_CERT_ENCRYPTED");
        }
        if (hwp5->flags & HWP5_CERT_EXTRA) {
            cli_jsonstr(flags, NULL, "HWP5_CERT_EXTRA");
        }
        if (hwp5->flags & HWP5_CERT_DRM) {
            cli_jsonstr(flags, NULL, "HWP5_CERT_DRM");
        }
        if (hwp5->flags & HWP5_CCL) {
            cli_jsonstr(flags, NULL, "HWP5_CCL");
        }
    }

    return CL_SUCCESS;
}

static cl_error_t hwp5_cb(void *cbdata, int fd, const char *filepath, cli_ctx *ctx, uint64_t temporary_reserved)
{
    UNUSEDPARAM(cbdata);
    UNUSEDPARAM(temporary_reserved);

    if (fd < 0 || !ctx)
        return CL_ENULLARG;

    return cli_magic_scan_desc_type_reserved(fd, filepath, ctx, CL_TYPE_ANY, NULL, LAYER_ATTRIBUTES_NONE);
}

cl_error_t cli_scanhwp5_stream(cli_ctx *ctx, hwp5_header_t *hwp5, char *name, int fd, const char *filepath)
{
    hwp5_debug("HWP5.x: NAME: %s\n", name ? name : "(NULL)");

    if (fd < 0) {
        cli_errmsg("HWP5.x: Invalid file descriptor argument\n");
        return CL_ENULLARG;
    }

    if (name) {
        /* encrypted and compressed streams */
        if (!strncmp(name, "bin", 3) || !strncmp(name, "jscriptversion", 14) ||
            !strncmp(name, "defaultjscript", 14) || !strncmp(name, "section", 7) ||
            !strncmp(name, "viewtext", 8) || !strncmp(name, "docinfo", 7)) {

            if (hwp5->flags & HWP5_PASSWORD) {
                cli_dbgmsg("HWP5.x: Password encrypted stream, scanning as-is\n");
                return cli_magic_scan_desc(fd, filepath, ctx, name, LAYER_ATTRIBUTES_NONE);
            }

            if (hwp5->flags & HWP5_COMPRESSED) {
                /* DocInfo JSON Handling */
                STATBUF statbuf;
                fmap_t *input;
                cl_error_t ret;

                hwp5_debug("HWP5.x: Sending %s for decompress and scan\n", name);

                /* fmap the input file for easier manipulation */
                if (FSTAT(fd, &statbuf) == -1) {
                    cli_errmsg("HWP5.x: Can't stat file descriptor\n");
                    return CL_ESTAT;
                }

                input = fmap_new(fd, 0, statbuf.st_size, NULL, filepath);
                if (!input) {
                    cli_errmsg("HWP5.x: Failed to get fmap for input stream\n");
                    return CL_EMAP;
                }
                ret = decompress_and_callback(ctx, input, 0, 0, "HWP5.x", hwp5_cb, NULL);
                fmap_free(input);
                return ret;
            }
        }

        /* JSON Output Summary Information */
        if (SCAN_COLLECT_METADATA && ctx->metadata_json != NULL) {
            if (name && !strncmp(name, "_5_hwpsummaryinformation", 24)) {
                cl_error_t summary_status;

                cli_dbgmsg("HWP5.x: Detected a '_5_hwpsummaryinformation' stream\n");
                summary_status = cli_ole2_summary_json(ctx, fd, 2, filepath);
                if (summary_status != CL_SUCCESS) {
                    cli_mark_scan_incomplete(ctx, "HWP5 summary information could not be inspected completely");
                    return summary_status;
                }
            }
        }
    }

    /* normal streams */
    return cli_magic_scan_desc(fd, filepath, ctx, name, LAYER_ATTRIBUTES_NONE);
}

/*** HWP3 ***/

/* all fields use little endian and unicode encoding, if applicable */

// File Identification Information - (30 total bytes)
#define HWP3_IDENTITY_INFO_SIZE 30

// Document Information - (128 total bytes)
#define HWP3_DOCINFO_SIZE 128

#define DI_WRITEPROT 24    /* offset 24 (4 bytes) - write protection */
#define DI_EXTERNAPP 28    /* offset 28 (2 bytes) - external application */
#define DI_PNAME 32        /* offset 32 (40 x 1 bytes) - print name */
#define DI_ANNOTE 72       /* offset 72 (24 x 1 bytes) - annotation */
#define DI_PASSWD 96       /* offset 96 (2 bytes) - password protected */
#define DI_COMPRESSED 124  /* offset 124 (1 byte) - compression */
#define DI_INFOBLKSIZE 126 /* offset 126 (2 bytes) - information block length */
struct hwp3_docinfo {
    uint32_t di_writeprot;
    uint16_t di_externapp;
    uint16_t di_passwd;
    uint8_t di_compressed;
    uint16_t di_infoblksize;
};

// Document Summary - (1008 total bytes)
#define HWP3_DOCSUMMARY_SIZE 1008

static size_t hwp3_readn(fmap_t *map, void *dst, size_t at, size_t len)
{
    /* fmap_readn() truncates a request that crosses EOF. Use the shared
     * full-range helper so only a fully in-range callback failure is CL_EREAD. */
    return fmap_readn_full(map, dst, at, len);
}

static cl_error_t hwp3_read_fixed(cli_ctx *ctx, fmap_t *map, void *dst, size_t at, size_t len,
                                  const char *reason)
{
    size_t nread = hwp3_readn(map, dst, at, len);

    if (nread == len)
        return CL_SUCCESS;

    cli_mark_scan_incomplete(ctx, reason);
    return nread == (size_t)-1 ? CL_EREAD : CL_EPARSE;
}

struct hwp3_docsummary_entry {
    size_t offset;
    const char *name;
} hwp3_docsummary_fields[] = {
    {0, "Title"},      /* offset 0 (56 x 2 bytes) - title */
    {112, "Subject"},  /* offset 112 (56 x 2 bytes) - subject */
    {224, "Author"},   /* offset 224 (56 x 2 bytes) - author */
    {336, "Date"},     /* offset 336 (56 x 2 bytes) - date */
    {448, "Keyword1"}, /* offset 448 (2 x 56 x 2 bytes) - keywords */
    {560, "Keyword2"},

    {672, "Etc0"}, /* offset 672 (3 x 56 x 2 bytes) - etc */
    {784, "Etc1"},
    {896, "Etc2"}};
#define NUM_DOCSUMMARY_FIELDS sizeof(hwp3_docsummary_fields) / sizeof(struct hwp3_docsummary_entry)

// Document Paragraph Information - (43 or 230 total bytes)
#define HWP3_PARAINFO_SIZE_S 43
#define HWP3_PARAINFO_SIZE_L 230
#define HWP3_LINEINFO_SIZE 14
#define HWP3_CHARSHPDATA_SIZE 31

#define HWP3_FIELD_LENGTH 512

#define PI_PPFS 0    /* offset 0 (1 byte)  - prior paragraph format style */
#define PI_NCHARS 1  /* offset 1 (2 bytes) - character count */
#define PI_NLINES 3  /* offset 3 (2 bytes) - line count */
#define PI_IFSC 5    /* offset 5 (1 byte)  - including font style of characters */
#define PI_FLAGS 6   /* offset 6 (1 byte)  - other flags */
#define PI_SPECIAL 7 /* offset 7 (4 bytes) - special characters markers */
#define PI_ISTYLE 11 /* offset 11 (1 byte) - paragraph style index */

#define PLI_LOFF 0  /* offset 0 (2 bytes) - line starting offset */
#define PLI_LCOR 2  /* offset 2 (2 bytes) - line blank correction */
#define PLI_LHEI 4  /* offset 4 (2 bytes) - line max char height */
#define PLI_LPAG 12 /* offset 12 (2 bytes) - line pagination*/

#define PCSD_SIZE 0  /* offset 0 (2 bytes) - size of characters */
#define PCSD_PROP 26 /* offset 26 (1 byte) - properties */

static inline cl_error_t hwp3_checktimelimit(cli_ctx *ctx, const char *reason)
{
    cl_error_t ret = cli_checktimelimit(ctx);

    if (ret != CL_SUCCESS)
        cli_mark_scan_incomplete(ctx, reason);

    return ret;
}

static inline cl_error_t parsehwp3_docinfo(cli_ctx *ctx, size_t offset, struct hwp3_docinfo *docinfo)
{
    const uint8_t *hwp3_ptr;
    cl_error_t iret;

    if (hwp3_checktimelimit(ctx, "HWP3 document-info inspection reached the configured time limit") != CL_SUCCESS)
        return CL_ETIMEOUT;

    if (offset > ctx->fmap->len || HWP3_DOCINFO_SIZE > ctx->fmap->len - offset) {
        cli_mark_scan_incomplete(ctx, "HWP3 document-info could not be read completely");
        return CL_EPARSE;
    }

    // TODO: use fmap_readn?
    if (!(hwp3_ptr = fmap_need_off_once(ctx->fmap, offset, HWP3_DOCINFO_SIZE))) {
        cli_errmsg("HWP3.x: Failed to read fmap for hwp docinfo\n");
        cli_mark_scan_incomplete(ctx, "HWP3 document-info could not be read completely");
        return CL_EREAD;
    }

    memcpy(&(docinfo->di_writeprot), hwp3_ptr + DI_WRITEPROT, sizeof(docinfo->di_writeprot));
    memcpy(&(docinfo->di_externapp), hwp3_ptr + DI_EXTERNAPP, sizeof(docinfo->di_externapp));
    memcpy(&(docinfo->di_passwd), hwp3_ptr + DI_PASSWD, sizeof(docinfo->di_passwd));
    memcpy(&(docinfo->di_compressed), hwp3_ptr + DI_COMPRESSED, sizeof(docinfo->di_compressed));
    memcpy(&(docinfo->di_infoblksize), hwp3_ptr + DI_INFOBLKSIZE, sizeof(docinfo->di_infoblksize));

    docinfo->di_writeprot   = le32_to_host(docinfo->di_writeprot);
    docinfo->di_externapp   = le16_to_host(docinfo->di_externapp);
    docinfo->di_passwd      = le16_to_host(docinfo->di_passwd);
    docinfo->di_infoblksize = le16_to_host(docinfo->di_infoblksize);

    hwp3_debug("HWP3.x: di_writeprot:   %u\n", docinfo->di_writeprot);
    hwp3_debug("HWP3.x: di_externapp:   %u\n", docinfo->di_externapp);
    hwp3_debug("HWP3.x: di_passwd:      %u\n", docinfo->di_passwd);
    hwp3_debug("HWP3.x: di_compressed:  %u\n", docinfo->di_compressed);
    hwp3_debug("HWP3.x: di_infoblksize: %u\n", docinfo->di_infoblksize);

    if (SCAN_COLLECT_METADATA) {
        json_object *header, *flags;
        char *str;

        header = cli_jsonobj(ctx->this_layer_metadata_json, "Hwp3Header");
        if (!header) {
            cli_errmsg("HWP3.x: No memory for Hwp3Header object\n");
            cli_mark_scan_incomplete(ctx, "HWP3 header metadata could not be allocated");
            return CL_EMEM;
        }

        flags = cli_jsonarray(header, "Flags");
        if (!flags) {
            cli_errmsg("HWP5.x: No memory for Hwp5Header/Flags array\n");
            cli_mark_scan_incomplete(ctx, "HWP3 header flags metadata could not be allocated");
            return CL_EMEM;
        }

        if (docinfo->di_writeprot) {
            cli_jsonstr(flags, NULL, "HWP3_WRITEPROTECTED"); /* HWP3_DISTRIBUTABLE */
        }
        if (docinfo->di_externapp) {
            cli_jsonstr(flags, NULL, "HWP3_EXTERNALAPPLICATION");
        }
        if (docinfo->di_passwd) {
            cli_jsonstr(flags, NULL, "HWP3_PASSWORD");
        }
        if (docinfo->di_compressed) {
            cli_jsonstr(flags, NULL, "HWP3_COMPRESSED");
        }

        /* Printed File Name */
        str = convert_hstr_to_utf8((char *)(hwp3_ptr + DI_PNAME), 40, "HWP3.x", &iret);
        if (!str) {
            cli_mark_scan_incomplete(ctx, "HWP3 document-info name metadata could not be allocated");
            return CL_EMEM;
        }

        if (iret == CL_VIRUS)
            cli_jsonbool(header, "PrintName_base64", 1);

        hwp3_debug("HWP3.x: di_pname:   %s\n", str);
        cli_jsonstr(header, "PrintName", str);
        free(str);

        /* Annotation */
        str = convert_hstr_to_utf8((char *)(hwp3_ptr + DI_ANNOTE), 24, "HWP3.x", &iret);
        if (!str) {
            cli_mark_scan_incomplete(ctx, "HWP3 document-info annotation metadata could not be allocated");
            return CL_EMEM;
        }

        if (iret == CL_VIRUS)
            cli_jsonbool(header, "Annotation_base64", 1);

        hwp3_debug("HWP3.x: di_annote:  %s\n", str);
        cli_jsonstr(header, "Annotation", str);
        free(str);
    }

    return CL_SUCCESS;
}

static inline cl_error_t parsehwp3_docsummary(cli_ctx *ctx, size_t offset)
{
    const uint8_t *hwp3_ptr;
    char *str;
    size_t i;
    cl_error_t ret, iret;

    json_object *summary;

    if (!SCAN_COLLECT_METADATA)
        return CL_SUCCESS;

    if (hwp3_checktimelimit(ctx, "HWP3 document-summary inspection reached the configured time limit") != CL_SUCCESS)
        return CL_ETIMEOUT;

    if (offset > ctx->fmap->len || HWP3_DOCSUMMARY_SIZE > ctx->fmap->len - offset) {
        cli_mark_scan_incomplete(ctx, "HWP3 document-summary could not be read completely");
        return CL_EPARSE;
    }

    if (!(hwp3_ptr = fmap_need_off_once(ctx->fmap, offset, HWP3_DOCSUMMARY_SIZE))) {
        cli_errmsg("HWP3.x: Failed to read fmap for hwp docsummary\n");
        cli_mark_scan_incomplete(ctx, "HWP3 document-summary could not be read completely");
        return CL_EREAD;
    }

    summary = cli_jsonobj(ctx->this_layer_metadata_json, "Hwp3SummaryInfo");
    if (!summary) {
        cli_errmsg("HWP3.x: No memory for json object\n");
        cli_mark_scan_incomplete(ctx, "HWP3 document-summary metadata could not be allocated");
        return CL_EMEM;
    }

    for (i = 0; i < NUM_DOCSUMMARY_FIELDS; i++) {
        str = convert_hstr_to_utf8((char *)(hwp3_ptr + hwp3_docsummary_fields[i].offset), 112, "HWP3.x", &iret);
        if (!str) {
            cli_mark_scan_incomplete(ctx, "HWP3 document-summary field could not be allocated");
            return CL_EMEM;
        }

        if (iret == CL_VIRUS) {
            char *b64;
            size_t b64len = strlen(hwp3_docsummary_fields[i].name) + 8;
            b64           = cli_max_calloc(1, b64len);
            if (!b64) {
                cli_errmsg("HWP3.x: Failed to allocate memory for b64 boolean\n");
                free(str);
                cli_mark_scan_incomplete(ctx, "HWP3 document-summary base64 metadata could not be allocated");
                return CL_EMEM;
            }
            snprintf(b64, b64len, "%s_base64", hwp3_docsummary_fields[i].name);
            cli_jsonbool(summary, b64, 1);
            free(b64);
        }

        hwp3_debug("HWP3.x: %s, %s\n", hwp3_docsummary_fields[i].name, str);
        ret = cli_jsonstr(summary, hwp3_docsummary_fields[i].name, str);
        free(str);
        if (ret != CL_SUCCESS) {
            cli_mark_scan_incomplete(ctx, "HWP3 document-summary field could not be recorded");
            return ret;
        }
    }

    return CL_SUCCESS;
}

#if HWP3_VERIFY
#define HWP3_PSPECIAL_VERIFY(map, offset, second, id, match)                          \
    do {                                                                              \
        if (fmap_readn(map, &match, offset + second, sizeof(match)) != sizeof(match)) \
            return CL_EREAD;                                                          \
                                                                                      \
        match = le16_to_host(match);                                                  \
                                                                                      \
        if (id != match) {                                                            \
            cli_errmsg("HWP3.x: ID %u block fails verification\n", id);               \
            return CL_EFORMAT;                                                        \
        }                                                                             \
    } while (0)

#else
#define HWP3_PSPECIAL_VERIFY(map, offset, second, id, match)
#endif

static inline cl_error_t parsehwp3_paragraph(cli_ctx *ctx, fmap_t *map, int p, uint32_t level, size_t *roffset, int *last)
{
    cl_error_t ret = CL_SUCCESS;
    cl_error_t read_status;

    size_t offset = *roffset;
    size_t new_offset;
    uint16_t nchars, nlines, content;
    uint8_t ppfs, ifsc, cfsb;
    uint16_t i;
    int c, l, sp = 0, term = 0;
#if HWP3_VERIFY
    uint16_t match;
#endif
#if HWP3_DEBUG
    /* other paragraph info */
    uint8_t flags, istyle;
    uint16_t fsize;
    uint32_t special;

    /* line info */
    uint16_t loff, lcor, lhei, lpag;

    /* char shape data */
    uint16_t pcsd_size;
    uint8_t pcsd_prop;
#endif

    if (hwp3_checktimelimit(ctx, "HWP3 paragraph inspection reached the configured time limit") != CL_SUCCESS)
        return CL_ETIMEOUT;

    hwp3_debug("HWP3.x: recursion level: %u\n", level);
    hwp3_debug("HWP3.x: Paragraph[%u, %d] starts @ offset %zu\n", level, p, offset);

    if (level >= ctx->engine->maxrechwp3) {
        cli_append_potentially_unwanted_if_heur_exceedsmax(ctx, "Heuristics.Limits.Exceeded.MaxRecursion", CL_EMAXREC);
        return CL_EMAXREC;
    }

    read_status = hwp3_read_fixed(ctx, map, &ppfs, offset + PI_PPFS, sizeof(ppfs),
                                   "HWP3 paragraph header could not be read completely");
    if (read_status != CL_SUCCESS)
        return read_status;

    read_status = hwp3_read_fixed(ctx, map, &nchars, offset + PI_NCHARS, sizeof(nchars),
                                  "HWP3 paragraph header could not be read completely");
    if (read_status != CL_SUCCESS)
        return read_status;

    nchars = le16_to_host(nchars);

    read_status = hwp3_read_fixed(ctx, map, &nlines, offset + PI_NLINES, sizeof(nlines),
                                  "HWP3 paragraph header could not be read completely");
    if (read_status != CL_SUCCESS)
        return read_status;

    nlines = le16_to_host(nlines);

    read_status = hwp3_read_fixed(ctx, map, &ifsc, offset + PI_IFSC, sizeof(ifsc),
                                  "HWP3 paragraph header could not be read completely");
    if (read_status != CL_SUCCESS)
        return read_status;

    hwp3_debug("HWP3.x: Paragraph[%u, %d]: ppfs   %u\n", level, p, ppfs);
    hwp3_debug("HWP3.x: Paragraph[%u, %d]: nchars %u\n", level, p, nchars);
    hwp3_debug("HWP3.x: Paragraph[%u, %d]: nlines %u\n", level, p, nlines);
    hwp3_debug("HWP3.x: Paragraph[%u, %d]: ifsc   %u\n", level, p, ifsc);

#if HWP3_DEBUG
    if (fmap_readn(map, &flags, offset + PI_FLAGS, sizeof(flags)) != sizeof(flags))
        return CL_EREAD;

    if (fmap_readn(map, &special, offset + PI_SPECIAL, sizeof(special)) != sizeof(special))
        return CL_EREAD;

    if (fmap_readn(map, &istyle, offset + PI_ISTYLE, sizeof(istyle)) != sizeof(istyle))
        return CL_EREAD;

    if (fmap_readn(map, &fsize, offset + 12, sizeof(fsize)) != sizeof(fsize))
        return CL_EREAD;

    hwp3_debug("HWP3.x: Paragraph[%u, %d]: flags  %x\n", level, p, flags);
    hwp3_debug("HWP3.x: Paragraph[%u, %d]: spcl   %x\n", level, p, special);
    hwp3_debug("HWP3.x: Paragraph[%u, %d]: istyle %u\n", level, p, istyle);
    hwp3_debug("HWP3.x: Paragraph[%u, %d]: fsize  %u\n", level, p, fsize);
#endif

    /* detected empty paragraph marker => end-of-paragraph list */
    if (nchars == 0) {
        hwp3_debug("HWP3.x: Detected end-of-paragraph list @ offset %zu\n", offset);
        hwp3_debug("HWP3.x: end recursion level: %u\n", level);
        (*roffset) = offset + HWP3_PARAINFO_SIZE_S;
        (*last)    = 1;
        return CL_SUCCESS;
    }

    if (ppfs)
        offset += HWP3_PARAINFO_SIZE_S;
    else
        offset += HWP3_PARAINFO_SIZE_L;

        /* line information blocks */
#if HWP3_DEBUG
    for (i = 0; (i < nlines) && (offset < map->len); i++) {
        hwp3_debug("HWP3.x: Paragraph[%u, %d]: Line %d information starts @ offset %zu\n", level, p, i, offset);
        if (fmap_readn(map, &loff, offset + PLI_LOFF, sizeof(loff)) != sizeof(loff))
            return CL_EREAD;

        if (fmap_readn(map, &lcor, offset + PLI_LCOR, sizeof(lcor)) != sizeof(lcor))
            return CL_EREAD;

        if (fmap_readn(map, &lhei, offset + PLI_LHEI, sizeof(lhei)) != sizeof(lhei))
            return CL_EREAD;

        if (fmap_readn(map, &lpag, offset + PLI_LPAG, sizeof(lpag)) != sizeof(lpag))
            return CL_EREAD;

        loff = le16_to_host(loff);
        lcor = le16_to_host(lcor);
        lhei = le16_to_host(lhei);
        lpag = le16_to_host(lpag);

        hwp3_debug("HWP3.x: Paragraph[%u, %d]: Line %d: loff %u\n", level, p, i, loff);
        hwp3_debug("HWP3.x: Paragraph[%u, %d]: Line %d: lcor %x\n", level, p, i, lcor);
        hwp3_debug("HWP3.x: Paragraph[%u, %d]: Line %d: lhei %u\n", level, p, i, lhei);
        hwp3_debug("HWP3.x: Paragraph[%u, %d]: Line %d: lpag %u\n", level, p, i, lpag);

        offset += HWP3_LINEINFO_SIZE;
    }
#else
    new_offset = offset + (nlines * HWP3_LINEINFO_SIZE);
    if ((new_offset < offset) || (new_offset >= map->len)) {
        cli_errmsg("HWP3.x: Paragraph[%u, %d]: nlines value is too high, invalid. %u\n", level, p, nlines);
        return CL_EPARSE;
    }
    offset = new_offset;
#endif

    if (offset >= map->len)
        return CL_EFORMAT;

    if (ifsc) {
        for (i = 0, c = 0; i < nchars; i++) {
            if (hwp3_checktimelimit(ctx, "HWP3 character-style traversal reached the configured time limit") != CL_SUCCESS)
                return CL_ETIMEOUT;

            /* examine byte for cs data type */
            read_status = hwp3_read_fixed(ctx, map, &cfsb, offset, sizeof(cfsb),
                                           "HWP3 character-style byte could not be read completely");
            if (read_status != CL_SUCCESS)
                return read_status;

            offset += sizeof(cfsb);

            switch (cfsb) {
                case 0: /* character shape block */
                    hwp3_debug("HWP3.x: Paragraph[%u, %d]: character font style data @ offset %zu\n", level, p, offset);

#if HWP3_DEBUG
                    if (fmap_readn(map, &pcsd_size, offset + PCSD_SIZE, sizeof(pcsd_size)) != sizeof(pcsd_size))
                        return CL_EREAD;

                    if (fmap_readn(map, &pcsd_prop, offset + PCSD_PROP, sizeof(pcsd_prop)) != sizeof(pcsd_prop))
                        return CL_EREAD;

                    pcsd_size = le16_to_host(pcsd_size);

                    hwp3_debug("HWP3.x: Paragraph[%u, %d]: CFS %u: pcsd_size %u\n", level, p, 0, pcsd_size);
                    hwp3_debug("HWP3.x: Paragraph[%u, %d]: CFS %u: pcsd_prop %x\n", level, p, 0, pcsd_prop);
#endif

                    c++;
                    offset += HWP3_CHARSHPDATA_SIZE;
                    break;
                case 1: /* normal character - as representation of another character for previous cs block */
                    break;
                default:
                    cli_errmsg("HWP3.x: Paragraph[%u, %d]: unknown CFS type 0x%x @ offset %zu\n", level, p, cfsb, offset);
                    cli_errmsg("HWP3.x: Paragraph parsing detected %d of %u characters\n", i, nchars);
                    return CL_EPARSE;
            }
        }

        hwp3_debug("HWP3.x: Paragraph[%u, %d]: detected %d CFS block(s) and %d characters\n", level, p, c, i);
    } else {
        hwp3_debug("HWP3.x: Paragraph[%u, %d]: separate character font style segment not stored\n", level, p);
    }

    if (!term)
        hwp3_debug("HWP3.x: Paragraph[%u, %d]: content starts @ offset %zu\n", level, p, offset);

    /* scan for end-of-paragraph [0x0d00 on offset parity to current content] */
    while ((!term) &&
           (offset < map->len)) {

        if (hwp3_checktimelimit(ctx, "HWP3 paragraph-content traversal reached the configured time limit") != CL_SUCCESS)
            return CL_ETIMEOUT;

        read_status = hwp3_read_fixed(ctx, map, &content, offset, sizeof(content),
                                      "HWP3 paragraph content could not be read completely");
        if (read_status != CL_SUCCESS)
            return read_status;

        content = le16_to_host(content);

        /* special character handling */
        if (content < 32) {
            hwp3_debug("HWP3.x: Paragraph[%u, %d]: detected special character %u @ offset %zu\n", level, p, content, offset);

            switch (content) {
                case 0:
                case 1:
                case 2:
                case 3:
                case 4:
                case 12:
                case 27: {
                    /* reserved */
                    uint32_t length;

                    hwp3_debug("HWP3.x: Paragraph[%u, %d]: detected special character as [reserved]\n", level, p);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (4 bytes) - length of information = n
                     * offset 6 (2 bytes) - special character ID
                     * offset 8 (n bytes) - information
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 6, content, match);

                    read_status = hwp3_read_fixed(ctx, map, &length, offset + 2, sizeof(length),
                                                  "HWP3 special-character length could not be read completely");
                    if (read_status != CL_SUCCESS)
                        return read_status;

                    length     = le32_to_host(length);
                    new_offset = offset + (8 + length);
                    if ((new_offset <= offset) || (new_offset > map->len)) {
                        cli_errmsg("HWP3.x: Paragraph[%u, %d]: length value is too high, invalid. %u\n", level, p, length);
                        return CL_EPARSE;
                    }
                    offset = new_offset;

#if HWP3_DEBUG
                    cli_errmsg("HWP3.x: Paragraph[%u, %d]: possible invalid usage of reserved special character %u\n", level, p, content);
                    return CL_EFORMAT;
#endif
                    break;
                }
                case 5: /* field codes */
                {
                    uint32_t length;

                    hwp3_debug("HWP3.x: Paragraph[%u, %d]: detected field code marker @ offset %zu\n", level, p, offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (4 bytes) - length of information = n
                     * offset 6 (2 bytes) - special character ID
                     * offset 8 (n bytes) - field code details
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 6, content, match);

                    read_status = hwp3_read_fixed(ctx, map, &length, offset + 2, sizeof(length),
                                                  "HWP3 special-character length could not be read completely");
                    if (read_status != CL_SUCCESS)
                        return read_status;

                    length     = le32_to_host(length);
                    new_offset = offset + (8 + length);
                    if ((new_offset <= offset) || (new_offset > map->len)) {
                        cli_errmsg("HWP3.x: Paragraph[%u, %d]: length value is too high, invalid. %u\n", level, p, length);
                        return CL_EPARSE;
                    }
                    offset = new_offset;
                    break;
                }
                case 6: /* bookmark */
                {
#if HWP3_VERIFY
                    uint32_t length;
#endif

                    hwp3_debug("HWP3.x: Paragraph[%u, %d]: detected bookmark marker @ offset %zu\n", level, p, offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (4 bytes) - length of information = 34
                     * offset 6 (2 bytes) - special character ID
                     * offset 8 (16 x 2 bytes) - bookmark name
                     * offset 40 (2 bytes) - bookmark type
                     * total is always 42 bytes
                     */

#if HWP3_VERIFY
                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 6, content, match);

                    /* length check - always 34 bytes */
                    read_status = hwp3_read_fixed(ctx, map, &length, offset + 2, sizeof(length),
                                                  "HWP3 special-character length could not be read completely");
                    if (read_status != CL_SUCCESS)
                        return read_status;

                    length = le32_to_host(length);

                    if (length != 34) {
                        cli_errmsg("HWP3.x: Bookmark has incorrect length: %u != 34)\n", length);
                        return CL_EFORMAT;
                    }
#endif
                    offset += 42;
                    break;
                }
                case 7: /* date format */
                {
                    hwp3_debug("HWP3.x: Paragraph[%u, %d]: detected date format marker @ offset %zu\n", level, p, offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (40 x 2 bytes) - date format as user-defined dialog
                     * offset 82 (2 bytes) - special character ID
                     * total is always 84 bytes
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 82, content, match);

                    offset += 84;
                    break;
                }
                case 8: /* date code */
                {
                    hwp3_debug("HWP3.x: Paragraph[%u, %d]: detected date code marker @ offset %zu\n", level, p, offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (40 x 2 bytes) - date format string
                     * offset 82 (4 x 2 bytes) - date (year, month, day of week)
                     * offset 90 (2 x 2 bytes) - time (hour, minute)
                     * offset 94 (2 bytes) - special character ID
                     * total is always 96 bytes
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 94, content, match);

                    offset += 96;
                    break;
                }
                case 9: /* tab */
                {
                    hwp3_debug("HWP3.x: Paragraph[%u, %d]: detected tab marker @ offset %zu\n", level, p, offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (2 bytes) - tab width
                     * offset 4 (2 bytes) - unknown(?)
                     * offset 6 (2 bytes) - special character ID
                     * total is always 8 bytes
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 6, content, match);

                    offset += 8;
                    break;
                }
                case 10: /* table, test box, equation, button, hypertext */
                {
                    uint16_t ncells;
#if HWP3_DEBUG
                    uint16_t type;
#endif
                    hwp3_debug("HWP3.x: Paragraph[%u, %d]: detected box object marker @ offset %zu\n", level, p, offset);

                    /* verification (only on HWP3_VERIFY) */
                    /* id block verify */
                    HWP3_PSPECIAL_VERIFY(map, offset, 6, content, match);
                    /* extra data block verify */
                    HWP3_PSPECIAL_VERIFY(map, offset, 24, content, match);

                    /* ID block is 8 bytes */
                    offset += 8;

                    /* box information (84 bytes) */
#if HWP3_DEBUG
                    /* box type located at offset 78 of box information */
                    if (fmap_readn(map, &type, offset + 78, sizeof(type)) != sizeof(type))
                        return CL_EREAD;

                    type = le16_to_host(type);
                    if (type == 0)
                        hwp3_debug("HWP3.x: Paragraph[%u, %d]: box object detected as table\n", level, p);
                    else if (type == 1)
                        hwp3_debug("HWP3.x: Paragraph[%u, %d]: box object detected as text box\n", level, p);
                    else if (type == 2)
                        hwp3_debug("HWP3.x: Paragraph[%u, %d]: box object detected as equation\n", level, p);
                    else if (type == 3)
                        hwp3_debug("HWP3.x: Paragraph[%u, %d]: box object detected as button\n", level, p);
                    else
                        hwp3_debug("HWP3.x: Paragraph[%u, %d]: box object detected as UNKNOWN(%u)\n", level, p, type);
#endif

                    /* ncells is located at offset 80 of box information */
                    read_status = hwp3_read_fixed(ctx, map, &ncells, offset + 80, sizeof(ncells),
                                                  "HWP3 box header could not be read completely");
                    if (read_status != CL_SUCCESS)
                        return read_status;

                    ncells = le16_to_host(ncells);
                    offset += 84;

                    hwp3_debug("HWP3.x: Paragraph[%u, %d]: box object contains %u cell(s)\n", level, p, ncells);

                    /* cell information (27 bytes x ncells(offset 80 of table)) */
                    hwp3_debug("HWP3.x: Paragraph[%u, %d]: box cell info array starts @ %zu\n", level, p, offset);

                    new_offset = offset + (27 * ncells);
                    if ((new_offset < offset) || (new_offset >= map->len)) {
                        cli_errmsg("HWP3.x: Paragraph[%u, %d]: number of box cells is too high, invalid. %u\n", level, p, ncells);
                        return CL_EPARSE;
                    }
                    offset = new_offset;

                    /* cell paragraph list */
                    hwp3_debug("HWP3.x: Paragraph[%u, %d]: box cell paragraph list starts @ %zu\n", level, p, offset);
                    for (i = 0; i < ncells; i++) {
                        l = 0;
                        while (!l && ((ret = parsehwp3_paragraph(ctx, map, sp++, level + 1, &offset, &l)) == CL_SUCCESS)) continue;
                        if (ret != CL_SUCCESS)
                            return ret;
                    }

                    /* box caption paragraph list */
                    hwp3_debug("HWP3.x: Paragraph[%u, %d]: box cell caption paragraph list starts @ %zu\n", level, p, offset);
                    l = 0;
                    while (!l && ((ret = parsehwp3_paragraph(ctx, map, sp++, level + 1, &offset, &l)) == CL_SUCCESS)) continue;
                    if (ret != CL_SUCCESS)
                        return ret;
                    break;
                }
                case 11: /* drawing */
                {
                    uint32_t size;
                    hwp3_debug("HWP3.x: Paragraph[%u, %d]: detected drawing marker @ offset %zu\n", level, p, offset);

                    /* verification (only on HWP3_VERIFY) */
                    /* id block verify */
                    HWP3_PSPECIAL_VERIFY(map, offset, 6, content, match);
                    /* extra data block verify */
                    HWP3_PSPECIAL_VERIFY(map, offset, 24, content, match);

                    /* ID block is 8 bytes */
                    offset += 8;

                    /* Drawing Info Block is 328+n bytes with n = size of image */
                    /* n is located at offset 0 of info block */
                    read_status = hwp3_read_fixed(ctx, map, &size, offset, sizeof(size),
                                                  "HWP3 drawing header could not be read completely");
                    if (read_status != CL_SUCCESS)
                        return read_status;

                    hwp3_debug("HWP3.x: Paragraph[%u, %d]: drawing is %u additional bytes\n", level, p, size);

                    size       = le32_to_host(size);
                    new_offset = offset + (348 + size);
                    if ((new_offset <= offset) || (new_offset >= map->len)) {
                        cli_errmsg("HWP3.x: Paragraph[%u, %d]: image size value is too high, invalid. %u\n", level, p, size);
                        return CL_EPARSE;
                    }
                    offset = new_offset;

                    /* caption paragraph list */
                    hwp3_debug("HWP3.x: Paragraph[%u, %d]: drawing caption paragraph list starts @ %zu\n", level, p, offset);
                    l = 0;
                    while (!l && ((ret = parsehwp3_paragraph(ctx, map, sp++, level + 1, &offset, &l)) == CL_SUCCESS)) continue;
                    if (ret != CL_SUCCESS)
                        return ret;
                    break;
                }
                case 13: /* end-of-paragraph marker - treated identically as character */
                    hwp3_debug("HWP3.x: Detected end-of-paragraph marker @ offset %zu\n", offset);
                    term = 1;

                    offset += sizeof(content);
                    break;
                case 14: /* line information */
                {
                    hwp3_debug("HWP3.x: Detected line information marker @ offset %zu\n", offset);

                    /* verification (only on HWP3_VERIFY) */
                    /* id block verify */
                    HWP3_PSPECIAL_VERIFY(map, offset, 6, content, match);
                    /* extra data block verify */
                    HWP3_PSPECIAL_VERIFY(map, offset, 24, content, match);

                    /* ID block is 8 bytes + line information is always 84 bytes */
                    offset += 92;
                    break;
                }
                case 15: /* hidden description */
                {
                    hwp3_debug("HWP3.x: Detected hidden description marker @ offset %zu\n", offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (4 bytes) - reserved
                     * offset 6 (2 bytes) - special character ID
                     * offset 8 (8 bytes) - reserved
                     * total is always 16 bytes
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 6, content, match);

                    offset += 16;

                    /* hidden description paragraph list */
                    hwp3_debug("HWP3.x: Paragraph[%u, %d]: hidden description paragraph list starts @ %zu\n", level, p, offset);
                    l = 0;
                    while (!l && ((ret = parsehwp3_paragraph(ctx, map, sp++, level + 1, &offset, &l)) == CL_SUCCESS)) continue;
                    if (ret != CL_SUCCESS)
                        return ret;
                    break;
                }
                case 16: /* header/footer */
                {
#if HWP3_DEBUG
                    uint8_t type;
#endif

                    hwp3_debug("HWP3.x: Paragraph[%u, %d]: detected header/footer marker @ offset %zu\n", level, p, offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (4 bytes) - reserved
                     * offset 6 (2 bytes) - special character ID
                     * offset 8 (8 x 1 byte) - reserved
                     * offset 16 (1 byte) - type (header/footer)
                     * offset 17 (1 byte) - kind
                     * total is always 18 bytes
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 6, content, match);

#if HWP3_DEBUG
                    if (fmap_readn(map, &type, offset + 16, sizeof(type)) != sizeof(type))
                        return CL_EREAD;

                    if (type == 0)
                        hwp3_debug("HWP3.x: Paragraph[%u, %d]: detected header/footer as header\n", level, p);
                    else if (type == 1)
                        hwp3_debug("HWP3.x: Paragraph[%u, %d]: detected header/footer as footer\n", level, p);
                    else
                        hwp3_debug("HWP3.x: Paragraph[%u, %d]: detected header/footer as UNKNOWN(%u)\n", level, p, type);
#endif
                    offset += 18;

                    /* content paragraph list */
                    hwp3_debug("HWP3.x: Paragraph[%u, %d]: header/footer paragraph list starts @ %zu\n", level, p, offset);
                    l = 0;
                    while (!l && ((ret = parsehwp3_paragraph(ctx, map, sp++, level + 1, &offset, &l)) == CL_SUCCESS)) continue;
                    if (ret != CL_SUCCESS)
                        return ret;
                    break;
                }
                case 17: /* footnote/endnote */
                {
                    hwp3_debug("HWP3.x: Detected footnote/endnote marker @ offset %zu\n", offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (4 bytes) - reserved
                     * offset 6 (2 bytes) - special character ID
                     * offset 8 (8 x 1 bytes) - reserved
                     * offset 16 (2 bytes) - number
                     * offset 18 (2 bytes) - type
                     * offset 20 (2 bytes) - alignment
                     * total is always 22 bytes
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 6, content, match);

                    offset += 22;

                    /* content paragraph list */
                    hwp3_debug("HWP3.x: Paragraph[%u, %d]: footnote/endnote paragraph list starts @ %zu\n", level, p, offset);
                    l = 0;
                    while (!l && ((ret = parsehwp3_paragraph(ctx, map, sp++, level + 1, &offset, &l)) == CL_SUCCESS)) continue;
                    if (ret != CL_SUCCESS)
                        return ret;
                    break;
                }
                case 18: /* paste code number */
                {
#if HWP3_DEBUG
                    uint8_t type;
#endif

                    hwp3_debug("HWP3.x: Paragraph[%u, %d]: detected paste code number marker @ offset %zu\n", level, p, offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (2 bytes) - type
                     * offset 4 (2 bytes) - number value
                     * offset 6 (2 bytes) - special character ID
                     * total is always 8 bytes
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 6, content, match);

#if HWP3_DEBUG
                    if (fmap_readn(map, &type, offset + 2, sizeof(type)) != sizeof(type))
                        return CL_EREAD;

                    if (type == 0)
                        hwp3_debug("HWP3.x: Paragraph[%u, %d]: detected paste code number as side\n", level, p);
                    else if (type == 1)
                        hwp3_debug("HWP3.x: Paragraph[%u, %d]: detected paste code number as footnote\n", level, p);
                    else if (type == 2)
                        hwp3_debug("HWP3.x: Paragraph[%u, %d]: detected paste code number as North America???\n", level, p);
                    else if (type == 3)
                        hwp3_debug("HWP3.x: Paragraph[%u, %d]: detected paste code number as drawing\n", level, p);
                    else if (type == 4)
                        hwp3_debug("HWP3.x: Paragraph[%u, %d]: detected paste code number as table\n", level, p);
                    else if (type == 5)
                        hwp3_debug("HWP3.x: Paragraph[%u, %d]: detected paste code number as equation\n", level, p);
                    else
                        hwp3_debug("HWP3.x: Paragraph[%u, %d]: detected paste code number as UNKNOWN(%u)\n", level, p, type);
#endif
                    offset += 8;
                    break;
                }
                case 19: /* code number change */
                {
                    hwp3_debug("HWP3.x: Paragraph[%u, %d]: detected code number change marker @ offset %zu\n", level, p, offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (2 bytes) - type
                     * offset 4 (2 bytes) - new number value
                     * offset 6 (2 bytes) - special character ID
                     * total is always 8 bytes
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 6, content, match);

                    offset += 8;
                    break;
                }
                case 20: {
                    hwp3_debug("HWP3.x: Paragraph[%u, %d]: detected thread page number marker @ offset %zu\n", level, p, offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (2 bytes) - location
                     * offset 4 (2 bytes) - shape
                     * offset 6 (2 bytes) - special character ID
                     * total is always 8 bytes
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 6, content, match);

                    offset += 8;
                    break;
                }
                case 21: /* hide special */
                {
                    hwp3_debug("HWP3.x: Paragraph[%u, %d]: detected hide special marker @ offset %zu\n", level, p, offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (2 bytes) - type
                     * offset 4 (2 bytes) - target
                     * offset 6 (2 bytes) - special character ID
                     * total is always 8 bytes
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 6, content, match);

                    offset += 8;
                    break;
                }
                case 22: /* mail merge display */
                {
                    hwp3_debug("HWP3.x: Paragraph[%u, %d]: detected mail merge display marker @ offset %zu\n", level, p, offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (20 x 1 bytes) - field name (in ASCII)
                     * offset 22 (2 bytes) - special character ID
                     * total is always 24 bytes
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 22, content, match);

                    offset += 24;
                    break;
                }
                case 23: /* overlapping letters */
                {
                    hwp3_debug("HWP3.x: Paragraph[%u, %d]: detected overlapping marker @ offset %zu\n", level, p, offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (3 x 2 bytes) - overlapping letters
                     * offset 8 (2 bytes) - special character ID
                     * total is always 10 bytes
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 8, content, match);

                    offset += 10;
                    break;
                }
                case 24: /* hyphen */
                {
                    hwp3_debug("HWP3.x: Paragraph[%u, %d]: detected hyphen marker @ offset %zu\n", level, p, offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (2 bytes) - width of hyphen
                     * offset 4 (2 bytes) - special character ID
                     * total is always 6 bytes
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 4, content, match);

                    offset += 6;
                    break;
                }
                case 25: /* title/table/picture show times */
                {
                    hwp3_debug("HWP3.x: Paragraph[%u, %d]: detected title/table/picture show times marker @ offset %zu\n", level, p, offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (2 bytes) - type
                     * offset 4 (2 bytes) - special character ID
                     * total is always 6 bytes
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 4, content, match);

                    offset += 6;
                    break;
                }
                case 26: /* browse displayed */
                {
                    hwp3_debug("HWP3.x: Paragraph[%u, %d]: detected browse displayed marker @ offset %zu\n", level, p, offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (60 x 2 bytes) - keyword 1
                     * offset 122 (60 x 2 bytes) - keyword 2
                     * offset 242 (2 bytes) - page number
                     * offset 244 (2 bytes) - special character ID
                     * total is always 246 bytes
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 244, content, match);

                    offset += 246;
                    break;
                }
                case 28: /* overview shape/summary number */
                {
                    hwp3_debug("HWP3.x: Paragraph[%u, %d]: detected overview shape/summary number marker @ offset %zu\n", level, p, offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (2 bytes) - type
                     * offset 4 (1 byte)  - form
                     * offset 5 (1 byte)  - step
                     * offset 6 (7 x 2 bytes)  - summary number
                     * offset 20 (7 x 2 bytes) - custom
                     * offset 34 (2 x 7 x 2 bytes) - decorative letters
                     * offset 62 (2 bytes) - special character ID
                     * total is always 64 bytes
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 62, content, match);

                    offset += 64;
                    break;
                }
                case 29: /* cross-reference */
                {
                    uint32_t length;

                    hwp3_debug("HWP3.x: Paragraph[%u, %d]: detected cross-reference marker @ offset %zu\n", level, p, offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (4 bytes) - length of information
                     * offset 6 (2 bytes) - special character ID
                     * offset 8 (n bytes) - ...
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 6, content, match);

                    read_status = hwp3_read_fixed(ctx, map, &length, offset + 2, sizeof(length),
                                                  "HWP3 special-character length could not be read completely");
                    if (read_status != CL_SUCCESS)
                        return read_status;

                    length     = le32_to_host(length);
                    new_offset = offset + (8 + length);
                    if ((new_offset <= offset) || (new_offset > map->len)) {
                        cli_errmsg("HWP3.x: Paragraph[%u, %d]: length value is too high, invalid. %u\n", level, p, length);
                        return CL_EPARSE;
                    }
                    offset = new_offset;
                    break;
                }
                case 30: /* bundle of blanks (ON SALE for 2.99!) */
                {
                    hwp3_debug("HWP3.x: Paragraph[%u, %d]: detected title/table/picture show times marker @ offset %zu\n", level, p, offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (2 bytes) - special character ID
                     * total is always 4 bytes
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 2, content, match);

                    offset += 4;
                    break;
                }
                case 31: /* fixed-width space */
                {
                    hwp3_debug("HWP3.x: Paragraph[%u, %d]: detected title/table/picture show times marker @ offset %zu\n", level, p, offset);

                    /*
                     * offset 0 (2 bytes) - special character ID
                     * offset 2 (2 bytes) - special character ID
                     * total is always 4 bytes
                     */

                    /* id block verification (only on HWP3_VERIFY) */
                    HWP3_PSPECIAL_VERIFY(map, offset, 2, content, match);

                    offset += 4;
                    break;
                }
                default:
                    hwp3_debug("HWP3.x: Paragraph[%u, %d]: detected special character as [UNKNOWN]\n", level, p);
                    cli_errmsg("HWP3.x: Paragraph[%u, %d]: cannot understand special character %u\n", level, p, content);
                    return CL_EPARSE;
            }
        } else { /* normal characters */
            offset += sizeof(content);
        }
    }

    hwp3_debug("HWP3.x: end recursion level: %d\n", level);

    (*roffset) = offset;
    return CL_SUCCESS;
}

static inline cl_error_t parsehwp3_infoblk_1(cli_ctx *ctx, fmap_t *dmap, size_t *offset, int *last)
{
    cl_error_t ret = CL_SUCCESS;
    cl_error_t read_status;

    uint32_t infoid, infolen;
    fmap_t *map = (dmap ? dmap : ctx->fmap);
    int i, count;
    long long unsigned infoloc = (long long unsigned)(*offset);
#if HWP3_DEBUG
    char field[HWP3_FIELD_LENGTH];
#endif
    json_object *infoblk_1, *contents = NULL, *counter, *entry = NULL;

    if (hwp3_checktimelimit(ctx, "HWP3 information-block inspection reached the configured time limit") != CL_SUCCESS)
        return CL_ETIMEOUT;

    hwp3_debug("HWP3.x: Information Block @ offset %llu\n", infoloc);

    if (SCAN_COLLECT_METADATA) {
        infoblk_1 = cli_jsonobj(ctx->this_layer_metadata_json, "InfoBlk_1");
        if (!infoblk_1) {
            cli_errmsg("HWP5.x: No memory for information block object\n");
            cli_mark_scan_incomplete(ctx, "HWP3 information-block metadata could not be allocated");
            return CL_EMEM;
        }

        contents = cli_jsonarray(infoblk_1, "Contents");
        if (!contents) {
            cli_errmsg("HWP5.x: No memory for information block contents array\n");
            cli_mark_scan_incomplete(ctx, "HWP3 information-block contents metadata could not be allocated");
            return CL_EMEM;
        }

        if (!json_object_object_get_ex(infoblk_1, "Count", &counter)) { /* object not found */
            cli_jsonint(infoblk_1, "Count", 1);
        } else {
            int value = json_object_get_int(counter);
            cli_jsonint(infoblk_1, "Count", value + 1);
        }
    }

    read_status = hwp3_read_fixed(ctx, map, &infoid, *offset, sizeof(infoid),
                                  "HWP3 information-block header could not be read completely");
    if (read_status != CL_SUCCESS)
        return read_status;
    *offset += sizeof(infoid);
    infoid = le32_to_host(infoid);

    if (SCAN_COLLECT_METADATA) {
        entry = cli_jsonobj(contents, NULL);
        if (!entry) {
            cli_errmsg("HWP5.x: No memory for information block entry object\n");
            cli_mark_scan_incomplete(ctx, "HWP3 information-block entry metadata could not be allocated");
            return CL_EMEM;
        }

        cli_jsonint(entry, "ID", infoid);
    }

    hwp3_debug("HWP3.x: Information Block[%llu]: ID:  %u\n", infoloc, infoid);

    /* Booking Information(5) - no length field and no content */
    if (infoid == 5) {
        hwp3_debug("HWP3.x: Information Block[%llu]: TYPE: Booking Information\n", infoloc);

        if (SCAN_COLLECT_METADATA)
            cli_jsonstr(entry, "Type", "Booking Information");

        return CL_SUCCESS;
    }

    read_status = hwp3_read_fixed(ctx, map, &infolen, *offset, sizeof(infolen),
                                  "HWP3 information-block header could not be read completely");
    if (read_status != CL_SUCCESS)
        return read_status;
    *offset += sizeof(infolen);
    infolen = le32_to_host(infolen);

    if (SCAN_COLLECT_METADATA) {
        cli_jsonint64(entry, "Offset", infoloc);
        cli_jsonint(entry, "Length", infolen);
    }

    hwp3_debug("HWP3.x: Information Block[%llu]: LEN: %u\n", infoloc, infolen);

    /* check information block bounds */
    if (*offset > map->len || (size_t)infolen > map->len - *offset) {
        size_t remaining = (*offset <= map->len) ? map->len - *offset : 0;
        cli_errmsg("HWP3.x: Information block length %u exceeds remaining map length %zu at offset %zu\n",
                   infolen, remaining, *offset);
        cli_mark_scan_incomplete(ctx, "HWP3 information block extends beyond the input map");
        return CL_EPARSE;
    }

    /* Information Blocks */
    switch (infoid) {
        case 0: /* Terminating */
            if (infolen == 0) {
                hwp3_debug("HWP3.x: Information Block[%llu]: TYPE: Terminating Entry\n", infoloc);

                if (SCAN_COLLECT_METADATA)
                    cli_jsonstr(entry, "Type", "Terminating Entry");

                if (last) *last = 1;
                return CL_SUCCESS;
            } else {
                cli_errmsg("HWP3.x: Information Block[%llu]: TYPE: Invalid Terminating Entry\n", infoloc);
                return CL_EFORMAT;
            }
        case 1: /* Image Data */
            hwp3_debug("HWP3.x: Information Block[%llu]: TYPE: Image Data\n", infoloc);

            if (SCAN_COLLECT_METADATA)
                cli_jsonstr(entry, "Type", "Image Data");

            if (infolen < 32) {
                cli_errmsg("HWP3.x: Image data information block is shorter than its 32-byte header\n");
                return CL_EFORMAT;
            }

#if HWP3_DEBUG /* additional fields can be added */
            memset(field, 0, HWP3_FIELD_LENGTH);
            if (fmap_readn(map, field, *offset, 16) != 16) {
                cli_errmsg("HWP3.x: Failed to read information block field @ %zu\n", *offset);
                return CL_EREAD;
            }
            hwp3_debug("HWP3.x: Information Block[%llu]: NAME: %s\n", infoloc, field);

            memset(field, 0, HWP3_FIELD_LENGTH);
            if (fmap_readn(map, field, *offset + 16, 16) != 16) {
                cli_errmsg("HWP3.x: Failed to read information block field @ %zu\n", *offset);
                return CL_EREAD;
            }
            hwp3_debug("HWP3.x: Information Block[%llu]: FORM: %s\n", infoloc, field);
#endif
            /* 32 bytes for extra data fields */
            if (infolen > 0)
                ret = cli_magic_scan_nested_fmap_type(map, *offset + 32, infolen - 32, ctx,
                                                      CL_TYPE_ANY, NULL, LAYER_ATTRIBUTES_NONE);
            break;
        case 2: /* OLE2 Data */
            hwp3_debug("HWP3.x: Information Block[%llu]: TYPE: OLE2 Data\n", infoloc);

            if (SCAN_COLLECT_METADATA)
                cli_jsonstr(entry, "Type", "OLE2 Data");

            if (infolen > 0)
                ret = cli_magic_scan_nested_fmap_type(map, *offset, infolen, ctx,
                                                      CL_TYPE_ANY, NULL, LAYER_ATTRIBUTES_NONE);
            break;
        case 3: /* Hypertext/Hyperlink Information */
            hwp3_debug("HWP3.x: Information Block[%llu]: TYPE: Hypertext/Hyperlink Information\n", infoloc);
            if (infolen % 617) {
                cli_errmsg("HWP3.x: Information Block[%llu]: Invalid multiple of 617 => %u\n", infoloc, infolen);
                return CL_EFORMAT;
            }

            count = (infolen / 617);
            hwp3_debug("HWP3.x: Information Block[%llu]: COUNT: %d entries\n", infoloc, count);

            if (SCAN_COLLECT_METADATA) {
                cli_jsonstr(entry, "Type", "Hypertext/Hyperlink Information");
                cli_jsonint(entry, "Count", count);
            }

            for (i = 0; i < count; i++) {
                if (hwp3_checktimelimit(ctx, "HWP3 information-block traversal reached the configured time limit") != CL_SUCCESS)
                    return CL_ETIMEOUT;

#if HWP3_DEBUG /* additional fields can be added */
                memset(field, 0, HWP3_FIELD_LENGTH);
                if (fmap_readn(map, field, *offset, 256) != 256) {
                    cli_errmsg("HWP3.x: Failed to read information block field @ %zu\n", *offset);
                    return CL_EREAD;
                }
                hwp3_debug("HWP3.x: Information Block[%llu]: %d: NAME: %s\n", infoloc, i, field);
#endif
                /* scanning macros - TODO - check numbers */
                /* Preserve every embedded-item result.  Replacing a prior
                 * detection or parser failure with a later clean item would
                 * let this information block report a clean layer. */
                ret = cli_merge_scan_status(
                    ret, cli_magic_scan_nested_fmap_type(map, *offset + (617 * i) + 288, 325, ctx,
                                                         CL_TYPE_ANY, NULL, LAYER_ATTRIBUTES_NONE));
            }
            break;
        case 4: /* Presentation Information */
            hwp3_debug("HWP3.x: Information Block[%llu]: TYPE: Presentation Information\n", infoloc);

            if (SCAN_COLLECT_METADATA)
                cli_jsonstr(entry, "Type", "Presentation Information");

            /* contains nothing of interest to scan */
            break;
        case 5: /* Booking Information */
            /* should never run this as it is short-circuited above */
            hwp3_debug("HWP3.x: Information Block[%llu]: TYPE: Booking Information\n", infoloc);

            if (SCAN_COLLECT_METADATA)
                cli_jsonstr(entry, "Type", "Booking Information");

            break;
        case 6: /* Background Image Data */
            hwp3_debug("HWP3.x: Information Block[%llu]: TYPE: Background Image Data\n", infoloc);

            if (infolen < 324) {
                cli_errmsg("HWP3.x: Background image information block is shorter than its 324-byte header\n");
                return CL_EFORMAT;
            }

            if (SCAN_COLLECT_METADATA) {
                cli_jsonstr(entry, "Type", "Background Image Data");
                cli_jsonint(entry, "ImageSize", infolen - 324);
            }

#if HWP3_DEBUG /* additional fields can be added */
            memset(field, 0, HWP3_FIELD_LENGTH);
            if (fmap_readn(map, field, *offset + 24, 256) != 256) {
                cli_errmsg("HWP3.x: Failed to read information block field @ %zu\n", *offset);
                return CL_EREAD;
            }
            hwp3_debug("HWP3.x: Information Block[%llu]: NAME: %s\n", infoloc, field);
#endif
            /* 324 bytes for extra data fields */
            if (infolen > 0)
                ret = cli_magic_scan_nested_fmap_type(map, *offset + 324, infolen - 324, ctx,
                                                      CL_TYPE_ANY, NULL, LAYER_ATTRIBUTES_NONE);
            break;
        case 0x100: /* Table Extension */
            hwp3_debug("HWP3.x: Information Block[%llu]: TYPE: Table Extension\n", infoloc);

            if (SCAN_COLLECT_METADATA)
                cli_jsonstr(entry, "Type", "Table Extension");

            /* contains nothing of interest to scan */
            break;
        case 0x101: /* Press Frame Information Field Name */
            hwp3_debug("HWP3.x: Information Block[%llu]: TYPE: Press Frame Information Field Name\n", infoloc);

            if (SCAN_COLLECT_METADATA)
                cli_jsonstr(entry, "Type", "Press Frame Information Field Name");

            /* contains nothing of interest to scan */
            break;
        default:
            cli_warnmsg("HWP3.x: Information Block[%llu]: TYPE: UNKNOWN(%u)\n", infoloc, infoid);
            if (infolen > 0)
                ret = cli_magic_scan_nested_fmap_type(map, *offset, infolen, ctx,
                                                      CL_TYPE_ANY, NULL, LAYER_ATTRIBUTES_NONE);
    }

    *offset += infolen;
    return ret;
}

static cl_error_t hwp3_cb(void *cbdata, int fd, const char *filepath, cli_ctx *ctx, uint64_t temporary_reserved)
{
    cl_error_t ret = CL_SUCCESS;
    fmap_t *map, *dmap;
    size_t offset, start, new_offset;
    size_t nread;
    int i, p = 0, last = 0;
    uint16_t nstyles;
    json_object *fonts = NULL;

    UNUSEDPARAM(temporary_reserved);

    UNUSEDPARAM(filepath);

    if (hwp3_checktimelimit(ctx, "HWP3 content inspection reached the configured time limit") != CL_SUCCESS)
        return CL_ETIMEOUT;

    offset = start = cbdata ? *(size_t *)cbdata : 0;

    if (offset == 0) {
        if (fd < 0) {
            cli_errmsg("HWP3.x: Invalid file descriptor argument\n");
            return CL_ENULLARG;
        } else {
            STATBUF statbuf;

            if (FSTAT(fd, &statbuf) == -1) {
                cli_errmsg("HWP3.x: Can't stat file descriptor\n");
                return CL_ESTAT;
            }

            map = dmap = fmap_new(fd, 0, statbuf.st_size, NULL, filepath);
            if (!map) {
                cli_errmsg("HWP3.x: Failed to get fmap for uncompressed stream\n");
                return CL_EMAP;
            }
        }
    } else {
        hwp3_debug("HWP3.x: Document Content Stream starts @ offset %zu\n", offset);

        map  = ctx->fmap;
        dmap = NULL;
    }

    /* Fonts - 7 entries of 2 + (n x 40) bytes where n is the first 2 bytes of the entry */
    if (SCAN_COLLECT_METADATA)
        fonts = cli_jsonarray(ctx->this_layer_metadata_json, "FontCounts");

    for (i = 0; i < 7; i++) {
        uint16_t nfonts;

        if (hwp3_checktimelimit(ctx, "HWP3 font-table traversal reached the configured time limit") != CL_SUCCESS) {
            if (dmap)
                fmap_free(dmap);
            return CL_ETIMEOUT;
        }

        nread = hwp3_readn(map, &nfonts, offset, sizeof(nfonts));
        if (nread != sizeof(nfonts)) {
            if (dmap)
                fmap_free(dmap);
            if (nread == (size_t)-1) {
                cli_mark_scan_incomplete(ctx, "HWP3 font-table header could not be read completely");
                return CL_EREAD;
            }
            cli_mark_scan_incomplete(ctx, "HWP3 font-table header is truncated");
            return CL_EPARSE;
        }
        nfonts = le16_to_host(nfonts);

        if (SCAN_COLLECT_METADATA)
            cli_jsonint(fonts, NULL, nfonts);

        hwp3_debug("HWP3.x: Font Entry %d with %u entries @ offset %zu\n", i + 1, nfonts, offset);
        new_offset = offset + (2 + nfonts * 40);
        if ((new_offset <= offset) || (new_offset >= map->len)) {
            cli_errmsg("HWP3.x: Font Entry: number of fonts is too high, invalid. %u\n", nfonts);
            if (dmap)
                fmap_free(dmap);
            return CL_EPARSE;
        }
        offset = new_offset;
    }

    /* Styles - 2 + (n x 238) bytes where n is the first 2 bytes of the section */
    nread = hwp3_readn(map, &nstyles, offset, sizeof(nstyles));
    if (nread != sizeof(nstyles)) {
        if (dmap)
            fmap_free(dmap);
        if (nread == (size_t)-1) {
            cli_mark_scan_incomplete(ctx, "HWP3 style-table header could not be read completely");
            return CL_EREAD;
        }
        cli_mark_scan_incomplete(ctx, "HWP3 style-table header is truncated");
        return CL_EPARSE;
    }
    nstyles = le16_to_host(nstyles);

    if (SCAN_COLLECT_METADATA)
        cli_jsonint(ctx->this_layer_metadata_json, "StyleCount", nstyles);

    hwp3_debug("HWP3.x: %u Styles @ offset %zu\n", nstyles, offset);
    new_offset = offset + (2 + nstyles * 238);
    if ((new_offset <= offset) || (new_offset >= map->len)) {
        cli_errmsg("HWP3.x: Font Entry: number of font styles is too high, invalid. %u\n", nstyles);
        if (dmap)
            fmap_free(dmap);
        return CL_EPARSE;
    }
    offset += (2 + nstyles * 238);

    last = 0;
    /* Paragraphs - variable */
    /* Paragraphs - are terminated with 0x0d00[13(CR) as hchar], empty paragraph marks end of section and do NOT end with 0x0d00 */
    while (!last && ((ret = parsehwp3_paragraph(ctx, map, p++, 0, &offset, &last)) == CL_SUCCESS)) continue;
    /* return is never a virus */
    if (ret != CL_SUCCESS) {
        if (dmap)
            fmap_free(dmap);
        return ret;
    }

    if (SCAN_COLLECT_METADATA)
        cli_jsonint(ctx->this_layer_metadata_json, "ParagraphCount", p);

    last = 0;
    /* 'additional information block #1's - attachments and media */
    while (!last && ((ret = parsehwp3_infoblk_1(ctx, map, &offset, &last)) == CL_SUCCESS)) continue;

    /* scan the uncompressed stream - both compressed and uncompressed cases [ALLMATCH] */
    if (ret == CL_SUCCESS) {
        size_t dlen = offset - start;

        ret = cli_magic_scan_nested_fmap_type(map, start, dlen, ctx, CL_TYPE_ANY, NULL, LAYER_ATTRIBUTES_NONE);
    }

    if (dmap)
        fmap_free(dmap);
    return ret;
}

cl_error_t cli_scanhwp3(cli_ctx *ctx)
{
    cl_error_t ret = CL_SUCCESS;

    struct hwp3_docinfo docinfo;
    size_t offset = 0, new_offset = 0;
    fmap_t *map;

    if (ctx == NULL) {
        cli_dbgmsg("HWP3: passed context was NULL\n");
        return CL_ENULLARG;
    }
    map = ctx->fmap;
    if (map == NULL) {
        cli_mark_scan_incomplete(ctx, "HWP3 input map is unavailable");
        return CL_EPARSE;
    }
    if (!ctx->engine)
        return CL_ENULLARG;

    if (hwp3_checktimelimit(ctx, "HWP3 inspection reached the configured time limit") != CL_SUCCESS)
        return CL_ETIMEOUT;

    /*
    // version
    cli_jsonint(header, "RawVersion", hwp5->version);
    */
    offset += HWP3_IDENTITY_INFO_SIZE;

    if ((ret = parsehwp3_docinfo(ctx, offset, &docinfo)) != CL_SUCCESS)
        goto done;

    offset += HWP3_DOCINFO_SIZE;

    if ((ret = parsehwp3_docsummary(ctx, offset)) != CL_SUCCESS)
        goto done;

    offset += HWP3_DOCSUMMARY_SIZE;

    /* password-protected document - cannot parse */
    if (docinfo.di_passwd) {
        cli_errmsg("HWP3.x: password-protected file cannot be parsed\n");
        cli_mark_scan_incomplete(ctx, "HWP3 password-protected content cannot be parsed");
        ret = CL_EPARSE;
        goto done;
    }

    if (docinfo.di_infoblksize) {
        /* OPTIONAL TODO: HANDLE OPTIONAL INFORMATION BLOCK #0's FOR PRECLASS */
        new_offset = offset + docinfo.di_infoblksize;
        if ((new_offset <= offset) || (new_offset >= map->len)) {
            cli_errmsg("HWP3.x: Doc info block size is too high, invalid. %u\n", docinfo.di_infoblksize);
            ret = CL_EPARSE;
            goto done;
        }
        offset = new_offset;
    }

    if (docinfo.di_compressed)
        ret = decompress_and_callback(ctx, ctx->fmap, offset, 0, "HWP3.x", hwp3_cb, NULL);
    else
        ret = hwp3_cb(&offset, 0, ctx->fmap->path, ctx, 0);

    if (ret != CL_SUCCESS)
        goto done;

    /* OPTIONAL TODO: HANDLE OPTIONAL ADDITIONAL INFORMATION BLOCK #2's FOR PRECLASS*/

done:
    if (ctx && ret != CL_SUCCESS && ret != CL_VIRUS && ret != CL_BREAK && !ctx->scan_incomplete)
        cli_mark_scan_incomplete(ctx, "HWP3 inspection ended before completion");

    return ret;
}

/*** HWPML (hijacking the msxml parser) ***/
static const struct key_entry hwpml_keys[] = {
    {"hwpml", "HWPML", MSXML_JSON_ROOT | MSXML_JSON_ATTRIB},

    /* HEAD - Document Properties */
    //{ "head",               "Head",               MSXML_JSON_WRKPTR },
    {"docsummary", "DocumentProperties", MSXML_JSON_WRKPTR},
    {"title", "Title", MSXML_JSON_WRKPTR | MSXML_JSON_VALUE},
    {"author", "Author", MSXML_JSON_WRKPTR | MSXML_JSON_VALUE},
    {"date", "Date", MSXML_JSON_WRKPTR | MSXML_JSON_VALUE},
    {"docsetting", "DocumentSettings", MSXML_JSON_WRKPTR},
    {"beginnumber", "BeginNumber", MSXML_JSON_WRKPTR | MSXML_JSON_ATTRIB},
    {"caretpos", "CaretPos", MSXML_JSON_WRKPTR | MSXML_JSON_ATTRIB},
    //{ "bindatalist",        "BinDataList",        MSXML_JSON_WRKPTR },
    //{ "binitem",            "BinItem",            MSXML_JSON_WRKPTR | MSXML_JSON_ATTRIB },
    {"facenamelist", "FaceNameList", MSXML_IGNORE_ELEM},            /* fonts list */
    {"borderfilllist", "BorderFillList", MSXML_IGNORE_ELEM},        /* borders list */
    {"charshapelist", "CharShapeList", MSXML_IGNORE_ELEM},          /* character shapes */
    {"tabdeflist", "TableDefList", MSXML_IGNORE_ELEM},              /* table defs */
    {"numberinglist", "NumberingList", MSXML_IGNORE_ELEM},          /* numbering list */
    {"parashapelist", "ParagraphShapeList", MSXML_IGNORE_ELEM},     /* paragraph shapes */
    {"stylelist", "StyleList", MSXML_IGNORE_ELEM},                  /* styles */
    {"compatibledocument", "WordCompatibility", MSXML_IGNORE_ELEM}, /* word compatibility data */

    /* BODY - Document Contents */
    {"body", "Body", MSXML_IGNORE_ELEM}, /* document contents (we could build a document contents summary */

    /* TAIL - Document Attachments */
    //{ "tail",               "Tail",               MSXML_JSON_WRKPTR },
    {"bindatastorage", "BinaryDataStorage", MSXML_JSON_WRKPTR},
    {"bindata", "BinaryData", MSXML_SCAN_CB | MSXML_JSON_WRKPTR | MSXML_JSON_ATTRIB},
    {"scriptcode", "ScriptCodeStorage", MSXML_JSON_WRKPTR | MSXML_JSON_ATTRIB},
    {"scriptheader", "ScriptHeader", MSXML_SCAN_CB | MSXML_JSON_WRKPTR | MSXML_JSON_VALUE},
    {"scriptsource", "ScriptSource", MSXML_SCAN_CB | MSXML_JSON_WRKPTR | MSXML_JSON_VALUE}};
static size_t num_hwpml_keys = sizeof(hwpml_keys) / sizeof(struct key_entry);

/* binary streams needs to be base64-decoded then decompressed if fields are set */
static cl_error_t hwpml_scan_cb(void *cbdata, int fd, const char *filepath, cli_ctx *ctx, uint64_t temporary_reserved)
{
    UNUSEDPARAM(cbdata);
    UNUSEDPARAM(temporary_reserved);

    if (fd < 0 || !ctx)
        return CL_ENULLARG;

    return cli_magic_scan_desc_type_reserved(fd, filepath, ctx, CL_TYPE_ANY, NULL, LAYER_ATTRIBUTES_NONE);
}

static int hwpml_base64_value(unsigned char value)
{
    if (value >= 'A' && value <= 'Z')
        return value - 'A';
    if (value >= 'a' && value <= 'z')
        return value - 'a' + 26;
    if (value >= '0' && value <= '9')
        return value - '0' + 52;
    if (value == '+')
        return 62;
    if (value == '/')
        return 63;
    return -1;
}

static cl_error_t hwpml_flush_base64_output(cli_ctx *ctx, int output_fd, const unsigned char *output,
                                            size_t output_used, uint64_t *total)
{
    cl_error_t ret;
    uint64_t next_total;

    if (output_used == 0)
        return CL_SUCCESS;

    if (*total > UINT64_MAX - output_used) {
        cli_mark_scan_incomplete(ctx, "HWPML Base64 decoded size overflowed");
        return CL_EPARSE;
    }
    next_total = *total + output_used;

    ret = cli_checklimits("HWPML Base64", ctx, next_total, 0, 0);
    if (ret != CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, "HWPML Base64 attachment exceeds configured scan limits");
        return (ret == CL_ETIMEOUT) ? ret : CL_EPARSE;
    }

    ret = cli_checktimelimit(ctx);
    if (ret != CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, "HWPML Base64 decoded attachment reached the configured time limit");
        return ret;
    }

    ret = cli_scan_reserve_temporary(ctx, (uint64_t)output_used);
    if (ret != CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, "HWPML Base64 decoded attachment exceeds temporary storage limits");
        return ret;
    }

    ret = cli_checktimelimit(ctx);
    if (ret != CL_SUCCESS) {
        cli_scan_release_temporary(ctx, (uint64_t)output_used);
        cli_mark_scan_incomplete(ctx, "HWPML Base64 decoded attachment reached the configured time limit");
        return ret;
    }

    if (cli_writen(output_fd, output, output_used) != output_used) {
        cli_scan_release_temporary(ctx, (uint64_t)output_used);
        cli_mark_scan_incomplete(ctx, "HWPML Base64 decoded attachment could not be written completely");
        return CL_EWRITE;
    }

    *total = next_total;
    return CL_SUCCESS;
}

cl_error_t cli_hwpml_decode_base64_fd(cli_ctx *ctx, int input_fd, int output_fd, uint64_t *decoded_size)
{
    unsigned char input[HWPML_BASE64_IO_SIZE];
    unsigned char output[HWPML_BASE64_IO_SIZE];
    unsigned char quartet[4];
    uint64_t total      = 0;
    size_t output_used  = 0;
    size_t quartet_used = 0;
    size_t i;
    size_t produced;
    size_t nread;
    int a, b, c, d;
    int terminal = 0;
    cl_error_t ret;

    if (!ctx || !ctx->engine || input_fd < 0 || output_fd < 0)
        return CL_ENULLARG;

    if (decoded_size)
        *decoded_size = 0;

    if (lseek(input_fd, 0, SEEK_SET) == (off_t)-1) {
        cli_mark_scan_incomplete(ctx, "HWPML Base64 attachment could not be rewound");
        return CL_ESEEK;
    }

    for (;;) {
        ret = cli_checktimelimit(ctx);
        if (ret != CL_SUCCESS) {
            cli_mark_scan_incomplete(ctx, "HWPML Base64 decoding ended at the configured time limit");
            return ret;
        }

        nread = cli_readn(input_fd, input, sizeof(input));
        if (nread == (size_t)-1) {
            cli_mark_scan_incomplete(ctx, "HWPML Base64 attachment could not be read completely");
            return CL_EREAD;
        }
        if (nread == 0)
            break;

        for (i = 0; i < (size_t)nread; i++) {
            if (isspace((int)input[i]))
                continue;

            if (terminal || (input[i] != '=' && hwpml_base64_value(input[i]) < 0)) {
                cli_mark_scan_incomplete(ctx, "HWPML Base64 attachment contains invalid trailing data");
                return CL_EPARSE;
            }

            quartet[quartet_used++] = input[i];
            if (quartet_used != sizeof(quartet))
                continue;

            if (quartet[0] == '=' || quartet[1] == '=' ||
                (quartet[2] == '=' && quartet[3] != '=')) {
                cli_mark_scan_incomplete(ctx, "HWPML Base64 attachment has invalid padding");
                return CL_EPARSE;
            }

            a = hwpml_base64_value(quartet[0]);
            b = hwpml_base64_value(quartet[1]);
            c = quartet[2] == '=' ? 0 : hwpml_base64_value(quartet[2]);
            d = quartet[3] == '=' ? 0 : hwpml_base64_value(quartet[3]);
            if (a < 0 || b < 0 || c < 0 || d < 0) {
                cli_mark_scan_incomplete(ctx, "HWPML Base64 attachment contains an invalid alphabet value");
                return CL_EPARSE;
            }

            produced = quartet[2] == '=' ? 1 : (quartet[3] == '=' ? 2 : 3);
            if (output_used > sizeof(output) - produced) {
                ret = hwpml_flush_base64_output(ctx, output_fd, output, output_used, &total);
                if (ret != CL_SUCCESS)
                    return ret;
                if (decoded_size)
                    *decoded_size = total;
                output_used = 0;
            }

            output[output_used++] = (unsigned char)((a << 2) | (b >> 4));
            if (produced > 1)
                output[output_used++] = (unsigned char)((b << 4) | (c >> 2));
            if (produced > 2)
                output[output_used++] = (unsigned char)((c << 6) | d);

            if (produced != 3)
                terminal = 1;
            quartet_used = 0;
        }
    }

    if (quartet_used != 0) {
        cli_mark_scan_incomplete(ctx, "HWPML Base64 attachment ended with an incomplete quartet");
        return CL_EPARSE;
    }

    ret = hwpml_flush_base64_output(ctx, output_fd, output, output_used, &total);
    if (ret != CL_SUCCESS)
        return ret;

    if (decoded_size)
        *decoded_size = total;
    return CL_SUCCESS;
}

static cl_error_t hwpml_binary_cb(int fd, const char *filepath, cli_ctx *ctx, int num_attribs, struct attrib_entry *attribs, void *cbdata)
{
    cl_error_t ret;

    int i, df = -1, com = 0, enc = 0;
    uint64_t decoded_reserved = 0;
    char *tempfile            = NULL;

    UNUSEDPARAM(cbdata);

    /* check attributes for compression and encoding */
    for (i = 0; i < num_attribs; i++) {
        if (!strcmp(attribs[i].key, "Compress")) {
            if (!strcmp(attribs[i].value, "true"))
                com = 1;
            else if (!strcmp(attribs[i].value, "false"))
                com = 0;
            else
                com = -1;
        }

        if (!strcmp(attribs[i].key, "Encoding")) {
            if (!strcmp(attribs[i].value, "Base64"))
                enc = 1;
            else
                enc = -1;
        }
    }

    hwpml_debug("HWPML: Checking attributes: com: %d, enc: %d\n", com, enc);

    if (com < 0) {
        cli_mark_scan_incomplete(ctx, "HWPML attachment uses an unrecognized compression mode");
        return CL_EPARSE;
    }

    /* decode the binary data if needed - base64 */
    if (enc < 0) {
        cli_errmsg("HWPML: Unrecognized encoding method\n");
        cli_mark_scan_incomplete(ctx, "HWPML attachment uses an unrecognized encoding mode");
        return CL_EPARSE;
    } else if (enc == 1) {
        hwpml_debug("HWPML: Decoding base64-encoded binary data\n");

        /* Decode from the extracted XML text tempfile to a second tempfile in
         * fixed-size buffers. Neither encoded nor decoded attachment data is
         * materialized as one allocation. */
        if ((ret = cli_gentempfd(ctx->this_layer_tmpdir, &tempfile, &df)) != CL_SUCCESS) {
            cli_warnmsg("HWPML: Failed to create temporary file for decoded stream scanning\n");
            cli_mark_scan_incomplete(ctx, "HWPML decoded temporary output could not be created");
            return ret;
        }

        ret = cli_hwpml_decode_base64_fd(ctx, fd, df, &decoded_reserved);
        if (ret != CL_SUCCESS) {
            cli_scan_release_temporary(ctx, decoded_reserved);
            decoded_reserved = 0;
            goto hwpml_end;
        }

        /* keeps the later logic simpler */
        fd = df;

        cli_dbgmsg("HWPML: Decoded binary data to %s\n", tempfile);
    }

    /* decompress the file if needed - zlib */
    if (com) {
        STATBUF statbuf;
        fmap_t *input;

        hwpml_debug("HWPML: Decompressing binary data\n");

        /* fmap the input file for easier manipulation */
        if (FSTAT(fd, &statbuf) == -1) {
            cli_errmsg("HWPML: Can't stat file descriptor\n");
            ret = CL_ESTAT;
            goto hwpml_end;
        }

        input = fmap_new(fd, 0, statbuf.st_size, NULL, (fd == df) ? tempfile : filepath);
        if (!input) {
            cli_errmsg("HWPML: Failed to get fmap for binary data\n");
            ret = CL_EMAP;
            goto hwpml_end;
        }
        ret = decompress_and_callback(ctx, input, 0, 0, "HWPML", hwpml_scan_cb, NULL);
        fmap_free(input);
    } else {
        if (fd == df) { /* fd is a decoded tempfile */
            ret = hwpml_scan_cb(NULL, fd, tempfile, ctx, decoded_reserved);
        } else { /* fd is the original filepath, no decoding necessary */
            ret = hwpml_scan_cb(NULL, fd, filepath, ctx, 0);
        }
    }

    /* close decoded file descriptor if used */
hwpml_end:
    if (decoded_reserved)
        cli_scan_release_temporary(ctx, decoded_reserved);
    if (df >= 0) {
        if (close(df) != 0) {
            cli_mark_scan_incomplete(ctx, "HWPML decoded temporary output could not be closed");
            if (ret == CL_SUCCESS || ret == CL_VERIFIED)
                ret = CL_EWRITE;
        }
        if (!(ctx->engine->keeptmp) && cli_unlink(tempfile)) {
            cli_mark_scan_incomplete(ctx, "HWPML decoded temporary output could not be removed");
            if (ret == CL_SUCCESS || ret == CL_VERIFIED)
                ret = CL_EUNLINK;
        }
        free(tempfile);
    }
    return ret;
}

cl_error_t cli_scanhwpml(cli_ctx *ctx)
{
    cl_error_t ret = CL_SUCCESS;

    struct msxml_ctx mxctx;

    cli_dbgmsg("in cli_scanhwpml()\n");

    if (!ctx)
        return CL_ENULLARG;

    if (!ctx->fmap) {
        cli_mark_scan_incomplete(ctx, "HWPML input map is unavailable");
        return CL_EPARSE;
    }
    if (!ctx->engine)
        return CL_ENULLARG;

    memset(&mxctx, 0, sizeof(mxctx));
    mxctx.scan_cb = hwpml_binary_cb;
    ret           = cli_msxml_parse_document_streaming(ctx, ctx->fmap, hwpml_keys, num_hwpml_keys,
                                                       MSXML_FLAG_JSON | MSXML_FLAG_FAIL_INCOMPLETE, &mxctx);

    /* HWPML attachment scanning cannot suppress XML errors: an incomplete
     * document may hide later embedded content. Preserve both callback
     * failures and native libxml2 parser errors as non-clean. */
    if (ret == CL_SUCCESS && ctx->scan_incomplete) {
        cli_mark_scan_incomplete(ctx, "HWPML XML parse ended before every embedded attachment was inspected");
        ret = CL_EPARSE;
    }

    if (ret != CL_SUCCESS && ret != CL_VIRUS && ret != CL_BREAK)
        cli_mark_scan_incomplete(ctx, "HWPML XML parse ended before every embedded attachment was inspected");

    return ret;
}
