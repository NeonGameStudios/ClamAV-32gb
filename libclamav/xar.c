/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2013 Sourcefire, Inc.
 *
 *  Authors: Steven Morgan <smorgan@sourcefire.com>
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

#include <errno.h>
#include "xar.h"
#include "fmap.h"

#include <libxml/xmlreader.h>
#include "clamav.h"
#include "str.h"
#include "scanners.h"
#include "inflate64.h"
#include "lzma_iface.h"

#define XAR_COPY_CHUNK_SIZE (64U * 1024U)

static size_t xar_readn(fmap_t *map, void *dst, size_t at, size_t len)
{
    /* fmap_readn() truncates requests that extend beyond the map, which can
     * otherwise make a short XAR header look like a backing-read failure.
     * Preflight the complete fixed range so only an in-range callback failure
     * is reported as CL_EREAD. */
    if (map == NULL || at > map->len || len > map->len - at)
        return 0;
    return fmap_readn(map, dst, at, len);
}

static cl_error_t xar_incomplete(cli_ctx *ctx, const char *reason)
{
    cli_mark_scan_incomplete(ctx, reason);
    return CL_EPARSE;
}

static cl_error_t xar_checktimelimit(cli_ctx *ctx, const char *reason)
{
    cl_error_t status = cli_checktimelimit(ctx);

    if (status != CL_SUCCESS)
        cli_mark_scan_incomplete(ctx, reason);

    return status;
}

/*
   xar_cleanup_temp_file - cleanup after cli_gentempfd
   parameters:
     ctx - cli_ctx context pointer
     fd  - fd to close
     tmpname - name of file to unlink, address of storage to free
     temporary_reserved - reserved output bytes to release, may be NULL
   returns - CL_SUCCESS or CL_EUNLINK
 */
static int xar_cleanup_temp_file(cli_ctx *ctx, int fd, char *tmpname, uint64_t *temporary_reserved)
{
    int rc = CL_SUCCESS;
    if (fd > -1 && close(fd) == -1) {
        cli_mark_scan_incomplete(ctx, "XAR temporary output could not be closed");
        rc = CL_EWRITE;
    }
    if (tmpname != NULL) {
        if (!ctx->engine->keeptmp) {
            if (cli_unlink(tmpname)) {
                cli_dbgmsg("cli_scanxar: error unlinking tmpfile %s\n", tmpname);
                cli_mark_scan_incomplete(ctx, "XAR temporary output could not be removed");
                if (CL_SUCCESS == rc)
                    rc = CL_EUNLINK;
            }
        }
        free(tmpname);
    }
    if (temporary_reserved && *temporary_reserved) {
        cli_scan_release_temporary(ctx, *temporary_reserved);
        *temporary_reserved = 0;
    }
    return rc;
}

static cl_error_t xar_reserve_output(cli_ctx *ctx, uint64_t *reserved, uint64_t bytes, const char *reason)
{
    cl_error_t status;

    if (bytes == 0)
        return CL_SUCCESS;
    if (NULL == reserved || UINT64_MAX - *reserved < bytes) {
        cli_mark_scan_incomplete(ctx, reason);
        return CL_ERESOURCE;
    }

    status = xar_checktimelimit(ctx, "XAR temporary output reached the configured time limit");
    if (status != CL_SUCCESS)
        return status;

    status = cli_scan_reserve_temporary(ctx, bytes);
    if (status != CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, reason);
        return status;
    }

    *reserved += bytes;
    return CL_SUCCESS;
}

static cl_error_t xar_write_output(cli_ctx *ctx, int fd, const void *data, size_t len,
                                   uint64_t *reserved, const char *reserve_reason,
                                   const char *deadline_reason, const char *failure_reason)
{
    cl_error_t status;

    status = xar_reserve_output(ctx, reserved, (uint64_t)len, reserve_reason);
    if (status != CL_SUCCESS)
        return status;

    status = xar_checktimelimit(ctx, deadline_reason);
    if (status != CL_SUCCESS) {
        if (reserved != NULL && *reserved >= (uint64_t)len) {
            cli_scan_release_temporary(ctx, (uint64_t)len);
            *reserved -= (uint64_t)len;
        }
        return status;
    }

    if (cli_writen(fd, data, len) != len) {
        if (reserved != NULL && *reserved >= (uint64_t)len) {
            cli_scan_release_temporary(ctx, (uint64_t)len);
            *reserved -= (uint64_t)len;
        }
        cli_mark_scan_incomplete(ctx, failure_reason);
        return CL_EWRITE;
    }

    return CL_SUCCESS;
}

static cl_error_t xar_bounded_xml_length(const xmlChar *data, size_t limit, size_t *length)
{
    size_t i;

    if (NULL == data || NULL == length)
        return CL_ENULLARG;

    for (i = 0; i < limit; i++) {
        if (data[i] == 0) {
            *length = i;
            return CL_SUCCESS;
        }
    }

    if (data[limit] == 0) {
        *length = limit;
        return CL_SUCCESS;
    }

    return CL_ERESOURCE;
}

static cl_error_t xar_spool_toc(cli_ctx *ctx, int fd, const unsigned char *data, size_t len,
                                uint64_t *reserved)
{
    return xar_write_output(ctx, fd, data, len, reserved,
                            "XAR TOC temporary spool could not be reserved",
                            "XAR TOC temporary spool write reached the configured time limit",
                            "XAR TOC temporary spool could not be written completely");
}

static int xar_toc_read(void *opaque, char *buffer, int len)
{
    int fd = *(int *)opaque;
    ssize_t got;

    if (len <= 0)
        return 0;

    do {
        got = read(fd, buffer, (size_t)len);
    } while (got < 0 && errno == EINTR);

    return got < 0 ? -1 : (int)got;
}

static int xar_toc_close(void *opaque)
{
    UNUSEDPARAM(opaque);
    return 0;
}

/*
   xar_get_numeric_from_xml_element - extract xml element value as numeric
   parameters:
     reader - xmlTextReaderPtr
   value - pointer to size_t to contain the returned value
   returns - CL_SUCCESS or CL_EFORMAT
 */
static int xar_get_numeric_from_xml_element(xmlTextReaderPtr reader, size_t *value)
{
    const xmlChar *numstr;

    if (xmlTextReaderRead(reader) == 1 && xmlTextReaderNodeType(reader) == XML_READER_TYPE_TEXT) {
        numstr = xmlTextReaderConstValue(reader);
        if (numstr) {
            unsigned long long numval;
            char *endptr = NULL;
            errno        = 0;
            numval       = strtoull((const char *)numstr, &endptr, 10);
            if (numstr[0] == '-' || errno == ERANGE || numval > SIZE_MAX ||
                ((const xmlChar *)endptr == numstr)) {

                cli_dbgmsg("cli_scanxar: XML element value invalid\n");
                return CL_EFORMAT;
            }
            *value = (size_t)numval;
            return CL_SUCCESS;
        }
    }
    cli_dbgmsg("cli_scanxar: No text for XML element\n");
    return CL_EFORMAT;
}

/*
  xar_get_checksum_values - extract checksum and hash algorithm from xml element
  parameters:
    reader - xmlTextReaderPtr
    cksum - pointer to char* for returning checksum value.
    hash - pointer to int for returning checksum algorithm.
  returns - void
 */
static void xar_get_checksum_values(xmlTextReaderPtr reader, unsigned char **cksum, int *hash)
{
    xmlChar *style = xmlTextReaderGetAttribute(reader, (const xmlChar *)"style");
    const xmlChar *xmlval;

    *hash = XAR_CKSUM_NONE;
    if (style == NULL) {
        cli_dbgmsg("cli_scaxar: xmlTextReaderGetAttribute no style attribute "
                   "for checksum element\n");
    } else {
        cli_dbgmsg("cli_scanxar: checksum algorithm is %s.\n", style);
        if (0 == xmlStrcasecmp(style, (const xmlChar *)"sha1")) {
            *hash = XAR_CKSUM_SHA1;
        } else if (0 == xmlStrcasecmp(style, (const xmlChar *)"md5")) {
            *hash = XAR_CKSUM_MD5;
        } else {
            cli_dbgmsg("cli_scanxar: checksum algorithm %s is unsupported.\n", style);
            *hash = XAR_CKSUM_OTHER;
        }
    }
    if (style != NULL)
        xmlFree(style);

    if (xmlTextReaderRead(reader) == 1 && xmlTextReaderNodeType(reader) == XML_READER_TYPE_TEXT) {
        xmlval = xmlTextReaderConstValue(reader);
        if (xmlval) {
            cli_dbgmsg("cli_scanxar: checksum value is %s.\n", xmlval);
            if (((*hash == XAR_CKSUM_SHA1) && (xmlStrlen(xmlval) == 2 * SHA1_HASH_SIZE)) ||
                ((*hash == XAR_CKSUM_MD5) && (xmlStrlen(xmlval) == 2 * MD5_HASH_SIZE))) {
                *cksum = xmlStrdup(xmlval);
            } else {
                cli_dbgmsg("cli_scanxar: checksum type is unknown or length is invalid.\n");
                *hash  = XAR_CKSUM_OTHER;
                *cksum = NULL;
            }
        } else {
            *cksum = NULL;
            cli_dbgmsg("cli_scanxar: xmlTextReaderConstValue() returns NULL for checksum value.\n");
        }
    } else
        cli_dbgmsg("cli_scanxar: No text for XML checksum element.\n");
}

/*
   xar_get_toc_data_values - return the values of a <data> or <ea> xml element that represent
                             an extent of data on the heap.
   parameters:
     reader - xmlTextReaderPtr
     length - pointer to long for returning value of the <length> element.
     offset - pointer to long for returning value of the <offset> element.
     size - pointer to long for returning value of the <size> element.
     encoding - pointer to int for returning indication of the <encoding> style attribute.
     a_cksum - pointer to char* for return archived checksum value.
     a_hash - pointer to int for returning archived checksum algorithm.
     e_cksum - pointer to char* for return extracted checksum value.
     e_hash - pointer to int for returning extracted checksum algorithm.
   returns - CL_FORMAT, CL_SUCCESS, CL_BREAK. CL_BREAK indicates no more <data>/<ea> element.
 */
static int xar_get_toc_data_values(xmlTextReaderPtr reader, cli_ctx *ctx, size_t *length, size_t *offset, size_t *size, int *encoding,
                                   unsigned char **a_cksum, int *a_hash, unsigned char **e_cksum, int *e_hash)
{
    const xmlChar *name;
    int indata = 0, inea = 0;
    int rc, gotoffset = 0, gotlength = 0, gotsize = 0;

    *a_cksum  = NULL;
    *a_hash   = XAR_CKSUM_NONE;
    *e_cksum  = NULL;
    *e_hash   = XAR_CKSUM_NONE;
    *encoding = CL_TYPE_ANY;

    rc = xar_checktimelimit(ctx, "XAR TOC data traversal reached the configured time limit");
    if (rc != CL_SUCCESS)
        return rc;

    rc = xmlTextReaderRead(reader);
    while (rc == 1) {
        rc = xar_checktimelimit(ctx, "XAR TOC data traversal reached the configured time limit");
        if (rc != CL_SUCCESS)
            return rc;

        name = xmlTextReaderConstLocalName(reader);
        if (indata || inea) {
            /*  cli_dbgmsg("cli_scanxar: xmlTextReaderRead read %s\n", name); */
            if (xmlStrEqual(name, (const xmlChar *)"offset") &&
                xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT) {
                if (CL_SUCCESS == xar_get_numeric_from_xml_element(reader, offset))
                    gotoffset = 1;

            } else if (xmlStrEqual(name, (const xmlChar *)"length") &&
                       xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT) {
                if (CL_SUCCESS == xar_get_numeric_from_xml_element(reader, length))
                    gotlength = 1;

            } else if (xmlStrEqual(name, (const xmlChar *)"size") &&
                       xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT) {
                if (CL_SUCCESS == xar_get_numeric_from_xml_element(reader, size))
                    gotsize = 1;

            } else if (xmlStrEqual(name, (const xmlChar *)"archived-checksum") &&
                       xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT) {
                cli_dbgmsg("cli_scanxar: <archived-checksum>:\n");
                xar_get_checksum_values(reader, a_cksum, a_hash);

            } else if ((xmlStrEqual(name, (const xmlChar *)"extracted-checksum") ||
                        xmlStrEqual(name, (const xmlChar *)"unarchived-checksum")) &&
                       xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT) {
                cli_dbgmsg("cli_scanxar: <extracted-checksum>:\n");
                xar_get_checksum_values(reader, e_cksum, e_hash);

            } else if (xmlStrEqual(name, (const xmlChar *)"encoding") &&
                       xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT) {
                xmlChar *style = xmlTextReaderGetAttribute(reader, (const xmlChar *)"style");
                if (style == NULL) {
                    cli_dbgmsg("cli_scaxar: xmlTextReaderGetAttribute no style attribute "
                               "for encoding element\n");
                    *encoding = CL_TYPE_ANY;
                } else if (xmlStrEqual(style, (const xmlChar *)"application/x-gzip")) {
                    cli_dbgmsg("cli_scanxar: encoding = application/x-gzip.\n");
                    *encoding = CL_TYPE_GZ;
                } else if (xmlStrEqual(style, (const xmlChar *)"application/octet-stream")) {
                    cli_dbgmsg("cli_scanxar: encoding = application/octet-stream.\n");
                    *encoding = CL_TYPE_ANY;
                } else if (xmlStrEqual(style, (const xmlChar *)"application/x-bzip2")) {
                    cli_dbgmsg("cli_scanxar: encoding = application/x-bzip2.\n");
                    *encoding = CL_TYPE_BZ;
                } else if (xmlStrEqual(style, (const xmlChar *)"application/x-lzma")) {
                    cli_dbgmsg("cli_scanxar: encoding = application/x-lzma.\n");
                    *encoding = CL_TYPE_7Z;
                } else if (xmlStrEqual(style, (const xmlChar *)"application/x-xz")) {
                    cli_dbgmsg("cli_scanxar: encoding = application/x-xz.\n");
                    *encoding = CL_TYPE_XZ;
                } else {
                    cli_dbgmsg("cli_scaxar: unknown style value=%s for encoding element\n", style);
                    *encoding = CL_TYPE_ANY;
                }
                if (style != NULL)
                    xmlFree(style);

            } else if (indata && xmlStrEqual(name, (const xmlChar *)"data") &&
                       xmlTextReaderNodeType(reader) == XML_READER_TYPE_END_ELEMENT) {
                break;

            } else if (inea && xmlStrEqual(name, (const xmlChar *)"ea") &&
                       xmlTextReaderNodeType(reader) == XML_READER_TYPE_END_ELEMENT) {
                break;
            }

        } else {
            if (xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT) {
                if (xmlStrEqual(name, (const xmlChar *)"data")) {
                    cli_dbgmsg("cli_scanxar: xmlTextReaderRead read <data>\n");
                    indata = 1;
                } else if (xmlStrEqual(name, (const xmlChar *)"ea")) {
                    cli_dbgmsg("cli_scanxar: xmlTextReaderRead read <ea>\n");
                    inea = 1;
                }
            } else if ((xmlTextReaderNodeType(reader) == XML_READER_TYPE_END_ELEMENT) &&
                       xmlStrEqual(name, (const xmlChar *)"xar")) {
                cli_dbgmsg("cli_scanxar: finished parsing xar TOC.\n");
                break;
            }
        }
        rc = xmlTextReaderRead(reader);
    }

    if (rc < 0) {
        cli_dbgmsg("cli_scanxar: XML reader failed while reading TOC data values.\n");
        return CL_EFORMAT;
    }

    if (gotoffset && gotlength && gotsize) {
        rc = CL_SUCCESS;
    } else if (!indata && !inea && 0 == gotoffset + gotlength + gotsize)
        rc = CL_BREAK;
    else
        rc = CL_EFORMAT;

    return rc;
}

/*
  xar_process_subdocument - check TOC for xml subdocument. If found, extract and
                            scan in memory.
  Parameters:
     reader - xmlTextReaderPtr
     ctx - pointer to cli_ctx
  Returns:
     CL_SUCCESS - subdoc found and clean scan (or virus found and SCAN_ALLMATCHES), or no subdocument
     other - error return code from cli_magic_scan_buff()
*/
static int xar_scan_subdocuments(xmlTextReaderPtr reader, cli_ctx *ctx)
{
    int rc = CL_SUCCESS, fd;
    int cleanup_rc;
    int temp_rc;
    int reader_status;
    cl_error_t time_status;
    size_t subdoc_len;
    uint64_t subdoc_reserved;
    xmlChar *subdoc;
    const xmlChar *name;
    char *tmpname;

    while (1) {
        time_status = xar_checktimelimit(ctx, "XAR subdocument traversal reached the configured time limit");
        if (time_status != CL_SUCCESS) {
            rc = time_status;
            break;
        }
        reader_status = xmlTextReaderRead(reader);
        if (reader_status != 1)
            break;

        name = xmlTextReaderConstLocalName(reader);
        if (name == NULL) {
            cli_dbgmsg("cli_scanxar: xmlTextReaderConstLocalName() no name.\n");
            rc = CL_EFORMAT;
            break;
        }
        if (xmlStrEqual(name, (const xmlChar *)"toc") &&
            xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT)
            return CL_SUCCESS;
        if (xmlStrEqual(name, (const xmlChar *)"subdoc") &&
            xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT) {
            subdoc = xmlTextReaderReadInnerXml(reader);
            if (subdoc == NULL) {
                cli_dbgmsg("cli_scanxar: no content in subdoc element.\n");
                xmlTextReaderNext(reader);
                continue;
            }

            /* xmlTextReaderReadInnerXml() necessarily materializes this one
             * XML fragment, but the old path then scanned that allocation
             * directly and used an int length. Bound the legacy API, account
             * the handoff against temporary storage, and keep the nested scan
             * on the reservation-aware descriptor path. */
            if (xar_bounded_xml_length(subdoc, CLI_MAX_ALLOCATION, &subdoc_len) != CL_SUCCESS) {
                cli_mark_scan_incomplete(ctx, "XAR subdocument exceeds the bounded allocation limit");
                xmlFree(subdoc);
                return CL_ERESOURCE;
            }
            cli_dbgmsg("cli_scanxar: staged XML subdocument, len %zu.\n", subdoc_len);

            subdoc_reserved = 0;
            fd      = -1;
            tmpname = NULL;
            temp_rc = cli_gentempfd(ctx->this_layer_tmpdir, &tmpname, &fd);
            if (temp_rc != CL_SUCCESS) {
                cli_dbgmsg("cli_scanxar: Can't create temporary file for subdocument.\n");
                cli_mark_scan_incomplete(ctx, "XAR subdocument temporary output could not be created");
                rc = temp_rc;
                goto subdocument_cleanup;
            }

            rc = xar_write_output(ctx, fd, subdoc, subdoc_len, &subdoc_reserved,
                                  "XAR subdocument temporary output exceeds storage limits",
                                  "XAR subdocument temporary output write reached the configured time limit",
                                  "XAR subdocument temporary output could not be written completely");
            if (rc != CL_SUCCESS) {
                cli_dbgmsg("cli_scanxar: cli_writen error writing subdoc temporary file.\n");
                goto subdocument_cleanup;
            }

            if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
                cli_mark_scan_incomplete(ctx, "XAR subdocument temporary output could not be rewound");
                rc = CL_ESEEK;
                goto subdocument_cleanup;
            }

            rc = cli_magic_scan_desc_type_reserved(fd, tmpname, ctx, CL_TYPE_ANY, NULL,
                                                   LAYER_ATTRIBUTES_NONE);

        subdocument_cleanup:
            cleanup_rc = xar_cleanup_temp_file(ctx, fd, tmpname, &subdoc_reserved);
            fd          = -1;
            tmpname     = NULL;
            if (CL_SUCCESS == rc && CL_SUCCESS != cleanup_rc)
                rc = cleanup_rc;

            xmlFree(subdoc);
            if (rc != CL_SUCCESS)
                return rc;
            xmlTextReaderNext(reader);
        }
    }

    if (rc == CL_ETIMEOUT)
        return rc;
    if (reader_status < 0)
        return xar_incomplete(ctx, "XAR TOC XML reader failed before file entries were inspected");

    return rc;
}

static void *xar_hash_init(int hash, void **sc, void **mc)
{
    if (!sc && !mc)
        return NULL;
    switch (hash) {
        case XAR_CKSUM_SHA1:
            *sc = cl_hash_init("sha1");
            if (!(*sc)) {
                return NULL;
            }

            return *sc;
        case XAR_CKSUM_MD5:
            *mc = cl_hash_init("md5");
            if (!(*mc)) {
                return NULL;
            }

            return *mc;
        case XAR_CKSUM_OTHER:
        case XAR_CKSUM_NONE:
        default:
            return NULL;
    }
}

static void xar_hash_update(void *hash_ctx, void *data, unsigned long size, int hash)
{
    if (!hash_ctx || !data || !size)
        return;

    switch (hash) {
        case XAR_CKSUM_NONE:
        case XAR_CKSUM_OTHER:
            return;
    }

    cl_update_hash(hash_ctx, data, size);
}

static void xar_hash_final(void *hash_ctx, void *result, int hash)
{
    if (!hash_ctx || !result)
        return;

    switch (hash) {
        case XAR_CKSUM_OTHER:
        case XAR_CKSUM_NONE:
            return;
    }

    cl_finish_hash(hash_ctx, result);
}

static int xar_hash_check(int hash, const void *result, const void *expected)
{
    int len;

    if (!result || !expected)
        return 1;
    switch (hash) {
        case XAR_CKSUM_SHA1:
            len = SHA1_HASH_SIZE;
            break;
        case XAR_CKSUM_MD5:
            len = MD5_HASH_SIZE;
            break;
        case XAR_CKSUM_OTHER:
        case XAR_CKSUM_NONE:
        default:
            return 1;
    }
    return memcmp(result, expected, len);
}

/*
  cli_scanxar - scan an xar archive.
  Parameters:
    ctx - pointer to cli_ctx.
  returns - CL_SUCCESS or CL_ error code.
*/

int cli_scanxar(cli_ctx *ctx)
{
    int rc                      = CL_SUCCESS;
    unsigned int cksum_fails    = 0;
    unsigned int extract_errors = 0;

    int fd = -1;
    struct xar_header hdr;
    fmap_t *map = ctx->fmap;
    size_t length, offset, size, at, heap_start, data_end;
    int encoding;
    z_stream strm;
    char *tmpname = NULL, *tocname = NULL;
    xmlTextReaderPtr reader = NULL;
    int toc_fd              = -1;
    int cleanup_rc;
    uint64_t toc_reserved = 0;
    uint64_t member_reserved = 0;
    int a_hash, e_hash;
    unsigned char *a_cksum = NULL, *e_cksum = NULL;
    void *a_hash_ctx = NULL, *e_hash_ctx = NULL;
    char e_hash_result[SHA1_HASH_SIZE];
    char a_hash_result[SHA1_HASH_SIZE];

    memset(&strm, 0x00, sizeof(z_stream));

    rc = xar_checktimelimit(ctx, "XAR inspection reached the configured time limit");
    if (rc != CL_SUCCESS)
        return rc;

    /* retrieve xar header */
    {
        size_t header_read = xar_readn(ctx->fmap, &hdr, 0, sizeof(hdr));

        if (header_read != sizeof(hdr)) {
            cli_dbgmsg("cli_scanxar: Invalid header, too short.\n");
            if (header_read == (size_t)-1) {
                cli_mark_scan_incomplete(ctx, "XAR header could not be read completely");
                return CL_EREAD;
            }
            return xar_incomplete(ctx, "XAR header is incomplete");
        }
    }
    hdr.magic = be32_to_host(hdr.magic);

    if (hdr.magic == XAR_HEADER_MAGIC) {
        cli_dbgmsg("cli_scanxar: Matched magic\n");
    } else {
        cli_dbgmsg("cli_scanxar: Invalid magic\n");
        return xar_incomplete(ctx, "XAR header has invalid magic");
    }
    hdr.size                    = be16_to_host(hdr.size);
    hdr.version                 = be16_to_host(hdr.version);
    hdr.toc_length_compressed   = be64_to_host(hdr.toc_length_compressed);
    hdr.toc_length_decompressed = be64_to_host(hdr.toc_length_decompressed);
    hdr.chksum_alg              = be32_to_host(hdr.chksum_alg);

    if (hdr.toc_length_compressed > SIZE_MAX || hdr.toc_length_decompressed > SIZE_MAX ||
        hdr.size > map->len || hdr.toc_length_compressed > map->len - hdr.size) {
        cli_dbgmsg("cli_scanxar: TOC dimensions exceed the native/parser range or the input map\n");
        return xar_incomplete(ctx, "XAR TOC dimensions are invalid or outside the input map");
    }
    rc = cli_checklimits("XAR TOC", ctx, hdr.toc_length_decompressed, hdr.toc_length_compressed, 0);
    if (rc != CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, "XAR TOC exceeds configured scan limits");
        return rc;
    }

    /* cli_dbgmsg("hdr.magic %x\n", hdr.magic); */
    /* cli_dbgmsg("hdr.size %i\n", hdr.size); */
    /* cli_dbgmsg("hdr.version %i\n", hdr.version); */
    /* cli_dbgmsg("hdr.toc_length_compressed %lu\n", hdr.toc_length_compressed); */
    /* cli_dbgmsg("hdr.toc_length_decompressed %lu\n", hdr.toc_length_decompressed); */
    /* cli_dbgmsg("hdr.chksum_alg %i\n", hdr.chksum_alg); */

    /* Stream the compressed TOC through zlib into a quota-accounted temporary
     * file. The old path mapped the complete compressed TOC and allocated the
     * complete decompressed XML document, imposing an unrelated 64 MiB cap. */
    if ((rc = cli_gentempfd(ctx->this_layer_tmpdir, &tocname, &toc_fd)) != CL_SUCCESS) {
        cli_dbgmsg("cli_scanxar: Can't create temporary file for TOC.\n");
        cli_mark_scan_incomplete(ctx, "XAR TOC temporary output could not be created");
        goto exit_toc;
    }

    {
        unsigned char inbuf[XAR_COPY_CHUNK_SIZE];
        unsigned char outbuf[XAR_COPY_CHUNK_SIZE];
        uint64_t compressed_read      = 0;
        uint64_t decompressed_written = 0;
        bool stream_complete          = false;

        rc = inflateInit(&strm);
        if (rc != Z_OK) {
            cli_dbgmsg("cli_scanxar: inflateInit error %i\n", rc);
            cli_mark_scan_incomplete(ctx, "XAR TOC decoder could not be initialized");
            rc = CL_EFORMAT;
            goto exit_toc;
        }

        while (compressed_read < hdr.toc_length_compressed && !stream_complete) {
            size_t chunk         = MIN(sizeof(inbuf), (size_t)(hdr.toc_length_compressed - compressed_read));
            size_t source_offset = hdr.size + (size_t)compressed_read;

            rc = xar_checktimelimit(ctx, "XAR TOC decoder traversal reached the configured time limit");
            if (rc != CL_SUCCESS) {
                inflateEnd(&strm);
                goto exit_toc;
            }

            if (fmap_readn(ctx->fmap, inbuf, source_offset, chunk) != chunk) {
                cli_dbgmsg("cli_scanxar: could not read the complete compressed TOC chunk\n");
                cli_mark_scan_incomplete(ctx, "XAR TOC could not be read completely");
                rc = CL_EREAD;
                inflateEnd(&strm);
                goto exit_toc;
            }

            compressed_read += chunk;
            strm.next_in  = inbuf;
            strm.avail_in = (uInt)chunk;

            do {
                int inflate_rc;
                size_t produced;

                rc = xar_checktimelimit(ctx, "XAR TOC decoder traversal reached the configured time limit");
                if (rc != CL_SUCCESS) {
                    inflateEnd(&strm);
                    goto exit_toc;
                }

                strm.next_out  = outbuf;
                strm.avail_out = sizeof(outbuf);
                inflate_rc     = inflate(&strm, compressed_read == hdr.toc_length_compressed ? Z_FINISH : Z_NO_FLUSH);
                produced       = sizeof(outbuf) - strm.avail_out;

                if (produced > hdr.toc_length_decompressed - decompressed_written) {
                    cli_mark_scan_incomplete(ctx, "XAR TOC decompressed output exceeded its declared length");
                    rc = CL_EFORMAT;
                    inflateEnd(&strm);
                    goto exit_toc;
                }

                rc = xar_spool_toc(ctx, toc_fd, outbuf, produced, &toc_reserved);
                if (rc != CL_SUCCESS) {
                    inflateEnd(&strm);
                    goto exit_toc;
                }
                decompressed_written += produced;

                if (inflate_rc == Z_STREAM_END) {
                    stream_complete = true;
                    if (strm.avail_in != 0 || compressed_read != hdr.toc_length_compressed) {
                        cli_mark_scan_incomplete(ctx, "XAR TOC compressed range contains trailing data");
                        rc = CL_EFORMAT;
                        inflateEnd(&strm);
                        goto exit_toc;
                    }
                    break;
                }
                if (inflate_rc != Z_OK && inflate_rc != Z_BUF_ERROR) {
                    cli_dbgmsg("cli_scanxar: TOC decoder did not reach stream end: %i\n", inflate_rc);
                    cli_mark_scan_incomplete(ctx, "XAR TOC decompression was incomplete");
                    rc = CL_EFORMAT;
                    inflateEnd(&strm);
                    goto exit_toc;
                }
                if (inflate_rc == Z_BUF_ERROR && strm.avail_in == 0 && produced == 0) {
                    cli_mark_scan_incomplete(ctx, "XAR TOC decoder made no progress");
                    rc = CL_EFORMAT;
                    inflateEnd(&strm);
                    goto exit_toc;
                }
            } while (strm.avail_in != 0 || strm.avail_out == 0);
        }

        if (!stream_complete || decompressed_written != hdr.toc_length_decompressed) {
            cli_mark_scan_incomplete(ctx, "XAR TOC decompressed length disagrees with its header");
            rc = CL_EFORMAT;
            inflateEnd(&strm);
            goto exit_toc;
        }

        if (inflateEnd(&strm) != Z_OK) {
            cli_mark_scan_incomplete(ctx, "XAR TOC decoder could not be finalized");
            rc = CL_EFORMAT;
            goto exit_toc;
        }
    }

    /* Scan the completed TOC as a child, then parse it through libxml2's
     * streaming file-descriptor reader. Avoid charging the same TOC bytes as
     * both materialization and descriptor scan. */
    if (lseek(toc_fd, 0, SEEK_SET) == (off_t)-1) {
        cli_mark_scan_incomplete(ctx, "XAR TOC temporary spool could not be rewound");
        rc = CL_ESEEK;
        goto exit_toc;
    }
    rc = cli_magic_scan_desc_type_reserved(toc_fd, tocname, ctx, CL_TYPE_ANY, NULL, LAYER_ATTRIBUTES_NONE);
    if (rc != CL_SUCCESS)
        goto exit_toc;
    if (lseek(toc_fd, 0, SEEK_SET) == (off_t)-1) {
        cli_mark_scan_incomplete(ctx, "XAR TOC temporary spool could not be rewound for XML parsing");
        rc = CL_ESEEK;
        goto exit_toc;
    }

    reader = xmlReaderForIO(xar_toc_read, xar_toc_close, &toc_fd, "xar-toc.xml", NULL, CLAMAV_MIN_XMLREADER_FLAGS);
    if (reader == NULL) {
        cli_dbgmsg("cli_scanxar: xmlReaderForIO error for TOC\n");
        rc = xar_incomplete(ctx, "XAR TOC XML parser could not be initialized");
        goto exit_toc;
    }

    rc = xar_scan_subdocuments(reader, ctx);
    if (rc != CL_SUCCESS) {
        cli_dbgmsg("xar_scan_subdocuments returns %i.\n", rc);
        goto exit_reader;
    }

    /* Walk the TOC XML and extract files */
    fd      = -1;
    tmpname = NULL;
    while (CL_SUCCESS == (rc = xar_get_toc_data_values(reader, ctx, &length, &offset, &size, &encoding,
                                                       &a_cksum, &a_hash, &e_cksum, &e_hash))) {
        int do_extract_cksum = 1;
        unsigned char *blockp;
        void *a_sc, *e_sc;
        void *a_mc, *e_mc;
        char *expected;

        /* clean up temp file from previous loop iteration */
        if (fd > -1 && tmpname) {
            rc      = xar_cleanup_temp_file(ctx, fd, tmpname, &member_reserved);
            tmpname = NULL;
            if (rc != CL_SUCCESS)
                goto exit_reader;
        }

        {
            heap_start = hdr.size + (size_t)hdr.toc_length_compressed;
            if (offset > map->len - heap_start || length > map->len - heap_start - offset) {
                cli_dbgmsg("cli_scanxar: heap extent exceeds the input map\n");
                rc = CL_EFORMAT;
                goto exit_reader;
            }

            at       = heap_start + offset;
            data_end = at + length;
        }

        rc = cli_checklimits("XAR member", ctx, size, length, 0);
        if (rc != CL_SUCCESS) {
            cli_mark_scan_incomplete(ctx, "XAR member exceeds configured scan limits");
            goto exit_reader;
        }

        if ((rc = cli_gentempfd(ctx->this_layer_tmpdir, &tmpname, &fd)) != CL_SUCCESS) {
            cli_dbgmsg("cli_scanxar: Can't generate temporary file.\n");
            cli_mark_scan_incomplete(ctx, "XAR member temporary output could not be created");
            goto exit_reader;
        }

        cli_dbgmsg("cli_scanxar: decompress into temp file:\n%s, size %zu,\n"
                   "from xar heap offset %zu length %zu\n",
                   tmpname, size, offset, length);

        a_hash_ctx = xar_hash_init(a_hash, &a_sc, &a_mc);
        e_hash_ctx = xar_hash_init(e_hash, &e_sc, &e_mc);

        switch (encoding) {
            case CL_TYPE_GZ: {
                uint64_t total_out   = 0;
                bool stream_complete = false;
                /* inflate gzip directly because file segments do not contain magic */
                memset(&strm, 0, sizeof(strm));
                if ((rc = inflateInit(&strm)) != Z_OK) {
                    cli_dbgmsg("cli_scanxar: InflateInit failed: %d\n", rc);
                    rc = CL_EFORMAT;
                    extract_errors++;
                    break;
                }

                while (at < map->len && at < data_end) {
                    unsigned long avail_in;
                    void *next_in;
                    unsigned int bytes = MIN(data_end - at, map->pgsz);

                    rc = xar_checktimelimit(ctx, "XAR gzip decoder traversal reached the configured time limit");
                    if (rc != CL_SUCCESS) {
                        inflateEnd(&strm);
                        goto exit_tmpfile;
                    }

                    if (!(strm.next_in = next_in = (void *)fmap_need_off_once(map, at, bytes))) {
                        cli_dbgmsg("cli_scanxar: Can't read %u bytes @ %lu.\n", bytes, (long unsigned)at);
                        inflateEnd(&strm);
                        rc = CL_EREAD;
                        goto exit_tmpfile;
                    }
                    at += bytes;
                    strm.avail_in = avail_in = bytes;
                    do {
                        int inf;
                        size_t produced;
                        cl_error_t limit_status;
                        unsigned char buff[FILEBUFF];

                        rc = xar_checktimelimit(ctx, "XAR gzip decoder traversal reached the configured time limit");
                        if (rc != CL_SUCCESS)
                            break;

                        strm.avail_out = sizeof(buff);
                        strm.next_out  = buff;
                        inf            = inflate(&strm, Z_SYNC_FLUSH);
                        if (inf != Z_OK && inf != Z_STREAM_END && inf != Z_BUF_ERROR) {
                            cli_dbgmsg("cli_scanxar: inflate error %i %s.\n", inf, strm.msg ? strm.msg : "");
                            rc = CL_EFORMAT;
                            extract_errors++;
                            break;
                        }

                        produced = sizeof(buff) - strm.avail_out;

                        if (produced > UINT64_MAX - total_out) {
                            cli_mark_scan_incomplete(ctx, "XAR gzip output size overflowed");
                            rc = CL_EFORMAT;
                            break;
                        }
                        total_out += produced;
                        limit_status = cli_checklimits("cli_scanxar", ctx, total_out, 0, 0);
                        if (limit_status != CL_SUCCESS) {
                            cli_mark_scan_incomplete(ctx, "XAR gzip member exceeds configured scan limits");
                            rc = limit_status;
                            break;
                        }

                        if (e_hash_ctx != NULL)
                            xar_hash_update(e_hash_ctx, buff, produced, e_hash);

                        if ((rc = xar_write_output(ctx, fd, buff, produced, &member_reserved,
                                                   "XAR gzip member exceeds temporary storage limits",
                                                   "XAR gzip member output reached the configured time limit",
                                                   "XAR gzip member could not be written completely")) != CL_SUCCESS) {
                            cli_dbgmsg("cli_scanxar: cli_writen error file %s.\n", tmpname);
                            inflateEnd(&strm);
                            goto exit_tmpfile;
                        }
                        if (inf == Z_STREAM_END) {
                            stream_complete = true;
                            break;
                        }
                    } while (strm.avail_out == 0);

                    avail_in -= strm.avail_in;
                    if (a_hash_ctx != NULL)
                        xar_hash_update(a_hash_ctx, next_in, avail_in, a_hash);

                    if (rc != CL_SUCCESS)
                        break;
                    if (stream_complete) {
                        if (strm.avail_in != 0 || at < data_end) {
                            cli_mark_scan_incomplete(ctx, "XAR gzip stream ended before its declared compressed range");
                            rc = CL_EFORMAT;
                        }
                        break;
                    }
                    if (strm.avail_in != 0) {
                        cli_mark_scan_incomplete(ctx, "XAR gzip decoder stopped before consuming its input chunk");
                        rc = CL_EFORMAT;
                        break;
                    }
                }

                inflateEnd(&strm);
                if (rc == CL_SUCCESS && !stream_complete) {
                    cli_mark_scan_incomplete(ctx, "XAR gzip member ended before the decoder reached stream end");
                    rc = CL_EFORMAT;
                }
                if (rc != CL_SUCCESS)
                    goto exit_tmpfile;
                break;
            }
            case CL_TYPE_7Z:
#define CLI_LZMA_OBUF_SIZE 1024 * 1024
#define CLI_LZMA_HDR_SIZE LZMA_PROPS_SIZE + 8
#define CLI_LZMA_IBUF_SIZE CLI_LZMA_OBUF_SIZE >> 2 /* estimated compression ratio 25% */
            {
                struct CLI_LZMA lz;
                size_t in_remaining = MIN(length, map->len - at);
                uint64_t out_size   = 0;
                unsigned char *buff = __lzma_wrap_alloc(NULL, CLI_LZMA_OBUF_SIZE);
                int lret;
                bool stream_complete = false;

                if (length > in_remaining)
                    length = in_remaining;

                memset(&lz, 0, sizeof(lz));
                if (buff == NULL) {
                    cli_dbgmsg("cli_scanxar: memory request for lzma decompression buffer fails.\n");
                    rc = CL_EMEM;
                    goto exit_tmpfile;
                }

                if (data_end - at < CLI_LZMA_HDR_SIZE) {
                    cli_dbgmsg("cli_scanxar: LZMA extent is shorter than its header\n");
                    rc = CL_EFORMAT;
                    __lzma_wrap_free(NULL, buff);
                    goto exit_tmpfile;
                }

                blockp = (void *)fmap_need_off_once(map, at, CLI_LZMA_HDR_SIZE);
                if (blockp == NULL) {
                    char errbuff[128];
                    cli_strerror(errno, errbuff, sizeof(errbuff));
                    cli_dbgmsg("cli_scanxar: Can't read %i bytes @ %zu, errno:%s.\n",
                               CLI_LZMA_HDR_SIZE, at, errbuff);
                    rc = CL_EREAD;
                    __lzma_wrap_free(NULL, buff);
                    goto exit_tmpfile;
                }

                lz.next_in  = blockp;
                lz.avail_in = CLI_LZMA_HDR_SIZE;

                if (a_hash_ctx != NULL)
                    xar_hash_update(a_hash_ctx, blockp, CLI_LZMA_HDR_SIZE, a_hash);

                lret = cli_LzmaInit(&lz, 0);
                if (lret != LZMA_RESULT_OK) {
                    cli_dbgmsg("cli_scanxar: cli_LzmaInit() fails: %i.\n", lret);
                    rc = CL_EFORMAT;
                    __lzma_wrap_free(NULL, buff);
                    extract_errors++;
                    break;
                }

                at += CLI_LZMA_HDR_SIZE;
                in_remaining -= CLI_LZMA_HDR_SIZE;
                while (at < map->len && at < data_end) {
                    SizeT avail_in;
                    SizeT avail_out;
                    void *next_in;
                    unsigned long in_consumed;

                    rc = xar_checktimelimit(ctx, "XAR LZMA decoder traversal reached the configured time limit");
                    if (rc != CL_SUCCESS) {
                        cli_LzmaShutdown(&lz);
                        __lzma_wrap_free(NULL, buff);
                        goto exit_tmpfile;
                    }

                    lz.next_out  = buff;
                    lz.avail_out = CLI_LZMA_OBUF_SIZE;
                    lz.avail_in = avail_in = MIN(CLI_LZMA_IBUF_SIZE, in_remaining);
                    lz.next_in = next_in = (void *)fmap_need_off_once(map, at, lz.avail_in);
                    if (lz.next_in == NULL) {
                        char errbuff[128];
                        cli_strerror(errno, errbuff, sizeof(errbuff));
                        cli_dbgmsg("cli_scanxar: Can't read %zu bytes @ %zu, errno: %s.\n",
                                   lz.avail_in, at, errbuff);
                        rc = CL_EREAD;
                        __lzma_wrap_free(NULL, buff);
                        cli_LzmaShutdown(&lz);
                        goto exit_tmpfile;
                    }

                    lret = cli_LzmaDecode(&lz);
                    if (lret != LZMA_RESULT_OK && lret != LZMA_STREAM_END) {
                        cli_dbgmsg("cli_scanxar: cli_LzmaDecode() fails: %i.\n", lret);
                        rc = CL_EFORMAT;
                        extract_errors++;
                        break;
                    }

                    in_consumed = avail_in - lz.avail_in;
                    in_remaining -= in_consumed;
                    at += in_consumed;
                    avail_out = CLI_LZMA_OBUF_SIZE - lz.avail_out;

                    if (avail_out == 0)
                        cli_dbgmsg("cli_scanxar: cli_LzmaDecode() produces no output for "
                                   "avail_in %llu, avail_out %llu.\n",
                                   (long long unsigned)avail_in, (long long unsigned)avail_out);

                    if (a_hash_ctx != NULL)
                        xar_hash_update(a_hash_ctx, next_in, in_consumed, a_hash);
                    if (e_hash_ctx != NULL)
                        xar_hash_update(e_hash_ctx, buff, avail_out, e_hash);

                    if (in_consumed == 0 && avail_out == 0 && lret != LZMA_STREAM_END) {
                        cli_mark_scan_incomplete(ctx, "XAR LZMA decoder made no progress");
                        rc = CL_EFORMAT;
                        break;
                    }

                    if (avail_out > UINT64_MAX - out_size) {
                        cli_mark_scan_incomplete(ctx, "XAR LZMA output size overflowed");
                        rc = CL_EFORMAT;
                        break;
                    }
                    out_size += avail_out;
                    rc = cli_checklimits("cli_scanxar", ctx, out_size, 0, 0);
                    if (rc != CL_SUCCESS) {
                        cli_mark_scan_incomplete(ctx, "XAR LZMA member exceeds configured scan limits");
                        break;
                    }

                    /* Write a decompressed block. */
                    /* cli_dbgmsg("Writing %li bytes to LZMA decompress temp file, " */
                    /*            "consumed %li of %li available compressed bytes.\n", */
                    /*            avail_out, in_consumed, avail_in); */

                    if ((rc = xar_write_output(ctx, fd, buff, avail_out, &member_reserved,
                                               "XAR LZMA member exceeds temporary storage limits",
                                               "XAR LZMA member output reached the configured time limit",
                                               "XAR LZMA member could not be written completely")) != CL_SUCCESS) {
                        cli_dbgmsg("cli_scanxar: cli_writen error writing lzma temp file for %llu bytes.\n",
                                   (long long unsigned)avail_out);
                        __lzma_wrap_free(NULL, buff);
                        cli_LzmaShutdown(&lz);
                        goto exit_tmpfile;
                    }

                    if (lret == LZMA_STREAM_END) {
                        stream_complete = true;
                        break;
                    }
                }

                cli_LzmaShutdown(&lz);
                __lzma_wrap_free(NULL, buff);
                if (rc == CL_SUCCESS && !stream_complete) {
                    cli_mark_scan_incomplete(ctx, "XAR LZMA member ended before the decoder reached stream end");
                    rc = CL_EFORMAT;
                }
                if (rc != CL_SUCCESS)
                    goto exit_tmpfile;
            } break;
            case CL_TYPE_ANY:
            default:
            case CL_TYPE_BZ:
            case CL_TYPE_XZ:
                /* for uncompressed, bzip2, xz, and unknown, just pull the file, cli_magic_scan_desc does the rest */
                do_extract_cksum = 0;
                {
                    unsigned char copy_buffer[XAR_COPY_CHUNK_SIZE];
                    size_t copied = 0;

                    while (copied < length) {
                        size_t writelen = MIN(sizeof(copy_buffer), length - copied);

                        rc = xar_checktimelimit(ctx, "XAR member traversal reached the configured time limit");
                        if (rc != CL_SUCCESS)
                            goto exit_tmpfile;

                        if (fmap_readn(map, copy_buffer, at + copied, writelen) != writelen) {
                            cli_mark_scan_incomplete(ctx, "XAR member could not be read completely");
                            rc = CL_EREAD;
                            goto exit_tmpfile;
                        }
                        if (a_hash_ctx != NULL)
                            xar_hash_update(a_hash_ctx, copy_buffer, writelen, a_hash);
                        if ((rc = xar_write_output(ctx, fd, copy_buffer, writelen, &member_reserved,
                                                   "XAR member exceeds temporary storage limits",
                                                   "XAR member output reached the configured time limit",
                                                   "XAR member could not be written completely")) != CL_SUCCESS) {
                            cli_dbgmsg("cli_scanxar: cli_writen error %zu bytes @ %zu.\n", writelen, at + copied);
                            goto exit_tmpfile;
                        }
                        copied += writelen;
                    }
                    /*break;*/
                }
        } /* end of switch */

        if (a_hash_ctx != NULL) {
            xar_hash_final(a_hash_ctx, a_hash_result, a_hash);
            a_hash_ctx = NULL;
        } else if (rc == CL_SUCCESS) {
            cli_dbgmsg("cli_scanxar: archived-checksum missing.\n");
            cksum_fails++;
        }
        if (e_hash_ctx != NULL) {
            xar_hash_final(e_hash_ctx, e_hash_result, e_hash);
            e_hash_ctx = NULL;
        } else if (rc == CL_SUCCESS) {
            cli_dbgmsg("cli_scanxar: extracted-checksum(unarchived-checksum) missing.\n");
            cksum_fails++;
        }

        if (rc == CL_SUCCESS) {
            if (a_cksum != NULL) {
                expected = cli_hex2str((char *)a_cksum);
                if (xar_hash_check(a_hash, a_hash_result, expected) != 0) {
                    cli_dbgmsg("cli_scanxar: archived-checksum mismatch.\n");
                    cksum_fails++;
                } else {
                    cli_dbgmsg("cli_scanxar: archived-checksum matched.\n");
                }
                free(expected);
            }

            if (e_cksum != NULL) {
                if (do_extract_cksum) {
                    expected = cli_hex2str((char *)e_cksum);
                    if (xar_hash_check(e_hash, e_hash_result, expected) != 0) {
                        cli_dbgmsg("cli_scanxar: extracted-checksum mismatch.\n");
                        cksum_fails++;
                    } else {
                        cli_dbgmsg("cli_scanxar: extracted-checksum matched.\n");
                    }
                    free(expected);
                }
            }

            rc = cli_magic_scan_desc_type_reserved(fd, tmpname, ctx, CL_TYPE_ANY, NULL, LAYER_ATTRIBUTES_NONE); /// TODO: collect file names in xar_get_toc_data_values()
            if (rc != CL_SUCCESS) {
                goto exit_tmpfile;
            }
        }

        if (a_cksum != NULL) {
            xmlFree(a_cksum);
            a_cksum = NULL;
        }
        if (e_cksum != NULL) {
            xmlFree(e_cksum);
            e_cksum = NULL;
        }
    }

exit_tmpfile:
    cleanup_rc = xar_cleanup_temp_file(ctx, fd, tmpname, &member_reserved);
    if ((CL_SUCCESS == rc || CL_VERIFIED == rc) && CL_SUCCESS != cleanup_rc)
        rc = cleanup_rc;
    if (a_hash_ctx != NULL)
        xar_hash_final(a_hash_ctx, a_hash_result, a_hash);
    if (e_hash_ctx != NULL)
        xar_hash_final(e_hash_ctx, e_hash_result, e_hash);

exit_reader:
    if (a_cksum != NULL)
        xmlFree(a_cksum);
    if (e_cksum != NULL)
        xmlFree(e_cksum);
    xmlTextReaderClose(reader);
    xmlFreeTextReader(reader);

exit_toc:
    cleanup_rc = xar_cleanup_temp_file(ctx, toc_fd, tocname, &toc_reserved);
    if ((CL_SUCCESS == rc || CL_VERIFIED == rc) && CL_SUCCESS != cleanup_rc)
        rc = cleanup_rc;
    if (rc != CL_SUCCESS && rc != CL_VIRUS && rc != CL_BREAK && !ctx->scan_incomplete)
        cli_mark_scan_incomplete(ctx, "XAR inspection ended before completion");
    if (rc == CL_BREAK)
        rc = CL_SUCCESS;

    if (cksum_fails + extract_errors != 0) {
        cli_dbgmsg("cli_scanxar: %u checksum errors and %u extraction errors.\n",
                   cksum_fails, extract_errors);
    }

    return rc;
}
