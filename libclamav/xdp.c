/*
 *  Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 *
 *  Author: Shawn Webb
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
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL.  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so.  If you
 *  do not wish to do so, delete this exception statement from your
 *  version.  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#if !defined(_WIN32)
#include <unistd.h>
#endif
#include <errno.h>

#include "xar.h"
#include "fmap.h"

#include <libxml/xmlreader.h>

#include "clamav.h"
#include "str.h"
#include "scanners.h"
#include "conv.h"
#include "xdp.h"
#include "filetypes.h"
#include "msxml.h"

static char *dump_xdp(cli_ctx *ctx, fmap_t *map);

static char *dump_xdp(cli_ctx *ctx, fmap_t *map)
{
    int fd;
    char *filename;
    unsigned char buffer[FILEBUFF];
    size_t offset = 0;
    size_t wanted;
    size_t nread;
    size_t nwritten;
    ssize_t writeret;

    if (cli_gentempfd(ctx->this_layer_tmpdir, &filename, &fd) != CL_SUCCESS)
        return NULL;

    while (offset < map->len) {
        wanted = MIN(sizeof(buffer), map->len - offset);
        nread  = fmap_readn(map, buffer, offset, wanted);
        if (nread != wanted) {
            cli_errmsg("dump_xdp: failed to read XDP input at offset %zu\n", offset);
            close(fd);
            cli_unlink(filename);
            free(filename);
            return NULL;
        }

        nwritten = 0;
        while (nwritten < nread) {
            writeret = write(fd, buffer + nwritten, nread - nwritten);
            if (writeret < 0) {
                if (errno == EAGAIN || errno == EINTR)
                    continue;

                close(fd);
                cli_unlink(filename);
                free(filename);
                return NULL;
            }
            if (writeret == 0) {
                close(fd);
                cli_unlink(filename);
                free(filename);
                return NULL;
            }

            nwritten += (size_t)writeret;
        }
        offset += nread;
    }

    cli_dbgmsg("dump_xdp: Dumped payload to %s\n", filename);

    close(fd);

    return filename;
}

cl_error_t cli_scanxdp(cli_ctx *ctx)
{
    xmlTextReaderPtr reader = NULL;
    struct msxml_cbdata cbdata;
    const xmlChar *name, *value;
    char *decoded;
    size_t decodedlen;
    size_t encodedlen;
    cl_error_t rc = CL_SUCCESS;
    cl_error_t limitret;
    char *dumpname;
    int read_status;

    if (!ctx || !ctx->fmap)
        return CL_ENULLARG;

    if (ctx->fmap->len > XDP_DEEP_PARSE_MAX_SIZE) {
        cli_mark_scan_incomplete(ctx, "XDP layer exceeds the 64 MiB libxml2 deep-parser limit");
        return CL_EPARSE;
    }

    if (ctx->engine && ctx->engine->keeptmp) {
        dumpname = dump_xdp(ctx, ctx->fmap);
        if (dumpname)
            free(dumpname);
    }

    memset(&cbdata, 0, sizeof(cbdata));
    cbdata.map = ctx->fmap;
    reader     = xmlReaderForIO(msxml_read_cb, NULL, &cbdata, "xdp.xml", NULL, CLAMAV_MIN_XMLREADER_FLAGS);
    if (!reader) {
        cli_mark_scan_incomplete(ctx, "XDP streaming XML reader could not be initialized");
        return CL_EPARSE;
    }

    while ((read_status = xmlTextReaderRead(reader)) == 1) {
        name = xmlTextReaderConstLocalName(reader);
        if (!(name))
            continue;

        if (!strcmp((const char *)name, "chunk") && xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT) {
            value = xmlTextReaderReadInnerXml(reader);
            if (!value) {
                cli_mark_scan_incomplete(ctx, "XDP chunk value could not be materialized within its bounded layer");
                rc = CL_EPARSE;
                break;
            }

            encodedlen = strlen((const char *)value);
            decoded    = cl_base64_decode((char *)value, encodedlen, NULL, &decodedlen, 0);
            if (!decoded || decodedlen > XDP_DEEP_PARSE_MAX_SIZE) {
                free(decoded);
                xmlFree((void *)value);
                cli_mark_scan_incomplete(ctx, "XDP chunk could not be decoded within the bounded parser limit");
                rc = CL_EPARSE;
                break;
            }

            limitret = cli_checklimits("XDP chunk", ctx, decodedlen, 0, 0);
            if (limitret != CL_SUCCESS) {
                free(decoded);
                xmlFree((void *)value);
                cli_mark_scan_incomplete(ctx, "XDP decoded chunk exceeds configured scan limits");
                rc = (limitret == CL_ETIMEOUT) ? limitret : CL_EPARSE;
                break;
            }

            /* Every decoded chunk is required inspection input. The former
             * PDF-magic prefilter allowed other decoded payloads to return
             * clean without ever reaching the nested scanner. */
            if (decodedlen != 0)
                rc = cli_magic_scan_buff(decoded, decodedlen, ctx, NULL, LAYER_ATTRIBUTES_NONE);
            free(decoded);
            xmlFree((void *)value);
            if (rc != CL_SUCCESS)
                break;
        }
    }

    if (read_status < 0 && rc == CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, "XDP streaming XML parse failed before all chunks were inspected");
        rc = CL_EPARSE;
    }

    if (xmlTextReaderClose(reader) != 0 && rc == CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, "XDP streaming XML reader did not close cleanly");
        rc = CL_EPARSE;
    }

    xmlFreeTextReader(reader);

    return rc;
}
