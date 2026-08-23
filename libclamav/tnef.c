/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Nigel Horne
 *
 *  Acknowledgements: The algorithm was based on
 *                    kdepim/ktnef/lib/ktnefparser.cpp from KDE.
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
#include <fcntl.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "clamav.h"
#include "others.h"

#include "mbox.h"
#include "tnef.h"

static int tnef_message(fmap_t *map, off_t *pos, uint16_t type, uint16_t tag, int32_t length, off_t fsize);
static cl_error_t tnef_attachment(fmap_t *map, off_t *pos, uint16_t type, uint16_t tag, int32_t length, const char *dir, cli_ctx *ctx, fileblob **fbref, off_t fsize);
static int tnef_header(fmap_t *map, off_t *pos, uint8_t *part, uint16_t *type, uint16_t *tag, int32_t *length);
static size_t tnef_readn(fmap_t *map, void *dst, off_t at, size_t len);

#define TNEF_SIGNATURE 0x223E9f78
#define LVL_MESSAGE 0x01
#define LVL_ATTACHMENT 0x02

#define TNEF_HEADER_EOF         0
#define TNEF_HEADER_SUCCESS     1
#define TNEF_HEADER_TRUNCATED  -1
#define TNEF_HEADER_READ_ERROR -2

#define attMSGCLASS 0x8008
#define attBODY 0x800c
#define attATTACHDATA 0x800f  /* Attachment Data */
#define attATTACHTITLE 0x8010 /* Attachment File Name */
#define attDATEMODIFIED 0x8020
#define attTNEFVERSION 0x9006
#define attOEMCODEPAGE 0x9007

#define host16(v) le16_to_host(v)
#define host32(v) le32_to_host(v)

/* a TNEF file must be at least this size */
#define MIN_SIZE (sizeof(uint32_t) + sizeof(uint16_t))

static cl_error_t tnef_checktimelimit(cli_ctx *ctx, const char *reason)
{
    cl_error_t ret = cli_checktimelimit(ctx);

    if (ret != CL_SUCCESS)
        cli_mark_scan_incomplete(ctx, reason);

    return ret;
}

int cli_tnef(const char *dir, cli_ctx *ctx)
{
    uint32_t i32;
    uint16_t i16;
    fileblob *fb;
    cl_error_t ret;
    int alldone;
    off_t fsize, pos = 0;

    if (ctx == NULL || ctx->fmap == NULL) {
        if (ctx != NULL)
            cli_mark_scan_incomplete(ctx, "TNEF input map is unavailable");
        return CL_ENULLARG;
    }

    ret = tnef_checktimelimit(ctx, "TNEF inspection reached the configured time limit");
    if (ret != CL_SUCCESS)
        return ret;

    fsize = ctx->fmap->len;

    if (fsize < (off_t)MIN_SIZE) {
        cli_mark_scan_incomplete(ctx, "TNEF header was truncated");
        cli_dbgmsg("cli_tngs: file too small\n");
        return CL_EPARSE;
    }

    if (fmap_readn(ctx->fmap, &i32, pos, sizeof(uint32_t)) != sizeof(uint32_t)) {
        cli_mark_scan_incomplete(ctx, "TNEF signature could not be read completely");
        return CL_EREAD;
    }
    pos += sizeof(uint32_t);

    if (host32(i32) != TNEF_SIGNATURE) {
        return CL_EFORMAT;
    }

    if (fmap_readn(ctx->fmap, &i16, pos, sizeof(uint16_t)) != sizeof(uint16_t)) {
        cli_mark_scan_incomplete(ctx, "TNEF attribute level could not be read completely");
        return CL_EREAD;
    }
    pos += sizeof(uint16_t);

    fb      = NULL;
    ret     = CL_CLEAN; /* we don't know if it's clean or not :-) */
    alldone = 0;

    do {
        uint8_t part  = 0;
        uint16_t type = 0, tag = 0;
        int32_t length = 0;

        ret = tnef_checktimelimit(ctx, "TNEF attribute traversal reached the configured time limit");
        if (ret != CL_SUCCESS) {
            alldone = 1;
            break;
        }

        switch (tnef_header(ctx->fmap, &pos, &part, &type, &tag, &length)) {
            case TNEF_HEADER_EOF:
                alldone = 1;
                break;
            case TNEF_HEADER_SUCCESS:
                break;
            case TNEF_HEADER_READ_ERROR:
                cli_mark_scan_incomplete(ctx, "TNEF attribute header could not be read completely");
                ret     = CL_EREAD;
                alldone = 1;
                break;
            default:
                /*
                 * A truncated attribute header means part of the TNEF
                 * container was not inspected. Do not normalize that partial
                 * parse into a clean result.
                 */
                cli_warnmsg("cli_tnef: file truncated\n");
                cli_mark_scan_incomplete(ctx, "TNEF attribute header could not be read completely");
                ret     = CL_EPARSE;
                alldone = 1;
                break;
        }
        if (alldone)
            break;
        if (length == 0)
            continue;
        if (length < 0) {
            cli_warnmsg("Corrupt TNEF header detected - length %d\n",
                        (int)length);
            ret = CL_EFORMAT;
            break;
        }
        switch (part) {
            case LVL_MESSAGE:
                cli_dbgmsg("TNEF - found message\n");
                if (tag == attBODY) {
                    cli_mark_scan_incomplete(ctx, "TNEF message body is not inspected");
                }
                if (fb != NULL) {
                    fileblobDestroy(fb);
                    fb = NULL;
                }
                fb = fileblobCreate();
                if (fb == NULL) {
                    ret     = CL_EMEM;
                    alldone = 1;
                    break;
                }
                fileblobSetCTX(fb, ctx);
                if (fb->isIncomplete) {
                    ret     = CL_ERESOURCE;
                    alldone = 1;
                    break;
                }
                if (tnef_message(ctx->fmap, &pos, type, tag, length, fsize) != 0) {
                    cli_dbgmsg("TNEF: Error reading TNEF message\n");
                    ret     = CL_EFORMAT;
                    alldone = 1;
                }
                break;
            case LVL_ATTACHMENT:
                cli_dbgmsg("TNEF - found attachment\n");
                ret = tnef_attachment(ctx->fmap, &pos, type, tag, length, dir, ctx, &fb, fsize);
                if (ret != CL_SUCCESS) {
                    cli_dbgmsg("TNEF: Error reading TNEF attachment\n");
                    alldone = 1;
                }
                if (fb)
                    fileblobSetCTX(fb, ctx);
                break;
            case 0:
                break;
            default: {
                cl_error_t dump_ret = CL_SUCCESS;

                cli_warnmsg("TNEF - unknown level %d tag 0x%x\n", (int)part, (int)tag);

                /*
                 * Dump the file incase it was part of an
                 * email that's about to be deleted
                 */
                if (cli_debug_flag) {
                    int fout       = -1;
                    char *filename = cli_gentemp(ctx->this_layer_tmpdir);
                    char buffer[BUFSIZ];

                    if (filename)
                        fout = open(filename, O_WRONLY | O_CREAT | O_EXCL | O_TRUNC | O_BINARY, 0600);

                    if (fout >= 0) {
                        size_t count;

                        cli_warnmsg("Saving dump to %s:  refer to https://docs.clamav.net/manual/Installing.html\n", filename);

                        pos = 0;
                        while (1) {
                            if (tnef_checktimelimit(ctx, "TNEF debug-dump traversal reached the configured time limit") != CL_SUCCESS) {
                                dump_ret = CL_ETIMEOUT;
                                alldone = 1;
                                break;
                            }
                            count = fmap_readn(ctx->fmap, buffer, pos, sizeof(buffer));
                            if (count == (size_t)-1 || count == 0)
                                break;
                            pos += count;
                            if (tnef_checktimelimit(ctx, "TNEF debug-dump output reached the configured time limit") != CL_SUCCESS) {
                                dump_ret = CL_ETIMEOUT;
                                alldone = 1;
                                break;
                            }
                            if (cli_writen(fout, buffer, count) != count) {
                                cli_mark_scan_incomplete(ctx, "TNEF debug-dump output could not be written completely");
                                dump_ret = CL_EWRITE;
                                alldone = 1;
                                break;
                            }
                        }
                        close(fout);
                    }
                    free(filename);
                }
                ret     = dump_ret == CL_SUCCESS ? CL_EFORMAT : dump_ret;
                alldone = 1;
                break;
            }
        }
    } while (!alldone);

    if (fb) {
        cli_dbgmsg("cli_tnef: flushing final data\n");
        if (fileblobGetFilename(fb) == NULL) {
            cli_dbgmsg("Saving TNEF portion with an unknown name\n");
            fileblobSetFilename(fb, dir, "tnef");
        }
        fileblobDestroy(fb);
        fb = NULL;
    }

    /* The message body is a required content path.  Preserve any stronger
     * result, but never let the sticky omission normalize back to clean for
     * direct callers that do not run the common result reconciler. */
    if ((ret == CL_CLEAN || ret == CL_SUCCESS) && ctx->scan_incomplete)
        ret = CL_EPARSE;

    cli_dbgmsg("cli_tnef: returning %d\n", ret);
    return ret;
}

static int
tnef_message(fmap_t *map, off_t *pos, uint16_t type, uint16_t tag, int32_t length, off_t fsize)
{
    off_t offset;
#ifdef CL_DEBUG
    uint32_t i32;
    char *string;
    size_t string_len;
#else
    UNUSEDPARAM(map);
#endif

    cli_dbgmsg("message tag 0x%x, type 0x%x, length %d\n", tag, type,
               (int)length);

    offset = *pos;

    /*
     * a lot of this stuff should be only discovered in debug mode...
     */
    switch (tag) {
        case attBODY:
            cli_warnmsg("TNEF body is not inspected; scan is incomplete\n");
            break;
#ifdef CL_DEBUG
        case attTNEFVERSION:
            /*assert(length == sizeof(uint32_t))*/
            if (fmap_readn(map, &i32, *pos, sizeof(uint32_t)) != sizeof(uint32_t))
                return -1;
            (*pos) += sizeof(uint32_t);
            i32 = host32(i32);
            cli_dbgmsg("TNEF version %d\n", i32);
            break;
        case attOEMCODEPAGE:
            /* 8 bytes, but just print the first 4 */
            /*assert(length == sizeof(uint32_t))*/
            if (fmap_readn(map, &i32, *pos, sizeof(uint32_t)) != sizeof(uint32_t))
                return -1;
            (*pos) += sizeof(uint32_t);
            i32 = host32(i32);
            cli_dbgmsg("TNEF codepage %d\n", i32);
            break;
        case attDATEMODIFIED:
            /* 14 bytes, long */
            break;
        case attMSGCLASS:
            if (length <= 0)
                return -1;
            string_len = (size_t)length;
            if (string_len == SIZE_MAX)
                return -1;
            string = cli_max_malloc(string_len + 1);
            if (string == NULL) {
                cli_errmsg("tnef_message: Unable to allocate memory for string\n");
                return -1;
            }
            if (fmap_readn(map, string, *pos, string_len) != string_len) {
                free(string);
                return -1;
            }
            (*pos) += (off_t)string_len;
            string[string_len] = '\0';
            cli_dbgmsg("TNEF class %s\n", string);
            free(string);
            break;
        default:
            cli_dbgmsg("TNEF - unsupported message tag 0x%x type 0x%d length %d\n", tag, type, length);
            break;
#endif
    }

    /*cli_dbgmsg("%lu %lu\n", (long)(offset + length), ftell(fp));*/

    if (!CLI_ISCONTAINED_2_0_TO(fsize, offset, length)) {
        cli_dbgmsg("TNEF: Incorrect length field in tnef_message\n");
        return -1;
    }
    (*pos) = offset + length;

    /* Checksum - TODO, verify */
    (*pos) += 2;

    return 0;
}

static cl_error_t
tnef_attachment(fmap_t *map, off_t *pos, uint16_t type, uint16_t tag, int32_t length, const char *dir, cli_ctx *ctx, fileblob **fbref, off_t fsize)
{
    cl_error_t status;
    uint32_t todo;
    off_t offset;
    char *string;
    size_t string_len;

    cli_dbgmsg("attachment tag 0x%x, type 0x%x, length %d\n", tag, type,
               (int)length);

    offset = *pos;

    /* Validate the complete declared payload before reading or materializing
     * any part of it. A genuinely short TNEF attribute is malformed input;
     * only a fully in-range fmap callback failure is an operational read
     * error. */
    if (!CLI_ISCONTAINED_2_0_TO(fsize, offset, length)) {
        cli_dbgmsg("TNEF: Incorrect length field in tnef_attachment\n");
        cli_mark_scan_incomplete(ctx, "TNEF attachment length is outside the input");
        return CL_EFORMAT;
    }

    switch (tag) {
        case attATTACHTITLE:
            if (length <= 0)
                return CL_EFORMAT;
            string_len = (size_t)length;
            if (string_len == SIZE_MAX)
                return CL_EFORMAT;
            string = cli_max_malloc(string_len + 1);
            if (string == NULL) {
                cli_errmsg("tnef_attachment: Unable to allocate memory for string\n");
                cli_mark_scan_incomplete(ctx, "TNEF attachment title could not be allocated");
                return CL_EMEM;
            }
            if (fmap_readn(map, string, *pos, string_len) != string_len) {
                free(string);
                cli_mark_scan_incomplete(ctx, "TNEF attachment title could not be read completely");
                return CL_EREAD;
            }
            (*pos) += (off_t)string_len;
            string[string_len] = '\0';
            cli_dbgmsg("TNEF filename %s\n", string);
            if (*fbref == NULL) {
                *fbref = fileblobCreate();
                if (*fbref == NULL) {
                    cli_mark_scan_incomplete(ctx, "TNEF attachment output blob could not be allocated");
                    free(string);
                    return CL_EMEM;
                }
                fileblobSetCTX(*fbref, ctx);
                if ((*fbref)->isIncomplete) {
                    free(string);
                    return CL_ERESOURCE;
                }
            }
            fileblobSetFilename(*fbref, dir, string);
            if ((*fbref)->isIncomplete) {
                free(string);
                return CL_ETMPFILE;
            }
            free(string);
            break;
        case attATTACHDATA:
            if (*fbref == NULL) {
                *fbref = fileblobCreate();
                if (*fbref == NULL) {
                    cli_mark_scan_incomplete(ctx, "TNEF attachment output blob could not be allocated");
                    return CL_EMEM;
                }
            }
            fileblobSetCTX(*fbref, ctx);
            if ((*fbref)->isIncomplete)
                return CL_ERESOURCE;
            if (fileblobGetFilename(*fbref) == NULL) {
                fileblobSetFilename(*fbref, dir, "tnef");
                if ((*fbref)->isIncomplete)
                    return CL_ETMPFILE;
            }
            todo = length;
            while (todo) {
                unsigned char buf[BUFSIZ];
                size_t wanted = MIN(sizeof(buf), todo);
                size_t got;

                status = tnef_checktimelimit(ctx, "TNEF attachment traversal reached the configured time limit");
                if (status != CL_SUCCESS)
                    return status;

                got = fmap_readn(map, buf, *pos, wanted);
                if (got != wanted) {
                    cli_mark_scan_incomplete(ctx, "TNEF attachment data could not be read completely");
                    return CL_EREAD;
                }
                (*pos) += (off_t)got;

                if (fileblobAddData(*fbref, buf, got) < 0) {
                    cli_mark_scan_incomplete(ctx, "TNEF attachment data could not be materialized completely");
                    return CL_ERESOURCE;
                }
                todo -= (uint32_t)got;
            }
            break;
        default:
            cli_dbgmsg("TNEF - unsupported attachment tag 0x%x type 0x%d length %d\n",
                       tag, type, (int)length);
            break;
    }

    /*cli_dbgmsg("%lu %lu\n", (long)(offset + length), ftell(fp));*/

    if (!CLI_ISCONTAINED_2_0_TO(fsize, offset, length)) {
        cli_dbgmsg("TNEF: Incorrect length field in tnef_attachment\n");
        cli_mark_scan_incomplete(ctx, "TNEF attachment length is outside the input");
        return CL_EFORMAT;
    }
    (*pos) = offset + (off_t)length; /* shouldn't be needed */

    (*pos) += 2;

    return CL_SUCCESS;
}

static int
tnef_header(fmap_t *map, off_t *pos, uint8_t *part, uint16_t *type, uint16_t *tag, int32_t *length)
{
    uint32_t i32;
    size_t rc;

    /* An exact end-of-map is the normal end of a TNEF attribute list. An
     * in-range fmap failure is different: treating it as EOF would allow a
     * direct parser caller to report a clean, partially inspected container. */
    if (*pos < 0 || (uint64_t)*pos > (uint64_t)map->len)
        return TNEF_HEADER_TRUNCATED;
    if ((uint64_t)*pos == (uint64_t)map->len)
        return TNEF_HEADER_EOF;
    rc = tnef_readn(map, part, *pos, 1);
    if (rc != 1)
        return rc == (size_t)-1 ? TNEF_HEADER_READ_ERROR : TNEF_HEADER_TRUNCATED;
    (*pos)++;

    if (*part == (uint8_t)0)
        return TNEF_HEADER_EOF;

    rc = tnef_readn(map, &i32, *pos, sizeof(uint32_t));
    if (rc != sizeof(uint32_t)) {
        if (((*part == '\n') || (*part == '\r')) && (rc == 0)) {
            /*
             * trailing newline in the file, could be caused by
             * broken quoted-printable encoding in the source
             * message missing a final '='
             */
            cli_dbgmsg("tnef_header: ignoring trailing newline\n");
            return TNEF_HEADER_EOF;
        }
        return rc == (size_t)-1 ? TNEF_HEADER_READ_ERROR : TNEF_HEADER_TRUNCATED;
    }
    (*pos) += sizeof(uint32_t);

    i32   = host32(i32);
    *tag  = (uint16_t)(i32 & 0xFFFF);
    *type = (uint16_t)((i32 & 0xFFFF0000) >> 16);

    rc = tnef_readn(map, &i32, *pos, sizeof(uint32_t));
    if (rc != sizeof(uint32_t))
        return rc == (size_t)-1 ? TNEF_HEADER_READ_ERROR : TNEF_HEADER_TRUNCATED;
    (*pos) += sizeof(uint32_t);
    *length = (int32_t)host32(i32);

    cli_dbgmsg("message tag 0x%x, type 0x%x, length %d\n",
               *tag, *type, (int)*length);

    return TNEF_HEADER_SUCCESS;
}

static size_t
tnef_readn(fmap_t *map, void *dst, off_t at, size_t len)
{
    /* fmap_readn() uses (size_t)-1 for both callback failures and an offset
     * beyond the map. Preserve impossible or incomplete fixed structures as
     * short input so only an in-range callback failure for a fully available
     * structure becomes an operational read error. */
    if (at < 0 || (uint64_t)at > (uint64_t)map->len)
        return 0;
    if (len > map->len - (size_t)at)
        return 0;
    return fmap_readn(map, dst, (size_t)at, len);
}
