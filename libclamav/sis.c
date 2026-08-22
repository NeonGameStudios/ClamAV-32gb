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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#include <fcntl.h>
#include <stdbool.h>
#include <zlib.h>

#include "others.h"
#include "clamav.h"
#include "scanners.h"
#include "sis.h"

#define EC32(x) cli_readint32(&(x))
#define EC16(x) cli_readint16(&(x))

/*
 * The SIS header begins with four 4-byte UIDs.
 *
 * SIS format reference: https://web.archive.org/web/20021017223232/http://homepage.ntlworld.com/thouky/software/psifs/sis.html
 *
 * SIS v9.x format reference: https://web.archive.org/web/20101011053920/http://developer.symbian.org/wiki/images/b/b7/SymbianOSv9.x_SIS_File_Format_Specification.pdf
 *   See Section 3 (page 8)
 */
#define SIZEOF_HEADER_UUIDS 16

static cl_error_t real_scansis(cli_ctx *, const char *);
static cl_error_t real_scansis9x(cli_ctx *, const char *);

static cl_error_t
sis_incomplete(cli_ctx *ctx, const char *reason)
{
    cli_mark_scan_incomplete(ctx, reason);
    return CL_EPARSE;
}

static cl_error_t
sis_read_failure(cli_ctx *ctx, size_t nread, const char *read_reason, const char *short_reason)
{
    if (nread == (size_t)-1) {
        cli_mark_scan_incomplete(ctx, read_reason);
        return CL_EREAD;
    }

    cli_mark_scan_incomplete(ctx, short_reason);
    return CL_EPARSE;
}

static const void *
sis_need_off(cli_ctx *ctx, size_t offset, size_t length, cl_error_t *status,
             const char *read_reason, const char *short_reason)
{
    const void *ptr;

    if (ctx == NULL || ctx->fmap == NULL || status == NULL)
        return NULL;

    if (offset > ctx->fmap->len || length > ctx->fmap->len - offset) {
        cli_mark_scan_incomplete(ctx, short_reason);
        *status = CL_EPARSE;
        return NULL;
    }

    ptr = fmap_need_off_once(ctx->fmap, offset, length);
    if (ptr == NULL) {
        cli_mark_scan_incomplete(ctx, read_reason);
        *status = CL_EREAD;
        return NULL;
    }

    *status = CL_SUCCESS;
    return ptr;
}

static cl_error_t
sis_checktimelimit(cli_ctx *ctx, const char *reason)
{
    cl_error_t status = cli_checktimelimit(ctx);

    if (status != CL_SUCCESS)
        cli_mark_scan_incomplete(ctx, reason);

    return status;
}

static void
sis_note_cleanup_failure(cli_ctx *ctx, cl_error_t *status, int failed, const char *reason)
{
    if (!failed)
        return;

    cli_mark_scan_incomplete(ctx, reason);
    if (*status == CL_SUCCESS || *status == CL_CLEAN || *status == CL_BREAK)
        *status = CL_EUNLINK;
}

#define SIS_STREAM_CHUNK (64U * 1024U)

/* Copy or inflate one SIS member into a caller-owned temporary descriptor.
 * The caller reserves the declared output size before invoking this helper and
 * keeps that reservation until the nested descriptor scan has completed. */
static cl_error_t sis_stream_member_to_fd(cli_ctx *ctx, fmap_t *map, uint64_t input_offset,
                                          uint64_t input_size, uint64_t output_size, bool compressed, int fd)
{
    uint8_t input[SIS_STREAM_CHUNK];
    uint8_t output[SIS_STREAM_CHUNK];
    uint64_t input_pos         = input_offset;
    uint64_t input_remaining   = input_size;
    uint64_t output_total      = 0;
    const char *failure_reason = "SIS member could not be streamed completely";
    cl_error_t status          = CL_SUCCESS;
    z_stream stream;
    bool stream_initialized = false;

    if (ctx == NULL || map == NULL || fd < 0) {
        return CL_EARG;
    }

    if (input_offset > (uint64_t)map->len || input_size > (uint64_t)map->len - input_offset) {
        failure_reason = "SIS member data was outside the archive map";
        status         = CL_EPARSE;
        goto done;
    }

    if (!compressed && input_size != output_size) {
        failure_reason = "SIS uncompressed member size disagreed with its metadata";
        status         = CL_EPARSE;
        goto done;
    }

    if (!compressed) {
        while (input_remaining != 0) {
            size_t chunk;
            size_t nread;

            status = cli_checktimelimit(ctx);
            if (status != CL_SUCCESS) {
                failure_reason = "SIS member copy reached the configured time limit";
                goto done;
            }

            chunk = (input_remaining > sizeof(input)) ? sizeof(input) : (size_t)input_remaining;
            nread = fmap_readn(map, input, (size_t)input_pos, chunk);
            if (nread != chunk) {
                failure_reason = "SIS member could not be read completely";
                status         = (nread == (size_t)-1) ? CL_EREAD : CL_EPARSE;
                goto done;
            }
            status = cli_checktimelimit(ctx);
            if (status != CL_SUCCESS) {
                failure_reason = "SIS member output reached the configured time limit";
                goto done;
            }
            if (cli_writen(fd, input, chunk) != chunk) {
                failure_reason = "SIS member could not be written completely";
                status         = CL_EWRITE;
                goto done;
            }

            input_pos += chunk;
            input_remaining -= chunk;
            output_total += chunk;
        }

        goto done;
    }

    memset(&stream, 0, sizeof(stream));
    if (inflateInit(&stream) != Z_OK) {
        failure_reason = "SIS zlib stream could not be initialized";
        status         = CL_EPARSE;
        goto done;
    }
    stream_initialized = true;

    for (;;) {
        uInt before_input;
        size_t produced;
        int zstatus;

        status = cli_checktimelimit(ctx);
        if (status != CL_SUCCESS) {
            failure_reason = "SIS zlib stream reached the configured time limit";
            goto done;
        }

        if (stream.avail_in == 0 && input_remaining != 0) {
            size_t chunk = (input_remaining > sizeof(input)) ? sizeof(input) : (size_t)input_remaining;
            size_t nread = fmap_readn(map, input, (size_t)input_pos, chunk);

            if (nread != chunk) {
                failure_reason = "SIS compressed member could not be read completely";
                status         = (nread == (size_t)-1) ? CL_EREAD : CL_EPARSE;
                goto done;
            }
            input_pos += chunk;
            input_remaining -= chunk;
            stream.next_in  = input;
            stream.avail_in = (uInt)chunk;
        }

        stream.next_out  = output;
        stream.avail_out = sizeof(output);
        before_input     = stream.avail_in;
        zstatus          = inflate(&stream, Z_NO_FLUSH);
        produced         = sizeof(output) - stream.avail_out;

        if (produced != 0) {
            if (output_total > output_size || (uint64_t)produced > output_size - output_total) {
                failure_reason = "SIS decompressed member exceeded its declared output size";
                status         = CL_EFORMAT;
                goto done;
            }
            status = cli_checktimelimit(ctx);
            if (status != CL_SUCCESS) {
                failure_reason = "SIS decompressed member output reached the configured time limit";
                goto done;
            }
            if (cli_writen(fd, output, produced) != produced) {
                failure_reason = "SIS decompressed member could not be written completely";
                status         = CL_EWRITE;
                goto done;
            }
            output_total += produced;
        }

        if (zstatus == Z_STREAM_END) {
            if (input_remaining != 0 || stream.avail_in != 0) {
                failure_reason = "SIS compressed member contains trailing data";
                status         = CL_EPARSE;
            } else if (output_total != output_size) {
                failure_reason = "SIS decompressed member size disagreed with its metadata";
                status         = CL_EPARSE;
            }
            break;
        }
        if (zstatus != Z_OK) {
            failure_reason = "SIS compressed member did not reach zlib stream completion";
            status         = (zstatus == Z_MEM_ERROR) ? CL_EMEM : CL_EPARSE;
            goto done;
        }
        if (before_input == stream.avail_in && produced == 0) {
            failure_reason = "SIS zlib stream made no progress";
            status         = CL_EPARSE;
            goto done;
        }
    }

done:
    if (stream_initialized && inflateEnd(&stream) != Z_OK && status == CL_SUCCESS) {
        failure_reason = "SIS zlib stream could not be finalized";
        status         = CL_EPARSE;
    }
    if (status == CL_SUCCESS && output_total != output_size) {
        failure_reason = "SIS member output size disagreed with its metadata";
        status         = CL_EPARSE;
    }
    if (status != CL_SUCCESS && status != CL_ETIMEOUT)
        cli_mark_scan_incomplete(ctx, failure_reason);
    return status;
}

/*************************************************
       This is the wrapper to the old and new
            format handlers - see below.
 *************************************************/

cl_error_t cli_scansis(cli_ctx *ctx)
{
    char *tmpd;
    unsigned int i;
    cl_error_t status;
    uint32_t uid[4];
    fmap_t *map;

    if ((ctx == NULL) || (ctx->fmap == NULL))
        return CL_ENULLARG;

    status = sis_checktimelimit(ctx, "SIS inspection reached the configured time limit");
    if (status != CL_SUCCESS)
        return status;

    map = ctx->fmap;

    cli_dbgmsg("in scansis()\n");

    if (!(tmpd = cli_gentemp_with_prefix(ctx->this_layer_tmpdir, "sis-tmp")))
        return CL_ETMPDIR;
    if (mkdir(tmpd, 0700)) {
        cli_dbgmsg("SIS: Can't create temporary directory %s\n", tmpd);
        free(tmpd);
        return CL_ETMPDIR;
    }
    if (ctx->engine->keeptmp)
        cli_dbgmsg("SIS: Extracting files to %s\n", tmpd);

    {
        size_t nread = fmap_readn(map, &uid, 0, SIZEOF_HEADER_UUIDS);

        if (nread != SIZEOF_HEADER_UUIDS) {
            cl_error_t read_status = sis_read_failure(ctx, nread,
                                                       "SIS UID header could not be read completely",
                                                       "SIS UID header was truncated");

            cli_dbgmsg("SIS: unable to read UIDs\n");
            if (cli_rmdirs(tmpd) != 0)
                cli_mark_scan_incomplete(ctx, "SIS temporary directory could not be removed");
            free(tmpd);
            return read_status;
        }
    }

    cli_dbgmsg("SIS: UIDS %x %x %x - %x\n", EC32(uid[0]), EC32(uid[1]), EC32(uid[2]), EC32(uid[3]));
    if (uid[2] == le32_to_host(0x10000419)) {
        i = real_scansis(ctx, tmpd);
    } else if (uid[0] == le32_to_host(0x10201a7a)) {
        i = real_scansis9x(ctx, tmpd);
    } else {
        cli_dbgmsg("SIS: UIDs failed to match\n");
        i = CL_EFORMAT;
    }

    if (!ctx->engine->keeptmp && cli_rmdirs(tmpd) != 0) {
        cli_mark_scan_incomplete(ctx, "SIS temporary directory could not be removed");
        if (i == CL_SUCCESS || i == CL_CLEAN || i == CL_BREAK)
            i = CL_EUNLINK;
    }

    free(tmpd);
    return i;
}

/*************************************************
     This is the handler for the old (pre 0.9)
                 SIS file format.
 *************************************************/

enum {
    PKGfile,     /* I'm a real file */
    PKGlangfile, /* Ich bin auch eine Datei */
    PKGoption,   /* options */
    PKGif,       /* #IF */
    PKGelsif,    /* #ELSIF */
    PKGelse,     /* #ELSE */
    PKGendif     /* #ENDIF */
};

enum {
    FTsimple = 0,
    FTtext,
    FTcomponent,
    FTrun,
    FTnull,
    FTmime,
    FTsubsis,
    FTcontsis,
    FTtextuninst,
    FTnotinst = 99
};

#define GETD2(VAR)                                                                             \
    {                                                                                          \
        /* cli_dbgmsg("GETD2 smax: %d sleft: %d\n", smax, sleft); */                           \
        if (sis_checktimelimit(ctx, "SIS metadata traversal reached the configured time limit") != CL_SUCCESS) { \
            status = CL_ETIMEOUT;                                                              \
            goto done;                                                                         \
        }                                                                                        \
        if (sleft < 4) {                                                                       \
            memcpy(buff, buff + smax - sleft, sleft);                                          \
            size_t tmp = fmap_readn(map, buff + sleft, pos, BUFSIZ - sleft);                   \
            smax       = tmp;                                                                  \
            if (((size_t)-1) == tmp) {                                                         \
                cli_dbgmsg("SIS: Read failed during GETD2\n");                                 \
                status = sis_incomplete(ctx, "SIS field could not be read completely");        \
                goto done;                                                                     \
            } else if ((smax += sleft) < 4) {                                                  \
                cli_dbgmsg("SIS: EOF\n");                                                      \
                status = sis_incomplete(ctx, "SIS field ended before its value was complete"); \
                goto done;                                                                     \
            }                                                                                  \
            pos += smax - sleft;                                                               \
            sleft = smax;                                                                      \
        }                                                                                      \
        VAR = cli_readint32(&buff[smax - sleft]);                                              \
        sleft -= 4;                                                                            \
    }

#define SKIP(N)                                                                                     \
    /* cli_dbgmsg("SKIP smax: %d sleft: %d\n", smax, sleft); */                                     \
    if (sleft >= (N))                                                                               \
        sleft -= (N);                                                                               \
    else {                                                                                          \
        if ((N) < sleft) {                                                                          \
            cli_dbgmsg("SIS: Refusing to seek back\n");                                             \
            free((void *)alangs);                                                                   \
            return sis_incomplete(ctx, "SIS parser attempted to seek outside its buffered stream"); \
        }                                                                                           \
        pos += (N)-sleft;                                                                           \
        size_t tmp = fmap_readn(map, buff, pos, BUFSIZ);                                            \
        if (((size_t)-1) == tmp) {                                                                  \
            cli_dbgmsg("SIS: Read failed during SKIP\n");                                           \
            free((void *)alangs);                                                                   \
            return sis_incomplete(ctx, "SIS skip could not be read completely");                    \
        }                                                                                           \
        sleft = smax = tmp;                                                                         \
        pos += smax;                                                                                \
    }

const char *sislangs[] = {"UNKNOWN", "UK English", "French", "German", "Spanish", "Italian", "Swedish", "Danish", "Norwegian", "Finnish", "American", "Swiss French", "Swiss German", "Portuguese", "Turkish", "Icelandic", "Russian", "Hungarian", "Dutch", "Belgian Flemish", "Australian English", "Belgian French", "Austrian German", "New Zealand English", "International French", "Czech", "Slovak", "Polish", "Slovenian", "Taiwanese Chinese", "Hong Kong Chinese", "PRC Chinese", "Japanese", "Thai", "Afrikaans", "Albanian", "Amharic", "Arabic", "Armenian", "Tagalog", "Belarussian", "Bengali", "Bulgarian", "Burmese", "Catalan", "Croation", "Canadian English", "International English", "South African English", "Estonian", "Farsi", "Canadian French", "Gaelic", "Georgian", "Greek", "Cyprus Greek", "Gujarati", "Hebrew", "Hindi", "Indonesian", "Irish", "Swiss Italian", "Kannada", "Kazakh", "Kmer", "Korean", "Lao", "Latvian", "Lithuanian", "Macedonian", "Malay", "Malayalam", "Marathi", "Moldovian", "Mongolian", "Norwegian Nynorsk", "Brazilian Portuguese", "Punjabi", "Romanian", "Serbian", "Sinhalese", "Somali", "International Spanish", "American Spanish", "Swahili", "Finland Swedish", "Reserved", "Tamil", "Telugu", "Tibetan", "Tigrinya", "Cyprus Turkish", "Turkmen", "Ukrainian", "Urdu", "Reserved", "Vietnamese", "Welsh", "Zulu", "Other"};
#define MAXLANG (sizeof(sislangs) / sizeof(sislangs[0]))

static cl_error_t getsistring(cli_ctx *ctx, fmap_t *map, uint32_t ptr, uint32_t len, char **name_out)
{
    char *name;
    uint32_t i;

    if (name_out == NULL)
        return CL_ENULLARG;
    *name_out = NULL;

    if (!len)
        return CL_SUCCESS;
    if (len > 400) len = 400;
    name = cli_max_malloc(len + 1);
    if (!name) {
        cli_dbgmsg("SIS: OOM\n");
        cli_mark_scan_incomplete(ctx, "SIS string could not be allocated");
        return CL_EMEM;
    }
    {
        size_t nread = fmap_readn(map, name, ptr, len);

        if (nread != len) {
            cl_error_t status = sis_read_failure(ctx, nread,
                                                  "SIS string could not be read completely",
                                                  "SIS string was truncated");

            cli_dbgmsg("SIS: Unable to read string\n");
            free(name);
            return status;
        }
    }
    for (i = 0; i < len; i += 2) name[i / 2] = name[i];
    name[i / 2] = '\0';
    *name_out = name;
    return CL_SUCCESS;
}

static cl_error_t spamsisnames(cli_ctx *ctx, fmap_t *map, size_t pos, uint16_t langs, const char **alangs)
{
    uint32_t *values;
    uint32_t *ptrs;
    uint32_t *lens;
    unsigned int j;
    size_t nread;

    const uint32_t len = sizeof(uint32_t) * langs * 2;

    values = cli_max_malloc(len);
    if (values == NULL) {
        cli_mark_scan_incomplete(ctx, "SIS name table could not be allocated");
        return CL_EMEM;
    }

    nread = fmap_readn(map, values, pos, len);
    if (nread != len) {
        cl_error_t status = sis_read_failure(ctx, nread,
                                             "SIS name table could not be read completely",
                                             "SIS name table was truncated");

        cli_dbgmsg("SIS: Unable to read lengths and pointers\n");
        free(values);
        return status;
    }
    lens = values;
    ptrs = &lens[langs];

    for (j = 0; j < langs; j++) {
        char *name = NULL;
        cl_error_t status = sis_checktimelimit(ctx, "SIS metadata traversal reached the configured time limit");

        if (status != CL_SUCCESS) {
            free(values);
            return status;
        }

        status = getsistring(ctx, map, EC32(ptrs[j]), EC32(lens[j]), &name);

        if (status != CL_SUCCESS) {
            free(values);
            return status;
        }
        if (name != NULL) {
            cli_dbgmsg("\t%s (%s - @%x, len %d)\n", name, alangs[j], EC32(ptrs[j]), EC32(lens[j]));
            free(name);
        }
    }
    free(values);
    return CL_SUCCESS;
}

static cl_error_t real_scansis(cli_ctx *ctx, const char *tmpd)
{
    cl_error_t status       = CL_EPARSE;
    cl_error_t limit_status = CL_CLEAN;

    struct {
        uint16_t filesum;
        uint16_t langs;
        uint16_t files;
        uint16_t deps;
        uint16_t ulangs;
        uint16_t instfiles;
        uint16_t drive;
        uint16_t caps;
        uint32_t version;
        uint16_t flags;
        uint16_t type;
        uint16_t verhi;
        uint16_t verlo;
        uint32_t versub;
        uint32_t plangs;
        uint32_t pfiles;
        uint32_t pdeps;
        uint32_t pcerts;
        uint32_t pnames;
        uint32_t psig;
        uint32_t pcaps;
        uint32_t uspace;
        uint32_t nspace;
    } sis;
    const char **alangs = NULL;
    const uint16_t *llangs;
    unsigned int i, umped = 0;
    uint32_t sleft = 0, smax = 0;
    uint8_t compd, buff[BUFSIZ];
    size_t pos;
    fmap_t *map             = ctx->fmap;
    uint32_t *ptrs          = NULL;
    int fd                  = -1;
    char *original_filepath = NULL;
    char *install_filepath  = NULL;

    status = sis_checktimelimit(ctx, "SIS metadata traversal reached the configured time limit");
    if (status != CL_SUCCESS)
        goto done;

    {
        size_t nread = fmap_readn(map, &sis, SIZEOF_HEADER_UUIDS, sizeof(sis));

        if (nread != sizeof(sis)) {
            status = sis_read_failure(ctx, nread,
                                      "SIS header could not be read completely",
                                      "SIS header was truncated");
            cli_dbgmsg("SIS: Unable to read header\n");
            goto done;
        }
    }
    /*  cli_dbgmsg("SIS HEADER INFO: \nFile checksum: %x\nLangs: %d\nFiles: %d\nDeps: %d\nUsed langs: %d\nInstalled files: %d\nDest drive: %d\nCapabilities: %d\nSIS Version: %d\nFlags: %x\nType: %d\nVersion: %d.%d.%d\nLangs@: %x\nFiles@: %x\nDeps@: %x\nCerts@: %x\nName@: %x\nSig@: %x\nCaps@: %x\nUspace: %d\nNspace: %d\n\n", sis.filesum, sis.langs, sis.files, sis.deps, sis.ulangs, sis.instfiles, sis.drive, sis.caps, sis.version, sis.flags, sis.type, sis.verhi, sis.verlo, sis.versub, sis.plangs, sis.pfiles, sis.pdeps, sis.pcerts, sis.pnames, sis.psig, sis.pcaps, sis.uspace, sis.nspace);
     */

#if WORDS_BIGENDIAN != 0
    sis.langs  = EC16(sis.langs);
    sis.files  = EC16(sis.files);
    sis.deps   = EC16(sis.deps);
    sis.flags  = EC16(sis.flags);
    sis.plangs = EC32(sis.plangs);
    sis.pfiles = EC32(sis.pfiles);
    sis.pdeps  = EC32(sis.pdeps);
    sis.pnames = EC32(sis.pnames);
    sis.pcaps  = EC32(sis.pcaps);
#endif

    if (!sis.langs || sis.langs >= MAXLANG) {
        cli_dbgmsg("SIS: Too many or too few languages found\n");
        goto done;
    }

    pos = sis.plangs;

    if (!(llangs = sis_need_off(ctx, pos, sis.langs * sizeof(uint16_t), &status,
                                "SIS language table could not be read completely",
                                "SIS language table was truncated"))) {
        cli_dbgmsg("SIS: Unable to read languages\n");
        goto done;
    }
    pos += sis.langs * sizeof(uint16_t);
    if (!(alangs = cli_max_malloc(sis.langs * sizeof(char *)))) {
        cli_dbgmsg("SIS: OOM\n");
        goto done;
    }
    for (i = 0; i < sis.langs; i++) {
        status = sis_checktimelimit(ctx, "SIS metadata traversal reached the configured time limit");
        if (status != CL_SUCCESS)
            goto done;
        alangs[i] = (size_t)EC16(llangs[i]) < MAXLANG ? sislangs[EC16(llangs[i])] : sislangs[0];
    }

    if (!sis.pnames) {
        cli_dbgmsg("SIS: Application without a name?\n");
    } else {
        cli_dbgmsg("SIS: Application name:\n");
        status = spamsisnames(ctx, map, sis.pnames, sis.langs, alangs);
        if (status != CL_SUCCESS) {
            goto done;
        }
    }

    if (!sis.pcaps) {
        cli_dbgmsg("SIS: Application without capabilities?\n");
    } else {
        cli_dbgmsg("SIS: Provides:\n");
        status = spamsisnames(ctx, map, sis.pcaps, sis.langs, alangs);
        if (status != CL_SUCCESS) {
            goto done;
        }
    }

    if (!sis.pdeps) {
        cli_dbgmsg("SIS: No dependencies set for this application\n");
    } else {
        cli_dbgmsg("SIS: Depends on:\n");
        for (i = 0; i < sis.deps; i++) {
            struct {
                uint32_t uid;
                uint16_t verhi;
                uint16_t verlo;
                uint32_t versub;
            } dep;

            status = sis_checktimelimit(ctx, "SIS metadata traversal reached the configured time limit");
            if (status != CL_SUCCESS)
                goto done;

            pos = sis.pdeps + i * (sizeof(dep) + sis.langs * 2 * sizeof(uint32_t));
            {
                size_t nread = fmap_readn(map, &dep, pos, sizeof(dep));

                if (nread != sizeof(dep)) {
                    status = sis_read_failure(ctx, nread,
                                              "SIS dependency header could not be read completely",
                                              "SIS dependency header was truncated");
                    cli_dbgmsg("SIS: Unable to read dependencies\n");
                    goto done;
                }
            }
            {
                cl_error_t names_status;

                pos += sizeof(dep);
                cli_dbgmsg("\tUID: %x v. %d.%d.%d\n\taka:\n", EC32(dep.uid), EC16(dep.verhi), EC16(dep.verlo), EC32(dep.versub));
                names_status = spamsisnames(ctx, map, pos, sis.langs, alangs);
                if (names_status != CL_SUCCESS) {
                    status = names_status;
                    goto done;
                }
            }
        }
    }

    compd = !(sis.flags & 0x0008);
    cli_dbgmsg("SIS: Package is%s compressed\n", (compd) ? "" : " not");

    if (SIZEOF_HEADER_UUIDS + sizeof(sis) > sis.pfiles) {
        cli_dbgmsg("SIS: Invalid SIS format or not an SIS file. The pointer to the file records must not point to within the SIS header: %u\n", sis.pfiles);
        goto done;
    }

    pos = sis.pfiles;
    for (i = 0; i < sis.files; i++) {
        uint32_t pkgtype, fcount = 1;
        uint32_t j;

        status = sis_checktimelimit(ctx, "SIS metadata traversal reached the configured time limit");
        if (status != CL_SUCCESS)
            goto done;

        GETD2(pkgtype);
        cli_dbgmsg("SIS: Pkgtype: %d\n", pkgtype);
        switch (pkgtype) {
            case PKGlangfile:
                fcount = sis.langs;
                break;
            case PKGfile: {
                uint32_t ftype, options, ssname, psname, sdname, pdname;
                const char *sftype;
                uint32_t *lens, *olens;
                fcount = sis.langs;

                GETD2(ftype);
                GETD2(options);
                GETD2(ssname);
                GETD2(psname);
                GETD2(sdname);
                GETD2(pdname);
                switch (ftype) {
                    case FTsimple:
                        sftype = "simple";
                        break;
                    case FTtext:
                        sftype = "text";
                        break;
                    case FTcomponent:
                        sftype = "component";
                        break;
                    case FTrun:
                        sftype = "run";
                        break;
                    case FTnull:
                        sftype = "null";
                        break;
                    case FTmime:
                        sftype = "mime";
                        break;
                    case FTsubsis:
                        sftype = "sub sis";
                        break;
                    case FTcontsis:
                        sftype = "container sis";
                        break;
                    case FTtextuninst:
                        sftype = "uninstall text";
                        break;
                    case FTnotinst:
                        sftype = "not to be installed";
                        break;
                    default:
                        sftype = "unknown";
                }
                cli_dbgmsg("SIS: File details:\n\tOptions: %d\n\tType: %s\n", options, sftype);
                status = getsistring(ctx, map, psname, ssname, &original_filepath);
                if (status != CL_SUCCESS)
                    goto done;
                if (original_filepath != NULL) {
                    cli_dbgmsg("\tOriginal filename: %s\n", original_filepath);
                    /* We'll keep the original filepath around to pass to the scan function */
                }
                status = getsistring(ctx, map, pdname, sdname, &install_filepath);
                if (status != CL_SUCCESS)
                    goto done;
                if (install_filepath != NULL) {
                    cli_dbgmsg("\tInstalled to: %s\n", install_filepath);
                    CLI_FREE_AND_SET_NULL(install_filepath);
                }

                if (!(ptrs = cli_max_malloc(fcount * sizeof(uint32_t) * 3))) {
                    cli_dbgmsg("\tOOM\n");
                    status = CL_EMEM;
                    goto done;
                }
                lens  = &ptrs[fcount];
                olens = &ptrs[fcount * 2];
                for (j = 0; j < fcount; j++) {
                    status = sis_checktimelimit(ctx, "SIS metadata traversal reached the configured time limit");
                    if (status != CL_SUCCESS)
                        goto done;
                    GETD2(lens[j]);
                }
                for (j = 0; j < fcount; j++) {
                    status = sis_checktimelimit(ctx, "SIS metadata traversal reached the configured time limit");
                    if (status != CL_SUCCESS)
                        goto done;
                    GETD2(ptrs[j]);
                }
                for (j = 0; j < fcount; j++) {
                    status = sis_checktimelimit(ctx, "SIS metadata traversal reached the configured time limit");
                    if (status != CL_SUCCESS)
                        goto done;
                    GETD2(olens[j]);
                }

                if (ftype != FTnull) {
                    char ofn[1024];

                    /*
                     * There should be 1 version of the file for each language.
                     */
                    for (j = 0; j < fcount; j++) {
                        uint64_t member_output_size;
                        bool temporary_reserved = false;

                        status = sis_checktimelimit(ctx, "SIS metadata traversal reached the configured time limit");
                        if (status != CL_SUCCESS)
                            goto done;

                        if (!lens[j]) {
                            cli_dbgmsg("\tSkipping empty file\n");
                            continue;
                        }

                        if (SIZEOF_HEADER_UUIDS + sizeof(sis) > ptrs[j]) {
                            cli_dbgmsg("\tThe pointer (offset) of the file in the archive cannot be within the SIS header: %u\n", ptrs[j]);
                            /* A non-empty language member was declared, but
                             * its payload points into the package header. Do
                             * not silently discard it and let the package
                             * appear clean; preserve any valid sibling
                             * members while making this malformed layer
                             * fail-visible. */
                            cli_mark_scan_incomplete(ctx, "SIS member offset points inside the package header");
                            if (limit_status == CL_CLEAN)
                                limit_status = CL_EPARSE;
                            continue;
                        }

                        {
                            cl_error_t limitret = cli_checklimits("sis", ctx, lens[j], 0, 0);
                            if (limitret != CL_CLEAN) {
                                if (limitret != CL_ETIMEOUT)
                                    cli_mark_scan_incomplete(ctx, "SIS member exceeds configured scan limits");
                                if (limit_status == CL_CLEAN)
                                    limit_status = limitret;
                                continue;
                            }
                        }
                        cli_dbgmsg("\tUnpacking lang#%d - ptr:%x compressed size:%x original (decompressed) size:%x\n", j, ptrs[j], lens[j], olens[j]);

                        member_output_size = compd ? (uint64_t)olens[j] : (uint64_t)lens[j];
                        {
                            cl_error_t limitret = cli_checklimits("sis", ctx, member_output_size, 0, 0);
                            if (limitret != CL_CLEAN) {
                                if (limitret != CL_ETIMEOUT)
                                    cli_mark_scan_incomplete(ctx, "SIS decompressed member exceeds configured scan limits");
                                if (limit_status == CL_CLEAN)
                                    limit_status = limitret;
                                continue;
                            }
                        }

                        status = cli_scan_reserve_temporary(ctx, member_output_size);
                        if (status != CL_SUCCESS) {
                            if (limit_status == CL_CLEAN)
                                limit_status = status;
                            continue;
                        }
                        temporary_reserved = true;

                        snprintf(ofn, 1024, "%s" PATHSEP "sis%02d", tmpd, umped);
                        ofn[1023] = '\0';
                        if ((fd = open(ofn, O_RDWR | O_CREAT | O_TRUNC | O_BINARY, 0600)) == -1) {
                            cli_errmsg("SIS: unable to create output file %s - aborting.\n", ofn);
                            cli_scan_release_temporary(ctx, member_output_size);
                            status = CL_ECREAT;
                            goto done;
                        }

                        status = sis_stream_member_to_fd(ctx, map, ptrs[j], lens[j], member_output_size, compd, fd);
                        if (status != CL_SUCCESS) {
                            sis_note_cleanup_failure(ctx, &status, close(fd) != 0,
                                                     "SIS temporary output could not be closed");
                            fd = -1;
                            cli_scan_release_temporary(ctx, member_output_size);
                            if (limit_status == CL_CLEAN)
                                limit_status = status;
                            continue;
                        }

                        status = cli_magic_scan_desc_type_reserved(fd, ofn, ctx, CL_TYPE_ANY, original_filepath,
                                                                   LAYER_ATTRIBUTES_NONE);
                        sis_note_cleanup_failure(ctx, &status, close(fd) != 0,
                                                 "SIS temporary output could not be closed");
                        fd = -1;
                        if (temporary_reserved) {
                            cli_scan_release_temporary(ctx, member_output_size);
                            temporary_reserved = false;
                        }
                        if (CL_SUCCESS != status) {
                            goto done;
                        }

                        umped++;
                    }
                }

                CLI_FREE_AND_SET_NULL(original_filepath);
                CLI_FREE_AND_SET_NULL(ptrs);

                fcount = 2 * sizeof(uint32_t);
                break;
            }
            case PKGoption:
                cli_dbgmsg("SIS: I'm an option\n");
                GETD2(fcount);
                fcount *= sis.langs * 2 * sizeof(uint32_t);
                break;
            case PKGif:
                cli_dbgmsg("SIS: #if\n");
                GETD2(fcount);
                break;
            case PKGelsif:
                cli_dbgmsg("SIS: #elsif\n");
                GETD2(fcount);
                break;
            case PKGelse:
                cli_dbgmsg("SIS: #else\n");
                fcount = 0;
                break;
            case PKGendif:
                cli_dbgmsg("SIS: #endif\n");
                fcount = 0;
                break;
            default:
                cli_dbgmsg("SIS: Unknown PKGtype, expect troubles\n");
                fcount = 0;
        }
        SKIP(fcount);
    }

    status = (limit_status != CL_CLEAN) ? limit_status : CL_CLEAN;

done:
    if (-1 != fd) {
        sis_note_cleanup_failure(ctx, &status, close(fd) != 0,
                                 "SIS temporary output could not be closed");
    }
    CLI_FREE_AND_SET_NULL(original_filepath);
    CLI_FREE_AND_SET_NULL(ptrs);
    CLI_FREE_AND_SET_NULL(alangs);

    return status;
}

/*************************************************
     This is the handler for the new (post 9.x)
                  SIS file format.
 *************************************************/

enum { T_INVALID,
       T_STRING,
       T_ARRAY,
       T_COMPRESSED,
       T_VERSION,
       T_VERSIONRANGE,
       T_DATE,
       T_TIME,
       T_DATETIME,
       T_UID,
       T_UNUSED,
       T_LANGUAGE,
       T_CONTENTS,
       T_CONTROLLER,
       T_INFO,
       T_SUPPORTEDLANGUAGES,
       T_SUPPORTEDOPTIONS,
       T_PREREQUISITES,
       T_DEPENDENCY,
       T_PROPERTIES,
       T_PROPERTY,
       T_SIGNATURES,
       T_CERTIFICATECHAIN,
       T_LOGO,
       T_FILEDESCRIPTION,
       T_HASH,
       T_IF,
       T_ELSEIF,
       T_INSTALLBLOCK,
       T_EXPRESSION,
       T_DATA,
       T_DATAUNIT,
       T_FILEDATA,
       T_SUPPORTEDOPTION,
       T_CONTROLLERCHECKSUM,
       T_DATACHECKSUM,
       T_SIGNATURE,
       T_BLOB,
       T_SIGNATUREALGORITHM,
       T_SIGNATURECERTIFICATECHAIN,
       T_DATAINDEX,
       T_CAPABILITIES,
       T_MAXVALUE };

const char *sisfields[] = {"Invalid", "String", "Array", "Compressed", "Version", "VersionRange", "Date", "Time", "DateTime", "Uid", "Unused", "Language", "Contents", "Controller", "Info", "SupportedLanguages", "SupportedOptions", "Prerequisites", "Dependency", "Properties", "Property", "Signatures", "CertificateChain", "Logo", "FileDescription", "Hash", "If", "ElseIf", "InstallBlock", "Expression", "Data", "DataUnit", "FileData", "SupportedOption", "ControllerChecksum", "DataChecksum", "Signature", "Blob", "SignatureAlgorithm", "SignatureCertificateChain", "DataIndex", "Capabilities"};

#define ALIGN4(x) (((x) & ~3) + ((((x)&1) | (((x) >> 1) & 1)) << 2))

#define HERE printf("here\n"), abort();

struct SISTREAM {
    fmap_t *map;
    size_t pos;
    uint8_t buff[BUFSIZ];
    uint32_t smax;
    uint32_t sleft;
    long fnext[7];
    uint32_t fsize[7];
    unsigned int level;
    int incomplete;
    cl_error_t failure;
};

static cl_error_t sis9x_checktimelimit(cli_ctx *ctx, struct SISTREAM *s)
{
    cl_error_t status = sis_checktimelimit(ctx, "SIS 9.x field traversal reached the configured time limit");

    if (status != CL_SUCCESS) {
        s->incomplete = 1;
        if (s->failure == CL_CLEAN)
            s->failure = status;
    }

    return status;
}

static inline int getd(struct SISTREAM *s, uint32_t *v)
{
    if (s->sleft < 4) {
        size_t nread;
        memcpy(s->buff, s->buff + s->smax - s->sleft, s->sleft);
        nread = fmap_readn(s->map, &s->buff[s->sleft], s->pos, BUFSIZ - s->sleft);
        if (nread == (size_t)-1) {
            s->incomplete = 1;
            if (s->failure == CL_CLEAN)
                s->failure = CL_EREAD;
            return 1;
        }
        if ((s->sleft = s->smax = nread + s->sleft) < 4) {
            s->incomplete = 1;
            if (s->failure == CL_CLEAN)
                s->failure = CL_EPARSE;
            return 1;
        }
        s->pos += nread;
    }
    *v = cli_readint32(&s->buff[s->smax - s->sleft]);
    s->sleft -= 4;
    return 0;
}

static inline int getsize(struct SISTREAM *s)
{
    uint32_t *fsize = &s->fsize[s->level];
    if (getd(s, fsize) || !*fsize)
        return 1;
    if ((*fsize) >> 31 || (s->level && *fsize > s->fsize[s->level - 1] * 2)) {
        s->incomplete = 1;
        if (s->failure == CL_CLEAN)
            s->failure = CL_EPARSE;
        return 1;
    }
    /* To handle crafted archives we allow the content to overflow the container but only up to 2 times the container size */
    s->fnext[s->level] = s->pos - s->sleft + *fsize;
    return 0;
}

static inline int getfield(struct SISTREAM *s, uint32_t *field)
{
    int ret;
    if (!(ret = getd(s, field)))
        ret = getsize(s);
    if (!ret) {
        if (*field < T_MAXVALUE)
            cli_dbgmsg("SIS: %d:Got %s(%x) field with size %x\n", s->level, sisfields[*field], *field, s->fsize[s->level]);
        else
            cli_dbgmsg("SIS: %d:Got invalid(%x) field with size %x\n", s->level, *field, s->fsize[s->level]);
    }
    return ret;
}

static inline int skip(struct SISTREAM *s, uint32_t size)
{
    long seekto;
    cli_dbgmsg("SIS: skipping %x\n", size);
    if (s->sleft >= size)
        s->sleft -= size;
    else {
        seekto = size - s->sleft;
        if (seekto < 0) { /* in case sizeof(long)==sizeof(uint32_t) */
            s->incomplete = 1;
            if (s->failure == CL_CLEAN)
                s->failure = CL_EPARSE;
            return 1;
        }
        s->pos += seekto;
        /*     s->sleft = s->smax = fread(s->buff,1,BUFSIZ,s->f); */
        s->sleft = s->smax = 0;
    }
    return 0;
}

static inline int skipthis(struct SISTREAM *s)
{
    return skip(s, ALIGN4(s->fsize[s->level]));
}

static inline void seeknext(struct SISTREAM *s)
{
    s->pos = s->fnext[s->level];
    /*   s->sleft = s->smax = fread(s->buff,1,BUFSIZ,s->f); */
    s->sleft = s->smax = 0;
}

static cl_error_t real_scansis9x(cli_ctx *ctx, const char *tmpd)
{
    cl_error_t ret = CL_CLEAN;

    struct SISTREAM stream;
    struct SISTREAM *s = &stream;
    uint32_t field, optst[] = {T_CONTROLLERCHECKSUM, T_DATACHECKSUM, T_COMPRESSED};
    unsigned int i;

    s->map        = ctx->fmap;
    s->pos        = 0;
    s->smax       = 0;
    s->sleft      = 0;
    s->level      = 0;
    s->incomplete = 0;
    s->failure    = CL_CLEAN;

    ret = sis_checktimelimit(ctx, "SIS 9.x inspection reached the configured time limit");
    if (ret != CL_SUCCESS)
        return ret;

    if (getfield(s, &field) || field != T_CONTENTS)
        return sis_incomplete(ctx, "SIS 9.x contents field was truncated or invalid");
    s->level++;

    for (i = 0; i < 3;) {
        ret = sis9x_checktimelimit(ctx, s);
        if (ret != CL_SUCCESS)
            return ret;
        if (getfield(s, &field)) return sis_incomplete(ctx, "SIS 9.x option field was truncated");
        for (; i < 3; i++) {
            ret = sis9x_checktimelimit(ctx, s);
            if (ret != CL_SUCCESS)
                return ret;
            if (field == optst[i]) {
                if (skipthis(s)) return sis_incomplete(ctx, "SIS 9.x option field could not be skipped completely");
                i++;
                break;
            }
        }
    }
    if (field != T_COMPRESSED)
        return sis_incomplete(ctx, "SIS 9.x compressed contents field was missing");

    i = 0;
    while (1) { /* 1DATA */
        if (sis9x_checktimelimit(ctx, s) != CL_SUCCESS)
            break;
        if (getfield(s, &field) || field != T_DATA) break;

        s->level++;
        while (1) { /* DATA::ARRAY */
            uint32_t atype;
            if (sis9x_checktimelimit(ctx, s) != CL_SUCCESS)
                break;
            if (getfield(s, &field) || field != T_ARRAY || getd(s, &atype) || atype != T_DATAUNIT || s->fsize[s->level] < 4) break;
            s->fsize[s->level] -= 4;

            s->level++;
            while (s->fsize[s->level - 1]) { /* FOREACH DATA::ARRAY::DATAUNITs */
                if (sis9x_checktimelimit(ctx, s) != CL_SUCCESS || getsize(s))
                    break;
                cli_dbgmsg("SIS: %d:Got dataunit element with size %x\n", s->level, s->fsize[s->level]);
                if (ALIGN4(s->fsize[s->level]) < s->fsize[s->level - 1])
                    s->fsize[s->level - 1] -= ALIGN4(s->fsize[s->level]);
                else
                    s->fsize[s->level - 1] = 0;

                s->level++;
                while (1) { /* DATA::ARRAY::DATAUNIT[x]::ARRAY */
                    if (sis9x_checktimelimit(ctx, s) != CL_SUCCESS)
                        break;
                    if (getfield(s, &field) || field != T_ARRAY || getd(s, &atype) || atype != T_FILEDATA || s->fsize[s->level] < 4) break;
                    s->fsize[s->level] -= 4;

                    s->level++;
                    while (s->fsize[s->level - 1]) { /* FOREACH DATA::ARRAY::DATAUNIT[x]::ARRAY::FILEDATA */
                        uint32_t usize, usizeh, len;
                        char tempf[1024];
                        int fd;
                        uint64_t member_input_size;
                        uint64_t member_output_size;
                        bool temporary_reserved = false;

                        if (sis9x_checktimelimit(ctx, s) != CL_SUCCESS || getsize(s))
                            break;

                        cli_dbgmsg("SIS: %d:Got filedata element with size %x\n", s->level, s->fsize[s->level]);
                        if (ALIGN4(s->fsize[s->level]) < s->fsize[s->level - 1])
                            s->fsize[s->level - 1] -= ALIGN4(s->fsize[s->level]);
                        else
                            s->fsize[s->level - 1] = 0;

                        s->level++;
                        while (1) { /* DATA::ARRAY::DATAUNIT[x]::ARRAY::FILEDATA[x]::COMPRESSED */
                            if (sis9x_checktimelimit(ctx, s) != CL_SUCCESS)
                                break;
                            if (getfield(s, &field) || field != T_COMPRESSED || getd(s, &field) || getd(s, &usize) || getd(s, &usizeh) || usizeh) break;
                            s->fsize[s->level] -= 12;
                            cli_dbgmsg("SIS: File is%s compressed - size %x -> %x\n", (field) ? "" : " not", s->fsize[s->level], usize);
                            snprintf(tempf, 1024, "%s" PATHSEP "sis9x%02d", tmpd, i++);
                            tempf[1023] = '\0';
                            s->pos -= (long)s->sleft;
                            s->sleft = s->smax = 0;
                            len                = ALIGN4(s->fsize[s->level]);
                            /* The field is four-byte aligned on disk, but
                             * compressed data uses its exact declared length;
                             * the alignment bytes are skipped with the
                             * surrounding field cursor below. */
                            member_input_size  = field ? (uint64_t)s->fsize[s->level] : (uint64_t)len;
                            member_output_size = field ? (uint64_t)usize : (uint64_t)len;

                            {
                                cl_error_t limitret = cli_checklimits("sis", ctx, member_input_size, 0, 0);
                                if (limitret != CL_CLEAN) {
                                    if (limitret != CL_ETIMEOUT)
                                        cli_mark_scan_incomplete(ctx, "SIS 9.x member exceeds configured scan limits");
                                    s->incomplete = 1;
                                    if (s->failure == CL_CLEAN)
                                        s->failure = limitret;
                                    break;
                                }
                            }
                            {
                                cl_error_t limitret = cli_checklimits("sis", ctx, member_output_size, 0, 0);
                                if (limitret != CL_CLEAN) {
                                    if (limitret != CL_ETIMEOUT)
                                        cli_mark_scan_incomplete(ctx, "SIS 9.x decompressed member exceeds configured scan limits");
                                    s->incomplete = 1;
                                    if (s->failure == CL_CLEAN)
                                        s->failure = limitret;
                                    break;
                                }
                            }
                            if ((ret = cli_scan_reserve_temporary(ctx, member_output_size)) != CL_SUCCESS) {
                                s->incomplete = 1;
                                if (s->failure == CL_CLEAN)
                                    s->failure = ret;
                                break;
                            }
                            temporary_reserved = true;

                            if ((fd = open(tempf, O_RDWR | O_CREAT | O_TRUNC | O_BINARY, 0600)) == -1) {
                                cli_errmsg("SIS: unable to create output file %s - aborting.\n", tempf);
                                s->incomplete = 1;
                                if (s->failure == CL_CLEAN)
                                    s->failure = CL_ECREAT;
                                cli_scan_release_temporary(ctx, member_output_size);
                                temporary_reserved = false;
                                break;
                            }

                            ret = sis_stream_member_to_fd(ctx, s->map, s->pos, member_input_size,
                                                          member_output_size, field != 0, fd);
                            s->pos += len;
                            if (ret != CL_SUCCESS) {
                                s->incomplete = 1;
                                if (s->failure == CL_CLEAN)
                                    s->failure = ret;
                                sis_note_cleanup_failure(ctx, &ret, close(fd) != 0,
                                                         "SIS 9.x temporary output could not be closed");
                                fd = -1;
                                cli_scan_release_temporary(ctx, member_output_size);
                                temporary_reserved = false;
                                break;
                            }

                            ret = cli_magic_scan_desc_type_reserved(fd, tempf, ctx, CL_TYPE_ANY, NULL,
                                                                    LAYER_ATTRIBUTES_NONE);
                            sis_note_cleanup_failure(ctx, &ret, close(fd) != 0,
                                                     "SIS 9.x temporary output could not be closed");
                            fd = -1;
                            if (temporary_reserved) {
                                cli_scan_release_temporary(ctx, member_output_size);
                                temporary_reserved = false;
                            }
                            if (CL_SUCCESS != ret) {
                                return ret;
                            }
                            break;
                        } /* DATA::ARRAY::DATAUNIT[x]::ARRAY::FILEDATA[x]::COMPRESSED */
                        s->level--;
                        seeknext(s);
                    } /* FOREACH DATA::ARRAY::DATAUNIT[x]::ARRAY::FILEDATAs */
                    s->level--;
                    break;
                } /* DATA::ARRAY::DATAUNIT[x]::ARRAY */
                s->level--;
                seeknext(s);
            } /* FOREACH DATA::ARRAY::DATAUNITs */
            s->level--;
            break;
        } /* DATA::ARRAY */
        s->level--;
        seeknext(s);
    }
    if (s->incomplete) {
        if (s->failure != CL_ETIMEOUT)
            cli_mark_scan_incomplete(ctx, "SIS 9.x content stream was incomplete");
        return (s->failure == CL_CLEAN) ? CL_EPARSE : s->failure;
    }
    return ret;
}

/*************************************************
  An (incomplete) FSM approach to sis9x unpacking
    maybe needed if sisdataindex gets exploited
 *************************************************/

/* #include <stdio.h> */
/* #include <stdint.h> */
/* #include <stdlib.h> */
/* #include <string.h> */
/* #include <zlib.h> */

/*   /\* FIXME: RESEEK before spamming strings if not compressed *\/ */
/* #define SPAMSARRAY(WHO) \ */
/*   GETD(field); \ */
/*   fsz-=4; \ */
/*   if(field!=T_STRING) { \ */
/*     printf(WHO" - Unexpected array type, skipping\n"); \ */
/*     break; \ */
/*   } \ */
/*   while(fsz>4) { \ */
/*     GETD(field); \ */
/*     fsz-=4; \ */
/*     if(field && fsz<=sleft && field<=fsz) { \ */
/*       stringifycbuff(&cbuff[smax-sleft], field); \ */
/*       printf(WHO" - \"%s\"\n", &cbuff[smax-sleft]); \ */
/*     } else { \ */
/*       printf(WHO" - Name not decoded\n"); \ */
/*       break; \ */
/*     } \ */
/*     SKIP(ALIGN4(field)); \ */
/*     fsz-=(ALIGN4(field)); \ */
/*     if((int32_t)fsz<0) fsz=0; \ */
/*   } */

/* enum { T_INVALID, T_STRING, T_ARRAY, T_COMPRESSED, T_VERSION, T_VERSIONRANGE, T_DATE, T_TIME, T_DATETIME, T_UID, T_UNUSED, T_LANGUAGE, T_CONTENTS, T_CONTROLLER, T_INFO, T_SUPPORTEDLANGUAGES, T_SUPPORTEDOPTIONS, T_PREREQUISITES, T_DEPENDENCY, T_PROPERTIES, T_PROPERTY, T_SIGNATURES, T_CERTIFICATECHAIN, T_LOGO, T_FILEDESCRIPTION, T_HASH, T_IF, T_ELSEIF, T_INSTALLBLOCK, T_EXPRESSION, T_DATA, T_DATAUNIT, T_FILEDATA, T_SUPPORTEDOPTION, T_CONTROLLERCHECKSUM, T_DATACHECKSUM, T_SIGNATURE, T_BLOB, T_SIGNATUREALGORITHM, T_SIGNATURECERTIFICATECHAIN, T_DATAINDEX, T_CAPABILITIES, T_MAXVALUE, CUST_SKIP }; */

/* #define GETD(VAR) \ */
/*   if (cbuff) { \ */
/*     if (sleft<4) { \ */
/*       printf("Unexpectedly reached end of compressed buffer\n"); \ */
/*       free(cbuff); \ */
/*       cbuff=NULL; \ */
/*       smax=sleft=0; \ */
/*     } else { \ */
/*       VAR = cli_readint32(&cbuff[smax-sleft]); \ */
/*       sleft-=4; \ */
/*     } \ */
/*   } else { \ */
/*     if (sleft<4) { \ */
/*       memcpy(buff, buff+smax-sleft, sleft); \ */
/*       if ((smax=fread(buff+sleft,1,BUFSIZ-sleft,f)+sleft)<4) { \ */
/* 	printf("EOF\n"); \ */
/* 	return -1; \ */
/*       } \ */
/*       sleft=smax; \ */
/*     } \ */
/*     VAR = cli_readint32(&buff[smax-sleft]); \ */
/*     sleft-=4; \ */
/*   } */

/* #define SKIP(N) \ */
/*   if (cbuff && sleft<=(N)) { \ */
/*     free(cbuff); \ */
/*     cbuff=NULL; \ */
/*     smax=sleft=0; \ */
/*   } \ */
/*   if (sleft>=(N)) sleft-=(N); \ */
/*   else { \ */
/*     if ((ssize_t)((N)-sleft)<0) { \ */
/*       printf("Refusing to seek back\n"); \ */
/*       return -1; \ */
/*     } \ */
/*     fseek(f, (N)-sleft, SEEK_CUR); \ */
/*     sleft=smax=fread(buff,1,BUFSIZ,f); \ */
/*   } */

/* #define RESEEK() \ */
/*   if (!cbuff) { \ */
/*     fseek(f, -(long)sleft, SEEK_CUR); \ */
/*     sleft=smax=fread(buff,1,BUFSIZ,f); \ */
/*   } */

/* #define GETSZ \ */
/*   GETD(fsz); \ */
/*   if(fsz>>31) { \ */
/*     printf("Size too big\n"); \ */
/*     return -1; \ */
/*   } */

/* #define GETSIZE(TREE) \ */
/*   GETD(fsz); \ */
/*   if(!fsz || (fsz>>31)) { \ */
/*     printf(TREE" - Wrong field size\n"); \ */
/*     goto SIS_ERROR; \ */
/*   } */

/* static void stringifycbuff(uint8_t *ptr, uint32_t len) { */
/*   uint32_t i; */

/*   if (len>400) len=400; */
/*   for(i = 0 ; i < len; i+=2) ptr[i/2] = ptr[i]; */
/*   ptr[i/2]='\0'; */
/*   return; */
/* } */

/* const char *sisfields[] = {"Invalid", "String", "Array", "Compressed", "Version", "VersionRange", "Date", "Time", "DateTime", "Uid", "Unused", "Language", "Contents", "Controller", "Info", "SupportedLanguages", "SupportedOptions", "Prerequisites", "Dependency", "Properties", "Property", "Signatures", "CertificateChain", "Logo", "FileDescription", "Hash", "If", "ElseIf", "InstallBlock", "Expression", "Data", "DataUnit", "FileData", "SupportedOption", "ControllerChecksum", "DataChecksum", "Signature", "Blob", "SignatureAlgorithm", "SignatureCertificateChain", "DataIndex", "Capabilities", "PLACEHOLDER"}; */

/* const char *sislangs[] = {"UNKNOWN", "UK English","French", "German", "Spanish", "Italian", "Swedish", "Danish", "Norwegian", "Finnish", "American", "Swiss French", "Swiss German", "Portuguese", "Turkish", "Icelandic", "Russian", "Hungarian", "Dutch", "Belgian Flemish", "Australian English", "Belgian French", "Austrian German", "New Zealand English", "International French", "Czech", "Slovak", "Polish", "Slovenian", "Taiwanese Chinese", "Hong Kong Chinese", "PRC Chinese", "Japanese", "Thai", "Afrikaans", "Albanian", "Amharic", "Arabic", "Armenian", "Tagalog", "Belarussian", "Bengali", "Bulgarian", "Burmese", "Catalan", "Croation", "Canadian English", "International English", "South African English", "Estonian", "Farsi", "Canadian French", "Gaelic", "Georgian", "Greek", "Cyprus Greek", "Gujarati", "Hebrew", "Hindi", "Indonesian", "Irish", "Swiss Italian", "Kannada", "Kazakh", "Kmer", "Korean", "Lao", "Latvian", "Lithuanian", "Macedonian", "Malay", "Malayalam", "Marathi", "Moldovian", "Mongolian", "Norwegian Nynorsk", "Brazilian Portuguese", "Punjabi", "Romanian", "Serbian", "Sinhalese", "Somali", "International Spanish", "American Spanish", "Swahili", "Finland Swedish", "Reserved", "Tamil", "Telugu", "Tibetan", "Tigrinya", "Cyprus Turkish", "Turkmen", "Ukrainian", "Urdu", "Reserved", "Vietnamese", "Welsh", "Zulu", "Other"}; */
/* #define MAXLANG (sizeof(sislangs)/sizeof(sislangs[0])) */

/* int main(int argc, char **argv) { */
/*   FILE *f = fopen(argv[1], "r"); */
/*   uint32_t uid[4]; */
/*   unsigned int i, sleft=0, smax=0, level=0; */
/*   uint8_t buff[BUFSIZ], *cbuff=NULL; */
/*   uint32_t field, fsz; */
/*   int ret = 0; */

/*   struct { */
/*     char tree[200]; */
/*     unsigned int next[200]; */
/*     unsigned int count; */
/*   } sstack; */

/*   const struct PIPPO { */
/*     uint32_t expect; */
/*     uint8_t optional; */
/*     uint8_t dir; */
/*     struct PIPPO *next; */
/*     char *what; */
/*   } s[] = { */
/*     { T_CONTENTS,                   0, 1, &s[1], ""}, */
/*     { T_CONTROLLERCHECKSUM,         1, 0, &s[2], ""}, */
/*     { T_DATACHECKSUM,               1, 0, &s[3], ""}, */
/*     { T_COMPRESSED,                 0, 1, &s[4], ""}, */
/*     { T_CONTROLLER,                 0, 1, &s[5], ""}, */
/*     { T_INFO,                       0, 1, &s[6], ""}, */
/*     { T_UID,                        0, 0, &s[7], "App UID"}, */
/*     { T_STRING,                     0, 0, &s[8], "Vendor name"}, */
/*     { T_ARRAY,                      0, 0, &s[9], "App names"}, */
/*     { T_ARRAY,                      0, 0, &s[10], "Vendor names"}, */
/*     { T_VERSION,                    0, 0, &s[11], "App Version"}, */
/*     { T_DATETIME,                   0, 0, &s[12], ""}, */
/*     { T_DATE,                       0, 0, &s[13], "Creation Date"}, */
/*     { T_TIME,                       0, 0, &s[14], "Creation Time"}, */
/*     { CUST_SKIP,                    4, 0, &s[15], ""}, */
/*     { T_SUPPORTEDOPTIONS,           0, 2, &s[16], ""}, */
/*     { T_SUPPORTEDLANGUAGES,         0, 1, &s[17], ""}, */
/*     { T_ARRAY,                      0, 0, &s[18], "Supported Languages"}, */
/*     { T_PREREQUISITES,              0, 2, &s[19], ""}, */
/*     { T_PROPERTIES,                 0, 0, &s[20], ""}, */
/*     { T_LOGO,                       1, 0, &s[21], ""}, */
/*     { T_INSTALLBLOCK,               0, 0, &s[22], ""}, */
/*     { T_SIGNATURECERTIFICATECHAIN,  1, 0, &s[23], ""}, */
/*     { T_DATAINDEX,                  0, 0, &s[24], ""}, */
/*     { T_DATA,                       0, 3, NULL, NULL} */
/*   }; */
/*   struct PIPPO *this; */

/*   struct { */
/*     struct PIPPO s; */
/*     uint32_t totalsize; */
/*     struct PIPPO *next; */
/*   } t_array; */

/*   GETD(uid[0]); */
/*   GETD(uid[1]); */
/*   GETD(uid[2]); */
/*   GETD(uid[3]); */

/*   printf("UIDS: %x %x %x - %x\n",uid[0],uid[1],uid[2],uid[3]); */

/*   sstack.next[0]=0; */
/*   sstack.count=0; */

/*   for (this=&s[0]; this; this=this->next) { */
/*     if(this->expect==CUST_SKIP) { */
/*       SKIP(this->optional); */
/*       continue; */
/*     } */
/*     if (this!=&t_array) { */
/*       GETD(field); */
/*       GETSIZE("FIXME"); */
/*     } else { */
/*       GETSIZE("FIXME"); */
/*       if (t_array.totalsize<=(ALIGN4(fsz)+4)) */
/* 	this->next = t_array.next; */
/*       t_array.totalsize-=ALIGN4(fsz)+4; */
/*       field = this->expect; */
/*     } */
/*     if(field>=T_MAXVALUE) { */
/*       printf("Bogus field found\n"); */
/*       ret=-1; */
/*       break; */
/*     } */
/*     for( ; this && this->optional && this->expect!=field; this=this->next) */
/*       printf("Skipping optional state %s\n", sisfields[this->expect]); */
/*     if(!this) { */
/*       printf("Broken SIS file\n"); */
/*       break; */
/*     } */
/*     if(!this->optional && this->expect!=field) { */
/*       printf("Error: expected %s but found %s\n", sisfields[this->expect], sisfields[field]); */
/*       goto SIS_ERROR; */
/*     } */
/*     printf("Got %s field (%d) with size %x(%u)\n", sisfields[field], field, fsz, fsz); */

/*     switch(this->dir) { */
/*     case 1: /\* up *\/ */
/*       strncpy(&sstack.tree[sstack.next[sstack.count]], sisfields[field], 200-sstack.next[sstack.count]); */
/*       strncat(sstack.tree, ":", 200); */
/*       sstack.count++; */
/*       sstack.tree[199]='\0'; */
/*       sstack.next[sstack.count]=strlen(sstack.tree); */
/*       break; */
/*     case 0: */
/*       sstack.count--; */
/*     default: */
/*       sstack.count-=this->dir-1; */
/*       strncpy(&sstack.tree[sstack.next[sstack.count]], sisfields[field], 200-sstack.next[sstack.count]); */
/*       strncat(sstack.tree, ":", 200); */
/*       sstack.tree[199]='\0'; */
/*     } */

/*     printf("%s\n", sstack.tree); */

/*     switch(field) { */
/*     case T_CONTENTS: */
/*       continue; */
/*     case T_CONTROLLERCHECKSUM: */
/*       break; */
/*     case T_DATACHECKSUM: */
/*       break; */
/*     case T_COMPRESSED: */
/*       if(cbuff) { */
/* 	printf("Found nested compressed streams, aborting\n"); */
/* 	goto SIS_ERROR; */
/*       } else { */
/* 	uint32_t method; */
/* 	uint32_t usize; */
/* 	uint32_t misc; */
/* 	int zresult; */
/* 	uint8_t *dbuff; */
/* 	uLongf uusize; */

/* 	GETD(method); */
/* 	GETD(usize); */
/* 	GETD(misc); */
/* 	fsz-=12; */
/* 	if (misc) { */
/* 	  printf("%s filesize too big\n", sstack.tree); */
/* 	  goto SIS_ERROR; */
/* 	} */
/* 	printf("%s compression %d, size %d, usize %d\n", sstack.tree, method, fsz, usize); */
/* 	if(method) { */
/* 	  fseek(f, -(long)sleft, SEEK_CUR); */
/* 	  sleft=smax=0; */
/* 	  uusize=usize; */
/* 	  if(!(dbuff=malloc(ALIGN4(fsz)))) { */
/* 	    printf("%s Out of memory\n", sstack.tree); */
/* 	    goto SIS_ERROR; */
/* 	  } */
/* 	  if(!(cbuff=malloc(usize))) { */
/* 	    free(dbuff); */
/* 	    printf("%s Out of memory\n", sstack.tree); */
/* 	    goto SIS_ERROR; */
/* 	  } */
/* 	  if (fread(dbuff,ALIGN4(fsz),1,f) != 1) { */
/* 	    printf("%s Failed to read compressed data\n", sstack.tree); */
/* 	    free(dbuff); */
/* 	    goto SIS_ERROR; */
/* 	  } */
/* 	  zresult=uncompress(cbuff, &uusize, dbuff, fsz); */
/* 	  free(dbuff); */
/* 	  if (zresult!=Z_OK) { */
/* 	    printf("%s Unpacking failure, skipping block\n", sstack.tree); */
/* 	    goto SIS_ERROR; */
/* 	  } */
/* 	  if ((uLongf)usize != uusize) { */
/* 	    printf("%s Expected size %lx but got %lx\n", sstack.tree, (uLongf)usize, uusize); */
/* 	    goto SIS_ERROR; */
/* 	  } */
/* 	  smax=sleft=uusize; */
/* 	  fwrite(cbuff, uusize, 1, fopen("/tmp/gunz", "w")); */
/* 	} */
/* 	continue; */
/*       } */
/*     case T_CONTROLLER: */
/*       continue; */
/*     case T_INFO: */
/*       continue; */
/*     case T_UID: */
/*       GETD(field); */
/*       fsz-=4; */
/*       printf("%s %s = %x\n", sstack.tree, this->what, field); */
/*       break; */
/*     case T_STRING: */
/*       RESEEK(); */
/*       if(fsz && fsz<=sleft) { */
/* 	char *t=(cbuff)?&cbuff[smax-sleft]:&buff[smax-sleft]; */
/* 	stringifycbuff(t, fsz); */
/* 	printf("%s %s = \"%s\"\n", sstack.tree, this->what, t); */
/*       } else printf("%s %s not decoded\n", sstack.tree, this->what); */
/*       break; */
/*     case T_ARRAY: */
/*       GETD(field); */
/*       fsz-=4; */
/*       t_array.s.expect = field; */
/*       t_array.s.optional = 0; */
/*       t_array.s.dir = 0; */
/*       t_array.s.next = &t_array; */
/*       t_array.s.what = this->what; */
/*       t_array.next = this->next; */
/*       t_array.totalsize = ALIGN4(fsz); */
/*       this = &t_array; */
/*       continue; */
/*     case T_VERSION: { */
/*       uint32_t maj,min,bld; */
/*       GETD(maj); */
/*       GETD(min); */
/*       GETD(bld); */
/*       printf("%s %s = %u.%u.%u\n", sstack.tree, this->what, maj, min, bld); */
/*       fsz-=12; */
/*       break; */
/*     } */
/*     case T_DATETIME: */
/*       continue; */
/*     case T_DATE: */
/*       GETD(field); */
/*       fsz-=4; */
/*       printf("%s %s = %u-%u-%u\n", sstack.tree, this->what, field&0xffff, (field>>16)&0xff, (field>>24)&0xff); */
/*       break; */
/*     case T_TIME: */
/*       GETD(field); */
/*       fsz-=4; /\* -1 aligns to 0 *\/ */
/*       printf("%s %s = %u:%u:%u\n", sstack.tree, this->what, field&0xff, (field>>8)&0xff, (field>>16)&0xff); */
/*       break; */
/*     case T_SUPPORTEDOPTIONS: */
/*       /\* FIXME: ANYTHING USEFUL HERE? *\/ */
/*       break; */
/*     case T_SUPPORTEDLANGUAGES: */
/*       continue; */
/*     case T_LANGUAGE: */
/*       GETD(field); */
/*       fsz-=4; */
/*        printf("%s %s = \"%s\"\n", sstack.tree, this->what, field>=MAXLANG ? "Bad Language" : sislangs[field]); */
/*        break; */
/*     case T_PREREQUISITES: */
/*       break; */
/*     case T_PROPERTIES: */
/*       break; */
/*     case T_LOGO: */
/*       break; */
/*     case T_INSTALLBLOCK: */
/*       break; */
/*     case T_SIGNATURECERTIFICATECHAIN: */
/*       t_array.s.expect = field; */
/*       t_array.s.optional = 1; */
/*       t_array.s.dir = 0; */
/*       t_array.s.next = this; */
/*       this = &t_array; */
/*       break; */
/*     case T_DATAINDEX: */
/*       GETD(field); */
/*       fsz-=4; */
/*       printf("%s %s = %x\n", sstack.tree, this->what, field); */
/*       if(cbuff) { */
/* 	if(ALIGN4(fsz) || sleft) */
/* 	  printf("Trailing garbage found in compressed controller\n"); */
/* 	fsz=sleft=smax=0; */
/* 	free(cbuff); */
/* 	cbuff=NULL; */
/*       } */
/*       break; */
/*     default: */
/*       printf("Error: unhandled field %d\n", field); */
/*       goto SIS_ERROR; */
/*     } */
/*     SKIP(ALIGN4(fsz)); */
/*   } */
/*   return 0; */

/*   SIS_ERROR: */
/*   if(cbuff) free(cbuff); */
/*   fclose(f); */
/*   return 0; */
/* } */
