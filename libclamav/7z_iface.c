/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2011-2013 Sourcefire, Inc.
 *
 *  Authors: aCaB
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

#if defined(_WIN32)
#include <WinSock2.h>
#include <Windows.h>
#endif

#include "clamav.h"
#include "7z_iface.h"
#include "lzma_iface.h"
#include "scanners.h"
#include "others.h"
#include "fmap.h"

#include "7z/7z.h"
#include "7z/7zAlloc.h"
#include "7z/7zFile.h"

static ISzAlloc allocImp = {__lzma_wrap_alloc, __lzma_wrap_free}, allocTempImp = {__lzma_wrap_alloc, __lzma_wrap_free};

/* File-type matching only proves the six-byte 7-Zip signature.  Embedded SFX
 * candidates need the complete start header before they are allowed to become
 * a nested layer; otherwise arbitrary payload bytes can be misclassified as a
 * malformed archive and taint an otherwise complete parent scan. */
cl_error_t cli_7z_header_check(cli_ctx *ctx, size_t offset)
{
    const unsigned char *header;
    uint64_t archive_size;
    uint64_t next_header_offset;
    uint64_t next_header_size;

    if (ctx == NULL || ctx->fmap == NULL)
        return CL_ENULLARG;

    if (offset > ctx->fmap->len || ctx->fmap->len - offset < k7zStartHeaderSize)
        return CL_EFORMAT;

    header = (const unsigned char *)fmap_need_off_once(ctx->fmap, offset, k7zStartHeaderSize);
    if (header == NULL || memcmp(header, k7zSignature, k7zSignatureSize) != 0)
        return CL_EFORMAT;

    if (header[6] != k7zMajorVersion)
        return CL_EPARSE;

    /* The recovery-mode reader handles an all-zero next-header tuple by
     * searching the tail, so leave that valid parser behavior intact. */
    next_header_offset = (uint64_t)cli_readint64(header + 12);
    next_header_size   = (uint64_t)cli_readint64(header + 20);
    if (next_header_offset == 0 && next_header_size == 0)
        return CL_SUCCESS;

    archive_size = (uint64_t)(ctx->fmap->len - offset);
    if (archive_size < k7zStartHeaderSize ||
        next_header_offset > archive_size - k7zStartHeaderSize ||
        next_header_size > archive_size - k7zStartHeaderSize - next_header_offset)
        return CL_EPARSE;

    return CL_SUCCESS;
}

typedef struct
{
    ISeqOutStream s;
    int fd;
} CClamFileOutStream;

static size_t ClamFileOutStream_Write(void *pp, const void *data, size_t size)
{
    CClamFileOutStream *p = (CClamFileOutStream *)pp;
    size_t written = cli_writen(p->fd, data, size);

    /* ISeqOutStream uses a short write (zero here) to report failure. Do not
     * pass cli_writen()'s (size_t)-1 sentinel to the 7-Zip CRC wrapper: it
     * would be interpreted as an enormous successful write. */
    return (written == (size_t)-1) ? 0 : written;
}

static SRes FileInStream_fmap_Read(void *pp, void *buf, size_t *size)
{
    CFileInStream *p = (CFileInStream *)pp;
    size_t read_sz;

    if (*size == 0)
        return 0;

    read_sz = fmap_readn(p->file.fmap, buf, p->s.curpos, *size);
    if (read_sz == (size_t)-1) {
        *size = 0;
        return SZ_ERROR_READ;
    }

    p->s.curpos += read_sz;

    *size = read_sz;
    return SZ_OK;
}

static SRes FileInStream_fmap_Seek(void *pp, Int64 *pos, ESzSeek origin)
{
    CFileInStream *p = (CFileInStream *)pp;
    Int64 map_length;
    Int64 base;

    if (p == NULL || p->file.fmap == NULL || pos == NULL)
        return 1;

    map_length = (Int64)p->file.fmap->len;
    if (map_length < 0 || p->s.curpos < 0 || (Int64)p->s.curpos > map_length)
        return 1;

    switch (origin) {
        case SZ_SEEK_SET:
            base = 0;
            break;
        case SZ_SEEK_CUR:
            base = (Int64)p->s.curpos;
            break;
        case SZ_SEEK_END:
            base = map_length;
            break;
        default:
            return 1;
    }

    /* The position must remain within the fmap. Comparing before adding also
     * handles INT64_MIN without negating it and prevents signed overflow. */
    if (*pos < -base || *pos > map_length - base)
        return 1;

    *pos         = base + *pos;
    p->s.curpos  = (off_t)*pos;
    return 0;
}

#define UTFBUFSZ 256
int cli_7unz(cli_ctx *ctx, size_t offset)
{
    CFileInStream archiveStream;
    CLookToRead lookStream;
    CSzArEx db;
    SRes res;
    UInt16 utf16buf[UTFBUFSZ], *utf16name = utf16buf;
    int namelen            = UTFBUFSZ;
    cl_error_t found       = CL_CLEAN;
    Int64 begin_of_archive = offset;

    /* Replacement for
       FileInStream_CreateVTable(&archiveStream); */
    archiveStream.s.Read    = FileInStream_fmap_Read;
    archiveStream.s.Seek    = FileInStream_fmap_Seek;
    archiveStream.s.curpos  = 0;
    archiveStream.file.fmap = ctx->fmap;

    LookToRead_CreateVTable(&lookStream, False);

    if (archiveStream.s.Seek(&archiveStream.s, &begin_of_archive, SZ_SEEK_SET) != 0) {
        cli_mark_scan_incomplete(ctx, "7-Zip archive start could not be reached");
        return CL_ESEEK;
    }

    lookStream.realStream = &archiveStream.s;
    LookToRead_Init(&lookStream);

    SzArEx_Init(&db);
    res = SzArEx_Open(&db, &lookStream.s, &allocImp, &allocTempImp);
    if (res == SZ_ERROR_ENCRYPTED && SCAN_HEURISTIC_ENCRYPTED_ARCHIVE) {
        cli_dbgmsg("cli_7unz: Encrypted header found in archive.\n");
        found = cli_append_potentially_unwanted(ctx, "Heuristics.Encrypted.7Zip");
    } else if (res == SZ_OK) {
        UInt32 i, blockIndex = 0xFFFFFFFF;
        Byte *outBuffer      = NULL;
        size_t outBufferSize = 0;
        unsigned int encrypted = 0;

        for (i = 0; i < db.db.NumFiles; i++) {
            UInt64 outSizeProcessed = 0;
            const CSzFileItem *f    = db.db.Files + i;
            char *name;
            char *tmp_name;
            size_t j;
            int newnamelen, fd;
            cl_error_t limitret;
            CClamFileOutStream output;

            // abort if we would exceed max files or max scan time.
            if ((found = cli_checklimits("7unz", ctx, 0, 0, 0)))
                break;

            if (f->IsDir)
                continue;

            // skip this file if we would exceed max file size or max scan size. (we already checked for the max files and max scan time)
            limitret = cli_checklimits("7unz", ctx, f->Size, 0, 0);
            if (limitret != CL_SUCCESS) {
                if (limitret != CL_ETIMEOUT)
                    cli_mark_scan_incomplete(ctx, "7-Zip member exceeds configured scan limits");
                if (found == CL_CLEAN)
                    found = limitret;
                continue;
            }

            if (!db.FileNameOffsets)
                newnamelen = 0; /* no filename */
            else {
                newnamelen = SzArEx_GetFileNameUtf16(&db, i, NULL);
                if (newnamelen > namelen) {
                    if (namelen > UTFBUFSZ)
                        free(utf16name);
                    utf16name = cli_max_malloc(newnamelen * 2);
                    if (!utf16name) {
                        found = CL_EMEM;
                        break;
                    }
                    namelen = newnamelen;
                }
                SzArEx_GetFileNameUtf16(&db, i, utf16name);
            }

            name = (char *)utf16name;
            for (j = 0; j < (size_t)newnamelen; j++) /* FIXME */
                name[j] = utf16name[j];
            name[j] = 0;
            cli_dbgmsg("cli_7unz: extracting %s\n", name);

            if ((found = cli_gentempfd(ctx->this_layer_tmpdir, &tmp_name, &fd)))
                break;
            output.s.Write = ClamFileOutStream_Write;
            output.fd       = fd;
            res = SzArEx_ExtractToStream(&db, &lookStream.s, i, &output.s,
                                         &outSizeProcessed, &allocImp, &allocTempImp);
            if (res == SZ_ERROR_UNSUPPORTED) {
                UInt32 folderIndex = db.FileIndexToFolderIndexMap[i];
                UInt64 folderSize = 0;
                int allow_legacy = folderIndex == (UInt32)-1;
                if (!allow_legacy && folderIndex < db.db.NumFolders) {
                    folderSize = SzFolder_GetUnpackSize(&db.db.Folders[folderIndex]);
                    allow_legacy = folderSize <= CLI_MAX_ALLOCATION;
                }
                if (allow_legacy) {
                    size_t legacyOffset = 0;
                    size_t legacySize   = 0;
                    res = SzArEx_Extract(&db, &lookStream.s, i, &blockIndex,
                                         &outBuffer, &outBufferSize, &legacyOffset,
                                         &legacySize, &allocImp, &allocTempImp);
                    if (res == SZ_OK && legacySize != 0) {
                        if (cli_writen(fd, outBuffer + legacyOffset, legacySize) != legacySize) {
                            cli_mark_scan_incomplete(ctx, "7-Zip legacy member output could not be written completely");
                            res = SZ_ERROR_WRITE;
                        } else {
                            outSizeProcessed = legacySize;
                        }
                    }
                } else {
                    cli_dbgmsg("cli_7unz: refusing whole-folder fallback for " STDu64 " bytes\n", folderSize);
                }
            }
            if (res == SZ_ERROR_ENCRYPTED) {
                encrypted = 1;
                if (SCAN_HEURISTIC_ENCRYPTED_ARCHIVE) {
                    cli_dbgmsg("cli_7unz: Encrypted files found in archive.\n");
                    found = cli_append_potentially_unwanted(ctx, "Heuristics.Encrypted.7Zip");
                    if (found != CL_SUCCESS) {
                        close(fd);
                        if (!ctx->engine->keeptmp)
                            (void)cli_unlink(tmp_name);
                        free(tmp_name);
                        break;
                    }
                }
            }
            if (CL_VIRUS == cli_matchmeta(ctx, name, 0, f->Size, encrypted, i, f->CrcDefined ? f->Crc : 0)) {
                found = CL_VIRUS;
                close(fd);
                if (!ctx->engine->keeptmp)
                    (void)cli_unlink(tmp_name);
                free(tmp_name);
                break;
            }
            if (res != SZ_OK) {
                cli_dbgmsg("cli_unz: extraction failed with %d\n", res);
                if (res != SZ_ERROR_ENCRYPTED || !SCAN_HEURISTIC_ENCRYPTED_ARCHIVE) {
                    cli_mark_scan_incomplete(ctx, "7-Zip member extraction was incomplete");
                    if (found == CL_CLEAN)
                        found = CL_EPARSE;
                }
                close(fd);
                if (!ctx->engine->keeptmp)
                    (void)cli_unlink(tmp_name);
                free(tmp_name);
                continue;
            } else if (outSizeProcessed == 0) {
                cli_dbgmsg("cli_unz: extracted empty file\n");
                close(fd);
                if (!ctx->engine->keeptmp)
                    (void)cli_unlink(tmp_name);
                free(tmp_name);
            } else {
                cli_dbgmsg("cli_7unz: Saving to %s\n", tmp_name);
                found = cli_magic_scan_desc(fd, tmp_name, ctx, name, LAYER_ATTRIBUTES_NONE);

                close(fd);
                if (!ctx->engine->keeptmp && cli_unlink(tmp_name))
                    found = CL_EUNLINK;

                free(tmp_name);
                if (found != CL_SUCCESS)
                    break;
            }
        }
        IAlloc_Free(&allocImp, outBuffer);
    } else if (res != SZ_ERROR_ENCRYPTED) {
        cli_mark_scan_incomplete(ctx, "7-Zip archive header could not be parsed completely");
        found = CL_EPARSE;
    } else {
        cli_mark_scan_incomplete(ctx, "7-Zip encrypted archive header prevents inspection");
        found = CL_EPARSE;
    }
    SzArEx_Free(&db, &allocImp);
    if (namelen > UTFBUFSZ)
        free(utf16name);

    if (res == SZ_OK)
        cli_dbgmsg("cli_7unz: completed successfully\n");
    else if (res == SZ_ERROR_UNSUPPORTED)
        cli_dbgmsg("cli_7unz: unsupported\n");
    else if (res == SZ_ERROR_MEM)
        cli_dbgmsg("cli_7unz: oom\n");
    else if (res == SZ_ERROR_CRC)
        cli_dbgmsg("cli_7unz: crc mismatch\n");
    else if (res == SZ_ERROR_ENCRYPTED)
        cli_dbgmsg("cli_7unz: encrypted\n");
    else
        cli_dbgmsg("cli_7unz: error %d\n", res);

    return found;
}
