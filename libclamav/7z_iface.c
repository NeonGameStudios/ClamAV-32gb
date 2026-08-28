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

static cl_error_t cli_7z_checktimelimit(cli_ctx *ctx, const char *reason)
{
    cl_error_t ret = cli_checktimelimit(ctx);

    if (ret != CL_SUCCESS)
        cli_mark_scan_incomplete(ctx, reason);

    return ret;
}

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
    if (header == NULL)
        return CL_EREAD;
    if (memcmp(header, k7zSignature, k7zSignatureSize) != 0)
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
    cli_ctx *ctx;
    cl_error_t status;
    int fd;
    uint64_t declared_size;
    uint64_t written;
} CClamFileOutStream;

typedef struct
{
    CFileInStream stream;
    cli_ctx *ctx;
    cl_error_t status;
} CClamFileInStream;

#define CLAM_BCJ2_TEMP_STREAM_COUNT 4U

typedef struct CClamBcj2TempEntry CClamBcj2TempEntry;
typedef struct CClamBcj2TempProvider CClamBcj2TempProvider;

typedef struct
{
    ISeqOutStream s;
    CClamBcj2TempEntry *entry;
} CClamBcj2TempOutStream;

typedef struct
{
    ISeqInStream s;
    CClamBcj2TempEntry *entry;
} CClamBcj2TempInStream;

struct CClamBcj2TempEntry {
    CClamBcj2TempProvider *provider;
    CClamBcj2TempOutStream output;
    CClamBcj2TempInStream input;
    char *name;
    int fd;
    uint64_t expected;
    uint64_t written;
    uint64_t read;
    uint64_t reserved;
    bool created;
    bool finished;
};

struct CClamBcj2TempProvider {
    ISzBcj2TempStreams interface;
    cli_ctx *ctx;
    cl_error_t status;
    CClamBcj2TempEntry entries[CLAM_BCJ2_TEMP_STREAM_COUNT];
};

bool cli_7z_output_range_allowed(uint64_t written, uint64_t size, uint64_t declared_size)
{
    return written <= declared_size && size <= declared_size - written;
}

static size_t ClamFileOutStream_Write(void *pp, const void *data, size_t size)
{
    CClamFileOutStream *p = (CClamFileOutStream *)pp;
    size_t written;

    if (p == NULL || (size != 0 && data == NULL))
        return 0;

    if (!cli_7z_output_range_allowed(p->written, (uint64_t)size, p->declared_size)) {
        cli_mark_scan_incomplete(p->ctx, "7-Zip extracted output exceeded its declared member size");
        p->status = CL_EUNPACK;
        return 0;
    }

    if (p->ctx && cli_7z_checktimelimit(p->ctx, "7-Zip member extraction reached the configured time limit") != CL_SUCCESS) {
        p->status = CL_ETIMEOUT;
        return 0;
    }

    written = cli_writen(p->fd, data, size);

    /* ISeqOutStream uses a short write (zero here) to report failure. Do not
     * pass cli_writen()'s (size_t)-1 sentinel to the 7-Zip CRC wrapper: it
     * would be interpreted as an enormous successful write. */
    if (written == (size_t)-1) {
        cli_mark_scan_incomplete(p->ctx, "7-Zip extracted output could not be written completely");
        p->status = CL_EWRITE;
        return 0;
    }
    p->written += written;
    if (written != size) {
        cli_mark_scan_incomplete(p->ctx, "7-Zip extracted output could not be written completely");
        p->status = CL_EWRITE;
    }
    if (p->ctx && cli_7z_checktimelimit(p->ctx, "7-Zip member output reached the configured time limit") != CL_SUCCESS) {
        p->status = CL_ETIMEOUT;
        return 0;
    }
    return written;
}

static SRes ClamBcj2TempProvider_StatusToSRes(cl_error_t status)
{
    switch (status) {
        case CL_ETIMEOUT:
            return SZ_ERROR_PROGRESS;
        case CL_EMEM:
        case CL_ERESOURCE:
            return SZ_ERROR_MEM;
        case CL_EREAD:
        case CL_ESEEK:
            return SZ_ERROR_READ;
        case CL_EUNPACK:
            return SZ_ERROR_DATA;
        default:
            return SZ_ERROR_WRITE;
    }
}

static SRes ClamBcj2TempProvider_Fail(CClamBcj2TempProvider *provider,
                                      cl_error_t status, const char *reason)
{
    if (provider == NULL)
        return SZ_ERROR_FAIL;
    if (provider->status == CL_SUCCESS)
        provider->status = status;
    if (provider->ctx != NULL && reason != NULL)
        cli_mark_scan_incomplete(provider->ctx, reason);
    return ClamBcj2TempProvider_StatusToSRes(provider->status);
}

static SRes ClamBcj2TempProvider_Checkpoint(void *opaque)
{
    CClamBcj2TempProvider *provider = (CClamBcj2TempProvider *)opaque;
    cl_error_t status;

    if (provider == NULL || provider->ctx == NULL)
        return SZ_ERROR_PARAM;
    if (provider->status != CL_SUCCESS)
        return ClamBcj2TempProvider_StatusToSRes(provider->status);
    status = cli_7z_checktimelimit(provider->ctx,
                                   "7-Zip solid-folder extraction reached the configured time limit");
    if (status != CL_SUCCESS) {
        provider->status = status;
        return SZ_ERROR_PROGRESS;
    }
    return SZ_OK;
}

static size_t ClamBcj2TempOutStream_Write(void *pp, const void *data, size_t size)
{
    CClamBcj2TempOutStream *stream = (CClamBcj2TempOutStream *)pp;
    CClamBcj2TempEntry *entry;
    size_t written;

    if (stream == NULL || stream->entry == NULL || (size != 0 && data == NULL))
        return 0;
    entry = stream->entry;
    if (!entry->created || entry->finished || entry->fd < 0)
        return 0;
    if (ClamBcj2TempProvider_Checkpoint(entry->provider) != SZ_OK)
        return 0;
    if (!cli_7z_output_range_allowed(entry->written, (uint64_t)size, entry->expected)) {
        ClamBcj2TempProvider_Fail(entry->provider, CL_EUNPACK,
                                  "7-Zip BCJ2 scratch output exceeded its declared size");
        return 0;
    }
    if (size == 0)
        return 0;
    written = cli_writen(entry->fd, data, size);
    if (written == (size_t)-1 || written != size) {
        ClamBcj2TempProvider_Fail(entry->provider, CL_EWRITE,
                                  "7-Zip BCJ2 scratch output could not be written completely");
        return 0;
    }
    entry->written += written;
    if (ClamBcj2TempProvider_Checkpoint(entry->provider) != SZ_OK)
        return 0;
    return written;
}

static SRes ClamBcj2TempInStream_Read(void *pp, void *data, size_t *size)
{
    CClamBcj2TempInStream *stream = (CClamBcj2TempInStream *)pp;
    CClamBcj2TempEntry *entry;
    size_t requested;
    size_t read;

    if (stream == NULL || stream->entry == NULL || size == NULL ||
        (*size != 0 && data == NULL))
        return SZ_ERROR_READ;
    entry = stream->entry;
    if (!entry->finished || entry->fd < 0 || entry->read > entry->expected) {
        *size = 0;
        return SZ_ERROR_READ;
    }
    if (ClamBcj2TempProvider_Checkpoint(entry->provider) != SZ_OK) {
        *size = 0;
        return ClamBcj2TempProvider_StatusToSRes(entry->provider->status);
    }
    requested = *size;
    if ((uint64_t)requested > entry->expected - entry->read)
        requested = (size_t)(entry->expected - entry->read);
    if (requested == 0) {
        *size = 0;
        return SZ_OK;
    }
    read = cli_readn(entry->fd, data, requested);
    if (read == (size_t)-1 || read != requested) {
        *size = 0;
        return ClamBcj2TempProvider_Fail(entry->provider, CL_EREAD,
                                         "7-Zip BCJ2 scratch input could not be read completely");
    }
    entry->read += read;
    *size = read;
    if (ClamBcj2TempProvider_Checkpoint(entry->provider) != SZ_OK) {
        *size = 0;
        return ClamBcj2TempProvider_StatusToSRes(entry->provider->status);
    }
    return SZ_OK;
}

static SRes ClamBcj2TempProvider_Create(void *opaque, UInt32 streamIndex,
                                        UInt64 expectedSize, ISeqOutStream **outStream)
{
    CClamBcj2TempProvider *provider = (CClamBcj2TempProvider *)opaque;
    CClamBcj2TempEntry *entry;
    cl_error_t status;

    if (provider == NULL || outStream == NULL || streamIndex == 0 ||
        streamIndex >= CLAM_BCJ2_TEMP_STREAM_COUNT)
        return SZ_ERROR_PARAM;
    *outStream = NULL;
    if (ClamBcj2TempProvider_Checkpoint(provider) != SZ_OK)
        return ClamBcj2TempProvider_StatusToSRes(provider->status);
    entry = &provider->entries[streamIndex];
    if (entry->created)
        return ClamBcj2TempProvider_Fail(provider, CL_EUNPACK,
                                         "7-Zip BCJ2 scratch stream was created more than once");
    if (expectedSize > INT64_MAX)
        return ClamBcj2TempProvider_Fail(provider, CL_ERESOURCE,
                                         "7-Zip BCJ2 scratch size is not representable");

    status = cli_scan_reserve_temporary(provider->ctx, expectedSize);
    if (status != CL_SUCCESS)
        return ClamBcj2TempProvider_Fail(provider, status,
                                         "7-Zip BCJ2 scratch storage exceeded its resource limit");
    entry->reserved = expectedSize;
    entry->expected = expectedSize;
    entry->created  = true;
    status          = cli_gentempfd(provider->ctx->this_layer_tmpdir, &entry->name, &entry->fd);
    if (status != CL_SUCCESS)
        return ClamBcj2TempProvider_Fail(provider, status,
                                         "7-Zip BCJ2 scratch file could not be created");
    entry->output.s.Write = ClamBcj2TempOutStream_Write;
    entry->output.entry   = entry;
    entry->input.s.Read   = ClamBcj2TempInStream_Read;
    entry->input.entry    = entry;
    *outStream            = &entry->output.s;
    return SZ_OK;
}

static SRes ClamBcj2TempProvider_Finish(void *opaque, UInt32 streamIndex,
                                        ISeqInStream **inStream)
{
    CClamBcj2TempProvider *provider = (CClamBcj2TempProvider *)opaque;
    CClamBcj2TempEntry *entry;
    STATBUF fileStatus;

    if (provider == NULL || inStream == NULL || streamIndex == 0 ||
        streamIndex >= CLAM_BCJ2_TEMP_STREAM_COUNT)
        return SZ_ERROR_PARAM;
    *inStream = NULL;
    entry     = &provider->entries[streamIndex];
    if (!entry->created || entry->finished || entry->fd < 0 ||
        entry->written != entry->expected || FSTAT(entry->fd, &fileStatus) != 0 ||
        fileStatus.st_size < 0 || !S_ISREG(fileStatus.st_mode) ||
        (uint64_t)fileStatus.st_size != entry->expected)
        return ClamBcj2TempProvider_Fail(provider, CL_EUNPACK,
                                         "7-Zip BCJ2 scratch output did not match its declared size");
    if (lseek(entry->fd, 0, SEEK_SET) == (off_t)-1)
        return ClamBcj2TempProvider_Fail(provider, CL_ESEEK,
                                         "7-Zip BCJ2 scratch input could not be rewound");
    entry->finished = true;
    *inStream       = &entry->input.s;
    return ClamBcj2TempProvider_Checkpoint(provider);
}

static void ClamBcj2TempProvider_Init(CClamBcj2TempProvider *provider, cli_ctx *ctx)
{
    UInt32 i;

    memset(provider, 0, sizeof(*provider));
    provider->interface.opaque     = provider;
    provider->interface.Create     = ClamBcj2TempProvider_Create;
    provider->interface.Finish     = ClamBcj2TempProvider_Finish;
    provider->interface.Checkpoint = ClamBcj2TempProvider_Checkpoint;
    provider->ctx                  = ctx;
    provider->status               = CL_SUCCESS;
    for (i = 0; i < CLAM_BCJ2_TEMP_STREAM_COUNT; i++) {
        provider->entries[i].provider = provider;
        provider->entries[i].fd       = -1;
    }
}

static void ClamBcj2TempProvider_Cleanup(CClamBcj2TempProvider *provider)
{
    UInt32 i;

    if (provider == NULL)
        return;
    for (i = 1; i < CLAM_BCJ2_TEMP_STREAM_COUNT; i++) {
        CClamBcj2TempEntry *entry = &provider->entries[i];
        if (!entry->created)
            continue;
        if (entry->fd >= 0) {
            if (close(entry->fd) != 0)
                ClamBcj2TempProvider_Fail(provider, CL_EWRITE,
                                          "7-Zip BCJ2 scratch file could not be closed");
            entry->fd = -1;
        }
        if (entry->name != NULL && !provider->ctx->engine->keeptmp &&
            cli_unlink(entry->name) != 0)
            ClamBcj2TempProvider_Fail(provider, CL_EUNLINK,
                                      "7-Zip BCJ2 scratch file could not be removed");
        cli_scan_release_temporary(provider->ctx, entry->reserved);
        free(entry->name);
        entry->name     = NULL;
        entry->reserved = 0;
    }
}

static cl_error_t cli_7z_error_status(SRes res)
{
    switch (res) {
        case SZ_ERROR_READ:
            return CL_EREAD;
        case SZ_ERROR_WRITE:
            return CL_EWRITE;
        case SZ_ERROR_MEM:
            return CL_EMEM;
        case SZ_ERROR_PROGRESS:
            return CL_ETIMEOUT;
        default:
            return CL_EPARSE;
    }
}

bool cli_7z_output_matches_declared(int fd, uint64_t declared_size, uint64_t processed_size)
{
    STATBUF output_stat;

    if (processed_size != declared_size || FSTAT(fd, &output_stat) != 0 || output_stat.st_size < 0 ||
        !S_ISREG(output_stat.st_mode) || (uint64_t)output_stat.st_size != declared_size)
        return false;

    return true;
}

cl_error_t cli_7z_reset_output_for_legacy(int fd, uint64_t *written)
{
    if (fd < 0 || written == NULL)
        return CL_ENULLARG;
    if (ftruncate(fd, 0) != 0)
        return CL_EWRITE;
    if (lseek(fd, 0, SEEK_SET) == (off_t)-1)
        return CL_ESEEK;
    *written = 0;
    return CL_SUCCESS;
}

cl_error_t cli_7z_merge_cleanup_status(cl_error_t status, cl_error_t cleanup_status)
{
    if (cleanup_status == CL_SUCCESS)
        return status;
    if (status == CL_SUCCESS || status == CL_VERIFIED || status == CL_BREAK)
        return cleanup_status;
    return status;
}

static void cli_7z_cleanup_temp(cli_ctx *ctx, int fd, const char *tmp_name, cl_error_t *status,
                                uint64_t temporary_reserved)
{
    if (close(fd) == -1) {
        cli_mark_scan_incomplete(ctx, "7-Zip temporary output could not be closed");
        *status = cli_7z_merge_cleanup_status(*status, CL_EWRITE);
    }
    if (!ctx->engine->keeptmp && cli_unlink(tmp_name)) {
        cli_mark_scan_incomplete(ctx, "7-Zip temporary output could not be removed");
        *status = cli_7z_merge_cleanup_status(*status, CL_EUNLINK);
    }
    cli_scan_release_temporary(ctx, temporary_reserved);
}

static SRes FileInStream_fmap_Read(void *pp, void *buf, size_t *size)
{
    CClamFileInStream *p = (CClamFileInStream *)pp;
    size_t read_sz;

    if (p == NULL || p->stream.file.fmap == NULL || size == NULL)
        return SZ_ERROR_READ;
    if (*size == 0)
        return 0;

    if (p->ctx != NULL &&
        (p->status = cli_7z_checktimelimit(p->ctx, "7-Zip archive input reached the configured time limit")) != CL_SUCCESS) {
        *size = 0;
        return SZ_ERROR_READ;
    }

    if (p->stream.s.curpos < 0 || (uint64_t)p->stream.s.curpos > (uint64_t)p->stream.file.fmap->len) {
        *size = 0;
        return SZ_ERROR_INPUT_EOF;
    }

    /* fmap_readn() uses (size_t)-1 for both an out-of-range request and a
     * fully in-range backing-read failure. Clip a request at the map
     * boundary first so malformed/truncated input becomes the decoder's EOF
     * result, while a callback failure for the clipped in-range window still
     * remains SZ_ERROR_READ and therefore CL_EREAD. */
    {
        size_t available = p->stream.file.fmap->len - (size_t)p->stream.s.curpos;
        if (*size > available)
            *size = available;
    }
    if (*size == 0)
        return SZ_OK;

    read_sz = fmap_readn(p->stream.file.fmap, buf, p->stream.s.curpos, *size);
    if (read_sz == (size_t)-1) {
        *size = 0;
        return SZ_ERROR_READ;
    }

    p->stream.s.curpos += read_sz;

    *size = read_sz;
    return SZ_OK;
}

static SRes FileInStream_fmap_Seek(void *pp, Int64 *pos, ESzSeek origin)
{
    CClamFileInStream *p = (CClamFileInStream *)pp;
    Int64 map_length;
    Int64 base;

    if (p == NULL || p->stream.file.fmap == NULL || pos == NULL)
        return 1;

    if (p->ctx != NULL &&
        (p->status = cli_7z_checktimelimit(p->ctx, "7-Zip archive input reached the configured time limit")) != CL_SUCCESS)
        return 1;

    map_length = (Int64)p->stream.file.fmap->len;
    if (map_length < 0 || p->stream.s.curpos < 0 || (Int64)p->stream.s.curpos > map_length)
        return 1;

    switch (origin) {
        case SZ_SEEK_SET:
            base = 0;
            break;
        case SZ_SEEK_CUR:
            base = (Int64)p->stream.s.curpos;
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

    *pos               = base + *pos;
    p->stream.s.curpos = (off_t)*pos;
    return 0;
}

#define UTFBUFSZ 256
int cli_7unz(cli_ctx *ctx, size_t offset)
{
    CClamFileInStream archiveStream;
    CLookToRead lookStream;
    CSzArEx db;
    SRes res;
    UInt16 utf16buf[UTFBUFSZ], *utf16name = utf16buf;
    size_t namelen         = UTFBUFSZ;
    cl_error_t found       = CL_CLEAN;
    Int64 begin_of_archive = offset;

    if (!ctx)
        return CL_ENULLARG;
    if (!ctx->fmap) {
        cli_mark_scan_incomplete(ctx, "7-Zip input map is unavailable");
        return CL_EPARSE;
    }
    if (!ctx->engine)
        return CL_ENULLARG;

    if (cli_7z_checktimelimit(ctx, "7-Zip inspection reached the configured time limit") != CL_SUCCESS)
        return CL_ETIMEOUT;

    /* Replacement for
       FileInStream_CreateVTable(&archiveStream); */
    archiveStream.stream.s.Read    = FileInStream_fmap_Read;
    archiveStream.stream.s.Seek    = FileInStream_fmap_Seek;
    archiveStream.stream.s.curpos  = 0;
    archiveStream.stream.file.fmap = ctx->fmap;
    archiveStream.ctx              = ctx;
    archiveStream.status           = CL_SUCCESS;

    LookToRead_CreateVTable(&lookStream, False);

    if (archiveStream.stream.s.Seek(&archiveStream.stream.s, &begin_of_archive, SZ_SEEK_SET) != 0) {
        cli_mark_scan_incomplete(ctx, "7-Zip archive start could not be reached");
        return archiveStream.status != CL_SUCCESS ? archiveStream.status : CL_ESEEK;
    }

    lookStream.realStream = &archiveStream.stream.s;
    LookToRead_Init(&lookStream);

    SzArEx_Init(&db);
    res = SzArEx_Open(&db, &lookStream.s, &allocImp, &allocTempImp);
    if (archiveStream.status != CL_SUCCESS) {
        found = archiveStream.status;
    } else if (res == SZ_ERROR_ENCRYPTED && SCAN_HEURISTIC_ENCRYPTED_ARCHIVE) {
        cli_dbgmsg("cli_7unz: Encrypted header found in archive.\n");
        cli_mark_scan_incomplete(ctx, "7-Zip encrypted archive header prevents inspection");
        found = cli_append_potentially_unwanted(ctx, "Heuristics.Encrypted.7Zip");
        if (found == CL_SUCCESS)
            found = CL_EPARSE;
    } else if (res == SZ_OK) {
        UInt32 i, blockIndex = 0xFFFFFFFF;
        Byte *outBuffer      = NULL;
        size_t outBufferSize = 0;

        for (i = 0; i < db.db.NumFiles; i++) {
            UInt64 outSizeProcessed = 0;
            const CSzFileItem *f    = db.db.Files + i;
            char *name;
            char *tmp_name;
            size_t j;
            size_t newnamelen;
            int fd;
            cl_error_t limitret;
            cl_error_t metadata_status;
            CClamFileOutStream output;
            CClamBcj2TempProvider bcj2TempProvider;
            uint64_t temporary_reserved = 0;
            unsigned int encrypted      = 0;
            bool output_mismatch        = false;

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
                    if (newnamelen > SIZE_MAX / sizeof(*utf16name)) {
                        cli_mark_scan_incomplete(ctx, "7-Zip member name length could not be represented");
                        found = CL_ERESOURCE;
                        break;
                    }
                    utf16name = cli_max_malloc(newnamelen * sizeof(*utf16name));
                    if (!utf16name) {
                        cli_mark_scan_incomplete(ctx, "7-Zip member name could not be allocated");
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

            if (f->Size > SIZE_MAX) {
                cli_mark_scan_incomplete(ctx, "7-Zip member size could not be represented");
                found = CL_ERESOURCE;
                break;
            }
            found = cli_scan_reserve_temporary(ctx, f->Size);
            if (found != CL_SUCCESS)
                break;
            temporary_reserved = f->Size;

            found = cli_gentempfd(ctx->this_layer_tmpdir, &tmp_name, &fd);
            if (found != CL_SUCCESS) {
                cli_mark_scan_incomplete(ctx, "7-Zip temporary output could not be created");
                cli_scan_release_temporary(ctx, temporary_reserved);
                break;
            }
            output.s.Write       = ClamFileOutStream_Write;
            output.ctx           = ctx;
            output.status        = CL_SUCCESS;
            output.fd            = fd;
            output.declared_size = f->Size;
            output.written       = 0;
            ClamBcj2TempProvider_Init(&bcj2TempProvider, ctx);
            res = SzArEx_ExtractToStreamEx(&db, &lookStream.s, i, &output.s,
                                           &outSizeProcessed, &allocImp, &allocTempImp,
                                           &bcj2TempProvider.interface);
            ClamBcj2TempProvider_Cleanup(&bcj2TempProvider);
            if (output.status != CL_SUCCESS) {
                found = output.status;
                cli_7z_cleanup_temp(ctx, fd, tmp_name, &found, temporary_reserved);
                free(tmp_name);
                break;
            }
            if (bcj2TempProvider.status != CL_SUCCESS) {
                found = bcj2TempProvider.status;
                cli_7z_cleanup_temp(ctx, fd, tmp_name, &found, temporary_reserved);
                free(tmp_name);
                break;
            }
            if (archiveStream.status != CL_SUCCESS) {
                found = archiveStream.status;
                cli_7z_cleanup_temp(ctx, fd, tmp_name, &found, temporary_reserved);
                free(tmp_name);
                break;
            }
            if (res == SZ_ERROR_UNSUPPORTED) {
                UInt32 folderIndex = db.FileIndexToFolderIndexMap[i];
                UInt64 folderSize  = 0;
                int allow_legacy   = folderIndex == (UInt32)-1;
                if (!allow_legacy && folderIndex < db.db.NumFolders) {
                    folderSize   = SzFolder_GetUnpackSize(&db.db.Folders[folderIndex]);
                    allow_legacy = folderSize <= CLI_MAX_ALLOCATION;
                }
                if (allow_legacy) {
                    cl_error_t reset_status = cli_7z_reset_output_for_legacy(fd, &output.written);
                    if (reset_status != CL_SUCCESS) {
                        cli_mark_scan_incomplete(ctx, "7-Zip legacy fallback output could not be reset");
                        found = reset_status;
                        cli_7z_cleanup_temp(ctx, fd, tmp_name, &found, temporary_reserved);
                        free(tmp_name);
                        break;
                    }
                    size_t legacyOffset = 0;
                    size_t legacySize   = 0;
                    res                 = SzArEx_Extract(&db, &lookStream.s, i, &blockIndex,
                                                         &outBuffer, &outBufferSize, &legacyOffset,
                                                         &legacySize, &allocImp, &allocTempImp);
                    if (archiveStream.status != CL_SUCCESS) {
                        found = archiveStream.status;
                        cli_7z_cleanup_temp(ctx, fd, tmp_name, &found, temporary_reserved);
                        free(tmp_name);
                        break;
                    }
                    if (res == SZ_OK && legacySize != 0) {
                        size_t legacy_written = ClamFileOutStream_Write(&output, outBuffer + legacyOffset, legacySize);
                        if (output.status != CL_SUCCESS) {
                            found = output.status;
                            res   = SZ_ERROR_WRITE;
                        } else if (legacy_written != legacySize) {
                            cli_mark_scan_incomplete(ctx, "7-Zip legacy member output could not be written completely");
                            found = CL_EWRITE;
                            res   = SZ_ERROR_WRITE;
                        } else {
                            outSizeProcessed = legacySize;
                        }
                    }
                } else {
                    cli_dbgmsg("cli_7unz: refusing whole-folder fallback for " STDu64 " bytes\n", (uint64_t)folderSize);
                }
            }
            if (res == SZ_ERROR_ENCRYPTED) {
                encrypted = 1;
                cli_mark_scan_incomplete(ctx, "7-Zip encrypted member contents prevent inspection");
                if (SCAN_HEURISTIC_ENCRYPTED_ARCHIVE) {
                    cli_dbgmsg("cli_7unz: Encrypted files found in archive.\n");
                    found = cli_append_potentially_unwanted(ctx, "Heuristics.Encrypted.7Zip");
                    if (found != CL_SUCCESS) {
                        cli_7z_cleanup_temp(ctx, fd, tmp_name, &found, temporary_reserved);
                        free(tmp_name);
                        break;
                    }
                }
                if (found == CL_SUCCESS)
                    found = CL_EPARSE;
            }
            if (res == SZ_OK && !cli_7z_output_matches_declared(fd, f->Size, outSizeProcessed)) {
                cli_mark_scan_incomplete(ctx, "7-Zip extracted output did not match its declared member size");
                found           = CL_EUNPACK;
                res             = SZ_ERROR_DATA;
                output_mismatch = true;
            }
            metadata_status = cli_matchmeta(ctx, name, 0, f->Size, encrypted, i, f->CrcDefined ? f->Crc : 0);
            if (metadata_status != CL_SUCCESS) {
                found = metadata_status;
                if (metadata_status != CL_VIRUS && metadata_status != CL_VERIFIED && metadata_status != CL_BREAK)
                    cli_mark_scan_incomplete(ctx, "7-Zip member metadata matching did not complete");
                cli_7z_cleanup_temp(ctx, fd, tmp_name, &found, temporary_reserved);
                free(tmp_name);
                break;
            }
            if (res != SZ_OK) {
                cli_dbgmsg("cli_unz: extraction failed with %d\n", res);
                if (res != SZ_ERROR_ENCRYPTED || !SCAN_HEURISTIC_ENCRYPTED_ARCHIVE) {
                    cli_mark_scan_incomplete(ctx, "7-Zip member extraction was incomplete");
                    if (found == CL_CLEAN)
                        found = cli_7z_error_status(res);
                }
                cli_7z_cleanup_temp(ctx, fd, tmp_name, &found, temporary_reserved);
                free(tmp_name);
                if (output_mismatch)
                    break;
                continue;
            } else if (outSizeProcessed == 0) {
                cli_dbgmsg("cli_unz: extracted empty file\n");
                cli_7z_cleanup_temp(ctx, fd, tmp_name, &found, temporary_reserved);
                free(tmp_name);
            } else {
                cli_dbgmsg("cli_7unz: Saving to %s\n", tmp_name);
                found = cli_magic_scan_desc_type_reserved(fd, tmp_name, ctx, CL_TYPE_ANY, name,
                                                          LAYER_ATTRIBUTES_NONE);

                if (found != CL_SUCCESS && found != CL_VIRUS && found != CL_VERIFIED && found != CL_BREAK)
                    cli_mark_scan_incomplete(ctx, "7-Zip extracted-file scan did not complete");
                cli_7z_cleanup_temp(ctx, fd, tmp_name, &found, temporary_reserved);

                free(tmp_name);
                if (found != CL_SUCCESS)
                    break;
            }
        }
        IAlloc_Free(&allocImp, outBuffer);
    } else if (res == SZ_ERROR_READ) {
        cli_mark_scan_incomplete(ctx, "7-Zip archive could not be read completely");
        found = CL_EREAD;
    } else if (res == SZ_ERROR_MEM) {
        cli_mark_scan_incomplete(ctx, "7-Zip archive could not be allocated");
        found = CL_EMEM;
    } else if (res != SZ_ERROR_ENCRYPTED) {
        cli_mark_scan_incomplete(ctx, "7-Zip archive header could not be parsed completely");
        found = cli_7z_error_status(res);
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

    if (ctx->scan_incomplete && found == CL_SUCCESS)
        found = CL_EPARSE;

    return found;
}
