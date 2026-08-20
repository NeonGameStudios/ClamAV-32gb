/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Nigel Horne
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
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h> /* for NAME_MAX */
#endif

#ifdef C_DARWIN
#include <sys/types.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "clamav.h"
#include "others.h"
#include "mbox.h"
#include "matcher.h"
#include "scanners.h"
#include "filetypes.h"

#include <assert.h>

/* Scheduled for rewrite in 0.94 (bb#804). Disabling for now */
/* #define	MAX_SCAN_SIZE	20*1024	/\* */
/* 				 * The performance benefit of scanning */
/* 				 * early disappears on medium and */
/* 				 * large sized files */
/* 				 *\/ */

static const char *blobGetFilename(const blob *b);

blob *
blobCreate(void)
{
#ifdef CL_DEBUG
    blob *b = (blob *)calloc(1, sizeof(blob));
    if (b)
        b->magic = BLOBCLASS;
    cli_dbgmsg("blobCreate\n");
    return b;
#else
    return (blob *)calloc(1, sizeof(blob));
#endif
}

void blobDestroy(blob *b)
{
#ifdef CL_DEBUG
    cli_dbgmsg("blobDestroy %d\n", b->magic);
#else
    cli_dbgmsg("blobDestroy\n");
#endif

    assert(b != NULL);
#ifdef CL_DEBUG
    assert(b->magic == BLOBCLASS);
#endif

    if (b->name)
        free(b->name);
    if (b->data)
        free(b->data);
#ifdef CL_DEBUG
    b->magic = INVALIDCLASS;
#endif
    free(b);
}

void blobArrayDestroy(blob *blobList[], int n)
{
    assert(blobList != NULL);

    while (--n >= 0) {
        cli_dbgmsg("blobArrayDestroy: %d\n", n);
        if (blobList[n]) {
            blobDestroy(blobList[n]);
            blobList[n] = NULL;
        }
    }
}

/*
 * No longer needed to be growable, so turn into a normal memory area which
 * the caller must free. The passed blob is destroyed
 */
void *
blobToMem(blob *b)
{
    void *ret;

    assert(b != NULL);
#ifdef CL_DEBUG
    assert(b->magic == BLOBCLASS);
#endif

    if (!b->isClosed)
        blobClose(b);
    if (b->name)
        free(b->name);
#ifdef CL_DEBUG
    b->magic = INVALIDCLASS;
#endif
    ret = (void *)b->data;
    free(b);

    return ret;
}

/*ARGSUSED*/
void blobSetFilename(blob *b, const char *dir, const char *filename)
{
    assert(b != NULL);
#ifdef CL_DEBUG
    assert(b->magic == BLOBCLASS);
#endif
    assert(filename != NULL);

    UNUSEDPARAM(dir);

    cli_dbgmsg("blobSetFilename: %s\n", filename);

    if (b->name)
        free(b->name);

    b->name = cli_safer_strdup(filename);

    if (b->name)
        sanitiseName(b->name);
}

static const char *
blobGetFilename(const blob *b)
{
    assert(b != NULL);
#ifdef CL_DEBUG
    assert(b->magic == BLOBCLASS);
#endif

    return b->name;
}

/*
 * Returns <0 for failure
 */
int blobAddData(blob *b, const unsigned char *data, size_t len)
{
#if HAVE_CLI_GETPAGESIZE
    static int pagesize = 0;
    int growth;
#endif

    assert(b != NULL);
#ifdef CL_DEBUG
    assert(b->magic == BLOBCLASS);
#endif
    assert(data != NULL);

    if (len == 0)
        return 0;

    if (b->isClosed) {
        /*
         * Should be cli_dbgmsg, but I want to see them for now,
         * and cli_dbgmsg doesn't support debug levels
         */
        cli_warnmsg("Reopening closed blob\n");
        b->isClosed = 0;
    }
    /*
     * The payoff here is between reducing the number of calls to
     * malloc/realloc and not overallocating memory. A lot of machines
     * are more tight with memory than one may imagine which is why
     * we don't just allocate a *huge* amount and be done with it. Closing
     * the blob helps because that reclaims memory. If you know the maximum
     * size of a blob before you start adding data, use blobGrow() that's
     * the most optimum
     */
#if HAVE_CLI_GETPAGESIZE
    if (pagesize == 0) {
        pagesize = cli_getpagesize();
        if (pagesize <= 0)
            pagesize = 4096;
    }
    growth = pagesize;
    if (len >= (size_t)pagesize)
        growth = ((len / pagesize) + 1) * pagesize;

    /*cli_dbgmsg("blobGrow: b->size %lu, b->len %lu, len %lu, growth = %u\n",
                b->size, b->len, len, growth);*/

    if (b->data == NULL) {
        assert(b->len == 0);
        assert(b->size == 0);

        b->size = growth;
        b->data = cli_max_malloc(growth);
        if (NULL == b->data) {
            b->size = 0;
            return -1;
        }
    } else if (b->size < b->len + (off_t)len) {
        unsigned char *p = cli_max_realloc(b->data, b->size + growth);

        if (p == NULL)
            return -1;

        b->size += growth;
        b->data = p;
    }
#else
    if (b->data == NULL) {
        assert(b->len == 0);
        assert(b->size == 0);

        b->size = (off_t)len * 4;
        b->data = cli_max_malloc(b->size);
        if (NULL == b->data) {
            b->size = 0;
            return -1;
        }
    } else if (b->size < b->len + (off_t)len) {
        unsigned char *p = cli_max_realloc(b->data, b->size + (len * 4));

        if (p == NULL)
            return -1;

        b->size += (off_t)len * 4;
        b->data = p;
    }
#endif

    if (b->data) {
        memcpy(&b->data[b->len], data, len);
        b->len += (off_t)len;
    } else {
        b->size = 0;
        return -1;
    }
    return 0;
}

unsigned char *
blobGetData(const blob *b)
{
    assert(b != NULL);
#ifdef CL_DEBUG
    assert(b->magic == BLOBCLASS);
#endif

    if (b->len == 0)
        return NULL;
    return b->data;
}

size_t
blobGetDataSize(const blob *b)
{
    assert(b != NULL);
#ifdef CL_DEBUG
    assert(b->magic == BLOBCLASS);
#endif

    return b->len;
}

void blobClose(blob *b)
{
    assert(b != NULL);
#ifdef CL_DEBUG
    assert(b->magic == BLOBCLASS);
#endif

    if (b->isClosed) {
        cli_warnmsg("Attempt to close a previously closed blob\n");
        return;
    }

    /*
     * Nothing more is going to be added to this blob. If it'll save more
     * than a trivial amount (say 64 bytes) of memory, shrink the allocation
     */
    if ((b->size - b->len) >= 64) {
        if (b->len == 0) { /* Not likely */
            free(b->data);
            b->data = NULL;
            cli_dbgmsg("blobClose: recovered all %lu bytes\n",
                       (unsigned long)b->size);
            b->size = 0;
        } else {
            unsigned char *ptr = cli_max_realloc(b->data, b->len);

            if (ptr == NULL) {
                return;
            }

            cli_dbgmsg("blobClose: recovered %lu bytes from %lu\n",
                       (unsigned long)(b->size - b->len),
                       (unsigned long)b->size);
            b->size = b->len;
            b->data = ptr;
        }
    }
    b->isClosed = 1;
}

/*
 * Returns 0 if the blobs are the same
 */
int blobcmp(const blob *b1, const blob *b2)
{
    size_t s1, s2;

    assert(b1 != NULL);
    assert(b2 != NULL);

    if (b1 == b2)
        return 0;

    s1 = blobGetDataSize(b1);
    s2 = blobGetDataSize(b2);

    if (s1 != s2)
        return 1;

    if ((s1 == 0) && (s2 == 0))
        return 0;

    return memcmp(blobGetData(b1), blobGetData(b2), s1);
}

/*
 * Return clamav return code
 */
int blobGrow(blob *b, size_t len)
{
    assert(b != NULL);
#ifdef CL_DEBUG
    assert(b->magic == BLOBCLASS);
#endif

    if (len == 0)
        return CL_SUCCESS;

    if (b->isClosed) {
        /*
         * Should be cli_dbgmsg, but I want to see them for now,
         * and cli_dbgmsg doesn't support debug levels
         */
        cli_warnmsg("Growing closed blob\n");
        b->isClosed = 0;
    }
    if (b->data == NULL) {
        assert(b->len == 0);
        assert(b->size == 0);

        b->data = cli_max_malloc(len);
        if (b->data)
            b->size = (off_t)len;
    } else {
        unsigned char *ptr = cli_max_realloc(b->data, b->size + len);

        if (ptr) {
            b->size += (off_t)len;
            b->data = ptr;
        }
    }

    return (b->data) ? CL_SUCCESS : CL_EMEM;
}

fileblob *
fileblobCreate(void)
{
#ifdef CL_DEBUG
    fileblob *fb = (fileblob *)calloc(1, sizeof(fileblob));
    if (fb)
        fb->b.magic = BLOBCLASS;
    cli_dbgmsg("blobCreate\n");
    return fb;
#else
    return (fileblob *)calloc(1, sizeof(fileblob));
#endif
}

/*
 * A fileblob is often populated before the descriptor scan starts. Keep its
 * on-disk bytes in the same temporary-space budget as parser output while it
 * is being built. The descriptor scanner releases this reservation immediately
 * before it takes its normal whole-file reservation, and destruction releases
 * any reservation left by an aborted or failed materialization.
 */
static void
fileblobReleaseTemporary(fileblob *fb)
{
    if (fb == NULL)
        return;

    if (fb->temporary_ctx && fb->temporary_bytes)
        cli_scan_release_temporary(fb->temporary_ctx, fb->temporary_bytes);

    fb->temporary_ctx   = NULL;
    fb->temporary_bytes = 0;
}

static void
fileblobMarkIncomplete(fileblob *fb, const char *reason)
{
    cli_ctx *ctx;

    if (fb == NULL)
        return;

    fb->isIncomplete = 1;
    ctx              = fb->ctx ? fb->ctx : fb->temporary_ctx;
    if (ctx)
        cli_mark_scan_incomplete(ctx, reason);
}

static void
fileblobNoteCleanupFailure(cli_ctx *ctx, const char *reason)
{
    if (ctx)
        cli_mark_scan_incomplete(ctx, reason);
}

static int
fileblobReserveTemporary(fileblob *fb, cli_ctx *ctx, uint64_t bytes)
{
    if (fb == NULL || ctx == NULL)
        return 0;

    if (fb->temporary_ctx && fb->temporary_ctx != ctx)
        fileblobReleaseTemporary(fb);

    if (fb->temporary_ctx == NULL)
        fb->temporary_ctx = ctx;

    if (bytes == 0)
        return 0;

    if (UINT64_MAX - fb->temporary_bytes < bytes ||
        cli_scan_reserve_temporary(ctx, bytes) != CL_SUCCESS) {
        fileblobMarkIncomplete(fb,
                               "fileblob temporary spool exceeded the configured resource limit");
        return -1;
    }

    fb->temporary_bytes += bytes;
    return 0;
}

static int
fileblobReserveExistingTemporary(fileblob *fb)
{
    STATBUF sb;

    if (fb == NULL || fb->ctx == NULL || fb->fp == NULL || fb->isIncomplete)
        return 0;

    if (fb->temporary_ctx == fb->ctx)
        return 0;

    if (fflush(fb->fp) != 0 || FSTAT(fb->fd, &sb) != 0 || sb.st_size < 0) {
        fb->isIncomplete = 1;
        cli_mark_scan_incomplete(fb->ctx,
                                 "fileblob temporary spool could not be measured");
        return -1;
    }

    return fileblobReserveTemporary(fb, fb->ctx, (uint64_t)sb.st_size);
}

/*
 * Returns CL_CLEAN or CL_VIRUS for completed scans, and preserves any
 * operational/parser error returned by fileblobScan(). Destroys the fileblob
 * and removes the file if possible.
 */
int fileblobScanAndDestroy(fileblob *fb)
{
    cl_error_t rc;

    if (fb == NULL)
        return CL_ENULLARG;

    rc = fileblobScan(fb);
    switch (rc) {
        case CL_VIRUS:
            fileblobDestructiveDestroy(fb);
            return CL_VIRUS;
        case CL_BREAK:
            fileblobDestructiveDestroy(fb);
            return CL_CLEAN;
        case CL_CLEAN:
            fileblobDestroy(fb);
            return CL_CLEAN;
        default:
            fileblobMarkIncomplete(fb, "fileblob scan did not complete");
            fileblobDestroy(fb);
            return rc;
    }
}

/*
 * Destroy the fileblob, and remove the file associated with it
 */
void fileblobDestructiveDestroy(fileblob *fb)
{
    cli_ctx *cleanup_ctx = fb->ctx ? fb->ctx : fb->temporary_ctx;

    if (fb->fp && fb->fullname) {
        if (fclose(fb->fp) != 0)
            fileblobNoteCleanupFailure(cleanup_ctx, "fileblob temporary spool could not be closed");
        cli_dbgmsg("fileblobDestructiveDestroy: %s\n", fb->fullname);
        if (!cleanup_ctx || !cleanup_ctx->engine->keeptmp) {
            if (cli_unlink(fb->fullname))
                fileblobNoteCleanupFailure(cleanup_ctx, "fileblob temporary spool could not be removed");
        }
        free(fb->fullname);
        fb->fp       = NULL;
        fb->fullname = NULL;
    }
    if (fb->b.name) {
        free(fb->b.name);
        fb->b.name = NULL;
    }
    fileblobDestroy(fb);
}

/*
 * Destroy the fileblob, and remove the file associated with it if that file is
 * empty
 */
void fileblobDestroy(fileblob *fb)
{
    cli_ctx *cleanup_ctx;

    assert(fb != NULL);
#ifdef CL_DEBUG
    assert(fb->b.magic == BLOBCLASS);
#endif

    cleanup_ctx = fb->ctx ? fb->ctx : fb->temporary_ctx;
    fileblobReleaseTemporary(fb);

    if (fb->b.name && fb->fp) {
        if (fclose(fb->fp) != 0)
            fileblobNoteCleanupFailure(cleanup_ctx, "fileblob temporary spool could not be closed");
        if (fb->fullname) {
            cli_dbgmsg("fileblobDestroy: %s\n", fb->fullname);
            if (!fb->isNotEmpty) {
                cli_dbgmsg("fileblobDestroy: not saving empty file\n");
                if (cli_unlink(fb->fullname))
                    fileblobNoteCleanupFailure(cleanup_ctx, "fileblob temporary spool could not be removed");
            }
        }
        free(fb->b.name);

        if (fb->b.data) {
            free(fb->b.data);
            fb->b.data = NULL;
            fb->b.len = fb->b.size = 0;
        }
    } else if (fb->b.data) {
        free(fb->b.data);
        if (fb->b.name) {
            cli_errmsg("fileblobDestroy: %s not saved: report to https://github.com/Cisco-Talos/clamav/issues\n",
                       (fb->fullname) ? fb->fullname : fb->b.name);
            free(fb->b.name);
        } else
            cli_errmsg("fileblobDestroy: file not saved (%lu bytes): report to https://github.com/Cisco-Talos/clamav/issues\n",
                       (unsigned long)fb->b.len);
    } else if (fb->b.name) {
        free(fb->b.name);
        fb->b.name = NULL;
    }
    if (fb->fullname)
        free(fb->fullname);
#ifdef CL_DEBUG
    fb->b.magic = INVALIDCLASS;
#endif
    free(fb);
}

void fileblobPartialSet(fileblob *fb, const char *fullname, const char *arg)
{
    UNUSEDPARAM(arg);

    if (fb->b.name)
        return;

    assert(fullname != NULL);

    cli_dbgmsg("fileblobPartialSet: saving to %s\n", fullname);

    fb->fd = open(fullname, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY | O_EXCL, 0600);
    if (fb->fd < 0) {
        cli_errmsg("fileblobPartialSet: unable to create file: %s\n", fullname);
        fileblobMarkIncomplete(fb, "fileblob temporary spool could not be created");
        return;
    }
    fb->fp = fdopen(fb->fd, "wb");

    if (fb->fp == NULL) {
        cli_errmsg("fileblobSetFilename: fdopen failed\n");
        close(fb->fd);
        fileblobMarkIncomplete(fb, "fileblob temporary spool could not be opened");
        return;
    }
    blobSetFilename(&fb->b, fb->ctx ? fb->ctx->this_layer_tmpdir : NULL, fullname);
    if (fb->b.data)
        if (fileblobAddData(fb, fb->b.data, fb->b.len) == 0) {
            free(fb->b.data);
            fb->b.data = NULL;
            fb->b.len = fb->b.size = 0;
            fb->isNotEmpty         = 1;
        } else {
            free(fb->b.data);
            fb->b.data = NULL;
            fb->b.len = fb->b.size = 0;
        }
    fb->fullname = cli_safer_strdup(fullname);
}

void fileblobSetFilename(fileblob *fb, const char *dir, const char *filename)
{
    char *fullname;

    if (fb->b.name)
        return;

    assert(filename != NULL);
    assert(dir != NULL);

    blobSetFilename(&fb->b, dir, filename);

    /*
     * Reload the filename, it may be different from the one we've
     * asked for, e.g. '/'s taken out
     */
    filename = blobGetFilename(&fb->b);

    assert(filename != NULL);

    if (cli_gentempfd(dir, &fullname, &fb->fd) != CL_SUCCESS) {
        fileblobMarkIncomplete(fb, "fileblob temporary spool could not be created");
        return;
    }

    cli_dbgmsg("fileblobSetFilename: file %s saved to %s\n", filename, fullname);

    fb->fp = fdopen(fb->fd, "wb");

    if (fb->fp == NULL) {
        cli_errmsg("fileblobSetFilename: fdopen failed\n");
        close(fb->fd);
        free(fullname);
        fileblobMarkIncomplete(fb, "fileblob temporary spool could not be opened");
        return;
    }
    if (fb->b.data)
        if (fileblobAddData(fb, fb->b.data, fb->b.len) == 0) {
            free(fb->b.data);
            fb->b.data = NULL;
            fb->b.len = fb->b.size = 0;
            fb->isNotEmpty         = 1;
        } else {
            free(fb->b.data);
            fb->b.data = NULL;
            fb->b.len = fb->b.size = 0;
        }
    fb->fullname = fullname;
}

int fileblobAddData(fileblob *fb, const unsigned char *data, size_t len)
{
    if (len == 0)
        return 0;

    assert(data != NULL);

    if (fb->fp) {
#if defined(MAX_SCAN_SIZE) && (MAX_SCAN_SIZE > 0)
        const cli_ctx *ctx = fb->ctx;

        if (fb->isIncomplete)
            return -1;
        if (fb->isInfected) /* pretend all was written */
            return 0;
        if ((fb->ctx || fb->temporary_ctx) &&
            fileblobReserveTemporary(fb, fb->ctx ? fb->ctx : fb->temporary_ctx, (uint64_t)len) < 0)
            return -1;
        if (ctx) {
            int do_scan = 1;

            if (cli_checklimits("fileblobAddData", ctx, fb->bytes_scanned, 0, 0) != CL_CLEAN)
                do_scan = 0;

            if (fb->bytes_scanned > MAX_SCAN_SIZE)
                do_scan = 0;
            if (do_scan) {
                int stateful_matchers = 0;
                unsigned int matcher_index;

                /* fileblobAddData() is an early, best-effort scan. It may be
                 * called repeatedly with adjacent pieces, so a fresh
                 * cli_scan_buff() per append cannot preserve multipart or
                 * logical-signature state. Defer this optimization whenever
                 * such signatures are loaded; fileblobScan() performs the
                 * authoritative full-file scan after the blob is complete. */
                for (matcher_index = 0; matcher_index < CLI_MTARGETS; matcher_index++) {
                    if (ctx->engine->root[matcher_index] &&
                        (ctx->engine->root[matcher_index]->ac_partsigs ||
                         ctx->engine->root[matcher_index]->ac_lsigs ||
                         ctx->engine->root[matcher_index]->ac_reloff_num)) {
                        stateful_matchers = 1;
                        break;
                    }
                }

                if (ctx->scanned)
                    *ctx->scanned += len;
                fb->bytes_scanned += len;

                if (cli_updatelimits(ctx, len) == CL_CLEAN) {
                    if (stateful_matchers) {
                        cli_dbgmsg("fileblobAddData: deferring early scan to preserve multipart/logical matcher state\n");
                    } else if (len > 5) {
                        /* cli_scan_buff() deliberately keeps a bounded uint32_t
                         * window. Split an unusually large in-memory append, but
                         * overlap adjacent windows by the longest configured
                         * pattern so a signature cannot straddle the split. */
                        size_t scan_offset = 0;
                        size_t overlap     = 0;
                        unsigned int i;

                        for (i = 0; i < CLI_MTARGETS; i++) {
                            if (ctx->engine->root[i] && ctx->engine->root[i]->maxpatlen > overlap)
                                overlap = ctx->engine->root[i]->maxpatlen - 1;
                        }

                        while (scan_offset < len) {
                            size_t chunk_start   = scan_offset > overlap ? scan_offset - overlap : 0;
                            size_t available     = len - chunk_start;
                            uint32_t scan_length = available > UINT32_MAX ? UINT32_MAX : (uint32_t)available;

                            if (cli_scan_buff(data + chunk_start, scan_length, (uint64_t)chunk_start, ctx, CL_TYPE_BINARY_DATA, NULL) == CL_VIRUS) {
                                fb->isInfected = 1;
                                break;
                            }
                            scan_offset = chunk_start + scan_length;
                        }
                    }
                }
            }
        }
#endif

#if !defined(MAX_SCAN_SIZE) || (MAX_SCAN_SIZE == 0)
        if (fb->isIncomplete)
            return -1;
        if (fb->isInfected) /* pretend all was written */
            return 0;
        if ((fb->ctx || fb->temporary_ctx) &&
            fileblobReserveTemporary(fb, fb->ctx ? fb->ctx : fb->temporary_ctx, (uint64_t)len) < 0)
            return -1;
#endif

        if (fwrite(data, len, 1, fb->fp) != 1) {
            cli_errmsg("fileblobAddData: Can't write %lu bytes to temporary file %s\n",
                       (unsigned long)len, fb->b.name);
            fileblobMarkIncomplete(fb, "fileblob temporary spool write failed");
            return -1;
        }
        fb->isNotEmpty = 1;
        return 0;
    }
    if (fb->isIncomplete)
        return -1;
    return blobAddData(&(fb->b), data, len);
}

const char *
fileblobGetFilename(const fileblob *fb)
{
    return blobGetFilename(&(fb->b));
}

void fileblobSetCTX(fileblob *fb, cli_ctx *ctx)
{
    if (fb == NULL)
        return;

    if (ctx == NULL) {
        /* textToFileblob() deliberately clears the scan context for a caller
         * that is only using the fileblob as a formatter. Keep any reservation
         * already acquired until destruction, because the file still exists. */
        fb->ctx = NULL;
        return;
    }

    fb->ctx = ctx;
    (void)fileblobReserveExistingTemporary(fb);
}

/*
 * Performs a full scan on the fileblob, returning ClamAV status:
 *	CL_BREAK means clean
 *	CL_CLEAN means unknown
 *	CL_VIRUS means infected
 */
cl_error_t fileblobScan(fileblob *fb)
{
    cl_error_t rc;
    STATBUF sb;

    if (fb->isInfected)
        return CL_VIRUS;
    if (fb->isIncomplete) {
        if (fb->ctx)
            cli_mark_scan_incomplete(fb->ctx,
                                     "fileblob materialization was incomplete");
        return CL_ERESOURCE;
    }
    if (fb->fp == NULL || fb->fullname == NULL) {
        /* shouldn't happen, scan called before fileblobSetFilename */
        cli_warnmsg("fileblobScan, fullname == NULL\n");
        return CL_ENULLARG; /* there is no CL_UNKNOWN */
    }
    if (fb->ctx == NULL) {
        /* fileblobSetCTX hasn't been called */
        cli_dbgmsg("fileblobScan, ctx == NULL\n");
        return CL_CLEAN; /* there is no CL_UNKNOWN */
    }

    if (fflush(fb->fp) != 0 || lseek(fb->fd, 0, SEEK_SET) == (off_t)-1 || FSTAT(fb->fd, &sb) != 0 || sb.st_size < 0) {
        fb->isIncomplete = 1;
        cli_mark_scan_incomplete(fb->ctx,
                                 "fileblob temporary spool could not be scanned");
        fileblobReleaseTemporary(fb);
        return CL_ESTAT;
    }

    /* cli_magic_scan_desc() owns the reservation for the descriptor scan.
     * Release the build-time reservation first so the same bytes are not
     * charged twice. */
    fileblobReleaseTemporary(fb);

    rc = cli_matchmeta(fb->ctx, fb->b.name, sb.st_size, sb.st_size, 0, 0, 0);
    if (rc != CL_SUCCESS) {
        return rc;
    }

    rc = cli_magic_scan_desc(fb->fd, fb->fullname, fb->ctx, fb->b.name, LAYER_ATTRIBUTES_NONE);
    if (rc != CL_SUCCESS) {
        return rc;
    }

    return CL_BREAK;
}

/*
 * Doesn't perform a full scan just lets the caller know if something suspicious has
 * been seen yet
 */
int fileblobInfected(const fileblob *fb)
{
    return fb->isInfected;
}

/*
 * Different operating systems allow different characters in their filenames
 * FIXME: What does QNX want? There is no #ifdef C_QNX, but if there were
 * it may be best to treat it like MSDOS
 */
void sanitiseName(char *name)
{
    char c;
    while ((c = *name)) {
        if (c != '.' && c != '_' && (c > 'z' || c < '0' || (c > '9' && c < 'A') || (c > 'Z' && c < 'a'))) {
            *name = '_';
        }
        name++;
    }
}
