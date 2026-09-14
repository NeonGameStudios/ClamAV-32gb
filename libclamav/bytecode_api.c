/*
 *  ClamAV bytecode internal API
 *
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009-2013 Sourcefire, Inc.
 *
 *  Authors: Török Edvin
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

#ifdef HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <math.h>
#include <ctype.h>
#include <stdint.h>

#include <json.h>
#include <bzlib.h>

#include "clamav.h"
#include "clambc.h"
#include "bytecode.h"
#include "bytecode_priv.h"
#include "type_desc.h"
#include "bytecode_api.h"
#include "bytecode_api_impl.h"
#include "others.h"
#include "pe.h"
#include "pdf.h"
#include "disasm.h"
#include "scanners.h"
#include "jsparse/js-norm.h"
#include "hashtab.h"
#include "str.h"
#include "filetypes.h"
#include "lzma_iface.h"

#define EV ctx->bc_events

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define API_MISUSE() cli_event_error_str(EV, "API misuse @" TOSTRING(__LINE__))

static void cli_bcapi_mark_map_read_error(struct cli_bc_ctx *ctx, const char *reason)
{
    cli_ctx *cctx;

    if (!ctx || !ctx->ctx)
        return;

    cctx = (cli_ctx *)ctx->ctx;
    cli_mark_scan_incomplete(cctx, reason);
}

static void cli_bcapi_mark_coordinate_error(struct cli_bc_ctx *ctx, const char *reason)
{
    cli_ctx *cctx;

    if (!ctx || !ctx->ctx)
        return;

    cctx = (cli_ctx *)ctx->ctx;
    cli_mark_scan_incomplete(cctx, reason);
}

static void cli_bcapi_note_cleanup_failure(cli_ctx *cctx, cl_error_t *status,
                                           cl_error_t failure, const char *reason)
{
    if (cctx)
        cli_mark_scan_incomplete(cctx, reason);
    if (status)
        *status = cli_merge_cleanup_status(*status, failure);
}

static int cli_bcapi_table_size(unsigned current, size_t element_size,
                                unsigned *next, size_t *bytes)
{
    if (!element_size || current == UINT_MAX)
        return -1;

    *next = current + 1;
    if ((size_t)*next > SIZE_MAX / element_size)
        return -1;

    *bytes = (size_t)*next * element_size;
    return 0;
}

struct bc_lzma {
    struct CLI_LZMA stream;
    int32_t from;
    int32_t to;
};

struct bc_bzip2 {
    bz_stream stream;
    int32_t from;
    int32_t to;
};

uint32_t cli_bcapi_test1(struct cli_bc_ctx *ctx, uint32_t a, uint32_t b)
{
    UNUSEDPARAM(ctx);
    return (a == 0xf00dbeef && b == 0xbeeff00d) ? 0x12345678 : 0x55;
}

uint32_t cli_bcapi_test2(struct cli_bc_ctx *ctx, uint32_t a)
{
    UNUSEDPARAM(ctx);
    return a == 0xf00d ? 0xd00f : 0x5555;
}

int32_t cli_bcapi_read(struct cli_bc_ctx *ctx, uint8_t *data, int32_t size)
{
    size_t n;
    if (!ctx)
        return -1;
    if (!ctx->fmap) {
        API_MISUSE();
        return -1;
    }
    if (size < 0) {
        cli_warnmsg("bytecode: negative read size: %d\n", size);
        API_MISUSE();
        return -1;
    }
    if (size > 0 && !data) {
        cli_dbgmsg("bcapi_read: non-empty read requires a destination buffer\n");
        API_MISUSE();
        return -1;
    }
    if (ctx->off < 0 || (uint64_t)ctx->off > (uint64_t)SIZE_MAX ||
        (uint64_t)size > (uint64_t)SIZE_MAX - (uint64_t)ctx->off) {
        cli_dbgmsg("bcapi_read: offset or requested range is not representable\n");
        API_MISUSE();
        return -1;
    }
    n = fmap_readn(ctx->fmap, data, ctx->off, size);
    if ((n == 0) || (n == (size_t)-1)) {
        cli_dbgmsg("bcapi_read: fmap_readn returned %s (requested %d)\n",
                   n == 0 ? "EOF" : "an error", size);
        cli_event_count(EV, BCEV_READ_ERR);
        if (n == (size_t)-1 && ctx->off >= 0 && (uint64_t)ctx->off < ctx->fmap->len)
            cli_bcapi_mark_map_read_error(ctx, "Bytecode could not read the complete input map");
        return (int32_t)n;
    }
    cli_event_int(EV, BCEV_OFFSET, ctx->off);
    cli_event_fastdata(EV, BCEV_READ, data, size);
    // cli_event_data(EV, BCEV_READ, data, n);
    ctx->off += n;
    return (int32_t)n;
}

int64_t cli_bcapi_read64(struct cli_bc_ctx *ctx, uint8_t *data, uint32_t size)
{
    size_t n;

    if (!ctx)
        return -1;
    if (!ctx->fmap || ctx->off < 0 || (uint64_t)ctx->off > (uint64_t)SIZE_MAX) {
        API_MISUSE();
        return -1;
    }
    if (size != 0 && !data) {
        cli_dbgmsg("bcapi_read64: non-empty read requires a destination buffer\n");
        API_MISUSE();
        return -1;
    }

    n = fmap_readn(ctx->fmap, data, (size_t)ctx->off, size);
    if ((n == 0) || (n == (size_t)-1)) {
        cli_dbgmsg("bcapi_read64: fmap_readn returned %s (requested %u)\n",
                   n == 0 ? "EOF" : "an error", size);
        cli_event_count(EV, BCEV_READ_ERR);
        if (n == (size_t)-1 && (uint64_t)ctx->off < (uint64_t)ctx->fmap->len)
            cli_bcapi_mark_map_read_error(ctx, "Bytecode v2 could not read the complete input map");
        return (n == (size_t)-1) ? -1 : 0;
    }
    cli_event_int(EV, BCEV_OFFSET, ctx->off);
    cli_event_fastdata(EV, BCEV_READ, data, (uint32_t)n);
    if ((uint64_t)n > (uint64_t)INT64_MAX - (uint64_t)ctx->off) {
        cli_bcapi_mark_map_read_error(ctx, "Bytecode v2 read offset overflowed");
        return -1;
    }
    ctx->off += (off_t)n;
    return (int64_t)n;
}

int32_t cli_bcapi_seek(struct cli_bc_ctx *ctx, int32_t pos, uint32_t whence)
{
    int64_t base;
    int64_t off;

    if (!ctx || !ctx->fmap) {
        cli_dbgmsg("bcapi_seek: no fmap\n");
        if (ctx)
            API_MISUSE();
        return -1;
    }
    switch (whence) {
        case 0:
            base = 0;
            break;
        case 1:
            if (ctx->off < 0)
                return -1;
            base = (int64_t)ctx->off;
            break;
        case 2:
            base = ctx->file_size;
            break;
        default:
            API_MISUSE();
            cli_dbgmsg("bcapi_seek: invalid whence value\n");
            return -1;
    }
    if (pos < 0) {
        int64_t magnitude = (int64_t)(-(pos + 1)) + 1;
        if (base < magnitude)
            return -1;
        off = base - magnitude;
    } else {
        if (base > INT64_MAX - (int64_t)pos)
            return -1;
        off = base + pos;
    }
    if (off < 0 || (uint64_t)off > (uint64_t)ctx->file_size) {
        cli_dbgmsg("bcapi_seek: out of file: %lld (max %d)\n",
                   (long long)off, ctx->file_size);
        return -1;
    }
    if ((uint64_t)off > (uint64_t)INT32_MAX) {
        cli_bcapi_mark_coordinate_error(ctx, "Bytecode v1 seek result requires 64-bit file coordinates");
        return -1;
    }
    cli_event_int(EV, BCEV_OFFSET, off);
    ctx->off = (off_t)off;
    return (int32_t)off;
}

int64_t cli_bcapi_seek64(struct cli_bc_ctx *ctx, int64_t pos, uint32_t whence)
{
    uint64_t base, target;

    if (!ctx)
        return -1;
    if (!ctx->fmap || ctx->off < 0) {
        API_MISUSE();
        return -1;
    }
    switch (whence) {
        case 0:
            base = 0;
            break;
        case 1:
            base = (uint64_t)ctx->off;
            break;
        case 2:
            base = ctx->file_size64;
            break;
        default:
            API_MISUSE();
            return -1;
    }

    if (pos < 0) {
        uint64_t magnitude = (uint64_t)(-(pos + 1)) + 1;
        if (base < magnitude)
            return -1;
        target = base - magnitude;
    } else {
        if (base > UINT64_MAX - (uint64_t)pos)
            return -1;
        target = base + (uint64_t)pos;
    }
    if (target > ctx->file_size64 || target > (uint64_t)INT64_MAX || target > (uint64_t)SIZE_MAX) {
        cli_dbgmsg("bcapi_seek64: out of file: " STDu64 " (max " STDu64 ")\n",
                   target, ctx->file_size64);
        return -1;
    }
    cli_event_int(EV, BCEV_OFFSET, target);
    ctx->off = (off_t)target;
    return (int64_t)target;
}

uint32_t cli_bcapi_debug_print_str(struct cli_bc_ctx *ctx, const uint8_t *str, uint32_t len)
{
    int print_len;

    if (!ctx || !str || !len)
        return -1;
    print_len = len > (uint32_t)INT_MAX ? INT_MAX : (int)len;
    cli_event_fastdata(EV, BCEV_DBG_STR, str, len);
    cli_dbgmsg("bytecode debug: %.*s\n", print_len, str);
    return 0;
}

uint32_t cli_bcapi_debug_print_uint(struct cli_bc_ctx *ctx, uint32_t a)
{
    if (!ctx)
        return -1;
    cli_event_int(EV, BCEV_DBG_INT, a);
    // cli_dbgmsg("bytecode debug: %d\n", a);
    // return 0;
    if (!cli_debug_flag)
        return 0;

    return cli_eprintf("%d", a);
}

/*TODO: compiler should make sure that only constants are passed here, and not
 * pointers to arbitrary locations that may not be valid when bytecode finishes
 * executing */
uint32_t cli_bcapi_setvirusname(struct cli_bc_ctx *ctx, const uint8_t *name, uint32_t len)
{
    if (!ctx || (len && !name))
        return -1;
    ctx->virname = (const char *)name;
    return 0;
}

uint32_t cli_bcapi_disasm_x86(struct cli_bc_ctx *ctx, struct DISASM_RESULT *res, uint32_t len)
{
    int n;
    const unsigned char *buf;
    const unsigned char *next;
    UNUSEDPARAM(len);
    if (!ctx || !res || !ctx->fmap || ctx->off < 0 ||
        (uint64_t)ctx->off >= (uint64_t)ctx->fmap->len) {
        if (!ctx)
            return -1;
        API_MISUSE();
        return -1;
    }
    /* 32 should be longest instr we support decoding.
     * When we'll support mmx/sse instructions this should be updated! */
    n   = MIN(32, ctx->fmap->len - ctx->off);
    buf = fmap_need_off_once(ctx->fmap, ctx->off, n);
    if (buf)
        next = cli_disasm_one(buf, n, res, 0);
    else {
        next = NULL;
        cli_bcapi_mark_map_read_error(ctx, "Bytecode disassembly could not read the complete input map");
    }
    if (!next) {
        cli_dbgmsg("bcapi_disasm: failed\n");
        cli_event_count(EV, BCEV_DISASM_FAIL);
        return -1;
    }
    return ctx->off + next - buf;
}

/* TODO: field in ctx, id of last bytecode that called magicscandesc, reset
 * after hooks/other bytecodes are run. TODO: need a more generic solution
 * to avoid uselessly recursing on bytecode-unpacked files, but also a way to
 * override the limit if we need it in a special situation */
int32_t cli_bcapi_write(struct cli_bc_ctx *ctx, uint8_t *data, int32_t len)
{
    char err[128];
    size_t materialized;
    size_t unmaterialized;
    size_t res;
    uint64_t write_len;

    cli_ctx *cctx;

    if (!ctx || (len > 0 && !data))
        return -1;
    cctx = (cli_ctx *)ctx->ctx;
    if (ctx->output_failed) {
        cli_bcapi_mark_map_read_error(ctx, "Bytecode temporary output was already incomplete");
        return -1;
    }
    if (len < 0) {
        cli_warnmsg("Bytecode API: called with negative length!\n");
        API_MISUSE();
        return -1;
    }
    write_len = (uint64_t)(uint32_t)len;
    if (UINT64_MAX - ctx->written < write_len) {
        cli_bcapi_mark_map_read_error(ctx, "Bytecode output size accounting overflowed");
        return -1;
    }
    if (-1 == ctx->outfd) {
        ctx->tempfile = cli_gentemp_with_prefix(cctx ? cctx->this_layer_tmpdir : NULL, "bcapi_write");
        if (!ctx->tempfile) {
            cli_dbgmsg("Bytecode API: Unable to allocate memory for tempfile\n");
            cli_bcapi_mark_map_read_error(ctx, "Bytecode temporary output could not be allocated");
            cli_event_error_oom(EV, 0);
            return -1;
        }
        ctx->outfd = open(ctx->tempfile, O_RDWR | O_CREAT | O_EXCL | O_TRUNC | O_BINARY, 0600);
        if (ctx->outfd == -1) {
            cli_warnmsg("Bytecode API: Can't create file %s: %s\n", ctx->tempfile, cli_strerror(errno, err, sizeof(err)));
            cli_bcapi_mark_map_read_error(ctx, "Bytecode temporary output could not be opened");
            cli_event_error_str(EV, "cli_bcapi_write: Can't create temporary file");
            free(ctx->tempfile);
            ctx->tempfile = NULL;
            return -1;
        }
        cli_dbgmsg("bytecode opened new tempfile: %s\n", ctx->tempfile);
    }

    cli_event_fastdata(ctx->bc_events, BCEV_WRITE, data, len);
    if (cli_checklimits("bytecode api", cctx, ctx->written + write_len, 0, 0))
        return -1;
    if (cctx && write_len) {
        if (cli_scan_reserve_temporary(cctx, write_len) != CL_SUCCESS)
            return -1;
        if (cli_checktimelimit(cctx) != CL_SUCCESS) {
            cli_scan_release_temporary(cctx, write_len);
            cli_mark_scan_incomplete(cctx, "Bytecode temporary output reached the configured time limit");
            return -1;
        }
        if (UINT64_MAX - ctx->temporary_reserved < write_len) {
            cli_scan_release_temporary(cctx, write_len);
            cli_bcapi_mark_map_read_error(ctx, "Bytecode temporary output accounting overflowed");
            return -1;
        }
        ctx->temporary_reserved += write_len;
        if (cli_checktimelimit(cctx) != CL_SUCCESS) {
            cli_scan_release_temporary(cctx, write_len);
            ctx->temporary_reserved -= write_len;
            cli_mark_scan_incomplete(cctx, "Bytecode temporary output reached the configured time limit");
            return -1;
        }
    }
    res = cli_writen(ctx->outfd, data, (size_t)len);
    if (res != (size_t)len) {
        if (res == (size_t)-1)
            cli_warnmsg("Bytecode API: write failed: %s\n", cli_strerror(errno, err, sizeof(err)));
        else
            cli_warnmsg("Bytecode API: short write: %zu of " STDu64 " bytes\n", res, write_len);
        cli_event_error_str(EV, "cli_bcapi_write: write failed");

        /* cli_writen() returns the prefix which reached the file for a
         * short write. Keep that prefix charged to the shared temporary
         * budget until the context owns and cleans up the output. Releasing
         * the full request here would make materialized bytes invisible to
         * resource accounting while the temporary file still contains them. */
        materialized = res == (size_t)-1 || res > (size_t)len ? 0 : res;
        unmaterialized = (size_t)write_len - materialized;
        if (cctx) {
            if (unmaterialized) {
                if (ctx->temporary_reserved < unmaterialized) {
                    cli_bcapi_mark_map_read_error(ctx, "Bytecode temporary output accounting underflowed");
                } else {
                    cli_scan_release_temporary(cctx, unmaterialized);
                    ctx->temporary_reserved -= unmaterialized;
                }
            }
            cli_mark_scan_incomplete(cctx, "Bytecode temporary output could not be written completely");
        }
        if (materialized) {
            ctx->written += (uint64_t)materialized;
        }
        ctx->output_failed = 1;
        return -1;
    }
    ctx->written += write_len;
    return (int32_t)res;
}

void cli_bytecode_context_set_trace(struct cli_bc_ctx *ctx, unsigned level,
                                    bc_dbg_callback_trace trace,
                                    bc_dbg_callback_trace_op trace_op,
                                    bc_dbg_callback_trace_val trace_val,
                                    bc_dbg_callback_trace_ptr trace_ptr)
{
    if (!ctx)
        return;
    ctx->trace       = trace;
    ctx->trace_op    = trace_op;
    ctx->trace_val   = trace_val;
    ctx->trace_ptr   = trace_ptr;
    ctx->trace_level = level;
}

uint32_t cli_bcapi_trace_scope(struct cli_bc_ctx *ctx, const uint8_t *scope, uint32_t scopeid)
{
    if (!ctx)
        return -1;
    if (LIKELY(!ctx->trace_level))
        return 0;
    if (ctx->scope != (const char *)scope) {
        ctx->scope   = (const char *)scope ? (const char *)scope : "?";
        ctx->scopeid = scopeid;
        ctx->trace_level |= 0x80; /* temporarily increase level to print params */
    } else if ((ctx->trace_level >= trace_scope) && ctx->scopeid != scopeid) {
        ctx->scopeid = scopeid;
        ctx->trace_level |= 0x40; /* temporarily increase level to print location */
    }
    return 0;
}

uint32_t cli_bcapi_trace_directory(struct cli_bc_ctx *ctx, const uint8_t *dir, uint32_t dummy)
{
    if (!ctx)
        return -1;
    UNUSEDPARAM(dummy);
    if (LIKELY(!ctx->trace_level))
        return 0;
    ctx->directory = (const char *)dir ? (const char *)dir : "";
    return 0;
}

uint32_t cli_bcapi_trace_source(struct cli_bc_ctx *ctx, const uint8_t *file, uint32_t line)
{
    if (!ctx)
        return -1;
    if (LIKELY(ctx->trace_level < trace_line))
        return 0;
    if (ctx->file != (const char *)file || ctx->line != line) {
        ctx->col  = 0;
        ctx->file = (const char *)file ? (const char *)file : "??";
        ctx->line = line;
    }
    return 0;
}

uint32_t cli_bcapi_trace_op(struct cli_bc_ctx *ctx, const uint8_t *op, uint32_t col)
{
    if (!ctx)
        return -1;
    if (LIKELY(ctx->trace_level < trace_col))
        return 0;
    if (!ctx->trace)
        return -1;
    if (ctx->trace_level & 0xc0) {
        ctx->col = col;
        /* func/scope changed and they needed param/location event */
        ctx->trace(ctx, (ctx->trace_level & 0x80) ? trace_func : trace_scope);
        ctx->trace_level &= ~0xc0;
    }
    if (LIKELY(ctx->trace_level < trace_col))
        return 0;
    if (ctx->col != col) {
        ctx->col = col;
        ctx->trace(ctx, trace_col);
    } else {
        ctx->trace(ctx, trace_line);
    }
    if (LIKELY(ctx->trace_level < trace_op))
        return 0;
    if (ctx->trace_op && op)
        ctx->trace_op(ctx, (const char *)op);
    return 0;
}

uint32_t cli_bcapi_trace_value(struct cli_bc_ctx *ctx, const uint8_t *name, uint32_t value)
{
    if (!ctx)
        return -1;
    if (LIKELY(ctx->trace_level < trace_val))
        return 0;
    if (!ctx->trace)
        return -1;
    if (ctx->trace_level & 0x80) {
        if ((ctx->trace_level & 0x7f) < trace_param)
            return 0;
        ctx->trace(ctx, trace_param);
    }
    if (ctx->trace_val && name)
        ctx->trace_val(ctx, (const char *)name, value);
    return 0;
}

uint32_t cli_bcapi_trace_ptr(struct cli_bc_ctx *ctx, const uint8_t *ptr, uint32_t dummy)
{
    if (!ctx)
        return -1;
    UNUSEDPARAM(dummy);
    if (LIKELY(ctx->trace_level < trace_val))
        return 0;
    if (!ctx->trace)
        return -1;
    if (ctx->trace_level & 0x80) {
        if ((ctx->trace_level & 0x7f) < trace_param)
            return 0;
        ctx->trace(ctx, trace_param);
    }
    if (ctx->trace_ptr)
        ctx->trace_ptr(ctx, ptr);
    return 0;
}

uint32_t cli_bcapi_pe_rawaddr(struct cli_bc_ctx *ctx, uint32_t rva)
{
    uint32_t ret;
    unsigned err                      = 0;
    const struct cli_pe_hook_data *pe;

    if (!ctx || !ctx->hooks.pedata)
        return PE_INVALID_RVA;
    pe = ctx->hooks.pedata;
    if (!ctx->sections && pe->nsections)
        return PE_INVALID_RVA;

    ret = cli_rawaddr(rva, ctx->sections, pe->nsections, &err,
                      ctx->file_size, pe->hdr_size);
    if (err) {
        cli_dbgmsg("bcapi_pe_rawaddr invalid rva: %u\n", rva);
        return PE_INVALID_RVA;
    }
    return ret;
}

static inline const char *cli_memmem(const char *haystack, unsigned hlen,
                                     const unsigned char *needle, unsigned nlen)
{
    const char *p;
    unsigned char c;
    if (!needle || !haystack) {
        return NULL;
    }
    c = *needle++;
    if (nlen == 1)
        return memchr(haystack, c, hlen);

    while (hlen >= nlen) {
        p        = haystack;
        haystack = memchr(haystack, c, hlen - nlen + 1);
        if (!haystack)
            return NULL;
        hlen -= haystack + 1 - p;
        p = haystack + 1;
        if (!memcmp(p, needle, nlen - 1))
            return haystack;
        haystack = p;
    }
    return NULL;
}

static int64_t cli_bcapi_file_find_limit_common(struct cli_bc_ctx *ctx, const uint8_t *data,
                                                uint32_t len, uint64_t limit)
{
    fmap_t *map;
    uint64_t off;
    size_t n;

    if (!ctx)
        return -1;
    map = ctx->fmap;
    if (!map || !data || !len || !limit || ctx->off < 0) {
        cli_dbgmsg("bcapi_file_find preconditions not met\n");
        API_MISUSE();
        return -1;
    }
    char buf[4096];

    if (len > sizeof(buf) / 4)
        return -1;
    off = (uint64_t)ctx->off;
    if (off > limit || limit > (uint64_t)map->len)
        return -1;

    cli_event_int(EV, BCEV_OFFSET, off);
    cli_event_fastdata(EV, BCEV_FIND, data, len);
    for (;;) {
        const char *p;
        size_t readlen     = sizeof(buf);
        uint64_t remaining = limit - off;

        if (!remaining || off > (uint64_t)SIZE_MAX)
            return -1;
        if (remaining < readlen)
            readlen = (size_t)remaining;
        n = fmap_readn(map, buf, (size_t)off, readlen);
        if (n == (size_t)-1) {
            if (off < (uint64_t)map->len)
                cli_bcapi_mark_map_read_error(ctx, "Bytecode search could not read the complete input map");
            return -1;
        }
        if (n < len)
            return -1;
        p = cli_memmem(buf, n, data, len);
        if (p) {
            uint64_t result = off + (uint64_t)(p - buf);

            if (result > (uint64_t)INT64_MAX) {
                cli_bcapi_mark_coordinate_error(ctx, "Bytecode v2 file-find result exceeds the signed 64-bit ABI");
                return -1;
            }
            return (int64_t)result;
        }
        if ((uint64_t)n > limit - off || n <= (size_t)(len - 1))
            return -1;
        /* Keep the final len - 1 bytes in the next search window. Without
         * this overlap, a signature split across two fmap reads is missed. */
        off += n - (size_t)(len - 1);
    }
}

int32_t cli_bcapi_file_find(struct cli_bc_ctx *ctx, const uint8_t *data, uint32_t len)
{
    int64_t result;
    if (!ctx)
        return -1;
    result = cli_bcapi_file_find_limit_common(ctx, data, len, ctx->fmap ? ctx->fmap->len : 0);
    if (result > INT32_MAX) {
        cli_bcapi_mark_coordinate_error(ctx, "Bytecode v1 file-find result requires 64-bit matcher offsets");
        return -1;
    }
    return (int32_t)result;
}

int64_t cli_bcapi_file_find64(struct cli_bc_ctx *ctx, const uint8_t *data, uint32_t len)
{
    if (!ctx)
        return -1;
    return cli_bcapi_file_find_limit_common(ctx, data, len, ctx->fmap ? ctx->fmap->len : 0);
}

int32_t cli_bcapi_file_find_limit(struct cli_bc_ctx *ctx, const uint8_t *data, uint32_t len, int32_t limit)
{
    int64_t result;
    if (limit <= 0)
        return -1;
    result = cli_bcapi_file_find_limit_common(ctx, data, len, (uint32_t)limit);
    if (result > INT32_MAX) {
        cli_bcapi_mark_coordinate_error(ctx, "Bytecode v1 file-find result requires 64-bit matcher offsets");
        return -1;
    }
    return (int32_t)result;
}

int64_t cli_bcapi_file_find_limit64(struct cli_bc_ctx *ctx, const uint8_t *data, uint32_t len, uint64_t limit)
{
    if (!ctx)
        return -1;
    return cli_bcapi_file_find_limit_common(ctx, data, len, limit);
}

int32_t cli_bcapi_file_byteat64(struct cli_bc_ctx *ctx, uint64_t off)
{
    unsigned char c;
    size_t n;
    if (!ctx)
        return -1;
    if (!ctx->fmap || off > (uint64_t)SIZE_MAX) {
        cli_dbgmsg("bcapi_file_byteat64: invalid map or offset\n");
        return -1;
    }
    cli_event_int(EV, BCEV_OFFSET, off);
    n = fmap_readn(ctx->fmap, &c, (size_t)off, 1);
    if (n != 1) {
        if (n == (size_t)-1 && off < (uint64_t)ctx->fmap->len)
            cli_bcapi_mark_map_read_error(ctx, "Bytecode v2 byte lookup could not read the complete input map");
        return -1;
    }
    return c;
}

int32_t cli_bcapi_file_byteat(struct cli_bc_ctx *ctx, uint32_t off)
{
    return cli_bcapi_file_byteat64(ctx, off);
}

uint8_t *cli_bcapi_malloc(struct cli_bc_ctx *ctx, uint32_t size)
{
    void *v;

    if (!ctx)
        return NULL;
#if USE_MPOOL
    if (!ctx->mpool) {
        ctx->mpool = mpool_create();
        if (!ctx->mpool) {
            cli_dbgmsg("bytecode: mpool_create failed!\n");
            cli_event_error_oom(EV, 0);
            return NULL;
        }
    }

    if (0 == size || size > CLI_MAX_ALLOCATION) {
        cli_warnmsg("cli_bcapi_malloc(): File or section is too large to scan (" STDu32 " bytes). For your safety, ClamAV limits how much memory an operation can allocate to %d bytes\n",
                    size, CLI_MAX_ALLOCATION);
        v = NULL;
    } else {
        v = MPOOL_MALLOC(ctx->mpool, size);
    }
#else
    void **new_mallocs;

    if (0 == size || size > CLI_MAX_ALLOCATION) {
        cli_warnmsg("cli_bcapi_malloc(): File or section is too large to scan (" STDu32 " bytes). For your safety, ClamAV limits how much memory an operation can allocate to %d bytes\n",
                    size, CLI_MAX_ALLOCATION);
        v = NULL;
    } else {
        v = cli_max_malloc(size);
        if (v != NULL) {
            if (ctx->nmallocs == SIZE_MAX ||
                ctx->nmallocs + 1 > SIZE_MAX / sizeof(*ctx->mallocs)) {
                free(v);
                v = NULL;
            } else {
                new_mallocs = cli_max_realloc(ctx->mallocs,
                                              (ctx->nmallocs + 1) * sizeof(*ctx->mallocs));
                if (new_mallocs == NULL) {
                    free(v);
                    v = NULL;
                } else {
                    ctx->mallocs                = new_mallocs;
                    ctx->mallocs[ctx->nmallocs] = v;
                    ctx->nmallocs++;
                }
            }
        }
    }
#endif
    if (!v)
        cli_event_error_oom(EV, size);
    return v;
}

int32_t cli_bcapi_get_pe_section(struct cli_bc_ctx *ctx, struct cli_exe_section *section, uint32_t num)
{
    if (!ctx || !section || !ctx->hooks.pedata || !ctx->sections)
        return -1;
    if (num < ctx->hooks.pedata->nsections) {
        memcpy(section, &ctx->sections[num], sizeof(struct cli_exe_section));
        return 0;
    }
    return -1;
}

int32_t cli_bcapi_fill_buffer(struct cli_bc_ctx *ctx, uint8_t *buf,
                              uint32_t buflen, uint32_t filled,
                              uint32_t pos, uint32_t fill)
{
    int32_t res;
    uint32_t remaining, tofill;
    UNUSEDPARAM(fill);
    if (!ctx || !buf || !buflen || buflen > CLI_MAX_ALLOCATION ||
        filled > buflen || pos > filled) {
        cli_dbgmsg("fill_buffer1\n");
        if (ctx)
            API_MISUSE();
        return -1;
    }
    if (ctx->off >= ctx->file_size) {
        cli_dbgmsg("fill_buffer2\n");
        API_MISUSE();
        return 0;
    }
    remaining = filled - pos;
    if (remaining) {
        if (!CLI_ISCONTAINED(buf, buflen, buf + pos, remaining)) {
            cli_dbgmsg("fill_buffer3\n");
            API_MISUSE();
            return -1;
        }
        memmove(buf, buf + pos, remaining);
    }
    tofill = buflen - remaining;
    if (!CLI_ISCONTAINED(buf, buflen, buf + remaining, tofill)) {
        cli_dbgmsg("fill_buffer4\n");
        API_MISUSE();
        return -1;
    }
    res = cli_bcapi_read(ctx, buf + remaining, tofill);
    if (res <= 0) {
        cli_dbgmsg("fill_buffer5\n");
        API_MISUSE();
        return res;
    }
    return remaining + res;
}

int32_t cli_bcapi_extract_new(struct cli_bc_ctx *ctx, int32_t id)
{
    cli_ctx *cctx;
    cl_error_t res;
    bool discard_output;

    if (!ctx)
        return CL_ENULLARG;
    cctx = (cli_ctx *)ctx->ctx;
    if (ctx->output_failed) {
        cli_bcapi_mark_map_read_error(ctx, "Bytecode extracted output was incomplete");
        return CL_EWRITE;
    }

    cli_event_count(EV, BCEV_EXTRACTED);
    cli_dbgmsg("previous tempfile had " STDu64 " bytes\n", ctx->written);
    if (!ctx->written)
        return 0;
    if (ctx->ctx) {
        /* The reserved descriptor handoff below enters cli_magic_scan(),
         * which charges this extracted member exactly once as a child layer.
         * Do not pre-charge it here: doing so consumed MaxScanSize and
         * MaxFiles before the same member was admitted by the child scanner. */
        res = CL_SUCCESS;
    } else {
        cli_bcapi_mark_map_read_error(ctx, "Bytecode extracted output has no scan context");
        return CL_ENULLARG;
    }
    ctx->written = 0;
    if (lseek(ctx->outfd, 0, SEEK_SET) == -1) {
        cli_dbgmsg("bytecode: call to lseek() has failed\n");
        if (cctx)
            cli_mark_scan_incomplete(cctx, "Bytecode extracted output could not be rewound");
        return CL_ESEEK;
    }
    cli_dbgmsg("bytecode: scanning extracted file %s\n", ctx->tempfile);
    if (cctx) {
        if (ctx->temporary_reserved)
            res = cli_magic_scan_desc_type_reserved(ctx->outfd, ctx->tempfile, cctx, ctx->containertype, NULL, LAYER_ATTRIBUTES_NONE);
        else
            res = cli_magic_scan_desc_type(ctx->outfd, ctx->tempfile, cctx, ctx->containertype, NULL, LAYER_ATTRIBUTES_NONE);
        if (res == CL_VIRUS) {
            ctx->virname = cli_get_last_virus(cctx);
            ctx->found   = 1;
        }
    }
    discard_output = cctx && cctx->engine->keeptmp;
    if (!discard_output && ftruncate(ctx->outfd, 0) == -1) {
        cli_dbgmsg("ftruncate failed on %d\n", ctx->outfd);
        cli_bcapi_note_cleanup_failure(cctx, &res, CL_EWRITE,
                                        "Bytecode extracted output could not be truncated");
        discard_output = true;
    }
    if (discard_output) {
        if (close(ctx->outfd) == -1)
            cli_bcapi_note_cleanup_failure(cctx, &res, CL_EWRITE,
                                            "Bytecode extracted output could not be closed");
        ctx->outfd = -1;

        if (!(cctx && cctx->engine->keeptmp) && ctx->tempfile) {
            if (cli_unlink(ctx->tempfile))
                cli_bcapi_note_cleanup_failure(cctx, &res, CL_EUNLINK,
                                                "Bytecode extracted output could not be removed");
        }
        free(ctx->tempfile);
        ctx->tempfile = NULL;
    }
    if (ctx->temporary_reserved && cctx) {
        cli_scan_release_temporary(cctx, ctx->temporary_reserved);
        ctx->temporary_reserved = 0;
    }
    cli_dbgmsg("bytecode: extracting new file with id %u\n", id);
    return res;
}

#define BUF 16
int32_t cli_bcapi_read_number(struct cli_bc_ctx *ctx, uint32_t radix)
{
    unsigned i;
    const char *p;
    int32_t result;
    uint64_t off;

    if (!ctx || (radix != 10 && radix != 16) || !ctx->fmap)
        return -1;
    cli_event_int(EV, BCEV_OFFSET, ctx->off);
    while (ctx->off >= 0 && (uint64_t)ctx->off < ctx->fmap->len) {
        off = (uint64_t)ctx->off;
        /* A short final range is ordinary EOF for this strict, fixed-width
         * API. A failed contained request, however, means the backing map
         * could not supply bytes that are present in the input. */
        if (ctx->fmap->len - off < BUF)
            return -1;
        p = fmap_need_off_once(ctx->fmap, ctx->off, BUF);
        if (!p) {
            cli_bcapi_mark_map_read_error(ctx, "Bytecode number parsing could not read the complete input map");
            return -1;
        }
        for (i = 0; i < BUF; i++) {
            if ((p[i] >= '0' && p[i] <= '9') || (radix == 16 && ((p[i] >= 'a' && p[i] <= 'f') || (p[i] >= 'A' && p[i] <= 'F')))) {
                char *endptr;
                p = fmap_need_ptr_once(ctx->fmap, p + i, 16);
                if (!p) {
                    if (off + i <= ctx->fmap->len && ctx->fmap->len - (off + i) >= BUF)
                        cli_bcapi_mark_map_read_error(ctx, "Bytecode number parsing could not read the complete input map");
                    return -1;
                }
                result = strtoul(p, &endptr, radix);
                ctx->off += i + (endptr - p);
                return result;
            }
        }
        ctx->off += BUF;
    }
    return -1;
}

int32_t cli_bcapi_hashset_new(struct cli_bc_ctx *ctx)
{
    unsigned n;
    size_t table_size;
    struct cli_hashset *s;

    if (!ctx)
        return -1;

    if (cli_bcapi_table_size(ctx->nhashsets, sizeof(*ctx->hashsets), &n, &table_size) != 0) {
        cli_event_error_oom(EV, 0);
        return -1;
    }
    s = cli_max_realloc(ctx->hashsets, table_size);
    if (!s) {
        cli_event_error_oom(EV, 0);
        return -1;
    }
    ctx->hashsets = s;
    s             = &s[n - 1];
    if (cli_hashset_init(s, 16, 80) != CL_SUCCESS) {
        memset(s, 0, sizeof(*s));
        return -1;
    }
    ctx->nhashsets = n;
    return n - 1;
}

static struct cli_hashset *get_hashset(struct cli_bc_ctx *ctx, int32_t id)
{
    if (!ctx)
        return NULL;
    if (id < 0 || (unsigned int)id >= ctx->nhashsets || !ctx->hashsets) {
        API_MISUSE();
        return NULL;
    }
    return &ctx->hashsets[id];
}

int32_t cli_bcapi_hashset_add(struct cli_bc_ctx *ctx, int32_t id, uint32_t key)
{
    struct cli_hashset *s = get_hashset(ctx, id);
    if (!s)
        return -1;
    return cli_hashset_addkey(s, key) == CL_SUCCESS ? 0 : -1;
}

int32_t cli_bcapi_hashset_remove(struct cli_bc_ctx *ctx, int32_t id, uint32_t key)
{
    struct cli_hashset *s = get_hashset(ctx, id);
    if (!s)
        return -1;
    return cli_hashset_removekey(s, key) == CL_SUCCESS ? 0 : -1;
}

int32_t cli_bcapi_hashset_contains(struct cli_bc_ctx *ctx, int32_t id, uint32_t key)
{
    struct cli_hashset *s = get_hashset(ctx, id);
    if (!s)
        return -1;
    return cli_hashset_contains(s, key);
}

int32_t cli_bcapi_hashset_empty(struct cli_bc_ctx *ctx, int32_t id)
{
    struct cli_hashset *s = get_hashset(ctx, id);
    return s ? !s->count : 1;
}

int32_t cli_bcapi_hashset_done(struct cli_bc_ctx *ctx, int32_t id)
{
    struct cli_hashset *s = get_hashset(ctx, id);
    if (!s)
        return -1;
    cli_hashset_destroy(s);
    if ((unsigned int)id == ctx->nhashsets - 1) {
        ctx->nhashsets--;
        if (!ctx->nhashsets) {
            free(ctx->hashsets);
            ctx->hashsets = NULL;
        } else {
            s = cli_max_realloc(ctx->hashsets, ctx->nhashsets * sizeof(*s));
            if (s)
                ctx->hashsets = s;
        }
    }
    return 0;
}

int32_t cli_bcapi_buffer_pipe_new(struct cli_bc_ctx *ctx, uint32_t size)
{
    unsigned char *data;
    struct bc_buffer *b;
    unsigned n;
    size_t table_size;

    if (!ctx)
        return -1;

    if (cli_bcapi_table_size(ctx->nbuffers, sizeof(*ctx->buffers), &n, &table_size) != 0) {
        cli_event_error_oom(EV, 0);
        return -1;
    }

    data = cli_max_calloc(1, size);
    if (!data)
        return -1;
    b = cli_max_realloc(ctx->buffers, table_size);
    if (!b) {
        free(data);
        return -1;
    }
    ctx->buffers = b;
    b            = &b[n - 1];
    /* New slots must not inherit stale fmap ownership from the heap. */
    memset(b, 0, sizeof(*b));
    b->data         = data;
    b->size         = size;
    ctx->nbuffers   = n;
    return n - 1;
}

int32_t cli_bcapi_buffer_pipe_new_fromfile(struct cli_bc_ctx *ctx, uint32_t at)
{
    struct bc_buffer *b;
    unsigned n;
    size_t table_size;

    if (!ctx)
        return -1;

    if (cli_bcapi_table_size(ctx->nbuffers, sizeof(*ctx->buffers), &n, &table_size) != 0) {
        cli_event_error_oom(EV, 0);
        return -1;
    }

    if (at >= ctx->file_size)
        return -1;

    b = cli_max_realloc(ctx->buffers, table_size);
    if (!b) {
        return -1;
    }
    ctx->buffers = b;
    b            = &b[n - 1];
    memset(b, 0, sizeof(*b));
    /* NULL data means read from file at pos read_cursor */
    b->read_cursor = at;
    ctx->nbuffers  = n;
    return n - 1;
}

int32_t cli_bcapi_buffer_pipe_new_fromfile64(struct cli_bc_ctx *ctx, uint64_t at)
{
    struct bc_buffer *b;
    unsigned n;
    size_t table_size;

    if (!ctx)
        return -1;

    if (cli_bcapi_table_size(ctx->nbuffers, sizeof(*ctx->buffers), &n, &table_size) != 0) {
        cli_event_error_oom(EV, 0);
        return -1;
    }

    if (at >= ctx->file_size64 || at > (uint64_t)SIZE_MAX)
        return -1;

    b = cli_max_realloc(ctx->buffers, table_size);
    if (!b)
        return -1;
    ctx->buffers = b;
    b            = &b[n - 1];
    memset(b, 0, sizeof(*b));
    b->read_cursor = at;
    ctx->nbuffers  = n;
    return n - 1;
}

static struct bc_buffer *get_buffer(struct cli_bc_ctx *ctx, int32_t id)
{
    if (!ctx || !ctx->buffers || id < 0 || (unsigned int)id >= ctx->nbuffers) {
        cli_dbgmsg("bytecode api: invalid buffer id %u\n", id);
        return NULL;
    }
    return &ctx->buffers[id];
}

uint32_t cli_bcapi_buffer_pipe_read_avail(struct cli_bc_ctx *ctx, int32_t id)
{
    uint64_t available = cli_bcapi_buffer_pipe_read_avail64(ctx, id);
    return available > UINT32_MAX ? UINT32_MAX : (uint32_t)available;
}

uint64_t cli_bcapi_buffer_pipe_read_avail64(struct cli_bc_ctx *ctx, int32_t id)
{
    struct bc_buffer *b = get_buffer(ctx, id);
    if (!b)
        return 0;
    if (b->data) {
        if (b->write_cursor <= b->read_cursor)
            return 0;
        return b->write_cursor - b->read_cursor;
    }
    if (!ctx->fmap || b->read_cursor >= ctx->file_size64)
        return 0;
    if (ctx->file_size64 - b->read_cursor >= BUFSIZ)
        return BUFSIZ;
    return ctx->file_size64 - b->read_cursor;
}

static void cli_bcapi_buffer_pipe_release_map_read(struct bc_buffer *b)
{
    if (b == NULL || !b->map_read_locked)
        return;

    if (b->map_read_fmap != NULL && b->map_read_offset <= (uint64_t)SIZE_MAX)
        fmap_unneed_off(b->map_read_fmap, (size_t)b->map_read_offset, b->map_read_length);

    b->map_read_fmap   = NULL;
    b->map_read_offset = 0;
    b->map_read_length = 0;
    b->map_read_locked = 0;
}

const uint8_t *cli_bcapi_buffer_pipe_read_get(struct cli_bc_ctx *ctx, int32_t id, uint32_t size)
{
    struct bc_buffer *b = get_buffer(ctx, id);
    const uint8_t *result;

    if (!b || size > cli_bcapi_buffer_pipe_read_avail(ctx, id) || !size)
        return NULL;
    if (b->data)
        return b->data + b->read_cursor;

    /* A bytecode consumer owns the returned pointer until the matching
     * read_stopped() call. Release a previous window before replacing it so
     * an API consumer that retries a read cannot retain locked fmap pages. */
    cli_bcapi_buffer_pipe_release_map_read(b);
    if (ctx->fmap == NULL || b->read_cursor > (uint64_t)SIZE_MAX)
        return NULL;

    if (b->read_cursor > (uint64_t)ctx->fmap->len ||
        (uint64_t)size > (uint64_t)ctx->fmap->len - b->read_cursor) {
        cli_bcapi_mark_map_read_error(ctx, "Bytecode buffer-pipe input range is outside the input map");
        return NULL;
    }

    result = fmap_need_off(ctx->fmap, (size_t)b->read_cursor, size);
    if (result == NULL) {
        cli_bcapi_mark_map_read_error(ctx, "Bytecode buffer-pipe input could not be read completely");
        return NULL;
    }
    if (result != NULL) {
        b->map_read_fmap   = ctx->fmap;
        b->map_read_offset = b->read_cursor;
        b->map_read_length = size;
        b->map_read_locked = 1;
    }
    return result;
}

int32_t cli_bcapi_buffer_pipe_read_stopped(struct cli_bc_ctx *ctx, int32_t id, uint32_t amount)
{
    struct bc_buffer *b = get_buffer(ctx, id);
    if (!b)
        return -1;
    if (b->data) {
        if (b->write_cursor <= b->read_cursor)
            return -1;
        if (b->read_cursor + amount > b->write_cursor)
            b->read_cursor = b->write_cursor;
        else
            b->read_cursor += amount;
        if (b->read_cursor >= b->size &&
            b->write_cursor >= b->size)
            b->read_cursor = b->write_cursor = 0;
        return 0;
    }

    if (b->read_cursor > ctx->file_size64 || (uint64_t)amount > ctx->file_size64 - b->read_cursor) {
        cli_bcapi_buffer_pipe_release_map_read(b);
        b->read_cursor = ctx->file_size64;
        return -1;
    }

    cli_bcapi_buffer_pipe_release_map_read(b);
    b->read_cursor += amount;
    return 0;
}

uint32_t cli_bcapi_buffer_pipe_write_avail(struct cli_bc_ctx *ctx, int32_t id)
{
    struct bc_buffer *b = get_buffer(ctx, id);
    if (!b)
        return 0;
    if (!b->data)
        return 0;
    if (b->write_cursor >= b->size)
        return 0;
    return b->size - b->write_cursor;
}

uint8_t *cli_bcapi_buffer_pipe_write_get(struct cli_bc_ctx *ctx, int32_t id, uint32_t size)
{
    struct bc_buffer *b = get_buffer(ctx, id);
    if (!b || size > cli_bcapi_buffer_pipe_write_avail(ctx, id) || !size)
        return NULL;
    if (!b->data)
        return NULL;
    return b->data + b->write_cursor;
}

int32_t cli_bcapi_buffer_pipe_write_stopped(struct cli_bc_ctx *ctx, int32_t id, uint32_t size)
{
    struct bc_buffer *b = get_buffer(ctx, id);
    if (!b || !b->data)
        return -1;
    if (b->write_cursor + size >= b->size)
        b->write_cursor = b->size;
    else
        b->write_cursor += size;
    return 0;
}

int32_t cli_bcapi_buffer_pipe_done(struct cli_bc_ctx *ctx, int32_t id)
{
    struct bc_buffer *b = get_buffer(ctx, id);
    if (!b)
        return -1;
    cli_bcapi_buffer_pipe_release_map_read(b);
    free(b->data);
    b->data = NULL;
    return -0;
}

int32_t cli_bcapi_inflate_init(struct cli_bc_ctx *ctx, int32_t from, int32_t to, int32_t windowBits)
{
    int ret;
    z_stream stream;
    struct bc_inflate *b;
    unsigned n;
    size_t table_size;

    if (!ctx)
        return -1;

    if (cli_bcapi_table_size(ctx->ninflates, sizeof(*ctx->inflates), &n, &table_size) != 0) {
        cli_event_error_oom(EV, 0);
        return -1;
    }
    if (!get_buffer(ctx, from) || !get_buffer(ctx, to)) {
        cli_dbgmsg("bytecode api: inflate_init: invalid buffers!\n");
        return -1;
    }
    b = cli_max_realloc(ctx->inflates, table_size);
    if (!b) {
        return -1;
    }
    ctx->inflates = b;
    b              = &b[n - 1];

    b->from     = from;
    b->to       = to;
    b->needSync = 0;
    memset(&b->stream, 0, sizeof(stream));
    ret = inflateInit2(&b->stream, windowBits);
    switch (ret) {
        case Z_MEM_ERROR:
            cli_dbgmsg("bytecode api: inflateInit2: out of memory!\n");
            memset(b, 0, sizeof(*b));
            return -1;
        case Z_VERSION_ERROR:
            cli_dbgmsg("bytecode api: inflateinit2: zlib version error!\n");
            memset(b, 0, sizeof(*b));
            return -1;
        case Z_STREAM_ERROR:
            cli_dbgmsg("bytecode api: inflateinit2: zlib stream error!\n");
            memset(b, 0, sizeof(*b));
            return -1;
        case Z_OK:
            break;
        default:
            cli_dbgmsg("bytecode api: inflateInit2: unknown error %d\n", ret);
            memset(b, 0, sizeof(*b));
            return -1;
    }

    ctx->ninflates = n;
    return n - 1;
}

static struct bc_inflate *get_inflate(struct cli_bc_ctx *ctx, int32_t id)
{
    if (!ctx || id < 0 || (unsigned int)id >= ctx->ninflates || !ctx->inflates)
        return NULL;
    return &ctx->inflates[id];
}

int32_t cli_bcapi_inflate_process(struct cli_bc_ctx *ctx, int32_t id)
{
    int ret;
    unsigned avail_in_orig, avail_out_orig;
    struct bc_inflate *b = get_inflate(ctx, id);
    if (!b || b->from == -1 || b->to == -1)
        return -1;

    b->stream.avail_in = avail_in_orig =
        cli_bcapi_buffer_pipe_read_avail(ctx, b->from);

    b->stream.next_in = (void *)cli_bcapi_buffer_pipe_read_get(ctx, b->from,
                                                               b->stream.avail_in);

    b->stream.avail_out = avail_out_orig =
        cli_bcapi_buffer_pipe_write_avail(ctx, b->to);

    b->stream.next_out = cli_bcapi_buffer_pipe_write_get(ctx, b->to,
                                                         b->stream.avail_out);

    if (!b->stream.avail_in || !b->stream.avail_out || !b->stream.next_in || !b->stream.next_out)
        return -1;
    /* try hard to extract data, skipping over corrupted data */
    do {
        if (!b->needSync) {
            ret = inflate(&b->stream, Z_NO_FLUSH);
            if (ret == Z_DATA_ERROR) {
                cli_dbgmsg("bytecode api: inflate at %lu: %s, trying to recover\n", b->stream.total_in,
                           b->stream.msg);
                b->needSync = 1;
            }
        }
        if (b->needSync) {
            ret = inflateSync(&b->stream);
            if (ret == Z_OK) {
                cli_dbgmsg("bytecode api: successfully recovered inflate stream\n");
                b->needSync = 0;
                continue;
            }
        }
        break;
    } while (1);
    cli_bcapi_buffer_pipe_read_stopped(ctx, b->from, avail_in_orig - b->stream.avail_in);
    cli_bcapi_buffer_pipe_write_stopped(ctx, b->to, avail_out_orig - b->stream.avail_out);

    if (ret == Z_MEM_ERROR) {
        cli_dbgmsg("bytecode api: out of memory!\n");
        cli_bcapi_inflate_done(ctx, id);
        return ret;
    }
    if (ret == Z_STREAM_END) {
        cli_bcapi_inflate_done(ctx, id);
    }
    if (ret == Z_BUF_ERROR) {
        cli_dbgmsg("bytecode api: buffer error!\n");
    }

    return ret;
}

int32_t cli_bcapi_inflate_done(struct cli_bc_ctx *ctx, int32_t id)
{
    int ret;
    struct bc_inflate *b = get_inflate(ctx, id);
    if (!b || b->from == -1 || b->to == -1)
        return -1;
    ret = inflateEnd(&b->stream);
    if (ret == Z_STREAM_ERROR)
        cli_dbgmsg("bytecode api: inflateEnd: %s\n", b->stream.msg);
    b->from = b->to = -1;
    return ret;
}

int32_t cli_bcapi_lzma_init(struct cli_bc_ctx *ctx, int32_t from, int32_t to)
{
    int ret;
    struct bc_lzma *b;
    unsigned n;
    size_t table_size;
    unsigned avail_in_orig;

    if (!ctx)
        return -1;

    if (cli_bcapi_table_size(ctx->nlzmas, sizeof(*ctx->lzmas), &n, &table_size) != 0) {
        cli_event_error_oom(EV, 0);
        return -1;
    }

    if (!get_buffer(ctx, from) || !get_buffer(ctx, to)) {
        cli_dbgmsg("bytecode api: lzma_init: invalid buffers!\n");
        return -1;
    }

    avail_in_orig = cli_bcapi_buffer_pipe_read_avail(ctx, from);
    if (avail_in_orig < LZMA_PROPS_SIZE + 8) {
        cli_dbgmsg("bytecode api: lzma_init: not enough bytes in pipe to read LZMA header!\n");
        return -1;
    }

    b = cli_max_realloc(ctx->lzmas, table_size);
    if (!b) {
        return -1;
    }
    ctx->lzmas = b;
    b           = &b[n - 1];

    b->from = from;
    b->to   = to;
    memset(&b->stream, 0, sizeof(b->stream));

    b->stream.avail_in = avail_in_orig;

    b->stream.next_in = (void *)cli_bcapi_buffer_pipe_read_get(ctx, b->from,
                                                               b->stream.avail_in);

    if (!b->stream.next_in) {
        cli_bcapi_buffer_pipe_read_stopped(ctx, b->from, 0);
        memset(b, 0, sizeof(*b));
        return -1;
    }

    if ((ret = cli_LzmaInit(&b->stream, 0)) != LZMA_RESULT_OK) {
        cli_dbgmsg("bytecode api: LzmaInit: Failed to initialize LZMA decompressor: %d!\n", ret);
        cli_bcapi_buffer_pipe_read_stopped(ctx, b->from, avail_in_orig - b->stream.avail_in);
        cli_LzmaShutdown(&b->stream);
        memset(b, 0, sizeof(*b));
        return ret;
    }

    cli_bcapi_buffer_pipe_read_stopped(ctx, b->from, avail_in_orig - b->stream.avail_in);
    ctx->nlzmas = n;
    return n - 1;
}

static struct bc_lzma *get_lzma(struct cli_bc_ctx *ctx, int32_t id)
{
    if (!ctx || id < 0 || (unsigned int)id >= ctx->nlzmas || !ctx->lzmas)
        return NULL;
    return &ctx->lzmas[id];
}

int32_t cli_bcapi_lzma_process(struct cli_bc_ctx *ctx, int32_t id)
{
    int ret;
    unsigned avail_in_orig, avail_out_orig;
    struct bc_lzma *b = get_lzma(ctx, id);
    if (!b || b->from == -1 || b->to == -1)
        return -1;

    b->stream.avail_in = avail_in_orig =
        cli_bcapi_buffer_pipe_read_avail(ctx, b->from);

    b->stream.next_in = (void *)cli_bcapi_buffer_pipe_read_get(ctx, b->from,
                                                               b->stream.avail_in);

    b->stream.avail_out = avail_out_orig =
        cli_bcapi_buffer_pipe_write_avail(ctx, b->to);
    b->stream.next_out = (uint8_t *)cli_bcapi_buffer_pipe_write_get(ctx, b->to,
                                                                    b->stream.avail_out);

    if (!b->stream.avail_in || !b->stream.avail_out || !b->stream.next_in || !b->stream.next_out)
        return -1;

    ret = cli_LzmaDecode(&b->stream);
    cli_bcapi_buffer_pipe_read_stopped(ctx, b->from, avail_in_orig - b->stream.avail_in);
    cli_bcapi_buffer_pipe_write_stopped(ctx, b->to, avail_out_orig - b->stream.avail_out);

    if (ret != LZMA_RESULT_OK && ret != LZMA_STREAM_END) {
        cli_dbgmsg("bytecode api: LzmaDecode: Error %d while decoding\n", ret);
        cli_bcapi_lzma_done(ctx, id);
    }

    return ret;
}

int32_t cli_bcapi_lzma_done(struct cli_bc_ctx *ctx, int32_t id)
{
    struct bc_lzma *b = get_lzma(ctx, id);
    if (!b || b->from == -1 || b->to == -1)
        return -1;
    cli_LzmaShutdown(&b->stream);
    b->from = b->to = -1;
    return 0;
}

int32_t cli_bcapi_bzip2_init(struct cli_bc_ctx *ctx, int32_t from, int32_t to)
{
    int ret;
    struct bc_bzip2 *b;
    unsigned n;
    size_t table_size;

    if (!ctx)
        return -1;

    if (cli_bcapi_table_size(ctx->nbzip2s, sizeof(*ctx->bzip2s), &n, &table_size) != 0) {
        cli_event_error_oom(EV, 0);
        return -1;
    }
    if (!get_buffer(ctx, from) || !get_buffer(ctx, to)) {
        cli_dbgmsg("bytecode api: bzip2_init: invalid buffers!\n");
        return -1;
    }
    b = cli_max_realloc(ctx->bzip2s, table_size);
    if (!b) {
        return -1;
    }
    ctx->bzip2s = b;
    b            = &b[n - 1];

    b->from = from;
    b->to   = to;
    memset(&b->stream, 0, sizeof(b->stream));
    ret = BZ2_bzDecompressInit(&b->stream, 0, 0);
    switch (ret) {
        case BZ_CONFIG_ERROR:
            cli_dbgmsg("bytecode api: BZ2_bzDecompressInit: Library has been mis-compiled!\n");
            memset(b, 0, sizeof(*b));
            return -1;
        case BZ_PARAM_ERROR:
            cli_dbgmsg("bytecode api: BZ2_bzDecompressInit: Invalid arguments!\n");
            memset(b, 0, sizeof(*b));
            return -1;
        case BZ_MEM_ERROR:
            cli_dbgmsg("bytecode api: BZ2_bzDecompressInit: Insufficient memory available!\n");
            memset(b, 0, sizeof(*b));
            return -1;
        case BZ_OK:
            break;
        default:
            cli_dbgmsg("bytecode api: BZ2_bzDecompressInit: unknown error %d\n", ret);
            memset(b, 0, sizeof(*b));
            return -1;
    }

    ctx->nbzip2s = n;
    return n - 1;
}

static struct bc_bzip2 *get_bzip2(struct cli_bc_ctx *ctx, int32_t id)
{
    if (!ctx || id < 0 || (unsigned int)id >= ctx->nbzip2s || !ctx->bzip2s)
        return NULL;
    return &ctx->bzip2s[id];
}

int32_t cli_bcapi_bzip2_process(struct cli_bc_ctx *ctx, int32_t id)
{
    int ret;
    unsigned avail_in_orig, avail_out_orig;
    struct bc_bzip2 *b = get_bzip2(ctx, id);
    if (!b || b->from == -1 || b->to == -1)
        return -1;

    b->stream.avail_in = avail_in_orig =
        cli_bcapi_buffer_pipe_read_avail(ctx, b->from);

    b->stream.next_in = (void *)cli_bcapi_buffer_pipe_read_get(ctx, b->from,
                                                               b->stream.avail_in);

    b->stream.avail_out = avail_out_orig =
        cli_bcapi_buffer_pipe_write_avail(ctx, b->to);

    b->stream.next_out = (char *)cli_bcapi_buffer_pipe_write_get(ctx, b->to,
                                                                 b->stream.avail_out);

    if (!b->stream.avail_in || !b->stream.avail_out || !b->stream.next_in || !b->stream.next_out)
        return -1;
    /* try hard to extract data, skipping over corrupted data */
    ret = BZ2_bzDecompress(&b->stream);
    cli_bcapi_buffer_pipe_read_stopped(ctx, b->from, avail_in_orig - b->stream.avail_in);
    cli_bcapi_buffer_pipe_write_stopped(ctx, b->to, avail_out_orig - b->stream.avail_out);

    /* check if nothing written whatsoever */
    if ((ret != BZ_OK) && (b->stream.avail_out == avail_out_orig)) {
        /* Inflation failed */
        cli_errmsg("cli_bcapi_bzip2_process: failed to decompress data\n");
    }

    return ret;
}

int32_t cli_bcapi_bzip2_done(struct cli_bc_ctx *ctx, int32_t id)
{
    int ret;
    struct bc_bzip2 *b = get_bzip2(ctx, id);
    if (!b || b->from == -1 || b->to == -1)
        return -1;
    ret = BZ2_bzDecompressEnd(&b->stream);
    if (ret != BZ_OK)
        cli_mark_scan_incomplete((cli_ctx *)ctx->ctx,
                                 "Bytecode BZIP2 decompressor could not be finalized");
    b->from = b->to = -1;
    return ret;
}

int32_t cli_bcapi_bytecode_rt_error(struct cli_bc_ctx *ctx, int32_t id)
{
    int32_t line = id >> 8;
    int32_t col  = id & 0xff;
    UNUSEDPARAM(ctx);
    cli_warnmsg("Bytecode runtime error at line %u, col %u\n", line, col);
    return 0;
}

int32_t cli_bcapi_jsnorm_init(struct cli_bc_ctx *ctx, int32_t from)
{
    struct parser_state *state;
    struct bc_jsnorm *b;
    unsigned n;
    size_t table_size;

    if (!ctx)
        return -1;

    if (cli_bcapi_table_size(ctx->njsnorms, sizeof(*ctx->jsnorms), &n, &table_size) != 0) {
        cli_event_error_oom(EV, 0);
        return -1;
    }
    if (!get_buffer(ctx, from)) {
        cli_dbgmsg("bytecode api: jsnorm_init: invalid buffers!\n");
        return -1;
    }
    state = cli_js_init();
    if (!state)
        return -1;
    b = cli_max_realloc(ctx->jsnorms, table_size);
    if (!b) {
        cli_js_destroy(state);
        return -1;
    }
    ctx->jsnorms = b;
    b             = &b[n - 1];
    b->from       = from;
    b->state      = state;
    if (!ctx->jsnormdir) {
        cli_ctx *cctx  = (cli_ctx *)ctx->ctx;
        ctx->jsnormdir = cli_gentemp_with_prefix(cctx && cctx->engine ? cctx->engine->tmpdir : NULL, "normalized-js");
        if (!ctx->jsnormdir) {
            cli_bcapi_mark_map_read_error(ctx, "Bytecode normalized JavaScript directory could not be allocated");
            cli_js_destroy(b->state);
            memset(b, 0, sizeof(*b));
            return -1;
        }
        if (mkdir(ctx->jsnormdir, 0700)) {
            cli_dbgmsg("js: can't create temp dir %s\n", ctx->jsnormdir);
            cli_bcapi_mark_map_read_error(ctx, "Bytecode normalized JavaScript directory could not be created");
            free(ctx->jsnormdir);
            ctx->jsnormdir = NULL;
            cli_js_destroy(b->state);
            memset(b, 0, sizeof(*b));
            return CL_ETMPDIR;
        }
    }
    ctx->njsnorms = n;
    return n - 1;
}

static struct bc_jsnorm *get_jsnorm(struct cli_bc_ctx *ctx, int32_t id)
{
    if (!ctx || id < 0 || (unsigned int)id >= ctx->njsnorms || !ctx->jsnorms)
        return NULL;
    return &ctx->jsnorms[id];
}

int32_t cli_bcapi_jsnorm_process(struct cli_bc_ctx *ctx, int32_t id)
{
    unsigned avail;
    const unsigned char *in;
    cli_ctx *cctx;
    struct bc_jsnorm *b;

    if (!ctx)
        return -1;
    cctx = ctx->ctx;
    b    = get_jsnorm(ctx, id);
    if (!b || b->from == -1 || !b->state)
        return -1;

    avail = cli_bcapi_buffer_pipe_read_avail(ctx, b->from);
    in    = cli_bcapi_buffer_pipe_read_get(ctx, b->from, avail);
    if (!avail || !in)
        return -1;
    if (cctx && UINT64_MAX - ctx->jsnormwritten < (uint64_t)avail) {
        cli_bcapi_mark_map_read_error(ctx, "JavaScript normalization input accounting overflowed");
        return -1;
    }
    if (cctx && cli_checklimits("bytecode js api", cctx, ctx->jsnormwritten + avail, 0, 0)) {
        (void)cli_bcapi_buffer_pipe_read_stopped(ctx, b->from, avail);
        return -1;
    }
    cli_bcapi_buffer_pipe_read_stopped(ctx, b->from, avail);
    cli_js_process_buffer(b->state, (char *)in, avail);
    ctx->jsnormwritten += avail;
    return 0;
}

int32_t cli_bcapi_jsnorm_done(struct cli_bc_ctx *ctx, int32_t id)
{
    struct bc_jsnorm *b = get_jsnorm(ctx, id);
    cl_error_t output_status;

    if (!b || b->from == -1)
        return -1;
    ctx->jsnormwritten = 0;
    cli_js_parse_done(b->state);
    output_status = cli_js_output_ctx(b->state, ctx->jsnormdir, (cli_ctx *)ctx->ctx);
    if (output_status != CL_SUCCESS) {
        cli_bcapi_mark_map_read_error(ctx, "JavaScript normalization output could not be completed");
        cli_js_destroy(b->state);
        b->state = NULL;
        b->from  = -1;
        return -1;
    }
    cli_js_destroy(b->state);
    b->state = NULL;
    b->from  = -1;
    return 0;
}

static inline double myround(double a)
{
    if (a < 0)
        return a - 0.5;
    return a + 0.5;
}

int32_t cli_bcapi_ilog2(struct cli_bc_ctx *ctx, uint32_t a, uint32_t b)
{
    double f;
    UNUSEDPARAM(ctx);
    if (!b)
        return 0x7fffffff;
    /* log(a/b) is -32..32, so 2^26*32=2^31 covers the entire range of int32 */
    f = (1 << 26) * log((double)a / b) / log(2);
    return (int32_t)myround(f);
}

int32_t cli_bcapi_ipow(struct cli_bc_ctx *ctx, int32_t a, int32_t b, int32_t c)
{
    UNUSEDPARAM(ctx);
    if (!a && b < 0)
        return 0x7fffffff;
    return (int32_t)myround(c * pow(a, b));
}

uint32_t cli_bcapi_iexp(struct cli_bc_ctx *ctx, int32_t a, int32_t b, int32_t c)
{
    double f;
    UNUSEDPARAM(ctx);
    if (!b)
        return 0x7fffffff;
    f = c * exp((double)a / b);
    return (uint32_t)myround(f);
}

int32_t cli_bcapi_isin(struct cli_bc_ctx *ctx, int32_t a, int32_t b, int32_t c)
{
    double f;
    UNUSEDPARAM(ctx);
    if (!b)
        return 0x7fffffff;
    f = c * sin((double)a / b);
    return (int32_t)myround(f);
}

int32_t cli_bcapi_icos(struct cli_bc_ctx *ctx, int32_t a, int32_t b, int32_t c)
{
    double f;
    UNUSEDPARAM(ctx);
    if (!b)
        return 0x7fffffff;
    f = c * cos((double)a / b);
    return (int32_t)myround(f);
}

int32_t cli_bcapi_memstr(struct cli_bc_ctx *ctx, const uint8_t *h, int32_t hs,
                         const uint8_t *n, int32_t ns)
{
    const uint8_t *s;
    if (!ctx || !h || !n || hs < 0 || ns < 0) {
        if (!ctx)
            return -1;
        API_MISUSE();
        return -1;
    }
    cli_event_fastdata(EV, BCEV_MEM_1, h, hs);
    cli_event_fastdata(EV, BCEV_MEM_2, n, ns);
    s = (const uint8_t *)cli_memstr((const char *)h, hs, (const char *)n, ns);
    if (!s)
        return -1;
    return s - h;
}

int32_t cli_bcapi_hex2ui(struct cli_bc_ctx *ctx, uint32_t ah, uint32_t bh)
{
    char result = 0;
    unsigned char in[2];
    UNUSEDPARAM(ctx);

    in[0] = ah;
    in[1] = bh;

    if (cli_hex2str_to((const char *)in, &result, 2) == -1)
        return -1;
    return result;
}

int32_t cli_bcapi_atoi(struct cli_bc_ctx *ctx, const uint8_t *str, int32_t len)
{
    int32_t number = 0;
    const uint8_t *end;
    UNUSEDPARAM(ctx);

    if (!str || len <= 0)
        return -1;
    end = str + len;
    while (str < end && isspace((unsigned char)*str))
        str++;
    if (str == end)
        return -1; /* all spaces */
    if (*str == '+')
        str++;
    if (str == end)
        return -1; /* all spaces and +*/
    if (*str == '-')
        return -1; /* only positive numbers */
    if (!isdigit((unsigned char)*str))
        return -1;
    while (str < end && isdigit((unsigned char)*str)) {
        int digit = *str - '0';
        if (number > (INT32_MAX - digit) / 10)
            return -1;
        number = number * 10 + digit;
        str++;
    }
    return number;
}

uint32_t cli_bcapi_debug_print_str_start(struct cli_bc_ctx *ctx, const uint8_t *s, uint32_t len)
{
    int print_len;

    if (!ctx || !s || len == 0)
        return -1;
    print_len = len > (uint32_t)INT_MAX ? INT_MAX : (int)len;
    cli_event_fastdata(EV, BCEV_DBG_STR, s, len);
    cli_dbgmsg("bytecode debug: %.*s", print_len, s);
    return 0;
}

uint32_t cli_bcapi_debug_print_str_nonl(struct cli_bc_ctx *ctx, const uint8_t *s, uint32_t len)
{
    if (!ctx || !s || len == 0)
        return -1;
    if (!cli_debug_flag)
        return 0;
    return fwrite(s, 1, len, stderr);
}

uint32_t cli_bcapi_entropy_buffer(struct cli_bc_ctx *ctx, uint8_t *s, int32_t len)
{
    uint32_t probTable[256];
    unsigned int i;
    double entropy = 0;
    double log2    = log(2);

    UNUSEDPARAM(ctx);

    if (!s || len <= 0)
        return -1;
    memset(probTable, 0, sizeof(probTable));
    for (i = 0; i < (unsigned int)len; i++) {
        probTable[s[i]]++;
    }
    for (i = 0; i < 256; i++) {
        double p;
        if (!probTable[i])
            continue;
        p = (double)probTable[i] / len;
        entropy += -p * log(p) / log2;
    }
    entropy *= 1 << 26;
    return (uint32_t)entropy;
}

int32_t cli_bcapi_map_new(struct cli_bc_ctx *ctx, int32_t keysize, int32_t valuesize)
{
    unsigned n;
    size_t table_size;
    struct cli_map *s;

    if (!ctx)
        return -1;

    if (cli_bcapi_table_size(ctx->nmaps, sizeof(*ctx->maps), &n, &table_size) != 0) {
        cli_event_error_oom(EV, 0);
        return -1;
    }
    if (keysize <= 0 || valuesize < 0)
        return -1;
    s = cli_max_realloc(ctx->maps, table_size);
    if (!s)
        return -1;
    ctx->maps = s;
    s          = &s[n - 1];
    if (cli_map_init(s, keysize, valuesize, 16) != CL_SUCCESS) {
        memset(s, 0, sizeof(*s));
        return -1;
    }
    ctx->nmaps = n;
    return n - 1;
}

static struct cli_map *get_hashtab(struct cli_bc_ctx *ctx, int32_t id)
{
    if (!ctx || id < 0 || (unsigned int)id >= ctx->nmaps || !ctx->maps)
        return NULL;
    return &ctx->maps[id];
}

int32_t cli_bcapi_map_addkey(struct cli_bc_ctx *ctx, const uint8_t *key, int32_t keysize, int32_t id)
{
    cl_error_t ret;
    struct cli_map *s = get_hashtab(ctx, id);
    if (!s)
        return -1;

    ret = cli_map_addkey(s, key, keysize);
    switch (ret) {
        case CL_SUCCESS: {
            // key didn't exist and was added
            return 1;
        }
        case CL_ECREAT: {
            // already added
            return 0;
        }
        default: {
            // error occurred
            return -1;
        }
    }
}

int32_t cli_bcapi_map_setvalue(struct cli_bc_ctx *ctx, const uint8_t *value, int32_t valuesize, int32_t id)
{
    struct cli_map *s = get_hashtab(ctx, id);
    if (!s)
        return -1;
    return cli_map_setvalue(s, value, valuesize) == CL_SUCCESS ? 0 : -1;
}

int32_t cli_bcapi_map_remove(struct cli_bc_ctx *ctx, const uint8_t *key, int32_t keysize, int32_t id)
{
    cl_error_t ret;
    struct cli_map *s = get_hashtab(ctx, id);
    if (!s)
        return -1;

    ret = cli_map_removekey(s, key, keysize);
    switch (ret) {
        case CL_SUCCESS: {
            // found and removed
            return 1;
        }
        case CL_EUNLINK: {
            // not found
            return 0;
        }
        default: {
            // error occurred
            return -1;
        }
    }
}

int32_t cli_bcapi_map_find(struct cli_bc_ctx *ctx, const uint8_t *key, int32_t keysize, int32_t id)
{
    cl_error_t ret;
    struct cli_map *s = get_hashtab(ctx, id);
    if (!s)
        return -1;

    ret = cli_map_find(s, key, keysize);
    switch (ret) {
        case CL_SUCCESS: {
            // found
            return 1;
        }
        case CL_EACCES: {
            // not found
            return 0;
        }
        default: {
            // error occurred
            return -1;
        }
    }
}

int32_t cli_bcapi_map_getvaluesize(struct cli_bc_ctx *ctx, int32_t id)
{
    struct cli_map *s = get_hashtab(ctx, id);
    if (!s)
        return -1;
    return cli_map_getvalue_size(s);
}

uint8_t *cli_bcapi_map_getvalue(struct cli_bc_ctx *ctx, int32_t id, int32_t valuesize)
{
    struct cli_map *s = get_hashtab(ctx, id);
    if (!s)
        return NULL;
    if (cli_map_getvalue_size(s) != valuesize)
        return NULL;
    return (uint8_t *)cli_map_getvalue(s);
}

int32_t cli_bcapi_map_done(struct cli_bc_ctx *ctx, int32_t id)
{
    struct cli_map *s = get_hashtab(ctx, id);
    if (!s)
        return -1;
    cli_map_delete(s);
    if ((unsigned int)id == ctx->nmaps - 1) {
        ctx->nmaps--;
        if (!ctx->nmaps) {
            free(ctx->maps);
            ctx->maps = NULL;
        } else {
            s = cli_max_realloc(ctx->maps, ctx->nmaps * (sizeof(*s)));
            if (s)
                ctx->maps = s;
        }
    }
    return 0;
}

uint32_t cli_bcapi_engine_functionality_level(struct cli_bc_ctx *ctx)
{
    UNUSEDPARAM(ctx);
    return cl_retflevel();
}

uint32_t cli_bcapi_engine_dconf_level(struct cli_bc_ctx *ctx)
{
    UNUSEDPARAM(ctx);
    return CL_FLEVEL_DCONF;
}

uint32_t cli_bcapi_engine_scan_options(struct cli_bc_ctx *ctx)
{
    cli_ctx *cctx;
    uint32_t options = 0;

    if (ctx == NULL || ctx->ctx == NULL)
        return 0;
    cctx = (cli_ctx *)ctx->ctx;
    if (cctx->options == NULL)
        return 0;
    options = CL_SCAN_RAW;

    if (cctx->options->general & CL_SCAN_GENERAL_ALLMATCHES)
        options |= CL_SCAN_ALLMATCHES;
    if (cctx->options->general & CL_SCAN_GENERAL_HEURISTICS)
        options |= CL_SCAN_ALGORITHMIC;
    if (cctx->options->general & CL_SCAN_GENERAL_COLLECT_METADATA)
        options |= CL_SCAN_FILE_PROPERTIES;
    if (cctx->options->general & CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE)
        options |= CL_SCAN_HEURISTIC_PRECEDENCE;

    if (cctx->options->parse & CL_SCAN_PARSE_ARCHIVE)
        options |= CL_SCAN_ARCHIVE;
    if (cctx->options->parse & CL_SCAN_PARSE_ELF)
        options |= CL_SCAN_ELF;
    if (cctx->options->parse & CL_SCAN_PARSE_PDF)
        options |= CL_SCAN_PDF;
    if (cctx->options->parse & CL_SCAN_PARSE_SWF)
        options |= CL_SCAN_SWF;
    if (cctx->options->parse & CL_SCAN_PARSE_HWP3)
        options |= CL_SCAN_HWP3;
    if (cctx->options->parse & CL_SCAN_PARSE_XMLDOCS)
        options |= CL_SCAN_XMLDOCS;
    if (cctx->options->parse & CL_SCAN_PARSE_MAIL)
        options |= CL_SCAN_MAIL;
    if (cctx->options->parse & CL_SCAN_PARSE_OLE2)
        options |= CL_SCAN_OLE2;
    if (cctx->options->parse & CL_SCAN_PARSE_HTML)
        options |= CL_SCAN_HTML;
    if (cctx->options->parse & CL_SCAN_PARSE_PE)
        options |= CL_SCAN_PE;
    // if (cctx->options->parse & CL_SCAN_MAIL_URL)
    //    options |= CL_SCAN_MAILURL; /* deprecated circa 2009 */

    if (cctx->options->heuristic & CL_SCAN_HEURISTIC_BROKEN)
        options |= CL_SCAN_BLOCKBROKEN;
    if (cctx->options->heuristic & CL_SCAN_HEURISTIC_EXCEEDS_MAX)
        options |= CL_SCAN_BLOCKMAX;
    if (cctx->options->heuristic & CL_SCAN_HEURISTIC_PHISHING_SSL_MISMATCH)
        options |= CL_SCAN_PHISHING_BLOCKSSL;
    if (cctx->options->heuristic & CL_SCAN_HEURISTIC_PHISHING_CLOAK)
        options |= CL_SCAN_PHISHING_BLOCKCLOAK;
    if (cctx->options->heuristic & CL_SCAN_HEURISTIC_MACROS)
        options |= CL_SCAN_BLOCKMACROS;
    if ((cctx->options->heuristic & CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE) ||
        (cctx->options->heuristic & CL_SCAN_HEURISTIC_ENCRYPTED_DOC))
        options |= CL_SCAN_BLOCKENCRYPTED;
    if (cctx->options->heuristic & CL_SCAN_HEURISTIC_PARTITION_INTXN)
        options |= CL_SCAN_PARTITION_INTXN;
    if (cctx->options->heuristic & CL_SCAN_HEURISTIC_STRUCTURED)
        options |= CL_SCAN_STRUCTURED;
    if (cctx->options->heuristic & CL_SCAN_HEURISTIC_STRUCTURED_SSN_NORMAL)
        options |= CL_SCAN_STRUCTURED_SSN_NORMAL;
    if (cctx->options->heuristic & CL_SCAN_HEURISTIC_STRUCTURED_SSN_STRIPPED)
        options |= CL_SCAN_STRUCTURED_SSN_STRIPPED;

    if (cctx->options->mail & CL_SCAN_MAIL_PARTIAL_MESSAGE)
        options |= CL_SCAN_PARTIAL_MESSAGE;

    if (cctx->options->dev & CL_SCAN_DEV_COLLECT_SHA)
        options |= CL_SCAN_INTERNAL_COLLECT_SHA;
    if (cctx->options->dev & CL_SCAN_DEV_COLLECT_PERFORMANCE_INFO)
        options |= CL_SCAN_PERFORMANCE_INFO;

    return options;
}

static bool cli_bcapi_option_name_equal(const uint8_t *option_name, uint32_t name_len,
                                        const char *expected)
{
    size_t i;
    size_t expected_len = strlen(expected);

    if ((size_t)name_len != expected_len)
        return false;
    for (i = 0; i < expected_len; i++) {
        uint8_t actual = option_name[i];

        if (actual >= 'A' && actual <= 'Z')
            actual = (uint8_t)(actual + ('a' - 'A'));
        if (actual != (uint8_t)expected[i])
            return false;
    }
    return true;
}

uint32_t cli_bcapi_engine_scan_options_ex(struct cli_bc_ctx *ctx, const uint8_t *option_name, uint32_t name_len)
{
    uint32_t result = 0;

    if (ctx == NULL || option_name == NULL || name_len == 0) {
        cli_warnmsg("engine_scan_options_ex: Invalid arguments!\n");
        goto done;
    }

    cli_ctx *cctx = (cli_ctx *)ctx->ctx;
    if (cctx == NULL || cctx->options == NULL) {
        cli_warnmsg("engine_scan_options_ex: Invalid arguments!\n");
        goto done;
    }

#define OPTION_IS(name) cli_bcapi_option_name_equal(option_name, name_len, (name))
    if (OPTION_IS("general allmatch"))
        result = !!(cctx->options->general & CL_SCAN_GENERAL_ALLMATCHES);
    else if (OPTION_IS("general collect metadata"))
        result = !!(cctx->options->general & CL_SCAN_GENERAL_COLLECT_METADATA);
    else if (OPTION_IS("general heuristics"))
        result = !!(cctx->options->general & CL_SCAN_GENERAL_HEURISTICS);
    else if (OPTION_IS("heuristic precedence"))
        result = !!(cctx->options->general & CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE);
    else if (OPTION_IS("parse archive"))
        result = !!(cctx->options->parse & CL_SCAN_PARSE_ARCHIVE);
    else if (OPTION_IS("parse elf"))
        result = !!(cctx->options->parse & CL_SCAN_PARSE_ELF);
    else if (OPTION_IS("parse pdf"))
        result = !!(cctx->options->parse & CL_SCAN_PARSE_PDF);
    else if (OPTION_IS("parse swf"))
        result = !!(cctx->options->parse & CL_SCAN_PARSE_SWF);
    else if (OPTION_IS("parse hwp3"))
        result = !!(cctx->options->parse & CL_SCAN_PARSE_HWP3);
    else if (OPTION_IS("parse xmldocs"))
        result = !!(cctx->options->parse & CL_SCAN_PARSE_XMLDOCS);
    else if (OPTION_IS("parse mail"))
        result = !!(cctx->options->parse & CL_SCAN_PARSE_MAIL);
    else if (OPTION_IS("parse ole2"))
        result = !!(cctx->options->parse & CL_SCAN_PARSE_OLE2);
    else if (OPTION_IS("parse html"))
        result = !!(cctx->options->parse & CL_SCAN_PARSE_HTML);
    else if (OPTION_IS("parse pe"))
        result = !!(cctx->options->parse & CL_SCAN_PARSE_PE);
    else if (OPTION_IS("heuristic broken"))
        result = !!(cctx->options->heuristic & CL_SCAN_HEURISTIC_BROKEN);
    else if (OPTION_IS("heuristic exceeds max"))
        result = !!(cctx->options->heuristic & CL_SCAN_HEURISTIC_EXCEEDS_MAX);
    else if (OPTION_IS("heuristic phishing ssl mismatch"))
        result = !!(cctx->options->heuristic & CL_SCAN_HEURISTIC_PHISHING_SSL_MISMATCH);
    else if (OPTION_IS("heuristic phishing cloak"))
        result = !!(cctx->options->heuristic & CL_SCAN_HEURISTIC_PHISHING_CLOAK);
    else if (OPTION_IS("heuristic macros"))
        result = !!(cctx->options->heuristic & CL_SCAN_HEURISTIC_MACROS);
    else if (OPTION_IS("heuristic encrypted archive"))
        result = !!(cctx->options->heuristic & CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE);
    else if (OPTION_IS("heuristic encrypted doc"))
        result = !!(cctx->options->heuristic & CL_SCAN_HEURISTIC_ENCRYPTED_DOC);
    else if (OPTION_IS("heuristic partition intersection"))
        result = !!(cctx->options->heuristic & CL_SCAN_HEURISTIC_PARTITION_INTXN);
    else if (OPTION_IS("heuristic structured"))
        result = !!(cctx->options->heuristic & CL_SCAN_HEURISTIC_STRUCTURED);
    else if (OPTION_IS("heuristic structured ssn normal"))
        result = !!(cctx->options->heuristic & CL_SCAN_HEURISTIC_STRUCTURED_SSN_NORMAL);
    else if (OPTION_IS("heuristic structured ssn stripped"))
        result = !!(cctx->options->heuristic & CL_SCAN_HEURISTIC_STRUCTURED_SSN_STRIPPED);
    else if (OPTION_IS("mail partial message"))
        result = !!(cctx->options->mail & CL_SCAN_MAIL_PARTIAL_MESSAGE);
    else if (OPTION_IS("dev collect sha"))
        result = !!(cctx->options->dev & CL_SCAN_DEV_COLLECT_SHA);
    else if (OPTION_IS("dev collect performance info"))
        result = !!(cctx->options->dev & CL_SCAN_DEV_COLLECT_PERFORMANCE_INFO);
#undef OPTION_IS

done:
    return result;
}

uint32_t cli_bcapi_engine_db_options(struct cli_bc_ctx *ctx)
{
    cli_ctx *cctx;

    if (ctx == NULL || ctx->ctx == NULL)
        return 0;
    cctx = (cli_ctx *)ctx->ctx;
    if (cctx->engine == NULL)
        return 0;
    return cctx->engine->dboptions;
}

int32_t cli_bcapi_extract_set_container(struct cli_bc_ctx *ctx, uint32_t ftype)
{
    if (!ctx || ftype > CL_TYPE_IGNORED)
        return -1;
    ctx->containertype = ftype;
    return 0;
}

int32_t cli_bcapi_input_switch(struct cli_bc_ctx *ctx, int32_t extracted_file)
{
    fmap_t *map;

    if (!ctx)
        return -1;
    if (0 == extracted_file) {
        /*
         * Set input back to original fmap.
         */
        if (0 == ctx->extracted_file_input) {
            /* Input already set to original fmap, nothing to do. */
            return 0;
        }

        /* Free the fmap used for the extracted file */
        fmap_free(ctx->fmap);

        /* Restore pointer to original fmap */
        cli_bytecode_context_setfile(ctx, ctx->save_map);
        ctx->save_map = NULL;

        ctx->extracted_file_input = 0;
        cli_dbgmsg("bytecode api: input switched back to main file\n");
        return 0;
    } else {
        /*
         * Set input to extracted file.
         */
        if (1 == ctx->extracted_file_input) {
            /* Input already set to extracted file, nothing to do. */
            return 0;
        }

        if (ctx->outfd < 0) {
            /* no valid fd to switch to use for fmap */
            return -1;
        }

        /* Create fmap for the extracted file */
        map = fmap_new(ctx->outfd, 0, 0, NULL, ctx->tempfile);
        if (!map) {
            cli_warnmsg("can't mmap() extracted temporary file %s\n", ctx->tempfile);
            return -1;
        }

        /* Save off pointer to original fmap */
        ctx->save_map = ctx->fmap;
        cli_bytecode_context_setfile(ctx, map);

        ctx->extracted_file_input = 1;
        cli_dbgmsg("bytecode api: input switched to extracted file\n");
        return 0;
    }
}

uint32_t cli_bcapi_get_environment(struct cli_bc_ctx *ctx, struct cli_environment *env, uint32_t len)
{
    if (!ctx || !env || len > sizeof(*env) || (len && !ctx->env)) {
        if (!ctx)
            return -1;
        cli_dbgmsg("cli_bcapi_get_environment len %u > %lu\n", len, (unsigned long)sizeof(*env));
        return -1;
    }
    memcpy(env, ctx->env, len);
    return 0;
}

uint32_t cli_bcapi_disable_bytecode_if(struct cli_bc_ctx *ctx, const int8_t *reason, uint32_t len, uint32_t cond)
{
    UNUSEDPARAM(len);
    if (!ctx || !ctx->bc || (cond && !reason))
        return -1;
    if (ctx->bc->kind != BC_STARTUP) {
        cli_dbgmsg("Bytecode must be BC_STARTUP to call disable_bytecode_if\n");
        return -1;
    }
    if (!cond)
        return ctx->bytecode_disable_status;
    if (*reason == '^')
        cli_warnmsg("Bytecode: disabling completely because %s\n", reason + 1);
    else
        cli_dbgmsg("Bytecode: disabling completely because %s\n", reason);
    ctx->bytecode_disable_status = 2;
    return ctx->bytecode_disable_status;
}

uint32_t cli_bcapi_disable_jit_if(struct cli_bc_ctx *ctx, const int8_t *reason, uint32_t len, uint32_t cond)
{
    UNUSEDPARAM(len);
    if (!ctx || !ctx->bc || (cond && !reason))
        return -1;
    if (ctx->bc->kind != BC_STARTUP) {
        cli_dbgmsg("Bytecode must be BC_STARTUP to call disable_jit_if\n");
        return -1;
    }
    if (!cond)
        return ctx->bytecode_disable_status;
    if (*reason == '^')
        cli_warnmsg("Bytecode: disabling JIT because %s\n", reason + 1);
    else
        cli_dbgmsg("Bytecode: disabling JIT because %s\n", reason);
    if (ctx->bytecode_disable_status != 2) /* no reenabling */
        ctx->bytecode_disable_status = 1;
    return ctx->bytecode_disable_status;
}

int32_t cli_bcapi_version_compare(struct cli_bc_ctx *ctx, const uint8_t *lhs, uint32_t lhs_len,
                                  const uint8_t *rhs, uint32_t rhs_len)
{
    unsigned i = 0, j = 0;
    unsigned long li = 0, ri = 0;
    UNUSEDPARAM(ctx);
    if ((lhs_len && !lhs) || (rhs_len && !rhs))
        return -1;
    do {
        while (i < lhs_len && j < rhs_len && lhs[i] == rhs[j] &&
               !isdigit(lhs[i]) && !isdigit(rhs[j])) {
            i++;
            j++;
        }
        if (i == lhs_len && j == rhs_len)
            return 0;
        if (i == lhs_len)
            return -1;
        if (j == rhs_len)
            return 1;
        if (!isdigit(lhs[i]) || !isdigit(rhs[j]))
            return lhs[i] < rhs[j] ? -1 : 1;
        while (isdigit(lhs[i]) && i < lhs_len)
            li = 10 * li + (lhs[i++] - '0');
        while (isdigit(rhs[j]) && j < rhs_len)
            ri = 10 * ri + (rhs[j++] - '0');
        if (li < ri)
            return -1;
        if (li > ri)
            return 1;
    } while (1);
}

static int check_bits(uint32_t query, uint32_t value, uint8_t shift, uint8_t mask)
{
    uint8_t q = (query >> shift) & mask;
    uint8_t v = (value >> shift) & mask;
    /* q == mask -> ANY */
    if (q == v || q == mask)
        return 1;
    return 0;
}

uint32_t cli_bcapi_check_platform(struct cli_bc_ctx *ctx, uint32_t a, uint32_t b, uint32_t c)
{
    if (!ctx || !ctx->env)
        return 0;
    unsigned ret =
        check_bits(a, ctx->env->platform_id_a, 24, 0xff) &&
        check_bits(a, ctx->env->platform_id_a, 20, 0xf) &&
        check_bits(a, ctx->env->platform_id_a, 16, 0xf) &&
        check_bits(a, ctx->env->platform_id_a, 8, 0xff) &&
        check_bits(a, ctx->env->platform_id_a, 0, 0xff) &&
        check_bits(b, ctx->env->platform_id_b, 28, 0xf) &&
        check_bits(b, ctx->env->platform_id_b, 24, 0xf) &&
        check_bits(b, ctx->env->platform_id_b, 16, 0xff) &&
        check_bits(b, ctx->env->platform_id_b, 8, 0xff) &&
        check_bits(b, ctx->env->platform_id_b, 0, 0xff) &&
        check_bits(c, ctx->env->platform_id_c, 24, 0xff) &&
        check_bits(c, ctx->env->platform_id_c, 16, 0xff) &&
        check_bits(c, ctx->env->platform_id_c, 8, 0xff) &&
        check_bits(c, ctx->env->platform_id_c, 0, 0xff);
    if (ret) {
        cli_dbgmsg("check_platform(0x%08x,0x%08x,0x%08x) = match\n", a, b, c);
    }
    return ret;
}

int32_t cli_bcapi_pdf_get_obj_num(struct cli_bc_ctx *ctx)
{
    if (!ctx || !ctx->pdf_phase)
        return -1;
    return ctx->pdf_nobjs;
}

int32_t cli_bcapi_pdf_get_flags(struct cli_bc_ctx *ctx)
{
    if (!ctx || !ctx->pdf_phase || !ctx->pdf_flags)
        return -1;
    return *ctx->pdf_flags;
}

int32_t cli_bcapi_pdf_set_flags(struct cli_bc_ctx *ctx, int32_t flags)
{
    if (!ctx || !ctx->pdf_phase || !ctx->pdf_flags)
        return -1;
    cli_dbgmsg("cli_pdf: bytecode set_flags %08x -> %08x\n",
               *ctx->pdf_flags,
               flags);
    *ctx->pdf_flags = flags;
    return 0;
}

int32_t cli_bcapi_pdf_lookupobj(struct cli_bc_ctx *ctx, uint32_t objid)
{
    unsigned i;
    if (!ctx || !ctx->pdf_phase || !ctx->pdf_objs)
        return -1;
    for (i = 0; i < ctx->pdf_nobjs; i++) {
        if (ctx->pdf_objs[i] && ctx->pdf_objs[i]->id == objid)
            return i;
    }
    return -1;
}

uint64_t cli_bcapi_pdf_getobjsize64(struct cli_bc_ctx *ctx, int32_t objidx)
{
    uint32_t next_idx;

    if (!ctx || !ctx->pdf_phase || objidx < 0 || !ctx->pdf_objs ||
        (uint32_t)objidx >= ctx->pdf_nobjs ||
        ctx->pdf_phase == PDF_PHASE_POSTDUMP ||
        !ctx->pdf_objs[objidx]) /* map is obj itself, no access to pdf anymore */
        return 0;

    next_idx = (uint32_t)objidx + 1U;
    if (next_idx == ctx->pdf_nobjs) {
        if (ctx->pdf_objs[objidx]->start > ctx->pdf_size)
            return 0;
        return ctx->pdf_size - ctx->pdf_objs[objidx]->start;
    }

    if (next_idx >= ctx->pdf_nobjs || !ctx->pdf_objs[next_idx] ||
        ctx->pdf_objs[next_idx]->start < ctx->pdf_objs[objidx]->start ||
        ctx->pdf_objs[next_idx]->start - ctx->pdf_objs[objidx]->start < 4)
        return 0;

    return ctx->pdf_objs[next_idx]->start - ctx->pdf_objs[objidx]->start - 4;
}

uint32_t cli_bcapi_pdf_getobjsize(struct cli_bc_ctx *ctx, int32_t objidx)
{
    uint64_t size = cli_bcapi_pdf_getobjsize64(ctx, objidx);

    return size > UINT32_MAX ? 0 : (uint32_t)size;
}

const uint8_t *cli_bcapi_pdf_getobj(struct cli_bc_ctx *ctx, int32_t objidx, uint32_t amount)
{
    uint32_t size = cli_bcapi_pdf_getobjsize(ctx, objidx);
    const uint8_t *object;

    if (!ctx || !ctx->pdf_phase || ctx->pdf_phase == PDF_PHASE_POSTDUMP ||
        objidx < 0 || !ctx->pdf_objs || (uint32_t)objidx >= ctx->pdf_nobjs ||
        !ctx->pdf_objs[objidx] || !ctx->fmap || amount > size)
        return NULL;
    /* The ABI has no matching release call for this borrowed pointer. Keep
     * the access bounded and unlocked; the bytecode hook consumes it during
     * the call and cannot safely retain a page lock across hooks. */
    object = fmap_need_off_once(ctx->fmap, ctx->pdf_objs[objidx]->start, amount);
    if (object == NULL)
        cli_bcapi_mark_map_read_error(ctx, "Bytecode PDF object could not be read completely");
    return object;
}

int32_t cli_bcapi_pdf_getobjid(struct cli_bc_ctx *ctx, int32_t objidx)
{
    if (!ctx || !ctx->pdf_phase || objidx < 0 || !ctx->pdf_objs ||
        (uint32_t)objidx >= ctx->pdf_nobjs || !ctx->pdf_objs[objidx])
        return -1;
    return ctx->pdf_objs[objidx]->id;
}

int32_t cli_bcapi_pdf_getobjflags(struct cli_bc_ctx *ctx, int32_t objidx)
{
    if (!ctx || !ctx->pdf_phase || objidx < 0 || !ctx->pdf_objs ||
        (uint32_t)objidx >= ctx->pdf_nobjs || !ctx->pdf_objs[objidx])
        return -1;
    return ctx->pdf_objs[objidx]->flags;
}

int32_t cli_bcapi_pdf_setobjflags(struct cli_bc_ctx *ctx, int32_t objidx, int32_t flags)
{
    if (!ctx || !ctx->pdf_phase || objidx < 0 || !ctx->pdf_objs ||
        (uint32_t)objidx >= ctx->pdf_nobjs || !ctx->pdf_objs[objidx])
        return -1;
    cli_dbgmsg("cli_pdf: bytecode setobjflags %08x -> %08x\n",
               ctx->pdf_objs[objidx]->flags,
               flags);
    ctx->pdf_objs[objidx]->flags = flags;
    return 0;
}

int32_t cli_bcapi_pdf_get_offset(struct cli_bc_ctx *ctx, int32_t objidx)
{
    uint64_t offset = cli_bcapi_pdf_get_offset64(ctx, objidx);

    if (offset > INT32_MAX) {
        cli_bcapi_mark_coordinate_error(ctx, "Bytecode v1 PDF offset requires 64-bit coordinates");
        return -1;
    }
    return (int32_t)offset;
}

uint64_t cli_bcapi_pdf_get_offset64(struct cli_bc_ctx *ctx, int32_t objidx)
{
    if (!ctx || !ctx->pdf_phase || objidx < 0 || !ctx->pdf_objs ||
        (uint32_t)objidx >= ctx->pdf_nobjs || !ctx->pdf_objs[objidx])
        return UINT64_MAX;
    if (ctx->pdf_startoff < 0 ||
        (uint64_t)ctx->pdf_startoff > UINT64_MAX - ctx->pdf_objs[objidx]->start)
        return UINT64_MAX;
    return (uint64_t)ctx->pdf_startoff + ctx->pdf_objs[objidx]->start;
}

int32_t cli_bcapi_pdf_get_phase(struct cli_bc_ctx *ctx)
{
    if (!ctx)
        return -1;
    return ctx->pdf_phase;
}

int32_t cli_bcapi_pdf_get_dumpedobjid(struct cli_bc_ctx *ctx)
{
    if (!ctx || ctx->pdf_phase != PDF_PHASE_POSTDUMP)
        return -1;
    return ctx->pdf_dumpedid;
}

int32_t cli_bcapi_running_on_jit(struct cli_bc_ctx *ctx)
{
    if (!ctx)
        return 0;
    ctx->no_diff = 1;
    return ctx->on_jit;
}

int32_t cli_bcapi_get_file_reliability(struct cli_bc_ctx *ctx)
{
    if (!ctx)
        return 3;
    cli_ctx *cctx = (cli_ctx *)ctx->ctx;
    return cctx ? cctx->corrupted_input : 3;
}

int32_t cli_bcapi_json_is_active(struct cli_bc_ctx *ctx)
{
    if (!ctx)
        return 0;
    cli_ctx *cctx = (cli_ctx *)ctx->ctx;
    if (cctx && cctx->metadata_json != NULL) {
        return 1;
    }
    return 0;
}

static int32_t cli_bcapi_json_objs_init(struct cli_bc_ctx *ctx)
{
    unsigned n;
    size_t table_size;
    json_object **j, **jobjs = (json_object **)(ctx->jsonobjs);
    cli_ctx *cctx = (cli_ctx *)ctx->ctx;

    if (cli_bcapi_table_size(ctx->njsonobjs, sizeof(json_object *), &n, &table_size) != 0) {
        cli_event_error_oom(EV, 0);
        return -1;
    }

    j = cli_max_realloc(jobjs, table_size);
    if (!j) { /* memory allocation failure */
        cli_event_error_oom(EV, 0);
        return -1;
    }
    ctx->jsonobjs  = (void **)j;
    ctx->njsonobjs = n;
    j[n - 1]       = cctx->metadata_json;

    return 0;
}

#define INIT_JSON_OBJS(ctx)                  \
    if (!cli_bcapi_json_is_active(ctx))      \
        return -1;                           \
    if (ctx->njsonobjs == 0) {               \
        if (cli_bcapi_json_objs_init(ctx)) { \
            return -1;                       \
        }                                    \
    }

int32_t cli_bcapi_json_get_object(struct cli_bc_ctx *ctx, const int8_t *name, int32_t name_len, int32_t objid)
{
    unsigned n;
    size_t name_size, table_size;
    json_object **j, *jobj, **jobjs;
    char *namep;

    INIT_JSON_OBJS(ctx);
    jobjs = ((json_object **)(ctx->jsonobjs));
    if (objid < 0 || (unsigned int)objid >= ctx->njsonobjs) {
        cli_dbgmsg("bytecode api[json_get_object]: invalid json objid requested\n");
        return -1;
    }

    if (!name || name_len < 0) {
        cli_dbgmsg("bytecode api[json_get_object]: unnamed object queried\n");
        return -1;
    }

    if (cli_bcapi_table_size(ctx->njsonobjs, sizeof(json_object *), &n, &table_size) != 0) {
        cli_event_error_oom(EV, 0);
        return -1;
    }

    jobj = jobjs[objid];
    if (!jobj) /* shouldn't be possible */
        return -1;

    name_size = (size_t)name_len;
    if (name_size > (size_t)CLI_MAX_ALLOCATION - 1) {
        cli_event_error_oom(EV, 0);
        return -1;
    }

    namep = (char *)cli_max_malloc(name_size + 1);
    if (!namep)
        return -1;
    strncpy(namep, (char *)name, name_size);
    namep[name_size] = '\0';

    if (!json_object_object_get_ex(jobj, namep, &jobj)) { /* object not found */
        free(namep);
        return 0;
    }

    j = cli_max_realloc(jobjs, table_size);
    if (!j) { /* memory allocation failure */
        free(namep);
        cli_event_error_oom(EV, 0);
        return -1;
    }
    ctx->jsonobjs  = (void **)j;
    ctx->njsonobjs = n;
    j[n - 1]       = jobj;

    cli_dbgmsg("bytecode api[json_get_object]: assigned %s => ID %d\n", namep, n - 1);
    free(namep);
    return n - 1;
}

int32_t cli_bcapi_json_get_type(struct cli_bc_ctx *ctx, int32_t objid)
{
    enum json_type type;
    json_object **jobjs;

    INIT_JSON_OBJS(ctx);
    jobjs = ((json_object **)(ctx->jsonobjs));
    if (objid < 0 || (unsigned int)objid >= ctx->njsonobjs) {
        cli_dbgmsg("bytecode api[json_get_type]: invalid json objid requested\n");
        return -1;
    }
    if (!jobjs[objid])
        return -1;

    type = json_object_get_type(jobjs[objid]);
    switch (type) {
        case json_type_null:
            return JSON_TYPE_NULL;
        case json_type_boolean:
            return JSON_TYPE_BOOLEAN;
        case json_type_double:
            return JSON_TYPE_DOUBLE;
        case json_type_int:
            return JSON_TYPE_INT;
        case json_type_object:
            return JSON_TYPE_OBJECT;
        case json_type_array:
            return JSON_TYPE_ARRAY;
        case json_type_string:
            return JSON_TYPE_STRING;
        default:
            cli_dbgmsg("bytecode api[json_get_type]: unrecognized json type %d\n", type);
    }

    return -1;
}

int32_t cli_bcapi_json_get_array_length(struct cli_bc_ctx *ctx, int32_t objid)
{
    enum json_type type;
    json_object **jobjs;

    INIT_JSON_OBJS(ctx);
    jobjs = (json_object **)(ctx->jsonobjs);
    if (objid < 0 || (unsigned int)objid >= ctx->njsonobjs) {
        cli_dbgmsg("bytecode api[json_array_get_length]: invalid json objid requested\n");
        return -1;
    }
    if (!jobjs[objid])
        return -1;

    type = json_object_get_type(jobjs[objid]);
    if (type != json_type_array) {
        return -2; /* error code for not an array */
    }

    return json_object_array_length(jobjs[objid]);
}

int32_t cli_bcapi_json_get_array_idx(struct cli_bc_ctx *ctx, int32_t idx, int32_t objid)
{
    enum json_type type;
    unsigned n;
    size_t table_size;
    int length;
    json_object **j, *jarr = NULL, *jobj = NULL, **jobjs;

    INIT_JSON_OBJS(ctx);
    jobjs = (json_object **)(ctx->jsonobjs);
    if (objid < 0 || (unsigned int)objid >= ctx->njsonobjs) {
        cli_dbgmsg("bytecode api[json_array_get_idx]: invalid json objid requested\n");
        return -1;
    }

    jarr = jobjs[objid];
    if (!jarr) /* shouldn't be possible */
        return -1;

    type = json_object_get_type(jarr);
    if (type != json_type_array) {
        return -2; /* error code for not an array */
    }

    length = json_object_array_length(jarr);
    if (idx >= 0 && idx < length) {
        if (cli_bcapi_table_size(ctx->njsonobjs, sizeof(json_object *), &n, &table_size) != 0) {
            cli_event_error_oom(EV, 0);
            return -1;
        }

        jobj = json_object_array_get_idx(jarr, idx);
        if (!jobj) { /* object not found */
            return 0;
        }

        j = cli_max_realloc(jobjs, table_size);
        if (!j) { /* memory allocation failure */
            cli_event_error_oom(EV, 0);
            return -1;
        }
        ctx->jsonobjs  = (void **)j;
        ctx->njsonobjs = n;
        j[n - 1]       = jobj;

        cli_dbgmsg("bytecode api[json_array_get_idx]: assigned array @ %d => ID %d\n", idx, n - 1);
        return n - 1;
    }

    return 0;
}

int32_t cli_bcapi_json_get_string_length(struct cli_bc_ctx *ctx, int32_t objid)
{
    enum json_type type;
    json_object *jobj, **jobjs;
    int32_t len;
    const char *jstr;

    INIT_JSON_OBJS(ctx);
    jobjs = (json_object **)(ctx->jsonobjs);
    if (objid < 0 || (unsigned int)objid >= ctx->njsonobjs) {
        cli_dbgmsg("bytecode api[json_get_string_length]: invalid json objid requested\n");
        return -1;
    }

    jobj = jobjs[objid];
    if (!jobj) /* shouldn't be possible */
        return -1;

    type = json_object_get_type(jobj);
    if (type != json_type_string) {
        return -2; /* error code for not an array */
    }

    // len = json_object_get_string_len(jobj); /* not in JSON <0.10 */
    jstr = json_object_get_string(jobj);
    if (!jstr || strlen(jstr) > INT32_MAX)
        return -1;
    len = (int32_t)strlen(jstr);

    return len;
}

int32_t cli_bcapi_json_get_string(struct cli_bc_ctx *ctx, int8_t *str, int32_t str_len, int32_t objid)
{
    enum json_type type;
    json_object *jobj, **jobjs;
    int32_t len;
    const char *jstr;

    INIT_JSON_OBJS(ctx);
    if (!str || str_len <= 0)
        return -1;
    jobjs = (json_object **)(ctx->jsonobjs);
    if (objid < 0 || (unsigned int)objid >= ctx->njsonobjs) {
        cli_dbgmsg("bytecode api[json_get_string]: invalid json objid requested\n");
        return -1;
    }

    jobj = jobjs[objid];
    if (!jobj) /* shouldn't be possible */
        return -1;

    type = json_object_get_type(jobj);
    if (type != json_type_string) {
        return -2; /* error code for not an array */
    }

    // len = json_object_get_string_len(jobj); /* not in JSON <0.10 */
    jstr = json_object_get_string(jobj);
    if (!jstr || strlen(jstr) > INT32_MAX)
        return -1;
    len = (int32_t)strlen(jstr);

    if (len + 1 > str_len) {
        /* limit on str-len */
        strncpy((char *)str, jstr, str_len - 1);
        str[str_len - 1] = '\0';
        return str_len;
    } else {
        /* limit on len+1 */
        memcpy((char *)str, jstr, len);
        str[len] = '\0';
        return len + 1;
    }
}

int32_t cli_bcapi_json_get_boolean(struct cli_bc_ctx *ctx, int32_t objid)
{
    json_object *jobj, **jobjs;

    INIT_JSON_OBJS(ctx);
    jobjs = (json_object **)(ctx->jsonobjs);
    if (objid < 0 || (unsigned int)objid >= ctx->njsonobjs) {
        cli_dbgmsg("bytecode api[json_get_boolean]: invalid json objid requested\n");
        return -1;
    }

    jobj = jobjs[objid];
    if (!jobj)
        return -1;
    return json_object_get_boolean(jobj);
}

int32_t cli_bcapi_json_get_int(struct cli_bc_ctx *ctx, int32_t objid)
{
    json_object *jobj, **jobjs;

    INIT_JSON_OBJS(ctx);
    jobjs = (json_object **)(ctx->jsonobjs);
    if (objid < 0 || (unsigned int)objid >= ctx->njsonobjs) {
        cli_dbgmsg("bytecode api[json_get_int]: invalid json objid requested\n");
        return -1;
    }

    jobj = jobjs[objid];
    if (!jobj)
        return -1;
    return json_object_get_int(jobj);
}
