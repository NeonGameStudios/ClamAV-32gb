/*
 *  Unit tests for bytecode functions.
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
#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>

#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include <check.h>
#include <fcntl.h>
#include <errno.h>

// libclamav
#include "clamav.h"
#include "others.h"
#include "bytecode.h"
#include "bytecode_api_impl.h"
#include "dconf.h"
#include "bytecode_priv.h"
#include "pdf.h"
#include "pe.h"
#include "clamav_rust.h"

#include "checks.h"

#ifdef CL_THREAD_SAFE
#include <pthread.h>
#endif

static void runtest(const char *file, uint64_t expected, int fail, int nojit,
                    const char *infile, struct cli_pe_hook_data *pedata,
                    struct cli_exe_section *sections, const char *expectedvirname,
                    int testmode)
{
    fmap_t *map = NULL;
    int rc;
    int fd = open_testfile(file, O_RDONLY); /* CBC databases should be opened in text mode (not binary), or else CRLF line indexing with `fgets()` will fail. */
    FILE *f;
    struct cli_bc bc;
    cli_ctx cctx;
    struct cli_bc_ctx *ctx;
    struct cli_all_bc bcs;
    uint64_t v;
    struct cl_engine *engine;
    int fdin = -1;
    char filestr[512];
    const char *virname = NULL;
    struct cl_scan_options options;

    memset(&cctx, 0, sizeof(cctx));
    memset(&options, 0, sizeof(struct cl_scan_options));
    cctx.options = &options;

    cctx.options->general |= CL_SCAN_GENERAL_ALLMATCHES;
    cctx.engine = engine = cl_engine_new();
    ck_assert_msg(!!cctx.engine, "cannot create engine");
    rc = cl_engine_compile(engine);
    ck_assert_msg(!rc, "cannot compile engine");

    cctx.dconf = cctx.engine->dconf;

    cctx.recursion_stack_size = cctx.engine->max_recursion_level;
    cctx.recursion_stack      = calloc(sizeof(cli_scan_layer_t), cctx.recursion_stack_size);
    ck_assert_msg(!!cctx.recursion_stack, "calloc() for recursion_stack failed");

    // ctx was memset, so recursion_level starts at 0.
    cctx.recursion_stack[cctx.recursion_level].fmap = NULL;

    cctx.fmap = cctx.recursion_stack[cctx.recursion_level].fmap;

    ck_assert_msg(fd >= 0, "retmagic open failed");
    f = fdopen(fd, "r");
    ck_assert_msg(!!f, "retmagic fdopen failed");

    cl_debug();

    if (!nojit) {
        rc = cli_bytecode_init(&bcs);
        ck_assert_msg(rc == CL_SUCCESS, "cli_bytecode_init failed");
    } else {
        bcs.engine = NULL;
    }

    bcs.all_bcs = &bc;
    bcs.count   = 1;

    rc = cli_bytecode_load(&bc, f, NULL, 1, 0);
    ck_assert_msg(rc == CL_SUCCESS, "cli_bytecode_load failed");
    fclose(f);

    if (testmode && have_clamjit())
        engine->bytecode_mode = CL_BYTECODE_MODE_TEST;

    rc = cli_bytecode_prepare2(engine, &bcs, BYTECODE_ENGINE_MASK);
    ck_assert_msg(rc == CL_SUCCESS, "cli_bytecode_prepare failed");

    if (have_clamjit() && !nojit && !testmode) {
        ck_assert_msg(bc.state == bc_jit, "preparing for JIT failed");
    }

    ctx                   = cli_bytecode_context_alloc();
    ctx->bytecode_timeout = fail == CL_ETIMEOUT ? 10 : 10000;
    ck_assert_msg(!!ctx, "cli_bytecode_context_alloc failed");

    ctx->ctx = &cctx;
    if (infile) {
        snprintf(filestr, sizeof(filestr), OBJDIR PATHSEP "%s", infile);
        fdin = open(filestr, O_RDONLY | O_BINARY);
        if (fdin < 0 && errno == ENOENT)
            fdin = open_testfile(infile, O_RDONLY | O_BINARY);
        ck_assert_msg(fdin >= 0, "failed to open infile");
        map = fmap_new(fdin, 0, 0, filestr, NULL);
        ck_assert_msg(!!map, "unable to fmap infile");
        if (pedata)
            ctx->hooks.pedata = pedata;
        ctx->sections = sections;
        cli_bytecode_context_setfile(ctx, map);
    }

    cli_bytecode_context_setfuncid(ctx, &bc, 0);
    rc = cli_bytecode_run(&bcs, &bc, ctx);
    ck_assert_msg(rc == fail, "cli_bytecode_run failed, expected: %u, have: %u\n",
                  fail, rc);

    if (rc == CL_SUCCESS) {
        v = cli_bytecode_context_getresult_int(ctx);
        ck_assert_msg(v == expected, "Invalid return value from bytecode run, expected: " STDx64 ", have: " STDx64 "\n",
                      expected, v);
    }
    if (infile && expectedvirname) {
        ck_assert_msg(ctx->virname &&
                          !strcmp(ctx->virname, expectedvirname),
                      "Invalid virname, expected: %s\n", expectedvirname);
    }
    cli_bytecode_context_destroy(ctx);
    if (map)
        fmap_free(map);
    cli_bytecode_destroy(&bc);
    cli_bytecode_done(&bcs);
    if (cctx.recursion_stack[cctx.recursion_level].evidence) {
        evidence_free(cctx.recursion_stack[cctx.recursion_level].evidence);
    }
    free(cctx.recursion_stack);
    cl_engine_free(engine);
    if (fdin >= 0)
        close(fdin);
}

START_TEST(test_retmagic_jit)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "retmagic.cbc", 0x1234f00d, CL_SUCCESS, 0, NULL, NULL, NULL, NULL, 0);
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "retmagic.cbc", 0x1234f00d, CL_SUCCESS, 0, NULL, NULL, NULL, NULL, 1);
}
END_TEST

START_TEST(test_retmagic_int)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "retmagic.cbc", 0x1234f00d, CL_SUCCESS, 1, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST(test_arith_jit)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "arith.cbc", 0xd5555555, CL_SUCCESS, 0, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST(test_arith_int)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "arith.cbc", 0xd5555555, CL_SUCCESS, 1, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST(test_apicalls_jit)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "apicalls.cbc", 0xf00d, CL_SUCCESS, 0, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST(test_apicalls_int)
{
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "apicalls.cbc", 0xf00d, CL_SUCCESS, 1, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST(test_apicalls2_jit)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "apicalls2.cbc", 0xf00d, CL_SUCCESS, 0, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST(test_apicalls2_int)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "apicalls2.cbc", 0xf00d, CL_SUCCESS, 1, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST(test_div0_jit)
{
    cl_init(CL_INIT_DEFAULT);
    /* must not crash on div#0 but catch it */
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "div0.cbc", 0, CL_EBYTECODE, 0, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST(test_div0_int)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "div0.cbc", 0, CL_EBYTECODE, 1, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST(test_lsig_jit)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "lsig.cbc", 0, 0, 0, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST(test_lsig_int)
{
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "lsig.cbc", 0, 0, 1, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST(test_inf_jit)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "inf.cbc", 0, CL_ETIMEOUT, 0, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST(test_inf_int)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "inf.cbc", 0, CL_ETIMEOUT, 1, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST(test_matchwithread_jit)
{
    struct cli_exe_section sect;
    struct cli_pe_hook_data pedata;
    cl_init(CL_INIT_DEFAULT);
    memset(&pedata, 0, sizeof(pedata));
    pedata.ep = 64;
    cli_writeint32(&pedata.opt32.ImageBase, 0x400000);
    pedata.hdr_size  = 0x400;
    pedata.nsections = 1;
    sect.rva         = 4096;
    sect.vsz         = 4096;
    sect.raw         = 0;
    sect.rsz         = 512;
    sect.urva        = 4096;
    sect.uvsz        = 4096;
    sect.uraw        = 1;
    sect.ursz        = 512;
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "matchwithread.cbc", 0, 0, 0,
            "input" PATHSEP "clamav_hdb_scanfiles" PATHSEP "clam.exe",
            &pedata, &sect, "ClamAV-Test-File-detected-via-bytecode", 0);
}
END_TEST

START_TEST(test_matchwithread_int)
{
    struct cli_exe_section sect;
    struct cli_pe_hook_data pedata;
    cl_init(CL_INIT_DEFAULT);
    memset(&pedata, 0, sizeof(pedata));
    pedata.ep = 64;
    cli_writeint32(&pedata.opt32.ImageBase, 0x400000);
    pedata.hdr_size  = 0x400;
    pedata.nsections = 1;
    sect.rva         = 4096;
    sect.vsz         = 4096;
    sect.raw         = 0;
    sect.rsz         = 512;
    sect.urva        = 4096;
    sect.uvsz        = 4096;
    sect.uraw        = 1;
    sect.ursz        = 512;
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "matchwithread.cbc", 0, 0, 1,
            "input" PATHSEP "clamav_hdb_scanfiles" PATHSEP "clam.exe",
            &pedata, &sect, "ClamAV-Test-File-detected-via-bytecode", 0);
}
END_TEST

START_TEST(test_pdf_jit)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "pdf.cbc", 0, 0, 0, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST(test_pdf_int)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "pdf.cbc", 0, 0, 1, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST(test_bswap_jit)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "bswap.cbc", 0xbeef, 0, 0, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST(test_bswap_int)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "bswap.cbc", 0xbeef, 0, 1, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST(test_inflate_jit)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "inflate.cbc", 0xbeef, 0, 1, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST(test_inflate_int)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "inflate.cbc", 0xbeef, 0, 0, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST(test_api_extract_jit)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "api_extract_7.cbc", 0xf00d, 0, 0,
            "input" PATHSEP "bytecode_scanfiles" PATHSEP "apitestfile", NULL, NULL, NULL, 0);
}
END_TEST

START_TEST(test_api_files_jit)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "api_files_7.cbc", 0xf00d, 0, 0,
            "input" PATHSEP "bytecode_scanfiles" PATHSEP "apitestfile", NULL, NULL, NULL, 0);
}
END_TEST

START_TEST(test_apicalls2_7_jit)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "apicalls2_7.cbc", 0xf00d, 0, 0, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST(test_apicalls_7_jit)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "apicalls_7.cbc", 0xf00d, 0, 0, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST(test_arith_7_jit)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "arith_7.cbc", 0xd55555dd, CL_SUCCESS, 0, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST(test_debug_jit)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "debug_7.cbc", 0xf00d, 0, 0, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST(test_inf_7_jit)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "inf_7.cbc", 0, CL_ETIMEOUT, 0, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST(test_lsig_7_jit)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "lsig_7.cbc", 0, 0, 0, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST(test_retmagic_7_jit)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "retmagic_7.cbc", 0x1234f00d, CL_SUCCESS, 0, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST(test_testadt_jit)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "testadt_7.cbc", 0xf00d, 0, 0, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST(test_api_extract_int)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "api_extract_7.cbc", 0xf00d, 0, 1,
            "input" PATHSEP "bytecode_scanfiles" PATHSEP "apitestfile", NULL, NULL, NULL, 0);
}
END_TEST

START_TEST(test_api_files_int)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "api_files_7.cbc", 0xf00d, 0, 1,
            "input" PATHSEP "bytecode_scanfiles" PATHSEP "apitestfile", NULL, NULL, NULL, 0);
}
END_TEST

START_TEST(test_apicalls2_7_int)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "apicalls2_7.cbc", 0xf00d, 0, 1, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST(test_apicalls_7_int)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "apicalls_7.cbc", 0xf00d, 0, 1, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST(test_arith_7_int)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "arith_7.cbc", 0xd55555dd, CL_SUCCESS, 1, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST(test_debug_int)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "debug_7.cbc", 0xf00d, 0, 1, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST(test_inf_7_int)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "inf_7.cbc", 0, CL_ETIMEOUT, 1, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST(test_lsig_7_int)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "lsig_7.cbc", 0, 0, 1, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST(test_retmagic_7_int)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "retmagic_7.cbc", 0x1234f00d, CL_SUCCESS, 1, NULL, NULL, NULL, NULL, 0);
}
END_TEST

START_TEST(test_testadt_int)
{
    cl_init(CL_INIT_DEFAULT);
    runtest("input" PATHSEP "bytecode_sigs" PATHSEP "testadt_7.cbc", 0xf00d, 0, 1, NULL, NULL, NULL, NULL, 0);
}
END_TEST

static void runload(const char *dbname, struct cl_engine *engine, unsigned signoexp)
{
    char *str;
    unsigned signo = 0;
    int rc;

    str = malloc(strlen(SRCDIR) + 1 + strlen(dbname) + 1);
    ck_assert_msg(!!str, "malloc");
    sprintf(str, "%s" PATHSEP "%s", SRCDIR, dbname);

    rc = cl_load(str, engine, &signo, CL_DB_STDOPT);
    ck_assert_msg(rc == CL_SUCCESS, "failed to load %s: %s\n",
                  str, cl_strerror(rc));
    ck_assert_msg(signo == signoexp, "different number of signatures loaded, expected %u, got %u\n",
                  signoexp, signo);
    free(str);

    rc = cl_engine_compile(engine);
    ck_assert_msg(rc == CL_SUCCESS, "failed to load %s: %s\n",
                  str, cl_strerror(rc));
}

START_TEST(test_load_bytecode_jit)
{
    struct cl_engine *engine;
    cl_init(CL_INIT_DEFAULT);
    engine = cl_engine_new();
    ck_assert_msg(!!engine, "failed to create engine\n");

    runload("input" PATHSEP "bytecode_sigs" PATHSEP "bytecode.cvd", engine, 5);

    cl_engine_free(engine);
}
END_TEST

START_TEST(test_load_bytecode_int)
{
    struct cl_engine *engine;
    cl_init(CL_INIT_DEFAULT);
    engine                  = cl_engine_new();
    engine->dconf->bytecode = BYTECODE_INTERPRETER;
    ck_assert_msg(!!engine, "failed to create engine\n");

    runload("input" PATHSEP "bytecode_sigs" PATHSEP "bytecode.cvd", engine, 5);

    cl_engine_free(engine);
}
END_TEST

struct bytecode_failing_pread_state {
    size_t length;
    off_t fail_at;
};

static off_t bytecode_failing_pread_cb(void *handle, void *buf, size_t count, off_t offset)
{
    struct bytecode_failing_pread_state *state = handle;

    if (offset >= state->fail_at) {
        errno = EIO;
        return -1;
    }
    if (offset < 0 || (uint64_t)offset >= state->length)
        return 0;
    if (count > state->length - (size_t)offset)
        count = state->length - (size_t)offset;
    if (count > (size_t)(state->fail_at - offset))
        count = (size_t)(state->fail_at - offset);
    memset(buf, 0x5a, count);
    return (off_t)count;
}

START_TEST(test_bytecode_map_read_failure_is_fail_visible)
{
    struct bytecode_failing_pread_state pread_state;
    struct cli_bc_ctx *bcctx;
    cli_ctx cctx;
    fmap_t *map;
    uint8_t buffer[8192];

    memset(&cctx, 0, sizeof(cctx));
    pread_state.length  = sizeof(buffer);
    pread_state.fail_at = 4096;
    map = cl_fmap_open_handle(&pread_state, 0, pread_state.length,
                              bytecode_failing_pread_cb, 0);
    ck_assert_ptr_nonnull(map);
    cctx.fmap = map;

    bcctx = cli_bytecode_context_alloc();
    ck_assert_ptr_nonnull(bcctx);
    bcctx->ctx = &cctx;
    ck_assert_int_eq(cli_bytecode_context_setfile(bcctx, map), CL_SUCCESS);

    bcctx->off = map->len;
    ck_assert_int_eq(cli_bcapi_read(bcctx, buffer, 1), 0);
    ck_assert(!cctx.scan_incomplete);

    bcctx->off = 0;
    ck_assert_int_eq(cli_bcapi_read(bcctx, buffer, sizeof(buffer)), -1);
    ck_assert(cctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cctx.scan_incomplete  = false;
    map->dont_cache_flag  = false;
    bcctx->off            = 0;
    ck_assert_int_eq(cli_bcapi_read_number(bcctx, 10), -1);
    ck_assert(cctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cli_bytecode_context_destroy(bcctx);
    cl_fmap_close(map);
}
END_TEST

START_TEST(test_bytecode_output_uses_64bit_accounting_and_temporary_quota)
{
    struct cl_engine *engine;
    struct cli_bc_ctx *bcctx;
    cli_ctx cctx;
    uint8_t payload[5] = {0, 1, 2, 3, 4};
    uint8_t byte = 0;

    engine = cl_engine_new();
    ck_assert_ptr_nonnull(engine);

    memset(&cctx, 0, sizeof(cctx));
    cctx.engine = engine;
    ck_assert_int_eq(cli_updatelimits(&cctx, UINT64_C(4294967296)), CL_SUCCESS);
    ck_assert_uint_eq(cctx.scansize, UINT64_C(4294967296));

    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_TEMPORARY_SIZE, 4), CL_SUCCESS);

    memset(&cctx, 0, sizeof(cctx));
    cctx.engine = engine;
    bcctx         = cli_bytecode_context_alloc();
    ck_assert_ptr_nonnull(bcctx);
    bcctx->ctx = &cctx;
    ck_assert_int_eq(cli_bcapi_write(bcctx, payload, sizeof(payload)), -1);
    ck_assert(cctx.scan_incomplete);
    ck_assert_uint_eq(cctx.temporary_bytes, 0);
    cli_bytecode_context_destroy(bcctx);

    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_TEMPORARY_SIZE, 8), CL_SUCCESS);
    memset(&cctx, 0, sizeof(cctx));
    cctx.engine = engine;
    bcctx       = cli_bytecode_context_alloc();
    ck_assert_ptr_nonnull(bcctx);
    bcctx->ctx = &cctx;
    ck_assert_int_eq(cli_bcapi_write(bcctx, payload, sizeof(payload)), sizeof(payload));
    ck_assert_uint_eq(bcctx->written, sizeof(payload));
    ck_assert_uint_eq(bcctx->temporary_reserved, sizeof(payload));
    ck_assert_uint_eq(cctx.temporary_bytes, sizeof(payload));
    cli_bytecode_context_destroy(bcctx);
    ck_assert_uint_eq(cctx.temporary_bytes, 0);

    memset(&cctx, 0, sizeof(cctx));
    cctx.engine = engine;
    bcctx       = cli_bytecode_context_alloc();
    ck_assert_ptr_nonnull(bcctx);
    bcctx->ctx     = &cctx;
    bcctx->written = UINT32_MAX;
    ck_assert_int_eq(cli_bcapi_write(bcctx, &byte, 1), 1);
    ck_assert_uint_eq(bcctx->written, UINT64_C(4294967296));
    cli_bytecode_context_destroy(bcctx);

    cl_engine_free(engine);
}
END_TEST

START_TEST(test_bytecode_v2_uses_64bit_file_coordinates)
{
    const uint64_t boundary = UINT64_C(4294967296);
    struct bytecode_failing_pread_state pread_state;
    struct cli_bc_ctx *bcctx;
    struct cli_bc bc;
    fmap_t *map;
    uint8_t byte;
    int32_t pipe_id;

    memset(&bc, 0, sizeof(bc));
    bc.metadata.formatlevel = BC_FORMAT_LEVEL_V2;
    pread_state.length       = (size_t)(boundary + 1);
    pread_state.fail_at      = INT64_MAX;
    map = cl_fmap_open_handle(&pread_state, 0, pread_state.length,
                              bytecode_failing_pread_cb, 1);
    ck_assert_ptr_nonnull(map);

    bcctx = cli_bytecode_context_alloc();
    ck_assert_ptr_nonnull(bcctx);
    bcctx->bc = &bc;
    ck_assert_int_eq(cli_bytecode_context_setfile(bcctx, map), CL_SUCCESS);
    ck_assert_uint_eq(bcctx->file_size64, boundary + 1);

    bcctx->off = (off_t)boundary;
    ck_assert_int_eq(cli_bcapi_read64(bcctx, &byte, 1), 1);
    ck_assert_int_eq(byte, 0x5a);
    ck_assert_uint_eq((uint64_t)bcctx->off, boundary + 1);

    ck_assert_int_eq(cli_bcapi_seek64(bcctx, -1, SEEK_END), (int64_t)boundary);
    ck_assert_int_eq(cli_bcapi_file_byteat64(bcctx, boundary), 0x5a);
    ck_assert_int_eq(cli_bcapi_file_find64(bcctx, (const uint8_t *)"A", 1), -1);
    bcctx->off = (off_t)boundary;
    ck_assert_int_eq(cli_bcapi_file_find_limit64(bcctx, &byte, 1, boundary + 1),
                     (int64_t)boundary);

    pipe_id = cli_bcapi_buffer_pipe_new_fromfile64(bcctx, boundary);
    ck_assert(pipe_id >= 0);
    ck_assert_uint_eq(cli_bcapi_buffer_pipe_read_avail64(bcctx, pipe_id), 1);
    ck_assert_int_eq(cli_bcapi_buffer_pipe_done(bcctx, pipe_id), 0);

    cli_bytecode_context_destroy(bcctx);
    cl_fmap_close(map);
}
END_TEST

START_TEST(test_bytecode_v2_pdf_coordinates_are_native_width)
{
#if SIZE_MAX > UINT32_MAX
    struct cli_bc_ctx *bcctx;
    struct cli_bc bc;
    struct pdf_obj first;
    struct pdf_obj second;
    struct pdf_obj *objects[2];
    const size_t first_offset = (size_t)UINT32_MAX + 128U;
    const size_t first_size = 37U;
    const size_t second_offset = first_offset + 4U + first_size;
    const off_t pdf_start = (off_t)UINT32_MAX + 64;

    memset(&bc, 0, sizeof(bc));
    memset(&first, 0, sizeof(first));
    memset(&second, 0, sizeof(second));
    bc.metadata.formatlevel = BC_FORMAT_LEVEL_V2;
    first.start = first_offset;
    second.start = second_offset;
    objects[0] = &first;
    objects[1] = &second;

    bcctx = cli_bytecode_context_alloc();
    ck_assert_ptr_nonnull(bcctx);
    bcctx->bc = &bc;
    ck_assert_int_eq(cli_bytecode_context_setpdf(bcctx, PDF_PHASE_PARSED, 2,
                                                 objects, NULL,
                                                 second_offset + 11U,
                                                 pdf_start),
                     CL_SUCCESS);

    ck_assert_uint_eq(cli_bcapi_pdf_getobjsize64(bcctx, 0), first_size);
    ck_assert_uint_eq(cli_bcapi_pdf_getobjsize64(bcctx, 1), 11U);
    ck_assert_uint_eq(cli_bcapi_pdf_get_offset64(bcctx, 0),
                      (uint64_t)pdf_start + first_offset);
    ck_assert_int_eq(cli_bcapi_pdf_get_offset(bcctx, 0), -1);

    cli_bytecode_context_destroy(bcctx);
#else
    ck_assert(1);
#endif
}
END_TEST

START_TEST(test_bytecode_large_map_hook_gates_only_applicable_bytecode)
{
    struct cl_engine *engine;
    struct cli_bc_ctx *bcctx;
    struct cli_bc *bc;
    unsigned hook_slot = BC_PRECLASS - _BC_START_HOOKS;
    cli_scan_layer_t layer;
    cli_ctx cctx;
    fmap_t map;
    cl_error_t ret;

    ck_assert(cli_bytecode_file_size_compatible(UINT32_MAX));
    ck_assert(!cli_bytecode_file_size_compatible(UINT64_C(4294967296)));
    ck_assert(!cli_bytecode_file_size_compatible(UINT64_C(34359738368)));

    memset(&cctx, 0, sizeof(cctx));
    memset(&layer, 0, sizeof(layer));
    memset(&map, 0, sizeof(map));
    map.len                  = (size_t)UINT64_C(4294967296);
    layer.fmap               = &map;
    cctx.fmap                = &map;
    cctx.recursion_stack     = &layer;
    cctx.recursion_stack_size = 1;

    engine = cl_engine_new();
    ck_assert_ptr_nonnull(engine);
    cctx.engine = engine;
    bcctx       = cli_bytecode_context_alloc();
    ck_assert_ptr_nonnull(bcctx);

    /* Merely reaching a hook dispatch point is not a skipped inspection when
     * the engine has no bytecode registered there. */
    ret = cli_bytecode_runhook(&cctx, engine, bcctx, BC_PRECLASS, &map);
    ck_assert_int_eq(ret, CL_SUCCESS);
    ck_assert(!cctx.scan_incomplete);
    ck_assert(!map.dont_cache_flag);

    engine->bcs.all_bcs = calloc(1, sizeof(*engine->bcs.all_bcs));
    engine->hooks[hook_slot] = calloc(1, sizeof(*engine->hooks[hook_slot]));
    ck_assert_ptr_nonnull(engine->bcs.all_bcs);
    ck_assert_ptr_nonnull(engine->hooks[hook_slot]);
    engine->bcs.count          = 1;
    engine->hooks_cnt[hook_slot] = 1;
    engine->hooks[hook_slot][0]  = 0;
    bc = &engine->bcs.all_bcs[0];

    /* A logical hook whose signature did not match is equally inapplicable. */
    bc->lsig         = strdup("unit-test-logical-hook");
    bc->hook_lsig_id = 1;
    ck_assert_ptr_nonnull(bc->lsig);
    ret = cli_bytecode_runhook(&cctx, engine, bcctx, BC_PRECLASS, &map);
    ck_assert_int_eq(ret, CL_SUCCESS);
    ck_assert(!cctx.scan_incomplete);
    ck_assert(!map.dont_cache_flag);

    /* Once a hook really would execute, the 32-bit ABI limit is a visible
     * incomplete-scan result. */
    free(bc->lsig);
    bc->lsig         = NULL;
    bc->hook_lsig_id = 0;
    ret = cli_bytecode_runhook(&cctx, engine, bcctx, BC_PRECLASS, &map);
    ck_assert_int_eq(ret, CL_EMAXSIZE);
    ck_assert(cctx.scan_incomplete);
    ck_assert(map.dont_cache_flag);

    cli_bytecode_context_destroy(bcctx);
    cl_engine_free(engine);
}
END_TEST

START_TEST(test_bytecode_lsig_rejects_invalid_dispatch_arguments)
{
    struct cli_all_bc bcs;
    cli_ctx cctx;

    memset(&bcs, 0, sizeof(bcs));
    memset(&cctx, 0, sizeof(cctx));

    /* Invalid dispatch metadata must be rejected before all_bcs[bc_idx - 1]
     * can perform pointer arithmetic on a null or out-of-range base. */
    ck_assert_int_eq(cli_bytecode_runlsig(&cctx, NULL, NULL, 0, NULL, NULL, NULL), CL_ENULLARG);
    ck_assert_int_eq(cli_bytecode_runlsig(&cctx, NULL, &bcs, 0, NULL, NULL, NULL), CL_ENULLARG);
}
END_TEST

#if defined(CL_THREAD_SAFE) && defined(C_LINUX) && ((__GLIBC__ << 16) + __GLIBC_MINOR__ >= (2 << 16) + 4)
#define DO_BARRIER
#endif

#ifdef DO_BARRIER
static pthread_barrier_t barrier;
static void *thread(void *arg)
{
    struct cl_engine *engine;
    engine = cl_engine_new();
    ck_assert_msg(!!engine, "failed to create engine\n");
    /* run all cl_load at once, to maximize chance of a crash
     * in case of a race condition */
    pthread_barrier_wait(&barrier);
    runload("input" PATHSEP "bytecode_sigs" PATHSEP "bytecode.cvd", engine, 5);
    cl_engine_free(engine);
    return NULL;
}

START_TEST(test_parallel_load)
{
#define N 5
    pthread_t threads[N];
    unsigned i;
    FILE *fixture;

    cl_init(CL_INIT_DEFAULT);
    /* Check assertions use thread-local test state and must not be raised from
     * the worker threads below. Keep a missing checkout fixture as a visible
     * test failure, but report it on the test thread before creating workers. */
    fixture = fopen(SRCDIR PATHSEP "input" PATHSEP "bytecode_sigs" PATHSEP "bytecode.cvd", "rb");
    if (fixture == NULL) {
        ck_abort_msg("missing bytecode fixture: %s", SRCDIR PATHSEP "input" PATHSEP "bytecode_sigs" PATHSEP "bytecode.cvd");
        return;
    }
    fclose(fixture);

    pthread_barrier_init(&barrier, NULL, N);
    for (i = 0; i < N; i++) {
        pthread_create(&threads[i], NULL, thread, NULL);
    }
    for (i = 0; i < N; i++) {
        pthread_join(threads[i], NULL);
    }
    /* DB load used to crash due to 'static' variable in cache.c,
     * and also due to something wrong in LLVM 2.7.
     * Enabled the mutex around codegen in bytecode2llvm.cpp, and this test is
     * here to make sure it doesn't crash */
}
END_TEST
#endif

Suite *test_bytecode_suite(void)
{
    Suite *s            = suite_create("bytecode");
    TCase *tc_cli_arith = tcase_create("arithmetic");
    TCase *tc_cli_read  = tcase_create("map_read");
    suite_add_tcase(s, tc_cli_arith);
    suite_add_tcase(s, tc_cli_read);
    tcase_set_timeout(tc_cli_arith, 20);
    tcase_set_timeout(tc_cli_read, 20);
    tcase_add_test(tc_cli_arith, test_retmagic_jit);
    tcase_add_test(tc_cli_arith, test_arith_jit);
    tcase_add_test(tc_cli_arith, test_apicalls_jit);
    tcase_add_test(tc_cli_arith, test_apicalls2_jit);
    tcase_add_test(tc_cli_arith, test_div0_jit);
    tcase_add_test(tc_cli_arith, test_lsig_jit);
    tcase_add_test(tc_cli_arith, test_inf_jit);
    tcase_add_test(tc_cli_arith, test_matchwithread_jit);
    tcase_add_test(tc_cli_arith, test_pdf_jit);
    tcase_add_test(tc_cli_arith, test_bswap_jit);
    tcase_add_test(tc_cli_arith, test_inflate_jit);

    tcase_add_test(tc_cli_arith, test_arith_int);
    tcase_add_test(tc_cli_arith, test_apicalls_int);
    tcase_add_test(tc_cli_arith, test_apicalls2_int);
    tcase_add_test(tc_cli_arith, test_div0_int);
    tcase_add_test(tc_cli_arith, test_lsig_int);
    tcase_add_test(tc_cli_arith, test_inf_int);
    tcase_add_test(tc_cli_arith, test_matchwithread_int);
    tcase_add_test(tc_cli_arith, test_pdf_int);
    tcase_add_test(tc_cli_arith, test_bswap_int);
    tcase_add_test(tc_cli_arith, test_inflate_int);
    tcase_add_test(tc_cli_arith, test_retmagic_int);

    tcase_add_test(tc_cli_arith, test_api_extract_jit);
    tcase_add_test(tc_cli_arith, test_api_files_jit);
    tcase_add_test(tc_cli_arith, test_apicalls2_7_jit);
    tcase_add_test(tc_cli_arith, test_apicalls_7_jit);
    tcase_add_test(tc_cli_arith, test_apicalls_7_jit);
    tcase_add_test(tc_cli_arith, test_arith_7_jit);
    tcase_add_test(tc_cli_arith, test_debug_jit);
    tcase_add_test(tc_cli_arith, test_inf_7_jit);
    tcase_add_test(tc_cli_arith, test_lsig_7_jit);
    tcase_add_test(tc_cli_arith, test_retmagic_7_jit);
    tcase_add_test(tc_cli_arith, test_testadt_jit);

    tcase_add_test(tc_cli_arith, test_api_extract_int);
    tcase_add_test(tc_cli_arith, test_api_files_int);
    tcase_add_test(tc_cli_arith, test_apicalls2_7_int);
    tcase_add_test(tc_cli_arith, test_apicalls_7_int);
    tcase_add_test(tc_cli_arith, test_apicalls_7_int);
    tcase_add_test(tc_cli_arith, test_arith_7_int);
    tcase_add_test(tc_cli_arith, test_debug_int);
    tcase_add_test(tc_cli_arith, test_inf_7_int);
    tcase_add_test(tc_cli_arith, test_lsig_7_int);
    tcase_add_test(tc_cli_arith, test_retmagic_int);
    tcase_add_test(tc_cli_arith, test_testadt_int);

    tcase_add_test(tc_cli_arith, test_load_bytecode_jit);
    tcase_add_test(tc_cli_arith, test_load_bytecode_int);
    tcase_add_test(tc_cli_arith, test_bytecode_large_map_hook_gates_only_applicable_bytecode);
    tcase_add_test(tc_cli_arith, test_bytecode_lsig_rejects_invalid_dispatch_arguments);
    tcase_add_test(tc_cli_read, test_bytecode_v2_uses_64bit_file_coordinates);
    tcase_add_test(tc_cli_read, test_bytecode_v2_pdf_coordinates_are_native_width);
    tcase_add_test(tc_cli_read, test_bytecode_map_read_failure_is_fail_visible);
    tcase_add_test(tc_cli_read, test_bytecode_output_uses_64bit_accounting_and_temporary_quota);
#ifdef DO_BARRIER
    tcase_add_test(tc_cli_arith, test_parallel_load);
#endif

    return s;
}
