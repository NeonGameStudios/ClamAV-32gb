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

struct bytecode_search_pread_state {
    size_t length;
    size_t marker_offset;
    const uint8_t *marker;
    size_t marker_length;
};

static off_t bytecode_search_pread_cb(void *handle, void *buf, size_t count, off_t offset)
{
    struct bytecode_search_pread_state *state = handle;
    size_t start;
    size_t end;
    size_t marker_end;
    size_t copy_start;
    size_t copy_end;

    if (offset < 0 || (uint64_t)offset >= state->length)
        return 0;
    start = (size_t)offset;
    if (count > state->length - start)
        count = state->length - start;
    memset(buf, 0, count);
    end = start + count;
    if (state->marker_offset > SIZE_MAX - state->marker_length)
        return -1;
    marker_end = state->marker_offset + state->marker_length;
    copy_start = MAX(start, state->marker_offset);
    copy_end   = MIN(end, marker_end);
    if (copy_start < copy_end) {
        memcpy((uint8_t *)buf + copy_start - start,
               state->marker + copy_start - state->marker_offset,
               copy_end - copy_start);
    }
    return (off_t)count;
}

static int bytecode_write_number_override(FILE *output, const char *line,
                                          size_t offset, uint64_t value)
{
    char encoded[18];
    uint64_t remaining = value;
    unsigned digits     = 1;
    unsigned old_digits;
    unsigned i;

    if ((unsigned char)line[offset] < 0x60 ||
        (unsigned char)line[offset] > 0x70)
        return -1;
    old_digits = (unsigned char)line[offset] - 0x60;
    while (remaining >>= 4)
        digits++;
    encoded[0] = (char)(0x60 + digits);
    for (i = 0; i < digits; i++)
        encoded[i + 1] = (char)(0x60 + ((value >> (i * 4)) & 0xf));
    if (fwrite(line, 1, offset, output) != offset ||
        fwrite(encoded, 1, digits + 1, output) != digits + 1 ||
        fputs(line + offset + old_digits + 1, output) == EOF)
        return -1;
    return 0;
}

static cl_error_t bytecode_load_mutated_interface_fixture(unsigned formatlevel,
                                                           unsigned maxapi,
                                                           unsigned maxglobal)
{
    const char *fixture = "input" PATHSEP "bytecode_sigs" PATHSEP
                          "Clamav-Unit-Test-Signature.cbc";
    char line[8192];
    struct cli_bc bc;
    FILE *input;
    FILE *mutated;
    int fd;
    cl_error_t rc = CL_EOPEN;

    fd = open_testfile(fixture, O_RDONLY);
    if (fd < 0)
        return CL_EOPEN;
    input = fdopen(fd, "r");
    if (input == NULL) {
        close(fd);
        return CL_EOPEN;
    }
    mutated = tmpfile();
    if (mutated == NULL) {
        fclose(input);
        return CL_ETMPFILE;
    }
    while (fgets(line, sizeof(line), input) != NULL) {
        size_t offset = SIZE_MAX;
        uint64_t value = 0;

        if (!strncmp(line, BC_HEADER, sizeof(BC_HEADER) - 1)) {
            offset = sizeof(BC_HEADER) - 1;
            value  = formatlevel;
        } else if (line[0] == 'E' && maxapi != UINT_MAX) {
            offset = 1;
            value  = maxapi;
        } else if (line[0] == 'G' && maxglobal != UINT_MAX) {
            offset = 1;
            value  = maxglobal;
        }
        if (offset == SIZE_MAX) {
            if (fputs(line, mutated) == EOF)
                goto done;
        } else if (bytecode_write_number_override(mutated, line, offset, value) != 0) {
            goto done;
        }
    }
    if (ferror(input) || fflush(mutated) != 0 || fseek(mutated, 0, SEEK_SET) != 0)
        goto done;
    rc = cli_bytecode_load(&bc, mutated, NULL, 1, 0);
    cli_bytecode_destroy(&bc);

done:
    fclose(mutated);
    fclose(input);
    return rc;
}

static cl_error_t bytecode_load_mutated_type_fixture(int mutation)
{
    const char *fixture = "input" PATHSEP "bytecode_sigs" PATHSEP
                          "Clamav-Unit-Test-Signature.cbc";
    char line[8192];
    struct cli_bc bc;
    FILE *input;
    FILE *mutated;
    int fd;
    int found = 0;
    cl_error_t rc = CL_EOPEN;

    fd = open_testfile(fixture, O_RDONLY);
    if (fd < 0)
        return CL_EOPEN;
    input = fdopen(fd, "r");
    if (input == NULL) {
        close(fd);
        return CL_EOPEN;
    }
    mutated = tmpfile();
    if (mutated == NULL) {
        fclose(input);
        return CL_ETMPFILE;
    }
    while (fgets(line, sizeof(line), input) != NULL) {
        if (line[0] == 'T') {
            /* The fixture's first dynamic type is [1 x i64].  Turn it into
             * { self } or retain the array shape with UINT_MAX elements. */
            if (mutation == 1) {
                if (fwrite(line, 1, 3, mutated) != 3 ||
                    fputs("caabed", mutated) == EOF ||
                    fputs(line + 8, mutated) == EOF)
                    goto done;
            } else if (mutation == 2) {
                if (fwrite(line, 1, 4, mutated) != 4 ||
                    fputs("hooooooooah", mutated) == EOF ||
                    fputs(line + 8, mutated) == EOF)
                    goto done;
            } else if (fputs(line, mutated) == EOF) {
                goto done;
            }
            found = 1;
        } else if (fputs(line, mutated) == EOF) {
            goto done;
        }
    }
    if (!found || ferror(input) || fflush(mutated) != 0 ||
        fseek(mutated, 0, SEEK_SET) != 0)
        goto done;
    memset(&bc, 0, sizeof(bc));
    rc = cli_bytecode_load(&bc, mutated, NULL, 1, 0);
    cli_bytecode_destroy(&bc);

done:
    fclose(mutated);
    fclose(input);
    return rc;
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

START_TEST(test_bytecode_v1_read_rejects_invalid_offsets)
{
    struct cli_bc_ctx *bcctx;
    cli_ctx cctx;
    fmap_t *map;
    uint8_t buffer[2] = {0};

    memset(&cctx, 0, sizeof(cctx));
    map = cl_fmap_open_memory(buffer, sizeof(buffer));
    ck_assert_ptr_nonnull(map);
    cctx.fmap = map;

    bcctx = cli_bytecode_context_alloc();
    ck_assert_ptr_nonnull(bcctx);
    bcctx->ctx = &cctx;
    ck_assert_int_eq(cli_bytecode_context_setfile(bcctx, map), CL_SUCCESS);

    bcctx->off = -1;
    ck_assert_int_eq(cli_bcapi_read(bcctx, buffer, 1), -1);

    if ((uint64_t)SIZE_MAX < (uint64_t)INT64_MAX) {
        bcctx->off = (off_t)SIZE_MAX;
        ck_assert_int_eq(cli_bcapi_read(bcctx, buffer, 2), -1);
    }

    cli_bytecode_context_destroy(bcctx);
    cl_fmap_close(map);
}
END_TEST

START_TEST(test_bytecode_v1_coordinate_narrowing_is_fail_visible)
{
#if SIZE_MAX > UINT32_MAX
    const uint64_t boundary = (uint64_t)INT32_MAX + 1;
    struct bytecode_failing_pread_state pread_state;
    struct cli_bc_ctx *bcctx;
    struct cli_bc bc;
    struct pdf_obj object;
    struct pdf_obj *objects[1];
    cli_ctx cctx;
    fmap_t *map;
    unsigned char byte = 0x5a;

    memset(&bc, 0, sizeof(bc));
    memset(&object, 0, sizeof(object));
    memset(&cctx, 0, sizeof(cctx));
    pread_state.length  = (size_t)(boundary + 1);
    pread_state.fail_at = INT64_MAX;
    map = cl_fmap_open_handle(&pread_state, 0, pread_state.length,
                              bytecode_failing_pread_cb, 1);
    ck_assert_ptr_nonnull(map);

    bcctx = cli_bytecode_context_alloc();
    ck_assert_ptr_nonnull(bcctx);
    bcctx->bc  = &bc;
    bcctx->ctx = &cctx;
    cctx.fmap  = map;
    ck_assert_int_eq(cli_bytecode_context_setfile(bcctx, map), CL_SUCCESS);

    ck_assert_int_eq(cli_bcapi_seek(bcctx, 0, SEEK_END), -1);
    ck_assert_uint_eq((uint64_t)bcctx->off, 0);
    ck_assert(cctx.scan_incomplete);
    ck_assert_str_eq(cctx.scan_incomplete_reason,
                     "Bytecode v1 seek result requires 64-bit file coordinates");
    ck_assert(map->dont_cache_flag);

    cctx.scan_incomplete        = false;
    cctx.scan_incomplete_reason = NULL;
    map->dont_cache_flag        = false;
    bcctx->off                  = (off_t)boundary;
    ck_assert_int_eq(cli_bcapi_file_find(bcctx, &byte, 1), -1);
    ck_assert(cctx.scan_incomplete);
    ck_assert_str_eq(cctx.scan_incomplete_reason,
                     "Bytecode v1 file-find result requires 64-bit matcher offsets");
    ck_assert(map->dont_cache_flag);

    cctx.scan_incomplete        = false;
    cctx.scan_incomplete_reason = NULL;
    map->dont_cache_flag        = false;
    objects[0]                  = &object;
    ck_assert_int_eq(cli_bytecode_context_setpdf(bcctx, PDF_PHASE_PARSED, 1,
                                                  objects, NULL, 1, (off_t)boundary),
                     CL_SUCCESS);
    ck_assert_int_eq(cli_bcapi_pdf_get_offset(bcctx, 0), -1);
    ck_assert(cctx.scan_incomplete);
    ck_assert_str_eq(cctx.scan_incomplete_reason,
                     "Bytecode v1 PDF offset requires 64-bit coordinates");
    ck_assert(map->dont_cache_flag);

    cli_bytecode_context_destroy(bcctx);
    cl_fmap_close(map);
#else
    ck_assert(1);
#endif
}
END_TEST

START_TEST(test_bytecode_output_uses_64bit_accounting_and_temporary_quota)
{
    struct cl_engine *engine;
    struct cli_bc_ctx *bcctx;
    cli_ctx cctx;
    uint8_t payload[5] = {0, 1, 2, 3, 4};
    uint8_t byte = 0;
    int replacement_fd;

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
    bcctx->ctx = &cctx;
    ck_assert_int_eq(cli_bcapi_write(bcctx, payload, sizeof(payload)), sizeof(payload));
    ck_assert_int_eq(close(bcctx->outfd), 0);
    ck_assert_int_eq(cli_bcapi_write(bcctx, payload, sizeof(payload)), -1);
    ck_assert(cctx.scan_incomplete);
    ck_assert_uint_eq(bcctx->written, sizeof(payload));
    ck_assert_uint_eq(bcctx->temporary_reserved, sizeof(payload));
    ck_assert_uint_eq(cctx.temporary_bytes, sizeof(payload));
    ck_assert_int_eq(cli_bcapi_extract_new(bcctx, 0), -1);
    replacement_fd = open("/dev/null", O_WRONLY | O_BINARY);
    ck_assert_int_gt(replacement_fd, -1);
    bcctx->outfd = replacement_fd;
    cli_bytecode_context_destroy(bcctx);
    ck_assert_uint_eq(cctx.temporary_bytes, 0);

    memset(&cctx, 0, sizeof(cctx));
    cctx.engine = engine;
    ck_assert_int_eq(gettimeofday(&cctx.time_limit, NULL), 0);
    cctx.time_limit.tv_sec--;
    bcctx = cli_bytecode_context_alloc();
    ck_assert_ptr_nonnull(bcctx);
    bcctx->ctx = &cctx;
    ck_assert_int_eq(cli_bcapi_write(bcctx, payload, sizeof(payload)), -1);
    ck_assert(cctx.scan_incomplete);
    ck_assert(cctx.scan_timed_out);
    ck_assert_uint_eq(cctx.temporary_bytes, 0);
    cli_bytecode_context_destroy(bcctx);

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

START_TEST(test_bytecode_jsnorm_limit_failure_releases_input)
{
    struct cl_engine *engine;
    struct cli_bc_ctx *bcctx;
    cli_ctx cctx;
    fmap_t *map;
    const char input[] = "alert(1);";
    int32_t input_id;
    int32_t jsnorm_id;

    cl_init(CL_INIT_DEFAULT);
    engine = cl_engine_new();
    ck_assert_ptr_nonnull(engine);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_FILES, 1), CL_SUCCESS);

    memset(&cctx, 0, sizeof(cctx));
    cctx.engine       = engine;
    cctx.scannedfiles = 1;
    bcctx             = cli_bytecode_context_alloc();
    ck_assert_ptr_nonnull(bcctx);
    bcctx->ctx = &cctx;
    map = cl_fmap_open_memory((const unsigned char *)input, sizeof(input) - 1);
    ck_assert_ptr_nonnull(map);
    cctx.fmap = map;
    ck_assert_int_eq(cli_bytecode_context_setfile(bcctx, map), CL_SUCCESS);
    input_id = cli_bcapi_buffer_pipe_new_fromfile64(bcctx, 0);
    ck_assert_int_ge(input_id, 0);
    jsnorm_id = cli_bcapi_jsnorm_init(bcctx, input_id);
    ck_assert_int_ge(jsnorm_id, 0);
    ck_assert_int_eq(cli_bcapi_jsnorm_process(bcctx, jsnorm_id), -1);
    ck_assert(cctx.scan_incomplete);
    ck_assert_str_eq(cctx.scan_incomplete_reason,
                     "Heuristics.Limits.Exceeded.MaxFiles");
    ck_assert_uint_eq(cli_bcapi_buffer_pipe_read_avail(bcctx, input_id), 0);
    ck_assert(!bcctx->buffers[input_id].map_read_locked);
    cli_bytecode_context_destroy(bcctx);
    cl_fmap_close(map);

    cl_engine_free(engine);
}
END_TEST

START_TEST(test_bytecode_v2_uses_64bit_file_coordinates)
{
    const uint64_t boundary = UINT64_C(4294967296);
    struct bytecode_failing_pread_state pread_state;
    struct cli_bc_ctx *bcctx;
    struct cli_bc bc;
    cli_ctx cctx;
    fmap_t *map;
    uint8_t byte;
    int32_t pipe_id;

    memset(&bc, 0, sizeof(bc));
    memset(&cctx, 0, sizeof(cctx));
    bc.metadata.formatlevel = BC_FORMAT_LEVEL_V2;
    pread_state.length       = (size_t)(boundary + 1);
    pread_state.fail_at      = INT64_MAX;
    map = cl_fmap_open_handle(&pread_state, 0, pread_state.length,
                              bytecode_failing_pread_cb, 1);
    ck_assert_ptr_nonnull(map);

    bcctx = cli_bytecode_context_alloc();
    ck_assert_ptr_nonnull(bcctx);
    bcctx->bc = &bc;
    bcctx->ctx = &cctx;
    cctx.fmap = map;
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
    ck_assert_ptr_nonnull(cli_bcapi_buffer_pipe_read_get(bcctx, pipe_id, 1));
    ck_assert_int_eq(cli_bcapi_buffer_pipe_read_stopped(bcctx, pipe_id, 1), 0);
    fmap_release_unlocked(map);
    ck_assert_uint_eq(map->paged, 0);
    ck_assert_int_eq(cli_bcapi_buffer_pipe_done(bcctx, pipe_id), 0);

    pread_state.fail_at         = (off_t)boundary;
    cctx.scan_incomplete        = false;
    cctx.scan_incomplete_reason = NULL;
    map->dont_cache_flag        = false;
    pipe_id                     = cli_bcapi_buffer_pipe_new_fromfile64(bcctx, boundary);
    ck_assert(pipe_id >= 0);
    ck_assert_uint_eq(cli_bcapi_buffer_pipe_read_avail64(bcctx, pipe_id), 1);
    ck_assert_ptr_null(cli_bcapi_buffer_pipe_read_get(bcctx, pipe_id, 1));
    ck_assert(cctx.scan_incomplete);
    ck_assert_str_eq(cctx.scan_incomplete_reason, "Bytecode buffer-pipe input could not be read completely");
    ck_assert(map->dont_cache_flag);
    ck_assert_int_eq(cli_bcapi_buffer_pipe_done(bcctx, pipe_id), 0);

    cli_bytecode_context_destroy(bcctx);
    cl_fmap_close(map);
}
END_TEST

START_TEST(test_bytecode_file_find_crosses_read_windows)
{
    static const uint8_t marker[] = {0x41, 0x42, 0x43, 0x44};
    struct bytecode_search_pread_state state;
    struct cli_bc_ctx *bcctx;
    struct cli_bc bc;
    fmap_t *map;

    memset(&bc, 0, sizeof(bc));
    state.length        = 8192;
    state.marker_offset = 4095;
    state.marker        = marker;
    state.marker_length = sizeof(marker);
    map = cl_fmap_open_handle(&state, 0, state.length,
                              bytecode_search_pread_cb, 1);
    ck_assert_ptr_nonnull(map);
    bcctx = cli_bytecode_context_alloc();
    ck_assert_ptr_nonnull(bcctx);
    bcctx->bc = &bc;
    ck_assert_int_eq(cli_bytecode_context_setfile(bcctx, map), CL_SUCCESS);
    ck_assert_int_eq(cli_bcapi_file_find(bcctx, marker, sizeof(marker)), 4095);
    cli_bytecode_context_destroy(bcctx);
    cl_fmap_close(map);

#if SIZE_MAX > UINT32_MAX
    if (sizeof(off_t) >= sizeof(int64_t)) {
        bc.metadata.formatlevel = BC_FORMAT_LEVEL_V2;
        state.marker_offset     = (size_t)UINT64_C(4294967296) + 4095U;
        state.length            = state.marker_offset + sizeof(marker);
        map = cl_fmap_open_handle(&state, 0, state.length,
                                  bytecode_search_pread_cb, 1);
        ck_assert_ptr_nonnull(map);
        bcctx = cli_bytecode_context_alloc();
        ck_assert_ptr_nonnull(bcctx);
        bcctx->bc = &bc;
        ck_assert_int_eq(cli_bytecode_context_setfile(bcctx, map), CL_SUCCESS);
        bcctx->off = (off_t)UINT64_C(4294967296);
        ck_assert_int_eq(cli_bcapi_file_find64(bcctx, marker, sizeof(marker)),
                         (int64_t)state.marker_offset);
        cli_bytecode_context_destroy(bcctx);
        cl_fmap_close(map);
    }
#endif
}
END_TEST

START_TEST(test_bytecode_v2_interfaces_require_format8)
{
    ck_assert_uint_eq(cli_apicall_maxapi, BC_V1_API_COUNT + 9U);
    ck_assert_str_eq(cli_apicalls[BC_V1_API_COUNT].name, "read64");

    ck_assert(cli_bytecode_api_allowed_for_format(BC_FORMAT_096, BC_V1_API_COUNT));
    ck_assert(cli_bytecode_api_allowed_for_format(BC_FORMAT_LEVEL, BC_V1_API_COUNT));
    ck_assert(!cli_bytecode_api_allowed_for_format(BC_FORMAT_LEVEL, BC_V1_API_COUNT + 1U));
    ck_assert(cli_bytecode_api_allowed_for_format(BC_FORMAT_LEVEL_V2, BC_V1_API_COUNT + 1U));
    ck_assert(cli_bytecode_api_allowed_for_format(BC_FORMAT_LEVEL_V2, cli_apicall_maxapi));
    ck_assert(!cli_bytecode_api_allowed_for_format(BC_FORMAT_LEVEL_V2, 0));
    ck_assert(!cli_bytecode_api_allowed_for_format(BC_FORMAT_LEVEL_V2, cli_apicall_maxapi + 1U));

    ck_assert(cli_bytecode_global_allowed_for_format(BC_FORMAT_LEVEL, BC_V1_MAX_GLOBAL));
    ck_assert(!cli_bytecode_global_allowed_for_format(BC_FORMAT_LEVEL, GLOBAL_FILESIZE64));
    ck_assert(!cli_bytecode_global_allowed_for_format(BC_FORMAT_LEVEL, GLOBAL_MATCH_OFFSETS64));
    ck_assert(cli_bytecode_global_allowed_for_format(BC_FORMAT_LEVEL_V2, GLOBAL_FILESIZE64));
    ck_assert(cli_bytecode_global_allowed_for_format(BC_FORMAT_LEVEL_V2, GLOBAL_MATCH_OFFSETS64));
    ck_assert(!cli_bytecode_global_allowed_for_format(BC_FORMAT_LEVEL_V2, _LAST_GLOBAL));
}
END_TEST

START_TEST(test_bytecode_loader_enforces_v2_format_boundary)
{
    ck_assert_int_eq(bytecode_load_mutated_interface_fixture(
                         BC_FORMAT_LEVEL, BC_V1_API_COUNT + 1U, UINT_MAX),
                     CL_EMALFDB);
    ck_assert_int_eq(bytecode_load_mutated_interface_fixture(
                         BC_FORMAT_LEVEL, UINT_MAX, GLOBAL_FILESIZE64),
                     CL_EMALFDB);
    ck_assert_int_eq(bytecode_load_mutated_interface_fixture(
                         BC_FORMAT_LEVEL_V2, BC_V1_API_COUNT + 1U,
                         GLOBAL_FILESIZE64),
                     CL_SUCCESS);
}
END_TEST

START_TEST(test_bytecode_loader_accepts_valid_fixture)
{
    const char *fixture = "input" PATHSEP "bytecode_sigs" PATHSEP
                          "Clamav-Unit-Test-Signature.cbc";
    struct cli_bc bc;
    FILE *input;
    int fd;

    fd = open_testfile(fixture, O_RDONLY);
    ck_assert_int_ge(fd, 0);
    input = fdopen(fd, "r");
    ck_assert_ptr_nonnull(input);

    memset(&bc, 0, sizeof(bc));
    ck_assert_int_eq(cli_bytecode_load(&bc, input, NULL, 1, 0), CL_SUCCESS);
    cli_bytecode_destroy(&bc);
    fclose(input);
}
END_TEST

START_TEST(test_bytecode_loader_rejects_truncated_records)
{
    char line[8192];
    struct cli_bc bc;
    FILE *input;
    FILE *truncated;
    size_t length;
    size_t cut;
    int fd;

    fd = open_testfile("input" PATHSEP "bytecode_sigs" PATHSEP
                       "Clamav-Unit-Test-Signature.cbc", O_RDONLY);
    ck_assert_int_ge(fd, 0);
    input = fdopen(fd, "r");
    ck_assert_ptr_nonnull(input);
    ck_assert_ptr_nonnull(fgets(line, sizeof(line), input));
    fclose(input);

    length = strlen(line);
    while (length && (line[length - 1] == '\n' || line[length - 1] == '\r'))
        line[--length] = '\0';
    ck_assert_int_gt((int)length, (int)(sizeof(BC_HEADER) - 1));

    /* Every proper prefix of the supported header, including the complete
     * header with all subsequent records absent, must fail closed.  This
     * exercises all end-of-line reads without relying on an allocator fault. */
    for (cut = sizeof(BC_HEADER) - 1; cut <= length; cut++) {
        truncated = tmpfile();
        ck_assert_ptr_nonnull(truncated);
        ck_assert_uint_eq(fwrite(line, 1, cut, truncated), cut);
        ck_assert_int_eq(fputc('\n', truncated), '\n');
        ck_assert_int_eq(fseek(truncated, 0, SEEK_SET), 0);

        memset(&bc, 0, sizeof(bc));
        ck_assert_msg(cli_bytecode_load(&bc, truncated, NULL, 1, 0) != CL_SUCCESS,
                      "truncated bytecode header prefix of %zu bytes was accepted",
                      cut);
        cli_bytecode_destroy(&bc);
        fclose(truncated);
    }
}
END_TEST

START_TEST(test_bytecode_loader_rejects_recursive_or_oversized_types)
{
    ck_assert_int_eq(bytecode_load_mutated_type_fixture(1), CL_EMALFDB);
    ck_assert_int_eq(bytecode_load_mutated_type_fixture(2), CL_EMALFDB);
}
END_TEST

START_TEST(test_bytecode_engine_scan_options_query)
{
    static const uint8_t general_name[]   = "GeNeRaL AlLmAtCh";
    static const uint8_t parse_name[]     = "parse archive";
    static const uint8_t heuristic_name[] = "heuristic broken";
    static const uint8_t mail_name[]      = "mail partial message";
    static const uint8_t dev_name[]       = "dev collect sha";
    static const uint8_t precedence_name[] = "heuristic precedence";
    static const uint8_t disabled_name[]  = "parse pdf";
    static const uint8_t unknown_name[]   = "parse archive trailing";
    static const uint8_t embedded_nul[]   = "parse archive\0trailing";
    struct cl_scan_options options;
    struct cli_bc_ctx bcctx;
    cli_ctx cctx;

    memset(&options, 0, sizeof(options));
    memset(&bcctx, 0, sizeof(bcctx));
    memset(&cctx, 0, sizeof(cctx));
    options.general   = CL_SCAN_GENERAL_ALLMATCHES;
    options.parse     = CL_SCAN_PARSE_ARCHIVE;
    options.heuristic = CL_SCAN_HEURISTIC_BROKEN;
    options.mail      = CL_SCAN_MAIL_PARTIAL_MESSAGE;
    options.dev       = CL_SCAN_DEV_COLLECT_SHA;
    options.general  |= CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE;
    cctx.options      = &options;
    bcctx.ctx         = &cctx;

    ck_assert_uint_eq(cli_bcapi_engine_scan_options_ex(&bcctx, general_name, sizeof(general_name) - 1), 1);
    ck_assert_uint_eq(cli_bcapi_engine_scan_options_ex(&bcctx, parse_name, sizeof(parse_name) - 1), 1);
    ck_assert_uint_eq(cli_bcapi_engine_scan_options_ex(&bcctx, heuristic_name, sizeof(heuristic_name) - 1), 1);
    ck_assert_uint_eq(cli_bcapi_engine_scan_options_ex(&bcctx, mail_name, sizeof(mail_name) - 1), 1);
    ck_assert_uint_eq(cli_bcapi_engine_scan_options_ex(&bcctx, dev_name, sizeof(dev_name) - 1), 1);
    ck_assert_uint_eq(cli_bcapi_engine_scan_options_ex(&bcctx, precedence_name, sizeof(precedence_name) - 1), 1);
    ck_assert_uint_eq(cli_bcapi_engine_scan_options_ex(&bcctx, disabled_name, sizeof(disabled_name) - 1), 0);
    ck_assert_uint_eq(cli_bcapi_engine_scan_options_ex(&bcctx, unknown_name, sizeof(unknown_name) - 1), 0);
    ck_assert_uint_eq(cli_bcapi_engine_scan_options_ex(&bcctx, embedded_nul, sizeof(embedded_nul) - 1), 0);
    ck_assert_uint_eq(cli_bcapi_engine_scan_options_ex(&bcctx, NULL, 0), 0);
}
END_TEST

START_TEST(test_bytecode_pdf_object_access_does_not_retain_fmap_pages)
{
    struct bytecode_failing_pread_state pread_state;
    struct cli_bc_ctx *bcctx;
    struct cli_bc bc;
    struct pdf_obj first;
    struct pdf_obj second;
    struct pdf_obj *objects[2];
    cli_ctx cctx;
    fmap_t *map;

    memset(&bc, 0, sizeof(bc));
    memset(&first, 0, sizeof(first));
    memset(&second, 0, sizeof(second));
    memset(&cctx, 0, sizeof(cctx));
    pread_state.length  = 8192;
    pread_state.fail_at = INT64_MAX;
    map = cl_fmap_open_handle(&pread_state, 0, pread_state.length,
                              bytecode_failing_pread_cb, 1);
    ck_assert_ptr_nonnull(map);

    bc.metadata.formatlevel = BC_FORMAT_LEVEL_V2;
    first.start             = 0;
    second.start            = 8;
    objects[0]              = &first;
    objects[1]              = &second;

    bcctx = cli_bytecode_context_alloc();
    ck_assert_ptr_nonnull(bcctx);
    bcctx->bc = &bc;
    bcctx->ctx = &cctx;
    cctx.fmap = map;
    ck_assert_int_eq(cli_bytecode_context_setfile(bcctx, map), CL_SUCCESS);
    ck_assert_int_eq(cli_bytecode_context_setpdf(bcctx, PDF_PHASE_PARSED, 2,
                                                  objects, NULL, 16, 0),
                     CL_SUCCESS);
    ck_assert_ptr_nonnull(cli_bcapi_pdf_getobj(bcctx, 0, 4));
    fmap_release_unlocked(map);
    ck_assert_uint_eq(map->paged, 0);

    pread_state.fail_at        = 0;
    cctx.scan_incomplete       = false;
    cctx.scan_incomplete_reason = NULL;
    map->dont_cache_flag       = false;
    ck_assert_ptr_null(cli_bcapi_pdf_getobj(bcctx, 0, 4));
    ck_assert(cctx.scan_incomplete);
    ck_assert_str_eq(cctx.scan_incomplete_reason, "Bytecode PDF object could not be read completely");
    ck_assert(map->dont_cache_flag);

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

START_TEST(test_bytecode_v1_offset_overflow_continues_to_v2_hook)
{
#if SIZE_MAX > UINT32_MAX
    unsigned char byte = 0;
    struct cl_engine *engine;
    struct cli_bc_ctx *bcctx;
    struct cli_bc *bcs;
    cli_scan_layer_t layer;
    cli_ctx cctx;
    fmap_t *map;
    cl_error_t ret;
    unsigned hook_slot = BC_PRECLASS - _BC_START_HOOKS;
    unsigned i;

    memset(&cctx, 0, sizeof(cctx));
    memset(&layer, 0, sizeof(layer));

    engine = cl_engine_new();
    ck_assert_ptr_nonnull(engine);
    map = cl_fmap_open_memory(&byte, sizeof(byte));
    ck_assert_ptr_nonnull(map);
    layer.fmap                = map;
    cctx.engine               = engine;
    cctx.fmap                 = map;
    cctx.recursion_stack      = &layer;
    cctx.recursion_stack_size = 1;

    engine->bcs.all_bcs         = calloc(2, sizeof(*engine->bcs.all_bcs));
    engine->hooks[hook_slot]    = calloc(2, sizeof(*engine->hooks[hook_slot]));
    ck_assert_ptr_nonnull(engine->bcs.all_bcs);
    ck_assert_ptr_nonnull(engine->hooks[hook_slot]);
    engine->bcs.count            = 2;
    engine->hooks_cnt[hook_slot] = 2;
    engine->hooks[hook_slot][0]  = 0;
    engine->hooks[hook_slot][1]  = 1;

    bcs = engine->bcs.all_bcs;
    for (i = 0; i < 2; i++) {
        bcs[i].id                   = i + 1;
        bcs[i].metadata.formatlevel = i == 0 ? BC_FORMAT_LEVEL : BC_FORMAT_LEVEL_V2;
        bcs[i].num_func             = 1;
        bcs[i].funcs                = calloc(1, sizeof(*bcs[i].funcs));
        bcs[i].state                = bc_loaded;
        ck_assert_ptr_nonnull(bcs[i].funcs);
    }

    bcctx = cli_bytecode_context_alloc();
    ck_assert_ptr_nonnull(bcctx);
    bcctx->ctx      = &cctx;
    bcctx->lsigoff[0] = (uint64_t)UINT32_MAX + 1;
    for (i = 1; i < 64; i++)
        bcctx->lsigoff[i] = CLI_OFF_NONE64;

    ret = cli_bytecode_runhook(&cctx, engine, bcctx, BC_PRECLASS, map);
    ck_assert_int_eq(ret, CL_EMAXSIZE);
    ck_assert(cctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    /* The legacy hook was skipped, but the later v2 hook selected the native
     * offset array before its intentionally unprepared runtime failed. */
    ck_assert(bcctx->hooks.match_offsets64 == bcctx->lsigoff);

    cli_bytecode_context_destroy(bcctx);
    cl_fmap_close(map);
    cl_engine_free(engine);
#else
    ck_assert(1);
#endif
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

START_TEST(test_bytecode_lsig_execution_failure_is_fail_visible)
{
    static const unsigned char bytes[] = {0x00};
    struct cl_engine *engine;
    struct cli_bc bc;
    struct cli_bc_func func;
    struct cli_all_bc bcs;
    struct cli_bc_ctx *bcctx;
    cli_scan_layer_t layer;
    cli_ctx cctx;
    fmap_t *map;
    struct cli_bc *hook_bc;
    uint32_t lsigcnt[64] = {0};
    uint64_t lsigoff[64];
    cl_error_t ret;
    unsigned hook_slot = BC_PRECLASS - _BC_START_HOOKS;
    unsigned i;

    for (i = 0; i < 64; i++)
        lsigoff[i] = CLI_OFF_NONE64;

    memset(&bc, 0, sizeof(bc));
    memset(&func, 0, sizeof(func));
    memset(&bcs, 0, sizeof(bcs));
    memset(&cctx, 0, sizeof(cctx));
    memset(&layer, 0, sizeof(layer));
    bc.id                  = 1;
    bc.metadata.formatlevel = BC_FORMAT_LEVEL_V2;
    bc.num_func            = 1;
    bc.funcs               = &func;
    bc.state               = bc_loaded;
    bcs.all_bcs            = &bc;
    bcs.count              = 1;

    engine = cl_engine_new();
    ck_assert_ptr_nonnull(engine);
    map = cl_fmap_open_memory(bytes, sizeof(bytes));
    ck_assert_ptr_nonnull(map);
    layer.fmap               = map;
    cctx.engine              = engine;
    cctx.fmap                = map;
    cctx.recursion_stack    = &layer;
    cctx.recursion_stack_size = 1;

    /* A loaded, unprepared bytecode entry makes cli_bytecode_run return an
     * execution error. That required logical matcher failure must not become
     * a clean result. */
    ret = cli_bytecode_runlsig(&cctx, NULL, &bcs, 1, lsigcnt, lsigoff, map);
    ck_assert_int_eq(ret, CL_EARG);
    ck_assert(cctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    /* A required logical bytecode entry must not look clean when its runtime
     * was disabled during preparation. */
    cctx.scan_incomplete = false;
    map->dont_cache_flag  = false;
    bc.state               = bc_disabled;
    ret = cli_bytecode_runlsig(&cctx, NULL, &bcs, 1, lsigcnt, lsigoff, map);
    ck_assert_int_eq(ret, CL_EBYTECODE);
    ck_assert(cctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);
    bc.state = bc_loaded;

    /* The same invariant applies to an applicable hook. A production hook
     * execution failure must not be hidden by the hook loop's clean fallback. */
    cctx.scan_incomplete = false;
    map->dont_cache_flag  = false;
    engine->bcs.all_bcs   = calloc(1, sizeof(*engine->bcs.all_bcs));
    engine->hooks[hook_slot] = calloc(1, sizeof(*engine->hooks[hook_slot]));
    ck_assert_ptr_nonnull(engine->bcs.all_bcs);
    ck_assert_ptr_nonnull(engine->hooks[hook_slot]);
    engine->bcs.count          = 1;
    engine->hooks_cnt[hook_slot] = 1;
    engine->hooks[hook_slot][0]  = 0;
    hook_bc                       = &engine->bcs.all_bcs[0];
    hook_bc->id                   = 2;
    hook_bc->metadata.formatlevel = BC_FORMAT_LEVEL_V2;
    hook_bc->num_func             = 1;
    hook_bc->funcs                = calloc(1, sizeof(*hook_bc->funcs));
    hook_bc->state                = bc_loaded;
    ck_assert_ptr_nonnull(hook_bc->funcs);

    bcctx = cli_bytecode_context_alloc();
    ck_assert_ptr_nonnull(bcctx);
    bcctx->ctx = &cctx;
    ret        = cli_bytecode_runhook(&cctx, engine, bcctx, BC_PRECLASS, map);
    ck_assert_int_eq(ret, CL_EARG);
    ck_assert(cctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    /* The hook path must fail closed for the same disabled-runtime boundary. */
    cctx.scan_incomplete = false;
    map->dont_cache_flag  = false;
    hook_bc->state         = bc_disabled;
    ret = cli_bytecode_runhook(&cctx, engine, bcctx, BC_PRECLASS, map);
    ck_assert_int_eq(ret, CL_EBYTECODE);
    ck_assert(cctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cli_bytecode_context_destroy(bcctx);

    cl_fmap_close(map);
    cl_engine_free(engine);
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

START_TEST(test_bytecode_timeout_respects_scan_deadline)
{
    struct cl_engine engine;
    cli_ctx scan_ctx;
    struct cli_bc_ctx bytecode_ctx;
    struct timeval now;

    memset(&engine, 0, sizeof(engine));
    memset(&scan_ctx, 0, sizeof(scan_ctx));
    memset(&bytecode_ctx, 0, sizeof(bytecode_ctx));
    engine.bytecode_timeout = 60000;
    scan_ctx.engine          = &engine;
    ck_assert_int_eq(gettimeofday(&now, NULL), 0);
    scan_ctx.time_limit.tv_sec  = now.tv_sec + 1;
    scan_ctx.time_limit.tv_usec = now.tv_usec;

    cli_bytecode_context_setctx(&bytecode_ctx, &scan_ctx);
    ck_assert_msg(bytecode_ctx.bytecode_timeout > 0, "bytecode timeout must remain positive");
    ck_assert_msg(bytecode_ctx.bytecode_timeout <= 1000, "bytecode timeout must honor the one-second scan deadline");

    memset(&bytecode_ctx, 0, sizeof(bytecode_ctx));
    memset(&scan_ctx.time_limit, 0, sizeof(scan_ctx.time_limit));
    cli_bytecode_context_setctx(&bytecode_ctx, &scan_ctx);
    ck_assert_uint_eq(bytecode_ctx.bytecode_timeout, engine.bytecode_timeout);
}
END_TEST

Suite *test_bytecode_suite(void)
{
    Suite *s            = suite_create("bytecode");
    TCase *tc_cli_arith = tcase_create("arithmetic");
    TCase *tc_cli_read  = tcase_create("map_read");
    TCase *tc_cli_loader = tcase_create("loader");
    TCase *tc_cli_valid_loader = tcase_create("valid_loader");
    suite_add_tcase(s, tc_cli_arith);
    suite_add_tcase(s, tc_cli_read);
    suite_add_tcase(s, tc_cli_loader);
    suite_add_tcase(s, tc_cli_valid_loader);
    tcase_set_timeout(tc_cli_arith, 20);
    tcase_set_timeout(tc_cli_read, 20);
    tcase_set_timeout(tc_cli_loader, 20);
    tcase_set_timeout(tc_cli_valid_loader, 20);
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
    tcase_add_test(tc_cli_arith, test_bytecode_v1_offset_overflow_continues_to_v2_hook);
    tcase_add_test(tc_cli_arith, test_bytecode_lsig_rejects_invalid_dispatch_arguments);
    tcase_add_test(tc_cli_arith, test_bytecode_lsig_execution_failure_is_fail_visible);
    tcase_add_test(tc_cli_arith, test_bytecode_timeout_respects_scan_deadline);
    tcase_add_test(tc_cli_read, test_bytecode_v2_uses_64bit_file_coordinates);
    tcase_add_test(tc_cli_read, test_bytecode_file_find_crosses_read_windows);
    tcase_add_test(tc_cli_read, test_bytecode_v2_interfaces_require_format8);
    tcase_add_test(tc_cli_read, test_bytecode_loader_enforces_v2_format_boundary);
    tcase_add_test(tc_cli_read, test_bytecode_engine_scan_options_query);
    tcase_add_test(tc_cli_read, test_bytecode_pdf_object_access_does_not_retain_fmap_pages);
    tcase_add_test(tc_cli_read, test_bytecode_v2_pdf_coordinates_are_native_width);
    tcase_add_test(tc_cli_read, test_bytecode_map_read_failure_is_fail_visible);
    tcase_add_test(tc_cli_read, test_bytecode_v1_read_rejects_invalid_offsets);
    tcase_add_test(tc_cli_read, test_bytecode_v1_coordinate_narrowing_is_fail_visible);
    tcase_add_test(tc_cli_read, test_bytecode_output_uses_64bit_accounting_and_temporary_quota);
    tcase_add_test(tc_cli_read, test_bytecode_jsnorm_limit_failure_releases_input);
    tcase_add_test(tc_cli_valid_loader, test_bytecode_loader_accepts_valid_fixture);
    tcase_add_test(tc_cli_loader, test_bytecode_loader_rejects_truncated_records);
    tcase_add_test(tc_cli_loader, test_bytecode_loader_rejects_recursive_or_oversized_types);
#ifdef DO_BARRIER
    tcase_add_test(tc_cli_arith, test_parallel_load);
#endif

    return s;
}
