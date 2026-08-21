/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2008-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm
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

#include <check.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

// libclamav
#include "clamav.h"
#include "readdb.h"
#include "matcher.h"
#include "matcher-ac.h"
#include "matcher-bm.h"
#include "matcher-hash.h"
#include "matcher-pcre.h"
#include "others.h"
#include "scanners.h"
#include "default.h"
#include "clamav_rust.h"
#include "yara_exec.h"
#include "bytecode.h"

#include "checks.h"

extern int64_t read_uint32_t(fmap_t *fmap, size_t offset);

#define TEST_YARA_UNDEFINED ((int64_t)0xFFFABADAFABADAFF)

static const struct ac_testdata_s {
    const char *data;
    const char *hexsig;
    const char *virname;
} ac_testdata[] = {
    /* IMPORTANT: ac_testdata[i].hexsig should only match ac_testdata[i].data */
    {"daaaaaaaaddbbbbbcce", "64[4-4]61616161{2}6262[3-6]65", "Test_1: anchored and ranged wildcard"},
    {"ebbbbbbbbeecccccddf", "6262(6162|6364|6265|6465){2}6363", "Test_2: multi-byte fixed alternate w/ ranged wild"},
    {"aaaabbbbcccccdddddeeee", "616161*63636363*6565", "Test_3: unbounded wildcards"},
    {"oprstuwxy", "6f??727374????7879", "Test_4: nibble wildcards"},
    {"abdcabcddabccadbbdbacb", "6463{2-3}64646162(63|64|65)6361*6462????6261{-1}6362", "Test_5: various wildcard combinations w/ alternate"},
    {"abcdefghijkabcdefghijk", "62????65666768*696a6b6162{2-3}656667[1-3]6b", "Test_6: various wildcard combinations"},
    {"abcadbabcadbabcacb", "6?6164?26?62{3}?26162?361", "Test_7: nibble and ranged wildcards"},
    /* testcase for filter bug: it was checking only first 32 chars, and last
     * maxpatlen */
    {"\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1dddddddddddddddddddd5\1\1\1\1\1\1\1\1\1\1\1\1\1", "6464646464646464646464646464646464646464(35|36)", "Test_8: filter bug"},

    /* altbyte */
    {"aabaa", "6161(62|63|64)6161", "Ac_Altstr_Test_1"}, /* control */
    {"aacaa", "6161(62|63|64)6161", "Ac_Altstr_Test_1"}, /* control */
    {"aadaa", "6161(62|63|64)6161", "Ac_Altstr_Test_1"}, /* control */

    /* alt-fstr */
    {"aabbbaa", "6161(626262|636363|646464)6161", "Ac_Altstr_Test_2"}, /* control */
    {"aacccaa", "6161(626262|636363|646464)6161", "Ac_Altstr_Test_2"}, /* control */
    {"aadddaa", "6161(626262|636363|646464)6161", "Ac_Altstr_Test_2"}, /* control */

    /* alt-vstr */
    {"aabbaa", "6161(6262|63636363|6464646464)6161", "Ac_Altstr_Test_3"},    /* control */
    {"aaccccaa", "6161(6262|63636363|6464646464)6161", "Ac_Altstr_Test_3"},  /* control */
    {"aadddddaa", "6161(6262|63636363|6464646464)6161", "Ac_Altstr_Test_3"}, /* control */

    /* alt-embed */
    {"aajjaa", "6161(6a6a|66(6767|6868)66|6969)6161", "Ac_Altstr_Test_4"},   /* control */
    {"aafggfaa", "6161(6a6a|66(6767|6868)66|6969)6161", "Ac_Altstr_Test_4"}, /* control */
    {"aafhhfaa", "6161(6a6a|66(6767|6868)66|6969)6161", "Ac_Altstr_Test_4"}, /* control */
    {"aaiiaa", "6161(6a6a|66(6767|6868)66|6969)6161", "Ac_Altstr_Test_4"},   /* control */

    {NULL, NULL, NULL}};

static const struct ac_sigopts_testdata_s {
    const char *data;
    uint32_t dlength;
    const char *hexsig;
    const char *offset;
    const uint16_t sigopts;
    const char *virname;
    const uint8_t expected_result;
} ac_sigopts_testdata[] = {
    /* nocase */
    {"aaaaa", 5, "6161616161", "*", ACPATT_OPTION_NOOPTS, "AC_Sigopts_Test_1", CL_VIRUS}, /* control */
    {"bBbBb", 5, "6262626262", "*", ACPATT_OPTION_NOOPTS, "AC_Sigopts_Test_2", CL_CLEAN}, /* nocase control */
    {"cCcCc", 5, "6363636363", "*", ACPATT_OPTION_NOCASE, "AC_Sigopts_Test_3", CL_VIRUS}, /* nocase test */

    /* fullword */
    {"ddddd&e", 7, "6464646464", "*", ACPATT_OPTION_FULLWORD, "AC_Sigopts_Test_4", CL_VIRUS},   /* fullword start */
    {"s&eeeee&e", 9, "6565656565", "*", ACPATT_OPTION_FULLWORD, "AC_Sigopts_Test_5", CL_VIRUS}, /* fullword middle */
    {"s&fffff", 7, "6666666666", "*", ACPATT_OPTION_FULLWORD, "AC_Sigopts_Test_6", CL_VIRUS},   /* fullword end */
    {"sggggg", 6, "6767676767", "*", ACPATT_OPTION_FULLWORD, "AC_Sigopts_Test_7", CL_CLEAN},    /* fullword fail start */
    {"hhhhhe", 6, "6868686868", "*", ACPATT_OPTION_FULLWORD, "AC_Sigopts_Test_8", CL_CLEAN},    /* fullword fail end */

    {"iiiii", 5, "(W)6969696969", "*", ACPATT_OPTION_NOOPTS, "AC_Sigopts_Test_9", CL_VIRUS},   /* fullword class start */
    {"jjj&jj", 6, "6a6a6a(W)6a6a", "*", ACPATT_OPTION_NOOPTS, "AC_Sigopts_Test_10", CL_VIRUS}, /* fullword class middle */
    {"kkkkk", 5, "6b6b6b6b6b(W)", "*", ACPATT_OPTION_NOOPTS, "AC_Sigopts_Test_11", CL_VIRUS},  /* fullword class end */
    {"slllll", 6, "(W)6c6c6c6c6c", "*", ACPATT_OPTION_NOOPTS, "AC_Sigopts_Test_12", CL_CLEAN}, /* fullword fail start */
    {"mmmmme", 6, "6d6d6d6d6d(W)", "*", ACPATT_OPTION_NOOPTS, "AC_Sigopts_Test_13", CL_CLEAN}, /* fullword class end */

    {"nNnNn", 5, "6e6e6e6e6e", "*", ACPATT_OPTION_NOCASE | ACPATT_OPTION_FULLWORD, "AC_Sigopts_Test_14", CL_VIRUS},  /* nocase fullword */
    {"soOoOo", 6, "6f6f6f6f6f", "*", ACPATT_OPTION_NOCASE | ACPATT_OPTION_FULLWORD, "AC_Sigopts_Test_15", CL_CLEAN}, /* nocase fullword start fail */
    {"pPpPpe", 6, "7070707070", "*", ACPATT_OPTION_NOCASE | ACPATT_OPTION_FULLWORD, "AC_Sigopts_Test_16", CL_CLEAN}, /* nocase fullword end fail */

    /* wide */
    {"q\0q\0q\0q\0q\0", 10, "7171717171", "*", ACPATT_OPTION_WIDE, "AC_Sigopts_Test_17", CL_VIRUS},                          /* control */
    {"r\0R\0r\0R\0r\0", 10, "7272727272", "*", ACPATT_OPTION_WIDE | ACPATT_OPTION_NOCASE, "AC_Sigopts_Test_18", CL_VIRUS},   /* control */
    {"s\0s\0s\0s\0s\0", 10, "7373737373", "*", ACPATT_OPTION_WIDE | ACPATT_OPTION_FULLWORD, "AC_Sigopts_Test_19", CL_VIRUS}, /* control */

    {"t\0t\0t\0t\0t\0", 10, "7474747474", "*", ACPATT_OPTION_WIDE | ACPATT_OPTION_ASCII, "AC_Sigopts_Test_20", CL_VIRUS}, /* control */

    {"u\0u\0u\0u\0u\0", 10, "7575757575", "*", ACPATT_OPTION_WIDE | ACPATT_OPTION_NOCASE | ACPATT_OPTION_FULLWORD, "AC_Sigopts_Test_21", CL_VIRUS}, /* control */
    {"v\0v\0v\0v\0v\0", 10, "7676767676", "*", ACPATT_OPTION_WIDE | ACPATT_OPTION_NOCASE | ACPATT_OPTION_ASCII, "AC_Sigopts_Test_22", CL_VIRUS},    /* control */

    {"w\0w\0w\0w\0w\0", 10, "7777777777", "*", ACPATT_OPTION_WIDE | ACPATT_OPTION_FULLWORD | ACPATT_OPTION_ASCII, "AC_Sigopts_Test_23", CL_VIRUS},                        /* control */
    {"x\0x\0x\0x\0x\0", 10, "7878787878", "*", ACPATT_OPTION_WIDE | ACPATT_OPTION_NOCASE | ACPATT_OPTION_FULLWORD | ACPATT_OPTION_ASCII, "AC_Sigopts_Test_24", CL_VIRUS}, /* control */

    {NULL, 0, NULL, NULL, ACPATT_OPTION_NOOPTS, NULL, CL_CLEAN}};

static const struct pcre_testdata_s {
    const char *data;
    const char *hexsig;
    const char *offset;
    const uint16_t sigopts;
    const char *virname;
    const uint8_t expected_result;
} pcre_testdata[] = {
    {"clamav", "/clamav/", "*", ACPATT_OPTION_NOOPTS, "Test_1: simple string", CL_VIRUS},
    {"cla:mav", "/cla:mav/", "*", ACPATT_OPTION_NOOPTS, "Test_2: embedded colon", CL_VIRUS},

    {"notbasic", "/basic/r", "0", ACPATT_OPTION_NOOPTS, "Test_3: rolling option", CL_VIRUS},
    {"nottrue", "/true/", "0", ACPATT_OPTION_NOOPTS, "Test4: rolling(off) option", CL_SUCCESS},

    {"not12345678truly", "/12345678/e", "3,8", ACPATT_OPTION_NOOPTS, "Test_5: encompass option", CL_VIRUS},
    {"not23456789truly", "/23456789/e", "4,8", ACPATT_OPTION_NOOPTS, "Test6: encompass option (low end)", CL_SUCCESS},
    {"not34567890truly", "/34567890/e", "3,7", ACPATT_OPTION_NOOPTS, "Test7: encompass option (high end)", CL_SUCCESS},

    {"notapietruly", "/apie/re", "2,2", ACPATT_OPTION_NOOPTS, "Test8: rolling encompass", CL_SUCCESS},
    {"notafigtruly", "/afig/e", "2,2", ACPATT_OPTION_NOOPTS, "Test9: rolling(off) encompass", CL_SUCCESS},
    {"notatretruly", "/atre/re", "2,6", ACPATT_OPTION_NOOPTS, "Test10: rolling encompass", CL_VIRUS},
    {"notasadtruly", "/asad/e", "2,6", ACPATT_OPTION_NOOPTS, "Test11: rolling(off) encompass", CL_VIRUS},

    {NULL, NULL, NULL, ACPATT_OPTION_NOOPTS, NULL, CL_CLEAN}};

static cli_ctx ctx;
static struct cl_scan_options options;

static fmap_t thefmap;
static const char *virname = NULL;
static void setup(void)
{
    struct cli_matcher *root;
    virname = NULL;

    memset(&thefmap, 0, sizeof(thefmap));

    memset(&ctx, 0, sizeof(ctx));
    memset(&options, 0, sizeof(struct cl_scan_options));
    ctx.options = &options;

    ctx.engine = cl_engine_new();
    ck_assert_msg(!!ctx.engine, "cl_engine_new() failed");

    ctx.dconf = ctx.engine->dconf;

    ctx.recursion_stack_size = ctx.engine->max_recursion_level;
    ctx.recursion_stack      = calloc(sizeof(cli_scan_layer_t), ctx.recursion_stack_size);
    ck_assert_msg(!!ctx.recursion_stack, "calloc() for recursion_stack failed");

    // ctx was memset, so recursion_level starts at 0.
    ctx.recursion_stack[ctx.recursion_level].fmap = &thefmap;

    ctx.fmap = ctx.recursion_stack[ctx.recursion_level].fmap;

    root = (struct cli_matcher *)MPOOL_CALLOC(ctx.engine->mempool, 1, sizeof(struct cli_matcher));
    ck_assert_msg(root != NULL, "root == NULL");
#ifdef USE_MPOOL
    root->mempool = ctx.engine->mempool;
#endif

    ctx.engine->root[0] = root;
}

static void teardown(void)
{
    cl_engine_free((struct cl_engine *)ctx.engine);
    if (ctx.recursion_stack[ctx.recursion_level].evidence) {
        evidence_free(ctx.recursion_stack[ctx.recursion_level].evidence);
    }
    free(ctx.recursion_stack);
}

START_TEST(test_ac_scanbuff)
{
    struct cli_ac_data mdata;
    struct cli_matcher *root;
    unsigned int i;
    int ret;

    root = ctx.engine->root[0];
    ck_assert_msg(root != NULL, "root == NULL");
    root->ac_only = 1;

#ifdef USE_MPOOL
    root->mempool = mpool_create();
#endif
    ret = cli_ac_init(root, CLI_DEFAULT_AC_MINDEPTH, CLI_DEFAULT_AC_MAXDEPTH, 1);
    ck_assert_msg(ret == CL_SUCCESS, "cli_ac_init() failed");

    for (i = 0; ac_testdata[i].data; i++) {
        ret = cli_add_content_match_pattern(root, ac_testdata[i].virname, ac_testdata[i].hexsig, 0, 0, 0, "*", NULL, 0);
        ck_assert_msg(ret == CL_SUCCESS, "cli_add_content_match_pattern failed");
    }

    ret = cli_ac_buildtrie(root);
    ck_assert_msg(ret == CL_SUCCESS, "cli_ac_buildtrie() failed");

    ret = cli_ac_initdata(&mdata, root->ac_partsigs, 0, 0, CLI_DEFAULT_AC_TRACKLEN);
    ck_assert_msg(ret == CL_SUCCESS, "cli_ac_initdata() failed");

    ctx.options->general &= ~CL_SCAN_GENERAL_ALLMATCHES; /* make sure all-match is disabled */
    for (i = 0; ac_testdata[i].data; i++) {
        ret = cli_ac_scanbuff((const unsigned char *)ac_testdata[i].data, strlen(ac_testdata[i].data), &virname, NULL, NULL, root, &mdata, 0, 0, NULL, AC_SCAN_VIR, NULL);
        ck_assert_msg(ret == CL_VIRUS, "cli_ac_scanbuff() failed for %s", ac_testdata[i].virname);
        ck_assert_msg(!strncmp(virname, ac_testdata[i].virname, strlen(ac_testdata[i].virname)), "Dataset %u matched with %s", i, virname);

        ret = cli_scan_buff((const unsigned char *)ac_testdata[i].data, strlen(ac_testdata[i].data), 0, &ctx, 0, NULL);
        ck_assert_msg(ret == CL_VIRUS, "cli_scan_buff() failed for %s", ac_testdata[i].virname);
        ck_assert_msg(!strncmp(virname, ac_testdata[i].virname, strlen(ac_testdata[i].virname)), "Dataset %u matched with %s", i, virname);
    }

    cli_ac_freedata(&mdata);
}
END_TEST

START_TEST(test_ac_scanbuff_allscan)
{
    struct cli_ac_data mdata;
    struct cli_matcher *root;
    unsigned int i;
    int ret;

    root = ctx.engine->root[0];
    ck_assert_msg(root != NULL, "root == NULL");
    root->ac_only = 1;

#ifdef USE_MPOOL
    root->mempool = mpool_create();
#endif
    ret = cli_ac_init(root, CLI_DEFAULT_AC_MINDEPTH, CLI_DEFAULT_AC_MAXDEPTH, 1);
    ck_assert_msg(ret == CL_SUCCESS, "cli_ac_init() failed");

    for (i = 0; ac_testdata[i].data; i++) {
        ret = cli_add_content_match_pattern(root, ac_testdata[i].virname, ac_testdata[i].hexsig, 0, 0, 0, "*", NULL, 0);
        ck_assert_msg(ret == CL_SUCCESS, "cli_add_content_match_pattern failed");
    }

    ret = cli_ac_buildtrie(root);
    ck_assert_msg(ret == CL_SUCCESS, "cli_ac_buildtrie() failed");

    ret = cli_ac_initdata(&mdata, root->ac_partsigs, 0, 0, CLI_DEFAULT_AC_TRACKLEN);
    ck_assert_msg(ret == CL_SUCCESS, "cli_ac_initdata() failed");

    ctx.options->general |= CL_SCAN_GENERAL_ALLMATCHES; /* enable all-match */
    for (i = 0; ac_testdata[i].data; i++) {
        ret = cli_ac_scanbuff((const unsigned char *)ac_testdata[i].data, strlen(ac_testdata[i].data), &virname, NULL, NULL, root, &mdata, 0, 0, NULL, AC_SCAN_VIR, NULL);
        ck_assert_msg(ret == CL_VIRUS, "cli_ac_scanbuff() failed for %s", ac_testdata[i].virname);
        ck_assert_msg(!strncmp(virname, ac_testdata[i].virname, strlen(ac_testdata[i].virname)), "Dataset %u matched with %s", i, virname);

        ret = cli_scan_buff((const unsigned char *)ac_testdata[i].data, strlen(ac_testdata[i].data), 0, &ctx, 0, NULL);
        ck_assert_msg(ret == CL_SUCCESS, "cli_scan_buff() failed for %s", ac_testdata[i].virname);

        // phishingScan() doesn't check the number of alerts. When using CL_SCAN_GENERAL_ALLMATCHES
        // or if using `CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE` and `cli_append_potentially_unwanted()`
        // we need to count the number of alerts manually to determine the verdict.
        ck_assert_msg(0 < evidence_num_alerts(ctx.this_layer_evidence), "cli_scan_buff() failed for %s", ac_testdata[i].virname);
        ck_assert_msg(!strncmp(virname, ac_testdata[i].virname, strlen(ac_testdata[i].virname)), "Dataset %u matched with %s", i, virname);
        if (evidence_num_alerts(ctx.this_layer_evidence) > 0) {
            // Reset evidence for the next scan.
            evidence_free(ctx.recursion_stack[ctx.recursion_level].evidence);
            ctx.recursion_stack[ctx.recursion_level].evidence = NULL;
            ctx.this_layer_evidence                           = NULL;
        }
    }

    cli_ac_freedata(&mdata);
}
END_TEST

START_TEST(test_ac_scanbuff_ex)
{
    struct cli_ac_data mdata;
    struct cli_matcher *root;
    unsigned int i;
    int ret;

    root = ctx.engine->root[0];
    ck_assert_msg(root != NULL, "root == NULL");
    root->ac_only = 1;

#ifdef USE_MPOOL
    root->mempool = mpool_create();
#endif
    ret = cli_ac_init(root, CLI_DEFAULT_AC_MINDEPTH, CLI_DEFAULT_AC_MAXDEPTH, 1);
    ck_assert_msg(ret == CL_SUCCESS, "[ac_ex] cli_ac_init() failed");

    for (i = 0; ac_sigopts_testdata[i].data; i++) {
        ret = cli_sigopts_handler(root, ac_sigopts_testdata[i].virname, ac_sigopts_testdata[i].hexsig, ac_sigopts_testdata[i].sigopts, 0, 0, ac_sigopts_testdata[i].offset, NULL, 0);
        ck_assert_msg(ret == CL_SUCCESS, "[ac_ex] cli_sigopts_handler() failed");
    }

    ret = cli_ac_buildtrie(root);
    ck_assert_msg(ret == CL_SUCCESS, "[ac_ex] cli_ac_buildtrie() failed");

    ret = cli_ac_initdata(&mdata, root->ac_partsigs, 0, 0, CLI_DEFAULT_AC_TRACKLEN);
    ck_assert_msg(ret == CL_SUCCESS, "[ac_ex] cli_ac_initdata() failed");

    ctx.options->general &= ~CL_SCAN_GENERAL_ALLMATCHES; /* make sure all-match is disabled */
    for (i = 0; ac_sigopts_testdata[i].data; i++) {
        ret = cli_ac_scanbuff((const unsigned char *)ac_sigopts_testdata[i].data, ac_sigopts_testdata[i].dlength, &virname, NULL, NULL, root, &mdata, 0, 0, NULL, AC_SCAN_VIR, NULL);
        ck_assert_msg(ret == ac_sigopts_testdata[i].expected_result, "[ac_ex] cli_ac_scanbuff() failed for %s (%d != %d)", ac_sigopts_testdata[i].virname, ret, ac_sigopts_testdata[i].expected_result);
        if (ac_sigopts_testdata[i].expected_result == CL_VIRUS)
            ck_assert_msg(!strncmp(virname, ac_sigopts_testdata[i].virname, strlen(ac_sigopts_testdata[i].virname)), "[ac_ex] Dataset %u matched with %s", i, virname);

        ret = cli_scan_buff((const unsigned char *)ac_sigopts_testdata[i].data, ac_sigopts_testdata[i].dlength, 0, &ctx, 0, NULL);
        ck_assert_msg(ret == ac_sigopts_testdata[i].expected_result, "[ac_ex] cli_ac_scanbuff() failed for %s (%d != %d)", ac_sigopts_testdata[i].virname, ret, ac_sigopts_testdata[i].expected_result);
    }

    cli_ac_freedata(&mdata);
}
END_TEST

START_TEST(test_ac_scanbuff_allscan_ex)
{
    struct cli_ac_data mdata;
    struct cli_matcher *root;
    unsigned int i;
    int ret;

    root = ctx.engine->root[0];
    ck_assert_msg(root != NULL, "root == NULL");
    root->ac_only = 1;

#ifdef USE_MPOOL
    root->mempool = mpool_create();
#endif
    ret = cli_ac_init(root, CLI_DEFAULT_AC_MINDEPTH, CLI_DEFAULT_AC_MAXDEPTH, 1);
    ck_assert_msg(ret == CL_SUCCESS, "[ac_ex] cli_ac_init() failed");

    for (i = 0; ac_sigopts_testdata[i].data; i++) {
        ret = cli_sigopts_handler(root, ac_sigopts_testdata[i].virname, ac_sigopts_testdata[i].hexsig, ac_sigopts_testdata[i].sigopts, 0, 0, ac_sigopts_testdata[i].offset, NULL, 0);
        ck_assert_msg(ret == CL_SUCCESS, "[ac_ex] cli_sigopts_handler() failed");
    }

    ret = cli_ac_buildtrie(root);
    ck_assert_msg(ret == CL_SUCCESS, "[ac_ex] cli_ac_buildtrie() failed");

    ret = cli_ac_initdata(&mdata, root->ac_partsigs, 0, 0, CLI_DEFAULT_AC_TRACKLEN);
    ck_assert_msg(ret == CL_SUCCESS, "[ac_ex] cli_ac_initdata() failed");

    ctx.options->general |= CL_SCAN_GENERAL_ALLMATCHES; /* enable all-match */
    for (i = 0; ac_sigopts_testdata[i].data; i++) {
        cl_error_t verdict = CL_CLEAN;

        ret = cli_ac_scanbuff((const unsigned char *)ac_sigopts_testdata[i].data, ac_sigopts_testdata[i].dlength, &virname, NULL, NULL, root, &mdata, 0, 0, NULL, AC_SCAN_VIR, NULL);
        ck_assert_msg(ret == ac_sigopts_testdata[i].expected_result, "[ac_ex] cli_ac_scanbuff() failed for %s (%d != %d)", ac_sigopts_testdata[i].virname, ret, ac_sigopts_testdata[i].expected_result);
        if (ac_sigopts_testdata[i].expected_result == CL_VIRUS)
            ck_assert_msg(!strncmp(virname, ac_sigopts_testdata[i].virname, strlen(ac_sigopts_testdata[i].virname)), "[ac_ex] Dataset %u matched with %s", i, virname);

        ret = cli_scan_buff((const unsigned char *)ac_sigopts_testdata[i].data, ac_sigopts_testdata[i].dlength, 0, &ctx, 0, NULL);
        ck_assert_msg(ret == CL_SUCCESS, "[ac_ex] cli_ac_scanbuff() failed for %s (%d != %d)", ac_sigopts_testdata[i].virname, ret, ac_sigopts_testdata[i].expected_result);

        // phishingScan() doesn't check the number of alerts. When using CL_SCAN_GENERAL_ALLMATCHES
        // or if using `CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE` and `cli_append_potentially_unwanted()`
        // we need to count the number of alerts manually to determine the verdict.
        if (0 < evidence_num_alerts(ctx.this_layer_evidence)) {
            verdict = CL_VIRUS;
        }

        ck_assert_msg(verdict == ac_sigopts_testdata[i].expected_result, "[ac_ex] cli_ac_scanbuff() failed for %s (%d != %d)", ac_sigopts_testdata[i].virname, verdict, ac_sigopts_testdata[i].expected_result);
        if (evidence_num_alerts(ctx.this_layer_evidence) > 0) {
            // Reset evidence for the next scan.
            evidence_free(ctx.recursion_stack[ctx.recursion_level].evidence);
            ctx.recursion_stack[ctx.recursion_level].evidence = NULL;
            ctx.this_layer_evidence                           = NULL;
        }
    }

    cli_ac_freedata(&mdata);
}
END_TEST

START_TEST(test_bm_scanbuff)
{
    struct cli_matcher *root;
    const char *virname = NULL;
    int ret;

    root = ctx.engine->root[0];
    ck_assert_msg(root != NULL, "root == NULL");

#ifdef USE_MPOOL
    root->mempool = mpool_create();
#endif
    ret = cli_bm_init(root);
    ck_assert_msg(ret == CL_SUCCESS, "cli_bm_init() failed");

    ret = cli_add_content_match_pattern(root, "Sig1", "deadbabe", 0, 0, 0, "*", NULL, 0);
    ck_assert_msg(ret == CL_SUCCESS, "cli_add_content_match_pattern failed");
    ret = cli_add_content_match_pattern(root, "Sig2", "deadbeef", 0, 0, 0, "*", NULL, 0);
    ck_assert_msg(ret == CL_SUCCESS, "cli_add_content_match_pattern failed");
    ret = cli_add_content_match_pattern(root, "Sig3", "babedead", 0, 0, 0, "*", NULL, 0);
    ck_assert_msg(ret == CL_SUCCESS, "cli_add_content_match_pattern failed");

    ctx.options->general &= ~CL_SCAN_GENERAL_ALLMATCHES; /* make sure all-match is disabled */
    ret = cli_bm_scanbuff((const unsigned char *)"blah\xde\xad\xbe\xef", 8, &virname, NULL, root, 0, NULL, NULL, NULL);
    ck_assert_msg(ret == CL_VIRUS, "cli_bm_scanbuff() failed");
    ck_assert_msg(!strncmp(virname, "Sig2", 4), "Incorrect signature matched in cli_bm_scanbuff()\n");
}
END_TEST

START_TEST(test_bm_scanbuff_allscan)
{
    struct cli_matcher *root;
    const char *virname = NULL;
    int ret;

    root = ctx.engine->root[0];
    ck_assert_msg(root != NULL, "root == NULL");

#ifdef USE_MPOOL
    root->mempool = mpool_create();
#endif
    ret = cli_bm_init(root);
    ck_assert_msg(ret == CL_SUCCESS, "cli_bm_init() failed");

    ret = cli_add_content_match_pattern(root, "Sig1", "deadbabe", 0, 0, 0, "*", NULL, 0);
    ck_assert_msg(ret == CL_SUCCESS, "cli_add_content_match_pattern failed");
    ret = cli_add_content_match_pattern(root, "Sig2", "deadbeef", 0, 0, 0, "*", NULL, 0);
    ck_assert_msg(ret == CL_SUCCESS, "cli_add_content_match_pattern failed");
    ret = cli_add_content_match_pattern(root, "Sig3", "babedead", 0, 0, 0, "*", NULL, 0);
    ck_assert_msg(ret == CL_SUCCESS, "cli_add_content_match_pattern failed");

    ctx.options->general |= CL_SCAN_GENERAL_ALLMATCHES; /* enable all-match */
    ret = cli_bm_scanbuff((const unsigned char *)"blah\xde\xad\xbe\xef", 8, &virname, NULL, root, 0, NULL, NULL, NULL);
    ck_assert_msg(ret == CL_VIRUS, "cli_bm_scanbuff() failed");
    ck_assert_msg(!strncmp(virname, "Sig2", 4), "Incorrect signature matched in cli_bm_scanbuff()\n");
}
END_TEST

START_TEST(test_pcre_scanbuff)
{
    struct cli_ac_data mdata;
    struct cli_matcher *root;
    char *hexsig;
    unsigned int i, hexlen;
    int ret;

    root = ctx.engine->root[0];
    ck_assert_msg(root != NULL, "root == NULL");

#ifdef USE_MPOOL
    root->mempool = mpool_create();
#endif
    for (i = 0; pcre_testdata[i].data; i++) {
        hexlen = strlen(PCRE_BYPASS) + strlen(pcre_testdata[i].hexsig) + 1;

        hexsig = calloc(hexlen, sizeof(char));
        ck_assert_msg(hexsig != NULL, "[pcre] failed to prepend bypass (out-of-memory)");

        strncat(hexsig, PCRE_BYPASS, hexlen);
        strncat(hexsig, pcre_testdata[i].hexsig, hexlen);

        ret = readdb_parse_ldb_subsignature(root, pcre_testdata[i].virname, hexsig, pcre_testdata[i].offset, NULL, 0, 0, 0, NULL);
        ck_assert_msg(ret == CL_SUCCESS, "[pcre] readdb_parse_ldb_subsignature failed");
        free(hexsig);
    }

    ret = cli_pcre_build(root, CLI_DEFAULT_PCRE_MATCH_LIMIT, CLI_DEFAULT_PCRE_RECMATCH_LIMIT, NULL);
    ck_assert_msg(ret == CL_SUCCESS, "[pcre] cli_pcre_build() failed");

    // recomputate offsets

    ret = cli_ac_initdata(&mdata, root->ac_partsigs, root->ac_lsigs, root->ac_reloff_num, CLI_DEFAULT_AC_TRACKLEN);
    ck_assert_msg(ret == CL_SUCCESS, "[pcre] cli_ac_initdata() failed");

    ctx.options->general &= ~CL_SCAN_GENERAL_ALLMATCHES; /* make sure all-match is disabled */
    for (i = 0; pcre_testdata[i].data; i++) {
        ret = cli_pcre_scanbuf((const unsigned char *)pcre_testdata[i].data, strlen(pcre_testdata[i].data), &virname, NULL, root, NULL, NULL, NULL);
        ck_assert_msg(ret == pcre_testdata[i].expected_result, "[pcre] cli_pcre_scanbuff() failed for %s (%d != %d)", pcre_testdata[i].virname, ret, pcre_testdata[i].expected_result);

        // we cannot check if the virname matches because we didn't load a whole logical signature, and virnames are stored in the lsig structure, now.

        ret = cli_scan_buff((const unsigned char *)pcre_testdata[i].data, strlen(pcre_testdata[i].data), 0, &ctx, 0, NULL);
        ck_assert_msg(ret == pcre_testdata[i].expected_result, "[pcre] cli_scan_buff() failed for %s", pcre_testdata[i].virname);
    }

    cli_ac_freedata(&mdata);
}
END_TEST

START_TEST(test_pcre_scanbuff_allscan)
{
    struct cli_ac_data mdata;
    struct cli_matcher *root;
    char *hexsig;
    unsigned int i, hexlen;
    int ret;

    root = ctx.engine->root[0];
    ck_assert_msg(root != NULL, "root == NULL");

#ifdef USE_MPOOL
    root->mempool = mpool_create();
#endif

    for (i = 0; pcre_testdata[i].data; i++) {
        hexlen = strlen(PCRE_BYPASS) + strlen(pcre_testdata[i].hexsig) + 1;

        hexsig = calloc(hexlen, sizeof(char));
        ck_assert_msg(hexsig != NULL, "[pcre] failed to prepend bypass (out-of-memory)");

        strncat(hexsig, PCRE_BYPASS, hexlen);
        strncat(hexsig, pcre_testdata[i].hexsig, hexlen);

        ret = readdb_parse_ldb_subsignature(root, pcre_testdata[i].virname, hexsig, pcre_testdata[i].offset, NULL, 0, 0, 1, NULL);
        ck_assert_msg(ret == CL_SUCCESS, "[pcre] readdb_parse_ldb_subsignature failed");
        free(hexsig);
    }

    ret = cli_pcre_build(root, CLI_DEFAULT_PCRE_MATCH_LIMIT, CLI_DEFAULT_PCRE_RECMATCH_LIMIT, NULL);
    ck_assert_msg(ret == CL_SUCCESS, "[pcre] cli_pcre_build() failed");

    // recomputate offsets

    ret = cli_ac_initdata(&mdata, root->ac_partsigs, root->ac_lsigs, root->ac_reloff_num, CLI_DEFAULT_AC_TRACKLEN);
    ck_assert_msg(ret == CL_SUCCESS, "[pcre] cli_ac_initdata() failed");

    ctx.options->general |= CL_SCAN_GENERAL_ALLMATCHES; /* enable all-match */
    for (i = 0; pcre_testdata[i].data; i++) {
        cl_error_t verdict = CL_CLEAN;

        ret = cli_pcre_scanbuf((const unsigned char *)pcre_testdata[i].data, strlen(pcre_testdata[i].data), &virname, NULL, root, NULL, NULL, NULL);
        ck_assert_msg(ret == pcre_testdata[i].expected_result, "[pcre] cli_pcre_scanbuff() failed for %s (%d != %d)", pcre_testdata[i].virname, ret, pcre_testdata[i].expected_result);

        // we cannot check if the virname matches because we didn't load a whole logical signature, and virnames are stored in the lsig structure, now.

        ret = cli_scan_buff((const unsigned char *)pcre_testdata[i].data, strlen(pcre_testdata[i].data), 0, &ctx, 0, NULL);

        // cli_scan_buff() doesn't check the number of alerts. When using CL_SCAN_GENERAL_ALLMATCHES
        // or if using `CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE` and `cli_append_potentially_unwanted()`
        // we need to count the number of alerts manually to determine the verdict.
        if (0 < evidence_num_alerts(ctx.this_layer_evidence)) {
            verdict = CL_VIRUS;
        }

        ck_assert_msg(verdict == pcre_testdata[i].expected_result, "[pcre] cli_scan_buff() failed for %s", pcre_testdata[i].virname);
        /* num_virus field add to test case struct */
        if (evidence_num_alerts(ctx.this_layer_evidence) > 0) {
            // Reset evidence for the next scan.
            evidence_free(ctx.recursion_stack[ctx.recursion_level].evidence);
            ctx.recursion_stack[ctx.recursion_level].evidence = NULL;
            ctx.this_layer_evidence                           = NULL;
        }
    }

    cli_ac_freedata(&mdata);
}
END_TEST

START_TEST(test_large_file_offset_values)
{
    struct cli_matcher *root = ctx.engine->root[0];
    struct cli_target_info info;
    struct cli_bm_patt first, second;
    struct cli_bm_patt *patterns[2];
    struct cli_bm_off offsets;
    uint64_t offdata[4] = {0};
    uint64_t offset_min = 0, offset_max = 0;

    ck_assert_int_eq(cli_caloff("5000000000,7", NULL, TARGET_GENERIC, offdata, &offset_min, &offset_max), CL_SUCCESS);
    ck_assert_uint_eq(offdata[0], CLI_OFF_ABSOLUTE);
    ck_assert_uint_eq(offset_min, 5000000000ULL);
    ck_assert_uint_eq(offset_max, 5000000007ULL);

    ck_assert_int_eq(cli_caloff("4294967294", NULL, TARGET_GENERIC, offdata, &offset_min, &offset_max), CL_SUCCESS);
    ck_assert_uint_eq(offset_min, 4294967294ULL);
    ck_assert(offset_min != CLI_OFF_NONE64);
    ck_assert_int_eq(cli_caloff("4294967295", NULL, TARGET_GENERIC, offdata, &offset_min, &offset_max), CL_SUCCESS);
    ck_assert_uint_eq(offset_min, 4294967295ULL);
    ck_assert(offset_min != CLI_OFF_ANY64);
    ck_assert_int_eq(cli_caloff("4294967296", NULL, TARGET_GENERIC, offdata, &offset_min, &offset_max), CL_SUCCESS);
    ck_assert_uint_eq(offset_min, 4294967296ULL);
    ck_assert_int_eq(cli_caloff("*", NULL, TARGET_GENERIC, offdata, &offset_min, &offset_max), CL_SUCCESS);
    ck_assert_uint_eq(offdata[0], CLI_OFF_ANY64);
    ck_assert(CLI_OFF_ANY64 != CLI_OFF_NONE64);

    ck_assert_int_eq(cli_caloff("-1", NULL, TARGET_GENERIC, offdata, &offset_min, &offset_max), CL_EMALFDB);
    ck_assert_int_eq(cli_caloff("18446744073709551614", NULL, TARGET_GENERIC, offdata, &offset_min, &offset_max), CL_EMALFDB);
    ck_assert_int_eq(cli_caloff("18446744073709551615", NULL, TARGET_GENERIC, offdata, &offset_min, &offset_max), CL_EMALFDB);
    ck_assert_int_eq(cli_caloff("18446744073709551613,1", NULL, TARGET_GENERIC, offdata, &offset_min, &offset_max), CL_EMALFDB);

    memset(&info, 0, sizeof(info));
    info.fsize = (off_t)34359738368ULL;
    memset(&first, 0, sizeof(first));
    memset(&second, 0, sizeof(second));
    first.offdata[0]       = CLI_OFF_ABSOLUTE;
    first.offset_min       = 5000000000ULL;
    first.length           = 1;
    second.offdata[0]      = CLI_OFF_ABSOLUTE;
    second.offset_min      = 1;
    second.length          = 1;
    patterns[0]            = &first;
    patterns[1]            = &second;
    root->bm_pattab        = patterns;
    root->bm_patterns      = 2;

    ck_assert_int_eq(cli_bm_initoff(root, &offsets, &info), CL_SUCCESS);
    ck_assert_uint_eq(offsets.cnt, 2);
    ck_assert_uint_eq(offsets.offtab[0], 1);
    ck_assert_uint_eq(offsets.offtab[1], 5000000000ULL);
    cli_bm_freeoff(&offsets);

    root->bm_pattab   = NULL;
    root->bm_patterns = 0;
}
END_TEST

START_TEST(test_bm_offset_mode_matches_above_uint32)
{
#if SIZE_MAX > UINT32_MAX
    struct cli_matcher *root = ctx.engine->root[0];
    struct cli_target_info info;
    struct cli_bm_off offsets;
    const struct cli_bm_patt *matched = NULL;
    const char *matched_name = NULL;
    cl_error_t ret;

    ck_assert_ptr_nonnull(root);
    memset(&info, 0, sizeof(info));
    memset(&offsets, 0, sizeof(offsets));
    root->bm_offmode = 1;

#ifdef USE_MPOOL
    root->mempool = mpool_create();
#endif
    ck_assert_int_eq(cli_bm_init(root), CL_SUCCESS);
    ck_assert_int_eq(cli_add_content_match_pattern(root, "BM_Large_Offset",
                                                   "deadbeef", 0, 0, 0,
                                                   "5000000000", NULL, 0),
                     CL_SUCCESS);

    info.fsize = (off_t)34359738368ULL;
    ck_assert_int_eq(cli_bm_initoff(root, &offsets, &info), CL_SUCCESS);
    ck_assert_uint_eq(offsets.cnt, 1);
    ck_assert_uint_eq(offsets.offtab[0], 5000000000ULL);

    ret = cli_bm_scanbuff((const unsigned char *)"\xde\xad\xbe\xef", 4,
                          &matched_name, &matched, root, 5000000000ULL,
                          &info, &offsets, NULL);
    ck_assert_int_eq(ret, CL_VIRUS);
    ck_assert_str_eq(matched_name, "BM_Large_Offset.UNOFFICIAL");
    ck_assert_ptr_nonnull(matched);
    ck_assert_uint_eq(matched->offset_min, 5000000000ULL);

    cli_bm_freeoff(&offsets);
#else
    ck_assert(1);
#endif
}
END_TEST

START_TEST(test_bm_initoff_rejects_coordinate_wrap)
{
    struct cli_matcher *root = ctx.engine->root[0];
    struct cli_target_info info;
    struct cli_bm_off offsets;
    struct cli_bm_patt valid;
    struct cli_bm_patt wrapped;
    struct cli_bm_patt *patterns[2];

    ck_assert_ptr_nonnull(root);
    memset(&info, 0, sizeof(info));
    memset(&offsets, 0, sizeof(offsets));
    memset(&valid, 0, sizeof(valid));
    memset(&wrapped, 0, sizeof(wrapped));
    info.fsize = (off_t)34359738368ULL;

    valid.offdata[0]      = CLI_OFF_ABSOLUTE;
    valid.offset_min      = 5000000000ULL;
    valid.length          = 4;
    valid.virname         = "valid";
    wrapped.offdata[0]    = CLI_OFF_ABSOLUTE;
    wrapped.offset_min    = UINT64_MAX - 1;
    wrapped.prefix_length = 4;
    wrapped.length        = 4;
    wrapped.virname       = "wrapped";
    patterns[0]           = &valid;
    patterns[1]           = &wrapped;
    root->bm_pattab       = patterns;
    root->bm_patterns     = 2;

    ck_assert_int_eq(cli_bm_initoff(root, &offsets, &info), CL_SUCCESS);
    ck_assert_uint_eq(offsets.cnt, 1);
    ck_assert_uint_eq(offsets.offtab[0], 5000000000ULL);
    cli_bm_freeoff(&offsets);

    root->bm_pattab   = NULL;
    root->bm_patterns = 0;
}
END_TEST

START_TEST(test_ac_offset_mode_matches_above_uint32)
{
#if SIZE_MAX > UINT32_MAX
    struct cli_matcher *root = ctx.engine->root[0];
    struct cli_ac_data mdata;
    struct cli_ac_result *results = NULL;
    cl_error_t ret;

    ck_assert_ptr_nonnull(root);
    root->ac_only = 1;

#ifdef USE_MPOOL
    root->mempool = mpool_create();
#endif
    ck_assert_int_eq(cli_ac_init(root, CLI_DEFAULT_AC_MINDEPTH, CLI_DEFAULT_AC_MAXDEPTH, 1), CL_SUCCESS);
    ck_assert_int_eq(cli_add_content_match_pattern(root, "AC_Large_Offset",
                                                   "deadbeef", 0, 0, 0,
                                                   "5000000000", NULL, 0),
                     CL_SUCCESS);
    ck_assert_int_eq(cli_ac_buildtrie(root), CL_SUCCESS);
    ck_assert_int_eq(cli_ac_initdata(&mdata, root->ac_partsigs, 0, 0,
                                     CLI_DEFAULT_AC_TRACKLEN),
                     CL_SUCCESS);

    ret = cli_ac_scanbuff((const unsigned char *)"\xde\xad\xbe\xef", 4,
                          NULL, NULL, &results, root, &mdata,
                          5000000000ULL, CL_TYPE_ANY, NULL, AC_SCAN_VIR, NULL);
    ck_assert_int_eq(ret, CL_CLEAN);
    ck_assert_ptr_nonnull(results);
    ck_assert_str_eq(results->virname, "AC_Large_Offset.UNOFFICIAL");
    ck_assert_uint_eq((uint64_t)results->offset, 5000000000ULL);

    free(results);
    cli_ac_freedata(&mdata);
#else
    ck_assert(1);
#endif
}
END_TEST

START_TEST(test_pcre_full_map_range_arithmetic)
{
    ck_assert(cli_matcher_window_reaches_map_end(31, 1, 32));
    ck_assert(cli_matcher_window_reaches_map_end(32, 0, 32));
    ck_assert(cli_matcher_window_reaches_map_end(UINT64_MAX, UINT32_MAX, 32));
    ck_assert(!cli_matcher_window_reaches_map_end(0, 31, 32));
    ck_assert(cli_matcher_window_reaches_map_end(1, 31, 32));
}
END_TEST

START_TEST(test_bytecode_offset_compatibility)
{
    uint64_t offsets[64];
    uint32_t legacy_offsets[64];
    unsigned int i;

    for (i = 0; i < 64; i++)
        offsets[i] = CLI_OFF_NONE64;

    offsets[0] = 4294967293ULL;
    ck_assert(cli_lsig_bytecode_compatible(UINT32_MAX, offsets, legacy_offsets));
    ck_assert_uint_eq(legacy_offsets[0], 4294967293U);
    ck_assert_uint_eq(legacy_offsets[1], CLI_OFF_NONE);

    offsets[0] = 4294967294ULL;
    ck_assert(!cli_lsig_bytecode_compatible(UINT32_MAX, offsets, legacy_offsets));
    offsets[0] = 4294967295ULL;
    ck_assert(!cli_lsig_bytecode_compatible(UINT32_MAX, offsets, legacy_offsets));
    offsets[0] = CLI_OFF_NONE64;
    ck_assert(!cli_lsig_bytecode_compatible(4294967296ULL, offsets, legacy_offsets));
}
END_TEST

START_TEST(test_logical_bytecode_missing_entry_is_fail_visible)
{
    static const unsigned char bytes[] = {0x00};
    static char logic[]                  = "0";
    struct cli_ac_lsig lsig;
    struct cli_ac_lsig *lsigtable[1];
    struct cli_matcher root;
    struct cli_ac_data mdata;
    fmap_t *map;
    cl_error_t ret;

    memset(&lsig, 0, sizeof(lsig));
    memset(&root, 0, sizeof(root));
    lsig.id             = 0;
    lsig.bc_idx         = 1;
    lsig.type           = CLI_LSIG_NORMAL;
    lsig.u.logic        = logic;
    lsig.virname        = (char *)"MissingLogicalBytecode";
    lsig.tdb.subsigs    = 1;
    lsigtable[0]        = &lsig;
    root.ac_lsigs       = 1;
    root.ac_lsigtable   = lsigtable;

    ck_assert_int_eq(cli_ac_initdata(&mdata, 0, 1, 0, CLI_DEFAULT_AC_TRACKLEN), CL_SUCCESS);
    mdata.lsigcnt[0][0] = 1;
    map = cl_fmap_open_memory(bytes, sizeof(bytes));
    ck_assert_ptr_nonnull(map);
    ctx.fmap                    = map;
    ctx.recursion_stack[0].fmap = map;

    ret = cli_exp_eval(&ctx, &root, &mdata, NULL);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    ctx.fmap                    = &thefmap;
    ctx.recursion_stack[0].fmap = &thefmap;
    cl_fmap_close(map);
    cli_ac_freedata(&mdata);
}
END_TEST

START_TEST(test_logical_bytecode_v1_large_file_is_fail_visible)
{
#if SIZE_MAX > UINT32_MAX
    static char logic[] = "0";
    struct cli_ac_lsig lsig;
    struct cli_ac_lsig *lsigtable[1];
    struct cli_matcher root;
    struct cli_ac_data mdata;
    struct cli_bc *bc;
    cl_error_t ret;

    memset(&lsig, 0, sizeof(lsig));
    memset(&root, 0, sizeof(root));
    lsig.id             = 0;
    lsig.bc_idx         = 1;
    lsig.type           = CLI_LSIG_NORMAL;
    lsig.u.logic        = logic;
    lsig.virname        = (char *)"LegacyLargeLogicalBytecode";
    lsig.tdb.subsigs    = 1;
    lsigtable[0]        = &lsig;
    root.ac_lsigs       = 1;
    root.ac_lsigtable   = lsigtable;

    ck_assert_int_eq(cli_ac_initdata(&mdata, 0, 1, 0, CLI_DEFAULT_AC_TRACKLEN), CL_SUCCESS);
    mdata.lsigcnt[0][0] = 1;
    thefmap.len         = (size_t)UINT32_MAX + 1U;
    ctx.fmap             = &thefmap;
    ctx.recursion_stack[ctx.recursion_level].fmap = &thefmap;

    ctx.engine->bcs.all_bcs = calloc(1, sizeof(*ctx.engine->bcs.all_bcs));
    ck_assert_ptr_nonnull(ctx.engine->bcs.all_bcs);
    ctx.engine->bcs.count = 1;
    bc = &ctx.engine->bcs.all_bcs[0];
    bc->metadata.formatlevel = BC_FORMAT_LEVEL;

    ret = cli_exp_eval(&ctx, &root, &mdata, NULL);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason,
                     "logical signature requires a file size or offset outside the bytecode ABI");
    ck_assert(thefmap.dont_cache_flag);

    cli_ac_freedata(&mdata);
#else
    ck_assert(1);
#endif
}
END_TEST

START_TEST(test_yara_uint32_read_accepts_exact_tail)
{
    static const unsigned char bytes[] = {0x78, 0x56, 0x34, 0x12};
    uint32_t expected;
    fmap_t *map;

    memcpy(&expected, bytes, sizeof(expected));
    map = cl_fmap_open_memory(bytes, sizeof(bytes));
    ck_assert_ptr_nonnull(map);
    ck_assert_int_eq(read_uint32_t(map, 0), (int64_t)expected);
    ck_assert_int_eq(read_uint32_t(map, 1), TEST_YARA_UNDEFINED);
    cl_fmap_close(map);
}
END_TEST

#ifdef HAVE_YARA
static const void *yara_map_read_failure(fmap_t *map, size_t at, size_t len, int lock)
{
    (void)lock;
    if (at == 0 && len == sizeof(uint32_t))
        return NULL;
    if (at > map->len || len > map->len - at)
        return NULL;
    return (const uint8_t *)map->data + at;
}
#endif

START_TEST(test_yara_map_read_failure_is_fail_visible)
{
#ifdef HAVE_YARA
    static const unsigned char bytes[] = {0x78, 0x56, 0x34, 0x12};
    uint64_t offset = 0;
    uint8_t code[]  = {OP_PUSH, 0, 0, 0, 0, 0, 0, 0, 0, OP_UINT32, OP_POP, OP_HALT};
    struct cli_ac_lsig lsig;
    struct cli_ac_lsig *lsigtable[1];
    struct cli_matcher root;
    fmap_t *map;
    cl_error_t ret;

    memcpy(code + 1, &offset, sizeof(offset));
    memset(&lsig, 0, sizeof(lsig));
    memset(&root, 0, sizeof(root));
    lsig.id             = 0;
    lsig.type           = CLI_YARA_NORMAL;
    lsig.u.code_start   = code;
    lsig.virname        = (char *)"YaraMapReadFailure";
    lsigtable[0]        = &lsig;
    root.ac_lsigs       = 1;
    root.ac_lsigtable   = lsigtable;

    map = cl_fmap_open_memory(bytes, sizeof(bytes));
    ck_assert_ptr_nonnull(map);
    map->need = yara_map_read_failure;
    ctx.fmap = map;

    ret = cli_exp_eval(&ctx, &root, NULL, NULL);
    ck_assert_int_eq(ret, CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    ctx.fmap = &thefmap;
#else
    ck_assert(1);
#endif
}
END_TEST

START_TEST(test_yara_evaluation_accounts_matcher_work)
{
#ifdef HAVE_YARA
    static const unsigned char bytes[] = {0x00, 0x01, 0x02, 0x03};
    static uint8_t code[]                  = {OP_HALT};
    struct cli_ac_lsig lsig;
    struct cli_ac_lsig *lsigtable[1];
    struct cli_matcher root;
    fmap_t *map;
    cl_error_t ret;

    memset(&lsig, 0, sizeof(lsig));
    memset(&root, 0, sizeof(root));
    lsig.id             = 0;
    lsig.type           = CLI_YARA_NORMAL;
    lsig.u.code_start   = code;
    lsig.virname        = (char *)"YaraMatcherWorkTest";
    lsigtable[0]        = &lsig;
    root.ac_lsigs       = 1;
    root.ac_lsigtable   = lsigtable;

    map = cl_fmap_open_memory(bytes, sizeof(bytes));
    ck_assert_ptr_nonnull(map);
    ctx.fmap = map;

    ret = cli_exp_eval(&ctx, &root, NULL, NULL);
    ck_assert_int_eq(ret, CL_SUCCESS);
    ck_assert_uint_eq(ctx.matcher_work, sizeof(bytes));

    ctx.matcher_work = 0;
    ck_assert_int_eq(cl_engine_set_num(ctx.engine, CL_ENGINE_MAX_MATCHER_WORK, sizeof(bytes) - 1), CL_SUCCESS);
    ret = cli_exp_eval(&ctx, &root, NULL, NULL);
    ck_assert_int_eq(ret, CL_ERESOURCE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    ctx.fmap = &thefmap;
#else
    ck_assert(1);
#endif
}
END_TEST

START_TEST(test_yara_execution_honors_scan_time_limit)
{
#ifdef HAVE_YARA
    uint8_t code[27] = {OP_PUSH, 0, 0, 0, 0, 0, 0, 0, 0,
                        OP_PUSH, 0, 0, 0, 0, 0, 0, 0, 0,
                        OP_JLE, 0, 0, 0, 0, 0, 0, 0, 0};
    uint64_t target = PTR_TO_UINT64(code);
    struct cli_ac_lsig lsig;
    struct cli_ac_lsig *lsigtable[1];
    struct cli_matcher root;
    cl_error_t ret;

    memcpy(code + 19, &target, sizeof(target));
    memset(&lsig, 0, sizeof(lsig));
    memset(&root, 0, sizeof(root));
    lsig.id           = 0;
    lsig.type         = CLI_YARA_NORMAL;
    lsig.u.code_start = code;
    lsig.virname      = (char *)"YaraTimeoutTest";
    lsigtable[0]      = &lsig;
    root.ac_lsigs     = 1;
    root.ac_lsigtable = lsigtable;
    ctx.time_limit.tv_sec  = 1;
    ctx.time_limit.tv_usec = 0;

    ret = cli_exp_eval(&ctx, &root, NULL, NULL);
    ck_assert_int_eq(ret, CL_ETIMEOUT);
    ck_assert(ctx.abort_scan);
    ck_assert(ctx.scan_timed_out);
#else
    ck_assert(1);
#endif
}
END_TEST

START_TEST(test_byte_compare_overlap_dedup)
{
    struct cli_matcher root;
    struct cli_ac_data mdata;
    struct cli_ac_lsig lsig;
    struct cli_ac_lsig *lsigtable[1];
    struct cli_bcomp_meta bcomp;
    struct cli_bcomp_meta *bcomptable[1];
    struct cli_bcomp_comp comparison;
    struct cli_bcomp_comp *comparisons[1];
    unsigned char first_window[16]  = {0};
    unsigned char second_window[16] = {0};

    memset(&root, 0, sizeof(root));
    memset(&lsig, 0, sizeof(lsig));
    memset(&bcomp, 0, sizeof(bcomp));
    memset(&comparison, 0, sizeof(comparison));

    lsig.tdb.subsigs = 2;
    lsigtable[0]     = &lsig;
    root.ac_lsigs      = 1;
    root.ac_lsigtable  = lsigtable;

    comparison.comp_symbol = '=';
    comparison.comp_value  = 42;
    comparisons[0]         = &comparison;

    bcomp.ref_subsigid = 0;
    bcomp.lsigid[0]    = 1;
    bcomp.lsigid[1]    = 0;
    bcomp.lsigid[2]    = 1;
    bcomp.offset       = 4;
    bcomp.options      = CLI_BCOMP_BIN | CLI_BCOMP_BE;
    bcomp.byte_len     = 1;
    bcomp.comps        = comparisons;
    bcomp.comp_count   = 1;
    bcomptable[0]      = &bcomp;
    root.bcomp_metas     = 1;
    root.bcomp_metatable = bcomptable;

    ck_assert_int_eq(cli_ac_initdata(&mdata, 1, 1, 0, CLI_DEFAULT_AC_TRACKLEN), CL_SUCCESS);
    mdata.lsigcnt[0][0]          = 1;
    mdata.lsigsuboff_first[0][0] = 100;
    mdata.lsigsuboff_last[0][0]  = 100;

    /* Absolute target 104 occurs in both overlapping windows. */
    first_window[8]  = 42;
    second_window[2] = 42;
    ck_assert_int_eq(cli_bcomp_scanbuf(first_window, sizeof(first_window), 96, NULL, &root, &mdata, &ctx), CL_SUCCESS);
    ck_assert_uint_eq(mdata.lsigcnt[0][1], 1);
    ck_assert_int_eq(cli_bcomp_scanbuf(second_window, sizeof(second_window), 102, NULL, &root, &mdata, &ctx), CL_SUCCESS);
    ck_assert_uint_eq(mdata.lsigcnt[0][1], 1);
    ck_assert_uint_eq(mdata.lsigsuboff_last[0][1], 104);

    cli_ac_freedata(&mdata);
}
END_TEST

START_TEST(test_byte_compare_offset_above_uint32)
{
#if SIZE_MAX > UINT32_MAX
    const uint64_t reference_offset = 5000000000ULL;
    struct cli_matcher root;
    struct cli_ac_data mdata;
    struct cli_ac_lsig lsig;
    struct cli_ac_lsig *lsigtable[1];
    struct cli_bcomp_meta bcomp;
    struct cli_bcomp_meta *bcomptable[1];
    struct cli_bcomp_comp comparison;
    struct cli_bcomp_comp *comparisons[1];
    unsigned char window[16] = {0};

    memset(&root, 0, sizeof(root));
    memset(&lsig, 0, sizeof(lsig));
    memset(&bcomp, 0, sizeof(bcomp));
    memset(&comparison, 0, sizeof(comparison));

    lsig.tdb.subsigs = 2;
    lsigtable[0]      = &lsig;
    root.ac_lsigs     = 1;
    root.ac_lsigtable = lsigtable;

    comparison.comp_symbol = '=';
    comparison.comp_value  = 42;
    comparisons[0]         = &comparison;

    bcomp.ref_subsigid = 0;
    bcomp.lsigid[0]    = 1;
    bcomp.lsigid[1]    = 0;
    bcomp.lsigid[2]    = 1;
    bcomp.offset       = 4;
    bcomp.options      = CLI_BCOMP_BIN | CLI_BCOMP_BE;
    bcomp.byte_len     = 1;
    bcomp.comps        = comparisons;
    bcomp.comp_count   = 1;
    bcomptable[0]      = &bcomp;
    root.bcomp_metas     = 1;
    root.bcomp_metatable = bcomptable;

    ck_assert_int_eq(cli_ac_initdata(&mdata, 1, 1, 0, CLI_DEFAULT_AC_TRACKLEN), CL_SUCCESS);
    mdata.lsigcnt[0][0]          = 1;
    mdata.lsigsuboff_first[0][0] = reference_offset;
    mdata.lsigsuboff_last[0][0]  = reference_offset;

    window[4] = 42;
    ck_assert_int_eq(cli_bcomp_scanbuf(window, sizeof(window), reference_offset,
                                       NULL, &root, &mdata, &ctx),
                     CL_SUCCESS);
    ck_assert_uint_eq(mdata.lsigcnt[0][1], 1);
    ck_assert_uint_eq(mdata.lsigsuboff_last[0][1], reference_offset + 4);

    cli_ac_freedata(&mdata);
#else
    ck_assert(1);
#endif
}
END_TEST

START_TEST(test_exact_hash_at_uint32_max)
{
    uint8_t first[16]  = {0};
    uint8_t second[16] = {0};
    const char *matched = NULL;
    char *first_name;
    char *second_name;

    second[0] = 1;
    first_name  = MPOOL_CALLOC(ctx.engine->mempool, strlen("HashBoundaryFirst") + 1, 1);
    second_name = MPOOL_CALLOC(ctx.engine->mempool, strlen("HashBoundarySecond") + 1, 1);
    ck_assert_ptr_nonnull(first_name);
    ck_assert_ptr_nonnull(second_name);
    memcpy(first_name, "HashBoundaryFirst", strlen("HashBoundaryFirst"));
    memcpy(second_name, "HashBoundarySecond", strlen("HashBoundarySecond"));
    ck_assert_int_eq(hm_addhash_bin((struct cl_engine *)ctx.engine, HASH_PURPOSE_WHOLE_FILE_DETECT, second, CLI_HASH_MD5, UINT32_MAX, second_name), CL_SUCCESS);
    ck_assert_int_eq(hm_addhash_bin((struct cl_engine *)ctx.engine, HASH_PURPOSE_WHOLE_FILE_DETECT, first, CLI_HASH_MD5, UINT32_MAX, first_name), CL_SUCCESS);
    hm_flush(ctx.engine->hm_hdb);

    ck_assert(cli_hm_have_size(ctx.engine->hm_hdb, CLI_HASH_MD5, UINT32_MAX));
    ck_assert_int_eq(cli_hm_scan(first, UINT32_MAX, &matched, ctx.engine->hm_hdb, CLI_HASH_MD5), CL_VIRUS);
    ck_assert_str_eq(matched, "HashBoundaryFirst");
    matched = NULL;
    ck_assert_int_eq(cli_hm_scan(second, UINT32_MAX, &matched, ctx.engine->hm_hdb, CLI_HASH_MD5), CL_VIRUS);
    ck_assert_str_eq(matched, "HashBoundarySecond");
}
END_TEST

START_TEST(test_exact_hash_at_large_size)
{
#if SIZE_MAX > UINT32_MAX
    static const hash_purpose_t purposes[] = {
        HASH_PURPOSE_WHOLE_FILE_DETECT,
        HASH_PURPOSE_PE_SECTION_DETECT,
        HASH_PURPOSE_WHOLE_FILE_FP_CHECK,
        HASH_PURPOSE_PE_IMPORT_DETECT};
    static const char *labels[] = {
        "HashLargeWholeFile",
        "HashLargeSection",
        "HashLargeFalsePositive",
        "HashLargeImport"};
    struct cl_engine *engine = (struct cl_engine *)ctx.engine;
    struct cli_matcher **roots[] = {
        &engine->hm_hdb,
        &engine->hm_mdb,
        &engine->hm_fp,
        &engine->hm_imp};
    const uint64_t size = 5000000000ULL;
    uint8_t digest[MD5_HASH_SIZE] = {0};
    char *names[4];
    const char *matched = NULL;
    size_t i;

    for (i = 0; i < sizeof(labels) / sizeof(labels[0]); i++) {
        names[i] = MPOOL_CALLOC(ctx.engine->mempool, strlen(labels[i]) + 1, 1);
        ck_assert_ptr_nonnull(names[i]);
        memcpy(names[i], labels[i], strlen(labels[i]));

        digest[0] = (uint8_t)(i + 1);
        ck_assert_int_eq(hm_addhash_bin(engine, purposes[i], digest, CLI_HASH_MD5,
                                        size, names[i]),
                         CL_SUCCESS);
        ck_assert_ptr_nonnull(*roots[i]);
        hm_flush(*roots[i]);
        ck_assert(cli_hm_have_size(*roots[i], CLI_HASH_MD5, size));
        ck_assert_int_eq(cli_hm_scan(digest, size, &matched, *roots[i], CLI_HASH_MD5),
                         CL_VIRUS);
        ck_assert_str_eq(matched, labels[i]);
        matched = NULL;
    }
#else
    ck_assert(1);
#endif
}
END_TEST

START_TEST(test_fp_hash_read_failure_is_fail_visible)
{
    static const uint8_t digest[MD5_HASH_SIZE] = {0};
    cl_error_t ret;

    thefmap.len = 1;
    ck_assert_int_eq(hm_addhash_bin((struct cl_engine *)ctx.engine,
                                    HASH_PURPOSE_WHOLE_FILE_FP_CHECK,
                                    digest, CLI_HASH_MD5, thefmap.len,
                                    "FalsePositiveHashReadFailure"),
                     CL_SUCCESS);
    hm_flush(ctx.engine->hm_fp);

    ret = cli_append_virus(&ctx, "FP.Hash.Read.Failure");
    ck_assert_int_eq(ret, CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "false-positive hash could not be read");
    ck_assert(thefmap.dont_cache_flag);
}
END_TEST

START_TEST(test_trust_layers_rejects_missing_reason)
{
    json_object *metadata;
    cl_error_t ret;

    metadata = json_object_new_object();
    ck_assert_ptr_nonnull(metadata);
    options.general |= CL_SCAN_GENERAL_COLLECT_METADATA;
    ctx.recursion_stack[0].metadata_json = metadata;

    ret = cli_trust_layers(&ctx, 0, 0, NULL);
    ck_assert_int_eq(ret, CL_ENULLARG);

    ctx.this_layer_metadata_json = metadata;
    ret = cli_trust_this_layer(&ctx, NULL);
    ck_assert_int_eq(ret, CL_ENULLARG);

    ctx.recursion_stack[0].metadata_json = NULL;
    ctx.this_layer_metadata_json = NULL;
    options.general &= ~CL_SCAN_GENERAL_COLLECT_METADATA;
    json_object_put(metadata);
}
END_TEST

#ifndef _WIN32
#define MATCHER_TEST_FM_MASK_PAGED 0x40000000U

struct matcher_failing_pread_state {
    size_t length;
    size_t fail_at;
    unsigned int reads;
};

static off_t matcher_failing_pread(void *handle, void *buf, size_t count, off_t offset)
{
    struct matcher_failing_pread_state *state = handle;

    state->reads++;
    if (offset < 0 || (uint64_t)offset >= state->fail_at) {
        errno = EIO;
        return -1;
    }
    if (count > state->fail_at - (size_t)offset)
        count = state->fail_at - (size_t)offset;
    if (count > state->length - (size_t)offset)
        count = state->length - (size_t)offset;
    memset(buf, 0x5a, count);
    return (off_t)count;
}

START_TEST(test_scan_fmap_pread_failure_is_incomplete)
{
    struct matcher_failing_pread_state state;
    fmap_t *map;
    cl_error_t ret;

    memset(&state, 0, sizeof(state));
    state.length  = (size_t)SCANBUFF + 1;
    state.fail_at = (size_t)SCANBUFF;
    map = cl_fmap_open_handle(&state, 0, state.length, matcher_failing_pread, 0);
    ck_assert_ptr_nonnull(map);

    ctx.fmap                                             = map;
    ctx.recursion_stack[ctx.recursion_level].fmap        = map;
    ret = cli_scan_fmap(&ctx, CL_TYPE_ANY, false, NULL, AC_SCAN_VIR, NULL);
    ck_assert_int_eq(ret, CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);
    ck_assert_msg(state.reads >= 2, "synthetic pread failure was not reached");
    ck_assert_msg(!(map->bitmap[(size_t)SCANBUFF / map->pgsz] & MATCHER_TEST_FM_MASK_PAGED),
                  "failed input page remained marked resident");

    ctx.fmap                                      = &thefmap;
    ctx.recursion_stack[ctx.recursion_level].fmap = &thefmap;
    cl_fmap_close(map);
}
END_TEST
#endif

static const void *matcher_pcre_full_map_read_failure(fmap_t *map, size_t at, size_t len, int lock)
{
    (void)lock;
    if ((at == 0) && (len == map->len))
        return NULL;
    if ((len == 0) || (at > map->len) || (len > map->len - at))
        return NULL;
    return (const uint8_t *)map->data + at;
}

START_TEST(test_pcre_full_map_read_failure_is_fail_visible)
{
    static const uint8_t input[SCANBUFF + 1] = {0};
    static char pcre_signature[]              = PCRE_BYPASS "/deadbeef/";
    struct cli_matcher *root = ctx.engine->root[0];
    fmap_t *map;
    cl_error_t ret;

    ck_assert_ptr_nonnull(root);
    ck_assert_int_eq(readdb_parse_ldb_subsignature(root, "PcreFullMapReadFailure",
                                                   pcre_signature, "*", NULL, 0, 0, 0, NULL),
                     CL_SUCCESS);
    ck_assert_int_eq(cli_pcre_build(root, CLI_DEFAULT_PCRE_MATCH_LIMIT,
                                    CLI_DEFAULT_PCRE_RECMATCH_LIMIT, NULL),
                     CL_SUCCESS);

    map = cl_fmap_open_memory(input, sizeof(input));
    ck_assert_ptr_nonnull(map);
    map->need = matcher_pcre_full_map_read_failure;
    ctx.fmap = map;
    ctx.recursion_stack[ctx.recursion_level].fmap = map;

    ret = cli_scan_fmap(&ctx, CL_TYPE_ANY, false, NULL, AC_SCAN_VIR, NULL);
    ck_assert_int_eq(ret, CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason,
                     "PCRE subject could not be mapped completely");
    ck_assert(map->dont_cache_flag);

    ctx.fmap                                      = &thefmap;
    ctx.recursion_stack[ctx.recursion_level].fmap = &thefmap;
    cl_fmap_close(map);
}
END_TEST

START_TEST(test_scan_fmap_without_generic_root_is_safe)
{
    struct cli_matcher *generic_root = ctx.engine->root[0];
    struct cli_matcher *target_root;

    target_root = (struct cli_matcher *)MPOOL_CALLOC(ctx.engine->mempool, 1, sizeof(struct cli_matcher));
    ck_assert_ptr_nonnull(target_root);
    target_root->type                         = TARGET_PE;
    ctx.engine->root[0]                       = NULL;
    ctx.engine->root[1]                       = target_root;
    thefmap.len                               = 0;
    ctx.fmap                                   = &thefmap;
    ctx.recursion_stack[ctx.recursion_level].fmap = &thefmap;

    ck_assert_int_eq(cli_scan_fmap(&ctx, CL_TYPE_MSEXE, false, NULL, AC_SCAN_VIR, NULL), CL_SUCCESS);
    ck_assert(!ctx.scan_incomplete);

    ctx.engine->root[0] = generic_root;
}
END_TEST

START_TEST(test_pcre_matcher_limit_is_preserved_by_fmap)
{
    static char pcre_signature[] = PCRE_BYPASS "/00/";
    static const uint8_t input[2] = {0};
    struct cli_matcher *root     = ctx.engine->root[0];
    fmap_t *map;
    cl_error_t ret;

    ck_assert_ptr_nonnull(root);
    ck_assert_int_eq(readdb_parse_ldb_subsignature(root, "PcreFmapLimit",
                                                   pcre_signature, "*", NULL, 0, 0, 0, NULL),
                     CL_SUCCESS);
    ck_assert_int_eq(cli_pcre_build(root, CLI_DEFAULT_PCRE_MATCH_LIMIT,
                                    CLI_DEFAULT_PCRE_RECMATCH_LIMIT, NULL),
                     CL_SUCCESS);
    ck_assert_int_eq(cl_engine_set_num(ctx.engine, CL_ENGINE_PCRE_MAX_FILESIZE, 1), CL_SUCCESS);

    map = cl_fmap_open_memory(input, sizeof(input));
    ck_assert_ptr_nonnull(map);
    ctx.fmap                                      = map;
    ctx.recursion_stack[ctx.recursion_level].fmap = map;

    ret = cli_scan_fmap(&ctx, CL_TYPE_ANY, false, NULL, AC_SCAN_VIR, NULL);
    ck_assert_int_eq(ret, CL_EMAXSIZE);
    ck_assert(ctx.scan_incomplete);

    ctx.fmap                                      = &thefmap;
    ctx.recursion_stack[ctx.recursion_level].fmap = &thefmap;
    cl_fmap_close(map);
}
END_TEST

START_TEST(test_pcre_subject_limit_is_fail_visible)
{
    struct cl_engine *engine;
    fmap_t parent;
    fmap_t child;
    cl_error_t ret;
    int get_status;

    engine = (struct cl_engine *)ctx.engine;
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_PCRE_MAX_FILESIZE, 0), CL_SUCCESS);
    ck_assert_uint_eq((uint64_t)cl_engine_get_num(engine, CL_ENGINE_PCRE_MAX_FILESIZE, &get_status),
                      (uint64_t)CLI_MAX_PCRE_CONTIGUOUS_FILESIZE);
    ck_assert_int_eq(get_status, CL_SUCCESS);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_PCRE_MAX_FILESIZE, (long long)CLI_MAX_LARGE_FILESIZE), CL_SUCCESS);
    ck_assert_uint_eq((uint64_t)cl_engine_get_num(engine, CL_ENGINE_PCRE_MAX_FILESIZE, &get_status),
                      (uint64_t)CLI_MAX_PCRE_CONTIGUOUS_FILESIZE);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_PCRE_MAX_FILESIZE, -1), CL_EARG);

    memset(&parent, 0, sizeof(parent));
    memset(&child, 0, sizeof(child));
    ck_assert_msg(ctx.recursion_stack_size > 1, "test requires a child recursion layer");

    ctx.recursion_stack[0].fmap = &parent;
    ctx.recursion_stack[1].fmap = &child;
    ctx.recursion_level         = 1;
    ctx.fmap                    = &child;

    ret = cli_pcre_check_size_limit(&ctx, 100, 100);
    ck_assert_int_eq(ret, CL_SUCCESS);
    ck_assert(!ctx.scan_incomplete);

    ret = cli_pcre_check_size_limit(&ctx, 100, 101);
    ck_assert_int_eq(ret, CL_EMAXSIZE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(parent.dont_cache_flag);
    ck_assert(child.dont_cache_flag);
    ret = CL_SUCCESS;
    ck_assert(cli_scan_result_should_halt(&ctx, CL_SUCCESS, &ret));
    ck_assert_int_eq(ret, CL_EPARSE);

    ctx.scan_incomplete        = false;
    parent.dont_cache_flag     = false;
    child.dont_cache_flag      = false;
    ret = cli_pcre_check_size_limit(&ctx, 0, (uint64_t)CLI_MAX_PCRE_CONTIGUOUS_FILESIZE);
    ck_assert_int_eq(ret, CL_SUCCESS);
    ret = cli_pcre_check_size_limit(&ctx, 0, (uint64_t)CLI_MAX_PCRE_CONTIGUOUS_FILESIZE + 1);
    ck_assert_int_eq(ret, CL_EMAXSIZE);
    ck_assert(ctx.scan_incomplete);

    ctx.scan_incomplete        = false;
    parent.dont_cache_flag     = false;
    child.dont_cache_flag      = false;
    ret = cli_pcre_check_size_limit(&ctx, CLI_MAX_LARGE_FILESIZE, (uint64_t)CLI_MAX_PCRE_CONTIGUOUS_FILESIZE + 1);
    ck_assert_int_eq(ret, CL_EMAXSIZE);
    ck_assert(ctx.scan_incomplete);

    ctx.scan_incomplete        = false;
    parent.dont_cache_flag     = false;
    child.dont_cache_flag      = false;
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_CONTIGUOUS_SIZE, 4096), CL_SUCCESS);
    ret = cli_pcre_check_size_limit(&ctx, 0, 4096);
    ck_assert_int_eq(ret, CL_SUCCESS);
    ret = cli_pcre_check_size_limit(&ctx, 0, 4097);
    ck_assert_int_eq(ret, CL_EMAXSIZE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(parent.dont_cache_flag);
    ck_assert(child.dont_cache_flag);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_CONTIGUOUS_SIZE, 0), CL_SUCCESS);

    ctx.recursion_level         = 0;
    ctx.recursion_stack[0].fmap = &thefmap;
    ctx.recursion_stack[1].fmap = NULL;
    ctx.fmap                    = &thefmap;
}
END_TEST

Suite *test_matchers_suite(void)
{
    Suite *s = suite_create("matchers");
    TCase *tc_matchers;
    tc_matchers = tcase_create("matchers");
    suite_add_tcase(s, tc_matchers);
    tcase_add_checked_fixture(tc_matchers, setup, teardown);
    tcase_add_test(tc_matchers, test_ac_scanbuff);
    tcase_add_test(tc_matchers, test_ac_scanbuff_ex);
    tcase_add_test(tc_matchers, test_bm_scanbuff);
    tcase_add_test(tc_matchers, test_pcre_scanbuff);
    tcase_add_test(tc_matchers, test_ac_scanbuff_allscan);
    tcase_add_test(tc_matchers, test_ac_scanbuff_allscan_ex);
    tcase_add_test(tc_matchers, test_bm_scanbuff_allscan);
    tcase_add_test(tc_matchers, test_pcre_scanbuff_allscan);
    tcase_add_test(tc_matchers, test_large_file_offset_values);
    tcase_add_test(tc_matchers, test_bm_offset_mode_matches_above_uint32);
    tcase_add_test(tc_matchers, test_bm_initoff_rejects_coordinate_wrap);
    tcase_add_test(tc_matchers, test_ac_offset_mode_matches_above_uint32);
    tcase_add_test(tc_matchers, test_pcre_full_map_range_arithmetic);
    tcase_add_test(tc_matchers, test_exact_hash_at_uint32_max);
    tcase_add_test(tc_matchers, test_exact_hash_at_large_size);
    tcase_add_test(tc_matchers, test_fp_hash_read_failure_is_fail_visible);
    tcase_add_test(tc_matchers, test_trust_layers_rejects_missing_reason);
    tcase_add_test(tc_matchers, test_bytecode_offset_compatibility);
    tcase_add_test(tc_matchers, test_logical_bytecode_missing_entry_is_fail_visible);
    tcase_add_test(tc_matchers, test_logical_bytecode_v1_large_file_is_fail_visible);
    tcase_add_test(tc_matchers, test_yara_uint32_read_accepts_exact_tail);
    tcase_add_test(tc_matchers, test_yara_map_read_failure_is_fail_visible);
    tcase_add_test(tc_matchers, test_yara_evaluation_accounts_matcher_work);
    tcase_add_test(tc_matchers, test_yara_execution_honors_scan_time_limit);
    tcase_add_test(tc_matchers, test_byte_compare_overlap_dedup);
    tcase_add_test(tc_matchers, test_byte_compare_offset_above_uint32);
#ifndef _WIN32
    tcase_add_test(tc_matchers, test_scan_fmap_pread_failure_is_incomplete);
#endif
    tcase_add_test(tc_matchers, test_pcre_full_map_read_failure_is_fail_visible);
    tcase_add_test(tc_matchers, test_scan_fmap_without_generic_root_is_safe);
    tcase_add_test(tc_matchers, test_pcre_matcher_limit_is_preserved_by_fmap);
    tcase_add_test(tc_matchers, test_pcre_subject_limit_is_fail_visible);
    return s;
}
