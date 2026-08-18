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

#include "checks.h"

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
    tcase_add_test(tc_matchers, test_exact_hash_at_uint32_max);
    tcase_add_test(tc_matchers, test_bytecode_offset_compatibility);
    tcase_add_test(tc_matchers, test_byte_compare_overlap_dedup);
#ifndef _WIN32
    tcase_add_test(tc_matchers, test_scan_fmap_pread_failure_is_incomplete);
#endif
    tcase_add_test(tc_matchers, test_pcre_subject_limit_is_fail_visible);
    return s;
}
