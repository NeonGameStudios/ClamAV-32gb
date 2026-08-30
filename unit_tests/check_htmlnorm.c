/*
 *  Unit tests for HTML normalizer;
 *
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2008-2013 Sourcefire, Inc.
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
#include <errno.h>
#include <limits.h>
#ifndef _WIN32
#include <sys/time.h>
#endif

#include <check.h>
#include <fcntl.h>
#include <string.h>

// libclamav
#include "clamav.h"
#include "fmap.h"
#include "dconf.h"
#include "htmlnorm.h"
#include "others.h"
#include "fmap.h"

#include "checks.h"

static char *dir;

#ifdef CLAMAV_TEST_MALLOC_WRAP
extern int htmlnorm_test_fail_next_malloc;
extern int htmlnorm_test_fail_next_realloc;
#endif

static off_t htmlnorm_failing_pread(void *handle, void *buf, size_t count, off_t offset)
{
    (void)handle;
    (void)buf;
    (void)count;
    (void)offset;
    errno = EIO;
    return -1;
}

static void htmlnorm_setup(void)
{
    cl_init(CL_INIT_DEFAULT);
    dconf_setup();
    dir = cli_gentemp(NULL);
    ck_assert_msg(!!dir, "cli_gentemp failed");
}

static void htmlnorm_teardown(void)
{
    dconf_teardown();
    /* can't call fail() functions in teardown, it can cause SEGV */
    cli_rmdirs(dir);
    free(dir);
    dir = NULL;
}

static struct test {
    const char *input;
    const char *nocommentref;
    const char *notagsref;
    const char *jsref;
} tests[] = {
    /* NULL means don't test it */
    {"input" PATHSEP "htmlnorm_scanfiles" PATHSEP "htmlnorm_buf.html",
     "input" PATHSEP "htmlnorm_reffiles" PATHSEP "buf.nocomment.ref",
     "input" PATHSEP "htmlnorm_reffiles" PATHSEP "buf.notags.ref",
     NULL},

    {"input" PATHSEP "htmlnorm_scanfiles" PATHSEP "htmlnorm_encode.html",
     "input" PATHSEP "htmlnorm_reffiles" PATHSEP "encode.nocomment.ref",
     NULL,
     "input" PATHSEP "htmlnorm_reffiles" PATHSEP "encode.js.ref"},

    {"input" PATHSEP "htmlnorm_scanfiles" PATHSEP "htmlnorm_js_test.html",
     "input" PATHSEP "htmlnorm_reffiles" PATHSEP "js.nocomment.ref",
     NULL,
     "input" PATHSEP "htmlnorm_reffiles" PATHSEP "js.js.ref"},

    {"input" PATHSEP "htmlnorm_scanfiles" PATHSEP "htmlnorm_test.html",
     "input" PATHSEP "htmlnorm_reffiles" PATHSEP "test.nocomment.ref",
     "input" PATHSEP "htmlnorm_reffiles" PATHSEP "test.notags.ref",
     NULL},

    {"input" PATHSEP "htmlnorm_scanfiles" PATHSEP "htmlnorm_urls.html",
     "input" PATHSEP "htmlnorm_reffiles" PATHSEP "urls.nocomment.ref",
     "input" PATHSEP "htmlnorm_reffiles" PATHSEP "urls.notags.ref",
     NULL}};

static void check_dir(const char *dire, const struct test *test)
{
    char filename[4096];
    int fd, reffd;

    if (test->nocommentref) {
        snprintf(filename, sizeof(filename), "%s" PATHSEP "nocomment.html", dire);
        fd = open(filename, O_RDONLY | O_BINARY);
        ck_assert_msg(fd > 0, "unable to open: %s", filename);
        reffd = open_testfile(test->nocommentref, O_RDONLY | O_BINARY);

        diff_files(fd, reffd);

        /* diff_files will close both fd's */
    }
    if (test->notagsref) {
        snprintf(filename, sizeof(filename), "%s" PATHSEP "notags.html", dire);
        fd = open(filename, O_RDONLY | O_BINARY);
        ck_assert_msg(fd > 0, "unable to open: %s", filename);
        reffd = open_testfile(test->notagsref, O_RDONLY | O_BINARY);

        diff_files(fd, reffd);

        /* diff_files will close both fd's */
    }
    if (test->jsref) {
        snprintf(filename, sizeof(filename), "%s" PATHSEP "javascript", dire);
        fd = open(filename, O_RDONLY | O_BINARY);
        ck_assert_msg(fd > 0, "unable to open: %s", filename);
        reffd = open_testfile(test->jsref, O_RDONLY | O_BINARY);

        diff_files(fd, reffd);

        /* diff_files will close both fd's */
    }
}

START_TEST(test_htmlnorm_api)
{
    int fd;
    tag_arguments_t hrefs;
    fmap_t *map;

    memset(&hrefs, 0, sizeof(hrefs));

    fd = open_testfile(tests[_i].input, O_RDONLY | O_BINARY);
    ck_assert_msg(fd > 0, "open_testfile failed");

    map = fmap_new(fd, 0, 0, tests[_i].input, NULL);
    ck_assert_msg(!!map, "fmap failed");

    ck_assert_msg(mkdir(dir, 0700) == 0, "mkdir failed: %s", dir);
    ck_assert_msg(html_normalise_map(NULL, map, dir, NULL, dconf) == 1, "html_normalise_map failed");
    check_dir(dir, &tests[_i]);
    ck_assert_msg(cli_rmdirs(dir) == 0, "rmdirs failed: %s", dir);

    ck_assert_msg(mkdir(dir, 0700) == 0, "mkdir failed: %s", dir);
    ck_assert_msg(html_normalise_map(NULL, map, dir, NULL, NULL) == 1, "html_normalise_map failed");
    ck_assert_msg(cli_rmdirs(dir) == 0, "rmdirs failed: %s", dir);

    ck_assert_msg(mkdir(dir, 0700) == 0, "mkdir failed: %s", dir);
    ck_assert_msg(html_normalise_map(NULL, map, dir, &hrefs, dconf) == 1, "html_normalise_map failed");
    ck_assert_msg(cli_rmdirs(dir) == 0, "rmdirs failed: %s", dir);
    html_tag_arg_free(&hrefs);

    memset(&hrefs, 0, sizeof(hrefs));
    hrefs.scanContents = 1;
    ck_assert_msg(mkdir(dir, 0700) == 0, "mkdir failed: %s", dir);
    ck_assert_msg(html_normalise_map(NULL, map, dir, &hrefs, dconf) == 1, "html_normalise_map failed");
    ck_assert_msg(cli_rmdirs(dir) == 0, "rmdirs failed: %s", dir);
    html_tag_arg_free(&hrefs);

    fmap_free(map);

    close(fd);
}
END_TEST

START_TEST(test_html_normalization_table_size_rejects_overflow)
{
    size_t bytes = 0;
    tag_arguments_t args;
    form_data_t form;
    char *existing_url;
    char **existing_urls;

    ck_assert_int_eq(cli_html_tag_table_size(0, sizeof(char *), &bytes), CL_SUCCESS);
    ck_assert_uint_eq(bytes, 0);
    ck_assert_int_eq(cli_html_tag_table_size(CLI_MAX_ALLOCATION / sizeof(char *) + 1,
                                             sizeof(char *), &bytes),
                     CL_ERESOURCE);
    ck_assert_int_eq(cli_html_tag_table_size(SIZE_MAX, sizeof(char *), &bytes), CL_ERESOURCE);
    ck_assert_int_eq(cli_html_tag_table_size(1, 0, &bytes), CL_EARG);
    ck_assert_int_eq(cli_html_tag_table_size(1, sizeof(char *), NULL), CL_EARG);

    memset(&args, 0, sizeof(args));
    args.count = INT_MAX;
    ck_assert(!html_tag_arg_add(&args, "href", NULL));
    ck_assert_int_eq(args.count, INT_MAX);

    memset(&args, 0, sizeof(args));
    args.count = -1;
    ck_assert(!html_tag_arg_add(&args, "href", NULL));
    ck_assert_int_eq(args.count, -1);

    memset(&form, 0, sizeof(form));
    ck_assert(html_insert_form_data("https://example.test/", &form));
    ck_assert_uint_eq(form.count, 1);
    html_form_data_tag_free(&form);

    memset(&form, 0, sizeof(form));
    form.count = SIZE_MAX;
    ck_assert(!html_insert_form_data("https://example.test/", &form));
    ck_assert_uint_eq(form.count, SIZE_MAX);

    /* A rejected growth request must not discard the already published URL
     * table. Keep the count intentionally beyond the individual allocation
     * ceiling so this exercises the preflight without allocating a large
     * table. */
    existing_url  = cli_safer_strdup("https://keep.example/");
    existing_urls = cli_max_realloc(NULL, sizeof(*existing_urls));
    ck_assert_ptr_nonnull(existing_url);
    ck_assert_ptr_nonnull(existing_urls);
    existing_urls[0] = existing_url;
    form.urls         = existing_urls;
    form.count        = CLI_MAX_ALLOCATION / sizeof(*existing_urls) + 1U;
    ck_assert(!html_insert_form_data("https://new.example/", &form));
    ck_assert_ptr_eq(form.urls, existing_urls);
    ck_assert_ptr_eq(form.urls[0], existing_url);
    ck_assert_uint_eq(form.count, CLI_MAX_ALLOCATION / sizeof(*existing_urls) + 1U);
    free(existing_url);
    free(existing_urls);
}
END_TEST

#ifdef CLAMAV_TEST_MALLOC_WRAP
START_TEST(test_html_normalization_allocation_failures_are_fail_visible)
{
    static unsigned char input[] = "<html>allocation failure</html>";
    tag_arguments_t args;
    cli_ctx ctx;

    memset(&args, 0, sizeof(args));
    ck_assert(html_tag_arg_add(&args, "href", "https://keep.example/"));
    htmlnorm_test_fail_next_realloc = 1;
    ck_assert(!html_tag_arg_add(&args, "src", "https://new.example/"));
    ck_assert_int_eq(args.count, 1);
    ck_assert_str_eq((const char *)args.tag[0], "href");
    ck_assert_str_eq((const char *)args.value[0], "https://keep.example/");
    html_tag_arg_free(&args);

    memset(&ctx, 0, sizeof(ctx));
    htmlnorm_test_fail_next_malloc = 1;
    ck_assert(!html_normalise_mem(&ctx, input, sizeof(input) - 1U, NULL, NULL, NULL));
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "HTML normalization input could not be read completely");
}
END_TEST
#endif

START_TEST(test_htmlnorm_mapped_read_failure_is_fail_visible)
{
    cli_ctx ctx;
    fmap_t *map;

    memset(&ctx, 0, sizeof(ctx));
    ck_assert_msg(mkdir(dir, 0700) == 0, "mkdir failed: %s", dir);

    map = cl_fmap_open_handle(NULL, 0, 8192, htmlnorm_failing_pread, 0);
    ck_assert_ptr_nonnull(map);
    ctx.fmap = map;

    ck_assert(!html_normalise_map(&ctx, map, dir, NULL, NULL));
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    ck_assert_msg(cli_rmdirs(dir) == 0, "rmdirs failed: %s", dir);
}
END_TEST

START_TEST(test_htmlnorm_invalid_input_is_fail_visible)
{
    cli_ctx ctx;

    memset(&ctx, 0, sizeof(ctx));

    ck_assert(!html_normalise_map(&ctx, NULL, NULL, NULL, NULL));
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "HTML normalization input map is unavailable");

    memset(&ctx, 0, sizeof(ctx));
    ck_assert(!html_normalise_mem_form_data(&ctx, NULL, 1, NULL, NULL, NULL, NULL));
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "HTML normalization input buffer is unavailable");

    memset(&ctx, 0, sizeof(ctx));
    ck_assert(!html_normalise_mem_form_data(&ctx, NULL, -1, NULL, NULL, NULL, NULL));
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "HTML normalization input buffer size is invalid");
}
END_TEST

START_TEST(test_htmlnorm_temporary_limit_is_fail_visible)
{
    static const unsigned char input[] = "<html><body>temporary quota</body></html>";
    struct cl_engine *engine;
    cli_ctx ctx;
    fmap_t *map;
    uint64_t temporary_reserved = 0;

    memset(&ctx, 0, sizeof(ctx));
    engine = cl_engine_new();
    ck_assert_ptr_nonnull(engine);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_TEMPORARY_SIZE, 1), CL_SUCCESS);

    ck_assert_msg(mkdir(dir, 0700) == 0, "mkdir failed: %s", dir);
    map = cl_fmap_open_memory(input, sizeof(input) - 1);
    ck_assert_ptr_nonnull(map);
    ctx.engine = engine;
    ctx.fmap   = map;

    ck_assert(!html_normalise_map_with_quota(&ctx, map, dir, NULL, NULL, &temporary_reserved));
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);
    ck_assert_uint_eq(temporary_reserved, 0);

    cl_fmap_close(map);
    cl_engine_free(engine);
    ck_assert_msg(cli_rmdirs(dir) == 0, "rmdirs failed: %s", dir);
}
END_TEST

#ifndef _WIN32
START_TEST(test_htmlnorm_time_limit_is_fail_visible)
{
    static const unsigned char input[] = "<html><body>timeout</body></html>";
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    ctx.engine = &engine;
    ck_assert_msg(mkdir(dir, 0700) == 0, "mkdir failed: %s", dir);

    map = cl_fmap_open_memory(input, sizeof(input) - 1U);
    ck_assert_ptr_nonnull(map);
    ctx.fmap = map;
    ck_assert_int_eq(gettimeofday(&ctx.time_limit, NULL), 0);
    ctx.time_limit.tv_sec--;

    ck_assert(!html_normalise_map(&ctx, map, dir, NULL, NULL));
    ck_assert(ctx.scan_timed_out);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason,
                     "HTML normalization reached the configured time limit");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    ck_assert_msg(cli_rmdirs(dir) == 0, "rmdirs failed: %s", dir);
}
END_TEST
#endif

START_TEST(test_screnc_nullterminate)
{
    int fd = open_testfile("input" PATHSEP "other_scanfiles" PATHSEP "screnc_test", O_RDONLY | O_BINARY);
    fmap_t *map;
    cli_ctx ctx;
    struct cl_engine *engine;
    uint64_t temporary_reserved = 0;

    engine = cl_engine_new();
    ck_assert_ptr_nonnull(engine);
    memset(&ctx, 0, sizeof(ctx));
    ctx.engine = engine;
    ck_assert_msg(mkdir(dir, 0700) == 0, "mkdir failed");
    map = fmap_new(fd, 0, 0, "screnc_test", NULL);
    ck_assert_msg(!!map, "fmap failed");
    ck_assert_msg(html_screnc_decode_ctx(&ctx, map, dir, &temporary_reserved) == 1, "html_screnc_decode failed");
    ck_assert(temporary_reserved > 0);
    cli_scan_release_temporary(&ctx, temporary_reserved);
    ck_assert_uint_eq(ctx.temporary_bytes, 0);
    fmap_free(map);
    ck_assert_msg(cli_rmdirs(dir) == 0, "rmdirs failed");
    close(fd);
    cl_engine_free(engine);
}
END_TEST

#ifndef _WIN32
START_TEST(test_screnc_time_limit_is_fail_visible)
{
    int fd = open_testfile("input" PATHSEP "other_scanfiles" PATHSEP "screnc_test", O_RDONLY | O_BINARY);
    fmap_t *map;
    cli_ctx ctx;
    struct cl_engine *engine;
    uint64_t temporary_reserved = 0;

    engine = cl_engine_new();
    ck_assert_ptr_nonnull(engine);
    memset(&ctx, 0, sizeof(ctx));
    ctx.engine = engine;
    ck_assert_msg(mkdir(dir, 0700) == 0, "mkdir failed");
    map = fmap_new(fd, 0, 0, "screnc_test", NULL);
    ck_assert_ptr_nonnull(map);
    ck_assert_int_eq(gettimeofday(&ctx.time_limit, NULL), 0);
    ctx.time_limit.tv_sec--;

    ck_assert(!html_screnc_decode_ctx(&ctx, map, dir, &temporary_reserved));
    ck_assert(ctx.scan_timed_out);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason,
                     "HTML script-encoded inspection reached the configured time limit");
    ck_assert_uint_eq(temporary_reserved, 0);
    ck_assert_uint_eq(ctx.temporary_bytes, 0);
    ck_assert(map->dont_cache_flag);

    fmap_free(map);
    ck_assert_msg(cli_rmdirs(dir) == 0, "rmdirs failed");
    close(fd);
    cl_engine_free(engine);
}
END_TEST
#endif

START_TEST(test_screnc_temporary_limit_is_fail_visible)
{
    int fd = open_testfile("input" PATHSEP "other_scanfiles" PATHSEP "screnc_test", O_RDONLY | O_BINARY);
    fmap_t *map;
    cli_ctx ctx;
    struct cl_engine *engine;
    uint64_t temporary_reserved = 0;

    engine = cl_engine_new();
    ck_assert_ptr_nonnull(engine);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_TEMPORARY_SIZE, 1), CL_SUCCESS);
    memset(&ctx, 0, sizeof(ctx));
    ctx.engine = engine;
    ck_assert_msg(mkdir(dir, 0700) == 0, "mkdir failed");
    map = fmap_new(fd, 0, 0, "screnc_test", NULL);
    ck_assert_ptr_nonnull(map);
    ck_assert(!html_screnc_decode_ctx(&ctx, map, dir, &temporary_reserved));
    ck_assert(ctx.scan_incomplete);
    ck_assert_uint_eq(temporary_reserved, 0);
    ck_assert_uint_eq(ctx.temporary_bytes, 0);
    fmap_free(map);
    ck_assert_msg(cli_rmdirs(dir) == 0, "rmdirs failed");
    close(fd);
    cl_engine_free(engine);
}
END_TEST

Suite *test_htmlnorm_suite(void)
{
    Suite *s = suite_create("htmlnorm");
    TCase *tc_htmlnorm_api;

    tc_htmlnorm_api = tcase_create("htmlnorm api");
    suite_add_tcase(s, tc_htmlnorm_api);

    tcase_add_loop_test(tc_htmlnorm_api, test_htmlnorm_api, 0, sizeof(tests) / sizeof(tests[0]));

    tcase_add_unchecked_fixture(tc_htmlnorm_api,
                                htmlnorm_setup, htmlnorm_teardown);
    tcase_add_test(tc_htmlnorm_api, test_htmlnorm_invalid_input_is_fail_visible);
    tcase_add_test(tc_htmlnorm_api, test_html_normalization_table_size_rejects_overflow);
#ifdef CLAMAV_TEST_MALLOC_WRAP
    tcase_add_test(tc_htmlnorm_api, test_html_normalization_allocation_failures_are_fail_visible);
#endif
    tcase_add_test(tc_htmlnorm_api, test_htmlnorm_mapped_read_failure_is_fail_visible);
    tcase_add_test(tc_htmlnorm_api, test_htmlnorm_temporary_limit_is_fail_visible);
#ifndef _WIN32
    tcase_add_test(tc_htmlnorm_api, test_htmlnorm_time_limit_is_fail_visible);
#endif
    tcase_add_test(tc_htmlnorm_api, test_screnc_nullterminate);
#ifndef _WIN32
    tcase_add_test(tc_htmlnorm_api, test_screnc_time_limit_is_fail_visible);
#endif
    tcase_add_test(tc_htmlnorm_api, test_screnc_temporary_limit_is_fail_visible);

    return s;
}
