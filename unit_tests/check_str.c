/*
 *  Unit tests for string functions.
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

#include <stdlib.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <check.h>

// libclamav
#include "clamav.h"
#include "conv.h"
#include "others.h"
#include "str.h"
#include "entconv.h"
#include "line.h"
#include "mbox.h"
#include "message.h"
#include "jsparse/textbuf.h"

#include "checks.h"

START_TEST(test_unescape_simple)
{
    char *str = cli_unescape("");
    ck_assert_msg(str && strlen(str) == 0, "cli_unescape empty string");
    free(str);

    str = cli_unescape("1");
    ck_assert_msg(str && !strcmp(str, "1"), "cli_unescape one char");
    free(str);

    str = cli_unescape("tesT");
    ck_assert_msg(str && !strcmp(str, "tesT"), "cli_unescape simple string");
    free(str);
}
END_TEST

START_TEST(test_unescape_hex)
{
    char *str = cli_unescape("%5a");
    ck_assert_msg(str && !strcmp(str, "\x5a"), "cli_unescape hex");
    free(str);

    str = cli_unescape("%b5%8");
    ck_assert_msg(str && !strcmp(str, "\xb5%8"), "cli_unescape truncated");
    free(str);

    str = cli_unescape("%b5%");
    ck_assert_msg(str && !strcmp(str, "\xb5%"), "cli_unescape truncated/2");
    free(str);

    str = cli_unescape("%00");
    ck_assert_msg(str && !strcmp(str, "\x1"), "cli_unescape 00");
    free(str);
}
END_TEST

START_TEST(test_unescape_unicode)
{
    char *str = cli_unescape("%u05D0");
    /* unicode is converted to utf-8 representation */
    ck_assert_msg(str && !strcmp(str, "\xd7\x90"), "cli_unescape unicode aleph");
    free(str);

    str = cli_unescape("%u00a2%u007f%u0080%u07ff%u0800%ue000");
    ck_assert_msg(str && !strcmp(str, "\xc2\xa2\x7f\xc2\x80\xdf\xbf\xe0\xa0\x80\xee\x80\x80"),
                  "cli_unescape utf-8 test");
    free(str);

    str = cli_unescape("%%u123%u12%u1%u%u1234");
    ck_assert_msg(str && !strcmp(str, "%%u123%u12%u1%u\xe1\x88\xb4"),
                  "cli_unescape unicode truncated");

    free(str);
}
END_TEST

static struct text_buffer buf;

static void buf_setup(void)
{
    memset(&buf, 0, sizeof(buf));
}

static void buf_teardown(void)
{
    if (buf.data)
        free(buf.data);
    memset(&buf, 0, sizeof(buf));
}

START_TEST(test_append_len)
{
    ck_assert_msg(textbuffer_append_len(&buf, "test", 3) != -1, "tbuf append");
    ck_assert_msg(buf.data && !strncmp(buf.data, "tes", 3), "textbuffer_append_len");
    errmsg_expected();
    ck_assert_msg(textbuffer_append_len(&buf, "TEST", 4) != -1, "tbuf append");
    ck_assert_msg(buf.data && !strncmp(buf.data, "tesTEST", 4), "textbuffer_append_len");
}
END_TEST

START_TEST(test_append)
{
    ck_assert_msg(textbuffer_append(&buf, "test") != -1, "tbuf append");
    ck_assert_msg(textbuffer_putc(&buf, '\0') != -1, "tbuf putc");
    ck_assert_msg(buf.data && !strcmp(buf.data, "test"), "textbuffer_append");
}
END_TEST

START_TEST(test_putc)
{
    ck_assert_msg(textbuffer_putc(&buf, '\x5a') != -1, "tbuf putc");
    ck_assert_msg(buf.data && buf.data[0] == '\x5a', "textbuffer_putc");
}
END_TEST

START_TEST(test_textbuffer_rejects_size_overflow)
{
    buf.pos      = (size_t)-1;
    buf.capacity = (size_t)-1;

    ck_assert_int_eq(textbuffer_ensure_capacity(&buf, 1), -1);
    ck_assert_ptr_null(buf.data);
}
END_TEST

START_TEST(test_normalize)
{
    const char *str      = "test\\0\\b\\t\\n\\v\\f\\r\\z\\x2a\\u1234test";
    const char *expected = "test\x1\b\t\n\v\f\rz\x2a\xe1\x88\xb4test";
    int rc;

    rc = cli_textbuffer_append_normalize(&buf, str, strlen(str));
    ck_assert_msg(rc != -1, "normalize");

    ck_assert_msg(textbuffer_putc(&buf, '\0') != -1, "putc \\0");
    ck_assert_msg(buf.data && !strcmp(buf.data, expected), "normalized text");
}
END_TEST

START_TEST(hex2str)
{
    char *r;
    const char inp1[] = "a00026";
    const char out1[] = "\xa0\x00\x26";
    const char inp2[] = "ag0026";

    r = cli_hex2str(inp1);
    ck_assert_msg(!!r, "cli_hex2str NULL");
    ck_assert_msg(!memcmp(r, out1, sizeof(out1) - 1),
                  "cli_hex2str invalid output");
    free(r);

    r = cli_hex2str(inp2);
    ck_assert_msg(!r, "cli_hex2str on invalid input");
}
END_TEST

START_TEST(test_str2hex_rejects_output_size_wrap)
{
    static const char input[] = "ClamAV";
    char *hex;
    size_t native_wrap_len = (size_t)(UINT_MAX / 2U) + 1U;

    hex = cli_str2hex(input, sizeof(input) - 1);
    ck_assert_ptr_nonnull(hex);
    ck_assert_str_eq(hex, "436c616d4156");
    free(hex);

    /* The old unsigned-int product allocated one byte for this length. */
    ck_assert_ptr_null(cli_str2hex(input, (unsigned int)native_wrap_len));
    ck_assert_ptr_null(cli_str2hex(input, UINT_MAX));
}
END_TEST

START_TEST(test_base64_decode_rejects_length_overflow)
{
    static char valid[] = "Zg==";
    static char input[] = "A";
    unsigned char *decoded;
    size_t decoded_len = 0;

    decoded = (unsigned char *)cl_base64_decode(valid, sizeof(valid) - 1, NULL, &decoded_len, 1);
    ck_assert_ptr_nonnull(decoded);
    ck_assert_uint_eq(decoded_len, 1);
    ck_assert_int_eq(decoded[0], 'f');
    free(decoded);

    /* These lengths must be rejected before the decoder inspects input. */
    ck_assert_ptr_null(cl_base64_decode(input, (size_t)-1, NULL, &decoded_len, 0));
    ck_assert_ptr_null(cl_base64_decode(input, (size_t)CLI_MAX_ALLOCATION + 1U, NULL, &decoded_len, 0));
    ck_assert_ptr_null(cl_base64_decode(NULL, 1, NULL, &decoded_len, 0));
    ck_assert_ptr_null(cl_base64_encode(NULL, 1));
}
END_TEST

static struct base64lines {
    const char *line;
    const char *decoded;
    unsigned int len;
} base64tests[] = {
    {"", "", 0},
    {"Zg==", "f", 1},
    {"Zm8=", "fo", 2},
    {"Zm9v", "foo", 3},
    {"Zm9vYg==", "foob", 4},
    {"Zm9vYmFy", "foobar", 6},
    /* with missing padding */
    {"Zg", "f", 1},
    {"Zm8", "fo", 2},
    {"Zm9vYg", "foob", 4}};

START_TEST(test_base64)
{
    unsigned char *ret, *ret2;
    unsigned len;
    unsigned char buf[1024];
    const struct base64lines *test = &base64tests[_i];
    message *m                     = messageCreate();
    ck_assert_msg(!!m, "Unable to create message");

    ret = decodeLine(m, BASE64, test->line, buf, sizeof(buf));
    ck_assert_msg(!!ret, "unable to decode line");

    ret2 = base64Flush(m, ret);

    if (!ret2)
        ret2 = ret;
    *ret2 = '\0';
    len   = ret2 - buf;
    ck_assert_msg(len == test->len, "invalid base64 decoded length: %u expected %u (%s)\n",
                  len, test->len, buf);
    ck_assert_msg(!memcmp(buf, test->decoded, test->len),
                  "invalid base64 decoded data: %s, expected:%s\n",
                  buf, test->decoded);
    messageDestroy(m);
}
END_TEST

START_TEST(test_message_addline_materialization_limit_is_fail_visible)
{
    cli_ctx ctx;
    message *m = messageCreate();
    line_t *line = lineCreate("x");

    memset(&ctx, 0, sizeof(ctx));
    ck_assert_ptr_nonnull(m);
    ck_assert_ptr_nonnull(line);
    m->ctx = &ctx;
    m->materialized_bytes = MESSAGE_MAX_MATERIALIZED_BYTES;
    ck_assert_int_eq(messageAddLine(m, line), -1);
    ck_assert_int_eq(m->isTruncated, 1);
    ck_assert(ctx.scan_incomplete);
    ck_assert_uint_eq(m->materialized_bytes, MESSAGE_MAX_MATERIALIZED_BYTES);
    lineUnlink(line);
    messageDestroy(m);
}
END_TEST

START_TEST(test_message_addstr_materialization_limit_is_fail_visible)
{
    cli_ctx ctx;
    message *m = messageCreate();

    memset(&ctx, 0, sizeof(ctx));
    ck_assert_ptr_nonnull(m);
    m->ctx = &ctx;
    m->materialized_bytes = MESSAGE_MAX_MATERIALIZED_BYTES;
    ck_assert_int_eq(messageAddStr(m, "x"), -1);
    ck_assert_int_eq(m->isTruncated, 1);
    ck_assert(ctx.scan_incomplete);
    ck_assert_uint_eq(m->materialized_bytes, MESSAGE_MAX_MATERIALIZED_BYTES);
    messageDestroy(m);
}
END_TEST

START_TEST(test_message_move_text_preserves_materialization_limit)
{
    message *source = messageCreate();
    message *destination = messageCreate();
    text *body;
    const size_t expected_bytes = strlen("body") + 1 + sizeof(text) + sizeof(line_t);

    ck_assert_ptr_nonnull(source);
    ck_assert_ptr_nonnull(destination);
    ck_assert_int_eq(messageAddStr(source, "body"), 1);
    ck_assert_uint_eq(source->materialized_bytes, expected_bytes);
    body = messageGetBody(source);
    ck_assert_ptr_nonnull(body);
    ck_assert_int_eq(messageMoveText(destination, body, source), 0);
    ck_assert_uint_eq(destination->materialized_bytes, expected_bytes);
    ck_assert_uint_eq(source->materialized_bytes, 0);
    messageDestroy(destination);
    messageDestroy(source);
}
END_TEST

START_TEST(test_message_addstr_deduplicated_blank_does_not_charge)
{
    message *m = messageCreate();
    size_t materialized_bytes;

    ck_assert_ptr_nonnull(m);
    ck_assert_int_eq(messageAddStr(m, NULL), 1);
    materialized_bytes = m->materialized_bytes;
    ck_assert_int_eq(messageAddStr(m, NULL), 1);
    ck_assert_uint_eq(m->materialized_bytes, materialized_bytes);
    messageDestroy(m);
}
END_TEST

START_TEST(test_message_export_rejects_truncated_materialization)
{
    message *m = messageCreate();
    blob *b;

    ck_assert_ptr_nonnull(m);
    ck_assert_int_eq(messageAddStr(m, "body"), 1);
    m->isTruncated = 1;
    b = messageToBlob(m, 0);
    ck_assert_ptr_null(b);
    messageDestroy(m);
}
END_TEST

START_TEST(test_message_table_size_rejects_product_wrap)
{
    size_t bytes;
    message *m;

    ck_assert_int_eq(cli_message_table_size(0, sizeof(char *), &bytes), CL_SUCCESS);
    ck_assert_uint_eq(bytes, 0);
    ck_assert_int_eq(cli_message_table_size(CLI_MAX_ALLOCATION / sizeof(char *),
                                            sizeof(char *), &bytes),
                     CL_SUCCESS);
    ck_assert_uint_eq(bytes, CLI_MAX_ALLOCATION);
    ck_assert_int_eq(cli_message_table_size(CLI_MAX_ALLOCATION / sizeof(char *) + 1,
                                            sizeof(char *), &bytes),
                     CL_ERESOURCE);
    ck_assert_int_eq(cli_message_table_size(SIZE_MAX, sizeof(char *), &bytes), CL_ERESOURCE);
    ck_assert_int_eq(cli_message_table_size(1, 0, &bytes), CL_EARG);
    ck_assert_int_eq(cli_message_table_size(1, sizeof(char *), NULL), CL_EARG);

    m = messageCreate();
    ck_assert_ptr_nonnull(m);
    messageAddArgument(m, "name=file");
    ck_assert_uint_eq(m->numberOfArguments, 1);
    messageSetEncoding(m, "base64");
    ck_assert_int_eq(m->numberOfEncTypes, 1);
    messageDestroy(m);
}
END_TEST

START_TEST(test_message_header_admission_failures_are_fail_visible)
{
    cli_ctx ctx;
    message *m;

    memset(&ctx, 0, sizeof(ctx));
    m = messageCreate();
    ck_assert_ptr_nonnull(m);
    messageSetCTX(m, &ctx);

    /* Exercise the saturated pointer-table admission without allocating a
     * SIZE_MAX-sized table. A failed header argument must taint the message
     * and preserve the first incomplete reason for the outer scan. */
    m->numberOfArguments = SIZE_MAX;
    messageAddArgument(m, "name=file");
    ck_assert(m->isTruncated);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason,
                     "MIME argument table exceeded its native representation");
    messageDestroy(m);

    memset(&ctx, 0, sizeof(ctx));
    m = messageCreate();
    ck_assert_ptr_nonnull(m);
    messageSetCTX(m, &ctx);

    /* The encoding table has the same bounded-admission contract. */
    m->numberOfEncTypes = INT_MAX;
    messageSetEncoding(m, "base64");
    ck_assert(m->isTruncated);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason,
                     "MIME encoding table count is saturated");
    messageDestroy(m);
}
END_TEST

START_TEST(test_iconv_cache_table_size_rejects_product_wrap)
{
    size_t bytes;

    ck_assert_int_eq(cli_iconv_cache_table_size(0, sizeof(void *), &bytes), CL_SUCCESS);
    ck_assert_uint_eq(bytes, 0);
    ck_assert_int_eq(cli_iconv_cache_table_size(CLI_MAX_ALLOCATION / sizeof(void *),
                                                sizeof(void *), &bytes),
                     CL_SUCCESS);
    ck_assert_uint_eq(bytes, CLI_MAX_ALLOCATION);
    ck_assert_int_eq(cli_iconv_cache_table_size(CLI_MAX_ALLOCATION / sizeof(void *) + 1,
                                                sizeof(void *), &bytes),
                     CL_ERESOURCE);
    ck_assert_int_eq(cli_iconv_cache_table_size(SIZE_MAX, sizeof(void *), &bytes), CL_ERESOURCE);
    ck_assert_int_eq(cli_iconv_cache_table_size(1, 0, &bytes), CL_EARG);
    ck_assert_int_eq(cli_iconv_cache_table_size(1, sizeof(void *), NULL), CL_EARG);
}
END_TEST

static struct {
    const char *u16;
    const char *u8;
} u16_tests[] = {
    {"\x74\x00\x65\x00\x73\x00\x74\x00\x00\x00", "test"},
    {"\xff\xfe\x00", ""},
    {"\x80\x00\x00", "\xc2\x80"},
    {"\xff\x07\x00", "\xdf\xbf"},
    {"\x00\x08\x00", "\xe0\xa0\x80"},
    {"\xff\x0f\x00", "\xe0\xbf\xbf"},
    {"\x00\x10\x00", "\xe1\x80\x80"},
    {"\xff\xcf\x00", "\xec\xbf\xbf"},
    {"\x00\xd0\x00", "\xed\x80\x80"},
    {"\xff\xd7\x00", "\xed\x9f\xbf"},
    {"\x00\xe0\x00", "\xee\x80\x80"},
    {"\xff\xff\x00", "\xef\xbf\xbf"},
    {"\x00\xd8\x00\xdc\x00", "\xf0\x90\x80\x80"},
    {"\xbf\xd8\xff\xdf\x00", "\xf0\xbf\xbf\xbf"},
    {"\xc0\xd8\x00\xdc\x00", "\xf1\x80\x80\x80"},
    {"\xbf\xdb\xff\xdf\x00", "\xf3\xbf\xbf\xbf"},
    {"\xc0\xdb\x00\xdc\x00", "\xf4\x80\x80\x80"},
    {"\xff\xdb\xff\xdf\x00", "\xf4\x8f\xbf\xbf"},
    {"\x00\xdc\x00\xd8\x00", "\xef\xbf\xbd\xef\xbf\xbd"}};

static unsigned u16_len(const char *s)
{
    unsigned i;
    for (i = 0; s[i] || s[i + 1]; i += 2) {
    }
    return i;
}

START_TEST(test_u16_u8)
{
    char *result = cli_utf16_to_utf8(u16_tests[_i].u16, u16_len(u16_tests[_i].u16), E_UTF16_LE);
    ck_assert_msg(!!result, "cli_utf16_to_utf8 non-null");
    ck_assert_msg(!strcmp(result, u16_tests[_i].u8), "utf16_to_8 %d failed, expected: %s, got %s", _i, u16_tests[_i].u8, result);
    free(result);
}
END_TEST

START_TEST(test_utf16_to_utf8_rejects_length_overflow)
{
    /* This length makes length * 3 wrap to a tiny value on unsigned native
     * arithmetic. The converter must reject it before reading the pointer. */
    const size_t overflowing_length = SIZE_MAX / 3 + 1;
    const size_t over_allocation_length =
        (((size_t)CLI_MAX_ALLOCATION - 2) / 3 + 1) * 2;

    ck_assert_ptr_null(cli_utf16_to_utf8((const char *)(uintptr_t)1,
                                         overflowing_length, E_UTF16_LE));
    ck_assert_ptr_null(cli_utf16_to_utf8((const char *)(uintptr_t)1,
                                         over_allocation_length, E_UTF16_LE));
}
END_TEST

START_TEST(test_utf16_helpers_reject_invalid_empty_boundaries)
{
    unsigned char output = 0;

    ck_assert_ptr_null(u16_normalize_tobuffer('A', NULL, 0));
    ck_assert_ptr_null(u16_normalize_tobuffer('A', &output, 0));
    ck_assert_ptr_null(cli_utf16toascii(NULL, 2));
    ck_assert_ptr_null(cli_utf16_to_utf8(NULL, 1, E_UTF16_LE));
    ck_assert_ptr_null(cli_utf16_to_utf8(NULL, 2, E_UTF16_LE));
}
END_TEST

Suite *test_str_suite(void)
{
    Suite *s = suite_create("str");
    TCase *tc_cli_unescape, *tc_tbuf, *tc_str, *tc_decodeline;

    tc_cli_unescape = tcase_create("cli_unescape");
    suite_add_tcase(s, tc_cli_unescape);
    tcase_add_test(tc_cli_unescape, test_unescape_simple);
    tcase_add_test(tc_cli_unescape, test_unescape_unicode);
    tcase_add_test(tc_cli_unescape, test_unescape_hex);

    tc_tbuf = tcase_create("jsnorm textbuf functions");
    suite_add_tcase(s, tc_tbuf);
    tcase_add_checked_fixture(tc_tbuf, buf_setup, buf_teardown);
    tcase_add_test(tc_tbuf, test_append_len);
    tcase_add_test(tc_tbuf, test_append);
    tcase_add_test(tc_tbuf, test_putc);
    tcase_add_test(tc_tbuf, test_textbuffer_rejects_size_overflow);
    tcase_add_test(tc_tbuf, test_normalize);

    tc_str = tcase_create("str functions");
    suite_add_tcase(s, tc_str);
    tcase_add_test(tc_str, hex2str);
    tcase_add_test(tc_str, test_str2hex_rejects_output_size_wrap);
    tcase_add_test(tc_str, test_base64_decode_rejects_length_overflow);
    tcase_add_test(tc_str, test_utf16_to_utf8_rejects_length_overflow);
    tcase_add_test(tc_str, test_utf16_helpers_reject_invalid_empty_boundaries);

    tcase_add_loop_test(tc_str, test_u16_u8, 0, sizeof(u16_tests) / sizeof(u16_tests[0]));

    tc_decodeline = tcase_create("decodeline");
    suite_add_tcase(s, tc_decodeline);

    tcase_add_loop_test(tc_decodeline, test_base64, 0, sizeof(base64tests) / sizeof(base64tests[0]));
    tcase_add_test(tc_str, test_message_addline_materialization_limit_is_fail_visible);
    tcase_add_test(tc_str, test_message_addstr_materialization_limit_is_fail_visible);
    tcase_add_test(tc_str, test_message_move_text_preserves_materialization_limit);
    tcase_add_test(tc_str, test_message_addstr_deduplicated_blank_does_not_charge);
    tcase_add_test(tc_str, test_message_export_rejects_truncated_materialization);
    tcase_add_test(tc_str, test_message_table_size_rejects_product_wrap);
    tcase_add_test(tc_str, test_message_header_admission_failures_are_fail_visible);
    tcase_add_test(tc_str, test_iconv_cache_table_size_rejects_product_wrap);

    return s;
}
