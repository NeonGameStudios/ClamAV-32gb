#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <check.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <zlib.h>
#include <bzlib.h>
#ifdef NOBZ2PREFIX
#define BZ2_bzBuffToBuffCompress bzBuffToBuffCompress
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#include <libxml/parser.h>

#include "platform.h"

// libclamav
#include "clamav.h"
#include "blob.h"
#include "default.h"
#include "readdb.h"
#include "others.h"
#include "matcher.h"
#include "version.h"
#include "dsig.h"
#include "fpu.h"
#include "entconv.h"
#include "actions.h"
#include "cache.h"
#include "stats.h"
#include "stats_json.h"
#include "scanners.h"
#include "dconf.h"
#include "msxml.h"
#include "msxml_parser.h"
#include "rtf.h"
#include "swf.h"
#include "tnef.h"
#include "unzip.h"
#include "hwp.h"
#include "ole2_extract.h"
#include "vba_extract.h"
#include "pdf.h"
#include "pdfdecode.h"
#include "xdp.h"
#include "asn1.h"
#include "ishield.h"
#include "unarj.h"
#include "pe.h"
#include "pe_icons.h"
#include "spin.h"
#include "elf.h"
#include "dmg.h"
#include "egg.h"
#include "7z_iface.h"
#include "autoit.h"
#include "binhex.h"
#include "nsis/nulsft.h"
#include "apm.h"
#include "gpt.h"
#include "mbr.h"
#include "libmspack.h"
#include "macho.h"
#include "udf.h"
#include "hfsplus.h"
#include "gif.h"
#include "png.h"
#include "tiff.h"
#include "jpeg.h"
#include "mbox.h"
#include "uuencode.h"
#include "xar.h"
#include "xlm_extract.h"
#include "special.h"
#include "textnorm.h"
#include "scan_report.h"

#include "checks.h"

#ifdef CLAMAV_TEST_JS_IO_WRAP
extern int clamav_test_fail_write;
extern int clamav_test_fail_close;
#endif

static int fpu_words = FPU_ENDIAN_INITME;
#define NO_FPU_ENDIAN (fpu_words == FPU_ENDIAN_UNKNOWN)
#define EA06_SCAN strstr(file, "clam.ea06.exe")
#define FALSE_NEGATIVE (EA06_SCAN && NO_FPU_ENDIAN)
#define ZIP_TEST_METHOD_STORED 0U
#define ZIP_TEST_METHOD_DEFLATE 8U
#define ZIP_TEST_METHOD_DEFLATE64 9U
#define ZIP_TEST_METHOD_IMPLODE 6U
#define ZIP_TEST_METHOD_BZIP2 12U
#define ZIP_TEST_FLAG_ENCRYPTED 1U
#define ZIP_TEST_FLAG_DATA_DESCRIPTOR (1U << 3)
#define ZIP_TEST_FLAG_STRONG_ENCRYPTION (1U << 6)
#define ZIP_TEST_FLAG_MASKED_HEADER (1U << 13)

// Define SRCDIR and OBJDIR when not defined, for the sake of the IDE.
#ifndef SRCDIR
#define SRCDIR " should be defined by CMake "
#endif
#ifndef OBJDIR
#define OBJDIR " should be defined by CMake "
#endif

static char *tmpdir;

static void cl_setup(void)
{
    tmpdir = cli_gentemp(NULL);
    mkdir(tmpdir, 0700);
    ck_assert_msg(!!tmpdir, "cli_gentemp failed");
}

static void cl_teardown(void)
{
    /* can't call fail() functions in teardown, it can cause SEGV */
    cli_rmdirs(tmpdir);
    free(tmpdir);
    tmpdir = NULL;
}

START_TEST(test_cl_fmap_set_hash_accepts_full_hash)
{
    static const unsigned char data[] = "public fmap hash API regression";
    unsigned char hash[SHA256_HASH_SIZE];
    cl_fmap_t *map;
    bool have_hash = false;
    char *hash_string = NULL;

    memset(hash, 0xa5, sizeof(hash));
    map = cl_fmap_open_memory(data, sizeof(data) - 1U);
    ck_assert_ptr_nonnull(map);

    ck_assert_int_eq(CL_SUCCESS, cl_fmap_set_hash(map, "sha2-256", hash));
    ck_assert_int_eq(CL_SUCCESS, cl_fmap_have_hash(map, "sha2-256", &have_hash));
    ck_assert(have_hash);
    ck_assert_int_eq(CL_SUCCESS, cl_fmap_get_hash(map, "sha2-256", &hash_string));
    ck_assert_ptr_nonnull(hash_string);
    ck_assert_str_eq(hash_string,
                     "a5a5a5a5a5a5a5a5"
                     "a5a5a5a5a5a5a5a5"
                     "a5a5a5a5a5a5a5a5"
                     "a5a5a5a5a5a5a5a5");

    free(hash_string);
    cl_fmap_close(map);
}
END_TEST

START_TEST(test_cl_fmap_get_data_clamps_wrapped_length)
{
    static const unsigned char data[] = "public fmap range API regression";
    const uint8_t *view = NULL;
    size_t view_length = 0;
    cl_fmap_t *map;

    map = cl_fmap_open_memory(data, sizeof(data) - 1U);
    ck_assert_ptr_nonnull(map);
    ck_assert_int_eq(cl_fmap_get_data(map, 1, SIZE_MAX, &view, &view_length), CL_SUCCESS);
    ck_assert_ptr_nonnull(view);
    ck_assert_uint_eq(view_length, sizeof(data) - 2U);
    ck_assert_mem_eq(view, data + 1, view_length);
    cl_fmap_close(map);
}
END_TEST

/* extern void cl_free(struct cl_engine *engine); */
START_TEST(test_cl_free)
{
    // struct cl_engine *engine = NULL;
    // cl_free(NULL);
}
END_TEST

/* extern int cl_build(struct cl_engine *engine); */
START_TEST(test_cl_build)
{
    // struct cl_engine *engine;
    // ck_assert_msg(CL_ENULLARG == cl_build(NULL), "cl_build null pointer");
    // engine = calloc(sizeof(struct cl_engine),1);
    // ck_assert_msg(engine, "cl_build calloc");
    // ck_assert_msg(CL_ENULLARG == cl_build(engine), "cl_build(engine) with null ->root");

    // engine->root = calloc(CL_TARGET_TABLE_SIZE, sizeof(struct cli_matcher *));
}
END_TEST

/* extern void cl_debug(void); */
START_TEST(test_cl_debug)
{
    int old_status = cli_set_debug_flag(0);

    cl_debug();
    ck_assert_msg(1 == cli_get_debug_flag(), "cl_debug failed to set cli_debug_flag");

    (void)cli_set_debug_flag(1);

    cl_debug();
    ck_assert_msg(1 == cli_get_debug_flag(), "cl_debug failed when flag was already set");

    (void)cli_set_debug_flag(old_status);
}
END_TEST

START_TEST(test_sequential_parser_status_merge_is_fail_closed)
{
    ck_assert_int_eq(cli_merge_scan_status(CL_SUCCESS, CL_EPARSE), CL_EPARSE);
    ck_assert_int_eq(cli_merge_scan_status(CL_EPARSE, CL_SUCCESS), CL_EPARSE);
    ck_assert_int_eq(cli_merge_scan_status(CL_EFORMAT, CL_EREAD), CL_EFORMAT);
    ck_assert_int_eq(cli_merge_scan_status(CL_EFORMAT, CL_EMEM), CL_EMEM);
    ck_assert_int_eq(cli_merge_scan_status(CL_EPARSE, CL_VIRUS), CL_VIRUS);
    ck_assert_int_eq(cli_merge_scan_status(CL_VIRUS, CL_EPARSE), CL_VIRUS);
}
END_TEST

#ifndef _WIN32
/* extern const char *cl_retdbdir(void); */
START_TEST(test_cl_retdbdir)
{
    ck_assert_msg(!strcmp(DATADIR, cl_retdbdir()), "cl_retdbdir");
}
END_TEST

#endif

#ifndef REPO_VERSION
#define REPO_VERSION VERSION
#endif

/* extern const char *cl_retver(void); */
START_TEST(test_cl_retver)
{
    const char *ver = cl_retver();
    ck_assert_msg(!strcmp(REPO_VERSION "" VERSION_SUFFIX, ver), "cl_retver");
    ck_assert_msg(strcspn(ver, "012345789") < strlen(ver),
                  "cl_retver must have a number");
}
END_TEST

/* extern void cl_cvdfree(struct cl_cvd *cvd); */
START_TEST(test_cl_cvdfree)
{
    // struct cl_cvd *cvd1, *cvd2;

    // cvd1 = malloc(sizeof(struct cl_cvd));
    // ck_assert_msg(cvd1, "cvd malloc");
    // cl_cvdfree(cvd1);

    // cvd2 = malloc(sizeof(struct cl_cvd));
    // cvd2->time = malloc(1);
    // cvd2->md5 = malloc(1);
    // cvd2->dsig= malloc(1);
    // cvd2->builder = malloc(1);
    // ck_assert_msg(cvd2, "cvd malloc");
    // ck_assert_msg(cvd2->time, "cvd malloc");
    // ck_assert_msg(cvd2->md5, "cvd malloc");
    // ck_assert_msg(cvd2->dsig, "cvd malloc");
    // ck_assert_msg(cvd2->builder, "cvd malloc");
    // cl_cvdfree(cvd2);
    // cl_cvdfree(NULL);
}
END_TEST

/* extern int cl_statfree(struct cl_stat *dbstat); */
START_TEST(test_cl_statfree)
{
    // struct cl_stat *stat;
    // ck_assert_msg(CL_ENULLARG == cl_statfree(NULL), "cl_statfree(NULL)");

    // stat = malloc(sizeof(struct cl_stat));
    // ck_assert_msg(NULL != stat, "malloc");
    // ck_assert_msg(CL_SUCCESS == cl_statfree(stat), "cl_statfree(empty_struct)");

    // stat = malloc(sizeof(struct cl_stat));
    // ck_assert_msg(NULL != stat, "malloc");
    // stat->stattab = strdup("test");
    // ck_assert_msg(NULL != stat->stattab, "strdup");
    // ck_assert_msg(CL_SUCCESS == cl_statfree(stat), "cl_statfree(stat with stattab)");

    // stat = malloc(sizeof(struct cl_stat));
    // ck_assert_msg(NULL != stat, "malloc");
    // stat->stattab = NULL;
    // ck_assert_msg(CL_SUCCESS == cl_statfree(stat), "cl_statfree(stat with stattab) set to NULL");
}
END_TEST

/* extern unsigned int cl_retflevel(void); */
START_TEST(test_cl_retflevel)
{
}
END_TEST

/* extern struct cl_cvd *cl_cvdhead(const char *file); */
START_TEST(test_cl_cvdhead)
{
    // ck_assert_msg(NULL == cl_cvdhead(NULL), "cl_cvdhead(null)");
    // ck_assert_msg(NULL == cl_cvdhead("input" PATHSEP "cl_cvdhead" PATHSEP "1.txt"), "cl_cvdhead(515 byte file, all nulls)");
    /* the data read from the file is passed to cl_cvdparse, test cases for that are separate */
}
END_TEST

/* extern struct cl_cvd *cl_cvdparse(const char *head); */
START_TEST(test_cl_cvdparse)
{
}
END_TEST

static int get_test_file(int i, char *file, unsigned fsize, unsigned long *size);
static struct cl_engine *g_engine;

static cl_error_t unexpected_pre_cache_status(int fd, const char *type, void *context)
{
    (void)fd;
    (void)type;
    (void)context;
    return CL_EREAD;
}

static cl_error_t unexpected_file_inspection_status(
    int fd,
    const char *type,
    const char **ancestors,
    size_t parent_file_size,
    const char *file_name,
    size_t file_size,
    const char *file_buffer,
    uint32_t recursion_level,
    uint32_t layer_attributes,
    void *context)
{
    (void)fd;
    (void)type;
    (void)ancestors;
    (void)parent_file_size;
    (void)file_name;
    (void)file_size;
    (void)file_buffer;
    (void)recursion_level;
    (void)layer_attributes;
    (void)context;
    return CL_EREAD;
}

static cl_error_t unexpected_pre_scan_status(int fd, const char *type, void *context)
{
    (void)fd;
    (void)type;
    (void)context;
    return CL_EREAD;
}

static cl_error_t unexpected_post_scan_status(int fd, int result, const char *virname, void *context)
{
    (void)fd;
    (void)result;
    (void)virname;
    (void)context;
    return CL_EREAD;
}

enum legacy_callback_status_kind {
    LEGACY_PRE_CACHE_STATUS,
    LEGACY_FILE_INSPECTION_STATUS,
    LEGACY_PRE_SCAN_STATUS,
    LEGACY_POST_SCAN_STATUS
};

static void assert_legacy_callback_status_is_fail_visible(enum legacy_callback_status_kind kind)
{
    static const uint8_t input[] = "legacy callback status regression";
    struct cl_scan_options options;
    cl_fmap_t *map;
    cl_scan_report_t *report = NULL;
    cl_verdict_t verdict = CL_VERDICT_NOTHING_FOUND;
    const char *last_alert    = NULL;
    uint64_t scanned          = 0;
    cl_error_t report_status = CL_SUCCESS;
    cl_scan_completion_t completion;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    map = cl_fmap_open_memory(input, sizeof(input) - 1U);
    ck_assert_ptr_nonnull(map);

    switch (kind) {
        case LEGACY_PRE_CACHE_STATUS:
            cl_engine_set_clcb_pre_cache(g_engine, unexpected_pre_cache_status);
            break;
        case LEGACY_FILE_INSPECTION_STATUS:
            cl_engine_set_clcb_file_inspection(g_engine, unexpected_file_inspection_status);
            break;
        case LEGACY_PRE_SCAN_STATUS:
            cl_engine_set_clcb_pre_scan(g_engine, unexpected_pre_scan_status);
            break;
        case LEGACY_POST_SCAN_STATUS:
            cl_engine_set_clcb_post_scan(g_engine, unexpected_post_scan_status);
            break;
    }

    ret = cl_scanmap_ex2(map,
                         "legacy-callback-status",
                         &verdict,
                         &last_alert,
                         &scanned,
                         g_engine,
                         &options,
                         NULL,
                         NULL,
                         NULL,
                         NULL,
                         NULL,
                         NULL,
                         &report);

    cl_engine_set_clcb_pre_cache(g_engine, NULL);
    cl_engine_set_clcb_file_inspection(g_engine, NULL);
    cl_engine_set_clcb_pre_scan(g_engine, NULL);
    cl_engine_set_clcb_post_scan(g_engine, NULL);

    ck_assert_int_eq(ret, CL_EREAD);
    ck_assert_ptr_nonnull(report);
    ck_assert_int_eq(cl_scan_report_get_status(report, &report_status), CL_SUCCESS);
    ck_assert_int_eq(report_status, CL_EREAD);
    ck_assert_int_eq(cl_scan_report_get_completion(report, &completion), CL_SUCCESS);
    ck_assert_int_ne(completion, CL_SCAN_COMPLETION_COMPLETE);

    cl_scan_report_free(report);
    cl_fmap_close(map);
}

START_TEST(test_legacy_callback_errors_are_fail_visible)
{
    assert_legacy_callback_status_is_fail_visible(LEGACY_PRE_CACHE_STATUS);
    assert_legacy_callback_status_is_fail_visible(LEGACY_FILE_INSPECTION_STATUS);
    assert_legacy_callback_status_is_fail_visible(LEGACY_PRE_SCAN_STATUS);
    assert_legacy_callback_status_is_fail_visible(LEGACY_POST_SCAN_STATUS);
}
END_TEST

static cl_error_t unexpected_scan_callback_status(cl_scan_layer_t *layer, void *context)
{
    (void)layer;
    (void)context;
    return CL_EREAD;
}

static void assert_scan_callback_status_is_fail_visible(cl_scan_callback_t location, unsigned int suffix)
{
    uint8_t input[64];
    struct cl_scan_options options;
    cl_fmap_t *map;
    cl_scan_report_t *report = NULL;
    cl_verdict_t verdict = CL_VERDICT_NOTHING_FOUND;
    const char *last_alert    = NULL;
    uint64_t scanned          = 0;
    cl_error_t report_status = CL_SUCCESS;
    cl_scan_completion_t completion;
    cl_error_t ret;

    (void)snprintf((char *)input, sizeof(input), "modern callback status regression %u", suffix);
    memset(&options, 0, sizeof(options));
    map = cl_fmap_open_memory(input, strlen((char *)input));
    ck_assert_ptr_nonnull(map);

    cl_engine_set_scan_callback(g_engine, unexpected_scan_callback_status, location);
    ret = cl_scanmap_ex2(map,
                         "modern-callback-status",
                         &verdict,
                         &last_alert,
                         &scanned,
                         g_engine,
                         &options,
                         NULL,
                         NULL,
                         NULL,
                         NULL,
                         NULL,
                         NULL,
                         &report);
    cl_engine_set_scan_callback(g_engine, NULL, location);

    ck_assert_int_eq(ret, CL_EREAD);
    ck_assert_ptr_nonnull(report);
    ck_assert_int_eq(cl_scan_report_get_status(report, &report_status), CL_SUCCESS);
    ck_assert_int_eq(report_status, CL_EREAD);
    ck_assert_int_eq(cl_scan_report_get_completion(report, &completion), CL_SUCCESS);
    ck_assert_int_ne(completion, CL_SCAN_COMPLETION_COMPLETE);

    cl_scan_report_free(report);
    cl_fmap_close(map);
}

START_TEST(test_scan_callback_errors_are_fail_visible)
{
    assert_scan_callback_status_is_fail_visible(CL_SCAN_CALLBACK_PRE_HASH, 1);
    assert_scan_callback_status_is_fail_visible(CL_SCAN_CALLBACK_PRE_SCAN, 2);
    assert_scan_callback_status_is_fail_visible(CL_SCAN_CALLBACK_POST_SCAN, 3);
}
END_TEST

/* These historical fixtures deliberately contain malformed embedded layers.
 * With fail-closed parser propagation they are no longer allowed to look
 * clean when the embedded test signature cannot be reached. Keep complete
 * fixture virus assertions unchanged and require an explicit parse error for
 * only these known incomplete cases. */
static bool test_file_requires_fail_closed_result(const char *file)
{
    const char *name = strrchr(file, *PATHSEP);

    if (name)
        name++;
    else
        name = file;

    return (0 == strcmp(name, "clam_IScab_ext.exe") ||
            0 == strcmp(name, "clam_IScab_int.exe") ||
            0 == strcmp(name, "clam_ISmsi_int.exe") ||
            0 == strcmp(name, "clam.exe.mbox.uu") ||
            0 == strcmp(name, "clam.ole.doc") ||
            0 == strcmp(name, "clam-wwpack.exe") ||
            0 == strcmp(name, "clam.ea05.exe") ||
            0 == strcmp(name, "clam.ea06.exe"));
}

static void assert_test_file_scan_result(cl_error_t ret, const char *virname, const char *file, const char *operation)
{
    if (test_file_requires_fail_closed_result(file)) {
        ck_assert_msg(ret == CL_EPARSE || ret == CL_VIRUS,
                      "%s unexpectedly normalized an incomplete fixture for %s: %s",
                      operation, file, cl_strerror(ret));
        if (ret == CL_EPARSE) {
            ck_assert_msg(NULL == virname,
                          "%s returned a detection for parse-failed fixture %s",
                          operation, file);
        } else {
            ck_assert_msg(virname && !strcmp(virname, "ClamAV-Test-File.UNOFFICIAL"),
                          "%s virusname: %s", operation, virname ? virname : "(null)");
        }
    } else {
        ck_assert_msg(ret == CL_VIRUS, "%s failed for %s: %s", operation, file, cl_strerror(ret));
        ck_assert_msg(virname && !strcmp(virname, "ClamAV-Test-File.UNOFFICIAL"),
                      "%s virusname: %s", operation, virname ? virname : "(null)");
    }
}

/* cl_error_t cl_scandesc(int desc, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, const struct cl_limits *limits, struct cl_scan_options* options) */
START_TEST(test_cl_scandesc)
{
    const char *virname = NULL;
    char file[256];
    unsigned long size;
    unsigned long int scanned = 0;
    cl_error_t ret;
    struct cl_scan_options options;

    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0;

    int fd = get_test_file(_i, file, sizeof(file), &size);
    cli_dbgmsg("scanning (scandesc) %s\n", file);
    ret = cl_scandesc(fd, file, &virname, &scanned, g_engine, &options);
    cli_dbgmsg("scan end (scandesc) %s\n", file);

    if (!FALSE_NEGATIVE) {
        assert_test_file_scan_result(ret, virname, file, "cl_scandesc");
    }
    close(fd);
}
END_TEST

START_TEST(test_cl_scandesc_allscan)
{
    const char *virname = NULL;
    char file[256];
    unsigned long size;
    unsigned long int scanned = 0;
    int ret;
    struct cl_scan_options options;

    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0;
    options.general |= CL_SCAN_GENERAL_ALLMATCHES;

    int fd = get_test_file(_i, file, sizeof(file), &size);
    cli_dbgmsg("scanning (scandesc) %s\n", file);
    ret = cl_scandesc(fd, file, &virname, &scanned, g_engine, &options);

    cli_dbgmsg("scan end (scandesc) %s\n", file);

    if (!FALSE_NEGATIVE) {
        assert_test_file_scan_result(ret, virname, file, "cl_scandesc_allscan");
    }
    close(fd);
}
END_TEST

//* int cl_scanfile(const char *filename, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, const struct cl_limits *limits, unsigned int options) */
START_TEST(test_cl_scanfile)
{
    const char *virname = NULL;
    char file[256];
    unsigned long size;
    unsigned long int scanned = 0;
    int ret;
    struct cl_scan_options options;

    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0;

    int fd = get_test_file(_i, file, sizeof(file), &size);
    close(fd);

    cli_dbgmsg("scanning (scanfile) %s\n", file);
    ret = cl_scanfile(file, &virname, &scanned, g_engine, &options);
    cli_dbgmsg("scan end (scanfile) %s\n", file);

    if (!FALSE_NEGATIVE) {
        assert_test_file_scan_result(ret, virname, file, "cl_scanfile");
    }
}
END_TEST

START_TEST(test_cl_scanfile_allscan)
{
    const char *virname = NULL;
    char file[256];
    unsigned long size;
    unsigned long int scanned = 0;
    int ret;
    struct cl_scan_options options;

    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0;
    options.general |= CL_SCAN_GENERAL_ALLMATCHES;

    int fd = get_test_file(_i, file, sizeof(file), &size);
    close(fd);

    cli_dbgmsg("scanning (scanfile_allscan) %s\n", file);
    ret = cl_scanfile(file, &virname, &scanned, g_engine, &options);
    cli_dbgmsg("scan end (scanfile_allscan) %s\n", file);

    if (!FALSE_NEGATIVE) {
        assert_test_file_scan_result(ret, virname, file, "cl_scanfile_allscan");
    }
}
END_TEST

static char *create_materialization_limit_fixture(int unix_mbox)
{
    static const char mbox_header[] =
        "From test@example.com Thu Jan  1 00:00:00 1970\n"
        "Content-Type: text/plain\n"
        "Subject: materialization-limit-regression\n"
        "\n";
    static const char single_message_header[] =
        "Date: Thu, 01 Jan 1970 00:00:00 +0000\n"
        "Content-Type: text/plain\n"
        "Subject: materialization-limit-regression\n"
        "\n";
    char block[64000];
    char *path = NULL;
    int fd = -1;
    size_t body_bytes = 0;
    const size_t materialization_limit = 64U * 1024U * 1024U;
    const char *header = unix_mbox ? mbox_header : single_message_header;
    size_t line;

    /* Keep each generated line below RFC2821LENGTH while using block writes
     * so this remains a practical integration test rather than a syscall
     * benchmark. The body crosses the former in-memory materialization cap and
     * must now be handled by the disk-backed mail spool. */
    for (line = 0; line < sizeof(block) / 1000U; line++) {
        memset(block + line * 1000U, 'A', 999U);
        block[line * 1000U + 999U] = '\n';
    }

    ck_assert_int_eq(cli_gentempfd(tmpdir, &path, &fd), CL_SUCCESS);
    ck_assert_ptr_nonnull(path);
    ck_assert_int_eq(write(fd, header, strlen(header)), (ssize_t)strlen(header));

    while (body_bytes <= materialization_limit) {
        ck_assert_int_eq(write(fd, block, sizeof(block)), (ssize_t)sizeof(block));
        body_bytes += sizeof(block);
    }
    ck_assert_int_eq(close(fd), 0);

    return path;
}

static char *create_streaming_multipart_fixture(void)
{
    static const char header[] =
        "Date: Thu, 01 Jan 1970 00:00:00 +0000\n"
        "Content-Type: multipart/mixed; boundary=stream-part\n"
        "\n"
        "--stream-part\n"
        "Content-Type: application/octet-stream\n"
        "Content-Disposition: attachment; filename=stream.bin\n"
        "\n";
    static const char trailer[] = "\n--stream-part--\n";
    char block[64000];
    char *path = NULL;
    int fd     = -1;
    size_t i;

    memset(block, 'B', sizeof(block));
    ck_assert_int_eq(cli_gentempfd(tmpdir, &path, &fd), CL_SUCCESS);
    ck_assert_ptr_nonnull(path);
    ck_assert_int_eq(write(fd, header, sizeof(header) - 1),
                     (ssize_t)(sizeof(header) - 1));
    for (i = 0; i < 32; i++)
        ck_assert_int_eq(write(fd, block, sizeof(block)), (ssize_t)sizeof(block));
    ck_assert_int_eq(write(fd, trailer, sizeof(trailer) - 1),
                     (ssize_t)(sizeof(trailer) - 1));
    ck_assert_int_eq(close(fd), 0);

    return path;
}

static char *create_streaming_nested_message_fixture(void)
{
    static const char header[] =
        "Date: Thu, 01 Jan 1970 00:00:00 +0000\n"
        "Content-Type: message/rfc822\n"
        "Content-Transfer-Encoding: 8bit\n"
        "\n"
        "Date: Thu, 01 Jan 1970 00:00:00 +0000\n"
        "Content-Type: text/plain\n"
        "\n";
    char block[64000];
    char *path = NULL;
    int fd     = -1;
    size_t body_bytes = 0;
    const size_t materialization_limit = 64U * 1024U * 1024U;

    memset(block, 'C', sizeof(block));
    ck_assert_int_eq(cli_gentempfd(tmpdir, &path, &fd), CL_SUCCESS);
    ck_assert_ptr_nonnull(path);
    ck_assert_int_eq(write(fd, header, sizeof(header) - 1),
                     (ssize_t)(sizeof(header) - 1));
    while (body_bytes <= materialization_limit) {
        ck_assert_int_eq(write(fd, block, sizeof(block)), (ssize_t)sizeof(block));
        body_bytes += sizeof(block);
    }
    ck_assert_int_eq(close(fd), 0);

    return path;
}

static void assert_large_mail_body_streams(const char *path, int alert_limits,
                                           uint64_t minimum_scanned)
{
    struct cl_scan_options options;
    cl_verdict_t verdict = CL_VERDICT_NOTHING_FOUND;
    const char *last_alert = NULL;
    uint64_t scanned = 0;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    options.parse = ~0U;
    if (alert_limits)
        options.heuristic = CL_SCAN_HEURISTIC_EXCEEDS_MAX;

    ret = cl_scanfile_ex(path, &verdict, &last_alert, &scanned,
                         g_engine, &options, NULL, NULL, NULL, NULL, NULL,
                         NULL);

    ck_assert_int_eq(ret, CL_SUCCESS);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert_msg(scanned > minimum_scanned,
                  "large mail body was not fully scanned");
}

static char *create_nested_maxfiles_fixture(void)
{
    static const char fixture[] =
        "From first@example.com Thu Jan  1 00:00:00 1970\n"
        "Date: Thu, 01 Jan 1970 00:00:00 +0000\n"
        "Content-Type: multipart/mixed; boundary=limitparts\n"
        "\n"
        "--limitparts\n"
        "Content-Type: application/octet-stream\n"
        "Content-Disposition: attachment; filename=first.bin\n"
        "\n"
        "first attachment\n"
        "--limitparts\n"
        "Content-Type: message/rfc822\n"
        "Content-Transfer-Encoding: base64\n"
        "\n"
        "RGF0ZTogVGh1LCAwMSBKYW4gMTk3MCAwMDowMDowMCArMDAwMApDb250ZW50LVR5cGU6IHRleHQvcGxhaW4KCnNlY29uZCBuZXN0ZWQgbWVzc2FnZQo=\n"
        "--limitparts--\n"
        "\n"
        /* The header-only trailing entry is intentionally not parsed. It
         * keeps the first entry non-final so the UNIX mbox loop must retain
         * its nested MAXFILES result instead of relying on the final-entry
         * switch below. */
        "From second@example.com Thu Jan  1 00:00:00 1970\n"
        "Content-Type: text/plain\n";
    char *path = NULL;
    int fd     = -1;

    ck_assert_int_eq(cli_gentempfd(tmpdir, &path, &fd), CL_SUCCESS);
    ck_assert_ptr_nonnull(path);
    ck_assert_int_eq(write(fd, fixture, sizeof(fixture) - 1),
                     (ssize_t)(sizeof(fixture) - 1));
    ck_assert_int_eq(close(fd), 0);

    return path;
}

static char *create_mhtml_unterminated_comment_fixture(void)
{
    static const char fixture[] =
        "From: sender@example.com\n"
        "Date: Thu, 01 Jan 1970 00:00:00 +0000\n"
        "MIME-Version: 1.0\n"
        "Content-Type: multipart/related; boundary=mhtml-regression\n"
        "\n"
        "--mhtml-regression\n"
        "Content-Type: text/html; charset=UTF-8\n"
        "Content-Location: https://example.invalid/root.html\n"
        "\n"
        "<html><head><!-- <xml><o:documentproperties>unterminated --></head>"
        "<body>mhtml preclassification regression</body></html>\n"
        "--mhtml-regression--\n";
    char *path = NULL;
    int fd     = -1;

    ck_assert_int_eq(cli_gentempfd(tmpdir, &path, &fd), CL_SUCCESS);
    ck_assert_ptr_nonnull(path);
    ck_assert_int_eq(write(fd, fixture, sizeof(fixture) - 1),
                     (ssize_t)(sizeof(fixture) - 1));
    ck_assert_int_eq(close(fd), 0);

    return path;
}

static char *create_large_mhtml_fixture(void)
{
    static const char header[] =
        "From: sender@example.com\n"
        "Date: Thu, 01 Jan 1970 00:00:00 +0000\n"
        "MIME-Version: 1.0\n"
        "Content-Type: multipart/related; boundary=mhtml-large\n"
        "\n"
        "--mhtml-large\n"
        "Content-Type: text/html; charset=UTF-8\n"
        "Content-Location: https://example.invalid/large.html\n"
        "\n"
        "<html><body>\n";
    static const char trailer[] =
        "</body></html>\n"
        "--mhtml-large--\n";
    char block[64U * 1024U];
    char *path = NULL;
    const size_t target = 65U * 1024U * 1024U;
    size_t body_bytes = 0;
    int fd = -1;

    memset(block, 'M', sizeof(block));
    block[sizeof(block) - 1] = '\n';
    ck_assert_int_eq(cli_gentempfd(tmpdir, &path, &fd), CL_SUCCESS);
    ck_assert_ptr_nonnull(path);
    ck_assert_int_eq(write(fd, header, sizeof(header) - 1), (ssize_t)(sizeof(header) - 1));
    while (body_bytes < target) {
        const size_t write_bytes = MIN(sizeof(block), target - body_bytes);

        ck_assert_int_eq(write(fd, block, write_bytes), (ssize_t)write_bytes);
        body_bytes += write_bytes;
    }
    ck_assert_int_eq(write(fd, trailer, sizeof(trailer) - 1), (ssize_t)(sizeof(trailer) - 1));
    ck_assert_int_eq(close(fd), 0);

    return path;
}

static char *create_partial_message_missing_fragment_fixture(void)
{
    static const char fixture[] =
        "From: sender@example.com\n"
        "Date: Thu, 01 Jan 1970 00:00:00 +0000\n"
        "MIME-Version: 1.0\n"
        "Content-Type: message/partial; id=missing-fragment-regression; number=2; total=2\n"
        "\n"
        "This is only fragment two.\n";
    char *path = NULL;
    int fd     = -1;

    ck_assert_int_eq(cli_gentempfd(tmpdir, &path, &fd), CL_SUCCESS);
    ck_assert_ptr_nonnull(path);
    ck_assert_int_eq(write(fd, fixture, sizeof(fixture) - 1),
                     (ssize_t)(sizeof(fixture) - 1));
    ck_assert_int_eq(close(fd), 0);

    return path;
}

static char *create_unknown_message_subtype_fixture(void)
{
    static const char fixture[] =
        "From: sender@example.com\n"
        "Date: Thu, 01 Jan 1970 00:00:00 +0000\n"
        "MIME-Version: 1.0\n"
        "Content-Type: message/x-large-file-regression\n"
        "Content-Transfer-Encoding: 8bit\n"
        "\n"
        "Unsupported message subtype must remain incomplete.\n";
    char *path = NULL;
    int fd     = -1;

    ck_assert_int_eq(cli_gentempfd(tmpdir, &path, &fd), CL_SUCCESS);
    ck_assert_ptr_nonnull(path);
    ck_assert_int_eq(write(fd, fixture, sizeof(fixture) - 1),
                     (ssize_t)(sizeof(fixture) - 1));
    ck_assert_int_eq(close(fd), 0);
    return path;
}

static char *create_large_partial_message_fixture(void)
{
    static const char header[] =
        "From: sender@example.com\n"
        "Date: Thu, 01 Jan 1970 00:00:00 +0000\n"
        "MIME-Version: 1.0\n"
        "Content-Type: message/partial; id=large-partial-regression; number=1; total=2\n"
        "\n";
    char block[4096];
    char *path = NULL;
    int fd     = -1;
    size_t i;

    ck_assert_int_eq(cli_gentempfd(tmpdir, &path, &fd), CL_SUCCESS);
    ck_assert_ptr_nonnull(path);
    ck_assert_int_eq(write(fd, header, sizeof(header) - 1), (ssize_t)(sizeof(header) - 1));

    memset(block, 'P', sizeof(block));
    block[sizeof(block) - 1] = '\n';
    for (i = 0; i < (65U * 1024U * 1024U) / sizeof(block); i++)
        ck_assert_int_eq(write(fd, block, sizeof(block)), (ssize_t)sizeof(block));

    ck_assert_int_eq(close(fd), 0);
    return path;
}

static char *create_large_disposition_notification_fixture(void)
{
    static const char header[] =
        "From: sender@example.com\n"
        "Date: Thu, 01 Jan 1970 00:00:00 +0000\n"
        "MIME-Version: 1.0\n"
        "Content-Type: message/disposition-notification\n"
        "Content-Transfer-Encoding: 8bit\n"
        "\n";
    char block[64000];
    char *path = NULL;
    int fd     = -1;
    size_t body_bytes;
    size_t line;

    for (line = 0; line < sizeof(block) / 1000U; line++) {
        memset(block + line * 1000U, 'D', 999U);
        block[line * 1000U + 999U] = '\n';
    }

    ck_assert_int_eq(cli_gentempfd(tmpdir, &path, &fd), CL_SUCCESS);
    ck_assert_ptr_nonnull(path);
    ck_assert_int_eq(write(fd, header, sizeof(header) - 1), (ssize_t)(sizeof(header) - 1));

    body_bytes = 0;
    while (body_bytes <= 64U * 1024U * 1024U) {
        ck_assert_int_eq(write(fd, block, sizeof(block)), (ssize_t)sizeof(block));
        body_bytes += sizeof(block);
    }

    ck_assert_int_eq(close(fd), 0);
    return path;
}

START_TEST(test_mbox_nested_maxfiles_is_fail_visible)
{
    struct cl_engine *engine;
    struct cl_scan_options options;
    cl_scan_report_t *report = NULL;
    cl_scan_report_metrics_t metrics;
    cl_scan_completion_t completion;
    cl_verdict_t verdict = CL_VERDICT_STRONG_INDICATOR;
    const char *last_alert = "stale";
    uint64_t scanned = UINT64_MAX;
    char *path;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    options.parse = ~0U;
    path = create_nested_maxfiles_fixture();

    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    engine = cl_engine_new();
    ck_assert_ptr_nonnull(engine);
    engine->maxfiles = 1;
    ck_assert_int_eq(cl_engine_compile(engine), CL_SUCCESS);

    ret = cl_scanfile_ex2(path, &verdict, &last_alert, &scanned,
                          engine, &options, NULL, NULL, NULL, NULL, NULL,
                          NULL, &report);
    ck_assert_int_eq(ret, CL_EMAXFILES);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert_ptr_nonnull(report);
    ck_assert_int_eq(cl_scan_report_get_status(report, &ret), CL_SUCCESS);
    ck_assert_int_eq(ret, CL_EMAXFILES);
    ck_assert_int_eq(cl_scan_report_get_completion(report, &completion), CL_SUCCESS);
    ck_assert_int_eq(completion, CL_SCAN_COMPLETION_LIMIT_INCOMPLETE);
    ck_assert_int_eq(cl_scan_report_get_metrics(report, &metrics), CL_SUCCESS);
    ck_assert(metrics.skipped_operations > 0);

    cl_scan_report_free(report);
    cl_engine_free(engine);
    free(path);
}
END_TEST

START_TEST(test_partial_message_missing_fragment_is_fail_visible)
{
    struct cl_scan_options options;
    cl_verdict_t verdict = CL_VERDICT_NOTHING_FOUND;
    const char *last_alert = NULL;
    uint64_t scanned = 0;
    char *path;
    cl_error_t ret;

    ck_assert_int_eq(cl_engine_set_str(g_engine, CL_ENGINE_TMPDIR, tmpdir), CL_SUCCESS);
    memset(&options, 0, sizeof(options));
    options.parse = ~0U;
    options.mail  = CL_SCAN_MAIL_PARTIAL_MESSAGE;
    path          = create_partial_message_missing_fragment_fixture();

    ret = cl_scanfile_ex(path, &verdict, &last_alert, &scanned,
                         g_engine, &options, NULL, NULL, NULL, NULL,
                         NULL, NULL);
    ck_assert_msg(ret != CL_SUCCESS,
                  "missing RFC 1341 fragment returned clean");

    free(path);
}
END_TEST

START_TEST(test_unknown_message_subtype_is_fail_visible)
{
    struct cl_scan_options options;
    cl_verdict_t verdict    = CL_VERDICT_NOTHING_FOUND;
    const char *last_alert  = NULL;
    uint64_t scanned        = 0;
    char *path              = create_unknown_message_subtype_fixture();
    cl_error_t ret;

    ck_assert_int_eq(cl_engine_set_str(g_engine, CL_ENGINE_TMPDIR, tmpdir), CL_SUCCESS);
    memset(&options, 0, sizeof(options));
    options.parse = ~0U;

    ret = cl_scanfile_ex(path, &verdict, &last_alert, &scanned,
                         g_engine, &options, NULL, NULL, NULL, NULL,
                         NULL, NULL);
    ck_assert_msg(ret != CL_SUCCESS,
                  "unsupported message subtype returned clean");

    free(path);
}
END_TEST

START_TEST(test_partial_message_large_body_uses_streaming_spool)
{
    struct cl_scan_options options;
    cl_verdict_t verdict = CL_VERDICT_NOTHING_FOUND;
    const char *last_alert = NULL;
    uint64_t scanned = 0;
    char *path;
    cl_error_t ret;

    ck_assert_int_eq(cl_engine_set_str(g_engine, CL_ENGINE_TMPDIR, tmpdir), CL_SUCCESS);
    memset(&options, 0, sizeof(options));
    options.parse = ~0U;
    options.mail  = CL_SCAN_MAIL_PARTIAL_MESSAGE;
    path          = create_large_partial_message_fixture();

    ret = cl_scanfile_ex(path, &verdict, &last_alert, &scanned,
                         g_engine, &options, NULL, NULL, NULL, NULL,
                         NULL, NULL);
    ck_assert_int_eq(ret, CL_SUCCESS);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);

    free(path);
}
END_TEST

START_TEST(test_disposition_notification_large_body_uses_streaming_spool)
{
    char *path = create_large_disposition_notification_fixture();

    assert_large_mail_body_streams(path, 0, 64U * 1024U * 1024U);
    free(path);
}
END_TEST

START_TEST(test_mhtml_unterminated_comment_is_fail_visible)
{
    struct cl_scan_options options;
    cl_verdict_t verdict = CL_VERDICT_NOTHING_FOUND;
    const char *last_alert = NULL;
    uint64_t scanned = 0;
    char *path;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    options.parse   = ~0U;
    options.general = CL_SCAN_GENERAL_COLLECT_METADATA;
    path            = create_mhtml_unterminated_comment_fixture();

    ret = cl_scanfile_ex(path, &verdict, &last_alert, &scanned,
                         g_engine, &options, NULL, NULL, NULL, NULL,
                         NULL, NULL);
    ck_assert_msg(ret != CL_SUCCESS,
                  "unterminated MHTML preclassification returned clean");

    free(path);
}
END_TEST

START_TEST(test_mhtml_large_body_uses_streaming_spool)
{
    struct cl_scan_options options;
    cl_verdict_t verdict = CL_VERDICT_NOTHING_FOUND;
    const char *last_alert = NULL;
    uint64_t scanned = 0;
    char *path;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    options.parse   = ~0U;
    options.general = CL_SCAN_GENERAL_COLLECT_METADATA;
    path            = create_large_mhtml_fixture();

    ret = cl_scanfile_ex(path, &verdict, &last_alert, &scanned,
                         g_engine, &options, NULL, NULL, NULL, NULL, NULL,
                         NULL);
    ck_assert_int_eq(ret, CL_SUCCESS);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert_msg(scanned > 65U * 1024U * 1024U,
                  "large MHTML root was not fully scanned");

    free(path);
}
END_TEST

START_TEST(test_mbox_large_body_uses_streaming_spool)
{
    char *path = create_materialization_limit_fixture(1);

    assert_large_mail_body_streams(path, 1, 64U * 1024U * 1024U);
    free(path);
}
END_TEST

START_TEST(test_mbox_large_body_streams_without_alert)
{
    char *path = create_materialization_limit_fixture(1);

    assert_large_mail_body_streams(path, 0, 64U * 1024U * 1024U);
    free(path);
}
END_TEST

START_TEST(test_scan_report_complete_and_json)
{
    static const char payload[] = "structured scan report fixture\n";
    struct cl_engine *engine;
    struct cl_scan_options options;
    cl_scan_report_t *report = NULL;
    cl_scan_report_metrics_t metrics;
    cl_scan_report_limits_t limits;
    cl_scan_completion_t completion;
    cl_error_t status;
    cl_verdict_t verdict = CL_VERDICT_NOTHING_FOUND;
    const char *last_alert = NULL;
    const char *file_type = NULL;
    char *json = NULL;
    char *path = NULL;
    int fd = -1;

    memset(&options, 0, sizeof(options));
    engine = cl_engine_new();
    ck_assert_ptr_nonnull(engine);
    ck_assert_int_eq(cl_engine_compile(engine), CL_SUCCESS);
    ck_assert_int_eq(cli_gentempfd(tmpdir, &path, &fd), CL_SUCCESS);
    ck_assert_int_eq(write(fd, payload, sizeof(payload) - 1), (ssize_t)(sizeof(payload) - 1));
    ck_assert_int_eq(close(fd), 0);

    status = cl_scanfile_ex2(path, &verdict, &last_alert, NULL,
                             engine, &options, NULL, NULL, NULL, NULL,
                             NULL, NULL, &report);
    ck_assert_int_eq(status, CL_SUCCESS);
    ck_assert_ptr_nonnull(report);
    ck_assert_int_eq(cl_scan_report_get_status(report, &status), CL_SUCCESS);
    ck_assert_int_eq(status, CL_SUCCESS);
    ck_assert_int_eq(cl_scan_report_get_completion(report, &completion), CL_SUCCESS);
    ck_assert_int_eq(completion, CL_SCAN_COMPLETION_COMPLETE);
    ck_assert_int_eq(cl_scan_report_get_file_type(report, &file_type), CL_SUCCESS);
    ck_assert_ptr_nonnull(file_type);
    ck_assert_str_eq(file_type, "CL_TYPE_TEXT_ASCII");
    ck_assert_int_eq(cl_scan_report_get_metrics(report, &metrics), CL_SUCCESS);
    ck_assert_int_eq(cl_scan_report_get_limits(report, &limits), CL_SUCCESS);
    ck_assert_uint_eq(limits.max_matcher_work, CLI_MAX_MATCHER_WORK);
    ck_assert_uint_eq(limits.max_temporary_size, CLI_MAX_TEMPORARY_SIZE);
    ck_assert_uint_eq(limits.max_contiguous_size, CLI_MAX_CONTIGUOUS_SIZE);
    ck_assert_uint_eq(metrics.root_size, sizeof(payload) - 1);
    ck_assert_uint_eq(metrics.logical_bytes, sizeof(payload) - 1);
    ck_assert(metrics.files_scanned > 0);
    ck_assert_int_eq(cl_scan_report_to_json(report, &json), CL_SUCCESS);
    ck_assert_ptr_nonnull(json);
    ck_assert_ptr_nonnull(strstr(json, "\"completion\":\"COMPLETE\""));
    ck_assert_ptr_nonnull(strstr(json, "\"file_type\":\"CL_TYPE_TEXT_ASCII\""));

    free(json);
    cl_scan_report_free(report);
    cl_engine_free(engine);
    cli_unlink(path);
    free(path);
}
END_TEST

#if !defined(_WIN32) && SIZE_MAX > UINT32_MAX
static off_t largefile_pread_cb(void *handle, void *buf, size_t count, off_t offset)
{
    return pread(*((int *)handle), buf, count, offset);
}

static void assert_library_exact_edge_result(
    const char *api,
    uint64_t file_size,
    uint64_t marker_offset,
    cl_error_t status,
    cl_verdict_t verdict,
    uint64_t scanned,
    const char *last_alert,
    cl_scan_report_t *report)
{
    cl_scan_report_metrics_t metrics;
    cl_scan_report_limits_t limits;
    cl_scan_completion_t completion;
    cl_error_t report_status;

    ck_assert_msg(status == CL_SUCCESS, "%s returned %d", api, status);
    ck_assert_msg(verdict == CL_VERDICT_STRONG_INDICATOR,
                  "%s did not return the strong-indicator verdict", api);
    ck_assert_ptr_nonnull(last_alert);
    ck_assert_str_eq(last_alert, "LargeFile.Library.32G.UNOFFICIAL");
    ck_assert_ptr_nonnull(report);
    ck_assert_int_eq(cl_scan_report_get_status(report, &report_status), CL_SUCCESS);
    ck_assert_int_eq(report_status, CL_SUCCESS);
    ck_assert_int_eq(cl_scan_report_get_completion(report, &completion), CL_SUCCESS);
    ck_assert_int_eq(completion, CL_SCAN_COMPLETION_DETECTION_TERMINATED);
    ck_assert_int_eq(cl_scan_report_get_metrics(report, &metrics), CL_SUCCESS);
    ck_assert_int_eq(cl_scan_report_get_limits(report, &limits), CL_SUCCESS);
    ck_assert_uint_eq(metrics.root_size, file_size);
    ck_assert_uint_ge(metrics.matcher_bytes, file_size);
    ck_assert_uint_ge(scanned, marker_offset + sizeof("CLAMAV-LF-32G-EDGE") - 1);
    ck_assert_msg(metrics.logical_bytes >= marker_offset + sizeof("CLAMAV-LF-32G-EDGE") - 1,
                  "%s stopped before the exact-tail marker: " STDu64,
                  api,
                  metrics.logical_bytes);
    ck_assert_uint_eq(limits.max_file_size, file_size);
    ck_assert_uint_eq(limits.max_scan_size, CLI_MAX_LOGICAL_SCAN_SIZE);
    ck_assert_uint_eq(limits.max_matcher_work, CLI_MAX_MATCHER_WORK);
    ck_assert_uint_eq(limits.max_temporary_size, CLI_MAX_TEMPORARY_SIZE);
    ck_assert_uint_eq(limits.max_contiguous_size, CLI_MAX_CONTIGUOUS_SIZE);
}

START_TEST(test_library_exact_32g_tail_detection)
{
    static const uint64_t file_size       = UINT64_C(32) * 1024 * 1024 * 1024;
    static const uint64_t marker_offset   = file_size - 64;
    static const char marker[]            = "CLAMAV-LF-32G-EDGE";
    static const char signature[]         =
        "LargeFile.Library.32G:0:*:434c414d41562d4c462d3332472d4544474500\n";
    struct cl_engine *engine;
    struct cl_scan_options options;
    cl_scan_report_t *report = NULL;
    cl_verdict_t verdict = CL_VERDICT_NOTHING_FOUND;
    const char *last_alert = NULL;
    char signature_path[PATH_MAX];
    char *path = NULL;
    unsigned int sigs = 0;
    cl_error_t status;
    uint64_t scanned = 0;
    int fd = -1;
    int sigfd = -1;
    cl_fmap_t *map = NULL;

    ck_assert_msg(getenv("CLAMAV_LARGEFILE_QUALIFY") != NULL,
                  "the exact-32-GiB test requires CLAMAV_LARGEFILE_QUALIFY=1");

    ck_assert_int_eq(snprintf(signature_path, sizeof(signature_path), "%s/largefile-library-edge.ndb", tmpdir),
                     (int)strlen(tmpdir) + (int)strlen("/largefile-library-edge.ndb"));
    sigfd = open(signature_path, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0600);
    ck_assert_int_ge(sigfd, 0);
    ck_assert_int_eq(write(sigfd, signature, sizeof(signature) - 1), (ssize_t)(sizeof(signature) - 1));
    ck_assert_int_eq(close(sigfd), 0);
    sigfd = -1;

    engine = cl_engine_new();
    ck_assert_ptr_nonnull(engine);
    ck_assert_int_eq(cl_load(signature_path, engine, &sigs, CL_DB_STDOPT), CL_SUCCESS);
    ck_assert_uint_eq(sigs, 1);
    ck_assert_int_eq(cl_engine_set_str(engine, CL_ENGINE_TMPDIR, tmpdir), CL_SUCCESS);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_DISABLE_CACHE, 1), CL_SUCCESS);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_FILESIZE, (long long)file_size), CL_SUCCESS);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_SCANSIZE, (long long)CLI_MAX_LOGICAL_SCAN_SIZE), CL_SUCCESS);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_SCANTIME, 1000U * 60U * 240U), CL_SUCCESS);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_MATCHER_WORK, (long long)CLI_MAX_MATCHER_WORK), CL_SUCCESS);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_TEMPORARY_SIZE, (long long)CLI_MAX_TEMPORARY_SIZE), CL_SUCCESS);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_CONTIGUOUS_SIZE, (long long)CLI_MAX_CONTIGUOUS_SIZE), CL_SUCCESS);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_PCRE_MAX_FILESIZE, (long long)CLI_MAX_CONTIGUOUS_SIZE), CL_SUCCESS);
    ck_assert_int_eq(cl_engine_compile(engine), CL_SUCCESS);
    ck_assert_int_eq(cli_unlink(signature_path), 0);

    ck_assert_int_eq(cli_gentempfd(tmpdir, &path, &fd), CL_SUCCESS);
    ck_assert_int_eq(ftruncate(fd, (off_t)file_size), 0);
    ck_assert_int_eq(lseek(fd, (off_t)marker_offset, SEEK_SET), (off_t)marker_offset);
    ck_assert_int_eq(write(fd, marker, sizeof(marker) - 1), (ssize_t)(sizeof(marker) - 1));
    ck_assert_int_eq(close(fd), 0);
    fd = -1;

    memset(&options, 0, sizeof(options));
    options.parse = ~0U;
    status = cl_scanfile_ex2(path, &verdict, &last_alert, &scanned,
                             engine, &options, NULL, NULL, NULL, NULL,
                             NULL, NULL, &report);
    assert_library_exact_edge_result("cl_scanfile_ex2", file_size, marker_offset,
                                     status, verdict, scanned, last_alert, report);

    cl_scan_report_free(report);
    report = NULL;
    verdict = CL_VERDICT_NOTHING_FOUND;
    last_alert = NULL;
    scanned = 0;

    fd = open(path, O_RDONLY | O_BINARY);
    ck_assert_int_ge(fd, 0);
    status = cl_scandesc_ex2(fd, path, &verdict, &last_alert, &scanned,
                             engine, &options, NULL, NULL, NULL, NULL,
                             NULL, NULL, &report);
    ck_assert_int_eq(close(fd), 0);
    fd = -1;
    assert_library_exact_edge_result("cl_scandesc_ex2", file_size, marker_offset,
                                     status, verdict, scanned, last_alert, report);

    cl_scan_report_free(report);
    report = NULL;
    verdict = CL_VERDICT_NOTHING_FOUND;
    last_alert = NULL;
    scanned = 0;

    fd = open(path, O_RDONLY | O_BINARY);
    ck_assert_int_ge(fd, 0);
    map = cl_fmap_open_handle(&fd, 0, (size_t)file_size, largefile_pread_cb, 1);
    ck_assert_ptr_nonnull(map);
    status = cl_scanmap_ex2(map, path, &verdict, &last_alert, &scanned,
                             engine, &options, NULL, NULL, NULL, NULL,
                             NULL, NULL, &report);
    cl_fmap_close(map);
    map = NULL;
    ck_assert_int_eq(close(fd), 0);
    fd = -1;
    assert_library_exact_edge_result("cl_scanmap_ex2", file_size, marker_offset,
                                     status, verdict, scanned, last_alert, report);

    cl_scan_report_free(report);
    cl_engine_free(engine);
    cli_unlink(path);
    free(path);
}
END_TEST
#endif

START_TEST(test_descriptor_temporary_reservation_is_reported)
{
    static const char payload[] = "descriptor temporary reservation\n";
    struct cl_engine *engine;
    struct cl_scan_options options;
    cl_scan_report_t *report = NULL;
    cl_scan_report_metrics_t metrics;
    cl_error_t status;
    cl_verdict_t verdict = CL_VERDICT_NOTHING_FOUND;
    const char *last_alert = NULL;
    char *path = NULL;
    int fd = -1;

    memset(&options, 0, sizeof(options));
    engine = cl_engine_new();
    ck_assert_ptr_nonnull(engine);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_TEMPORARY_SIZE, 8), CL_SUCCESS);
    ck_assert_int_eq(cl_engine_compile(engine), CL_SUCCESS);
    ck_assert_int_eq(cli_gentempfd(tmpdir, &path, &fd), CL_SUCCESS);
    ck_assert_int_eq(write(fd, payload, sizeof(payload) - 1), (ssize_t)(sizeof(payload) - 1));
    ck_assert_int_eq(lseek(fd, 0, SEEK_SET), 0);

    status = cli_scandesc_ex2_with_temporary_bytes(
        fd,
        path,
        &verdict,
        &last_alert,
        NULL,
        engine,
        &options,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        8,
        &report);
    ck_assert_int_eq(status, CL_SUCCESS);
    ck_assert_ptr_nonnull(report);
    ck_assert_int_eq(cl_scan_report_get_metrics(report, &metrics), CL_SUCCESS);
    ck_assert_uint_eq(metrics.temporary_bytes, 8);
    cl_scan_report_free(report);
    report = NULL;

    ck_assert_int_eq(lseek(fd, 0, SEEK_SET), 0);
    status = cli_scandesc_ex2_with_temporary_bytes(
        fd,
        path,
        &verdict,
        &last_alert,
        NULL,
        engine,
        &options,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        9,
        &report);
    ck_assert_int_eq(status, CL_ERESOURCE);
    ck_assert_ptr_nonnull(report);

    cl_scan_report_free(report);
    close(fd);
    cl_engine_free(engine);
    cli_unlink(path);
    free(path);
}
END_TEST

START_TEST(test_scanfile_temporary_reservation_is_reported)
{
    static const char payload[] = "scanfile temporary reservation\n";
    struct cl_engine *engine;
    struct cl_scan_options options;
    cl_scan_report_t *report = NULL;
    cl_scan_report_metrics_t metrics;
    cl_error_t status;
    cl_verdict_t verdict = CL_VERDICT_NOTHING_FOUND;
    const char *last_alert = NULL;
    char *path = NULL;
    int fd = -1;

    memset(&options, 0, sizeof(options));
    engine = cl_engine_new();
    ck_assert_ptr_nonnull(engine);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_TEMPORARY_SIZE, 8), CL_SUCCESS);
    ck_assert_int_eq(cl_engine_compile(engine), CL_SUCCESS);
    ck_assert_int_eq(cli_gentempfd(tmpdir, &path, &fd), CL_SUCCESS);
    ck_assert_int_eq(write(fd, payload, sizeof(payload) - 1), (ssize_t)(sizeof(payload) - 1));
    ck_assert_int_eq(close(fd), 0);
    fd = -1;

    status = cli_scanfile_ex2_with_temporary_bytes(
        path,
        &verdict,
        &last_alert,
        NULL,
        engine,
        &options,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        8,
        &report);
    ck_assert_int_eq(status, CL_SUCCESS);
    ck_assert_ptr_nonnull(report);
    ck_assert_int_eq(cl_scan_report_get_metrics(report, &metrics), CL_SUCCESS);
    ck_assert_uint_eq(metrics.temporary_bytes, 8);
    cl_scan_report_free(report);
    report = NULL;

    status = cli_scanfile_ex2_with_temporary_bytes(
        path,
        &verdict,
        &last_alert,
        NULL,
        engine,
        &options,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        9,
        &report);
    ck_assert_int_eq(status, CL_ERESOURCE);
    ck_assert_ptr_nonnull(report);

    cl_scan_report_free(report);
    cl_engine_free(engine);
    cli_unlink(path);
    free(path);
}
END_TEST

START_TEST(test_scan_report_detection_precedes_incomplete_state)
{
    cl_scan_report_t *report = NULL;
    cl_scan_completion_t completion;
    cl_verdict_t verdict;
    cli_ctx ctx;

    memset(&ctx, 0, sizeof(ctx));
    ctx.scan_incomplete = true;
    ctx.scan_incomplete_reason = "required parser did not complete";

    ck_assert_int_eq(cli_scan_report_create(&report, NULL), CL_SUCCESS);
    ck_assert_ptr_nonnull(report);
    cli_scan_report_finish(report, &ctx, CL_VIRUS, CL_VERDICT_NOTHING_FOUND, "Test.Detection");
    ck_assert_int_eq(cl_scan_report_get_completion(report, &completion), CL_SUCCESS);
    ck_assert_int_eq(completion, CL_SCAN_COMPLETION_DETECTION_TERMINATED);
    ck_assert_int_eq(cl_scan_report_get_verdict(report, &verdict), CL_SUCCESS);
    ck_assert_int_eq(verdict, CL_VERDICT_STRONG_INDICATOR);
    cl_scan_report_free(report);
}
END_TEST

START_TEST(test_scan_report_unsupported_encryption_is_not_malformed)
{
    cl_scan_report_t *report = NULL;
    cl_scan_completion_t completion;
    cli_ctx ctx;

    memset(&ctx, 0, sizeof(ctx));
    ctx.scan_incomplete        = true;
    ctx.scan_incomplete_reason = "7-Zip encrypted archive header prevents inspection";

    ck_assert_int_eq(cli_scan_report_create(&report, NULL), CL_SUCCESS);
    ck_assert_ptr_nonnull(report);
    cli_scan_report_finish(report, &ctx, CL_EPARSE, CL_VERDICT_NOTHING_FOUND, NULL);
    ck_assert_int_eq(cl_scan_report_get_completion(report, &completion), CL_SUCCESS);
    ck_assert_int_eq(completion, CL_SCAN_COMPLETION_UNSUPPORTED);
    cl_scan_report_free(report);
}
END_TEST

START_TEST(test_scan_report_unsupported_decoder_statuses_are_unsupported)
{
    const cl_error_t statuses[] = {CL_EUNPACK, CL_EBYTECODE, CL_EBYTECODE_TESTFAIL};
    size_t i;

    for (i = 0; i < sizeof(statuses) / sizeof(statuses[0]); i++) {
        cl_scan_report_t *report = NULL;
        cl_scan_completion_t completion;

        ck_assert_int_eq(cli_scan_report_create(&report, NULL), CL_SUCCESS);
        ck_assert_ptr_nonnull(report);
        cli_scan_report_finish(report, NULL, statuses[i], CL_VERDICT_NOTHING_FOUND, NULL);
        ck_assert_int_eq(cl_scan_report_get_completion(report, &completion), CL_SUCCESS);
        ck_assert_int_eq(completion, CL_SCAN_COMPLETION_UNSUPPORTED);
        cl_scan_report_free(report);
    }
}
END_TEST

START_TEST(test_scan_report_break_is_application_abort)
{
    cl_scan_report_t *report = NULL;
    cl_scan_completion_t completion;

    ck_assert_int_eq(cli_scan_report_create(&report, NULL), CL_SUCCESS);
    ck_assert_ptr_nonnull(report);
    cli_scan_report_finish(report, NULL, CL_BREAK, CL_VERDICT_NOTHING_FOUND, NULL);
    ck_assert_int_eq(cl_scan_report_get_completion(report, &completion), CL_SUCCESS);
    ck_assert_int_eq(completion, CL_SCAN_COMPLETION_APPLICATION_ABORT);
    cl_scan_report_free(report);
}
END_TEST

START_TEST(test_scan_report_operational_failure_is_resource_failure)
{
    cl_scan_report_t *report = NULL;
    cl_scan_completion_t completion;
    cli_ctx ctx;

    memset(&ctx, 0, sizeof(ctx));
    ctx.scan_incomplete = true;
    ctx.scan_incomplete_reason = "temporary output could not be written completely";

    ck_assert_int_eq(cli_scan_report_create(&report, NULL), CL_SUCCESS);
    ck_assert_ptr_nonnull(report);
    cli_scan_report_finish(report, &ctx, CL_EWRITE, CL_VERDICT_NOTHING_FOUND, NULL);
    ck_assert_int_eq(cl_scan_report_get_completion(report, &completion), CL_SUCCESS);
    ck_assert_int_eq(completion, CL_SCAN_COMPLETION_RESOURCE_FAILURE);
    cl_scan_report_free(report);
}
END_TEST

START_TEST(test_scan_report_sticky_resource_failure_is_not_a_scan_limit)
{
    cl_scan_report_t *report = NULL;
    cl_scan_completion_t completion;
    cli_ctx ctx;

    memset(&ctx, 0, sizeof(ctx));
    ctx.scan_incomplete        = true;
    ctx.limit_exceeded         = true;
    ctx.limit_exceeded_result  = CL_ERESOURCE;
    ctx.scan_incomplete_reason = "temporary storage exceeded the configured resource limit";

    ck_assert_int_eq(cli_scan_report_create(&report, NULL), CL_SUCCESS);
    cli_scan_report_finish(report, &ctx, CL_SUCCESS, CL_VERDICT_NOTHING_FOUND, NULL);
    ck_assert_int_eq(cl_scan_report_get_completion(report, &completion), CL_SUCCESS);
    ck_assert_int_eq(completion, CL_SCAN_COMPLETION_RESOURCE_FAILURE);
    cl_scan_report_free(report);
}
END_TEST

START_TEST(test_scan_report_counts_skipped_operations)
{
    cl_scan_report_t *report = NULL;
    cl_scan_report_metrics_t metrics;
    cli_ctx ctx;

    memset(&ctx, 0, sizeof(ctx));
    cli_mark_scan_incomplete(&ctx, "first required path did not complete");
    cli_mark_scan_incomplete(&ctx, "second required path did not complete");

    ck_assert(ctx.scan_incomplete);
    ck_assert_uint_eq(ctx.skipped_operations, 2);
    ck_assert_int_eq(cli_scan_report_create(&report, NULL), CL_SUCCESS);
    cli_scan_report_finish(report, &ctx, CL_SUCCESS, CL_VERDICT_NOTHING_FOUND, NULL);
    ck_assert_int_eq(cl_scan_report_get_metrics(report, &metrics), CL_SUCCESS);
    ck_assert_uint_eq(metrics.skipped_operations, 2);
    cl_scan_report_free(report);
}
END_TEST

START_TEST(test_scan_report_post_scan_failure_is_fail_visible)
{
    cl_scan_report_t *report = NULL;
    cl_scan_report_metrics_t metrics;
    cl_scan_completion_t completion;
    cl_error_t status;
    const char *reason = NULL;

    ck_assert_int_eq(cli_scan_report_create(&report, NULL), CL_SUCCESS);
    cli_scan_report_finish(report, NULL, CL_SUCCESS, CL_VERDICT_NOTHING_FOUND, NULL);
    cli_scan_report_note_post_scan_failure(report, CL_EREAD,
                                           "input descriptor could not be closed");

    ck_assert_int_eq(cl_scan_report_get_status(report, &status), CL_SUCCESS);
    ck_assert_int_eq(status, CL_EREAD);
    ck_assert_int_eq(cl_scan_report_get_completion(report, &completion), CL_SUCCESS);
    ck_assert_int_eq(completion, CL_SCAN_COMPLETION_RESOURCE_FAILURE);
    ck_assert_int_eq(cl_scan_report_get_reason(report, &reason), CL_SUCCESS);
    ck_assert_str_eq(reason, "input descriptor could not be closed");
    ck_assert_int_eq(cl_scan_report_get_metrics(report, &metrics), CL_SUCCESS);
    ck_assert_uint_eq(metrics.skipped_operations, 1);

    cl_scan_report_free(report);
}
END_TEST

START_TEST(test_scan_report_merge_preserves_detection_and_peaks)
{
    cl_scan_report_t *aggregate = NULL;
    cl_scan_report_t *first = NULL;
    cl_scan_report_t *second = NULL;
    cl_scan_report_metrics_t metrics;
    cl_scan_completion_t completion;
    cl_verdict_t verdict;

    ck_assert_int_eq(cli_scan_report_create(&aggregate, NULL), CL_SUCCESS);
    ck_assert_int_eq(cli_scan_report_create(&first, NULL), CL_SUCCESS);
    ck_assert_int_eq(cli_scan_report_create(&second, NULL), CL_SUCCESS);

    cli_scan_report_set_root_size(first, 10);
    cli_scan_report_note_logical(first, 10, 1);
    cli_scan_report_note_contiguous(first, 100);
    cli_scan_report_finish(first, NULL, CL_SUCCESS, CL_VERDICT_NOTHING_FOUND, NULL);

    cli_scan_report_set_root_size(second, 20);
    cli_scan_report_note_logical(second, 20, 2);
    cli_scan_report_note_temporary(second, 200);
    cli_scan_report_finish(second, NULL, CL_VIRUS, CL_VERDICT_NOTHING_FOUND, "Test.Merge.Detection");

    cli_scan_report_merge(aggregate, first);
    cli_scan_report_merge(aggregate, second);
    ck_assert_int_eq(cl_scan_report_get_completion(aggregate, &completion), CL_SUCCESS);
    ck_assert_int_eq(completion, CL_SCAN_COMPLETION_DETECTION_TERMINATED);
    ck_assert_int_eq(cl_scan_report_get_verdict(aggregate, &verdict), CL_SUCCESS);
    ck_assert_int_eq(verdict, CL_VERDICT_STRONG_INDICATOR);
    ck_assert_int_eq(cl_scan_report_get_metrics(aggregate, &metrics), CL_SUCCESS);
    ck_assert_uint_eq(metrics.root_size, 30);
    ck_assert_uint_eq(metrics.logical_bytes, 30);
    ck_assert_uint_eq(metrics.contiguous_bytes, 100);
    ck_assert_uint_eq(metrics.temporary_bytes, 200);
    ck_assert_uint_eq(metrics.files_scanned, 2);

    cl_scan_report_free(aggregate);
    cl_scan_report_free(first);
    cl_scan_report_free(second);
}
END_TEST

START_TEST(test_resource_limit_engine_fields_and_accounting)
{
    struct cl_engine *engine;
    cli_ctx ctx;

    engine = cl_engine_new();
    ck_assert_ptr_nonnull(engine);
    ck_assert_uint_eq((uint64_t)cl_engine_get_num(engine, CL_ENGINE_MAX_MATCHER_WORK, NULL), CLI_MAX_MATCHER_WORK);
    ck_assert_uint_eq((uint64_t)cl_engine_get_num(engine, CL_ENGINE_MAX_TEMPORARY_SIZE, NULL), CLI_MAX_TEMPORARY_SIZE);
    ck_assert_uint_eq((uint64_t)cl_engine_get_num(engine, CL_ENGINE_MAX_CONTIGUOUS_SIZE, NULL), CLI_MAX_CONTIGUOUS_SIZE);

    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_MATCHER_WORK, 1024), CL_SUCCESS);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_TEMPORARY_SIZE, 2048), CL_SUCCESS);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_CONTIGUOUS_SIZE, 4096), CL_SUCCESS);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_MATCHER_WORK, (long long)CLI_MAX_MATCHER_WORK + 1), CL_EARG);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_TEMPORARY_SIZE, (long long)CLI_MAX_TEMPORARY_SIZE + 1), CL_EARG);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_CONTIGUOUS_SIZE, (long long)CLI_MAX_CONTIGUOUS_SIZE + 1), CL_EARG);

    memset(&ctx, 0, sizeof(ctx));
    ctx.engine = engine;
    ck_assert_int_eq(cli_scan_account_matcher_work(&ctx, 1024), CL_SUCCESS);
    ck_assert_int_eq(cli_scan_account_matcher_work(&ctx, 1), CL_ERESOURCE);
    ck_assert(ctx.scan_incomplete);
    ck_assert_int_eq(cli_scan_reserve_contiguous(&ctx, 4096), CL_SUCCESS);
    cli_scan_release_contiguous(&ctx, 4096);
    ck_assert_int_eq(cli_scan_reserve_temporary(&ctx, 2048), CL_SUCCESS);
    cli_scan_release_temporary(&ctx, 2048);

    memset(&ctx, 0, sizeof(ctx));
    ctx.engine         = engine;
    ctx.matcher_work   = UINT64_MAX;
    ctx.contiguous_bytes = UINT64_MAX;
    ctx.temporary_bytes  = UINT64_MAX;
    ck_assert_int_eq(cli_scan_account_matcher_work(&ctx, 1), CL_ERESOURCE);
    ck_assert_int_eq(cli_scan_reserve_contiguous(&ctx, 1), CL_ERESOURCE);
    ck_assert_int_eq(cli_scan_reserve_temporary(&ctx, 1), CL_ERESOURCE);

    cl_engine_free(engine);
}
END_TEST

START_TEST(test_largefile_default_profile_values)
{
    struct cl_engine *engine = cl_engine_new();

    ck_assert_ptr_nonnull(engine);
#ifdef CLAMAV_LARGE_FILE_DEFAULTS
    ck_assert_uint_eq((uint64_t)cl_engine_get_num(engine, CL_ENGINE_MAX_FILESIZE, NULL), CLI_MAX_LARGE_FILESIZE);
    ck_assert_uint_eq((uint64_t)cl_engine_get_num(engine, CL_ENGINE_MAX_SCANSIZE, NULL), CLI_MAX_LOGICAL_SCAN_SIZE);
    ck_assert_uint_eq((uint64_t)cl_engine_get_num(engine, CL_ENGINE_PCRE_MAX_FILESIZE, NULL), CLI_MAX_CONTIGUOUS_SIZE);
    ck_assert_uint_eq((uint64_t)cl_engine_get_num(engine, CL_ENGINE_MAX_SCANTIME, NULL), CLI_DEFAULT_TIMELIMIT);
#else
    ck_assert_uint_eq((uint64_t)cl_engine_get_num(engine, CL_ENGINE_MAX_FILESIZE, NULL), CLI_DEFAULT_MAXFILESIZE);
    ck_assert_uint_eq((uint64_t)cl_engine_get_num(engine, CL_ENGINE_MAX_SCANSIZE, NULL), CLI_DEFAULT_MAXSCANSIZE);
    ck_assert_uint_eq((uint64_t)cl_engine_get_num(engine, CL_ENGINE_PCRE_MAX_FILESIZE, NULL), CLI_DEFAULT_PCRE_MAX_FILESIZE);
    ck_assert_uint_eq((uint64_t)cl_engine_get_num(engine, CL_ENGINE_MAX_SCANTIME, NULL), CLI_DEFAULT_TIMELIMIT);
#endif
    cl_engine_free(engine);
}
END_TEST

START_TEST(test_fileblob_temporary_spool_accounting)
{
    static const unsigned char payload[] = "12345";
    struct cl_engine *engine;
    cli_ctx ctx;
    fileblob *fb;

    engine = cl_engine_new();
    ck_assert_ptr_nonnull(engine);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_TEMPORARY_SIZE, 4), CL_SUCCESS);

    memset(&ctx, 0, sizeof(ctx));
    ctx.engine           = engine;
    ctx.this_layer_tmpdir = tmpdir;

    fb = fileblobCreate();
    ck_assert_ptr_nonnull(fb);
    fileblobSetCTX(fb, &ctx);
    fileblobSetFilename(fb, tmpdir, "temporary-quota");
    ck_assert_int_eq(fileblobAddData(fb, payload, sizeof(payload) - 1), -1);
    ck_assert(ctx.scan_incomplete);
    ck_assert_uint_eq(ctx.temporary_bytes, 0);
    fileblobDestructiveDestroy(fb);

    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_TEMPORARY_SIZE, 8), CL_SUCCESS);
    memset(&ctx, 0, sizeof(ctx));
    ctx.engine            = engine;
    ctx.this_layer_tmpdir = tmpdir;

    fb = fileblobCreate();
    ck_assert_ptr_nonnull(fb);
    fileblobSetFilename(fb, tmpdir, "temporary-backfill");
    ck_assert_int_eq(fileblobAddData(fb, payload, sizeof(payload) - 1), 0);
    ck_assert_uint_eq(ctx.temporary_bytes, 0);
    fileblobSetCTX(fb, &ctx);
    ck_assert_uint_eq(ctx.temporary_bytes, sizeof(payload) - 1);
    ck_assert_uint_eq(ctx.temporary_peak, sizeof(payload) - 1);
    fileblobDestructiveDestroy(fb);
    ck_assert_uint_eq(ctx.temporary_bytes, 0);

    cl_engine_free(engine);
}
END_TEST

START_TEST(test_fileblob_scan_errors_are_fail_visible)
{
    struct cl_engine *engine;
    cli_ctx ctx;
    fileblob *fb;

    engine = cl_engine_new();
    ck_assert_ptr_nonnull(engine);

    memset(&ctx, 0, sizeof(ctx));
    ctx.engine = engine;

    fb = fileblobCreate();
    ck_assert_ptr_nonnull(fb);
    fileblobSetCTX(fb, &ctx);
    fb->isIncomplete = 1;
    ck_assert_int_eq(fileblobScanAndDestroy(fb), CL_ERESOURCE);
    ck_assert(ctx.scan_incomplete);

    cl_engine_free(engine);
}
END_TEST

START_TEST(test_parser_gate_limits_reject_above_32g)
{
    struct cl_engine *engine = cl_engine_new();
    struct cl_settings *settings;
    const long long over_32g = (long long)CLI_MAX_LARGE_FILESIZE + 1;

    ck_assert_ptr_nonnull(engine);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_EMBEDDEDPE, over_32g), CL_EARG);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_HTMLNORMALIZE, over_32g), CL_EARG);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_HTMLNOTAGS, over_32g), CL_EARG);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_SCRIPTNORMALIZE, over_32g), CL_EARG);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_ZIPTYPERCG, over_32g), CL_EARG);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_HTMLNORMALIZE, CLI_MAX_LARGE_FILESIZE), CL_SUCCESS);
    ck_assert_uint_eq(cl_engine_get_num(engine, CL_ENGINE_MAX_HTMLNORMALIZE, NULL), CLI_MAX_LARGE_FILESIZE);

    settings = cl_engine_settings_copy(engine);
    ck_assert_ptr_nonnull(settings);
    settings->maxhtmlnormalize = (uint64_t)over_32g;
    ck_assert_int_eq(cl_engine_settings_apply(engine, settings), CL_EARG);
    settings->maxhtmlnormalize = CLI_MAX_LARGE_FILESIZE;
    settings->maxscansize      = CLI_MAX_LOGICAL_SCAN_SIZE + 1;
    ck_assert_int_eq(cl_engine_settings_apply(engine, settings), CL_EARG);
    ck_assert_int_eq(cl_engine_settings_free(settings), CL_SUCCESS);
    cl_engine_free(engine);
}
END_TEST

START_TEST(test_engine_set_num_rejects_narrowing_and_negative_values)
{
    struct cl_engine *engine = cl_engine_new();
    struct cl_settings *settings;
    uint64_t maxfilesize_before;

    ck_assert_ptr_nonnull(engine);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_FILESIZE, 4096), CL_SUCCESS);
    maxfilesize_before = (uint64_t)cl_engine_get_num(engine, CL_ENGINE_MAX_FILESIZE, NULL);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_FILESIZE, -1), CL_EARG);
    ck_assert_uint_eq((uint64_t)cl_engine_get_num(engine, CL_ENGINE_MAX_FILESIZE, NULL), maxfilesize_before);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_EMBEDDEDPE, -1), CL_EARG);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_HTMLNORMALIZE, -1), CL_EARG);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_HTMLNOTAGS, -1), CL_EARG);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_SCRIPTNORMALIZE, -1), CL_EARG);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_ZIPTYPERCG, -1), CL_EARG);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_SCANSIZE, -1), CL_EARG);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_SCANSIZE,
                                       (long long)CLI_MAX_LOGICAL_SCAN_SIZE + 1), CL_EARG);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_SCANTIME, -1), CL_EARG);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_SCANTIME,
                                       (long long)UINT32_MAX + 1), CL_EARG);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_FILES, -1), CL_EARG);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_FILES, (long long)UINT32_MAX + 1), CL_EARG);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_RECURSION, (long long)UINT32_MAX + 1), CL_EARG);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_AC_MINDEPTH, (long long)UINT8_MAX + 1), CL_EARG);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_AC_MAXDEPTH, -1), CL_EARG);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_PCRE_MATCH_LIMIT, -1), CL_EARG);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_PCRE_RECMATCH_LIMIT, -1), CL_EARG);

    settings = cl_engine_settings_copy(engine);
    ck_assert_ptr_nonnull(settings);
    settings->ac_mindepth = UINT8_MAX + 1U;
    ck_assert_int_eq(cl_engine_settings_apply(engine, settings), CL_EARG);
    ck_assert_int_eq(cl_engine_settings_free(settings), CL_SUCCESS);
    cl_engine_free(engine);
}
END_TEST

START_TEST(test_single_message_large_body_uses_streaming_spool)
{
    char *path = create_materialization_limit_fixture(0);

    assert_large_mail_body_streams(path, 1, 64U * 1024U * 1024U);
    free(path);
}
END_TEST

START_TEST(test_single_message_large_body_streams_without_alert)
{
    char *path = create_materialization_limit_fixture(0);

    assert_large_mail_body_streams(path, 0, 64U * 1024U * 1024U);
    free(path);
}
END_TEST

START_TEST(test_multipart_body_uses_streaming_spool)
{
    char *path = create_streaming_multipart_fixture();

    assert_large_mail_body_streams(path, 0, 1024U * 1024U);
    free(path);
}
END_TEST

START_TEST(test_nested_rfc822_body_uses_streaming_spool)
{
    char *path = create_streaming_nested_message_fixture();

    assert_large_mail_body_streams(path, 0, 64U * 1024U * 1024U);
    free(path);
}
END_TEST

START_TEST(test_nsis_crc_trailer_is_not_a_member_header)
{
    const char *virname = NULL;
    const char *file    = OBJDIR PATHSEP "input" PATHSEP "clamav_hdb_scanfiles" PATHSEP "clam-nsis.exe";
    unsigned long int scanned = 0;
    struct cl_scan_options options;
    int ret;

    memset(&options, 0, sizeof(options));
    options.parse |= ~0;

    ret = cl_scanfile(file, &virname, &scanned, g_engine, &options);

    ck_assert_msg(ret == CL_VIRUS, "valid NSIS archive with a four-byte CRC trailer failed: %s", cl_strerror(ret));
    ck_assert_msg(virname && !strcmp(virname, "ClamAV-Test-File.UNOFFICIAL"), "virusname: %s", virname);
}
END_TEST

START_TEST(test_cl_scanfile_callback)
{
    const char *virname = NULL;
    char file[256];
    unsigned long size;
    unsigned long int scanned = 0;
    int ret;
    struct cl_scan_options options;

    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0;

    int fd = get_test_file(_i, file, sizeof(file), &size);
    close(fd);

    cli_dbgmsg("scanning (scanfile_cb) %s\n", file);
    /* TODO: test callbacks */
    ret = cl_scanfile_callback(file, &virname, &scanned, g_engine, &options, NULL);
    cli_dbgmsg("scan end (scanfile_cb) %s\n", file);

    if (!FALSE_NEGATIVE) {
        assert_test_file_scan_result(ret, virname, file, "cl_scanfile_cb");
    }
}
END_TEST

START_TEST(test_cl_scanfile_callback_allscan)
{
    const char *virname = NULL;
    char file[256];
    unsigned long size;
    unsigned long int scanned = 0;
    int ret;
    struct cl_scan_options options;

    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0;
    options.general |= CL_SCAN_GENERAL_ALLMATCHES;

    int fd = get_test_file(_i, file, sizeof(file), &size);
    close(fd);

    cli_dbgmsg("scanning (scanfile_cb_allscan) %s\n", file);
    /* TODO: test callbacks */
    ret = cl_scanfile_callback(file, &virname, &scanned, g_engine, &options, NULL);
    cli_dbgmsg("scan end (scanfile_cb_allscan) %s\n", file);

    if (!FALSE_NEGATIVE) {
        assert_test_file_scan_result(ret, virname, file, "cl_scanfile_cb_allscan");
    }
}
END_TEST

START_TEST(test_cl_scandesc_callback)
{
    const char *virname = NULL;
    char file[256];
    unsigned long size;
    unsigned long int scanned = 0;
    int ret;
    struct cl_scan_options options;

    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0;

    int fd = get_test_file(_i, file, sizeof(file), &size);

    cli_dbgmsg("scanning (scandesc_cb) %s\n", file);
    /* TODO: test callbacks */
    ret = cl_scandesc_callback(fd, file, &virname, &scanned, g_engine, &options, NULL);
    cli_dbgmsg("scan end (scandesc_cb) %s\n", file);

    if (!FALSE_NEGATIVE) {
        assert_test_file_scan_result(ret, virname, file, "cl_scandesc_callback");
    }
    close(fd);
}
END_TEST

START_TEST(test_cl_scandesc_callback_allscan)
{
    const char *virname = NULL;
    char file[256];
    unsigned long size;
    unsigned long int scanned = 0;
    int ret;
    struct cl_scan_options options;

    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0;
    options.general |= CL_SCAN_GENERAL_ALLMATCHES;

    int fd = get_test_file(_i, file, sizeof(file), &size);

    cli_dbgmsg("scanning (scandesc_cb_allscan) %s\n", file);
    /* TODO: test callbacks */
    ret = cl_scandesc_callback(fd, file, &virname, &scanned, g_engine, &options, NULL);
    cli_dbgmsg("scan end (scandesc_cb_allscan) %s\n", file);

    if (!FALSE_NEGATIVE) {
        assert_test_file_scan_result(ret, virname, file, "cl_scandesc_callback_allscan");
    }
    close(fd);
}
END_TEST

/* cl_error_t cl_load(const char *path, struct cl_engine **engine, unsigned int *signo, unsigned int options) */
START_TEST(test_cl_load)
{
    cl_error_t ret;
    struct cl_engine *engine;
    unsigned int sigs = 0;
    const char *testfile;
    const char *cvdcertsdir;

    ret = cl_init(CL_INIT_DEFAULT);
    ck_assert_msg(ret == CL_SUCCESS, "cl_init failed: %s", cl_strerror(ret));

    engine = cl_engine_new();
    ck_assert_msg(engine != NULL, "cl_engine_new failed");

    /* load test cvd */
    testfile = SRCDIR PATHSEP "input" PATHSEP "freshclam_testfiles" PATHSEP "test-5.cvd";
    ret      = cl_load(testfile, engine, &sigs, CL_DB_STDOPT);
    ck_assert_msg(ret == CL_SUCCESS, "cl_load failed for: %s -- %s", testfile, cl_strerror(ret));
    ck_assert_msg(sigs > 0, "No signatures loaded");

    cl_engine_free(engine);
}
END_TEST

/* cl_error_t cl_cvdverify_ex(const char *file, const char *certs_directory, uint32_t dboptions) */
START_TEST(test_cl_cvdverify)
{
    cl_error_t ret;
    const char *testfile;
    char newtestfile[PATH_MAX];
    FILE *orig_fs;
    FILE *new_fs;
    char cvd_bytes[5000];
    const char *cvdcertsdir;

    cvdcertsdir = getenv("CVD_CERTS_DIR");
    ck_assert_msg(cvdcertsdir != NULL, "CVD_CERTS_DIR not set");

    // Should be able to verify this cvd
    testfile = SRCDIR "/input/freshclam_testfiles/test-1.cvd";
    ret      = cl_cvdverify_ex(testfile, cvdcertsdir, 0);
    ck_assert_msg(CL_SUCCESS == ret, "cl_cvdverify_ex failed for: %s -- %s", testfile, cl_strerror(ret));

    // Can't verify a cvd that doesn't exist
    testfile = SRCDIR "/input/freshclam_testfiles/test-na.cvd";
    ret      = cl_cvdverify_ex(testfile, cvdcertsdir, 0);
    ck_assert_msg(CL_ECVD == ret, "cl_cvdverify_ex should have failed for: %s -- %s", testfile, cl_strerror(ret));

    // A cdiff is not a cvd. Cannot verify with cl_cvdverify_ex!
    testfile = SRCDIR "/input/freshclam_testfiles/test-2.cdiff";
    ret      = cl_cvdverify_ex(testfile, cvdcertsdir, 0);
    ck_assert_msg(CL_ECVD == ret, "cl_cvdverify_ex should have failed for: %s -- %s", testfile, cl_strerror(ret));

    // Can't verify an hdb file
    testfile = SRCDIR "/input/clamav.hdb";
    ret      = cl_cvdverify_ex(testfile, cvdcertsdir, 0);
    ck_assert_msg(CL_ECVD == ret, "cl_cvdverify_ex should have failed for: %s -- %s", testfile, cl_strerror(ret));

    // Modify the cvd to make it invalid
    sprintf(newtestfile, "%s/modified.cvd", tmpdir);

    orig_fs = fopen(SRCDIR "/input/freshclam_testfiles/test-1.cvd", "rb");
    ck_assert_msg(orig_fs != NULL, "Failed to open %s", testfile);

    new_fs = fopen(newtestfile, "wb");
    ck_assert_msg(new_fs != NULL, "Failed to open %s", newtestfile);

    // Copy the first 5000 bytes
    fread(cvd_bytes, 1, 5000, orig_fs);
    fwrite(cvd_bytes, 1, 5000, new_fs);

    fclose(orig_fs);
    fclose(new_fs);

    // Now verify the modified cvd
    ret = cl_cvdverify_ex(newtestfile, cvdcertsdir, 0);
    ck_assert_msg(CL_EVERIFY == ret, "cl_cvdverify_ex should have failed for: %s -- %s", newtestfile, cl_strerror(ret));
}
END_TEST

/* cl_error_t cl_cvdunpack_ex(const char *file, const char *dir, const char *certs_directory, uint32_t dboptions) */
START_TEST(test_cl_cvdunpack_ex)
{
    cl_error_t ret;
    char *utf8       = NULL;
    size_t utf8_size = 0;
    const char *testfile;

    testfile = SRCDIR "/input/freshclam_testfiles/test-1.cvd";
    ret      = cl_cvdunpack_ex(testfile, tmpdir, NULL, CL_DB_UNSIGNED);
    ck_assert_msg(CL_SUCCESS == ret, "cl_cvdunpack_ex: failed for: %s -- %s", testfile, cl_strerror(ret));

    // Can't unpack a cdiff
    testfile = SRCDIR "/input/freshclam_testfiles/test-2.cdiff";
    ret      = cl_cvdunpack_ex(testfile, tmpdir, NULL, CL_DB_UNSIGNED);
    ck_assert_msg(CL_ECVD == ret, "cl_cvdunpack_ex: should have failed for: %s -- %s", testfile, cl_strerror(ret));
}
END_TEST

/* int cl_statinidir(const char *dirname, struct cl_stat *dbstat) */
START_TEST(test_cl_statinidir)
{
}
END_TEST

/* int cl_statchkdir(const struct cl_stat *dbstat) */
START_TEST(test_cl_statchkdir)
{
}
END_TEST

/* void cl_settempdir(const char *dir, short leavetemps) */
START_TEST(test_cl_settempdir)
{
}
END_TEST

/* const char *cl_strerror(int clerror) */
START_TEST(test_cl_strerror)
{
}
END_TEST

struct limit_alert_callback_state {
    unsigned int calls;
    cl_error_t result;
};

static cl_error_t limit_alert_callback(cl_scan_layer_t *layer, void *context)
{
    struct limit_alert_callback_state *state = context;

    if ((NULL == layer) || (NULL == state))
        return CL_ERROR;

    state->calls++;
    return state->result;
}

START_TEST(test_top_level_maxfilesize_is_fail_visible)
{
    static const unsigned char data[11] = "0123456789";
    struct cl_engine *engine;
    struct cl_scan_options options;
    cl_fmap_t *map;
    struct limit_alert_callback_state callback_state;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    unsigned long legacy_scanned;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    memset(&callback_state, 0, sizeof(callback_state));
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    engine = cl_engine_new();
    ck_assert_ptr_nonnull(engine);
    engine->maxfilesize = 10;
    engine->maxscansize = 10;
    ck_assert_int_eq(cl_engine_compile(engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);

    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;
    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        engine, &options, NULL, NULL, NULL, NULL, NULL, NULL);
    ck_assert_int_eq(ret, CL_EMAXSIZE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert_uint_eq(scanned, 0);

    legacy_scanned = ULONG_MAX;
    ret = cl_scanmap_callback(map, NULL, &last_alert, &legacy_scanned, engine, &options, NULL);
    ck_assert_int_eq(ret, CL_EMAXSIZE);
    ck_assert_uint_eq(legacy_scanned, 0);

    options.heuristic = CL_SCAN_HEURISTIC_EXCEEDS_MAX;
    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        engine, &options, NULL, NULL, NULL, NULL, NULL, NULL);
    ck_assert_int_eq(ret, CL_SUCCESS);
    ck_assert_int_eq(verdict, CL_VERDICT_POTENTIALLY_UNWANTED);
    ck_assert_str_eq(last_alert, "Heuristics.Limits.Exceeded.MaxFileSize");

    ret = cl_scanmap_callback(map, NULL, &last_alert, &legacy_scanned, engine, &options, NULL);
    ck_assert_int_eq(ret, CL_VIRUS);

    /* A modern alert callback may filter the heuristic indicator, but doing
     * so must expose the original configured-limit failure rather than turn
     * content that was never scanned into a clean result. */
    callback_state.result = CL_SUCCESS;
    cl_engine_set_scan_callback(engine, limit_alert_callback, CL_SCAN_CALLBACK_ALERT);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;
    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        engine, &options, &callback_state, NULL, NULL, NULL, NULL, NULL);
    ck_assert_int_eq(ret, CL_EMAXSIZE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert_uint_eq(callback_state.calls, 1);

    cl_fmap_close(map);
    cl_engine_free(engine);
}
END_TEST

#ifndef _WIN32
START_TEST(test_html_normalize_cap_is_fail_visible)
{
    struct cl_engine *engine;
    struct cl_scan_options options;
    cl_fmap_t *map;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    unsigned char *data;
    size_t length;
    cl_error_t ret;

    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    engine = cl_engine_new();
    ck_assert_ptr_nonnull(engine);
    /* Use a small explicit cap so this regression never allocates a large
     * fixture merely to exercise the fail-visible boundary. */
    engine->maxhtmlnormalize = 1024;
    length = (size_t)engine->maxhtmlnormalize + 1U;
    data   = calloc(1, length);
    ck_assert_ptr_nonnull(data);
    memcpy(data, "<html><body>large document</body></html>",
           MIN(length, sizeof("<html><body>large document</body></html>") - 1U));

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_HTML;
    ck_assert_int_eq(cl_engine_compile(engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, length);
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        engine, &options, NULL, NULL, NULL, NULL,
                        "CL_TYPE_HTML", NULL);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(engine);
    free(data);
}
END_TEST

START_TEST(test_html_normalize_cap_does_not_skip_raw_matching)
{
    static const unsigned char data[] =
        "<html><body>CLAMAV-TEST-STRING-NOT-EICAR</body></html>";
    const char *signature = SRCDIR PATHSEP "input" PATHSEP "other_sigs" PATHSEP
                            "Clamav-Unit-Test-Signature.hdb";
    struct cl_engine *engine;
    struct cl_scan_options options;
    cl_fmap_t *map;
    cl_verdict_t verdict = CL_VERDICT_NOTHING_FOUND;
    const char *last_alert = NULL;
    uint64_t scanned       = 0;
    unsigned int sigs      = 0;
    cl_error_t ret;

    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    engine = cl_engine_new();
    ck_assert_ptr_nonnull(engine);
    ck_assert_int_eq(cl_load(signature, engine, &sigs, CL_DB_STDOPT), CL_SUCCESS);
    ck_assert_uint_eq(sigs, 1);

    /* Force the enabled HTML parser to skip normalization while leaving the
     * outer raw signature applicable. The raw pass must still detect. */
    engine->maxhtmlnormalize = sizeof(data) - 2U;
    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_HTML;
    ck_assert_int_eq(cl_engine_compile(engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data) - 1U);
    ck_assert_ptr_nonnull(map);

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        engine, &options, NULL, NULL, NULL, NULL,
                        "CL_TYPE_HTML", NULL);
    ck_assert_int_eq(ret, CL_VIRUS);
    ck_assert_int_eq(verdict, CL_VERDICT_STRONG_INDICATOR);
    ck_assert_str_eq(last_alert, "Clamav-Unit-Test-Signature.UNOFFICIAL");

    cl_fmap_close(map);
    cl_engine_free(engine);
}
END_TEST

START_TEST(test_html_notags_cap_is_fail_visible)
{
    struct cl_engine *engine;
    struct cl_scan_options options;
    cl_fmap_t *map;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    static const unsigned char data[] = "<html><body>normalized content</body></html>";
    cl_error_t ret;

    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    engine = cl_engine_new();
    ck_assert_ptr_nonnull(engine);
    /* Force the required no-tags view over its cap. The scanner must not
     * silently omit that view. */
    engine->maxhtmlnormalize = 1024;
    engine->maxhtmlnotags   = 1;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_HTML;
    ck_assert_int_eq(cl_engine_compile(engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data) - 1U);
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        engine, &options, NULL, NULL, NULL, NULL,
                        "CL_TYPE_HTML", NULL);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(engine);
}
END_TEST

START_TEST(test_html_notags_cap_uses_generated_size)
{
    struct cl_engine *engine;
    struct cl_scan_options options;
    cl_fmap_t *map;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    static const unsigned char data[] = "<html><body>normalized content</body></html>";
    cl_error_t ret;

    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    engine = cl_engine_new();
    ck_assert_ptr_nonnull(engine);
    /* The input is larger than the no-tags cap, but its generated no-tags
     * representation fits. The scanner must measure the generated view rather
     * than incorrectly applying the cap to the original input. */
    engine->maxhtmlnormalize = 1024;
    engine->maxhtmlnotags   = 40;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_HTML;
    ck_assert_int_eq(cl_engine_compile(engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data) - 1U);
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        engine, &options, NULL, NULL, NULL, NULL,
                        "CL_TYPE_HTML", NULL);
    ck_assert_int_eq(ret, CL_SUCCESS);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(!map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(engine);
}
END_TEST

#ifdef CLAMAV_TEST_JS_IO_WRAP
START_TEST(test_html_normalize_cleanup_close_failure_is_fail_visible)
{
    static const unsigned char data[] = "<html><body>normalized content</body></html>";
    struct cl_engine *engine;
    struct cl_scan_options options;
    cl_fmap_t *map;
    cl_verdict_t verdict = CL_VERDICT_STRONG_INDICATOR;
    const char *last_alert = "stale";
    uint64_t scanned       = UINT64_MAX;
    cl_error_t ret;

    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    engine = cl_engine_new();
    ck_assert_ptr_nonnull(engine);
    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_HTML;
    ck_assert_int_eq(cl_engine_compile(engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data) - 1U);
    ck_assert_ptr_nonnull(map);

    clamav_test_fail_close = 1;
    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        engine, &options, NULL, NULL, NULL, NULL,
                        "CL_TYPE_HTML", NULL);
    clamav_test_fail_close = 0;

    ck_assert_msg(ret != CL_SUCCESS,
                  "HTML normalization close failure returned clean");
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(engine);
}
END_TEST
#endif
#endif

#ifndef _WIN32
START_TEST(test_top_level_maxfilesize_descriptor_is_fail_visible)
{
    static const char data[11] = "0123456789";
    struct cl_engine *engine;
    struct cl_scan_options options;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    char *path = NULL;
    int fd     = -1;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    engine = cl_engine_new();
    ck_assert_ptr_nonnull(engine);
    engine->maxfilesize = 10;
    engine->maxscansize = 10;
    ck_assert_int_eq(cl_engine_compile(engine), CL_SUCCESS);

    ck_assert_int_eq(cli_gentempfd(tmpdir, &path, &fd), CL_SUCCESS);
    ck_assert_ptr_nonnull(path);
    ck_assert_int_eq(write(fd, data, sizeof(data)), (ssize_t)sizeof(data));

    ret = cl_scandesc_ex(fd, path, &verdict, &last_alert, &scanned,
                         engine, &options, NULL, NULL, NULL, NULL, NULL, NULL);
    ck_assert_int_eq(ret, CL_EMAXSIZE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert_uint_eq(scanned, 0);

    options.heuristic = CL_SCAN_HEURISTIC_EXCEEDS_MAX;
    ret = cl_scandesc_ex(fd, path, &verdict, &last_alert, &scanned,
                         engine, &options, NULL, NULL, NULL, NULL, NULL, NULL);
    ck_assert_int_eq(ret, CL_SUCCESS);
    ck_assert_int_eq(verdict, CL_VERDICT_POTENTIALLY_UNWANTED);
    ck_assert_str_eq(last_alert, "Heuristics.Limits.Exceeded.MaxFileSize");

    close(fd);
    free(path);
    cl_engine_free(engine);
}
END_TEST
#endif

static void init_synthetic_limit_ctx(
    struct cl_engine *engine,
    struct cl_scan_options *options,
    cli_ctx *ctx,
    cli_scan_layer_t *layers,
    uint32_t layer_count,
    fmap_t *root_map)
{
    memset(engine, 0, sizeof(*engine));
    memset(options, 0, sizeof(*options));
    memset(ctx, 0, sizeof(*ctx));
    memset(layers, 0, sizeof(*layers) * layer_count);
    memset(root_map, 0, sizeof(*root_map));

    layers[0].fmap            = root_map;
    ctx->engine               = engine;
    ctx->options              = options;
    ctx->fmap                 = root_map;
    ctx->recursion_stack      = layers;
    ctx->recursion_stack_size = layer_count;
}

START_TEST(test_maxscansize_exact_and_crossing_are_fail_visible)
{
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_scan_layer_t layers[1];
    cli_ctx ctx;
    fmap_t map;
    cl_error_t result;

    init_synthetic_limit_ctx(&engine, &options, &ctx, layers, 1, &map);
    engine.maxscansize = CLI_MAX_LARGE_FILESIZE;
    ctx.scansize       = CLI_MAX_LARGE_FILESIZE - 10;

    /* Consuming the last permitted byte is allowed and remains cacheable. */
    ck_assert_int_eq(cli_updatelimits(&ctx, 10), CL_SUCCESS);
    ck_assert_msg(ctx.scansize == CLI_MAX_LARGE_FILESIZE,
                  "exact MaxScanSize accounting narrowed at 32 GiB");
    ck_assert_uint_eq(ctx.scannedfiles, 1);
    ck_assert(!ctx.scan_incomplete);
    ck_assert(!ctx.limit_exceeded);
    ck_assert(!map.dont_cache_flag);

    /* The first byte beyond MaxScanSize is skipped and is never clean. */
    ck_assert_int_eq(cli_updatelimits(&ctx, 1), CL_EMAXSIZE);
    ck_assert_msg(ctx.scansize == CLI_MAX_LARGE_FILESIZE,
                  "crossing MaxScanSize changed the consumed byte count");
    ck_assert_uint_eq(ctx.scannedfiles, 1);
    ck_assert(ctx.scan_incomplete);
    ck_assert(ctx.limit_exceeded);
    ck_assert(map.dont_cache_flag);

    result = CL_SUCCESS;
    ck_assert(cli_scan_result_should_halt(&ctx, CL_EMAXSIZE, &result));
    ck_assert_int_eq(result, CL_EMAXSIZE);

    /* If a parser loses the immediate MAX code, the sticky configured-limit
     * cause still preserves the exact public result. */
    result = CL_SUCCESS;
    ck_assert(cli_scan_result_should_halt(&ctx, CL_SUCCESS, &result));
    ck_assert_int_eq(result, CL_EMAXSIZE);

    /* A zero MaxScanSize means unlimited: accounting must continue instead
     * of being clamped back to zero, and impossible native accumulation must
     * saturate rather than wrap. */
    init_synthetic_limit_ctx(&engine, &options, &ctx, layers, 1, &map);
    engine.maxscansize = 0;
    ctx.scansize       = 40;
    ck_assert_int_eq(cli_updatelimits(&ctx, 2), CL_SUCCESS);
    ck_assert_uint_eq(ctx.scansize, 42);
    ctx.scansize = UINT64_MAX - 2;
    ck_assert_int_eq(cli_updatelimits(&ctx, 7), CL_SUCCESS);
    ck_assert_uint_eq(ctx.scansize, UINT64_MAX);

    /* The remaining-space calculation must not wrap if a defensive caller
     * presents an already-over-limit accumulated count. */
    init_synthetic_limit_ctx(&engine, &options, &ctx, layers, 1, &map);
    engine.maxscansize = CLI_MAX_LARGE_FILESIZE;
    ctx.scansize       = CLI_MAX_LARGE_FILESIZE + 1;
    ck_assert_int_eq(cli_updatelimits(&ctx, 1), CL_EMAXSIZE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map.dont_cache_flag);

    /* Exercise cli_magic_scan's former early clean-return path without a
     * matcher, parser, allocation, or backing file. */
    init_synthetic_limit_ctx(&engine, &options, &ctx, layers, 1, &map);
    engine.dboptions   = CL_DB_COMPILED;
    engine.maxscansize = 10;
    map.len            = 11;
    ck_assert_int_eq(cli_magic_scan(&ctx, CL_TYPE_ANY), CL_EMAXSIZE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map.dont_cache_flag);
}
END_TEST

START_TEST(test_logical_views_do_not_consume_logical_scan_budget)
{
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_scan_layer_t layers[2];
    cli_ctx ctx;
    fmap_t root_map;
    fmap_t view_map;

    init_synthetic_limit_ctx(&engine, &options, &ctx, layers, 2, &root_map);
    memset(&view_map, 0, sizeof(view_map));
    engine.max_recursion_level = 2;
    engine.maxscansize         = 5;
    engine.maxfilesize         = 5;
    engine.maxfiles            = 1;
    ctx.scannedfiles           = 1;
    view_map.len               = 7;

    /* A normalized view can be larger than the remaining logical budget: it
     * is the same object, and its actual matcher bytes are accounted by the
     * matcher-work path rather than by MaxScanSize/MaxFiles. */
    ck_assert_int_eq(cli_recursion_stack_push(&ctx, &view_map, CL_TYPE_ANY, true,
                                              LAYER_ATTRIBUTES_NORMALIZED),
                     CL_SUCCESS);
    ck_assert_uint_eq(ctx.scansize, 0);
    ck_assert_uint_eq(ctx.scannedfiles, 1);
    ck_assert(!ctx.scan_incomplete);
    (void)cli_recursion_stack_pop(&ctx);

    /* HandlerType reclassification follows the same logical-object rule. */
    ck_assert_int_eq(cli_recursion_stack_push(&ctx, &view_map, CL_TYPE_ANY, true,
                                              LAYER_ATTRIBUTES_RETYPED),
                     CL_SUCCESS);
    ck_assert_uint_eq(ctx.scansize, 0);
    ck_assert_uint_eq(ctx.scannedfiles, 1);
    ck_assert(!ctx.scan_incomplete);
    (void)cli_recursion_stack_pop(&ctx);
}
END_TEST

START_TEST(test_maxfiles_exact_and_crossing_are_fail_visible)
{
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_scan_layer_t layers[1];
    cli_ctx ctx;
    fmap_t map;
    cl_error_t result;

    init_synthetic_limit_ctx(&engine, &options, &ctx, layers, 1, &map);
    engine.maxfiles  = 2;
    ctx.scannedfiles = 1;

    /* The file that reaches MaxFiles is allowed. */
    ck_assert_int_eq(cli_updatelimits(&ctx, 7), CL_SUCCESS);
    ck_assert_uint_eq(ctx.scannedfiles, 2);
    ck_assert_uint_eq(ctx.scansize, 7);
    ck_assert(!ctx.scan_incomplete);
    ck_assert(!map.dont_cache_flag);

    /* A subsequent file would cross the boundary and must be skipped visibly. */
    ck_assert_int_eq(cli_updatelimits(&ctx, 7), CL_EMAXFILES);
    ck_assert_uint_eq(ctx.scannedfiles, 2);
    ck_assert_uint_eq(ctx.scansize, 7);
    ck_assert(ctx.scan_incomplete);
    ck_assert(ctx.limit_exceeded);
    ck_assert(map.dont_cache_flag);

    result = CL_SUCCESS;
    ck_assert(cli_scan_result_should_halt(&ctx, CL_EMAXFILES, &result));
    ck_assert_int_eq(result, CL_EMAXFILES);

    /* The same boundary must remain visible through cli_magic_scan rather
     * than its historical status = CL_SUCCESS early return. */
    init_synthetic_limit_ctx(&engine, &options, &ctx, layers, 1, &map);
    engine.dboptions = CL_DB_COMPILED;
    engine.maxfiles  = 1;
    ctx.scannedfiles = 1;
    map.len          = 7;
    ck_assert_int_eq(cli_magic_scan(&ctx, CL_TYPE_ANY), CL_EMAXFILES);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map.dont_cache_flag);
}
END_TEST

START_TEST(test_maxrecursion_exact_and_crossing_are_fail_visible)
{
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_scan_layer_t layers[2];
    cli_ctx ctx;
    fmap_t root_map;
    fmap_t child_map;
    fmap_t grandchild_map;
    cl_error_t result;

    init_synthetic_limit_ctx(&engine, &options, &ctx, layers, 2, &root_map);
    memset(&child_map, 0, sizeof(child_map));
    memset(&grandchild_map, 0, sizeof(grandchild_map));
    engine.max_recursion_level = 2;
    child_map.len               = 7;
    grandchild_map.len          = 7;

    /* The final configured stack slot is usable. */
    ck_assert_int_eq(cli_recursion_stack_push(&ctx, &child_map, CL_TYPE_ANY, true, LAYER_ATTRIBUTES_NONE), CL_SUCCESS);
    ck_assert_uint_eq(ctx.recursion_level, 1);
    ck_assert(ctx.fmap == &child_map);
    ck_assert(!ctx.scan_incomplete);
    ck_assert(!root_map.dont_cache_flag);
    ck_assert(!child_map.dont_cache_flag);

    /* One more nested layer crosses MaxRecursion and taints every parent. */
    grandchild_map.len = 7;
    ck_assert_int_eq(cli_recursion_stack_push(&ctx, &grandchild_map, CL_TYPE_ANY, true, LAYER_ATTRIBUTES_NONE), CL_EMAXREC);
    ck_assert_uint_eq(ctx.recursion_level, 1);
    ck_assert(ctx.fmap == &child_map);
    ck_assert(ctx.scan_incomplete);
    ck_assert(ctx.limit_exceeded);
    ck_assert(root_map.dont_cache_flag);
    ck_assert(child_map.dont_cache_flag);

    /* A blocked nested child must not prevent this container layer from
     * scanning an independent sibling that may contain a detection. */
    result = CL_EMAXREC;
    ck_assert(!cli_scan_result_should_halt(&ctx, CL_EMAXREC, &result));
    ck_assert_int_eq(result, CL_SUCCESS);

    /* If no later sibling produces a stronger verdict, the root scan still
     * exposes the exact configured-limit result and remains non-cacheable. */
    ctx.recursion_level = 0;
    ctx.fmap            = &root_map;
    result = CL_SUCCESS;
    ck_assert(cli_scan_result_should_halt(&ctx, CL_SUCCESS, &result));
    ck_assert_int_eq(result, CL_EMAXREC);
}
END_TEST

START_TEST(test_configured_limit_result_precedence_and_alert_compatibility)
{
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_scan_layer_t layers[1];
    cli_ctx ctx;
    fmap_t map;
    cl_error_t result;

    init_synthetic_limit_ctx(&engine, &options, &ctx, layers, 1, &map);
    ctx.scan_incomplete = true;
    ctx.limit_exceeded  = true;
    map.dont_cache_flag = true;

    /* AlertExceedsMax keeps the established extended-API representation:
     * success plus a detection verdict. Legacy wrappers translate that
     * verdict to CL_VIRUS. The map remains explicitly non-cacheable. */
    options.heuristic = CL_SCAN_HEURISTIC_EXCEEDS_MAX;
    layers[0].verdict = CL_VERDICT_POTENTIALLY_UNWANTED;
    result            = CL_EMAXFILES;
    ck_assert(cli_scan_result_should_halt(&ctx, CL_EMAXFILES, &result));
    ck_assert_int_eq(result, CL_SUCCESS);
    ck_assert(map.dont_cache_flag);

    /* An option bit alone is insufficient: a filtered/ignored indicator must
     * fall back to the configured-limit error. */
    layers[0].verdict = CL_VERDICT_NOTHING_FOUND;
    result            = CL_SUCCESS;
    ck_assert(cli_scan_result_should_halt(&ctx, CL_EMAXFILES, &result));
    ck_assert_int_eq(result, CL_EMAXFILES);

    /* Detection, critical-resource, and timeout results remain stronger than
     * either the configured-limit error or its heuristic representation. */
    layers[0].verdict = CL_VERDICT_POTENTIALLY_UNWANTED;
    result            = CL_SUCCESS;
    ck_assert(cli_scan_result_should_halt(&ctx, CL_VIRUS, &result));
    ck_assert_int_eq(result, CL_VIRUS);

    result = CL_SUCCESS;
    ck_assert(cli_scan_result_should_halt(&ctx, CL_EMEM, &result));
    ck_assert_int_eq(result, CL_EMEM);

    ctx.scan_timed_out = true;
    result             = CL_SUCCESS;
    ck_assert(cli_scan_result_should_halt(&ctx, CL_EMAXSIZE, &result));
    ck_assert_int_eq(result, CL_ETIMEOUT);
}
END_TEST

START_TEST(test_callback_abort_is_not_reported_as_timeout)
{
    cli_scan_layer_t layers[1];
    cli_ctx ctx;
    fmap_t map;
    cl_error_t result;

    memset(layers, 0, sizeof(layers));
    memset(&ctx, 0, sizeof(ctx));
    memset(&map, 0, sizeof(map));
    layers[0].fmap           = &map;
    ctx.fmap                 = &map;
    ctx.recursion_stack      = layers;
    ctx.recursion_stack_size = 1;
    ctx.abort_scan           = true;

    result = CL_BREAK;
    ck_assert(cli_scan_result_should_halt(&ctx, CL_BREAK, &result));
    ck_assert_int_eq(result, CL_SUCCESS);

    /* Some archive parsers normalize CL_BREAK while unwinding. The sticky
     * abort must still stop outer layers without inventing a timeout. */
    result = CL_BREAK;
    ck_assert(cli_scan_result_should_halt(&ctx, CL_SUCCESS, &result));
    ck_assert_int_eq(result, CL_SUCCESS);

    /* An explicit timeout still takes precedence if it follows a callback
     * abort before the scan finishes unwinding. */
    result = CL_SUCCESS;
    ck_assert(cli_scan_result_should_halt(&ctx, CL_ETIMEOUT, &result));
    ck_assert_int_eq(result, CL_ETIMEOUT);
}
END_TEST

START_TEST(test_timeout_policy_is_fail_visible)
{
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_scan_layer_t layers[1];
    cli_ctx ctx;
    fmap_t map;
    cl_error_t result;

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(layers, 0, sizeof(layers));
    memset(&ctx, 0, sizeof(ctx));
    memset(&map, 0, sizeof(map));
    engine.maxscantime       = 1;
    layers[0].fmap           = &map;
    ctx.engine               = &engine;
    ctx.options              = &options;
    ctx.fmap                 = &map;
    ctx.recursion_stack      = layers;
    ctx.recursion_stack_size = 1;

    ck_assert_int_eq(gettimeofday(&ctx.time_limit, NULL), 0);
    ctx.time_limit.tv_sec--;
    ck_assert_int_eq(cli_checktimelimit(&ctx), CL_ETIMEOUT);
    ck_assert(ctx.abort_scan);
    ck_assert(ctx.scan_timed_out);

    result = CL_SUCCESS;
    ck_assert(cli_scan_result_should_halt(&ctx, CL_SUCCESS, &result));
    ck_assert_int_eq(result, CL_ETIMEOUT);

    result = CL_SUCCESS;
    ck_assert(cli_scan_result_should_halt(&ctx, CL_ETIMEOUT, &result));
    ck_assert_int_eq(result, CL_ETIMEOUT);

    result = CL_SUCCESS;
    ck_assert(cli_scan_result_should_halt(&ctx, CL_VIRUS, &result));
    ck_assert_int_eq(result, CL_VIRUS);

    result = CL_SUCCESS;
    ck_assert(cli_scan_result_should_halt(&ctx, CL_EMEM, &result));
    ck_assert_int_eq(result, CL_EMEM);

    /* A parser may mark the scan incomplete before the deadline expires.
     * Preserve the more specific terminal timeout during finalization. */
    ctx.scan_incomplete = true;
    result              = CL_SUCCESS;
    ck_assert(cli_scan_result_should_halt(&ctx, CL_SUCCESS, &result));
    ck_assert_int_eq(result, CL_ETIMEOUT);
}
END_TEST

START_TEST(test_parser_error_statuses_are_fail_closed)
{
    static const cl_error_t parser_errors[] = {
        CL_ERROR, CL_EOPEN, CL_ECREAT, CL_EACCES, CL_EMAP,
        CL_EFORMAT, CL_EPARSE, CL_EREAD, CL_EUNPACK};
    cli_scan_layer_t layers[1];
    cli_ctx ctx;
    fmap_t map;
    cl_error_t result;
    size_t i;

    memset(layers, 0, sizeof(layers));
    memset(&ctx, 0, sizeof(ctx));
    memset(&map, 0, sizeof(map));
    layers[0].fmap           = &map;
    ctx.fmap                 = &map;
    ctx.recursion_stack      = layers;
    ctx.recursion_stack_size = 1;

    for (i = 0; i < sizeof(parser_errors) / sizeof(parser_errors[0]); i++) {
        ctx.scan_incomplete        = false;
        ctx.scan_incomplete_reason = NULL;
        map.dont_cache_flag        = false;
        result                     = CL_SUCCESS;

        ck_assert(cli_scan_result_should_halt(&ctx, parser_errors[i], &result));
        ck_assert_int_eq(result, parser_errors[i]);
        ck_assert(ctx.scan_incomplete);
        ck_assert(map.dont_cache_flag);
    }
}
END_TEST

#ifndef _WIN32
START_TEST(test_action_setup_quarantine_lock_uses_validated_directory_handle)
{
    char *parent_dir          = NULL;
    char *validated_path      = NULL;
    char *validated_saved     = NULL;
    char *replacement_lock    = NULL;
    char *lockname            = NULL;
    int validated_fd          = -1;
    struct stat lock_stat     = {0};

    parent_dir = cli_gentemp(NULL);
    ck_assert_msg(NULL != parent_dir, "cli_gentemp failed");
    ck_assert_msg(0 == mkdir(parent_dir, 0700), "mkdir(%s) failed", parent_dir);

    validated_path = cli_newfilepath(parent_dir, "quarantine");
    validated_saved = cli_newfilepath(parent_dir, "quarantine-original");
    ck_assert_msg((NULL != validated_path) && (NULL != validated_saved), "Failed to allocate quarantine paths");

    ck_assert_msg(0 == mkdir(validated_path, 0700), "mkdir(%s) failed", validated_path);

    validated_fd = open(validated_path, O_RDONLY | O_NOFOLLOW);
    ck_assert_msg(-1 != validated_fd, "open(%s) failed: %s", validated_path, strerror(errno));

    ck_assert_msg(0 == rename(validated_path, validated_saved), "rename(%s, %s) failed: %s",
                  validated_path, validated_saved, strerror(errno));
    ck_assert_msg(0 == mkdir(validated_path, 0700), "mkdir(%s) replacement failed: %s",
                  validated_path, strerror(errno));

    ck_assert_msg(0 == action_setup_quarantine_lock_at(validated_fd, validated_path, &lockname),
                  "action_setup_quarantine_lock_at failed");
    ck_assert_msg(NULL != lockname, "action_setup_quarantine_lock_at did not return a lock name");

    ck_assert_msg(0 == fstatat(validated_fd, lockname, &lock_stat, AT_SYMLINK_NOFOLLOW),
                  "fstatat(validated_fd, %s) failed: %s", lockname, strerror(errno));
    ck_assert_msg(S_ISREG(lock_stat.st_mode), "Expected quarantine lock to be a regular file");

    replacement_lock = cli_newfilepath(validated_path, lockname);
    ck_assert_msg(NULL != replacement_lock, "Failed to allocate replacement lock path");
    ck_assert_msg(0 != access(replacement_lock, F_OK),
                  "Lock file was created in the replacement quarantine path");

    ck_assert_msg(0 == unlinkat(validated_fd, lockname, 0), "unlinkat(validated_fd, %s) failed: %s",
                  lockname, strerror(errno));
    free(lockname);
    lockname = NULL;

    close(validated_fd);
    validated_fd = -1;

    cli_rmdirs(parent_dir);
    free(replacement_lock);
    free(validated_saved);
    free(validated_path);
    free(parent_dir);
}
END_TEST

START_TEST(test_action_source_open_relative_path_stores_absolute_action_path)
{
    const char *relative_path = "payload";
    char *parent_dir          = NULL;
    char *file_path           = NULL;
    int cwd_fd                = -1;
    int fd                    = -1;
    action_source_t source;

    action_source_init(&source);

    /* Keep the source argument relative without writing under CTest's source
     * working directory, which may intentionally be mounted read-only. */
    parent_dir = cli_gentemp(NULL);
    ck_assert_msg(NULL != parent_dir, "cli_gentemp failed");
    ck_assert_msg(0 == mkdir(parent_dir, 0700), "mkdir(%s) failed: %s", parent_dir, strerror(errno));

    file_path = cli_newfilepath(parent_dir, "payload");
    ck_assert_msg(NULL != file_path, "Failed to allocate payload path");

    fd = open(file_path, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0600);
    ck_assert_msg(-1 != fd, "open(%s) failed: %s", file_path, strerror(errno));
    ck_assert_msg(4 == write(fd, "test", 4), "write(%s) failed: %s", file_path, strerror(errno));
    close(fd);
    fd = -1;

    cwd_fd = open(".", O_RDONLY | O_BINARY);
    ck_assert_msg(-1 != cwd_fd, "open current working directory failed: %s", strerror(errno));
    ck_assert_msg(0 == chdir(parent_dir), "chdir(%s) failed: %s", parent_dir, strerror(errno));
    ck_assert_msg(CL_SUCCESS == action_source_open(relative_path, &source),
                  "action_source_open(%s) failed", relative_path);
    ck_assert_msg(0 == fchdir(cwd_fd), "fchdir failed: %s", strerror(errno));
    close(cwd_fd);
    cwd_fd = -1;
    ck_assert_msg(NULL != source.action_path, "action_source_open did not populate action_path");
    ck_assert_msg('/' == source.action_path[0],
                  "Expected absolute action_path for relative source path, got '%s'", source.action_path);

    action_source_close(&source);

    ck_assert_msg(0 == unlink(file_path), "unlink(%s) failed: %s", file_path, strerror(errno));
    free(file_path);
    file_path = NULL;
    ck_assert_msg(0 == rmdir(parent_dir), "rmdir(%s) failed: %s", parent_dir, strerror(errno));
    free(parent_dir);
    parent_dir = NULL;
}
END_TEST

START_TEST(test_action_source_open_path_rejects_replaced_symlink)
{
    char *parent_dir       = NULL;
    char *file_path        = NULL;
    char *replacement_path = NULL;
    char *resolved_path    = NULL;
    int fd                 = -1;
    action_source_t source;

    action_source_init(&source);

    parent_dir = cli_gentemp(NULL);
    ck_assert_msg(NULL != parent_dir, "cli_gentemp failed");
    ck_assert_msg(0 == mkdir(parent_dir, 0700), "mkdir(%s) failed: %s", parent_dir, strerror(errno));

    file_path = cli_newfilepath(parent_dir, "payload");
    replacement_path = cli_newfilepath(parent_dir, "replacement");
    ck_assert_msg((NULL != file_path) && (NULL != replacement_path), "Failed to allocate test paths");

    fd = open(file_path, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0600);
    ck_assert_msg(-1 != fd, "open(%s) failed: %s", file_path, strerror(errno));
    ck_assert_msg(7 == write(fd, "payload", 7), "write(%s) failed: %s", file_path, strerror(errno));
    close(fd);
    fd = -1;

    ck_assert_msg(CL_SUCCESS == cli_realpath(file_path, &resolved_path),
                  "cli_realpath(%s) failed", file_path);

    fd = open(replacement_path, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0600);
    ck_assert_msg(-1 != fd, "open(%s) failed: %s", replacement_path, strerror(errno));
    ck_assert_msg(11 == write(fd, "replacement", 11), "write(%s) failed: %s", replacement_path, strerror(errno));
    close(fd);
    fd = -1;

    ck_assert_msg(0 == unlink(file_path), "unlink(%s) failed: %s", file_path, strerror(errno));
    ck_assert_msg(0 == symlink(replacement_path, file_path), "symlink(%s, %s) failed: %s",
                  replacement_path, file_path, strerror(errno));

    ck_assert_msg(CL_SUCCESS != action_source_open_path(file_path, resolved_path, &source),
                  "action_source_open_path accepted a resolved path that had been replaced by a symlink");

    action_source_close(&source);

    ck_assert_msg(0 == unlink(file_path), "unlink(%s) symlink failed: %s", file_path, strerror(errno));
    ck_assert_msg(0 == unlink(replacement_path), "unlink(%s) failed: %s", replacement_path, strerror(errno));
    free(resolved_path);
    free(replacement_path);
    free(file_path);
    ck_assert_msg(0 == rmdir(parent_dir), "rmdir(%s) failed: %s", parent_dir, strerror(errno));
    free(parent_dir);
}
END_TEST

START_TEST(test_action_source_close_reports_descriptor_failure)
{
    action_source_t source;
    char *path = NULL;
    int fd = -1;

    action_source_init(&source);
    path = cli_gentemp(NULL);
    ck_assert_ptr_nonnull(path);

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0600);
    ck_assert_int_ge(fd, 0);
    ck_assert_int_eq(write(fd, "test", 4), 4);
    ck_assert_int_eq(close(fd), 0);

    ck_assert_int_eq(action_source_open(path, &source), CL_SUCCESS);
    ck_assert_int_eq(close(source.scan_fd), 0);
    ck_assert_int_eq(action_source_close(&source), CL_EREAD);
    ck_assert_int_eq(source.scan_fd, -1);

    ck_assert_int_eq(unlink(path), 0);
    free(path);
}
END_TEST
#endif

static char **testfiles     = NULL;
static unsigned testfiles_n = 0;

static const int expected_testfiles = 53;

static unsigned skip_files(void)
{
    unsigned skipped = 0;

    /* skip .rar files if unrar is disabled */
#if HAVE_UNRAR
#else
    skipped += 2;
#endif

    return skipped;
}

static void init_testfiles(void)
{
    struct dirent *dirent;
    unsigned i = 0;
    int expect = expected_testfiles;

    DIR *d = opendir(OBJDIR PATHSEP "input" PATHSEP "clamav_hdb_scanfiles");
    ck_assert_msg(!!d, "opendir");
    if (!d)
        return;
    testfiles   = NULL;
    testfiles_n = 0;
    while ((dirent = readdir(d))) {
        if (strncmp(dirent->d_name, "clam", 4))
            continue;
        i++;
        testfiles = cli_safer_realloc(testfiles, i * sizeof(*testfiles));
        ck_assert_msg(!!testfiles, "cli_safer_realloc");
        testfiles[i - 1] = strdup(dirent->d_name);
    }
    testfiles_n = i;
    if (get_fpu_endian() == FPU_ENDIAN_UNKNOWN)
        expect--;
    expect -= skip_files();
    ck_assert_msg(testfiles_n == expect, "testfiles: %d != %d", testfiles_n, expect);

    closedir(d);
}

static void free_testfiles(void)
{
    unsigned i;
    for (i = 0; i < testfiles_n; i++) {
        free(testfiles[i]);
    }
    free(testfiles);
    testfiles   = NULL;
    testfiles_n = 0;
}

static int inited = 0;

static void engine_setup(void)
{
    unsigned int sigs = 0;
    const char *hdb   = OBJDIR PATHSEP "input" PATHSEP "clamav.hdb";

    init_testfiles();
    if (!inited)
        ck_assert_msg(cl_init(CL_INIT_DEFAULT) == 0, "cl_init");
    inited   = 1;
    g_engine = cl_engine_new();
    ck_assert_msg(!!g_engine, "engine");
    tmpdir = cli_gentemp(NULL);
    ck_assert_msg(!!tmpdir, "cli_gentemp failed");
    ck_assert_int_eq(mkdir(tmpdir, 0700), 0);
    ck_assert_msg(cl_load(hdb, g_engine, &sigs, CL_DB_STDOPT) == 0, "cl_load %s", hdb);
    ck_assert_msg(sigs == 1, "sigs");
    /* Keep the scan-API fixture independent of any process-level dynamic
     * configuration state. Its embedded OneNote signature is a required
     * qualification path, so explicitly enable the document parser on the
     * fresh test engine. */
    g_engine->dconf->doc  |= DOC_CONF_ONENOTE;
    g_engine->dconf->mail |= MAIL_CONF_MBOX;
    /* The scan-API qualification fixture exercises the planned large-file
     * parser gates without activating those defaults before release
     * qualification is complete. Keep the legacy top-level MaxFileSize and
     * MaxScanSize unchanged so their boundary tests remain meaningful. */
    g_engine->maxembeddedpe      = CLI_MAX_LARGE_FILESIZE;
    g_engine->maxhtmlnormalize   = CLI_MAX_LARGE_FILESIZE;
    g_engine->maxhtmlnotags      = CLI_MAX_LARGE_FILESIZE;
    g_engine->maxscriptnormalize = CLI_MAX_LARGE_FILESIZE;
    g_engine->maxziptypercg      = CLI_MAX_LARGE_FILESIZE;
    g_engine->pcre_max_filesize  = CLI_MAX_LARGE_FILESIZE;
    ck_assert_msg(cl_engine_compile(g_engine) == 0, "cl_engine_compile");
}

static void engine_teardown(void)
{
    free_testfiles();
    cl_engine_free(g_engine);
    cli_rmdirs(tmpdir);
    free(tmpdir);
    tmpdir = NULL;
}

START_TEST(test_clean_cache_distinguishes_large_sizes)
{
    cli_ctx ctx;
    fmap_t map;
    struct cl_scan_options options;
    uint8_t hash[SHA256_HASH_SIZE];
    size_t large_size = (size_t)UINT32_MAX + 1;

    memset(&ctx, 0, sizeof(ctx));
    memset(&map, 0, sizeof(map));
    memset(&options, 0, sizeof(options));
    memset(hash, 0xa5, sizeof(hash));

    ck_assert_msg(NULL != g_engine->cache, "clean cache was not initialized");
    ck_assert_msg(CL_SUCCESS == fmap_set_hash(&map, hash, CLI_HASH_SHA2_256), "failed to seed synthetic fmap hash");

    map.len     = large_size;
    ctx.engine  = g_engine;
    ctx.fmap    = &map;
    ctx.options = &options;

    clean_cache_add(&ctx);
    ck_assert_msg(CL_CLEAN == clean_cache_check(&ctx), "large clean-cache entry was not found");

    clean_cache_remove(hash, large_size, g_engine);
    ctx.scan_incomplete = true;
    ck_assert_msg(CL_VIRUS == clean_cache_check(&ctx), "incomplete scan was allowed to use clean cache");
    clean_cache_add(&ctx);
    ctx.scan_incomplete = false;
    ck_assert_msg(CL_VIRUS == clean_cache_check(&ctx), "incomplete scan was added to clean cache");

    clean_cache_add(&ctx);
    ck_assert_msg(CL_CLEAN == clean_cache_check(&ctx), "clean scan was not restored to cache");

    map.len = 0;
    ck_assert_msg(CL_VIRUS == clean_cache_check(&ctx), "large clean-cache size aliased its truncated 32-bit value");

    map.len = large_size;
    clean_cache_remove(hash, large_size, g_engine);
    ck_assert_msg(CL_VIRUS == clean_cache_check(&ctx), "large clean-cache entry was not removed");
}
END_TEST

START_TEST(test_stats_preserves_large_sample_size)
{
    cli_intel_t *intel = (cli_intel_t *)g_engine->stats_data;
    unsigned char md5[MD5_HASH_SIZE];
    uint32_t old_stats_flags = g_engine->dconf->stats;
    uint32_t old_maxsamples;
    uint32_t old_maxmem;
    size_t large_size = (size_t)UINT32_MAX + 123;
    char expected[64];
    char *json;

    ck_assert_msg(NULL != intel, "stats state was not initialized");
    memset(md5, 0x5a, sizeof(md5));
    clamav_stats_flush(g_engine, intel);

    old_maxsamples = intel->maxsamples;
    old_maxmem     = intel->maxmem;
    intel->maxsamples = UINT32_MAX;
    intel->maxmem     = UINT32_MAX;
    g_engine->dconf->stats &= ~DCONF_STATS_DISABLED;

    clamav_stats_add_sample("Large.Sample", md5, large_size, NULL, intel);
    ck_assert_msg(NULL != intel->samples, "large stats sample was not recorded");
    ck_assert_msg((uint64_t)large_size == intel->samples->size, "large stats sample size was truncated");

    json = export_stats_to_json(g_engine, intel);
    ck_assert_msg(NULL != json, "large stats sample JSON was not produced");
    snprintf(expected, sizeof(expected), "\"size\": " STDu64, (uint64_t)large_size);
    ck_assert_msg(NULL != strstr(json, expected), "large stats sample JSON size was truncated: %s", json);
    free(json);

    clamav_stats_flush(g_engine, intel);
    intel->maxsamples       = old_maxsamples;
    intel->maxmem           = old_maxmem;
    g_engine->dconf->stats  = old_stats_flags;
}
END_TEST

static int get_test_file(int i, char *file, unsigned fsize, unsigned long *size)
{
    int fd;
    STATBUF st;

    ck_assert_msg(i < testfiles_n, "%i < %i %s", i, testfiles_n, file);
    snprintf(file, fsize, OBJDIR PATHSEP "input" PATHSEP "clamav_hdb_scanfiles" PATHSEP "%s", testfiles[i]);

    fd = open(file, O_RDONLY | O_BINARY);
    ck_assert_msg(fd > 0, "open");
    ck_assert_msg(FSTAT(fd, &st) == 0, "fstat");
    *size = st.st_size;
    return fd;
}

#ifndef _WIN32
static off_t pread_cb(void *handle, void *buf, size_t count, off_t offset)
{
    return pread(*((int *)handle), buf, count, offset);
}

struct offset_pread_state {
    const unsigned char *data;
    size_t length;
    off_t source_offset;
};

static off_t offset_pread_cb(void *handle, void *buf, size_t count, off_t offset)
{
    struct offset_pread_state *state = handle;
    size_t relative;

    if (offset < state->source_offset ||
        (uint64_t)(offset - state->source_offset) >= state->length)
        return 0;

    relative = (size_t)(offset - state->source_offset);
    if (count > state->length - relative)
        count = state->length - relative;
    memcpy(buf, state->data + relative, count);
    return (off_t)count;
}

START_TEST(test_fmap_handle_accepts_tail_window_at_large_source_offset)
{
    static const unsigned char data[] = "tail-window";
    struct offset_pread_state state;
    cl_fmap_t *map;
    const unsigned char *window;

    state.data          = data;
    state.length        = sizeof(data) - 1U;
    state.source_offset = (off_t)4096;

    map = cl_fmap_open_handle(&state, (size_t)state.source_offset, state.length,
                              offset_pread_cb, 0);
    ck_assert_ptr_nonnull(map);
    window = fmap_need_off_once(map, 0, state.length);
    ck_assert_ptr_nonnull(window);
    ck_assert_int_eq(memcmp(window, data, state.length), 0);
    cl_fmap_close(map);
}
END_TEST

#ifdef ANONYMOUS_MAP
#define TEST_FM_MASK_PAGED 0x40000000U
#define TEST_FMAP_AGING_SCAN_BUDGET 8192U
#define TEST_FMAP_AGING_FREE_BUDGET 4096U

struct synthetic_pread_state {
    size_t length;
    off_t fail_at;
    unsigned int reads;
};

static unsigned char synthetic_byte_at(size_t offset)
{
    unsigned char value = (unsigned char)(((offset / 4096) + 1) & 0xff);

    return value ? value : 0xa5;
}

static off_t synthetic_pread_cb(void *handle, void *buf, size_t count, off_t offset)
{
    struct synthetic_pread_state *state = handle;
    unsigned char *out                 = buf;
    size_t original_count;
    size_t position;
    size_t chunk;

    state->reads++;
    if (state->fail_at >= 0 && offset >= state->fail_at) {
        errno = EIO;
        return -1;
    }
    if (offset < 0 || (uint64_t)offset >= state->length)
        return 0;
    if (count > state->length - (size_t)offset)
        count = state->length - (size_t)offset;

    original_count = count;
    position       = (size_t)offset;
    while (count > 0) {
        chunk = MIN(count, 4096 - (position % 4096));
        memset(out, synthetic_byte_at(position), chunk);
        out += chunk;
        position += chunk;
        count -= chunk;
    }
    return (off_t)original_count;
}

static uint64_t synthetic_count_paged(const cl_fmap_t *map)
{
    uint64_t count = 0;
    uint64_t page;

    for (page = 0; page < map->pages; page++) {
        if (map->bitmap[page] & TEST_FM_MASK_PAGED)
            count++;
    }
    return count;
}

START_TEST(test_fmap_aging_is_bounded_and_wraps)
{
    struct synthetic_pread_state state;
    cl_fmap_t *map;
    cl_fmap_t *duplicate;
    const unsigned char *data;
    uint64_t max_paged = 0;
    unsigned int reads_before;
    int wrapped     = 0;
    int saw_release = 0;
    size_t offset;
    size_t request;
    size_t length = 40 * 1024 * 1024;

    memset(&state, 0, sizeof(state));
    state.length  = length;
    state.fail_at = -1;
    map = cl_fmap_open_handle(&state, 0, length, synthetic_pread_cb, 1);
    ck_assert_ptr_nonnull(map);
    ck_assert(map->aging_owner == map);
    ck_assert_msg(map->pages > TEST_FMAP_AGING_SCAN_BUDGET, "test fmap must exceed one aging scan budget");

    /* Seed the last page before the map exceeds the high-water mark. This
     * makes a forced cursor wrap flush a one-page range immediately before
     * it visits page zero. */
    data = fmap_need_off_once(map, length - 4096, 4096);
    ck_assert_ptr_nonnull(data);
    ck_assert_uint_eq(data[0], synthetic_byte_at(length - 4096));

    duplicate = fmap_duplicate(map, 0, length, NULL);
    ck_assert_ptr_nonnull(duplicate);
    ck_assert(duplicate->aging_owner == map);

    /* fmap_get_hash() uses ten-megabyte windows, while raw matching uses
     * smaller windows. Exercise the larger case so neither path can grow
     * resident memory from one pass to the next. */
    for (offset = 0; offset < length; offset += 10 * 1024 * 1024) {
        request = MIN(length - offset, (size_t)(10 * 1024 * 1024));
        data    = fmap_need_off_once(duplicate, offset, request);
        ck_assert_ptr_nonnull(data);
        ck_assert_uint_eq(data[0], synthetic_byte_at(offset));
        ck_assert_uint_eq(map->paged, synthetic_count_paged(map));
        ck_assert_msg(map->aging_scanned_last <= TEST_FMAP_AGING_SCAN_BUDGET,
                      "fmap aging inspected %llu bitmap entries", (unsigned long long)map->aging_scanned_last);
        ck_assert_msg(map->aging_released_last <= TEST_FMAP_AGING_FREE_BUDGET,
                      "fmap aging released %llu pages", (unsigned long long)map->aging_released_last);
        if (map->aging_released_last > 0)
            saw_release = 1;
        if (map->paged > max_paged)
            max_paged = map->paged;

        if (!wrapped && map->paged > (8 * 1024 * 1024) / map->pgsz) {
            /* The last page is resident. Releasing across the cursor wrap must
             * update its bitmap state so this request performs another read. */
            map->aging_cursor = map->pages - 1;
            reads_before      = state.reads;
            data              = fmap_need_off_once(duplicate, length - 4096, 4096);
            ck_assert_ptr_nonnull(data);
            ck_assert_uint_eq(data[0], synthetic_byte_at(length - 4096));
            ck_assert_msg(state.reads > reads_before, "wrapped eviction returned anonymous zero data without re-reading");
            ck_assert_uint_eq(map->paged, synthetic_count_paged(map));
            ck_assert_msg(map->aging_scanned_last <= TEST_FMAP_AGING_SCAN_BUDGET,
                          "wrapped aging inspected %llu bitmap entries", (unsigned long long)map->aging_scanned_last);
            ck_assert_msg(map->aging_released_last > 0 && map->aging_released_last <= TEST_FMAP_AGING_FREE_BUDGET,
                          "wrapped aging released %llu pages", (unsigned long long)map->aging_released_last);
            ck_assert_msg(map->aging_cursor < map->pages - 1, "aging cursor did not wrap");
            wrapped     = 1;
            saw_release = 1;
        }
    }
    ck_assert_msg(max_paged <= (16 * 1024 * 1024) / map->pgsz,
                  "fmap retained %llu pages during a sequential scan", (unsigned long long)max_paged);
    ck_assert(wrapped);
    ck_assert(saw_release);

    free_duplicate_fmap(duplicate);
    cl_fmap_close(map);
}
END_TEST

START_TEST(test_fmap_gets_releases_read_pages)
{
    struct synthetic_pread_state state;
    cl_fmap_t *map;
    unsigned char buffer[4096];
    size_t at = 0;
    size_t length = 40 * 1024 * 1024;
    uint64_t max_paged = 0;

    memset(&state, 0, sizeof(state));
    state.length  = length;
    state.fail_at = -1;
    map = cl_fmap_open_handle(&state, 0, length, synthetic_pread_cb, 1);
    ck_assert_ptr_nonnull(map);

    while (at < length) {
        size_t previous_at = at;
        const unsigned char *result = fmap_gets(map, (char *)buffer, &at, sizeof(buffer));

        ck_assert_ptr_nonnull(result);
        ck_assert_msg(at > previous_at, "fmap_gets did not advance at");
        ck_assert_uint_eq(buffer[0], synthetic_byte_at(previous_at));
        if (map->paged > max_paged)
            max_paged = map->paged;
    }

    ck_assert_msg(max_paged <= 2, "fmap_gets retained %llu pages", (unsigned long long)max_paged);
    cl_fmap_close(map);
}
END_TEST

START_TEST(test_fmap_release_unlocked_evicts_whole_subject_pages)
{
    struct synthetic_pread_state state;
    cl_fmap_t *map;
    const unsigned char *data;
    unsigned int reads_before;
    size_t length = 16 * 1024 * 1024;

    memset(&state, 0, sizeof(state));
    state.length  = length;
    state.fail_at = -1;
    map = cl_fmap_open_handle(&state, 0, length, synthetic_pread_cb, 1);
    ck_assert_ptr_nonnull(map);

    data = fmap_need_off_once(map, 0, length);
    ck_assert_ptr_nonnull(data);
    ck_assert_uint_eq(data[0], synthetic_byte_at(0));
    ck_assert_msg(map->paged > 0, "whole-subject request did not page input");

    fmap_release_unlocked(map);
    ck_assert_uint_eq(map->paged, 0);
    ck_assert_uint_eq(synthetic_count_paged(map), 0);

    reads_before = state.reads;
    data         = fmap_need_off_once(map, 0, 4096);
    ck_assert_ptr_nonnull(data);
    ck_assert_uint_eq(data[0], synthetic_byte_at(0));
    ck_assert_msg(state.reads > reads_before, "evicted pages were not re-read");

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_metadata_hash_read_failure_is_fail_visible)
{
    struct synthetic_pread_state state;
    struct cl_engine *engine;
    struct cl_scan_options options;
    cl_fmap_t *map;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    const size_t hash_window = 10U * 1024U * 1024U;
    cl_error_t ret;

    memset(&state, 0, sizeof(state));
    state.length  = hash_window + 1U;
    state.fail_at = (off_t)hash_window;
    memset(&options, 0, sizeof(options));
    options.general = CL_SCAN_GENERAL_COLLECT_METADATA;

    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    engine = cl_engine_new();
    ck_assert_ptr_nonnull(engine);
    ck_assert_int_eq(cl_engine_compile(engine), CL_SUCCESS);
    map = cl_fmap_open_handle(&state, 0, state.length, synthetic_pread_cb, 1);
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        engine, &options, NULL, NULL, NULL, NULL,
                        "CL_TYPE_TEXT", NULL);
    ck_assert_msg(ret != CL_SUCCESS, "metadata hash read failure normalized to clean");
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert_msg(state.reads >= 2, "metadata hash did not reach the injected failing window");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(engine);
}
END_TEST
#endif /* ANONYMOUS_MAP */

struct authenticode_hash_map_state {
    const uint8_t *data;
    size_t data_length;
    size_t fail_at;
    size_t calls;
    size_t max_request;
    size_t last_offset;
    bool repeat_data;
};

static const void *authenticode_hash_test_need(fmap_t *map, size_t at, size_t len, int lock)
{
    struct authenticode_hash_map_state *state = map->handle;

    UNUSEDPARAM(lock);
    state->calls++;
    state->last_offset = at;
    if (len > state->max_request)
        state->max_request = len;

    if (at >= state->fail_at)
        return NULL;

    if (state->repeat_data)
        return len <= state->data_length ? state->data : NULL;

    if (at > state->data_length || len > state->data_length - at)
        return NULL;
    return state->data + at;
}

START_TEST(test_authenticode_hash_regions_are_native_and_bounded)
{
    size_t length = (size_t)CLI_AUTHENTICODE_HASH_CHUNK_SIZE + 257;
    uint8_t *data;
    uint8_t expected[SHA256_HASH_SIZE];
    uint8_t actual[SHA256_HASH_SIZE];
    uint8_t high_data[64];
    struct authenticode_hash_map_state state;
    struct cli_mapped_region region;
    fmap_t map;
    void *hash_ctx;
    cl_error_t status;
    size_t i;

    data = malloc(length);
    ck_assert_ptr_nonnull(data);
    for (i = 0; i < length; i++)
        data[i] = (uint8_t)((i * 37U + 11U) & 0xffU);

    memset(&state, 0, sizeof(state));
    memset(&map, 0, sizeof(map));
    state.data        = data;
    state.data_length = length;
    state.fail_at     = SIZE_MAX;
    map.handle        = &state;
    map.need          = authenticode_hash_test_need;
    map.len           = length;
    region.offset     = 0;
    region.size       = length;

    hash_ctx = cl_hash_init("sha2-256");
    ck_assert_ptr_nonnull(hash_ctx);
    status = cli_hash_mapped_regions(&map, hash_ctx, &region, 1, NULL);
    ck_assert_int_eq(status, CL_SUCCESS);
    cl_finish_hash(hash_ctx, actual);
    ck_assert_ptr_nonnull(cl_sha256(data, length, expected, NULL));
    ck_assert_msg(0 == memcmp(actual, expected, sizeof(actual)), "chunked Authenticode digest changed byte semantics");
    ck_assert_msg(state.calls == 2, "expected two bounded hash reads, got %zu", state.calls);
    ck_assert_msg(state.max_request == CLI_AUTHENTICODE_HASH_CHUNK_SIZE,
                  "AuthentiCode hash requested %zu bytes at once", state.max_request);

    for (i = 0; i < sizeof(high_data); i++)
        high_data[i] = (uint8_t)(0xa0U + i);
    memset(&state, 0, sizeof(state));
    memset(&map, 0, sizeof(map));
    state.data        = high_data;
    state.data_length = sizeof(high_data);
    state.fail_at     = SIZE_MAX;
    state.repeat_data = true;
    map.handle        = &state;
    map.need          = authenticode_hash_test_need;
    map.len           = (size_t)UINT32_MAX + 4096;
    region.offset     = (size_t)UINT32_MAX + 128;
    region.size       = sizeof(high_data);

    hash_ctx = cl_hash_init("sha2-256");
    ck_assert_ptr_nonnull(hash_ctx);
    status = cli_hash_mapped_regions(&map, hash_ctx, &region, 1, NULL);
    ck_assert_int_eq(status, CL_SUCCESS);
    cl_finish_hash(hash_ctx, actual);
    ck_assert_ptr_nonnull(cl_sha256(high_data, sizeof(high_data), expected, NULL));
    ck_assert_msg(0 == memcmp(actual, expected, sizeof(actual)), "native-width hash region produced the wrong digest");
    ck_assert_msg(state.last_offset == region.offset,
                  "native-width hash offset was narrowed from %zu to %zu", region.offset, state.last_offset);

    free(data);
}
END_TEST

START_TEST(test_authenticode_hash_failure_is_fail_visible)
{
    size_t length = (size_t)CLI_AUTHENTICODE_HASH_CHUNK_SIZE + 64;
    uint8_t *data;
    struct authenticode_hash_map_state state;
    struct cli_mapped_region regions[2];
    cli_scan_layer_t layer;
    cli_ctx ctx;
    fmap_t map;
    void *hash_ctx;
    cl_error_t status;

    data = calloc(1, length);
    ck_assert_ptr_nonnull(data);
    memset(&state, 0, sizeof(state));
    memset(&layer, 0, sizeof(layer));
    memset(&ctx, 0, sizeof(ctx));
    memset(&map, 0, sizeof(map));
    state.data        = data;
    state.data_length = length;
    state.fail_at     = CLI_AUTHENTICODE_HASH_CHUNK_SIZE;
    map.handle        = &state;
    map.need          = authenticode_hash_test_need;
    map.len           = length;
    layer.fmap        = &map;
    ctx.fmap          = &map;
    ctx.recursion_stack = &layer;
    ctx.recursion_stack_size = 1;
    regions[0].offset = 0;
    regions[0].size   = length;

    hash_ctx = cl_hash_init("sha2-256");
    ck_assert_ptr_nonnull(hash_ctx);
    status = cli_hash_mapped_regions(&map, hash_ctx, regions, 1, &ctx);
    ck_assert_int_eq(status, CL_EREAD);
    cl_hash_destroy(hash_ctx);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map.dont_cache_flag);
    ck_assert_msg(state.max_request <= CLI_AUTHENTICODE_HASH_CHUNK_SIZE,
                  "failed Authenticode hash requested %zu bytes at once", state.max_request);

    /* Every coordinate is checked before the first digest byte is consumed. */
    ctx.scan_incomplete    = false;
    map.dont_cache_flag    = false;
    state.calls            = 0;
    state.max_request      = 0;
    state.fail_at          = SIZE_MAX;
    regions[0].offset      = 0;
    regions[0].size        = 16;
    regions[1].offset      = length - 4;
    regions[1].size        = 8;
    hash_ctx = cl_hash_init("sha2-256");
    ck_assert_ptr_nonnull(hash_ctx);
    status = cli_hash_mapped_regions(&map, hash_ctx, regions, 2, &ctx);
    ck_assert_int_eq(status, CL_EREAD);
    cl_hash_destroy(hash_ctx);
    ck_assert_msg(state.calls == 0, "invalid later region allowed a partial Authenticode digest");
    ck_assert(ctx.scan_incomplete);
    ck_assert(map.dont_cache_flag);

    free(data);
}
END_TEST

START_TEST(test_pe_overlay_range_preserves_native_size)
{
    struct cli_exe_section sections[2];
    size_t file_size = (size_t)UINT32_MAX + 65536;
    size_t overlay_start;
    size_t overlay_size;
    cl_error_t status;

    memset(sections, 0, sizeof(sections));
    sections[0].raw = 4096;
    sections[0].rsz = 4096;
    sections[1].raw = 16384;
    sections[1].rsz = 8192;

    status = cli_pe_calculate_overlay_range(sections, 2, file_size, &overlay_start, &overlay_size);
    ck_assert_int_eq(status, CL_SUCCESS);
    ck_assert_msg(overlay_start == 24576, "PE overlay start was %zu", overlay_start);
    ck_assert_msg(overlay_size == file_size - overlay_start,
                  "PE overlay length was narrowed from %zu to %zu", file_size - overlay_start, overlay_size);
    ck_assert_msg(overlay_size > UINT32_MAX, "synthetic PE overlay did not cross the 32-bit boundary");

    sections[1].raw = UINT32_MAX - 3;
    sections[1].rsz = 8;
    status = cli_pe_calculate_overlay_range(sections, 2, (size_t)UINT32_MAX, &overlay_start, &overlay_size);
    ck_assert_int_eq(status, CL_EFORMAT);
}
END_TEST

struct zip_stream_pread_state {
    const uint8_t *data;
    size_t length;
    size_t max_read;
};

static off_t zip_stream_pread_cb(void *handle, void *buf, size_t count, off_t offset)
{
    struct zip_stream_pread_state *state = handle;

    if (count > state->max_read)
        state->max_read = count;
    if (offset < 0 || (uint64_t)offset >= state->length)
        return 0;
    if (count > state->length - (size_t)offset)
        count = state->length - (size_t)offset;
    memcpy(buf, state->data + (size_t)offset, count);
    return (off_t)count;
}

static const uint8_t *zip_stream_expected;
static size_t zip_stream_expected_length;
static unsigned int zip_stream_callback_calls;
static cl_error_t zip_stream_callback_result;
static uint64_t zip_stream_temporary_limit;

static cl_error_t zip_stream_test_cb(int fd, const char *filepath, cli_ctx *ctx, const char *name, uint32_t attributes)
{
    uint8_t *actual = NULL;
    STATBUF sb;

    UNUSEDPARAM(filepath);
    UNUSEDPARAM(ctx);
    UNUSEDPARAM(name);
    UNUSEDPARAM(attributes);

    zip_stream_callback_calls++;
    ck_assert_int_eq(FSTAT(fd, &sb), 0);
    ck_assert_msg((uint64_t)sb.st_size == zip_stream_expected_length,
                  "ZIP callback got %llu bytes, expected %zu",
                  (unsigned long long)sb.st_size, zip_stream_expected_length);
    ck_assert_int_eq(lseek(fd, 0, SEEK_SET), 0);

    if (zip_stream_expected_length) {
        actual = malloc(zip_stream_expected_length);
        ck_assert_ptr_nonnull(actual);
        ck_assert_uint_eq(cli_readn(fd, actual, zip_stream_expected_length), zip_stream_expected_length);
        ck_assert_msg(0 == memcmp(actual, zip_stream_expected, zip_stream_expected_length),
                      "ZIP callback received incomplete or corrupted tail data");
        free(actual);
    }

    return zip_stream_callback_result;
}

static cl_error_t zip_index_meta_alert_cb(
    const char *container_type,
    unsigned long fsize_container,
    const char *filename,
    unsigned long fsize_real,
    int is_encrypted,
    unsigned int filepos_container,
    void *context)
{
    UNUSEDPARAM(container_type);
    UNUSEDPARAM(fsize_container);
    UNUSEDPARAM(filename);
    UNUSEDPARAM(fsize_real);
    UNUSEDPARAM(is_encrypted);
    UNUSEDPARAM(filepos_container);
    UNUSEDPARAM(context);
    return CL_VIRUS;
}

struct zip_index_alert_state {
    unsigned int calls;
    cl_error_t result;
};

static cl_error_t zip_index_alert_result_cb(cl_scan_layer_t *layer, void *context)
{
    struct zip_index_alert_state *state = context;

    UNUSEDPARAM(layer);
    state->calls++;
    return state->result;
}

static uint8_t *zip_stream_raw_deflate(const uint8_t *input, size_t input_length, size_t *output_length)
{
    z_stream stream;
    uint8_t *output;
    uLong bound;
    int zret;

    memset(&stream, 0, sizeof(stream));
    bound  = compressBound((uLong)input_length);
    output = malloc((size_t)bound);
    ck_assert_ptr_nonnull(output);

    zret = deflateInit2(&stream, Z_NO_COMPRESSION, Z_DEFLATED, -MAX_WBITS, 8, Z_DEFAULT_STRATEGY);
    ck_assert_int_eq(zret, Z_OK);
    stream.next_in   = (Bytef *)input;
    stream.avail_in  = (uInt)input_length;
    stream.next_out  = output;
    stream.avail_out = (uInt)bound;
    zret             = deflate(&stream, Z_FINISH);
    ck_assert_int_eq(zret, Z_STREAM_END);
    *output_length = (size_t)stream.total_out;
    ck_assert_int_eq(deflateEnd(&stream), Z_OK);
    return output;
}

static uint8_t *zip_stream_bzip2(const uint8_t *input, size_t input_length, size_t *output_length)
{
    unsigned int bound;
    unsigned int produced;
    uint8_t *output;
    int bzret;

    ck_assert_msg(input_length <= UINT_MAX, "BZIP2 unit-test input is too large");
    bound = (unsigned int)input_length + (unsigned int)(input_length / 100U) + 601U;
    output = malloc(bound);
    ck_assert_ptr_nonnull(output);
    produced = bound;
    bzret = BZ2_bzBuffToBuffCompress((char *)output, &produced, (char *)input,
                                     (unsigned int)input_length, 9, 0, 30);
    ck_assert_int_eq(bzret, BZ_OK);
    *output_length = produced;
    return output;
}

static uint8_t *gzip_stream(const uint8_t *input, size_t input_length, size_t *output_length)
{
    z_stream stream;
    uint8_t *output;
    uLong bound;
    int zret;

    ck_assert_msg(input_length <= UINT_MAX, "GZip unit-test input is too large");
    memset(&stream, 0, sizeof(stream));
    /* Leave room for the gzip wrapper in addition to the deflate payload. */
    bound  = compressBound((uLong)input_length) + 64U;
    output = malloc((size_t)bound);
    ck_assert_ptr_nonnull(output);

    zret = deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                        MAX_WBITS + 16, 8, Z_DEFAULT_STRATEGY);
    ck_assert_int_eq(zret, Z_OK);
    stream.next_in   = (Bytef *)input;
    stream.avail_in  = (uInt)input_length;
    stream.next_out  = output;
    stream.avail_out = (uInt)bound;
    zret             = deflate(&stream, Z_FINISH);
    ck_assert_int_eq(zret, Z_STREAM_END);
    *output_length = (size_t)stream.total_out;
    ck_assert_int_eq(deflateEnd(&stream), Z_OK);
    return output;
}

static uint8_t *swf_cws_stream(const uint8_t *input, size_t input_length, size_t *output_length)
{
    z_stream stream;
    uint8_t *output;
    uLong bound;
    size_t header_size = 8U;
    int zret;

    ck_assert_msg(input_length <= UINT_MAX - header_size, "CWS unit-test input is too large");
    memset(&stream, 0, sizeof(stream));
    bound  = compressBound((uLong)input_length) + 64U;
    output = malloc(header_size + (size_t)bound);
    ck_assert_ptr_nonnull(output);
    output[0] = 'C';
    output[1] = 'W';
    output[2] = 'S';
    output[3] = 9U;
    cli_writeint32(output + 4, (uint32_t)(header_size + input_length));

    zret = deflateInit(&stream, Z_DEFAULT_COMPRESSION);
    ck_assert_int_eq(zret, Z_OK);
    stream.next_in   = (Bytef *)input;
    stream.avail_in  = (uInt)input_length;
    stream.next_out  = output + header_size;
    stream.avail_out = (uInt)bound;
    zret             = deflate(&stream, Z_FINISH);
    ck_assert_int_eq(zret, Z_STREAM_END);
    *output_length = header_size + (size_t)stream.total_out;
    ck_assert_int_eq(deflateEnd(&stream), Z_OK);
    return output;
}

static uint8_t *zip_stream_implode_literals(const uint8_t *input, size_t input_length, size_t *output_length)
{
    const size_t tree_bytes = 10U;
    size_t bit_offset;
    size_t i;
    unsigned int bit;
    uint8_t *output;

    ck_assert_msg(0 == input_length % 8U,
                  "literal-only Implode fixture must end on a byte boundary");
    ck_assert_msg(input_length / 8U <= (SIZE_MAX - tree_bytes) / 9U,
                  "literal-only Implode fixture length overflow");
    *output_length = tree_bytes + (input_length / 8U) * 9U;
    output = calloc(1, *output_length);
    ck_assert_ptr_nonnull(output);

    /* Four runs of sixteen six-bit codes form complete 64-entry length and
     * distance trees. Flags=0 selects uncoded eight-bit literals. */
    output[0] = 3U;
    output[1] = output[2] = output[3] = output[4] = 0xf5U;
    output[5] = 3U;
    output[6] = output[7] = output[8] = output[9] = 0xf5U;

    bit_offset = tree_bytes * 8U;
    for (i = 0; i < input_length; i++) {
        output[bit_offset / 8U] |= (uint8_t)(1U << (bit_offset % 8U));
        bit_offset++;
        for (bit = 0; bit < 8U; bit++, bit_offset++) {
            if (input[i] & (uint8_t)(1U << bit))
                output[bit_offset / 8U] |= (uint8_t)(1U << (bit_offset % 8U));
        }
    }
    ck_assert_uint_eq(bit_offset, *output_length * 8U);
    return output;
}

static void zip_stream_fill(uint8_t *data, size_t length)
{
    uint32_t value = 0x9e3779b9U;
    size_t i;

    for (i = 0; i < length; i++) {
        value   = value * 1664525U + 1013904223U;
        data[i] = (uint8_t)(value >> 24);
    }
}

static void zip_stream_write_u16(uint8_t *dst, uint16_t value)
{
    dst[0] = (uint8_t)(value & 0xffU);
    dst[1] = (uint8_t)(value >> 8);
}

static void zip_stream_write_u32(uint8_t *dst, uint32_t value)
{
    dst[0] = (uint8_t)(value & 0xffU);
    dst[1] = (uint8_t)((value >> 8) & 0xffU);
    dst[2] = (uint8_t)((value >> 16) & 0xffU);
    dst[3] = (uint8_t)(value >> 24);
}

static void zip_stream_write_u64(uint8_t *dst, uint64_t value)
{
    unsigned int i;

    for (i = 0; i < 8U; i++)
        dst[i] = (uint8_t)(value >> (i * 8U));
}

static void zip_stream_crypto_update(uint32_t key[3], uint8_t input)
{
    key[0] = (uint32_t)crc32(key[0] ^ 0xffffffffU, &input, 1) ^ 0xffffffffU;
    key[1] = (key[1] + (key[0] & 0xffU)) * 134775813U + 1U;
    input  = (uint8_t)(key[1] >> 24);
    key[2] = (uint32_t)crc32(key[2] ^ 0xffffffffU, &input, 1) ^ 0xffffffffU;
}

static uint8_t zip_stream_crypto_byte(const uint32_t key[3])
{
    uint32_t temp = (key[2] & 0xffffU) | 2U;
    return (uint8_t)((temp * (temp ^ 1U)) >> 8);
}

static uint8_t *zip_stream_encrypt_stored(
    const uint8_t *input,
    size_t input_length,
    const char *password,
    uint32_t crc,
    size_t *output_length)
{
    uint32_t key[3] = {305419896U, 591751049U, 878082192U};
    uint8_t header[12] = {0};
    uint8_t *output;
    size_t i;

    for (i = 0; password[i]; i++)
        zip_stream_crypto_update(key, (uint8_t)password[i]);
    header[10] = (uint8_t)(crc >> 16);
    header[11] = (uint8_t)(crc >> 24);

    *output_length = input_length + sizeof(header);
    output = malloc(*output_length);
    ck_assert_ptr_nonnull(output);
    for (i = 0; i < sizeof(header); i++) {
        output[i] = header[i] ^ zip_stream_crypto_byte(key);
        zip_stream_crypto_update(key, header[i]);
    }
    for (i = 0; i < input_length; i++) {
        output[sizeof(header) + i] = input[i] ^ zip_stream_crypto_byte(key);
        zip_stream_crypto_update(key, input[i]);
    }
    return output;
}

static uint8_t *zip_stream_local_archive(
    const uint8_t *compressed,
    size_t compressed_length,
    uint32_t advertised_size,
    uint16_t method,
    uint32_t crc,
    size_t *archive_length)
{
    static const char filename[] = "stream-test.bin";
    const size_t header_length   = 30U;
    const size_t filename_length = sizeof(filename) - 1U;
    uint8_t *archive;

    ck_assert_msg(compressed_length <= UINT32_MAX, "test compressed member is too large");
    *archive_length = header_length + filename_length + compressed_length;
    archive         = calloc(1, *archive_length);
    ck_assert_ptr_nonnull(archive);

    zip_stream_write_u32(archive, 0x04034b50U);
    zip_stream_write_u16(archive + 4, 20U);
    zip_stream_write_u16(archive + 8, method);
    zip_stream_write_u32(archive + 14, crc);
    zip_stream_write_u32(archive + 18, (uint32_t)compressed_length);
    zip_stream_write_u32(archive + 22, advertised_size);
    zip_stream_write_u16(archive + 26, (uint16_t)filename_length);
    memcpy(archive + header_length, filename, filename_length);
    memcpy(archive + header_length + filename_length, compressed, compressed_length);
    return archive;
}

static uint8_t *zip_stream_local_archive_flags(
    const uint8_t *compressed,
    size_t compressed_length,
    uint32_t advertised_size,
    uint16_t method,
    uint16_t flags,
    uint32_t crc,
    size_t *archive_length)
{
    uint8_t *archive = zip_stream_local_archive(compressed, compressed_length,
                                                advertised_size, method, crc,
                                                archive_length);

    zip_stream_write_u16(archive + 6, flags);
    zip_stream_write_u32(archive + 14, crc);
    return archive;
}

static uint8_t *zip_stream_local_zip64_archive(
    const uint8_t *compressed,
    size_t compressed_length,
    uint64_t advertised_size,
    uint64_t advertised_compressed_size,
    uint16_t method,
    uint32_t crc,
    size_t *archive_length)
{
    static const char filename[] = "stream-test.bin";
    const size_t header_length   = 30U;
    const size_t filename_length = sizeof(filename) - 1U;
    const size_t extra_length    = 20U;
    uint8_t *archive;
    uint8_t *extra;

    *archive_length = header_length + filename_length + extra_length + compressed_length;
    archive = calloc(1, *archive_length);
    ck_assert_ptr_nonnull(archive);
    zip_stream_write_u32(archive, 0x04034b50U);
    zip_stream_write_u16(archive + 4, 45U);
    zip_stream_write_u16(archive + 8, method);
    zip_stream_write_u32(archive + 14, crc);
    zip_stream_write_u32(archive + 18, UINT32_MAX);
    zip_stream_write_u32(archive + 22, UINT32_MAX);
    zip_stream_write_u16(archive + 26, (uint16_t)filename_length);
    zip_stream_write_u16(archive + 28, (uint16_t)extra_length);
    memcpy(archive + header_length, filename, filename_length);
    extra = archive + header_length + filename_length;
    zip_stream_write_u16(extra, 0x0001U);
    zip_stream_write_u16(extra + 2, 16U);
    zip_stream_write_u64(extra + 4, advertised_size);
    zip_stream_write_u64(extra + 12, advertised_compressed_size);
    memcpy(extra + extra_length, compressed, compressed_length);
    return archive;
}

static uint8_t *zip_stream_central_archive(
    const uint8_t *compressed,
    size_t compressed_length,
    uint32_t advertised_size,
    uint16_t method,
    uint32_t crc,
    size_t *archive_length)
{
    static const char filename[] = "stream-test.bin";
    const size_t filename_length = sizeof(filename) - 1U;
    const size_t central_length  = 46U + filename_length;
    const size_t end_length      = 22U;
    uint8_t *local;
    uint8_t *archive;
    uint8_t *central;
    uint8_t *end;
    size_t local_length;

    local = zip_stream_local_archive(compressed, compressed_length, advertised_size,
                                     method, crc, &local_length);
    ck_assert_msg(local_length <= UINT32_MAX && central_length <= UINT32_MAX,
                  "test ZIP catalogue offsets exceed 32 bits");

    *archive_length = local_length + central_length + end_length;
    archive         = calloc(1, *archive_length);
    ck_assert_ptr_nonnull(archive);
    memcpy(archive, local, local_length);
    free(local);

    central = archive + local_length;
    zip_stream_write_u32(central, 0x02014b50U);
    zip_stream_write_u16(central + 4, 20U);
    zip_stream_write_u16(central + 6, 20U);
    zip_stream_write_u16(central + 10, method);
    zip_stream_write_u32(central + 16, crc);
    zip_stream_write_u32(central + 20, (uint32_t)compressed_length);
    zip_stream_write_u32(central + 24, advertised_size);
    zip_stream_write_u16(central + 28, (uint16_t)filename_length);
    memcpy(central + 46, filename, filename_length);

    end = central + central_length;
    zip_stream_write_u32(end, 0x06054b50U);
    zip_stream_write_u16(end + 8, 1U);
    zip_stream_write_u16(end + 10, 1U);
    zip_stream_write_u32(end + 12, (uint32_t)central_length);
    zip_stream_write_u32(end + 16, (uint32_t)local_length);
    return archive;
}

static uint8_t *zip_stream_central_data_descriptor_archive(
    const uint8_t *input,
    size_t input_length,
    size_t *archive_length,
    size_t *descriptor_offset)
{
    static const char filename[] = "descriptor.bin";
    const size_t local_header_length = 30U;
    const size_t filename_length     = sizeof(filename) - 1U;
    const size_t descriptor_length   = 16U;
    const size_t central_length     = 46U + filename_length;
    const size_t end_length         = 22U;
    const size_t local_data_offset  = local_header_length + filename_length;
    const uint32_t crc              = (uint32_t)crc32(0L, input, (uInt)input_length);
    size_t central_offset;
    uint8_t *archive;
    uint8_t *central;
    uint8_t *end;

    ck_assert_msg(input_length <= UINT32_MAX, "test ZIP member is too large");
    ck_assert_msg(input_length <= SIZE_MAX - local_data_offset - descriptor_length,
                  "test ZIP descriptor offset overflows");
    central_offset = local_data_offset + input_length + descriptor_length;
    ck_assert_msg(central_offset <= SIZE_MAX - central_length - end_length,
                  "test ZIP catalogue length overflows");
    ck_assert_msg(central_offset <= UINT32_MAX && central_length <= UINT32_MAX,
                  "test ZIP catalogue offsets exceed 32 bits");

    *archive_length    = central_offset + central_length + end_length;
    *descriptor_offset = local_data_offset + input_length;
    archive            = calloc(1, *archive_length);
    ck_assert_ptr_nonnull(archive);

    zip_stream_write_u32(archive, 0x04034b50U);
    zip_stream_write_u16(archive + 4, 20U);
    zip_stream_write_u16(archive + 6, ZIP_TEST_FLAG_DATA_DESCRIPTOR);
    zip_stream_write_u16(archive + 8, ZIP_TEST_METHOD_STORED);
    zip_stream_write_u16(archive + 26, (uint16_t)filename_length);
    memcpy(archive + local_header_length, filename, filename_length);
    memcpy(archive + local_data_offset, input, input_length);
    zip_stream_write_u32(archive + *descriptor_offset, 0x08074b50U);
    zip_stream_write_u32(archive + *descriptor_offset + 4U, crc);
    zip_stream_write_u32(archive + *descriptor_offset + 8U, (uint32_t)input_length);
    zip_stream_write_u32(archive + *descriptor_offset + 12U, (uint32_t)input_length);

    central = archive + central_offset;
    zip_stream_write_u32(central, 0x02014b50U);
    zip_stream_write_u16(central + 4, 20U);
    zip_stream_write_u16(central + 6, 20U);
    zip_stream_write_u16(central + 8, ZIP_TEST_FLAG_DATA_DESCRIPTOR);
    zip_stream_write_u16(central + 10, ZIP_TEST_METHOD_STORED);
    zip_stream_write_u32(central + 16, crc);
    zip_stream_write_u32(central + 20, (uint32_t)input_length);
    zip_stream_write_u32(central + 24, (uint32_t)input_length);
    zip_stream_write_u16(central + 28, (uint16_t)filename_length);
    memcpy(central + 46, filename, filename_length);

    end = central + central_length;
    zip_stream_write_u32(end, 0x06054b50U);
    zip_stream_write_u16(end + 8, 1U);
    zip_stream_write_u16(end + 10, 1U);
    zip_stream_write_u32(end + 12, (uint32_t)central_length);
    zip_stream_write_u32(end + 16, (uint32_t)central_offset);
    return archive;
}

static uint8_t *zip_stream_central_masked_archive(
    const uint8_t *compressed,
    size_t compressed_length,
    uint32_t advertised_size,
    uint16_t method,
    uint32_t crc,
    size_t *archive_length)
{
    static const size_t local_header_length = 30U;
    static const size_t filename_length     = sizeof("stream-test.bin") - 1U;
    const size_t local_length = local_header_length + filename_length + compressed_length;
    uint8_t *archive;

    archive = zip_stream_central_archive(compressed, compressed_length, advertised_size,
                                         method, crc, archive_length);
    ck_assert_msg(local_length <= *archive_length, "masked ZIP fixture is unexpectedly short");

    /* Bit 13 masks only the local CRC and size fields.  The central
     * directory remains authoritative for those values. */
    zip_stream_write_u16(archive + 6, ZIP_TEST_FLAG_MASKED_HEADER);
    zip_stream_write_u32(archive + 14, 0U);
    zip_stream_write_u32(archive + 18, 0U);
    zip_stream_write_u32(archive + 22, 0U);
    zip_stream_write_u16(archive + local_length + 8, ZIP_TEST_FLAG_MASKED_HEADER);
    return archive;
}

static uint8_t *zip_stream_empty_central_archive(size_t entry_count, size_t *archive_length)
{
    const size_t local_record_length   = 31U;
    const size_t central_record_length = 47U;
    const size_t end_length            = 22U;
    size_t central_offset;
    size_t central_length;
    size_t i;
    uint8_t *archive;
    uint8_t *record;
    uint8_t *end;

    ck_assert_msg(entry_count > 0 && entry_count <= UINT16_MAX,
                  "invalid tiny ZIP entry count");
    ck_assert_msg(entry_count <= (SIZE_MAX - end_length) /
                                     (local_record_length + central_record_length),
                  "tiny ZIP fixture length overflow");

    central_offset  = entry_count * local_record_length;
    central_length  = entry_count * central_record_length;
    *archive_length = central_offset + central_length + end_length;
    archive         = calloc(1, *archive_length);
    ck_assert_ptr_nonnull(archive);

    for (i = 0; i < entry_count; i++) {
        record = archive + i * local_record_length;
        zip_stream_write_u32(record, 0x04034b50U);
        zip_stream_write_u16(record + 4, 20U);
        zip_stream_write_u16(record + 26, 1U);
        record[30] = (uint8_t)('a' + (i % 26U));
    }

    for (i = 0; i < entry_count; i++) {
        record = archive + central_offset + i * central_record_length;
        zip_stream_write_u32(record, 0x02014b50U);
        zip_stream_write_u16(record + 4, 20U);
        zip_stream_write_u16(record + 6, 20U);
        zip_stream_write_u16(record + 28, 1U);
        zip_stream_write_u32(record + 42, (uint32_t)(i * local_record_length));
        record[46] = (uint8_t)('a' + (i % 26U));
    }

    end = archive + central_offset + central_length;
    zip_stream_write_u32(end, 0x06054b50U);
    zip_stream_write_u16(end + 8, (uint16_t)entry_count);
    zip_stream_write_u16(end + 10, (uint16_t)entry_count);
    zip_stream_write_u32(end + 12, (uint32_t)central_length);
    zip_stream_write_u32(end + 16, (uint32_t)central_offset);
    return archive;
}

static cl_error_t zip_index_run_maxfiles(
    size_t entry_count,
    uint32_t maxfiles,
    const char *search_name,
    size_t *matched_offset,
    bool *scan_incomplete,
    bool *dont_cache)
{
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_scan_layer_t layer;
    cli_ctx ctx;
    cl_fmap_t *map;
    uint8_t *archive;
    size_t archive_length;
    cl_error_t ret;

    archive = zip_stream_empty_central_archive(entry_count, &archive_length);
    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&layer, 0, sizeof(layer));
    memset(&ctx, 0, sizeof(ctx));

    map = cl_fmap_open_memory(archive, archive_length);
    ck_assert_ptr_nonnull(map);
    engine.maxfiles          = maxfiles;
    ctx.engine               = &engine;
    ctx.options              = &options;
    ctx.fmap                 = map;
    ctx.this_layer_tmpdir    = tmpdir;
    ctx.recursion_stack      = &layer;
    ctx.recursion_stack_size = 1;
    layer.type               = CL_TYPE_ZIP;
    layer.size               = archive_length;
    layer.fmap               = map;

    if (search_name) {
        ret = unzip_search_single(&ctx, search_name, strlen(search_name), matched_offset);
    } else {
        ret = cli_unzip(&ctx);
    }
    *scan_incomplete = ctx.scan_incomplete;
    *dont_cache      = map->dont_cache_flag;

    cl_fmap_close(map);
    free(archive);
    return ret;
}

static cl_error_t zip_index_run_central_alert(
    cl_error_t callback_result,
    unsigned int *callback_calls,
    bool *abort_scan,
    bool *scan_incomplete,
    cl_verdict_t *verdict)
{
    static const uint8_t input[] = "central-callback";
    struct zip_stream_pread_state state;
    struct zip_index_alert_state alert_state = {0, callback_result};
    struct cl_engine *engine;
    struct cl_scan_options options;
    cli_scan_layer_t layer;
    cli_ctx ctx;
    cl_fmap_t *map;
    uint8_t *archive;
    size_t archive_length;
    cl_error_t ret;

    archive = zip_stream_central_archive(input, sizeof(input), sizeof(input),
                                         ZIP_TEST_METHOD_STORED,
                                         (uint32_t)crc32(0L, input, (uInt)sizeof(input)),
                                         &archive_length);
    ck_assert_ptr_nonnull(archive);

    memset(&state, 0, sizeof(state));
    memset(&options, 0, sizeof(options));
    memset(&layer, 0, sizeof(layer));
    memset(&ctx, 0, sizeof(ctx));
    state.data   = archive;
    state.length = archive_length;
    map = cl_fmap_open_handle(&state, 0, archive_length, zip_stream_pread_cb, 1);
    ck_assert_ptr_nonnull(map);

    engine = cl_engine_new();
    ck_assert_ptr_nonnull(engine);
    cl_engine_set_clcb_meta(engine, zip_index_meta_alert_cb);
    cl_engine_set_scan_callback(engine, zip_index_alert_result_cb, CL_SCAN_CALLBACK_ALERT);

    ctx.engine               = engine;
    ctx.options              = &options;
    ctx.dconf                = engine->dconf;
    ctx.fmap                 = map;
    ctx.this_layer_tmpdir    = tmpdir;
    ctx.recursion_stack      = &layer;
    ctx.recursion_stack_size = 1;
    ctx.cb_ctx               = &alert_state;
    layer.type               = CL_TYPE_ZIP;
    layer.size               = archive_length;
    layer.fmap               = map;

    ret              = cli_unzip(&ctx);
    *callback_calls  = alert_state.calls;
    *abort_scan      = ctx.abort_scan;
    *scan_incomplete = ctx.scan_incomplete;
    *verdict         = layer.verdict;

    if (layer.evidence)
        evidence_free(layer.evidence);
    cl_engine_free(engine);
    cl_fmap_close(map);
    free(archive);
    return ret;
}

static cl_error_t zip_stream_run(
    const uint8_t *compressed,
    size_t compressed_length,
    uint64_t advertised_size,
    uint16_t method,
    uint64_t maxfilesize,
    const uint8_t *expected,
    size_t expected_length,
    cl_error_t callback_result,
    size_t *max_read,
    bool *scan_incomplete,
    size_t *files_unzipped)
{
    struct zip_stream_pread_state state;
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_scan_layer_t layers[2];
    cli_ctx ctx;
    cl_fmap_t *map;
    uint8_t *archive;
    size_t archive_length;
    uint32_t expected_crc;
    cl_error_t ret;

    memset(&state, 0, sizeof(state));
    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(layers, 0, sizeof(layers));
    memset(&ctx, 0, sizeof(ctx));

    ck_assert_msg(advertised_size <= UINT32_MAX, "test advertised ZIP size is too large");
    expected_crc = (uint32_t)crc32(0L, expected, (uInt)expected_length);
    archive      = zip_stream_local_archive(compressed, compressed_length,
                                            (uint32_t)advertised_size, method,
                                            expected_crc, &archive_length);
    state.data   = archive;
    state.length = archive_length;
    map = cl_fmap_open_handle(&state, 0, archive_length, zip_stream_pread_cb, 1);
    ck_assert_ptr_nonnull(map);

    engine.maxfilesize      = maxfilesize;
    engine.maxtemporarysize = zip_stream_temporary_limit;
    ctx.engine            = &engine;
    ctx.options           = &options;
    ctx.fmap              = map;
    ctx.this_layer_tmpdir = tmpdir;
    ctx.recursion_stack      = layers;
    ctx.recursion_stack_size = 2;
    layers[0].type           = CL_TYPE_ZIP;
    layers[0].size           = archive_length;
    layers[0].fmap           = map;

    zip_stream_expected        = expected;
    zip_stream_expected_length = expected_length;
    zip_stream_callback_calls  = 0;
    zip_stream_callback_result = callback_result;

    *files_unzipped = 0;
    ret = unzip_single_internal(&ctx, 0, zip_stream_test_cb);
    *files_unzipped = zip_stream_callback_calls;
    *max_read        = state.max_read;
    *scan_incomplete = ctx.scan_incomplete;
    cl_fmap_close(map);
    free(archive);
    return ret;
}

static cl_error_t zip_stream_run_archive(
    uint8_t *archive,
    size_t archive_length,
    uint64_t maxfilesize,
    struct cli_pwdb *zip_password,
    const uint8_t *expected,
    size_t expected_length,
    size_t *max_read,
    bool *scan_incomplete,
    size_t *files_unzipped)
{
    struct zip_stream_pread_state state;
    struct cli_pwdb *password_lists[CLI_PWDB_COUNT];
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_scan_layer_t layer;
    cli_ctx ctx;
    cl_fmap_t *map;
    cl_error_t ret;

    memset(&state, 0, sizeof(state));
    memset(password_lists, 0, sizeof(password_lists));
    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&layer, 0, sizeof(layer));
    memset(&ctx, 0, sizeof(ctx));

    state.data   = archive;
    state.length = archive_length;
    map = cl_fmap_open_handle(&state, 0, archive_length, zip_stream_pread_cb, 1);
    ck_assert_ptr_nonnull(map);

    if (zip_password) {
        password_lists[CLI_PWDB_ZIP] = zip_password;
        engine.pwdbs = password_lists;
    }
    engine.maxfilesize       = maxfilesize;
    ctx.engine               = &engine;
    ctx.options              = &options;
    ctx.fmap                 = map;
    ctx.this_layer_tmpdir    = tmpdir;
    ctx.recursion_stack      = &layer;
    ctx.recursion_stack_size = 1;
    layer.type               = CL_TYPE_ZIP;
    layer.size               = archive_length;
    layer.fmap               = map;

    zip_stream_expected        = expected;
    zip_stream_expected_length = expected_length;
    zip_stream_callback_calls  = 0;
    zip_stream_callback_result = CL_SUCCESS;

    ret = unzip_single_internal(&ctx, 0, zip_stream_test_cb);
    *files_unzipped = zip_stream_callback_calls;
    *max_read        = state.max_read;
    *scan_incomplete = ctx.scan_incomplete;
    cl_fmap_close(map);
    free(archive);
    return ret;
}

START_TEST(test_zip_stream_stored_refill_bound_and_tail)
{
    const size_t length = CLI_ZIP_INPUT_CHUNK_SIZE * 2U + 37U;
    uint8_t *input      = malloc(length);
    size_t max_read;
    size_t files_unzipped;
    bool incomplete;
    cl_error_t ret;

    ck_assert_ptr_nonnull(input);
    zip_stream_fill(input, length);
    memcpy(input + length - 16, "ZIP-TAIL-MARKER!", 16);

    ret = zip_stream_run(input, length, length, ZIP_TEST_METHOD_STORED, length, input, length,
                         CL_SUCCESS, &max_read, &incomplete, &files_unzipped);
    ck_assert_int_eq(ret, CL_SUCCESS);
    ck_assert_uint_eq(zip_stream_callback_calls, 1);
    ck_assert_uint_eq(files_unzipped, 1);
    ck_assert(!incomplete);
    ck_assert_msg(max_read <= CLI_ZIP_INPUT_CHUNK_SIZE + (size_t)cli_getpagesize(),
                  "stored ZIP requested %zu bytes in one fmap read", max_read);
    free(input);
}
END_TEST

START_TEST(test_zip_temporary_limit_is_fail_visible)
{
    static const uint8_t input[] = "ZIP temporary quota";
    size_t max_read;
    size_t files_unzipped;
    bool incomplete;
    cl_error_t ret;

    zip_stream_temporary_limit = sizeof(input) - 2U;
    ret = zip_stream_run(input, sizeof(input) - 1U, sizeof(input) - 1U,
                         ZIP_TEST_METHOD_STORED, sizeof(input) - 1U,
                         input, sizeof(input) - 1U, CL_SUCCESS, &max_read,
                         &incomplete, &files_unzipped);
    zip_stream_temporary_limit = 0;

    ck_assert_int_eq(ret, CL_ERESOURCE);
    ck_assert_uint_eq(files_unzipped, 0);
    ck_assert(incomplete);
}
END_TEST

START_TEST(test_zip_stream_deflate_refill_bound_and_tail)
{
    const size_t length = CLI_ZIP_INPUT_CHUNK_SIZE * 2U + 37U;
    uint8_t *input      = malloc(length);
    uint8_t *compressed;
    size_t compressed_length;
    size_t max_read;
    size_t files_unzipped;
    bool incomplete;
    cl_error_t ret;

    ck_assert_ptr_nonnull(input);
    zip_stream_fill(input, length);
    memcpy(input + length - 16, "ZIP-TAIL-MARKER!", 16);
    compressed = zip_stream_raw_deflate(input, length, &compressed_length);
    ck_assert_msg(compressed_length > CLI_ZIP_INPUT_CHUNK_SIZE,
                  "test fixture must cross at least one ZIP input refill");

    ret = zip_stream_run(compressed, compressed_length, length, ZIP_TEST_METHOD_DEFLATE, length,
                         input, length, CL_SUCCESS, &max_read, &incomplete, &files_unzipped);
    ck_assert_int_eq(ret, CL_SUCCESS);
    ck_assert_uint_eq(zip_stream_callback_calls, 1);
    ck_assert_uint_eq(files_unzipped, 1);
    ck_assert(!incomplete);
    ck_assert_msg(max_read <= CLI_ZIP_INPUT_CHUNK_SIZE + (size_t)cli_getpagesize(),
                  "deflated ZIP requested %zu bytes in one fmap read", max_read);

    free(compressed);
    free(input);
}
END_TEST

START_TEST(test_zip_stream_bzip2_refill_bound_and_tail)
{
    const size_t length = CLI_ZIP_INPUT_CHUNK_SIZE * 2U + 37U;
    uint8_t *input      = malloc(length);
    uint8_t *compressed;
    size_t compressed_length;
    size_t max_read;
    size_t files_unzipped;
    bool incomplete;
    cl_error_t ret;

    ck_assert_ptr_nonnull(input);
    zip_stream_fill(input, length);
    memcpy(input + length - 16, "ZIP-TAIL-MARKER!", 16);
    compressed = zip_stream_bzip2(input, length, &compressed_length);
    ck_assert_msg(compressed_length > CLI_ZIP_INPUT_CHUNK_SIZE,
                  "BZIP2 fixture must cross at least one ZIP input refill");

    ret = zip_stream_run(compressed, compressed_length, length, ZIP_TEST_METHOD_BZIP2,
                         length, input, length, CL_SUCCESS, &max_read,
                         &incomplete, &files_unzipped);
    ck_assert_int_eq(ret, CL_SUCCESS);
    ck_assert_uint_eq(files_unzipped, 1);
    ck_assert(!incomplete);
    ck_assert_msg(max_read <= CLI_ZIP_INPUT_CHUNK_SIZE + (size_t)cli_getpagesize(),
                  "BZIP2 ZIP requested %zu bytes in one fmap read", max_read);

    free(compressed);
    free(input);
}
END_TEST

START_TEST(test_zip_stream_deflate64_terminal_validation)
{
    const size_t length = CLI_ZIP_INPUT_CHUNK_SIZE + 19U;
    uint8_t *input      = malloc(length);
    uint8_t *compressed;
    size_t compressed_length;
    size_t max_read;
    size_t files_unzipped;
    bool incomplete;
    cl_error_t ret;

    ck_assert_ptr_nonnull(input);
    zip_stream_fill(input, length);
    /* Ordinary raw DEFLATE streams are a strict subset accepted by the
     * Deflate64 decoder, providing a deterministic terminal/refill fixture. */
    compressed = zip_stream_raw_deflate(input, length, &compressed_length);

    ret = zip_stream_run(compressed, compressed_length, length,
                         ZIP_TEST_METHOD_DEFLATE64, length, input, length,
                         CL_SUCCESS, &max_read, &incomplete, &files_unzipped);
    ck_assert_int_eq(ret, CL_SUCCESS);
    ck_assert_uint_eq(files_unzipped, 1);
    ck_assert(!incomplete);
    ck_assert_msg(max_read <= CLI_ZIP_INPUT_CHUNK_SIZE + (size_t)cli_getpagesize(),
                  "Deflate64 ZIP requested %zu bytes in one fmap read", max_read);

    ret = zip_stream_run(compressed, compressed_length - 1U, length,
                         ZIP_TEST_METHOD_DEFLATE64, length, input, length,
                         CL_SUCCESS, &max_read, &incomplete, &files_unzipped);
    ck_assert_int_eq(ret, CL_EUNPACK);
    ck_assert_uint_eq(files_unzipped, 0);
    ck_assert(incomplete);

    free(compressed);
    free(input);
}
END_TEST

START_TEST(test_zip_stream_zipcrypto_stored_is_bounded)
{
    static const char password_text[] = "clamav-largefile-test";
    const size_t length = CLI_ZIP_INPUT_CHUNK_SIZE * 2U + 37U;
    struct cli_pwdb password;
    uint8_t *input = malloc(length);
    uint8_t *encrypted;
    uint8_t *archive;
    size_t encrypted_length;
    size_t archive_length;
    size_t max_read;
    size_t files_unzipped;
    uint32_t crc;
    bool incomplete;
    cl_error_t ret;

    ck_assert_ptr_nonnull(input);
    zip_stream_fill(input, length);
    crc = (uint32_t)crc32(0L, input, (uInt)length);
    encrypted = zip_stream_encrypt_stored(input, length, password_text, crc,
                                          &encrypted_length);
    archive = zip_stream_local_archive_flags(encrypted, encrypted_length,
                                             (uint32_t)length,
                                             ZIP_TEST_METHOD_STORED,
                                             ZIP_TEST_FLAG_ENCRYPTED,
                                             crc, &archive_length);
    memset(&password, 0, sizeof(password));
    password.name   = (char *)"unit-test-password";
    password.passwd = (char *)password_text;
    password.length = (uint16_t)(sizeof(password_text) - 1U);

    ret = zip_stream_run_archive(archive, archive_length, length, &password,
                                 input, length, &max_read, &incomplete,
                                 &files_unzipped);
    ck_assert_int_eq(ret, CL_SUCCESS);
    ck_assert_uint_eq(files_unzipped, 1);
    ck_assert(!incomplete);
    ck_assert_msg(max_read <= CLI_ZIP_INPUT_CHUNK_SIZE + (size_t)cli_getpagesize(),
                  "ZipCrypto requested %zu bytes in one fmap read", max_read);

    free(encrypted);

    /* Keep the password verifier bytes unchanged but corrupt a low CRC bit.
     * The final plaintext CRC gate, not just the weak ZipCrypto header check,
     * must prevent a callback. */
    crc ^= 1U;
    encrypted = zip_stream_encrypt_stored(input, length, password_text, crc,
                                          &encrypted_length);
    archive = zip_stream_local_archive_flags(encrypted, encrypted_length,
                                             (uint32_t)length,
                                             ZIP_TEST_METHOD_STORED,
                                             ZIP_TEST_FLAG_ENCRYPTED,
                                             crc, &archive_length);
    ret = zip_stream_run_archive(archive, archive_length, length, &password,
                                 input, length, &max_read, &incomplete,
                                 &files_unzipped);
    ck_assert_int_eq(ret, CL_EUNPACK);
    ck_assert_uint_eq(files_unzipped, 0);
    ck_assert(incomplete);

    free(encrypted);
    free(input);
}
END_TEST

START_TEST(test_zip64_member_sizes_are_not_narrowed)
{
    static const uint8_t byte = 0x7a;
    uint8_t *archive;
    size_t archive_length;
    size_t max_read;
    size_t files_unzipped;
    bool incomplete;
    cl_error_t ret;

    archive = zip_stream_local_zip64_archive(&byte, 1U, 1U, 1U,
                                             ZIP_TEST_METHOD_STORED,
                                             (uint32_t)crc32(0L, &byte, 1U),
                                             &archive_length);
    ret = zip_stream_run_archive(archive, archive_length, 1U, NULL,
                                 &byte, 1U, &max_read, &incomplete,
                                 &files_unzipped);
    ck_assert_int_eq(ret, CL_SUCCESS);
    ck_assert_uint_eq(files_unzipped, 1);
    ck_assert(!incomplete);

    /* A synthetic >4 GiB ZIP64 csize cannot fit this tiny fmap. It must fail
     * before any narrowing could turn it into a one-byte clean extraction. */
    archive = zip_stream_local_zip64_archive(&byte, 1U, 1U,
                                             UINT64_C(0x100000000),
                                             ZIP_TEST_METHOD_STORED,
                                             (uint32_t)crc32(0L, &byte, 1U),
                                             &archive_length);
    ret = zip_stream_run_archive(archive, archive_length, UINT64_C(0x100000000),
                                 NULL, &byte, 1U, &max_read, &incomplete,
                                 &files_unzipped);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert_uint_eq(files_unzipped, 0);
    ck_assert(incomplete);
}
END_TEST

START_TEST(test_zip_stream_implode_refill_bound_and_terminal)
{
    const size_t length = CLI_ZIP_INPUT_CHUNK_SIZE * 2U;
    uint8_t *input      = malloc(length);
    uint8_t *compressed;
    size_t compressed_length;
    size_t max_read;
    size_t files_unzipped;
    bool incomplete;
    cl_error_t ret;

    ck_assert_ptr_nonnull(input);
    zip_stream_fill(input, length);
    compressed = zip_stream_implode_literals(input, length, &compressed_length);
    ck_assert_msg(compressed_length > CLI_ZIP_INPUT_CHUNK_SIZE * 2U,
                  "Implode fixture must cross multiple ZIP input refills");

    ret = zip_stream_run(compressed, compressed_length, length,
                         ZIP_TEST_METHOD_IMPLODE, length, input, length,
                         CL_SUCCESS, &max_read, &incomplete, &files_unzipped);
    ck_assert_int_eq(ret, CL_SUCCESS);
    ck_assert_uint_eq(files_unzipped, 1);
    ck_assert(!incomplete);
    ck_assert_msg(max_read <= CLI_ZIP_INPUT_CHUNK_SIZE + (size_t)cli_getpagesize(),
                  "Implode ZIP requested %zu bytes in one fmap read", max_read);

    ret = zip_stream_run(compressed, compressed_length - 1U, length,
                         ZIP_TEST_METHOD_IMPLODE, length, input, length,
                         CL_SUCCESS, &max_read, &incomplete, &files_unzipped);
    ck_assert_int_eq(ret, CL_EUNPACK);
    ck_assert_uint_eq(files_unzipped, 0);
    ck_assert(incomplete);

    free(compressed);
    free(input);
}
END_TEST

START_TEST(test_zip_stream_exact_limit_and_n_plus_one)
{
    const size_t limit = BUFSIZ * 2U;
    uint8_t *exact     = malloc(limit);
    uint8_t *over      = malloc(limit + 1U);
    uint8_t *compressed;
    size_t compressed_length;
    size_t max_read;
    size_t files_unzipped;
    bool incomplete;
    cl_error_t ret;

    ck_assert_ptr_nonnull(exact);
    ck_assert_ptr_nonnull(over);
    zip_stream_fill(exact, limit);
    memcpy(over, exact, limit);
    over[limit] = 0xa5;

    compressed = zip_stream_raw_deflate(exact, limit, &compressed_length);
    ret = zip_stream_run(compressed, compressed_length, limit, ZIP_TEST_METHOD_DEFLATE, limit,
                         exact, limit, CL_SUCCESS, &max_read, &incomplete, &files_unzipped);
    ck_assert_int_eq(ret, CL_SUCCESS);
    ck_assert_uint_eq(zip_stream_callback_calls, 1);
    ck_assert_uint_eq(files_unzipped, 1);
    ck_assert(!incomplete);
    free(compressed);

    compressed = zip_stream_raw_deflate(over, limit + 1U, &compressed_length);
    /* Lie in the header so only the runtime output check can discover N+1. */
    ret = zip_stream_run(compressed, compressed_length, limit, ZIP_TEST_METHOD_DEFLATE, limit,
                         over, limit + 1U, CL_SUCCESS, &max_read, &incomplete, &files_unzipped);
    ck_assert_int_eq(ret, CL_EMAXSIZE);
    ck_assert_uint_eq(zip_stream_callback_calls, 0);
    ck_assert_uint_eq(files_unzipped, 0);
    ck_assert(incomplete);

    free(compressed);
    free(over);
    free(exact);
}
END_TEST

START_TEST(test_zip_stream_truncated_deflate_and_callback_status)
{
    const size_t length = BUFSIZ * 3U + 11U;
    uint8_t *input      = malloc(length);
    uint8_t *compressed;
    size_t compressed_length;
    size_t max_read;
    size_t files_unzipped;
    bool incomplete;
    cl_error_t ret;

    ck_assert_ptr_nonnull(input);
    zip_stream_fill(input, length);
    compressed = zip_stream_raw_deflate(input, length, &compressed_length);
    ck_assert_msg(compressed_length > 1, "raw deflate fixture unexpectedly short");

    ret = zip_stream_run(compressed, compressed_length - 1U, length, ZIP_TEST_METHOD_DEFLATE, length,
                         input, length, CL_SUCCESS, &max_read, &incomplete, &files_unzipped);
    ck_assert_int_eq(ret, CL_EUNPACK);
    ck_assert_uint_eq(zip_stream_callback_calls, 0);
    ck_assert_uint_eq(files_unzipped, 0);
    ck_assert(incomplete);

    ret = zip_stream_run(input, length, length, ZIP_TEST_METHOD_STORED, length,
                         input, length, CL_BREAK, &max_read, &incomplete, &files_unzipped);
    ck_assert_int_eq(ret, CL_BREAK);
    ck_assert_uint_eq(zip_stream_callback_calls, 1);
    ck_assert_uint_eq(files_unzipped, 1);
    ck_assert(!incomplete);

    free(compressed);
    free(input);
}
END_TEST

#ifdef CLAMAV_TEST_JS_IO_WRAP
START_TEST(test_zip_output_write_failure_is_fail_visible)
{
    static const uint8_t input[] = "ZIP output write fault injection";
    size_t max_read;
    size_t files_unzipped;
    bool incomplete;
    cl_error_t ret;

    clamav_test_fail_write = 1;
    ret = zip_stream_run(input, sizeof(input) - 1U, sizeof(input) - 1U,
                         ZIP_TEST_METHOD_STORED, sizeof(input) - 1U,
                         input, sizeof(input) - 1U, CL_SUCCESS, &max_read,
                         &incomplete, &files_unzipped);
    clamav_test_fail_write = 0;

    ck_assert_int_eq(ret, CL_EWRITE);
    ck_assert_uint_eq(files_unzipped, 0);
    ck_assert(incomplete);
}
END_TEST

START_TEST(test_zip_output_close_failure_is_fail_visible)
{
    static const uint8_t input[] = "ZIP output close fault injection";
    size_t max_read;
    size_t files_unzipped;
    bool incomplete;
    cl_error_t ret;

    clamav_test_fail_close = 1;
    ret = zip_stream_run(input, sizeof(input) - 1U, sizeof(input) - 1U,
                         ZIP_TEST_METHOD_STORED, sizeof(input) - 1U,
                         input, sizeof(input) - 1U, CL_SUCCESS, &max_read,
                         &incomplete, &files_unzipped);
    clamav_test_fail_close = 0;

    ck_assert_int_eq(ret, CL_EWRITE);
    ck_assert_uint_eq(files_unzipped, 1);
    ck_assert(incomplete);
}
END_TEST

START_TEST(test_cryptff_staging_failures_are_fail_visible)
{
    static const uint8_t cryptff[] = {
        0xb6, 0xb9, 0xac, 0xae, 0xfe, 0xff, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x9c, 0x8d, 0x86, 0x8f, 0x8b, 0x99, 0x8a, 0x8b,
    };
    struct cl_engine *scan_engine;
    struct cl_scan_options options;
    cli_scan_layer_t layers[2];
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    memset(layers, 0, sizeof(layers));
    memset(&ctx, 0, sizeof(ctx));
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);

    map = cl_fmap_open_memory(cryptff, sizeof(cryptff));
    ck_assert_ptr_nonnull(map);
    layers[0].fmap           = map;
    ctx.engine               = scan_engine;
    ctx.dconf                = scan_engine->dconf;
    ctx.options              = &options;
    ctx.fmap                 = map;
    ctx.this_layer_tmpdir    = tmpdir;
    ctx.recursion_stack      = layers;
    ctx.recursion_stack_size = 2;

    clamav_test_fail_write = 1;
    ret                    = cli_magic_scan(&ctx, CL_TYPE_CRYPTFF);
    clamav_test_fail_write = 0;
    ck_assert_int_eq(ret, CL_EWRITE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    memset(layers, 0, sizeof(layers));
    memset(&ctx, 0, sizeof(ctx));
    layers[0].fmap           = map;
    ctx.engine               = scan_engine;
    ctx.dconf                = scan_engine->dconf;
    ctx.options              = &options;
    ctx.fmap                 = map;
    ctx.this_layer_tmpdir    = tmpdir;
    ctx.recursion_stack      = layers;
    ctx.recursion_stack_size = 2;
    map->dont_cache_flag     = false;
    clamav_test_fail_close = 1;
    ret                    = cli_magic_scan(&ctx, CL_TYPE_CRYPTFF);
    clamav_test_fail_close = 0;
    ck_assert_int_eq(ret, CL_EWRITE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);

}
END_TEST

START_TEST(test_cryptff_temporary_quota_is_fail_visible)
{
    static const uint8_t cryptff[] = {
        0xb6, 0xb9, 0xac, 0xae, 0xfe, 0xff, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x9c, 0x8d, 0x86, 0x8f, 0x8b, 0x99, 0x8a, 0x8b,
    };
    struct cl_engine *scan_engine;
    struct cl_scan_options options;
    cli_scan_layer_t layers[2];
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    memset(layers, 0, sizeof(layers));
    memset(&ctx, 0, sizeof(ctx));
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_set_num(scan_engine, CL_ENGINE_MAX_TEMPORARY_SIZE, 4), CL_SUCCESS);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);

    map = cl_fmap_open_memory(cryptff, sizeof(cryptff));
    ck_assert_ptr_nonnull(map);
    layers[0].fmap           = map;
    ctx.engine               = scan_engine;
    ctx.dconf                = scan_engine->dconf;
    ctx.options              = &options;
    ctx.fmap                 = map;
    ctx.this_layer_tmpdir    = tmpdir;
    ctx.recursion_stack      = layers;
    ctx.recursion_stack_size = 2;

    ret = cli_magic_scan(&ctx, CL_TYPE_CRYPTFF);
    ck_assert_int_eq(ret, CL_ERESOURCE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);
    ck_assert_uint_eq(ctx.temporary_bytes, 0);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_gzip_staging_failures_are_fail_visible)
{
    static const uint8_t input[] = "GZip staging fault injection";
    uint8_t *gzip;
    size_t gzip_length;
    struct cl_scan_options options;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    fmap_t *map;
    cl_error_t ret;

    gzip = gzip_stream(input, sizeof(input) - 1U, &gzip_length);
    ck_assert_ptr_nonnull(gzip);
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;

    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(gzip, gzip_length);
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    clamav_test_fail_write = 1;
    ret                    = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                                            scan_engine, &options, NULL, NULL, NULL, NULL,
                                            "CL_TYPE_GZ", NULL);
    clamav_test_fail_write = 0;
    ck_assert_int_eq(ret, CL_EWRITE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);

    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(gzip, gzip_length);
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    clamav_test_fail_close = 1;
    ret                    = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                                            scan_engine, &options, NULL, NULL, NULL, NULL,
                                            "CL_TYPE_GZ", NULL);
    clamav_test_fail_close = 0;
    ck_assert_int_eq(ret, CL_EWRITE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
    free(gzip);
}
END_TEST
#endif

START_TEST(test_zip_truncated_entry_paths_are_fail_visible)
{
    static const uint8_t archive[] = {0x50, 0x4b, 0x03, 0x04};
    uint8_t variable_header[32] = {0};
    uint8_t truncated_extra[34] = {0};
    uint8_t truncated_zip64[38] = {0};
    const uint8_t *variable_fixtures[3];
    const size_t variable_fixture_lengths[3] = {
        sizeof(variable_header),
        sizeof(truncated_extra),
        sizeof(truncated_zip64),
    };
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_scan_layer_t layer;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;
    size_t fixture_index;

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&layer, 0, sizeof(layer));
    memset(&ctx, 0, sizeof(ctx));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    map = cl_fmap_open_memory(archive, sizeof(archive));
    ck_assert_ptr_nonnull(map);
    ctx.engine            = &engine;
    ctx.options           = &options;
    ctx.fmap              = map;
    ctx.this_layer_tmpdir = tmpdir;
    ctx.recursion_stack  = &layer;
    ctx.recursion_stack_size = 1;
    layer.fmap            = map;

    ret = cli_unzip(&ctx);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);
    cl_fmap_close(map);

    map = cl_fmap_open_memory(archive, sizeof(archive));
    ck_assert_ptr_nonnull(map);
    memset(&ctx, 0, sizeof(ctx));
    ctx.engine            = &engine;
    ctx.options           = &options;
    ctx.fmap              = map;
    ctx.this_layer_tmpdir = tmpdir;

    ret = unzip_search(&ctx, &(struct zip_requests){0});
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);
    cl_fmap_close(map);

    map = cl_fmap_open_memory(archive, sizeof(archive));
    ck_assert_ptr_nonnull(map);
    memset(&ctx, 0, sizeof(ctx));
    ctx.engine            = &engine;
    ctx.options           = &options;
    ctx.fmap              = map;
    ctx.this_layer_tmpdir = tmpdir;

    ret = unzip_single_internal(&ctx, 0, NULL);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);
    cl_fmap_close(map);

    /* Reach the variable local-header fields: the fixed 30-byte header is
     * complete, but the declared filename extends beyond the mapped slice.
     * This is the fallback path that previously returned clean with no
     * records when the central directory was absent. */
    zip_stream_write_u32(variable_header, 0x04034b50U);
    zip_stream_write_u16(variable_header + 4, 20U);
    zip_stream_write_u16(variable_header + 26, 8U);
    memcpy(variable_header + 30, "ab", 2);
    variable_fixtures[0] = variable_header;

    /* The fixed header is complete, but the declared extra field extends
     * beyond the mapped slice. */
    zip_stream_write_u32(truncated_extra, 0x04034b50U);
    zip_stream_write_u16(truncated_extra + 4, 20U);
    zip_stream_write_u16(truncated_extra + 28, 8U);
    zip_stream_write_u16(truncated_extra + 30, 0x5455U);
    zip_stream_write_u16(truncated_extra + 32, 4U);
    variable_fixtures[1] = truncated_extra;

    /* A ZIP64 local header declares both 64-bit sizes, but its ZIP64 extra
     * field contains only a prefix of the required values. */
    zip_stream_write_u32(truncated_zip64, 0x04034b50U);
    zip_stream_write_u16(truncated_zip64 + 4, 45U);
    zip_stream_write_u32(truncated_zip64 + 18, UINT32_MAX);
    zip_stream_write_u32(truncated_zip64 + 22, UINT32_MAX);
    zip_stream_write_u16(truncated_zip64 + 28, 20U);
    zip_stream_write_u16(truncated_zip64 + 30, 0x0001U);
    zip_stream_write_u16(truncated_zip64 + 32, 16U);
    zip_stream_write_u32(truncated_zip64 + 34, 1U);
    variable_fixtures[2] = truncated_zip64;

    for (fixture_index = 0; fixture_index < 3; fixture_index++) {
        map = cl_fmap_open_memory(variable_fixtures[fixture_index],
                                  variable_fixture_lengths[fixture_index]);
        ck_assert_ptr_nonnull(map);
        memset(&ctx, 0, sizeof(ctx));
        ctx.engine            = &engine;
        ctx.options           = &options;
        ctx.fmap              = map;
        ctx.this_layer_tmpdir = tmpdir;

        ret = cli_unzip(&ctx);
        ck_assert_int_eq(ret, CL_EPARSE);
        ck_assert(ctx.scan_incomplete);
        ck_assert(map->dont_cache_flag);
        cl_fmap_close(map);
    }
}
END_TEST

static const void *zip_local_filename_read_failure(fmap_t *map, size_t at, size_t len, int lock)
{
    (void)lock;
    if (at == 30U)
        return NULL;
    if (len == 0 || at > map->len || len > map->len - at)
        return NULL;
    return (const uint8_t *)map->data + at;
}

static size_t zip_targeted_read_failure_offset;

static const void *zip_targeted_read_failure(fmap_t *map, size_t at, size_t len, int lock)
{
    (void)lock;
    if (at == zip_targeted_read_failure_offset)
        return NULL;
    if (len == 0 || at > map->len || len > map->len - at)
        return NULL;
    return (const uint8_t *)map->data + at;
}

static const void *compressed_input_read_failure(fmap_t *map, size_t at, size_t len, int lock)
{
    (void)lock;
    if (at == 0U)
        return NULL;
    if (len == 0 || at > map->len || len > map->len - at)
        return NULL;
    return (const uint8_t *)map->data + at;
}

START_TEST(test_zip_local_filename_read_failure_is_fail_visible)
{
    uint8_t archive[31] = {0};
    struct cl_engine engine;
    cli_ctx ctx;
    cli_scan_layer_t layer;
    fmap_t *map;
    cl_error_t ret;

    /* A complete empty stored member reaches the filename window without
     * needing a decoder or nested scan callback. */
    archive[0]  = 0x50;
    archive[1]  = 0x4b;
    archive[2]  = 0x03;
    archive[3]  = 0x04;
    archive[4]  = 20U;
    archive[26] = 1U;
    archive[30] = 'x';

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    memset(&layer, 0, sizeof(layer));
    map = cl_fmap_open_memory(archive, sizeof(archive));
    ck_assert_ptr_nonnull(map);
    map->need             = zip_local_filename_read_failure;
    ctx.engine            = &engine;
    ctx.fmap              = map;
    ctx.recursion_stack   = &layer;
    ctx.recursion_stack_size = 1;
    layer.fmap            = map;

    ret = unzip_single_internal(&ctx, 0, NULL);
    ck_assert_int_eq(ret, CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason,
                     "ZIP local filename field could not be read completely");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_zip_local_header_index_read_failure_is_fail_visible)
{
    static const uint8_t input[30] = {0};
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    struct zip_record *catalogue = NULL;
    size_t num_records           = 0;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(input, sizeof(input));
    ck_assert_ptr_nonnull(map);
    zip_targeted_read_failure_offset = 0;
    map->need = zip_targeted_read_failure;
    ctx.engine = &engine;
    ctx.fmap   = map;

    ret = index_local_file_headers_within_bounds(&ctx, map, map->len, 0,
                                                 map->len, 0, &catalogue,
                                                 &num_records);
    ck_assert_int_eq(ret, CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason,
                     "ZIP local-header discovery window could not be read completely");
    ck_assert(map->dont_cache_flag);
    ck_assert_ptr_null(catalogue);
    ck_assert_uint_eq(num_records, 0U);

    cl_fmap_close(map);
    zip_targeted_read_failure_offset = 0;
}
END_TEST

START_TEST(test_zip_local_header_read_failure_is_fail_visible)
{
    static const uint8_t input[30] = {0};
    struct cl_engine engine;
    cli_ctx ctx;
    cli_scan_layer_t layer;
    fmap_t *map;
    size_t zip_size = 0;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    memset(&layer, 0, sizeof(layer));
    map = cl_fmap_open_memory(input, sizeof(input));
    ck_assert_ptr_nonnull(map);
    zip_targeted_read_failure_offset = 0;
    map->need                     = zip_targeted_read_failure;
    ctx.engine                    = &engine;
    ctx.fmap                      = map;
    ctx.recursion_stack           = &layer;
    ctx.recursion_stack_size      = 1;
    layer.fmap                    = map;

    ret = cli_unzip_single_header_check(&ctx, 0, &zip_size);
    ck_assert_int_eq(ret, CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason,
                     "ZIP local header could not be read completely");
    ck_assert(map->dont_cache_flag);
    ck_assert_uint_eq(zip_size, 0U);

    cl_fmap_close(map);
    zip_targeted_read_failure_offset = 0;
}
END_TEST

START_TEST(test_gzip_bzip_truncated_streams_are_fail_visible)
{
    static const uint8_t input[] = "large-file compressed stream boundary";
    static const char *const types[] = {"CL_TYPE_GZ", "CL_TYPE_BZ"};
    uint8_t *gzip;
    uint8_t *bzip;
    size_t lengths[2];
    const uint8_t *archives[2];
    size_t i;

    gzip        = gzip_stream(input, sizeof(input) - 1U, &lengths[0]);
    bzip        = zip_stream_bzip2(input, sizeof(input) - 1U, &lengths[1]);
    archives[0] = gzip;
    archives[1] = bzip;

    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    for (i = 0; i < 2; i++) {
        struct cl_scan_options options;
        fmap_t *map;
        struct cl_engine *scan_engine;
        cl_verdict_t verdict;
        const char *last_alert;
        uint64_t scanned;
        cl_error_t ret;

        ck_assert_msg(lengths[i] > 1, "%s fixture unexpectedly short", types[i]);
        memset(&options, 0, sizeof(options));
        options.parse = CL_SCAN_PARSE_ARCHIVE;
        scan_engine = cl_engine_new();
        ck_assert_ptr_nonnull(scan_engine);
        ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
        map = cl_fmap_open_memory(archives[i], lengths[i] - 1U);
        ck_assert_ptr_nonnull(map);
        verdict    = CL_VERDICT_STRONG_INDICATOR;
        last_alert = "stale";
        scanned    = UINT64_MAX;

        ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                            scan_engine, &options, NULL, NULL, NULL, NULL,
                            types[i], NULL);
        ck_assert_msg(ret == CL_EUNPACK || ret == CL_EPARSE,
                      "%s truncated stream returned %s (%d)", types[i],
                      cl_strerror(ret), ret);
        ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
        ck_assert(last_alert == NULL);
        ck_assert(map->dont_cache_flag);

        cl_fmap_close(map);
        cl_engine_free(scan_engine);
    }

    free(gzip);
    free(bzip);
}
END_TEST

START_TEST(test_compressed_input_read_failure_is_fail_visible)
{
    static const uint8_t xz[] = {
        0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04,
        0xe6, 0xd6, 0xb4, 0x46, 0x02, 0x00, 0x21, 0x01,
        0x16, 0x00, 0x00, 0x00, 0x74, 0x2f, 0xe5,
        0xa3, 0x01, 0x00, 0x0c, 0x78, 0x7a, 0x2d, 0x6c,
        0x69, 0x6d, 0x69, 0x74, 0x2d, 0x74, 0x65, 0x73,
        0x74, 0x00, 0x00, 0x00, 0x00, 0x6f, 0xc7, 0xf2, 0xf6,
        0xa5, 0x44, 0x03, 0x64, 0x00, 0x01, 0x25, 0x0d,
        0x71, 0x19, 0xc4, 0xb6, 0x1f, 0xb6, 0xf3, 0x7d,
        0x01, 0x00, 0x00, 0x00, 0x04, 0x59, 0x5a};
    static const char *const types[] = {"CL_TYPE_GZ", "CL_TYPE_BZ", "CL_TYPE_XZ"};
    uint8_t *gzip;
    uint8_t *bzip;
    const uint8_t *archives[3];
    size_t lengths[3];
    static const uint8_t input[] = "compressed fmap callback failure";
    size_t i;

    gzip         = gzip_stream(input, sizeof(input) - 1U, &lengths[0]);
    bzip         = zip_stream_bzip2(input, sizeof(input) - 1U, &lengths[1]);
    archives[0]  = gzip;
    archives[1]  = bzip;
    archives[2]  = xz;
    lengths[2]   = sizeof(xz);
    ck_assert_ptr_nonnull(gzip);
    ck_assert_ptr_nonnull(bzip);

    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    for (i = 0; i < 3; i++) {
        struct cl_scan_options options;
        struct cl_engine *scan_engine;
        cl_verdict_t verdict;
        const char *last_alert;
        uint64_t scanned;
        fmap_t *map;
        cl_error_t ret;

        memset(&options, 0, sizeof(options));
        options.parse = CL_SCAN_PARSE_ARCHIVE;
        scan_engine = cl_engine_new();
        ck_assert_ptr_nonnull(scan_engine);
        ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
        map = cl_fmap_open_memory(archives[i], lengths[i]);
        ck_assert_ptr_nonnull(map);
        map->need   = compressed_input_read_failure;
        verdict     = CL_VERDICT_STRONG_INDICATOR;
        last_alert  = "stale";
        scanned     = UINT64_MAX;

        ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                            scan_engine, &options, NULL, NULL, NULL, NULL,
                            types[i], NULL);
        ck_assert_msg(ret == CL_EREAD,
                      "%s callback failure returned %s (%d)", types[i],
                      cl_strerror(ret), ret);
        ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
        ck_assert_ptr_null(last_alert);
        ck_assert(map->dont_cache_flag);

        cl_fmap_close(map);
        cl_engine_free(scan_engine);
    }

    free(gzip);
    free(bzip);
}
END_TEST

START_TEST(test_xz_limit_is_fail_visible)
{
    static const uint8_t archive[] = {
        0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04,
        0xe6, 0xd6, 0xb4, 0x46, 0x02, 0x00, 0x21, 0x01,
        0x16, 0x00, 0x00, 0x00, 0x74, 0x2f, 0xe5,
        0xa3, 0x01, 0x00, 0x0c, 0x78, 0x7a, 0x2d, 0x6c,
        0x69, 0x6d, 0x69, 0x74, 0x2d, 0x74, 0x65, 0x73,
        0x74, 0x00, 0x00, 0x00, 0x00, 0x6f, 0xc7, 0xf2, 0xf6,
        0xa5, 0x44, 0x03, 0x64, 0x00, 0x01, 0x25, 0x0d,
        0x71, 0x19, 0xc4, 0xb6, 0x1f, 0xb6, 0xf3, 0x7d,
        0x01, 0x00, 0x00, 0x00, 0x04, 0x59, 0x5a};
    struct cl_scan_options options;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    fmap_t *map;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_set_num(scan_engine, CL_ENGINE_MAX_SCANSIZE, 1), CL_SUCCESS);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(archive, sizeof(archive));
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL,
                        "CL_TYPE_XZ", NULL);
    ck_assert_int_eq(ret, CL_EMAXSIZE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_xz_truncated_stream_is_fail_visible)
{
    static const uint8_t archive[] = {
        0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04,
        0xe6, 0xd6, 0xb4, 0x46, 0x02, 0x00, 0x21, 0x01,
        0x16, 0x00, 0x00, 0x00, 0x74, 0x2f, 0xe5,
        0xa3, 0x01, 0x00, 0x0c, 0x78, 0x7a, 0x2d, 0x6c,
        0x69, 0x6d, 0x69, 0x74, 0x2d, 0x74, 0x65, 0x73,
        0x74, 0x00, 0x00, 0x00, 0x00, 0x6f, 0xc7, 0xf2, 0xf6,
        0xa5, 0x44, 0x03, 0x64, 0x00, 0x01, 0x25, 0x0d,
        0x71, 0x19, 0xc4, 0xb6, 0x1f, 0xb6, 0xf3, 0x7d,
        0x01, 0x00, 0x00, 0x00, 0x04, 0x59, 0x5a};
    struct cl_scan_options options;
    struct cl_engine *scan_engine;
    cl_fmap_t *map;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    ck_assert_msg(sizeof(archive) > 1U, "XZ fixture unexpectedly short");
    map = cl_fmap_open_memory(archive, sizeof(archive) - 1U);
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL,
                        "CL_TYPE_XZ", NULL);
    ck_assert_msg(ret == CL_EUNPACK || ret == CL_EPARSE,
                  "truncated XZ stream returned %s (%d)", cl_strerror(ret), ret);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_compressed_output_temporary_limit_is_fail_visible)
{
    static const uint8_t xz_archive[] = {
        0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04,
        0xe6, 0xd6, 0xb4, 0x46, 0x02, 0x00, 0x21, 0x01,
        0x16, 0x00, 0x00, 0x00, 0x74, 0x2f, 0xe5,
        0xa3, 0x01, 0x00, 0x0c, 0x78, 0x7a, 0x2d, 0x6c,
        0x69, 0x6d, 0x69, 0x74, 0x2d, 0x74, 0x65, 0x73,
        0x74, 0x00, 0x00, 0x00, 0x00, 0x6f, 0xc7, 0xf2, 0xf6,
        0xa5, 0x44, 0x03, 0x64, 0x00, 0x01, 0x25, 0x0d,
        0x71, 0x19, 0xc4, 0xb6, 0x1f, 0xb6, 0xf3, 0x7d,
        0x01, 0x00, 0x00, 0x00, 0x04, 0x59, 0x5a};
    static const char *const types[] = {"CL_TYPE_GZ", "CL_TYPE_BZ", "CL_TYPE_XZ"};
    static const uint8_t *const static_archives[] = {NULL, NULL, xz_archive};
    static const size_t static_lengths[] = {0, 0, sizeof(xz_archive)};
    static const uint8_t input[] = "compressed temporary quota";
    uint8_t *gzip;
    uint8_t *bzip;
    const uint8_t *archives[3];
    size_t lengths[3];
    size_t i;

    gzip      = gzip_stream(input, sizeof(input) - 1U, &lengths[0]);
    bzip      = zip_stream_bzip2(input, sizeof(input) - 1U, &lengths[1]);
    archives[0] = gzip;
    archives[1] = bzip;
    archives[2] = static_archives[2];
    lengths[2]  = static_lengths[2];

    ck_assert_ptr_nonnull(gzip);
    ck_assert_ptr_nonnull(bzip);
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);

    for (i = 0; i < 3; i++) {
        struct cl_scan_options options;
        struct cl_engine *scan_engine;
        cl_verdict_t verdict;
        const char *last_alert;
        uint64_t scanned;
        fmap_t *map;
        cl_error_t ret;

        memset(&options, 0, sizeof(options));
        options.parse = CL_SCAN_PARSE_ARCHIVE;
        scan_engine = cl_engine_new();
        ck_assert_ptr_nonnull(scan_engine);
        ck_assert_int_eq(cl_engine_set_num(scan_engine, CL_ENGINE_MAX_TEMPORARY_SIZE, 1), CL_SUCCESS);
        ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
        map = cl_fmap_open_memory(archives[i], lengths[i]);
        ck_assert_ptr_nonnull(map);
        verdict    = CL_VERDICT_STRONG_INDICATOR;
        last_alert = "stale";
        scanned    = UINT64_MAX;

        ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                            scan_engine, &options, NULL, NULL, NULL, NULL,
                            types[i], NULL);
        /* The XZ wrapper may normalize a sticky incomplete scan to
         * CL_EPARSE while preserving the fail-closed verdict and cache
         * state. The resource-limit paths must never look clean. */
        ck_assert_msg(ret == CL_ERESOURCE || (i == 2 && ret == CL_EPARSE),
                      "%s temporary limit returned %s (%d)", types[i],
                      cl_strerror(ret), ret);
        ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
        ck_assert(last_alert == NULL);
        ck_assert(map->dont_cache_flag);

        cl_fmap_close(map);
        cl_engine_free(scan_engine);
    }

    free(gzip);
    free(bzip);
}
END_TEST

START_TEST(test_swf_truncated_uncompressed_header_is_fail_visible)
{
    static const uint8_t archive[] = {'F', 'W', 'S', 9U};
    static const uint8_t declared_size[] = {'F', 'W', 'S', 9U, 9U, 0U, 0U, 0U};
    struct cl_scan_options options;
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_SWF | CL_SCAN_PARSE_ARCHIVE;
    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(archive, sizeof(archive));
    ck_assert_ptr_nonnull(map);
    ctx.engine            = &engine;
    ctx.options           = &options;
    ctx.fmap              = map;
    ctx.this_layer_tmpdir = tmpdir;

    ret = cli_scanswf(&ctx);
    ck_assert_msg(ret == CL_EPARSE,
                  "truncated FWS header returned %s (%d)", cl_strerror(ret), ret);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);

    map = cl_fmap_open_memory(declared_size, sizeof(declared_size));
    ck_assert_ptr_nonnull(map);
    memset(&ctx, 0, sizeof(ctx));
    ctx.engine            = &engine;
    ctx.options           = &options;
    ctx.fmap              = map;
    ctx.this_layer_tmpdir = tmpdir;

    ret = cli_scanswf(&ctx);
    ck_assert_msg(ret == CL_EPARSE,
                  "short FWS body returned %s (%d)", cl_strerror(ret), ret);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_swf_time_limit_is_fail_visible)
{
    static const uint8_t data[] = {0};
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine = &engine;
    ctx.fmap   = map;
    ck_assert_int_eq(gettimeofday(&ctx.time_limit, NULL), 0);
    ctx.time_limit.tv_sec--;

    ret = cli_scanswf(&ctx);
    ck_assert_int_eq(ret, CL_ETIMEOUT);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "SWF inspection reached the configured time limit");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

static size_t swf_read_failure_offset = SIZE_MAX;

static const void *swf_targeted_read_failure(fmap_t *map, size_t at, size_t len, int lock)
{
    (void)lock;
    if (at == swf_read_failure_offset)
        return NULL;
    if (len == 0 || at > map->len || len > map->len - at)
        return NULL;
    return (const uint8_t *)map->data + at;
}

START_TEST(test_swf_required_read_failure_is_fail_visible)
{
    static const uint8_t archive[] = {'F', 'W', 'S', 9U, 9U, 0U, 0U, 0U, 0U};
    static const size_t failure_offsets[] = {0U, 8U};
    static const char *const reasons[] = {
        "SWF file header could not be read completely",
        "SWF frame metadata could not be read completely"};
    struct cl_scan_options options;
    struct cl_engine engine;
    cli_ctx ctx;
    size_t i;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_SWF | CL_SCAN_PARSE_ARCHIVE;
    memset(&engine, 0, sizeof(engine));

    for (i = 0; i < sizeof(failure_offsets) / sizeof(failure_offsets[0]); i++) {
        fmap_t *map;
        cl_error_t ret;

        map = cl_fmap_open_memory(archive, sizeof(archive));
        ck_assert_ptr_nonnull(map);
        swf_read_failure_offset = failure_offsets[i];
        map->need                       = swf_targeted_read_failure;
        memset(&ctx, 0, sizeof(ctx));
        ctx.engine            = &engine;
        ctx.options           = &options;
        ctx.fmap              = map;
        ctx.this_layer_tmpdir = tmpdir;

        ret = cli_scanswf(&ctx);
        ck_assert_int_eq(ret, CL_EREAD);
        ck_assert(ctx.scan_incomplete);
        ck_assert_str_eq(ctx.scan_incomplete_reason, reasons[i]);
        ck_assert(map->dont_cache_flag);

        cl_fmap_close(map);
    }
    swf_read_failure_offset = SIZE_MAX;
}
END_TEST

START_TEST(test_swf_truncated_frame_metadata_is_fail_visible)
{
    static const uint8_t archive[] = {'F', 'W', 'S', 9U, 9U, 0U, 0U, 0U, 0U};
    struct cl_scan_options options;
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_SWF | CL_SCAN_PARSE_ARCHIVE;
    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(archive, sizeof(archive));
    ck_assert_ptr_nonnull(map);
    ctx.engine  = &engine;
    ctx.options = &options;
    ctx.fmap    = map;

    /* The header and one frame-metadata byte fit, but the required frame
     * count is truncated after the parser has entered the FWS path. */
    ret = cli_scanswf(&ctx);
    ck_assert_int_eq(ret, CL_EFORMAT);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_swf_truncated_tag_payload_is_fail_visible)
{
    static const uint8_t archive[] = {
        'F', 'W', 'S', 9U, 16U, 0U, 0U, 0U,
        0U, 0U, 0U, 0U, 0U,
        0x4aU, 0x00U, 0U};
    struct cl_scan_options options;
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;
    uint8_t old_debug;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_SWF | CL_SCAN_PARSE_ARCHIVE;
    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(archive, sizeof(archive));
    ck_assert_ptr_nonnull(map);
    ctx.engine  = &engine;
    ctx.options = &options;
    ctx.fmap    = map;

    old_debug = cli_set_debug_flag(1);
    ret       = cli_scanswf(&ctx);
    (void)cli_set_debug_flag(old_debug);

    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_msxml_truncated_document_is_fail_visible)
{
    static const uint8_t document[] = "<worddocument><author>truncated";
    struct cl_scan_options options;
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_XMLDOCS | CL_SCAN_PARSE_ARCHIVE;
    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(document, sizeof(document) - 1U);
    ck_assert_ptr_nonnull(map);
    ctx.engine  = &engine;
    ctx.options = &options;
    ctx.fmap    = map;

    ret = cli_scanmsxml(&ctx);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_msxml_base64_decode_failure_is_fail_visible)
{
    static const uint8_t document[] = "<chunk>QUJD$A==</chunk>";
    static const struct key_entry keys[] = {{"chunk", "Chunk", MSXML_SCAN_B64}};
    struct cl_engine engine;
    struct msxml_ctx mxctx;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;
    xmlTextReaderPtr reader;

    memset(&engine, 0, sizeof(engine));
    memset(&mxctx, 0, sizeof(mxctx));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(document, sizeof(document) - 1U);
    ck_assert_ptr_nonnull(map);
    reader = xmlReaderForMemory((const char *)document, (int)(sizeof(document) - 1U), "msxml-base64.xml", NULL, 0);
    ck_assert_ptr_nonnull(reader);
    ctx.engine = &engine;
    ctx.fmap   = map;

    ret = cli_msxml_parse_document(&ctx, reader, keys, sizeof(keys) / sizeof(keys[0]), MSXML_FLAG_FAIL_INCOMPLETE, &mxctx);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "MSXML base64 data was malformed or could not be decoded completely");

    xmlFreeTextReader(reader);
    cl_fmap_close(map);
}
END_TEST

START_TEST(test_msxml_stream_time_limit_is_fail_visible)
{
    static const uint8_t document[] = "<chunk>QUJD</chunk>";
    static const struct key_entry keys[] = {{"chunk", "Chunk", MSXML_SCAN_B64}};
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(document, sizeof(document) - 1U);
    ck_assert_ptr_nonnull(map);
    ctx.engine = &engine;
    ctx.fmap   = map;
    ck_assert_int_eq(gettimeofday(&ctx.time_limit, NULL), 0);
    ctx.time_limit.tv_sec--;

    ret = cli_msxml_parse_document_streaming(&ctx, map, keys, sizeof(keys) / sizeof(keys[0]),
                                             MSXML_FLAG_FAIL_INCOMPLETE, NULL);
    ck_assert_int_eq(ret, CL_ETIMEOUT);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "MSXML streaming inspection reached the configured time limit");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_xdp_time_limit_is_fail_visible)
{
    static const uint8_t document[] = "<chunk>QUJD</chunk>";
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(document, sizeof(document) - 1U);
    ck_assert_ptr_nonnull(map);
    engine.keeptmp = 1;
    ctx.engine     = &engine;
    ctx.fmap       = map;
    ck_assert_int_eq(gettimeofday(&ctx.time_limit, NULL), 0);
    ctx.time_limit.tv_sec--;

    ret = cli_scanxdp(&ctx);
    ck_assert_int_eq(ret, CL_ETIMEOUT);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "XDP temporary dump reached the configured time limit");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_rtf_truncated_document_is_fail_visible)
{
    static const uint8_t document[] = {'{', '\\', 'r', 't', 'f', '1'};
    struct cl_scan_options options;
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(document, sizeof(document));
    ck_assert_ptr_nonnull(map);
    ctx.engine            = &engine;
    ctx.options           = &options;
    ctx.fmap              = map;
    ctx.this_layer_tmpdir = tmpdir;

    ret = cli_scanrtf(&ctx);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_rtf_time_limit_is_fail_visible)
{
    static const uint8_t data[] = {0};
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine = &engine;
    ctx.fmap   = map;
    ck_assert_int_eq(gettimeofday(&ctx.time_limit, NULL), 0);
    ctx.time_limit.tv_sec--;

    ret = cli_scanrtf(&ctx);
    ck_assert_int_eq(ret, CL_ETIMEOUT);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "RTF inspection reached the configured time limit");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

static const void *rtf_input_read_failure(fmap_t *map, size_t at, size_t len, int lock)
{
    (void)map;
    (void)at;
    (void)len;
    (void)lock;
    return NULL;
}

START_TEST(test_rtf_input_read_failure_is_fail_visible)
{
    static const uint8_t document[] = {'{', '\\', 'r', 't', 'f', '1', ' '};
    struct cl_scan_options options;
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(document, sizeof(document));
    ck_assert_ptr_nonnull(map);
    map->need               = rtf_input_read_failure;
    ctx.engine              = &engine;
    ctx.options             = &options;
    ctx.fmap                = map;
    ctx.this_layer_tmpdir   = tmpdir;

    ret = cli_scanrtf(&ctx);
    ck_assert_int_eq(ret, CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "RTF input could not be read completely");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_rtf_split_object_data_header_is_fail_visible)
{
    static const char object_prefix[] = "{\\object{\\objdata ";
    static const char object_header[] = "010500000200000000000000000000000000000002000000";
    static const char object_suffix[] = "41}}}";
    struct cl_scan_options options;
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;
    char *document;
    size_t length = 0;
    size_t padding;

    document = calloc(1, 20000);
    ck_assert_ptr_nonnull(document);
    memcpy(document + length, "{\\rtf1 ", strlen("{\\rtf1 "));
    length += strlen("{\\rtf1 ");
    padding = (8190U + 8192U - (length + strlen(object_prefix) + strlen(object_header)) % 8192U) % 8192U;
    memset(document + length, 'a', padding);
    length += padding;
    memcpy(document + length, object_prefix, strlen(object_prefix));
    length += strlen(object_prefix);
    memcpy(document + length, object_header, strlen(object_header));
    length += strlen(object_header);
    memcpy(document + length, object_suffix, strlen(object_suffix));
    length += strlen(object_suffix);

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(document, length);
    ck_assert_ptr_nonnull(map);
    ctx.engine            = &engine;
    ctx.options           = &options;
    ctx.fmap              = map;
    ctx.this_layer_tmpdir = tmpdir;

    ret = cli_scanrtf(&ctx);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    free(document);
}
END_TEST

START_TEST(test_ole10_truncated_object_is_fail_visible)
{
    char file_path[PATH_MAX];
    uint32_t object_size = 8;
    struct cl_scan_options options;
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;
    int fd;

    snprintf(file_path, sizeof(file_path), "%s/ole10-truncated-object", tmpdir);
    fd = open(file_path, O_RDWR | O_CREAT | O_TRUNC | O_BINARY, 0600);
    ck_assert_msg(fd >= 0, "open(%s) failed: %s", file_path, strerror(errno));
    ck_assert_int_eq(write(fd, &object_size, sizeof(object_size)), (ssize_t)sizeof(object_size));
    ck_assert_int_eq(write(fd, "x", 1), 1);
    ck_assert_int_eq(lseek(fd, 0, SEEK_SET), 0);

    map = fmap_new(fd, 0, 0, file_path, NULL);
    ck_assert_ptr_nonnull(map);
    memset(&options, 0, sizeof(options));
    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    ctx.engine            = &engine;
    ctx.options           = &options;
    ctx.fmap              = map;
    ctx.this_layer_tmpdir = tmpdir;

    ret = cli_scan_ole10(fd, &ctx);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    close(fd);
    unlink(file_path);
}
END_TEST

START_TEST(test_ole10_temporary_limit_is_fail_visible)
{
    char file_path[PATH_MAX];
    uint32_t object_size = 8;
    struct cl_scan_options options;
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;
    int fd;

    snprintf(file_path, sizeof(file_path), "%s/ole10-temporary-limit", tmpdir);
    fd = open(file_path, O_RDWR | O_CREAT | O_TRUNC | O_BINARY, 0600);
    ck_assert_msg(fd >= 0, "open(%s) failed: %s", file_path, strerror(errno));
    ck_assert_int_eq(write(fd, &object_size, sizeof(object_size)), (ssize_t)sizeof(object_size));
    ck_assert_int_eq(write(fd, "12345", 5), 5);
    ck_assert_int_eq(lseek(fd, 0, SEEK_SET), 0);

    map = fmap_new(fd, 0, 0, file_path, NULL);
    ck_assert_ptr_nonnull(map);
    memset(&options, 0, sizeof(options));
    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    engine.maxtemporarysize = object_size - 1U;
    ctx.engine              = &engine;
    ctx.options             = &options;
    ctx.fmap                = map;
    ctx.this_layer_tmpdir   = tmpdir;

    ret = cli_scan_ole10(fd, &ctx);
    ck_assert_int_eq(ret, CL_ERESOURCE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    close(fd);
    unlink(file_path);
}
END_TEST

#if HAVE_UNRAR
START_TEST(test_rar_truncated_header_is_fail_visible)
{
    static const uint8_t data[] = {
        0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00, /* RAR 1.5-4.x signature */
        0x30, 0x6f,                               /* archive-header CRC16 */
        0x73, 0x00, 0x00, 0x0d,                   /* archive header */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x74                                        /* truncated file header */
    };
    struct cl_scan_options options;
    struct cl_engine *scan_engine;
    cl_fmap_t *map;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL, "CL_TYPE_RAR", NULL);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

#ifndef _WIN32
struct rar_stage_pread_state {
    uint8_t data[FILEBUFF * 32U];
    size_t fail_at;
    unsigned int successful_reads;
};

static off_t rar_stage_pread_cb(void *handle, void *buf, size_t count, off_t offset)
{
    struct rar_stage_pread_state *state = handle;

    if (offset < 0 || (uint64_t)offset >= state->fail_at || count > state->fail_at - (size_t)offset)
        return -1;
    memcpy(buf, state->data + (size_t)offset, count);
    state->successful_reads++;
    return (off_t)count;
}

START_TEST(test_rar_nested_stage_read_failure_is_publicly_fail_visible)
{
    struct rar_stage_pread_state state;
    struct cl_scan_options options;
    struct cl_engine *scan_engine;
    cl_fmap_t *parent;
    cl_fmap_t *nested;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    memset(&state, 0, sizeof(state));
    memset(state.data, 0x5a, sizeof(state.data));
    /* The nested map starts at parent offset 1.  Fail the first staged
     * window so the RAR path exercises the real partial-copy disposition,
     * rather than merely handing a truncated archive to UnRAR. */
    state.fail_at = 2U;
    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;

    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);

    parent = cl_fmap_open_handle(&state, 0, sizeof(state.data), rar_stage_pread_cb, 1);
    ck_assert_ptr_nonnull(parent);
    nested = fmap_duplicate(parent, 1, parent->len - 1U, "nested-rar-stage");
    ck_assert_ptr_nonnull(nested);

    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;
    ret = cl_scanmap_ex(nested, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL,
                        "CL_TYPE_RAR", NULL);
    ck_assert_msg(ret != CL_SUCCESS,
                  "nested RAR staging read failure normalized to clean (%d)", ret);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(nested->dont_cache_flag);

    /* RAR staging must be admitted against the temporary quota before any
     * nested fmap bytes are copied to disk. */
    scan_engine->maxtemporarysize = nested->len - 1U;
    state.successful_reads       = 0;
    nested->dont_cache_flag      = false;
    verdict                      = CL_VERDICT_STRONG_INDICATOR;
    last_alert                   = "stale";
    scanned                      = UINT64_MAX;
    ret = cl_scanmap_ex(nested, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL,
                        "CL_TYPE_RAR", NULL);
    ck_assert_int_eq(ret, CL_ERESOURCE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(nested->dont_cache_flag);
    ck_assert_uint_eq(state.successful_reads, 0);

    free_duplicate_fmap(nested);
    cl_fmap_close(parent);
    cl_engine_free(scan_engine);
}
END_TEST
#endif

#endif

START_TEST(test_rar_without_backend_is_explicitly_unsupported)
{
    static const uint8_t data[] = {
        0x58,                                      /* parent payload prefix */
        0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00, /* RAR signature */
        0x00, 0x00,                               /* header CRC16 */
        0x73, 0x00, 0x00,                         /* RAR4 main header */
        0x07, 0x00};                               /* header size */
    static const char *const types[] = {"CL_TYPE_RAR", "CL_TYPE_RARSFX"};
    struct cl_scan_options options;
    struct cl_engine *scan_engine;
    cl_error_t results[2];
    cl_verdict_t verdicts[2];
    const char *alerts[2];
    int cache_flags[2];
    cl_error_t embedded_result;
    cl_verdict_t embedded_verdict;
    const char *embedded_alert;
    int embedded_cache_flag;
    int saved_sdb;
    int saved_have_rar;
    unsigned int i;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);

    saved_have_rar = have_rar;
    have_rar       = 0;
    for (i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
        fmap_t *map = cl_fmap_open_memory(data, sizeof(data));
        uint64_t scanned;

        ck_assert_ptr_nonnull(map);
        verdicts[i] = CL_VERDICT_STRONG_INDICATOR;
        alerts[i]   = "stale";
        scanned     = UINT64_MAX;
        results[i]  = cl_scanmap_ex(map, NULL, &verdicts[i], &alerts[i], &scanned,
                                    scan_engine, &options, NULL, NULL, NULL, NULL,
                                    types[i], NULL);
        cache_flags[i] = map->dont_cache_flag;
        cl_fmap_close(map);
    }

    {
        fmap_t *map = cl_fmap_open_memory(data, sizeof(data));
        uint64_t scanned = UINT64_MAX;

        ck_assert_ptr_nonnull(map);
        saved_sdb           = scan_engine->sdb;
        scan_engine->sdb    = 1;
        embedded_verdict    = CL_VERDICT_STRONG_INDICATOR;
        embedded_alert      = "stale";
        embedded_result     = cl_scanmap_ex(map, NULL, &embedded_verdict, &embedded_alert, &scanned,
                                            scan_engine, &options, NULL, NULL, NULL, NULL,
                                            "CL_TYPE_TEXT_ASCII", NULL);
        scan_engine->sdb    = saved_sdb;
        embedded_cache_flag = map->dont_cache_flag;
        cl_fmap_close(map);
    }
    have_rar = saved_have_rar;

    for (i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
        ck_assert_int_eq(results[i], CL_EPARSE);
        ck_assert_int_eq(verdicts[i], CL_VERDICT_NOTHING_FOUND);
        ck_assert(alerts[i] == NULL);
        ck_assert(cache_flags[i]);
    }
    ck_assert_int_eq(embedded_result, CL_EPARSE);
    ck_assert_int_eq(embedded_verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(embedded_alert == NULL);
    ck_assert(embedded_cache_flag);

    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_swf_zlib_truncated_stream_is_fail_visible)
{
    static const uint8_t body[6] = {0};
    struct cl_scan_options options;
    fmap_t *map;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    uint8_t *archive;
    size_t archive_length;
    cl_error_t ret;

    archive = swf_cws_stream(body, sizeof(body), &archive_length);
    ck_assert_msg(archive_length > 1, "CWS fixture unexpectedly short");
    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_SWF | CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(archive, archive_length - 1U);
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL,
                        "CL_TYPE_SWF", NULL);
    ck_assert_msg(ret == CL_EUNPACK || ret == CL_EPARSE,
                  "truncated CWS stream returned %s (%d)", cl_strerror(ret), ret);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
    free(archive);
}
END_TEST

START_TEST(test_swf_lzma_declared_input_size_is_fail_visible)
{
    static const uint8_t archive[] = {
        'Z', 'W', 'S', 13U, 8U, 0U, 0U, 0U, /* SWF header */
        1U, 0U, 0U, 0U,                    /* declared compressed length */
        0U, 0U, 0U, 0U, 0U                 /* LZMA properties, no payload */
    };
    struct cl_scan_options options;
    fmap_t *map;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_SWF | CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(archive, sizeof(archive));
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL,
                        "CL_TYPE_SWF", NULL);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_swf_output_temporary_limit_is_fail_visible)
{
    static const uint8_t body[6] = {0};
    struct cl_scan_options options;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    fmap_t *map;
    uint8_t *archive;
    size_t archive_length;
    cl_error_t ret;

    archive = swf_cws_stream(body, sizeof(body), &archive_length);
    ck_assert_ptr_nonnull(archive);
    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_SWF | CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_set_num(scan_engine, CL_ENGINE_MAX_TEMPORARY_SIZE, 1), CL_SUCCESS);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(archive, archive_length);
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL,
                        "CL_TYPE_SWF", NULL);
    ck_assert_msg(ret == CL_ERESOURCE,
                  "SWF temporary limit returned %s (%d)", cl_strerror(ret), ret);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
    free(archive);
}
END_TEST

#ifdef CLAMAV_TEST_JS_IO_WRAP
START_TEST(test_swf_cleanup_close_failure_is_fail_visible)
{
    static const uint8_t body[6] = {0};
    struct cl_scan_options options;
    fmap_t *map;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    uint8_t *archive;
    size_t archive_length;
    cl_error_t ret;

    archive = swf_cws_stream(body, sizeof(body), &archive_length);
    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_SWF | CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(archive, archive_length);
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    clamav_test_fail_close = 1;
    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL,
                        "CL_TYPE_SWF", NULL);
    clamav_test_fail_close = 0;

    ck_assert_msg(ret != CL_SUCCESS, "SWF temporary close failure returned clean");
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
    free(archive);
}
END_TEST
#endif

static cl_error_t zip_stream_run_local_flags(
    const uint8_t *input,
    size_t input_length,
    uint16_t method,
    uint16_t flags,
    size_t *max_read,
    bool *scan_incomplete,
    size_t *callback_calls)
{
    uint8_t *archive;
    size_t archive_length;
    uint32_t crc = (uint32_t)crc32(0L, input, (uInt)input_length);
    cl_error_t ret;

    archive = zip_stream_local_archive_flags(input, input_length,
                                             (uint32_t)input_length,
                                             method, flags, crc,
                                             &archive_length);
    ret = zip_stream_run_archive(archive, archive_length, input_length,
                                 NULL, input, input_length, max_read,
                                 scan_incomplete, callback_calls);
    return ret;
}

START_TEST(test_zip_unsupported_flags_and_method_are_fail_visible)
{
    const uint8_t input[] = "bounded-zip-policy";
    size_t max_read;
    size_t callback_calls;
    bool incomplete;
    cl_error_t ret;

    ret = zip_stream_run_local_flags(input, sizeof(input), ZIP_TEST_METHOD_STORED,
                                     ZIP_TEST_FLAG_STRONG_ENCRYPTION,
                                     &max_read, &incomplete, &callback_calls);
    ck_assert_int_eq(ret, CL_EUNPACK);
    ck_assert_uint_eq(callback_calls, 0);
    ck_assert(incomplete);

    ret = zip_stream_run_local_flags(input, sizeof(input), ZIP_TEST_METHOD_STORED,
                                     ZIP_TEST_FLAG_ENCRYPTED | ZIP_TEST_FLAG_STRONG_ENCRYPTION,
                                     &max_read, &incomplete, &callback_calls);
    ck_assert_int_eq(ret, CL_EUNPACK);
    ck_assert_uint_eq(callback_calls, 0);
    ck_assert(incomplete);

    ret = zip_stream_run_local_flags(input, sizeof(input), ZIP_TEST_METHOD_STORED,
                                     ZIP_TEST_FLAG_MASKED_HEADER,
                                     &max_read, &incomplete, &callback_calls);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert_uint_eq(callback_calls, 0);
    ck_assert(incomplete);

    ret = zip_stream_run_local_flags(input, sizeof(input), ZIP_TEST_METHOD_STORED,
                                     ZIP_TEST_FLAG_DATA_DESCRIPTOR,
                                     &max_read, &incomplete, &callback_calls);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert_uint_eq(callback_calls, 0);
    ck_assert(incomplete);

    ret = zip_stream_run_local_flags(input, sizeof(input), 99U, 0,
                                     &max_read, &incomplete, &callback_calls);
    ck_assert_int_eq(ret, CL_EUNPACK);
    ck_assert_uint_eq(callback_calls, 0);
    ck_assert(incomplete);
    ck_assert_msg(max_read <= CLI_ZIP_INPUT_CHUNK_SIZE + (size_t)cli_getpagesize(),
                  "unsupported ZIP method requested %zu bytes in one fmap read", max_read);
}
END_TEST

START_TEST(test_zip_central_directory_resolves_masked_local_values)
{
    static const uint8_t input[] = "masked-central-values";
    struct cl_engine *engine;
    struct cl_scan_options options;
    cli_scan_layer_t layers[2];
    cli_ctx ctx;
    cl_fmap_t *map;
    size_t archive_length;
    uint8_t *archive;
    cl_error_t ret;

    archive = zip_stream_central_masked_archive(input, sizeof(input) - 1U,
                                                sizeof(input) - 1U,
                                                ZIP_TEST_METHOD_STORED,
                                                (uint32_t)crc32(0L, input, (uInt)(sizeof(input) - 1U)),
                                                &archive_length);
    ck_assert_ptr_nonnull(archive);

    engine = cl_engine_new();
    ck_assert_ptr_nonnull(engine);
    ck_assert_int_eq(cl_engine_compile(engine), CL_SUCCESS);
    memset(&options, 0, sizeof(options));
    memset(layers, 0, sizeof(layers));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(archive, archive_length);
    ck_assert_ptr_nonnull(map);

    ctx.engine               = engine;
    ctx.options              = &options;
    ctx.dconf                = engine->dconf;
    ctx.fmap                 = map;
    ctx.this_layer_tmpdir    = tmpdir;
    ctx.recursion_stack      = layers;
    ctx.recursion_stack_size = 2;
    layers[0].type           = CL_TYPE_ZIP;
    layers[0].size           = archive_length;
    layers[0].fmap           = map;

    ret = cli_unzip(&ctx);
    ck_assert_int_eq(ret, CL_SUCCESS);
    ck_assert(!ctx.scan_incomplete);

    cl_fmap_close(map);
    cl_engine_free(engine);
    free(archive);
}
END_TEST

START_TEST(test_zip_central_filename_read_failure_is_fail_visible)
{
    static const uint8_t input[] = "central-directory-member";
    static const char member_name[] = "stream-test.bin";
    struct cl_engine *engine;
    struct cl_scan_options options;
    cli_scan_layer_t layer;
    cli_ctx ctx;
    fmap_t *map;
    size_t archive_length;
    size_t local_length;
    uint8_t *archive;
    cl_error_t ret;

    archive = zip_stream_central_archive(input, sizeof(input) - 1U,
                                         sizeof(input) - 1U,
                                         ZIP_TEST_METHOD_STORED,
                                         (uint32_t)crc32(0L, input, (uInt)(sizeof(input) - 1U)),
                                         &archive_length);
    ck_assert_ptr_nonnull(archive);

    local_length = 30U + (sizeof(member_name) - 1U) + (sizeof(input) - 1U);
    zip_targeted_read_failure_offset = local_length + 46U;

    engine = cl_engine_new();
    ck_assert_ptr_nonnull(engine);
    ck_assert_int_eq(cl_engine_compile(engine), CL_SUCCESS);
    memset(&options, 0, sizeof(options));
    memset(&layer, 0, sizeof(layer));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(archive, archive_length);
    ck_assert_ptr_nonnull(map);
    map->need                = zip_targeted_read_failure;
    ctx.engine               = engine;
    ctx.options              = &options;
    ctx.dconf                = engine->dconf;
    ctx.fmap                 = map;
    ctx.this_layer_tmpdir    = tmpdir;
    ctx.recursion_stack      = &layer;
    ctx.recursion_stack_size = 1;
    layer.type               = CL_TYPE_ZIP;
    layer.size               = archive_length;
    layer.fmap               = map;

    ret = cli_unzip(&ctx);
    ck_assert_int_eq(ret, CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason,
                     "ZIP central filename field could not be read completely");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(engine);
    free(archive);
    zip_targeted_read_failure_offset = 0;
}
END_TEST

START_TEST(test_zip_central_header_read_failure_is_fail_visible)
{
    static const uint8_t input[] = "central-header-read-failure";
    static const char member_name[] = "stream-test.bin";
    struct cl_engine *engine;
    struct cl_scan_options options;
    cli_scan_layer_t layer;
    cli_ctx ctx;
    fmap_t *map;
    size_t archive_length;
    size_t local_length;
    uint8_t *archive;
    cl_error_t ret;

    archive = zip_stream_central_archive(input, sizeof(input) - 1U,
                                         sizeof(input) - 1U,
                                         ZIP_TEST_METHOD_STORED,
                                         (uint32_t)crc32(0L, input, (uInt)(sizeof(input) - 1U)),
                                         &archive_length);
    ck_assert_ptr_nonnull(archive);

    local_length = 30U + (sizeof(member_name) - 1U) + (sizeof(input) - 1U);
    zip_targeted_read_failure_offset = local_length;

    engine = cl_engine_new();
    ck_assert_ptr_nonnull(engine);
    ck_assert_int_eq(cl_engine_compile(engine), CL_SUCCESS);
    memset(&options, 0, sizeof(options));
    memset(&layer, 0, sizeof(layer));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(archive, archive_length);
    ck_assert_ptr_nonnull(map);
    map->need                = zip_targeted_read_failure;
    ctx.engine               = engine;
    ctx.options              = &options;
    ctx.dconf                = engine->dconf;
    ctx.fmap                 = map;
    ctx.this_layer_tmpdir    = tmpdir;
    ctx.recursion_stack      = &layer;
    ctx.recursion_stack_size = 1;
    layer.type               = CL_TYPE_ZIP;
    layer.size               = archive_length;
    layer.fmap               = map;

    ret = cli_unzip(&ctx);
    ck_assert_int_eq(ret, CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason,
                     "ZIP central-directory record signature could not be read completely");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(engine);
    free(archive);
    zip_targeted_read_failure_offset = 0;
}
END_TEST

START_TEST(test_zip_eocd_read_failure_is_fail_visible)
{
    static const uint8_t input[] = "eocd-read-failure";
    struct cl_engine *engine;
    struct cl_scan_options options;
    cli_scan_layer_t layer;
    cli_ctx ctx;
    fmap_t *map;
    size_t archive_length;
    uint8_t *archive;
    cl_error_t ret;

    archive = zip_stream_central_archive(input, sizeof(input) - 1U,
                                         sizeof(input) - 1U,
                                         ZIP_TEST_METHOD_STORED,
                                         (uint32_t)crc32(0L, input, (uInt)(sizeof(input) - 1U)),
                                         &archive_length);
    ck_assert_ptr_nonnull(archive);
    ck_assert_msg(archive_length >= 22U, "ZIP fixture is missing its EOCD record");
    zip_targeted_read_failure_offset = archive_length - 22U;

    engine = cl_engine_new();
    ck_assert_ptr_nonnull(engine);
    ck_assert_int_eq(cl_engine_compile(engine), CL_SUCCESS);
    memset(&options, 0, sizeof(options));
    memset(&layer, 0, sizeof(layer));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(archive, archive_length);
    ck_assert_ptr_nonnull(map);
    map->need                = zip_targeted_read_failure;
    ctx.engine               = engine;
    ctx.options              = &options;
    ctx.dconf                = engine->dconf;
    ctx.fmap                 = map;
    ctx.this_layer_tmpdir    = tmpdir;
    ctx.recursion_stack      = &layer;
    ctx.recursion_stack_size = 1;
    layer.type               = CL_TYPE_ZIP;
    layer.size               = archive_length;
    layer.fmap               = map;

    ret = cli_unzip(&ctx);
    ck_assert_int_eq(ret, CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason,
                     "ZIP end-of-central-directory record could not be read completely");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(engine);
    free(archive);
    zip_targeted_read_failure_offset = 0;
}
END_TEST

START_TEST(test_zip64_metadata_read_failures_are_fail_visible)
{
    uint8_t locator_archive[42] = {0};
    uint8_t eocd_archive[98]    = {0};
    const uint8_t *fixtures[]   = {locator_archive, eocd_archive};
    const size_t lengths[]      = {sizeof(locator_archive), sizeof(eocd_archive)};
    const size_t failure_offsets[] = {0U, 20U};
    const char *reasons[] = {
        "ZIP64 locator could not be read completely",
        "ZIP64 end-of-central-directory record could not be read completely"};
    size_t i;

    /* The classic EOCD advertises ZIP64 metadata. The first fixture fails
     * while reading the locator immediately before it. */
    zip_stream_write_u32(locator_archive + 20, 0x06054b50U);
    zip_stream_write_u16(locator_archive + 30, UINT16_MAX);
    zip_stream_write_u32(locator_archive + 32, UINT32_MAX);
    zip_stream_write_u32(locator_archive + 36, UINT32_MAX);

    /* The second fixture has a readable locator that points at an in-range
     * ZIP64 EOCD window, which is the injected failure point. */
    zip_stream_write_u32(eocd_archive + 20, 0x06064b50U);
    zip_stream_write_u32(eocd_archive + 56, 0x07064b50U);
    zip_stream_write_u64(eocd_archive + 64, 20U);
    zip_stream_write_u32(eocd_archive + 76, 0x06054b50U);
    zip_stream_write_u16(eocd_archive + 86, UINT16_MAX);
    zip_stream_write_u32(eocd_archive + 88, UINT32_MAX);
    zip_stream_write_u32(eocd_archive + 92, UINT32_MAX);

    for (i = 0; i < sizeof(fixtures) / sizeof(fixtures[0]); i++) {
        struct cl_engine *engine;
        struct cl_scan_options options;
        cli_scan_layer_t layer;
        cli_ctx ctx;
        fmap_t *map;
        cl_error_t ret;

        zip_targeted_read_failure_offset = failure_offsets[i];
        engine = cl_engine_new();
        ck_assert_ptr_nonnull(engine);
        ck_assert_int_eq(cl_engine_compile(engine), CL_SUCCESS);
        memset(&options, 0, sizeof(options));
        memset(&layer, 0, sizeof(layer));
        memset(&ctx, 0, sizeof(ctx));
        map = cl_fmap_open_memory(fixtures[i], lengths[i]);
        ck_assert_ptr_nonnull(map);
        map->need                = zip_targeted_read_failure;
        ctx.engine               = engine;
        ctx.options              = &options;
        ctx.dconf                = engine->dconf;
        ctx.fmap                 = map;
        ctx.this_layer_tmpdir    = tmpdir;
        ctx.recursion_stack      = &layer;
        ctx.recursion_stack_size = 1;
        layer.type               = CL_TYPE_ZIP;
        layer.size               = lengths[i];
        layer.fmap               = map;

        ret = cli_unzip(&ctx);
        ck_assert_int_eq(ret, CL_EREAD);
        ck_assert(ctx.scan_incomplete);
        ck_assert_str_eq(ctx.scan_incomplete_reason, reasons[i]);
        ck_assert(map->dont_cache_flag);

        cl_fmap_close(map);
        cl_engine_free(engine);
    }
    zip_targeted_read_failure_offset = 0;
}
END_TEST

START_TEST(test_zip_data_descriptor_read_failures_are_fail_visible)
{
    static const uint8_t input[] = "descriptor-read-failure";
    const size_t failure_delta[] = {0U, 4U};
    const char *reasons[] = {
        "ZIP data descriptor could not be read completely",
        "ZIP data descriptor payload could not be read completely"};
    uint8_t *archive;
    size_t archive_length;
    size_t descriptor_offset;
    size_t i;

    archive = zip_stream_central_data_descriptor_archive(input, sizeof(input) - 1U,
                                                         &archive_length,
                                                         &descriptor_offset);
    ck_assert_ptr_nonnull(archive);

    for (i = 0; i < sizeof(failure_delta) / sizeof(failure_delta[0]); i++) {
        struct cl_engine *engine;
        struct cl_scan_options options;
        cli_scan_layer_t layer;
        cli_ctx ctx;
        fmap_t *map;
        cl_error_t ret;

        zip_targeted_read_failure_offset = descriptor_offset + failure_delta[i];
        engine = cl_engine_new();
        ck_assert_ptr_nonnull(engine);
        ck_assert_int_eq(cl_engine_compile(engine), CL_SUCCESS);
        memset(&options, 0, sizeof(options));
        memset(&layer, 0, sizeof(layer));
        memset(&ctx, 0, sizeof(ctx));
        map = cl_fmap_open_memory(archive, archive_length);
        ck_assert_ptr_nonnull(map);
        map->need                = zip_targeted_read_failure;
        ctx.engine               = engine;
        ctx.options              = &options;
        ctx.dconf                = engine->dconf;
        ctx.fmap                 = map;
        ctx.this_layer_tmpdir    = tmpdir;
        ctx.recursion_stack      = &layer;
        ctx.recursion_stack_size = 1;
        layer.type               = CL_TYPE_ZIP;
        layer.size               = archive_length;
        layer.fmap               = map;

        ret = cli_unzip(&ctx);
        ck_assert_int_eq(ret, CL_EREAD);
        ck_assert(ctx.scan_incomplete);
        ck_assert_str_eq(ctx.scan_incomplete_reason, reasons[i]);
        ck_assert(map->dont_cache_flag);

        cl_fmap_close(map);
        cl_engine_free(engine);
    }

    free(archive);
    zip_targeted_read_failure_offset = 0;
}
END_TEST

START_TEST(test_zip_masked_sfx_candidate_is_not_confirmed)
{
    static const uint8_t input[] = "masked-sfx-candidate";
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_scan_layer_t layer;
    cli_ctx ctx;
    cl_fmap_t *map;
    size_t archive_length;
    size_t zip_size = 0;
    uint8_t *archive;
    cl_error_t ret;

    archive = zip_stream_local_archive_flags(input, sizeof(input) - 1U,
                                              sizeof(input) - 1U,
                                              ZIP_TEST_METHOD_STORED,
                                              ZIP_TEST_FLAG_MASKED_HEADER,
                                              (uint32_t)crc32(0L, input, (uInt)(sizeof(input) - 1U)),
                                              &archive_length);
    ck_assert_ptr_nonnull(archive);
    zip_stream_write_u32(archive + 14, 0U);
    zip_stream_write_u32(archive + 18, 0U);
    zip_stream_write_u32(archive + 22, 0U);

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&layer, 0, sizeof(layer));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(archive, archive_length);
    ck_assert_ptr_nonnull(map);
    ctx.engine               = &engine;
    ctx.options              = &options;
    ctx.fmap                 = map;
    ctx.this_layer_tmpdir    = tmpdir;
    ctx.recursion_stack      = &layer;
    ctx.recursion_stack_size = 1;
    layer.type               = CL_TYPE_ZIPSFX;
    layer.size               = archive_length;
    layer.fmap               = map;

    ret = cli_unzip_single_header_check(&ctx, 0, &zip_size);
    ck_assert_int_eq(ret, CL_EFORMAT);
    ck_assert_uint_eq(zip_size, 0U);
    ck_assert(!ctx.scan_incomplete);
    ck_assert(!map->dont_cache_flag);

    cl_fmap_close(map);
    free(archive);
}
END_TEST

START_TEST(test_zip_local_only_masked_header_is_fail_visible)
{
    static const uint8_t input[] = "masked-local-only";
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_scan_layer_t layer;
    cli_ctx ctx;
    cl_fmap_t *map;
    size_t archive_length;
    uint8_t *archive;
    cl_error_t ret;

    archive = zip_stream_local_archive_flags(input, sizeof(input) - 1U,
                                              sizeof(input) - 1U,
                                              ZIP_TEST_METHOD_STORED,
                                              ZIP_TEST_FLAG_MASKED_HEADER,
                                              (uint32_t)crc32(0L, input, (uInt)(sizeof(input) - 1U)),
                                              &archive_length);
    ck_assert_ptr_nonnull(archive);
    zip_stream_write_u32(archive + 14, 0U);
    zip_stream_write_u32(archive + 18, 0U);
    zip_stream_write_u32(archive + 22, 0U);

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&layer, 0, sizeof(layer));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(archive, archive_length);
    ck_assert_ptr_nonnull(map);
    ctx.engine               = &engine;
    ctx.options              = &options;
    ctx.fmap                 = map;
    ctx.this_layer_tmpdir    = tmpdir;
    ctx.recursion_stack      = &layer;
    ctx.recursion_stack_size = 1;
    layer.type               = CL_TYPE_ZIP;
    layer.size               = archive_length;
    layer.fmap               = map;

    ret = cli_unzip(&ctx);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    free(archive);
}
END_TEST

START_TEST(test_zip_local_index_propagates_callback_abort)
{
    const uint8_t input[] = "callback-abort";
    struct zip_stream_pread_state state;
    struct cl_engine *engine;
    struct cl_scan_options options;
    cli_scan_layer_t layer;
    cli_ctx ctx;
    cl_fmap_t *map;
    uint8_t *archive;
    size_t archive_length;
    struct zip_index_alert_state alert_state = {0, CL_BREAK};
    cl_error_t ret;

    archive = zip_stream_local_archive(input, sizeof(input), sizeof(input),
                                       ZIP_TEST_METHOD_STORED,
                                       (uint32_t)crc32(0L, input, (uInt)sizeof(input)),
                                       &archive_length);
    ck_assert_ptr_nonnull(archive);

    memset(&state, 0, sizeof(state));
    memset(&options, 0, sizeof(options));
    memset(&layer, 0, sizeof(layer));
    memset(&ctx, 0, sizeof(ctx));
    state.data   = archive;
    state.length = archive_length;
    map = cl_fmap_open_handle(&state, 0, archive_length, zip_stream_pread_cb, 1);
    ck_assert_ptr_nonnull(map);

    engine = cl_engine_new();
    ck_assert_ptr_nonnull(engine);
    cl_engine_set_clcb_meta(engine, zip_index_meta_alert_cb);
    cl_engine_set_scan_callback(engine, zip_index_alert_result_cb, CL_SCAN_CALLBACK_ALERT);

    ctx.engine               = engine;
    ctx.options              = &options;
    ctx.dconf                = engine->dconf;
    ctx.fmap                 = map;
    ctx.this_layer_tmpdir    = tmpdir;
    ctx.recursion_stack      = &layer;
    ctx.recursion_stack_size = 1;
    ctx.cb_ctx               = &alert_state;
    layer.type               = CL_TYPE_ZIP;
    layer.size               = archive_length;
    layer.fmap               = map;

    ret = cli_unzip(&ctx);
    ck_assert_int_eq(ret, CL_BREAK);
    ck_assert_uint_eq(alert_state.calls, 1);
    ck_assert(ctx.abort_scan);
    ck_assert(!ctx.scan_timed_out);

    if (layer.evidence)
        evidence_free(layer.evidence);
    cl_engine_free(engine);
    cl_fmap_close(map);
    free(archive);
}
END_TEST

START_TEST(test_zip_central_index_propagates_callback_status)
{
    unsigned int callback_calls;
    bool abort_scan;
    bool incomplete;
    cl_verdict_t verdict;
    cl_error_t ret;

    ret = zip_index_run_central_alert(CL_BREAK, &callback_calls, &abort_scan,
                                      &incomplete, &verdict);
    ck_assert_int_eq(ret, CL_BREAK);
    ck_assert_uint_eq(callback_calls, 1);
    ck_assert(abort_scan);
    ck_assert(!incomplete);

    ret = zip_index_run_central_alert(CL_VERIFIED, &callback_calls, &abort_scan,
                                      &incomplete, &verdict);
    ck_assert_int_eq(ret, CL_VERIFIED);
    ck_assert_uint_eq(callback_calls, 1);
    ck_assert(!abort_scan);
    ck_assert(!incomplete);
    ck_assert_int_eq(verdict, CL_VERDICT_TRUSTED);

    ret = zip_index_run_central_alert(CL_VIRUS, &callback_calls, &abort_scan,
                                      &incomplete, &verdict);
    ck_assert_int_eq(ret, CL_VIRUS);
    ck_assert_uint_eq(callback_calls, 1);
    ck_assert(abort_scan);
    ck_assert(!incomplete);
}
END_TEST

START_TEST(test_zip_maxfiles_is_inclusive_and_detection_precedes_limit)
{
    size_t matched_offset = SIZE_MAX;
    bool incomplete;
    bool dont_cache;
    cl_error_t ret;

    ret = zip_index_run_maxfiles(1U, 1U, NULL, &matched_offset,
                                 &incomplete, &dont_cache);
    ck_assert_int_eq(ret, CL_SUCCESS);
    ck_assert(!incomplete);
    ck_assert(!dont_cache);

    ret = zip_index_run_maxfiles(2U, 2U, NULL, &matched_offset,
                                 &incomplete, &dont_cache);
    ck_assert_int_eq(ret, CL_SUCCESS);
    ck_assert(!incomplete);
    ck_assert(!dont_cache);

    ret = zip_index_run_maxfiles(2U, 1U, NULL, &matched_offset,
                                 &incomplete, &dont_cache);
    ck_assert_int_eq(ret, CL_EMAXFILES);
    ck_assert(incomplete);
    ck_assert(dont_cache);

    ret = zip_index_run_maxfiles(1U, 1U, "missing", &matched_offset,
                                 &incomplete, &dont_cache);
    ck_assert_int_eq(ret, CL_SUCCESS);
    ck_assert(!incomplete);

    ret = zip_index_run_maxfiles(2U, 1U, "missing", &matched_offset,
                                 &incomplete, &dont_cache);
    ck_assert_int_eq(ret, CL_EMAXFILES);
    ck_assert(incomplete);
    ck_assert(dont_cache);

    matched_offset = SIZE_MAX;
    ret = zip_index_run_maxfiles(2U, 1U, "b", &matched_offset,
                                 &incomplete, &dont_cache);
    ck_assert_int_eq(ret, CL_VIRUS);
    ck_assert_uint_eq(matched_offset, 31U);
    ck_assert(!incomplete);
}
END_TEST

START_TEST(test_zip_stream_central_catalogue_path)
{
    const char *virname       = NULL;
    unsigned long int scanned = 0;
    struct zip_stream_pread_state state;
    struct cl_scan_options options;
    cl_fmap_t *map;
    uint8_t *input;
    uint8_t *compressed;
    uint8_t *archive;
    size_t compressed_length;
    size_t archive_length;
    STATBUF sb;
    char filepath[256];
    int fd;
    int ret;

    snprintf(filepath, sizeof(filepath), OBJDIR PATHSEP "input" PATHSEP "clamav_hdb_scanfiles" PATHSEP "clam.exe");
    fd = open(filepath, O_RDONLY | O_BINARY);
    ck_assert_msg(fd >= 0, "open failed for %s", filepath);
    ck_assert_int_eq(FSTAT(fd, &sb), 0);
    ck_assert_msg(sb.st_size > 0 && (uint64_t)sb.st_size <= UINT32_MAX,
                  "unexpected clam.exe fixture size");

    input = malloc((size_t)sb.st_size);
    ck_assert_ptr_nonnull(input);
    ck_assert_uint_eq(cli_readn(fd, input, (size_t)sb.st_size), (size_t)sb.st_size);
    close(fd);

    compressed = zip_stream_raw_deflate(input, (size_t)sb.st_size, &compressed_length);
    archive = zip_stream_central_archive(compressed, compressed_length, (uint32_t)sb.st_size,
                                         ZIP_TEST_METHOD_DEFLATE,
                                         (uint32_t)crc32(0L, input, (uInt)sb.st_size),
                                         &archive_length);

    memset(&state, 0, sizeof(state));
    state.data   = archive;
    state.length = archive_length;
    map = cl_fmap_open_handle(&state, 0, archive_length, zip_stream_pread_cb, 1);
    ck_assert_ptr_nonnull(map);

    memset(&options, 0, sizeof(options));
    options.parse |= ~0;
    ret = cl_scanmap_callback(map, "central-stream.zip", &virname, &scanned, g_engine, &options, NULL);
    ck_assert_int_eq(ret, CL_VIRUS);
    ck_assert_msg(virname && !strcmp(virname, "ClamAV-Test-File.UNOFFICIAL"),
                  "central ZIP member was not scanned through cli_unzip: %s", virname ? virname : "(null)");

    cl_fmap_close(map);
    free(archive);
    free(compressed);
    free(input);
}
END_TEST

START_TEST(test_zip_abort_reason_is_preserved)
{
    uint8_t archive[128] = {0};
    struct zip_stream_pread_state state;
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_scan_layer_t layer;
    cli_ctx ctx;
    cl_fmap_t *map;
    size_t local_header_offset = 0;
    cl_error_t ret;

    memset(&state, 0, sizeof(state));
    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&layer, 0, sizeof(layer));
    memset(&ctx, 0, sizeof(ctx));

    state.data   = archive;
    state.length = sizeof(archive);
    map = cl_fmap_open_handle(&state, 0, sizeof(archive), zip_stream_pread_cb, 1);
    ck_assert_ptr_nonnull(map);

    ctx.engine               = &engine;
    ctx.options              = &options;
    ctx.fmap                 = map;
    ctx.recursion_stack      = &layer;
    ctx.recursion_stack_size = 1;
    ctx.abort_scan           = true;
    layer.type               = CL_TYPE_ZIP;
    layer.size               = sizeof(archive);
    layer.fmap               = map;

    ret = cli_unzip(&ctx);
    ck_assert_int_eq(ret, CL_BREAK);

    ret = unzip_search_single(&ctx, "member", strlen("member"), &local_header_offset);
    ck_assert_int_eq(ret, CL_BREAK);

    ctx.scan_timed_out = true;
    ret                = cli_unzip(&ctx);
    ck_assert_int_eq(ret, CL_ETIMEOUT);

    ret = unzip_search_single(&ctx, "member", strlen("member"), &local_header_offset);
    ck_assert_int_eq(ret, CL_ETIMEOUT);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_cl_scanmap_callback_handle)
{
    const char *virname       = NULL;
    unsigned long int scanned = 0;
    cl_fmap_t *map;
    int ret;
    char file[256];
    unsigned long size;
    struct cl_scan_options options;

    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0;

    int fd = get_test_file(_i, file, sizeof(file), &size);
    /* intentionally use different way than scanners.c for testing */
    map = cl_fmap_open_handle(&fd, 0, size, pread_cb, 1);
    ck_assert_msg(!!map, "cl_fmap_open_handle");

    cli_dbgmsg("scanning (handle) %s\n", file);
    ret = cl_scanmap_callback(map, file, &virname, &scanned, g_engine, &options, NULL);
    cli_dbgmsg("scan end (handle) %s\n", file);

    if (!FALSE_NEGATIVE) {
        assert_test_file_scan_result(ret, virname, file, "cl_scanmap_callback");
    }
    cl_fmap_close(map);
    close(fd);
}
END_TEST

START_TEST(test_cl_scanmap_callback_handle_allscan)
{
    const char *virname       = NULL;
    unsigned long int scanned = 0;
    cl_fmap_t *map;
    int ret;
    char file[256];
    unsigned long size;
    struct cl_scan_options options;

    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0;
    options.general |= CL_SCAN_GENERAL_ALLMATCHES;

    int fd = get_test_file(_i, file, sizeof(file), &size);
    /* intentionally use different way than scanners.c for testing */
    map = cl_fmap_open_handle(&fd, 0, size, pread_cb, 1);
    ck_assert(!!map);

    cli_dbgmsg("scanning (handle) allscan %s\n", file);
    ret = cl_scanmap_callback(map, file, &virname, &scanned, g_engine, &options, NULL);
    cli_dbgmsg("scan end (handle) allscan %s\n", file);

    if (!FALSE_NEGATIVE) {
        assert_test_file_scan_result(ret, virname, file, "cl_scanmap_callback_allscan");
    }
    cl_fmap_close(map);
    close(fd);
}
END_TEST
#endif

#ifdef HAVE_SYS_MMAN_H
START_TEST(test_cl_scanmap_callback_mem)
{
    const char *virname       = NULL;
    unsigned long int scanned = 0;
    cl_fmap_t *map;
    int ret;
    void *mem;
    unsigned long size;
    char file[256];
    struct cl_scan_options options;

    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0;

    int fd = get_test_file(_i, file, sizeof(file), &size);

    mem = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    ck_assert_msg(mem != MAP_FAILED, "mmap");

    /* intentionally use different way than scanners.c for testing */
    map = cl_fmap_open_memory(mem, size);
    ck_assert_msg(!!map, "cl_fmap_open_mem");

    cli_dbgmsg("scanning (mem) %s\n", file);
    ret = cl_scanmap_callback(map, file, &virname, &scanned, g_engine, &options, NULL);
    cli_dbgmsg("scan end (mem) %s\n", file);
    if (!FALSE_NEGATIVE) {
        assert_test_file_scan_result(ret, virname, file, "cl_scanmap_callback_mem");
    }
    close(fd);
    cl_fmap_close(map);

    munmap(mem, size);
}
END_TEST

START_TEST(test_cl_scanmap_callback_mem_allscan)
{
    const char *virname       = NULL;
    unsigned long int scanned = 0;
    cl_fmap_t *map;
    int ret;
    void *mem;
    unsigned long size;
    char file[256];
    struct cl_scan_options options;

    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0;
    options.general |= CL_SCAN_GENERAL_ALLMATCHES;

    int fd = get_test_file(_i, file, sizeof(file), &size);

    mem = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    ck_assert_msg(mem != MAP_FAILED, "mmap");

    /* intentionally use different way than scanners.c for testing */
    map = cl_fmap_open_memory(mem, size);
    ck_assert(!!map);

    cli_dbgmsg("scanning (mem) allscan %s\n", file);
    ret = cl_scanmap_callback(map, file, &virname, &scanned, g_engine, &options, NULL);
    cli_dbgmsg("scan end (mem) allscan %s\n", file);
    if (!FALSE_NEGATIVE) {
        assert_test_file_scan_result(ret, virname, file, "cl_scanmap_callback_mem_allscan");
    }
    close(fd);
    cl_fmap_close(map);
    munmap(mem, size);
}
END_TEST
#endif

START_TEST(test_fmap_duplicate)
{
    cl_fmap_t *map;
    cl_fmap_t *dup_map     = NULL;
    cl_fmap_t *dup_dup_map = NULL;
    char map_data[6]       = {'a', 'b', 'c', 'd', 'e', 'f'};
    char tmp[6];
    size_t bread = 0;

    map = cl_fmap_open_memory(map_data, sizeof(map_data));
    ck_assert_msg(!!map, "cl_fmap_open_handle failed");

    /*
     * Test duplicate of entire map
     */
    cli_dbgmsg("duplicating complete map\n");
    dup_map = fmap_duplicate(map, 0, map->len, "complete duplicate");
    ck_assert_msg(!!dup_map, "fmap_duplicate failed");
    ck_assert_msg(dup_map->nested_offset == 0, "dup_map nested_offset is incorrect: %zu", dup_map->nested_offset);
    ck_assert_msg(dup_map->len == map->len, "dup_map len is incorrect: %zu", dup_map->len);
    ck_assert_msg(dup_map->real_len == map->len, "dup_map real len is incorrect: %zu", dup_map->real_len);

    bread = fmap_readn(dup_map, tmp, 0, 6);
    ck_assert(bread == 6);
    ck_assert(0 == memcmp(map_data, tmp, 6));

    cli_dbgmsg("freeing dup_map\n");
    free_duplicate_fmap(dup_map);
    dup_map = NULL;

    /*
     * Test duplicate of map at offset 2
     */
    cli_dbgmsg("duplicating 2 bytes into map\n");
    dup_map = fmap_duplicate(map, 2, map->len, "offset duplicate");
    ck_assert_msg(!!dup_map, "fmap_duplicate failed");
    ck_assert_msg(dup_map->nested_offset == 2, "dup_map nested_offset is incorrect: %zu", dup_map->nested_offset);
    ck_assert_msg(dup_map->len == 4, "dup_map len is incorrect: %zu", dup_map->len);
    ck_assert_msg(dup_map->real_len == 6, "dup_map real len is incorrect: %zu", dup_map->real_len);

    bread = fmap_readn(dup_map, tmp, 0, 6);
    ck_assert(bread == 4);
    ck_assert(0 == memcmp(map_data + 2, tmp, 4));

    /*
     * Test duplicate of duplicate map, also at offset 2 (total 4 bytes in)
     */
    cli_dbgmsg("duplicating 2 bytes into dup_map\n");
    dup_dup_map = fmap_duplicate(dup_map, 2, dup_map->len, "double offset duplicate");
    ck_assert_msg(!!dup_dup_map, "fmap_duplicate failed");
    ck_assert_msg(dup_dup_map->nested_offset == 4, "dup_dup_map nested_offset is incorrect: %zu", dup_dup_map->nested_offset);
    ck_assert_msg(dup_dup_map->len == 2, "dup_dup_map len is incorrect: %zu", dup_dup_map->len);
    ck_assert_msg(dup_dup_map->real_len == 6, "dup_dup_map real len is incorrect: %zu", dup_dup_map->real_len);

    bread = fmap_readn(dup_dup_map, tmp, 0, 6);
    ck_assert(bread == 2);
    ck_assert(0 == memcmp(map_data + 4, tmp, 2));

    cli_dbgmsg("freeing dup_dup_map\n");
    free_duplicate_fmap(dup_dup_map);
    dup_dup_map = NULL;
    cli_dbgmsg("freeing dup_map\n");
    free_duplicate_fmap(dup_map);
    dup_map = NULL;

    /*
     * Test duplicate of map omitting the last 2 bytes
     */
    cli_dbgmsg("duplicating map with shorter len\n");
    dup_map = fmap_duplicate(map, 0, map->len - 2, "short duplicate");
    ck_assert_msg(!!dup_map, "fmap_duplicate failed");
    ck_assert_msg(dup_map->nested_offset == 0, "dup_map nested_offset is incorrect: %zu", dup_map->nested_offset);
    ck_assert_msg(dup_map->len == 4, "dup_map len is incorrect: %zu", dup_map->len);
    ck_assert_msg(dup_map->real_len == 4, "dup_map real len is incorrect: %zu", dup_map->real_len);

    bread = fmap_readn(dup_map, tmp, 0, 6);
    ck_assert(bread == 4);
    ck_assert(0 == memcmp(map_data, tmp, 4));

    /*
     * Test duplicate of the duplicate omitting the last 2 bytes again (so just the first 2 bytes)
     */
    cli_dbgmsg("duplicating dup_map with shorter len\n");
    dup_dup_map = fmap_duplicate(dup_map, 0, dup_map->len - 2, "double short duplicate");
    ck_assert_msg(!!dup_dup_map, "fmap_duplicate failed");
    ck_assert_msg(dup_dup_map->nested_offset == 0, "dup_dup_map nested_offset is incorrect: %zu", dup_dup_map->nested_offset);
    ck_assert_msg(dup_dup_map->len == 2, "dup_dup_map len is incorrect: %zu", dup_dup_map->len);
    ck_assert_msg(dup_dup_map->real_len == 2, "dup_dup_map real len is incorrect: %zu", dup_dup_map->real_len);

    bread = fmap_readn(dup_dup_map, tmp, 0, 6);
    ck_assert(bread == 2);
    ck_assert(0 == memcmp(map_data, tmp, 2));

    cli_dbgmsg("freeing dup_dup_map\n");
    free_duplicate_fmap(dup_dup_map);
    dup_dup_map = NULL;
    cli_dbgmsg("freeing dup_map\n");
    free_duplicate_fmap(dup_map);
    dup_map = NULL;

    /*
     * Test duplicate of map at offset 2
     */
    cli_dbgmsg("duplicating 2 bytes into map\n");
    dup_map = fmap_duplicate(map, 2, map->len, "offset duplicate");
    ck_assert_msg(!!dup_map, "fmap_duplicate failed");
    ck_assert_msg(dup_map->nested_offset == 2, "dup_map nested_offset is incorrect: %zu", dup_map->nested_offset);
    ck_assert_msg(dup_map->len == 4, "dup_map len is incorrect: %zu", dup_map->len);
    ck_assert_msg(dup_map->real_len == 6, "dup_map real len is incorrect: %zu", dup_map->real_len);

    bread = fmap_readn(dup_map, tmp, 0, 6);
    ck_assert(bread == 4);
    ck_assert(0 == memcmp(map_data + 2, tmp, 4));

    /*
     * Test duplicate of the duplicate omitting the last 2 bytes again (so just the middle 2 bytes)
     */
    cli_dbgmsg("duplicating dup_map with shorter len\n");
    dup_dup_map = fmap_duplicate(dup_map, 0, dup_map->len - 2, "offset short duplicate");
    ck_assert_msg(!!dup_dup_map, "fmap_duplicate failed");
    ck_assert_msg(dup_dup_map->nested_offset == 2, "dup_dup_map nested_offset is incorrect: %zu", dup_map->nested_offset);
    ck_assert_msg(dup_dup_map->len == 2, "dup_dup_map len is incorrect: %zu", dup_map->len);
    ck_assert_msg(dup_dup_map->real_len == 4, "dup_dup_map real len is incorrect: %zu", dup_map->real_len);

    bread = fmap_readn(dup_dup_map, tmp, 0, 6);
    ck_assert(bread == 2);
    ck_assert(0 == memcmp(map_data + 2, tmp, 2));

    cli_dbgmsg("freeing dup_dup_map\n");
    free_duplicate_fmap(dup_dup_map);
    dup_dup_map = NULL;
    cli_dbgmsg("freeing dup_map\n");
    free_duplicate_fmap(dup_map);
    dup_map = NULL;

    cli_dbgmsg("freeing map\n");
    cl_fmap_close(map);
}
END_TEST

START_TEST(test_fmap_duplicate_out_of_bounds)
{
    cl_fmap_t *map;
    cl_fmap_t *dup_map     = NULL;
    cl_fmap_t *dup_dup_map = NULL;
    char map_data[6]       = {'a', 'b', 'c', 'd', 'e', 'f'};
    char tmp[6];
    size_t bread = 0;

    map = cl_fmap_open_memory(map_data, sizeof(map_data));
    ck_assert_msg(!!map, "cl_fmap_open_memory failed");

    /*
     * Test 0-byte duplicate
     */
    cli_dbgmsg("duplicating 0 bytes of map\n");
    dup_map = fmap_duplicate(map, 0, 0, "zero-byte dup");
    ck_assert_msg(!!dup_map, "fmap_duplicate failed");
    ck_assert_msg(dup_map->nested_offset == 0, "dup_map nested_offset is incorrect: %zu", dup_map->nested_offset);
    ck_assert_msg(dup_map->len == 0, "dup_map len is incorrect: %zu", dup_map->len);
    ck_assert_msg(dup_map->real_len == 0, "dup_map real len is incorrect: %zu", dup_map->real_len);

    bread = fmap_readn(dup_map, tmp, 0, 6);
    ck_assert(bread == 0);

    cli_dbgmsg("freeing dup_map\n");
    free_duplicate_fmap(dup_map);
    dup_map = NULL;

    /*
     * Test duplicate of entire map + 1
     */
    cli_dbgmsg("duplicating complete map + 1 byte\n");
    dup_map = fmap_duplicate(map, 0, map->len + 1, "duplicate + 1");
    ck_assert_msg(!!dup_map, "fmap_duplicate failed");
    ck_assert_msg(dup_map->nested_offset == 0, "dup_map nested_offset is incorrect: %zu", dup_map->nested_offset);
    ck_assert_msg(dup_map->len == map->len, "dup_map len is incorrect: %zu", dup_map->len);
    ck_assert_msg(dup_map->real_len == map->len, "dup_map real len is incorrect: %zu", dup_map->real_len);

    bread = fmap_readn(dup_map, tmp, 0, 6);
    ck_assert(bread == 6);
    ck_assert(0 == memcmp(map_data, tmp, 6));

    cli_dbgmsg("freeing dup_map\n");
    free_duplicate_fmap(dup_map);
    dup_map = NULL;

    /*
     * Test duplicate of map at offset 4
     */
    cli_dbgmsg("duplicating 4 bytes into map\n");
    dup_map = fmap_duplicate(map, 4, map->len, "offset duplicate");
    ck_assert_msg(!!dup_map, "fmap_duplicate failed");
    ck_assert_msg(dup_map->nested_offset == 4, "dup_map nested_offset is incorrect: %zu", dup_map->nested_offset);
    ck_assert_msg(dup_map->len == 2, "dup_map len is incorrect: %zu", dup_map->len);
    ck_assert_msg(dup_map->real_len == 6, "dup_map real len is incorrect: %zu", dup_map->real_len);

    bread = fmap_readn(dup_map, tmp, 0, 6);
    ck_assert(bread == 2);
    ck_assert(0 == memcmp(map_data + 4, tmp, 2));

    /*
     * Test duplicate of duplicate map, also at offset 4 (total 8 bytes in, which is 2 bytes too far)
     */
    cli_dbgmsg("duplicating 4 bytes into dup_map\n");
    dup_dup_map = fmap_duplicate(dup_map, 4, dup_map->len, "out of bounds offset duplicate");
    ck_assert_msg(NULL == dup_dup_map, "fmap_duplicate should have failed!");

    cli_dbgmsg("freeing dup_map\n");
    free_duplicate_fmap(dup_map);
    dup_map = NULL;

    /*
     * Test duplicate just 2 bytes of the original
     */
    cli_dbgmsg("duplicating map with shorter len\n");
    dup_map = fmap_duplicate(map, 0, 2, "short duplicate");
    ck_assert_msg(!!dup_map, "fmap_duplicate failed");
    ck_assert_msg(dup_map->nested_offset == 0, "dup_map nested_offset is incorrect: %zu", dup_map->nested_offset);
    ck_assert_msg(dup_map->len == 2, "dup_map len is incorrect: %zu", dup_map->len);
    ck_assert_msg(dup_map->real_len == 2, "dup_map real len is incorrect: %zu", dup_map->real_len);

    bread = fmap_readn(dup_map, tmp, 0, 6);
    ck_assert(bread == 2);
    ck_assert(0 == memcmp(map_data, tmp, 2));

    /* Note: Keeping the previous dup_map around for a sequence of double-dup tests. */

    /*
     * Test duplicate 1 bytes into the 2-byte duplicate, requesting 2 bytes
     * This should result in a 1-byte double-dup
     */
    cli_dbgmsg("duplicating 1 byte in, 1 too many\n");
    dup_dup_map = fmap_duplicate(dup_map, 1, 2, "1 byte in, 1 too many");
    ck_assert_msg(!!dup_dup_map, "fmap_duplicate failed");
    ck_assert_msg(dup_dup_map->nested_offset == 1, "dup_dup_map nested_offset is incorrect: %zu", dup_dup_map->nested_offset);
    ck_assert_msg(dup_dup_map->len == 1, "dup_dup_map len is incorrect: %zu", dup_dup_map->len);
    ck_assert_msg(dup_dup_map->real_len == 2, "dup_dup_map real len is incorrect: %zu", dup_dup_map->real_len);

    bread = fmap_readn(dup_dup_map, tmp, 0, 6);
    ck_assert(bread == 1);
    ck_assert(0 == memcmp(map_data + 1, tmp, 1));

    cli_dbgmsg("freeing dup_dup_map\n");
    free_duplicate_fmap(dup_dup_map);
    dup_dup_map = NULL;

    /*
     * Test duplicate 2 bytes into the 2-byte duplicate, requesting 2 bytes
     * This should result in a 0-byte double-dup
     */
    cli_dbgmsg("duplicating 2 bytes in, 2 bytes too many\n");
    dup_dup_map = fmap_duplicate(dup_map, 2, 2, "2 bytes in, 2 bytes too many");
    ck_assert_msg(!!dup_dup_map, "fmap_duplicate failed");
    ck_assert_msg(dup_dup_map->nested_offset == 2, "dup_dup_map nested_offset is incorrect: %zu", dup_dup_map->nested_offset);
    ck_assert_msg(dup_dup_map->len == 0, "dup_dup_map len is incorrect: %zu", dup_dup_map->len);
    ck_assert_msg(dup_dup_map->real_len == 2, "dup_dup_map real len is incorrect: %zu", dup_dup_map->real_len);

    bread = fmap_readn(dup_dup_map, tmp, 0, 6);
    ck_assert(bread == 0);

    cli_dbgmsg("freeing dup_dup_map\n");
    free_duplicate_fmap(dup_dup_map);
    dup_dup_map = NULL;

    /*
     * Test duplicate 3 bytes into the 2-byte duplicate, requesting 2 bytes
     */
    cli_dbgmsg("duplicating 0-byte of duplicate\n");
    dup_dup_map = fmap_duplicate(dup_map, 3, 2, "2 bytes in, 3 bytes too many");
    ck_assert_msg(NULL == dup_dup_map, "fmap_duplicate should have failed!");

    /* Ok, we're done with this dup_map */
    cli_dbgmsg("freeing dup_map\n");
    free_duplicate_fmap(dup_map);
    dup_map = NULL;

    cli_dbgmsg("freeing map\n");
    cl_fmap_close(map);
}
END_TEST

#define FMAP_TEST_STRING_PART_1 "Hello, World!\0"
#define FMAP_TEST_STRING_PART_2 "Don't be a stranger!\nBe my friend!\0"
#define FMAP_TEST_STRING FMAP_TEST_STRING_PART_1 FMAP_TEST_STRING_PART_2

/**
 * @brief convenience function for testing
 *
 * the map data should:
 *  - be at least 6 bytes long
 *  - include a '\n' in the middle.
 *  - plus one '\0' after that.
 *  - and end with '\0'.
 *
 * @param map           The map.
 * @param map_data      A copy of the expected map data.
 * @param map_data_len  The length of the expected map data.
 */
static void fmap_api_tests(cl_fmap_t *map, const char *map_data, size_t map_data_len, const char *msg)
{
    char *tmp    = NULL;
    size_t bread = 0;
    const char *ptr, *ptr_2;
    size_t at;
    size_t lenout;
    const char *ptr_after_newline;
    size_t offset_after_newline;

    tmp = calloc(map_data_len + 1, 1);
    ck_assert_msg(tmp != NULL, "%s", msg);

    /*
     * Test fmap_readn()
     */
    bread = fmap_readn(map, tmp, 0, 5);
    ck_assert_msg(bread == 5, "%s: unexpected # bytes read: %zu", msg, bread);
    ck_assert_msg(0 == memcmp(map_data, tmp, 5), "%s: %s != %s", msg, map_data, tmp);

    /*
     * Test fmap_need_offstr()
     */
    ptr = fmap_need_offstr(map, 0, 5);
    ck_assert_msg(ptr == NULL, "%s: fmap_need_offstr should not have found a string terminator in the first 6 bytes: %s", msg, ptr);

    /*
     * Test fmap_need_offstr()
     */
    // This API must find a NULL-terminating byte
    ptr = fmap_need_offstr(map, 0, map_data_len + 5); // request at least as much as exists.
    ck_assert_msg(ptr != NULL, "%s: fmap_need_offstr failed to find a string.", msg);
    ck_assert_msg(*ptr == map_data[0], "%s: %c != %c", msg, *ptr, map_data[0]);

    /*
     * Test fmap_gets()
     */
    // first lets find the offset of the '\n' in this data.
    ptr_after_newline = memchr(map_data, '\n', map_data_len);
    ck_assert_msg(ptr_after_newline != NULL, "%s", msg);
    offset_after_newline = (size_t)ptr_after_newline - (size_t)map_data + 1;

    // This API will stop after newline or EOF, but not a NULL byte.
    memset(tmp, 0xff, map_data_len + 1); // pre-load `tmp` with 0xff so our NULL check later is guaranteed to be meaningful.
    at  = 3;                             // start at offset 3
    ptr = fmap_gets(map, tmp, &at, map_data_len + 1);
    ck_assert_msg(ptr == tmp, "%s: %zu != %zu", msg, (size_t)ptr, (size_t)tmp);
    ck_assert_msg(at == offset_after_newline, "%s: %zu != %zu", msg, at, offset_after_newline); // at should point to the character after '\n'
    ck_assert_msg(0 == memcmp(map_data + 3, tmp, offset_after_newline - 3), "%s: fmap_gets read: %s", msg, tmp);
    ck_assert_msg(tmp[offset_after_newline - 3] == '\0', "%s: data read by fmap_gets, but that value is '0x%02x'", msg, tmp[offset_after_newline - 3]); // should have a null terminator afterwards.

    memset(tmp, 0xff, map_data_len + 1); // pre-load `tmp` with 0xff so our NULL check later is guaranteed to be meaningful.
    // continue from previous read, ..
    ptr = fmap_gets(map, tmp, &at, map_data_len + 1); // read the rest of the string
    ck_assert_msg(ptr == tmp, "%s: fmap_gets should return dst pointer but returned: %zu", msg, (size_t)ptr);
    ck_assert_msg(at == map_data_len, "%s: %zu != %zu", msg, at, map_data_len); // at should point just past end of string
    ck_assert_msg(0 == memcmp(map_data + offset_after_newline, tmp, map_data_len - offset_after_newline), "%s", msg);
    ck_assert_msg(tmp[map_data_len - offset_after_newline] == '\0', "%s: data read by fmap_gets, but that value is '0x%02x'", msg, tmp[map_data_len - offset_after_newline]); // should have a null terminator afterwards.

    /*
     * Test fmap_need_off_once_len()
     */
    ptr = fmap_need_off_once_len(map, 0, map_data_len + 50, &lenout); // request more bytes than is available
    ck_assert_msg(ptr != NULL, "%s: failed to get pointer into map :(", msg);
    ck_assert_msg(lenout == map_data_len, "%s: %zu != %zu", msg, lenout, map_data_len);
    ck_assert_msg(0 == memcmp(ptr, map_data, offset_after_newline), "%s", msg);

    /*
     * Test fmap_need_off_once()
     */
    ptr = fmap_need_off_once(map, 0, map_data_len + 50); // request more bytes than is available
    ck_assert_msg(ptr == NULL, "%s: should have failed to get pointer into map :(", msg);

    ptr = fmap_need_off_once(map, 0, offset_after_newline);
    ck_assert_msg(ptr != NULL, "%s: failed to get pointer into map :(", msg);
    ck_assert_msg(0 == memcmp(ptr, map_data, offset_after_newline), "%s", msg);

    /*
     * Test fmap_need_ptr_once()
     */
    ptr_2 = fmap_need_ptr_once(map, ptr, map_data_len + 50); // request more bytes than is available
    ck_assert_msg(ptr_2 == NULL, "%s: should have failed to get pointer into map :(", msg);

    ptr_2 = fmap_need_ptr_once(map, ptr, offset_after_newline);
    ck_assert_msg(ptr_2 != NULL, "%s: failed to get pointer into map :(", msg);
    ck_assert_msg(0 == memcmp(ptr_2, map_data, offset_after_newline), "%s", msg);

    free(tmp);
}

START_TEST(test_fmap_rejects_wrapped_nested_ranges)
{
    cl_fmap_t *map;
    char output[8];
    size_t at;

    map = cl_fmap_open_memory("01234567", 8);
    ck_assert_ptr_nonnull(map);

    /* A nested offset plus a caller offset must never wrap back into the
     * beginning of the original map. */
    map->nested_offset = SIZE_MAX - 3;
    map->len           = 8;
    map->real_len      = SIZE_MAX;

    ck_assert_ptr_null(fmap_need_off_once(map, 4, 1));
    ck_assert_ptr_null(fmap_need_offstr(map, 4, 1));

    at = 4;
    ck_assert_ptr_null(fmap_gets(map, output, &at, sizeof(output)));

    /* The same checked addition protects construction of nested views. */
    ck_assert_ptr_null(fmap_duplicate(map, 0, map->len, NULL));
    ck_assert_ptr_null(fmap_duplicate(map, 4, 1, NULL));

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_fmap_assorted_api)
{
    cl_fmap_t *mem_based_map     = NULL;
    cl_fmap_t *fd_based_map      = NULL;
    cl_fmap_t *fd_based_dup_map  = NULL;
    cl_fmap_t *dup_map           = NULL;
    char *fmap_dump_filepath     = NULL;
    int fmap_dump_fd             = -1;
    char *dup_fmap_dump_filepath = NULL;
    int dup_fmap_dump_fd         = -1;

    mem_based_map = cl_fmap_open_memory(FMAP_TEST_STRING, sizeof(FMAP_TEST_STRING));
    ck_assert_msg(!!mem_based_map, "cl_fmap_open_memory failed");
    cli_dbgmsg("created fmap from memory/buffer\n");

    /*
     * Test a few things on the original map.
     */
    fmap_api_tests(mem_based_map, FMAP_TEST_STRING, sizeof(FMAP_TEST_STRING), "mem map");

    /*
     * Test fmap_dump_to_file()
     */
    ck_assert_int_eq(CL_SUCCESS, fmap_dump_to_file(mem_based_map, NULL, NULL, &fmap_dump_filepath, &fmap_dump_fd, 0, mem_based_map->len));
    ck_assert_msg(fmap_dump_fd != -1, "fmap_dump_fd failed");
    cli_dbgmsg("dumped map to %s\n", fmap_dump_filepath);

    fd_based_map = fmap_new(fmap_dump_fd, 0, 0, NULL, NULL); // using fmap_new() instead of cl_fmap_open_handle() because I don't want to have to stat the file to figure out the len. fmap_new() does that for us.
    ck_assert_msg(!!fd_based_map, "cl_fmap_open_handle failed");
    cli_dbgmsg("created fmap from file descriptor\n");

    /*
     * Test those same things on an fmap created with an fd that is a dumped copy of the original map.
     */
    fmap_api_tests(fd_based_map, FMAP_TEST_STRING, sizeof(FMAP_TEST_STRING), "handle map");

    /*
     * Test duplicate of mem-based map at an offset
     */
    cli_dbgmsg("duplicating part way into mem-based fmap\n");
    dup_map = fmap_duplicate(
        mem_based_map,
        sizeof(FMAP_TEST_STRING_PART_1) - 1, // minus automatic null terminator
        mem_based_map->len - (sizeof(FMAP_TEST_STRING_PART_1) - 1),
        "offset duplicate");
    ck_assert_msg(!!dup_map, "fmap_duplicate failed");
    ck_assert_msg(dup_map->nested_offset == sizeof(FMAP_TEST_STRING_PART_1) - 1, "%zu != %zu", dup_map->nested_offset, sizeof(FMAP_TEST_STRING_PART_1) - 1);
    ck_assert_msg(dup_map->len == sizeof(FMAP_TEST_STRING_PART_2), "%zu != %zu", dup_map->len, sizeof(FMAP_TEST_STRING_PART_2));
    ck_assert_msg(dup_map->real_len == sizeof(FMAP_TEST_STRING), "%zu != %zu", dup_map->real_len, sizeof(FMAP_TEST_STRING));

    /*
     * Test those same things on an fmap created with an fd that is a dumped copy of the original map.
     */
    fmap_api_tests(dup_map, FMAP_TEST_STRING_PART_2, sizeof(FMAP_TEST_STRING_PART_2), "nested mem map");

    /* Ok, we're done with this dup_map */
    cli_dbgmsg("freeing dup_map\n");
    free_duplicate_fmap(dup_map);
    dup_map = NULL;

    /*
     * Test duplicate of handle-based map at an offset
     */
    cli_dbgmsg("duplicating part way into handle-based fmap\n");
    dup_map = fmap_duplicate(
        fd_based_map,
        sizeof(FMAP_TEST_STRING_PART_1) - 1, // minus automatic null terminator
        fd_based_map->len - (sizeof(FMAP_TEST_STRING_PART_1) - 1),
        "offset duplicate");
    ck_assert_msg(!!dup_map, "fmap_duplicate failed");
    ck_assert_msg(dup_map->nested_offset == sizeof(FMAP_TEST_STRING_PART_1) - 1, "%zu != %zu", dup_map->nested_offset, sizeof(FMAP_TEST_STRING_PART_1) - 1);
    ck_assert_msg(dup_map->len == sizeof(FMAP_TEST_STRING_PART_2), "%zu != %zu", dup_map->len, sizeof(FMAP_TEST_STRING_PART_2));
    ck_assert_msg(dup_map->real_len == sizeof(FMAP_TEST_STRING), "%zu != %zu", dup_map->real_len, sizeof(FMAP_TEST_STRING));

    /*
     * Test those same things on an fmap created with an fd that is a dumped copy of the original map.
     */
    fmap_api_tests(dup_map, FMAP_TEST_STRING_PART_2, sizeof(FMAP_TEST_STRING_PART_2), "nested handle map");

    /*
     * Test fmap_dump_to_file() on a nested fmap
     */
    ck_assert_int_eq(CL_SUCCESS, fmap_dump_to_file(dup_map, NULL, NULL, &dup_fmap_dump_filepath, &dup_fmap_dump_fd, 0, SIZE_MAX));
    ck_assert_msg(dup_fmap_dump_fd != -1, "fmap_dump_fd failed");
    cli_dbgmsg("dumped map to %s\n", dup_fmap_dump_filepath);
    {
        char dumped_nested[sizeof(FMAP_TEST_STRING_PART_2)];
        ck_assert_int_eq(lseek(dup_fmap_dump_fd, 0, SEEK_SET), 0);
        ck_assert_int_eq(read(dup_fmap_dump_fd, dumped_nested, sizeof(dumped_nested)), (ssize_t)sizeof(dumped_nested));
        ck_assert_mem_eq(dumped_nested, FMAP_TEST_STRING_PART_2, sizeof(dumped_nested));
    }

    /* Ok, we're done with this dup_map */
    cli_dbgmsg("freeing dup_map\n");
    free_duplicate_fmap(dup_map);
    dup_map = NULL;

    /* We can close the fd-based map now that we're done with its duplicate */
    cl_fmap_close(fd_based_map);
    fd_based_map = NULL;

    close(fmap_dump_fd);
    fmap_dump_fd = -1;

    cli_unlink(fmap_dump_filepath);
    free(fmap_dump_filepath);
    fmap_dump_filepath = NULL;

    /* And we can close the original mem-based map as well */
    cl_fmap_close(mem_based_map);
    mem_based_map = NULL;

    /*
     * Let's make an fmap of the dumped nested map, and run the tests to verify that everything is as expected.
     */
    fd_based_dup_map = fmap_new(dup_fmap_dump_fd, 0, 0, NULL, NULL); // using fmap_new() instead of cl_fmap_open_handle() because I don't want to have to stat the file to figure out the len. fmap_new() does that for us.
    ck_assert_msg(!!fd_based_dup_map, "cl_fmap_open_handle failed");
    cli_dbgmsg("created fmap from file descriptor\n");

    /*
     * Test those same things on an fmap created with an fd that is a dumped copy of the original map.
     */
    fmap_api_tests(fd_based_dup_map, FMAP_TEST_STRING_PART_2, sizeof(FMAP_TEST_STRING_PART_2), "dumped nested handle map");

    /* Ok, we're done with the fmap based on the dumped dup_map */
    cli_dbgmsg("freeing fmap of dumped dup_map\n");
    cl_fmap_close(fd_based_dup_map);
    fd_based_dup_map = NULL;

    close(dup_fmap_dump_fd);
    dup_fmap_dump_fd = -1;

    cli_unlink(dup_fmap_dump_filepath);
    free(dup_fmap_dump_filepath);
    dup_fmap_dump_filepath = NULL;
}
END_TEST

START_TEST(test_fmap_ffi_layout)
{
    ck_assert_msg(sizeof(cl_fmap_t) == 312, "unexpected C cl_fmap_t size: %zu", sizeof(cl_fmap_t));
    ck_assert_msg(offsetof(cl_fmap_t, aging_owner) == 80, "unexpected C aging_owner offset: %zu", offsetof(cl_fmap_t, aging_owner));
    ck_assert_msg(offsetof(cl_fmap_t, offset) == 96, "unexpected C offset field offset: %zu", offsetof(cl_fmap_t, offset));
    ck_assert_msg(offsetof(cl_fmap_t, bitmap) == 288, "unexpected C bitmap offset: %zu", offsetof(cl_fmap_t, bitmap));
}
END_TEST

START_TEST(test_format_width_limits_are_fail_visible)
{
    cli_ctx ctx;
    fmap_t map;
    fmap_t *hwpole2_map;
    cl_error_t ret;

    /* HWPOLE2 carries only a 32-bit payload-size prefix. A native map above
     * that representable range must fail before the nested scan is entered. */
    {
        static const uint8_t hwpole2_prefix[sizeof(uint32_t)] = {0};

        hwpole2_map = cl_fmap_open_memory(hwpole2_prefix, sizeof(hwpole2_prefix));
        ck_assert_ptr_nonnull(hwpole2_map);
        memset(&ctx, 0, sizeof(ctx));
        ctx.fmap      = hwpole2_map;
        hwpole2_map->len = (size_t)UINT32_MAX + sizeof(uint32_t) + 1;
        ret      = cli_scanhwpole2(&ctx);
        ck_assert_msg(ret == CL_EPARSE, "oversized HWPOLE2 returned %d", ret);
        ck_assert(ctx.scan_incomplete);
        ck_assert(hwpole2_map->dont_cache_flag);
        cl_fmap_close(hwpole2_map);
    }
}
END_TEST

START_TEST(test_hwpole2_declared_size_mismatch_is_fail_visible)
{
    static const uint8_t hwpole2_data[] = {1, 0, 0, 0, 0};
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    map = cl_fmap_open_memory(hwpole2_data, sizeof(hwpole2_data));
    ck_assert_ptr_nonnull(map);
    memset(&ctx, 0, sizeof(ctx));
    ctx.fmap = map;

    ret = cli_scanhwpole2(&ctx);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_hwpml_truncated_document_is_fail_visible)
{
    static const uint8_t malformed_hwpml[] =
        "<?xml version=\"1.0\"?><HWPML><BODY>";
    struct cl_engine *scan_engine;
    struct cl_scan_options options;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    memset(&ctx, 0, sizeof(ctx));

    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(malformed_hwpml, sizeof(malformed_hwpml) - 1);
    ck_assert_ptr_nonnull(map);

    ctx.engine            = scan_engine;
    ctx.dconf             = scan_engine->dconf;
    ctx.options           = &options;
    ctx.fmap              = map;
    ctx.this_layer_tmpdir = tmpdir;

    ret = cli_scanhwpml(&ctx);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

#ifndef _WIN32
START_TEST(test_pdf_stream_limit_is_fail_visible)
{
    static const uint8_t raw_stream[] = "0123456789";
    static const uint8_t decoded_stream[] = "0123456789abcdef";
    uint8_t compressed[64];
    uLongf compressed_len = sizeof(compressed);
    struct cl_engine *scan_engine;
    struct cl_scan_options options;
    struct pdf_obj obj;
    struct pdf_struct pdf;
    cli_ctx ctx;
    fmap_t *map;
    char *path = NULL;
    int fd = -1;
    cl_error_t status;
    size_t written;

    memset(&options, 0, sizeof(options));
    memset(&obj, 0, sizeof(obj));
    memset(&pdf, 0, sizeof(pdf));
    memset(&ctx, 0, sizeof(ctx));

    ck_assert_int_eq(compress2(compressed, &compressed_len, decoded_stream,
                               sizeof(decoded_stream) - 1, Z_BEST_SPEED), Z_OK);
    ck_assert_int_eq(cli_gentempfd(tmpdir, &path, &fd), CL_SUCCESS);
    ck_assert_ptr_nonnull(path);

    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_set_num(scan_engine, CL_ENGINE_MAX_SCANSIZE, 4), CL_SUCCESS);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);

    map = cl_fmap_open_memory(raw_stream, sizeof(raw_stream) - 1);
    ck_assert_ptr_nonnull(map);
    ctx.engine            = scan_engine;
    ctx.dconf             = scan_engine->dconf;
    ctx.options           = &options;
    ctx.fmap              = map;
    ctx.this_layer_tmpdir = tmpdir;
    pdf.ctx               = &ctx;
    obj.id                = 1U << 8;

    status  = CL_SUCCESS;
    written = pdf_decodestream(&pdf, &obj, NULL, (const char *)raw_stream,
                               sizeof(raw_stream) - 1, 0, fd, &status, NULL);
    ck_assert_uint_eq(written, 0);
    ck_assert_int_eq(status, CL_EMAXSIZE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    memset(&ctx, 0, sizeof(ctx));
    memset(&pdf, 0, sizeof(pdf));
    memset(&obj, 0, sizeof(obj));
    ctx.engine            = scan_engine;
    ctx.dconf             = scan_engine->dconf;
    ctx.options           = &options;
    ctx.fmap              = map;
    ctx.this_layer_tmpdir = tmpdir;
    pdf.ctx               = &ctx;
    obj.id                = 2U << 8;
    obj.numfilters        = 1;
    obj.filterlist[0]     = OBJ_FILTER_FLATE;

    status  = CL_SUCCESS;
    written = pdf_decodestream(&pdf, &obj, NULL, (const char *)compressed,
                               (uint32_t)compressed_len, 0, fd, &status, NULL);
    ck_assert_uint_eq(written, 0);
    ck_assert_int_eq(status, CL_EMAXSIZE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    close(fd);
    cli_unlink(path);
    free(path);
    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

#if SIZE_MAX > UINT32_MAX
START_TEST(test_pdf_stream_width_boundary_is_fail_visible)
{
    static const uint8_t input[] = {0};
    struct cl_engine *scan_engine;
    struct cl_scan_options options;
    struct pdf_obj obj;
    struct pdf_struct pdf;
    cli_ctx ctx;
    fmap_t *map;
    char *path = NULL;
    int fd = -1;
    cl_error_t status;
    size_t written;

    memset(&options, 0, sizeof(options));
    memset(&obj, 0, sizeof(obj));
    memset(&pdf, 0, sizeof(pdf));
    memset(&ctx, 0, sizeof(ctx));

    ck_assert_int_eq(cli_gentempfd(tmpdir, &path, &fd), CL_SUCCESS);
    ck_assert_ptr_nonnull(path);
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);

    map = cl_fmap_open_memory(input, sizeof(input));
    ck_assert_ptr_nonnull(map);
    ctx.engine            = scan_engine;
    ctx.dconf             = scan_engine->dconf;
    ctx.options           = &options;
    ctx.fmap              = map;
    ctx.this_layer_tmpdir = tmpdir;
    pdf.ctx               = &ctx;
    obj.id                = 8U << 8;

    status  = CL_SUCCESS;
    written = pdf_decodestream(&pdf, &obj, NULL, (const char *)input,
                               (size_t)UINT32_MAX + 1U, 0, fd, &status, NULL);
    ck_assert_uint_eq(written, 0);
    ck_assert_int_eq(status, CL_ERESOURCE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    close(fd);
    cli_unlink(path);
    free(path);
    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_pdf_stream_allocation_boundary_is_fail_visible)
{
    static const uint8_t input[] = {0};
    struct cl_engine *scan_engine;
    struct cl_scan_options options;
    struct pdf_obj obj;
    struct pdf_struct pdf;
    cli_ctx ctx;
    fmap_t *map;
    char *path = NULL;
    int fd = -1;
    cl_error_t status;
    size_t written;

    memset(&options, 0, sizeof(options));
    memset(&obj, 0, sizeof(obj));
    memset(&pdf, 0, sizeof(pdf));
    memset(&ctx, 0, sizeof(ctx));

    ck_assert_int_eq(cli_gentempfd(tmpdir, &path, &fd), CL_SUCCESS);
    ck_assert_ptr_nonnull(path);
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);

    map = cl_fmap_open_memory(input, sizeof(input));
    ck_assert_ptr_nonnull(map);
    ctx.engine            = scan_engine;
    ctx.dconf             = scan_engine->dconf;
    ctx.options           = &options;
    ctx.fmap              = map;
    ctx.this_layer_tmpdir = tmpdir;
    pdf.ctx               = &ctx;
    obj.id                = 9U << 8;

    status  = CL_SUCCESS;
    written = pdf_decodestream(&pdf, &obj, NULL, (const char *)input,
                               (size_t)CLI_MAX_ALLOCATION + 1U, 0, fd, &status, NULL);
    ck_assert_uint_eq(written, 0);
    ck_assert_int_eq(status, CL_ERESOURCE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    close(fd);
    cli_unlink(path);
    free(path);
    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_pdf_object_coordinates_are_native_width)
{
    struct pdf_obj obj;
    const size_t wide_offset = (size_t)UINT32_MAX + 1U;

    memset(&obj, 0, sizeof(obj));
    obj.start = wide_offset;
    ck_assert_uint_eq(obj.start, wide_offset);
    ck_assert_msg(sizeof(obj.start) >= sizeof(size_t),
                  "PDF object coordinate was narrowed below native size_t width");
}
END_TEST
#endif

START_TEST(test_pdf_extracted_object_limit_is_fail_visible)
{
    static const uint8_t javascript[] = "/JavaScript /JS (0123456789)\n";
    struct cl_engine *scan_engine;
    struct cl_scan_options options;
    struct pdf_obj obj;
    struct pdf_struct pdf;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t status;

    memset(&options, 0, sizeof(options));
    memset(&obj, 0, sizeof(obj));
    memset(&pdf, 0, sizeof(pdf));
    memset(&ctx, 0, sizeof(ctx));

    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_set_num(scan_engine, CL_ENGINE_MAX_SCANSIZE, 4), CL_SUCCESS);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);

    map = cl_fmap_open_memory(javascript, sizeof(javascript) - 1);
    ck_assert_ptr_nonnull(map);
    ctx.engine            = scan_engine;
    ctx.dconf             = scan_engine->dconf;
    ctx.options           = &options;
    ctx.fmap              = map;
    ctx.this_layer_tmpdir = tmpdir;
    pdf.ctx               = &ctx;
    pdf.map               = (const char *)javascript;
    pdf.size              = sizeof(javascript) - 1;
    pdf.dir               = tmpdir;
    obj.id                = 3U << 8;
    obj.start             = 0;
    obj.size              = sizeof(javascript) - 1;
    obj.flags             = 1U << OBJ_JAVASCRIPT;

    status = pdf_extract_obj(&pdf, &obj, PDF_EXTRACT_OBJ_NONE);
    ck_assert_int_eq(status, CL_EMAXSIZE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_pdf_extract_decoder_error_is_fail_visible)
{
    static const uint8_t malformed_flate[] = {0x78, 0x9c, 0xff, 0xff, 0xff, 0xff};
    struct cl_engine *scan_engine;
    struct cl_scan_options options;
    struct pdf_obj obj;
    struct pdf_struct pdf;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t status;

    memset(&options, 0, sizeof(options));
    memset(&obj, 0, sizeof(obj));
    memset(&pdf, 0, sizeof(pdf));
    memset(&ctx, 0, sizeof(ctx));

    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);

    map = cl_fmap_open_memory(malformed_flate, sizeof(malformed_flate));
    ck_assert_ptr_nonnull(map);
    ctx.engine            = scan_engine;
    ctx.dconf             = scan_engine->dconf;
    ctx.options           = &options;
    ctx.fmap              = map;
    ctx.this_layer_tmpdir = tmpdir;
    pdf.ctx               = &ctx;
    pdf.map               = (const char *)malformed_flate;
    pdf.size              = sizeof(malformed_flate);
    pdf.dir               = tmpdir;
    obj.id          = 9U << 8;
    obj.flags       = (1U << OBJ_STREAM) | (1U << OBJ_FILTER_FLATE);
    obj.stream      = (const char *)malformed_flate;
    obj.stream_size = sizeof(malformed_flate);

    status = pdf_extract_obj(&pdf, &obj, PDF_EXTRACT_OBJ_NONE);
    ck_assert_int_eq(status, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_pdf_truncated_trailer_is_fail_visible)
{
    static const uint8_t missing_eof[] =
        "%PDF-1.7\n1 0 obj\n<<>>\nendobj\n";
    static const uint8_t missing_startxref[] =
        "%PDF-1.7\n%%EOF\n";
    static const uint8_t negative_xref[] =
        "%PDF-1.7\nstartxref\n-1\n%%EOF\n";
    const uint8_t *cases[] = {
        missing_eof,
        missing_startxref,
        negative_xref,
    };
    const size_t lengths[] = {
        sizeof(missing_eof) - 1,
        sizeof(missing_startxref) - 1,
        sizeof(negative_xref) - 1,
    };
    struct cl_engine *scan_engine;
    struct cl_scan_options options;
    cli_ctx ctx;
    fmap_t *map;
    size_t i;

    memset(&options, 0, sizeof(options));
    memset(&ctx, 0, sizeof(ctx));

    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        memset(&ctx, 0, sizeof(ctx));
        map = cl_fmap_open_memory(cases[i], lengths[i]);
        ck_assert_ptr_nonnull(map);
        ctx.engine            = scan_engine;
        ctx.dconf             = scan_engine->dconf;
        ctx.options           = &options;
        ctx.fmap              = map;
        ctx.this_layer_tmpdir = tmpdir;

        ck_assert_int_eq(cli_pdf(tmpdir, &ctx, 0), CL_EPARSE);
        ck_assert(ctx.scan_incomplete);
        ck_assert(map->dont_cache_flag);

        cl_fmap_close(map);
    }

    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_pdf_truncated_object_is_fail_visible)
{
    static const uint8_t truncated_object[] =
        "%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\n%%EOF\n";
    struct cl_engine *scan_engine;
    struct cl_scan_options options;
    cli_ctx ctx;
    fmap_t *map;

    memset(&options, 0, sizeof(options));
    memset(&ctx, 0, sizeof(ctx));

    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);

    map = cl_fmap_open_memory(truncated_object, sizeof(truncated_object) - 1U);
    ck_assert_ptr_nonnull(map);
    ctx.engine            = scan_engine;
    ctx.dconf             = scan_engine->dconf;
    ctx.options           = &options;
    ctx.fmap              = map;
    ctx.this_layer_tmpdir = tmpdir;

    ck_assert_int_eq(cli_pdf(tmpdir, &ctx, 0), CL_EFORMAT);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason,
                     "PDF object parsing ended before inspection completed");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_pdf_decode_error_is_fail_visible)
{
    static const uint8_t malformed_flate[] = {0x78, 0x9c, 0xff, 0xff, 0xff, 0xff};
    struct cl_engine *scan_engine;
    struct cl_scan_options options;
    struct pdf_obj obj;
    struct pdf_struct pdf;
    cli_ctx ctx;
    fmap_t *map;
    char *path = NULL;
    int fd = -1;
    cl_error_t status;

    memset(&options, 0, sizeof(options));
    memset(&obj, 0, sizeof(obj));
    memset(&pdf, 0, sizeof(pdf));
    memset(&ctx, 0, sizeof(ctx));

    ck_assert_int_eq(cli_gentempfd(tmpdir, &path, &fd), CL_SUCCESS);
    ck_assert_ptr_nonnull(path);
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);

    map = cl_fmap_open_memory(malformed_flate, sizeof(malformed_flate));
    ck_assert_ptr_nonnull(map);
    ctx.engine            = scan_engine;
    ctx.dconf             = scan_engine->dconf;
    ctx.options           = &options;
    ctx.fmap              = map;
    ctx.this_layer_tmpdir = tmpdir;
    pdf.ctx               = &ctx;
    obj.id                = 4U << 8;
    obj.numfilters        = 1;
    obj.filterlist[0]     = OBJ_FILTER_FLATE;

    status = CL_SUCCESS;
    (void)pdf_decodestream(&pdf, &obj, NULL, (const char *)malformed_flate,
                           sizeof(malformed_flate), 0, fd, &status, NULL);
    ck_assert_int_eq(status, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    close(fd);
    cli_unlink(path);
    free(path);
    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_pdf_empty_flate_stream_is_fail_visible)
{
    static const uint8_t empty_flate[] = {'\r'};
    struct cl_engine *scan_engine;
    struct cl_scan_options options;
    struct pdf_obj obj;
    struct pdf_struct pdf;
    cli_ctx ctx;
    fmap_t *map;
    char *path = NULL;
    int fd = -1;
    cl_error_t status;

    memset(&options, 0, sizeof(options));
    memset(&obj, 0, sizeof(obj));
    memset(&pdf, 0, sizeof(pdf));
    memset(&ctx, 0, sizeof(ctx));

    ck_assert_int_eq(cli_gentempfd(tmpdir, &path, &fd), CL_SUCCESS);
    ck_assert_ptr_nonnull(path);
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);

    map = cl_fmap_open_memory(empty_flate, sizeof(empty_flate));
    ck_assert_ptr_nonnull(map);
    ctx.engine            = scan_engine;
    ctx.dconf             = scan_engine->dconf;
    ctx.options           = &options;
    ctx.fmap              = map;
    ctx.this_layer_tmpdir = tmpdir;
    pdf.ctx               = &ctx;
    obj.id                = 5U << 8;
    obj.numfilters        = 1;
    obj.filterlist[0]     = OBJ_FILTER_FLATE;

    status = CL_SUCCESS;
    (void)pdf_decodestream(&pdf, &obj, NULL, (const char *)empty_flate,
                           sizeof(empty_flate), 0, fd, &status, NULL);
    ck_assert_int_eq(status, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    close(fd);
    cli_unlink(path);
    free(path);
    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_pdf_unsupported_filter_is_fail_visible)
{
    static const uint8_t raw_stream[] = "unsupported PDF image filter";
    struct cl_engine *scan_engine;
    struct cl_scan_options options;
    struct pdf_obj obj;
    struct pdf_struct pdf;
    cli_ctx ctx;
    fmap_t *map;
    char *path = NULL;
    int fd = -1;
    cl_error_t status;
    size_t written;

    memset(&options, 0, sizeof(options));
    memset(&obj, 0, sizeof(obj));
    memset(&pdf, 0, sizeof(pdf));
    memset(&ctx, 0, sizeof(ctx));

    ck_assert_int_eq(cli_gentempfd(tmpdir, &path, &fd), CL_SUCCESS);
    ck_assert_ptr_nonnull(path);
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);

    map = cl_fmap_open_memory(raw_stream, sizeof(raw_stream) - 1);
    ck_assert_ptr_nonnull(map);
    ctx.engine            = scan_engine;
    ctx.dconf             = scan_engine->dconf;
    ctx.options           = &options;
    ctx.fmap              = map;
    ctx.this_layer_tmpdir = tmpdir;
    pdf.ctx               = &ctx;
    obj.id                = 7U << 8;
    obj.numfilters        = 1;
    obj.filterlist[0]     = OBJ_FILTER_DCT;

    status  = CL_SUCCESS;
    written = pdf_decodestream(&pdf, &obj, NULL, (const char *)raw_stream,
                               sizeof(raw_stream) - 1, 0, fd, &status, NULL);
    ck_assert_uint_eq(written, sizeof(raw_stream) - 1);
    ck_assert_int_eq(status, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    close(fd);
    cli_unlink(path);
    free(path);
    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_pdf_unsupported_encryption_is_fail_visible)
{
    static const uint8_t encrypted_stream[] = "encrypted PDF stream";
    struct cl_engine *scan_engine;
    struct cl_scan_options options;
    struct pdf_obj obj;
    struct pdf_struct pdf;
    cli_ctx ctx;
    fmap_t *map;
    char *path = NULL;
    int fd = -1;
    cl_error_t status;
    size_t written;

    memset(&options, 0, sizeof(options));
    memset(&obj, 0, sizeof(obj));
    memset(&pdf, 0, sizeof(pdf));
    memset(&ctx, 0, sizeof(ctx));

    ck_assert_int_eq(cli_gentempfd(tmpdir, &path, &fd), CL_SUCCESS);
    ck_assert_ptr_nonnull(path);
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);

    map = cl_fmap_open_memory(encrypted_stream, sizeof(encrypted_stream) - 1U);
    ck_assert_ptr_nonnull(map);
    ctx.engine            = scan_engine;
    ctx.dconf             = scan_engine->dconf;
    ctx.options           = &options;
    ctx.fmap              = map;
    ctx.this_layer_tmpdir = tmpdir;
    pdf.ctx               = &ctx;
    pdf.flags             = 1U << DECRYPTABLE_PDF;
    obj.id                = 8U << 8;
    obj.flags             = 1U << OBJ_FILTER_CRYPT;
    obj.numfilters        = 1;
    obj.filterlist[0]     = OBJ_FILTER_CRYPT;

    status  = CL_SUCCESS;
    written = pdf_decodestream(&pdf, &obj, NULL, (const char *)encrypted_stream,
                               sizeof(encrypted_stream) - 1U, 0, fd, &status, NULL);
    ck_assert_uint_eq(written, sizeof(encrypted_stream) - 1U);
    ck_assert_int_eq(status, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason,
                     "PDF encrypted stream uses unsupported encryption or has no usable key");
    ck_assert(map->dont_cache_flag);

    close(fd);
    cli_unlink(path);
    free(path);
    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_pdf_truncated_flate_after_prefix_is_fail_visible)
{
    enum { DECODED_LENGTH = 16384 };
    uint8_t decoded[DECODED_LENGTH];
    uint8_t *compressed;
    uLongf compressed_length;
    struct cl_engine *scan_engine;
    struct cl_scan_options options;
    struct pdf_obj obj;
    struct pdf_struct pdf;
    cli_ctx ctx;
    fmap_t *map;
    char *path = NULL;
    int fd = -1;
    cl_error_t status;
    size_t i;

    for (i = 0; i < sizeof(decoded); i++)
        decoded[i] = (uint8_t)((i * 37U) ^ (i >> 3));
    compressed_length = compressBound((uLong)sizeof(decoded));
    compressed        = malloc((size_t)compressed_length);
    ck_assert_ptr_nonnull(compressed);
    ck_assert_int_eq(compress2(compressed, &compressed_length, decoded,
                               sizeof(decoded), Z_BEST_SPEED), Z_OK);
    ck_assert_msg(compressed_length > 1U, "PDF Flate fixture unexpectedly short");

    memset(&options, 0, sizeof(options));
    memset(&obj, 0, sizeof(obj));
    memset(&pdf, 0, sizeof(pdf));
    memset(&ctx, 0, sizeof(ctx));
    ck_assert_int_eq(cli_gentempfd(tmpdir, &path, &fd), CL_SUCCESS);
    ck_assert_ptr_nonnull(path);

    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(compressed, (size_t)compressed_length - 1U);
    ck_assert_ptr_nonnull(map);
    ctx.engine            = scan_engine;
    ctx.dconf             = scan_engine->dconf;
    ctx.options           = &options;
    ctx.fmap              = map;
    ctx.this_layer_tmpdir = tmpdir;
    pdf.ctx               = &ctx;
    obj.id                = 6U << 8;
    obj.numfilters        = 1;
    obj.filterlist[0]     = OBJ_FILTER_FLATE;

    status = CL_SUCCESS;
    (void)pdf_decodestream(&pdf, &obj, NULL, (const char *)compressed,
                           (uint32_t)compressed_length - 1U, 0, fd, &status, NULL);
    ck_assert_msg(status == CL_EPARSE || status == CL_EUNPACK,
                  "truncated PDF Flate after a valid prefix returned %s (%d)",
                  cl_strerror(status), status);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    close(fd);
    cli_unlink(path);
    free(path);
    cl_fmap_close(map);
    cl_engine_free(scan_engine);
    free(compressed);
}
END_TEST

START_TEST(test_pdf_truncated_lzw_after_prefix_is_fail_visible)
{
    /* MSB-first 9-bit codes: CLEAR (256), 'A' (65), with EOI omitted. */
    static const uint8_t truncated_lzw[] = {0x80, 0x10, 0x40};
    struct cl_engine *scan_engine;
    struct cl_scan_options options;
    struct pdf_obj obj;
    struct pdf_struct pdf;
    cli_ctx ctx;
    fmap_t *map;
    char *path = NULL;
    int fd = -1;
    cl_error_t status;

    memset(&options, 0, sizeof(options));
    memset(&obj, 0, sizeof(obj));
    memset(&pdf, 0, sizeof(pdf));
    memset(&ctx, 0, sizeof(ctx));
    ck_assert_int_eq(cli_gentempfd(tmpdir, &path, &fd), CL_SUCCESS);
    ck_assert_ptr_nonnull(path);

    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(truncated_lzw, sizeof(truncated_lzw));
    ck_assert_ptr_nonnull(map);
    ctx.engine            = scan_engine;
    ctx.dconf             = scan_engine->dconf;
    ctx.options           = &options;
    ctx.fmap              = map;
    ctx.this_layer_tmpdir = tmpdir;
    pdf.ctx               = &ctx;
    obj.id                = 7U << 8;
    obj.numfilters        = 1;
    obj.filterlist[0]     = OBJ_FILTER_LZW;

    status = CL_SUCCESS;
    (void)pdf_decodestream(&pdf, &obj, NULL, (const char *)truncated_lzw,
                           sizeof(truncated_lzw), 0, fd, &status, NULL);
    ck_assert_int_eq(status, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    close(fd);
    cli_unlink(path);
    free(path);
    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST
#endif

START_TEST(test_legacy_parser_limit_returns_are_fail_visible)
{
    static const uint8_t hwp3_identity[30] = {
        0x48, 0x57, 0x50, 0x20, 0x44, 0x6f, 0x63, 0x75, 0x6d, 0x65,
        0x6e, 0x74, 0x20, 0x46, 0x69, 0x6c, 0x65, 0x20, 0x56, 0x33,
        0x2e, 0x30, 0x30, 0x20, 0x1a, 0x01, 0x02, 0x03, 0x04, 0x05};
    uint8_t hwp3_data[1183] = {0};
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_scan_layer_t layer;
    cli_ctx ctx;
    fmap_t *map;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    /* The zeroed HWP3 sections leave one paragraph entry after the seven
     * empty font entries and empty style table. A zero MaxRecHWP3 limit
     * reaches the parser's guard before it reads that paragraph. */
    memcpy(hwp3_data, hwp3_identity, sizeof(hwp3_identity));
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_HWP3;
    ck_assert_int_eq(cl_engine_set_num(scan_engine, CL_ENGINE_MAX_RECHWP3, 0), CL_SUCCESS);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map                     = cl_fmap_open_memory(hwp3_data, sizeof(hwp3_data));
    ck_assert_ptr_nonnull(map);
    verdict                 = CL_VERDICT_STRONG_INDICATOR;
    last_alert              = "stale";
    scanned                 = UINT64_MAX;
    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL, "CL_TYPE_HWP3", NULL);
    ck_assert_int_eq(ret, CL_EMAXREC);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    cl_fmap_close(map);
    cl_engine_free(scan_engine);

    /* OLE2 has a separate initial cumulative-MaxScanSize check before it
     * can inspect the container header. It must carry the same sticky state
     * as the shared limit helpers instead of returning a bare MAX result. */
    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&layer, 0, sizeof(layer));
    memset(&ctx, 0, sizeof(ctx));
    engine.maxscansize        = 10;
    map                      = cl_fmap_open_memory(hwp3_data, sizeof(hwp3_data));
    ck_assert_ptr_nonnull(map);
    layer.fmap               = map;
    ctx.engine                = &engine;
    ctx.options               = &options;
    ctx.fmap                  = map;
    ctx.recursion_stack       = &layer;
    ctx.recursion_stack_size  = 1;
    ctx.scansize              = 10;

    ret = cli_ole2_extract(tmpdir, &ctx, NULL, NULL, NULL, NULL);
    ck_assert_int_eq(ret, CL_EMAXSIZE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(ctx.limit_exceeded);
    ck_assert_int_eq(ctx.limit_exceeded_result, CL_EMAXSIZE);
    ck_assert(map->dont_cache_flag);
    cl_fmap_close(map);
}
END_TEST

START_TEST(test_ole2_member_limit_is_fail_visible)
{
    const char *file = SRCDIR PATHSEP "input" PATHSEP "other_scanfiles" PATHSEP "has_png_and_jpeg.xls";
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_scan_layer_t layer;
    cli_ctx ctx;
    fmap_t *map;
    struct uniq *files = NULL;
    cl_error_t ret;
    int fd;

    fd = open(file, O_RDONLY | O_BINARY);
    ck_assert_msg(fd >= 0, "open(%s) failed: %s", file, strerror(errno));
    map = fmap_new(fd, 0, 0, file, NULL);
    ck_assert_ptr_nonnull(map);

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&layer, 0, sizeof(layer));
    memset(&ctx, 0, sizeof(ctx));
    engine.maxfilesize        = 1;
    engine.maxscansize        = 64;
    layer.fmap               = map;
    ctx.engine               = &engine;
    ctx.options              = &options;
    ctx.fmap                 = map;
    ctx.this_layer_tmpdir    = tmpdir;
    ctx.recursion_stack      = &layer;
    ctx.recursion_stack_size = 1;

    ret = cli_ole2_extract(tmpdir, &ctx, &files, NULL, NULL, NULL);
    ck_assert_int_eq(ret, CL_EMAXSIZE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(ctx.limit_exceeded);
    ck_assert_int_eq(ctx.limit_exceeded_result, CL_EMAXSIZE);
    ck_assert(map->dont_cache_flag);
    ck_assert_ptr_null(files);

    cl_fmap_close(map);
    close(fd);
}
END_TEST

START_TEST(test_msexpand_truncated_output_is_fail_visible)
{
    uint8_t data[14] = {
        0x53, 0x5a, 0x44, 0x44, /* MAGIC1 */
        0x88, 0xf0, 0x27, 0x33, /* MAGIC2 */
        0x41, 0x00,             /* MAGIC3 */
        0x01, 0x00, 0x00, 0x00  /* declared output size */
    };
    uint8_t overproduced_data[17] = {
        0x53, 0x5a, 0x44, 0x44, /* MAGIC1 */
        0x88, 0xf0, 0x27, 0x33, /* MAGIC2 */
        0x41, 0x00,             /* MAGIC3 */
        0x01, 0x00, 0x00, 0x00, /* declared output size */
        0x03, 'A', 'B'          /* two literals: output exceeds the declaration */
    };
    struct cl_scan_options options;
    fmap_t *map;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;
    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL, "CL_TYPE_MSSZDD", NULL);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);

    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(overproduced_data, sizeof(overproduced_data));
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;
    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL, "CL_TYPE_MSSZDD", NULL);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);

    data[10] = 0x02;
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_set_num(scan_engine, CL_ENGINE_MAX_SCANSIZE, 1), CL_SUCCESS);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;
    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL, "CL_TYPE_MSSZDD", NULL);
    ck_assert_int_eq(ret, CL_EMAXSIZE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);

    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_set_num(scan_engine, CL_ENGINE_MAX_TEMPORARY_SIZE, 1), CL_SUCCESS);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;
    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL, "CL_TYPE_MSSZDD", NULL);
    ck_assert_msg(ret == CL_ERESOURCE,
                  "MSEXPAND temporary limit returned %s (%d)", cl_strerror(ret), ret);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_msexpand_time_limit_is_fail_visible)
{
    static const uint8_t data[] = {0};
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    uint64_t temporary_reserved = 0;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine = &engine;
    ctx.fmap   = map;
    ck_assert_int_eq(gettimeofday(&ctx.time_limit, NULL), 0);
    ctx.time_limit.tv_sec--;

    ret = cli_msexpand(&ctx, -1, &temporary_reserved);
    ck_assert_int_eq(ret, CL_ETIMEOUT);
    ck_assert_int_eq(temporary_reserved, 0);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "MSEXPAND inspection reached the configured time limit");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_uuencode_truncated_attachment_is_fail_visible)
{
    static const uint8_t data[] = "begin 644 payload\n";
    struct cl_scan_options options;
    fmap_t *map;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data) - 1);
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL, "CL_TYPE_UUENCODED", NULL);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_uuencode_temporary_limit_is_fail_visible)
{
    static const uint8_t data[] = "begin 644 payload\n#0V%T\n`\nend\n";
    struct cl_scan_options options;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    fmap_t *map;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_set_num(scan_engine, CL_ENGINE_MAX_TEMPORARY_SIZE, 1), CL_SUCCESS);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data) - 1U);
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL,
                        "CL_TYPE_UUENCODED", NULL);
    ck_assert_msg(ret == CL_ERESOURCE,
                  "UUEncode temporary limit returned %s (%d)", cl_strerror(ret), ret);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_binhex_truncated_header_is_fail_visible)
{
    static const uint8_t data[] =
        "(This file must be converted with BinHex 4.0)\r\n:";
    struct cl_scan_options options;
    fmap_t *map;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data) - 1);
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL, "CL_TYPE_BINHEX", NULL);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_binhex_time_limit_is_fail_visible)
{
    static const uint8_t data[] = {0};
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine = &engine;
    ctx.fmap   = map;
    ck_assert_int_eq(gettimeofday(&ctx.time_limit, NULL), 0);
    ctx.time_limit.tv_sec--;

    ret = cli_binhex(&ctx);
    ck_assert_int_eq(ret, CL_ETIMEOUT);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "BinHex inspection reached the configured time limit");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_binhex_truncated_data_fork_is_fail_visible)
{
    static const uint8_t data[] =
        "(This file must be converted with BinHex 4.0)\r\n:!8%!9&P3480548%!!!!!!!)!!!!!!!!!";
    struct cl_scan_options options;
    fmap_t *map;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data) - 1);
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL, "CL_TYPE_BINHEX", NULL);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_binhex_short_resource_fork_is_fail_visible)
{
    static const uint8_t data[] =
        "(This file must be converted with BinHex 4.0)\r\n:!!\"8@9\"&3e*&33!!!!!!!!!!!!%!!!!!8J!!";
    struct cl_scan_options options;
    fmap_t *map;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data) - 1U);
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL, "CL_TYPE_BINHEX", NULL);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_binhex_output_temporary_limit_is_fail_visible)
{
    static const uint8_t data[] =
        "(This file must be converted with BinHex 4.0)\r\n:!8%!9&P3480548%!!!!!!!)!!!!!!!!!";
    struct cl_scan_options options;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    fmap_t *map;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_set_num(scan_engine, CL_ENGINE_MAX_TEMPORARY_SIZE, 1), CL_SUCCESS);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data) - 1U);
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL,
                        "CL_TYPE_BINHEX", NULL);
    ck_assert_msg(ret == CL_ERESOURCE,
                  "BinHex temporary limit returned %s (%d)", cl_strerror(ret), ret);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

#ifdef CLAMAV_TEST_JS_IO_WRAP
START_TEST(test_binhex_cleanup_close_failure_is_fail_visible)
{
    static const uint8_t data[] =
        "(This file must be converted with BinHex 4.0)\r\n:";
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data) - 1);
    ck_assert_ptr_nonnull(map);
    ctx.engine             = &engine;
    ctx.options            = &options;
    ctx.fmap               = map;
    ctx.this_layer_tmpdir = tmpdir;

    clamav_test_fail_close = 1;
    ret = cli_binhex(&ctx);
    clamav_test_fail_close = 0;

    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);
    ck_assert_msg(ctx.skipped_operations > 1,
                  "BinHex cleanup failures were not recorded after the parser failure");
    cl_fmap_close(map);
}
END_TEST
#endif

START_TEST(test_sis_truncated_contents_is_fail_visible)
{
    static const uint8_t data[16] = {
        0x7a, 0x1a, 0x20, 0x10, /* Symbian SIS 9.x UID */
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00};
    struct cl_scan_options options;
    fmap_t *map;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL, "CL_TYPE_SIS", NULL);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_sis_name_table_read_failure_is_fail_visible)
{
    uint8_t data[92] = {0};
    struct cl_scan_options options;
    fmap_t *map;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    /* Old SIS metadata declares a two-byte application name whose payload
     * starts at the final byte of the map. The name table itself is present,
     * but the string read must be reported as truncated rather than ignored. */
    data[8]  = 0x19;
    data[9]  = 0x04;
    data[11] = 0x10;
    data[18] = 1;
    cli_writeint32(data + 52, 84); /* file records begin at the header end */
    cli_writeint32(data + 64, 84); /* application name table */
    cli_writeint32(data + 84, 2);  /* UTF-16 byte length */
    cli_writeint32(data + 88, 91); /* one byte remains at the declared payload */

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL, "CL_TYPE_SIS", NULL);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_sis_truncated_compressed_member_is_fail_visible)
{
    uint8_t data[134] = {0};
    struct cl_scan_options options;
    fmap_t *map;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    /* Minimal pre-9.x SIS package with a zlib header but no complete stream. */
    data[8]  = 0x19;
    data[9]  = 0x04;
    data[11] = 0x10;
    data[18] = 1;
    data[20] = 1;
    data[36] = 0x00; /* package is compressed */
    cli_writeint32(data + 48, 84);
    cli_writeint32(data + 52, 86);
    cli_writeint32(data + 114, 2);
    cli_writeint32(data + 118, 126);
    cli_writeint32(data + 122, 8);
    data[126] = 0x78;
    data[127] = 0x9c;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL, "CL_TYPE_SIS", NULL);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_python_compiled_parser_is_explicitly_unsupported)
{
    static const uint8_t data[] = {0x42, 0x0d, 0x0d, 0x0a, 0, 0, 0, 0};
    struct cl_scan_options options;
    fmap_t *map;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL,
                        "CL_TYPE_PYTHON_COMPILED", NULL);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_ai_model_parser_is_explicitly_unsupported)
{
    static const uint8_t data[] = {0x47, 0x47, 0x55, 0x46, 0x01, 0, 0, 0};
    struct cl_scan_options options;
    fmap_t *map;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL,
                        "CL_TYPE_AI_MODEL", NULL);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_graphics_bmp_truncated_header_is_fail_visible)
{
    static const uint8_t data[] = {0x42, 0x4d, 0, 0, 0, 0, 0, 0};
    struct cl_scan_options options;
    fmap_t *map;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_IMAGE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL,
                        "CL_TYPE_GRAPHICS", NULL);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_bmp_missing_uncompressed_pixel_range_is_malformed)
{
    uint8_t data[54] = {0};
    struct cl_scan_options options;
    fmap_t *map;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    data[0]  = 'B';
    data[1]  = 'M';
    data[2]  = 54;
    data[10] = 54;
    data[14] = 40;
    data[18] = 1;
    data[22] = 1;
    data[26] = 1;
    data[28] = 24;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_IMAGE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL,
                        "CL_TYPE_GRAPHICS", NULL);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_bmp_structural_admission_remains_incomplete)
{
    uint8_t data[58] = {0};
    struct cl_scan_options options;
    fmap_t *map;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    data[0]  = 'B';
    data[1]  = 'M';
    data[2]  = 58;
    data[10] = 54;
    data[14] = 40;
    data[18] = 1;
    data[22] = 1;
    data[26] = 1;
    data[28] = 24;
    data[34] = 4;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_IMAGE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL,
                        "CL_TYPE_GRAPHICS", NULL);
    ck_assert_msg((ret == CL_EUNPACK) || (ret == CL_EPARSE),
                  "expected explicit BMP incompleteness, got %d", ret);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_jp2_truncated_box_is_fail_visible)
{
    static const uint8_t data[] = {
        0x00, 0x00, 0x00, 0x0c, 0x6a, 0x50,
        0x20, 0x20, 0x0d, 0x0a, 0x87, 0x0a};
    struct cl_scan_options options;
    fmap_t *map;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_IMAGE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL,
                        "CL_TYPE_GRAPHICS", NULL);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_jp2_time_limit_is_fail_visible)
{
    static const uint8_t data[] = {0};
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine = &engine;
    ctx.fmap   = map;
    ck_assert_int_eq(gettimeofday(&ctx.time_limit, NULL), 0);
    ctx.time_limit.tv_sec--;

    ret = cli_scanjp2(&ctx);
    ck_assert_int_eq(ret, CL_ETIMEOUT);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "JP2 inspection reached the configured time limit");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_jp2_structural_admission_remains_incomplete)
{
    static const uint8_t signature[] = {
        0x00, 0x00, 0x00, 0x0c, 0x6a, 0x50,
        0x20, 0x20, 0x0d, 0x0a, 0x87, 0x0a};
    uint8_t data[50] = {0};
    struct cl_scan_options options;
    fmap_t *map;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    memcpy(data, signature, sizeof(signature));
    data[15] = 16;
    memcpy(data + 16, "ftyp", 4);
    memcpy(data + 20, "jp2 ", 4);
    data[27] = 0;
    data[31] = 12;
    memcpy(data + 32, "jp2h", 4);
    data[39] = 0;
    data[43] = 10;
    memcpy(data + 44, "jp2c", 4);
    data[48] = 0xff;
    data[49] = 0x4f;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_IMAGE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL,
                        "CL_TYPE_GRAPHICS", NULL);
    ck_assert_msg((ret == CL_EUNPACK) || (ret == CL_EPARSE),
                  "expected explicit JP2 incompleteness, got %d", ret);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_generic_graphics_parser_is_explicitly_unsupported)
{
    static const uint8_t data[] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc};
    struct cl_scan_options options;
    fmap_t *map;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_IMAGE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL,
                        "CL_TYPE_GRAPHICS", NULL);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_sis_compressed_member_streams_to_nested_scan)
{
    static const uint8_t compressed[] = {
        0x78, 0x9c, 0x0b, 0xf6, 0x0c, 0x76, 0x71, 0x0c,
        0x71, 0x54, 0x04, 0x00, 0x0a, 0x88, 0x02, 0x2b};
    uint8_t data[142] = {0};
    struct cl_scan_options options;
    fmap_t *map;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    /* Minimal pre-9.x SIS package with a valid compressed eight-byte member. */
    data[8]  = 0x19;
    data[9]  = 0x04;
    data[11] = 0x10;
    data[18] = 1;
    data[20] = 1;
    data[36] = 0x00; /* package is compressed */
    cli_writeint32(data + 48, 84);
    cli_writeint32(data + 52, 86);
    cli_writeint32(data + 114, sizeof(compressed));
    cli_writeint32(data + 118, 126);
    cli_writeint32(data + 122, 8);
    memcpy(data + 126, compressed, sizeof(compressed));

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL, "CL_TYPE_SIS", NULL);
    ck_assert_int_eq(ret, CL_CLEAN);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_sis_member_limit_is_fail_visible)
{
    uint8_t data[134] = {0};
    struct cl_scan_options options;
    fmap_t *map;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    /* Minimal pre-9.x SIS package: one uncompressed file whose eight-byte
     * member exceeds the one-byte MaxScanSize configured below. */
    data[8]  = 0x19;
    data[9]  = 0x04;
    data[11] = 0x10; /* old SIS format UID */
    data[18] = 1;    /* one language */
    data[20] = 1;    /* one file */
    data[36] = 0x08; /* package is not compressed */
    cli_writeint32(data + 48, 84);  /* language table */
    cli_writeint32(data + 52, 86);  /* file records */
    cli_writeint32(data + 114, 8);  /* compressed/member length */
    cli_writeint32(data + 118, 126); /* member offset */
    cli_writeint32(data + 122, 8);  /* decompressed length */
    memcpy(data + 126, "SISDATA!", 8);

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_set_num(scan_engine, CL_ENGINE_MAX_SCANSIZE, 1), CL_SUCCESS);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL, "CL_TYPE_SIS", NULL);
    ck_assert_int_eq(ret, CL_EMAXSIZE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_sis_member_header_offset_is_fail_visible)
{
    uint8_t data[134] = {0};
    struct cl_scan_options options;
    fmap_t *map;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    /* Minimal pre-9.x SIS package whose declared member points into the
     * package header. The parser must not turn that omitted member into clean. */
    data[8]  = 0x19;
    data[9]  = 0x04;
    data[11] = 0x10; /* old SIS format UID */
    data[18] = 1;    /* one language */
    data[20] = 1;    /* one file */
    data[36] = 0x08; /* package is not compressed */
    cli_writeint32(data + 48, 84);  /* language table */
    cli_writeint32(data + 52, 86);  /* file records */
    cli_writeint32(data + 114, 8);  /* compressed/member length */
    cli_writeint32(data + 118, 80); /* invalid offset inside SIS header */
    cli_writeint32(data + 122, 8);  /* decompressed length */
    memcpy(data + 126, "SISDATA!", 8);

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL, "CL_TYPE_SIS", NULL);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_tar_truncated_header_is_fail_visible)
{
    uint8_t data[511] = {0};
    struct cl_scan_options options;
    fmap_t *map;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    data[0] = 'x';
    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL, "CL_TYPE_POSIX_TAR", NULL);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

static const void *tar_initial_header_read_failure(fmap_t *map, size_t at, size_t len, int lock)
{
    (void)map;
    (void)at;
    (void)len;
    (void)lock;
    return NULL;
}

START_TEST(test_tar_initial_header_read_failure_is_fail_visible)
{
    static const uint8_t data[512] = {0};
    struct cl_scan_options options;
    fmap_t *map;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    map->need    = tar_initial_header_read_failure;
    verdict      = CL_VERDICT_STRONG_INDICATOR;
    last_alert   = "stale";
    scanned      = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL, "CL_TYPE_POSIX_TAR", NULL);
    ck_assert_int_eq(ret, CL_EREAD);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_tar_invalid_magic_is_fail_visible)
{
    uint8_t data[512] = {0};
    unsigned int checksum = 0;
    struct cl_scan_options options;
    fmap_t *map;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;
    size_t i;

    memcpy(data, "invalid-magic", sizeof("invalid-magic") - 1U);
    memcpy(data + 100, "0000777", 7);
    memcpy(data + 124, "00000000000", 11);
    data[156] = '0';
    memcpy(data + 257, "xxxxx", 5);
    memset(data + 148, ' ', 8);
    for (i = 0; i < 512; i++)
        checksum += data[i];
    snprintf((char *)(data + 148), 8, "%06o", checksum);
    data[154] = ' ';
    data[155] = '\0';

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL,
                        "CL_TYPE_POSIX_TAR", NULL);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_tar_temporary_limit_is_fail_visible)
{
    uint8_t data[2048] = {0};
    unsigned int checksum = 0;
    struct cl_scan_options options;
    fmap_t *map;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;
    size_t i;

    memcpy(data, "large-member", sizeof("large-member") - 1U);
    memcpy(data + 100, "0000777", 7);
    memcpy(data + 124, "00000000002", 11);
    data[156] = '0';
    memcpy(data + 257, "ustar", 5);
    data[148] = ' ';
    data[149] = ' ';
    data[150] = ' ';
    data[151] = ' ';
    data[152] = ' ';
    data[153] = ' ';
    data[154] = ' ';
    data[155] = ' ';
    for (i = 0; i < 512; i++)
        checksum += data[i];
    snprintf((char *)(data + 148), 8, "%06o", checksum);
    data[154] = ' ';
    data[155] = '\0';
    data[512] = 'x';
    data[513] = 'y';

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_set_num(scan_engine, CL_ENGINE_MAX_TEMPORARY_SIZE, 1), CL_SUCCESS);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL,
                        "CL_TYPE_POSIX_TAR", NULL);
    ck_assert_msg(ret == CL_ERESOURCE,
                  "TAR temporary limit returned %s (%d)", cl_strerror(ret), ret);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_cpio_time_limit_is_fail_visible)
{
    enum { CPIO_OLD, CPIO_ODC, CPIO_NEWC, CPIO_CRC, CPIO_FORMATS };
    static const uint8_t data[] = {0};
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;
    int format;

    memset(&engine, 0, sizeof(engine));
    for (format = 0; format < CPIO_FORMATS; format++) {
        memset(&ctx, 0, sizeof(ctx));
        map = cl_fmap_open_memory(data, sizeof(data));
        ck_assert_ptr_nonnull(map);
        ctx.engine = &engine;
        ctx.fmap   = map;
        ck_assert_int_eq(gettimeofday(&ctx.time_limit, NULL), 0);
        ctx.time_limit.tv_sec--;

        switch (format) {
            case CPIO_OLD:
                ret = cli_scancpio_old(&ctx);
                break;
            case CPIO_ODC:
                ret = cli_scancpio_odc(&ctx);
                break;
            case CPIO_NEWC:
                ret = cli_scancpio_newc(&ctx, 0);
                break;
            default:
                ret = cli_scancpio_newc(&ctx, 1);
                break;
        }

        ck_assert_int_eq(ret, CL_ETIMEOUT);
        ck_assert(ctx.scan_incomplete);
        ck_assert_str_eq(ctx.scan_incomplete_reason, "CPIO member traversal reached the configured time limit");
        ck_assert(map->dont_cache_flag);
        cl_fmap_close(map);
    }
}
END_TEST

START_TEST(test_cpio_truncated_header_is_fail_visible)
{
    static const char *const types[] = {
        "CL_TYPE_CPIO_OLD",
        "CL_TYPE_CPIO_ODC",
        "CL_TYPE_CPIO_NEWC",
        "CL_TYPE_CPIO_CRC"};
    static const uint8_t data[6] = {0};
    struct cl_scan_options options;
    struct cl_engine *scan_engine;
    size_t i;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);

    for (i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
        fmap_t *map;
        cl_verdict_t verdict = CL_VERDICT_STRONG_INDICATOR;
        const char *last_alert = "stale";
        uint64_t scanned       = UINT64_MAX;
        cl_error_t ret;

        map = cl_fmap_open_memory(data, sizeof(data));
        ck_assert_ptr_nonnull(map);
        ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                            scan_engine, &options, NULL, NULL, NULL, NULL, types[i], NULL);
        ck_assert_int_eq(ret, CL_EPARSE);
        ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
        ck_assert(last_alert == NULL);
        ck_assert(map->dont_cache_flag);
        cl_fmap_close(map);
    }

    cl_engine_free(scan_engine);
}
END_TEST

static const void *cpio_member_name_read_failure(fmap_t *map, size_t at, size_t len, int lock);
static const void *cpio_initial_read_failure(fmap_t *map, size_t at, size_t len, int lock);

START_TEST(test_cpio_member_name_read_failure_is_fail_visible)
{
    static const uint8_t data[118] = {
        [0] = '0', [1] = '7', [2] = '0', [3] = '7', [4] = '0', [5] = '1',
        [94] = '0', [95] = '0', [96] = '0', [97] = '0', [98] = '0', [99] = '0', [100] = '0', [101] = '8',
        [110] = 'p', [111] = 'a', [112] = 'y', [113] = 'l', [114] = 'o', [115] = 'a', [116] = 'd', [117] = '\0'};
    struct cl_scan_options options;
    struct cl_engine *scan_engine;
    fmap_t *map;
    cl_verdict_t verdict = CL_VERDICT_STRONG_INDICATOR;
    const char *last_alert = "stale";
    uint64_t scanned       = UINT64_MAX;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);

    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    map->need = cpio_member_name_read_failure;
    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL,
                        "CL_TYPE_CPIO_NEWC", NULL);
    ck_assert_int_eq(ret, CL_EREAD);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert_ptr_null(last_alert);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_cpio_impossible_next_header_is_parse_error)
{
    /* A valid newc header with a one-byte name advances past this deliberately
     * short map before the next header. The coordinate is impossible, so the
     * parser must report truncation rather than an fmap callback failure. */
    static const uint8_t data[111] = {
        [0]   = '0', [1] = '7', [2] = '0', [3] = '7', [4] = '0', [5] = '1',
        [54]  = '0', [55] = '0', [56] = '0', [57] = '0', [58] = '0', [59] = '0', [60] = '0', [61] = '0',
        [94]  = '0', [95] = '0', [96] = '0', [97] = '0', [98] = '0', [99] = '0', [100] = '0',
        [101] = '1',
        [110] = '\0'};
    struct cl_scan_options options;
    struct cl_engine *scan_engine;
    fmap_t *map;
    cl_verdict_t verdict = CL_VERDICT_STRONG_INDICATOR;
    const char *last_alert = "stale";
    uint64_t scanned       = UINT64_MAX;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);

    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL,
                        "CL_TYPE_CPIO_NEWC", NULL);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert_ptr_null(last_alert);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_cpio_initial_read_failure_is_read_error)
{
    static const uint8_t data[110] = {
        [0] = '0', [1] = '7', [2] = '0', [3] = '7', [4] = '0', [5] = '1'};
    struct cl_scan_options options;
    struct cl_engine *scan_engine;
    fmap_t *map;
    cl_verdict_t verdict = CL_VERDICT_STRONG_INDICATOR;
    const char *last_alert = "stale";
    uint64_t scanned       = UINT64_MAX;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);

    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    map->need = cpio_initial_read_failure;
    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL,
                        "CL_TYPE_CPIO_NEWC", NULL);
    ck_assert_int_eq(ret, CL_EREAD);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert_ptr_null(last_alert);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_iso_time_limit_is_fail_visible)
{
    static const uint8_t data[] = {0};
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine = &engine;
    ctx.fmap   = map;
    ck_assert_int_eq(gettimeofday(&ctx.time_limit, NULL), 0);
    ctx.time_limit.tv_sec--;

    ck_assert_int_eq(cli_scaniso(&ctx, 32768), CL_ETIMEOUT);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "ISO inspection reached the configured time limit");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_iso_truncated_directory_is_fail_visible)
{
    enum { ISO_OFFSET = 32768, ISO_DESCRIPTOR_BYTES = 2454 };
    uint8_t data[ISO_OFFSET + ISO_DESCRIPTOR_BYTES] = {0};
    struct cl_engine *scan_engine;
    struct cl_scan_options options;
    fmap_t *map;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    /* Provide the primary and following descriptor signatures, but point the
     * root directory record at a block beyond this truncated map. */
    data[ISO_OFFSET] = 1;
    memcpy(data + ISO_OFFSET + 1, "CD001", 5);
    data[ISO_OFFSET + 128] = 0x00;
    data[ISO_OFFSET + 129] = 0x08; /* 2048-byte logical blocks */
    data[ISO_OFFSET + 2048] = 0;
    memcpy(data + ISO_OFFSET + 2049, "CD001", 5);
    data[ISO_OFFSET + 157] = 0;
    data[ISO_OFFSET + 158] = 0xe8;
    data[ISO_OFFSET + 159] = 0x03; /* root directory block 1000 */
    data[ISO_OFFSET + 166] = 34;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);

    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;
    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL, "CL_TYPE_ISO9660", NULL);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

struct iso_volume_read_failure_state {
    const uint8_t *data;
    size_t length;
    off_t fail_offset;
};

static off_t iso_volume_read_failure_cb(void *handle, void *buf, size_t count, off_t offset)
{
    struct iso_volume_read_failure_state *state = handle;

    if (offset >= 0 && (uint64_t)offset <= (uint64_t)state->fail_offset &&
        count > (size_t)((uint64_t)state->fail_offset - (uint64_t)offset))
        return -1;
    if (offset < 0 || (uint64_t)offset >= state->length)
        return 0;
    if (count > state->length - (size_t)offset)
        count = state->length - (size_t)offset;
    memcpy(buf, state->data + (size_t)offset, count);
    return (off_t)count;
}

START_TEST(test_iso_volume_read_failure_is_fail_visible)
{
    enum { ISO_OFFSET = 32768, ISO_DESCRIPTOR_BYTES = 2454 };
    uint8_t data[ISO_OFFSET + ISO_DESCRIPTOR_BYTES] = {0};
    struct iso_volume_read_failure_state state;
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;

    data[ISO_OFFSET] = 1;
    memcpy(data + ISO_OFFSET + 1, "CD001", 5);
    data[ISO_OFFSET + 128] = 0x00;
    data[ISO_OFFSET + 129] = 0x08; /* 2048-byte logical blocks */

    state.data        = data;
    state.length      = sizeof(data);
    state.fail_offset = ISO_OFFSET;
    map                = cl_fmap_open_handle(&state, 0, state.length, iso_volume_read_failure_cb, 0);
    ck_assert_ptr_nonnull(map);

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    ctx.engine = &engine;
    ctx.fmap   = map;

    ck_assert_int_eq(cli_scaniso(&ctx, ISO_OFFSET), CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "ISO volume descriptor could not be read completely");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_iso_unsupported_extent_layouts_are_fail_visible)
{
    enum {
        ISO_OFFSET = 32768,
        ROOT_BLOCK  = 32,
        ROOT_OFFSET = ROOT_BLOCK * 2048,
        ISO_LENGTH  = ROOT_OFFSET + 2048
    };
    static const uint8_t flags[] = {1, 0x80};
    uint8_t data[ISO_LENGTH];
    struct cl_engine *scan_engine;
    struct cl_scan_options options;
    size_t i;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);

    for (i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
        fmap_t *map;
        cl_verdict_t verdict = CL_VERDICT_STRONG_INDICATOR;
        const char *last_alert = "stale";
        uint64_t scanned       = UINT64_MAX;
        cl_error_t ret;

        memset(data, 0, sizeof(data));
        data[ISO_OFFSET] = 1;
        memcpy(data + ISO_OFFSET + 1, "CD001", 5);
        data[ISO_OFFSET + 128] = 0x00;
        data[ISO_OFFSET + 129] = 0x08; /* 2048-byte logical blocks */
        data[ISO_OFFSET + 2048] = 0;
        memcpy(data + ISO_OFFSET + 2049, "CD001", 5);

        /* The primary root record points to a directory block in the map. */
        data[ISO_OFFSET + 156] = 34;
        data[ISO_OFFSET + 158] = ROOT_BLOCK;
        data[ISO_OFFSET + 166] = 34;

        /* The first child record is either interleaved or multi-extent. */
        data[ROOT_OFFSET] = 34;
        data[ROOT_OFFSET + 2] = ROOT_BLOCK + 1;
        data[ROOT_OFFSET + 10] = 1;
        data[ROOT_OFFSET + 25] = flags[i];
        data[ROOT_OFFSET + 26] = (flags[i] == 1) ? 1 : 0;
        data[ROOT_OFFSET + 32] = 1;
        data[ROOT_OFFSET + 33] = 'x';

        map = cl_fmap_open_memory(data, sizeof(data));
        ck_assert_ptr_nonnull(map);
        ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                            scan_engine, &options, NULL, NULL, NULL, NULL, "CL_TYPE_ISO9660", NULL);
        ck_assert_int_eq(ret, CL_EPARSE);
        ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
        ck_assert(last_alert == NULL);
        ck_assert(map->dont_cache_flag);
        cl_fmap_close(map);
    }

    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_iso_directory_coordinate_overflow_is_fail_visible)
{
    enum {
        ISO_OFFSET = 32768,
        ROOT_BLOCK  = 32,
        ROOT_OFFSET = ROOT_BLOCK * 2048,
        ISO_LENGTH  = ROOT_OFFSET + 2048
    };
    uint8_t data[ISO_LENGTH] = {0};
    struct cl_engine *scan_engine;
    struct cl_scan_options options;
    fmap_t *map;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);

    data[ISO_OFFSET] = 1;
    memcpy(data + ISO_OFFSET + 1, "CD001", 5);
    data[ISO_OFFSET + 128] = 0x00;
    data[ISO_OFFSET + 129] = 0x08; /* 2048-byte logical blocks */
    data[ISO_OFFSET + 2048] = 0;
    memcpy(data + ISO_OFFSET + 2049, "CD001", 5);
    data[ISO_OFFSET + 156] = 34;
    data[ISO_OFFSET + 158] = ROOT_BLOCK;
    data[ISO_OFFSET + 166] = 34;

    /* The child extent plus its one-block extended attribute length wraps a
     * 32-bit ISO block coordinate unless the parser rejects it first. */
    data[ROOT_OFFSET]      = 34;
    data[ROOT_OFFSET + 1]  = 1;
    data[ROOT_OFFSET + 2]  = 0xff;
    data[ROOT_OFFSET + 3]  = 0xff;
    data[ROOT_OFFSET + 4]  = 0xff;
    data[ROOT_OFFSET + 5]  = 0xff;
    data[ROOT_OFFSET + 10] = 1;
    data[ROOT_OFFSET + 32] = 1;
    data[ROOT_OFFSET + 33] = 'x';

    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;
    ret        = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                               scan_engine, &options, NULL, NULL, NULL, NULL,
                               "CL_TYPE_ISO9660", NULL);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_xar_truncated_header_is_fail_visible)
{
    uint8_t data[28] = {0};
    struct cl_scan_options options;
    struct cl_engine *scan_engine;
    fmap_t *map;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    data[0]  = 0x78;
    data[1]  = 0x61;
    data[2]  = 0x72;
    data[3]  = 0x21;
    data[5]  = sizeof(data); /* header reaches the end of the map */
    data[15] = 1;            /* non-empty compressed TOC is unavailable */
    data[23] = 1;
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL, "CL_TYPE_XAR", NULL);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_xar_time_limit_is_fail_visible)
{
    static const uint8_t data[] = {0};
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine = &engine;
    ctx.fmap   = map;
    ck_assert_int_eq(gettimeofday(&ctx.time_limit, NULL), 0);
    ctx.time_limit.tv_sec--;

    ret = cli_scanxar(&ctx);
    ck_assert_int_eq(ret, CL_ETIMEOUT);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "XAR inspection reached the configured time limit");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

static uint8_t *xar_test_make_archive_from_toc(const uint8_t *toc, size_t toc_length, size_t *data_length);

START_TEST(test_xar_invalid_file_metadata_is_fail_visible)
{
    static const uint8_t toc[] = "<?xml version=\"1.0\"?><xar><toc><file><data><offset>bad</offset><length>bad</length><size>bad</size></data></file></toc>";
    uint8_t *data;
    size_t data_length;
    struct cl_scan_options options;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    fmap_t *map;
    cl_error_t ret;

    data = xar_test_make_archive_from_toc(toc, sizeof(toc) - 1U, &data_length);
    ck_assert_ptr_nonnull(data);
    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);

    map = cl_fmap_open_memory(data, data_length);
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL, "CL_TYPE_XAR", NULL);
    ck_assert_msg(ret != CL_SUCCESS,
                  "XAR invalid file metadata was reported clean");
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
    free(data);
}
END_TEST

static void xar_test_write_be64(uint8_t *dst, uint64_t value)
{
    unsigned int i;

    for (i = 0; i < 8U; i++)
        dst[i] = (uint8_t)(value >> (56U - (8U * i)));
}

static uint8_t *xar_test_make_archive_from_toc(const uint8_t *toc, size_t toc_length, size_t *data_length)
{
    uLongf compressed_length;
    uint8_t *data;

    compressed_length = compressBound((uLong)toc_length);
    *data_length = sizeof(struct xar_header) + (size_t)compressed_length;
    data         = calloc(1, *data_length);
    if (data == NULL)
        return NULL;

    data[0] = 0x78;
    data[1] = 0x61;
    data[2] = 0x72;
    data[3] = 0x21;
    data[4] = 0;
    data[5] = sizeof(struct xar_header);
    xar_test_write_be64(data + 16, toc_length);
    if (compress(data + sizeof(struct xar_header), &compressed_length, toc, (uLong)toc_length) != Z_OK) {
        free(data);
        return NULL;
    }
    xar_test_write_be64(data + 8, compressed_length);
    *data_length = sizeof(struct xar_header) + (size_t)compressed_length;

    return data;
}

static uint8_t *xar_test_make_archive(size_t *data_length)
{
    static const uint8_t toc[] = "<?xml version=\"1.0\"?><xar><toc><file>";

    return xar_test_make_archive_from_toc(toc, sizeof(toc) - 1U, data_length);
}

START_TEST(test_xar_xml_reader_error_is_fail_visible)
{
    uint8_t *data;
    size_t data_length;
    struct cl_scan_options options;
    struct cl_engine *scan_engine;
    fmap_t *map;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    data = xar_test_make_archive(&data_length);
    ck_assert_ptr_nonnull(data);

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);

    map = cl_fmap_open_memory(data, data_length);
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL, "CL_TYPE_XAR", NULL);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
    free(data);
}
END_TEST

START_TEST(test_xar_toc_temporary_quota_is_fail_visible)
{
    uint8_t *data;
    size_t data_length;
    struct cl_scan_options options;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    fmap_t *map;
    cl_error_t ret;

    data = xar_test_make_archive(&data_length);
    ck_assert_ptr_nonnull(data);
    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_set_num(scan_engine, CL_ENGINE_MAX_TEMPORARY_SIZE, 4), CL_SUCCESS);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);

    map = cl_fmap_open_memory(data, data_length);
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL, "CL_TYPE_XAR", NULL);
    ck_assert_msg(ret == CL_ERESOURCE,
                  "XAR temporary limit returned %s (%d)", cl_strerror(ret), ret);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
    free(data);
}
END_TEST

START_TEST(test_xar_subdocument_temporary_quota_is_fail_visible)
{
    static const uint8_t toc[] = "<?xml version=\"1.0\"?><xar><subdoc><file/></subdoc><toc>";
    uint8_t *data;
    size_t data_length;
    struct cl_scan_options options;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    fmap_t *map;
    cl_error_t ret;

    data = xar_test_make_archive_from_toc(toc, sizeof(toc) - 1U, &data_length);
    ck_assert_ptr_nonnull(data);
    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    /* The TOC reservation fits, but the 7-byte <file/> subdocument cannot be
     * added while that reservation remains held through the XML walk. */
    ck_assert_int_eq(cl_engine_set_num(scan_engine, CL_ENGINE_MAX_TEMPORARY_SIZE,
                                       (long long)(sizeof(toc) - 1U + 6U)),
                     CL_SUCCESS);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);

    map = cl_fmap_open_memory(data, data_length);
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL, "CL_TYPE_XAR", NULL);
    ck_assert_msg(ret == CL_ERESOURCE,
                  "XAR subdocument temporary limit returned %s (%d)", cl_strerror(ret), ret);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
    free(data);
}
END_TEST

START_TEST(test_partition_parser_errors_are_fail_visible)
{
    static const uint8_t data[] = {0};
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_scan_layer_t layer;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));

#define ASSERT_PARTITION_FAILURE(scanner_call, layer_type)                              \
    do {                                                                                 \
        memset(&layer, 0, sizeof(layer));                                                \
        memset(&ctx, 0, sizeof(ctx));                                                    \
        map = cl_fmap_open_memory(data, sizeof(data));                                   \
        ck_assert_ptr_nonnull(map);                                                      \
        ctx.engine               = &engine;                                             \
        ctx.options              = &options;                                             \
        ctx.fmap                 = map;                                                  \
        ctx.this_layer_tmpdir    = tmpdir;                                               \
        ctx.recursion_stack      = &layer;                                               \
        ctx.recursion_stack_size = 1;                                                    \
        layer.type               = (layer_type);                                        \
        layer.size               = sizeof(data);                                         \
        layer.fmap               = map;                                                  \
        ret                      = (scanner_call);                                       \
        ck_assert_int_eq(ret, CL_EFORMAT);                                               \
        ck_assert(ctx.scan_incomplete);                                                 \
        ck_assert(map->dont_cache_flag);                                                 \
        cl_fmap_close(map);                                                              \
    } while (0)

    ASSERT_PARTITION_FAILURE(cli_scanmbr(&ctx, 512), CL_TYPE_MBR);
    ASSERT_PARTITION_FAILURE(cli_scanapm(&ctx), CL_TYPE_APM);
    ASSERT_PARTITION_FAILURE(cli_scangpt(&ctx, 512), CL_TYPE_GPT);

#undef ASSERT_PARTITION_FAILURE
}
END_TEST

static const void *partition_boot_record_read_failure(fmap_t *map, size_t at, size_t len, int lock);

START_TEST(test_mbr_partition_read_failure_is_fail_visible)
{
    uint8_t data[1024] = {0};
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_scan_layer_t layer;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&layer, 0, sizeof(layer));
    memset(&ctx, 0, sizeof(ctx));
    engine.maxpartitions    = 1;
    options.parse            = CL_SCAN_PARSE_ARCHIVE;
    map                      = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    map->need                = partition_boot_record_read_failure;
    ctx.engine               = &engine;
    ctx.options              = &options;
    ctx.fmap                 = map;
    ctx.recursion_stack      = &layer;
    ctx.recursion_stack_size = 1;
    layer.type               = CL_TYPE_MBR;
    layer.size               = sizeof(data);
    layer.fmap               = map;

    ret = cli_scanmbr(&ctx, 512);
    ck_assert_int_eq(ret, CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "MBR master boot record could not be read completely");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_gpt_partition_read_failure_is_fail_visible)
{
    uint8_t data[6 * 512] = {0};
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_scan_layer_t layer;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&layer, 0, sizeof(layer));
    memset(&ctx, 0, sizeof(ctx));
    engine.maxpartitions    = 1;
    options.parse            = CL_SCAN_PARSE_ARCHIVE;
    map                      = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    map->need                = partition_boot_record_read_failure;
    ctx.engine               = &engine;
    ctx.options              = &options;
    ctx.fmap                 = map;
    ctx.recursion_stack      = &layer;
    ctx.recursion_stack_size = 1;
    layer.type               = CL_TYPE_GPT;
    layer.size               = sizeof(data);
    layer.fmap               = map;

    ret = cli_scangpt(&ctx, 512);
    ck_assert_int_eq(ret, CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "GPT protective MBR could not be read completely");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_mbr_partition_limit_is_fail_visible)
{
    uint8_t data[1024] = {0};
    struct cl_scan_options options;
    struct cl_engine *scan_engine;
    fmap_t *map;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    /* A valid MBR with one non-empty partition, while MaxPartitions=0 must
     * not report clean after skipping that partition. */
    data[446 + 4] = 0x83; /* Linux partition type. */
    cli_writeint32(data + 446 + 8, 1); /* first LBA */
    cli_writeint32(data + 446 + 12, 1); /* number of LBAs */
    data[510] = 0x55;
    data[511] = 0xaa;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_set_num(scan_engine, CL_ENGINE_MAX_PARTITIONS, 0), CL_SUCCESS);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL, "CL_TYPE_MBR", NULL);
    ck_assert_int_eq(ret, CL_EMAXFILES);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_apm_partition_limit_is_fail_visible)
{
    uint8_t data[1024] = {0};
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_scan_layer_t layer;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    /* A valid two-block Apple partition map, while MaxPartitions=0, must not
     * report success after skipping the declared partition entries. */
    data[0] = 0x45;
    data[1] = 0x52; /* DDM signature: "ER". */
    data[2] = 0x02;
    data[3] = 0x00; /* 512-byte blocks. */
    data[4] = 0x00;
    data[5] = 0x00;
    data[6] = 0x00;
    data[7] = 0x02; /* two blocks in the image. */
    data[512] = 0x50;
    data[513] = 0x4d; /* APM signature: "PM". */
    data[516] = 0x00;
    data[517] = 0x00;
    data[518] = 0x00;
    data[519] = 0x02; /* partition map plus one declared partition. */
    memcpy(data + 512 + 48, "Apple_partition_map", 19);

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&layer, 0, sizeof(layer));
    memset(&ctx, 0, sizeof(ctx));
    engine.maxpartitions     = 0;
    options.parse             = CL_SCAN_PARSE_ARCHIVE;
    map                       = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine                = &engine;
    ctx.options               = &options;
    ctx.fmap                  = map;
    ctx.this_layer_tmpdir     = tmpdir;
    ctx.recursion_stack       = &layer;
    ctx.recursion_stack_size  = 1;
    layer.type                = CL_TYPE_APM;
    layer.size                = sizeof(data);
    layer.fmap                = map;

    ret = cli_scanapm(&ctx);
    ck_assert_int_eq(ret, CL_EMAXFILES);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_apm_invalid_partition_is_fail_visible)
{
    uint8_t data[1536] = {0};
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_scan_layer_t layer;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    /* The map header and partition entry are readable, but the declared
     * partition begins beyond the image. It must not be skipped as clean. */
    data[0] = 0x45;
    data[1] = 0x52; /* DDM signature: "ER". */
    data[2] = 0x02;
    data[3] = 0x00; /* 512-byte blocks. */
    data[4] = 0x00;
    data[5] = 0x00;
    data[6] = 0x00;
    data[7] = 0x03; /* three blocks in the image. */
    data[512] = 0x50;
    data[513] = 0x4d; /* APM signature: "PM". */
    data[516] = 0x00;
    data[517] = 0x00;
    data[518] = 0x00;
    data[519] = 0x02; /* partition map plus one declared partition. */
    memcpy(data + 512 + 48, "Apple_partition_map", 19);
    data[1024] = 0x50;
    data[1025] = 0x4d; /* partition entry signature: "PM". */
    data[1028] = 0x00;
    data[1029] = 0x00;
    data[1030] = 0x00;
    data[1031] = 0x03; /* first block is beyond the three-block image. */
    data[1032] = 0x00;
    data[1033] = 0x00;
    data[1034] = 0x00;
    data[1035] = 0x01; /* one block. */

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&layer, 0, sizeof(layer));
    memset(&ctx, 0, sizeof(ctx));
    engine.maxpartitions    = 2;
    options.parse            = CL_SCAN_PARSE_ARCHIVE;
    map                      = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine               = &engine;
    ctx.options              = &options;
    ctx.fmap                 = map;
    ctx.this_layer_tmpdir    = tmpdir;
    ctx.recursion_stack      = &layer;
    ctx.recursion_stack_size = 1;
    layer.type               = CL_TYPE_APM;
    layer.size               = sizeof(data);
    layer.fmap               = map;

    ret = cli_scanapm(&ctx);
    ck_assert_int_eq(ret, CL_EFORMAT);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

static const void *apm_partition_read_failure(fmap_t *map, size_t at, size_t len, int lock);

START_TEST(test_apm_partition_read_failure_is_fail_visible)
{
    uint8_t data[1536] = {0};
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_scan_layer_t layer;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    /* The driver map and partition-map header are readable, but the first
     * declared partition entry fails in-range in the fmap callback. */
    data[0] = 0x45;
    data[1] = 0x52; /* DDM signature: "ER". */
    data[2] = 0x02;
    data[3] = 0x00; /* 512-byte blocks. */
    data[4] = 0x00;
    data[5] = 0x00;
    data[6] = 0x00;
    data[7] = 0x03; /* three blocks in the image. */
    data[512] = 0x50;
    data[513] = 0x4d; /* APM signature: "PM". */
    data[516] = 0x00;
    data[517] = 0x00;
    data[518] = 0x00;
    data[519] = 0x02; /* partition map plus one declared partition. */
    memcpy(data + 512 + 48, "Apple_partition_map", 19);

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&layer, 0, sizeof(layer));
    memset(&ctx, 0, sizeof(ctx));
    engine.maxpartitions    = 2;
    options.parse            = CL_SCAN_PARSE_ARCHIVE;
    map                      = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    map->need                = apm_partition_read_failure;
    ctx.engine               = &engine;
    ctx.options              = &options;
    ctx.fmap                 = map;
    ctx.this_layer_tmpdir    = tmpdir;
    ctx.recursion_stack      = &layer;
    ctx.recursion_stack_size = 1;
    layer.type               = CL_TYPE_APM;
    layer.size               = sizeof(data);
    layer.fmap               = map;

    ret = cli_scanapm(&ctx);
    ck_assert_int_eq(ret, CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "APM partition entry could not be read completely");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

static void write_test_le64(uint8_t *data, uint64_t value)
{
    cli_writeint32(data, (uint32_t)value);
    cli_writeint32(data + sizeof(uint32_t), (uint32_t)(value >> 32));
}

START_TEST(test_gpt_invalid_partition_is_fail_visible)
{
    uint8_t data[6 * 512] = {0};
    uint8_t *primary = data + 512;
    uint8_t *table = data + 2 * 512;
    uint8_t *secondary = data + 5 * 512;
    uint32_t table_crc;
    uint32_t header_crc;
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_scan_layer_t layer;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    /* Protective MBR. */
    data[446 + 4] = MBR_PROTECTIVE;
    cli_writeint32(data + 446 + 8, 1);
    cli_writeint32(data + 446 + 12, 5);
    data[510] = 0x55;
    data[511] = 0xaa;

    /* One non-empty partition whose last LBA exceeds the usable range. */
    table[0] = 1;
    write_test_le64(table + 32, 3);
    write_test_le64(table + 40, 5);
    table_crc = (uint32_t)crc32(0L, table, sizeof(struct gpt_partition_entry));

    memcpy(primary, GPT_SIGNATURE_STR, 8);
    cli_writeint32(primary + 8, 0x00010000U);
    cli_writeint32(primary + 12, sizeof(struct gpt_header));
    write_test_le64(primary + 24, 1);
    write_test_le64(primary + 32, 5);
    write_test_le64(primary + 40, 3);
    write_test_le64(primary + 48, 4);
    write_test_le64(primary + 72, 2);
    cli_writeint32(primary + 80, 1);
    cli_writeint32(primary + 84, sizeof(struct gpt_partition_entry));
    cli_writeint32(primary + 88, table_crc);
    header_crc = (uint32_t)crc32(0L, primary, sizeof(struct gpt_header));
    cli_writeint32(primary + 16, header_crc);

    memcpy(secondary, primary, sizeof(struct gpt_header));
    write_test_le64(secondary + 24, 5);
    write_test_le64(secondary + 32, 1);
    cli_writeint32(secondary + 16, 0);
    header_crc = (uint32_t)crc32(0L, secondary, sizeof(struct gpt_header));
    cli_writeint32(secondary + 16, header_crc);

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&layer, 0, sizeof(layer));
    memset(&ctx, 0, sizeof(ctx));
    engine.maxpartitions    = 1;
    options.parse            = CL_SCAN_PARSE_ARCHIVE;
    map                      = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine               = &engine;
    ctx.options              = &options;
    ctx.fmap                 = map;
    ctx.this_layer_tmpdir    = tmpdir;
    ctx.recursion_stack      = &layer;
    ctx.recursion_stack_size = 1;
    layer.type               = CL_TYPE_GPT;
    layer.size               = sizeof(data);
    layer.fmap               = map;

    ret = cli_scangpt(&ctx, 512);
    ck_assert_int_eq(ret, CL_EFORMAT);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

static const void *hwp3_docinfo_read_failure(fmap_t *map, size_t at, size_t len, int lock)
{
    (void)lock;
    if (at == 30U)
        return NULL;
    if (len == 0 || at > map->len || len > map->len - at)
        return NULL;
    return (const uint8_t *)map->data + at;
}

START_TEST(test_hwp3_parser_errors_are_fail_visible)
{
    uint8_t data[1000] = {0};
    cli_ctx ctx;
    struct cl_scan_options options;
    fmap_t *map;
    cl_error_t ret;

    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    memset(&ctx, 0, sizeof(ctx));
    memset(&options, 0, sizeof(options));
    ctx.fmap = map;
    ctx.options = &options;

    /* The HWP3 identity and document-info sections fit, but the required
     * 1008-byte document-summary section is truncated. */
    ret = cli_scanhwp3(&ctx);
    ck_assert_msg(ret == CL_EPARSE || ret == CL_EREAD,
                  "truncated HWP3 returned unexpected error %d", ret);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_hwp3_time_limit_is_fail_visible)
{
    static const uint8_t data[] = {0};
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine = &engine;
    ctx.fmap   = map;
    ck_assert_int_eq(gettimeofday(&ctx.time_limit, NULL), 0);
    ctx.time_limit.tv_sec--;

    ret = cli_scanhwp3(&ctx);
    ck_assert_int_eq(ret, CL_ETIMEOUT);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "HWP3 inspection reached the configured time limit");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_hwp3_information_block_length_is_fail_visible)
{
    enum {
        HWP3_INFO_OFFSET = 30 + 128 + 1008 + (7 * 2) + 2 + 43,
        HWP3_IMAGE_INFO_LENGTH = 31,
        HWP3_BACKGROUND_INFO_LENGTH = 323
    };
    static const uint8_t info_ids[]       = {1, 6};
    static const uint32_t info_lengths[]  = {HWP3_IMAGE_INFO_LENGTH, HWP3_BACKGROUND_INFO_LENGTH};
    uint8_t data[HWP3_INFO_OFFSET + 8 + HWP3_BACKGROUND_INFO_LENGTH] = {0};
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;
    size_t i;

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    engine.maxrechwp3 = 100;

    /* A zeroed HWP3 content stream ends its paragraph list immediately. The
     * following image-information blocks declare less than their fixed
     * 32-byte and 324-byte preambles; no underflowed nested range may be
     * attempted. */
    for (i = 0; i < sizeof(info_ids) / sizeof(info_ids[0]); i++) {
        memset(data, 0, sizeof(data));
        memset(&ctx, 0, sizeof(ctx));
        data[HWP3_INFO_OFFSET]     = info_ids[i];
        data[HWP3_INFO_OFFSET + 4] = (uint8_t)info_lengths[i];

        map = cl_fmap_open_memory(data, HWP3_INFO_OFFSET + 8 + info_lengths[i]);
        ck_assert_ptr_nonnull(map);
        ctx.engine  = &engine;
        ctx.options = &options;
        ctx.fmap = map;

        ret = cli_scanhwp3(&ctx);
        ck_assert_int_eq(ret, CL_EFORMAT);
        ck_assert(ctx.scan_incomplete);
        ck_assert(map->dont_cache_flag);

        cl_fmap_close(map);
    }
}
END_TEST

START_TEST(test_hwp3_document_info_read_failure_is_fail_visible)
{
    uint8_t data[30 + 128 + 1008] = {0};
    cli_ctx ctx;
    struct cl_scan_options options;
    fmap_t *map;
    cl_error_t ret;

    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    map->need = hwp3_docinfo_read_failure;
    memset(&ctx, 0, sizeof(ctx));
    memset(&options, 0, sizeof(options));
    ctx.fmap = map;
    ctx.options = &options;

    ret = cli_scanhwp3(&ctx);
    ck_assert_int_eq(ret, CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "HWP3 document-info could not be read completely");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_onenote_dispatch_honors_document_dconf)
{
    static const uint8_t malformed[] = {0, 0, 0, 0, 0, 0, 0, 0};
    struct cl_scan_options options;
    struct cl_engine *scan_engine;
    cl_fmap_t *map;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ONENOTE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);

    /* The parser must be skipped when both dynamic-configuration bits are
     * disabled, even though the ordinary ScanOneNote parse option is
     * requested. */
    scan_engine->dconf->archive &= ~ARCH_CONF_SIS;
    scan_engine->dconf->doc &= ~DOC_CONF_ONENOTE;
    map = cl_fmap_open_memory(malformed, sizeof(malformed));
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;
    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL,
                        "CL_TYPE_ONENOTE", NULL);
    ck_assert_int_eq(ret, CL_SUCCESS);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(!map->dont_cache_flag);
    cl_fmap_close(map);

    /* The archive bit is intentionally enabled alone. It must not dispatch
     * OneNote, because ARCH_CONF_SIS and DOC_CONF_ONENOTE are independent
     * dynamic-configuration words despite sharing the same numeric bit. */
    scan_engine->dconf->archive |= ARCH_CONF_SIS;
    map = cl_fmap_open_memory(malformed, sizeof(malformed));
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;
    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL,
                        "CL_TYPE_ONENOTE", NULL);
    ck_assert_int_eq(ret, CL_SUCCESS);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(!map->dont_cache_flag);
    cl_fmap_close(map);

    /* Enabling only the document bit must dispatch the parser and preserve
     * its malformed-input failure instead of silently falling through clean. */
    scan_engine->dconf->archive &= ~ARCH_CONF_SIS;
    scan_engine->dconf->doc |= DOC_CONF_ONENOTE;
    map = cl_fmap_open_memory(malformed, sizeof(malformed));
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;
    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL,
                        "CL_TYPE_ONENOTE", NULL);
    ck_assert_msg(ret != CL_SUCCESS, "enabled OneNote parser returned clean");
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);
    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_hwp3_truncated_raw_deflate_is_fail_visible)
{
    enum {
        HWP3_CONTENT_OFFSET = 30 + 128 + 1008,
        CONTENT_LENGTH       = 16384
    };
    uint8_t content[CONTENT_LENGTH];
    uint8_t *compressed;
    size_t compressed_length;
    uint8_t *data;
    size_t data_length;
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;
    size_t i;

    for (i = 0; i < sizeof(content); i++)
        content[i] = (uint8_t)((i * 19U) ^ (i >> 2));
    compressed = zip_stream_raw_deflate(content, sizeof(content), &compressed_length);
    ck_assert_msg(compressed_length > 1U, "HWP raw-deflate fixture unexpectedly short");
    data_length = HWP3_CONTENT_OFFSET + compressed_length - 1U;
    data        = calloc(1, data_length);
    ck_assert_ptr_nonnull(data);
    data[30 + 124] = 1U; /* HWP3 document-info compression flag. */
    memcpy(data + HWP3_CONTENT_OFFSET, compressed, compressed_length - 1U);

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, data_length);
    ck_assert_ptr_nonnull(map);
    ctx.engine            = &engine;
    ctx.options           = &options;
    ctx.fmap              = map;
    ctx.this_layer_tmpdir = tmpdir;

    ret = cli_scanhwp3(&ctx);
    ck_assert_int_eq(ret, CL_EUNPACK);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    free(data);
    free(compressed);
}
END_TEST

START_TEST(test_hwp3_password_protection_is_fail_visible)
{
    uint8_t data[30 + 128 + 1008] = {0};
    cli_ctx ctx;
    struct cl_scan_options options;
    fmap_t *map;
    cl_error_t ret;

    /* HWP3 document-info begins after the 30-byte identity section. The
     * password flag is a little-endian 16-bit value at document-info offset
     * 96; the complete document summary lets the parser reach that decision. */
    data[30 + 96] = 1;

    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    memset(&ctx, 0, sizeof(ctx));
    memset(&options, 0, sizeof(options));
    ctx.fmap = map;
    ctx.options = &options;

    ret = cli_scanhwp3(&ctx);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_7z_truncated_header_is_fail_visible)
{
    static const uint8_t data[] = {0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c};
    struct cl_scan_options options;
    fmap_t *map;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL, "CL_TYPE_7Z", NULL);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_7z_read_failure_is_fail_visible)
{
    uint8_t data[34] = {0};
    struct cl_scan_options options;
    fmap_t *map;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    memcpy(data, "7z\xbc\xaf'\x1c", 6);
    data[6] = 0;
    data[7] = 4;
    zip_stream_write_u64(data + 12, 0U);
    zip_stream_write_u64(data + 20, 2U);
    data[32] = 0x01;
    data[33] = 0x00;
    zip_stream_write_u32(data + 28, (uint32_t)crc32(0L, data + 32, 2U));

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    zip_targeted_read_failure_offset = 32U;
    map->need = zip_targeted_read_failure;
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL, "CL_TYPE_7Z", NULL);
    ck_assert_int_eq(ret, CL_EREAD);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
    zip_targeted_read_failure_offset = 0;
}
END_TEST

START_TEST(test_7z_output_size_mismatch_is_fail_visible)
{
    static const uint8_t data[] = "7-Zip output-size regression";
    char *path = NULL;
    int fd = -1;

    ck_assert_int_eq(cli_gentempfd(tmpdir, &path, &fd), CL_SUCCESS);
    ck_assert_ptr_nonnull(path);
    ck_assert_int_eq(write(fd, data, sizeof(data) - 1), (ssize_t)(sizeof(data) - 1));
    ck_assert(cli_7z_output_matches_declared(fd, sizeof(data) - 1, sizeof(data) - 1));
    ck_assert(!cli_7z_output_matches_declared(fd, sizeof(data), sizeof(data) - 1));
    ck_assert(!cli_7z_output_matches_declared(fd, sizeof(data) - 1, sizeof(data)));

    ck_assert_int_eq(close(fd), 0);
    ck_assert_int_eq(cli_unlink(path), 0);
    free(path);
}
END_TEST

START_TEST(test_7z_time_limit_is_fail_visible)
{
    static const uint8_t data[] = {0};
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine = &engine;
    ctx.fmap   = map;
    ck_assert_int_eq(gettimeofday(&ctx.time_limit, NULL), 0);
    ctx.time_limit.tv_sec--;

    ret = cli_7unz(&ctx, 0);
    ck_assert_int_eq(ret, CL_ETIMEOUT);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "7-Zip inspection reached the configured time limit");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_egg_sfx_header_admission)
{
    static const uint8_t valid_header[] = {
        0x45, 0x47, 0x47, 0x41, /* EGG_HEADER_MAGIC */
        0x00, 0x01,             /* EGG_HEADER_VERSION */
        0x01, 0x00, 0x00, 0x00, /* nonzero header id */
        0x00, 0x00, 0x00, 0x00  /* reserved */
    };
    uint8_t unsupported[sizeof(valid_header)];
    uint8_t malformed[sizeof(valid_header)];
    fmap_t *map;

    map = cl_fmap_open_memory(valid_header, sizeof(valid_header));
    ck_assert_ptr_nonnull(map);
    ck_assert_int_eq(cli_egg_header_check(map, 0), CL_SUCCESS);
    cl_fmap_close(map);

    map = cl_fmap_open_memory(valid_header, 4);
    ck_assert_ptr_nonnull(map);
    ck_assert_int_eq(cli_egg_header_check(map, 0), CL_EFORMAT);
    cl_fmap_close(map);

    memcpy(unsupported, valid_header, sizeof(unsupported));
    unsupported[4] = 0x01;
    map = cl_fmap_open_memory(unsupported, sizeof(unsupported));
    ck_assert_ptr_nonnull(map);
    ck_assert_int_eq(cli_egg_header_check(map, 0), CL_EPARSE);
    cl_fmap_close(map);

    memcpy(malformed, valid_header, sizeof(malformed));
    malformed[6] = 0;
    map = cl_fmap_open_memory(malformed, sizeof(malformed));
    ck_assert_ptr_nonnull(map);
    ck_assert_int_eq(cli_egg_header_check(map, 0), CL_EPARSE);
    cl_fmap_close(map);
}
END_TEST

typedef struct {
    uint8_t *buffer;
    size_t capacity;
    size_t length;
} egg_test_output;

static cl_error_t egg_test_capture(void *opaque, const void *data, size_t length)
{
    egg_test_output *output = (egg_test_output *)opaque;

    if (output == NULL || data == NULL || output->length > output->capacity ||
        length > output->capacity - output->length)
        return CL_EWRITE;

    memcpy(output->buffer + output->length, data, length);
    output->length += length;
    return CL_SUCCESS;
}

START_TEST(test_egg_lzma_stream_extracts_bounded_member)
{
    static const uint8_t lzma_data[] = {
        0x5d, 0x00, 0x00, 0x01, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x22, 0x91, 0xec, 0x40, 0x4c, 0x2e,
        0x68, 0xa0, 0x4e, 0x9c, 0x2a, 0x28, 0xa5, 0x56, 0xcc, 0x2d,
        0x60, 0xcd, 0x9e, 0xff, 0xff, 0xb6, 0x74, 0x00, 0x00};
    static const uint8_t expected[] = "EGG LZMA stream";
    uint8_t archive[128];
    uint8_t decoded[sizeof(expected) - 1U];
    egg_test_output output;
    fmap_t *map;
    void *handle = NULL;
    char **comments = NULL;
    uint32_t ncomments = 0;
    const char *filename = NULL;
    uint64_t output_length = 0;
    size_t offset = 0;

    memset(archive, 0, sizeof(archive));
    zip_stream_write_u32(archive + offset, 0x41474745U);
    offset += 4;
    zip_stream_write_u16(archive + offset, 0x0100U);
    offset += 2;
    zip_stream_write_u32(archive + offset, 1U);
    offset += 4;
    zip_stream_write_u32(archive + offset, 0U);
    offset += 4;
    zip_stream_write_u32(archive + offset, 0x08E28222U);
    offset += 4;

    zip_stream_write_u32(archive + offset, 0x0A8590E3U);
    offset += 4;
    zip_stream_write_u32(archive + offset, 1U);
    offset += 4;
    zip_stream_write_u64(archive + offset, sizeof(expected) - 1U);
    offset += 8;
    zip_stream_write_u32(archive + offset, 0x0A8591ACU);
    offset += 4;
    archive[offset++] = 0;
    zip_stream_write_u16(archive + offset, 8U);
    offset += 2;
    memcpy(archive + offset, "test.txt", 8);
    offset += 8;
    zip_stream_write_u32(archive + offset, 0x08E28222U);
    offset += 4;

    zip_stream_write_u32(archive + offset, 0x02B50C13U);
    offset += 4;
    archive[offset++] = 4;
    archive[offset++] = 0;
    zip_stream_write_u32(archive + offset, sizeof(expected) - 1U);
    offset += 4;
    zip_stream_write_u32(archive + offset, sizeof(lzma_data));
    offset += 4;
    zip_stream_write_u32(archive + offset, 0U);
    offset += 4;
    zip_stream_write_u32(archive + offset, 0x08E28222U);
    offset += 4;
    memcpy(archive + offset, lzma_data, sizeof(lzma_data));
    offset += sizeof(lzma_data);
    zip_stream_write_u32(archive + offset, 0x08E28222U);
    offset += 4;
    ck_assert(offset <= sizeof(archive));

    memset(&output, 0, sizeof(output));
    output.buffer   = decoded;
    output.capacity = sizeof(decoded);
    map             = cl_fmap_open_memory(archive, offset);
    ck_assert_ptr_nonnull(map);

    ck_assert_int_eq(cli_egg_open(map, &handle, &comments, &ncomments), CL_SUCCESS);
    ck_assert_int_eq(cli_egg_extract_file_stream(handle, egg_test_capture, &output,
                                                 &filename, &output_length),
                     CL_SUCCESS);
    ck_assert_str_eq(filename, "test.txt");
    ck_assert_uint_eq(output_length, sizeof(expected) - 1U);
    ck_assert_uint_eq(output.length, sizeof(expected) - 1U);
    ck_assert_mem_eq(output.buffer, expected, sizeof(expected) - 1U);

    free((void *)filename);
    cli_egg_close(handle);
    cl_fmap_close(map);
}
END_TEST

START_TEST(test_egg_time_limit_is_fail_visible)
{
    static const uint8_t data[] = {0};
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    void *handle = NULL;
    char **comments = NULL;
    uint32_t ncomments = 0;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine = &engine;
    ctx.fmap   = map;
    ck_assert_int_eq(gettimeofday(&ctx.time_limit, NULL), 0);
    ctx.time_limit.tv_sec--;

    ret = cli_egg_open_ex(map, &handle, &comments, &ncomments, &ctx);
    ck_assert_int_eq(ret, CL_ETIMEOUT);
    ck_assert_ptr_null(handle);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "EGG traversal reached the configured time limit");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_egg_extra_field_admission_is_fail_visible)
{
    static const uint8_t valid_header[] = {
        0x45, 0x47, 0x47, 0x41, /* EGG_HEADER_MAGIC */
        0x00, 0x01,             /* EGG_HEADER_VERSION */
        0x01, 0x00, 0x00, 0x00, /* nonzero header id */
        0x00, 0x00, 0x00, 0x00  /* reserved */
    };
    uint8_t archive[sizeof(valid_header) + 4 + 4 + 1 + 2];
    uint8_t file_archive[sizeof(valid_header) + 4 + 16 + 4 + 1 + 4];
    fmap_t *map;
    void *handle = NULL;
    char **comments = NULL;
    uint32_t ncomments = 0;
    size_t offset;

    memset(archive, 0, sizeof(archive));
    memcpy(archive, valid_header, sizeof(valid_header));
    offset = sizeof(valid_header);
    zip_stream_write_u32(archive + offset, 0x08D1470FU);
    offset += 4;
    archive[offset++] = 0;
    zip_stream_write_u16(archive + offset, 0);

    map = cl_fmap_open_memory(archive, sizeof(archive));
    ck_assert_ptr_nonnull(map);
    ck_assert_int_eq(cli_egg_open(map, &handle, &comments, &ncomments), CL_EFORMAT);
    ck_assert_ptr_null(handle);
    cl_fmap_close(map);

    memset(file_archive, 0, sizeof(file_archive));
    memcpy(file_archive, valid_header, sizeof(valid_header));
    offset = sizeof(valid_header);
    zip_stream_write_u32(file_archive + offset, 0x08E28222U);
    offset += 4;
    zip_stream_write_u32(file_archive + offset, 0x0A8590E3U);
    offset += 4;
    zip_stream_write_u32(file_archive + offset, 1U);
    offset += 4;
    zip_stream_write_u64(file_archive + offset, 0U);
    offset += 8;
    zip_stream_write_u32(file_archive + offset, 0x08D1470FU);
    offset += 4;
    file_archive[offset++] = 0;
    zip_stream_write_u16(file_archive + offset, 0);

    map = cl_fmap_open_memory(file_archive, sizeof(file_archive));
    ck_assert_ptr_nonnull(map);
    handle    = NULL;
    comments  = NULL;
    ncomments = 0;
    ck_assert_int_eq(cli_egg_open(map, &handle, &comments, &ncomments), CL_EFORMAT);
    ck_assert_ptr_null(handle);
    cl_fmap_close(map);

    memset(archive, 0, sizeof(archive));
    memcpy(archive, valid_header, sizeof(valid_header));
    offset = sizeof(valid_header);
    zip_stream_write_u32(archive + offset, 0x08D1470FU);
    offset += 4;
    archive[offset++] = 1;
    zip_stream_write_u32(archive + offset, UINT32_MAX);

    map = cl_fmap_open_memory(archive, sizeof(archive));
    ck_assert_ptr_nonnull(map);
    handle    = NULL;
    comments  = NULL;
    ncomments = 0;
    ck_assert_int_eq(cli_egg_open(map, &handle, &comments, &ncomments), CL_EMAXSIZE);
    ck_assert_ptr_null(handle);
    cl_fmap_close(map);

    memset(file_archive, 0, sizeof(file_archive));
    memcpy(file_archive, valid_header, sizeof(valid_header));
    offset = sizeof(valid_header);
    zip_stream_write_u32(file_archive + offset, 0x08E28222U);
    offset += 4;
    zip_stream_write_u32(file_archive + offset, 0x0A8590E3U);
    offset += 4;
    zip_stream_write_u32(file_archive + offset, 1U);
    offset += 4;
    zip_stream_write_u64(file_archive + offset, 0U);
    offset += 8;
    zip_stream_write_u32(file_archive + offset, 0x08D1470FU);
    offset += 4;
    file_archive[offset++] = 1;
    zip_stream_write_u32(file_archive + offset, UINT32_MAX);

    map = cl_fmap_open_memory(file_archive, sizeof(file_archive));
    ck_assert_ptr_nonnull(map);
    handle    = NULL;
    comments  = NULL;
    ncomments = 0;
    ck_assert_int_eq(cli_egg_open(map, &handle, &comments, &ncomments), CL_EMAXSIZE);
    ck_assert_ptr_null(handle);
    cl_fmap_close(map);
}
END_TEST

START_TEST(test_autoit_ea06_missing_member_is_fail_visible)
{
    uint8_t data[25];
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(data, 0, sizeof(data));
    data[0] = 0x36;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine            = &engine;
    ctx.fmap              = map;
    ctx.this_layer_tmpdir = tmpdir;

    ret = cli_scanautoit(&ctx, 0);
    ck_assert_int_eq(ret, CL_EFORMAT);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "AutoIt EA06 member header has invalid magic");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_embedded_candidate_admission_headers)
{
    static const uint8_t autoit_prefix[] = {
        0xa3, 0x48, 0x4b, 0xbe, 0x98, 0x6c, 0x4a, 0xa9,
        0x99, 0x4c, 0x53, 0x0a, 0x86, 0xd6, 0x48, 0x7d,
        0x41, 0x55, 0x33, 0x21, 0x45, 0x41, 0x30,
    };
    uint8_t nsis[0x54d];
    uint8_t autoit[40];
    uint8_t ishield[14 + 0x20];
    static const uint8_t pdf[] = "%PDF-1.7";
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_ctx ctx;
    fmap_t *map;

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&ctx, 0, sizeof(ctx));
    ctx.engine  = &engine;
    ctx.options = &options;

    memset(nsis, 0, sizeof(nsis));
    nsis[0]    = 0xef;
    nsis[1]    = 0xbe;
    nsis[2]    = 0xad;
    nsis[3]    = 0xde;
    cli_writeint32(nsis + 0x14, 0x1105);
    cli_writeint32(nsis + 0x18, sizeof(nsis));
    map        = cl_fmap_open_memory(nsis, sizeof(nsis));
    ck_assert_ptr_nonnull(map);
    ctx.fmap = map;
    ck_assert_int_eq(cli_nulsft_header_check(&ctx, 0), CL_SUCCESS);
    cl_fmap_close(map);

    cli_writeint32(nsis + 0x18, sizeof(nsis) + 1);
    map        = cl_fmap_open_memory(nsis, sizeof(nsis));
    ck_assert_ptr_nonnull(map);
    ctx.fmap = map;
    ck_assert_int_eq(cli_nulsft_header_check(&ctx, 0), CL_EPARSE);
    cl_fmap_close(map);

    memset(autoit, 0, sizeof(autoit));
    memcpy(autoit, autoit_prefix, sizeof(autoit_prefix));
    autoit[sizeof(autoit_prefix)] = 0x35;
    map                            = cl_fmap_open_memory(autoit, sizeof(autoit));
    ck_assert_ptr_nonnull(map);
    ctx.fmap = map;
    ck_assert_int_eq(cli_autoit_header_check(&ctx, 0), CL_SUCCESS);
    cl_fmap_close(map);

    map = cl_fmap_open_memory(autoit, sizeof(autoit_prefix) + 1);
    ck_assert_ptr_nonnull(map);
    ctx.fmap = map;
    ck_assert_int_eq(cli_autoit_header_check(&ctx, 0), CL_EPARSE);
    cl_fmap_close(map);

    memset(ishield, 0, sizeof(ishield));
    memcpy(ishield, "InstallShield\0", 14);
    map = cl_fmap_open_memory(ishield, sizeof(ishield));
    ck_assert_ptr_nonnull(map);
    ctx.fmap = map;
    ck_assert_int_eq(cli_ishield_msi_header_check(&ctx, 0), CL_SUCCESS);
    cl_fmap_close(map);

    map = cl_fmap_open_memory(ishield, 14 + 0x1f);
    ck_assert_ptr_nonnull(map);
    ctx.fmap = map;
    ck_assert_int_eq(cli_ishield_msi_header_check(&ctx, 0), CL_EPARSE);
    cl_fmap_close(map);

    map = cl_fmap_open_memory(pdf, sizeof(pdf) - 1);
    ck_assert_ptr_nonnull(map);
    ck_assert_int_eq(cli_pdf_header_check(map, 0), CL_SUCCESS);
    cl_fmap_close(map);

    map = cl_fmap_open_memory("%PDF-2.7", 8);
    ck_assert_ptr_nonnull(map);
    ck_assert_int_eq(cli_pdf_header_check(map, 0), CL_EPARSE);
    cl_fmap_close(map);
}
END_TEST

START_TEST(test_parser_temporary_directory_failures_are_fail_visible)
{
    static const uint8_t input[] = {0x35};
    char invalid_tmpdir[PATH_MAX];
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;

    ck_assert_msg(snprintf(invalid_tmpdir, sizeof(invalid_tmpdir), "%s/parser-temp-root-does-not-exist", tmpdir) < (int)sizeof(invalid_tmpdir),
                  "temporary directory test path was truncated");

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    ctx.engine            = &engine;
    ctx.this_layer_tmpdir = invalid_tmpdir;

    map = cl_fmap_open_memory(input, sizeof(input));
    ck_assert_ptr_nonnull(map);
    ctx.fmap = map;
    ck_assert_int_eq(cli_scanautoit(&ctx, 0), CL_ETMPDIR);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "AutoIt temporary directory could not be created");
    ck_assert(map->dont_cache_flag);
    cl_fmap_close(map);

    memset(&ctx, 0, sizeof(ctx));
    ctx.engine            = &engine;
    ctx.this_layer_tmpdir = invalid_tmpdir;
    map                   = cl_fmap_open_memory(input, sizeof(input));
    ck_assert_ptr_nonnull(map);
    ctx.fmap = map;
    ck_assert_int_eq(cli_scannulsft(&ctx, 0), CL_ETMPDIR);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "NSIS temporary directory could not be created");
    ck_assert(map->dont_cache_flag);
    cl_fmap_close(map);
}
END_TEST

static const void *embedded_header_read_failure(fmap_t *map, size_t at, size_t len, int lock)
{
    (void)map;
    (void)at;
    (void)len;
    (void)lock;
    return NULL;
}

static const void *riff_chunk_read_failure(fmap_t *map, size_t at, size_t len, int lock)
{
    (void)lock;
    if (at == 12U)
        return NULL;
    if (len == 0 || at > map->len || len > map->len - at)
        return NULL;
    return (const uint8_t *)map->data + at;
}

static const void *hfsplus_catalog_header_read_failure(fmap_t *map, size_t at, size_t len, int lock)
{
    (void)lock;
    if (at == (8U * 512U))
        return NULL;
    if (len == 0 || at > map->len || len > map->len - at)
        return NULL;
    return (const uint8_t *)map->data + at;
}

static const void *hfsplus_fork_read_failure(fmap_t *map, size_t at, size_t len, int lock)
{
    (void)lock;
    if (at == (30U * 512U))
        return NULL;
    if (len == 0 || at > map->len || len > map->len - at)
        return NULL;
    return (const uint8_t *)map->data + at;
}

static const void *hfsplus_catalog_node_read_failure(fmap_t *map, size_t at, size_t len, int lock)
{
    (void)lock;
    if (at == (9U * 512U))
        return NULL;
    if (len == 0 || at > map->len || len > map->len - at)
        return NULL;
    return (const uint8_t *)map->data + at;
}

static const void *apm_partition_read_failure(fmap_t *map, size_t at, size_t len, int lock)
{
    (void)lock;
    if (at == 1024U)
        return NULL;
    if (len == 0 || at > map->len || len > map->len - at)
        return NULL;
    return (const uint8_t *)map->data + at;
}

static const void *partition_boot_record_read_failure(fmap_t *map, size_t at, size_t len, int lock)
{
    (void)lock;
    if (at == 446U)
        return NULL;
    if (len == 0 || at > map->len || len > map->len - at)
        return NULL;
    return (const uint8_t *)map->data + at;
}

static const void *elf_program_header_read_failure(fmap_t *map, size_t at, size_t len, int lock)
{
    (void)lock;
    if (at == 64U)
        return NULL;
    if (len == 0 || at > map->len || len > map->len - at)
        return NULL;
    return (const uint8_t *)map->data + at;
}

static const void *macho_load_command_read_failure(fmap_t *map, size_t at, size_t len, int lock)
{
    (void)lock;
    if (at == 32U)
        return NULL;
    if (len == 0 || at > map->len || len > map->len - at)
        return NULL;
    return (const uint8_t *)map->data + at;
}

/* The checked-in PE fixture's first import thunk is at this raw file offset.
 * Allow every other memory window so the scan reaches the thunk-table read. */
#define PE_TEST_IMPORT_DESCRIPTOR_OFFSET 0x126e00U
#define PE_TEST_IMPORT_DLL_NAME_OFFSET   0x1274bcU
#define PE_TEST_IMPORT_FUNCTION_OFFSET   0x127066U
#define PE_TEST_IMPORT_THUNK_OFFSET      0x126e3cU

struct pe_native_offset_map_state {
    const uint8_t *data;
    size_t length;
    size_t source_offset;
};

static const void *pe_native_offset_map_need(fmap_t *map, size_t at, size_t len, int lock)
{
    struct pe_native_offset_map_state *state = map->handle;
    size_t absolute;
    size_t relative;

    (void)lock;
    if (NULL == state || len == 0 || at > map->len || len > map->len - at ||
        at > SIZE_MAX - map->nested_offset)
        return NULL;

    absolute = map->nested_offset + at;
    if (absolute < state->source_offset)
        return NULL;

    relative = absolute - state->source_offset;
    if (relative > state->length || len > state->length - relative)
        return NULL;

    return state->data + relative;
}

static const void *pe_import_thunk_read_failure(fmap_t *map, size_t at, size_t len, int lock)
{
    (void)lock;
    if (at == PE_TEST_IMPORT_THUNK_OFFSET)
        return NULL;
    if (len == 0 || at > map->len || len > map->len - at)
        return NULL;
    return (const uint8_t *)map->data + at;
}

static size_t pe_petite_section_read_offset;

static const void *pe_petite_section_read_failure(fmap_t *map, size_t at, size_t len, int lock)
{
    (void)lock;
    if (at == pe_petite_section_read_offset)
        return NULL;
    if (len == 0 || at > map->len || len > map->len - at)
        return NULL;
    return (const uint8_t *)map->data + at;
}

static const void *fmap_gets_read_failure(fmap_t *map, char *dst, size_t *at, size_t max_len)
{
    (void)map;
    (void)dst;
    (void)at;
    (void)max_len;
    return NULL;
}

static const void *cpio_member_name_read_failure(fmap_t *map, size_t at, size_t len, int lock)
{
    (void)lock;
    if (at == 110U)
        return NULL;
    if (len == 0 || at > map->len || len > map->len - at)
        return NULL;
    return (const uint8_t *)map->data + at;
}

static const void *cpio_initial_read_failure(fmap_t *map, size_t at, size_t len, int lock)
{
    (void)lock;
    if (at == 0)
        return NULL;
    if (len == 0 || at > map->len || len > map->len - at)
        return NULL;
    return (const uint8_t *)map->data + at;
}

static const void *tnef_attribute_read_failure(fmap_t *map, size_t at, size_t len, int lock)
{
    (void)lock;
    if (at == sizeof(uint32_t) + sizeof(uint16_t))
        return NULL;
    if (len == 0 || at > map->len || len > map->len - at)
        return NULL;
    return (const uint8_t *)map->data + at;
}

static const void *gif_version_read_failure(fmap_t *map, size_t at, size_t len, int lock)
{
    (void)lock;
    if (at == strlen("GIF"))
        return NULL;
    if (len == 0 || at > map->len || len > map->len - at)
        return NULL;
    return (const uint8_t *)map->data + at;
}

static const void *jpeg_required_read_failure(fmap_t *map, size_t at, size_t len, int lock)
{
    (void)lock;
    if (at == 0U)
        return NULL;
    if (len == 0 || at > map->len || len > map->len - at)
        return NULL;
    return (const uint8_t *)map->data + at;
}

START_TEST(test_embedded_header_read_failures_are_fail_visible)
{
    static const uint8_t pdf[] = "%PDF-1.7";
    static const uint8_t arj[] = {0x60, 0xea, 0x22, 0x00};
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    size_t archive_size = 0;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    ctx.engine = &engine;

    map = cl_fmap_open_memory(pdf, sizeof(pdf) - 1);
    ck_assert_ptr_nonnull(map);
    map->need = embedded_header_read_failure;
    ck_assert_int_eq(cli_pdf_header_check(map, 0), CL_EREAD);
    cl_fmap_close(map);

    map = cl_fmap_open_memory(arj, sizeof(arj));
    ck_assert_ptr_nonnull(map);
    map->need = embedded_header_read_failure;
    ctx.fmap = map;
    ret      = cli_unarj_header_check(&ctx, 0, &archive_size);
    ck_assert_int_eq(ret, CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);
    cl_fmap_close(map);
}
END_TEST

START_TEST(test_pdf_parser_read_failure_is_fail_visible)
{
    static const uint8_t input[] = "%PDF-1.7\n";
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&ctx, 0, sizeof(ctx));
    ctx.engine            = &engine;
    ctx.options           = &options;
    ctx.this_layer_tmpdir = tmpdir;

    map = cl_fmap_open_memory(input, sizeof(input) - 1U);
    ck_assert_ptr_nonnull(map);
    map->need = embedded_header_read_failure;
    ctx.fmap  = map;

    ret = cli_pdf(tmpdir, &ctx, 0);
    ck_assert_int_eq(ret, CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "PDF parser version window could not be read completely");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_binhex_encoded_read_failure_is_fail_visible)
{
    static const uint8_t input[] = "nonempty BinHex input";
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    ctx.engine            = &engine;
    ctx.this_layer_tmpdir = tmpdir;

    map = cl_fmap_open_memory(input, sizeof(input) - 1U);
    ck_assert_ptr_nonnull(map);
    map->need = embedded_header_read_failure;
    ctx.fmap  = map;

    ret = cli_binhex(&ctx);
    ck_assert_int_eq(ret, CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason,
                     "BinHex encoded input could not be read completely");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_file_type_detection_read_failure_is_fail_visible)
{
    static const uint8_t input[] = "file typing read failure";
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_scan_layer_t layer;
    cli_ctx ctx;
    fmap_t *map;

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&layer, 0, sizeof(layer));
    memset(&ctx, 0, sizeof(ctx));
    engine.dboptions         = CL_DB_COMPILED;
    ctx.engine               = &engine;
    ctx.options              = &options;
    ctx.recursion_stack      = &layer;
    ctx.recursion_stack_size = 1;

    map = cl_fmap_open_memory(input, sizeof(input) - 1U);
    ck_assert_ptr_nonnull(map);
    map->need = embedded_header_read_failure;
    layer.fmap = map;
    ctx.fmap   = map;

    ck_assert_int_eq(cli_magic_scan(&ctx, CL_TYPE_ANY), CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason,
                     "file type detection could not read the input completely");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_mydoom_detector_read_failure_is_fail_visible)
{
    static const uint8_t input[8 * 4 * 2] = {0};
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    ctx.engine = &engine;

    map = cl_fmap_open_memory(input, sizeof(input));
    ck_assert_ptr_nonnull(map);
    map->need = embedded_header_read_failure;
    ctx.fmap = map;

    ck_assert_int_eq(cli_check_mydoom_log(&ctx), CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason,
                     "Mydoom log detector input window could not be read completely");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_riff_header_read_failure_is_fail_visible)
{
    static const uint8_t input[] = {
        'R', 'I', 'F', 'F',
        0x00, 0x00, 0x00, 0x00,
        'A', 'C', 'O', 'N',
    };
    cli_ctx ctx;
    fmap_t *map;

    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(input, sizeof(input));
    ck_assert_ptr_nonnull(map);
    map->need = embedded_header_read_failure;
    ctx.fmap   = map;

    ck_assert_int_eq(cli_check_riff_exploit(&ctx), CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "RIFF header could not be read completely");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_riff_chunk_read_failure_is_fail_visible)
{
    static const uint8_t input[] = {
        'R', 'I', 'F', 'F',
        0x00, 0x00, 0x00, 0x00,
        'A', 'C', 'O', 'N',
        'a', 'n', 'i', 'h',
        0x24, 0x00, 0x00, 0x00,
    };
    cli_ctx ctx;
    fmap_t *map;

    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(input, sizeof(input));
    ck_assert_ptr_nonnull(map);
    map->need = riff_chunk_read_failure;
    ctx.fmap   = map;

    ck_assert_int_eq(cli_check_riff_exploit(&ctx), CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "RIFF chunk header was truncated");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_structured_detector_read_failure_is_fail_visible)
{
    static const uint8_t input[] = "structured detector read failure";
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_ctx ctx;
    fmap_t *map;

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&ctx, 0, sizeof(ctx));
    engine.min_cc_count = 1;
    options.heuristic   = CL_SCAN_HEURISTIC_STRUCTURED;
    ctx.engine           = &engine;
    ctx.options          = &options;

    map = cl_fmap_open_memory(input, sizeof(input) - 1);
    ck_assert_ptr_nonnull(map);
    map->need = embedded_header_read_failure;
    ctx.fmap   = map;

    ck_assert_int_eq(cli_scan_structured(&ctx), CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason,
                     "Structured data detector input could not be read completely");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_tnef_exact_eof_ends_attribute_list)
{
    static const uint8_t input[] = {
        0x78, 0x9f, 0x3e, 0x22, /* TNEF signature */
        0x00, 0x00              /* key, followed by exact EOF */
    };
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    ctx.engine            = &engine;
    ctx.this_layer_tmpdir = tmpdir;

    map = cl_fmap_open_memory(input, sizeof(input));
    ck_assert_ptr_nonnull(map);
    ctx.fmap = map;

    ck_assert_int_eq(cli_tnef(tmpdir, &ctx), CL_CLEAN);
    ck_assert(!ctx.scan_incomplete);
    ck_assert(!map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_tnef_time_limit_is_fail_visible)
{
    static const uint8_t data[] = {0};
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine = &engine;
    ctx.fmap   = map;
    ck_assert_int_eq(gettimeofday(&ctx.time_limit, NULL), 0);
    ctx.time_limit.tv_sec--;

    ret = cli_tnef(tmpdir, &ctx);
    ck_assert_int_eq(ret, CL_ETIMEOUT);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "TNEF inspection reached the configured time limit");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_tnef_initial_read_failure_is_fail_visible)
{
    static const uint8_t input[sizeof(uint32_t) + sizeof(uint16_t)] = {0};
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    ctx.engine            = &engine;
    ctx.this_layer_tmpdir = tmpdir;

    map = cl_fmap_open_memory(input, sizeof(input));
    ck_assert_ptr_nonnull(map);
    map->need = embedded_header_read_failure;
    ctx.fmap   = map;

    ck_assert_int_eq(cli_tnef(tmpdir, &ctx), CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason,
                     "TNEF signature could not be read completely");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_tnef_attribute_read_failure_is_fail_visible)
{
    static const uint8_t input[] = {
        0x78, 0x9f, 0x3e, 0x22, /* TNEF signature */
        0x00, 0x00,             /* key */
        0x01                    /* attribute level read is fault-injected */
    };
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    ctx.engine            = &engine;
    ctx.this_layer_tmpdir = tmpdir;

    map = cl_fmap_open_memory(input, sizeof(input));
    ck_assert_ptr_nonnull(map);
    map->need = tnef_attribute_read_failure;
    ctx.fmap   = map;

    ck_assert_int_eq(cli_tnef(tmpdir, &ctx), CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason,
                     "TNEF attribute header could not be read completely");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_uuencode_initial_read_failure_is_fail_visible)
{
    static const uint8_t input[] = "nonempty uuencode input";
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    ctx.engine = &engine;

    map = cl_fmap_open_memory(input, sizeof(input) - 1U);
    ck_assert_ptr_nonnull(map);
    map->gets = fmap_gets_read_failure;
    ctx.fmap = map;

    ck_assert_int_eq(cli_uuencode(&ctx, tmpdir, map), CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason,
                     "UUencoded input could not be read completely");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_uuencode_time_limit_is_fail_visible)
{
    static const uint8_t data[] = {0};
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine = &engine;
    ctx.fmap   = map;
    ck_assert_int_eq(gettimeofday(&ctx.time_limit, NULL), 0);
    ctx.time_limit.tv_sec--;

    ret = cli_uuencode(&ctx, tmpdir, map);
    ck_assert_int_eq(ret, CL_ETIMEOUT);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "UUencoded inspection reached the configured time limit");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_mbox_initial_read_failure_is_fail_visible)
{
    static const uint8_t input[] = "nonempty MIME input";
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    ctx.engine = &engine;

    map = cl_fmap_open_memory(input, sizeof(input) - 1U);
    ck_assert_ptr_nonnull(map);
    map->gets = fmap_gets_read_failure;
    ctx.fmap = map;

    ck_assert_int_eq(cli_mbox(tmpdir, &ctx), CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason,
                     "MIME message input could not be read completely");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_mbox_line_read_failure_is_fail_visible)
{
    static const uint8_t input[] = "P I legacy message\n\nbody";
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    ctx.engine = &engine;

    map = cl_fmap_open_memory(input, sizeof(input) - 1U);
    ck_assert_ptr_nonnull(map);
    map->need = embedded_header_read_failure;
    ctx.fmap = map;

    ck_assert_int_eq(cli_mbox(tmpdir, &ctx), CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason,
                     "MIME message line input could not be read completely");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_mbox_oversized_line_is_fail_visible)
{
    static const uint8_t prefix[] = "Content-Type: text/plain\nSubject: ";
    uint8_t input[2048];
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    size_t input_len = sizeof(prefix) - 1U;

    memcpy(input, prefix, input_len);
    memset(input + input_len, 'A', 1100U);
    input_len += 1100U;
    input[input_len++] = '\n';
    input[input_len++] = '\n';

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    ctx.engine            = &engine;
    ctx.this_layer_tmpdir = tmpdir;

    map = cl_fmap_open_memory(input, input_len);
    ck_assert_ptr_nonnull(map);

    ck_assert_int_eq(cli_mbox(tmpdir, &ctx), CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason,
                     "MIME message line exceeds bounded parser representation");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_mbox_truncated_uuencode_is_fail_visible)
{
    static const uint8_t data[] =
        "From sender@example.com Sat Jan  1 00:00:00 2022\n"
        "Subject: truncated uuencode\n"
        "\n"
        "begin 644 payload\n";
    struct cl_scan_options options;
    fmap_t *map;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_MAIL;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data) - 1);
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL, "CL_TYPE_MAIL", NULL);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_mbox_truncated_binhex_is_fail_visible)
{
    static const uint8_t data[] =
        "From sender@example.com Sat Jan  1 00:00:00 2022\n"
        "Subject: truncated BinHex\n"
        "Content-Type: application/mac-binhex40\n"
        "Content-Transfer-Encoding: x-binhex\n"
        "\n"
        "(This file must be converted with BinHex 4.0)\n"
        ":";
    struct cl_scan_options options;
    fmap_t *map;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_MAIL | CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data) - 1);
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL, "CL_TYPE_MAIL", NULL);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_fileblob_cleanup_failures_are_fail_visible)
{
    struct cl_engine *engine;
    cli_ctx ctx;
    fileblob *fb;

    engine = cl_engine_new();
    ck_assert_ptr_nonnull(engine);
    memset(&ctx, 0, sizeof(ctx));
    ctx.engine            = engine;
    ctx.this_layer_tmpdir = tmpdir;

    fb = fileblobCreate();
    ck_assert_ptr_nonnull(fb);
    fileblobSetCTX(fb, &ctx);
    fileblobSetFilename(fb, tmpdir, "cleanup-failure");
    ck_assert_ptr_nonnull(fb->fp);
    ck_assert_int_eq(close(fb->fd), 0);
    fileblobDestructiveDestroy(fb);
    ck_assert(ctx.scan_incomplete);

    cl_engine_free(engine);
}
END_TEST

START_TEST(test_tnef_truncated_header_is_fail_visible)
{
    const uint8_t data[7] = {
        0x78, 0x9f, 0x3e, 0x22, /* TNEF signature */
        0x00, 0x00,             /* key */
        0x01                      /* truncated attribute part */
    };
    struct cl_scan_options options;
    fmap_t *map;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_MAIL;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL, "CL_TYPE_TNEF", NULL);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_tnef_short_header_is_fail_visible)
{
    static const uint8_t data[4] = {0x78, 0x9f, 0x3e, 0x22};
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&ctx, 0, sizeof(ctx));
    options.parse = CL_SCAN_PARSE_MAIL;
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine            = &engine;
    ctx.options           = &options;
    ctx.fmap              = map;
    ctx.this_layer_tmpdir = tmpdir;

    ret = cli_tnef(tmpdir, &ctx);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_tnef_message_body_is_fail_visible)
{
    static const uint8_t data[] = {
        0x78, 0x9f, 0x3e, 0x22, /* TNEF signature */
        0x00, 0x00,             /* key */
        0x01,                   /* message level */
        0x0c, 0x80, 0x00, 0x00, /* attBODY, type 0 */
        0x05, 0x00, 0x00, 0x00, /* five-byte body */
        'h', 'e', 'l', 'l', 'o',
        0x00, 0x00 /* checksum */
    };
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&ctx, 0, sizeof(ctx));
    options.parse         = CL_SCAN_PARSE_MAIL;
    ctx.engine            = &engine;
    ctx.options           = &options;
    ctx.this_layer_tmpdir = tmpdir;
    map                   = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.fmap = map;

    ret = cli_tnef(tmpdir, &ctx);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_tnef_attachment_temporary_limit_is_fail_visible)
{
    static const uint8_t data[] = {
        0x78, 0x9f, 0x3e, 0x22, /* TNEF signature */
        0x00, 0x00,             /* key */
        0x02,                   /* attachment level */
        0x0f, 0x80, 0x00, 0x00, /* attachment data tag */
        0x05, 0x00, 0x00, 0x00, /* five-byte attachment */
        0x01, 0x02, 0x03, 0x04, 0x05,
        0x00, 0x00 /* checksum */
    };
    struct cl_engine *engine;
    struct cl_scan_options options;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    engine = cl_engine_new();
    ck_assert_ptr_nonnull(engine);
    ck_assert_int_eq(cl_engine_set_num(engine, CL_ENGINE_MAX_TEMPORARY_SIZE, 4), CL_SUCCESS);
    memset(&options, 0, sizeof(options));
    memset(&ctx, 0, sizeof(ctx));
    options.parse         = CL_SCAN_PARSE_MAIL;
    ctx.engine             = engine;
    ctx.options            = &options;
    ctx.this_layer_tmpdir = tmpdir;
    map                     = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.fmap = map;

    ret = cli_tnef(tmpdir, &ctx);
    ck_assert_int_eq(ret, CL_ERESOURCE);
    ck_assert(ctx.scan_incomplete);
    ck_assert_uint_eq(ctx.temporary_bytes, 0);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(engine);
}
END_TEST

START_TEST(test_ole2_truncated_property_tree_is_fail_visible)
{
    char file_path[PATH_MAX];
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_ctx ctx;
    fmap_t *map;
    struct uniq *files = NULL;
    cl_error_t ret;
    int fd;

    snprintf(file_path, sizeof(file_path), "%s/input/other_scanfiles/ole2_encryption/password.fat.xls", SRCDIR);
    fd = open(file_path, O_RDONLY | O_BINARY);
    ck_assert_msg(fd >= 0, "open(%s) failed: %s", file_path, strerror(errno));

    /* Keep the CFB header but truncate the property-sector map. The walker
     * must report the failed property read instead of treating it as clean. */
    map = fmap_new(fd, 0, 4096, file_path, NULL);
    ck_assert_ptr_nonnull(map);

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&ctx, 0, sizeof(ctx));
    ctx.options            = &options;
    ctx.engine             = &engine;
    ctx.fmap               = map;
    ctx.this_layer_tmpdir  = tmpdir;

    ret = cli_ole2_extract(tmpdir, &ctx, &files, NULL, NULL, NULL);
    ck_assert_msg(ret != CL_CLEAN, "truncated OLE2 property tree returned clean");
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);
    ck_assert_ptr_null(files);

    cl_fmap_close(map);
    close(fd);
}
END_TEST

START_TEST(test_ole2_truncated_header_is_fail_visible)
{
    static const uint8_t data[16] = {0};
    struct cl_scan_options options;
    fmap_t *map;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_OLE2;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL, "CL_TYPE_MSOLE2", NULL);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_ole2_header_read_failure_is_fail_visible)
{
    char file_path[PATH_MAX];
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_ctx ctx;
    fmap_t *map;
    struct uniq *files = NULL;
    cl_error_t ret;
    int fd;

    snprintf(file_path, sizeof(file_path), "%s/input/other_scanfiles/has_png_and_jpeg.xls", SRCDIR);
    fd = open(file_path, O_RDONLY | O_BINARY);
    ck_assert_msg(fd >= 0, "open(%s) failed: %s", file_path, strerror(errno));

    map = fmap_new(fd, 0, 0, file_path, NULL);
    ck_assert_ptr_nonnull(map);
    map->need = embedded_header_read_failure;

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&ctx, 0, sizeof(ctx));
    ctx.engine            = &engine;
    ctx.options           = &options;
    ctx.fmap              = map;
    ctx.this_layer_tmpdir = tmpdir;

    ret = cli_ole2_extract(tmpdir, &ctx, &files, NULL, NULL, NULL);
    ck_assert_int_eq(ret, CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "OLE2 header could not be read completely");
    ck_assert(map->dont_cache_flag);
    ck_assert_ptr_null(files);

    cl_fmap_close(map);
    close(fd);
}
END_TEST

START_TEST(test_ole2_invalid_block_geometry_is_fail_visible)
{
    static const uint8_t magic[] = {0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1};
    uint8_t data[512] = {0};
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_ctx ctx;
    fmap_t *map;
    struct uniq *files = NULL;
    cl_error_t ret;

    memcpy(data, magic, sizeof(magic));
    data[30] = 5;
    map      = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&ctx, 0, sizeof(ctx));
    ctx.engine            = &engine;
    ctx.options           = &options;
    ctx.fmap              = map;
    ctx.this_layer_tmpdir = tmpdir;

    ret = cli_ole2_extract(NULL, &ctx, &files, NULL, NULL, NULL);
    ck_assert_int_eq(ret, CL_EFORMAT);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "OLE2 big-block size exponent is invalid");
    ck_assert(map->dont_cache_flag);
    ck_assert_ptr_null(files);

    memset(&ctx, 0, sizeof(ctx));
    ctx.engine            = &engine;
    ctx.options           = &options;
    ctx.fmap              = map;
    ctx.this_layer_tmpdir = tmpdir;
    map->dont_cache_flag  = false;
    data[30]              = 9;
    data[32]              = 10;
    files                 = NULL;

    ret = cli_ole2_extract(NULL, &ctx, &files, NULL, NULL, NULL);
    ck_assert_int_eq(ret, CL_EFORMAT);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "OLE2 small-block size exponent is invalid");
    ck_assert(map->dont_cache_flag);
    ck_assert_ptr_null(files);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_xlm_missing_input_is_fail_visible)
{
    static const uint8_t parent_data[] = {0};
    char hash[] = "xlm-missing-input";
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    map = cl_fmap_open_memory(parent_data, sizeof(parent_data));
    ck_assert_ptr_nonnull(map);

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&ctx, 0, sizeof(ctx));
    ctx.engine             = &engine;
    ctx.options            = &options;
    ctx.fmap               = map;
    ctx.this_layer_tmpdir = tmpdir;

    ret = cli_extract_xlm_macros_and_images(tmpdir, &ctx, hash, 1);
    ck_assert_int_eq(ret, CL_EOPEN);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_xlm_truncated_record_header_is_fail_visible)
{
    static const uint8_t parent_data[] = {0};
    const uint8_t truncated_header[] = {0x06};
    char hash[] = "xlm-truncated-header";
    char file_path[PATH_MAX];
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;
    int fd;

    snprintf(file_path, sizeof(file_path), "%s/%s_1", tmpdir, hash);
    fd = open(file_path, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR);
    ck_assert_msg(fd >= 0, "open(%s) failed: %s", file_path, strerror(errno));
    ck_assert_int_eq(write(fd, truncated_header, sizeof(truncated_header)), (ssize_t)sizeof(truncated_header));
    ck_assert_int_eq(close(fd), 0);

    map = cl_fmap_open_memory(parent_data, sizeof(parent_data));
    ck_assert_ptr_nonnull(map);

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&ctx, 0, sizeof(ctx));
    ctx.engine             = &engine;
    ctx.options            = &options;
    ctx.fmap               = map;
    ctx.this_layer_tmpdir = tmpdir;

    ret = cli_extract_xlm_macros_and_images(tmpdir, &ctx, hash, 1);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    unlink(file_path);
}
END_TEST

START_TEST(test_xlm_temporary_output_limit_is_fail_visible)
{
    static const uint8_t parent_data[] = {0};
    char hash[] = "xlm-temporary-limit";
    char file_path[PATH_MAX];
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;
    int fd;

    snprintf(file_path, sizeof(file_path), "%s/%s_1", tmpdir, hash);
    fd = open(file_path, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR);
    ck_assert_msg(fd >= 0, "open(%s) failed: %s", file_path, strerror(errno));
    ck_assert_int_eq(close(fd), 0);

    map = cl_fmap_open_memory(parent_data, sizeof(parent_data));
    ck_assert_ptr_nonnull(map);

    memset(&engine, 0, sizeof(engine));
    engine.maxtemporarysize = 1;
    memset(&options, 0, sizeof(options));
    memset(&ctx, 0, sizeof(ctx));
    ctx.engine             = &engine;
    ctx.options            = &options;
    ctx.fmap               = map;
    ctx.this_layer_tmpdir = tmpdir;

    ret = cli_extract_xlm_macros_and_images(tmpdir, &ctx, hash, 1);
    ck_assert_int_eq(ret, CL_ERESOURCE);
    ck_assert(ctx.scan_incomplete);
    ck_assert_uint_eq(ctx.temporary_bytes, 0);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    unlink(file_path);
}
END_TEST

START_TEST(test_xlm_string_extensions_are_fail_visible)
{
    static const uint8_t parent_data[] = {0};
    static const uint8_t rich_string_record[] = {
        0x07, 0x02, /* OPC_STRING */
        0x06, 0x00, /* record length */
        0x01, 0x00, /* one ANSI character */
        0x08,       /* rich-string extension flag */
        0x01, 0x00, /* one formatting run */
        'X',
    };
    char hash[] = "xlm-string-extensions";
    char file_path[PATH_MAX];
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;
    int fd;

    snprintf(file_path, sizeof(file_path), "%s/%s_1", tmpdir, hash);
    fd = open(file_path, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR);
    ck_assert_msg(fd >= 0, "open(%s) failed: %s", file_path, strerror(errno));
    ck_assert_int_eq(write(fd, rich_string_record, sizeof(rich_string_record)),
                     (ssize_t)sizeof(rich_string_record));
    ck_assert_int_eq(close(fd), 0);

    map = cl_fmap_open_memory(parent_data, sizeof(parent_data));
    ck_assert_ptr_nonnull(map);

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&ctx, 0, sizeof(ctx));
    ctx.engine            = &engine;
    ctx.options           = &options;
    ctx.fmap              = map;
    ctx.this_layer_tmpdir = tmpdir;

    ret = cli_extract_xlm_macros_and_images(tmpdir, &ctx, hash, 1);
    ck_assert_int_eq(ret, CL_EUNPACK);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    unlink(file_path);
}
END_TEST

START_TEST(test_ole2_vba_materialization_failure_is_fail_visible)
{
    char file_path[PATH_MAX];
    char invalid_dir[PATH_MAX];
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_ctx ctx;
    fmap_t *map;
    struct uniq *files = NULL;
    cl_error_t ret;
    int fd;

    snprintf(file_path, sizeof(file_path), "%s/input/other_scanfiles/has_png_and_jpeg.xls", SRCDIR);
    snprintf(invalid_dir, sizeof(invalid_dir), "%s/ole2-materialization-output-does-not-exist", tmpdir);
    fd = open(file_path, O_RDONLY | O_BINARY);
    ck_assert_msg(fd >= 0, "open(%s) failed: %s", file_path, strerror(errno));

    map = fmap_new(fd, 0, 0, file_path, NULL);
    ck_assert_ptr_nonnull(map);

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&ctx, 0, sizeof(ctx));
    engine.maxfiles    = 0;
    ctx.options        = &options;
    ctx.engine         = &engine;
    ctx.fmap           = map;
    ctx.this_layer_tmpdir = tmpdir;

    ret = cli_ole2_extract(invalid_dir, &ctx, &files, NULL, NULL, NULL);
    ck_assert_msg(ret == CL_ECREAT, "OLE2 materialization returned %d", ret);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);
    ck_assert_ptr_null(files);

    cl_fmap_close(map);
    close(fd);
}
END_TEST

START_TEST(test_ole2_temporary_limit_is_fail_visible)
{
    char file_path[PATH_MAX];
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_ctx ctx;
    fmap_t *map;
    struct uniq *files = NULL;
    cl_error_t ret;
    int fd;

    snprintf(file_path, sizeof(file_path), "%s/input/other_scanfiles/has_png_and_jpeg.xls", SRCDIR);
    fd = open(file_path, O_RDONLY | O_BINARY);
    ck_assert_msg(fd >= 0, "open(%s) failed: %s", file_path, strerror(errno));

    map = fmap_new(fd, 0, 0, file_path, NULL);
    ck_assert_ptr_nonnull(map);
    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&ctx, 0, sizeof(ctx));
    engine.maxtemporarysize = 1;
    ctx.engine              = &engine;
    ctx.options             = &options;
    ctx.fmap                = map;
    ctx.this_layer_tmpdir   = tmpdir;

    ret = cli_ole2_extract(tmpdir, &ctx, &files, NULL, NULL, NULL);
    ck_assert_int_eq(ret, CL_ERESOURCE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);
    ck_assert_ptr_null(files);

    cl_fmap_close(map);
    close(fd);
}
END_TEST

START_TEST(test_ole2_time_limit_is_fail_visible)
{
    static const uint8_t data[] = {0};
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine = &engine;
    ctx.fmap   = map;
    ck_assert_int_eq(gettimeofday(&ctx.time_limit, NULL), 0);
    ctx.time_limit.tv_sec--;

    ret = cli_ole2_extract(tmpdir, &ctx, NULL, NULL, NULL, NULL);
    ck_assert_int_eq(ret, CL_ETIMEOUT);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "OLE2 inspection reached the configured time limit");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

#ifdef CLAMAV_TEST_JS_IO_WRAP
START_TEST(test_ole2_output_close_failure_is_fail_visible)
{
    const char *file = SRCDIR PATHSEP "input" PATHSEP "other_scanfiles" PATHSEP "has_png_and_jpeg.xls";
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_ctx ctx;
    fmap_t *map;
    struct uniq *files = NULL;
    cl_error_t ret;
    int fd;

    fd = open(file, O_RDONLY | O_BINARY);
    ck_assert_msg(fd >= 0, "open(%s) failed: %s", file, strerror(errno));
    map = fmap_new(fd, 0, 0, file, NULL);
    ck_assert_ptr_nonnull(map);

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&ctx, 0, sizeof(ctx));
    ctx.engine             = &engine;
    ctx.options            = &options;
    ctx.fmap               = map;
    ctx.this_layer_tmpdir  = tmpdir;

    clamav_test_fail_close = 1;
    ret = cli_ole2_extract(tmpdir, &ctx, &files, NULL, NULL, NULL);
    clamav_test_fail_close = 0;

    ck_assert_msg(ret != CL_SUCCESS, "OLE2 output close failure returned clean");
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);
    if (files)
        uniq_free(files);

    cl_fmap_close(map);
    close(fd);
}
END_TEST
#endif

#ifndef _WIN32
START_TEST(test_vba_inflate_seek_failure_is_fail_visible)
{
    int pipefd[2];
    unsigned char *data;
    size_t size = SIZE_MAX;

    ck_assert_int_eq(pipe(pipefd), 0);
    close(pipefd[1]);

    data = cli_vba_inflate(pipefd[0], 0, &size);
    close(pipefd[0]);

    ck_assert_ptr_null(data);
    ck_assert_uint_eq(size, 0);
}
END_TEST

START_TEST(test_word_macro_directory_truncation_is_fail_visible)
{
    char path[PATH_MAX];
    unsigned char fib[8] = {0x20, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_ctx ctx;
    fmap_t *map;
    int fd;
    static const uint8_t map_data[] = {0};

    snprintf(path, sizeof(path), "%s/word-macro-truncated", tmpdir);
    fd = open(path, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    ck_assert_int_ne(fd, -1);
    ck_assert_int_eq(ftruncate(fd, 0x121), 0);
    ck_assert_int_eq(pwrite(fd, fib, sizeof(fib), 0x118), (ssize_t)sizeof(fib));
    ck_assert_int_eq(lseek(fd, 0, SEEK_SET), 0);

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(map_data, sizeof(map_data));
    ck_assert_ptr_nonnull(map);
    ctx.engine  = &engine;
    ctx.options = &options;
    ctx.fmap    = map;

    ck_assert_ptr_null(cli_wm_readdir_ex(fd, &ctx));
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    close(fd);
    unlink(path);
}
END_TEST
#endif

static void dmg_test_write_be32(uint8_t *dst, uint32_t value)
{
    dst[0] = (uint8_t)(value >> 24);
    dst[1] = (uint8_t)(value >> 16);
    dst[2] = (uint8_t)(value >> 8);
    dst[3] = (uint8_t)value;
}

static void dmg_test_write_be64(uint8_t *dst, uint64_t value)
{
    unsigned int i;

    for (i = 0; i < 8U; i++)
        dst[i] = (uint8_t)(value >> (56U - 8U * i));
}

static uint8_t *dmg_test_image(const char *xml, size_t *image_length)
{
    uint8_t *image;
    size_t xml_length = strlen(xml);
    size_t total;
    size_t koly;

    ck_assert_msg(xml_length <= SIZE_MAX - sizeof(struct dmg_koly_block), "DMG test image overflow");
    total = xml_length + sizeof(struct dmg_koly_block);
    image = calloc(1, total);
    ck_assert_ptr_nonnull(image);
    memcpy(image, xml, xml_length);
    koly = total - sizeof(struct dmg_koly_block);
    dmg_test_write_be32(image + koly + offsetof(struct dmg_koly_block, magic), 0x6b6f6c79U);
    dmg_test_write_be64(image + koly + offsetof(struct dmg_koly_block, dataForkOffset), 0);
    dmg_test_write_be64(image + koly + offsetof(struct dmg_koly_block, dataForkLength), xml_length);
    dmg_test_write_be64(image + koly + offsetof(struct dmg_koly_block, xmlOffset), 0);
    dmg_test_write_be64(image + koly + offsetof(struct dmg_koly_block, xmlLength), xml_length);
    *image_length = total;
    return image;
}

static char *dmg_test_base64_encode(const uint8_t *input, size_t input_length)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t output_length;
    size_t in_pos = 0;
    size_t out_pos = 0;
    char *output;

    ck_assert_msg(input_length <= (SIZE_MAX / 4U) * 3U - 2U, "DMG Base64 test length overflow");
    output_length = ((input_length + 2U) / 3U) * 4U;
    output        = malloc(output_length + 1U);
    ck_assert_ptr_nonnull(output);

    while (in_pos < input_length) {
        size_t remaining = input_length - in_pos;
        uint32_t value   = (uint32_t)input[in_pos] << 16;

        if (remaining > 1U)
            value |= (uint32_t)input[in_pos + 1U] << 8;
        if (remaining > 2U)
            value |= input[in_pos + 2U];
        output[out_pos++] = alphabet[(value >> 18) & 0x3fU];
        output[out_pos++] = alphabet[(value >> 12) & 0x3fU];
        output[out_pos++] = remaining > 1U ? alphabet[(value >> 6) & 0x3fU] : '=';
        output[out_pos++] = remaining > 2U ? alphabet[value & 0x3fU] : '=';
        in_pos += MIN(remaining, 3U);
    }
    output[out_pos] = '\0';
    return output;
}

static char *dmg_test_mish_base64(const uint32_t *stripe_types, size_t stripe_count)
{
    uint8_t *mish;
    size_t mish_length;
    size_t i;
    char *base64;

    ck_assert_msg(stripe_count > 0 && stripe_count <= UINT32_MAX, "invalid DMG test stripe count");
    ck_assert_msg(stripe_count <= (SIZE_MAX - sizeof(struct dmg_mish_block)) / sizeof(struct dmg_block_data),
                  "DMG mish test length overflow");
    mish_length = sizeof(struct dmg_mish_block) + stripe_count * sizeof(struct dmg_block_data);
    mish        = calloc(1, mish_length);
    ck_assert_ptr_nonnull(mish);
    memcpy(mish, "mish", 4);
    dmg_test_write_be32(mish + offsetof(struct dmg_mish_block, version), 1);
    dmg_test_write_be32(mish + offsetof(struct dmg_mish_block, blockDataCount), (uint32_t)stripe_count);
    for (i = 0; i < stripe_count; i++) {
        size_t stripe_offset = sizeof(struct dmg_mish_block) + i * sizeof(struct dmg_block_data);

        dmg_test_write_be32(mish + stripe_offset + offsetof(struct dmg_block_data, type), stripe_types[i]);
    }
    base64 = dmg_test_base64_encode(mish, mish_length);
    free(mish);
    return base64;
}

static cl_error_t dmg_test_scan_data_body(const char *data_body, struct cl_engine *engine, int *scan_incomplete)
{
    static const char prefix[] =
        "<?xml version=\"1.0\"?><plist><dict><key>resource-fork</key><dict>"
        "<key>blkx</key><array><dict><key>Data</key><data>";
    static const char suffix[] = "</data></dict></array></dict></dict></plist>";
    struct cl_scan_options options;
    cli_scan_layer_t layers[4];
    cli_ctx ctx;
    cl_fmap_t *map;
    uint8_t *image;
    size_t image_length;
    size_t xml_length;
    char *xml;
    cl_error_t ret;

    ck_assert_msg(strlen(data_body) <= SIZE_MAX - sizeof(prefix) - sizeof(suffix), "DMG XML test length overflow");
    xml_length = sizeof(prefix) - 1U + strlen(data_body) + sizeof(suffix);
    xml        = malloc(xml_length);
    ck_assert_ptr_nonnull(xml);
    ck_assert_int_eq(snprintf(xml, xml_length, "%s%s%s", prefix, data_body, suffix), (int)(xml_length - 1U));

    memset(&options, 0, sizeof(options));
    memset(layers, 0, sizeof(layers));
    memset(&ctx, 0, sizeof(ctx));
    image = dmg_test_image(xml, &image_length);
    free(xml);
    map = cl_fmap_open_memory(image, image_length);
    ck_assert_ptr_nonnull(map);
    ctx.engine                 = engine;
    ctx.options                = &options;
    ctx.fmap                   = map;
    ctx.this_layer_tmpdir      = tmpdir;
    ctx.recursion_stack        = layers;
    ctx.recursion_stack_size   = 4;
    layers[0].type             = CL_TYPE_DMG;
    layers[0].size             = image_length;
    layers[0].fmap             = map;

    ret = cli_scandmg(&ctx);
    if (scan_incomplete)
        *scan_incomplete = ctx.scan_incomplete;
    cl_fmap_close(map);
    free(image);
    return ret;
}

START_TEST(test_dmg_strict_base64_and_terminal_end_validation)
{
    const uint32_t terminal_end[] = {DMG_STRIPE_END};
    const uint32_t missing_end[] = {DMG_STRIPE_SKIP};
    const uint32_t early_end[] = {DMG_STRIPE_END, DMG_STRIPE_SKIP};
    char *valid = dmg_test_mish_base64(terminal_end, 1);
    size_t valid_length = strlen(valid);
    char *body;
    char *bad;
    int incomplete;
    cl_error_t ret;
    struct cl_engine *engine;

    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    engine = cl_engine_new();
    ck_assert_ptr_nonnull(engine);
    ck_assert_int_eq(cl_engine_compile(engine), CL_SUCCESS);

    /* A valid value may be split between ordinary text and CDATA and may
     * contain XML whitespace between Base64 characters. */
    body = malloc(valid_length + sizeof(" \n<![CDATA[]]>\t"));
    ck_assert_ptr_nonnull(body);
    memcpy(body, " \n", 2);
    memcpy(body + 2, valid, valid_length / 2U);
    memcpy(body + 2 + valid_length / 2U, "<![CDATA[", 9);
    memcpy(body + 11 + valid_length / 2U, valid + valid_length / 2U, valid_length - valid_length / 2U);
    memcpy(body + 11 + valid_length, "]]>\t", 4);
    body[15 + valid_length] = '\0';
    incomplete              = 0;
    ret                     = dmg_test_scan_data_body(body, engine, &incomplete);
    ck_assert_msg(ret == CL_CLEAN, "valid split DMG Base64 returned %d", ret);
    ck_assert(!incomplete);
    free(body);

    bad = strdup(valid);
    ck_assert_ptr_nonnull(bad);
    bad[4] = '$';
    incomplete = 0;
    ret = dmg_test_scan_data_body(bad, engine, &incomplete);
    ck_assert_msg(ret != CL_CLEAN && ret != CL_VIRUS, "invalid-alphabet DMG Base64 returned %d", ret);
    ck_assert(incomplete);
    free(bad);

    bad = strdup(valid);
    ck_assert_ptr_nonnull(bad);
    bad[1] = '=';
    incomplete = 0;
    ret = dmg_test_scan_data_body(bad, engine, &incomplete);
    ck_assert_msg(ret != CL_CLEAN && ret != CL_VIRUS, "misplaced-padding DMG Base64 returned %d", ret);
    ck_assert(incomplete);
    free(bad);

    bad = strdup(valid);
    ck_assert_ptr_nonnull(bad);
    bad[valid_length - 1U] = '\0';
    incomplete = 0;
    ret = dmg_test_scan_data_body(bad, engine, &incomplete);
    ck_assert_msg(ret != CL_CLEAN && ret != CL_VIRUS, "incomplete-quartet DMG Base64 returned %d", ret);
    ck_assert(incomplete);
    free(bad);

    bad = malloc(valid_length + 2U);
    ck_assert_ptr_nonnull(bad);
    memcpy(bad, valid, valid_length);
    bad[valid_length]      = 'A';
    bad[valid_length + 1U] = '\0';
    incomplete             = 0;
    ret                    = dmg_test_scan_data_body(bad, engine, &incomplete);
    ck_assert_msg(ret != CL_CLEAN && ret != CL_VIRUS, "post-padding DMG Base64 suffix returned %d", ret);
    ck_assert(incomplete);
    free(bad);

    bad        = dmg_test_mish_base64(missing_end, 1);
    incomplete = 0;
    ret        = dmg_test_scan_data_body(bad, engine, &incomplete);
    ck_assert_msg(ret != CL_CLEAN && ret != CL_VIRUS, "DMG mish without END returned %d", ret);
    ck_assert(incomplete);
    free(bad);

    bad        = dmg_test_mish_base64(early_end, 2);
    incomplete = 0;
    ret        = dmg_test_scan_data_body(bad, engine, &incomplete);
    ck_assert_msg(ret != CL_CLEAN && ret != CL_VIRUS, "DMG mish with non-final END returned %d", ret);
    ck_assert(incomplete);
    free(bad);
    free(valid);
    cl_engine_free(engine);
}
END_TEST

START_TEST(test_dmg_malformed_metadata_is_fail_visible)
{
    static const char truncated_xml[] =
        "<?xml version=\"1.0\"?><plist><dict><key>resource-fork</key><dict>"
        "<key>blkx</key><array><dict><key>Data</key><data>AAAA";
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_scan_layer_t layers[2];
    cli_ctx ctx;
    cl_fmap_t *map;
    uint8_t *image;
    size_t image_length;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(layers, 0, sizeof(layers));
    memset(&ctx, 0, sizeof(ctx));
    image = dmg_test_image(truncated_xml, &image_length);
    map = cl_fmap_open_memory(image, image_length);
    ck_assert_ptr_nonnull(map);
    ctx.engine               = &engine;
    ctx.options              = &options;
    ctx.fmap                 = map;
    ctx.this_layer_tmpdir    = tmpdir;
    ctx.recursion_stack      = layers;
    ctx.recursion_stack_size = 2;
    layers[0].type           = CL_TYPE_DMG;
    layers[0].size           = image_length;
    layers[0].fmap           = map;

    ret = cli_scandmg(&ctx);
    ck_assert_msg(ret != CL_CLEAN && ret != CL_VIRUS,
                  "truncated DMG metadata returned %d", ret);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    free(image);

    image = calloc(1, sizeof(struct dmg_koly_block));
    ck_assert_ptr_nonnull(image);
    map = cl_fmap_open_memory(image, sizeof(struct dmg_koly_block));
    ck_assert_ptr_nonnull(map);
    memset(layers, 0, sizeof(layers));
    memset(&ctx, 0, sizeof(ctx));
    ctx.engine               = &engine;
    ctx.options              = &options;
    ctx.fmap                 = map;
    ctx.this_layer_tmpdir    = tmpdir;
    ctx.recursion_stack      = layers;
    ctx.recursion_stack_size = 2;
    layers[0].type           = CL_TYPE_DMG;
    layers[0].size           = sizeof(struct dmg_koly_block);
    layers[0].fmap           = map;

    ret = cli_scandmg(&ctx);
    ck_assert_msg(ret == CL_EPARSE, "truncated DMG without a complete koly trailer returned %d", ret);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    free(image);
}
END_TEST

START_TEST(test_dmg_trailer_read_failure_is_fail_visible)
{
    static const char xml[] = "<plist/>";
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_ctx ctx;
    fmap_t *map;
    uint8_t *image;
    size_t image_length;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&ctx, 0, sizeof(ctx));
    image = dmg_test_image(xml, &image_length);
    map = cl_fmap_open_memory(image, image_length);
    ck_assert_ptr_nonnull(map);
    zip_targeted_read_failure_offset = image_length - sizeof(struct dmg_koly_block);
    map->need = zip_targeted_read_failure;
    ctx.engine  = &engine;
    ctx.options = &options;
    ctx.fmap    = map;

    ret = cli_scandmg(&ctx);
    ck_assert_int_eq(ret, CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    free(image);
    zip_targeted_read_failure_offset = 0;
}
END_TEST

START_TEST(test_dmg_invalid_trailer_is_fail_visible)
{
    static const uint8_t data[1024] = {0};
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_scan_layer_t layers[2];
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(layers, 0, sizeof(layers));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine               = &engine;
    ctx.options              = &options;
    ctx.fmap                 = map;
    ctx.this_layer_tmpdir    = tmpdir;
    ctx.recursion_stack      = layers;
    ctx.recursion_stack_size = 2;
    layers[0].type           = CL_TYPE_DMG;
    layers[0].size           = sizeof(data);
    layers[0].fmap           = map;

    ret = cli_scandmg(&ctx);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

struct dmg_test_sparse_map {
    uint8_t trailer[sizeof(struct dmg_koly_block)];
    size_t logical_length;
};

static const void *dmg_test_sparse_need(fmap_t *map, size_t at, size_t length, int lock)
{
    struct dmg_test_sparse_map *state = map->handle;
    size_t trailer_offset;

    UNUSEDPARAM(lock);
    if (!state || state->logical_length < sizeof(state->trailer))
        return NULL;
    trailer_offset = state->logical_length - sizeof(state->trailer);
    if (at < trailer_offset || at > state->logical_length || length > state->logical_length - at)
        return NULL;
    return state->trailer + (at - trailer_offset);
}


#ifndef _WIN32
struct nested_copy_pread_state {
    uint8_t data[FILEBUFF * 32U];
    size_t fail_at;
    size_t max_request;
    unsigned int successful_reads;
};

static off_t nested_copy_pread_cb(void *handle, void *buf, size_t count, off_t offset)
{
    struct nested_copy_pread_state *state = handle;

    if (count > state->max_request)
        state->max_request = count;
    if (offset < 0 || (uint64_t)offset >= state->fail_at)
        return -1;
    if (count > state->fail_at - (size_t)offset)
        return -1;
    memcpy(buf, state->data + (size_t)offset, count);
    state->successful_reads++;
    return (off_t)count;
}

START_TEST(test_nested_fmap_ranges_and_force_to_disk_are_fail_visible)
{
    struct nested_copy_pread_state state;
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_scan_layer_t layer;
    cli_ctx ctx;
    cl_fmap_t *map;
    cl_error_t ret;

    memset(&state, 0, sizeof(state));
    memset(state.data, 0x5a, sizeof(state.data));
    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&layer, 0, sizeof(layer));
    memset(&ctx, 0, sizeof(ctx));
    state.fail_at          = FILEBUFF * 8U + 1U;
    state.max_request      = 0;
    engine.engine_options  = ENGINE_OPTIONS_FORCE_TO_DISK;
    ctx.engine             = &engine;
    ctx.options            = &options;
    ctx.this_layer_tmpdir  = tmpdir;
    ctx.recursion_stack    = &layer;
    ctx.recursion_stack_size = 1;

    map = cl_fmap_open_handle(&state, 0, sizeof(state.data), nested_copy_pread_cb, 1);
    ck_assert_ptr_nonnull(map);
    ctx.fmap   = map;
    layer.fmap = map;

    ret = cli_magic_scan_nested_fmap_type(map, sizeof(state.data) - 2U, 4U, &ctx,
                                          CL_TYPE_ANY, NULL, LAYER_ATTRIBUTES_NONE);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    ctx.scan_incomplete = false;
    map->dont_cache_flag = false;
    ret = cli_magic_scan_nested_fmap_type(map, 0, sizeof(state.data), &ctx,
                                          CL_TYPE_ANY, NULL, LAYER_ATTRIBUTES_NONE);
    ck_assert_int_eq(ret, CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "nested fmap could not be read completely while forcing it to disk");
    ck_assert(map->dont_cache_flag);
    ck_assert_msg(state.successful_reads != 0,
                  "force-to-disk copy attempted to materialize the entire nested range at once");

    /* Logical child admission must happen before a force-to-disk copy. */
    state.fail_at          = sizeof(state.data);
    state.successful_reads = 0;
    engine.maxfilesize     = sizeof(state.data) - 1U;
    ctx.scan_incomplete     = false;
    map->dont_cache_flag    = false;
    ret = cli_magic_scan_nested_fmap_type(map, 0, sizeof(state.data), &ctx,
                                          CL_TYPE_ANY, NULL, LAYER_ATTRIBUTES_NONE);
    ck_assert_int_eq(ret, CL_EMAXSIZE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);
    ck_assert_uint_eq(state.successful_reads, 0);

    engine.maxfilesize = 0;

    /* Temporary admission must happen before the force-to-disk copy. */
    state.fail_at             = sizeof(state.data);
    state.successful_reads    = 0;
    engine.maxtemporarysize   = sizeof(state.data) - 1U;
    ctx.scan_incomplete       = false;
    map->dont_cache_flag       = false;
    ret = cli_magic_scan_nested_fmap_type(map, 0, sizeof(state.data), &ctx,
                                          CL_TYPE_ANY, NULL, LAYER_ATTRIBUTES_NONE);
    ck_assert_int_eq(ret, CL_ERESOURCE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);
    ck_assert_uint_eq(state.successful_reads, 0);

    cl_fmap_close(map);
}
END_TEST

static void ishield_test_write_u64(uint8_t *dst, uint64_t value)
{
    unsigned int i;

    for (i = 0; i < 8U; i++)
        dst[i] = (uint8_t)(value >> (8U * i));
}

START_TEST(test_ishield_msi_partial_limit_and_decode_failures_are_visible)
{
    enum {
        ISHIELD_TEST_HEADER_SIZE = 0x20,
        ISHIELD_TEST_FILEBLOCK_SIZE = 312,
        ISHIELD_TEST_CSIZE_OFFSET = 268
    };
    uint8_t data[ISHIELD_TEST_HEADER_SIZE + ISHIELD_TEST_FILEBLOCK_SIZE + 8];
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_scan_layer_t layer;
    cli_ctx ctx;
    cl_fmap_t *map;
    cl_error_t ret;

    memset(data, 0, sizeof(data));
    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&layer, 0, sizeof(layer));
    memset(&ctx, 0, sizeof(ctx));
    data[0]                 = 1;
    ctx.engine              = &engine;
    ctx.options             = &options;
    ctx.this_layer_tmpdir   = tmpdir;
    ctx.recursion_stack     = &layer;
    ctx.recursion_stack_size = 1;

    data[8] = 1;
    map     = cl_fmap_open_memory(data, ISHIELD_TEST_HEADER_SIZE);
    ck_assert_ptr_nonnull(map);
    ctx.fmap   = map;
    layer.fmap = map;
    ret        = cli_scanishield_msi(&ctx, 0);
    ck_assert_int_eq(ret, CL_EUNPACK);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason,
                     "InstallShield MSI control metadata is unsupported by the bounded parser");
    ck_assert(map->dont_cache_flag);
    cl_fmap_close(map);

    data[8]                   = 0;
    ctx.scan_incomplete       = false;
    ctx.scan_incomplete_reason = NULL;

    map = cl_fmap_open_memory(data, ISHIELD_TEST_HEADER_SIZE);
    ck_assert_ptr_nonnull(map);
    ctx.fmap            = map;
    layer.fmap          = map;
    map->dont_cache_flag = false;
    ret = cli_scanishield_msi(&ctx, 0);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);
    cl_fmap_close(map);

    data[ISHIELD_TEST_HEADER_SIZE] = 'k';
    ishield_test_write_u64(data + ISHIELD_TEST_HEADER_SIZE + ISHIELD_TEST_CSIZE_OFFSET, 8);
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.fmap            = map;
    layer.fmap          = map;
    ctx.scan_incomplete = false;
    map->dont_cache_flag = false;
    engine.maxfilesize  = 4;
    ret = cli_scanishield_msi(&ctx, 0);
    ck_assert_int_eq(ret, CL_EMAXSIZE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);
    cl_fmap_close(map);

    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.fmap            = map;
    layer.fmap          = map;
    ctx.scan_incomplete = false;
    map->dont_cache_flag = false;
    engine.maxfilesize  = 0;
    ret = cli_scanishield_msi(&ctx, 0);
    ck_assert_int_eq(ret, CL_EUNPACK);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);
    cl_fmap_close(map);
}
END_TEST

START_TEST(test_hwpml_base64_decoder_is_bounded_and_fail_visible)
{
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t map;
    FILE *encoded;
    FILE *decoded;
    unsigned char encoded_block[8192];
    unsigned char decoded_block[4096];
    const unsigned char expected[3] = {'A', 'B', 'C'};
    uint64_t decoded_size = 0;
    uint64_t verified = 0;
    size_t i;
    size_t block;
    size_t got;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    memset(&map, 0, sizeof(map));
    ctx.engine = &engine;
    ctx.fmap   = &map;

    for (i = 0; i < sizeof(encoded_block); i += 4)
        memcpy(encoded_block + i, "QUJD", 4);

    encoded = tmpfile();
    decoded = tmpfile();
    ck_assert_ptr_nonnull(encoded);
    ck_assert_ptr_nonnull(decoded);
    for (block = 0; block < 12; block++)
        ck_assert_msg(fwrite(encoded_block, 1, sizeof(encoded_block), encoded) == sizeof(encoded_block),
                      "failed to construct encoded HWPML test attachment");
    ck_assert_int_eq(fflush(encoded), 0);

    ret = cli_hwpml_decode_base64_fd(&ctx, fileno(encoded), fileno(decoded), &decoded_size);
    ck_assert_msg(ret == CL_SUCCESS, "bounded HWPML Base64 decoder returned %d", ret);
    ck_assert_msg(decoded_size == 12U * sizeof(encoded_block) / 4U * 3U,
                  "decoded size was %llu", (unsigned long long)decoded_size);
    ck_assert(!ctx.scan_incomplete);
    ck_assert(!map.dont_cache_flag);

    ck_assert_int_eq(fseek(decoded, 0, SEEK_SET), 0);
    while ((got = fread(decoded_block, 1, sizeof(decoded_block), decoded)) != 0) {
        for (i = 0; i < got; i++)
            ck_assert_msg(decoded_block[i] == expected[(verified + i) % 3],
                          "decoded byte %llu was 0x%02x", (unsigned long long)(verified + i), decoded_block[i]);
        verified += got;
    }
    ck_assert_msg(verified == decoded_size, "verified %llu of %llu decoded bytes",
                  (unsigned long long)verified, (unsigned long long)decoded_size);
    fclose(decoded);
    fclose(encoded);

    memset(&ctx, 0, sizeof(ctx));
    memset(&map, 0, sizeof(map));
    ctx.engine = &engine;
    ctx.fmap   = &map;
    encoded    = tmpfile();
    decoded    = tmpfile();
    ck_assert_ptr_nonnull(encoded);
    ck_assert_ptr_nonnull(decoded);
    ck_assert_msg(fwrite("QUJD$A==", 1, 8, encoded) == 8, "failed to construct malformed Base64 input");
    ck_assert_int_eq(fflush(encoded), 0);

    ret = cli_hwpml_decode_base64_fd(&ctx, fileno(encoded), fileno(decoded), &decoded_size);
    ck_assert_msg(ret == CL_EPARSE, "malformed HWPML Base64 returned %d", ret);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map.dont_cache_flag);
    fclose(decoded);
    fclose(encoded);
}
END_TEST

START_TEST(test_ishield_truncated_metadata_is_fail_visible)
{
    static const uint8_t data[] = {'n', 'a', 'm', 'e', 0};
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&ctx, 0, sizeof(ctx));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine            = &engine;
    ctx.options           = &options;
    ctx.fmap              = map;
    ctx.this_layer_tmpdir = tmpdir;

    ret = cli_scanishield(&ctx, 0, map->len);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_ishield_invalid_embedded_header_is_fail_visible)
{
    uint8_t data[128];
    size_t used = 0;
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_scan_layer_t layer;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(data, 0, sizeof(data));
    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&layer, 0, sizeof(layer));
    memset(&ctx, 0, sizeof(ctx));

    memcpy(data + used, "data1.hdr", sizeof("data1.hdr"));
    used += sizeof("data1.hdr");
    memcpy(data + used, "", 1);
    used += 1;
    memcpy(data + used, "", 1);
    used += 1;
    memcpy(data + used, "20", sizeof("20"));
    used += sizeof("20");
    used += 20;

    memcpy(data + used, "data1.cab", sizeof("data1.cab"));
    used += sizeof("data1.cab");
    memcpy(data + used, "", 1);
    used += 1;
    memcpy(data + used, "", 1);
    used += 1;
    memcpy(data + used, "0", sizeof("0"));
    used += sizeof("0");

    map = cl_fmap_open_memory(data, used);
    ck_assert_ptr_nonnull(map);
    options.parse         = CL_SCAN_PARSE_ARCHIVE;
    ctx.engine            = &engine;
    ctx.options           = &options;
    ctx.fmap              = map;
    ctx.this_layer_tmpdir = tmpdir;
    ctx.recursion_stack  = &layer;
    ctx.recursion_stack_size = 1;
    layer.fmap            = map;

    ret = cli_scanishield(&ctx, 0, map->len);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

static void arj_test_write_u16(uint8_t *dst, uint16_t value)
{
    dst[0] = (uint8_t)value;
    dst[1] = (uint8_t)(value >> 8);
}

static void arj_test_write_u32(uint8_t *dst, uint32_t value)
{
    unsigned int i;

    for (i = 0; i < 4U; i++)
        dst[i] = (uint8_t)(value >> (8U * i));
}

static size_t arj_read_failure_offset = SIZE_MAX;

static const void *arj_targeted_read_failure(fmap_t *map, size_t at, size_t len, int lock)
{
    (void)lock;
    if (at == arj_read_failure_offset)
        return NULL;
    if (len == 0 || at > map->len || len > map->len - at)
        return NULL;
    return (const uint8_t *)map->data + at;
}

START_TEST(test_arj_stored_member_read_failure_is_fail_visible)
{
    uint8_t data[87];
    struct cl_scan_options options;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;
    fmap_t *map;

    memset(data, 0, sizeof(data));
    data[0] = 0x60;
    data[1] = 0xea;
    arj_test_write_u16(data + 2, 34);
    data[4]  = 30;
    data[34] = 'a';

    data[43] = 0x60;
    data[44] = 0xea;
    arj_test_write_u16(data + 45, 35);
    data[47] = 30;
    data[52] = 0;
    arj_test_write_u32(data + 59, 2);
    arj_test_write_u32(data + 63, 2);
    data[77] = 'f';
    data[86] = 'x';

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    arj_read_failure_offset = 86U;
    map->need            = arj_targeted_read_failure;
    verdict              = CL_VERDICT_STRONG_INDICATOR;
    last_alert           = "stale";
    scanned              = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL,
                        "CL_TYPE_ARJ", NULL);
    ck_assert_int_eq(ret, CL_EREAD);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    arj_read_failure_offset = SIZE_MAX;
    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_arj_truncated_main_header_is_fail_visible)
{
    uint8_t data[4];
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    size_t archive_size = 0;
    cl_error_t ret;

    memset(data, 0, sizeof(data));
    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));

    data[0] = 0x60;
    data[1] = 0xea;
    arj_test_write_u16(data + 2, 34);

    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine = &engine;
    ctx.fmap   = map;

    ret = cli_unarj_header_check(&ctx, 0, &archive_size);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_arj_truncated_member_is_fail_visible)
{
    uint8_t data[87];
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    size_t archive_size = 0;
    cl_error_t ret;

    memset(data, 0, sizeof(data));
    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));

    data[0] = 0x60;
    data[1] = 0xea;
    arj_test_write_u16(data + 2, 34);
    data[4]  = 30;
    data[34] = 'a';

    data[43] = 0x60;
    data[44] = 0xea;
    arj_test_write_u16(data + 45, 33);
    data[47] = 30;
    arj_test_write_u32(data + 59, 2);
    data[77] = 'f';

    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine = &engine;
    ctx.fmap   = map;

    ret = cli_unarj_header_check(&ctx, 0, &archive_size);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_arj_truncated_member_extraction_is_fail_visible)
{
    uint8_t data[87];
    struct cl_engine *scan_engine;
    struct cl_scan_options options;
    fmap_t *map;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    memset(data, 0, sizeof(data));
    data[0] = 0x60;
    data[1] = 0xea;
    arj_test_write_u16(data + 2, 34);
    data[4]  = 30;
    data[34] = 'a';

    data[43] = 0x60;
    data[44] = 0xea;
    arj_test_write_u16(data + 45, 35);
    data[47] = 30;
    data[52] = 0;
    arj_test_write_u32(data + 59, 2);
    arj_test_write_u32(data + 63, 2);
    data[77] = 'f';
    data[86] = 'x';

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL,
                        "CL_TYPE_ARJ", NULL);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_arj_output_size_mismatch_is_fail_visible)
{
    uint8_t data[87];
    struct cl_engine *scan_engine;
    struct cl_scan_options options;
    fmap_t *map;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;

    memset(data, 0, sizeof(data));
    data[0] = 0x60;
    data[1] = 0xea;
    arj_test_write_u16(data + 2, 34);
    data[4]  = 30;
    data[34] = 'a';

    data[43] = 0x60;
    data[44] = 0xea;
    arj_test_write_u16(data + 45, 35);
    data[47] = 30;
    data[52] = 0;
    arj_test_write_u32(data + 59, 1);
    arj_test_write_u32(data + 63, 2);
    data[77] = 'f';
    data[86] = 'x';

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL,
                        "CL_TYPE_ARJ", NULL);
    ck_assert_int_eq(ret, CL_EUNPACK);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_arj_member_limit_is_fail_visible)
{
    uint8_t data[87];
    struct cl_scan_options options;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;
    fmap_t *map;

    memset(data, 0, sizeof(data));
    data[0] = 0x60;
    data[1] = 0xea;
    arj_test_write_u16(data + 2, 34);
    data[4]  = 30;
    data[34] = 'a';

    data[43] = 0x60;
    data[44] = 0xea;
    arj_test_write_u16(data + 45, 35);
    data[47] = 30;
    data[52] = 0;
    arj_test_write_u32(data + 59, 2);
    arj_test_write_u32(data + 63, 2);
    data[77] = 'f';
    data[86] = 'x';

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_set_num(scan_engine, CL_ENGINE_MAX_SCANSIZE, 1), CL_SUCCESS);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL,
                        "CL_TYPE_ARJ", NULL);
    ck_assert_int_eq(ret, CL_EMAXSIZE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_arj_temporary_limit_is_fail_visible)
{
    uint8_t data[87];
    struct cl_scan_options options;
    struct cl_engine *scan_engine;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;
    fmap_t *map;

    memset(data, 0, sizeof(data));
    data[0] = 0x60;
    data[1] = 0xea;
    arj_test_write_u16(data + 2, 34);
    data[4]  = 30;
    data[34] = 'a';

    data[43] = 0x60;
    data[44] = 0xea;
    arj_test_write_u16(data + 45, 35);
    data[47] = 30;
    data[52] = 0;
    arj_test_write_u32(data + 59, 2);
    arj_test_write_u32(data + 63, 2);
    data[77] = 'f';
    data[86] = 'x';

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_ARCHIVE;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_set_num(scan_engine, CL_ENGINE_MAX_TEMPORARY_SIZE, 1), CL_SUCCESS);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;

    ret = cl_scanmap_ex(map, NULL, &verdict, &last_alert, &scanned,
                        scan_engine, &options, NULL, NULL, NULL, NULL,
                        "CL_TYPE_ARJ", NULL);
    ck_assert_msg(ret == CL_ERESOURCE,
                  "ARJ temporary limit returned %s (%d)", cl_strerror(ret), ret);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_pe_truncated_header_is_fail_visible)
{
    static const uint8_t data[] = {'M', 'Z'};
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_scan_layer_t layer;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&layer, 0, sizeof(layer));
    memset(&ctx, 0, sizeof(ctx));

    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine               = &engine;
    ctx.options              = &options;
    ctx.fmap                 = map;
    ctx.recursion_stack      = &layer;
    ctx.recursion_stack_size = 1;
    layer.fmap               = map;

    ret = cli_scanpe(&ctx);
    ck_assert_int_eq(ret, CL_EFORMAT);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

#if SIZE_MAX > UINT32_MAX
START_TEST(test_pe_header_nested_fmap_accepts_native_offset)
{
    char file_path[PATH_MAX];
    struct cl_engine *scan_engine;
    struct cl_scan_options options;
    struct cli_exe_info peinfo;
    struct pe_native_offset_map_state state;
    cli_ctx header_ctx;
    struct stat st;
    fmap_t *parent;
    fmap_t *nested;
    uint8_t *data;
    size_t offset = 0;
    size_t source_offset = (size_t)UINT32_MAX + 4096U;
    cl_error_t ret;
    int fd;

    snprintf(file_path, sizeof(file_path), "%s/input/pe_allmatch/test.exe", SRCDIR);
    fd = open(file_path, O_RDONLY | O_BINARY);
    ck_assert_msg(fd >= 0, "open(%s) failed: %s", file_path, strerror(errno));
    ck_assert_msg(FSTAT(fd, &st) == 0, "fstat(%s) failed: %s", file_path, strerror(errno));
    ck_assert_msg((uintmax_t)st.st_size <= SIZE_MAX - source_offset,
                  "PE fixture cannot be placed at the synthetic native offset");

    data = malloc((size_t)st.st_size);
    ck_assert_ptr_nonnull(data);
    while (offset < (size_t)st.st_size) {
        ssize_t nread = read(fd, data + offset, (size_t)st.st_size - offset);
        ck_assert_msg(nread > 0, "read(%s) failed: %s", file_path, strerror(errno));
        offset += (size_t)nread;
    }
    close(fd);

    memset(&options, 0, sizeof(options));
    memset(&header_ctx, 0, sizeof(header_ctx));
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);

    state.data         = data;
    state.length       = (size_t)st.st_size;
    state.source_offset = source_offset;
    parent             = cl_fmap_open_memory(data, 1);
    ck_assert_ptr_nonnull(parent);
    parent->handle     = &state;
    parent->need       = pe_native_offset_map_need;
    parent->len        = source_offset + state.length;
    parent->real_len   = parent->len;

    nested = fmap_duplicate(parent, source_offset, state.length, "embedded-pe-header-test");
    ck_assert_ptr_nonnull(nested);
    ck_assert_uint_eq(nested->nested_offset, source_offset);

    header_ctx.engine            = scan_engine;
    header_ctx.dconf             = scan_engine->dconf;
    header_ctx.options           = &options;
    header_ctx.fmap              = nested;
    header_ctx.this_layer_tmpdir = tmpdir;
    cli_exe_info_init(&peinfo, 0);
    ret = cli_peheader(&header_ctx, &peinfo, CLI_PEHEADER_OPT_NONE);
    ck_assert_int_eq(ret, CL_SUCCESS);
    ck_assert_uint_eq(peinfo.offset, 0);
    ck_assert(!header_ctx.scan_incomplete);
    cli_exe_info_destroy(&peinfo);

    free_duplicate_fmap(nested);
    cl_fmap_close(parent);
    cl_engine_free(scan_engine);
    free(data);
}
END_TEST
#endif

START_TEST(test_executable_metadata_targetinfo_failure_is_fail_visible)
{
    static const uint8_t data[] = {'M', 'Z'};
    struct cli_target_info info;
    cli_ctx ctx;
    fmap_t *map;

    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.fmap = map;

    cli_targetinfo_init(&info);
    cli_targetinfo(&info, TARGET_PE, &ctx);
    ck_assert_int_eq(info.status, -1);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "Executable metadata parsing ended before inspection completed");
    ck_assert(map->dont_cache_flag);

    cli_targetinfo_destroy(&info);
    cl_fmap_close(map);
}
END_TEST

START_TEST(test_pe_import_thunk_read_failure_is_fail_visible)
{
    char file_path[PATH_MAX];
    struct cl_engine *scan_engine;
    struct cl_scan_options options;
    struct stat st;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    cl_error_t ret;
    fmap_t *map;
    uint8_t *data;
    uint8_t original_descriptor_name[sizeof(uint32_t)];
    size_t offset = 0;
    int fd;

    snprintf(file_path, sizeof(file_path), "%s/input/pe_allmatch/test.exe", SRCDIR);
    fd = open(file_path, O_RDONLY | O_BINARY);
    ck_assert_msg(fd >= 0, "open(%s) failed: %s", file_path, strerror(errno));
    ck_assert_msg(FSTAT(fd, &st) == 0, "fstat(%s) failed: %s", file_path, strerror(errno));
    ck_assert_msg(st.st_size > PE_TEST_IMPORT_THUNK_OFFSET + sizeof(uint32_t), "PE fixture is unexpectedly short");
    ck_assert_msg(st.st_size > PE_TEST_IMPORT_DLL_NAME_OFFSET, "PE fixture lacks its imported DLL name");
    ck_assert_msg(st.st_size > PE_TEST_IMPORT_FUNCTION_OFFSET + 256U,
                  "PE fixture lacks its imported function name window");

    data = malloc((size_t)st.st_size);
    ck_assert_ptr_nonnull(data);
    while (offset < (size_t)st.st_size) {
        ssize_t nread = read(fd, data + offset, (size_t)st.st_size - offset);
        ck_assert_msg(nread > 0, "read(%s) failed: %s", file_path, strerror(errno));
        offset += (size_t)nread;
    }
    close(fd);
    memcpy(original_descriptor_name, data + PE_TEST_IMPORT_DESCRIPTOR_OFFSET + 12, sizeof(original_descriptor_name));

    map = cl_fmap_open_memory(data, (size_t)st.st_size);
    ck_assert_ptr_nonnull(map);
    map->need = pe_import_thunk_read_failure;

    memset(&options, 0, sizeof(options));
    options.general = CL_SCAN_GENERAL_COLLECT_METADATA;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);

    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;
    ret        = cl_scanmap_ex(map, file_path, &verdict, &last_alert, &scanned,
                               scan_engine, &options, NULL, NULL, NULL, NULL,
                               "CL_TYPE_MSEXE", NULL);
    ck_assert_msg(ret != CL_SUCCESS, "PE import thunk read failure returned clean");
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert_ptr_null(last_alert);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);

    /* The first descriptor's Name field is at +12. Keep its thunk RVA
     * nonzero while clearing Name to create a malformed terminator. */
    memset(data + PE_TEST_IMPORT_DESCRIPTOR_OFFSET + 12, 0, sizeof(uint32_t));
    map = cl_fmap_open_memory(data, (size_t)st.st_size);
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;
    ret        = cl_scanmap_ex(map, file_path, &verdict, &last_alert, &scanned,
                               scan_engine, &options, NULL, NULL, NULL, NULL,
                               "CL_TYPE_MSEXE", NULL);
    ck_assert_msg(ret != CL_SUCCESS, "malformed PE import descriptor returned clean");
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert_ptr_null(last_alert);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);

    /* Restore the descriptor and corrupt the mapped DLL name. The import
     * parser must validate the bytes it read, not the destination string that
     * has not yet been allocated. */
    memcpy(data + PE_TEST_IMPORT_DESCRIPTOR_OFFSET + 12, original_descriptor_name, sizeof(original_descriptor_name));
    data[PE_TEST_IMPORT_DLL_NAME_OFFSET] = '!';
    map = cl_fmap_open_memory(data, (size_t)st.st_size);
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;
    ret        = cl_scanmap_ex(map, file_path, &verdict, &last_alert, &scanned,
                               scan_engine, &options, NULL, NULL, NULL, NULL,
                               "CL_TYPE_MSEXE", NULL);
    ck_assert_int_eq(ret, CL_EFORMAT);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert_ptr_null(last_alert);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);

    /* Restore the DLL name and remove the terminator from the first imported
     * function name. CLI_STRNDUP must not turn this truncated name into a
     * valid child. */
    data[PE_TEST_IMPORT_DLL_NAME_OFFSET] = 'K';
    memset(data + PE_TEST_IMPORT_FUNCTION_OFFSET, 'A', 256U);
    map = cl_fmap_open_memory(data, (size_t)st.st_size);
    ck_assert_ptr_nonnull(map);
    verdict    = CL_VERDICT_STRONG_INDICATOR;
    last_alert = "stale";
    scanned    = UINT64_MAX;
    ret        = cl_scanmap_ex(map, file_path, &verdict, &last_alert, &scanned,
                               scan_engine, &options, NULL, NULL, NULL, NULL,
                               "CL_TYPE_MSEXE", NULL);
    ck_assert_int_eq(ret, CL_EFORMAT);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert_ptr_null(last_alert);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
    free(data);
}
END_TEST

START_TEST(test_pe_petite_section_read_failure_is_fail_visible)
{
    char file_path[PATH_MAX];
    struct cl_engine *scan_engine;
    struct cl_scan_options options;
    cli_scan_layer_t layer;
    cli_ctx header_ctx;
    cli_ctx ctx;
    struct cli_exe_info peinfo;
    struct stat st;
    fmap_t *map;
    cl_error_t ret;
    uint8_t *data;
    size_t offset = 0;
    int fd;

    snprintf(file_path, sizeof(file_path), "%s/input/pe_allmatch/test.exe", SRCDIR);
    fd = open(file_path, O_RDONLY | O_BINARY);
    ck_assert_msg(fd >= 0, "open(%s) failed: %s", file_path, strerror(errno));
    ck_assert_msg(FSTAT(fd, &st) == 0, "fstat(%s) failed: %s", file_path, strerror(errno));

    data = malloc((size_t)st.st_size);
    ck_assert_ptr_nonnull(data);
    while (offset < (size_t)st.st_size) {
        ssize_t nread = read(fd, data + offset, (size_t)st.st_size - offset);
        ck_assert_msg(nread > 0, "read(%s) failed: %s", file_path, strerror(errno));
        offset += (size_t)nread;
    }
    close(fd);

    map = cl_fmap_open_memory(data, (size_t)st.st_size);
    ck_assert_ptr_nonnull(map);

    memset(&options, 0, sizeof(options));
    memset(&header_ctx, 0, sizeof(header_ctx));
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);

    header_ctx.engine            = scan_engine;
    header_ctx.dconf             = scan_engine->dconf;
    header_ctx.options           = &options;
    header_ctx.fmap              = map;
    header_ctx.this_layer_tmpdir = tmpdir;
    cli_exe_info_init(&peinfo, 0);
    ck_assert_int_eq(cli_peheader(&header_ctx, &peinfo, CLI_PEHEADER_OPT_NONE), CL_SUCCESS);
    ck_assert_msg(peinfo.nsections > 1, "PE fixture has too few sections for Petite regression");
    ck_assert_msg(peinfo.ep <= (size_t)st.st_size - 5U, "PE fixture entrypoint is unexpectedly close to EOF");
    pe_petite_section_read_offset = peinfo.sections[peinfo.nsections - 1].raw;
    ck_assert_msg(pe_petite_section_read_offset < (size_t)st.st_size,
                  "PE fixture Petite section is outside the input map");

    data[peinfo.ep] = '\xb8';
    cli_writeint32(data + peinfo.ep + 1,
                   peinfo.sections[peinfo.nsections - 1].rva + cli_readint32(&peinfo.pe_opt.opt32.ImageBase));
    cli_exe_info_destroy(&peinfo);

    map->need = pe_petite_section_read_failure;
    memset(&layer, 0, sizeof(layer));
    memset(&ctx, 0, sizeof(ctx));
    ctx.engine               = scan_engine;
    ctx.dconf                = scan_engine->dconf;
    ctx.options              = &options;
    ctx.fmap                 = map;
    ctx.this_layer_tmpdir    = tmpdir;
    ctx.recursion_stack      = &layer;
    ctx.recursion_stack_size = 1;
    layer.fmap               = map;

    ret = cli_scanpe(&ctx);
    ck_assert_msg(ret != CL_SUCCESS, "PE Petite section read failure returned clean");
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "PE Petite section could not be read completely");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
    free(data);
}
END_TEST

START_TEST(test_pe_unpack_limit_is_fail_visible)
{
    const char *file = OBJDIR PATHSEP "input" PATHSEP "clamav_hdb_scanfiles" PATHSEP "clam-upx.exe";
    struct cl_engine *scan_engine;
    struct cl_scan_options options;
    cli_scan_layer_t layer;
    cli_ctx ctx;
    fmap_t *map;
    struct stat st;
    cl_error_t ret;
    int fd;

    fd = open(file, O_RDONLY | O_BINARY);
    ck_assert_msg(fd >= 0, "open(%s) failed: %s", file, strerror(errno));
    ck_assert_int_eq(FSTAT(fd, &st), 0);
    ck_assert_msg((uintmax_t)st.st_size > 1024U,
                  "UPX fixture is too small for the unpacker-limit regression: %jd",
                  (intmax_t)st.st_size);

    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_set_num(scan_engine, CL_ENGINE_MAX_FILESIZE, 1024), CL_SUCCESS);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);

    map = cl_fmap_open_handle(&fd, 0, (size_t)st.st_size, pread_cb, 1);
    ck_assert_ptr_nonnull(map);
    memset(&options, 0, sizeof(options));
    memset(&layer, 0, sizeof(layer));
    memset(&ctx, 0, sizeof(ctx));
    ctx.engine               = scan_engine;
    ctx.dconf                = scan_engine->dconf;
    ctx.options              = &options;
    ctx.fmap                 = map;
    ctx.this_layer_tmpdir    = tmpdir;
    ctx.recursion_stack      = &layer;
    ctx.recursion_stack_size = 1;
    layer.fmap               = map;

    ret = cli_scanpe(&ctx);
    ck_assert_int_eq(ret, CL_EMAXSIZE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    close(fd);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_pe_unpack_temporary_limit_is_fail_visible)
{
    const char *file = OBJDIR PATHSEP "input" PATHSEP "clamav_hdb_scanfiles" PATHSEP "clam-upx.exe";
    struct cl_engine *scan_engine;
    struct cl_scan_options options;
    cli_scan_layer_t layer;
    cli_ctx ctx;
    struct stat st;
    fmap_t *map;
    cl_error_t ret;
    int fd;

    fd = open(file, O_RDONLY | O_BINARY);
    ck_assert_msg(fd >= 0, "open(%s) failed: %s", file, strerror(errno));
    ck_assert_int_eq(FSTAT(fd, &st), 0);
    ck_assert_msg((uintmax_t)st.st_size > 1024U,
                  "UPX fixture is too small for the temporary-limit regression: %jd",
                  (intmax_t)st.st_size);

    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_set_num(scan_engine, CL_ENGINE_MAX_TEMPORARY_SIZE, 1), CL_SUCCESS);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);

    map = cl_fmap_open_handle(&fd, 0, (size_t)st.st_size, pread_cb, 1);
    ck_assert_ptr_nonnull(map);
    memset(&options, 0, sizeof(options));
    memset(&layer, 0, sizeof(layer));
    memset(&ctx, 0, sizeof(ctx));
    ctx.engine               = scan_engine;
    ctx.dconf                = scan_engine->dconf;
    ctx.options              = &options;
    ctx.fmap                 = map;
    ctx.this_layer_tmpdir    = tmpdir;
    ctx.recursion_stack      = &layer;
    ctx.recursion_stack_size = 1;
    layer.fmap               = map;

    ret = cli_scanpe(&ctx);
    ck_assert_int_eq(ret, CL_ERESOURCE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    close(fd);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_pe_unpack_contiguous_size_is_fail_visible)
{
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_ctx ctx;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&ctx, 0, sizeof(ctx));
    ctx.engine  = &engine;
    ctx.options = &options;

    ret = cli_pe_unpack_size_check(&ctx, "test PE unpacker", (uint64_t)CLI_MAX_ALLOCATION + 1);
    ck_assert_int_eq(ret, CL_ERESOURCE);
    ck_assert(ctx.scan_incomplete);
}
END_TEST

START_TEST(test_pespin_limit_accounting_is_fail_visible)
{
    struct cl_engine engine;
    struct cl_scan_options options;
    struct cli_exe_section sections[2];
    cli_ctx ctx;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&sections, 0, sizeof(sections));
    memset(&ctx, 0, sizeof(ctx));
    engine.maxfilesize = UINT64_C(0x100000000);
    sections[0].vsz    = UINT32_MAX;
    sections[1].vsz    = UINT32_MAX;
    ctx.engine         = &engine;
    ctx.options        = &options;

    ret = cli_pespin_check_limits(&ctx, sections, 2, 0x3);
    ck_assert_int_eq(ret, 2);
    ck_assert(ctx.scan_incomplete);
    ck_assert(ctx.limit_exceeded);
    ck_assert_int_eq(ctx.limit_exceeded_result, CL_EMAXSIZE);
}
END_TEST

static void mspack_test_write_u16(uint8_t *dst, uint16_t value)
{
    dst[0] = (uint8_t)value;
    dst[1] = (uint8_t)(value >> 8);
}

static void mspack_test_write_u32(uint8_t *dst, uint32_t value)
{
    unsigned int i;

    for (i = 0; i < 4U; i++)
        dst[i] = (uint8_t)(value >> (8U * i));
}

#ifdef CLAMAV_TEST_MSPACK_CONSTRUCTOR_WRAP
struct mspack_system;
struct mscab_decompressor;
struct mschm_decompressor;

extern struct mscab_decompressor *__real_mspack_create_cab_decompressor(struct mspack_system *sys);
extern struct mschm_decompressor *__real_mspack_create_chm_decompressor(struct mspack_system *sys);

static int mspack_test_fail_cab_constructor;
static int mspack_test_fail_chm_constructor;

struct mscab_decompressor *__wrap_mspack_create_cab_decompressor(struct mspack_system *sys)
{
    if (mspack_test_fail_cab_constructor)
        return NULL;
    return __real_mspack_create_cab_decompressor(sys);
}

struct mschm_decompressor *__wrap_mspack_create_chm_decompressor(struct mspack_system *sys)
{
    if (mspack_test_fail_chm_constructor)
        return NULL;
    return __real_mspack_create_chm_decompressor(sys);
}

START_TEST(test_mspack_constructor_failures_are_fail_visible)
{
    static const uint8_t data[] = {'M', 'S', 'C', 'F'};
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_scan_layer_t layer;
    cli_ctx ctx;
    cl_fmap_t *map;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&layer, 0, sizeof(layer));
    memset(&ctx, 0, sizeof(ctx));
    ctx.engine               = &engine;
    ctx.options              = &options;
    ctx.recursion_stack      = &layer;
    ctx.recursion_stack_size = 1;
    ctx.this_layer_tmpdir    = tmpdir;

    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.fmap   = map;
    layer.fmap = map;

    mspack_test_fail_cab_constructor = 1;
    {
        size_t cab_size = 0;

        ret = cli_mscab_header_check(&ctx, 0, &cab_size);
        ck_assert_int_eq(ret, CL_EUNPACK);
        ck_assert(ctx.scan_incomplete);
        ck_assert(map->dont_cache_flag);
    }

    ctx.scan_incomplete  = false;
    map->dont_cache_flag = false;
    ret = cli_scanmscab(&ctx, 0);
    ck_assert_int_eq(ret, CL_EUNPACK);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    ctx.scan_incomplete           = false;
    map->dont_cache_flag          = false;
    mspack_test_fail_cab_constructor = 0;
    mspack_test_fail_chm_constructor = 1;
    ret = cli_scanmschm(&ctx);
    ck_assert_int_eq(ret, CL_EUNPACK);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    mspack_test_fail_chm_constructor = 0;
    cl_fmap_close(map);
}
END_TEST
#endif

START_TEST(test_script_normalization_window_offset_is_stable)
{
    enum {
        SCRIPT_SIZE   = 2U * 1024U * 1024U,
        MARKER_OFFSET = 20000U,
    };
    static const unsigned char marker[] = "MARK";
    struct cl_engine *scan_engine;
    struct cl_scan_options options;
    cli_scan_layer_t layer;
    cli_ctx ctx;
    fmap_t *map;
    unsigned char *script;
    cl_error_t ret;

    script = malloc(SCRIPT_SIZE);
    ck_assert_ptr_nonnull(script);
    memset(script, 'a', SCRIPT_SIZE);
    memcpy(script + MARKER_OFFSET, marker, sizeof(marker) - 1U);

    memset(&options, 0, sizeof(options));
    memset(&layer, 0, sizeof(layer));
    memset(&ctx, 0, sizeof(ctx));
    options.parse = ~0U;

    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cli_initroots(scan_engine, 0), CL_SUCCESS);
    ck_assert_int_eq(cli_add_content_match_pattern(scan_engine->root[7],
                                                   "ScriptWindowOffset",
                                                   "6d61726b", 0, 0, 0,
                                                   "20000", NULL, 0),
                     CL_SUCCESS);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);

    map = cl_fmap_open_memory(script, SCRIPT_SIZE);
    ck_assert_ptr_nonnull(map);
    ctx.engine               = scan_engine;
    ctx.dconf                = scan_engine->dconf;
    ctx.options              = &options;
    ctx.fmap                 = map;
    ctx.this_layer_tmpdir    = tmpdir;
    ctx.recursion_stack      = &layer;
    ctx.recursion_stack_size = 1;
    layer.fmap               = map;

    ret = cli_magic_scan(&ctx, CL_TYPE_SCRIPT);
    ck_assert_int_eq(ret, CL_VIRUS);
    ck_assert(!ctx.scan_incomplete);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
    free(script);
}
END_TEST

#ifdef CLAMAV_TEST_FMAP_NEW_WRAP
extern fmap_t *__real_fmap_new(int fd, off_t offset, size_t len, const char *name, const char *path);

static int fmap_new_test_fail;

fmap_t *__wrap_fmap_new(int fd, off_t offset, size_t len, const char *name, const char *path)
{
    if (fmap_new_test_fail)
        return NULL;
    return __real_fmap_new(fd, offset, len, name, path);
}

START_TEST(test_normalized_script_map_failure_is_fail_visible)
{
    static const unsigned char script[] = "var marker = 1;";
    struct cl_engine *scan_engine;
    struct cl_scan_options options;
    cli_scan_layer_t layer;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    memset(&layer, 0, sizeof(layer));
    memset(&ctx, 0, sizeof(ctx));
    options.parse            = CL_SCAN_PARSE_HTML;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    ck_assert_ptr_nonnull(scan_engine->root[7]);
    scan_engine->root[7]->linked_bcs = 1;

    map = cl_fmap_open_memory(script, sizeof(script) - 1U);
    ck_assert_ptr_nonnull(map);
    ctx.engine               = scan_engine;
    ctx.dconf                = scan_engine->dconf;
    ctx.options              = &options;
    ctx.fmap                 = map;
    ctx.this_layer_tmpdir    = tmpdir;
    ctx.recursion_stack      = &layer;
    ctx.recursion_stack_size = 1;
    layer.fmap               = map;

    fmap_new_test_fail = 1;
    ret = cli_magic_scan(&ctx, CL_TYPE_SCRIPT);
    fmap_new_test_fail = 0;
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST

START_TEST(test_descriptor_limit_preflight_precedes_fmap_creation)
{
    static const char data[11] = "0123456789";
    struct cl_engine *engine;
    struct cl_scan_options options;
    cl_verdict_t verdict;
    const char *last_alert;
    uint64_t scanned;
    char *path = NULL;
    int fd     = -1;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    engine = cl_engine_new();
    ck_assert_ptr_nonnull(engine);
    engine->maxfilesize = 10;
    engine->maxscansize = 10;
    ck_assert_int_eq(cl_engine_compile(engine), CL_SUCCESS);

    ck_assert_int_eq(cli_gentempfd(tmpdir, &path, &fd), CL_SUCCESS);
    ck_assert_ptr_nonnull(path);
    ck_assert_int_eq(write(fd, data, sizeof(data)), (ssize_t)sizeof(data));

    fmap_new_test_fail = 1;
    ret = cl_scandesc_ex(fd, path, &verdict, &last_alert, &scanned,
                         engine, &options, NULL, NULL, NULL, NULL, NULL, NULL);
    fmap_new_test_fail = 0;

    ck_assert_int_eq(ret, CL_EMAXSIZE);
    ck_assert_int_eq(verdict, CL_VERDICT_NOTHING_FOUND);
    ck_assert(last_alert == NULL);
    ck_assert_uint_eq(scanned, 0);

    close(fd);
    free(path);
    cl_engine_free(engine);
}
END_TEST

START_TEST(test_child_descriptor_inspection_failure_is_fail_visible)
{
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_scan_layer_t layer;
    cli_ctx ctx;
    fmap_t map;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&layer, 0, sizeof(layer));
    memset(&ctx, 0, sizeof(ctx));
    memset(&map, 0, sizeof(map));

    ctx.engine               = &engine;
    ctx.options              = &options;
    ctx.fmap                 = &map;
    ctx.recursion_stack      = &layer;
    ctx.recursion_stack_size = 1;
    layer.fmap               = &map;

    ret = cli_magic_scan_desc_type(-1, NULL, &ctx, CL_TYPE_ANY, NULL, LAYER_ATTRIBUTES_NONE);
    ck_assert_int_eq(ret, CL_ESTAT);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map.dont_cache_flag);
}
END_TEST
#endif

#ifdef CLAMAV_TEST_JS_IO_WRAP
START_TEST(test_script_normalization_cleanup_close_failure_is_fail_visible)
{
    static const unsigned char script[] = "var marker = 1;";
    struct cl_engine *scan_engine;
    struct cl_scan_options options;
    cli_scan_layer_t layers[2];
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&options, 0, sizeof(options));
    memset(layers, 0, sizeof(layers));
    memset(&ctx, 0, sizeof(ctx));
    options.parse = ~0U;
    ck_assert_int_eq(cl_init(CL_INIT_DEFAULT), CL_SUCCESS);
    scan_engine = cl_engine_new();
    ck_assert_ptr_nonnull(scan_engine);
    ck_assert_int_eq(cl_engine_compile(scan_engine), CL_SUCCESS);
    ck_assert_ptr_nonnull(scan_engine->root[7]);
    scan_engine->root[7]->linked_bcs = 1;

    map = cl_fmap_open_memory(script, sizeof(script) - 1U);
    ck_assert_ptr_nonnull(map);
    layers[0].fmap           = map;
    ctx.engine               = scan_engine;
    ctx.dconf                = scan_engine->dconf;
    ctx.options              = &options;
    ctx.fmap                 = map;
    ctx.this_layer_tmpdir    = tmpdir;
    ctx.recursion_stack      = layers;
    ctx.recursion_stack_size = 2;

    clamav_test_fail_close = 1;
    ret                    = cli_magic_scan(&ctx, CL_TYPE_SCRIPT);
    clamav_test_fail_close = 0;
    ck_assert_int_eq(ret, CL_EWRITE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    cl_engine_free(scan_engine);
}
END_TEST
#endif

START_TEST(test_mspack_scan_limit_is_fail_visible)
{
    enum {
        CAB_HEADER_SIZE = 36,
        CAB_FOLDER_SIZE = 8,
        CAB_FILE_SIZE   = 18,
        CAB_DATA_SIZE   = 9,
        CAB_TOTAL_SIZE  = CAB_HEADER_SIZE + CAB_FOLDER_SIZE + CAB_FILE_SIZE + CAB_DATA_SIZE
    };
    uint8_t data[CAB_TOTAL_SIZE] = {0};
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_scan_layer_t layer;
    cli_ctx ctx;
    cl_fmap_t *map;
    cl_error_t ret;

    /* A minimal one-file, uncompressed CAB. The test starts with the
     * cumulative scan budget already exhausted, so the bridge must reject
     * the uninspected member before creating extraction output. */
    memcpy(data, "MSCF", 4);
    mspack_test_write_u32(data + 8, CAB_TOTAL_SIZE);
    mspack_test_write_u32(data + 16, CAB_HEADER_SIZE + CAB_FOLDER_SIZE);
    data[24] = 3;
    data[25] = 1;
    mspack_test_write_u16(data + 26, 1);
    mspack_test_write_u16(data + 28, 1);

    mspack_test_write_u32(data + 36, CAB_HEADER_SIZE + CAB_FOLDER_SIZE + CAB_FILE_SIZE);
    mspack_test_write_u16(data + 40, 1);
    mspack_test_write_u16(data + 42, 0);

    mspack_test_write_u32(data + 44, 1);
    mspack_test_write_u32(data + 48, 0);
    mspack_test_write_u16(data + 52, 0);
    memcpy(data + 60, "a", 2);

    mspack_test_write_u16(data + 66, 1);
    mspack_test_write_u16(data + 68, 1);
    data[70] = 'x';

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&layer, 0, sizeof(layer));
    memset(&ctx, 0, sizeof(ctx));
    engine.maxscansize        = 1;
    ctx.engine                = &engine;
    ctx.options               = &options;
    ctx.scansize              = 1;
    ctx.recursion_stack       = &layer;
    ctx.recursion_stack_size  = 1;
    ctx.this_layer_tmpdir     = tmpdir;

    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.fmap   = map;
    layer.fmap = map;

    ret = cli_scanmscab(&ctx, 0);
    ck_assert_int_eq(ret, CL_EMAXSIZE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    /* A member that is otherwise admissible must still be rejected before
     * extraction when the shared temporary budget is already exhausted. */
    ctx.scansize              = 0;
    ctx.temporary_bytes       = 1;
    ctx.scan_incomplete       = false;
    ctx.limit_exceeded        = false;
    ctx.limit_exceeded_result = CL_SUCCESS;
    engine.maxscansize        = 0;
    engine.maxtemporarysize   = 1;
    map->dont_cache_flag      = false;

    ret = cli_scanmscab(&ctx, 0);
    ck_assert_int_eq(ret, CL_ERESOURCE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_mspack_time_limit_is_fail_visible)
{
    uint8_t data[36] = {0};
    struct cl_engine engine;
    cli_ctx ctx;
    cl_fmap_t *map;
    size_t cab_size = 0;
    cl_error_t ret;

    memcpy(data, "MSCF", 4);
    mspack_test_write_u32(data + 8, sizeof(data));
    mspack_test_write_u32(data + 16, sizeof(data));

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine = &engine;
    ctx.fmap   = map;
    ck_assert_int_eq(gettimeofday(&ctx.time_limit, NULL), 0);
    ctx.time_limit.tv_sec--;

    ret = cli_mscab_header_check(&ctx, 0, &cab_size);
    ck_assert_int_eq(ret, CL_ETIMEOUT);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "CAB header inspection reached the configured time limit");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_mscab_truncated_fixed_header_is_fail_visible)
{
    static const uint8_t weak_data[] = {'M', 'S', 'C', 'F'};
    uint8_t data[36] = {0};
    struct cl_engine engine;
    cli_ctx ctx;
    cl_fmap_t *map;
    cl_fmap_t *weak_map;
    size_t cab_size = 0;
    cl_error_t ret;

    memcpy(data, "MSCF", 4);
    mspack_test_write_u32(data + 8, 64);
    mspack_test_write_u32(data + 16, 36);

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));

    weak_map = cl_fmap_open_memory(weak_data, sizeof(weak_data));
    ck_assert_ptr_nonnull(weak_map);
    ctx.engine = &engine;
    ctx.fmap   = weak_map;
    ret        = cli_mscab_header_check(&ctx, 0, &cab_size);
    ck_assert_int_eq(ret, CL_EFORMAT);
    ck_assert(!ctx.scan_incomplete);
    ck_assert(!weak_map->dont_cache_flag);
    cl_fmap_close(weak_map);

    ctx.scan_incomplete = false;
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine = &engine;
    ctx.fmap   = map;

    ret = cli_mscab_header_check(&ctx, 0, &cab_size);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_elf_truncated_header_is_fail_visible)
{
    static const uint8_t data[] = {0x7f, 'E', 'L', 'F'};
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_scan_layer_t layer;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&layer, 0, sizeof(layer));
    memset(&ctx, 0, sizeof(ctx));

    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine               = &engine;
    ctx.options              = &options;
    ctx.fmap                 = map;
    ctx.recursion_stack      = &layer;
    ctx.recursion_stack_size = 1;
    layer.fmap               = map;

    ret = cli_scanelf(&ctx);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_elf_time_limit_is_fail_visible)
{
    static const uint8_t data[] = {0};
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine = &engine;
    ctx.fmap   = map;
    ck_assert_int_eq(gettimeofday(&ctx.time_limit, NULL), 0);
    ctx.time_limit.tv_sec--;

    ret = cli_scanelf(&ctx);
    ck_assert_int_eq(ret, CL_ETIMEOUT);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "ELF inspection reached the configured time limit");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_elf_scan_program_header_read_failure_is_fail_visible)
{
    uint8_t data[64 + 56] = {0};
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    data[0] = 0x7f;
    data[1] = 'E';
    data[2] = 'L';
    data[3] = 'F';
    data[4] = 2; /* ELFCLASS64. */
    data[5] = 1; /* ELFDATA2LSB. */
    data[6] = 1;
    zip_stream_write_u16(data + 16, 2);
    zip_stream_write_u16(data + 18, 62);
    zip_stream_write_u32(data + 20, 1);
    zip_stream_write_u64(data + 24, 0x400000U);
    zip_stream_write_u64(data + 32, 64U);
    zip_stream_write_u16(data + 52, sizeof(struct elf_file_hdr64));
    zip_stream_write_u16(data + 54, sizeof(struct elf_program_hdr64));
    zip_stream_write_u16(data + 56, 1);
    zip_stream_write_u16(data + 58, sizeof(struct elf_section_hdr64));

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    map->need   = elf_program_header_read_failure;
    ctx.engine  = &engine;
    ctx.options = &options;
    ctx.fmap    = map;

    ret = cli_scanelf(&ctx);
    ck_assert_int_eq(ret, CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "ELF program header could not be read completely");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_elf_metadata_read_failure_is_fail_visible)
{
    uint8_t data[64 + 56] = {0};
    struct cli_exe_info exeinfo;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    /* A confirmed ELF64 header points at a required program header whose
     * in-range fmap window fails. Metadata-only parsing must not stay clean. */
    data[0] = 0x7f;
    data[1] = 'E';
    data[2] = 'L';
    data[3] = 'F';
    data[4] = 2; /* ELFCLASS64. */
    data[5] = 1; /* ELFDATA2LSB. */
    data[6] = 1;
    zip_stream_write_u16(data + 16, 2);
    zip_stream_write_u16(data + 18, 62);
    zip_stream_write_u32(data + 20, 1);
    zip_stream_write_u64(data + 24, 0x400000U);
    zip_stream_write_u64(data + 32, 64U);
    zip_stream_write_u16(data + 52, sizeof(struct elf_file_hdr64));
    zip_stream_write_u16(data + 54, sizeof(struct elf_program_hdr64));
    zip_stream_write_u16(data + 56, 1);
    zip_stream_write_u16(data + 58, sizeof(struct elf_section_hdr64));

    memset(&ctx, 0, sizeof(ctx));
    cli_exe_info_init(&exeinfo, 0);
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    map->need = elf_program_header_read_failure;
    ctx.fmap = map;

    ret = cli_elfheader(&ctx, &exeinfo);
    ck_assert_int_eq(ret, CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "ELF metadata parsing ended before inspection completed");
    ck_assert(map->dont_cache_flag);

    cli_exe_info_destroy(&exeinfo);
    cl_fmap_close(map);
}
END_TEST

#if SIZE_MAX > UINT32_MAX
struct elf_large_metadata_state {
    size_t length;
    size_t max_offset;
    uint64_t section_offset;
    uint8_t file_header[sizeof(struct elf_file_hdr64)];
    uint8_t program_header[sizeof(struct elf_program_hdr64)];
    uint8_t section_header[sizeof(struct elf_section_hdr64)];
};

static void elf_large_metadata_copy(uint8_t *dst, size_t count, uint64_t offset,
                                    uint64_t source_offset, const uint8_t *source,
                                    size_t source_length)
{
    uint64_t read_end   = offset + count;
    uint64_t source_end = source_offset + source_length;
    uint64_t copy_start;
    uint64_t copy_end;

    if (offset >= source_end || read_end <= source_offset)
        return;

    copy_start = MAX(offset, source_offset);
    copy_end   = MIN(read_end, source_end);
    memcpy(dst + (size_t)(copy_start - offset), source + (size_t)(copy_start - source_offset),
           (size_t)(copy_end - copy_start));
}

static off_t elf_large_metadata_pread_cb(void *handle, void *buf, size_t count, off_t offset)
{
    struct elf_large_metadata_state *state = handle;

    if (offset < 0 || (uint64_t)offset >= state->length)
        return 0;
    if (count > state->length - (size_t)offset)
        count = state->length - (size_t)offset;
    if ((size_t)offset > state->max_offset)
        state->max_offset = (size_t)offset;

    memset(buf, 0, count);
    elf_large_metadata_copy(buf, count, (uint64_t)offset, 0, state->file_header,
                            sizeof(state->file_header));
    elf_large_metadata_copy(buf, count, (uint64_t)offset, sizeof(state->file_header),
                            state->program_header, sizeof(state->program_header));
    elf_large_metadata_copy(buf, count, (uint64_t)offset, state->section_offset,
                            state->section_header, sizeof(state->section_header));
    return (off_t)count;
}

static void elf_large_metadata_fixture_init(struct elf_large_metadata_state *state,
                                            int overflow_entry_offset)
{
    memset(state, 0, sizeof(*state));
    state->section_offset = (uint64_t)UINT32_MAX + 0x1000U;
    state->length         = (size_t)(state->section_offset + sizeof(state->section_header));

    state->file_header[0] = 0x7f;
    state->file_header[1] = 'E';
    state->file_header[2] = 'L';
    state->file_header[3] = 'F';
    state->file_header[4] = 2; /* ELFCLASS64 */
    state->file_header[5] = 1; /* ELFDATA2LSB */
    state->file_header[6] = 1;
    zip_stream_write_u16(state->file_header + 16, 2);
    zip_stream_write_u16(state->file_header + 18, 62);
    zip_stream_write_u32(state->file_header + 20, 1);
    zip_stream_write_u64(state->file_header + 24, overflow_entry_offset ? 0x400001U : 0x400000U);
    zip_stream_write_u64(state->file_header + 32, sizeof(state->file_header));
    zip_stream_write_u64(state->file_header + 40, state->section_offset);
    zip_stream_write_u16(state->file_header + 52, sizeof(state->file_header));
    zip_stream_write_u16(state->file_header + 54, sizeof(state->program_header));
    zip_stream_write_u16(state->file_header + 56, 1);
    zip_stream_write_u16(state->file_header + 58, sizeof(state->section_header));
    zip_stream_write_u16(state->file_header + 60, 1);

    zip_stream_write_u32(state->program_header + 0, 1); /* PT_LOAD */
    zip_stream_write_u32(state->program_header + 4, 5);
    zip_stream_write_u64(state->program_header + 8,
                         overflow_entry_offset ? UINT64_MAX : state->section_offset);
    zip_stream_write_u64(state->program_header + 16, 0x400000U);
    zip_stream_write_u64(state->program_header + 24, 0x400000U);
    zip_stream_write_u64(state->program_header + 32, 0x1000U);
    zip_stream_write_u64(state->program_header + 40, 0x1000U);
    zip_stream_write_u64(state->program_header + 48, 0x1000U);

    zip_stream_write_u32(state->section_header + 4, 1); /* SHT_PROGBITS */
    zip_stream_write_u64(state->section_header + 16, UINT64_C(0x100000000));
    zip_stream_write_u64(state->section_header + 24, state->section_offset);
    zip_stream_write_u64(state->section_header + 32, 0x100U);
}

START_TEST(test_elf64_metadata_preserves_native_coordinates)
{
    struct elf_large_metadata_state state;
    struct cli_exe_info exeinfo;
    struct cli_target_info target_info;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;
    uint64_t offdata[4] = {CLI_OFF_SX_PLUS, 0, 0, 0};
    uint64_t offset_min = CLI_OFF_NONE64;
    uint64_t offset_max = CLI_OFF_NONE64;

    if (sizeof(off_t) <= 4)
        return;

    elf_large_metadata_fixture_init(&state, 0);
    memset(&ctx, 0, sizeof(ctx));
    cli_exe_info_init(&exeinfo, 0);
    map = cl_fmap_open_handle(&state, 0, state.length, elf_large_metadata_pread_cb, 0);
    ck_assert_ptr_nonnull(map);
    ctx.fmap = map;

    ret = cli_elfheader(&ctx, &exeinfo);
    ck_assert_int_eq(ret, CL_SUCCESS);
    ck_assert(exeinfo.has_native_coordinates);
    ck_assert_ptr_nonnull(exeinfo.sections64);
    ck_assert_uint_eq(exeinfo.ep64, state.section_offset);
    ck_assert_uint_eq(exeinfo.sections64[0].raw, state.section_offset);
    ck_assert_uint_eq(exeinfo.sections64[0].rva, UINT64_C(0x100000000));
    ck_assert_uint_eq(exeinfo.ep, 0);
    ck_assert_uint_eq(exeinfo.sections[0].raw, 0);
    ck_assert(exeinfo.legacy_metadata_incomplete);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    memset(&target_info, 0, sizeof(target_info));
    target_info.fsize    = (off_t)state.length;
    target_info.status   = 1;
    target_info.exeinfo = exeinfo;
    ret = cli_caloff(NULL, &target_info, TARGET_ELF, offdata, &offset_min, &offset_max);
    ck_assert_int_eq(ret, CL_SUCCESS);
    ck_assert_uint_eq(offset_min, state.section_offset);

    cli_exe_info_destroy(&exeinfo);
    cl_fmap_close(map);
}
END_TEST

START_TEST(test_elf64_entry_offset_overflow_is_fail_visible)
{
    struct elf_large_metadata_state state;
    struct cl_scan_options options;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    if (sizeof(off_t) <= 4)
        return;

    elf_large_metadata_fixture_init(&state, 1);
    memset(&options, 0, sizeof(options));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_handle(&state, 0, state.length, elf_large_metadata_pread_cb, 0);
    ck_assert_ptr_nonnull(map);
    ctx.options = &options;
    ctx.fmap = map;

    ret = cli_scanelf(&ctx);
    ck_assert_int_eq(ret, CL_EFORMAT);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST
#endif

START_TEST(test_macho_truncated_header_is_fail_visible)
{
    static const uint8_t data[] = {0xfe, 0xed, 0xfa, 0xce};
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));

    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine = &engine;
    ctx.fmap   = map;

    ret = cli_scanmacho(&ctx, NULL);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_macho_time_limit_is_fail_visible)
{
    static const uint8_t data[] = {0};
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine = &engine;
    ctx.fmap   = map;
    ck_assert_int_eq(gettimeofday(&ctx.time_limit, NULL), 0);
    ctx.time_limit.tv_sec--;

    ret = cli_scanmacho(&ctx, NULL);
    ck_assert_int_eq(ret, CL_ETIMEOUT);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "Mach-O inspection reached the configured time limit");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_macho_unibin_time_limit_is_fail_visible)
{
    static const uint8_t data[] = {0};
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine = &engine;
    ctx.fmap   = map;
    ck_assert_int_eq(gettimeofday(&ctx.time_limit, NULL), 0);
    ctx.time_limit.tv_sec--;

    ret = cli_scanmacho_unibin(&ctx);
    ck_assert_int_eq(ret, CL_ETIMEOUT);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "Mach-O universal-binary inspection reached the configured time limit");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

static void macho_test_write_u32(uint8_t *dst, uint32_t value);

START_TEST(test_macho_metadata_read_failure_is_fail_visible)
{
    uint8_t data[32 + 8] = {0};
    struct cli_exe_info info;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    /* A confirmed Mach-O header points at a required load command whose
     * in-range fmap window fails. Metadata-only parsing must not stay clean. */
    macho_test_write_u32(data + 0, 0xfeedfacfU);
    macho_test_write_u32(data + 4, 0x01000007U); /* CPU_TYPE_X86_64. */
    macho_test_write_u32(data + 12, 2U);         /* MH_EXECUTE. */
    macho_test_write_u32(data + 16, 1U);         /* one load command. */
    macho_test_write_u32(data + 20, 8U);

    memset(&info, 0, sizeof(info));
    cli_exe_info_init(&info, 0);
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    map->need = macho_load_command_read_failure;
    ctx.fmap = map;

    ret = cli_machoheader(&ctx, &info);
    ck_assert_int_eq(ret, CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "Mach-O metadata parsing ended before inspection completed");
    ck_assert(map->dont_cache_flag);

    cli_exe_info_destroy(&info);
    cl_fmap_close(map);
}
END_TEST

START_TEST(test_macho_scan_load_command_read_failure_is_fail_visible)
{
    uint8_t data[32 + 8] = {0};
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    macho_test_write_u32(data + 0, 0xfeedfacfU);
    macho_test_write_u32(data + 4, 0x01000007U); /* CPU_TYPE_X86_64. */
    macho_test_write_u32(data + 12, 2U);         /* MH_EXECUTE. */
    macho_test_write_u32(data + 16, 1U);         /* one load command. */
    macho_test_write_u32(data + 20, 8U);

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    map->need = macho_load_command_read_failure;
    ctx.engine = &engine;
    ctx.fmap   = map;

    ret = cli_scanmacho(&ctx, NULL);
    ck_assert_int_eq(ret, CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "Mach-O load command could not be read completely");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

static void macho_test_write_u32(uint8_t *dst, uint32_t value)
{
    dst[0] = (uint8_t)value;
    dst[1] = (uint8_t)(value >> 8);
    dst[2] = (uint8_t)(value >> 16);
    dst[3] = (uint8_t)(value >> 24);
}

static void macho_test_write_u64(uint8_t *dst, uint64_t value)
{
    macho_test_write_u32(dst, (uint32_t)value);
    macho_test_write_u32(dst + 4, (uint32_t)(value >> 32));
}

START_TEST(test_macho_native_metadata_preserves_64bit_sections)
{
    enum {
        MACHO_HEADER_SIZE  = 32,
        LOAD_COMMAND_SIZE  = 8,
        SEGMENT64_SIZE     = 64,
        SECTION64_SIZE     = 80,
        ARCHIVE_SIZE       = MACHO_HEADER_SIZE + LOAD_COMMAND_SIZE + SEGMENT64_SIZE + SECTION64_SIZE
    };
    uint8_t data[ARCHIVE_SIZE] = {0};
    struct cli_exe_info info;
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;
    size_t section_offset = MACHO_HEADER_SIZE + LOAD_COMMAND_SIZE + SEGMENT64_SIZE;

    macho_test_write_u32(data + 0, 0xfeedfacfU);
    macho_test_write_u32(data + 4, 0x01000007U); /* CPU_TYPE_X86_64 */
    macho_test_write_u32(data + 12, 2U);         /* MH_EXECUTE */
    macho_test_write_u32(data + 16, 1U);         /* one load command */
    macho_test_write_u32(data + 20, LOAD_COMMAND_SIZE + SEGMENT64_SIZE + SECTION64_SIZE);
    macho_test_write_u32(data + MACHO_HEADER_SIZE, 0x19U); /* LC_SEGMENT_64 */
    macho_test_write_u32(data + MACHO_HEADER_SIZE + 4, LOAD_COMMAND_SIZE + SEGMENT64_SIZE + SECTION64_SIZE);
    macho_test_write_u32(data + MACHO_HEADER_SIZE + LOAD_COMMAND_SIZE + 56, 1U); /* nsects */
    macho_test_write_u64(data + section_offset + 16, UINT64_C(0x100000000)); /* addr */
    macho_test_write_u64(data + section_offset + 24, UINT64_C(0x100000000)); /* size */
    macho_test_write_u32(data + section_offset + 48, 0x200U);                 /* file offset */

    memset(&info, 0, sizeof(info));
    cli_exe_info_init(&info, 0);
    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine = &engine;
    ctx.fmap   = map;

    ret = cli_machoheader(&ctx, &info);
    ck_assert_int_eq(ret, CL_SUCCESS);
    ck_assert(info.has_native_coordinates);
    ck_assert_ptr_nonnull(info.sections64);
    ck_assert_uint_eq(info.sections64[0].rva, UINT64_C(0x100000000));
    ck_assert_uint_eq(info.sections64[0].vsz, UINT64_C(0x100000000));
    ck_assert(info.legacy_metadata_incomplete);
    ck_assert_uint_eq(info.sections[0].rva, 0);
    ck_assert_uint_eq(info.sections[0].vsz, 0);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cli_exe_info_destroy(&info);
    cl_fmap_close(map);
}
END_TEST

#if SIZE_MAX > UINT32_MAX
struct macho_unibin_range_state {
    size_t length;
    uint8_t data[8U + 20U]; /* fat_header plus one fat_arch */
};

static off_t macho_unibin_range_pread_cb(void *handle, void *buf, size_t count, off_t offset)
{
    struct macho_unibin_range_state *state = handle;
    size_t source_length;

    if (offset < 0 || (uint64_t)offset >= state->length)
        return 0;
    if (count > state->length - (size_t)offset)
        count = state->length - (size_t)offset;

    memset(buf, 0, count);
    if ((size_t)offset < sizeof(state->data)) {
        source_length = sizeof(state->data) - (size_t)offset;
        if (source_length > count)
            source_length = count;
        memcpy(buf, state->data + (size_t)offset, source_length);
    }
    return (off_t)count;
}

START_TEST(test_macho_unibin_member_range_is_fail_visible)
{
    struct macho_unibin_range_state state;
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&state, 0, sizeof(state));
    state.length = (size_t)UINT32_MAX;
    macho_test_write_u32(state.data + 0, 0xcafebabeU);
    macho_test_write_u32(state.data + 4, 1U);
    macho_test_write_u32(state.data + 8 + 8, UINT32_MAX - 8U);
    macho_test_write_u32(state.data + 8 + 12, 16U);

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_handle(&state, 0, state.length, macho_unibin_range_pread_cb, 0);
    ck_assert_ptr_nonnull(map);
    ctx.engine = &engine;
    ctx.fmap   = map;

    ret = cli_scanmacho_unibin(&ctx);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "Mach-O universal-binary architecture range is outside the input map");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST
#endif

START_TEST(test_macho_section_alignment_exponent_is_fail_visible)
{
    enum {
        MACHO_HEADER_SIZE  = 32,
        LOAD_COMMAND_SIZE  = 8,
        SEGMENT64_SIZE     = 64,
        SECTION64_SIZE     = 80,
        ARCHIVE_SIZE       = MACHO_HEADER_SIZE + LOAD_COMMAND_SIZE + SEGMENT64_SIZE + SECTION64_SIZE
    };
    uint8_t data[ARCHIVE_SIZE] = {0};
    struct cl_engine engine;
    struct cl_scan_options options;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    /* A complete 64-bit LC_SEGMENT_64/section_64 with align == 32 reaches
     * the guarded shift; a truncated header would only test earlier bounds. */
    macho_test_write_u32(data + 0, 0xfeedfacfU);
    macho_test_write_u32(data + 4, 0x01000007U); /* CPU_TYPE_X86_64 */
    macho_test_write_u32(data + 12, 2U);         /* MH_EXECUTE */
    macho_test_write_u32(data + 16, 1U);         /* one load command */
    macho_test_write_u32(data + 20, LOAD_COMMAND_SIZE + SEGMENT64_SIZE + SECTION64_SIZE);
    macho_test_write_u32(data + MACHO_HEADER_SIZE, 0x19U); /* LC_SEGMENT_64 */
    macho_test_write_u32(data + MACHO_HEADER_SIZE + 4, LOAD_COMMAND_SIZE + SEGMENT64_SIZE + SECTION64_SIZE);
    macho_test_write_u32(data + MACHO_HEADER_SIZE + LOAD_COMMAND_SIZE + 56, 1U); /* nsects */
    macho_test_write_u32(data + MACHO_HEADER_SIZE + LOAD_COMMAND_SIZE + SEGMENT64_SIZE + 52, 32U);

    memset(&engine, 0, sizeof(engine));
    memset(&options, 0, sizeof(options));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine = &engine;
    ctx.options = &options;
    ctx.fmap   = map;

    ret = cli_scanmacho(&ctx, NULL);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_udf_truncated_descriptor_area_is_fail_visible)
{
    static const uint8_t data[] = {0};
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine = &engine;
    ctx.fmap   = map;

    ret = cli_scanudf(&ctx, UDF_EMPTY_LEN);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_udf_time_limit_is_fail_visible)
{
    static const uint8_t data[] = {0};
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine = &engine;
    ctx.fmap   = map;
    ck_assert_int_eq(gettimeofday(&ctx.time_limit, NULL), 0);
    ctx.time_limit.tv_sec--;

    ret = cli_scanudf(&ctx, UDF_EMPTY_LEN);
    ck_assert_int_eq(ret, CL_ETIMEOUT);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "UDF inspection reached the configured time limit");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

struct udf_descriptor_read_failure_state {
    const uint8_t *data;
    size_t length;
    off_t fail_offset;
};

static off_t udf_descriptor_read_failure_cb(void *handle, void *buf, size_t count, off_t offset)
{
    struct udf_descriptor_read_failure_state *state = handle;

    if (offset >= 0 && (uint64_t)offset <= (uint64_t)state->fail_offset &&
        count > (size_t)((uint64_t)state->fail_offset - (uint64_t)offset))
        return -1;
    if (offset < 0 || (uint64_t)offset >= state->length)
        return 0;
    if (count > state->length - (size_t)offset)
        count = state->length - (size_t)offset;
    memcpy(buf, state->data + (size_t)offset, count);
    return (off_t)count;
}

START_TEST(test_udf_descriptor_read_failure_is_fail_visible)
{
    enum { UDF_TEST_SIZE = UDF_EMPTY_LEN + (3 * VOLUME_DESCRIPTOR_SIZE) };
    static const uint8_t data[UDF_TEST_SIZE] = {0};
    struct udf_descriptor_read_failure_state state;
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    state.data        = data;
    state.length      = sizeof(data);
    state.fail_offset = UDF_EMPTY_LEN;
    map                = cl_fmap_open_handle(&state, 0, state.length, udf_descriptor_read_failure_cb, 0);
    ck_assert_ptr_nonnull(map);

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    ctx.engine = &engine;
    ctx.fmap   = map;

    ret = cli_scanudf(&ctx, UDF_EMPTY_LEN);
    ck_assert_int_eq(ret, CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "UDF generic volume descriptor area could not be read completely");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

static void test_udf_set_generic_identifiers(uint8_t *data, size_t base)
{
    static const char identifiers[][5] = {"BEA01", "NSR02", "TEA01"};
    size_t i;

    for (i = 0; i < 3; i++) {
        memcpy(data + base + (i * VOLUME_DESCRIPTOR_SIZE) + offsetof(GenericVolumeStructureDescriptor, standardIdentifier),
               identifiers[i],
               sizeof(identifiers[i]));
    }
}

START_TEST(test_udf_unknown_generic_descriptor_is_fail_visible)
{
    enum {
        UDF_TEST_SIZE = UDF_EMPTY_LEN + (3 * VOLUME_DESCRIPTOR_SIZE)
    };
    uint8_t *data;
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    data = calloc(1, UDF_TEST_SIZE);
    ck_assert_ptr_nonnull(data);
    memcpy(data + UDF_EMPTY_LEN + offsetof(GenericVolumeStructureDescriptor, standardIdentifier), "BAD00", 5);

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, UDF_TEST_SIZE);
    ck_assert_ptr_nonnull(map);
    ctx.engine = &engine;
    ctx.fmap   = map;

    ret = cli_scanudf(&ctx, UDF_EMPTY_LEN);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "UDF generic volume descriptor identifier is unsupported");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    free(data);
}
END_TEST

START_TEST(test_udf_mismatched_file_lists_are_fail_visible)
{
    enum {
        UDF_TEST_VOLUME_BLOCKS = 15,
        UDF_TEST_SIZE          = UDF_EMPTY_LEN + (UDF_TEST_VOLUME_BLOCKS * VOLUME_DESCRIPTOR_SIZE),
        UDF_TEST_PRIMARY       = 1,
        UDF_TEST_IMPLEMENTATION_USE = 4,
        UDF_TEST_PARTITION     = 5,
        UDF_TEST_LOGICAL       = 6,
        UDF_TEST_UNALLOCATED   = 7,
        UDF_TEST_TERMINATING   = 8,
        UDF_TEST_LVID          = 9,
        UDF_TEST_ANCHOR        = 2,
        UDF_TEST_FILE_SET      = 256,
        UDF_TEST_FILE_IDENTIFIER = 257
    };
    uint8_t *data;
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    size_t base = UDF_EMPTY_LEN;
    cl_error_t ret;

    data = calloc(1, UDF_TEST_SIZE);
    ck_assert_ptr_nonnull(data);
    test_udf_set_generic_identifiers(data, base);

    /* The first three blocks are generic volume descriptors. The following
     * sequence supplies the required descriptor tags, then one file
     * identifier with no matching file entry. */
    data[base + (3 * VOLUME_DESCRIPTOR_SIZE)]       = UDF_TEST_PRIMARY & 0xff;
    data[base + (3 * VOLUME_DESCRIPTOR_SIZE) + 1]   = UDF_TEST_PRIMARY >> 8;
    data[base + (4 * VOLUME_DESCRIPTOR_SIZE)]       = UDF_TEST_IMPLEMENTATION_USE & 0xff;
    data[base + (4 * VOLUME_DESCRIPTOR_SIZE) + 1]   = UDF_TEST_IMPLEMENTATION_USE >> 8;
    data[base + (5 * VOLUME_DESCRIPTOR_SIZE)]       = UDF_TEST_LOGICAL & 0xff;
    data[base + (5 * VOLUME_DESCRIPTOR_SIZE) + 1]   = UDF_TEST_LOGICAL >> 8;
    data[base + (6 * VOLUME_DESCRIPTOR_SIZE)]       = UDF_TEST_PARTITION & 0xff;
    data[base + (6 * VOLUME_DESCRIPTOR_SIZE) + 1]   = UDF_TEST_PARTITION >> 8;
    data[base + (7 * VOLUME_DESCRIPTOR_SIZE)]       = UDF_TEST_UNALLOCATED & 0xff;
    data[base + (7 * VOLUME_DESCRIPTOR_SIZE) + 1]   = UDF_TEST_UNALLOCATED >> 8;
    data[base + (8 * VOLUME_DESCRIPTOR_SIZE)]       = UDF_TEST_TERMINATING & 0xff;
    data[base + (8 * VOLUME_DESCRIPTOR_SIZE) + 1]   = UDF_TEST_TERMINATING >> 8;
    data[base + (9 * VOLUME_DESCRIPTOR_SIZE)]       = UDF_TEST_LVID & 0xff;
    data[base + (9 * VOLUME_DESCRIPTOR_SIZE) + 1]   = UDF_TEST_LVID >> 8;
    data[base + (10 * VOLUME_DESCRIPTOR_SIZE)]      = UDF_TEST_TERMINATING & 0xff;
    data[base + (10 * VOLUME_DESCRIPTOR_SIZE) + 1]  = UDF_TEST_TERMINATING >> 8;
    data[base + (11 * VOLUME_DESCRIPTOR_SIZE)]      = UDF_TEST_ANCHOR & 0xff;
    data[base + (11 * VOLUME_DESCRIPTOR_SIZE) + 1]  = UDF_TEST_ANCHOR >> 8;
    data[base + (12 * VOLUME_DESCRIPTOR_SIZE)]      = UDF_TEST_FILE_SET & 0xff;
    data[base + (12 * VOLUME_DESCRIPTOR_SIZE) + 1]  = UDF_TEST_FILE_SET >> 8;
    data[base + (13 * VOLUME_DESCRIPTOR_SIZE)]      = UDF_TEST_FILE_IDENTIFIER & 0xff;
    data[base + (13 * VOLUME_DESCRIPTOR_SIZE) + 1]  = UDF_TEST_FILE_IDENTIFIER >> 8;
    data[base + (14 * VOLUME_DESCRIPTOR_SIZE)]      = 0xff;
    data[base + (14 * VOLUME_DESCRIPTOR_SIZE) + 1]  = 0x03;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, UDF_TEST_SIZE);
    ck_assert_ptr_nonnull(map);
    ctx.engine = &engine;
    ctx.fmap   = map;

    ret = cli_scanudf(&ctx, UDF_EMPTY_LEN);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "UDF file identifier and file entry counts do not match");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    free(data);
}
END_TEST

START_TEST(test_udf_allocation_descriptor_alignment_is_fail_visible)
{
    enum {
        UDF_TEST_VOLUME_BLOCKS       = 16,
        UDF_TEST_SIZE                = UDF_EMPTY_LEN + (UDF_TEST_VOLUME_BLOCKS * VOLUME_DESCRIPTOR_SIZE),
        UDF_TEST_PRIMARY             = 1,
        UDF_TEST_IMPLEMENTATION_USE  = 4,
        UDF_TEST_PARTITION           = 5,
        UDF_TEST_LOGICAL             = 6,
        UDF_TEST_UNALLOCATED         = 7,
        UDF_TEST_TERMINATING         = 8,
        UDF_TEST_LVID                = 9,
        UDF_TEST_ANCHOR              = 2,
        UDF_TEST_FILE_SET            = 256,
        UDF_TEST_FILE_IDENTIFIER     = 257,
        UDF_TEST_FILE_ENTRY          = 261,
        UDF_TEST_MALFORMED_ALLOC_LEN = 17
    };
    uint8_t *data;
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    size_t base = UDF_EMPTY_LEN;
    size_t fed_offset;
    cl_error_t ret;

    data = calloc(1, UDF_TEST_SIZE);
    ck_assert_ptr_nonnull(data);
    test_udf_set_generic_identifiers(data, base);

    /* Supply the required descriptor sequence, one file identifier, one
     * file entry, and a non-descriptor marker that triggers file extraction. */
    data[base + (3 * VOLUME_DESCRIPTOR_SIZE)]       = UDF_TEST_PRIMARY & 0xff;
    data[base + (3 * VOLUME_DESCRIPTOR_SIZE) + 1]   = UDF_TEST_PRIMARY >> 8;
    data[base + (4 * VOLUME_DESCRIPTOR_SIZE)]       = UDF_TEST_IMPLEMENTATION_USE & 0xff;
    data[base + (4 * VOLUME_DESCRIPTOR_SIZE) + 1]   = UDF_TEST_IMPLEMENTATION_USE >> 8;
    data[base + (5 * VOLUME_DESCRIPTOR_SIZE)]       = UDF_TEST_LOGICAL & 0xff;
    data[base + (5 * VOLUME_DESCRIPTOR_SIZE) + 1]   = UDF_TEST_LOGICAL >> 8;
    data[base + (6 * VOLUME_DESCRIPTOR_SIZE)]       = UDF_TEST_PARTITION & 0xff;
    data[base + (6 * VOLUME_DESCRIPTOR_SIZE) + 1]   = UDF_TEST_PARTITION >> 8;
    data[base + (7 * VOLUME_DESCRIPTOR_SIZE)]       = UDF_TEST_UNALLOCATED & 0xff;
    data[base + (7 * VOLUME_DESCRIPTOR_SIZE) + 1]   = UDF_TEST_UNALLOCATED >> 8;
    data[base + (8 * VOLUME_DESCRIPTOR_SIZE)]       = UDF_TEST_TERMINATING & 0xff;
    data[base + (8 * VOLUME_DESCRIPTOR_SIZE) + 1]   = UDF_TEST_TERMINATING >> 8;
    data[base + (9 * VOLUME_DESCRIPTOR_SIZE)]       = UDF_TEST_LVID & 0xff;
    data[base + (9 * VOLUME_DESCRIPTOR_SIZE) + 1]   = UDF_TEST_LVID >> 8;
    data[base + (10 * VOLUME_DESCRIPTOR_SIZE)]      = UDF_TEST_TERMINATING & 0xff;
    data[base + (10 * VOLUME_DESCRIPTOR_SIZE) + 1]  = UDF_TEST_TERMINATING >> 8;
    data[base + (11 * VOLUME_DESCRIPTOR_SIZE)]      = UDF_TEST_ANCHOR & 0xff;
    data[base + (11 * VOLUME_DESCRIPTOR_SIZE) + 1]  = UDF_TEST_ANCHOR >> 8;
    data[base + (12 * VOLUME_DESCRIPTOR_SIZE)]      = UDF_TEST_FILE_SET & 0xff;
    data[base + (12 * VOLUME_DESCRIPTOR_SIZE) + 1]  = UDF_TEST_FILE_SET >> 8;
    data[base + (13 * VOLUME_DESCRIPTOR_SIZE)]      = UDF_TEST_FILE_IDENTIFIER & 0xff;
    data[base + (13 * VOLUME_DESCRIPTOR_SIZE) + 1]  = UDF_TEST_FILE_IDENTIFIER >> 8;
    data[base + (14 * VOLUME_DESCRIPTOR_SIZE)]      = UDF_TEST_FILE_ENTRY & 0xff;
    data[base + (14 * VOLUME_DESCRIPTOR_SIZE) + 1]  = UDF_TEST_FILE_ENTRY >> 8;
    fed_offset = base + (14 * VOLUME_DESCRIPTOR_SIZE);
    data[fed_offset + offsetof(FileEntryDescriptor, allocationDescLen)]     = UDF_TEST_MALFORMED_ALLOC_LEN;
    data[fed_offset + offsetof(FileEntryDescriptor, allocationDescLen) + 1] = 0;
    data[base + (15 * VOLUME_DESCRIPTOR_SIZE)] = 0xff;
    data[base + (15 * VOLUME_DESCRIPTOR_SIZE) + 1] = 0x03;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, UDF_TEST_SIZE);
    ck_assert_ptr_nonnull(map);
    ctx.engine = &engine;
    ctx.fmap   = map;

    ret = cli_scanudf(&ctx, UDF_EMPTY_LEN);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "UDF allocation descriptor length is not aligned");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
    free(data);
}
END_TEST

static void test_hfsplus_put_be16(uint8_t *dst, uint16_t value)
{
    dst[0] = (uint8_t)(value >> 8);
    dst[1] = (uint8_t)value;
}

static void test_hfsplus_put_be32(uint8_t *dst, uint32_t value)
{
    dst[0] = (uint8_t)(value >> 24);
    dst[1] = (uint8_t)(value >> 16);
    dst[2] = (uint8_t)(value >> 8);
    dst[3] = (uint8_t)value;
}

static void test_hfsplus_put_be64(uint8_t *dst, uint64_t value)
{
    test_hfsplus_put_be32(dst, (uint32_t)(value >> 32));
    test_hfsplus_put_be32(dst + 4, (uint32_t)value);
}

static void test_hfsplus_tree_header(uint8_t *data, size_t offset, uint16_t node_size, uint16_t max_key_length)
{
    uint8_t *record = data + offset + sizeof(hfsNodeDescriptor);

    test_hfsplus_put_be32(data + offset + offsetof(hfsNodeDescriptor, fLink), 0);
    test_hfsplus_put_be32(data + offset + offsetof(hfsNodeDescriptor, bLink), 0);
    data[offset + offsetof(hfsNodeDescriptor, kind)] = HFS_NODEKIND_HEADER;
    data[offset + offsetof(hfsNodeDescriptor, height)] = 0;
    test_hfsplus_put_be16(data + offset + offsetof(hfsNodeDescriptor, numRecords), 3);
    test_hfsplus_put_be16(data + offset + offsetof(hfsNodeDescriptor, reserved), 0);

    test_hfsplus_put_be16(record + offsetof(hfsHeaderRecord, treeDepth), 0);
    test_hfsplus_put_be32(record + offsetof(hfsHeaderRecord, firstLeafNode), 0);
    test_hfsplus_put_be16(record + offsetof(hfsHeaderRecord, nodeSize), node_size);
    test_hfsplus_put_be16(record + offsetof(hfsHeaderRecord, maxKeyLength), max_key_length);
    test_hfsplus_put_be32(record + offsetof(hfsHeaderRecord, totalNodes), 1);
}

static void test_hfsplus_catalog_file_leaf(uint8_t *data, size_t offset)
{
    size_t record_offset = offset + sizeof(hfsNodeDescriptor);
    size_t file_offset   = record_offset + 6 + 2;

    memset(data + offset, 0, 4096);
    data[offset + offsetof(hfsNodeDescriptor, kind)]   = HFS_NODEKIND_LEAF;
    data[offset + offsetof(hfsNodeDescriptor, height)] = 1;
    test_hfsplus_put_be16(data + offset + offsetof(hfsNodeDescriptor, numRecords), 1);
    test_hfsplus_put_be16(data + record_offset, 6);
    test_hfsplus_put_be16(data + file_offset + offsetof(hfsPlusCatalogFile, recordType), HFSPLUS_RECTYPE_FILE);
    test_hfsplus_put_be32(data + file_offset + offsetof(hfsPlusCatalogFile, fileID), hfsFirstUserCatalogNodeID);
    test_hfsplus_put_be16(data + file_offset + offsetof(hfsPlusCatalogFile, permissions) + offsetof(hfsPlusBSDInfo, fileMode), HFS_MODE_FILE);
    test_hfsplus_put_be16(data + offset + 4096 - 2, (uint16_t)(record_offset - offset));
}

static void test_hfsplus_invalid_leaf(uint8_t *data, size_t offset)
{
    memset(data + offset, 0, 4096);
    data[offset + offsetof(hfsNodeDescriptor, kind)]   = HFS_NODEKIND_LEAF;
    data[offset + offsetof(hfsNodeDescriptor, height)] = 1;
    test_hfsplus_put_be16(data + offset + offsetof(hfsNodeDescriptor, numRecords), 1);
    /* A zero record offset is before the node descriptor and must fail. */
    test_hfsplus_put_be16(data + offset + 4096 - 2, 0);
}

START_TEST(test_hfsplus_declared_attributes_failure_is_fail_visible)
{
    uint8_t data[1024 + (32 * 512)];
    uint8_t *volume;
    uint8_t *fork;
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(data, 0, sizeof(data));
    volume = data + 1024;
    test_hfsplus_put_be16(volume + offsetof(hfsPlusVolumeHeader, signature), 0x482b);
    test_hfsplus_put_be16(volume + offsetof(hfsPlusVolumeHeader, version), 4);
    test_hfsplus_put_be32(volume + offsetof(hfsPlusVolumeHeader, blockSize), 512);
    test_hfsplus_put_be32(volume + offsetof(hfsPlusVolumeHeader, totalBlocks), 32);

    fork = volume + offsetof(hfsPlusVolumeHeader, extentsFile);
    test_hfsplus_put_be64(fork + offsetof(hfsPlusForkData, logicalSize), 512);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, totalBlocks), 1);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, extents) + offsetof(hfsPlusExtentDescriptor, startBlock), 4);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, extents) + offsetof(hfsPlusExtentDescriptor, blockCount), 1);

    fork = volume + offsetof(hfsPlusVolumeHeader, catalogFile);
    test_hfsplus_put_be64(fork + offsetof(hfsPlusForkData, logicalSize), 4096);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, totalBlocks), 8);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, extents) + offsetof(hfsPlusExtentDescriptor, startBlock), 8);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, extents) + offsetof(hfsPlusExtentDescriptor, blockCount), 8);

    /* A non-empty attributes fork whose first block is outside the map. */
    fork = volume + offsetof(hfsPlusVolumeHeader, attributesFile);
    test_hfsplus_put_be64(fork + offsetof(hfsPlusForkData, logicalSize), 512);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, totalBlocks), 1);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, extents) + offsetof(hfsPlusExtentDescriptor, startBlock), 100);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, extents) + offsetof(hfsPlusExtentDescriptor, blockCount), 1);

    test_hfsplus_tree_header(data, 4 * 512, 512, 10);
    test_hfsplus_tree_header(data, 8 * 512, 4096, 6);

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine = &engine;
    ctx.fmap   = map;

    ret = cli_scanhfsplus(&ctx);
    ck_assert_int_eq(ret, CL_EFORMAT);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_hfsplus_tree_header_read_failure_is_fail_visible)
{
    uint8_t data[1024 + (40 * 512)];
    uint8_t *volume;
    uint8_t *fork;
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(data, 0, sizeof(data));
    volume = data + 1024;
    test_hfsplus_put_be16(volume + offsetof(hfsPlusVolumeHeader, signature), 0x482b);
    test_hfsplus_put_be16(volume + offsetof(hfsPlusVolumeHeader, version), 4);
    test_hfsplus_put_be32(volume + offsetof(hfsPlusVolumeHeader, blockSize), 512);
    test_hfsplus_put_be32(volume + offsetof(hfsPlusVolumeHeader, totalBlocks), 40);

    fork = volume + offsetof(hfsPlusVolumeHeader, extentsFile);
    test_hfsplus_put_be64(fork + offsetof(hfsPlusForkData, logicalSize), 512);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, totalBlocks), 1);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, extents) + offsetof(hfsPlusExtentDescriptor, startBlock), 4);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, extents) + offsetof(hfsPlusExtentDescriptor, blockCount), 1);

    fork = volume + offsetof(hfsPlusVolumeHeader, catalogFile);
    test_hfsplus_put_be64(fork + offsetof(hfsPlusForkData, logicalSize), 8192);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, totalBlocks), 16);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, extents) + offsetof(hfsPlusExtentDescriptor, startBlock), 8);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, extents) + offsetof(hfsPlusExtentDescriptor, blockCount), 16);

    test_hfsplus_tree_header(data, 4 * 512, 512, 10);
    test_hfsplus_tree_header(data, 8 * 512, 4096, 6);

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    map->need = hfsplus_catalog_header_read_failure;
    ctx.engine = &engine;
    ctx.fmap   = map;

    ret = cli_scanhfsplus(&ctx);
    ck_assert_int_eq(ret, CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "HFS+ file-tree header could not be read completely");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_hfsplus_catalog_node_read_failure_is_fail_visible)
{
    uint8_t data[1024 + (40 * 512)];
    uint8_t *volume;
    uint8_t *fork;
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(data, 0, sizeof(data));
    volume = data + 1024;
    test_hfsplus_put_be16(volume + offsetof(hfsPlusVolumeHeader, signature), 0x482b);
    test_hfsplus_put_be16(volume + offsetof(hfsPlusVolumeHeader, version), 4);
    test_hfsplus_put_be32(volume + offsetof(hfsPlusVolumeHeader, blockSize), 512);
    test_hfsplus_put_be32(volume + offsetof(hfsPlusVolumeHeader, totalBlocks), 40);

    fork = volume + offsetof(hfsPlusVolumeHeader, extentsFile);
    test_hfsplus_put_be64(fork + offsetof(hfsPlusForkData, logicalSize), 512);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, totalBlocks), 1);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, extents) + offsetof(hfsPlusExtentDescriptor, startBlock), 4);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, extents) + offsetof(hfsPlusExtentDescriptor, blockCount), 1);

    fork = volume + offsetof(hfsPlusVolumeHeader, catalogFile);
    test_hfsplus_put_be64(fork + offsetof(hfsPlusForkData, logicalSize), 8192);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, totalBlocks), 16);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, extents) + offsetof(hfsPlusExtentDescriptor, startBlock), 8);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, extents) + offsetof(hfsPlusExtentDescriptor, blockCount), 16);

    test_hfsplus_tree_header(data, 4 * 512, 512, 10);
    test_hfsplus_tree_header(data, 8 * 512, 4096, 6);
    test_hfsplus_put_be32(data + (8 * 512) + sizeof(hfsNodeDescriptor) + offsetof(hfsHeaderRecord, firstLeafNode), 1);
    test_hfsplus_put_be32(data + (8 * 512) + sizeof(hfsNodeDescriptor) + offsetof(hfsHeaderRecord, totalNodes), 2);

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    map->need = hfsplus_catalog_node_read_failure;
    ctx.engine = &engine;
    ctx.fmap   = map;

    ret = cli_scanhfsplus(&ctx);
    ck_assert_int_eq(ret, CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "HFS+ file-tree node could not be read completely");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_hfsplus_fork_read_failure_is_fail_visible)
{
    uint8_t data[1024 + (40 * 512)];
    uint8_t *volume;
    uint8_t *fork;
    uint8_t *file;
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(data, 0, sizeof(data));
    volume = data + 1024;
    test_hfsplus_put_be16(volume + offsetof(hfsPlusVolumeHeader, signature), 0x482b);
    test_hfsplus_put_be16(volume + offsetof(hfsPlusVolumeHeader, version), 4);
    test_hfsplus_put_be32(volume + offsetof(hfsPlusVolumeHeader, blockSize), 512);
    test_hfsplus_put_be32(volume + offsetof(hfsPlusVolumeHeader, totalBlocks), 40);

    fork = volume + offsetof(hfsPlusVolumeHeader, extentsFile);
    test_hfsplus_put_be64(fork + offsetof(hfsPlusForkData, logicalSize), 512);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, totalBlocks), 1);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, extents) + offsetof(hfsPlusExtentDescriptor, startBlock), 4);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, extents) + offsetof(hfsPlusExtentDescriptor, blockCount), 1);

    fork = volume + offsetof(hfsPlusVolumeHeader, catalogFile);
    test_hfsplus_put_be64(fork + offsetof(hfsPlusForkData, logicalSize), 8192);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, totalBlocks), 16);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, extents) + offsetof(hfsPlusExtentDescriptor, startBlock), 8);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, extents) + offsetof(hfsPlusExtentDescriptor, blockCount), 16);

    test_hfsplus_tree_header(data, 4 * 512, 512, 10);
    test_hfsplus_tree_header(data, 8 * 512, 4096, 6);
    test_hfsplus_put_be32(data + (8 * 512) + sizeof(hfsNodeDescriptor) + offsetof(hfsHeaderRecord, firstLeafNode), 1);
    test_hfsplus_put_be32(data + (8 * 512) + sizeof(hfsNodeDescriptor) + offsetof(hfsHeaderRecord, totalNodes), 2);
    test_hfsplus_catalog_file_leaf(data, 16 * 512);
    file = data + (16 * 512) + sizeof(hfsNodeDescriptor) + 8;
    fork = file + offsetof(hfsPlusCatalogFile, dataFork);
    test_hfsplus_put_be64(fork + offsetof(hfsPlusForkData, logicalSize), 512);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, totalBlocks), 1);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, extents) + offsetof(hfsPlusExtentDescriptor, startBlock), 30);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, extents) + offsetof(hfsPlusExtentDescriptor, blockCount), 1);

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    map->need               = hfsplus_fork_read_failure;
    ctx.engine              = &engine;
    ctx.fmap                = map;
    ctx.this_layer_tmpdir   = tmpdir;

    ret = cli_scanhfsplus(&ctx);
    ck_assert_int_eq(ret, CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "HFS+ fork contents could not be read completely");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_hfsplus_attribute_tree_failure_is_fail_visible)
{
    uint8_t data[1024 + (40 * 512)];
    uint8_t *volume;
    uint8_t *fork;
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(data, 0, sizeof(data));
    volume = data + 1024;
    test_hfsplus_put_be16(volume + offsetof(hfsPlusVolumeHeader, signature), 0x482b);
    test_hfsplus_put_be16(volume + offsetof(hfsPlusVolumeHeader, version), 4);
    test_hfsplus_put_be32(volume + offsetof(hfsPlusVolumeHeader, blockSize), 512);
    test_hfsplus_put_be32(volume + offsetof(hfsPlusVolumeHeader, totalBlocks), 40);

    fork = volume + offsetof(hfsPlusVolumeHeader, extentsFile);
    test_hfsplus_put_be64(fork + offsetof(hfsPlusForkData, logicalSize), 512);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, totalBlocks), 1);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, extents) + offsetof(hfsPlusExtentDescriptor, startBlock), 4);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, extents) + offsetof(hfsPlusExtentDescriptor, blockCount), 1);

    fork = volume + offsetof(hfsPlusVolumeHeader, catalogFile);
    test_hfsplus_put_be64(fork + offsetof(hfsPlusForkData, logicalSize), 8192);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, totalBlocks), 16);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, extents) + offsetof(hfsPlusExtentDescriptor, startBlock), 8);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, extents) + offsetof(hfsPlusExtentDescriptor, blockCount), 16);

    fork = volume + offsetof(hfsPlusVolumeHeader, attributesFile);
    test_hfsplus_put_be64(fork + offsetof(hfsPlusForkData, logicalSize), 8192);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, totalBlocks), 16);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, extents) + offsetof(hfsPlusExtentDescriptor, startBlock), 24);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, extents) + offsetof(hfsPlusExtentDescriptor, blockCount), 16);

    test_hfsplus_tree_header(data, 4 * 512, 512, 10);
    test_hfsplus_tree_header(data, 8 * 512, 4096, 6);
    test_hfsplus_put_be32(data + (8 * 512) + sizeof(hfsNodeDescriptor) + offsetof(hfsHeaderRecord, firstLeafNode), 1);
    test_hfsplus_put_be32(data + (8 * 512) + sizeof(hfsNodeDescriptor) + offsetof(hfsHeaderRecord, totalNodes), 2);
    test_hfsplus_tree_header(data, 24 * 512, 4096, 0);
    test_hfsplus_put_be32(data + (24 * 512) + sizeof(hfsNodeDescriptor) + offsetof(hfsHeaderRecord, firstLeafNode), 1);
    test_hfsplus_put_be32(data + (24 * 512) + sizeof(hfsNodeDescriptor) + offsetof(hfsHeaderRecord, totalNodes), 2);
    test_hfsplus_catalog_file_leaf(data, 16 * 512);
    test_hfsplus_invalid_leaf(data, 32 * 512);

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine            = &engine;
    ctx.fmap              = map;
    ctx.this_layer_tmpdir = tmpdir;

    ret = cli_scanhfsplus(&ctx);
    ck_assert_int_eq(ret, CL_EFORMAT);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "HFS+ compressed-file attributes could not be inspected");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_hfsplus_catalog_size_accounting_is_fail_visible)
{
    uint8_t data[1024 + (32 * 512)];
    uint8_t *volume;
    uint8_t *fork;
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(data, 0, sizeof(data));
    volume = data + 1024;
    test_hfsplus_put_be16(volume + offsetof(hfsPlusVolumeHeader, signature), 0x482b);
    test_hfsplus_put_be16(volume + offsetof(hfsPlusVolumeHeader, version), 4);
    test_hfsplus_put_be32(volume + offsetof(hfsPlusVolumeHeader, blockSize), 512);
    test_hfsplus_put_be32(volume + offsetof(hfsPlusVolumeHeader, totalBlocks), 32);

    fork = volume + offsetof(hfsPlusVolumeHeader, extentsFile);
    test_hfsplus_put_be64(fork + offsetof(hfsPlusForkData, logicalSize), 512);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, totalBlocks), 1);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, extents) + offsetof(hfsPlusExtentDescriptor, startBlock), 4);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, extents) + offsetof(hfsPlusExtentDescriptor, blockCount), 1);

    fork = volume + offsetof(hfsPlusVolumeHeader, catalogFile);
    test_hfsplus_put_be64(fork + offsetof(hfsPlusForkData, logicalSize), 4096);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, totalBlocks), 8);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, extents) + offsetof(hfsPlusExtentDescriptor, startBlock), 8);
    test_hfsplus_put_be32(fork + offsetof(hfsPlusForkData, extents) + offsetof(hfsPlusExtentDescriptor, blockCount), 8);

    test_hfsplus_tree_header(data, 4 * 512, 512, 10);
    test_hfsplus_tree_header(data, 8 * 512, 4096, 6);
    /* 1 Mi nodes * 4096 bytes wraps a 32-bit product to zero. */
    test_hfsplus_put_be32(data + (8 * 512) + sizeof(hfsNodeDescriptor) + offsetof(hfsHeaderRecord, totalNodes), 0x00100000);

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine             = &engine;
    ctx.fmap               = map;
    ctx.this_layer_tmpdir  = tmpdir;

    ret = cli_scanhfsplus(&ctx);
    ck_assert_int_eq(ret, CL_EFORMAT);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_hfsplus_truncated_header_is_fail_visible)
{
    static const uint8_t data[] = {0};
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine = &engine;
    ctx.fmap   = map;

    ret = cli_scanhfsplus(&ctx);
    ck_assert_int_eq(ret, CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_hfsplus_time_limit_is_fail_visible)
{
    static const uint8_t data[] = {0};
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine = &engine;
    ctx.fmap   = map;
    ck_assert_int_eq(gettimeofday(&ctx.time_limit, NULL), 0);
    ctx.time_limit.tv_sec--;

    ret = cli_scanhfsplus(&ctx);
    ck_assert_int_eq(ret, CL_ETIMEOUT);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "HFS+ inspection reached the configured time limit");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_gif_truncated_blocks_are_fail_visible)
{
    static const uint8_t truncated_graphic_control_extension[] = {
        'G', 'I', 'F', '8', '9', 'a',
        0, 0, 0, 0, 0, 0, 0,
        0x21, 0xf9, 0x04, 0
    };
    static const uint8_t truncated_global_color_table[] = {
        'G', 'I', 'F', '8', '9', 'a',
        0, 0, 0, 0, 0, 0x80, 0
    };
    static const uint8_t truncated_extension_sub_block[] = {
        'G', 'I', 'F', '8', '9', 'a',
        0, 0, 0, 0, 0, 0, 0,
        0x21, 0xfe, 0x04, 0
    };
    static const uint8_t truncated_local_color_table[] = {
        'G', 'I', 'F', '8', '9', 'a',
        0, 0, 0, 0, 0, 0, 0,
        0x2c, 0, 0, 0, 0, 0, 0, 0, 0, 0x80
    };
    static const uint8_t truncated_lzw_minimum_code_size[] = {
        'G', 'I', 'F', '8', '9', 'a',
        0, 0, 0, 0, 0, 0, 0,
        0x2c, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    static const uint8_t missing_image_trailer[] = {
        'G', 'I', 'F', '8', '9', 'a',
        0, 0, 0, 0, 0, 0, 0,
        0x2c, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        2, 0
    };
    const uint8_t *cases[] = {
        truncated_graphic_control_extension,
        truncated_global_color_table,
        truncated_extension_sub_block,
        truncated_local_color_table,
        truncated_lzw_minimum_code_size,
        missing_image_trailer,
    };
    const size_t lengths[] = {
        sizeof(truncated_graphic_control_extension),
        sizeof(truncated_global_color_table),
        sizeof(truncated_extension_sub_block),
        sizeof(truncated_local_color_table),
        sizeof(truncated_lzw_minimum_code_size),
        sizeof(missing_image_trailer),
    };
    cli_ctx ctx;
    fmap_t *map;
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        memset(&ctx, 0, sizeof(ctx));
        map       = cl_fmap_open_memory(cases[i], lengths[i]);
        ck_assert_ptr_nonnull(map);
        ctx.fmap  = map;

        ck_assert_int_eq(cli_parsegif(&ctx), CL_EPARSE);
        ck_assert(ctx.scan_incomplete);
        ck_assert(map->dont_cache_flag);

        cl_fmap_close(map);
    }
}
END_TEST

START_TEST(test_gif_header_read_failures_are_fail_visible)
{
    static const uint8_t magic_input[]   = {'G', 'I', 'F'};
    static const uint8_t version_input[] = {'G', 'I', 'F', '8', '9', 'a'};
    cli_ctx ctx;
    fmap_t *map;

    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(magic_input, sizeof(magic_input));
    ck_assert_ptr_nonnull(map);
    map->need = embedded_header_read_failure;
    ctx.fmap   = map;
    ck_assert_int_eq(cli_parsegif(&ctx), CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "Heuristics.Broken.Media.GIF.CantReadMagic");
    ck_assert(map->dont_cache_flag);
    cl_fmap_close(map);

    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(version_input, sizeof(version_input));
    ck_assert_ptr_nonnull(map);
    map->need = gif_version_read_failure;
    ctx.fmap   = map;
    ck_assert_int_eq(cli_parsegif(&ctx), CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "Heuristics.Broken.Media.GIF.TruncatedVersion");
    ck_assert(map->dont_cache_flag);
    cl_fmap_close(map);
}
END_TEST

START_TEST(test_gif_block_timeout_is_fail_visible)
{
    static const uint8_t data[] = {
        'G', 'I', 'F', '8', '9', 'a',
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    cli_ctx ctx;
    fmap_t *map;

    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.fmap = map;
    ck_assert_int_eq(gettimeofday(&ctx.time_limit, NULL), 0);
    ctx.time_limit.tv_sec--;

    ck_assert_int_eq(cli_parsegif(&ctx), CL_ETIMEOUT);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "GIF block traversal reached the configured time limit");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_png_truncated_chunks_are_fail_visible)
{
    static const uint8_t missing_iend[] = {
        0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a,
        0, 0, 0, 13, 'I', 'H', 'D', 'R',
        0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0,
        0, 0, 0, 0,
    };
    static const uint8_t truncated_chunk_type[] = {
        0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a,
        0, 0, 0, 0,
    };
    static const uint8_t truncated_chunk_data[] = {
        0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a,
        0, 0, 0, 1, 'I', 'D', 'A', 'T',
    };
    static const uint8_t truncated_chunk_crc[] = {
        0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a,
        0, 0, 0, 0, 'I', 'E', 'N', 'D',
    };
    static const uint8_t invalid_iend_length[] = {
        0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a,
        0, 0, 0, 1, 'I', 'E', 'N', 'D', 0,
        0, 0, 0, 0,
    };
    const uint8_t *cases[] = {
        missing_iend,
        truncated_chunk_type,
        truncated_chunk_data,
        truncated_chunk_crc,
        invalid_iend_length,
    };
    const size_t lengths[] = {
        sizeof(missing_iend),
        sizeof(truncated_chunk_type),
        sizeof(truncated_chunk_data),
        sizeof(truncated_chunk_crc),
        sizeof(invalid_iend_length),
    };
    cli_ctx ctx;
    fmap_t *map;
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        memset(&ctx, 0, sizeof(ctx));
        map      = cl_fmap_open_memory(cases[i], lengths[i]);
        ck_assert_ptr_nonnull(map);
        ctx.fmap = map;

        ck_assert_int_eq(cli_parsepng(&ctx), CL_EPARSE);
        ck_assert(ctx.scan_incomplete);
        ck_assert(map->dont_cache_flag);

        cl_fmap_close(map);
    }
}
END_TEST

START_TEST(test_png_chunk_read_failure_is_fail_visible)
{
    static const uint8_t input[] = {
        0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a,
        0x00, 0x00, 0x00, 0x0d,
    };
    cli_ctx ctx;
    fmap_t *map;

    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(input, sizeof(input));
    ck_assert_ptr_nonnull(map);
    map->need = embedded_header_read_failure;
    ctx.fmap   = map;

    ck_assert_int_eq(cli_parsepng(&ctx), CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "PNG chunk length could not be read completely");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_png_chunk_timeout_is_fail_visible)
{
    static const uint8_t data[] = {
        0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a,
    };
    cli_ctx ctx;
    fmap_t *map;

    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.fmap = map;
    ck_assert_int_eq(gettimeofday(&ctx.time_limit, NULL), 0);
    ctx.time_limit.tv_sec--;

    ck_assert_int_eq(cli_parsepng(&ctx), CL_ETIMEOUT);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "PNG chunk traversal reached the configured time limit");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_png_large_ancillary_chunk_uses_bounded_mapping)
{
    /* This sparse fixture is deliberately larger than the historical 2 GiB
     * chunk-length rejection. The parser should validate and skip the
     * ancillary payload without borrowing it as one contiguous fmap window. */
    const uint8_t prefix[] = {
        0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a,
        0, 0, 0, 13, 'I', 'H', 'D', 'R',
        0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0,
        0, 0, 0, 0,
    };
    const uint8_t large_chunk_header[] = {
        0x80, 0, 0, 0, 't', 'E', 'X', 't',
    };
    const uint8_t crc[] = {0, 0, 0, 0};
    const uint8_t iend[] = {
        0, 0, 0, 0, 'I', 'E', 'N', 'D',
        0, 0, 0, 0,
    };
    const uint64_t chunk_data_length = UINT64_C(0x80000000);
    const uint64_t data_offset        = sizeof(prefix) + sizeof(large_chunk_header);
    const uint64_t crc_offset         = data_offset + chunk_data_length;
    const uint64_t iend_offset        = crc_offset + sizeof(crc);
    const uint64_t file_size          = iend_offset + sizeof(iend);
    char file_path[PATH_MAX];
    cli_ctx ctx;
    fmap_t *map;
    int fd;

    /* The first-release target is a 64-bit file/offset platform. Keep the
     * regression harmless for legacy 32-bit unit-test builds. */
    if (sizeof(size_t) <= 4 || sizeof(off_t) <= 4)
        return;

    snprintf(file_path, sizeof(file_path), "%s/png-large-ancillary-chunk", tmpdir);
    fd = open(file_path, O_RDWR | O_CREAT | O_TRUNC | O_BINARY, 0600);
    ck_assert_msg(fd >= 0, "open(%s) failed: %s", file_path, strerror(errno));
    ck_assert_int_eq(ftruncate(fd, (off_t)file_size), 0);

    ck_assert_int_eq(lseek(fd, 0, SEEK_SET), 0);
    ck_assert_int_eq(write(fd, prefix, sizeof(prefix)), (ssize_t)sizeof(prefix));
    ck_assert_int_eq(write(fd, large_chunk_header, sizeof(large_chunk_header)),
                     (ssize_t)sizeof(large_chunk_header));
    ck_assert_int_eq(lseek(fd, (off_t)crc_offset, SEEK_SET), (off_t)crc_offset);
    ck_assert_int_eq(write(fd, crc, sizeof(crc)), (ssize_t)sizeof(crc));
    ck_assert_int_eq(lseek(fd, (off_t)iend_offset, SEEK_SET), (off_t)iend_offset);
    ck_assert_int_eq(write(fd, iend, sizeof(iend)), (ssize_t)sizeof(iend));

    map = fmap_new(fd, 0, 0, file_path, NULL);
    ck_assert_ptr_nonnull(map);
    memset(&ctx, 0, sizeof(ctx));
    ctx.fmap = map;

    ck_assert_int_eq(cli_parsepng(&ctx), CL_SUCCESS);
    ck_assert(!ctx.scan_incomplete);

    cl_fmap_close(map);
    close(fd);
    unlink(file_path);
}
END_TEST

START_TEST(test_tiff_truncated_structures_are_fail_visible)
{
    static const uint8_t truncated_first_ifd_offset[] = {
        'I', 'I', 0x2a, 0x00,
        0x08, 0x00, 0x00,
    };
    static const uint8_t invalid_first_ifd_offset[] = {
        'I', 'I', 0x2a, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };
    static const uint8_t truncated_ifd_entry[] = {
        'I', 'I', 0x2a, 0x00,
        0x08, 0x00, 0x00, 0x00,
        0x01, 0x00,
    };
    static const uint8_t truncated_next_ifd_offset[] = {
        'I', 'I', 0x2a, 0x00,
        0x08, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
    };
    static const uint8_t out_of_range_ifd_value[] = {
        'I', 'I', 0x2a, 0x00,
        0x08, 0x00, 0x00, 0x00,
        0x01, 0x00,
        0x00, 0x01, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };
    const uint8_t *cases[] = {
        truncated_first_ifd_offset,
        invalid_first_ifd_offset,
        truncated_ifd_entry,
        truncated_next_ifd_offset,
        out_of_range_ifd_value,
    };
    const size_t lengths[] = {
        sizeof(truncated_first_ifd_offset),
        sizeof(invalid_first_ifd_offset),
        sizeof(truncated_ifd_entry),
        sizeof(truncated_next_ifd_offset),
        sizeof(out_of_range_ifd_value),
    };
    cli_ctx ctx;
    fmap_t *map;
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        memset(&ctx, 0, sizeof(ctx));
        map      = cl_fmap_open_memory(cases[i], lengths[i]);
        ck_assert_ptr_nonnull(map);
        ctx.fmap = map;

        ck_assert_int_eq(cli_parsetiff(&ctx), CL_EPARSE);
        ck_assert(ctx.scan_incomplete);
        ck_assert(map->dont_cache_flag);

        cl_fmap_close(map);
    }
}
END_TEST

START_TEST(test_tiff_initial_read_failure_is_fail_visible)
{
    static const uint8_t data[] = {'I', 'I', 0x2a, 0x00};
    cli_ctx ctx;
    fmap_t *map;

    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    map->need = embedded_header_read_failure;
    ctx.fmap   = map;

    ck_assert_int_eq(cli_parsetiff(&ctx), CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "TIFF magic could not be read completely");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_tiff_ifd_value_size_is_fail_visible)
{
    static const uint8_t data[] = {
        'I', 'I', 0x2a, 0x00,
        0x08, 0x00, 0x00, 0x00,
        0x01, 0x00,
        0x00, 0x01, 0x05, 0x00,
        0xff, 0xff, 0xff, 0xff,
        0x10, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };
    cli_ctx ctx;
    fmap_t *map;

    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.fmap = map;

    ck_assert_int_eq(cli_parsetiff(&ctx), CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_tiff_ifd_timeout_is_fail_visible)
{
    static const uint8_t data[] = {
        'I', 'I', 0x2a, 0x00,
        0x08, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };
    cli_ctx ctx;
    fmap_t *map;

    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.fmap = map;
    ck_assert_int_eq(gettimeofday(&ctx.time_limit, NULL), 0);
    ctx.time_limit.tv_sec--;

    ck_assert_int_eq(cli_parsetiff(&ctx), CL_ETIMEOUT);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "TIFF IFD traversal reached the configured time limit");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

#if SIZE_MAX > UINT32_MAX
struct tiff_large_cursor_state {
    size_t length;
    size_t max_offset;
    unsigned int header_reads;
};

static off_t tiff_large_cursor_pread_cb(void *handle, void *buf, size_t count, off_t offset)
{
    static const uint8_t prefix[] = {
        'I', 'I', 0x2a, 0x00,
        0xfe, 0xff, 0xff, 0xff,
    };
    struct tiff_large_cursor_state *state = handle;
    size_t copy_length;

    if (offset < 0 || (uint64_t)offset >= state->length)
        return 0;

    if ((size_t)offset > state->max_offset)
        state->max_offset = (size_t)offset;

    if (count > state->length - (size_t)offset)
        count = state->length - (size_t)offset;
    memset(buf, 0, count);

    if ((offset == 0 && state->header_reads++ == 0) ||
        (offset > 0 && (size_t)offset < sizeof(prefix))) {
        copy_length = MIN(count, sizeof(prefix) - (size_t)offset);
        memcpy(buf, prefix + (size_t)offset, copy_length);
    }

    return (off_t)count;
}

START_TEST(test_tiff_ifd_cursor_does_not_wrap_above_uint32)
{
    struct tiff_large_cursor_state state;
    cli_ctx ctx;
    fmap_t *map;

    memset(&state, 0, sizeof(state));
    state.length = (size_t)UINT32_MAX + 8U;
    memset(&ctx, 0, sizeof(ctx));

    map = cl_fmap_open_handle(&state, 0, state.length, tiff_large_cursor_pread_cb, 0);
    ck_assert_ptr_nonnull(map);
    ctx.fmap = map;

    ck_assert_int_eq(cli_parsetiff(&ctx), CL_CLEAN);
    ck_assert_msg(state.max_offset > (size_t)UINT32_MAX,
                  "TIFF IFD cursor wrapped below the 4 GiB boundary");

    cl_fmap_close(map);
}
END_TEST
#endif

START_TEST(test_jpeg_truncated_structures_are_fail_visible)
{
    static const uint8_t truncated_header[] = {
        0xff, 0xd8, 0xff,
    };
    static const uint8_t truncated_segment_size[] = {
        0xff, 0xd8, 0xff, 0xe0, 0x00,
    };
    static const uint8_t truncated_photoshop_resource[] = {
        0xff, 0xd8, 0xff, 0xed, 0x00, 0x14,
        'P',  'h',  'o',  't',  'o',  's',  'h',  'o',  'p',  ' ',
        '3',  '.',  '0',  '\0',
        '8',  'B',  'I',  'M',
    };
    const uint8_t *cases[] = {
        truncated_header,
        truncated_segment_size,
        truncated_photoshop_resource,
    };
    const size_t lengths[] = {
        sizeof(truncated_header),
        sizeof(truncated_segment_size),
        sizeof(truncated_photoshop_resource),
    };
    cli_ctx ctx;
    fmap_t *map;
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        memset(&ctx, 0, sizeof(ctx));
        map = cl_fmap_open_memory(cases[i], lengths[i]);
        ck_assert_ptr_nonnull(map);
        ctx.fmap = map;

        ck_assert_int_eq(cli_parsejpeg(&ctx), CL_EPARSE);
        ck_assert(ctx.scan_incomplete);
        ck_assert(map->dont_cache_flag);

        cl_fmap_close(map);
    }
}
END_TEST

START_TEST(test_jpeg_time_limit_is_fail_visible)
{
    static const uint8_t data[] = {0};
    struct cl_engine engine;
    cli_ctx ctx;
    fmap_t *map;
    cl_error_t ret;

    memset(&engine, 0, sizeof(engine));
    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine = &engine;
    ctx.fmap   = map;
    ck_assert_int_eq(gettimeofday(&ctx.time_limit, NULL), 0);
    ctx.time_limit.tv_sec--;

    ret = cli_parsejpeg(&ctx);
    ck_assert_int_eq(ret, CL_ETIMEOUT);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "JPEG inspection reached the configured time limit");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_jpeg_required_read_failure_is_fail_visible)
{
    static const uint8_t data[] = {0xff, 0xd8, 0xff, 0xe0};
    cli_ctx ctx;
    fmap_t *map;

    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    map->need = jpeg_required_read_failure;
    ctx.fmap = map;

    ck_assert_int_eq(cli_parsejpeg(&ctx), CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "Heuristics.Broken.Media.JPEG.CantReadHeader");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_jpeg_photoshop_exact_eof_is_complete)
{
    static const uint8_t data[] = {
        0xff, 0xd8, 0xff, 0xed, 0x00, 0x10,
        'P',  'h',  'o',  't',  'o',  's',  'h',  'o',  'p',  ' ',
        '3',  '.',  '0',  '\0',
    };
    cli_ctx ctx;
    fmap_t *map;

    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.fmap = map;

    ck_assert_int_eq(cli_parsejpeg(&ctx), CL_SUCCESS);
    ck_assert(!ctx.scan_incomplete);
    ck_assert(!map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

struct textnorm_pread_state {
    size_t length;
    off_t fail_at;
};

static off_t textnorm_pread_cb(void *handle, void *buf, size_t count, off_t offset)
{
    struct textnorm_pread_state *state = handle;

    if (offset >= state->fail_at) {
        errno = EIO;
        return -1;
    }
    if (offset < 0 || (uint64_t)offset >= state->length)
        return 0;
    if (count > state->length - (size_t)offset)
        count = state->length - (size_t)offset;
    memset(buf, 'A', count);
    return (off_t)count;
}

START_TEST(test_text_normalize_map_read_failure_is_fail_visible)
{
    struct textnorm_pread_state pread_state;
    struct text_norm_state state;
    unsigned char normalized[8192];
    fmap_t *map;
    size_t written;

    pread_state.length  = 8192;
    pread_state.fail_at = 4096;
    map = cl_fmap_open_handle(&pread_state, 0, pread_state.length, textnorm_pread_cb, 0);
    ck_assert_ptr_nonnull(map);
    ck_assert_int_eq(text_normalize_init(&state, normalized, sizeof(normalized)), CL_SUCCESS);

    written = text_normalize_map(&state, map, 0);
    ck_assert_uint_eq(written, 4096);
    ck_assert(state.read_error);
    ck_assert_int_eq(state.read_status, CL_EREAD);

    ck_assert_int_eq(text_normalize_init(&state, normalized, sizeof(normalized)), CL_SUCCESS);
    written = text_normalize_map(&state, map, pread_state.length + 1U);
    ck_assert_uint_eq(written, 0U);
    ck_assert(state.read_error);
    ck_assert_int_eq(state.read_status, CL_EPARSE);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_riff_truncated_chunk_is_fail_visible)
{
    static const uint8_t truncated_chunk[] = {
        'R', 'I', 'F', 'F',
        0x00, 0x00, 0x00, 0x00,
        'A', 'C', 'O', 'N',
    };
    cli_ctx ctx;
    fmap_t *map;

    memset(&ctx, 0, sizeof(ctx));
    map = cl_fmap_open_memory(truncated_chunk, sizeof(truncated_chunk));
    ck_assert_ptr_nonnull(map);
    ctx.fmap = map;

    ck_assert_int_eq(cli_check_riff_exploit(&ctx), CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

static void pe_icon_test_write_u16(uint8_t *dst, uint16_t value)
{
    dst[0] = (uint8_t)value;
    dst[1] = (uint8_t)(value >> 8);
}

static void pe_icon_test_write_u32(uint8_t *dst, uint32_t value)
{
    dst[0] = (uint8_t)value;
    dst[1] = (uint8_t)(value >> 8);
    dst[2] = (uint8_t)(value >> 16);
    dst[3] = (uint8_t)(value >> 24);
}

static const void *pe_icon_resource_read_failure(fmap_t *map, size_t at, size_t len, int lock)
{
    (void)map;
    (void)at;
    (void)len;
    (void)lock;
    return NULL;
}

START_TEST(test_pe_icon_truncated_resource_is_fail_visible)
{
    uint8_t data[256];
    struct cl_engine engine;
    struct icon_matcher matcher;
    struct cli_exe_section section;
    struct cli_exe_info peinfo;
    icon_groupset iconset;
    cli_ctx ctx;
    fmap_t *map;

    memset(data, 0, sizeof(data));
    memset(&engine, 0, sizeof(engine));
    memset(&matcher, 0, sizeof(matcher));
    memset(&section, 0, sizeof(section));
    memset(&peinfo, 0, sizeof(peinfo));
    memset(&ctx, 0, sizeof(ctx));

    /* Resource tree: type 3 (icon) and type 14 (icon group), each with one
     * language entry. The icon data entry points just beyond the map. */
    pe_icon_test_write_u16(data + 14, 2);
    pe_icon_test_write_u32(data + 16, 3);
    pe_icon_test_write_u32(data + 20, 0x80000020U);
    pe_icon_test_write_u32(data + 24, 14);
    pe_icon_test_write_u32(data + 28, 0x80000040U);

    pe_icon_test_write_u16(data + 0x20 + 14, 1);
    pe_icon_test_write_u32(data + 0x30, 1);
    pe_icon_test_write_u32(data + 0x34, 0x80000060U);

    pe_icon_test_write_u16(data + 0x40 + 14, 1);
    pe_icon_test_write_u32(data + 0x50, 1);
    pe_icon_test_write_u32(data + 0x54, 0x800000a0U);

    pe_icon_test_write_u16(data + 0x60 + 14, 1);
    pe_icon_test_write_u32(data + 0x70, 0);
    pe_icon_test_write_u32(data + 0x74, 0x80U);
    pe_icon_test_write_u32(data + 0x80, sizeof(data));
    pe_icon_test_write_u32(data + 0x84, 4);

    pe_icon_test_write_u16(data + 0xa0 + 14, 1);
    pe_icon_test_write_u32(data + 0xb0, 1);
    pe_icon_test_write_u32(data + 0xb4, 0xc0U);
    pe_icon_test_write_u32(data + 0xc0, 0xe0U);
    pe_icon_test_write_u32(data + 0xc4, 20);
    pe_icon_test_write_u16(data + 0xe2, 1);
    pe_icon_test_write_u16(data + 0xe4, 1);
    pe_icon_test_write_u16(data + 0xec, 32);
    pe_icon_test_write_u16(data + 0xf2, 1);

    section.rsz          = sizeof(data);
    peinfo.sections      = &section;
    peinfo.nsections     = 1;
    peinfo.ndatadirs     = 3;
    peinfo.dirs[2].VirtualAddress = 0;
    peinfo.hdr_size      = 0;
    engine.maxiconspe    = 100;
    engine.iconcheck     = &matcher;

    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine = &engine;
    ctx.fmap   = map;
    cli_icongroupset_init(&iconset);

    ck_assert_int_eq(cli_scanicon(&iconset, &ctx, &peinfo), CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_pe_icon_bitmap_header_range_is_fail_visible)
{
    uint8_t data[1024];
    struct cl_engine engine;
    struct icon_matcher matcher;
    struct cli_exe_section section;
    struct cli_exe_info peinfo;
    icon_groupset iconset;
    cli_ctx ctx;
    fmap_t *map;

    memset(data, 0, sizeof(data));
    memset(&engine, 0, sizeof(engine));
    memset(&matcher, 0, sizeof(matcher));
    memset(&section, 0, sizeof(section));
    memset(&peinfo, 0, sizeof(peinfo));
    memset(&ctx, 0, sizeof(ctx));

    /* Resource tree: type 3 (icon) and type 14 (icon group), each with one
     * language entry. The icon data entry points at a bitmap header whose
     * declared size wraps a 32-bit file offset in the old implementation. */
    pe_icon_test_write_u16(data + 14, 2);
    pe_icon_test_write_u32(data + 16, 3);
    pe_icon_test_write_u32(data + 20, 0x80000020U);
    pe_icon_test_write_u32(data + 24, 14);
    pe_icon_test_write_u32(data + 28, 0x80000040U);

    pe_icon_test_write_u16(data + 0x20 + 14, 1);
    pe_icon_test_write_u32(data + 0x30, 1);
    pe_icon_test_write_u32(data + 0x34, 0x80000060U);

    pe_icon_test_write_u16(data + 0x40 + 14, 1);
    pe_icon_test_write_u32(data + 0x50, 1);
    pe_icon_test_write_u32(data + 0x54, 0x800000a0U);

    pe_icon_test_write_u16(data + 0x60 + 14, 1);
    pe_icon_test_write_u32(data + 0x70, 0);
    pe_icon_test_write_u32(data + 0x74, 0x80U);
    pe_icon_test_write_u32(data + 0x80, 0x100U);
    pe_icon_test_write_u32(data + 0x84, 4);

    pe_icon_test_write_u16(data + 0xa0 + 14, 1);
    pe_icon_test_write_u32(data + 0xb0, 1);
    pe_icon_test_write_u32(data + 0xb4, 0xc0U);
    pe_icon_test_write_u32(data + 0xc0, 0xe0U);
    pe_icon_test_write_u32(data + 0xc4, 20);
    pe_icon_test_write_u16(data + 0xe2, 1);
    pe_icon_test_write_u16(data + 0xe4, 1);
    pe_icon_test_write_u16(data + 0xec, 32);
    pe_icon_test_write_u16(data + 0xf2, 1);

    pe_icon_test_write_u32(data + 0x100, UINT32_MAX);
    pe_icon_test_write_u32(data + 0x104, 16);
    pe_icon_test_write_u32(data + 0x108, 32);
    pe_icon_test_write_u16(data + 0x10c, 1);
    pe_icon_test_write_u16(data + 0x10e, 1);

    section.rsz                   = sizeof(data);
    peinfo.sections               = &section;
    peinfo.nsections              = 1;
    peinfo.ndatadirs              = 3;
    peinfo.dirs[2].VirtualAddress = 0;
    peinfo.hdr_size               = 0;
    engine.maxiconspe             = 100;
    engine.iconcheck              = &matcher;

    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    ctx.engine = &engine;
    ctx.fmap   = map;
    cli_icongroupset_init(&iconset);

    ck_assert_int_eq(cli_scanicon(&iconset, &ctx, &peinfo), CL_EPARSE);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "PE icon bitmap header extends beyond the input map");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST

START_TEST(test_pe_icon_resource_tree_read_failure_is_fail_visible)
{
    uint8_t data[256] = {0};
    struct cl_engine engine;
    struct icon_matcher matcher;
    struct cli_exe_section section;
    struct cli_exe_info peinfo;
    icon_groupset iconset;
    cli_ctx ctx;
    fmap_t *map;

    memset(&engine, 0, sizeof(engine));
    memset(&matcher, 0, sizeof(matcher));
    memset(&section, 0, sizeof(section));
    memset(&peinfo, 0, sizeof(peinfo));
    memset(&ctx, 0, sizeof(ctx));

    section.rsz                   = sizeof(data);
    peinfo.sections               = &section;
    peinfo.nsections              = 1;
    peinfo.ndatadirs              = 3;
    peinfo.dirs[2].VirtualAddress = 0;
    peinfo.hdr_size               = 0;
    engine.maxiconspe             = 100;
    engine.iconcheck              = &matcher;

    map = cl_fmap_open_memory(data, sizeof(data));
    ck_assert_ptr_nonnull(map);
    map->need  = pe_icon_resource_read_failure;
    ctx.engine = &engine;
    ctx.fmap   = map;
    cli_icongroupset_init(&iconset);

    ck_assert_int_eq(cli_scanicon(&iconset, &ctx, &peinfo), CL_EREAD);
    ck_assert(ctx.scan_incomplete);
    ck_assert_str_eq(ctx.scan_incomplete_reason, "PE icon resource tree could not be read completely");
    ck_assert(map->dont_cache_flag);

    cl_fmap_close(map);
}
END_TEST
#endif

static Suite *test_cl_suite(void)
{
    Suite *s           = suite_create("cl_suite");
    TCase *tc_cl       = tcase_create("cl_api");
#if !defined(_WIN32) && SIZE_MAX > UINT32_MAX
    TCase *tc_largefile;
#endif
    TCase *tc_cl_scan  = tcase_create("cl_scan_api");
    TCase *tc_dmg      = tcase_create("dmg");
    TCase *tc_gif      = tcase_create("gif");
    TCase *tc_png      = tcase_create("png");
    TCase *tc_tiff     = tcase_create("tiff");
    TCase *tc_pdf      = tcase_create("pdf");
    TCase *tc_hwp3     = tcase_create("hwp3");
    TCase *tc_xar      = tcase_create("xar");
    TCase *tc_hwpml    = tcase_create("hwpml");
    char *user_timeout = NULL;
    int expect         = expected_testfiles;
    suite_add_tcase(s, tc_cl);
    tcase_add_checked_fixture(tc_cl, cl_setup, cl_teardown);
#if !defined(_WIN32) && SIZE_MAX > UINT32_MAX
    if (getenv("CLAMAV_LARGEFILE_QUALIFY") != NULL) {
        tc_largefile = tcase_create("largefile_qualification");
        suite_add_tcase(s, tc_largefile);
        tcase_add_checked_fixture(tc_largefile, cl_setup, cl_teardown);
        tcase_add_test(tc_largefile, test_library_exact_32g_tail_detection);
    }
#endif
    suite_add_tcase(s, tc_dmg);
    tcase_add_checked_fixture(tc_dmg, cl_setup, cl_teardown);
    suite_add_tcase(s, tc_gif);
    suite_add_tcase(s, tc_png);
    suite_add_tcase(s, tc_tiff);
    suite_add_tcase(s, tc_pdf);
    tcase_add_checked_fixture(tc_pdf, cl_setup, cl_teardown);
    suite_add_tcase(s, tc_hwp3);
    suite_add_tcase(s, tc_xar);
    suite_add_tcase(s, tc_hwpml);
    tcase_add_checked_fixture(tc_hwpml, cl_setup, cl_teardown);
    tcase_add_test(tc_dmg, test_dmg_strict_base64_and_terminal_end_validation);
    tcase_add_test(tc_dmg, test_dmg_malformed_metadata_is_fail_visible);
    tcase_add_test(tc_dmg, test_dmg_trailer_read_failure_is_fail_visible);
    tcase_add_test(tc_dmg, test_dmg_invalid_trailer_is_fail_visible);
    tcase_add_test(tc_cl, test_cl_free);
    tcase_add_test(tc_cl, test_cl_build);
    tcase_add_test(tc_cl, test_cl_debug);
#ifndef _WIN32
    tcase_add_test(tc_cl, test_cl_retdbdir);
#endif
    tcase_add_test(tc_cl, test_cl_fmap_set_hash_accepts_full_hash);
    tcase_add_test(tc_cl, test_cl_fmap_get_data_clamps_wrapped_length);
#ifndef _WIN32
    tcase_add_test(tc_cl, test_html_normalize_cap_is_fail_visible);
    tcase_add_test(tc_cl, test_html_normalize_cap_does_not_skip_raw_matching);
    tcase_add_test(tc_cl, test_html_notags_cap_is_fail_visible);
    tcase_add_test(tc_cl, test_html_notags_cap_uses_generated_size);
#ifdef CLAMAV_TEST_JS_IO_WRAP
    tcase_add_test(tc_cl, test_html_normalize_cleanup_close_failure_is_fail_visible);
#endif
#endif
    tcase_add_test(tc_cl, test_cl_retver);
    tcase_add_test(tc_cl, test_cl_cvdfree);
    tcase_add_test(tc_cl, test_cl_statfree);
    tcase_add_test(tc_cl, test_cl_retflevel);
    tcase_add_test(tc_cl, test_cl_cvdhead);
    tcase_add_test(tc_cl, test_cl_cvdparse);
    tcase_add_test(tc_cl, test_cl_load);
    tcase_add_test(tc_cl, test_cl_cvdverify);
    tcase_add_test(tc_cl, test_cl_statinidir);
    tcase_add_test(tc_cl, test_cl_statchkdir);
    tcase_add_test(tc_cl, test_cl_settempdir);
    tcase_add_test(tc_cl, test_cl_strerror);
    tcase_add_test(tc_cl, test_top_level_maxfilesize_is_fail_visible);
    tcase_add_test(tc_cl, test_maxscansize_exact_and_crossing_are_fail_visible);
    tcase_add_test(tc_cl, test_logical_views_do_not_consume_logical_scan_budget);
    tcase_add_test(tc_cl, test_maxfiles_exact_and_crossing_are_fail_visible);
    tcase_add_test(tc_cl, test_mbox_nested_maxfiles_is_fail_visible);
    tcase_add_test(tc_cl, test_scan_report_complete_and_json);
    tcase_add_test(tc_cl, test_scan_report_detection_precedes_incomplete_state);
    tcase_add_test(tc_cl, test_scan_report_unsupported_encryption_is_not_malformed);
    tcase_add_test(tc_cl, test_scan_report_unsupported_decoder_statuses_are_unsupported);
    tcase_add_test(tc_cl, test_scan_report_break_is_application_abort);
    tcase_add_test(tc_cl, test_scan_report_operational_failure_is_resource_failure);
    tcase_add_test(tc_cl, test_scan_report_sticky_resource_failure_is_not_a_scan_limit);
    tcase_add_test(tc_cl, test_scan_report_counts_skipped_operations);
    tcase_add_test(tc_cl, test_scan_report_post_scan_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_scan_report_merge_preserves_detection_and_peaks);
    tcase_add_test(tc_cl, test_descriptor_temporary_reservation_is_reported);
    tcase_add_test(tc_cl, test_scanfile_temporary_reservation_is_reported);
    tcase_add_test(tc_cl, test_resource_limit_engine_fields_and_accounting);
    tcase_add_test(tc_cl, test_largefile_default_profile_values);
    tcase_add_test(tc_cl, test_fileblob_temporary_spool_accounting);
    tcase_add_test(tc_cl, test_fileblob_scan_errors_are_fail_visible);
    tcase_add_test(tc_cl, test_parser_gate_limits_reject_above_32g);
    tcase_add_test(tc_cl, test_engine_set_num_rejects_narrowing_and_negative_values);
    tcase_add_test(tc_cl, test_maxrecursion_exact_and_crossing_are_fail_visible);
    tcase_add_test(tc_cl, test_configured_limit_result_precedence_and_alert_compatibility);
    tcase_add_test(tc_cl, test_legacy_callback_errors_are_fail_visible);
    tcase_add_test(tc_cl, test_scan_callback_errors_are_fail_visible);
    tcase_add_test(tc_cl, test_callback_abort_is_not_reported_as_timeout);
    tcase_add_test(tc_cl, test_timeout_policy_is_fail_visible);
    tcase_add_test(tc_cl, test_parser_error_statuses_are_fail_closed);
    tcase_add_test(tc_cl, test_sequential_parser_status_merge_is_fail_closed);
    tcase_add_test(tc_cl, test_fmap_ffi_layout);
    tcase_add_test(tc_cl, test_format_width_limits_are_fail_visible);
    tcase_add_test(tc_cl, test_hwpole2_declared_size_mismatch_is_fail_visible);
    tcase_add_test(tc_hwpml, test_hwpml_truncated_document_is_fail_visible);
    tcase_add_test(tc_cl, test_legacy_parser_limit_returns_are_fail_visible);
    tcase_add_test(tc_cl, test_msexpand_truncated_output_is_fail_visible);
    tcase_add_test(tc_cl, test_msexpand_time_limit_is_fail_visible);
    tcase_add_test(tc_cl, test_fileblob_cleanup_failures_are_fail_visible);
    tcase_add_test(tc_cl, test_tnef_truncated_header_is_fail_visible);
    tcase_add_test(tc_cl, test_tnef_short_header_is_fail_visible);
    tcase_add_test(tc_cl, test_tnef_message_body_is_fail_visible);
    tcase_add_test(tc_cl, test_tnef_attachment_temporary_limit_is_fail_visible);
    tcase_add_test(tc_cl, test_uuencode_truncated_attachment_is_fail_visible);
    tcase_add_test(tc_cl, test_uuencode_temporary_limit_is_fail_visible);
    tcase_add_test(tc_cl, test_mbox_truncated_uuencode_is_fail_visible);
    tcase_add_test(tc_cl, test_mbox_truncated_binhex_is_fail_visible);
    tcase_add_test(tc_cl, test_binhex_truncated_header_is_fail_visible);
    tcase_add_test(tc_cl, test_binhex_time_limit_is_fail_visible);
    tcase_add_test(tc_cl, test_binhex_truncated_data_fork_is_fail_visible);
    tcase_add_test(tc_cl, test_binhex_short_resource_fork_is_fail_visible);
    tcase_add_test(tc_cl, test_binhex_output_temporary_limit_is_fail_visible);
#ifdef CLAMAV_TEST_JS_IO_WRAP
    tcase_add_test(tc_cl, test_binhex_cleanup_close_failure_is_fail_visible);
#endif
    tcase_add_test(tc_cl, test_sis_truncated_contents_is_fail_visible);
    tcase_add_test(tc_cl, test_sis_name_table_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_python_compiled_parser_is_explicitly_unsupported);
    tcase_add_test(tc_cl, test_ai_model_parser_is_explicitly_unsupported);
    tcase_add_test(tc_cl, test_graphics_bmp_truncated_header_is_fail_visible);
    tcase_add_test(tc_cl, test_bmp_missing_uncompressed_pixel_range_is_malformed);
    tcase_add_test(tc_cl, test_bmp_structural_admission_remains_incomplete);
    tcase_add_test(tc_cl, test_jp2_truncated_box_is_fail_visible);
    tcase_add_test(tc_cl, test_jp2_time_limit_is_fail_visible);
    tcase_add_test(tc_cl, test_jp2_structural_admission_remains_incomplete);
    tcase_add_test(tc_cl, test_generic_graphics_parser_is_explicitly_unsupported);
    tcase_add_test(tc_cl, test_sis_truncated_compressed_member_is_fail_visible);
    tcase_add_test(tc_cl, test_sis_compressed_member_streams_to_nested_scan);
    tcase_add_test(tc_cl, test_sis_member_limit_is_fail_visible);
    tcase_add_test(tc_cl, test_sis_member_header_offset_is_fail_visible);
    tcase_add_test(tc_cl, test_tar_truncated_header_is_fail_visible);
    tcase_add_test(tc_cl, test_tar_initial_header_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_tar_invalid_magic_is_fail_visible);
    tcase_add_test(tc_cl, test_tar_temporary_limit_is_fail_visible);
    tcase_add_test(tc_cl, test_cpio_time_limit_is_fail_visible);
    tcase_add_test(tc_cl, test_cpio_truncated_header_is_fail_visible);
    tcase_add_test(tc_cl, test_cpio_member_name_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_cpio_impossible_next_header_is_parse_error);
    tcase_add_test(tc_cl, test_cpio_initial_read_failure_is_read_error);
    tcase_add_test(tc_cl, test_parser_temporary_directory_failures_are_fail_visible);
    tcase_add_test(tc_cl, test_iso_truncated_directory_is_fail_visible);
    tcase_add_test(tc_cl, test_iso_time_limit_is_fail_visible);
    tcase_add_test(tc_cl, test_iso_volume_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_iso_unsupported_extent_layouts_are_fail_visible);
    tcase_add_test(tc_cl, test_iso_directory_coordinate_overflow_is_fail_visible);
    tcase_add_test(tc_cl, test_xar_truncated_header_is_fail_visible);
    tcase_add_test(tc_xar, test_xar_time_limit_is_fail_visible);
    tcase_add_test(tc_xar, test_xar_invalid_file_metadata_is_fail_visible);
    tcase_add_test(tc_xar, test_xar_xml_reader_error_is_fail_visible);
    tcase_add_test(tc_xar, test_xar_toc_temporary_quota_is_fail_visible);
    tcase_add_test(tc_xar, test_xar_subdocument_temporary_quota_is_fail_visible);
    tcase_add_test(tc_cl, test_partition_parser_errors_are_fail_visible);
    tcase_add_test(tc_cl, test_mbr_partition_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_gpt_partition_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_mbr_partition_limit_is_fail_visible);
    tcase_add_test(tc_cl, test_apm_partition_limit_is_fail_visible);
    tcase_add_test(tc_cl, test_apm_invalid_partition_is_fail_visible);
    tcase_add_test(tc_cl, test_apm_partition_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_gpt_invalid_partition_is_fail_visible);
    tcase_add_test(tc_hwp3, test_hwp3_parser_errors_are_fail_visible);
    tcase_add_test(tc_hwp3, test_hwp3_time_limit_is_fail_visible);
    tcase_add_test(tc_hwp3, test_hwp3_information_block_length_is_fail_visible);
    tcase_add_test(tc_hwp3, test_hwp3_document_info_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_onenote_dispatch_honors_document_dconf);
    tcase_add_test(tc_hwp3, test_hwp3_truncated_raw_deflate_is_fail_visible);
    tcase_add_test(tc_hwp3, test_hwp3_password_protection_is_fail_visible);
    tcase_add_test(tc_cl, test_7z_truncated_header_is_fail_visible);
    tcase_add_test(tc_cl, test_7z_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_7z_output_size_mismatch_is_fail_visible);
    tcase_add_test(tc_cl, test_7z_time_limit_is_fail_visible);
    tcase_add_test(tc_cl, test_zip_temporary_limit_is_fail_visible);
    tcase_add_test(tc_cl, test_egg_sfx_header_admission);
    tcase_add_test(tc_cl, test_egg_time_limit_is_fail_visible);
    tcase_add_test(tc_cl, test_egg_extra_field_admission_is_fail_visible);
    tcase_add_test(tc_cl, test_egg_lzma_stream_extracts_bounded_member);
    tcase_add_test(tc_cl, test_autoit_ea06_missing_member_is_fail_visible);
    tcase_add_test(tc_cl, test_embedded_candidate_admission_headers);
    tcase_add_test(tc_cl, test_embedded_header_read_failures_are_fail_visible);
    tcase_add_test(tc_cl, test_binhex_encoded_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_file_type_detection_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_mydoom_detector_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_riff_header_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_riff_chunk_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_structured_detector_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_tnef_exact_eof_ends_attribute_list);
    tcase_add_test(tc_cl, test_tnef_time_limit_is_fail_visible);
    tcase_add_test(tc_cl, test_tnef_initial_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_tnef_attribute_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_uuencode_initial_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_uuencode_time_limit_is_fail_visible);
    tcase_add_test(tc_cl, test_mbox_initial_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_mbox_line_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_mbox_oversized_line_is_fail_visible);
#if HAVE_UNRAR
    tcase_add_test(tc_cl, test_rar_truncated_header_is_fail_visible);
#ifndef _WIN32
    tcase_add_test(tc_cl, test_rar_nested_stage_read_failure_is_publicly_fail_visible);
#endif
#endif
    tcase_add_test(tc_cl, test_rar_without_backend_is_explicitly_unsupported);
    tcase_add_test(tc_cl, test_ole2_truncated_header_is_fail_visible);
    tcase_add_test(tc_cl, test_ole2_header_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_ole2_invalid_block_geometry_is_fail_visible);
    tcase_add_test(tc_cl, test_ole2_truncated_property_tree_is_fail_visible);
    tcase_add_test(tc_cl, test_xlm_missing_input_is_fail_visible);
    tcase_add_test(tc_cl, test_xlm_truncated_record_header_is_fail_visible);
    tcase_add_test(tc_cl, test_xlm_temporary_output_limit_is_fail_visible);
    tcase_add_test(tc_cl, test_xlm_string_extensions_are_fail_visible);
    tcase_add_test(tc_cl, test_ole2_vba_materialization_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_ole2_temporary_limit_is_fail_visible);
    tcase_add_test(tc_cl, test_ole2_time_limit_is_fail_visible);
#ifdef CLAMAV_TEST_JS_IO_WRAP
    tcase_add_test(tc_cl, test_ole2_output_close_failure_is_fail_visible);
#endif
#ifndef _WIN32
    tcase_add_test(tc_cl, test_vba_inflate_seek_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_word_macro_directory_truncation_is_fail_visible);
#endif
#ifndef _WIN32
    tcase_add_test(tc_cl, test_pdf_stream_limit_is_fail_visible);
#if SIZE_MAX > UINT32_MAX
    tcase_add_test(tc_cl, test_pdf_stream_width_boundary_is_fail_visible);
    tcase_add_test(tc_cl, test_pdf_stream_allocation_boundary_is_fail_visible);
    tcase_add_test(tc_cl, test_pdf_object_coordinates_are_native_width);
#endif
    tcase_add_test(tc_cl, test_pdf_extracted_object_limit_is_fail_visible);
    tcase_add_test(tc_cl, test_pdf_extract_decoder_error_is_fail_visible);
    tcase_add_test(tc_cl, test_nested_fmap_ranges_and_force_to_disk_are_fail_visible);
    tcase_add_test(tc_cl, test_ishield_msi_partial_limit_and_decode_failures_are_visible);
    tcase_add_test(tc_cl, test_ishield_truncated_metadata_is_fail_visible);
    tcase_add_test(tc_cl, test_ishield_invalid_embedded_header_is_fail_visible);
    tcase_add_test(tc_cl, test_arj_truncated_main_header_is_fail_visible);
    tcase_add_test(tc_cl, test_arj_stored_member_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_arj_truncated_member_is_fail_visible);
    tcase_add_test(tc_cl, test_arj_truncated_member_extraction_is_fail_visible);
    tcase_add_test(tc_cl, test_arj_output_size_mismatch_is_fail_visible);
    tcase_add_test(tc_cl, test_arj_member_limit_is_fail_visible);
    tcase_add_test(tc_cl, test_arj_temporary_limit_is_fail_visible);
    tcase_add_test(tc_cl, test_pe_truncated_header_is_fail_visible);
#if SIZE_MAX > UINT32_MAX
    tcase_add_test(tc_cl, test_pe_header_nested_fmap_accepts_native_offset);
#endif
    tcase_add_test(tc_cl, test_executable_metadata_targetinfo_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_pe_import_thunk_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_pe_icon_truncated_resource_is_fail_visible);
    tcase_add_test(tc_cl, test_pe_icon_bitmap_header_range_is_fail_visible);
    tcase_add_test(tc_cl, test_pe_icon_resource_tree_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_pe_unpack_limit_is_fail_visible);
    tcase_add_test(tc_cl, test_pe_unpack_temporary_limit_is_fail_visible);
    tcase_add_test(tc_cl, test_pe_unpack_contiguous_size_is_fail_visible);
    tcase_add_test(tc_cl, test_pespin_limit_accounting_is_fail_visible);
    tcase_add_test(tc_cl, test_ole2_member_limit_is_fail_visible);
    tcase_add_test(tc_cl, test_script_normalization_window_offset_is_stable);
#ifdef CLAMAV_TEST_MSPACK_CONSTRUCTOR_WRAP
    tcase_add_test(tc_cl, test_mspack_constructor_failures_are_fail_visible);
#endif
#ifdef CLAMAV_TEST_FMAP_NEW_WRAP
    tcase_add_test(tc_cl, test_normalized_script_map_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_descriptor_limit_preflight_precedes_fmap_creation);
    tcase_add_test(tc_cl, test_child_descriptor_inspection_failure_is_fail_visible);
#endif
#ifdef CLAMAV_TEST_JS_IO_WRAP
    tcase_add_test(tc_cl, test_script_normalization_cleanup_close_failure_is_fail_visible);
#endif
    tcase_add_test(tc_cl, test_mspack_scan_limit_is_fail_visible);
    tcase_add_test(tc_cl, test_mspack_time_limit_is_fail_visible);
    tcase_add_test(tc_cl, test_mscab_truncated_fixed_header_is_fail_visible);
    tcase_add_test(tc_cl, test_elf_truncated_header_is_fail_visible);
    tcase_add_test(tc_cl, test_elf_time_limit_is_fail_visible);
    tcase_add_test(tc_cl, test_elf_scan_program_header_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_elf_metadata_read_failure_is_fail_visible);
#if SIZE_MAX > UINT32_MAX
    tcase_add_test(tc_cl, test_elf64_metadata_preserves_native_coordinates);
    tcase_add_test(tc_cl, test_elf64_entry_offset_overflow_is_fail_visible);
#endif
    tcase_add_test(tc_cl, test_macho_truncated_header_is_fail_visible);
    tcase_add_test(tc_cl, test_macho_time_limit_is_fail_visible);
    tcase_add_test(tc_cl, test_macho_unibin_time_limit_is_fail_visible);
    tcase_add_test(tc_cl, test_macho_metadata_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_macho_scan_load_command_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_macho_native_metadata_preserves_64bit_sections);
#if SIZE_MAX > UINT32_MAX
    tcase_add_test(tc_cl, test_macho_unibin_member_range_is_fail_visible);
#endif
    tcase_add_test(tc_cl, test_macho_section_alignment_exponent_is_fail_visible);
    tcase_add_test(tc_cl, test_udf_truncated_descriptor_area_is_fail_visible);
    tcase_add_test(tc_cl, test_udf_time_limit_is_fail_visible);
    tcase_add_test(tc_cl, test_udf_descriptor_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_udf_unknown_generic_descriptor_is_fail_visible);
    tcase_add_test(tc_cl, test_udf_mismatched_file_lists_are_fail_visible);
    tcase_add_test(tc_cl, test_udf_allocation_descriptor_alignment_is_fail_visible);
    tcase_add_test(tc_cl, test_hfsplus_declared_attributes_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_hfsplus_tree_header_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_hfsplus_catalog_node_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_hfsplus_fork_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_hfsplus_attribute_tree_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_hfsplus_catalog_size_accounting_is_fail_visible);
    tcase_add_test(tc_cl, test_hfsplus_truncated_header_is_fail_visible);
    tcase_add_test(tc_cl, test_hfsplus_time_limit_is_fail_visible);
    tcase_add_test(tc_gif, test_gif_truncated_blocks_are_fail_visible);
    tcase_add_test(tc_gif, test_gif_header_read_failures_are_fail_visible);
    tcase_add_test(tc_gif, test_gif_block_timeout_is_fail_visible);
    tcase_add_test(tc_png, test_png_truncated_chunks_are_fail_visible);
    tcase_add_test(tc_png, test_png_chunk_read_failure_is_fail_visible);
    tcase_add_test(tc_png, test_png_chunk_timeout_is_fail_visible);
    tcase_add_test(tc_png, test_png_large_ancillary_chunk_uses_bounded_mapping);
    tcase_add_test(tc_tiff, test_tiff_truncated_structures_are_fail_visible);
    tcase_add_test(tc_tiff, test_tiff_initial_read_failure_is_fail_visible);
    tcase_add_test(tc_tiff, test_tiff_ifd_value_size_is_fail_visible);
    tcase_add_test(tc_tiff, test_tiff_ifd_timeout_is_fail_visible);
#if SIZE_MAX > UINT32_MAX
    tcase_add_test(tc_tiff, test_tiff_ifd_cursor_does_not_wrap_above_uint32);
#endif
    tcase_add_test(tc_cl, test_riff_truncated_chunk_is_fail_visible);
    tcase_add_test(tc_cl, test_jpeg_truncated_structures_are_fail_visible);
    tcase_add_test(tc_cl, test_jpeg_time_limit_is_fail_visible);
    tcase_add_test(tc_cl, test_jpeg_required_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_jpeg_photoshop_exact_eof_is_complete);
    tcase_add_test(tc_cl, test_text_normalize_map_read_failure_is_fail_visible);
    tcase_add_test(tc_pdf, test_pdf_parser_read_failure_is_fail_visible);
    tcase_add_test(tc_pdf, test_pdf_truncated_trailer_is_fail_visible);
    tcase_add_test(tc_pdf, test_pdf_truncated_object_is_fail_visible);
    tcase_add_test(tc_pdf, test_pdf_decode_error_is_fail_visible);
    tcase_add_test(tc_pdf, test_pdf_empty_flate_stream_is_fail_visible);
    tcase_add_test(tc_pdf, test_pdf_unsupported_filter_is_fail_visible);
    tcase_add_test(tc_pdf, test_pdf_unsupported_encryption_is_fail_visible);
    tcase_add_test(tc_pdf, test_pdf_truncated_flate_after_prefix_is_fail_visible);
    tcase_add_test(tc_pdf, test_pdf_truncated_lzw_after_prefix_is_fail_visible);
    tcase_add_test(tc_cl, test_hwpml_base64_decoder_is_bounded_and_fail_visible);
    tcase_add_test(tc_cl, test_top_level_maxfilesize_descriptor_is_fail_visible);
    tcase_add_test(tc_cl, test_action_setup_quarantine_lock_uses_validated_directory_handle);
    tcase_add_test(tc_cl, test_action_source_open_relative_path_stores_absolute_action_path);
    tcase_add_test(tc_cl, test_action_source_open_path_rejects_replaced_symlink);
    tcase_add_test(tc_cl, test_action_source_close_reports_descriptor_failure);
    tcase_add_test(tc_cl, test_zip_stream_stored_refill_bound_and_tail);
    tcase_add_test(tc_cl, test_zip_stream_deflate_refill_bound_and_tail);
    tcase_add_test(tc_cl, test_zip_stream_bzip2_refill_bound_and_tail);
    tcase_add_test(tc_cl, test_zip_stream_deflate64_terminal_validation);
    tcase_add_test(tc_cl, test_zip_stream_zipcrypto_stored_is_bounded);
    tcase_add_test(tc_cl, test_zip64_member_sizes_are_not_narrowed);
    tcase_add_test(tc_cl, test_zip_stream_implode_refill_bound_and_terminal);
    tcase_add_test(tc_cl, test_zip_stream_exact_limit_and_n_plus_one);
    tcase_add_test(tc_cl, test_zip_stream_truncated_deflate_and_callback_status);
#ifdef CLAMAV_TEST_JS_IO_WRAP
    tcase_add_test(tc_cl, test_zip_output_write_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_zip_output_close_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_cryptff_staging_failures_are_fail_visible);
    tcase_add_test(tc_cl, test_cryptff_temporary_quota_is_fail_visible);
    tcase_add_test(tc_cl, test_gzip_staging_failures_are_fail_visible);
#endif
    tcase_add_test(tc_cl, test_zip_truncated_entry_paths_are_fail_visible);
    tcase_add_test(tc_cl, test_zip_local_filename_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_zip_local_header_index_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_zip_local_header_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_zip_central_header_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_gzip_bzip_truncated_streams_are_fail_visible);
    tcase_add_test(tc_cl, test_compressed_input_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_xz_limit_is_fail_visible);
    tcase_add_test(tc_cl, test_xz_truncated_stream_is_fail_visible);
    tcase_add_test(tc_cl, test_compressed_output_temporary_limit_is_fail_visible);
    tcase_add_test(tc_cl, test_swf_zlib_truncated_stream_is_fail_visible);
    tcase_add_test(tc_cl, test_swf_lzma_declared_input_size_is_fail_visible);
    tcase_add_test(tc_cl, test_swf_output_temporary_limit_is_fail_visible);
    tcase_add_test(tc_cl, test_swf_time_limit_is_fail_visible);
    tcase_add_test(tc_cl, test_swf_required_read_failure_is_fail_visible);
#ifdef CLAMAV_TEST_JS_IO_WRAP
    tcase_add_test(tc_cl, test_swf_cleanup_close_failure_is_fail_visible);
#endif
    tcase_add_test(tc_cl, test_swf_truncated_uncompressed_header_is_fail_visible);
    tcase_add_test(tc_cl, test_swf_truncated_frame_metadata_is_fail_visible);
    tcase_add_test(tc_cl, test_swf_truncated_tag_payload_is_fail_visible);
    tcase_add_test(tc_cl, test_msxml_truncated_document_is_fail_visible);
    tcase_add_test(tc_cl, test_msxml_base64_decode_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_msxml_stream_time_limit_is_fail_visible);
    tcase_add_test(tc_cl, test_xdp_time_limit_is_fail_visible);
    tcase_add_test(tc_cl, test_rtf_truncated_document_is_fail_visible);
    tcase_add_test(tc_cl, test_rtf_time_limit_is_fail_visible);
    tcase_add_test(tc_cl, test_rtf_input_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_rtf_split_object_data_header_is_fail_visible);
    tcase_add_test(tc_cl, test_ole10_truncated_object_is_fail_visible);
    tcase_add_test(tc_cl, test_ole10_temporary_limit_is_fail_visible);
    tcase_add_test(tc_cl, test_zip_unsupported_flags_and_method_are_fail_visible);
    tcase_add_test(tc_cl, test_zip_central_directory_resolves_masked_local_values);
    tcase_add_test(tc_cl, test_zip_central_filename_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_zip_eocd_read_failure_is_fail_visible);
    tcase_add_test(tc_cl, test_zip64_metadata_read_failures_are_fail_visible);
    tcase_add_test(tc_cl, test_zip_data_descriptor_read_failures_are_fail_visible);
    tcase_add_test(tc_cl, test_zip_masked_sfx_candidate_is_not_confirmed);
    tcase_add_test(tc_cl, test_zip_local_only_masked_header_is_fail_visible);
    tcase_add_test(tc_cl, test_zip_local_index_propagates_callback_abort);
    tcase_add_test(tc_cl, test_zip_central_index_propagates_callback_status);
    tcase_add_test(tc_cl, test_zip_maxfiles_is_inclusive_and_detection_precedes_limit);
#endif

    suite_add_tcase(s, tc_cl_scan);
    tcase_add_checked_fixture(tc_cl_scan, engine_setup, engine_teardown);

    if (get_fpu_endian() == FPU_ENDIAN_UNKNOWN)
        expect--;
    expect -= skip_files();
    tcase_add_loop_test(tc_cl_scan, test_cl_scandesc, 0, expect);
    tcase_add_loop_test(tc_cl_scan, test_cl_scandesc_allscan, 0, expect);
    tcase_add_loop_test(tc_cl_scan, test_cl_scanfile, 0, expect);
    tcase_add_loop_test(tc_cl_scan, test_cl_scanfile_allscan, 0, expect);
    tcase_add_test(tc_cl_scan, test_mbox_large_body_uses_streaming_spool);
    tcase_add_test(tc_cl_scan, test_mbox_large_body_streams_without_alert);
    tcase_add_test(tc_cl_scan, test_partial_message_missing_fragment_is_fail_visible);
    tcase_add_test(tc_cl_scan, test_unknown_message_subtype_is_fail_visible);
    tcase_add_test(tc_cl_scan, test_partial_message_large_body_uses_streaming_spool);
    tcase_add_test(tc_cl_scan, test_disposition_notification_large_body_uses_streaming_spool);
    tcase_add_test(tc_cl_scan, test_mhtml_unterminated_comment_is_fail_visible);
    tcase_add_test(tc_cl_scan, test_mhtml_large_body_uses_streaming_spool);
    tcase_add_test(tc_cl_scan, test_single_message_large_body_uses_streaming_spool);
    tcase_add_test(tc_cl_scan, test_single_message_large_body_streams_without_alert);
    tcase_add_test(tc_cl_scan, test_multipart_body_uses_streaming_spool);
    tcase_add_test(tc_cl_scan, test_nested_rfc822_body_uses_streaming_spool);
    tcase_add_loop_test(tc_cl_scan, test_cl_scandesc_callback, 0, expect);
    tcase_add_loop_test(tc_cl_scan, test_cl_scandesc_callback_allscan, 0, expect);
    tcase_add_loop_test(tc_cl_scan, test_cl_scanfile_callback, 0, expect);
    tcase_add_loop_test(tc_cl_scan, test_cl_scanfile_callback_allscan, 0, expect);
    tcase_add_test(tc_cl_scan, test_nsis_crc_trailer_is_not_a_member_header);
#ifndef _WIN32
    tcase_add_test(tc_cl_scan, test_zip_stream_central_catalogue_path);
    tcase_add_test(tc_cl_scan, test_zip_abort_reason_is_preserved);
    tcase_add_loop_test(tc_cl_scan, test_cl_scanmap_callback_handle, 0, expect);
    tcase_add_loop_test(tc_cl_scan, test_cl_scanmap_callback_handle_allscan, 0, expect);
#endif
#ifdef HAVE_SYS_MMAN_H
    tcase_add_loop_test(tc_cl_scan, test_cl_scanmap_callback_mem, 0, expect);
    tcase_add_loop_test(tc_cl_scan, test_cl_scanmap_callback_mem_allscan, 0, expect);
#endif
    tcase_add_loop_test(tc_cl_scan, test_fmap_duplicate, 0, expect);
    tcase_add_loop_test(tc_cl_scan, test_fmap_duplicate_out_of_bounds, 0, expect);
    tcase_add_loop_test(tc_cl_scan, test_fmap_assorted_api, 0, expect);
    tcase_add_test(tc_cl_scan, test_fmap_rejects_wrapped_nested_ranges);
    tcase_add_test(tc_cl_scan, test_clean_cache_distinguishes_large_sizes);
    tcase_add_test(tc_cl_scan, test_stats_preserves_large_sample_size);
#if !defined(_WIN32) && defined(ANONYMOUS_MAP)
    tcase_add_test(tc_cl_scan, test_fmap_aging_is_bounded_and_wraps);
    tcase_add_test(tc_cl_scan, test_fmap_handle_accepts_tail_window_at_large_source_offset);
    tcase_add_test(tc_cl_scan, test_fmap_gets_releases_read_pages);
    tcase_add_test(tc_cl_scan, test_fmap_release_unlocked_evicts_whole_subject_pages);
    tcase_add_test(tc_cl_scan, test_metadata_hash_read_failure_is_fail_visible);
#endif
    tcase_add_test(tc_cl_scan, test_authenticode_hash_regions_are_native_and_bounded);
    tcase_add_test(tc_cl_scan, test_authenticode_hash_failure_is_fail_visible);
    tcase_add_test(tc_cl_scan, test_pe_overlay_range_preserves_native_size);

    user_timeout = getenv("T");
    if (user_timeout) {
        int timeout = atoi(user_timeout);
        tcase_set_timeout(tc_cl_scan, timeout);
        printf("Using test case timeout of %d seconds set by user\n", timeout);
    } else {
        printf("Using default test timeout; alter by setting 'T' env var (in seconds)\n");
    }
    return s;
}

static uint8_t le_data[4]     = {0x67, 0x45, 0x23, 0x01};
static int32_t le_expected[4] = {0x01234567, 0x67012345, 0x45670123, 0x23456701};
uint8_t *data                 = NULL;
uint8_t *data2                = NULL;
#define DATA_REP 100

static void data_setup(void)
{
    uint8_t *p;
    size_t i;

    data  = malloc(sizeof(le_data) * DATA_REP);
    data2 = malloc(sizeof(le_data) * DATA_REP);
    ck_assert_msg(!!data, "unable to allocate memory for fixture");
    ck_assert_msg(!!data2, "unable to allocate memory for fixture");
    p = data;
    /* make multiple copies of le_data, we need to run readint tests in a loop, so we need
     * to give it some data to run it on */
    for (i = 0; i < DATA_REP; i++) {
        memcpy(p, le_data, sizeof(le_data));
        p += sizeof(le_data);
    }
    memset(data2, 0, DATA_REP * sizeof(le_data));
}

static void data_teardown(void)
{
    free(data);
    free(data2);
}

/* test reading with different alignments, _i is parameter from tcase_add_loop_test */
START_TEST(test_cli_readint16)
{
    size_t j;
    int16_t value;
    /* read 2 bytes apart, start is not always aligned*/
    for (j = _i; j <= DATA_REP * sizeof(le_data) - 2; j += 2) {
        value = le_expected[j & 3];
        ck_assert_msg(cli_readint16(&data[j]) == value, "(1) data read must be little endian");
    }
    /* read 2 bytes apart, always aligned*/
    for (j = 0; j <= DATA_REP * sizeof(le_data) - 2; j += 2) {
        value = le_expected[j & 3];
        ck_assert_msg(cli_readint16(&data[j]) == value, "(2) data read must be little endian");
    }
}
END_TEST

/* test reading with different alignments, _i is parameter from tcase_add_loop_test */
START_TEST(test_cli_readint32)
{
    size_t j;
    int32_t value = le_expected[_i & 3];
    /* read 4 bytes apart, start is not always aligned*/
    for (j = _i; j < DATA_REP * sizeof(le_data) - 4; j += 4) {
        ck_assert_msg(cli_readint32(&data[j]) == value, "(1) data read must be little endian");
    }
    value = le_expected[0];
    /* read 4 bytes apart, always aligned*/
    for (j = 0; j < DATA_REP * sizeof(le_data) - 4; j += 4) {
        ck_assert_msg(cli_readint32(&data[j]) == value, "(2) data read must be little endian");
    }
}
END_TEST

/* test writing with different alignments, _i is parameter from tcase_add_loop_test */
START_TEST(test_cli_writeint32)
{
    size_t j;
    /* write 4 bytes apart, start is not always aligned*/
    for (j = _i; j < DATA_REP * sizeof(le_data) - 4; j += 4) {
        cli_writeint32(&data2[j], 0x12345678);
    }
    for (j = _i; j < DATA_REP * sizeof(le_data) - 4; j += 4) {
        ck_assert_msg(cli_readint32(&data2[j]) == 0x12345678, "write/read mismatch");
    }
    /* write 4 bytes apart, always aligned*/
    for (j = 0; j < DATA_REP * sizeof(le_data) - 4; j += 4) {
        cli_writeint32(&data2[j], 0x12345678);
    }
    for (j = 0; j < DATA_REP * sizeof(le_data) - 4; j += 4) {
        ck_assert_msg(cli_readint32(&data2[j]) == 0x12345678, "write/read mismatch");
    }
}
END_TEST

static struct dsig_test {
    const char *md5;
    const char *dsig;
    int result;
} dsig_tests[] = {
    {"ae307614434715274c60854c931a26de", "60uhCFmiN48J8r6c7coBv9Q1mehAWEGh6GPYA+60VhQcuXfb0iV1O+sCEyMiRXt/iYF6vXtPXHVd6DiuZ4Gfrry7sVQqNTt3o1/KwU1rc0l5FHgX/nC99fdr/fjaFtinMtRnUXHLeu0j8e6HK+7JLBpD37fZ60GC9YY86EclYGe",
     CL_SUCCESS},
    {"96b7feb3b2a863846438809fe481906f", "Zh5gmf09Zfj6V4gmRKu/NURzhFiE9VloI7w1G33BgDdGSs0Xhscx6sjPUpFSCPsjOalyS4L8q7RS+NdGvNCsLymiIH6RYItlOZsygFhcGuH4jt15KAaAkvEg2TwmqR8z41nUaMlZ0c8q1MXYCLvQJyFARsfzIxS3PAoN2Y3HPoe",
     CL_SUCCESS},
    {"ae307614434715274c60854c931a26de", "Zh5gmf09Zfj6V4gmRKu/NURzhFiE9VloI7w1G33BgDdGSs0Xhscx6sjPUpFSCPsjOalyS4L8q7RS+NdGvNCsLymiIH6RYItlOZsygFhcGuH4jt15KAaAkvEg2TwmqR8z41nUaMlZ0c8q1MXYCLvQJyFARsfzIxS3PAoN2Y3HPoe",
     CL_EVERIFY},
    {"96b7feb3b2a863846438809fe481906f", "60uhCFmiN48J8r6c7coBv9Q1mehAWEGh6GPYA+60VhQcuXfb0iV1O+sCEyMiRXt/iYF6vXtPXHVd6DiuZ4Gfrry7sVQqNTt3o1/KwU1rc0l5FHgX/nC99fdr/fjaFtinMtRnUXHLeu0j8e6HK+7JLBpD37fZ60GC9YY86EclYGe",
     CL_EVERIFY},
    {"ae307614434715274060854c931a26de", "60uhCFmiN48J8r6c7coBv9Q1mehAWEGh6GPYA+60VhQcuXfb0iV1O+sCEyMiRXt/iYF6vXtPXHVd6DiuZ4Gfrry7sVQqNTt3o1/KwU1rc0l5FHgX/nC99fdr/fjaFtinMtRnUXHLeu0j8e6HK+7JLBpD37fZ60GC9YY86EclYGe",
     CL_EVERIFY},
    {"ae307614434715274c60854c931a26de", "60uhCFmiN48J8r6c7coBv9Q1mehAWEGh6GPYA+60VhQcuXfb0iV1O+sCEyMiRXt/iYF6vXtPXHVd6DiuZ4Gfrry7sVQqNTt3o1/KwU1rc0l5FHgX/nC99fdr/fjaatinMtRnUXHLeu0j8e6HK+7JLBpD37fZ60GC9YY86EclYGe",
     CL_EVERIFY},
    {"96b7feb3b2a863846438809fe481906f", "Zh5gmf09Zfj6V4gmRKu/NURzhFiE9VloI7w1G33BgDdGSs0Xhscx6sjPUpFSCPsjOalyS4L8q7RS+NdGvNCsLymiIH6RYItlOZsygFhcGuH4jt15KAaAkvEg2TwmqR8z41nUaMlZ0c8q1MYYCLvQJyFARsfzIxS3PAoN2Y3HPoe",
     CL_EVERIFY},
    {"ge307614434715274c60854c931a26dee", "60uhCFmiN48J8r6c7coBv9Q1mehAWEGh6GPYA+60VhQcuXfb0iV1O+sCEyMiRXt/iYF6vXtPXHVd6DiuZ4Gfrry7sVQqNTt3o1/KwU1rc0l5FHgX/nC99fdr/fjaFtinMtRnUXHLeu0j8e6HK+7JLBpD37fZ60GC9YY86EclYGe",
     CL_EVERIFY},
    {"ae307614434715274c60854c931a26de", "60uhCFmiN48J8r6c7coBv9Q1mehAWEGh6GPYA+60VhQcuXfb0iV1O+sCEyMiRXt/iYF6vXtPXHVd6DiuZ4Gfrry7sVQqNTt3o1/KwU1rc0l5FHgX/nC99fdr/fjaFtinMtRnUXHLeu0j8e6HK+7JLBpD37fZ60GC9YY86EclYGee",
     CL_EVERIFY},
    {"ae307614434715274c60854c931a26de", "60uhCFmiN48J8r6c7coBv9Q1mehAWEGh6GPYA+",
     CL_EVERIFY}};

static const size_t dsig_tests_cnt = sizeof(dsig_tests) / sizeof(dsig_tests[0]);

START_TEST(test_cli_dsig)
{
    ck_assert_msg(cli_versig(dsig_tests[_i].md5, dsig_tests[_i].dsig) == dsig_tests[_i].result,
                  "digital signature verification test failed");
}
END_TEST

static uint8_t tv1[3] = {
    0x61, 0x62, 0x63};

static uint8_t tv2[56] = {
    0x61, 0x62, 0x63, 0x64, 0x62, 0x63, 0x64, 0x65,
    0x63, 0x64, 0x65, 0x66, 0x64, 0x65, 0x66, 0x67,
    0x65, 0x66, 0x67, 0x68, 0x66, 0x67, 0x68, 0x69,
    0x67, 0x68, 0x69, 0x6a, 0x68, 0x69, 0x6a, 0x6b,
    0x69, 0x6a, 0x6b, 0x6c, 0x6a, 0x6b, 0x6c, 0x6d,
    0x6b, 0x6c, 0x6d, 0x6e, 0x6c, 0x6d, 0x6e, 0x6f,
    0x6d, 0x6e, 0x6f, 0x70, 0x6e, 0x6f, 0x70, 0x71};

static uint8_t res256[3][SHA256_HASH_SIZE] = {
    {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde,
     0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
     0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad},
    {0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93,
     0x0c, 0x3e, 0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
     0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1},
    {0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92, 0x81, 0xa1, 0xc7, 0xe2,
     0x84, 0xd7, 0x3e, 0x67, 0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e,
     0x04, 0x6d, 0x39, 0xcc, 0xc7, 0x11, 0x2c, 0xd0}};

START_TEST(test_sha2_256)
{
    void *sha2_256;
    uint8_t h_sha2_256[SHA256_HASH_SIZE];
    uint8_t buf[1000];
    int i;

    memset(buf, 0x61, sizeof(buf));

    cl_sha256(tv1, sizeof(tv1), h_sha2_256, NULL);
    ck_assert_msg(!memcmp(h_sha2_256, res256[0], sizeof(h_sha2_256)), "sha2-256 test vector #1 failed");

    cl_sha256(tv2, sizeof(tv2), h_sha2_256, NULL);
    ck_assert_msg(!memcmp(h_sha2_256, res256[1], sizeof(h_sha2_256)), "sha2-256 test vector #2 failed");

    sha2_256 = cl_hash_init("sha2-256");
    ck_assert_msg(sha2_256 != NULL, "Could not create EVP_MD_CTX for sha2-256");

    for (i = 0; i < 1000; i++)
        cl_update_hash(sha2_256, buf, sizeof(buf));
    cl_finish_hash(sha2_256, h_sha2_256);
    ck_assert_msg(!memcmp(h_sha2_256, res256[2], sizeof(h_sha2_256)), "sha2-256 test vector #3 failed");
}
END_TEST

START_TEST(test_sanitize_path)
{
    const char *unsanitized   = NULL;
    char *sanitized           = NULL;
    char *sanitized_base      = NULL;
    const char *expected      = NULL;
    const char *expected_base = NULL;

    unsanitized = "";
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), NULL);
    ck_assert_msg(NULL == sanitized, "Expected: NULL, Found: \"%s\"", sanitized);

    unsanitized = "";
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), &sanitized_base);
    ck_assert_msg(NULL == sanitized, "Expected: NULL, Found: \"%s\"", sanitized);
    ck_assert_msg(NULL == sanitized_base, "Expected: NULL, Found: \"%s\"", sanitized_base);

    unsanitized = NULL;
    sanitized   = cli_sanitize_filepath(unsanitized, 0, NULL);
    ck_assert_msg(NULL == sanitized, "Expected: NULL, Found: \"%s\"", sanitized);

    unsanitized = NULL;
    sanitized   = cli_sanitize_filepath(unsanitized, 0, &sanitized_base);
    ck_assert_msg(NULL == sanitized, "Expected: NULL, Found: \"%s\"", sanitized);
    ck_assert_msg(NULL == sanitized_base, "Expected: NULL, Found: \"%s\"", sanitized_base);

    unsanitized = NULL;
    sanitized   = cli_sanitize_filepath(unsanitized, 50, NULL);
    ck_assert_msg(NULL == sanitized, "Expected: NULL, Found: \"%s\"", sanitized);

    unsanitized = NULL;
    sanitized   = cli_sanitize_filepath(unsanitized, 50, &sanitized_base);
    ck_assert_msg(NULL == sanitized, "Expected: NULL, Found: \"%s\"", sanitized);
    ck_assert_msg(NULL == sanitized_base, "Expected: NULL, Found: \"%s\"", sanitized_base);

    unsanitized = "badlen";
    sanitized   = cli_sanitize_filepath(unsanitized, 0, NULL);
    ck_assert_msg(NULL == sanitized, "Expected: NULL, Found: \"%s\"", sanitized);

    unsanitized = "badlen";
    sanitized   = cli_sanitize_filepath(unsanitized, 0, &sanitized_base);
    ck_assert_msg(NULL == sanitized, "Expected: NULL, Found: \"%s\"", sanitized);
    ck_assert_msg(NULL == sanitized_base, "Expected: NULL, Found: \"%s\"", sanitized_base);

    unsanitized = ".." PATHSEP;
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), NULL);
    ck_assert_msg(NULL == sanitized, "Expected: NULL, Found: \"%s\"", sanitized);

    unsanitized = ".." PATHSEP;
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), &sanitized_base);
    ck_assert_msg(NULL == sanitized, "Expected: NULL, Found: \"%s\"", sanitized);
    ck_assert_msg(NULL == sanitized_base, "Expected: NULL, Found: \"%s\"", sanitized_base);

    unsanitized = "." PATHSEP;
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), NULL);
    ck_assert_msg(NULL == sanitized, "Expected: NULL, Found: \"%s\"", sanitized);

    unsanitized = "." PATHSEP;
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), &sanitized_base);
    ck_assert_msg(NULL == sanitized, "Expected: NULL, Found: \"%s\"", sanitized);
    ck_assert_msg(NULL == sanitized_base, "Expected: NULL, Found: \"%s\"", sanitized_base);

    unsanitized = PATHSEP;
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), NULL);
    ck_assert_msg(NULL == sanitized, "sanitize_path: sanitized path should have been NULL (3)");

    unsanitized = PATHSEP;
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), &sanitized_base);
    ck_assert_msg(NULL == sanitized, "Expected: NULL, Found: \"%s\"", sanitized);
    ck_assert_msg(NULL == sanitized_base, "Expected: NULL, Found: \"%s\"", sanitized_base);

    unsanitized = ".." PATHSEP "relative_bad_1";
    expected    = "relative_bad_1";
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), NULL);
    ck_assert(NULL != sanitized);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    free(sanitized);

    unsanitized   = ".." PATHSEP "relative_bad_1";
    expected      = "relative_bad_1";
    expected_base = "relative_bad_1";
    sanitized     = cli_sanitize_filepath(unsanitized, strlen(unsanitized), &sanitized_base);
    ck_assert(NULL != sanitized);
    ck_assert(NULL != sanitized_base);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    ck_assert_msg(!strcmp(expected_base, sanitized_base), "Expected: \"%s\", Found: \"%s\"", expected_base, sanitized_base);
    free(sanitized);

    unsanitized = "relative" PATHSEP ".." PATHSEP "good";
    expected    = "relative" PATHSEP ".." PATHSEP "good";
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), NULL);
    ck_assert(NULL != sanitized);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    free(sanitized);

    unsanitized   = "relative" PATHSEP ".." PATHSEP "good";
    expected      = "relative" PATHSEP ".." PATHSEP "good";
    expected_base = "good";
    sanitized     = cli_sanitize_filepath(unsanitized, strlen(unsanitized), &sanitized_base);
    ck_assert(NULL != sanitized);
    ck_assert(NULL != sanitized_base);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    ck_assert_msg(!strcmp(expected_base, sanitized_base), "Expected: \"%s\", Found: \"%s\"", expected_base, sanitized_base);
    free(sanitized);

    unsanitized = "relative" PATHSEP ".." PATHSEP ".." PATHSEP "bad_2";
    expected    = "relative" PATHSEP ".." PATHSEP "bad_2";
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), NULL);
    ck_assert(NULL != sanitized);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    free(sanitized);

    unsanitized   = "relative" PATHSEP ".." PATHSEP ".." PATHSEP "bad_2";
    expected      = "relative" PATHSEP ".." PATHSEP "bad_2";
    expected_base = "bad_2";
    sanitized     = cli_sanitize_filepath(unsanitized, strlen(unsanitized), &sanitized_base);
    ck_assert(NULL != sanitized);
    ck_assert(NULL != sanitized_base);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    ck_assert_msg(!strcmp(expected_base, sanitized_base), "Expected: \"%s\", Found: \"%s\"", expected_base, sanitized_base);
    free(sanitized);

    unsanitized = "relative" PATHSEP "." PATHSEP ".." PATHSEP ".." PATHSEP "bad_current";
    expected    = "relative" PATHSEP ".." PATHSEP "bad_current";
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), NULL);
    ck_assert(NULL != sanitized);
    ck_assert_msg(!strcmp(sanitized, "relative" PATHSEP ".." PATHSEP "bad_current"), "sanitize_path: bad relative current path test failed");
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    free(sanitized);

    unsanitized   = "relative" PATHSEP "." PATHSEP ".." PATHSEP ".." PATHSEP "bad_current";
    expected      = "relative" PATHSEP ".." PATHSEP "bad_current";
    expected_base = "bad_current";
    sanitized     = cli_sanitize_filepath(unsanitized, strlen(unsanitized), &sanitized_base);
    ck_assert(NULL != sanitized);
    ck_assert(NULL != sanitized_base);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    ck_assert_msg(!strcmp(expected_base, sanitized_base), "Expected: \"%s\", Found: \"%s\"", expected_base, sanitized_base);
    free(sanitized);

    unsanitized = "relative/../../bad_win_posix_path"; // <-- posix paths intentionally specified -- should still work on Windows)
    expected    = "relative" PATHSEP ".." PATHSEP "bad_win_posix_path";
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), NULL);
    ck_assert(NULL != sanitized);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    free(sanitized);

    unsanitized   = "relative/../../bad_win_posix_path"; // <-- posix paths intentionally specified -- should still work on Windows)
    expected      = "relative" PATHSEP ".." PATHSEP "bad_win_posix_path";
    expected_base = "bad_win_posix_path";
    sanitized     = cli_sanitize_filepath(unsanitized, strlen(unsanitized), &sanitized_base);
    ck_assert(NULL != sanitized);
    ck_assert(NULL != sanitized_base);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    ck_assert_msg(!strcmp(expected_base, sanitized_base), "Expected: \"%s\", Found: \"%s\"", expected_base, sanitized_base);
    free(sanitized);

    unsanitized = "" PATHSEP "absolute" PATHSEP ".." PATHSEP ".." PATHSEP "bad";
    expected    = "absolute" PATHSEP ".." PATHSEP "bad";
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), NULL);
    ck_assert(NULL != sanitized);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    free(sanitized);

    unsanitized   = "" PATHSEP "absolute" PATHSEP ".." PATHSEP ".." PATHSEP "bad";
    expected      = "absolute" PATHSEP ".." PATHSEP "bad";
    expected_base = "bad";
    sanitized     = cli_sanitize_filepath(unsanitized, strlen(unsanitized), &sanitized_base);
    ck_assert(NULL != sanitized);
    ck_assert(NULL != sanitized_base);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    ck_assert_msg(!strcmp(expected_base, sanitized_base), "Expected: \"%s\", Found: \"%s\"", expected_base, sanitized_base);
    free(sanitized);

    unsanitized = "" PATHSEP "absolute" PATHSEP ".." PATHSEP "good";
    expected    = "absolute" PATHSEP ".." PATHSEP "good";
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), NULL);
    ck_assert(NULL != sanitized);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    free(sanitized);

    unsanitized   = "" PATHSEP "absolute" PATHSEP ".." PATHSEP "good";
    expected      = "absolute" PATHSEP ".." PATHSEP "good";
    expected_base = "good";
    sanitized     = cli_sanitize_filepath(unsanitized, strlen(unsanitized), &sanitized_base);
    ck_assert(NULL != sanitized);
    ck_assert(NULL != sanitized_base);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    ck_assert_msg(!strcmp(expected_base, sanitized_base), "Expected: \"%s\", Found: \"%s\"", expected_base, sanitized_base);
    free(sanitized);

    unsanitized = "relative" PATHSEP "normal";
    expected    = "relative" PATHSEP "normal";
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), NULL);
    ck_assert(NULL != sanitized);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    free(sanitized);

    unsanitized   = "relative" PATHSEP "normal";
    expected      = "relative" PATHSEP "normal";
    expected_base = "normal";
    sanitized     = cli_sanitize_filepath(unsanitized, strlen(unsanitized), &sanitized_base);
    ck_assert(NULL != sanitized);
    ck_assert(NULL != sanitized_base);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    ck_assert_msg(!strcmp(expected_base, sanitized_base), "Expected: \"%s\", Found: \"%s\"", expected_base, sanitized_base);
    free(sanitized);

    unsanitized = "relative" PATHSEP PATHSEP "doublesep";
    expected    = "relative" PATHSEP "doublesep";
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), NULL);
    ck_assert(NULL != sanitized);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    free(sanitized);

    unsanitized   = "relative" PATHSEP PATHSEP "doublesep";
    expected      = "relative" PATHSEP "doublesep";
    expected_base = "doublesep";
    sanitized     = cli_sanitize_filepath(unsanitized, strlen(unsanitized), &sanitized_base);
    ck_assert(NULL != sanitized);
    ck_assert(NULL != sanitized_base);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    ck_assert_msg(!strcmp(expected_base, sanitized_base), "Expected: \"%s\", Found: \"%s\"", expected_base, sanitized_base);
    free(sanitized);

    unsanitized = "relative" PATHSEP "shortname" PATHSEP "1";
    expected    = "relative" PATHSEP "shortname" PATHSEP "1";
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), NULL);
    ck_assert(NULL != sanitized);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    free(sanitized);

    unsanitized   = "relative" PATHSEP "shortname" PATHSEP "1";
    expected      = "relative" PATHSEP "shortname" PATHSEP "1";
    expected_base = "1";
    sanitized     = cli_sanitize_filepath(unsanitized, strlen(unsanitized), &sanitized_base);
    ck_assert(NULL != sanitized);
    ck_assert(NULL != sanitized_base);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    ck_assert_msg(!strcmp(expected_base, sanitized_base), "Expected: \"%s\", Found: \"%s\"", expected_base, sanitized_base);
    free(sanitized);

    unsanitized = "relative" PATHSEP "noname" PATHSEP;
    expected    = "relative" PATHSEP "noname" PATHSEP;
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), NULL);
    ck_assert(NULL != sanitized);
    ck_assert_msg(!strcmp(sanitized, "relative" PATHSEP "noname" PATHSEP), "sanitize_path: relative no name path test failed");
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    free(sanitized);

    unsanitized = "relative" PATHSEP "noname" PATHSEP;
    expected    = "relative" PATHSEP "noname" PATHSEP;
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), &sanitized_base);
    ck_assert(NULL != sanitized);
    ck_assert(NULL == sanitized_base);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    free(sanitized);
}
END_TEST

START_TEST(test_cli_codepage_to_utf8_jis)
{
    cl_error_t ret;
    char *utf8       = NULL;
    size_t utf8_size = 0;

    ret = cli_codepage_to_utf8("\x82\xB1\x82\xF1\x82\xC9\x82\xBF\x82\xCD", 10, CODEPAGE_JAPANESE_SHIFT_JIS, &utf8, &utf8_size);
    ck_assert_msg(CL_SUCCESS == ret, "test_cli_codepage_to_utf8: Failed to convert CODEPAGE_JAPANESE_SHIFT_JIS to UTF8: ret != SUCCESS!");
    ck_assert_msg(NULL != utf8, "sanitize_path: Failed to convert CODEPAGE_JAPANESE_SHIFT_JIS to UTF8: utf8 pointer is NULL!");
    ck_assert_msg(0 == strcmp(utf8, "こんにちは"), "sanitize_path: '%s' doesn't match '%s'", utf8, "こんにちは");

    if (NULL != utf8) {
        free(utf8);
        utf8 = NULL;
    }
}
END_TEST

START_TEST(test_cli_codepage_to_utf8_utf16be_null_term)
{
    cl_error_t ret;
    char *utf8       = NULL;
    size_t utf8_size = 0;

    ret = cli_codepage_to_utf8("\x00\x48\x00\x65\x00\x6c\x00\x6c\x00\x6f\x00\x20\x00\x77\x00\x6f\x00\x72\x00\x6c\x00\x64\x00\x21\x00\x00", 26, CODEPAGE_UTF16_BE, &utf8, &utf8_size);
    ck_assert_msg(CL_SUCCESS == ret, "test_cli_codepage_to_utf8: Failed to convert CODEPAGE_UTF16_BE to UTF8: ret != SUCCESS!");
    ck_assert_msg(NULL != utf8, "sanitize_path: Failed to convert CODEPAGE_UTF16_BE to UTF8: utf8 pointer is NULL!");
    ck_assert_msg(0 == strcmp(utf8, "Hello world!"), "sanitize_path: '%s' doesn't match '%s'", utf8, "Hello world!");

    if (NULL != utf8) {
        free(utf8);
        utf8 = NULL;
    }
}
END_TEST

START_TEST(test_cli_codepage_to_utf8_utf16be_no_null_term)
{
    cl_error_t ret;
    char *utf8       = NULL;
    size_t utf8_size = 0;

    ret = cli_codepage_to_utf8("\x00\x48\x00\x65\x00\x6c\x00\x6c\x00\x6f\x00\x20\x00\x77\x00\x6f\x00\x72\x00\x6c\x00\x64\x00\x21", 24, CODEPAGE_UTF16_BE, &utf8, &utf8_size);
    ck_assert_msg(CL_SUCCESS == ret, "test_cli_codepage_to_utf8: Failed to convert CODEPAGE_UTF16_BE to UTF8: ret != SUCCESS!");
    ck_assert_msg(NULL != utf8, "sanitize_path: Failed to convert CODEPAGE_UTF16_BE to UTF8: utf8 pointer is NULL!");
    ck_assert_msg(0 == strcmp(utf8, "Hello world!"), "sanitize_path: '%s' doesn't match '%s'", utf8, "Hello world!");

    if (NULL != utf8) {
        free(utf8);
        utf8 = NULL;
    }
}
END_TEST

START_TEST(test_cli_codepage_to_utf8_utf16le)
{
    cl_error_t ret;
    char *utf8       = NULL;
    size_t utf8_size = 0;

    ret = cli_codepage_to_utf8("\x48\x00\x65\x00\x6c\x00\x6c\x00\x6f\x00\x20\x00\x77\x00\x6f\x00\x72\x00\x6c\x00\x64\x00\x21\x00\x00\x00", 26, CODEPAGE_UTF16_LE, &utf8, &utf8_size);
    ck_assert_msg(CL_SUCCESS == ret, "test_cli_codepage_to_utf8: Failed to convert CODEPAGE_UTF16_LE to UTF8: ret != SUCCESS!");
    ck_assert_msg(NULL != utf8, "sanitize_path: Failed to convert CODEPAGE_UTF16_LE to UTF8: utf8 pointer is NULL!");
    ck_assert_msg(0 == strcmp(utf8, "Hello world!"), "sanitize_path: '%s' doesn't match '%s'", utf8, "Hello world!");

    if (NULL != utf8) {
        free(utf8);
        utf8 = NULL;
    }
}
END_TEST

static Suite *test_cli_suite(void)
{
    Suite *s               = suite_create("cli");
    TCase *tc_cli_others   = tcase_create("byteorder_macros");
    TCase *tc_cli_dsig     = tcase_create("digital signatures");
    TCase *tc_cli_assorted = tcase_create("assorted functions");

    suite_add_tcase(s, tc_cli_others);
    tcase_add_checked_fixture(tc_cli_others, data_setup, data_teardown);
    tcase_add_loop_test(tc_cli_others, test_cli_readint32, 0, 16);
    tcase_add_loop_test(tc_cli_others, test_cli_readint16, 0, 16);
    tcase_add_loop_test(tc_cli_others, test_cli_writeint32, 0, 16);

    suite_add_tcase(s, tc_cli_dsig);
    tcase_add_loop_test(tc_cli_dsig, test_cli_dsig, 0, dsig_tests_cnt);
    tcase_add_test(tc_cli_dsig, test_sha2_256);

    suite_add_tcase(s, tc_cli_assorted);
    tcase_add_test(tc_cli_assorted, test_sanitize_path);
    tcase_add_test(tc_cli_assorted, test_cli_codepage_to_utf8_jis);
    tcase_add_test(tc_cli_assorted, test_cli_codepage_to_utf8_utf16be_null_term);
    tcase_add_test(tc_cli_assorted, test_cli_codepage_to_utf8_utf16be_no_null_term);
    tcase_add_test(tc_cli_assorted, test_cli_codepage_to_utf8_utf16le);

    return s;
}

void errmsg_expected(void)
{
    fputs("cli_errmsg() expected here\n", stderr);
}

int open_testfile(const char *name, int flags)
{
    int fd;
    char *str;

    str = malloc(strlen(name) + strlen(SRCDIR) + 2);
    ck_assert_msg(!!str, "malloc");
    sprintf(str, "%s" PATHSEP "%s", SRCDIR, name);

    fd = open(str, flags);
    ck_assert_msg(fd >= 0, "open() failed: %s", str);
    free(str);
    return fd;
}

void diff_file_mem(int fd, const char *ref, size_t len)
{
    char c1, c2;
    size_t p, reflen = len;
    char *buf = malloc(len);

    ck_assert_msg(!!buf, "unable to malloc buffer: %zu", len);
    p = read(fd, buf, len);
    ck_assert_msg(p == len, "file is smaller: %lu, expected: %lu", p, len);
    p = 0;
    while (len > 0) {
        c1 = ref[p];
        c2 = buf[p];
        if (c1 != c2)
            break;
        p++;
        len--;
    }
    if (len > 0)
        ck_assert_msg(c1 == c2, "file contents mismatch at byte: %lu, was: %c, expected: %c", p, c2, c1);
    free(buf);
    p = lseek(fd, 0, SEEK_END);
    ck_assert_msg(p == reflen, "trailing garbage, file size: %ld, expected: %ld", p, reflen);
    close(fd);
}

void diff_files(int fd, int ref_fd)
{
    char *ref;
    ssize_t nread;
    off_t siz = lseek(ref_fd, 0, SEEK_END);
    ck_assert_msg(siz != -1, "lseek failed");

    ref = malloc(siz);
    ck_assert_msg(!!ref, "unable to malloc buffer: " STDi64, (int64_t)siz);

    ck_assert_msg(lseek(ref_fd, 0, SEEK_SET) == 0, "lseek failed");
    nread = read(ref_fd, ref, siz);
    ck_assert_msg(nread == siz, "short read, expected: %ld, was: %ld", siz, nread);
    close(ref_fd);
    diff_file_mem(fd, ref, siz);
    free(ref);
}

#ifdef USE_MPOOL
static mpool_t *pool;
#else
static void *pool;
#endif
struct cli_dconf *dconf;

void dconf_setup(void)
{
    pool  = NULL;
    dconf = NULL;
#ifdef USE_MPOOL
    pool = mpool_create();
    ck_assert_msg(!!pool, "unable to create pool");
#endif
    dconf = cli_mpool_dconf_init(pool);
    ck_assert_msg(!!dconf, "failed to init dconf");
}

void dconf_teardown(void)
{
    MPOOL_FREE(pool, dconf);
#ifdef USE_MPOOL
    if (pool)
        mpool_destroy(pool);
#endif
}

#ifndef _WIN32
static void check_version_compatible()
{
    /* check 0.9.8 is not ABI compatible with 0.9.6,
     * if by accident you compile with check 0.9.6 header
     * and link with 0.9.8 then check will hang/crash. */
    if ((check_major_version != CHECK_MAJOR_VERSION) ||
        (check_minor_version != CHECK_MINOR_VERSION) ||
        (check_micro_version != CHECK_MICRO_VERSION)) {
        fprintf(stderr, "ERROR: check version mismatch!\n"
                        "\tVersion from header: %u.%u.%u\n"
                        "\tVersion from library: %u.%u.%u\n"
                        "\tMake sure check.h and -lcheck are same version!\n",
                CHECK_MAJOR_VERSION,
                CHECK_MINOR_VERSION,
                CHECK_MICRO_VERSION,
                check_major_version,
                check_minor_version,
                check_micro_version);
        exit(EXIT_FAILURE);
    }
}
#endif

int main(int argc, char **argv)
{
    int nf;
    Suite *s;
    SRunner *sr;
    const char *run_suite;
    const char *run_case;
    FILE *log_file = NULL;

    UNUSEDPARAM(argc);
    UNUSEDPARAM(argv);

    cl_initialize_crypto();

    fpu_words = get_fpu_endian();

#ifndef _WIN32
    check_version_compatible();
#endif
    s  = test_cl_suite();
    sr = srunner_create(s);

    srunner_add_suite(sr, test_cli_suite());
    srunner_add_suite(sr, test_jsnorm_suite());
    srunner_add_suite(sr, test_str_suite());
    srunner_add_suite(sr, test_regex_suite());
    srunner_add_suite(sr, test_disasm_suite());
    srunner_add_suite(sr, test_uniq_suite());
    srunner_add_suite(sr, test_matchers_suite());
    srunner_add_suite(sr, test_htmlnorm_suite());
    srunner_add_suite(sr, test_bytecode_suite());

    srunner_set_log(sr, OBJDIR PATHSEP "test.log");
    log_file = freopen(OBJDIR PATHSEP "test-stderr.log", "w+", stderr);
    if (log_file == NULL) {
        // The stderr FILE pointer may be closed by `freopen()` even if redirecting to the log file files.
        // So we will output the error message to stdout instead.
        fputs("Unable to redirect stderr!\n", stdout);
    }
    cl_debug();

    run_suite = getenv("CK_RUN_SUITE");
    run_case  = getenv("CK_RUN_CASE");
    if (run_suite != NULL || run_case != NULL)
        srunner_run(sr, run_suite, run_case, CK_NORMAL);
    else
        srunner_run_all(sr, CK_NORMAL);
    nf = srunner_ntests_failed(sr);
    if (nf)
        printf("NOTICE: Use the 'T' environment variable to adjust testcase timeout\n");
    srunner_free(sr);

    xmlCleanupParser();

    if (log_file) {
        fclose(log_file);
    }

    return (nf == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
