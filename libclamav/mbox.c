/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Nigel Horne
 *
 *  Acknowledgements: Some ideas came from Stephen White <stephen@earth.li>,
 *                    Michael Dankov <misha@btrc.ru>, Gianluigi Tiesi <sherpya@netfarm.it>,
 *                    Everton da Silva Marques, Thomas Lamy <Thomas.Lamy@in-online.net>,
 *                    James Stevens <James@kyzo.com>
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

#ifdef CL_THREAD_SAFE
#ifndef _REENTRANT
#define _REENTRANT /* for Solaris 2.8 */
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <stdbool.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <ctype.h>
#include <time.h>
#include <fcntl.h>
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <dirent.h>
#include <limits.h>
#include <signal.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef CL_THREAD_SAFE
#include <pthread.h>
#endif

#if defined(_WIN32) || defined(_WIN64)
#define strtok_r strtok_s
#endif

#include "clamav.h"
#include "others.h"
#include "str.h"
#include "filetypes.h"
#include "mbox.h"
#include "dconf.h"
#include "fmap.h"
#include "json_api.h"
#include "msxml_parser.h"

#include <libxml/xmlversion.h>
#include <libxml/HTMLtree.h>
#include <libxml/HTMLparser.h>
#include <libxml/xmlreader.h>

#define DCONF_PHISHING mctx->ctx->dconf->phishing

#ifdef CL_DEBUG

#if defined(C_LINUX)
#include <features.h>
#endif

#if __GLIBC__ == 2 && __GLIBC_MINOR__ >= 1 && !defined(__UCLIBC__) || defined(__UCLIBC_HAS_BACKTRACE__)
#define HAVE_BACKTRACE
#endif
#endif

#ifdef HAVE_BACKTRACE
#include <execinfo.h>

#ifdef USE_SYSLOG
#include <syslog.h>
#endif

static void sigsegv(int sig);
static void print_trace(int use_syslog);

/*#define    SAVE_TMP */ /* Save the file being worked on in tmp */
#endif

#if defined(NO_STRTOK_R) || !defined(CL_THREAD_SAFE)
#undef strtok_r
#undef __strtok_r
#define strtok_r(a, b, c) strtok(a, b)
#endif

typedef enum {
    FAIL,
    OK,
    OK_ATTACHMENTS_NOT_SAVED,
    VIRUS,
    MAXREC,
    MAXFILES
} mbox_status;

#ifndef isblank
#define isblank(c) (((c) == ' ') || ((c) == '\t'))
#endif

#define SAVE_TO_DISC /* multipart/message are saved in a temporary file */

#include "htmlnorm.h"

#include "phishcheck.h"

#ifndef _WIN32
#include <sys/time.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#if !defined(C_BEOS) && !defined(C_INTERIX)
#include <net/if.h>
#include <arpa/inet.h>
#endif
#endif

#include <fcntl.h>

/*
 * Use CL_SCAN_MAIL_PARTIAL_MESSAGE to handle messages covered by section 7.3.2 of RFC1341.
 *    This is experimental code so it is up to YOU to (1) ensure it's secure
 * (2) periodically trim the directory of old files
 *
 * If you use the load balancing feature of clamav-milter to run clamd on
 * more than one machine you must make sure that .../partial is on a shared
 * network filesystem
 */

/*
 * Slows things down a lot and only catches unencoded copies
 * of EICAR within bounces, which don't matter
 */
// #define    SCAN_UNENCODED_BOUNCES

typedef struct mbox_ctx {
    const char *dir;
    const table_t *rfc821Table;
    const table_t *subtypeTable;
    cli_ctx *ctx;
    unsigned int files; /* number of files extracted */
    json_object *wrkobj;
    cl_error_t message_failure_status;
} mbox_ctx;

/* Metadata is part of the confirmed MIME-layer result contract. A report
 * failure must therefore remain visible after the parser continues, while a
 * stronger detection or resource result must retain precedence. */
static void mbox_record_json_failure(mbox_ctx *mctx, mbox_status *status,
                                     const char *reason)
{
    if (mctx == NULL || mctx->ctx == NULL)
        return;

    cli_mark_scan_incomplete(mctx->ctx, reason);
    if (status != NULL && *status != VIRUS && *status != MAXREC && *status != MAXFILES)
        *status = FAIL;
}

static void mbox_record_json_status(mbox_ctx *mctx, mbox_status *status,
                                    cl_error_t ret, const char *reason)
{
    if (ret != CL_SUCCESS)
        mbox_record_json_failure(mctx, status, reason);
}

static void mbox_merge_json_status(mbox_status *status, mbox_status metadata_status)
{
    if (status != NULL && metadata_status != OK && *status != VIRUS &&
        *status != MAXREC && *status != MAXFILES)
        *status = FAIL;
}

/* The internal mbox_status enum intentionally describes parser control flow,
 * but it cannot carry a fileblob's specific output/materialization error.
 * Preserve that status at the mbox boundary so a later FAIL/CL_EFORMAT result
 * cannot hide CL_ECREAT, CL_EOPEN, CL_EWRITE, CL_ETIMEOUT, or CL_ERESOURCE. */
static void mbox_record_message_failure(mbox_ctx *mctx, const message *m,
                                        const char *reason)
{
    cl_error_t status;

    if (mctx == NULL || mctx->ctx == NULL)
        return;

    if (m != NULL) {
        status = messageGetMaterializationStatus(m);
        if (status != CL_SUCCESS && mctx->message_failure_status == CL_SUCCESS)
            mctx->message_failure_status = status;
    }
    cli_mark_scan_incomplete(mctx->ctx, reason);
}

static void mbox_record_status(mbox_ctx *mctx, cl_error_t status,
                               const char *reason)
{
    if (mctx == NULL || mctx->ctx == NULL)
        return;

    if (status == CL_SUCCESS)
        status = CL_EPARSE;
    if (mctx->message_failure_status == CL_SUCCESS)
        mctx->message_failure_status = status;
    cli_mark_scan_incomplete(mctx->ctx, reason);
}

/* A reassembled message is materialized through a fileblob rather than the
 * message body spool. Preserve the blob's first specific failure before the
 * blob is destroyed and the internal mailbox status is reduced to FAIL. */
static void mbox_record_fileblob_failure(mbox_ctx *mctx, const fileblob *fb,
                                         cl_error_t fallback_status,
                                         const char *reason)
{
    cl_error_t status = fallback_status;

    if (mctx == NULL || mctx->ctx == NULL)
        return;

    if (fb != NULL && fb->incomplete_status != CL_SUCCESS)
        status = fb->incomplete_status;
    if (status == CL_SUCCESS)
        status = CL_ERESOURCE;
    mbox_record_status(mctx, status, reason);
}

/* if supported by the system, use the optimized
 * version of getc, that doesn't do locking,
 * and is possibly implemented entirely as a macro */
#if defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200112L
#define GETC(fp) getc_unlocked(fp)
#define LOCKFILE(fp) flockfile(fp)
#define UNLOCKFILE(fp) funlockfile(fp)
#else
#define GETC(fp) getc(fp)
#define LOCKFILE(fp)
#define UNLOCKFILE(fp)
#endif

static int cli_parse_mbox(const char *dir, cli_ctx *ctx);
static int scanFileblob(mbox_ctx *mctx, fileblob *fb);
static message *parseEmailFile(fmap_t *map, size_t *at, const table_t *rfc821Table, const char *firstLine, const char *dir, cli_ctx *ctx, bool *heuristicFound, cl_error_t *failure_status);
static message *parseEmailHeaders(message *m, const table_t *rfc821Table, bool *heuristicFound);
static int parseEmailHeader(message *m, const char *line, const table_t *rfc821, cli_ctx *ctx, bool *heuristicFound);
static cl_error_t parseMHTMLComment(const char *comment, cli_ctx *ctx, void *wrkjobj, void *cbdata);
static mbox_status parseRootMHTML(mbox_ctx *mctx, message *m, text *t);
static mbox_status parseEmailBody(message *messageIn, text *textIn, mbox_ctx *mctx, unsigned int recursion_level);
static mbox_status parseMultipartBodySpool(message *mainMessage, mbox_ctx *mctx, unsigned int recursion_level);
static int boundaryStart(const char *line, const char *boundary);
static int boundaryEnd(const char *line, const char *boundary);
static int initialiseTables(table_t **rfc821Table, table_t **subtypeTable);
static int getTextPart(message *const messages[], size_t size);
static size_t strip(char *buf, int len);
static int parseMimeHeader(message *m, const char *cmd, const table_t *rfc821Table, const char *arg, cli_ctx *ctx, bool *heuristicFound);
static int saveTextPart(mbox_ctx *mctx, message *m, int destroy_text);
static char *rfc2047(const char *in, cli_ctx *ctx);
static char *rfc822comments(const char *in, char *out);
static int rfc1341(mbox_ctx *mctx, message *m);
static bool usefulHeader(int commandNumber, const char *cmd);
static char *getline_from_mbox(char *buffer, size_t len, fmap_t *map, size_t *at, cli_ctx *ctx,
                               cl_error_t *failure_status, bool reject_unterminated_line);
static bool isBounceStart(mbox_ctx *mctx, const char *line);
static mbox_status exportBinhexMessage(mbox_ctx *mctx, message *m);
static int exportBounceMessage(mbox_ctx *ctx, text *start);
static const char *getMimeTypeStr(mime_type mimetype);
static const char *getEncTypeStr(encoding_type enctype);
static message *do_multipart(message *mainMessage, message **messages, int i, mbox_status *rc, mbox_ctx *mctx, message *messageIn, text **tptr, unsigned int recursion_level);
static int count_quotes(const char *buf);
static bool next_is_folded_header(const text *t);
static bool newline_in_header(const char *line);

static bool messageNeedsMaterializedBody(const message *m)
{
    if (m == NULL)
        return false;

    /* Every MIME body now enters the disk-backed state machine. Unsupported
     * message subtypes are rejected explicitly after their bounded spool is
     * complete, rather than retaining an unbounded line list just to reach the
     * legacy rejection branch. */
    return false;
}

static blob *getHrefs(mbox_ctx *, message *m, tag_arguments_t *hrefs, bool *incomplete);
static void hrefs_done(blob *b, tag_arguments_t *hrefs);
static void checkURLs(message *m, mbox_ctx *mctx, mbox_status *rc, int is_html);

static bool haveTooManyMIMEPartsPerMessage(size_t mimePartCnt, cli_ctx *ctx, mbox_status *rc);
static bool hitLineFoldCnt(const char *const line, size_t *lineFoldCnt, cli_ctx *ctx, bool *heuristicFound);
static bool haveTooManyHeaderBytes(size_t totalLen, cli_ctx *ctx, bool *heuristicFound);
static bool haveTooManyEmailHeaders(size_t totalHeaderCnt, cli_ctx *ctx, bool *heuristicFound);
static bool haveTooManyMIMEArguments(size_t argCnt, cli_ctx *ctx, bool *heuristicFound);

/* MIME parsing has several line-oriented paths that can otherwise spend a
 * long time in input, header, or part traversal without reaching a generic
 * scan-limit helper. Keep the shared deadline sticky and make expiry
 * fail-visible to the outer mailbox result policy. */
static bool mbox_check_deadline(cli_ctx *ctx)
{
    if (cli_checktimelimit(ctx) == CL_SUCCESS)
        return false;

    cli_mark_scan_incomplete(ctx, "MIME parser reached the configured time limit");
    return true;
}

/* Maximum line length according to RFC2821 */
#define RFC2821LENGTH 1000

/* Hashcodes for our hash tables */
#define CONTENT_TYPE 1
#define CONTENT_TRANSFER_ENCODING 2
#define CONTENT_DISPOSITION 3

/* Mime sub types */
#define PLAIN 1
#define ENRICHED 2
#define HTML 3
#define RICHTEXT 4
#define MIXED 5
#define ALTERNATIVE 6 /* RFC1521*/
#define DIGEST 7
#define SIGNED 8
#define PARALLEL 9
#define RELATED 10      /* RFC2387 */
#define REPORT 11       /* RFC1892 */
#define APPLEDOUBLE 12  /* Handling of this in only noddy for now */
#define FAX MIXED       /*                                              \
                         * RFC3458                                      \
                         * Drafts stated to treat is as mixed if it is  \
                         * not known.  This disappeared in the final    \
                         * version (except when talking about           \
                         * voice-message), but it is good enough for us \
                         * since we do no validation of coversheet      \
                         * presence etc. (which also has disappeared    \
                         * in the final version)                        \
                         */
#define ENCRYPTED 13    /*                                        \
                         * e.g. RFC2015                           \
                         * Content-Type: multipart/encrypted;     \
                         * boundary="nextPart1383049.XCRrrar2yq"; \
                         * protocol="application/pgp-encrypted"   \
                         */
#define X_BFILE RELATED /*                                             \
                         * BeOS, expert two parts: the file and its    \
                         * attributes. The attributes part comes as    \
                         *    Content-Type: application/x-be_attribute \
                         *        name="foo"                           \
                         * I can't find where it is defined, any       \
                         * pointers would be appreciated. For now      \
                         * we treat it as multipart/related            \
                         */
#define KNOWBOT 14      /* Unknown and undocumented format? */

#define HEURISTIC_EMAIL_MAX_LINE_FOLDS_PER_HEADER (256 * 1024)
#define HEURISTIC_EMAIL_MAX_HEADER_BYTES (1024 * 256)
#define HEURISTIC_EMAIL_MAX_HEADERS 1024
#define HEURISTIC_EMAIL_MAX_MIME_PARTS_PER_MESSAGE 1024
#define HEURISTIC_EMAIL_MAX_ARGUMENTS_PER_HEADER 256

static const struct tableinit {
    const char *key;
    int value;
} rfc821headers[] = {
    /* TODO: make these regular expressions */
    {"Content-Type", CONTENT_TYPE},
    {"Content-Transfer-Encoding", CONTENT_TRANSFER_ENCODING},
    {"Content-Disposition", CONTENT_DISPOSITION},
    {NULL, 0}},
  mimeSubtypes[] = {/* see RFC2045 */
                    /* subtypes of Text */
                    {"plain", PLAIN},
                    {"enriched", ENRICHED},
                    {"html", HTML},
                    {"richtext", RICHTEXT},
                    /* subtypes of Multipart */
                    {"mixed", MIXED},
                    {"alternative", ALTERNATIVE},
                    {"digest", DIGEST},
                    {"signed", SIGNED},
                    {"parallel", PARALLEL},
                    {"related", RELATED},
                    {"report", REPORT},
                    {"appledouble", APPLEDOUBLE},
                    {"fax-message", FAX},
                    {"encrypted", ENCRYPTED},
                    {"x-bfile", X_BFILE},          /* BeOS */
                    {"knowbot", KNOWBOT},          /* ??? */
                    {"knowbot-metadata", KNOWBOT}, /* ??? */
                    {"knowbot-code", KNOWBOT},     /* ??? */
                    {"knowbot-state", KNOWBOT},    /* ??? */
                    {NULL, 0}},
  mimeTypeStr[] = {{"NOMIME", NOMIME}, {"APPLICATION", APPLICATION}, {"AUDIO", AUDIO}, {"IMAGE", IMAGE}, {"MESSAGE", MESSAGE}, {"MULTIPART", MULTIPART}, {"TEXT", TEXT}, {"VIDEO", VIDEO}, {"MEXTENSION", MEXTENSION}, {NULL, 0}}, encTypeStr[] = {{"NOENCODING", NOENCODING}, {"QUOTEDPRINTABLE", QUOTEDPRINTABLE}, {"BASE64", BASE64}, {"EIGHTBIT", EIGHTBIT}, {"BINARY", BINARY}, {"UUENCODE", UUENCODE}, {"YENCODE", YENCODE}, {"EEXTENSION", EEXTENSION}, {"BINHEX", BINHEX}, {NULL, 0}};

#ifdef CL_THREAD_SAFE
static pthread_mutex_t tables_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif
static table_t *rfc821  = NULL;
static table_t *subtype = NULL;

int cli_mbox(const char *dir, cli_ctx *ctx)
{
    if (dir == NULL) {
        cli_dbgmsg("cli_mbox called with NULL dir\n");
        return CL_ENULLARG;
    }
    if (ctx == NULL) {
        cli_dbgmsg("cli_mbox called with NULL context\n");
        return CL_ENULLARG;
    }
    if (ctx->fmap == NULL) {
        cli_mark_scan_incomplete(ctx, "MIME message input map is unavailable");
        return CL_EPARSE;
    }
    if (ctx->engine == NULL) {
        cli_dbgmsg("cli_mbox called with context missing engine\n");
        return CL_ENULLARG;
    }
    if (ctx->options == NULL) {
        cli_dbgmsg("cli_mbox called with context missing scan options\n");
        return CL_ENULLARG;
    }
    if (ctx->dconf == NULL) {
        cli_dbgmsg("cli_mbox called with context missing detector configuration\n");
        return CL_ENULLARG;
    }
    return cli_parse_mbox(dir, ctx);
}

/*
 * Scan a parser-generated fileblob without allowing a missing spool or an
 * operational scan error to collapse into a clean MIME result.
 */
static int
scanFileblob(mbox_ctx *mctx, fileblob *fb)
{
    int rc;

    if (fb == NULL) {
        cli_mark_scan_incomplete(mctx->ctx,
                                 "MIME temporary spool could not be created or materialized");
        return CL_ERESOURCE;
    }

    /* textToFileblob() clears the context for historical non-scanning
     * conversion callers. Mail parser spools are authoritative scan inputs,
     * so restore the active context before the scan. */
    fileblobSetCTX(fb, mctx->ctx);
    rc = fileblobScanAndDestroy(fb);
    if (rc != CL_CLEAN && rc != CL_VIRUS)
        cli_mark_scan_incomplete(mctx->ctx,
                                 "MIME temporary spool scan did not complete");

    return rc;
}

static void
destroyPartialOutput(fileblob *fb, const char *outname)
{
    if (fb)
        fileblobDestructiveDestroy(fb);
    if (outname)
        cli_unlink(outname);
}

/*
 * TODO: when signal handling is added, need to remove temp files when a
 *    signal is received
 * TODO: add option to scan in memory not via temp files, perhaps with a
 * named pipe or memory mapped file, though this won't work on big e-mails
 * containing many levels of encapsulated messages - it'd just take too much
 * RAM
 * TODO: parse .msg format files
 * TODO: fully handle AppleDouble format, see
 *    http://www.lazerware.com/formats/Specs/AppleSingle_AppleDouble.pdf
 * TODO: ensure parseEmailHeaders is always called before parseEmailBody
 * TODO: create parseEmail which calls parseEmailHeaders then parseEmailBody
 * TODO: Handle unexpected NUL bytes in header lines which stop strcmp()s:
 *    e.g. \0Content-Type: application/binary;
 */
static int
cli_parse_mbox(const char *dir, cli_ctx *ctx)
{
    int retcode;
    cl_error_t line_failure = CL_SUCCESS;
    message *body;
    char buffer[RFC2821LENGTH + 1];
    mbox_ctx mctx;
    size_t at   = 0;
    fmap_t *map = ctx->fmap;

    cli_dbgmsg("in mbox()\n");

    if (mbox_check_deadline(ctx))
        return CL_ETIMEOUT;

    if (!fmap_gets(map, buffer, &at, sizeof(buffer))) {
        /* EOF at the end of the map is an empty message. A nonempty map that
         * could not yield its first line indicates an incomplete read or
         * invalid fmap range and must remain fail-visible. */
        if (at < map->len) {
            cli_mark_scan_incomplete(ctx, "MIME message input could not be read completely");
            return CL_EREAD;
        }
        return CL_CLEAN;
    }

#ifdef CL_THREAD_SAFE
    pthread_mutex_lock(&tables_mutex);
#endif

    if (initialiseTables(&rfc821, &subtype) < 0) {
#ifdef CL_THREAD_SAFE
        pthread_mutex_unlock(&tables_mutex);
#endif
        cli_mark_scan_incomplete(ctx,
                                 "MIME parser tables could not be initialized");
        return CL_EMEM;
    }

#ifdef CL_THREAD_SAFE
    pthread_mutex_unlock(&tables_mutex);
#endif

    retcode = CL_SUCCESS;
    body    = NULL;

    mctx.dir          = dir;
    mctx.rfc821Table  = rfc821;
    mctx.subtypeTable = subtype;
    mctx.ctx          = ctx;
    mctx.files        = 0;
    mctx.wrkobj       = ctx->this_layer_metadata_json;
    mctx.message_failure_status = CL_SUCCESS;

    /*
     * Is it a UNIX style mbox with more than one
     * mail message, or just a single mail message?
     *
     * TODO: It would be better if we called cli_magic_scan_dir here rather than
     * in cli_scanmail. Then we could improve the way mailboxes with more
     * than one message is handled, e.g. giving a better indication of
     * which message within the mailbox is infected
     */
    /*if((strncmp(buffer, "From ", 5) == 0) && isalnum(buffer[5])) {*/
    if (strncmp(buffer, "From ", 5) == 0) {
        /*
         * Have been asked to check a UNIX style mbox file, which
         * may contain more than one e-mail message to decode
         *
         * It would be far better for scanners.c to do this splitting
         * and do this
         *    FOR EACH mail in the mailbox
         *    DO
         *        pass this mail to cli_mbox --
         *        scan this file
         *        IF this file has a virus quit
         *        THEN
         *            return CL_VIRUS
         *        FI
         *    END
         * This would remove a problem with this code that it can
         * fill up the tmp directory before it starts scanning
         */
        bool lastLineWasEmpty;
        bool headersParsed;
        int messagenumber;
        message *m = messageCreate(); /*Create an empty email */

        if (m == NULL) {
            cli_mark_scan_incomplete(ctx,
                                     "MIME mailbox message object could not be allocated");
            return CL_EMEM;
        }

        lastLineWasEmpty = false;
        headersParsed    = false;
        messagenumber    = 1;
        messageSetCTX(m, ctx);

        do {
            cli_chomp(buffer);
            /*if(lastLineWasEmpty && (strncmp(buffer, "From ", 5) == 0) && isalnum(buffer[5])) */
            if (lastLineWasEmpty && (strncmp(buffer, "From ", 5) == 0)) {
                cli_dbgmsg("Deal with message number %d\n", messagenumber++);
                /*
                 * End of a message in the mail box
                 */
                bool heuristicFound = false;
                if (headersParsed) {
                    /* Headers were finalized at the first body separator;
                     * m already contains only the current body. */
                    body          = m;
                    m             = NULL;
                    headersParsed = false;
                } else {
                    body = parseEmailHeaders(m, rfc821, &heuristicFound);
                    if (body == NULL) {
                        messageReset(m);
                        messageSetCTX(m, ctx);
                        if (heuristicFound) {
                            retcode = CL_VIRUS;
                            break;
                        }
                        continue;
                    }
                    messageDestroy(m);
                }
                messageSetCTX(body, ctx);
                if (body->isTruncated) {
                    cli_append_potentially_unwanted_if_heur_exceedsmax(
                        ctx, "Heuristics.Limits.Exceeded.MailMaterialization", CL_EMAXSIZE);
                    retcode = CL_EMAXSIZE;
                    /* Do not discard the limit result while advancing to a
                     * later message in the mailbox. The capped message was
                     * not fully represented and must not be scanned as if it
                     * were complete. */
                    messageDestroy(body);
                    body = NULL;
                    m    = NULL;
                    break;
                }
                if (messageGetBody(body) || messageHasBodySpool(body)) {
                    mbox_status rc = parseEmailBody(body, NULL, &mctx, 0);
                    if (rc == FAIL) {
                        m = body;
                        messageReset(m);
                        messageSetCTX(m, ctx);
                        continue;
                    } else if (rc == VIRUS) {
                        cli_dbgmsg("Message number %d is infected\n",
                                   messagenumber - 1);
                        retcode = CL_VIRUS;
                        m       = NULL;
                        break;
                    } else if (rc == MAXREC) {
                        retcode = CL_EMAXREC;
                        cli_append_potentially_unwanted_if_heur_exceedsmax(
                            ctx, "Heuristics.Limits.Exceeded.MaxRecursion", CL_EMAXREC);
                        messageDestroy(body);
                        body = NULL;
                        m    = NULL;
                        break;
                    } else if (rc == MAXFILES) {
                        retcode = CL_EMAXFILES;
                        cli_append_potentially_unwanted_if_heur_exceedsmax(
                            ctx, "Heuristics.Limits.Exceeded.MaxFiles", CL_EMAXFILES);
                        messageDestroy(body);
                        body = NULL;
                        m    = NULL;
                        break;
                    }
                }
                /*
                 * Starting a new message, throw away all the
                 * information about the old one. It would
                 * be best to be able to scan this message
                 * now, but cli_magic_scan_file needs arguments
                 * that haven't been passed here so it can't be
                 * called
                 */
                m = body;
                messageReset(m);
                messageSetCTX(m, ctx);

                cli_dbgmsg("Finished processing message\n");
            } else {
                lastLineWasEmpty = (bool)(buffer[0] == '\0');
            }

            if (!headersParsed && buffer[0] == '\0') {
                bool heuristicFound = false;

                /* Parse headers as soon as their separator arrives. This
                 * allows ordinary bodies to switch to disk-backed streaming
                 * before any large body content is retained in text nodes. */
                if (messageAddStr(m, NULL) < 0)
                    break;
                body = parseEmailHeaders(m, rfc821, &heuristicFound);
                if (body == NULL) {
                    messageReset(m);
                    messageSetCTX(m, ctx);
                    if (heuristicFound) {
                        retcode = CL_VIRUS;
                        break;
                    }
                    continue;
                }
                messageSetCTX(body, ctx);
                messageDestroy(m);
                m             = body;
                headersParsed = true;

                if (!messageNeedsMaterializedBody(m) && messageBeginBodySpool(m) < 0) {
                    m->isTruncated = true;
                    break;
                }
                continue;
            }

            if (isuuencodebegin(buffer)) {
                /*
                 * Fast track visa to uudecode.
                 * TODO: binhex, yenc
                 */
                {
                    int decode_status;
                    cl_error_t decode_failure = CL_SUCCESS;

                    decode_status = uudecodeFile(m, buffer, dir, map, &at, &decode_failure);

                    if (decode_status < 0) {
                        if (decode_failure != CL_SUCCESS) {
                            retcode = decode_failure;
                            break;
                        }
                        if (decode_status == UUDECODE_READ_ERROR) {
                            retcode = CL_EREAD;
                            break;
                        }
                        if (ctx->scan_timed_out) {
                            retcode = CL_ETIMEOUT;
                            break;
                        }
                        cli_mark_scan_incomplete(ctx, "UUencoded attachment in mail was not terminated or decoded completely");
                        if (messageAddStr(m, buffer) < 0) {
                            break;
                        }
                    }
                }
            } else {
                /* at this point, the \n has been removed */
                if (messageAddStr(m, buffer) < 0) {
                    break;
                }
            }
        } while (getline_from_mbox(buffer, sizeof(buffer) - 1, map, &at, ctx,
                                    &line_failure, !headersParsed) != NULL);

        if (retcode == CL_SUCCESS && line_failure != CL_SUCCESS)
            retcode = line_failure;

        if (retcode == CL_SUCCESS) {
            cli_dbgmsg("Extract attachments from email %d\n", messagenumber);
            if (headersParsed) {
                body          = m;
                m             = NULL;
                headersParsed = false;
            } else {
                bool heuristicFound = false;
                body                = parseEmailHeaders(m, rfc821, &heuristicFound);
                if (heuristicFound) {
                    retcode = CL_VIRUS;
                }
            }
        }
        if (m) {
            messageDestroy(m);
        }
    } else {
        /*
         * It's a single message, parse the headers then the body
         */
        if (strncmp(buffer, "P I ", 4) == 0) {
            /*
             * CommuniGate Pro format: ignore headers until
             * blank line
             */
            while (1) {
                if (mbox_check_deadline(ctx)) {
                    retcode = CL_ETIMEOUT;
                    break;
                }
                if (!fmap_gets(map, buffer, &at, sizeof(buffer))) {
                    if (at < map->len) {
                        cli_mark_scan_incomplete(ctx, "MIME message input could not be read completely");
                        retcode = CL_EREAD;
                    }
                    break;
                }
                if (strchr("\r\n", buffer[0]) != NULL)
                    break;
            }
        }
        /* getline_from_mbox could be using unlocked_stdio(3),
         * so lock file here */
        /*
         * Ignore any blank lines at the top of the message
         */
        while (strchr("\r\n", buffer[0]) &&
               (getline_from_mbox(buffer, sizeof(buffer) - 1, map, &at, ctx,
                                  &line_failure, true) != NULL)) {
            ;
        }

        if (retcode == CL_SUCCESS && line_failure != CL_SUCCESS)
            retcode = line_failure;

        buffer[sizeof(buffer) - 1] = '\0';

        bool heuristicFound = false;
        cl_error_t parse_status = CL_SUCCESS;
        body                = NULL;
        if (retcode == CL_SUCCESS) {
            body = parseEmailFile(map, &at, rfc821, buffer, dir, ctx, &heuristicFound, &parse_status);
            if (heuristicFound) {
                retcode = CL_VIRUS;
            } else if (parse_status != CL_SUCCESS) {
                retcode = parse_status;
            } else if (ctx->scan_timed_out) {
                retcode = CL_ETIMEOUT;
            }
        }
    }

    if (body) {
        /*
         * Write out the last entry in the mailbox
         */
        if ((retcode == CL_SUCCESS) && !body->isTruncated &&
            (messageGetBody(body) || messageHasBodySpool(body))) {
            messageSetCTX(body, ctx);
            switch (parseEmailBody(body, NULL, &mctx, 0)) {
                case OK:
                case OK_ATTACHMENTS_NOT_SAVED:
                    break;
                case FAIL:
                    /*
                     * beware: cli_magic_scan_desc(),
                     * changes this into CL_CLEAN, so only
                     * use it to inform the higher levels
                     * that we couldn't decode it because
                     * it isn't an mbox, not to signal
                     * decoding errors on what *is* a valid
                     * mbox
                     */
                    retcode = CL_EFORMAT;
                    break;
                case MAXREC:
                    retcode = CL_EMAXREC;
                    cli_append_potentially_unwanted_if_heur_exceedsmax(ctx, "Heuristics.Limits.Exceeded.MaxRecursion", CL_EMAXREC); // Doing this now because it's actually tracking email recursion,-
                                                                                                                                    // not fmap recursion, but it still is aborting with stuff not scanned.
                                                                                                                                    // Also, we didn't have access to the ctx when this happened earlier.
                    break;
                case MAXFILES:
                    retcode = CL_EMAXFILES;
                    cli_append_potentially_unwanted_if_heur_exceedsmax(ctx, "Heuristics.Limits.Exceeded.MaxFiles", CL_EMAXFILES); // Doing this now because it's actually tracking email parts,-
                                                                                                                                  // not actual files, but it still is aborting with stuff not scanned.
                                                                                                                                  // Also, we didn't have access to the ctx when this happened earlier.
                    break;
                case VIRUS:
                    retcode = CL_VIRUS;
                    break;
            }
        }

        if (body->isTruncated) {
            const cl_error_t materialization_status =
                messageGetMaterializationStatus(body);

            if (materialization_status != CL_SUCCESS &&
                (retcode == CL_SUCCESS || retcode == CL_EFORMAT))
                retcode = materialization_status;
            else if (retcode == CL_SUCCESS) {
                cli_append_potentially_unwanted_if_heur_exceedsmax(
                    ctx, "Heuristics.Limits.Exceeded.MailMaterialization", CL_EMAXSIZE);
                retcode = CL_EMAXSIZE;
            }
        }

        /*
         * Tidy up and quit
         */
        messageDestroy(body);
    }

    /* A parser may have already scanned a child successfully after skipping
     * required input. Do not allow that sticky state to collapse into a
     * clean mailbox result while unwinding to cli_scanmail(). */
    if ((retcode != CL_VIRUS) && ctx->scan_timed_out)
        retcode = CL_ETIMEOUT;
    else if ((retcode == CL_SUCCESS || retcode == CL_EFORMAT || retcode == CL_EPARSE) &&
             mctx.message_failure_status != CL_SUCCESS)
        retcode = mctx.message_failure_status;
    else if ((retcode == CL_SUCCESS) && ctx->scan_incomplete)
        retcode = CL_EPARSE;

    cli_dbgmsg("cli_mbox returning %d\n", retcode);

    return retcode;
}

#define READ_STRUCT_BUFFER_LEN 1024
typedef struct _ReadStruct {
    char buffer[READ_STRUCT_BUFFER_LEN + 1];

    size_t bufferLen;

    struct _ReadStruct *next;

} ReadStruct;

static ReadStruct *
appendReadStruct(ReadStruct *rs, const char *const buffer)
{
    if (NULL == rs || NULL == buffer || rs->bufferLen > READ_STRUCT_BUFFER_LEN) {
        cli_dbgmsg("appendReadStruct: Invalid argument\n");
        goto done;
    }

    size_t spaceLeft = (READ_STRUCT_BUFFER_LEN - rs->bufferLen);

    if (strlen(buffer) > spaceLeft) {
        ReadStruct *next = NULL;
        int part         = spaceLeft;
        strncpy(&(rs->buffer[rs->bufferLen]), buffer, part);
        rs->bufferLen += part;

        CLI_CALLOC_OR_GOTO_DONE(next, 1, sizeof(ReadStruct));

        rs->next = next;
        strcpy(next->buffer, &(buffer[part]));
        next->bufferLen = strlen(&(buffer[part]));

        rs = next;
    } else {
        strcpy(&(rs->buffer[rs->bufferLen]), buffer);
        rs->bufferLen += strlen(buffer);
    }

done:
    return rs;
}

static char *
getMallocedBufferFromList(const ReadStruct *head)
{

    const ReadStruct *rs = head;
    size_t bufferLen      = 1;
    char *working        = NULL;
    char *ret            = NULL;

    while (rs) {
        bufferLen += rs->bufferLen;
        rs = rs->next;
    }

    CLI_MAX_MALLOC_OR_GOTO_DONE(working, bufferLen);

    rs        = head;
    bufferLen = 0;
    while (rs) {
        memcpy(&(working[bufferLen]), rs->buffer, rs->bufferLen);
        bufferLen += rs->bufferLen;
        working[bufferLen] = 0;
        rs                 = rs->next;
    }

    ret = working;
done:
    if (NULL == ret) {
        CLI_FREE_AND_SET_NULL(working);
    }

    return ret;
}

static void
freeList(ReadStruct *head)
{
    while (head) {
        ReadStruct *rs = head->next;
        CLI_FREE_AND_SET_NULL(head);
        head = rs;
    }
}

#ifndef FREELIST_REALLOC
#define FREELIST_REALLOC(head, curr) \
    do {                             \
        if (curr != head) {          \
            freeList(head->next);    \
        }                            \
        head->bufferLen = 0;         \
        head->next      = 0;         \
        curr            = head;      \
    } while (0)
#endif /*FREELIST_REALLOC*/

/*Check if we have repeated blank lines with only a semicolon at the end.  Semicolon is a delimiter for parameters,
 * but if there is no data, it isn't a parameter.  Allow the first one because it may be continuation of a previous line
 * that actually had data in it.*/
static bool
doContinueMultipleEmptyOptions(const char *const line, bool *lastWasOnlySemi)
{
    if (line) {
        size_t i   = 0;
        int doCont = 1;
        for (; i < strlen(line); i++) {
            if (isblank(line[i])) {
            } else if (';' == line[i]) {
            } else {
                doCont = 0;
                break;
            }
        }

        if (1 == doCont) {
            if (*lastWasOnlySemi) {
                return true;
            }
            *lastWasOnlySemi = true;
        } else {
            *lastWasOnlySemi = false;
        }
    }
    return false;
}

static bool
hitLineFoldCnt(const char *const line, size_t *lineFoldCnt, cli_ctx *ctx, bool *heuristicFound)
{

    if (line) {
        if (isblank(line[0])) {
            (*lineFoldCnt)++;
        } else {
            (*lineFoldCnt) = 0;
        }

        if ((*lineFoldCnt) >= HEURISTIC_EMAIL_MAX_LINE_FOLDS_PER_HEADER) {
            if (SCAN_HEURISTIC_EXCEEDS_MAX) {
                cli_append_potentially_unwanted(ctx, "Heuristics.Limits.Exceeded.EmailLineFoldCnt");
                *heuristicFound = true;
            }
            cli_mark_scan_incomplete(ctx,
                                     "MIME parser exceeded the configured folded-header limit");

            return true;
        }
    }
    return false;
}

static bool
haveTooManyHeaderBytes(size_t totalLen, cli_ctx *ctx, bool *heuristicFound)
{

    if (totalLen > HEURISTIC_EMAIL_MAX_HEADER_BYTES) {
        if (SCAN_HEURISTIC_EXCEEDS_MAX) {
            cli_append_potentially_unwanted(ctx, "Heuristics.Limits.Exceeded.EmailHeaderBytes");
            *heuristicFound = true;
        }
        cli_mark_scan_incomplete(ctx,
                                 "MIME parser exceeded the configured header-byte limit");

        return true;
    }
    return false;
}

static bool
haveTooManyEmailHeaders(size_t totalHeaderCnt, cli_ctx *ctx, bool *heuristicFound)
{

    if (totalHeaderCnt > HEURISTIC_EMAIL_MAX_HEADERS) {
        if (SCAN_HEURISTIC_EXCEEDS_MAX) {
            cli_append_potentially_unwanted(ctx, "Heuristics.Limits.Exceeded.EmailHeaders");
            *heuristicFound = true;
        }
        cli_mark_scan_incomplete(ctx,
                                 "MIME parser exceeded the configured header-count limit");

        return true;
    }
    return false;
}

static bool
haveTooManyMIMEPartsPerMessage(size_t mimePartCnt, cli_ctx *ctx, mbox_status *rc)
{

    if (mimePartCnt >= HEURISTIC_EMAIL_MAX_MIME_PARTS_PER_MESSAGE) {
        if (SCAN_HEURISTIC_EXCEEDS_MAX) {
            cli_append_potentially_unwanted(ctx, "Heuristics.Limits.Exceeded.EmailMIMEPartsPerMessage");
            *rc = VIRUS;
        }
        cli_mark_scan_incomplete(ctx,
                                 "MIME parser exceeded the configured MIME-part limit");
        if (*rc == OK)
            *rc = FAIL;

        return true;
    }
    return false;
}

static bool
haveTooManyMIMEArguments(size_t argCnt, cli_ctx *ctx, bool *heuristicFound)
{

    if (argCnt >= HEURISTIC_EMAIL_MAX_ARGUMENTS_PER_HEADER) {
        if (SCAN_HEURISTIC_EXCEEDS_MAX) {
            cli_append_potentially_unwanted(ctx, "Heuristics.Limits.Exceeded.EmailMIMEArguments");
            *heuristicFound = true;
        }
        cli_mark_scan_incomplete(ctx,
                                 "MIME parser exceeded the configured MIME-argument limit");

        return true;
    }

    return false;
}

/*
 * Read in an email message from fin, parse it, and return the message
 *
 * FIXME: files full of new lines and nothing else are
 * handled ungracefully...
 */
static message *
parseEmailFile(fmap_t *map, size_t *at, const table_t *rfc821, const char *firstLine, const char *dir, cli_ctx *ctx, bool *heuristicFound, cl_error_t *failure_status)
{
    bool inHeader     = true;
    bool bodyIsEmpty  = true;
    bool lastWasBlank = false, lastBodyLineWasBlank = false;
    message *ret;
    bool anyHeadersFound = false;
    int commandNumber    = -1;
    char *boundary       = NULL;
    char buffer[RFC2821LENGTH + 1];
    bool lastWasOnlySemi    = false;
    int err                 = 1;
    size_t totalHeaderBytes = 0;
    size_t totalHeaderCnt   = 0;
    size_t first_line_len;

    size_t lineFoldCnt = 0;

    *heuristicFound = false;
    if (failure_status)
        *failure_status = CL_SUCCESS;

    ReadStruct *head = NULL;
    ReadStruct *curr = NULL;
    cli_dbgmsg("parseEmailFile\n");

    ret = messageCreate();
    if (ret == NULL) {
        cli_mark_scan_incomplete(ctx,
                                 "MIME message body object could not be allocated");
        return NULL;
    }
    messageSetCTX(ret, ctx);

    CLI_CALLOC_OR_GOTO_DONE(head, 1, sizeof(ReadStruct));
    curr = head;

    first_line_len = 0;
    while (first_line_len < sizeof(buffer) - 1U && firstLine[first_line_len] != '\0')
        first_line_len++;
    memcpy(buffer, firstLine, first_line_len);
    buffer[first_line_len] = '\0';
    do {
        const char *line;

        if (mbox_check_deadline(ctx))
            break;

        (void)cli_chomp(buffer);

        if (buffer[0] == '\0')
            line = NULL;
        else
            line = buffer;

        if (doContinueMultipleEmptyOptions(line, &lastWasOnlySemi)) {
            continue;
        }

        if (hitLineFoldCnt(line, &lineFoldCnt, ctx, heuristicFound)) {
            break;
        }

        /*
         * Don't blank lines which are only spaces from headers,
         * otherwise they'll be treated as the end of header marker
         */
        if (lastWasBlank) {
            lastWasBlank = false;
            if (boundaryStart(buffer, boundary)) {
                cli_dbgmsg("Found a header line with space that should be blank\n");
                inHeader = false;
            }
        }
        if (inHeader) {
            cli_dbgmsg("parseEmailFile: check '%s'\n", buffer);

            /*
             * Ensure wide characters are handled where
             * sizeof(char) > 1
             */
            if (line && isspace(line[0] & 0xFF)) {
                char copy[sizeof(buffer)];

                strcpy(copy, buffer);
                strstrip(copy);
                if (copy[0] == '\0') {
                    /*
                     * The header line contains only white
                     * space. This is not the end of the
                     * headers according to RFC2822, but
                     * some MUAs will handle it as though
                     * it were, and virus writers exploit
                     * this bug. We can't just break from
                     * the loop here since that would allow
                     * other exploits such as inserting a
                     * white space line before the
                     * content-type line. So we just have
                     * to make a best guess. Sigh.
                     */
                    if (head->bufferLen) {
                        char *header     = getMallocedBufferFromList(head);
                        int needContinue = 0;
                        if (header == NULL) {
                            cli_mark_scan_incomplete(ctx,
                                                     "MIME header line could not be materialized");
                            goto done;
                        }

                        totalHeaderCnt++;
                        if (haveTooManyEmailHeaders(totalHeaderCnt, ctx, heuristicFound)) {
                            CLI_FREE_AND_SET_NULL(header);
                            break;
                        }
                        needContinue = (parseEmailHeader(ret, header, rfc821, ctx, heuristicFound) < 0);
                        if (*heuristicFound) {
                            CLI_FREE_AND_SET_NULL(header);
                            break;
                        }

                        CLI_FREE_AND_SET_NULL(header);
                        FREELIST_REALLOC(head, curr);

                        if (needContinue) {
                            continue;
                        }
                    }

                    if (boundary ||
                        ((boundary = (char *)messageFindArgument(ret, "boundary")) != NULL)) {
                        lastWasBlank = true;
                        continue;
                    }
                }
            }
            if ((line == NULL) && (0 == head->bufferLen)) { /* empty line */
                /*
                 * A blank line signifies the end of
                 * the header and the start of the text
                 */
                if (!anyHeadersFound)
                    /* Ignore the junk at the top */
                    continue;

                cli_dbgmsg("End of header information\n");
                inHeader    = false;
                bodyIsEmpty = true;
                /* Multipart and encapsulated-message bodies still need the
                 * legacy boundary/header state machine. Ordinary text and
                 * application parts can be consumed incrementally into the
                 * shared disk-backed spool instead of retaining every line. */
                if (!messageNeedsMaterializedBody(ret) && messageBeginBodySpool(ret) < 0) {
                    ret->isTruncated = true;
                    break;
                }
            } else {
                char *ptr;
                const char *lookahead;
                bool lineAdded = true;

                if (0 == head->bufferLen) {
                    char cmd[RFC2821LENGTH + 1], out[RFC2821LENGTH + 1];

                    /*
                     * Continuation of line we're ignoring?
                     */
                    if (isblank(line[0]))
                        continue;

                    /*
                     * Is this a header we're interested in?
                     */
                    if ((strchr(line, ':') == NULL) ||
                        (cli_strtokbuf(line, 0, ":", cmd) == NULL)) {
                        if (strncmp(line, "From ", 5) == 0)
                            anyHeadersFound = true;
                        continue;
                    }

                    ptr           = rfc822comments(cmd, out);
                    commandNumber = tableFind(rfc821, ptr ? ptr : cmd);

                    switch (commandNumber) {
                        case CONTENT_TRANSFER_ENCODING:
                        case CONTENT_DISPOSITION:
                        case CONTENT_TYPE:
                            anyHeadersFound = true;
                            break;
                        default:
                            if (!anyHeadersFound)
                                anyHeadersFound = usefulHeader(commandNumber, cmd);
                            continue;
                    }
                    curr = appendReadStruct(curr, line);
                    if (NULL == curr) {
                        cli_mark_scan_incomplete(ctx,
                                                 "MIME header read structure could not be allocated");
                        ret->isTruncated = true;
                        break;
                    }
                } else if (line != NULL) {
                    curr = appendReadStruct(curr, line);
                    if (NULL == curr) {
                        cli_mark_scan_incomplete(ctx,
                                                 "MIME header read structure could not be allocated");
                        ret->isTruncated = true;
                        break;
                    }
                } else {
                    lineAdded = false;
                }

                if (lineAdded) {
                    const size_t line_len = strlen(line);

                    if (line_len > SIZE_MAX - totalHeaderBytes) {
                        cli_mark_scan_incomplete(ctx,
                                                 "MIME message header size exceeded native representation");
                        break;
                    }
                    totalHeaderBytes += line_len;
                    if (haveTooManyHeaderBytes(totalHeaderBytes, ctx, heuristicFound)) {
                        break;
                    }
                }

                lookahead = fmap_need_off_once(map, *at, 1);
                if (lookahead == NULL && *at < map->len) {
                    cli_mark_scan_incomplete(ctx, "MIME message header lookahead could not be read completely");
                    if (failure_status)
                        *failure_status = CL_EREAD;
                    break;
                }
                if (lookahead) {
                    /*
                     * Section B.2 of RFC822 says TAB or
                     * SPACE means a continuation of the
                     * previous entry.
                     *
                     * Add all the arguments on the line
                     */
                    if (isblank(*lookahead))
                        continue;
                }

                /*
                 * Handle broken headers, where the next
                 * line isn't indented by whitespace
                 */
                {
                    char *header     = getMallocedBufferFromList(head); /*This is the issue */
                    int needContinue = 0;
                    if (header == NULL) {
                        cli_mark_scan_incomplete(ctx,
                                                 "MIME header line could not be materialized");
                        goto done;
                    }

                    needContinue = (header[strlen(header) - 1] == ';');
                    if (0 == needContinue) {
                        needContinue = (line && (count_quotes(header) & 1));
                    }

                    if (0 == needContinue) {
                        totalHeaderCnt++;
                        if (haveTooManyEmailHeaders(totalHeaderCnt, ctx, heuristicFound)) {
                            CLI_FREE_AND_SET_NULL(header);
                            break;
                        }
                        needContinue = (parseEmailHeader(ret, header, rfc821, ctx, heuristicFound) < 0);
                        if (*heuristicFound) {
                            CLI_FREE_AND_SET_NULL(header);
                            break;
                        }
                        /*Check total headers here;*/
                    }

                    CLI_FREE_AND_SET_NULL(header);
                    if (needContinue) {
                        continue;
                    }
                    FREELIST_REALLOC(head, curr);
                }
            }
        } else if (line && isuuencodebegin(line)) {
            /*
             * Fast track visa to uudecode.
             * TODO: binhex, yenc
             */
            bodyIsEmpty = false;
            int decode_status;
            cl_error_t decode_failure = CL_SUCCESS;

            decode_status = uudecodeFile(ret, line, dir, map, at, &decode_failure);

            if (decode_status < 0) {
                if (decode_failure != CL_SUCCESS) {
                    if (failure_status)
                        *failure_status = decode_failure;
                    break;
                }
                if (ctx->scan_timed_out)
                    break;
                if (decode_status == UUDECODE_READ_ERROR) {
                    if (failure_status)
                        *failure_status = CL_EREAD;
                    break;
                }
                cli_mark_scan_incomplete(ctx, "UUencoded attachment in mail was not terminated or decoded completely");
                if (messageAddStr(ret, line) < 0) {
                    ret->isTruncated = true;
                    break;
                }
            }
        } else {
            if (line == NULL) {
                /*
                 * Although this would save time and RAM, some
                 * phish signatures have been built which need
                 * the blank lines
                 */
                if (lastBodyLineWasBlank &&
                    (messageGetMimeType(ret) != TEXT)) {
                    cli_dbgmsg("Ignoring consecutive blank lines in the body\n");
                    continue;
                }
                lastBodyLineWasBlank = true;
            } else {
                if (bodyIsEmpty) {
                    /*
                     * Broken message: new line in the
                     * middle of the headers, so the first
                     * line of the body is in fact
                     * the last lines of the header
                     */
                    if (newline_in_header(line))
                        continue;
                    bodyIsEmpty = false;
                }
                lastBodyLineWasBlank = false;
            }

            if (messageAddStr(ret, line) < 0) {
                ret->isTruncated = true;
                break;
            }
        }
    } while (getline_from_mbox(buffer, sizeof(buffer) - 1, map, at, ctx,
                               failure_status, inHeader) != NULL);

    err = 0;
done:
    if (head == NULL)
        cli_mark_scan_incomplete(ctx,
                                 "MIME header read list could not be allocated");
    if (err) {
        cli_errmsg("parseEmailFile: ERROR parsing file\n");
        ret->isTruncated = true;
    }

    CLI_FREE_AND_SET_NULL(boundary);

    freeList(head);

    if (!anyHeadersFound) {
        /*
         * False positive in believing we have an e-mail when we don't
         */
        messageDestroy(ret);
        cli_dbgmsg("parseEmailFile: no headers found, assuming it isn't an email\n");
        return NULL;
    }

    if (*heuristicFound) {
        messageDestroy(ret);
        cli_dbgmsg("parseEmailFile: found heuristic\n");
        return NULL;
    }

    cli_dbgmsg("parseEmailFile: return\n");

    return ret;
}

/*
 * The given message contains a raw e-mail.
 *
 * Returns the message's body with the correct arguments set, empties the
 * given message's contents (note that it isn't destroyed)
 *
 * TODO: remove the duplication with parseEmailFile
 */
static message *
parseEmailHeaders(message *m, const table_t *rfc821, bool *heuristicFound)
{
    bool inHeader    = true;
    bool bodyIsEmpty = true;
    text *t;
    message *ret;
    bool anyHeadersFound  = false;
    int commandNumber     = -1;
    char *fullline        = NULL;
    size_t fulllinelength = 0;
    bool lastWasOnlySemi  = false;
    size_t lineFoldCnt    = 0;
    size_t totalHeaderCnt = 0;

    cli_dbgmsg("parseEmailHeaders\n");

    *heuristicFound = false;

    if (m == NULL)
        return NULL;

    ret = messageCreate();
    if (ret == NULL) {
        cli_mark_scan_incomplete(m->ctx,
                                 "MIME parsed-header object could not be allocated");
        return NULL;
    }
    messageSetCTX(ret, m->ctx);
    ret->isTruncated = m->isTruncated;

    for (t = messageGetBody(m); t; t = t->t_next) {
        const char *line;

        if (mbox_check_deadline(m->ctx))
            break;

        if (t->t_line)
            line = lineGetData(t->t_line);
        else
            line = NULL;

        if (doContinueMultipleEmptyOptions(line, &lastWasOnlySemi)) {
            continue;
        }

        if (hitLineFoldCnt(line, &lineFoldCnt, m->ctx, heuristicFound)) {
            break;
        }

        if (inHeader) {
            cli_dbgmsg("parseEmailHeaders: check '%s'\n",
                       line ? line : "");
            if (line == NULL) {
                /*
                 * A blank line signifies the end of
                 * the header and the start of the text
                 */
                cli_dbgmsg("End of header information\n");
                if (!anyHeadersFound) {
                    cli_dbgmsg("Nothing interesting in the header\n");
                    break;
                }
                inHeader    = false;
                bodyIsEmpty = true;
            } else {
                char *ptr;
                bool lineAdded = true;

                if (fullline == NULL) {
                    char cmd[RFC2821LENGTH + 1];

                    /*
                     * Continuation of line we're ignoring?
                     */
                    if (isblank(line[0]))
                        continue;

                    /*
                     * Is this a header we're interested in?
                     */
                    if ((strchr(line, ':') == NULL) ||
                        (cli_strtokbuf(line, 0, ":", cmd) == NULL)) {
                        if (strncmp(line, "From ", 5) == 0)
                            anyHeadersFound = true;
                        continue;
                    }

                    ptr           = rfc822comments(cmd, NULL);
                    commandNumber = tableFind(rfc821, ptr ? ptr : cmd);
                    if (ptr)
                        free(ptr);

                    switch (commandNumber) {
                        case CONTENT_TRANSFER_ENCODING:
                        case CONTENT_DISPOSITION:
                        case CONTENT_TYPE:
                            anyHeadersFound = true;
                            break;
                        default:
                            if (!anyHeadersFound)
                                anyHeadersFound = usefulHeader(commandNumber, cmd);
                            continue;
                    }
                    {
                        const size_t line_len = strlen(line);

                        if (line_len == SIZE_MAX) {
                            cli_mark_scan_incomplete(m->ctx,
                                                     "MIME header line size exceeded native representation");
                            continue;
                        }
                        fullline       = cli_safer_strdup(line);
                        fulllinelength = line_len + 1U;
                    }
                    if (fullline == NULL) {
                        cli_mark_scan_incomplete(m->ctx,
                                                 "MIME header line could not be allocated");
                        continue;
                    }
                } else if (line) {
                    const size_t line_len = strlen(line);

                    if (line_len == SIZE_MAX || fulllinelength > SIZE_MAX - line_len - 1U) {
                        cli_mark_scan_incomplete(m->ctx,
                                                 "MIME folded header size exceeded native representation");
                        free(fullline);
                        fullline       = NULL;
                        fulllinelength = 0;
                        continue;
                    }
                    fulllinelength += line_len + 1U;
                    ptr = cli_max_realloc(fullline, fulllinelength);
                    if (ptr == NULL) {
                        cli_mark_scan_incomplete(m->ctx,
                                                 "MIME folded header could not be allocated");
                        free(fullline);
                        fullline       = NULL;
                        fulllinelength = 0;
                        continue;
                    }
                    fullline = ptr;
                    cli_strlcat(fullline, line, fulllinelength);
                } else {
                    lineAdded = false;
                }

                /*continue doesn't seem right here, but that is what is done everywhere else when a malloc fails.*/
                if (NULL == fullline) {
                    continue;
                }

                if (lineAdded) {
                    if (haveTooManyHeaderBytes(fulllinelength, m->ctx, heuristicFound)) {
                        break;
                    }
                }

                if (next_is_folded_header(t))
                    /* Add arguments to this line */
                    continue;

                lineUnlink(t->t_line);
                t->t_line = NULL;

                if (count_quotes(fullline) & 1)
                    continue;

                ptr = rfc822comments(fullline, NULL);
                if (ptr) {
                    free(fullline);
                    fullline = ptr;
                }

                totalHeaderCnt++;
                if (haveTooManyEmailHeaders(totalHeaderCnt, m->ctx, heuristicFound)) {
                    break;
                }
                {
                    const int header_status =
                        parseEmailHeader(ret, fullline, rfc821, m->ctx, heuristicFound);

                    /* A failed or heuristic header is terminal for this
                     * assembled header, but neither outcome owns the
                     * temporary buffer. Reset it before continuing so the
                     * next physical header cannot be appended to stale
                     * state, and so an error path cannot leak the buffer. */
                    free(fullline);
                    fullline       = NULL;
                    fulllinelength = 0;

                    if (header_status < 0)
                        continue;
                    if (*heuristicFound)
                        break;
                }
            }
        } else {
            if (bodyIsEmpty) {
                if (line == NULL)
                    /* throw away leading blank lines */
                    continue;
                /*
                 * Broken message: new line in the
                 * middle of the headers, so the first
                 * line of the body is in fact
                 * the last lines of the header
                 */
                if (newline_in_header(line))
                    continue;
                bodyIsEmpty = false;
            }
            /*if(t->t_line && isuuencodebegin(t->t_line))
                puts("FIXME: add fast visa here");*/
            cli_dbgmsg("parseEmailHeaders: finished with headers, moving body\n");
            messageMoveText(ret, t, m);
            break;
        }
    }

    if (m->ctx && m->ctx->scan_timed_out) {
        if (fullline)
            free(fullline);
        messageDestroy(ret);
        return NULL;
    }

    if (fullline) {
        if (*fullline) switch (commandNumber) {
                case CONTENT_TRANSFER_ENCODING:
                case CONTENT_DISPOSITION:
                case CONTENT_TYPE:
                    cli_dbgmsg("parseEmailHeaders: Fullline unparsed '%s'\n", fullline);
            }
        free(fullline);
    }

    if (!anyHeadersFound) {
        /*
         * False positive in believing we have an e-mail when we don't
         */
        messageDestroy(ret);
        cli_dbgmsg("parseEmailHeaders: no headers found, assuming it isn't an email\n");
        return NULL;
    }
    if (*heuristicFound) {
        messageDestroy(ret);
        cli_dbgmsg("parseEmailHeaders: found a heuristic, delete message and stop parsing.\n");
        return NULL;
    }

    cli_dbgmsg("parseEmailHeaders: return\n");

    return ret;
}

/*
 * Handle a header line of an email message
 */
static int
parseEmailHeader(message *m, const char *line, const table_t *rfc821, cli_ctx *ctx, bool *heuristicFound)
{
    int ret = -1;
#ifdef CL_THREAD_SAFE
    char *strptr;
#endif
    const char *separator;
    char *cmd, *copy, tokenseparator[2];

    cli_dbgmsg("parseEmailHeader '%s'\n", line);

    /*
     * In RFC822 the separator between the key a value is a colon,
     * e.g.    Content-Transfer-Encoding: base64
     * However some MUA's are lapse about this and virus writers exploit
     * this hole, so we need to check all known possibilities
     */
    for (separator = ":= "; *separator; separator++)
        if (strchr(line, *separator) != NULL)
            break;

    if (*separator == '\0')
        return -1;

    copy = rfc2047(line, ctx);
    if (copy == NULL) {
        /* an RFC checker would return -1 here */
        copy = cli_safer_strdup(line);
        if (NULL == copy) {
            cli_mark_scan_incomplete(ctx,
                                     "MIME header command could not be allocated");
            goto done;
        }
    }

    tokenseparator[0] = *separator;
    tokenseparator[1] = '\0';

#ifdef CL_THREAD_SAFE
    cmd = strtok_r(copy, tokenseparator, &strptr);
#else
    cmd = strtok(copy, tokenseparator);
#endif

    if (cmd && (strstrip(cmd) > 0)) {
#ifdef CL_THREAD_SAFE
        char *arg = strtok_r(NULL, "", &strptr);
#else
        char *arg = strtok(NULL, "");
#endif

        if (arg) {
            /*
             * Found a header such as
             * Content-Type: multipart/mixed;
             * set arg to be
             * "multipart/mixed" and cmd to
             * be "Content-Type"
             */
            ret = parseMimeHeader(m, cmd, rfc821, arg, ctx, heuristicFound);
        }
    }
done:
    CLI_FREE_AND_SET_NULL(copy);

    return ret;
}

static const struct key_entry mhtml_keys[] = {
    /* root html tags for microsoft office document */
    {"html", "RootHTML", MSXML_JSON_ROOT | MSXML_JSON_ATTRIB},

    {"head", "Head", MSXML_JSON_WRKPTR | MSXML_COMMENT_CB},
    {"meta", "Meta", MSXML_JSON_WRKPTR | MSXML_JSON_MULTI | MSXML_JSON_ATTRIB},
    {"link", "Link", MSXML_JSON_WRKPTR | MSXML_JSON_MULTI | MSXML_JSON_ATTRIB},
    {"script", "Script", MSXML_JSON_WRKPTR | MSXML_JSON_MULTI | MSXML_JSON_VALUE}};
static size_t num_mhtml_keys = sizeof(mhtml_keys) / sizeof(struct key_entry);

static const struct key_entry mhtml_comment_keys[] = {
    /* embedded xml tags (comment) for microsoft office document */
    {"o:documentproperties", "DocumentProperties", MSXML_JSON_ROOT | MSXML_JSON_ATTRIB},
    {"o:author", "Author", MSXML_JSON_WRKPTR | MSXML_JSON_VALUE},
    {"o:lastauthor", "LastAuthor", MSXML_JSON_WRKPTR | MSXML_JSON_VALUE},
    {"o:revision", "Revision", MSXML_JSON_WRKPTR | MSXML_JSON_VALUE},
    {"o:totaltime", "TotalTime", MSXML_JSON_WRKPTR | MSXML_JSON_VALUE},
    {"o:created", "Created", MSXML_JSON_WRKPTR | MSXML_JSON_VALUE},
    {"o:lastsaved", "LastSaved", MSXML_JSON_WRKPTR | MSXML_JSON_VALUE},
    {"o:pages", "Pages", MSXML_JSON_WRKPTR | MSXML_JSON_VALUE},
    {"o:words", "Words", MSXML_JSON_WRKPTR | MSXML_JSON_VALUE},
    {"o:characters", "Characters", MSXML_JSON_WRKPTR | MSXML_JSON_VALUE},
    {"o:company", "Company", MSXML_JSON_WRKPTR | MSXML_JSON_VALUE},
    {"o:lines", "Lines", MSXML_JSON_WRKPTR | MSXML_JSON_VALUE},
    {"o:paragraphs", "Paragraphs", MSXML_JSON_WRKPTR | MSXML_JSON_VALUE},
    {"o:characterswithspaces", "CharactersWithSpaces", MSXML_JSON_WRKPTR | MSXML_JSON_VALUE},
    {"o:version", "Version", MSXML_JSON_WRKPTR | MSXML_JSON_VALUE},

    {"o:officedocumentsettings", "DocumentSettings", MSXML_IGNORE_ELEM},
    {"w:worddocument", "WordDocument", MSXML_IGNORE_ELEM},
    {"w:latentstyles", "LatentStyles", MSXML_IGNORE_ELEM}};
static size_t num_mhtml_comment_keys = sizeof(mhtml_comment_keys) / sizeof(struct key_entry);

/* MHTML comments are metadata only. Keep the legacy in-memory XML reader from
 * turning an attacker-sized comment into an unaccounted contiguous allocation
 * or an int-sized length conversion. */
#define MHTML_COMMENT_XML_MAX_SIZE (64U * 1024U * 1024U)

/*
 * The related multipart root HTML file comment parsing wrapper.
 *
 * Attempts to leverage msxml parser, cannot operate without LIBXML2.
 * This function is only used for Preclassification JSON.
 */
static cl_error_t parseMHTMLComment(const char *comment, cli_ctx *ctx, void *wrkjobj, void *cbdata)
{
    cl_error_t ret = CL_SUCCESS;

    const char *xmlsrt, *xmlend, *search;
    size_t comment_len, remaining, xml_offset, xml_remaining, fragment_len;
    xmlTextReaderPtr reader;

    UNUSEDPARAM(cbdata);
    UNUSEDPARAM(wrkjobj);

    if (comment == NULL) {
        cli_dbgmsg("parseMHTMLComment: comment value is missing\n");
        cli_mark_scan_incomplete(ctx, "MHTML comment XML value was unavailable");
        return CL_EPARSE;
    }

    comment_len = CLI_STRNLEN(comment, (size_t)MHTML_COMMENT_XML_MAX_SIZE + 1U);
    if (comment_len > MHTML_COMMENT_XML_MAX_SIZE) {
        cli_dbgmsg("parseMHTMLComment: comment exceeds bounded metadata limit\n");
        cli_mark_scan_incomplete(ctx, "MHTML comment XML exceeds bounded metadata limit");
        return CL_ERESOURCE;
    }

    search    = comment;
    remaining = comment_len;
    while ((xmlsrt = CLI_STRNSTR(search, "<xml>", remaining)) != NULL) {
        xml_offset   = (size_t)(xmlsrt - comment);
        xml_remaining = comment_len - xml_offset;
        xmlend       = CLI_STRNSTR(xmlsrt + sizeof("<xml>") - 1U, "</xml>",
                             xml_remaining - (sizeof("<xml>") - 1U));
        if (xmlend == NULL) {
            cli_dbgmsg("parseMHTMLComment: unbounded xml tag\n");
            cli_mark_scan_incomplete(ctx, "MHTML comment XML element was not terminated");
            return CL_EPARSE;
        }

        fragment_len = (size_t)(xmlend - xmlsrt) + (sizeof("</xml>") - 1U);
        if (fragment_len > INT_MAX) {
            cli_dbgmsg("parseMHTMLComment: XML fragment exceeds reader length limit\n");
            cli_mark_scan_incomplete(ctx, "MHTML comment XML fragment exceeds reader length limit");
            return CL_ERESOURCE;
        }

        reader = xmlReaderForMemory(xmlsrt, (int)fragment_len, "comment.xml", NULL, CLAMAV_MIN_XMLREADER_FLAGS);
        if (!reader) {
            cli_dbgmsg("parseMHTMLComment: cannot initialize xmlReader\n");

            cli_mark_scan_incomplete(ctx, "MHTML comment XML reader could not be initialized");

            if (ctx->this_layer_metadata_json != NULL &&
                cli_json_parse_error(ctx->this_layer_metadata_json, "MHTML_ERROR_XML_READER_MEM") != CL_SUCCESS)
                cli_mark_scan_incomplete(ctx, "MHTML XML-reader memory error metadata could not be recorded");

            return CL_EPARSE; // libxml2 failed!
        }

        /* comment callback is not set to prevent recursion */
        /* TODO: should we separate the key dictionaries? */
        /* TODO: should we use the json object pointer? */
        ret = cli_msxml_parse_document(ctx, reader, mhtml_comment_keys, num_mhtml_comment_keys,
                                       MSXML_FLAG_JSON | MSXML_FLAG_FAIL_INCOMPLETE, NULL);

        xmlTextReaderClose(reader);
        xmlFreeTextReader(reader);
        if (ret != CL_SUCCESS)
            return ret;

        search    = xmlend + (sizeof("</xml>") - 1U);
        remaining = comment_len - (size_t)(search - comment);
    }
    return ret;
}

/*
 * The related multipart root HTML file parsing wrapper.
 *
 * Attempts to leverage msxml parser, cannot operate without LIBXML2.
 * This function is only used for Preclassification JSON.
 */
static mbox_status
parseRootMHTML(mbox_ctx *mctx, message *m, text *t)
{
    cli_ctx *ctx = mctx->ctx;
#ifdef LIBXML_HTML_ENABLED
    struct msxml_ctx mxctx;
    fileblob *input_fb = NULL;
    const char *input_path = NULL;
    bool borrowed_input   = false;
    htmlDocPtr htmlDoc;
    xmlTextReaderPtr reader;
    int ret        = CL_SUCCESS;
    mbox_status rc = OK;
    mbox_status metadata_rc = OK;
    json_object *rhtml;

    cli_dbgmsg("in parseRootMHTML\n");

    if (ctx == NULL)
        return OK;

    if (m == NULL && t == NULL)
        return OK;

    /* Prefer the completed raw body spool directly. Encoded spools and the
     * legacy line-list representation are exported to a file-backed input,
     * keeping the HTML preclassifier out of the bounded blob materialization
     * path. */
    if (m != NULL && m->body_spool &&
        (messageGetEncoding(m) == NOENCODING || messageGetEncoding(m) == BINARY ||
         messageGetEncoding(m) == EIGHTBIT)) {
        input_fb       = m->body_spool;
        borrowed_input = true;
        if (input_fb->isIncomplete || input_fb->fp == NULL || input_fb->fullname == NULL ||
            fflush(input_fb->fp) != 0) {
            mbox_record_message_failure(mctx, m,
                                        "MHTML root HTML input could not be materialized completely");
            input_fb = NULL;
        }
    } else if (m != NULL) {
        input_fb = messageToFileblob(m, mctx->dir, 0);
        if (input_fb == NULL)
            mbox_record_message_failure(mctx, m,
                                        "MHTML root HTML input could not be materialized completely");
    } else { /* t != NULL */
        input_fb = fileblobCreate();
        if (input_fb != NULL) {
            fileblobSetFilename(input_fb, mctx->dir, "mhtml-root");
            if (input_fb->isIncomplete || input_fb->fp == NULL)
                fileblobDestructiveDestroy(input_fb);
            else {
                input_fb = textToFileblob(t, input_fb, 0);
                fileblobSetCTX(input_fb, ctx);
            }
        }
    }

    if (input_fb != NULL && !input_fb->isIncomplete && input_fb->fp != NULL &&
        input_fb->fullname != NULL && fflush(input_fb->fp) == 0)
        input_path = input_fb->fullname;

    if (input_path == NULL) {
        cli_mark_scan_incomplete(ctx, "MHTML root HTML input could not be materialized completely");
        if (!borrowed_input && input_fb)
            fileblobDestructiveDestroy(input_fb);
        return FAIL;
    }

    htmlDoc = htmlReadFile(input_path, NULL, CLAMAV_MIN_XMLREADER_FLAGS | HTML_PARSE_NOWARNING);
    if (htmlDoc == NULL) {
        cli_dbgmsg("parseRootMHTML: cannot initialize read html document\n");

        cli_mark_scan_incomplete(ctx, "MHTML root HTML document could not be parsed completely");

        if (ctx->this_layer_metadata_json != NULL &&
            cli_json_parse_error(ctx->this_layer_metadata_json, "MHTML_ERROR_HTML_READ") != CL_SUCCESS)
            cli_mark_scan_incomplete(ctx, "MHTML HTML-read error metadata could not be recorded");

        if (!borrowed_input)
            fileblobDestructiveDestroy(input_fb);
        return FAIL;
    }

    if (mctx->wrkobj) {
        rhtml = cli_jsonobj(mctx->wrkobj, "RootHTML");
        if (rhtml == NULL) {
            mbox_record_json_failure(mctx, &metadata_rc,
                                     "MHTML root HTML metadata object could not be allocated");
        } else {
            const char *encoding = (const char *)htmlGetMetaEncoding(htmlDoc);

            /* MHTML-specific properties */
            if (encoding != NULL) {
                mbox_record_json_status(mctx, &metadata_rc,
                                        cli_jsonstr(rhtml, "Encoding", encoding),
                                        "MHTML root HTML encoding metadata could not be recorded");
            } else {
                mbox_record_json_status(mctx, &metadata_rc,
                                        cli_jsonnull(rhtml, "Encoding"),
                                        "MHTML root HTML encoding metadata could not be recorded");
            }
            mbox_record_json_status(mctx, &metadata_rc,
                                    cli_jsonint(rhtml, "CompressMode", xmlGetDocCompressMode(htmlDoc)),
                                    "MHTML root HTML compression metadata could not be recorded");
        }
    }

    reader = xmlReaderWalker(htmlDoc);
    if (reader == NULL) {
        cli_dbgmsg("parseRootMHTML: cannot initialize xmlTextReader\n");

        cli_mark_scan_incomplete(ctx, "MHTML root HTML XML reader could not be initialized");

        if (ctx->this_layer_metadata_json != NULL &&
            cli_json_parse_error(ctx->this_layer_metadata_json, "MHTML_ERROR_XML_READER_IO") != CL_SUCCESS)
            cli_mark_scan_incomplete(ctx, "MHTML XML-reader error metadata could not be recorded");

        if (!borrowed_input)
            fileblobDestructiveDestroy(input_fb);
        return FAIL;
    }

    memset(&mxctx, 0, sizeof(mxctx));
    /* no scanning callback set */
    mxctx.comment_cb = parseMHTMLComment;
    ret              = cli_msxml_parse_document(ctx, reader, mhtml_keys, num_mhtml_keys,
                                                MSXML_FLAG_JSON | MSXML_FLAG_WALK | MSXML_FLAG_FAIL_INCOMPLETE,
                                                &mxctx);
    switch (ret) {
        case CL_SUCCESS:
            rc = OK;
            break;

        case CL_EMAXREC:
            rc = MAXREC;
            break;

        case CL_EMAXFILES:
            rc = MAXFILES;
            break;

        case CL_VIRUS:
            rc = VIRUS;
            break;

        default:
            cli_mark_scan_incomplete(ctx, "MHTML root HTML parser did not complete");
            rc = FAIL;
    }

    if ((rc == OK || rc == OK_ATTACHMENTS_NOT_SAVED) && metadata_rc != OK)
        rc = metadata_rc;

    xmlTextReaderClose(reader);
    xmlFreeTextReader(reader);
    xmlFreeDoc(htmlDoc);
    if (!borrowed_input)
        fileblobDestructiveDestroy(input_fb);
    return rc;
#else  /* LIBXML_HTML_ENABLED */
    UNUSEDPARAM(m);
    UNUSEDPARAM(t);
    cli_dbgmsg("in parseRootMHTML\n");
    cli_dbgmsg("parseRootMHTML: parsing html documents disabled in libxml2!\n");
    cli_mark_scan_incomplete(mctx->ctx, "MHTML root HTML parsing is unavailable in this build");
    return FAIL;
#endif /* LIBXML_HTML_ENABLED */
}

static mbox_status finishStreamedMultipartPart(message **partp, mbox_ctx *mctx,
                                               unsigned int recursion_level)
{
    message *part;
    mbox_status rc;

    if (partp == NULL || *partp == NULL)
        return OK;

    part   = *partp;
    *partp = NULL;
    rc     = parseEmailBody(part, NULL, mctx, recursion_level + 1);
    messageDestroy(part);
    return rc;
}

typedef struct streamed_mime_part {
    message *part;
    struct streamed_mime_part *next;
} streamed_mime_part;

static int queueStreamedMimePart(streamed_mime_part **head,
                                 streamed_mime_part **tail, message **partp,
                                 cli_ctx *ctx)
{
    streamed_mime_part *entry;

    if (partp == NULL || *partp == NULL)
        return 0;

    entry = (streamed_mime_part *)calloc(1, sizeof(*entry));
    if (entry == NULL) {
        cli_mark_scan_incomplete(ctx,
                                 "Multipart related part list could not be allocated");
        return -1;
    }

    entry->part = *partp;
    *partp     = NULL;
    if (*tail)
        (*tail)->next = entry;
    else
        *head = entry;
    *tail = entry;
    return 0;
}

static void destroyStreamedMimeParts(streamed_mime_part *parts)
{
    while (parts != NULL) {
        streamed_mime_part *next = parts->next;

        if (parts->part)
            messageDestroy(parts->part);
        free(parts);
        parts = next;
    }
}

static mbox_status
scanStreamedRelatedParts(streamed_mime_part *parts, mbox_ctx *mctx,
                         unsigned int recursion_level)
{
    streamed_mime_part *entry;
    message *root = NULL;
    mbox_status result = OK;

    /* Match getTextPart(): prefer the first HTML part, otherwise retain the
     * last text part as the root candidate. The parts remain disk-backed
     * until this selection is complete. */
    for (entry = parts; entry != NULL; entry = entry->next) {
        const mime_type type = entry->part ? messageGetMimeType(entry->part) : NOMIME;
        const char *subtype = entry->part ? messageGetMimeSubtype(entry->part) : NULL;

        if (mbox_check_deadline(mctx->ctx)) {
            result = FAIL;
            break;
        }

        if (type == TEXT) {
            if (subtype && strcasecmp(subtype, "html") == 0) {
                root = entry->part;
                break;
            }
            root = entry->part;
        }
    }

    if (root != NULL && mctx->ctx->this_layer_metadata_json != NULL) {
        const mbox_status root_rc = parseRootMHTML(mctx, root, NULL);

        if (root_rc == VIRUS)
            result = VIRUS;
        else if (root_rc != OK)
            result = root_rc;
    }

    for (entry = parts; entry != NULL; entry = entry->next) {
        mbox_status part_rc;

        if (mbox_check_deadline(mctx->ctx)) {
            result = FAIL;
            break;
        }

        if (entry->part == NULL)
            continue;
        part_rc = finishStreamedMultipartPart(&entry->part, mctx, recursion_level);
        if (part_rc == VIRUS) {
            result = VIRUS;
            break;
        }
        if ((part_rc == MAXREC) || (part_rc == MAXFILES)) {
            result = part_rc;
            break;
        }
        if (part_rc != OK && result == OK)
            result = part_rc;
    }

    return result;
}

/*
 * Consume a disk-backed multipart body one MIME part at a time. The parent
 * spool remains on disk while the current child owns its own bounded spool;
 * this keeps the working set independent of the total message size and lets
 * nested multipart messages recurse through the same state machine.
 */
static mbox_status parseMultipartBodySpool(message *mainMessage, mbox_ctx *mctx,
                                           unsigned int recursion_level)
{
    char *boundary = NULL;
    FILE *input    = NULL;
    fileblob *source;
    message *headers   = NULL;
    message *part      = NULL;
    streamed_mime_part *parts_head = NULL;
    streamed_mime_part *parts_tail = NULL;
    mbox_status result = OK;
    bool saw_boundary  = false;
    bool closed        = false;
    size_t mime_part_count = 0;
    const char *main_subtype;
    bool is_related;
    char line[4096];

    if (mainMessage == NULL || mctx == NULL || mainMessage->body_spool == NULL)
        return FAIL;

    if (mbox_check_deadline(mctx->ctx))
        return FAIL;

    main_subtype = messageGetMimeSubtype(mainMessage);
    is_related  = main_subtype && strcasecmp(main_subtype, "related") == 0;

    if ((messageGetEncoding(mainMessage) != NOENCODING) &&
        (messageGetEncoding(mainMessage) != BINARY) &&
        (messageGetEncoding(mainMessage) != EIGHTBIT)) {
        cli_mark_scan_incomplete(mctx->ctx,
                                 "Multipart body uses an unsupported transfer encoding");
        return FAIL;
    }

    boundary = messageFindArgument(mainMessage, "boundary");
    if (boundary == NULL || *boundary == '\0') {
        cli_mark_scan_incomplete(mctx->ctx,
                                 "Multipart body has no usable boundary");
        if (boundary)
            free(boundary);
        return FAIL;
    }
    cli_chomp(boundary);

    source = mainMessage->body_spool;
    if (source->isIncomplete || source->fp == NULL || source->fullname == NULL ||
        fflush(source->fp) != 0 || (input = fopen(source->fullname, "rb")) == NULL) {
        cli_mark_scan_incomplete(mctx->ctx,
                                 "Multipart body spool could not be opened completely");
        goto done;
    }

    while (fgets(line, sizeof(line), input) != NULL) {
        size_t line_len = strlen(line);

        if (mbox_check_deadline(mctx->ctx)) {
            result = FAIL;
            break;
        }

        if (line_len == sizeof(line) - 1 && line[line_len - 1] != '\n' && !feof(input)) {
            cli_mark_scan_incomplete(mctx->ctx,
                                     "Multipart boundary line exceeded the streaming buffer");
            result = FAIL;
            break;
        }
        cli_chomp(line);

        if (boundaryEnd(line, boundary)) {
            mbox_status part_rc;

            if (headers != NULL) {
                cli_mark_scan_incomplete(mctx->ctx,
                                         "Multipart part ended before its headers terminated");
                messageDestroy(headers);
                headers = NULL;
                result  = FAIL;
            }
            if (is_related) {
                if (queueStreamedMimePart(&parts_head, &parts_tail, &part, mctx->ctx) < 0) {
                    result = FAIL;
                    break;
                }
                part_rc = OK;
            } else {
                part_rc = finishStreamedMultipartPart(&part, mctx, recursion_level);
            }
            if (part_rc == VIRUS) {
                result = VIRUS;
                break;
            }
            if ((part_rc == MAXREC) || (part_rc == MAXFILES)) {
                result = part_rc;
                break;
            }
            if (part_rc != OK && result == OK)
                result = part_rc;
            closed = true;
            break;
        }

        if (boundaryStart(line, boundary)) {
            mbox_status part_rc;

            /* Keep the streaming multipart path subject to the same
             * per-message part bound as the legacy line-list path. Without
             * this check a related message could queue an arbitrary number
             * of disk-backed child spools before MaxFiles or the shared
             * temporary quota had a chance to stop it. */
            if (mime_part_count == SIZE_MAX) {
                cli_mark_scan_incomplete(mctx->ctx,
                                         "MIME multipart part count exceeded its native representation");
                result = FAIL;
                break;
            }
            mime_part_count++;
            if (haveTooManyMIMEPartsPerMessage(mime_part_count, mctx->ctx, &result))
                break;

            if (is_related) {
                if (queueStreamedMimePart(&parts_head, &parts_tail, &part, mctx->ctx) < 0) {
                    result = FAIL;
                    break;
                }
                part_rc = OK;
            } else {
                part_rc = finishStreamedMultipartPart(&part, mctx, recursion_level);
            }
            if (part_rc == VIRUS) {
                result = VIRUS;
                break;
            }
            if ((part_rc == MAXREC) || (part_rc == MAXFILES)) {
                result = part_rc;
                break;
            }
            if (part_rc != OK && result == OK)
                result = part_rc;
            if (headers != NULL) {
                cli_mark_scan_incomplete(mctx->ctx,
                                         "Multipart boundary interrupted part headers");
                messageDestroy(headers);
                headers = NULL;
                if (result == OK)
                    result = FAIL;
            }
            headers = messageCreate();
            if (headers == NULL) {
                cli_mark_scan_incomplete(mctx->ctx,
                                         "Multipart part headers could not be allocated");
                result = FAIL;
                break;
            }
            messageSetCTX(headers, mctx->ctx);
            saw_boundary = true;
            continue;
        }

        if (!saw_boundary)
            continue; /* MIME preamble. */

        if (headers != NULL) {
            if (messageAddStr(headers, (line[0] == '\0') ? NULL : line) < 0) {
                cli_mark_scan_incomplete(mctx->ctx,
                                         "Multipart part headers could not be materialized");
                result = FAIL;
                break;
            }
            if (line[0] == '\0') {
                bool heuristicFound = false;
                message *parsed     = parseEmailHeaders(headers, mctx->rfc821Table,
                                                        &heuristicFound);
                messageDestroy(headers);
                headers = NULL;
                if (parsed == NULL) {
                    if (heuristicFound)
                        result = VIRUS;
                    else {
                        cli_mark_scan_incomplete(mctx->ctx,
                                                 "Multipart part headers could not be parsed");
                        result = FAIL;
                    }
                    break;
                }
                messageSetCTX(parsed, mctx->ctx);
                if (!messageNeedsMaterializedBody(parsed) && messageBeginBodySpool(parsed) < 0) {
                    messageDestroy(parsed);
                    result = FAIL;
                    break;
                }
                part = parsed;
            }
        } else if (part == NULL || messageAddStr(part, (line[0] == '\0') ? NULL : line) < 0) {
            cli_mark_scan_incomplete(mctx->ctx,
                                     "Multipart part body could not be spooled");
            result = FAIL;
            break;
        }
    }

    if (input != NULL && ferror(input)) {
        cli_mark_scan_incomplete(mctx->ctx,
                                 "Multipart body spool read failed");
        if (result == OK)
            result = FAIL;
    }

    if (!closed) {
        cli_mark_scan_incomplete(mctx->ctx,
                                 "Multipart body did not contain a terminating boundary");
        if (result == OK)
            result = FAIL;
    }

    if (headers != NULL) {
        cli_mark_scan_incomplete(mctx->ctx,
                                 "Multipart part ended before its headers terminated");
        messageDestroy(headers);
        headers = NULL;
        if (result == OK)
            result = FAIL;
    }

    if (is_related) {
        if (queueStreamedMimePart(&parts_head, &parts_tail, &part, mctx->ctx) < 0)
            result = FAIL;
        {
            const mbox_status parts_rc = scanStreamedRelatedParts(parts_head, mctx,
                                                                   recursion_level);
            if (parts_rc == VIRUS || parts_rc == MAXREC || parts_rc == MAXFILES)
                result = parts_rc;
            else if (parts_rc != OK && result == OK)
                result = parts_rc;
        }
    } else if (part != NULL) {
        mbox_status part_rc = finishStreamedMultipartPart(&part, mctx, recursion_level);
        if (part_rc == VIRUS)
            result = VIRUS;
        else if ((part_rc == MAXREC) || (part_rc == MAXFILES))
            result = part_rc;
        else if (part_rc != OK && result == OK)
            result = part_rc;
    }

    if (!saw_boundary) {
        cli_mark_scan_incomplete(mctx->ctx,
                                 "Multipart body contained no boundary-delimited part");
        if (result == OK)
            result = FAIL;
    }

done:
    if (input) {
        if (fclose(input) != 0) {
            cli_mark_scan_incomplete(mctx->ctx,
                                     "Multipart body spool could not be closed completely");
            if (result == OK)
                result = FAIL;
        }
        input = NULL;
    }
    if (headers)
        messageDestroy(headers);
    if (part)
        messageDestroy(part);
    destroyStreamedMimeParts(parts_head);
    if (boundary)
        free(boundary);
    return result;
}

/*
 * This is a recursive routine.
 *
 * This function parses the body of mainMessage and saves its attachments in dir
 *
 * mainMessage is the buffer to be parsed, it contains an e-mail's body, without
 * any headers. First time of calling it'll be
 * the whole message. Later it'll be parts of a multipart message
 * textIn is the plain text message being built up so far
 */
static mbox_status
parseEmailBody(message *messageIn, text *textIn, mbox_ctx *mctx, unsigned int recursion_level)
{
    mbox_status rc;
    text *aText          = textIn;
    message *mainMessage = messageIn;
    fileblob *fb;
    bool infected                  = false;
    const struct cl_engine *engine = mctx->ctx->engine;
    const int doPhishingScan       = engine->dboptions & CL_DB_PHISHING_URLS && (DCONF_PHISHING & PHISHING_CONF_ENGINE);
    json_object *saveobj           = mctx->wrkobj;
    bool heuristicFound            = false;

    if (messageIn && messageIn->isTruncated) {
        cli_mark_scan_incomplete(mctx->ctx,
                                 "Mail parser input was materialized incompletely");
        return FAIL;
    }

    if (mbox_check_deadline(mctx->ctx))
        return FAIL;

    cli_dbgmsg("in parseEmailBody, %u files saved so far\n",
               mctx->files);

    /* FIXMELIMITS: this should be better integrated */
    if (engine->max_recursion_level)
        /*
         * This is approximate
         */
        if (recursion_level > engine->max_recursion_level) {
            // Note: engine->max_recursion_level is re-purposed here out of convenience.
            //       ole2 recursion does not leverage the ctx->recursion_stack stack.
            cli_dbgmsg("parseEmailBody: hit maximum recursion level (%u)\n", recursion_level);
            cli_mark_scan_incomplete(mctx->ctx,
                                     "MIME parser exceeded MaxRecursion before the child was inspected");
            return MAXREC;
        }
    if (engine->maxfiles && (mctx->files >= engine->maxfiles)) {
        /*
         * FIXME: This is only approx - it may have already
         * been exceeded
         */
        cli_dbgmsg("parseEmailBody: number of files exceeded %u\n", engine->maxfiles);
        cli_mark_scan_incomplete(mctx->ctx,
                                 "MIME parser exceeded MaxFiles before the child was inspected");
        return MAXFILES;
    }

    rc = OK;

    /* Bodies are collected by messageAddStr() directly into a quota-accounted
     * fileblob. Multipart parts are split from that spool one child at a time;
     * ordinary and encapsulated bodies are scanned from their completed spool. */
    if (mainMessage && messageHasBodySpool(mainMessage)) {
        const mime_type streamed_type = messageGetMimeType(mainMessage);
        const char *streamed_subtype  = messageGetMimeSubtype(mainMessage);

        if (streamed_type == MULTIPART) {
            rc = parseMultipartBodySpool(mainMessage, mctx, recursion_level);
        } else if (streamed_type == MESSAGE &&
                   streamed_subtype && strcasecmp(streamed_subtype, "partial") == 0) {
            if (mctx->ctx->options->mail & CL_SCAN_MAIL_PARTIAL_MESSAGE) {
                const int partial_rc = rfc1341(mctx, mainMessage);

                if (partial_rc == CL_VIRUS)
                    rc = VIRUS;
                else if (partial_rc == CL_SUCCESS || partial_rc == CL_CLEAN)
                    rc = OK;
                else {
                    cli_mark_scan_incomplete(mctx->ctx,
                                             "Partial MIME message could not be saved completely");
                    rc = FAIL;
                }
            } else {
                cli_warnmsg("Partial message received from MUA/MTA - message cannot be scanned\n");
                cli_mark_scan_incomplete(mctx->ctx,
                                         "Partial MIME message support is disabled");
                rc = FAIL;
            }
        } else if (streamed_type == MESSAGE &&
                   (!streamed_subtype ||
                    (strcasecmp(streamed_subtype, "rfc822") != 0 &&
                     strcasecmp(streamed_subtype, "delivery-status") != 0 &&
                     strcasecmp(streamed_subtype, "disposition-notification") != 0))) {
            if (streamed_subtype && strcasecmp(streamed_subtype, "external-body") == 0)
                cli_warnmsg("Attempt to send Content-type message/external-body trapped\n");
            else
                cli_warnmsg("Unsupported message format `%s' - if you believe this is an error, submit it to www.clamav.net\n",
                            streamed_subtype ? streamed_subtype : "(missing subtype)");
            cli_mark_scan_incomplete(mctx->ctx,
                                     streamed_subtype && strcasecmp(streamed_subtype, "external-body") == 0
                                         ? "External-body MIME content cannot be inspected locally"
                                         : "Unsupported MIME message format could not be inspected");
            rc = FAIL;
        } else {
            if (doPhishingScan && (streamed_type == NOMIME || streamed_type == TEXT))
                checkURLs(mainMessage, mctx, &rc, streamed_type == TEXT);

            fb = messageToFileblob(mainMessage, mctx->dir, 1);
            if (fb == NULL) {
                mbox_record_message_failure(mctx, mainMessage,
                                            "MIME body could not be exported completely from its spool");
                rc = FAIL;
            } else if (streamed_type == MESSAGE && !fb->isNotEmpty) {
                cli_mark_scan_incomplete(mctx->ctx,
                                         "Encapsulated MIME message has no body to inspect");
                fileblobDestroy(fb);
                rc = FAIL;
            } else {
                const int scan_rc = scanFileblob(mctx, fb);
                if (scan_rc == CL_VIRUS)
                    rc = VIRUS;
                else if (scan_rc != CL_CLEAN && rc == OK)
                    rc = FAIL;
                mctx->files++;
            }
        }

        mctx->wrkobj = saveobj;
        return rc;
    }

    /* Anything left to be parsed? */
    if (mainMessage && (messageGetBody(mainMessage) != NULL)) {
        mime_type mimeType;
        int subtype, inhead, htmltextPart, inMimeHead, i;
        const char *mimeSubtype;
        char *boundary;
        const text *t_line;
        /*bool isAlternative;*/
        message *aMessage;
        int multiparts     = 0;
        message **messages = NULL; /* parts of a multipart message */

        cli_dbgmsg("Parsing mail file\n");

        mimeType    = messageGetMimeType(mainMessage);
        mimeSubtype = messageGetMimeSubtype(mainMessage);

        if (mctx->wrkobj != NULL) {
            json_object *bodyobj = cli_jsonobj(mctx->wrkobj, "Body");

            if (bodyobj == NULL) {
                mbox_record_json_failure(mctx, &rc,
                                         "MIME body metadata object could not be allocated");
                mctx->wrkobj = NULL;
            } else {
                mctx->wrkobj = bodyobj;
                mbox_record_json_status(mctx, &rc,
                                        cli_jsonstr(mctx->wrkobj, "MimeType", getMimeTypeStr(mimeType)),
                                        "MIME body type metadata could not be recorded");
                mbox_record_json_status(mctx, &rc,
                                        cli_jsonstr(mctx->wrkobj, "MimeSubtype", mimeSubtype),
                                        "MIME body subtype metadata could not be recorded");
                mbox_record_json_status(mctx, &rc,
                                        cli_jsonstr(mctx->wrkobj, "EncodingType", getEncTypeStr(messageGetEncoding(mainMessage))),
                                        "MIME body encoding metadata could not be recorded");
                mbox_record_json_status(mctx, &rc,
                                        cli_jsonstr(mctx->wrkobj, "Disposition", messageGetDispositionType(mainMessage)),
                                        "MIME body disposition metadata could not be recorded");
                if (messageHasFilename(mainMessage)) {
                    char *filename = messageGetFilename(mainMessage);
                    mbox_record_json_status(mctx, &rc,
                                            cli_jsonstr(mctx->wrkobj, "Filename", filename),
                                            "MIME body filename metadata could not be recorded");
                    free(filename);
                } else {
                    mbox_record_json_status(mctx, &rc,
                                            cli_jsonstr(mctx->wrkobj, "Filename", "(inline)"),
                                            "MIME body filename metadata could not be recorded");
                }
            }
        }

        /* pre-process */
        subtype = tableFind(mctx->subtypeTable, mimeSubtype);
        if ((mimeType == TEXT) && (subtype == PLAIN)) {
            /*
             * This is effectively no encoding, notice that we
             * don't check that charset is us-ascii
             */
            cli_dbgmsg("text/plain: Assume no attachments\n");
            mimeType = NOMIME;
            messageSetMimeSubtype(mainMessage, "");
        } else if ((mimeType == MESSAGE) &&
                   (strcasecmp(mimeSubtype, "rfc822-headers") == 0)) {
            /*
             * RFC1892/RFC3462: section 2 text/rfc822-headers
             * incorrectly sent as message/rfc822-headers
             *
             * Parse as text/plain, i.e. no mime
             */
            cli_dbgmsg("Changing message/rfc822-headers to text/rfc822-headers\n");
            mimeType = NOMIME;
            messageSetMimeSubtype(mainMessage, "");
        } else
            cli_dbgmsg("mimeType = %d\n", (int)mimeType);

        switch (mimeType) {
            case NOMIME:
                cli_dbgmsg("Not a mime encoded message\n");
                aText = textAddMessage(aText, mainMessage);

                if (!doPhishingScan) {
                    break;
                }
                /*
                 * Fall through: some phishing mails claim they are
                 * text/plain, when they are in fact html
                 */
                /* fall through */
            case TEXT:
                /* text/plain has been preprocessed as no encoding */
                if (doPhishingScan) {
                    /*
                     * It would be better to save and scan the
                     * file and only checkURLs if it's found to be
                     * clean
                     */
                    checkURLs(mainMessage, mctx, &rc, (subtype == HTML));
                    /*
                     * There might be html sent without subtype
                     * html too, so scan them for phishing
                     */
                    if (rc == VIRUS)
                        infected = true;
                }
                break;
            case MULTIPART:
                cli_dbgmsg("Content-type 'multipart' handler\n");
                boundary = messageFindArgument(mainMessage, "boundary");

                if (mctx->wrkobj != NULL)
                    mbox_record_json_status(mctx, &rc,
                                            cli_jsonstr(mctx->wrkobj, "Boundary", boundary),
                                            "MIME multipart boundary metadata could not be recorded");

                if (boundary == NULL) {
                    cli_dbgmsg("Multipart/%s MIME message contains no boundary header\n",
                               mimeSubtype);
                    /* Broken e-mail message */
                    mimeType = NOMIME;
                    /*
                     * The break means that we will still
                     * check if the file contains a uuencoded file
                     */
                    break;
                }

                cli_chomp(boundary);

                /* Perhaps it should assume mixed? */
                if (mimeSubtype[0] == '\0') {
                    cli_dbgmsg("Multipart has no subtype assuming alternative\n");
                    mimeSubtype = "alternative";
                    messageSetMimeSubtype(mainMessage, "alternative");
                }

                /*
                 * Get to the start of the first message
                 */
                t_line = messageGetBody(mainMessage);

                if (t_line == NULL) {
                    cli_dbgmsg("Multipart MIME message has no body\n");
                    free((char *)boundary);
                    mimeType = NOMIME;
                    break;
                }

                do
                    if (t_line->t_line) {
                        if (boundaryStart(lineGetData(t_line->t_line), boundary))
                            break;
                        /*
                         * Found a binhex file before
                         *    the first multipart
                         * TODO: check yEnc
                         */
                        if (binhexBegin(mainMessage) == t_line) {
                            const mbox_status binhex_rc = exportBinhexMessage(mctx, mainMessage);

                            if (binhex_rc == VIRUS) {
                                rc       = VIRUS;
                                infected = true;
                                break;
                            } else if (binhex_rc != OK && rc == OK) {
                                rc = FAIL;
                            }
                        } else if (t_line->t_next &&
                                   (encodingLine(mainMessage) == t_line->t_next)) {
                            /*
                             * We look for the next line
                             * since later on we'll skip
                             * over the important line when
                             * we think it's a blank line
                             * at the top of the message -
                             * which it would have been in
                             * an RFC compliant world
                             */
                            cli_dbgmsg("Found MIME attachment before the first MIME section \"%s\"\n",
                                       lineGetData(t_line->t_next->t_line));
                            if (messageGetEncoding(mainMessage) == NOENCODING)
                                break;
                        }
                    }
                while ((t_line = t_line->t_next) != NULL);

                if (t_line == NULL) {
                    cli_dbgmsg("Multipart MIME message contains no boundary lines (%s)\n",
                               boundary);
                    free((char *)boundary);
                    mimeType = NOMIME;
                    /*
                     * The break means that we will still
                     * check if the file contains a yEnc/binhex file
                     */
                    break;
                }
                /*
                 * Build up a table of all of the parts of this
                 * multipart message. Remember, each part may itself
                 * be a multipart message.
                 */
                inhead     = 1;
                inMimeHead = 0;

                /*
                 * Re-read this variable in case mimeSubtype has changed
                 */
                subtype = tableFind(mctx->subtypeTable, mimeSubtype);

                /*
                 * Parse the mainMessage object and create an array
                 * of objects called messages, one for each of the
                 * multiparts that mainMessage contains.
                 *
                 * This looks like parseEmailHeaders() - maybe there's
                 * some duplication of code to be cleaned up
                 *
                 * We may need to create an array rather than just
                 * save each part as it is found because not all
                 * elements will need scanning, and we don't yet know
                 * which of those elements it will be, except in
                 * the case of mixed, when all parts need to be scanned.
                 */
                for (multiparts = 0; t_line && !infected; multiparts++) {
                    int lines = 0;
                    message **m;
                    mbox_status old_rc;
                    size_t message_table_size;

                    if (multiparts < 0 || multiparts == INT_MAX ||
                        cli_message_table_size((size_t)multiparts + 1,
                                               sizeof(*messages), &message_table_size) != CL_SUCCESS) {
                        cli_mark_scan_incomplete(mctx->ctx,
                                                 "MIME multipart table exceeded its bounded representation");
                        rc = FAIL;
                        break;
                    }

                    m = cli_max_realloc(messages, message_table_size);
                    if (m == NULL) {
                        cli_mark_scan_incomplete(mctx->ctx,
                                                 "MIME multipart table could not be allocated");
                        rc = FAIL;
                        break;
                    }
                    messages = m;

                    aMessage = messages[multiparts] = messageCreate();
                    if (aMessage == NULL) {
                        cli_mark_scan_incomplete(mctx->ctx,
                                                 "MIME multipart message could not be allocated");
                        rc = FAIL;
                        break;
                    }
                    messageSetCTX(aMessage, mctx->ctx);

                    cli_dbgmsg("Now read in part %d\n", multiparts);

                    /*
                     * Ignore blank lines. There shouldn't be ANY
                     * but some viruses insert them
                     */
                    while ((t_line = t_line->t_next) != NULL)
                        if (t_line->t_line &&
                            /*(cli_chomp(t_line->t_text) > 0))*/
                            (strlen(lineGetData(t_line->t_line)) > 0))
                            break;

                    if (t_line == NULL) {
                        cli_dbgmsg("Empty part\n");
                        /*
                         * Remove this part unless there's
                         * a binhex portion somewhere in
                         * the complete message that we may
                         * throw away by mistake if the MIME
                         * encoding information is incorrect
                         */
                        if (mainMessage &&
                            (binhexBegin(mainMessage) == NULL)) {
                            messageDestroy(aMessage);
                            --multiparts;
                        }
                        continue;
                    }

                    do {
                        const char *line = lineGetData(t_line->t_line);

                        /*
                        cli_dbgmsg("multipart %d: inMimeHead %d inhead %d boundary '%s' line '%s' next '%s'\n",
                        multiparts, inMimeHead, inhead, boundary, line,
                        t_line->t_next && t_line->t_next->t_line ? lineGetData(t_line->t_next->t_line) : "(null)");
                        */

                        if (inMimeHead) { /* continuation line */
                            if (line == NULL) {
                                /*inhead =*/inMimeHead = 0;
                                continue;
                            }
                            /*
                             * Handle continuation lines
                             * because the previous line
                             * ended with a ; or this line
                             * starts with a white space
                             */
                            cli_dbgmsg("Multipart %d: About to add mime Argument '%s'\n",
                                       multiparts, line);
                            /*
                             * Handle the case when it
                             * isn't really a continuation
                             * line:
                             * Content-Type: application/octet-stream;
                             * Content-Transfer-Encoding: base64
                             */
                            parseEmailHeader(aMessage, line, mctx->rfc821Table, mctx->ctx, &heuristicFound);
                            if (heuristicFound) {
                                rc = VIRUS;
                                break;
                            }

                            while (isspace((int)*line))
                                line++;

                            if (*line == '\0') {
                                inhead = inMimeHead = 0;
                                continue;
                            }
                            inMimeHead = false;
                            messageAddArgument(aMessage, line);
                        } else if (inhead) { /* handling normal headers */
                            /*int quotes;*/
                            char *fullline, *ptr;

                            if (line == NULL) {
                                /*
                                 * empty line, should the end of the headers,
                                 * but some base64 decoders, e.g. uudeview, are broken
                                 * and will handle this type of entry, decoding the
                                 * base64 content...
                                 * Content-Type: application/octet-stream; name=text.zip
                                 * Content-Transfer-Encoding: base64
                                 * Content-Disposition: attachment; filename="text.zip"
                                 *
                                 * Content-Disposition: attachment;
                                 *    filename=text.zip
                                 * Content-Type: application/octet-stream;
                                 *    name=text.zip
                                 * Content-Transfer-Encoding: base64
                                 *
                                 * UEsDBAoAAAAAAACgPjJ2RHw676gAAO+oAABEAAAAbWFpbF90ZXh0LWluZm8udHh0ICAgICAgICAg
                                 */
                                const text *next = t_line->t_next;

                                if (next && next->t_line) {
                                    const char *data = lineGetData(next->t_line);

                                    if ((messageGetEncoding(aMessage) == NOENCODING) &&
                                        (messageGetMimeType(aMessage) == APPLICATION) &&
                                        data && strstr(data, "base64")) {
                                        /*
                                         * Handle this nightmare (note the blank
                                         * line in the header and the incorrect
                                         * content-transfer-encoding header)
                                         *
                                         * Content-Type: application/octet-stream; name="zipped_files.EXEX-Spanska: Yes
                                         *
                                         * r-Encoding: base64
                                         * Content-Disposition: attachment; filename="zipped_files.EXE"
                                         */
                                        messageSetEncoding(aMessage, "base64");
                                        cli_dbgmsg("Ignoring fake end of headers\n");
                                        continue;
                                    }
                                    if ((strncmp(data, "Content", 7) == 0) ||
                                        (strncmp(data, "filename=", 9) == 0)) {
                                        cli_dbgmsg("Ignoring fake end of headers\n");
                                        continue;
                                    }
                                }
                                cli_dbgmsg("Multipart %d: End of header information\n",
                                           multiparts);
                                inhead = 0;
                                continue;
                            }
                            if (isspace((int)*line)) {
                                /*
                                 * The first line is
                                 * continuation line.
                                 * This is tricky
                                 * to handle, but
                                 * all we can do is our
                                 * best
                                 */
                                cli_dbgmsg("Part %d starts with a continuation line\n",
                                           multiparts);
                                messageAddArgument(aMessage, line);
                                /*
                                 * Give it a default
                                 * MIME type since
                                 * that may be the
                                 * missing line
                                 *
                                 * Choose application to
                                 * force a save
                                 */
                                if (messageGetMimeType(aMessage) == NOMIME)
                                    messageSetMimeType(aMessage, "application");
                                continue;
                            }

                            inMimeHead = false;

                            if (strlen(line) > RFC2821LENGTH) {
                                cli_dbgmsg("parseEmailBody: line length exceeds RFC2821 maximum length (1000)\n");
                                cli_mark_scan_incomplete(mctx->ctx,
                                                         "MIME message line exceeds bounded parser representation");
                                rc = FAIL;
                                break;
                            }

                            fullline = rfc822comments(line, NULL);
                            if (fullline == NULL)
                                fullline = cli_safer_strdup(line);
                            if (fullline == NULL) {
                                cli_mark_scan_incomplete(mctx->ctx,
                                                         "MIME header line could not be allocated");
                                rc = FAIL;
                                break;
                            }

                            /*quotes = count_quotes(fullline);*/

                            /*
                             * Fold next lines to the end of this
                             * if they start with a white space
                             * or if this line has an odd number of quotes:
                             * Content-Type: application/octet-stream; name="foo
                             * "
                             */
                            while (t_line && next_is_folded_header(t_line)) {
                                const char *data;
                                size_t datasz;

                                t_line = t_line->t_next;

                                data = lineGetData(t_line->t_line);

                                if (data == NULL) {
                                    cli_mark_scan_incomplete(
                                        mctx->ctx,
                                        "MIME folded header line could not be read");
                                    free(fullline);
                                    fullline = NULL;
                                    rc       = FAIL;
                                    break;
                                }

                                if (data[0] == '\0' || data[1] == '\0') {
                                    /*
                                     * Broken message: the
                                     * blank line at the end
                                     * of the headers isn't blank -
                                     * it contains a space
                                     */
                                    cli_dbgmsg("Multipart %d: headers not terminated by blank line\n",
                                               multiparts);
                                    inhead = false;
                                    break;
                                }

                                {
                                    const size_t full_len = strlen(fullline);
                                    const size_t data_len = data ? strlen(data) : 0;

                                    if (data == NULL || data_len == SIZE_MAX ||
                                        full_len > SIZE_MAX - data_len - 1U) {
                                        cli_mark_scan_incomplete(
                                            mctx->ctx,
                                            "MIME folded header size exceeded native representation");
                                        free(fullline);
                                        fullline = NULL;
                                        rc       = FAIL;
                                        break;
                                    }
                                    datasz = full_len + data_len + 1U;
                                }
                                {
                                    bool fold_heuristic = false;

                                    if (haveTooManyHeaderBytes(datasz, mctx->ctx,
                                                               &fold_heuristic)) {
                                        if (fold_heuristic) {
                                            heuristicFound = true;
                                            rc             = VIRUS;
                                        } else {
                                            rc = FAIL;
                                        }
                                        free(fullline);
                                        fullline = NULL;
                                        break;
                                    }
                                }
                                ptr    = cli_max_realloc(fullline, datasz);

                                if (ptr == NULL) {
                                    cli_mark_scan_incomplete(mctx->ctx,
                                                             "MIME folded header could not be allocated");
                                    free(fullline);
                                    fullline = NULL;
                                    rc = FAIL;
                                    break;
                                }

                                fullline = ptr;
                                cli_strlcat(fullline, data, datasz);

                                /*quotes = count_quotes(data);*/
                            }

                            if (fullline == NULL)
                                break;

                            cli_dbgmsg("Multipart %d: About to parse folded header '%s'\n",
                                       multiparts, fullline);

                            parseEmailHeader(aMessage, fullline, mctx->rfc821Table, mctx->ctx, &heuristicFound);
                            free(fullline);
                            if (heuristicFound) {
                                rc = VIRUS;
                            }
                        } else if (boundaryEnd(line, boundary)) {
                            /*
                             * Some viruses put information
                             * *after* the end of message,
                             * which presumably some broken
                             * mail clients find, so we
                             * can't assume that this
                             * is the end of the message
                             */
                            /* t_line = NULL;*/
                            break;
                        } else if (boundaryStart(line, boundary)) {
                            inhead = 1;
                            break;
                        } else {
                            if (messageAddLine(aMessage, t_line->t_line) < 0)
                                break;
                            lines++;
                        }
                    } while ((t_line = t_line->t_next) != NULL);

                    cli_dbgmsg("Part %d has %d lines, rc = %d\n",
                               multiparts, lines, (int)rc);

                    /*
                     * Only save in the array of messages if some
                     * decision will be taken on whether to scan.
                     * If all parts will be scanned then save to
                     * file straight away
                     */
                    switch (subtype) {
                        case MIXED:
                        case ALTERNATIVE:
                        case REPORT:
                        case DIGEST:
                        case APPLEDOUBLE:
                        case KNOWBOT:
                        case -1:
                            old_rc      = rc;
                            mainMessage = do_multipart(mainMessage,
                                                       messages, multiparts,
                                                       &rc, mctx, messageIn,
                                                       &aText, recursion_level);
                            if ((rc == OK_ATTACHMENTS_NOT_SAVED) && (old_rc == OK))
                                rc = OK;
                            if (messages[multiparts]) {
                                messageDestroy(messages[multiparts]);
                                messages[multiparts] = NULL;
                            }
                            --multiparts;
                            if (rc == VIRUS)
                                infected = true;
                            break;

                        case RELATED:
                        case ENCRYPTED:
                        case SIGNED:
                        case PARALLEL:
                            /* all the subtypes that we handle
                             * (all from the switch(tableFind...) below)
                             * must be listed here */
                            break;
                        default:
                            /* this is a subtype that we
                             * don't handle anyway,
                             * don't store */
                            if (messages[multiparts]) {
                                messageDestroy(messages[multiparts]);
                                messages[multiparts] = NULL;
                            }
                            --multiparts;
                    }
                }

                free((char *)boundary);

                if (haveTooManyMIMEPartsPerMessage(multiparts, mctx->ctx, &rc)) {
                    if (messages) {
                        for (i = 0; i < multiparts; i++) {
                            if (messages[i])
                                messageDestroy(messages[i]);
                        }
                        free(messages);
                        messages = NULL;
                    }
                    break;
                }

                /*
                 * Preprocess. Anything special to be done before
                 * we handle the multiparts?
                 */
                switch (subtype) {
                    case KNOWBOT:
                        /* TODO */
                        cli_dbgmsg("multipart/knowbot parsed as multipart/mixed for now\n");
                        mimeSubtype = "mixed";
                        break;
                    case -1:
                        /*
                         * According to section 7.2.6 of
                         * RFC1521, unrecognized multiparts
                         * should be treated as multipart/mixed.
                         */
                        cli_dbgmsg("Unsupported multipart format `%s', parsed as mixed\n", mimeSubtype);
                        mimeSubtype = "mixed";
                        break;
                }

                /*
                 * We've finished message we're parsing
                 */
                if (mainMessage && (mainMessage != messageIn)) {
                    messageDestroy(mainMessage);
                    mainMessage = NULL;
                }

                cli_dbgmsg("The message has %d parts\n", multiparts);

                if (infected || ((multiparts == 0) && (aText == NULL))) {
                    if (messages) {
                        for (i = 0; i < multiparts; i++) {
                            if (messages[i])
                                messageDestroy(messages[i]);
                        }
                        free(messages);
                        messages = NULL;
                    }
                    if (aText && (textIn == NULL))
                        textDestroy(aText);

                    mctx->wrkobj = saveobj;

                    /*
                     * Nothing to do
                     */
                    switch (rc) {
                        case VIRUS:
                            return VIRUS;
                        case MAXREC:
                            return MAXREC;
                        case MAXFILES:
                            return MAXFILES;
                        case FAIL:
                            return FAIL;
                        default:
                            return OK_ATTACHMENTS_NOT_SAVED;
                    }
                }

                cli_dbgmsg("Find out the multipart type (%s)\n", mimeSubtype);

                /*
                 * We now have all the parts of the multipart message
                 * in the messages array:
                 *    message *messages[multiparts]
                 * Let's decide what to do with them all
                 */
                switch (tableFind(mctx->subtypeTable, mimeSubtype)) {
                    case RELATED:
                        cli_dbgmsg("Multipart related handler\n");
                        /*
                         * Have a look to see if there's HTML code
                         * which will need scanning
                         */

                        // It's okay if multiparts == 0

                        htmltextPart = getTextPart(messages, multiparts);

                        if (htmltextPart >= 0 && messages) {
                            if (messageGetBody(messages[htmltextPart])) {

                                aText = textAddMessage(aText, messages[htmltextPart]);
                            }
                        } else {
                            /*
                             * There isn't an HTML bit. If there's a
                             * multipart bit, it'll may be in there
                             * somewhere
                             */
                            for (i = 0; i < multiparts; i++) {
                                if (messageGetMimeType(messages[i]) == MULTIPART) {
                                    htmltextPart = i;
                                    break;
                                }
                            }
                        }

                        if (htmltextPart == -1) {
                            cli_dbgmsg("No HTML code found to be scanned\n");
                        } else {
                            mbox_status mhtml_rc = OK;

                            /* Send root HTML file for preclassification */
                            if (mctx->ctx->this_layer_metadata_json)
                                mhtml_rc = parseRootMHTML(mctx, messages[htmltextPart], aText);

                            {
                                mbox_status body_rc = parseEmailBody(messages[htmltextPart], aText, mctx, recursion_level + 1);
                                if (body_rc != OK)
                                    rc = body_rc;
                                else if ((mhtml_rc != OK) && (rc == OK))
                                    rc = mhtml_rc;
                            }
                            if ((rc == OK) && messages[htmltextPart]) {
                                messageDestroy(messages[htmltextPart]);
                                messages[htmltextPart] = NULL;
                            } else if (rc == VIRUS) {
                                infected = true;
                                break;
                            }
                        }

                        /*
                         * The message is confused about the difference
                         * between alternative and related. Badtrans.B
                         * suffers from this problem.
                         *
                         * Fall through in this case:
                         * Content-Type: multipart/related;
                         *    type="multipart/alternative"
                         */
                        /* fall through */
                    case DIGEST:
                        /*
                         * According to section 5.1.5 RFC2046, the
                         * default mime type of multipart/digest parts
                         * is message/rfc822
                         *
                         * We consider them as alternative, wrong in
                         * the strictest sense since they aren't
                         * alternatives - all parts a valid - but it's
                         * OK for our needs since it means each part
                         * will be scanned
                         */
                    case ALTERNATIVE:
                        cli_dbgmsg("Multipart alternative handler\n");

                        /*
                         * Fall through - some clients are broken and
                         * say alternative instead of mixed. The Klez
                         * virus is broken that way, and anyway we
                         * wish to scan all of the alternatives
                         */
                        /* fall through */
                    case REPORT:
                        /*
                         * According to section 1 of RFC1892, the
                         * syntax of multipart/report is the same
                         * as multipart/mixed. There are some required
                         * parameters, but there's no need for us to
                         * verify that they exist
                         */
                    case ENCRYPTED:
                        /* MUAs without encryption plugins can display as multipart/mixed,
                         * just scan it*/
                    case MIXED:
                    case APPLEDOUBLE: /* not really supported */
                        /*
                         * Look for attachments
                         *
                         * Not all formats are supported. If an
                         * unsupported format turns out to be
                         * common enough to implement, it is a simple
                         * matter to add it
                         */
                        if (aText) {
                            if (mainMessage && (mainMessage != messageIn))
                                messageDestroy(mainMessage);
                            mainMessage = NULL;
                        }

                        cli_dbgmsg("Mixed message with %d parts\n", multiparts);
                        for (i = 0; i < multiparts; i++) {
                            mainMessage = do_multipart(mainMessage,
                                                       messages, i, &rc, mctx,
                                                       messageIn, &aText, recursion_level + 1);
                            if (rc == VIRUS) {
                                infected = true;
                                break;
                            }
                            if (rc == MAXREC)
                                break;
                            if (rc == MAXFILES)
                                break;
                            if (rc == OK_ATTACHMENTS_NOT_SAVED)
                                rc = OK;
                        }

                        /* rc = parseEmailBody(NULL, NULL, mctx, recursion_level + 1); */
                        break;
                    case SIGNED:
                    case PARALLEL:
                        /*
                         * If we're here it could be because we have a
                         * multipart/mixed message, consisting of a
                         * message followed by an attachment. That
                         * message itself is a multipart/alternative
                         * message and we need to dig out the plain
                         * text part of that alternative
                         */
                        if (messages) {
                            htmltextPart = getTextPart(messages, multiparts);
                            if (htmltextPart == -1)
                                htmltextPart = 0;
                            rc = parseEmailBody(messages[htmltextPart], aText, mctx, recursion_level + 1);
                        }
                        break;
                    default:
                        cli_dbgmsg("Unexpected mime sub type\n");
                        rc = FAIL;
                        break;
                }

                if (mainMessage && (mainMessage != messageIn))
                    messageDestroy(mainMessage);

                if (aText && (textIn == NULL)) {
                    if (!infected) {
                        cli_dbgmsg("Save non mime and/or text/plain part\n");
                        fb = fileblobCreate();
                        if (fb != NULL) {
                            fileblobSetFilename(fb, mctx->dir, "textpart");
                            /*fileblobAddData(fb, "Received: by clamd (textpart)\n", 30);*/
                            fileblobSetCTX(fb, mctx->ctx);
                            {
                                int scan_rc = scanFileblob(mctx, textToFileblob(aText, fb, 1));
                                if (scan_rc == CL_VIRUS)
                                    rc = VIRUS;
                                else if (scan_rc != CL_CLEAN)
                                    rc = FAIL;
                            }
                            mctx->files++;
                        } else {
                            cli_mark_scan_incomplete(mctx->ctx,
                                                     "MIME text-part temporary spool could not be created");
                            rc = FAIL;
                        }
                    }
                    textDestroy(aText);
                }

                if (messages) {
                    for (i = 0; i < multiparts; i++) {
                        if (messages[i])
                            messageDestroy(messages[i]);
                    }
                    free(messages);
                    messages = NULL;
                }

                mctx->wrkobj = saveobj;

                return rc;

            case MESSAGE:
                /*
                 * Check for forbidden encodings
                 */
                switch (messageGetEncoding(mainMessage)) {
                    case NOENCODING:
                    case EIGHTBIT:
                    case BINARY:
                        break;
                    default:
                        cli_dbgmsg("MIME type 'message' cannot be decoded\n");
                        cli_mark_scan_incomplete(mctx->ctx,
                                                 "MIME message uses an unsupported transfer encoding");
                        break;
                }
                rc = FAIL;
                if ((strcasecmp(mimeSubtype, "rfc822") == 0) ||
                    (strcasecmp(mimeSubtype, "delivery-status") == 0)) {
                    message *m = parseEmailHeaders(mainMessage, mctx->rfc821Table, &heuristicFound);
                    if (m) {
                        cli_dbgmsg("Decode rfc822\n");

                        messageSetCTX(m, mctx->ctx);

                        if (mainMessage && (mainMessage != messageIn)) {
                            messageDestroy(mainMessage);
                            mainMessage = NULL;
                        } else
                            messageReset(mainMessage);
                        if (messageGetBody(m))
                            rc = parseEmailBody(m, NULL, mctx, recursion_level + 1);
                        else
                            cli_mark_scan_incomplete(mctx->ctx,
                                                     "Encapsulated MIME message has no body to inspect");

                        messageDestroy(m);
                    } else if (heuristicFound) {
                        rc = VIRUS;
                    } else {
                        cli_mark_scan_incomplete(mctx->ctx,
                                                 "Encapsulated MIME message headers could not be parsed completely");
                    }
                    break;
                } else if (strcasecmp(mimeSubtype, "disposition-notification") == 0) {
                    /* RFC 2298 - handle like a normal email */
                    rc = OK;
                    break;
                } else if (strcasecmp(mimeSubtype, "partial") == 0) {
                    if (mctx->ctx->options->mail & CL_SCAN_MAIL_PARTIAL_MESSAGE) {
                        /* RFC1341 message split over many emails */
                        const int partial_rc = rfc1341(mctx, mainMessage);

                        if (partial_rc == CL_VIRUS)
                            rc = VIRUS;
                        else if (partial_rc == CL_SUCCESS || partial_rc == CL_CLEAN)
                            rc = OK;
                        else
                            cli_mark_scan_incomplete(mctx->ctx,
                                                     "Partial MIME message could not be reassembled completely");
                    } else {
                        cli_warnmsg("Partial message received from MUA/MTA - message cannot be scanned\n");
                        cli_mark_scan_incomplete(mctx->ctx,
                                                 "Partial MIME message support is disabled");
                    }
                } else if (strcasecmp(mimeSubtype, "external-body") == 0) {
                    /* TODO */
                    cli_warnmsg("Attempt to send Content-type message/external-body trapped\n");
                    cli_mark_scan_incomplete(mctx->ctx,
                                             "External-body MIME content cannot be inspected locally");
                } else {
                    cli_warnmsg("Unsupported message format `%s' - if you believe this file contains a virus, submit it to www.clamav.net\n", mimeSubtype);
                    cli_mark_scan_incomplete(mctx->ctx,
                                             "Unsupported MIME message format could not be inspected");
                }

                if (mainMessage && (mainMessage != messageIn))
                    messageDestroy(mainMessage);

                if (messages) {
                    for (i = 0; i < multiparts; i++) {
                        if (messages[i])
                            messageDestroy(messages[i]);
                    }
                    free(messages);
                    messages = NULL;
                }

                mctx->wrkobj = saveobj;

                return rc;

            default:
                cli_dbgmsg("Message received with unknown mime encoding - assume application\n");
                /*
                 * Some Yahoo emails attach as
                 * Content-Type: X-unknown/unknown;
                 * instead of
                 * Content-Type: application/unknown;
                 * so let's try our best to salvage something
                 */
                /* fall through */
            case APPLICATION:
                /*cptr = messageGetMimeSubtype(mainMessage);

                if((strcasecmp(cptr, "octet-stream") == 0) ||
                   (strcasecmp(cptr, "x-msdownload") == 0)) {*/
                {
                    fb = messageToFileblob(mainMessage, mctx->dir, 1);

                    if (fb) {
                        cli_dbgmsg("Saving main message as attachment\n");
                        {
                            int scan_rc = scanFileblob(mctx, fb);
                            if (scan_rc == CL_VIRUS)
                                rc = VIRUS;
                            else if (scan_rc != CL_CLEAN)
                                rc = FAIL;
                        }
                        mctx->files++;
                        if (mainMessage != messageIn) {
                            messageDestroy(mainMessage);
                            mainMessage = NULL;
                        } else
                            messageReset(mainMessage);
                    } else {
                        mbox_record_message_failure(mctx, mainMessage,
                                                    "MIME attachment could not be materialized completely");
                        (void)scanFileblob(mctx, fb);
                        rc = FAIL;
                    }
                } /*else
                cli_warnmsg("Discarded application not sent as attachment\n");*/
                break;

            case AUDIO:
            case VIDEO:
            case IMAGE:
                break;
        }

        if (messages) {
            /* "can't happen" */
            cli_warnmsg("messages != NULL\n");
            for (i = 0; i < multiparts; i++) {
                if (messages[i])
                    messageDestroy(messages[i]);
            }
            free(messages);
            messages = NULL;
        }
    }

    if (aText && (textIn == NULL)) {
        /* Look for a bounce in the text (non mime encoded) portion */
        const text *t;
        /* isBounceStart() is expensive, reduce the number of calls */
        bool lookahead_definitely_is_bounce = false;

        for (t = aText; t && (rc != VIRUS); t = t->t_next) {
            const line_t *l = t->t_line;
            const text *lookahead, *topofbounce;
            const char *s;
            bool inheader;

            if (l == NULL) {
                continue;
            }

            if (lookahead_definitely_is_bounce)
                lookahead_definitely_is_bounce = false;
            else if (!isBounceStart(mctx, lineGetData(l)))
                continue;

            lookahead = t->t_next;
            if (lookahead) {
                if (isBounceStart(mctx, lineGetData(lookahead->t_line))) {
                    lookahead_definitely_is_bounce = true;
                    /* don't save worthless header lines */
                    continue;
                }
            } else /* don't save a single liner */
                break;

            /*
             * We've found what looks like the start of a bounce
             * message. Only bother saving if it really is a bounce
             * message, this helps to speed up scanning of ping-pong
             * messages that have lots of bounces within bounces in
             * them
             */
            for (; lookahead; lookahead = lookahead->t_next) {
                l = lookahead->t_line;

                if (l == NULL)
                    break;
                s = lineGetData(l);
                if (strncasecmp(s, "Content-Type:", 13) == 0) {
                    /*
                     * Don't bother with text/plain or
                     * text/html
                     */
                    if (CLI_STRCASESTR(s, "text/plain") != NULL)
                        /*
                         * Don't bother to save the
                         * unuseful part, read past
                         * the headers then we'll go
                         * on to look for the next
                         * bounce message
                         */
                        continue;
                    if ((!doPhishingScan) &&
                        (CLI_STRCASESTR(s, "text/html") != NULL))
                        continue;
                    break;
                }
            }

            if (lookahead && (lookahead->t_line == NULL)) {
                cli_dbgmsg("Non mime part bounce message is not mime encoded, so it will not be scanned\n");
                t = lookahead;
                /* look for next bounce message */
                continue;
            }

            /*
             * Prescan the bounce message to see if there's likely
             * to be anything nasty.
             * This algorithm is hand crafted and may be breakable
             * so all submissions are welcome. It's best NOT to
             * remove this however you may be tempted, because it
             * significantly speeds up the scanning of multiple
             * bounces (i.e. bounces within many bounces)
             */
            for (; lookahead; lookahead = lookahead->t_next) {
                l = lookahead->t_line;

                if (l) {
                    s = lineGetData(l);
                    if ((strncasecmp(s, "Content-Type:", 13) == 0) &&
                        (strstr(s, "multipart/") == NULL) &&
                        (strstr(s, "message/rfc822") == NULL) &&
                        (strstr(s, "text/plain") == NULL))
                        break;
                }
            }
            if (lookahead == NULL) {
                cli_dbgmsg("cli_mbox: I believe it's plain text which must be clean\n");
                /* nothing here, move along please */
                break;
            }
            if ((fb = fileblobCreate()) == NULL)
                break;
            cli_dbgmsg("Save non mime part bounce message\n");
            fileblobSetFilename(fb, mctx->dir, "bounce");
            fileblobAddData(fb, (const unsigned char *)"Received: by clamd (bounce)\n", 28);
            fileblobSetCTX(fb, mctx->ctx);

            inheader    = true;
            topofbounce = NULL;
            do {
                l = t->t_line;

                if (l == NULL) {
                    if (inheader) {
                        inheader    = false;
                        topofbounce = t;
                    }
                } else {
                    s = lineGetData(l);
                    fileblobAddData(fb, (const unsigned char *)s, strlen(s));
                }
                fileblobAddData(fb, (const unsigned char *)"\n", 1);
                lookahead = t->t_next;
                if (lookahead == NULL)
                    break;
                t = lookahead;
                l = t->t_line;
                if ((!inheader) && l) {
                    s = lineGetData(l);
                    if (isBounceStart(mctx, s)) {
                        cli_dbgmsg("Found the start of another bounce candidate (%s)\n", s);
                        lookahead_definitely_is_bounce = true;
                        break;
                    }
                }
            } while (!fileblobInfected(fb));

            {
                const int scan_rc = scanFileblob(mctx, fb);

                if (scan_rc == CL_VIRUS)
                    rc = VIRUS;
                else if (scan_rc != CL_CLEAN && rc != VIRUS)
                    rc = FAIL;
            }
            mctx->files++;

            if (topofbounce)
                t = topofbounce;
        }
        textDestroy(aText);
        aText = NULL;
    }

    /*
     * No attachments - scan the text portions, often files
     * are hidden in HTML code
     */
    if (mainMessage && (rc != VIRUS)) {
        text *t_line;

        /*
         * Look for uu-encoded main file
         */
        if (mainMessage->body_first != NULL &&
            (encodingLine(mainMessage) != NULL) &&
            ((t_line = bounceBegin(mainMessage)) != NULL)) {
            int scan_rc = exportBounceMessage(mctx, t_line);
            if (scan_rc == CL_VIRUS)
                rc = VIRUS;
            else if (scan_rc != CL_CLEAN)
                rc = FAIL;
            else
                rc = OK;
        } else {
            bool saveIt;

            if (messageGetMimeType(mainMessage) == MESSAGE)
                /*
                 * Quick peek, if the encapsulated
                 * message has no
                 * content encoding statement don't
                 * bother saving to scan, it's safe
                 */
                saveIt = (bool)(encodingLine(mainMessage) != NULL);
            else if (mainMessage->body_last != NULL && (t_line = encodingLine(mainMessage)) != NULL) {
                /*
                 * Some bounces include the message
                 * body without the headers.
                 * FIXME: Unfortunately this generates a
                 * lot of false positives that a bounce
                 * has been found when it hasn't.
                 */
                if ((fb = fileblobCreate()) != NULL) {
                    cli_dbgmsg("Found a bounce message with no header at '%s'\n",
                               lineGetData(t_line->t_line));
                    fileblobSetFilename(fb, mctx->dir, "bounce");
                    fileblobAddData(fb,
                                    (const unsigned char *)"Received: by clamd (bounce)\n",
                                    28);

                    fileblobSetCTX(fb, mctx->ctx);
                    const int scan_rc = scanFileblob(mctx, textToFileblob(t_line, fb, 1));

                    if (scan_rc == CL_VIRUS)
                        rc = VIRUS;
                    else if (scan_rc != CL_CLEAN && rc != VIRUS)
                        rc = FAIL;
                    mctx->files++;
                }
                saveIt = false;
            } else
                /*
                 * Save the entire text portion,
                 * since it may be an HTML file with
                 * a JavaScript virus or a phish
                 */
                saveIt = true;

            if (saveIt) {
                cli_dbgmsg("Saving text part to scan, rc = %d\n",
                           (int)rc);
                {
                    int scan_rc = saveTextPart(mctx, mainMessage, 1);
                    if (scan_rc == CL_VIRUS)
                        rc = VIRUS;
                    else if (scan_rc != CL_CLEAN)
                        rc = FAIL;
                }

                if (mainMessage != messageIn) {
                    messageDestroy(mainMessage);
                    mainMessage = NULL;
                } else
                    messageReset(mainMessage);
            }
        }
    } /*else
        rc = OK_ATTACHMENTS_NOT_SAVED; */
      /* nothing saved */

    if (mainMessage && (mainMessage != messageIn))
        messageDestroy(mainMessage);

    if ((rc != FAIL) && infected)
        rc = VIRUS;

    mctx->wrkobj = saveobj;

    cli_dbgmsg("parseEmailBody() returning %d\n", (int)rc);

    return rc;
}

/*
 * Is the current line the start of a new section?
 *
 * New sections start with --boundary
 */
static int
boundaryStart(const char *line, const char *boundary)
{
    const char *ptr;
    char *out;
    int rc;
    char buf[RFC2821LENGTH + 1];
    char *newline;

    if (line == NULL || *line == '\0')
        return 0; /* empty line */
    if (boundary == NULL)
        return 0;

    newline = strdup(line);
    if (!(newline))
        newline = (char *)line;

    if (newline != line && strlen(line)) {
        char *p;
        /* Trim trailing spaces */
        p = newline + strlen(line) - 1;
        while (p >= newline && *p == ' ')
            *(p--) = '\0';
    }

    if (newline != line)
        cli_chomp(newline);

    /* cli_dbgmsg("boundaryStart: line = '%s' boundary = '%s'\n", line, boundary); */

    if ((*newline != '-') && (*newline != '(')) {
        if (newline != line)
            free(newline);
        return 0;
    }

    if (strchr(newline, '-') == NULL) {
        if (newline != line)
            free(newline);
        return 0;
    }

    if (strlen(newline) <= sizeof(buf)) {
        out = NULL;
        ptr = rfc822comments(newline, buf);
    } else
        ptr = out = rfc822comments(newline, NULL);

    if (ptr == NULL)
        ptr = newline;

    if ((*ptr++ != '-') || (*ptr == '\0')) {
        if (out)
            free(out);
        if (newline != line)
            free(newline);

        return 0;
    }

    /*
     * Gibe.B3 is broken, it has:
     *    boundary="---- =_NextPart_000_01C31177.9DC7C000"
     * but its boundaries look like
     *    ------ =_NextPart_000_01C31177.9DC7C000
     * notice the one too few '-'.
     * Presumably this is a deliberate exploitation of a bug in some mail
     * clients.
     *
     * The trouble is that this creates a lot of false positives for
     * boundary conditions, if we're too lax about matches. We do our level
     * best to avoid these false positives. For example if we have
     * boundary="1" we want to ensure that we don't break out of every line
     * that has -1 in it instead of starting --1. This needs some more work.
     *
     * Look with and without RFC822 comments stripped, I've seen some
     * samples where () are taken as comments in boundaries and some where
     * they're not. Irrespective of whatever RFC2822 says, we need to find
     * viruses in both types of mails.
     */
    if ((strstr(&ptr[1], boundary) != NULL) || (strstr(newline, boundary) != NULL)) {
        const char *k = ptr;

        /*
         * We need to ensure that we don't match --11=-=-=11 when
         * looking for --1=-=-=1 in well behaved headers, that's a
         * false positive problem mentioned above
         */
        rc = 0;
        do
            if (strcmp(++k, boundary) == 0) {
                rc = 1;
                break;
            }
        while (*k == '-');
        if (rc == 0) {
            k = &line[1];
            do
                if (strcmp(++k, boundary) == 0) {
                    rc = 1;
                    break;
                }
            while (*k == '-');
        }
    } else if (*ptr++ != '-')
        rc = 0;
    else
        rc = (strcasecmp(ptr, boundary) == 0);

    if (out)
        free(out);

    if (rc == 1)
        cli_dbgmsg("boundaryStart: found %s in %s\n", boundary, line);

    if (newline != line)
        free(newline);

    return rc;
}

/*
 * Is the current line the end?
 *
 * The message ends with --boundary--
 */
static int
boundaryEnd(const char *line, const char *boundary)
{
    size_t len;
    char *newline, *p, *p2;

    if (line == NULL || *line == '\0')
        return 0;

    p = newline = strdup(line);
    if (!(newline)) {
        p       = (char *)line;
        newline = (char *)line;
    }

    if (newline != line && strlen(line)) {
        /* Trim trailing spaces */
        p2 = newline + strlen(line) - 1;
        while (p2 >= newline && *p2 == ' ')
            *(p2--) = '\0';
    }

    /* cli_dbgmsg("boundaryEnd: line = '%s' boundary = '%s'\n", newline, boundary); */

    if (*p++ != '-') {
        if (newline != line)
            free(newline);
        return 0;
    }

    if (*p++ != '-') {
        if (newline != line)
            free(newline);

        return 0;
    }

    len = strlen(boundary);
    if (strncasecmp(p, boundary, len) != 0) {
        if (newline != line)
            free(newline);

        return 0;
    }
    /*
     * Use < rather than == because some broken mails have white
     * space after the boundary
     */
    if (strlen(p) < (len + 2)) {
        if (newline != line)
            free(newline);

        return 0;
    }

    p = &p[len];
    if (*p++ != '-') {
        if (newline != line)
            free(newline);

        return 0;
    }

    if (*p == '-') {
        /* cli_dbgmsg("boundaryEnd: found %s in %s\n", boundary, p); */
        if (newline != line)
            free(newline);

        return 1;
    }

    if (newline != line)
        free(newline);

    return 0;
}

/*
 * Initialise the various lookup tables
 *
 * Only initializes the tables if not already initialized.
 */
static int
initialiseTables(table_t **rfc821Table, table_t **subtypeTable)
{
    const struct tableinit *tableinit;

    /*
     * Initialise the various look up tables
     */
    if (NULL == *rfc821Table) {
        *rfc821Table = tableCreate();
        if (*rfc821Table == NULL) {
            return -1;
        }

        for (tableinit = rfc821headers; tableinit->key; tableinit++) {
            if (tableInsert(*rfc821Table, tableinit->key, tableinit->value) < 0) {
                tableDestroy(*rfc821Table);
                *rfc821Table = NULL;
                return -1;
            }
        }
    }
    if (NULL == *subtypeTable) {
        *subtypeTable = tableCreate();
        if (*subtypeTable == NULL) {
            tableDestroy(*rfc821Table);
            *rfc821Table = NULL;
            return -1;
        }

        for (tableinit = mimeSubtypes; tableinit->key; tableinit++) {
            if (tableInsert(*subtypeTable, tableinit->key, tableinit->value) < 0) {
                tableDestroy(*rfc821Table);
                tableDestroy(*subtypeTable);
                *rfc821Table  = NULL;
                *subtypeTable = NULL;
                return -1;
            }
        }
    }

    return 0;
}

/*
 * If there's a HTML text version use that, otherwise
 * use the first text part, otherwise just use the
 * first one around. HTML text is most likely to include
 * a scripting worm
 *
 * If we can't find one, return -1
 */
static int
getTextPart(message *const messages[], size_t size)
{
    size_t i;
    int textpart = -1;

    for (i = 0; i < size; i++)
        if (messages[i] && (messageGetMimeType(messages[i]) == TEXT)) {
            if (strcasecmp(messageGetMimeSubtype(messages[i]), "html") == 0)
                return (int)i;
            textpart = (int)i;
        }

    return textpart;
}

/*
 * strip -
 *    Remove the trailing spaces from a buffer. Don't call this directly,
 * always call strstrip() which is a wrapper to this routine to be used with
 * NUL terminated strings. This code looks a bit strange because of its
 * heritage from code that worked on strings that weren't necessarily NUL
 * terminated.
 * TODO: rewrite for clamAV
 *
 * Returns its new length (a la strlen)
 *
 * len must be int not size_t because of the >= 0 test, it is sizeof(buf)
 *    not strlen(buf)
 */
static size_t
strip(char *buf, int len)
{
    register char *ptr;
    register size_t i;

    if ((buf == NULL) || (len <= 0))
        return 0;

    i = strlen(buf);
    if (len > (int)(i + 1))
        return i;
    ptr = &buf[--len];

#if defined(UNIX) || defined(C_LINUX) || defined(C_DARWIN) /* watch - it may be in shared text area */
    do
        if (*ptr)
            *ptr = '\0';
    while ((--len >= 0) && (!isgraph(*--ptr)) && (*ptr != '\n') && (*ptr != '\r'));
#else /* more characters can be displayed on DOS */
    do
#ifndef REAL_MODE_DOS
        if (*ptr) /* C8.0 puts into a text area */
#endif
            *ptr = '\0';
    while ((--len >= 0) && ((*--ptr == '\0') || isspace((int)(*ptr & 0xFF))));
#endif
    return ((size_t)(len + 1));
}

/*
 * strstrip:
 *    Strip a given string
 */
size_t
strstrip(char *s)
{
    if (s == (char *)NULL)
        return (0);

    return (strip(s, strlen(s) + 1));
}

/*
 * Returns 0 for OK, -1 for error
 */
static int
parseMimeHeader(message *m, const char *cmd, const table_t *rfc821Table, const char *arg, cli_ctx *ctx, bool *heuristicFound)
{
    char *copy, *p, *buf;
    const char *ptr;
    int commandNumber;
    size_t argCnt = 0;

    *heuristicFound = false;

    cli_dbgmsg("parseMimeHeader: cmd='%s', arg='%s'\n", cmd, arg);

    copy = rfc822comments(cmd, NULL);
    if (copy) {
        commandNumber = tableFind(rfc821Table, copy);
        free(copy);
    } else {
        commandNumber = tableFind(rfc821Table, cmd);
    }

    copy = rfc822comments(arg, NULL);

    if (copy) {
        ptr = copy;
    } else {
        ptr = arg;
    }

    buf = NULL;

    switch (commandNumber) {
        case CONTENT_TYPE:
            /*
             * Fix for non RFC1521 compliant mailers
             * that send content-type: Text instead
             * of content-type: Text/Plain, or
             * just simply "Content-Type:"
             */
            if (arg == NULL)
                /*
                 * According to section 4 of RFC1521:
                 * "Note also that a subtype specification is
                 * MANDATORY. There are no default subtypes"
                 *
                 * We have to break this and make an assumption
                 * for the subtype because virus writers and
                 * email client writers don't get it right
                 */
                cli_dbgmsg("Empty content-type received, no subtype specified, assuming text/plain; charset=us-ascii\n");
            else if (strchr(ptr, '/') == NULL)
                /*
                 * Empty field, such as
                 *    Content-Type:
                 * which I believe is illegal according to
                 * RFC1521
                 */
                cli_dbgmsg("Invalid content-type '%s' received, no subtype specified, assuming text/plain; charset=us-ascii\n", ptr);
            else {
                int i;

                buf = cli_max_malloc(strlen(ptr) + 1);
                if (buf == NULL) {
                    cli_errmsg("parseMimeHeader: Unable to allocate memory for buf %llu\n", (long long unsigned)(strlen(ptr) + 1));
                    cli_mark_scan_incomplete(ctx,
                                             "MIME Content-Type buffer could not be allocated");
                    if (copy)
                        free(copy);
                    return -1;
                }
                /*
                 * Some clients are broken and
                 * put white space after the ;
                 */
                if (*arg == '/') {
                    cli_dbgmsg("Content-type '/' received, assuming application/octet-stream\n");
                    messageSetMimeType(m, "application");
                    messageSetMimeSubtype(m, "octet-stream");
                } else {
                    /*
                     * The content type could be in quotes:
                     *    Content-Type: "multipart/mixed"
                     * FIXME: this is a hack in that ignores
                     *    the quotes, it doesn't handle
                     *    them properly
                     */
                    while (isspace((const unsigned char)*ptr))
                        ptr++;
                    if (ptr[0] == '\"')
                        ptr++;

                    if (ptr[0] != '/') {
                        char *s;
#ifdef CL_THREAD_SAFE
                        char *strptr = NULL;
#endif

                        s = cli_strtokbuf(ptr, 0, ";", buf);
                        /*
                         * Handle
                         * Content-Type: foo/bar multipart/mixed
                         * and
                         * Content-Type: multipart/mixed foo/bar
                         */
                        if (s && *s) {
                            char *buf2 = cli_safer_strdup(buf);

                            if (buf2 == NULL) {
                                cli_mark_scan_incomplete(ctx,
                                                         "MIME Content-Type token buffer could not be allocated");
                                if (copy)
                                    free(copy);
                                free(buf);
                                return -1;
                            }
                            for (;;) {
#ifdef CL_THREAD_SAFE
                                int set = messageSetMimeType(m, strtok_r(s, "/", &strptr));
#else
                                int set = messageSetMimeType(m, strtok(s, "/"));
#endif

#ifdef CL_THREAD_SAFE
                                s = strtok_r(NULL, ";", &strptr);
#else
                                s       = strtok(NULL, ";");
#endif
                                if (s == NULL)
                                    break;
                                if (set) {
                                    size_t len = strstrip(s) - 1;
                                    if (s[len] == '\"') {
                                        s[len] = '\0';
                                        len    = strstrip(s);
                                    }
                                    if (len) {
                                        if (strchr(s, ' '))
                                            messageSetMimeSubtype(m,
                                                                  cli_strtokbuf(s, 0, " ", buf2));
                                        else
                                            messageSetMimeSubtype(m, s);
                                    }
                                }

                                while (*s && !isspace((unsigned char)*s))
                                    s++;
                                if (*s++ == '\0')
                                    break;
                                if (*s == '\0')
                                    break;
                            }
                            free(buf2);
                        }
                    }
                }

                /*
                 * Add in all rest of the arguments.
                 * e.g. if the header is this:
                 * Content-Type:', arg='multipart/mixed; boundary=foo
                 * we find the boundary argument set it
                 */
                i = 1;
                while (cli_strtokbuf(ptr, i++, ";", buf) != NULL) {
                    cli_dbgmsg("mimeArgs = '%s'\n", buf);

                    argCnt++;
                    if (haveTooManyMIMEArguments(argCnt, ctx, heuristicFound)) {
                        break;
                    }
                    messageAddArguments(m, buf);
                }
            }
            break;
        case CONTENT_TRANSFER_ENCODING:
            messageSetEncoding(m, ptr);
            break;
        case CONTENT_DISPOSITION:
            buf = cli_max_malloc(strlen(ptr) + 1);
            if (buf == NULL) {
                cli_errmsg("parseMimeHeader: Unable to allocate memory for buf %llu\n", (long long unsigned)(strlen(ptr) + 1));
                cli_mark_scan_incomplete(ctx,
                                         "MIME Content-Disposition buffer could not be allocated");
                if (copy)
                    free(copy);
                return -1;
            }
            p = cli_strtokbuf(ptr, 0, ";", buf);
            if (p && *p) {
                messageSetDispositionType(m, p);
                messageAddArgument(m, cli_strtokbuf(ptr, 1, ";", buf));
            }
            if (!messageHasFilename(m))
                /*
                 * Handle this type of header, without
                 * a filename (e.g. some Worm.Torvil.D)
                 *    Content-ID: <nRfkHdrKsAxRU>
                 * Content-Transfer-Encoding: base64
                 * Content-Disposition: attachment
                 */
                messageAddArgument(m, "filename=unknown");
    }
    if (copy)
        free(copy);
    if (buf)
        free(buf);

    return 0;
}

/*
 * Save the text portion of the message
 */
static int
saveTextPart(mbox_ctx *mctx, message *m, int destroy_text)
{
    fileblob *fb;

    messageAddArgument(m, "filename=textportion");
    if ((fb = messageToFileblob(m, mctx->dir, destroy_text)) != NULL) {
        /*
         * Save main part to scan that
         */
        cli_dbgmsg("Saving main message\n");

        mctx->files++;
        return scanFileblob(mctx, fb);
    }
    mbox_record_message_failure(mctx, m,
                                "MIME text part could not be materialized as a temporary spool");
    cli_mark_scan_incomplete(mctx->ctx,
                             "MIME text part could not be materialized as a temporary spool");
    return (mctx->message_failure_status != CL_SUCCESS) ? mctx->message_failure_status : CL_ETMPFILE;
}

/*
 * Handle RFC822 comments in headers.
 * If out == NULL, return a buffer without the comments, the caller must free
 *    the returned buffer
 * Return NULL on error or if the input * has no comments.
 * See section 3.4.3 of RFC822
 * TODO: handle comments that go on to more than one line
 */
static char *
rfc822comments(const char *in, char *out)
{
    const char *iptr;
    char *optr;
    int backslash, inquote, commentlevel;

    if (in == NULL || out == in) {
        cli_errmsg("rfc822comments: Invalid parameters.n");
        return NULL;
    }

    if (strchr(in, '(') == NULL) {
        return NULL;
    }

    while (isspace((const unsigned char)*in)) {
        in++;
    }

    if (out == NULL) {
        out = cli_max_malloc(strlen(in) + 1);
        if (out == NULL) {
            cli_errmsg("rfc822comments: Unable to allocate memory for out %llu\n", (long long unsigned)(strlen(in) + 1));
            return NULL;
        }
    }

    backslash = commentlevel = inquote = 0;
    optr                               = out;

    cli_dbgmsg("rfc822comments: contains a comment\n");

    for (iptr = in; *iptr; iptr++)
        if (backslash) {
            if (commentlevel == 0)
                *optr++ = *iptr;
            backslash = 0;
        } else
            switch (*iptr) {
                case '\\':
                    backslash = 1;
                    break;
                case '\"':
                    *optr++ = '\"';
                    inquote = !inquote;
                    break;
                case '(':
                    if (inquote)
                        *optr++ = '(';
                    else
                        commentlevel++;
                    break;
                case ')':
                    if (inquote)
                        *optr++ = ')';
                    else if (commentlevel > 0)
                        commentlevel--;
                    break;
                default:
                    if (commentlevel == 0)
                        *optr++ = *iptr;
            }

    if (backslash) /* last character was a single backslash */
        *optr++ = '\\';
    *optr = '\0';

    /*strstrip(out);*/

    cli_dbgmsg("rfc822comments '%s'=>'%s'\n", in, out);

    return out;
}

/*
 * Handle RFC2047 encoding. Returns a malloc'd buffer that the caller must
 * free, or NULL on error
 */
static char *
rfc2047(const char *in, cli_ctx *ctx)
{
    char *out, *pout;
    size_t len;

    if ((strstr(in, "=?") == NULL) || (strstr(in, "?=") == NULL))
        return cli_safer_strdup(in);

    cli_dbgmsg("rfc2047 '%s'\n", in);
    out = cli_max_malloc(strlen(in) + 1);

    if (out == NULL) {
        cli_errmsg("rfc2047: Unable to allocate memory for out %llu\n", (long long unsigned)(strlen(in) + 1));
        return NULL;
    }

    pout = out;

    /* For each RFC2047 string */
    while (*in) {
        char encoding, *ptr, *enctext;
        message *m;
        blob *b;

        /* Find next RFC2047 string */
        while (*in) {
            if ((*in == '=') && (in[1] == '?')) {
                in += 2;
                break;
            }
            *pout++ = *in++;
        }
        /* Skip over charset, find encoding */
        while ((*in != '?') && *in)
            in++;
        if (*in == '\0')
            break;
        encoding = *++in;
        encoding = (char)tolower(encoding);

        if ((encoding != 'q') && (encoding != 'b')) {
            cli_warnmsg("Unsupported RFC2047 encoding type '%c' - if you believe this file contains a virus, submit it to www.clamav.net\n", encoding);
            free(out);
            out = NULL;
            break;
        }
        /* Skip to encoded text */
        if (*++in != '?')
            break;
        if (*++in == '\0')
            break;

        enctext = cli_safer_strdup(in);
        if (enctext == NULL) {
            free(out);
            out = NULL;
            break;
        }
        in = strstr(in, "?=");
        if (in == NULL) {
            free(enctext);
            break;
        }
        in += 2;
        ptr = strstr(enctext, "?=");
        if (NULL == ptr) {
            free(enctext);
            break;
        }
        *ptr = '\0';
        /*cli_dbgmsg("Need to decode '%s' with method '%c'\n", enctext, encoding);*/

        m = messageCreate();
        if (m == NULL) {
            free(enctext);
            break;
        }
        if (messageAddStr(m, enctext) < 0) {
            cli_mark_scan_incomplete(ctx, "RFC2047 header materialization was incomplete");
            messageDestroy(m);
            free(enctext);
            free(out);
            return NULL;
        }

        free(enctext);
        enctext = NULL;

        switch (encoding) {
            case 'q':
                messageSetEncoding(m, "quoted-printable");
                break;
            case 'b':
                messageSetEncoding(m, "base64");
                break;
        }
        b = messageToBlob(m, 1);
        if (b == NULL) {
            cli_mark_scan_incomplete(ctx, "RFC2047 decoded header could not be materialized completely");
            messageDestroy(m);
            free(out);
            return NULL;
        }
        len = blobGetDataSize(b);
        cli_dbgmsg("Decoded as '%*.*s'\n", (int)len, (int)len,
                   (const char *)blobGetData(b));
        memcpy(pout, blobGetData(b), len);
        blobDestroy(b);
        messageDestroy(m);
        if (len > 0 && pout[len - 1] == '\n')
            pout += len - 1;
        else
            pout += len;
    }
    if (out == NULL)
        return NULL;

    *pout = '\0';

    cli_dbgmsg("rfc2047 returns '%s'\n", out);
    return out;
}

/*
 * Handle partial messages
 */
static bool
parsePartialCount(const char *value, unsigned int *count)
{
    const char *start;
    char *end;
    unsigned long parsed;

    if (value == NULL || count == NULL)
        return false;

    start = value;
    while (isspace((unsigned char)*start))
        start++;
    if (!isdigit((unsigned char)*start))
        return false;

    errno  = 0;
    parsed = strtoul(start, &end, 10);
    if (errno == ERANGE || end == start || parsed == 0 ||
        parsed > HEURISTIC_EMAIL_MAX_MIME_PARTS_PER_MESSAGE)
        return false;

    while (isspace((unsigned char)*end))
        end++;
    if (*end == ';') {
        end++;
        while (isspace((unsigned char)*end))
            end++;
    }
    if (*end != '\0')
        return false;

    *count = (unsigned int)parsed;
    return true;
}

static int
rfc1341(mbox_ctx *mctx, message *m)
{
    char *arg, *id, *number, *total, *oldfilename;
    const char *tmpdir = NULL;
    unsigned int n, t = 0;
    bool have_total = false;
    char pdir[PATH_MAX + 1];
    int pdir_length;
    unsigned char md5_val[16];
    char *md5_hex;

    if ((NULL == mctx) || (NULL == m)) {
        cli_dbgmsg("rfc1341: Invalid NULL arguments\n");
        return -1;
    }

    id = (char *)messageFindArgument(m, "id");
    if (id == NULL || *id == '\0') {
        cli_mark_scan_incomplete(mctx->ctx,
                                 "MIME partial message identifier is missing or empty");
        free(id);
        return -1;
    }

    number = (char *)messageFindArgument(m, "number");
    if (number == NULL || !parsePartialCount(number, &n)) {
        cli_mark_scan_incomplete(mctx->ctx,
                                 "MIME partial message number is invalid");
        free(id);
        free(number);
        return CL_EPARSE;
    }

    total = (char *)messageFindArgument(m, "total");
    if (total != NULL) {
        if (!parsePartialCount(total, &t) || n > t) {
            cli_mark_scan_incomplete(mctx->ctx,
                                     "MIME partial message total is invalid");
            free(id);
            free(number);
            free(total);
            return CL_EPARSE;
        }
        have_total = true;
    }

    if (mbox_check_deadline(mctx->ctx)) {
        free(id);
        free(number);
        free(total);
        return CL_ETIMEOUT;
    }

    if (NULL != mctx->ctx) {
        tmpdir = cl_engine_get_str((const struct cl_engine *)mctx->ctx->engine, CL_ENGINE_TMPDIR, NULL);
    }
    if (NULL == tmpdir) {
        tmpdir = cli_gettmpdir();
    }

    pdir_length = (tmpdir == NULL)
                      ? -1
                      : snprintf(pdir, sizeof(pdir), "%s" PATHSEP "clamav-partial", tmpdir);
    if (pdir_length < 0 || pdir_length >= (int)sizeof(pdir)) {
        cli_mark_scan_incomplete(mctx->ctx,
                                 "Partial MIME directory path is too long");
        free(id);
        free(number);
        free(total);
        return CL_EPARSE;
    }

    errno = 0;
    if ((mkdir(pdir, S_IRUSR | S_IWUSR) < 0) && (errno != EEXIST)) {
        cli_errmsg("Can't create the directory '%s'\n", pdir);
        mbox_record_status(
            mctx, CL_ECREAT,
            "Partial MIME directory could not be created");
        free(id);
        free(number);
        free(total);
        return -1;
    } else if (errno == EEXIST) {
        STATBUF statb;

        if (CLAMSTAT(pdir, &statb) < 0) {
            char err[128];
            cli_errmsg("Partial directory %s: %s\n", pdir,
                       cli_strerror(errno, err, sizeof(err)));
            mbox_record_status(
                mctx, CL_ESTAT,
                "Partial MIME directory could not be inspected");
            free(id);
            free(number);
            free(total);
            return -1;
        }
        if (statb.st_mode & 077)
            cli_warnmsg("Insecure partial directory %s (mode 0%o)\n",
                        pdir,
#ifdef ACCESSPERMS
                        (int)(statb.st_mode & ACCESSPERMS)
#else
                        (int)(statb.st_mode & 0777)
#endif
            );
    }

    oldfilename = messageGetFilename(m);

    if (strlen(id) > SIZE_MAX - 10U ||
        strlen(number) > SIZE_MAX - 10U - strlen(id)) {
        cli_mark_scan_incomplete(mctx->ctx,
                                 "MIME partial message filename length overflowed");
        free(id);
        free(number);
        free(total);
        return CL_ERESOURCE;
    }
    arg = cli_max_malloc(10U + strlen(id) + strlen(number));
    if (arg) {
        sprintf(arg, "filename=%s%s", id, number);
        messageAddArgument(m, arg);
        free(arg);
    }

    if (oldfilename) {
        cli_dbgmsg("Must reset to %s\n", oldfilename);
        free(oldfilename);
    }

    cl_hash_data("md5", id, strlen(id), md5_val, NULL);
    md5_hex = cli_str2hex((const char *)md5_val, 16);

    if (!md5_hex) {
        cli_mark_scan_incomplete(mctx->ctx, "MIME partial message identifier could not be allocated");
        free(id);
        free(number);
        free(total);
        return CL_EMEM;
    }

    {
        const int save_status = messageSavePartial(m, pdir, md5_hex, n);

        /* cl_error_t values are non-negative enum members. The historical
         * caller checked only for a negative sentinel, which allowed a
         * positive CL_ECREAT/CL_EWRITE/etc. from the fileblob layer to be
         * treated as a successfully saved fragment. Preserve the specific
         * status before the parser converts the RFC 1341 branch to its
         * internal mailbox control result. */
        if (save_status != CL_SUCCESS) {
            mbox_record_message_failure(
                mctx, m, "MIME partial message could not be saved completely");
            cli_mark_scan_incomplete(mctx->ctx,
                                     "MIME partial message could not be saved completely");
            free(md5_hex);
            free(id);
            free(number);
            free(total);
            return save_status > CL_SUCCESS ? save_status : CL_EPARSE;
        }
    }

    cli_dbgmsg("rfc1341: %s, %s of %s\n", id, number, (total) ? total : "?");
    if (have_total) {
        DIR *dd = NULL;

        free(total);
        total = NULL;
        /*
         * If it's the last one - reassemble it
         * FIXME: this assumes that we receive the parts in order
         */
        if ((n == t) && ((dd = opendir(pdir)) != NULL)) {
            fileblob *fout;
            char outname[PATH_MAX + 1];
            time_t now;

            sanitiseName(id);

            snprintf(outname, sizeof(outname) - 1, "%s" PATHSEP "%s", mctx->dir, id);

            cli_dbgmsg("outname: %s\n", outname);

            fout = fileblobCreate();
            if (fout == NULL) {
                cli_errmsg("Can't open '%s' for writing", outname);
                mbox_record_fileblob_failure(
                    mctx, NULL, CL_EMEM,
                    "MIME partial message reassembly output could not be allocated");
                free(id);
                free(number);
                free(md5_hex);
                closedir(dd);
                return -1;
            }

            fileblobSetCTX(fout, mctx->ctx);
            (void)cli_unlink(outname);
            fileblobPartialSet(fout, outname, NULL);
            if (fout->isIncomplete || fout->fp == NULL) {
                cli_errmsg("Can't open '%s' for writing", outname);
                mbox_record_fileblob_failure(
                    mctx, fout, CL_EOPEN,
                    "MIME partial message reassembly output could not be opened");
                destroyPartialOutput(fout, outname);
                free(id);
                free(number);
                free(md5_hex);
                closedir(dd);
                return -1;
            }

            time(&now);
            for (n = 1; n <= t; n++) {
                char filename[NAME_MAX + 1];
                struct dirent *dent;
                bool found_part = false;

                if (mbox_check_deadline(mctx->ctx)) {
                    mbox_record_status(
                        mctx, CL_ETIMEOUT,
                        "MIME partial message reassembly reached the configured time limit");
                    destroyPartialOutput(fout, outname);
                    free(md5_hex);
                    free(id);
                    free(number);
                    closedir(dd);
                    return CL_ETIMEOUT;
                }

                snprintf(filename, sizeof(filename), "_%s-%u", md5_hex, n);

                for (;;) {
                    FILE *fin;
                    char buffer[BUFSIZ], fullname[PATH_MAX + 1 + 256 + 1];
                    int nblanks;
                    int fin_error;
                    int fin_close_error;
                    STATBUF statb;
                    const char *dentry_idpart;
                    int test_fd;

                    if (mbox_check_deadline(mctx->ctx)) {
                        mbox_record_status(
                            mctx, CL_ETIMEOUT,
                            "MIME partial message reassembly reached the configured time limit");
                        destroyPartialOutput(fout, outname);
                        free(md5_hex);
                        free(id);
                        free(number);
                        closedir(dd);
                        return CL_ETIMEOUT;
                    }

                    errno = 0;
                    dent  = readdir(dd);
                    if (dent == NULL) {
                        if (errno != 0) {
                            mbox_record_status(
                                mctx, CL_EREAD,
                                "Partial MIME directory could not be enumerated completely");
                            destroyPartialOutput(fout, outname);
                            free(md5_hex);
                            free(id);
                            free(number);
                            closedir(dd);
                            return -1;
                        }
                        break;
                    }

                    if (dent->d_ino == 0)
                        continue;

                    if (!strcmp(".", dent->d_name) ||
                        !strcmp("..", dent->d_name))
                        continue;
                    snprintf(fullname, sizeof(fullname) - 1,
                             "%s" PATHSEP "%s", pdir, dent->d_name);
                    dentry_idpart = strchr(dent->d_name, '_');

                    if (!dentry_idpart ||
                        strcmp(filename, dentry_idpart) != 0) {
                        if (!m->ctx->engine->keeptmp)
                            continue;

                        if ((test_fd = open(fullname, O_RDONLY | O_BINARY)) < 0)
                            continue;

                        if (FSTAT(test_fd, &statb) < 0) {
                            close(test_fd);
                            continue;
                        }

                        if (now - statb.st_mtime > (time_t)(7 * 24 * 3600)) {
                            if (cli_unlink(fullname)) {
                                mbox_record_status(
                                    mctx, CL_EUNLINK,
                                    "Partial MIME fragment could not be removed");
                                destroyPartialOutput(fout, outname);
                                free(md5_hex);
                                free(id);
                                free(number);
                                closedir(dd);
                                close(test_fd);
                                return -1;
                            }
                        }

                        close(test_fd);
                        continue;
                    }

                    found_part = true;
                    fin        = fopen(fullname, "rb");
                    if (fin == NULL) {
                        cli_errmsg("Can't open '%s' for reading", fullname);
                        mbox_record_status(
                            mctx, CL_EOPEN,
                            "Partial MIME fragment could not be opened");
                        destroyPartialOutput(fout, outname);
                        free(md5_hex);
                        free(id);
                        free(number);
                        closedir(dd);
                        return -1;
                    }
                    nblanks = 0;
                    while (fgets(buffer, sizeof(buffer) - 1, fin) != NULL)
                        /*
                         * Ensure that trailing newlines
                         * aren't copied
                         */
                        if (buffer[0] == '\n')
                            nblanks++;
                        else {
                            if (nblanks)
                                do {
                                    if (fileblobAddData(fout, (const unsigned char *)"\n", 1) < 0)
                                        break;
                                } while (--nblanks > 0);
                            if (nblanks || fileblobAddData(fout,
                                                            (const unsigned char *)buffer,
                                                            strlen(buffer)) < 0) {
                                mbox_record_fileblob_failure(
                                    mctx, fout, CL_EWRITE,
                                    "MIME partial message reassembly output could not be written");
                                fclose(fin);
                                destroyPartialOutput(fout, outname);
                                free(md5_hex);
                                free(id);
                                free(number);
                                closedir(dd);
                                return -1;
                            }
                        }
                    fin_error       = ferror(fin);
                    fin_close_error = fclose(fin);
                    if (fin_error || fin_close_error != 0) {
                        mbox_record_status(
                            mctx, CL_EREAD,
                            "Partial MIME fragment could not be read completely");
                        destroyPartialOutput(fout, outname);
                        free(md5_hex);
                        free(id);
                        free(number);
                        closedir(dd);
                        return -1;
                    }

                    /* don't unlink if leave temps */
                    if (!m->ctx->engine->keeptmp) {
                        if (cli_unlink(fullname)) {
                            mbox_record_status(
                                mctx, CL_EUNLINK,
                                "Partial MIME fragment could not be removed");
                            destroyPartialOutput(fout, outname);
                            free(md5_hex);
                            free(id);
                            free(number);
                            closedir(dd);
                            return -1;
                        }
                    }
                    break;
                }
                if (!found_part) {
                    mbox_record_status(
                        mctx, CL_EPARSE,
                        "Partial MIME message is missing a numbered fragment");
                    destroyPartialOutput(fout, outname);
                    free(md5_hex);
                    free(id);
                    free(number);
                    closedir(dd);
                    return -1;
                }
                rewinddir(dd);
            }
            if (closedir(dd) != 0) {
                mbox_record_status(
                    mctx, CL_EREAD,
                    "Partial MIME directory could not be closed");
                destroyPartialOutput(fout, outname);
                free(md5_hex);
                free(id);
                free(number);
                return -1;
            }
            {
                int scan_rc = scanFileblob(mctx, fout);

                mctx->files++;
                if (scan_rc != CL_CLEAN && scan_rc != CL_VIRUS) {
                    mbox_record_status(
                        mctx,
                        scan_rc > CL_SUCCESS ? (cl_error_t)scan_rc : CL_EPARSE,
                        "Reassembled partial MIME message could not be scanned completely");
                    cli_unlink(outname);
                }
                free(md5_hex);
                free(id);
                free(number);
                return scan_rc;
            }
        } else if (n == t) {
            cli_mark_scan_incomplete(mctx->ctx,
                                     "Partial MIME directory could not be opened");
        }
    }
    free(number);
    free(id);
    free(md5_hex);

    return 0;
}

static void
hrefs_done(blob *b, tag_arguments_t *hrefs)
{
    if (b)
        blobDestroy(b);
    html_tag_arg_free(hrefs);
}

#define TEXT_URL_MAP_CHUNK (64U * 1024U)

/* Extract text URLs from a file-backed fmap without materializing the entire
 * HTML body. Keep only the current URL and the six bytes needed to recognize
 * http:, https:, and ftp: prefixes across chunk boundaries. */
static bool extract_text_urls_map(cli_ctx *ctx, fmap_t *map, tag_arguments_t *hrefs)
{
    unsigned char buffer[TEXT_URL_MAP_CHUNK];
    char history[sizeof("https:") - 1];
    char url[1024];
    size_t history_len = 0;
    size_t url_len     = 0;
    size_t offset      = 0;

    while (offset < map->len) {
        size_t wanted = MIN((size_t)TEXT_URL_MAP_CHUNK, map->len - offset);
        size_t i;

        if (mbox_check_deadline(ctx)) {
            cli_dbgmsg("HTML phishing URL extraction reached the configured time limit\n");
            return false;
        }

        if (fmap_readn(map, buffer, offset, wanted) != wanted) {
            cli_mark_scan_incomplete(ctx, "HTML phishing input could not be read completely");
            return false;
        }

        for (i = 0; i < wanted; i++) {
            unsigned char c = buffer[i];

            if (url_len) {
                if (c == ' ' || c == '\n' || c == '\t') {
                    url[url_len] = '\0';
                    if (!html_tag_arg_add(hrefs, "href", url)) {
                        cli_mark_scan_incomplete(ctx, "HTML phishing URL state could not be allocated");
                        return false;
                    }
                    url_len     = 0;
                    history_len = 0;
                } else if (url_len < sizeof(url) - 1) {
                    url[url_len++] = (char)c;
                } else {
                    url[url_len] = '\0';
                    if (!html_tag_arg_add(hrefs, "href", url)) {
                        cli_mark_scan_incomplete(ctx, "HTML phishing URL state could not be allocated");
                        return false;
                    }
                    url_len     = 0;
                    history_len = 0;
                }
                continue;
            }

            if (history_len < sizeof(history)) {
                history[history_len++] = (char)c;
            } else {
                memmove(history, history + 1, sizeof(history) - 1);
                history[sizeof(history) - 1] = (char)c;
            }

            if (history_len >= 6 &&
                (history[history_len - 6] | 0x20) == 'h' &&
                (history[history_len - 5] | 0x20) == 't' &&
                (history[history_len - 4] | 0x20) == 't' &&
                (history[history_len - 3] | 0x20) == 'p' &&
                (history[history_len - 2] | 0x20) == 's' && history[history_len - 1] == ':') {
                memcpy(url, history + history_len - 6, 6);
                url_len = 6;
            } else if (history_len >= 5 &&
                       (history[history_len - 5] | 0x20) == 'h' &&
                       (history[history_len - 4] | 0x20) == 't' &&
                       (history[history_len - 3] | 0x20) == 't' &&
                       (history[history_len - 2] | 0x20) == 'p' &&
                       history[history_len - 1] == ':') {
                memcpy(url, history + history_len - 5, 5);
                url_len = 5;
            } else if (history_len >= 4 &&
                       (history[history_len - 4] | 0x20) == 'f' &&
                       (history[history_len - 3] | 0x20) == 't' &&
                       (history[history_len - 2] | 0x20) == 'p' &&
                       history[history_len - 1] == ':') {
                memcpy(url, history + history_len - 4, 4);
                url_len = 4;
            }
        }

        offset += wanted;
    }

    if (mbox_check_deadline(ctx)) {
        cli_dbgmsg("HTML phishing URL extraction reached the configured time limit\n");
        return false;
    }

    if (url_len) {
        url[url_len] = '\0';
        if (!html_tag_arg_add(hrefs, "href", url)) {
            cli_mark_scan_incomplete(ctx, "HTML phishing URL state could not be allocated");
            return false;
        }
    }

    return true;
}

/*
 * This used to be part of checkURLs, split out, because phishingScan needs it
 * too, and phishingScan might be used in situations where checkURLs is
 * disabled (see ifdef)
 */
static blob *
getHrefs(mbox_ctx *mctx, message *m, tag_arguments_t *hrefs, bool *incomplete)
{
    cli_ctx *ctx = mctx->ctx;
    const char *tmpdir = ctx && ctx->this_layer_tmpdir ? ctx->this_layer_tmpdir : NULL;
    fileblob *input    = NULL;
    fmap_t *map        = NULL;
    blob *b            = NULL;
    bool owns_input    = false;
    uint64_t temporary_reserved = 0;
    STATBUF sb;

    if (incomplete)
        *incomplete = false;

    /* A completed raw body spool is already file-backed. Encoded spools and
     * legacy line-list messages are exported to a temporary fileblob so the
     * normalizer still receives decoded bytes without a whole-message blob. */
    if (m && m->body_spool &&
        (messageGetEncoding(m) == NOENCODING || messageGetEncoding(m) == BINARY ||
         messageGetEncoding(m) == EIGHTBIT)) {
        input = m->body_spool;
    } else {
        input      = messageToFileblob(m, tmpdir, 0);
        owns_input = true;
    }

    if (input == NULL || input->isIncomplete || input->fp == NULL || input->fullname == NULL ||
        fflush(input->fp) != 0 || FSTAT(input->fd, &sb) != 0 || sb.st_size < 0 ||
        (uint64_t)sb.st_size > (uint64_t)(size_t)-1) {
        if (input == NULL || input->isIncomplete)
            mbox_record_message_failure(mctx, m,
                                        "HTML phishing input could not be materialized completely");
        cli_mark_scan_incomplete(ctx, "HTML phishing input could not be materialized completely");
        if (incomplete)
            *incomplete = true;
        goto done;
    }

    if (sb.st_size == 0)
        goto done;

    map = fmap_new(input->fd, 0, (size_t)sb.st_size, input->fullname, input->fullname);
    if (map == NULL) {
        cli_mark_scan_incomplete(ctx, "HTML phishing input could not be mapped completely");
        if (incomplete)
            *incomplete = true;
        goto done;
    }

    hrefs->count = 0;
    hrefs->tag = hrefs->value = NULL;
    hrefs->contents           = NULL;

    cli_dbgmsg("getHrefs: calling html_normalise_map\n");
    if (!html_normalise_map_with_quota(ctx, map, tmpdir, hrefs, ctx->dconf, &temporary_reserved)) {
        cli_mark_scan_incomplete(ctx, "HTML phishing input could not be normalized completely");
        if (incomplete)
            *incomplete = true;
        goto done;
    }
    cli_dbgmsg("getHrefs: html_normalise_map returned\n");
    if (!hrefs->count && hrefs->scanContents) {
        if (!extract_text_urls_map(ctx, map, hrefs)) {
            if (incomplete)
                *incomplete = true;
            goto done;
        }
    }

    b = blobCreate();
    if (b == NULL) {
        cli_mark_scan_incomplete(ctx, "HTML phishing result could not be allocated");
        if (incomplete)
            *incomplete = true;
    }

done:
    if (temporary_reserved)
        cli_scan_release_temporary(ctx, temporary_reserved);
    if (map)
        fmap_free(map);
    if (owns_input && input)
        fileblobDestructiveDestroy(input);
    return b;
}

/*
 * validate URLs for phishes
 * followurls: see if URLs point to malware
 */
static void
checkURLs(message *mainMessage, mbox_ctx *mctx, mbox_status *rc, int is_html)
{
    blob *b;
    tag_arguments_t hrefs;
    bool incomplete = false;

    UNUSEDPARAM(is_html);

    if (*rc == VIRUS)
        return;

    hrefs.scanContents = mctx->ctx->engine->dboptions & CL_DB_PHISHING_URLS && (DCONF_PHISHING & PHISHING_CONF_ENGINE);

    if (!hrefs.scanContents)
        /*
         * Don't waste time extracting hrefs (parsing html), nobody
         * will need it
         */
        return;

    hrefs.count = 0;
    hrefs.tag = hrefs.value = NULL;
    hrefs.contents          = NULL;

    b = getHrefs(mctx, mainMessage, &hrefs, &incomplete);
    if (incomplete && *rc == OK)
        *rc = FAIL;
    if (b) {
        if (hrefs.scanContents) {
            if (phishingScan(mctx->ctx, &hrefs) == CL_VIRUS) {
                /*
                 * FIXME: message objects' contents are
                 *    encapsulated so we should not access
                 *    the members directly
                 */
                mainMessage->isInfected = true;
                *rc                     = VIRUS;
                cli_dbgmsg("PH:Phishing found\n");
            }
        }
    }
    hrefs_done(b, &hrefs);
}

#ifdef HAVE_BACKTRACE
static void
sigsegv(int sig)
{
    signal(SIGSEGV, SIG_DFL);
    print_trace(1);
    exit(SIGSEGV);
}

static void
print_trace(int use_syslog)
{
    void *array[10];
    size_t size;
    char **strings;
    size_t i;
    pid_t pid = getpid();

    cli_errmsg("Segmentation fault, attempting to print backtrace\n");

    size    = backtrace(array, 10);
    strings = backtrace_symbols(array, size);

    cli_errmsg("Backtrace of pid %d:\n", pid);
    if (use_syslog)
        syslog(LOG_ERR, "Backtrace of pid %d:", pid);

    for (i = 0; i < size; i++) {
        cli_errmsg("%s\n", strings[i]);
        if (use_syslog)
            syslog(LOG_ERR, "bt[%llu]: %s", (unsigned long long)i, strings[i]);
    }

#ifdef SAVE_TMP
    cli_errmsg("The errant mail file has been saved\n");
#endif
    /* #else TODO: dump the current email */

    free(strings);
}
#endif

/* See also clamav-milter */
static bool
usefulHeader(int commandNumber, const char *cmd)
{
    switch (commandNumber) {
        case CONTENT_TRANSFER_ENCODING:
        case CONTENT_DISPOSITION:
        case CONTENT_TYPE:
            return true;
        default:
            if (strcasecmp(cmd, "From") == 0)
                return true;
            if (strcasecmp(cmd, "Received") == 0)
                return true;
            if (strcasecmp(cmd, "De") == 0)
                return true;
    }

    return false;
}

/*
 * Like fgets but cope with end of line by "\n", "\r\n", "\n\r", "\r"
 */
static char *
getline_from_mbox(char *buffer, size_t buffer_len, fmap_t *map, size_t *at, cli_ctx *ctx,
                  cl_error_t *failure_status, bool reject_unterminated_line)
{
    const char *src, *cursrc;
    char *curbuf;
    size_t i;
    bool line_terminated = false;

    if (mbox_check_deadline(ctx))
        return NULL;

    if (map == NULL || at == NULL || *at > map->len) {
        cli_mark_scan_incomplete(ctx, "MIME message line input range is invalid");
        return NULL;
    }

    size_t input_len = MIN(map->len - *at, buffer_len + 1);
    src = cursrc = fmap_need_off_once(map, *at, input_len);

    /* we check for eof from the result of GETC()
    if(feof(fin))
        return NULL;*/
    if (!src) {
        cli_dbgmsg("getline_from_mbox: fmap need failed\n");
        if (*at < map->len) {
            cli_mark_scan_incomplete(ctx, "MIME message line input could not be read completely");
            if (failure_status)
                *failure_status = CL_EREAD;
        }
        return NULL;
    }
    if ((buffer_len == 0) || (buffer == NULL)) {
        cli_errmsg("Invalid call to getline_from_mbox(). Refer to https://docs.clamav.net/manual/Installing.html\n");
        return NULL;
    }

    curbuf = buffer;

    for (i = 0; i < buffer_len; i++) {
        char c;

        if (!input_len--) {
            if (curbuf == buffer) {
                /* EOF on first char */
                return NULL;
            }
            break;
        }

        switch ((c = *cursrc++)) {
            case '\0':
                continue;
            case '\n':
                *curbuf++ = '\n';
                line_terminated = true;
                if (input_len && *cursrc == '\r') {
                    i++;
                    cursrc++;
                }
                break;
            case '\r':
                *curbuf++ = '\r';
                line_terminated = true;
                if (input_len && *cursrc == '\n') {
                    i++;
                    cursrc++;
                }
                break;
            default:
                *curbuf++ = c;
                continue;
        }
        break;
    }
    *at += cursrc - src;
    *curbuf = '\0';

    if (!line_terminated && *at < map->len) {
        const char *next = fmap_need_off_once(map, *at, 1);

        if (!next) {
            cli_mark_scan_incomplete(ctx, "MIME message line input could not be read completely");
            if (failure_status)
                *failure_status = CL_EREAD;
            return NULL;
        }
        if (reject_unterminated_line && *next != '\n' && *next != '\r') {
            cli_mark_scan_incomplete(ctx, "MIME message line exceeds bounded parser representation");
            return NULL;
        }
    }

    return buffer;
}

/*
 * Is this line a candidate for the start of a bounce message?
 */
static bool
isBounceStart(mbox_ctx *mctx, const char *line)
{
    size_t len;

    if (line == NULL)
        return false;
    if (*line == '\0')
        return false;
    /*if((strncmp(line, "From ", 5) == 0) && !isalnum(line[5]))
        return false;
    if((strncmp(line, ">From ", 6) == 0) && !isalnum(line[6]))
        return false;*/

    len = strlen(line);
    if ((len < 6) || (len >= 72))
        return false;

    if ((memcmp(line, "From ", 5) == 0) ||
        (memcmp(line, ">From ", 6) == 0)) {
        int numSpaces = 0, numDigits = 0;

        line += 4;

        do
            if (*line == ' ')
                numSpaces++;
            else if (isdigit((*line) & 0xFF))
                numDigits++;
        while (*++line != '\0');

        if (numSpaces < 6)
            return false;
        if (numDigits < 11)
            return false;
        return true;
    }
    return (bool)(cli_compare_ftm_file((const unsigned char *)line, len, mctx->ctx->engine) == CL_TYPE_MAIL);
}

/*
 * Extract a binhexEncoded message and preserve the scan result for the mbox
 *    caller.
 */
static mbox_status
exportBinhexMessage(mbox_ctx *mctx, message *m)
{
    fileblob *fb;

    if (messageGetEncoding(m) == NOENCODING)
        messageSetEncoding(m, "x-binhex");

    fb = messageToFileblob(m, mctx->dir, 0);

    if (fb) {
        cli_dbgmsg("Binhex file decoded to %s\n",
                   fileblobGetFilename(fb));

        {
            const int scan_rc = scanFileblob(mctx, fb);

            if (scan_rc == CL_VIRUS)
                return VIRUS;
            if (scan_rc != CL_CLEAN)
                return FAIL;
        }
        mctx->files++;
    } else {
        cli_errmsg("Couldn't decode binhex file to %s\n", mctx->dir);
        mbox_record_message_failure(mctx, m,
                                    "BinHex mail attachment could not be materialized");
        cli_mark_scan_incomplete(mctx->ctx,
                                 "BinHex mail attachment could not be materialized");
        return FAIL;
    }

    return OK;
}

/*
 * Locate any bounce message and extract it. Return cl_status
 */
static int
exportBounceMessage(mbox_ctx *mctx, text *start)
{
    int rc = CL_CLEAN;
    text *t;
    fileblob *fb;

    /*
     * Attempt to save the original (unbounced)
     * message - clamscan will find that in the
     * directory and call us again (with any luck)
     * having found an e-mail message to handle.
     *
     * This finds a lot of false positives, the
     * search that a content type is in the
     * bounce (i.e. it's after the bounce header)
     * helps a bit.
     *
     * messageAddLine
     * optimization could help here, but needs
     * careful thought, do it with line numbers
     * would be best, since the current method in
     * messageAddLine of checking encoding first
     * must remain otherwise non bounce messages
     * won't be scanned
     */
    for (t = start; t; t = t->t_next) {
        const char *txt = lineGetData(t->t_line);
        char cmd[RFC2821LENGTH + 1];

        if (txt == NULL)
            continue;
        if (cli_strtokbuf(txt, 0, ":", cmd) == NULL)
            continue;

        switch (tableFind(mctx->rfc821Table, cmd)) {
            case CONTENT_TRANSFER_ENCODING:
                if ((strstr(txt, "7bit") == NULL) &&
                    (strstr(txt, "8bit") == NULL))
                    break;
                continue;
            case CONTENT_DISPOSITION:
                break;
            case CONTENT_TYPE:
                if (strstr(txt, "text/plain") != NULL)
                    t = NULL;
                break;
            default:
                if (strcasecmp(cmd, "From") == 0)
                    start = t;
                else if (strcasecmp(cmd, "Received") == 0)
                    start = t;
                continue;
        }
        break;
    }
    if (t && ((fb = fileblobCreate()) != NULL)) {
        cli_dbgmsg("Found a bounce message\n");
        fileblobSetFilename(fb, mctx->dir, "bounce");
        fileblobSetCTX(fb, mctx->ctx);
        if (textToFileblob(start, fb, 1) == NULL) {
            cli_dbgmsg("Nothing new to save in the bounce message\n");
            fileblobDestroy(fb);
        } else
            rc = scanFileblob(mctx, fb);
        mctx->files++;
    } else
        cli_dbgmsg("Not found a bounce message\n");

    return rc;
}

/*
 * Get string representation of mimetype
 */
static const char *getMimeTypeStr(mime_type mimetype)
{
    const struct tableinit *entry = mimeTypeStr;

    while (entry->key) {
        if (mimetype == ((mime_type)entry->value)) {
            return entry->key;
        }
        entry++;
    }
    return "UNKNOWN";
}

/*
 * Get string representation of encoding type
 */
static const char *getEncTypeStr(encoding_type enctype)
{
    const struct tableinit *entry = encTypeStr;

    while (entry->key) {
        if (enctype == ((encoding_type)entry->value)) {
            return entry->key;
        }
        entry++;
    }
    return "UNKNOWN";
}

/*
 * Handle the ith element of a number of multiparts, e.g. multipart/alternative
 */
static message *
do_multipart(message *mainMessage, message **messages, int i, mbox_status *rc, mbox_ctx *mctx, message *messageIn, text **tptr, unsigned int recursion_level)
{
    bool addToText = false;
    const char *dtype;
#ifndef SAVE_TO_DISC
    message *body;
#endif
    message *aMessage        = messages[i];
    const int doPhishingScan = mctx->ctx->engine->dboptions & CL_DB_PHISHING_URLS && (DCONF_PHISHING & PHISHING_CONF_ENGINE);
    json_object *thisobj     = NULL;
    json_object *saveobj     = mctx->wrkobj;
    mbox_status metadata_rc  = OK;

    if (mctx->wrkobj != NULL) {
        json_object *multiobj = cli_jsonarray(mctx->wrkobj, "Multipart");
        if (multiobj == NULL) {
            cli_errmsg("Cannot get multipart preclass array\n");
            mbox_record_json_failure(mctx, &metadata_rc,
                                     "MIME multipart metadata array could not be allocated");
        } else if (NULL == (thisobj = cli_jsonobj(NULL, NULL))) {
            cli_dbgmsg("Cannot allocate new json object for message part.\n");
            mbox_record_json_failure(mctx, &metadata_rc,
                                     "MIME multipart message metadata object could not be allocated");
        } else if (json_object_array_add(multiobj, thisobj) != 0) {
            json_object_put(thisobj);
            thisobj = NULL;
            mbox_record_json_failure(mctx, &metadata_rc,
                                     "MIME multipart metadata array entry could not be recorded");
        }
    }

    if (aMessage == NULL) {
        if (thisobj != NULL)
            mbox_record_json_status(mctx, &metadata_rc,
                                    cli_jsonstr(thisobj, "MimeType", "NULL"),
                                    "MIME multipart null-part metadata could not be recorded");
        mbox_merge_json_status(rc, metadata_rc);
        return mainMessage;
    }

    if (*rc != OK) {
        mbox_merge_json_status(rc, metadata_rc);
        return mainMessage;
    }

    if (aMessage->isTruncated) {
        cli_mark_scan_incomplete(mctx->ctx,
                                 "MIME part text materialization was truncated");
        *rc = FAIL;
        return mainMessage;
    }

    cli_dbgmsg("Mixed message part %d is of type %d\n",
               i, messageGetMimeType(aMessage));

    if (thisobj != NULL) {
        mbox_record_json_status(mctx, &metadata_rc,
                                cli_jsonstr(thisobj, "MimeType", getMimeTypeStr(messageGetMimeType(aMessage))),
                                "MIME multipart type metadata could not be recorded");
        mbox_record_json_status(mctx, &metadata_rc,
                                cli_jsonstr(thisobj, "MimeSubtype", messageGetMimeSubtype(aMessage)),
                                "MIME multipart subtype metadata could not be recorded");
        mbox_record_json_status(mctx, &metadata_rc,
                                cli_jsonstr(thisobj, "EncodingType", getEncTypeStr(messageGetEncoding(aMessage))),
                                "MIME multipart encoding metadata could not be recorded");
        mbox_record_json_status(mctx, &metadata_rc,
                                cli_jsonstr(thisobj, "Disposition", messageGetDispositionType(aMessage)),
                                "MIME multipart disposition metadata could not be recorded");
        if (messageHasFilename(aMessage)) {
            char *filename = messageGetFilename(aMessage);
            mbox_record_json_status(mctx, &metadata_rc,
                                    cli_jsonstr(thisobj, "Filename", filename),
                                    "MIME multipart filename metadata could not be recorded");
            free(filename);
        } else {
            mbox_record_json_status(mctx, &metadata_rc,
                                    cli_jsonstr(thisobj, "Filename", "(inline)"),
                                    "MIME multipart filename metadata could not be recorded");
        }
    }

    switch (messageGetMimeType(aMessage)) {
        case APPLICATION:
        case AUDIO:
        case IMAGE:
        case VIDEO:
            break;
        case NOMIME:
            cli_dbgmsg("No mime headers found in multipart part %d\n", i);
            if (mainMessage) {
                if (binhexBegin(aMessage)) {
                    cli_dbgmsg("Found binhex message in multipart/mixed mainMessage\n");

                    {
                        const mbox_status binhex_rc = exportBinhexMessage(mctx, mainMessage);

                        if (binhex_rc == VIRUS)
                            *rc = VIRUS;
                        else if (binhex_rc != OK)
                            *rc = FAIL;
                    }
                }
                if (mainMessage != messageIn)
                    messageDestroy(mainMessage);
                mainMessage = NULL;
            } else if (aMessage) {
                if (binhexBegin(aMessage)) {
                    cli_dbgmsg("Found binhex message in multipart/mixed non mime part\n");
                    {
                        const mbox_status binhex_rc = exportBinhexMessage(mctx, aMessage);

                        if (binhex_rc == VIRUS)
                            *rc = VIRUS;
                        else if (binhex_rc != OK)
                            *rc = FAIL;
                    }
                    messageReset(messages[i]);
                }
            }
            addToText = true;
            if (messageGetBody(aMessage) == NULL)
                /*
                 * No plain text version
                 */
                cli_dbgmsg("No plain text alternative\n");
            break;
        case TEXT:
            dtype = messageGetDispositionType(aMessage);
            cli_dbgmsg("Mixed message text part disposition \"%s\"\n",
                       dtype);
            if (strcasecmp(dtype, "attachment") == 0)
                break;
            if ((*dtype == '\0') || (strcasecmp(dtype, "inline") == 0)) {
                const char *cptr;

                if (mainMessage && (mainMessage != messageIn))
                    messageDestroy(mainMessage);
                mainMessage = NULL;
                cptr        = messageGetMimeSubtype(aMessage);
                cli_dbgmsg("Mime subtype \"%s\"\n", cptr);
                if ((tableFind(mctx->subtypeTable, cptr) == PLAIN) &&
                    (messageGetEncoding(aMessage) == NOENCODING)) {
                    /*
                     * Strictly speaking, a text/plain part
                     * is not an attachment. We pretend it
                     * is so that we can decode and scan it
                     */
                    if (!messageHasFilename(aMessage)) {
                        cli_dbgmsg("Adding part to main message\n");
                        addToText = true;
                    } else
                        cli_dbgmsg("Treating inline as attachment\n");
                } else {
                    const int is_html = (tableFind(mctx->subtypeTable, cptr) == HTML);
                    if (doPhishingScan)
                        checkURLs(aMessage, mctx, rc, is_html);
                    messageAddArgument(aMessage,
                                       "filename=mixedtextportion");
                }
                break;
            }
            cli_dbgmsg("Text type %s is not supported\n", dtype);
            mbox_merge_json_status(rc, metadata_rc);
            return mainMessage;
        case MESSAGE:
            /* Content-Type: message/rfc822 */
            cli_dbgmsg("Found message inside multipart (encoding type %d)\n",
                       messageGetEncoding(aMessage));
#ifndef SCAN_UNENCODED_BOUNCES
            switch (messageGetEncoding(aMessage)) {
                case NOENCODING:
                case EIGHTBIT:
                case BINARY:
                    if (encodingLine(aMessage) == NULL) {
                        /*
                         * This means that the message
                         * has no attachments
                         *
                         * The test for
                         * messageGetEncoding is needed
                         * since encodingLine won't have
                         * been set if the message
                         * itself has been encoded
                         */
                        cli_dbgmsg("Unencoded multipart/message will not be scanned\n");
                        messageDestroy(messages[i]);
                        messages[i] = NULL;
                        mbox_merge_json_status(rc, metadata_rc);
                        return mainMessage;
                    }
                    /* FALLTHROUGH */
                default:
                    cli_dbgmsg("Encoded multipart/message will be scanned\n");
            }
#endif

#ifdef SAVE_TO_DISC
            /*
             * Save this embedded message
             * to a temporary file
             */
            {
                int scan_rc = saveTextPart(mctx, aMessage, 1);
                if (scan_rc == CL_VIRUS)
                    *rc = VIRUS;
                else if (scan_rc != CL_CLEAN)
                    *rc = FAIL;
            }
            messageDestroy(messages[i]);
            messages[i] = NULL;
#else
            /*
             * Scan in memory, faster but is open to DoS attacks
             * when many nested levels are involved.
             */
            body = parseEmailHeaders(aMessage, mctx->rfc821Table);

            /*
             * We've finished with the
             * original copy of the message,
             * so throw that away and
             * deal with the encapsulated
             * message as a message.
             * This can save a lot of memory
             */
            messageDestroy(messages[i]);
            messages[i]  = NULL;
            mctx->wrkobj = thisobj;

            if (body) {
                messageSetCTX(body, mctx->ctx);
                *rc = parseEmailBody(body, NULL, mctx, recursion_level + 1);
                if ((*rc == OK) && messageContainsVirus(body))
                    *rc = VIRUS;
                messageDestroy(body);
            }

            mctx->wrkobj = saveobj;
#endif
            mbox_merge_json_status(rc, metadata_rc);
            return mainMessage;
        case MULTIPART:
            /*
             * It's a multi part within a multi part
             * Run the message parser on this bit, it won't
             * be an attachment
             */
            cli_dbgmsg("Found multipart inside multipart\n");
            mctx->wrkobj = thisobj;

            if (aMessage) {
                /*
                 * The headers were parsed when reading in the
                 * whole multipart section
                 */
                *rc = parseEmailBody(aMessage, *tptr, mctx, recursion_level + 1);
                cli_dbgmsg("Finished recursion, rc = %d\n", (int)*rc);
                messageDestroy(messages[i]);
                messages[i] = NULL;
            } else {
                *rc = parseEmailBody(NULL, NULL, mctx, recursion_level + 1);
                if (mainMessage && (mainMessage != messageIn)) {
                    messageDestroy(mainMessage);
                }
                mainMessage = NULL;
            }

            mctx->wrkobj = saveobj;

            mbox_merge_json_status(rc, metadata_rc);
            return mainMessage;
        default:
            cli_dbgmsg("Only text and application attachments are fully supported, type = %d\n",
                       messageGetMimeType(aMessage));
            /* fall through - we may be able to salvage something */
    }

    if (*rc != VIRUS) {
        fileblob *fb = messageToFileblob(aMessage, mctx->dir, 1);

        if (fb == NULL)
            mbox_record_message_failure(mctx, aMessage,
                                        "MIME attachment could not be materialized completely");

        json_object *arrobj;
#if (JSON_C_MAJOR_VERSION == 0) && (JSON_C_MINOR_VERSION < 13)
        int arrlen = 0;
#else
        size_t arrlen = 0;
#endif

        if (thisobj != NULL) {
            /* attempt to determine container size - prevents incorrect type reporting */
            if (json_object_object_get_ex(mctx->ctx->this_layer_metadata_json, "ContainedObjects", &arrobj)) {
                arrlen = json_object_array_length(arrobj);
            }
        }

        if (fb) {
            /* aMessage doesn't always have a ctx set */
            fileblobSetCTX(fb, mctx->ctx);
        }

        {
            int scan_rc = scanFileblob(mctx, fb);

            if (scan_rc == CL_VIRUS) {
                *rc = VIRUS;
            } else if (scan_rc != CL_CLEAN) {
                *rc = FAIL;
            }
        }

        if (fb) {
            /* aMessage doesn't always have a ctx set */
            if (!addToText) {
                mctx->files++;
            }
        }

        if (thisobj != NULL) {
            json_object *entry = NULL;
            const char *dtype  = NULL;

            /* attempt to acquire container type */
            if (json_object_object_get_ex(mctx->ctx->this_layer_metadata_json, "ContainedObjects", &arrobj)) {
                if (json_object_array_length(arrobj) > arrlen) {
                    entry = json_object_array_get_idx(arrobj, arrlen);
                }
            }
            if (entry) {
                json_object_object_get_ex(entry, "FileType", &entry);
                if (entry) {
                    dtype = json_object_get_string(entry);
                }
            }
            mbox_record_json_status(mctx, &metadata_rc,
                                    cli_jsonint(thisobj, "ContainedObjectsIndex", (int32_t)arrlen),
                                    "MIME multipart contained-object index metadata could not be recorded");
            mbox_record_json_status(mctx, &metadata_rc,
                                    cli_jsonstr(thisobj, "ClamAVFileType", dtype ? dtype : "UNKNOWN"),
                                    "MIME multipart contained-object type metadata could not be recorded");
        }

        if (messageContainsVirus(aMessage)) {
            *rc = VIRUS;
        }
    }
    messageDestroy(aMessage);
    messages[i] = NULL;

    mbox_merge_json_status(rc, metadata_rc);
    return mainMessage;
}

/*
 * Returns the number of quote characters in the given string
 */
static int
count_quotes(const char *buf)
{
    int quotes = 0;

    while (*buf)
        if (*buf++ == '\"')
            quotes++;

    return quotes;
}

/*
 * Will the next line be a folded header? See RFC2822 section 2.2.3
 */
static bool
next_is_folded_header(const text *t)
{
    const text *next = t->t_next;
    const char *data, *ptr;

    if (next == NULL)
        return false;

    if (next->t_line == NULL)
        return false;

    data = lineGetData(next->t_line);

    /*
     * Section B.2 of RFC822 says TAB or SPACE means a continuation of the
     * previous entry.
     */
    if (isblank(data[0]))
        return true;

    if (strchr(data, '=') == NULL)
        /*
         * Avoid false positives with
         *    Content-Type: text/html;
         *    Content-Transfer-Encoding: quoted-printable
         */
        return false;

    /*
     * Some are broken and don't fold headers lines
     * correctly as per section 2.2.3 of RFC2822.
     * Generally they miss the white space at
     * the start of the fold line:
     *    Content-Type: multipart/related;
     *    type="multipart/alternative";
     *    boundary="----=_NextPart_000_006A_01C6AC47.348CB550"
     * should read:
     *    Content-Type: multipart/related;
     *     type="multipart/alternative";
     *     boundary="----=_NextPart_000_006A_01C6AC47.348CB550"
     * Since we're a virus checker not an RFC
     * verifier we need to handle these
     */
    data = lineGetData(t->t_line);

    ptr = strchr(data, '\0');

    while (--ptr > data)
        switch (*ptr) {
            case ';':
                return true;
            case '\n':
            case ' ':
            case '\r':
            case '\t':
                continue; /* white space at end of line */
            default:
                return false;
        }
    return false;
}

/*
 * This routine is called on the first line of the body of
 * an email to handle broken messages that have newlines
 * in the middle of its headers
 */
static bool
newline_in_header(const char *line)
{
    cli_dbgmsg("newline_in_header, check \"%s\"\n", line);

    if (strncmp(line, "Message-Id: ", 12) == 0)
        return true;
    if (strncmp(line, "Date: ", 6) == 0)
        return true;

    cli_dbgmsg("newline_in_header, returning \"%s\"\n", line);

    return false;
}
