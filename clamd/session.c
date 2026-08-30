/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm, Török Edvin
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
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#include <dirent.h>
#ifndef _WIN32
#include <sys/socket.h>
#include <arpa/inet.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#ifdef HAVE_FD_PASSING
#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif
#endif

#include <sys/time.h>
#endif
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <stddef.h>
#include <limits.h>

// libclamav
#include "clamav.h"
#include "str.h"
#include "others.h"
#include "scan_report.h"

// common
#include "optparser.h"
#include "output.h"
#include "misc.h"

#include "clamd_others.h"
#include "scanner.h"
#include "server.h"
#include "session.h"
#include "thrmgr.h"
#include "clamdcom.h"

#ifndef HAVE_FD_PASSING
#define FEATURE_FDPASSING 0
#else
#define FEATURE_FDPASSING 1
#endif

static struct {
    const char *cmd;
    const size_t len;
    enum commands cmdtype;
    int need_arg;
    int support_old;
    int enabled;
} commands[] = {
    /* Report commands must precede their legacy prefixes (SCAN, CONTSCAN,
     * MULTISCAN, and ALLMATCHSCAN). */
    {CMD25, sizeof(CMD25) - 1, COMMAND_SCANREPORT, 1, 0, 1},
    {CMD26, sizeof(CMD26) - 1, COMMAND_CONTSCANREPORT, 1, 0, 1},
    {CMD27, sizeof(CMD27) - 1, COMMAND_MULTISCANREPORT, 1, 0, 1},
    {CMD28, sizeof(CMD28) - 1, COMMAND_ALLMATCHSCANREPORT, 1, 0, 1},
    {CMD29, sizeof(CMD29) - 1, COMMAND_FILDESREPORT, 0, 0, FEATURE_FDPASSING},
    {CMD30, sizeof(CMD30) - 1, COMMAND_INSTREAMREPORT, 0, 0, 1},
    {CMD1, sizeof(CMD1) - 1, COMMAND_SCAN, 1, 1, 0},
    {CMD3, sizeof(CMD3) - 1, COMMAND_SHUTDOWN, 0, 1, 0},
    {CMD4, sizeof(CMD4) - 1, COMMAND_RELOAD, 0, 1, 0},
    {CMD5, sizeof(CMD5) - 1, COMMAND_PING, 0, 1, 0},
    {CMD6, sizeof(CMD6) - 1, COMMAND_CONTSCAN, 1, 1, 0},
    /* must be before VERSION, because they share common prefix! */
    {CMD18, sizeof(CMD18) - 1, COMMAND_COMMANDS, 0, 0, 1},
    {CMD7, sizeof(CMD7) - 1, COMMAND_VERSION, 0, 1, 1},
    {CMD10, sizeof(CMD10) - 1, COMMAND_END, 0, 0, 1},
    {CMD11, sizeof(CMD11) - 1, COMMAND_SHUTDOWN, 0, 1, 1},
    {CMD13, sizeof(CMD13) - 1, COMMAND_MULTISCAN, 1, 1, 1},
    {CMD14, sizeof(CMD14) - 1, COMMAND_FILDES, 0, 1, FEATURE_FDPASSING},
    {CMD15, sizeof(CMD15) - 1, COMMAND_STATS, 0, 0, 1},
    {CMD16, sizeof(CMD16) - 1, COMMAND_IDSESSION, 0, 0, 1},
    {CMD17, sizeof(CMD17) - 1, COMMAND_INSTREAM, 0, 0, 1},
    {CMD19, sizeof(CMD19) - 1, COMMAND_DETSTATSCLEAR, 0, 1, 1},
    {CMD20, sizeof(CMD20) - 1, COMMAND_DETSTATS, 0, 1, 1},
    {CMD21, sizeof(CMD21) - 1, COMMAND_ALLMATCHSCAN, 1, 0, 1}};

enum commands parse_command(const char *cmd, const char **argument, int oldstyle)
{
    size_t i;
    *argument = NULL;
    for (i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
        const size_t len = commands[i].len;
        if (!strncmp(cmd, commands[i].cmd, len)) {
            const char *arg = cmd + len;
            if (commands[i].need_arg) {
                if (!*arg) { /* missing argument */
                    logg(LOGG_DEBUG_NV, "Command %s missing argument!\n", commands[i].cmd);
                    return COMMAND_UNKNOWN;
                }
                *argument = arg + 1;
            } else {
                if (*arg) { /* extra stuff after command */
                    logg(LOGG_DEBUG_NV, "Command %s has trailing garbage!\n", commands[i].cmd);
                    return COMMAND_UNKNOWN;
                }
                *argument = NULL;
            }
            if (oldstyle && !commands[i].support_old) {
                logg(LOGG_DEBUG_NV, "Command sent as old-style when not supported: %s\n", commands[i].cmd);
                return COMMAND_UNKNOWN;
            }
            return commands[i].cmdtype;
        }
    }
    return COMMAND_UNKNOWN;
}

int conn_reply_single(const client_conn_t *conn, const char *path, const char *status)
{
    if (conn->structured_report)
        return 0;

    if (conn->id) {
        if (path)
            return mdprintf(conn->sd, "%u: %s: %s%c", conn->id, path, status, conn->term);
        return mdprintf(conn->sd, "%u: %s%c", conn->id, status, conn->term);
    }
    if (path)
        return mdprintf(conn->sd, "%s: %s%c", path, status, conn->term);
    return mdprintf(conn->sd, "%s%c", status, conn->term);
}

int conn_reply(const client_conn_t *conn, const char *path,
               const char *msg, const char *status)
{
    if (conn->structured_report)
        return 0;

    if (conn->id) {
        if (path)
            return mdprintf(conn->sd, "%u: %s: %s %s%c", conn->id, path, msg,
                            status, conn->term);
        return mdprintf(conn->sd, "%u: %s %s%c", conn->id, msg, status,
                        conn->term);
    }
    if (path)
        return mdprintf(conn->sd, "%s: %s %s%c", path, msg, status, conn->term);
    return mdprintf(conn->sd, "%s %s%c", msg, status, conn->term);
}

int conn_reply_virus(const client_conn_t *conn, const char *file,
                     const char *virname)
{
    if (conn->structured_report)
        return 0;

    if (conn->id) {
        return mdprintf(conn->sd, "%u: %s: %s FOUND%c", conn->id, file, virname,
                        conn->term);
    }
    return mdprintf(conn->sd, "%s: %s FOUND%c", file, virname, conn->term);
}

int conn_reply_error(const client_conn_t *conn, const char *msg)
{
    return conn_reply(conn, NULL, msg, "ERROR");
}

#define BUFFSIZE 1024
int conn_reply_errno(const client_conn_t *conn, const char *path,
                     const char *msg)
{
    char err[BUFFSIZE + sizeof(". ERROR")];
    cli_strerror(errno, err, BUFFSIZE - 1);
    strcat(err, ". ERROR");
    return conn_reply(conn, path, msg, err);
}

/* Send only non-sensitive completion data.  The frame is deliberately
 * independent of the legacy text protocol: a 32-bit network-order length,
 * one JSON object, then a zero-length terminator frame. */
int conn_reply_scan_report(const client_conn_t *conn, cl_error_t status, int infected)
{
    char fallback[1024];
    char id_prefix[64];
    char *serialized = NULL;
    char *json       = NULL;
    const char *payload;
    cl_error_t fallback_status;
    uint32_t length;
    uint32_t network_length;
    uint32_t terminator = 0;
    int json_length;
    int use_fallback    = 1;
    int fallback_infected;
    int fallback_verdict;

    if (!conn)
        return -1;

    /* The scanner can finish its report before a daemon-side close,
     * aggregation, or transport step reports an error. Do not serialize a
     * clean COMPLETE report after that later failure. Detection remains
     * authoritative, and cli_scan_report_note_post_scan_failure() preserves
     * an already non-complete or detection-terminated report. */
    if (conn->structured_scan_report) {
        cl_error_t report_status = status;

        if (infected && report_status == CL_SUCCESS)
            report_status = CL_VIRUS;
        if (report_status != CL_SUCCESS && report_status != CL_VERIFIED)
            cli_scan_report_note_post_scan_failure(conn->structured_scan_report,
                                                   report_status,
                                                   "daemon scan completion reported a non-success status");
    }

    /* Prefer the same versioned report emitted by the public *_ex2 API.  The
     * clamd protocol adds the request id at the front because the library
     * report deliberately has no transport-specific fields. */
    if (conn->structured_scan_report &&
        cl_scan_report_to_json(conn->structured_scan_report, &serialized) == CL_SUCCESS &&
        serialized && serialized[0] == '{') {
        int prefix_length        = snprintf(id_prefix, sizeof(id_prefix), "{\"id\":%u,", conn->id);
        size_t serialized_length = strlen(serialized);

        /* Keep the producer bound identical to the clamd clients.  The
         * length-prefixed wire field is 32-bit, but accepting an arbitrary
         * serialized report here could still allocate or narrow an oversized
         * JSON payload before the client has a chance to reject it. */
        if (prefix_length >= 0 && (size_t)prefix_length < sizeof(id_prefix) && serialized_length >= 2 &&
            (size_t)prefix_length <= CLAMD_SCAN_REPORT_MAX_FRAME &&
            serialized_length - 1U <= CLAMD_SCAN_REPORT_MAX_FRAME - (size_t)prefix_length) {
            json = (char *)malloc((size_t)prefix_length + serialized_length);
            if (json) {
                memcpy(json, id_prefix, (size_t)prefix_length);
                memcpy(json + prefix_length, serialized + 1, serialized_length);
                json_length  = (int)((size_t)prefix_length + serialized_length - 1);
                payload      = json;
                use_fallback = 0;
            }
        }
    }

    if (use_fallback) {
        /* A missing report is itself an incomplete result. Never turn a
         * successful scan into a clean answer merely because report
         * serialization or its transport buffer could not be allocated. */
        fallback_infected = infected || status == CL_VIRUS;
        fallback_status   = status;
        if (fallback_infected && fallback_status == CL_SUCCESS)
            fallback_status = CL_VIRUS;
        else if (!fallback_infected && fallback_status == CL_SUCCESS)
            fallback_status = CL_EMEM;
        fallback_verdict = fallback_infected ? CL_VERDICT_STRONG_INDICATOR
                                              : CL_VERDICT_NOTHING_FOUND;
        free(json);
        json        = NULL;
        json_length = snprintf(fallback, sizeof(fallback),
                               "{\"version\":1,\"id\":%u,\"status\":%d,\"verdict\":%d,\"completion\":\"%s\","
                               "\"file_type\":\"CL_TYPE_BINARY_DATA\",\"root_size\":0,\"logical_bytes\":0,"
                               "\"matcher_bytes\":0,\"contiguous_bytes\":0,\"temporary_bytes\":0,"
                               "\"files_scanned\":0,\"max_recursion_depth\":0,\"elapsed_ms\":0,"
                               "\"parser_operations\":0,\"detector_operations\":0,\"skipped_operations\":1,"
                               "\"max_file_size\":0,\"max_scan_size\":0,\"max_pcre_file_size\":0,"
                               "\"max_matcher_work\":0,\"max_temporary_size\":0,\"max_contiguous_size\":0,"
                               "\"max_scan_time\":0,\"max_files\":0,\"max_recursion\":0,"
                               "\"reason\":\"structured scan report unavailable\"}",
                               conn->id, (int)fallback_status, fallback_verdict,
                               clamd_scan_report_completion(fallback_status, fallback_infected));
        if (json_length < 0 || (size_t)json_length >= sizeof(fallback))
            goto done;
        payload = fallback;
    }

    length         = (uint32_t)json_length;
    network_length = htonl(length);
    if (cli_writen(conn->sd, &network_length, sizeof(network_length)) != sizeof(network_length) ||
        cli_writen(conn->sd, payload, length) != length ||
        cli_writen(conn->sd, &terminator, sizeof(terminator)) != sizeof(terminator))
        goto done;

    json_length = 0;

done:
    free(serialized);
    free(json);
    return json_length == 0 ? 0 : -1;
}

/* returns
 *  -1 on fatal error (shutdown)
 *  0 on ok
 *  >0 errors encountered
 */
int command(client_conn_t *conn, int *virus)
{
    int desc                 = conn->sd;
    struct cl_engine *engine = conn->engine;
    struct cl_scan_options options;
    const struct optstruct *opts = conn->opts;
    enum scan_type type          = TYPE_INIT;
    int maxdirrec;
    int ret   = 0;
    int flags = CLI_FTW_STD;

    memcpy(&options, conn->options, sizeof(struct cl_scan_options));

    struct scan_cb_data scandata;
    struct cli_ftw_cbdata data;
    unsigned ok, error, total;
    STATBUF sb;
    jobgroup_t *group = NULL;

    if (thrmgr_group_need_terminate(conn->group)) {
        logg(LOGG_DEBUG_NV, "Client disconnected while command was active\n");
        if (conn->scanfd != -1)
            close(conn->scanfd);
        return 1;
    }
    thrmgr_setactiveengine(engine);

    data.data = &scandata;
    memset(&scandata, 0, sizeof(scandata));
    scandata.id            = conn->id;
    scandata.group         = conn->group;
    scandata.odesc         = desc;
    scandata.conn          = conn;
    scandata.options       = &options;
    scandata.engine        = engine;
    scandata.opts          = opts;
    scandata.thr_pool      = conn->thrpool;
    scandata.toplevel_path = conn->filename;

    switch (conn->cmdtype) {
        case COMMAND_SCAN:
            thrmgr_setactivetask(NULL, "SCAN");
            type = TYPE_SCAN;
            break;
        case COMMAND_CONTSCAN:
            thrmgr_setactivetask(NULL, "CONTSCAN");
            type = TYPE_CONTSCAN;
            break;
        case COMMAND_MULTISCAN: {
            int multiscan, max, alive;

            /* use MULTISCAN only for directories (bb #1869) */
            if (CLAMSTAT(conn->filename, &sb) == 0 &&
                !S_ISDIR(sb.st_mode)) {
                thrmgr_setactivetask(NULL, "CONTSCAN");
                type = TYPE_CONTSCAN;
                break;
            }

            pthread_mutex_lock(&conn->thrpool->pool_mutex);
            multiscan = conn->thrpool->thr_multiscan;
            max       = conn->thrpool->thr_max;
            if (max <= 1) {
                /* With one worker, MULTISCAN has no parallel work to
                 * schedule. Run the directory through the ordinary
                 * sequential walker instead of rejecting a valid request. */
                pthread_mutex_unlock(&conn->thrpool->pool_mutex);
                thrmgr_setactivetask(NULL, "CONTSCAN");
                type = TYPE_CONTSCAN;
                break;
            } else if (multiscan + 1 < max)
                conn->thrpool->thr_multiscan = multiscan + 1;
            else {
                alive = conn->thrpool->thr_alive;
                ret   = -1;
            }
            pthread_mutex_unlock(&conn->thrpool->pool_mutex);
            if (ret) {
                /* multiscan has 1 control thread, so there needs to be at least
                   1 threads that is a non-multiscan controlthread to scan and
                   make progress. */
                logg(LOGG_WARNING, "Not enough threads for multiscan. Max: %d, Alive: %d, Multiscan: %d+1\n",
                     max, alive, multiscan);
                conn_reply(conn, conn->filename, "Not enough threads for multiscan. Increase MaxThreads.", "ERROR");
                return 1;
            }
            flags &= ~CLI_FTW_NEED_STAT;
            thrmgr_setactivetask(NULL, "MULTISCAN");
            type           = TYPE_MULTISCAN;
            scandata.group = group = thrmgr_group_new();
            if (!group) {
                if (optget(opts, "ExitOnOOM")->enabled)
                    return -1;
                else
                    return 1;
            }
            if (conn->structured_report)
                conn->structured_report_group = group;
            break;
        }
        case COMMAND_MULTISCANFILE: {
            char *scan_filename    = conn->filename;
            char *display_filename = (NULL != conn->display_filename) ? conn->display_filename : conn->filename;

            thrmgr_setactivetask(NULL, "MULTISCANFILE");
            scandata.group    = NULL;
            scandata.type     = TYPE_SCAN;
            scandata.thr_pool = NULL;
            /* TODO: check ret value */
            ret = scan_callback(NULL, display_filename, scan_filename, visit_file, &data); /* callback freed display_filename */
            if (scan_filename != display_filename) {
                free(scan_filename);
            }
            conn->filename         = NULL;
            conn->display_filename = NULL;
            *virus                 = scandata.infected_files;
            if (ret == CL_EMEM && optget(opts, "ExitOnOOM")->enabled)
                return -1;
            if (ret == CL_BREAK) {
                thrmgr_group_terminate(conn->group);
                return 1;
            }
            /* scan_callback records ordinary parser/limit/read failures in
             * scandata.errors. Preserve an unexpected non-success result as
             * an error too, rather than allowing a worker to report success
             * with no infected file. */
            if (ret != CL_SUCCESS && ret != CL_VIRUS && scandata.errors == 0)
                scandata.errors++;
            return scandata.errors > 0 ? scandata.errors : 0;
        }
        case COMMAND_FILDES:
            thrmgr_setactivetask(NULL, "FILDES");
#ifdef HAVE_FD_PASSING
            if (conn->scanfd == -1) {
                conn_reply_error(conn, "FILDES: didn't receive file descriptor.");
                return 1;
            } else {
                ret = scanfd(conn, NULL, engine, &options, opts, desc, 0);
                if (ret == CL_VIRUS) {
                    *virus = 1;
                    ret    = 0;
                } else if (ret == CL_EMEM) {
                    if (optget(opts, "ExitOnOOM")->enabled)
                        ret = -1;
                    else
                        ret = 1;
                } else if (ret == CL_ETIMEOUT) {
                    thrmgr_group_terminate(conn->group);
                    ret = 1;
                } else if (ret != CL_SUCCESS) {
                    /* scanfd() has already emitted the legacy error reply.
                     * Preserve the non-clean result for the command worker
                     * and IDSESSION aggregate instead of turning parser,
                     * limit, or I/O failures into successful completion. */
                    ret = 1;
                } else
                    ret = 0;
                logg(LOGG_DEBUG_NV, "Closed fd %d\n", conn->scanfd);
                close(conn->scanfd);
            }
            return ret;
#else
            conn_reply_error(conn, "FILDES support not compiled in.");
            close(conn->scanfd);
            /* The wire error is not a successful scan. Keep the worker and
             * IDSESSION aggregate fail-visible when this optional ingress is
             * unavailable in the build. */
            return 1;
#endif
        case COMMAND_STATS:
            thrmgr_setactivetask(NULL, "STATS");
            if (conn->group)
                mdprintf(desc, "%u: ", conn->id);
            thrmgr_printstats(desc, conn->term);
            return 0;
        case COMMAND_INSTREAMSCAN:
            thrmgr_setactivetask(NULL, "INSTREAM");
            ret = scanfd(conn, NULL, engine, &options, opts, desc, 1);
            if (ret == CL_VIRUS) {
                *virus = 1;
                ret    = 0;
            } else if (ret == CL_EMEM) {
                if (optget(opts, "ExitOnOOM")->enabled)
                    ret = -1;
                else
                    ret = 1;
            } else if (ret == CL_ETIMEOUT) {
                thrmgr_group_terminate(conn->group);
                ret = 1;
            } else if (ret != CL_SUCCESS) {
                /* Do not let a descriptor/stream parser failure disappear
                 * after scanfd() has sent its error response. */
                ret = 1;
            } else
                ret = 0;
            if (ftruncate(conn->scanfd, 0) == -1) {
                /* not serious, we're going to close it and unlink it anyway */
                logg(LOGG_DEBUG, "ftruncate failed: %d\n", errno);
            }
            close(conn->scanfd);
            conn->scanfd = -1;
            cli_unlink(conn->filename);
            return ret;
        case COMMAND_ALLMATCHSCAN:
            if (!optget(opts, "AllowAllMatchScan")->enabled) {
                logg(LOGG_DEBUG_NV, "Rejecting ALLMATCHSCAN command.\n");
                conn_reply(conn, conn->filename, "ALLMATCHSCAN command disabled by clamd configuration.", "ERROR");
                return 1;
            }
            thrmgr_setactivetask(NULL, "ALLMATCHSCAN");
            scandata.options->general |= CL_SCAN_GENERAL_ALLMATCHES;
            type = TYPE_SCAN;
            break;
        default:
            logg(LOGG_ERROR, "Invalid command dispatched: %d\n", conn->cmdtype);
            return 1;
    }

    scandata.type = type;
    maxdirrec     = optget(opts, "MaxDirectoryRecursion")->numarg;
    if (optget(opts, "FollowDirectorySymlinks")->enabled)
        flags |= CLI_FTW_FOLLOW_DIR_SYMLINK;
    if (optget(opts, "FollowFileSymlinks")->enabled)
        flags |= CLI_FTW_FOLLOW_FILE_SYMLINK;

    if (!optget(opts, "CrossFilesystems")->enabled)
        if (CLAMSTAT(conn->filename, &sb) == 0)
            scandata.dev = sb.st_dev;

    ret = cli_ftw(conn->filename, flags, maxdirrec ? maxdirrec : INT_MAX, scan_callback, &data, scan_pathchk);
    if (ret == CL_EMEM) {
        if (optget(opts, "ExitOnOOM")->enabled)
            return -1;
        else
            return 1;
    }
    /* cli_ftw() can fail before scan_callback() has a chance to record the
     * failure in scandata.errors. Preserve that status so a path or directory
     * request cannot be reduced to a clean result with no scanned object. */
    if (ret != CL_SUCCESS && ret != CL_VIRUS && scandata.errors == 0) {
        scandata.errors++;
        if (conn->structured_report && conn->structured_status == CL_SUCCESS)
            conn->structured_status = ret;
    }
    if (scandata.group && type == TYPE_MULTISCAN) {
        thrmgr_group_waitforall(group, &ok, &error, &total);
        conn->structured_report_group = NULL;
        pthread_mutex_lock(&conn->thrpool->pool_mutex);
        conn->thrpool->thr_multiscan--;
        pthread_mutex_unlock(&conn->thrpool->pool_mutex);
    } else {
        error = scandata.errors;
        total = scandata.total;
        ok    = total - error - scandata.infected_files;
    }

    if (ok + error == total && (error != total)) {
        if (conn_reply_single(conn, conn->filename, "OK") == -1)
            ret = CL_ETIMEOUT;
    }
    *virus = total - (ok + error);

    if (ret == CL_ETIMEOUT)
        thrmgr_group_terminate(conn->group);
    return error;
}

static void dispatch_failed_resources(client_conn_t *conn)
{
    if (conn == NULL)
        return;

    if (conn->scanfd != -1) {
        if (close(conn->scanfd) != 0)
            logg(LOGG_WARNING, "Failed to close a descriptor after command dispatch failure: %s\n", strerror(errno));
        conn->scanfd = -1;
    }

    if (conn->filename != NULL) {
        if (conn->cmdtype == COMMAND_INSTREAMSCAN && cli_unlink(conn->filename) != CL_SUCCESS)
            logg(LOGG_WARNING, "Failed to remove staged INSTREAM input after command dispatch failure\n");
        free(conn->filename);
        conn->filename = NULL;
    }
}

static int dispatch_command(client_conn_t *conn, enum commands cmd, const char *argument)
{
    int ret = 0;
    int reserved = 0;
    int dispatch_attempted = 0;
    int bulk;
    client_conn_t *dup_conn = (client_conn_t *)malloc(sizeof(struct client_conn_tag));

    if (!dup_conn) {
        logg(LOGG_ERROR, "Can't allocate memory for client_conn\n");
        return -1;
    }
    memcpy(dup_conn, conn, sizeof(*conn));
    dup_conn->cmdtype = cmd;
    reserved = dup_conn->stream_admission_reserved;
    conn->stream_admission_reserved = 0;
    if (cl_engine_addref(dup_conn->engine)) {
        logg(LOGG_ERROR, "cl_engine_addref() failed\n");
        if (reserved)
            thrmgr_release_reservation(dup_conn->thrpool);
        free(dup_conn);
        return -1;
    }
    dup_conn->scanfd   = -1;
    dup_conn->filename = NULL;
    bulk             = 1;
    switch (cmd) {
        case COMMAND_FILDES:
            if (conn->scanfd == -1) {
                if (conn->structured_report)
                    (void)conn_reply_scan_report(dup_conn, CL_ESTAT, 0);
                else
                    conn_reply_error(dup_conn, "No file descriptor received.");
                ret = 1;
            }
            dup_conn->scanfd = conn->scanfd;
            /* consume FD */
            conn->scanfd = -1;
            break;
        case COMMAND_SCAN:
        case COMMAND_CONTSCAN:
        case COMMAND_MULTISCAN:
        case COMMAND_ALLMATCHSCAN:
            dup_conn->filename = cli_strdup_to_utf8(argument);
            if (!dup_conn->filename) {
                logg(LOGG_ERROR, "Failed to allocate memory for filename\n");
                ret = -1;
            }
            break;
        case COMMAND_INSTREAMSCAN:
            dup_conn->scanfd  = conn->scanfd;
            conn->scanfd      = -1;
            dup_conn->filename = conn->filename;
            conn->filename     = NULL;
            break;
        case COMMAND_STATS:
            /* not a scan command, don't queue to bulk */
            bulk = 0;
            /* just dispatch the command */
            break;
        default:
            logg(LOGG_ERROR, "Invalid command dispatch: %d\n", cmd);
            ret = -2;
            break;
    }
    if (!dup_conn->group)
        bulk = 0;
    if (!ret) {
        dispatch_attempted = 1;
        if (!(reserved ? thrmgr_group_dispatch_reserved(dup_conn->thrpool, dup_conn->group, dup_conn, bulk)
                       : thrmgr_group_dispatch(dup_conn->thrpool, dup_conn->group, dup_conn, bulk))) {
            logg(LOGG_ERROR, "thread dispatch failed\n");
            ret = -2;
        }
    }
    if (ret) {
        if (reserved && !dispatch_attempted)
            thrmgr_release_reservation(dup_conn->thrpool);
        dispatch_failed_resources(dup_conn);
        cl_engine_free(dup_conn->engine);
        free(dup_conn);
    }
    return ret;
}

static int print_ver(int desc, char term, const struct cl_engine *engine)
{
    uint32_t ver;

    ver = cl_engine_get_num(engine, CL_ENGINE_DB_VERSION, NULL);
    if (ver) {
        char timestr[32];
        const char *tstr;
        time_t t;
        t    = cl_engine_get_num(engine, CL_ENGINE_DB_TIME, NULL);
        tstr = cli_ctime(&t, timestr, sizeof(timestr));
        /* cut trailing \n */
        timestr[strlen(tstr) - 1] = '\0';
        return mdprintf(desc, "ClamAV %s/%u/%s%c", get_version(), (unsigned int)ver, tstr, term);
    }
    return mdprintf(desc, "ClamAV %s%c", get_version(), term);
}

static void print_commands(int desc, char term, const struct cl_engine *engine)
{
    unsigned i, n;
    const char *engine_ver = cl_retver();
    const char *clamd_ver  = get_version();
    if (strcmp(engine_ver, clamd_ver)) {
        mdprintf(desc, "ENGINE VERSION MISMATCH: %s != %s. ERROR%c",
                 engine_ver, clamd_ver, term);
        return;
    }
    print_ver(desc, '|', engine);
    mdprintf(desc, " COMMANDS:");
    n = sizeof(commands) / sizeof(commands[0]);
    for (i = 0; i < n; i++) {
        mdprintf(desc, " %s", commands[i].cmd);
    }
    mdprintf(desc, "%c", term);
}

/* returns:
 *  <0 for error
 *     -1 out of memory
 *     -2 other
 *   0 for async dispatched
 *   1 for command completed (connection can be closed)
 */
int execute_or_dispatch_command(client_conn_t *conn, enum commands cmd, const char *argument)
{
    int desc                       = conn->sd;
    char term                      = conn->term;
    const struct cl_engine *engine = conn->engine;
    /* execute commands that can be executed quickly on the recvloop thread,
     * these must:
     *  - not involve any operation that can block for a long time, such as disk
     *  I/O
     *  - send of atomic message is allowed.
     * Dispatch other commands */
    if (conn->group) {
        switch (cmd) {
            case COMMAND_FILDES:
            case COMMAND_FILDESREPORT:
            case COMMAND_SCAN:
            case COMMAND_SCANREPORT:
            case COMMAND_CONTSCANREPORT:
            case COMMAND_MULTISCANREPORT:
            case COMMAND_ALLMATCHSCANREPORT:
            case COMMAND_END:
            case COMMAND_INSTREAM:
            case COMMAND_INSTREAMREPORT:
            case COMMAND_INSTREAMSCAN:
            case COMMAND_VERSION:
            case COMMAND_PING:
            case COMMAND_STATS:
            case COMMAND_COMMANDS:
                /* These commands are accepted inside IDSESSION */
                break;
            default:
                /* these commands are not recognized inside an IDSESSION */
                conn_reply_error(conn, "Command invalid inside IDSESSION.");
                logg(LOGG_DEBUG_NV, "SESSION: command is not valid inside IDSESSION: %d\n", cmd);
                conn->group = NULL;
                return 1;
        }
    }

    switch (cmd) {
        case COMMAND_SCANREPORT:
            conn->structured_report = 1;
            return dispatch_command(conn, COMMAND_SCAN, argument);
        case COMMAND_CONTSCANREPORT:
            conn->structured_report = 1;
            return dispatch_command(conn, COMMAND_CONTSCAN, argument);
        case COMMAND_MULTISCANREPORT:
            /* Keep one report frame per request.  COMMAND_MULTISCAN uses its
             * existing sequential fallback when MaxThreads is one, while
             * preserving parallel directory scans when workers are available.
             * Child reports are merged by the owning scan worker. */
            conn->structured_report = 1;
            return dispatch_command(conn, COMMAND_MULTISCAN, argument);
        case COMMAND_ALLMATCHSCANREPORT:
            conn->structured_report = 1;
            return dispatch_command(conn, COMMAND_ALLMATCHSCAN, argument);
        case COMMAND_FILDESREPORT:
            conn->structured_report = 1;
            return dispatch_command(conn, COMMAND_FILDES, argument);
        case COMMAND_SHUTDOWN:
            if (optget(conn->opts, "EnableShutdownCommand")->enabled) {
                pthread_mutex_lock(&exit_mutex);
                progexit = 1;
                pthread_mutex_unlock(&exit_mutex);
            } else {
                conn_reply_single(conn, NULL, "COMMAND UNAVAILABLE");
            }
            return 1;
        case COMMAND_RELOAD:
            if (optget(conn->opts, "EnableReloadCommand")->enabled) {
                pthread_mutex_lock(&reload_mutex);
                reload = 1;
                pthread_mutex_unlock(&reload_mutex);
                mdprintf(desc, "RELOADING%c", term);
                /* we set reload flag, and we'll reload before closing the connection */
            } else {
                conn_reply_single(conn, NULL, "COMMAND UNAVAILABLE");
            }
            return 1;
        case COMMAND_PING:
            if (conn->group)
                mdprintf(desc, "%u: PONG%c", conn->id, term);
            else
                mdprintf(desc, "PONG%c", term);
            return conn->group ? 0 : 1;
        case COMMAND_VERSION: {
            if (optget(conn->opts, "EnableVersionCommand")->enabled) {
                if (conn->group)
                    mdprintf(desc, "%u: ", conn->id);
                print_ver(desc, conn->term, engine);
                return conn->group ? 0 : 1;
            } else {
                conn_reply_single(conn, NULL, "COMMAND UNAVAILABLE");
                return 1;
            }
        }
        case COMMAND_COMMANDS: {
            if (conn->group)
                mdprintf(desc, "%u: ", conn->id);
            print_commands(desc, conn->term, engine);
            return conn->group ? 0 : 1;
        }
        case COMMAND_DETSTATSCLEAR: {
            /* TODO: tell client this command has been removed */
            return 1;
        }
        case COMMAND_DETSTATS: {
            /* TODO: tell client this command has been removed */
            return 1;
        }
        case COMMAND_INSTREAM:
        case COMMAND_INSTREAMREPORT: {
            uint64_t stream_limit;
            uint64_t temporary_limit;
            int rc;
            if (cmd == COMMAND_INSTREAMREPORT)
                conn->structured_report = 1;
            rc = cli_gentempfd(optget(conn->opts, "TemporaryDirectory")->strarg, &conn->filename, &conn->scanfd);
            if (rc != CL_SUCCESS) {
                if (conn->stream_admission_reserved) {
                    thrmgr_release_reservation(conn->thrpool);
                    conn->stream_admission_reserved = 0;
                }
                if (conn->structured_report)
                    (void)conn_reply_scan_report(conn, CL_ETMPFILE, 0);
                return 1;
            }
            stream_limit       = clamd_stream_limit(conn->opts);
            temporary_limit    = (uint64_t)cl_engine_get_num(conn->engine, CL_ENGINE_MAX_TEMPORARY_SIZE, NULL);
            conn->quota_source = CLAMD_QUOTA_SOURCE_STREAM;
            conn->quota        = stream_limit;
            conn->stream_bytes = 0;
            if (temporary_limit && (!stream_limit || temporary_limit < stream_limit)) {
                conn->quota        = temporary_limit;
                conn->quota_source = CLAMD_QUOTA_SOURCE_TEMPORARY;
            }
            conn->mode = MODE_STREAM;
            return 0;
        }
        case COMMAND_STATS: {
            if (optget(conn->opts, "EnableStatsCommand")->enabled) {
                return dispatch_command(conn, cmd, argument);
            } else {
                conn_reply_single(conn, NULL, "COMMAND UNAVAILABLE");
                return 1;
            }
        }
        case COMMAND_MULTISCAN:
        case COMMAND_CONTSCAN:
        case COMMAND_FILDES:
        case COMMAND_SCAN:
        case COMMAND_INSTREAMSCAN:
        case COMMAND_ALLMATCHSCAN:
            return dispatch_command(conn, cmd, argument);
        case COMMAND_IDSESSION:
            conn->group = thrmgr_group_new();
            if (!conn->group)
                return CL_EMEM;
            return 0;
        case COMMAND_END:
            if (!conn->group) {
                /* end without idsession? */
                conn_reply_single(conn, NULL, "UNKNOWN COMMAND");
                return 1;
            }
            /* need to close connection  if we were last in group */
            return 1;
        /*case COMMAND_UNKNOWN:*/
        default:
            conn_reply_single(conn, NULL, "UNKNOWN COMMAND");
            return 1;
    }
}
