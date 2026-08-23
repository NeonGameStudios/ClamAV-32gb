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
#include <limits.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <fcntl.h>
#ifndef _WIN32
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif
#include <pthread.h>

// libclamav
#include "clamav.h"
#include "others.h"
#include "scan_report.h"
#include "scanners.h"

// common
#include "idmef_logging.h"
#include "optparser.h"
#include "output.h"
#include "misc.h"

#include "clamd_others.h"
#include "scanner.h"
#include "shared.h"
#include "thrmgr.h"
#include "server.h"

#ifdef C_LINUX
dev_t procdev; /* /proc device */
#endif

extern int progexit;
extern time_t reloaded_time;
extern pthread_mutex_t reload_mutex;

static client_conn_t *structured_report_target(client_conn_t *conn)
{
    if (NULL == conn)
        return NULL;

    return (NULL != conn->structured_report_owner) ? conn->structured_report_owner : conn;
}

static int structured_report_enabled(const client_conn_t *conn)
{
    return (NULL != conn) && (conn->structured_report || (NULL != conn->structured_report_owner));
}

static void structured_report_note_status(client_conn_t *conn, cl_error_t status)
{
    client_conn_t *target;
    jobgroup_t *report_group;
    int terminated = 0;

    if ((NULL == conn) || (CL_SUCCESS == status))
        return;

    report_group = conn->structured_report_group;
    if (NULL != report_group) {
        pthread_mutex_lock(&report_group->mutex);
        terminated = report_group->force_exit;
        pthread_mutex_lock(&exit_mutex);
        terminated |= progexit;
        pthread_mutex_unlock(&exit_mutex);
        if (terminated)
            goto done;
    }

    target = structured_report_target(conn);
    if (NULL == target)
        goto done;

    if ((CL_SUCCESS == target->structured_status) || (CL_VIRUS == status))
        target->structured_status = status;

done:
    if (NULL != report_group)
        pthread_mutex_unlock(&report_group->mutex);
}

static cl_error_t record_structured_scan_report(client_conn_t *conn, cl_scan_report_t *report)
{
    client_conn_t *target;
    jobgroup_t *report_group = NULL;
    cl_error_t status        = CL_SUCCESS;
    int terminated           = 0;

    if (NULL == conn) {
        cl_scan_report_free(report);
        return CL_ENULLARG;
    }

    if (NULL == report)
        return CL_SUCCESS;

    target = structured_report_target(conn);
    if (NULL == target) {
        cl_scan_report_free(report);
        return CL_ENULLARG;
    }

    report_group = conn->structured_report_group;
    if (NULL != report_group) {
        pthread_mutex_lock(&report_group->mutex);
        terminated = report_group->force_exit;
        pthread_mutex_lock(&exit_mutex);
        terminated |= progexit;
        pthread_mutex_unlock(&exit_mutex);
        if (terminated) {
            cl_scan_report_free(report);
            status = CL_BREAK;
            goto done;
        }
    }

    if (NULL == target->structured_scan_report) {
        target->structured_scan_report           = report;
        target->structured_scan_report_aggregate = 0;
        goto done;
    }

    if (!target->structured_scan_report_aggregate) {
        cl_scan_report_t *aggregate = NULL;

        status = cli_scan_report_create(&aggregate, target->engine);
        if (status != CL_SUCCESS) {
            cl_scan_report_free(report);
            goto done;
        }
        cli_scan_report_set_target(aggregate, target->filename);
        cli_scan_report_merge(aggregate, target->structured_scan_report);
        cl_scan_report_free(target->structured_scan_report);
        target->structured_scan_report           = aggregate;
        target->structured_scan_report_aggregate = 1;
    }

    cli_scan_report_merge(target->structured_scan_report, report);
    cl_scan_report_free(report);

done:
    if (NULL != report_group)
        pthread_mutex_unlock(&report_group->mutex);
    return status;
}

static void record_structured_scan_skip(struct scan_cb_data *scandata,
                                        cl_error_t status,
                                        const char *reason)
{
    cl_scan_report_t *report = NULL;
    cli_ctx context;

    if ((NULL == scandata) || (NULL == scandata->conn) ||
        !structured_report_enabled(scandata->conn))
        return;

    if (cli_scan_report_create(&report, scandata->engine) != CL_SUCCESS) {
        structured_report_note_status(scandata->conn, CL_EMEM);
        return;
    }

    memset(&context, 0, sizeof(context));
    context.engine                 = scandata->engine;
    context.scan_incomplete        = true;
    context.skipped_operations     = 1;
    context.scan_incomplete_reason = reason;
    cli_scan_report_set_target(report, scandata->toplevel_path);
    cli_scan_report_finish(report, &context, status,
                           CL_VERDICT_NOTHING_FOUND, NULL);

    if (record_structured_scan_report(scandata->conn, report) != CL_SUCCESS)
        scandata->conn->structured_status = CL_EMEM;
}

static void record_structured_empty_scan(struct scan_cb_data *scandata,
                                         const char *target)
{
    cl_scan_report_t *report = NULL;

    if ((NULL == scandata) || (NULL == scandata->conn) ||
        !structured_report_enabled(scandata->conn))
        return;

    if (cli_scan_report_create(&report, scandata->engine) != CL_SUCCESS) {
        structured_report_note_status(scandata->conn, CL_EMEM);
        return;
    }

    cli_scan_report_set_target(report, target ? target : scandata->toplevel_path);
    cli_scan_report_set_root_size(report, 0);
    cli_scan_report_note_logical(report, 0, 0);
    cli_scan_report_finish(report, NULL, CL_SUCCESS,
                           CL_VERDICT_NOTHING_FOUND, NULL);

    if (record_structured_scan_report(scandata->conn, report) != CL_SUCCESS)
        scandata->conn->structured_status = CL_EMEM;
}

static void publish_scanned_bytes(unsigned long int *destination, uint64_t scanned_bytes)
{
    uint64_t scaled = scanned_bytes / CL_COUNT_PRECISION;

    if (NULL == destination)
        return;

    *destination = (scaled > (uint64_t)ULONG_MAX) ? ULONG_MAX : (unsigned long int)scaled;
}

void msg_callback(enum cl_msg severity, const char *fullmsg, const char *msg, void *ctx)
{
    struct cb_context *c = ctx;
    const char *filename = (c && c->filename) ? c->filename : "";

    UNUSEDPARAM(fullmsg);

    switch (severity) {
        case CL_MSG_ERROR:
            logg(LOGG_WARNING, "[LibClamAV] %s: %s", filename, msg);
            break;
        case CL_MSG_WARN:
            logg(LOGG_INFO, "[LibClamAV] %s: %s", filename, msg);
            break;
        case CL_MSG_INFO_VERBOSE:
            logg(LOGG_DEBUG, "[LibClamAV] %s: %s", filename, msg);
            break;
        default:
            logg(LOGG_DEBUG_NV, "[LibClamAV] %s: %s", filename, msg);
            break;
    }
}

void hash_callback(int fd, unsigned long long size, const char *md5, const char *virname, void *ctx)
{
    struct cb_context *c = ctx;
    UNUSEDPARAM(fd);
    UNUSEDPARAM(virname);

    if (!c)
        return;
    c->virsize = size;
    strncpy(c->virhash, md5, MD5_HASH_SIZE * 2);
    c->virhash[MD5_HASH_SIZE * 2] = '\0';
}

void clamd_virus_found_cb(int fd, const char *virname, void *ctx)
{
    struct cb_context *c   = ctx;
    struct scan_cb_data *d = c->scandata;
    const char *fname;

    UNUSEDPARAM(fd);

    if (d == NULL)
        return;
    if (!(d->options->general & CL_SCAN_GENERAL_ALLMATCHES) && !(d->options->general & CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE))
        return;
    if (virname == NULL)
        return;

    fname = (c && c->filename) ? c->filename : "(filename not set)";

    if (virname) {
        d->infected++;
        conn_reply_virus(d->conn, fname, virname);
        if (c->virsize > 0 && optget(d->opts, "ExtendedDetectionInfo")->enabled)
            logg(LOGG_INFO, "%s: %s(%s:%llu) FOUND\n", fname, virname, c->virhash, c->virsize);
        logg(LOGG_INFO, "%s: %s FOUND\n", fname, virname);
    }

    return;
}

#define BUFFSIZE 1024
cl_error_t scan_callback(STATBUF *sb, char *filename, const char *msg, enum cli_ftw_reason reason, struct cli_ftw_cbdata *data)
{
    struct scan_cb_data *scandata = data->data;
    const char *virname           = NULL;
    cl_error_t ret                = CL_SUCCESS;
    int type                      = scandata->type;
    struct cb_context context;
    char *scan_filename = NULL;
    const char *scan_path;

    /* detect disconnected socket,
     * this should NOT detect half-shutdown sockets (SHUT_WR) */
    if (send(scandata->conn->sd, &ret, 0, 0) == -1 && errno != EINTR) {
        logg(LOGG_DEBUG_NV, "Client disconnected while command was active!\n");
        thrmgr_group_terminate(scandata->conn->group);
        if (reason == visit_file)
            free(filename);
        return CL_BREAK;
    }

    if (thrmgr_group_need_terminate(scandata->conn->group)) {
        logg(LOGG_WARNING, "Client disconnected while scanjob was active\n");
        if (reason == visit_file)
            free(filename);
        return CL_BREAK;
    }
    scandata->total++;
    switch (reason) {
        case error_mem:
            if (msg)
                logg(LOGG_ERROR, "Memory allocation failed during cli_ftw() on %s\n",
                     msg);
            else
                logg(LOGG_ERROR, "Memory allocation failed during cli_ftw()\n");
            scandata->errors++;
            record_structured_scan_skip(scandata, CL_EMEM,
                                        "directory walk allocation failed");
            free(filename);
            return CL_EMEM;
        case error_stat:
            conn_reply_errno(scandata->conn, msg, "File path check failure:");
            logg(LOGG_WARNING, "File path check failure on: %s\n", msg);
            scandata->errors++;
            record_structured_scan_skip(scandata, CL_ESTAT,
                                        "directory walk stat failed");
            free(filename);
            return CL_SUCCESS;
        case warning_skipped_dir:
            logg(LOGG_WARNING, "Directory recursion limit reached, skipping %s\n", msg);
            scandata->errors++;
            record_structured_scan_skip(scandata, CL_EMAXREC,
                                        "directory recursion limit skipped a required path");
            free(filename);
            return CL_SUCCESS;
        case warning_skipped_link:
            logg(LOGG_DEBUG_NV, "Skipping symlink: %s\n", msg);
            free(filename);
            return CL_SUCCESS;
        case warning_skipped_special:
            if (msg == scandata->toplevel_path)
                conn_reply(scandata->conn, msg, "Not supported file type", "ERROR");
            logg(LOGG_DEBUG, "Not supported file type: %s\n", msg);
            scandata->errors++;
            record_structured_scan_skip(scandata, CL_EUNPACK,
                                        "unsupported file type was skipped");
            free(filename);
            return CL_SUCCESS;
        case visit_directory_toplev:
            free(filename);
            return CL_SUCCESS;
        case visit_file:
            break;
    }

#ifdef C_LINUX
    /* check whether the file is excluded */
    if (procdev && sb && (sb->st_dev == procdev)) {
        free(filename);
        return CL_SUCCESS;
    }
#endif

    if (sb && sb->st_size == 0) { /* empty file */
        if (msg == scandata->toplevel_path)
            conn_reply_single(scandata->conn, filename, "Empty file");
        record_structured_empty_scan(scandata, filename);
        free(filename);
        return CL_SUCCESS;
    }

    scan_path = (NULL != msg) ? msg : filename;
    /*
     * Resolve the path used for the actual scan open. Keep filename as the
     * client-visible name, but do not let a symlinked parent component change
     * the object opened after cli_ftw() has performed its checks.
     */
    if (NULL != scan_path) {
        ret = cli_realpath(scan_path, &scan_filename);
        if (CL_SUCCESS != ret) {
            conn_reply_errno(scandata->conn, filename, "File path check failure:");
            logg(LOGG_WARNING, "File path check failure for: %s\n", filename);
            scandata->errors++;
            record_structured_scan_skip(scandata, ret,
                                        "real path resolution failed");
            free(filename);
            return (CL_EMEM == ret) ? ret : CL_SUCCESS;
        }
        scan_path = scan_filename;
    }

    if (type == TYPE_MULTISCAN) {
        client_conn_t *client_conn = (client_conn_t *)calloc(1, sizeof(struct client_conn_tag));
        if (client_conn) {
            client_conn->scanfd   = -1;
            client_conn->sd       = scandata->odesc;
            client_conn->filename = (NULL != scan_filename) ? scan_filename : filename;
            if (NULL != scan_filename) {
                client_conn->display_filename = filename;
                scan_filename                 = NULL;
            }
            filename                             = NULL;
            client_conn->cmdtype                 = COMMAND_MULTISCANFILE;
            client_conn->structured_report       = scandata->conn->structured_report;
            client_conn->structured_report_owner = scandata->conn->structured_report ? scandata->conn : NULL;
            client_conn->structured_report_group = scandata->conn->structured_report ? scandata->group : NULL;
            client_conn->term                    = scandata->conn->term;
            client_conn->options                 = scandata->options;
            client_conn->opts                    = scandata->opts;
            client_conn->group                   = scandata->group;
            if (cl_engine_addref(scandata->engine)) {
                logg(LOGG_ERROR, "cl_engine_addref() failed\n");
                free(client_conn->filename);
                free(client_conn->display_filename);
                free(client_conn);
                return CL_EMEM;
            } else {
                client_conn->engine = scandata->engine;
                pthread_mutex_lock(&reload_mutex);
                client_conn->engine_timestamp = reloaded_time;
                pthread_mutex_unlock(&reload_mutex);
                if (!thrmgr_group_dispatch(scandata->thr_pool, scandata->group, client_conn, 1)) {
                    logg(LOGG_ERROR, "thread dispatch failed\n");
                    cl_engine_free(scandata->engine);
                    free(client_conn->filename);
                    free(client_conn->display_filename);
                    free(client_conn);
                    return CL_EMEM;
                }
            }
        } else {
            logg(LOGG_ERROR, "Can't allocate memory for client_conn\n");
            scandata->errors++;
            free(scan_filename);
            free(filename);
            return CL_EMEM;
        }
        return CL_SUCCESS;
    }

    thrmgr_setactivetask(filename, NULL);
    context.filename = filename;
    context.virsize  = 0;
    context.scandata = scandata;
    if (structured_report_enabled(scandata->conn)) {
        cl_error_t report_status;
        cl_scan_report_t *report = NULL;
        cl_verdict_t verdict     = CL_VERDICT_NOTHING_FOUND;
        uint64_t scanned_bytes   = 0;
        cl_error_t record_status;

        report_status = cl_scanfile_ex2(
            scan_path,
            &verdict,
            &virname,
            &scanned_bytes,
            scandata->engine,
            scandata->options,
            &context,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            &report);
        record_status = record_structured_scan_report(scandata->conn, report);
        if (record_status != CL_SUCCESS) {
            ret                               = CL_EMEM;
            scandata->conn->structured_status = CL_EMEM;
        }
        publish_scanned_bytes(&scandata->scanned, scanned_bytes);
        if (record_status == CL_SUCCESS)
            ret = report_status;
        if ((verdict == CL_VERDICT_STRONG_INDICATOR) ||
            (verdict == CL_VERDICT_POTENTIALLY_UNWANTED)) {
            ret                               = CL_VIRUS;
            scandata->conn->structured_status = CL_VIRUS;
        } else if (ret != CL_SUCCESS && scandata->conn->structured_status == CL_SUCCESS) {
            scandata->conn->structured_status = ret;
        }
        structured_report_note_status(scandata->conn, scandata->conn->structured_status);
    } else {
        ret = cl_scanfile_callback(scan_path, &virname, &scandata->scanned, scandata->engine, scandata->options, &context);
    }
    if (ret == CL_VIRUS)
        scandata->conn->structured_status = CL_VIRUS;
    else if (ret != CL_SUCCESS && scandata->conn->structured_status == CL_SUCCESS)
        scandata->conn->structured_status = ret;
    thrmgr_setactivetask(NULL, NULL);

    if (thrmgr_group_need_terminate(scandata->conn->group)) {
        free(scan_filename);
        free(filename);
        logg(LOGG_DEBUG, "Client disconnected while scanjob was active\n");
        return ret == CL_ETIMEOUT ? ret : CL_BREAK;
    }

    if ((ret == CL_VIRUS) && (virname == NULL)) {
        logg(LOGG_DEBUG, "%s: reported CL_VIRUS but no virname returned!\n", filename);
        ret = CL_EMEM;
    }

    if (ret == CL_EACCES) {
        if (conn_reply(scandata->conn, filename, "Access denied.", "ERROR") == -1) {
            free(scan_filename);
            free(filename);
            return CL_ETIMEOUT;
        }
        logg(LOGG_DEBUG, "Access denied: %s\n", filename);
        scandata->errors++;
        free(scan_filename);
        free(filename);
        return CL_SUCCESS;
    }

    if (ret == CL_VIRUS) {
        /* infected counts individual detections for ALLMATCHES callback
         * output. Keep the aggregate counter at one per input file so a file
         * with several signatures cannot underflow command()'s summary math. */
        scandata->infected_files++;

        if (scandata->options->general & CL_SCAN_GENERAL_ALLMATCHES || (scandata->infected && scandata->options->general & CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE)) {
            if (optget(scandata->opts, "PreludeEnable")->enabled) {
                prelude_logging(filename, virname, context.virhash, context.virsize);
            }
            virusaction(scan_path, virname, scandata->opts);
        } else {
            scandata->infected++;
            virusaction(scan_path, virname, scandata->opts);
            if (conn_reply_virus(scandata->conn, filename, virname) == -1) {
                free(scan_filename);
                free(filename);
                return CL_ETIMEOUT;
            }
            if (optget(scandata->opts, "PreludeEnable")->enabled) {
                prelude_logging(filename, virname, context.virhash, context.virsize);
            }

            if (context.virsize && optget(scandata->opts, "ExtendedDetectionInfo")->enabled)
                logg(LOGG_INFO, "%s: %s(%s:%llu) FOUND\n", filename, virname, context.virhash, context.virsize);
            else
                logg(LOGG_INFO, "%s: %s FOUND\n", filename, virname);
        }
    } else if (ret != CL_CLEAN) {
        scandata->errors++;
        if (conn_reply(scandata->conn, filename, cl_strerror(ret), "ERROR") == -1) {
            free(scan_filename);
            free(filename);
            return CL_ETIMEOUT;
        }
        logg(LOGG_INFO, "%s: %s ERROR\n", filename, cl_strerror(ret));
    } else if (logok) {
        logg(LOGG_INFO, "%s: OK\n", filename);
    }

    free(scan_filename);
    free(filename);

    if (ret == CL_EMEM) /* stop scanning */
        return ret;

    if (type == TYPE_SCAN) {
        /* virus -> break */
        return ret;
    }

    /* keep scanning always */
    return CL_SUCCESS;
}

int scan_pathchk(const char *path, struct cli_ftw_cbdata *data)
{
    struct scan_cb_data *scandata = data->data;
    const struct optstruct *opt;
    STATBUF statbuf;

    if ((opt = optget(scandata->opts, "ExcludePath"))->enabled) {
        while (opt) {
            if (match_regex(path, opt->strarg) == 1) {
                if (scandata->type != TYPE_MULTISCAN)
                    conn_reply_single(scandata->conn, path, "Excluded");
                return 1;
            }
            opt = (const struct optstruct *)opt->nextarg;
        }
    }

    if (!optget(scandata->opts, "CrossFilesystems")->enabled) {
        if (CLAMSTAT(path, &statbuf) == 0) {
            if (statbuf.st_dev != scandata->dev) {
                if (scandata->type != TYPE_MULTISCAN)
                    conn_reply_single(scandata->conn, path, "Excluded (another filesystem)");
                return 1;
            }
        }
    }

    return 0;
}

cl_error_t scanfd(
    client_conn_t *conn,
    unsigned long int *scanned,
    const struct cl_engine *engine,
    struct cl_scan_options *options,
    const struct optstruct *opts,
    int odesc,
    int stream)
{
    cl_error_t ret      = -1;
    int fd              = conn->scanfd;
    const char *virname = NULL;
    STATBUF statbuf;
    struct cb_context context;
    char fdstr[32];
    const char *reply_fdstr;

    char *filepath     = NULL;
    char *log_filename = fdstr;

    UNUSEDPARAM(odesc);

    if (stream) {
        struct sockaddr_in sa;
        socklen_t salen = sizeof(sa);
        if (getpeername(conn->sd, (struct sockaddr *)&sa, &salen) || salen > sizeof(sa) || sa.sin_family != AF_INET)
            strncpy(fdstr, "instream(local)", sizeof(fdstr));
        else
            snprintf(fdstr, sizeof(fdstr), "instream(%s@%u)", inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));
        reply_fdstr = "stream";
    } else {
        snprintf(fdstr, sizeof(fdstr), "fd[%d]", fd);
        reply_fdstr = fdstr;
    }
    if (FSTAT(fd, &statbuf) == -1 || !S_ISREG(statbuf.st_mode)) {
        if (conn->structured_report)
            conn->structured_status = CL_ESTAT;
        logg(LOGG_INFO, "%s: Not a regular file. ERROR\n", fdstr);
        if (conn_reply(conn, reply_fdstr, "Not a regular file", "ERROR") == -1) {
            ret = CL_ETIMEOUT;
            goto done;
        }
        ret = CL_BREAK;
        goto done;
    }

    /* Try to get the real filename, for logging purposes */
    if (!stream) {
        if (CL_SUCCESS != cli_get_filepath_from_filedesc(fd, &filepath)) {
            logg(LOGG_DEBUG, "%s: Unable to determine the filepath given the file descriptor.\n", fdstr);
        } else {
            log_filename = filepath;
        }
    }

    thrmgr_setactivetask(fdstr, NULL);
    context.filename = fdstr;
    context.virsize  = 0;
    context.scandata = NULL;
    if (structured_report_enabled(conn)) {
        cl_error_t report_status;
        cl_scan_report_t *report = NULL;
        cl_verdict_t verdict     = CL_VERDICT_NOTHING_FOUND;
        uint64_t scanned_bytes   = 0;
        cl_error_t record_status;

        report_status = cli_scandesc_ex2_with_temporary_bytes(
            fd,
            log_filename,
            &verdict,
            &virname,
            &scanned_bytes,
            engine,
            options,
            &context,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            stream ? conn->stream_bytes : 0,
            &report);
        record_status = record_structured_scan_report(conn, report);
        if (record_status != CL_SUCCESS) {
            ret                     = CL_EMEM;
            conn->structured_status = CL_EMEM;
        }
        publish_scanned_bytes(scanned, scanned_bytes);
        if (record_status == CL_SUCCESS)
            ret = report_status;
        if ((verdict == CL_VERDICT_STRONG_INDICATOR) ||
            (verdict == CL_VERDICT_POTENTIALLY_UNWANTED)) {
            ret                     = CL_VIRUS;
            conn->structured_status = CL_VIRUS;
        } else if (ret != CL_SUCCESS && conn->structured_status == CL_SUCCESS) {
            conn->structured_status = ret;
        }
        structured_report_note_status(conn, conn->structured_status);
    } else {
        cl_error_t report_status;
        cl_verdict_t verdict = CL_VERDICT_NOTHING_FOUND;
        uint64_t scanned_bytes = 0;

        report_status = cli_scandesc_ex2_with_temporary_bytes(
            fd,
            log_filename,
            &verdict,
            &virname,
            &scanned_bytes,
            engine,
            options,
            &context,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            stream ? conn->stream_bytes : 0,
            NULL);
        publish_scanned_bytes(scanned, scanned_bytes);
        ret = report_status;
        if ((verdict == CL_VERDICT_STRONG_INDICATOR) ||
            (verdict == CL_VERDICT_POTENTIALLY_UNWANTED))
            ret = CL_VIRUS;
    }
    if (ret == CL_VIRUS)
        conn->structured_status = CL_VIRUS;
    else if (ret != CL_SUCCESS && conn->structured_status == CL_SUCCESS)
        conn->structured_status = ret;
    thrmgr_setactivetask(NULL, NULL);

    if (thrmgr_group_need_terminate(conn->group)) {
        logg(LOGG_DEBUG, "Client disconnected while scanjob was active\n");
        ret = ret == CL_ETIMEOUT ? ret : CL_BREAK;
        goto done;
    }

    if (ret == CL_VIRUS) {
        virusaction(log_filename, virname, opts);
        if (conn_reply_virus(conn, reply_fdstr, virname) == -1)
            ret = CL_ETIMEOUT;
        if (context.virsize && optget(opts, "ExtendedDetectionInfo")->enabled)
            logg(LOGG_INFO, "%s: %s(%s:%llu) FOUND\n", log_filename, virname, context.virhash, context.virsize);
        else
            logg(LOGG_INFO, "%s: %s FOUND\n", log_filename, virname);
    } else if (ret != CL_CLEAN) {
        if (conn_reply(conn, reply_fdstr, cl_strerror(ret), "ERROR") == -1)
            ret = CL_ETIMEOUT;
        logg(LOGG_INFO, "%s: %s ERROR\n", log_filename, cl_strerror(ret));
    } else {
        if (conn_reply_single(conn, reply_fdstr, "OK") == CL_ETIMEOUT)
            ret = CL_ETIMEOUT;
        if (logok)
            logg(LOGG_INFO, "%s: OK\n", log_filename);
    }

done:
    if (NULL != filepath) {
        free(filepath);
    }

    return ret;
}

/* The deprecated STREAM command is not dispatched by clamd. Keep this
 * internal symbol fail-visible for out-of-tree callers rather than retaining
 * the old truncating socket implementation. INSTREAM is the supported
 * length-framed protocol and stages a complete file before scanning it. */
int scanstream(
    int odesc,
    unsigned long int *scanned,
    const struct cl_engine *engine,
    struct cl_scan_options *options,
    const struct optstruct *opts,
    char term)
{
    UNUSEDPARAM(scanned);
    UNUSEDPARAM(engine);
    UNUSEDPARAM(options);
    UNUSEDPARAM(opts);

    if (odesc >= 0)
        mdprintf(odesc, "STREAM command is no longer supported; use INSTREAM%c", term);
    return CL_EFORMAT;
}
