/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm, aCaB
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

#if defined(C_SOLARIS)
#ifndef __EXTENSIONS__
#define __EXTENSIONS__
#endif
#endif

/* must be first because it may define _XOPEN_SOURCE */
#include "fdpassing.h"
#include <stdio.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#ifndef _WIN32
#include <sys/resource.h>
#endif
#ifndef _WIN32
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#endif

// libclamav
#include "clamav.h"
#include "others.h"

// common
#include "actions.h"
#include "output.h"
#include "misc.h"
#include "clamdcom.h"

#include "proto.h"
#include "client.h"

extern uint64_t maxstream;
int printinfected;
extern struct optstruct *clamdopts;

#define DEFAULT_MAX_ACTION_SOURCES 64

static unsigned int get_max_action_sources(void)
{
#ifndef _WIN32
#ifdef RLIMIT_NOFILE
    struct rlimit rlim;

    if ((0 == getrlimit(RLIMIT_NOFILE, &rlim)) && (RLIM_INFINITY != rlim.rlim_cur)) {
        rlim_t limit = rlim.rlim_cur;

        if (limit <= 16) {
            return 1;
        }

        limit = (limit - 16) / 2;
        if (limit < 1) {
            return 1;
        }
        if (limit < DEFAULT_MAX_ACTION_SOURCES) {
            return (unsigned int)limit;
        }
    }
#endif
#endif

    return DEFAULT_MAX_ACTION_SOURCES;
}

struct client_walk_policy {
    bool check_cross_filesystems;
    bool have_dev;
    dev_t dev;
#ifdef C_LINUX
    bool check_proc;
    dev_t proc_dev;
#endif
};

/**
 * Initialize client-side traversal policy for local quarantine actions.
 *
 * When clamdscan performs local actions, it walks paths client-side and sends
 * individual files to clamd. Preserve clamd's procfs and CrossFilesystems=no
 * behavior for those action scans so files skipped by daemon-side directory
 * scans are not opened or quarantined by the client-side walk.
 */
static void client_walk_policy_init(struct client_walk_policy *policy, const char *path)
{
    STATBUF sb;

    policy->check_cross_filesystems = (NULL != action) && !optget(clamdopts, "CrossFilesystems")->enabled;
    policy->have_dev                = false;
    policy->dev                     = 0;
#ifdef C_LINUX
    policy->check_proc = false;
    policy->proc_dev   = 0;

    if ((NULL != action) && (0 == CLAMSTAT("/proc", &sb)) && !sb.st_size) {
        policy->check_proc = true;
        policy->proc_dev   = sb.st_dev;
    }
#endif

    if (policy->check_cross_filesystems && (0 == CLAMSTAT(path, &sb))) {
        policy->have_dev = true;
        policy->dev      = sb.st_dev;
    }
}

/**
 * Return nonzero when a path should be skipped by a client-side walk.
 */
static int client_path_excluded(const char *path, const struct client_walk_policy *policy)
{
    STATBUF sb;

    if (chkpath(path, clamdopts)) {
        return 1;
    }

#ifdef C_LINUX
    if ((NULL != policy) && policy->check_proc &&
        (0 == CLAMSTAT(path, &sb)) && (sb.st_dev == policy->proc_dev)) {
        return 1;
    }
#endif

    if ((NULL != policy) && policy->check_cross_filesystems && policy->have_dev &&
        (0 == CLAMSTAT(path, &sb)) && (sb.st_dev != policy->dev)) {
        return 1;
    }

    return 0;
}

static int ftw_chkpath(const char *path, struct cli_ftw_cbdata *data)
{
    const struct client_walk_policy *policy = NULL;

    if ((NULL != data) && (NULL != data->data)) {
        policy = (const struct client_walk_policy *)data->data;
    }

    return client_path_excluded(path, policy);
}

int clamdscan_write_client_failure_report(FILE *stream, const char *target, cl_error_t status)
{
    cl_scan_report_t *report = NULL;
    char *json              = NULL;
    int result              = 0;

    if (NULL == stream)
        return 0;

    if (cli_scan_report_create(&report, NULL) != CL_SUCCESS)
        return -1;
    cli_scan_report_set_target(report, target);
    cli_scan_report_finish(report, NULL, status, CL_VERDICT_NOTHING_FOUND, NULL);
    if (cl_scan_report_to_json(report, &json) != CL_SUCCESS) {
        cl_scan_report_free(report);
        return -1;
    }

    if (fwrite(json, 1, strlen(json), stream) != strlen(json) || fputc('\n', stream) == EOF)
        result = -1;

    free(json);
    cl_scan_report_free(report);
    return result;
}

/* Used by serial_callback() */
struct client_serial_data {
    /* Must be first: ftw_chkpath() receives only cli_ftw_cbdata::data. */
    struct client_walk_policy walk_policy;
    int infected;
    int scantype;
    int printok;
    int files;
    int errors;
    int flags;
    int maxlevel;
    FILE *report_stream;
};

/* FTW callback for scanning in non IDSESSION mode
 * Returns SUCCESS or BREAK on success, CL_EXXX on error */
static cl_error_t serial_callback(STATBUF *sb, char *filename, const char *path, enum cli_ftw_reason reason, struct cli_ftw_cbdata *data)
{
    cl_error_t status = CL_EOPEN;

    struct client_serial_data *c = (struct client_serial_data *)data->data;
    int sockd, ret;
    const char *f          = filename;
    const char *scan_path  = path;
    char *real_filter_path = NULL;
    action_source_t action_source;
    bool have_action_source = false;
    bool report_target      = (reason == visit_file);
    bool report_written     = false;
    cl_error_t report_status = CL_SUCCESS;

    action_source_init(&action_source);

    UNUSEDPARAM(sb);

    if (CL_SUCCESS != cli_realpath((const char *)path, &real_filter_path)) {
        logg(LOGG_DEBUG, "Failed to determine real filename of %s.\n", path);
    } else {
        scan_path = real_filter_path;
    }

    if (client_path_excluded(scan_path, &c->walk_policy)) {
        /* Exclude the path */
        status = CL_SUCCESS;
        goto done;
    }
    c->files++;
    switch (reason) {
        case error_stat:
            logg(LOGG_ERROR, "Can't access file %s\n", path);
            c->errors++;
            report_target = true;
            report_status = CL_ESTAT;
            status = CL_SUCCESS;
            goto done;
        case error_mem:
            logg(LOGG_ERROR, "Memory allocation failed in ftw\n");
            c->errors++;
            report_target = true;
            report_status = CL_EMEM;
            status = CL_EMEM;
            goto done;
        case warning_skipped_dir:
            logg(LOGG_WARNING, "Directory recursion limit reached\n");
            c->errors++;
            c->printok      = 0;
            report_target = true;
            report_status = CL_EMAXREC;
            status = CL_SUCCESS;
            goto done;
        case warning_skipped_link:
            status = CL_SUCCESS;
            goto done;
        case warning_skipped_special:
            logg(LOGG_WARNING, "%s: Not supported file type\n", path);
            c->errors++;
            report_target = true;
            report_status = CL_ERROR;
            status = CL_SUCCESS;
            goto done;
        case visit_directory_toplev:
            if ((c->scantype >= STREAM) || action) {
                status = CL_SUCCESS;
                goto done;
            }
            f = scan_path;
            break;
        case visit_file:
            if (action) {
                ret = action_source_open_path(f, scan_path, &action_source);
                if (CL_SUCCESS != ret) {
                    logg(LOGG_WARNING, "Can't open file %s for safe quarantine action: %s\n", f, cl_strerror(ret));
                    c->errors++;
                    report_status = ret;
                    status = CL_SUCCESS;
                    goto done;
                }
                have_action_source = true;
            } else {
                f = scan_path;
            }
            break;
    }

    if ((sockd = dconnect(clamdopts)) < 0) {
        c->errors++;
        report_status = CL_EOPEN;
        goto done;
    }
    if (c->report_stream) {
        int report_infected   = 0;
        int report_incomplete = 0;

        ret = dsreport(sockd, c->scantype, f, have_action_source ? &action_source : NULL,
                       have_action_source, c->report_stream, &report_infected,
                       &report_incomplete, &c->errors, clamdopts);
        if (ret < 0) {
            c->errors++;
            c->printok = 0;
            report_status = CL_ERROR;
            status     = CL_BREAK;
            goto done;
        }
        report_written = true;
        c->infected += report_infected;
        if (report_infected || report_incomplete)
            c->printok = 0;
        if (report_infected)
            logg(LOGG_INFO, "%s: FOUND\n", f);
        else if (report_incomplete)
            logg(LOGG_INFO, "%s: INCOMPLETE\n", f);
        closesocket(sockd);
        status = CL_SUCCESS;
        goto done;
    }

    ret = dsresult(sockd, c->scantype, f, have_action_source ? &action_source : NULL, have_action_source, &c->printok, &c->errors, clamdopts);
    closesocket(sockd);
    if (ret < 0) {
        c->errors++;
        goto done;
    }
    c->infected += ret;
    if (reason == visit_directory_toplev) {
        status = CL_BREAK;
        goto done;
    }

    status = CL_SUCCESS;
done:
    if (c->report_stream && report_target && !report_written &&
        clamdscan_write_client_failure_report(c->report_stream, f, report_status) != 0)
        c->errors++;
    if (have_action_source) {
        action_source_close(&action_source);
    }
    if (NULL != real_filter_path) {
        free(real_filter_path);
    }
    free(filename);
    return status;
}

/* Non-IDSESSION handler
 * Returns non zero for serious errors, zero otherwise */
int serial_client_scan(char *file, int scantype, int *infected, int *err, int maxlevel, int flags, FILE *report_stream)
{
    struct cli_ftw_cbdata data;
    struct client_serial_data cdata;
    int ftw;

    cdata.infected      = 0;
    cdata.files         = 0;
    cdata.errors        = 0;
    cdata.printok       = printinfected ^ 1;
    cdata.scantype      = scantype;
    cdata.flags         = flags;
    cdata.maxlevel      = maxlevel ? maxlevel : INT_MAX;
    cdata.report_stream = report_stream;
    client_walk_policy_init(&cdata.walk_policy, file);
    data.data = &cdata;

    ftw = cli_ftw(file, flags, maxlevel ? maxlevel : INT_MAX, serial_callback, &data, ftw_chkpath);
    *infected += cdata.infected;
    *err += cdata.errors;

    if (!cdata.errors && (ftw == CL_SUCCESS || ftw == CL_BREAK)) {
        if (cdata.printok)
            logg(LOGG_INFO, "%s: OK\n", file);
        return 0;
    } else if (!cdata.files) {
        logg(LOGG_INFO, "%s: No files scanned\n", file);
        return 0;
    }
    return 1;
}

/* Used in IDSESSION mode */
struct client_parallel_data {
    /* Must be first: ftw_chkpath() receives only cli_ftw_cbdata::data. */
    struct client_walk_policy walk_policy;
    int infected;
    int files;
    int errors;
    int scantype;
    int sockd;
    int lastid;
    int printok;
    FILE *report_stream;
    struct SCANID {
        unsigned int id;
        const char *file;
        action_source_t *action_source;
        struct SCANID *next;
    } *ids;
    unsigned int action_sources;
    unsigned int max_action_sources;
};

static int report_json_id(const char *json, uint32_t length, unsigned int *id)
{
    const char *field;
    char *end = NULL;
    unsigned long value;

    if (!json || !id || length == 0)
        return -1;
    field = strstr(json, "\"id\":");
    if (!field)
        field = strstr(json, "\"id\": ");
    if (!field)
        return -1;
    field = strchr(field, ':');
    if (!field)
        return -1;
    value = strtoul(field + 1, &end, 10);
    if (end == field + 1 || value > UINT_MAX)
        return -1;
    *id = (unsigned int)value;
    return 0;
}

static int dspreport(struct client_parallel_data *c)
{
    char *json                 = NULL;
    char *terminator_json      = NULL;
    uint32_t json_length       = 0;
    uint32_t terminator_length = 0;
    int terminator             = 0;
    int frame_infected         = 0;
    int frame_incomplete       = 0;
    cl_error_t frame_status    = CL_ERROR;
    unsigned int rid;
    struct SCANID **id;
    const char *filename;
    action_source_t *action_source;

    if (recv_scan_report_frame(c->sockd, &json, &json_length, &terminator) < 0 || terminator)
        return 1;
    /* Each IDSESSION structured response is a complete framed response:
     * exactly one report object followed by the zero-length terminator.  Do
     * not leave that terminator in the socket, where the next request would
     * mistake it for its own empty response. */
    terminator = 0;
    if (recv_scan_report_frame(c->sockd, &terminator_json, &terminator_length, &terminator) < 0 || !terminator) {
        free(json);
        free(terminator_json);
        return 1;
    }
    free(terminator_json);
    if (report_json_id(json, json_length, &rid) < 0 ||
        scan_report_json_status(json, json_length, &frame_infected, &frame_incomplete,
                                &frame_status) < 0) {
        free(json);
        return 1;
    }
    id = &c->ids;
    while (*id && (*id)->id != rid)
        id = &(*id)->next;
    if (!*id) {
        free(json);
        return 1;
    }
    filename      = (*id)->file;
    action_source = (*id)->action_source;
    if (c->report_stream &&
        (fwrite(json, 1, json_length, c->report_stream) != json_length ||
         fputc('\n', c->report_stream) == EOF)) {
        free(json);
        return 1;
    }
    if (frame_infected) {
        c->infected++;
        c->printok = 0;
        logg(LOGG_INFO, "%s: FOUND\n", filename);
        if (action && action_source)
            action(action_source);
    } else if (frame_incomplete) {
        c->errors++;
        c->printok = 0;
        logg(LOGG_INFO, "%s: INCOMPLETE (%s)\n", filename, cl_strerror(frame_status));
    }
    free(json);
    free((void *)filename);
    if (action_source) {
        action_source_close(action_source);
        free(action_source);
        if (c->action_sources > 0)
            c->action_sources--;
    }
    {
        struct SCANID *completed = *id;
        *id                      = completed->next;
        free(completed);
    }
    return 0;
}

/* Sends a proper scan request to clamd and parses its replies
 * This is used only in IDSESSION mode
 * Returns 0 on success, 1 on hard failures, 2 on len == 0 (bb#1717) */
static int dspresult(struct client_parallel_data *c)
{
    const char *filename;
    action_source_t *action_source;
    char *bol, *eol;
    unsigned int rid;
    int len;
    struct SCANID **id = NULL;
    struct RCVLN rcv;

    if (c->report_stream)
        return dspreport(c);

    recvlninit(&rcv, c->sockd);
    do {
        len = recvln(&rcv, &bol, &eol);
        if (len < 0) return 1;
        if (!len) return 2;
        if ((rid = atoi(bol))) {
            id = &c->ids;
            while (*id) {
                if ((*id)->id == rid) break;
                id = &((*id)->next);
            }
            if (!*id) id = NULL;
        }
        if (!id) {
            logg(LOGG_ERROR, "Bogus session id from clamd\n");
            return 1;
        }
        filename      = (*id)->file;
        action_source = (*id)->action_source;
        if (len > 7) {
            char *colon = strrchr(bol, ':');
            if (!colon) {
                logg(LOGG_ERROR, "Failed to parse reply\n");
                return 1;
            } else if (!memcmp(eol - 7, " FOUND", 6)) {
                c->infected++;
                c->printok = 0;
                logg(LOGG_INFO, "%s%s\n", filename, colon);
                if (action && (NULL != action_source)) action(action_source);
            } else if (!memcmp(eol - 7, " ERROR", 6)) {
                c->errors++;
                c->printok = 0;
                logg(LOGG_INFO, "%s%s\n", filename, colon);
            }
        }
        free((void *)filename);
        if (NULL != action_source) {
            action_source_close(action_source);
            free(action_source);
            if (c->action_sources > 0) {
                c->action_sources--;
            }
        }
        bol = (char *)*id;
        *id = (*id)->next;
        free(bol);
    } while (rcv.cur != rcv.buf); /* clamd sends whole lines, so, on partial lines, we just assume
                                    more data can be recv()'d with close to zero latency */
    return 0;
}

static void free_scanids(struct client_parallel_data *c)
{
    struct SCANID *id;

    if (NULL == c) {
        return;
    }

    while (NULL != c->ids) {
        id     = c->ids;
        c->ids = id->next;

        if (c->report_stream &&
            clamdscan_write_client_failure_report(c->report_stream, id->file, CL_ERROR) != 0)
            c->errors++;
        free((void *)id->file);
        if (NULL != id->action_source) {
            action_source_close(id->action_source);
            free(id->action_source);
            if (c->action_sources > 0) {
                c->action_sources--;
            }
        }
        free(id);
    }
}

/* FTW callback for scanning in IDSESSION mode
 * Returns SUCCESS on success, CL_EXXX or BREAK on error */
static cl_error_t parallel_callback(STATBUF *sb, char *filename, const char *path, enum cli_ftw_reason reason, struct cli_ftw_cbdata *data)
{
    cl_error_t status = CL_EOPEN;

    struct client_parallel_data *c = (struct client_parallel_data *)data->data;
    struct SCANID *cid             = NULL;
    int res                        = 0;
    action_source_t *action_source = NULL;
    const char *scan_path          = filename;
    char *real_filter_path         = NULL;
    bool report_target             = (reason == visit_file);
    cl_error_t report_status       = CL_SUCCESS;

    UNUSEDPARAM(sb);
    UNUSEDPARAM(path);

    if (CL_SUCCESS != cli_realpath((const char *)filename, &real_filter_path)) {
        logg(LOGG_DEBUG, "Failed to determine real filename of %s.\n", filename);
    } else {
        scan_path = real_filter_path;
    }

    if (client_path_excluded(scan_path, &c->walk_policy)) {
        /* Exclude the path */
        status = CL_SUCCESS;
        goto done;
    }
    c->files++;
    switch (reason) {
        case error_stat:
            logg(LOGG_ERROR, "Can't access file %s\n", filename);
            c->errors++;
            report_target = true;
            report_status = CL_ESTAT;
            status = CL_SUCCESS;
            goto done;
        case error_mem:
            logg(LOGG_ERROR, "Memory allocation failed in ftw\n");
            c->errors++;
            report_target = true;
            report_status = CL_EMEM;
            status = CL_EMEM;
            goto done;
        case warning_skipped_dir:
            logg(LOGG_WARNING, "Directory recursion limit reached\n");
            c->errors++;
            c->printok      = 0;
            report_target   = true;
            report_status   = CL_EMAXREC;
            status = CL_SUCCESS;
            goto done;
        case warning_skipped_special:
            logg(LOGG_WARNING, "%s: Not supported file type\n", filename);
            c->errors++;
            report_target = true;
            report_status = CL_ERROR;
            /* fall-through */
        case warning_skipped_link:
        case visit_directory_toplev:
            status = CL_SUCCESS;
            goto done;
        case visit_file:
            break;
    }

    if (action) {
        while (c->action_sources >= c->max_action_sources) {
            if (dspresult(c)) {
                report_status = CL_ERROR;
                status = CL_BREAK;
                goto done;
            }
        }

        action_source = malloc(sizeof(*action_source));
        if (NULL == action_source) {
            logg(LOGG_ERROR, "Failed to allocate action source: %s\n", strerror(errno));
            c->errors++;
            report_status = CL_EMEM;
            status = CL_EMEM;
            goto done;
        }
        {
            cl_error_t action_status = action_source_open_path(filename, scan_path, action_source);
            if (CL_SUCCESS != action_status) {
                logg(LOGG_WARNING, "Can't open file %s for safe quarantine action.\n", filename);
                c->errors++;
                report_status = action_status;
                status = CL_SUCCESS;
                goto done;
            }
        }
    }

    while (1) {
        /* consume all the available input to let some of the clamd
         * threads blocked on send() to be dead.
         * by doing so we shouldn't deadlock on the next recv() */
        fd_set rfds, wfds;
        FD_ZERO(&rfds);
        FD_SET(c->sockd, &rfds);
        FD_ZERO(&wfds);
        FD_SET(c->sockd, &wfds);
        if (select(c->sockd + 1, &rfds, &wfds, NULL, NULL) < 0) {
            if (errno == EINTR) continue;
            logg(LOGG_ERROR, "select() failed during session: %s\n", strerror(errno));
            status = CL_BREAK;
            goto done;
        }
        if (FD_ISSET(c->sockd, &rfds)) {
            if (dspresult(c)) {
                report_status = CL_ERROR;
                status = CL_BREAK;
                goto done;
            } else
                continue;
        }
        if (FD_ISSET(c->sockd, &wfds)) break;
    }

    switch (c->scantype) {
#ifdef HAVE_FD_PASSING
        case FILDES:
            if (c->report_stream)
                res = (NULL != action_source)
                          ? send_fdpass_fd_report_checked(c->sockd, action_source->scan_fd,
                                                          action_source->display_path, clamdopts)
                          : send_fdpass_report_checked(c->sockd, scan_path, clamdopts);
            else
                res = (NULL != action_source)
                          ? send_fdpass_fd_checked(c->sockd, action_source->scan_fd,
                                                   action_source->display_path, clamdopts)
                          : send_fdpass_checked(c->sockd, scan_path, clamdopts);
            break;
#endif
        case STREAM:
            if (c->report_stream)
                res = (NULL != action_source) ? send_stream_fd_report(c->sockd, action_source->scan_fd, action_source->display_path, clamdopts) : send_stream_report(c->sockd, scan_path, clamdopts);
            else
                res = (NULL != action_source) ? send_stream_fd_action(c->sockd, action_source->scan_fd, action_source->display_path, clamdopts) : send_stream(c->sockd, scan_path, clamdopts);
            break;
    }
    if (res <= 0) {
        c->printok = 0;
        c->errors++;
        report_status = res ? CL_ERROR : CL_EOPEN;
        status = res ? CL_BREAK : CL_SUCCESS;
        goto done;
    }

    cid = (struct SCANID *)malloc(sizeof(struct SCANID));
    if (!cid) {
        logg(LOGG_ERROR, "Failed to allocate scanid entry: %s\n", strerror(errno));
        report_status = CL_EMEM;
        status = CL_BREAK;
        goto done;
    }

    cid->id            = ++c->lastid;
    cid->file          = filename;
    cid->action_source = action_source;
    cid->next          = c->ids;
    c->ids             = cid;
    if (NULL != action_source) {
        c->action_sources++;
    }

    /* Give up ownership of the filename to the client parallel scan ID list */
    filename      = NULL;
    action_source = NULL;

    status = CL_SUCCESS;

done:
    if (c->report_stream && report_target && NULL == cid &&
        clamdscan_write_client_failure_report(c->report_stream, filename, report_status) != 0)
        c->errors++;
    if (NULL != action_source) {
        action_source_close(action_source);
        free(action_source);
    }
    if (NULL != filename) {
        free(filename);
    }
    if (NULL != real_filter_path) {
        free(real_filter_path);
    }
    return status;
}

/* IDSESSION handler
 * Returns non zero for serious errors, zero otherwise */
int parallel_client_scan(char *file, int scantype, int *infected, int *err, int maxlevel, int flags, FILE *report_stream)
{
    struct cli_ftw_cbdata data;
    struct client_parallel_data cdata;
    int ftw;
    const char zIDSESSION[] = "zIDSESSION";
    const char zEND[]       = "zEND";

    if ((cdata.sockd = dconnect(clamdopts)) < 0) {
        if (report_stream && clamdscan_write_client_failure_report(report_stream, file, CL_EOPEN) != 0)
            logg(LOGG_ERROR, "Can't write structured scan report for %s\n", file);
        return 1;
    }

    if (sendln(cdata.sockd, zIDSESSION, sizeof(zIDSESSION))) {
        if (report_stream && clamdscan_write_client_failure_report(report_stream, file, CL_ERROR) != 0)
            logg(LOGG_ERROR, "Can't write structured scan report for %s\n", file);
        closesocket(cdata.sockd);
        return 1;
    }

    cdata.infected           = 0;
    cdata.files              = 0;
    cdata.errors             = 0;
    cdata.scantype           = scantype;
    cdata.lastid             = 0;
    cdata.ids                = NULL;
    cdata.printok            = printinfected ^ 1;
    cdata.report_stream      = report_stream;
    cdata.action_sources     = 0;
    cdata.max_action_sources = get_max_action_sources();
    client_walk_policy_init(&cdata.walk_policy, file);
    data.data = &cdata;

    ftw = cli_ftw(file, flags, maxlevel ? maxlevel : INT_MAX, parallel_callback, &data, ftw_chkpath);

    if (ftw != CL_SUCCESS) {
        free_scanids(&cdata);
        *err += cdata.errors;
        *infected += cdata.infected;
        closesocket(cdata.sockd);
        return 1;
    }

    sendln(cdata.sockd, zEND, sizeof(zEND));
    while (cdata.ids && !dspresult(&cdata)) continue;
    closesocket(cdata.sockd);

    if (cdata.ids) {
        logg(LOGG_ERROR, "Clamd closed the connection before scanning all files.\n");
        free_scanids(&cdata);
        *infected += cdata.infected;
        *err += cdata.errors;
        return 1;
    }
    *infected += cdata.infected;
    *err += cdata.errors;

    if (cdata.errors)
        return 1;

    if (!cdata.files)
        return 0;

    if (cdata.printok)
        logg(LOGG_INFO, "%s: OK\n", file);
    return 0;
}
