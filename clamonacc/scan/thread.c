/*
 *  Copyright (C) 2015-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Mickey Sola
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
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>

#if defined(HAVE_SYS_FANOTIFY_H)
#include <sys/fanotify.h>
#endif

// libclamav
#include "others.h"

// common
#include "optparser.h"
#include "output.h"

#include "../misc/priv_fts.h"
#include "../misc/utils.h"
#include "../client/client.h"
#include "thread.h"
#if defined(HAVE_SYS_FANOTIFY_H)
#include "../fanotif/fanotif.h"
#endif

static pthread_mutex_t onas_scan_lock = PTHREAD_MUTEX_INITIALIZER;

static int onas_scan(struct onas_scan_event *event_data, const char *fname, STATBUF sb, int *infected, int *err, cl_error_t *ret_code);
static cl_error_t onas_scan_safe(struct onas_scan_event *event_data, const char *fname, STATBUF sb, int *infected, int *err, cl_error_t *ret_code);
static cl_error_t onas_scan_thread_scanfile(struct onas_scan_event *event_data, const char *fname, STATBUF sb, int *infected, int *err, cl_error_t *ret_code);
static cl_error_t onas_scan_thread_handle_dir(struct onas_scan_event *event_data, const char *pathname);
static cl_error_t onas_scan_thread_handle_file(struct onas_scan_event *event_data, const char *pathname);

/**
 * @brief Safe-scan wrapper, originally used by inotify and fanotify threads, now exists for error checking/convenience.
 *
 * Owned by scanthread to try to force multithreaded client architecture which better avoids kernel level deadlocks from
 * fanotify blocking/prevention.
 */
static int onas_scan(struct onas_scan_event *event_data, const char *fname, STATBUF sb, int *infected, int *err, cl_error_t *ret_code)
{
    int ret                = 0;
    int i                  = 0;
    uint8_t retry_on_error = event_data->bool_opts & ONAS_SCTH_B_RETRY_ON_E;

    ret = onas_scan_safe(event_data, fname, sb, infected, err, ret_code);

    if (*err) {
        switch (*ret_code) {
            case CL_EACCES:
            case CL_ESTAT:
                logg(LOGG_DEBUG, "ClamMisc: Scan issue; Daemon could not find or access: %s)\n", fname);
                break;
                /* TODO: handle other errors */
            case CL_EPARSE:
                logg(LOGG_INFO, "ClamMisc: Internal issue; Failed to parse reply from daemon: %s)\n", fname);
                break;
            case CL_EREAD:
            case CL_EWRITE:
            case CL_EMEM:
            case CL_ENULLARG:
            case CL_ERROR:
            default:
                logg(LOGG_INFO, "ClamMisc: Unexpected issue; Daemon failed to scan: %s\n", fname);
        }
        if (retry_on_error) {
            logg(LOGG_DEBUG, "ClamMisc: reattempting scan ... \n");
            while (*err && i < event_data->retry_attempts) {
                ret = onas_scan_safe(event_data, fname, sb, infected, err, ret_code);

                i++;
            }
        }
    }

    return ret;
}

/**
 * @brief Thread-safe scan wrapper to ensure there's no process contention over use of the socket.
 *
 * This is noticeably slower, and I had no issues running smaller scale tests with it off, but better than sorry until more testing can be done.
 *
 * TODO: make this configurable?
 */
static cl_error_t onas_scan_safe(struct onas_scan_event *event_data, const char *fname, STATBUF sb, int *infected, int *err, cl_error_t *ret_code)
{

    int ret = 0;
    int fd  = -1;

#if defined(HAVE_SYS_FANOTIFY_H)
    uint8_t b_fanotify;

    b_fanotify = event_data->bool_opts & ONAS_SCTH_B_FANOTIFY ? 1 : 0;

    if (b_fanotify) {
        fd = event_data->fmd->fd;
    }
#endif

    pthread_mutex_lock(&onas_scan_lock);

    ret = onas_client_scan(event_data->tcpaddr, event_data->portnum, event_data->scantype, event_data->maxstream, event_data->sizelimit,
                           fname, fd, event_data->timeout, sb, infected, err, ret_code);

    pthread_mutex_unlock(&onas_scan_lock);

    return ret;
}

static cl_error_t onas_scan_thread_scanfile(struct onas_scan_event *event_data, const char *fname, STATBUF sb, int *infected, int *err, cl_error_t *ret_code)
{

#if defined(HAVE_SYS_FANOTIFY_H)
    struct fanotify_response res;
    uint8_t b_fanotify;
#endif

    int ret = 0;

    uint8_t b_scan;
    uint8_t b_deny_on_error;

    if (NULL == event_data || NULL == fname || NULL == infected || NULL == err || NULL == ret_code) {
        logg(LOGG_ERROR, "ClamWorker: scan failed (NULL arg given)\n");
        return CL_ENULLARG;
    }

    b_scan          = event_data->bool_opts & ONAS_SCTH_B_SCAN ? 1 : 0;
    b_deny_on_error = event_data->bool_opts & ONAS_SCTH_B_DENY_ON_E ? 1 : 0;

#if defined(HAVE_SYS_FANOTIFY_H)
    b_fanotify = event_data->bool_opts & ONAS_SCTH_B_FANOTIFY ? 1 : 0;
    if (b_fanotify) {
        if (NULL == event_data->fmd || event_data->fmd->fd < 0 || event_data->fan_fd < 0) {
            *err      = 1;
            *ret_code = CL_EARG;
            logg(LOGG_ERROR, "ClamWorker: scan failed (invalid fanotify event context)\n");
            if (event_data->fmd != NULL && event_data->fmd->fd >= 0) {
                (void)onas_release_failed_event(event_data->fan_fd, event_data->fmd);
                event_data->fmd->fd = -1;
            }
            return CL_EARG;
        }
        res.fd       = event_data->fmd->fd;
        res.response = FAN_ALLOW;
    }
#endif

    if (b_scan) {
        ret = onas_scan(event_data, fname, sb, infected, err, ret_code);

        if (*err && *ret_code != CL_SUCCESS) {
            logg(LOGG_DEBUG, "ClamWorker: scan failed with error code %d\n", *ret_code);
        }
    }

#if defined(HAVE_SYS_FANOTIFY_H)
    /* Preflight failures (stat/size limits) deliberately clear b_scan so the
     * worker does not submit an invalid or partial object.  They still must
     * deny a permission event when prevention mode is configured; otherwise
     * an incomplete scan would silently become an allow.  Monitoring-only
     * events leave the default allow response and merely log the failure. */
    if (b_fanotify && ((*err && b_deny_on_error) || *infected)) {
        res.response = FAN_DENY;
    }
#endif

#if defined(HAVE_SYS_FANOTIFY_H)
    if (b_fanotify) {
        if (event_data->fmd->mask & FAN_ALL_PERM_EVENTS) {
            ssize_t written;

            do {
                written = write(event_data->fan_fd, &res, sizeof(res));
            } while (written == -1 && errno == EINTR);

            if (written != (ssize_t)sizeof(res)) {
                int response_errno = written < 0 ? errno : EIO;

                logg(LOGG_ERROR, "ClamWorker: internal error (can't write complete response to fanotify): %s\n",
                     strerror(response_errno));
                if (response_errno == ENOENT) {
                    logg(LOGG_DEBUG, "ClamWorker: permission event has already been written ... recovering ...\n");
                }
                /* An allow response that was not accepted must not become an
                 * implicit allow when the metadata descriptor is released.
                 * Try the shared denial-and-close path, then mark the copied
                 * descriptor closed so cleanup does not issue a second close. */
                (void)onas_release_failed_event(event_data->fan_fd, event_data->fmd);
                event_data->fmd->fd = -1;
                ret                = CL_EWRITE;
            }
        }
    }

    if (b_fanotify) {

#ifdef ONAS_DEBUG
        logg(LOGG_DEBUG, "ClamWorker: closing fd, %d)\n", event_data->fmd->fd);
#endif
        if (event_data->fmd->fd >= 0 && -1 == close(event_data->fmd->fd)) {

            logg(LOGG_ERROR, "ClamWorker: internal error (can't close fanotify meta fd, %d)\n", event_data->fmd->fd);
            if (errno == EBADF) {
                logg(LOGG_DEBUG, "ClamWorker: fd already closed ... recovering ...\n");
            } else {
                ret = CL_EUNLINK;
            }
        }
    }
#endif
    return ret;
}

static cl_error_t onas_scan_thread_handle_dir(struct onas_scan_event *event_data, const char *pathname)
{
    FTS *ftsp        = NULL;
    int32_t ftspopts = FTS_NOCHDIR | FTS_PHYSICAL | FTS_XDEV;
    FTSENT *curr     = NULL;

    int32_t infected    = 0;
    int32_t err         = 0;
    cl_error_t ret_code = CL_SUCCESS;
    cl_error_t ret      = CL_SUCCESS;
    cl_error_t scan_ret = CL_SUCCESS;

    int32_t fres = 0;
    STATBUF sb;

    char *const pathargv[] = {(char *)pathname, NULL};

    if (NULL == event_data || NULL == pathname) {
        return CL_ENULLARG;
    }

    if (!(ftsp = _priv_fts_open(pathargv, ftspopts, NULL))) {
        ret = CL_EOPEN;
        goto out;
    }

    while (1) {
        /* fts_read() reports an unrecoverable walk failure as NULL with errno
         * set.  Reset errno for each call so a previous scan operation cannot
         * be mistaken for a traversal failure at end of walk. */
        errno = 0;
        curr  = _priv_fts_read(ftsp);
        if (NULL == curr) {
            if (errno != 0) {
                logg(LOGG_ERROR, "ClamWorker: directory traversal of '%s' failed at end of walk (errno %d)\n", pathname, errno);
                if (CL_SUCCESS == ret) {
                    ret = CL_ESTAT;
                }
            }
            break;
        }

        switch (curr->fts_info) {
            case FTS_D:
            case FTS_DP:
            case FTS_DC:
            case FTS_DOT:
            case FTS_W:
                /* Directories are traversed, not submitted as scan files. */
                continue;
            case FTS_F:
            case FTS_SL:
            case FTS_SLNONE:
                break;
            case FTS_DNR:
            case FTS_ERR:
            case FTS_NS:
                logg(LOGG_ERROR, "ClamWorker: incomplete directory traversal of '%s' (FTS status %d, errno %d)\n",
                     curr->fts_path ? curr->fts_path : pathname, curr->fts_info, curr->fts_errno);
                if (CL_SUCCESS == ret) {
                    ret = CL_ESTAT;
                }
                continue;
            default:
                logg(LOGG_ERROR, "ClamWorker: unknown FTS status %d for '%s'; refusing to treat the directory as complete\n",
                     curr->fts_info, curr->fts_path ? curr->fts_path : pathname);
                if (CL_SUCCESS == ret) {
                    ret = CL_ESTAT;
                }
                continue;
        }

        fres = CLAMSTAT(curr->fts_path, &sb);
        if (fres != 0) {
            logg(LOGG_ERROR, "ClamWorker: unable to stat '%s' during directory traversal; treating the extra scan as incomplete\n",
                 curr->fts_path);
            if (CL_SUCCESS == ret) {
                ret = CL_ESTAT;
            }
            continue;
        }

        if (sb.st_size < 0) {
            logg(LOGG_ERROR, "ClamWorker: invalid negative size for '%s' during directory traversal; treating the extra scan as incomplete\n",
                 curr->fts_path);
            if (CL_SUCCESS == ret) {
                ret = CL_ESTAT;
            }
            continue;
        }

        if (event_data->sizelimit && (uint64_t)sb.st_size > event_data->sizelimit) {
            /* Inotify extra scans have no permission response to deny.  Skip
             * only this object, keep scanning independent siblings, and
             * return a non-clean status so the omission is observable. */
            logg(LOGG_DEBUG, "ClamWorker: size limit surpassed while doing extra scanning; skipping '%s'\n", curr->fts_path);
            if (CL_SUCCESS == ret) {
                ret = CL_EMAXSIZE;
            }
            continue;
        }

        infected = 0;
        err      = 0;
        ret_code = CL_SUCCESS;
        scan_ret = onas_scan_thread_scanfile(event_data, curr->fts_path, sb, &infected, &err, &ret_code);
        if (CL_SUCCESS == ret && CL_SUCCESS != scan_ret) {
            ret = scan_ret;
        }
        if (err && CL_SUCCESS == ret && CL_SUCCESS != ret_code && CL_VIRUS != ret_code) {
            ret = ret_code;
        }
    }

out:
    if (ftsp) {
        if (_priv_fts_close(ftsp) != 0) {
            logg(LOGG_ERROR, "ClamWorker: could not close directory traversal of '%s'; treating the extra scan as incomplete\n", pathname);
            if (CL_SUCCESS == ret) {
                ret = CL_ESTAT;
            }
        }
    }

    return ret;
}

static cl_error_t onas_scan_thread_handle_file(struct onas_scan_event *event_data, const char *pathname)
{

    STATBUF sb;
    int32_t infected    = 0;
    int32_t err         = 0;
    cl_error_t ret_code = CL_SUCCESS;
    int fres            = 0;
    cl_error_t ret      = 0;

    if (NULL == pathname || NULL == event_data) {
        return CL_ENULLARG;
    }

    /* Keep the value passed to the scan/permission-response helper defined
     * even when the path disappears between the kernel event and stat().
     * The helper still sees b_scan cleared and must not submit this object,
     * but passing an indeterminate STATBUF by value is undefined behavior. */
    memset(&sb, 0, sizeof(sb));
    fres = CLAMSTAT(pathname, &sb);
    if (fres != 0) {
        err      = 1;
        ret_code = CL_ESTAT;
        /* Do not pass an uninitialized STATBUF to the client.  For a
         * permission event, the fanotify response below will deny access when
         * prevention is enabled; monitoring-only mode may log and continue. */
        event_data->bool_opts &= ((uint16_t)~ONAS_SCTH_B_SCAN);
        logg(LOGG_DEBUG, "ClamWorker: unable to stat '%s'; treating the permission event as incomplete\n", pathname);
    }
    if (fres == 0 && sb.st_size < 0) {
        err      = 1;
        ret_code = CL_ESTAT;
        event_data->bool_opts &= ((uint16_t)~ONAS_SCTH_B_SCAN);
        logg(LOGG_DEBUG, "ClamWorker: invalid negative size for '%s'; treating the permission event as incomplete\n", pathname);
    }
    if (event_data->sizelimit) {
        if (fres != 0 || (fres == 0 && sb.st_size >= 0 && (uint64_t)sb.st_size > event_data->sizelimit)) {
            /* don't skip so we avoid lockups, but don't scan either;
             * while it should be obvious, this will unconditionally set
             * the bit in the map to 0 regardless of original orientation */
            event_data->bool_opts &= ((uint16_t)~ONAS_SCTH_B_SCAN);
            if (fres == 0) {
                err      = 1;
                ret_code = CL_EMAXSIZE;
                logg(LOGG_DEBUG, "ClamWorker: '%s' exceeds OnAccessMaxFileSize; treating the permission event as incomplete\n", pathname);
            }
        }
    }

    ret = onas_scan_thread_scanfile(event_data, pathname, sb, &infected, &err, &ret_code);

    /* A preflight failure deliberately disables submission, so the scanfile
     * helper can still return success after delivering a fanotify response.
     * Preserve the skipped scan's status for inotify callers and diagnostics. */
    if (CL_SUCCESS == ret && err && CL_SUCCESS != ret_code && CL_VIRUS != ret_code) {
        ret = ret_code;
    }

#ifdef ONAS_DEBUG
    /* very noisy, debug only */
    if (event_data->bool_opts & ONAS_SCTH_B_INOTIFY) {
        logg(LOGG_DEBUG, "ClamWorker: Inotify Scan Results ...\n\tret = %d ...\n\tinfected = %d ...\n\terr = %d ...\n\tret_code = %d\n",
             ret, infected, err, ret_code);
    } else {
        logg(LOGG_DEBUG, "ClamWorker: Fanotify Scan Results ...\n\tret = %d ...\n\tinfected = %d ...\n\terr = %d ...\n\tret_code = %d\n\tfd = %d\n",
             ret, infected, err, ret_code, event_data->fmd->fd);
    }
#endif

    return ret;
}

/**
 * @brief worker thread designed to work with the lovely c-thread-pool library to handle our scanning jobs after our queue thread consumes an event
 *
 * @param arg this should always be an onas_scan_event struct
 */
void *onas_scan_worker(void *arg)
{

    struct onas_scan_event *event_data = (struct onas_scan_event *)arg;

    uint8_t b_dir;
    uint8_t b_file;
    uint8_t b_inotify;
    uint8_t b_fanotify;

    if (NULL == event_data || NULL == event_data->pathname) {
        logg(LOGG_INFO, "ClamWorker: invalid worker arguments for scanning thread\n");
        if (event_data) {
            logg(LOGG_INFO, "ClamWorker: pathname is null\n");
#if defined(HAVE_SYS_FANOTIFY_H)
            if (event_data->fmd) {
                onas_release_failed_event(event_data->fan_fd, event_data->fmd);
            }
#endif
        }
        goto done;
    }

    /* load in boolean info from event struct; makes for easier reading--you're welcome */
    b_dir      = event_data->bool_opts & ONAS_SCTH_B_DIR ? 1 : 0;
    b_file     = event_data->bool_opts & ONAS_SCTH_B_FILE ? 1 : 0;
    b_inotify  = event_data->bool_opts & ONAS_SCTH_B_INOTIFY ? 1 : 0;
    b_fanotify = event_data->bool_opts & ONAS_SCTH_B_FANOTIFY ? 1 : 0;

#if defined(HAVE_SYS_FANOTIFY_H)
    if (b_inotify) {
        logg(LOGG_DEBUG, "ClamWorker: handling inotify event ...\n");

        if (b_dir) {
            logg(LOGG_DEBUG, "ClamWorker: performing (extra) scanning on directory '%s'\n", event_data->pathname);
            cl_error_t dir_ret = onas_scan_thread_handle_dir(event_data, event_data->pathname);
            if (CL_SUCCESS != dir_ret) {
                logg(LOGG_INFO, "ClamWorker: extra directory scan of '%s' was incomplete (status %d)\n", event_data->pathname, dir_ret);
            }
        } else if (b_file) {
            logg(LOGG_DEBUG, "ClamWorker: performing (extra) scanning on file '%s'\n", event_data->pathname);
            cl_error_t file_ret = onas_scan_thread_handle_file(event_data, event_data->pathname);
            if (CL_SUCCESS != file_ret) {
                logg(LOGG_INFO, "ClamWorker: extra file scan of '%s' was incomplete (status %d)\n", event_data->pathname, file_ret);
            }
        }

    } else if (b_fanotify) {

        logg(LOGG_DEBUG, "ClamWorker: performing scanning on file '%s'\n", event_data->pathname);
        cl_error_t file_ret = onas_scan_thread_handle_file(event_data, event_data->pathname);
        if (CL_SUCCESS != file_ret) {
            logg(LOGG_INFO, "ClamWorker: permission scan of '%s' was incomplete (status %d)\n", event_data->pathname, file_ret);
        }
    } else {
        /* something went very wrong, so check if we have an open fd,
         * try to close it to resolve any potential lingering permissions event,
         * then move to cleanup */
        if (event_data->fmd) {
            if (event_data->fmd->fd >= 0) {
                onas_release_failed_event(event_data->fan_fd, event_data->fmd);
                goto done;
            }
        }
    }
#endif
done:
    /* our job to cleanup event data: worker queue just kicks us off in a thread pool, drops the event object
     * from the queue and forgets about us */

    if (NULL != event_data) {
        if (NULL != event_data->pathname) {
            free(event_data->pathname);
            event_data->pathname = NULL;
        }

#if defined(HAVE_SYS_FANOTIFY_H)
        if (NULL != event_data->fmd) {
            free(event_data->fmd);
            event_data->fmd = NULL;
        }
#endif
        free(event_data);
        event_data = NULL;
    }

    return NULL;
}

/**
 * @brief Simple utility function for external interfaces to add relevant context information to scan_event struct.
 *
 * Doing this mapping cuts down significantly on memory overhead when queueing hundreds of these scan_event structs
 * especially vs using a copy of a raw context struct.
 *
 * Other potential design options include giving the event access to the "global" context struct address instead,
 * to further cut down on space used, but (among other thread safety concerns) I'd prefer the worker threads not
 * have the ability to modify it at all to keep down on potential maintenance headaches in the future.
 */
cl_error_t onas_map_context_info_to_event_data(struct onas_context *ctx, struct onas_scan_event **event_data)
{

    if (NULL == ctx || NULL == event_data || NULL == *event_data) {
        logg(LOGG_DEBUG, "ClamScThread: context and scan event struct are null ...\n");
        return CL_ENULLARG;
    }

    (*event_data)->scantype       = ctx->scantype;
    (*event_data)->timeout        = ctx->timeout;
    (*event_data)->maxstream      = ctx->maxstream;
    (*event_data)->fan_fd         = ctx->fan_fd;
    (*event_data)->sizelimit      = ctx->sizelimit;
    (*event_data)->retry_attempts = ctx->retry_attempts;

    if (ctx->retry_on_error) {
        (*event_data)->bool_opts |= ONAS_SCTH_B_RETRY_ON_E;
    }

    if (ctx->deny_on_error) {
        (*event_data)->bool_opts |= ONAS_SCTH_B_DENY_ON_E;
    }

    if (ctx->isremote) {
        (*event_data)->bool_opts |= ONAS_SCTH_B_REMOTE;
        (*event_data)->tcpaddr = optget(ctx->clamdopts, "TCPAddr")->strarg;
        (*event_data)->portnum = ctx->portnum;
    } else {
        (*event_data)->tcpaddr = optget(ctx->clamdopts, "LocalSocket")->strarg;
    }

    return CL_SUCCESS;
}
