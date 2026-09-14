/*
 *  Copyright (C) 2019-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

#if defined(HAVE_SYS_FANOTIFY_H)

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <sys/fanotify.h>

// libclamav
#include "clamav.h"
#include "scanners.h"

// common
#include "optparser.h"
#include "output.h"

// clamd
#include "server.h"

#include "../inotif/hash.h"
#include "../inotif/inotif.h"

#include "../client/client.h"

#include "../scan/thread.h"
#include "../scan/onas_queue.h"

#include "../misc/utils.h"

#include "fanotif.h"

extern pthread_t ddd_pid;
extern pthread_t scan_queue_pid;
static int onas_fan_fd = -1;

static int onas_wait_for_fanotify(int fan_fd)
{
    fd_set rfds;
    int ret;

    do {
        /* select() mutates the descriptor set; rebuild it for every wait so
         * an idle period cannot leave the next wait watching no descriptors. */
        FD_ZERO(&rfds);
        FD_SET(fan_fd, &rfds);
        ret = select(fan_fd + 1, &rfds, NULL, NULL, NULL);
    } while (ret == -1 && errno == EINTR);

    return ret;
}

/* A permission event must receive a decision even when the event cannot be
 * represented as a queue item. Closing its metadata fd without a response
 * can leave the requesting task blocked or turn an operational failure into
 * an unintended allow. Reject failed-to-queue events before releasing the
 * kernel-owned descriptor. */
int onas_release_failed_event(int fan_fd, const struct fanotify_event_metadata *fmd)
{
    int ret = 0;

    if (NULL == fmd || fmd->fd < 0) {
        return 0;
    }

    if (fmd->mask & FAN_ALL_PERM_EVENTS) {
        struct fanotify_response response;
        ssize_t written;

        response.fd       = fmd->fd;
        response.response = FAN_DENY;
        do {
            written = write(fan_fd, &response, sizeof(response));
        } while (written == -1 && errno == EINTR);
        if (written != (ssize_t)sizeof(response)) {
            int response_errno = written < 0 ? errno : EIO;

            logg(LOGG_ERROR, "ClamFanotif: failed to deny an unqueued permission event: %s\n", strerror(response_errno));
            ret = -1;
        }
    }

    if (close(fmd->fd) == -1) {
        int close_errno = errno;

        if (close_errno != EBADF) {
            logg(LOGG_ERROR, "ClamFanotif: failed to close a failed event descriptor: %s\n", strerror(close_errno));
            ret = -1;
        }
    }

    return ret;
}

cl_error_t onas_setup_fanotif(struct onas_context **ctx)
{

    const struct optstruct *pt;
    uint64_t fan_mask = FAN_EVENT_ON_CHILD;

    const struct optstruct *pt_tmpdir;
    const char *clamd_tmpdir;

    ddd_pid = 0;

    if (!ctx || !*ctx) {
        logg(LOGG_ERROR, "ClamFanotif: unable to start clamonacc. (bad context)\n");
        return CL_EARG;
    }

    onas_fan_fd      = (*ctx)->fan_fd;
    (*ctx)->fan_mask = fan_mask;

    if (optget((*ctx)->clamdopts, "OnAccessPrevention")->enabled && !optget((*ctx)->clamdopts, "OnAccessMountPath")->enabled) {
        logg(LOGG_DEBUG, "ClamFanotif: kernel-level blocking feature enabled ... preventing malicious files access attempts\n");
        (*ctx)->fan_mask |= FAN_ACCESS_PERM | FAN_OPEN_PERM;
    } else {
        logg(LOGG_DEBUG, "ClamFanotif: kernel-level blocking feature disabled ...\n");
        if (optget((*ctx)->clamdopts, "OnAccessPrevention")->enabled && optget((*ctx)->clamdopts, "OnAccessMountPath")->enabled) {
            logg(LOGG_DEBUG, "ClamFanotif: feature not available when watching mounts ... \n");
        }
        (*ctx)->fan_mask |= FAN_ACCESS | FAN_OPEN;
    }

    pt_tmpdir = optget((*ctx)->clamdopts, "TemporaryDirectory");
    if (pt_tmpdir->enabled) {
        clamd_tmpdir = pt_tmpdir->strarg;
    } else {
        clamd_tmpdir = cli_gettmpdir();
    }

    if ((pt = optget((*ctx)->clamdopts, "OnAccessMountPath"))->enabled) {
        while (pt) {
            /* dirfd is a pathname-resolution descriptor, not the fanotify
             * event descriptor.  Absolute paths still require AT_FDCWD on
             * kernels that validate this argument. */
            if (fanotify_mark(onas_fan_fd, FAN_MARK_ADD | FAN_MARK_MOUNT, (*ctx)->fan_mask, AT_FDCWD, pt->strarg) != 0) {
                logg(LOGG_ERROR, "ClamFanotif: can't include mountpoint '%s': %s\n", pt->strarg, strerror(errno));
                return CL_EARG;
            } else {
                logg(LOGG_DEBUG, "ClamFanotif: recursively watching the mount point '%s'\n", pt->strarg);
            }
            pt = (struct optstruct *)pt->nextarg;
        }

    } else if (!optget((*ctx)->clamdopts, "OnAccessDisableDDD")->enabled) {
        (*ctx)->ddd_enabled = 1;
    } else {
        if ((pt = optget((*ctx)->clamdopts, "OnAccessIncludePath"))->enabled) {
            while (pt) {
                if (0 == strcmp(clamd_tmpdir, pt->strarg)) {
                    logg(LOGG_ERROR, "ClamFanotif: Not watching path '%s'\n", pt->strarg);
                    logg(LOGG_ERROR, "ClamFanotif: ClamOnAcc should not watch the directory clamd is using for temp files\n");
                    logg(LOGG_ERROR, "ClamFanotif: Consider setting TemporaryDirectory in clamd.conf to a different directory.\n");
                    pt = (struct optstruct *)pt->nextarg;
                    continue;
                }

                if (fanotify_mark(onas_fan_fd, FAN_MARK_ADD, (*ctx)->fan_mask, AT_FDCWD, pt->strarg) != 0) {
                    logg(LOGG_ERROR, "ClamFanotif: can't include path '%s': %s\n", pt->strarg, strerror(errno));
                    return CL_EARG;
                } else {
                    logg(LOGG_DEBUG, "ClamFanotif: watching directory '%s' (non-recursively)\n", pt->strarg);
                }
                pt = (struct optstruct *)pt->nextarg;
            }
        } else {
            logg(LOGG_ERROR, "ClamFanotif: please specify at least one path with OnAccessIncludePath\n");
            return CL_EARG;
        }
    }

    /* Load other options. */
    (*ctx)->sizelimit = optget((*ctx)->clamdopts, "OnAccessMaxFileSize")->numarg;
    if ((*ctx)->sizelimit) {
        logg(LOGG_DEBUG, "ClamFanotif: max file size limited to %lu bytes\n", (*ctx)->sizelimit);
    } else {
        logg(LOGG_DEBUG, "ClamFanotif: file size limit disabled\n");
    }

    return CL_SUCCESS;
}

int onas_fan_eloop(struct onas_context **ctx)
{
    int ret     = 0;
    int err_cnt = 0;
    short int scan;
    char buf[4096];
    ssize_t bread;
    struct fanotify_event_metadata *fmd;
    char proc_fd_fname[1024];
    char fname[1024];
    ssize_t len;
    int check;

    logg(LOGG_DEBUG, "ClamFanotif: starting fanotify event loop with process id (%d) ... \n", getpid());
    ret = onas_wait_for_fanotify((*ctx)->fan_fd);
    if (ret <= 0) {
        logg(LOGG_ERROR, "ClamFanotif: failed waiting for fanotify input ... %s\n",
             ret == 0 ? "watch descriptor was not ready" : strerror(errno));
        return 2;
    }

    time_t start = time(NULL) - 30;
    while (1) {
        /* errno is only meaningful when read() returns a negative result.
         * Clear it before each read so a recovered EOVERFLOW/EMFILE/EACCES
         * cannot be mistaken for an error on the next successful batch. */
        errno = 0;
        bread = read((*ctx)->fan_fd, buf, sizeof(buf));
        if (bread <= 0) {
            if (bread < 0) {
                switch (errno) {
                    case EOVERFLOW:
                        if (time(NULL) - start >= 30) {
                            logg(LOGG_DEBUG, "ClamFanotif: internal error (failed to read data) ... %s\n", strerror(errno));
                            logg(LOGG_DEBUG, "ClamFanotif: file too large for fanotify ... recovering and continuing scans...\n");
                            start = time(NULL);
                        }
                        continue;
                    case EACCES:
                        logg(LOGG_DEBUG, "ClamFanotif: internal error (failed to read data) ... %s\n", strerror(errno));
                        logg(LOGG_DEBUG, "ClamFanotif: check your SELinux audit logs and consider adding an exception \
						... recovering and continuing scans...\n");
                        continue;
                    case EMFILE:
                        logg(LOGG_DEBUG, "ClamFanotif: internal error (failed to read data) ... %s\n", strerror(errno));
                        logg(LOGG_DEBUG, "ClamFanotif: waiting for consumer thread to catch up then retrying ...\n");
                        sleep(3);
                        continue;
                    default:
                        break;
                }
            }
            break;
        }

        fmd = (struct fanotify_event_metadata *)buf;
        while (FAN_EVENT_OK(fmd, bread)) {
            if (fmd->vers != FANOTIFY_METADATA_VERSION) {
                onas_release_failed_event((*ctx)->fan_fd, fmd);
                logg(LOGG_ERROR, "ClamFanotif: Mismatch of fanotify metadata version.\n");
                return 2;
            }
            scan = 1;
            if (fmd->fd >= 0) {
                sprintf(proc_fd_fname, "/proc/self/fd/%d", fmd->fd);
                errno = 0;
                len   = readlink(proc_fd_fname, fname, sizeof(fname));
                if (len == -1) {
                    int readlink_errno = errno;

                    onas_release_failed_event((*ctx)->fan_fd, fmd);
                    logg(LOGG_ERROR, "ClamFanotif: internal error (readlink() failed), %d, %s\n", fmd->fd, strerror(readlink_errno));
                    if (readlink_errno == EBADF) {
                        logg(LOGG_INFO, "ClamWorker: fd already closed ... recovering ...\n");
                        fmd = FAN_EVENT_NEXT(fmd, bread);
                        continue;
                    } else {
                        return 2;
                    }
                }
                if (len >= (ssize_t)sizeof(fname)) {
                    if (onas_release_failed_event((*ctx)->fan_fd, fmd) != 0)
                        return 2;
                    logg(LOGG_ERROR, "ClamFanotif: pathname for event fd %d exceeds the supported length; refusing the event\n", fmd->fd);
                    fmd = FAN_EVENT_NEXT(fmd, bread);
                    continue;
                }
                fname[len] = '\0';

                if ((check = onas_fan_checkowner(fmd->pid, (*ctx)->clamdopts))) {
                    scan = 0;
                    if (check != CHK_SELF) {
                        logg(LOGG_DEBUG, "ClamFanotif: %s skipped (excluded UID)\n", fname);
                    }
                }

                if (scan) {
                    struct onas_scan_event *event_data;

                    event_data = calloc(1, sizeof(struct onas_scan_event));
                    if (NULL == event_data) {
                        onas_release_failed_event((*ctx)->fan_fd, fmd);
                        logg(LOGG_ERROR, "ClamFanotif: could not allocate memory for event data struct\n");
                        return 2;
                    }

                    /* general mapping */
                    if (CL_SUCCESS != onas_map_context_info_to_event_data(*ctx, &event_data)) {
                        onas_release_failed_event((*ctx)->fan_fd, fmd);
                        free(event_data);
                        logg(LOGG_ERROR, "ClamFanotif: could not map context into event data\n");
                        return 2;
                    }
                    scan ? event_data->bool_opts |= ONAS_SCTH_B_SCAN : scan;

                    /* fanotify specific stuffs */
                    event_data->bool_opts |= ONAS_SCTH_B_FANOTIFY;
                    event_data->fmd = malloc(sizeof(struct fanotify_event_metadata));
                    if (NULL == event_data->fmd) {
                        onas_release_failed_event((*ctx)->fan_fd, fmd);
                        free(event_data);
                        logg(LOGG_ERROR, "ClamFanotif: could not allocate memory for event data struct fmd\n");
                        return 2;
                    }
                    memcpy(event_data->fmd, fmd, sizeof(struct fanotify_event_metadata));
                    event_data->pathname = cli_safer_strdup(fname);
                    if (NULL == event_data->pathname) {
                        onas_release_failed_event((*ctx)->fan_fd, fmd);
                        free(event_data->fmd);
                        free(event_data);
                        logg(LOGG_ERROR, "ClamFanotif: could not allocate memory for event data struct pathname\n");
                        return 2;
                    }

                    logg(LOGG_DEBUG, "ClamFanotif: attempting to feed consumer queue\n");
                    /* feed consumer queue */
                    if (CL_SUCCESS != onas_queue_event(event_data)) {
                        /* A permission event cannot be retried after its
                         * decision is written.  Deny it now because queue
                         * admission failed before a scan could complete. */
                        if (fmd->mask & FAN_ALL_PERM_EVENTS) {
                            onas_release_failed_event((*ctx)->fan_fd, fmd);
                            free(event_data->pathname);
                            free(event_data->fmd);
                            free(event_data);
                            logg(LOGG_ERROR, "ClamFanotif: permission event was denied because the scan queue rejected it\n");
                            return 2;
                        }
                        close(fmd->fd);
                        free(event_data->pathname);
                        free(event_data->fmd);
                        free(event_data);
                        logg(LOGG_ERROR, "ClamFanotif: error occurred while feeding consumer queue ... \n");
                        if ((*ctx)->retry_on_error) {
                            err_cnt++;
                            if (err_cnt < (*ctx)->retry_attempts) {
                                logg(LOGG_INFO, "ClamFanotif: ... recovering ...\n");
                                fmd = FAN_EVENT_NEXT(fmd, bread);
                                continue;
                            }
                        }
                        return 2;
                    }
                } else {
                    if (fmd->mask & FAN_ALL_PERM_EVENTS) {
                        struct fanotify_response res;
                        ssize_t written;

                        res.fd       = fmd->fd;
                        res.response = FAN_ALLOW;

                        do {
                            written = write((*ctx)->fan_fd, &res, sizeof(res));
                        } while (written == -1 && errno == EINTR);

                        if (written != (ssize_t)sizeof(res)) {
                            onas_release_failed_event((*ctx)->fan_fd, fmd);
                            logg(LOGG_ERROR, "ClamFanotif: error occurred while excluding event\n");
                            return 2;
                        }
                    }

                    if (-1 == close(fmd->fd)) {
                        logg(LOGG_ERROR, "ClamFanotif: error occurred while closing metadata fd, %d\n", fmd->fd);
                        if (errno == EBADF) {
                            logg(LOGG_INFO, "ClamFanotif: fd already closed ... recovering ...\n");
                        } else {
                            return 2;
                        }
                    }
                }
            }
            fmd = FAN_EVENT_NEXT(fmd, bread);
        }
        ret = onas_wait_for_fanotify((*ctx)->fan_fd);
        if (ret <= 0) {
            logg(LOGG_ERROR, "ClamFanotif: failed waiting for fanotify input ... %s\n",
                 ret == 0 ? "watch descriptor was not ready" : strerror(errno));
            return 2;
        }
    }

    if (bread < 0) {
        logg(LOGG_ERROR, "ClamFanotif: internal error (failed to read data) ... %s\n", strerror(errno));
        return 2;
    }

    return ret;
}
#endif
