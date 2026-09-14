/*
 *  Copyright (C) 2015-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm, aCaB, Mickey Sola
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
#include <stdint.h>
#include <curl/curl.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#ifdef HAVE_FD_PASSING
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
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

#include "communication.h"
#include "protocol.h"
#include "client.h"
#include "socket.h"

static const char *scancmd[] = {"CONTSCAN", "MULTISCAN", "INSTREAM", "FILDES", "ALLMATCHSCAN"};

/* A signal must not turn a resumable source read into a truncated scan.  Keep
 * the retry local to the on-access stream path so genuine read failures still
 * retain their CL_EREAD classification at every call site. */
static ssize_t onas_read_retry(int fd, void *buffer, size_t length)
{
    ssize_t bytes;

    do {
        bytes = read(fd, buffer, length);
    } while (bytes < 0 && errno == EINTR);

    return bytes;
}

/* Issues an INSTREAM command to clamd and streams the given file
 * Returns >0 on success, 0 soft fail, -1 hard fail */
static int onas_send_stream(CURL *curl, const char *filename, int fd, int64_t timeout, uint64_t maxstream, bool action_stream, cl_error_t *ret_code)
{
    uint32_t buf[BUFSIZ / sizeof(uint32_t)];
    uint64_t len;
    int ret        = 1;
    int close_flag = 0;
    bool known_size;
    STATBUF statbuf;
    uint64_t bytesRead     = 0;
    const char zINSTREAM[] = "zINSTREAMREPORT";

    /* The public option contract maps zero to the bounded 32-GiB ceiling and
     * rejects larger values. Keep both sides defensive for callers that
     * construct the on-access context directly instead of going through
     * optparser; otherwise an unknown-size stream could bypass the hard
     * ingress ceiling even though regular-file preflight is bounded. */
    if (maxstream == 0 || maxstream > CLI_MAX_LARGE_FILESIZE)
        maxstream = CLI_MAX_LARGE_FILESIZE;

    if (-1 == fd) {
        if (NULL == filename) {
            logg(LOGG_ERROR, "onas_send_stream: Invalid args, a filename or file descriptor must be provided.\n");
            return 0;
        } else {
            if ((fd = safe_open(filename, O_RDONLY | O_BINARY)) < 0) {
                logg(LOGG_DEBUG, "%s: Failed to open file. ERROR\n", filename);
                return 0;
            }
            // logg(LOGG_INFO, "DEBUG: >>>>> fd is %d\n", fd);
            close_flag = 1;
        }
    }

    if (FSTAT(fd, &statbuf)) {
        logg(LOGG_ERROR, "onas_send_stream: Invalid args, bad file descriptor.\n");
        ret = -1;
        goto strm_out;
    }

    if (S_ISDIR(statbuf.st_mode)) {
        ret = 0;
        goto strm_out;
    }

    if (statbuf.st_size < 0) {
        logg(LOGG_ERROR, "%s: On-access stream input has an invalid negative size. ERROR\n",
             filename ? filename : "FD");
        if (ret_code)
            *ret_code = CL_ESTAT;
        ret = -1;
        goto strm_out;
    }

    known_size = S_ISREG(statbuf.st_mode);
    if (known_size && (uint64_t)statbuf.st_size > maxstream) {
        logg(LOGG_ERROR, "%s: File size exceeds the effective on-access stream limit; refusing to send a truncated stream. ERROR\n",
             filename ? filename : "FD");
        if (ret_code)
            *ret_code = CL_EMAXSIZE;
        ret = -1;
        goto strm_out;
    }

    if (known_size && lseek(fd, 0, SEEK_SET) == (off_t)-1) {
        logg(LOGG_ERROR, "%s: Failed to rewind the on-access stream input. ERROR\n",
             filename ? filename : "FD");
        if (ret_code)
            *ret_code = CL_ESEEK;
        ret = -1;
        goto strm_out;
    }

    if (onas_sendln(curl, zINSTREAM, sizeof(zINSTREAM), timeout, ret_code)) {
        ret = -1;
        goto strm_out;
    }

    /* Regular files have an admitted length. Pipes and other non-regular
     * descriptors are unknown-size streams and must be consumed up to the
     * bounded ceiling instead of being mistaken for empty files because
     * fstat().st_size is zero. */
    len = known_size ? (uint64_t)statbuf.st_size : maxstream;
    while (bytesRead < len) {
        uint64_t remaining = len - bytesRead;
        size_t read_len    = (remaining < sizeof(buf)) ? (size_t)remaining : sizeof(buf);
        ssize_t bytes      = onas_read_retry(fd, buf, read_len);
        uint32_t chunk_len;

        if (bytes < 0) {
            logg(LOGG_ERROR, "Failed to read from %s.\n", filename ? filename : "FD");
            /* A source read failure is distinct from a transport write
             * failure: preserve the local input classification for the
             * caller instead of allowing the generic fallback to report
             * CL_EWRITE. */
            if (ret_code)
                *ret_code = CL_EREAD;
            ret = -1;
            goto strm_out;
        } else if (0 == bytes) {
            if (known_size) {
                logg(LOGG_ERROR, "%s: Regular stream input ended before its admitted size. ERROR\n",
                     filename ? filename : "FD");
                if (ret_code)
                    *ret_code = CL_EREAD;
                ret = -1;
                goto strm_out;
            }
            /* EOF is the normal completion signal for pipes and other
             * unknown-size descriptors; do not send a zero-length chunk. */
            break;
        }
        bytesRead += bytes;

        chunk_len = htonl((uint32_t)bytes);
        if (onas_sendln(curl, (const char *)&chunk_len, sizeof(chunk_len), timeout, ret_code) ||
            onas_sendln(curl, (const char *)buf, (size_t)bytes, timeout, ret_code)) {
            ret = -1;
            goto strm_out;
        }
    }

    if (known_size && bytesRead < len) {
        logg(LOGG_ERROR, "%s: File changed while streaming; refusing to send a partial INSTREAM chunk. ERROR\n",
             filename ? filename : "FD");
        if (ret_code) {
            *ret_code = CL_EREAD;
        }
        ret = -1;
        goto strm_out;
    }

    /* A regular file may grow after the initial stat. Do not terminate an
     * ordinary on-access stream after the original length and report a clean
     * prefix; quarantine/action streams already used this check, but the
     * completeness invariant applies to every stream. */
    if (known_size && (bytesRead == len)) {
        ssize_t bytes = onas_read_retry(fd, buf, 1);

        if (bytes < 0) {
            logg(LOGG_ERROR, "Failed to read from %s.\n", filename ? filename : "FD");
            if (ret_code)
                *ret_code = CL_EREAD;
            ret = -1;
            goto strm_out;
        } else if (bytes > 0) {
            if (bytesRead >= maxstream) {
                logg(LOGG_ERROR, "%s: File size exceeds the effective on-access stream limit; refusing to send a truncated %s stream. ERROR\n",
                     filename ? filename : "FD", action_stream ? "quarantine" : "scan");
                if (ret_code) {
                    *ret_code = CL_EMAXSIZE;
                }
            } else {
                logg(LOGG_ERROR, "%s: File grew while streaming; refusing to send a partial %s stream. ERROR\n",
                     filename ? filename : "FD", action_stream ? "quarantine" : "scan");
                if (ret_code) {
                    *ret_code = CL_EREAD;
                }
            }
            ret = -1;
            goto strm_out;
        }
    }

    /* Unknown-size inputs are admitted one byte at a time beyond the final
     * full chunk.  If another byte exists, close the request without sending
     * a terminator so the daemon cannot mistake the bounded prefix for a
     * complete clean scan. */
    if (!known_size && bytesRead == len) {
        ssize_t bytes = onas_read_retry(fd, buf, 1);

        if (bytes > 0) {
            logg(LOGG_ERROR, "%s: Unknown-size input exceeds the effective on-access stream limit; refusing to send a truncated stream. ERROR\n",
                 filename ? filename : "FD");
            if (ret_code)
                *ret_code = CL_EMAXSIZE;
            ret = -1;
            goto strm_out;
        }
        if (bytes < 0) {
            logg(LOGG_ERROR, "Failed to read from %s.\n", filename ? filename : "FD");
            if (ret_code)
                *ret_code = CL_EREAD;
            ret = -1;
            goto strm_out;
        }
    }

    *buf = 0;
    if (onas_sendln(curl, (const char *)buf, 4, timeout, ret_code)) {
        ret = -1;
        goto strm_out;
    }

strm_out:
    if (close_flag) {
        close(fd);
    }
    return ret;
}

#ifdef HAVE_FD_PASSING
static uint64_t onas_fdpass_deadline(int64_t timeout_ms)
{
    struct timeval now;
    uint64_t now_ms;
    uint64_t wait_ms;

    if (timeout_ms <= 0 || gettimeofday(&now, NULL) != 0)
        return 0;

    now_ms  = (uint64_t)now.tv_sec * 1000U + (uint64_t)now.tv_usec / 1000U;
    wait_ms = (uint64_t)timeout_ms;
    if (wait_ms > UINT64_MAX - now_ms)
        return UINT64_MAX;
    return now_ms + wait_ms;
}

static int onas_fdpass_wait_writable(int sockd, uint64_t deadline_ms)
{
    struct timeval now;
    struct timeval wait;
    uint64_t now_ms;
    uint64_t remaining_ms;
    int result;

    for (;;) {
        fd_set writefds;
        fd_set errorfds;

        /* Reinitialize select's mutable arguments after every EINTR and
         * recompute the remaining time from the operation deadline. */
        if (gettimeofday(&now, NULL) != 0)
            return -1;

        now_ms = (uint64_t)now.tv_sec * 1000U + (uint64_t)now.tv_usec / 1000U;
        if (deadline_ms == 0) {
            remaining_ms = 0;
        } else if (now_ms >= deadline_ms) {
            errno = ETIMEDOUT;
            return 0;
        } else {
            remaining_ms = deadline_ms - now_ms;
        }

        wait.tv_sec  = (long)(remaining_ms / 1000U);
        wait.tv_usec = (long)((remaining_ms % 1000U) * 1000U);
        FD_ZERO(&writefds);
        FD_ZERO(&errorfds);
        FD_SET(sockd, &writefds);
        FD_SET(sockd, &errorfds);

        result = select(sockd + 1, NULL, &writefds, &errorfds, &wait);
        if (result >= 0 || errno != EINTR)
            return result;
    }
}

static int onas_fdpass_deadline_reached(uint64_t deadline_ms)
{
    struct timeval now;
    uint64_t now_ms;

    if (!deadline_ms || gettimeofday(&now, NULL) != 0)
        return 0;

    now_ms = (uint64_t)now.tv_sec * 1000U + (uint64_t)now.tv_usec / 1000U;
    return now_ms >= deadline_ms;
}

static int onas_fdpass_send_bytes(int sockd, const void *buffer, size_t length,
                                  int64_t timeout_ms, cl_error_t *ret_code)
{
    const char *cursor = (const char *)buffer;
    size_t remaining   = length;
    uint64_t deadline_ms;

    if (!buffer || sockd < 0)
        return -1;

    deadline_ms = onas_fdpass_deadline(timeout_ms);
    while (remaining) {
        ssize_t sent;

        do {
            if (onas_fdpass_deadline_reached(deadline_ms)) {
                logg(LOGG_ERROR, "ClamCom: TIMEOUT while sending on fd-passing socket\n");
                if (ret_code && *ret_code == CL_SUCCESS)
                    *ret_code = CL_ETIMEOUT;
                return -1;
            }
#ifdef MSG_NOSIGNAL
            sent = send(sockd, cursor, remaining, MSG_NOSIGNAL);
#else
            sent = send(sockd, cursor, remaining, 0);
#endif
        } while (sent < 0 && errno == EINTR);

        if (sent > 0) {
            cursor += sent;
            remaining -= (size_t)sent;
            continue;
        }

        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            int wait_result = onas_fdpass_wait_writable(sockd, deadline_ms);
            if (wait_result > 0)
                continue;
            if (wait_result == 0) {
                logg(LOGG_ERROR, "ClamCom: TIMEOUT while waiting on fd-passing socket (send)\n");
                if (ret_code && *ret_code == CL_SUCCESS)
                    *ret_code = CL_ETIMEOUT;
            } else if (ret_code && *ret_code == CL_SUCCESS) {
                *ret_code = CL_EWRITE;
            }
            return -1;
        }

        logg(LOGG_ERROR, "Can't send to clamd over fd-passing socket: %s\n", strerror(errno));
        if (ret_code && *ret_code == CL_SUCCESS)
            *ret_code = CL_EWRITE;
        return -1;
    }

    return 0;
}

static int onas_send_fdpass(int sockd, int fd, int64_t timeout_ms, cl_error_t *ret_code)
{

    char dummy[] = "";
    struct iovec iov[1];
    struct msghdr msg;
    struct cmsghdr *cmsg;
    unsigned char fdbuf[CMSG_SPACE(sizeof(int))];
    const char zFILDES[] = "zFILDESREPORT";

    if (onas_fdpass_send_bytes(sockd, zFILDES, sizeof(zFILDES), timeout_ms, ret_code)) {
        return -1;
    }

    iov[0].iov_base = dummy;
    iov[0].iov_len  = 1;
    memset(&msg, 0, sizeof(msg));
    msg.msg_control         = fdbuf;
    msg.msg_iov             = iov;
    msg.msg_iovlen          = 1;
    msg.msg_controllen      = CMSG_LEN(sizeof(int));
    cmsg                    = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_len          = CMSG_LEN(sizeof(int));
    cmsg->cmsg_level        = SOL_SOCKET;
    cmsg->cmsg_type         = SCM_RIGHTS;
    *(int *)CMSG_DATA(cmsg) = fd;

    {
        ssize_t sent;
        uint64_t deadline_ms = onas_fdpass_deadline(timeout_ms);

        do {
            if (onas_fdpass_deadline_reached(deadline_ms)) {
                logg(LOGG_ERROR, "ClamCom: TIMEOUT while sending FD on fd-passing socket\n");
                if (ret_code && *ret_code == CL_SUCCESS)
                    *ret_code = CL_ETIMEOUT;
                return -1;
            }
#ifdef MSG_NOSIGNAL
            sent = sendmsg(sockd, &msg, MSG_NOSIGNAL);
#else
            sent = sendmsg(sockd, &msg, 0);
#endif
            if (sent < 0 && errno == EINTR)
                continue;
            if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                int wait_result = onas_fdpass_wait_writable(sockd, deadline_ms);
                if (wait_result > 0)
                    continue;
                if (wait_result == 0) {
                    logg(LOGG_ERROR, "ClamCom: TIMEOUT while waiting on fd-passing socket (sendmsg)\n");
                    if (ret_code && *ret_code == CL_SUCCESS)
                        *ret_code = CL_ETIMEOUT;
                } else if (ret_code && *ret_code == CL_SUCCESS) {
                    *ret_code = CL_EWRITE;
                }
                return -1;
            }
            break;
        } while (1);

        if (sent != (ssize_t)iov[0].iov_len) {
            if (sent < 0) {
                logg(LOGG_ERROR, "FD send failed: %s\n", strerror(errno));
            } else {
                logg(LOGG_ERROR, "FD send was incomplete (%zd of %zu bytes)\n", sent, iov[0].iov_len);
            }
            if (ret_code && *ret_code == CL_SUCCESS)
                *ret_code = CL_EWRITE;
            return -1;
        }
    }

    return 1;
}

/* Issues a FILDES command and pass a FD to clamd
 * Returns >0 on success, 0 soft fail, -1 hard fail */
static int onas_fdpass(const char *filename, int fd, int sockd, uint64_t maxstream,
                       int64_t timeout_ms, cl_error_t *ret_code)
{
    int ret        = 1;
    int close_flag = 0;
    STATBUF statbuf;

    /* The option parser rejects values above the fork's hard ceiling and maps
     * zero to that ceiling. Keep the protocol boundary defensive for callers
     * that construct an on-access context directly. */
    if (maxstream == 0 || maxstream > CLI_MAX_LARGE_FILESIZE)
        maxstream = CLI_MAX_LARGE_FILESIZE;

    if (-1 == fd) {
        if (filename) {
            if ((fd = open(filename, O_RDONLY)) < 0) {
                logg(LOGG_DEBUG, "%s: Failed to open file. ERROR\n", filename);
                return 0;
            }
            close_flag = 1;
        } else {
            fd = -1;
        }
    }

    if (sockd == -1) {
        logg(LOGG_DEBUG, "ClamProto: error when getting socket descriptor\n");
        ret = -1;
        goto fd_out;
    }

    if (FSTAT(fd, &statbuf) != 0) {
        logg(LOGG_ERROR, "%s: Failed to stat FILDES input. ERROR\n",
             filename ? filename : "FD");
        if (ret_code)
            *ret_code = CL_ESTAT;
        ret = -1;
        goto fd_out;
    }

    if (statbuf.st_size < 0) {
        logg(LOGG_ERROR, "%s: On-access FILDES input has an invalid negative size. ERROR\n",
             filename ? filename : "FD");
        if (ret_code)
            *ret_code = CL_ESTAT;
        ret = -1;
        goto fd_out;
    }

    if (S_ISREG(statbuf.st_mode) && (uint64_t)statbuf.st_size > maxstream) {
        logg(LOGG_ERROR, "%s: File size exceeds the effective on-access FILDES limit; refusing to pass the descriptor. ERROR\n",
             filename ? filename : "FD");
        if (ret_code)
            *ret_code = CL_EMAXSIZE;
        ret = -1;
        goto fd_out;
    }

    ret = onas_send_fdpass(sockd, fd, timeout_ms, ret_code);

    if (ret < 0) {
        logg(LOGG_DEBUG, "ClamProto: error when fdpassing\n");
        ret = -1;
        goto fd_out;
    }

fd_out:
    if (close_flag) {
        close(fd);
    }
    return ret;
}
#endif

/* Sends a proper scan request to clamd and parses its replies
 * This is used only in non IDSESSION mode
 * Returns the number of infected files or -1 on error
 * NOTE: filename may be NULL for STREAM scantype. */
int onas_dsresult(CURL *curl, int scantype, uint64_t maxstream, const char *filename, const action_source_t *action_source,
                  int fd, int64_t timeout, int *printok, int *errors, cl_error_t *ret_code)
{
    int infected = 0, len = 0, beenthere = 0;
    char *bol, *eol;
    size_t command_len;
    size_t command_prefix_len;
    size_t filename_len;
    int formatted_len;
    struct onas_rcvln rcv;
    STATBUF sb;
    int sockd                                                        = -1;
    int (*recv_func)(struct onas_rcvln *, char **, char **, int64_t) = NULL;
    const char *display_filename                                     = (NULL != action_source) ? action_source->display_path : filename;
    int scan_fd                                                      = (NULL != action_source) ? action_source->scan_fd : fd;

#ifdef HAVE_FD_PASSING
    if (FILDES == scantype) {
        sockd = onas_get_sockd(timeout, ret_code);
    }
#endif

    onas_recvlninit(&rcv, curl, sockd);
    if ((FILDES == scantype) && (rcv.sockd >= 0)) {
        recv_func = &onas_fd_recvln;
    } else {
        recv_func = &onas_recvln;
    }

    switch (scantype) {
        case MULTI:
        case CONT:
        case ALLMATCH:
            if (!filename) {
                logg(LOGG_INFO, "Filename cannot be NULL for MULTISCAN or CONTSCAN.\n");
                if (ret_code) {
                    *ret_code = CL_ENULLARG;
                }
                infected = -1;
                goto done;
            }
            command_prefix_len = strlen(scancmd[scantype]) + strlen("zREPORT ");
            filename_len       = strlen(filename);
            if (filename_len > SIZE_MAX - command_prefix_len ||
                filename_len + command_prefix_len == SIZE_MAX) {
                logg(LOGG_ERROR, "Scan command length overflow for on-access path.\n");
                if (ret_code) {
                    *ret_code = CL_EMEM;
                }
                infected = -1;
                goto done;
            }
            command_len = filename_len + command_prefix_len + 1;
            if (!(bol = malloc(command_len))) {
                logg(LOGG_ERROR, "Cannot allocate a command buffer: %s\n", strerror(errno));
                if (ret_code) {
                    *ret_code = CL_EMEM;
                }
                infected = -1;
                goto done;
            }
            formatted_len = snprintf(bol, command_len, "z%sREPORT %s", scancmd[scantype], filename);
            if (formatted_len < 0 || (size_t)formatted_len >= command_len) {
                logg(LOGG_ERROR, "Cannot format the on-access scan command.\n");
                free(bol);
                if (ret_code) {
                    *ret_code = CL_EFORMAT;
                }
                infected = -1;
                goto done;
            }
            if (onas_sendln(curl, bol, command_len, timeout, ret_code)) {
                if (ret_code && *ret_code == CL_SUCCESS) {
                    *ret_code = CL_EWRITE;
                }
                free(bol);
                infected = -1;
                goto done;
            }
            free(bol);
            /* Path-based commands have been sent successfully.  Keep the
             * common transport guard from treating the zero-byte command
             * setup as an unsent scan request. */
            len = 1;
            break;

        case STREAM:
            /* NULL filename safe in send_stream() */
            len = onas_send_stream(curl, display_filename, scan_fd, timeout, maxstream, NULL != action_source, ret_code);
            break;
#ifdef HAVE_FD_PASSING
        case FILDES:
            /* NULL filename safe in send_fdpass() */
            len = onas_fdpass(display_filename, scan_fd, sockd, maxstream, timeout, ret_code);
            break;
#endif
    }

    if (len <= 0) {
        *printok = 0;
        /* A request that was not sent is never a clean scan.  In particular,
         * a mutable path can disappear between the event and safe_open(), but
         * treating that zero-length result as a successful skip would let the
         * caller label an uninspected file clean.  Monitoring-only mode may
         * still allow the event; it must receive an explicit non-clean status
         * so the omission remains visible, and prevention mode can deny it. */
        if (errors) {
            (*errors)++;
        }
        if (ret_code && (CL_SUCCESS == *ret_code)) {
            *ret_code = (len == 0) ? CL_EOPEN : CL_EWRITE;
        }
        infected = -1;
        goto done;
    }

    /* All on-access scan modes use the versioned framed report protocol. A
     * non-detection incomplete report is an error, never an implicit clean;
     * detections retain precedence when a multi-frame request contains both. */
    {
        int report_infected   = 0;
        int report_incomplete = 0;
        cl_error_t report_status = CL_SUCCESS;

        if (onas_recv_scan_report(&rcv, timeout, &report_infected,
                                  &report_incomplete, &report_status) < 0) {
            if (ret_code && *ret_code == CL_SUCCESS)
                *ret_code = (rcv.curlcode == CURLE_OPERATION_TIMEDOUT) ? CL_ETIMEOUT : CL_EREAD;
            if (errors)
                (*errors)++;
            *printok = 0;
            infected = -1;
            goto done;
        }

        if (report_incomplete && !report_infected) {
            if (ret_code) {
                *ret_code = (report_status == CL_SUCCESS || report_status == CL_VERIFIED ||
                             report_status == CL_VIRUS)
                                ? CL_EPARSE
                                : report_status;
            }
            if (errors)
                (*errors)++;
            *printok = 0;
            infected = -1;
            logg(LOGG_INFO, "%s: structured clamd report incomplete (%s)\n",
                 display_filename ? display_filename : "FD", cl_strerror(report_status));
            goto done;
        }

        if (report_infected) {
            *printok = 0;
            if (ret_code)
                *ret_code = CL_VIRUS;
            infected = 1;
            if (display_filename)
                logg(LOGG_INFO, "%s FOUND\n", display_filename);
            if (action && NULL != action_source)
                action(action_source);
            goto done;
        }

        *printok = 1;
        infected = 0;
        if (ret_code)
            *ret_code = CL_SUCCESS;
        goto done;
    }

    while ((len = (*recv_func)(&rcv, &bol, &eol, timeout))) {

        if (len == -1) {

            if (ret_code) {
                *ret_code = (rcv.curlcode == CURLE_OPERATION_TIMEDOUT) ? CL_ETIMEOUT : CL_EREAD;
            }
            infected = -1;
            goto done;
        }
        beenthere = 1;
        if (!display_filename) {
            logg(LOGG_INFO, "%s\n", bol);
        }
        if (len > 7) {
            char *colon = strrchr(bol, ':');

            if (colon && colon[1] != ' ') {
                char *br;
                *colon = 0;

                br = strrchr(bol, '(');
                if (br) {
                    *br = 0;
                }
                colon = strrchr(bol, ':');
            }

            if (!colon) {
                char *unkco = "UNKNOWN COMMAND";
                if (!strncmp(bol, unkco, sizeof(unkco) - 1)) {
                    logg(LOGG_DEBUG, "clamd replied \"UNKNOWN COMMAND\". Command was %s\n",
                         (scantype < 0 || scantype > MAX_SCANTYPE) ? "unidentified" : scancmd[scantype]);
                } else {
                    logg(LOGG_DEBUG, "Failed to parse reply: \"%s\"\n", bol);
                }

                if (ret_code) {
                    *ret_code = CL_EPARSE;
                }
                infected = -1;
                goto done;

            } else if (!memcmp(eol - 7, " FOUND", 6)) {
                static char last_filename[PATH_MAX + 1] = {'\0'};
                *(eol - 7)                              = 0;
                *printok                                = 0;

                if (scantype != ALLMATCH) {
                    infected++;
                } else {
                    if (filename != NULL && strcmp(filename, last_filename)) {
                        infected++;
                        strncpy(last_filename, filename, PATH_MAX);
                        last_filename[PATH_MAX] = '\0';
                    }
                }

                if (display_filename) {
                    if (scantype >= STREAM) {
                        logg(LOGG_INFO, "%s%s FOUND\n", display_filename, colon);
                        if (action) {
                            if (NULL != action_source) {
                                action(action_source);
                            }
                        }
                    } else {
                        logg(LOGG_INFO, "%s FOUND\n", bol);
                        *colon = '\0';
                        if (action) {
                            if (NULL != action_source) {
                                action(action_source);
                            }
                        }
                    }
                }

                if (ret_code) {
                    *ret_code = CL_VIRUS;
                }

            } else if ((len > 32 && !memcmp(eol - 33, "No such file or directory. ERROR", 32)) ||
                       (len > 34 && !memcmp(eol - 35, "Can't open file or directory ERROR", 34))) {
                if (errors) {
                    (*errors)++;
                }
                *printok = 0;

                if (display_filename) {
                    (scantype >= STREAM) ? logg(LOGG_DEBUG, "%s%s\n", display_filename, colon) : logg(LOGG_DEBUG, "%s\n", bol);
                }

                if (ret_code) {
                    *ret_code = CL_ESTAT;
                }
            } else if ((len > 21 && !memcmp(eol - 22, " Access denied. ERROR", 21)) ||
                       (len > 23 && !memcmp(eol - 24, "Can't access file ERROR", 23)) ||
                       (len > 41 && !memcmp(eol - 42, " lstat() failed: Permission denied. ERROR", 41))) {
                if (errors) {
                    (*errors)++;
                }
                *printok = 0;

                if (display_filename) {
                    (scantype >= STREAM) ? logg(LOGG_INFO, "%s%s\n", display_filename, colon) : logg(LOGG_INFO, "%s\n", bol);
                }

                if (ret_code) {
                    *ret_code = CL_EACCES;
                }
            } else if (len > 6 && !memcmp(eol - 7, " ERROR", 6)) {
                if (errors) {
                    (*errors)++;
                }
                *printok = 0;

                if (display_filename) {
                    (scantype >= STREAM) ? logg(LOGG_INFO, "%s%s\n", display_filename, colon) : logg(LOGG_INFO, "%s\n", bol);
                }

                if (ret_code) {
                    *ret_code = CL_ERROR;
                }
            }
        }
    }
    if (!beenthere) {
        if (!display_filename) {
            logg(LOGG_INFO, "STDIN: noreply from clamd\n.");
            if (ret_code) {
                *ret_code = CL_EACCES;
            }
            infected = -1;
            goto done;
        }
        if (CLAMSTAT(display_filename, &sb) == -1) {
            logg(LOGG_INFO, "%s: stat() failed with %s, clamd may not be responding\n",
                 display_filename, strerror(errno));
            if (ret_code) {
                *ret_code = CL_EACCES;
            }
            infected = -1;
            goto done;
        }
        if (!S_ISDIR(sb.st_mode)) {
            logg(LOGG_INFO, "%s: no reply from clamd\n", display_filename);
            if (ret_code) {
                *ret_code = CL_EACCES;
            }
            infected = -1;
            goto done;
        }
    }

done:
    if (sockd >= 0) {
        closesocket(sockd);
    }
    return infected;
}
