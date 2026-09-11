/*
 *  Copyright (C) 2020-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Author: Mickey Sola
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

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#ifdef HAVE_FD_PASSING
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/time.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#endif

#include "clamav.h"
#include "output.h"

#include "optparser.h"
#include "../clamonacc.h"
#include "socket.h"
#include "platform.h"

#ifdef HAVE_FD_PASSING
struct onas_sock_t onas_sock = {.written = 0};
#endif

/**
 * One time socket setup for unix file descriptor passing
 *
 * @param ctx a pointer to the onas context struct
 * @param allow_fdpass true if fd passing is enabled or required by this scan mode
 * @return CL_SUCCESS if writing to socket struct was successful, CL_EWRITE if the socket has already been written to
 */
cl_error_t onas_set_sock_only_once(struct onas_context *ctx, bool allow_fdpass)
{

    const struct optstruct *opt;

#ifdef HAVE_FD_PASSING
    if (onas_sock.written != 1) {
        if (((opt =
                  optget(ctx->clamdopts, "LocalSocket"))
                 ->enabled) &&
            allow_fdpass) {
            memset((void *)&onas_sock, 0, sizeof(onas_sock));
            onas_sock.sock.sun_family = AF_UNIX;
            strncpy(onas_sock.sock.sun_path, opt->strarg, sizeof(onas_sock.sock.sun_path));
            onas_sock.sock.sun_path[sizeof(onas_sock.sock.sun_path) - 1] = '\0';
            onas_sock.written                                            = 1;
            return CL_SUCCESS;
        }
    }
#endif

    return CL_EWRITE;
}

/**
 * Retrieves a working socket descriptor for unix fdpassing
 *
 * @return Returns socket descriptor on success, -1 on failure
 */
#ifdef HAVE_FD_PASSING
static uint64_t onas_connect_deadline(int64_t timeout_ms)
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

static int onas_connect_wait(int sockd, uint64_t deadline_ms)
{
    struct timeval now;
    struct timeval wait;
    uint64_t now_ms;
    uint64_t remaining_ms;
    int result;

    for (;;) {
        fd_set writefds;
        fd_set errorfds;

        /* select() may modify both the fd sets and timeout, including when it
         * is interrupted. Rebuild them from the absolute deadline for every
         * retry so EINTR cannot turn a bounded connect into an unbounded one. */
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
#endif

int onas_get_sockd(int64_t timeout_ms, cl_error_t *ret_code)
{

#ifdef HAVE_FD_PASSING

    int sockd = 0;
    int flags;
    int wait_result;
    int connect_error;
    socklen_t connect_error_len;
    uint64_t deadline_ms;

    if (onas_sock.written && (sockd = socket(AF_UNIX, SOCK_STREAM, 0)) >= 0) {
        flags = fcntl(sockd, F_GETFL, 0);
        if (flags < 0 || fcntl(sockd, F_SETFL, flags | O_NONBLOCK) < 0) {
            logg(LOGG_ERROR, "ClamSock: Could not make the fd-passing socket nonblocking\n");
            if (ret_code && *ret_code == CL_SUCCESS)
                *ret_code = CL_ECREAT;
            closesocket(sockd);
            return -1;
        }

        deadline_ms = onas_connect_deadline(timeout_ms);
#ifdef SO_NOSIGPIPE
        {
            int no_sigpipe = 1;
            if (setsockopt(sockd, SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe, sizeof(no_sigpipe)) < 0) {
                logg(LOGG_ERROR, "ClamSock: Could not disable SIGPIPE on the fd-passing socket\n");
                if (ret_code && *ret_code == CL_SUCCESS)
                    *ret_code = CL_ECREAT;
                closesocket(sockd);
                return -1;
            }
        }
#endif
        if (connect(sockd, (struct sockaddr *)&onas_sock.sock, sizeof(onas_sock.sock)) == 0)
            return sockd;

        if (errno == EINPROGRESS) {
            wait_result = onas_connect_wait(sockd, deadline_ms);
            if (wait_result > 0) {
                connect_error     = 0;
                connect_error_len = sizeof(connect_error);
                if (getsockopt(sockd, SOL_SOCKET, SO_ERROR, &connect_error, &connect_error_len) == 0 &&
                    connect_error == 0)
                    return sockd;
                if (connect_error != 0)
                    errno = connect_error;
            } else if (wait_result == 0) {
                logg(LOGG_ERROR, "ClamSock: Timed out connecting to clamd on LocalSocket\n");
                if (ret_code && *ret_code == CL_SUCCESS)
                    *ret_code = CL_ETIMEOUT;
                closesocket(sockd);
                return -1;
            }
        }

        {
            logg(LOGG_ERROR, "ClamSock: Could not connect to clamd on LocalSocket \n");
            if (ret_code && *ret_code == CL_SUCCESS)
                *ret_code = CL_ECREAT;
            closesocket(sockd);
        }
    }
    else if (ret_code && *ret_code == CL_SUCCESS) {
        *ret_code = CL_ECREAT;
    }
#endif
    return -1;
}
