/*
 *  Copyright (C) 2015-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009-2010 Sourcefire, Inc.
 *
 *  Author: aCaB, Mickey Sola
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
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <curl/curl.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <errno.h>

#if !defined(_WIN32)
#include <arpa/inet.h>
#include <sys/socket.h>
#endif

// libclamav
#include "clamav.h"

// shared
#include "output.h"

// common
#include "clamdcom.h"

#include "communication.h"

static int onas_socket_wait(curl_socket_t sockfd, int32_t b_recv, uint64_t timeout_ms);

static int onas_recv_bytes(struct onas_rcvln *rcv_data, void *buffer,
                           size_t length, int64_t timeout_ms)
{
    unsigned char *cursor = (unsigned char *)buffer;
    uint64_t wait_timeout = timeout_ms > 0 ? (uint64_t)timeout_ms : 0;

    if (!rcv_data || !buffer)
        return -1;

    while (length) {
        size_t received = 0;

        if (rcv_data->sockd >= 0) {
            int wait_result = onas_socket_wait(rcv_data->sockd, 1, wait_timeout);
            ssize_t result;

            if (wait_result <= 0) {
                rcv_data->curlcode = (wait_result == 0) ? CURLE_OPERATION_TIMEDOUT : CURLE_RECV_ERROR;
                return -1;
            }

            do {
                result = recv(rcv_data->sockd, cursor,
                              length,
                              0);
            } while (result < 0 && errno == EINTR);

            if (result <= 0) {
                rcv_data->curlcode = CURLE_RECV_ERROR;
                return -1;
            }
            received = (size_t)result;
        } else {
            curl_socket_t sockfd;
            CURLcode curlcode;

#if ((LIBCURL_VERSION_MAJOR > 7) || (LIBCURL_VERSION_MAJOR == 7 && LIBCURL_VERSION_MINOR >= 45))
            curlcode = curl_easy_getinfo(rcv_data->curl, CURLINFO_ACTIVESOCKET, &sockfd);
#else
            long long_sockfd;
            curlcode = curl_easy_getinfo(rcv_data->curl, CURLINFO_LASTSOCKET, &long_sockfd);
            sockfd   = (curl_socket_t)long_sockfd;
#endif
            if (CURLE_OK != curlcode) {
                rcv_data->curlcode = curlcode;
                return -1;
            }

            do {
                curlcode = curl_easy_recv(rcv_data->curl, cursor, length, &received);
                if (CURLE_AGAIN == curlcode) {
                    int wait_result = onas_socket_wait(sockfd, 1, wait_timeout);
                    if (wait_result <= 0) {
                        rcv_data->curlcode = (wait_result == 0) ? CURLE_OPERATION_TIMEDOUT : CURLE_RECV_ERROR;
                        return -1;
                    }
                }
            } while (CURLE_AGAIN == curlcode);

            if (CURLE_OK != curlcode || received == 0) {
                rcv_data->curlcode = (CURLE_OK == curlcode) ? CURLE_RECV_ERROR : curlcode;
                return -1;
            }
        }

        cursor += received;
        length -= received;
    }

    return 0;
}

/**
 * Function from curl example code, Copyright (C) 1998 - 2018, Daniel Stenberg, see COPYING.curl for license details
 */
static int onas_socket_wait(curl_socket_t sockfd, int32_t b_recv, uint64_t timeout_ms)
{
    struct timeval tv;
    fd_set infd, outfd, errfd;
    int ret;

    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    FD_ZERO(&infd);
    FD_ZERO(&outfd);
    FD_ZERO(&errfd);

    FD_SET(sockfd, &errfd); /* always check for error */

    if (b_recv) {
        FD_SET(sockfd, &infd);
    } else {
        FD_SET(sockfd, &outfd);
    }

    /* select() returns the number of signalled sockets or -1 */
    ret = select((int)sockfd + 1, &infd, &outfd, &errfd, &tv);

    return ret;
}

/* Sends bytes over a socket
 * Returns 0 on success */
int onas_sendln(CURL *curl, const void *line, size_t len, int64_t timeout, cl_error_t *ret_code)
{
    size_t sent = 0;
    CURLcode curlcode;
    curl_socket_t sockfd;

#if ((LIBCURL_VERSION_MAJOR > 7) || (LIBCURL_VERSION_MAJOR == 7 && LIBCURL_VERSION_MINOR >= 45))
    /* Use new CURLINFO_ACTIVESOCKET option */
    curlcode = curl_easy_getinfo(curl, CURLINFO_ACTIVESOCKET, &sockfd);
#else
    /* Use deprecated CURLINFO_LASTSOCKET option */
    long long_sockfd;
    curlcode = curl_easy_getinfo(curl, CURLINFO_LASTSOCKET, &long_sockfd);
    sockfd   = (curl_socket_t)long_sockfd;
#endif

    if (CURLE_OK != curlcode) {
        logg(LOGG_ERROR, "ClamCom: could not get curl active socket info %s\n", curl_easy_strerror(curlcode));
        if (ret_code && *ret_code == CL_SUCCESS) {
            *ret_code = CL_EWRITE;
        }
        return 1;
    }

    while (len) {

        do {
            curlcode = curl_easy_send(curl, line, len, &sent);
            if (CURLE_AGAIN == curlcode) {
                int wait_result = onas_socket_wait(sockfd, 0, timeout);
                if (wait_result <= 0) {
                    if (wait_result == 0) {
                        logg(LOGG_ERROR, "ClamCom: TIMEOUT while waiting on socket (send)\n");
                        if (ret_code && *ret_code == CL_SUCCESS) {
                            *ret_code = CL_ETIMEOUT;
                        }
                    } else if (ret_code && *ret_code == CL_SUCCESS) {
                        *ret_code = CL_EWRITE;
                    }
                    return 1;
                }
            } else if (CURLE_OK != curlcode) {
                if (ret_code && *ret_code == CL_SUCCESS) {
                    *ret_code = CL_EWRITE;
                }
                return 1;
            }
        } while (CURLE_AGAIN == curlcode);

        if (sent == 0) {
            if (errno == EINTR) {
                continue;
            } else if (errno == EFAULT) {
                /* Users have reported frequent "bad address" errors when files
                   are created & removed before the file can be sent to be
                   scanned. This isn't a critical error, so we'll log it in
                   verbose-mode only. */
                logg(LOGG_DEBUG, "Can't send to clamd: %s\n", strerror(errno));
            } else {
                logg(LOGG_ERROR, "Can't send to clamd: %s\n", strerror(errno));
            }

            if (ret_code && *ret_code == CL_SUCCESS) {
                *ret_code = CL_EWRITE;
            }

            return 1;
        }

        line += sent;
        len -= sent;
    }

    return 0;
}

/* Inits a RECVLN struct before it can be used in recvln() - see below */
void onas_recvlninit(struct onas_rcvln *rcv_data, CURL *curl, int sockd)
{
    rcv_data->curl     = curl;
    rcv_data->curlcode = CURLE_OK;
    rcv_data->lnstart = rcv_data->curr = rcv_data->buf;
    rcv_data->retlen                   = 0;
    rcv_data->sockd                    = sockd;
}

int onas_recv_scan_report(struct onas_rcvln *rcv_data, int64_t timeout_ms,
                          int *infected, int *incomplete, cl_error_t *status_out)
{
    int received = 0;

    if (!rcv_data || !infected || !incomplete || !status_out)
        return -1;

    *infected   = 0;
    *incomplete = 0;
    *status_out = CL_SUCCESS;

    for (;;) {
        uint32_t network_length;
        uint32_t length;
        char *payload;
        int frame_infected   = 0;
        int frame_incomplete = 0;
        cl_error_t frame_status = CL_ERROR;

        if (onas_recv_bytes(rcv_data, &network_length, sizeof(network_length), timeout_ms) < 0)
            return -1;

        length = ntohl(network_length);
        if (length == 0)
            return received ? 0 : -1;
        if (length > CLAMD_SCAN_REPORT_MAX_FRAME)
            return -1;

        payload = (char *)malloc((size_t)length + 1U);
        if (!payload)
            return -1;
        if (onas_recv_bytes(rcv_data, payload, length, timeout_ms) < 0) {
            free(payload);
            return -1;
        }
        payload[length] = '\0';

        if (scan_report_json_status(payload, length, &frame_infected,
                                    &frame_incomplete, &frame_status) < 0) {
            free(payload);
            return -1;
        }

        received = 1;
        if (frame_infected) {
            *infected = 1;
            *status_out = CL_VIRUS;
        } else if (frame_incomplete) {
            *incomplete = 1;
            if (!*infected &&
                (*status_out == CL_SUCCESS || *status_out == CL_ERROR || *status_out == CL_EPARSE))
                *status_out = frame_status;
        }
        free(payload);
    }
}

/* Receives a full (terminated with \0) line from a socket
 * Sets ret_bol to the begin of the received line, and optionally
 * ret_eol to the end of line.
 * Should be called repeatedly until all input is consumed
 * Returns:
 * - the length of the line (a positive number) on success
 * - 0 if the connection is closed
 * - -1 on error
 */
int onas_recvln(struct onas_rcvln *rcv_data, char **ret_bol, char **ret_eol, int64_t timeout)
{
    char *eol;
    int ret = 0;
    curl_socket_t sockfd;

#if ((LIBCURL_VERSION_MAJOR > 7) || (LIBCURL_VERSION_MAJOR == 7 && LIBCURL_VERSION_MINOR >= 45))
    /* Use new CURLINFO_ACTIVESOCKET option */
    rcv_data->curlcode = curl_easy_getinfo(rcv_data->curl, CURLINFO_ACTIVESOCKET, &sockfd);
#else
    /* Use deprecated CURLINFO_LASTSOCKET option */
    long long_sockfd;
    rcv_data->curlcode = curl_easy_getinfo(rcv_data->curl, CURLINFO_LASTSOCKET, &long_sockfd);
    sockfd             = (curl_socket_t)long_sockfd;
#endif

    if (CURLE_OK != rcv_data->curlcode) {
        logg(LOGG_ERROR, "ClamCom: could not get curl active socket info %s\n", curl_easy_strerror(rcv_data->curlcode));
        return -1;
    }

    while (1) {
        if (!rcv_data->retlen) {
            do {
                rcv_data->curlcode = curl_easy_recv(rcv_data->curl, rcv_data->curr,
                                                    sizeof(rcv_data->buf) - (rcv_data->curr - rcv_data->buf), &(rcv_data->retlen));

                if (CURLE_AGAIN == rcv_data->curlcode) {
                    int wait_result = onas_socket_wait(sockfd, 1, timeout);
                    if (wait_result <= 0) {
                        if (wait_result == 0) {
                            logg(LOGG_ERROR, "ClamCom: TIMEOUT while waiting on socket (recv)\n");
                            rcv_data->curlcode = CURLE_OPERATION_TIMEDOUT;
                        }
                        return -1;
                    }
                }

            } while (CURLE_AGAIN == rcv_data->curlcode);

            if (rcv_data->retlen <= 0) {
                if (rcv_data->retlen && errno == EINTR) {
                    rcv_data->retlen = 0;
                    continue;
                }

                if (rcv_data->retlen || rcv_data->curr != rcv_data->buf) {
                    *rcv_data->curr = '\0';

                    if (strcmp(rcv_data->buf, "UNKNOWN COMMAND\n")) {
                        logg(LOGG_ERROR, "Communication error, clamd received unknown command\n");
                    } else {
                        logg(LOGG_ERROR, "Command rejected by clamd (wrong clamd version?)\n");
                    }

                    return -1;
                }

                return 0;
            }
        }

        if ((eol = memchr(rcv_data->curr, 0, rcv_data->retlen))) {
            eol++;
            rcv_data->retlen -= eol - rcv_data->curr;

            *ret_bol = rcv_data->lnstart;
            if (ret_eol) {
                *ret_eol = eol;
            }

            ret = eol - rcv_data->lnstart;
            if (rcv_data->retlen) {
                rcv_data->lnstart = rcv_data->curr = eol;
            } else {
                rcv_data->lnstart = rcv_data->curr = rcv_data->buf;
            }

            return ret;
        }

        rcv_data->retlen += rcv_data->curr - rcv_data->lnstart;

        if (!eol && rcv_data->retlen == sizeof(rcv_data->buf)) {
            logg(LOGG_ERROR, "Overlong reply from clamd\n");
            return -1;
        }

        if (!eol) {
            if (rcv_data->buf != rcv_data->lnstart) {
                memmove(rcv_data->buf, rcv_data->lnstart, rcv_data->retlen);
                rcv_data->lnstart = rcv_data->buf;
            }

            rcv_data->curr   = &rcv_data->lnstart[rcv_data->retlen];
            rcv_data->retlen = 0;
        }
    }
}

/* Receives a full (terminated with \0) line from a socket
 * Sets ret_bol to the begin of the received line, and optionally
 * ret_eol to the end of line.
 * Should be called repeatedly until all input is consumed
 * Returns:
 * - the length of the line (a positive number) on success
 * - 0 if the connection is closed
 * - -1 on error
 */
int onas_fd_recvln(struct onas_rcvln *rcv_data, char **ret_bol, char **ret_eol, int64_t timeout_ms)
{
    char *eol;

    UNUSEDPARAM(timeout_ms);

    while (1) {
        if (!rcv_data->retlen) {
            rcv_data->retlen = recv(rcv_data->sockd, rcv_data->curr, sizeof(rcv_data->buf) - (rcv_data->curr - rcv_data->buf), 0);
            if (rcv_data->retlen <= 0) {
                if (rcv_data->retlen && errno == EINTR) {
                    rcv_data->retlen = 0;
                    continue;
                }
                if (rcv_data->retlen || rcv_data->curr != rcv_data->buf) {
                    *rcv_data->curr = '\0';
                    if (strcmp(rcv_data->buf, "UNKNOWN COMMAND\n"))
                        logg(LOGG_ERROR, "Communication error\n");
                    else
                        logg(LOGG_ERROR, "Command rejected by clamd (wrong clamd version?)\n");
                    return -1;
                }
                return 0;
            }
        }
        if ((eol = memchr(rcv_data->curr, 0, rcv_data->retlen))) {
            int ret = 0;
            eol++;
            rcv_data->retlen -= eol - rcv_data->curr;
            *ret_bol = rcv_data->lnstart;
            if (ret_eol) *ret_eol = eol;
            ret = eol - rcv_data->lnstart;
            if (rcv_data->retlen)
                rcv_data->lnstart = rcv_data->curr = eol;
            else
                rcv_data->lnstart = rcv_data->curr = rcv_data->buf;
            return ret;
        }
        rcv_data->retlen += rcv_data->curr - rcv_data->lnstart;
        if (!eol && rcv_data->retlen == sizeof(rcv_data->buf)) {
            logg(LOGG_ERROR, "Overlong reply from clamd\n");
            return -1;
        }
        if (!eol) {
            if (rcv_data->buf != rcv_data->lnstart) { /* old memmove sux */
                memmove(rcv_data->buf, rcv_data->lnstart, rcv_data->retlen);
                rcv_data->lnstart = rcv_data->buf;
            }
            rcv_data->curr   = &rcv_data->lnstart[rcv_data->retlen];
            rcv_data->retlen = 0;
        }
    }
}
