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
#include <json.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <curl/curl.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <time.h>
#ifndef _WIN32
#include <sys/time.h>
#endif

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

static int onas_now_ms(uint64_t *now_ms)
{
#if defined(CLOCK_MONOTONIC)
    struct timespec now;

    if (now_ms == NULL || clock_gettime(CLOCK_MONOTONIC, &now) != 0 ||
        now.tv_sec < 0 || now.tv_nsec < 0 || now.tv_nsec >= 1000000000L ||
        (uint64_t)now.tv_sec > (UINT64_MAX - (uint64_t)now.tv_nsec) / 1000000000U)
        return -1;

    *now_ms = (uint64_t)now.tv_sec * 1000U + (uint64_t)now.tv_nsec / 1000000U;
    return 0;
#elif !defined(_WIN32)
    struct timeval now;

    if (now_ms == NULL || gettimeofday(&now, NULL) != 0 || now.tv_sec < 0 ||
        now.tv_usec < 0 || now.tv_usec >= 1000000L)
        return -1;

    *now_ms = (uint64_t)now.tv_sec * 1000U + (uint64_t)now.tv_usec / 1000U;
    return 0;
#else
    (void)now_ms;
    return -1;
#endif
}

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
    uint64_t now_ms;
    uint64_t deadline_ms = 0;

    if (timeout_ms > 0) {
        if (onas_now_ms(&now_ms) != 0)
            return -1;
        deadline_ms = (timeout_ms > UINT64_MAX - now_ms) ? UINT64_MAX : now_ms + timeout_ms;
    }

    for (;;) {
        fd_set infd;
        fd_set outfd;
        fd_set errfd;
        int ret;

        /* select() mutates both the fd sets and timeout. Rebuild them after
         * every EINTR and measure the remaining time from one absolute
         * deadline so signal storms cannot extend OnAccessCurlTimeout. */
        if (deadline_ms > 0) {
            if (onas_now_ms(&now_ms) != 0)
                return -1;
            if (now_ms >= deadline_ms) {
                errno = ETIMEDOUT;
                return 0;
            }
            now_ms = deadline_ms - now_ms;
            tv.tv_sec  = (long)(now_ms / 1000U);
            tv.tv_usec = (long)((now_ms % 1000U) * 1000U);
        } else {
            tv.tv_sec  = 0;
            tv.tv_usec = 0;
        }

        FD_ZERO(&infd);
        FD_ZERO(&outfd);
        FD_ZERO(&errfd);
        FD_SET(sockfd, &errfd); /* always check for error */

        if (b_recv)
            FD_SET(sockfd, &infd);
        else
            FD_SET(sockfd, &outfd);

        /* select() returns the number of signalled sockets or -1. */
        ret = select((int)sockfd + 1, &infd, &outfd, &errfd, &tv);
        if (ret >= 0 || errno != EINTR)
            return ret;
    }
}

/* Sends bytes over a socket
 * Returns 0 on success */
int onas_sendln(CURL *curl, const void *line, size_t len, int64_t timeout, cl_error_t *ret_code)
{
    size_t sent = 0;
    uint64_t wait_timeout = timeout > 0 ? (uint64_t)timeout : 0;
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
                int wait_result = onas_socket_wait(sockfd, 0, wait_timeout);
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

/* Add the process-local on-access event identity to a validated daemon report
 * before publishing it.  Keeping the report fields at the top level lets
 * existing report consumers continue to inspect them while the event number
 * gives the R13 runner an explicit join key for clamonacc permission evidence. */
int onas_write_scan_report(FILE *stream, const char *payload, size_t payload_length, uint64_t event_id)
{
    json_object *object = NULL;
    json_object *event_number;
    json_object *existing = NULL;
    const char *serialized;
    char *alert = NULL;
    int frame_infected   = 0;
    int frame_incomplete = 0;
    cl_error_t frame_status = CL_ERROR;
    int result = -1;

    if (stream == NULL)
        return 0;
    if (payload == NULL || payload_length == 0 || payload_length > UINT32_MAX ||
        strlen(payload) != payload_length ||
        event_id > (uint64_t)INT64_MAX)
        return -1;

    /* The daemon frame was already semantically validated by the caller, but
     * this helper is also an externally visible publication boundary.  Parse
     * it through the shared status validator first so trailing bytes,
     * duplicate top-level keys, non-object payloads, and contradictory
     * completion/verdict combinations cannot be rewritten into apparently
     * authoritative JSONL evidence. */
    if (scan_report_json_status(payload, (uint32_t)payload_length,
                                &frame_infected, &frame_incomplete,
                                &frame_status) < 0)
        goto done;
    if (scan_report_json_alert(payload, (uint32_t)payload_length, &alert) < 0)
        goto done;
    if (frame_infected && (alert == NULL || *alert == '\0'))
        goto done;
    free(alert);
    alert = NULL;
    object = json_tokener_parse(payload);
    if (object == NULL || json_object_get_type(object) != json_type_object)
        goto done;
    if (json_object_object_get_ex(object, "clamonacc_event_id", &existing))
        goto done;

    event_number = json_object_new_int64((int64_t)event_id);
    if (event_number == NULL || json_object_object_add(object, "clamonacc_event_id", event_number) != 0) {
        if (event_number != NULL)
            json_object_put(event_number);
        goto done;
    }

    serialized = json_object_to_json_string_ext(object, JSON_C_TO_STRING_PLAIN);
    if (serialized == NULL)
        goto done;
    if (fwrite(serialized, 1, strlen(serialized), stream) != strlen(serialized) ||
        fputc('\n', stream) == EOF || fflush(stream) != 0)
        goto done;

    result = 0;

done:
    free(alert);
    if (object != NULL)
        json_object_put(object);
    return result;
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
                          int *infected, int *incomplete, cl_error_t *status_out,
                          FILE *report_stream, int *report_written,
                          uint64_t event_id)
{
    int received = 0;
    char *report_payload = NULL;
    uint32_t report_length = 0;

    if (!rcv_data || !infected || !incomplete || !status_out ||
        (report_stream != NULL && report_written == NULL))
        return -1;

    *infected   = 0;
    *incomplete = 0;
    *status_out = CL_SUCCESS;
    if (report_written != NULL)
        *report_written = 0;

    for (;;) {
        uint32_t network_length;
        uint32_t length;
        char *payload;
        int frame_infected   = 0;
        int frame_incomplete = 0;
        cl_error_t frame_status = CL_ERROR;

        if (onas_recv_bytes(rcv_data, &network_length, sizeof(network_length), timeout_ms) < 0) {
            free(report_payload);
            return -1;
        }

        length = ntohl(network_length);
        if (length == 0) {
            if (!received)
                return -1;
            if (report_stream != NULL) {
                if (onas_write_scan_report(report_stream, report_payload,
                                           report_length, event_id) != 0) {
                    free(report_payload);
                    return -1;
                }
                *report_written = 1;
            }
            free(report_payload);
            return 0;
        }
        if (length > CLAMD_SCAN_REPORT_MAX_FRAME) {
            free(report_payload);
            return -1;
        }
        if (received) {
            /* Each on-access request has one authoritative structured report
             * frame. Do not merge a second frame, since a duplicate or
             * conflicting daemon response must remain fail-visible. */
            logg(LOGG_ERROR, "Received multiple structured scan report frames from clamd.\n");
            free(report_payload);
            return -1;
        }

        payload = (char *)malloc((size_t)length + 1U);
        if (!payload) {
            free(report_payload);
            return -1;
        }
        if (onas_recv_bytes(rcv_data, payload, length, timeout_ms) < 0) {
            free(payload);
            free(report_payload);
            return -1;
        }
        payload[length] = '\0';

        if (scan_report_json_status(payload, length, &frame_infected,
                                    &frame_incomplete, &frame_status) < 0) {
            free(payload);
            free(report_payload);
            return -1;
        }

        if (frame_infected) {
            char *frame_alert = NULL;

            /* A detection without its exact alert name cannot be joined to
             * the retained case evidence.  Keep the on-access contract in
             * parity with the daemon report consumer and fail closed before
             * publishing or allowing the event. */
            if (scan_report_json_alert(payload, length, &frame_alert) < 0 ||
                frame_alert == NULL || *frame_alert == '\0') {
                free(frame_alert);
                free(payload);
                free(report_payload);
                return -1;
            }
            free(frame_alert);
        }

        /* Retain the validated daemon report content for publication after
         * the terminating zero-length frame.  The event identity is added by
         * onas_write_scan_report; keeping the write until termination ensures
         * that a duplicate or truncated frame sequence is never claimed as
         * proof. */
        if (report_stream != NULL) {
            report_payload = payload;
            report_length = length;
        } else {
            free(payload);
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
    uint64_t wait_timeout = timeout > 0 ? (uint64_t)timeout : 0;
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
                    int wait_result = onas_socket_wait(sockfd, 1, wait_timeout);
                    if (wait_result <= 0) {
                        if (wait_result == 0) {
                            logg(LOGG_ERROR, "ClamCom: TIMEOUT while waiting on socket (recv)\n");
                            rcv_data->curlcode = CURLE_OPERATION_TIMEDOUT;
                        } else {
                            rcv_data->curlcode = CURLE_RECV_ERROR;
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
    uint64_t wait_timeout = timeout_ms > 0 ? (uint64_t)timeout_ms : 0;

    while (1) {
        if (!rcv_data->retlen) {
            int wait_result = onas_socket_wait(rcv_data->sockd, 1, wait_timeout);
            ssize_t received;

            if (wait_result <= 0) {
                rcv_data->curlcode = (wait_result == 0) ? CURLE_OPERATION_TIMEDOUT : CURLE_RECV_ERROR;
                return -1;
            }

            do {
                received = recv(rcv_data->sockd, rcv_data->curr,
                                sizeof(rcv_data->buf) - (rcv_data->curr - rcv_data->buf), 0);
            } while (received < 0 && errno == EINTR);

            if (received <= 0) {
                if (received < 0) {
                    rcv_data->curlcode = CURLE_RECV_ERROR;
                }
                if (received < 0 || rcv_data->curr != rcv_data->buf) {
                    *rcv_data->curr = '\0';
                    if (strcmp(rcv_data->buf, "UNKNOWN COMMAND\n"))
                        logg(LOGG_ERROR, "Communication error\n");
                    else
                        logg(LOGG_ERROR, "Command rejected by clamd (wrong clamd version?)\n");
                    return -1;
                }
                return 0;
            }
            rcv_data->retlen = (size_t)received;
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
