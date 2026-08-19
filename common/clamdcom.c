/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009-2013 Sourcefire, Inc.
 *
 *  Author: aCaB
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
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <errno.h>
#include <limits.h>

#ifndef _WIN32
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#endif

#include "clamav.h"
#include "actions.h"
#include "output.h"
#include "clamdcom.h"

#ifndef _WIN32
struct sockaddr_un nixsock;
#endif

static const char *scancmd[] = {"CONTSCAN", "MULTISCAN", "INSTREAM", "FILDES", "ALLMATCHSCAN"};

/* Sends bytes over a socket
 * Returns 0 on success */
int sendln(int sockd, const char *line, unsigned int len)
{
    while (len) {
        int sent = send(sockd, line, len, 0);
        if (sent <= 0) {
            if (sent && errno == EINTR) continue;
            logg(LOGG_ERROR, "Can't send to clamd: %s\n", strerror(errno));
            return 1;
        }
        line += sent;
        len -= sent;
    }
    return 0;
}

/* Inits a RECVLN struct before it can be used in recvln() - see below */
void recvlninit(struct RCVLN *s, int sockd)
{
    s->sockd = sockd;
    s->bol = s->cur = s->buf;
    s->r            = 0;
}

/* Receives a full (terminated with \0) line from a socket
 * Sets rbol to the begin of the received line, and optionally
 * reol to the end of line.
 * Should be called repeatedly until all input is consumed
 * Returns:
 * - the length of the line (a positive number) on success
 * - 0 if the connection is closed
 * - -1 on error
 */
int recvln(struct RCVLN *s, char **rbol, char **reol)
{
    char *eol;

    while (1) {
        if (!s->r) {
            s->r = recv(s->sockd, s->cur, sizeof(s->buf) - (s->cur - s->buf), 0);
            if (s->r <= 0) {
                if (s->r && errno == EINTR) {
                    s->r = 0;
                    continue;
                }
                if (s->r || s->cur != s->buf) {
                    *s->cur = '\0';
                    if (strcmp(s->buf, "UNKNOWN COMMAND\n"))
                        logg(LOGG_ERROR, "Communication error\n");
                    else
                        logg(LOGG_ERROR, "Command rejected by clamd (wrong clamd version?)\n");
                    return -1;
                }
                return 0;
            }
        }
        if ((eol = memchr(s->cur, 0, s->r))) {
            int ret = 0;
            eol++;
            s->r -= eol - s->cur;
            *rbol = s->bol;
            if (reol) *reol = eol;
            ret = eol - s->bol;
            if (s->r)
                s->bol = s->cur = eol;
            else
                s->bol = s->cur = s->buf;
            return ret;
        }
        s->r += s->cur - s->bol;
        if (!eol && s->r == sizeof(s->buf)) {
            logg(LOGG_ERROR, "Overlong reply from clamd\n");
            return -1;
        }
        if (!eol) {
            if (s->buf != s->bol) { /* old memmove sux */
                memmove(s->buf, s->bol, s->r);
                s->bol = s->buf;
            }
            s->cur = &s->bol[s->r];
            s->r   = 0;
        }
    }
}

/* Determines if a path should be excluded
 * 0: scan, 1: skip */
int chkpath(const char *path, struct optstruct *clamdopts)
{
    int status = 0;
    const struct optstruct *opt;
    char *real_path = NULL;

    if (!path) {
        status = 1;
        goto done;
    }

    if ((opt = optget(clamdopts, "ExcludePath"))->enabled) {
        while (opt) {
            if (match_regex(path, opt->strarg) == 1) {
                logg(LOGG_DEBUG, "%s: Excluded\n", path);
                status = 1;
                goto done;
            }
            opt = opt->nextarg;
        }
    }

done:
    if (NULL != real_path) {
        free(real_path);
    }
    return status;
}

#ifdef HAVE_FD_PASSING
/* Issues a FILDES-family command and pass a FD to clamd
 * Returns >0 on success, 0 soft fail, -1 hard fail */
static int send_fdpass_fd_command(int sockd, int fd, const char *command)
{
    struct iovec iov[1];
    struct msghdr msg;
    struct cmsghdr *cmsg;
    unsigned char fdbuf[CMSG_SPACE(sizeof(int))];
    char dummy[] = "";

    if (fd < 0) {
        return 0;
    }

    if (sendln(sockd, command, (unsigned int)strlen(command) + 1U)) {
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
    if (sendmsg(sockd, &msg, 0) == -1) {
        logg(LOGG_ERROR, "FD send failed: %s\n", strerror(errno));
        return -1;
    }
    return 1;
}

int send_fdpass_fd(int sockd, int fd)
{
    return send_fdpass_fd_command(sockd, fd, "zFILDES");
}

int send_fdpass_fd_report(int sockd, int fd)
{
    return send_fdpass_fd_command(sockd, fd, "zFILDESREPORT");
}

/* Issues a FILDES command and pass a FD to clamd
 * Returns >0 on success, 0 soft fail, -1 hard fail */
int send_fdpass(int sockd, const char *filename)
{
    int fd;
    int ret;
    int close_fd = 0;

    if (filename) {
        if ((fd = open(filename, O_RDONLY)) < 0) {
            logg(LOGG_INFO, "%s: Failed to open file\n", filename);
            return 0;
        }
        close_fd = 1;
    } else
        fd = 0;
    ret = send_fdpass_fd(sockd, fd);
    if (close_fd) {
        close(fd);
    }
    return ret;
}

int send_fdpass_report(int sockd, const char *filename)
{
    int fd;
    int ret;
    int close_fd = 0;

    if (filename) {
        if ((fd = open(filename, O_RDONLY)) < 0) {
            logg(LOGG_INFO, "%s: Failed to open file\n", filename);
            return 0;
        }
        close_fd = 1;
    } else
        fd = 0;
    ret = send_fdpass_fd_report(sockd, fd);
    if (close_fd)
        close(fd);
    return ret;
}
#endif

/* Issues an INSTREAM-family command to clamd and streams the given file
 * Returns >0 on success, 0 soft fail, -1 hard fail */
static int send_stream_fd_common(int sockd, int fd, const char *display_filename,
                                 struct optstruct *clamdopts, bool reject_over_limit,
                                 const char *command)
{
    uint32_t buf[BUFSIZ / sizeof(uint32_t)];
    int len;
    uint64_t todo = (uint64_t)optget(clamdopts, "StreamMaxLength")->numarg;
    STATBUF sb;

    if (fd < 0) {
        return 0;
    }

    if (reject_over_limit &&
        (0 == FSTAT(fd, &sb)) &&
        S_ISREG(sb.st_mode) &&
        (sb.st_size > 0) &&
        ((uint64_t)sb.st_size > (uint64_t)todo)) {
        logg(LOGG_ERROR, "%s: File size exceeds StreamMaxLength; refusing to send a truncated stream. ERROR\n",
             display_filename ? display_filename : "STDIN");
        return 0;
    }

    if (sendln(sockd, command, (unsigned int)strlen(command) + 1U)) {
        return -1;
    }

    if (0 != fd) {
        (void)lseek(fd, 0, SEEK_SET);
    }

    while ((len = read(fd, &buf[1], sizeof(buf) - sizeof(uint32_t))) > 0) {
        if (reject_over_limit && ((uint64_t)len > todo)) {
            logg(LOGG_ERROR, "%s: File size exceeds StreamMaxLength; refusing to send a truncated stream. ERROR\n",
                 display_filename ? display_filename : "STDIN");
            return -1;
        }
        if ((uint64_t)len > todo) len = (int)todo;
        buf[0] = htonl(len);
        if (sendln(sockd, (const char *)buf, len + sizeof(uint32_t))) {
            return -1;
        }
        todo -= len;
        if (!todo) {
            if (reject_over_limit) {
                len = read(fd, &buf[1], 1);
                if (len > 0) {
                    logg(LOGG_ERROR, "%s: File size exceeds StreamMaxLength; refusing to send a truncated stream. ERROR\n",
                         display_filename ? display_filename : "STDIN");
                    return -1;
                }
            } else {
                len = 0;
            }
            break;
        }
    }
    if (len) {
        logg(LOGG_ERROR, "Failed to read from %s.\n", display_filename ? display_filename : "STDIN");
        return reject_over_limit ? -1 : 0;
    }
    *buf = 0;
    sendln(sockd, (const char *)buf, 4);
    return 1;
}

int send_stream_fd(int sockd, int fd, const char *display_filename, struct optstruct *clamdopts)
{
    /* A successful INSTREAM request must represent the complete input.  The
     * legacy client silently stopped at StreamMaxLength, sent the normal
     * terminator, and could therefore report a clean verdict for only a file
     * prefix.  Apply the same fail-closed accounting used by action streams to
     * every stream, including pipes/stdin where no size preflight is possible. */
    return send_stream_fd_common(sockd, fd, display_filename, clamdopts, true, "zINSTREAM");
}

int send_stream_fd_action(int sockd, int fd, const char *display_filename, struct optstruct *clamdopts)
{
    return send_stream_fd_common(sockd, fd, display_filename, clamdopts, true, "zINSTREAM");
}

int send_stream_fd_report(int sockd, int fd, const char *display_filename, struct optstruct *clamdopts)
{
    return send_stream_fd_common(sockd, fd, display_filename, clamdopts, true, "zINSTREAMREPORT");
}

/* Issues an INSTREAM command to clamd and streams the given file
 * Returns >0 on success, 0 soft fail, -1 hard fail */
int send_stream(int sockd, const char *filename, struct optstruct *clamdopts)
{
    int fd;
    int ret;

    if (filename) {
        if ((fd = safe_open(filename, O_RDONLY | O_BINARY)) < 0) {
            logg(LOGG_INFO, "%s: Failed to open file. ERROR\n", filename);
            return 0;
        }
    } else {
        /* Read stream from STDIN */
        fd = 0;
    }

    ret = send_stream_fd(sockd, fd, filename, clamdopts);
    if (0 != fd) {
        close(fd);
    }
    return ret;
}

int send_stream_report(int sockd, const char *filename, struct optstruct *clamdopts)
{
    int fd;
    int ret;

    if (filename) {
        if ((fd = safe_open(filename, O_RDONLY | O_BINARY)) < 0) {
            logg(LOGG_INFO, "%s: Failed to open file. ERROR\n", filename);
            return 0;
        }
    } else {
        fd = 0;
    }

    ret = send_stream_fd_report(sockd, fd, filename, clamdopts);
    if (fd != 0)
        close(fd);
    return ret;
}

/* Connects to clamd
 * Returns a FD or -1 on error */
int dconnect(struct optstruct *clamdopts)
{
    int sockd, res;
    const struct optstruct *opt;
    struct addrinfo hints, *info, *p;
    char port[10];
    char *ipaddr;

#ifndef _WIN32
    opt = optget(clamdopts, "LocalSocket");
    if (opt->enabled) {
        if ((sockd = socket(AF_UNIX, SOCK_STREAM, 0)) >= 0) {
            if (connect(sockd, (struct sockaddr *)&nixsock, sizeof(nixsock)) == 0)
                return sockd;
            else {
                logg(LOGG_ERROR, "Could not connect to clamd on LocalSocket %s: %s\n", opt->strarg, strerror(errno));
                close(sockd);
            }
        }
    }
#endif

    snprintf(port, sizeof(port), "%lld", optget(clamdopts, "TCPSocket")->numarg);

    opt = optget(clamdopts, "TCPAddr");
    while (opt) {
        if (opt->enabled) {
            ipaddr = NULL;
            if (opt->strarg)
                ipaddr = (!strcmp(opt->strarg, "any") ? NULL : opt->strarg);

            memset(&hints, 0x00, sizeof(struct addrinfo));
            hints.ai_family   = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;

            if ((res = getaddrinfo(ipaddr, port, &hints, &info))) {
                logg(LOGG_ERROR, "Could not lookup %s: %s\n", ipaddr ? ipaddr : "", gai_strerror(res));
                opt = opt->nextarg;
                continue;
            }

            for (p = info; p != NULL; p = p->ai_next) {
                if ((sockd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0) {
                    logg(LOGG_ERROR, "Can't create the socket: %s\n", strerror(errno));
                    continue;
                }

                if (connect(sockd, p->ai_addr, p->ai_addrlen) < 0) {
                    logg(LOGG_ERROR, "Could not connect to clamd on %s: %s\n", opt->strarg, strerror(errno));
                    closesocket(sockd);
                    continue;
                }

                freeaddrinfo(info);
                return sockd;
            }

            freeaddrinfo(info);
        }
        opt = opt->nextarg;
    }

    return -1;
}

/* Sends a proper scan request to clamd and parses its replies
 * This is used only in non IDSESSION mode
 * Returns the number of infected files or -1 on error
 * NOTE: filename may be NULL for STREAM scantype. */
int dsresult(int sockd, int scantype, const char *filename, const action_source_t *action_source, bool apply_action, int *printok, int *errors, struct optstruct *clamdopts)
{
    int infected = 0, len = 0, beenthere = 0;
    char *bol, *eol;
    struct RCVLN rcv;
    STATBUF sb;
    const char *display_filename = (NULL != action_source) ? action_source->display_path : filename;

    recvlninit(&rcv, sockd);

    switch (scantype) {
        case MULTI:
        case CONT:
        case ALLMATCH:
            if (!filename) {
                logg(LOGG_INFO, "Filename cannot be NULL for MULTISCAN or CONTSCAN.\n");
                infected = -1;
                goto done;
            }
            len = strlen(filename) + strlen(scancmd[scantype]) + 3;
            if (!(bol = malloc(len))) {
                logg(LOGG_ERROR, "Cannot allocate a command buffer: %s\n", strerror(errno));
                infected = -1;
                goto done;
            }
            sprintf(bol, "z%s %s", scancmd[scantype], filename);
            if (sendln(sockd, bol, len)) {
                free(bol);
                infected = -1;
                goto done;
            }
            free(bol);
            break;

        case STREAM:
            /* NULL filename safe in send_stream() */
            len = (NULL != action_source) ? send_stream_fd_action(sockd, action_source->scan_fd, display_filename, clamdopts) : send_stream(sockd, filename, clamdopts);
            break;
#ifdef HAVE_FD_PASSING
        case FILDES:
            /* NULL filename safe in send_fdpass() */
            len = (NULL != action_source) ? send_fdpass_fd(sockd, action_source->scan_fd) : send_fdpass(sockd, filename);
            break;
#endif
    }

    if (len <= 0) {
        if (printok)
            *printok = 0;
        if (errors)
            (*errors)++;
        infected = len;
        goto done;
    }

    while ((len = recvln(&rcv, &bol, &eol))) {
        if (len == -1) {
            infected = -1;
            goto done;
        }
        beenthere = 1;
        if (!filename) logg(LOGG_INFO, "%s\n", bol);
        if (len > 7) {
            char *colon = strrchr(bol, ':');
            if (colon && colon[1] != ' ') {
                char *br;
                *colon = 0;
                br     = strrchr(bol, '(');
                if (br)
                    *br = 0;
                colon = strrchr(bol, ':');
            }
            if (!colon) {
                char *unkco = "UNKNOWN COMMAND";
                if (!strncmp(bol, unkco, sizeof(unkco) - 1))
                    logg(LOGG_INFO, "clamd replied \"UNKNOWN COMMAND\". Command was %s\n",
                         (scantype < 0 || scantype > MAX_SCANTYPE) ? "unidentified" : scancmd[scantype]);
                else
                    logg(LOGG_INFO, "Failed to parse reply: \"%s\"\n", bol);
                infected = -1;
                goto done;
            } else if (!memcmp(eol - 7, " FOUND", 6)) {
                static char last_filename[PATH_MAX + 1] = {'\0'};
                *(eol - 7)                              = 0;
                if (printok)
                    *printok = 0;
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
                        if (apply_action && action && (NULL != action_source)) action(action_source);
                    } else {
                        logg(LOGG_INFO, "%s FOUND\n", bol);
                        *colon = '\0';
                        if (apply_action && action && (NULL != action_source)) action(action_source);
                    }
                }
            } else if (!memcmp(eol - 7, " ERROR", 6)) {
                if (errors)
                    (*errors)++;
                if (printok)
                    *printok = 0;
                if (display_filename) {
                    if (scantype >= STREAM)
                        logg(LOGG_INFO, "%s%s\n", display_filename, colon);
                    else
                        logg(LOGG_INFO, "%s\n", bol);
                }
            }
        }
    }
    if (!beenthere) {
        if (!filename) {
            logg(LOGG_INFO, "STDIN: noreply from clamd\n.");
            infected = -1;
            goto done;
        }
        if (CLAMSTAT(filename, &sb) == -1) {
            logg(LOGG_INFO, "%s: stat() failed with %s, clamd may not be responding\n",
                 filename, strerror(errno));
            infected = -1;
            goto done;
        }
        if (!S_ISDIR(sb.st_mode)) {
            logg(LOGG_INFO, "%s: no reply from clamd\n", filename);
            infected = -1;
            goto done;
        }
    }

done:
    return infected;
}

#define CLAMD_SCAN_REPORT_MAX_FRAME (16U * 1024U * 1024U)

static int recv_full(int sockd, void *buffer, size_t length)
{
    unsigned char *cursor = (unsigned char *)buffer;

    while (length) {
        int received = recv(sockd, (char *)cursor, (int)((length > INT_MAX) ? INT_MAX : length), 0);
        if (received <= 0)
            return -1;
        cursor += (size_t)received;
        length -= (size_t)received;
    }
    return 0;
}

/* Read one length-prefixed structured report frame.  A zero-length frame is
 * the protocol terminator and is returned as 0; a JSON frame is returned as
 * 1.  The caller owns *json. */
int recv_scan_report_frame(int sockd, char **json, uint32_t *json_length, int *terminator)
{
    uint32_t network_length;
    uint32_t length;
    char *payload;

    if (!json || !json_length || !terminator)
        return -1;
    *json       = NULL;
    *json_length = 0;
    *terminator = 0;

    if (recv_full(sockd, &network_length, sizeof(network_length)) < 0)
        return -1;
    length = ntohl(network_length);
    if (!length) {
        *terminator = 1;
        return 0;
    }
    if (length > CLAMD_SCAN_REPORT_MAX_FRAME)
        return -1;

    payload = (char *)malloc((size_t)length + 1U);
    if (!payload)
        return -1;
    if (recv_full(sockd, payload, length) < 0) {
        free(payload);
        return -1;
    }
    payload[length] = '\0';
    *json           = payload;
    *json_length    = length;
    return 1;
}

static int report_json_contains(const char *json, const char *compact, const char *spaced)
{
    return (strstr(json, compact) != NULL) || (strstr(json, spaced) != NULL);
}

int scan_report_json_status(const char *json, uint32_t json_length, int *infected, int *incomplete)
{
    const char *verdict_infected = "\"verdict\":\"infected\"";
    const char *verdict_clean    = "\"verdict\":\"clean\"";
    const char *verdict_partial  = "\"verdict\":\"incomplete\"";
    const char *completion_done  = "\"completion\":\"COMPLETE\"";

    if (!json || !infected || !incomplete || json_length == 0)
        return -1;
    if (json[json_length] != '\0')
        return -1;

    if (report_json_contains(json, verdict_infected, "\"verdict\": \"infected\"")) {
        *infected = 1;
        *incomplete = 0;
        return 0;
    }
    if (report_json_contains(json, verdict_partial, "\"verdict\": \"incomplete\"")) {
        *infected = 0;
        *incomplete = 1;
        return 0;
    }
    if (report_json_contains(json, verdict_clean, "\"verdict\": \"clean\"") &&
        report_json_contains(json, completion_done, "\"completion\": \"COMPLETE\"")) {
        *infected = 0;
        *incomplete = 0;
        return 0;
    }

    /* libclamav's versioned report uses the public numeric cl_verdict_t
     * field.  Transport clients must accept that representation as well as
     * the compact legacy clamd wrapper above.  A detection-terminated
     * completion is unambiguous; every other recognized non-complete state is
     * an incomplete result and must not be treated as clean. */
    if (report_json_contains(json, "\"completion\":\"DETECTION_TERMINATED\"",
                             "\"completion\": \"DETECTION_TERMINATED\"")) {
        *infected = 1;
        *incomplete = 0;
        return 0;
    }
    if (report_json_contains(json, "\"completion\":\"COMPLETE\"",
                             "\"completion\": \"COMPLETE\"")) {
        *infected = 0;
        *incomplete = 0;
        return 0;
    }
    if (report_json_contains(json, "\"completion\":\"LIMIT_INCOMPLETE\"",
                             "\"completion\": \"LIMIT_INCOMPLETE\"") ||
        report_json_contains(json, "\"completion\":\"UNSUPPORTED\"",
                             "\"completion\": \"UNSUPPORTED\"") ||
        report_json_contains(json, "\"completion\":\"MALFORMED_CONFIRMED\"",
                             "\"completion\": \"MALFORMED_CONFIRMED\"") ||
        report_json_contains(json, "\"completion\":\"RESOURCE_FAILURE\"",
                             "\"completion\": \"RESOURCE_FAILURE\"") ||
        report_json_contains(json, "\"completion\":\"APPLICATION_ABORT\"",
                             "\"completion\": \"APPLICATION_ABORT\"")) {
        *infected = 0;
        *incomplete = 1;
        return 0;
    }
    return -1;
}

int dsreport(int sockd, int scantype, const char *filename, const struct action_source *action_source,
             bool apply_action, FILE *report_stream, int *infected, int *incomplete,
             int *errors, struct optstruct *clamdopts)
{
    int sent = 0;
    int frame;
    int terminated = 0;
    const char *display_filename = (NULL != action_source) ? action_source->display_path : filename;

    if (!infected || !incomplete || !errors)
        return -1;

    switch (scantype) {
        case CONT:
            if (!filename)
                return -1;
            {
                size_t length = strlen(filename) + sizeof("zCONTSCANREPORT ");
                char *command = (char *)malloc(length);
                if (!command)
                    return -1;
                snprintf(command, length, "zCONTSCANREPORT %s", filename);
                sent = sendln(sockd, command, (unsigned int)length);
                free(command);
            }
            break;
        case MULTI:
            if (!filename)
                return -1;
            {
                size_t length = strlen(filename) + sizeof("zMULTISCANREPORT ");
                char *command = (char *)malloc(length);
                if (!command)
                    return -1;
                snprintf(command, length, "zMULTISCANREPORT %s", filename);
                sent = sendln(sockd, command, (unsigned int)length);
                free(command);
            }
            break;
        case ALLMATCH:
            if (!filename)
                return -1;
            {
                size_t length = strlen(filename) + sizeof("zALLMATCHSCANREPORT ");
                char *command = (char *)malloc(length);
                if (!command)
                    return -1;
                snprintf(command, length, "zALLMATCHSCANREPORT %s", filename);
                sent = sendln(sockd, command, (unsigned int)length);
                free(command);
            }
            break;
        case STREAM:
            sent = (NULL != action_source)
                       ? send_stream_fd_report(sockd, action_source->scan_fd, display_filename, clamdopts)
                       : send_stream_report(sockd, filename, clamdopts);
            break;
#ifdef HAVE_FD_PASSING
        case FILDES:
            sent = (NULL != action_source)
                       ? send_fdpass_fd_report(sockd, action_source->scan_fd)
                       : send_fdpass_report(sockd, filename);
            break;
#endif
        default:
            return -1;
    }

    if (sent <= 0)
        return -1;

    while (!terminated) {
        char *json = NULL;
        uint32_t json_length = 0;
        int frame_infected = 0;
        int frame_incomplete = 0;

        frame = recv_scan_report_frame(sockd, &json, &json_length, &terminated);
        if (frame < 0)
            return -1;
        if (terminated)
            break;
        if (scan_report_json_status(json, json_length, &frame_infected, &frame_incomplete) < 0) {
            free(json);
            return -1;
        }
        if (report_stream &&
            (fwrite(json, 1, json_length, report_stream) != json_length ||
             fputc('\n', report_stream) == EOF)) {
            free(json);
            return -1;
        }
        if (frame_infected) {
            (*infected)++;
            if (apply_action && action && action_source)
                action((action_source_t *)action_source);
        } else if (frame_incomplete) {
            (*incomplete)++;
            (*errors)++;
        }
        free(json);
    }

    return 0;
}
