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
#include <ctype.h>
#include <stdlib.h>

#include <json.h>

#ifndef _WIN32
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#endif

#include "clamav.h"
#include "default.h"
#include "actions.h"
#include "output.h"
#include "clamdcom.h"

#ifndef _WIN32
struct sockaddr_un nixsock;
#endif

static const char *scancmd[] = {"CONTSCAN", "MULTISCAN", "INSTREAM", "FILDES", "ALLMATCHSCAN"};

uint64_t clamd_stream_limit(const struct optstruct *clamdopts)
{
    const struct optstruct *stream_limit;

    if (!clamdopts)
        return CLI_MAX_LARGE_FILESIZE;

    stream_limit = optget(clamdopts, "StreamMaxLength");
    if (!stream_limit || stream_limit->numarg <= 0)
        return CLI_MAX_LARGE_FILESIZE;

    /* Keep the shared daemon/client contract fail-closed even when an
     * optstruct did not come through common/optparser.c. Stale callers and
     * programmatic integrations can construct an option object directly;
     * neither side of the protocol may stage or send more than the certified
     * 32-GiB ingress ceiling. */
    if ((uint64_t)stream_limit->numarg > CLI_MAX_LARGE_FILESIZE)
        return CLI_MAX_LARGE_FILESIZE;

    return (uint64_t)stream_limit->numarg;
}

/* Sends bytes over a socket
 * Returns 0 on success */
int sendln(int sockd, const char *line, unsigned int len)
{
    while (len) {
        ssize_t sent = send(sockd, line, len, 0);
        if (sent <= 0) {
            if (sent < 0 && errno == EINTR) continue;
            logg(LOGG_ERROR, "Can't send to clamd: %s\n", strerror(errno));
            return 1;
        }
        line += sent;
        len -= sent;
    }
    return 0;
}

/* Build a NUL-terminated path command without allowing size_t arithmetic or
 * the unsigned-int sendln() length to wrap. */
static int build_clamd_path_command(const char *prefix, const char *filename,
                                    char **command_out, unsigned int *length_out)
{
    size_t prefix_len;
    size_t filename_len;
    size_t command_len;
    int formatted_len;
    char *command;

    if (!prefix || !filename || !command_out || !length_out)
        return -1;

    prefix_len  = strlen(prefix);
    filename_len = strlen(filename);
    if (prefix_len == SIZE_MAX || filename_len > SIZE_MAX - prefix_len - 1)
        return -1;
    command_len = prefix_len + filename_len + 1;
    if (command_len > UINT_MAX)
        return -1;

    command = (char *)malloc(command_len);
    if (!command)
        return -1;
    formatted_len = snprintf(command, command_len, "%s%s", prefix, filename);
    if (formatted_len < 0 || (size_t)formatted_len + 1 != command_len) {
        free(command);
        return -1;
    }

    *command_out = command;
    *length_out = (unsigned int)command_len;
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

/* Parse the numeric prefix emitted by clamd for a legacy IDSESSION reply.
 * The colon is part of the wire grammar; requiring it prevents a malformed
 * line such as "7garbage" from being correlated with request 7. */
int parse_clamd_session_id(const char *line, unsigned int *id)
{
    char *end;
    unsigned long value;

    if (!line || !id || line[0] < '1' || line[0] > '9')
        return -1;

    errno = 0;
    value = strtoul(line, &end, 10);
    if (errno == ERANGE || end == line || *end != ':' || value > UINT_MAX)
        return -1;

    *id = (unsigned int)value;
    return 0;
}

/* Return the only terminal outcomes allowed on the legacy text protocol.
 * The reply length includes the NUL frame terminator, as returned by recvln.
 * Keeping this check separate from filename/session-ID correlation prevents an
 * unknown suffix from being treated as a clean result. */
cl_error_t parse_clamd_legacy_reply(const char *line, unsigned int length)
{
    if (!line || length == 0 || line[length - 1] != '\0' || !strchr(line, ':'))
        return CL_EPARSE;

    if (length >= sizeof(" FOUND") &&
        memcmp(line + length - sizeof(" FOUND"), " FOUND", sizeof(" FOUND") - 1) == 0)
        return CL_VIRUS;
    if (length >= sizeof(" ERROR") &&
        memcmp(line + length - sizeof(" ERROR"), " ERROR", sizeof(" ERROR") - 1) == 0)
        return CL_ERROR;
    if (length >= sizeof(" OK") &&
        memcmp(line + length - sizeof(" OK"), " OK", sizeof(" OK") - 1) == 0)
        return CL_SUCCESS;
    if (length >= sizeof(" Excluded") &&
        memcmp(line + length - sizeof(" Excluded"), " Excluded", sizeof(" Excluded") - 1) == 0)
        return CL_SUCCESS;

    return CL_EPARSE;
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
    {
        ssize_t sent;

        do {
            sent = sendmsg(sockd, &msg, 0);
        } while (sent == -1 && errno == EINTR);

        if (sent != (ssize_t)iov[0].iov_len) {
            if (sent < 0) {
                logg(LOGG_ERROR, "FD send failed: %s\n", strerror(errno));
            } else {
                logg(LOGG_ERROR, "FD send was incomplete (%zd of %zu bytes)\n", sent, iov[0].iov_len);
            }
            return -1;
        }
    }
    return 1;
}

/* FILDES carries a complete descriptor rather than a length-framed stream.
 * Reject a known regular file before sending it.  When the daemon's
 * MaxFileSize policy is available, use it; otherwise use the fork's hard
 * 32-GiB ceiling.  The daemon still rechecks the descriptor after receipt
 * because the file can change between these two observations. */
int clamd_fdpass_size_preflight(int fd, const char *display_filename,
                                const struct optstruct *clamdopts,
                                cl_error_t *failure_status,
                                uint64_t *size_out)
{
    const struct optstruct *max_file_size;
    STATBUF sb;
    uint64_t limit = CLI_MAX_LARGE_FILESIZE;

    if (failure_status)
        *failure_status = CL_SUCCESS;
    if (size_out)
        *size_out = 0;

    if (fd < 0)
        return 0;

    if (clamdopts) {
        max_file_size = optget(clamdopts, "MaxFileSize");
        if (max_file_size && max_file_size->numarg > 0) {
            limit = (uint64_t)max_file_size->numarg;
            if (limit > CLI_MAX_LARGE_FILESIZE)
                limit = CLI_MAX_LARGE_FILESIZE;
        }
    }

    if (FSTAT(fd, &sb) != 0) {
        logg(LOGG_ERROR, "%s: Failed to stat FILDES input: %s\n",
             display_filename ? display_filename : "FD", strerror(errno));
        if (failure_status)
            *failure_status = CL_ESTAT;
        return -1;
    }
    if (!S_ISREG(sb.st_mode)) {
        /* The legacy wrappers historically let the daemon report this
         * protocol error.  Keep that behavior for unknown-size descriptors;
         * only regular files have a client-side size that can be admitted. */
        if (!clamdopts)
            return 1;
        logg(LOGG_ERROR, "%s: FILDES input is not a regular file. ERROR\n",
             display_filename ? display_filename : "FD");
        if (failure_status)
            *failure_status = CL_EARG;
        return 0;
    }
    if (sb.st_size < 0) {
        logg(LOGG_ERROR, "%s: FILDES input has an invalid negative size. ERROR\n",
             display_filename ? display_filename : "FD");
        if (failure_status)
            *failure_status = CL_ESTAT;
        return -1;
    }
    if (size_out)
        *size_out = (uint64_t)sb.st_size;
    if ((uint64_t)sb.st_size > limit) {
        logg(LOGG_ERROR, "%s: File size exceeds MaxFileSize; refusing FILDES input. ERROR\n",
             display_filename ? display_filename : "FD");
        if (failure_status)
            *failure_status = CL_EMAXSIZE;
        return 0;
    }
    return 1;
}

static int send_fdpass_fd_checked_common(int sockd, int fd, const char *display_filename,
                                         const struct optstruct *clamdopts, bool report)
{
    int preflight = clamd_fdpass_size_preflight(fd, display_filename, clamdopts, NULL, NULL);

    if (preflight <= 0)
        return preflight;
    return send_fdpass_fd_command(sockd, fd, report ? "zFILDESREPORT" : "zFILDES");
}

int send_fdpass_fd(int sockd, int fd)
{
    return send_fdpass_fd_checked_common(sockd, fd, NULL, NULL, false);
}

int send_fdpass_fd_report(int sockd, int fd)
{
    return send_fdpass_fd_checked_common(sockd, fd, NULL, NULL, true);
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

int send_fdpass_fd_checked(int sockd, int fd, const char *display_filename,
                           const struct optstruct *clamdopts)
{
    return send_fdpass_fd_checked_common(sockd, fd, display_filename, clamdopts, false);
}

int send_fdpass_checked(int sockd, const char *filename,
                        const struct optstruct *clamdopts)
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
    } else {
        fd = 0;
    }
    ret = send_fdpass_fd_checked(sockd, fd, filename ? filename : "STDIN", clamdopts);
    if (close_fd)
        close(fd);
    return ret;
}

int send_fdpass_fd_report_checked(int sockd, int fd, const char *display_filename,
                                  const struct optstruct *clamdopts)
{
    return send_fdpass_fd_checked_common(sockd, fd, display_filename, clamdopts, true);
}

int send_fdpass_report_checked(int sockd, const char *filename,
                               const struct optstruct *clamdopts)
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
    } else {
        fd = 0;
    }
    ret = send_fdpass_fd_report_checked(sockd, fd, filename ? filename : "STDIN", clamdopts);
    if (close_fd)
        close(fd);
    return ret;
}
#endif

/* A report client must distinguish a known-size stream admission refusal from
 * a transport failure.  The stream sender keeps its historical 0 soft-fail
 * result for direct callers, while dsreport() translates this preflight into
 * a bounded LIMIT_INCOMPLETE fallback with the original input metadata. */
static int clamd_stream_size_preflight(int fd, const char *display_filename,
                                       const struct optstruct *clamdopts,
                                       cl_error_t *failure_status,
                                       uint64_t *size_out)
{
    STATBUF sb;
    uint64_t limit;

    if (failure_status)
        *failure_status = CL_SUCCESS;
    if (size_out)
        *size_out = 0;

    if (fd < 0)
        return 0;

    if (FSTAT(fd, &sb) != 0) {
        logg(LOGG_ERROR, "%s: Failed to stat stream input: %s\n",
             display_filename ? display_filename : "STDIN", strerror(errno));
        if (failure_status)
            *failure_status = CL_ESTAT;
        return -1;
    }

    if (!S_ISREG(sb.st_mode))
        return 1;

    if (sb.st_size < 0) {
        logg(LOGG_ERROR, "%s: Stream input has an invalid negative size. ERROR\n",
             display_filename ? display_filename : "STDIN");
        if (failure_status)
            *failure_status = CL_ESTAT;
        return -1;
    }

    if (size_out)
        *size_out = (uint64_t)sb.st_size;

    limit = clamd_stream_limit(clamdopts);
    if ((uint64_t)sb.st_size > limit) {
        logg(LOGG_ERROR, "%s: File size exceeds StreamMaxLength; refusing to send a truncated stream. ERROR\n",
             display_filename ? display_filename : "STDIN");
        if (failure_status)
            *failure_status = CL_EMAXSIZE;
        return 0;
    }

    return 1;
}

/* Issues an INSTREAM-family command to clamd and streams the given file
 * Returns >0 on success, 0 soft fail, -1 hard fail */
static int send_stream_fd_common(int sockd, int fd, const char *display_filename,
                                 struct optstruct *clamdopts, const char *command)
{
    uint32_t buf[BUFSIZ / sizeof(uint32_t)];
    ssize_t len;
    uint64_t todo;
    bool known_size;
    STATBUF sb;

    if (fd < 0) {
        return 0;
    }

    /* The public option contract treats zero as the bounded 32-GiB ceiling,
     * not as an unbounded or zero-byte stream. Keep the client-side
     * preflight identical to clamd's engine validation. */
    todo = clamd_stream_limit(clamdopts);

    if (FSTAT(fd, &sb) != 0) {
        logg(LOGG_ERROR, "%s: Failed to stat stream input: %s\n",
             display_filename ? display_filename : "STDIN", strerror(errno));
        return -1;
    }

    if (sb.st_size < 0) {
        logg(LOGG_ERROR, "%s: Stream input has an invalid negative size. ERROR\n",
             display_filename ? display_filename : "STDIN");
        return -1;
    }

    known_size = S_ISREG(sb.st_mode);
    if (known_size &&
        (sb.st_size > 0) &&
        ((uint64_t)sb.st_size > (uint64_t)todo)) {
        logg(LOGG_ERROR, "%s: File size exceeds StreamMaxLength; refusing to send a truncated stream. ERROR\n",
             display_filename ? display_filename : "STDIN");
        return 0;
    }

    if (known_size)
        todo = (uint64_t)sb.st_size;

    /* A descriptor supplied by a caller must represent the complete
     * object.  Rewind regular files before starting the protocol, including
     * when standard input refers to a regular file.  Pipes and other
     * streaming descriptors are intentionally left at their current position
     * because they are not seekable. */
    if (S_ISREG(sb.st_mode) && lseek(fd, 0, SEEK_SET) < 0) {
        logg(LOGG_ERROR, "%s: Failed to rewind regular stream input: %s\n",
             display_filename ? display_filename : "STDIN", strerror(errno));
        return -1;
    }

    if (sendln(sockd, command, (unsigned int)strlen(command) + 1U)) {
        return -1;
    }

    if (known_size && todo == 0) {
        do {
            len = read(fd, &buf[1], 1);
        } while (len < 0 && errno == EINTR);
        if (len > 0) {
            logg(LOGG_ERROR, "%s: Regular stream input grew after admission. ERROR\n",
                 display_filename ? display_filename : "STDIN");
            return -1;
        }
        if (len < 0) {
            logg(LOGG_ERROR, "Failed to read from %s.\n", display_filename ? display_filename : "STDIN");
            return -1;
        }
    } else {
        do {
            len = read(fd, &buf[1], sizeof(buf) - sizeof(uint32_t));
        } while (len < 0 && errno == EINTR);
    }
    while (len > 0) {
        if ((uint64_t)len > todo) {
            logg(LOGG_ERROR, "%s: File size exceeds StreamMaxLength; refusing to send a truncated stream. ERROR\n",
                 display_filename ? display_filename : "STDIN");
            return -1;
        }
        buf[0] = htonl(len);
        if (sendln(sockd, (const char *)buf, len + sizeof(uint32_t))) {
            return -1;
        }
        todo -= len;
        if (!todo) {
            do {
                len = read(fd, &buf[1], 1);
            } while (len < 0 && errno == EINTR);
            if (len > 0) {
                logg(LOGG_ERROR, "%s: File size exceeds StreamMaxLength; refusing to send a truncated stream. ERROR\n",
                     display_filename ? display_filename : "STDIN");
                return -1;
            }
            if (len < 0) {
                logg(LOGG_ERROR, "Failed to read from %s.\n", display_filename ? display_filename : "STDIN");
                return -1;
            }
            break;
        }
        do {
            len = read(fd, &buf[1], sizeof(buf) - sizeof(uint32_t));
        } while (len < 0 && errno == EINTR);
    }
    if (len) {
        logg(LOGG_ERROR, "Failed to read from %s.\n", display_filename ? display_filename : "STDIN");
        return -1;
    }
    if (known_size && todo) {
        logg(LOGG_ERROR, "%s: Regular stream input ended before its admitted size. ERROR\n",
             display_filename ? display_filename : "STDIN");
        return -1;
    }
    *buf = 0;
    if (sendln(sockd, (const char *)buf, 4))
        return -1;
    return 1;
}

int send_stream_fd(int sockd, int fd, const char *display_filename, struct optstruct *clamdopts)
{
    /* A successful INSTREAM request must represent the complete input.  The
     * legacy client silently stopped at StreamMaxLength, sent the normal
     * terminator, and could therefore report a clean verdict for only a file
     * prefix.  Apply the same fail-closed accounting used by action streams to
     * every stream, including pipes/stdin where no size preflight is possible. */
    return send_stream_fd_common(sockd, fd, display_filename, clamdopts, "zINSTREAM");
}

int send_stream_fd_action(int sockd, int fd, const char *display_filename, struct optstruct *clamdopts)
{
    return send_stream_fd_common(sockd, fd, display_filename, clamdopts, "zINSTREAM");
}

int send_stream_fd_report(int sockd, int fd, const char *display_filename, struct optstruct *clamdopts)
{
    return send_stream_fd_common(sockd, fd, display_filename, clamdopts, "zINSTREAMREPORT");
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
    cl_error_t reply_status;
    char *bol;
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
            {
                char prefix[sizeof("zALLMATCHSCAN ")];
                unsigned int command_len;
                int prefix_len;

                prefix_len = snprintf(prefix, sizeof(prefix), "z%s ", scancmd[scantype]);
                if (prefix_len < 0 || (size_t)prefix_len >= sizeof(prefix) ||
                    build_clamd_path_command(prefix, filename, &bol, &command_len) < 0) {
                    logg(LOGG_ERROR, "Cannot build a bounded clamd scan command.\n");
                    infected = -1;
                    goto done;
                }
                if (sendln(sockd, bol, command_len)) {
                    free(bol);
                    infected = -1;
                    goto done;
                }
                free(bol);
            }
            /* A successfully sent path request only needs a positive reply
             * sentinel; the command length is not a scan result. */
            len = 1;
            break;
        case STREAM:
            /* NULL filename safe in send_stream() */
            len = (NULL != action_source) ? send_stream_fd_action(sockd, action_source->scan_fd, display_filename, clamdopts) : send_stream(sockd, filename, clamdopts);
            break;
#ifdef HAVE_FD_PASSING
        case FILDES:
            /* NULL filename safe in send_fdpass() */
            len = (NULL != action_source)
                      ? send_fdpass_fd_checked(sockd, action_source->scan_fd, display_filename, clamdopts)
                      : send_fdpass_checked(sockd, filename, clamdopts);
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

    while ((len = recvln(&rcv, &bol, NULL))) {
        if (len == -1) {
            infected = -1;
            goto done;
        }
        beenthere = 1;
        if (!filename) logg(LOGG_INFO, "%s\n", bol);
        reply_status = parse_clamd_legacy_reply(bol, (unsigned int)len);
        if (reply_status == CL_EPARSE) {
            logg(LOGG_INFO, "Failed to parse reply: \"%s\"\n", bol);
            infected = -1;
            goto done;
        }
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
            } else if (reply_status == CL_VIRUS) {
                static char last_filename[PATH_MAX + 1] = {'\0'};
                *(bol + len - sizeof(" FOUND"))         = 0;
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
            } else if (reply_status == CL_ERROR) {
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

static int recv_full(int sockd, void *buffer, size_t length)
{
    unsigned char *cursor = (unsigned char *)buffer;

    while (length) {
        int received = recv(sockd, (char *)cursor, (int)((length > INT_MAX) ? INT_MAX : length), 0);
        if (received < 0 && errno == EINTR)
            continue;
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
    *json        = NULL;
    *json_length = 0;
    *terminator  = 0;

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

static void report_json_free_keys(char **keys, size_t key_count)
{
    size_t i;

    for (i = 0; i < key_count; i++)
        free(keys[i]);
    free(keys);
}

/* Decode one top-level object key so escaped spellings such as "id" and
 * "\u0069d" cannot evade duplicate-key detection. JSON-C keeps only one
 * value for duplicate object names, so accepting them would make the
 * structured-report result depend on which duplicate happened to win. */
static int report_json_decode_key(const char *json, size_t json_length,
                                  size_t *cursor, char **key_out)
{
    size_t start;
    size_t end;
    size_t token_length;
    char *token = NULL;
    char *key = NULL;
    const char *value;
    struct json_tokener *tokener = NULL;
    struct json_object *object = NULL;
    enum json_tokener_error error;
    size_t parse_end;

    if (!json || !cursor || !key_out || *cursor >= json_length || json[*cursor] != '"')
        return -1;

    start = *cursor;
    end = start + 1;
    while (end < json_length) {
        unsigned char current = (unsigned char)json[end];

        if (current == '"')
            break;
        if (current < 0x20)
            return -1;
        if (current == '\\') {
            end++;
            if (end >= json_length)
                return -1;
            if (json[end] == 'u') {
                if (json_length - end < 5)
                    return -1;
                end += 4;
            }
        }
        end++;
    }
    if (end >= json_length || json[end] != '"')
        return -1;

    token_length = end - start + 1;
    if (token_length > INT_MAX)
        return -1;
    token = (char *)malloc(token_length + 1);
    if (!token)
        return -1;
    memcpy(token, json + start, token_length);
    token[token_length] = '\0';

    tokener = json_tokener_new();
    if (!tokener)
        goto fail;
    object = json_tokener_parse_ex(tokener, token, (int)token_length);
    error = json_tokener_get_error(tokener);
    parse_end = (size_t)json_tokener_get_parse_end(tokener);
    json_tokener_free(tokener);
    tokener = NULL;
    if (error != json_tokener_success || !object || parse_end != token_length ||
        !json_object_is_type(object, json_type_string))
        goto fail;

    value = json_object_get_string(object);
    if (!value)
        goto fail;
    key = (char *)malloc(strlen(value) + 1);
    if (!key)
        goto fail;
    strcpy(key, value);
    json_object_put(object);
    free(token);
    *cursor = end + 1;
    *key_out = key;
    return 0;

fail:
    if (tokener)
        json_tokener_free(tokener);
    json_object_put(object);
    free(key);
    free(token);
    return -1;
}

/* Detect duplicate names in the top-level structured-report object before
 * JSON-C collapses them. Nested metadata is intentionally not inspected: the
 * report consumers only bind top-level fields, and the normal parser remains
 * responsible for validating nested JSON syntax. */
static int report_json_top_level_keys_unique(const char *json, uint32_t json_length)
{
    char **keys = NULL;
    size_t key_count = 0;
    size_t key_capacity = 0;
    size_t cursor = 0;
    size_t i;

    while (cursor < json_length && isspace((unsigned char)json[cursor]))
        cursor++;
    if (cursor >= json_length || json[cursor] != '{')
        return 0;
    cursor++;

    while (1) {
        char *key = NULL;
        size_t depth = 0;
        bool in_string = false;

        while (cursor < json_length && isspace((unsigned char)json[cursor]))
            cursor++;
        if (cursor >= json_length)
            goto fail;
        if (json[cursor] == '}') {
            cursor++;
            while (cursor < json_length && isspace((unsigned char)json[cursor]))
                cursor++;
            if (cursor != json_length)
                goto fail;
            report_json_free_keys(keys, key_count);
            return 0;
        }

        if (report_json_decode_key(json, json_length, &cursor, &key) < 0)
            goto fail;
        for (i = 0; i < key_count; i++) {
            if (strcmp(keys[i], key) == 0) {
                free(key);
                goto fail;
            }
        }
        if (key_count == key_capacity) {
            size_t next_capacity = key_capacity ? key_capacity * 2 : 8;
            char **next_keys;

            if (next_capacity < key_capacity || next_capacity > SIZE_MAX / sizeof(*keys)) {
                free(key);
                goto fail;
            }
            next_keys = (char **)realloc(keys, next_capacity * sizeof(*keys));
            if (!next_keys) {
                free(key);
                goto fail;
            }
            keys = next_keys;
            key_capacity = next_capacity;
        }
        keys[key_count++] = key;

        while (cursor < json_length && isspace((unsigned char)json[cursor]))
            cursor++;
        if (cursor >= json_length || json[cursor] != ':')
            goto fail;
        cursor++;
        while (cursor < json_length && isspace((unsigned char)json[cursor]))
            cursor++;

        while (cursor < json_length) {
            unsigned char current = (unsigned char)json[cursor];

            if (in_string) {
                if (current == '\\') {
                    if (cursor + 1 >= json_length)
                        goto fail;
                    cursor += 2;
                    continue;
                }
                if (current == '"')
                    in_string = false;
                cursor++;
                continue;
            }
            if (current == '"') {
                in_string = true;
                cursor++;
                continue;
            }
            if (current == '{' || current == '[') {
                depth++;
                cursor++;
                continue;
            }
            if (current == '}' || current == ']') {
                if (depth == 0) {
                    if (current != '}')
                        goto fail;
                    break;
                }
                depth--;
                cursor++;
                continue;
            }
            if (current == ',' && depth == 0)
                break;
            cursor++;
        }
        if (in_string || depth != 0 || cursor >= json_length)
            goto fail;
        while (cursor < json_length && isspace((unsigned char)json[cursor]))
            cursor++;
        if (cursor >= json_length)
            goto fail;
        if (json[cursor] == ',') {
            cursor++;
            continue;
        }
        if (json[cursor] == '}') {
            cursor++;
            while (cursor < json_length && isspace((unsigned char)json[cursor]))
                cursor++;
            if (cursor != json_length)
                goto fail;
            report_json_free_keys(keys, key_count);
            return 0;
        }
        goto fail;
    }

fail:
    report_json_free_keys(keys, key_count);
    return -1;
}

static struct json_object *report_json_parse_object(const char *json, uint32_t json_length)
{
    struct json_object *object;
    struct json_tokener *tokener;
    enum json_tokener_error error;
    size_t parse_end;

    if (!json || json_length == 0 || json_length > INT_MAX || json[json_length] != '\0' ||
        report_json_top_level_keys_unique(json, json_length) < 0)
        return NULL;

    tokener = json_tokener_new();
    if (!tokener)
        return NULL;
    object = json_tokener_parse_ex(tokener, json, (int)json_length);
    error  = json_tokener_get_error(tokener);
    parse_end = (size_t)json_tokener_get_parse_end(tokener);
    while (parse_end < json_length && isspace((unsigned char)json[parse_end]))
        parse_end++;
    json_tokener_free(tokener);

    if (error != json_tokener_success || !object || parse_end != json_length ||
        !json_object_is_type(object, json_type_object)) {
        json_object_put(object);
        return NULL;
    }
    return object;
}

int scan_report_json_id(const char *json, uint32_t json_length, unsigned int *id)
{
    struct json_object *object;
    struct json_object *id_object = NULL;
    int64_t value;

    if (!json || !id || json_length == 0)
        return -1;

    object = report_json_parse_object(json, json_length);
    if (!object || !json_object_object_get_ex(object, "id", &id_object) ||
        !json_object_is_type(id_object, json_type_int)) {
        json_object_put(object);
        return -1;
    }

    value = json_object_get_int64(id_object);
    if (value < 0 || (uint64_t)value > UINT_MAX) {
        json_object_put(object);
        return -1;
    }

    *id = (unsigned int)value;
    json_object_put(object);
    return 0;
}

static int scan_report_json_status_value(struct json_object *object, cl_error_t *status_out, int required)
{
    struct json_object *status_object = NULL;
    int status;

    if (!object || !status_out)
        return -1;
    if (!json_object_object_get_ex(object, "status", &status_object)) {
        if (required)
            return -1;
        *status_out = CL_EPARSE;
        return 0;
    }
    if (!json_object_is_type(status_object, json_type_int))
        return -1;
    status = json_object_get_int(status_object);
    if (status < CL_SUCCESS || status >= CL_ELAST_ERROR)
        return -1;
    *status_out = (cl_error_t)status;
    return 0;
}

static int scan_report_json_incomplete_status_is_valid(cl_error_t status)
{
    return status != CL_SUCCESS && status != CL_VERIFIED && status != CL_VIRUS;
}

static int scan_report_completion_name_is_known(const char *completion)
{
    if (!completion)
        return 0;

    return strcmp(completion, "COMPLETE") == 0 ||
           strcmp(completion, "DETECTION_TERMINATED") == 0 ||
           strcmp(completion, "LIMIT_INCOMPLETE") == 0 ||
           strcmp(completion, "UNSUPPORTED") == 0 ||
           strcmp(completion, "MALFORMED_CONFIRMED") == 0 ||
           strcmp(completion, "RESOURCE_FAILURE") == 0 ||
           strcmp(completion, "APPLICATION_ABORT") == 0;
}

static int scan_report_completion_name_is_incomplete(const char *completion)
{
    if (!completion)
        return 0;

    return strcmp(completion, "LIMIT_INCOMPLETE") == 0 ||
           strcmp(completion, "UNSUPPORTED") == 0 ||
           strcmp(completion, "MALFORMED_CONFIRMED") == 0 ||
           strcmp(completion, "RESOURCE_FAILURE") == 0 ||
           strcmp(completion, "APPLICATION_ABORT") == 0;
}

int scan_report_json_status(const char *json, uint32_t json_length, int *infected, int *incomplete,
                            cl_error_t *status_out)
{
    struct json_object *object;
    struct json_object *completion_object = NULL;
    struct json_object *status_object     = NULL;
    struct json_object *verdict_object    = NULL;
    const char *completion;
    cl_error_t report_status;
    int verdict;

    if (!json || !infected || !incomplete || !status_out || json_length == 0)
        return -1;

    *infected   = 0;
    *incomplete = 0;
    *status_out = CL_ERROR;

    object = report_json_parse_object(json, json_length);
    if (!object || !json_object_object_get_ex(object, "verdict", &verdict_object)) {
        json_object_put(object);
        return -1;
    }

    if (json_object_object_get_ex(object, "completion", &completion_object)) {
        if (!json_object_is_type(completion_object, json_type_string))
            goto invalid;
        completion = json_object_get_string(completion_object);
        if (!completion)
            goto invalid;
    } else {
        completion = NULL;
    }

    /* Do not let an unrecognized completion label turn a malformed or
     * contradictory report into an authoritative outcome. */
    if (completion && !scan_report_completion_name_is_known(completion))
        goto invalid;

    if (json_object_is_type(verdict_object, json_type_int)) {
        if (!json_object_object_get_ex(object, "version", &status_object) ||
            !json_object_is_type(status_object, json_type_int) ||
            json_object_get_int64(status_object) != 1)
            goto invalid;

        verdict = json_object_get_int(verdict_object);

        if (!completion || verdict < CL_VERDICT_NOTHING_FOUND ||
            verdict > CL_VERDICT_POTENTIALLY_UNWANTED)
            goto invalid;

        /* Detection remains authoritative even when a sibling parser path
         * also reported an incomplete outcome. */
        if (verdict == CL_VERDICT_STRONG_INDICATOR ||
            verdict == CL_VERDICT_POTENTIALLY_UNWANTED) {
            if (strcmp(completion, "DETECTION_TERMINATED") != 0)
                goto invalid;
            if (scan_report_json_status_value(object, &report_status, 0) < 0)
                goto invalid;
            *infected   = 1;
            *incomplete = 0;
            *status_out = CL_VIRUS;
            json_object_put(object);
            return 0;
        }

        if (strcmp(completion, "DETECTION_TERMINATED") == 0)
            goto invalid;
        if (strcmp(completion, "COMPLETE") == 0) {
            if (verdict != CL_VERDICT_NOTHING_FOUND && verdict != CL_VERDICT_TRUSTED)
                goto invalid;
            if (!json_object_object_get_ex(object, "status", &status_object) ||
                !json_object_is_type(status_object, json_type_int))
                goto invalid;
            if (json_object_get_int(status_object) != CL_SUCCESS)
                goto invalid;
            *infected   = 0;
            *incomplete = 0;
            *status_out = CL_SUCCESS;
            json_object_put(object);
            return 0;
        }
        if (strcmp(completion, "LIMIT_INCOMPLETE") == 0 ||
            strcmp(completion, "UNSUPPORTED") == 0 ||
            strcmp(completion, "MALFORMED_CONFIRMED") == 0 ||
            strcmp(completion, "RESOURCE_FAILURE") == 0 ||
            strcmp(completion, "APPLICATION_ABORT") == 0) {
            if (scan_report_json_status_value(object, &report_status, 1) < 0 ||
                !scan_report_json_incomplete_status_is_valid(report_status))
                goto invalid;
            *infected   = 0;
            *incomplete = 1;
            *status_out = report_status;
            json_object_put(object);
            return 0;
        }
        goto invalid;
    }

    if (!json_object_is_type(verdict_object, json_type_string))
        goto invalid;
    if (strcmp(json_object_get_string(verdict_object), "infected") == 0) {
        if (completion && strcmp(completion, "DETECTION_TERMINATED") != 0)
            goto invalid;
        if (scan_report_json_status_value(object, &report_status, 0) < 0)
            goto invalid;
        *infected   = 1;
        *incomplete = 0;
        *status_out = CL_VIRUS;
        json_object_put(object);
        return 0;
    }
    if (strcmp(json_object_get_string(verdict_object), "incomplete") == 0) {
        if (completion && !scan_report_completion_name_is_incomplete(completion))
            goto invalid;
        if (scan_report_json_status_value(object, &report_status, 0) < 0 ||
            !scan_report_json_incomplete_status_is_valid(report_status))
            goto invalid;
        *infected   = 0;
        *incomplete = 1;
        *status_out = report_status;
        json_object_put(object);
        return 0;
    }
    /* A string-valued clean verdict is not a versioned structured report.
     * In particular, do not accept the historical compact fallback as a
     * successful clean result when its report body is unavailable. */

invalid:
    json_object_put(object);
    return -1;
}

const char *scan_report_completion_name(cl_scan_completion_t completion)
{
    switch (completion) {
        case CL_SCAN_COMPLETION_COMPLETE:
            return "COMPLETE";
        case CL_SCAN_COMPLETION_DETECTION_TERMINATED:
            return "DETECTION_TERMINATED";
        case CL_SCAN_COMPLETION_LIMIT_INCOMPLETE:
            return "LIMIT_INCOMPLETE";
        case CL_SCAN_COMPLETION_UNSUPPORTED:
            return "UNSUPPORTED";
        case CL_SCAN_COMPLETION_MALFORMED_CONFIRMED:
            return "MALFORMED_CONFIRMED";
        case CL_SCAN_COMPLETION_RESOURCE_FAILURE:
            return "RESOURCE_FAILURE";
        case CL_SCAN_COMPLETION_APPLICATION_ABORT:
            return "APPLICATION_ABORT";
        default:
            return NULL;
    }
}

static int scan_report_completion_from_name(const char *name, cl_scan_completion_t *completion_out)
{
    cl_scan_completion_t completion;

    if (!name || !completion_out)
        return -1;
    for (completion = CL_SCAN_COMPLETION_COMPLETE;
         completion <= CL_SCAN_COMPLETION_APPLICATION_ABORT;
         completion++) {
        const char *expected = scan_report_completion_name(completion);
        if (expected && strcmp(name, expected) == 0) {
            *completion_out = completion;
            return 0;
        }
    }
    return -1;
}

static int scan_report_json_u64_value(struct json_object *object, const char *name, uint64_t *value_out)
{
    struct json_object *value_object = NULL;
    int64_t value;

    if (!object || !name || !value_out ||
        !json_object_object_get_ex(object, name, &value_object) ||
        !json_object_is_type(value_object, json_type_int))
        return -1;
    value = json_object_get_int64(value_object);
    if (value < 0)
        return -1;
    *value_out = (uint64_t)value;
    return 0;
}

int scan_report_json_metadata(const char *json, uint32_t json_length,
                              cl_scan_completion_t *completion_out,
                              uint64_t *root_size_out,
                              uint64_t *logical_bytes_out,
                              uint64_t *max_scan_size_out,
                              uint64_t *skipped_operations_out,
                              uint64_t *last_alert_offset_out,
                              int *last_alert_offset_valid_out)
{
    struct json_object *object;
    struct json_object *version_object = NULL;
    struct json_object *completion_object = NULL;
    int64_t version;

    if (!json || !completion_out || !root_size_out || !logical_bytes_out ||
        !max_scan_size_out || !skipped_operations_out ||
        !last_alert_offset_out || !last_alert_offset_valid_out || json_length == 0)
        return -1;

    *last_alert_offset_out       = 0;
    *last_alert_offset_valid_out = 0;
    object = report_json_parse_object(json, json_length);
    if (!object ||
        !json_object_object_get_ex(object, "version", &version_object) ||
        !json_object_is_type(version_object, json_type_int)) {
        json_object_put(object);
        return -1;
    }
    version = json_object_get_int64(version_object);
    if (version != 1 ||
        !json_object_object_get_ex(object, "completion", &completion_object) ||
        !json_object_is_type(completion_object, json_type_string) ||
        scan_report_completion_from_name(json_object_get_string(completion_object), completion_out) < 0 ||
        scan_report_json_u64_value(object, "root_size", root_size_out) < 0 ||
        scan_report_json_u64_value(object, "logical_bytes", logical_bytes_out) < 0 ||
        scan_report_json_u64_value(object, "max_scan_size", max_scan_size_out) < 0 ||
        scan_report_json_u64_value(object, "skipped_operations", skipped_operations_out) < 0) {
        json_object_put(object);
        return -1;
    }

    if (json_object_object_get_ex(object, "last_alert_offset", &completion_object)) {
        if (scan_report_json_u64_value(object, "last_alert_offset", last_alert_offset_out) < 0) {
            json_object_put(object);
            return -1;
        }
        if (*last_alert_offset_out > *root_size_out) {
            json_object_put(object);
            return -1;
        }
        *last_alert_offset_valid_out = 1;
    }

    json_object_put(object);
    return 0;
}

int scan_report_json_alert(const char *json, uint32_t json_length, char **alert)
{
    struct json_object *object;
    struct json_object *alert_object = NULL;
    const char *value;

    if (!json || !alert || json_length == 0 || json[json_length] != '\0')
        return -1;

    *alert = NULL;
    object = report_json_parse_object(json, json_length);
    if (!object)
        return -1;
    if (!json_object_object_get_ex(object, "last_alert", &alert_object)) {
        json_object_put(object);
        return 0;
    }
    if (json_object_is_type(alert_object, json_type_null)) {
        json_object_put(object);
        return 0;
    }
    if (!json_object_is_type(alert_object, json_type_string)) {
        json_object_put(object);
        return -1;
    }
    value = json_object_get_string(alert_object);
    *alert = value ? strdup(value) : NULL;
    json_object_put(object);
    return value && !*alert ? -1 : 0;
}

int dsreport(int sockd, int scantype, const char *filename, const struct action_source *action_source,
             bool apply_action, FILE *report_stream, int *infected, int *incomplete,
             int *errors, struct optstruct *clamdopts)
{
    int sent = 0;
    int frame;
    int terminated               = 0;
    char *command;
    const char *display_filename = (NULL != action_source) ? action_source->display_path : filename;

    if (!infected || !incomplete || !errors)
        return -1;

#ifdef HAVE_FD_PASSING
    if (scantype == FILDES && clamdopts != NULL) {
        int preflight_fd = -1;
        bool close_preflight_fd = false;
        cl_error_t preflight_status = CL_SUCCESS;
        int preflight;

        if (action_source != NULL) {
            preflight_fd = action_source->scan_fd;
        } else if (filename != NULL) {
            preflight_fd = safe_open(filename, O_RDONLY | O_BINARY);
            close_preflight_fd = (preflight_fd >= 0);
        } else {
            preflight_fd = 0;
        }
        if (preflight_fd < 0) {
            if (close_preflight_fd)
                close(preflight_fd);
            return -1;
        }
        preflight = clamd_fdpass_size_preflight(
            preflight_fd, display_filename, clamdopts, &preflight_status, NULL);
        if (close_preflight_fd)
            close(preflight_fd);
        if (preflight == 0 && preflight_status == CL_EMAXSIZE)
            return -(int)CL_EMAXSIZE;
        if (preflight < 0)
            return -1;
    }
#endif

    if (scantype == STREAM) {
        int preflight_fd = -1;
        bool close_preflight_fd = false;
        cl_error_t preflight_status = CL_SUCCESS;
        int preflight;

        if (action_source != NULL) {
            preflight_fd = action_source->scan_fd;
        } else if (filename != NULL) {
            preflight_fd = safe_open(filename, O_RDONLY | O_BINARY);
            close_preflight_fd = (preflight_fd >= 0);
        } else {
            preflight_fd = 0;
        }
        if (preflight_fd < 0) {
            if (close_preflight_fd)
                close(preflight_fd);
            return -1;
        }

        preflight = clamd_stream_size_preflight(
            preflight_fd, display_filename, clamdopts, &preflight_status, NULL);
        if (close_preflight_fd)
            close(preflight_fd);
        if (preflight == 0 && preflight_status == CL_EMAXSIZE)
            return -(int)CL_EMAXSIZE;
        if (preflight < 0)
            return -1;
    }

    /* sendln() returns zero on success; use a positive sentinel here because
     * the shared report loop treats non-positive send results as failures. */
    switch (scantype) {
        case CONT:
            if (!filename)
                return -1;
            {
                unsigned int command_len;
                if (build_clamd_path_command("zCONTSCANREPORT ", filename, &command, &command_len) < 0)
                    return -1;
                if (sendln(sockd, command, command_len)) {
                    free(command);
                    return -1;
                }
                sent = 1;
                free(command);
            }
            break;
        case MULTI:
            if (!filename)
                return -1;
            {
                unsigned int command_len;
                if (build_clamd_path_command("zMULTISCANREPORT ", filename, &command, &command_len) < 0)
                    return -1;
                if (sendln(sockd, command, command_len)) {
                    free(command);
                    return -1;
                }
                sent = 1;
                free(command);
            }
            break;
        case ALLMATCH:
            if (!filename)
                return -1;
            {
                unsigned int command_len;
                if (build_clamd_path_command("zALLMATCHSCANREPORT ", filename, &command, &command_len) < 0)
                    return -1;
                if (sendln(sockd, command, command_len)) {
                    free(command);
                    return -1;
                }
                sent = 1;
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
                       ? send_fdpass_fd_report_checked(sockd, action_source->scan_fd, display_filename, clamdopts)
                       : send_fdpass_report_checked(sockd, filename, clamdopts);
            break;
#endif
        default:
            return -1;
    }

    if (sent <= 0) {
        /* Preserve a client-side known-size admission failure so the report
         * caller can serialize LIMIT_INCOMPLETE instead of a generic
         * transport/resource fallback. */
        if (sent == -(int)CL_EMAXSIZE)
            return sent;
        return -1;
    }

    {
        int received = 0;

        while (!terminated) {
            char *json           = NULL;
            uint32_t json_length = 0;
            int frame_infected   = 0;
            int frame_incomplete = 0;
            cl_error_t frame_status = CL_ERROR;
            char *frame_alert     = NULL;

            frame = recv_scan_report_frame(sockd, &json, &json_length, &terminated);
            if (frame < 0) {
                logg(LOGG_ERROR, "Failed to receive structured scan report frame from clamd.\n");
                return -1;
            }
            if (terminated)
                break;
            /* Each structured report request has exactly one JSON report
             * object followed by the zero-length terminator. Do not merge a
             * second frame into the caller's result. */
            if (received) {
                logg(LOGG_ERROR, "Received multiple structured scan report frames from clamd.\n");
                free(json);
                return -1;
            }
            received = 1;
            if (scan_report_json_status(json, json_length, &frame_infected, &frame_incomplete,
                                        &frame_status) < 0) {
                logg(LOGG_ERROR, "Invalid structured scan report frame from clamd (%u bytes).\n", json_length);
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
                if (scan_report_json_alert(json, json_length, &frame_alert) < 0) {
                    free(json);
                    return -1;
                }
                if (!frame_alert || !*frame_alert) {
                    logg(LOGG_ERROR,
                         "%s: infected structured report has no exact alert name\n",
                         display_filename ? display_filename : "stdin");
                    free(frame_alert);
                    free(json);
                    return -1;
                }
                (*infected)++;
                logg(LOGG_INFO, "%s: %s FOUND\n", display_filename ? display_filename : "stdin",
                     frame_alert);
                if (apply_action && action && action_source)
                    action((action_source_t *)action_source);
            } else if (frame_incomplete) {
                (*incomplete)++;
                (*errors)++;
                logg(LOGG_INFO, "%s: INCOMPLETE (%s)\n", display_filename ? display_filename : "stream",
                     cl_strerror(frame_status));
            }
            free(frame_alert);
            free(json);
        }

        if (!received)
            return -1;
    }

    return 0;
}
