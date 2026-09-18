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

#ifndef ONAS_COM_H
#define ONAS_COM_H

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#include <stdio.h>

#include "misc.h"

struct onas_rcvln {
    char buf[PATH_MAX + 1024];
    int sockd;
    CURL *curl;
    CURLcode curlcode;
    size_t retlen;
    char *curr;
    char *lnstart;
};

int onas_sendln(CURL *curl, const void *line, size_t len, int64_t timeout_ms, cl_error_t *ret_code);
int onas_write_scan_report(FILE *stream, const char *payload, size_t payload_length, uint64_t event_id);
void onas_recvlninit(struct onas_rcvln *s, CURL *curl, int sockd);
int onas_recvln(struct onas_rcvln *rcv_data, char **ret_bol, char **ret_eol, int64_t timeout_ms);
int onas_fd_recvln(struct onas_rcvln *rcv_data, char **ret_bol, char **ret_eol, int64_t timeout_ms);
int onas_recv_scan_report(struct onas_rcvln *rcv_data, int64_t timeout_ms,
                          int *infected, int *incomplete, cl_error_t *status_out,
                          FILE *report_stream, int *report_written,
                          uint64_t event_id);

#endif
