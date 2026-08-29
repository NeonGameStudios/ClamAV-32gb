/*
 *  Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 *
 *  Author: Shawn Webb
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <sys/types.h>
#include <errno.h>

#if defined(_WIN32)
#include <WinSock2.h>
#include <Windows.h>
#endif

#include "others.h"
#include "clamav.h"

#define JSON_BUFSZ 512

char *hex_encode(char *buf, char *data, size_t len);
char *ensure_bufsize(char *buf, size_t *oldsize, size_t used, size_t additional);
char *export_stats_to_json(struct cl_engine *engine, cli_intel_t *intel);

char *hex_encode(char *buf, char *data, size_t len)
{
    size_t i;
    char *p;
    static const char hex[] = "0123456789abcdef";

    if ((len != 0 && data == NULL) || len > (SIZE_MAX - 1) / 2)
        return NULL;

    p = (buf != NULL) ? buf : cli_max_calloc(1, (len * 2) + 1);
    if (!(p))
        return NULL;

    for (i = 0; i < len; i++) {
        unsigned char value = (unsigned char)data[i];
        p[i * 2]     = hex[value >> 4];
        p[(i * 2) + 1] = hex[value & 0x0f];
    }
    p[len * 2] = '\0';

    return p;
}

char *ensure_bufsize(char *buf, size_t *oldsize, size_t used, size_t additional)
{
    char *p;
    size_t required;
    size_t growth;
    size_t chunks;
    size_t increase;
    size_t newsize;

    if (oldsize == NULL || used > *oldsize || additional > SIZE_MAX - used) {
        cli_errmsg("ensure_bufsize: invalid size request\n");
        free(buf);
        return NULL;
    }
    if (additional <= *oldsize - used)
        return buf;

    required = used + additional;
    if (required > CLI_MAX_ALLOCATION) {
        cli_errmsg("ensure_bufsize: requested JSON exceeds the individual allocation limit\n");
        free(buf);
        return NULL;
    }

    growth = required - *oldsize;
    chunks = growth / JSON_BUFSZ;
    if (growth % JSON_BUFSZ != 0)
        chunks++;
    if (chunks > SIZE_MAX / JSON_BUFSZ) {
        cli_errmsg("ensure_bufsize: JSON growth overflows native size\n");
        free(buf);
        return NULL;
    }
    increase = chunks * JSON_BUFSZ;
    if (increase > SIZE_MAX - *oldsize)
        newsize = required;
    else
        newsize = *oldsize + increase;
    if (newsize < required || newsize > CLI_MAX_ALLOCATION)
        newsize = required;

    p = cli_max_realloc(buf, newsize);
    if (!(p)) {
        cli_errmsg("ensure_bufsize: Could not allocate more memory: %s (errno: %d)\n", strerror(errno), errno);
        free(buf);
        return NULL;
    }

    *oldsize = newsize;
    return p;
}

static char *json_appendf(char *buf, size_t *bufsz, size_t *used, const char *format, ...)
{
    va_list ap;
    va_list measure;
    int needed;
    int written;

    if (bufsz == NULL || used == NULL || format == NULL) {
        free(buf);
        return NULL;
    }

    va_start(ap, format);
    va_copy(measure, ap);
    needed = vsnprintf(NULL, 0, format, measure);
    va_end(measure);
    if (needed < 0 || (size_t)needed == SIZE_MAX ||
        (size_t)needed + 1 > SIZE_MAX - *used) {
        va_end(ap);
        free(buf);
        return NULL;
    }

    buf = ensure_bufsize(buf, bufsz, *used, (size_t)needed + 1);
    if (buf == NULL) {
        va_end(ap);
        return NULL;
    }

    written = vsnprintf(buf + *used, *bufsz - *used, format, ap);
    va_end(ap);
    if (written < 0 || written != needed) {
        free(buf);
        return NULL;
    }
    *used += (size_t)written;
    return buf;
}

static char *json_append_escaped(char *buf, size_t *bufsz, size_t *used, const char *value)
{
    const unsigned char *p;
    size_t required = 2;

    if (value == NULL)
        value = "";

    for (p = (const unsigned char *)value; *p != '\0'; p++) {
        size_t addition;

        if (*p == '"' || *p == '\\' || *p == '\b' || *p == '\f' ||
            *p == '\n' || *p == '\r' || *p == '\t')
            addition = 2;
        else if (*p < 0x20)
            addition = 6;
        else
            addition = 1;

        if (addition > SIZE_MAX - required) {
            free(buf);
            return NULL;
        }
        required += addition;
    }
    if (required == SIZE_MAX || *used > SIZE_MAX - (required + 1)) {
        free(buf);
        return NULL;
    }

    buf = ensure_bufsize(buf, bufsz, *used, required + 1);
    if (buf == NULL)
        return NULL;

    buf[(*used)++] = '"';
    for (p = (const unsigned char *)value; *p != '\0'; p++) {
        switch (*p) {
            case '"':
                buf[(*used)++] = '\\';
                buf[(*used)++] = '"';
                break;
            case '\\':
                buf[(*used)++] = '\\';
                buf[(*used)++] = '\\';
                break;
            case '\b':
                buf[(*used)++] = '\\';
                buf[(*used)++] = 'b';
                break;
            case '\f':
                buf[(*used)++] = '\\';
                buf[(*used)++] = 'f';
                break;
            case '\n':
                buf[(*used)++] = '\\';
                buf[(*used)++] = 'n';
                break;
            case '\r':
                buf[(*used)++] = '\\';
                buf[(*used)++] = 'r';
                break;
            case '\t':
                buf[(*used)++] = '\\';
                buf[(*used)++] = 't';
                break;
            default:
                if (*p < 0x20) {
                    static const char hex[] = "0123456789abcdef";
                    buf[(*used)++] = '\\';
                    buf[(*used)++] = 'u';
                    buf[(*used)++] = '0';
                    buf[(*used)++] = '0';
                    buf[(*used)++] = hex[*p >> 4];
                    buf[(*used)++] = hex[*p & 0x0f];
                } else {
                    buf[(*used)++] = (char)*p;
                }
                break;
        }
    }
    buf[(*used)++] = '"';
    buf[*used]      = '\0';
    return buf;
}

char *export_stats_to_json(struct cl_engine *engine, cli_intel_t *intel)
{
    char *buf = NULL, *hostid, md5[33];
    cli_flagged_sample_t *sample;
    size_t bufsz = JSON_BUFSZ;
    size_t curused = 0;
    size_t i, j;
    bool first_sample = true;

    if (engine == NULL || intel == NULL)
        return NULL;

    if (!(intel->hostid))
        if ((engine->cb_stats_get_hostid))
            intel->hostid = engine->cb_stats_get_hostid(engine->stats_data);

    hostid = (intel->hostid != NULL) ? intel->hostid : STATS_ANON_UUID;

    buf = cli_max_calloc(1, JSON_BUFSZ);
    if (!(buf))
        return NULL;

    buf = json_appendf(buf, &bufsz, &curused, "{\n\t\"hostid\": ");
    if (buf == NULL)
        return NULL;
    buf = json_append_escaped(buf, &bufsz, &curused, hostid);
    if (buf == NULL)
        return NULL;
    buf = json_appendf(buf, &bufsz, &curused, ",\n");
    if (buf == NULL)
        return NULL;
    if (intel->host_info != NULL) {
        buf = json_appendf(buf, &bufsz, &curused, "\t\"host_info\": ");
        if (buf == NULL)
            return NULL;
        buf = json_append_escaped(buf, &bufsz, &curused, intel->host_info);
        if (buf == NULL)
            return NULL;
        buf = json_appendf(buf, &bufsz, &curused, ",\n");
        if (buf == NULL)
            return NULL;
    }
    buf = json_appendf(buf, &bufsz, &curused, "\t\"samples\": [\n");
    if (buf == NULL)
        return NULL;

    for (sample = intel->samples; sample != NULL; sample = sample->next) {
        if (sample->hits == 0)
            continue;

        if (!first_sample) {
            buf = json_appendf(buf, &bufsz, &curused, ",\n");
            if (buf == NULL)
                return NULL;
        }
        first_sample = false;

        memset(md5, 0x00, sizeof(md5));
        if (hex_encode(md5, sample->md5, sizeof(sample->md5)) == NULL) {
            free(buf);
            return NULL;
        }

        buf = json_appendf(buf, &bufsz, &curused, "\t\t\t{\n");
        if (!(buf))
            return NULL;

        buf = json_appendf(buf, &bufsz, &curused, "\t\t\t\"hash\": \"%s\",\n", md5);
        if (!(buf))
            return NULL;

        /* Reuse the md5 variable for serializing the number of hits */
        snprintf(md5, sizeof(md5), "%u", sample->hits);
        buf = json_appendf(buf, &bufsz, &curused, "\t\t\t\"hits\": %s,\n", md5);
        if (!(buf))
            return NULL;

        snprintf(md5, sizeof(md5), STDu64, sample->size);
        buf = json_appendf(buf, &bufsz, &curused, "\t\t\t\"size\": %s,\n", md5);
        if (!(buf))
            return NULL;

        if (sample->sections != NULL && sample->sections->nsections != 0) {
            if (sample->sections->sections == NULL) {
                free(buf);
                return NULL;
            }
            buf = json_appendf(buf, &bufsz, &curused, "\t\t\t\"sections\": [\n");
            if (!(buf))
                return NULL;

            for (i = 0; i < sample->sections->nsections; i++) {
                if (i != 0) {
                    buf = json_appendf(buf, &bufsz, &curused, ",\n");
                    if (!(buf))
                        return NULL;
                }
                buf = json_appendf(buf, &bufsz, &curused, "\t\t\t\t{\n");
                if (!(buf))
                    return NULL;

                memset(md5, 0x00, sizeof(md5));
                for (j = 0; j < 16; j++)
                    snprintf(md5 + (j * 2), sizeof(md5) - (j * 2), "%02x", sample->sections->sections[i].md5[j]);

                buf = json_appendf(buf, &bufsz, &curused, "\t\t\t\t\t\"hash\": \"%s\",\n", md5);
                if (!(buf))
                    return NULL;
                buf = json_appendf(buf, &bufsz, &curused, "\t\t\t\t\t\"size\": %zu\n", sample->sections->sections[i].len);
                if (!(buf))
                    return NULL;
                buf = json_appendf(buf, &bufsz, &curused, "\t\t\t\t}");
                if (!(buf))
                    return NULL;
            }

            buf = json_appendf(buf, &bufsz, &curused, "\n\t\t\t],\n");
            if (!(buf))
                return NULL;
        }

        buf = json_appendf(buf, &bufsz, &curused, "\t\t\t\"virus_names\": [ ");
        if (!(buf))
            return NULL;

        if (sample->virus_name != NULL) {
            bool first_virus = true;
            for (i = 0; sample->virus_name[i] != NULL; i++) {
                if (!first_virus) {
                    buf = json_appendf(buf, &bufsz, &curused, ", ");
                    if (!(buf))
                        return NULL;
                }
                first_virus = false;
                buf = json_append_escaped(buf, &bufsz, &curused, sample->virus_name[i]);
                if (!(buf))
                    return NULL;
            }
        }

        buf = json_appendf(buf, &bufsz, &curused, " ]\n\t\t}");
        if (!(buf))
            return NULL;
    }

    buf = json_appendf(buf, &bufsz, &curused, "\n\t]\n}\n");
    if (!(buf))
        return NULL;

    return buf;
}
