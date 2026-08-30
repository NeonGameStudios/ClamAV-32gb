/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Trog, Török Edvin
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <ctype.h>
#ifndef _WIN32
#include <netinet/in.h>
#endif

#include "clamav.h"
#include "others.h"
#include "special.h"
#include "matcher.h"

/* NOTE: Photoshop stores data in BIG ENDIAN format, this is the opposite
        to virtually everything else */

#define special_endian_convert_16(v) be16_to_host(v)
#define special_endian_convert_32(v) be32_to_host(v)

int cli_check_mydoom_log(cli_ctx *ctx)
{
    uint32_t record[16];
    const uint8_t *ptr;
    uint32_t check, key;
    fmap_t *map;
    unsigned int blocks;

    cli_dbgmsg("in cli_check_mydoom_log()\n");
    if (ctx == NULL) {
        cli_dbgmsg("Mydoom log detector: passed context was NULL\n");
        return CL_ENULLARG;
    }
    map = ctx->fmap;
    if (map == NULL) {
        cli_mark_scan_incomplete(ctx, "Mydoom log detector input map is unavailable");
        return CL_EPARSE;
    }
    blocks = map->len / (8 * 4);
    if (blocks < 2)
        return CL_CLEAN;
    if (blocks > 5)
        blocks = 5;

    /*
     * The following pointer might not be properly aligned. There there is
     * memcmp() + memcpy() workaround to avoid performing an unaligned access
     * while reading the uint32_t.
     */
    ptr = fmap_need_off_once(map, 0, 8 * 4 * blocks);
    if (!ptr) {
        cli_mark_scan_incomplete(ctx, "Mydoom log detector input window could not be read completely");
        return CL_EREAD;
    }

    while (blocks) { /* This wasn't probably intended but that's what the current code does anyway */
        const uint32_t marker_ff = 0xffffffff;

        if (!memcmp(ptr + ((size_t)(--blocks) * sizeof(uint32_t)),
                    &marker_ff, sizeof(uint32_t)))
            return CL_CLEAN;
    }

    memcpy(record, ptr, sizeof(record));

    key   = ~be32_to_host(record[0]);
    check = (be32_to_host(record[1]) ^ key) +
            (be32_to_host(record[2]) ^ key) +
            (be32_to_host(record[3]) ^ key) +
            (be32_to_host(record[4]) ^ key) +
            (be32_to_host(record[5]) ^ key) +
            (be32_to_host(record[6]) ^ key) +
            (be32_to_host(record[7]) ^ key);
    if ((~check) != key)
        return CL_CLEAN;

    key   = ~be32_to_host(record[8]);
    check = (be32_to_host(record[9]) ^ key) +
            (be32_to_host(record[10]) ^ key) +
            (be32_to_host(record[11]) ^ key) +
            (be32_to_host(record[12]) ^ key) +
            (be32_to_host(record[13]) ^ key) +
            (be32_to_host(record[14]) ^ key) +
            (be32_to_host(record[15]) ^ key);
    if ((~check) != key)
        return CL_CLEAN;

    return cli_append_potentially_unwanted(ctx, "Heuristics.Worm.Mydoom.M.log");
}

static uint32_t riff_endian_convert_32(uint32_t value, int big_endian)
{
    if (big_endian)
        return be32_to_host(value);
    else
        return le32_to_host(value);
}

static cl_error_t riff_checktimelimit(cli_ctx *ctx)
{
    cl_error_t status = cli_checktimelimit(ctx);

    if (status != CL_SUCCESS)
        cli_mark_scan_incomplete(ctx, "RIFF inspection reached the configured time limit");

    return status;
}

/* fmap_need_off_once() uses NULL for both an unavailable range and a failed
 * backing read. Keep those cases distinct while the RIFF exploit detector
 * walks a structurally confirmed file. */
static const void *riff_need_off(cli_ctx *ctx, off_t offset, size_t length, cl_error_t *read_status)
{
    fmap_t *map;
    const void *ptr;

    if (read_status != NULL)
        *read_status = CL_EPARSE;
    if (ctx == NULL || ctx->fmap == NULL || length == 0)
        return NULL;

    map = ctx->fmap;
    if (offset < 0 || (uint64_t)offset > (uint64_t)map->len ||
        length > map->len - (size_t)offset)
        return NULL;

    ptr = fmap_need_off_once(map, (size_t)offset, length);
    if (NULL == ptr) {
        if (read_status != NULL)
            *read_status = CL_EREAD;
    } else if (read_status != NULL) {
        *read_status = CL_SUCCESS;
    }

    return ptr;
}

static int riff_read_chunk(cli_ctx *ctx, off_t *offset, int big_endian, int rec_level, uint64_t limit,
                           cl_error_t *read_status)
{
    cl_error_t time_status;
    uint32_t cache_buf;
    const char *buffer;
    const uint8_t *buf;
    uint32_t chunk_size;
    uint64_t next_offset;
    uint64_t list_end;
    off_t cur_offset = *offset;
    fmap_t *map      = ctx->fmap;

    time_status = riff_checktimelimit(ctx);
    if (time_status != CL_SUCCESS)
        return time_status;

    if (rec_level > 1000) {
        cli_dbgmsg("riff_read_chunk: recursion level exceeded\n");
        cli_mark_scan_incomplete(ctx, "RIFF inspection exceeded the nested-list limit");
        return CL_EPARSE;
    }

    if (cur_offset < 0 || (uint64_t)cur_offset > limit || 8 > limit - (uint64_t)cur_offset) {
        cli_mark_scan_incomplete(ctx, "RIFF chunk header exceeded its containing range");
        if (read_status != NULL)
            *read_status = CL_EPARSE;
        return CL_EPARSE;
    }

    if (!(buf = riff_need_off(ctx, cur_offset, 4 * 2, read_status))) {
        cli_mark_scan_incomplete(ctx, "RIFF chunk header was truncated");
        return (*read_status == CL_EREAD) ? CL_EREAD : CL_EPARSE;
    }
    cur_offset += 4 * 2;

    buffer = (const char *)buf;
    memcpy(&cache_buf, buffer + sizeof(cache_buf),
           sizeof(cache_buf));
    chunk_size = riff_endian_convert_32(cache_buf, big_endian);

    next_offset = (uint64_t)cur_offset + chunk_size;
    if (next_offset < (uint64_t)cur_offset || next_offset > limit || next_offset > map->len) {
        cli_mark_scan_incomplete(ctx, "RIFF chunk data was truncated");
        return CL_EPARSE;
    }
    if (chunk_size & 1) {
        if (next_offset == UINT64_MAX) {
            cli_mark_scan_incomplete(ctx, "RIFF chunk padding coordinate overflowed");
            return CL_EPARSE;
        }
        next_offset++;
        if (next_offset > limit || next_offset > map->len) {
            cli_mark_scan_incomplete(ctx, "RIFF chunk padding was truncated");
            return CL_EPARSE;
        }
    }
    if (next_offset > (uint64_t)INT64_MAX) {
        cli_mark_scan_incomplete(ctx, "RIFF chunk coordinate exceeded the supported range");
        return CL_EPARSE;
    }
    *offset = (off_t)next_offset;

    if (!memcmp(buf, "anih", 4) && chunk_size != 36)
        return 2;

    if (memcmp(buf, "RIFF", 4) == 0) {
        return 0;
    } else if (memcmp(buf, "RIFX", 4) == 0) {
        return 0;
    }

    if ((memcmp(buf, "LIST", 4) == 0) ||
        (memcmp(buf, "PROP", 4) == 0) ||
        (memcmp(buf, "FORM", 4) == 0) ||
        (memcmp(buf, "CAT ", 4) == 0)) {
        if (chunk_size < 4 || !riff_need_off(ctx, cur_offset, 4, read_status)) {
            cli_dbgmsg("riff_read_chunk: read list type failed\n");
            cli_mark_scan_incomplete(ctx, "RIFF list type was truncated");
            return (*read_status == CL_EREAD) ? CL_EREAD : CL_EPARSE;
        }
        list_end = (uint64_t)cur_offset + chunk_size;
        *offset = cur_offset + 4;
        while ((uint64_t)*offset < list_end) {
            int child_ret = riff_read_chunk(ctx, offset, big_endian, rec_level + 1, list_end, read_status);

            if (child_ret != 1)
                return child_ret;
        }
        if ((uint64_t)*offset != list_end) {
            cli_mark_scan_incomplete(ctx, "RIFF list contents did not end at the declared boundary");
            return CL_EPARSE;
        }
        *offset = (off_t)next_offset;
        return 1;
    }

    /* FIXME: WTF!?
        if (lseek(fd, offset, SEEK_SET) != offset) {
                return 2;
        }
        */
    return 1;
}

int cli_check_riff_exploit(cli_ctx *ctx)
{
    cl_error_t time_status;
    const uint8_t *buf;
    int big_endian, retval;
    cl_error_t read_status = CL_SUCCESS;
    off_t offset;
    fmap_t *map;
    uint32_t riff_size_raw;
    uint64_t riff_end;

    cli_dbgmsg("in cli_check_riff_exploit()\n");

    if (ctx == NULL)
        return CL_ENULLARG;
    if (ctx->fmap == NULL) {
        cli_mark_scan_incomplete(ctx, "RIFF input map is unavailable");
        return CL_EPARSE;
    }
    map = ctx->fmap;

    time_status = riff_checktimelimit(ctx);
    if (time_status != CL_SUCCESS)
        return time_status;

    /* A map shorter than the fixed RIFF/ACON probe is not a candidate. Once
     * the complete probe range exists, a failed fmap read is an operational
     * failure and must not be reduced to a clean non-RIFF result. */
    if (map->len < 4 * 3)
        return 0;
    if (!(buf = riff_need_off(ctx, 0, 4 * 3, &read_status))) {
        cli_mark_scan_incomplete(ctx, "RIFF header could not be read completely");
        return (read_status == CL_EREAD) ? CL_EREAD : CL_EPARSE;
    }

    if (memcmp(buf, "RIFF", 4) == 0) {
        big_endian = FALSE;
    } else if (memcmp(buf, "RIFX", 4) == 0) {
        big_endian = TRUE;
    } else {
        /* Not a RIFF file */
        return 0;
    }

    if (memcmp(buf + (2U * sizeof(uint32_t)), "ACON", 4) != 0) {
        /* Only scan MS animated icon files */
        /* There is a *lot* of broken software out there that produces bad RIFF files */
        return 0;
    }

    memcpy(&riff_size_raw, buf + sizeof(uint32_t), sizeof(riff_size_raw));
    /* Promote before adding the fixed RIFF header size.  The format field is
     * 32-bit, but a 64-bit fmap can represent the resulting end coordinate
     * at the 4-GiB boundary without wrapping it back to zero. */
    riff_end = (uint64_t)8U + riff_endian_convert_32(riff_size_raw, big_endian);
    if (riff_end < 12U || riff_end > map->len) {
        cli_mark_scan_incomplete(ctx, "RIFF container range was truncated");
        return CL_EPARSE;
    }

    offset = 4 * 3;
    if ((uint64_t)offset < riff_end) {
        do {
            retval = riff_read_chunk(ctx, &offset, big_endian, 1, riff_end, &read_status);
        } while (retval == 1 && (uint64_t)offset < riff_end);

        if (retval == 1 && (uint64_t)offset == riff_end)
            retval = 0;
    } else {
        retval = 0;
    }

    return retval;
}

static inline int swizz_j48(const uint16_t n[])
{
    cli_dbgmsg("swizz_j48: %u, %u, %u\n", n[0], n[1], n[2]);
    /* rules based on J48 tree */
    if (n[0] <= 961 || !n[1])
        return 0;
    if (n[0] <= 1006)
        return (n[2] > 0 && n[2] <= 6);
    else
        return n[1] <= 10 && n[2];
}

void cli_detect_swizz_str(const unsigned char *str, uint32_t len, struct swizz_stats *stats, int blob)
{
    unsigned char stri[4096];
    size_t i, j = 0;
    int bad       = 0;
    int lastalnum = 0;
    uint8_t ngrams[17576];
    uint16_t all = 0;
    uint16_t ngram_cnts[3];
    uint16_t words = 0;
    int ret;

    stats->entries++;
    for (i = 0; (i < (size_t)len - 1) && (j < sizeof(stri) - 2); i += 2) {
        unsigned char c = str[i];
        if (str[i + 1] || !c) {
            bad++;
            continue;
        }
        if (!isalnum(c)) {
            if (!lastalnum)
                continue;
            lastalnum = 0;
            c         = ' ';
        } else {
            lastalnum = 1;
            if (isdigit(c))
                continue;
        }
        stri[j++] = tolower(c);
    }
    stri[j++] = '\0';
    if ((!blob && (bad >= 8)) || j < 4)
        return;
    memset(ngrams, 0, sizeof(ngrams));
    memset(ngram_cnts, 0, sizeof(ngram_cnts));
    for (i = 0; i < j - 2; i++) {
        if (stri[i] != ' ' && stri[i + 1] != ' ' && stri[i + 2] != ' ') {
            uint16_t idx = (stri[i] - 'a') * 676 + (stri[i + 1] - 'a') * 26 + (stri[i + 2] - 'a');
            if (idx < sizeof(ngrams)) {
                ngrams[idx]++;
                stats->gngrams[idx]++;
            }
        } else if (stri[i] == ' ')
            words++;
    }
    for (i = 0; i < sizeof(ngrams); i++) {
        uint8_t v = ngrams[i];
        if (v > 3) v = 3;
        if (v) {
            ngram_cnts[v - 1]++;
            all++;
        }
    }
    if (!all)
        return;
    cli_dbgmsg("cli_detect_swizz_str: %u, %u, %u\n", ngram_cnts[0], ngram_cnts[1], ngram_cnts[2]);
    /* normalize */
    for (i = 0; i < sizeof(ngram_cnts) / sizeof(ngram_cnts[0]); i++) {
        uint32_t v    = ngram_cnts[i];
        ngram_cnts[i] = (v << 10) / all;
    }
    ret = swizz_j48(ngram_cnts) ? CL_VIRUS : CL_CLEAN;
    if (words < 3) ret = CL_CLEAN;
    cli_dbgmsg("cli_detect_swizz_str: %s, %u words\n", ret == CL_VIRUS ? "suspicious" : "ok", words);
    if (ret == CL_VIRUS) {
        stats->suspicious += j;
        cli_dbgmsg("cli_detect_swizz_str: %s\n", stri);
    }
    stats->total += j;
}

static inline int swizz_j48_global(const uint32_t gn[])
{
    if (gn[0] <= 24185) {
        return gn[0] > 22980 && gn[8] > 0 && gn[8] <= 97;
    }
    if (!gn[8]) {
        if (gn[4] <= 311) {
            if (!gn[4]) {
                return gn[1] > 0 &&
                       ((gn[0] <= 26579 && gn[3] > 0) ||
                        (gn[0] > 28672 && gn[0] <= 30506));
            }
            if (gn[5] <= 616) {
                if (gn[6] <= 104) {
                    return gn[9] <= 167;
                }
                return gn[6] <= 286;
            }
        }
        return 0;
    }
    return 1;
}

int cli_detect_swizz(struct swizz_stats *stats)
{
    uint32_t gn[10];
    uint32_t all = 0;
    size_t i;
    int global_swizz = CL_CLEAN;

    cli_dbgmsg("cli_detect_swizz: %lu/%lu, version:%d, manifest: %d \n",
               (unsigned long)stats->suspicious, (unsigned long)stats->total,
               stats->has_version, stats->has_manifest);
    memset(gn, 0, sizeof(gn));
    for (i = 0; i < 17576; i++) {
        uint8_t v = stats->gngrams[i];
        if (v > 10) v = 10;
        if (v) {
            gn[v - 1]++;
            all++;
        }
    }
    if (all) {
        /* normalize */
        cli_dbgmsg("cli_detect_swizz: gn: ");
        for (i = 0; i < sizeof(gn) / sizeof(gn[0]); i++) {
            uint32_t v = gn[i];
            gn[i]      = (v << 15) / all;
            if (cli_debug_flag)
                cli_eprintf("%lu, ", (unsigned long)gn[i]);
        }
        global_swizz = swizz_j48_global(gn) ? CL_VIRUS : CL_CLEAN;
        if (cli_debug_flag) {
            cli_eprintf("\n");
            cli_dbgmsg("cli_detect_swizz: global: %s\n", global_swizz ? "suspicious" : "clean");
        }
    }

    if (stats->errors > stats->entries || stats->errors >= SWIZZ_MAXERRORS) {
        cli_dbgmsg("cli_detect_swizz: resources broken, ignoring\n");
        return CL_CLEAN;
    }
    if (stats->total <= 337)
        return CL_CLEAN;
    if (stats->suspicious << 10 > 40 * stats->total)
        return CL_VIRUS;
    if (!stats->suspicious)
        return CL_CLEAN;
    return global_swizz;
}
