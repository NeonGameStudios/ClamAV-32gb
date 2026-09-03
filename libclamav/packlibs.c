/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Alberto Wu, Michal 'GiM' Spadlinski
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

#include "clamav.h"
#include "others.h"
#include "execs.h"
#include "pe.h"
#include "packlibs.h"

static int doubledl(const char **scur, uint8_t *mydlptr, const char *buffer, uint32_t buffersize)
{
    unsigned char mydl  = *mydlptr;
    unsigned char olddl = mydl;

    mydl *= 2;
    if (!(olddl & 0x7f)) {
        if (*scur < buffer || *scur >= buffer + buffersize - 1)
            return -1;
        olddl = **scur;
        mydl  = olddl * 2 + 1;
        *scur = *scur + 1;
    }
    *mydlptr = mydl;
    return (olddl >> 7) & 1;
}

int cli_pack_length_step(uint32_t value, uint32_t bit, uint32_t *next)
{
    if (next == NULL || bit > 1 || value > (UINT32_MAX - bit) / 2)
        return -1;

    *next = value * 2 + bit;
    return 0;
}

static int pack_backbytes_step(uint32_t low, uint32_t length, uint32_t *backbytes)
{
    if (backbytes == NULL || length == 0 || length - 1 > (UINT32_MAX - low) / 0x100U)
        return -1;

    *backbytes = low + (length - 1) * 0x100U;
    return 0;
}

static int pack_backref_window(const char *dest, size_t dsize, const char *cdst,
                               uint32_t backbytes, uint32_t backsize)
{
    size_t output_offset;

    if (dest == NULL || cdst == NULL || cdst < dest)
        return -1;

    output_offset = (size_t)(cdst - dest);
    if (output_offset > dsize || (size_t)backbytes > output_offset)
        return -1;

    if ((size_t)backsize > dsize - output_offset ||
        (size_t)backsize > dsize - (output_offset - (size_t)backbytes))
        return -1;

    return 0;
}

static int fsg_checktimelimit(cli_ctx *ctx, uint32_t *ticks)
{
    if (ctx == NULL)
        return 0;

    (*ticks)++;
    if (*ticks < 4096)
        return 0;

    *ticks = 0;
    if (cli_checktimelimit(ctx) != CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, "FSG decompression reached the configured time limit");
        return 1;
    }

    return 0;
}

int cli_unfsg_ctx(const char *source, char *dest, int ssize, int dsize, const char **endsrc, char **enddst, cli_ctx *ctx)
{
    uint8_t mydl = 0x80;
    uint32_t backbytes, backsize, oldback = 0;
    uint32_t ticks = 0;
    const char *csrc = source;
    char *cdst       = dest;
    int oob, lostbit = 1;

    if (source == NULL || dest == NULL || ssize <= 0 || dsize <= 0) return -1;
    if (ctx != NULL && cli_checktimelimit(ctx) != CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, "FSG decompression reached the configured time limit");
        return -1;
    }
    *cdst++ = *csrc++;

    while (1) {
        if (fsg_checktimelimit(ctx, &ticks))
            return -1;
        if ((oob = doubledl(&csrc, &mydl, source, ssize))) {
            if (oob == -1)
                return -1;
            /* 164 */
            backsize = 0;
            if ((oob = doubledl(&csrc, &mydl, source, ssize))) {
                if (oob == -1)
                    return -1;
                /* 16a */
                backbytes = 0;
                if ((oob = doubledl(&csrc, &mydl, source, ssize))) {
                    if (oob == -1)
                        return -1;
                    /* 170 */
                    lostbit = 1;
                    backsize++;
                    backbytes = 0x10;
                    while (backbytes < 0x100) {
                        if (fsg_checktimelimit(ctx, &ticks))
                            return -1;
                        if ((oob = doubledl(&csrc, &mydl, source, ssize)) == -1)
                            return -1;
                        backbytes = backbytes * 2 + oob;
                    }
                    backbytes &= 0xff;
                    if (!backbytes) {
                        if (cdst >= dest + dsize)
                            return -1;
                        *cdst++ = 0x00;
                        continue;
                    }
                } else {
                    /* 18f */
                    if (csrc >= source + ssize)
                        return -1;
                    backbytes = *(unsigned char *)csrc;
                    if (cli_pack_length_step(backsize, backbytes & 1, &backsize) == -1)
                        return -1;
                    backbytes = (backbytes & 0xff) >> 1;
                    csrc++;
                    if (!backbytes)
                        break;
                    if (backsize > UINT32_MAX - 2)
                        return -1;
                    backsize += 2;
                    oldback = backbytes;
                    lostbit = 0;
                }
            } else {
                /* 180 */
                backsize = 1;
                do {
                    if (fsg_checktimelimit(ctx, &ticks))
                        return -1;
                    if ((oob = doubledl(&csrc, &mydl, source, ssize)) == -1)
                        return -1;
                    if (cli_pack_length_step(backsize, (uint32_t)oob, &backsize) == -1)
                        return -1;
                    if ((oob = doubledl(&csrc, &mydl, source, ssize)) == -1)
                        return -1;
                } while (oob);

                backsize = backsize - 1 - lostbit;
                if (!backsize) {
                    /* 18a */
                    backsize = 1;
                    do {
                        if (fsg_checktimelimit(ctx, &ticks))
                            return -1;
                        if ((oob = doubledl(&csrc, &mydl, source, ssize)) == -1)
                            return -1;
                        if (cli_pack_length_step(backsize, (uint32_t)oob, &backsize) == -1)
                            return -1;
                        if ((oob = doubledl(&csrc, &mydl, source, ssize)) == -1)
                            return -1;
                    } while (oob);

                    backbytes = oldback;
                } else {
                    /* 198 */
                    if (csrc >= source + ssize)
                        return -1;
                    backbytes = *(unsigned char *)csrc;
                    if (pack_backbytes_step(backbytes, backsize, &backbytes) == -1)
                        return -1;
                    backsize = 1;
                    csrc++;
                    do {
                        if (fsg_checktimelimit(ctx, &ticks))
                            return -1;
                        if ((oob = doubledl(&csrc, &mydl, source, ssize)) == -1)
                            return -1;
                        if (cli_pack_length_step(backsize, (uint32_t)oob, &backsize) == -1)
                            return -1;
                        if ((oob = doubledl(&csrc, &mydl, source, ssize)) == -1)
                            return -1;
                    } while (oob);

                    if (backbytes >= 0x7d00) {
                        if (backsize == UINT32_MAX)
                            return -1;
                        backsize++;
                    }
                    if (backbytes >= 0x500) {
                        if (backsize == UINT32_MAX)
                            return -1;
                        backsize++;
                    }
                    if (backbytes <= 0x7f) {
                        if (backsize > UINT32_MAX - 2)
                            return -1;
                        backsize += 2;
                    }

                    oldback = backbytes;
                }
                lostbit = 0;
            }
            if (pack_backref_window(dest, (size_t)dsize, cdst, backbytes, backsize) == -1)
                return -1;
            while (backsize--) {
                if (fsg_checktimelimit(ctx, &ticks))
                    return -1;
                *cdst = *(cdst - backbytes);
                cdst++;
            }

        } else {
            /* 15d */
            if (cdst < dest || cdst >= dest + dsize || csrc < source || csrc >= source + ssize)
                return -1;
            *cdst++ = *csrc++;
            lostbit = 1;
        }
    }

    if (endsrc) *endsrc = csrc;
    if (enddst) *enddst = cdst;
    return 0;
}

int cli_unfsg(const char *source, char *dest, int ssize, int dsize, const char **endsrc, char **enddst)
{
    return cli_unfsg_ctx(source, dest, ssize, dsize, endsrc, enddst, NULL);
}

static int mew_checktimelimit(cli_ctx *ctx, uint32_t *ticks)
{
    if (ctx == NULL)
        return 0;

    (*ticks)++;
    if (*ticks < 4096)
        return 0;

    *ticks = 0;
    if (cli_checktimelimit(ctx) != CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, "MEW decompression reached the configured time limit");
        return 1;
    }

    return 0;
}

int unmew_ctx(const char *source, char *dest, int ssize, int dsize, const char **endsrc, char **enddst, cli_ctx *ctx)
{
    uint8_t mydl = 0x80;
    uint32_t myeax_backbytes, myecx_backsize, oldback = 0;
    uint32_t ticks = 0;
    const char *csrc = source;
    char *cdst       = dest;
    int oob, lostbit = 1;

    if (source == NULL || dest == NULL || endsrc == NULL || enddst == NULL || ssize <= 0 || dsize <= 0)
        return -1;
    if (ctx != NULL && cli_checktimelimit(ctx) != CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, "MEW decompression reached the configured time limit");
        return -1;
    }
    *cdst++ = *csrc++;

    while (1) {
        if (mew_checktimelimit(ctx, &ticks))
            return -1;
        if ((oob = doubledl(&csrc, &mydl, source, ssize))) {
            if (oob == -1)
                return -1;
            /* 164 */
            myecx_backsize = 0;
            if ((oob = doubledl(&csrc, &mydl, source, ssize))) {
                if (oob == -1)
                    return -1;
                /* 16a */
                myeax_backbytes = 0;
                if ((oob = doubledl(&csrc, &mydl, source, ssize))) {
                    if (oob == -1)
                        return -1;
                    /* 170 */
                    lostbit = 1;
                    myecx_backsize++;
                    myeax_backbytes = 0x10;
                    while (myeax_backbytes < 0x100) {
                        if (mew_checktimelimit(ctx, &ticks))
                            return -1;
                        if ((oob = doubledl(&csrc, &mydl, source, ssize)) == -1)
                            return -1;
                        myeax_backbytes = myeax_backbytes * 2 + oob;
                    }
                    myeax_backbytes &= 0xff;
                    if (!myeax_backbytes) {
                        if (cdst >= dest + dsize)
                            return -1;
                        *cdst++ = 0x00;
                        /*cli_dbgmsg("X%02x  ", *(cdst-1)&0xff);*/
                        continue;
                    }
                } else {
                    /* 18f */
                    if (csrc >= source + ssize)
                        return -1;
                    myeax_backbytes = *(unsigned char *)csrc;
                    if (cli_pack_length_step(myecx_backsize, myeax_backbytes & 1, &myecx_backsize) == -1)
                        return -1;
                    myeax_backbytes = (myeax_backbytes & 0xff) >> 1;
                    csrc++;
                    if (!myeax_backbytes) {
                        /* cli_dbgmsg("\nBREAK \n"); */
                        break;
                    }
                    if (myecx_backsize > UINT32_MAX - 2)
                        return -1;
                    myecx_backsize += 2;
                    oldback = myeax_backbytes;
                    lostbit = 0;
                }
            } else {
                /* 180 */
                myecx_backsize = 1;
                do {
                    if (mew_checktimelimit(ctx, &ticks))
                        return -1;
                    if ((oob = doubledl(&csrc, &mydl, source, ssize)) == -1)
                        return -1;
                    if (cli_pack_length_step(myecx_backsize, (uint32_t)oob, &myecx_backsize) == -1)
                        return -1;
                    if ((oob = doubledl(&csrc, &mydl, source, ssize)) == -1)
                        return -1;
                } while (oob);

                myecx_backsize = myecx_backsize - 1 - lostbit;
                if (!myecx_backsize) {
                    /* 18a */
                    myecx_backsize = 1;
                    do {
                        if (mew_checktimelimit(ctx, &ticks))
                            return -1;
                        if ((oob = doubledl(&csrc, &mydl, source, ssize)) == -1)
                            return -1;
                        if (cli_pack_length_step(myecx_backsize, (uint32_t)oob, &myecx_backsize) == -1)
                            return -1;
                        if ((oob = doubledl(&csrc, &mydl, source, ssize)) == -1)
                            return -1;
                    } while (oob);

                    myeax_backbytes = oldback;
                } else {
                    /* 198 */
                    if (csrc >= source + ssize)
                        return -1;
                    myeax_backbytes = *(unsigned char *)csrc;
                    if (pack_backbytes_step(myeax_backbytes, myecx_backsize, &myeax_backbytes) == -1)
                        return -1;
                    myecx_backsize = 1;
                    csrc++;
                    do {
                        if (mew_checktimelimit(ctx, &ticks))
                            return -1;
                        if ((oob = doubledl(&csrc, &mydl, source, ssize)) == -1)
                            return -1;
                        if (cli_pack_length_step(myecx_backsize, (uint32_t)oob, &myecx_backsize) == -1)
                            return -1;
                        if ((oob = doubledl(&csrc, &mydl, source, ssize)) == -1)
                            return -1;
                    } while (oob);

                    if (myeax_backbytes >= 0x7d00) {
                        if (myecx_backsize == UINT32_MAX)
                            return -1;
                        myecx_backsize++;
                    }
                    if (myeax_backbytes >= 0x500) {
                        if (myecx_backsize == UINT32_MAX)
                            return -1;
                        myecx_backsize++;
                    }
                    if (myeax_backbytes <= 0x7f) {
                        if (myecx_backsize > UINT32_MAX - 2)
                            return -1;
                        myecx_backsize += 2;
                    }

                    oldback = myeax_backbytes;
                }
                lostbit = 0;
            }
            if (pack_backref_window(dest, (size_t)dsize, cdst, myeax_backbytes, myecx_backsize) == -1) {
                cli_dbgmsg("MEW: back-reference window is outside the reconstructed output\n");
                return -1;
            }
            while (myecx_backsize--) {
                if (mew_checktimelimit(ctx, &ticks))
                    return -1;
                *cdst = *(cdst - myeax_backbytes);
                cdst++;
            }

        } else {
            /* 15d */
            if (cdst < dest || cdst >= dest + dsize || csrc < source || csrc >= source + ssize) {
                cli_dbgmsg("MEW: retf %p %p+%08x=%p, %p %p+%08x=%p\n",
                           cdst, dest, dsize, dest + dsize, csrc, source, ssize, source + ssize);
                return -1;
            }
            *cdst++ = *csrc++;
            /* cli_dbgmsg("Z%02x  ", *(cdst-1)&0xff); */
            lostbit = 1;
        }
    }

    *endsrc = csrc;
    *enddst = cdst;
    return 0;
}

int unmew(const char *source, char *dest, int ssize, int dsize, const char **endsrc, char **enddst)
{
    return unmew_ctx(source, dest, ssize, dsize, endsrc, enddst, NULL);
}
