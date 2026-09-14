/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Alberto Wu
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

/*
** upxdec.c
**
** 05/05/2k4 - 1st attempt
** 08/05/2k4 - Now works as a charm :D
** 09/05/2k4 - Moved code outta main(), got rid of globals for thread safety, added bound checking, minor cleaning
** 04/06/2k4 - Now we handle 2B, 2D and 2E :D
** 28/08/2k4 - PE rebuild for nested packers
** 12/12/2k4 - Improved PE rebuild code and added some debug info on failure
** 23/03/2k7 - New approach for rebuilding:
               o Get imports via magic
               o Get imports via leascan
               o if (!pe) pe=scan4pe();
               o if (!pe) forgepe();
*/

/*
** This code unpacks a dumped UPX1 section to a file.
** It was written reversing the loader found on some Win32 UPX compressed trojans; while porting
** it to C i've kinda followed the asm flow so it will probably be a bit hard to read.
** This code DOES NOT revert the uncompressed section to its original state as no E8/E9 fixup and
** of cause no IAT rebuild are performed.
**
** The Win32 asm unpacker is really a little programming jewel, pretty damn rare in these days of
** bloatness. My gratitude to whoever wrote it.
*/

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "clamav.h"
#include "others.h"
#include "upx.h"
#include "str.h"
#include "lzma_iface.h"

#define PEALIGN(o, a) (((a)) ? (((o) / (a)) * (a)) : (o))

int cli_upx_align_up_u32(uint32_t value, uint32_t alignment, uint32_t *aligned)
{
    uint32_t remainder;

    if (aligned == NULL)
        return -1;
    if (alignment == 0) {
        *aligned = value;
        return 0;
    }

    remainder = value % alignment;
    if (remainder && value > UINT32_MAX - (alignment - remainder))
        return -1;

    *aligned = value + (alignment - remainder) * (remainder != 0);
    return 0;
}

int cli_upx_relative_window_offset(uint32_t section_rva, uint32_t target_rva,
                                   size_t available, int64_t adjustment,
                                   size_t needed, size_t *offset)
{
    uint64_t relative;

    if (offset == NULL || target_rva < section_rva)
        return -1;

    relative = (uint64_t)target_rva - (uint64_t)section_rva;
    if (relative > (uint64_t)available)
        return -1;

    if (adjustment < 0) {
        uint64_t magnitude = (uint64_t)(-(adjustment + 1)) + 1U;
        if (magnitude > relative)
            return -1;
        relative -= magnitude;
    } else {
        if ((uint64_t)adjustment > (uint64_t)available - relative)
            return -1;
        relative += (uint64_t)adjustment;
    }

    if (relative > (uint64_t)available || needed > available - (size_t)relative)
        return -1;

    *offset = (size_t)relative;
    return 0;
}

/* The LZMA wrapper stores a virtual address for its optional 0x15-byte
 * wrapper prefix. Convert it to a section-relative coordinate before
 * deciding whether the prefix is present; unsigned VA - image-base - RVA
 * arithmetic can otherwise wrap into the one accepted skew value. */
int cli_upx_lzma_skew_offset(uint32_t image_base, uint32_t section_rva,
                             uint32_t target_va, size_t available,
                             uint32_t *skew)
{
    size_t relative;

    if (skew == NULL)
        return -1;

    *skew = 0;
    if (target_va < image_base ||
        cli_upx_relative_window_offset(section_rva, target_va - image_base,
                                       available, 0, 0, &relative) < 0)
        return 0;

    if (relative == 0x15)
        *skew = 0x15;
    return 0;
}

/* UPX is a legacy, bounded-buffer decoder. Keep its context-free public
 * implementation, but checkpoint the shared scan deadline often enough that
 * hostile bitstreams cannot consume the entire scan budget in a tight loop. */
static int upx_checktimelimit(struct cli_ctx_tag *ctx, uint32_t *ticks)
{
    if (ctx == NULL)
        return 0;

    (*ticks)++;
    if (*ticks < 4096)
        return 0;

    *ticks = 0;
    if (cli_checktimelimit(ctx) != CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, "PE UPX decompression reached the configured time limit");
        return 1;
    }

    return 0;
}

#define HEADERS "\
\x4D\x5A\x90\x00\x02\x00\x00\x00\x04\x00\x0F\x00\xFF\xFF\x00\x00\
\xB0\x00\x00\x00\x00\x00\x00\x00\x40\x00\x1A\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xD0\x00\x00\x00\
\x0E\x1F\xB4\x09\xBA\x0D\x00\xCD\x21\xB4\x4C\xCD\x21\x54\x68\x69\
\x73\x20\x66\x69\x6C\x65\x20\x77\x61\x73\x20\x63\x72\x65\x61\x74\
\x65\x64\x20\x62\x79\x20\x43\x6C\x61\x6D\x41\x56\x20\x66\x6F\x72\
\x20\x69\x6E\x74\x65\x72\x6E\x61\x6C\x20\x75\x73\x65\x20\x61\x6E\
\x64\x20\x73\x68\x6F\x75\x6C\x64\x20\x6E\x6F\x74\x20\x62\x65\x20\
\x72\x75\x6E\x2E\x0D\x0A\x43\x6C\x61\x6D\x41\x56\x20\x2D\x20\x41\
\x20\x47\x50\x4C\x20\x76\x69\x72\x75\x73\x20\x73\x63\x61\x6E\x6E\
\x65\x72\x20\x2D\x20\x68\x74\x74\x70\x3A\x2F\x2F\x77\x77\x77\x2E\
\x63\x6C\x61\x6D\x61\x76\x2E\x6E\x65\x74\x0D\x0A\x24\x00\x00\x00\
"
#define FAKEPE "\
\x50\x45\x00\x00\x4C\x01\x01\x00\x43\x4C\x41\x4D\x00\x00\x00\x00\
\x00\x00\x00\x00\xE0\x00\x83\x8F\x0B\x01\x00\x00\x00\x10\x00\x00\
\x00\x10\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x10\x00\x00\
\x00\x10\x00\x00\x00\x00\x40\x00\x00\x10\x00\x00\x00\x02\x00\x00\
\x01\x00\x00\x00\x00\x00\x00\x00\x03\x00\x0A\x00\x00\x00\x00\x00\
\xFF\xFF\xFF\xFF\x00\x02\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\
\x00\x00\x10\x00\x00\x10\x00\x00\x00\x00\x10\x00\x00\x10\x00\x00\
\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x2e\x63\x6c\x61\x6d\x30\x31\x00\
\xFF\xFF\xFF\xFF\x00\x10\x00\x00\xFF\xFF\xFF\xFF\x00\x02\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\
"

static char *checkpe(char *dst, uint32_t dsize, size_t pehdr_offset,
                     uint32_t *valign, unsigned int *sectcnt)
{
    char *pehdr;
    char *sections;
    size_t sections_offset;

    if (dst == NULL || valign == NULL || sectcnt == NULL || pehdr_offset > dsize ||
        dsize - pehdr_offset < 0xf8)
        return NULL;

    pehdr = dst + pehdr_offset;

    if (cli_readint32(pehdr) != 0x4550) return NULL;

    if (!(*valign = cli_readint32(pehdr + 0x38))) return NULL;

    sections = pehdr + 0xf8;
    sections_offset = pehdr_offset + 0xf8;
    if (!(*sectcnt = (unsigned char)pehdr[6] + (unsigned char)pehdr[7] * 256)) return NULL;

    if (*sectcnt > (dsize - sections_offset) / 0x28) return NULL;

    return sections;
}

/* PE from UPX */

static int pefromupx(const char *src, uint32_t ssize, char *dst, uint32_t *dsize, uint32_t ep, uint32_t upx0, uint32_t upx1, uint32_t *magic, uint32_t dend, struct cli_ctx_tag *ctx)
{
    char *sections = NULL, *pehdr = NULL, *newbuf;
    unsigned int sectcnt = 0, upd = 1;
    uint32_t realstuffsz = 0, valign = 0;
    uint32_t foffset = 0xd0 + 0xf8;
    uint32_t ticks = 0;
    uint32_t vsize, urva;
    uint32_t offset1, offset2, offset3;
    size_t ep_offset, candidate_offset, pehdr_offset = SIZE_MAX;
    size_t output_capacity;

    if ((dst == NULL) || (src == NULL) || (dsize == NULL) || (magic == NULL))
        return -1;

    output_capacity = (size_t)*dsize;
    if (output_capacity > SIZE_MAX - 8192U)
        return -1;
    if (dend > *dsize)
        return -1;
    output_capacity += 8192U;

    if (upx_checktimelimit(ctx, &ticks))
        return -1;

    if (cli_upx_relative_window_offset(upx1, ep, ssize, 0, 0, &ep_offset) < 0)
        return -1;

    while (sectcnt < 4 && (valign = magic[sectcnt++])) {
        if (cli_upx_relative_window_offset(upx1, ep, ssize, (int64_t)valign - 2, 2,
                                           &candidate_offset) == 0 &&
            src[candidate_offset] == '\x8d' && /* lea edi, ...                  */
            src[candidate_offset + 1] == '\xbe') /* ... [esi + offset]          */
            break;
    }

    if (!valign && cli_upx_relative_window_offset(upx1, ep, ssize, 0x80, 8,
                                                  &candidate_offset) == 0) {
        const char *pt = &src[candidate_offset];
        cli_dbgmsg("UPX: bad magic - scanning for imports\n");

        while ((pt = cli_memstr(pt, ssize - (pt - src) - 8, "\x8d\xbe", 2))) {
            if (upx_checktimelimit(ctx, &ticks))
                return -1;
            if (pt[6] == '\x8b' && pt[7] == '\x07') { /* lea edi, [esi+imports] / mov eax, [edi] */
                uint64_t desired_offset = (uint64_t)(pt - src) + 2U;
                if (desired_offset >= ep_offset && desired_offset - ep_offset <= UINT32_MAX) {
                    valign = (uint32_t)(desired_offset - ep_offset);
                    break;
                }
            }
            pt++;
        }
    }

    if (valign && cli_upx_relative_window_offset(upx1, ep, ssize, valign, 4,
                                                 &candidate_offset) == 0) {
        realstuffsz = cli_readint32(src + candidate_offset);

        if (realstuffsz >= *dsize) {
            cli_dbgmsg("UPX: wrong realstuff size\n");
            /* fallback and eventually craft */
        } else {
            pehdr_offset = realstuffsz;
            while (CLI_ISCONTAINED_0_TO(*dsize, pehdr_offset, 8) &&
                   cli_readint32(dst + pehdr_offset)) {
                if (upx_checktimelimit(ctx, &ticks))
                    return -1;
                pehdr_offset += 8;
                while (CLI_ISCONTAINED_0_TO(*dsize, pehdr_offset, 1) &&
                       dst[pehdr_offset]) {
                    if (upx_checktimelimit(ctx, &ticks))
                        return -1;
                    pehdr_offset++;
                }
                if (pehdr_offset >= *dsize) {
                    pehdr_offset = SIZE_MAX;
                    break;
                }
                pehdr_offset++;
                while (CLI_ISCONTAINED_0_TO(*dsize, pehdr_offset, 1) &&
                       dst[pehdr_offset]) {
                    if (upx_checktimelimit(ctx, &ticks))
                        return -1;
                    pehdr_offset++;
                }
                if (pehdr_offset >= *dsize) {
                    pehdr_offset = SIZE_MAX;
                    break;
                }
                pehdr_offset++;
            }

            if (pehdr_offset != SIZE_MAX &&
                CLI_ISCONTAINED_0_TO(*dsize, pehdr_offset, 4)) {
                pehdr_offset += 4;
                sections = checkpe(dst, *dsize, pehdr_offset, &valign, &sectcnt);
                if (sections != NULL)
                    pehdr = dst + pehdr_offset;
            }
        }
    }

    if (!pehdr && dend > 0xf8 + 0x28) {
        cli_dbgmsg("UPX: no luck - scanning for PE\n");
        pehdr_offset = dend - 0xf8 - 0x28;
        while (pehdr_offset > 0) {
            if (upx_checktimelimit(ctx, &ticks))
                return -1;
            if ((sections = checkpe(dst, *dsize, pehdr_offset, &valign, &sectcnt))) {
                pehdr = dst + pehdr_offset;
                break;
            }
            pehdr_offset--;
        }
        if (!pehdr)
            pehdr_offset = SIZE_MAX;
        else
            realstuffsz = (uint32_t)pehdr_offset;
    }

    if (!pehdr) {
        uint32_t rebsz;

        cli_dbgmsg("UPX: no luck - brutally crafting a reasonable PE\n");
        if (cli_upx_align_up_u32(dend, 0x1000, &rebsz) < 0 ||
            rebsz > UINT32_MAX - 0x200U ||
            (size_t)rebsz + 0x200U > output_capacity) {
            cli_dbgmsg("UPX: crafted PE size is out of bounds\n");
            return -1;
        }
        if (!(newbuf = (char *)cli_max_calloc((size_t)rebsz + 0x200U, sizeof(char)))) {
            cli_dbgmsg("UPX: malloc failed - giving up rebuild\n");
            return -1;
        }
        memcpy(newbuf, HEADERS, 0xd0);
        memcpy(newbuf + 0xd0, FAKEPE, 0x120);
        memcpy(newbuf + 0x200, dst, dend);
        memcpy(dst, newbuf, (size_t)dend + 0x200U);
        free(newbuf);
        cli_writeint32(dst + 0xd0 + 0x50, rebsz + 0x1000);
        cli_writeint32(dst + 0xd0 + 0x100, rebsz);
        cli_writeint32(dst + 0xd0 + 0x108, rebsz);
        *dsize = rebsz + 0x200;
        cli_dbgmsg("UPX: PE structure added to uncompressed data\n");
        return 1;
    }

    if (!sections)
        sectcnt = 0;
    {
        size_t header_size = (size_t)foffset + (size_t)0x28U * sectcnt;
        if (header_size > UINT32_MAX ||
            cli_upx_align_up_u32((uint32_t)header_size, valign, &foffset) < 0)
            return -1;
    }

    for (upd = 0; upd < sectcnt; upd++) {
        if (upx_checktimelimit(ctx, &ticks))
            return -1;
        if (cli_upx_align_up_u32((uint32_t)cli_readint32(sections + 8), valign, &vsize) < 0)
            return -1;
        urva = PEALIGN((uint32_t)cli_readint32(sections + 12), valign);

        /* Within bounds ? */
        if (!CLI_ISCONTAINED(upx0, realstuffsz, urva, vsize)) {
            cli_dbgmsg("UPX: Sect %d out of bounds - giving up rebuild\n", upd);
            return -1;
        }

        cli_writeint32(sections + 8, vsize);
        cli_writeint32(sections + 12, urva);
        cli_writeint32(sections + 16, vsize);
        cli_writeint32(sections + 20, foffset);
        if (vsize > UINT32_MAX - foffset) {
            /* Integer overflow */
            return -1;
        }
        foffset += vsize;

        sections += 0x28;
    }

    cli_writeint32(pehdr + 8, 0x4d414c43);
    cli_writeint32(pehdr + 0x3c, valign);

    if ((size_t)foffset > output_capacity)
        return -1;
    if (!(newbuf = (char *)cli_max_calloc(foffset, sizeof(char)))) {
        cli_dbgmsg("UPX: malloc failed - giving up rebuild\n");
        return -1;
    }

    memcpy(newbuf, HEADERS, 0xd0);
    memcpy(newbuf + 0xd0, pehdr, 0xf8 + 0x28 * sectcnt);
    sections = pehdr + 0xf8;
    for (upd = 0; upd < sectcnt; upd++) {
        size_t source_offset;

        if (upx_checktimelimit(ctx, &ticks)) {
            free(newbuf);
            return -1;
        }
        offset1 = (uint32_t)cli_readint32(sections + 20);
        offset2 = (uint32_t)cli_readint32(sections + 16);
        if (offset1 > foffset || offset2 > foffset - offset1) {
            free(newbuf);
            return -1;
        }

        offset3 = (uint32_t)cli_readint32(sections + 12);
        if (offset3 < upx0 || offset3 - upx0 > *dsize) {
            free(newbuf);
            return -1;
        }
        source_offset = (size_t)(offset3 - upx0);
        if (offset2 > (size_t)*dsize - source_offset) {
            free(newbuf);
            return -1;
        }
        memcpy(newbuf + offset1, dst + source_offset, offset2);
        sections += 0x28;
    }

    /* CBA restoring the imports they'll look different from the originals anyway... */
    /* ...and yeap i miss the icon too :P */

    if ((size_t)foffset > output_capacity) {
        cli_dbgmsg("UPX: wrong raw size - giving up rebuild\n");
        free(newbuf);
        return -1;
    }
    memcpy(dst, newbuf, foffset);
    *dsize = foffset;
    free(newbuf);

    cli_dbgmsg("UPX: PE structure rebuilt from compressed file\n");
    return 1;
}

/* [doubleebx] */

static int upx_doubleebx(const char *src, uint32_t *myebx, uint32_t *scur, uint32_t ssize,
                         struct cli_ctx_tag *ctx, uint32_t *ticks)
{
    uint32_t oldebx = *myebx;

    if (upx_checktimelimit(ctx, ticks))
        return -1;

    *myebx *= 2;
    if (!(oldebx & 0x7fffffff)) {
        if (!CLI_ISCONTAINED_0_TO(ssize, *scur, 4))
            return -1;
        oldebx = cli_readint32(src + *scur);
        *myebx = oldebx * 2 + 1;
        *scur += 4;
    }
    return (oldebx >> 31);
}

#define doubleebx(src, myebx, scur, ssize) upx_doubleebx(src, myebx, scur, ssize, ctx, &ticks)

/* [inflate] */

int upx_inflate2b(const char *src, uint32_t ssize, char *dst, uint32_t *dsize, uint32_t upx0, uint32_t upx1, uint32_t ep, struct cli_ctx_tag *ctx)
{
    int32_t backbytes, unp_offset = -1;
    uint32_t backsize, back_offset, myebx = 0, scur = 0, dcur = 0, i, magic[] = {0x108, 0x110, 0xd5, 0};
    uint32_t ticks = 0;
    int oob;

    while (1) {
        while ((oob = doubleebx(src, &myebx, &scur, ssize)) == 1) {
            if (scur >= ssize || dcur >= *dsize)
                return -1;
            dst[dcur++] = src[scur++];
        }

        if (oob == -1)
            return -1;

        backbytes = 1;

        while (1) {
            if ((oob = doubleebx(src, &myebx, &scur, ssize)) == -1)
                return -1;
            if (((int64_t)backbytes + oob) > INT32_MAX / 2)
                return -1;
            backbytes = backbytes * 2 + oob;
            if ((oob = doubleebx(src, &myebx, &scur, ssize)) == -1)
                return -1;
            if (oob)
                break;
        }

        backbytes -= 3;

        if (backbytes >= 0) {

            if (scur >= ssize)
                return -1;
            if (backbytes & 0xff000000)
                return -1;
            backbytes <<= 8;
            backbytes += (unsigned char)(src[scur++]);
            backbytes ^= 0xffffffff;

            if (!backbytes)
                break;
            unp_offset = backbytes;
        }

        if ((backsize = (uint32_t)doubleebx(src, &myebx, &scur, ssize)) == 0xffffffff)
            return -1;
        if ((oob = doubleebx(src, &myebx, &scur, ssize)) == -1)
            return -1;
        if (backsize + oob > UINT32_MAX / 2)
            return -1;
        backsize = backsize * 2 + oob;
        if (!backsize) {
            backsize++;
            do {
                if ((oob = doubleebx(src, &myebx, &scur, ssize)) == -1)
                    return -1;
                if (backsize + oob > UINT32_MAX / 2)
                    return -1;
                backsize = backsize * 2 + oob;
            } while ((oob = doubleebx(src, &myebx, &scur, ssize)) == 0);
            if (oob == -1)
                return -1;
            if (backsize > UINT32_MAX - 2)
                return -1;
            backsize += 2;
        }

        if ((uint32_t)unp_offset < 0xfffff300)
            backsize++;

        backsize++;

        if (unp_offset >= 0 || (uint32_t)(-(int64_t)unp_offset) > dcur)
            return -1;
        back_offset = dcur - (uint32_t)(-(int64_t)unp_offset);
        if (!CLI_ISCONTAINED_0_TO(*dsize, back_offset, backsize) ||
            !CLI_ISCONTAINED_0_TO(*dsize, dcur, backsize))
            return -1;
        for (i = 0; i < backsize; i++) {
            if ((i & 0xffffU) == 0 && upx_checktimelimit(ctx, &ticks))
                return -1;
            dst[dcur + i] = dst[back_offset + i];
        }
        dcur += backsize;
    }

    return pefromupx(src, ssize, dst, dsize, ep, upx0, upx1, magic, dcur, ctx);
}

int upx_inflate2d(const char *src, uint32_t ssize, char *dst, uint32_t *dsize, uint32_t upx0, uint32_t upx1, uint32_t ep, struct cli_ctx_tag *ctx)
{
    int32_t backbytes, unp_offset = -1;
    uint32_t backsize, back_offset, myebx = 0, scur = 0, dcur = 0, i, magic[] = {0x11c, 0x124, 0};
    uint32_t ticks = 0;
    int oob;

    while (1) {
        while ((oob = doubleebx(src, &myebx, &scur, ssize)) == 1) {
            if (scur >= ssize || dcur >= *dsize)
                return -1;
            dst[dcur++] = src[scur++];
        }

        if (oob == -1)
            return -1;

        backbytes = 1;

        while (1) {
            if ((oob = doubleebx(src, &myebx, &scur, ssize)) == -1)
                return -1;
            if (((int64_t)backbytes + oob) > INT32_MAX / 2)
                return -1;
            backbytes = backbytes * 2 + oob;
            if ((oob = doubleebx(src, &myebx, &scur, ssize)) == -1)
                return -1;
            if (oob)
                break;
            backbytes--;
            if ((oob = doubleebx(src, &myebx, &scur, ssize)) == -1)
                return -1;
            if (((int64_t)backbytes + oob) > INT32_MAX / 2)
                return -1;
            backbytes = backbytes * 2 + oob;
        }

        backsize = 0;
        backbytes -= 3;

        if (backbytes >= 0) {

            if (scur >= ssize)
                return -1;
            if (backbytes & 0xff000000)
                return -1;
            backbytes <<= 8;
            backbytes += (unsigned char)(src[scur++]);
            backbytes ^= 0xffffffff;

            if (!backbytes)
                break;
            backsize = backbytes & 1;
            CLI_SAR(backbytes, 1);
            unp_offset = backbytes;
        } else {
            if ((backsize = (uint32_t)doubleebx(src, &myebx, &scur, ssize)) == 0xffffffff)
                return -1;
        }

        if ((oob = doubleebx(src, &myebx, &scur, ssize)) == -1)
            return -1;
        if (backsize + oob > UINT32_MAX / 2)
            return -1;
        backsize = backsize * 2 + oob;
        if (!backsize) {
            backsize++;
            do {
                if ((oob = doubleebx(src, &myebx, &scur, ssize)) == -1)
                    return -1;
                if (backsize + oob > UINT32_MAX / 2)
                    return -1;
                backsize = backsize * 2 + oob;
            } while ((oob = doubleebx(src, &myebx, &scur, ssize)) == 0);
            if (oob == -1)
                return -1;
            if (backsize > UINT32_MAX - 2)
                return -1;
            backsize += 2;
        }

        if ((uint32_t)unp_offset < 0xfffffb00)
            backsize++;

        backsize++;
        if (unp_offset >= 0 || (uint32_t)(-(int64_t)unp_offset) > dcur)
            return -1;
        back_offset = dcur - (uint32_t)(-(int64_t)unp_offset);
        if (!CLI_ISCONTAINED_0_TO(*dsize, back_offset, backsize) ||
            !CLI_ISCONTAINED_0_TO(*dsize, dcur, backsize))
            return -1;
        for (i = 0; i < backsize; i++) {
            if ((i & 0xffffU) == 0 && upx_checktimelimit(ctx, &ticks))
                return -1;
            dst[dcur + i] = dst[back_offset + i];
        }
        dcur += backsize;
    }

    return pefromupx(src, ssize, dst, dsize, ep, upx0, upx1, magic, dcur, ctx);
}

int upx_inflate2e(const char *src, uint32_t ssize, char *dst, uint32_t *dsize, uint32_t upx0, uint32_t upx1, uint32_t ep, struct cli_ctx_tag *ctx)
{
    int32_t backbytes, unp_offset = -1;
    uint32_t backsize, back_offset, myebx = 0, scur = 0, dcur = 0, i, magic[] = {0x128, 0x130, 0};
    uint32_t ticks = 0;
    int oob;

    for (;;) {
        while ((oob = doubleebx(src, &myebx, &scur, ssize))) {
            if (oob == -1)
                return -1;
            if (scur >= ssize || dcur >= *dsize)
                return -1;
            dst[dcur++] = src[scur++];
        }

        backbytes = 1;

        for (;;) {
            if ((oob = doubleebx(src, &myebx, &scur, ssize)) == -1)
                return -1;
            if (((int64_t)backbytes + oob) > INT32_MAX / 2)
                return -1;
            backbytes = backbytes * 2 + oob;
            if ((oob = doubleebx(src, &myebx, &scur, ssize)) == -1)
                return -1;
            if (oob)
                break;
            backbytes--;
            if ((oob = doubleebx(src, &myebx, &scur, ssize)) == -1)
                return -1;
            if (((int64_t)backbytes + oob) > INT32_MAX / 2)
                return -1;
            backbytes = backbytes * 2 + oob;
        }

        backbytes -= 3;

        if (backbytes >= 0) {

            if (scur >= ssize)
                return -1;
            if (backbytes & 0xff000000)
                return -1;
            backbytes <<= 8;
            backbytes += (unsigned char)(src[scur++]);
            backbytes ^= 0xffffffff;

            if (!backbytes)
                break;
            backsize = backbytes & 1; /* Using backsize to carry on the shifted out bit (UPX uses CF) */
            CLI_SAR(backbytes, 1);
            unp_offset = backbytes;
        } else {
            if ((backsize = (uint32_t)doubleebx(src, &myebx, &scur, ssize)) == 0xffffffff)
                return -1;
        } /* Using backsize to carry on the doubleebx result (UPX uses CF) */

        if (backsize) { /* i.e. IF ( last sar shifted out 1 bit || last doubleebx()==1 ) */
            if ((backsize = (uint32_t)doubleebx(src, &myebx, &scur, ssize)) == 0xffffffff)
                return -1;
        } else {
            backsize = 1;
            if ((oob = doubleebx(src, &myebx, &scur, ssize)) == -1)
                return -1;
            if (oob) {
                if ((oob = doubleebx(src, &myebx, &scur, ssize)) == -1)
                    return -1;
                if (backsize + oob > UINT32_MAX / 2)
                    return -1;
                backsize = 2 + oob;
            } else {
                do {
                    if ((oob = doubleebx(src, &myebx, &scur, ssize)) == -1)
                        return -1;
                    if (backsize + oob > UINT32_MAX / 2)
                        return -1;
                    backsize = backsize * 2 + oob;
                } while ((oob = doubleebx(src, &myebx, &scur, ssize)) == 0);
                if (oob == -1)
                    return -1;
                if (backsize > UINT32_MAX - 2)
                    return -1;
                backsize += 2;
            }
        }

        if ((uint32_t)unp_offset < 0xfffffb00)
            backsize++;

        if (backsize > UINT32_MAX - 2)
            return -1;
        backsize += 2;

        if (unp_offset >= 0 || (uint32_t)(-(int64_t)unp_offset) > dcur)
            return -1;
        back_offset = dcur - (uint32_t)(-(int64_t)unp_offset);
        if (!CLI_ISCONTAINED_0_TO(*dsize, back_offset, backsize) ||
            !CLI_ISCONTAINED_0_TO(*dsize, dcur, backsize))
            return -1;
        for (i = 0; i < backsize; i++) {
            if ((i & 0xffffU) == 0 && upx_checktimelimit(ctx, &ticks))
                return -1;
            dst[dcur + i] = dst[back_offset + i];
        }
        dcur += backsize;
    }

    return pefromupx(src, ssize, dst, dsize, ep, upx0, upx1, magic, dcur, ctx);
}

int upx_inflatelzma(const char *src, uint32_t ssize, char *dst, uint32_t *dsize, uint32_t upx0, uint32_t upx1, uint32_t ep, uint32_t properties, struct cli_ctx_tag *ctx)
{
    struct CLI_LZMA l;
    uint32_t magic[] = {0xb16, 0xb1e, 0};
    unsigned char fake_lzmahdr[5];
    uint32_t ticks = 0;

    if (upx_checktimelimit(ctx, &ticks))
        return -1;

    memset(&l, 0, sizeof(l));
    cli_writeint32(fake_lzmahdr + 1, *dsize);
    uint8_t lc = properties & 0xff;
    uint8_t lp = (properties >> 8) & 0xff;
    uint8_t pb = (properties >> 16) & 0xff;
    if (lc >= 9 || lp >= 5 || pb >= 5)
        return -1;
    /* The UPX LZMA wrapper reserves the first two bytes before the raw
     * payload.  Reject a section without that prefix before allocating the
     * decoder state. */
    if (ssize <= 2)
        return -1;

    *fake_lzmahdr = lc + 9 * (5 * pb + lp);
    l.next_in     = fake_lzmahdr;
    l.avail_in    = 5;
    if (cli_LzmaInit(&l, *dsize) != LZMA_RESULT_OK)
        return -1;
    /* Keep the decoder's advertised window aligned with the advanced pointer;
     * otherwise a truncated section can make it read two bytes beyond the
     * bounded fmap window. */
    l.avail_in  = (SizeT)(ssize - 2U);
    l.avail_out = *dsize;
    l.next_in   = (unsigned char *)src + 2;
    l.next_out  = (unsigned char *)dst;

    if (cli_LzmaDecode(&l) != LZMA_STREAM_END) {
        /*     __asm__ __volatile__("int3"); */
        cli_LzmaShutdown(&l);
        return -1;
    }
    cli_LzmaShutdown(&l);

    if (upx_checktimelimit(ctx, &ticks))
        return -1;

    return pefromupx(src, ssize, dst, dsize, ep, upx0, upx1, magic, *dsize, ctx);
}

#undef doubleebx
