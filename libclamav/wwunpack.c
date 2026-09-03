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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "clamav.h"
#include "others.h"
#include "execs.h"
#include "wwunpack.h"

#if HAVE_STRING_H
#include <string.h>
#endif

#define RESEED                                  \
    if (CLI_ISCONTAINED(compd, szd, ccur, 4)) { \
        bt = cli_readint32(ccur);               \
        ccur += 4;                              \
    } else {                                    \
        cli_dbgmsg("WWPack: Out of bits\n");    \
        error = CL_EPARSE;                      \
    }                                           \
    bc = 32;

#define BIT          \
    bits = bt >> 31; \
    bt <<= 1;        \
    if (!--bc) {     \
        RESEED;      \
    }

#define BITS(N)                                     \
    bits = bt >> (32 - (N));                        \
    if (bc >= (N)) {                                \
        bc -= (N);                                  \
        bt <<= (N);                                 \
        if (!bc) {                                  \
            RESEED;                                 \
        }                                           \
    } else {                                        \
        if (CLI_ISCONTAINED(compd, szd, ccur, 4)) { \
            bt = cli_readint32(ccur);               \
            ccur += 4;                              \
            bc += 32 - (N);                         \
            bits |= bt >> (bc);                     \
            bt <<= (32 - bc);                       \
        } else {                                    \
            cli_dbgmsg("WWPack: Out of bits\n");    \
            error = CL_EPARSE;                      \
        }                                           \
    }

int cli_wwpack_source_window_offset(uint32_t section_rva, uint32_t source_delta,
                                    uint32_t source_end, uint32_t compressed_size,
                                    size_t available, size_t *offset)
{
    uint64_t source_limit;

    if (offset == NULL || source_delta > section_rva)
        return -1;

    source_limit = (uint64_t)section_rva - source_delta + source_end + 4U;
    if (source_limit < compressed_size ||
        source_limit - compressed_size > available ||
        compressed_size == 0)
        return -1;

    *offset = (size_t)(source_limit - compressed_size);
    return 0;
}

static uint8_t *ww_buffer_window(uint8_t *buf, size_t available, size_t offset, size_t needed)
{
    if (buf == NULL || offset > available || needed > available - offset)
        return NULL;

    return buf + offset;
}

static uint8_t *ww_offset_window(uint8_t *buf, size_t available, uint32_t base_offset,
                                 int64_t adjustment, size_t needed)
{
    int64_t adjusted = (int64_t)base_offset + adjustment;

    if (adjusted < 0 || (uint64_t)adjusted > available)
        return NULL;
    return ww_buffer_window(buf, available, (size_t)adjusted, needed);
}

static uint8_t *ww_adjusted_buffer_window(uint8_t *buf, size_t available, uint8_t *base,
                                          int64_t adjustment, size_t needed)
{
    uintptr_t buf_address;
    uintptr_t base_address;
    size_t base_offset;
    size_t offset;

    if (buf == NULL || base == NULL)
        return NULL;
    buf_address  = (uintptr_t)buf;
    base_address = (uintptr_t)base;
    if (base_address < buf_address || base_address - buf_address > available)
        return NULL;
    base_offset = (size_t)(base_address - buf_address);
    if (adjustment < 0) {
        uint64_t magnitude = (uint64_t)(-(adjustment + 1)) + 1U;

        if (magnitude > base_offset)
            return NULL;
        offset = base_offset - (size_t)magnitude;
    } else {
        uint64_t forward = (uint64_t)adjustment;

        if (forward > available - base_offset)
            return NULL;
        offset = base_offset + (size_t)forward;
    }

    return ww_buffer_window(buf, available, offset, needed);
}

cl_error_t wwunpack(uint8_t *exe, uint32_t exesz, uint8_t *wwsect, struct cli_exe_section *sects, uint16_t scount, uint32_t pe, int desc, cli_ctx *ctx)
{
    uint8_t *structs, *compd, *ccur, *unpd, *ucur, bc;
    uint32_t src, source_delta, srcend, szd, bt, bits;
    size_t source_offset;
    uint32_t ticks = 0;
    cl_error_t error = 0;
    uint16_t i;

    if (exe == NULL || wwsect == NULL || sects == NULL || exesz == 0 ||
        (structs = ww_buffer_window(wwsect, sects[scount].rsz, 0x2a1, 17)) == NULL) {
        cli_mark_scan_incomplete(ctx, "WWPack input or metadata window is invalid");
        return CL_EPARSE;
    }

    cli_dbgmsg("in wwunpack\n");
    while (1) {
        if (cli_checktimelimit(ctx) != CL_SUCCESS) {
            cli_mark_scan_incomplete(ctx, "WWPack decompression reached the configured time limit");
            error = CL_ETIMEOUT;
            break;
        }
        if (!CLI_ISCONTAINED(wwsect, sects[scount].rsz, structs, 17)) {
            cli_dbgmsg("WWPack: Array of structs out of section\n");
            error = CL_EPARSE;
            break;
        }
        source_delta = cli_readint32(structs);
        if (source_delta > sects[scount].rva) {
            cli_dbgmsg("WWPack: Compressed source coordinate underflow\n");
            error = CL_EPARSE;
            break;
        }
        src = sects[scount].rva - source_delta; /* src delta / dst delta - not used / dwords / end of src */
        structs += 8;
        if (cli_readint32(structs) > UINT32_MAX / 4U) {
            cli_dbgmsg("WWPack: Compressed source size overflow\n");
            error = CL_EPARSE;
            break;
        }
        szd = cli_readint32(structs) * 4;
        structs += 4;
        srcend = cli_readint32(structs);
        structs += 4;

        if (cli_wwpack_source_window_offset(sects[scount].rva, source_delta,
                                             srcend, szd, exesz, &source_offset) != 0 ||
            (unpd = ucur = ww_buffer_window(exe, exesz, source_offset, szd)) == NULL) {
            cli_dbgmsg("WWPack: Compressed data out of file\n");
            error = CL_EPARSE;
            break;
        }
        cli_dbgmsg("WWP: src: %x, szd: %x, srcend: %x - %zx\n", src, szd, srcend, source_offset);
        if (!(compd = cli_max_malloc(szd))) {
            cli_dbgmsg("WWPack: Unable to allocate memory for compd\n");
            error = CL_EMEM;
            break;
        }
        memcpy(compd, unpd, szd);
        memset(unpd, -1, szd); /*FIXME*/
        ccur = compd;

        RESEED;
        while (CL_SUCCESS == error) {
            uint32_t backbytes, backsize;
            uint8_t saved;

            if (!(++ticks & 0xfffU) && cli_checktimelimit(ctx) != CL_SUCCESS) {
                cli_mark_scan_incomplete(ctx, "WWPack decompression reached the configured time limit");
                error = CL_ETIMEOUT;
                break;
            }

            BIT;
            if (!bits) { /* BYTE copy */
                if (ccur - compd >= szd || !CLI_ISCONTAINED(exe, exesz, ucur, 1))
                    error = CL_EPARSE;
                else
                    *ucur++ = *ccur++;
                continue;
            }

            BITS(2);
            if (bits == 3) { /* WORD backcopy */
                uint8_t shifted, subbed = 31;
                BITS(2);
                shifted = bits + 5;
                if (bits >= 2) {
                    shifted++;
                    subbed += 0x80;
                }
                backbytes = (1 << shifted) - subbed; /* 1h, 21h, 61h, 161h */
                BITS(shifted);                       /* 5, 6, 8, 9 */
                if (error || bits == 0x1ff) break;
                backbytes += bits;
                {
                    uint8_t *backcopy = ww_adjusted_buffer_window(exe, exesz, ucur,
                                                                   -(int64_t)backbytes, 2);

                    if (!CLI_ISCONTAINED(exe, exesz, ucur, 2) || backcopy == NULL) {
                        error = CL_EPARSE;
                    } else {
                        ucur[0] = backcopy[0];
                        ucur[1] = backcopy[1];
                        ucur += 2;
                    }
                }
                continue;
            }

            /* BLOCK backcopy */
            saved = bits; /* cmp al, 1 / pushf */

            BITS(3);
            if (bits < 6) {
                backbytes = bits;
                switch (bits) {
                    case 4: /* 10,11 */
                        backbytes++;
                        /* fall-through */
                    case 3: /* 8,9 */
                        BIT;
                        backbytes += bits;
                        /* fall-through */
                    case 0:
                    case 1:
                    case 2: /* 5,6,7 */
                        backbytes += 5;
                        break;
                    case 5: /* 12 */
                        backbytes = 12;
                        break;
                }
                BITS(backbytes);
                bits += (1 << backbytes) - 31;
            } else if (bits == 6) {
                BITS(0x0e);
                bits += 0x1fe1;
            } else {
                BITS(0x0f);
                bits += 0x5fe1;
            }

            backbytes = bits;

            /* popf / jb */
            if (!saved) {
                BIT;
                if (!bits) {
                    BIT;
                    bits += 5;
                } else {
                    BITS(3);
                    if (bits) {
                        bits += 6;
                    } else {
                        BITS(4);
                        if (bits) {
                            bits += 13;
                        } else {
                            uint8_t cnt      = 4;
                            uint16_t shifted = 0x0d;

                            do {
                                if (cnt == 7) {
                                    cnt     = 0x0e;
                                    shifted = 0;
                                    break;
                                }
                                shifted = ((shifted + 2) << 1) - 1;
                                BIT;
                                cnt++;
                            } while (!bits);
                            BITS(cnt);
                            bits += shifted;
                        }
                    }
                }
                backsize = bits;
            } else {
                backsize = saved + 2;
            }

            {
                uint8_t *backcopy = ww_adjusted_buffer_window(exe, exesz, ucur,
                                                               -(int64_t)backbytes, backsize);

                if (!CLI_ISCONTAINED(exe, exesz, ucur, backsize) || backcopy == NULL)
                    error = CL_EPARSE;
                else {
                while (backsize--) {
                    if (!(++ticks & 0xffffU) && cli_checktimelimit(ctx) != CL_SUCCESS) {
                        cli_mark_scan_incomplete(ctx, "WWPack decompression reached the configured time limit");
                        error = CL_ETIMEOUT;
                        break;
                    }
                    *ucur = *backcopy++;
                    ucur++;
                }
                }
            }
        }
        free(compd);
        if (error) {
            cli_dbgmsg("WWPack: decompression error\n");
            break;
        }
        if (error || !*structs++) break;
    }

    if (error == CL_EPARSE)
        cli_mark_scan_incomplete(ctx, "WWPack input or compressed stream was malformed");

    if (CL_SUCCESS == error) {

        // Verify minimum size of exe before dereferencing.
        uint8_t *pe_header = ww_offset_window(exe, exesz, pe, 0, 0x54);
        uint8_t *ww_header = ww_buffer_window(wwsect, sects[scount].rsz, 0x295, 4);

        if (pe_header == NULL) {
            cli_dbgmsg("WWPack: unpack memory address out of bounds.\n");
            cli_mark_scan_incomplete(ctx, "WWPack PE header window is outside the input buffer");
            return CL_EPARSE;
        }

        // Verify minimum size of wwsect before dereferencing.
        if (ww_header == NULL) {
            cli_dbgmsg("WWPack: unpack memory address out of bounds.\n");
            cli_mark_scan_incomplete(ctx, "WWPack metadata window is outside the input buffer");
            return CL_EPARSE;
        }

        pe_header[6] = (uint8_t)scount;
        pe_header[7] = (uint8_t)(scount >> 8);

        cli_writeint32(pe_header + 0x28, cli_readint32(ww_header) + sects[scount].rva + 0x299);

        cli_writeint32(pe_header + 0x50, cli_readint32(pe_header + 0x50) - sects[scount].vsz);

        {
            uint64_t section_table_offset = (uint64_t)pe +
                                             (0xffffU & cli_readint32(pe_header + 0x14)) + 0x18U;

            if (section_table_offset > exesz ||
                (structs = ww_buffer_window(exe, exesz, (size_t)section_table_offset, 0x28)) == NULL) {
                cli_dbgmsg("WWPack: section-table pointer out of bounds\n");
                cli_mark_scan_incomplete(ctx, "WWPack reconstructed section table is outside the input buffer");
                return CL_EPARSE;
            }
        }

        for (i = 0; i < scount; i++) {
            if (!(i & 0xffU) && cli_checktimelimit(ctx) != CL_SUCCESS) {
                cli_mark_scan_incomplete(ctx, "WWPack output reconstruction reached the configured time limit");
                return CL_ETIMEOUT;
            }
            if (!CLI_ISCONTAINED(exe, exesz, structs, 0x28)) {
                cli_dbgmsg("WWPack: structs pointer out of bounds\n");
                cli_mark_scan_incomplete(ctx, "WWPack reconstructed section table is outside the input buffer");
                return CL_EPARSE;
            }

            cli_writeint32(structs + 8, sects[i].vsz);
            cli_writeint32(structs + 12, sects[i].rva);
            cli_writeint32(structs + 16, sects[i].vsz);
            cli_writeint32(structs + 20, sects[i].rva);
            structs += 0x28;
        }
        if (!CLI_ISCONTAINED(exe, exesz, structs, 0x28)) {
            cli_dbgmsg("WWPack: structs pointer out of bounds\n");
            cli_mark_scan_incomplete(ctx, "WWPack reconstructed section table is outside the input buffer");
            return CL_EPARSE;
        }

        memset(structs, 0, 0x28);
        if (cli_checktimelimit(ctx) != CL_SUCCESS) {
            cli_mark_scan_incomplete(ctx, "WWPack output reached the configured time limit");
            return CL_ETIMEOUT;
        }
        if (cli_writen(desc, exe, exesz) != (size_t)exesz) {
            cli_mark_scan_incomplete(ctx, "WWPack output could not be written completely");
            error = CL_EWRITE;
        }
    }
    return error;
}
