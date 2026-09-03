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
** petitep.c
**
** 09/07/2k4 - Dumped and reversed
** 10/07/2k4 - Very 1st approach
** 10/07/2k4 - PE stuff and main loop
** 11/07/2k4 - Porting finished, tracking my bugs...
** 12/07/2k4 - ARRRRRGHHH :D
** 14/07/2k4 - Code cleaned
** 15/07/2k4 - Securing && ClamAV porting
** 21/07/2k4 - Unmangled imports now supported
** 22/07/2k4 - Unstripped .relocs now supported
**
*/

/*
** Unpacks a buffer containing a petite 2.2 compressed
** file. Doesn't perform Import Table unmangling. Doesn't
** fixup call/jumps. Tries to "guess" the original sections
** structure and entrypoint.
**
** Lotta phanx to Micky for patiently bearing my screams :P
** Greets to Ian Luck: the SEH MOVSB thingy almost got me :O
** TODO: Cope with level 0 and older petite versions.
*/

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "clamav.h"
#include "rebuildpe.h"
#include "execs.h"
#include "others.h"
#include "petite.h"

int cli_petite_rva_window_offset(uint32_t base_rva, uint32_t target_rva,
                                 int64_t adjustment, size_t available,
                                 size_t needed, size_t *offset)
{
    int64_t adjusted;
    uint64_t relative;

    if (offset == NULL)
        return -1;

    if ((adjustment > 0 &&
         (uint64_t)adjustment > (uint64_t)INT64_MAX - target_rva) ||
        (adjustment < 0 && adjustment < INT64_MIN + (int64_t)target_rva))
        return -1;

    adjusted = (int64_t)target_rva + adjustment;
    if (adjusted < 0 || (uint64_t)adjusted > UINT32_MAX ||
        (uint64_t)adjusted < base_rva)
        return -1;

    relative = (uint64_t)adjusted - base_rva;
    if (relative > SIZE_MAX || relative > available ||
        needed > available - (size_t)relative)
        return -1;

    *offset = (size_t)relative;
    return 0;
}

static char *petite_rva_window(char *buf, uint32_t base_rva, uint32_t target_rva,
                               int64_t adjustment, size_t available, size_t needed)
{
    size_t offset;

    if (buf == NULL || cli_petite_rva_window_offset(base_rva, target_rva,
                                                     adjustment, available,
                                                     needed, &offset) != 0)
        return NULL;

    return buf + offset;
}

static char *petite_buffer_window(char *buf, size_t available, size_t offset,
                                  size_t needed)
{
    if (buf == NULL || offset > available || needed > available - offset)
        return NULL;

    return buf + offset;
}

static char *petite_adjusted_buffer_window(char *buf, size_t available, char *base,
                                           int64_t adjustment, size_t needed)
{
    size_t base_offset;
    size_t offset;

    if (buf == NULL || base == NULL || base < buf || base > buf + available)
        return NULL;
    base_offset = (size_t)(base - buf);
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

    return petite_buffer_window(buf, available, offset, needed);
}

static int doubledl(char **scur, uint8_t *mydlptr, char *buffer, uint32_t buffersize)
{
    if (scur == NULL || mydlptr == NULL || buffer == NULL || buffersize == 0)
        return -1;

    unsigned char mydl  = *mydlptr;
    unsigned char olddl = mydl;

    mydl *= 2;
    if (!(olddl & 0x7f)) {
        if (*scur == NULL || *scur < buffer ||
            *scur >= buffer + buffersize ||
            (size_t)(*scur - buffer) >= (size_t)buffersize - 1U)
            return -1;
        olddl = **scur;
        mydl  = olddl * 2 + 1;
        *scur = *scur + 1;
    }
    *mydlptr = mydl;
    return (olddl >> 7) & 1;
}

static int petite_checktimelimit(cli_ctx *ctx, uint32_t *ticks)
{
    if (ctx == NULL)
        return 0;

    (*ticks)++;
    if (*ticks < 4096)
        return 0;

    *ticks = 0;
    if (cli_checktimelimit(ctx) != CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, "Petite decompression reached the configured time limit");
        return 1;
    }

    return 0;
}

int petite_inflate2x_1to9(char *buf, uint32_t minrva, uint32_t bufsz, struct cli_exe_section *sections, unsigned int sectcount, uint32_t Imagebase, uint32_t pep, int desc, int version, uint32_t ResRva, uint32_t ResSize, cli_ctx *ctx)
{
    char *packed     = NULL;
    uint32_t thisrva = 0, bottom = 0, enc_ep = 0, irva = 0, workdone = 0, grown = 0x355, skew = 0x35;
    int j = 0, oob, mangled = 0, check4resources = 0;
    uint32_t ticks = 0;
    struct cli_exe_section *usects = NULL;
    void *tmpsct                   = NULL;

    if (buf == NULL || sections == NULL || sectcount == 0 || bufsz == 0)
        return 1;

    /*
     * -] The real thing [-
     */

    /* NOTE: (435063->4350a5) Petite kernel32!imports and error strings */

    /* Here we adjust the start of packed blob, the size of petite code,
     * the difference in size if relocs were stripped
     * See below...
     */

    if (version == 2)
        packed = petite_rva_window(buf, minrva, sections[sectcount - 1].rva,
                                   0x1b8, bufsz, 4);
    if (version == 1) {
        packed = petite_rva_window(buf, minrva, sections[sectcount - 1].rva,
                                   0x178, bufsz, 4);
        grown  = 0x323; /* My name is Harry potter */
        skew   = 0x34;
    }

    if (packed == NULL)
        return 1;

    if (ctx != NULL && cli_checktimelimit(ctx) != CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, "Petite decompression reached the configured time limit");
        return 1;
    }

    while (1) {
        char *ssrc, *ddst;
        uint32_t size, srva;
        int backbytes, oldback, addsize;
        unsigned int backsize;

        if (petite_checktimelimit(ctx, &ticks)) {
            if (usects)
                free(usects);
            return 1;
        }

        if (!CLI_ISCONTAINED(buf, bufsz, packed, 4)) {
            if (usects)
                free(usects);
            return 1;
        }
        srva = cli_readint32(packed);

        if (!srva) {
            /* WERE DONE !!! :D */
            int t, upd = 1;

            if (j <= 0) /* Some non petite compressed files will get here */
                return 1;

            /* Select * from sections order by rva asc; */
            while (upd) {
                upd = 0;
                for (t = 0; t < j - 1; t++) {
                    uint32_t trva, trsz, tvsz;

                    if (usects[t].rva <= usects[t + 1].rva)
                        continue;
                    trva              = usects[t].rva;
                    trsz              = usects[t].rsz;
                    tvsz              = usects[t].vsz;
                    usects[t].rva     = usects[t + 1].rva;
                    usects[t].rsz     = usects[t + 1].rsz;
                    usects[t].vsz     = usects[t + 1].vsz;
                    usects[t + 1].rva = trva;
                    usects[t + 1].rsz = trsz;
                    usects[t + 1].vsz = tvsz;
                    upd               = 1;
                }
            }

            /* Computes virtualsize... we try to guess, actually :O */
            for (t = 0; t < j - 1; t++) {
                if (usects[t].vsz != usects[t + 1].rva - usects[t].rva)
                    usects[t].vsz = usects[t + 1].rva - usects[t].rva;
            }

            /*
             * Our encryption is pathetic and out software is lame but
             * we need to claim it's unbreakable.
             * So why don't we just mangle the imports and encrypt the EP?!
             */

            /* Decrypts old entrypoint if we got enough clues */
            if (enc_ep) {
                uint32_t virtaddr = pep + 5 + Imagebase, tmpep;
                int rndm = 0, dummy = 1;
                char *thunk = petite_rva_window(buf, minrva, irva, 0, bufsz, 4);
                char *imports;

                if (thunk == NULL) {
                    free(usects);
                    return 1;
                }

                if (version == 2) { /* 2.2 onley */

                    while (dummy && CLI_ISCONTAINED(buf, bufsz, thunk, 4)) {
                        uint32_t api;

                        if (petite_checktimelimit(ctx, &ticks)) {
                            free(usects);
                            return 1;
                        }

                        if (!cli_readint32(thunk)) {
                            workdone = 1;
                            break;
                        }

                        imports = petite_rva_window(buf, minrva,
                                                    cli_readint32(thunk), 0,
                                                    bufsz, 4);
                        if (imports == NULL) {
                            free(usects);
                            return 1;
                        }
                        thunk += 4;
                        dummy = 0;

                        while (CLI_ISCONTAINED(buf, bufsz, imports, 4)) {
                            if (petite_checktimelimit(ctx, &ticks)) {
                                free(usects);
                                return 1;
                            }
                            dummy = 0;

                            imports += 4;
                            if (!(api = cli_readint32(imports - 4))) {
                                dummy = 1;
                                break;
                            }
                            if ((api != (api | 0x80000000)) && mangled && --rndm < 0) {
                                api = virtaddr;
                                virtaddr += 5; /* EB + 1 double */
                                rndm = virtaddr & 7;
                            } else {
                                api = 0xbff01337; /* KERNEL32!leet */
                            }
                            if (sections[sectcount - 1].rva + Imagebase < api)
                                enc_ep--;
                            if (api < virtaddr)
                                enc_ep--;
                            tmpep  = (enc_ep & 0xfffffff8) >> 3 & 0x1fffffff;
                            enc_ep = (enc_ep & 7) << 29 | tmpep;
                        }
                    }
                } else
                    workdone = 1;
                enc_ep = pep + 5 + enc_ep;
                if (workdone == 1) {
                    cli_dbgmsg("Petite: Old EP: %x\n", enc_ep);
                } else {
                    enc_ep = usects[0].rva;
                    cli_dbgmsg("Petite: In troubles while attempting to decrypt old EP, using bogus %x\n", enc_ep);
                }
            }

            /* Let's compact data */
            for (t = 0; t < j; t++) {
                usects[t].raw = (t > 0) ? (usects[t - 1].raw + usects[t - 1].rsz) : 0;
                if (usects[t].rsz != 0) {
                    char *destination = petite_buffer_window(buf, bufsz,
                                                              usects[t].raw,
                                                              usects[t].rsz);
                    char *source = petite_rva_window(buf, minrva,
                                                     usects[t].rva, 0, bufsz,
                                                     usects[t].rsz);

                    if (destination == NULL || source == NULL) {
                        cli_dbgmsg("Petite: Invalid section window %d, Raw: %x, RSize:%x\n", t, usects[t].raw, usects[t].rsz);
                        free(usects);
                        return 1;
                    }
                    memmove(destination, source, usects[t].rsz);
                }
            }

            /* Showtime!!! */
            cli_dbgmsg("Petite: Sections dump:\n");
            for (t = 0; t < j; t++)
                cli_dbgmsg("Petite: .SECT%d RVA:%x VSize:%x ROffset: %x, RSize:%x\n", t, usects[t].rva, usects[t].vsz, usects[t].raw, usects[t].rsz);
            if (!cli_rebuildpe_ctx(ctx, buf, usects, j, Imagebase, enc_ep, ResRva, ResSize, desc)) {
                cli_dbgmsg("Petite: Rebuilding failed\n");
                free(usects);
                return 1;
            }
            free(usects);
            return 0;
        }

        size = srva & 0x7fffffff;
        if (srva != size) { /* Test and clear bit 31 */
            check4resources = 0;
            /*
             * Enumerates each petite data section
             * I should get here once or twice:
             * - 1 time for the resource section (if present)
             * - 1 time for the all_the_rest section
             */

            if (!CLI_ISCONTAINED(buf, bufsz, packed + 4, 8)) {
                if (usects)
                    free(usects);
                return 1;
            }
            /* Save the end of current packed section for later use */
            bottom = (uint32_t)cli_readint32(packed + 8);
            if (bottom > UINT32_MAX - 4) {
                /* bottom is too large, would cause integer overflow */
                if (usects)
                    free(usects);
                return 1;
            }
            bottom += 4;

            if (size == 0 || (size_t)size > SIZE_MAX / 4U) {
                if (usects)
                    free(usects);
                return 1;
            }
            {
                size_t copy_size = (size_t)size * 4U;
                int64_t copy_adjustment = -(int64_t)(copy_size - 4U);

                ssrc = petite_rva_window(buf, minrva, cli_readint32(packed + 4),
                                          copy_adjustment, bufsz, copy_size);
                ddst = petite_rva_window(buf, minrva, cli_readint32(packed + 8),
                                          copy_adjustment, bufsz, copy_size);
            }

            if (ssrc == NULL || ddst == NULL) {
                if (usects)
                    free(usects);
                return 1;
            }

            /* Copy packed data to the end of the current packed section */
            memmove(ddst, ssrc, (size_t)size * 4U);
            packed += 0x0c;
        } else {
            uint32_t check1, check2;
            uint8_t mydl = 0;
            uint8_t goback;
            unsigned int q;

            /* Unpack each original section in turn */

            if (!CLI_ISCONTAINED(buf, bufsz, packed + 4, 8)) {
                if (usects)
                    free(usects);
                return 1;
            }

            size    = cli_readint32(packed + 4); /* How many bytes to unpack */
            thisrva = cli_readint32(packed + 8); /* RVA of the original section */
            packed += 0x10;

            if (j >= 96) {
                cli_dbgmsg("Petite: maximum number of sections exceeded, giving up.\n");
                free(usects);
                return 1;
            }
            /* Alloc 1 more struct */
            if (!(tmpsct = cli_max_realloc(usects, sizeof(struct cli_exe_section) * (j + 1)))) {
                if (usects)
                    free(usects);
                return 1;
            }

            usects = (struct cli_exe_section *)tmpsct;
            /* Save section spex for later rebuilding */
            usects[j].rva = thisrva;
            usects[j].rsz = size;
            if ((int)(bottom - thisrva) > 0)
                usects[j].vsz = bottom - thisrva;
            else
                usects[j].vsz = size;
            usects[j].raw = 0; /* Cheaper than memset */

            if (!size) { /* That's a ghost section! reloc any1? :P */
                j++;
                continue;
            }

            ssrc = petite_rva_window(buf, minrva, srva, 0, bufsz, 1);
            ddst = petite_rva_window(buf, minrva, thisrva, 0, bufsz, 1);

            /* Last petite section (unpacked 1st) could contain unpacked data
             * (eg the icon): let's fix the rva
             */

            for (q = 0; q < sectcount; q++) {
                if (!CLI_ISCONTAINED(sections[q].rva, sections[q].vsz, usects[j].rva, usects[j].vsz))
                    continue;
                if (!check4resources) {
                    usects[j].rva = sections[q].rva;
                    usects[j].rsz = thisrva - sections[q].rva + size;
                }
                break;
            }
            if (q == sectcount) {
                free(usects);
                return 1;
            }

            /* Increase count of unpacked sections */
            j++;

            /* Setup some crap for later checks */
            if (size < 0x10000) {
                check1 = 0x0FFFFC060;
                check2 = 0x0FFFFFC60;
                goback = 5;
            } else if (size < 0x40000) {
                check1 = 0x0FFFF8180;
                check2 = 0x0FFFFF980;
                goback = 7;
            } else {
                check1 = 0x0FFFF8300;
                check2 = 0x0FFFFFB00;
                goback = 8;
            }

            /*
             * NOTE: on last loop we get esi=edi=ImageBase (which is not writeable)
             * The movsb on the next line causes the iat_rebuild_and_decrypt_oldEP()
             * func to get called instead... ehehe very smart ;)
             */

            if (ssrc == NULL || ddst == NULL) {
                free(usects);
                return 1;
            }

            size--;
            *ddst++   = *ssrc++; /* eheh u C gurus gotta luv these monsters :P */
            backbytes = 0;
            oldback   = 0;

            /* No surprises here... NRV any1??? ;) */
            while (size > 0) {
                if (petite_checktimelimit(ctx, &ticks)) {
                    free(usects);
                    return 1;
                }
                oob = doubledl(&ssrc, &mydl, buf, bufsz);
                if (oob == -1) {
                    free(usects);
                    return 1;
                }
                if (!oob) {
                    if (!CLI_ISCONTAINED(buf, bufsz, ssrc, 1) || !CLI_ISCONTAINED(buf, bufsz, ddst, 1)) {
                        free(usects);
                        return 1;
                    }
                    *ddst++ = (char)((*ssrc++) ^ (size & 0xff));
                    size--;
                } else {
                    addsize = 0;
                    backbytes++;
                    while (1) {
                        if (petite_checktimelimit(ctx, &ticks)) {
                            free(usects);
                            return 1;
                        }
                        if ((oob = doubledl(&ssrc, &mydl, buf, bufsz)) == -1) {
                            free(usects);
                            return 1;
                        }
                        if (backbytes >= INT_MAX / 2) {
                            free(usects);
                            cli_dbgmsg("Petite: probably invalid file\n");
                            return 1;
                        }
                        backbytes = backbytes * 2 + oob;
                        if ((oob = doubledl(&ssrc, &mydl, buf, bufsz)) == -1) {
                            free(usects);
                            return 1;
                        }
                        if (!oob)
                            break;
                    }
                    backbytes -= 3;
                    if (backbytes >= 0) {
                        backsize = goback;
                        do {
                            if ((oob = doubledl(&ssrc, &mydl, buf, bufsz)) == -1) {
                                free(usects);
                                return 1;
                            }
                            if (backbytes >= INT_MAX / 2) {
                                free(usects);
                                cli_dbgmsg("Petite: probably invalid file\n");
                                return 1;
                            }
                            backbytes = backbytes * 2 + oob;
                            backsize--;
                        } while (backsize);
                        backbytes ^= 0xffffffff;
                        addsize += 1 + (backbytes < (int)check2) + (backbytes < (int)check1);
                        oldback = backbytes;
                    } else {
                        backsize  = backbytes + 1;
                        backbytes = oldback;
                    }

                    if ((oob = doubledl(&ssrc, &mydl, buf, bufsz)) == -1) {
                        free(usects);
                        return 1;
                    }
                    backsize = backsize * 2 + oob;
                    if ((oob = doubledl(&ssrc, &mydl, buf, bufsz)) == -1) {
                        free(usects);
                        return 1;
                    }
                    backsize = backsize * 2 + oob;
                    if (!backsize) {
                        backsize++;
                        while (1) {
                            if ((oob = doubledl(&ssrc, &mydl, buf, bufsz)) == -1) {
                                free(usects);
                                return 1;
                            }
                            backsize = backsize * 2 + oob;
                            if ((oob = doubledl(&ssrc, &mydl, buf, bufsz)) == -1) {
                                free(usects);
                                return 1;
                            }
                            if (!oob)
                                break;
                        }
                        backsize += 2;
                    }
                    backsize += addsize;
                    if ((uint64_t)backsize > (uint64_t)size) {
                        free(usects);
                        return 1;
                    }
                    size -= backsize;
                    {
                        char *backref = petite_adjusted_buffer_window(
                            buf, bufsz, ddst, (int64_t)backbytes, backsize);

                        if (!CLI_ISCONTAINED(buf, bufsz, ddst, backsize) ||
                            backref == NULL) {
                            free(usects);
                            return 1;
                        }
                        while (backsize--) {
                            if (petite_checktimelimit(ctx, &ticks)) {
                                free(usects);
                                return 1;
                            }
                            *ddst = *backref;
                            ddst++;
                            backref++;
                        }
                    }
                    backbytes = 0;
                    backsize  = 0;
                } /* else */
            }     /* while(ebx) */

            /* Any lame petite code here? If so let's strip it
             * We've done version adjustments already, see above
             */

            if (j) {
                int strippetite = 0;
                uint32_t reloc;

                /* LONG MAGIC = 33C05E64 8B188B1B 8D63D65D */
                char *petite_magic = petite_adjusted_buffer_window(
                    buf, bufsz, ddst, -(int64_t)grown + 5 + 0x4f, 8);

                if (usects[j - 1].rsz > grown && petite_magic != NULL &&
                    cli_readint32(petite_magic) == 0x645ec033 &&
                    cli_readint32(petite_magic + 4) == 0x1b8b188b) {
                    reloc       = 0;
                    strippetite = 1;
                }
                petite_magic = petite_adjusted_buffer_window(
                    buf, bufsz, ddst, -(int64_t)grown + 5 + 0x4f - skew, 8);
                if (!strippetite &&
                    usects[j - 1].rsz > grown + skew &&
                    petite_magic != NULL &&
                    cli_readint32(petite_magic) == 0x645ec033 &&
                    cli_readint32(petite_magic + 4) == 0x1b8b188b) {
                    reloc       = skew; /* If the original exe had a .reloc were skewed */
                    strippetite = 1;
                }

                petite_magic = petite_adjusted_buffer_window(
                    buf, bufsz, ddst,
                    -(int64_t)grown + 0x0f - 8 - (int64_t)reloc, 8);
                if (strippetite && petite_magic != NULL) {
                    uint32_t test1, test2;

                    /* REMINDER: DON'T BPX IN HERE U DUMBASS!!!!!!!!!!!!!!!!!!!!!!!! */
                    test1 = cli_readint32(petite_magic) ^ 0x9d6661aa;
                    test2 = cli_readint32(petite_magic + 4) ^ 0xe908c483;

                    cli_dbgmsg("Petite: Found petite code in sect%d(%x). Let's strip it.\n", j - 1, usects[j - 1].rva);
                    petite_magic = petite_adjusted_buffer_window(
                        buf, bufsz, ddst,
                        -(int64_t)grown + 0x0f - (int64_t)reloc,
                        0x1c0 - 0x0f + 4);
                    if (test1 == test2 && petite_magic != NULL) {
                        irva    = cli_readint32(petite_magic + 0x112);
                        enc_ep  = cli_readint32(petite_magic) ^ test1;
                        mangled = ((uint32_t)cli_readint32(petite_magic + 0x1b1) != 0x90909090); /* FIXME: Magic's too short??? */
                        cli_dbgmsg("Petite: Encrypted EP: %x | Array of imports: %x\n", enc_ep, irva);
                    }
                    usects[j - 1].rsz -= grown + reloc;
                }
            }
            check4resources++;
        } /* outer else */
    }     /* while true */
}
