/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009-2013 Sourcefire, Inc.
 *
 *  Authors: aCaB <acab@clamav.net>
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

/* common routines to deal with installshield archives and installers */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#include <limits.h>
#if HAVE_STRINGS_H
#include <strings.h>
#endif
#if defined(HAVE_MMAP) && defined(HAVE_SYS_MMAN_H)
#include <sys/mman.h>
#endif
#include <zlib.h>

#include "clamav.h"
#include "scanners.h"
#include "others.h"
#include "fmap.h"
#include "ishield.h"

#ifndef LONG_MAX
#define LONG_MAX ((-1UL) >> 1)
#endif

#ifndef HAVE_ATTRIB_PACKED
#define __attribute__(x)
#endif
#ifdef HAVE_PRAGMA_PACK
#pragma pack(1)
#endif
#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack 1
#endif

/* PACKED things go here */

struct IS_HDR {
    uint32_t magic;
    uint32_t unk1; /* version ??? */
    uint32_t unk2; /* ??? */
    uint32_t data_off;
    uint32_t data_sz; /* ??? */
} __attribute__((packed));

struct IS_FB {
    char fname[0x104]; /* MAX_PATH */
    uint32_t unk1;     /* 6 */
    uint32_t unk2;
    uint64_t csize;
    uint32_t unk3;
    uint32_t unk4; /* 1 */
    uint32_t unk5;
    uint32_t unk6;
    uint32_t unk7;
    uint32_t unk8;
    uint32_t unk9;
    uint32_t unk10;
    uint32_t unk11;
} __attribute__((packed));

struct IS_COMPONENT {
    uint32_t str_name_off;
    uint32_t unk_str1_off;
    uint32_t unk_str2_off;
    uint16_t unk_flags;
    uint32_t unk_str3_off;
    uint32_t unk_str4_off;
    uint16_t ordinal_id;
    uint32_t str_shortname_off;
    uint32_t unk_str6_off;
    uint32_t unk_str7_off;
    uint32_t unk_str8_off;
    char guid1[16];
    char guid2[16];
    uint32_t unk_str9_off;
    char unk1[3];
    uint16_t unk_flags2;
    uint32_t unk3[5];
    uint32_t unk_str10_off;
    uint32_t unk4[4];
    uint16_t unk5;
    uint16_t sub_comp_cnt;
    uint32_t sub_comp_offs_array;
    uint32_t next_comp_off;
    uint32_t unk_str11_off;
    uint32_t unk_str12_off;
    uint32_t unk_str13_off;
    uint32_t unk_str14_off;
    uint32_t str_next1_off;
    uint32_t str_next2_off;
} __attribute__((packed));

struct IS_INSTTYPEHDR {
    uint32_t unk1;
    uint32_t cnt;
    uint32_t off;
} __attribute__((packed));

struct IS_INSTTYPEITEM {
    uint32_t str_name1_off;
    uint32_t str_name2_off;
    uint32_t str_name3_off;
    uint32_t cnt;
    uint32_t off;
} __attribute__((packed));

struct IS_OBJECTS {
    /* 200 */ uint32_t strings_off;
    /* 204 */ uint32_t zero1;
    /* 208 */ uint32_t comps_off;
    /* 20c */ uint32_t dirs_off;
    /* 210 */ uint32_t zero2;
    /* 214 */ uint32_t unk1, unk2; /* 0x4a636 304694 uguali - NOT AN OFFSET! */
    /* 21c */ uint32_t dirs_cnt;
    /* 220 */ uint32_t zero3;
    /* 224 */ uint32_t dirs_sz; /* dirs_cnt * 4 */
    /* 228 */ uint32_t files_cnt;
    /* 22c */ uint32_t dir_sz2; /* same as dirs_sz ?? */
    /* 230 */ uint16_t unk5;    /* 1 - comp count ?? */
    /* 232 */ uint32_t insttype_off;
    /* 234 */ uint16_t zero4;
    /* 238 */ uint32_t zero5;
    /* 23c */ uint32_t unk7; /* 0xd0 - 208 */
    /* 240 */ uint16_t unk8;
    /* 242 */ uint32_t unk9;
    /* 246 */ uint32_t unk10;
} __attribute__((packed));

struct IS_FILEITEM {
    uint16_t flags; /* bit 2 = INTERNAL, bit 3 = alternate filename layout; valid values are 0, 4, 8, 0xc */
    uint64_t size;
    uint64_t csize;
    uint64_t stream_off;
    uint8_t md5[16];
    uint64_t versioninfo_id;
    uint32_t zero1;
    uint32_t zero2;
    uint32_t str_name_off;
    uint16_t dir_id;
    uint32_t unk13;       /* 0, 20, 21 ??? */
    uint32_t unk14;       /* timestamp ??? */
    uint32_t unk15;       /* begins with 1 then 2 but not the cab# ??? */
    uint32_t prev_dup_id; /* msvcrt #38(0, 97, 2) #97(38, 1181, 3) ... , 0, 1) */
    uint32_t next_dup_id;
    uint8_t flag_has_dup; /* HAS_NEXT = 2 | HAS_BOTH = 3 | HAS_PREV = 1 */
    uint16_t datafile_id;
} __attribute__((packed));

#ifdef HAVE_PRAGMA_PACK
#pragma pack()
#endif
#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack
#endif

static cl_error_t is_dump_and_scan(cli_ctx *ctx, off_t off, size_t fsize);
static const uint8_t skey[] = {0xec, 0xca, 0x79, 0xf8}; /* ~0x13, ~0x35, ~0x86, ~0x07 */

cl_error_t cli_ishield_msi_header_check(cli_ctx *ctx, off_t offset)
{
    static const uint8_t magic[] = "InstallShield\0";
    const uint8_t *buf;
    size_t remaining;

    if (!ctx || !ctx->fmap)
        return CL_ENULLARG;
    if (offset < 0 || (uint64_t)offset > ctx->fmap->len)
        return CL_EFORMAT;

    remaining = ctx->fmap->len - (size_t)offset;
    if (remaining < sizeof(magic) - 1)
        return CL_EFORMAT;
    if (!(buf = fmap_need_off_once(ctx->fmap, offset, sizeof(magic) - 1)))
        return CL_EFORMAT;
    if (memcmp(buf, magic, sizeof(magic) - 1) != 0)
        return CL_EFORMAT;

    /* cli_scanishield_msi() consumes a 0x20-byte control block immediately
     * after the 14-byte InstallShield marker. */
    if (remaining - (sizeof(magic) - 1) < 0x20)
        return CL_EPARSE;
    if (!fmap_need_off_once(ctx->fmap, offset + (sizeof(magic) - 1), 0x20))
        return CL_EPARSE;

    return CL_SUCCESS;
}

/* Extracts the content of MSI based IS */
cl_error_t cli_scanishield_msi(cli_ctx *ctx, off_t off)
{
    cl_error_t ret;
    const uint8_t *buf;
    unsigned int fcount, scanned = 0;
    fmap_t *map;

    if (!ctx || !ctx->engine || !ctx->fmap)
        return CL_ENULLARG;
    map = ctx->fmap;

    cli_dbgmsg("in ishield-msi\n");
    if (!(buf = fmap_need_off_once(map, off, 0x20))) {
        cli_dbgmsg("ishield-msi: short read for header\n");
        cli_mark_scan_incomplete(ctx, "InstallShield MSI header is truncated");
        return CL_EPARSE;
    }

    off += 0x20;
    if (cli_readint32(buf + 8) | cli_readint32(buf + 0xc) | cli_readint32(buf + 0x10) | cli_readint32(buf + 0x14) | cli_readint32(buf + 0x18) | cli_readint32(buf + 0x1c)) {
        return CL_SUCCESS;
    }

    if (!(fcount = cli_readint32(buf))) {
        cli_dbgmsg("ishield-msi: no files?\n");
        return CL_SUCCESS;
    }

    while (fcount--) {
        struct IS_FB fb;
        uint8_t obuf[BUFSIZ], *key = (uint8_t *)&fb.fname;
        char *filename = NULL;
        char *tempfile;
        unsigned int i, lameidx = 0, keylen;
        int ofd;
        uint64_t csize                = 0;
        uint64_t outsize              = 0;
        uint64_t temporary_reserved   = 0;
        bool stream_complete          = false;
        z_stream z;

        if (ctx->engine->maxfiles && scanned >= ctx->engine->maxfiles) {
            cli_dbgmsg("ishield-msi: File limit reached (max: %u)\n", ctx->engine->maxfiles);
            cli_mark_scan_incomplete(ctx, "InstallShield MSI member count exceeds configured scan limits");
            return CL_EMAXFILES;
        }

        if (fmap_readn(map, &fb, off, sizeof(fb)) != sizeof(fb)) {
            cli_dbgmsg("ishield-msi: short read for fileblock\n");
            cli_mark_scan_incomplete(ctx, "InstallShield MSI file record is truncated");
            return CL_EPARSE;
        }

        off += sizeof(fb);
        fb.fname[sizeof(fb.fname) - 1] = '\0';

        csize = le64_to_host(fb.csize);
        if (!CLI_ISCONTAINED_0_TO(map->len, off, csize)) {
            cli_dbgmsg("ishield-msi: next stream is out of file, giving up\n");
            cli_mark_scan_incomplete(ctx, "InstallShield MSI member is outside the containing map");
            return CL_EPARSE;
        }
        if (csize == 0)
            stream_complete = true;

        ret = cli_checklimits("InstallShield MSI", ctx, csize, 0, 0);
        if (ret != CL_SUCCESS) {
            cli_dbgmsg("ishield-msi: refusing partial stream due to scan limits (" STDu64 ")\n", csize);
            if (ret != CL_ETIMEOUT)
                cli_mark_scan_incomplete(ctx, "InstallShield MSI member exceeds configured scan limits");
            return ret;
        }

        keylen = strlen((const char *)key);
        if (!keylen) {
            cli_mark_scan_incomplete(ctx, "InstallShield MSI member has an empty decryption key");
            return CL_EFORMAT;
        }

        filename = cli_safer_strdup((const char *)key);
        if (!filename)
            return CL_EMEM;

        /* FIXMEISHIELD: cleanup the spam below */
        cli_dbgmsg("ishield-msi: File %s (csize: %llx, unk1:%x unk2:%x unk3:%x unk4:%x unk5:%x unk6:%x unk7:%x unk8:%x unk9:%x unk10:%x unk11:%x)\n", key, (long long)csize, fb.unk1, fb.unk2, fb.unk3, fb.unk4, fb.unk5, fb.unk6, fb.unk7, fb.unk8, fb.unk9, fb.unk10, fb.unk11);
        if (!(tempfile = cli_gentemp(ctx->this_layer_tmpdir))) {
            if (NULL != filename) {
                free(filename);
            }
            return CL_EMEM;
        }

        if ((ofd = open(tempfile, O_RDWR | O_CREAT | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR)) < 0) {
            cli_dbgmsg("ishield-msi: failed to create file %s\n", tempfile);
            free(tempfile);
            if (NULL != filename) {
                free(filename);
            }
            return CL_ECREAT;
        }

        for (i = 0; i < keylen; i++) {
            key[i] ^= skey[i & 3];
        }

        memset(&z, 0, sizeof(z));
        if (inflateInit(&z) != Z_OK) {
            cli_mark_scan_incomplete(ctx, "InstallShield MSI decompressor could not be initialized");
            close(ofd);
            if (!ctx->engine->keeptmp)
                (void)cli_unlink(tempfile);
            free(tempfile);
            free(filename);
            return CL_EUNPACK;
        }

        ret = CL_SUCCESS;

        while (csize && ret == CL_SUCCESS && !stream_complete) {
            uint8_t buf2[BUFSIZ];
            z.avail_in = MIN(csize, sizeof(buf2));
            if (fmap_readn(map, buf2, off, z.avail_in) != z.avail_in) {
                cli_dbgmsg("ishield-msi: premature EOS or read fail\n");
                cli_mark_scan_incomplete(ctx, "InstallShield MSI compressed member could not be read completely");
                ret = CL_EREAD;
                break;
            }
            off += z.avail_in;
            for (i = 0; i < z.avail_in; i++, lameidx++) {
                uint8_t c = buf2[i];
                c         = (c >> 4) | (c << 4);
                c ^= key[(lameidx & 0x3ff) % keylen];
                buf2[i] = c;
            }
            csize -= z.avail_in;
            z.next_in = buf2;
            do {
                int inf;
                size_t produced;
                z.avail_out = sizeof(obuf);
                z.next_out  = obuf;
                inf         = inflate(&z, 0);
                if (inf != Z_OK && inf != Z_STREAM_END && inf != Z_BUF_ERROR) {
                    cli_dbgmsg("ishield-msi: bad stream\n");
                    cli_mark_scan_incomplete(ctx, "InstallShield MSI member decompression failed");
                    ret = CL_EUNPACK;
                    break;
                }
                produced = sizeof(obuf) - z.avail_out;
                if (outsize > UINT64_MAX - produced) {
                    cli_mark_scan_incomplete(ctx, "InstallShield MSI member output size overflowed");
                    ret = CL_EMAXSIZE;
                    break;
                }
                ret = cli_checklimits("InstallShield MSI", ctx, outsize + produced, 0, 0);
                if (ret != CL_SUCCESS) {
                    cli_dbgmsg("ishield-msi: refusing partial output due to configured scan limits\n");
                    if (ret != CL_ETIMEOUT)
                        cli_mark_scan_incomplete(ctx, "InstallShield MSI member output exceeds configured scan limits");
                    break;
                }
                if (produced) {
                    if (UINT64_MAX - temporary_reserved < (uint64_t)produced ||
                        cli_scan_reserve_temporary(ctx, (uint64_t)produced) != CL_SUCCESS) {
                        cli_mark_scan_incomplete(ctx, "InstallShield MSI member temporary output exceeds storage limits");
                        ret = CL_ERESOURCE;
                        break;
                    }
                    temporary_reserved += (uint64_t)produced;
                    if (cli_writen(ofd, obuf, produced) != produced) {
                        cli_mark_scan_incomplete(ctx, "InstallShield MSI member temporary output could not be written completely");
                        ret = CL_EWRITE;
                        break;
                    }
                }
                outsize += produced;

                if (inf == Z_STREAM_END) {
                    if (z.avail_in != 0 || csize != 0) {
                        cli_mark_scan_incomplete(ctx, "InstallShield MSI member has trailing compressed data");
                        ret = CL_EFORMAT;
                    } else {
                        stream_complete = true;
                    }
                    break;
                }

                if (inf == Z_BUF_ERROR && produced == 0 && z.avail_in != 0) {
                    cli_mark_scan_incomplete(ctx, "InstallShield MSI decompressor made no progress");
                    ret = CL_EUNPACK;
                    break;
                }
            } while (z.avail_in != 0 || z.avail_out == 0);
        }

        inflateEnd(&z);

        if (ret == CL_SUCCESS && !stream_complete) {
            cli_mark_scan_incomplete(ctx, "InstallShield MSI compressed member ended before stream completion");
            ret = CL_EUNPACK;
        }

        if (ret == CL_SUCCESS) {
            cli_dbgmsg("ishield-msi: extracted to %s\n", tempfile);

            if (lseek(ofd, 0, SEEK_SET) == -1) {
                cli_dbgmsg("ishield-msi: call to lseek() failed\n");
                ret = CL_ESEEK;
            }
            if (ret == CL_SUCCESS)
                ret = cli_magic_scan_desc_type_reserved(ofd, tempfile, ctx, CL_TYPE_ANY, filename,
                                                         LAYER_ATTRIBUTES_NONE);
        }
        if (close(ofd) != 0) {
            cli_mark_scan_incomplete(ctx, "InstallShield MSI member temporary output could not be closed");
            if (ret == CL_SUCCESS || ret == CL_VERIFIED)
                ret = CL_EWRITE;
        }

        if (!ctx->engine->keeptmp) {
            if (cli_unlink(tempfile)) {
                cli_mark_scan_incomplete(ctx, "InstallShield MSI member temporary output could not be removed");
                if (ret == CL_SUCCESS || ret == CL_VERIFIED)
                    ret = CL_EUNLINK;
            }
        }
        free(tempfile);
        if (temporary_reserved)
            cli_scan_release_temporary(ctx, temporary_reserved);

        if (NULL != filename) {
            free(filename);
        }

        if (ret != CL_SUCCESS) {
            return ret;
        }

        scanned++;
    }
    return CL_SUCCESS;
}

struct IS_CABSTUFF {
    struct CABARRAY {
        unsigned int cabno;
        off_t off;
        size_t sz;
    } *cabs;
    off_t hdr;
    size_t hdrsz;
    unsigned int cabcnt;
};

static void md5str(uint8_t *sum);
static cl_error_t is_parse_hdr(cli_ctx *ctx, struct IS_CABSTUFF *c);
static cl_error_t is_extract_cab(cli_ctx *ctx, uint64_t off, uint64_t size, uint64_t csize);

/* Extract the content of older (non-MSI) IS */
cl_error_t cli_scanishield(cli_ctx *ctx, off_t off, size_t sz)
{
    cl_error_t ret = CL_SUCCESS;
    const char *fname, *path, *version, *strsz, *data;
    char *eostr;
    long fsize;
    off_t coff           = off;
    struct IS_CABSTUFF c = {NULL, -1, 0, 0};
    fmap_t *map;
    unsigned fc = 0;
    size_t input_end;

    if (!ctx || !ctx->engine || !ctx->fmap)
        return CL_ENULLARG;
    map = ctx->fmap;

    if (off < 0 || (uint64_t)off > map->len || sz > map->len - (size_t)off) {
        cli_mark_scan_incomplete(ctx, "InstallShield archive range is outside the containing map");
        return CL_EPARSE;
    }
    input_end = (size_t)off + sz;

    while (ret == CL_SUCCESS) {
        fname = fmap_need_offstr(map, coff, 2048);
        if (!fname) {
            if (coff < 0 || (size_t)coff != input_end) {
                cli_mark_scan_incomplete(ctx, "InstallShield metadata ended before a complete file record");
                ret = CL_EPARSE;
            }
            break;
        }
        coff += strlen(fname) + 1;

        path = fmap_need_offstr(map, coff, 2048);
        if (!path) {
            cli_mark_scan_incomplete(ctx, "InstallShield file record ended before its path");
            ret = CL_EPARSE;
            break;
        }
        coff += strlen(path) + 1;

        version = fmap_need_offstr(map, coff, 2048);
        if (!version) {
            cli_mark_scan_incomplete(ctx, "InstallShield file record ended before its version");
            ret = CL_EPARSE;
            break;
        }
        coff += strlen(version) + 1;

        strsz = fmap_need_offstr(map, coff, 2048);
        if (!strsz) {
            cli_mark_scan_incomplete(ctx, "InstallShield file record ended before its size");
            ret = CL_EPARSE;
            break;
        }
        coff += strlen(strsz) + 1;

        data = &strsz[strlen(strsz) + 1];

        fsize = strtol(strsz, &eostr, 10);
        if (fsize < 0 || fsize == LONG_MAX ||
            !*strsz || !eostr || eostr == strsz || *eostr ||
            (unsigned long)fsize >= sz ||
            (size_t)(data - fname) > sz - fsize) {
            cli_mark_scan_incomplete(ctx, "InstallShield file record contained an invalid size or range");
            ret = CL_EPARSE;
            break;
        }

        cli_dbgmsg("ishield: @%lx found file %s (%s) - version %s - size %lu\n", (unsigned long int)coff, fname, path, version, (unsigned long int)fsize);
        if (CL_SUCCESS != cli_matchmeta(ctx, fname, fsize, fsize, 0, fc++, 0)) {
            ret = CL_VIRUS;
            break;
        }

        sz -= (data - fname) + fsize;

        if (!strncasecmp(fname, "data", 4)) {
            long cabno;
            if (!strcasecmp(fname + 4, "1.hdr")) {
                if (c.hdr == -1) {
                    cli_dbgmsg("ishield: added data1.hdr to array\n");
                    c.hdr   = coff;
                    c.hdrsz = fsize;
                    coff += fsize;
                    continue;
                }
                cli_warnmsg("ishield: got multiple header files\n");
            }
            cabno = strtol(fname + 4, &eostr, 10);
            if (cabno > 0 && cabno < 65536 && fname[4] && eostr && eostr != &fname[4] && !strcasecmp(eostr, ".cab")) {
                unsigned int i;
                for (i = 0; i < c.cabcnt && i != c.cabs[i].cabno; i++) {
                }
                if (i == c.cabcnt) {
                    c.cabcnt++;
                    if (!(c.cabs = cli_max_realloc_or_free(c.cabs, sizeof(struct CABARRAY) * c.cabcnt))) {
                        ret = CL_EMEM;
                        break;
                    }
                    cli_dbgmsg("ishield: added data%lu.cab to array\n", cabno);
                    c.cabs[i].cabno = cabno;
                    c.cabs[i].off   = coff;
                    c.cabs[i].sz    = fsize;
                    coff += fsize;
                    continue;
                }
                cli_warnmsg("ishield: got multiple data%lu.cab files\n", cabno);
            }
        }

        fmap_unneed_ptr(map, fname, data - fname);
        ret = is_dump_and_scan(ctx, coff, fsize);
        coff += fsize;
    }

    if ((ret == CL_SUCCESS) &&
        (c.cabcnt || c.hdr != -1)) {

        if (CL_SUCCESS == (ret = is_parse_hdr(ctx, &c))) {
            unsigned int i;
            if (c.hdr != -1) {
                cli_dbgmsg("ishield: scanning data1.hdr\n");
                ret = is_dump_and_scan(ctx, c.hdr, c.hdrsz);
            }
            for (i = 0; i < c.cabcnt && ret == CL_SUCCESS; i++) {
                cli_dbgmsg("ishield: scanning data%u.cab\n", c.cabs[i].cabno);
                ret = is_dump_and_scan(ctx, c.cabs[i].off, c.cabs[i].sz);
            }
        }
    }

    if (c.cabs) {
        free(c.cabs);
    }

    return ret;
}

/* Utility func to scan a fd @ a given offset and size */
static cl_error_t is_dump_and_scan(cli_ctx *ctx, off_t off, size_t fsize)
{
    char *fname;
    const char *buf;
    int ofd;
    cl_error_t ret = CL_SUCCESS;
    uint64_t temporary_reserved;
    fmap_t *map = ctx->fmap;

    if (!fsize) {
        cli_dbgmsg("ishield: skipping empty file\n");
        return CL_SUCCESS;
    }

    if (off < 0 || (uint64_t)off > map->len || fsize > map->len - (size_t)off) {
        cli_mark_scan_incomplete(ctx, "InstallShield embedded file is outside the containing map");
        return CL_EPARSE;
    }

    ret = cli_checklimits("InstallShield", ctx, fsize, 0, 0);
    if (ret != CL_SUCCESS) {
        if (ret != CL_ETIMEOUT)
            cli_mark_scan_incomplete(ctx, "InstallShield embedded file exceeds configured scan limits");
        return ret;
    }

    temporary_reserved = (uint64_t)fsize;
    if (cli_scan_reserve_temporary(ctx, temporary_reserved) != CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, "InstallShield embedded file exceeds temporary storage limits");
        return CL_ERESOURCE;
    }

    if (!(fname = cli_gentemp(ctx->this_layer_tmpdir))) {
        cli_scan_release_temporary(ctx, temporary_reserved);
        return CL_EMEM;
    }

    if ((ofd = open(fname, O_RDWR | O_CREAT | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR)) < 0) {
        cli_errmsg("ishield: failed to create file %s\n", fname);
        free(fname);
        cli_scan_release_temporary(ctx, temporary_reserved);
        return CL_ECREAT;
    }

    while (fsize) {
        size_t rd = MIN(fsize, map->pgsz);
        ret       = cli_checktimelimit(ctx);
        if (ret != CL_SUCCESS)
            break;
        if (!(buf = fmap_need_off_once(map, off, rd))) {
            cli_dbgmsg("ishield: read error\n");
            cli_mark_scan_incomplete(ctx, "InstallShield embedded file could not be read completely");
            ret = CL_EREAD;
            break;
        }
        if (cli_writen(ofd, buf, rd) != rd) {
            cli_mark_scan_incomplete(ctx, "InstallShield embedded file temporary output could not be written completely");
            ret = CL_EWRITE;
            break;
        }
        fsize -= rd;
        off += rd;
    }

    if (!fsize) {
        cli_dbgmsg("ishield: extracted to %s\n", fname);
        if (lseek(ofd, 0, SEEK_SET) == -1) {
            cli_dbgmsg("ishield: call to lseek() failed\n");
            ret = CL_ESEEK;
        }
        if (ret == CL_SUCCESS)
            ret = cli_magic_scan_desc_type_reserved(ofd, fname, ctx, CL_TYPE_ANY, NULL, LAYER_ATTRIBUTES_NONE);
    }

    if (close(ofd) != 0) {
        cli_mark_scan_incomplete(ctx, "InstallShield embedded file temporary output could not be closed");
        if (ret == CL_SUCCESS || ret == CL_VERIFIED)
            ret = CL_EWRITE;
    }

    if (!ctx->engine->keeptmp) {
        if (cli_unlink(fname)) {
            cli_mark_scan_incomplete(ctx, "InstallShield embedded file temporary output could not be removed");
            if (ret == CL_SUCCESS || ret == CL_VERIFIED)
                ret = CL_EUNLINK;
        }
    }

    free(fname);
    cli_scan_release_temporary(ctx, temporary_reserved);
    return ret;
}

/* Process data1.hdr and extracts all the available files from dataX.cab */
static cl_error_t is_parse_hdr(cli_ctx *ctx, struct IS_CABSTUFF *c)
{
    uint32_t h1_data_off, objs_files_cnt, objs_dirs_off;
    size_t off;
    unsigned int i, scanned = 0;
    int ret = CL_SUCCESS;
    char hash[33], *hdr;
    fmap_t *map = ctx->fmap;

    const struct IS_HDR *h1;
    struct IS_OBJECTS *objs;
    /* struct IS_INSTTYPEHDR *typehdr; -- UNUSED */

    if (c->hdr < 0 || !c->hdrsz || !c->cabcnt) {
        cli_dbgmsg("is_parse_hdr: inconsistent hdr, maybe a false match\n");
        cli_mark_scan_incomplete(ctx, "InstallShield header metadata is incomplete");
        return CL_EPARSE;
    }

    if (c->hdr < 0 || (uint64_t)c->hdr > map->len || c->hdrsz > map->len - (size_t)c->hdr) {
        cli_mark_scan_incomplete(ctx, "InstallShield header is outside the containing map");
        return CL_EPARSE;
    }

    /* Only pin the structure currently being read. The old c->hdrsz request
     * could fault an attacker-controlled multi-gigabyte header into memory. */
    if (!(h1 = fmap_need_off(map, (size_t)c->hdr, sizeof(*h1)))) {
        cli_dbgmsg("is_parse_hdr: not enough room for H1\n");
        cli_mark_scan_incomplete(ctx, "InstallShield header is truncated");
        return CL_EPARSE;
    }

    hdr = (char *)h1;
    if (le32_to_host(h1->magic) != 0x28635349) {
        cli_dbgmsg("is_parse_hdr: bad magic. wrong version?\n");
        fmap_unneed_ptr(map, h1, sizeof(*h1));
        cli_mark_scan_incomplete(ctx, "InstallShield header has an invalid magic");
        return CL_EPARSE;
    }

    h1_data_off = le32_to_host(h1->data_off);
    if (h1_data_off > c->hdrsz || sizeof(*objs) > c->hdrsz - h1_data_off) {
        fmap_unneed_ptr(map, h1, sizeof(*h1));
        cli_mark_scan_incomplete(ctx, "InstallShield object table is outside the header");
        return CL_EPARSE;
    }
    objs = (struct IS_OBJECTS *)fmap_need_ptr(map, hdr + h1_data_off, sizeof(*objs));
    if (!objs) {
        cli_dbgmsg("is_parse_hdr: not enough room for OBJECTS\n");
        fmap_unneed_ptr(map, h1, sizeof(*h1));
        cli_mark_scan_incomplete(ctx, "InstallShield object table could not be read");
        return CL_EREAD;
    }

    cli_dbgmsg("is_parse_hdr: magic %x, unk1 %x, unk2 %x, data_off %x, data_sz %x\n",
               h1->magic, h1->unk1, h1->unk2, h1_data_off, h1->data_sz);

    fmap_unneed_ptr(map, h1, sizeof(*h1));

    /*     cli_errmsg("COMPONENTS\n"); */
    /*     off = le32_to_host(objs->comps_off) + h1_data_off; */
    /*     for(i=1;  ; i++) { */
    /* 	struct IS_COMPONENT *cmp = (struct IS_COMPONENT *)(hdr + off); */
    /* 	if(!CLI_ISCONTAINED(hdr, c->hdrsz, ((char *)cmp), sizeof(*cmp))) { */
    /* 	    cli_dbgmsg("is_extract: not enough room for COMPONENT\n"); */
    /* 	    free(hdr); */
    /* 	    return CL_SUCCESS; */
    /* 	} */
    /* 	cli_errmsg("%06u\t%s\n", i, &hdr[le32_to_host(cmp->str_name_off) + h1_data_off]); */
    /* 	spam_strarray(hdr, h1_data_off + cmp->sub_comp_offs_array, h1_data_off, cmp->sub_comp_cnt); */
    /* 	if(!cmp->next_comp_off) break; */
    /* 	off = le32_to_host(cmp->next_comp_off) + h1_data_off; */
    /*     } */

    /*     cli_errmsg("DIRECTORIES (%u)", le32_to_host(objs->dirs_cnt)); */
    objs_dirs_off = le32_to_host(objs->dirs_off);
    /*     spam_strarray(hdr, h1_data_off + objs_dirs_off, h1_data_off + objs_dirs_off, objs->dirs_cnt); */

    /*     typehdr = (struct INSTTYPEHDR *)&hdr[h1_data_off + le32_to_host(objs->insttype_off)]; */
    /*     printf("INSTTYPES (unk1: %d)\n-----------\n", typehdr->unk1); */
    /*     off = typehdr->off + h1_data_off; */
    /*     for(i=1; i<=typehdr->cnt; i++) { */
    /* 	uint32_t x = *(uint32_t *)(&hdr[off]); */
    /* 	struct INSTTYPEITEM *item = (struct INSTTYPEITEM *)&hdr[x + h1_data_off]; */
    /* 	printf("%06u\t%s\t aka %s\taka %s\n", i, &hdr[item->str_name1_off + h1_data_off], &hdr[item->str_name2_off + h1_data_off], &hdr[item->str_name3_off + h1_data_off]); */
    /* 	printf("components:\n"); */
    /* 	spam_strarray(hdr, h1_data_off + item->off, h1_data_off, item->cnt); */
    /* 	off+=4; */
    /*     } */

    /* dir = &hdr[*(uint32_t *)(&hdr[h1_data_off + objs_dirs_off + 4 * file->dir_id]) + h1_data_off + objs_dirs_off] */

    objs_files_cnt = le32_to_host(objs->files_cnt);
    {
        uint64_t file_table_off = (uint64_t)h1_data_off + objs_dirs_off + le32_to_host(objs->dir_sz2);
        uint64_t file_table_len = (uint64_t)objs_files_cnt * sizeof(struct IS_FILEITEM);

        if (file_table_off > c->hdrsz || file_table_len > c->hdrsz - file_table_off) {
            fmap_unneed_ptr(map, objs, sizeof(*objs));
            cli_mark_scan_incomplete(ctx, "InstallShield file table is outside the header");
            return CL_EPARSE;
        }
        off = (size_t)file_table_off;
    }
    fmap_unneed_ptr(map, objs, sizeof(*objs));
    for (i = 0; i < objs_files_cnt; i++) {
        struct IS_FILEITEM *file = (struct IS_FILEITEM *)fmap_need_off(map, c->hdr + off, sizeof(*file));

        if (file) {
            const char *emptyname = "", *dir_name = emptyname, *file_name = emptyname;
            uint64_t dir_rel  = (uint64_t)h1_data_off + objs_dirs_off + 4ULL * le32_to_host(file->dir_id); /* rel off of dir entry from array of rel ptrs */
            uint64_t file_rel = (uint64_t)objs_dirs_off + h1_data_off + le32_to_host(file->str_name_off);  /* rel off of fname */
            uint64_t file_stream_off, file_size, file_csize;
            uint16_t cabno;

            memcpy(hash, file->md5, 16);
            md5str((uint8_t *)hash);
            if (dir_rel <= c->hdrsz && 4 <= c->hdrsz - dir_rel &&
                fmap_need_ptr_once(map, &hdr[(size_t)dir_rel], 4)) {
                uint64_t resolved_dir_rel = (uint64_t)cli_readint32(&hdr[(size_t)dir_rel]) + h1_data_off + objs_dirs_off;

                if (resolved_dir_rel < c->hdrsz &&
                    fmap_need_str(map, &hdr[(size_t)resolved_dir_rel], MIN((size_t)4096, c->hdrsz - (size_t)resolved_dir_rel))) {
                    dir_rel  = resolved_dir_rel;
                    dir_name = &hdr[(size_t)dir_rel];
                }
            }
            if (file_rel < c->hdrsz &&
                fmap_need_str(map, &hdr[(size_t)file_rel], MIN((size_t)4096, c->hdrsz - (size_t)file_rel)))
                file_name = &hdr[(size_t)file_rel];

            file_stream_off = le64_to_host(file->stream_off);
            file_size       = le64_to_host(file->size);
            file_csize      = le64_to_host(file->csize);
            cabno           = le16_to_host(file->datafile_id);

            switch (le16_to_host(file->flags)) {
                case 0:
                case 8:
                    /* FIXMEISHIELD: for FS scan ? */
                    cli_dbgmsg("is_parse_hdr: skipped external file:%s\\%s (size: %llu csize: %llu md5:%s)\n",
                               dir_name,
                               file_name,
                               (long long)file_size, (long long)file_csize, hash);
                    break;
                case 4:
                case 0xc:
                    cli_dbgmsg("is_parse_hdr: file %s\\%s (size: %llu csize: %llu md5:%s offset:%llx (data%u.cab) 13:%x 14:%x 15:%x)\n",
                               dir_name,
                               file_name,
                               (long long)file_size, (long long)file_csize, hash, (long long)file_stream_off,
                               cabno, file->unk13, file->unk14, file->unk15);
                    if (file->flag_has_dup & 1)
                        cli_dbgmsg("is_parse_hdr: not scanned (dup)\n");
                    else {
                        if (file_size) {
                            unsigned int j;
                            cl_error_t cabret = CL_SUCCESS;
                            cl_error_t limitret;

                            limitret = cli_checklimits("InstallShield", ctx, 0, 0, 0);
                            if (limitret != CL_SUCCESS) {
                                if (limitret != CL_ETIMEOUT)
                                    cli_mark_scan_incomplete(ctx, "InstallShield member exceeds configured scan limits");
                                if (file_name != emptyname)
                                    fmap_unneed_ptr(map, (void *)file_name, strlen(file_name) + 1);
                                if (dir_name != emptyname)
                                    fmap_unneed_ptr(map, (void *)dir_name, strlen(dir_name) + 1);
                                return limitret;
                            }

                            for (j = 0; j < c->cabcnt && c->cabs[j].cabno != cabno; j++) {
                            }
                            if (j != c->cabcnt) {
                                uint64_t member_off;

                                if (c->cabs[j].off < 0 || file_stream_off > UINT64_MAX - (uint64_t)c->cabs[j].off) {
                                    cli_mark_scan_incomplete(ctx, "InstallShield CAB member offset overflowed");
                                    cabret = CL_EPARSE;
                                } else {
                                    member_off = file_stream_off + (uint64_t)c->cabs[j].off;
                                }

                                if (cabret == CL_SUCCESS &&
                                    CLI_ISCONTAINED(c->cabs[j].off, c->cabs[j].sz, member_off, file_csize)) {
                                    if (ctx->engine->maxfiles && scanned >= ctx->engine->maxfiles) {
                                        cli_dbgmsg("is_parse_hdr: File limit reached (max: %u)\n", ctx->engine->maxfiles);
                                        cli_mark_scan_incomplete(ctx, "InstallShield CAB member count exceeds configured scan limits");
                                        if (file_name != emptyname)
                                            fmap_unneed_ptr(map, (void *)file_name, strlen(file_name) + 1);
                                        if (dir_name != emptyname)
                                            fmap_unneed_ptr(map, (void *)dir_name, strlen(dir_name) + 1);
                                        return CL_EMAXFILES;
                                    }
                                    scanned++;
                                    cabret = is_extract_cab(ctx, member_off, file_size, file_csize);
                                } else if (cabret == CL_SUCCESS) {
                                    cli_dbgmsg("is_parse_hdr: stream out of file\n");
                                    cli_mark_scan_incomplete(ctx, "InstallShield CAB member is outside its data file");
                                    cabret = CL_EPARSE;
                                }
                            } else {
                                cli_dbgmsg("is_parse_hdr: data%u.cab not available\n", cabno);
                                cli_mark_scan_incomplete(ctx, "InstallShield CAB data file is unavailable");
                                cabret = CL_EPARSE;
                            }
                            if (cabret != CL_SUCCESS) {
                                if (file_name != emptyname)
                                    fmap_unneed_ptr(map, (void *)file_name, strlen(file_name) + 1);
                                if (dir_name != emptyname)
                                    fmap_unneed_ptr(map, (void *)dir_name, strlen(dir_name) + 1);
                                return cabret;
                            }
                        } else {
                            cli_dbgmsg("is_parse_hdr: skipped empty file\n");
                        }
                    }
                    break;
                default:
                    cli_dbgmsg("is_parse_hdr: skipped unknown file entry %u\n", i);
                    ret = CL_EPARSE;
            }
            if (file_name != emptyname)
                fmap_unneed_ptr(map, (void *)file_name, strlen(file_name) + 1);
            if (dir_name != emptyname)
                fmap_unneed_ptr(map, (void *)dir_name, strlen(dir_name) + 1);
            fmap_unneed_ptr(map, file, sizeof(*file));
            /*
             * Keep walking after an unsupported record. Remember the parse
             * error and mark it incomplete after the member walk so a virus
             * in a subsequent, supported CAB record can still take
             * precedence.
             */
        } else {
            cli_dbgmsg("is_parse_hdr: FILEITEM out of bounds\n");
            cli_mark_scan_incomplete(ctx, "InstallShield file record could not be read");
            return CL_EREAD;
        }
        off += sizeof(*file);
    }
    if (ret != CL_SUCCESS)
        cli_mark_scan_incomplete(ctx, "InstallShield file record uses an unsupported storage mode");
    return ret;
}

static void md5str(uint8_t *sum)
{
    int i;
    for (i = 15; i >= 0; i--) {
        uint8_t lo = (sum[i] & 0xf), hi = (sum[i] >> 4);
        lo += '0' + (lo > 9) * '\'';
        hi += '0' + (hi > 9) * '\'';
        sum[i * 2 + 1] = lo;
        sum[i * 2]     = hi;
    }
    sum[32] = '\0';
}

#define IS_CABBUFSZ 65536

static cl_error_t is_extract_cab(cli_ctx *ctx, uint64_t off, uint64_t size, uint64_t csize)
{
    cl_error_t ret = CL_SUCCESS;
    const uint8_t *inbuf;
    uint8_t *outbuf;
    char *tempfile;
    int ofd;
    z_stream z;
    uint64_t outsz             = 0;
    uint64_t temporary_reserved = 0;
    bool extraction_complete   = false;
    fmap_t *map              = ctx->fmap;

    if (!(outbuf = malloc(IS_CABBUFSZ))) {
        cli_errmsg("is_extract_cab: Unable to allocate memory for outbuf\n");
        return CL_EMEM;
    }

    ret = cli_checklimits("InstallShield", ctx, size, 0, 0);
    if (ret != CL_SUCCESS) {
        if (ret != CL_ETIMEOUT)
            cli_mark_scan_incomplete(ctx, "InstallShield CAB output exceeds configured scan limits");
        free(outbuf);
        return ret;
    }
    if (cli_scan_reserve_temporary(ctx, size) != CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, "InstallShield CAB output exceeds temporary storage limits");
        free(outbuf);
        return CL_ERESOURCE;
    }
    temporary_reserved = size;

    if (!(tempfile = cli_gentemp(ctx->this_layer_tmpdir))) {
        cli_scan_release_temporary(ctx, temporary_reserved);
        free(outbuf);
        return CL_EMEM;
    }
    if ((ofd = open(tempfile, O_RDWR | O_CREAT | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR)) < 0) {
        cli_errmsg("is_extract_cab: failed to create file %s\n", tempfile);
        free(tempfile);
        free(outbuf);
        cli_scan_release_temporary(ctx, temporary_reserved);
        return CL_ECREAT;
    }

    while (csize) {
        uint16_t chunksz;
        bool chunk_complete = false;

        ret = cli_checktimelimit(ctx);
        if (ret != CL_SUCCESS)
            break;
        if (csize < 2) {
            cli_dbgmsg("is_extract_cab: no room for chunk size\n");
            cli_mark_scan_incomplete(ctx, "InstallShield CAB chunk header is truncated");
            ret = CL_EPARSE;
            break;
        }
        csize -= 2;
        if (!(inbuf = fmap_need_off_once(map, off, 2))) {
            cli_dbgmsg("is_extract_cab: short read for chunk size\n");
            cli_mark_scan_incomplete(ctx, "InstallShield CAB chunk header could not be read");
            ret = CL_EREAD;
            break;
        }
        off += 2;
        chunksz = inbuf[0] | (inbuf[1] << 8);
        if (!chunksz) {
            cli_dbgmsg("is_extract_cab: zero sized chunk\n");
            continue;
        }
        if (csize < chunksz) {
            cli_dbgmsg("is_extract_cab: chunk is bigger than csize\n");
            cli_mark_scan_incomplete(ctx, "InstallShield CAB chunk exceeds its member boundary");
            ret = CL_EPARSE;
            break;
        }
        csize -= chunksz;
        if (!(inbuf = fmap_need_off_once(map, off, chunksz))) {
            cli_dbgmsg("is_extract_cab: short read for chunk\n");
            cli_mark_scan_incomplete(ctx, "InstallShield CAB chunk could not be read completely");
            ret = CL_EREAD;
            break;
        }
        off += chunksz;
        memset(&z, 0, sizeof(z));
        if (inflateInit2(&z, -MAX_WBITS) != Z_OK) {
            cli_mark_scan_incomplete(ctx, "InstallShield CAB decompressor could not be initialized");
            ret = CL_EUNPACK;
            break;
        }
        z.next_in  = (uint8_t *)inbuf;
        z.avail_in = chunksz;
        while (ret == CL_SUCCESS) {
            int zret;
            z.next_out  = outbuf;
            z.avail_out = IS_CABBUFSZ;
            zret        = inflate(&z, 0);
            if (zret == Z_OK || zret == Z_STREAM_END || zret == Z_BUF_ERROR) {
                unsigned int umpd = IS_CABBUFSZ - z.avail_out;
                uint64_t writelen = umpd;
                cl_error_t limitret;

                if (outsz > UINT64_MAX - writelen) {
                    cli_dbgmsg("ishield_extract_cab: output size overflow guard hit\n");
                    cli_mark_scan_incomplete(ctx, "InstallShield CAB output size overflowed");
                    ret = CL_EMAXSIZE;
                    break;
                }

                limitret = cli_checklimits("InstallShield", ctx, outsz + writelen, 0, 0);
                if (limitret != CL_SUCCESS) {
                    if (limitret != CL_ETIMEOUT)
                        cli_mark_scan_incomplete(ctx, "InstallShield CAB output exceeds configured scan limits");
                    ret = limitret;
                    break;
                }

                if (outsz > size || writelen > size - outsz) {
                    cli_mark_scan_incomplete(ctx, "InstallShield CAB output exceeds declared member size");
                    ret = CL_EFORMAT;
                    break;
                }

                if (writelen && cli_writen(ofd, outbuf, writelen) != writelen) {
                    cli_mark_scan_incomplete(ctx, "InstallShield CAB temporary output could not be written completely");
                    ret = CL_EWRITE;
                    break;
                }
                outsz += writelen;

                if (zret == Z_STREAM_END) {
                    if (z.avail_in != 0) {
                        cli_mark_scan_incomplete(ctx, "InstallShield CAB chunk has trailing compressed data");
                        ret = CL_EFORMAT;
                    } else {
                        chunk_complete = true;
                    }
                    break;
                }

                if (zret == Z_BUF_ERROR && umpd == 0) {
                    cli_mark_scan_incomplete(ctx, "InstallShield CAB decompressor made no progress");
                    ret = CL_EUNPACK;
                    break;
                }
                continue;
            }
            cli_dbgmsg("is_extract_cab: file decompression failed with %d\n", zret);
            cli_mark_scan_incomplete(ctx, "InstallShield CAB member decompression failed");
            ret = CL_EUNPACK;
            break;
        }
        inflateEnd(&z);
        if (!chunk_complete)
            break;
    }

    if (ret == CL_SUCCESS && csize == 0)
        extraction_complete = true;

    free(outbuf);
    if (extraction_complete && outsz != size) {
        cli_dbgmsg("is_extract_cab: extracted %llu bytes to %s, expected %llu.\n", (long long)outsz, tempfile, (long long)size);
        cli_mark_scan_incomplete(ctx, "InstallShield CAB output size disagrees with member metadata");
        ret = CL_EFORMAT;
    }

    if (extraction_complete && ret == CL_SUCCESS) {
        cli_dbgmsg("is_extract_cab: extracted to %s\n", tempfile);
        if (lseek(ofd, 0, SEEK_SET) == -1) {
            cli_dbgmsg("is_extract_cab: call to lseek() failed\n");
            ret = CL_ESEEK;
        }
        if (ret == CL_SUCCESS)
            ret = cli_magic_scan_desc_type_reserved(ofd, tempfile, ctx, CL_TYPE_ANY, NULL, LAYER_ATTRIBUTES_NONE);
    }

    if (close(ofd) != 0) {
        cli_mark_scan_incomplete(ctx, "InstallShield CAB temporary output could not be closed");
        if (ret == CL_SUCCESS || ret == CL_VERIFIED)
            ret = CL_EWRITE;
    }
    if (!ctx->engine->keeptmp) {
        if (cli_unlink(tempfile)) {
            cli_mark_scan_incomplete(ctx, "InstallShield CAB temporary output could not be removed");
            if (ret == CL_SUCCESS || ret == CL_VERIFIED)
                ret = CL_EUNLINK;
        }
    }
    free(tempfile);
    cli_scan_release_temporary(ctx, temporary_reserved);
    return ret;
}
