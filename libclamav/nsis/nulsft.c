/*
 *  Copyright (C) 2007-2008 Sourcefire Inc.
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

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "clamav.h"
#include "others.h"
#include "nsis_bzlib.h"
/* #include "zlib.h" */
#include "nsis_zlib.h"
#include "lzma_iface.h"
#include "matcher.h"
#include "scanners.h"
#include "nulsft.h" /* SHUT UP GCC -Wextra */
#include "fmap.h"

#define EC32(x) le32_to_host(x)
#define NSIS_CONTIGUOUS_INPUT_MAX CLI_MAX_ALLOCATION

enum {
    COMP_NOT_DETECTED,
    COMP_BZIP2,
    COMP_LZMA,
    COMP_ZLIB,
    COMP_NOCOMP
};

struct nsis_st {
    size_t curpos;
    int ofd;
    int opened;
    size_t off;
    size_t fullsz;
    char *dir;
    uint32_t asz;
    uint32_t hsz;
    uint32_t fno;
    uint8_t comp;
    uint8_t solid;
    uint8_t freecomp;
    uint8_t eof;
    struct stream_state nsis;
    nsis_bzstream bz;
    struct CLI_LZMA lz;
    /*   z_stream z; */
    nsis_z_stream z;
    const unsigned char *freeme;
    fmap_t *map;
    char ofn[1024];
};

#define LINESTR(x) #x
#define LINESTR2(x) LINESTR(x)
#define __AT__ " at "__FILE__ \
               ":" LINESTR2(__LINE__)

static int nsis_init(struct nsis_st *n)
{
    switch (n->comp) {
        case COMP_BZIP2:
            memset(&n->bz, 0, sizeof(nsis_bzstream));
            if (nsis_BZ2_bzDecompressInit(&n->bz, 0, 0) != BZ_OK)
                return CL_EUNPACK;
            n->freecomp = 1;
            break;
        case COMP_LZMA:
            memset(&n->lz, 0, sizeof(struct CLI_LZMA));
            if (cli_LzmaInit(&n->lz, 0xffffffffffffffffULL) != LZMA_RESULT_OK)
                return CL_EUNPACK;
            n->freecomp = 1;
            break;
        case COMP_ZLIB:
            memset(&n->z, 0, sizeof(z_stream));
            /*     inflateInit2(&n->z, -MAX_WBITS); */
            /*     n->freecomp=1; */
            nsis_inflateInit(&n->z);
            n->freecomp = 0;
    }
    return CL_SUCCESS;
}

static void nsis_shutdown(struct nsis_st *n)
{
    if (!n->freecomp)
        return;

    switch (n->comp) {
        case COMP_BZIP2:
            nsis_BZ2_bzDecompressEnd(&n->bz);
            break;
        case COMP_LZMA:
            cli_LzmaShutdown(&n->lz);
            break;
        case COMP_ZLIB:
            /*     inflateEnd(&n->z); */
            break;
    }

    n->freecomp = 0;
}

static int nsis_decomp(struct nsis_st *n)
{
    int ret = CL_EFORMAT;
    switch (n->comp) {
        case COMP_BZIP2:
            n->bz.avail_in  = n->nsis.avail_in;
            n->bz.next_in   = n->nsis.next_in;
            n->bz.avail_out = n->nsis.avail_out;
            n->bz.next_out  = n->nsis.next_out;
            switch (nsis_BZ2_bzDecompress(&n->bz)) {
                case BZ_OK:
                    ret = CL_SUCCESS;
                    break;
                case BZ_STREAM_END:
                    ret = CL_BREAK;
            }
            n->nsis.avail_in  = n->bz.avail_in;
            n->nsis.next_in   = n->bz.next_in;
            n->nsis.avail_out = n->bz.avail_out;
            n->nsis.next_out  = n->bz.next_out;
            break;
        case COMP_LZMA:
            n->lz.avail_in  = n->nsis.avail_in;
            n->lz.next_in   = n->nsis.next_in;
            n->lz.avail_out = n->nsis.avail_out;
            n->lz.next_out  = n->nsis.next_out;
            switch (cli_LzmaDecode(&n->lz)) {
                case LZMA_RESULT_OK:
                    ret = CL_SUCCESS;
                    break;
                case LZMA_STREAM_END:
                    ret = CL_BREAK;
            }
            n->nsis.avail_in  = n->lz.avail_in;
            n->nsis.next_in   = n->lz.next_in;
            n->nsis.avail_out = n->lz.avail_out;
            n->nsis.next_out  = n->lz.next_out;
            break;
        case COMP_ZLIB:
            n->z.avail_in  = n->nsis.avail_in;
            n->z.next_in   = n->nsis.next_in;
            n->z.avail_out = n->nsis.avail_out;
            n->z.next_out  = n->nsis.next_out;
            /*  switch (inflate(&n->z, Z_NO_FLUSH)) { */
            switch (nsis_inflate(&n->z)) {
                case Z_OK:
                    ret = CL_SUCCESS;
                    break;
                case Z_STREAM_END:
                    ret = CL_BREAK;
            }
            n->nsis.avail_in  = n->z.avail_in;
            n->nsis.next_in   = n->z.next_in;
            n->nsis.avail_out = n->z.avail_out;
            n->nsis.next_out  = n->z.next_out;
            break;
    }
    return ret;
}

static int nsis_unpack_next(struct nsis_st *n, cli_ctx *ctx)
{
    const unsigned char *ibuf;
    uint32_t size, loops;
    uint64_t total_out = 0;
    int ret, gotsome = 0;
    unsigned char obuf[BUFSIZ];

    if (n->eof) {
        cli_dbgmsg("NSIS: extraction complete\n");
        return CL_BREAK;
    }

    if ((ret = cli_checklimits("NSIS", ctx, 0, 0, 0)) != CL_CLEAN)
        return ret;

    if (n->fno)
        snprintf(n->ofn, 1023, "%s" PATHSEP "content.%.3u", n->dir, n->fno);
    else
        snprintf(n->ofn, 1023, "%s" PATHSEP "headers", n->dir);

    n->fno++;
    n->opened = 0;

    if (!n->solid) {
        if (n->asz == 0 || n->asz == 4) {
            cli_dbgmsg("NSIS: reached archive trailer - extraction complete\n");
            return CL_BREAK;
        }
        if (n->asz < 4) {
            cli_mark_scan_incomplete(ctx, "NSIS archive trailer is truncated");
            return CL_EFORMAT;
        }
        if (fmap_readn(n->map, &size, n->curpos, 4) != 4) {
            cli_mark_scan_incomplete(ctx, "NSIS member size field is truncated");
            return CL_EREAD;
        }
        n->curpos += 4;
        loops = EC32(size);
        if (!(size = (loops & ~0x80000000))) {
            cli_dbgmsg("NSIS: empty file found\n");
            return CL_SUCCESS;
        }
        if (n->asz < 4 || size > n->asz - 4) {
            cli_dbgmsg("NSIS: next file is outside the archive\n");
            cli_mark_scan_incomplete(ctx, "NSIS member extends outside the archive");
            return CL_EFORMAT;
        }

        n->asz -= size + 4;

        if ((ret = cli_checklimits("NSIS", ctx, size, 0, 0)) != CL_CLEAN) {
            cli_mark_scan_incomplete(ctx, "NSIS member exceeds configured scan limits");
            return ret;
        }
        if (size > NSIS_CONTIGUOUS_INPUT_MAX) {
            cli_mark_scan_incomplete(ctx, "NSIS non-solid member exceeds the bounded contiguous decoder input");
            return CL_EMAXSIZE;
        }
        if (!(ibuf = fmap_need_off_once(n->map, n->curpos, size))) {
            cli_dbgmsg("NSIS: cannot read %u bytes"__AT__
                       "\n",
                       size);
            cli_mark_scan_incomplete(ctx, "NSIS member could not be read completely");
            return CL_EREAD;
        }
        if ((n->ofd = open(n->ofn, O_RDWR | O_CREAT | O_TRUNC | O_BINARY, 0600)) == -1) {
            cli_errmsg("NSIS: unable to create output file %s - aborting.\n", n->ofn);
            return CL_ECREAT;
        }
        n->opened = 1;
        n->curpos += size;
        if (loops == size) {

            if (cli_writen(n->ofd, ibuf, size) != size) {
                cli_dbgmsg("NSIS: cannot write output file"__AT__
                           "\n");
                close(n->ofd);
                return CL_EWRITE;
            }
        } else {
            if ((ret = nsis_init(n)) != CL_SUCCESS) {
                cli_dbgmsg("NSIS: decompressor init failed"__AT__
                           "\n");
                close(n->ofd);
                return ret;
            }

            n->nsis.avail_in  = size;
            n->nsis.next_in   = (void *)ibuf;
            n->nsis.next_out  = obuf;
            n->nsis.avail_out = BUFSIZ;
            loops             = 0;

            while ((ret = nsis_decomp(n)) == CL_SUCCESS) {
                if ((size = n->nsis.next_out - obuf) > 0) {
                    gotsome = 1;
                    if (size > UINT64_MAX - total_out) {
                        cli_mark_scan_incomplete(ctx, "NSIS expanded member size overflowed");
                        close(n->ofd);
                        nsis_shutdown(n);
                        return CL_EFORMAT;
                    }
                    total_out += size;
                    if ((ret = cli_checklimits("NSIS", ctx, total_out, 0, 0)) != CL_CLEAN) {
                        cli_mark_scan_incomplete(ctx, "NSIS expanded member exceeds configured scan limits");
                        close(n->ofd);
                        nsis_shutdown(n);
                        return ret;
                    }
                    if (cli_writen(n->ofd, obuf, size) != size) {
                        cli_dbgmsg("NSIS: cannot write output file"__AT__
                                   "\n");
                        close(n->ofd);
                        nsis_shutdown(n);
                        return CL_EWRITE;
                    }
                    n->nsis.next_out  = obuf;
                    n->nsis.avail_out = BUFSIZ;
                    loops             = 0;
                } else if (++loops > 20) {
                    cli_dbgmsg("NSIS: xs looping, breaking out"__AT__
                               "\n");
                    ret = CL_EFORMAT;
                    break;
                }
            }

            {
                int stream_ret = ret;

            nsis_shutdown(n);

            if ((n->nsis.next_out - obuf) > 0) {
                size_t tail = (size_t)(n->nsis.next_out - obuf);
                gotsome = 1;
                if (tail > UINT64_MAX - total_out) {
                    cli_mark_scan_incomplete(ctx, "NSIS expanded member size overflowed");
                    close(n->ofd);
                    return CL_EFORMAT;
                }
                total_out += tail;
                int limit_ret = cli_checklimits("NSIS", ctx, total_out, 0, 0);
                if (limit_ret != CL_CLEAN) {
                    cli_mark_scan_incomplete(ctx, "NSIS expanded member exceeds configured scan limits");
                    close(n->ofd);
                    return limit_ret;
                }
                if (cli_writen(n->ofd, obuf, tail) != tail) {
                    cli_dbgmsg("NSIS: cannot write output file"__AT__
                               "\n");
                    close(n->ofd);
                    return CL_EWRITE;
                }
            }

            if (stream_ret != CL_SUCCESS && stream_ret != CL_BREAK) {
                cli_dbgmsg("NSIS: bad stream"__AT__
                           "\n");
                cli_mark_scan_incomplete(ctx, gotsome ? "NSIS decompression produced only a partial member" : "NSIS member decompression failed");
                close(n->ofd);
                return stream_ret;
            }
            }
        }

        return CL_SUCCESS;

    } else {
        if (!n->freeme) {
            if (n->asz > NSIS_CONTIGUOUS_INPUT_MAX) {
                cli_mark_scan_incomplete(ctx, "NSIS solid archive exceeds the bounded contiguous decoder input");
                return CL_EMAXSIZE;
            }
            if ((ret = nsis_init(n)) != CL_SUCCESS) {
                cli_dbgmsg("NSIS: decompressor init failed\n");
                return ret;
            }
            if (!(n->freeme = fmap_need_off_once(n->map, n->curpos, n->asz))) {
                cli_dbgmsg("NSIS: cannot read %u bytes"__AT__
                           "\n",
                           n->asz);
                cli_mark_scan_incomplete(ctx, "NSIS solid archive could not be read completely");
                return CL_EREAD;
            }
            n->nsis.next_in  = (void *)n->freeme;
            n->nsis.avail_in = n->asz;
        }

        if (n->nsis.avail_in <= 4) {
            cli_dbgmsg("NSIS: extraction complete\n");
            return CL_BREAK;
        }
        n->nsis.next_out  = obuf;
        n->nsis.avail_out = 4;
        loops             = 0;

        while ((ret = nsis_decomp(n)) == CL_SUCCESS) {
            if (n->nsis.next_out - obuf == 4) break;
            if (++loops > 20) {
                cli_dbgmsg("NSIS: xs looping, breaking out"__AT__
                           "\n");
                ret = CL_BREAK;
                break;
            }
        }

        if (ret != CL_SUCCESS) {
            cli_dbgmsg("NSIS: bad stream"__AT__
                       "\n");
            cli_mark_scan_incomplete(ctx, "NSIS solid member header decompression was incomplete");
            return CL_EFORMAT;
        }

        size = cli_readint32(obuf);
        if ((ret = cli_checklimits("NSIS", ctx, size, 0, 0)) != CL_CLEAN) {
            cli_mark_scan_incomplete(ctx, "NSIS solid member exceeds configured scan limits");
            return ret;
        }

        if (size == 0) {
            cli_dbgmsg("NSIS: Empty file found.\n");
            return CL_SUCCESS;
        }

        n->nsis.next_out  = obuf;
        n->nsis.avail_out = MIN(BUFSIZ, size);
        loops             = 0;

        if ((n->ofd = open(n->ofn, O_RDWR | O_CREAT | O_TRUNC | O_BINARY, 0600)) == -1) {
            cli_errmsg("NSIS: unable to create output file %s - aborting.\n", n->ofn);
            return CL_ECREAT;
        }
        n->opened = 1;

        while (size && (ret = nsis_decomp(n)) == CL_SUCCESS) {
            unsigned int wsz;
            if ((wsz = n->nsis.next_out - obuf) > 0) {
                gotsome = 1;
                if (cli_writen(n->ofd, obuf, wsz) != wsz) {
                    cli_dbgmsg("NSIS: cannot write output file"__AT__
                               "\n");
                    close(n->ofd);
                    return CL_EWRITE;
                }
                size -= wsz;
                loops             = 0;
                n->nsis.next_out  = obuf;
                n->nsis.avail_out = MIN(size, BUFSIZ);
            } else if (++loops > 20) {
                cli_dbgmsg("NSIS: xs looping, breaking out"__AT__
                           "\n");
                ret = CL_EFORMAT;
                break;
            }
        }

        if ((n->nsis.next_out - obuf) > 0) {
            size_t tail = (size_t)(n->nsis.next_out - obuf);
            gotsome = 1;
            if (tail > size) {
                cli_mark_scan_incomplete(ctx, "NSIS solid decoder produced more data than declared");
                close(n->ofd);
                return CL_EFORMAT;
            }
            size -= (uint32_t)tail;
            if (cli_writen(n->ofd, obuf, tail) != tail) {
                cli_dbgmsg("NSIS: cannot write output file"__AT__
                           "\n");
                close(n->ofd);
                return CL_EWRITE;
            }
        }

        if (ret == CL_EFORMAT || size != 0) {
            cli_dbgmsg("NSIS: bad stream"__AT__
                       "\n");
            cli_mark_scan_incomplete(ctx, gotsome ? "NSIS solid decompression produced only a partial member" : "NSIS solid member decompression failed");
            close(n->ofd);
            return CL_EFORMAT;
        }

        if (ret == CL_BREAK) {
            n->eof = 1;
        } else if (ret != CL_SUCCESS) {
            cli_dbgmsg("NSIS: bad stream"__AT__
                       "\n");
            close(n->ofd);
            return CL_EFORMAT;
        }
        return CL_SUCCESS;
    }
}

static uint8_t nsis_detcomp(const char *b)
{
    if (*b == '1') return COMP_BZIP2;
    if ((cli_readint32(b) & ~0x80000000) == 0x5d) return COMP_LZMA;
    return COMP_ZLIB;
}

static int nsis_headers(struct nsis_st *n, cli_ctx *ctx)
{
    const char *buf;
    size_t pos;
    int i;
    uint8_t comps[] = {0, 0, 0, 0}, trunc = 0;

    if (n->off > n->map->len || n->map->len - n->off < 0x1c) {
        cli_mark_scan_incomplete(ctx, "NSIS header is outside the input map");
        return CL_EREAD;
    }
    if (!(buf = fmap_need_off_once(n->map, n->off, 0x1c)))
        return CL_EREAD;

    n->hsz    = (uint32_t)cli_readint32(buf + 0x14);
    n->asz    = (uint32_t)cli_readint32(buf + 0x18);
    n->fullsz = n->map->len;

    cli_dbgmsg("NSIS: Header info - Flags=%x, Header size=%x, Archive size=%x\n", cli_readint32(buf), n->hsz, n->asz);

    if (n->asz < 0x1c) {
        cli_mark_scan_incomplete(ctx, "NSIS archive size is shorter than its header");
        return CL_EFORMAT;
    }
    if (n->fullsz - n->off < n->asz) {
        cli_dbgmsg("NSIS: Possibly truncated file\n");
        cli_mark_scan_incomplete(ctx, "NSIS archive is shorter than its declared size");
        n->asz = (uint32_t)(n->fullsz - n->off);
        trunc++;
    } else if (n->fullsz - n->off != n->asz) {
        cli_dbgmsg("NSIS: Overlays found\n");
    }

    n->asz -= 0x1c;
    /* Guess if solid */
    /* The final four bytes are the NSIS archive CRC, not a member header. */
    for (i = 0, pos = 0; pos <= n->asz && n->asz - pos > 4; i++) {
        uint32_t nextsz;
        uint32_t rawsz;

        buf = fmap_need_off_once(n->map, n->off + 0x1c + pos, 4);
        if (buf == NULL) {
            cli_mark_scan_incomplete(ctx, "NSIS member table is truncated");
            return CL_EREAD;
        }
        rawsz  = (uint32_t)cli_readint32(buf);
        nextsz = rawsz & UINT32_C(0x7fffffff);
        if (!i) n->comp = nsis_detcomp(buf);
        pos += 4;
        if (rawsz & UINT32_C(0x80000000)) {
            if (nextsz < 4 || n->asz - pos < 4) {
                cli_mark_scan_incomplete(ctx, "NSIS compressed member header is invalid");
                return CL_EFORMAT;
            }
            buf = fmap_need_off_once(n->map, n->off + 0x1c + pos, 4);
            if (buf == NULL) {
                cli_mark_scan_incomplete(ctx, "NSIS compressed member header is truncated");
                return CL_EREAD;
            }
            comps[nsis_detcomp(buf)]++;
            nextsz -= 4;
            pos += 4;
        }
        if (nextsz > n->asz - pos) {
            n->solid = 1;
            break;
        }
        pos += nextsz;
    }

    if (trunc && i >= 2) n->solid = 0;

    cli_dbgmsg("NSIS: solid compression%s detected\n", (n->solid) ? "" : " not");

    /* Guess the compression method */
    if (!n->solid) {
        cli_dbgmsg("NSIS: bzip2 %u - lzma %u - zlib %u\n", comps[1], comps[2], comps[3]);
        n->comp = (comps[1] < comps[2]) ? (comps[2] < comps[3] ? COMP_ZLIB : COMP_LZMA) : (comps[1] < comps[3] ? COMP_ZLIB : COMP_BZIP2);
    }

    n->curpos = n->off + 0x1c;
    return nsis_unpack_next(n, ctx);
}

static int cli_nsis_unpack(struct nsis_st *n, cli_ctx *ctx)
{
    return (n->fno) ? nsis_unpack_next(n, ctx) : nsis_headers(n, ctx);
}

cl_error_t cli_nulsft_header_check(cli_ctx *ctx, off_t offset)
{
    const char *buf;
    size_t remaining;
    uint32_t header_size;
    uint32_t archive_size;

    if (!ctx || !ctx->fmap)
        return CL_ENULLARG;
    if (offset < 0 || (uint64_t)offset > ctx->fmap->len)
        return CL_EFORMAT;

    remaining = ctx->fmap->len - (size_t)offset;
    if (remaining < 0x1c)
        return CL_EFORMAT;
    if (!(buf = fmap_need_off_once(ctx->fmap, offset, 0x1c)))
        return CL_EFORMAT;

    /* The four bytes immediately before the NullsoftInst signature are the
     * NSIS archive marker. The complete fixed header is required before an
     * embedded candidate can create a nested layer. */
    if (cli_readint32(buf) != UINT32_C(0xdeadbeef))
        return CL_EFORMAT;

    header_size  = (uint32_t)cli_readint32(buf + 0x14);
    archive_size = (uint32_t)cli_readint32(buf + 0x18);
    if (header_size < 0x1c || archive_size < 0x1c || header_size > archive_size)
        return CL_EPARSE;
    if ((uint64_t)archive_size > remaining)
        return CL_EPARSE;

    return CL_SUCCESS;
}

int cli_scannulsft(cli_ctx *ctx, off_t offset)
{
    int ret;
    struct nsis_st nsist;

    cli_dbgmsg("in scannulsft()\n");

    memset(&nsist, 0, sizeof(struct nsis_st));

    if (offset < 0 || (uint64_t)offset > SIZE_MAX || (size_t)offset > ctx->fmap->len) {
        cli_mark_scan_incomplete(ctx, "NSIS archive offset is outside the input map");
        return CL_EREAD;
    }
    nsist.off = (size_t)offset;
    if (!(nsist.dir = cli_gentemp_with_prefix(ctx->this_layer_tmpdir, "nulsft-tmp")))
        return CL_ETMPDIR;
    if (mkdir(nsist.dir, 0700)) {
        cli_dbgmsg("NSIS: Can't create temporary directory %s\n", nsist.dir);
        free(nsist.dir);
        return CL_ETMPDIR;
    }

    nsist.map = ctx->fmap;
    if (ctx->engine->keeptmp) cli_dbgmsg("NSIS: Extracting files to %s\n", nsist.dir);

    do {
        ret = cli_nsis_unpack(&nsist, ctx);
        if (ret == CL_SUCCESS && nsist.opened == 0) {
            /* Don't scan a non-existent file */
            continue;
        }
        if (ret == CL_SUCCESS) {
            char *name = NULL;
            cli_dbgmsg("NSIS: Successfully extracted file #%u\n", nsist.fno);
            if (lseek(nsist.ofd, 0, SEEK_SET) == -1) {
                cli_dbgmsg("NSIS: call to lseek() failed\n");
                free(nsist.dir);
                return CL_ESEEK;
            }

            // Get basename of the file from nsist.ofn
            ret = cli_basename(nsist.ofn, strlen(nsist.ofn), &name, true /* posix_support_backslash_pathsep */);
            if (CL_SUCCESS != ret || NULL == name) {
                cli_dbgmsg("NSIS: Failed to get basename of the file\n");
                // If it fails, the name will just be NULL. That's okay.
            }

            if (nsist.fno == 1) {
                ret = cli_scan_desc(nsist.ofd, ctx, CL_TYPE_ANY, false, NULL, AC_SCAN_VIR, NULL, name, nsist.ofn, LAYER_ATTRIBUTES_NONE); /// TODO: Extract file names
            } else {
                ret = cli_magic_scan_desc(nsist.ofd, nsist.ofn, ctx, name, LAYER_ATTRIBUTES_NONE); /// TODO: Extract file names
            }

            CLI_FREE_AND_SET_NULL(name);

            close(nsist.ofd);

            if (!ctx->engine->keeptmp) {
                if (cli_unlink(nsist.ofn)) {
                    ret = CL_EUNLINK;
                }
            }
        }
    } while (ret == CL_SUCCESS);

    if (ret == CL_BREAK)
        ret = CL_CLEAN;

    nsis_shutdown(&nsist);

    if (!ctx->engine->keeptmp) {
        cli_rmdirs(nsist.dir);
    }

    free(nsist.dir);

    return ret;
}
