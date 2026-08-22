/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2011-2013 Sourcefire, Inc.
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

#include <string.h>

#include "clamav.h"
#include "scanners.h"
#include "iso9660.h"
#include "fmap.h"
#include "str.h"
#include "entconv.h"
#include "hashtab.h"

typedef struct {
    cli_ctx *ctx;
    size_t base_offset;
    unsigned int blocksz;
    unsigned int sectsz;
    unsigned int fileno;
    unsigned int joliet;
    char buf[260];
    struct cli_hashset dir_blocks;
} iso9660_t;

static cl_error_t iso_incomplete(cli_ctx *ctx, const char *reason)
{
    cli_mark_scan_incomplete(ctx, reason);
    return CL_EPARSE;
}

static const void *needblock(const iso9660_t *iso, unsigned int block, int temp, cl_error_t *read_status)
{
    cli_ctx *ctx;
    uint64_t available;
    uint64_t logical_offset;
    uint64_t block_offset;
    uint64_t absolute_offset;
    unsigned int blocks_per_sect;

    if (read_status)
        *read_status = CL_EPARSE;

    if (!iso || !iso->ctx || !iso->ctx->fmap || !iso->sectsz || !iso->blocksz ||
        iso->blocksz > iso->sectsz)
        return NULL;

    ctx = iso->ctx;
    if (iso->base_offset > ctx->fmap->len)
        return NULL;

    available       = (uint64_t)(ctx->fmap->len - iso->base_offset);
    blocks_per_sect = 2048 / iso->blocksz;
    if (!blocks_per_sect || (uint64_t)block >= (available / iso->sectsz) * blocks_per_sect)
        return NULL;                                  /* Block is out of file */

    logical_offset = (uint64_t)(block / blocks_per_sect) * iso->sectsz;   /* logical sector */
    block_offset   = (uint64_t)(block % blocks_per_sect) * iso->blocksz; /* logical block within the sector */
    if (logical_offset > UINT64_MAX - block_offset)
        return NULL;
    logical_offset += block_offset;
    if (logical_offset > available || (uint64_t)iso->blocksz > available - logical_offset)
        return NULL;

    absolute_offset = (uint64_t)iso->base_offset + logical_offset;
    if (absolute_offset > SIZE_MAX)
        return NULL;

    {
        const void *result = temp
                                 ? fmap_need_off_once(ctx->fmap, (size_t)absolute_offset, iso->blocksz)
                                 : fmap_need_off(ctx->fmap, (size_t)absolute_offset, iso->blocksz);
        if (!result && read_status)
            *read_status = CL_EREAD;
        return result;
    }
}

static cl_error_t iso_scan_file(const iso9660_t *iso, unsigned int block, unsigned int len)
{
    char *tmpf;
    int fd                      = -1;
    cl_error_t ret              = CL_SUCCESS;
    uint64_t temporary_reserved = 0;

    if (cli_gentempfd(iso->ctx->this_layer_tmpdir, &tmpf, &fd) != CL_SUCCESS) {
        cli_mark_scan_incomplete(iso->ctx, "ISO temporary output could not be created");
        return CL_ETMPFILE;
    }

    if (cli_scan_reserve_temporary(iso->ctx, (uint64_t)len) != CL_SUCCESS) {
        cli_mark_scan_incomplete(iso->ctx, "ISO file extent exceeds temporary storage limits");
        ret = CL_ERESOURCE;
        goto cleanup;
    }
    temporary_reserved = (uint64_t)len;

    cli_dbgmsg("iso_scan_file: dumping to %s\n", tmpf);
    while (len) {
        cl_error_t read_status;
        const void *buf;
        unsigned int todo;

        ret = cli_checktimelimit(iso->ctx);
        if (ret != CL_SUCCESS) {
            cli_mark_scan_incomplete(iso->ctx, "ISO file extent traversal reached the configured time limit");
            break;
        }

        buf  = needblock(iso, block, 1, &read_status);
        todo = MIN(len, iso->blocksz);

        if (!buf) {
            if (read_status == CL_EREAD) {
                cli_dbgmsg("iso_scan_file: cannot read file data block\n");
                cli_mark_scan_incomplete(iso->ctx, "ISO file data block could not be read completely");
                ret = CL_EREAD;
            } else {
                cli_dbgmsg("iso_scan_file: cannot dump block outside file, ISO may be truncated\n");
                ret = iso_incomplete(iso->ctx, "ISO file data block was outside the available map");
            }
            break;
        }
        if (cli_writen(fd, buf, todo) != todo) {
            cli_warnmsg("iso_scan_file: Can't write to file %s\n", tmpf);
            cli_mark_scan_incomplete(iso->ctx, "ISO file data could not be materialized completely");
            ret = CL_EWRITE;
            break;
        }
        len -= todo;
        block++;
    }

    if (!len) {
        ret = cli_magic_scan_desc_type_reserved(fd, tmpf, iso->ctx, CL_TYPE_ANY, iso->buf, LAYER_ATTRIBUTES_NONE);
        if (ret != CL_SUCCESS && ret != CL_VIRUS && ret != CL_VERIFIED && ret != CL_BREAK)
            cli_mark_scan_incomplete(iso->ctx, "ISO extracted-file scan did not complete");
    }

cleanup:
    if (close(fd) == -1) {
        cli_mark_scan_incomplete(iso->ctx, "ISO temporary output could not be closed");
        if (CL_SUCCESS == ret || CL_VERIFIED == ret)
            ret = CL_EWRITE;
    }
    if (!iso->ctx->engine->keeptmp && cli_unlink(tmpf)) {
        cli_mark_scan_incomplete(iso->ctx, "ISO temporary output could not be removed");
        if (CL_SUCCESS == ret || CL_VERIFIED == ret)
            ret = CL_EUNLINK;
    }

    free(tmpf);
    if (temporary_reserved)
        cli_scan_release_temporary(iso->ctx, temporary_reserved);
    return ret;
}

static char *iso_string(iso9660_t *iso, const void *src, unsigned int len)
{
    if (iso->joliet) {
        char *utf8;
        const char *uutf8;
        if (len > (sizeof(iso->buf) - 2)) {
            cli_mark_scan_incomplete(iso->ctx, "ISO directory entry name exceeded the parser buffer");
            len = sizeof(iso->buf) - 2;
        }
        memcpy(iso->buf, src, len);
        iso->buf[len]     = '\0';
        iso->buf[len + 1] = '\0';
        utf8              = cli_utf16_to_utf8(iso->buf, len, E_UTF16_BE);
        uutf8             = utf8 ? utf8 : "";
        strncpy(iso->buf, uutf8, sizeof(iso->buf));
        iso->buf[sizeof(iso->buf) - 1] = '\0';
        free(utf8);
    } else {
        if (len >= sizeof(iso->buf)) {
            cli_mark_scan_incomplete(iso->ctx, "ISO directory entry name exceeded the parser buffer");
            len = sizeof(iso->buf) - 1;
        }
        memcpy(iso->buf, src, len);
        iso->buf[len] = '\0';
    }
    return iso->buf;
}

static cl_error_t iso_parse_dir(iso9660_t *iso, unsigned int block, unsigned int len)
{
    cli_ctx *ctx   = iso->ctx;
    cl_error_t ret = CL_SUCCESS;

    if (len < 34) {
        cli_dbgmsg("iso_parse_dir: Directory too small, skipping\n");
        return iso_incomplete(ctx, "ISO directory record area was truncated");
    }

    for (; len && ret == CL_SUCCESS; block++, len -= MIN(len, iso->blocksz)) {
        const uint8_t *dir;
        uint8_t dir_block[2048];
        unsigned int dirsz;

        ret = cli_checktimelimit(ctx);
        if (ret != CL_SUCCESS) {
            cli_mark_scan_incomplete(ctx, "ISO directory traversal reached the configured time limit");
            break;
        }

        if (iso->dir_blocks.count > 1024) {
            cli_dbgmsg("iso_parse_dir: Breaking out due to too many dir records\n");
            return CL_BREAK;
        }

        if (cli_hashset_contains(&iso->dir_blocks, block)) {
            continue;
        }

        if (CL_SUCCESS != (ret = cli_hashset_addkey(&iso->dir_blocks, block))) {
            cli_mark_scan_incomplete(ctx, "ISO directory traversal state could not be extended");
            return ret;
        }

        {
            cl_error_t read_status;
            dir = needblock(iso, block, 0, &read_status);
            if (!dir) {
                if (read_status == CL_EREAD) {
                    cli_mark_scan_incomplete(ctx, "ISO directory block could not be read completely");
                    return CL_EREAD;
                }
                return iso_incomplete(ctx, "ISO directory block was outside the available map");
            }
            /* A directory entry may recurse into another directory or scan a
             * file extent. Copy this bounded block before those nested reads so
             * the directory fmap window never spans child work. */
            memcpy(dir_block, dir, iso->blocksz);
            fmap_unneed_ptr(ctx->fmap, (void *)dir, iso->blocksz);
            dir = dir_block;
        }

        for (dirsz = MIN(iso->blocksz, len);;) {
            unsigned int entrysz, fileoff, filesz, name_len;
            char *sep;

            ret = cli_checktimelimit(ctx);
            if (ret != CL_SUCCESS) {
                cli_mark_scan_incomplete(ctx, "ISO directory-entry traversal reached the configured time limit");
                break;
            }

            entrysz = *dir;

            if (!dirsz || !entrysz) /* continuing on next block, if any */
                break;
            if (entrysz > dirsz) { /* record size overlaps onto the next sector, no point in looking in there */
                cli_dbgmsg("iso_parse_dir: Directory entry overflow, breaking out %u %u\n", entrysz, dirsz);
                ret = iso_incomplete(ctx, "ISO directory entry exceeded its available record area");
                break;
            }
            if (entrysz < 34) { /* this shouldn't happen really*/
                cli_dbgmsg("iso_parse_dir: Too short directory entry\n");
                ret = iso_incomplete(ctx, "ISO directory entry was truncated");
                break;
            }
            filesz = dir[32];
            if (filesz == 1 && (dir[33] == 0 || dir[33] == 1)) { /* skip "." and ".." */
                dirsz -= entrysz;
                dir += entrysz;
                continue;
            }

            if (filesz + 33 > dirsz) {
                cli_dbgmsg("iso_parse_dir: Directory entry name overflow\n");
                ret = iso_incomplete(ctx, "ISO directory entry name was truncated");
                break;
            }
            iso_string(iso, &dir[33], filesz);
            name_len = MIN(filesz, (unsigned int)sizeof(iso->buf) - 1U);
            sep      = memchr(iso->buf, ';', name_len);
            if (sep)
                *sep = '\0';
            else
                iso->buf[name_len] = '\0';
            {
                uint64_t fileoff64 = (uint64_t)cli_readint32(dir + 2) + dir[1];
                if (fileoff64 > UINT32_MAX) {
                    ret = iso_incomplete(ctx, "ISO directory block coordinate overflowed");
                    break;
                }
                fileoff = (unsigned int)fileoff64;
            }
            filesz = cli_readint32(dir + 10);

            cli_dbgmsg("iso_parse_dir: %s '%s': off %x - size %x - flags %x - unit size %x - gap size %x - volume %u\n", (dir[25] & 2) ? "Directory" : "File", iso->buf, fileoff, filesz, dir[25], dir[26], dir[27], cli_readint32(&dir[28]) & 0xffff);
            ret = cli_matchmeta(ctx, iso->buf, filesz, filesz, 0, 0, 0);
            if (ret != CL_SUCCESS) {
                break;
            }

            if (dir[26] || dir[27]) {
                cli_dbgmsg("iso_parse_dir: Skipping interleaved file\n");
                ret = iso_incomplete(ctx, "ISO interleaved file layout is unsupported");
                break;
            } else if (dir[25] & 0x80) {
                cli_dbgmsg("iso_parse_dir: Skipping multi-extent file\n");
                ret = iso_incomplete(ctx, "ISO multi-extent file layout is unsupported");
                break;
            } else {
                if (dir[25] & 2) {
                    ret = iso_parse_dir(iso, fileoff, filesz);
                } else {
                    ret = cli_checklimits("ISO9660", ctx, filesz, 0, 0);
                    if (ret != CL_SUCCESS) {
                        cli_dbgmsg("iso_parse_dir: Skipping overlimit file\n");
                        cli_mark_scan_incomplete(ctx, "ISO file exceeded configured scan limits");
                    } else {
                        ret = iso_scan_file(iso, fileoff, filesz);
                    }
                }
                if (ret != CL_SUCCESS) {
                    break;
                }
            }
            dirsz -= entrysz;
            dir += entrysz;
        }

    }

    return ret;
}

cl_error_t cli_scaniso(cli_ctx *ctx, size_t offset)
{
    const uint8_t *privol, *next;
    const uint8_t *primary_map;
    uint8_t primary_descriptor[2448 + 6];
    uint8_t joliet_descriptor[2048];
    iso9660_t iso;
    int i;
    cl_error_t status   = CL_SUCCESS;
    cl_error_t ret      = CL_SUCCESS;
    uint32_t nextJoliet = 0;
    uint64_t root_directory_block64;

    if (ctx == NULL || ctx->fmap == NULL)
        return CL_ENULLARG;

    status = cli_checktimelimit(ctx);
    if (status != CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, "ISO inspection reached the configured time limit");
        return status;
    }

    if (offset < 32768) {
        /* Need 16 sectors at least 2048 bytes long */
        return iso_incomplete(ctx, "ISO volume descriptor started before the required system area");
    }

    if (offset > ctx->fmap->len || sizeof(primary_descriptor) > ctx->fmap->len - offset)
        return iso_incomplete(ctx, "ISO volume descriptor was truncated");

    primary_map = fmap_need_off(ctx->fmap, offset, sizeof(primary_descriptor));
    if (!primary_map) {
        cli_mark_scan_incomplete(ctx, "ISO volume descriptor could not be read completely");
        return CL_EREAD;
    }

    next = (uint8_t *)cli_memstr((char *)primary_map + 2049, sizeof(primary_descriptor) - 2049, "CD001", 5);
    if (!next) {
        /* Find next volume descriptor */
        fmap_unneed_off(ctx->fmap, offset, sizeof(primary_descriptor));
        return iso_incomplete(ctx, "ISO volume descriptor sequence was truncated");
    }

    iso.sectsz = (next - primary_map) - 1;
    if (iso.sectsz * 16 > offset) {
        /* Need room for 16 system sectors */
        fmap_unneed_off(ctx->fmap, offset, sizeof(primary_descriptor));
        return iso_incomplete(ctx, "ISO volume descriptor had an invalid sector layout");
    }

    iso.blocksz = cli_readint32(primary_map + 128) & 0xffff;
    if (iso.blocksz != 512 && iso.blocksz != 1024 && iso.blocksz != 2048) {
        /* Likely not a cdrom image */
        fmap_unneed_off(ctx->fmap, offset, sizeof(primary_descriptor));
        return iso_incomplete(ctx, "ISO volume descriptor had an invalid block size");
    }

    iso.base_offset = offset - iso.sectsz * 16;
    iso.joliet      = 0;

    for (i = 16; i < 32; i++) { /* scan for a joliet secondary volume descriptor */
        uint64_t descriptor_offset64 = (uint64_t)iso.base_offset + (uint64_t)i * iso.sectsz;
        size_t descriptor_offset;

        if (descriptor_offset64 > SIZE_MAX)
            break;
        descriptor_offset = (size_t)descriptor_offset64;
        next             = fmap_need_off_once(ctx->fmap, descriptor_offset, 2048);
        if (!next) {
            if (descriptor_offset <= ctx->fmap->len && 2048 <= ctx->fmap->len - descriptor_offset) {
                fmap_unneed_off(ctx->fmap, offset, sizeof(primary_descriptor));
                cli_mark_scan_incomplete(ctx, "ISO secondary volume descriptor could not be read completely");
                status = CL_EREAD;
                goto done;
            }
            break; /* Out of disk */
        }
        if (*next == 0xff || memcmp(next + 1, "CD001", 5))
            break; /* Not a volume descriptor */
        if (*next != 2)
            continue; /* Not a secondary volume descriptor */
        if (next[88] != 0x25 || next[89] != 0x2f)
            continue; /* Not a joliet descriptor */
        if (next[156 + 26] || next[156 + 27])
            continue; /* Root is interleaved so we fallback to the primary descriptor */
        switch (next[90]) {
            case 0x40: /* Level 1 */
                iso.joliet = 1;
                break;
            case 0x43: /* Level 2 */
                iso.joliet = 2;
                break;
            case 0x45: /* Level 3 */
                iso.joliet = 3;
                break;
            default: /* Not Joliet */
                continue;
        }
        memcpy(joliet_descriptor, next, sizeof(joliet_descriptor));
        break;
    }

    /* TODO rr, el torito, udf ? */

    /* The directory walk allocates and reads other fmap pages. Snapshot both
     * descriptors before releasing the primary locked window so later debug
     * and root-directory reads never use an unlocked mapped pointer. */
    memcpy(primary_descriptor, primary_map, sizeof(primary_descriptor));
    fmap_unneed_off(ctx->fmap, offset, sizeof(primary_descriptor));
    privol = primary_descriptor;
    if (!iso.joliet) {
        next = NULL;
    } else
        next = joliet_descriptor;

    nextJoliet = iso.joliet;
    iso.joliet = 0;

    do {
        status = cli_checktimelimit(ctx);
        if (status != CL_SUCCESS) {
            cli_mark_scan_incomplete(ctx, "ISO volume walk reached the configured time limit");
            goto done;
        }

        cli_dbgmsg("in cli_scaniso\n");
        if (cli_debug_flag) {
            cli_dbgmsg("cli_scaniso: Raw sector size: %u\n", iso.sectsz);
            cli_dbgmsg("cli_scaniso: Block size: %u\n", iso.blocksz);

            cli_dbgmsg("cli_scaniso: Volume descriptor version: %u\n", privol[6]);

#define ISOSTRING(src, len) iso_string(&iso, (src), (len))
            cli_dbgmsg("cli_scaniso: System: %s\n", ISOSTRING(privol + 8, 32));
            cli_dbgmsg("cli_scaniso: Volume: %s\n", ISOSTRING(privol + 40, 32));

            cli_dbgmsg("cli_scaniso: Volume space size: 0x%x blocks\n", cli_readint32(&privol[80]));
            cli_dbgmsg("cli_scaniso: Volume %u of %u\n", cli_readint32(privol + 124) & 0xffff, cli_readint32(privol + 120) & 0xffff);

            cli_dbgmsg("cli_scaniso: Volume Set: %s\n", ISOSTRING(privol + 190, 128));
            cli_dbgmsg("cli_scaniso: Publisher: %s\n", ISOSTRING(privol + 318, 128));
            cli_dbgmsg("cli_scaniso: Data Preparer: %s\n", ISOSTRING(privol + 446, 128));
            cli_dbgmsg("cli_scaniso: Application: %s\n", ISOSTRING(privol + 574, 128));

#define ISOTIME(s, n) cli_dbgmsg("cli_scaniso: "s                         \
                                 ": %c%c%c%c-%c%c-%c%c %c%c:%c%c:%c%c\n", \
                                 privol[n], privol[n + 1], privol[n + 2], privol[n + 3], privol[n + 4], privol[n + 5], privol[n + 6], privol[n + 7], privol[n + 8], privol[n + 9], privol[n + 10], privol[n + 11], privol[n + 12], privol[n + 13])
            ISOTIME("Volume creation time", 813);
            ISOTIME("Volume modification time", 830);
            ISOTIME("Volume expiration time", 847);
            ISOTIME("Volume effective time", 864);

            cli_dbgmsg("cli_scaniso: Path table size: 0x%x\n", cli_readint32(privol + 132) & 0xffff);
            cli_dbgmsg("cli_scaniso: LSB Path Table: 0x%x\n", cli_readint32(privol + 140));
            cli_dbgmsg("cli_scaniso: Opt LSB Path Table: 0x%x\n", cli_readint32(privol + 144));
            cli_dbgmsg("cli_scaniso: MSB Path Table: 0x%x\n", cbswap32(cli_readint32(privol + 148)));
            cli_dbgmsg("cli_scaniso: Opt MSB Path Table: 0x%x\n", cbswap32(cli_readint32(privol + 152)));
            cli_dbgmsg("cli_scaniso: File Structure Version: %u\n", privol[881]);

            if (iso.joliet)
                cli_dbgmsg("cli_scaniso: Joliet level %u\n", iso.joliet);
        }

        if (privol[156 + 26] || privol[156 + 27]) {
            cli_dbgmsg("cli_scaniso: Interleaved root directory is not supported\n");
            status = iso_incomplete(ctx, "ISO interleaved root directory is unsupported");
            goto done;
        }

        root_directory_block64 = (uint64_t)cli_readint32(privol + 156 + 2) + privol[156 + 1];
        if (root_directory_block64 > UINT32_MAX) {
            status = iso_incomplete(ctx, "ISO root directory block coordinate overflowed");
            goto done;
        }

        iso.ctx = ctx;
        ret     = cli_hashset_init(&iso.dir_blocks, 1024, 80);
        if (ret != CL_SUCCESS) {
            cli_mark_scan_incomplete(ctx, "ISO directory traversal state could not be allocated");
            status = ret;
            goto done;
        }

        ret = iso_parse_dir(&iso, (unsigned int)root_directory_block64, cli_readint32(privol + 156 + 10));
        cli_hashset_destroy(&iso.dir_blocks);
        switch (ret) {
            case CL_CLEAN:
                /* fallthrough */
            case CL_EFORMAT:
                /* fallthrough */
            case CL_EPARSE:
                break;
            default:
                /*Recoverable errors are above, anything else we need to return.*/
                status = ret;
                goto done;
        }
        if (ret > status) {
            status = ret;
        }

        privol     = next;
        next       = NULL;
        iso.joliet = nextJoliet;

    } while (privol);

done:

    if (status == CL_BREAK) {
        status = iso_incomplete(ctx, "ISO directory traversal reached its block limit");
    }

    return status;
}
