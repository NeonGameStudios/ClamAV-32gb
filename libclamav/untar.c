/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Nigel Horne
 *
 *  Summary: Extract files compressed with TAR compression format.
 *
 *  Acknowledgements: ClamAV untar code is based on a public domain minitar utility
 *                    by Charles G. Waldman.
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
#include <errno.h>
#include <limits.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/stat.h>
#include <fcntl.h>
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h> /* for NAME_MAX */
#endif

#include "clamav.h"
#include "others.h"
#include "untar.h"
#include "mbox.h"
#include "blob.h"
#include "scanners.h"
#include "matcher.h"

#define TARHEADERSIZE 512
/* BLOCKSIZE must be >= TARHEADERSIZE */
#define BLOCKSIZE TARHEADERSIZE
#define TARSIZEOFFSET 124
#define TARSIZELEN 12
#define TARCHECKSUMOFFSET 148
#define TARCHECKSUMLEN 8
#define TARFILETYPEOFFSET 156

static bool
octal(const char *str, uint64_t *value)
{
    uint64_t ret = 0;
    bool saw_digit = false;

    if (str == NULL || value == NULL)
        return false;

    while (*str == ' ')
        str++;

    while (*str >= '0' && *str <= '7') {
        uint64_t digit = (uint64_t)(*str - '0');

        if (ret > (UINT64_MAX - digit) / 8U)
            return false;
        ret = ret * 8U + digit;
        saw_digit = true;
        str++;
    }

    while (*str == ' ')
        str++;

    if (*str != '\0' || !saw_digit)
        return false;

    *value = ret;
    return true;
}

static bool
tar_size_field(const char *field, uint64_t *value)
{
    const unsigned char *bytes = (const unsigned char *)field;
    uint64_t parsed            = 0;
    size_t i;

    if (field == NULL || value == NULL)
        return false;

    /* GNU TAR uses 0x80 as the positive binary size marker. 0xff denotes a
     * negative two's-complement value and all other high-bit prefixes are
     * reserved; neither is a valid member size. */
    if (bytes[0] & 0x80) {
        if (bytes[0] != 0x80)
            return false;

        for (i = 1; i < TARSIZELEN; i++) {
            if (parsed > (UINT64_MAX - bytes[i]) / 256U)
                return false;
            parsed = parsed * 256U + bytes[i];
        }

        *value = parsed;
        return true;
    }

    return octal(field, value);
}

/**
 * Retrieve checksum values from a tar header block.
 * @param header Header data block, padded with zeroes to reach BLOCKSIZE
 * @return int value of checksum, -1 (from octal()) if bad value
 */
static int
getchecksum(const char *header)
{
    char ochecksum[TARCHECKSUMLEN + 1];
    uint64_t checksum;

    strncpy(ochecksum, header + TARCHECKSUMOFFSET, TARCHECKSUMLEN);
    ochecksum[TARCHECKSUMLEN] = '\0';
    if (!octal(ochecksum, &checksum) || checksum > INT_MAX)
        return -1;
    return (int)checksum;
}

static cl_error_t
cli_untar_checktimelimit(cli_ctx *ctx, const char *reason)
{
    cl_error_t status = cli_checktimelimit(ctx);

    if (status != CL_SUCCESS)
        cli_mark_scan_incomplete(ctx, reason);

    return status;
}

static cl_error_t cli_untar_finish_member(cli_ctx *ctx, int *fd, const char *fullname, const char *name,
                                          bool scan, uint64_t temporary_reserved)
{
    cl_error_t ret = CL_SUCCESS;

    if (fd == NULL || *fd < 0)
        return ret;

    if (scan) {
        if (lseek(*fd, 0, SEEK_SET) == -1) {
            cli_mark_scan_incomplete(ctx, "TAR temporary output could not be rewound");
            ret = CL_ESEEK;
        } else {
            ret = cli_magic_scan_desc_type_reserved(*fd, fullname, ctx, CL_TYPE_ANY, name,
                                                     LAYER_ATTRIBUTES_NONE);
        }
    }

    if (close(*fd) == -1) {
        cli_mark_scan_incomplete(ctx, "TAR temporary output could not be closed");
        if (ret == CL_SUCCESS || ret == CL_VERIFIED)
            ret = CL_EWRITE;
    }
    *fd = -1;

    if (!ctx->engine->keeptmp && cli_unlink(fullname)) {
        cli_mark_scan_incomplete(ctx, "TAR temporary output could not be removed");
        if (ret == CL_SUCCESS || ret == CL_VERIFIED)
            ret = CL_EUNLINK;
    }

    if (temporary_reserved)
        cli_scan_release_temporary(ctx, temporary_reserved);

    return ret;
}

/**
 * Calculate checksum values for tar header blocks.
 * @param header Header data block, padded with zeroes to reach BLOCKSIZE
 * @param targetsum Check value to match (as int not octal!)
 * @return 0 if checksum matches target, -1 if not
 */
static int
testchecksum(const char *header, int targetsum)
{
    const unsigned char *posix;
    const signed char *legacy;
    int posix_sum = 0, legacy_sum = 0;
    int i;

    // targetsum -1 represents an error from octal()
    if (targetsum == -1) {
        return -1;
    }

    /* Build checksums. POSIX is unsigned; some legacy tars use signed. */
    posix  = (unsigned char *)header;
    legacy = (signed char *)header;
    for (i = 0; i < BLOCKSIZE; i++) {
        if ((i >= TARCHECKSUMOFFSET) && (i < TARCHECKSUMOFFSET + TARCHECKSUMLEN)) {
            /* Use ascii value of space in place of checksum value */
            posix_sum += 32;
            legacy_sum += 32;
        } else {
            posix_sum += posix[i];
            legacy_sum += legacy[i];
        }
    }

    if ((targetsum == posix_sum) || (targetsum == legacy_sum)) {
        return 0;
    }
    return -1;
}

cl_error_t cli_untar(const char *dir, unsigned int posix, cli_ctx *ctx)
{
    cl_error_t ret;
    size_t size         = 0;
    uint64_t size_value = 0;
    int fout            = -1;
    int in_block        = 0;
    int last_header_bad = 0;
    bool incomplete     = false;
    bool saw_zero_block = false;
    bool member_incomplete = false;
    uint64_t temporary_reserved = 0;
    unsigned int files  = 0;
    char fullname[PATH_MAX + 1];
    char name[101];
    size_t pos      = 0;
    char zero[BLOCKSIZE];

    if ((ctx == NULL) || (ctx->fmap == NULL))
        return CL_ENULLARG;

    ret = cli_untar_checktimelimit(ctx, "TAR inspection reached the configured time limit");
    if (ret != CL_SUCCESS)
        return ret;

    cli_dbgmsg("In untar(%s)\n", dir);
    memset(zero, 0, sizeof(zero));

    for (;;) {
        const char *block;
        size_t nread;

        ret = cli_untar_checktimelimit(ctx, "TAR member traversal reached the configured time limit");
        if (ret != CL_SUCCESS) {
            if (fout >= 0) {
                (void)cli_untar_finish_member(ctx, &fout, fullname, name, false, temporary_reserved);
                temporary_reserved = 0;
            }
            return ret;
        }

        block = fmap_need_off_once_len(ctx->fmap, pos, BLOCKSIZE, &nread);
        cli_dbgmsg("cli_untar: pos = %lu\n", (unsigned long)pos);

        if (!in_block && !nread) {
            if (pos < ctx->fmap->len) {
                cli_mark_scan_incomplete(ctx, "TAR header could not be read completely");
                return CL_EREAD;
            }
            cli_mark_scan_incomplete(ctx, saw_zero_block ? "TAR end-of-archive marker was incomplete"
                                                          : "TAR end-of-archive marker was missing");
            return CL_EPARSE;
        }

        if (!nread)
            block = zero;

        if (!block) {
            if (fout >= 0) {
                ret = cli_untar_finish_member(ctx, &fout, fullname, name, false, temporary_reserved);
                temporary_reserved = 0;
                if (ret != CL_SUCCESS)
                    return ret;
            }
            cli_errmsg("cli_untar: block read error\n");
            return CL_EREAD;
        }
        pos += nread;

        if (!in_block) {
            char type;
            int directory, skipEntry = 0;
            int checksum = -1;
            char magic[7], osize[TARSIZELEN + 1];
            size = 0;
            if (fout >= 0) {
                ret = cli_untar_finish_member(ctx, &fout, fullname, name, !member_incomplete,
                                               temporary_reserved);
                temporary_reserved = 0;
                member_incomplete = false;
                if (ret != CL_SUCCESS) {
                    return ret;
                }
            }

            if (block[0] == '\0') {
                if (nread < TARHEADERSIZE) {
                    cli_mark_scan_incomplete(ctx, "TAR end-of-archive marker was truncated");
                    return CL_EPARSE;
                }
                if (memcmp(block, zero, BLOCKSIZE) != 0) {
                    cli_mark_scan_incomplete(ctx, "TAR end-of-archive marker was malformed");
                    return CL_EPARSE;
                }
                if (saw_zero_block)
                    break;
                saw_zero_block = true;
                continue;
            }
            saw_zero_block = false;
            if ((ret = cli_checklimits("cli_untar", ctx, 0, 0, 0)) != CL_CLEAN)
                return ret;

            if (nread < TARHEADERSIZE) {
                cli_mark_scan_incomplete(ctx, "TAR header was truncated");
                return CL_EPARSE;
            }

            checksum = getchecksum(block);
            cli_dbgmsg("cli_untar: Candidate checksum = %d, [%o in octal]\n", checksum, checksum);
            if (testchecksum(block, checksum) != 0) {
                // If checksum is bad, dump and look for next header block
                cli_dbgmsg("cli_untar: Invalid checksum in tar header. Skip to next...\n");
                if (last_header_bad == 0) {
                    last_header_bad++;
                    cli_dbgmsg("cli_untar: Invalid checksum found inside archive!\n");
                }
                cli_mark_scan_incomplete(ctx, "TAR header checksum was invalid");
                incomplete = true;
                continue;
            } else {
                last_header_bad = 0;
                cli_dbgmsg("cli_untar: Checksum %d is valid.\n", checksum);
            }

            if (posix) {
                strncpy(magic, block + 257, 5);
                magic[5] = '\0';
                if (strcmp(magic, "ustar") != 0) {
                    cli_dbgmsg("cli_untar: Incorrect magic string '%s' in tar header\n", magic);
                    cli_mark_scan_incomplete(ctx, "TAR header magic was invalid");
                    return CL_EPARSE;
                }
            }

            type = block[TARFILETYPEOFFSET];

            switch (type) {
                default:
                    cli_dbgmsg("cli_untar: unknown type flag %c\n", type);
                    /* fall-through */
                case '0':  /* plain file */
                case '\0': /* plain file */
                case '7':  /* contiguous file */
                case 'M':  /* continuation of a file from another volume; might as well scan it. */
                    files++;
                    directory = 0;
                    break;
                case '1': /* Link to already archived file */
                case '5': /* directory */
                case '2': /* sym link */
                case '3': /* char device */
                case '4': /* block device */
                case '6': /* fifo special */
                case 'V': /* Volume header */
                    directory = 1;
                    break;
                case 'K':
                case 'L':
                    /* GNU extension - ././@LongLink
                     * Discard the blocks with the extended filename,
                     * the last header will contain parts of it anyway
                     */
                case 'N': /* Old GNU format way of storing long filenames. */
                case 'A': /* Solaris ACL */
                case 'E': /* Solaris Extended attribute s*/
                case 'I': /* Inode only */
                case 'g': /* Global extended header */
                case 'x': /* Extended attributes */
                case 'X': /* Extended attributes (POSIX) */
                    directory = 0;
                    skipEntry = 1;
                    break;
            }

            if (directory) {
                in_block = 0;
                continue;
            }

            strncpy(osize, block + TARSIZEOFFSET, TARSIZELEN);
            osize[TARSIZELEN] = '\0';
            if (!tar_size_field(osize, &size_value) || size_value > SIZE_MAX) {
                cli_dbgmsg("cli_untar: Invalid size in tar header\n");
                cli_mark_scan_incomplete(ctx, "TAR entry size was invalid");
                incomplete = true;
                skipEntry++;
            } else {
                size = (size_t)size_value;
                cli_dbgmsg("cli_untar: size = %zu\n", size);
                ret = cli_checklimits("cli_untar", ctx, size, 0, 0);
                if (ret == CL_EMAXFILES) {
                    /* Scan no more files. */
                    skipEntry++;
                } else if (ret == CL_EMAXSIZE) {
                    /* Never scan a partial prefix of a member that exceeded
                     * the configured logical/file-size budget. */
                    cli_mark_scan_incomplete(ctx, "TAR member exceeded configured scan limits");
                    incomplete = true;
                    skipEntry++;
                } else if (ret != CL_SUCCESS) {
                    return ret;
                }
            }

            if (skipEntry) {
                size_t nskip = size;
                size_t padding = size % BLOCKSIZE ? BLOCKSIZE - (size % BLOCKSIZE) : 0;

                if (size == 0)
                    nskip = BLOCKSIZE;
                else if (padding && size > SIZE_MAX - padding) {
                    cli_dbgmsg("cli_untar: got overflowing skip size, giving up\n");
                    cli_mark_scan_incomplete(ctx, "TAR entry skip size overflowed");
                    return CL_EPARSE;
                } else {
                    nskip += padding;
                }

                cli_dbgmsg("cli_untar: skipping entry\n");
                if (nskip > SIZE_MAX - pos) {
                    cli_mark_scan_incomplete(ctx, "TAR entry skip offset overflowed");
                    return CL_EPARSE;
                }
                pos += nskip;
                continue;
            }

            strncpy(name, block, 100);
            name[100] = '\0';
            ret = cli_matchmeta(ctx, name, size, size, 0, files, 0);
            if (ret != CL_SUCCESS)
                return ret;

            ret = cli_untar_checktimelimit(ctx, "TAR member temporary admission reached the configured time limit");
            if (ret != CL_SUCCESS)
                return ret;

            ret = cli_scan_reserve_temporary(ctx, (uint64_t)size);
            if (ret != CL_SUCCESS) {
                cli_mark_scan_incomplete(ctx, "TAR member temporary output exceeded the configured limit");
                return ret;
            }
            temporary_reserved = (uint64_t)size;
            member_incomplete  = false;

            snprintf(fullname, sizeof(fullname) - 1, "%s" PATHSEP "tar%02u", dir, files);
            fullname[sizeof(fullname) - 1] = '\0';
            fout                           = open(fullname, O_RDWR | O_CREAT | O_EXCL | O_TRUNC | O_BINARY, 0600);

            if (fout < 0) {
                char err[128];
                cli_errmsg("cli_untar: Can't create temporary file %s: %s\n", fullname, cli_strerror(errno, err, sizeof(err)));
                if (temporary_reserved)
                    cli_scan_release_temporary(ctx, temporary_reserved);
                temporary_reserved = 0;
                return CL_ETMPFILE;
            }

            cli_dbgmsg("cli_untar: extracting to %s\n", fullname);

            in_block = 1;
        } else { /* write or continue writing file contents */
            size_t nbytes, nwritten;
            char err[128];

            nbytes = (size > 512) ? 512 : size;
            if (nread && (nread < nbytes))
                nbytes = nread;

            ret = cli_untar_checktimelimit(ctx, "TAR member output reached the configured time limit");
            if (ret != CL_SUCCESS) {
                (void)cli_untar_finish_member(ctx, &fout, fullname, name, false, temporary_reserved);
                temporary_reserved = 0;
                return ret;
            }

            nwritten = cli_writen(fout, block, nbytes);

            if (nwritten != nbytes) {
                cli_errmsg("cli_untar: only wrote %zu bytes to file %s (out of disc space?): %s\n",
                           nwritten, fullname, cli_strerror(errno, err, sizeof(err)));
                (void)cli_untar_finish_member(ctx, &fout, fullname, name, false, temporary_reserved);
                temporary_reserved = 0;
                return CL_EWRITE;
            }
            if (nbytes > size) {
                cli_warnmsg("cli_untar: More bytes written than requested!\n");
                size = 0;
            } else {
                size -= nbytes;
            }
            if ((size != 0) && (nread == 0)) {
                // Truncated tar file, so end file content like tar behavior
                cli_dbgmsg("cli_untar: No bytes read! Forcing end of file content.\n");
                cli_mark_scan_incomplete(ctx, "TAR entry ended before its declared content length");
                incomplete = true;
                member_incomplete = true;
                size       = 0;
            }
        }
        if (size == 0)
            in_block = 0;
    }
    if (fout >= 0) {
        ret = cli_untar_finish_member(ctx, &fout, fullname, name, !member_incomplete, temporary_reserved);
        temporary_reserved = 0;
        if (ret != CL_SUCCESS) {
            return ret;
        }
    }

    return incomplete ? CL_EPARSE : CL_CLEAN;
}
