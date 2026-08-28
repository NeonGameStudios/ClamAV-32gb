/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm
 *
 *  Acknowledgements: The header structures were based upon "ELF: Executable
 *                    and Linkable Format, Portable Formats Specification,
 *                    Version 1.1".
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
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <time.h>

#include "elf.h"
#include "clamav.h"
#include "execs.h"
#include "matcher.h"
#include "scanners.h"

#define EC16(v, conv) (conv ? cbswap16(v) : v)
#define EC32(v, conv) (conv ? cbswap32(v) : v)
#define EC64(v, conv) (conv ? cbswap64(v) : v)

#define CLI_TMPUNLK()               \
    if (!ctx->engine->keeptmp) {    \
        if (cli_unlink(tempfile)) { \
            free(tempfile);         \
            return CL_EUNLINK;      \
        }                           \
    }

static void cli_elf_sectionlog(uint32_t sh_type, uint32_t sh_flags);

static size_t cli_elf_readn(fmap_t *map, void *dst, uint64_t at, size_t len)
{
    /* fmap_readn() uses (size_t)-1 for both callback failures and an offset
     * beyond the map. Preserve an impossible ELF coordinate as short input;
     * only an in-range callback failure for a fully available structure is an
     * operational read error. */
    if (at > (uint64_t)map->len)
        return 0;
    if (len > map->len - (size_t)at)
        return 0;
    return fmap_readn(map, dst, (size_t)at, len);
}

static cl_error_t cli_elf_read_status(cli_ctx *ctx, size_t bytes_read, size_t expected, const char *reason)
{
    if (bytes_read == expected)
        return CL_SUCCESS;
    if (bytes_read == (size_t)-1) {
        if (ctx)
            cli_mark_scan_incomplete(ctx, reason);
        return CL_EREAD;
    }
    return CL_BREAK;
}

static cl_error_t cli_elf_broken_result(cli_ctx *ctx, cl_error_t fallback)
{
    cl_error_t ret;

    if (!ctx || !SCAN_HEURISTIC_BROKEN)
        return fallback;

    ret = cli_append_potentially_unwanted(ctx, "Heuristics.Broken.Executable");
    if (ret == CL_SUCCESS)
        return fallback;

    if (ret != CL_VIRUS && ret != CL_VERIFIED && ret != CL_BREAK)
        cli_mark_scan_incomplete(ctx, "ELF broken-executable heuristic alert could not be recorded");

    return ret;
}

static cl_error_t cli_elf_checktimelimit(cli_ctx *ctx, const char *reason)
{
    cl_error_t ret = cli_checktimelimit(ctx);

    if (ret != CL_SUCCESS && ctx)
        cli_mark_scan_incomplete(ctx, reason);

    return ret;
}

static uint64_t cli_rawaddr32(uint32_t vaddr, struct elf_program_hdr32 *ph, uint16_t phnum, uint8_t conv, uint8_t *err)
{
    uint16_t i, found = 0;
    uint32_t start, memsz;
    uint64_t delta, file_offset;

    for (i = 0; i < phnum; i++) {
        start = EC32(ph[i].p_vaddr, conv);
        memsz = EC32(ph[i].p_memsz, conv);
        if (vaddr >= start && vaddr - start < memsz) {
            found = 1;
            break;
        }
    }

    if (!found) {
        *err = 1;
        return 0;
    }

    *err = 0;
    delta       = (uint64_t)(vaddr - start);
    file_offset = EC32(ph[i].p_offset, conv);
    return file_offset + delta;
}

static uint64_t cli_rawaddr64(uint64_t vaddr, struct elf_program_hdr64 *ph, uint16_t phnum, uint8_t conv, uint8_t *err)
{
    uint16_t i, found = 0;
    uint64_t start, memsz, delta, file_offset;

    for (i = 0; i < phnum; i++) {
        start = EC64(ph[i].p_vaddr, conv);
        memsz = EC64(ph[i].p_memsz, conv);
        if (vaddr >= start && vaddr - start < memsz) {
            found = 1;
            break;
        }
    }

    if (!found) {
        *err = 1;
        return 0;
    }

    *err = 0;
    delta       = vaddr - start;
    file_offset = EC64(ph[i].p_offset, conv);
    if (delta > UINT64_MAX - file_offset) {
        *err = 1;
        return 0;
    }
    return file_offset + delta;
}

/* Return converted endian-fixed header, or error code */
static cl_error_t cli_elf_fileheader(cli_ctx *ctx, fmap_t *map, union elf_file_hdr *file_hdr,
                                     uint8_t *do_convert, uint8_t *is64)
{
    uint8_t format64, conv;
    uint16_t ehsize;
    size_t minimum_ehsize;
    cl_error_t read_status;
    size_t bytes_read;

    /* Load enough for smaller header first */
    bytes_read  = cli_elf_readn(map, file_hdr, 0, sizeof(struct elf_file_hdr32));
    read_status = cli_elf_read_status(ctx, bytes_read, sizeof(struct elf_file_hdr32),
                                      "ELF file header could not be read completely");
    if (read_status != CL_SUCCESS) {
        /* Not an ELF file? */
        cli_dbgmsg("ELF: Can't read file header\n");
        return read_status;
    }

    if (memcmp(file_hdr->hdr64.e_ident, "\x7f\x45\x4c\x46", 4)) {
        cli_dbgmsg("ELF: Not an ELF file\n");
        return CL_BREAK;
    }

    switch (file_hdr->hdr64.e_ident[4]) {
        case 1:
            cli_dbgmsg("ELF: ELF class 1 (32-bit)\n");
            format64 = 0;
            break;
        case 2:
            cli_dbgmsg("ELF: ELF class 2 (64-bit)\n");
            format64 = 1;
            break;
        default:
            cli_dbgmsg("ELF: Unknown ELF class (%u)\n", file_hdr->hdr64.e_ident[4]);
            return cli_elf_broken_result(ctx, CL_BREAK);
    }

    /* Need to know to endian convert */
    if (file_hdr->hdr64.e_ident[5] == 1) {
#if WORDS_BIGENDIAN == 0
        if (ctx)
            cli_dbgmsg("ELF: File is little-endian - conversion not required\n");
        conv = 0;
#else
        if (ctx)
            cli_dbgmsg("ELF: File is little-endian - data conversion enabled\n");
        conv = 1;
#endif
    } else if (file_hdr->hdr64.e_ident[5] == 2) {
#if WORDS_BIGENDIAN == 0
        if (ctx)
            cli_dbgmsg("ELF: File is big-endian - data conversion enabled\n");
        conv = 1;
#else
        if (ctx)
            cli_dbgmsg("ELF: File is big-endian - conversion not required\n");
        conv = 0;
#endif
    } else {
        cli_dbgmsg("ELF: Unknown data encoding (%u)\n", file_hdr->hdr64.e_ident[5]);
        return cli_elf_broken_result(ctx, CL_BREAK);
    }

    *do_convert = conv;
    *is64       = format64;

    /* Solve bit-size and conversion pronto */
    file_hdr->hdr64.e_type    = EC16(file_hdr->hdr64.e_type, conv);
    file_hdr->hdr64.e_machine = EC16(file_hdr->hdr64.e_machine, conv);
    file_hdr->hdr64.e_version = EC32(file_hdr->hdr64.e_version, conv);

    if (format64) {
        /* Read rest of 64-bit header */
        bytes_read  = cli_elf_readn(map, file_hdr->hdr32.pad, sizeof(struct elf_file_hdr32), ELF_HDR_SIZEDIFF);
        read_status = cli_elf_read_status(ctx, bytes_read, ELF_HDR_SIZEDIFF,
                                          "ELF 64-bit file header could not be read completely");
        if (read_status != CL_SUCCESS) {
            /* Not an ELF file? */
            cli_dbgmsg("ELF: Can't read file header\n");
            return read_status;
        }
        /* Now endian convert, if needed */
        if (conv) {
            file_hdr->hdr64.e_entry     = EC64(file_hdr->hdr64.e_entry, conv);
            file_hdr->hdr64.e_phoff     = EC64(file_hdr->hdr64.e_phoff, conv);
            file_hdr->hdr64.e_shoff     = EC64(file_hdr->hdr64.e_shoff, conv);
            file_hdr->hdr64.e_flags     = EC32(file_hdr->hdr64.e_flags, conv);
            file_hdr->hdr64.e_ehsize    = EC16(file_hdr->hdr64.e_ehsize, conv);
            file_hdr->hdr64.e_phentsize = EC16(file_hdr->hdr64.e_phentsize, conv);
            file_hdr->hdr64.e_phnum     = EC16(file_hdr->hdr64.e_phnum, conv);
            file_hdr->hdr64.e_shentsize = EC16(file_hdr->hdr64.e_shentsize, conv);
            file_hdr->hdr64.e_shnum     = EC16(file_hdr->hdr64.e_shnum, conv);
            file_hdr->hdr64.e_shstrndx  = EC16(file_hdr->hdr64.e_shstrndx, conv);
        }
    } else {
        /* Convert 32-bit structure, if needed */
        if (conv) {
            file_hdr->hdr32.hdr.e_entry     = EC32(file_hdr->hdr32.hdr.e_entry, conv);
            file_hdr->hdr32.hdr.e_phoff     = EC32(file_hdr->hdr32.hdr.e_phoff, conv);
            file_hdr->hdr32.hdr.e_shoff     = EC32(file_hdr->hdr32.hdr.e_shoff, conv);
            file_hdr->hdr32.hdr.e_flags     = EC32(file_hdr->hdr32.hdr.e_flags, conv);
            file_hdr->hdr32.hdr.e_ehsize    = EC16(file_hdr->hdr32.hdr.e_ehsize, conv);
            file_hdr->hdr32.hdr.e_phentsize = EC16(file_hdr->hdr32.hdr.e_phentsize, conv);
            file_hdr->hdr32.hdr.e_phnum     = EC16(file_hdr->hdr32.hdr.e_phnum, conv);
            file_hdr->hdr32.hdr.e_shentsize = EC16(file_hdr->hdr32.hdr.e_shentsize, conv);
            file_hdr->hdr32.hdr.e_shnum     = EC16(file_hdr->hdr32.hdr.e_shnum, conv);
            file_hdr->hdr32.hdr.e_shstrndx  = EC16(file_hdr->hdr32.hdr.e_shstrndx, conv);
        }
        /* Wipe pad for safety */
        memset(file_hdr->hdr32.pad, 0, ELF_HDR_SIZEDIFF);
    }

    if (format64) {
        ehsize         = file_hdr->hdr64.e_ehsize;
        minimum_ehsize = sizeof(struct elf_file_hdr64);
    } else {
        ehsize         = file_hdr->hdr32.hdr.e_ehsize;
        minimum_ehsize = sizeof(struct elf_file_hdr32);
    }

    /* The ELF ABI permits future header extensions, but the declared header
     * cannot omit fields understood by this parser or extend beyond the
     * containing map. Ignore any in-map extension bytes as permitted by the
     * format and keep all known fields range-safe. */
    if ((size_t)ehsize < minimum_ehsize) {
        cli_dbgmsg("ELF: File header size is smaller than the ELF class header\n");
        if (ctx)
            cli_mark_scan_incomplete(ctx, "ELF file header size is invalid");
        return CL_EFORMAT;
    }
    if ((size_t)ehsize > map->len) {
        cli_dbgmsg("ELF: File header extends beyond the input map\n");
        if (ctx)
            cli_mark_scan_incomplete(ctx, "ELF file header extends beyond the input map");
        return CL_BREAK;
    }

    return CL_CLEAN;
}

/* Read 32-bit program headers */
static int cli_elf_ph32(cli_ctx *ctx, fmap_t *map, struct cli_exe_info *elfinfo,
                        struct elf_file_hdr32 *file_hdr, uint8_t conv)
{
    struct elf_program_hdr32 *program_hdr = NULL;
    uint16_t phnum, phentsize;
    uint32_t entry;
    uint64_t fentry = 0;
    uint64_t phoff;
    uint32_t i;
    uint8_t err;

    /* Program headers and Entry */
    phnum = file_hdr->e_phnum;
    cli_dbgmsg("ELF: Number of program headers: %d\n", phnum);
    if (phnum > 128) {
        cli_dbgmsg("ELF: Suspicious number of program headers\n");
        return cli_elf_broken_result(ctx, CL_EFORMAT);
    }
    entry = file_hdr->e_entry;

    if (phnum) {
        phentsize = file_hdr->e_phentsize;
        /* Sanity check */
        if (phentsize != sizeof(struct elf_program_hdr32)) {
            cli_dbgmsg("ELF: phentsize != sizeof(struct elf_program_hdr32)\n");
            return cli_elf_broken_result(ctx, CL_EFORMAT);
        }

        phoff = file_hdr->e_phoff;
        if (ctx) {
            cli_dbgmsg("ELF: Program header table offset: " STDu64 "\n", phoff);
        }

        if (phnum) {
            program_hdr = (struct elf_program_hdr32 *)cli_max_calloc(phnum, sizeof(struct elf_program_hdr32));
            if (!program_hdr) {
                cli_errmsg("ELF: Can't allocate memory for program headers\n");
                if (ctx)
                    cli_mark_scan_incomplete(ctx, "ELF program header table could not be allocated");
                return CL_EMEM;
            }
            if (ctx) {
                cli_dbgmsg("------------------------------------\n");
            }
        }

        for (i = 0; i < phnum; i++) {
            cl_error_t read_status;

            read_status = cli_elf_checktimelimit(ctx, "ELF program-header traversal reached the configured time limit");
            if (read_status != CL_SUCCESS) {
                free(program_hdr);
                return read_status;
            }

            err = 0;
            read_status = cli_elf_read_status(ctx,
                                               cli_elf_readn(map, &program_hdr[i], phoff, sizeof(struct elf_program_hdr32)),
                                               sizeof(struct elf_program_hdr32),
                                               "ELF program header could not be read completely");
            if (read_status == CL_EREAD) {
                free(program_hdr);
                return CL_EREAD;
            }
            if (read_status != CL_SUCCESS)
                err = 1;
            phoff += sizeof(struct elf_program_hdr32);

            if (err) {
                cli_dbgmsg("ELF: Can't read segment #%d\n", i);
                if (ctx) {
                    cli_dbgmsg("ELF: Possibly broken ELF file\n");
                }
                free(program_hdr);
                return cli_elf_broken_result(ctx, CL_BREAK);
            }

            if (ctx) {
                cli_dbgmsg("ELF: Segment #%d\n", i);
                cli_dbgmsg("ELF: Segment type: 0x%x\n", EC32(program_hdr[i].p_type, conv));
                cli_dbgmsg("ELF: Segment offset: 0x%x\n", EC32(program_hdr[i].p_offset, conv));
                cli_dbgmsg("ELF: Segment virtual address: 0x%x\n", EC32(program_hdr[i].p_vaddr, conv));
                cli_dbgmsg("ELF: Segment real size: 0x%x\n", EC32(program_hdr[i].p_filesz, conv));
                cli_dbgmsg("ELF: Segment virtual size: 0x%x\n", EC32(program_hdr[i].p_memsz, conv));
                cli_dbgmsg("------------------------------------\n");
            }
        }

        if (entry) {
            fentry = cli_rawaddr32(entry, program_hdr, phnum, conv, &err);
            if (err) {
                cli_dbgmsg("ELF: Can't calculate file offset of entry point\n");
                free(program_hdr);
                return cli_elf_broken_result(ctx, CL_EFORMAT);
            }
            if (ctx) {
                cli_dbgmsg("ELF: Entry point address: 0x%.8x\n", entry);
                cli_dbgmsg("ELF: Entry point offset: 0x" STDx64 " (" STDu64 ")\n", fentry, fentry);
            }
        }
        free(program_hdr);
    }

    if (elfinfo) {
        elfinfo->ep64                 = fentry;
        elfinfo->has_native_coordinates = 1;
        if (fentry <= UINT32_MAX) {
            elfinfo->ep = (uint32_t)fentry;
        } else {
            elfinfo->ep                       = 0;
            elfinfo->legacy_metadata_incomplete = 1;
        }
    }

    return CL_CLEAN;
}

/* Read 64-bit program headers */
static cl_error_t cli_elf_ph64(cli_ctx *ctx, fmap_t *map, struct cli_exe_info *elfinfo,
                               struct elf_file_hdr64 *file_hdr, uint8_t conv)
{
    struct elf_program_hdr64 *program_hdr = NULL;
    uint16_t phnum, phentsize;
    uint64_t entry, fentry = 0, phoff;
    uint32_t i;
    uint8_t err;

    /* Program headers and Entry */
    phnum = file_hdr->e_phnum;
    cli_dbgmsg("ELF: Number of program headers: %d\n", phnum);
    if (phnum > 128) {
        cli_dbgmsg("ELF: Suspicious number of program headers\n");
        return cli_elf_broken_result(ctx, CL_EFORMAT);
    }
    entry = file_hdr->e_entry;

    if (phnum) {
        phentsize = file_hdr->e_phentsize;
        /* Sanity check */
        if (phentsize != sizeof(struct elf_program_hdr64)) {
            cli_dbgmsg("ELF: phentsize != sizeof(struct elf_program_hdr64)\n");
            return cli_elf_broken_result(ctx, CL_EFORMAT);
        }

        phoff = file_hdr->e_phoff;
        if (ctx) {
            cli_dbgmsg("ELF: Program header table offset: " STDu64 "\n", phoff);
        }

        if (phnum) {
            program_hdr = (struct elf_program_hdr64 *)cli_max_calloc(phnum, sizeof(struct elf_program_hdr64));
            if (!program_hdr) {
                cli_errmsg("ELF: Can't allocate memory for program headers\n");
                if (ctx)
                    cli_mark_scan_incomplete(ctx, "ELF program header table could not be allocated");
                return CL_EMEM;
            }
            if (ctx) {
                cli_dbgmsg("------------------------------------\n");
            }
        }

        for (i = 0; i < phnum; i++) {
            cl_error_t read_status;

            read_status = cli_elf_checktimelimit(ctx, "ELF program-header traversal reached the configured time limit");
            if (read_status != CL_SUCCESS) {
                free(program_hdr);
                return read_status;
            }

            if (i + 1 < phnum && phoff > UINT64_MAX - sizeof(struct elf_program_hdr64)) {
                cli_dbgmsg("ELF: Program header table coordinate overflow\n");
                free(program_hdr);
                return cli_elf_broken_result(ctx, CL_EFORMAT);
            }

            err = 0;
            read_status = cli_elf_read_status(ctx,
                                               cli_elf_readn(map, &program_hdr[i], phoff, sizeof(struct elf_program_hdr64)),
                                               sizeof(struct elf_program_hdr64),
                                               "ELF program header could not be read completely");
            if (read_status == CL_EREAD) {
                free(program_hdr);
                return CL_EREAD;
            }
            if (read_status != CL_SUCCESS)
                err = 1;

            if (err) {
                cli_dbgmsg("ELF: Can't read segment #%d\n", i);
                if (ctx) {
                    cli_dbgmsg("ELF: Possibly broken ELF file\n");
                }
                free(program_hdr);
                return cli_elf_broken_result(ctx, CL_BREAK);
            }

            phoff += sizeof(struct elf_program_hdr64);

            if (ctx) {
                cli_dbgmsg("ELF: Segment #%d\n", i);
                cli_dbgmsg("ELF: Segment type: 0x" STDx32 "\n", (uint32_t)EC32(program_hdr[i].p_type, conv));
                cli_dbgmsg("ELF: Segment offset: 0x" STDx64 "\n", (uint64_t)EC64(program_hdr[i].p_offset, conv));
                cli_dbgmsg("ELF: Segment virtual address: 0x" STDx64 "\n", (uint64_t)EC64(program_hdr[i].p_vaddr, conv));
                cli_dbgmsg("ELF: Segment real size: 0x" STDx64 "\n", (uint64_t)EC64(program_hdr[i].p_filesz, conv));
                cli_dbgmsg("ELF: Segment virtual size: 0x" STDx64 "\n", (uint64_t)EC64(program_hdr[i].p_memsz, conv));
                cli_dbgmsg("------------------------------------\n");
            }
        }

        if (entry) {
            fentry = cli_rawaddr64(entry, program_hdr, phnum, conv, &err);
            if (err) {
                cli_dbgmsg("ELF: Can't calculate file offset of entry point\n");
                free(program_hdr);
                return cli_elf_broken_result(ctx, CL_EFORMAT);
            }
            if (ctx) {
                cli_dbgmsg("ELF: Entry point address: 0x%.16" PRIx64 "\n", entry);
                cli_dbgmsg("ELF: Entry point offset: 0x%.16" PRIx64 " (" STDi64 ")\n", fentry, fentry);
            }
        }
        free(program_hdr);
    }

    if (elfinfo) {
        elfinfo->ep64                  = fentry;
        elfinfo->has_native_coordinates = 1;
        if (fentry <= UINT32_MAX) {
            elfinfo->ep = (uint32_t)fentry;
        } else {
            elfinfo->ep                        = 0;
            elfinfo->legacy_metadata_incomplete = 1;
        }
    }

    return CL_CLEAN;
}

/* 32-bit version of section header parsing */
static int cli_elf_sh32(cli_ctx *ctx, fmap_t *map, struct cli_exe_info *elfinfo,
                        struct elf_file_hdr32 *file_hdr, uint8_t conv)
{
    struct elf_section_hdr32 *section_hdr = NULL;
    uint16_t shnum, shentsize;
    uint64_t shoff;
    uint32_t i;

    shnum = file_hdr->e_shnum;
    cli_dbgmsg("ELF: Number of sections: %d\n", shnum);
    if (ctx && (shnum > 2048)) {
        cli_dbgmsg("ELF: Number of sections > 2048, skipping\n");
        return CL_BREAK;
    } else if (elfinfo && (shnum > 256)) {
        cli_dbgmsg("ELF: Suspicious number of sections\n");
        return CL_BREAK;
    }
    if (elfinfo) {
        elfinfo->nsections = shnum;
    }

    shentsize = file_hdr->e_shentsize;
    /* Sanity check */
    if (shentsize != sizeof(struct elf_section_hdr32)) {
        cli_dbgmsg("ELF: shentsize != sizeof(struct elf_section_hdr32)\n");
        return cli_elf_broken_result(ctx, CL_EFORMAT);
    }

    if (elfinfo && !shnum) {
        return CL_CLEAN;
    }

    shoff = file_hdr->e_shoff;
    if (ctx)
        cli_dbgmsg("ELF: Section header table offset: " STDu64 "\n", shoff);

    if (elfinfo) {
        elfinfo->sections = (struct cli_exe_section *)cli_max_calloc(shnum, sizeof(struct cli_exe_section));
        if (!elfinfo->sections) {
            cli_dbgmsg("ELF: Can't allocate memory for section headers\n");
            if (ctx)
                cli_mark_scan_incomplete(ctx, "ELF section metadata table could not be allocated");
            return CL_EMEM;
        }
        elfinfo->sections64 = (struct cli_exe_section64 *)cli_max_calloc(shnum, sizeof(struct cli_exe_section64));
        if (!elfinfo->sections64) {
            cli_dbgmsg("ELF: Can't allocate memory for native-width section headers\n");
            if (ctx)
                cli_mark_scan_incomplete(ctx, "ELF native-width section metadata table could not be allocated");
            return CL_EMEM;
        }
    }

    if (shnum) {
        section_hdr = (struct elf_section_hdr32 *)cli_max_calloc(shnum, shentsize);
        if (!section_hdr) {
            cli_errmsg("ELF: Can't allocate memory for section headers\n");
            if (ctx)
                cli_mark_scan_incomplete(ctx, "ELF section header table could not be allocated");
            return CL_EMEM;
        }
        if (ctx) {
            cli_dbgmsg("------------------------------------\n");
        }
    }

    /* Loop over section headers */
    for (i = 0; i < shnum; i++) {
        uint32_t sh_type, sh_flags;
        cl_error_t read_status;

        read_status = cli_elf_checktimelimit(ctx, "ELF section-header traversal reached the configured time limit");
        if (read_status != CL_SUCCESS) {
            free(section_hdr);
            return read_status;
        }

        read_status = cli_elf_read_status(ctx,
                                           cli_elf_readn(map, &section_hdr[i], shoff, sizeof(struct elf_section_hdr32)),
                                           sizeof(struct elf_section_hdr32),
                                           "ELF section header could not be read completely");
        if (read_status != CL_SUCCESS) {
            cli_dbgmsg("ELF: Can't read section header\n");
            if (read_status == CL_EREAD) {
                free(section_hdr);
                return CL_EREAD;
            }
            if (ctx) {
                cli_dbgmsg("ELF: Possibly broken ELF file\n");
            }
            free(section_hdr);
            return cli_elf_broken_result(ctx, CL_BREAK);
        }

        shoff += sizeof(struct elf_section_hdr32);

        if (elfinfo) {
            elfinfo->sections64[i].rva  = EC32(section_hdr[i].sh_addr, conv);
            elfinfo->sections64[i].raw  = EC32(section_hdr[i].sh_offset, conv);
            elfinfo->sections64[i].rsz  = EC32(section_hdr[i].sh_size, conv);
            elfinfo->sections64[i].urva = elfinfo->sections64[i].rva;
            elfinfo->sections64[i].uvsz = elfinfo->sections64[i].rsz;
            elfinfo->sections64[i].uraw = elfinfo->sections64[i].raw;
            elfinfo->sections64[i].ursz = elfinfo->sections64[i].rsz;

            elfinfo->sections[i].rva = (uint32_t)elfinfo->sections64[i].rva;
            elfinfo->sections[i].raw = (uint32_t)elfinfo->sections64[i].raw;
            elfinfo->sections[i].rsz = (uint32_t)elfinfo->sections64[i].rsz;
        }
        if (ctx) {
            cli_dbgmsg("ELF: Section %u\n", i);
            cli_dbgmsg("ELF: Section offset: %u\n", EC32(section_hdr[i].sh_offset, conv));
            cli_dbgmsg("ELF: Section size: %u\n", EC32(section_hdr[i].sh_size, conv));

            sh_type  = EC32(section_hdr[i].sh_type, conv);
            sh_flags = EC32(section_hdr[i].sh_flags, conv) & ELF_SHF_MASK;
            cli_elf_sectionlog(sh_type, sh_flags);

            cli_dbgmsg("------------------------------------\n");
        }
    }

    free(section_hdr);
    return CL_CLEAN;
}

/* 64-bit version of section header parsing */
static int cli_elf_sh64(cli_ctx *ctx, fmap_t *map, struct cli_exe_info *elfinfo,
                        struct elf_file_hdr64 *file_hdr, uint8_t conv)
{
    struct elf_section_hdr64 *section_hdr = NULL;
    uint16_t shnum, shentsize;
    uint32_t i;
    uint64_t shoff;

    shnum = file_hdr->e_shnum;
    cli_dbgmsg("ELF: Number of sections: %d\n", shnum);
    if (ctx && (shnum > 2048)) {
        cli_dbgmsg("ELF: Number of sections > 2048, skipping\n");
        return CL_BREAK;
    } else if (elfinfo && (shnum > 256)) {
        cli_dbgmsg("ELF: Suspicious number of sections\n");
        return CL_BREAK;
    }
    if (elfinfo) {
        elfinfo->nsections = shnum;
    }

    shentsize = file_hdr->e_shentsize;
    /* Sanity check */
    if (shentsize != sizeof(struct elf_section_hdr64)) {
        cli_dbgmsg("ELF: shentsize != sizeof(struct elf_section_hdr64)\n");
        return cli_elf_broken_result(ctx, CL_EFORMAT);
    }

    if (elfinfo && !shnum) {
        return CL_CLEAN;
    }

    shoff = file_hdr->e_shoff;
    if (ctx)
        cli_dbgmsg("ELF: Section header table offset: " STDu64 "\n", shoff);

    if (elfinfo) {
        elfinfo->sections = (struct cli_exe_section *)cli_max_calloc(shnum, sizeof(struct cli_exe_section));
        if (!elfinfo->sections) {
            cli_dbgmsg("ELF: Can't allocate memory for section headers\n");
            if (ctx)
                cli_mark_scan_incomplete(ctx, "ELF section metadata table could not be allocated");
            return CL_EMEM;
        }
        elfinfo->sections64 = (struct cli_exe_section64 *)cli_max_calloc(shnum, sizeof(struct cli_exe_section64));
        if (!elfinfo->sections64) {
            cli_dbgmsg("ELF: Can't allocate memory for native-width section headers\n");
            if (ctx)
                cli_mark_scan_incomplete(ctx, "ELF native-width section metadata table could not be allocated");
            return CL_EMEM;
        }
    }

    if (shnum) {
        section_hdr = (struct elf_section_hdr64 *)cli_max_calloc(shnum, shentsize);
        if (!section_hdr) {
            cli_errmsg("ELF: Can't allocate memory for section headers\n");
            if (ctx)
                cli_mark_scan_incomplete(ctx, "ELF section header table could not be allocated");
            return CL_EMEM;
        }
        if (ctx) {
            cli_dbgmsg("------------------------------------\n");
        }
    }

    /* Loop over section headers */
    for (i = 0; i < shnum; i++) {
        uint32_t sh_type, sh_flags;
        uint64_t section_addr, section_offset, section_size;
        cl_error_t read_status;

        read_status = cli_elf_checktimelimit(ctx, "ELF section-header traversal reached the configured time limit");
        if (read_status != CL_SUCCESS) {
            free(section_hdr);
            return read_status;
        }

        if (i + 1 < shnum && shoff > UINT64_MAX - sizeof(struct elf_section_hdr64)) {
            cli_dbgmsg("ELF: Section header table coordinate overflow\n");
            free(section_hdr);
            return cli_elf_broken_result(ctx, CL_EFORMAT);
        }

        read_status = cli_elf_read_status(ctx,
                                           cli_elf_readn(map, &section_hdr[i], shoff, sizeof(struct elf_section_hdr64)),
                                           sizeof(struct elf_section_hdr64),
                                           "ELF section header could not be read completely");
        if (read_status != CL_SUCCESS) {
            cli_dbgmsg("ELF: Can't read section header\n");
            if (read_status == CL_EREAD) {
                free(section_hdr);
                return CL_EREAD;
            }
            if (ctx) {
                cli_dbgmsg("ELF: Possibly broken ELF file\n");
            }
            free(section_hdr);
            return cli_elf_broken_result(ctx, CL_BREAK);
        }

        shoff += sizeof(struct elf_section_hdr64);

        if (elfinfo) {
            section_addr   = EC64(section_hdr[i].sh_addr, conv);
            section_offset = EC64(section_hdr[i].sh_offset, conv);
            section_size   = EC64(section_hdr[i].sh_size, conv);

            elfinfo->sections64[i].rva  = section_addr;
            elfinfo->sections64[i].raw  = section_offset;
            elfinfo->sections64[i].rsz  = section_size;
            elfinfo->sections64[i].chr  = (uint32_t)(EC64(section_hdr[i].sh_flags, conv) & ELF_SHF_MASK);
            elfinfo->sections64[i].urva = section_addr;
            elfinfo->sections64[i].uvsz = section_size;
            elfinfo->sections64[i].uraw = section_offset;
            elfinfo->sections64[i].ursz = section_size;

            if (section_addr > UINT32_MAX || section_offset > UINT32_MAX || section_size > UINT32_MAX) {
                /* Do not expose a partially narrowed section to legacy
                 * bytecode. Native matcher consumers use sections64. */
                memset(&elfinfo->sections[i], 0, sizeof(elfinfo->sections[i]));
                elfinfo->legacy_metadata_incomplete = 1;
            } else {
                elfinfo->sections[i].rva = (uint32_t)section_addr;
                elfinfo->sections[i].raw = (uint32_t)section_offset;
                elfinfo->sections[i].rsz = (uint32_t)section_size;
            }
        }
        if (ctx) {
            cli_dbgmsg("ELF: Section " STDu32 "\n", (uint32_t)i);
            cli_dbgmsg("ELF: Section offset: " STDu64 "\n", (uint64_t)EC64(section_hdr[i].sh_offset, conv));
            cli_dbgmsg("ELF: Section size: " STDu64 "\n", (uint64_t)EC64(section_hdr[i].sh_size, conv));

            sh_type  = EC32(section_hdr[i].sh_type, conv);
            sh_flags = (uint32_t)(EC64(section_hdr[i].sh_flags, conv) & ELF_SHF_MASK);
            cli_elf_sectionlog(sh_type, sh_flags);

            cli_dbgmsg("------------------------------------\n");
        }
    }

    free(section_hdr);
    return CL_CLEAN;
}

/* Print section type and selected flags to the log */
static void cli_elf_sectionlog(uint32_t sh_type, uint32_t sh_flags)
{
    switch (sh_type) {
        case 0x6: /* SHT_DYNAMIC */
            cli_dbgmsg("ELF: Section type: Dynamic linking information\n");
            break;
        case 0xb: /* SHT_DYNSYM */
            cli_dbgmsg("ELF: Section type: Symbols for dynamic linking\n");
            break;
        case 0xf: /* SHT_FINI_ARRAY */
            cli_dbgmsg("ELF: Section type: Array of pointers to termination functions\n");
            break;
        case 0x5: /* SHT_HASH */
            cli_dbgmsg("ELF: Section type: Symbol hash table\n");
            break;
        case 0xe: /* SHT_INIT_ARRAY */
            cli_dbgmsg("ELF: Section type: Array of pointers to initialization functions\n");
            break;
        case 0x8: /* SHT_NOBITS */
            cli_dbgmsg("ELF: Section type: Empty section (NOBITS)\n");
            break;
        case 0x7: /* SHT_NOTE */
            cli_dbgmsg("ELF: Section type: Note section\n");
            break;
        case 0x0: /* SHT_NULL */
            cli_dbgmsg("ELF: Section type: Null (no associated section)\n");
            break;
        case 0x10: /* SHT_PREINIT_ARRAY */
            cli_dbgmsg("ELF: Section type: Array of pointers to preinit functions\n");
            break;
        case 0x1: /* SHT_PROGBITS */
            cli_dbgmsg("ELF: Section type: Program information\n");
            break;
        case 0x9: /* SHT_REL */
            cli_dbgmsg("ELF: Section type: Relocation entries w/o explicit addends\n");
            break;
        case 0x4: /* SHT_RELA */
            cli_dbgmsg("ELF: Section type: Relocation entries with explicit addends\n");
            break;
        case 0x3: /* SHT_STRTAB */
            cli_dbgmsg("ELF: Section type: String table\n");
            break;
        case 0x2: /* SHT_SYMTAB */
            cli_dbgmsg("ELF: Section type: Symbol table\n");
            break;
        case 0x6ffffffd: /* SHT_GNU_verdef */
            cli_dbgmsg("ELF: Section type: Provided symbol versions\n");
            break;
        case 0x6ffffffe: /* SHT_GNU_verneed */
            cli_dbgmsg("ELF: Section type: Required symbol versions\n");
            break;
        case 0x6fffffff: /* SHT_GNU_versym */
            cli_dbgmsg("ELF: Section type: Symbol Version Table\n");
            break;
        default:
            cli_dbgmsg("ELF: Section type: Unknown\n");
    }

    if (sh_flags & ELF_SHF_WRITE)
        cli_dbgmsg("ELF: Section contains writable data\n");

    if (sh_flags & ELF_SHF_ALLOC)
        cli_dbgmsg("ELF: Section occupies memory\n");

    if (sh_flags & ELF_SHF_EXECINSTR)
        cli_dbgmsg("ELF: Section contains executable code\n");
}

/* Scan function for ELF */
cl_error_t cli_scanelf(cli_ctx *ctx)
{
    union elf_file_hdr file_hdr;
    fmap_t *map;
    cl_error_t ret;
    uint8_t conv = 0, is64 = 0;

    cli_dbgmsg("in cli_scanelf\n");

    if (ctx == NULL) {
        cli_dbgmsg("ELF: passed context was NULL\n");
        return CL_ENULLARG;
    }
    map = ctx->fmap;
    if (map == NULL) {
        cli_mark_scan_incomplete(ctx, "ELF input map is unavailable");
        return CL_EPARSE;
    }
    if (ctx->engine == NULL)
        return CL_ENULLARG;

    ret = cli_elf_checktimelimit(ctx, "ELF inspection reached the configured time limit");
    if (ret != CL_SUCCESS)
        return ret;

    /* Load header to determine size and class */
    ret = cli_elf_fileheader(ctx, map, &file_hdr, &conv, &is64);
    if (ret == CL_BREAK) {
        cli_mark_scan_incomplete(ctx, "ELF header parsing ended before inspection completed");
        return CL_EPARSE;
    } else if (ret != CL_CLEAN) {
        return ret;
    }

    /* Log File type and machine type */
    switch (file_hdr.hdr64.e_type) {
        case 0x0: /* ET_NONE */
            cli_dbgmsg("ELF: File type: None\n");
            break;
        case 0x1: /* ET_REL */
            cli_dbgmsg("ELF: File type: Relocatable\n");
            break;
        case 0x2: /* ET_EXEC */
            cli_dbgmsg("ELF: File type: Executable\n");
            break;
        case 0x3: /* ET_DYN */
            cli_dbgmsg("ELF: File type: Core\n");
            break;
        case 0x4: /* ET_CORE */
            cli_dbgmsg("ELF: File type: Core\n");
            break;
        default:
            cli_dbgmsg("ELF: File type: Unknown (%d)\n", file_hdr.hdr64.e_type);
    }

    switch (file_hdr.hdr64.e_machine) {
        /* Due to a huge list, we only include the most popular machines here */
        case 0: /* EM_NONE */
            cli_dbgmsg("ELF: Machine type: None\n");
            break;
        case 2: /* EM_SPARC */
            cli_dbgmsg("ELF: Machine type: SPARC\n");
            break;
        case 3: /* EM_386 */
            cli_dbgmsg("ELF: Machine type: Intel 80386\n");
            break;
        case 4: /* EM_68K */
            cli_dbgmsg("ELF: Machine type: Motorola 68000\n");
            break;
        case 8: /* EM_MIPS */
            cli_dbgmsg("ELF: Machine type: MIPS RS3000\n");
            break;
        case 9: /* EM_S370 */
            cli_dbgmsg("ELF: Machine type: IBM System/370\n");
            break;
        case 15: /* EM_PARISC */
            cli_dbgmsg("ELF: Machine type: HPPA\n");
            break;
        case 20: /* EM_PPC */
            cli_dbgmsg("ELF: Machine type: PowerPC\n");
            break;
        case 21: /* EM_PPC64 */
            cli_dbgmsg("ELF: Machine type: PowerPC 64-bit\n");
            break;
        case 22: /* EM_S390 */
            cli_dbgmsg("ELF: Machine type: IBM S390\n");
            break;
        case 40: /* EM_ARM */
            cli_dbgmsg("ELF: Machine type: ARM\n");
            break;
        case 41: /* EM_FAKE_ALPHA */
            cli_dbgmsg("ELF: Machine type: Digital Alpha\n");
            break;
        case 43: /* EM_SPARCV9 */
            cli_dbgmsg("ELF: Machine type: SPARC v9 64-bit\n");
            break;
        case 50: /* EM_IA_64 */
            cli_dbgmsg("ELF: Machine type: IA64\n");
            break;
        case 62: /* EM_X86_64 */
            cli_dbgmsg("ELF: Machine type: AMD x86-64\n");
            break;
        default:
            cli_dbgmsg("ELF: Machine type: Unknown (0x%x)\n", file_hdr.hdr64.e_machine);
    }

    /* Program headers and Entry */
    ret = cli_elf_checktimelimit(ctx, "ELF program-header inspection reached the configured time limit");
    if (ret != CL_SUCCESS)
        return ret;

    if (is64) {
        ret = cli_elf_ph64(ctx, map, NULL, &(file_hdr.hdr64), conv);
    } else {
        ret = cli_elf_ph32(ctx, map, NULL, &(file_hdr.hdr32.hdr), conv);
    }
    if (ret == CL_BREAK) {
        cli_mark_scan_incomplete(ctx, "ELF program-header parsing ended before inspection completed");
        return CL_EPARSE;
    } else if (ret != CL_CLEAN) {
        cli_mark_scan_incomplete(ctx, "ELF program-header parsing failed before inspection completed");
        return ret;
    }

    /* Sections */
    ret = cli_elf_checktimelimit(ctx, "ELF section-header inspection reached the configured time limit");
    if (ret != CL_SUCCESS)
        return ret;

    if (is64) {
        ret = cli_elf_sh64(ctx, map, NULL, &(file_hdr.hdr64), conv);
    } else {
        ret = cli_elf_sh32(ctx, map, NULL, &(file_hdr.hdr32.hdr), conv);
    }
    if (ret == CL_BREAK) {
        cli_mark_scan_incomplete(ctx, "ELF section-header parsing ended before inspection completed");
        return CL_EPARSE;
    } else if (ret != CL_CLEAN) {
        cli_mark_scan_incomplete(ctx, "ELF section-header parsing failed before inspection completed");
        return ret;
    }

    return CL_CLEAN;
}

/* ELF header parsing only
 * Returns 0 on success, -1 on error
 */
cl_error_t cli_elfheader(cli_ctx *ctx, struct cli_exe_info *elfinfo)
{
    union elf_file_hdr file_hdr;
    uint8_t conv = 0, is64 = 0;
    cl_error_t ret = CL_SUCCESS;

    cli_dbgmsg("in cli_elfheader\n");

    if (ctx == NULL)
        return CL_ENULLARG;
    if (elfinfo == NULL)
        return CL_ENULLARG;
    if (ctx->fmap == NULL) {
        cli_mark_scan_incomplete(ctx, "ELF input map is unavailable");
        return CL_EPARSE;
    }

    // TODO This code assumes elfinfo->offset == 0, which might not always
    // be the case.  For now just print this debug message and continue on
    if (0 != elfinfo->offset) {
        cli_dbgmsg("cli_elfheader: Assumption Violated: elfinfo->offset != 0\n");
    }

    ret = cli_elf_fileheader(NULL, ctx->fmap, &file_hdr, &conv, &is64);
    if (ret != CL_SUCCESS) {
        goto done;
    }

    /* Program headers and Entry */
    if (is64) {
        ret = cli_elf_ph64(NULL, ctx->fmap, elfinfo, &(file_hdr.hdr64), conv);
    } else {
        ret = cli_elf_ph32(NULL, ctx->fmap, elfinfo, &(file_hdr.hdr32.hdr), conv);
    }
    if (ret != CL_SUCCESS) {
        goto done;
    }

    /* Section Headers */
    if (is64) {
        ret = cli_elf_sh64(NULL, ctx->fmap, elfinfo, &(file_hdr.hdr64), conv);
    } else {
        ret = cli_elf_sh32(NULL, ctx->fmap, elfinfo, &(file_hdr.hdr32.hdr), conv);
    }
    if (ret != CL_SUCCESS) {
        goto done;
    }

    if (elfinfo->legacy_metadata_incomplete) {
        cli_mark_scan_incomplete(ctx, "ELF64 coordinates exceed the legacy 32-bit metadata ABI");
    }

done:

    if (ctx && ret != CL_SUCCESS && ret != CL_VIRUS && ret != CL_VERIFIED)
        cli_mark_scan_incomplete(ctx, "ELF metadata parsing ended before inspection completed");

    return ret;
}

/*
 * ELF file unpacking.
 */
cl_error_t cli_unpackelf(cli_ctx *ctx)
{
    cl_error_t ret = CL_SUCCESS;
    char *tempfile = NULL;
    int ndesc      = -1;
    uint64_t temporary_reserved = 0;
    struct cli_bc_ctx *bc_ctx;

    if (ctx == NULL)
        return CL_ENULLARG;
    if (ctx->fmap == NULL) {
        cli_mark_scan_incomplete(ctx, "ELF input map is unavailable");
        return CL_EPARSE;
    }
    if (ctx->engine == NULL)
        return CL_ENULLARG;

    /* Bytecode BC_ELF_UNPACKER hook */
    bc_ctx = cli_bytecode_context_alloc();
    if (!bc_ctx) {
        cli_errmsg("cli_scanelf: can't allocate memory for bc_ctx\n");
        cli_mark_scan_incomplete(ctx, "ELF bytecode unpacker context could not be allocated");
        ret = CL_EMEM;
        goto done;
    }

    cli_bytecode_context_setctx(bc_ctx, ctx);

    cli_dbgmsg("Running bytecode hook\n");
    ret = cli_bytecode_runhook(ctx, ctx->engine, bc_ctx, BC_ELF_UNPACKER, ctx->fmap);
    cli_dbgmsg("Finished running bytecode hook\n");
    if (CL_SUCCESS == ret) {
        // check for unpacked/rebuilt executable
        ndesc = cli_bytecode_context_getresult_file(bc_ctx, &tempfile, &temporary_reserved);
        if (ndesc != -1 && tempfile) {
            cli_dbgmsg("cli_scanelf: Unpacked and rebuilt ELF executable saved in %s\n", tempfile);

            if (lseek(ndesc, 0, SEEK_SET) == (off_t)-1) {
                cli_mark_scan_incomplete(ctx, "ELF unpacked output could not be rewound");
                ret = CL_ESEEK;
            } else {
                cli_dbgmsg("***** Scanning rebuilt ELF file *****\n");
                if (temporary_reserved)
                    ret = cli_magic_scan_desc_type_reserved(ndesc, tempfile, ctx, CL_TYPE_ANY, NULL, LAYER_ATTRIBUTES_NONE);
                else
                    ret = cli_magic_scan_desc(ndesc, tempfile, ctx, NULL, LAYER_ATTRIBUTES_NONE);
            }
        }
    }

done:
    // cli_bytecode_context_getresult_file() gives up ownership of temp file, so we must clean it up.
    if (-1 != ndesc) {
        if (close(ndesc) != 0) {
            cli_mark_scan_incomplete(ctx, "ELF unpacked output could not be closed");
            ret = cli_merge_cleanup_status(ret, CL_EWRITE);
        }
    }
    if (NULL != tempfile) {
        if (!ctx->engine->keeptmp) {
            if (cli_unlink(tempfile) != 0) {
                cli_mark_scan_incomplete(ctx, "ELF unpacked output could not be removed");
                ret = cli_merge_cleanup_status(ret, CL_EUNLINK);
            }
        }
        free(tempfile);
    }

    if (temporary_reserved)
        cli_scan_release_temporary(ctx, temporary_reserved);

    if (NULL != bc_ctx) {
        cli_bytecode_context_destroy(bc_ctx);
    }

    return ret;
}
