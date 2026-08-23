/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm <tkojm@clamav.net>
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

#include <stdio.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "clamav.h"
#include "others.h"
#include "macho.h"
#include "execs.h"
#include "scanners.h"

#define CLI_TMPUNLK()               \
    if (!ctx->engine->keeptmp) {    \
        if (cli_unlink(tempfile)) { \
            free(tempfile);         \
            return CL_EUNLINK;      \
        }                           \
    }

#define EC32(v, conv) (conv ? cbswap32(v) : v)
#define EC64(v, conv) (conv ? cbswap64(v) : v)

struct macho_hdr {
    uint32_t magic;
    uint32_t cpu_type;
    uint32_t cpu_subtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
};

struct macho_load_cmd {
    uint32_t cmd;
    uint32_t cmdsize;
};

struct macho_segment_cmd {
    char segname[16];
    uint32_t vmaddr;
    uint32_t vmsize;
    uint32_t fileoff;
    uint32_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t nsects;
    uint32_t flags;
};

struct macho_segment_cmd64 {
    char segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t nsects;
    uint32_t flags;
};

struct macho_section {
    char sectname[16];
    char segname[16];
    uint32_t addr;
    uint32_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t res1;
    uint32_t res2;
};

struct macho_section64 {
    char sectname[16];
    char segname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t res1;
    uint32_t res2;
};

struct macho_thread_state_ppc {
    uint32_t srr0; /* PC */
    uint32_t srr1;
    uint32_t reg[32];
    uint32_t cr;
    uint32_t xer;
    uint32_t lr;
    uint32_t ctr;
    uint32_t mq;
    uint32_t vrsave;
};

struct macho_thread_state_ppc64 {
    uint64_t srr0; /* PC */
    uint64_t srr1;
    uint64_t reg[32];
    uint32_t cr;
    uint64_t xer;
    uint64_t lr;
    uint64_t ctr;
    uint32_t vrsave;
};

struct macho_thread_state_x86 {
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    uint32_t edi;
    uint32_t esi;
    uint32_t ebp;
    uint32_t esp;
    uint32_t ss;
    uint32_t eflags;
    uint32_t eip;
    uint32_t cs;
    uint32_t ds;
    uint32_t es;
    uint32_t fs;
    uint32_t gs;
};

struct macho_fat_header {
    uint32_t magic;
    uint32_t nfats;
};

struct macho_fat_arch {
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t offset;
    uint32_t size;
    uint32_t align;
};

static size_t cli_macho_readn(fmap_t *map, uint64_t at, void *dst, size_t len)
{
    /* fmap_readn() uses (size_t)-1 for both callback failures and an offset
     * beyond the map. Preserve an impossible Mach-O coordinate as short
     * input; only an in-range callback failure for a fully available
     * structure is an operational read error. */
    if (at > (uint64_t)map->len)
        return 0;
    if (len > map->len - (size_t)at)
        return 0;
    return fmap_readn(map, dst, (size_t)at, len);
}

static cl_error_t cli_macho_read_status(size_t bytes_read, size_t expected)
{
    if (bytes_read == expected)
        return CL_SUCCESS;
    if (bytes_read == (size_t)-1)
        return CL_EREAD;
    return CL_BREAK;
}

static cl_error_t cli_macho_broken_result(cli_ctx *ctx, cl_error_t fallback, const char *incomplete_reason)
{
    cl_error_t ret;

    if (ctx && SCAN_HEURISTIC_BROKEN) {
        ret = cli_append_potentially_unwanted(ctx, "Heuristics.Broken.Executable");
        if (ret != CL_SUCCESS) {
            if (ret != CL_VIRUS && ret != CL_VERIFIED && ret != CL_BREAK)
                cli_mark_scan_incomplete(ctx, "Mach-O broken-executable heuristic alert could not be recorded");
            return ret;
        }
    }

    if (ctx && incomplete_reason)
        cli_mark_scan_incomplete(ctx, incomplete_reason);
    return fallback;
}

#define RETURN_BROKEN \
    return cli_macho_broken_result(ctx, CL_EPARSE, "Mach-O universal-binary parsing ended before inspection completed")

#define RETURN_MACHO_BROKEN \
    return cli_macho_broken_result(ctx, CL_EPARSE, get_fileinfo ? NULL : "Mach-O parsing ended before inspection completed")

static uint32_t cli_rawaddr(uint32_t vaddr, struct cli_exe_section *sects, uint16_t nsects, unsigned int *err)
{
    unsigned int i, found = 0;

    for (i = 0; i < nsects; i++) {
        if (sects[i].rva <= vaddr && vaddr - sects[i].rva < sects[i].vsz) {
            found = 1;
            break;
        }
    }

    if (!found || UINT32_MAX - sects[i].raw < vaddr - sects[i].rva) {
        *err = 1;
        return 0;
    }

    *err = 0;
    return vaddr - sects[i].rva + sects[i].raw;
}

static uint64_t cli_rawaddr64(uint64_t vaddr, struct cli_exe_section64 *sects, uint16_t nsects, unsigned int *err)
{
    unsigned int i, found = 0;

    for (i = 0; i < nsects; i++) {
        if (sects[i].rva <= vaddr && vaddr - sects[i].rva < sects[i].vsz) {
            found = 1;
            break;
        }
    }

    if (!found || UINT64_MAX - sects[i].raw < vaddr - sects[i].rva) {
        *err = 1;
        return 0;
    }

    *err = 0;
    return sects[i].raw + vaddr - sects[i].rva;
}

cl_error_t cli_scanmacho(cli_ctx *ctx, struct cli_exe_info *fileinfo)
{
    struct macho_hdr hdr;
    struct macho_load_cmd load_cmd;
    struct macho_segment_cmd segment_cmd;
    struct macho_segment_cmd64 segment_cmd64;
    struct macho_section section;
    struct macho_section64 section64;
    unsigned int i, j, sect = 0, conv, m64, nsects;
    bool get_fileinfo = false;
    unsigned int arch = 0, err;
    uint64_t ep = 0;
    struct cli_exe_section *sections = NULL;
    struct cli_exe_section64 *sections64 = NULL;
    char name[16];
    fmap_t *map;
    uint64_t at;
    cl_error_t read_status;

    if (ctx == NULL) {
        cli_dbgmsg("Mach-O: passed context was NULL\n");
        return CL_EARG;
    }
    if (ctx->fmap == NULL) {
        cli_mark_scan_incomplete(ctx, "Mach-O input map is unavailable");
        return CL_EPARSE;
    }
    map = ctx->fmap;

    read_status = cli_checktimelimit(ctx);
    if (read_status != CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, "Mach-O inspection reached the configured time limit");
        return read_status;
    }

    if (fileinfo) {
        get_fileinfo = true;

        // TODO This code assumes fileinfo->offset == 0, which might not always
        // be the case.  For now just print this debug message and continue on
        if (0 != fileinfo->offset) {
            cli_dbgmsg("cli_scanmacho: Assumption Violated: fileinfo->offset != 0\n");
        }
    }

    read_status = cli_macho_read_status(cli_macho_readn(map, 0, &hdr, sizeof(hdr)), sizeof(hdr));
    if (read_status != CL_SUCCESS) {
        cli_dbgmsg("cli_scanmacho: Can't read header\n");
        if (read_status == CL_EREAD) {
            if (!get_fileinfo)
                cli_mark_scan_incomplete(ctx, "Mach-O header could not be read completely");
            return CL_EREAD;
        }
        if (!get_fileinfo)
            cli_mark_scan_incomplete(ctx, "Mach-O header parsing ended before inspection completed");
        return get_fileinfo ? CL_EFORMAT : CL_EPARSE;
    }
    at = sizeof(hdr);

    if (hdr.magic == 0xfeedface) {
        conv = 0;
        m64  = 0;
    } else if (hdr.magic == 0xcefaedfe) {
        conv = 1;
        m64  = 0;
    } else if (hdr.magic == 0xfeedfacf) {
        conv = 0;
        m64  = 1;
    } else if (hdr.magic == 0xcffaedfe) {
        conv = 1;
        m64  = 1;
    } else {
        cli_dbgmsg("cli_scanmacho: Incorrect magic\n");
        if (!get_fileinfo)
            cli_mark_scan_incomplete(ctx, "Mach-O header has invalid magic");
        return get_fileinfo ? CL_EFORMAT : CL_EPARSE;
    }

    switch (EC32(hdr.cpu_type, conv)) {
        case 7:
            if (!get_fileinfo)
                cli_dbgmsg("MACHO: CPU Type: Intel 32-bit\n");
            arch = 1;
            break;
        case 7 | 0x1000000:
            if (!get_fileinfo)
                cli_dbgmsg("MACHO: CPU Type: Intel 64-bit\n");
            break;
        case 12:
            if (!get_fileinfo)
                cli_dbgmsg("MACHO: CPU Type: ARM\n");
            break;
        case 14:
            if (!get_fileinfo)
                cli_dbgmsg("MACHO: CPU Type: SPARC\n");
            break;
        case 18:
            if (!get_fileinfo)
                cli_dbgmsg("MACHO: CPU Type: POWERPC 32-bit\n");
            arch = 2;
            break;
        case 18 | 0x1000000:
            if (!get_fileinfo)
                cli_dbgmsg("MACHO: CPU Type: POWERPC 64-bit\n");
            arch = 3;
            break;
        default:
            if (!get_fileinfo)
                cli_dbgmsg("MACHO: CPU Type: ** UNKNOWN ** (%u)\n", EC32(hdr.cpu_type, conv));
            break;
    }

    if (!get_fileinfo) switch (EC32(hdr.filetype, conv)) {
            case 0x1: /* MH_OBJECT */
                cli_dbgmsg("MACHO: Filetype: Relocatable object file\n");
                break;
            case 0x2: /* MH_EXECUTE */
                cli_dbgmsg("MACHO: Filetype: Executable\n");
                break;
            case 0x3: /* MH_FVMLIB */
                cli_dbgmsg("MACHO: Filetype: Fixed VM shared library file\n");
                break;
            case 0x4: /* MH_CORE */
                cli_dbgmsg("MACHO: Filetype: Core file\n");
                break;
            case 0x5: /* MH_PRELOAD */
                cli_dbgmsg("MACHO: Filetype: Preloaded executable file\n");
                break;
            case 0x6: /* MH_DYLIB */
                cli_dbgmsg("MACHO: Filetype: Dynamically bound shared library\n");
                break;
            case 0x7: /* MH_DYLINKER */
                cli_dbgmsg("MACHO: Filetype: Dynamic link editor\n");
                break;
            case 0x8: /* MH_BUNDLE */
                cli_dbgmsg("MACHO: Filetype: Dynamically bound bundle file\n");
                break;
            case 0x9: /* MH_DYLIB_STUB */
                cli_dbgmsg("MACHO: Filetype: Shared library stub for static\n");
                break;
            default:
                cli_dbgmsg("MACHO: Filetype: ** UNKNOWN ** (0x%x)\n", EC32(hdr.filetype, conv));
        }

    if (!get_fileinfo) {
        cli_dbgmsg("MACHO: Number of load commands: %u\n", EC32(hdr.ncmds, conv));
        cli_dbgmsg("MACHO: Size of load commands: %u\n", EC32(hdr.sizeofcmds, conv));
    }

    if (m64)
        at += 4;

    hdr.ncmds = EC32(hdr.ncmds, conv);
    if (!hdr.ncmds || hdr.ncmds > 1024) {
        cli_dbgmsg("cli_scanmacho: Invalid number of load commands (%u)\n", hdr.ncmds);
        RETURN_MACHO_BROKEN;
    }

    for (i = 0; i < hdr.ncmds; i++) {
        read_status = cli_checktimelimit(ctx);
        if (read_status != CL_SUCCESS) {
            free(sections);
            free(sections64);
            cli_mark_scan_incomplete(ctx, "Mach-O load-command traversal reached the configured time limit");
            return read_status;
        }

        read_status = cli_macho_read_status(cli_macho_readn(map, at, &load_cmd, sizeof(load_cmd)), sizeof(load_cmd));
        if (read_status != CL_SUCCESS) {
            cli_dbgmsg("cli_scanmacho: Can't read load command\n");
            free(sections);
            free(sections64);
            if (read_status == CL_EREAD) {
                if (!get_fileinfo)
                    cli_mark_scan_incomplete(ctx, "Mach-O load command could not be read completely");
                return CL_EREAD;
            }
            RETURN_MACHO_BROKEN;
        }
        at += sizeof(load_cmd);
        /*
        if((m64 && EC32(load_cmd.cmdsize, conv) % 8) || (!m64 && EC32(load_cmd.cmdsize, conv) % 4)) {
            cli_dbgmsg("cli_scanmacho: Invalid command size (%u)\n", EC32(load_cmd.cmdsize, conv));
            free(sections);
            RETURN_BROKEN;
        }
        */
        load_cmd.cmd = EC32(load_cmd.cmd, conv);
        if ((m64 && load_cmd.cmd == 0x19) || (!m64 && load_cmd.cmd == 0x01)) { /* LC_SEGMENT */
            if (m64) {
                read_status = cli_macho_read_status(cli_macho_readn(map, at, &segment_cmd64, sizeof(segment_cmd64)), sizeof(segment_cmd64));
                if (read_status != CL_SUCCESS) {
                    cli_dbgmsg("cli_scanmacho: Can't read segment command\n");
                    free(sections);
                    free(sections64);
                    if (read_status == CL_EREAD) {
                        if (!get_fileinfo)
                            cli_mark_scan_incomplete(ctx, "Mach-O 64-bit segment command could not be read completely");
                        return CL_EREAD;
                    }
                    RETURN_MACHO_BROKEN;
                }
                at += sizeof(segment_cmd64);
                nsects = EC32(segment_cmd64.nsects, conv);
                strncpy(name, segment_cmd64.segname, sizeof(name));
                name[sizeof(name) - 1] = '\0';
            } else {
                read_status = cli_macho_read_status(cli_macho_readn(map, at, &segment_cmd, sizeof(segment_cmd)), sizeof(segment_cmd));
                if (read_status != CL_SUCCESS) {
                    cli_dbgmsg("cli_scanmacho: Can't read segment command\n");
                    free(sections);
                    free(sections64);
                    if (read_status == CL_EREAD) {
                        if (!get_fileinfo)
                            cli_mark_scan_incomplete(ctx, "Mach-O segment command could not be read completely");
                        return CL_EREAD;
                    }
                    RETURN_MACHO_BROKEN;
                }
                at += sizeof(segment_cmd);
                nsects = EC32(segment_cmd.nsects, conv);
                strncpy(name, segment_cmd.segname, sizeof(name));
                name[sizeof(name) - 1] = '\0';
            }
            if (!get_fileinfo) {
                cli_dbgmsg("MACHO: Segment name: %s\n", name);
                cli_dbgmsg("MACHO: Number of sections: %u\n", nsects);
            }
            if (nsects > 255) {
                cli_dbgmsg("cli_scanmacho: Invalid number of sections\n");
                free(sections);
                free(sections64);
                RETURN_MACHO_BROKEN;
            }
            if (!nsects) {
                if (!get_fileinfo)
                    cli_dbgmsg("MACHO: ------------------\n");
                continue;
            }
            sections = (struct cli_exe_section *)cli_max_realloc_or_free(sections, (sect + nsects) * sizeof(struct cli_exe_section));
            if (!sections) {
                cli_errmsg("cli_scanmacho: Can't allocate memory for 'sections'\n");
                if (!get_fileinfo)
                    cli_mark_scan_incomplete(ctx, "Mach-O section table could not be allocated");
                free(sections64);
                return CL_EMEM;
            }
            if (m64) {
                sections64 = (struct cli_exe_section64 *)cli_max_realloc_or_free(
                    sections64, (sect + nsects) * sizeof(struct cli_exe_section64));
                if (!sections64) {
                    cli_errmsg("cli_scanmacho: Can't allocate memory for native-width sections\n");
                    if (!get_fileinfo)
                        cli_mark_scan_incomplete(ctx, "Mach-O native-width section table could not be allocated");
                    free(sections);
                    return CL_EMEM;
                }
            }

            for (j = 0; j < nsects; j++) {
                read_status = cli_checktimelimit(ctx);
                if (read_status != CL_SUCCESS) {
                    free(sections);
                    free(sections64);
                    cli_mark_scan_incomplete(ctx, "Mach-O section traversal reached the configured time limit");
                    return read_status;
                }

                if (m64) {
                    read_status = cli_macho_read_status(cli_macho_readn(map, at, &section64, sizeof(section64)), sizeof(section64));
                    if (read_status != CL_SUCCESS) {
                        cli_dbgmsg("cli_scanmacho: Can't read section\n");
                        free(sections);
                        free(sections64);
                        if (read_status == CL_EREAD) {
                            if (!get_fileinfo)
                                cli_mark_scan_incomplete(ctx, "Mach-O 64-bit section could not be read completely");
                            return CL_EREAD;
                        }
                        RETURN_MACHO_BROKEN;
                    }
                    at += sizeof(section64);
                    sections64[sect].rva = EC64(section64.addr, conv);
                    sections64[sect].vsz = EC64(section64.size, conv);
                    sections64[sect].raw = EC32(section64.offset, conv);
                    if (EC32(section64.align, conv) >= 32) {
                        cli_dbgmsg("cli_scanmacho: Section alignment exponent is malformed\n");
                        free(sections);
                        free(sections64);
                        RETURN_MACHO_BROKEN;
                    }
                    {
                        uint64_t align = UINT64_C(1) << EC32(section64.align, conv);
                        uint64_t padding = (align - (sections64[sect].vsz % align)) % align;
                        if (UINT64_MAX - sections64[sect].vsz < padding) {
                            cli_dbgmsg("cli_scanmacho: Section size alignment overflowed\n");
                            free(sections);
                            free(sections64);
                            RETURN_MACHO_BROKEN;
                        }
                        sections64[sect].rsz = sections64[sect].vsz + padding;
                    }
                    sections64[sect].urva = sections64[sect].rva;
                    sections64[sect].uvsz = sections64[sect].vsz;
                    sections64[sect].uraw = sections64[sect].raw;
                    sections64[sect].ursz = sections64[sect].rsz;
                    if (sections64[sect].rva > UINT32_MAX || sections64[sect].vsz > UINT32_MAX ||
                        sections64[sect].raw > UINT32_MAX || sections64[sect].rsz > UINT32_MAX) {
                        memset(&sections[sect], 0, sizeof(sections[sect]));
                        if (get_fileinfo)
                            fileinfo->legacy_metadata_incomplete = 1;
                    } else {
                        sections[sect].rva = (uint32_t)sections64[sect].rva;
                        sections[sect].vsz = (uint32_t)sections64[sect].vsz;
                        sections[sect].raw = (uint32_t)sections64[sect].raw;
                        sections[sect].rsz = (uint32_t)sections64[sect].rsz;
                    }
                    strncpy(name, section64.sectname, sizeof(name));
                    name[sizeof(name) - 1] = '\0';
                } else {
                    read_status = cli_macho_read_status(cli_macho_readn(map, at, &section, sizeof(section)), sizeof(section));
                    if (read_status != CL_SUCCESS) {
                        cli_dbgmsg("cli_scanmacho: Can't read section\n");
                        free(sections);
                        free(sections64);
                        if (read_status == CL_EREAD) {
                            if (!get_fileinfo)
                                cli_mark_scan_incomplete(ctx, "Mach-O section could not be read completely");
                            return CL_EREAD;
                        }
                        RETURN_MACHO_BROKEN;
                    }
                    at += sizeof(section);
                    sections[sect].rva = EC32(section.addr, conv);
                    sections[sect].vsz = EC32(section.size, conv);
                    sections[sect].raw = EC32(section.offset, conv);
                    if (EC32(section.align, conv) >= 32) {
                        cli_dbgmsg("cli_scanmacho: Section aligned is malformed\n");
                        free(sections);
                        free(sections64);
                        RETURN_MACHO_BROKEN;
                    }
                    section.align = 1U << EC32(section.align, conv);
                    {
                        uint64_t padding = ((uint64_t)section.align - ((uint64_t)sections[sect].vsz % section.align)) % section.align;

                        if (padding > UINT32_MAX - sections[sect].vsz) {
                            cli_dbgmsg("cli_scanmacho: 32-bit section size alignment overflowed\n");
                            free(sections);
                            free(sections64);
                            RETURN_MACHO_BROKEN;
                        }
                        sections[sect].rsz = (uint32_t)((uint64_t)sections[sect].vsz + padding);
                    }
                    strncpy(name, section.sectname, sizeof(name));
                    name[sizeof(name) - 1] = '\0';
                }
                if (!get_fileinfo) {
                    cli_dbgmsg("MACHO: --- Section %u ---\n", sect);
                    cli_dbgmsg("MACHO: Name: %s\n", name);
                    cli_dbgmsg("MACHO: Virtual address: 0x" STDx64 "\n", sections64 ? sections64[sect].rva : (uint64_t)sections[sect].rva);
                    cli_dbgmsg("MACHO: Virtual size: %u\n", (unsigned int)sections[sect].vsz);
                    cli_dbgmsg("MACHO: Raw size: %u\n", (unsigned int)sections[sect].rsz);
                    if (sections[sect].raw)
                        cli_dbgmsg("MACHO: File offset: %u\n", (unsigned int)sections[sect].raw);
                }
                sect++;
            }
            if (!get_fileinfo)
                cli_dbgmsg("MACHO: ------------------\n");

        } else if (arch && (load_cmd.cmd == 0x4 || load_cmd.cmd == 0x5)) { /* LC_(UNIX)THREAD */
            at += 8;
            switch (arch) {
                case 1: /* x86 */
                {
                    struct macho_thread_state_x86 thread_state_x86;

                    read_status = cli_macho_read_status(cli_macho_readn(map, at, &thread_state_x86, sizeof(thread_state_x86)), sizeof(thread_state_x86));
                    if (read_status != CL_SUCCESS) {
                        cli_dbgmsg("cli_scanmacho: Can't read thread_state_x86\n");
                        free(sections);
                        free(sections64);
                        if (read_status == CL_EREAD) {
                            if (!get_fileinfo)
                                cli_mark_scan_incomplete(ctx, "Mach-O x86 thread state could not be read completely");
                            return CL_EREAD;
                        }
                        RETURN_MACHO_BROKEN;
                    }
                    at += sizeof(thread_state_x86);
                    break;
                }

                case 2: /* PPC */
                {
                    struct macho_thread_state_ppc thread_state_ppc;

                    read_status = cli_macho_read_status(cli_macho_readn(map, at, &thread_state_ppc, sizeof(thread_state_ppc)), sizeof(thread_state_ppc));
                    if (read_status != CL_SUCCESS) {
                        cli_dbgmsg("cli_scanmacho: Can't read thread_state_ppc\n");
                        free(sections);
                        free(sections64);
                        if (read_status == CL_EREAD) {
                            if (!get_fileinfo)
                                cli_mark_scan_incomplete(ctx, "Mach-O PPC thread state could not be read completely");
                            return CL_EREAD;
                        }
                        RETURN_MACHO_BROKEN;
                    }
                    at += sizeof(thread_state_ppc);
                    ep = EC32(thread_state_ppc.srr0, conv);
                    break;
                }

                case 3: /* PPC64 */
                {
                    struct macho_thread_state_ppc64 thread_state_ppc64;

                    read_status = cli_macho_read_status(cli_macho_readn(map, at, &thread_state_ppc64, sizeof(thread_state_ppc64)), sizeof(thread_state_ppc64));
                    if (read_status != CL_SUCCESS) {
                        cli_dbgmsg("cli_scanmacho: Can't read thread_state_ppc64\n");
                        free(sections);
                        free(sections64);
                        if (read_status == CL_EREAD) {
                            if (!get_fileinfo)
                                cli_mark_scan_incomplete(ctx, "Mach-O PPC64 thread state could not be read completely");
                            return CL_EREAD;
                        }
                        RETURN_MACHO_BROKEN;
                    }
                    at += sizeof(thread_state_ppc64);
                    ep = EC64(thread_state_ppc64.srr0, conv);
                    break;
                }
                default:
                    cli_errmsg("cli_scanmacho: Invalid arch setting!\n");
                    free(sections);
                    free(sections64);
                    return CL_EARG;
            }
        } else {
            if (EC32(load_cmd.cmdsize, conv) > sizeof(load_cmd))
                at += EC32(load_cmd.cmdsize, conv) - sizeof(load_cmd);
        }
    }

    if (ep) {
        if (!get_fileinfo)
            cli_dbgmsg("Entry Point: 0x" STDx64 "\n", ep);
        if (sections) {
            if (m64)
                ep = cli_rawaddr64(ep, sections64, sect, &err);
            else if (ep <= UINT32_MAX)
                ep = cli_rawaddr((uint32_t)ep, sections, sect, &err);
            else
                err = 1;
            if (err) {
                cli_dbgmsg("cli_scanmacho: Can't calculate EP offset\n");
                free(sections);
                free(sections64);
                if (!get_fileinfo)
                    cli_mark_scan_incomplete(ctx, "Mach-O entry-point mapping ended before inspection completed");
                return get_fileinfo ? CL_EFORMAT : CL_EPARSE;
            }
            if (!get_fileinfo)
                cli_dbgmsg("Entry Point file offset: " STDu64 "\n", ep);
        }
    }

    if (get_fileinfo) {
        if (m64) {
            fileinfo->ep64 = ep;
            fileinfo->has_native_coordinates = 1;
            if (ep <= UINT32_MAX)
                fileinfo->ep = (uint32_t)ep;
            else {
                fileinfo->ep = 0;
                fileinfo->legacy_metadata_incomplete = 1;
            }
            fileinfo->sections64 = sections64;
            sections64 = NULL;
        } else {
            fileinfo->ep = (uint32_t)ep;
        }
        fileinfo->nsections = sect;
        fileinfo->sections  = sections;
    } else {
        free(sections);
        free(sections64);
    }

    return CL_SUCCESS;
}

cl_error_t cli_machoheader(cli_ctx *ctx, struct cli_exe_info *fileinfo)
{
    cl_error_t ret = cli_scanmacho(ctx, fileinfo);

    if (ret != CL_SUCCESS && ret != CL_VIRUS && ret != CL_VERIFIED)
        cli_mark_scan_incomplete(ctx, "Mach-O metadata parsing ended before inspection completed");
    else if (ret == CL_SUCCESS && fileinfo && fileinfo->legacy_metadata_incomplete)
        cli_mark_scan_incomplete(ctx, "Mach-O coordinates exceed the legacy 32-bit metadata ABI");

    return ret;
}

cl_error_t cli_scanmacho_unibin(cli_ctx *ctx)
{
    struct macho_fat_header fat_header;
    struct macho_fat_arch fat_arch;
    unsigned int conv, i;
    cl_error_t ret = CL_SUCCESS;
    cl_error_t read_status;
    fmap_t *map;
    uint64_t at;

    if (ctx == NULL) {
        cli_dbgmsg("Mach-O universal-binary: passed context was NULL\n");
        return CL_EARG;
    }
    if (ctx->fmap == NULL) {
        cli_mark_scan_incomplete(ctx, "Mach-O universal-binary input map is unavailable");
        return CL_EPARSE;
    }
    map = ctx->fmap;

    read_status = cli_checktimelimit(ctx);
    if (read_status != CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, "Mach-O universal-binary inspection reached the configured time limit");
        return read_status;
    }

    read_status = cli_macho_read_status(cli_macho_readn(map, 0, &fat_header, sizeof(fat_header)), sizeof(fat_header));
    if (read_status != CL_SUCCESS) {
        cli_dbgmsg("cli_scanmacho_unibin: Can't read fat_header\n");
        if (read_status == CL_EREAD) {
            cli_mark_scan_incomplete(ctx, "Mach-O universal-binary header could not be read completely");
            return CL_EREAD;
        }
        cli_mark_scan_incomplete(ctx, "Mach-O universal-binary header parsing ended before inspection completed");
        return CL_EPARSE;
    }
    at = sizeof(fat_header);

    if (fat_header.magic == 0xcafebabe) {
        conv = 0;
    } else if (fat_header.magic == 0xbebafeca) {
        conv = 1;
    } else {
        cli_dbgmsg("cli_scanmacho_unibin: Incorrect magic\n");
        cli_mark_scan_incomplete(ctx, "Mach-O universal-binary header has invalid magic");
        return CL_EPARSE;
    }

    fat_header.nfats = EC32(fat_header.nfats, conv);
    if ((fat_header.nfats & 0xffff) >= 39) /* Java Bytecode */
        return CL_CLEAN;

    if (fat_header.nfats > 32) {
        cli_dbgmsg("cli_scanmacho_unibin: Invalid number of architectures\n");
        cli_mark_scan_incomplete(ctx, "Mach-O universal-binary architecture table is invalid");
        return CL_EPARSE;
    }
    cli_dbgmsg("UNIBIN: Number of architectures: %u\n", (unsigned int)fat_header.nfats);
    for (i = 0; i < fat_header.nfats; i++) {
        uint64_t member_end;

        read_status = cli_checktimelimit(ctx);
        if (read_status != CL_SUCCESS) {
            cli_mark_scan_incomplete(ctx, "Mach-O universal-binary traversal reached the configured time limit");
            return read_status;
        }

        read_status = cli_macho_read_status(cli_macho_readn(map, at, &fat_arch, sizeof(fat_arch)), sizeof(fat_arch));
        if (read_status != CL_SUCCESS) {
            cli_dbgmsg("cli_scanmacho_unibin: Can't read fat_arch\n");
            if (read_status == CL_EREAD) {
                cli_mark_scan_incomplete(ctx, "Mach-O universal-binary architecture header could not be read completely");
                return CL_EREAD;
            }
            RETURN_BROKEN;
        }
        at += sizeof(fat_arch);
        fat_arch.offset = EC32(fat_arch.offset, conv);
        fat_arch.size   = EC32(fat_arch.size, conv);
        cli_dbgmsg("UNIBIN: Binary %u of %u\n", i + 1, fat_header.nfats);
        cli_dbgmsg("UNIBIN: File offset: %u\n", fat_arch.offset);
        cli_dbgmsg("UNIBIN: File size: %u\n", fat_arch.size);

        /* The offset must be greater than the location of the header or we risk
           re-scanning the same data over and over again. The scan recursion max
           will save us, but it will still cause other problems and waste CPU. */
        if (fat_arch.offset < at) {
            cli_dbgmsg("Invalid fat offset: %d\n", fat_arch.offset);
            RETURN_BROKEN;
        }

        member_end = (uint64_t)fat_arch.offset + (uint64_t)fat_arch.size;
        if (member_end < fat_arch.offset || member_end > (uint64_t)map->len) {
            cli_dbgmsg("cli_scanmacho_unibin: Architecture range is outside the input map\n");
            cli_mark_scan_incomplete(ctx, "Mach-O universal-binary architecture range is outside the input map");
            ret = CL_EPARSE;
            break;
        }

        read_status = cli_checktimelimit(ctx);
        if (read_status != CL_SUCCESS) {
            cli_mark_scan_incomplete(ctx, "Mach-O universal-binary member traversal reached the configured time limit");
            return read_status;
        }

        ret = cli_magic_scan_nested_fmap_type(map, fat_arch.offset, fat_arch.size, ctx, CL_TYPE_ANY, NULL, LAYER_ATTRIBUTES_NONE);
        if (ret != CL_SUCCESS) {
            break;
        }
    }

    return ret; /* result from the last binary */
}

cl_error_t cli_unpackmacho(cli_ctx *ctx)
{
    cl_error_t ret = CL_SUCCESS;
    char *tempfile = NULL;
    int ndesc      = -1;
    uint64_t temporary_reserved = 0;
    struct cli_bc_ctx *bc_ctx;

    /* Bytecode BC_MACHO_UNPACKER hook */
    bc_ctx = cli_bytecode_context_alloc();
    if (!bc_ctx) {
        cli_errmsg("cli_unpackmacho: can't allocate memory for bc_ctx\n");
        cli_mark_scan_incomplete(ctx, "Mach-O bytecode unpacker context could not be allocated");
        ret = CL_EMEM;
        goto done;
    }

    cli_bytecode_context_setctx(bc_ctx, ctx);

    cli_dbgmsg("Running bytecode hook\n");
    ret = cli_bytecode_runhook(ctx, ctx->engine, bc_ctx, BC_MACHO_UNPACKER, ctx->fmap);
    cli_dbgmsg("Finished running bytecode hook\n");
    if (CL_SUCCESS == ret) {
        // check for unpacked/rebuilt executable
        ndesc = cli_bytecode_context_getresult_file(bc_ctx, &tempfile, &temporary_reserved);
        if (ndesc != -1 && tempfile) {
            cli_dbgmsg("cli_unpackmacho: Unpacked and rebuilt Mach-O executable saved in %s\n", tempfile);

            if (lseek(ndesc, 0, SEEK_SET) == (off_t)-1) {
                cli_mark_scan_incomplete(ctx, "Mach-O unpacked output could not be rewound");
                ret = CL_ESEEK;
            } else {
                cli_dbgmsg("***** Scanning rebuilt Mach-O file *****\n");
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
            cli_mark_scan_incomplete(ctx, "Mach-O unpacked output could not be closed");
            if (ret == CL_SUCCESS || ret == CL_VERIFIED || ret == CL_BREAK)
                ret = CL_EWRITE;
        }
    }
    if (NULL != tempfile) {
        if (!ctx->engine->keeptmp) {
            if (cli_unlink(tempfile) != 0) {
                cli_mark_scan_incomplete(ctx, "Mach-O unpacked output could not be removed");
                if (ret == CL_SUCCESS || ret == CL_VERIFIED || ret == CL_BREAK)
                    ret = CL_EUNLINK;
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
