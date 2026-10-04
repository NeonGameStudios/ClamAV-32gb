/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Ivan Zlatev
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

/* Decrypts files, protected by Y0da Cryptor 1.3 */

/* aCaB:
 * 13/01/2006 - merged standalone unpacker into libclamav
 * 14/01/2006 - major rewrite and bugfix
 */

#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <limits.h>
#include <sys/types.h>

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "clamav.h"
#include "pe.h"
#include "others.h"
#include "fmap.h"
#include "yc.h"

#define EC16(x) le16_to_host(x) /* Convert little endian to host */

#define DO_HEURISTIC 1
#define YC_DECRYPTOR_SIZE 0x30U
#define YC_IO_CHUNK_SIZE (64U * 1024U)

int cli_yc_adjusted_window_offset(uint32_t base_offset, int32_t adjustment,
                                  size_t available, size_t needed,
                                  size_t *offset)
{
    int64_t adjusted;

    if (offset == NULL)
        return -1;

    adjusted = (int64_t)base_offset + adjustment;
    if (adjusted < 0 || (uint64_t)adjusted > available ||
        needed > available - (size_t)adjusted)
        return -1;

    *offset = (size_t)adjusted;
    return 0;
}

static int yc_parse_failure(cli_ctx *ctx, const char *reason)
{
    cli_mark_scan_incomplete(ctx, reason);
    return CL_EPARSE;
}

static cl_error_t yc_bounds_failure(cli_ctx *ctx)
{
    cli_dbgmsg("yC: Bounds check assertion.\n");
#if DO_HEURISTIC
    cli_append_potentially_unwanted(ctx, "Heuristics.BoundsCheck");
#endif
    return CL_VIRUS;
}

static int yc_checktimelimit(cli_ctx *ctx, uint32_t *ticks)
{
    if (ctx == NULL)
        return 0;

    (*ticks)++;
    if (*ticks < 4096)
        return 0;

    *ticks = 0;
    if (cli_checktimelimit(ctx) != CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, "yC emulation reached the configured time limit");
        return 1;
    }

    return 0;
}

/* ========================================================================== */
/* "Emulates" the poly decryptors */

static cl_error_t yc_poly_emulator_block(cli_ctx *ctx,
                                         const uint8_t *decryptor,
                                         size_t decryptor_size,
                                         uint8_t *code,
                                         size_t code_size,
                                         uint8_t *cl,
                                         uint32_t *ticks,
                                         uint32_t *max_jmp_loop)
{

    /*
     This is the instruction set of the poly code.
     Numbers stand for example only.

     2C 05            SUB AL,5
     2AC1             SUB AL,CL
     34 10            XOR AL,10
     32C1             XOR AL,CL
     FEC8             DEC AL
     04 10            ADD AL,10
     02C1             ADD AL,CL
     C0C0 06          ROL AL,6
     C0C8 05          ROR AL,5
     D2C8             ROR AL,CL
     D2C0             ROL AL,CL

  */
    unsigned char al;
    unsigned int j;
    size_t i;

    if (decryptor == NULL || decryptor_size != YC_DECRYPTOR_SIZE ||
        code == NULL || cl == NULL || ticks == NULL || max_jmp_loop == NULL)
        return yc_bounds_failure(ctx);

    for (i = 0; i < code_size; i++) /* Byte looper - Decrypts every byte and write it back */
    {
        if (yc_checktimelimit(ctx, ticks))
            return CL_ETIMEOUT;
        al = code[i];

        for (j = 0; j < YC_DECRYPTOR_SIZE; j++) /* Poly Decryptor "Emulator" */
        {
            if (yc_checktimelimit(ctx, ticks))
                return CL_ETIMEOUT;
            if ((size_t)j >= decryptor_size)
                return yc_bounds_failure(ctx);

            switch (decryptor[j]) {

                case 0xEB: /* JMP short */
                    j++;
                    if ((size_t)j >= decryptor_size)
                        return yc_bounds_failure(ctx);
                    if (!*max_jmp_loop)
                        return yc_bounds_failure(ctx);
                    (*max_jmp_loop)--;
                    {
                        int64_t target = (int64_t)j + (int8_t)decryptor[j];
                        if (target < 0 || target > UINT_MAX - 1U)
                            return yc_bounds_failure(ctx);
                        j = (unsigned int)target;
                    }
                    break;

                case 0xFE: /* DEC  AL */
                    al--;
                    j++;
                    break;

                case '\x2A': /* SUB AL,CL */
                    al = al - *cl;
                    j++;
                    break;

                case '\x02': /* ADD AL,CL */
                    al = al + *cl;
                    j++;
                    break;
                case '\x32': /* XOR AL,CL */
                    al = al ^ *cl;
                    j++;
                    break;
                    ;
                case '\x04': /* ADD AL,num */
                    j++;
                    if ((size_t)j >= decryptor_size)
                        return yc_bounds_failure(ctx);
                    al = al + decryptor[j];
                    break;
                    ;
                case '\x34': /* XOR AL,num */
                    j++;
                    if ((size_t)j >= decryptor_size)
                        return yc_bounds_failure(ctx);
                    al = al ^ decryptor[j];
                    break;

                case '\x2C': /* SUB AL,num */
                    j++;
                    if ((size_t)j >= decryptor_size)
                        return yc_bounds_failure(ctx);
                    al = al - decryptor[j];
                    break;

                case 0xC0:
                    j++;
                    if ((size_t)j >= decryptor_size)
                        return yc_bounds_failure(ctx);
                    if (decryptor[j] == 0xC0) /* ROL AL,num */
                    {
                        j++;
                        if ((size_t)j >= decryptor_size)
                            return yc_bounds_failure(ctx);
                        CLI_ROL(al, decryptor[j]);
                    } else /* ROR AL,num */
                    {
                        j++;
                        if ((size_t)j >= decryptor_size)
                            return yc_bounds_failure(ctx);
                        CLI_ROR(al, decryptor[j]);
                    }
                    break;

                case 0xD2:
                    j++;
                    if ((size_t)j >= decryptor_size)
                        return yc_bounds_failure(ctx);
                    if (decryptor[j] == 0xC8) /* ROR AL,CL */
                    {
                        j++;
                        if ((size_t)j >= decryptor_size)
                            return yc_bounds_failure(ctx);
                        CLI_ROR(al, *cl);
                    } else /* ROL AL,CL */
                    {
                        j++;
                        if ((size_t)j >= decryptor_size)
                            return yc_bounds_failure(ctx);
                        CLI_ROL(al, *cl);
                    }
                    break;

                case 0x90:
                case 0xF8:
                case 0xF9:
                    break;

                default:
                    cli_dbgmsg("yC: Unhandled opcode %x\n", (unsigned char)decryptor[j]);
                    return CL_EUNPACK;
            }
        }
        (*cl)--;
        code[i] = al;
    }
    return CL_SUCCESS;
}

static int yc_offset_to_off_t(size_t offset, off_t *converted)
{
    off_t value;

    if (converted == NULL)
        return -1;
    value = (off_t)offset;
    if (value < 0 || (uint64_t)value != (uint64_t)offset)
        return -1;
    *converted = value;
    return 0;
}

static cl_error_t yc_read_at(cli_ctx *ctx, int fd, size_t filesize,
                             size_t offset, void *buffer, size_t length,
                             const char *range_reason, const char *read_reason)
{
    off_t file_offset;

    if (offset > filesize || length > filesize - offset)
        return yc_parse_failure(ctx, range_reason);
    if (yc_offset_to_off_t(offset, &file_offset) != 0)
        return yc_parse_failure(ctx, "yC file offset is not representable by the platform");
    if (lseek(fd, file_offset, SEEK_SET) == (off_t)-1) {
        cli_mark_scan_incomplete(ctx, read_reason);
        return CL_ESEEK;
    }
    if (cli_readn(fd, buffer, length) != length) {
        cli_mark_scan_incomplete(ctx, read_reason);
        return CL_EREAD;
    }
    return CL_SUCCESS;
}

static cl_error_t yc_write_at(cli_ctx *ctx, int fd, size_t filesize,
                              size_t offset, const void *buffer, size_t length,
                              const char *range_reason, const char *write_reason)
{
    off_t file_offset;

    if (offset > filesize || length > filesize - offset)
        return yc_parse_failure(ctx, range_reason);
    if (yc_offset_to_off_t(offset, &file_offset) != 0)
        return yc_parse_failure(ctx, "yC file offset is not representable by the platform");
    if (lseek(fd, file_offset, SEEK_SET) == (off_t)-1) {
        cli_mark_scan_incomplete(ctx, write_reason);
        return CL_ESEEK;
    }
    if (cli_writen(fd, buffer, length) != length) {
        cli_mark_scan_incomplete(ctx, write_reason);
        return CL_EWRITE;
    }
    return CL_SUCCESS;
}

static cl_error_t yc_stage_input(cli_ctx *ctx, fmap_t *map, int fd, size_t filesize)
{
    uint8_t buffer[YC_IO_CHUNK_SIZE];
    size_t offset = 0;

    if (map == NULL || map->len != filesize)
        return yc_parse_failure(ctx, "yC input map size changed before staging");
    if (ftruncate(fd, 0) != 0) {
        cli_mark_scan_incomplete(ctx, "yC output temporary file could not be truncated before staging");
        return CL_EWRITE;
    }
    if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
        cli_mark_scan_incomplete(ctx, "yC output temporary file could not be rewound for staging");
        return CL_ESEEK;
    }

    while (offset < filesize) {
        size_t length = filesize - offset;
        size_t bytes_read;

        if (length > sizeof(buffer))
            length = sizeof(buffer);
        if (cli_checktimelimit(ctx) != CL_SUCCESS) {
            cli_mark_scan_incomplete(ctx, "yC input staging reached the configured time limit");
            return CL_ETIMEOUT;
        }
        bytes_read = fmap_readn_full(map, buffer, offset, length);
        if (bytes_read != length) {
            cli_mark_scan_incomplete(ctx, "yC input could not be read completely during staging");
            return bytes_read == (size_t)-1 ? CL_EREAD : CL_EPARSE;
        }
        if (cli_writen(fd, buffer, length) != length) {
            cli_mark_scan_incomplete(ctx, "yC staged input could not be written completely");
            return CL_EWRITE;
        }
        offset += length;
    }

    return CL_SUCCESS;
}

static cl_error_t yc_poly_emulator_fd(cli_ctx *ctx, int fd, size_t filesize,
                                      size_t decryptor_offset, size_t code_offset,
                                      size_t code_size)
{
    uint8_t decryptor[YC_DECRYPTOR_SIZE];
    uint8_t code[YC_IO_CHUNK_SIZE];
    uint8_t cl = (uint8_t)(code_size & 0xff);
    uint32_t ticks = 0;
    uint32_t max_jmp_loop = 100000000U;
    size_t processed = 0;
    cl_error_t status;

    status = yc_read_at(ctx, fd, filesize, decryptor_offset, decryptor,
                        sizeof(decryptor),
                        "yC decryptor window is outside the staged input",
                        "yC decryptor could not be read from staged input");
    if (status != CL_SUCCESS)
        return status;

    while (processed < code_size) {
        size_t length = code_size - processed;
        size_t block_offset;

        if (length > sizeof(code))
            length = sizeof(code);
        if (code_offset > SIZE_MAX - processed)
            return yc_parse_failure(ctx, "yC code offset arithmetic overflowed");
        block_offset = code_offset + processed;
        if (cli_checktimelimit(ctx) != CL_SUCCESS) {
            cli_mark_scan_incomplete(ctx, "yC emulation reached the configured time limit");
            return CL_ETIMEOUT;
        }
        status = yc_read_at(ctx, fd, filesize, block_offset, code, length,
                            "yC code window is outside the staged input",
                            "yC code could not be read from staged input");
        if (status != CL_SUCCESS)
            return status;
        status = yc_poly_emulator_block(ctx, decryptor, sizeof(decryptor),
                                        code, length, &cl, &ticks,
                                        &max_jmp_loop);
        if (status != CL_SUCCESS)
            return status;
        status = yc_write_at(ctx, fd, filesize, block_offset, code, length,
                             "yC decrypted code window is outside the staged input",
                             "yC decrypted code could not be written to staged input");
        if (status != CL_SUCCESS)
            return status;
        processed += length;
    }

    return CL_SUCCESS;
}

static cl_error_t yc_read_u32_at(cli_ctx *ctx, int fd, size_t filesize,
                                 size_t offset, uint32_t *value,
                                 const char *range_reason, const char *read_reason)
{
    uint8_t bytes[sizeof(uint32_t)];
    cl_error_t status;

    status = yc_read_at(ctx, fd, filesize, offset, bytes, sizeof(bytes),
                        range_reason, read_reason);
    if (status == CL_SUCCESS)
        *value = (uint32_t)cli_readint32((const char *)bytes);
    return status;
}

static cl_error_t yc_write_u32_at(cli_ctx *ctx, int fd, size_t filesize,
                                  size_t offset, uint32_t value,
                                  const char *range_reason, const char *write_reason)
{
    uint8_t bytes[sizeof(uint32_t)];

    cli_writeint32((char *)bytes, value);
    return yc_write_at(ctx, fd, filesize, offset, bytes, sizeof(bytes),
                       range_reason, write_reason);
}

/* ========================================================================== */
/* Main routine stages and transforms yC files using bounded memory. */

int yc_decrypt(cli_ctx *ctx, fmap_t *map, size_t filesize,
               struct cli_exe_section *sections, unsigned int sectcount,
               uint32_t peoffset, int desc, uint64_t *temporary_reserved,
               uint32_t ecx, int16_t offset)
{
    struct pe_image_file_hdr pe;
    size_t ycsect;
    size_t sname_offset;
    size_t section_count;
    size_t section_table_size;
    size_t pe_header_size;
    size_t output_size;
    size_t i;
    size_t decryptor_offset;
    uint32_t old_size_of_image;
    uint32_t oep;
    uint8_t section_count_bytes[sizeof(uint16_t)];
    uint8_t zero_import_directory[8] = {0};
    cl_error_t status;

    if (map == NULL || sections == NULL || sectcount == 0 || filesize == 0 ||
        temporary_reserved == NULL ||
        cli_yc_adjusted_window_offset(sections[sectcount].raw, offset,
                                      filesize, 0, &ycsect) != 0 ||
        peoffset > filesize || sizeof(pe) > filesize - peoffset)
        return yc_parse_failure(ctx, "yC section or PE header coordinate is outside the staged input");

    status = yc_stage_input(ctx, map, desc, filesize);
    if (status != CL_SUCCESS)
        return status;

    status = yc_read_at(ctx, desc, filesize, peoffset, &pe, sizeof(pe),
                        "yC PE file header is outside the staged input",
                        "yC PE file header could not be read");
    if (status != CL_SUCCESS)
        return status;
    pe_header_size = sizeof(pe) + EC16(pe.SizeOfOptionalHeader);
    if (EC16(pe.SizeOfOptionalHeader) < 0x70 ||
        pe_header_size < sizeof(pe) ||
        pe_header_size > filesize - peoffset ||
        0x18 > filesize - peoffset - pe_header_size)
        return yc_parse_failure(ctx, "yC PE optional-header window is outside the staged input");
    sname_offset = peoffset + pe_header_size + 0x18;
    section_count = (size_t)sectcount;
    if (section_count > SIZE_MAX / 0x28 ||
        (section_table_size = section_count * 0x28) > filesize - sname_offset)
        return yc_parse_failure(ctx, "yC section-table window is outside the staged input");

    if (sections[sectcount].ursz > filesize)
        return yc_parse_failure(ctx, "yC output truncation would underflow the output size");
    output_size = filesize - sections[sectcount].ursz;

    /* First layer: decrypt the second-layer decryptor in the yC section. */
    cli_dbgmsg("yC: offset: %x, length: %x\n", offset, ecx);
    cli_dbgmsg("yC: decrypting decryptor on sect %d\n", sectcount);
    if (cli_checktimelimit(ctx) != CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, "yC emulation reached the configured time limit");
        return CL_ETIMEOUT;
    }
    if ((uint64_t)ecx + 0xc6 > (uint64_t)SIZE_MAX ||
        cli_yc_adjusted_window_offset(sections[sectcount].raw, offset,
                                      filesize, 0xc6 + (size_t)ecx,
                                      &decryptor_offset) != 0)
        return yc_parse_failure(ctx, "yC first-layer decryptor window is outside the staged input");
    status = yc_poly_emulator_fd(ctx, desc, filesize,
                                 decryptor_offset + 0x93,
                                 decryptor_offset + 0xc6,
                                 (size_t)ecx);
    if (status != CL_SUCCESS)
        return status;

    /* Second layer: decrypt each eligible section in bounded blocks. */
    for (i = 0; i < section_count; i++) {
        uint8_t section_name[4];
        uint32_t name;
        size_t name_offset;
        int32_t decryptor_adjustment;

        if (i > (SIZE_MAX - sname_offset) / 0x28)
            return yc_parse_failure(ctx, "yC section-name offset arithmetic overflowed");
        name_offset = sname_offset + i * 0x28;
        status = yc_read_at(ctx, desc, filesize, name_offset, section_name,
                            sizeof(section_name),
                            "yC section-name window is outside the staged input",
                            "yC section name could not be read");
        if (status != CL_SUCCESS)
            return status;
        name = (uint32_t)cli_readint32((const char *)section_name);

        if (cli_checktimelimit(ctx) != CL_SUCCESS) {
            cli_mark_scan_incomplete(ctx, "yC section emulation reached the configured time limit");
            return CL_ETIMEOUT;
        }
        if (!sections[i].raw ||
            !sections[i].rsz ||
            name == 0x63727372 ||     /* rsrc */
            name == 0x7273722E ||     /* .rsr */
            name == 0x6F6C6572 ||     /* relo */
            name == 0x6C65722E ||     /* .rel */
            name == 0x6164652E ||     /* .eda */
            name == 0x6164722E ||     /* .rda */
            name == 0x6164692E ||     /* .ida */
            name == 0x736C742E ||     /* .tls */
            (name & 0xffff) == 0x4379 /* yC */
        )
            continue;
        cli_dbgmsg("yC: decrypting sect%u\n", (unsigned int)i);
        if (sections[i].raw > output_size ||
            sections[i].ursz > output_size - sections[i].raw)
            return yc_parse_failure(ctx, "yC section raw coordinate or emulation window is outside the output");

        decryptor_adjustment = offset == -0x18 ? 0x3ea : 0x457;
        if (cli_yc_adjusted_window_offset(sections[sectcount].raw,
                                          (int32_t)offset + decryptor_adjustment,
                                          filesize,
                                          YC_DECRYPTOR_SIZE,
                                          &decryptor_offset) != 0)
            return yc_parse_failure(ctx, "yC section decryptor window is outside the staged input");
        status = yc_poly_emulator_fd(ctx, desc, filesize, decryptor_offset,
                                     sections[i].raw, sections[i].ursz);
        if (status != CL_SUCCESS)
            return status;
    }

    /* Resolve OEP and validate all output header coordinates before patching. */
    if (cli_yc_adjusted_window_offset(sections[sectcount].raw, 0xa0f,
                                      filesize, sizeof(uint32_t),
                                      &decryptor_offset) != 0)
        return yc_parse_failure(ctx, "yC original entry-point value is outside the staged input");
    status = yc_read_u32_at(ctx, desc, filesize, decryptor_offset, &oep,
                            "yC original entry-point value is outside the staged input",
                            "yC original entry-point value could not be read");
    if (status != CL_SUCCESS)
        return status;

    if (sectcount > UINT16_MAX)
        return yc_parse_failure(ctx, "yC section count cannot be represented in the PE header");
    if (peoffset > output_size ||
        offsetof(struct pe_image_file_hdr, NumberOfSections) > output_size - peoffset ||
        sizeof(section_count_bytes) > output_size - peoffset - offsetof(struct pe_image_file_hdr, NumberOfSections))
        return yc_parse_failure(ctx, "yC section-count field is outside the output");
    section_count_bytes[0] = (uint8_t)(sectcount & 0xff);
    section_count_bytes[1] = (uint8_t)((sectcount >> 8) & 0xff);
    status = yc_write_at(ctx, desc, filesize,
                         peoffset + offsetof(struct pe_image_file_hdr, NumberOfSections),
                         section_count_bytes, sizeof(section_count_bytes),
                         "yC section-count field is outside the staged input",
                         "yC section-count field could not be written");
    if (status != CL_SUCCESS)
        return status;

    if (peoffset > output_size || sizeof(pe) > output_size - peoffset ||
        0x70 > output_size - peoffset - sizeof(pe))
        return yc_parse_failure(ctx, "yC optional-header fields are outside the output");
    status = yc_write_at(ctx, desc, filesize,
                         peoffset + sizeof(pe) + 0x68,
                         zero_import_directory, sizeof(zero_import_directory),
                         "yC import-directory fields are outside the staged input",
                         "yC import-directory fields could not be cleared");
    if (status != CL_SUCCESS)
        return status;
    status = yc_write_u32_at(ctx, desc, filesize,
                             peoffset + sizeof(pe) + 16, oep,
                             "yC entry-point field is outside the staged input",
                             "yC entry-point field could not be written");
    if (status != CL_SUCCESS)
        return status;
    status = yc_read_u32_at(ctx, desc, filesize,
                            peoffset + sizeof(pe) + 0x38,
                            &old_size_of_image,
                            "yC SizeOfImage field is outside the staged input",
                            "yC SizeOfImage field could not be read");
    if (status != CL_SUCCESS)
        return status;
    if (old_size_of_image < sections[sectcount].vsz)
        return yc_parse_failure(ctx, "yC SizeOfImage adjustment would underflow");
    status = yc_write_u32_at(ctx, desc, filesize,
                             peoffset + sizeof(pe) + 0x38,
                             old_size_of_image - sections[sectcount].vsz,
                             "yC SizeOfImage field is outside the staged input",
                             "yC SizeOfImage field could not be written");
    if (status != CL_SUCCESS)
        return status;

    {
        off_t truncate_size;
        uint64_t discarded = (uint64_t)(filesize - output_size);

        if (yc_offset_to_off_t(output_size, &truncate_size) != 0)
            return yc_parse_failure(ctx, "yC output size is not representable by the platform");
        if (ftruncate(desc, truncate_size) != 0) {
            cli_mark_scan_incomplete(ctx, "yC output temporary file could not be truncated");
            return CL_EWRITE;
        }
        if (*temporary_reserved < discarded) {
            cli_mark_scan_incomplete(ctx, "yC temporary-storage accounting became inconsistent");
            return CL_ERESOURCE;
        }
        if (discarded != 0) {
            cli_scan_release_temporary(ctx, discarded);
            *temporary_reserved -= discarded;
        }
    }

    return CL_SUCCESS;
}
