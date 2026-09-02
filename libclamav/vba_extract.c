/*
 *  Extract VBA source code for component MS Office Documents
 *
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Trog, Nigel Horne
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
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <stdlib.h>
#include <ctype.h>
#if defined(HAVE_MMAP) && defined(HAVE_SYS_MMAN_H)
#include <sys/mman.h>
#endif

#include <zlib.h>
#include <json.h>

#include "clamav.h"

#include "others.h"
#include "scanners.h"
#include "vba_extract.h"
#ifdef CL_DEBUG
#include "mbox.h"
#endif
#include "blob.h"
#include "ole2_extract.h"
#include "entconv.h"

#define PPT_LZW_BUFFSIZE 8192
#define VBA_COMPRESSION_WINDOW 4096
#define VBA_METADATA_INPUT_WINDOW 8192
#define VBA_DIRECTORY_RELEASE_WINDOW (1024U * 1024U)
#define VBA_OLE_STREAM_NAME_LIMIT 126U
#define MIDDLE_SIZE 20
#define MAX_VBA_COUNT 1000 /* If there's more than 1000 macros something's up! */

#if defined(HAVE_MMAP) && defined(HAVE_SYS_MMAN_H) && SIZE_MAX > UINT32_MAX
#define VBA_HAVE_FILE_BACKED_DIRECTORY 1
#else
#define VBA_HAVE_FILE_BACKED_DIRECTORY 0
#endif

#ifndef HAVE_ATTRIB_PACKED
#define __attribute__(x)
#endif

/*
 * VBA (Visual Basic for Applications), versions 5 and 6
 */
struct vba56_header {
    unsigned char magic[2];
    unsigned char version[4];
    unsigned char ignore[28];
};

typedef struct {
    uint32_t sig;
    const char *ver;
    int big_endian; /* e.g. MAC Office */
} vba_version_t;

static int skip_past_nul(int fd);
static int read_uint16(int fd, uint16_t *u, int big_endian);
static int read_uint32(int fd, uint32_t *u, int big_endian);
static int seekandread(int fd, off_t offset, int whence, void *data, size_t len);
static vba_project_t *create_vba_project(int record_count, const char *dir, struct uniq *U);

static cl_error_t
vba_checktimelimit(cli_ctx *ctx, const char *reason)
{
    cl_error_t ret = cli_checktimelimit(ctx);

    if (ret != CL_SUCCESS)
        cli_mark_scan_incomplete(ctx, reason);

    return ret;
}

static void
vba_note_cleanup_failure(cli_ctx *ctx, cl_error_t *status, cl_error_t cleanup_status,
                         const char *reason)
{
    if (ctx)
        cli_mark_scan_incomplete(ctx, reason);
    if (status)
        *status = cli_merge_cleanup_status(*status, cleanup_status);
}

static cl_error_t
vba_readn_full(int fd, void *buffer, size_t length)
{
    size_t read_length = cli_readn(fd, buffer, length);

    if (read_length == length)
        return CL_SUCCESS;

    return read_length == (size_t)-1 ? CL_EREAD : CL_EPARSE;
}

static uint16_t
vba_endian_convert_16(uint16_t value, int big_endian)
{
    if (big_endian)
        return (uint16_t)be16_to_host(value);
    else
        return le16_to_host(value);
}

/* Seems to be a duplicate of riff_endian_convert_32() */
static uint32_t
vba_endian_convert_32(uint32_t value, int big_endian)
{
    if (big_endian)
        return be32_to_host(value);
    else
        return le32_to_host(value);
}

static char *
get_unicode_name(const char *name, int size, int big_endian)
{
    int i, increment;
    char *newname, *ret;

    if ((name == NULL) || (*name == '\0') || (size <= 0))
        return NULL;

    newname = (char *)cli_max_malloc(size * 7 + 1);
    if (newname == NULL) {
        cli_errmsg("get_unicode_name: Unable to allocate memory for newname\n");
        return NULL;
    }

    if ((!big_endian) && (size & 0x1)) {
        cli_dbgmsg("get_unicode_name: odd number of bytes %d\n", size);
        --size;
    }

    increment = (big_endian) ? 1 : 2;
    ret       = newname;

    for (i = 0; i < size; i += increment) {
        if ((!(name[i] & 0x80)) && isprint(name[i])) {
            *ret++ = tolower(name[i]);
        } else {
            if ((name[i] < 10) && (name[i] >= 0)) {
                *ret++ = '_';
                *ret++ = (char)(name[i] + '0');
            } else {
                uint16_t x;
                if ((i + 1) >= size)
                    break;
                x = (uint16_t)((name[i] < 0 ? 0 : name[i] << 8) | name[i + 1]);

                *ret++ = '_';
                *ret++ = (char)('a' + ((x & 0xF)));
                *ret++ = (char)('a' + ((x >> 4) & 0xF));
                *ret++ = (char)('a' + ((x >> 8) & 0xF));
                *ret++ = 'a';
                *ret++ = 'a';
            }
            *ret++ = '_';
        }
    }

    *ret = '\0';

    /* Saves a lot of memory */
    ret = cli_max_realloc(newname, (ret - newname) + 1);
    return ret ? ret : newname;
}

static void vba56_test_middle(int fd)
{
    char test_middle[MIDDLE_SIZE];

    /* MacOffice middle */
    static const uint8_t middle1_str[MIDDLE_SIZE] = {
        0x00, 0x01, 0x0d, 0x45, 0x2e, 0xe1, 0xe0, 0x8f, 0x10, 0x1a,
        0x85, 0x2e, 0x02, 0x60, 0x8c, 0x4d, 0x0b, 0xb4, 0x00, 0x00};
    /* MS Office middle */
    static const uint8_t middle2_str[MIDDLE_SIZE] = {
        0x00, 0x00, 0xe1, 0x2e, 0x45, 0x0d, 0x8f, 0xe0, 0x1a, 0x10,
        0x85, 0x2e, 0x02, 0x60, 0x8c, 0x4d, 0x0b, 0xb4, 0x00, 0x00};

    if (cli_readn(fd, &test_middle, MIDDLE_SIZE) != MIDDLE_SIZE)
        return;

    if ((memcmp(test_middle, middle1_str, MIDDLE_SIZE) != 0) &&
        (memcmp(test_middle, middle2_str, MIDDLE_SIZE) != 0)) {
        cli_dbgmsg("middle not found\n");
        if (lseek(fd, -MIDDLE_SIZE, SEEK_CUR) == -1) {
            cli_dbgmsg("vba_test_middle: call to lseek() failed\n");
            return;
        }
    } else
        cli_dbgmsg("middle found\n");
}

/* return count of valid strings found, 0 on error */
static int
vba_read_project_strings(int fd, int big_endian)
{
    unsigned char *buf = NULL;
    uint16_t buflen    = 0;
    uint16_t length    = 0;
    int ret = 0, getnewlength = 1;

    for (;;) {
        off_t offset;
        char *name;

        /* if no initial name length, exit */
        if (getnewlength && !read_uint16(fd, &length, big_endian)) {
            ret = 0;
            break;
        }
        getnewlength = 0;

        /* if too short, break */
        if (length < 6) {
            if (lseek(fd, -2, SEEK_CUR) == -1) {
                cli_dbgmsg("vba_read_project_strings: call to lseek() has failed\n");
                ret = 0;
            }
            break;
        }
        /* ensure buffer is large enough */
        if (length > buflen) {
            unsigned char *newbuf = (unsigned char *)cli_max_realloc(buf, length);
            if (newbuf == NULL) {
                ret = 0;
                break;
            }
            buflen = length;
            buf    = newbuf;
        }

        /* save current offset */
        offset = lseek(fd, 0, SEEK_CUR);
        if (offset == -1) {
            cli_dbgmsg("vba_read_project_strings: call to lseek() has failed\n");
            ret = 0;
            break;
        }

        /* if read name failed, break */
        if (cli_readn(fd, buf, (size_t)length) != (size_t)length) {
            cli_dbgmsg("read name failed - rewinding\n");
            if (lseek(fd, offset, SEEK_SET) == -1) {
                cli_dbgmsg("call to lseek() in read name failed\n");
                ret = 0;
            }
            break;
        }
        name = get_unicode_name((const char *)buf, length, big_endian);
        cli_dbgmsg("length: %d, name: %s\n", length, (name) ? name : "[null]");

        /* if invalid name, break */
        if ((name == NULL) || (memcmp("*\\", name, 2) != 0) ||
            (strchr("ghcd", name[2]) == NULL)) {
            /* Not a valid string, rewind */
            if (lseek(fd, -(length + 2), SEEK_CUR) == -1) {
                cli_dbgmsg("call to lseek() after get_unicode_name has failed\n");
                ret = 0;
            }
            free(name);
            break;
        }
        free(name);

        /* can't get length, break */
        if (!read_uint16(fd, &length, big_endian)) {
            break;
        }

        ret++;

        /* continue on reasonable length value */
        if ((length != 0) && (length != 65535)) {
            continue;
        }

        /* determine offset and run middle test */
        offset = lseek(fd, 10, SEEK_CUR);
        if (offset == -1) {
            cli_dbgmsg("call to lseek() has failed\n");
            ret = 0;
            break;
        }
        cli_dbgmsg("offset: %lu\n", (unsigned long)offset);
        vba56_test_middle(fd);
        getnewlength = 1;
    }

    free(buf);
    return ret;
}

static size_t vba_normalize(unsigned char *buffer, size_t size)
{
    enum {
        NORMAL        = 0,
        IN_STRING     = 1,
        UNDERSCORE    = 2,
        UNDERSCORE_CR = 3,
        SPACE         = 5,
    } state  = NORMAL;
    size_t o = 0;
    size_t i;
    for (i = 0; i < size; ++i) {
        // TODO: Don't normalize stuff in comments
        // FIXME: Use UTF glyphs instead of raw bytes
        switch (buffer[i]) {
            case '"':
                if (state == IN_STRING) {
                    state = NORMAL;
                } else if (state == NORMAL || state == UNDERSCORE || state == SPACE) {
                    state = IN_STRING;
                }
                buffer[o++] = '"';
                break;
            case '_':
                if (state == SPACE) {
                    state = UNDERSCORE;
                }
                buffer[o++] = '_';
                break;
            case '\r':
                if (state == UNDERSCORE) {
                    state = UNDERSCORE_CR;
                }
                buffer[o++] = '\r';
                break;
            case '\n':
                if (state == UNDERSCORE) {
                    o -= 1;
                    state = SPACE;
                } else if (state == UNDERSCORE_CR) {
                    o -= 2;
                    state = SPACE;
                } else {
                    buffer[o++] = '\n';
                    ;
                }
                break;
            case '\t':
            case ' ':
                if (state != SPACE) {
                    buffer[o++] = ' ';
                }
                if (state == NORMAL || state == UNDERSCORE) {
                    state = SPACE;
                }
                break;
            default:
                if (state == NORMAL || state == UNDERSCORE || state == SPACE) {
                    if (buffer[i] >= 'A' && buffer[i] <= 'Z') {
                        buffer[o++] = (unsigned char)tolower((int)buffer[i]);
                    } else {
                        buffer[o++] = buffer[i];
                    }
                    state = NORMAL;
                } else {
                    buffer[o++] = buffer[i];
                }
                break;
        }
    }
    return o;
}

#define VBA_NORMALIZE_OUTPUT_WINDOW 16384

struct vba_project_output {
    cli_ctx *ctx;
    int fd;
    uint64_t *temporary_reserved;
};

struct vba_stream_normalizer {
    struct vba_project_output *output;
    unsigned int state;
    unsigned char tail[2];
    size_t tail_size;
    unsigned char buffer[VBA_NORMALIZE_OUTPUT_WINDOW];
    size_t buffer_size;
    uint64_t output_size;
};

struct vba_module_pipeline {
    cli_ctx *ctx;
    cli_codepage_utf8_stream_t *converter;
    cl_error_t conversion_status;
    uint64_t inflated_size;
};

#if VBA_HAVE_FILE_BACKED_DIRECTORY
struct vba_directory_spool {
    struct vba_project_output output;
    uint64_t produced;
};
#endif

struct vba_metadata_digest {
    uint64_t hash;
    uint64_t size;
};

struct vba_metadata_writer {
    struct vba_project_output *output;
    struct vba_metadata_digest digest;
};

static void vba_directory_release_consumed(unsigned char *data, size_t data_len,
                                           size_t consumed, size_t *released);

static cl_error_t vba_project_output_write(struct vba_project_output *output,
                                           const unsigned char *data, size_t data_size)
{
    uint64_t write_size = (uint64_t)data_size;

    if (data_size == 0)
        return CL_SUCCESS;
    if (write_size > UINT64_MAX - *output->temporary_reserved ||
        cli_scan_reserve_temporary(output->ctx, write_size) != CL_SUCCESS) {
        cli_mark_scan_incomplete(output->ctx, "VBA project temporary output exceeds temporary storage limits");
        return CL_ERESOURCE;
    }
    *output->temporary_reserved += write_size;

    if (vba_checktimelimit(output->ctx, "VBA project temporary output reached the configured time limit") != CL_SUCCESS)
        return CL_ETIMEOUT;
    if (cli_writen(output->fd, data, data_size) != data_size) {
        cli_warnmsg("vba_readdir_new: Failed to write to output file\n");
        cli_mark_scan_incomplete(output->ctx, "VBA project temporary output could not be written completely");
        return CL_EWRITE;
    }

    return CL_SUCCESS;
}

static cl_error_t vba_metadata_output_write(const unsigned char *data, size_t data_size, void *context)
{
    struct vba_metadata_writer *writer = context;
    cl_error_t status;
    size_t i;

    if ((uint64_t)data_size > UINT64_MAX - writer->digest.size)
        return CL_EFORMAT;

    status = vba_project_output_write(writer->output, data, data_size);
    if (status != CL_SUCCESS)
        return status;

    for (i = 0; i < data_size; i++) {
        writer->digest.hash ^= data[i];
        writer->digest.hash *= UINT64_C(1099511628211);
    }
    writer->digest.size += (uint64_t)data_size;
    return CL_SUCCESS;
}

static cl_error_t vba_project_write_converted(struct vba_project_output *output,
                                              const unsigned char *data, size_t data_size,
                                              uint16_t codepage, struct vba_metadata_digest *digest,
                                              unsigned char *directory_data, size_t directory_size,
                                              size_t directory_offset, size_t *directory_released)
{
    struct vba_metadata_writer writer;
    cli_codepage_utf8_stream_t *converter = NULL;
    uint64_t converted_size = 0;
    size_t offset = 0;
    cl_error_t status;

    memset(&writer, 0, sizeof(writer));
    writer.output      = output;
    writer.digest.hash = UINT64_C(14695981039346656037);
    if (data_size == 0) {
        if (digest != NULL)
            *digest = writer.digest;
        return CL_SUCCESS;
    }

    status = cli_codepage_utf8_stream_open(codepage, vba_metadata_output_write,
                                           &writer, &converter);
    while (status == CL_SUCCESS && offset < data_size) {
        size_t take = MIN((size_t)VBA_METADATA_INPUT_WINDOW, data_size - offset);

        status = cli_codepage_utf8_stream_process(converter, data + offset, take);
        offset += take;
        vba_directory_release_consumed(directory_data, directory_size,
                                       directory_offset + offset, directory_released);
    }
    if (status == CL_SUCCESS)
        status = cli_codepage_utf8_stream_finish(converter, &converted_size);
    cli_codepage_utf8_stream_free(converter);

    if (status == CL_SUCCESS && converted_size != writer.digest.size)
        status = CL_EFORMAT;
    if (status == CL_SUCCESS && digest != NULL)
        *digest = writer.digest;
    return status;
}

static bool vba_metadata_digest_equal(const struct vba_metadata_digest *left,
                                      const struct vba_metadata_digest *right)
{
    return left->size == right->size && left->hash == right->hash;
}

#if VBA_HAVE_FILE_BACKED_DIRECTORY
static cl_error_t vba_directory_spool_write(const unsigned char *data, size_t data_size, void *context)
{
    struct vba_directory_spool *spool = context;
    uint64_t projected;
    cl_error_t status;

    if ((uint64_t)data_size > UINT64_MAX - spool->produced) {
        cli_mark_scan_incomplete(spool->output.ctx, "VBA project directory decompressed-size accounting overflowed");
        return CL_EFORMAT;
    }
    projected = spool->produced + (uint64_t)data_size;
    status    = cli_checklimits("VBA project directory", spool->output.ctx,
                                projected, 0, 0);
    if (status != CL_SUCCESS) {
        cli_mark_scan_incomplete(spool->output.ctx, "VBA project directory exceeds configured scan limits");
        return status;
    }

    status = vba_project_output_write(&spool->output, data, data_size);
    if (status == CL_SUCCESS)
        spool->produced = projected;
    return status;
}
#endif

static void vba_directory_release_consumed(unsigned char *data, size_t data_len,
                                           size_t consumed, size_t *released)
{
#if VBA_HAVE_FILE_BACKED_DIRECTORY && defined(MADV_DONTNEED)
    long system_page_size;
    size_t page_size;
    size_t release_end;

    if (data == NULL || released == NULL || consumed <= VBA_DIRECTORY_RELEASE_WINDOW ||
        *released >= data_len)
        return;

    system_page_size = sysconf(_SC_PAGESIZE);
    if (system_page_size <= 0)
        return;
    page_size  = (size_t)system_page_size;
    release_end = consumed - VBA_DIRECTORY_RELEASE_WINDOW;
    release_end = (release_end / page_size) * page_size;
    release_end = MIN(release_end, data_len);
    if (release_end > *released) {
        (void)madvise(data + *released, release_end - *released, MADV_DONTNEED);
        *released = release_end;
    }
#else
    UNUSEDPARAM(data);
    UNUSEDPARAM(data_len);
    UNUSEDPARAM(consumed);
    UNUSEDPARAM(released);
#endif
}

static cl_error_t vba_project_output_rollback(struct vba_project_output *output, off_t output_offset,
                                              uint64_t reservation_before)
{
    uint64_t released;

    if (*output->temporary_reserved < reservation_before)
        return CL_EFORMAT;
    released = *output->temporary_reserved - reservation_before;

    if (ftruncate(output->fd, output_offset) != 0 || lseek(output->fd, output_offset, SEEK_SET) == (off_t)-1) {
        cli_mark_scan_incomplete(output->ctx, "VBA module output could not be rolled back completely");
        return CL_EWRITE;
    }

    cli_scan_release_temporary(output->ctx, released);
    *output->temporary_reserved = reservation_before;
    return CL_SUCCESS;
}

static cl_error_t vba_stream_normalizer_flush(struct vba_stream_normalizer *normalizer)
{
    cl_error_t status;

    if (normalizer->buffer_size == 0)
        return CL_SUCCESS;
    if ((uint64_t)normalizer->buffer_size > UINT64_MAX - normalizer->output_size)
        return CL_EFORMAT;

    status = vba_project_output_write(normalizer->output, normalizer->buffer,
                                      normalizer->buffer_size);
    if (status != CL_SUCCESS)
        return status;

    normalizer->output_size += (uint64_t)normalizer->buffer_size;
    normalizer->buffer_size = 0;
    return CL_SUCCESS;
}

static cl_error_t vba_stream_normalizer_commit(struct vba_stream_normalizer *normalizer,
                                               unsigned char byte)
{
    if (normalizer->buffer_size == sizeof(normalizer->buffer)) {
        cl_error_t status = vba_stream_normalizer_flush(normalizer);
        if (status != CL_SUCCESS)
            return status;
    }
    normalizer->buffer[normalizer->buffer_size++] = byte;
    return CL_SUCCESS;
}

static cl_error_t vba_stream_normalizer_append(struct vba_stream_normalizer *normalizer,
                                               unsigned char byte)
{
    cl_error_t status;

    if (normalizer->tail_size == sizeof(normalizer->tail)) {
        status = vba_stream_normalizer_commit(normalizer, normalizer->tail[0]);
        if (status != CL_SUCCESS)
            return status;
        normalizer->tail[0] = normalizer->tail[1];
        normalizer->tail_size--;
    }
    normalizer->tail[normalizer->tail_size++] = byte;
    return CL_SUCCESS;
}

static cl_error_t vba_stream_normalizer_process(const unsigned char *data, size_t data_size, void *context)
{
    enum {
        NORMAL        = 0,
        IN_STRING     = 1,
        UNDERSCORE    = 2,
        UNDERSCORE_CR = 3,
        SPACE         = 4
    };
    struct vba_stream_normalizer *normalizer = context;
    size_t i;

    for (i = 0; i < data_size; i++) {
        unsigned char byte = data[i];
        cl_error_t status  = CL_SUCCESS;

        switch (byte) {
            case '"':
                if (normalizer->state == IN_STRING) {
                    normalizer->state = NORMAL;
                } else if (normalizer->state == NORMAL || normalizer->state == UNDERSCORE || normalizer->state == SPACE) {
                    normalizer->state = IN_STRING;
                }
                status = vba_stream_normalizer_append(normalizer, byte);
                break;
            case '_':
                if (normalizer->state == SPACE)
                    normalizer->state = UNDERSCORE;
                status = vba_stream_normalizer_append(normalizer, byte);
                break;
            case '\r':
                if (normalizer->state == UNDERSCORE)
                    normalizer->state = UNDERSCORE_CR;
                status = vba_stream_normalizer_append(normalizer, byte);
                break;
            case '\n':
                if (normalizer->state == UNDERSCORE) {
                    if (normalizer->tail_size < 1)
                        return CL_EFORMAT;
                    normalizer->tail_size--;
                    normalizer->state = SPACE;
                } else if (normalizer->state == UNDERSCORE_CR) {
                    if (normalizer->tail_size < 2)
                        return CL_EFORMAT;
                    normalizer->tail_size -= 2;
                    normalizer->state = SPACE;
                } else {
                    status = vba_stream_normalizer_append(normalizer, byte);
                }
                break;
            case '\t':
            case ' ':
                if (normalizer->state != SPACE)
                    status = vba_stream_normalizer_append(normalizer, ' ');
                if (normalizer->state == NORMAL || normalizer->state == UNDERSCORE)
                    normalizer->state = SPACE;
                break;
            default:
                if (normalizer->state == NORMAL || normalizer->state == UNDERSCORE || normalizer->state == SPACE) {
                    if (byte >= 'A' && byte <= 'Z')
                        byte = (unsigned char)tolower((int)byte);
                    normalizer->state = NORMAL;
                }
                status = vba_stream_normalizer_append(normalizer, byte);
                break;
        }

        if (status != CL_SUCCESS)
            return status;
    }

    return CL_SUCCESS;
}

static cl_error_t vba_stream_normalizer_finish(struct vba_stream_normalizer *normalizer)
{
    size_t i;

    for (i = 0; i < normalizer->tail_size; i++) {
        cl_error_t status = vba_stream_normalizer_commit(normalizer, normalizer->tail[i]);
        if (status != CL_SUCCESS)
            return status;
    }
    normalizer->tail_size = 0;
    return vba_stream_normalizer_flush(normalizer);
}

static cl_error_t vba_module_convert_write(const unsigned char *data, size_t data_size, void *context)
{
    struct vba_module_pipeline *pipeline = context;
    uint64_t projected_size;

    if ((uint64_t)data_size > UINT64_MAX - pipeline->inflated_size) {
        cli_mark_scan_incomplete(pipeline->ctx, "VBA module decompressed-size accounting overflowed");
        return CL_EFORMAT;
    }
    projected_size = pipeline->inflated_size + (uint64_t)data_size;
    pipeline->conversion_status = cli_checklimits("VBA module", pipeline->ctx,
                                                  projected_size, 0, 0);
    if (pipeline->conversion_status != CL_SUCCESS) {
        cli_mark_scan_incomplete(pipeline->ctx, "VBA module decompressed subject exceeds configured scan limits");
        return pipeline->conversion_status;
    }
    pipeline->conversion_status = vba_checktimelimit(
        pipeline->ctx, "VBA module decompression reached the configured time limit");
    if (pipeline->conversion_status != CL_SUCCESS)
        return pipeline->conversion_status;

    pipeline->conversion_status = cli_codepage_utf8_stream_process(pipeline->converter, data, data_size);
    if (pipeline->conversion_status == CL_SUCCESS)
        pipeline->inflated_size = projected_size;
    return pipeline->conversion_status;
}

static cl_error_t vba_extract_module_stream(int module_fd, off_t module_offset, uint16_t codepage,
                                            struct vba_project_output *output, uint64_t *module_output_size)
{
    struct vba_stream_normalizer normalizer;
    struct vba_module_pipeline pipeline;
    uint64_t converted_size = 0;
    uint64_t inflated_size  = 0;
    cl_error_t status;

    memset(&normalizer, 0, sizeof(normalizer));
    memset(&pipeline, 0, sizeof(pipeline));
    normalizer.output            = output;
    pipeline.ctx                 = output->ctx;
    pipeline.conversion_status   = CL_SUCCESS;

    status = cli_codepage_utf8_stream_open(codepage, vba_stream_normalizer_process,
                                           &normalizer, &pipeline.converter);
    if (status != CL_SUCCESS)
        return status;

    status = cli_vba_inflate_stream(module_fd, module_offset, vba_module_convert_write,
                                    &pipeline, &inflated_size);
    if (status == CL_SUCCESS && inflated_size != pipeline.inflated_size)
        status = CL_EFORMAT;
    if (status == CL_SUCCESS)
        status = cli_codepage_utf8_stream_finish(pipeline.converter, &converted_size);
    if (status == CL_SUCCESS)
        status = vba_stream_normalizer_finish(&normalizer);

    cli_codepage_utf8_stream_free(pipeline.converter);

    if (status == CL_SUCCESS && module_output_size != NULL)
        *module_output_size = normalizer.output_size;
    return status;
}

static cl_error_t vba_invoke_module_callback(cli_ctx *ctx, int output_fd,
                                             off_t output_offset, uint64_t output_size)
{
    unsigned char *module = NULL;
    off_t saved_offset;
    cl_error_t read_status;
    cl_error_t status = CL_SUCCESS;

    if (ctx->engine->cb_vba == NULL)
        return CL_SUCCESS;
    if (output_size == 0)
        return CL_SUCCESS;
    if (output_size > CLI_MAX_ALLOCATION || output_size > SIZE_MAX) {
        cli_mark_scan_incomplete(ctx, "VBA callback ABI cannot receive a module above the contiguous allocation boundary");
        return CL_EMAXSIZE;
    }

    module = cli_max_malloc((size_t)output_size);
    if (module == NULL) {
        cli_mark_scan_incomplete(ctx, "VBA callback module buffer could not be allocated");
        return CL_EMEM;
    }

    saved_offset = lseek(output_fd, 0, SEEK_CUR);
    if (saved_offset == (off_t)-1 || lseek(output_fd, output_offset, SEEK_SET) == (off_t)-1) {
        cli_mark_scan_incomplete(ctx, "VBA callback module output could not be positioned safely");
        status = CL_ESEEK;
        goto done;
    }

    read_status = vba_readn_full(output_fd, module, (size_t)output_size);
    if (lseek(output_fd, saved_offset, SEEK_SET) == (off_t)-1) {
        cli_mark_scan_incomplete(ctx, "VBA callback read could not restore the project output position");
        status = CL_ESEEK;
        goto done;
    }
    if (read_status != CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, "VBA callback module could not be read from bounded output");
        status = read_status;
        goto done;
    }

    ctx->engine->cb_vba(module, (size_t)output_size, ctx->cb_ctx);

done:
    free(module);
    return status;
}

/**
 * Read a VBA project in an OLE directory.
 * Contrary to cli_vba_readdir, this function uses the dir file to locate VBA modules.
 */
cl_error_t cli_vba_readdir_new(cli_ctx *ctx, const char *dir, struct uniq *U, const char *hash, uint32_t which,
                               int *tempfd, int *has_macros, char **tempfile, uint64_t *temporary_reserved_out)
{
    cl_error_t ret              = CL_SUCCESS;
    cl_error_t deferred_failure = CL_SUCCESS;
    char fullname[1024];
    int fd              = -1;
    int datafd          = -1;
    unsigned char *data = NULL;
    char *datafile      = NULL;
    bool data_is_mapped = false;
    size_t data_len;
    size_t data_offset;
    size_t data_released = 0;
    const char *stream_name = NULL;
    uint16_t codepage       = CODEPAGE_ISO8859_1;
    unsigned i;
    unsigned char *module_data = NULL, *module_data_utf8 = NULL;
    size_t module_data_size = 0, module_data_utf8_size = 0;
    uint64_t temporary_reserved = 0;
    uint64_t directory_reserved = 0;
    struct vba_project_output project_output;

    if (ctx == NULL || ctx->engine == NULL)
        return CL_ENULLARG;

    if (dir == NULL || hash == NULL || tempfd == NULL || has_macros == NULL || tempfile == NULL || temporary_reserved_out == NULL) {
        return CL_EARG;
    }

    *temporary_reserved_out = 0;

    cli_dbgmsg("vba_readdir_new: Scanning directory %s for VBA project\n", dir);

    snprintf(fullname, sizeof(fullname), "%s" PATHSEP "%s_%u", dir, hash, which);
    fullname[sizeof(fullname) - 1] = '\0';
    fd                             = open(fullname, O_RDONLY | O_BINARY);

    if (fd == -1) {
        ret = CL_EOPEN;
        goto done;
    }

#if VBA_HAVE_FILE_BACKED_DIRECTORY
    {
        struct vba_directory_spool directory_spool;
        struct stat data_stat;
        uint64_t data_len_u64 = 0;
        void *mapping;

        ret = cli_gentempfd_with_prefix(ctx->this_layer_tmpdir, "vba_directory", &datafile, &datafd);
        if (ret != CL_SUCCESS) {
            cli_mark_scan_incomplete(ctx, "VBA project directory backing file could not be created");
            goto done;
        }

        memset(&directory_spool, 0, sizeof(directory_spool));
        directory_spool.output.ctx                = ctx;
        directory_spool.output.fd                 = datafd;
        directory_spool.output.temporary_reserved = &directory_reserved;
        ret = cli_vba_inflate_stream(fd, 0, vba_directory_spool_write,
                                     &directory_spool, &data_len_u64);
        if (ret != CL_SUCCESS || data_len_u64 != directory_spool.produced) {
            cli_mark_scan_incomplete(ctx, "VBA project directory could not be decompressed completely");
            if (ret == CL_SUCCESS)
                ret = CL_EFORMAT;
            goto done;
        }
        if (data_len_u64 == 0 || data_len_u64 > SIZE_MAX) {
            cli_mark_scan_incomplete(ctx, "VBA project directory has an unsupported decompressed size");
            ret = CL_EMAXSIZE;
            goto done;
        }
        if (FSTAT(datafd, &data_stat) != 0 || data_stat.st_size < 0 ||
            !S_ISREG(data_stat.st_mode) ||
            (uint64_t)data_stat.st_size != data_len_u64) {
            cli_mark_scan_incomplete(ctx, "VBA project directory backing size could not be verified");
            ret = CL_EWRITE;
            goto done;
        }

        data_len = (size_t)data_len_u64;
        mapping  = mmap(NULL, data_len, PROT_READ, MAP_PRIVATE, datafd, 0);
        if (mapping == MAP_FAILED) {
            cli_mark_scan_incomplete(ctx, "VBA project directory backing could not be mapped");
            ret = CL_EMEM;
            goto done;
        }
        data           = mapping;
        data_is_mapped = true;
#ifdef MADV_SEQUENTIAL
        (void)madvise(mapping, data_len, MADV_SEQUENTIAL);
#endif

        if (close(datafd) != 0) {
            datafd = -1;
            vba_note_cleanup_failure(ctx, &deferred_failure, CL_EREAD,
                                     "VBA project directory backing could not be closed");
        }
        datafd = -1;
        if (!ctx->engine->keeptmp && cli_unlink(datafile) != 0) {
            vba_note_cleanup_failure(ctx, &deferred_failure, CL_EUNLINK,
                                     "VBA project directory backing could not be removed");
        } else if (!ctx->engine->keeptmp) {
            free(datafile);
            datafile = NULL;
        }
    }
#else
    if ((data = cli_vba_inflate(fd, 0, &data_len)) == NULL) {
        cli_dbgmsg("vba_readdir_new: Failed to decompress 'dir'\n");
        cli_mark_scan_incomplete(ctx, "VBA project directory could not be decompressed completely");
        ret = CL_EPARSE;
        goto done;
    }
#endif

    *has_macros = *has_macros + 1;

    if ((ret = cli_gentempfd_with_prefix(ctx->this_layer_tmpdir, "vba_project", tempfile, tempfd)) != CL_SUCCESS) {
        cli_warnmsg("vba_readdir_new: VBA project cannot be dumped to file\n");
        cli_mark_scan_incomplete(ctx, "VBA project temporary output could not be created");
        goto done;
    }

    project_output.ctx                = ctx;
    project_output.fd                 = *tempfd;
    project_output.temporary_reserved = &temporary_reserved;

    cli_dbgmsg("Dumping VBA project from dir %s to file %s\n", fullname, *tempfile);

#define CLI_WRITEN(msg, size)                                                       \
    do {                                                                            \
        ret = vba_project_output_write(&project_output,                             \
                                       (const unsigned char *)(msg), (size_t)(size)); \
        if (ret != CL_SUCCESS)                                                      \
            goto done;                                                              \
    } while (0)

#define CLI_WRITENHEX(msg, size)                                                           \
    do {                                                                                   \
        unsigned i;                                                                        \
        for (i = 0; i < size; ++i) {                                                       \
            char buf[4];                                                                   \
            if (snprintf(buf, sizeof(buf), "%02x", (msg)[i]) != 2) {                       \
                cli_warnmsg("vba_readdir_new: Failed to write hex data to output file\n"); \
                ret = CL_EWRITE;                                                           \
                goto done;                                                                 \
            }                                                                              \
            CLI_WRITEN(buf, 2);                                                            \
        }                                                                                  \
    } while (0)

#define CLI_WRITEN_CODEPAGE(msg, size, selected_codepage, digest)                                  \
    do {                                                                                            \
        ret = vba_project_write_converted(&project_output, (const unsigned char *)(msg),            \
                                          (size_t)(size), (selected_codepage), (digest),            \
                                          data_is_mapped ? data : NULL, data_len, data_offset,      \
                                          &data_released);                                          \
        if (ret != CL_SUCCESS) {                                                                    \
            cli_mark_scan_incomplete(ctx, "VBA project metadata could not be converted completely"); \
            goto done;                                                                              \
        }                                                                                            \
    } while (0)

    CLI_WRITEN("REM VBA project extracted from Microsoft Office document\n\n", 58);

    for (data_offset = 0; data_offset < data_len;) {
        uint16_t id, val16;
        uint32_t size, val32;

        if (sizeof(uint16_t) > data_len - data_offset) {
            cli_warnmsg("vba_readdir_new: Failed to read record type from dir\n");
            ret = CL_EREAD;
            goto done;
        }
        memcpy(&val16, &data[data_offset], sizeof(uint16_t));
        id = le16_to_host(val16);
        data_offset += sizeof(uint16_t);

        if (sizeof(uint32_t) > data_len - data_offset) {
            cli_warnmsg("vba_readdir_new: Failed to read record size from dir\n");
            ret = CL_EREAD;
            goto done;
        }
        memcpy(&val32, &data[data_offset], sizeof(uint32_t));
        size = le32_to_host(val32);
        data_offset += sizeof(uint32_t);

        if (size > data_len - data_offset) {
            cli_warnmsg("vba_readdir_new: Record stretches past the end of the file\n");
            ret = CL_EREAD;
            goto done;
        }

        switch (id) {
            // MS-OVBA 2.3.4.2.1.1 PROJECTSYSKIND
            case 0x0001: {
                if (size != sizeof(uint32_t)) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected PROJECTSYSKIND record size (%" PRIu32 " != 4)\n", size);
                    ret = CL_EREAD;
                    goto done;
                }
                memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                uint32_t sys_kind = le32_to_host(val32);
                data_offset += sizeof(uint32_t);
                CLI_WRITEN("REM PROJECTSYSKIND: ", 20);
                switch (sys_kind) {
                    case 0x0:
                        CLI_WRITEN("Windows 16 bit", 14);
                        break;
                    case 0x1:
                        CLI_WRITEN("Windows 32 bit", 14);
                        break;
                    case 0x2:
                        CLI_WRITEN("Macintosh", 9);
                        break;
                    case 0x3:
                        CLI_WRITEN("Windows 64 bit", 14);
                        break;
                    default: {
                        char str_sys_kind[22];
                        int len                                = snprintf(str_sys_kind, sizeof(str_sys_kind), "Unknown (0x%x)", sys_kind);
                        str_sys_kind[sizeof(str_sys_kind) - 1] = '\0';
                        if (len > 0) {
                            CLI_WRITEN(str_sys_kind, (size_t)len);
                        }
                        break;
                    }
                }
                CLI_WRITEN("\n", 1);
                break;
            }
            // MS-OVBA 2.3.4.2.1.2 PROJECTLCID
            case 0x0002: {
                if (size != sizeof(uint32_t)) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected PROJECTLCID record size (%" PRIu32 " != 4)\n", size);
                    ret = CL_EREAD;
                    goto done;
                }
                memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                uint32_t lcid = le32_to_host(val32);
                char buf[64];
                data_offset += size;
                int buf_length       = snprintf(buf, sizeof(buf), "REM PROJECTLCID: 0x%08x\n", lcid);
                buf[sizeof(buf) - 1] = '\0';
                if (buf_length > 0) {
                    CLI_WRITEN(buf, (size_t)buf_length);
                }
                break;
            }
            // MS-OVBA 2.3.4.2.1.3 PROJECTLCIDINVOKE
            case 0x0014: {
                if (size != sizeof(uint32_t)) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected PROJECTLCIDINVOKE record size (%" PRIu32 " != 4)\n", size);
                    ret = CL_EREAD;
                    goto done;
                }
                memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                uint32_t lcid_invoke = le32_to_host(val32);
                char buf[64];
                data_offset += sizeof(uint32_t);
                int buf_length       = snprintf(buf, sizeof(buf), "REM PROJECTLCIDINVOKE: 0x%08x\n", lcid_invoke);
                buf[sizeof(buf) - 1] = '\0';
                if (buf_length > 0) {
                    CLI_WRITEN(buf, (size_t)buf_length);
                }
                break;
            }
            // MS-OVBA 2.3.4.2.1.4 PROJECTCODEPAGE
            case 0x0003: {
                if (size != sizeof(uint16_t)) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected PROJECTCODEPAGE record size (%" PRIu32 " != 2)\n", size);
                    ret = CL_EREAD;
                    goto done;
                }
                memcpy(&val16, &data[data_offset], sizeof(uint16_t));
                codepage = le16_to_host(val16);
                char buf[64];
                data_offset += sizeof(uint16_t);
                int buf_length       = snprintf(buf, sizeof(buf), "REM PROJECTCODEPAGE: 0x%04x\n", codepage);
                buf[sizeof(buf) - 1] = '\0';
                if (buf_length > 0) {
                    CLI_WRITEN(buf, (size_t)buf_length);
                }
                break;
            }
            // MS-OVBA 2.3.4.2.1.5 PROJECTNAME
            case 0x0004: {
                if (size < 1 || size > 128) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected PROJECTNAME record size (1 <= %" PRIu32 " <= 128)\n", size);
                    ret = CL_EREAD;
                    goto done;
                }

                CLI_WRITEN("REM PROJECTNAME: ", 17);
                CLI_WRITEN_CODEPAGE(&data[data_offset], size, codepage, NULL);
                data_offset += size;
                CLI_WRITEN("\n", 1);
                break;
            }
            // MS-OVBA 2.3.4.2.1.6 PROJECTDOCSTRING
            case 0x0005: {
                CLI_WRITEN("REM PROJECTDOCSTRING: ", 22);
                CLI_WRITEN_CODEPAGE(&data[data_offset], size, codepage, NULL);
                data_offset += size;
                CLI_WRITEN("\n", 1);
                break;
            }
            // MS-OVBA 2.3.4.2.1.6 PROJECTDOCSTRING Unicode
            case 0x0040: {
                if (size % 2 != 0) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected PROJECTDOCSTRINGUNICODE record size (%" PRIu32 " but should be even)\n", size);
                    ret = CL_EREAD;
                    goto done;
                }
                CLI_WRITEN("REM PROJECTDOCSTRINGUNICODE: ", 29);
                CLI_WRITEN_CODEPAGE(&data[data_offset], size, CODEPAGE_UTF16_LE, NULL);
                data_offset += size;
                CLI_WRITEN("\n", 1);
                break;
            }
            // MS-OVBA 2.3.4.2.1.7 PROJECTHELPFILEPATH
            case 0x0006: {
                if (size > 260) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected PROJECTHELPFILEPATH record size (%" PRIu32 " <= 260)\n", size);
                    ret = CL_EREAD;
                    goto done;
                }
                const size_t projecthelpfilepath_offset = data_offset;
                CLI_WRITEN("REM PROJECTHELPFILEPATH: ", 25);
                CLI_WRITEN_CODEPAGE(&data[data_offset], size, codepage, NULL);
                data_offset += size;
                CLI_WRITEN("\n", 1);

                if (sizeof(uint16_t) > data_len - data_offset) {
                    cli_warnmsg("vba_readdir_new: Failed to read record type from dir\n");
                    ret = CL_EREAD;
                    goto done;
                }
                memcpy(&val16, &data[data_offset], sizeof(uint16_t));
                id = le16_to_host(val16);
                if (id != 0x003d) {
                    cli_warnmsg("vba_readdir_new: PROJECTHELPFILEPATH is not followed by PROJECTHELPFILEPATH2\n");
                    CLI_WRITEN("REM WARNING: PROJECTHELPFILEPATH is not followed by PROJECTHELPFILEPATH2\n", 73);
                    continue;
                }
                data_offset += sizeof(uint16_t);

                if (sizeof(uint32_t) > data_len - data_offset) {
                    cli_warnmsg("vba_readdir_new: Failed to read record size of PROJECTHELPFILEPATH2 record from dir\n");
                    ret = CL_EREAD;
                    goto done;
                }
                uint32_t size2;
                memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                size2 = le32_to_host(val32);
                data_offset += sizeof(uint32_t);

                if (size2 > data_len - data_offset) {
                    cli_warnmsg("vba_readdir_new: PROJECTHELPFILEPATH2 record stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }

                if (size2 > 260) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected PROJECTHELPFILEPATH2 record size (%" PRIu32 " <= 260)\n", size);
                    ret = CL_EREAD;
                    goto done;
                }

                if (size != size2) {
                    CLI_WRITEN("REM WARNING: PROJECTHELPFILEPATH and PROJECTHELPFILEPATH2 record sizes differ\n", 78);
                } else {
                    if (memcmp(&data[projecthelpfilepath_offset], &data[data_offset], size) != 0) {
                        CLI_WRITEN("REM WARNING: PROJECTHELPFILEPATH and PROJECTHELPFILEPATH2 contents differ\n", 74);
                    }
                }

                CLI_WRITEN("REM PROJECTHELPFILEPATH2: ", 26);
                CLI_WRITEN_CODEPAGE(&data[data_offset], size2, CODEPAGE_UTF16_LE, NULL);
                data_offset += size2;
                CLI_WRITEN("\n", 1);
                break;
            }
            // MS-OVBA 2.3.4.2.1.8 PROJECTHELPCONTEXT
            case 0x0007: {
                if (size != sizeof(uint32_t)) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected PROJECTHELPCONTEXT record size (%" PRIu32 " != 4)\n", size);
                    ret = CL_EREAD;
                    goto done;
                }
                memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                uint32_t context = le32_to_host(val32);
                char buf[64];
                data_offset += size;
                int buf_length       = snprintf(buf, sizeof(buf), "REM PROJECTHELPCONTEXT: 0x%04x\n", context);
                buf[sizeof(buf) - 1] = '\0';
                if (buf_length > 0) {
                    CLI_WRITEN(buf, (size_t)buf_length);
                }
                break;
            }
            // MS-OVBA 2.3.4.2.1.9 PROJECTLIBFLAGS
            case 0x0008: {
                if (size != sizeof(uint32_t)) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected PROJECTLIBFLAGS record size (%" PRIu32 " != 4)\n", size);
                    ret = CL_EREAD;
                    goto done;
                }
                memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                uint32_t libflags = le32_to_host(val32);
                char buf[64];
                data_offset += sizeof(uint32_t);
                int buf_length       = snprintf(buf, sizeof(buf), "REM PROJECTLIBFLAGS: 0x%04x\n", libflags);
                buf[sizeof(buf) - 1] = '\0';
                if (buf_length > 0) {
                    CLI_WRITEN(buf, (size_t)buf_length);
                }
                break;
            }
            // MS-OVBA 2.3.4.2.1.10 PROJECTVERSION
            case 0x0009: {
                // The PROJECTVERSION record size is expected to be 4, even though the record size is 6.
                if (size != 4) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected PROJECTVERSION record size (%" PRIu32 " != 4)\n", size);
                    ret = CL_EREAD;
                    goto done;
                }
                memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                uint32_t major = le32_to_host(val32);
                data_offset += size;

                if (sizeof(uint16_t) > data_len - data_offset) {
                    cli_warnmsg("vba_readdir_new: PROJECTVERSION record stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }
                memcpy(&val16, &data[data_offset], sizeof(uint16_t));
                uint16_t minor = le16_to_host(val16);
                data_offset += sizeof(uint16_t);
                char buf[64];
                int buf_length       = snprintf(buf, sizeof(buf), "REM PROJECTVERSION: %u.%u\n", major, minor);
                buf[sizeof(buf) - 1] = '\0';
                if (buf_length > 0) {
                    CLI_WRITEN(buf, (size_t)buf_length);
                }
                break;
            }
            // MS-OVBA 2.3.4.2.3 PROJECTMODULES
            case 0x000f: {
                if (size != sizeof(uint16_t)) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected PROJECTMODULES record size\n");
                    ret = CL_EREAD;
                    goto done;
                }
                memcpy(&val16, &data[data_offset], sizeof(uint16_t));
                uint16_t modules = le16_to_host(val16);
                data_offset += sizeof(uint16_t);
                char buf[64];
                int buf_length       = snprintf(buf, sizeof(buf), "REM PROJECTMODULES: %u\n", modules);
                buf[sizeof(buf) - 1] = '\0';
                if (buf_length > 0) {
                    CLI_WRITEN(buf, (size_t)buf_length);
                }
                break;
            }
            // MS-OVBA 2.3.4.2.3.1 PROJECTCOOKIE
            case 0x0013: {
                if (size != sizeof(uint16_t)) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected PROJECTCOOKIE record size\n");
                    ret = CL_EREAD;
                    goto done;
                }
                memcpy(&val16, &data[data_offset], sizeof(uint16_t));
                uint16_t cookie = le16_to_host(val16);
                data_offset += sizeof(uint16_t);
                char buf[64];
                int buf_length       = snprintf(buf, sizeof(buf), "REM PROJECTCOOKIE: 0x%04x\n", cookie);
                buf[sizeof(buf) - 1] = '\0';
                if (buf_length > 0) {
                    CLI_WRITEN(buf, (size_t)buf_length);
                }
                break;
            }
            // MS-OVBA 2.3.4.2.3.2 MODULE record
            case 0x0019: {
                struct vba_metadata_digest mbcs_digest;
                struct vba_metadata_digest utf16_digest;

                // MS-OVBA 2.3.4.2.3.2.1 MODULENAME
                CLI_WRITEN("\n\nREM MODULENAME: ", 18);
                CLI_WRITEN_CODEPAGE(&data[data_offset], size, codepage, &mbcs_digest);
                data_offset += size;

                // MS-OVBA 2.3.4.2.3.2.2 MODULENAMEUNICODE
                cli_dbgmsg("Reading MODULENAMEUNICODE record\n");
                if (sizeof(uint16_t) + sizeof(uint32_t) > data_len - data_offset) {
                    cli_dbgmsg("vba_readdir_new: MODULENAMEUNICODE record stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }

                memcpy(&val16, &data[data_offset], sizeof(uint16_t));
                if ((id = le16_to_host(val16)) != 0x0047) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected MODULENAMEUNICODE (0x47) record, but got 0x%04x\n", id);
                    ret = CL_EREAD;
                    goto done;
                }
                data_offset += sizeof(uint16_t);
                CLI_WRITEN("\nREM MODULENAMEUNICODE: ", 24);
                memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                size = le32_to_host(val32);
                data_offset += sizeof(uint32_t);

                if (size > data_len - data_offset) {
                    cli_dbgmsg("vba_readdir_new: MODULENAMEUNICODE stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }
                if (size % 2 != 0) {
                    cli_mark_scan_incomplete(ctx, "VBA Unicode module name has an odd byte length");
                    ret = CL_EREAD;
                    goto done;
                }

                CLI_WRITEN_CODEPAGE(&data[data_offset], size, CODEPAGE_UTF16_LE, &utf16_digest);
                data_offset += size;

                if (!vba_metadata_digest_equal(&mbcs_digest, &utf16_digest)) {
                    CLI_WRITEN("\nREM WARNING: MODULENAME and MODULENAMEUNICODE differ", 53);
                }

                // MS-OVBA 2.3.4.2.3.2.3 MODULESTREAMNAME
                cli_dbgmsg("Reading MODULESTREAMNAME record\n");
                if (sizeof(uint16_t) + sizeof(uint32_t) > data_len - data_offset) {
                    cli_dbgmsg("vba_readdir_new: MODULESTREAMNAME record stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }

                memcpy(&val16, &data[data_offset], sizeof(uint16_t));
                if ((id = le16_to_host(val16)) != 0x001a) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected MODULESTREAMNAME (0x1a) record, but got 0x%04x\n", id);
                    ret = CL_EREAD;
                    goto done;
                }
                data_offset += sizeof(uint16_t);
                CLI_WRITEN("\nREM MODULESTREAMNAME: ", 23);
                memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                size = le32_to_host(val32);
                data_offset += sizeof(uint32_t);

                if (size > data_len - data_offset) {
                    cli_dbgmsg("vba_readdir_new: MODULESTREAMNAME stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }
                CLI_WRITEN_CODEPAGE(&data[data_offset], size, codepage, &mbcs_digest);
                data_offset += size;

                cli_dbgmsg("Reading MODULESTREAMNAMEUNICODE record\n");
                if (sizeof(uint16_t) + sizeof(uint32_t) > data_len - data_offset) {
                    cli_dbgmsg("vba_readdir_new: MODULESTREAMNAMEUNICODE record stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }

                memcpy(&val16, &data[data_offset], sizeof(uint16_t));
                if ((id = le16_to_host(val16)) != 0x0032) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected MODULESTREAMNAMEUNICODE (0x32) record, but got 0x%04x\n", id);
                    ret = CL_EREAD;
                    goto done;
                }
                data_offset += sizeof(uint16_t);
                CLI_WRITEN("\nREM MODULESTREAMNAMEUNICODE: ", 30);
                memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                uint32_t module_stream_name_size = le32_to_host(val32);
                data_offset += sizeof(uint32_t);

                if (module_stream_name_size > data_len - data_offset) {
                    cli_dbgmsg("vba_readdir_new: MODULESTREAMNAMEUNICODE stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }
                if (module_stream_name_size == 0) {
                    cli_mark_scan_incomplete(ctx, "VBA Unicode module stream name is empty");
                    ret = CL_EFORMAT;
                    goto done;
                }
                if (module_stream_name_size > VBA_OLE_STREAM_NAME_LIMIT || module_stream_name_size % 2 != 0) {
                    cli_mark_scan_incomplete(ctx, "VBA Unicode module stream name exceeds the bounded OLE metadata limit");
                    ret = CL_EFORMAT;
                    goto done;
                }

                const unsigned char *module_stream_name = &data[data_offset];
                CLI_WRITEN_CODEPAGE(&data[data_offset], module_stream_name_size,
                                     CODEPAGE_UTF16_LE, &utf16_digest);
                data_offset += module_stream_name_size;

                if (!vba_metadata_digest_equal(&mbcs_digest, &utf16_digest)) {
                    CLI_WRITEN("\nREM WARNING: MODULESTREAMNAME and MODULESTREAMNAMEUNICODE differ", 65);
                }

                // MS-OVBA 2.3.4.2.3.2.4 MODULEDOCSTRING
                cli_dbgmsg("Reading MODULEDOCSTRING record\n");
                if (sizeof(uint16_t) + sizeof(uint32_t) > data_len - data_offset) {
                    cli_dbgmsg("vba_readdir_new: MODULEDOCSTRING record stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }

                memcpy(&val16, &data[data_offset], sizeof(uint16_t));
                if ((id = le16_to_host(val16)) != 0x001c) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected MODULEDOCSTRING (0x1c) record, but got 0x%04x\n", id);
                    ret = CL_EREAD;
                    goto done;
                }
                data_offset += sizeof(uint16_t);
                CLI_WRITEN("\nREM MODULEDOCSTRING: ", 22);
                memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                size = le32_to_host(val32);
                data_offset += sizeof(uint32_t);

                if (size > data_len - data_offset) {
                    cli_dbgmsg("vba_readdir_new: MODULEDOCSTRING stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }
                CLI_WRITEN_CODEPAGE(&data[data_offset], size, codepage, &mbcs_digest);
                data_offset += size;

                cli_dbgmsg("Reading MODULEDOCSTRINGUNICODE record\n");
                if (sizeof(uint16_t) + sizeof(uint32_t) > data_len - data_offset) {
                    cli_dbgmsg("vba_readdir_new: MODULEDOCSTRINGUNICODE record stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }

                memcpy(&val16, &data[data_offset], sizeof(uint16_t));
                if ((id = le16_to_host(val16)) != 0x0048) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected MODULEDOCSTRINGUNICODE (0x32) record, but got 0x%04x\n", id);
                    ret = CL_EREAD;
                    goto done;
                }
                data_offset += sizeof(uint16_t);
                CLI_WRITEN("\nREM MODULEDOCSTRINGUNICODE: ", 29);
                memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                size = le32_to_host(val32);
                data_offset += sizeof(uint32_t);

                if (size > data_len - data_offset) {
                    cli_dbgmsg("vba_readdir_new: MODULEDOCSTRINGUNICODE stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }
                if (size % 2 != 0) {
                    cli_mark_scan_incomplete(ctx, "VBA Unicode module docstring has an odd byte length");
                    ret = CL_EREAD;
                    goto done;
                }

                CLI_WRITEN_CODEPAGE(&data[data_offset], size, CODEPAGE_UTF16_LE, &utf16_digest);
                data_offset += size;

                if (!vba_metadata_digest_equal(&mbcs_digest, &utf16_digest)) {
                    CLI_WRITEN("\nREM WARNING: MODULEDOCSTRING and MODULEDOCSTRINGUNICODE differ", 63);
                }

                // MS-OVBA 2.3.4.2.3.2.5 MODULEOFFSET
                cli_dbgmsg("Reading MODULEOFFSET record\n");
                if (sizeof(uint16_t) + sizeof(uint32_t) > data_len - data_offset) {
                    cli_dbgmsg("vba_readdir_new: MODULEOFFSET record stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }

                memcpy(&val16, &data[data_offset], sizeof(uint16_t));
                if ((id = le16_to_host(val16)) != 0x0031) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected MODULEOFFSET (0x31) record, but got 0x%04x\n", id);
                    ret = CL_EREAD;
                    goto done;
                }
                data_offset += sizeof(uint16_t);
                memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                size = le32_to_host(val32);
                data_offset += sizeof(uint32_t);
                if (size != sizeof(uint32_t)) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected MODULEOFFSET record size");
                    ret = CL_EREAD;
                    goto done;
                }

                if (size > data_len - data_offset) {
                    cli_dbgmsg("vba_readdir_new: MODULEOFFSET stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }

                memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                uint32_t module_offset = le32_to_host(val32);
                data_offset += size;
                char buffer[64];
                int buffer_size = snprintf(buffer, sizeof(buffer), "\nREM MODULEOFFSET: 0x%08x", module_offset);
                if (buffer_size > 0) {
                    CLI_WRITEN(buffer, (size_t)buffer_size);
                }

                // MS-OVBA 2.3.4.2.3.2.6 MODULEHELPCONTEXT
                cli_dbgmsg("Reading MODULEHELPCONTEXT record\n");
                if (sizeof(uint16_t) + sizeof(uint32_t) > data_len - data_offset) {
                    cli_dbgmsg("vba_readdir_new: MODULEHELPCONTEXT record stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }

                memcpy(&val16, &data[data_offset], sizeof(uint16_t));
                if ((id = le16_to_host(val16)) != 0x001e) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected MODULEHELPCONTEXT (0x1e) record, but got 0x%04x\n", id);
                    ret = CL_EREAD;
                    goto done;
                }

                data_offset += sizeof(uint16_t);
                memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                size = le32_to_host(val32);
                data_offset += sizeof(uint32_t);
                if (size != sizeof(uint32_t)) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected MODULEHELPCONTEXT record size");
                    ret = CL_EREAD;
                    goto done;
                }

                if (size > data_len - data_offset) {
                    cli_dbgmsg("vba_readdir_new: MODULEHELPCONTEXT stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }

                memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                uint32_t help_context = le32_to_host(val32);
                data_offset += size;
                buffer_size = snprintf(buffer, sizeof(buffer), "\nREM MODULEHELPCONTEXT: 0x%08x", help_context);
                if (buffer_size > 0) {
                    CLI_WRITEN(buffer, (size_t)buffer_size);
                }

                // MS-OVBA 2.3.4.2.3.2.7 MODULECOOKIE
                cli_dbgmsg("Reading MODULECOOKIE record\n");
                if (sizeof(uint16_t) + sizeof(uint32_t) > data_len - data_offset) {
                    cli_dbgmsg("vba_readdir_new: MODULECOOKIE record stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }

                memcpy(&val16, &data[data_offset], sizeof(uint16_t));
                if ((id = le16_to_host(val16)) != 0x002c) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected MODULECOOKIE (0x2c) record, but got 0x%04x\n", id);
                    ret = CL_EREAD;
                    goto done;
                }
                data_offset += sizeof(uint16_t);
                memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                size = le32_to_host(val32);
                data_offset += sizeof(uint32_t);
                if (size != sizeof(uint16_t)) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected MODULECOOKIE record size");
                    ret = CL_EREAD;
                    goto done;
                }

                if (size > data_len - data_offset) {
                    cli_dbgmsg("vba_readdir_new: MODULECOOKIE record's cookie stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }

                memcpy(&val16, &data[data_offset], sizeof(uint16_t));
                uint16_t cookie = le16_to_host(val16);
                data_offset += size;
                buffer_size = snprintf(buffer, sizeof(buffer), "\nREM MODULECOOKIE: 0x%04x", cookie);
                if (buffer_size > 0) {
                    CLI_WRITEN(buffer, (size_t)buffer_size);
                }

                // MS-OVBA 2.3.4.2.3.2.8 MODULETYPE
                if (sizeof(uint16_t) + sizeof(uint32_t) > data_len - data_offset) {
                    cli_dbgmsg("vba_readdir_new: MODULETYPE record stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }

                memcpy(&val16, &data[data_offset], sizeof(uint16_t));
                id = le16_to_host(val16);
                if (id != 0x0021 && id != 0x0022) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected MODULETYPE (0x21/0x22) record, but got 0x%04x\n", id);
                    ret = CL_EREAD;
                    goto done;
                }
                data_offset += sizeof(uint16_t);
                memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                size = le32_to_host(val32);
                data_offset += sizeof(uint32_t);
                if (size != 0) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected MODULETYPE record size");
                    ret = CL_EREAD;
                    goto done;
                }
                if (id == 0x21) {
                    CLI_WRITEN("\nREM MODULETYPE: Procedural", 27);
                } else {
                    CLI_WRITEN("\nREM MODULETYPE: Class", 22);
                }

                // MS-OVBA 2.3.4.2.3.2.9 MODULEREADONLY
                if (sizeof(uint16_t) > data_len - data_offset) {
                    cli_dbgmsg("vba_readdir_new: MODULEREADONLY record id field stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }

                memcpy(&val16, &data[data_offset], sizeof(uint16_t));
                id = le16_to_host(val16);
                data_offset += sizeof(uint16_t);

                if (id == 0x0025) {
                    if (sizeof(uint32_t) > data_len - data_offset) {
                        cli_dbgmsg("vba_readdir_new: MODULEREADONLY record size field stretches past the end of the file\n");
                        ret = CL_EREAD;
                        goto done;
                    }

                    memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                    size = le32_to_host(val32);
                    data_offset += sizeof(uint32_t);
                    if (size != 0) {
                        cli_dbgmsg("cli_vba_readdir_new: Expected MODULEREADONLY record size");
                        ret = CL_EREAD;
                        goto done;
                    }
                    CLI_WRITEN("\nREM MODULEREADONLY", 19);

                    if (sizeof(uint16_t) > data_len - data_offset) {
                        cli_dbgmsg("vba_readdir_new: record id field after MODULEREADONLY stretches past the end of the file\n");
                        ret = CL_EREAD;
                        goto done;
                    }

                    memcpy(&val16, &data[data_offset], sizeof(uint16_t));
                    id = le16_to_host(val16);
                    data_offset += sizeof(uint16_t);
                }

                // MS-OVBA 2.3.4.2.3.2.10 MODULEPRIVATE
                if (id == 0x0028) {
                    if (sizeof(uint32_t) > data_len - data_offset) {
                        cli_dbgmsg("vba_readdir_new: MODULEPRIVATE record size field stretches past the end of the file\n");
                        ret = CL_EREAD;
                        goto done;
                    }

                    memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                    size = le32_to_host(val32);
                    data_offset += sizeof(uint32_t);
                    if (size != 0) {
                        cli_dbgmsg("cli_vba_readdir_new: Expected MODULEPRIVATE record size");
                        ret = CL_EREAD;
                        goto done;
                    }
                    CLI_WRITEN("\nREM MODULEPRIVATE", 18);

                    if (sizeof(uint16_t) > data_len - data_offset) {
                        cli_dbgmsg("vba_readdir_new: record id field after MODULEPRIVATE stretches past the end of the file\n");
                        ret = CL_EREAD;
                        goto done;
                    }

                    memcpy(&val16, &data[data_offset], sizeof(uint16_t));
                    id = le16_to_host(val16);
                    data_offset += sizeof(uint16_t);
                }

                // Terminator
                if (id != 0x002b) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected MODULETERMINATOR ....");
                    ret = CL_EREAD;
                    goto done;
                }

                if (sizeof(uint32_t) > data_len - data_offset) {
                    cli_dbgmsg("vba_readdir_new: MODULETERMINATOR record size field stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }

                memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                size = le32_to_host(val32);
                data_offset += sizeof(uint32_t);
                if (size != 0) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected MODULETERMINATOR record size");
                    ret = CL_EREAD;
                    goto done;
                }

                CLI_WRITEN("\nREM ##################################################\n", 56);

                stream_name = cli_ole2_get_property_name2((const char *)module_stream_name, (int)(module_stream_name_size + 2));
                char *module_hash;
                uint32_t module_hashcnt;
                if (stream_name == NULL) {
                    ret = CL_EMEM;
                    goto done;
                }
                if (uniq_get(U, stream_name, (uint32_t)strlen(stream_name), &module_hash, &module_hashcnt) != CL_SUCCESS) {
                    cli_dbgmsg("cli_vba_readdir_new: Cannot find module stream %s\n", stream_name);
                    ret = CL_EOPEN;
                    goto done;
                }

                int module_stream_found = 0;

                for (i = 1; i <= module_hashcnt; ++i) {
                    char module_filename[PATH_MAX];
                    snprintf(module_filename, sizeof(module_filename), "%s" PATHSEP "%s_%u", dir, module_hash, i);
                    module_filename[sizeof(module_filename) - 1] = '\0';

                    int module_fd = open(module_filename, O_RDONLY | O_BINARY);
                    if (module_fd == -1) {
                        continue;
                    }

                    off_t module_output_offset = lseek(*tempfd, 0, SEEK_CUR);
                    uint64_t reservation_before = temporary_reserved;
                    uint64_t module_output_size  = 0;
                    cl_error_t module_status;

                    if (module_output_offset == (off_t)-1) {
                        cli_mark_scan_incomplete(ctx, "VBA module output position could not be recorded");
                        ret = CL_ESEEK;
                        if (close(module_fd) != 0)
                            vba_note_cleanup_failure(ctx, &ret, CL_EREAD,
                                                     "VBA module temporary input could not be closed");
                        goto done;
                    }

                    module_status = vba_extract_module_stream(module_fd, module_offset, codepage,
                                                              &project_output, &module_output_size);
                    if (module_status != CL_BREAK) {
                        if (module_status != CL_SUCCESS) {
                            cl_error_t rollback_status = vba_project_output_rollback(
                                &project_output, module_output_offset, reservation_before);

                            cli_dbgmsg("cli_vba_readdir_new: Bounded module extraction failed: %s\n",
                                       cl_strerror(module_status));
                            cli_mark_scan_incomplete(ctx, "VBA module could not be decompressed, decoded, and normalized completely");
                            if (deferred_failure == CL_SUCCESS)
                                deferred_failure = module_status;
                            if (close(module_fd) != 0)
                                vba_note_cleanup_failure(ctx, &module_status, CL_EREAD,
                                                         "VBA module temporary input could not be closed");
                            deferred_failure = cli_merge_cleanup_status(deferred_failure, module_status);
                            module_stream_found = 1;

                            if (rollback_status != CL_SUCCESS) {
                                ret = rollback_status;
                                goto done;
                            }
                            CLI_WRITEN("\n<Error decoding module data>\n", 30);
                            break;
                        }

                        if (close(module_fd) != 0) {
                            vba_note_cleanup_failure(ctx, &module_status, CL_EREAD,
                                                     "VBA module temporary input could not be closed");
                        }
                        deferred_failure = cli_merge_cleanup_status(deferred_failure, module_status);

                        module_stream_found = 1;
                        module_status       = vba_invoke_module_callback(ctx, *tempfd,
                                                                         module_output_offset,
                                                                         module_output_size);
                        if (module_status == CL_ESEEK) {
                            ret = module_status;
                            goto done;
                        }
                        deferred_failure = cli_merge_cleanup_status(deferred_failure, module_status);
                        /* Callback delivery is auxiliary. Allocation, read,
                         * and contiguous-ABI failures are already recorded as
                         * incomplete, but must not suppress bounded scanning
                         * of the project spool. Preserve the failure for the
                         * direct project-directory caller after that scan. */
                        break;
                    }

                    /* Platforms without a bounded converter retain the legacy
                     * contiguous path for ABI compatibility. */
                    module_data = cli_vba_inflate(module_fd, module_offset, &module_data_size);
                    if (!module_data) {
                        cli_dbgmsg("cli_vba_readdir_new: Failed to extract module data\n");
                        cli_mark_scan_incomplete(ctx, "VBA module requires an unavailable bounded codepage converter or exceeded the fallback allocation boundary");
                        if (deferred_failure == CL_SUCCESS)
                            deferred_failure = CL_EPARSE;
                        if (close(module_fd) != 0)
                            vba_note_cleanup_failure(ctx, &deferred_failure, CL_EREAD,
                                                     "VBA module temporary input could not be closed");
                        continue;
                    }

                    if (close(module_fd) != 0) {
                        vba_note_cleanup_failure(ctx, &deferred_failure, CL_EREAD,
                                                 "VBA module temporary input could not be closed");
                    }
                    module_stream_found = 1;

                    if (CL_SUCCESS == cli_codepage_to_utf8((char *)module_data, module_data_size, codepage, (char **)&module_data_utf8, &module_data_utf8_size)) {
                        module_data_utf8_size = vba_normalize(module_data_utf8, module_data_utf8_size);

                        CLI_WRITEN(module_data_utf8, module_data_utf8_size);

                        if (NULL != ctx->engine->cb_vba)
                            ctx->engine->cb_vba(module_data_utf8, module_data_utf8_size, ctx->cb_ctx);

                        free(module_data_utf8);
                        module_data_utf8 = NULL;
                    } else {
                        if (NULL != ctx->engine->cb_vba)
                            ctx->engine->cb_vba(module_data, module_data_size, ctx->cb_ctx);

                        CLI_WRITEN("\n<Error decoding module data>\n", 30);
                        cli_dbgmsg("cli_vba_readdir_new: Failed to decode VBA module content from codepage %" PRIu16 " to UTF8\n", codepage);
                    }

                    free(module_data);
                    module_data = NULL;
                    break;
                }

                if (!module_stream_found) {
                    cli_dbgmsg("cli_vba_readdir_new: Cannot find module stream %s\n", stream_name);
                    cli_mark_scan_incomplete(ctx, "VBA module stream could not be opened for inspection");
                    if (deferred_failure == CL_SUCCESS)
                        deferred_failure = CL_EOPEN;
                }
                free((void *)stream_name);
                stream_name = NULL;

                break;
            }
            case 0x0010: { // Terminator
                ret = CL_SUCCESS;
                goto done;
            }
            default: {
                data_offset += size;
            }
        }
        if (data_is_mapped)
            vba_directory_release_consumed(data, data_len, data_offset, &data_released);
    }

#undef CLI_WRITEN
#undef CLI_WRITENHEX
#undef CLI_WRITEN_CODEPAGE

done:
    if (ret == CL_SUCCESS && deferred_failure != CL_SUCCESS)
        ret = deferred_failure;

    if (fd >= 0) {
        if (close(fd) != 0) {
            vba_note_cleanup_failure(ctx, &ret, CL_EREAD,
                                     "VBA project directory input could not be closed");
        }
    }
    if (data_is_mapped && data != NULL) {
#if VBA_HAVE_FILE_BACKED_DIRECTORY
        if (munmap(data, data_len) != 0) {
            vba_note_cleanup_failure(ctx, &ret, CL_ERESOURCE,
                                     "VBA project directory backing could not be unmapped");
        }
#endif
        data = NULL;
    } else if (data) {
        free((void *)data);
        data = NULL;
    }
    if (datafd >= 0) {
        if (close(datafd) != 0)
            vba_note_cleanup_failure(ctx, &ret, CL_EREAD,
                                     "VBA project directory backing could not be closed");
        datafd = -1;
    }
    if (datafile != NULL) {
        if (!ctx->engine->keeptmp && cli_unlink(datafile) != 0)
            vba_note_cleanup_failure(ctx, &ret, CL_EUNLINK,
                                     "VBA project directory backing could not be removed");
        free(datafile);
        datafile = NULL;
    }
    if (directory_reserved != 0)
        cli_scan_release_temporary(ctx, directory_reserved);
    if (stream_name) {
        free((void *)stream_name);
    }
    if (ret != CL_SUCCESS && *tempfd >= 0) {
        if (close(*tempfd) != 0)
            vba_note_cleanup_failure(ctx, &ret, CL_EWRITE,
                                     "VBA project temporary output could not be closed");
        *tempfd = -1;
    }
    if (module_data) {
        free(module_data);
        module_data = NULL;
    }
    if (module_data_utf8) {
        free(module_data_utf8);
        module_data_utf8 = NULL;
    }

    if (ret == CL_SUCCESS) {
        *temporary_reserved_out = temporary_reserved;
        temporary_reserved = 0;
    }
    if (temporary_reserved)
        cli_scan_release_temporary(ctx, temporary_reserved);

    return ret;
}

vba_project_t *
cli_vba_readdir(const char *dir, struct uniq *U, uint32_t which)
{
    unsigned char *buf;
    const unsigned char vba56_signature[] = {0xcc, 0x61};
    uint16_t record_count, buflen, ffff, byte_count;
    uint32_t offset;
    int i, j, fd, big_endian = FALSE;
    vba_project_t *vba_project;
    struct vba56_header v56h;
    off_t seekback;
    char fullname[1024], *hash;
    uint32_t hashcnt = 0;

    cli_dbgmsg("in cli_vba_readdir()\n");

    if (dir == NULL)
        return NULL;

    /*
     * _VBA_PROJECT files are embedded within office documents (OLE2)
     */

    if (CL_SUCCESS != uniq_get(U, "_vba_project", 12, &hash, &hashcnt)) {
        cli_dbgmsg("vba_readdir: uniq_get('_vba_project') failed. Unable to check # of embedded vba proj files\n");
        return NULL;
    }
    if (hashcnt == 0) {
        return NULL;
    }
    snprintf(fullname, sizeof(fullname), "%s" PATHSEP "%s_%u", dir, hash, which);
    fullname[sizeof(fullname) - 1] = '\0';
    fd                             = open(fullname, O_RDONLY | O_BINARY);

    if (fd == -1)
        return NULL;

    if (cli_readn(fd, &v56h, sizeof(struct vba56_header)) != sizeof(struct vba56_header)) {
        close(fd);
        return NULL;
    }
    if (memcmp(v56h.magic, vba56_signature, sizeof(v56h.magic)) != 0) {
        close(fd);
        return NULL;
    }

    i = vba_read_project_strings(fd, TRUE);
    if ((seekback = lseek(fd, 0, SEEK_CUR)) == -1) {
        cli_dbgmsg("vba_readdir: lseek() failed. Unable to guess VBA type\n");
        close(fd);
        return NULL;
    }
    if (lseek(fd, sizeof(struct vba56_header), SEEK_SET) == -1) {
        cli_dbgmsg("vba_readdir: lseek() failed. Unable to guess VBA type\n");
        close(fd);
        return NULL;
    }
    j = vba_read_project_strings(fd, FALSE);
    if (!i && !j) {
        close(fd);
        cli_dbgmsg("vba_readdir: Unable to guess VBA type\n");
        return NULL;
    }
    if (i > j) {
        big_endian = TRUE;
        if (lseek(fd, seekback, SEEK_SET) == -1) {
            cli_dbgmsg("vba_readdir: call to lseek() while guessing big-endian has failed\n");
            close(fd);
            return NULL;
        }
        cli_dbgmsg("vba_readdir: Guessing big-endian\n");
    } else {
        cli_dbgmsg("vba_readdir: Guessing little-endian\n");
    }

    /* junk some more stuff */
    do
        if (cli_readn(fd, &ffff, 2) != 2) {
            close(fd);
            return NULL;
        }
    while (ffff != 0xFFFF);

    /* check for alignment error */
    if (!seekandread(fd, -3, SEEK_CUR, &ffff, sizeof(uint16_t))) {
        close(fd);
        return NULL;
    }
    if (ffff != 0xFFFF) {
        if (lseek(fd, 1, SEEK_CUR) == -1) {
            cli_dbgmsg("call to lseek() while checking alignment error has failed\n");
            close(fd);
            return NULL;
        }
    }

    if (!read_uint16(fd, &ffff, big_endian)) {
        close(fd);
        return NULL;
    }

    if (ffff != 0xFFFF) {
        if (lseek(fd, ffff, SEEK_CUR) == -1) {
            cli_dbgmsg("call to lseek() while checking alignment error has failed\n");
            close(fd);
            return NULL;
        }
    }

    if (!read_uint16(fd, &ffff, big_endian)) {
        close(fd);
        return NULL;
    }

    if (ffff == 0xFFFF)
        ffff = 0;

    if (lseek(fd, ffff + 100, SEEK_CUR) == -1) {
        cli_dbgmsg("call to lseek() failed\n");
        close(fd);
        return NULL;
    }

    if (!read_uint16(fd, &record_count, big_endian)) {
        close(fd);
        return NULL;
    }
    cli_dbgmsg("vba_readdir: VBA Record count %d\n", record_count);
    if (record_count == 0) {
        /* No macros, assume clean */
        close(fd);
        return NULL;
    }
    if (record_count > MAX_VBA_COUNT) {
        /* Almost certainly an error */
        cli_dbgmsg("vba_readdir: VBA Record count too big\n");
        close(fd);
        return NULL;
    }

    vba_project = create_vba_project(record_count, dir, U);
    if (vba_project == NULL) {
        close(fd);
        return NULL;
    }
    buf    = NULL;
    buflen = 0;
    for (i = 0; i < record_count; i++) {
        uint16_t length;
        char *ptr;

        vba_project->colls[i] = 0;
        if (!read_uint16(fd, &length, big_endian))
            break;

        if (length == 0) {
            cli_dbgmsg("vba_readdir: zero name length\n");
            break;
        }
        if (length > buflen) {
            unsigned char *newbuf = (unsigned char *)cli_max_realloc(buf, length);
            if (newbuf == NULL)
                break;
            buflen = length;
            buf    = newbuf;
        }
        if (cli_readn(fd, buf, (size_t)length) != (size_t)length) {
            cli_dbgmsg("vba_readdir: read name failed\n");
            break;
        }
        ptr = get_unicode_name((const char *)buf, length, big_endian);
        if (ptr == NULL) break;
        if (CL_SUCCESS != uniq_get(U, ptr, strlen(ptr), &hash, &hashcnt)) {
            cli_dbgmsg("vba_readdir: uniq_get('%s') failed.\n", ptr);
            free(ptr);
            break;
        }
        vba_project->colls[i] = hashcnt;
        if (0 == vba_project->colls[i]) {
            cli_dbgmsg("vba_readdir: cannot find project %s (%s)\n", ptr, hash);
            free(ptr);
            break;
        }
        cli_dbgmsg("vba_readdir: project name: %s (%s)\n", ptr, hash);
        free(ptr);
        vba_project->name[i] = hash;
        if (!read_uint16(fd, &length, big_endian))
            break;
        if (lseek(fd, length, SEEK_CUR) == (off_t)-1) {
            cli_dbgmsg("vba_readdir: failed to skip project description\n");
            break;
        }

        if (!read_uint16(fd, &ffff, big_endian))
            break;
        if (ffff == 0xFFFF) {
            if (lseek(fd, 2, SEEK_CUR) == (off_t)-1) {
                cli_dbgmsg("vba_readdir: failed to skip project metadata\n");
                break;
            }
            if (!read_uint16(fd, &ffff, big_endian))
                break;
            if (lseek(fd, ffff + 8, SEEK_CUR) == (off_t)-1) {
                cli_dbgmsg("vba_readdir: failed to skip extended project metadata\n");
                break;
            }
        } else
            if (lseek(fd, ffff + 10, SEEK_CUR) == (off_t)-1) {
                cli_dbgmsg("vba_readdir: failed to skip project metadata\n");
                break;
            }

        if (!read_uint16(fd, &byte_count, big_endian))
            break;
        if (lseek(fd, (8 * byte_count) + 5, SEEK_CUR) == (off_t)-1) {
            cli_dbgmsg("vba_readdir: failed to skip module metadata\n");
            break;
        }
        if (!read_uint32(fd, &offset, big_endian))
            break;
        cli_dbgmsg("vba_readdir: offset: %" PRIu32 "\n", offset);
        vba_project->offset[i] = offset;
        if (lseek(fd, 2, SEEK_CUR) == (off_t)-1) {
            cli_dbgmsg("vba_readdir: failed to skip module terminator\n");
            break;
        }
    }

    if (buf)
        free(buf);

    close(fd);

    if (i < record_count) {
        free(vba_project->name);
        free(vba_project->colls);
        free(vba_project->dir);
        free(vba_project->offset);
        free(vba_project);
        return NULL;
    }

    return vba_project;
}

static cl_error_t vba_inflate_emit(cli_vba_inflate_write_cb write_cb, void *write_context,
                                   const unsigned char *data, size_t data_size, uint64_t *output_size)
{
    cl_error_t status;

    if (data_size == 0)
        return CL_SUCCESS;
    if ((uint64_t)data_size > UINT64_MAX - *output_size)
        return CL_EFORMAT;

    status = write_cb(data, data_size, write_context);
    if (status != CL_SUCCESS)
        return status;
    *output_size += (uint64_t)data_size;
    return CL_SUCCESS;
}

cl_error_t cli_vba_inflate_stream(int fd, off_t offset, cli_vba_inflate_write_cb write_cb,
                                  void *write_context, uint64_t *output_size)
{
    uint64_t pos;
    unsigned int shift, mask, distance, clean;
    uint64_t produced = 0;
    size_t read_result;
    uint8_t flag;
    uint16_t token;
    unsigned char buffer[VBA_COMPRESSION_WINDOW];
    cl_error_t status;

    if (output_size != NULL)
        *output_size = 0;
    if (fd < 0 || offset < 0 || write_cb == NULL)
        return CL_EARG;

    memset(buffer, 0, sizeof(buffer));
    if (lseek(fd, offset, SEEK_SET) == (off_t)-1 ||
        lseek(fd, 3, SEEK_CUR) == (off_t)-1) /* 1byte ?? , 2byte length ?? */
        return CL_ESEEK;

    clean = TRUE;
    pos   = 0;

    while ((read_result = cli_readn(fd, &flag, 1)) == 1) {
        for (mask = 1; mask < 0x100; mask <<= 1) {
            unsigned int winpos = (unsigned int)(pos % VBA_COMPRESSION_WINDOW);
            if (flag & mask) {
                uint16_t len;
                uint64_t srcpos;

                status = vba_readn_full(fd, &token, sizeof(token));
                if (status != CL_SUCCESS)
                    return status;
                token = vba_endian_convert_16(token, FALSE);
                shift    = 12 - (winpos > 0x10) - (winpos > 0x20) - (winpos > 0x40) - (winpos > 0x80) - (winpos > 0x100) - (winpos > 0x200) - (winpos > 0x400) - (winpos > 0x800);
                len      = (uint16_t)((token & ((1 << shift) - 1)) + 3);
                distance = token >> shift;

                if (pos > UINT64_MAX - len)
                    return CL_EFORMAT;

                if ((uint64_t)distance >= pos)
                    return CL_EFORMAT;

                srcpos = pos - distance - 1;
                if ((((srcpos + len) % VBA_COMPRESSION_WINDOW) < winpos) &&
                    ((winpos + len) < VBA_COMPRESSION_WINDOW) &&
                    (((srcpos % VBA_COMPRESSION_WINDOW) + len) < VBA_COMPRESSION_WINDOW) &&
                    (len <= VBA_COMPRESSION_WINDOW)) {
                    srcpos %= VBA_COMPRESSION_WINDOW;
                    memcpy(&buffer[winpos], &buffer[srcpos], len);
                    pos += len;
                } else {
                    while (len-- > 0) {
                        srcpos                                 = (pos - distance - 1) % VBA_COMPRESSION_WINDOW;
                        buffer[pos++ % VBA_COMPRESSION_WINDOW] = buffer[srcpos];
                    }
                }
            } else {
                if ((pos != 0) && (winpos == 0) && clean) {
                    if (cli_readn(fd, &token, 2) != 2)
                        return CL_EREAD;
                    status = vba_inflate_emit(write_cb, write_context, buffer,
                                              VBA_COMPRESSION_WINDOW, &produced);
                    if (status != CL_SUCCESS)
                        return status;
                    clean = FALSE;
                    break;
                }
                status = vba_readn_full(fd, &buffer[winpos], 1);
                if (status == CL_SUCCESS) {
                    if (pos == UINT64_MAX)
                        return CL_EFORMAT;
                    pos++;
                } else {
                    /* A flag bit announced a literal, but the compressed
                     * stream ended before that byte. Do not publish the
                     * preceding prefix as a complete module. */
                    return status;
                }
            }
            clean = TRUE;
        }
    }

    if (read_result == (size_t)-1)
        return CL_EREAD;

    status = vba_inflate_emit(write_cb, write_context, buffer,
                              (size_t)(pos % VBA_COMPRESSION_WINDOW), &produced);
    if (status != CL_SUCCESS)
        return status;

    if (output_size != NULL)
        *output_size = produced;
    return CL_SUCCESS;
}

struct vba_blob_output {
    blob *data;
};

static cl_error_t vba_blob_write(const unsigned char *data, size_t data_size, void *context)
{
    struct vba_blob_output *output = context;

    return blobAddData(output->data, data, data_size) < 0 ? CL_EMEM : CL_SUCCESS;
}

unsigned char *
cli_vba_inflate(int fd, off_t offset, size_t *size)
{
    struct vba_blob_output output;
    uint64_t output_size = 0;
    cl_error_t status;

    if (size != NULL)
        *size = 0;
    if (fd < 0)
        return NULL;

    output.data = blobCreate();
    if (output.data == NULL)
        return NULL;

    status = cli_vba_inflate_stream(fd, offset, vba_blob_write, &output, &output_size);
    if (status != CL_SUCCESS || output_size > SIZE_MAX) {
        blobDestroy(output.data);
        return NULL;
    }

    if (size != NULL)
        *size = (size_t)output_size;
    return (unsigned char *)blobToMem(output.data);
}

/*
 * See also cli_filecopy()
 */
static cl_error_t
ole_copy_file_data(cli_ctx *ctx, int s, int d, uint32_t len)
{
    unsigned char data[FILEBUFF];

    while (len > 0) {
        size_t todo = MIN(sizeof(data), len);

        if (cli_readn(s, data, todo) != todo)
            return CL_EREAD;
        if (vba_checktimelimit(ctx, "OLE10 embedded object output reached the configured time limit") != CL_SUCCESS)
            return CL_ETIMEOUT;
        if (cli_writen(d, data, todo) != todo)
            return CL_EWRITE;

        len -= todo;
    }

    return CL_SUCCESS;
}

static void
ole10_cleanup_output(cli_ctx *ctx, int *ofd, const char *fullname, cl_error_t *status)
{
    if (ofd != NULL && *ofd >= 0) {
        if (close(*ofd) != 0) {
            cli_mark_scan_incomplete(ctx, "OLE10 embedded object temporary output could not be closed");
            *status = cli_merge_cleanup_status(*status, CL_EWRITE);
        }
        *ofd = -1;
    }

    if (ctx && !ctx->engine->keeptmp && fullname && cli_unlink(fullname)) {
        cli_mark_scan_incomplete(ctx, "OLE10 embedded object temporary output could not be removed");
        *status = cli_merge_cleanup_status(*status, CL_EUNLINK);
    }
}

static cl_error_t
ole10_reconcile_status(cli_ctx *ctx, cl_error_t status)
{
    if (ctx != NULL && (status == CL_SUCCESS || status == CL_CLEAN) && ctx->scan_incomplete)
        return CL_EPARSE;

    return status;
}

int cli_scan_ole10(int fd, cli_ctx *ctx)
{
    int ofd;
    cl_error_t ret;
    uint32_t object_size;
    STATBUF statbuf;
    char *fullname;
    off_t payload_offset;
    uint64_t temporary_reserved = 0;

    if (ctx == NULL)
        return CL_ENULLARG;

    if (ctx->engine == NULL)
        return CL_ENULLARG;

    if (ctx->options == NULL)
        return CL_ENULLARG;

    if (fd < 0) {
        cli_mark_scan_incomplete(ctx, "OLE10 embedded object descriptor was invalid");
        return CL_EARG;
    }

    if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
        cli_mark_scan_incomplete(ctx, "OLE10 embedded object could not be rewound");
        return CL_ESEEK;
    }
    if (!read_uint32(fd, &object_size, FALSE)) {
        cli_mark_scan_incomplete(ctx, "OLE10 embedded object header was truncated");
        return CL_EPARSE;
    }

    if (FSTAT(fd, &statbuf) == -1) {
        cli_mark_scan_incomplete(ctx, "OLE10 embedded object could not be stat'ed");
        return CL_ESTAT;
    }

    if (statbuf.st_size < 0 || (uint64_t)object_size > (uint64_t)statbuf.st_size) {
        cli_mark_scan_incomplete(ctx, "OLE10 embedded object size exceeds the input");
        return CL_EPARSE;
    }

    if (((uint64_t)statbuf.st_size - (uint64_t)object_size) >= 4) {
        /* Probably the OLE type id */
        if (lseek(fd, 2, SEEK_CUR) == -1) {
            cli_mark_scan_incomplete(ctx, "OLE10 embedded object type header could not be read");
            return CL_ESEEK;
        }

        /* Attachment name */
        if (!skip_past_nul(fd)) {
            cli_mark_scan_incomplete(ctx, "OLE10 embedded object name was truncated");
            return CL_EPARSE;
        }

        /* Attachment full path */
        if (!skip_past_nul(fd)) {
            cli_mark_scan_incomplete(ctx, "OLE10 embedded object path was truncated");
            return CL_EPARSE;
        }

        /* ??? */
        if (lseek(fd, 8, SEEK_CUR) == -1) {
            cli_mark_scan_incomplete(ctx, "OLE10 embedded object metadata was truncated");
            return CL_ESEEK;
        }

        /* Attachment full path */
        if (!skip_past_nul(fd)) {
            cli_mark_scan_incomplete(ctx, "OLE10 embedded object target path was truncated");
            return CL_EPARSE;
        }

        if (!read_uint32(fd, &object_size, FALSE)) {
            cli_mark_scan_incomplete(ctx, "OLE10 embedded object payload header was truncated");
            return CL_EPARSE;
        }
        payload_offset = lseek(fd, 0, SEEK_CUR);
        if (payload_offset < 0 || (uint64_t)payload_offset > (uint64_t)statbuf.st_size ||
            (uint64_t)object_size > (uint64_t)statbuf.st_size - (uint64_t)payload_offset) {
            cli_mark_scan_incomplete(ctx, "OLE10 embedded object payload exceeds the input");
            return CL_EPARSE;
        }
    }

    ret = cli_scan_reserve_temporary(ctx, (uint64_t)object_size);
    if (ret != CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, "OLE10 embedded object exceeds temporary storage limits");
        return ret;
    }
    temporary_reserved = (uint64_t)object_size;

    ret = vba_checktimelimit(ctx, "OLE10 embedded object temporary admission reached the configured time limit");
    if (ret != CL_SUCCESS) {
        cli_scan_release_temporary(ctx, temporary_reserved);
        return ret;
    }

    if (!(fullname = cli_gentemp(ctx ? ctx->this_layer_tmpdir : NULL))) {
        cli_mark_scan_incomplete(ctx, "OLE10 embedded object temporary output could not be allocated");
        cli_scan_release_temporary(ctx, temporary_reserved);
        return CL_EMEM;
    }
    ofd = open(fullname, O_RDWR | O_CREAT | O_TRUNC | O_BINARY | O_EXCL,
               S_IWUSR | S_IRUSR);
    if (ofd < 0) {
        cli_warnmsg("cli_decode_ole_object: can't create %s\n", fullname);
        cli_mark_scan_incomplete(ctx, "OLE10 embedded object temporary output could not be created");
        cli_scan_release_temporary(ctx, temporary_reserved);
        free(fullname);
        return CL_ECREAT;
    }

    cli_dbgmsg("cli_decode_ole_object: decoding to %s\n", fullname);

    ret = ole_copy_file_data(ctx, fd, ofd, object_size);
    if (ret != CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, "OLE10 embedded object payload could not be copied completely");
        ole10_cleanup_output(ctx, &ofd, fullname, &ret);
        cli_scan_release_temporary(ctx, temporary_reserved);
        free(fullname);
        return ret;
    }

    if (lseek(ofd, 0, SEEK_SET) == (off_t)-1) {
        cli_mark_scan_incomplete(ctx, "OLE10 embedded object output could not be rewound");
        ole10_cleanup_output(ctx, &ofd, fullname, &ret);
        cli_scan_release_temporary(ctx, temporary_reserved);
        free(fullname);
        return CL_ESEEK;
    }

    ret = vba_checktimelimit(ctx, "OLE10 embedded object nested-scan handoff reached the configured time limit");
    if (ret == CL_SUCCESS)
        ret = cli_magic_scan_desc_type_reserved(ofd, fullname, ctx, CL_TYPE_ANY, NULL, LAYER_ATTRIBUTES_NONE);
    if (ret != CL_SUCCESS && ret != CL_VIRUS)
        cli_mark_scan_incomplete(ctx, "OLE10 embedded object scan did not complete");

    ole10_cleanup_output(ctx, &ofd, fullname, &ret);

    cli_scan_release_temporary(ctx, temporary_reserved);
    free(fullname);

    return ole10_reconcile_status(ctx, ret);
}

/*
 * Powerpoint files
 */
typedef struct {
    uint16_t type;
    uint32_t length;
} atom_header_t;

static int
ppt_read_atom_header(int fd, atom_header_t *atom_header)
{
    uint16_t v;
    struct ppt_header {
        uint16_t ver;
        uint16_t type;
        uint32_t length;
    } h;

    cli_dbgmsg("in ppt_read_atom_header\n");
    if (cli_readn(fd, &h, sizeof(struct ppt_header)) != sizeof(struct ppt_header)) {
        cli_dbgmsg("read ppt_header failed\n");
        return FALSE;
    }
    v = vba_endian_convert_16(h.ver, FALSE);
    cli_dbgmsg("\tversion: 0x%.2x\n", v & 0xF);
    cli_dbgmsg("\tinstance: 0x%.2x\n", v >> 4);

    atom_header->type = vba_endian_convert_16(h.type, FALSE);
    cli_dbgmsg("\ttype: 0x%.4x\n", atom_header->type);
    atom_header->length = vba_endian_convert_32(h.length, FALSE);
    cli_dbgmsg("\tlength: 0x%.8x\n", (int)atom_header->length);

    return TRUE;
}

/*
 * TODO: combine shared code with flatedecode() or cli_unzip_single()
 *	Needs cli_unzip_single to have a "length" argument
 */
static cl_error_t
ppt_reserve_output(cli_ctx *ctx, uint64_t *temporary_reserved, size_t output_size)
{
    uint64_t bytes = (uint64_t)output_size;

    if (ctx == NULL || bytes == 0)
        return CL_SUCCESS;

    if (bytes > UINT64_MAX - *temporary_reserved ||
        cli_scan_reserve_temporary(ctx, bytes) != CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, "PowerPoint temporary output exceeds temporary storage limits");
        return CL_ERESOURCE;
    }

    *temporary_reserved += bytes;
    return CL_SUCCESS;
}

static int
ppt_write_output(cli_ctx *ctx, uint64_t *temporary_reserved, int ofd, const void *buffer, size_t size)
{
    if (ppt_reserve_output(ctx, temporary_reserved, size) != CL_SUCCESS)
        return FALSE;

    if (vba_checktimelimit(ctx, "PowerPoint temporary output reached the configured time limit") != CL_SUCCESS)
        return FALSE;

    if (cli_writen(ofd, buffer, size) != size) {
        cli_mark_scan_incomplete(ctx, "PowerPoint temporary output could not be written completely");
        return FALSE;
    }

    return TRUE;
}

static int
ppt_close_output(cli_ctx *ctx, int ofd)
{
    if (close(ofd) != 0) {
        cli_mark_scan_incomplete(ctx, "PowerPoint temporary output could not be closed");
        return FALSE;
    }

    return TRUE;
}

static void
ppt_remove_output(cli_ctx *ctx, const char *fullname)
{
    if (cli_unlink(fullname) != 0)
        cli_mark_scan_incomplete(ctx, "PowerPoint temporary output could not be removed");
}

static int
ppt_finalize_decoder(cli_ctx *ctx, z_stream *stream)
{
    if (inflateEnd(stream) != Z_OK) {
        cli_mark_scan_incomplete(ctx, "PowerPoint compressed stream decoder could not be finalized");
        return FALSE;
    }

    return TRUE;
}

static int
ppt_unlzw(const char *dir, int fd, uint32_t length, cli_ctx *ctx, uint64_t *temporary_reserved)
{
    int ofd;
    int zret;
    off_t input_offset;
    z_stream stream;
    unsigned char inbuff[PPT_LZW_BUFFSIZE], outbuff[PPT_LZW_BUFFSIZE];
    char fullname[PATH_MAX + 1];

    input_offset = lseek(fd, 0L, SEEK_CUR);
    if (input_offset == (off_t)-1) {
        cli_dbgmsg("ppt_unlzw: failed to record input offset\n");
        cli_mark_scan_incomplete(ctx, "PowerPoint compressed stream position could not be recorded");
        return FALSE;
    }
    snprintf(fullname, sizeof(fullname) - 1, "%s" PATHSEP "ppt%.8lx.doc",
             dir, (long)input_offset);

    ofd = open(fullname, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY | O_EXCL,
               S_IWUSR | S_IRUSR);
    if (ofd == -1) {
        cli_warnmsg("ppt_unlzw: can't create %s\n", fullname);
        cli_mark_scan_incomplete(ctx, "PowerPoint temporary output could not be created");
        return FALSE;
    }

    memset(&stream, 0, sizeof(stream));

    stream.zalloc    = Z_NULL;
    stream.zfree     = Z_NULL;
    stream.opaque    = (void *)NULL;
    stream.next_in   = (Bytef *)inbuff;
    stream.next_out  = outbuff;
    stream.avail_out = sizeof(outbuff);
    stream.avail_in  = MIN(length, PPT_LZW_BUFFSIZE);

    if (cli_readn(fd, inbuff, (size_t)stream.avail_in) != (size_t)stream.avail_in) {
        ppt_close_output(ctx, ofd);
        ppt_remove_output(ctx, fullname);
        cli_mark_scan_incomplete(ctx, "PowerPoint compressed stream could not be read completely");
        return FALSE;
    }
    length -= stream.avail_in;

    if (inflateInit(&stream) != Z_OK) {
        ppt_close_output(ctx, ofd);
        ppt_remove_output(ctx, fullname);
        cli_mark_scan_incomplete(ctx, "PowerPoint compressed stream could not be initialized");
        cli_warnmsg("ppt_unlzw: inflateInit failed\n");
        return FALSE;
    }

    do {
        if (stream.avail_out == 0) {
            if (!ppt_write_output(ctx, temporary_reserved, ofd, outbuff, PPT_LZW_BUFFSIZE)) {
                ppt_close_output(ctx, ofd);
                (void)ppt_finalize_decoder(ctx, &stream);
                ppt_remove_output(ctx, fullname);
                return FALSE;
            }
            stream.next_out  = outbuff;
            stream.avail_out = PPT_LZW_BUFFSIZE;
        }
        if (stream.avail_in == 0) {
            stream.next_in  = inbuff;
            stream.avail_in = MIN(length, PPT_LZW_BUFFSIZE);
            if (cli_readn(fd, inbuff, (size_t)stream.avail_in) != (size_t)stream.avail_in) {
                ppt_close_output(ctx, ofd);
                (void)ppt_finalize_decoder(ctx, &stream);
                ppt_remove_output(ctx, fullname);
                cli_mark_scan_incomplete(ctx, "PowerPoint compressed stream could not be read completely");
                return FALSE;
            }
            length -= stream.avail_in;
        }
        zret = inflate(&stream, Z_NO_FLUSH);
    } while (zret == Z_OK);

    if (zret != Z_STREAM_END) {
        ppt_close_output(ctx, ofd);
        (void)ppt_finalize_decoder(ctx, &stream);
        ppt_remove_output(ctx, fullname);
        cli_mark_scan_incomplete(ctx, "PowerPoint compressed stream was not fully decoded");
        return FALSE;
    }

    /* inflate() may reach the end of its zlib stream before the declared
     * compressed atom payload is exhausted. The bytes already buffered in
     * stream.next_in have advanced fd, but the bytes still in the atom have
     * not. Advance the descriptor to the atom boundary before the caller
     * attempts to read the next atom; otherwise a large padded atom can make
     * the following valid atom look malformed or disappear from inspection. */
    if (length > 0) {
        off_t skip = (off_t)length;

        if ((uint64_t)skip != (uint64_t)length || lseek(fd, skip, SEEK_CUR) == (off_t)-1) {
            ppt_close_output(ctx, ofd);
            (void)ppt_finalize_decoder(ctx, &stream);
            ppt_remove_output(ctx, fullname);
            cli_mark_scan_incomplete(ctx, "PowerPoint compressed atom could not be advanced to its declared boundary");
            return FALSE;
        }
        length = 0;
    }

    if (!ppt_write_output(ctx, temporary_reserved, ofd, outbuff,
                          PPT_LZW_BUFFSIZE - stream.avail_out)) {
        ppt_close_output(ctx, ofd);
        (void)ppt_finalize_decoder(ctx, &stream);
        ppt_remove_output(ctx, fullname);
        return FALSE;
    }
    if (!ppt_close_output(ctx, ofd)) {
        ppt_remove_output(ctx, fullname);
        (void)ppt_finalize_decoder(ctx, &stream);
        return FALSE;
    }
    if (!ppt_finalize_decoder(ctx, &stream)) {
        ppt_remove_output(ctx, fullname);
        return FALSE;
    }

    return TRUE;
}

static const char *
ppt_stream_iter(int fd, const char *dir, cli_ctx *ctx, uint64_t *temporary_reserved)
{
    atom_header_t atom_header;
    STATBUF statbuf;

    if (FSTAT(fd, &statbuf) == -1 || statbuf.st_size < 0) {
        cli_mark_scan_incomplete(ctx, "PowerPoint input could not be inspected");
        return NULL;
    }

    while (1) {
        off_t header_offset = lseek(fd, 0, SEEK_CUR);

        if (vba_checktimelimit(ctx, "PowerPoint traversal reached the configured time limit") != CL_SUCCESS)
            return NULL;

        if (header_offset < 0 || (uint64_t)header_offset > (uint64_t)statbuf.st_size) {
            cli_mark_scan_incomplete(ctx, "PowerPoint atom header could not be positioned");
            return NULL;
        }
        if ((uint64_t)header_offset == (uint64_t)statbuf.st_size)
            break;
        if ((uint64_t)sizeof(atom_header_t) > (uint64_t)statbuf.st_size - (uint64_t)header_offset) {
            cli_mark_scan_incomplete(ctx, "PowerPoint input ended before an atom header was complete");
            return NULL;
        }
        if (!ppt_read_atom_header(fd, &atom_header)) {
            cli_mark_scan_incomplete(ctx, "PowerPoint atom header could not be read completely");
            return NULL;
        }

        if (atom_header.length == 0) {
            cli_mark_scan_incomplete(ctx, "PowerPoint atom has zero length");
            return NULL;
        }

        if (atom_header.type == 0x1011) {
            uint32_t length;
            off_t offset = lseek(fd, 0, SEEK_CUR);

            if (offset < 0 || (uint64_t)offset > (uint64_t)statbuf.st_size || atom_header.length < sizeof(uint32_t) ||
                (uint64_t)(atom_header.length - sizeof(uint32_t)) > (uint64_t)statbuf.st_size - (uint64_t)offset) {
                cli_mark_scan_incomplete(ctx, "PowerPoint compressed atom exceeds the input");
                return NULL;
            }

            /* Skip over ID */
            if (lseek(fd, sizeof(uint32_t), SEEK_CUR) == -1) {
                cli_dbgmsg("ppt_stream_iter: seek failed\n");
                cli_mark_scan_incomplete(ctx, "PowerPoint compressed atom could not be positioned");
                return NULL;
            }
            length = atom_header.length - sizeof(uint32_t);
            cli_dbgmsg("length: %d\n", (int)length);
            if (!ppt_unlzw(dir, fd, length, ctx, temporary_reserved)) {
                cli_dbgmsg("ppt_unlzw failed\n");
                return NULL;
            }
        } else {
            off_t offset = lseek(fd, 0, SEEK_CUR);
            /* Check we don't wrap or seek past the materialized input. */
            if (offset < 0 || (uint64_t)offset > (uint64_t)statbuf.st_size ||
                (uint64_t)atom_header.length > (uint64_t)statbuf.st_size - (uint64_t)offset) {
                cli_mark_scan_incomplete(ctx, "PowerPoint atom exceeds the input");
                return NULL;
            }
            offset += atom_header.length;
            if (lseek(fd, offset, SEEK_SET) != offset) {
                cli_mark_scan_incomplete(ctx, "PowerPoint atom could not be skipped completely");
                return NULL;
            }
        }
    }

    return dir;
}

char *
cli_ppt_vba_read_ex(int ifd, cli_ctx *ctx, uint64_t *temporary_reserved_out)
{
    char *dir;
    const char *ret;
    uint64_t temporary_reserved = 0;

    if (temporary_reserved_out != NULL)
        *temporary_reserved_out = 0;

    if (ctx == NULL)
        return NULL;

    if (ctx->engine == NULL)
        return NULL;

    if (ctx->options == NULL)
        return NULL;

    /* Create a directory to store the extracted OLE2 objects */
    dir = cli_gentemp_with_prefix(ctx->this_layer_tmpdir, "ppt-ole2-tmp");
    if (dir == NULL) {
        cli_mark_scan_incomplete(ctx, "PowerPoint temporary directory could not be allocated");
        return NULL;
    }
    if (mkdir(dir, 0700)) {
        cli_errmsg("cli_ppt_vba_read: Can't create temporary directory %s\n", dir);
        cli_mark_scan_incomplete(ctx, "PowerPoint temporary directory could not be created");
        free(dir);
        return NULL;
    }
    ret = ppt_stream_iter(ifd, dir, ctx, &temporary_reserved);
    if (ret == NULL) {
        if (cli_rmdirs(dir) != 0)
            cli_mark_scan_incomplete(ctx, "PowerPoint temporary directory could not be removed");
        cli_scan_release_temporary(ctx, temporary_reserved);
        free(dir);
        return NULL;
    }

    if (temporary_reserved_out != NULL) {
        *temporary_reserved_out = temporary_reserved;
    } else {
        cli_scan_release_temporary(ctx, temporary_reserved);
    }

    return dir;
}

char *
cli_ppt_vba_read(int ifd, cli_ctx *ctx)
{
    return cli_ppt_vba_read_ex(ifd, ctx, NULL);
}

/*
 * Word 6 macros
 */
typedef struct {
    unsigned char unused[12];
    uint32_t macro_offset;
    uint32_t macro_len;
} mso_fib_t;

typedef struct macro_entry_tag {
    uint32_t len;
    uint32_t offset;
    unsigned char key;
} macro_entry_t;

typedef struct macro_info_tag {
    struct macro_entry_tag *entries;
    uint16_t count;
} macro_info_t;

static int
word_read_fib(int fd, mso_fib_t *fib)
{
    struct {
        uint32_t offset;
        uint32_t len;
    } macro_details;

    if (!seekandread(fd, 0x118, SEEK_SET, &macro_details, sizeof(macro_details))) {
        cli_dbgmsg("read word_fib failed\n");
        return FALSE;
    }
    fib->macro_offset = vba_endian_convert_32(macro_details.offset, FALSE);
    fib->macro_len    = vba_endian_convert_32(macro_details.len, FALSE);

    return TRUE;
}

static int
word_read_macro_entry(int fd, macro_info_t *macro_info, uint64_t end_offset)
{
    size_t msize;
    uint16_t count = macro_info->count;
    macro_entry_t *macro_entry;
#ifdef HAVE_PRAGMA_PACK
#pragma pack(1)
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack 1
#endif
    struct macro {
        unsigned char version;
        unsigned char key;
        unsigned char ignore[10];
        uint32_t len __attribute__((packed));
        uint32_t state __attribute__((packed));
        uint32_t offset __attribute__((packed));
    } *m;
    const struct macro *n;
#ifdef HAVE_PRAGMA_PACK
#pragma pack()
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack
#endif
    if (count == 0)
        return TRUE;

    msize = count * sizeof(struct macro);
    m     = cli_max_malloc(msize);
    if (m == NULL) {
        cli_errmsg("word_read_macro_entry: Unable to allocate memory for 'm'\n");
        return FALSE;
    }

    {
        off_t current_offset = lseek(fd, 0, SEEK_CUR);
        if (current_offset < 0 || (uint64_t)current_offset > end_offset ||
            (uint64_t)msize > end_offset - (uint64_t)current_offset) {
            free(m);
            cli_dbgmsg("word_read_macro_entry: metadata exceeds declared directory\n");
            return FALSE;
        }
    }

    if (cli_readn(fd, m, msize) != msize) {
        free(m);
        cli_warnmsg("read %u macro_entries failed\n", count);
        return FALSE;
    }
    macro_entry = macro_info->entries;
    n           = m;
    do {
        macro_entry->key    = n->key;
        macro_entry->len    = vba_endian_convert_32(n->len, FALSE);
        macro_entry->offset = vba_endian_convert_32(n->offset, FALSE);
        macro_entry++;
        n++;
    } while (--count > 0);
    free(m);
    return TRUE;
}

static int
word_read_macro_info(int fd, macro_info_t *macro_info, uint64_t end_offset)
{
    off_t current_offset = lseek(fd, 0, SEEK_CUR);

    if (current_offset < 0 || (uint64_t)current_offset > end_offset ||
        sizeof(uint16_t) > end_offset - (uint64_t)current_offset) {
        cli_dbgmsg("word_read_macro_info: record header exceeds declared directory\n");
        macro_info->count = 0;
        return -1;
    }
    if (!read_uint16(fd, &macro_info->count, FALSE)) {
        cli_dbgmsg("read macro_info failed\n");
        macro_info->count = 0;
        return -1;
    }
    cli_dbgmsg("macro count: %d\n", macro_info->count);
    if (macro_info->count == 0)
        return 0;
    macro_info->entries = (macro_entry_t *)cli_max_malloc(sizeof(macro_entry_t) * macro_info->count);
    if (macro_info->entries == NULL) {
        macro_info->count = 0;
        cli_errmsg("word_read_macro_info: Unable to allocate memory for macro_info->entries\n");
        return -1;
    }
    if (!word_read_macro_entry(fd, macro_info, end_offset)) {
        free(macro_info->entries);
        macro_info->entries = NULL;
        macro_info->count   = 0;
        return -1;
    }
    return 1;
}

static int
word_read_bounded(int fd, void *buffer, size_t size, uint64_t end_offset)
{
    off_t current_offset = lseek(fd, 0, SEEK_CUR);

    if (current_offset < 0 || (uint64_t)current_offset > end_offset ||
        (uint64_t)size > end_offset - (uint64_t)current_offset)
        return FALSE;

    return cli_readn(fd, buffer, size) == size;
}

static int
word_read_uint16_bounded(int fd, uint16_t *value, uint64_t end_offset)
{
    if (!word_read_bounded(fd, value, sizeof(*value), end_offset))
        return FALSE;

    *value = vba_endian_convert_16(*value, FALSE);
    return TRUE;
}

static int
word_skip_bounded(int fd, uint64_t size, uint64_t end_offset)
{
    off_t current_offset = lseek(fd, 0, SEEK_CUR);
    uint64_t target_offset;
    off_t seek_offset;

    if (current_offset < 0 || (uint64_t)current_offset > end_offset ||
        size > end_offset - (uint64_t)current_offset)
        return FALSE;

    target_offset = (uint64_t)current_offset + size;
    seek_offset   = (off_t)target_offset;
    if ((uint64_t)seek_offset != target_offset || lseek(fd, seek_offset, SEEK_SET) != seek_offset)
        return FALSE;

    return TRUE;
}

static int
word_rewind_bounded(int fd, uint64_t size, uint64_t end_offset)
{
    off_t current_offset = lseek(fd, 0, SEEK_CUR);
    uint64_t target_offset;
    off_t seek_offset;

    if (current_offset < 0 || (uint64_t)current_offset > end_offset ||
        size > (uint64_t)current_offset)
        return FALSE;

    target_offset = (uint64_t)current_offset - size;
    seek_offset   = (off_t)target_offset;
    if ((uint64_t)seek_offset != target_offset || lseek(fd, seek_offset, SEEK_SET) != seek_offset)
        return FALSE;

    return TRUE;
}

static int
word_skip_oxo3(int fd, uint64_t end_offset)
{
    uint8_t count;

    if (!word_read_bounded(fd, &count, 1, end_offset)) {
        cli_dbgmsg("read oxo3 record1 failed\n");
        return FALSE;
    }
    cli_dbgmsg("oxo3 records1: %d\n", count);

    if (!word_skip_bounded(fd, (uint64_t)count * 14U, end_offset) ||
        !word_read_bounded(fd, &count, 1, end_offset)) {
        cli_dbgmsg("read oxo3 record2 failed\n");
        return FALSE;
    }

    if (count == 0) {
        uint8_t twobytes[2];

        if (!word_read_bounded(fd, twobytes, sizeof(twobytes), end_offset)) {
            cli_dbgmsg("read oxo3 failed\n");
            return FALSE;
        }
        if (twobytes[0] != 2) {
            if (!word_rewind_bounded(fd, sizeof(twobytes), end_offset))
                return FALSE;
            return TRUE;
        }
        count = twobytes[1];
    }
    if (count > 0)
        if (!word_skip_bounded(fd, (uint64_t)count * 4U + 1U, end_offset)) {
            cli_dbgmsg("lseek oxo3 failed\n");
            return FALSE;
        }

    cli_dbgmsg("oxo3 records2: %d\n", count);
    return TRUE;
}

static int
word_skip_menu_info(int fd, uint64_t end_offset)
{
    uint16_t count;

    if (!word_read_uint16_bounded(fd, &count, end_offset)) {
        cli_dbgmsg("read menu_info failed\n");
        return FALSE;
    }
    cli_dbgmsg("menu_info count: %d\n", count);

    if (count)
        if (!word_skip_bounded(fd, (uint64_t)count * 12U, end_offset))
            return FALSE;
    return TRUE;
}

static int
word_skip_macro_extnames(int fd, uint64_t end_offset)
{
    int is_unicode;
    uint16_t size;
    uint64_t extnames_end;
    off_t size_offset;
    off_t current_offset;

    size_offset = lseek(fd, 0, SEEK_CUR);
    if (size_offset < 0 || (uint64_t)size_offset > end_offset)
        return FALSE;
    if (!word_read_uint16_bounded(fd, &size, end_offset)) {
        cli_dbgmsg("read macro_extnames failed\n");
        return FALSE;
    }
    if (size == UINT16_MAX) { /* Unicode flag */
        if (!word_read_uint16_bounded(fd, &size, end_offset)) {
            cli_dbgmsg("read macro_extnames failed\n");
            return FALSE;
        }
        is_unicode = 1;
    } else
        is_unicode = 0;

    cli_dbgmsg("ext names size: 0x%x\n", size);

    if ((uint64_t)size > end_offset - (uint64_t)size_offset)
        return FALSE;
    extnames_end = (uint64_t)size_offset + (uint64_t)size;

    while (TRUE) {
        uint8_t length;
        uint64_t offset;

        current_offset = lseek(fd, 0, SEEK_CUR);
        if (current_offset < 0 || (uint64_t)current_offset > extnames_end)
            return FALSE;
        if ((uint64_t)current_offset == extnames_end)
            break;

        if (!word_read_bounded(fd, &length, sizeof(length), extnames_end)) {
            cli_dbgmsg("read macro_extnames failed\n");
            return FALSE;
        }

        if (is_unicode)
            offset = (uint64_t)length * 2U + 1U;
        else
            offset = (uint64_t)length;

        /* ignore numref as well */
        if (!word_skip_bounded(fd, offset + sizeof(uint16_t), extnames_end)) {
            cli_dbgmsg("read macro_extnames failed to seek\n");
            return FALSE;
        }
    }
    return TRUE;
}

static int
word_skip_macro_intnames(int fd, uint64_t end_offset)
{
    uint16_t count;

    if (!word_read_uint16_bounded(fd, &count, end_offset)) {
        cli_dbgmsg("read macro_intnames failed\n");
        return FALSE;
    }
    cli_dbgmsg("intnames count: %u\n", (unsigned int)count);

    while (count-- > 0) {
        uint8_t length;

        /* id */
        if (!word_skip_bounded(fd, sizeof(uint16_t), end_offset) ||
            !word_read_bounded(fd, &length, sizeof(length), end_offset)) {
            cli_dbgmsg("skip_macro_intnames failed\n");
            return FALSE;
        }

        /* Internal name, plus one byte of unknown data */
        if (!word_skip_bounded(fd, (uint64_t)length + 1U, end_offset)) {
            cli_dbgmsg("skip_macro_intnames failed\n");
            return FALSE;
        }
    }
    return TRUE;
}

vba_project_t *
cli_wm_readdir(int fd)
{
    return cli_wm_readdir_ex(fd, NULL);
}

vba_project_t *
cli_wm_readdir_ex(int fd, cli_ctx *ctx)
{
    int done, malformed = FALSE;
    uint64_t end_offset, start_offset;
    unsigned char info_id;
    macro_info_t macro_info;
    vba_project_t *vba_project;
    mso_fib_t fib;
    STATBUF statbuf;

    macro_info.entries = NULL;
    macro_info.count   = 0;

    if (!word_read_fib(fd, &fib)) {
        cli_mark_scan_incomplete(ctx, "Word macro directory header could not be read completely");
        return NULL;
    }

    if (fib.macro_len == 0) {
        cli_dbgmsg("wm_readdir: No macros detected\n");
        /* Must be clean */
        return NULL;
    }

    if (FSTAT(fd, &statbuf) == -1 || statbuf.st_size < 0) {
        cli_mark_scan_incomplete(ctx, "Word macro directory could not be inspected");
        return NULL;
    }

    if ((uint64_t)fib.macro_offset > (uint64_t)statbuf.st_size ||
        (uint64_t)fib.macro_len > (uint64_t)statbuf.st_size - (uint64_t)fib.macro_offset) {
        cli_mark_scan_incomplete(ctx, "Word macro directory exceeds the input");
        return NULL;
    }

    cli_dbgmsg("wm_readdir: macro offset: 0x%.4x\n", (int)fib.macro_offset);
    cli_dbgmsg("wm_readdir: macro len: 0x%.4x\n\n", (int)fib.macro_len);

    /* Go one past the start to ignore start_id */
    start_offset = (uint64_t)fib.macro_offset + 1;
    if (start_offset > (uint64_t)statbuf.st_size) {
        cli_mark_scan_incomplete(ctx, "Word macro directory has no complete start marker");
        return NULL;
    }
    {
        off_t seek_offset = (off_t)start_offset;
        if ((uint64_t)seek_offset != start_offset || lseek(fd, seek_offset, SEEK_SET) != seek_offset) {
            cli_dbgmsg("wm_readdir: lseek macro_offset failed\n");
            cli_mark_scan_incomplete(ctx, "Word macro directory could not be positioned");
            return NULL;
        }
    }

    end_offset = (uint64_t)fib.macro_offset + (uint64_t)fib.macro_len;
    done       = FALSE;

    while (!done) {
        off_t current_offset = lseek(fd, 0, SEEK_CUR);

        if (current_offset < 0 || (uint64_t)current_offset > end_offset) {
            cli_dbgmsg("wm_readdir: macro directory position failed\n");
            cli_mark_scan_incomplete(ctx, "Word macro directory position was invalid");
            malformed = TRUE;
            break;
        }
        if ((uint64_t)current_offset == end_offset) {
            cli_mark_scan_incomplete(ctx, "Word macro directory ended before its metadata was complete");
            malformed = TRUE;
            break;
        }
        if (cli_readn(fd, &info_id, 1) != 1) {
            cli_dbgmsg("wm_readdir: read macro_info failed\n");
            cli_mark_scan_incomplete(ctx, "Word macro directory metadata could not be read completely");
            malformed = TRUE;
            break;
        }
        switch (info_id) {
            case 0x01:
                if (macro_info.count)
                    free(macro_info.entries);
                macro_info.entries = NULL;
                macro_info.count   = 0;
                if (word_read_macro_info(fd, &macro_info, end_offset) < 0) {
                    cli_mark_scan_incomplete(ctx, "Word macro directory metadata could not be read completely");
                    malformed = TRUE;
                }
                done = TRUE;
                break;
            case 0x03:
                if (!word_skip_oxo3(fd, end_offset)) {
                    cli_mark_scan_incomplete(ctx, "Word macro directory oxo3 record was truncated");
                    malformed = TRUE;
                    done      = TRUE;
                }
                break;
            case 0x05:
                if (!word_skip_menu_info(fd, end_offset)) {
                    cli_mark_scan_incomplete(ctx, "Word macro directory menu record was truncated");
                    malformed = TRUE;
                    done      = TRUE;
                }
                break;
            case 0x10:
                if (!word_skip_macro_extnames(fd, end_offset)) {
                    cli_mark_scan_incomplete(ctx, "Word macro directory external names were truncated");
                    malformed = TRUE;
                    done      = TRUE;
                }
                break;
            case 0x11:
                if (!word_skip_macro_intnames(fd, end_offset)) {
                    cli_mark_scan_incomplete(ctx, "Word macro directory internal names were truncated");
                    malformed = TRUE;
                    done      = TRUE;
                }
                break;
            case 0x40: /* end marker */
            case 0x12: /* ??? */
                done = TRUE;
                break;
            default:
                cli_dbgmsg("wm_readdir: unknown type: 0x%x\n", info_id);
                cli_mark_scan_incomplete(ctx, "Word macro directory contains an unknown record");
                malformed = TRUE;
                done      = TRUE;
                break;
        }
    }

    if (malformed || macro_info.count == 0) {
        free(macro_info.entries);
        return NULL;
    }

    vba_project = create_vba_project(macro_info.count, "", NULL);
    if (vba_project == NULL) {
        cli_mark_scan_incomplete(ctx, "Word macro project could not be allocated");
        free(macro_info.entries);
        return NULL;
    }

    if (vba_project) {
        vba_project->length = (uint32_t *)cli_max_malloc(sizeof(uint32_t) * macro_info.count);
        vba_project->key    = (unsigned char *)cli_max_malloc(sizeof(unsigned char) * macro_info.count);
        if ((vba_project->length != NULL) &&
            (vba_project->key != NULL)) {
            int i;
            const macro_entry_t *m = macro_info.entries;

            for (i = 0; i < macro_info.count; i++) {
                vba_project->offset[i] = m->offset;
                vba_project->length[i] = m->len;
                vba_project->key[i]    = m->key;
                m++;
            }
        } else {
            cli_errmsg("cli_wm_readdir: Unable to allocate memory for vba_project\n");
            cli_mark_scan_incomplete(ctx, "Word macro project metadata could not be allocated");
            free(vba_project->name);
            free(vba_project->colls);
            free(vba_project->dir);
            free(vba_project->offset);
            if (vba_project->length)
                free(vba_project->length);
            if (vba_project->key)
                free(vba_project->key);
            free(vba_project);
            vba_project = NULL;
        }
    }
    free(macro_info.entries);

    return vba_project;
}

unsigned char *
cli_wm_decrypt_macro(int fd, off_t offset, uint32_t len, unsigned char key)
{
    unsigned char *buff;

    if (len == 0)
        return NULL;

    if (fd < 0)
        return NULL;

    buff = (unsigned char *)cli_max_malloc(len);
    if (buff == NULL) {
        cli_errmsg("cli_wm_decrypt_macro: Unable to allocate memory for buff\n");
        return NULL;
    }

    if (!seekandread(fd, offset, SEEK_SET, buff, len)) {
        free(buff);
        return NULL;
    }
    if (key) {
        unsigned char *p;

        for (p = buff; p < &buff[len]; p++)
            *p ^= key;
    }
    return buff;
}

/**
 * @brief Keep reading bytes until we reach a NUL.
 *
 * @param fd   File descriptor
 * @return int Returns FALSE if none is found, else TRUE
 */
static int skip_past_nul(int fd)
{
    char *end;
    char smallbuf[128];

    do {
        size_t nread = cli_readn(fd, smallbuf, sizeof(smallbuf));
        if ((nread == 0) || (nread == (size_t)-1))
            return FALSE;
        end = memchr(smallbuf, '\0', nread);
        if (end) {
            if (lseek(fd, 1 + (end - smallbuf) - (off_t)nread, SEEK_CUR) < 0)
                return FALSE;
            return TRUE;
        }
    } while (1);
}

/*
 * Read 2 bytes as a 16-bit number, host byte order. Return success or fail
 */
static int
read_uint16(int fd, uint16_t *u, int big_endian)
{
    if (cli_readn(fd, u, sizeof(uint16_t)) != sizeof(uint16_t))
        return FALSE;

    *u = vba_endian_convert_16(*u, big_endian);

    return TRUE;
}

/*
 * Read 4 bytes as a 32-bit number, host byte order. Return success or fail
 */
static int
read_uint32(int fd, uint32_t *u, int big_endian)
{
    if (cli_readn(fd, u, sizeof(uint32_t)) != sizeof(uint32_t))
        return FALSE;

    *u = vba_endian_convert_32(*u, big_endian);

    return TRUE;
}

/*
 * Miss some bytes then read a bit
 */
static int
seekandread(int fd, off_t offset, int whence, void *data, size_t len)
{
    if (lseek(fd, offset, whence) == (off_t)-1) {
        cli_dbgmsg("lseek failed\n");
        return FALSE;
    }
    return cli_readn(fd, data, len) == len;
}

/*
 * Create and initialise a vba_project structure
 */
static vba_project_t *
create_vba_project(int record_count, const char *dir, struct uniq *U)
{
    vba_project_t *ret;

    ret = (vba_project_t *)calloc(1, sizeof(struct vba_project_tag));

    if (ret == NULL) {
        cli_errmsg("create_vba_project: Unable to allocate memory for vba project structure\n");
        return NULL;
    }

    ret->name   = (char **)cli_max_malloc(sizeof(char *) * record_count);
    ret->colls  = (uint32_t *)cli_max_malloc(sizeof(uint32_t) * record_count);
    ret->dir    = cli_safer_strdup(dir);
    ret->offset = (uint32_t *)cli_max_malloc(sizeof(uint32_t) * record_count);

    if ((ret->colls == NULL) || (ret->name == NULL) || (ret->dir == NULL) || (ret->offset == NULL)) {
        cli_free_vba_project(ret);
        cli_errmsg("create_vba_project: Unable to allocate memory for vba project elements\n");
        return NULL;
    }
    ret->count = record_count;
    ret->U     = U;

    return ret;
}

/**
 * @brief Free up the memory associated with the vba_project_t type.
 *
 * @param project A vba_project_t type allocated by one of these:
 *  - create_vba_project()
 *  - cli_wm_readdir()
 *  - cli_vba_readdir()
 */
void cli_free_vba_project(vba_project_t *vba_project)
{
    if (vba_project) {
        if (vba_project->dir)
            free(vba_project->dir);
        if (vba_project->colls)
            free(vba_project->colls);
        if (vba_project->name)
            free(vba_project->name);
        if (vba_project->offset)
            free(vba_project->offset);
        if (vba_project->length)
            free(vba_project->length);
        if (vba_project->key)
            free(vba_project->key);
        free(vba_project);
    }

    return;
}
