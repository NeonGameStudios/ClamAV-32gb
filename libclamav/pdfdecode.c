/*
 *  Copyright (C) 2016-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Author: Kevin Lin
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
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL.  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so.  If you
 *  do not wish to do so, delete this exception statement from your
 *  version.  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <zlib.h>

#if HAVE_ICONV
#include <iconv.h>
#endif

#include "clamav.h"
#include "others.h"
#include "pdf.h"
#include "pdfdecode.h"
#include "str.h"
#include "bytecode.h"
#include "bytecode_api.h"
#include "lzw/lzwdec.h"

#define PDFTOKEN_FLAG_XREF 0x1

#define INFLATE_CHUNK_SIZE (1024 * 256)

struct pdf_token {
    uint32_t flags;   /* tracking flags */
    uint32_t success; /* successfully decoded filters */
    size_t length;    /* length of current content; TODO: transition to size_t */
    uint8_t *content; /* content stream */
};

struct pdf_stream_reader {
    struct pdf_struct *pdf;
    const uint8_t *memory;
    fmap_t *map;
    size_t length;
    size_t source_offset;
    const uint8_t *buffer;
    size_t buffer_length;
    size_t buffer_offset;
};

struct pdf_filter_stage {
    int fd;
    char *path;
    size_t length;
    uint64_t reserved;
};

static cl_error_t pdf_decoder_output_width_check(cli_ctx *ctx, size_t current, size_t additional)
{
    if (additional > (size_t)UINT32_MAX || current > (size_t)UINT32_MAX - additional) {
        cli_mark_scan_incomplete(ctx, "PDF decoder output exceeds the 32-bit decoder boundary");
        return CL_ERESOURCE;
    }

    return CL_SUCCESS;
}

static cl_error_t pdf_decoder_capacity_check(cli_ctx *ctx, size_t capacity)
{
    if (capacity > SIZE_MAX - INFLATE_CHUNK_SIZE || capacity > CLI_MAX_ALLOCATION - INFLATE_CHUNK_SIZE) {
        cli_mark_scan_incomplete(ctx, "PDF decoder output exceeds the individual allocation boundary");
        return CL_ERESOURCE;
    }

    return CL_SUCCESS;
}

static cl_error_t pdf_checktimelimit(struct pdf_struct *pdf, const char *reason)
{
    cli_ctx *ctx = pdf ? pdf->ctx : NULL;
    cl_error_t status = cli_checktimelimit(ctx);

    if (status != CL_SUCCESS && ctx)
        cli_mark_scan_incomplete(ctx, reason);

    return status;
}

static void pdf_stream_reader_init_memory(struct pdf_stream_reader *reader,
                                          struct pdf_struct *pdf,
                                          const uint8_t *memory, size_t length)
{
    memset(reader, 0, sizeof(*reader));
    reader->pdf    = pdf;
    reader->memory = memory;
    reader->length = length;
}

static cl_error_t pdf_stream_reader_init_file(struct pdf_stream_reader *reader,
                                              struct pdf_struct *pdf, int fd,
                                              size_t length, const char *path)
{
    memset(reader, 0, sizeof(*reader));
    reader->pdf    = pdf;
    reader->length = length;
    reader->map    = fmap_new(fd, 0, length, "pdf-filter-stage", path);
    if (reader->map == NULL) {
        cli_mark_scan_incomplete(pdf->ctx, "PDF filter-stage input could not be mapped for bounded reads");
        return CL_ERESOURCE;
    }
    return CL_SUCCESS;
}

static void pdf_stream_reader_destroy(struct pdf_stream_reader *reader)
{
    if (reader == NULL)
        return;
    if (reader->map != NULL)
        cl_fmap_close(reader->map);
    memset(reader, 0, sizeof(*reader));
}

static size_t pdf_stream_reader_consumed(const struct pdf_stream_reader *reader)
{
    size_t buffered = reader->buffer_length - reader->buffer_offset;

    return reader->source_offset - buffered;
}

static cl_error_t pdf_stream_reader_reset(struct pdf_stream_reader *reader,
                                          size_t offset)
{
    if (reader == NULL || offset > reader->length)
        return CL_EARG;
    reader->source_offset = offset;
    reader->buffer        = NULL;
    reader->buffer_length = 0;
    reader->buffer_offset = 0;
    return CL_SUCCESS;
}

static cl_error_t pdf_stream_reader_fill(struct pdf_stream_reader *reader)
{
    size_t length;
    const uint8_t *data;

    if (reader == NULL || reader->pdf == NULL)
        return CL_ENULLARG;
    if (reader->source_offset >= reader->length) {
        reader->buffer        = NULL;
        reader->buffer_length = 0;
        reader->buffer_offset = 0;
        return CL_SUCCESS;
    }

    length = MIN((size_t)PDF_INPUT_WINDOW_SIZE,
                 reader->length - reader->source_offset);
    if (reader->map != NULL) {
        data = fmap_need_off_once(reader->map, reader->source_offset, length);
        if (data == NULL) {
            cli_mark_scan_incomplete(reader->pdf->ctx,
                                     "PDF filter-stage input window could not be read");
            return CL_EREAD;
        }
    } else {
        if (reader->memory == NULL)
            return CL_ENULLARG;
        data = reader->memory + reader->source_offset;
    }

    reader->source_offset += length;
    reader->buffer        = data;
    reader->buffer_length = length;
    reader->buffer_offset = 0;
    return CL_SUCCESS;
}

static cl_error_t pdf_stream_reader_next_chunk(struct pdf_stream_reader *reader,
                                               const uint8_t **data,
                                               size_t *length)
{
    cl_error_t status;

    if (reader == NULL || data == NULL || length == NULL)
        return CL_ENULLARG;
    if (reader->buffer_offset == reader->buffer_length) {
        status = pdf_stream_reader_fill(reader);
        if (status != CL_SUCCESS)
            return status;
    }
    *data   = reader->buffer == NULL ? NULL : reader->buffer + reader->buffer_offset;
    *length = reader->buffer_length - reader->buffer_offset;
    reader->buffer_offset = reader->buffer_length;
    return CL_SUCCESS;
}

static cl_error_t pdf_stream_reader_get_byte(struct pdf_stream_reader *reader,
                                             uint8_t *byte, bool *at_eof)
{
    cl_error_t status;

    if (reader == NULL || byte == NULL || at_eof == NULL)
        return CL_ENULLARG;
    if (reader->buffer_offset == reader->buffer_length) {
        status = pdf_stream_reader_fill(reader);
        if (status != CL_SUCCESS)
            return status;
    }
    if (reader->buffer_length == 0) {
        *at_eof = true;
        return CL_SUCCESS;
    }

    *byte = reader->buffer[reader->buffer_offset++];
    *at_eof = false;
    return CL_SUCCESS;
}

static cl_error_t pdf_stream_reader_read_exact(struct pdf_stream_reader *reader,
                                               uint8_t *output, size_t length,
                                               bool *complete)
{
    size_t offset;

    if (reader == NULL || (length != 0 && output == NULL) || complete == NULL)
        return CL_ENULLARG;
    *complete = false;

    for (offset = 0; offset < length; offset++) {
        bool at_eof;
        cl_error_t status = pdf_stream_reader_get_byte(reader,
                                                       output + offset,
                                                       &at_eof);

        if (status != CL_SUCCESS)
            return status;
        if (at_eof)
            return CL_SUCCESS;
    }

    *complete = true;
    return CL_SUCCESS;
}

static cl_error_t pdf_stream_reader_check_deadline(
    struct pdf_stream_reader *reader, size_t *next_deadline_offset,
    const char *reason)
{
    size_t consumed;
    cl_error_t status;

    if (reader == NULL || next_deadline_offset == NULL || reason == NULL)
        return CL_ENULLARG;
    consumed = pdf_stream_reader_consumed(reader);
    if (consumed < *next_deadline_offset)
        return CL_SUCCESS;

    status = pdf_checktimelimit(reader->pdf, reason);
    if (status != CL_SUCCESS)
        return status;
    if (consumed > SIZE_MAX - PDF_INPUT_WINDOW_SIZE) {
        *next_deadline_offset = SIZE_MAX;
    } else {
        *next_deadline_offset = consumed + PDF_INPUT_WINDOW_SIZE;
    }
    return CL_SUCCESS;
}

static cl_error_t pdf_stream_reader_find_next_line(struct pdf_stream_reader *reader,
                                                   size_t search_start,
                                                   size_t *line_start)
{
    bool saw_line_end = false;
    cl_error_t status;

    if (reader == NULL || line_start == NULL || search_start > reader->length)
        return CL_ENULLARG;
    status = pdf_stream_reader_reset(reader, search_start);
    if (status != CL_SUCCESS)
        return status;

    for (;;) {
        uint8_t byte;
        bool at_eof;
        size_t consumed = pdf_stream_reader_consumed(reader);

        if ((consumed & 0x3fffU) == 0) {
            status = pdf_checktimelimit(reader->pdf,
                                        "PDF decoder resynchronization reached the configured time limit");
            if (status != CL_SUCCESS)
                return status;
        }
        status = pdf_stream_reader_get_byte(reader, &byte, &at_eof);
        if (status != CL_SUCCESS)
            return status;
        if (at_eof) {
            *line_start = reader->length;
            return CL_SUCCESS;
        }
        if (byte == '\n' || byte == '\r') {
            saw_line_end = true;
        } else if (saw_line_end) {
            *line_start = pdf_stream_reader_consumed(reader) - 1U;
            return CL_SUCCESS;
        }
    }
}

static cl_error_t pdf_write_output(struct pdf_struct *pdf, int fout, const void *data, size_t length)
{
    cl_error_t status;

    if (pdf == NULL || pdf->ctx == NULL || data == NULL || fout < 0)
        return CL_ENULLARG;

    status = pdf_checktimelimit(pdf, "PDF stream output admission reached the configured time limit");
    if (status != CL_SUCCESS)
        return status;

    if (pdf->temporary_reserved != NULL) {
        if (UINT64_MAX - *pdf->temporary_reserved < (uint64_t)length) {
            cli_mark_scan_incomplete(pdf->ctx, "PDF stream temporary output size overflowed");
            return CL_ERESOURCE;
        }

        status = cli_scan_reserve_temporary(pdf->ctx, (uint64_t)length);
        if (status != CL_SUCCESS) {
            cli_mark_scan_incomplete(pdf->ctx, "PDF stream output exceeds temporary storage limits");
            return status;
        }
        *pdf->temporary_reserved += (uint64_t)length;
    }

    status = pdf_checktimelimit(pdf, "PDF stream output write reached the configured time limit");
    if (status != CL_SUCCESS) {
        if (pdf->temporary_reserved != NULL) {
            cli_scan_release_temporary(pdf->ctx, (uint64_t)length);
            *pdf->temporary_reserved -= (uint64_t)length;
        }
        return status;
    }

    if (cli_writen(fout, data, length) != length) {
        if (pdf->temporary_reserved != NULL) {
            cli_scan_release_temporary(pdf->ctx, (uint64_t)length);
            *pdf->temporary_reserved -= (uint64_t)length;
        }
        cli_mark_scan_incomplete(pdf->ctx, "PDF stream output could not be written completely");
        return CL_EWRITE;
    }

    return CL_SUCCESS;
}

static cl_error_t pdf_write_raw_stream(struct pdf_struct *pdf, const char *stream, size_t streamlen, int fout,
                                       size_t *bytes_scanned)
{
    size_t offset = 0;
    cl_error_t status;

    status = cli_checklimits("pdf", pdf->ctx, (uint64_t)streamlen, 0, 0);
    if (status != CL_SUCCESS) {
        cli_mark_scan_incomplete(pdf->ctx, "PDF raw stream exceeded configured scan limits");
        return status;
    }

    while (offset < streamlen) {
        size_t chunk = MIN((size_t)PDF_INPUT_WINDOW_SIZE, streamlen - offset);

        status = pdf_checktimelimit(pdf, "PDF raw stream traversal reached the configured time limit");
        if (status != CL_SUCCESS)
            return status;

        status = pdf_write_output(pdf, fout, stream + offset, chunk);
        if (status != CL_SUCCESS)
            return status;
        offset += chunk;
    }

    if (bytes_scanned != NULL)
        *bytes_scanned = streamlen;
    return CL_SUCCESS;
}

static size_t pdf_decodestream_internal(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdf_dict *params, struct pdf_token *token, int fout, cl_error_t *status, struct objstm_struct *objstm);
static cl_error_t pdf_rollback_stream_output(struct pdf_struct *pdf, int fout,
                                             off_t output_start,
                                             uint64_t reservation_start);
static cl_error_t pdf_stream_flatedecode(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdf_dict *params,
                                         const char *stream, size_t streamlen, int fout, size_t *bytes_scanned);
static cl_error_t pdf_stream_rldecode(struct pdf_struct *pdf, const char *stream, size_t streamlen,
                                      int fout, size_t *bytes_scanned);
static cl_error_t pdf_stream_asciihexdecode(struct pdf_struct *pdf, struct pdf_obj *obj, const char *stream,
                                            size_t streamlen, int fout, size_t *bytes_scanned);
static cl_error_t pdf_stream_ascii85decode(struct pdf_struct *pdf, struct pdf_obj *obj, const char *stream,
                                           size_t streamlen, int fout, size_t *bytes_scanned);
static cl_error_t pdf_stream_lzwdecode(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdf_dict *params,
                                       const char *stream, size_t streamlen, int fout, size_t *bytes_scanned);
static cl_error_t pdf_stream_flatedecode_reader(struct pdf_struct *pdf, struct pdf_obj *obj,
                                                struct pdf_dict *params, struct pdf_stream_reader *reader,
                                                int fout, size_t *bytes_scanned);
static cl_error_t pdf_stream_rldecode_reader(struct pdf_struct *pdf, struct pdf_stream_reader *reader,
                                             int fout, size_t *bytes_scanned);
static cl_error_t pdf_stream_asciihexdecode_reader(struct pdf_struct *pdf, struct pdf_obj *obj,
                                                   struct pdf_stream_reader *reader, int fout,
                                                   size_t *bytes_scanned);
static cl_error_t pdf_stream_ascii85decode_reader(struct pdf_struct *pdf, struct pdf_obj *obj,
                                                  struct pdf_stream_reader *reader, int fout,
                                                  size_t *bytes_scanned);
static cl_error_t pdf_stream_lzwdecode_reader(struct pdf_struct *pdf, struct pdf_obj *obj,
                                              struct pdf_dict *params, struct pdf_stream_reader *reader,
                                              int fout, size_t *bytes_scanned);

static void pdf_filter_stage_init(struct pdf_filter_stage *stage)
{
    memset(stage, 0, sizeof(*stage));
    stage->fd = -1;
}

static cl_error_t pdf_filter_stage_cleanup(struct pdf_struct *pdf,
                                           struct pdf_filter_stage *stage,
                                           cl_error_t status)
{
    if (stage == NULL)
        return status;

    if (stage->fd >= 0 && close(stage->fd) != 0) {
        cli_mark_scan_incomplete(pdf->ctx,
                                 "PDF filter-stage file could not be closed");
        if (status == CL_SUCCESS || status == CL_VERIFIED ||
            status == CL_BREAK)
            status = CL_EWRITE;
    }
    stage->fd = -1;

    if (stage->path != NULL &&
        (pdf->ctx->engine == NULL || !pdf->ctx->engine->keeptmp) &&
        cli_unlink(stage->path) != 0) {
        cli_mark_scan_incomplete(pdf->ctx,
                                 "PDF filter-stage file could not be removed");
        if (status == CL_SUCCESS || status == CL_VERIFIED ||
            status == CL_BREAK)
            status = CL_EUNLINK;
    }
    free(stage->path);
    stage->path = NULL;

    if (stage->reserved != 0) {
        if (pdf->temporary_reserved == NULL ||
            *pdf->temporary_reserved < stage->reserved) {
            cli_mark_scan_incomplete(
                pdf->ctx,
                "PDF filter-stage temporary accounting underflowed during cleanup");
            if (status == CL_SUCCESS || status == CL_VERIFIED ||
                status == CL_BREAK)
                status = CL_ERESOURCE;
        } else {
            cli_scan_release_temporary(pdf->ctx, stage->reserved);
            *pdf->temporary_reserved -= stage->reserved;
        }
    }
    stage->reserved = 0;
    stage->length   = 0;
    return status;
}

static bool pdf_stream_filter_is_supported(uint32_t filter)
{
    return filter == OBJ_FILTER_FLATE || filter == OBJ_FILTER_RL ||
           filter == OBJ_FILTER_AH || filter == OBJ_FILTER_A85 ||
           filter == OBJ_FILTER_LZW;
}

static bool pdf_stream_filter_chain_is_supported(const struct pdf_obj *obj)
{
    uint32_t i;

    if (obj == NULL || obj->numfilters == 0 ||
        obj->numfilters > PDF_FILTERLIST_MAX)
        return false;
    for (i = 0; i < obj->numfilters; i++) {
        if (!pdf_stream_filter_is_supported(obj->filterlist[i]))
            return false;
    }
    return true;
}

static cl_error_t pdf_stream_filter_dispatch(
    struct pdf_struct *pdf, struct pdf_obj *obj, struct pdf_dict *params,
    uint32_t filter, struct pdf_stream_reader *reader, int fout,
    size_t *bytes_scanned)
{
    switch (filter) {
        case OBJ_FILTER_FLATE:
            return pdf_stream_flatedecode_reader(pdf, obj, params, reader,
                                                  fout, bytes_scanned);
        case OBJ_FILTER_RL:
            return pdf_stream_rldecode_reader(pdf, reader, fout,
                                               bytes_scanned);
        case OBJ_FILTER_AH:
            return pdf_stream_asciihexdecode_reader(pdf, obj, reader, fout,
                                                     bytes_scanned);
        case OBJ_FILTER_A85:
            return pdf_stream_ascii85decode_reader(pdf, obj, reader, fout,
                                                    bytes_scanned);
        case OBJ_FILTER_LZW:
            return pdf_stream_lzwdecode_reader(pdf, obj, params, reader,
                                                fout, bytes_scanned);
        default:
            return CL_EARG;
    }
}

static cl_error_t pdf_stream_filter_chain(
    struct pdf_struct *pdf, struct pdf_obj *obj, struct pdf_dict *params,
    const char *stream, size_t streamlen, int fout, size_t *bytes_scanned)
{
    struct pdf_filter_stage input_stage;
    struct pdf_filter_stage output_stage;
    struct pdf_stream_reader reader;
    uint64_t reservation_start = 0;
    off_t output_start;
    cl_error_t status = CL_SUCCESS;
    uint32_t i;
    bool reader_initialized = false;

    if (pdf == NULL || obj == NULL || stream == NULL || bytes_scanned == NULL ||
        obj->numfilters < 2 || !pdf_stream_filter_chain_is_supported(obj))
        return CL_EARG;
    *bytes_scanned = 0;
    pdf_filter_stage_init(&input_stage);
    pdf_filter_stage_init(&output_stage);

    output_start = lseek(fout, 0, SEEK_CUR);
    if (output_start < 0) {
        cli_mark_scan_incomplete(
            pdf->ctx,
            "PDF filter-chain output position could not be recorded");
        return CL_ESEEK;
    }
    if (pdf->temporary_reserved != NULL)
        reservation_start = *pdf->temporary_reserved;

    pdf_stream_reader_init_memory(&reader, pdf,
                                  (const uint8_t *)stream, streamlen);
    reader_initialized = true;

    for (i = 0; i < obj->numfilters; i++) {
        STATBUF output_stat;
        size_t decoded = 0;
        bool final_filter = i + 1U == obj->numfilters;
        int output_fd      = fout;

        status = pdf_checktimelimit(
            pdf, "PDF streamed filter chain reached the configured time limit");
        if (status != CL_SUCCESS)
            goto fail;

        if (!final_filter) {
            status = cli_gentempfd(pdf->ctx->this_layer_tmpdir,
                                   &output_stage.path, &output_stage.fd);
            if (status != CL_SUCCESS) {
                cli_mark_scan_incomplete(
                    pdf->ctx,
                    "PDF filter-chain intermediate file could not be created");
                goto fail;
            }
            output_fd = output_stage.fd;
        }

        status = pdf_stream_filter_dispatch(
            pdf, obj, params, obj->filterlist[i], &reader, output_fd,
            &decoded);
        if (status != CL_SUCCESS)
            goto fail;

        if (final_filter) {
            pdf_stream_reader_destroy(&reader);
            reader_initialized = false;
            status = pdf_filter_stage_cleanup(pdf, &input_stage, status);
            if (status != CL_SUCCESS)
                goto fail;
            *bytes_scanned = decoded;
            return CL_SUCCESS;
        }

        output_stage.length = decoded;
        if (pdf->temporary_reserved != NULL)
            output_stage.reserved = (uint64_t)decoded;
        if (FSTAT(output_stage.fd, &output_stat) != 0 ||
            output_stat.st_size < 0 || !S_ISREG(output_stat.st_mode) ||
            (uint64_t)output_stat.st_size != (uint64_t)decoded) {
            cli_mark_scan_incomplete(
                pdf->ctx,
                "PDF filter-chain intermediate size could not be verified");
            status = CL_EWRITE;
            goto fail;
        }

        pdf_stream_reader_destroy(&reader);
        reader_initialized = false;
        status = pdf_filter_stage_cleanup(pdf, &input_stage, status);
        if (status != CL_SUCCESS)
            goto fail;

        status = pdf_stream_reader_init_file(
            &reader, pdf, output_stage.fd, output_stage.length,
            output_stage.path);
        if (status != CL_SUCCESS)
            goto fail;
        reader_initialized = true;
        input_stage         = output_stage;
        pdf_filter_stage_init(&output_stage);
    }

    status = CL_EPARSE;

fail:
    if (reader_initialized)
        pdf_stream_reader_destroy(&reader);
    status = pdf_filter_stage_cleanup(pdf, &output_stage, status);
    status = pdf_filter_stage_cleanup(pdf, &input_stage, status);
    {
        cl_error_t rollback_status = pdf_rollback_stream_output(
            pdf, fout, output_start, reservation_start);

        if (rollback_status != CL_SUCCESS)
            return rollback_status;
    }
    return status;
}

static cl_error_t filter_ascii85decode(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdf_token *token);
static cl_error_t filter_rldecode(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdf_token *token);
static cl_error_t filter_flatedecode(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdf_dict *params, struct pdf_token *token);
static cl_error_t filter_asciihexdecode(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdf_token *token);
static cl_error_t filter_decrypt(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdf_dict *params, struct pdf_token *token, int mode);
static cl_error_t filter_lzwdecode(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdf_dict *params, struct pdf_token *token);

/**
 * @brief       Wrapper function for pdf_decodestream_internal.
 *
 * Allocate a token object to store decoded filter data.
 * Parse/decode the filter data and scan it.
 *
 * @param pdf       Pdf context structure.
 * @param obj       The object we found the filter content in.
 * @param params    (optional) Dictionary parameters describing the filter data.
 * @param stream    Filter stream buffer pointer.
 * @param streamlen Length of filter stream buffer.
 * @param xref      Indicates if the stream is an /XRef stream.  Do not apply forced decryption on /XRef streams.
 * @param fout      File descriptor to write to be scanned.
 * @param[out] rc   Return code ()
 * @param objstm    (optional) Object stream context structure.
 * @return size_t   The number of bytes written to 'fout' to be scanned.
 */
size_t pdf_decodestream(
    struct pdf_struct *pdf, struct pdf_obj *obj, struct pdf_dict *params,
    const char *stream, size_t streamlen, int xref, int fout, cl_error_t *status,
    struct objstm_struct *objstm)
{
    struct pdf_token *token = NULL;
    size_t bytes_scanned    = 0;

    if (!status) {
        /* invalid args, and no way to pass back the status code */
        return 0;
    }

    if (!pdf || !obj) {
        /* Invalid args */
        *status = CL_EARG;
        goto done;
    }

    *status = pdf_checktimelimit(pdf, "PDF stream inspection reached the configured time limit");
    if (*status != CL_SUCCESS)
        goto done;

    if (!stream || !streamlen || fout < 0) {
        cli_dbgmsg("pdf_decodestream: no filters or stream on obj %u %u\n", obj->id >> 8, obj->id & 0xff);
        *status = CL_ENULLARG;
        goto done;
    }
    if (obj->numfilters > PDF_FILTERLIST_MAX) {
        cli_mark_scan_incomplete(pdf->ctx,
                                 "PDF stream declares too many filters");
        *status = CL_EPARSE;
        goto done;
    }

    /* An unfiltered stream has no reason to enter the contiguous legacy
     * decoder token. Copy it to the child output in bounded chunks instead,
     * preserving the 64-bit containing-file coordinate and shared temporary
     * admission. On mmap-capable builds, an ordinary unencrypted object
     * stream retains that completed child as read-only file-backed storage. */
    if (obj->numfilters == 0 &&
        !(pdf->flags & (1 << DECRYPTABLE_PDF)) &&
        (objstm == NULL ||
         (PDF_HAVE_FILE_BACKED_OBJECT_STREAMS &&
          !(pdf->flags & (1 << ENCRYPTED_PDF))))) {
        *status = pdf_write_raw_stream(pdf, stream, streamlen, fout, &bytes_scanned);
        if (*status == CL_SUCCESS && objstm != NULL)
            *status = pdf_objstm_attach_file(pdf, objstm, fout,
                                             bytes_scanned);
        goto done;
    }

    /* Ordinary Flate, RunLength, ASCIIHex, ASCII85, and LZW streams do not
     * need the legacy whole-buffer token. A single filter writes directly to
     * the quota-accounted child file; supported chains retain at most one
     * completed input spool while producing the next stage. Ordinary
     * unencrypted object streams retain the completed final child through a
     * read-only file-backed mapping; encrypted streams must still pass through
     * decryption first. XRef streams deliberately skip forced decryption. */
    if (obj->numfilters != 0 &&
        pdf_stream_filter_chain_is_supported(obj) &&
        (objstm == NULL ||
         (PDF_HAVE_FILE_BACKED_OBJECT_STREAMS &&
          !(pdf->flags & (1 << ENCRYPTED_PDF)))) &&
        !(obj->flags & (1 << OBJ_FILTER_CRYPT)) &&
        (!(pdf->flags & (1 << DECRYPTABLE_PDF)) || xref)) {
        cl_error_t decode_status;

        if (obj->numfilters > 1) {
            decode_status = pdf_stream_filter_chain(
                pdf, obj, params, stream, streamlen, fout, &bytes_scanned);
        } else {
            switch (obj->filterlist[0]) {
                case OBJ_FILTER_FLATE:
                    decode_status = pdf_stream_flatedecode(pdf, obj, params, stream, streamlen, fout, &bytes_scanned);
                    break;
                case OBJ_FILTER_RL:
                    decode_status = pdf_stream_rldecode(pdf, stream, streamlen, fout, &bytes_scanned);
                    break;
                case OBJ_FILTER_AH:
                    decode_status = pdf_stream_asciihexdecode(pdf, obj, stream, streamlen, fout, &bytes_scanned);
                    break;
                case OBJ_FILTER_A85:
                    decode_status = pdf_stream_ascii85decode(pdf, obj, stream, streamlen, fout, &bytes_scanned);
                    break;
                case OBJ_FILTER_LZW:
                    decode_status = pdf_stream_lzwdecode(pdf, obj, params, stream, streamlen, fout, &bytes_scanned);
                    break;
                default:
                    decode_status = CL_EARG;
                    break;
            }
        }
        if (decode_status == CL_EPARSE || decode_status == CL_BREAK) {
            size_t raw_bytes           = 0;
            cl_error_t fallback_status = pdf_write_raw_stream(pdf, stream, streamlen, fout, &raw_bytes);

            if (fallback_status != CL_SUCCESS) {
                *status = fallback_status;
            } else {
                bytes_scanned = raw_bytes;
                *status       = (decode_status == CL_BREAK) ? CL_SUCCESS : CL_EPARSE;
            }
        } else if (decode_status == CL_SUCCESS && objstm != NULL) {
            *status = pdf_objstm_attach_file(pdf, objstm, fout,
                                             bytes_scanned);
        } else {
            *status = decode_status;
        }
        goto done;
    }

    /* The legacy filter implementations use 32-bit input lengths internally.
     * Reject a larger filtered stream before assigning it to the token or
     * narrowing it in a filter, rather than wrapping the length and scanning a
     * prefix. */
    if (streamlen > UINT32_MAX) {
        cli_mark_scan_incomplete(pdf->ctx, "PDF filtered stream exceeds the decoder's 32-bit input boundary");
        *status = CL_ERESOURCE;
        goto done;
    }

    if (streamlen > CLI_MAX_ALLOCATION) {
        cli_mark_scan_incomplete(pdf->ctx, "PDF stream exceeds the individual allocation boundary");
        *status = CL_ERESOURCE;
        goto done;
    }

    *status = CL_SUCCESS;

#if 0
    if (params)
        pdf_print_dict(params, 0);
#endif

    CLI_CALLOC_OR_GOTO_DONE(
        token, 1, sizeof(struct pdf_token),
        *status = CL_EMEM);

    token->flags = 0;
    if (xref)
        token->flags |= PDFTOKEN_FLAG_XREF;

    token->success = 0;

    CLI_MAX_CALLOC_OR_GOTO_DONE(
        token->content, 1, streamlen,
        *status = CL_EMEM);

    memcpy(token->content, stream, streamlen);
    token->length = streamlen;

    cli_dbgmsg("pdf_decodestream: detected %lu applied filters\n", (long unsigned)(obj->numfilters));

    bytes_scanned = pdf_decodestream_internal(pdf, obj, params, token, fout, status, objstm);
    if (CL_VIRUS == *status) {
        goto done;
    }

    if (0 == token->success && (*status == CL_SUCCESS || *status == CL_EPARSE)) {
        /*
         * Either:
         *  a) it failed to decode any filters, or
         *  b) there were no filters.
         *
         * Write out the raw stream to be scanned.
         *
         * Nota bene: If it did decode any filters, the internal() function would
         *            have written out the decoded stream to be scanned.
         */
        cl_error_t limit_status = cli_checklimits("pdf", pdf->ctx, streamlen, 0, 0);
        if (limit_status != CL_SUCCESS) {
            cli_mark_scan_incomplete(pdf->ctx, "PDF raw stream exceeded configured scan limits");
            *status = limit_status;
        } else {
            cli_dbgmsg("pdf_decodestream: no non-forced filters decoded, returning raw stream\n");

            cl_error_t write_status = pdf_write_output(pdf, fout, stream, streamlen);
            if (write_status != CL_SUCCESS) {
                cli_errmsg("pdf_decodestream: failed to write raw stream to output file\n");
                *status = write_status;
            } else {
                bytes_scanned = streamlen;
            }
        }
    }

done:
    if (status && (*status == CL_EPARSE) && pdf && pdf->ctx) {
        cli_mark_scan_incomplete(pdf->ctx, "PDF stream decoding did not complete");
    }

    /*
     * Free up the token, and token content, if any.
     */
    if (NULL != token) {
        if (NULL != token->content) {
            free(token->content);
            token->content = NULL;
            token->length  = 0;
        }
        free(token);
        token = NULL;
    }

    return bytes_scanned;
}

/**
 * @brief       Decode filter buffer data.
 *
 * Attempt to decompress, decrypt or otherwise parse it.
 *
 * @param pdf           Pdf context structure.
 * @param obj           The object we found the filter content in.
 * @param params        (optional) Dictionary parameters describing the filter data.
 * @param token         Pointer to and length of filter data.
 * @param fout          File handle to write data to be scanned.
 * @param[out] status   CL_CLEAN/CL_SUCCESS or CL_VIRUS/CL_E<error>
 * @param objstm        (optional) Object stream context structure.
 * @return ptrdiff_t    The number of bytes we wrote to 'fout'. -1 if failed out.
 */
static size_t pdf_decodestream_internal(
    struct pdf_struct *pdf, struct pdf_obj *obj, struct pdf_dict *params,
    struct pdf_token *token, int fout, cl_error_t *status, struct objstm_struct *objstm)
{
    cl_error_t retval    = CL_SUCCESS;
    size_t bytes_scanned = 0;
    const char *filter   = NULL;
    uint32_t i;

    if (!status) {
        /* invalid args, and no way to pass back the status code */
        return 0;
    }

    if (!pdf || !obj || !token) {
        /* Invalid args */
        *status = CL_EARG;
        goto done;
    }

    *status = pdf_checktimelimit(pdf, "PDF filter chain reached the configured time limit");
    if (*status != CL_SUCCESS)
        goto done;

    *status = CL_SUCCESS;

    /*
     * if pdf is decryptable, scan for CRYPT filter
     * if none, force a DECRYPT filter application
     */
    if ((pdf->flags & (1 << DECRYPTABLE_PDF)) && !(obj->flags & (1 << OBJ_FILTER_CRYPT))) {
        if (token->flags & PDFTOKEN_FLAG_XREF) /* TODO: is this on all crypt filters or only the assumed one? */
            cli_dbgmsg("pdf_decodestream_internal: skipping decoding => non-filter CRYPT (reason: xref)\n");
        else {
            cli_dbgmsg("pdf_decodestream_internal: decoding => non-filter CRYPT\n");
            retval = filter_decrypt(pdf, obj, params, token, 1);
            if (retval != CL_SUCCESS) {
                *status = CL_EPARSE;
                goto done;
            }
        }
    }

    for (i = 0; i < obj->numfilters; i++) {
        retval = pdf_checktimelimit(pdf, "PDF filter traversal reached the configured time limit");
        if (retval != CL_SUCCESS) {
            *status = retval;
            break;
        }

        switch (obj->filterlist[i]) {
            case OBJ_FILTER_A85:
                cli_dbgmsg("pdf_decodestream_internal: decoding [%u] => ASCII85DECODE\n", obj->filterlist[i]);
                retval = filter_ascii85decode(pdf, obj, token);
                break;

            case OBJ_FILTER_RL:
                cli_dbgmsg("pdf_decodestream_internal: decoding [%u] => RLDECODE\n", obj->filterlist[i]);
                retval = filter_rldecode(pdf, obj, token);
                break;

            case OBJ_FILTER_FLATE:
                cli_dbgmsg("pdf_decodestream_internal: decoding [%u] => FLATEDECODE\n", obj->filterlist[i]);
                retval = filter_flatedecode(pdf, obj, params, token);
                break;

            case OBJ_FILTER_AH:
                cli_dbgmsg("pdf_decodestream_internal: decoding [%u] => ASCIIHEXDECODE\n", obj->filterlist[i]);
                retval = filter_asciihexdecode(pdf, obj, token);
                break;

            case OBJ_FILTER_CRYPT:
                cli_dbgmsg("pdf_decodestream_internal: decoding [%u] => CRYPT\n", obj->filterlist[i]);
                retval = filter_decrypt(pdf, obj, params, token, 0);
                break;

            case OBJ_FILTER_LZW:
                cli_dbgmsg("pdf_decodestream_internal: decoding [%u] => LZWDECODE\n", obj->filterlist[i]);
                retval = filter_lzwdecode(pdf, obj, params, token);
                break;

            case OBJ_FILTER_JPX:
                if (!filter) filter = "JPXDECODE";
                /*fallthrough*/
            case OBJ_FILTER_DCT:
                if (!filter) filter = "DCTDECODE";
                /*fallthrough*/
            case OBJ_FILTER_FAX:
                if (!filter) filter = "FAXDECODE";
                /*fallthrough*/
            case OBJ_FILTER_JBIG2:
                if (!filter) filter = "JBIG2DECODE";

                cli_dbgmsg("pdf_decodestream_internal: unimplemented filter type [%u] => %s\n", obj->filterlist[i], filter);
                cli_mark_scan_incomplete(pdf->ctx,
                                         "PDF stream uses an unsupported filter and was not decoded");
                filter = NULL;
                retval = CL_EPARSE;
                break;

            default:
                cli_dbgmsg("pdf_decodestream_internal: unknown filter type [%u]\n", obj->filterlist[i]);
                cli_mark_scan_incomplete(pdf->ctx,
                                         "PDF stream uses an unknown filter and was not decoded");
                retval = CL_EPARSE;
                break;
        }

        if (!(token->content) || !(token->length)) {
            cli_dbgmsg("pdf_decodestream_internal: empty content, breaking after %u (of %u) filters\n", i, obj->numfilters);
            break;
        }

        if (retval != CL_SUCCESS) {
            const char *reason;

            switch (retval) {
                case CL_VIRUS:
                    *status = CL_VIRUS;
                    reason  = "detection";
                    break;
                case CL_BREAK:
                    *status = CL_SUCCESS;
                    reason  = "decoding break";
                    break;
                case CL_EMAXREC:
                case CL_EMAXSIZE:
                case CL_EMAXFILES:
                case CL_ETIMEOUT:
                case CL_ERESOURCE:
                    *status = retval;
                    reason  = (retval == CL_ERESOURCE) ? "resource boundary" : "configured limit";
                    break;
                default:
                    *status = CL_EPARSE;
                    reason  = "decoding error";
                    break;
            }

            cli_dbgmsg("pdf_decodestream_internal: stopping after %d (of %u) filters (reason: %s)\n", i, obj->numfilters, reason);
            break;
        }
        token->success++;
    }

    if ((*status == CL_SUCCESS) && (token->success > 0) && (NULL != token->content)) {
        /*
         * Looks like we successfully decoded some or all of the stream filters,
         * so lets write it out to a file descriptor we scan.
         *
         * In the event that we didn't decode any filters (or maybe there
         * weren't any filters), the calling function will do the same with
         * the raw stream.
         */
        cl_error_t limit_status = cli_checklimits("pdf", pdf->ctx, token->length, 0, 0);
        if (limit_status != CL_SUCCESS) {
            cli_mark_scan_incomplete(pdf->ctx, "PDF decoded stream exceeded configured scan limits");
            *status = limit_status;
        } else {
            cl_error_t write_status = pdf_write_output(pdf, fout, token->content, token->length);

            if (write_status != CL_SUCCESS) {
                cli_errmsg("pdf_decodestream_internal: failed to write decoded stream content to output file\n");
                *status = write_status;
            } else {
                bytes_scanned = token->length;
            }
        }
    }

    if ((NULL != objstm) &&
        (CL_SUCCESS == *status)) {
        unsigned int objs_found = pdf->nobjs;

        /*
         * The caller indicated that the decoded data is an object stream.
         * Perform experimental object stream parsing to extract objects from the stream.
         */
        objstm->streambuf     = (char *)token->content;
        objstm->streambuf_len = (size_t)token->length;

        /* Take ownership of the malloc'd buffer */
        token->content = NULL;
        token->length  = 0;

        /* Don't store the result. It's ok if some or all objects failed to parse.
           It would be far worse to add objects from a stream to the list, and then free
           the stream buffer due to an "error". */
        objstm->parse_status = pdf_find_and_parse_objs_in_objstm(pdf, objstm);
        if (CL_SUCCESS != objstm->parse_status) {
            cli_mark_scan_incomplete(pdf->ctx,
                                     "PDF object-stream parsing did not complete");
            cli_dbgmsg("pdf_decodestream_internal: pdf_find_and_parse_objs_in_objstm failed!\n");
        }

        if (pdf->nobjs <= objs_found) {
            cli_dbgmsg("pdf_decodestream_internal: pdf_find_and_parse_objs_in_objstm did not find any new objects!\n");
        } else {
            cli_dbgmsg("pdf_decodestream_internal: pdf_find_and_parse_objs_in_objstm found %u new objects.\n", pdf->nobjs - objs_found);
        }
    }

done:

    return bytes_scanned;
}

/*
 * ascii85 inflation
 * See http://www.piclist.com/techref/method/encode.htm (look for base85)
 */
static cl_error_t filter_ascii85decode(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdf_token *token)
{
    uint8_t *decoded, *dptr;
    size_t declen = 0;
    size_t decoded_size;

    const uint8_t *ptr = (uint8_t *)token->content;
    size_t remaining   = token->length;
    int quintet = 0, rc = CL_SUCCESS;
    uint64_t sum = 0;

    /* Check for overflow */
    if (remaining > (SIZE_MAX - 1) / 4) {
        cli_dbgmsg("cli_pdf: ascii85decode: overflow detected\n");
        return CL_EFORMAT;
    }

    /* 5:4 decoding ratio, with 1:4 expansion sequences => (4*length)+1 */
    decoded_size = (4 * remaining) + 1;
    if (decoded_size > CLI_MAX_ALLOCATION) {
        cli_mark_scan_incomplete(pdf->ctx, "PDF ASCII85 decoded output exceeds the individual allocation boundary");
        return CL_ERESOURCE;
    }
    if (!(dptr = decoded = (uint8_t *)cli_max_malloc(decoded_size))) {
        cli_errmsg("cli_pdf: cannot allocate memory for decoded output\n");
        cli_mark_scan_incomplete(pdf->ctx, "PDF ASCII85 decoded output could not be allocated");
        return CL_EMEM;
    }

    if (cli_memstr((const char *)ptr, remaining, "~>", 2) == NULL)
        cli_dbgmsg("cli_pdf: no EOF marker found\n");

    while (remaining > 0) {
        if (pdf_checktimelimit(pdf, "PDF ASCII85 traversal reached the configured time limit") != CL_SUCCESS) {
            rc = CL_ETIMEOUT;
            break;
        }
        int byte = (remaining--) ? (int)*ptr++ : EOF;

        if ((byte == '~') && (remaining > 0) && (*ptr == '>'))
            byte = EOF;

        if (byte >= '!' && byte <= 'u') {
            sum = (sum * 85) + ((uint32_t)byte - '!');
            if (++quintet == 5) {
                *dptr++ = (unsigned char)(sum >> 24);
                *dptr++ = (unsigned char)((sum >> 16) & 0xFF);
                *dptr++ = (unsigned char)((sum >> 8) & 0xFF);
                *dptr++ = (unsigned char)(sum & 0xFF);

                declen += 4;
                quintet = 0;
                sum     = 0;
            }
        } else if (byte == 'z') {
            if (quintet) {
                cli_dbgmsg("cli_pdf: unexpected 'z'\n");
                rc = CL_EFORMAT;
                break;
            }

            *dptr++ = '\0';
            *dptr++ = '\0';
            *dptr++ = '\0';
            *dptr++ = '\0';

            declen += 4;
        } else if (byte == EOF) {
            cli_dbgmsg("cli_pdf: last quintet contains %d bytes\n", quintet);
            if (quintet) {
                int i;

                if (quintet == 1) {
                    cli_dbgmsg("cli_pdf: invalid last quintet (only 1 byte)\n");
                    rc = CL_EFORMAT;
                    break;
                }

                for (i = quintet; i < 5; i++)
                    sum *= 85;

                if (quintet > 1)
                    sum += (0xFFFFFF >> ((quintet - 2) * 8));

                for (i = 0; i < quintet - 1; i++)
                    *dptr++ = (uint8_t)((sum >> (24 - 8 * i)) & 0xFF);
                declen += quintet - 1;
            }

            break;
        } else if (!isspace(byte)) {
            cli_dbgmsg("cli_pdf: invalid character 0x%x @ %zu\n",
                       byte & 0xFF, token->length - remaining);

            rc = CL_EFORMAT;
            break;
        }
    }

    if (rc == CL_SUCCESS) {
        free(token->content);

        cli_dbgmsg("cli_pdf: deflated %zu bytes from %zu total bytes\n",
                   declen, token->length);

        token->content = decoded;
        token->length  = declen;
    } else {
        if (!(obj->flags & ((1 << OBJ_IMAGE) | (1 << OBJ_TRUNCATED))))
            pdfobj_flag(pdf, obj, BAD_ASCIIDECODE);

        cli_dbgmsg("cli_pdf: error occurred parsing byte %zu of %zu\n",
                   token->length - remaining, token->length);
        free(decoded);
    }
    return rc;
}

/* imported from razorback */
static cl_error_t filter_rldecode(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdf_token *token)
{
    uint8_t *decoded, *temp;
    size_t declen = 0, capacity = 0;

    uint8_t *content = (uint8_t *)token->content;
    uint32_t length  = token->length;
    uint32_t offset  = 0;
    int rc           = CL_SUCCESS;

    UNUSEDPARAM(obj);

    capacity = INFLATE_CHUNK_SIZE;

    if (!(decoded = (uint8_t *)malloc(capacity))) {
        cli_errmsg("cli_pdf: cannot allocate memory for decoded output\n");
        cli_mark_scan_incomplete(pdf->ctx, "PDF RunLength decoded output could not be allocated");
        return CL_EMEM;
    }

    while (offset < length) {
        if (pdf_checktimelimit(pdf, "PDF RunLength traversal reached the configured time limit") != CL_SUCCESS) {
            rc = CL_ETIMEOUT;
            break;
        }
        uint8_t srclen = content[offset++];
        size_t output_length;

        if (srclen < 128) {
            /* direct copy of (srclen + 1) bytes */
            if (offset + srclen + 1 > length) {
                cli_dbgmsg("cli_pdf: required source length (%lu) exceeds remaining length (%lu)\n",
                           (long unsigned)(offset + srclen + 1), (long unsigned)(length - offset));
                rc = CL_EFORMAT;
                break;
            }
            output_length = (size_t)srclen + 1;
            if ((rc = pdf_decoder_output_width_check(pdf->ctx, declen, output_length)) != CL_SUCCESS)
                break;
            if (declen + output_length > capacity) {
                if ((rc = pdf_decoder_capacity_check(pdf->ctx, capacity)) != CL_SUCCESS)
                    break;

                if ((rc = cli_checklimits("pdf", pdf->ctx, capacity + INFLATE_CHUNK_SIZE, 0, 0)) != CL_SUCCESS)
                    break;

                if (!(temp = cli_max_realloc(decoded, capacity + INFLATE_CHUNK_SIZE))) {
                    cli_errmsg("cli_pdf: cannot reallocate memory for decoded output\n");
                    cli_mark_scan_incomplete(pdf->ctx, "PDF RunLength decoded output could not be grown");
                    rc = CL_EMEM;
                    break;
                }
                decoded = temp;
                capacity += INFLATE_CHUNK_SIZE;
            }

            memcpy(decoded + declen, content + offset, output_length);
            offset += srclen + 1;
            declen += output_length;
        } else if (srclen > 128) {
            /* copy the next byte (257 - srclen) times */
            if (offset + 1 > length) {
                cli_dbgmsg("cli_pdf: required source length (%lu) exceeds remaining length (%lu)\n",
                           (long unsigned)(offset + srclen + 1), (long unsigned)(length - offset));
                rc = CL_EFORMAT;
                break;
            }
            output_length = (size_t)(257 - srclen);
            if ((rc = pdf_decoder_output_width_check(pdf->ctx, declen, output_length)) != CL_SUCCESS)
                break;
            if (declen + output_length > capacity) {
                if ((rc = pdf_decoder_capacity_check(pdf->ctx, capacity)) != CL_SUCCESS)
                    break;
                if ((rc = cli_checklimits("pdf", pdf->ctx, capacity + INFLATE_CHUNK_SIZE, 0, 0)) != CL_SUCCESS) {
                    cli_dbgmsg("cli_pdf: required buffer size to inflate compressed filter exceeds maximum: %zu\n", capacity + INFLATE_CHUNK_SIZE);
                    break;
                }

                if (!(temp = cli_max_realloc(decoded, capacity + INFLATE_CHUNK_SIZE))) {
                    cli_errmsg("cli_pdf: cannot reallocate memory for decoded output\n");
                    cli_mark_scan_incomplete(pdf->ctx, "PDF RunLength decoded output could not be grown");
                    rc = CL_EMEM;
                    break;
                }
                decoded = temp;
                capacity += INFLATE_CHUNK_SIZE;
            }

            memset(decoded + declen, content[offset], output_length);
            offset++;
            declen += output_length;
        } else { /* srclen == 128 */
            /* end of data */
            cli_dbgmsg("cli_pdf: end-of-stream marker @ offset " STDu32 " (%zu bytes remaining)\n",
                       offset, token->length - offset);
            break;
        }
    }

    if (rc == CL_SUCCESS) {
        if (declen == 0) {
            cli_dbgmsg("cli_pdf: empty stream after inflation completed.\n");
            rc = CL_BREAK;
        } else if (!(temp = cli_max_realloc(decoded, declen))) {
            /* Shrink output buffer to final the decoded data length to minimize RAM usage */
            cli_errmsg("cli_pdf: cannot reallocate memory for decoded output\n");
            cli_mark_scan_incomplete(pdf->ctx, "PDF RunLength decoded output could not be resized");
            rc = CL_EMEM;
        } else {
            decoded = temp;
        }
    }

    if (rc == CL_SUCCESS || rc == CL_BREAK) {
        free(token->content);

        cli_dbgmsg("cli_pdf: decoded %zu bytes from %zu total bytes\n",
                   declen, token->length);

        token->content = decoded;
        token->length  = declen;
    } else {
        cli_dbgmsg("cli_pdf: error occurred parsing byte %u of %zu\n",
                   offset, token->length);
        free(decoded);
    }
    return rc;
}

static uint8_t *decode_nextlinestart(struct pdf_struct *pdf, uint8_t *content, size_t length)
{
    uint8_t *pt = content;
    size_t r;
    int toggle = 0;

    for (r = 0; r < length; r++, pt++) {
        if ((r & 0x3fffU) == 0 && pdf_checktimelimit(pdf, "PDF decoder resynchronization reached the configured time limit") != CL_SUCCESS)
            return NULL;
        if (*pt == '\n' || *pt == '\r')
            toggle = 1;
        else if (toggle)
            break;
    }

    return pt;
}

static cl_error_t pdf_rollback_stream_output(struct pdf_struct *pdf, int fout, off_t output_start,
                                             uint64_t reservation_start)
{
    cl_error_t status = CL_SUCCESS;

    if (ftruncate(fout, output_start) != 0) {
        cli_mark_scan_incomplete(pdf->ctx, "PDF streamed decoder output could not be truncated during rollback");
        return CL_EWRITE;
    }

    if (pdf->temporary_reserved != NULL) {
        uint64_t reservation_current = *pdf->temporary_reserved;

        if (reservation_current < reservation_start) {
            cli_mark_scan_incomplete(pdf->ctx, "PDF streamed decoder temporary accounting underflowed during rollback");
            status = CL_ERESOURCE;
        } else if (reservation_current != reservation_start) {
            cli_scan_release_temporary(pdf->ctx, reservation_current - reservation_start);
            *pdf->temporary_reserved = reservation_start;
        }
    }

    if (lseek(fout, output_start, SEEK_SET) != output_start) {
        cli_mark_scan_incomplete(pdf->ctx, "PDF streamed decoder output could not be rewound during rollback");
        if (status == CL_SUCCESS)
            status = CL_ESEEK;
    }

    return status;
}

static cl_error_t pdf_stream_output_flush(struct pdf_struct *pdf, int fout, uint8_t *output_buffer,
                                          size_t *output_buffered, size_t decoded,
                                          const char *limit_reason)
{
    cl_error_t status;

    if (output_buffer == NULL || output_buffered == NULL || limit_reason == NULL)
        return CL_ENULLARG;
    if (*output_buffered == 0)
        return CL_SUCCESS;

    status = cli_checklimits("pdf", pdf->ctx, (uint64_t)decoded, 0, 0);
    if (status != CL_SUCCESS) {
        cli_mark_scan_incomplete(pdf->ctx, limit_reason);
        return status;
    }

    status = pdf_write_output(pdf, fout, output_buffer, *output_buffered);
    if (status == CL_SUCCESS)
        *output_buffered = 0;
    return status;
}

static cl_error_t pdf_stream_output_append(struct pdf_struct *pdf, int fout, uint8_t *output_buffer,
                                           size_t *output_buffered, size_t *decoded,
                                           const uint8_t *data, size_t length,
                                           const char *overflow_reason, const char *limit_reason)
{
    size_t offset = 0;

    if (output_buffer == NULL || output_buffered == NULL || decoded == NULL ||
        (length != 0 && data == NULL) || overflow_reason == NULL || limit_reason == NULL)
        return CL_ENULLARG;
    if (*decoded > SIZE_MAX - length || *decoded > UINT64_MAX - length) {
        cli_mark_scan_incomplete(pdf->ctx, overflow_reason);
        return CL_ERESOURCE;
    }

    while (offset < length) {
        size_t available;
        size_t chunk;
        cl_error_t status;

        if (*output_buffered == INFLATE_CHUNK_SIZE) {
            status = pdf_stream_output_flush(pdf, fout, output_buffer, output_buffered,
                                             *decoded, limit_reason);
            if (status != CL_SUCCESS)
                return status;
        }

        available = INFLATE_CHUNK_SIZE - *output_buffered;
        chunk     = MIN(available, length - offset);
        memcpy(output_buffer + *output_buffered, data + offset, chunk);
        *output_buffered += chunk;
        *decoded += chunk;
        offset += chunk;
    }

    if (*output_buffered == INFLATE_CHUNK_SIZE)
        return pdf_stream_output_flush(pdf, fout, output_buffer, output_buffered,
                                       *decoded, limit_reason);
    return CL_SUCCESS;
}

static int pdf_asciihex_nibble(uint8_t byte)
{
    if (byte >= '0' && byte <= '9')
        return byte - '0';
    if (byte >= 'A' && byte <= 'F')
        return byte - 'A' + 10;
    if (byte >= 'a' && byte <= 'f')
        return byte - 'a' + 10;
    return -1;
}

static bool pdf_is_whitespace(uint8_t byte)
{
    return byte == 0 || byte == '\t' || byte == '\n' || byte == '\f' || byte == '\r' || byte == ' ';
}

static cl_error_t pdf_decodeparms_integer(struct pdf_struct *pdf,
                                          const struct pdf_dict_node *node,
                                          long *parsed)
{
    char *end;
    char *value;

    if (node == NULL || parsed == NULL)
        return CL_ENULLARG;
    value = (char *)node->value;
    if (node->type != PDF_DICT_STRING || value == NULL) {
        cli_mark_scan_incomplete(pdf->ctx, "PDF DecodeParms contained a missing or non-scalar numeric value");
        return CL_EPARSE;
    }

    errno   = 0;
    *parsed = strtol(value, &end, 10);
    while (*end != '\0' && isspace((unsigned char)*end))
        end++;
    if (end == value || *end != '\0' || errno == ERANGE) {
        cli_mark_scan_incomplete(pdf->ctx, "PDF DecodeParms contained an invalid numeric value");
        return CL_EPARSE;
    }
    return CL_SUCCESS;
}

static cl_error_t pdf_require_identity_predictor(struct pdf_struct *pdf,
                                                 struct pdf_dict *params)
{
    struct pdf_dict_node *node;

    if (params == NULL)
        return CL_SUCCESS;

    for (node = params->nodes; node != NULL; node = node->next) {
        long predictor;
        cl_error_t status;

        status = pdf_checktimelimit(pdf, "PDF predictor-parameter traversal reached the configured time limit");
        if (status != CL_SUCCESS)
            return status;
        if (node->key == NULL || strcmp(node->key, "/Predictor") != 0)
            continue;

        status = pdf_decodeparms_integer(pdf, node, &predictor);
        if (status != CL_SUCCESS)
            return status;
        cli_dbgmsg("cli_pdf: Predictor: %ld\n", predictor);
        if (predictor != 1) {
            cli_mark_scan_incomplete(pdf->ctx, "PDF predictor decoding is unsupported");
            return CL_EPARSE;
        }
    }
    return CL_SUCCESS;
}

static cl_error_t pdf_inflate_stream_attempt(struct pdf_struct *pdf,
                                             struct pdf_stream_reader *reader,
                                             int fout, size_t *decoded_length,
                                             int *inflate_status)
{
    uint8_t *output = NULL;
    z_stream stream;
    size_t decoded  = 0;
    cl_error_t status;
    int zstat = Z_OK;

    if (reader == NULL || decoded_length == NULL || inflate_status == NULL)
        return CL_ENULLARG;

    *decoded_length = 0;
    *inflate_status = Z_OK;

    output = (uint8_t *)malloc(INFLATE_CHUNK_SIZE);
    if (output == NULL) {
        cli_mark_scan_incomplete(pdf->ctx, "PDF streamed Flate output window could not be allocated");
        return CL_EMEM;
    }

    memset(&stream, 0, sizeof(stream));
    zstat = inflateInit(&stream);
    if (zstat != Z_OK) {
        cli_mark_scan_incomplete(pdf->ctx, "PDF streamed Flate decoder could not be initialized");
        free(output);
        return CL_EMEM;
    }

    status = CL_SUCCESS;
    for (;;) {
        uInt before_input;
        size_t produced;

        status = pdf_checktimelimit(pdf, "PDF streamed Flate traversal reached the configured time limit");
        if (status != CL_SUCCESS)
            break;

        if (stream.avail_in == 0) {
            const uint8_t *input;
            size_t input_length;

            status = pdf_stream_reader_next_chunk(reader, &input, &input_length);
            if (status != CL_SUCCESS)
                break;
            if (input_length != 0) {
                stream.next_in  = (Bytef *)input;
                stream.avail_in = (uInt)input_length;
            }
        }

        stream.next_out  = (Bytef *)output;
        stream.avail_out = (uInt)INFLATE_CHUNK_SIZE;
        before_input     = stream.avail_in;
        zstat            = inflate(&stream, Z_NO_FLUSH);
        produced         = INFLATE_CHUNK_SIZE - (size_t)stream.avail_out;

        if (produced != 0) {
            size_t required;

            if (decoded > SIZE_MAX - produced || decoded > UINT64_MAX - produced) {
                cli_mark_scan_incomplete(pdf->ctx, "PDF streamed Flate output size overflowed");
                status = CL_ERESOURCE;
                break;
            }
            required = decoded + produced;

            status = cli_checklimits("pdf", pdf->ctx, (uint64_t)required, 0, 0);
            if (status != CL_SUCCESS) {
                cli_mark_scan_incomplete(pdf->ctx, "PDF streamed Flate output exceeded configured scan limits");
                break;
            }

            status = pdf_write_output(pdf, fout, output, produced);
            if (status != CL_SUCCESS)
                break;
            decoded = required;
        }

        if (zstat == Z_STREAM_END)
            break;

        if (zstat == Z_OK) {
            if (before_input == stream.avail_in && produced == 0) {
                status = CL_EPARSE;
                break;
            }

            /* A full output window can leave buffered output to drain even
             * after the final input window was consumed. Otherwise, input
             * exhaustion before Z_STREAM_END is a truncated stream. */
            if (stream.avail_in == 0 && reader->source_offset == reader->length &&
                produced < INFLATE_CHUNK_SIZE) {
                status = CL_EPARSE;
                break;
            }
            continue;
        }

        if (zstat == Z_BUF_ERROR && stream.avail_in == 0 &&
            reader->source_offset < reader->length)
            continue;

        if (zstat == Z_MEM_ERROR) {
            cli_mark_scan_incomplete(pdf->ctx, "PDF streamed Flate decoder exhausted memory");
            status = CL_EMEM;
        } else {
            status = CL_EPARSE;
        }
        break;
    }

    *decoded_length = decoded;
    *inflate_status = zstat;
    (void)inflateEnd(&stream);
    free(output);
    return status;
}

static cl_error_t pdf_stream_flatedecode_reader(struct pdf_struct *pdf,
                                                struct pdf_obj *obj,
                                                struct pdf_dict *params,
                                                struct pdf_stream_reader *reader,
                                                int fout, size_t *bytes_scanned)
{
    size_t decoded       = 0;
    size_t payload_start = 0;
    off_t output_start;
    uint64_t reservation_start = 0;
    cl_error_t status;
    int zstat  = Z_OK;
    uint8_t first;
    bool at_eof;

    if (reader == NULL || bytes_scanned == NULL)
        return CL_ENULLARG;
    *bytes_scanned = 0;

    status = pdf_require_identity_predictor(pdf, params);
    if (status != CL_SUCCESS)
        return status;

    output_start = lseek(fout, 0, SEEK_CUR);
    if (output_start < 0) {
        cli_mark_scan_incomplete(pdf->ctx, "PDF streamed Flate output position could not be recorded");
        return CL_ESEEK;
    }
    if (pdf->temporary_reserved != NULL)
        reservation_start = *pdf->temporary_reserved;

    status = pdf_stream_reader_get_byte(reader, &first, &at_eof);
    if (status != CL_SUCCESS)
        goto rollback;
    if (at_eof) {
        cli_mark_scan_incomplete(pdf->ctx, "PDF Flate stream has no compressed payload");
        status = CL_EPARSE;
        goto rollback;
    }
    if (first == '\r') {
        payload_start = 1;
        pdfobj_flag(pdf, obj, BAD_STREAMSTART);
        if (payload_start == reader->length) {
            cli_dbgmsg("cli_pdf: Flate stream has no compressed payload after its leading carriage return\n");
            cli_mark_scan_incomplete(pdf->ctx, "PDF Flate stream has no compressed payload");
            status = CL_EPARSE;
            goto rollback;
        }
    } else {
        status = pdf_stream_reader_reset(reader, 0);
        if (status != CL_SUCCESS)
            goto rollback;
    }

    status = pdf_inflate_stream_attempt(pdf, reader, fout, &decoded, &zstat);
    if (status == CL_EPARSE && decoded == 0) {
        size_t resynchronized;

        status = pdf_stream_reader_find_next_line(reader, payload_start,
                                                  &resynchronized);
        if (status != CL_SUCCESS)
            goto rollback;

        if (resynchronized > payload_start &&
            resynchronized < reader->length) {
            status = pdf_stream_reader_reset(reader, resynchronized);
            if (status != CL_SUCCESS)
                goto rollback;
            pdfobj_flag(pdf, obj, BAD_FLATESTART);
            decoded = 0;
            status  = pdf_inflate_stream_attempt(pdf, reader, fout, &decoded,
                                                 &zstat);
        }
    }

    if (status == CL_SUCCESS) {
        cli_dbgmsg("cli_pdf: streamed Flate decoded %zu bytes from %zu input bytes\n",
                   decoded, reader->length);
        *bytes_scanned = decoded;
        return decoded == 0 ? CL_BREAK : CL_SUCCESS;
    }

rollback:
    {
        cl_error_t rollback_status = pdf_rollback_stream_output(pdf, fout, output_start, reservation_start);
        if (rollback_status != CL_SUCCESS)
            return rollback_status;
    }

    if (status == CL_EPARSE) {
        if (decoded == 0) {
            pdfobj_flag(pdf, obj, BAD_FLATESTART);
        } else {
            pdfobj_flag(pdf, obj, BAD_FLATE);
        }

        if (zstat == Z_OK || zstat == Z_BUF_ERROR) {
            cli_mark_scan_incomplete(pdf->ctx, "PDF Flate stream did not reach the decoder end state");
        } else {
            cli_mark_scan_incomplete(pdf->ctx, "PDF Flate decoder failed before the stream completed");
        }
    }

    return status;
}

static cl_error_t pdf_stream_flatedecode(struct pdf_struct *pdf,
                                         struct pdf_obj *obj,
                                         struct pdf_dict *params,
                                         const char *stream_data,
                                         size_t streamlen, int fout,
                                         size_t *bytes_scanned)
{
    struct pdf_stream_reader reader;
    cl_error_t status;

    pdf_stream_reader_init_memory(&reader, pdf,
                                  (const uint8_t *)stream_data, streamlen);
    status = pdf_stream_flatedecode_reader(pdf, obj, params, &reader, fout,
                                           bytes_scanned);
    pdf_stream_reader_destroy(&reader);
    return status;
}

static cl_error_t pdf_stream_rldecode_reader(struct pdf_struct *pdf,
                                             struct pdf_stream_reader *reader,
                                             int fout,
                                             size_t *bytes_scanned)
{
    uint8_t *output_buffer = NULL;
    uint8_t literal[128];
    uint8_t repeated[128];
    size_t decoded               = 0;
    size_t output_buffered       = 0;
    size_t next_deadline_offset  = 0;
    off_t output_start;
    uint64_t reservation_start = 0;
    cl_error_t status           = CL_SUCCESS;

    if (reader == NULL || bytes_scanned == NULL)
        return CL_ENULLARG;
    *bytes_scanned = 0;

    output_start = lseek(fout, 0, SEEK_CUR);
    if (output_start < 0) {
        cli_mark_scan_incomplete(pdf->ctx, "PDF streamed RunLength output position could not be recorded");
        return CL_ESEEK;
    }
    if (pdf->temporary_reserved != NULL)
        reservation_start = *pdf->temporary_reserved;

    output_buffer = (uint8_t *)malloc(INFLATE_CHUNK_SIZE);
    if (output_buffer == NULL) {
        cli_mark_scan_incomplete(pdf->ctx, "PDF streamed RunLength output window could not be allocated");
        return CL_EMEM;
    }

    for (;;) {
        const uint8_t *output;
        size_t output_length;
        uint8_t control;
        bool at_eof;

        status = pdf_stream_reader_check_deadline(
            reader, &next_deadline_offset,
            "PDF streamed RunLength traversal reached the configured time limit");
        if (status != CL_SUCCESS)
            break;

        status = pdf_stream_reader_get_byte(reader, &control, &at_eof);
        if (status != CL_SUCCESS)
            break;
        if (at_eof)
            break;
        if (control < 128) {
            bool complete;

            output_length = (size_t)control + 1U;
            status = pdf_stream_reader_read_exact(reader, literal,
                                                  output_length, &complete);
            if (status != CL_SUCCESS)
                break;
            if (!complete) {
                status = CL_EPARSE;
                break;
            }
            output = literal;
        } else if (control > 128) {
            uint8_t value;

            output_length = (size_t)(257U - control);
            status = pdf_stream_reader_get_byte(reader, &value, &at_eof);
            if (status != CL_SUCCESS)
                break;
            if (at_eof) {
                status = CL_EPARSE;
                break;
            }
            memset(repeated, value, output_length);
            output = repeated;
        } else {
            /* The legacy decoder accepts a complete packet sequence without
             * an end marker and ignores bytes after an observed marker. */
            break;
        }

        status = pdf_stream_output_append(pdf, fout, output_buffer, &output_buffered, &decoded,
                                          output, output_length,
                                          "PDF streamed RunLength output size overflowed",
                                          "PDF streamed RunLength output exceeded configured scan limits");
        if (status != CL_SUCCESS)
            break;
    }

    if (status == CL_SUCCESS)
        status = pdf_stream_output_flush(pdf, fout, output_buffer, &output_buffered, decoded,
                                         "PDF streamed RunLength output exceeded configured scan limits");

    if (status == CL_SUCCESS) {
        cli_dbgmsg("cli_pdf: streamed RunLength decoded %zu bytes from %zu input bytes\n",
                   decoded, reader->length);
        *bytes_scanned = decoded;
        free(output_buffer);
        return decoded == 0 ? CL_BREAK : CL_SUCCESS;
    }

    free(output_buffer);
    {
        cl_error_t rollback_status = pdf_rollback_stream_output(pdf, fout, output_start, reservation_start);
        if (rollback_status != CL_SUCCESS)
            return rollback_status;
    }

    if (status == CL_EPARSE)
        cli_mark_scan_incomplete(pdf->ctx, "PDF RunLength stream ended within an encoded packet");

    return status;
}

static cl_error_t pdf_stream_rldecode(struct pdf_struct *pdf,
                                      const char *stream_data,
                                      size_t streamlen, int fout,
                                      size_t *bytes_scanned)
{
    struct pdf_stream_reader reader;
    cl_error_t status;

    pdf_stream_reader_init_memory(&reader, pdf,
                                  (const uint8_t *)stream_data, streamlen);
    status = pdf_stream_rldecode_reader(pdf, &reader, fout, bytes_scanned);
    pdf_stream_reader_destroy(&reader);
    return status;
}

static cl_error_t pdf_stream_asciihexdecode_reader(
    struct pdf_struct *pdf, struct pdf_obj *obj,
    struct pdf_stream_reader *reader, int fout, size_t *bytes_scanned)
{
    uint8_t *output_buffer = NULL;
    size_t decoded              = 0;
    size_t output_buffered      = 0;
    size_t next_deadline_offset = 0;
    off_t output_start;
    uint64_t reservation_start = 0;
    cl_error_t status           = CL_SUCCESS;
    int high_nibble             = -1;

    if (reader == NULL || bytes_scanned == NULL)
        return CL_ENULLARG;
    *bytes_scanned = 0;

    output_start = lseek(fout, 0, SEEK_CUR);
    if (output_start < 0) {
        cli_mark_scan_incomplete(pdf->ctx, "PDF streamed ASCIIHex output position could not be recorded");
        return CL_ESEEK;
    }
    if (pdf->temporary_reserved != NULL)
        reservation_start = *pdf->temporary_reserved;

    output_buffer = (uint8_t *)malloc(INFLATE_CHUNK_SIZE);
    if (output_buffer == NULL) {
        cli_mark_scan_incomplete(pdf->ctx, "PDF streamed ASCIIHex output window could not be allocated");
        return CL_EMEM;
    }

    for (;;) {
        uint8_t byte;
        int nibble;
        bool at_eof;

        status = pdf_stream_reader_check_deadline(
            reader, &next_deadline_offset,
            "PDF streamed ASCIIHex traversal reached the configured time limit");
        if (status != CL_SUCCESS)
            break;

        status = pdf_stream_reader_get_byte(reader, &byte, &at_eof);
        if (status != CL_SUCCESS)
            break;
        if (at_eof)
            break;
        if (byte == '>')
            break;
        if (pdf_is_whitespace(byte))
            continue;

        nibble = pdf_asciihex_nibble(byte);
        if (nibble < 0) {
            status = CL_EPARSE;
            break;
        }
        if (high_nibble < 0) {
            high_nibble = nibble;
        } else {
            uint8_t output = (uint8_t)((high_nibble << 4) | nibble);

            high_nibble = -1;
            status = pdf_stream_output_append(pdf, fout, output_buffer, &output_buffered, &decoded,
                                              &output, 1U,
                                              "PDF streamed ASCIIHex output size overflowed",
                                              "PDF streamed ASCIIHex output exceeded configured scan limits");
            if (status != CL_SUCCESS)
                break;
        }
    }

    if (status == CL_SUCCESS && high_nibble >= 0) {
        uint8_t output = (uint8_t)(high_nibble << 4);

        status = pdf_stream_output_append(pdf, fout, output_buffer, &output_buffered, &decoded,
                                          &output, 1U,
                                          "PDF streamed ASCIIHex output size overflowed",
                                          "PDF streamed ASCIIHex output exceeded configured scan limits");
    }
    if (status == CL_SUCCESS)
        status = pdf_stream_output_flush(pdf, fout, output_buffer, &output_buffered, decoded,
                                         "PDF streamed ASCIIHex output exceeded configured scan limits");

    if (status == CL_SUCCESS) {
        cli_dbgmsg("cli_pdf: streamed ASCIIHex decoded %zu bytes from %zu input bytes\n",
                   decoded, reader->length);
        *bytes_scanned = decoded;
        free(output_buffer);
        return decoded == 0 ? CL_BREAK : CL_SUCCESS;
    }

    free(output_buffer);
    {
        cl_error_t rollback_status = pdf_rollback_stream_output(pdf, fout, output_start, reservation_start);
        if (rollback_status != CL_SUCCESS)
            return rollback_status;
    }

    if (status == CL_EPARSE) {
        if (!(obj->flags & ((1 << OBJ_IMAGE) | (1 << OBJ_TRUNCATED))))
            pdfobj_flag(pdf, obj, BAD_ASCIIDECODE);
        cli_mark_scan_incomplete(pdf->ctx, "PDF ASCIIHex stream contained an invalid byte");
    }
    return status;
}

static cl_error_t pdf_stream_asciihexdecode(struct pdf_struct *pdf,
                                            struct pdf_obj *obj,
                                            const char *stream_data,
                                            size_t streamlen, int fout,
                                            size_t *bytes_scanned)
{
    struct pdf_stream_reader reader;
    cl_error_t status;

    pdf_stream_reader_init_memory(&reader, pdf,
                                  (const uint8_t *)stream_data, streamlen);
    status = pdf_stream_asciihexdecode_reader(pdf, obj, &reader, fout,
                                              bytes_scanned);
    pdf_stream_reader_destroy(&reader);
    return status;
}

static cl_error_t pdf_stream_ascii85decode_reader(
    struct pdf_struct *pdf, struct pdf_obj *obj,
    struct pdf_stream_reader *reader, int fout, size_t *bytes_scanned)
{
    uint8_t *output_buffer = NULL;
    size_t decoded              = 0;
    size_t output_buffered      = 0;
    size_t next_deadline_offset = 0;
    off_t output_start;
    uint64_t reservation_start = 0;
    uint64_t sum               = 0;
    cl_error_t status          = CL_SUCCESS;
    unsigned int quintet       = 0;
    bool found_eod             = false;

    if (reader == NULL || bytes_scanned == NULL)
        return CL_ENULLARG;
    *bytes_scanned = 0;

    output_start = lseek(fout, 0, SEEK_CUR);
    if (output_start < 0) {
        cli_mark_scan_incomplete(pdf->ctx, "PDF streamed ASCII85 output position could not be recorded");
        return CL_ESEEK;
    }
    if (pdf->temporary_reserved != NULL)
        reservation_start = *pdf->temporary_reserved;

    output_buffer = (uint8_t *)malloc(INFLATE_CHUNK_SIZE);
    if (output_buffer == NULL) {
        cli_mark_scan_incomplete(pdf->ctx, "PDF streamed ASCII85 output window could not be allocated");
        return CL_EMEM;
    }

    for (;;) {
        uint8_t byte;
        bool at_eof;

        status = pdf_stream_reader_check_deadline(
            reader, &next_deadline_offset,
            "PDF streamed ASCII85 traversal reached the configured time limit");
        if (status != CL_SUCCESS)
            break;

        status = pdf_stream_reader_get_byte(reader, &byte, &at_eof);
        if (status != CL_SUCCESS)
            break;
        if (at_eof)
            break;
        if (byte == '~') {
            uint8_t partial[4];
            uint8_t marker;
            unsigned int i;

            status = pdf_stream_reader_get_byte(reader, &marker, &at_eof);
            if (status != CL_SUCCESS)
                break;
            if (at_eof || marker != '>') {
                status = CL_EPARSE;
                break;
            }
            found_eod = true;
            if (quintet == 1U) {
                status = CL_EPARSE;
                break;
            }
            for (i = quintet; i < 5U; i++)
                sum *= 85U;
            if (quintet > 1U)
                sum += UINT64_C(0xFFFFFF) >> ((quintet - 2U) * 8U);
            if (sum > UINT32_MAX) {
                status = CL_EPARSE;
                break;
            }
            for (i = 0; i + 1U < quintet; i++)
                partial[i] = (uint8_t)((sum >> (24U - 8U * i)) & 0xffU);
            if (quintet > 1U) {
                status = pdf_stream_output_append(pdf, fout, output_buffer, &output_buffered, &decoded,
                                                  partial, quintet - 1U,
                                                  "PDF streamed ASCII85 output size overflowed",
                                                  "PDF streamed ASCII85 output exceeded configured scan limits");
            }
            break;
        }

        if (byte >= '!' && byte <= 'u') {
            sum = (sum * 85U) + ((uint32_t)byte - '!');
            quintet++;
            if (quintet == 5U) {
                uint8_t output[4];

                if (sum > UINT32_MAX) {
                    status = CL_EPARSE;
                    break;
                }
                output[0] = (uint8_t)(sum >> 24U);
                output[1] = (uint8_t)((sum >> 16U) & 0xffU);
                output[2] = (uint8_t)((sum >> 8U) & 0xffU);
                output[3] = (uint8_t)(sum & 0xffU);
                status    = pdf_stream_output_append(pdf, fout, output_buffer, &output_buffered, &decoded,
                                                     output, sizeof(output),
                                                     "PDF streamed ASCII85 output size overflowed",
                                                     "PDF streamed ASCII85 output exceeded configured scan limits");
                if (status != CL_SUCCESS)
                    break;
                quintet = 0;
                sum     = 0;
            }
        } else if (byte == 'z') {
            static const uint8_t zeros[4] = {0};

            if (quintet != 0U) {
                status = CL_EPARSE;
                break;
            }
            status = pdf_stream_output_append(pdf, fout, output_buffer, &output_buffered, &decoded,
                                              zeros, sizeof(zeros),
                                              "PDF streamed ASCII85 output size overflowed",
                                              "PDF streamed ASCII85 output exceeded configured scan limits");
            if (status != CL_SUCCESS)
                break;
        } else if (!pdf_is_whitespace(byte)) {
            status = CL_EPARSE;
            break;
        }
    }

    if (!found_eod && status == CL_SUCCESS)
        cli_dbgmsg("cli_pdf: streamed ASCII85 input has no EOF marker\n");
    if (status == CL_SUCCESS)
        status = pdf_stream_output_flush(pdf, fout, output_buffer, &output_buffered, decoded,
                                         "PDF streamed ASCII85 output exceeded configured scan limits");

    if (status == CL_SUCCESS) {
        cli_dbgmsg("cli_pdf: streamed ASCII85 decoded %zu bytes from %zu input bytes\n",
                   decoded, reader->length);
        *bytes_scanned = decoded;
        free(output_buffer);
        return decoded == 0 ? CL_BREAK : CL_SUCCESS;
    }

    free(output_buffer);
    {
        cl_error_t rollback_status = pdf_rollback_stream_output(pdf, fout, output_start, reservation_start);
        if (rollback_status != CL_SUCCESS)
            return rollback_status;
    }

    if (status == CL_EPARSE) {
        if (!(obj->flags & ((1 << OBJ_IMAGE) | (1 << OBJ_TRUNCATED))))
            pdfobj_flag(pdf, obj, BAD_ASCIIDECODE);
        cli_mark_scan_incomplete(pdf->ctx, "PDF ASCII85 stream contained an invalid group");
    }
    return status;
}

static cl_error_t pdf_stream_ascii85decode(struct pdf_struct *pdf,
                                           struct pdf_obj *obj,
                                           const char *stream_data,
                                           size_t streamlen, int fout,
                                           size_t *bytes_scanned)
{
    struct pdf_stream_reader reader;
    cl_error_t status;

    pdf_stream_reader_init_memory(&reader, pdf,
                                  (const uint8_t *)stream_data, streamlen);
    status = pdf_stream_ascii85decode_reader(pdf, obj, &reader, fout,
                                             bytes_scanned);
    pdf_stream_reader_destroy(&reader);
    return status;
}

static cl_error_t pdf_lzw_parameters(struct pdf_struct *pdf, struct pdf_dict *params,
                                     int *early_change)
{
    struct pdf_dict_node *node;
    cl_error_t status;

    if (early_change == NULL)
        return CL_ENULLARG;
    *early_change = 1;

    status = pdf_require_identity_predictor(pdf, params);
    if (status != CL_SUCCESS)
        return status;
    if (params == NULL)
        return CL_SUCCESS;

    node = params->nodes;
    while (node != NULL) {
        long parsed;

        if (pdf_checktimelimit(pdf, "PDF LZW-parameter traversal reached the configured time limit") != CL_SUCCESS)
            return CL_ETIMEOUT;
        if (node->key == NULL || strcmp(node->key, "/EarlyChange") != 0) {
            node = node->next;
            continue;
        }

        status = pdf_decodeparms_integer(pdf, node, &parsed);
        if (status != CL_SUCCESS)
            return status;
        cli_dbgmsg("cli_pdf: EarlyChange: %ld\n", parsed);
        if (parsed != 0 && parsed != 1) {
            cli_mark_scan_incomplete(pdf->ctx, "PDF LZW EarlyChange parameter is outside its defined range");
            return CL_EPARSE;
        }
        *early_change = (int)parsed;
        node = node->next;
    }
    return CL_SUCCESS;
}

static cl_error_t pdf_lzw_stream_attempt(struct pdf_struct *pdf,
                                         struct pdf_stream_reader *reader,
                                         int early_change, int fout,
                                         size_t *decoded_length,
                                         int *decode_status)
{
    uint8_t *output_buffer = NULL;
    lzw_stream stream;
    size_t decoded         = 0;
    size_t output_buffered = 0;
    cl_error_t status      = CL_SUCCESS;
    int lzwstat            = LZW_OK;
    bool initialized       = false;

    if (reader == NULL || decoded_length == NULL || decode_status == NULL)
        return CL_ENULLARG;
    *decoded_length = 0;
    *decode_status  = LZW_OK;

    output_buffer = (uint8_t *)malloc(INFLATE_CHUNK_SIZE);
    if (output_buffer == NULL) {
        cli_mark_scan_incomplete(pdf->ctx, "PDF streamed LZW output window could not be allocated");
        return CL_EMEM;
    }

    memset(&stream, 0, sizeof(stream));
    stream.next_out  = output_buffer;
    stream.avail_out = INFLATE_CHUNK_SIZE;
    if (early_change)
        stream.flags |= LZW_FLAG_EARLYCHG;

    lzwstat = lzwInit(&stream);
    if (lzwstat != LZW_OK) {
        cli_mark_scan_incomplete(pdf->ctx, "PDF streamed LZW decoder could not be initialized");
        status = CL_EMEM;
        goto done;
    }
    initialized = true;

    for (;;) {
        unsigned int input_before;
        unsigned int output_before;
        size_t produced;

        status = pdf_checktimelimit(pdf, "PDF streamed LZW traversal reached the configured time limit");
        if (status != CL_SUCCESS)
            break;

        if (stream.avail_in == 0) {
            const uint8_t *input;
            size_t input_length;

            status = pdf_stream_reader_next_chunk(reader, &input, &input_length);
            if (status != CL_SUCCESS)
                break;
            if (input_length != 0) {
                stream.next_in  = (uint8_t *)input;
                stream.avail_in = (unsigned int)input_length;
            }
        }

        if (stream.avail_out == 0) {
            status = pdf_stream_output_flush(pdf, fout, output_buffer, &output_buffered,
                                             decoded,
                                             "PDF streamed LZW output exceeded configured scan limits");
            if (status != CL_SUCCESS)
                break;
            stream.next_out  = output_buffer;
            stream.avail_out = INFLATE_CHUNK_SIZE;
        }

        input_before  = stream.avail_in;
        output_before = stream.avail_out;
        lzwstat       = lzwInflate(&stream);
        produced      = (size_t)(output_before - stream.avail_out);

        if (decoded > SIZE_MAX - produced || decoded > UINT64_MAX - produced) {
            cli_mark_scan_incomplete(pdf->ctx, "PDF streamed LZW output size overflowed");
            status = CL_ERESOURCE;
            break;
        }
        decoded += produced;
        output_buffered += produced;

        if (lzwstat == LZW_STREAM_END) {
            status = pdf_stream_output_flush(pdf, fout, output_buffer, &output_buffered,
                                             decoded,
                                             "PDF streamed LZW output exceeded configured scan limits");
            break;
        }

        if (lzwstat == LZW_OK) {
            if (input_before == stream.avail_in && output_before == stream.avail_out) {
                status = CL_EPARSE;
                break;
            }
            if (stream.avail_out == 0 ||
                (stream.avail_in == 0 &&
                 reader->source_offset < reader->length))
                continue;
            if (stream.avail_in == 0 &&
                reader->source_offset == reader->length) {
                status = CL_EPARSE;
                break;
            }
            continue;
        }

        if (lzwstat == LZW_MEM_ERROR) {
            cli_mark_scan_incomplete(pdf->ctx, "PDF streamed LZW decoder exhausted memory");
            status = CL_EMEM;
        } else {
            status = CL_EPARSE;
        }
        break;
    }

done:
    *decoded_length = decoded;
    *decode_status  = lzwstat;
    if (initialized)
        (void)lzwInflateEnd(&stream);
    free(output_buffer);
    return status;
}

static cl_error_t pdf_stream_lzwdecode_reader(struct pdf_struct *pdf,
                                              struct pdf_obj *obj,
                                              struct pdf_dict *params,
                                              struct pdf_stream_reader *reader,
                                              int fout,
                                              size_t *bytes_scanned)
{
    size_t decoded       = 0;
    size_t payload_start = 0;
    off_t output_start;
    uint64_t reservation_start = 0;
    cl_error_t status;
    int early_change = 1;
    int lzwstat      = LZW_OK;
    uint8_t first;
    bool at_eof;

    if (reader == NULL || bytes_scanned == NULL)
        return CL_ENULLARG;
    *bytes_scanned = 0;

    if (pdf->ctx != NULL && pdf->ctx->dconf != NULL &&
        !(pdf->ctx->dconf->other & OTHER_CONF_LZW)) {
        cli_mark_scan_incomplete(pdf->ctx,
                                 "PDF LZW decoding is disabled and the stream was not inspected");
        return CL_EPARSE;
    }

    status = pdf_lzw_parameters(pdf, params, &early_change);
    if (status != CL_SUCCESS)
        return status;

    output_start = lseek(fout, 0, SEEK_CUR);
    if (output_start < 0) {
        cli_mark_scan_incomplete(pdf->ctx, "PDF streamed LZW output position could not be recorded");
        return CL_ESEEK;
    }
    if (pdf->temporary_reserved != NULL)
        reservation_start = *pdf->temporary_reserved;

    status = pdf_stream_reader_get_byte(reader, &first, &at_eof);
    if (status != CL_SUCCESS)
        goto rollback;
    if (at_eof) {
        cli_mark_scan_incomplete(pdf->ctx, "PDF LZW stream has no compressed payload");
        status = CL_EPARSE;
        goto rollback;
    }
    if (first == '\r') {
        payload_start = 1;
        pdfobj_flag(pdf, obj, BAD_STREAMSTART);
        if (payload_start == reader->length) {
            cli_dbgmsg("cli_pdf: LZW stream has no compressed payload after its leading carriage return\n");
            cli_mark_scan_incomplete(pdf->ctx, "PDF LZW stream has no compressed payload");
            status = CL_EPARSE;
            goto rollback;
        }
    } else {
        status = pdf_stream_reader_reset(reader, 0);
        if (status != CL_SUCCESS)
            goto rollback;
    }

    status = pdf_lzw_stream_attempt(pdf, reader, early_change, fout,
                                    &decoded, &lzwstat);
    if (status == CL_EPARSE && decoded == 0) {
        size_t resynchronized;

        status = pdf_stream_reader_find_next_line(reader, payload_start,
                                                  &resynchronized);
        if (status != CL_SUCCESS)
            goto rollback;

        if (resynchronized > payload_start &&
            resynchronized < reader->length) {
            status = pdf_stream_reader_reset(reader, resynchronized);
            if (status != CL_SUCCESS)
                goto rollback;
            decoded = 0;
            pdfobj_flag(pdf, obj, BAD_FLATESTART);
            status = pdf_lzw_stream_attempt(pdf, reader, early_change, fout,
                                            &decoded, &lzwstat);
        }
    }

    if (status == CL_SUCCESS) {
        cli_dbgmsg("cli_pdf: streamed LZW decoded %zu bytes from %zu input bytes\n",
                   decoded, reader->length);
        *bytes_scanned = decoded;
        return decoded == 0 ? CL_BREAK : CL_SUCCESS;
    }

rollback:
    {
        cl_error_t rollback_status = pdf_rollback_stream_output(pdf, fout, output_start, reservation_start);
        if (rollback_status != CL_SUCCESS)
            return rollback_status;
    }

    if (status == CL_EPARSE) {
        if (decoded == 0) {
            pdfobj_flag(pdf, obj, BAD_FLATESTART);
        } else {
            pdfobj_flag(pdf, obj, BAD_FLATE);
        }
        if (lzwstat == LZW_OK) {
            cli_mark_scan_incomplete(pdf->ctx, "PDF LZW stream did not reach the decoder end state");
        } else {
            cli_mark_scan_incomplete(pdf->ctx, "PDF LZW decoder failed before the stream completed");
        }
    }
    return status;
}

static cl_error_t pdf_stream_lzwdecode(struct pdf_struct *pdf,
                                       struct pdf_obj *obj,
                                       struct pdf_dict *params,
                                       const char *stream_data,
                                       size_t streamlen, int fout,
                                       size_t *bytes_scanned)
{
    struct pdf_stream_reader reader;
    cl_error_t status;

    pdf_stream_reader_init_memory(&reader, pdf,
                                  (const uint8_t *)stream_data, streamlen);
    status = pdf_stream_lzwdecode_reader(pdf, obj, params, &reader, fout,
                                         bytes_scanned);
    pdf_stream_reader_destroy(&reader);
    return status;
}

static cl_error_t filter_flatedecode(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdf_dict *params, struct pdf_token *token)
{
    uint8_t *decoded, *temp;
    size_t declen = 0, capacity = 0;

    uint8_t *content = (uint8_t *)token->content;
    uint32_t length  = token->length;
    z_stream stream;
    int zstat, rc = CL_SUCCESS;

    rc = pdf_require_identity_predictor(pdf, params);
    if (rc != CL_SUCCESS)
        return rc;

    if (*content == '\r') {
        content++;
        length--;
        pdfobj_flag(pdf, obj, BAD_STREAMSTART);
        /* PDF spec says stream is followed by \r\n or \n, but not \r alone.
         * Sample 0015315109, it has \r followed by zlib header.
         * Flag pdf as suspicious, and attempt to extract by skipping the \r.
         */
        if (!length) {
            cli_dbgmsg("cli_pdf: Flate stream has no compressed payload after its leading carriage return\n");
            return CL_EFORMAT;
        }
    }

    capacity = INFLATE_CHUNK_SIZE;

    if (!(decoded = (uint8_t *)malloc(capacity))) {
        cli_errmsg("cli_pdf: cannot allocate memory for decoded output\n");
        cli_mark_scan_incomplete(pdf->ctx, "PDF Flate decoded output could not be allocated");
        return CL_EMEM;
    }

    memset(&stream, 0, sizeof(stream));
    stream.next_in   = (Bytef *)content;
    stream.avail_in  = length;
    stream.next_out  = (Bytef *)decoded;
    stream.avail_out = INFLATE_CHUNK_SIZE;

    zstat = inflateInit(&stream);
    if (zstat != Z_OK) {
        cli_warnmsg("cli_pdf: inflateInit failed\n");
        cli_mark_scan_incomplete(pdf->ctx, "PDF Flate decoder could not be initialized");
        free(decoded);
        return CL_EMEM;
    }

    if (pdf_checktimelimit(pdf, "PDF Flate traversal reached the configured time limit") != CL_SUCCESS) {
        rc = CL_ETIMEOUT;
        (void)inflateEnd(&stream);
        free(decoded);
        return rc;
    }

    /* initial inflate */
    zstat = inflate(&stream, Z_NO_FLUSH);
    /* check if nothing written whatsoever */
    if ((zstat != Z_OK) && (stream.avail_out == INFLATE_CHUNK_SIZE)) {
        /* skip till EOL, and try inflating from there, sometimes
         * PDFs contain extra whitespace */
        uint8_t *q = decode_nextlinestart(pdf, content, length);
        if (pdf->ctx && pdf->ctx->scan_timed_out) {
            (void)inflateEnd(&stream);
            free(decoded);
            return CL_ETIMEOUT;
        }
        if (q) {
            (void)inflateEnd(&stream);
            length -= q - content;
            content = q;

            stream.next_in   = (Bytef *)content;
            stream.avail_in  = length;
            stream.next_out  = (Bytef *)decoded;
            stream.avail_out = capacity;

            zstat = inflateInit(&stream);
            if (zstat != Z_OK) {
                cli_warnmsg("cli_pdf: inflateInit failed\n");
                cli_mark_scan_incomplete(pdf->ctx, "PDF Flate decoder could not be initialized");
                free(decoded);
                return CL_EMEM;
            }

            pdfobj_flag(pdf, obj, BAD_FLATESTART);
        }

        zstat = inflate(&stream, Z_NO_FLUSH);
    }

    while (zstat == Z_OK && stream.avail_in) {
        if (pdf_checktimelimit(pdf, "PDF Flate traversal reached the configured time limit") != CL_SUCCESS) {
            rc = CL_ETIMEOUT;
            break;
        }
        /* extend output capacity if needed,*/
        if (stream.avail_out == 0) {
            if ((rc = pdf_decoder_capacity_check(pdf->ctx, capacity)) != CL_SUCCESS)
                break;
            if ((rc = cli_checklimits("pdf", pdf->ctx, capacity + INFLATE_CHUNK_SIZE, 0, 0)) != CL_SUCCESS) {
                cli_dbgmsg("cli_pdf: required buffer size to inflate compressed filter exceeds maximum: %u\n", capacity + INFLATE_CHUNK_SIZE);
                break;
            }

            if (!(temp = cli_max_realloc(decoded, capacity + INFLATE_CHUNK_SIZE))) {
                cli_errmsg("cli_pdf: cannot reallocate memory for decoded output\n");
                cli_mark_scan_incomplete(pdf->ctx, "PDF Flate decoded output could not be grown");
                rc = CL_EMEM;
                break;
            }
            decoded          = temp;
            stream.next_out  = decoded + capacity;
            stream.avail_out = INFLATE_CHUNK_SIZE;
            declen += INFLATE_CHUNK_SIZE;
            capacity += INFLATE_CHUNK_SIZE;
        }

        /* continue inflation */
        zstat = inflate(&stream, Z_NO_FLUSH);
    }

    /* add stream end fragment to decoded length */
    declen += (INFLATE_CHUNK_SIZE - stream.avail_out);

    /* error handling */
    switch (zstat) {
        case Z_STREAM_END:
            cli_dbgmsg("cli_pdf: inflated %zu bytes from %zu total bytes (%u bytes remaining)\n",
                       declen, token->length, stream.avail_in);
            break;

        case Z_OK:
            cli_dbgmsg("cli_pdf: input ended before the Flate stream reached Z_STREAM_END\n");
            cli_mark_scan_incomplete(pdf->ctx, "PDF Flate stream did not reach the decoder end state");
            if (rc == CL_SUCCESS)
                rc = CL_EPARSE;
            break;

        /* potentially fatal - *mostly* ignored as per older version */
        case Z_STREAM_ERROR:
        case Z_NEED_DICT:
        case Z_DATA_ERROR:
        case Z_MEM_ERROR:
        default:
            if (stream.msg)
                cli_dbgmsg("cli_pdf: after writing %zu bytes, got error \"%s\" inflating PDF stream in %u %u obj\n",
                           declen, stream.msg, obj->id >> 8, obj->id & 0xff);
            else
                cli_dbgmsg("cli_pdf: after writing %zu bytes, got error %d inflating PDF stream in %u %u obj\n",
                           declen, zstat, obj->id >> 8, obj->id & 0xff);

            cli_mark_scan_incomplete(pdf->ctx, "PDF Flate decoder failed before the stream completed");
            if (declen == 0) {
                pdfobj_flag(pdf, obj, BAD_FLATESTART);
                cli_dbgmsg("cli_pdf: no bytes were inflated.\n");

                if (rc == CL_SUCCESS)
                    rc = CL_EFORMAT;
            } else {
                pdfobj_flag(pdf, obj, BAD_FLATE);
                if (rc == CL_SUCCESS)
                    rc = CL_EFORMAT;
            }
            break;
    }

    (void)inflateEnd(&stream);

    if (declen > (size_t)UINT32_MAX) {
        cli_mark_scan_incomplete(pdf->ctx, "PDF Flate decoder output exceeds the 32-bit decoder boundary");
        rc = CL_ERESOURCE;
    }

    if (rc == CL_SUCCESS) {
        if (declen == 0) {
            cli_dbgmsg("cli_pdf: empty stream after inflation completed.\n");
            rc = CL_BREAK;
        } else if (!(temp = cli_max_realloc(decoded, declen))) {
            /* Shrink output buffer to final the decoded data length to minimize RAM usage */
            cli_errmsg("cli_pdf: cannot reallocate memory for decoded output\n");
            cli_mark_scan_incomplete(pdf->ctx, "PDF Flate decoded output could not be resized");
            rc = CL_EMEM;
        } else {
            decoded = temp;
        }
    }

    if (rc == CL_SUCCESS || rc == CL_BREAK) {
        free(token->content);

        token->content = decoded;
        token->length  = declen;
    } else {
        cli_dbgmsg("cli_pdf: error occurred parsing byte %zu of %zu\n",
                   (size_t)length - stream.avail_in, token->length);
        free(decoded);
    }

    return rc;
}

static cl_error_t filter_asciihexdecode(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdf_token *token)
{
    uint8_t *decoded;

    const uint8_t *content = (uint8_t *)token->content;
    size_t length          = token->length;
    size_t i, j;
    cl_error_t rc = CL_SUCCESS;

    if (!(decoded = (uint8_t *)cli_max_calloc(length / 2 + 1, sizeof(uint8_t)))) {
        cli_errmsg("cli_pdf: cannot allocate memory for decoded output\n");
        cli_mark_scan_incomplete(pdf->ctx, "PDF ASCIIHex decoded output could not be allocated");
        return CL_EMEM;
    }

    for (i = 0, j = 0; i + 1 < length; i++) {
        if (pdf_checktimelimit(pdf, "PDF ASCIIHex traversal reached the configured time limit") != CL_SUCCESS) {
            rc = CL_ETIMEOUT;
            break;
        }
        if (content[i] == ' ')
            continue;

        if (content[i] == '>')
            break;

        if (cli_hex2str_to((const char *)content + i, (char *)decoded + j, 2) == -1) {
            if (length - i < 4)
                continue;

            rc = CL_EFORMAT;
            break;
        }

        i++;
        j++;
    }

    if (rc == CL_SUCCESS) {
        free(token->content);

        cli_dbgmsg("cli_pdf: deflated %zu bytes from %zu total bytes\n",
                   j, token->length);

        token->content = decoded;
        token->length  = j;
    } else {
        if (!(obj->flags & ((1 << OBJ_IMAGE) | (1 << OBJ_TRUNCATED))))
            pdfobj_flag(pdf, obj, BAD_ASCIIDECODE);

        cli_dbgmsg("cli_pdf: error occurred parsing byte %zu of %zu\n",
                   i, token->length);
        free(decoded);
    }
    return rc;
}

/* modes: 0 = use default/DecodeParms, 1 = use document setting */
static cl_error_t filter_decrypt(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdf_dict *params, struct pdf_token *token, int mode)
{
    char *decrypted;
    size_t length       = (size_t)token->length;
    enum enc_method enc = ENC_IDENTITY;

    if (mode)
        enc = get_enc_method(pdf, obj);
    else if (params) {
        struct pdf_dict_node *node = params->nodes;

        while (node) {
            if (pdf_checktimelimit(pdf, "PDF encryption-parameter traversal reached the configured time limit") != CL_SUCCESS)
                return CL_ETIMEOUT;
            if (node->type == PDF_DICT_STRING) {
                if (!strncmp(node->key, "/Type", 6)) { /* optional field - Type */
                    /* MUST be "CryptFilterDecodeParms" */
                    if (node->value)
                        cli_dbgmsg("cli_pdf: Type: %s\n", (char *)(node->value));
                } else if (!strncmp(node->key, "/Name", 6)) { /* optional field - Name */
                    /* overrides document and default encryption method */
                    if (node->value)
                        cli_dbgmsg("cli_pdf: Name: %s\n", (char *)(node->value));
                    enc = parse_enc_method(pdf->CF, pdf->CF_n, (char *)(node->value), enc);
                }
            }
            node = node->next;
        }
    }

    decrypted = decrypt_any(pdf, obj->id, (const char *)token->content, &length, enc);
    if (!decrypted) {
        cli_dbgmsg("cli_pdf: failed to decrypt stream\n");
        if ((pdf->key == NULL) || (pdf->keylen == 0) ||
            (enc == ENC_NONE) || (enc == ENC_UNKNOWN)) {
            cli_mark_scan_incomplete(pdf->ctx,
                                     "PDF encrypted stream uses unsupported encryption or has no usable key");
        } else {
            cli_mark_scan_incomplete(pdf->ctx, "PDF encrypted stream could not be decrypted completely");
        }
        return CL_EPARSE; /* TODO: what should this value be? CL_SUCCESS would mirror previous behavior */
    }

    cli_dbgmsg("cli_pdf: decrypted %zu bytes from %zu total bytes\n",
               length, token->length);

    free(token->content);
    token->content = (uint8_t *)decrypted;
    token->length  = length;
    return CL_SUCCESS;
}

static cl_error_t filter_lzwdecode(struct pdf_struct *pdf, struct pdf_obj *obj, struct pdf_dict *params, struct pdf_token *token)
{
    uint8_t *decoded = NULL;
    uint8_t *temp    = NULL;
    size_t declen = 0, capacity = 0;

    uint8_t *content = (uint8_t *)token->content;
    uint32_t length  = token->length;
    lzw_stream stream;
    bool stream_initialized = false;
    int echg = 1, lzwstat, rc = CL_SUCCESS;

    if (pdf->ctx && pdf->ctx->dconf && !(pdf->ctx->dconf->other & OTHER_CONF_LZW)) {
        cli_mark_scan_incomplete(pdf->ctx,
                                 "PDF LZW decoding is disabled and the stream was not inspected");
        rc = CL_EPARSE;
        goto done;
    }

    rc = pdf_lzw_parameters(pdf, params, &echg);
    if (rc != CL_SUCCESS)
        goto done;

    if (*content == '\r') {
        content++;
        length--;
        pdfobj_flag(pdf, obj, BAD_STREAMSTART);
        /* PDF spec says stream is followed by \r\n or \n, but not \r alone.
         * Sample 0015315109, it has \r followed by zlib header.
         * Flag pdf as suspicious, and attempt to extract by skipping the \r.
         */
        if (!length) {
            cli_dbgmsg("cli_pdf: LZW stream has no compressed payload after its leading carriage return\n");
            rc = CL_EFORMAT;
            goto done;
        }
    }

    capacity = INFLATE_CHUNK_SIZE;

    if (!(decoded = (uint8_t *)malloc(capacity))) {
        cli_errmsg("cli_pdf: cannot allocate memory for decoded output\n");
        cli_mark_scan_incomplete(pdf->ctx, "PDF LZW decoded output could not be allocated");
        rc = CL_EMEM;
        goto done;
    }
    memset(&stream, 0, sizeof(stream));
    stream.next_in   = content;
    stream.avail_in  = length;
    stream.next_out  = decoded;
    stream.avail_out = INFLATE_CHUNK_SIZE;
    if (echg)
        stream.flags |= LZW_FLAG_EARLYCHG;

    lzwstat = lzwInit(&stream);
    if (lzwstat != Z_OK) {
        cli_warnmsg("cli_pdf: lzwInit failed\n");
        cli_mark_scan_incomplete(pdf->ctx, "PDF LZW decoder could not be initialized");
        rc = CL_EMEM;
        goto done;
    }
    stream_initialized = true;

    if (pdf_checktimelimit(pdf, "PDF LZW traversal reached the configured time limit") != CL_SUCCESS) {
        rc = CL_ETIMEOUT;
        goto done;
    }

    /* initial inflate */
    lzwstat = lzwInflate(&stream);
    /* check if nothing written whatsoever */
    if ((lzwstat != Z_OK) && (stream.avail_out == INFLATE_CHUNK_SIZE)) {
        /* skip till EOL, and try inflating from there, sometimes
         * PDFs contain extra whitespace */
        uint8_t *q = decode_nextlinestart(pdf, content, length);
        if (pdf->ctx && pdf->ctx->scan_timed_out) {
            rc = CL_ETIMEOUT;
            goto done;
        }
        if (q) {
            (void)lzwInflateEnd(&stream);
            stream_initialized = false;
            length -= q - content;
            content = q;

            stream.next_in   = content;
            stream.avail_in  = length;
            stream.next_out  = decoded;
            stream.avail_out = INFLATE_CHUNK_SIZE;

            lzwstat = lzwInit(&stream);
            if (lzwstat != Z_OK) {
                cli_warnmsg("cli_pdf: lzwInit failed\n");
                cli_mark_scan_incomplete(pdf->ctx, "PDF LZW decoder could not be initialized");
                rc = CL_EMEM;
                goto done;
            }
            stream_initialized = true;

            pdfobj_flag(pdf, obj, BAD_FLATESTART);
        }

        lzwstat = lzwInflate(&stream);
    }

    while (lzwstat == Z_OK && stream.avail_in) {
        if (pdf_checktimelimit(pdf, "PDF LZW traversal reached the configured time limit") != CL_SUCCESS) {
            rc = CL_ETIMEOUT;
            break;
        }
        /* extend output capacity if needed,*/
        if (stream.avail_out == 0) {
            if ((rc = pdf_decoder_capacity_check(pdf->ctx, capacity)) != CL_SUCCESS)
                goto done;
            if (declen > SIZE_MAX - INFLATE_CHUNK_SIZE) {
                cli_mark_scan_incomplete(pdf->ctx, "PDF LZW decoder output size overflowed");
                rc = CL_ERESOURCE;
                goto done;
            }
            if ((rc = cli_checklimits("pdf", pdf->ctx, capacity + INFLATE_CHUNK_SIZE, 0, 0)) != CL_SUCCESS) {
                cli_dbgmsg("cli_pdf: required buffer size to inflate compressed filter exceeds maximum: %zu\n", capacity + INFLATE_CHUNK_SIZE);
                break;
            }

            if (!(temp = cli_max_realloc(decoded, capacity + INFLATE_CHUNK_SIZE))) {
                cli_errmsg("cli_pdf: cannot reallocate memory for decoded output\n");
                cli_mark_scan_incomplete(pdf->ctx, "PDF LZW decoded output could not be grown");
                rc = CL_EMEM;
                break;
            }
            decoded          = temp;
            stream.next_out  = decoded + capacity;
            stream.avail_out = INFLATE_CHUNK_SIZE;
            declen += INFLATE_CHUNK_SIZE;
            capacity += INFLATE_CHUNK_SIZE;
        }

        /* continue inflation */
        lzwstat = lzwInflate(&stream);
    }

    if (declen > (UINT32_MAX - (INFLATE_CHUNK_SIZE - stream.avail_out))) {
        cli_mark_scan_incomplete(pdf->ctx, "PDF LZW decoder output exceeds the 32-bit decoder boundary");
        rc = CL_ERESOURCE;
        goto done;
    }

    /* add stream end fragment to decoded length */
    declen += (INFLATE_CHUNK_SIZE - stream.avail_out);

    /* error handling */
    switch (lzwstat) {
        case LZW_STREAM_END:
            cli_dbgmsg("cli_pdf: inflated %zu bytes from %zu total bytes (%u bytes remaining)\n",
                       declen, token->length, stream.avail_in);
            break;

        case LZW_OK:
            cli_dbgmsg("cli_pdf: input ended before the LZW stream reached LZW_STREAM_END\n");
            cli_mark_scan_incomplete(pdf->ctx, "PDF LZW stream did not reach the decoder end state");
            if (rc == CL_SUCCESS)
                rc = CL_EPARSE;
            break;

        /* potentially fatal - *mostly* ignored as per older version */
        case LZW_STREAM_ERROR:
        case LZW_DATA_ERROR:
        case LZW_MEM_ERROR:
        case LZW_BUF_ERROR:
        case LZW_DICT_ERROR:
        default:
            if (stream.msg)
                cli_dbgmsg("cli_pdf: after writing %zu bytes, got error \"%s\" inflating PDF stream in %u %u obj\n",
                           declen, stream.msg, obj->id >> 8, obj->id & 0xff);
            else
                cli_dbgmsg("cli_pdf: after writing %zu bytes, got error %d inflating PDF stream in %u %u obj\n",
                           declen, lzwstat, obj->id >> 8, obj->id & 0xff);

            cli_mark_scan_incomplete(pdf->ctx, "PDF LZW decoder failed before the stream completed");
            if (declen == 0) {
                pdfobj_flag(pdf, obj, BAD_FLATESTART);
                cli_dbgmsg("cli_pdf: no bytes were inflated.\n");

                if (rc == CL_SUCCESS)
                    rc = CL_EFORMAT;
            } else {
                pdfobj_flag(pdf, obj, BAD_FLATE);
                if (rc == CL_SUCCESS)
                    rc = CL_EFORMAT;
            }
            break;
    }

done:
    if (stream_initialized) {
        (void)lzwInflateEnd(&stream);
    }

    if (rc == CL_SUCCESS) {
        if (declen == 0) {
            cli_dbgmsg("cli_pdf: empty stream after inflation completed.\n");
            rc = CL_BREAK;
        } else if (!(temp = cli_max_realloc(decoded, declen))) {
            /* Shrink output buffer to final the decoded data length to minimize RAM usage */
            cli_errmsg("cli_pdf: cannot reallocate memory for decoded output\n");
            cli_mark_scan_incomplete(pdf->ctx, "PDF LZW decoded output could not be resized");
            rc = CL_EMEM;
        } else {
            decoded = temp;
        }
    }

    if ((rc == CL_SUCCESS || rc == CL_BREAK) && (NULL != decoded)) {
        free(token->content);

        token->content = decoded;
        token->length  = declen;
    } else {
        cli_dbgmsg("cli_pdf: error occurred parsing byte decoding lzw filter\n");
        if (NULL != decoded) {
            free(decoded);
        }
    }

    /*
       heuristic checks:
       - full dictionary heuristics?
       - invalid code points?
    */

    return rc;
}
