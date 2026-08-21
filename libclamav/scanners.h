/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm
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

#ifndef __SCANNERS_H
#define __SCANNERS_H

#include "clamav.h"
#include "others.h"
#include "filetypes.h"

/**
 * @brief Perform a magic scan of a file given a file descriptor.
 *
 * This API allows you to specify the file type in advance if you know it.
 *
 * @param desc          File descriptor
 * @param filepath      (optional) Full file path.
 * @param ctx           Scanning context structure.
 * @param type          CL_TYPE of data to be scanned.
 * @param name          (optional) Original name of the file (to set fmap name metadata)
 * @param attributes    Layer attributes of the file being scanned (is it normalized, decrypted, etc)
 * @return cl_error_t
 */
cl_error_t cli_magic_scan_desc_type(int desc, const char *filepath, cli_ctx *ctx, cli_file_t type,
                                    const char *name, uint32_t attributes);

/**
 * @brief Scan a descriptor whose temporary-space reservation is owned by the caller.
 *
 * The caller must reserve the complete output size with
 * cli_scan_reserve_temporary() before writing the descriptor and must keep
 * that reservation until this function returns. This is used by streaming
 * decoder adapters that spool output incrementally.
 */
cl_error_t cli_magic_scan_desc_type_reserved(int desc, const char *filepath, cli_ctx *ctx, cli_file_t type,
                                             const char *name, uint32_t attributes);

/**
 * @brief Scan a descriptor while accounting for caller-owned staged bytes.
 *
 * The reservation remains charged to the scan's temporary-space budget for
 * the duration of the scan. This is used by clamd after INSTREAM has staged
 * the source on disk, so parser spools and the staged source share the same
 * MaxTemporarySize ceiling.
 */
cl_error_t cli_scandesc_ex2_with_temporary_bytes(
    int desc,
    const char *filename,
    cl_verdict_t *verdict_out,
    const char **last_alert_out,
    uint64_t *scanned_out,
    const struct cl_engine *engine,
    struct cl_scan_options *scanoptions,
    void *context,
    const char *hash_hint,
    char **hash_out,
    const char *hash_alg,
    const char *file_type_hint,
    char **file_type_out,
    uint64_t temporary_bytes_reserved,
    cl_scan_report_t **report_out);

/**
 * @brief Scan a tempfile / sub-file of _any_ type, passing in the fd, filepath (if available), and the scanning context.
 *
 * @param desc          File descriptor
 * @param filepath      (optional) Full file path.
 * @param ctx           Scanning context structure.
 * @param name          (optional) Original name of the file (to set fmap name metadata)
 * @param attributes    Layer attributes of the file being scanned (is it normalized, decrypted, etc)
 * @return int          CL_SUCCESS, or an error code.
 */
cl_error_t cli_magic_scan_desc(int desc, const char *filepath, cli_ctx *ctx,
                               const char *name, uint32_t attributes);

/**
 * @brief Perform a magic scan on the current ctx.
 *
 * Calls to cli_magic_scan() should be wrapped with a cli_recursion_stack_push/pop, except in scan_common()
 *
 * @param ctx           Scanning context structure.
 * @param type          CL_TYPE of data to be scanned.
 * @return int          CL_SUCCESS, or an error code.
 */
cl_error_t cli_magic_scan(cli_ctx *ctx, cli_file_t type);

/**
 * @brief Scan the current fmap for configured structured-data heuristics.
 *
 * A backing-map read failure is incomplete rather than a clean result.
 */
cl_error_t cli_scan_structured(cli_ctx *ctx);

/**
 * Apply the central scan-result policy. Sticky timeout or incomplete state
 * must remain non-clean, while detections and critical failures retain
 * precedence. A visible AlertExceedsMax indicator represents a configured
 * limit as a detection instead of an error.
 */
bool cli_scan_result_should_halt(cli_ctx *ctx, cl_error_t result_in, cl_error_t *result_out);

/**
 * @brief   Preserve a prior parser result while merging sequential passes.
 */
cl_error_t cli_merge_scan_status(cl_error_t prior, cl_error_t current);

/**
 * @brief   Scan an offset/length into a file map.
 *
 * Useful for scanning files or other type-able data embedded plainly in an existing fmap.
 *
 * Makes use of magic_scan_nested_fmap_type() for map scans when not forced to disk,
 * or if force-to-disk IS enabled, it will write the file to a temp file and then
 * will scan with cli_magic_scan_desc_type().
 *
 * @param map           File map.
 * @param offset        Offset into file map.
 * @param length        Length from offset.
 * @param ctx           Scanning context structure.
 * @param type          CL_TYPE of data to be scanned.
 * @param name          (optional) Original name of the file (to set fmap name metadata)
 * @param attributes    Layer attributes of the file being scanned (is it normalized, decrypted, etc)
 * @return int          CL_SUCCESS, or an error code.
 */
cl_error_t cli_magic_scan_nested_fmap_type(cl_fmap_t *map, size_t offset, size_t length, cli_ctx *ctx,
                                           cli_file_t type, const char *name, uint32_t attributes);

/**
 * @brief   Convenience wrapper for cli_magic_scan_nested_fmap_type().
 *
 * Creates an fmap and calls cli_magic_scan_nested_fmap_type() for you, with type CL_TYPE_ANY.
 *
 * @param buffer        Pointer to the buffer to be scanned.
 * @param length        Size in bytes of the buffer being scanned.
 * @param ctx           Scanning context structure.
 * @param name          (optional) Original name of the file (to set fmap name metadata)
 * @param attributes    Layer attributes of the file being scanned (is it normalized, decrypted, etc)
 * @return int          CL_SUCCESS, or an error code.
 */
cl_error_t cli_magic_scan_buff(const void *buffer, size_t length, cli_ctx *ctx,
                               const char *name, uint32_t attributes);

/**
 * @brief   Internal-use version of cl_scanfile.
 *
 * This function will do a magic scan of an extracted file, given the file path.
 *
 * @param filename      Filepath of the file to be scanned.
 * @param ctx           Scanning context structure.
 * @param original_name (optional) Original name of the file (to set fmap name metadata)
 * @param attributes    Layer attributes of the file being scanned (is it normalized, decrypted, etc)
 * @return cl_error_t
 */
cl_error_t cli_magic_scan_file(const char *filename, cli_ctx *ctx,
                               const char *original_name, uint32_t attributes);

/**
 * @brief   Internal function to recursively scan a directory.
 *
 * This function will do a magic scan of each file in a directory, given the path.
 *
 * @param dirname       Filepath of the directory to be scanned.
 * @param ctx           Scanning context structure.
 * @param attributes    Layer attributes of the file being scanned (is it normalized, decrypted, etc)
 * @return cl_error_t
 */
cl_error_t cli_magic_scan_dir(const char *dirname, cli_ctx *ctx, uint32_t attributes);

/**
 * @brief Mark all scan recursion fmap layers as non-cacheable.
 *
 * This is to prevent libclamav from regurgitating the scan result for something that wasn't fully scanned.
 *
 * @param ctx   The scanning context.
 */
void emax_reached(cli_ctx *ctx);

/**
 * @brief Mark the current scan incomplete and preserve its first failure reason.
 *
 * @param ctx    Scan context.
 * @param reason Static or otherwise context-lifetime-safe reason string.
 */
void cli_mark_scan_incomplete(cli_ctx *ctx, const char *reason);

#endif
