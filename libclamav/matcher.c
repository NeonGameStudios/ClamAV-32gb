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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdbool.h>

#include "clamav.h"
#include "clamav_rust.h"
#include "others.h"
#include "matcher-ac.h"
#include "matcher-bm.h"
#include "matcher-pcre.h"
#include "filetypes.h"
#include "matcher.h"
#include "pe.h"
#include "elf.h"
#include "execs.h"
#include "special.h"
#include "scanners.h"
#include "str.h"
#include "default.h"
#include "macho.h"
#include "readdb.h"
#include "fmap.h"
#include "pe_icons.h"
#include "regex/regex.h"
#include "filtering.h"
#include "perflogging.h"
#include "bytecode_priv.h"
#include "bytecode_api_impl.h"
#ifdef HAVE_YARA
#include "yara_clam.h"
#include "yara_exec.h"
#endif

#ifdef CLI_PERF_LOGGING

static inline void perf_log_filter(int32_t pos, int32_t length, int8_t trie)
{
    cli_perf_log_add(RAW_BYTES_SCANNED, length);
    cli_perf_log_add(FILTER_BYTES_SCANNED, length - pos);
    cli_perf_log_count2(TRIE_SCANNED, trie, length - pos);
}

static inline int perf_log_tries(int8_t acmode, int8_t bm_called, int32_t length)
{
    if (bm_called)
        cli_perf_log_add(BM_SCANNED, length);
    if (acmode)
        cli_perf_log_add(AC_SCANNED, length);
    return 0;
}

#else
static inline void perf_log_filter(int32_t pos, uint32_t length, int8_t trie)
{
    UNUSEDPARAM(pos);
    UNUSEDPARAM(length);
    UNUSEDPARAM(trie);
}

static inline int perf_log_tries(int8_t acmode, int8_t bm_called, int32_t length)
{
    UNUSEDPARAM(acmode);
    UNUSEDPARAM(bm_called);
    UNUSEDPARAM(length);

    return 0;
}
#endif

cl_error_t cli_pcre_check_size_limit(cli_ctx *ctx, uint64_t configured_limit, uint64_t needed)
{
    uint64_t effective_limit  = configured_limit;
    uint64_t contiguous_limit = 0;
    int rc                    = CL_ERROR;

    /* PCRE2 consumes one contiguous subject. On qualifying 64-bit fmap builds
     * this can use the large-file ceiling while pages are loaded on demand;
     * other builds retain their bounded single-allocation ceiling. */
    if (effective_limit == 0 || effective_limit > (uint64_t)CLI_MAX_PCRE_CONTIGUOUS_FILESIZE)
        effective_limit = (uint64_t)CLI_MAX_PCRE_CONTIGUOUS_FILESIZE;

    if (NULL != ctx && NULL != ctx->engine) {
        contiguous_limit = (uint64_t)cl_engine_get_num(ctx->engine, CL_ENGINE_MAX_CONTIGUOUS_SIZE, &rc);
        if (rc == CL_SUCCESS && contiguous_limit != 0 && contiguous_limit < effective_limit)
            effective_limit = contiguous_limit;
    }

    if (needed <= effective_limit)
        return CL_SUCCESS;

    cli_dbgmsg("PCRE subject exceeds bounded whole-buffer limit (configured: " STDu64 ", effective: " STDu64 ", needed: " STDu64 ")\n",
               configured_limit, effective_limit, needed);
    cli_mark_scan_incomplete(ctx, "PCRE signatures require an oversized contiguous subject");
    return CL_EMAXSIZE;
}

bool cli_matcher_window_reaches_map_end(uint64_t offset, uint32_t length, size_t map_length)
{
    /* The subtraction is evaluated only when offset is within the map. */
    return (offset >= (uint64_t)map_length) ||
           ((uint64_t)length >= (uint64_t)map_length - offset);
}

static inline cl_error_t matcher_run(const struct cli_matcher *root,
                                     const unsigned char *buffer, uint32_t length,
                                     const char **virname, struct cli_ac_data *mdata,
                                     uint64_t offset,
                                     const struct cli_target_info *tinfo,
                                     cli_file_t ftype,
                                     struct cli_matched_type **ftoffset,
                                     unsigned int acmode,
                                     unsigned int pcremode,
                                     struct cli_ac_result **acres,
                                     fmap_t *map,
                                     struct cli_bm_off *offdata,
                                     struct cli_pcre_off *poffdata,
                                     cli_ctx *ctx)
{
    cl_error_t ret, saved_ret = CL_CLEAN;
    int32_t pos = 0;
    struct filter_match_info info;
    uint32_t orig_length;
    uint64_t orig_offset;
    const unsigned char *orig_buffer;

    if (root->filter) {
        if (filter_search_ext(root->filter, buffer, length, &info) == -1) {
            /*  for safety always scan last maxpatlen bytes */
            if (length > (uint32_t)root->maxpatlen + 1U)
                pos = (int32_t)(length - (uint32_t)root->maxpatlen - 1U);
            perf_log_filter(pos, length, root->type);
        } else {
            /* must not cut buffer for 64[4-4]6161, because we must be able to check
             * 64! */
            if (info.first_match > (unsigned long)root->maxpatlen + 1UL)
                pos = (int32_t)(info.first_match - (unsigned long)root->maxpatlen - 1UL);
            perf_log_filter(pos, length, root->type);
        }
    } else {
        perf_log_filter(0, length, root->type);
    }

    orig_length = length;
    orig_buffer = buffer;
    orig_offset = offset;
    length -= pos;
    buffer += pos;
    offset += pos;
    if (!root->ac_only) {
        perf_log_tries(0, 1, length);
        if (root->bm_offmode) {
            /* Don't use prefiltering for BM offset mode, since BM keeps tracks
             * of offsets itself, and doesn't work if we skip chunks of input
             * data */
            ret = cli_bm_scanbuff(orig_buffer, orig_length, virname, NULL, root, orig_offset, tinfo, offdata, ctx);
        } else {
            ret = cli_bm_scanbuff(buffer, length, virname, NULL, root, offset, tinfo, offdata, ctx);
        }
        if (ret != CL_SUCCESS) {
            if (ret != CL_VIRUS)
                return ret;
            /* else (ret == CL_VIRUS) */

            ret = cli_append_virus(ctx, *virname);
            if (ret != CL_SUCCESS)
                return ret;
        }
    }
    perf_log_tries(acmode, 0, length);
    ret = cli_ac_scanbuff(buffer, length, virname, NULL, acres, root, mdata, offset, ftype, ftoffset, acmode, ctx);
    if (ret != CL_SUCCESS) {
        if (ret == CL_VIRUS) {
            ret = cli_append_virus(ctx, *virname);
            if (ret != CL_SUCCESS)
                return ret;
        } else if (ret > CL_TYPENO && acmode & AC_SCAN_VIR) {
            saved_ret = ret;
        } else {
            return ret;
        }
    }

    if (root->bcomp_metas) {
        ret = cli_bcomp_scanbuf(orig_buffer, orig_length, orig_offset, acres, root, mdata, ctx);
        if (ret != CL_CLEAN) {
            if (ret > CL_TYPENO && acmode & AC_SCAN_VIR) {
                saved_ret = ret;
            } else {
                return ret;
            }
        }
    }

    switch (ftype) {
        case CL_TYPE_GIF:
        case CL_TYPE_TIFF:
        case CL_TYPE_JPEG:
        case CL_TYPE_PNG:
        case CL_TYPE_GRAPHICS: {
            if (ctx->recursion_stack[ctx->recursion_level].calculated_image_fuzzy_hash &&
                !fuzzy_hash_check(root->fuzzy_hashmap, mdata, ctx->recursion_stack[ctx->recursion_level].image_fuzzy_hash)) {
                cli_errmsg("Unexpected error when checking for fuzzy hash matches.\n");
                cli_mark_scan_incomplete(ctx, "image fuzzy hash matcher did not complete");
                return CL_ERROR;
            }
        }
        default:
            break;
    }

    /* due to logical triggered, pcres cannot be evaluated until after full subsig matching */
    /* cannot save pcre execution state without possible evasion; must scan entire buffer */
    /* however, scanning the whole buffer may require the whole buffer being loaded into memory */
    if (root->pcre_metas) {
        int rc;
        uint64_t maxfilesize;

        if (map && (pcremode == PCRE_SCAN_FMAP)) {
            /* Do not add the 64-bit file offset and 32-bit window length
             * before comparing them with the map length. Large-file scans
             * can legitimately carry offsets near UINT64_MAX, and wrapping
             * that addition would skip the required full-subject PCRE pass. */
            const bool scanned_to_map_end = cli_matcher_window_reaches_map_end(offset, length, map->len);

            if (scanned_to_map_end) {
                /* check that scanned map does not exceed pcre maxfilesize limit */
                maxfilesize = (uint64_t)cl_engine_get_num(ctx->engine, CL_ENGINE_PCRE_MAX_FILESIZE, &rc);
                if (rc != CL_SUCCESS)
                    return rc;
                ret = cli_pcre_check_size_limit(ctx, maxfilesize, map->len);
                if (ret != CL_SUCCESS)
                    return ret;

                ret = cli_scan_reserve_contiguous(ctx, map->len);
                if (ret != CL_SUCCESS)
                    return ret;
                ret = cli_checktimelimit(ctx);
                if (ret != CL_SUCCESS) {
                    cli_scan_release_contiguous(ctx, map->len);
                    cli_mark_scan_incomplete(ctx, "PCRE subject mapping reached the configured time limit");
                    return ret;
                }

                cli_dbgmsg("matcher_run: performing regex matching on full map after window at " STDu64 "+%u (map length %zu)\n",
                           offset, length, map->len);

                buffer = fmap_need_off_once(map, 0, map->len);
                if (!buffer) {
                    cli_scan_release_contiguous(ctx, map->len);
                    fmap_release_unlocked(map);
                    cli_mark_scan_incomplete(ctx, "PCRE subject could not be mapped completely");
                    return CL_EREAD;
                }

                /* scan the full buffer */
                ret = cli_pcre_scanbuf(buffer, map->len, virname, acres, root, mdata, poffdata, ctx);
                cli_scan_release_contiguous(ctx, map->len);
                fmap_release_unlocked(map);
            }
        } else if (pcremode == PCRE_SCAN_BUFF) {
            /* check that scanned buffer does not exceed pcre maxfilesize limit */
            maxfilesize = (uint64_t)cl_engine_get_num(ctx->engine, CL_ENGINE_PCRE_MAX_FILESIZE, &rc);
            if (rc != CL_SUCCESS)
                return rc;
            ret = cli_pcre_check_size_limit(ctx, maxfilesize, length);
            if (ret != CL_SUCCESS)
                return ret;

            ret = cli_scan_reserve_contiguous(ctx, length);
            if (ret != CL_SUCCESS)
                return ret;
            ret = cli_checktimelimit(ctx);
            if (ret != CL_SUCCESS) {
                cli_scan_release_contiguous(ctx, length);
                cli_mark_scan_incomplete(ctx, "PCRE subject scan reached the configured time limit");
                return ret;
            }

            cli_dbgmsg("matcher_run: performing regex matching on buffer with no map: " STDu64 "+%u(" STDu64 ")\n", offset, length, offset + length);
            /* scan the specified buffer */
            ret = cli_pcre_scanbuf(buffer, length, virname, acres, root, mdata, poffdata, ctx);
            cli_scan_release_contiguous(ctx, length);
        }
    }

    /* end experimental fragment */

    if (ctx && ret == CL_VIRUS) {
        ret = cli_append_virus(ctx, *virname);
        if (ret != CL_SUCCESS)
            return ret;
    }

    if (saved_ret && ret == CL_CLEAN) {
        return saved_ret;
    }

    return ret;
}

static cl_error_t cli_matcher_reconcile_status(cli_ctx *ctx, cl_error_t status)
{
    if (ctx != NULL && (status == CL_SUCCESS || status == CL_CLEAN) && ctx->scan_incomplete)
        return CL_EPARSE;

    return status;
}

cl_error_t cli_scan_buff(const unsigned char *buffer, uint32_t length, uint64_t offset, cli_ctx *ctx, cli_file_t ftype, struct cli_ac_data **acdata)
{
    cl_error_t ret = CL_CLEAN;
    cl_error_t status = CL_CLEAN;
    cl_error_t current;
    unsigned int i = 0, j = 0;
    struct cli_ac_data matcher_data;
    struct cli_matcher *generic_ac_root, *target_ac_root = NULL;
    bool target_match_ready = false;
    bool generic_match_ready = false;
    const char *virname            = NULL;
    const struct cl_engine *engine;

    if (!ctx) {
        cli_errmsg("cli_scan_buff: context == NULL\n");
        return CL_ENULLARG;
    }
    if (length != 0 && !buffer) {
        cli_errmsg("cli_scan_buff: buffer == NULL for non-empty input\n");
        return CL_ENULLARG;
    }

    engine = ctx->engine;

    if (!engine) {
        cli_errmsg("cli_scan_buff: engine == NULL\n");
        return CL_ENULLARG;
    }

    ret = cli_scan_account_matcher_work(ctx, length);
    if (ret != CL_SUCCESS)
        return ret;

    generic_ac_root = engine->root[0]; /* generic signatures */

    if (ftype != CL_TYPE_ANY) {
        // Identify the target type, to find the matcher root for that target.

        for (i = 1; i < CLI_MTARGETS; i++) {
            for (j = 0; j < cli_mtargets[i].target_count; ++j) {
                if (cli_mtargets[i].target[j] == ftype) {
                    // Identified the target type, now get the matcher root for that target.
                    target_ac_root = ctx->engine->root[i];
                    break; // Break out of inner loop
                }
            }
            if (target_ac_root) break;
        }
    }

    if (target_ac_root) {
        /* If a target-specific specific signature root was found for the given file type, match with it. */

        if (!acdata) {
            // no ac matcher data was provided, so we need to initialize our own.
            current = cli_ac_initdata(&matcher_data, target_ac_root->ac_partsigs, target_ac_root->ac_lsigs,
                                      target_ac_root->ac_reloff_num, CLI_DEFAULT_AC_TRACKLEN);
            if (CL_SUCCESS != current) {
                if (current == CL_EMEM)
                    cli_mark_scan_incomplete(ctx, "AC matcher state could not be allocated");
                status = cli_merge_scan_status(status, current);
                if (cli_scan_status_is_critical(current))
                    return status;
            } else {
                target_match_ready = true;
            }
        } else {
            target_match_ready = true;
        }

        if (target_match_ready) {
            ret = matcher_run(target_ac_root, buffer, length, &virname,
                              acdata ? (acdata[0]) : (&matcher_data),
                              offset, NULL, ftype, NULL, AC_SCAN_VIR, PCRE_SCAN_BUFF, NULL, ctx->fmap, NULL, NULL, ctx);

            if (!acdata) {
                // no longer need our AC local matcher data (if using)
                cli_ac_freedata(&matcher_data);
            }

            /* Preserve matcher failures instead of allowing the generic root to
             * turn a target-root failure into a clean buffer result. A
             * non-critical target-root failure must not suppress the independent
             * generic raw matcher; detections and critical failures still halt. */
            if (ret != CL_SUCCESS && ret < CL_TYPENO) {
                status = cli_merge_scan_status(status, ret);
                if (cli_scan_status_is_critical(ret))
                    return status;
            }
        }

        // reset virname back to NULL for matching with the generic AC root.
        virname = NULL;
    }

    if (generic_ac_root) {
        if (!acdata) {
            // no ac matcher data was provided, so we need to initialize our own.
            current = cli_ac_initdata(&matcher_data, generic_ac_root->ac_partsigs, generic_ac_root->ac_lsigs,
                                      generic_ac_root->ac_reloff_num, CLI_DEFAULT_AC_TRACKLEN);
            if (CL_SUCCESS != current) {
                if (current == CL_EMEM)
                    cli_mark_scan_incomplete(ctx, "AC matcher state could not be allocated");
                status = cli_merge_scan_status(status, current);
                if (cli_scan_status_is_critical(current))
                    return status;
            } else {
                generic_match_ready = true;
            }
        } else {
            generic_match_ready = true;
        }

        if (generic_match_ready) {
            ret = matcher_run(generic_ac_root, buffer, length, &virname,
                              acdata ? (acdata[1]) : (&matcher_data),
                              offset, NULL, ftype, NULL, AC_SCAN_VIR, PCRE_SCAN_BUFF, NULL, ctx->fmap, NULL, NULL, ctx);

            if (!acdata) {
                // no longer need our AC local matcher data (if using)
                cli_ac_freedata(&matcher_data);
            }

            if (ret != CL_SUCCESS && ret < CL_TYPENO)
                status = cli_merge_scan_status(status, ret);
        }
    } else {
        ret = CL_SUCCESS;
    }

    return cli_matcher_reconcile_status(ctx, status);
}

/*
 * offdata[0]: type
 * offdata[1]: offset value
 * offdata[2]: max shift
 * offdata[3]: section number
 */
static int cli_parse_uint64(const char *text, uint64_t *value)
{
    char *end = NULL;
    unsigned long long parsed;
    const unsigned char *cursor;

    if (!text || !*text)
        return 0;

    for (cursor = (const unsigned char *)text; *cursor; cursor++) {
        if (*cursor < '0' || *cursor > '9')
            return 0;
    }

    errno  = 0;
    parsed = strtoull(text, &end, 10);
    if (errno == ERANGE || end == text || *end != '\0')
        return 0;

    *value = (uint64_t)parsed;
    return 1;
}

static uint64_t cli_exe_entrypoint(const struct cli_exe_info *exeinfo)
{
    return exeinfo->has_native_coordinates ? exeinfo->ep64 : exeinfo->ep;
}

static uint64_t cli_exe_section_raw(const struct cli_exe_info *exeinfo, uint16_t section)
{
    if (exeinfo->sections64)
        return exeinfo->sections64[section].raw;
    return exeinfo->sections[section].raw;
}

static uint64_t cli_exe_section_size(const struct cli_exe_info *exeinfo, uint16_t section)
{
    if (exeinfo->sections64)
        return exeinfo->sections64[section].rsz;
    return exeinfo->sections[section].rsz;
}

cl_error_t cli_caloff(const char *offstr, const struct cli_target_info *info, cli_target_t target, uint64_t *offdata, uint64_t *offset_min, uint64_t *offset_max)
{
    char offcpy[65] = {0};
    uint64_t n = 0, val = 0;
    char *pt = NULL;

    if (!info) { /* decode offset string */
        if (!offstr) {
            cli_errmsg("cli_caloff: offstr == NULL\n");
            return CL_ENULLARG;
        }

        if (!strcmp(offstr, "*")) {
            offdata[0] = *offset_max = *offset_min = CLI_OFF_ANY64;
            return CL_SUCCESS;
        }

        if (strlen(offstr) > 64) {
            cli_errmsg("cli_caloff: Offset string too long\n");
            return CL_EMALFDB;
        }
        strcpy(offcpy, offstr);

        if ((pt = strchr(offcpy, ','))) {
            if (!cli_parse_uint64(pt + 1, &val)) {
                cli_errmsg("cli_caloff: Invalid offset shift value\n");
                return CL_EMALFDB;
            }
            offdata[2] = val;
            *pt        = 0;
        } else {
            offdata[2] = 0;
        }

        *offset_max = *offset_min = CLI_OFF_NONE64;

        if (!strncmp(offcpy, "EP+", 3) || !strncmp(offcpy, "EP-", 3)) {
            if (offcpy[2] == '+')
                offdata[0] = CLI_OFF_EP_PLUS;
            else
                offdata[0] = CLI_OFF_EP_MINUS;

            if (!cli_parse_uint64(&offcpy[3], &val)) {
                cli_errmsg("cli_caloff: Invalid offset value\n");
                return CL_EMALFDB;
            }
            offdata[1] = val;

        } else if (offcpy[0] == 'S') {
            if (offcpy[1] == 'E') {
                if (!cli_parse_uint64(&offcpy[2], &n)) {
                    cli_errmsg("cli_caloff: Invalid section number\n");
                    return CL_EMALFDB;
                }
                offdata[0] = CLI_OFF_SE;
                offdata[3] = n;

            } else if (!strncmp(offstr, "SL+", 3)) {
                offdata[0] = CLI_OFF_SL_PLUS;
                if (!cli_parse_uint64(&offcpy[3], &val)) {
                    cli_errmsg("cli_caloff: Invalid offset value\n");
                    return CL_EMALFDB;
                }
                offdata[1] = val;

            } else if (offcpy[1] && strchr(&offcpy[1], '+')) {
                char *plus = strchr(&offcpy[1], '+');
                *plus++    = '\0';
                if (!cli_parse_uint64(&offcpy[1], &n) || !cli_parse_uint64(plus, &val)) {
                    cli_errmsg("cli_caloff: Invalid section offset\n");
                    return CL_EMALFDB;
                }
                offdata[0] = CLI_OFF_SX_PLUS;
                offdata[1] = val;
                offdata[3] = n;
            } else {
                cli_errmsg("cli_caloff: Invalid offset string\n");
                return CL_EMALFDB;
            }

        } else if (!strncmp(offcpy, "EOF-", 4)) {
            offdata[0] = CLI_OFF_EOF_MINUS;
            if (!cli_parse_uint64(&offcpy[4], &val)) {
                cli_errmsg("cli_caloff: Invalid offset value\n");
                return CL_EMALFDB;
            }
            offdata[1] = val;
        } else if (!strncmp(offcpy, "VI", 2)) {
            /* versioninfo */
            offdata[0] = CLI_OFF_VERSION;
        } else if (strchr(offcpy, '$')) {
            size_t offlen = strlen(offcpy);

            if (offcpy[0] != '$' || offlen < 3 || offcpy[offlen - 1] != '$') {
                cli_errmsg("cli_caloff: Invalid macro($) in offset: %s\n", offcpy);
                return CL_EMALFDB;
            }
            offcpy[offlen - 1] = '\0';
            if (!cli_parse_uint64(&offcpy[1], &n)) {
                cli_errmsg("cli_caloff: Invalid macro($) in offset: %s\n", offcpy);
                return CL_EMALFDB;
            }
            if (n >= 32) {
                cli_errmsg("cli_caloff: at most 32 macro groups supported\n");
                return CL_EMALFDB;
            }
            offdata[0] = CLI_OFF_MACRO;
            offdata[1] = n;
        } else {
            offdata[0] = CLI_OFF_ABSOLUTE;
            if (!cli_parse_uint64(offcpy, &val)) {
                cli_errmsg("cli_caloff: Invalid offset value\n");
                return CL_EMALFDB;
            }

            /* CLI_OFF_NONE64 and CLI_OFF_ANY64 are tagged values, not file
             * coordinates. Reject an absolute range that reaches either one;
             * otherwise UINT64_MAX would turn an impossible anchor into a
             * wildcard in the native AC, BM, and PCRE paths. */
            if (val >= CLI_OFF_NONE64 || offdata[2] >= CLI_OFF_NONE64 - val) {
                cli_errmsg("cli_caloff: Absolute offset range collides with a reserved matcher sentinel\n");
                return CL_EMALFDB;
            }

            *offset_min = offdata[1] = val;
            *offset_max              = *offset_min + offdata[2];
        }

        if (offdata[0] != CLI_OFF_ANY64 && offdata[0] != CLI_OFF_ABSOLUTE &&
            offdata[0] != CLI_OFF_EOF_MINUS && offdata[0] != CLI_OFF_MACRO) {
            if (target != TARGET_PE && target != TARGET_ELF && target != TARGET_MACHO) {
                cli_errmsg("cli_caloff: Invalid offset type for target %u\n", target);
                return CL_EMALFDB;
            }
        }

    } else {
        /* calculate relative offsets */
        *offset_min = CLI_OFF_NONE64;
        if (offset_max)
            *offset_max = CLI_OFF_NONE64;
        if (info->status == -1) {
            // If the executable headers weren't parsed successfully then we
            // can't process any ndb/ldb EOF-n/EP+n/EP-n/Sx+n/SEx/SL+n subsigs
            return CL_SUCCESS;
        }

        switch (offdata[0]) {
            case CLI_OFF_EOF_MINUS:
                if (info->fsize < 0 || offdata[1] > (uint64_t)info->fsize)
                    break;
                *offset_min = info->fsize - offdata[1];
                break;

            case CLI_OFF_EP_PLUS:
                if (UINT64_MAX - cli_exe_entrypoint(&info->exeinfo) < offdata[1])
                    break;
                *offset_min = cli_exe_entrypoint(&info->exeinfo) + offdata[1];
                break;

            case CLI_OFF_EP_MINUS:
                if (offdata[1] > cli_exe_entrypoint(&info->exeinfo))
                    break;
                *offset_min = cli_exe_entrypoint(&info->exeinfo) - offdata[1];
                break;

            case CLI_OFF_SL_PLUS:
                if (!info->exeinfo.nsections)
                    break;
                if (UINT64_MAX - cli_exe_section_raw(&info->exeinfo, info->exeinfo.nsections - 1) < offdata[1])
                    break;
                *offset_min = cli_exe_section_raw(&info->exeinfo, info->exeinfo.nsections - 1) + offdata[1];
                break;

            case CLI_OFF_SX_PLUS:
                if (offdata[3] >= info->exeinfo.nsections)
                    *offset_min = CLI_OFF_NONE64;
                else if (UINT64_MAX - cli_exe_section_raw(&info->exeinfo, offdata[3]) < offdata[1])
                    *offset_min = CLI_OFF_NONE64;
                else
                    *offset_min = cli_exe_section_raw(&info->exeinfo, offdata[3]) + offdata[1];
                break;

            case CLI_OFF_SE:
                if (offdata[3] >= info->exeinfo.nsections) {
                    *offset_min = CLI_OFF_NONE64;
                } else {
                    *offset_min = cli_exe_section_raw(&info->exeinfo, offdata[3]);
                    if (offset_max) {
                        if (UINT64_MAX - *offset_min < cli_exe_section_size(&info->exeinfo, offdata[3]) ||
                            UINT64_MAX - (*offset_min + cli_exe_section_size(&info->exeinfo, offdata[3])) < offdata[2])
                            *offset_min = CLI_OFF_NONE64;
                        else
                            *offset_max = *offset_min + cli_exe_section_size(&info->exeinfo, offdata[3]) + offdata[2];
                    }
                    // TODO offdata[2] == MaxShift. Won't this make offset_max
                    // extend beyond the end of the section?  This doesn't seem like
                    // what we want...
                }
                break;

            case CLI_OFF_VERSION:
                if (offset_max)
                    *offset_min = *offset_max = CLI_OFF_ANY64;
                break;
            default:
                cli_errmsg("cli_caloff: Not a relative offset (type: " STDu64 ")\n", offdata[0]);
                return CL_EARG;
        }

        if (offset_max && *offset_max == CLI_OFF_NONE64 && *offset_min != CLI_OFF_NONE64) {
            if (UINT64_MAX - *offset_min < offdata[2])
                *offset_min = CLI_OFF_NONE64;
            else
                *offset_max = *offset_min + offdata[2];
        }
    }

    return CL_SUCCESS;
}

void cli_targetinfo_init(struct cli_target_info *info)
{

    if (NULL == info) {
        return;
    }
    info->status = 0;
    cli_exe_info_init(&(info->exeinfo), 0);
}

void cli_targetinfo(struct cli_target_info *info, cli_target_t target, cli_ctx *ctx)
{
    cl_error_t (*einfo)(cli_ctx *, struct cli_exe_info *) = NULL;
    cl_error_t ret;

    if (info == NULL)
        return;
    if (ctx == NULL || ctx->fmap == NULL) {
        info->status = -1;
        if (ctx != NULL)
            cli_mark_scan_incomplete(ctx, "Executable metadata context is unavailable");
        return;
    }

    info->fsize = ctx->fmap->len;

    switch (target) {
        case TARGET_PE:
            einfo = cli_pe_targetinfo;
            break;
        case TARGET_ELF:
            einfo = cli_elfheader;
            break;
        case TARGET_MACHO:
            /* A universal-binary wrapper has no thin-image entry point or
             * section table of its own.  Its members are scanned as separate
             * thin Mach-O layers and provide their own executable metadata.
             * Treat the wrapper's empty executable metadata as valid instead
             * of feeding the FAT header to the thin-image parser. */
            if (ctx->recursion_stack &&
                cli_recursion_stack_get_type(ctx, -1) == CL_TYPE_MACHO_UNIBIN) {
                info->status = 1;
                return;
            }
            einfo = cli_machoheader;
            break;
        default:
            return;
    }

    ret = einfo(ctx, &info->exeinfo);
    if (CL_SUCCESS != ret) {
        info->status = -1;
        if (ret != CL_VIRUS && ret != CL_VERIFIED)
            cli_mark_scan_incomplete(ctx, "Executable metadata parsing ended before inspection completed");
    } else {
        info->status = 1;
    }
}

void cli_targetinfo_destroy(struct cli_target_info *info)
{

    if (NULL == info) {
        return;
    }

    cli_exe_info_destroy(&(info->exeinfo));
    info->status = 0;
}

static cl_error_t cli_check_fp_trust_layers(cli_ctx *ctx, uint32_t start_layer, const char *source)
{
    cl_error_t ret;

    ret = cli_trust_layers(ctx, start_layer, ctx->recursion_level, source);
    if (CL_SUCCESS != ret) {
        cli_mark_scan_incomplete(ctx, "false-positive trust update failed");
    }

    return ret;
}

cl_error_t cli_check_fp(cli_ctx *ctx, const char *vname)
{
    cl_error_t status = CL_VIRUS;
    cl_error_t ret;

    size_t i;
    const char *virname = NULL;
    fmap_t *map;
    int32_t stack_index;

    uint8_t *hash;
    cli_hash_type_t hash_type;
    char hash_string[SHA256_HASH_SIZE * 2 + 1];

    bool need_hash[CLI_HASH_AVAIL_TYPES] = {false};

    if (!ctx || !ctx->engine || !ctx->recursion_stack ||
        ctx->recursion_stack_size == 0 ||
        ctx->recursion_level >= ctx->recursion_stack_size) {
        cli_errmsg("cli_check_fp: invalid scan context or recursion stack\n");
        return CL_ENULLARG;
    }

    stack_index = (int32_t)ctx->recursion_level;

    char *source = NULL;
    size_t source_len;

    while (stack_index >= 0) {
        map = ctx->recursion_stack[stack_index].fmap;

        if (!map) {
            cli_errmsg("cli_check_fp: fmap is unavailable for a recursion layer\n");
            cli_mark_scan_incomplete(ctx, "false-positive hash layer fmap is unavailable");
            status = CL_EPARSE;
            goto done;
        }

        need_hash[CLI_HASH_MD5] = cli_hm_have_size(ctx->engine->hm_fp, CLI_HASH_MD5, map->len) ||
                                  cli_hm_have_wild(ctx->engine->hm_fp, CLI_HASH_MD5);

        need_hash[CLI_HASH_SHA1] = cli_hm_have_size(ctx->engine->hm_fp, CLI_HASH_SHA1, map->len) ||
                                   cli_hm_have_wild(ctx->engine->hm_fp, CLI_HASH_SHA1) ||
                                   cli_hm_have_size(ctx->engine->hm_fp, CLI_HASH_SHA1, 1);

        need_hash[CLI_HASH_SHA2_256] = cli_hm_have_size(ctx->engine->hm_fp, CLI_HASH_SHA2_256, map->len) ||
                                       cli_hm_have_wild(ctx->engine->hm_fp, CLI_HASH_SHA2_256) ||
                                       cli_hm_have_size(ctx->engine->hm_fp, CLI_HASH_SHA2_256, 1) ||
                                       // If debug logging is enabled, we want to calculate SHA256 hashes for all layers.
                                       // Some users rely on the debug log output to create new FP signatures.
                                       cli_debug_flag;

        /* Set fmap to need hash later if required.
         * This is an optimization so we can calculate all needed hashes in one pass. */
        for (hash_type = CLI_HASH_MD5; hash_type < CLI_HASH_AVAIL_TYPES; hash_type++) {
            if (need_hash[hash_type]) {
                ret = fmap_will_need_hash_later(map, hash_type);
                if (CL_SUCCESS != ret) {
                    cli_dbgmsg("cli_check_fp: Failed to set fmap to need MD5 hash later\n");
                    cli_mark_scan_incomplete(ctx, "false-positive hash preparation failed");
                    status = ret;
                    goto done;
                }
            }
        }

        for (hash_type = CLI_HASH_MD5; hash_type < CLI_HASH_AVAIL_TYPES; hash_type++) {
            if (need_hash[hash_type]) {
                size_t hash_len = cli_hash_len(hash_type);

                /* If we need a hash, we will calculate it now */
                ret = fmap_get_hash_ctx(map, &hash, hash_type, ctx);
                if (CL_SUCCESS != ret) {
                    cli_dbgmsg("cli_check_fp: Failed to get hash for the map at stack index # %u\n", stack_index);
                    cli_mark_scan_incomplete(ctx, "false-positive hash could not be read");
                    status = ret;
                    goto done;
                }

                if (cli_debug_flag ||
                    ((CLI_HASH_MD5 == hash_type) && (ctx->engine->cb_hash))) {
                    /* Convert hash to string */
                    for (i = 0; i < hash_len; i++) {
                        sprintf(hash_string + i * 2, "%02x", hash[i]);
                    }
                    hash_string[hash_len * 2] = 0;

                    const char *name = ctx->recursion_stack[stack_index].fmap->name;
                    const char *type = cli_ftname(ctx->recursion_stack[stack_index].type);

                    cli_dbgmsg("FP SIGNATURE: %s:" STDu64 ":%s  # Name: %s, Type: %s\n",
                               hash_string, (uint64_t)map->len, vname ? vname : "Name", name ? name : "n/a", type);
                }

                if (CLI_HASH_MD5 == hash_type) {
                    /* Run legacy callbacks that include MD5 hash */
                    if (ctx->engine->cb_hash) {
                        ctx->engine->cb_hash(fmap_fd(ctx->fmap), map->len, hash_string, vname ? vname : "noname", ctx->cb_ctx);
                    }

                    if (ctx->engine->cb_stats_add_sample) {
                        stats_section_t sections;
                        memset(&sections, 0x00, sizeof(stats_section_t));

                        if (!(ctx->engine->engine_options & ENGINE_OPTIONS_DISABLE_PE_STATS) &&
                            !(ctx->engine->dconf->stats & (DCONF_STATS_DISABLED | DCONF_STATS_PE_SECTION_DISABLED))) {

                            cli_genhash_pe(ctx, CL_GENHASH_PE_CLASS_SECTION, 1, &sections);
                        }

                        // TODO We probably only want to call cb_stats_add_sample when
                        // sections.section != NULL... leaving as is for now
                        ctx->engine->cb_stats_add_sample(vname ? vname : "noname", hash, map->len, &sections, ctx->engine->stats_data);

                        if (sections.sections) {
                            free(sections.sections);
                        }
                    }
                }

                if (cli_hm_scan(hash, map->len, &virname, ctx->engine->hm_fp, hash_type) == CL_VIRUS) {
                    cli_dbgmsg("cli_check_fp: Found false positive detection for %s (fp sig: %s)\n", cli_hash_name(hash_type), virname);

                    source_len = strlen(virname) + strlen("false positive signature match: ") + 1;
                    source     = malloc(source_len);
                    if (source) {
                        snprintf(source, source_len, "false positive signature match: %s", virname);
                    }

                    // Remove any evidence and set the verdict to trusted for the layer where the FP hash matched, and for all contained layers.
                    ret = cli_check_fp_trust_layers(ctx, (uint32_t)stack_index, source);
                    if (CL_SUCCESS != ret) {
                        status = ret;
                        goto done;
                    }

                    free(source);
                    source = NULL;

                    status = CL_VERIFIED;
                    goto done;
                }
                if (cli_hm_scan_wild(hash, &virname, ctx->engine->hm_fp, hash_type) == CL_VIRUS) {
                    cli_dbgmsg("cli_check_fp: Found false positive detection for %s (fp sig: %s)\n", cli_hash_name(hash_type), virname);

                    source_len = strlen(virname) + strlen("false positive signature match: ") + 1;
                    source     = malloc(source_len);
                    if (source) {
                        snprintf(source, source_len, "false positive signature match: %s", virname);
                    }

                    // Remove any evidence and set the verdict to trusted for the layer where the FP hash matched, and for all contained layers.
                    ret = cli_check_fp_trust_layers(ctx, (uint32_t)stack_index, source);
                    if (CL_SUCCESS != ret) {
                        status = ret;
                        goto done;
                    }

                    free(source);
                    source = NULL;

                    status = CL_VERIFIED;
                    goto done;
                }

                if (CLI_HASH_MD5 != hash_type) {
                    /* See whether the hash matches those loaded in from .cat files
                     * (associated with the .CAB file type) */
                    if (cli_hm_scan(hash, 1, &virname, ctx->engine->hm_fp, hash_type) == CL_VIRUS) {
                        cli_dbgmsg("cli_check_fp: Found .CAB false positive detection for %s via catalog file\n", cli_hash_name(hash_type));

                        source_len = strlen(virname) + strlen("false positive signature match: ") + 1;
                        source     = malloc(source_len);
                        if (source) {
                            snprintf(source, source_len, "false positive signature match: %s", virname);
                        }

                        // Remove any evidence and set the verdict to trusted for the layer where the FP hash matched, and for all contained layers.
                        ret = cli_check_fp_trust_layers(ctx, (uint32_t)stack_index, source);
                        if (CL_SUCCESS != ret) {
                            status = ret;
                            goto done;
                        }

                        free(source);
                        source = NULL;

                        status = CL_VERIFIED;
                        goto done;
                    }
                }
            }
        }

        stack_index -= 1;
    }

done:

    if (NULL != source) {
        free(source);
    }

    return status;
}

static cl_error_t matchicon(cli_ctx *ctx, struct cli_exe_info *exeinfo, const char *grp1, const char *grp2)
{
    icon_groupset iconset;

    if (!ctx ||
        !ctx->engine ||
        !ctx->engine->iconcheck ||
        !ctx->engine->iconcheck->group_counts[0] ||
        !ctx->engine->iconcheck->group_counts[1] ||
        !exeinfo->res_addr) return CL_CLEAN;

    if (!(ctx->dconf->pe & PE_CONF_MATCHICON))
        return CL_CLEAN;

    cli_icongroupset_init(&iconset);
    cli_icongroupset_add(grp1 ? grp1 : "*", &iconset, 0, ctx);
    cli_icongroupset_add(grp2 ? grp2 : "*", &iconset, 1, ctx);
    return cli_scanicon(&iconset, ctx, exeinfo);
}

int32_t cli_bcapi_matchicon(struct cli_bc_ctx *ctx, const uint8_t *grp1, int32_t grp1len,
                            const uint8_t *grp2, int32_t grp2len)
{
    cl_error_t ret;
    char group1[128], group2[128];
    struct cli_exe_info info;

    // TODO This isn't a good check, since EP will be zero for DLLs and
    // (assuming pedata->ep is populated from exeinfo->pe) non-zero for
    // some MachO and ELF executables
    if (!ctx->hooks.pedata->ep) {
        cli_dbgmsg("bytecode: matchicon only works with PE files\n");
        return -1;
    }
    if ((size_t)grp1len > sizeof(group1) - 1 ||
        (size_t)grp2len > sizeof(group2) - 1)
        return -1;

    memcpy(group1, grp1, grp1len);
    memcpy(group2, grp2, grp2len);
    group1[grp1len] = 0;
    group2[grp2len] = 0;
    memset(&info, 0, sizeof(info));
    if (ctx->bc->kind == BC_PE_UNPACKER || ctx->bc->kind == BC_PE_ALL) {
        if (le16_to_host(ctx->hooks.pedata->file_hdr.Characteristics) & 0x2000 ||
            !ctx->hooks.pedata->dirs[2].Size)
            info.res_addr = 0;
        else
            info.res_addr = ctx->hooks.pedata->dirs[2].VirtualAddress;
    } else
        info.res_addr = ctx->resaddr; /* from target_info */
    info.sections  = (struct cli_exe_section *)ctx->sections;
    info.nsections = ctx->hooks.pedata->nsections;
    info.hdr_size  = ctx->hooks.pedata->hdr_size;
    cli_dbgmsg("bytecode matchicon %s %s\n", group1, group2);
    ret = matchicon(ctx->ctx, &info, group1[0] ? group1 : NULL,
                    group2[0] ? group2 : NULL);

    return (int32_t)ret;
}

cl_error_t cli_scan_desc(int desc, cli_ctx *ctx, cli_file_t ftype, bool filetype_only, struct cli_matched_type **ftoffset, unsigned int acmode, struct cli_ac_result **acres, const char *name, const char *path, uint32_t attributes)
{
    cl_error_t status = CL_CLEAN;
    int empty;
    fmap_t *new_map = NULL;

    if (!ctx) {
        cli_errmsg("cli_scan_desc: context == NULL\n");
        return CL_ENULLARG;
    }
    if (!ctx->engine) {
        cli_errmsg("cli_scan_desc: engine == NULL\n");
        return CL_ENULLARG;
    }

    new_map = fmap_check_empty(desc, 0, 0, &empty, name, path);
    if (NULL == new_map) {
        if (!empty) {
            cli_dbgmsg("cli_scan_desc: Failed to allocate new map for file descriptor scan.\n");
            status = CL_EMEM;
        }
        goto done;
    }

    status = cli_recursion_stack_push(ctx, new_map, ftype, true, attributes); /* Perform scan with child fmap */
    if (CL_SUCCESS != status) {
        cli_dbgmsg("cli_scan_desc: Failed to scan fmap.\n");
        goto done;
    }

    status = cli_scan_fmap(ctx, ftype, filetype_only, ftoffset, acmode, acres);

    (void)cli_recursion_stack_pop(ctx); /* Restore the parent fmap */

done:
    if (NULL != new_map) {
        fmap_free(new_map);
    }

    return status;
}

static int intermediates_eval(cli_ctx *ctx, struct cli_ac_lsig *ac_lsig)
{
    uint32_t i, icnt = ac_lsig->tdb.intermediates[0];

    // -1 is the deepest layer (the current layer), so we start at -2, which is the first ancestor
    int32_t j = -2;

    if (ctx->recursion_level < icnt)
        return 0;

    for (i = icnt; i > 0; i--) {
        if (ac_lsig->tdb.intermediates[i] == CL_TYPE_ANY)
            continue;
        if (ac_lsig->tdb.intermediates[i] != cli_recursion_stack_get_type(ctx, j--))
            return 0;
    }
    return 1;
}

/* Bytecode signatures expose match offsets through a frozen uint32_t ABI.
 * Native logical/YARA matching uses uint64_t offsets, so narrow only at this
 * boundary and refuse to invoke bytecode when an offset cannot be represented
 * without changing what the bytecode sees. */
int cli_lsig_bytecode_compatible(uint64_t file_size, const uint64_t *offsets, uint32_t *legacy_offsets)
{
    unsigned int i;

    if (!offsets || !legacy_offsets || file_size > UINT32_MAX)
        return 0;

    for (i = 0; i < 64; i++) {
        if (offsets[i] == CLI_OFF_NONE64) {
            legacy_offsets[i] = CLI_OFF_NONE;
        } else if (offsets[i] >= CLI_OFF_NONE) {
            /* The two highest uint32_t values are reserved by the bytecode
             * ABI. Passing a real match at either coordinate would change
             * what the bytecode observes. */
            return 0;
        } else {
            legacy_offsets[i] = (uint32_t)offsets[i];
        }
    }

    return 1;
}

static cl_error_t lsig_eval(cli_ctx *ctx, struct cli_matcher *root, struct cli_ac_data *acdata, struct cli_target_info *target_info, uint32_t lsid)
{
    cl_error_t status           = CL_CLEAN;
    unsigned evalcnt            = 0;
    uint64_t evalids            = 0;
    int expression_status;
    fmap_t *new_map             = NULL;
    struct cli_ac_lsig *ac_lsig;
    char *exp;
    char *exp_end;

    if (!ctx || !root || !root->ac_lsigtable || lsid >= root->ac_lsigs ||
        !acdata || !ctx->fmap) {
        if (ctx)
            cli_mark_scan_incomplete(ctx, "logical signature evaluation context is unavailable");
        if (ctx && ctx->fmap)
            ctx->fmap->dont_cache_flag = 1;
        return CL_EPARSE;
    }

    ac_lsig = root->ac_lsigtable[lsid];
    if (!ac_lsig || !ac_lsig->u.logic) {
        cli_mark_scan_incomplete(ctx, "logical signature expression is unavailable");
        ctx->fmap->dont_cache_flag = 1;
        return CL_EPARSE;
    }

    exp     = ac_lsig->u.logic;
    exp_end = exp + strlen(exp);

    /* The runtime match arrays have one fixed slot for each of the 64
     * supported logical subsignatures. Signature loading normally enforces
     * this, but keep a malformed or externally constructed matcher from
     * indexing beyond those arrays. Validate the expression against the
     * declared count before evaluating it with the match counters. */
    if (ac_lsig->tdb.subsigs == 0 || ac_lsig->tdb.subsigs > MAX_LDB_SUBSIGS) {
        cli_mark_scan_incomplete(ctx, "logical signature definition is malformed");
        ctx->fmap->dont_cache_flag = 1;
        return CL_EPARSE;
    }

    expression_status = cli_ac_chklsig(exp, exp_end, NULL, NULL, NULL, 1);
    if (expression_status < 0 || (uint32_t)expression_status >= ac_lsig->tdb.subsigs) {
        cli_mark_scan_incomplete(ctx, "logical signature definition is malformed");
        ctx->fmap->dont_cache_flag = 1;
        return CL_EPARSE;
    }

    status = cli_ac_chkmacro(root, acdata, lsid, ctx);
    if (status != CL_SUCCESS)
        return status;

    expression_status = cli_ac_chklsig(exp, exp_end, acdata->lsigcnt[lsid], &evalcnt, &evalids, 0);
    if (expression_status < 0) {
        cli_mark_scan_incomplete(ctx, "logical signature expression is malformed");
        ctx->fmap->dont_cache_flag = 1;
        status = CL_EPARSE;
        goto done;
    }
    if (expression_status != 1) {
        // Logical expression did not match.
        status = CL_CLEAN;
        goto done;
    }

    // Logical expression matched.
    // Need to check the other conditions, like target description block, icon group, bytecode, etc.

    // If the lsig requires a specific container type, check if check that it matches
    if (ac_lsig->tdb.container &&
        ac_lsig->tdb.container[0] != cli_recursion_stack_get_type(ctx, -2)) {
        // So far the match is good, but the container type doesn't match.
        // Because this may need to match in a different scenario where the
        // container does match, we do not want to cache this result.
        ctx->fmap->dont_cache_flag = 1;

        goto done;
    }

    // If the lsig has intermediates, check if they match the current recursion stack
    if (ac_lsig->tdb.intermediates &&
        !intermediates_eval(ctx, ac_lsig)) {
        // So far the match is good, but the intermediates type(s) do not match.
        // Because this may need to match in a different scenario where the
        // intermediates do match, we do not want to cache this result.
        ctx->fmap->dont_cache_flag = 1;

        goto done;
    }

    // If the lsig has filesize requirements, check if they match
    if (ac_lsig->tdb.filesize && (ac_lsig->tdb.filesize[0] > ctx->fmap->len || ac_lsig->tdb.filesize[1] < ctx->fmap->len)) {
        goto done;
    }

    if (ac_lsig->tdb.ep || ac_lsig->tdb.nos) {
        if (!target_info || target_info->status != 1)
            goto done;
        if (ac_lsig->tdb.ep && (ac_lsig->tdb.ep[0] > cli_exe_entrypoint(&target_info->exeinfo) || ac_lsig->tdb.ep[1] < cli_exe_entrypoint(&target_info->exeinfo)))
            goto done;
        if (ac_lsig->tdb.nos && (ac_lsig->tdb.nos[0] > target_info->exeinfo.nsections || ac_lsig->tdb.nos[1] < target_info->exeinfo.nsections))
            goto done;
    }

    if (ac_lsig->tdb.handlertype) {
        // This logical signature has a handler type, which means it's effectively a complex file type signature.
        // Instead of alerting, we'll make a duplicate fmap (add recursion depth, to prevent infinite loops) and
        // scan the file with the handler type.

        if (!ctx->recursion_stack || ctx->recursion_stack_size == 0 ||
            ctx->recursion_level >= ctx->recursion_stack_size) {
            cli_mark_scan_incomplete(ctx, "logical signature HandlerType recursion stack is unavailable");
            ctx->fmap->dont_cache_flag = 1;
            status = CL_EPARSE;
            goto done;
        }

        /*
         * If the current layer was re-typed already, then prevent HandlerType from being applied again.
         */
        if (!(ctx->recursion_stack[ctx->recursion_level].attributes & LAYER_ATTRIBUTES_RETYPED)) {
            /*
             * Create an fmap window into our current fmap using the original offset & length, and rescan as the new type
             *
             * TODO: Unsure if creating an fmap is the right move, or if we should rescan with the current fmap as-is,
             * since it's not really a container so much as it is type reassignment. This new fmap layer protect against
             * a possible infinite loop by applying the scan recursion limit, but maybe there's a better way?
             * Testing with both HandlerType type reassignment sigs + Container/Intermediates sigs should indicate if
             * a change is needed.
             */
            new_map = fmap_duplicate(ctx->fmap, 0, ctx->fmap->len, ctx->fmap->name);
            if (NULL == new_map) {
                status = CL_EMEM;
                cli_dbgmsg("Failed to duplicate the current fmap for a re-scan as a different type.\n");
                goto done;
            }

            status = cli_recursion_stack_push(ctx, new_map, ac_lsig->tdb.handlertype[0], true, LAYER_ATTRIBUTES_RETYPED); /* Perform scan with child fmap */
            if (CL_SUCCESS != status) {
                cli_dbgmsg("Failed to re-scan fmap as a new type.\n");
                goto done;
            }

            status = cli_magic_scan(ctx, ac_lsig->tdb.handlertype[0]);

            (void)cli_recursion_stack_pop(ctx); /* Restore the parent fmap */

            goto done;
        }
    }

    if (ac_lsig->tdb.icongrp1 || ac_lsig->tdb.icongrp2) {
        // Logical sig depends on icon match. Check for the icon match.

        if (!target_info || target_info->status != TARGET_PE) {
            // Icon group feature only applies to PE files, so target description must match a PE file.
            // This is a signature issue and should have been caught at load time, but just in case, we're checking again here.
            goto done;
        }

        if (CL_VIRUS != matchicon(ctx, &target_info->exeinfo, ac_lsig->tdb.icongrp1, ac_lsig->tdb.icongrp2)) {
            // No icon match!
            goto done;
        }
    }

    if (!ac_lsig->bc_idx) {
        // Logical sig does not depend on bytecode match. Report the virus.
        status = cli_append_virus(ctx, ac_lsig->virname);
        if (status != CL_SUCCESS) {
            goto done;
        }
    } else {
        // Logical sig depends on bytecode match. Check for the bytecode match.
        if (!ctx || !ctx->engine || !ctx->engine->bcs.all_bcs ||
            ac_lsig->bc_idx > ctx->engine->bcs.count) {
            cli_dbgmsg("lsig_eval: logical signature '%s' references unavailable bytecode entry %u\n",
                       ac_lsig->virname, ac_lsig->bc_idx);
            cli_mark_scan_incomplete(ctx, "logical signature references unavailable bytecode");
            if (ctx && ctx->fmap)
                ctx->fmap->dont_cache_flag = 1;
            status = CL_EPARSE;
            goto done;
        }
        const struct cli_bc *bc = &ctx->engine->bcs.all_bcs[ac_lsig->bc_idx - 1];

        if (bc->metadata.formatlevel != BC_FORMAT_LEVEL_V2) {
            uint32_t legacy_offsets[64];
            if (!cli_lsig_bytecode_compatible((uint64_t)ctx->fmap->len, acdata->lsigsuboff_first[lsid], legacy_offsets)) {
                cli_dbgmsg("lsig_eval: refusing to run v1 bytecode '%s' with a file size or logical-signature offset outside the 32-bit ABI\n",
                           ac_lsig->virname);
                cli_mark_scan_incomplete(ctx, "logical signature requires a file size or offset outside the bytecode ABI");
                ctx->fmap->dont_cache_flag = 1;
                status = CL_EPARSE;
                goto done;
            }
        }

        status = cli_bytecode_runlsig(ctx, target_info, &ctx->engine->bcs, ac_lsig->bc_idx,
                                      acdata->lsigcnt[lsid], acdata->lsigsuboff_first[lsid], ctx->fmap);
        if (CL_SUCCESS != status) {
            goto done;
        }

        // Check time limit here, because bytecode functions may take a while.
        status = cli_checktimelimit(ctx);
        if (CL_SUCCESS != status) {
            goto done;
        }
    }

done:
    if (NULL != new_map) {
        free_duplicate_fmap(new_map);
    }

    return status;
}

#ifdef HAVE_YARA
static cl_error_t yara_normalize_execution_status(int result)
{
#if REAL_YARA
    switch (result) {
        case ERROR_SUCCESS:
            return CL_SUCCESS;
        case ERROR_SCAN_TIMEOUT:
            return CL_ETIMEOUT;
        case ERROR_INSUFICIENT_MEMORY:
            return CL_EMEM;
        case ERROR_TOO_MANY_SCAN_THREADS:
        case ERROR_TOO_MANY_MATCHES:
            return CL_ERESOURCE;
        default:
            return CL_EPARSE;
    }
#else
    /* The bundled interpreter returns selected ClamAV statuses directly.
     * Other YARA error numbers must not be cast to cl_error_t: for example,
     * ERROR_EXEC_STACK_OVERFLOW is 25, which collides with CL_EMAXFILES. */
    switch ((cl_error_t)result) {
        case CL_SUCCESS:
        case CL_VIRUS:
        case CL_EREAD:
        case CL_ETIMEOUT:
        case CL_EMEM:
        case CL_ERESOURCE:
        case CL_EPARSE:
            return (cl_error_t)result;
        default:
            return CL_EPARSE;
    }
#endif
}

#if !REAL_YARA
static cl_error_t yara_instruction_stream_error(cli_ctx *ctx, const char *reason)
{
    cli_mark_scan_incomplete(ctx, reason);
    if (ctx != NULL && ctx->fmap != NULL)
        ctx->fmap->dont_cache_flag = 1;
    return CL_EPARSE;
}

static size_t yara_instruction_operand_size(uint8_t opcode)
{
    switch (opcode) {
        case OP_PUSH:
        case OP_CLEAR_M:
        case OP_ADD_M:
        case OP_INCR_M:
        case OP_PUSH_M:
        case OP_POP_M:
        case OP_SWAPUNDEF:
        case OP_JNUNDEF:
        case OP_JLE:
        case OP_PUSH_RULE:
        case OP_MATCH_RULE:
        case OP_OBJ_LOAD:
        case OP_CALL:
            return sizeof(uint64_t);
        case OP_HALT:
        case OP_AND:
        case OP_OR:
        case OP_XOR:
        case OP_NOT:
        case OP_LT:
        case OP_GT:
        case OP_LE:
        case OP_GE:
        case OP_EQ:
        case OP_NEQ:
        case OP_SZ_EQ:
        case OP_SZ_NEQ:
        case OP_SZ_TO_BOOL:
        case OP_ADD:
        case OP_SUB:
        case OP_MUL:
        case OP_DIV:
        case OP_MOD:
        case OP_NEG:
        case OP_SHL:
        case OP_SHR:
        case OP_POP:
        case OP_OF:
        case OP_STR_COUNT:
        case OP_STR_FOUND:
        case OP_STR_FOUND_AT:
        case OP_STR_FOUND_IN:
        case OP_STR_OFFSET:
        case OP_MATCHES:
        case OP_FILESIZE:
        case OP_ENTRYPOINT:
        case OP_INT8:
        case OP_INT16:
        case OP_INT32:
        case OP_UINT8:
        case OP_UINT16:
        case OP_UINT32:
            return 0;
        default:
            return SIZE_MAX;
    }
}

static cl_error_t yara_validate_instruction_stream(cli_ctx *ctx, const struct cli_ac_lsig *ac_lsig)
{
    const uint8_t *code;
    uintptr_t code_start;
    uintptr_t code_end;
    uint8_t *flags;
    size_t pc = 0;
    bool saw_halt = false;
    cl_error_t status = CL_SUCCESS;

    if (ac_lsig == NULL || ac_lsig->u.code_start == NULL || ac_lsig->code_size == 0)
        return yara_instruction_stream_error(ctx, "YARA matcher instruction stream is unavailable");
    if (ac_lsig->code_size > YARA_MAX_INSTRUCTION_STREAM_SIZE)
        return yara_instruction_stream_error(ctx, "YARA matcher instruction stream exceeds the bounded code size");

    code       = ac_lsig->u.code_start;
    code_start = (uintptr_t)code;
    if ((uint64_t)ac_lsig->code_size > (uint64_t)(UINTPTR_MAX - code_start))
        return yara_instruction_stream_error(ctx, "YARA matcher instruction stream range is not representable");
    code_end = code_start + (uintptr_t)ac_lsig->code_size;

    flags = cli_max_calloc(ac_lsig->code_size, sizeof(*flags));
    if (flags == NULL) {
        cli_mark_scan_incomplete(ctx, "YARA matcher instruction stream could not be validated");
        if (ctx != NULL && ctx->fmap != NULL)
            ctx->fmap->dont_cache_flag = 1;
        return CL_EMEM;
    }

    while (pc < ac_lsig->code_size) {
        uint8_t opcode;
        size_t operand_size;

        flags[pc] |= 0x01;
        opcode       = code[pc++];
        operand_size = yara_instruction_operand_size(opcode);
        if (operand_size == SIZE_MAX) {
            status = yara_instruction_stream_error(ctx, "YARA matcher instruction stream contains an unknown opcode");
            goto done;
        }
        if (operand_size > ac_lsig->code_size - pc) {
            status = yara_instruction_stream_error(ctx, "YARA matcher instruction stream has a truncated operand");
            goto done;
        }

        if (opcode == OP_JNUNDEF || opcode == OP_JLE) {
            uint64_t target_value;
            uintptr_t target;
            size_t target_offset;

            memcpy(&target_value, code + pc, sizeof(target_value));
            if (target_value > (uint64_t)UINTPTR_MAX) {
                status = yara_instruction_stream_error(ctx, "YARA matcher instruction stream has an invalid jump target");
                goto done;
            }
            target = (uintptr_t)target_value;
            if (target < code_start || target >= code_end) {
                status = yara_instruction_stream_error(ctx, "YARA matcher instruction stream has an invalid jump target");
                goto done;
            }
            target_offset = (size_t)(target - code_start);
            flags[target_offset] |= 0x02;
        }

        pc += operand_size;
        if (opcode == OP_HALT) {
            if (pc != ac_lsig->code_size) {
                status = yara_instruction_stream_error(ctx, "YARA matcher instruction stream has data after halt");
                goto done;
            }
            saw_halt = true;
            break;
        }
    }

    if (!saw_halt) {
        status = yara_instruction_stream_error(ctx, "YARA matcher instruction stream has no halt instruction");
        goto done;
    }

    for (pc = 0; pc < ac_lsig->code_size; pc++) {
        if ((flags[pc] & 0x02) != 0 && (flags[pc] & 0x01) == 0) {
            status = yara_instruction_stream_error(ctx, "YARA matcher instruction stream jumps into an operand");
            goto done;
        }
    }

done:
    free(flags);
    return status;
}
#endif

static cl_error_t yara_eval(cli_ctx *ctx, struct cli_matcher *root, struct cli_ac_data *acdata, struct cli_target_info *target_info, uint32_t lsid)
{
    struct cli_ac_lsig *ac_lsig = root->ac_lsigtable[lsid];
    cl_error_t rc;
    int execution_result;
    YR_SCAN_CONTEXT context;

    if (!ac_lsig || !ac_lsig->u.code_start) {
        cli_mark_scan_incomplete(ctx, "YARA matcher instruction stream is unavailable");
        if (ctx && ctx->fmap)
            ctx->fmap->dont_cache_flag = 1;
        return CL_EPARSE;
    }
#if !REAL_YARA
    rc = yara_validate_instruction_stream(ctx, ac_lsig);
    if (rc != CL_SUCCESS)
        return rc;
#endif
    if (!acdata) {
        cli_mark_scan_incomplete(ctx, "YARA matcher state is unavailable");
        if (ctx && ctx->fmap)
            ctx->fmap->dont_cache_flag = 1;
        return CL_EPARSE;
    }

    memset(&context, 0, sizeof(YR_SCAN_CONTEXT));
    context.fmap      = ctx->fmap;
    context.file_size = ctx->fmap->len;
    context.scan_ctx  = ctx;
    if (target_info != NULL) {
        if (target_info->status == 1)
            context.entry_point = cli_exe_entrypoint(&target_info->exeinfo);
    }

    execution_result = yr_execute_code(ac_lsig, acdata, &context, 0, 0);
    rc                = yara_normalize_execution_status(execution_result);

    if (rc == CL_VIRUS) {
        if (ac_lsig->flag & CLI_LSIG_FLAG_PRIVATE) {
            rc = CL_CLEAN;
        } else {
            rc = cli_append_virus(ctx, ac_lsig->virname);
        }
    }

    if (rc != CL_SUCCESS && rc != CL_VIRUS) {
        if (rc == CL_EREAD)
            cli_mark_scan_incomplete(ctx, "YARA matcher fmap read failed");
        else if (rc == CL_ETIMEOUT)
            cli_mark_scan_incomplete(ctx, "YARA matcher execution reached the configured time limit");
        else if (rc == CL_EMEM)
            cli_mark_scan_incomplete(ctx, "YARA matcher execution ran out of memory");
        else
            cli_mark_scan_incomplete(ctx, "YARA matcher execution failed");
        if (ctx->fmap != NULL)
            ctx->fmap->dont_cache_flag = 1;
    }
    return rc;
}
#endif

cl_error_t cli_exp_eval(cli_ctx *ctx, struct cli_matcher *root, struct cli_ac_data *acdata, struct cli_target_info *target_info)
{
    uint32_t i;
    cl_error_t status = CL_SUCCESS;
    cl_error_t current;
    bool yara_work_accounted = false;

    if (!ctx || !root || !ctx->fmap) {
        if (ctx)
            cli_mark_scan_incomplete(ctx, "logical matcher evaluation context is unavailable");
        if (ctx && ctx->fmap)
            ctx->fmap->dont_cache_flag = 1;
        return CL_ENULLARG;
    }

    if (root->ac_lsigs && !root->ac_lsigtable) {
        cli_mark_scan_incomplete(ctx, "logical signature table is unavailable");
        ctx->fmap->dont_cache_flag = 1;
        return CL_EPARSE;
    }

    for (i = 0; i < root->ac_lsigs; i++) {
        if (!root->ac_lsigtable[i]) {
            cli_mark_scan_incomplete(ctx, "logical signature entry is unavailable");
            ctx->fmap->dont_cache_flag = 1;
            current = CL_EPARSE;
        } else if (root->ac_lsigtable[i]->type == CLI_LSIG_NORMAL) {
            current = lsig_eval(ctx, root, acdata, target_info, i);
        }
#ifdef HAVE_YARA
        else if (root->ac_lsigtable[i]->type == CLI_YARA_NORMAL || root->ac_lsigtable[i]->type == CLI_YARA_OFFSET) {
            /* YARA bytecode can read arbitrary integer fields from the
             * current fmap after the raw matcher has completed. Charge one
             * bounded pass over this representation per logical root rather
             * than allowing those reads to bypass MaxMatcherWork. */
            if (!yara_work_accounted) {
                if (!ctx || !ctx->fmap) {
                    current = CL_ENULLARG;
                } else {
                    current = cli_scan_account_matcher_work(ctx, (uint64_t)ctx->fmap->len);
                }
                if (current != CL_SUCCESS) {
                    status = cli_merge_scan_status(status, current);
                    break;
                }
                yara_work_accounted = true;
            }
            current = yara_eval(ctx, root, acdata, target_info, i);
        }
#endif
        else {
            cli_dbgmsg("lsig_eval: logical signature has an unsupported type %u\n", root->ac_lsigtable[i]->type);
            cli_mark_scan_incomplete(ctx, "logical signature type is unsupported");
            if (ctx && ctx->fmap)
                ctx->fmap->dont_cache_flag = 1;
            current = CL_EPARSE;
        }

        status = cli_merge_scan_status(status, current);
        if (current == CL_VIRUS || cli_scan_status_is_critical(current)) {
            break;
        }

        if (i % 10 == 0) {
            // Check the time limit every n'th lsig.
            // In testing with a large signature set, we found n = 10 to be just as fast as 100 or
            // 1000 and has a significant performance improvement over checking with every lsig.
            current = cli_checktimelimit(ctx);
            if (CL_SUCCESS != current) {
                status = cli_merge_scan_status(status, current);
                cli_dbgmsg("Exceeded scan time limit while evaluating logical and yara signatures (max: %u)\n", ctx->engine->maxscantime);
                break;
            }
        }
    }

    return status;
}

cl_error_t cli_scan_fmap(cli_ctx *ctx, cli_file_t ftype, bool filetype_only, struct cli_matched_type **ftoffset, unsigned int acmode, struct cli_ac_result **acres)
{
    const unsigned char *buff;
    cl_error_t ret = CL_CLEAN, type = CL_CLEAN;
    cl_error_t status = CL_CLEAN;
    cl_error_t current;

    cli_hash_type_t hash_type;
    bool need_hash[CLI_HASH_AVAIL_TYPES] = {false};
    void *hashctx[CLI_HASH_AVAIL_TYPES]  = {NULL};
    unsigned char digest[CLI_HASH_AVAIL_TYPES][CLI_HASHLEN_MAX];

    unsigned int i = 0, j = 0;
    uint32_t maxpatlen, bytes;
    uint64_t offset = 0;

    struct cli_ac_data generic_ac_data;
    bool gdata_initialized = false;

    struct cli_ac_data target_ac_data;
    bool tdata_initialized = false;

    struct cli_bm_off bm_offsets_table;
    bool bm_offsets_table_initialized = false;

    struct cli_pcre_off generic_pcre_offsets_table;
    bool generic_pcre_offsets_table_initialized = false;

    struct cli_pcre_off target_pcre_offsets_table;
    bool target_pcre_offsets_table_initialized = false;

    struct cli_matcher *generic_ac_root = NULL, *target_ac_root = NULL;
    bool generic_match_ready = false;
    bool target_match_ready  = false;

    struct cli_target_info info;
    bool info_initialized = false;

    struct cli_matcher *hdb, *fp;
    bool scan_viruses;

    if (!ctx) {
        cli_errmsg("cli_scan_fmap: context == NULL\n");
        return CL_ENULLARG;
    }
    if (!ctx->engine) {
        cli_errmsg("cli_scan_fmap: engine == NULL\n");
        ret = CL_ENULLARG;
        goto done;
    }
    if (!ctx->fmap) {
        cli_mark_scan_incomplete(ctx, "matcher fmap is unavailable");
        ret = CL_EPARSE;
        goto done;
    }

    scan_viruses = (acmode & AC_SCAN_VIR) != 0;

    if (!filetype_only) {
        generic_ac_root = ctx->engine->root[0]; /* generic signatures */
    }

    if (ftype != CL_TYPE_ANY) {
        // Identify the target type, to find the matcher root for that target.

        for (i = 1; i < CLI_MTARGETS; i++) {
            for (j = 0; j < cli_mtargets[i].target_count; ++j) {
                if (cli_mtargets[i].target[j] == ftype) {
                    // Identified the target type, now get the matcher root for that target.
                    target_ac_root = ctx->engine->root[i];
                    break; // Break out of inner loop
                }
            }
            if (target_ac_root) break;
        }
    }

    if (!generic_ac_root) {
        if (!target_ac_root) {
            // Don't have a matcher root for either generic signatures or target-specific signatures.
            // Nothing to do!
            ret = CL_CLEAN;
            goto done;
        }
    }

    cli_targetinfo_init(&info);
    cli_targetinfo(&info, i, ctx);
    info_initialized = true;

    if (-1 == info.status) {
        cli_dbgmsg("cli_scan_fmap: Failed to successfully parse the executable header. "
                   "Scan features will be disabled, such as "
                   "NDB/LDB subsigs using EOF-n/EP+n/EP-n/Sx+n/SEx/SL+n, "
                   "fuzzy icon matching, "
                   "MDB/IMP sigs, "
                   "and bytecode sigs that require exe metadata\n");
    }

    /* If it's a PE, check the Authenticode header.  This would be more
     * appropriate in cli_scanpe, but scanraw->cli_scan_fmap gets
     * called first for PEs, and we want to determine the trust/block
     * status early on so we can skip things like embedded PE extraction
     * (which is broken for signed binaries within signed binaries).
     *
     * If we want to add support for more signature parsing in the future
     * (Ex: MachO sigs), do that here too.
     *
     * One benefit of not continuing on to scan files with trusted signatures
     * is that the bytes associated with the exe won't get counted against the
     * scansize limits, which means we have an increased chance of catching
     * malware in container types (NSIS, iShield, etc.) where the file size is
     * large.  A common case where this occurs is installers that embed one
     * or more of the various Microsoft Redistributable Setup packages.  These
     * can easily be 5 MB or more in size, and might appear before malware
     * does in a given sample.
     */

    if (1 == info.status && i == 1) {
        ret = cli_check_auth_header(ctx, &(info.exeinfo));
        if (ret == CL_VIRUS || ret == CL_VERIFIED) {
            goto done;
        }

        /* No catalog match is the expected non-terminal result. Preserve
         * every other Authenticode result so certificate-parser, callback,
         * and resource failures cannot be normalized into a clean scan. */
        if (ret != CL_EVERIFY) {
            goto done;
        }

        ret = CL_CLEAN;
    }

    if (!filetype_only) {
        /* If we're not doing a filetype-only scan, so we definitely need to include generic signatures.
           So initialize the ac data for the generic signatures root. */

        if (generic_ac_root) {
            current = cli_ac_initdata(&generic_ac_data, generic_ac_root->ac_partsigs, generic_ac_root->ac_lsigs,
                                      generic_ac_root->ac_reloff_num, CLI_DEFAULT_AC_TRACKLEN);
            if (CL_SUCCESS != current) {
                if (current == CL_EMEM)
                    cli_mark_scan_incomplete(ctx, "AC matcher state could not be allocated");
                status = cli_merge_scan_status(status, current);
                if (cli_scan_status_is_critical(current)) {
                    ret = current;
                    goto done;
                }
            } else {
                gdata_initialized = true;

                /* Recalculate the relative offsets in ac sigs (e.g. those that are based on pe/elf/macho section start/end). */
                current = cli_ac_caloff(generic_ac_root, &generic_ac_data, &info);
                if (CL_SUCCESS != current) {
                    status = cli_merge_scan_status(status, current);
                    if (cli_scan_status_is_critical(current)) {
                        ret = current;
                        goto done;
                    }
                } else {
                    /* Recalculate the pcre offsets.
                       This does an allocation, that we will need to free later. */
                    current = cli_pcre_recaloff(generic_ac_root, &generic_pcre_offsets_table, &info, ctx);
                    if (CL_SUCCESS != current) {
                        status = cli_merge_scan_status(status, current);
                        if (cli_scan_status_is_critical(current)) {
                            ret = current;
                            goto done;
                        }
                    } else {
                        generic_pcre_offsets_table_initialized = true;
                        generic_match_ready                      = true;
                    }
                }
            }
        }
    }

    if (target_ac_root) {
        /* We have to match against target-specific signatures.
           So initialize the ac data for the target-specific signatures root. */

        current = cli_ac_initdata(&target_ac_data, target_ac_root->ac_partsigs, target_ac_root->ac_lsigs,
                                  target_ac_root->ac_reloff_num, CLI_DEFAULT_AC_TRACKLEN);
        if (CL_SUCCESS != current) {
            if (current == CL_EMEM)
                cli_mark_scan_incomplete(ctx, "AC matcher state could not be allocated");
            status = cli_merge_scan_status(status, current);
            if (cli_scan_status_is_critical(current)) {
                ret = current;
                goto done;
            }
        } else {
            tdata_initialized = true;

            /* Recalculate the relative offsets in ac sigs (e.g. those that are based on pe/elf/macho section start/end). */
            current = cli_ac_caloff(target_ac_root, &target_ac_data, &info);
            if (CL_SUCCESS != current) {
                status = cli_merge_scan_status(status, current);
                if (cli_scan_status_is_critical(current)) {
                    ret = current;
                    goto done;
                }
            } else {
                if (target_ac_root->bm_offmode) {
                    if (ctx->fmap->len >= CLI_DEFAULT_BM_OFFMODE_FSIZE) {
                        /* Recalculate the relative offsets in boyer-moore signatures (e.g. those that are based on pe/elf/macho section start/end). */
                        current = cli_bm_initoff(target_ac_root, &bm_offsets_table, &info);
                        if (CL_SUCCESS != current) {
                            if (current == CL_EMEM)
                                cli_mark_scan_incomplete(ctx, "BM offset state could not be allocated");
                            status = cli_merge_scan_status(status, current);
                            if (cli_scan_status_is_critical(current)) {
                                ret = current;
                                goto done;
                            }
                        } else {
                            bm_offsets_table_initialized = true;
                        }
                    }
                }

                /* Recalculate the pcre offsets.
                   This does an allocation, that we will need to free later. */
                if (current == CL_SUCCESS) {
                    current = cli_pcre_recaloff(target_ac_root, &target_pcre_offsets_table, &info, ctx);
                    if (CL_SUCCESS != current) {
                        status = cli_merge_scan_status(status, current);
                        if (cli_scan_status_is_critical(current)) {
                            ret = current;
                            goto done;
                        }
                    } else {
                        target_pcre_offsets_table_initialized = true;
                        target_match_ready                      = true;
                    }
                }
            }
        }
    }

    /* A non-critical setup failure disables only that matcher root. Recompute
     * the overlap window from roots that are actually ready so an unavailable
     * root cannot alter the independent root's scan coordinates. */
    maxpatlen = 0;
    if (generic_match_ready)
        maxpatlen = generic_ac_root->maxpatlen;
    if (target_match_ready)
        maxpatlen = MAX(maxpatlen, target_ac_root->maxpatlen);

    hdb = ctx->engine->hm_hdb;
    fp  = ctx->engine->hm_fp;

    if (!filetype_only && scan_viruses && hdb) {
        /* We're not just doing file typing, we're checking for viruses.
           So we need to compute the hash sigs, if there are any.

           Computing the hash in chunks the same size and time that we do for
           matching with the AC & BM pattern matchers is an optimization so we
           we can do both processes while the cache is still hot. */

        need_hash[CLI_HASH_MD5] = cli_hm_have_size(hdb, CLI_HASH_MD5, ctx->fmap->len) ||
                                  cli_hm_have_wild(hdb, CLI_HASH_MD5) ||
                                  cli_hm_have_size(fp, CLI_HASH_MD5, ctx->fmap->len) ||
                                  cli_hm_have_wild(fp, CLI_HASH_MD5);

        need_hash[CLI_HASH_SHA1] = cli_hm_have_size(hdb, CLI_HASH_SHA1, ctx->fmap->len) ||
                                   cli_hm_have_wild(hdb, CLI_HASH_SHA1) ||
                                   cli_hm_have_size(fp, CLI_HASH_SHA1, ctx->fmap->len) ||
                                   cli_hm_have_wild(fp, CLI_HASH_SHA1);

        need_hash[CLI_HASH_SHA2_256] = cli_hm_have_size(hdb, CLI_HASH_SHA2_256, ctx->fmap->len) ||
                                       cli_hm_have_wild(hdb, CLI_HASH_SHA2_256) ||
                                       cli_hm_have_size(fp, CLI_HASH_SHA2_256, ctx->fmap->len) ||
                                       cli_hm_have_wild(fp, CLI_HASH_SHA2_256);

        /*
         * Initialize hash contexts for the hashes that we need to compute.
         */
        for (hash_type = CLI_HASH_MD5; hash_type < CLI_HASH_AVAIL_TYPES; hash_type++) {
            if (need_hash[hash_type] && !ctx->fmap->have_hash[hash_type]) {
                const char *hash_name = cli_hash_name(hash_type);

                hashctx[hash_type] = cl_hash_init(hash_name);
                if (NULL == hashctx[hash_type]) {
                    cli_errmsg("cli_scan_fmap: Error initializing %s hash context\n", hash_name);
                    cli_mark_scan_incomplete(ctx, "raw matcher hash context could not be initialized");
                    ctx->fmap->dont_cache_flag = 1;
                    ret = CL_EARG;
                    goto done;
                }
            }
        }
    }

    while (offset < ctx->fmap->len) {
        if (cli_checktimelimit(ctx) != CL_SUCCESS) {
            cli_dbgmsg("Exceeded scan time limit while scanning fmap (max: %u)\n", ctx->engine->maxscantime);
            ret = CL_ETIMEOUT;
            goto done;
        }

        bytes = MIN(ctx->fmap->len - offset, SCANBUFF);
        if (!(buff = fmap_need_off_once(ctx->fmap, offset, bytes))) {
            cli_errmsg("cli_scan_fmap: failed to map %u bytes at offset " STDu64 "\n", bytes, offset);
            cli_mark_scan_incomplete(ctx, "raw matcher input could not be mapped");
            ret = CL_EREAD;
            goto done;
        }
        ret = cli_scan_account_matcher_work(ctx, bytes);
        if (ret != CL_SUCCESS)
            goto done;
        if (ctx->scanned)
            *ctx->scanned += bytes;

        if (target_match_ready) {
            const char *virname = NULL;

            current = matcher_run(target_ac_root, buff, bytes, &virname, &target_ac_data, offset,
                              &info, ftype, ftoffset, acmode, PCRE_SCAN_FMAP, acres, ctx->fmap,
                              bm_offsets_table_initialized ? &bm_offsets_table : NULL,
                              &target_pcre_offsets_table, ctx);
            /* Preserve target-root failures while allowing the independent
             * generic raw matcher to run after non-critical errors. */
            if (current != CL_SUCCESS && current < CL_TYPENO) {
                status = cli_merge_scan_status(status, current);
                if (cli_scan_status_is_critical(current)) {
                    ret = current;
                    goto done;
                }
            }
        }

        if (!filetype_only && generic_match_ready) {
            const char *virname = NULL;

            current = matcher_run(generic_ac_root, buff, bytes, &virname, &generic_ac_data, offset,
                              &info, ftype, ftoffset, acmode, PCRE_SCAN_FMAP, acres, ctx->fmap,
                              NULL,
                              &generic_pcre_offsets_table, ctx);
            /* Do not let a resource, callback, timeout, or parser failure
             * disappear after the generic matcher has returned it. */
            if (current != CL_SUCCESS && current < CL_TYPENO) {
                status = cli_merge_scan_status(status, current);
                if (cli_scan_status_is_critical(current)) {
                    ret = current;
                    goto done;
                }
            } else if ((acmode & AC_SCAN_FT) && ((cli_file_t)current >= CL_TYPENO)) {
                if (current > type)
                    type = current;
            }

        }

        /* Hash-signature accumulation is independent of AC/BM/PCRE root
         * readiness. A non-critical matcher setup failure must not leave an
         * initialized hash context empty while the other raw root continues. */
        if (!filetype_only && scan_viruses && hdb && (bytes > (maxpatlen * (offset != 0)))) {
            const void *data  = buff + maxpatlen * (offset != 0);
            uint32_t data_len = bytes - maxpatlen * (offset != 0);

            for (hash_type = CLI_HASH_MD5; hash_type < CLI_HASH_AVAIL_TYPES; hash_type++) {
                /*
                 * Compute the hash for the current data chunk, if we need to.
                 */
                if (need_hash[hash_type] && !ctx->fmap->have_hash[hash_type]) {
                    if (cl_update_hash(hashctx[hash_type], data, data_len)) {
                        const char *hash_name = cli_hash_name(hash_type);
                        cli_errmsg("cli_scan_fmap: Error calculating %s hash!\n", hash_name);
                        ret = CL_EREAD;
                        goto done;
                    }
                }
            }
        }

        if (bytes < SCANBUFF)
            break;

        offset += bytes - maxpatlen;
    }

    if (!filetype_only && scan_viruses && hdb) {
        /* We're not just doing file typing, we're scanning for malware.
           So we need to check the hash sigs, if there are any. */
        for (hash_type = CLI_HASH_MD5; hash_type < CLI_HASH_AVAIL_TYPES; hash_type++) {
            /*
             * Compute the hash for the current data chunk, if we need to.
             */
            if (need_hash[hash_type] && !ctx->fmap->have_hash[hash_type]) {
                if (cl_finish_hash(hashctx[hash_type], digest[hash_type]) != 0) {
                    hashctx[hash_type] = NULL;
                    cli_mark_scan_incomplete(ctx, "raw matcher hash could not be finalized completely");
                    ret = CL_EREAD;
                    goto done;
                }
                hashctx[hash_type] = NULL;

                ret = fmap_set_hash(ctx->fmap, digest[hash_type], hash_type);
                if (CL_SUCCESS != ret) {
                    cli_mark_scan_incomplete(ctx, "raw matcher hash could not be cached completely");
                    goto done;
                }
            }
        }

        for (hash_type = CLI_HASH_MD5; hash_type < CLI_HASH_AVAIL_TYPES; hash_type++) {
            const char *virname   = NULL;
            const char *virname_w = NULL;
            uint8_t *hash         = NULL;

            /* If no hash, skip to next type */
            if (!need_hash[hash_type]) {
                continue;
            }

            /* Get the hash for the current type.
             * We already calculated all the needed ones, so this is a simple lookup.
             * Yes, I know there is the digest[] array, but that one may be hashes calculated before this function. */
            ret = fmap_get_hash_ctx(ctx->fmap, &hash, hash_type, ctx);
            if (CL_SUCCESS != ret) {
                cli_dbgmsg("cli_scan_fmap: Error getting hash for type %d\n", hash_type);
                goto done;
            }

            /* Do hash scan checking hash sigs with specific size.
             * This part is fast, so we aren't checking if there are any of hash sigs for this type of hash at this file size */
            ret = cli_hm_scan(hash, ctx->fmap->len, &virname, hdb, hash_type);
            if (ret == CL_VIRUS) {
                /* Matched with size-based hash ... */
                ret = cli_append_virus(ctx, virname);
                if (ret != CL_SUCCESS) {
                    goto done;
                }
            }

            /* Do hash scan checking hash sigs with wildcard size.
             * This part is fast, so we aren't checking if there are any hash sigs for this type of hash with wildcard size */
            ret = cli_hm_scan_wild(hash, &virname_w, hdb, hash_type);
            if (ret == CL_VIRUS) {
                /* Matched with size-agnostic hash ... */
                ret = cli_append_virus(ctx, virname_w);
                if (ret != CL_SUCCESS) {
                    goto done;
                }
            }
        }
    }

    ret = cli_merge_scan_status(status, ret);

    /*
     * Evaluate the logical expressions for clamav logical signatures and YARA rules.
     */
    // Evaluate for the target-specific signature AC matches.
    if (scan_viruses && target_match_ready) {
        if (ret != CL_VIRUS) {
            /* A target-root evaluation may be incomplete even when the
             * generic root still has useful work to do. Preserve that status
             * across the second root; a later clean result must never turn a
             * partially evaluated layer into a clean scan. Detections remain
             * stronger than all non-detection statuses. */
            ret = cli_merge_scan_status(ret, cli_exp_eval(ctx, target_ac_root, &target_ac_data, &info));
        }
    }

    // Evaluate for the generic signature AC matches.
    if (scan_viruses && generic_match_ready) {
        if (ret != CL_VIRUS) {
            ret = cli_merge_scan_status(ret, cli_exp_eval(ctx, generic_ac_root, &generic_ac_data, &info));
        }
    }

done:
    for (hash_type = CLI_HASH_MD5; hash_type < CLI_HASH_AVAIL_TYPES; hash_type++) {
        if (NULL != hashctx[hash_type]) {
            cl_hash_destroy(hashctx[hash_type]);
        }
    }

    if (gdata_initialized) {
        cli_ac_freedata(&generic_ac_data);
    }
    if (tdata_initialized) {
        cli_ac_freedata(&target_ac_data);
    }

    if (generic_pcre_offsets_table_initialized) {
        cli_pcre_freeoff(&generic_pcre_offsets_table);
    }
    if (target_pcre_offsets_table_initialized) {
        cli_pcre_freeoff(&target_pcre_offsets_table);
    }

    if (info_initialized) {
        cli_targetinfo_destroy(&info);
    }

    if (bm_offsets_table_initialized) {
        cli_bm_freeoff(&bm_offsets_table);
    }

    if ((ret == CL_SUCCESS || ret >= CL_TYPENO) && ctx->report)
        cli_scan_report_note_detector_operation(ctx->report);

    if (ret != CL_SUCCESS) {
        return ret;
    }

    ret = (acmode & AC_SCAN_FT) ? type : CL_SUCCESS;
    return cli_matcher_reconcile_status(ctx, ret);
}

#define CDBRANGE(field, val)                                              \
    if (field[0] != CLI_OFF_ANY) {                                        \
        if (field[0] == field[1] && field[0] != val)                      \
            continue;                                                     \
        else if (field[0] != field[1] && ((field[0] && field[0] > val) || \
                                          (field[1] && field[1] < val)))  \
            continue;                                                     \
    }

cl_error_t cli_matchmeta(cli_ctx *ctx, const char *fname, size_t fsizec, size_t fsizer, int encrypted, unsigned int filepos, int res1)
{
    const struct cli_cdb *cdb;
    cl_error_t ret = CL_SUCCESS;

    if (!ctx || !ctx->recursion_stack || ctx->recursion_stack_size == 0 ||
        ctx->recursion_level >= ctx->recursion_stack_size) {
        cli_errmsg("cli_matchmeta: invalid scan context or recursion stack\n");
        return CL_ENULLARG;
    }
    if (!ctx->engine) {
        cli_errmsg("cli_matchmeta: engine == NULL\n");
        return CL_ENULLARG;
    }

    cli_dbgmsg("CDBNAME:%s:%llu:%s:%llu:%llu:%d:%u:%u\n",
               cli_ftname(cli_recursion_stack_get_type(ctx, -1)), (long long unsigned)fsizec, fname ? fname : "n/a", (long long unsigned)fsizec, (long long unsigned)fsizer,
               encrypted, filepos, res1);

    if (ctx->engine->cb_meta) {
        if (ctx->engine->cb_meta(cli_ftname(cli_recursion_stack_get_type(ctx, -1)), fsizec, fname, fsizer, encrypted, filepos, ctx->cb_ctx) == CL_VIRUS) {
            cli_dbgmsg("inner file blocked by callback: %s\n", fname);

            ret = cli_append_virus(ctx, "Detected.By.Callback");
            if (ret != CL_SUCCESS) {
                return ret;
            }
        }
    }

    if (NULL == (cdb = ctx->engine->cdb)) {
        return CL_CLEAN;
    }

    do {
        if (cdb->ctype != CL_TYPE_ANY && cdb->ctype != cli_recursion_stack_get_type(ctx, -1))
            continue;

        if (cdb->encrypted != 2 && cdb->encrypted != encrypted)
            continue;

        if (cdb->res1 && (cdb->ctype == CL_TYPE_ZIP || cdb->ctype == CL_TYPE_RAR) && cdb->res1 != res1)
            continue;

        CDBRANGE(cdb->csize, cli_recursion_stack_get_size(ctx, -1));
        CDBRANGE(cdb->fsizec, fsizec);
        CDBRANGE(cdb->fsizer, fsizer);
        CDBRANGE(cdb->filepos, filepos);

        if (cdb->name.re_magic && (!fname || cli_regexec(&cdb->name, fname, 0, NULL, 0) == REG_NOMATCH))
            continue;

        ret = cli_append_virus(ctx, cdb->virname);
        if (ret != CL_SUCCESS) {
            return ret;
        }

    } while ((cdb = cdb->next));

    return ret;
}
