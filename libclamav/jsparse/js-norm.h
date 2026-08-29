/*
 *  Javascript normalizer.
 *
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2008-2013 Sourcefire, Inc.
 *
 *  Authors: Török Edvin
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
#ifndef JS_NORM_H
#define JS_NORM_H
#include <stddef.h>
#include <stdint.h>

struct parser_state;
struct text_buffer;
struct cli_ctx_tag;

cl_error_t cli_jsnorm_table_size(size_t count, size_t element_size, size_t *bytes);
struct parser_state *cli_js_init(void);
void cli_js_process_buffer(struct parser_state *state, const char *buf, size_t n);
void cli_js_parse_done(struct parser_state *state);
cl_error_t cli_js_output(struct parser_state *state, const char *tempdir);
cl_error_t cli_js_output_ctx(struct parser_state *state, const char *tempdir, struct cli_ctx_tag *ctx);
cl_error_t cli_js_output_ctx_with_quota(struct parser_state *state, const char *tempdir,
                                        struct cli_ctx_tag *ctx, uint64_t *temporary_reserved);
void cli_js_destroy(struct parser_state *state);

char *cli_unescape(const char *str);

#endif
