/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Alberto Wu
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

#ifndef __PETITE_H
#define __PETITE_H

#include "clamav-types.h"
#include "pe.h"

struct cli_ctx_tag;

/* Convert a Petite image RVA plus a signed adjustment to a zero-based window
 * in the reconstructed buffer without forming an out-of-object intermediate
 * pointer. */
int cli_petite_rva_window_offset(uint32_t base_rva, uint32_t target_rva,
                                 int64_t adjustment, size_t available,
                                 size_t needed, size_t *offset);
int cli_petite_length_step(uint32_t value, uint32_t bit, uint32_t *next);

int petite_inflate2x_1to9(char *buf, uint32_t minrva, uint32_t bufsz, struct cli_exe_section *sections, unsigned int sectcount, uint32_t Imagebase, uint32_t pep, int desc, int version, uint32_t ResRva, uint32_t ResSize, struct cli_ctx_tag *);

#endif
