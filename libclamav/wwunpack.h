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

#ifndef __WWP32_H
#define __WWP32_H

#include "clamav-types.h"
#include "execs.h"

struct cli_ctx_tag;

/* Convert WWPack's section-relative source description to a bounded native
 * input window without performing wrapped 32-bit subtraction or addition. */
int cli_wwpack_source_window_offset(uint32_t section_rva, uint32_t source_delta,
                                    uint32_t source_end, uint32_t compressed_size,
                                    size_t available, size_t *offset);

cl_error_t wwunpack(uint8_t *, uint32_t, uint8_t *, struct cli_exe_section *, uint16_t, uint32_t, int, struct cli_ctx_tag *);

#endif
