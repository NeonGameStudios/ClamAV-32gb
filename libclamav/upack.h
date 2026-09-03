/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Michal 'GiM' Spadlinski
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

#ifndef __UPACK_H
#define __UPACK_H

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "clamav-types.h"

struct cli_ctx_tag;

/* Convert a Upack image coordinate plus a signed instruction displacement to
 * a bounded zero-based window in the reconstructed buffer. */
int cli_upack_rva_window_offset(uint32_t base_rva, uint32_t target_rva,
                                int64_t adjustment, size_t available,
                                size_t needed, size_t *offset);

int unupack(int, char *, uint32_t, char *, uint32_t, uint32_t, uint32_t, uint32_t, int, struct cli_ctx_tag *);

#endif
