/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2011-2013 Sourcefire, Inc.
 *
 *  Authors: aCaB
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

#ifndef __ASN1_H
#define __ASN1_H

#include "others.h"
#include "fmap.h"

struct cli_mapped_region {
    size_t offset;
    size_t size;
};

/* Authenticode hashes may cover almost the entire input file.  Keep each fmap
 * request bounded so a multi-gigabyte PE never has to be prefaulted as one
 * contiguous region. */
#define CLI_AUTHENTICODE_HASH_CHUNK_SIZE (1024U * 1024U)

/**
 * Feed a list of fmap regions into an initialized hash context.
 *
 * The regions are validated against map->len before any bytes are hashed and
 * are then read in fixed-size chunks.  A read, coordinate, or digest failure
 * marks the scan incomplete when a scan context is supplied, preventing a
 * partial Authenticode/catalog calculation from trusting the layer.
 *
 * The caller owns hash_ctx and must finish it after CL_SUCCESS or destroy it
 * after any error.
 */
cl_error_t cli_hash_mapped_regions(fmap_t *map, void *hash_ctx, const struct cli_mapped_region *regions, uint32_t nregions, cli_ctx *ctx);

int asn1_load_mscat(fmap_t *map, struct cl_engine *engine);
cl_error_t asn1_check_mscat(struct cl_engine *engine, fmap_t *map, size_t offset, unsigned int size, const struct cli_mapped_region *regions, uint32_t nregions, cli_ctx *ctx);

#endif
