/*
 *  Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 */

#ifndef __BMP_H
#define __BMP_H

#include "others.h"

/*
 * Validate the bounded BMP headers without mapping or decoding the pixel
 * payload. A structurally admitted BMP remains explicitly incomplete until a
 * full parser is qualified.
 */
cl_error_t cli_scanbmp(cli_ctx *ctx);

#endif
