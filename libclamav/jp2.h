/*
 *  Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 */

#ifndef __JP2_H
#define __JP2_H

#include "others.h"

/*
 * Validate bounded JP2 box structure without mapping or decoding the
 * codestream payload. A structurally admitted JP2 remains explicitly
 * incomplete until a full parser is qualified.
 */
cl_error_t cli_scanjp2(cli_ctx *ctx);

#endif
