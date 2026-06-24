/*
 * Copyright (c) 2026 YuQing <384681@qq.com>
 *
 * This program is free software: you can use, redistribute, and/or modify
 * it under the terms of the Lesser GNU General Public License, version 3
 * or later ("LGPL"), as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 *
 * You should have received a copy of the Lesser GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "fc_version.h"

int fc_version(Version *version)
{
    version->major = FC_MAJOR_VERSION;
    version->minor = FC_MINOR_VERSION;
    version->patch = FC_PATCH_VERSION;
    return FC_VERSION_TO_INT1(*version);
}
