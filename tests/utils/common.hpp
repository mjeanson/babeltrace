/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2024 EfficiOS Inc.
 */

#ifndef BABELTRACE_TESTS_UTILS_COMMON_HPP
#define BABELTRACE_TESTS_UTILS_COMMON_HPP

#include <cstdint>

#include <babeltrace2/babeltrace.h>

template <typename FuncT>
void forEachMipVersion(FuncT&& func)
{
    for (std::uint64_t v = 0; v <= bt_get_maximal_mip_version(); ++v) {
        func(v);
    }
}

#endif /* BABELTRACE_TESTS_UTILS_COMMON_HPP */
