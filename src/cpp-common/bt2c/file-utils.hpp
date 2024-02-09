/*
 * Copyright (c) 2022 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_CPP_COMMON_FILE_UTILS_HPP
#define BABELTRACE_CPP_COMMON_FILE_UTILS_HPP

#include <cstdint>
#include <vector>

namespace bt2c {

/*
 * Returns a vector of all the bytes contained in `path`.
 */
std::vector<std::uint8_t> dataFromFile(const char *path);

} /* namespace bt2c */

#endif /* BABELTRACE_CPP_COMMON_FILE_UTILS_HPP */
