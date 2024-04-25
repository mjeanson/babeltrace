/*
 * Copyright (c) 2022 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_CPP_COMMON_BT2C_FILE_UTILS_HPP
#define BABELTRACE_CPP_COMMON_BT2C_FILE_UTILS_HPP

#include <cstdint>
#include <vector>

#include "c-string-view.hpp"

namespace bt2c {

class Logger;

/*
 * Returns a vector of all the bytes contained in `path`.
 *
 * Throws `NoSuchFileOrDirectoryError` if the file does not exist.
 *
 * If `fatalError` is true, log an error and appends an error
 * cause prior to throwing.  Otherwise, log at the debug level.
 */
std::vector<std::uint8_t> dataFromFile(const CStringView path, const Logger& logger,
                                       bool fatalError);

} /* namespace bt2c */

#endif /* BABELTRACE_CPP_COMMON_BT2C_FILE_UTILS_HPP */
