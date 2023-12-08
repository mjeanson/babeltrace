/*
 * Copyright (c) 2016-2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_CPP_COMMON_BT2C_TEXT_LOC_STR_HPP
#define BABELTRACE_CPP_COMMON_BT2C_TEXT_LOC_STR_HPP

#include <string>

#include "text-loc.hpp"

namespace bt2c {

/*
 * Text location string format.
 */
enum class TextLocStrFmt
{
    Offset,
    LineColNosAndOffset,
    LineColNos,
};

/*
 * Formats the text location `loc` as a string following the format
 * `fmt`.
 */
std::string textLocStr(const TextLoc& loc, TextLocStrFmt fmt);

} /* namespace bt2c */

#endif /* BABELTRACE_CPP_COMMON_BT2C_TEXT_LOC_STR_HPP */
