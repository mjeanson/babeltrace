/*
 * Copyright (c) 2022-2024 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_CPP_COMMON_BT2C_PARSE_JSON_AS_VAL_HPP
#define BABELTRACE_CPP_COMMON_BT2C_PARSE_JSON_AS_VAL_HPP

#include <cstdlib>

#include "logging.hpp"

#include "cpp-common/bt2s/string-view.hpp"

#include "json-val.hpp"

namespace bt2c {

/*
 * Parses the JSON text `str` and returns the resulting JSON value,
 * adding `baseOffset` to the text location offset of all the created
 * JSON values.
 *
 * When this function logs or appends a cause to the error of the
 * current thread, it uses `baseOffset` to format the text location part
 * of the message.
 */
JsonVal::UP parseJson(bt2s::string_view str, std::size_t baseOffset, const Logger& logger);

inline JsonVal::UP parseJson(const bt2s::string_view str, const Logger& logger)
{
    return parseJson(str, 0, logger);
}

} /* namespace bt2c */

#endif /* BABELTRACE_CPP_COMMON_BT2C_PARSE_JSON_AS_VAL_HPP */
