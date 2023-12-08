/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_CPP_COMMON_BT2C_BT2_VALUE_FROM_JSON_VAL_HPP
#define BABELTRACE_CPP_COMMON_BT2C_BT2_VALUE_FROM_JSON_VAL_HPP

#include "cpp-common/bt2/value.hpp"

#include "json-val.hpp"

namespace bt2c {

/*
 * Converts the JSON value `jsonVal` to an equivalent Babeltrace 2 value
 * object and returns it.
 */
bt2::Value::Shared bt2ValueFromJsonVal(const JsonVal& jsonVal);

} /* namespace bt2c */

#endif /* BABELTRACE_CPP_COMMON_BT2C_BT2_VALUE_FROM_JSON_VAL_HPP */
