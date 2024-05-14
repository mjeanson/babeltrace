/*
 * Copyright (c) 2024 EfficiOS, inc.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_CPP_COMMON_BT2C_FMT_HPP
#define BABELTRACE_CPP_COMMON_BT2C_FMT_HPP

#include "cpp-common/vendor/fmt/format.h" /* IWYU pragma: keep */
#include "cpp-common/vendor/wise-enum/wise_enum.h"

#include "uuid.hpp"

namespace internal {

template <typename T>
using EnableIfIsWiseEnum =
    typename std::enable_if<wise_enum::is_wise_enum<T>::value, wise_enum::string_type>::type;

} /* namespace internal */

namespace bt2 {

template <typename T>
::internal::EnableIfIsWiseEnum<T> format_as(const T val) noexcept
{
    return wise_enum::to_string<T>(val);
}

} /* namespace bt2 */

namespace bt2c {

template <typename T>
::internal::EnableIfIsWiseEnum<T> format_as(const T val) noexcept
{
    return wise_enum::to_string<T>(val);
}

inline std::string format_as(const UuidView uuid)
{
    return uuid.str();
}

} /* namespace bt2c */

#endif /* BABELTRACE_CPP_COMMON_BT2C_FMT_HPP */
