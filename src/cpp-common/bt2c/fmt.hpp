/*
 * Copyright (c) 2024 EfficiOS, inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include "common/common.h"
#include "cpp-common/bt2/message.hpp"
#include "cpp-common/vendor/fmt/format.h" /* IWYU pragma: keep */
#include "cpp-common/vendor/wise-enum/wise_enum.h"

#include "uuid.hpp"

namespace internal {

template <typename T>
using EnableIfIsWiseEnum =
    typename std::enable_if<wise_enum::is_wise_enum<T>::value, const char *>::type;

} /* namespace internal */

namespace bt2 {

template <typename T>
::internal::EnableIfIsWiseEnum<T> format_as(const T val) noexcept
{
    return wise_enum::to_string<T>(val);
}

inline const char *format_as(const MessageType type)
{
    return bt_common_message_type_string(static_cast<bt_message_type>(type));
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
