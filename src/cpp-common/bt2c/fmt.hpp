/*
 * Copyright (c) 2024 EfficiOS, inc.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_CPP_COMMON_BT2C_FMT_HPP
#define BABELTRACE_CPP_COMMON_BT2C_FMT_HPP

#include "cpp-common/bt2/value.hpp"
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

inline std::string format_as(const bt2::ConstValue val) noexcept
{
    switch (val.type()) {
    case ValueType::Null:
        return "null";

    case ValueType::Bool:
        return val.asBool().value() ? "true" : "false";

    case ValueType::UnsignedInteger:
        return fmt::format("{}u", val.asUnsignedInteger().value());

    case ValueType::SignedInteger:
        return fmt::format("{}", val.asSignedInteger().value());

    case ValueType::Real:
        return fmt::format("{}", val.asReal().value());

    case ValueType::String:
        return fmt::format("\"{}\"", val.asString().value());

    case ValueType::Array:
    {
        std::string ret {'['};
        const char *maybeComma = "";

        for (const auto elem : val.asArray()) {
            ret += fmt::format("{}{}", maybeComma, elem);
            maybeComma = ", ";
        }

        ret += ']';
        return ret;
    }

    case ValueType::Map:
    {
        std::string ret {'{'};
        const char *maybeComma = "";

        val.asMap().forEach([&](const bt2c::CStringView k, const bt2::ConstValue v) {
            ret += fmt::format("{}{}: {}", maybeComma, k, v);
            maybeComma = ", ";
        });

        ret += '}';
        return ret;
    }
    }

    bt_common_abort();
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
