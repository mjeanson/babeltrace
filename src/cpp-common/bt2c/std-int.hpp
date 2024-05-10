/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_CPP_COMMON_BT2C_STD_INT_HPP
#define BABELTRACE_CPP_COMMON_BT2C_STD_INT_HPP

#include <cstdint>

namespace bt2c {

/*
 * Whether or not an integer is signed.
 */
enum class Signedness
{
    Unsigned,
    Signed,
};

namespace internal {

template <std::size_t LenBitsV, Signedness SignednessV>
struct StdIntTBase;

template <>
struct StdIntTBase<8, Signedness::Signed>
{
    using Type = std::int8_t;
};

template <>
struct StdIntTBase<8, Signedness::Unsigned>
{
    using Type = std::uint8_t;
};

template <>
struct StdIntTBase<16, Signedness::Signed>
{
    using Type = std::int16_t;
};

template <>
struct StdIntTBase<16, Signedness::Unsigned>
{
    using Type = std::uint16_t;
};

template <>
struct StdIntTBase<32, Signedness::Signed>
{
    using Type = std::int32_t;
};

template <>
struct StdIntTBase<32, Signedness::Unsigned>
{
    using Type = std::uint32_t;
};

template <>
struct StdIntTBase<64, Signedness::Signed>
{
    using Type = std::int64_t;
};

template <>
struct StdIntTBase<64, Signedness::Unsigned>
{
    using Type = std::uint64_t;
};

} /* namespace internal */

/*
 * Standard fixed-length integer type `Type` of length `LenBitsV` bits
 * and signedness `SignednessV`.
 *
 * `LenBitsV` must be one of 8, 16, 32, or 64.
 *
 * For example, `StdIntT<32, Signedness::Signed>` is `std::int32_t`.
 */
template <std::size_t LenBitsV, Signedness SignednessV>
using StdIntT = typename internal::StdIntTBase<LenBitsV, SignednessV>::Type;

} /* namespace bt2c */

#endif /* BABELTRACE_CPP_COMMON_BT2C_STD_INT_HPP */
