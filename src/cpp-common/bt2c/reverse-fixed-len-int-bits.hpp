/*
 * Copyright (c) 2024 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_CPP_COMMON_BT2C_REVERSE_FIXED_LEN_INT_BITS_HPP
#define BABELTRACE_CPP_COMMON_BT2C_REVERSE_FIXED_LEN_INT_BITS_HPP

#include <cstddef>
#include <cstdint>

#include "common/assert.h"

#include "data-len.hpp"

namespace bt2c {
namespace internal {

/*
 * Swaps the bits.
 *
 * And then returns the result.
 *
 * See <https://matthewarcus.wordpress.com/2012/11/18/reversing-a-64-bit-word/>.
 */
template <typename T, T MaskV, std::size_t ShiftV>
T swapBits(const T p) noexcept
{
    const auto q = ((p >> ShiftV) ^ p) & MaskV;

    return p ^ q ^ (q << ShiftV);
}

} /* namespace internal */

/*
 * Based on Knuth's.
 *
 * For example, given an unsigned `val` with the value 0b111011010 and
 * `*len` set to 9, the returned value is 0b010110111.
 *
 * Given a _signed_ `val` with the value 0b01011 and `*len` set to 5,
 * the returned value is
 * 0b1111111111111111111111111111111111111111111111111111111111111010
 * (sign extended).
 *
 * `*len` must be less than or equal to 64.
 */
template <typename ValT>
ValT reverseFixedLenIntBits(const ValT val, const DataLen len)
{
    static_assert(sizeof(val) == sizeof(std::uint64_t), "`val` is a 64-bit integer");

    BT_ASSERT_DBG(*len <= 64);

    static constexpr std::uint64_t m0 = 0x5555555555555555ULL;

    /* Work with the unsigned version to perform the reversal */
    auto uVal = static_cast<std::uint64_t>(val);

    uVal = ((uVal >> 1) & m0) | (uVal & m0) << 1;
    uVal = internal::swapBits<std::uint64_t, 0x0300c0303030c303ULL, 4>(uVal);
    uVal = internal::swapBits<std::uint64_t, 0x00c0300c03f0003fULL, 8>(uVal);
    uVal = internal::swapBits<std::uint64_t, 0x00000ffc00003fffULL, 20>(uVal);
    uVal = (uVal >> 34) | (uVal << 30);

    /*
     * Sign-extends when `ValT` is signed because in that case the sign
     * bit (LSB of `val`) is at position 63 before this shift.
     */
    return static_cast<ValT>(uVal) >> (64 - *len);
}

} /* namespace bt2c */

#endif /* BABELTRACE_CPP_COMMON_BT2C_REVERSE_FIXED_LEN_INT_BITS_HPP */
