/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_CPP_COMMON_BT2C_DATA_LEN_HPP
#define BABELTRACE_CPP_COMMON_BT2C_DATA_LEN_HPP

#include "safe-ops.hpp"

namespace bt2c {

/*
 * A data length is a quantity of binary data (bits).
 *
 * This class can make some code clearer and safer because its
 * constructor is private so that you need to call DataLen::fromBits()
 * or DataLen::fromBytes() to create an instance.
 *
 * With a `DataLen` instance `len`, use `*len` or `len.bits()` to get
 * the quantity in bits and `len.bytes()` to get it in bytes (floored).
 *
 * You can add, subtract, and compare data lengths.
 */
class DataLen final
{
private:
    constexpr explicit DataLen(const unsigned long long lenBits) noexcept : _mLenBits {lenBits}
    {
    }

public:
    /*
     * Creates and returns a data length instance representing `lenBits`
     * bits.
     */
    static constexpr DataLen fromBits(const unsigned long long lenBits) noexcept
    {
        return DataLen {lenBits};
    }

    /*
     * Creates and returns a data length instance representing
     * `lenBytes` bytes.
     */
    static DataLen fromBytes(const unsigned long long lenBytes) noexcept
    {
        return DataLen {safeMul(lenBytes, 8ULL)};
    }

    /*
     * Number of bits of this data length.
     */
    constexpr unsigned long long operator*() const noexcept
    {
        return _mLenBits;
    }

    /*
     * Number of bits of this data length.
     */
    constexpr unsigned long long bits() const noexcept
    {
        return _mLenBits;
    }

    /*
     * Number of bytes (floor) of this data length.
     */
    constexpr unsigned long long bytes() const noexcept
    {
        return _mLenBits / 8;
    }

    /*
     * Whether or not this data length represents a multiple of eight
     * bits.
     */
    constexpr bool hasExtraBits() const noexcept
    {
        return this->extraBitCount() > 0;
    }

    /*
     * Remainder of this data length, in bits, divided by eight.
     */
    constexpr unsigned int extraBitCount() const noexcept
    {
        return _mLenBits & 7;
    }

    /*
     * Returns whether or not this data length is a power of two bits.
     */
    constexpr bool isPowOfTwo() const noexcept
    {
        return ((_mLenBits & (_mLenBits - 1)) == 0) && _mLenBits > 0;
    }

    constexpr bool operator==(const DataLen& other) const noexcept
    {
        return _mLenBits == other._mLenBits;
    }

    constexpr bool operator!=(const DataLen& other) const noexcept
    {
        return !(*this == other);
    }

    constexpr bool operator<(const DataLen& other) const noexcept
    {
        return _mLenBits < other._mLenBits;
    }

    constexpr bool operator<=(const DataLen& other) const noexcept
    {
        return (*this == other) || (*this < other);
    }

    constexpr bool operator>(const DataLen& other) const noexcept
    {
        return !(*this <= other);
    }

    constexpr bool operator>=(const DataLen& other) const noexcept
    {
        return (*this > other) || (*this == other);
    }

    DataLen& operator+=(const DataLen len) noexcept
    {
        _mLenBits = safeAdd(_mLenBits, len._mLenBits);
        return *this;
    }

    DataLen& operator-=(const DataLen len) noexcept
    {
        _mLenBits = safeSub(_mLenBits, len._mLenBits);
        return *this;
    }

    DataLen& operator*=(const unsigned long long mul) noexcept
    {
        _mLenBits = safeMul(_mLenBits, mul);
        return *this;
    }

private:
    unsigned long long _mLenBits = 0;
};

inline DataLen operator+(const DataLen lenA, const DataLen lenB) noexcept
{
    return DataLen::fromBits(safeAdd(*lenA, *lenB));
}

inline DataLen operator-(const DataLen lenA, const DataLen lenB) noexcept
{
    return DataLen::fromBits(safeSub(*lenA, *lenB));
}

inline DataLen operator*(const DataLen len, const unsigned long long mul) noexcept
{
    return DataLen::fromBits(safeMul(*len, mul));
}

/*
 * Use this namespace to access handy data length user literals, for
 * example:
 *
 *     using namespace bt2c::literals::datalen;
 *
 *     const auto bufSize = 64_MiBytes + 8_KiBits;
 */
namespace literals {
namespace datalen {

inline DataLen operator"" _bits(const unsigned long long val) noexcept
{
    return DataLen::fromBits(val);
}

inline DataLen operator"" _KiBits(const unsigned long long val) noexcept
{
    return DataLen::fromBits(safeMul(val, 1024ULL));
}

inline DataLen operator"" _MiBits(const unsigned long long val) noexcept
{
    return DataLen::fromBits(safeMul(val, 1024ULL * 1024));
}

inline DataLen operator"" _GiBits(const unsigned long long val) noexcept
{
    return DataLen::fromBits(safeMul(val, 1024ULL * 1024 * 1024));
}

inline DataLen operator"" _bytes(const unsigned long long val) noexcept
{
    return DataLen::fromBytes(val);
}

inline DataLen operator"" _KiBytes(const unsigned long long val) noexcept
{
    return DataLen::fromBytes(safeMul(val, 1024ULL));
}

inline DataLen operator"" _MiBytes(const unsigned long long val) noexcept
{
    return DataLen::fromBytes(safeMul(val, 1024ULL * 1024));
}

inline DataLen operator"" _GiBytes(const unsigned long long val) noexcept
{
    return DataLen::fromBytes(safeMul(val, 1024ULL * 1024 * 1024));
}

} /* namespace datalen */
} /* namespace literals */
} /* namespace bt2c */

#endif /* BABELTRACE_CPP_COMMON_BT2C_DATA_LEN_HPP */
