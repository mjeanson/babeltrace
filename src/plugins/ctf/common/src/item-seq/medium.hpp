/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_PLUGINS_CTF_COMMON_SRC_ITEM_SEQ_MEDIUM_HPP
#define BABELTRACE_PLUGINS_CTF_COMMON_SRC_ITEM_SEQ_MEDIUM_HPP

#include <cstdint>
#include <cstdlib>
#include <memory>
#include <stdexcept>

#include "cpp-common/bt2c/data-len.hpp"

namespace ctf {
namespace src {

/*
 * Data buffer: address and size.
 */
class Buf final
{
public:
    /*
     * Builds a 0-bytes buffer.
     */
    explicit Buf() noexcept = default;

    /*
     * Builds a buffer at the address `addr` and having the size `size`.
     *
     * The bytes at `addr` are owned by the medium returning the buffer,
     * not by this object.
     *
     * `addr` must not be `nullptr`.
     *
     * `*size` must be greater than zero.
     *
     * `size.hasExtraBits()` must be false.
     */
    explicit Buf(const std::uint8_t *addr, bt2c::DataLen size) noexcept;

    /* Default copy operations */
    Buf(const Buf&) noexcept = default;
    Buf& operator=(const Buf&) noexcept = default;

    /*
     * Address of this buffer.
     *
     * Only relevant if size() returns a value greater than zero.
     */
    const std::uint8_t *addr() const noexcept
    {
        return _mAddr;
    }

    /*
     * Size of this buffer.
     */
    bt2c::DataLen size() const noexcept
    {
        return _mSize;
    }

    /*
     * Returns a slice of this buffer from the offset `offset` to
     * the end.
     *
     * `offset` must be less than or equal to what size() returns.
     *
     * `offset.hasExtraBits()` must be false.
     */
    Buf slice(bt2c::DataLen offset) const noexcept;

private:
    const std::uint8_t *_mAddr = nullptr;
    bt2c::DataLen _mSize = bt2c::DataLen::fromBits(0);
};

class NoData final : public std::exception
{
public:
    explicit NoData() noexcept = default;
};

/*
 * A medium is the data provider of an item sequence iterator.
 *
 * A concrete medium class needs to implement:
 *
 * • nextBuf() to return the next buffer of data.
 * • seek() to change its position.
 *
 * On construction, the current offset of the medium is 0.
 */
class Medium
{
public:
    using UP = std::unique_ptr<Medium>;

protected:
    explicit Medium() noexcept = default;

public:
    virtual ~Medium() = default;

    /*
     * Returns the buffer at the offset `offset` having a size of at
     * least `minSize`.
     *
     * The returned buffer is to be read only and borrowed: it remains
     * owned by this medium. Calling this method invalidates the
     * previously returned buffer by the same medium.
     *
     * `offset.hasExtraBits()` must be false.
     *
     * `offset` doesn't need to be aligned in any special way.
     *
     * `minSize.bytes()` must be less than ten.
     *
     * `minSize.hasExtraBits()` must be false.
     *
     * This method may throw:
     *
     * `NoData`:
     *     There's no data at the offset `offset`.
     *
     * `bt2c::TryAgain`:
     *     No data is available right now: try again later.
     *
     * Other:
     *     User error.
     */
    virtual Buf buf(bt2c::DataLen offset, bt2c::DataLen minSize) = 0;
};

} /* namespace src */
} /* namespace ctf */

#endif /* BABELTRACE_PLUGINS_CTF_COMMON_SRC_ITEM_SEQ_MEDIUM_HPP */
