/*
 * Copyright (c) 2024 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_PLUGINS_CTF_COMMON_SRC_NULL_CP_FINDER_HPP
#define BABELTRACE_PLUGINS_CTF_COMMON_SRC_NULL_CP_FINDER_HPP

#include <array>
#include <cstdlib>

#include "cpp-common/bt2c/aliases.hpp"
#include "cpp-common/bt2s/optional.hpp"

namespace ctf {
namespace src {

/*
 * Null (U+0000) codepoint finder.
 *
 * An instance of this class keeps a temporary code unit of length
 * `CodeUnitLenV` bytes.
 *
 * Call findNullCp() to try to find the first U+0000 codepoint within
 * some string data part, updating the state of the finder at the same
 * time.
 *
 * When decoding a UTF-16/UTF-32 null-terminated string, the bytes of
 * the encoded U+0000 codepoint may span more than one medium buffer.
 *
 * For example, consider this scenario:
 *
 *     ╔═══════════════════════════════════════════════════════════════╗
 *     ║                            This null byte part of             ║
 *     ║                            the first U+0000 codepoint         ║
 *     ║                            ┆                                  ║
 *     ║ Current buffer             ┆     Next buffer                  ║
 *     ║ ┈┈┈────────────────────────▼──┐ ┌────────────────────────┈┈┈  ║
 *     ║    64 00 20 00 3c d8 3b df 00 │ │ 00 1f fc cc bc 44 35 56     ║
 *     ║ ┈┈┈▲──────────────────────────┘ └─▲──────────────────────┈┈┈  ║
 *     ║    ┆                              ┆                           ║
 *     ║    Code unit                      This null byte also part of ║
 *     ║    beginning                      the first U+0000 codepoint  ║
 *     ╚═══════════════════════════════════════════════════════════════╝
 *
 * Assume a UTF-16LE encoding (code unit size is two). Then there are
 * four complete code units in the current buffer, and half of one (the
 * last null byte).
 *
 * The two null bytes of the first U+0000 codepoint are within two
 * different buffers.
 *
 * The strategy here is keep each code unit in a temporary buffer
 * (`_mCodeUnitBuf`), along with its length in bytes
 * (`_mCodeUnitBufLen`). In findNullCp(), when `_mCodeUnitBufLen`
 * reaches the `CodeUnitLenV` while decoding, then we check if it
 * encodes U+0000.
 *
 * In the example above, after reading that the null byte of the current
 * buffer, `_mCodeUnitBuf[0]` is zero and `_mCodeUnitBufLen` is one.
 *
 * Afterwards, when given the next buffer, findNullCp() continues
 * reading the current code unit, making `_mCodeUnitBuf[1]` zero and
 * `_mCodeUnitBufLen` two. Since `_mCodeUnitBufLen` is equal to the code
 * unit size, the method can check the current code unit value: two
 * zeros, which means U+0000, which means the end of that
 * null-terminated string.
 */
template <std::size_t CodeUnitLenV>
class NullCpFinder final
{
    static_assert(CodeUnitLenV == 1 || CodeUnitLenV == 2 || CodeUnitLenV == 4,
                  "`CodeUnitLenV` is 1 (UTF-8), 2 (UTF-16), or 4 (UTF-32).");

public:
    explicit NullCpFinder() = default;

    /*
     * Tries to find the first U+0000 codepoint in `buffer` considering
     * what you already passed to this method and `CodeUnitLenV`.
     *
     * Returns an iterator _after_ the end of the encoded U+0000
     * codepoint on success, or `bt2s::nullopt` when it didn't find any
     * U+0000 codepoint. This means this method may return `str.end()`
     * if `str` finishes with a U+0000 codepoint.
     */
    bt2s::optional<bt2c::ConstBytes::const_iterator>
    findNullCp(const bt2c::ConstBytes buffer) noexcept
    {
        for (auto it = buffer.begin(); it != buffer.end(); ++it) {
            _mCodeUnitBuf[_mCodeUnitBufLen] = *it;
            ++_mCodeUnitBufLen;

            if (_mCodeUnitBufLen == CodeUnitLenV) {
                /* New complete code unit: is it U+0000? */
                if (_mCodeUnitBuf == _CodeUnitBuf {0}) {
                    /* Found U+0000 */
                    return it + 1;
                }

                /* New empty code unit */
                _mCodeUnitBufLen = 0;
            }
        }

        /* No U+0000 codepoint found */
        return bt2s::nullopt;
    }

private:
    /* Code unit buffer type */
    using _CodeUnitBuf = std::array<char, CodeUnitLenV>;

    /* Code unit buffer */
    _CodeUnitBuf _mCodeUnitBuf;

    /* Code unit buffer length */
    std::size_t _mCodeUnitBufLen = 0;
};

} /* namespace src */
} /* namespace ctf */

#endif /* BABELTRACE_PLUGINS_CTF_COMMON_SRC_NULL_CP_FINDER_HPP */
