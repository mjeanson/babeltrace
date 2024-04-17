/*
 * Copyright (c) 2016-2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_CPP_COMMON_BT2C_TEXT_LOC_HPP
#define BABELTRACE_CPP_COMMON_BT2C_TEXT_LOC_HPP

namespace bt2c {

/*
 * Location in a multiline text.
 */
class TextLoc final
{
public:
    /*
     * Builds a text location which targets offset `offset` bytes,
     * zero-based line number `lineNo`, and zero-based column number
     * `colNo`.
     */
    explicit TextLoc(unsigned long long offset = 0, unsigned long long lineNo = 0,
                     unsigned long long colNo = 0) noexcept;

    /*
     * Offset (bytes).
     */
    unsigned long long offset() const noexcept
    {
        return _mOffset;
    }

    /*
     * Line number (zero-based).
     */
    unsigned long long lineNo() const noexcept
    {
        return _mLineNo;
    }

    /*
     * Column number (zero-based).
     */
    unsigned long long colNo() const noexcept
    {
        return _mColNo;
    }

    /*
     * Line number (one-based).
     */
    unsigned long long naturalLineNo() const noexcept
    {
        return _mLineNo + 1;
    }

    /*
     * Column number (one-based).
     */
    unsigned long long naturalColNo() const noexcept
    {
        return _mColNo + 1;
    }

private:
    unsigned long long _mOffset = 0;
    unsigned long long _mLineNo = 0;
    unsigned long long _mColNo = 0;
};

} /* namespace bt2c */

#endif /* BABELTRACE_CPP_COMMON_BT2C_TEXT_LOC_HPP */
