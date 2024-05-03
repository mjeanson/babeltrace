/*
 * Copyright (c) 2024 EfficiOS, Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_CPP_COMMON_BT2C_UNICODE_CONV_HPP
#define BABELTRACE_CPP_COMMON_BT2C_UNICODE_CONV_HPP

#include <cstddef>
#include <vector>

#include <glib.h>

#include "logging.hpp"

#include "aliases.hpp"

namespace bt2c {

/*
 * A Unicode converter offers the utf8FromUtf*() methods to convert
 * UTF-16 and UTF-32 data to UTF-8.
 *
 * IMPORTANT: The conversion methods aren't thread-safe: a `UnicodeConv`
 * instance keeps an internal buffer where it writes the resulting UTF-8
 * data.
 */
class UnicodeConv final
{
public:
    explicit UnicodeConv(const bt2c::Logger& parentLogger);
    ~UnicodeConv();

    /*
     * Converts the UTF-16BE data `data` to UTF-8 and returns it.
     *
     * `data.data()` must not return `nullptr`.
     *
     * The returned data belongs to this Unicode converter and remains
     * valid as long as you don't call another method of this.
     *
     * Logs a message, appends a cause to the error of the current
     * thread, and throws an error if any conversion error occurs,
     * including incomplete data in `data`.
     */
    ConstBytes utf8FromUtf16Be(ConstBytes data);

    /*
     * Converts the UTF-16LE data `data` to UTF-8 and returns it.
     *
     * `data.data()` must not return `nullptr`.
     *
     * The returned data belongs to this Unicode converter and remains
     * valid as long as you don't call another method of this.
     *
     * Logs a message, appends a cause to the error of the current
     * thread, and throws an error if any conversion error occurs,
     * including incomplete data in `data`.
     */
    ConstBytes utf8FromUtf16Le(ConstBytes data);

    /*
     * Converts the UTF-32BE data `data` to UTF-8 and returns it.
     *
     * `data.data()` must not return `nullptr`.
     *
     * The returned data belongs to this Unicode converter and remains
     * valid as long as you don't call another method of this.
     *
     * Logs a message, appends a cause to the error of the current
     * thread, and throws an error if any conversion error occurs,
     * including incomplete data in `data`.
     */
    ConstBytes utf8FromUtf32Be(ConstBytes data);

    /*
     * Converts the UTF-32LE data `data` to UTF-8 and returns it.
     *
     * `data.data()` must not return `nullptr`.
     *
     * The returned data belongs to this Unicode converter and remains
     * valid as long as you don't call another method of this.
     *
     * Logs a message, appends a cause to the error of the current
     * thread, and throws an error if any conversion error occurs,
     * including incomplete data in `data`.
     */
    ConstBytes utf8FromUtf32Le(ConstBytes data);

private:
    ConstBytes _justDoIt(const char *sourceEncoding, GIConv& converter, const ConstBytes data,
                         std::size_t codeUnitSize);

    bt2c::Logger _mLogger;
    GIConv _mUtf16BeToUtf8IConv;
    GIConv _mUtf16LeToUtf8IConv;
    GIConv _mUtf32BeToUtf8IConv;
    GIConv _mUtf32LeToUtf8IConv;
    std::vector<std::uint8_t> _mBuf;
};

} /* namespace bt2c */

#endif /* BABELTRACE_CPP_COMMON_BT2C_UNICODE_CONV_HPP */
