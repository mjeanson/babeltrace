/*
 * Copyright (c) 2024 EfficiOS, Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <glib.h>

#include "common/assert.h"
#include "cpp-common/bt2/exc.hpp"

#include "unicode-conv.hpp"

namespace bt2c {
namespace {

const auto invalidGIConv = reinterpret_cast<GIConv>(-1);

} /* namespace */

UnicodeConv::UnicodeConv(const bt2c::Logger& parentLogger) :
    _mLogger {parentLogger, "UNICODE-CONV"}, _mUtf16BeToUtf8IConv {invalidGIConv},
    _mUtf16LeToUtf8IConv {invalidGIConv}, _mUtf32BeToUtf8IConv {invalidGIConv},
    _mUtf32LeToUtf8IConv {invalidGIConv}
{
}

namespace {

void tryCloseGIConv(const GIConv conv) noexcept
{
    if (conv != invalidGIConv) {
        g_iconv_close(conv);
    }
};

} /* namespace */

UnicodeConv::~UnicodeConv()
{
    tryCloseGIConv(_mUtf16BeToUtf8IConv);
    tryCloseGIConv(_mUtf16LeToUtf8IConv);
    tryCloseGIConv(_mUtf32BeToUtf8IConv);
    tryCloseGIConv(_mUtf32LeToUtf8IConv);
}

ConstBytes UnicodeConv::_justDoIt(const char * const srcEncoding, GIConv& conv,
                                  const ConstBytes data, const std::size_t codeUnitSize)
{
    /* Create iconv conversion descriptor if not created already */
    if (conv == invalidGIConv) {
        conv = g_iconv_open("UTF-8", srcEncoding);

        if (conv == invalidGIConv) {
            BT_CPPLOGE_ERRNO_APPEND_CAUSE_AND_THROW(bt2::Error, "g_iconv_open() failed",
                                                    ": from-encoding={}, to-encoding=UTF-8",
                                                    srcEncoding);
        }
    }

    /*
     * Compute a dumb, but safe upper bound for the UTF-8 output buffer.
     *
     * The input string can encode up to `data.size() / codeUnitSize`
     * codepoints. Then, each code point can take up to four bytes in
     * UTF-8.
     */
    _mBuf.resize(data.size() / codeUnitSize * 4);

    /* Convert */
    gsize inBytesLeft = data.size();
    gsize outBytesLeft = _mBuf.size();
    auto inBuf = const_cast<gchar *>(reinterpret_cast<const gchar *>(data.data()));
    auto outBuf = reinterpret_cast<gchar *>(_mBuf.data());

    if (g_iconv(conv, &inBuf, &inBytesLeft, &outBuf, &outBytesLeft) == -1) {
        BT_CPPLOGE_ERRNO_APPEND_CAUSE_AND_THROW(
            bt2::Error, "g_iconv() failed",
            ": input-byte-offset={}, from-encoding={}, to-encoding=UTF-8",
            data.size() - inBytesLeft, srcEncoding);
    }

    /*
     * When g_iconv() is successful, assert that it consumed all input.
     *
     * The (underlying) iconv() documentation outlines three
     * failure modes:
     *
     * 1. Insufficient output buffer space.
     * 2. Invalid multibyte sequence in input.
     * 3. Incomplete multibyte sequence in input.
     *
     * For any malformed input, iconv() will return error 2 or 3.
     *
     * This suggests that, barring input errors, a successful conversion
     * will consume all input bytes.
     */
    BT_ASSERT(inBytesLeft == 0);
    return {_mBuf.data(), _mBuf.size() - outBytesLeft};
}

ConstBytes UnicodeConv::utf8FromUtf16Be(const ConstBytes data)
{
    return this->_justDoIt("UTF-16BE", _mUtf16BeToUtf8IConv, data, 2);
}

ConstBytes UnicodeConv::utf8FromUtf16Le(const ConstBytes data)
{
    return this->_justDoIt("UTF-16LE", _mUtf16LeToUtf8IConv, data, 2);
}

ConstBytes UnicodeConv::utf8FromUtf32Be(const ConstBytes data)
{
    return this->_justDoIt("UTF-32BE", _mUtf32BeToUtf8IConv, data, 4);
}

ConstBytes UnicodeConv::utf8FromUtf32Le(const ConstBytes data)
{
    return this->_justDoIt("UTF-32LE", _mUtf32LeToUtf8IConv, data, 4);
}

} /* namespace bt2c */
