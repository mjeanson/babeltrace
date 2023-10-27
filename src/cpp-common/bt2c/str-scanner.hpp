/*
 * Copyright (c) 2015-2024 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_CPP_COMMON_BT2C_STR_SCANNER_HPP
#define BABELTRACE_CPP_COMMON_BT2C_STR_SCANNER_HPP

#include <cstdlib>
#include <limits>
#include <string>

#include "common/assert.h"
#include "cpp-common/bt2c/logging.hpp"
#include "cpp-common/bt2c/regex.hpp"
#include "cpp-common/bt2s/string-view.hpp"

#include "text-loc.hpp"

namespace bt2c {

/*
 * String scanner.
 *
 * A string scanner (lexer) wraps an input string view and scans
 * specific characters and sequences of characters, managing a
 * current position.
 *
 * When you call the various tryScan*() methods to try to scan some
 * contents, the methods advance the current position on success. They
 * also automatically skip initial whitespaces.
 */
class StrScanner final
{
public:
    using Iter = bt2s::string_view::const_iterator;

    /*
     * Builds a string scanner, wrapping the string `str`.
     *
     * When the string scanner logs or appends a cause to the error of
     * the current thread, it uses `baseOffset` to format the text
     * location part of the message.
     */
    explicit StrScanner(bt2s::string_view str, std::size_t baseOffset, const Logger& logger);

    /*
     * Alternative constructor setting the `baseOffset` parameter to 0.
     */
    explicit StrScanner(bt2s::string_view str, const Logger& logger);

    /*
     * Returns the current position.
     */
    Iter at() const noexcept
    {
        return _mAt;
    }

    /*
     * Sets the current position to `at`.
     *
     * NOTE: This may corrupt the current text location (loc()) if the
     * string between at() and `at` includes one or more
     * newline characters.
     */
    void at(const Iter at) noexcept
    {
        BT_ASSERT_DBG(at >= _mStr.begin() && at <= _mStr.end());
        _mAt = at;
    }

    /*
     * Returns the viewed string, the one with which this string scanner
     * was built.
     */
    bt2s::string_view str() const noexcept
    {
        return _mStr;
    }

    /*
     * Returns the number of characters left until `str().end()`.
     */
    std::size_t charsLeft() const noexcept
    {
        return _mStr.end() - _mAt;
    }

    /*
     * Returns the current text location considering `_mBaseOffset`.
     */
    TextLoc loc() const noexcept
    {
        return TextLoc {_mBaseOffset + static_cast<std::size_t>(_mAt - _mStr.begin()), _mNbLines,
                        static_cast<std::size_t>(_mAt - _mLineBegin)};
    }

    /*
     * Returns whether or not the end of the string is reached.
     */
    bool isDone() const noexcept
    {
        return _mAt == _mStr.end();
    }

    /*
     * Resets this string scanner, setting the current position
     * to `str().begin()`.
     */
    void reset();

    /*
     * Tries to scan a double-quoted literal string, considering the
     * characters of `escapeSeqStartList`, `\`, and `"` as escape
     * sequence starting characters, setting the current position to
     * after the closing double quote on success.
     *
     * If `escapeSeqStartList` includes `u`, then a `\u` escape sequence
     * is interpreted as in JSON: four hexadecimal characters which
     * represent the value of a single Unicode codepoint.
     *
     * Valid examples:
     *
     *     "salut!"
     *     "en circulation\nYves?"
     *     "\u03c9 often represents angular velocity in physics"
     *
     * Returns a view of the escaped string, without beginning/end
     * double quotes, on success, or an empty view if there's no
     * double-quoted literal string (or if the method reaches
     * `str().end()` before a closing `"`).
     *
     * Logs and appends a cause to the error of the current thread,
     * throwing `Error`, if the scanning method finds an invalid escape
     * sequence or an illegal control character.
     *
     * The returned string view remains valid as long as you don't call
     * any method of this object.
     */
    bt2s::string_view tryScanLitStr(bt2s::string_view escapeSeqStartList);

    /*
     * Tries to scan and decode a constant integer string, possibly
     * negative if `ValT` (either `unsigned long long` or `long long`)
     * is signed.
     *
     * Valid examples:
     *
     *     9283
     *     -42
     *     0
     *
     * Returns `bt2s::nullopt` if the method couldn't scan a
     * constant integer.
     *
     * Sets the current position to after this constant integer string
     * on success.
     */
    template <typename ValT>
    bt2s::optional<ValT> tryScanConstInt() noexcept;

    /*
     * Tries to scan and decode a constant unsigned integer string.
     *
     * Returns `bt2s::nullopt` if the method couldn't scan a constant
     * unsigned integer.
     *
     * Sets the current position to after this constant unsigned integer
     * string on success.
     */
    bt2s::optional<unsigned long long> tryScanConstUInt() noexcept
    {
        return this->tryScanConstInt<unsigned long long>();
    }

    /*
     * Tries to scan and decode a constant signed integer string,
     * possibly negative.
     *
     * Returns `bt2s::nullopt` if the method couldn't scan a constant
     * signed integer.
     *
     * Sets the current position to after this constant signed integer
     * string on success.
     */
    bt2s::optional<long long> tryScanConstSInt() noexcept
    {
        return this->tryScanConstInt<long long>();
    }

    /*
     * Tries to scan and decode a constant real number string, returning
     * `bt2s::nullopt` if not possible.
     *
     * The format of the real number string to scan is the JSON
     * (<https://www.json.org/>) number one, _with_ a fraction or an
     * exponent part. Without a fraction/exponent part, this method
     * returns `bt2s::nullopt`: use tryScanConstInt() to try scanning a
     * constant integer instead.
     *
     * Valid examples:
     *
     *     17.2
     *     -42.192
     *     8e9
     *     17E12
     *     9.14e+6
     *     -13.2777E-4
     *     0.0
     *     -0.0
     *
     * Sets the current position to after this constant real number
     * string on success.
     */
    bt2s::optional<double> tryScanConstReal() noexcept;

    /*
     * Tries to scan the specific token `token`, setting the current
     * position to after this string and returning `true` on success.
     */
    bool tryScanToken(bt2s::string_view token) noexcept;

    /*
     * Skips the next whitespaces, updating the current position.
     */
    void skipWhitespaces() noexcept;

private:
    /*
     * Tries to negate `ullVal` as a signed integer value if `ValT` is
     * signed and `negate` is true, returning `bt2s::nullopt` if it
     * can't.
     *
     * Always succeeds when `ValT` is unsigned.
     */
    template <typename ValT>
    static bt2s::optional<ValT> _tryNegateConstInt(unsigned long long ullVal, bool negate) noexcept;

    /*
     * Handles a `\u` escape sequence, appending the UTF-8-encoded
     * Unicode character to `_mStrBuf` on success, or throwing `Error`
     * on error.
     *
     * `at` is the position of the first hexadecimal character
     * after `\u`.
     */
    void _appendEscapedUnicodeChar(Iter at);

    /*
     * Tries to append an escaped character to `_mStrBuf` from the
     * escape sequence characters at the current positin, considering
     * the characters of `escapeSeqStartList`, `\`, and `"` as escape
     * sequence starting characters.
     */
    bool _tryAppendEscapedChar(bt2s::string_view escapeSeqStartList);

    /*
     * Tries to scan any character, returning it and advancing the
     * current position on success, or returning -1 if the current
     * position is `str().end()`.
     */
    int _tryScanAnyChar() noexcept
    {
        if (this->isDone()) {
            return -1;
        }

        const auto c = *_mAt;

        this->_incrAt();
        return c;
    }

    /*
     * Checks if the character at the current position is a newline,
     * updating the line count and line beginning position if so.
     */
    void _checkNewline() noexcept
    {
        if (*_mAt == '\n') {
            ++_mNbLines;
            _mLineBegin = _mAt + 1;
        }
    }

    /*
     * Increments `_mAt` by `count`.
     */
    void _incrAt(const std::size_t count = 1) noexcept
    {
        _mAt += count;
        BT_ASSERT_DBG(_mAt <= _mStr.end());
    }

    /*
     * Decrements `_mAt` by `count`.
     */
    void _decrAt(const std::size_t count = 1) noexcept
    {
        _mAt -= count;
        BT_ASSERT_DBG(_mAt >= _mStr.begin());
    }

private:
    /* Viewed string, given by user */
    bt2s::string_view _mStr;

    /* Current position within `_mStr` */
    Iter _mAt;

    /* Beginning of the current line */
    Iter _mLineBegin;

    /* Number of lines scanned so far */
    std::size_t _mNbLines = 0;

    /* String buffer, used by tryScanToken() and tryScanLitStr() */
    std::string _mStrBuf;

    /* Real number string regex */
    static const bt2c::Regex _realRegex;

    /* Base offset for error messages */
    std::size_t _mBaseOffset;

    /* Logging configuration */
    Logger _mLogger;
};

template <typename ValT>
bt2s::optional<ValT> StrScanner::_tryNegateConstInt(const unsigned long long ullVal,
                                                    const bool negate) noexcept
{
    /* Check for overflow */
    if (std::is_signed<ValT>::value) {
        constexpr auto llMaxAsUll =
            static_cast<unsigned long long>(std::numeric_limits<long long>::max());

        if (negate) {
            if (ullVal > llMaxAsUll + 1) {
                return bt2s::nullopt;
            }
        } else {
            if (ullVal > llMaxAsUll) {
                return bt2s::nullopt;
            }
        }
    }

    /* Success: cast and negate if needed */
    auto val = static_cast<ValT>(ullVal);

    if (negate) {
        val *= static_cast<ValT>(-1);
    }

    return val;
}

template <typename ValT>
bt2s::optional<ValT> StrScanner::tryScanConstInt() noexcept
{
    static_assert(std::is_same<ValT, long long>::value ||
                      std::is_same<ValT, unsigned long long>::value,
                  "`ValT` is `long long` or `unsigned long long`.");

    this->skipWhitespaces();

    /* Backup if we can't scan completely */
    const auto initAt = _mAt;

    /* Scan initial character */
    const auto c = this->_tryScanAnyChar();

    if (c < 0) {
        /* Nothing left */
        return bt2s::nullopt;
    }

    /* Check for negation */
    const bool negate = (c == '-');

    if (negate && !std::is_signed<ValT>::value) {
        /* Can't negate an unsigned integer */
        this->at(initAt);
        return bt2s::nullopt;
    }

    if (!negate) {
        /* No negation: rewind */
        this->_decrAt();
    }

    /*
     * Only allow a digit at this point: std::strtoull() below supports
     * an initial `+`, but this scanner doesn't.
     */
    if (this->isDone() || !std::isdigit(*_mAt)) {
        this->at(initAt);
        return bt2s::nullopt;
    }

    /* Parse */
    char *strEnd = nullptr;
    const auto ullVal = std::strtoull(&(*_mAt), &strEnd, 10);

    if ((ullVal == 0 && &(*_mAt) == strEnd) || errno == ERANGE) {
        /* Couldn't parse */
        errno = 0;
        this->at(initAt);
        return bt2s::nullopt;
    }

    /* Negate if needed */
    const auto val = this->_tryNegateConstInt<ValT>(ullVal, negate);

    if (!val) {
        /* Couldn't negate */
        this->at(initAt);
        return bt2s::nullopt;
    }

    /* Success: update current position and return value */
    this->at(_mStr.begin() + (strEnd - _mStr.data()));
    return val;
}

} /* namespace bt2c */

#endif /* BABELTRACE_CPP_COMMON_BT2C_STR_SCANNER_HPP */
