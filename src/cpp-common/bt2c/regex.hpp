/*
 * Copyright (c) 2024 EfficiOS Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_CPP_COMMON_BT2C_REGEX_HPP
#define BABELTRACE_CPP_COMMON_BT2C_REGEX_HPP

#include <glib.h>

#include "cpp-common/bt2c/logging.hpp"

namespace bt2c {

class Regex final
{
public:
    explicit Regex(const char * const pattern) noexcept
    {
        GError *error = nullptr;

        _mRegex = g_regex_new(pattern, G_REGEX_OPTIMIZE, static_cast<GRegexMatchFlags>(0), &error);

        if (!_mRegex) {
            BT_CPPLOGF_SPEC((bt2c::Logger {"BT2C", "REGEX", bt2c::Logger::Level::Fatal}),
                            "g_regex_new() failed: {}", error->message);
            bt_common_abort();
        }
    }

    Regex(const Regex&) = delete;
    Regex& operator=(const Regex&) = delete;

    ~Regex()
    {
        g_regex_unref(_mRegex);
    }

    bool match(const bt2s::string_view str) const noexcept
    {
        return g_regex_match_full(_mRegex, str.data(), str.size(), 0,
                                  static_cast<GRegexMatchFlags>(0), nullptr, nullptr);
    }

private:
    GRegex *_mRegex;
};

} /* namespace bt2c */

#endif /* BABELTRACE_CPP_COMMON_BT2C_REGEX_HPP */
