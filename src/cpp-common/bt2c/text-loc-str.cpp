/*
 * Copyright (c) 2016-2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include <sstream>

#include "text-loc-str.hpp"

namespace bt2c {

std::string textLocStr(const TextLoc& loc, const TextLocStrFmt fmt)
{
    std::ostringstream ss;

    if (fmt == TextLocStrFmt::LineColNosAndOffset || fmt == TextLocStrFmt::LineColNos) {
        ss << loc.naturalLineNo() << ':' << loc.naturalColNo();

        if (fmt == TextLocStrFmt::LineColNosAndOffset) {
            ss << ' ';
        }
    }

    if (fmt == TextLocStrFmt::Offset || fmt == TextLocStrFmt::LineColNosAndOffset) {
        ss << "@ " << loc.offset() << " bytes";
    }

    return ss.str();
}

} /* namespace bt2c */
