/*
 * Copyright (c) 2024 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_CPP_COMMON_BT2C_JOIN_HPP
#define BABELTRACE_CPP_COMMON_BT2C_JOIN_HPP

#include <sstream>
#include <string>

#include "cpp-common/bt2s/string-view.hpp"

namespace bt2c {
namespace internal {

template <typename StrT>
void appendStrToSs(std::ostringstream& ss, const StrT& str)
{
    ss.write(str.data(), str.size());
}

} /* namespace internal */

/*
 * Joins the strings of `container` with the delimiter `delim`.
 *
 * `ContainerT` needs a forward iterator and its elements need the
 * data() and size() methods.
 *
 * `container` may be empty.
 */
template <typename ContainerT>
std::string join(const ContainerT& container, const bt2s::string_view delim)
{
    if (container.empty()) {
        /* No elements */
        return {};
    }

    if (container.size() == 1) {
        /* Single element */
        return std::string {container.begin()->data(), container.begin()->size()};
    }

    /* Two or more elements */
    std::ostringstream ss;
    auto it = container.begin();

    internal::appendStrToSs(ss, *it);
    ++it;

    for (; it != container.end(); ++it) {
        internal::appendStrToSs(ss, delim);
        internal::appendStrToSs(ss, *it);
    }

    return ss.str();
}

} /* namespace bt2c */

#endif /* BABELTRACE_CPP_COMMON_BT2C_JOIN_HPP */
