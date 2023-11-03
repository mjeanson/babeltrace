/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2022-2024 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef BABELTRACE_PLUGINS_CTF_COMMON_METADATA_INT_RANGE_SET_HPP
#define BABELTRACE_PLUGINS_CTF_COMMON_METADATA_INT_RANGE_SET_HPP

#include <set>
#include <utility>

#include "common/assert.h"

#include "int-range.hpp"

namespace ctf {

/*
 * An integer range set is a set of integer ranges of which the values
 * are of type `ValT`.
 */
template <typename ValT>
class IntRangeSet final
{
public:
    /* Type of the lower and upper values of contained integer ranges */
    using Val = ValT;

    /* Type of contained integer ranges */
    using Range = IntRange<ValT>;

    /* Type of the set containing the ranges */
    using Set = std::set<Range>;

public:
    /*
     * Builds an empty integer range set.
     */
    explicit IntRangeSet()
    {
    }

    /*
     * Builds an integer range set containing the integer ranges
     * `ranges`.
     */
    explicit IntRangeSet(Set ranges) : _mRanges {std::move(ranges)}
    {
    }

    /*
     * Ranges of this integer range set.
     */
    const Set& ranges() const noexcept
    {
        return _mRanges;
    }

    /*
     * Range set iterator at the first range of this set.
     */
    typename Set::const_iterator begin() const noexcept
    {
        return _mRanges.begin();
    }

    /*
     * Range set iterator \em after the last range of this set.
     */
    typename Set::const_iterator end() const noexcept
    {
        return _mRanges.end();
    }

    /*
     * Returns whether or not this integer range set contains the
     * value `val` in at least one of its ranges.
     */
    bool contains(const Val val) const noexcept
    {
        for (auto& range : _mRanges) {
            if (range.contains(val)) {
                return true;
            }
        }

        return false;
    }

    /*
     * Returns whether or not at least one range contained in `other`
     * intersects with at least one range contained in this integer
     * range set.
     */
    bool intersects(const IntRangeSet& other) const noexcept
    {
        for (auto& range : _mRanges) {
            for (auto& otherRange : other.ranges()) {
                if (range.intersects(otherRange)) {
                    return true;
                }
            }
        }

        return false;
    }

    bool operator==(const IntRangeSet& other) const
    {
        return other.ranges() == _mRanges;
    }

    bool operator!=(const IntRangeSet& other) const
    {
        return !(*this == other);
    }

private:
    Set _mRanges;
};

/* Convenient aliases */
using UIntRangeSet = IntRangeSet<unsigned long long>;
using SIntRangeSet = IntRangeSet<long long>;

} /* namespace ctf */

#endif /* BABELTRACE_PLUGINS_CTF_COMMON_METADATA_INT_RANGE_SET_HPP */
