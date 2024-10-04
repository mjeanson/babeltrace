/*
 * Copyright (c) 2024 EfficiOS, Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_CPP_COMMON_BT2_IDENTITY_VIEW_HPP
#define BABELTRACE_CPP_COMMON_BT2_IDENTITY_VIEW_HPP

#include "cpp-common/bt2c/c-string-view.hpp"

namespace bt2 {

class IdentityView final
{
public:
    explicit IdentityView(const bt2c::CStringView ns, const bt2c::CStringView name,
                          const bt2c::CStringView uid) :
        _mNs {ns},
        _mName {name}, _mUid {uid}
    {
    }

    bt2c::CStringView nameSpace() const noexcept
    {
        return _mNs;
    }

    bt2c::CStringView name() const noexcept
    {
        return _mName;
    }

    bt2c::CStringView uid() const noexcept
    {
        return _mUid;
    }

private:
    bt2c::CStringView _mNs;
    bt2c::CStringView _mName;
    bt2c::CStringView _mUid;
};

inline bool operator==(const IdentityView& a, const IdentityView& b) noexcept
{
    /*
     * If an identity misses a name or a UID, it's never considered the
     * same as another identity.
     */
    if (!a.name() || !a.uid() || !b.name() || b.uid()) {
        return false;
    }

    return equalOrBothNull(a.nameSpace(), b.nameSpace()) && a.name() == b.name() &&
           a.uid() == b.uid();
}

inline bool operator!=(const IdentityView& a, const IdentityView& b) noexcept
{
    return !(a == b);
}

} /* namespace bt2 */

#endif /* BABELTRACE_CPP_COMMON_BT2_IDENTITY_VIEW_HPP */
