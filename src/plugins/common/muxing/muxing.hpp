/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2019 Francis Deslauriers <francis.deslauriers@efficios.com>
 */

#ifndef BABELTRACE_PLUGINS_COMMON_MUXING_MUXING_HPP
#define BABELTRACE_PLUGINS_COMMON_MUXING_MUXING_HPP

#include "cpp-common/bt2/message.hpp"

namespace muxing {

class MessageComparator final
{
public:
    explicit MessageComparator(const std::uint64_t graphMipVersion) :
        _mGraphMipVersion {graphMipVersion}
    {
    }

    int compare(bt2::ConstMessage left, bt2::ConstMessage right) const noexcept;

private:
    static int _messageTypeWeight(const bt2::MessageType msgType) noexcept;

    template <typename ObjT, typename ComparatorT>
    static int _compareOptionals(const bt2s::optional<ObjT>& left,
                                 const bt2s::optional<ObjT>& right,
                                 ComparatorT comparator) noexcept;

    template <typename ObjT, typename ComparatorT>
    static int _compareOptionalBorrowedObjects(const bt2::OptionalBorrowedObject<ObjT> left,
                                               const bt2::OptionalBorrowedObject<ObjT> right,
                                               ComparatorT comparator) noexcept;

    static int _compareStrings(const bt2c::CStringView left,
                               const bt2c::CStringView right) noexcept;

    template <typename T>
    static int _compareLt(const T left, const T right) noexcept;

    static int _compareMsgsTypes(const bt2::MessageType left,
                                 const bt2::MessageType right) noexcept;
    static int _compareUuids(const bt2c::UuidView left, const bt2c::UuidView right) noexcept;
    static int _compareOptUuids(const bt2s::optional<const bt2c::UuidView>& left,
                                const bt2s::optional<const bt2c::UuidView>& right) noexcept;
    static int _compareIdentities(const bt2::IdentityView& left,
                                  const bt2::IdentityView& right) noexcept;
    static int _compareEventClasses(const bt2::ConstEventClass left,
                                    const bt2::ConstEventClass right) noexcept;
    static int _compareClockClasses(const bt2::ConstClockClass left,
                                    const bt2::ConstClockClass right) noexcept;
    static int _compareStreamsSameIds(const bt2::ConstStream left,
                                      const bt2::ConstStream right) noexcept;
    static int _compareClockSnapshots(const bt2::ConstClockSnapshot left,
                                      const bt2::ConstClockSnapshot right) noexcept;
    static int _compareMessagesSameType(const bt2::ConstMessage left,
                                        const bt2::ConstMessage right) noexcept;
    static int _compareMessages(const bt2::ConstMessage left,
                                const bt2::ConstMessage right) noexcept;

    std::uint64_t _mGraphMipVersion;
};

} /* namespace muxing */

#endif /* BABELTRACE_PLUGINS_COMMON_MUXING_MUXING_HPP */
