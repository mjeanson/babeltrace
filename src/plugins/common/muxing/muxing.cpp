/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2019 Francis Deslauriers <francis.deslauriers@efficios.com>
 */

#include <babeltrace2/babeltrace.h>

#include "common/assert.h"
#include "common/common.h"
#include "common/uuid.h"
#include "cpp-common/bt2/message.hpp"

#include "muxing.hpp"

namespace muxing {

/*
 * Compares two optional objects.
 *
 * A non-empty object comes before an empty object. Two empty objects
 * are equal.
 *
 * If the two objects are non-empty, then call `comparator` to compare
 * the contents of both objects.
 */
template <typename ObjT, typename ComparatorT>
int MessageComparator::_compareOptionals(const bt2s::optional<ObjT>& left,
                                         const bt2s::optional<ObjT>& right,
                                         ComparatorT comparator) noexcept
{
    if (left && !right) {
        return -1;
    }

    if (!left && right) {
        return 1;
    }
    if (!left && !right) {
        return 0;
    }

    return comparator(*left, *right);
}

/*
 * Compares two optional borrowed objects.
 *
 * A non-empty object comes before an empty object. Two empty objects
 * are equal.
 *
 * If the two objects are non-empty, then call `comparator` to compare
 * the contents of both objects.
 */
template <typename ObjT, typename ComparatorT>
int MessageComparator::_compareOptionalBorrowedObjects(
    const bt2::OptionalBorrowedObject<ObjT> left, const bt2::OptionalBorrowedObject<ObjT> right,
    ComparatorT comparator) noexcept
{
    if (left && !right) {
        return -1;
    }

    if (!left && right) {
        return 1;
    }
    if (!left && !right) {
        return 0;
    }

    return comparator(*left, *right);
}

/*
 * Compare two (nullable) strings.
 *
 * A non-null string comes before a null string. Two null strings
 * are equal.
 *
 * If both strings aren't null, then compare them with `std::strcmp`.
 */
int MessageComparator::_compareStrings(const bt2c::CStringView left,
                                       const bt2c::CStringView right) noexcept
{
    if (left && !right) {
        return -1;
    }

    if (!left && right) {
        return 1;
    }

    if (!left && !right) {
        return 0;
    }

    return std::strcmp(left, right);
}

/*
 * Returns a weight corresponding to `msgType` to sort message types in
 * an arbitrary order.
 *
 * A lower weight means a higher priority (sorted before).
 */
int MessageComparator::_messageTypeWeight(const bt2::MessageType msgType) noexcept
{
    switch (msgType) {
    case bt2::MessageType::StreamBeginning:
        return 0;

    case bt2::MessageType::PacketBeginning:
        return 1;

    case bt2::MessageType::Event:
        return 2;

    case bt2::MessageType::DiscardedEvents:
        return 3;

    case bt2::MessageType::PacketEnd:
        return 4;

    case bt2::MessageType::MessageIteratorInactivity:
        return 5;

    case bt2::MessageType::DiscardedPackets:
        return 6;

    case bt2::MessageType::StreamEnd:
        return 7;
    }

    bt_common_abort();
}

/*
 * Compares two values using operator<().
 */
template <typename T>
int MessageComparator::_compareLt(const T left, const T right) noexcept
{
    if (left < right) {
        return -1;
    } else if (right < left) {
        return 1;
    } else {
        return 0;
    }
}

int MessageComparator::_compareMsgsTypes(const bt2::MessageType left,
                                         const bt2::MessageType right) noexcept
{
    return _compareLt(_messageTypeWeight(left), _messageTypeWeight(right));
}

int MessageComparator::_compareUuids(const bt2c::UuidView left, const bt2c::UuidView right) noexcept
{
    return bt_uuid_compare(left.data(), right.data());
}

int MessageComparator::_compareOptUuids(const bt2s::optional<const bt2c::UuidView>& left,
                                        const bt2s::optional<const bt2c::UuidView>& right) noexcept
{
    return _compareOptionals(left, right, _compareUuids);
}

int MessageComparator::_compareEventClasses(const bt2::ConstEventClass left,
                                            const bt2::ConstEventClass right) noexcept
{
    if (const auto ret = _compareLt(left.id(), right.id())) {
        return ret;
    }

    if (const auto ret = _compareStrings(left.name(), right.name())) {
        return ret;
    }

    if (const auto ret = _compareOptionals(left.logLevel(), right.logLevel(),
                                           _compareLt<bt2::EventClassLogLevel>)) {
        return ret;
    }

    return _compareStrings(left.emfUri(), right.emfUri());
}

int MessageComparator::_compareClockClasses(const bt2::ConstClockClass left,
                                            const bt2::ConstClockClass right) noexcept
{
    if (const auto ret = _compareOptUuids(left.uuid(), right.uuid())) {
        return ret;
    }

    if (const auto ret = _compareLt(left.origin().isUnixEpoch(), right.origin().isUnixEpoch())) {
        return ret;
    }

    if (const auto ret = _compareStrings(left.name(), right.name())) {
        return ret;
    }

    if (const auto ret = _compareLt(left.frequency(), right.frequency())) {
        return ret;
    }

    return _compareLt(left.precision(), right.precision());
}

int MessageComparator::_compareStreamsSameIds(const bt2::ConstStream left,
                                              const bt2::ConstStream right) noexcept
{
    BT_ASSERT_DBG(left.id() == right.id());

    if (const auto ret = _compareStrings(left.name(), right.name())) {
        return ret;
    }

    const auto leftCls = left.cls();
    const auto rightCls = right.cls();

    BT_ASSERT_DBG(leftCls.id() == rightCls.id());

    if (const auto ret = _compareStrings(leftCls.name(), rightCls.name())) {
        return ret;
    }

    if (const auto ret = _compareLt(leftCls.assignsAutomaticEventClassId(),
                                    rightCls.assignsAutomaticEventClassId())) {
        return ret;
    }

    if (const auto ret =
            _compareLt(leftCls.assignsAutomaticStreamId(), rightCls.assignsAutomaticStreamId())) {
        return ret;
    }

    /* Compare stream class support of discarded events. */
    if (const auto ret =
            _compareLt(leftCls.supportsDiscardedEvents(), rightCls.supportsDiscardedEvents())) {
        return ret;
    }

    /* Compare stream class discarded events default clock snapshot. */
    if (const auto ret = _compareLt(leftCls.discardedEventsHaveDefaultClockSnapshots(),
                                    rightCls.discardedEventsHaveDefaultClockSnapshots())) {
        return ret;
    }

    /* Compare stream class support of packets. */
    if (const auto ret = _compareLt(leftCls.supportsPackets(), rightCls.supportsPackets())) {
        return ret;
    }

    if (leftCls.supportsPackets()) {
        /*
		* Compare stream class presence of discarded packets beginning default
		* clock snapshot.
		*/
        if (const auto ret = _compareLt(leftCls.packetsHaveBeginningClockSnapshot(),
                                        rightCls.packetsHaveBeginningClockSnapshot())) {
            return ret;
        }

        /*
		* Compare stream class presence of discarded packets end default clock
		* snapshot.
		*/
        if (const auto ret = _compareLt(leftCls.packetsHaveEndClockSnapshot(),
                                        rightCls.packetsHaveEndClockSnapshot())) {
            return ret;
        }

        /* Compare stream class support of discarded packets. */
        if (const auto ret = _compareLt(leftCls.supportsDiscardedPackets(),
                                        rightCls.supportsDiscardedPackets())) {
            return ret;
        }

        /* Compare stream class discarded packets default clock snapshot. */
        if (const auto ret = _compareLt(leftCls.discardedPacketsHaveDefaultClockSnapshots(),
                                        rightCls.discardedPacketsHaveDefaultClockSnapshots())) {
            return ret;
        }
    }

    /* Compare the clock classes associated to the stream classes. */
    return _compareOptionalBorrowedObjects(leftCls.defaultClockClass(),
                                           rightCls.defaultClockClass(), _compareClockClasses);
}

int MessageComparator::_compareClockSnapshots(const bt2::ConstClockSnapshot left,
                                              const bt2::ConstClockSnapshot right) noexcept
{
    return _compareLt(left.value(), right.value());
}

namespace {

bt2::OptionalBorrowedObject<bt2::ConstStream> borrowStream(const bt2::ConstMessage msg) noexcept
{
    switch (msg.type()) {
    case bt2::MessageType::StreamBeginning:
        return msg.asStreamBeginning().stream();

    case bt2::MessageType::StreamEnd:
        return msg.asStreamEnd().stream();

    case bt2::MessageType::PacketBeginning:
        return msg.asPacketBeginning().packet().stream();

    case bt2::MessageType::PacketEnd:
        return msg.asPacketEnd().packet().stream();

    case bt2::MessageType::Event:
        return msg.asEvent().event().stream();

    case bt2::MessageType::DiscardedEvents:
        return msg.asDiscardedEvents().stream();

    case bt2::MessageType::DiscardedPackets:
        return msg.asDiscardedPackets().stream();

    case bt2::MessageType::MessageIteratorInactivity:
        return {};
    }

    bt_common_abort();
}

} /* namespace */

int MessageComparator::_compareMessagesSameType(const bt2::ConstMessage left,
                                                const bt2::ConstMessage right) noexcept
{
    BT_ASSERT_DBG(left.type() == right.type());

    switch (left.type()) {
    case bt2::MessageType::StreamBeginning:
    case bt2::MessageType::StreamEnd:
    case bt2::MessageType::PacketBeginning:
    case bt2::MessageType::PacketEnd:
        return _compareStreamsSameIds(*borrowStream(left), *borrowStream(right));

    case bt2::MessageType::Event:
    {
        const auto leftEvent = left.asEvent().event();
        const auto rightEvent = right.asEvent().event();

        if (const auto ret = _compareEventClasses(leftEvent.cls(), rightEvent.cls())) {
            return ret;
        }

        return _compareStreamsSameIds(leftEvent.stream(), rightEvent.stream());
    }

    case bt2::MessageType::DiscardedEvents:
    {
        /*
		 * Compare streams first to check if there is a
		 * mismatch about discarded event related configuration
		 * in the stream class.
		 */

        const auto leftDiscEv = left.asDiscardedEvents();
        const auto rightDiscEv = right.asDiscardedEvents();

        if (const auto ret = _compareStreamsSameIds(leftDiscEv.stream(), rightDiscEv.stream())) {
            return ret;
        }

        if (leftDiscEv.stream().cls().discardedEventsHaveDefaultClockSnapshots()) {
            const auto leftBegCs = leftDiscEv.beginningDefaultClockSnapshot();
            const auto rightBegCs = rightDiscEv.beginningDefaultClockSnapshot();
            const auto leftEndCs = leftDiscEv.endDefaultClockSnapshot();
            const auto rightEndCs = rightDiscEv.endDefaultClockSnapshot();

            if (const auto ret = _compareClockSnapshots(leftBegCs, rightBegCs)) {
                return ret;
            }

            if (const auto ret = _compareClockSnapshots(leftEndCs, rightEndCs)) {
                return ret;
            }

            if (const auto ret =
                    _compareClockClasses(leftBegCs.clockClass(), rightBegCs.clockClass())) {
                return ret;
            }
        }

        return _compareOptionals(leftDiscEv.count(), rightDiscEv.count(),
                                 _compareLt<std::uint64_t>);
    }
    case bt2::MessageType::DiscardedPackets:
    {
        const auto leftDiscPkts = left.asDiscardedPackets();
        const auto rightDiscPkts = right.asDiscardedPackets();

        /*
		 * Compare streams first to check if there is a
		 * mismatch about discarded packets related
		 * configuration in the stream class.
		 */
        if (const auto ret =
                _compareStreamsSameIds(leftDiscPkts.stream(), rightDiscPkts.stream())) {
            return ret;
        }

        if (leftDiscPkts.stream().cls().discardedPacketsHaveDefaultClockSnapshots()) {
            const auto leftBegCs = leftDiscPkts.beginningDefaultClockSnapshot();
            const auto rightBegCs = rightDiscPkts.beginningDefaultClockSnapshot();
            const auto leftEndCs = leftDiscPkts.endDefaultClockSnapshot();
            const auto rightEndCs = rightDiscPkts.endDefaultClockSnapshot();

            if (const auto ret = _compareClockSnapshots(leftBegCs, rightBegCs)) {
                return ret;
            }

            if (const auto ret = _compareClockSnapshots(leftEndCs, rightEndCs)) {
                return ret;
            }

            if (const auto ret =
                    _compareClockClasses(leftBegCs.clockClass(), rightBegCs.clockClass())) {
                return ret;
            }
        }

        return _compareOptionals(leftDiscPkts.count(), leftDiscPkts.count(),
                                 _compareLt<std::uint64_t>);
    }
    case bt2::MessageType::MessageIteratorInactivity:
    {
        const auto leftCs = left.asMessageIteratorInactivity().clockSnapshot();
        const auto rightCs = right.asMessageIteratorInactivity().clockSnapshot();

        if (const auto ret = _compareClockSnapshots(leftCs, rightCs)) {
            return ret;
        }

        return _compareClockClasses(leftCs.clockClass(), rightCs.clockClass());
    }
    }

    bt_common_abort();
}

int MessageComparator::compare(const bt2::ConstMessage left,
                               const bt2::ConstMessage right) const noexcept
{
    BT_ASSERT_DBG(left.libObjPtr() != right.libObjPtr());

    if (const auto ret = _compareOptionalBorrowedObjects(
            borrowStream(left), borrowStream(right),
            [](const bt2::ConstStream leftStream, const bt2::ConstStream rightStream) {
                const auto leftTrace = leftStream.trace();
                const auto rightTrace = rightStream.trace();

                /* Compare trace UUIDs. */
                if (const auto ret = _compareOptUuids(leftTrace.uuid(), rightTrace.uuid())) {
                    return ret;
                }

                /* Compare trace names. */
                if (const auto ret = _compareStrings(leftTrace.name(), rightTrace.name())) {
                    return ret;
                }

                /* Compare stream class IDs. */
                if (const auto ret = _compareLt(leftStream.cls().id(), rightStream.cls().id())) {
                    return ret;
                }

                /* Compare stream IDs. */
                return _compareLt(leftStream.id(), rightStream.id());
            })) {
        return ret;
    }

    if (const auto ret = _compareMsgsTypes(left.type(), right.type())) {
        return ret;
    }

    return _compareMessagesSameType(left, right);
}

} /* namespace muxing */
