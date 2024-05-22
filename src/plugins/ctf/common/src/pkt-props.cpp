/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022 EfficiOS Inc. and Linux Foundation
 */

#include "../../common/src/item-seq/item-seq-iter.hpp"
#include "../../common/src/item-seq/logging-item-visitor.hpp"
#include "pkt-props.hpp"

namespace ctf {
namespace src {
namespace {

struct ReadPacketPropertiesItemVisitor final : public ItemVisitor
{
    void visit(const DataStreamInfoItem& item) override
    {
        props.dataStreamCls = item.cls();
        props.dataStreamId = item.id();
    }

    void visit(const PktInfoItem& item) override
    {
        props.expectedTotalLen = item.expectedTotalLen();
        props.expectedContentLen = item.expectedContentLen();
        props.snapshots.discEventRecordCounter = item.discEventRecordCounterSnap();
        props.snapshots.beginDefClk = item.beginDefClkVal();
        props.snapshots.endDefClk = item.endDefClkVal();
        _mDone = true;
    }

    bool done() const noexcept
    {
        return _mDone;
    }

    PktProps props;

private:
    bool _mDone = false;
};
} /* namespace */

PktProps readPktProps(const TraceCls& traceCls, Medium::UP medium, const bt2c::DataLen pktOffset,
                      const bt2c::Logger& parentLogger)
{
    bt2c::Logger logger {parentLogger, "PLUGIN/CTF/PKT-PROPS"};
    BT_CPPLOGD_SPEC(logger, "Reading packet properties: pkt-offset-bytes={}", pktOffset.bytes());

    ItemSeqIter itemSeqIter {std::move(medium), traceCls, pktOffset, logger};
    ReadPacketPropertiesItemVisitor visitor;
    LoggingItemVisitor loggingVisitor {logger};

    while (!visitor.done()) {
        const Item *item = itemSeqIter.next();
        BT_ASSERT(item);

        if (parentLogger.wouldLogT()) {
            item->accept(loggingVisitor);
        }

        item->accept(visitor);
    }

    return visitor.props;
}

} /* namespace src */
} /* namespace ctf */
