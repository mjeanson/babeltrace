/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022 Simon Marchi <simon.marchi@efficios.com>
 * Copyright (c) 2022 Philippe Proulx <eeppeliteloop@gmail.com>
 */

#ifndef BABELTRACE_PLUGINS_CTF_COMMON_SRC_ITEM_SEQ_LOGGING_ITEM_VISITOR_HPP
#define BABELTRACE_PLUGINS_CTF_COMMON_SRC_ITEM_SEQ_LOGGING_ITEM_VISITOR_HPP

#include <string>

#include "cpp-common/bt2c/logging.hpp"

#include "item-visitor.hpp"
#include "item.hpp"

namespace ctf {
namespace src {

/*
 * An item visitor which logs information (with the `BT_LOG_TRACE`
 * level) about the visited item.
 *
 * An instance of `LoggingItemVisitor` is meant to be used as such:
 *
 *     LoggingItemVisitor visitor {logCfg};
 *
 *     // ...
 *
 *     if (_mLogger.wouldLogT()) {
 *         item.accept(visitor);
 *     }
 */
class LoggingItemVisitor final : public ItemVisitor
{
public:
    /*
     * Builds a logging item visitor using the introductory
     * text `intro`.
     *
     * The message of each logging statement starts with `intro`.
     */
    explicit LoggingItemVisitor(std::string intro, const bt2c::Logger& parentLogger);

    /*
     * Builds a logging item visitor using the introductory text
     * `Processing item`.
     */
    explicit LoggingItemVisitor(const bt2c::Logger& parentLogger);

    /* Visiting methods below */
    void visit(const DataStreamInfoItem&) override;
    void visit(const DefClkValItem&) override;
    void visit(const DynLenArrayFieldBeginItem&) override;
    void visit(const DynLenBlobFieldBeginItem&) override;
    void visit(const DynLenStrFieldBeginItem&) override;
    void visit(const EventRecordInfoItem&) override;
    void visit(const FixedLenBitArrayFieldItem&) override;
    void visit(const FixedLenBoolFieldItem&) override;
    void visit(const FixedLenFloatFieldItem&) override;
    void visit(const FixedLenSIntFieldItem&) override;
    void visit(const FixedLenUIntFieldItem&) override;
    void visit(const Item&) override;
    void visit(const MetadataStreamUuidItem&) override;
    void visit(const OptionalFieldWithBoolSelBeginItem&) override;
    void visit(const OptionalFieldWithSIntSelBeginItem&) override;
    void visit(const OptionalFieldWithUIntSelBeginItem&) override;
    void visit(const PktInfoItem&) override;
    void visit(const PktMagicNumberItem&) override;
    void visit(const RawDataItem&) override;
    void visit(const ScopeBeginItem&) override;
    void visit(const ScopeEndItem&) override;
    void visit(const StaticLenArrayFieldBeginItem&) override;
    void visit(const StaticLenBlobFieldBeginItem&) override;
    void visit(const StaticLenStrFieldBeginItem&) override;
    void visit(const StructFieldBeginItem&) override;
    void visit(const VariantFieldWithSIntSelBeginItem&) override;
    void visit(const VariantFieldWithUIntSelBeginItem&) override;
    void visit(const VarLenSIntFieldItem&) override;
    void visit(const VarLenUIntFieldItem&) override;

private:
    void _log(const Item& item, const std::ostringstream& extra);

    /* Introductory text */
    std::string _mIntro;

    /* Logging configuration */
    bt2c::Logger _mLogger;
};

} /* namespace src */
} /* namespace ctf */

#endif /* BABELTRACE_PLUGINS_CTF_COMMON_SRC_ITEM_SEQ_LOGGING_ITEM_VISITOR_HPP */
