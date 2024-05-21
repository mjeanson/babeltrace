/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022 Simon Marchi <simon.marchi@efficios.com>
 * Copyright (c) 2022 Philippe Proulx <eeppeliteloop@gmail.com>
 */

#include <sstream>
#include <string>

#include "common/assert.h"
#include "common/common.h"
#include "cpp-common/bt2c/fmt.hpp"
#include "cpp-common/vendor/fmt/format.h"

#include "item.hpp"
#include "logging-item-visitor.hpp"

namespace ctf {
namespace src {

LoggingItemVisitor::LoggingItemVisitor(const bt2c::Logger& parentLogger) :
    LoggingItemVisitor {"Processing item", parentLogger}
{
}

LoggingItemVisitor::LoggingItemVisitor(std::string intro, const bt2c::Logger& parentLogger) :
    _mIntro {std::move(intro)}, _mLogger {parentLogger, "PLUGIN/CTF/LOGGING-ITEM-VISITOR"}
{
}

template <typename ValT>
void appendField(std::ostringstream& ss, const char * const name, const ValT& val)
{
    ss << fmt::format(", {}={}", name, val);
}

namespace {

void appendDataLenBitsField(std::ostringstream& ss, const bt2c::DataLen& len)
{
    appendField(ss, "len-bits", len.bits());
}

void appendDataLenBytesField(std::ostringstream& ss, const bt2c::DataLen& len)
{
    BT_ASSERT_DBG(!len.hasExtraBits());
    appendField(ss, "len-bytes", len.bytes());
}

template <typename ItemT>
void appendItemDataLenBitsField(std::ostringstream& ss, const ItemT& item)
{
    appendDataLenBitsField(ss, item.len());
}

template <typename ItemT>
void appendItemDataLenBytesField(std::ostringstream& ss, const ItemT& item)
{
    appendDataLenBytesField(ss, item.len());
}

template <typename ItemT>
void appendItemLenField(std::ostringstream& ss, const ItemT& item)
{
    appendField(ss, "len", item.len());
}

} /* namespace */

void LoggingItemVisitor::visit(const Item& item)
{
    std::ostringstream ss;

    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const RawDataItem& item)
{
    std::ostringstream ss;

    appendDataLenBytesField(ss, item.len());

    if (item.data().size() > 0) {
        ss << ", first-bytes=";

        for (const auto byte : item.data()) {
            ss << fmt::format("{:02x}", byte);
        }
    }

    this->_log(item, ss);
}

namespace {

template <typename ClsT>
void tryAppendClsIdentity(std::ostringstream& ss, const ClsT * const cls)
{
    if (cls) {
        appendField(ss, "cls-id", cls->id());

        if (cls->ns()) {
            appendField(ss, "cls-ns", *cls->ns());
        }

        if (cls->name()) {
            appendField(ss, "cls-name", *cls->name());
        }

        if (cls->uid()) {
            appendField(ss, "cls-uid", *cls->uid());
        }
    }
}

} /* namespace */

void LoggingItemVisitor::visit(const DataStreamInfoItem& item)
{
    std::ostringstream ss;

    if (item.id()) {
        appendField(ss, "id", *item.id());
    }

    tryAppendClsIdentity(ss, item.cls());
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const DefClkValItem& item)
{
    std::ostringstream ss;

    appendField(ss, "cycles", item.cycles());
    this->_log(item, ss);
}

namespace {

template <typename ItemT>
void appendItemMinAlignField(std::ostringstream& ss, const ItemT& item)
{
    appendField(ss, "min-align", item.cls().minAlign());
}

} /* namespace */

void LoggingItemVisitor::visit(const DynLenArrayFieldBeginItem& item)
{
    std::ostringstream ss;

    appendItemMinAlignField(ss, item);
    appendItemLenField(ss, item);
    this->_log(item, ss);
}

namespace {

template <typename ItemT>
void appendBlobFieldBeginItemMediaTypeField(std::ostringstream& ss, const ItemT& item)
{
    appendField(ss, "media-type", item.cls().mediaType());
}

} /* namespace */

void LoggingItemVisitor::visit(const DynLenBlobFieldBeginItem& item)
{
    std::ostringstream ss;

    appendBlobFieldBeginItemMediaTypeField(ss, item);
    appendItemDataLenBytesField(ss, item);
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const DynLenStrFieldBeginItem& item)
{
    std::ostringstream ss;

    appendItemDataLenBytesField(ss, item);
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const EventRecordInfoItem& item)
{
    std::ostringstream ss;

    if (item.defClkVal()) {
        appendField(ss, "def-clk-val", *item.defClkVal());
    }

    tryAppendClsIdentity(ss, item.cls());
    this->_log(item, ss);
}

namespace {

void appendFixedLenBitArrayFieldItemFields(std::ostringstream& ss,
                                           const FixedLenBitArrayFieldItem& item)
{
    appendDataLenBitsField(ss, item.cls().len());
    appendField(ss, "byte-order", item.cls().byteOrder() == ByteOrder::Big ? "be" : "le");

    if (item.cls().isRev()) {
        appendField(ss, "bit-order-is-rev", true);
    }

    appendField(ss, "align", item.cls().align());
}

} /* namespace */

void LoggingItemVisitor::visit(const FixedLenBitArrayFieldItem& item)
{
    std::ostringstream ss;

    appendFixedLenBitArrayFieldItemFields(ss, item);
    appendField(ss, "val-as-uint", item.uIntVal());
    this->_log(item, ss);
}

namespace {

template <typename ItemT>
void appendItemValField(std::ostringstream& ss, const ItemT& item)
{
    appendField(ss, "val", item.val());
}

} /* namespace */

void LoggingItemVisitor::visit(const FixedLenBoolFieldItem& item)
{
    std::ostringstream ss;

    appendFixedLenBitArrayFieldItemFields(ss, item);
    appendItemValField(ss, item);
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const FixedLenFloatFieldItem& item)
{
    std::ostringstream ss;

    appendFixedLenBitArrayFieldItemFields(ss, item);
    appendItemValField(ss, item);
    this->_log(item, ss);
}

template <typename ItemT>
void appendIntFieldItemVal(std::ostringstream& ss, const ItemT& item)
{
    ss << ", val=";

    switch (item.cls().prefDispBase()) {
    case DispBase::Oct:
        ss << fmt::format("{:#o}", item.val());
        break;
    case DispBase::Dec:
        ss << item.val();
        break;
    case DispBase::Bin:
        ss << fmt::format("{:#b}", item.val());
        break;
    case DispBase::Hex:
        ss << fmt::format("{:#x}", item.val());
        break;
    default:
        bt_common_abort();
    }
}

void LoggingItemVisitor::visit(const FixedLenSIntFieldItem& item)
{
    std::ostringstream ss;

    appendFixedLenBitArrayFieldItemFields(ss, item);
    appendIntFieldItemVal(ss, item);
    this->_log(item, ss);
}

template <typename ItemT>
void appendUIntFieldItemRolesField(std::ostringstream& ss, const ItemT& item)
{
    if (item.cls().roles().empty()) {
        return;
    }

    ss << ", roles=[";

    {
        auto prependComma = false;

        for (const auto role : item.cls().roles()) {
            if (prependComma) {
                ss << ", ";
            }

            ss << wise_enum::to_string(role);
            prependComma = true;
        }
    }

    ss << ']';
}

void LoggingItemVisitor::visit(const FixedLenUIntFieldItem& item)
{
    std::ostringstream ss;

    appendFixedLenBitArrayFieldItemFields(ss, item);
    appendUIntFieldItemRolesField(ss, item);
    appendIntFieldItemVal(ss, item);
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const MetadataStreamUuidItem& item)
{
    std::ostringstream ss;

    appendField(ss, "uuid", item.uuid());
    this->_log(item, ss);
}

namespace {

template <typename ItemT>
void appendItemSelValField(std::ostringstream& ss, const ItemT& item)
{
    appendField(ss, "sel-val", item.selVal());
}

template <typename ItemT>
void appendOptionalFieldBeginItemFields(std::ostringstream& ss, const ItemT& item)
{
    appendItemSelValField(ss, item);
    appendField(ss, "is-enabled", item.isEnabled());
}

} /* namespace */

void LoggingItemVisitor::visit(const OptionalFieldWithBoolSelBeginItem& item)
{
    std::ostringstream ss;

    appendOptionalFieldBeginItemFields(ss, item);
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const OptionalFieldWithSIntSelBeginItem& item)
{
    std::ostringstream ss;

    appendOptionalFieldBeginItemFields(ss, item);
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const OptionalFieldWithUIntSelBeginItem& item)
{
    std::ostringstream ss;

    appendOptionalFieldBeginItemFields(ss, item);
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const PktInfoItem& item)
{
    std::ostringstream ss;

    if (item.seqNum()) {
        appendField(ss, "seq-num", *item.seqNum());
    }

    if (item.discEventRecordCounterSnap()) {
        appendField(ss, "disc-er-counter-snap", *item.discEventRecordCounterSnap());
    }

    if (item.expectedTotalLen()) {
        appendField(ss, "exp-total-len-bits", item.expectedTotalLen()->bits());
    }

    if (item.expectedContentLen()) {
        appendField(ss, "exp-content-len-bits", item.expectedContentLen()->bits());
    }

    if (item.beginDefClkVal()) {
        appendField(ss, "begin-def-clk-val", *item.beginDefClkVal());
    }

    if (item.endDefClkVal()) {
        appendField(ss, "end-def-clk-val", *item.endDefClkVal());
    }

    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const PktMagicNumberItem& item)
{
    std::ostringstream ss;

    appendItemValField(ss, item);
    this->_log(item, ss);
}

namespace {

void appendScopeItemScopeField(std::ostringstream& ss, const ScopeItem& item)
{
    appendField(ss, "scope", wise_enum::to_string(item.scope()));
}

} /* namespace */

void LoggingItemVisitor::visit(const ScopeBeginItem& item)
{
    std::ostringstream ss;

    appendScopeItemScopeField(ss, item);
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const ScopeEndItem& item)
{
    std::ostringstream ss;

    appendScopeItemScopeField(ss, item);
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const StaticLenArrayFieldBeginItem& item)
{
    std::ostringstream ss;

    appendItemMinAlignField(ss, item);
    appendField(ss, "len", item.cls().len());
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const StaticLenBlobFieldBeginItem& item)
{
    std::ostringstream ss;

    appendBlobFieldBeginItemMediaTypeField(ss, item);
    appendDataLenBytesField(ss, bt2c::DataLen::fromBytes(item.cls().len()));
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const StaticLenStrFieldBeginItem& item)
{
    std::ostringstream ss;

    appendDataLenBytesField(ss, bt2c::DataLen::fromBytes(item.cls().len()));
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const StructFieldBeginItem& item)
{
    std::ostringstream ss;

    appendItemMinAlignField(ss, item);
    appendField(ss, "member-count", item.cls().size());
    this->_log(item, ss);
}

namespace {

void appendVariantFieldBeginItemSelOptIndexField(std::ostringstream& ss,
                                                 const VariantFieldBeginItem& item)
{
    appendField(ss, "sel-opt-index", item.selectedOptIndex());
}

} /* namespace */

void LoggingItemVisitor::visit(const VariantFieldWithSIntSelBeginItem& item)
{
    std::ostringstream ss;

    appendItemSelValField(ss, item);
    appendVariantFieldBeginItemSelOptIndexField(ss, item);
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const VariantFieldWithUIntSelBeginItem& item)
{
    std::ostringstream ss;

    appendItemSelValField(ss, item);
    appendVariantFieldBeginItemSelOptIndexField(ss, item);
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const VarLenSIntFieldItem& item)
{
    std::ostringstream ss;

    appendItemDataLenBitsField(ss, item);
    appendIntFieldItemVal(ss, item);
    this->_log(item, ss);
}

void LoggingItemVisitor::visit(const VarLenUIntFieldItem& item)
{
    std::ostringstream ss;

    appendItemDataLenBitsField(ss, item);
    appendUIntFieldItemRolesField(ss, item);
    appendIntFieldItemVal(ss, item);
    this->_log(item, ss);
}

void LoggingItemVisitor::_log(const Item& item, const std::ostringstream& extra)
{
    BT_CPPLOGT("{}: type={}{}", _mIntro, wise_enum::to_string(item.type()), extra.str());
}

} /* namespace src */
} /* namespace ctf */
