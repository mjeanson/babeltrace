/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_PLUGINS_CTF_COMMON_SRC_ITEM_SEQ_ITEM_VISITOR_HPP
#define BABELTRACE_PLUGINS_CTF_COMMON_SRC_ITEM_SEQ_ITEM_VISITOR_HPP

namespace ctf {
namespace src {

class ArrayFieldBeginItem;
class ArrayFieldEndItem;
class BeginItem;
class BlobFieldBeginItem;
class BlobFieldEndItem;
class DataStreamInfoItem;
class DefClkValItem;
class DynLenArrayFieldBeginItem;
class DynLenArrayFieldEndItem;
class DynLenBlobFieldBeginItem;
class DynLenBlobFieldEndItem;
class DynLenStrFieldBeginItem;
class DynLenStrFieldEndItem;
class EndItem;
class EventRecordBeginItem;
class EventRecordEndItem;
class EventRecordInfoItem;
class FixedLenBitArrayFieldItem;
class FixedLenBitMapFieldItem;
class FixedLenBoolFieldItem;
class FixedLenFloatFieldItem;
class FixedLenSIntFieldItem;
class FixedLenUIntFieldItem;
class Item;
class MetadataStreamUuidItem;
class NonNullTerminatedStrFieldBeginItem;
class NonNullTerminatedStrFieldEndItem;
class NullTerminatedStrFieldBeginItem;
class NullTerminatedStrFieldEndItem;
class OptionalFieldBeginItem;
class OptionalFieldEndItem;
class OptionalFieldWithBoolSelBeginItem;
class OptionalFieldWithBoolSelEndItem;
class OptionalFieldWithSIntSelBeginItem;
class OptionalFieldWithSIntSelEndItem;
class OptionalFieldWithUIntSelBeginItem;
class OptionalFieldWithUIntSelEndItem;
class PktBeginItem;
class PktContentBeginItem;
class PktContentEndItem;
class PktEndItem;
class PktInfoItem;
class PktMagicNumberItem;
class RawDataItem;
class ScopeBeginItem;
class ScopeEndItem;
class StaticLenArrayFieldBeginItem;
class StaticLenArrayFieldEndItem;
class StaticLenBlobFieldBeginItem;
class StaticLenBlobFieldEndItem;
class StaticLenStrFieldBeginItem;
class StaticLenStrFieldEndItem;
class StructFieldBeginItem;
class StructFieldEndItem;
class VariantFieldBeginItem;
class VariantFieldEndItem;
class VariantFieldWithSIntSelBeginItem;
class VariantFieldWithSIntSelEndItem;
class VariantFieldWithUIntSelBeginItem;
class VariantFieldWithUIntSelEndItem;
class VarLenIntFieldItem;
class VarLenSIntFieldItem;
class VarLenUIntFieldItem;

/*
 * Abstract item visitor base class.
 */
class ItemVisitor
{
public:
    virtual ~ItemVisitor() = default;
    virtual void visit(const ArrayFieldBeginItem&);
    virtual void visit(const ArrayFieldEndItem&);
    virtual void visit(const BeginItem&);
    virtual void visit(const BlobFieldBeginItem&);
    virtual void visit(const BlobFieldEndItem&);
    virtual void visit(const DataStreamInfoItem&);
    virtual void visit(const DefClkValItem&);
    virtual void visit(const DynLenArrayFieldBeginItem&);
    virtual void visit(const DynLenArrayFieldEndItem&);
    virtual void visit(const DynLenBlobFieldBeginItem&);
    virtual void visit(const DynLenBlobFieldEndItem&);
    virtual void visit(const DynLenStrFieldBeginItem&);
    virtual void visit(const DynLenStrFieldEndItem&);
    virtual void visit(const EndItem&);
    virtual void visit(const EventRecordBeginItem&);
    virtual void visit(const EventRecordEndItem&);
    virtual void visit(const EventRecordInfoItem&);
    virtual void visit(const FixedLenBitArrayFieldItem&);
    virtual void visit(const FixedLenBitMapFieldItem&);
    virtual void visit(const FixedLenBoolFieldItem&);
    virtual void visit(const FixedLenFloatFieldItem&);
    virtual void visit(const FixedLenSIntFieldItem&);
    virtual void visit(const FixedLenUIntFieldItem&);
    virtual void visit(const Item&);
    virtual void visit(const MetadataStreamUuidItem&);
    virtual void visit(const NonNullTerminatedStrFieldBeginItem&);
    virtual void visit(const NonNullTerminatedStrFieldEndItem&);
    virtual void visit(const NullTerminatedStrFieldBeginItem&);
    virtual void visit(const NullTerminatedStrFieldEndItem&);
    virtual void visit(const OptionalFieldBeginItem&);
    virtual void visit(const OptionalFieldEndItem&);
    virtual void visit(const OptionalFieldWithBoolSelBeginItem&);
    virtual void visit(const OptionalFieldWithBoolSelEndItem&);
    virtual void visit(const OptionalFieldWithSIntSelBeginItem&);
    virtual void visit(const OptionalFieldWithSIntSelEndItem&);
    virtual void visit(const OptionalFieldWithUIntSelBeginItem&);
    virtual void visit(const OptionalFieldWithUIntSelEndItem&);
    virtual void visit(const PktBeginItem&);
    virtual void visit(const PktContentBeginItem&);
    virtual void visit(const PktContentEndItem&);
    virtual void visit(const PktEndItem&);
    virtual void visit(const PktInfoItem&);
    virtual void visit(const PktMagicNumberItem&);
    virtual void visit(const RawDataItem&);
    virtual void visit(const ScopeBeginItem&);
    virtual void visit(const ScopeEndItem&);
    virtual void visit(const StaticLenArrayFieldBeginItem&);
    virtual void visit(const StaticLenArrayFieldEndItem&);
    virtual void visit(const StaticLenBlobFieldBeginItem&);
    virtual void visit(const StaticLenBlobFieldEndItem&);
    virtual void visit(const StaticLenStrFieldBeginItem&);
    virtual void visit(const StaticLenStrFieldEndItem&);
    virtual void visit(const StructFieldBeginItem&);
    virtual void visit(const StructFieldEndItem&);
    virtual void visit(const VariantFieldBeginItem&);
    virtual void visit(const VariantFieldEndItem&);
    virtual void visit(const VariantFieldWithSIntSelBeginItem&);
    virtual void visit(const VariantFieldWithSIntSelEndItem&);
    virtual void visit(const VariantFieldWithUIntSelBeginItem&);
    virtual void visit(const VariantFieldWithUIntSelEndItem&);
    virtual void visit(const VarLenIntFieldItem&);
    virtual void visit(const VarLenSIntFieldItem&);
    virtual void visit(const VarLenUIntFieldItem&);
};

} /* namespace src */
} /* namespace ctf */

#endif /* BABELTRACE_PLUGINS_CTF_COMMON_SRC_ITEM_SEQ_ITEM_VISITOR_HPP */
