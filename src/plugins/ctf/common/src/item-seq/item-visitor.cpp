/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include "item-visitor.hpp"
#include "item.hpp"

namespace ctf {
namespace src {

void ItemVisitor::visit(const Item&)
{
}

void ItemVisitor::visit(const BeginItem& item)
{
    this->visit(static_cast<const Item&>(item));
}

void ItemVisitor::visit(const EndItem& item)
{
    this->visit(static_cast<const Item&>(item));
}

void ItemVisitor::visit(const PktBeginItem& item)
{
    this->visit(static_cast<const BeginItem&>(item));
}

void ItemVisitor::visit(const PktEndItem& item)
{
    this->visit(static_cast<const EndItem&>(item));
}

void ItemVisitor::visit(const ScopeBeginItem& item)
{
    this->visit(static_cast<const BeginItem&>(item));
}

void ItemVisitor::visit(const ScopeEndItem& item)
{
    this->visit(static_cast<const EndItem&>(item));
}

void ItemVisitor::visit(const PktContentBeginItem& item)
{
    this->visit(static_cast<const BeginItem&>(item));
}

void ItemVisitor::visit(const PktContentEndItem& item)
{
    this->visit(static_cast<const EndItem&>(item));
}

void ItemVisitor::visit(const EventRecordBeginItem& item)
{
    this->visit(static_cast<const BeginItem&>(item));
}

void ItemVisitor::visit(const EventRecordEndItem& item)
{
    this->visit(static_cast<const EndItem&>(item));
}

void ItemVisitor::visit(const PktMagicNumberItem& item)
{
    this->visit(static_cast<const Item&>(item));
}

void ItemVisitor::visit(const MetadataStreamUuidItem& item)
{
    this->visit(static_cast<const Item&>(item));
}

void ItemVisitor::visit(const DefClkValItem& item)
{
    this->visit(static_cast<const Item&>(item));
}

void ItemVisitor::visit(const DataStreamInfoItem& item)
{
    this->visit(static_cast<const Item&>(item));
}

void ItemVisitor::visit(const PktInfoItem& item)
{
    this->visit(static_cast<const Item&>(item));
}

void ItemVisitor::visit(const EventRecordInfoItem& item)
{
    this->visit(static_cast<const Item&>(item));
}

void ItemVisitor::visit(const FixedLenBitArrayFieldItem& item)
{
    this->visit(static_cast<const Item&>(item));
}

void ItemVisitor::visit(const FixedLenBitMapFieldItem& item)
{
    this->visit(static_cast<const FixedLenBitArrayFieldItem&>(item));
}

void ItemVisitor::visit(const FixedLenBoolFieldItem& item)
{
    this->visit(static_cast<const FixedLenBitArrayFieldItem&>(item));
}

void ItemVisitor::visit(const FixedLenSIntFieldItem& item)
{
    this->visit(static_cast<const FixedLenBitArrayFieldItem&>(item));
}

void ItemVisitor::visit(const FixedLenUIntFieldItem& item)
{
    this->visit(static_cast<const FixedLenBitArrayFieldItem&>(item));
}

void ItemVisitor::visit(const FixedLenFloatFieldItem& item)
{
    this->visit(static_cast<const FixedLenBitArrayFieldItem&>(item));
}

void ItemVisitor::visit(const VarLenIntFieldItem& item)
{
    this->visit(static_cast<const Item&>(item));
}

void ItemVisitor::visit(const VarLenSIntFieldItem& item)
{
    this->visit(static_cast<const VarLenIntFieldItem&>(item));
}

void ItemVisitor::visit(const VarLenUIntFieldItem& item)
{
    this->visit(static_cast<const VarLenIntFieldItem&>(item));
}

void ItemVisitor::visit(const NullTerminatedStrFieldBeginItem& item)
{
    this->visit(static_cast<const BeginItem&>(item));
}

void ItemVisitor::visit(const NullTerminatedStrFieldEndItem& item)
{
    this->visit(static_cast<const EndItem&>(item));
}

void ItemVisitor::visit(const RawDataItem& item)
{
    this->visit(static_cast<const Item&>(item));
}

void ItemVisitor::visit(const ArrayFieldBeginItem& item)
{
    this->visit(static_cast<const BeginItem&>(item));
}

void ItemVisitor::visit(const ArrayFieldEndItem& item)
{
    this->visit(static_cast<const EndItem&>(item));
}

void ItemVisitor::visit(const StaticLenArrayFieldBeginItem& item)
{
    this->visit(static_cast<const ArrayFieldBeginItem&>(item));
}

void ItemVisitor::visit(const StaticLenArrayFieldEndItem& item)
{
    this->visit(static_cast<const ArrayFieldEndItem&>(item));
}

void ItemVisitor::visit(const DynLenArrayFieldBeginItem& item)
{
    this->visit(static_cast<const ArrayFieldBeginItem&>(item));
}

void ItemVisitor::visit(const DynLenArrayFieldEndItem& item)
{
    this->visit(static_cast<const ArrayFieldEndItem&>(item));
}

void ItemVisitor::visit(const NonNullTerminatedStrFieldBeginItem& item)
{
    this->visit(static_cast<const BeginItem&>(item));
}

void ItemVisitor::visit(const NonNullTerminatedStrFieldEndItem& item)
{
    this->visit(static_cast<const EndItem&>(item));
}

void ItemVisitor::visit(const StaticLenStrFieldBeginItem& item)
{
    this->visit(static_cast<const NonNullTerminatedStrFieldBeginItem&>(item));
}

void ItemVisitor::visit(const StaticLenStrFieldEndItem& item)
{
    this->visit(static_cast<const NonNullTerminatedStrFieldEndItem&>(item));
}

void ItemVisitor::visit(const DynLenStrFieldBeginItem& item)
{
    this->visit(static_cast<const NonNullTerminatedStrFieldBeginItem&>(item));
}

void ItemVisitor::visit(const DynLenStrFieldEndItem& item)
{
    this->visit(static_cast<const NonNullTerminatedStrFieldEndItem&>(item));
}

void ItemVisitor::visit(const BlobFieldBeginItem& item)
{
    this->visit(static_cast<const BeginItem&>(item));
}

void ItemVisitor::visit(const BlobFieldEndItem& item)
{
    this->visit(static_cast<const EndItem&>(item));
}

void ItemVisitor::visit(const StaticLenBlobFieldBeginItem& item)
{
    this->visit(static_cast<const BlobFieldBeginItem&>(item));
}

void ItemVisitor::visit(const StaticLenBlobFieldEndItem& item)
{
    this->visit(static_cast<const BlobFieldEndItem&>(item));
}

void ItemVisitor::visit(const DynLenBlobFieldBeginItem& item)
{
    this->visit(static_cast<const BlobFieldBeginItem&>(item));
}

void ItemVisitor::visit(const DynLenBlobFieldEndItem& item)
{
    this->visit(static_cast<const BlobFieldEndItem&>(item));
}

void ItemVisitor::visit(const StructFieldBeginItem& item)
{
    this->visit(static_cast<const BeginItem&>(item));
}

void ItemVisitor::visit(const StructFieldEndItem& item)
{
    this->visit(static_cast<const EndItem&>(item));
}

void ItemVisitor::visit(const VariantFieldBeginItem& item)
{
    this->visit(static_cast<const BeginItem&>(item));
}

void ItemVisitor::visit(const VariantFieldEndItem& item)
{
    this->visit(static_cast<const EndItem&>(item));
}

void ItemVisitor::visit(const VariantFieldWithSIntSelBeginItem& item)
{
    this->visit(static_cast<const VariantFieldBeginItem&>(item));
}

void ItemVisitor::visit(const VariantFieldWithSIntSelEndItem& item)
{
    this->visit(static_cast<const VariantFieldEndItem&>(item));
}

void ItemVisitor::visit(const VariantFieldWithUIntSelBeginItem& item)
{
    this->visit(static_cast<const VariantFieldBeginItem&>(item));
}

void ItemVisitor::visit(const VariantFieldWithUIntSelEndItem& item)
{
    this->visit(static_cast<const VariantFieldEndItem&>(item));
}

void ItemVisitor::visit(const OptionalFieldBeginItem& item)
{
    this->visit(static_cast<const BeginItem&>(item));
}

void ItemVisitor::visit(const OptionalFieldEndItem& item)
{
    this->visit(static_cast<const EndItem&>(item));
}

void ItemVisitor::visit(const OptionalFieldWithBoolSelBeginItem& item)
{
    this->visit(static_cast<const OptionalFieldBeginItem&>(item));
}

void ItemVisitor::visit(const OptionalFieldWithBoolSelEndItem& item)
{
    this->visit(static_cast<const OptionalFieldEndItem&>(item));
}

void ItemVisitor::visit(const OptionalFieldWithSIntSelBeginItem& item)
{
    this->visit(static_cast<const OptionalFieldBeginItem&>(item));
}

void ItemVisitor::visit(const OptionalFieldWithSIntSelEndItem& item)
{
    this->visit(static_cast<const OptionalFieldEndItem&>(item));
}

void ItemVisitor::visit(const OptionalFieldWithUIntSelBeginItem& item)
{
    this->visit(static_cast<const OptionalFieldBeginItem&>(item));
}

void ItemVisitor::visit(const OptionalFieldWithUIntSelEndItem& item)
{
    this->visit(static_cast<const OptionalFieldEndItem&>(item));
}

} /* namespace src */
} /* namespace ctf */
