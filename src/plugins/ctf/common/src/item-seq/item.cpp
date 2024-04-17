/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include "item.hpp"

namespace ctf {
namespace src {

Item::Item(const Type type) noexcept : _mType {type}
{
}

BeginItem::BeginItem(const Type type) noexcept : Item {type}
{
}

EndItem::EndItem(const Type type) noexcept : Item {type}
{
}

PktBeginItem::PktBeginItem() noexcept : BeginItem {Type::PktBegin}
{
}

void PktBeginItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

PktEndItem::PktEndItem() noexcept : EndItem {Type::PktEnd}
{
}

void PktEndItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

ScopeBeginItem::ScopeBeginItem() noexcept : BeginItem {Type::ScopeBegin}
{
}

void ScopeBeginItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

ScopeEndItem::ScopeEndItem() noexcept : EndItem {Type::ScopeEnd}
{
}

void ScopeEndItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

EventRecordBeginItem::EventRecordBeginItem() noexcept : BeginItem {Type::EventRecordBegin}
{
}

void EventRecordBeginItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

EventRecordEndItem::EventRecordEndItem() noexcept : EndItem {Type::EventRecordEnd}
{
}

void EventRecordEndItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

PktContentBeginItem::PktContentBeginItem() noexcept : BeginItem {Type::PktContentBegin}
{
}

void PktContentBeginItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

PktContentEndItem::PktContentEndItem() noexcept : EndItem {Type::PktContentEnd}
{
}

void PktContentEndItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

PktMagicNumberItem::PktMagicNumberItem() noexcept : Item {Type::PktMagicNumber}
{
}

void PktMagicNumberItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

MetadataStreamUuidItem::MetadataStreamUuidItem() noexcept : Item {Type::MetadataStreamUuid}
{
}

void MetadataStreamUuidItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

DataStreamInfoItem::DataStreamInfoItem() noexcept : Item {Type::DataStreamInfo}
{
}

void DataStreamInfoItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

DefClkValItem::DefClkValItem() noexcept : Item {Type::DefClkValue}
{
}

void DefClkValItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

PktInfoItem::PktInfoItem() noexcept : Item {Type::PktInfo}
{
}

void PktInfoItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

EventRecordInfoItem::EventRecordInfoItem() noexcept : Item {Type::EventRecordInfo}
{
}

void EventRecordInfoItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

FixedLenBitArrayFieldItem::FixedLenBitArrayFieldItem(const Type type) noexcept : Item {type}
{
}

FixedLenBitArrayFieldItem::FixedLenBitArrayFieldItem() noexcept :
    FixedLenBitArrayFieldItem {Type::FixedLenBitArrayField}
{
}

void FixedLenBitArrayFieldItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

FixedLenBitMapFieldItem::FixedLenBitMapFieldItem() noexcept :
    FixedLenBitArrayFieldItem {Type::FixedLenBitMapField}
{
}

void FixedLenBitMapFieldItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

FixedLenBoolFieldItem::FixedLenBoolFieldItem() noexcept :
    FixedLenBitArrayFieldItem {Type::FixedLenBoolField}
{
}

void FixedLenBoolFieldItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

FixedLenSIntFieldItem::FixedLenSIntFieldItem(const Type type) noexcept :
    FixedLenBitArrayFieldItem {type}
{
}

FixedLenSIntFieldItem::FixedLenSIntFieldItem() noexcept :
    FixedLenSIntFieldItem {Type::FixedLenSIntField}
{
}

void FixedLenSIntFieldItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

FixedLenUIntFieldItem::FixedLenUIntFieldItem(const Type type) noexcept :
    FixedLenBitArrayFieldItem {type}
{
}

FixedLenUIntFieldItem::FixedLenUIntFieldItem() noexcept :
    FixedLenUIntFieldItem {Type::FixedLenUIntField}
{
}

void FixedLenUIntFieldItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

FixedLenFloatFieldItem::FixedLenFloatFieldItem() noexcept :
    FixedLenBitArrayFieldItem {Type::FixedLenFloatField}
{
}

void FixedLenFloatFieldItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

VarLenIntFieldItem::VarLenIntFieldItem(const Type type) noexcept :
    Item {type}, _mLen {bt2c::DataLen::fromBits(0)}
{
}

VarLenSIntFieldItem::VarLenSIntFieldItem(const Type type) noexcept : VarLenIntFieldItem {type}
{
}

VarLenSIntFieldItem::VarLenSIntFieldItem() noexcept : VarLenSIntFieldItem {Type::VarLenSIntField}
{
}

void VarLenSIntFieldItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

VarLenUIntFieldItem::VarLenUIntFieldItem(const Type type) noexcept : VarLenIntFieldItem {type}
{
}

VarLenUIntFieldItem::VarLenUIntFieldItem() noexcept : VarLenUIntFieldItem {Type::VarLenUIntField}
{
}

void VarLenUIntFieldItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

NullTerminatedStrFieldBeginItem::NullTerminatedStrFieldBeginItem() noexcept :
    BeginItem {Type::NullTerminatedStrFieldBegin}
{
}

void NullTerminatedStrFieldBeginItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

NullTerminatedStrFieldEndItem::NullTerminatedStrFieldEndItem() noexcept :
    EndItem {Type::NullTerminatedStrFieldEnd}
{
}

void NullTerminatedStrFieldEndItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

RawDataItem::RawDataItem() noexcept : Item {Type::RawData}
{
}

void RawDataItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

ArrayFieldBeginItem::ArrayFieldBeginItem(const Type type) noexcept : BeginItem {type}
{
}

ArrayFieldEndItem::ArrayFieldEndItem(const Type type) noexcept : EndItem {type}
{
}

StaticLenArrayFieldBeginItem::StaticLenArrayFieldBeginItem() noexcept :
    ArrayFieldBeginItem {Type::StaticLenArrayFieldBegin}
{
}

void StaticLenArrayFieldBeginItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

StaticLenArrayFieldEndItem::StaticLenArrayFieldEndItem() noexcept :
    ArrayFieldEndItem {Type::StaticLenArrayFieldEnd}
{
}

void StaticLenArrayFieldEndItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

DynLenArrayFieldBeginItem::DynLenArrayFieldBeginItem() noexcept :
    ArrayFieldBeginItem {Type::DynLenArrayFieldBegin}
{
}

void DynLenArrayFieldBeginItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

DynLenArrayFieldEndItem::DynLenArrayFieldEndItem() noexcept :
    ArrayFieldEndItem {Type::DynLenArrayFieldEnd}
{
}

void DynLenArrayFieldEndItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

StaticLenStrFieldBeginItem::StaticLenStrFieldBeginItem() noexcept :
    NonNullTerminatedStrFieldBeginItem {Type::StaticLenStrFieldBegin}
{
}

void StaticLenStrFieldBeginItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

StaticLenStrFieldEndItem::StaticLenStrFieldEndItem() noexcept :
    NonNullTerminatedStrFieldEndItem {Type::StaticLenStrFieldEnd}
{
}

void StaticLenStrFieldEndItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

DynLenStrFieldBeginItem::DynLenStrFieldBeginItem() noexcept :
    NonNullTerminatedStrFieldBeginItem {Type::DynLenStrFieldBegin}
{
}

void DynLenStrFieldBeginItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

DynLenStrFieldEndItem::DynLenStrFieldEndItem() noexcept :
    NonNullTerminatedStrFieldEndItem {Type::DynLenStrFieldEnd}
{
}

void DynLenStrFieldEndItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

StaticLenBlobFieldBeginItem::StaticLenBlobFieldBeginItem() noexcept :
    BlobFieldBeginItem {Type::StaticLenBlobFieldBegin}
{
}

void StaticLenBlobFieldBeginItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

StaticLenBlobFieldEndItem::StaticLenBlobFieldEndItem() noexcept :
    BlobFieldEndItem {Type::StaticLenBlobFieldEnd}
{
}

void StaticLenBlobFieldEndItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

DynLenBlobFieldBeginItem::DynLenBlobFieldBeginItem() noexcept :
    BlobFieldBeginItem {Type::DynLenBlobFieldBegin}
{
}

void DynLenBlobFieldBeginItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

DynLenBlobFieldEndItem::DynLenBlobFieldEndItem() noexcept :
    BlobFieldEndItem {Type::DynLenBlobFieldEnd}
{
}

void DynLenBlobFieldEndItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

StructFieldBeginItem::StructFieldBeginItem() noexcept : BeginItem {Type::StructFieldBegin}
{
}

void StructFieldBeginItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

StructFieldEndItem::StructFieldEndItem() noexcept : EndItem {Type::StructFieldEnd}
{
}

void StructFieldEndItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

VariantFieldBeginItem::VariantFieldBeginItem(const Type type) noexcept : BeginItem {type}
{
}

VariantFieldEndItem::VariantFieldEndItem(const Type type) noexcept : EndItem {type}
{
}

void VariantFieldWithUIntSelBeginItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

void VariantFieldWithUIntSelEndItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

void VariantFieldWithSIntSelBeginItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

void VariantFieldWithSIntSelEndItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

OptionalFieldBeginItem::OptionalFieldBeginItem(const Type type) noexcept : BeginItem {type}
{
}

OptionalFieldEndItem::OptionalFieldEndItem(const Type type) noexcept : EndItem {type}
{
}

OptionalFieldWithBoolSelBeginItem::OptionalFieldWithBoolSelBeginItem() noexcept :
    OptionalFieldBeginItem {Item::Type::OptionalFieldWithBoolSelBegin}
{
}

void OptionalFieldWithBoolSelBeginItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

OptionalFieldWithBoolSelEndItem::OptionalFieldWithBoolSelEndItem() noexcept :
    OptionalFieldEndItem {Item::Type::OptionalFieldWithBoolSelEnd}
{
}

void OptionalFieldWithBoolSelEndItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

void OptionalFieldWithUIntSelBeginItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

void OptionalFieldWithUIntSelEndItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

void OptionalFieldWithSIntSelBeginItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

void OptionalFieldWithSIntSelEndItem::accept(ItemVisitor& visitor) const
{
    visitor.visit(*this);
}

} /* namespace src */
} /* namespace ctf */
