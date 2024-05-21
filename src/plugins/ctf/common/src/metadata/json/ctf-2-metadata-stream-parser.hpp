/*
 * Copyright (c) 2022-2024 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_JSON_CTF_2_METADATA_STREAM_PARSER_HPP
#define BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_JSON_CTF_2_METADATA_STREAM_PARSER_HPP

#include <cstdint>

#include <babeltrace2/babeltrace.h>

#include "../ctf-ir.hpp"
#include "../metadata-stream-parser.hpp"
#include "ctf-2-fc-builder.hpp"
#include "val-req.hpp"

namespace ctf {
namespace src {

/*
 * CTF 2 metadata stream (JSON text sequence) parser.
 *
 * Build an instance of `Ctf2MetadataStreamParser`, and then call
 * parseSection() as often as needed with one or more _complete_
 * CTF 2 fragments.
 *
 * You may also call the static Ctf2MetadataStreamParser::parse() method
 * to parse a whole CTF 2 metadata stream.
 */
class Ctf2MetadataStreamParser final : public MetadataStreamParser
{
public:
    /*
     * Builds a CTF 2 metadata stream parser.
     *
     * If `selfComp` exists, then the parser uses it each time you call
     * parseSection() to finalize the current trace class.
     */
    explicit Ctf2MetadataStreamParser(bt2::OptionalBorrowedObject<bt2::SelfComponent> selfComp,
                                      const ClkClsCfg& clkClsCfg, const bt2c::Logger& parentLogger);

    /*
     * Parses the whole CTF 2 metadata stream in `buffer` and returns
     * the resulting trace class and optional metadata stream UUID on
     * success, or appends a cause to the error of the current thread
     * and throws `bt2c::Error` otherwise.
     */
    static ParseRet parse(bt2::OptionalBorrowedObject<bt2::SelfComponent> selfComp,
                          const ClkClsCfg& clkClsCfg, bt2c::ConstBytes buffer,
                          const bt2c::Logger& parentLogger);

private:
    void _parseSection(bt2c::ConstBytes buffer) override;

    /*
     * Parses one or more complete fragments in `buffer`, updating the
     * internal state on success, or appending a cause to the error of
     * the current thread and throwing `bt2c::Error` otherwise.
     */
    void _parseFragments(bt2c::ConstBytes buffer);

    /*
     * Parses the JSON fragment in `buffer`, updating the internal state
     * on success, or appending a cause to the error of the current
     * thread and throwing `bt2c::Error` on failure.
     */
    void _parseFragment(bt2c::ConstBytes buffer);

    /*
     * Handles the JSON fragment `jsonFragment`, updating the internal
     * state on success, or appending a cause to the error of the
     * current thread and throwing `bt2c::Error` on failure.
     */
    void _handleFragment(const bt2c::JsonVal& jsonFragment);

    /*
     * Handles the JSON field class alias fragment `jsonFragment`,
     * updating the internal state on success, or appending a cause to
     * the error of the current thread and throwing `bt2c::Error`
     * on failure.
     */
    void _handleFcAliasFragment(const bt2c::JsonObjVal& jsonFragment);

    /*
     * Forwards to validateScopeFcRoles() using the logger of
     * this parser..
     *
     * Appends a cause to the error of the current thread and throwing
     * `bt2c::Error` on failure.
     */
    void _validateScopeFcRoles(const Fc& fc, const UIntFieldRoles& allowedRoles,
                               bool allowMetadataStreamUuidRole);

    /*
     * Validates the field roles of the packet header field class `fc`.
     */
    void _validatePktHeaderFcRoles(const Fc& fc);

    /*
     * Validates the field roles of the JSON trace class fragment
     * `jsonFragment`.
     */
    void _validateTraceClsFragmentRoles(const bt2c::JsonObjVal& jsonFragment);

    /*
     * Handles the JSON trace class fragment `jsonFragment`, updating
     * the internal state on success, or appending a cause to the error
     * of the current thread and throwing `bt2c::Error` on
     * failure.
     */
    void _handleTraceClsFragment(const bt2c::JsonObjVal& jsonFragment);

    /*
     * Handles the JSON clock class fragment `jsonFragment`, updating
     * the internal state on success, or appending a cause to the error
     * of the current thread and throwing `bt2c::Error` on
     * failure.
     */
    void _handleClkClsFragment(const bt2c::JsonObjVal& jsonFragment);

    /*
     * Validates that the field class `fc` doesn't contain an unsigned
     * integer field class having a default clock timestamp role if
     * `allowDefClkTsRole` is false.
     */
    void _validateClkTsRoles(const Fc& fc, bool allowClkTsRole);

    /*
     * Validates the roles of the packet context, event record header,
     * and common event record context field classes `pktCtxFc`,
     * `eventRecordHeaderFc`, and `commonEventRecordCtxFc`.
     */
    void _validateDataStreamClsRoles(const Fc *pktCtxFc, const Fc *eventRecordHeaderFc,
                                     const Fc *commonEventRecordCtxFc, bool allowDefClkTsRole);

    /*
     * Handles the JSON data stream class fragment `jsonFragment`,
     * updating the internal state on success, or appending a cause to
     * the error of the current thread and throwing `bt2c::Error`
     * on failure.
     */
    void _handleDataStreamClsFragment(const bt2c::JsonObjVal& jsonFragment);

    /*
     * Validates the roles of specific event record context and event
     * record payload field classes `specCtxFc` and `payloadFc`.
     */
    void _validateEventRecordClsRoles(const Fc *specCtxFc, const Fc *payloadFc);

    /*
     * Handles the JSON event record class fragment `jsonFragment`,
     * updating the internal state on success, or appending a cause to
     * the error of the current thread and throwing `bt2c::Error`
     * on failure.
     */
    void _handleEventRecordClsFragment(const bt2c::JsonObjVal& jsonFragment);

    /*
     * Ensures that `*_mTraceCls` exists.
     */
    void _ensureExistingTraceCls();

    /*
     * If a JSON value has the key `key` in `jsonVal`:
     *     Returns `nullptr`.
     *
     * Otherwise:
     *     Converts `*jsonVal[key]` to a scope field class and returns
     *     it, considering `pktHeaderFc`, `pktCtxFc`,
     *     `eventRecordHeaderFc`, `commonEventRecordCtxFc`,
     *     `specEventRecordCtxFc`, and `eventRecordPayloadFc` as the
     *     current packet header, packet context, event record header,
     *     common event record context, specific event record context,
     *     and event record payload field classes.
     */
    Fc::UP _scopeFcOfJsonVal(const bt2c::JsonObjVal& jsonVal, const std::string& key, Scope scope,
                             const Fc *pktHeaderFc = nullptr, const Fc *pktCtxFc = nullptr,
                             const Fc *eventRecordHeaderFc = nullptr,
                             const Fc *commonEventRecordCtxFc = nullptr,
                             const Fc *specEventRecordCtxFc = nullptr,
                             const Fc *eventRecordPayloadFc = nullptr);

    /*
     * If a JSON value has the key `key` in the JSON event record class
     * fragment value `jsonVal`:
     *     Returns `nullptr`.
     *
     * Otherwise:
     *     Converts `*jsonEventRecordCls[key]` to a scope field class
     *     and returns it, considering the current packet header field
     *     class, the field classes of `dataStreamCls`, and
     *     `specEventRecordCtxFc` and `eventRecordPayloadFc` as the
     *     current specific event record context and event record
     *     payload field classes.
     */
    Fc::UP _eventRecordClsScopeFcOfJsonVal(const bt2c::JsonObjVal& jsonEventRecordCls,
                                           const std::string& key, Scope scope,
                                           const DataStreamCls& dataStreamCls,
                                           const Fc *specEventRecordCtxFc = nullptr,
                                           const Fc *eventRecordPayloadFc = nullptr);

    /*
     * If a JSON value has the key `key` in the JSON data stream class
     * fragment value `jsonDataStreamCls`:
     *     Returns `nullptr`.
     *
     * Otherwise:
     *     Converts `*jsonDataStreamCls[key]` to a field class and
     *     returns it, considering the current packet header field
     *     class, and `pktCtxFc`, `eventRecordHeaderFc`, and
     *     `commonEventRecordCtxFc` as the current packet context, event
     *     record header, and common event record context field classes.
     */
    Fc::UP _dataStreamClsScopeFcOfJsonVal(const bt2c::JsonObjVal& jsonDataStreamCls,
                                          const std::string& key, Scope scope,
                                          const Fc *pktCtxFc = nullptr,
                                          const Fc *eventRecordHeaderFc = nullptr,
                                          const Fc *commonEventRecordCtxFc = nullptr);

    /*
     * If a JSON value has the key `key` in the JSON trace class
     * fragment value `jsonTraceCls`:
     *     Returns `nullptr`.
     *
     * Otherwise:
     *     Converts `*jsonTraceCls[key]` to a field class and returns
     *     it, considering the JSON trace class fragment value
     *     `jsonTraceCls` as the conversion context.
     */
    Fc::UP _traceClsScopeFcOfJsonVal(const bt2c::JsonObjVal& jsonTraceCls, const std::string& key);

    /*
     * Returns a text location with an offset of `at` relative to the
     * `buffer.begin()`, also considering `_mCurOffsetInStream`.
     *
     * `at` must be within `buffer`.
     */
    bt2c::TextLoc _loc(bt2c::ConstBytes buffer,
                       const bt2c::ConstBytes::const_iterator at) const noexcept
    {
        BT_ASSERT_DBG(at >= buffer.begin());
        BT_ASSERT_DBG(at < buffer.end());
        return bt2c::TextLoc {_mCurOffsetInStream.bytes() + (at - buffer.begin())};
    }

private:
    /* Logging configuration */
    bt2c::Logger _mLogger;

    /* Current offset within the whole metadata stream */
    bt2c::DataLen _mCurOffsetInStream = bt2c::DataLen::fromBytes(0);

    /* Current fragment index */
    std::size_t _mCurFragmentIndex = 0;

    /* Fragment requirement */
    Ctf2JsonAnyFragmentValReq _mFragmentValReq;

    /* Default clock offset JSON value */
    bt2c::JsonObjVal::UP _mDefClkOffsetVal;

    /*
     * Map of clock class ID to clock class object.
     *
     * Clock class fragments "float" in a CTF 2 metadata stream, in that
     * they aren't used yet, but could be afterwards through an ID
     * reference within a data stream class.
     *
     * This map stores them until the parser needs one for a data
     * stream class.
     */
    std::unordered_map<std::string, ClkCls::SP> _mClkClasses;

    /* Field class builder, which keeps track of field class aliases */
    Ctf2FcBuilder _mFcBuilder;
};

} /* namespace src */
} /* namespace ctf */

#endif /* BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_JSON_CTF_2_METADATA_STREAM_PARSER_HPP */
