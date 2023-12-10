/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2022 Francis Deslauriers <francis.deslauriers@efficios.com>
 * Copyright 2024 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_TSDL_CTF_1_METADATA_STREAM_PARSER_HPP
#define BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_TSDL_CTF_1_METADATA_STREAM_PARSER_HPP

#include "cpp-common/bt2c/aliases.hpp"
#include "cpp-common/bt2c/libc-up.hpp"

#include "../../../metadata/ctf-ir.hpp"
#include "../ctf-ir.hpp"
#include "../metadata-stream-parser.hpp"
#include "ctf-meta.hpp"
#include "metadata-stream-decoder.hpp"
#include "scanner.hpp"

namespace ctf {
namespace src {

/*
 * CTF 1 metadata stream (TSDL) parser.
 *
 * Build an instance of `Ctf1MetadataStreamParser`, and then call
 * parseSection() as often as needed with one or more complete
 * packetized or plain text TSDL root blocks.
 *
 * You may also call the static Ctf1MetadataStreamParser::parse() method
 * to parse a whole packetized or plain text CTF 1 metadata stream.
 *
 * IMPLEMENTATION
 * ━━━━━━━━━━━━━━
 * The current parsing strategy is to reuse the C parser, which was
 * written for Babeltrace 2.0, almost as is.
 *
 * The output of said legacy parser is a `ctf_trace_class` instance.
 * When parsing more metadata stream data, the current legacy (original)
 * trace class (`_mOrigCtfIrGenerator->ctf_tc`) gets updated. This means
 * potentially adding more clock classes, data classes, and event
 * classes to `_mOrigCtfIrGenerator->ctf_tc`.
 *
 * The top-level legacy structures contain an `is_translated` member
 * which indicates whether or not a `Ctf1MetadataStreamParser` instance
 * translated from legacy CTF IR to woke CTF IR (the classes
 * of `ctf::src`).
 *
 * All in all, this is the data flow from packetized or plain text
 * metadata stream bytes to woke CTF IR instances:
 *
 *          ┌───────────────────────┐
 *          │ Metadata stream bytes │
 *          │ (possibly packetized) │
 *          └───────────────────────┘
 *                      ↓
 *         ╔═════════════════════════╗
 *         ║ Metadata stream decoder ║
 *         ║   (`_mStreamDecoder`)   ║
 *         ╚═════════════════════════╝
 *                      ↓
 *     ┌──────────────────────────────────┐
 *     │ Plain text metadata stream bytes │
 *     └──────────────────────────────────┘
 *                      ↓
 *              ╔═══════════════╗ ┈┈┈┈┈┈┈┈┈┈┈┈┈┈┐
 *              ║  AST scanner  ║               ┊
 *              ║ (`*_mScanner`)║               ┊
 *              ╚═══════════════╝               ┊
 *                      ↓                       ┊
 *          ┌───────────────────────┐           ┊
 *          │       AST nodes       │           ┊
 *          │ (within `*_mScanner`) │           ┊
 *          └───────────────────────┘           ┊
 *                      ↓                       ├┈ Legacy code
 *        ╔═══════════════════════════╗         ┊
 *        ║      AST node parser      ║         ┊
 *        ║ (`*_mOrigCtfIrGenerator`) ║         ┊
 *        ╚═══════════════════════════╝         ┊
 *                      ↓                       ┊
 *     ┌──────────────────────────────────┐     ┊
 *     │         Original CTF IR          │     ┊
 *     │ (`_mOrigCtfIrGenerator->ctf_tc`) │     ┊
 *     └──────────────────────────────────┘ ┈┈┈┈┘
 *                      ↓
 *       ╔══════════════════════════════╗
 *       ║         This parser          ║
 *       ║ (`Ctf1MetadataStreamParser`) ║
 *       ╚══════════════════════════════╝
 *                      ↓
 *              ┏━━━━━━━━━━━━━━┓
 *              ┃ Woke CTF IR  ┃
 *              ┃ (traceCls()) ┃
 *              ┗━━━━━━━━━━━━━━┛
 */
class Ctf1MetadataStreamParser final : public MetadataStreamParser
{
public:
    /*
     * Builds a CTF 1 metadata stream parser.
     *
     * If `selfComp` exists, then the parser uses it each time you call
     * parseSection() to finalize its current trace class.
     */
    explicit Ctf1MetadataStreamParser(bt2::OptionalBorrowedObject<bt2::SelfComponent> selfComp,
                                      const ClkClsCfg& clkClsCfg, const bt2c::Logger& parentLogger);

    /*
     * Parses the whole packetized or plain text CTF 1 metadata stream
     * in `buffer` and returns the resulting trace class and optional
     * metadata stream UUID on success, or appends a cause to the error
     * of the current thread and throws `bt2c::Error` otherwise.
     */
    static ParseRet parse(bt2::OptionalBorrowedObject<bt2::SelfComponent> selfComp,
                          const ClkClsCfg& clkClsCfg, bt2c::ConstBytes buffer,
                          const bt2c::Logger& parentLogger);

private:
    void _parseSection(bt2c::ConstBytes buffer) override;

    /*
     * Translates the original CTF IR field class `origFc` and returns
     * the translated object.
     */
    Fc::UP _fcFromOrigFc(const ctf_field_class& origFc);

    /*
     * Translates the original CTF IR structure field class `origFc` and
     * returns the translated object.
     */
    Fc::UP _fcFromOrigFc(const ctf_field_class_struct& origFc);

    /*
     * Translates the original CTF IR static-length array field class
     * `origFc` and returns the translated object.
     */
    Fc::UP _fcFromOrigFc(const ctf_field_class_array& origFc);

    /*
     * Translates the original CTF IR field path `origFieldPath` to a
     * field location and returns the translated object.
     */
    FieldLoc _fieldLocFromOrigFieldPath(const ctf_field_path& origFieldPath);

    /*
     * Translates the original CTF IR dynamic-length array field class
     * `origFc` and returns the translated object.
     */
    Fc::UP _fcFromOrigFc(const ctf_field_class_sequence& origFc);

    /*
     * Translates the options of the original CTF IR variant field class
     * `origFc` and returns the translated objects.
     */
    template <typename VariantFcT>
    typename VariantFcT::Opts _variantOptsFromOrigVariantFc(const ctf_field_class_variant& origFc)
    {
        typename VariantFcT::Opts opts;

        for (std::size_t iOpt = 0; iOpt < origFc.options->len; ++iOpt) {
            auto& origOpt = *ctf_field_class_variant_borrow_option_by_index_const(&origFc, iOpt);

            /*
             * In an original CTF IR variant field class FC, the
             * `ranges` member contains an array of integer ranges, each
             * one associated to a specific option of FC.
             *
             * Only add to `ranges` below the ones for the current
             * option.
             */
            typename VariantFcT::SelFieldRanges::Set ranges;

            for (std::size_t iRange = 0; iRange < origFc.ranges->len; ++iRange) {
                auto& origRange =
                    *ctf_field_class_variant_borrow_range_by_index_const(&origFc, iRange);

                if (origRange.option_index == iOpt) {
                    ranges.emplace(
                        static_cast<typename VariantFcT::SelVal>(origRange.range.lower.u),
                        static_cast<typename VariantFcT::SelVal>(origRange.range.upper.u));
                }
            }

            /* Create and add variant field class option */
            opts.emplace_back(createVariantFcOpt(
                this->_fcFromOrigFc(*origOpt.fc),
                typename VariantFcT::SelFieldRanges {std::move(ranges)}, origOpt.name->str));
        }

        return opts;
    }

    /*
     * Translates the original CTF IR variant field class `origFc` and
     * returns the translated object.
     */
    Fc::UP _fcFromOrigFc(const ctf_field_class_variant& origFc);

    /*
     * Translates the original CTF IR clock class `origClkCls` and
     * returns the translated object.
     */
    ClkCls::SP _clkClsFromOrigClkCls(const ctf_clock_class& origClkCls);

    /*
     * Tries to translate the original CTF IR event record class
     * `origEventRecordCls`, adding the translated object to the current
     * data stream class and marking it as translated on success.
     */
    void _tryTranslateEventRecordCls(ctf_event_class& origEventRecordCls);

    /*
     * Tries to translate the original CTF IR data stream class
     * `origDataStreamCls`, adding the translated object to the current
     * trace class and marking it as translated on success.
     *
     * Returns the translated data stream class.
     */
    DataStreamCls& _tryTranslateDataStreamCls(ctf_stream_class& origDataStreamCls);

    /*
     * Translates the original CTF IR trace class `origTraceCls` and
     * returns it.
     */
    std::unique_ptr<TraceCls> _translateTraceCls(ctf_trace_class& origTraceCls);

    /*
     * Tries to translate the original CTF IR trace class `origTraceCls`
     * as well as all its data stream and event record classes.
     */
    void _tryTranslate(ctf_trace_class& origTraceCls);

    /*
     * Returns an `std::FILE` unique pointer from the string `str`.
     *
     * `str` must remain alive and not change while you use the returned
     * object.
     */
    bt2c::FileUP _fileUpFromStr(const std::string& str);

    /*
     * Deleter for a unique pointer to CTF scanner.
     */
    struct _CtfScannerDeleter final
    {
        void operator()(ctf_scanner * const scanner) noexcept
        {
            ctf_scanner_free(scanner);
        }
    };

    /* Logging configuration */
    bt2c::Logger _mLogger;

    /* Map of original CTF IR clock classes to clock classes */
    std::unordered_map<const ctf_clock_class *, ClkCls::SP> _mClkClsMap;

    /* Field class translation context */
    struct
    {
        /* Current data stream class */
        DataStreamCls *dataStreamCls = nullptr;

        /* Original CTF IR trace class */
        const ctf_trace_class *origTraceCls = nullptr;

        /* Current original CTF IR data stream class */
        const ctf_stream_class *origDataStreamCls = nullptr;

        /* Current original CTF IR event record class */
        const ctf_event_class *origEventRecordCls = nullptr;
    } _mFcTranslationCtx;

    /* Original CTF IR generator (from AST nodes) */
    ctf_visitor_generate_ir::UP _mOrigCtfIrGenerator;

    /* TSDL scanner */
    std::unique_ptr<ctf_scanner, _CtfScannerDeleter> _mScanner;

    /* Metadata stream decoder */
    MetadataStreamDecoder _mStreamDecoder;
};

} /* namespace src */
} /* namespace ctf */

#endif /* BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_TSDL_CTF_1_METADATA_STREAM_PARSER_HPP */
