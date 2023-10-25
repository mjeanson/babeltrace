/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022-2024 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_METADATA_STREAM_PARSER_HPP
#define BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_METADATA_STREAM_PARSER_HPP

#include <memory>
#include <unordered_set>
#include <utility>

#include "cpp-common/bt2/self-component-port.hpp"
#include "cpp-common/bt2c/aliases.hpp"
#include "cpp-common/bt2c/uuid.hpp"

#include "../clk-cls-cfg.hpp"
#include "ctf-ir.hpp"

namespace ctf {
namespace src {

/*
 * Abstract base CTF metadata stream parser class.
 */
class MetadataStreamParser
{
public:
    using UP = std::unique_ptr<MetadataStreamParser>;

    /*
     * Common return type of a static parse() method of a derived class.
     */
    struct ParseRet final
    {
        std::unique_ptr<TraceCls> traceCls;
        bt2s::optional<bt2c::Uuid> uuid;
    };

protected:
    explicit MetadataStreamParser(bt2::OptionalBorrowedObject<bt2::SelfComponent> selfComp,
                                  const ClkClsCfg& clkClsCfg) noexcept;

public:
    virtual ~MetadataStreamParser() = default;

    /*
     * Parses the section of metadata stream in `buffer` possibly
     * creating or updating the current trace class (as returned
     * by traceCls()).
     */
    void parseSection(bt2c::ConstBytes buffer);

    /*
     * Current trace class, or `nullptr` if none exists at this point.
     */
    const TraceCls *traceCls() const noexcept
    {
        return _mTraceCls.get();
    }

    /*
     * Releases the current trace class.
     */
    std::unique_ptr<TraceCls> releaseTraceCls() noexcept
    {
        return std::move(_mTraceCls);
    }

    /*
     * Current metadata stream UUID, or `bt2s::nullopt` if none exists
     * at this point.
     */
    const bt2s::optional<bt2c::Uuid>& metadataStreamUuid() const noexcept
    {
        return _mMetadataStreamUuid;
    }

    /* Log level names for user attributes */
    static const char * const logLevelEmergencyName;
    static const char * const logLevelAlertName;
    static const char * const logLevelCriticalName;
    static const char * const logLevelErrorName;
    static const char * const logLevelWarningName;
    static const char * const logLevelNoticeName;
    static const char * const logLevelInfoName;
    static const char * const logLevelDebugSystemName;
    static const char * const logLevelDebugProgramName;
    static const char * const logLevelDebugProcessName;
    static const char * const logLevelDebugModuleName;
    static const char * const logLevelDebugUnitName;
    static const char * const logLevelDebugFunctionName;
    static const char * const logLevelDebugLineName;
    static const char * const logLevelDebugName;

protected:
    /*
     * Self component access for derived classes.
     */
    bt2::OptionalBorrowedObject<bt2::SelfComponent> _selfComp() const noexcept
    {
        return _mSelfComp;
    }

private:
    virtual void _parseSection(bt2c::ConstBytes buffer) = 0;

    /*
     * Finalizes `*_mTraceCls` after its creation or when it gets new
     * data stream classes or event record classes.
     *
     * This function:
     *
     * • Sets the key value saving indexes of key field classes and the
     *   saved key value index of dependent (dynamic-length, optional,
     *   and variant) field classes.
     *
     * • Reconfigures the clock classes of `*_mTraceCls`
     *   using `_mClkClsCfg`.
     *
     * • Normalizes the offsets of the clock classes of `*_mTraceCls` so
     *   that the cycle part is less than the frequency.
     *
     * • If `_mSelfComp` exists, then translates the contained objects
     *   to their trace IR equivalents.
     */
    void _finalizeTraceCls();

    /*
     * Applies the clock offset of `_mClkClsCfg` to `clkCls`.
     */
    void _adjustClkClsOffsetFromOrigin(ClkCls& clkCls) noexcept;

    /*
     * Reconfigures `clkCls` using `_mClkClsCfg`.
     */
    void _adjustClkCls(ClkCls& clkCls) noexcept;

protected:
    /* Trace class */
    std::unique_ptr<TraceCls> _mTraceCls;

    /* Metadata stream UUID */
    bt2s::optional<bt2c::Uuid> _mMetadataStreamUuid;

private:
    /* Clock class configuration */
    ClkClsCfg _mClkClsCfg;

    /*
     * Clock classes to which we have already applied the config and
     * normalized.
     */
    std::unordered_set<const ClkCls *> _mAdjustedClkClasses;

    /* Self component, used to finalize `*_mTraceCls` */
    bt2::OptionalBorrowedObject<bt2::SelfComponent> _mSelfComp;
};

} /* namespace src */
} /* namespace ctf */

#endif /* BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_METADATA_STREAM_PARSER_HPP */
