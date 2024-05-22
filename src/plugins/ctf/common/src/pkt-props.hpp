/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022 EfficiOS Inc. and Linux Foundation
 */

#ifndef BABELTRACE_PLUGINS_CTF_COMMON_SRC_PKT_PROPS_HPP
#define BABELTRACE_PLUGINS_CTF_COMMON_SRC_PKT_PROPS_HPP

#include "cpp-common/bt2c/data-len.hpp"
#include "cpp-common/bt2c/logging.hpp"
#include "cpp-common/bt2s/optional.hpp"

#include "item-seq/medium.hpp"
#include "metadata/ctf-ir.hpp"

namespace ctf {
namespace src {

struct PktProps final
{
    bt2s::optional<bt2c::DataLen> expectedTotalLen;
    bt2s::optional<bt2c::DataLen> expectedContentLen;
    const DataStreamCls *dataStreamCls;
    bt2s::optional<unsigned long long> dataStreamId;

    struct
    {
        bt2s::optional<unsigned long long> discEventRecordCounter;
        bt2s::optional<unsigned long long> beginDefClk;
        bt2s::optional<unsigned long long> endDefClk;
    } snapshots;
};

/*
 * Extract packet properties at offset.
 */
PktProps readPktProps(const TraceCls& traceCls, Medium::UP medium, bt2c::DataLen pktOffset,
                      const bt2c::Logger& parentLogger);

} /* namespace src */
} /* namespace ctf */

#endif /* BABELTRACE_PLUGINS_CTF_COMMON_SRC_PKT_PROPS_HPP */
