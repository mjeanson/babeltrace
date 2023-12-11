/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2022 EfficiOS, Inc.
 */

#include "normalize-clk-offset.hpp"

namespace ctf {
namespace src {

std::pair<long long, unsigned long long> normalizeClkOffset(long long offsetSeconds,
                                                            unsigned long long offsetCycles,
                                                            const unsigned long long freq) noexcept
{
    if (offsetCycles >= freq) {
        const unsigned long long secInOffsetCycles = offsetCycles / freq;

        offsetSeconds += (long long) secInOffsetCycles;
        offsetCycles -= secInOffsetCycles * freq;
    }

    return std::make_pair(offsetSeconds, offsetCycles);
}

} /* namespace src */
} /* namespace ctf */
