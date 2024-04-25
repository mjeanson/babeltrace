
/*
 * Copyright (c) 2022 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */
#include <fstream>

#include "logging.hpp"

#include "exc.hpp"
#include "file-utils.hpp"

namespace bt2c {

std::vector<std::uint8_t> dataFromFile(const char * const filePath, const Logger& logger,
                                       const bool fatalError)
{
    /*
     * Open a file stream and seek to the end of the stream to compute the size
     * of the buffer required.
    */
    std::ifstream file {filePath, std::ios::binary | std::ios::ate};

    if (!file) {
        constexpr const char *msg = "No such file or directory: path=\"{}\"";

        if (fatalError) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(logger, msg, filePath);
        } else {
            BT_CPPLOGD_SPEC(logger, msg, filePath);
        }

        throw NoSuchFileOrDirectoryError {};
    }

    const auto size = file.tellg();
    std::vector<uint8_t> buffer(static_cast<std::size_t>(size));

    /*
     * Seek the reading head back at the beginning of the stream to actually
     * read the content.
     */
    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char *>(buffer.data()), size);
    return buffer;
}

} /* namespace bt2c */
