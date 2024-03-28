/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2016-2017 Philippe Proulx <pproulx@efficios.com>
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "common/uuid.h"
#include "compat/memstream.h"

#include "decoder-packetized-file-stream-to-buf.hpp"
#include "decoder.hpp"

#define TSDL_MAGIC 0x75d11d57

struct packet_header
{
    uint32_t magic;
    bt_uuid_t uuid;
    uint32_t checksum;
    uint32_t content_size;
    uint32_t packet_size;
    uint8_t compression_scheme;
    uint8_t encryption_scheme;
    uint8_t checksum_scheme;
    uint8_t major;
    uint8_t minor;
} __attribute__((__packed__));

static int decode_packet(FILE *in_fp, FILE *out_fp, int byte_order, bool *is_uuid_set,
                         uint8_t *uuid, const bt2c::Logger& logger)
{
    struct packet_header header;
    size_t readlen, writelen, toread;
    uint8_t buf[512 + 1]; /* + 1 for debug-mode \0 */
    int ret = 0;
    const long offset = ftell(in_fp);

    if (offset < 0) {
        BT_CPPLOGE_ERRNO_APPEND_CAUSE_SPEC(logger, "Failed to get current metadata file position",
                                           ".");
        goto error;
    }
    BT_CPPLOGD_SPEC(logger, "Decoding metadata packet: offset={}", offset);
    readlen = fread(&header, sizeof(header), 1, in_fp);
    if (feof(in_fp) != 0) {
        BT_CPPLOGI_SPEC(logger, "Reached end of file: offset={}", ftell(in_fp));
        goto end;
    }
    if (readlen < 1) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(logger, "Cannot decode metadata packet: offset={}", offset);
        goto error;
    }

    if (byte_order != BYTE_ORDER) {
        header.magic = GUINT32_SWAP_LE_BE(header.magic);
        header.checksum = GUINT32_SWAP_LE_BE(header.checksum);
        header.content_size = GUINT32_SWAP_LE_BE(header.content_size);
        header.packet_size = GUINT32_SWAP_LE_BE(header.packet_size);
    }

    if (header.compression_scheme) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(
            logger,
            "Metadata packet compression is not supported as of this version: "
            "compression-scheme={}, offset={}",
            (unsigned int) header.compression_scheme, offset);
        goto error;
    }

    if (header.encryption_scheme) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(
            logger,
            "Metadata packet encryption is not supported as of this version: "
            "encryption-scheme={}, offset={}",
            (unsigned int) header.encryption_scheme, offset);
        goto error;
    }

    if (header.checksum || header.checksum_scheme) {
        auto checksum = header.checksum;

        BT_CPPLOGE_APPEND_CAUSE_SPEC(
            logger,
            "Metadata packet checksum verification is not supported as of this version: "
            "checksum-scheme={}, checksum={}, offset={}",
            (unsigned int) header.checksum_scheme, checksum, offset);
        goto error;
    }

    if (!ctf_metadata_decoder_is_packet_version_valid(header.major, header.minor)) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(logger,
                                     "Invalid metadata packet version: "
                                     "version={}.{}, offset={}",
                                     header.major, header.minor, offset);
        goto error;
    }

    /* Set expected trace UUID if not set; otherwise validate it */
    if (is_uuid_set) {
        if (!*is_uuid_set) {
            bt_uuid_copy(uuid, header.uuid);
            *is_uuid_set = true;
        } else if (bt_uuid_compare(header.uuid, uuid)) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(
                logger,
                "Metadata UUID mismatch between packets of the same stream: "
                "packet-uuid=\"" BT_UUID_FMT "\", "
                "expected-uuid=\"" BT_UUID_FMT "\", "
                "offset={}",
                BT_UUID_FMT_VALUES(header.uuid), BT_UUID_FMT_VALUES(uuid), offset);
            goto error;
        }
    }

    if ((header.content_size / CHAR_BIT) < sizeof(header)) {
        auto content_size = header.content_size;

        BT_CPPLOGE_APPEND_CAUSE_SPEC(logger,
                                     "Bad metadata packet content size: content-size={}, "
                                     "offset={}",
                                     content_size, offset);
        goto error;
    }

    toread = header.content_size / CHAR_BIT - sizeof(header);

    for (;;) {
        size_t loop_read;

        loop_read = MIN(sizeof(buf) - 1, toread);
        readlen = fread(buf, sizeof(uint8_t), loop_read, in_fp);
        if (ferror(in_fp)) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(logger,
                                         "Cannot read metadata packet buffer: "
                                         "offset={}, read-size={}",
                                         ftell(in_fp), loop_read);
            goto error;
        }
        if (readlen > loop_read) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(logger,
                                         "fread returned more byte than expected: "
                                         "read-size-asked={}, read-size-returned={}",
                                         loop_read, readlen);
            goto error;
        }

        writelen = fwrite(buf, sizeof(uint8_t), readlen, out_fp);
        if (writelen < readlen || ferror(out_fp)) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(logger,
                                         "Cannot write decoded metadata text to buffer: "
                                         "read-offset={}, write-size={}",
                                         ftell(in_fp), readlen);
            goto error;
        }

        toread -= readlen;
        if (toread == 0) {
            int fseek_ret;

            /* Read leftover padding */
            toread = (header.packet_size - header.content_size) / CHAR_BIT;
            fseek_ret = fseek(in_fp, toread, SEEK_CUR);
            if (fseek_ret < 0) {
                BT_CPPLOGW_STR_SPEC(logger, "Missing padding at the end of the metadata stream.");
            }
            break;
        }
    }

    goto end;

error:
    ret = -1;

end:
    return ret;
}

int ctf_metadata_decoder_packetized_file_stream_to_buf(FILE *fp, char **buf, int byte_order,
                                                       bool *is_uuid_set, uint8_t *uuid,
                                                       const bt2c::Logger& parentLogger)
{
    FILE *out_fp;
    size_t size;
    int ret = 0;
    int tret;
    size_t packet_index = 0;
    bt2c::Logger logger {parentLogger, "PLUGIN/CTF/META/DECODER-DECODE-PACKET"};

    out_fp = bt_open_memstream(buf, &size);
    if (!out_fp) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(logger, "Cannot open memory stream: {}.", strerror(errno));
        goto error;
    }

    for (;;) {
        if (feof(fp) != 0) {
            break;
        }

        tret = decode_packet(fp, out_fp, byte_order, is_uuid_set, uuid, logger);
        if (tret) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(logger, "Cannot decode packet: index={}", packet_index);
            goto error;
        }

        packet_index++;
    }

    /* Make sure the whole string ends with a null character */
    tret = fputc('\0', out_fp);
    if (tret == EOF) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(logger, "Cannot append '\\0' to the decoded metadata buffer.");
        goto error;
    }

    /* Close stream, which also flushes the buffer */
    ret = bt_close_memstream(buf, &size, out_fp);
    /*
     * See fclose(3). Further access to out_fp after both success
     * and error, even through another bt_close_memstream(), results
     * in undefined behavior. Nullify out_fp to ensure we don't
     * fclose it twice on error.
     */
    out_fp = NULL;
    if (ret < 0) {
        BT_CPPLOGE_ERRNO_APPEND_CAUSE_SPEC(logger, "Cannot close memory stream", ".");
        goto error;
    }

    goto end;

error:
    ret = -1;

    if (out_fp) {
        if (bt_close_memstream(buf, &size, out_fp)) {
            BT_CPPLOGE_ERRNO_SPEC(logger, "Cannot close memory stream", ".");
        }
    }

    if (*buf) {
        free(*buf);
        *buf = NULL;
    }

end:
    return ret;
}
