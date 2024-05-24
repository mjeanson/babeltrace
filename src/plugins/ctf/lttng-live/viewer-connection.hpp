/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2016 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef BABELTRACE_PLUGINS_CTF_LTTNG_LIVE_VIEWER_CONNECTION_HPP
#define BABELTRACE_PLUGINS_CTF_LTTNG_LIVE_VIEWER_CONNECTION_HPP

#include <memory>
#include <string>

#include <glib.h>
#include <stdint.h>

#include <babeltrace2/babeltrace.h>

#include "compat/socket.hpp"
#include "cpp-common/bt2/value.hpp"
#include "cpp-common/bt2c/glib-up.hpp"
#include "cpp-common/bt2c/logging.hpp"

#define LTTNG_DEFAULT_NETWORK_VIEWER_PORT 5344

#define LTTNG_LIVE_MAJOR 2
#define LTTNG_LIVE_MINOR 4

enum lttng_live_viewer_status
{
    LTTNG_LIVE_VIEWER_STATUS_OK = 0,
    LTTNG_LIVE_VIEWER_STATUS_ERROR = -1,
    LTTNG_LIVE_VIEWER_STATUS_INTERRUPTED = -2,
};

enum lttng_live_get_one_metadata_status
{
    /* The end of the metadata stream was reached. */
    LTTNG_LIVE_GET_ONE_METADATA_STATUS_END = 1,
    /* One metadata packet was received and written to file. */
    LTTNG_LIVE_GET_ONE_METADATA_STATUS_OK = LTTNG_LIVE_VIEWER_STATUS_OK,
    /*
     * A critical error occurred when contacting the relay or while
     * handling its response.
     */
    LTTNG_LIVE_GET_ONE_METADATA_STATUS_ERROR = LTTNG_LIVE_VIEWER_STATUS_ERROR,

    LTTNG_LIVE_GET_ONE_METADATA_STATUS_INTERRUPTED = LTTNG_LIVE_VIEWER_STATUS_INTERRUPTED,

    /* The metadata stream was not found on the relay. */
    LTTNG_LIVE_GET_ONE_METADATA_STATUS_CLOSED = -3,
};

struct live_viewer_connection
{
    using UP = std::unique_ptr<live_viewer_connection>;

    explicit live_viewer_connection(const bt2c::Logger& parentLogger) :
        logger {parentLogger, "PLUGIN/SRC.CTF.LTTNG-LIVE/VIEWER"}
    {
    }

    ~live_viewer_connection();

    bt2c::Logger logger;

    std::string url;

    bt2c::GStringUP relay_hostname;
    bt2c::GStringUP target_hostname;
    bt2c::GStringUP session_name;
    bt2c::GStringUP proto;

    BT_SOCKET control_sock {};
    int port = 0;

    int32_t major = 0;
    int32_t minor = 0;

    bool in_query = false;
    struct lttng_live_msg_iter *lttng_live_msg_iter = nullptr;
};

struct packet_index_time
{
    uint64_t timestamp_begin;
    uint64_t timestamp_end;
};

struct packet_index
{
    off_t offset;          /* offset of the packet in the file, in bytes */
    int64_t data_offset;   /* offset of data within the packet, in bits */
    uint64_t packet_size;  /* packet size, in bits */
    uint64_t content_size; /* content size, in bits */
    uint64_t events_discarded;
    uint64_t events_discarded_len;      /* length of the field, in bits */
    struct packet_index_time ts_cycles; /* timestamp in cycles */
    struct packet_index_time ts_real;   /* realtime timestamp */
    /* CTF_INDEX 1.0 limit */
    uint64_t stream_instance_id; /* ID of the channel instance */
    uint64_t packet_seq_num;     /* packet sequence number */
};

enum lttng_live_viewer_status
live_viewer_connection_create(const char *url, bool in_query,
                              struct lttng_live_msg_iter *lttng_live_msg_iter,
                              const bt2c::Logger& parentLogger, live_viewer_connection::UP& viewer);

enum lttng_live_viewer_status
lttng_live_create_viewer_session(struct lttng_live_msg_iter *lttng_live_msg_iter);

bt2::Value::Shared
live_viewer_connection_list_sessions(struct live_viewer_connection *viewer_connection);

enum lttng_live_get_stream_bytes_status
{
    LTTNG_LIVE_GET_STREAM_BYTES_STATUS_OK = __BT_FUNC_STATUS_OK,
    LTTNG_LIVE_GET_STREAM_BYTES_STATUS_AGAIN = __BT_FUNC_STATUS_AGAIN,
    LTTNG_LIVE_GET_STREAM_BYTES_STATUS_ERROR = __BT_FUNC_STATUS_ERROR,
    LTTNG_LIVE_GET_STREAM_BYTES_STATUS_EOF = __BT_FUNC_STATUS_END,
};

lttng_live_get_stream_bytes_status
lttng_live_get_stream_bytes(struct lttng_live_msg_iter *lttng_live_msg_iter,
                            struct lttng_live_stream_iterator *stream, uint8_t *buf,
                            uint64_t offset, uint64_t req_len, uint64_t *recv_len);

#endif /* BABELTRACE_PLUGINS_CTF_LTTNG_LIVE_VIEWER_CONNECTION_HPP */
