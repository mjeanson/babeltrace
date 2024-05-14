/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2016 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef BABELTRACE_PLUGINS_CTF_LTTNG_LIVE_METADATA_HPP
#define BABELTRACE_PLUGINS_CTF_LTTNG_LIVE_METADATA_HPP

#include <stdint.h>

#include "lttng-live.hpp"

int lttng_live_metadata_create_stream(struct lttng_live_session *session, uint64_t ctf_trace_id,
                                      uint64_t stream_id);

enum lttng_live_iterator_status lttng_live_metadata_update(struct lttng_live_trace *trace);

#endif /* BABELTRACE_PLUGINS_CTF_LTTNG_LIVE_METADATA_HPP */
