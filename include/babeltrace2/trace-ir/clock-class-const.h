#ifndef BABELTRACE_TRACE_IR_CLOCK_CLASS_CONST_H
#define BABELTRACE_TRACE_IR_CLOCK_CLASS_CONST_H

/*
 * Copyright 2017-2018 Philippe Proulx <pproulx@efficios.com>
 * Copyright 2013, 2014 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * The Common Trace Format (CTF) Specification is available at
 * http://www.efficios.com/ctf
 */

#include <stdint.h>

/* For bt_bool, bt_uuid, bt_clock_class */
#include <babeltrace2/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum bt_clock_class_status {
	BT_CLOCK_CLASS_STATUS_OK = 0,
	BT_CLOCK_CLASS_STATUS_NOMEM = -12,
	BT_CLOCK_CLASS_STATUS_OVERFLOW = -75,
} bt_clock_class_status;

extern const char *bt_clock_class_get_name(
		const bt_clock_class *clock_class);

extern const char *bt_clock_class_get_description(
		const bt_clock_class *clock_class);

extern uint64_t bt_clock_class_get_frequency(
		const bt_clock_class *clock_class);

extern uint64_t bt_clock_class_get_precision(
		const bt_clock_class *clock_class);

extern void bt_clock_class_get_offset(const bt_clock_class *clock_class,
		int64_t *seconds, uint64_t *cycles);

extern bt_bool bt_clock_class_origin_is_unix_epoch(
		const bt_clock_class *clock_class);

extern bt_uuid bt_clock_class_get_uuid(
		const bt_clock_class *clock_class);

extern bt_clock_class_status bt_clock_class_cycles_to_ns_from_origin(
		const bt_clock_class *clock_class,
		uint64_t cycles, int64_t *ns_from_origin);

extern void bt_clock_class_get_ref(const bt_clock_class *clock_class);

extern void bt_clock_class_put_ref(const bt_clock_class *clock_class);

#define BT_CLOCK_CLASS_PUT_REF_AND_RESET(_var)		\
	do {						\
		bt_clock_class_put_ref(_var);		\
		(_var) = NULL;				\
	} while (0)

#define BT_CLOCK_CLASS_MOVE_REF(_var_dst, _var_src)	\
	do {						\
		bt_clock_class_put_ref(_var_dst);	\
		(_var_dst) = (_var_src);		\
		(_var_src) = NULL;			\
	} while (0)

#ifdef __cplusplus
}
#endif

#endif /* BABELTRACE_TRACE_IR_CLOCK_CLASS_CONST_H */
