/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2013 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Common Trace Format Object Stack.
 */

#ifndef _OBJSTACK_H
#define _OBJSTACK_H

#include <cstddef>

namespace bt2c {

class Logger;

} /* namespace bt2c */

struct objstack *objstack_create(const bt2c::Logger& parentLogger);
void objstack_destroy(struct objstack *objstack);

/*
 * Allocate len bytes of zeroed memory.
 * Return NULL on error.
 */
void *objstack_alloc(struct objstack *objstack, size_t len);

#endif /* _OBJSTACK_H */
