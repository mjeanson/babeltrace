/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2012 (c) Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * endian.h compatibility layer.
 */

#ifndef BABELTRACE_COMPAT_ENDIAN_H
#define BABELTRACE_COMPAT_ENDIAN_H

#ifdef __FreeBSD__
#include <sys/endian.h>

#elif defined(__sun__)
#include <sys/byteorder.h>

#ifndef __BIG_ENDIAN
#define __BIG_ENDIAN 4321
#endif
#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN 1234
#endif

#ifdef _LITTLE_ENDIAN
#define __BYTE_ORDER __LITTLE_ENDIAN
#endif

#ifdef _BIG_ENDIAN
#define __BYTE_ORDER __BIG_ENDIAN
#endif

#define LITTLE_ENDIAN  __LITTLE_ENDIAN
#define BIG_ENDIAN     __BIG_ENDIAN
#define BYTE_ORDER     __BYTE_ORDER

#define betoh16(x) BE_16(x)
#define letoh16(x) LE_16(x)
#define betoh32(x) BE_32(x)
#define letoh32(x) LE_32(x)
#define betoh64(x) BE_64(x)
#define letoh64(x) LE_64(x)
#define htobe16(x) BE_16(x)
#define be16toh(x) BE_16(x)
#define htobe32(x) BE_32(x)
#define be32toh(x) BE_32(x)
#define htobe64(x) BE_64(x)
#define be64toh(x) BE_64(x)

#elif defined(__MINGW32__)
#include <stdint.h>
#include <stdlib.h>

#ifndef __BIG_ENDIAN
#define __BIG_ENDIAN 4321
#endif
#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN 1234
#endif

#ifndef __BYTE_ORDER
#define __BYTE_ORDER __LITTLE_ENDIAN
#endif

#define LITTLE_ENDIAN  __LITTLE_ENDIAN
#define BIG_ENDIAN     __BIG_ENDIAN
#define PDP_ENDIAN     __PDP_ENDIAN
#define BYTE_ORDER     __BYTE_ORDER

#define htobe16(x) (uint16_t) _byteswap_ushort(x)
#define htole16(x) (x)
#define be16toh(x) (uint16_t) _byteswap_ushort(x)
#define le16toh(x) (x)

#define htobe32(x) (uint32_t) _byteswap_ulong(x)
#define htole32(x) (x)
#define be32toh(x) (uint32_t) _byteswap_ulong(x)
#define le32toh(x) (x)

#define htobe64(x) (uint64_t) _byteswap_uint64(x)
#define htole64(x) (x)
#define be64toh(x) (uint64_t) _byteswap_uint64(x)
#define le64toh(x) (x)

#elif defined(__APPLE__)
# include <machine/endian.h>
# include <libkern/OSByteOrder.h>

# if BYTE_ORDER == LITTLE_ENDIAN
#  define htobe16(x) OSSwapConstInt16(x)
#  define htole16(x) (x)
#  define be16toh(x) OSSwapConstInt16(x)
#  define le16toh(x) (x)

#  define htobe32(x) OSSwapConstInt32(x)
#  define htole32(x) (x)
#  define be32toh(x) OSSwapConstInt32(x)
#  define le32toh(x) (x)

#  define htobe64(x) OSSwapConstInt64(x)
#  define htole64(x) (x)
#  define be64toh(x) OSSwapConstInt64(x)
#  define le64toh(x) (x)

# else /* BYTE_ORDER == LITTLE_ENDIAN */
#  define htobe16(x) (x)
#  define htole16(x) OSSwapConstInt16(x)
#  define be16toh(x) (x)
#  define le16toh(x) OSSwapConstInt16(x)

#  define htobe32(x) (x)
#  define htole32(x) OSSwapConstInt32(x)
#  define be32toh(x) (x)
#  define le32toh(x) OSSwapConstInt32(x)

#  define htobe64(x) (x)
#  define htole64(x) OSSwapConstInt64(x)
#  define be64toh(x) (x)
#  define le64toh(x) OSSwapConstInt64(x)
#  endif

#else
#include <endian.h>

/*
 * htobe/betoh are not defined for glibc < 2.9, so add them explicitly
 * if they are missing.
 */
# ifdef __USE_BSD
/* Conversion interfaces. */
#  include <byteswap.h>

#  if __BYTE_ORDER == __LITTLE_ENDIAN
#   ifndef htobe16
#    define htobe16(x) __bswap_16(x)
#   endif
#   ifndef htole16
#    define htole16(x) (x)
#   endif
#   ifndef be16toh
#    define be16toh(x) __bswap_16(x)
#   endif
#   ifndef le16toh
#    define le16toh(x) (x)
#   endif

#   ifndef htobe32
#    define htobe32(x) __bswap_32(x)
#   endif
#   ifndef htole32
#    define htole32(x) (x)
#   endif
#   ifndef be32toh
#    define be32toh(x) __bswap_32(x)
#   endif
#   ifndef le32toh
#    define le32toh(x) (x)
#   endif

#   ifndef htobe64
#    define htobe64(x) __bswap_64(x)
#   endif
#   ifndef htole64
#    define htole64(x) (x)
#   endif
#   ifndef be64toh
#    define be64toh(x) __bswap_64(x)
#   endif
#   ifndef le64toh
#    define le64toh(x) (x)
#   endif

#  else /* __BYTE_ORDER == __LITTLE_ENDIAN */
#   ifndef htobe16
#    define htobe16(x) (x)
#   endif
#   ifndef htole16
#    define htole16(x) __bswap_16(x)
#   endif
#   ifndef be16toh
#    define be16toh(x) (x)
#   endif
#   ifndef le16toh
#    define le16toh(x) __bswap_16(x)
#   endif

#   ifndef htobe32
#    define htobe32(x) (x)
#   endif
#   ifndef htole32
#    define htole32(x) __bswap_32(x)
#   endif
#   ifndef be32toh
#    define be32toh(x) (x)
#   endif
#   ifndef le32toh
#    define le32toh(x) __bswap_32(x)
#   endif

#   ifndef htobe64
#    define htobe64(x) (x)
#   endif
#   ifndef htole64
#    define htole64(x) __bswap_64(x)
#   endif
#   ifndef be64toh
#    define be64toh(x) (x)
#   endif
#   ifndef le64toh
#    define le64toh(x) __bswap_64(x)
#   endif

#  endif /* __BYTE_ORDER == __LITTLE_ENDIAN */
# endif /* __USE_BSD */
#endif /* else -- __FreeBSD__ */

#ifndef FLOAT_WORD_ORDER
#ifdef __FLOAT_WORD_ORDER
#define FLOAT_WORD_ORDER	__FLOAT_WORD_ORDER
#else /* __FLOAT_WORD_ORDER */
#define FLOAT_WORD_ORDER	BYTE_ORDER
#endif /* __FLOAT_WORD_ORDER */
#endif /* FLOAT_WORD_ORDER */

#endif /* BABELTRACE_COMPAT_ENDIAN_H */
