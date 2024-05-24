/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef BABELTRACE_COMMON_MACROS_H
#define BABELTRACE_COMMON_MACROS_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
#define BT_EXTERN_C extern "C"
#else
#define BT_EXTERN_C
#endif

#define bt_max_t(type, a, b)	\
	((type) (a) > (type) (b) ? (type) (a) : (type) (b))

/*
 * BT_EXPORT: set the visibility for exported functions.
 */
#if defined(_WIN32) || defined(__CYGWIN__)
#define BT_EXPORT
#else
#define BT_EXPORT __attribute__((visibility("default")))
#endif

/*
 * BT_NOEXCEPT: defined to `noexcept` if compiling as C++, else empty.
 */
#if defined(__cplusplus)
#define BT_NOEXCEPT noexcept
#else
#define BT_NOEXCEPT
#endif

/* Enable `txt` if developer mode is enabled. */
#ifdef BT_DEV_MODE
#define BT_IF_DEV_MODE(txt) txt
#else
#define BT_IF_DEV_MODE(txt)
#endif

/* Wrapper for g_array_index that adds bound checking.  */
#define bt_g_array_index(a, t, i)		\
	g_array_index((a), t, ({ BT_ASSERT_DBG((i) < (a)->len); (i); }))

/*
 * Copied from:
 * <https://stackoverflow.com/questions/37411809/how-to-elegantly-fix-this-unused-variable-warning/37412551#37412551>:
 *
 * * sizeof() ensures that the expression is not evaluated at all, so
 *   its side-effects don't happen. That is to be consistent with the
 *   usual behaviour of debug-only constructs, such as assert().
 *
 * * `((_expr), 0)` uses the comma operator to swallow the actual type
 *   of `(_expr)`. This is to prevent VLAs from triggering evaluation.
 *
 * * `(void)` explicitly ignores the result of `(_expr)` and sizeof() so
 *   no "unused value" warning appears.
 */

#define BT_USE_EXPR(_expr)		((void) sizeof((void) (_expr), 0))
#define BT_USE_EXPR2(_expr1, _expr2)					\
	((void) sizeof((void) (_expr1), (void) (_expr2), 0))
#define BT_USE_EXPR3(_expr1, _expr2, _expr3)				\
	((void) sizeof((void) (_expr1), (void) (_expr2), (void) (_expr3), 0))
#define BT_USE_EXPR4(_expr1, _expr2, _expr3, _expr4)			\
	((void) sizeof((void) (_expr1), (void) (_expr2),		\
		(void) (_expr3), (void) (_expr4), 0))
#define BT_USE_EXPR5(_expr1, _expr2, _expr3, _expr4, _expr5)		\
	((void) sizeof((void) (_expr1), (void) (_expr2),		\
		(void) (_expr3), (void) (_expr4), (void) (_expr5), 0))

#define BT_DIAG_PUSH _Pragma ("GCC diagnostic push")
#define BT_DIAG_POP _Pragma ("GCC diagnostic push")

#define BT_DIAG_IGNORE_SHADOW _Pragma("GCC diagnostic ignored \"-Wshadow\"")
#define BT_DIAG_IGNORE_NULL_DEREFERENCE _Pragma("GCC diagnostic ignored \"-Wnull-dereference\"")

#if defined __clang__
#  if __has_warning("-Wunused-but-set-variable")
#    define BT_DIAG_IGNORE_UNUSED_BUT_SET_VARIABLE \
	_Pragma("GCC diagnostic ignored \"-Wunused-but-set-variable\"")
#  endif
#endif

#if !defined BT_DIAG_IGNORE_UNUSED_BUT_SET_VARIABLE
#  define BT_DIAG_IGNORE_UNUSED_BUT_SET_VARIABLE
#endif

#ifdef __cplusplus
}
#endif

#endif /* BABELTRACE_COMMON_MACROS_H */
