# SPDX-License-Identifier: FSFAP
#
# ===========================================================================
#   https://www.gnu.org/software/autoconf-archive/ax_prog_flex_version.html
# ===========================================================================
#
# SYNOPSIS
#
#   AX_PROG_FLEX_VERSION([VERSION],[ACTION-IF-TRUE],[ACTION-IF-FALSE])
#
# DESCRIPTION
#
#   Makes sure that flex version is greater or equal to the version
#   indicated. If true the shell commands in ACTION-IF-TRUE are executed. If
#   not the shell commands in commands in ACTION-IF-TRUE are executed. If
#   not the shell commands in ACTION-IF-FALSE are run. Note if $LEX is not
#   set (for example by running AC_PROG_LEX or AC_PATH_PROG) the macro
#   will fail.
#
#   Example:
#
#     AC_PROG_LEX
#     AX_PROG_FLEX_VERSION([2.5.39],[ ... ],[ ... ])
#
#   This will check to make sure that the flex you have is at least version
#   2.5.39 or greater.
#
#   NOTE: This macro uses the $LEX variable to perform the check, if it's
#   empty it will failover to the $FLEX variable for backwards compatibility.
#
# LICENSE
#
#   Copyright (c) 2015 Jonathan Rajotte-Julien <jonathan.rajotte-julien@efficios.com>
#                 2017 Michael Jeanson <mjeanson@efficios.com>
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

#serial 3

AC_DEFUN([AX_PROG_FLEX_VERSION],[
    AC_REQUIRE([AC_PROG_SED])
    AC_REQUIRE([AC_PROG_GREP])

    AS_IF([test -z "$LEX"],[
        AS_IF([test -n "$FLEX"],[
            LEX=$FLEX
        ])
    ])

    AS_IF([test -n "$LEX"],[
        ax_flex_version="$1"

        AC_MSG_CHECKING([for flex version])
        changequote(<<,>>)
        flex_version=`$LEX --version 2>&1 \
          | $SED -n -e '/flex /b inspect
b
: inspect
s/.* (\{0,1\}\([0-9]*\.[0-9]*\.[0-9]*\))\{0,1\}.*/\1/;p'`
        changequote([,])
        AC_MSG_RESULT($flex_version)

	AC_SUBST([FLEX_VERSION],[$flex_version])

        AX_COMPARE_VERSION([$flex_version],[ge],[$ax_flex_version],[
	    :
            $2
        ],[
	    :
            $3
        ])
    ],[
        AC_MSG_WARN([could not find flex])
        $3
    ])
])
