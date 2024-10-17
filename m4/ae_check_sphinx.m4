# SPDX-FileCopyrightText: 2015 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: FSFULLR
#
# ae_check_sphinx.m4 -- check for Sphinx Python package
#
# Sphinx ships with a script named "sphinx-build", which is usually
# installed in "/usr/bin". Unfortunately, this script uses
# "/usr/bin/python" as its interpreter. Since "/usr/bin/python" can
# be either Python 2 or Python 3, depending on the distribution, and
# since we absolutely need the Python 3 Sphinx package for Babeltrace
# because it needs to import our bindings for autodocumentation,
# there's no way to tell if "sphinx-build" is actually using Python 2
# or Python 3.
#
# This macro checks if the Sphinx package ("sphinx") is installed
# and visible from the interpreter designated by the PYTHON variable.
# It sets PYTHON_SPHINX_EXISTS to "yes" if Sphinx is found for the
# given Python interpreter, otherwise "no".

# AE_CHECK_PYTHON_SPHINX(PYTHON)
# ---------------------------------------------------------------------------
AC_DEFUN([AE_CHECK_PYTHON_SPHINX],
    [prog="
try:
    import sphinx
    print('yes')
except ImportError:
    print('no')"
    PYTHON_SPHINX_EXISTS=`${$1} -c "$prog"`])
