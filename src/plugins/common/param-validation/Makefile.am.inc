# SPDX-License-Identifier: MIT

noinst_LTLIBRARIES += \
	libplugins-common-param-validation.la

libplugins_common_param_validation_la_SOURCES = \
	%reldir%/param-validation.c \
	%reldir%/param-validation.h
