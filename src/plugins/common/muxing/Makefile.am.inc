# SPDX-License-Identifier: MIT

noinst_LTLIBRARIES += \
	libplugins-common-muxing.la

libplugins_common_muxing_la_SOURCES = \
	%reldir%/muxing.c \
	%reldir%/muxing.h
