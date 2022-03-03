# SPDX-License-Identifier: MIT

AUTOMAKE_OPTIONS = subdir-objects

## Common plugins internal libs ##

noinst_LTLIBRARIES = \
	libplugins-common-muxing.la \
	libplugins-common-param-validation.la

libplugins_common_muxing_la_SOURCES = \
	common/muxing/muxing.c \
	common/muxing/muxing.h

libplugins_common_param_validation_la_SOURCES = \
	common/param-validation/param-validation.c \
	common/param-validation/param-validation.h


## Plugins ##

plugindir = "$(BABELTRACE_PLUGINS_DIR)"
plugin_LTLIBRARIES =

### CTF plugin ###

plugin_LTLIBRARIES += babeltrace-plugin-ctf.la

babeltrace_plugin_ctf_la_SOURCES = \
	ctf/plugin.cpp

babeltrace_plugin_ctf_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(LT_NO_UNDEFINED) \
	-avoid-version -module $(LD_NOTEXT)

babeltrace_plugin_ctf_la_LIBADD = \
	libplugin-ctf-common.la \
	libplugin-ctf-fs-sink.la \
	libplugin-ctf-fs-src.la \
	libplugin-ctf-lttng-live.la \
	libplugins-common-param-validation.la

if !ENABLE_BUILT_IN_PLUGINS
babeltrace_plugin_ctf_la_LIBADD += \
	$(top_builddir)/src/lib/libbabeltrace2.la \
	$(top_builddir)/src/liblogging.la \
	$(top_builddir)/src/libcommon.la \
	$(top_builddir)/src/libctfser.la
endif

noinst_LTLIBRARIES += \
	libplugin-ctf-common.la \
	libplugin-ctf-common-metadata-parser.la \
	libplugin-ctf-common-metadata-ast.la \
	libplugin-ctf-fs-sink.la \
	libplugin-ctf-fs-src.la \
	libplugin-ctf-lttng-live.la

#AM_CPPFLAGS += -I$(builddir) -I$(srcdir)
AM_YFLAGS = -t -d -v -Wno-yacc

BUILT_SOURCES = ctf/common/metadata/parser.hpp

libplugin_ctf_common_metadata_parser_la_SOURCES = \
	ctf/common/metadata/lexer.lpp \
	ctf/common/metadata/parser.ypp \
	ctf/common/metadata/objstack.cpp

# scanner-symbols.h is included to prefix generated yy_* symbols
# with bt_.
libplugin_ctf_common_metadata_parser_la_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-include ctf/common/metadata/scanner-symbols.hpp

# This library contains (mostly) generated code, silence some warnings that it
# produces.
libplugin_ctf_common_metadata_parser_la_CXXFLAGS = \
	$(AM_CXXFLAGS) \
	-Wno-unused-function \
	-Wno-null-dereference

libplugin_ctf_common_metadata_ast_la_SOURCES = \
	ctf/common/metadata/visitor-generate-ir.cpp \
	ctf/common/metadata/visitor-semantic-validator.cpp \
	ctf/common/metadata/visitor-parent-links.cpp \
	ctf/common/metadata/ast.hpp \
	ctf/common/metadata/objstack.hpp \
	ctf/common/metadata/parser.hpp \
	ctf/common/metadata/parser-wrap.hpp \
	ctf/common/metadata/scanner.hpp \
	ctf/common/metadata/scanner-symbols.hpp \
	ctf/common/metadata/decoder.cpp \
	ctf/common/metadata/decoder.hpp \
	ctf/common/metadata/decoder-packetized-file-stream-to-buf.cpp \
	ctf/common/metadata/decoder-packetized-file-stream-to-buf.hpp \
	ctf/common/metadata/logging.cpp \
	ctf/common/metadata/logging.hpp \
	ctf/common/metadata/ctf-meta.hpp \
	ctf/common/metadata/ctf-meta-visitors.hpp \
	ctf/common/metadata/ctf-meta-validate.cpp \
	ctf/common/metadata/ctf-meta-update-meanings.cpp \
	ctf/common/metadata/ctf-meta-update-in-ir.cpp \
	ctf/common/metadata/ctf-meta-update-default-clock-classes.cpp \
	ctf/common/metadata/ctf-meta-update-text-array-sequence.cpp \
	ctf/common/metadata/ctf-meta-update-alignments.cpp \
	ctf/common/metadata/ctf-meta-update-value-storing-indexes.cpp \
	ctf/common/metadata/ctf-meta-update-stream-class-config.cpp \
	ctf/common/metadata/ctf-meta-warn-meaningless-header-fields.cpp \
	ctf/common/metadata/ctf-meta-translate.cpp \
	ctf/common/metadata/ctf-meta-resolve.cpp \
	ctf/common/metadata/ctf-meta-configure-ir-trace.cpp \
	ctf/common/metadata/ctf-meta-configure-ir-trace.hpp

if BABELTRACE_BUILD_WITH_MINGW
libplugin_ctf_common_metadata_ast_la_LIBADD = -lintl -liconv -lole32
endif

# start with empty files to clean
CLEANFILES =

if HAVE_BISON
# we have bison: we can clean the generated parser files
CLEANFILES += \
	ctf/common/metadata/parser.cpp \
	ctf/common/metadata/parser.hpp \
	ctf/common/metadata/parser.output
else # HAVE_BISON
# create target used to stop the build if we want to build the parser,
# but we don't have the necessary tool to do so
ERR_MSG = "Error: Cannot build target because bison is missing."
ERR_MSG += "Make sure bison is installed and run the configure script again."

ctf/common/metadata/parser.cpp ctf/common/metadata/parser.hpp: ctf/common/metadata/parser.ypp
	@echo $(ERR_MSG)
	@false

BUILT_SOURCES += ctf/common/metadata/parser.cpp ctf/common/metadata/parser.hpp
endif # HAVE_BISON

if HAVE_FLEX
# we have flex: we can clean the generated lexer files
CLEANFILES += ctf/common/metadata/lexer.cpp
else # HAVE_FLEX
# create target used to stop the build if we want to build the lexer,
# but we don't have the necessary tool to do so
ERR_MSG = "Error: Cannot build target because flex is missing."
ERR_MSG += "Make sure flex is installed and run the configure script again."

ctf/common/metadata/filter-lexer.cpp: ctf/common/metadata/lexer.lpp
	@echo $(ERR_MSG)
	@false

BUILT_SOURCES += ctf/common/metadata/lexer.cpp
endif # HAVE_FLEX

libplugin_ctf_common_la_SOURCES = \
	ctf/common/print.hpp \
	ctf/common/bfcr/bfcr.cpp \
	ctf/common/bfcr/bfcr.hpp \
	ctf/common/msg-iter/msg-iter.cpp \
	ctf/common/msg-iter/msg-iter.hpp

libplugin_ctf_common_la_LIBADD = \
	libplugin-ctf-common-metadata-parser.la \
	libplugin-ctf-common-metadata-ast.la

libplugin_ctf_fs_sink_la_SOURCES = \
	ctf/fs-sink/fs-sink.cpp \
	ctf/fs-sink/fs-sink.hpp \
	ctf/fs-sink/fs-sink-ctf-meta.hpp \
	ctf/fs-sink/translate-trace-ir-to-ctf-ir.cpp \
	ctf/fs-sink/translate-trace-ir-to-ctf-ir.hpp \
	ctf/fs-sink/translate-ctf-ir-to-tsdl.cpp \
	ctf/fs-sink/translate-ctf-ir-to-tsdl.hpp \
	ctf/fs-sink/fs-sink-stream.cpp \
	ctf/fs-sink/fs-sink-stream.hpp \
	ctf/fs-sink/fs-sink-trace.cpp \
	ctf/fs-sink/fs-sink-trace.hpp

libplugin_ctf_fs_src_la_SOURCES = \
	ctf/fs-src/data-stream-file.cpp \
	ctf/fs-src/data-stream-file.hpp \
	ctf/fs-src/file.cpp \
	ctf/fs-src/file.hpp \
	ctf/fs-src/fs.cpp \
	ctf/fs-src/fs.hpp \
	ctf/fs-src/lttng-index.hpp \
	ctf/fs-src/metadata.cpp \
	ctf/fs-src/metadata.hpp \
	ctf/fs-src/query.hpp \
	ctf/fs-src/query.cpp

libplugin_ctf_lttng_live_la_SOURCES = \
	ctf/lttng-live/lttng-live.cpp \
	ctf/lttng-live/lttng-live.hpp \
	ctf/lttng-live/data-stream.cpp \
	ctf/lttng-live/data-stream.hpp \
	ctf/lttng-live/metadata.cpp \
	ctf/lttng-live/metadata.hpp \
	ctf/lttng-live/viewer-connection.cpp \
	ctf/lttng-live/viewer-connection.hpp \
	ctf/lttng-live/lttng-viewer-abi.hpp

libplugin_ctf_lttng_live_la_LIBADD =

if !ENABLE_BUILT_IN_PLUGINS
libplugin_ctf_lttng_live_la_LIBADD += \
	libplugins-common-muxing.la
endif

if BABELTRACE_BUILD_WITH_MINGW
libplugin_ctf_lttng_live_la_LIBADD += -lws2_32
endif


### LTTng-Utils plugin ###

plugin_LTLIBRARIES += babeltrace-plugin-lttng-utils.la

babeltrace_plugin_lttng_utils_la_SOURCES = \
	lttng-utils/plugin.c

babeltrace_plugin_lttng_utils_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(LT_NO_UNDEFINED) \
	-avoid-version -module $(LD_NOTEXT) \
	$(ELFUTILS_LIBS)

babeltrace_plugin_lttng_utils_la_LIBADD =

if ENABLE_DEBUG_INFO
babeltrace_plugin_lttng_utils_la_LIBADD += \
	libplugin-lttng-utils-debug-info.la
endif

if !ENABLE_BUILT_IN_PLUGINS
babeltrace_plugin_lttng_utils_la_LIBADD += \
	$(top_builddir)/src/lib/libbabeltrace2.la \
	$(top_builddir)/src/libcommon.la \
	$(top_builddir)/src/liblogging.la \
	libplugins-common-param-validation.la
endif

noinst_LTLIBRARIES += \
	libplugin-lttng-utils-debug-info.la

libplugin_lttng_utils_debug_info_la_LIBADD = \
	$(top_builddir)/src/libfd-cache.la

libplugin_lttng_utils_debug_info_la_SOURCES = \
	lttng-utils/debug-info/bin-info.c \
	lttng-utils/debug-info/bin-info.h \
	lttng-utils/debug-info/crc32.c \
	lttng-utils/debug-info/crc32.h \
	lttng-utils/debug-info/debug-info.c \
	lttng-utils/debug-info/debug-info.h \
	lttng-utils/debug-info/dwarf.c \
	lttng-utils/debug-info/dwarf.h \
	lttng-utils/debug-info/trace-ir-data-copy.c \
	lttng-utils/debug-info/trace-ir-data-copy.h \
	lttng-utils/debug-info/trace-ir-mapping.c \
	lttng-utils/debug-info/trace-ir-mapping.h \
	lttng-utils/debug-info/trace-ir-metadata-copy.c \
	lttng-utils/debug-info/trace-ir-metadata-copy.h \
	lttng-utils/debug-info/trace-ir-metadata-field-class-copy.c \
	lttng-utils/debug-info/trace-ir-metadata-field-class-copy.h \
	lttng-utils/debug-info/utils.c \
	lttng-utils/debug-info/utils.h


### Text plugin ###

plugin_LTLIBRARIES += babeltrace-plugin-text.la

babeltrace_plugin_text_la_SOURCES = \
	text/plugin.c

babeltrace_plugin_text_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(LT_NO_UNDEFINED) \
	-avoid-version -module $(LD_NOTEXT)

babeltrace_plugin_text_la_LIBADD = \
	libplugin-text-pretty-cc.la \
	libplugin-text-dmesg-cc.la \
	libplugin-text-details-cc.la

if !ENABLE_BUILT_IN_PLUGINS
babeltrace_plugin_text_la_LIBADD += \
	$(top_builddir)/src/lib/libbabeltrace2.la \
	$(top_builddir)/src/libcommon.la \
	$(top_builddir)/src/liblogging.la \
	$(top_builddir)/src/libcompat.la \
	libplugins-common-param-validation.la
endif

noinst_LTLIBRARIES += \
	libplugin-text-details-cc.la \
	libplugin-text-dmesg-cc.la \
	libplugin-text-pretty-cc.la

libplugin_text_details_cc_la_SOURCES = \
	text/details/colors.h \
	text/details/details.c \
	text/details/details.h \
	text/details/obj-lifetime-mgmt.c \
	text/details/obj-lifetime-mgmt.h \
	text/details/write.c \
	text/details/write.h

libplugin_text_dmesg_cc_la_SOURCES = \
	text/dmesg/dmesg.c \
	text/dmesg/dmesg.h

libplugin_text_pretty_cc_la_SOURCES = \
	text/pretty/pretty.c \
	text/pretty/pretty.h \
	text/pretty/print.c


### Utils plugin ###

plugin_LTLIBRARIES += babeltrace-plugin-utils.la

babeltrace_plugin_utils_la_SOURCES = \
	utils/plugin.c

babeltrace_plugin_utils_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(LT_NO_UNDEFINED) \
	-avoid-version -module $(LD_NOTEXT)

babeltrace_plugin_utils_la_LIBADD = \
	libplugin-utils-counter-cc.la \
	libplugin-utils-dummy-cc.la \
	libplugin-utils-muxer.la \
	libplugin-utils-trimmer.la

if !ENABLE_BUILT_IN_PLUGINS
babeltrace_plugin_utils_la_LIBADD += \
	$(top_builddir)/src/lib/libbabeltrace2.la \
	$(top_builddir)/src/libcommon.la \
	$(top_builddir)/src/liblogging.la \
	libplugins-common-param-validation.la
endif

noinst_LTLIBRARIES += \
	libplugin-utils-counter-cc.la \
	libplugin-utils-dummy-cc.la \
	libplugin-utils-muxer.la \
	libplugin-utils-trimmer.la

libplugin_utils_counter_cc_la_SOURCES = \
	utils/counter/counter.c \
	utils/counter/counter.h

libplugin_utils_dummy_cc_la_SOURCES = \
	utils/dummy/dummy.c \
	utils/dummy/dummy.h

libplugin_utils_muxer_la_SOURCES = \
	utils/muxer/muxer.c \
	utils/muxer/muxer.h

libplugin_utils_muxer_la_LIBADD = \
	libplugins-common-muxing.la

libplugin_utils_trimmer_la_SOURCES = \
	utils/trimmer/trimmer.c \
	utils/trimmer/trimmer.h


if ENABLE_DEBUG_INFO
SUBDIRS =
endif
