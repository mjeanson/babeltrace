AM_CPPFLAGS += $(PYTHON_INCLUDE)

providerdir = "$(BABELTRACE_PROVIDERSDIR)"

provider_LTLIBRARIES = babeltrace-python-plugin-provider.la

babeltrace_python_plugin_provider_la_SOURCES = \
	python-plugin-provider.c logging.c logging.h
babeltrace_python_plugin_provider_la_LDFLAGS = \
	$(LT_NO_UNDEFINED) \
	-avoid-version -module \
	$(PYTHON_LIBS)

babeltrace_python_plugin_provider_la_LIBADD =

if !ENABLE_BUILT_IN_PLUGINS
babeltrace_python_plugin_provider_la_LIBADD += \
	$(top_builddir)/logging/libbabeltrace-logging.la \
	$(top_builddir)/common/libbabeltrace-common.la \
	$(top_builddir)/lib/libbabeltrace.la
endif
