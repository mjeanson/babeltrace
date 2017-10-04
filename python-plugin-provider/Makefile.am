if ENABLE_PYTHON_PLUGIN_PROVIDER
AM_CPPFLAGS += $(PYTHON_INCLUDE)

sources = python-plugin-provider.c logging.c logging.h

if ENABLE_BUILT_IN_PYTHON_PLUGIN_PROVIDER
# When the plugin provider is to be built in the library, create
# a simple convience library that will be statically linked in.

noinst_LTLIBRARIES = libbabeltrace-python-plugin-provider.la

# Plug-in system library
libbabeltrace_python_plugin_provider_la_SOURCES = \
	$(sources)

libbabeltrace_python_plugin_provider_la_LDFLAGS = \
	$(PYTHON_LIBS)
else
# When the plugin provider is to be built as an external plugin,
# create an unversionned module that will always have the same
# file name.

providerdir = "$(BABELTRACE_PROVIDERSDIR)"

provider_LTLIBRARIES = babeltrace-python-plugin-provider.la

babeltrace_python_plugin_provider_la_SOURCES = \
	$(sources)
babeltrace_python_plugin_provider_la_LDFLAGS = \
	$(LT_NO_UNDEFINED) \
	-avoid-version -module \
	$(PYTHON_LIBS)

babeltrace_python_plugin_provider_la_LIBADD = \
	$(top_builddir)/logging/libbabeltrace-logging.la \
	$(top_builddir)/common/libbabeltrace-common.la \
	$(top_builddir)/lib/libbabeltrace.la
endif
endif
