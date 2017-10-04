ACLOCAL_AMFLAGS = -I m4

SUBDIRS = include		\
	common			\
	compat			\
	logging

# If the plugin provider is to be built in the library,
# build it first and don't link it on the lib.
# Otherwise, build the lib first, then the provider and link
# it on the lib.
if ENABLE_BUILT_IN_PYTHON_PLUGIN_PROVIDER
SUBDIRS += python-plugin-provider \
	lib
else
SUBDIRS += lib			\
	python-plugin-provider
endif

SUBDIRS +=			\
	plugins			\
	cli			\
	bindings		\
	tests			\
	doc			\
	extras

dist_doc_DATA = ChangeLog LICENSE mit-license.txt gpl-2.0.txt \
		std-ext-lib.txt README CONTRIBUTING.adoc

dist_noinst_DATA = CodingStyle

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = babeltrace.pc babeltrace-ctf.pc

CONTRIBUTING.html: $(srcdir)/CONTRIBUTING.adoc
	asciidoc --verbose -a source-highlighter=pygments $<

CLEANFILES = CONTRIBUTING.html
