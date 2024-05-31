/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2017 Philippe Proulx <pproulx@efficios.com>
 */

#include <string>

#include <glib.h>

#include <babeltrace2/babeltrace.h>

#include "common/assert.h"
#include "cpp-common/bt2/graph.hpp"
#include "cpp-common/bt2/plugin-load.hpp"
#include "cpp-common/bt2/query-executor.hpp"
#include "cpp-common/bt2/value.hpp"
#include "cpp-common/bt2c/call.hpp"
#include "cpp-common/bt2c/fmt.hpp" /* IWYU pragma: keep */
#include "cpp-common/vendor/fmt/core.h"

#include "tap/tap.h"

#define NR_TESTS          36
#define NON_EXISTING_PATH "/this/hopefully/does/not/exist/5bc75f8d-0dba-4043-a509-d7984b97e42b.so"

namespace {

/* Those symbols are written to by some test plugins */
int getIntEnvVar(const char *name)
{
    const char *val = getenv(name);

    if (!val) {
        return -1;
    }

    return atoi(val);
}

void resetTestPluginEnvVars()
{
    g_setenv("BT_TEST_PLUGIN_INITIALIZE_CALLED", "0", 1);
    g_setenv("BT_TEST_PLUGIN_FINALIZE_CALLED", "0", 1);
}

std::string getTestPluginPath(const char *plugin_dir, const char *plugin_name)
{
    return fmt::format("{}" G_DIR_SEPARATOR_S "plugin-{}." G_MODULE_SUFFIX, plugin_dir,
                       plugin_name);
}

void testMinimal(const char *pluginDir)
{
    diag("minimal plugin test below");
    resetTestPluginEnvVars();

    const auto minimalPath = getTestPluginPath(pluginDir, "minimal");

    {
        const auto plugins = bt2::findAllPluginsFromFile(minimalPath, false);
        ok(plugins, "bt_plugin_find_all_from_file() returns a plugin set");
        ok(getIntEnvVar("BT_TEST_PLUGIN_INITIALIZE_CALLED") == 1,
           "plugin's initialization function is called during bt_plugin_find_all_from_file()");
        ok(plugins->length() == 1,
           "bt_plugin_find_all_from_file() returns the expected number of plugins");

        const auto plugin = (*plugins)[0];
        ok(plugin->name() == "test_minimal", "bt_plugin_get_name() returns the expected name");
        ok(plugin->description() == "Minimal Babeltrace plugin with no component classes",
           "bt_plugin_get_description() returns the expected description");
        ok(!plugin->version().has_value(), "bt_plugin_get_version() fails when there's no version");
        ok(plugin->author() == "Janine Sutto",
           "bt_plugin_get_author() returns the expected author");
        ok(plugin->license() == "Beerware", "bt_plugin_get_license() returns the expected license");
        ok(plugin->path() == minimalPath, "bt_plugin_get_path() returns the expected path");
        ok(plugin->sourceComponentClasses().length() == 0,
           "bt_plugin_get_source_component_class_count() returns the expected value");
        ok(plugin->filterComponentClasses().length() == 0,
           "bt_plugin_get_filter_component_class_count() returns the expected value");
        ok(plugin->sinkComponentClasses().length() == 0,
           "bt_plugin_get_sink_component_class_count() returns the expected value");
        ok(getIntEnvVar("BT_TEST_PLUGIN_FINALIZE_CALLED") == 0,
           "plugin's finalize function is not yet called");
    }

    ok(getIntEnvVar("BT_TEST_PLUGIN_FINALIZE_CALLED") == 1,
       "plugin's finalize function is called when the plugin is destroyed");
}

void testSfs(const char *plugin_dir)
{
    diag("sfs plugin test below");

    const auto sfsPath = getTestPluginPath(plugin_dir, "sfs");
    auto plugins = bt2::findAllPluginsFromFile(sfsPath, false);

    BT_ASSERT(plugins);
    BT_ASSERT(plugins->length() == 1);

    const auto plugin = (*plugins)[0];
    const auto version = plugin->version();

    ok(version.has_value(), "bt_plugin_get_version() succeeds when there's a version");
    ok(version->major() == 1, "bt_plugin_get_version() returns the expected major version");
    ok(version->minor() == 2, "bt_plugin_get_version() returns the expected minor version");
    ok(version->patch() == 3, "bt_plugin_get_version() returns the expected patch version");
    ok(version->extra() == "yes", "bt_plugin_get_version() returns the expected extra version");
    ok(plugin->sourceComponentClasses().length() == 1,
       "bt_plugin_get_source_component_class_count() returns the expected value");
    ok(plugin->filterComponentClasses().length() == 1,
       "bt_plugin_get_filter_component_class_count() returns the expected value");
    ok(plugin->sinkComponentClasses().length() == 1,
       "bt_plugin_get_sink_component_class_count() returns the expected value");

    const auto sourceCompCls = plugin->sourceComponentClasses()["source"];

    ok(sourceCompCls,
       "bt_plugin_borrow_source_component_class_by_name_const() finds a source component class");

    const auto sinkCompCls = plugin->sinkComponentClasses()["sink"];

    ok(sinkCompCls,
       "bt_plugin_borrow_sink_component_class_by_name_const() finds a sink component class");
    ok(sinkCompCls->help() ==
           "Bacon ipsum dolor amet strip steak cupim pastrami venison shoulder.\n"
           "Prosciutto beef ribs flank meatloaf pancetta brisket kielbasa drumstick\n"
           "venison tenderloin cow tail. Beef short loin shoulder meatball, sirloin\n"
           "ground round brisket salami cupim pork bresaola turkey bacon boudin.\n",
       "bt_component_class_get_help() returns the expected help text");

    const auto filterCompCls = plugin->filterComponentClasses()["filter"];

    ok(filterCompCls,
       "bt_plugin_borrow_filter_component_class_by_name_const() finds a filter component class");

    const auto params = bt2::createValue(INT64_C(23));
    const auto queryExec = bt2::QueryExecutor::create(*filterCompCls, "get-something", *params);

    BT_ASSERT(queryExec);

    const auto results = queryExec->query();

    ok(results, "bt_query_executor_query() succeeds");
    BT_ASSERT(results->isArray());
    BT_ASSERT(results->asArray().length() == 2);

    const auto resObject = results->asArray()[0].asString().value();
    const auto resParams = results->asArray()[1];

    ok(resObject == "get-something",
       "bt_component_class_query() receives the expected object name");
    ok(resParams == *params, "bt_component_class_query() receives the expected parameters");

    const auto sinkCompClsRef = sinkCompCls->shared();

    plugins.reset();

    const auto graph = bt2::Graph::create(0);

    BT_ASSERT(graph);

    const auto sinkComponent =
        graph->addComponent(*sinkCompCls, "the-sink", {}, bt2::LoggingLevel::None);
    ok(sinkComponent.name() == "the-sink",
       "bt_graph_add_sink_component() still works after the plugin object is destroyed");
}

void testCreateAllFromDir(const char *pluginDir)
{
    diag("create from all test below");

    const auto caughtError = bt2c::call([]() {
        try {
            bt2::findAllPluginsFromDir(NON_EXISTING_PATH, BT_FALSE, BT_FALSE);
            return false;
        } catch (const bt2::Error&) {
            bt_current_thread_clear_error();
            return true;
        }
    });

    ok(caughtError, "bt_plugin_find_all_from_dir() fails with an invalid path");

    const auto plugins = bt2::findAllPluginsFromDir(pluginDir, BT_FALSE, BT_FALSE);
    ok(plugins, "bt_plugin_find_all_from_dir() returns a plugin set with a valid path");

    /* 2 or 4, if `.la` files are considered or not */
    ok(plugins->length() == 2 || plugins->length() == 4,
       "bt_plugin_find_all_from_dir() returns the expected number of plugin objects");
}

void testFind(const char *pluginDir)
{
    ok(!bt2::findPlugin(NON_EXISTING_PATH, true, false, false, false, false),
       "bt_plugin_find() returns BT_PLUGIN_STATUS_NOT_FOUND with an unknown plugin name");

    const auto pluginPath = fmt::format(
        "{}" G_SEARCHPATH_SEPARATOR_S G_DIR_SEPARATOR_S
        "ec1d09e5-696c-442e-b1c3-f9c6cf7f5958" G_SEARCHPATH_SEPARATOR_S G_SEARCHPATH_SEPARATOR_S
            G_SEARCHPATH_SEPARATOR_S "{}" G_SEARCHPATH_SEPARATOR_S
        "8db46494-a398-466a-9649-c765ae077629" G_SEARCHPATH_SEPARATOR_S,
        NON_EXISTING_PATH, pluginDir);

    g_setenv("BABELTRACE_PLUGIN_PATH", pluginPath.c_str(), 1);

    const auto plugin = bt2::findPlugin("test_minimal", true, false, false, false, false);

    ok(plugin, "bt_plugin_find() returns a plugin object");
    ok(plugin->author() == "Janine Sutto",
       "bt_plugin_find() finds the correct plugin for a given name");
}

} /* namespace */

int main(int argc, char **argv)
{
    if (argc != 2) {
        fmt::println(stderr, "Usage: test_plugin plugin_directory");
        return 1;
    }

    const auto pluginDir = argv[1];

    plan_tests(NR_TESTS);
    testMinimal(pluginDir);
    testSfs(pluginDir);
    testCreateAllFromDir(pluginDir);
    testFind(pluginDir);
    return exit_status();
}
