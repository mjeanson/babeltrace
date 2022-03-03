# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2019 EfficiOS Inc.
#

import unittest
import bt2
import os

_TEST_PLUGIN_BUILDDIR = os.environ['BT_TESTS_BUILDDIR']
_TEST_PLUGIN_PLUGINS_PATH = os.environ['BT_PLUGINS_PATH']
_TEST_PLUGIN_PLUGIN_EXTENSION_BY_OS = {'cygwin': 'dll', 'mingw': 'dll'}


class PluginSetTestCase(unittest.TestCase):
    def test_create(self):
        pset = bt2.find_plugins_in_path(_TEST_PLUGIN_PLUGINS_PATH)
        self.assertTrue(len(pset) >= 3)

    def test_getitem(self):
        pset = bt2.find_plugins_in_path(_TEST_PLUGIN_PLUGINS_PATH)
        self.assertTrue(pset[0].path.startswith(_TEST_PLUGIN_PLUGINS_PATH))

    def test_iter(self):
        pset = bt2.find_plugins_in_path(_TEST_PLUGIN_PLUGINS_PATH)
        names = set()

        for plugin in pset:
            names.add(plugin.name)

        self.assertTrue('ctf' in names)
        self.assertTrue('utils' in names)
        self.assertTrue('text' in names)


class FindPluginsTestCase(unittest.TestCase):
    def test_find_nonexistent_dir(self):
        with self.assertRaises(ValueError):
            bt2.find_plugins_in_path(
                '/this/does/not/exist/246703df-cb85-46d5-8406-5e8dc4a88b41'
            )

    def test_find_none_existing_dir(self):
        plugins = bt2.find_plugins_in_path(_TEST_PLUGIN_BUILDDIR, recurse=False)
        self.assertIsNone(plugins)

    def test_find_dir(self):
        pset = bt2.find_plugins_in_path(_TEST_PLUGIN_PLUGINS_PATH)
        self.assertTrue(len(pset) >= 3)

    def test_find_file(self):
        extension = _TEST_PLUGIN_PLUGIN_EXTENSION_BY_OS.get(
            os.environ['BT_TESTS_OS_TYPE'], 'so'
        )
        plugin_name = 'babeltrace-plugin-utils.{}'.format(extension)
        path = os.path.join(_TEST_PLUGIN_PLUGINS_PATH, '.libs', plugin_name)
        pset = bt2.find_plugins_in_path(path)
        self.assertTrue(len(pset) == 1)


class FindPluginTestCase(unittest.TestCase):
    def test_find_none(self):
        plugin = bt2.find_plugin(
            'this-does-not-exist-246703df-cb85-46d5-8406-5e8dc4a88b41'
        )
        self.assertIsNone(plugin)

    def test_find_existing(self):
        plugin = bt2.find_plugin('ctf', find_in_user_dir=False, find_in_sys_dir=False)
        self.assertIsNotNone(plugin)


class PluginTestCase(unittest.TestCase):
    def setUp(self):
        self._plugin = bt2.find_plugin(
            'ctf', find_in_user_dir=False, find_in_sys_dir=False
        )

    def tearDown(self):
        del self._plugin

    def test_name(self):
        self.assertEqual(self._plugin.name, 'ctf')

    def test_path(self):
        plugin_path = os.path.abspath(os.path.normcase(self._plugin.path))
        plugin_path_env = os.path.abspath(os.path.normcase(_TEST_PLUGIN_PLUGINS_PATH))
        self.assertTrue(plugin_path.startswith(plugin_path_env))

    def test_author(self):
        self.assertEqual(self._plugin.author, 'EfficiOS <https://www.efficios.com/>')

    def test_license(self):
        self.assertEqual(self._plugin.license, 'MIT')

    def test_description(self):
        self.assertEqual(self._plugin.description, 'CTF input and output')

    def test_version(self):
        self.assertIsNone(self._plugin.version)

    def test_source_comp_classes_len(self):
        self.assertEqual(len(self._plugin.source_component_classes), 2)

    def test_source_comp_classes_getitem(self):
        self.assertEqual(self._plugin.source_component_classes['fs'].name, 'fs')

    def test_source_comp_classes_getitem_invalid(self):
        with self.assertRaises(KeyError):
            self._plugin.source_component_classes['lol']

    def test_source_comp_classes_iter(self):
        plugins = {}

        for cc_name, cc in self._plugin.source_component_classes.items():
            plugins[cc_name] = cc

        self.assertTrue('fs' in plugins)
        self.assertTrue('lttng-live' in plugins)
        self.assertEqual(plugins['fs'].name, 'fs')
        self.assertEqual(plugins['lttng-live'].name, 'lttng-live')

    def test_filter_comp_classes_len(self):
        plugin = bt2.find_plugin('utils', find_in_user_dir=False, find_in_sys_dir=False)
        self.assertEqual(len(plugin.filter_component_classes), 2)

    def test_sink_comp_classes_len(self):
        self.assertEqual(len(self._plugin.sink_component_classes), 1)


if __name__ == '__main__':
    unittest.main()
