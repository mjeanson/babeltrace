# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2022 EfficiOS, Inc.
#


# Decorator for unittest.TestCast sub-classes to run tests against CTF 1 and
# CTF 2 versions of the same traces.
#
# Replaces all test_* methods with a test_*_ctf_1 and a test_*_ctf_2 variant.
#
# For instance, it transforms this:
#
#   @test_all_ctf_versions
#   class MyTestCase(unittest.TestCase):
#       test_something(self):
#           pass
#
# into:
#
#   class MyTestcase(unittest.TestCase):
#       test_something_ctf_1(self):
#           pass
#
#       test_something_ctf_2(self):
#           pass
#
# The test methods are wrapped such that the self._ctf_version attribute is
# set to either 1 or 2 during the call to each method.
def test_all_ctf_versions(cls):
    for attr_name, attr_value in list(cls.__dict__.items()):
        if not attr_name.startswith("test_") or not callable(attr_value):
            continue

        for ctf_version in 1, 2:
            # Callable that wraps and replaces test methods in order to
            # temporarily set the _ctf_version attribute on the TestCase class.
            def set_ctf_version_wrapper_method(self, ctf_version, test_method):
                assert not hasattr(self, "_ctf_version")
                self._ctf_version = ctf_version

                try:
                    return test_method(self)
                finally:
                    assert hasattr(self, "_ctf_version")
                    del self._ctf_version

            def wrap_method(wrapper_method, ctf_version, original_method):
                return lambda self: wrapper_method(self, ctf_version, original_method)

            setattr(
                cls,
                "{}_ctf_{}".format(attr_name, ctf_version),
                wrap_method(set_ctf_version_wrapper_method, ctf_version, attr_value),
            )

        delattr(cls, attr_name)

    return cls
