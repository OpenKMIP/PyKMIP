# Copyright (c) 2015 The Johns Hopkins University/Applied Physics Laboratory
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from six import string_types
from testtools import TestCase

from kmip.core.objects import ExtensionName
from kmip.core.objects import ExtensionTag
from kmip.core.objects import ExtensionType


class TestExtensionName(TestCase):
    """
    A test suite for the ExtensionName class.

    Since ExtensionName is a simple wrapper for the TextString primitive, only
    a few tests pertaining to construction are needed.
    """

    def setUp(self):
        super(TestExtensionName, self).setUp()

    def tearDown(self):
        super(TestExtensionName, self).tearDown()

    def _test_init(self, value):
        if (isinstance(value, string_types)) or (value is None):
            extension_name = ExtensionName(value)

            if value is None:
                value = ''

            msg = "expected {0}, observed {1}".format(
                value, extension_name.value)
            self.assertEqual(value, extension_name.value, msg)
        else:
            self.assertRaises(TypeError, ExtensionName, value)

    def test_init_with_none(self):
        """
        Test that an ExtensionName object can be constructed with no specified
        value.
        """
        self._test_init(None)

    def test_init_with_valid(self):
        """
        Test that an ExtensionName object can be constructed with a valid
        string value.
        """
        self._test_init("valid")

    def test_init_with_invalid(self):
        """
        Test that a TypeError exception is raised when a non-string value is
        used to construct an ExtensionName object.
        """
        self._test_init(0)


class TestExtensionTag(TestCase):
    """
    A test suite for the ExtensionTag class.

    Since ExtensionTag is a simple wrapper for the Integer primitive, only a
    few tests pertaining to construction are needed.
    """

    def setUp(self):
        super(TestExtensionTag, self).setUp()

    def tearDown(self):
        super(TestExtensionTag, self).tearDown()

    def _test_init(self, value):
        if (isinstance(value, int)) or (value is None):
            extension_tag = ExtensionTag(value)

            if value is None:
                value = 0

            msg = "expected {0}, observed {1}".format(
                value, extension_tag.value)
            self.assertEqual(value, extension_tag.value, msg)
        else:
            self.assertRaises(TypeError, ExtensionTag, value)

    def test_init_with_none(self):
        """
        Test that an ExtensionTag object can be constructed with no specified
        value.
        """
        self._test_init(None)

    def test_init_with_valid(self):
        """
        Test that an ExtensionTag object can be constructed with a valid
        integer value.
        """
        self._test_init(0)

    def test_init_with_invalid(self):
        """
        Test that a TypeError exception is raised when a non-integer value is
        used to construct an ExtensionName object.
        """
        self._test_init("invalid")


class TestExtensionType(TestCase):
    """
    A test suite for the ExtensionType class.

    Since ExtensionType is a simple wrapper for the Integer primitive, only a
    few tests pertaining to construction are needed.
    """

    def setUp(self):
        super(TestExtensionType, self).setUp()

    def tearDown(self):
        super(TestExtensionType, self).tearDown()

    def _test_init(self, value):
        if (isinstance(value, int)) or (value is None):
            extension_type = ExtensionType(value)

            if value is None:
                value = 0

            msg = "expected {0}, observed {1}".format(
                value, extension_type.value)
            self.assertEqual(value, extension_type.value, msg)
        else:
            self.assertRaises(TypeError, ExtensionType, value)

    def test_init_with_none(self):
        """
        Test that an ExtensionType object can be constructed with no specified
        value.
        """
        self._test_init(None)

    def test_init_with_valid(self):
        """
        Test that an ExtensionType object can be constructed with a valid
        integer value.
        """
        self._test_init(0)

    def test_init_with_invalid(self):
        """
        Test that a TypeError exception is raised when a non-string value is
        used to construct an ExtensionType object.
        """
        self._test_init("invalid")
