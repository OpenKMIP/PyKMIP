# Copyright (c) 2016 The Johns Hopkins University/Applied Physics Laboratory
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

import testtools

from kmip.core import enums
from kmip.pie.sqltypes import ManagedObjectName

class TestSqlTypesManagedObjectName(testtools.TestCase):
    """
    Test suite for objects in sqltypes.py.
    """

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        ManagedObjectName objects with the same data.
        """
        a = ManagedObjectName('a', 0)
        b = ManagedObjectName('a', 0)
        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_name(self):
        """
        Test that the equality operator returns False when comparing two
        ManagedObjectName objects with different names.
        """
        a = ManagedObjectName('a', 0)
        b = ManagedObjectName('b', 0)
        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_index(self):
        """
        Test that the equality operator returns False when comparing two
        ManagedObjectName objects with different indices.
        """
        a = ManagedObjectName('a', 0)
        b = ManagedObjectName('a', 1)
        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_name_type(self):
        """
        Test that the equality operator returns False when comparing two
        ManagedObjectName objects with different name types.
        """
        a = ManagedObjectName('a', 0, enums.NameType.UNINTERPRETED_TEXT_STRING)
        b = ManagedObjectName('a', 0, enums.NameType.URI)
        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_class_type(self):
        """
        Test that the equality operator returns False when comparing a
        ManagedObjectName object with a different type of object.
        """
        a = ManagedObjectName('a', 0, enums.NameType.UNINTERPRETED_TEXT_STRING)
        b = 'foo'
        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the not equal operator returns False when comparing two
        ManagedObjectName objects with the same data.
        """
        a = ManagedObjectName('a', 0)
        b = ManagedObjectName('a', 0)
        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_name(self):
        """
        Test that the not equal operator returns True when comparing two
        ManagedObjectName objects with different names.
        """
        a = ManagedObjectName('a', 0)
        b = ManagedObjectName('b', 0)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_index(self):
        """
        Test that the not equal operator returns True when comparing two
        ManagedObjectName objects with different indices.
        """
        a = ManagedObjectName('a', 0)
        b = ManagedObjectName('a', 1)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_name_type(self):
        """
        Test that the not equal operator returns True when comparing two
        ManagedObjectName objects with different name types.
        """
        a = ManagedObjectName('a', 0, enums.NameType.UNINTERPRETED_TEXT_STRING)
        b = ManagedObjectName('a', 0, enums.NameType.URI)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_class_type(self):
        """
        Test that the not equal operator returns False when comparing a
        ManagedObjectName object with a different type of object.
        """
        a = ManagedObjectName('a', 0, enums.NameType.UNINTERPRETED_TEXT_STRING)
        b = 'foo'
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test that __repr__ is implemented.
        """
        a = ManagedObjectName('a', 0, enums.NameType.UNINTERPRETED_TEXT_STRING)
        repr(a)
