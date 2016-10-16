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
from kmip.core import attributes
from kmip.pie.objects import CryptographicObject
from kmip.pie.sqltypes import ManagedObjectName
from kmip.pie.sqltypes import CryptographicObjectLink


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


class TestSqlTypesCryptographicObjectLink(testtools.TestCase):
    """
    Test suite for CryptographicObjectLink in sqltypes.py.
    """
    def setUp(self):
        super(TestSqlTypesCryptographicObjectLink, self).setUp()
        """
        TODO:
        Without import of CryptographicObject (or ManagedObject)
            from kmip.pie.objects,
        when running only test of current test-file,
        there is an sqlalchemy exception:
            sqlalchemy.exc.InvalidRequestError: One or more mappers failed to
            initialize - can't proceed with initialization of other mappers.
            Original exception was: When initializing mapper
            Mapper|ManagedObjectName|managed_object_names, expression
            'ManagedObject' failed to locate a name ("name 'ManagedObject'
            is not defined"). If this is a class name, consider adding this
            relationship() to the <class 'kmip.pie.sqltypes.ManagedObjectName'>
            class after both dependent classes have been defined.

        Here below instantiating CryptographicObject object to satisfy
        style check.
        """
        self.crypto_object = CryptographicObject()

    def test_empty_object(self):
        """
        Test epmty CryptographicObjectLink object.
        """
        a = CryptographicObjectLink()
        self.assertTrue(a.link_type is None)
        self.assertTrue(a.linked_oid is None)

    def test_invalid_init_parameters(self):
        """
        Test the exception raised when instantiating
        CryptographicObjectLink object with invalid link data
        """
        args = ('invalid', 0)
        self.assertRaises(TypeError, CryptographicObjectLink, *args)

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        CryptographicObjectLink objects with the same data.
        """
        link = attributes.Link.create(enums.LinkType.PUBLIC_KEY_LINK, 12)
        a = CryptographicObjectLink(link, 0)
        b = CryptographicObjectLink(link, 0)
        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal(self):
        """
        Test that the equality operator returns False when comparing two
        CryptographicObjectLink objects with different link types and
        linked object ID.
        """
        link_aa = attributes.Link.create(enums.LinkType.PUBLIC_KEY_LINK, 12)
        link_ab = attributes.Link.create(enums.LinkType.PUBLIC_KEY_LINK, 13)
        link_ba = attributes.Link.create(enums.LinkType.PRIVATE_KEY_LINK, 12)
        link_bb = attributes.Link.create(enums.LinkType.PRIVATE_KEY_LINK, 13)
        aa = CryptographicObjectLink(link_aa, 0)
        ab = CryptographicObjectLink(link_ab, 0)
        ba = CryptographicObjectLink(link_ba, 0)
        bb = CryptographicObjectLink(link_bb, 0)
        self.assertFalse(aa == ab)
        self.assertFalse(ba == aa)
        self.assertFalse(aa == bb)
        self.assertFalse(aa == 'invalid')

    def test_equal_on_not_equal_index(self):
        """
        Test that the equality operator returns False when comparing two
        CryptographicObjectLink objects with different indices.
        """
        link = attributes.Link.create(enums.LinkType.PUBLIC_KEY_LINK, 12)
        a = CryptographicObjectLink(link, 0)
        b = CryptographicObjectLink(link, 1)
        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the not equal operator returns False when comparing two
        CryptographicObjectLink objects with the same data.
        """
        link = attributes.Link.create(enums.LinkType.PUBLIC_KEY_LINK, 12)
        a = CryptographicObjectLink(link, 0)
        b = CryptographicObjectLink(link, 0)
        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal(self):
        """
        Test that the not equal operator returns True when comparing two
        CryptographicObjectLink objects with different link types and
        linked object ID.
        """
        link_aa = attributes.Link.create(enums.LinkType.PUBLIC_KEY_LINK, 12)
        link_ab = attributes.Link.create(enums.LinkType.PUBLIC_KEY_LINK, 13)
        link_ba = attributes.Link.create(enums.LinkType.PRIVATE_KEY_LINK, 12)
        link_bb = attributes.Link.create(enums.LinkType.PRIVATE_KEY_LINK, 13)
        aa = CryptographicObjectLink(link_aa, 0)
        ab = CryptographicObjectLink(link_ab, 0)
        ba = CryptographicObjectLink(link_ba, 0)
        bb = CryptographicObjectLink(link_bb, 0)
        self.assertTrue(aa != ab)
        self.assertTrue(ba != aa)
        self.assertTrue(aa != bb)
        self.assertTrue(aa != 'invalid')

    def test_not_equal_on_not_equal_index(self):
        """
        Test that the not equal operator returns True when comparing two
        CryptographicObjectLink objects with different indices.
        """
        link = attributes.Link.create(enums.LinkType.PUBLIC_KEY_LINK, 12)
        a = CryptographicObjectLink(link, 0)
        b = CryptographicObjectLink(link, 1)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test that __repr__ is implemented.
        """
        repr_expected = (
            "<CryptographicObjectLink(type='%s', "
            "linked-oid='%s', index='%d')>")

        link = attributes.Link.create(enums.LinkType.PUBLIC_KEY_LINK, 12)
        a = CryptographicObjectLink(link, 0)
        self.assertTrue(repr(a) == repr_expected)
