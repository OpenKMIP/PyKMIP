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


from testtools import TestCase

from kmip.core import exceptions
from kmip.core.attributes import Link
from kmip.core.enums import LinkType

from kmip.pie.objects import CryptographicObject


class DummyCryptographicObject(CryptographicObject):
    """
    A dummy CryptographicObject subclass for testing purposes.
    """

    def __init__(self, object_type=None):
        """
        Create a DummyCryptographicObject
        """
        super(DummyCryptographicObject, self).__init__()

        self._object_type = object_type

    def validate(self):
        super(DummyCryptographicObject, self).validate()
        return

    def __repr__(self):
        super(DummyCryptographicObject, self).__repr__()
        return ''

    def __str__(self):
        super(DummyCryptographicObject, self).__str__()
        return ''

    def __eq__(self, other):
        super(DummyCryptographicObject, self).__eq__(other)
        return True

    def __ne__(self, other):
        super(DummyCryptographicObject, self).__ne__(other)
        return False


class TestCryptographicObject(TestCase):
    """
    Test suite for CryptographicObject.

    Since CryptographicObject is an ABC abstract class, all tests are run
    against a dummy subclass defined above, DummyCryptographicObject.
    """

    def setUp(self):
        super(TestCryptographicObject, self).setUp()

    def tearDown(self):
        super(TestCryptographicObject, self).tearDown()

    def test_init(self):
        """
        Test that a complete subclass of CryptographicObject can be
        instantiated.
        """
        DummyCryptographicObject()

    def test_valid_link_types(self):
        """
        Test list of valid Link types associated with crytpgraphic object.
        """
        dummy = DummyCryptographicObject()
        valid_types = dummy.valid_link_types()

        base = "expected {0}, received {1}"
        msg = base.format(list, valid_types)
        self.assertIsInstance(valid_types, list, msg)
        self.assertEqual(4, len(valid_types))
        self.assertIn(LinkType.PARENT_LINK, valid_types)
        self.assertIn(LinkType.CHILD_LINK, valid_types)
        self.assertIn(LinkType.PREVIOUS_LINK, valid_types)
        self.assertIn(LinkType.NEXT_LINK, valid_types)

    def test_validate_valid_link(self):
        """
        Test validating of the already existing link
        """
        dummy = DummyCryptographicObject()
        link = Link(
            link_type=LinkType.PARENT_LINK,
            linked_oid='1234')

        dummy.validate_link(link)

    def test_validate_same_link(self):
        """
        Test validating of the link of the same type
        and with the same referenced object ID
        """
        dummy = DummyCryptographicObject()
        link = Link(
            link_type=LinkType.PARENT_LINK,
            linked_oid='1234')
        dummy.links.extend([link])

        dummy.validate_link(link)

    def test_validate_another_link_of_same_type(self):
        """
        Test validating of second link of the same type
        and with the different referenced object ID
        """
        dummy = DummyCryptographicObject()
        link = Link(
            link_type=LinkType.PARENT_LINK,
            linked_oid='1234')
        dummy.links.extend([link])

        link_bis = Link(
            link_type=LinkType.PARENT_LINK,
            linked_oid='4321')

        self.assertRaises(exceptions.InvalidField, dummy.validate_link,
                          link_bis)

    def test_validate_link_not_allowed_type(self):
        """
        Test validating of the already existing link
        """
        dummy = DummyCryptographicObject()
        link = Link(
            link_type=LinkType.PUBLIC_KEY_LINK,
            linked_oid='1234')

        self.assertRaises(exceptions.InvalidField, dummy.validate_link, link)

    def test_repr(self):
        """
        Test that repr can be applied to a CryptographicObject.
        """
        dummy = DummyCryptographicObject()
        repr(dummy)

    def test_str(self):
        """
        Test that str can be applied to a CryptographicObject.
        """
        dummy = DummyCryptographicObject()
        str(dummy)

    def test_eq(self):
        """
        Test that equality can be applied to a CryptographicObject.
        """
        dummy = DummyCryptographicObject()
        self.assertTrue(dummy == dummy)

    def test_ne(self):
        """
        Test that inequality can be applied to a CryptographicObject.
        """
        dummy = DummyCryptographicObject()
        self.assertFalse(dummy != dummy)
