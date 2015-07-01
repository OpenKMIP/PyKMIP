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

from kmip.pie.objects import ManagedObject


class DummyManagedObject(ManagedObject):
    """
    A dummy ManagedObject subclass for testing purposes.
    """

    def __init__(self, object_type=None):
        """
        Create a DummyManagedObject

        Args:
            object_type (any): A value to test the setting of the object_type
                attribute. Optional, defaults to None.
        """
        super(DummyManagedObject, self).__init__()

        self._object_type = object_type

    def validate(self):
        super(DummyManagedObject, self).validate()
        return

    def __repr__(self):
        super(DummyManagedObject, self).__repr__()
        return ''

    def __str__(self):
        super(DummyManagedObject, self).__str__()
        return ''

    def __eq__(self, other):
        super(DummyManagedObject, self).__eq__(other)
        return True

    def __ne__(self, other):
        super(DummyManagedObject, self).__ne__(other)
        return False


class TestManagedObject(TestCase):
    """
    Test suite for ManagedObject.

    Since ManagedObject is an ABC abstract class, all tests are run against a
    dummy subclass defined above, DummyManagedObject.
    """

    def setUp(self):
        super(TestManagedObject, self).setUp()

    def tearDown(self):
        super(TestManagedObject, self).tearDown()

    def test_init(self):
        """
        Test that a complete subclass of ManagedObject can be instantiated.
        """
        DummyManagedObject()

    def test_get_object_type(self):
        """
        Test that the object type can be retrieved from the ManagedObject.
        """
        expected = 'dummy'
        dummy = DummyManagedObject(expected)
        observed = dummy.object_type

        self.assertEqual(expected, observed)

    def test_set_object_type(self):
        """
        Test that an AttributeError is raised when attempting to change the
        value of the object type.
        """
        dummy = DummyManagedObject()

        def set_object_type():
            dummy.object_type = 'placeholder'

        self.assertRaises(AttributeError, set_object_type)

    def test_validate(self):
        """
        Test that validate can be called on a ManagedObject.
        """
        dummy = DummyManagedObject()
        dummy.validate()

    def test_repr(self):
        """
        Test that repr can be applied to a ManagedObject.
        """
        dummy = DummyManagedObject()
        repr(dummy)

    def test_str(self):
        """
        Test that str can be applied to a ManagedObject.
        """
        dummy = DummyManagedObject()
        str(dummy)

    def test_eq(self):
        """
        Test that equality can be applied to a ManagedObject.
        """
        dummy = DummyManagedObject()
        self.assertTrue(dummy == dummy)

    def test_ne(self):
        """
        Test that inequality can be applied to a ManagedObject.
        """
        dummy = DummyManagedObject()
        self.assertFalse(dummy != dummy)
