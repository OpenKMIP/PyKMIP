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

import binascii
import testtools

from kmip.core import enums
from kmip.pie import objects


class TestOpaqueObject(testtools.TestCase):
    """
    Test suite for OpaqueObject.
    """
    def setUp(self):
        super(TestOpaqueObject, self).setUp()

        # Encoding taken from Sections 3.1.5 of the KMIP 1.1 testing
        # documentation.
        self.bytes_a = (
            b'\x53\x65\x63\x72\x65\x74\x50\x61\x73\x73\x77\x6F\x72\x64')
        self.bytes_b = (
            b'\x53\x65\x63\x72\x65\x74\x50\x61\x73\x73\x77\x6F\x72\x65')

    def tearDown(self):
        super(TestOpaqueObject, self).tearDown()

    def test_init(self):
        """
        Test that a OpaqueObject object can be instantiated.
        """
        obj = objects.OpaqueObject(
            self.bytes_a, enums.OpaqueDataType.NONE)

        self.assertEqual(obj.value, self.bytes_a)
        self.assertEqual(obj.opaque_type, enums.OpaqueDataType.NONE)
        self.assertEqual(obj.names, ['Opaque Object'])

    def test_init_with_args(self):
        """
        Test that a OpaqueObject object can be instantiated with all arguments.
        """
        obj = objects.OpaqueObject(
            self.bytes_a,
            enums.OpaqueDataType.NONE,
            name='Test Opaque Object')

        self.assertEqual(obj.value, self.bytes_a)
        self.assertEqual(obj.opaque_type, enums.OpaqueDataType.NONE)
        self.assertEqual(obj.names, ['Test Opaque Object'])

    def test_get_object_type(self):
        """
        Test that the object type can be retrieved from the OpaqueObject.
        """
        expected = enums.ObjectType.OPAQUE_DATA
        obj = objects.OpaqueObject(self.bytes_a, enums.OpaqueDataType.NONE)
        observed = obj.object_type
        self.assertEqual(expected, observed)

    def test_validate_on_invalid_value(self):
        """
        Test that a TypeError is raised when an invalid value is used to
        construct a OpaqueObject.
        """
        args = (0, enums.OpaqueDataType.NONE)
        self.assertRaises(TypeError, objects.OpaqueObject, *args)

    def test_validate_on_invalid_data_type(self):
        """
        Test that a TypeError is raised when an invalid data type is used to
        construct a OpaqueObject.
        """
        args = (self.bytes_a, 'invalid')
        self.assertRaises(TypeError, objects.OpaqueObject, *args)

    def test_validate_on_invalid_name(self):
        """
        Test that a TypeError is raised when an invalid name value is used to
        construct a OpaqueObject.
        """
        args = (self.bytes_a, enums.OpaqueDataType.NONE)
        kwargs = {'name': 0}
        self.assertRaises(TypeError, objects.OpaqueObject, *args, **kwargs)

    def test_repr(self):
        """
        Test that repr can be applied to a OpaqueObject.
        """
        obj = objects.OpaqueObject(self.bytes_a, enums.OpaqueDataType.NONE)
        args = "value={0}, opaque_type={1}".format(
            binascii.hexlify(self.bytes_a), enums.OpaqueDataType.NONE)
        expected = "OpaqueObject({0})".format(args)
        observed = repr(obj)
        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a OpaqueObject.
        """
        obj = objects.OpaqueObject(self.bytes_a, enums.OpaqueDataType.NONE)
        expected = str(binascii.hexlify(self.bytes_a))
        observed = str(obj)
        self.assertEqual(expected, observed)

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        OpaqueObject objects with the same data.
        """
        a = objects.OpaqueObject(self.bytes_a, enums.OpaqueDataType.NONE)
        b = objects.OpaqueObject(self.bytes_a, enums.OpaqueDataType.NONE)
        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_value(self):
        """
        Test that the equality operator returns False when comparing two
        OpaqueObject objects with different data.
        """
        a = objects.OpaqueObject(self.bytes_a, enums.OpaqueDataType.NONE)
        b = objects.OpaqueObject(self.bytes_b, enums.OpaqueDataType.NONE)
        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_data_type(self):
        """
        Test that the equality operator returns False when comparing two
        OpaqueObject objects with different data.
        """
        a = objects.OpaqueObject(self.bytes_a, enums.OpaqueDataType.NONE)
        b = objects.OpaqueObject(self.bytes_a, enums.OpaqueDataType.NONE)
        b.opaque_type = "invalid"
        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing a
        OpaqueObject object to a non-OpaqueObject object.
        """
        a = objects.OpaqueObject(self.bytes_a, enums.OpaqueDataType.NONE)
        b = "invalid"
        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing
        two OpaqueObject objects with the same internal data.
        """
        a = objects.OpaqueObject(self.bytes_a, enums.OpaqueDataType.NONE)
        b = objects.OpaqueObject(self.bytes_a, enums.OpaqueDataType.NONE)
        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_value(self):
        """
        Test that the equality operator returns True when comparing two
        OpaqueObject objects with different data.
        """
        a = objects.OpaqueObject(self.bytes_a, enums.OpaqueDataType.NONE)
        b = objects.OpaqueObject(self.bytes_b, enums.OpaqueDataType.NONE)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_data_type(self):
        """
        Test that the equality operator returns True when comparing two
        OpaqueObject objects with different data.
        """
        a = objects.OpaqueObject(self.bytes_a, enums.OpaqueDataType.NONE)
        b = objects.OpaqueObject(self.bytes_a, enums.OpaqueDataType.NONE)
        b.opaque_type = "invalid"
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns True when comparing a
        OpaqueObject object to a non-OpaqueObject object.
        """
        a = objects.OpaqueObject(self.bytes_a, enums.OpaqueDataType.NONE)
        b = "invalid"
        self.assertTrue(a != b)
        self.assertTrue(b != a)
