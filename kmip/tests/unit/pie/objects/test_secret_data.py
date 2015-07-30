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


class TestSecretData(testtools.TestCase):
    """
    Test suite for SecretData.
    """
    def setUp(self):
        super(TestSecretData, self).setUp()

        # Secret data taken from Sections 3.1.5 of the KMIP 1.1 testing
        # documentation.
        self.bytes_a = (
            b'\x53\x65\x63\x72\x65\x74\x50\x61\x73\x73\x77\x6F\x72\x64')
        self.bytes_b = (
            b'\x53\x65\x63\x72\x65\x74\x50\x61\x73\x73\x77\x6F\x72\x65')

    def tearDown(self):
        super(TestSecretData, self).tearDown()

    def test_init(self):
        """
        Test that a SecretData object can be instantiated.
        """
        secret = objects.SecretData(
            self.bytes_a, enums.SecretDataType.PASSWORD)

        self.assertEqual(secret.value, self.bytes_a)
        self.assertEqual(secret.data_type, enums.SecretDataType.PASSWORD)
        self.assertEqual(secret.cryptographic_usage_masks, list())
        self.assertEqual(secret.names, ['Secret Data'])

    def test_init_with_args(self):
        """
        Test that a SecretData object can be instantiated with all arguments.
        """
        key = objects.SecretData(
            self.bytes_a,
            enums.SecretDataType.PASSWORD,
            masks=[enums.CryptographicUsageMask.VERIFY],
            name='Test Secret Data')

        self.assertEqual(key.value, self.bytes_a)
        self.assertEqual(key.data_type, enums.SecretDataType.PASSWORD)
        self.assertEqual(key.cryptographic_usage_masks,
                         [enums.CryptographicUsageMask.VERIFY])
        self.assertEqual(key.names, ['Test Secret Data'])

    def test_get_object_type(self):
        """
        Test that the object type can be retrieved from the SecretData.
        """
        expected = enums.ObjectType.SECRET_DATA
        key = objects.SecretData(self.bytes_a, enums.SecretDataType.PASSWORD)
        observed = key.object_type
        self.assertEqual(expected, observed)

    def test_validate_on_invalid_value(self):
        """
        Test that a TypeError is raised when an invalid value is used to
        construct a SecretData.
        """
        args = (0, enums.SecretDataType.PASSWORD)
        self.assertRaises(TypeError, objects.SecretData, *args)

    def test_validate_on_invalid_data_type(self):
        """
        Test that a TypeError is raised when an invalid data type is used to
        construct a SecretData.
        """
        args = (self.bytes_a, 'invalid')
        self.assertRaises(TypeError, objects.SecretData, *args)

    def test_validate_on_invalid_masks(self):
        """
        Test that a TypeError is raised when an invalid masks value is used to
        construct a SecretData.
        """
        args = (self.bytes_a, enums.SecretDataType.PASSWORD)
        kwargs = {'masks': 'invalid'}
        self.assertRaises(TypeError, objects.SecretData, *args, **kwargs)

    def test_validate_on_invalid_mask(self):
        """
        Test that a TypeError is raised when an invalid mask value is used to
        construct a SecretData.
        """
        args = (self.bytes_a, enums.SecretDataType.PASSWORD)
        kwargs = {'masks': ['invalid']}
        self.assertRaises(TypeError, objects.SecretData, *args, **kwargs)

    def test_validate_on_invalid_name(self):
        """
        Test that a TypeError is raised when an invalid name value is used to
        construct a SecretData.
        """
        args = (self.bytes_a, enums.SecretDataType.PASSWORD)
        kwargs = {'name': 0}
        self.assertRaises(TypeError, objects.SecretData, *args, **kwargs)

    def test_repr(self):
        """
        Test that repr can be applied to a SecretData.
        """
        key = objects.SecretData(self.bytes_a, enums.SecretDataType.PASSWORD)
        args = "value={0}, data_type={1}".format(
            binascii.hexlify(self.bytes_a), enums.SecretDataType.PASSWORD)
        expected = "SecretData({0})".format(args)
        observed = repr(key)
        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a SecretData.
        """
        key = objects.SecretData(self.bytes_a, enums.SecretDataType.PASSWORD)
        expected = str(binascii.hexlify(self.bytes_a))
        observed = str(key)
        self.assertEqual(expected, observed)

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        SecretData objects with the same data.
        """
        a = objects.SecretData(self.bytes_a, enums.SecretDataType.PASSWORD)
        b = objects.SecretData(self.bytes_a, enums.SecretDataType.PASSWORD)
        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_value(self):
        """
        Test that the equality operator returns False when comparing two
        SecretData objects with different data.
        """
        a = objects.SecretData(self.bytes_a, enums.SecretDataType.PASSWORD)
        b = objects.SecretData(self.bytes_b, enums.SecretDataType.PASSWORD)
        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_data_type(self):
        """
        Test that the equality operator returns False when comparing two
        SecretData objects with different data.
        """
        a = objects.SecretData(self.bytes_a, enums.SecretDataType.PASSWORD)
        b = objects.SecretData(self.bytes_a, enums.SecretDataType.SEED)
        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing a
        SecretData object to a non-SecretData object.
        """
        a = objects.SecretData(self.bytes_a, enums.SecretDataType.PASSWORD)
        b = "invalid"
        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing
        two SecretData objects with the same internal data.
        """
        a = objects.SecretData(self.bytes_a, enums.SecretDataType.PASSWORD)
        b = objects.SecretData(self.bytes_a, enums.SecretDataType.PASSWORD)
        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_value(self):
        """
        Test that the equality operator returns True when comparing two
        SecretData objects with different data.
        """
        a = objects.SecretData(self.bytes_a, enums.SecretDataType.PASSWORD)
        b = objects.SecretData(self.bytes_b, enums.SecretDataType.PASSWORD)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_data_type(self):
        """
        Test that the equality operator returns True when comparing two
        SecretData objects with different data.
        """
        a = objects.SecretData(self.bytes_a, enums.SecretDataType.PASSWORD)
        b = objects.SecretData(self.bytes_a, enums.SecretDataType.SEED)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns True when comparing a
        SecretData object to a non-SecretData object.
        """
        a = objects.SecretData(self.bytes_a, enums.SecretDataType.PASSWORD)
        b = "invalid"
        self.assertTrue(a != b)
        self.assertTrue(b != a)
