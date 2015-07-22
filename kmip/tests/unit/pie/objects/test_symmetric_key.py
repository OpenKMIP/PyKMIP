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


class TestSymmetricKey(testtools.TestCase):
    """
    Test suite for SymmetricKey.
    """

    def setUp(self):
        super(TestSymmetricKey, self).setUp()

        # Key values taken from Sections 14.2, 15.2, and 18.1 of the KMIP 1.1
        # testing documentation.
        self.bytes_128a = (
            b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E'
            b'\x0F')
        self.bytes_128b = (
            b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE'
            b'\xFF')
        self.bytes_256a = (
            b'\x00\x00\x11\x11\x22\x22\x33\x33\x44\x44\x55\x55\x66\x66\x77\x77'
            b'\x88\x88\x99\x99\xAA\xAA\xBB\xBB\xCC\xCC\xDD\xDD\xEE\xEE\xFF'
            b'\xFF')
        self.bytes_256b = (
            b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
            b'\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E'
            b'\x1F')

    def tearDown(self):
        super(TestSymmetricKey, self).tearDown()

    def test_init(self):
        """
        Test that a SymmetricKey object can be instantiated.
        """
        key = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128a)

        self.assertEqual(key.cryptographic_algorithm,
                         enums.CryptographicAlgorithm.AES)
        self.assertEqual(key.cryptographic_length, 128)
        self.assertEqual(key.value, self.bytes_128a)
        self.assertEqual(key.cryptographic_usage_masks, list())
        self.assertEqual(key.names, ['Symmetric Key'])

    def test_init_with_args(self):
        """
        Test that a SymmetricKey object can be instantiated with all arguments.
        """
        key = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            128,
            self.bytes_128a,
            masks=[enums.CryptographicUsageMask.ENCRYPT,
                   enums.CryptographicUsageMask.DECRYPT],
            name='Test Symmetric Key')

        self.assertEqual(key.cryptographic_algorithm,
                         enums.CryptographicAlgorithm.AES)
        self.assertEqual(key.cryptographic_length, 128)
        self.assertEqual(key.value, self.bytes_128a)
        self.assertEqual(key.cryptographic_usage_masks,
                         [enums.CryptographicUsageMask.ENCRYPT,
                          enums.CryptographicUsageMask.DECRYPT])
        self.assertEqual(key.names, ['Test Symmetric Key'])

    def test_get_object_type(self):
        """
        Test that the object type can be retrieved from the SymmetricKey.
        """
        expected = enums.ObjectType.SYMMETRIC_KEY
        key = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128a)
        observed = key.object_type

        self.assertEqual(expected, observed)

    def test_validate_on_invalid_algorithm(self):
        """
        Test that a TypeError is raised when an invalid algorithm value is
        used to construct a SymmetricKey.
        """
        args = ('invalid', 128, self.bytes_128a)

        self.assertRaises(TypeError, objects.SymmetricKey, *args)

    def test_validate_on_invalid_length(self):
        """
        Test that a TypeError is raised when an invalid length value is used
        to construct a SymmetricKey.
        """
        args = (enums.CryptographicAlgorithm.AES, 'invalid', self.bytes_128a)

        self.assertRaises(TypeError, objects.SymmetricKey, *args)

    def test_validate_on_invalid_value(self):
        """
        Test that a TypeError is raised when an invalid value is used to
        construct a SymmetricKey.
        """
        args = (enums.CryptographicAlgorithm.AES, 128, 0)

        self.assertRaises(TypeError, objects.SymmetricKey, *args)

    def test_validate_on_invalid_masks(self):
        """
        Test that a TypeError is raised when an invalid masks value is used to
        construct a SymmetricKey.
        """
        args = (enums.CryptographicAlgorithm.AES, 128, self.bytes_128a)
        kwargs = {'masks': 'invalid'}

        self.assertRaises(TypeError, objects.SymmetricKey, *args, **kwargs)

    def test_validate_on_invalid_mask(self):
        """
        Test that a TypeError is raised when an invalid mask value is used to
        construct a SymmetricKey.
        """
        args = (enums.CryptographicAlgorithm.AES, 128, self.bytes_128a)
        kwargs = {'masks': ['invalid']}

        self.assertRaises(TypeError, objects.SymmetricKey, *args, **kwargs)

    def test_validate_on_invalid_name(self):
        """
        Test that a TypeError is raised when an invalid name value is used to
        construct a SymmetricKey.
        """
        args = (enums.CryptographicAlgorithm.AES, 128, self.bytes_128a)
        kwargs = {'name': 0}

        self.assertRaises(TypeError, objects.SymmetricKey, *args, **kwargs)

    def test_validate_on_invalid_length_value(self):
        """
        Test that a ValueError is raised when an invalid length value is
        used to construct a SymmetricKey.
        """
        args = (enums.CryptographicAlgorithm.AES, 256, self.bytes_128a)

        self.assertRaises(ValueError, objects.SymmetricKey, *args)

    def test_validate_on_invalid_value_length(self):
        """
        Test that a ValueError is raised when an invalid value is used to
        construct a SymmetricKey.
        """
        args = (enums.CryptographicAlgorithm.AES, 128, self.bytes_256a)

        self.assertRaises(ValueError, objects.SymmetricKey, *args)

    def test_repr(self):
        """
        Test that repr can be applied to a SymmetricKey.
        """
        key = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128a)

        args = "algorithm={0}, length={1}, value={2}".format(
            enums.CryptographicAlgorithm.AES, 128,
            binascii.hexlify(self.bytes_128a))
        expected = "SymmetricKey({0})".format(args)
        observed = repr(key)

        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a SymmetricKey.
        """
        key = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128a)
        expected = str(binascii.hexlify(self.bytes_128a))
        observed = str(key)

        self.assertEqual(expected, observed)

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        SymmetricKey objects with the same data.
        """
        a = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128a)
        b = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128a)

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_algorithm(self):
        """
        Test that the equality operator returns False when comparing two
        SymmetricKey objects with different data.
        """
        a = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128a)
        b = objects.SymmetricKey(
            enums.CryptographicAlgorithm.RSA, 128, self.bytes_128a)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_length(self):
        """
        Test that the equality operator returns False when comparing two
        SymmetricKey objects with different data.
        """
        a = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128a)
        b = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES, 256, self.bytes_256a)
        b.value = self.bytes_128a

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_value(self):
        """
        Test that the equality operator returns False when comparing two
        SymmetricKey objects with different data.
        """
        a = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128a)
        b = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128b)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing a
        SymmetricKey object to a non-SymmetricKey object.
        """
        a = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128a)
        b = "invalid"

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing
        two SymmetricKey objects with the same internal data.
        """
        a = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128a)
        b = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128a)

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_algorithm(self):
        """
        Test that the inequality operator returns True when comparing two
        SymmetricKey objects with different data.
        """
        a = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128a)
        b = objects.SymmetricKey(
            enums.CryptographicAlgorithm.RSA, 128, self.bytes_128a)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_length(self):
        """
        Test that the inequality operator returns True when comparing two
        SymmetricKey objects with different data.
        """
        a = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128a)
        b = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES, 256, self.bytes_256a)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_value(self):
        """
        Test that the inequality operator returns True when comparing two
        SymmetricKey objects with different data.
        """
        a = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128a)
        b = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128b)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns True when comparing a
        SymmetricKey object to a non-SymmetricKey object.
        """
        a = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128a)
        b = "invalid"

        self.assertTrue(a != b)
        self.assertTrue(b != a)
