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


class TestPublicKey(testtools.TestCase):
    """
    Test suite for PublicKey.
    """
    def setUp(self):
        super(TestPublicKey, self).setUp()

        # Key values taken from Sections 8.2 and 13.4 of the KMIP 1.1
        # testing documentation.
        self.bytes_1024 = (
            b'\x30\x81\x9F\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01'
            b'\x05\x00\x03\x81\x8D\x00\x30\x81\x89\x02\x81\x81\x00\x93\x04\x51'
            b'\xC9\xEC\xD9\x4F\x5B\xB9\xDA\x17\xDD\x09\x38\x1B\xD2\x3B\xE4\x3E'
            b'\xCA\x8C\x75\x39\xF3\x01\xFC\x8A\x8C\xD5\xD5\x27\x4C\x3E\x76\x99'
            b'\xDB\xDC\x71\x1C\x97\xA7\xAA\x91\xE2\xC5\x0A\x82\xBD\x0B\x10\x34'
            b'\xF0\xDF\x49\x3D\xEC\x16\x36\x24\x27\xE5\x8A\xCC\xE7\xF6\xCE\x0F'
            b'\x9B\xCC\x61\x7B\xBD\x8C\x90\xD0\x09\x4A\x27\x03\xBA\x0D\x09\xEB'
            b'\x19\xD1\x00\x5F\x2F\xB2\x65\x52\x6A\xAC\x75\xAF\x32\xF8\xBC\x78'
            b'\x2C\xDE\xD2\xA5\x7F\x81\x1E\x03\xEA\xF6\x7A\x94\x4D\xE5\xE7\x84'
            b'\x13\xDC\xA8\xF2\x32\xD0\x74\xE6\xDC\xEA\x4C\xEC\x9F\x02\x03\x01'
            b'\x00\x01')
        self.bytes_2048 = (
            b'\x30\x82\x01\x0A\x02\x82\x01\x01\x00\xAB\x7F\x16\x1C\x00\x42\x49'
            b'\x6C\xCD\x6C\x6D\x4D\xAD\xB9\x19\x97\x34\x35\x35\x77\x76\x00\x3A'
            b'\xCF\x54\xB7\xAF\x1E\x44\x0A\xFB\x80\xB6\x4A\x87\x55\xF8\x00\x2C'
            b'\xFE\xBA\x6B\x18\x45\x40\xA2\xD6\x60\x86\xD7\x46\x48\x34\x6D\x75'
            b'\xB8\xD7\x18\x12\xB2\x05\x38\x7C\x0F\x65\x83\xBC\x4D\x7D\xC7\xEC'
            b'\x11\x4F\x3B\x17\x6B\x79\x57\xC4\x22\xE7\xD0\x3F\xC6\x26\x7F\xA2'
            b'\xA6\xF8\x9B\x9B\xEE\x9E\x60\xA1\xD7\xC2\xD8\x33\xE5\xA5\xF4\xBB'
            b'\x0B\x14\x34\xF4\xE7\x95\xA4\x11\x00\xF8\xAA\x21\x49\x00\xDF\x8B'
            b'\x65\x08\x9F\x98\x13\x5B\x1C\x67\xB7\x01\x67\x5A\xBD\xBC\x7D\x57'
            b'\x21\xAA\xC9\xD1\x4A\x7F\x08\x1F\xCE\xC8\x0B\x64\xE8\xA0\xEC\xC8'
            b'\x29\x53\x53\xC7\x95\x32\x8A\xBF\x70\xE1\xB4\x2E\x7B\xB8\xB7\xF4'
            b'\xE8\xAC\x8C\x81\x0C\xDB\x66\xE3\xD2\x11\x26\xEB\xA8\xDA\x7D\x0C'
            b'\xA3\x41\x42\xCB\x76\xF9\x1F\x01\x3D\xA8\x09\xE9\xC1\xB7\xAE\x64'
            b'\xC5\x41\x30\xFB\xC2\x1D\x80\xE9\xC2\xCB\x06\xC5\xC8\xD7\xCC\xE8'
            b'\x94\x6A\x9A\xC9\x9B\x1C\x28\x15\xC3\x61\x2A\x29\xA8\x2D\x73\xA1'
            b'\xF9\x93\x74\xFE\x30\xE5\x49\x51\x66\x2A\x6E\xDA\x29\xC6\xFC\x41'
            b'\x13\x35\xD5\xDC\x74\x26\xB0\xF6\x05\x02\x03\x01\x00\x01')

    def tearDown(self):
        super(TestPublicKey, self).tearDown()

    def test_init(self):
        """
        Test that a PublicKey object can be instantiated.
        """
        key = objects.PublicKey(
            enums.CryptographicAlgorithm.RSA, 1024, self.bytes_1024)

        self.assertEqual(
            key.cryptographic_algorithm, enums.CryptographicAlgorithm.RSA)
        self.assertEqual(key.cryptographic_length, 1024)
        self.assertEqual(key.value, self.bytes_1024)
        self.assertEqual(key.key_format_type, enums.KeyFormatType.X_509)
        self.assertEqual(key.cryptographic_usage_masks, list())
        self.assertEqual(key.names, ['Public Key'])

    def test_init_with_args(self):
        """
        Test that a PublicKey object can be instantiated with all arguments.
        """
        key = objects.PublicKey(
            enums.CryptographicAlgorithm.RSA,
            1024,
            self.bytes_1024,
            enums.KeyFormatType.X_509,
            masks=[enums.CryptographicUsageMask.ENCRYPT,
                   enums.CryptographicUsageMask.DECRYPT],
            name='Test Public Key')

        self.assertEqual(key.cryptographic_algorithm,
                         enums.CryptographicAlgorithm.RSA)
        self.assertEqual(key.cryptographic_length, 1024)
        self.assertEqual(key.value, self.bytes_1024)
        self.assertEqual(key.key_format_type, enums.KeyFormatType.X_509)
        self.assertEqual(key.cryptographic_usage_masks,
                         [enums.CryptographicUsageMask.ENCRYPT,
                          enums.CryptographicUsageMask.DECRYPT])
        self.assertEqual(key.names, ['Test Public Key'])

    def test_get_object_type(self):
        """
        Test that the object type can be retrieved from the PublicKey.
        """
        expected = enums.ObjectType.PUBLIC_KEY
        key = objects.PublicKey(
            enums.CryptographicAlgorithm.RSA, 1024, self.bytes_1024,
            enums.KeyFormatType.X_509)
        observed = key.object_type
        self.assertEqual(expected, observed)

    def test_validate_on_invalid_algorithm(self):
        """
        Test that a TypeError is raised when an invalid algorithm value is
        used to construct a PublicKey.
        """
        args = ('invalid', 1024, self.bytes_1024, enums.KeyFormatType.X_509)
        self.assertRaises(TypeError, objects.PublicKey, *args)

    def test_validate_on_invalid_length(self):
        """
        Test that a TypeError is raised when an invalid length value is used
        to construct a PublicKey.
        """
        args = (enums.CryptographicAlgorithm.RSA, 'invalid', self.bytes_1024,
                enums.KeyFormatType.X_509)
        self.assertRaises(TypeError, objects.PublicKey, *args)

    def test_validate_on_invalid_value(self):
        """
        Test that a TypeError is raised when an invalid value is used to
        construct a PublicKey.
        """
        args = (enums.CryptographicAlgorithm.RSA, 1024, 0,
                enums.KeyFormatType.X_509)
        self.assertRaises(TypeError, objects.PublicKey, *args)

    def test_validate_on_invalid_format_type(self):
        """
        Test that a TypeError is raised when an invalid format type is used to
        construct a PublicKey.
        """
        args = (enums.CryptographicAlgorithm.RSA, 1024, self.bytes_1024,
                'invalid')
        self.assertRaises(TypeError, objects.PublicKey, *args)

    def test_validate_on_invalid_format_type_value(self):
        """
        Test that a ValueError is raised when an invalid format type is used to
        construct a PublicKey.
        """
        args = (enums.CryptographicAlgorithm.RSA, 1024, self.bytes_1024,
                enums.KeyFormatType.OPAQUE)
        self.assertRaises(ValueError, objects.PublicKey, *args)

    def test_validate_on_invalid_masks(self):
        """
        Test that a TypeError is raised when an invalid masks value is used to
        construct a PublicKey.
        """
        args = (enums.CryptographicAlgorithm.RSA, 1024, self.bytes_1024,
                enums.KeyFormatType.X_509)
        kwargs = {'masks': 'invalid'}
        self.assertRaises(TypeError, objects.PublicKey, *args, **kwargs)

    def test_validate_on_invalid_mask(self):
        """
        Test that a TypeError is raised when an invalid mask value is used to
        construct a PublicKey.
        """
        args = (enums.CryptographicAlgorithm.RSA, 1024, self.bytes_1024,
                enums.KeyFormatType.X_509)
        kwargs = {'masks': ['invalid']}
        self.assertRaises(TypeError, objects.PublicKey, *args, **kwargs)

    def test_validate_on_invalid_name(self):
        """
        Test that a TypeError is raised when an invalid name value is used to
        construct a PublicKey.
        """
        args = (enums.CryptographicAlgorithm.RSA, 1024, self.bytes_1024,
                enums.KeyFormatType.X_509)
        kwargs = {'name': 0}
        self.assertRaises(TypeError, objects.PublicKey, *args, **kwargs)

    def test_repr(self):
        """
        Test that repr can be applied to a PublicKey.
        """
        key = objects.PublicKey(
            enums.CryptographicAlgorithm.RSA, 1024, self.bytes_1024,
            enums.KeyFormatType.X_509)
        args = "algorithm={0}, length={1}, value={2}, format_type={3}".format(
            enums.CryptographicAlgorithm.RSA, 1024,
            binascii.hexlify(self.bytes_1024), enums.KeyFormatType.X_509)
        expected = "PublicKey({0})".format(args)
        observed = repr(key)
        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a PublicKey.
        """
        key = objects.PublicKey(
            enums.CryptographicAlgorithm.RSA, 1024, self.bytes_1024,
            enums.KeyFormatType.X_509)
        expected = str(binascii.hexlify(self.bytes_1024))
        observed = str(key)
        self.assertEqual(expected, observed)

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        PublicKey objects with the same data.
        """
        a = objects.PublicKey(
            enums.CryptographicAlgorithm.RSA, 1024, self.bytes_1024,
            enums.KeyFormatType.X_509)
        b = objects.PublicKey(
            enums.CryptographicAlgorithm.RSA, 1024, self.bytes_1024,
            enums.KeyFormatType.X_509)
        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_algorithm(self):
        """
        Test that the equality operator returns False when comparing two
        PublicKey objects with different data.
        """
        a = objects.PublicKey(
            enums.CryptographicAlgorithm.RSA, 1024, self.bytes_1024,
            enums.KeyFormatType.X_509)
        b = objects.PublicKey(
            enums.CryptographicAlgorithm.AES, 1024, self.bytes_1024,
            enums.KeyFormatType.X_509)
        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_length(self):
        """
        Test that the equality operator returns False when comparing two
        PublicKey objects with different data.
        """
        a = objects.PublicKey(
            enums.CryptographicAlgorithm.RSA, 1024, self.bytes_1024,
            enums.KeyFormatType.X_509)
        b = objects.PublicKey(
            enums.CryptographicAlgorithm.RSA, 2048, self.bytes_1024,
            enums.KeyFormatType.X_509)
        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_value(self):
        """
        Test that the equality operator returns False when comparing two
        PublicKey objects with different data.
        """
        a = objects.PublicKey(
            enums.CryptographicAlgorithm.RSA, 1024, self.bytes_1024,
            enums.KeyFormatType.X_509)
        b = objects.PublicKey(
            enums.CryptographicAlgorithm.RSA, 1024, self.bytes_2048,
            enums.KeyFormatType.X_509)
        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_format_type(self):
        """
        Test that the equality operator returns False when comparing two
        PublicKey objects with different data.
        """
        a = objects.PublicKey(
            enums.CryptographicAlgorithm.RSA, 1024, self.bytes_1024,
            enums.KeyFormatType.X_509)
        b = objects.PublicKey(
            enums.CryptographicAlgorithm.RSA, 1024, self.bytes_1024,
            enums.KeyFormatType.PKCS_1)
        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing a
        PublicKey object to a non-PublicKey object.
        """
        a = objects.PublicKey(
            enums.CryptographicAlgorithm.RSA, 1024, self.bytes_1024,
            enums.KeyFormatType.X_509)
        b = "invalid"
        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing
        two PublicKey objects with the same internal data.
        """
        a = objects.PublicKey(
            enums.CryptographicAlgorithm.RSA, 2048, self.bytes_2048,
            enums.KeyFormatType.PKCS_1)
        b = objects.PublicKey(
            enums.CryptographicAlgorithm.RSA, 2048, self.bytes_2048,
            enums.KeyFormatType.PKCS_1)
        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_algorithm(self):
        """
        Test that the equality operator returns True when comparing two
        PublicKey objects with different data.
        """
        a = objects.PublicKey(
            enums.CryptographicAlgorithm.RSA, 2048, self.bytes_2048,
            enums.KeyFormatType.PKCS_1)
        b = objects.PublicKey(
            enums.CryptographicAlgorithm.AES, 2048, self.bytes_2048,
            enums.KeyFormatType.PKCS_1)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_length(self):
        """
        Test that the equality operator returns True when comparing two
        PublicKey objects with different data.
        """
        a = objects.PublicKey(
            enums.CryptographicAlgorithm.RSA, 2048, self.bytes_2048,
            enums.KeyFormatType.PKCS_1)
        b = objects.PublicKey(
            enums.CryptographicAlgorithm.RSA, 1024, self.bytes_1024,
            enums.KeyFormatType.PKCS_1)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_value(self):
        """
        Test that the equality operator returns True when comparing two
        PublicKey objects with different data.
        """
        a = objects.PublicKey(
            enums.CryptographicAlgorithm.RSA, 2048, self.bytes_2048,
            enums.KeyFormatType.PKCS_1)
        b = objects.PublicKey(
            enums.CryptographicAlgorithm.RSA, 2048, self.bytes_1024,
            enums.KeyFormatType.PKCS_1)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_format_type(self):
        """
        Test that the equality operator returns True when comparing two
        PublicKey objects with different data.
        """
        a = objects.PublicKey(
            enums.CryptographicAlgorithm.RSA, 2048, self.bytes_2048,
            enums.KeyFormatType.PKCS_1)
        b = objects.PublicKey(
            enums.CryptographicAlgorithm.RSA, 2048, self.bytes_2048,
            enums.KeyFormatType.X_509)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns True when comparing a
        PublicKey object to a non-PublicKey object.
        """
        a = objects.PublicKey(
            enums.CryptographicAlgorithm.RSA, 2048, self.bytes_2048,
            enums.KeyFormatType.PKCS_1)
        b = "invalid"
        self.assertTrue(a != b)
        self.assertTrue(b != a)
