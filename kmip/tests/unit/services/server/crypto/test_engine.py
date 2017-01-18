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
from kmip.core import exceptions
from kmip.services.server import crypto


class TestCryptographyEngine(testtools.TestCase):
    """
    Test suite for the CryptographyEngine.
    """

    def setUp(self):
        super(TestCryptographyEngine, self).setUp()

    def tearDown(self):
        super(TestCryptographyEngine, self).tearDown()

    def test_init(self):
        """
        Test that a CryptographyEngine can be constructed.
        """
        crypto.CryptographyEngine()

    def test_create_symmetric_key(self):
        """
        Test that a symmetric key can be created with valid arguments.
        """
        engine = crypto.CryptographyEngine()
        key = engine.create_symmetric_key(
            enums.CryptographicAlgorithm.AES,
            256
        )

        self.assertIn('value', key)
        self.assertIn('format', key)
        self.assertEqual(enums.KeyFormatType.RAW, key.get('format'))

    def test_create_symmetric_key_with_invalid_algorithm(self):
        """
        Test that an InvalidField error is raised when creating a symmetric
        key with an invalid algorithm.
        """
        engine = crypto.CryptographyEngine()

        args = ['invalid', 256]
        self.assertRaises(
            exceptions.InvalidField,
            engine.create_symmetric_key,
            *args
        )

    def test_create_symmetric_key_with_invalid_length(self):
        """
        Test that an InvalidField error is raised when creating a symmetric
        key with an invalid length.
        """
        engine = crypto.CryptographyEngine()

        args = [enums.CryptographicAlgorithm.AES, 'invalid']
        self.assertRaises(
            exceptions.InvalidField,
            engine.create_symmetric_key,
            *args
        )

    def test_create_symmetric_key_with_cryptographic_failure(self):
        """
        Test that a CryptographicFailure error is raised when the symmetric
        key generation process fails.
        """
        # Create a dummy algorithm that always fails on instantiation.
        class DummyAlgorithm(object):
            key_sizes = [0]

            def __init__(self, key_bytes):
                raise Exception()

        engine = crypto.CryptographyEngine()
        engine._symmetric_key_algorithms.update([(
            enums.CryptographicAlgorithm.AES,
            DummyAlgorithm
        )])

        args = [enums.CryptographicAlgorithm.AES, 0]
        self.assertRaises(
            exceptions.CryptographicFailure,
            engine.create_symmetric_key,
            *args
        )

    def test_create_asymmetric_key(self):
        """
        Test that an asymmetric key pair can be created with valid arguments.
        """
        engine = crypto.CryptographyEngine()
        public_key, private_key = engine.create_asymmetric_key_pair(
            enums.CryptographicAlgorithm.RSA,
            2048
        )

        self.assertIn('value', public_key)
        self.assertIn('format', public_key)
        self.assertIn('value', private_key)
        self.assertIn('format', private_key)

    def test_create_asymmetric_key_with_invalid_algorithm(self):
        """
        Test that an InvalidField error is raised when creating an asymmetric
        key pair with an invalid algorithm.
        """
        engine = crypto.CryptographyEngine()

        args = ['invalid', 2048]
        self.assertRaises(
            exceptions.InvalidField,
            engine.create_asymmetric_key_pair,
            *args
        )

    def test_create_asymmetric_key_with_invalid_length(self):
        """
        Test that an CryptographicFailure error is raised when creating an
        asymmetric key pair with an invalid length.
        """
        engine = crypto.CryptographyEngine()

        args = [enums.CryptographicAlgorithm.RSA, 0]
        self.assertRaises(
            exceptions.CryptographicFailure,
            engine.create_asymmetric_key_pair,
            *args
        )

    def test_mac(self):
        """
        Test that MAC operation can be done with valid arguments.
        """
        key1 = (b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                b'\x00\x00\x00\x00')
        key2 = (b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                b'\x00\x00\x00\x00')
        key3 = key1
        data = (b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B'
                b'\x0C\x0D\x0E\x0F')

        engine = crypto.CryptographyEngine()

        # test cmac
        mac_data1 = engine.mac(
            enums.CryptographicAlgorithm.AES,
            key1,
            data
        )
        mac_data2 = engine.mac(
            enums.CryptographicAlgorithm.AES,
            key2,
            data
        )
        mac_data3 = engine.mac(
            enums.CryptographicAlgorithm.AES,
            key3,
            data
        )
        self.assertNotEqual(mac_data1, mac_data2)
        self.assertEqual(mac_data1, mac_data3)

        # test hmac
        mac_data1 = engine.mac(
            enums.CryptographicAlgorithm.HMAC_SHA256,
            key1,
            data
        )
        mac_data2 = engine.mac(
            enums.CryptographicAlgorithm.HMAC_SHA256,
            key2,
            data
        )
        mac_data3 = engine.mac(
            enums.CryptographicAlgorithm.HMAC_SHA256,
            key3,
            data
        )
        self.assertNotEqual(mac_data1, mac_data2)
        self.assertEqual(mac_data1, mac_data3)

    def test_mac_with_invalid_algorithm(self):
        """
        Test that an InvalidField error is raised when doing the MAC
        with an invalid algorithm.
        """
        engine = crypto.CryptographyEngine()

        key = (b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
               b'\x00\x00\x00\x00')
        data = (b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B'
                b'\x0C\x0D\x0E\x0F')
        args = ['invalid', key, data]
        self.assertRaises(
            exceptions.InvalidField,
            engine.mac,
            *args
        )

    def test_mac_with_cryptographic_failure(self):
        pass
        """
        Test that an CryptographicFailure error is raised when the MAC
        process fails.
        """

        # Create dummy algorithm that always fails on instantiation.
        class DummySymmetricKeyAlgorithm(object):
            key_sizes = [0]

            def __init__(self, key_bytes):
                raise Exception()

        class DummyHashAlgorithm(object):

            def __init__(self):
                raise Exception()

        key = (b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
               b'\x00\x00\x00\x00')
        data = (b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B'
                b'\x0C\x0D\x0E\x0F')

        engine = crypto.CryptographyEngine()

        engine._symmetric_key_algorithms.update([(
            enums.CryptographicAlgorithm.AES,
            DummySymmetricKeyAlgorithm
        )])

        args = [enums.CryptographicAlgorithm.AES, key, data]
        self.assertRaises(
            exceptions.CryptographicFailure,
            engine.mac,
            *args
        )

        engine._hash_algorithms.update([(
            enums.CryptographicAlgorithm.HMAC_SHA256,
            DummyHashAlgorithm
        )])

        args = [enums.CryptographicAlgorithm.HMAC_SHA256, key, data]
        self.assertRaises(
            exceptions.CryptographicFailure,
            engine.mac,
            *args
        )
