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

    def test_X509_get_public_key(self):
        blob_pubkey = (
            b'\x30\x5C\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05'
            b'\x00\x03\x4B\x00\x30\x48\x02\x41\x00\x91\xFA\xEC\x70\xC7\x04\x6F'
            b'\xF2\x63\xA2\xB6\x12\x90\x02\x89\x95\x13\x81\x7C\xC0\xCC\xE3\x7D'
            b'\x30\xF7\xDD\xF2\x34\x44\x9F\xBD\x03\xB9\x92\x01\xCD\x9A\x08\x26'
            b'\x51\xAC\x84\xEA\x88\x25\x51\x04\xCB\xBE\xCC\xD6\xFB\x1A\x4D\xD9'
            b'\xFB\x1C\xCF\x21\x3F\xED\xEE\xCC\xE7\x02\x03\x01\x00\x01')
        blob_cert = (
            b'\x30\x82\x01\xDD\x30\x82\x01\x87\xA0\x03\x02\x01\x02\x02\x09\x00'
            b'\xE7\x14\xF1\x22\x0A\x07\x85\x15\x30\x0D\x06\x09\x2A\x86\x48\x86'
            b'\xF7\x0D\x01\x01\x0B\x05\x00\x30\x4A\x31\x0D\x30\x0B\x06\x03\x55'
            b'\x04\x0A\x0C\x04\x4B\x4D\x49\x50\x31\x16\x30\x14\x06\x03\x55\x04'
            b'\x0B\x0C\x0D\x43\x72\x79\x70\x74\x6F\x20\x45\x6E\x67\x69\x6E\x65'
            b'\x31\x21\x30\x1F\x06\x03\x55\x04\x03\x0C\x18\x54\x65\x73\x74\x20'
            b'\x58\x35\x30\x39\x5F\x67\x65\x74\x5F\x70\x75\x62\x6C\x69\x63\x5F'
            b'\x6B\x65\x79\x30\x1E\x17\x0D\x31\x36\x30\x35\x31\x38\x30\x36\x35'
            b'\x31\x34\x36\x5A\x17\x0D\x31\x38\x30\x35\x30\x38\x30\x36\x35\x31'
            b'\x34\x36\x5A\x30\x4A\x31\x0D\x30\x0B\x06\x03\x55\x04\x0A\x0C\x04'
            b'\x4B\x4D\x49\x50\x31\x16\x30\x14\x06\x03\x55\x04\x0B\x0C\x0D\x43'
            b'\x72\x79\x70\x74\x6F\x20\x45\x6E\x67\x69\x6E\x65\x31\x21\x30\x1F'
            b'\x06\x03\x55\x04\x03\x0C\x18\x54\x65\x73\x74\x20\x58\x35\x30\x39'
            b'\x5F\x67\x65\x74\x5F\x70\x75\x62\x6C\x69\x63\x5F\x6B\x65\x79\x30'
            b'\x5C\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00'
            b'\x03\x4B\x00\x30\x48\x02\x41\x00\x91\xFA\xEC\x70\xC7\x04\x6F\xF2'
            b'\x63\xA2\xB6\x12\x90\x02\x89\x95\x13\x81\x7C\xC0\xCC\xE3\x7D\x30'
            b'\xF7\xDD\xF2\x34\x44\x9F\xBD\x03\xB9\x92\x01\xCD\x9A\x08\x26\x51'
            b'\xAC\x84\xEA\x88\x25\x51\x04\xCB\xBE\xCC\xD6\xFB\x1A\x4D\xD9\xFB'
            b'\x1C\xCF\x21\x3F\xED\xEE\xCC\xE7\x02\x03\x01\x00\x01\xA3\x50\x30'
            b'\x4E\x30\x1D\x06\x03\x55\x1D\x0E\x04\x16\x04\x14\x43\xE1\x07\xF3'
            b'\xB0\x58\x48\x1B\x18\x45\x2A\x86\x23\x14\x92\x19\x8C\xA8\x2C\xB7'
            b'\x30\x1F\x06\x03\x55\x1D\x23\x04\x18\x30\x16\x80\x14\x43\xE1\x07'
            b'\xF3\xB0\x58\x48\x1B\x18\x45\x2A\x86\x23\x14\x92\x19\x8C\xA8\x2C'
            b'\xB7\x30\x0C\x06\x03\x55\x1D\x13\x04\x05\x30\x03\x01\x01\xFF\x30'
            b'\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0B\x05\x00\x03\x41'
            b'\x00\x6F\xDD\xAE\x28\x2F\x65\x09\x7B\xE7\xD8\xA7\x00\x18\x14\xEB'
            b'\x9A\xE7\x14\xEA\xE9\x45\x2A\x8F\xF6\xCB\x6F\xDC\x2C\x17\x20\x7C'
            b'\xF8\x49\x12\x83\x91\xEA\x57\xAC\x8C\x2A\x3A\xF3\xCC\xB2\x39\xB2'
            b'\x3B\x22\x17\x80\xFB\x55\x6E\x44\xB0\x89\x45\x12\xAF\xEE\xB2\x2F'
            b'\xD6'
        )

        engine = crypto.CryptographyEngine()

        pubkey_from_cert = engine.X509_get_public_key(blob_cert)
        self.assertEqual(blob_pubkey, pubkey_from_cert)
