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
