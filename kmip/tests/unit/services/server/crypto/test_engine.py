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

import mock
import pytest
import testtools

from cryptography.hazmat import backends
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

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
        key3 = (b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                b'\x00\x00\x00\x00')
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
        """
        Test that an CryptographicFailure error is raised when the MAC
        process fails.
        """

        # Create dummy hash algorithm that always fails on instantiation.
        class DummyHashAlgorithm(object):

            def __init__(self):
                raise Exception()

        key = (b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
               b'\x00\x00\x00\x00')
        data = (b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B'
                b'\x0C\x0D\x0E\x0F')

        engine = crypto.CryptographyEngine()

        # RC4 is not block cipher so cmac should raise exception
        args = [enums.CryptographicAlgorithm.RC4, key, data]
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

    def test_encrypt_symmetric_invalid_algorithm(self):
        """
        Test that the right errors are raised when invalid symmetric
        encryption algorithms are used.
        """
        engine = crypto.CryptographyEngine()

        args = (None, b'', b'')
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "Encryption algorithm is required.",
            engine.encrypt,
            *args
        )

        args = ('invalid', b'', b'')
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "Encryption algorithm 'invalid' is not a supported symmetric "
            "encryption algorithm.",
            engine.encrypt,
            *args
        )

    def test_encrypt_symmetric_invalid_algorithm_key(self):
        """
        Test that the right error is raised when an invalid key is used with
        a symmetric encryption algorithm.
        """
        engine = crypto.CryptographyEngine()

        args = (enums.CryptographicAlgorithm.AES, b'', b'')
        self.assertRaisesRegex(
            exceptions.CryptographicFailure,
            "Invalid key bytes for the specified encryption algorithm.",
            engine.encrypt,
            *args
        )

    def test_encrypt_symmetric_no_mode_needed(self):
        """
        Test that data can be symmetrically encrypted for certain inputs
        without a cipher mode.
        """
        engine = crypto.CryptographyEngine()

        engine.encrypt(
            enums.CryptographicAlgorithm.RC4,
            b'\x00\x01\x02\x03\x04\x05\x06\x07',
            b'\x0F\x0E\x0D\x0C\x0B\x0A\x09\x08'
        )

    def test_encrypt_symmetric_invalid_cipher_mode(self):
        """
        Test that the right errors are raised when invalid cipher modes are
        used with symmetric encryption.
        """
        engine = crypto.CryptographyEngine()

        args = (
            enums.CryptographicAlgorithm.AES,
            b'\x00\x01\x02\x03\x04\x05\x06\x07'
            b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F',
            b'\x0F\x0E\x0D\x0C\x0B\x0A\x09\x08'
            b'\x07\x06\x05\x04\x03\x02\x01\x00'
        )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "Cipher mode is required.",
            engine.encrypt,
            *args
        )

        kwargs = {'cipher_mode': 'invalid'}
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "Cipher mode 'invalid' is not a supported mode.",
            engine.encrypt,
            *args,
            **kwargs
        )

    def test_encrypt_symmetric_generate_iv(self):
        """
        Test that the initialization vector is correctly generated and
        returned for an appropriate set of symmetric encryption inputs.
        """
        engine = crypto.CryptographyEngine()

        result = engine.encrypt(
            enums.CryptographicAlgorithm.AES,
            b'\x00\x01\x02\x03\x04\x05\x06\x07'
            b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F',
            b'\x0F\x0E\x0D\x0C\x0B\x0A\x09\x08'
            b'\x07\x06\x05\x04\x03\x02\x01\x00',
            cipher_mode=enums.BlockCipherMode.CBC,
            padding_method=enums.PaddingMethod.PKCS5
        )

        self.assertIn('iv_nonce', result.keys())
        self.assertIsNotNone(result.get('iv_nonce'))

        result = engine.encrypt(
            enums.CryptographicAlgorithm.AES,
            b'\x00\x01\x02\x03\x04\x05\x06\x07'
            b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F',
            b'\x0F\x0E\x0D\x0C\x0B\x0A\x09\x08'
            b'\x07\x06\x05\x04\x03\x02\x01\x00',
            cipher_mode=enums.BlockCipherMode.CBC,
            padding_method=enums.PaddingMethod.PKCS5,
            iv_nonce=(
                b'\x00\x10\x20\x30\x40\x50\x60\x70'
                b'\x80\x90\xA0\xB0\xC0\xD0\xE0\xF0'
            )
        )

        self.assertNotIn('iv_nonce', result.keys())

    def test_encrypt_asymmetric_invalid_encryption_algorithm(self):
        """
        Test that the right error is raised when an invalid asymmetric
        encryption algorithm is specified.
        """
        engine = crypto.CryptographyEngine()

        args = ('invalid', b'', b'', None, None)
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The cryptographic algorithm 'invalid' is not supported for "
            "asymmetric encryption.",
            engine._encrypt_asymmetric,
            *args
        )

    def test_encrypt_asymmetric_invalid_hashing_algorithm(self):
        """
        Test that the right error is raised when an invalid hashing algorithm
        is specified.
        """
        engine = crypto.CryptographyEngine()

        args = (
            enums.CryptographicAlgorithm.RSA,
            b'',
            b''
        )
        kwargs = {
            'padding_method': enums.PaddingMethod.OAEP,
            'hashing_algorithm': 'invalid'
        }
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The hashing algorithm 'invalid' is not supported for asymmetric "
            "encryption.",
            engine.encrypt,
            *args,
            **kwargs
        )

    def test_encrypt_asymmetric_invalid_padding_method(self):
        """
        Test that the right error is raised when an invalid padding method
        is specified.
        """
        engine = crypto.CryptographyEngine()

        args = (
            enums.CryptographicAlgorithm.RSA,
            b'',
            b''
        )
        kwargs = {
            'padding_method': 'invalid',
            'hashing_algorithm': enums.HashingAlgorithm.SHA_1
        }
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The padding method 'invalid' is not supported for asymmetric "
            "encryption.",
            engine.encrypt,
            *args,
            **kwargs
        )

    def test_encrypt_asymmetric_invalid_public_key(self):
        """
        Test that the right error is raised when an invalid public key is
        specified.
        """
        engine = crypto.CryptographyEngine()

        args = (
            enums.CryptographicAlgorithm.RSA,
            'invalid',
            b''
        )
        kwargs = {
            'padding_method': enums.PaddingMethod.OAEP,
            'hashing_algorithm': enums.HashingAlgorithm.SHA_1
        }
        self.assertRaisesRegex(
            exceptions.CryptographicFailure,
            "The public key bytes could not be loaded.",
            engine.encrypt,
            *args,
            **kwargs
        )

    def test_decrypt_asymmetric_invalid_encryption_algorithm(self):
        """
        Test that the right error is raised when an invalid asymmetric
        decryption algorithm is specified.
        """
        engine = crypto.CryptographyEngine()

        args = ('invalid', b'', b'', None, None)
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The cryptographic algorithm 'invalid' is not supported for "
            "asymmetric decryption.",
            engine._decrypt_asymmetric,
            *args
        )

    def test_decrypt_asymmetric_invalid_hashing_algorithm(self):
        """
        Test that the right error is raised when an invalid hashing algorithm
        is specified.
        """
        engine = crypto.CryptographyEngine()

        args = (
            enums.CryptographicAlgorithm.RSA,
            b'',
            b''
        )
        kwargs = {
            'padding_method': enums.PaddingMethod.OAEP,
            'hashing_algorithm': 'invalid'
        }
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The hashing algorithm 'invalid' is not supported for asymmetric "
            "decryption.",
            engine.decrypt,
            *args,
            **kwargs
        )

    def test_decrypt_asymmetric_invalid_padding_method(self):
        """
        Test that the right error is raised when an invalid padding method
        is specified.
        """
        engine = crypto.CryptographyEngine()

        args = (
            enums.CryptographicAlgorithm.RSA,
            b'',
            b''
        )
        kwargs = {
            'padding_method': 'invalid',
            'hashing_algorithm': enums.HashingAlgorithm.SHA_1
        }
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The padding method 'invalid' is not supported for asymmetric "
            "decryption.",
            engine.decrypt,
            *args,
            **kwargs
        )

    def test_decrypt_asymmetric_invalid_private_key(self):
        """
        Test that the right error is raised when an invalid private key is
        specified.
        """
        engine = crypto.CryptographyEngine()

        args = (
            enums.CryptographicAlgorithm.RSA,
            'invalid',
            b''
        )
        kwargs = {
            'padding_method': enums.PaddingMethod.OAEP,
            'hashing_algorithm': enums.HashingAlgorithm.SHA_1
        }
        self.assertRaisesRegex(
            exceptions.CryptographicFailure,
            "The private key bytes could not be loaded.",
            engine.decrypt,
            *args,
            **kwargs
        )

    def test_decrypt_symmetric_invalid_algorithm(self):
        """
        Test that the right errors are raised when invalid symmetric decryption
        algorithms are used.
        """
        engine = crypto.CryptographyEngine()

        args = (None, b'', b'')
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "Decryption algorithm is required.",
            engine.decrypt,
            *args
        )

        args = ('invalid', b'', b'')
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "Decryption algorithm 'invalid' is not a supported symmetric "
            "decryption algorithm.",
            engine.decrypt,
            *args
        )

    def test_decrypt_symmetric_invalid_algorithm_key(self):
        """
        Test that the right error is raised when an invalid key is used with
        a symmetric decryption algorithm.
        """
        engine = crypto.CryptographyEngine()

        args = (enums.CryptographicAlgorithm.AES, b'', b'')
        self.assertRaisesRegex(
            exceptions.CryptographicFailure,
            "Invalid key bytes for the specified decryption algorithm.",
            engine.decrypt,
            *args
        )

    def test_decrypt_symmetric_invalid_cipher_mode(self):
        """
        Test that the right errors are raised when invalid cipher modes are
        used with symmetric decryption.
        """
        engine = crypto.CryptographyEngine()

        args = (
            enums.CryptographicAlgorithm.AES,
            b'\x00\x01\x02\x03\x04\x05\x06\x07'
            b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F',
            b'\x0F\x0E\x0D\x0C\x0B\x0A\x09\x08'
            b'\x07\x06\x05\x04\x03\x02\x01\x00'
        )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "Cipher mode is required.",
            engine.decrypt,
            *args
        )

        kwargs = {'cipher_mode': 'invalid'}
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "Cipher mode 'invalid' is not a supported mode.",
            engine.decrypt,
            *args,
            **kwargs
        )

    def test_decrypt_symmetric_missing_iv_nonce(self):
        """
        Test that the right error is raised when an IV/nonce is not provided
        for the symmetric decryption algorithm.
        """
        engine = crypto.CryptographyEngine()

        args = (
            enums.CryptographicAlgorithm.AES,
            b'\x00\x01\x02\x03\x04\x05\x06\x07'
            b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F',
            b'\x0F\x0E\x0D\x0C\x0B\x0A\x09\x08'
            b'\x07\x06\x05\x04\x03\x02\x01\x00'
        )
        kwargs = {
            'cipher_mode': enums.BlockCipherMode.CBC,
            'padding_method': enums.PaddingMethod.PKCS5
        }
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "IV/nonce is required.",
            engine.decrypt,
            *args,
            **kwargs
        )

    def test_handle_symmetric_padding_invalid(self):
        """
        Test that the right errors are raised when invalid padding methods
        are used.
        """
        engine = crypto.CryptographyEngine()

        args = (
            algorithms.AES,
            b'\x01\x02\x03\x04',
            None
        )

        self.assertRaisesRegex(
            exceptions.InvalidField,
            "Padding method is required.",
            engine._handle_symmetric_padding,
            *args
        )

        args = (
            algorithms.AES,
            b'\x01\x02\x03\x04',
            'invalid'
        )

        self.assertRaisesRegex(
            exceptions.InvalidField,
            "Padding method 'invalid' is not supported.",
            engine._handle_symmetric_padding,
            *args
        )

    def test_derive_key_missing_hash_algorithm(self):
        """
        Test that the right error is raised when the hash algorithm is not
        provided for key derivation.
        """
        engine = crypto.CryptographyEngine()

        args = (
            enums.DerivationMethod.HASH,
            16
        )

        self.assertRaisesRegex(
            exceptions.InvalidField,
            "Hash algorithm is required.",
            engine.derive_key,
            *args
        )

    def test_derive_key_invalid_hash_algorithm(self):
        """
        Test that the right error is raised when an invalid hash algorithm is
        provided for key derivation.
        """
        engine = crypto.CryptographyEngine()

        args = (
            enums.DerivationMethod.HASH,
            16
        )
        kwargs = {
            'hash_algorithm': 'invalid'
        }

        self.assertRaisesRegex(
            exceptions.InvalidField,
            "Hash algorithm 'invalid' is not a supported hashing algorithm.",
            engine.derive_key,
            *args,
            **kwargs
        )

    def test_derive_key_both_derivation_data_and_key_material(self):
        """
        Test that the right error is raised when both derivation data and key
        material are provided for hash-based key derivation.
        """
        engine = crypto.CryptographyEngine()

        args = (
            enums.DerivationMethod.HASH,
            16
        )
        kwargs = {
            'hash_algorithm': enums.HashingAlgorithm.SHA_256,
            'derivation_data': b'\x01\x02\x03\x04',
            'key_material': b'\x0A\x0B\x0C\x0D'
        }

        self.assertRaisesRegex(
            exceptions.InvalidField,
            "For hash-based key derivation, specify only derivation data or "
            "key material, not both.",
            engine.derive_key,
            *args,
            **kwargs
        )

    def test_derive_key_missing_derivation_data_and_key_material(self):
        """
        Test that the right error is raised when neither derivation data nor
        key material are provided for hash-based key derivation.
        """
        engine = crypto.CryptographyEngine()

        args = (
            enums.DerivationMethod.HASH,
            16
        )
        kwargs = {
            'hash_algorithm': enums.HashingAlgorithm.SHA_256
        }

        self.assertRaisesRegex(
            exceptions.InvalidField,
            "For hash-based key derivation, derivation data or key material "
            "must be specified.",
            engine.derive_key,
            *args,
            **kwargs
        )

    def test_derive_key_missing_salt(self):
        """
        Test that the right error is raised when the salt is not provided for
        PBKDF2-based key derivation.
        """
        engine = crypto.CryptographyEngine()

        args = (
            enums.DerivationMethod.PBKDF2,
            16
        )
        kwargs = {
            'hash_algorithm': enums.HashingAlgorithm.SHA_256
        }

        self.assertRaisesRegex(
            exceptions.InvalidField,
            "For PBKDF2 key derivation, salt must be specified.",
            engine.derive_key,
            *args,
            **kwargs
        )

    def test_derive_key_missing_iteration_count(self):
        """
        Test that the right error is raised when the iteration count is not
        provided for PBKDF2-based key derivation.
        """
        engine = crypto.CryptographyEngine()

        args = (
            enums.DerivationMethod.PBKDF2,
            16
        )
        kwargs = {
            'hash_algorithm': enums.HashingAlgorithm.SHA_256,
            'salt': b'\x11\x22\x33\x44'
        }

        self.assertRaisesRegex(
            exceptions.InvalidField,
            "For PBKDF2 key derivation, iteration count must be specified.",
            engine.derive_key,
            *args,
            **kwargs
        )

    def test_derive_key_invalid_derivation_method(self):
        """
        Test that the right error is raised when an invalid derivation method
        is specified for key derivation.
        """
        engine = crypto.CryptographyEngine()

        args = (
            'invalid',
            16
        )
        kwargs = {
            'hash_algorithm': enums.HashingAlgorithm.SHA_256
        }

        self.assertRaisesRegex(
            exceptions.InvalidField,
            "Derivation method 'invalid' is not a supported key derivation "
            "method.",
            engine.derive_key,
            *args,
            **kwargs
        )

    def test_wrap_key_invalid_wrapping_method(self):
        """
        Test that the right error is raised when an invalid wrapping method
        is specified for key wrapping.
        """
        engine = crypto.CryptographyEngine()

        args = (b'', 'invalid', enums.BlockCipherMode.NIST_KEY_WRAP, b'')
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "Wrapping method 'invalid' is not a supported key wrapping "
            "method.",
            engine.wrap_key,
            *args
        )

    def test_wrap_key_invalid_encryption_algorithm(self):
        """
        Test that the right error is raised when an invalid encryption
        algorithm is specified for encryption-based key wrapping.
        """
        engine = crypto.CryptographyEngine()

        args = (b'', enums.WrappingMethod.ENCRYPT, 'invalid', b'')
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "Encryption algorithm 'invalid' is not a supported key wrapping "
            "algorithm.",
            engine.wrap_key,
            *args
        )

    def test_wrap_key_cryptographic_error(self):
        """
        Test that the right error is raised when an error occurs during the
        key wrapping process.
        """
        engine = crypto.CryptographyEngine()

        args = (
            b'',
            enums.WrappingMethod.ENCRYPT,
            enums.BlockCipherMode.NIST_KEY_WRAP,
            b''
        )
        self.assertRaises(
            exceptions.CryptographicFailure,
            engine.wrap_key,
            *args
        )

    def test_sign_no_alg(self):
        """
        Test that an InvalidField exception is raised when sign is
        called without sufficient crypto parameters.
        """
        engine = crypto.CryptographyEngine()

        args = (None, None, None, None, None, None)
        self.assertRaisesRegex(
            exceptions.InvalidField,
            'For signing, either a digital signature algorithm or a hash'
            ' algorithm and a cryptographic algorithm must be specified.',
            engine.sign,
            *args
        )

    def test_sign_non_RSA(self):
        """
        Test that an InvalidField exception is raised when sign is
        called with a crypto algorithm other than RSA.
        """
        engine = crypto.CryptographyEngine()

        args = (
            None,
            enums.CryptographicAlgorithm.TRIPLE_DES,
            enums.HashingAlgorithm.MD5,
            None,
            None,
            None
        )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            'For signing, an RSA key must be used.',
            engine.sign,
            *args
        )

    def test_sign_invalid_padding(self):
        """
        Test that an InvalidField exception is raised when sign is
        called with an unsupported padding algorithm.
        """
        engine = crypto.CryptographyEngine()

        args = (
            None,
            enums.CryptographicAlgorithm.RSA,
            enums.HashingAlgorithm.MD5,
            enums.PaddingMethod.OAEP,
            DER_RSA_KEY,
            None
        )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "Padding method 'PaddingMethod.OAEP' is not a supported"
            " signature padding method.",
            engine.sign,
            *args
        )

    def test_sign_no_padding(self):
        """
        Test that an InvalidField exception is raised when sign is
        called without a padding algorithm.
        """
        engine = crypto.CryptographyEngine()

        args = (
            None,
            enums.CryptographicAlgorithm.RSA,
            enums.HashingAlgorithm.MD5,
            None,
            DER_RSA_KEY,
            None
        )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            'For signing, a padding method must be specified.',
            engine.sign,
            *args
        )

    def test_sign_invalid_key_bytes(self):
        """
        Test that an InvalidField exception is raised when
        sign is called with invalid key bytes.
        """
        engine = crypto.CryptographyEngine()

        args = (
            None,
            enums.CryptographicAlgorithm.RSA,
            enums.HashingAlgorithm.MD5,
            enums.PaddingMethod.PKCS1v15,
            'thisisnotavalidkey',
            None
        )

        self.assertRaisesRegex(
            exceptions.InvalidField,
            'Unable to deserialize key '
            'bytes, unknown format.',
            engine.sign,
            *args
        )

    def test_verify_signature_mismatching_signing_algorithms(self):
        """
        Test that the right error is raised when both the signing algorithm
        and the digital signature algorithm are provided and do not match.
        """
        engine = crypto.CryptographyEngine()

        args = (
            b'',
            b'',
            b'',
            enums.PaddingMethod.PSS
        )
        kwargs = {
            'signing_algorithm': enums.CryptographicAlgorithm.ECDSA,
            'hashing_algorithm': enums.HashingAlgorithm.SHA_1,
            'digital_signature_algorithm':
                enums.DigitalSignatureAlgorithm.SHA1_WITH_RSA_ENCRYPTION
        }
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The signing algorithm does not match the digital signature "
            "algorithm.",
            engine.verify_signature,
            *args,
            **kwargs
        )

    def test_verify_signature_mismatching_hashing_algorithms(self):
        """
        Test that the right error is raised when both the hashing algorithm
        and the digital signature algorithm are provided and do not match.
        """
        engine = crypto.CryptographyEngine()

        args = (
            b'',
            b'',
            b'',
            enums.PaddingMethod.PSS
        )
        kwargs = {
            'signing_algorithm': enums.CryptographicAlgorithm.RSA,
            'hashing_algorithm': enums.HashingAlgorithm.SHA_256,
            'digital_signature_algorithm':
                enums.DigitalSignatureAlgorithm.SHA1_WITH_RSA_ENCRYPTION
        }
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The hashing algorithm does not match the digital signature "
            "algorithm.",
            engine.verify_signature,
            *args,
            **kwargs
        )

    def test_verify_signature_pss_missing_hashing_algorithm(self):
        """
        Test that the right error is raised when PSS padding is used and no
        hashing algorithm is provided.
        """
        engine = crypto.CryptographyEngine()

        args = (
            b'',
            b'',
            b'',
            enums.PaddingMethod.PSS
        )
        kwargs = {
            'signing_algorithm': enums.CryptographicAlgorithm.RSA,
            'hashing_algorithm': None,
            'digital_signature_algorithm': None
        }
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "A hashing algorithm must be specified for PSS padding.",
            engine.verify_signature,
            *args,
            **kwargs
        )

    def test_verify_signature_invalid_padding_method(self):
        """
        Test that the right error is raised when an invalid padding method is
        used.
        """
        engine = crypto.CryptographyEngine()

        args = (
            b'',
            b'',
            b'',
            'invalid'
        )
        kwargs = {
            'signing_algorithm': enums.CryptographicAlgorithm.RSA,
            'hashing_algorithm': enums.HashingAlgorithm.SHA_1,
            'digital_signature_algorithm': None
        }
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The padding method 'invalid' is not supported for signature "
            "verification.",
            engine.verify_signature,
            *args,
            **kwargs
        )

    def test_verify_signature_invalid_signing_key(self):
        """
        Test that the right error is raised when an invalid signing key is
        used.
        """
        engine = crypto.CryptographyEngine()

        args = (
            'invalid',
            b'',
            b'',
            enums.PaddingMethod.PSS
        )
        kwargs = {
            'signing_algorithm': enums.CryptographicAlgorithm.RSA,
            'hashing_algorithm': enums.HashingAlgorithm.SHA_1,
            'digital_signature_algorithm': None
        }
        self.assertRaisesRegex(
            exceptions.CryptographicFailure,
            "The signing key bytes could not be loaded.",
            engine.verify_signature,
            *args,
            **kwargs
        )

    def test_verify_signature_invalid_signature(self):
        """
        Test that verifying an invalid signature returns the right value.
        """
        engine = crypto.CryptographyEngine()

        backend = backends.default_backend()
        public_key_numbers = rsa.RSAPublicNumbers(
            int('010001', 16),
            int(
                'ac13d9fdae7b7335b69cd98567e9647d99bf373a9e05ce3435d66465f328'
                'b7f7334b792aee7efa044ebc4c7a30b21a5d7a89cdb3a30dfcd9fee9995e'
                '09415edc0bf9e5b4c3f74ff53fb4d29441bf1b7ed6cbdd4a47f9252269e1'
                '646f6c1aee0514e93f6cb9df71d06c060a2104b47b7260ac37c106861dc7'
                '8ca5a25faa9cb2e3',
                16)
        )
        public_key = public_key_numbers.public_key(backend)
        public_bytes = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.PKCS1
        )

        args = (
            public_bytes,
            b'',
            b'',
            enums.PaddingMethod.PSS
        )
        kwargs = {
            'signing_algorithm': enums.CryptographicAlgorithm.RSA,
            'hashing_algorithm': enums.HashingAlgorithm.SHA_1,
            'digital_signature_algorithm': None
        }
        self.assertFalse(
            engine.verify_signature(*args, **kwargs)
        )

    def test_verify_signature_unexpected_verification_error(self):
        """
        Test that the right error is raised when an unexpected error occurs
        during signature verification.
        """
        engine = crypto.CryptographyEngine()

        backend = backends.default_backend()
        public_key_numbers = rsa.RSAPublicNumbers(
            int('010001', 16),
            int(
                'ac13d9fdae7b7335b69cd98567e9647d99bf373a9e05ce3435d66465f328'
                'b7f7334b792aee7efa044ebc4c7a30b21a5d7a89cdb3a30dfcd9fee9995e'
                '09415edc0bf9e5b4c3f74ff53fb4d29441bf1b7ed6cbdd4a47f9252269e1'
                '646f6c1aee0514e93f6cb9df71d06c060a2104b47b7260ac37c106861dc7'
                '8ca5a25faa9cb2e3',
                16)
        )
        public_key = public_key_numbers.public_key(backend)
        public_bytes = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.PKCS1
        )

        args = (
            public_bytes,
            b'',
            b'',
            enums.PaddingMethod.PKCS1v15
        )
        kwargs = {
            'signing_algorithm': enums.CryptographicAlgorithm.RSA,
            'hashing_algorithm': None,
            'digital_signature_algorithm': None
        }
        self.assertRaisesRegex(
            exceptions.CryptographicFailure,
            "The signature verification process failed.",
            engine.verify_signature,
            *args,
            **kwargs
        )

    def test_verify_signature_invalid_signing_algorithm(self):
        """
        Test that the right error is raised when an invalid signing algorithm
        is used.
        """
        engine = crypto.CryptographyEngine()

        args = (
            b'',
            b'',
            b'',
            enums.PaddingMethod.PSS
        )
        kwargs = {
            'signing_algorithm': 'invalid',
            'hashing_algorithm': enums.HashingAlgorithm.SHA_1,
            'digital_signature_algorithm': None
        }
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The signing algorithm 'invalid' is not supported for signature "
            "verification.",
            engine.verify_signature,
            *args,
            **kwargs
        )


# TODO(peter-hamilton): Replace this with actual fixture files from NIST CAPV.
# Most of these test vectors were obtained from the pyca/cryptography test
# suite.
# GCM test vectors were obtained from the NIST CAVP test suite:
#
# https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip
@pytest.fixture(
    scope='function',
    params=[
        {'algorithm': enums.CryptographicAlgorithm.TRIPLE_DES,
         'cipher_mode': enums.BlockCipherMode.ECB,
         'key': (
            b'\x01\x01\x01\x01\x01\x01\x01\x01'
            b'\x01\x01\x01\x01\x01\x01\x01\x01'
            b'\x01\x01\x01\x01\x01\x01\x01\x01'
         ),
         'plain_text': (
            b'\x01\x02\x03\x04\x05\x06\x07\x08'
         ),
         'cipher_text': (
            b'\xCE\xAD\x37\x3D\xB8\x0E\xAB\xF8'
         ),
         'iv_nonce': None},
        {'algorithm': enums.CryptographicAlgorithm.AES,
         'cipher_mode': enums.BlockCipherMode.ECB,
         'key': (
            b'\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00'
         ),
         'plain_text': (
            b'\xf3\x44\x81\xec\x3c\xc6\x27\xba'
            b'\xcd\x5d\xc3\xfb\x08\xf2\x73\xe6'
         ),
         'cipher_text': (
            b'\x03\x36\x76\x3e\x96\x6d\x92\x59'
            b'\x5a\x56\x7c\xc9\xce\x53\x7f\x5e'
         ),
         'iv_nonce': None},
        {'algorithm': enums.CryptographicAlgorithm.AES,
         'cipher_mode': enums.BlockCipherMode.CBC,
         'key': (
             b'\x00\x00\x00\x00\x00\x00\x00\x00'
             b'\x00\x00\x00\x00\x00\x00\x00\x00'
         ),
         'iv_nonce': (
             b'\x00\x00\x00\x00\x00\x00\x00\x00'
             b'\x00\x00\x00\x00\x00\x00\x00\x00'
         ),
         'plain_text': (
             b'\xf3\x44\x81\xec\x3c\xc6\x27\xba'
             b'\xcd\x5d\xc3\xfb\x08\xf2\x73\xe6'
         ),
         'cipher_text': (
             b'\x03\x36\x76\x3e\x96\x6d\x92\x59'
             b'\x5a\x56\x7c\xc9\xce\x53\x7f\x5e'
         )},
        {'algorithm': enums.CryptographicAlgorithm.AES,
         'cipher_mode': enums.BlockCipherMode.CBC,
         'key': (
             b'\x6e\xd7\x6d\x2d\x97\xc6\x9f\xd1'
             b'\x33\x95\x89\x52\x39\x31\xf2\xa6'
             b'\xcf\xf5\x54\xb1\x5f\x73\x8f\x21'
             b'\xec\x72\xdd\x97\xa7\x33\x09\x07'
         ),
         'iv_nonce': (
             b'\x85\x1e\x87\x64\x77\x6e\x67\x96'
             b'\xaa\xb7\x22\xdb\xb6\x44\xac\xe8'
         ),
         'plain_text': (
             b'\x62\x82\xb8\xc0\x5c\x5c\x15\x30'
             b'\xb9\x7d\x48\x16\xca\x43\x47\x62'
         ),
         'cipher_text': (
             b'\x6a\xcc\x04\x14\x2e\x10\x0a\x65'
             b'\xf5\x1b\x97\xad\xf5\x17\x2c\x41'
         )},
        {'algorithm': enums.CryptographicAlgorithm.AES,
         'cipher_mode': enums.BlockCipherMode.GCM,
         'key': (
             b'\xfe\x32\xb0\xc7\x4c\xd7\x45\x8b'
             b'\x75\xcb\x19\x6f\x48\x6b\x35\xc6'
             b'\x19\xb7\xc6\xb4\xfe\x3f\x49\x64'
             b'\xa4\x9a\xd9\x25\x37\x76\x27\xd7'
         ),
         'iv_nonce': (
             b'\x66\x30\xe6\xd4\xb9\xd9\x04\x1f'
             b'\xe2\xba\xf6\xd1\xd6\x88\x7a\x56'
             b'\x4e\xfe\xe7\x54\x90\xc2\xdd\x6f'
             b'\x5d\x3e\x7f\xb4\xc3\xac\x4d\xe9'
             b'\xfd\xa1\x69\x74\x71\xcc\x14\x80'
             b'\x3a\x03\x3f\x55\x1d\x2e\x05\x56'
             b'\x19\xd9\xb6\x84\x83\x08\xb9\xf2'
             b'\x53\x5b\x0d\x85\x43\x8f\x16\x02'
             b'\x3c\x1b\x96\x81\xb2\x62\xa5\xf3'
             b'\xd5\x43\x95\xec\xd9\x56\x3b\x88'
             b'\x10\x8b\xe8\xad\x4a\x78\xee\x2a'
             b'\x4d\xec\xe8\x88\xc4\xc3\x4c\xda'
             b'\xe6\xaf\x21\xd8\xef\xc5\xcf\x71'
             b'\x9e\xfa\x27\x04\x9b\x4a\x45\xcc'
             b'\x49\x70\xdb\xba\x37\xef\x57\x15'
             b'\xa9\x9a\x96\x44\xae\xd0\xd3\x94'
         ),
         'plain_text': (
             b'\x40\x31\x55\x40\x39\x07\x4e\x10'
             b'\x5d\xb2\x36\xdd\x8b\x7c\x81\xb6'
             b'\x7e\xc1\xd7\xa4\xed\x0d\xd5\x94'
             b'\x8e\x85\xa0\x0f\x3f\x6d\x4c\x87'
             b'\x2d\xc8\x72\xc8\x7b\x47\xc4\x5a'
             b'\xf1\x81\xf0\x39\x58\xc1\xee\xfe'
             b'\x60\x62\xff'
         ),
         'auth_additional_data': (
             b'\xd3\xc6\x2d\xa2\x77\x97\xba\x8e\x16'
             b'\x82\x1a\x1b\xe2\x47\x8a\x6f'
         ),
         'auth_tag_length': 16,
         'cipher_text': (
             b'\xfb\x10\xfa\x35\x45\x92\x53\xab'
             b'\x7a\x87\xb3\x27\x32\x63\x56\x05'
             b'\x56\xb8\x49\xba\x6b\xf1\xf5\xde'
             b'\x46\xd4\xc8\x59\xf8\xad\xa6\xca'
             b'\xca\xe4\x53\x9a\x5b\x7e\xaf\x9a'
             b'\xd1\x16\xd4\x56\xf5\x0d\x2f\x80'
             b'\xb6\x3d\xd7'
         ),
         'auth_tag': (
             b'\xbd\x9b\x6f\x23\xc9\x39\xa7\xd4'
             b'\xf5\xbe\xb0\x9d\x92\xf0\x17\x56'
         )},
        {'algorithm': enums.CryptographicAlgorithm.AES,
         'cipher_mode': enums.BlockCipherMode.GCM,
         'key': (
             b'\x2c\xd6\xfd\x85\xf1\x30\x28\x38'
             b'\x63\x53\xff\xa1\x52\x1d\x8d\x7b'
             b'\xc8\xeb\xed\x26\xb1\x6d\x94\x40'
             b'\x5f\x03\xf6\xda\x5d\xef\x2d\xa8'
         ),
         'iv_nonce': (
             b'\xba\x7a\x97\x67\x0f\xbb\x02\x62'
             b'\x24\x36\x92\x9d'
         ),
         'plain_text': (
             b'\x8b\x4f\x7e\x75\x16\x31\xe7\x65'
             b'\xdc\x13\xfa\x63\xf0\x2f\x63\x4b'
         ),
         'auth_additional_data': (
             b'\x90\xee\x7e\x56\xf9\x59\x34\x76'
             b'\x1c\x39\xab\x75\x37\x2a\xc2\xc6'
         ),
         'auth_tag_length': 8,
         'cipher_text': (
             b'\x8c\xdc\x3f\x57\x48\xb1\x59\x36'
             b'\x6c\x94\xaf\x48\xe2\xcf\xa0\x98'
         ),
         'auth_tag': (
             b'\xfe\xb3\x8e\x85\x4e\xdf\x4d\x79'
         )},
        {'algorithm': enums.CryptographicAlgorithm.BLOWFISH,
         'cipher_mode': enums.BlockCipherMode.OFB,
         'key': (
             b'\x01\x23\x45\x67\x89\xAB\xCD\xEF'
             b'\xF0\xE1\xD2\xC3\xB4\xA5\x96\x87'
         ),
         'iv_nonce': b'\xFE\xDC\xBA\x98\x76\x54\x32\x10',
         'plain_text': (
             b'\x37\x36\x35\x34\x33\x32\x31\x20'
             b'\x4E\x6F\x77\x20\x69\x73\x20\x74'
             b'\x68\x65\x20\x74\x69\x6D\x65\x20'
             b'\x66\x6F\x72\x20\x00'
         ),
         'cipher_text': (
             b'\xE7\x32\x14\xA2\x82\x21\x39\xCA'
             b'\x62\xB3\x43\xCC\x5B\x65\x58\x73'
             b'\x10\xDD\x90\x8D\x0C\x24\x1B\x22'
             b'\x63\xC2\xCF\x80\xDA'
         )},
        {'algorithm': enums.CryptographicAlgorithm.CAST5,
         'cipher_mode': enums.BlockCipherMode.CFB,
         'key': (
             b'\xb9\xba\x9f\xa3\x2c\xc4\x91\xd8'
             b'\xac\x2b\xeb\x5f\x99\x19\x3d\x57'
         ),
         'iv_nonce': b'\x95\x51\x14\x52\xb7\x1e\x53\xe9',
         'plain_text': (
             b'\xb4\x03\x82\x70\x5a\xae\xea\x41'
             b'\x09\x7c\x30\x9d\xa6\xcd\x06\x01'
             b'\x0f\x15\xe0\x9c\x01\x30\xfa\x4b'
             b'\x3a\xf6\x9c\xc8\xda\x10\x9d\x1f'
             b'\x0f\x0a\x26\x61\xf1\xa8\xb8\x9b'
             b'\xab\x7e\x70\x09\xdc\xbb\x8a\x88'
             b'\x3d\x46\x25\x4a\x83\x0c\x45\xcd'
             b'\x87\x98\x1e\x0e\xa4\xe4\x90\xfa'
         ),
         'cipher_text': (
             b'\x67\x74\xad\xe6\x98\x43\x92\xea'
             b'\xf6\x70\xdc\x2f\x8c\x23\x97\xe8'
             b'\x7a\xf5\xc8\x50\x32\x53\x76\xd9'
             b'\x23\x0c\xf6\x22\xd7\xf0\xa0\xfd'
             b'\x0a\x4a\x0c\x68\x56\x5c\x9e\xfd'
             b'\xaf\x58\xc2\xae\xc1\x8e\x35\x2a'
             b'\x31\x5a\x0f\x9c\xa6\xbe\xeb\x8e'
             b'\x1b\xf4\xdf\xb6\x73\x76\x8f\x0e'
         )},
        {'algorithm': enums.CryptographicAlgorithm.CAMELLIA,
         'cipher_mode': enums.BlockCipherMode.OFB,
         'key': (
             b'\x2B\x7E\x15\x16\x28\xAE\xD2\xA6'
             b'\xAB\xF7\x15\x88\x09\xCF\x4F\x3C'
         ),
         'iv_nonce': (
             b'\x00\x01\x02\x03\x04\x05\x06\x07'
             b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
         ),
         'plain_text': (
             b'\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96'
             b'\xE9\x3D\x7E\x11\x73\x93\x17\x2A'
         ),
         'cipher_text': (
             b'\x14\xF7\x64\x61\x87\x81\x7E\xB5'
             b'\x86\x59\x91\x46\xB8\x2B\xD7\x19'
         )},
        {'algorithm': enums.CryptographicAlgorithm.RC4,
         'cipher_mode': None,
         'key': (
             b'\x01\x02\x03\x04\x05\x06\x07\x08'
             b'\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10'
             b'\x11\x12\x13\x14\x15\x16\x17\x18'
             b'\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20'
         ),
         'iv_nonce': None,
         'plain_text': (
             b'\x00\x00\x00\x00\x00\x00\x00\x00'
             b'\x00\x00\x00\x00\x00\x00\x00\x00'
         ),
         'cipher_text': (
             b'\xea\xa6\xbd\x25\x88\x0b\xf9\x3d'
             b'\x3f\x5d\x1e\x4c\xa2\x61\x1d\x91'
         )},
        {'algorithm': enums.CryptographicAlgorithm.TRIPLE_DES,
         'cipher_mode': enums.BlockCipherMode.ECB,
         'key': b'\x01\x01\x01\x01\x01\x01\x01\x01',
         'plain_text': b'\x80\x00\x00\x00\x00\x00\x00\x00',
         'cipher_text': b'\x95\xF8\xA5\xE5\xDD\x31\xD9\x00',
         'iv_nonce': None}
    ]
)
def symmetric_parameters(request):
    return request.param


def test_encrypt_symmetric(symmetric_parameters):
    """
    Test that various encryption algorithms and block cipher modes can be
    used to correctly symmetrically encrypt data.
    """

    engine = crypto.CryptographyEngine()

    engine._handle_symmetric_padding = mock.MagicMock(
        return_value=symmetric_parameters.get('plain_text')
    )

    result = engine.encrypt(
        symmetric_parameters.get('algorithm'),
        symmetric_parameters.get('key'),
        symmetric_parameters.get('plain_text'),
        cipher_mode=symmetric_parameters.get('cipher_mode'),
        iv_nonce=symmetric_parameters.get('iv_nonce'),
        auth_additional_data=symmetric_parameters.get('auth_additional_data'),
        auth_tag_length=symmetric_parameters.get('auth_tag_length')
    )

    if engine._handle_symmetric_padding.called:
        engine._handle_symmetric_padding.assert_called_once_with(
            engine._symmetric_key_algorithms.get(
                symmetric_parameters.get('algorithm')
            ),
            symmetric_parameters.get('plain_text'),
            None
        )

    assert symmetric_parameters.get('cipher_text') == result.get('cipher_text')
    assert symmetric_parameters.get('auth_tag') == result.get('auth_tag')


def test_decrypt_symmetric(symmetric_parameters):
    """
    Test that various decryption algorithms and block cipher modes can be
    used to correctly symmetrically decrypt data.
    """
    engine = crypto.CryptographyEngine()

    engine._handle_symmetric_padding = mock.MagicMock(
        return_value=symmetric_parameters.get('plain_text')
    )

    result = engine.decrypt(
        symmetric_parameters.get('algorithm'),
        symmetric_parameters.get('key'),
        symmetric_parameters.get('cipher_text'),
        cipher_mode=symmetric_parameters.get('cipher_mode'),
        iv_nonce=symmetric_parameters.get('iv_nonce'),
        auth_additional_data=symmetric_parameters.get('auth_additional_data'),
        auth_tag=symmetric_parameters.get('auth_tag')
    )

    if engine._handle_symmetric_padding.called:
        engine._handle_symmetric_padding.assert_called_once_with(
            engine._symmetric_key_algorithms.get(
                symmetric_parameters.get('algorithm')
            ),
            symmetric_parameters.get('plain_text'),
            None,
            undo_padding=True
        )

    assert symmetric_parameters.get('plain_text') == result


# Most of these test vectors were obtained from the pyca/cryptography test
# suite:
#
# cryptography_vectors/asymmetric/RSA/pkcs-1v2-1d2-vec/oaep-vect.txt
# cryptography_vectors/asymmetric/RSA/pkcs1v15crypt-vectors.txt
@pytest.fixture(
    scope='function',
    params=[
        {'algorithm': enums.CryptographicAlgorithm.RSA,
         'padding_method': enums.PaddingMethod.OAEP,
         'hashing_algorithm': enums.HashingAlgorithm.SHA_1,
         'encoding': serialization.Encoding.DER,
         'public_key': {
             'n': int(
                 'a8b3b284af8eb50b387034a860f146c4919f318763cd6c5598c8ae4811a'
                 '1e0abc4c7e0b082d693a5e7fced675cf4668512772c0cbc64a742c6c630'
                 'f533c8cc72f62ae833c40bf25842e984bb78bdbf97c0107d55bdb662f5c'
                 '4e0fab9845cb5148ef7392dd3aaff93ae1e6b667bb3d4247616d4f5ba10'
                 'd4cfd226de88d39f16fb',
                 16
             ),
             'e': int('010001', 16)
         },
         'private_key': {
             'd': int(
                 '53339cfdb79fc8466a655c7316aca85c55fd8f6dd898fdaf119517ef4f5'
                 '2e8fd8e258df93fee180fa0e4ab29693cd83b152a553d4ac4d1812b8b9f'
                 'a5af0e7f55fe7304df41570926f3311f15c4d65a732c483116ee3d3d2d0'
                 'af3549ad9bf7cbfb78ad884f84d5beb04724dc7369b31def37d0cf539e9'
                 'cfcdd3de653729ead5d1',
                 16
             ),
             'p': int(
                 'd32737e7267ffe1341b2d5c0d150a81b586fb3132bed2f8d5262864a9cb'
                 '9f30af38be448598d413a172efb802c21acf1c11c520c2f26a471dcad21'
                 '2eac7ca39d',
                 16
             ),
             'q': int(
                 'cc8853d1d54da630fac004f471f281c7b8982d8224a490edbeb33d3e3d5'
                 'cc93c4765703d1dd791642f1f116a0dd852be2419b2af72bfe9a030e860'
                 'b0288b5d77',
                 16
             ),
             'dmp1': int(
                 '0e12bf1718e9cef5599ba1c3882fe8046a90874eefce8f2ccc20e4f2741'
                 'fb0a33a3848aec9c9305fbecbd2d76819967d4671acc6431e4037968db3'
                 '7878e695c1',
                 16
             ),
             'dmq1': int(
                 '95297b0f95a2fa67d00707d609dfd4fc05c89dafc2ef6d6ea55bec771ea'
                 '333734d9251e79082ecda866efef13c459e1a631386b7e354c899f5f112'
                 'ca85d71583',
                 16
             ),
             'iqmp': int(
                 '4f456c502493bdc0ed2ab756a3a6ed4d67352a697d4216e93212b127a63'
                 'd5411ce6fa98d5dbefd73263e3728142743818166ed7dd63687dd2a8ca1'
                 'd2f4fbd8e1',
                 16
             )
         },
         'plain_text': (
             b'\x66\x28\x19\x4e\x12\x07\x3d\xb0'
             b'\x3b\xa9\x4c\xda\x9e\xf9\x53\x23'
             b'\x97\xd5\x0d\xba\x79\xb9\x87\x00'
             b'\x4a\xfe\xfe\x34'
         )},
        {'algorithm': enums.CryptographicAlgorithm.RSA,
         'padding_method': enums.PaddingMethod.PKCS1v15,
         'encoding': serialization.Encoding.PEM,
         'public_key': {
             'n': int(
                 '98b70582ca808fd1d3509562a0ef305af6d9875443b35bdf24d536353e3'
                 'f1228dcd12a78568356c6ff323abf72ac1cdbfe712fb49fe594a5a2175d'
                 '48b6732538d8df37cb970be4a5b562c3f298db9ddf75607877918cced1d'
                 '0d1f377338c0d3d3207797e862c65d11439e588177527a7ded91971adcf'
                 '91e2e834e37f05a73655',
                 16
             ),
             'e': int('010001', 16)
         },
         'private_key': {
             'd': int(
                 '0614a786052d284cd906a8e413f7622c050f3549c026589ea27750e0bed'
                 '9410e5a7883a1e603f5c517ad36d49faac5bd66bcb8030fa8d309e351dd'
                 'd782d843df975680ae73eea9aab289b757205dadb8fdfb989ec8db8e709'
                 '5f51f24529f5637aa669331e2569f8b854abecec99aa264c3da7cc6866f'
                 '0c0e1fb8469848581c73',
                 16
             ),
             'p': int(
                 'cb61a88c8c305ad9a8fbec2ba4c86cccc2028024aa1690c29bc8264d2fe'
                 'be87e4f86e912ef0f5c1853d71cbc9b14baed3c37cef6c7a3598b6fbe06'
                 '4810905b57',
                 16
             ),
             'q': int(
                 'c0399f0b9380faba38ff80d2fff6ede79cfdabf658972077a5e2b295693'
                 'ea51072268b91746eea9be04ad66100ebed733db4cd0147a18d6de8c0cd'
                 '8fbf249c33',
                 16
             ),
             'dmp1': int(
                 '944c3a6579574cf7873362ab14359cb7d50393c2a84f59f0bd3cbd48ed1'
                 '77c6895be8eb6e29ff58c3b9e0ff32ab57bf3be440762848184aa9aa919'
                 'd574567e73',
                 16
             ),
             'dmq1': int(
                 '45ebefd58727308cd2b4e6085a8158d29a418feec114e00385bceb96fbb'
                 'c84d071a561b95c30087900e2580edb05f6cea7907fcdca5f92917b4bbe'
                 'ba5e1e140f',
                 16
             ),
             'iqmp': int(
                 'c52468c8fd15e5da2f6c8eba4e97baebe995b67a1a7ad719dd9fff366b1'
                 '84d5ab455075909292044ecb345cf2cdd26228e21f85183255f4a9e69f4'
                 'c7152ebb0f',
                 16
             )
         },
         'plain_text': (
             b'\xe9\xa7\x71\xe0\xa6\x5f\x28\x70'
             b'\x8e\x83\xd5\xe6\xcc\x89\x8a\x41'
             b'\xd7'
         )}
    ]
)
def asymmetric_parameters(request):
    return request.param


def test_encrypt_decrypt_asymmetric(asymmetric_parameters):
    """
    Test that various encryption/decryption algorithms can be used to
    correctly asymmetrically encrypt data.
    """
    # NOTE (peter-hamilton) Randomness included in RSA padding schemes
    # makes it impossible to unit test just encryption; it's not possible
    # to predict the cipher text. Instead, we test the encrypt/decrypt
    # cycle to ensure that they correctly mirror each other.
    backend = backends.default_backend()
    public_key_numbers = rsa.RSAPublicNumbers(
        asymmetric_parameters.get('public_key').get('e'),
        asymmetric_parameters.get('public_key').get('n')
    )
    public_key = public_key_numbers.public_key(backend)
    public_bytes = public_key.public_bytes(
        asymmetric_parameters.get('encoding'),
        serialization.PublicFormat.PKCS1
    )

    private_key_numbers = rsa.RSAPrivateNumbers(
        p=asymmetric_parameters.get('private_key').get('p'),
        q=asymmetric_parameters.get('private_key').get('q'),
        d=asymmetric_parameters.get('private_key').get('d'),
        dmp1=asymmetric_parameters.get('private_key').get('dmp1'),
        dmq1=asymmetric_parameters.get('private_key').get('dmq1'),
        iqmp=asymmetric_parameters.get('private_key').get('iqmp'),
        public_numbers=public_key_numbers
    )
    private_key = private_key_numbers.private_key(backend)
    private_bytes = private_key.private_bytes(
        asymmetric_parameters.get('encoding'),
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )

    engine = crypto.CryptographyEngine()

    result = engine.encrypt(
        asymmetric_parameters.get('algorithm'),
        public_bytes,
        asymmetric_parameters.get('plain_text'),
        padding_method=asymmetric_parameters.get('padding_method'),
        hashing_algorithm=asymmetric_parameters.get('hashing_algorithm')
    )
    result = engine.decrypt(
        asymmetric_parameters.get('algorithm'),
        private_bytes,
        result.get('cipher_text'),
        padding_method=asymmetric_parameters.get('padding_method'),
        hashing_algorithm=asymmetric_parameters.get('hashing_algorithm')
    )

    assert asymmetric_parameters.get('plain_text') == result


@pytest.fixture(
    scope='function',
    params=[
        {'algorithm': algorithms.AES,
         'plain_text': b'\x48\x65\x6C\x6C\x6F',
         'padding_method': enums.PaddingMethod.PKCS5,
         'padded_text': (
             b'\x48\x65\x6C\x6C\x6F\x0B\x0B\x0B'
             b'\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B'
         )},
        {'algorithm': algorithms.TripleDES,
         'plain_text': b'\x48\x65\x6C\x6C\x6F',
         'padding_method': enums.PaddingMethod.ANSI_X923,
         'padded_text': b'\x48\x65\x6C\x6C\x6F\x00\x00\x03'}
    ]
)
def symmetric_padding_parameters(request):
    return request.param


def test_handle_symmetric_padding(symmetric_padding_parameters):
    """
    Test that data of various lengths can be padded correctly using different
    padding schemes.
    """
    engine = crypto.CryptographyEngine()

    result = engine._handle_symmetric_padding(
        symmetric_padding_parameters.get('algorithm'),
        symmetric_padding_parameters.get('plain_text'),
        symmetric_padding_parameters.get('padding_method')
    )

    assert result == symmetric_padding_parameters.get('padded_text')


def test_handle_symmetric_padding_undo(symmetric_padding_parameters):
    """
    Test that data of various lengths can be unpadded correctly using
    different padding schemes.
    """
    engine = crypto.CryptographyEngine()

    result = engine._handle_symmetric_padding(
        symmetric_padding_parameters.get('algorithm'),
        symmetric_padding_parameters.get('padded_text'),
        symmetric_padding_parameters.get('padding_method'),
        undo_padding=True
    )

    assert result == symmetric_padding_parameters.get('plain_text')


# PBKDF2 test vectors were obtained from IETF RFC 6070:
#
# https://www.ietf.org/rfc/rfc6070.txt
#
# HMAC test vectors were obtained from IETF RFC 5869:
#
# https://tools.ietf.org/html/rfc5869
#
# HASH test vectors for SHA1/SHA224/SHA256/SHA384/SHA512
# were obtained from the NIST CAVP test suite. Test vectors for MD5 were
# obtained from NIST NSRL:
#
# http://csrc.nist.gov/groups/STM/cavp/documents/shs/shabytetestvectors.zip
# https://www.nsrl.nist.gov/testdata/
#
# NIST 800-108 Counter Mode test vectors were obtained from the NIST CAVP
# test suite:
#
# http://csrc.nist.gov/groups/STM/cavp/documents/KBKDF800-108/kbkdfvs.pdf
# http://csrc.nist.gov/groups/STM/cavp/documents/KBKDF800-108/CounterMode.zip
@pytest.fixture(
    scope='function',
    params=[
        {'derivation_method': enums.DerivationMethod.PBKDF2,
         'derivation_length': 20,
         'key_material': b'password',
         'hash_algorithm': enums.HashingAlgorithm.SHA_1,
         'salt': b'salt',
         'iteration_count': 1,
         'derived_data': (
             b'\x0c\x60\xc8\x0f\x96\x1f\x0e\x71'
             b'\xf3\xa9\xb5\x24\xaf\x60\x12\x06'
             b'\x2f\xe0\x37\xa6'
         )},
        {'derivation_method': enums.DerivationMethod.PBKDF2,
         'derivation_length': 20,
         'key_material': b'password',
         'hash_algorithm': enums.HashingAlgorithm.SHA_1,
         'salt': b'salt',
         'iteration_count': 4096,
         'derived_data': (
                 b'\x4b\x00\x79\x01\xb7\x65\x48\x9a'
                 b'\xbe\xad\x49\xd9\x26\xf7\x21\xd0'
                 b'\x65\xa4\x29\xc1'
         )},
        {'derivation_method': enums.DerivationMethod.PBKDF2,
         'derivation_length': 25,
         'key_material': b'passwordPASSWORDpassword',
         'hash_algorithm': enums.HashingAlgorithm.SHA_1,
         'salt': b'saltSALTsaltSALTsaltSALTsaltSALTsalt',
         'iteration_count': 4096,
         'derived_data': (
             b'\x3d\x2e\xec\x4f\xe4\x1c\x84\x9b'
             b'\x80\xc8\xd8\x36\x62\xc0\xe4\x4a'
             b'\x8b\x29\x1a\x96\x4c\xf2\xf0\x70'
             b'\x38'
         )},
        {'derivation_method': enums.DerivationMethod.PBKDF2,
         'derivation_length': 16,
         'key_material': b'pass\x00word',
         'hash_algorithm': enums.HashingAlgorithm.SHA_1,
         'salt': b'sa\x00lt',
         'iteration_count': 4096,
         'derived_data': (
             b'\x56\xfa\x6a\xa7\x55\x48\x09\x9d'
             b'\xcc\x37\xd7\xf0\x34\x25\xe0\xc3'
         )},
        {'derivation_method': enums.DerivationMethod.HMAC,
         'derivation_length': 42,
         'derivation_data': (
             b'\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7'
             b'\xf8\xf9'
         ),
         'key_material': (
             b'\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
             b'\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
             b'\x0b\x0b\x0b\x0b\x0b\x0b'
         ),
         'hash_algorithm': enums.HashingAlgorithm.SHA_256,
         'salt': (
             b'\x00\x01\x02\x03\x04\x05\x06\x07'
             b'\x08\x09\x0a\x0b\x0c'
         ),
         'derived_data': (
             b'\x3c\xb2\x5f\x25\xfa\xac\xd5\x7a'
             b'\x90\x43\x4f\x64\xd0\x36\x2f\x2a'
             b'\x2d\x2d\x0a\x90\xcf\x1a\x5a\x4c'
             b'\x5d\xb0\x2d\x56\xec\xc4\xc5\xbf'
             b'\x34\x00\x72\x08\xd5\xb8\x87\x18'
             b'\x58\x65'
         )},
        {'derivation_method': enums.DerivationMethod.HMAC,
         'derivation_length': 82,
         'derivation_data': (
             b'\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7'
             b'\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf'
             b'\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7'
             b'\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf'
             b'\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7'
             b'\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf'
             b'\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7'
             b'\xe8\xe9\xea\xeb\xec\xed\xee\xef'
             b'\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7'
             b'\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff'
         ),
         'key_material': (
             b'\x00\x01\x02\x03\x04\x05\x06\x07'
             b'\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
             b'\x10\x11\x12\x13\x14\x15\x16\x17'
             b'\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f'
             b'\x20\x21\x22\x23\x24\x25\x26\x27'
             b'\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f'
             b'\x30\x31\x32\x33\x34\x35\x36\x37'
             b'\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f'
             b'\x40\x41\x42\x43\x44\x45\x46\x47'
             b'\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f'
         ),
         'hash_algorithm': enums.HashingAlgorithm.SHA_256,
         'salt': (
             b'\x60\x61\x62\x63\x64\x65\x66\x67'
             b'\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f'
             b'\x70\x71\x72\x73\x74\x75\x76\x77'
             b'\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f'
             b'\x80\x81\x82\x83\x84\x85\x86\x87'
             b'\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f'
             b'\x90\x91\x92\x93\x94\x95\x96\x97'
             b'\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f'
             b'\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7'
             b'\xa8\xa9\xaa\xab\xac\xad\xae\xaf'
         ),
         'derived_data': (
             b'\xb1\x1e\x39\x8d\xc8\x03\x27\xa1'
             b'\xc8\xe7\xf7\x8c\x59\x6a\x49\x34'
             b'\x4f\x01\x2e\xda\x2d\x4e\xfa\xd8'
             b'\xa0\x50\xcc\x4c\x19\xaf\xa9\x7c'
             b'\x59\x04\x5a\x99\xca\xc7\x82\x72'
             b'\x71\xcb\x41\xc6\x5e\x59\x0e\x09'
             b'\xda\x32\x75\x60\x0c\x2f\x09\xb8'
             b'\x36\x77\x93\xa9\xac\xa3\xdb\x71'
             b'\xcc\x30\xc5\x81\x79\xec\x3e\x87'
             b'\xc1\x4c\x01\xd5\xc1\xf3\x43\x4f'
             b'\x1d\x87'
         )},
        {'derivation_method': enums.DerivationMethod.HMAC,
         'derivation_length': 42,
         'derivation_data': b'',
         'key_material': (
             b'\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
             b'\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
             b'\x0b\x0b\x0b\x0b\x0b\x0b'
         ),
         'hash_algorithm': enums.HashingAlgorithm.SHA_256,
         'salt': b'',
         'derived_data': (
             b'\x8d\xa4\xe7\x75\xa5\x63\xc1\x8f'
             b'\x71\x5f\x80\x2a\x06\x3c\x5a\x31'
             b'\xb8\xa1\x1f\x5c\x5e\xe1\x87\x9e'
             b'\xc3\x45\x4e\x5f\x3c\x73\x8d\x2d'
             b'\x9d\x20\x13\x95\xfa\xa4\xb6\x1a'
             b'\x96\xc8'
         )},
        {'derivation_method': enums.DerivationMethod.HMAC,
         'derivation_length': 42,
         'derivation_data': (
             b'\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7'
             b'\xf8\xf9'
         ),
         'key_material': (
             b'\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
             b'\x0b\x0b\x0b'
         ),
         'hash_algorithm': enums.HashingAlgorithm.SHA_1,
         'salt': (
             b'\x00\x01\x02\x03\x04\x05\x06\x07'
             b'\x08\x09\x0a\x0b\x0c'
         ),
         'derived_data': (
             b'\x08\x5a\x01\xea\x1b\x10\xf3\x69'
             b'\x33\x06\x8b\x56\xef\xa5\xad\x81'
             b'\xa4\xf1\x4b\x82\x2f\x5b\x09\x15'
             b'\x68\xa9\xcd\xd4\xf1\x55\xfd\xa2'
             b'\xc2\x2e\x42\x24\x78\xd3\x05\xf3'
             b'\xf8\x96'
         )},
        {'derivation_method': enums.DerivationMethod.HMAC,
         'derivation_length': 82,
         'derivation_data': (
             b'\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7'
             b'\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf'
             b'\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7'
             b'\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf'
             b'\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7'
             b'\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf'
             b'\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7'
             b'\xe8\xe9\xea\xeb\xec\xed\xee\xef'
             b'\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7'
             b'\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff'
         ),
         'key_material': (
             b'\x00\x01\x02\x03\x04\x05\x06\x07'
             b'\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
             b'\x10\x11\x12\x13\x14\x15\x16\x17'
             b'\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f'
             b'\x20\x21\x22\x23\x24\x25\x26\x27'
             b'\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f'
             b'\x30\x31\x32\x33\x34\x35\x36\x37'
             b'\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f'
             b'\x40\x41\x42\x43\x44\x45\x46\x47'
             b'\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f'
         ),
         'hash_algorithm': enums.HashingAlgorithm.SHA_1,
         'salt': (
             b'\x60\x61\x62\x63\x64\x65\x66\x67'
             b'\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f'
             b'\x70\x71\x72\x73\x74\x75\x76\x77'
             b'\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f'
             b'\x80\x81\x82\x83\x84\x85\x86\x87'
             b'\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f'
             b'\x90\x91\x92\x93\x94\x95\x96\x97'
             b'\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f'
             b'\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7'
             b'\xa8\xa9\xaa\xab\xac\xad\xae\xaf'
         ),
         'derived_data': (
             b'\x0b\xd7\x70\xa7\x4d\x11\x60\xf7'
             b'\xc9\xf1\x2c\xd5\x91\x2a\x06\xeb'
             b'\xff\x6a\xdc\xae\x89\x9d\x92\x19'
             b'\x1f\xe4\x30\x56\x73\xba\x2f\xfe'
             b'\x8f\xa3\xf1\xa4\xe5\xad\x79\xf3'
             b'\xf3\x34\xb3\xb2\x02\xb2\x17\x3c'
             b'\x48\x6e\xa3\x7c\xe3\xd3\x97\xed'
             b'\x03\x4c\x7f\x9d\xfe\xb1\x5c\x5e'
             b'\x92\x73\x36\xd0\x44\x1f\x4c\x43'
             b'\x00\xe2\xcf\xf0\xd0\x90\x0b\x52'
             b'\xd3\xb4'
         )},
        {'derivation_method': enums.DerivationMethod.HMAC,
         'derivation_length': 42,
         'derivation_data': b'',
         'key_material': (
             b'\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
             b'\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
             b'\x0b\x0b\x0b\x0b\x0b\x0b'
         ),
         'hash_algorithm': enums.HashingAlgorithm.SHA_1,
         'salt': b'',
         'derived_data': (
             b'\x0a\xc1\xaf\x70\x02\xb3\xd7\x61'
             b'\xd1\xe5\x52\x98\xda\x9d\x05\x06'
             b'\xb9\xae\x52\x05\x72\x20\xa3\x06'
             b'\xe0\x7b\x6b\x87\xe8\xdf\x21\xd0'
             b'\xea\x00\x03\x3d\xe0\x39\x84\xd3'
             b'\x49\x18'
         )},
        {'derivation_method': enums.DerivationMethod.HMAC,
         'derivation_length': 42,
         'derivation_data': b'',
         'key_material': (
             b'\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c'
             b'\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c'
             b'\x0c\x0c\x0c\x0c\x0c\x0c'
         ),
         'hash_algorithm': enums.HashingAlgorithm.SHA_1,
         'salt': b'',
         'derived_data': (
             b'\x2c\x91\x11\x72\x04\xd7\x45\xf3'
             b'\x50\x0d\x63\x6a\x62\xf6\x4f\x0a'
             b'\xb3\xba\xe5\x48\xaa\x53\xd4\x23'
             b'\xb0\xd1\xf2\x7e\xbb\xa6\xf5\xe5'
             b'\x67\x3a\x08\x1d\x70\xcc\xe7\xac'
             b'\xfc\x48'
         )},
        {'derivation_method': enums.DerivationMethod.HASH,
         'derivation_length': 16,
         'derivation_data': (
             b'abc'
         ),
         'hash_algorithm': enums.HashingAlgorithm.MD5,
         'derived_data': (
             b'\x90\x01\x50\x98\x3C\xD2\x4F\xB0'
             b'\xD6\x96\x3F\x7D\x28\xE1\x7F\x72'
         )},
        {'derivation_method': enums.DerivationMethod.HASH,
         'derivation_length': 16,
         'derivation_data': (
             b'abcdbcdecdefdefgefghfghighijhijk'
             b'ijkljklmklmnlmnomnopnopq'
         ),
         'hash_algorithm': enums.HashingAlgorithm.MD5,
         'derived_data': (
             b'\x82\x15\xEF\x07\x96\xA2\x0B\xCA'
             b'\xAA\xE1\x16\xD3\x87\x6C\x66\x4A'
         )},
        {'derivation_method': enums.DerivationMethod.HASH,
         'derivation_length': 20,
         'derivation_data': b'',
         'hash_algorithm': enums.HashingAlgorithm.SHA_1,
         'derived_data': (
             b'\xda\x39\xa3\xee\x5e\x6b\x4b\x0d'
             b'\x32\x55\xbf\xef\x95\x60\x18\x90'
             b'\xaf\xd8\x07\x09'
         )},
        {'derivation_method': enums.DerivationMethod.HASH,
         'derivation_length': 20,
         'derivation_data': (
             b'\x03\x21\x79\x4b\x73\x94\x18\xc2'
             b'\x4e\x7c\x2e\x56\x52\x74\x79\x1c'
             b'\x4b\xe7\x49\x75\x2a\xd2\x34\xed'
             b'\x56\xcb\x0a\x63\x47\x43\x0c\x6b'
         ),
         'hash_algorithm': enums.HashingAlgorithm.SHA_1,
         'derived_data': (
             b'\xb8\x99\x62\xc9\x4d\x60\xf6\xa3'
             b'\x32\xfd\x60\xf6\xf0\x7d\x4f\x03'
             b'\x2a\x58\x6b\x76'
         )},
        {'derivation_method': enums.DerivationMethod.HASH,
         'derivation_length': 28,
         'derivation_data': b'',
         'hash_algorithm': enums.HashingAlgorithm.SHA_224,
         'derived_data': (
             b'\xd1\x4a\x02\x8c\x2a\x3a\x2b\xc9'
             b'\x47\x61\x02\xbb\x28\x82\x34\xc4'
             b'\x15\xa2\xb0\x1f\x82\x8e\xa6\x2a'
             b'\xc5\xb3\xe4\x2f'
         )},
        {'derivation_method': enums.DerivationMethod.HASH,
         'derivation_length': 28,
         'derivation_data': (
             b'\xa3\x31\x0b\xa0\x64\xbe\x2e\x14'
             b'\xad\x32\x27\x6e\x18\xcd\x03\x10'
             b'\xc9\x33\xa6\xe6\x50\xc3\xc7\x54'
             b'\xd0\x24\x3c\x6c\x61\x20\x78\x65'
             b'\xb4\xb6\x52\x48\xf6\x6a\x08\xed'
             b'\xf6\xe0\x83\x26\x89\xa9\xdc\x3a'
             b'\x2e\x5d\x20\x95\xee\xea\x50\xbd'
             b'\x86\x2b\xac\x88\xc8\xbd\x31\x8d'
         ),
         'hash_algorithm': enums.HashingAlgorithm.SHA_224,
         'derived_data': (
             b'\xb2\xa5\x58\x6d\x9c\xbf\x0b\xaa'
             b'\x99\x91\x57\xb4\xaf\x06\xd8\x8a'
             b'\xe0\x8d\x7c\x9f\xaa\xb4\xbc\x1a'
             b'\x96\x82\x9d\x65'
         )},
        {'derivation_method': enums.DerivationMethod.HASH,
         'derivation_length': 32,
         'derivation_data': b'',
         'hash_algorithm': enums.HashingAlgorithm.SHA_256,
         'derived_data': (
             b'\xe3\xb0\xc4\x42\x98\xfc\x1c\x14'
             b'\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24'
             b'\x27\xae\x41\xe4\x64\x9b\x93\x4c'
             b'\xa4\x95\x99\x1b\x78\x52\xb8\x55'
         )},
        {'derivation_method': enums.DerivationMethod.HASH,
         'derivation_length': 32,
         'derivation_data': (
             b'\xf4\x99\xcc\x3f\x6e\x3c\xf7\xc3'
             b'\x12\xff\xdf\xba\x61\xb1\x26\x0c'
             b'\x37\x12\x9c\x1a\xfb\x39\x10\x47'
             b'\x19\x33\x67\xb7\xb2\xed\xeb\x57'
             b'\x92\x53\xe5\x1d\x62\xba\x6d\x91'
             b'\x1e\x7b\x81\x8c\xca\xe1\x55\x3f'
             b'\x61\x46\xea\x78\x0f\x78\xe2\x21'
             b'\x9f\x62\x93\x09'
         ),
         'hash_algorithm': enums.HashingAlgorithm.SHA_256,
         'derived_data': (
             b'\x0b\x66\xc8\xb4\xfe\xfe\xbc\x8d'
             b'\xc7\xda\x0b\xbe\xdc\x11\x14\xf2'
             b'\x28\xaa\x63\xc3\x7d\x5c\x30\xe9'
             b'\x1a\xb5\x00\xf3\xea\xdf\xce\xc5'
         )},
        {'derivation_method': enums.DerivationMethod.HASH,
         'derivation_length': 48,
         'derivation_data': b'',
         'hash_algorithm': enums.HashingAlgorithm.SHA_384,
         'derived_data': (
             b'\x38\xb0\x60\xa7\x51\xac\x96\x38'
             b'\x4c\xd9\x32\x7e\xb1\xb1\xe3\x6a'
             b'\x21\xfd\xb7\x11\x14\xbe\x07\x43'
             b'\x4c\x0c\xc7\xbf\x63\xf6\xe1\xda'
             b'\x27\x4e\xde\xbf\xe7\x6f\x65\xfb'
             b'\xd5\x1a\xd2\xf1\x48\x98\xb9\x5b'
         )},
        {'derivation_method': enums.DerivationMethod.HASH,
         'derivation_length': 48,
         'derivation_data': (
             b'\x3b\xf5\x2c\xc5\xee\x86\xb9\xa0'
             b'\x19\x0f\x39\x0a\x5c\x03\x66\xa5'
             b'\x60\xb5\x57\x00\x0d\xbe\x51\x15'
             b'\xfd\x9e\xe1\x16\x30\xa6\x27\x69'
             b'\x01\x15\x75\xf1\x58\x81\x19\x8f'
             b'\x22\x78\x76\xe8\xfe\x68\x5a\x69'
             b'\x39\xbc\x8b\x89\xfd\x48\xa3\x4e'
             b'\xc5\xe7\x1e\x13\x14\x62\xb2\x88'
             b'\x67\x94\xdf\xfa\x68\xcc\xc6\xd5'
             b'\x64\x73\x3e\x67\xff\xef\x25\xe6'
             b'\x27\xc6\xf4\xb5\x46\x07\x96\xe3'
             b'\xbc\xe6\x7b\xf5\x8c\xa6\xe8\xe5'
             b'\x55\xbc\x91\x6a\x85\x31\x69\x7a'
             b'\xc9\x48\xb9\x0d\xc8\x61\x6f\x25'
             b'\x10\x1d\xb9\x0b\x50\xc3\xd3\xdb'
             b'\xc9\xe2\x1e\x42\xff\x38\x71\x87'
         ),
         'hash_algorithm': enums.HashingAlgorithm.SHA_384,
         'derived_data': (
             b'\x12\xb6\xcb\x35\xed\xa9\x2e\xe3'
             b'\x73\x56\xdd\xee\x77\x78\x1a\x17'
             b'\xb3\xd9\x0e\x56\x38\x24\xa9\x84'
             b'\xfa\xff\xc6\xfd\xd1\x69\x3b\xd7'
             b'\x62\x60\x39\x63\x55\x63\xcf\xc3'
             b'\xb9\xa2\xb0\x0f\x9c\x65\xee\xfd'
         )},
        {'derivation_method': enums.DerivationMethod.HASH,
         'derivation_length': 64,
         'key_material': b'',
         'hash_algorithm': enums.HashingAlgorithm.SHA_512,
         'derived_data': (
             b'\xcf\x83\xe1\x35\x7e\xef\xb8\xbd'
             b'\xf1\x54\x28\x50\xd6\x6d\x80\x07'
             b'\xd6\x20\xe4\x05\x0b\x57\x15\xdc'
             b'\x83\xf4\xa9\x21\xd3\x6c\xe9\xce'
             b'\x47\xd0\xd1\x3c\x5d\x85\xf2\xb0'
             b'\xff\x83\x18\xd2\x87\x7e\xec\x2f'
             b'\x63\xb9\x31\xbd\x47\x41\x7a\x81'
             b'\xa5\x38\x32\x7a\xf9\x27\xda\x3e'
         )},
        {'derivation_method': enums.DerivationMethod.HASH,
         'derivation_length': 64,
         'derivation_data': (
             b'\xa7\x66\xb2\xa7\xef\x91\x67\x21'
             b'\xf4\x67\x7b\x67\xdb\xc6\x5e\xf9'
             b'\xb4\xd1\xbd\xa1\xad\x4e\x53\xfc'
             b'\x85\x4b\x02\x36\x44\x08\x22\x15'
             b'\x2a\x11\x19\x39\xe5\xab\x2b\xa2'
             b'\x07\x71\x94\x72\xb6\x3f\xd4\xf4'
             b'\xa5\x4f\x4b\xde\x44\xa2\x05\xd3'
             b'\x34\xa2\xd7\x2c\xfe\x05\xab\xf8'
             b'\x04\xf4\x18\x41\xb8\x6d\x36\x92'
             b'\x0b\xe6\xb0\xb5\x29\x33\x1a\xc1'
             b'\x63\xa9\x85\x55\x6c\x84\x51\x1e'
             b'\xc9\x86\x43\x9f\x83\xe1\xd7\x31'
             b'\x1f\x57\xd8\x48\xcf\xa0\x2d\xf9'
             b'\xea\x0c\xf6\xb9\x9a'
         ),
         'hash_algorithm': enums.HashingAlgorithm.SHA_512,
         'derived_data': (
             b'\xdd\xd6\x0f\x93\xa3\xba\xbc\x78'
             b'\x29\x9c\xf7\x63\xe7\x91\x9d\x45'
             b'\xac\x6f\x47\x97\x00\xe1\xad\xb0'
             b'\x5a\xb1\x37\xac\xdf\x89\xc1\x52'
             b'\x1e\xcb\x9d\xfe\xac\xd0\x91\xe5'
             b'\x8c\xa5\x7a\x1d\xb9\x64\xa9\xc3'
             b'\xcd\x1f\xa3\x91\x92\xcc\x1e\x9f'
             b'\x73\x4c\xaa\x1c\x5f\xa6\x29\x75'
         )},
        {'derivation_method': enums.DerivationMethod.NIST800_108_C,
         'derivation_length': 16,
         'derivation_data': (
             b'\x8e\x34\x7e\xf5\x5d\x5f\x5e\x99'
             b'\xea\xb6\xde\x70\x6b\x51\xde\x7c'
             b'\xe0\x04\xf3\x88\x28\x89\xe2\x59'
             b'\xff\x4e\x5c\xff\x10\x21\x67\xa5'
             b'\xa4\xbd\x71\x15\x78\xd4\xce\x17'
             b'\xdd\x9a\xbe\x56\xe5\x1c\x1f\x2d'
             b'\xf9\x50\xe2\xfc\x81\x2e\xc1\xb2'
             b'\x17\xca\x08\xd6'
         ),
         'key_material': (
             b'\xf7\x59\x17\x33\xc8\x56\x59\x35'
             b'\x65\x13\x09\x75\x35\x19\x54\xd0'
             b'\x15\x5a\xbf\x3c'
         ),
         'hash_algorithm': enums.HashingAlgorithm.SHA_1,
         'derived_data': (
             b'\x34\xfe\x44\xb0\xd8\xc4\x1b\x93'
             b'\xf5\xfa\x64\xfb\x96\xf0\x0e\x5b'
         )},
        {'derivation_method': enums.DerivationMethod.NIST800_108_C,
         'derivation_length': 16,
         'derivation_data': (
             b'\x4e\x5a\xc7\x53\x98\x03\xda\x89'
             b'\x58\x1e\xe0\x88\xc7\xd1\x02\x35'
             b'\xa1\x05\x36\x36\x00\x54\xb7\x2b'
             b'\x8e\x9f\x18\xf7\x7c\x25\xaf\x01'
             b'\x01\x9b\x29\x06\x56\xb6\x04\x28'
             b'\x02\x4c\xe0\x1f\xcc\xf4\x90\x22'
             b'\xd8\x31\x94\x14\x07\xe6\xbd\x27'
             b'\xff\x9e\x2d\x28'
         ),
         'key_material': (
             b'\xf5\xcb\x7c\xc6\x20\x7f\x59\x20'
             b'\xdd\x60\x15\x5d\xdb\x68\xc3\xfb'
             b'\xbd\xf5\x10\x43\x65\x30\x5d\x2c'
             b'\x1a\xbc\xd3\x11'
         ),
         'hash_algorithm': enums.HashingAlgorithm.SHA_224,
         'derived_data': (
             b'\x0a\xdb\xaa\xb4\x3e\xdd\x53\x2b'
             b'\x56\x0a\x32\x2c\x84\xac\x54\x0e'
         )},
        {'derivation_method': enums.DerivationMethod.NIST800_108_C,
         'derivation_length': 16,
         'derivation_data': (
             b'\x01\x32\x2b\x96\xb3\x0a\xcd\x19'
             b'\x79\x79\x44\x4e\x46\x8e\x1c\x5c'
             b'\x68\x59\xbf\x1b\x1c\xf9\x51\xb7'
             b'\xe7\x25\x30\x3e\x23\x7e\x46\xb8'
             b'\x64\xa1\x45\xfa\xb2\x5e\x51\x7b'
             b'\x08\xf8\x68\x3d\x03\x15\xbb\x29'
             b'\x11\xd8\x0a\x0e\x8a\xba\x17\xf3'
             b'\xb4\x13\xfa\xac'
         ),
         'key_material': (
             b'\xdd\x1d\x91\xb7\xd9\x0b\x2b\xd3'
             b'\x13\x85\x33\xce\x92\xb2\x72\xfb'
             b'\xf8\xa3\x69\x31\x6a\xef\xe2\x42'
             b'\xe6\x59\xcc\x0a\xe2\x38\xaf\xe0'
         ),
         'hash_algorithm': enums.HashingAlgorithm.SHA_256,
         'derived_data': (
             b'\x10\x62\x13\x42\xbf\xb0\xfd\x40'
             b'\x04\x6c\x0e\x29\xf2\xcf\xdb\xf0'
         )},
        {'derivation_method': enums.DerivationMethod.NIST800_108_C,
         'derivation_length': 16,
         'derivation_data': (
             b'\x63\x8e\x95\x06\xa2\xc7\xbe\x69'
             b'\xea\x34\x6b\x84\x62\x9a\x01\x0c'
             b'\x0e\x22\x5b\x75\x48\xf5\x08\x16'
             b'\x2c\x89\xf2\x9c\x1d\xdb\xfd\x70'
             b'\x47\x2c\x2b\x58\xe7\xdc\x8a\xa6'
             b'\xa5\xb0\x66\x02\xf1\xc8\xed\x49'
             b'\x48\xcd\xa7\x9c\x62\x70\x82\x18'
             b'\xe2\x6a\xc0\xe2'
         ),
         'key_material': (
             b'\x21\x6e\xd0\x44\x76\x9c\x4c\x39'
             b'\x08\x18\x8e\xce\x61\x60\x1a\xf8'
             b'\x81\x9c\x30\xf5\x01\xd1\x29\x95'
             b'\xdf\x60\x8e\x06\xf5\xe0\xe6\x07'
             b'\xab\x54\xf5\x42\xee\x2d\xa4\x19'
             b'\x06\xdf\xdb\x49\x71\xf2\x0f\x9d'
         ),
         'hash_algorithm': enums.HashingAlgorithm.SHA_384,
         'derived_data': (
             b'\xd4\xb1\x44\xbb\x40\xc7\xca\xbe'
             b'\xd1\x39\x63\xd7\xd4\x31\x8e\x72'
         )},
        {'derivation_method': enums.DerivationMethod.NIST800_108_C,
         'derivation_length': 16,
         'derivation_data': (
             b'\xb5\x0b\x0c\x96\x3c\x6b\x30\x34'
             b'\xb8\xcf\x19\xcd\x3f\x5c\x4e\xbe'
             b'\x4f\x49\x85\xaf\x0c\x03\xe5\x75'
             b'\xdb\x62\xe6\xfd\xf1\xec\xfe\x4f'
             b'\x28\xb9\x5d\x7c\xe1\x6d\xf8\x58'
             b'\x43\x24\x6e\x15\x57\xce\x95\xbb'
             b'\x26\xcc\x9a\x21\x97\x4b\xbd\x2e'
             b'\xb6\x9e\x83\x55'
         ),
         'key_material': (
             b'\xdd\x5d\xbd\x45\x59\x3e\xe2\xac'
             b'\x13\x97\x48\xe7\x64\x5b\x45\x0f'
             b'\x22\x3d\x2f\xf2\x97\xb7\x3f\xd7'
             b'\x1c\xbc\xeb\xe7\x1d\x41\x65\x3c'
             b'\x95\x0b\x88\x50\x0d\xe5\x32\x2d'
             b'\x99\xef\x18\xdf\xdd\x30\x42\x82'
             b'\x94\xc4\xb3\x09\x4f\x4c\x95\x43'
             b'\x34\xe5\x93\xbd\x98\x2e\xc6\x14'
         ),
         'hash_algorithm': enums.HashingAlgorithm.SHA_512,
         'derived_data': (
             b'\xe5\x99\x3b\xf9\xbd\x2a\xa1\xc4'
             b'\x57\x46\x04\x2e\x12\x59\x81\x55'
         )},
        {'derivation_method': enums.DerivationMethod.ENCRYPT,
         'derivation_data': (
             b'\x37\x36\x35\x34\x33\x32\x31\x20'
             b'\x4E\x6F\x77\x20\x69\x73\x20\x74'
             b'\x68\x65\x20\x74\x69\x6D\x65\x20'
             b'\x66\x6F\x72\x20\x00'
         ),
         'key_material': (
             b'\x01\x23\x45\x67\x89\xAB\xCD\xEF'
             b'\xF0\xE1\xD2\xC3\xB4\xA5\x96\x87'
         ),
         'encryption_algorithm': enums.CryptographicAlgorithm.BLOWFISH,
         'cipher_mode': enums.BlockCipherMode.CBC,
         'padding_method': enums.PaddingMethod.PKCS5,
         'iv_nonce': b'\xFE\xDC\xBA\x98\x76\x54\x32\x10',
         'derived_data': (
             b'\x6B\x77\xB4\xD6\x30\x06\xDE\xE6'
             b'\x05\xB1\x56\xE2\x74\x03\x97\x93'
             b'\x58\xDE\xB9\xE7\x15\x46\x16\xD9'
             b'\x74\x9D\xEC\xBE\xC0\x5D\x26\x4B'
         )}
    ]
)
def derivation_parameters(request):
    return request.param


def test_derive_key(derivation_parameters):
    """
    Test that various derivation methods and settings can be used to correctly
    derive key data.
    """
    engine = crypto.CryptographyEngine()

    result = engine.derive_key(
        derivation_parameters.get('derivation_method'),
        derivation_parameters.get('derivation_length'),
        derivation_data=derivation_parameters.get('derivation_data'),
        key_material=derivation_parameters.get('key_material'),
        hash_algorithm=derivation_parameters.get('hash_algorithm'),
        salt=derivation_parameters.get('salt'),
        iteration_count=derivation_parameters.get('iteration_count'),
        encryption_algorithm=derivation_parameters.get('encryption_algorithm'),
        padding_method=derivation_parameters.get('padding_method'),
        cipher_mode=derivation_parameters.get('cipher_mode'),
        iv_nonce=derivation_parameters.get('iv_nonce')
    )

    assert derivation_parameters.get('derived_data') == result


# AES Key Wrap test vectors were obtained from IETF RFC 3394:
#
# https://www.ietf.org/rfc/rfc3394.txt
@pytest.fixture(
    scope='function',
    params=[
        {'key_material': (
             b'\x00\x11\x22\x33\x44\x55\x66\x77'
             b'\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF'
         ),
         'wrapping_method': enums.WrappingMethod.ENCRYPT,
         'key_wrap_algorithm': enums.BlockCipherMode.NIST_KEY_WRAP,
         'encryption_key': (
             b'\x00\x01\x02\x03\x04\x05\x06\x07'
             b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
         ),
         'wrapped_data': (
             b'\x1F\xA6\x8B\x0A\x81\x12\xB4\x47'
             b'\xAE\xF3\x4B\xD8\xFB\x5A\x7B\x82'
             b'\x9D\x3E\x86\x23\x71\xD2\xCF\xE5'
         )},
        {'key_material': (
             b'\x00\x11\x22\x33\x44\x55\x66\x77'
             b'\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF'
         ),
         'wrapping_method': enums.WrappingMethod.ENCRYPT,
         'key_wrap_algorithm': enums.BlockCipherMode.NIST_KEY_WRAP,
         'encryption_key': (
             b'\x00\x01\x02\x03\x04\x05\x06\x07'
             b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
             b'\x10\x11\x12\x13\x14\x15\x16\x17'
         ),
         'wrapped_data': (
             b'\x96\x77\x8B\x25\xAE\x6C\xA4\x35'
             b'\xF9\x2B\x5B\x97\xC0\x50\xAE\xD2'
             b'\x46\x8A\xB8\xA1\x7A\xD8\x4E\x5D'
         )},
        {'key_material': (
             b'\x00\x11\x22\x33\x44\x55\x66\x77'
             b'\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF'
         ),
         'wrapping_method': enums.WrappingMethod.ENCRYPT,
         'key_wrap_algorithm': enums.BlockCipherMode.NIST_KEY_WRAP,
         'encryption_key': (
             b'\x00\x01\x02\x03\x04\x05\x06\x07'
             b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
             b'\x10\x11\x12\x13\x14\x15\x16\x17'
             b'\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F'
         ),
         'wrapped_data': (
             b'\x64\xE8\xC3\xF9\xCE\x0F\x5B\xA2'
             b'\x63\xE9\x77\x79\x05\x81\x8A\x2A'
             b'\x93\xC8\x19\x1E\x7D\x6E\x8A\xE7'
         )},
        {'key_material': (
             b'\x00\x11\x22\x33\x44\x55\x66\x77'
             b'\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF'
             b'\x00\x01\x02\x03\x04\x05\x06\x07'
         ),
         'wrapping_method': enums.WrappingMethod.ENCRYPT,
         'key_wrap_algorithm': enums.BlockCipherMode.NIST_KEY_WRAP,
         'encryption_key': (
             b'\x00\x01\x02\x03\x04\x05\x06\x07'
             b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
             b'\x10\x11\x12\x13\x14\x15\x16\x17'
         ),
         'wrapped_data': (
             b'\x03\x1D\x33\x26\x4E\x15\xD3\x32'
             b'\x68\xF2\x4E\xC2\x60\x74\x3E\xDC'
             b'\xE1\xC6\xC7\xDD\xEE\x72\x5A\x93'
             b'\x6B\xA8\x14\x91\x5C\x67\x62\xD2'
         )},
        {'key_material': (
             b'\x00\x11\x22\x33\x44\x55\x66\x77'
             b'\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF'
             b'\x00\x01\x02\x03\x04\x05\x06\x07'
         ),
         'wrapping_method': enums.WrappingMethod.ENCRYPT,
         'key_wrap_algorithm': enums.BlockCipherMode.NIST_KEY_WRAP,
         'encryption_key': (
             b'\x00\x01\x02\x03\x04\x05\x06\x07'
             b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
             b'\x10\x11\x12\x13\x14\x15\x16\x17'
             b'\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F'
         ),
         'wrapped_data': (
             b'\xA8\xF9\xBC\x16\x12\xC6\x8B\x3F'
             b'\xF6\xE6\xF4\xFB\xE3\x0E\x71\xE4'
             b'\x76\x9C\x8B\x80\xA3\x2C\xB8\x95'
             b'\x8C\xD5\xD1\x7D\x6B\x25\x4D\xA1'
         )},
        {'key_material': (
             b'\x00\x11\x22\x33\x44\x55\x66\x77'
             b'\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF'
             b'\x00\x01\x02\x03\x04\x05\x06\x07'
             b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
         ),
         'wrapping_method': enums.WrappingMethod.ENCRYPT,
         'key_wrap_algorithm': enums.BlockCipherMode.NIST_KEY_WRAP,
         'encryption_key': (
             b'\x00\x01\x02\x03\x04\x05\x06\x07'
             b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
             b'\x10\x11\x12\x13\x14\x15\x16\x17'
             b'\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F'
         ),
         'wrapped_data': (
             b'\x28\xC9\xF4\x04\xC4\xB8\x10\xF4'
             b'\xCB\xCC\xB3\x5C\xFB\x87\xF8\x26'
             b'\x3F\x57\x86\xE2\xD8\x0E\xD3\x26'
             b'\xCB\xC7\xF0\xE7\x1A\x99\xF4\x3B'
             b'\xFB\x98\x8B\x9B\x7A\x02\xDD\x21'
         )}
    ]
)
def wrapping_parameters(request):
    return request.param


def test_wrap_key(wrapping_parameters):
    """
    Test that various wrapping methods and settings can be used to correctly
    wrap key data.
    """
    engine = crypto.CryptographyEngine()

    result = engine.wrap_key(
        wrapping_parameters.get('key_material'),
        wrapping_parameters.get('wrapping_method'),
        wrapping_parameters.get('key_wrap_algorithm'),
        wrapping_parameters.get('encryption_key')
    )

    assert wrapping_parameters.get('wrapped_data') == result


# Test vectors obtained from pyca/cryptography
# https://cryptography.io/en/latest/


DER_RSA_KEY = (
    b'\x30\x82\x02\x5e\x02\x01\x00\x02\x81\x81\x00\xae\xba\xc1\xb9\xa1\x74\x31'
    b'\x5d\x27\xcc\x3c\x20\x1e\x21\x57\x89\x43\x72\xd6\x45\x0d\x4c\xf8\x0c\xe0'
    b'\xeb\xcf\x51\x69\x51\x9b\x9e\x85\x50\x03\x6f\x4a\xbe\x0f\xe4\xf9\x4f\xbf'
    b'\x9c\xca\x60\x6f\x39\x74\x33\x65\x49\x96\x11\xba\x3f\x25\xa9\xa4\x71\x58'
    b'\xba\x05\x21\x4b\x65\x5f\x42\x58\xa4\xc2\x95\x16\xbe\xca\xa5\x83\xf2\xd2'
    b'\x66\x50\x69\x6a\xd6\xfc\x03\xd5\xb4\x7d\x3a\xba\x9c\x54\x79\xfd\xb0\x47'
    b'\x7d\x29\x51\x33\x99\xcb\x19\x28\x3c\xcd\xc2\x8d\xbb\x23\xb7\xc7\xee\xe4'
    b'\xb3\x5d\xc9\x40\xda\xca\x00\x55\xdc\xd2\x8f\x50\x3b\x02\x03\x01\x00\x01'
    b'\x02\x81\x81\x00\x92\x89\x09\x42\xd6\xc6\x8d\x47\xa4\xc2\xc1\x81\xe6\x02'
    b'\xec\x58\xaf\x7a\x35\x7c\x7f\xa5\x17\x3a\x25\xbf\x5d\x84\xd7\x20\x9b\xb4'
    b'\x1b\xf5\x78\x8b\xf3\x50\xe6\x1f\x8f\x7e\x74\x21\xd8\x0f\x7b\xf7\xe1\x1d'
    b'\xe1\x4a\x0f\x53\x1a\xb1\x2e\xb2\xd0\xb8\x46\x42\xeb\x5d\x18\x11\x70\xc2'
    b'\xc5\x8a\xab\xbd\x67\x54\x84\x2f\xaf\xee\x57\xfe\xf2\xf5\x45\xd0\x9f\xdc'
    b'\x66\x49\x02\xe5\x5b\xac\xed\x5a\x3c\x6d\x26\xf3\x46\x58\x59\xd3\x3a\x33'
    b'\xa5\x55\x53\x7d\xaf\x22\x63\xaa\xef\x28\x35\x4c\x8b\x53\x51\x31\x45\xa7'
    b'\xe2\x28\x82\x4d\xab\xb1\x02\x41\x00\xd3\xaa\x23\x7e\x89\x42\xb9\x3d\x56'
    b'\xa6\x81\x25\x4c\x27\xbe\x1f\x4a\x49\x6c\xa4\xa8\x7f\xc0\x60\x4b\x0c\xff'
    b'\x8f\x98\x0e\x74\x2d\x2b\xbb\x91\xb8\x8a\x24\x7b\x6e\xbb\xed\x01\x45\x8c'
    b'\x4a\xfd\xb6\x8c\x0f\x8c\x6d\x4a\x37\xe0\x28\xc5\xfc\xb3\xa6\xa3\x9c\xa6'
    b'\x4f\x02\x41\x00\xd3\x54\x16\x8c\x61\x9c\x83\x6e\x85\x97\xfe\xf5\x01\x93'
    b'\xa6\xf4\x26\x07\x95\x2a\x1c\x87\xeb\xae\x91\xdb\x50\x43\xb8\x85\x50\x72'
    b'\xb4\xe9\x2a\xf5\xdc\xed\xb2\x14\x87\x73\xdf\xbd\x21\x7b\xaf\xc8\xdc\x9d'
    b'\xa8\xae\x8e\x75\x7e\x72\x48\xc1\xe5\x13\xa1\x44\x68\x55\x02\x41\x00\x90'
    b'\xfd\xa2\x14\xc2\xb7\xb7\x26\x82\x5d\xca\x67\x9f\x34\x36\x33\x3e\xf2\xee'
    b'\xfe\x18\x02\x72\xe8\x43\x60\xe3\x0b\x1d\x11\x01\x9a\x13\xb4\x08\x0d\x0e'
    b'\x6c\x11\x35\x78\x7b\xd0\x7c\x30\xaf\x09\xfe\xeb\x10\x97\x94\x21\xdc\x06'
    b'\xac\x47\x7b\x64\x20\xc9\x40\xbc\x57\x02\x40\x16\x4d\xe8\xb7\x56\x52\x13'
    b'\x99\x25\xa6\x7e\x35\x53\xbe\x46\xbf\xbc\x07\xce\xd9\x8b\xfb\x58\x87\xab'
    b'\x43\x4f\x7c\x66\x4c\x43\xca\x67\x87\xb8\x8e\x0c\x8c\x55\xe0\x4e\xcf\x8f'
    b'\x0c\xc2\x2c\xf0\xc7\xad\x69\x42\x75\x71\xf9\xba\xa7\xcb\x40\x13\xb2\x77'
    b'\xb1\xe5\xa5\x02\x41\x00\xca\xe1\x50\xf5\xfa\x55\x9b\x2e\x2c\x39\x44\x4e'
    b'\x0f\x5c\x65\x10\x34\x09\x2a\xc9\x7b\xac\x10\xd5\x28\xdd\x15\xdf\xda\x25'
    b'\x4c\xb0\x6b\xef\x41\xe3\x98\x81\xf7\xe7\x49\x69\x10\xb4\x65\x56\x59\xdc'
    b'\x84\x2d\x30\xb9\xae\x27\x59\xf3\xc2\xcd\x41\xc7\x9a\x36\x84\xec'
)

PEM_RSA_KEY = (
    b'\x2d\x2d\x2d\x2d\x2d\x42\x45\x47\x49\x4e\x20\x50\x52\x49\x56\x41\x54\x45'
    b'\x20\x4b\x45\x59\x2d\x2d\x2d\x2d\x2d\x0a\x4d\x49\x49\x43\x64\x67\x49\x42'
    b'\x41\x44\x41\x4e\x42\x67\x6b\x71\x68\x6b\x69\x47\x39\x77\x30\x42\x41\x51'
    b'\x45\x46\x41\x41\x53\x43\x41\x6d\x41\x77\x67\x67\x4a\x63\x41\x67\x45\x41'
    b'\x41\x6f\x47\x42\x41\x4e\x37\x66\x45\x45\x4f\x66\x4a\x2f\x2b\x4e\x65\x6a'
    b'\x50\x58\x0a\x6e\x79\x4f\x46\x44\x61\x37\x42\x33\x65\x63\x71\x4c\x4f\x4f'
    b'\x39\x2f\x6c\x58\x62\x53\x31\x6c\x65\x2b\x70\x5a\x30\x6b\x6d\x38\x33\x39'
    b'\x4c\x48\x59\x31\x2f\x42\x70\x56\x6a\x45\x5a\x2f\x45\x4d\x4a\x4f\x76\x59'
    b'\x52\x61\x34\x36\x67\x54\x32\x37\x55\x49\x37\x76\x41\x0a\x30\x55\x73\x57'
    b'\x67\x77\x63\x4c\x36\x42\x67\x41\x58\x50\x46\x79\x67\x42\x41\x4a\x39\x69'
    b'\x35\x76\x2b\x5a\x31\x44\x30\x38\x58\x4c\x5a\x67\x79\x37\x46\x39\x32\x4d'
    b'\x33\x35\x52\x53\x69\x63\x43\x68\x65\x58\x56\x4b\x43\x35\x78\x71\x6a\x5a'
    b'\x5a\x39\x34\x46\x56\x57\x0a\x5a\x57\x57\x4e\x69\x6e\x31\x33\x77\x46\x71'
    b'\x4c\x63\x64\x33\x34\x43\x47\x61\x6d\x45\x79\x39\x48\x38\x33\x55\x5a\x41'
    b'\x67\x4d\x42\x41\x41\x45\x43\x67\x59\x45\x41\x30\x41\x77\x32\x36\x49\x6b'
    b'\x59\x45\x34\x30\x45\x4f\x49\x54\x64\x2f\x35\x42\x6a\x46\x33\x48\x4f\x0a'
    b'\x4c\x63\x37\x48\x48\x4d\x6e\x74\x4e\x45\x53\x44\x38\x43\x65\x6a\x6b\x50'
    b'\x4f\x39\x42\x71\x6d\x62\x65\x4c\x48\x4e\x30\x70\x54\x69\x61\x75\x2b\x77'
    b'\x39\x76\x73\x55\x32\x55\x4f\x6c\x76\x66\x79\x55\x61\x67\x63\x4b\x58\x47'
    b'\x68\x41\x64\x2f\x48\x4a\x32\x50\x6f\x4b\x0a\x37\x50\x62\x73\x53\x68\x34'
    b'\x33\x75\x63\x4f\x49\x64\x50\x68\x6a\x6e\x50\x34\x63\x47\x79\x44\x43\x75'
    b'\x69\x38\x78\x51\x6f\x30\x58\x6e\x69\x54\x43\x71\x34\x59\x43\x77\x4f\x6b'
    b'\x45\x42\x44\x61\x42\x78\x55\x54\x56\x4c\x68\x4d\x4a\x41\x2b\x68\x32\x66'
    b'\x46\x56\x4a\x0a\x4a\x4b\x36\x5a\x75\x44\x43\x75\x53\x54\x32\x48\x37\x56'
    b'\x61\x6a\x4f\x79\x45\x43\x51\x51\x44\x30\x46\x46\x50\x41\x62\x6c\x37\x47'
    b'\x32\x35\x39\x63\x43\x77\x56\x52\x34\x63\x49\x44\x71\x49\x78\x45\x53\x4e'
    b'\x47\x6d\x34\x39\x4a\x46\x59\x7a\x57\x74\x4f\x66\x61\x39\x0a\x4d\x53\x43'
    b'\x69\x62\x6b\x32\x66\x46\x30\x38\x62\x39\x6a\x64\x67\x4f\x62\x63\x42\x49'
    b'\x56\x61\x42\x38\x50\x6c\x45\x6f\x47\x53\x6e\x4a\x58\x38\x34\x75\x56\x4d'
    b'\x54\x73\x2f\x58\x74\x41\x6b\x45\x41\x36\x63\x47\x54\x6c\x61\x4a\x43\x68'
    b'\x4b\x73\x67\x69\x45\x67\x39\x0a\x48\x39\x54\x64\x63\x63\x72\x6b\x59\x4c'
    b'\x4e\x7a\x5a\x50\x64\x34\x58\x41\x35\x67\x2f\x4d\x78\x4c\x47\x30\x68\x58'
    b'\x38\x2f\x36\x69\x5a\x69\x76\x38\x36\x37\x65\x4b\x43\x2b\x38\x54\x36\x6f'
    b'\x2b\x44\x4d\x42\x47\x72\x7a\x2b\x30\x66\x4d\x44\x51\x4d\x35\x57\x49\x4d'
    b'\x0a\x77\x42\x76\x57\x58\x51\x4a\x41\x47\x78\x6b\x57\x6f\x30\x71\x64\x6f'
    b'\x78\x35\x47\x39\x77\x55\x53\x4e\x69\x45\x47\x56\x54\x6d\x6c\x4f\x50\x2b'
    b'\x4d\x70\x79\x61\x72\x39\x61\x41\x71\x47\x57\x31\x53\x41\x33\x63\x73\x31'
    b'\x46\x76\x43\x71\x6d\x4d\x41\x47\x57\x36\x67\x0a\x66\x30\x4a\x70\x47\x75'
    b'\x73\x45\x6d\x37\x43\x52\x50\x42\x6c\x43\x6b\x33\x77\x4b\x50\x39\x58\x7a'
    b'\x62\x30\x43\x50\x6b\x51\x4a\x41\x50\x34\x52\x71\x4a\x65\x37\x42\x52\x47'
    b'\x74\x37\x6d\x34\x79\x46\x6a\x33\x43\x33\x2b\x34\x4f\x32\x4b\x74\x43\x59'
    b'\x4f\x6f\x64\x45\x0a\x48\x54\x2b\x4b\x2b\x79\x5a\x49\x41\x6c\x48\x57\x46'
    b'\x47\x62\x4d\x6d\x68\x61\x35\x30\x78\x4d\x38\x58\x36\x48\x48\x4e\x36\x56'
    b'\x6e\x63\x46\x68\x63\x35\x31\x4c\x33\x64\x70\x47\x75\x4c\x32\x5a\x46\x4d'
    b'\x4b\x35\x66\x77\x51\x4a\x41\x50\x6c\x6c\x42\x5a\x43\x5a\x37\x0a\x67\x33'
    b'\x74\x78\x52\x56\x4b\x57\x53\x6b\x76\x38\x4b\x6b\x43\x2f\x33\x7a\x79\x6e'
    b'\x56\x32\x56\x6d\x73\x43\x33\x35\x36\x34\x5a\x43\x57\x6b\x5a\x37\x79\x68'
    b'\x4a\x49\x39\x4e\x79\x6e\x62\x76\x7a\x4d\x67\x6c\x41\x44\x67\x69\x2b\x4f'
    b'\x6e\x53\x6f\x7a\x46\x68\x73\x45\x0a\x38\x32\x55\x74\x38\x58\x64\x42\x68'
    b'\x30\x30\x76\x75\x51\x3d\x3d\x0a\x2d\x2d\x2d\x2d\x2d\x45\x4e\x44\x20\x50'
    b'\x52\x49\x56\x41\x54\x45\x20\x4b\x45\x59\x2d\x2d\x2d\x2d\x2d\x0a'
)


SIGN_TEST_DATA = (b'\x01\x02\x03\x04\x05\x06\x07\x08'
                  b'\x09\x10\x11\x12\x13\x14\x15\x16')


@pytest.fixture(
    scope='function',
    params=[
        {'digital_signature_algorithm':
            enums.DigitalSignatureAlgorithm.MD5_WITH_RSA_ENCRYPTION,
         'crypto_alg': None,
         'hash_algorithm': None,
         'padding': enums.PaddingMethod.PSS,
         'key': DER_RSA_KEY,
         'verify_args': (padding.PSS(
                             mgf=padding.MGF1(hashes.MD5()),
                             salt_length=padding.PSS.MAX_LENGTH
                         ),
                         hashes.MD5())},
        {'digital_signature_algorithm':
            enums.DigitalSignatureAlgorithm.SHA1_WITH_RSA_ENCRYPTION,
         'crypto_alg': None,
         'hash_algorithm': None,
         'padding': enums.PaddingMethod.PKCS1v15,
         'key': PEM_RSA_KEY,
         'verify_args': (padding.PKCS1v15(), hashes.SHA1())},
        {'digital_signature_algorithm':
            enums.DigitalSignatureAlgorithm.SHA224_WITH_RSA_ENCRYPTION,
         'crypto_alg': None,
         'hash_algorithm': None,
         'padding': enums.PaddingMethod.PSS,
         'key': DER_RSA_KEY,
         'verify_args': (padding.PSS(
                             mgf=padding.MGF1(hashes.SHA224()),
                             salt_length=padding.PSS.MAX_LENGTH
                         ),
                         hashes.SHA224())},
        {'digital_signature_algorithm':
            enums.DigitalSignatureAlgorithm.SHA256_WITH_RSA_ENCRYPTION,
         'crypto_alg': None,
         'hash_algorithm': None,
         'padding': enums.PaddingMethod.PKCS1v15,
         'key': PEM_RSA_KEY,
         'verify_args': (padding.PKCS1v15(), hashes.SHA256())},
        {'digital_signature_algorithm':
            enums.DigitalSignatureAlgorithm.SHA384_WITH_RSA_ENCRYPTION,
         'crypto_alg': None,
         'hash_algorithm': None,
         'padding': enums.PaddingMethod.PSS,
         'key': DER_RSA_KEY,
         'verify_args': (padding.PSS(
                             mgf=padding.MGF1(hashes.SHA384()),
                             salt_length=padding.PSS.MAX_LENGTH
                         ),
                         hashes.SHA384())},
        {'digital_signature_algorithm': None,
         'crypto_alg': enums.CryptographicAlgorithm.RSA,
         'hash_algorithm': enums.HashingAlgorithm.SHA_512,
         'padding': enums.PaddingMethod.PKCS1v15,
         'key': PEM_RSA_KEY,
         'verify_args': (padding.PKCS1v15(), hashes.SHA512())}
    ]
)
def signing_parameters(request):
    return request.param


def load_private_key(key):
    try:
        return serialization.load_der_private_key(
            key,
            password=None,
            backend=default_backend()
        )
    except Exception:
        return serialization.load_pem_private_key(
            key,
            password=None,
            backend=default_backend()
        )


def test_sign(signing_parameters):
    engine = crypto.CryptographyEngine()
    result = engine.sign(
         signing_parameters.get('digital_signature_algorithm'),
         signing_parameters.get('crypto_alg'),
         signing_parameters.get('hash_algorithm'),
         signing_parameters.get('padding'),
         signing_parameters.get('key'),
         SIGN_TEST_DATA
    )

    private_key = load_private_key(signing_parameters.get('key'))

    public_key = private_key.public_key()
    public_key.verify(
        result,
        SIGN_TEST_DATA,
        signing_parameters.get('verify_args')[0],
        signing_parameters.get('verify_args')[1]
    )


# RSA signing test vectors were obtained from pyca/cryptography:
#
# https://github.com/pyca/cryptography/blob/master/vectors/
# cryptography_vectors/asymmetric/RSA/pkcs1v15sign-vectors.txt
@pytest.fixture(
    scope='function',
    params=[
        {'signing_algorithm': enums.CryptographicAlgorithm.RSA,
         'padding_method': enums.PaddingMethod.PKCS1v15,
         'hashing_algorithm': enums.HashingAlgorithm.SHA_1,
         'digital_signature_algorithm': None,
         'encoding': serialization.Encoding.DER,
         'public_key': {
             'n': int(
                 'a56e4a0e701017589a5187dc7ea841d156f2ec0e36ad52a44dfeb1e61f7'
                 'ad991d8c51056ffedb162b4c0f283a12a88a394dff526ab7291cbb307ce'
                 'abfce0b1dfd5cd9508096d5b2b8b6df5d671ef6377c0921cb23c270a70e'
                 '2598e6ff89d19f105acc2d3f0cb35f29280e1386b6f64c4ef22e1e1f20d'
                 '0ce8cffb2249bd9a2137',
                 16
             ),
             'e': int('010001', 16)
         },
         'message': (
             b'\xcd\xc8\x7d\xa2\x23\xd7\x86\xdf'
             b'\x3b\x45\xe0\xbb\xbc\x72\x13\x26'
             b'\xd1\xee\x2a\xf8\x06\xcc\x31\x54'
             b'\x75\xcc\x6f\x0d\x9c\x66\xe1\xb6'
             b'\x23\x71\xd4\x5c\xe2\x39\x2e\x1a'
             b'\xc9\x28\x44\xc3\x10\x10\x2f\x15'
             b'\x6a\x0d\x8d\x52\xc1\xf4\xc4\x0b'
             b'\xa3\xaa\x65\x09\x57\x86\xcb\x76'
             b'\x97\x57\xa6\x56\x3b\xa9\x58\xfe'
             b'\xd0\xbc\xc9\x84\xe8\xb5\x17\xa3'
             b'\xd5\xf5\x15\xb2\x3b\x8a\x41\xe7'
             b'\x4a\xa8\x67\x69\x3f\x90\xdf\xb0'
             b'\x61\xa6\xe8\x6d\xfa\xae\xe6\x44'
             b'\x72\xc0\x0e\x5f\x20\x94\x57\x29'
             b'\xcb\xeb\xe7\x7f\x06\xce\x78\xe0'
             b'\x8f\x40\x98\xfb\xa4\x1f\x9d\x61'
             b'\x93\xc0\x31\x7e\x8b\x60\xd4\xb6'
             b'\x08\x4a\xcb\x42\xd2\x9e\x38\x08'
             b'\xa3\xbc\x37\x2d\x85\xe3\x31\x17'
             b'\x0f\xcb\xf7\xcc\x72\xd0\xb7\x1c'
             b'\x29\x66\x48\xb3\xa4\xd1\x0f\x41'
             b'\x62\x95\xd0\x80\x7a\xa6\x25\xca'
             b'\xb2\x74\x4f\xd9\xea\x8f\xd2\x23'
             b'\xc4\x25\x37\x02\x98\x28\xbd\x16'
             b'\xbe\x02\x54\x6f\x13\x0f\xd2\xe3'
             b'\x3b\x93\x6d\x26\x76\xe0\x8a\xed'
             b'\x1b\x73\x31\x8b\x75\x0a\x01\x67'
             b'\xd0'
         ),
         'signature': (
             b'\x6b\xc3\xa0\x66\x56\x84\x29\x30'
             b'\xa2\x47\xe3\x0d\x58\x64\xb4\xd8'
             b'\x19\x23\x6b\xa7\xc6\x89\x65\x86'
             b'\x2a\xd7\xdb\xc4\xe2\x4a\xf2\x8e'
             b'\x86\xbb\x53\x1f\x03\x35\x8b\xe5'
             b'\xfb\x74\x77\x7c\x60\x86\xf8\x50'
             b'\xca\xef\x89\x3f\x0d\x6f\xcc\x2d'
             b'\x0c\x91\xec\x01\x36\x93\xb4\xea'
             b'\x00\xb8\x0c\xd4\x9a\xac\x4e\xcb'
             b'\x5f\x89\x11\xaf\xe5\x39\xad\xa4'
             b'\xa8\xf3\x82\x3d\x1d\x13\xe4\x72'
             b'\xd1\x49\x05\x47\xc6\x59\xc7\x61'
             b'\x7f\x3d\x24\x08\x7d\xdb\x6f\x2b'
             b'\x72\x09\x61\x67\xfc\x09\x7c\xab'
             b'\x18\xe9\xa4\x58\xfc\xb6\x34\xcd'
             b'\xce\x8e\xe3\x58\x94\xc4\x84\xd7'
         )},
        {'signing_algorithm': None,
         'padding_method': enums.PaddingMethod.PSS,
         'hashing_algorithm': None,
         'digital_signature_algorithm':
             enums.DigitalSignatureAlgorithm.SHA1_WITH_RSA_ENCRYPTION,
         'encoding': serialization.Encoding.PEM,
         'public_key': {
             'n': int(
                 'ac13d9fdae7b7335b69cd98567e9647d99bf373a9e05ce3435d66465f32'
                 '8b7f7334b792aee7efa044ebc4c7a30b21a5d7a89cdb3a30dfcd9fee999'
                 '5e09415edc0bf9e5b4c3f74ff53fb4d29441bf1b7ed6cbdd4a47f925226'
                 '9e1646f6c1aee0514e93f6cb9df71d06c060a2104b47b7260ac37c10686'
                 '1dc78ca5a25faa9cb2e3',
                 16
             ),
             'e': int('010001', 16)
         },
         'message': (
             b'\xe1\xc0\xf9\x8d\x53\xf8\xf8\xb1'
             b'\x41\x90\x57\xd5\xb9\xb1\x0b\x07'
             b'\xfe\xea\xec\x32\xc0\x46\x3a\x4d'
             b'\x68\x38\x2f\x53\x1b\xa1\xd6\xcf'
             b'\xe4\xed\x38\xa2\x69\x4a\x34\xb9'
             b'\xc8\x05\xad\xf0\x72\xff\xbc\xeb'
             b'\xe2\x1d\x8d\x4b\x5c\x0e\x8c\x33'
             b'\x45\x2d\xd8\xf9\xc9\xbf\x45\xd1'
             b'\xe6\x33\x75\x11\x33\x58\x82\x29'
             b'\xd2\x93\xc6\x49\x6b\x7c\x98\x3c'
             b'\x2c\x72\xbd\x21\xd3\x39\x27\x2d'
             b'\x78\x28\xb0\xd0\x9d\x01\x0b\xba'
             b'\xd3\x18\xd9\x98\xf7\x04\x79\x67'
             b'\x33\x8a\xce\xfd\x01\xe8\x74\xac'
             b'\xe5\xf8\x6d\x2a\x60\xf3\xb3\xca'
             b'\xe1\x3f\xc5\xc6\x65\x08\xcf\xb7'
             b'\x23\x78\xfd\xd6\xc8\xde\x24\x97'
             b'\x65\x10\x3c\xe8\xfe\x7c\xd3\x3a'
             b'\xd0\xef\x16\x86\xfe\xb2\x5e\x6a'
             b'\x35\xfb\x64\xe0\x96\xa4'
         ),
         'signature': (
             b'\x01\xf6\xe5\xff\x04\x22\x1a\xdc'
             b'\x6c\x2f\x22\xa7\x61\x05\x3b\xc4'
             b'\x73\x27\x65\xdd\xdc\x3f\x76\x56'
             b'\xd0\xd1\x22\xad\x3b\x8a\x4e\x4f'
             b'\x8f\xe5\x5b\xd0\xc0\x9e\xb1\x07'
             b'\x80\xa1\x39\xcd\xa9\x32\x34\xef'
             b'\x98\x8f\xe2\x50\x20\x1e\xb2\xfe'
             b'\xbd\x08\xb6\xee\x85\xd7\x0d\x16'
             b'\x05\xa5\xba\x56\x85\x21\x52\x99'
             b'\xf0\x74\xc8\x0b\xaf\xf8\x1e\x2c'
             b'\xa3\x10\x7d\xa9\x17\x5c\x2f\x5a'
             b'\x7c\x6b\x60\xea\xa2\x8a\x75\x8c'
             b'\xa9\x34\xf2\xff\x16\x98\x8f\xe8'
             b'\x5f\xf8\x41\x57\xd9\x51\x44\x8a'
             b'\x85\xec\x1e\xd1\x71\xf9\xef\x8b'
             b'\xb8\xa1\x0c\xfa\x14\x7b\x7e\xf8'
         )}
    ]
)
def signature_parameters(request):
    return request.param


def test_verify_signature(signature_parameters):
    """
    Test that various signature verification methods and settings can be used
    to correctly verify signatures.
    """
    engine = crypto.CryptographyEngine()

    backend = backends.default_backend()
    public_key_numbers = rsa.RSAPublicNumbers(
        signature_parameters.get('public_key').get('e'),
        signature_parameters.get('public_key').get('n')
    )
    public_key = public_key_numbers.public_key(backend)
    public_bytes = public_key.public_bytes(
        signature_parameters.get('encoding'),
        serialization.PublicFormat.PKCS1
    )

    result = engine.verify_signature(
        signing_key=public_bytes,
        message=signature_parameters.get('message'),
        signature=signature_parameters.get('signature'),
        padding_method=signature_parameters.get('padding_method'),
        signing_algorithm=signature_parameters.get('signing_algorithm'),
        hashing_algorithm=signature_parameters.get('hashing_algorithm'),
        digital_signature_algorithm=signature_parameters.get(
            'digital_signature_algorithm'
        )
    )

    assert result
