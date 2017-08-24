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

import binascii
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

        # IDEA is not block cipher so cmac should raise exception
        args = [enums.CryptographicAlgorithm.IDEA, key, data]
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
        self.assertRaisesRegexp(
            exceptions.InvalidField,
            "Encryption algorithm is required.",
            engine.encrypt,
            *args
        )

        args = ('invalid', b'', b'')
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
            exceptions.InvalidField,
            "Cipher mode is required.",
            engine.encrypt,
            *args
        )

        kwargs = {'cipher_mode': 'invalid'}
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
            exceptions.InvalidField,
            "Decryption algorithm is required.",
            engine.decrypt,
            *args
        )

        args = ('invalid', b'', b'')
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
            exceptions.InvalidField,
            "Cipher mode is required.",
            engine.decrypt,
            *args
        )

        kwargs = {'cipher_mode': 'invalid'}
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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

        self.assertRaisesRegexp(
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

        self.assertRaisesRegexp(
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

        self.assertRaisesRegexp(
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

        self.assertRaisesRegexp(
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

        self.assertRaisesRegexp(
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

        self.assertRaisesRegexp(
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

        self.assertRaisesRegexp(
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

        self.assertRaisesRegexp(
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

        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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

        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        iv_nonce=symmetric_parameters.get('iv_nonce')
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
        iv_nonce=symmetric_parameters.get('iv_nonce')
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


DER_RSA_KEY = ('3082025e02010002818100aebac1b9a174315d27cc3c201e215789'
               '4372d6450d4cf80ce0ebcf5169519b9e8550036f4abe0fe4f94fbf'
               '9cca606f39743365499611ba3f25a9a47158ba05214b655f4258a4'
               'c29516becaa583f2d26650696ad6fc03d5b47d3aba9c5479fdb047'
               '7d29513399cb19283ccdc28dbb23b7c7eee4b35dc940daca0055dc'
               'd28f503b02030100010281810092890942d6c68d47a4c2c181e602'
               'ec58af7a357c7fa5173a25bf5d84d7209bb41bf5788bf350e61f8f'
               '7e7421d80f7bf7e11de14a0f531ab12eb2d0b84642eb5d181170c2'
               'c58aabbd6754842fafee57fef2f545d09fdc664902e55baced5a3c'
               '6d26f3465859d33a33a555537daf2263aaef28354c8b53513145a7'
               'e228824dabb1024100d3aa237e8942b93d56a681254c27be1f4a49'
               '6ca4a87fc0604b0cff8f980e742d2bbb91b88a247b6ebbed01458c'
               '4afdb68c0f8c6d4a37e028c5fcb3a6a39ca64f024100d354168c61'
               '9c836e8597fef50193a6f42607952a1c87ebae91db5043b8855072'
               'b4e92af5dcedb2148773dfbd217bafc8dc9da8ae8e757e7248c1e5'
               '13a144685502410090fda214c2b7b726825dca679f3436333ef2ee'
               'fe180272e84360e30b1d11019a13b4080d0e6c1135787bd07c30af'
               '09feeb10979421dc06ac477b6420c940bc570240164de8b7565213'
               '9925a67e3553be46bfbc07ced98bfb5887ab434f7c664c43ca6787'
               'b88e0c8c55e04ecf8f0cc22cf0c7ad69427571f9baa7cb4013b277'
               'b1e5a5024100cae150f5fa559b2e2c39444e0f5c651034092ac97b'
               'ac10d528dd15dfda254cb06bef41e39881f7e7496910b4655659dc'
               '842d30b9ae2759f3c2cd41c79a3684ec')

PEM_RSA_KEY = ('2d2d2d2d2d424547494e205253412050524956415445204b45592d'
               '2d2d2d2d0a4d4949435867494241414b4267514375757347356f58'
               '51785853664d504341654956654a51334c575251314d2b417a6736'
               '383952615647626e6f56514132394b0a76672f6b2b552b2f6e4d70'
               '67627a6c304d32564a6c6847365079577070484659756755685332'
               '5666516c696b777055577673716c672f4c535a6c4270617462380a'
               '41395730665471366e4652352f62424866536c524d356e4c475367'
               '387a634b4e75794f33782b376b7331334a514e724b41465863306f'
               '39514f774944415141420a416f4742414a4b4a43554c57786f3148'
               '704d4c426765594337466976656a5638663655584f69572f585954'
               '58494a7530472f5634692f4e5135682b50666e51680a3241393739'
               '2b456434556f50557871784c724c5175455a433631305945584443'
               '785971727657645568432b76376c662b38765646304a2f635a6b6b'
               '43355675730a37566f386253627a526c685a307a6f7a7056565466'
               '613869593672764b44564d69314e524d55576e3469694354617578'
               '416b454130366f6a666f6c43755431570a706f456c5443652b4830'
               '704a624b536f6638426753777a2f6a35674f644330727535473469'
               '695237627276744155574d537632326a412b4d62556f3334436a46'
               '0a2f4c4f6d6f35796d54774a42414e4e55466f78686e494e75685a'
               '662b395147547076516d42355571484966727270486255454f3468'
               '564279744f6b7139647a740a7368534863392b3949587576794e79'
               '64714b364f64583579534d486c4536464561465543515143512f61'
               '4955777265334a6f4a64796d65664e44597a50764c750a2f686743'
               '63756844594f4d4c485245426d684f304341304f62424531654876'
               '516644437643663772454a655549647747724564375a43444a514c'
               '7858416b41570a54656933566c49546d53576d666a5654766b612f'
               '7641664f3259763757496572513039385a6b7844796d6548754934'
               '4d6a46586754732b50444d4973384d65740a61554a3163666d3670'
               '38744145374a337365576c416b454179754651396670566d793473'
               '4f55524f4431786c4544514a4b736c37724244564b4e305633396f'
               '6c0a544c42723730486a6d49483335306c70454c526c566c6e6368'
               '4330777561346e576650437a5548486d6a614537413d3d0a2d2d2d'
               '2d2d454e44205253412050524956415445204b45592d2d2d2d2d0a')

RSA_private_key = serialization.load_der_private_key(
    binascii.unhexlify(DER_RSA_KEY),
    password=None,
    backend=default_backend()
)

RSA_public_key = RSA_private_key.public_key()

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

    RSA_public_key.verify(
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
