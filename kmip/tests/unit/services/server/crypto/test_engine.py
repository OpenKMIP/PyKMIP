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

from cryptography.hazmat.primitives.ciphers import algorithms

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

    def test_encrypt_invalid_algorithm(self):
        """
        Test that the right errors are raised when invalid encryption
        algorithms are used.
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

    def test_encrypt_invalid_algorithm_key(self):
        """
        Test that the right error is raised when an invalid key is used with
        an encryption algorithm.
        """
        engine = crypto.CryptographyEngine()

        args = (enums.CryptographicAlgorithm.AES, b'', b'')
        self.assertRaisesRegexp(
            exceptions.CryptographicFailure,
            "Invalid key bytes for the specified encryption algorithm.",
            engine.encrypt,
            *args
        )

    def test_encrypt_no_mode_needed(self):
        """
        Test that data can be encrypted for certain inputs without a cipher
        mode.
        """
        engine = crypto.CryptographyEngine()

        engine.encrypt(
            enums.CryptographicAlgorithm.RC4,
            b'\x00\x01\x02\x03\x04\x05\x06\x07',
            b'\x0F\x0E\x0D\x0C\x0B\x0A\x09\x08'
        )

    def test_encrypt_invalid_cipher_mode(self):
        """
        Test that the right errors are raised when invalid cipher modes are
        used.
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

    def test_encrypt_generate_iv(self):
        """
        Test that the initialization vector is correctly generated and
        returned for an appropriate set of encryption inputs.
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

    def test_decrypt_invalid_algorithm(self):
        """
        Test that the right errors are raised when invalid decryption
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

    def test_decrypt_invalid_algorithm_key(self):
        """
        Test that the right error is raised when an invalid key is used with
        a decryption algorithm.
        """
        engine = crypto.CryptographyEngine()

        args = (enums.CryptographicAlgorithm.AES, b'', b'')
        self.assertRaisesRegexp(
            exceptions.CryptographicFailure,
            "Invalid key bytes for the specified decryption algorithm.",
            engine.decrypt,
            *args
        )

    def test_decrypt_invalid_cipher_mode(self):
        """
        Test that the right errors are raised when invalid cipher modes are
        used.
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

    def test_decrypt_missing_iv_nonce(self):
        """
        Test that the right error is raised when an IV/nonce is not provided
        for the decryption algorithm.
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
def encrypt_parameters(request):
    return request.param


def test_encrypt(encrypt_parameters):
    """
    Test that various encryption algorithms and block cipher modes can be
    used to correctly encrypt data.
    """

    engine = crypto.CryptographyEngine()

    engine._handle_symmetric_padding = mock.MagicMock(
        return_value=encrypt_parameters.get('plain_text')
    )

    result = engine.encrypt(
        encrypt_parameters.get('algorithm'),
        encrypt_parameters.get('key'),
        encrypt_parameters.get('plain_text'),
        cipher_mode=encrypt_parameters.get('cipher_mode'),
        iv_nonce=encrypt_parameters.get('iv_nonce')
    )

    if engine._handle_symmetric_padding.called:
        engine._handle_symmetric_padding.assert_called_once_with(
            engine._symmetric_key_algorithms.get(
                encrypt_parameters.get('algorithm')
            ),
            encrypt_parameters.get('plain_text'),
            None
        )

    assert encrypt_parameters.get('cipher_text') == result.get('cipher_text')


def test_decrypt(encrypt_parameters):
    """
    Test that various decryption algorithms and block cipher modes can be
    used to correctly decrypt data.
    """
    engine = crypto.CryptographyEngine()

    engine._handle_symmetric_padding = mock.MagicMock(
        return_value=encrypt_parameters.get('plain_text')
    )

    result = engine.decrypt(
        encrypt_parameters.get('algorithm'),
        encrypt_parameters.get('key'),
        encrypt_parameters.get('cipher_text'),
        cipher_mode=encrypt_parameters.get('cipher_mode'),
        iv_nonce=encrypt_parameters.get('iv_nonce')
    )

    if engine._handle_symmetric_padding.called:
        engine._handle_symmetric_padding.assert_called_once_with(
            engine._symmetric_key_algorithms.get(
                encrypt_parameters.get('algorithm')
            ),
            encrypt_parameters.get('plain_text'),
            None,
            undo_padding=True
        )

    assert encrypt_parameters.get('plain_text') == result


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
