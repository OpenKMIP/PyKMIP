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


@pytest.fixture(
    scope='function',
    params=[
        {'algorithm': algorithms.AES,
         'plain_text': b'\x48\x65\x6C\x6C\x6F',
         'padding_method': enums.PaddingMethod.PKCS5,
         'result': (
             b'\x48\x65\x6C\x6C\x6F\x0B\x0B\x0B'
             b'\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B'
         )},
        {'algorithm': algorithms.TripleDES,
         'plain_text': b'\x48\x65\x6C\x6C\x6F',
         'padding_method': enums.PaddingMethod.ANSI_X923,
         'result': b'\x48\x65\x6C\x6C\x6F\x00\x00\x03'}
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

    assert result == symmetric_padding_parameters.get('result')
