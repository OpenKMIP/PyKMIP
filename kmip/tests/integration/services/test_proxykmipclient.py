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

import testtools
import time
import pytest

from kmip.core import enums
from kmip.core.factories import attributes as attribute_factory

from kmip.pie import exceptions
from kmip.pie import factory
from kmip.pie import objects

@pytest.mark.usefixtures("simple")
class TestProxyKmipClientIntegration(testtools.TestCase):

    def setUp(self):
        super(TestProxyKmipClientIntegration, self).setUp()
        self.object_factory = factory.ObjectFactory()
        self.attribute_factory = attribute_factory.AttributeFactory()

    def tearDown(self):
        super(TestProxyKmipClientIntegration, self).tearDown()

        uuids = self.client.locate()
        for uuid in uuids:
            self.client.revoke(enums.RevocationReasonCode.KEY_COMPROMISE, uuid)
            self.client.destroy(uid=uuid)

    def test_symmetric_key_create_get_destroy(self):
        """
        Test that the ProxyKmipClient can create, retrieve, and destroy a
        symmetric key.
        """
        uid = self.client.create(enums.CryptographicAlgorithm.AES, 256)
        self.assertIsInstance(uid, str)

        try:
            key = self.client.get(uid)
            self.assertIsInstance(key, objects.SymmetricKey)
            self.assertEqual(
                key.cryptographic_algorithm,
                enums.CryptographicAlgorithm.AES)
            self.assertEqual(key.cryptographic_length, 256)
        finally:
            self.client.revoke(enums.RevocationReasonCode.KEY_COMPROMISE, uid)
            self.client.destroy(uid)
            self.assertRaises(
                exceptions.KmipOperationFailure, self.client.get, uid)
            self.assertRaises(
                exceptions.KmipOperationFailure, self.client.destroy, uid)

    def test_create_get_wrapped_destroy(self):
        """
        Test that the ProxyKmipClient can create keys, retrieve a wrapped key,
        and then destroy the keys for cleanup.
        """
        key_id = self.client.create(enums.CryptographicAlgorithm.AES, 256)
        wrapping_id = self.client.create(
            enums.CryptographicAlgorithm.AES,
            256,
            cryptographic_usage_mask=[
                enums.CryptographicUsageMask.WRAP_KEY,
                enums.CryptographicUsageMask.UNWRAP_KEY,
                enums.CryptographicUsageMask.ENCRYPT,
                enums.CryptographicUsageMask.DECRYPT
            ]
        )

        self.client.activate(wrapping_id)

        unwrapped_key = self.client.get(key_id)
        wrapped_key = self.client.get(
            key_id,
            key_wrapping_specification={
                'wrapping_method': enums.WrappingMethod.ENCRYPT,
                'encryption_key_information': {
                    'unique_identifier': wrapping_id,
                    'cryptographic_parameters': {
                        'block_cipher_mode':
                            enums.BlockCipherMode.NIST_KEY_WRAP
                    }
                },
                'encoding_option': enums.EncodingOption.NO_ENCODING
            }
        )

        self.assertNotEqual(unwrapped_key.value, wrapped_key.value)

        self.client.revoke(enums.RevocationReasonCode.KEY_COMPROMISE, key_id)
        self.client.revoke(enums.RevocationReasonCode.KEY_COMPROMISE,
                           wrapping_id)
        self.client.destroy(key_id)
        self.client.destroy(wrapping_id)

    def test_symmetric_key_register_get_destroy(self):
        """
        Test that the ProxyKmipClient can register, retrieve, and destroy a
        symmetric key.
        """
        # Key encoding obtained from Section 14.2 of the KMIP 1.1 test
        # documentation.
        key = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            128,
            (b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E'
             b'\x0F'),
            name="Test Symmetric Key"
        )

        uid = self.client.register(key)
        self.assertIsInstance(uid, str)

        try:
            result = self.client.get(uid)
            self.assertIsInstance(result, objects.SymmetricKey)
            self.assertEqual(
                result, key, "expected {0}\nobserved {1}".format(result, key))
        finally:
            self.client.revoke(enums.RevocationReasonCode.KEY_COMPROMISE, uid)
            self.client.destroy(uid)
            self.assertRaises(
                exceptions.KmipOperationFailure, self.client.get, uid)
            self.assertRaises(
                exceptions.KmipOperationFailure, self.client.destroy, uid)

    def test_register_wrapped_get_destroy(self):
        """
        Test that a wrapped key can be registered with the server and that its
        metadata is retrieved with the get operation.
        """
        key = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            128,
            (b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E'
             b'\x0F'),
            key_wrapping_data={
                'wrapping_method': enums.WrappingMethod.ENCRYPT,
                'encryption_key_information': {
                    'unique_identifier': '42',
                    'cryptographic_parameters': {
                        'block_cipher_mode':
                            enums.BlockCipherMode.NIST_KEY_WRAP
                    }
                },
                'encoding_option': enums.EncodingOption.NO_ENCODING
            }
        )
        key_id = self.client.register(key)

        result = self.client.get(key_id)
        key_wrapping_data = result.key_wrapping_data
        self.assertIsInstance(key_wrapping_data, dict)
        self.assertEqual(
            enums.WrappingMethod.ENCRYPT,
            key_wrapping_data.get('wrapping_method')
        )
        eki = key_wrapping_data.get('encryption_key_information')
        self.assertIsInstance(eki, dict)
        self.assertEqual('42', eki.get('unique_identifier'))
        cp = eki.get('cryptographic_parameters')
        self.assertIsInstance(cp, dict)
        self.assertEqual(
            enums.BlockCipherMode.NIST_KEY_WRAP,
            cp.get('block_cipher_mode')
        )
        self.assertEqual(
            enums.EncodingOption.NO_ENCODING,
            key_wrapping_data.get('encoding_option')
        )
        self.client.revoke(enums.RevocationReasonCode.KEY_COMPROMISE, key_id)
        self.client.destroy(key_id)

    def test_register_app_specific_get(self):
        """
        Test that a key with app specifc info can be registered with the
        server and that its metadata is retrieved with the get operation.
        """
        key = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            128,
            (b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E'
             b'\x0F'),
            app_specific_info=[
                {
                    'application_namespace': 'Testing',
                    'application_data': 'Testing2'
                },
                {
                    'application_namespace': 'Testing3',
                    'application_data': 'Testing4'
                }
            ]
        )
        key_id = self.client.register(key)
        attribute_list = self.client.get_attribute_list(key_id)
        self.assertIn('Application Specific Information', attribute_list)
        result_id, attribute_list = self.client.get_attributes(
            uid=key_id,
            attribute_names=['Application Specific Information']
        )
        self.assertEqual(key_id, result_id)

        attribute = attribute_list[0]
        self.assertEqual(
            'Application Specific Information',
            attribute.attribute_name.value
        )
        self.assertEqual(
            'Testing',
            attribute.attribute_value.application_namespace
        )
        self.assertEqual(
            'Testing2',
            attribute.attribute_value.application_data
        )

        attribute2 = attribute_list[1]
        self.assertEqual(
            'Application Specific Information',
            attribute2.attribute_name.value
        )
        self.assertEqual(
            'Testing3',
            attribute2.attribute_value.application_namespace
        )
        self.assertEqual(
            'Testing4',
            attribute2.attribute_value.application_data
        )

        self.client.revoke(enums.RevocationReasonCode.KEY_COMPROMISE, key_id)
        self.client.destroy(key_id)

    def test_asymmetric_key_pair_create_get_destroy(self):
        """
        Test that the ProxyKmipClient can create, retrieve, and destroy an
        asymmetric key pair.
        """
        public_uid, private_uid = self.client.create_key_pair(
            enums.CryptographicAlgorithm.RSA,
            2048,
            public_usage_mask=[enums.CryptographicUsageMask.ENCRYPT],
            private_usage_mask=[enums.CryptographicUsageMask.DECRYPT]
        )
        self.assertIsInstance(public_uid, str)
        self.assertIsInstance(private_uid, str)

        try:
            public_key = self.client.get(public_uid)
            self.assertIsInstance(public_key, objects.PublicKey)
            self.assertEqual(
                public_key.cryptographic_algorithm,
                enums.CryptographicAlgorithm.RSA)
            self.assertEqual(public_key.cryptographic_length, 2048)

            private_key = self.client.get(private_uid)
            self.assertIsInstance(private_key, objects.PrivateKey)
            self.assertEqual(
                private_key.cryptographic_algorithm,
                enums.CryptographicAlgorithm.RSA)
            self.assertEqual(private_key.cryptographic_length, 2048)
        finally:
            self.client.revoke(enums.RevocationReasonCode.KEY_COMPROMISE,
                               public_uid)
            self.client.destroy(public_uid)
            self.assertRaises(
                exceptions.KmipOperationFailure, self.client.get, public_uid)
            self.assertRaises(
                exceptions.KmipOperationFailure, self.client.destroy,
                public_uid)

            self.client.revoke(enums.RevocationReasonCode.KEY_COMPROMISE,
                               private_uid)
            self.client.destroy(private_uid)
            self.assertRaises(
                exceptions.KmipOperationFailure, self.client.get, private_uid)
            self.assertRaises(
                exceptions.KmipOperationFailure, self.client.destroy,
                private_uid)

    def test_public_key_register_get_destroy(self):
        """
        Test that the ProxyKmipClient can register, retrieve, and destroy a
        public key.
        """
        # Key encoding obtained from Section 13.4 of the KMIP 1.1 test
        # documentation.
        key = objects.PublicKey(
            enums.CryptographicAlgorithm.RSA,
            2048,
            (b'\x30\x82\x01\x0A\x02\x82\x01\x01\x00\xAB\x7F\x16\x1C\x00\x42'
             b'\x49\x6C\xCD\x6C\x6D\x4D\xAD\xB9\x19\x97\x34\x35\x35\x77\x76'
             b'\x00\x3A\xCF\x54\xB7\xAF\x1E\x44\x0A\xFB\x80\xB6\x4A\x87\x55'
             b'\xF8\x00\x2C\xFE\xBA\x6B\x18\x45\x40\xA2\xD6\x60\x86\xD7\x46'
             b'\x48\x34\x6D\x75\xB8\xD7\x18\x12\xB2\x05\x38\x7C\x0F\x65\x83'
             b'\xBC\x4D\x7D\xC7\xEC\x11\x4F\x3B\x17\x6B\x79\x57\xC4\x22\xE7'
             b'\xD0\x3F\xC6\x26\x7F\xA2\xA6\xF8\x9B\x9B\xEE\x9E\x60\xA1\xD7'
             b'\xC2\xD8\x33\xE5\xA5\xF4\xBB\x0B\x14\x34\xF4\xE7\x95\xA4\x11'
             b'\x00\xF8\xAA\x21\x49\x00\xDF\x8B\x65\x08\x9F\x98\x13\x5B\x1C'
             b'\x67\xB7\x01\x67\x5A\xBD\xBC\x7D\x57\x21\xAA\xC9\xD1\x4A\x7F'
             b'\x08\x1F\xCE\xC8\x0B\x64\xE8\xA0\xEC\xC8\x29\x53\x53\xC7\x95'
             b'\x32\x8A\xBF\x70\xE1\xB4\x2E\x7B\xB8\xB7\xF4\xE8\xAC\x8C\x81'
             b'\x0C\xDB\x66\xE3\xD2\x11\x26\xEB\xA8\xDA\x7D\x0C\xA3\x41\x42'
             b'\xCB\x76\xF9\x1F\x01\x3D\xA8\x09\xE9\xC1\xB7\xAE\x64\xC5\x41'
             b'\x30\xFB\xC2\x1D\x80\xE9\xC2\xCB\x06\xC5\xC8\xD7\xCC\xE8\x94'
             b'\x6A\x9A\xC9\x9B\x1C\x28\x15\xC3\x61\x2A\x29\xA8\x2D\x73\xA1'
             b'\xF9\x93\x74\xFE\x30\xE5\x49\x51\x66\x2A\x6E\xDA\x29\xC6\xFC'
             b'\x41\x13\x35\xD5\xDC\x74\x26\xB0\xF6\x05\x02\x03\x01\x00\x01'),
            enums.KeyFormatType.PKCS_1)

        uid = self.client.register(key)
        self.assertIsInstance(uid, str)

        try:
            result = self.client.get(uid)
            self.assertIsInstance(result, objects.PublicKey)
            self.assertEqual(
                result, key, "expected {0}\nobserved {1}".format(result, key))
        finally:
            self.client.revoke(enums.RevocationReasonCode.KEY_COMPROMISE, uid)
            self.client.destroy(uid)
            self.assertRaises(
                exceptions.KmipOperationFailure, self.client.get, uid)
            self.assertRaises(
                exceptions.KmipOperationFailure, self.client.destroy, uid)

    def test_private_key_register_get_destroy(self):
        """
        Test that the ProxyKmipClient can register, retrieve, and destroy a
        private key.
        """
        # Key encoding obtained from Section 13.4 of the KMIP 1.1 test
        # documentation.
        key = objects.PrivateKey(
            enums.CryptographicAlgorithm.RSA,
            2048,
            (b'\x30\x82\x04\xA5\x02\x01\x00\x02\x82\x01\x01\x00\xAB\x7F\x16'
             b'\x1C\x00\x42\x49\x6C\xCD\x6C\x6D\x4D\xAD\xB9\x19\x97\x34\x35'
             b'\x35\x77\x76\x00\x3A\xCF\x54\xB7\xAF\x1E\x44\x0A\xFB\x80\xB6'
             b'\x4A\x87\x55\xF8\x00\x2C\xFE\xBA\x6B\x18\x45\x40\xA2\xD6\x60'
             b'\x86\xD7\x46\x48\x34\x6D\x75\xB8\xD7\x18\x12\xB2\x05\x38\x7C'
             b'\x0F\x65\x83\xBC\x4D\x7D\xC7\xEC\x11\x4F\x3B\x17\x6B\x79\x57'
             b'\xC4\x22\xE7\xD0\x3F\xC6\x26\x7F\xA2\xA6\xF8\x9B\x9B\xEE\x9E'
             b'\x60\xA1\xD7\xC2\xD8\x33\xE5\xA5\xF4\xBB\x0B\x14\x34\xF4\xE7'
             b'\x95\xA4\x11\x00\xF8\xAA\x21\x49\x00\xDF\x8B\x65\x08\x9F\x98'
             b'\x13\x5B\x1C\x67\xB7\x01\x67\x5A\xBD\xBC\x7D\x57\x21\xAA\xC9'
             b'\xD1\x4A\x7F\x08\x1F\xCE\xC8\x0B\x64\xE8\xA0\xEC\xC8\x29\x53'
             b'\x53\xC7\x95\x32\x8A\xBF\x70\xE1\xB4\x2E\x7B\xB8\xB7\xF4\xE8'
             b'\xAC\x8C\x81\x0C\xDB\x66\xE3\xD2\x11\x26\xEB\xA8\xDA\x7D\x0C'
             b'\xA3\x41\x42\xCB\x76\xF9\x1F\x01\x3D\xA8\x09\xE9\xC1\xB7\xAE'
             b'\x64\xC5\x41\x30\xFB\xC2\x1D\x80\xE9\xC2\xCB\x06\xC5\xC8\xD7'
             b'\xCC\xE8\x94\x6A\x9A\xC9\x9B\x1C\x28\x15\xC3\x61\x2A\x29\xA8'
             b'\x2D\x73\xA1\xF9\x93\x74\xFE\x30\xE5\x49\x51\x66\x2A\x6E\xDA'
             b'\x29\xC6\xFC\x41\x13\x35\xD5\xDC\x74\x26\xB0\xF6\x05\x02\x03'
             b'\x01\x00\x01\x02\x82\x01\x00\x3B\x12\x45\x5D\x53\xC1\x81\x65'
             b'\x16\xC5\x18\x49\x3F\x63\x98\xAA\xFA\x72\xB1\x7D\xFA\x89\x4D'
             b'\xB8\x88\xA7\xD4\x8C\x0A\x47\xF6\x25\x79\xA4\xE6\x44\xF8\x6D'
             b'\xA7\x11\xFE\xC8\x50\xCD\xD9\xDB\xBD\x17\xF6\x9A\x44\x3D\x2E'
             b'\xC1\xDD\x60\xD3\xC6\x18\xFA\x74\xCD\xE5\xFD\xAF\xAB\xD6\xBA'
             b'\xA2\x6E\xB0\xA3\xAD\xB4\xDE\xF6\x48\x0F\xB1\x21\x8C\xD3\xB0'
             b'\x83\xE2\x52\xE8\x85\xB6\xF0\x72\x9F\x98\xB2\x14\x4D\x2B\x72'
             b'\x29\x3E\x1B\x11\xD7\x33\x93\xBC\x41\xF7\x5B\x15\xEE\x3D\x75'
             b'\x69\xB4\x99\x5E\xD1\xA1\x44\x25\xDA\x43\x19\xB7\xB2\x6B\x0E'
             b'\x8F\xEF\x17\xC3\x75\x42\xAE\x5C\x6D\x58\x49\xF8\x72\x09\x56'
             b'\x7F\x39\x25\xA4\x7B\x01\x6D\x56\x48\x59\x71\x7B\xC5\x7F\xCB'
             b'\x45\x22\xD0\xAA\x49\xCE\x81\x6E\x5B\xE7\xB3\x08\x81\x93\x23'
             b'\x6E\xC9\xEF\xFF\x14\x08\x58\x04\x5B\x73\xC5\xD7\x9B\xAF\x38'
             b'\xF7\xC6\x7F\x04\xC5\xDC\xF0\xE3\x80\x6A\xD9\x82\xD1\x25\x90'
             b'\x58\xC3\x47\x3E\x84\x71\x79\xA8\x78\xF2\xC6\xB3\xBD\x96\x8F'
             b'\xB9\x9E\xA4\x6E\x91\x85\x89\x2F\x36\x76\xE7\x89\x65\xC2\xAE'
             b'\xD4\x87\x7B\xA3\x91\x7D\xF0\x7C\x5E\x92\x74\x74\xF1\x9E\x76'
             b'\x4B\xA6\x1D\xC3\x8D\x63\xBF\x29\x02\x81\x81\x00\xD5\xC6\x9C'
             b'\x8C\x3C\xDC\x24\x64\x74\x4A\x79\x37\x13\xDA\xFB\x9F\x1D\xBC'
             b'\x79\x9F\xF9\x64\x23\xFE\xCD\x3C\xBA\x79\x42\x86\xBC\xE9\x20'
             b'\xF4\xB5\xC1\x83\xF9\x9E\xE9\x02\x8D\xB6\x21\x2C\x62\x77\xC4'
             b'\xC8\x29\x7F\xCF\xBC\xE7\xF7\xC2\x4C\xA4\xC5\x1F\xC7\x18\x2F'
             b'\xB8\xF4\x01\x9F\xB1\xD5\x65\x96\x74\xC5\xCB\xE6\xD5\xFA\x99'
             b'\x20\x51\x34\x17\x60\xCD\x00\x73\x57\x29\xA0\x70\xA9\xE5\x4D'
             b'\x34\x2B\xEB\xA8\xEF\x47\xEE\x82\xD3\xA0\x1B\x04\xCE\xC4\xA0'
             b'\x0D\x4D\xDB\x41\xE3\x51\x16\xFC\x22\x1E\x85\x4B\x43\xA6\x96'
             b'\xC0\xE6\x41\x9B\x1B\x02\x81\x81\x00\xCD\x5E\xA7\x70\x27\x89'
             b'\x06\x4B\x67\x35\x40\xCB\xFF\x09\x35\x6A\xD8\x0B\xC3\xD5\x92'
             b'\x81\x2E\xBA\x47\x61\x0B\x9F\xAC\x6A\xEC\xEF\xE2\x2A\xCA\xE4'
             b'\x38\x45\x9C\xDA\x74\xE5\x96\x53\xD8\x8C\x04\x18\x9D\x34\x39'
             b'\x9B\xF5\xB1\x4B\x92\x0E\x34\xEF\x38\xA7\xD0\x9F\xE6\x95\x93'
             b'\x39\x6E\x8F\xE7\x35\xE6\xF0\xA6\xAE\x49\x90\x40\x10\x41\xD8'
             b'\xA4\x06\xB6\xFD\x86\xA1\x16\x1E\x45\xF9\x5A\x3E\xAA\x5C\x10'
             b'\x12\xE6\x66\x2E\x44\xF1\x5F\x33\x5A\xC9\x71\xE1\x76\x6B\x2B'
             b'\xB9\xC9\x85\x10\x99\x74\x14\x1B\x44\xD3\x7E\x1E\x31\x98\x20'
             b'\xA5\x5F\x02\x81\x81\x00\xB2\x87\x12\x37\xBF\x9F\xAD\x38\xC3'
             b'\x31\x6A\xB7\x87\x7A\x6A\x86\x80\x63\xE5\x42\xA7\x18\x6D\x43'
             b'\x1E\x8D\x27\xC1\x9A\xC0\x41\x45\x84\x03\x39\x42\xE9\xFF\x6E'
             b'\x29\x73\xBB\x7B\x2D\x8B\x0E\x94\xAD\x1E\xE8\x21\x58\x10\x8F'
             b'\xBC\x86\x64\x51\x7A\x5A\x46\x7F\xB9\x63\x01\x4B\xD5\xDC\xC2'
             b'\xB4\xFB\x08\x7C\x23\x03\x9D\x11\x92\x0D\xBE\x22\xFD\x9F\x16'
             b'\xB4\xD8\x9E\x23\x22\x5C\xD4\x55\xAD\xBA\xF3\x2E\xF4\x3F\x18'
             b'\x58\x64\xA3\x6D\x63\x03\x09\xD6\x85\x3F\x77\x14\xB3\x9A\xAE'
             b'\x1E\xBE\xE3\x93\x8F\x87\xC2\x70\x7E\x17\x8C\x73\x9F\x9F\x02'
             b'\x81\x81\x00\x96\x90\xBE\xD1\x4B\x2A\xFA\xA2\x6D\x98\x6D\x59'
             b'\x22\x31\xEE\x27\xD7\x1D\x49\x06\x5B\xD2\xBA\x1F\x78\x15\x7E'
             b'\x20\x22\x98\x81\xFD\x9D\x23\x22\x7D\x0F\x84\x79\xEA\xEF\xA9'
             b'\x22\xFD\x75\xD5\xB1\x6B\x1A\x56\x1F\xA6\x68\x0B\x04\x0C\xA0'
             b'\xBD\xCE\x65\x0B\x23\xB9\x17\xA4\xB1\xBB\x79\x83\xA7\x4F\xAD'
             b'\x70\xE1\xC3\x05\xCB\xEC\x2B\xFF\x1A\x85\xA7\x26\xA1\xD9\x02'
             b'\x60\xE4\xF1\x08\x4F\x51\x82\x34\xDC\xD3\xFE\x77\x0B\x95\x20'
             b'\x21\x5B\xD5\x43\xBB\x6A\x41\x17\x71\x87\x54\x67\x6A\x34\x17'
             b'\x16\x66\xA7\x9F\x26\xE7\x9C\x14\x9C\x5A\xA1\x02\x81\x81\x00'
             b'\xA0\xC9\x85\xA0\xA0\xA7\x91\xA6\x59\xF9\x97\x31\x13\x4C\x44'
             b'\xF3\x7B\x2E\x52\x0A\x2C\xEA\x35\x80\x0A\xD2\x72\x41\xED\x36'
             b'\x0D\xFD\xE6\xE8\xCA\x61\x4F\x12\x04\x7F\xD0\x8B\x76\xAC\x4D'
             b'\x13\xC0\x56\xA0\x69\x9E\x2F\x98\xA1\xCA\xC9\x10\x11\x29\x4D'
             b'\x71\x20\x8F\x4A\xBA\xB3\x3B\xA8\x7A\xA0\x51\x7F\x41\x5B\xAC'
             b'\xA8\x8D\x6B\xAC\x00\x60\x88\xFA\x60\x1D\x34\x94\x17\xE1\xF0'
             b'\xC9\xB2\x3A\xFF\xA4\xD4\x96\x61\x8D\xBC\x02\x49\x86\xED\x69'
             b'\x0B\xBB\x7B\x02\x57\x68\xFF\x9D\xF8\xAC\x15\x41\x6F\x48\x9F'
             b'\x81\x29\xC3\x23\x41\xA8\xB4\x4F'),
            enums.KeyFormatType.PKCS_8)

        uid = self.client.register(key)
        self.assertIsInstance(uid, str)

        try:
            result = self.client.get(uid)
            self.assertIsInstance(result, objects.PrivateKey)
            self.assertEqual(
                result, key, "expected {0}\nobserved {1}".format(result, key))
        finally:
            self.client.revoke(enums.RevocationReasonCode.KEY_COMPROMISE, uid)
            self.client.destroy(uid)
            self.assertRaises(
                exceptions.KmipOperationFailure, self.client.get, uid)
            self.assertRaises(
                exceptions.KmipOperationFailure, self.client.destroy, uid)

    def test_x509_certificate_register_get_destroy(self):
        """
        Test that the ProxyKmipClient can register, retrieve, and destroy an
        X.509 certificate.
        """
        # Certificate encoding obtained from Section 13.2 of the KMIP 1.1 test
        # documentation.
        cert = objects.X509Certificate(
            (b'\x30\x82\x03\x12\x30\x82\x01\xFA\xA0\x03\x02\x01\x02\x02\x01'
             b'\x01\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05\x05'
             b'\x00\x30\x3B\x31\x0B\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55'
             b'\x53\x31\x0D\x30\x0B\x06\x03\x55\x04\x0A\x13\x04\x54\x45\x53'
             b'\x54\x31\x0E\x30\x0C\x06\x03\x55\x04\x0B\x13\x05\x4F\x41\x53'
             b'\x49\x53\x31\x0D\x30\x0B\x06\x03\x55\x04\x03\x13\x04\x4B\x4D'
             b'\x49\x50\x30\x1E\x17\x0D\x31\x30\x31\x31\x30\x31\x32\x33\x35'
             b'\x39\x35\x39\x5A\x17\x0D\x32\x30\x31\x31\x30\x31\x32\x33\x35'
             b'\x39\x35\x39\x5A\x30\x3B\x31\x0B\x30\x09\x06\x03\x55\x04\x06'
             b'\x13\x02\x55\x53\x31\x0D\x30\x0B\x06\x03\x55\x04\x0A\x13\x04'
             b'\x54\x45\x53\x54\x31\x0E\x30\x0C\x06\x03\x55\x04\x0B\x13\x05'
             b'\x4F\x41\x53\x49\x53\x31\x0D\x30\x0B\x06\x03\x55\x04\x03\x13'
             b'\x04\x4B\x4D\x49\x50\x30\x82\x01\x22\x30\x0D\x06\x09\x2A\x86'
             b'\x48\x86\xF7\x0D\x01\x01\x01\x05\x00\x03\x82\x01\x0F\x00\x30'
             b'\x82\x01\x0A\x02\x82\x01\x01\x00\xAB\x7F\x16\x1C\x00\x42\x49'
             b'\x6C\xCD\x6C\x6D\x4D\xAD\xB9\x19\x97\x34\x35\x35\x77\x76\x00'
             b'\x3A\xCF\x54\xB7\xAF\x1E\x44\x0A\xFB\x80\xB6\x4A\x87\x55\xF8'
             b'\x00\x2C\xFE\xBA\x6B\x18\x45\x40\xA2\xD6\x60\x86\xD7\x46\x48'
             b'\x34\x6D\x75\xB8\xD7\x18\x12\xB2\x05\x38\x7C\x0F\x65\x83\xBC'
             b'\x4D\x7D\xC7\xEC\x11\x4F\x3B\x17\x6B\x79\x57\xC4\x22\xE7\xD0'
             b'\x3F\xC6\x26\x7F\xA2\xA6\xF8\x9B\x9B\xEE\x9E\x60\xA1\xD7\xC2'
             b'\xD8\x33\xE5\xA5\xF4\xBB\x0B\x14\x34\xF4\xE7\x95\xA4\x11\x00'
             b'\xF8\xAA\x21\x49\x00\xDF\x8B\x65\x08\x9F\x98\x13\x5B\x1C\x67'
             b'\xB7\x01\x67\x5A\xBD\xBC\x7D\x57\x21\xAA\xC9\xD1\x4A\x7F\x08'
             b'\x1F\xCE\xC8\x0B\x64\xE8\xA0\xEC\xC8\x29\x53\x53\xC7\x95\x32'
             b'\x8A\xBF\x70\xE1\xB4\x2E\x7B\xB8\xB7\xF4\xE8\xAC\x8C\x81\x0C'
             b'\xDB\x66\xE3\xD2\x11\x26\xEB\xA8\xDA\x7D\x0C\xA3\x41\x42\xCB'
             b'\x76\xF9\x1F\x01\x3D\xA8\x09\xE9\xC1\xB7\xAE\x64\xC5\x41\x30'
             b'\xFB\xC2\x1D\x80\xE9\xC2\xCB\x06\xC5\xC8\xD7\xCC\xE8\x94\x6A'
             b'\x9A\xC9\x9B\x1C\x28\x15\xC3\x61\x2A\x29\xA8\x2D\x73\xA1\xF9'
             b'\x93\x74\xFE\x30\xE5\x49\x51\x66\x2A\x6E\xDA\x29\xC6\xFC\x41'
             b'\x13\x35\xD5\xDC\x74\x26\xB0\xF6\x05\x02\x03\x01\x00\x01\xA3'
             b'\x21\x30\x1F\x30\x1D\x06\x03\x55\x1D\x0E\x04\x16\x04\x14\x04'
             b'\xE5\x7B\xD2\xC4\x31\xB2\xE8\x16\xE1\x80\xA1\x98\x23\xFA\xC8'
             b'\x58\x27\x3F\x6B\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01'
             b'\x01\x05\x05\x00\x03\x82\x01\x01\x00\xA8\x76\xAD\xBC\x6C\x8E'
             b'\x0F\xF0\x17\x21\x6E\x19\x5F\xEA\x76\xBF\xF6\x1A\x56\x7C\x9A'
             b'\x13\xDC\x50\xD1\x3F\xEC\x12\xA4\x27\x3C\x44\x15\x47\xCF\xAB'
             b'\xCB\x5D\x61\xD9\x91\xE9\x66\x31\x9D\xF7\x2C\x0D\x41\xBA\x82'
             b'\x6A\x45\x11\x2F\xF2\x60\x89\xA2\x34\x4F\x4D\x71\xCF\x7C\x92'
             b'\x1B\x4B\xDF\xAE\xF1\x60\x0D\x1B\xAA\xA1\x53\x36\x05\x7E\x01'
             b'\x4B\x8B\x49\x6D\x4F\xAE\x9E\x8A\x6C\x1D\xA9\xAE\xB6\xCB\xC9'
             b'\x60\xCB\xF2\xFA\xE7\x7F\x58\x7E\xC4\xBB\x28\x20\x45\x33\x88'
             b'\x45\xB8\x8D\xD9\xAE\xEA\x53\xE4\x82\xA3\x6E\x73\x4E\x4F\x5F'
             b'\x03\xB9\xD0\xDF\xC4\xCA\xFC\x6B\xB3\x4E\xA9\x05\x3E\x52\xBD'
             b'\x60\x9E\xE0\x1E\x86\xD9\xB0\x9F\xB5\x11\x20\xC1\x98\x34\xA9'
             b'\x97\xB0\x9C\xE0\x8D\x79\xE8\x13\x11\x76\x2F\x97\x4B\xB1\xC8'
             b'\xC0\x91\x86\xC4\xD7\x89\x33\xE0\xDB\x38\xE9\x05\x08\x48\x77'
             b'\xE1\x47\xC7\x8A\xF5\x2F\xAE\x07\x19\x2F\xF1\x66\xD1\x9F\xA9'
             b'\x4A\x11\xCC\x11\xB2\x7E\xD0\x50\xF7\xA2\x7F\xAE\x13\xB2\x05'
             b'\xA5\x74\xC4\xEE\x00\xAA\x8B\xD6\x5D\x0D\x70\x57\xC9\x85\xC8'
             b'\x39\xEF\x33\x6A\x44\x1E\xD5\x3A\x53\xC6\xB6\xB6\x96\xF1\xBD'
             b'\xEB\x5F\x7E\xA8\x11\xEB\xB2\x5A\x7F\x86'))

        uid = self.client.register(cert)
        self.assertIsInstance(uid, str)

        try:
            result = self.client.get(uid)
            self.assertIsInstance(result, objects.X509Certificate)
            self.assertEqual(
                result, cert, "expected {0}\nobserved {1}".format(
                    result, cert))
        finally:
            self.client.revoke(enums.RevocationReasonCode.KEY_COMPROMISE, uid)
            self.client.destroy(uid)
            self.assertRaises(
                exceptions.KmipOperationFailure, self.client.get, uid)
            self.assertRaises(
                exceptions.KmipOperationFailure, self.client.destroy, uid)

    def test_secret_data_register_get_destroy(self):
        """
        Test that the ProxyKmipClient can register, retrieve, and destroy a
        secret.
        """
        # Secret encoding obtained from Section 3.1.5 of the KMIP 1.1 test
        # documentation.
        secret = objects.SecretData(
            (b'\x53\x65\x63\x72\x65\x74\x50\x61\x73\x73\x77\x6F\x72\x64'),
            enums.SecretDataType.PASSWORD)

        uid = self.client.register(secret)
        self.assertIsInstance(uid, str)

        try:
            result = self.client.get(uid)
            self.assertIsInstance(result, objects.SecretData)
            self.assertEqual(
                result, secret, "expected {0}\nobserved {1}".format(
                    result, secret))
        finally:
            self.client.revoke(enums.RevocationReasonCode.KEY_COMPROMISE, uid)
            self.client.destroy(uid)
            self.assertRaises(
                exceptions.KmipOperationFailure, self.client.get, uid)
            self.assertRaises(
                exceptions.KmipOperationFailure, self.client.destroy, uid)

    def test_secret_data_register_get_destroy_app_specific(self):
        """
        Test that the ProxyKmipClient can register, retrieve, and destroy a
        secret with the app specific info field.
        """
        # Secret encoding obtained from Section 3.1.5 of the KMIP 1.1 test
        # documentation.
        secret = objects.SecretData(
            b'\x53\x65\x63\x72\x65\x74\x50\x61\x73\x73\x77\x6F\x72\x64',
            enums.SecretDataType.PASSWORD,
            app_specific_info=[
                {
                    'application_namespace': 'Testing',
                    'application_data': 'Testing2'
                },
                {
                    'application_namespace': 'Testing3',
                    'application_data': 'Testing4'
                }
            ]
            )

        uid = self.client.register(secret)
        self.assertIsInstance(uid, str)

        try:
            result = self.client.get(uid)
            self.assertIsInstance(result, objects.SecretData)
            self.assertEqual(
                result, secret, "expected {0}\nobserved {1}".format(
                    result, secret))
            attribute_list = self.client.get_attribute_list(uid)
            self.assertIn('Application Specific Information', attribute_list)
            result_id, attribute_list = self.client.get_attributes(
                uid=uid,
                attribute_names=['Application Specific Information']
            )
            self.assertEqual(uid, result_id)

            attribute = attribute_list[0]
            self.assertEqual(
                'Application Specific Information',
                attribute.attribute_name.value
            )
            self.assertEqual(
                'Testing',
                attribute.attribute_value.application_namespace
            )
            self.assertEqual(
                'Testing2',
                attribute.attribute_value.application_data
            )

            attribute2 = attribute_list[1]
            self.assertEqual(
                'Application Specific Information',
                attribute2.attribute_name.value
            )
            self.assertEqual(
                'Testing3',
                attribute2.attribute_value.application_namespace
            )
            self.assertEqual(
                'Testing4',
                attribute2.attribute_value.application_data
            )

        finally:
            self.client.revoke(enums.RevocationReasonCode.KEY_COMPROMISE, uid)
            self.client.destroy(uid)
            self.assertRaises(
                exceptions.KmipOperationFailure, self.client.get, uid)
            self.assertRaises(
                exceptions.KmipOperationFailure, self.client.destroy, uid)

    def test_opaque_object_register_get_destroy(self):
        """
        Test that the ProxyKmipClient can register, retrieve, and destroy an
        opaque object.
        """
        # Object encoding obtained from Section 3.1.5 of the KMIP 1.1 test
        # documentation.
        obj = objects.OpaqueObject(
            b'\x53\x65\x63\x72\x65\x74\x50\x61\x73\x73\x77\x6F\x72\x64',
            enums.OpaqueDataType.NONE)
        uid = self.client.register(obj)
        self.assertIsInstance(uid, str)

        try:
            result = self.client.get(uid)
            self.assertIsInstance(result, objects.OpaqueObject)
            self.assertEqual(
                result, obj, "expected {0}\nobserved {1}".format(result, obj))
        finally:
            self.client.destroy(uid)
            self.assertRaises(
                exceptions.KmipOperationFailure, self.client.get, uid)
            self.assertRaises(
                exceptions.KmipOperationFailure, self.client.destroy, uid)

    def test_derive_key_using_pbkdf2(self):
        """
        Test that the ProxyKmipClient can derive a new key using PBKDF2.
        """
        password_id = self.client.register(
            objects.SecretData(
                b'password',
                enums.SecretDataType.PASSWORD,
                masks=[enums.CryptographicUsageMask.DERIVE_KEY]
            )
        )
        key_id = self.client.derive_key(
            enums.ObjectType.SYMMETRIC_KEY,
            [password_id],
            enums.DerivationMethod.PBKDF2,
            {
                'cryptographic_parameters': {
                    'hashing_algorithm': enums.HashingAlgorithm.SHA_1
                },
                'salt': b'salt',
                'iteration_count': 4096
            },
            cryptographic_length=160,
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES
        )

        key = self.client.get(key_id)
        self.assertEqual(
            (
                b'\x4b\x00\x79\x01\xb7\x65\x48\x9a'
                b'\xbe\xad\x49\xd9\x26\xf7\x21\xd0'
                b'\x65\xa4\x29\xc1'
            ),
            key.value
        )

        attribute_list = self.client.get_attribute_list(key_id)
        self.assertIn('Cryptographic Algorithm', attribute_list)
        self.assertIn('Cryptographic Length', attribute_list)

        result_id, attribute_list = self.client.get_attributes(
            uid=key_id,
            attribute_names=['Cryptographic Algorithm', 'Cryptographic Length']
        )
        self.assertEqual(key_id, result_id)
        self.assertEqual(2, len(attribute_list))

        attribute = attribute_list[0]
        self.assertEqual(
            'Cryptographic Algorithm',
            attribute.attribute_name.value
        )
        self.assertEqual(
            enums.CryptographicAlgorithm.AES,
            attribute.attribute_value.value
        )

        attribute = attribute_list[1]
        self.assertEqual(
            'Cryptographic Length',
            attribute.attribute_name.value
        )
        self.assertEqual(160, attribute.attribute_value.value)
        self.client.revoke(enums.RevocationReasonCode.KEY_COMPROMISE, key_id)
        self.client.destroy(key_id)

    def test_derive_key_using_encryption(self):
        """
        Test that the ProxyKmipClient can derive a new key using encryption.
        """
        key_id = self.client.register(
            objects.SymmetricKey(
                enums.CryptographicAlgorithm.BLOWFISH,
                128,
                (
                    b'\x01\x23\x45\x67\x89\xAB\xCD\xEF'
                    b'\xF0\xE1\xD2\xC3\xB4\xA5\x96\x87'
                ),
                masks=[enums.CryptographicUsageMask.DERIVE_KEY]
            )
        )
        secret_id = self.client.derive_key(
            enums.ObjectType.SECRET_DATA,
            [key_id],
            enums.DerivationMethod.ENCRYPT,
            {
                'cryptographic_parameters': {
                    'block_cipher_mode': enums.BlockCipherMode.CBC,
                    'padding_method': enums.PaddingMethod.PKCS5,
                    'cryptographic_algorithm':
                        enums.CryptographicAlgorithm.BLOWFISH
                },
                'initialization_vector': b'\xFE\xDC\xBA\x98\x76\x54\x32\x10',
                'derivation_data': (
                    b'\x37\x36\x35\x34\x33\x32\x31\x20'
                    b'\x4E\x6F\x77\x20\x69\x73\x20\x74'
                    b'\x68\x65\x20\x74\x69\x6D\x65\x20'
                    b'\x66\x6F\x72\x20\x00'
                )
            },
            cryptographic_length=256
        )

        secret = self.client.get(secret_id)
        self.assertEqual(
            (
                b'\x6B\x77\xB4\xD6\x30\x06\xDE\xE6'
                b'\x05\xB1\x56\xE2\x74\x03\x97\x93'
                b'\x58\xDE\xB9\xE7\x15\x46\x16\xD9'
                b'\x74\x9D\xEC\xBE\xC0\x5D\x26\x4B'
            ),
            secret.value
        )

    def test_derive_key_using_nist_800_108c(self):
        """
        Test that the ProxyKmipClient can derive a new key using
        NIST 800 108-C.
        """
        base_id = self.client.register(
            objects.SymmetricKey(
                enums.CryptographicAlgorithm.AES,
                512,
                (
                    b'\xdd\x5d\xbd\x45\x59\x3e\xe2\xac'
                    b'\x13\x97\x48\xe7\x64\x5b\x45\x0f'
                    b'\x22\x3d\x2f\xf2\x97\xb7\x3f\xd7'
                    b'\x1c\xbc\xeb\xe7\x1d\x41\x65\x3c'
                    b'\x95\x0b\x88\x50\x0d\xe5\x32\x2d'
                    b'\x99\xef\x18\xdf\xdd\x30\x42\x82'
                    b'\x94\xc4\xb3\x09\x4f\x4c\x95\x43'
                    b'\x34\xe5\x93\xbd\x98\x2e\xc6\x14'
                ),
                masks=[enums.CryptographicUsageMask.DERIVE_KEY]
            )
        )
        key_id = self.client.derive_key(
            enums.ObjectType.SYMMETRIC_KEY,
            [base_id],
            enums.DerivationMethod.NIST800_108_C,
            {
                'cryptographic_parameters': {
                    'hashing_algorithm': enums.HashingAlgorithm.SHA_512
                },
                'derivation_data': (
                    b'\xb5\x0b\x0c\x96\x3c\x6b\x30\x34'
                    b'\xb8\xcf\x19\xcd\x3f\x5c\x4e\xbe'
                    b'\x4f\x49\x85\xaf\x0c\x03\xe5\x75'
                    b'\xdb\x62\xe6\xfd\xf1\xec\xfe\x4f'
                    b'\x28\xb9\x5d\x7c\xe1\x6d\xf8\x58'
                    b'\x43\x24\x6e\x15\x57\xce\x95\xbb'
                    b'\x26\xcc\x9a\x21\x97\x4b\xbd\x2e'
                    b'\xb6\x9e\x83\x55'
                )
            },
            cryptographic_length=128,
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES
        )

        key = self.client.get(key_id)
        self.assertEqual(
            (
                b'\xe5\x99\x3b\xf9\xbd\x2a\xa1\xc4'
                b'\x57\x46\x04\x2e\x12\x59\x81\x55'
            ),
            key.value
        )

        attribute_list = self.client.get_attribute_list(key_id)
        self.assertIn('Cryptographic Algorithm', attribute_list)
        self.assertIn('Cryptographic Length', attribute_list)

        result_id, attribute_list = self.client.get_attributes(
            uid=key_id,
            attribute_names=['Cryptographic Algorithm', 'Cryptographic Length']
        )
        self.assertEqual(key_id, result_id)
        self.assertEqual(2, len(attribute_list))

        attribute = attribute_list[0]
        self.assertEqual(
            'Cryptographic Algorithm',
            attribute.attribute_name.value
        )
        self.assertEqual(
            enums.CryptographicAlgorithm.AES,
            attribute.attribute_value.value
        )

        attribute = attribute_list[1]
        self.assertEqual(
            'Cryptographic Length',
            attribute.attribute_name.value
        )
        self.assertEqual(128, attribute.attribute_value.value)

    def test_derive_key_using_hmac(self):
        """
        Test that the ProxyKmipClient can derive a new key using HMAC.
        """
        base_id = self.client.register(
            objects.SecretData(
                (
                    b'\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c'
                    b'\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c'
                    b'\x0c\x0c\x0c\x0c\x0c\x0c'
                ),
                enums.SecretDataType.SEED,
                masks=[enums.CryptographicUsageMask.DERIVE_KEY]
            )
        )
        secret_id = self.client.derive_key(
            enums.ObjectType.SECRET_DATA,
            [base_id],
            enums.DerivationMethod.HMAC,
            {
                'cryptographic_parameters': {
                    'hashing_algorithm': enums.HashingAlgorithm.SHA_1
                },
                'derivation_data': b'',
                'salt': b''
            },
            cryptographic_length=336
        )

        secret = self.client.get(secret_id)
        self.assertEqual(
            (
                b'\x2c\x91\x11\x72\x04\xd7\x45\xf3'
                b'\x50\x0d\x63\x6a\x62\xf6\x4f\x0a'
                b'\xb3\xba\xe5\x48\xaa\x53\xd4\x23'
                b'\xb0\xd1\xf2\x7e\xbb\xa6\xf5\xe5'
                b'\x67\x3a\x08\x1d\x70\xcc\xe7\xac'
                b'\xfc\x48'
            ),
            secret.value
        )

    def test_encrypt_decrypt(self):
        """
        Test that the ProxyKmipClient can create an encryption key, encrypt
        plain text with it, and then decrypt the cipher text, retrieving the
        original plain text.
        """
        # Create an encryption key.
        key_id = self.client.create(
            enums.CryptographicAlgorithm.AES,
            256,
            cryptographic_usage_mask=[
                enums.CryptographicUsageMask.ENCRYPT,
                enums.CryptographicUsageMask.DECRYPT
            ]
        )

        # Activate the encryption key.
        self.client.activate(key_id)

        # Encrypt some plain text.
        plain_text = b'This is a secret message.'
        cipher_text, iv = self.client.encrypt(
            plain_text,
            uid=key_id,
            cryptographic_parameters={
                'cryptographic_algorithm': enums.CryptographicAlgorithm.AES,
                'block_cipher_mode': enums.BlockCipherMode.CBC,
                'padding_method': enums.PaddingMethod.PKCS5
            },
            iv_counter_nonce=(
                b'\x85\x1e\x87\x64\x77\x6e\x67\x96'
                b'\xaa\xb7\x22\xdb\xb6\x44\xac\xe8'
            )
        )

        self.assertEqual(None, iv)

        # Decrypt the cipher text.
        result = self.client.decrypt(
            cipher_text,
            uid=key_id,
            cryptographic_parameters={
                'cryptographic_algorithm': enums.CryptographicAlgorithm.AES,
                'block_cipher_mode': enums.BlockCipherMode.CBC,
                'padding_method': enums.PaddingMethod.PKCS5
            },
            iv_counter_nonce=(
                b'\x85\x1e\x87\x64\x77\x6e\x67\x96'
                b'\xaa\xb7\x22\xdb\xb6\x44\xac\xe8'
            )
        )

        self.assertEqual(plain_text, result)

        # Clean up.
        self.client.revoke(enums.RevocationReasonCode.KEY_COMPROMISE, key_id)
        self.client.destroy(key_id)

    def test_create_key_pair_sign_signature_verify(self):
        """
        Test that the ProxyKmipClient can create an asymmetric key pair and
        then use that key pair (1) to sign data and (2) verify the signature
        on the data.
        """
        # Create a public/private key pair.
        public_key_id, private_key_id = self.client.create_key_pair(
            enums.CryptographicAlgorithm.RSA,
            2048,
            public_usage_mask=[
                enums.CryptographicUsageMask.VERIFY
            ],
            private_usage_mask=[
                enums.CryptographicUsageMask.SIGN
            ]
        )

        self.assertIsInstance(public_key_id, str)
        self.assertIsInstance(private_key_id, str)

        # Activate the signing key and the signature verification key.
        self.client.activate(private_key_id)
        self.client.activate(public_key_id)

        # Sign a message.
        signature = self.client.sign(
            b'This is a signed message.',
            uid=private_key_id,
            cryptographic_parameters={
                'padding_method': enums.PaddingMethod.PSS,
                'cryptographic_algorithm': enums.CryptographicAlgorithm.RSA,
                'hashing_algorithm': enums.HashingAlgorithm.SHA_256
            }
        )

        self.assertIsInstance(signature, bytes)

        # Verify the message signature.
        result = self.client.signature_verify(
            b'This is a signed message.',
            signature,
            uid=public_key_id,
            cryptographic_parameters={
                'padding_method': enums.PaddingMethod.PSS,
                'cryptographic_algorithm': enums.CryptographicAlgorithm.RSA,
                'hashing_algorithm': enums.HashingAlgorithm.SHA_256
            }
        )

        self.assertEqual(result, enums.ValidityIndicator.VALID)

        # Clean up.
        self.client.revoke(
            enums.RevocationReasonCode.KEY_COMPROMISE,
            public_key_id
        )
        self.client.revoke(
            enums.RevocationReasonCode.KEY_COMPROMISE,
            private_key_id
        )
        self.client.destroy(public_key_id)
        self.client.destroy(private_key_id)

    def test_certificate_register_locate_destroy(self):
        """
        Test that newly registered certificates can be located based on their
        attributes.
        """
        label = "Integration Test - Register-Locate-Destroy Certificate"
        value = (
            b'\x30\x82\x03\x12\x30\x82\x01\xFA\xA0\x03\x02\x01\x02\x02\x01\x01'
            b'\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05\x05\x00\x30'
            b'\x3B\x31\x0B\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x0D'
            b'\x30\x0B\x06\x03\x55\x04\x0A\x13\x04\x54\x45\x53\x54\x31\x0E\x30'
            b'\x0C\x06\x03\x55\x04\x0B\x13\x05\x4F\x41\x53\x49\x53\x31\x0D\x30'
            b'\x0B\x06\x03\x55\x04\x03\x13\x04\x4B\x4D\x49\x50\x30\x1E\x17\x0D'
            b'\x31\x30\x31\x31\x30\x31\x32\x33\x35\x39\x35\x39\x5A\x17\x0D\x32'
            b'\x30\x31\x31\x30\x31\x32\x33\x35\x39\x35\x39\x5A\x30\x3B\x31\x0B'
            b'\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x0D\x30\x0B\x06'
            b'\x03\x55\x04\x0A\x13\x04\x54\x45\x53\x54\x31\x0E\x30\x0C\x06\x03'
            b'\x55\x04\x0B\x13\x05\x4F\x41\x53\x49\x53\x31\x0D\x30\x0B\x06\x03'
            b'\x55\x04\x03\x13\x04\x4B\x4D\x49\x50\x30\x82\x01\x22\x30\x0D\x06'
            b'\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00\x03\x82\x01\x0F'
            b'\x00\x30\x82\x01\x0A\x02\x82\x01\x01\x00\xAB\x7F\x16\x1C\x00\x42'
            b'\x49\x6C\xCD\x6C\x6D\x4D\xAD\xB9\x19\x97\x34\x35\x35\x77\x76\x00'
            b'\x3A\xCF\x54\xB7\xAF\x1E\x44\x0A\xFB\x80\xB6\x4A\x87\x55\xF8\x00'
            b'\x2C\xFE\xBA\x6B\x18\x45\x40\xA2\xD6\x60\x86\xD7\x46\x48\x34\x6D'
            b'\x75\xB8\xD7\x18\x12\xB2\x05\x38\x7C\x0F\x65\x83\xBC\x4D\x7D\xC7'
            b'\xEC\x11\x4F\x3B\x17\x6B\x79\x57\xC4\x22\xE7\xD0\x3F\xC6\x26\x7F'
            b'\xA2\xA6\xF8\x9B\x9B\xEE\x9E\x60\xA1\xD7\xC2\xD8\x33\xE5\xA5\xF4'
            b'\xBB\x0B\x14\x34\xF4\xE7\x95\xA4\x11\x00\xF8\xAA\x21\x49\x00\xDF'
            b'\x8B\x65\x08\x9F\x98\x13\x5B\x1C\x67\xB7\x01\x67\x5A\xBD\xBC\x7D'
            b'\x57\x21\xAA\xC9\xD1\x4A\x7F\x08\x1F\xCE\xC8\x0B\x64\xE8\xA0\xEC'
            b'\xC8\x29\x53\x53\xC7\x95\x32\x8A\xBF\x70\xE1\xB4\x2E\x7B\xB8\xB7'
            b'\xF4\xE8\xAC\x8C\x81\x0C\xDB\x66\xE3\xD2\x11\x26\xEB\xA8\xDA\x7D'
            b'\x0C\xA3\x41\x42\xCB\x76\xF9\x1F\x01\x3D\xA8\x09\xE9\xC1\xB7\xAE'
            b'\x64\xC5\x41\x30\xFB\xC2\x1D\x80\xE9\xC2\xCB\x06\xC5\xC8\xD7\xCC'
            b'\xE8\x94\x6A\x9A\xC9\x9B\x1C\x28\x15\xC3\x61\x2A\x29\xA8\x2D\x73'
            b'\xA1\xF9\x93\x74\xFE\x30\xE5\x49\x51\x66\x2A\x6E\xDA\x29\xC6\xFC'
            b'\x41\x13\x35\xD5\xDC\x74\x26\xB0\xF6\x05\x02\x03\x01\x00\x01\xA3'
            b'\x21\x30\x1F\x30\x1D\x06\x03\x55\x1D\x0E\x04\x16\x04\x14\x04\xE5'
            b'\x7B\xD2\xC4\x31\xB2\xE8\x16\xE1\x80\xA1\x98\x23\xFA\xC8\x58\x27'
            b'\x3F\x6B\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05\x05'
            b'\x00\x03\x82\x01\x01\x00\xA8\x76\xAD\xBC\x6C\x8E\x0F\xF0\x17\x21'
            b'\x6E\x19\x5F\xEA\x76\xBF\xF6\x1A\x56\x7C\x9A\x13\xDC\x50\xD1\x3F'
            b'\xEC\x12\xA4\x27\x3C\x44\x15\x47\xCF\xAB\xCB\x5D\x61\xD9\x91\xE9'
            b'\x66\x31\x9D\xF7\x2C\x0D\x41\xBA\x82\x6A\x45\x11\x2F\xF2\x60\x89'
            b'\xA2\x34\x4F\x4D\x71\xCF\x7C\x92\x1B\x4B\xDF\xAE\xF1\x60\x0D\x1B'
            b'\xAA\xA1\x53\x36\x05\x7E\x01\x4B\x8B\x49\x6D\x4F\xAE\x9E\x8A\x6C'
            b'\x1D\xA9\xAE\xB6\xCB\xC9\x60\xCB\xF2\xFA\xE7\x7F\x58\x7E\xC4\xBB'
            b'\x28\x20\x45\x33\x88\x45\xB8\x8D\xD9\xAE\xEA\x53\xE4\x82\xA3\x6E'
            b'\x73\x4E\x4F\x5F\x03\xB9\xD0\xDF\xC4\xCA\xFC\x6B\xB3\x4E\xA9\x05'
            b'\x3E\x52\xBD\x60\x9E\xE0\x1E\x86\xD9\xB0\x9F\xB5\x11\x20\xC1\x98'
            b'\x34\xA9\x97\xB0\x9C\xE0\x8D\x79\xE8\x13\x11\x76\x2F\x97\x4B\xB1'
            b'\xC8\xC0\x91\x86\xC4\xD7\x89\x33\xE0\xDB\x38\xE9\x05\x08\x48\x77'
            b'\xE1\x47\xC7\x8A\xF5\x2F\xAE\x07\x19\x2F\xF1\x66\xD1\x9F\xA9\x4A'
            b'\x11\xCC\x11\xB2\x7E\xD0\x50\xF7\xA2\x7F\xAE\x13\xB2\x05\xA5\x74'
            b'\xC4\xEE\x00\xAA\x8B\xD6\x5D\x0D\x70\x57\xC9\x85\xC8\x39\xEF\x33'
            b'\x6A\x44\x1E\xD5\x3A\x53\xC6\xB6\xB6\x96\xF1\xBD\xEB\x5F\x7E\xA8'
            b'\x11\xEB\xB2\x5A\x7F\x86')
        usage_mask = [
            enums.CryptographicUsageMask.ENCRYPT,
            enums.CryptographicUsageMask.VERIFY
        ]

        certificate = objects.Certificate(
            enums.CertificateType.X_509,
            value,
            masks=usage_mask,
            name=label
        )
        a_id = self.client.register(certificate)

        # Test locating the certificate by its "Certificate Type" value.
        result = self.client.locate(
            attributes=[
                self.attribute_factory.create_attribute(
                    enums.AttributeType.CERTIFICATE_TYPE,
                    enums.CertificateType.X_509
                )
            ]
        )
        self.assertEqual(1, len(result))
        self.assertEqual(a_id, result[0])

        result = self.client.locate(
            attributes=[
                self.attribute_factory.create_attribute(
                    enums.AttributeType.CERTIFICATE_TYPE,
                    enums.CertificateType.PGP
                )
            ]
        )
        self.assertEqual(0, len(result))

        # Clean up the certificate
        self.client.destroy(a_id)

    def test_create_getattributes_locate_destroy(self):
        """
        Test that the ProxyKmipClient can create symmetric keys and then
        locate those keys using their attributes.
        """
        start_time = int(time.time())
        time.sleep(2)

        # Create some symmetric keys
        a_id = self.client.create(enums.CryptographicAlgorithm.AES, 256)

        time.sleep(2)
        mid_time = int(time.time())
        time.sleep(2)

        b_id = self.client.create(enums.CryptographicAlgorithm.IDEA, 128)

        time.sleep(2)
        end_time = int(time.time())

        self.assertIsInstance(a_id, str)
        self.assertIsInstance(b_id, str)

        # Get the "Initial Date" attributes for each key
        result_id, result_attributes = self.client.get_attributes(
            uid=a_id,
            attribute_names=["Initial Date"]
        )
        self.assertEqual(1, len(result_attributes))
        self.assertEqual(
            "Initial Date",
            result_attributes[0].attribute_name.value
        )
        initial_date_a = result_attributes[0].attribute_value.value

        result_id, result_attributes = self.client.get_attributes(
            uid=b_id,
            attribute_names=["Initial Date"]
        )
        self.assertEqual(1, len(result_attributes))
        self.assertEqual(
            "Initial Date",
            result_attributes[0].attribute_name.value
        )
        initial_date_b = result_attributes[0].attribute_value.value

        # Test locating each key by its exact "Initial Date" value
        result = self.client.locate(
            attributes=[
                self.attribute_factory.create_attribute(
                    enums.AttributeType.INITIAL_DATE,
                    initial_date_a
                )
            ]
        )
        self.assertEqual(1, len(result))
        self.assertEqual(a_id, result[0])

        result = self.client.locate(
            attributes=[
                self.attribute_factory.create_attribute(
                    enums.AttributeType.INITIAL_DATE,
                    initial_date_b
                )
            ]
        )
        self.assertEqual(1, len(result))
        self.assertEqual(b_id, result[0])

        # Test locating each key by a range around its "Initial Date" value
        result = self.client.locate(
            attributes=[
                self.attribute_factory.create_attribute(
                    enums.AttributeType.INITIAL_DATE,
                    start_time
                ),
                self.attribute_factory.create_attribute(
                    enums.AttributeType.INITIAL_DATE,
                    mid_time
                )
            ]
        )
        self.assertEqual(1, len(result))
        self.assertEqual(a_id, result[0])

        result = self.client.locate(
            attributes=[
                self.attribute_factory.create_attribute(
                    enums.AttributeType.INITIAL_DATE,
                    mid_time
                ),
                self.attribute_factory.create_attribute(
                    enums.AttributeType.INITIAL_DATE,
                    end_time
                )
            ]
        )
        self.assertEqual(1, len(result))
        self.assertEqual(b_id, result[0])

        result = self.client.locate(
            attributes=[
                self.attribute_factory.create_attribute(
                    enums.AttributeType.INITIAL_DATE,
                    start_time
                ),
                self.attribute_factory.create_attribute(
                    enums.AttributeType.INITIAL_DATE,
                    end_time
                )
            ]
        )
        self.assertEqual(2, len(result))
        self.assertIn(a_id, result)
        self.assertIn(b_id, result)

        # Test locating each key by its state.
        result = self.client.locate(
            attributes=[
                self.attribute_factory.create_attribute(
                    enums.AttributeType.STATE,
                    enums.State.PRE_ACTIVE
                )
            ]
        )
        self.assertEqual(2, len(result))
        self.assertIn(a_id, result)
        self.assertIn(b_id, result)

        # Test locating each key by its object type.
        result = self.client.locate(
            attributes=[
                self.attribute_factory.create_attribute(
                    enums.AttributeType.OBJECT_TYPE,
                    enums.ObjectType.SYMMETRIC_KEY
                )
            ]
        )
        self.assertEqual(2, len(result))
        self.assertIn(a_id, result)
        self.assertIn(b_id, result)

        # Test locating each key by its cryptographic algorithm.
        result = self.client.locate(
            attributes=[
                self.attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                    enums.CryptographicAlgorithm.AES
                )
            ]
        )
        self.assertEqual(1, len(result))
        self.assertIn(a_id, result)

        result = self.client.locate(
            attributes=[
                self.attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                    enums.CryptographicAlgorithm.IDEA
                )
            ]
        )
        self.assertEqual(1, len(result))
        self.assertIn(b_id, result)

        result = self.client.locate(
            attributes=[
                self.attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                    enums.CryptographicAlgorithm.RSA
                )
            ]
        )
        self.assertEqual(0, len(result))

        # Test locating each key by its cryptographic length.
        result = self.client.locate(
            attributes=[
                self.attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                    128
                )
            ]
        )
        self.assertEqual(1, len(result))
        self.assertIn(b_id, result)

        result = self.client.locate(
            attributes=[
                self.attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                    256
                )
            ]
        )
        self.assertEqual(1, len(result))
        self.assertIn(a_id, result)

        result = self.client.locate(
            attributes=[
                self.attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                    2048
                )
            ]
        )
        self.assertEqual(0, len(result))

        # Test locating each key by its unique identifier.
        result = self.client.locate(
            attributes=[
                self.attribute_factory.create_attribute(
                    enums.AttributeType.UNIQUE_IDENTIFIER,
                    a_id
                )
            ]
        )
        self.assertEqual(1, len(result))
        self.assertIn(a_id, result)

        result = self.client.locate(
            attributes=[
                self.attribute_factory.create_attribute(
                    enums.AttributeType.UNIQUE_IDENTIFIER,
                    b_id
                )
            ]
        )
        self.assertEqual(1, len(result))
        self.assertIn(b_id, result)

        result = self.client.locate(
            attributes=[
                self.attribute_factory.create_attribute(
                    enums.AttributeType.UNIQUE_IDENTIFIER,
                    "unknown"
                )
            ]
        )
        self.assertEqual(0, len(result))

        # Test locating each key by its operation policy name.
        result = self.client.locate(
            attributes=[
                self.attribute_factory.create_attribute(
                    enums.AttributeType.OPERATION_POLICY_NAME,
                    "default"
                )
            ]
        )
        self.assertEqual(2, len(result))
        self.assertIn(a_id, result)
        self.assertIn(b_id, result)

        result = self.client.locate(
            attributes=[
                self.attribute_factory.create_attribute(
                    enums.AttributeType.OPERATION_POLICY_NAME,
                    "unknown"
                )
            ]
        )
        self.assertEqual(0, len(result))

        # Test locating keys using offset and maximum item constraints.
        result = self.client.locate(offset_items=1)

        self.assertEqual(1, len(result))
        self.assertIn(a_id, result)

        result = self.client.locate(maximum_items=1)

        self.assertEqual(1, len(result))
        self.assertIn(b_id, result)

        result = self.client.locate(offset_items=1, maximum_items=1)

        self.assertEqual(1, len(result))
        self.assertIn(a_id, result)

        # Test locating keys using their cryptographic usage masks
        mask = [enums.CryptographicUsageMask.ENCRYPT]
        result = self.client.locate(
            attributes=[
                self.attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    mask
                )
            ]
        )
        self.assertEqual(2, len(result))
        self.assertIn(a_id, result)
        self.assertIn(b_id, result)

        mask.append(enums.CryptographicUsageMask.DECRYPT)
        result = self.client.locate(
            attributes=[
                self.attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    mask
                )
            ]
        )
        self.assertEqual(2, len(result))
        self.assertIn(a_id, result)
        self.assertIn(b_id, result)

        mask.append(enums.CryptographicUsageMask.SIGN)
        result = self.client.locate(
            attributes=[
                self.attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    mask
                )
            ]
        )
        self.assertEqual(0, len(result))

        mask = [enums.CryptographicUsageMask.EXPORT]
        result = self.client.locate(
            attributes=[
                self.attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    mask
                )
            ]
        )
        self.assertEqual(0, len(result))

        # Clean up the keys
        self.client.revoke(enums.RevocationReasonCode.KEY_COMPROMISE, a_id)
        self.client.revoke(enums.RevocationReasonCode.KEY_COMPROMISE, b_id)
        self.client.destroy(a_id)
        self.client.destroy(b_id)

    def test_split_key_register_get_destroy(self):
        """
        Test that the ProxyKmipClient can register, retrieve, and destroy a
        split key.
        """
        key = objects.SplitKey(
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
            cryptographic_length=128,
            key_value=(
                b'\x00\x01\x02\x03\x04\x05\x06\x07'
                b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
            ),
            name="Test Split Key",
            cryptographic_usage_masks=[enums.CryptographicUsageMask.EXPORT],
            key_format_type=enums.KeyFormatType.RAW,
            key_wrapping_data=None,
            split_key_parts=3,
            key_part_identifier=1,
            split_key_threshold=2,
            split_key_method=enums.SplitKeyMethod.XOR,
            prime_field_size=None
        )

        uid = self.client.register(key)
        self.assertIsInstance(uid, str)

        try:
            result = self.client.get(uid)
            self.assertIsInstance(result, objects.SplitKey)
            self.assertEqual(
                enums.CryptographicAlgorithm.AES,
                result.cryptographic_algorithm
            )
            self.assertEqual(128, result.cryptographic_length)
            self.assertEqual(
                (
                    b'\x00\x01\x02\x03\x04\x05\x06\x07'
                    b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
                ),
                result.value
            )
            self.assertEqual(enums.KeyFormatType.RAW, result.key_format_type)
            self.assertEqual(3, result.split_key_parts)
            self.assertEqual(1, result.key_part_identifier)
            self.assertEqual(2, result.split_key_threshold)
            self.assertEqual(enums.SplitKeyMethod.XOR, result.split_key_method)
            self.assertIsNone(result.prime_field_size)
        finally:
            self.client.revoke(enums.RevocationReasonCode.KEY_COMPROMISE, uid)
            self.client.destroy(uid)
            self.assertRaises(
                exceptions.KmipOperationFailure, self.client.get, uid)
            self.assertRaises(
                exceptions.KmipOperationFailure, self.client.destroy, uid)

    def test_modify_delete_attribute(self):
        """
        Test that the ProxyKmipClient can modify and delete an attribute.
        """
        key_id = self.client.create(
            enums.CryptographicAlgorithm.IDEA,
            128,
            name="Symmetric Key"
        )

        self.assertIsInstance(key_id, str)

        # Get the "Name" attribute for the key.
        result_id, result_attributes = self.client.get_attributes(
            uid=key_id,
            attribute_names=["Name"]
        )
        self.assertEqual(1, len(result_attributes))
        self.assertEqual("Name", result_attributes[0].attribute_name.value)
        self.assertEqual(
            "Symmetric Key",
            result_attributes[0].attribute_value.name_value.value
        )

        # Modify the "Name" attribute for the key.
        response_id, response_attr = self.client.modify_attribute(
            unique_identifier=key_id,
            attribute=self.attribute_factory.create_attribute(
                enums.AttributeType.NAME,
                "Modified Name",
                index=0
            )
        )
        self.assertEqual(key_id, response_id)
        self.assertEqual("Name", response_attr.attribute_name.value)
        self.assertEqual(0, response_attr.attribute_index.value)
        self.assertEqual(
            "Modified Name",
            response_attr.attribute_value.name_value.value
        )

        # Get the "Name" attribute for the key to verify it was modified.
        result_id, result_attributes = self.client.get_attributes(
            uid=key_id,
            attribute_names=["Name"]
        )
        self.assertEqual(1, len(result_attributes))
        self.assertEqual("Name", result_attributes[0].attribute_name.value)
        self.assertEqual(
            "Modified Name",
            result_attributes[0].attribute_value.name_value.value
        )

        # Delete the "Name" attribute for the key.
        response_id, response_attr = self.client.delete_attribute(
            unique_identifier=key_id,
            attribute_name="Name",
            attribute_index=0
        )
        self.assertEqual(key_id, response_id)
        self.assertEqual("Name", response_attr.attribute_name.value)
        self.assertEqual(0, response_attr.attribute_index.value)
        self.assertEqual(
            "Modified Name",
            response_attr.attribute_value.name_value.value
        )
