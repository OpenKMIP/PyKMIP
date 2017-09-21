# Copyright (c) 2014 The Johns Hopkins University/Applied Physics Laboratory
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

from kmip.core import attributes
from kmip.core import enums
from kmip.core import misc
from kmip.core import objects
from kmip.core import secrets
from kmip.core import utils

from kmip.core.messages import payloads


class TestGetRequestPayload(testtools.TestCase):
    """
    Test suite for the Get request payload.
    """

    def setUp(self):
        super(TestGetRequestPayload, self).setUp()

        # Encoding obtained in part from the KMIP 1.1 testing document,
        # Sections 3.1.3 and 14.1. The rest of the encoding was built by
        # hand.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Unique Identifier - 49a1ca88-6bea-4fb2-b450-7e58802c3038
        #     Key Format Type - Raw
        #     Key Compression Type - EC Public Key Type Uncompressed
        #     Key Wrapping Specification
        #         Key Wrapping Method - Encrypt
        #         Encryption Key Information
        #             Unique Identifier - 100182d5-72b8-47aa-8383-4d97d512e98a
        #             Cryptographic Parameters
        #                 Block Cipher Mode - NIST Key Wrap
        #         Encoding Option - No Encoding

        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\xC8'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x34\x39\x61\x31\x63\x61\x38\x38\x2D\x36\x62\x65\x61\x2D\x34\x66'
            b'\x62\x32\x2D\x62\x34\x35\x30\x2D\x37\x65\x35\x38\x38\x30\x32\x63'
            b'\x33\x30\x33\x38\x00\x00\x00\x00'
            b'\x42\x00\x42\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x41\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x47\x01\x00\x00\x00\x70'
            b'\x42\x00\x9E\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x36\x01\x00\x00\x00\x48'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x31\x30\x30\x31\x38\x32\x64\x35\x2D\x37\x32\x62\x38\x2D\x34\x37'
            b'\x61\x61\x2D\x38\x33\x38\x33\x2D\x34\x64\x39\x37\x64\x35\x31\x32'
            b'\x65\x39\x38\x61\x00\x00\x00\x00'
            b'\x42\x00\x2B\x01\x00\x00\x00\x10'
            b'\x42\x00\x11\x05\x00\x00\x00\x04\x00\x00\x00\x0D\x00\x00\x00\x00'
            b'\x42\x00\xA3\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
        )

        # Encoding obtained from the KMIP 1.1 testing document, Section 3.1.3.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Unique Identifier - 49a1ca88-6bea-4fb2-b450-7e58802c3038

        self.partial_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x30'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x34\x39\x61\x31\x63\x61\x38\x38\x2D\x36\x62\x65\x61\x2D\x34\x66'
            b'\x62\x32\x2D\x62\x34\x35\x30\x2D\x37\x65\x35\x38\x38\x30\x32\x63'
            b'\x33\x30\x33\x38\x00\x00\x00\x00'
        )

        self.empty_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestGetRequestPayload, self).tearDown()

    def test_init(self):
        """
        Test that a Get request payload can be constructed with no arguments.
        """
        payload = payloads.GetRequestPayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.key_format_type)
        self.assertEqual(None, payload.key_compression_type)
        self.assertEqual(None, payload.key_wrapping_specification)

    def test_init_with_args(self):
        """
        Test that a Get request payload can be constructed with valid values.
        """
        payload = payloads.GetRequestPayload(
            unique_identifier='00000000-2222-4444-6666-888888888888',
            key_format_type=enums.KeyFormatType.RAW,
            key_compression_type=enums.KeyCompressionType.
            EC_PUBLIC_KEY_TYPE_UNCOMPRESSED,
            key_wrapping_specification=objects.KeyWrappingSpecification(
                wrapping_method=enums.WrappingMethod.ENCRYPT
            )
        )

        self.assertEqual(
            '00000000-2222-4444-6666-888888888888',
            payload.unique_identifier
        )
        self.assertEqual(enums.KeyFormatType.RAW, payload.key_format_type)
        self.assertEqual(
            enums.KeyCompressionType.EC_PUBLIC_KEY_TYPE_UNCOMPRESSED,
            payload.key_compression_type
        )
        self.assertIsInstance(
            payload.key_wrapping_specification,
            objects.KeyWrappingSpecification
        )
        self.assertEqual(
            enums.WrappingMethod.ENCRYPT,
            payload.key_wrapping_specification.wrapping_method
        )

    def test_invalid_unique_identifier(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the unique identifier of a Get request payload.
        """
        kwargs = {'unique_identifier': 0}
        self.assertRaisesRegexp(
            TypeError,
            "Unique identifier must be a string.",
            payloads.GetRequestPayload,
            **kwargs
        )

        args = (payloads.GetRequestPayload(), 'unique_identifier', 0)
        self.assertRaisesRegexp(
            TypeError,
            "Unique identifier must be a string.",
            setattr,
            *args
        )

    def test_invalid_key_format_type(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the key format type of a Get request payload.
        """
        kwargs = {'key_format_type': 'invalid'}
        self.assertRaisesRegexp(
            TypeError,
            "Key format type must be a KeyFormatType enumeration.",
            payloads.GetRequestPayload,
            **kwargs
        )

        args = (payloads.GetRequestPayload(), 'key_format_type', 'invalid')
        self.assertRaisesRegexp(
            TypeError,
            "Key format type must be a KeyFormatType enumeration.",
            setattr,
            *args
        )

    def test_invalid_key_compression_type(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the key compression type of a Get request payload.
        """
        kwargs = {'key_compression_type': 'invalid'}
        self.assertRaisesRegexp(
            TypeError,
            "Key compression type must be a KeyCompressionType enumeration.",
            payloads.GetRequestPayload,
            **kwargs
        )

        args = (
            payloads.GetRequestPayload(),
            'key_compression_type',
            'invalid'
        )
        self.assertRaisesRegexp(
            TypeError,
            "Key compression type must be a KeyCompressionType enumeration.",
            setattr,
            *args
        )

    def test_invalid_key_wrapping_specification(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the key wrapping specification of a Get request payload.
        """
        kwargs = {'key_wrapping_specification': 'invalid'}
        self.assertRaisesRegexp(
            TypeError,
            "Key wrapping specification must be a KeyWrappingSpecification "
            "struct.",
            payloads.GetRequestPayload,
            **kwargs
        )

        args = (
            payloads.GetRequestPayload(),
            'key_wrapping_specification',
            'invalid'
        )
        self.assertRaisesRegexp(
            TypeError,
            "Key wrapping specification must be a KeyWrappingSpecification "
            "struct.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a GetRequestPayload struct can be read from a data stream.
        """
        payload = payloads.GetRequestPayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.key_format_type)
        self.assertEqual(None, payload.key_compression_type)
        self.assertEqual(None, payload.key_wrapping_specification)

        payload.read(self.full_encoding)

        self.assertEqual(
            '49a1ca88-6bea-4fb2-b450-7e58802c3038',
            payload.unique_identifier
        )
        self.assertEqual(enums.KeyFormatType.RAW, payload.key_format_type)
        self.assertEqual(
            enums.KeyCompressionType.EC_PUBLIC_KEY_TYPE_UNCOMPRESSED,
            payload.key_compression_type
        )
        self.assertIsInstance(
            payload.key_wrapping_specification,
            objects.KeyWrappingSpecification
        )
        k = payload.key_wrapping_specification
        self.assertEqual(
            enums.WrappingMethod.ENCRYPT,
            k.wrapping_method
        )
        self.assertIsInstance(
            k.encryption_key_information,
            objects.EncryptionKeyInformation
        )
        e = k.encryption_key_information
        self.assertEqual(
            '100182d5-72b8-47aa-8383-4d97d512e98a',
            e.unique_identifier
        )
        self.assertIsInstance(
            e.cryptographic_parameters,
            attributes.CryptographicParameters
        )
        self.assertEqual(
            enums.BlockCipherMode.NIST_KEY_WRAP,
            e.cryptographic_parameters.block_cipher_mode
        )
        self.assertEqual(
            k.encoding_option,
            enums.EncodingOption.NO_ENCODING
        )

    def test_read_partial(self):
        """
        Test that a GetRequestPayload struct can be read from a partial data
        stream.
        """
        payload = payloads.GetRequestPayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.key_format_type)
        self.assertEqual(None, payload.key_compression_type)
        self.assertEqual(None, payload.key_wrapping_specification)

        payload.read(self.partial_encoding)

        self.assertEqual(
            '49a1ca88-6bea-4fb2-b450-7e58802c3038',
            payload.unique_identifier
        )
        self.assertEqual(None, payload.key_format_type)
        self.assertEqual(None, payload.key_compression_type)
        self.assertEqual(None, payload.key_wrapping_specification)

    def test_read_empty(self):
        """
        Test that a GetRequestPayload struct can be read from an empty data
        stream.
        """
        payload = payloads.GetRequestPayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.key_format_type)
        self.assertEqual(None, payload.key_compression_type)
        self.assertEqual(None, payload.key_wrapping_specification)

        payload.read(self.empty_encoding)

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.key_format_type)
        self.assertEqual(None, payload.key_compression_type)
        self.assertEqual(None, payload.key_wrapping_specification)

    def test_write(self):
        """
        Test that a GetRequestPayload struct can be written to a data stream.
        """
        payload = payloads.GetRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            key_format_type=enums.KeyFormatType.RAW,
            key_compression_type=enums.KeyCompressionType.
            EC_PUBLIC_KEY_TYPE_UNCOMPRESSED,
            key_wrapping_specification=objects.KeyWrappingSpecification(
                wrapping_method=enums.WrappingMethod.ENCRYPT,
                encryption_key_information=objects.EncryptionKeyInformation(
                    unique_identifier='100182d5-72b8-47aa-8383-4d97d512e98a',
                    cryptographic_parameters=attributes.
                    CryptographicParameters(
                        block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                    )
                ),
                encoding_option=enums.EncodingOption.NO_ENCODING
            )
        )
        stream = utils.BytearrayStream()

        payload.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_partial(self):
        """
        Test that a partially defined GetRequestPayload struct can be written
        to a data stream.
        """
        payload = payloads.GetRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038'
        )
        stream = utils.BytearrayStream()

        payload.write(stream)

        self.assertEqual(len(self.partial_encoding), len(stream))
        self.assertEqual(str(self.partial_encoding), str(stream))

    def test_write_empty(self):
        """
        Test that an empty GetRequestPayload struct can be written to a data
        stream.
        """
        payload = payloads.GetRequestPayload()
        stream = utils.BytearrayStream()

        payload.write(stream)

        self.assertEqual(len(self.empty_encoding), len(stream))
        self.assertEqual(str(self.empty_encoding), str(stream))

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        GetRequestPayload structs with the same data.
        """
        a = payloads.GetRequestPayload()
        b = payloads.GetRequestPayload()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = payloads.GetRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            key_format_type=enums.KeyFormatType.RAW,
            key_compression_type=enums.KeyCompressionType.
            EC_PUBLIC_KEY_TYPE_UNCOMPRESSED,
            key_wrapping_specification=objects.KeyWrappingSpecification(
                wrapping_method=enums.WrappingMethod.ENCRYPT,
                encryption_key_information=objects.EncryptionKeyInformation(
                    unique_identifier='100182d5-72b8-47aa-8383-4d97d512e98a',
                    cryptographic_parameters=attributes.
                    CryptographicParameters(
                        block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                    )
                ),
                encoding_option=enums.EncodingOption.NO_ENCODING
            )
        )
        b = payloads.GetRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            key_format_type=enums.KeyFormatType.RAW,
            key_compression_type=enums.KeyCompressionType.
            EC_PUBLIC_KEY_TYPE_UNCOMPRESSED,
            key_wrapping_specification=objects.KeyWrappingSpecification(
                wrapping_method=enums.WrappingMethod.ENCRYPT,
                encryption_key_information=objects.EncryptionKeyInformation(
                    unique_identifier='100182d5-72b8-47aa-8383-4d97d512e98a',
                    cryptographic_parameters=attributes.
                    CryptographicParameters(
                        block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                    )
                ),
                encoding_option=enums.EncodingOption.NO_ENCODING
            )
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_unique_identifier(self):
        """
        Test that the equality operator returns False when comparing two
        GetRequestPayload structs with different unique identifiers.
        """
        a = payloads.GetRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038'
        )
        b = payloads.GetRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c303f'
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_key_format_type(self):
        """
        Test that the equality operator returns False when comparing two
        GetRequestPayload structs with different key format types.
        """
        a = payloads.GetRequestPayload(
            key_format_type=enums.KeyFormatType.RAW
        )
        b = payloads.GetRequestPayload(
            key_format_type=enums.KeyFormatType.OPAQUE
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_key_compression_type(self):
        """
        Test that the equality operator returns False when comparing two
        GetRequestPayload structs with different key compression types.
        """
        a = payloads.GetRequestPayload(
            key_compression_type=enums.KeyCompressionType.
            EC_PUBLIC_KEY_TYPE_UNCOMPRESSED
        )
        b = payloads.GetRequestPayload(
            key_compression_type=enums.KeyCompressionType.
            EC_PUBLIC_KEY_TYPE_X9_62_HYBRID
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_key_wrapping_specification(self):
        """
        Test that the equality operator returns False when comparing two
        GetRequestPayload structs with different key wrapping specifications.
        """
        a = payloads.GetRequestPayload(
            key_wrapping_specification=objects.KeyWrappingSpecification(
                wrapping_method=enums.WrappingMethod.ENCRYPT_THEN_MAC_SIGN,
                encryption_key_information=objects.EncryptionKeyInformation(
                    unique_identifier='100182d5-72b8-47aa-ffff-4d97d512e98a',
                    cryptographic_parameters=attributes.
                    CryptographicParameters(
                        block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                    )
                ),
                encoding_option=enums.EncodingOption.NO_ENCODING
            )
        )
        b = payloads.GetRequestPayload(
            key_wrapping_specification=objects.KeyWrappingSpecification(
                wrapping_method=enums.WrappingMethod.ENCRYPT,
                encryption_key_information=objects.EncryptionKeyInformation(
                    unique_identifier='100182d5-72b8-47aa-8383-4d97d512e98a',
                    cryptographic_parameters=attributes.
                    CryptographicParameters(
                        block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                    )
                ),
                encoding_option=enums.EncodingOption.NO_ENCODING
            )
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        GetRequestPayload structs with different types.
        """
        a = payloads.GetRequestPayload()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        GetRequestPayload structs with the same data.
        """
        a = payloads.GetRequestPayload()
        b = payloads.GetRequestPayload()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = payloads.GetRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            key_format_type=enums.KeyFormatType.RAW,
            key_compression_type=enums.KeyCompressionType.
            EC_PUBLIC_KEY_TYPE_UNCOMPRESSED,
            key_wrapping_specification=objects.KeyWrappingSpecification(
                wrapping_method=enums.WrappingMethod.ENCRYPT,
                encryption_key_information=objects.EncryptionKeyInformation(
                    unique_identifier='100182d5-72b8-47aa-8383-4d97d512e98a',
                    cryptographic_parameters=attributes.
                    CryptographicParameters(
                        block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                    )
                ),
                encoding_option=enums.EncodingOption.NO_ENCODING
            )
        )
        b = payloads.GetRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            key_format_type=enums.KeyFormatType.RAW,
            key_compression_type=enums.KeyCompressionType.
            EC_PUBLIC_KEY_TYPE_UNCOMPRESSED,
            key_wrapping_specification=objects.KeyWrappingSpecification(
                wrapping_method=enums.WrappingMethod.ENCRYPT,
                encryption_key_information=objects.EncryptionKeyInformation(
                    unique_identifier='100182d5-72b8-47aa-8383-4d97d512e98a',
                    cryptographic_parameters=attributes.
                    CryptographicParameters(
                        block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                    )
                ),
                encoding_option=enums.EncodingOption.NO_ENCODING
            )
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_unique_identifier(self):
        """
        Test that the inequality operator returns True when comparing two
        GetRequestPayload structs with different unique identifiers.
        """
        a = payloads.GetRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038'
        )
        b = payloads.GetRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c303f'
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_key_format_type(self):
        """
        Test that the inequality operator returns True when comparing two
        GetRequestPayload structs with different key format types.
        """
        a = payloads.GetRequestPayload(
            key_format_type=enums.KeyFormatType.RAW
        )
        b = payloads.GetRequestPayload(
            key_format_type=enums.KeyFormatType.OPAQUE
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_key_compression_type(self):
        """
        Test that the equality operator returns False when comparing two
        GetRequestPayload structs with different key compression types.
        """
        a = payloads.GetRequestPayload(
            key_compression_type=enums.KeyCompressionType.
            EC_PUBLIC_KEY_TYPE_UNCOMPRESSED
        )
        b = payloads.GetRequestPayload(
            key_compression_type=enums.KeyCompressionType.
            EC_PUBLIC_KEY_TYPE_X9_62_HYBRID
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_key_wrapping_specification(self):
        """
        Test that the inequality operator returns True when comparing two
        GetRequestPayload structs with different key wrapping specifications.
        """
        a = payloads.GetRequestPayload(
            key_wrapping_specification=objects.KeyWrappingSpecification(
                wrapping_method=enums.WrappingMethod.ENCRYPT_THEN_MAC_SIGN,
                encryption_key_information=objects.EncryptionKeyInformation(
                    unique_identifier='100182d5-72b8-47aa-ffff-4d97d512e98a',
                    cryptographic_parameters=attributes.
                    CryptographicParameters(
                        block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                    )
                ),
                encoding_option=enums.EncodingOption.NO_ENCODING
            )
        )
        b = payloads.GetRequestPayload(
            key_wrapping_specification=objects.KeyWrappingSpecification(
                wrapping_method=enums.WrappingMethod.ENCRYPT,
                encryption_key_information=objects.EncryptionKeyInformation(
                    unique_identifier='100182d5-72b8-47aa-8383-4d97d512e98a',
                    cryptographic_parameters=attributes.
                    CryptographicParameters(
                        block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                    )
                ),
                encoding_option=enums.EncodingOption.NO_ENCODING
            )
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        GetRequestPayload structs with different types.
        """
        a = payloads.GetRequestPayload()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test that repr can be applied to a GetRequestPayload struct.
        """
        payload = payloads.GetRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            key_format_type=enums.KeyFormatType.RAW,
            key_compression_type=enums.KeyCompressionType.
            EC_PUBLIC_KEY_TYPE_UNCOMPRESSED,
            key_wrapping_specification=objects.KeyWrappingSpecification(
                wrapping_method=enums.WrappingMethod.ENCRYPT,
                encryption_key_information=objects.EncryptionKeyInformation(
                    unique_identifier='100182d5-72b8-47aa-8383-4d97d512e98a',
                    cryptographic_parameters=attributes.
                    CryptographicParameters(
                        block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                    )
                ),
                encoding_option=enums.EncodingOption.NO_ENCODING
            )
        )

        expected = (
            "GetRequestPayload("
            "unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038', "
            "key_format_type=KeyFormatType.RAW, "
            "key_compression_type="
            "KeyCompressionType.EC_PUBLIC_KEY_TYPE_UNCOMPRESSED, "
            "key_wrapping_specification="
            "KeyWrappingSpecification("
            "wrapping_method=WrappingMethod.ENCRYPT, "
            "encryption_key_information=EncryptionKeyInformation("
            "unique_identifier='100182d5-72b8-47aa-8383-4d97d512e98a', "
            "cryptographic_parameters=CryptographicParameters("
            "block_cipher_mode=BlockCipherMode.NIST_KEY_WRAP, "
            "padding_method=None, "
            "hashing_algorithm=None, "
            "key_role_type=None, "
            "digital_signature_algorithm=None, "
            "cryptographic_algorithm=None, "
            "random_iv=None, "
            "iv_length=None, "
            "tag_length=None, "
            "fixed_field_length=None, "
            "invocation_field_length=None, "
            "counter_length=None, "
            "initial_counter_value=None)), "
            "mac_signature_key_information=None, "
            "attribute_names=None, "
            "encoding_option=EncodingOption.NO_ENCODING))"
        )
        observed = repr(payload)

        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a GetRequestPayload struct.
        """
        payload = payloads.GetRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            key_format_type=enums.KeyFormatType.RAW,
            key_compression_type=enums.KeyCompressionType.
            EC_PUBLIC_KEY_TYPE_UNCOMPRESSED,
            key_wrapping_specification=objects.KeyWrappingSpecification(
                wrapping_method=enums.WrappingMethod.ENCRYPT,
                encryption_key_information=objects.EncryptionKeyInformation(
                    unique_identifier='100182d5-72b8-47aa-8383-4d97d512e98a',
                    cryptographic_parameters=attributes.
                    CryptographicParameters(
                        block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                    )
                ),
                encoding_option=enums.EncodingOption.NO_ENCODING
            )
        )

        expected = str({
            'unique_identifier': '49a1ca88-6bea-4fb2-b450-7e58802c3038',
            'key_format_type': enums.KeyFormatType.RAW,
            'key_compression_type': enums.KeyCompressionType.
            EC_PUBLIC_KEY_TYPE_UNCOMPRESSED,
            'key_wrapping_specification': objects.KeyWrappingSpecification(
                wrapping_method=enums.WrappingMethod.ENCRYPT,
                encryption_key_information=objects.EncryptionKeyInformation(
                    unique_identifier='100182d5-72b8-47aa-8383-4d97d512e98a',
                    cryptographic_parameters=attributes.
                    CryptographicParameters(
                        block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                    )
                ),
                encoding_option=enums.EncodingOption.NO_ENCODING
            )
        })
        observed = str(payload)

        self.assertEqual(expected, observed)


class TestGetResponsePayload(testtools.TestCase):
    """
    Test suite for the Get response payload.
    """

    def setUp(self):
        super(TestGetResponsePayload, self).setUp()

        # Encoding obtained from the KMIP 1.1 testing document, Section 3.1.3.
        #
        # This encoding matches the following set of values:
        # Response Payload
        #     Object Type - Symmetric Key
        #     Unique Identifier - 49a1ca88-6bea-4fb2-b450-7e58802c3038
        #     Symmetric Key
        #         Key Block
        #             Key Format Type - Raw
        #             Key Value
        #                 Key Material - 0x7367578051012A6D134A855E25C8CD5E4C
        #                                A131455729D3C8
        #             Cryptographic Algorithm - 3DES
        #             Cryptographic Length - 168

        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\xA8'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x34\x39\x61\x31\x63\x61\x38\x38\x2D\x36\x62\x65\x61\x2D\x34\x66'
            b'\x62\x32\x2D\x62\x34\x35\x30\x2D\x37\x65\x35\x38\x38\x30\x32\x63'
            b'\x33\x30\x33\x38\x00\x00\x00\x00'
            b'\x42\x00\x8F\x01\x00\x00\x00\x60'
            b'\x42\x00\x40\x01\x00\x00\x00\x58'
            b'\x42\x00\x42\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x45\x01\x00\x00\x00\x20'
            b'\x42\x00\x43\x08\x00\x00\x00\x18'
            b'\x73\x67\x57\x80\x51\x01\x2A\x6D\x13\x4A\x85\x5E\x25\xC8\xCD\x5E'
            b'\x4C\xA1\x31\x45\x57\x29\xD3\xC8'
            b'\x42\x00\x28\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x2A\x02\x00\x00\x00\x04\x00\x00\x00\xA8\x00\x00\x00\x00'
        )

        self.partial_encoding_missing_object_type = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\xA0'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x34\x39\x61\x31\x63\x61\x38\x38\x2D\x36\x62\x65\x61\x2D\x34\x66'
            b'\x62\x32\x2D\x62\x34\x35\x30\x2D\x37\x65\x35\x38\x38\x30\x32\x63'
            b'\x33\x30\x33\x38\x00\x00\x00\x00'
            b'\x42\x00\x8F\x01\x00\x00\x00\x60'
            b'\x42\x00\x40\x01\x00\x00\x00\x58'
            b'\x42\x00\x42\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x45\x01\x00\x00\x00\x20'
            b'\x42\x00\x43\x08\x00\x00\x00\x18'
            b'\x73\x67\x57\x80\x51\x01\x2A\x6D\x13\x4A\x85\x5E\x25\xC8\xCD\x5E'
            b'\x4C\xA1\x31\x45\x57\x29\xD3\xC8'
            b'\x42\x00\x28\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x2A\x02\x00\x00\x00\x04\x00\x00\x00\xA8\x00\x00\x00\x00'
        )
        self.partial_encoding_missing_unique_id = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x78'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x8F\x01\x00\x00\x00\x60'
            b'\x42\x00\x40\x01\x00\x00\x00\x58'
            b'\x42\x00\x42\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x45\x01\x00\x00\x00\x20'
            b'\x42\x00\x43\x08\x00\x00\x00\x18'
            b'\x73\x67\x57\x80\x51\x01\x2A\x6D\x13\x4A\x85\x5E\x25\xC8\xCD\x5E'
            b'\x4C\xA1\x31\x45\x57\x29\xD3\xC8'
            b'\x42\x00\x28\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x2A\x02\x00\x00\x00\x04\x00\x00\x00\xA8\x00\x00\x00\x00'
        )
        self.partial_encoding_missing_secret = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x40'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x34\x39\x61\x31\x63\x61\x38\x38\x2D\x36\x62\x65\x61\x2D\x34\x66'
            b'\x62\x32\x2D\x62\x34\x35\x30\x2D\x37\x65\x35\x38\x38\x30\x32\x63'
            b'\x33\x30\x33\x38\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestGetResponsePayload, self).tearDown()

    def test_init(self):
        """
        Test that a GetRequestPayload struct can be constructed with no
        arguments.
        """
        payload = payloads.GetResponsePayload()

        self.assertEqual(None, payload.object_type)
        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.secret)

    def test_init_with_args(self):
        """
        Test that a GetRequestPayload struct can be constructed with valid
        values.
        """
        payload = payloads.GetResponsePayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifier='11111111-3333-5555-7777-999999999999',
            secret=secrets.SymmetricKey(
                key_block=objects.KeyBlock(
                    key_format_type=misc.KeyFormatType(
                        enums.KeyFormatType.RAW
                    ),
                    key_value=objects.KeyValue(
                        key_material=objects.KeyMaterial(
                            b'\x73\x67\x57\x80\x51\x01\x2A\x6D'
                            b'\x13\x4A\x85\x5E\x25\xC8\xCD\x5E'
                            b'\x4C\xA1\x31\x45\x57\x29\xD3\xC8'
                        )
                    ),
                    cryptographic_algorithm=attributes.CryptographicAlgorithm(
                        enums.CryptographicAlgorithm.TRIPLE_DES
                    ),
                    cryptographic_length=attributes.CryptographicLength(168)
                )
            )
        )

        self.assertEqual(
            enums.ObjectType.SYMMETRIC_KEY,
            payload.object_type
        )
        self.assertEqual(
            '11111111-3333-5555-7777-999999999999',
            payload.unique_identifier
        )
        self.assertIsInstance(payload.secret, secrets.SymmetricKey)
        self.assertIsInstance(payload.secret.key_block, objects.KeyBlock)
        self.assertIsInstance(
            payload.secret.key_block.key_format_type,
            misc.KeyFormatType
        )
        self.assertEqual(
            enums.KeyFormatType.RAW,
            payload.secret.key_block.key_format_type.value
        )
        self.assertIsInstance(
            payload.secret.key_block.key_value,
            objects.KeyValue
        )
        self.assertIsInstance(
            payload.secret.key_block.key_value.key_material,
            objects.KeyMaterial
        )
        self.assertEqual(
            (
                b'\x73\x67\x57\x80\x51\x01\x2A\x6D'
                b'\x13\x4A\x85\x5E\x25\xC8\xCD\x5E'
                b'\x4C\xA1\x31\x45\x57\x29\xD3\xC8'
            ),
            payload.secret.key_block.key_value.key_material.value
        )
        self.assertIsInstance(
            payload.secret.key_block.cryptographic_algorithm,
            attributes.CryptographicAlgorithm
        )
        self.assertEqual(
            enums.CryptographicAlgorithm.TRIPLE_DES,
            payload.secret.key_block.cryptographic_algorithm.value
        )
        self.assertIsInstance(
            payload.secret.key_block.cryptographic_length,
            attributes.CryptographicLength
        )
        self.assertEqual(
            168,
            payload.secret.key_block.cryptographic_length.value
        )

    def test_invalid_object_type(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the object type of a GetResponsePayload struct.
        """
        kwargs = {'object_type': 'invalid'}
        self.assertRaisesRegexp(
            TypeError,
            "Object type must be an ObjectType enumeration.",
            payloads.GetResponsePayload,
            **kwargs
        )

        args = (payloads.GetResponsePayload(), 'object_type', 'invalid')
        self.assertRaisesRegexp(
            TypeError,
            "Object type must be an ObjectType enumeration.",
            setattr,
            *args
        )

    def test_invalid_unique_identifier(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the unique identifier of a GetResponsePayload struct.
        """
        kwargs = {'unique_identifier': 0}
        self.assertRaisesRegexp(
            TypeError,
            "Unique identifier must be a string.",
            payloads.GetResponsePayload,
            **kwargs
        )

        args = (payloads.GetResponsePayload(), 'unique_identifier', 0)
        self.assertRaisesRegexp(
            TypeError,
            "Unique identifier must be a string.",
            setattr,
            *args
        )

    def test_invalid_secret(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the secret of a GetResponsePayload struct.
        """
        kwargs = {'secret': 0}
        self.assertRaisesRegexp(
            TypeError,
            "Secret must be one of the following structs: Certificate, "
            "OpaqueObject, PrivateKey, PublicKey, SecretData, SplitKey, "
            "SymmetricKey, Template",
            payloads.GetResponsePayload,
            **kwargs
        )

        args = (payloads.GetResponsePayload(), 'secret', 0)
        self.assertRaisesRegexp(
            TypeError,
            "Secret must be one of the following structs: Certificate, "
            "OpaqueObject, PrivateKey, PublicKey, SecretData, SplitKey, "
            "SymmetricKey, Template",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a GetResponsePayload struct can be read from a data stream.
        """
        payload = payloads.GetResponsePayload()

        self.assertEqual(None, payload.object_type)
        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.secret)

        payload.read(self.full_encoding)

        self.assertEqual(enums.ObjectType.SYMMETRIC_KEY, payload.object_type)
        self.assertEqual(
            '49a1ca88-6bea-4fb2-b450-7e58802c3038',
            payload.unique_identifier
        )
        self.assertIsInstance(payload.secret, secrets.SymmetricKey)
        self.assertIsInstance(payload.secret.key_block, objects.KeyBlock)
        self.assertIsInstance(
            payload.secret.key_block.key_format_type,
            misc.KeyFormatType
        )
        self.assertEqual(
            enums.KeyFormatType.RAW,
            payload.secret.key_block.key_format_type.value
        )
        self.assertIsInstance(
            payload.secret.key_block.key_value,
            objects.KeyValue
        )
        self.assertIsInstance(
            payload.secret.key_block.key_value.key_material,
            objects.KeyMaterial
        )
        self.assertEqual(
            (
                b'\x73\x67\x57\x80\x51\x01\x2A\x6D'
                b'\x13\x4A\x85\x5E\x25\xC8\xCD\x5E'
                b'\x4C\xA1\x31\x45\x57\x29\xD3\xC8'
            ),
            payload.secret.key_block.key_value.key_material.value
        )
        self.assertIsInstance(
            payload.secret.key_block.cryptographic_algorithm,
            attributes.CryptographicAlgorithm
        )
        self.assertEqual(
            enums.CryptographicAlgorithm.TRIPLE_DES,
            payload.secret.key_block.cryptographic_algorithm.value
        )
        self.assertIsInstance(
            payload.secret.key_block.cryptographic_length,
            attributes.CryptographicLength
        )
        self.assertEqual(
            168,
            payload.secret.key_block.cryptographic_length.value
        )

    def test_read_missing_object_type(self):
        """
        Test that a ValueError gets raised when a required GetResponsePayload
        field is missing when decoding the struct.
        """
        payload = payloads.GetResponsePayload()
        args = (self.partial_encoding_missing_object_type, )
        self.assertRaisesRegexp(
            ValueError,
            "Parsed payload encoding is missing the object type field.",
            payload.read,
            *args
        )

    def test_read_missing_unique_identifier(self):
        """
        Test that a ValueError gets raised when a required GetResponsePayload
        field is missing when decoding the struct.
        """
        payload = payloads.GetResponsePayload()
        args = (self.partial_encoding_missing_unique_id, )
        self.assertRaisesRegexp(
            ValueError,
            "Parsed payload encoding is missing the unique identifier field.",
            payload.read,
            *args
        )

    def test_read_missing_secret(self):
        """
        Test that a ValueError gets raised when a required GetResponsePayload
        field is missing when decoding the struct.
        """
        payload = payloads.GetResponsePayload()
        args = (self.partial_encoding_missing_secret, )
        self.assertRaisesRegexp(
            ValueError,
            "Parsed payload encoding is missing the secret field.",
            payload.read,
            *args
        )

    def test_write(self):
        """
        Test that a GetResponsePayload struct can be written to a data stream.
        """
        payload = payloads.GetResponsePayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            secret=secrets.SymmetricKey(
                key_block=objects.KeyBlock(
                    key_format_type=misc.KeyFormatType(
                        enums.KeyFormatType.RAW
                    ),
                    key_value=objects.KeyValue(
                        key_material=objects.KeyMaterial(
                            b'\x73\x67\x57\x80\x51\x01\x2A\x6D'
                            b'\x13\x4A\x85\x5E\x25\xC8\xCD\x5E'
                            b'\x4C\xA1\x31\x45\x57\x29\xD3\xC8'
                        )
                    ),
                    cryptographic_algorithm=attributes.CryptographicAlgorithm(
                        enums.CryptographicAlgorithm.TRIPLE_DES
                    ),
                    cryptographic_length=attributes.CryptographicLength(168)
                )
            )
        )
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_missing_object_type(self):
        """
        Test that a ValueError gets raised when a required GetResponsePayload
        field is missing when encoding the struct.
        """
        payload = payloads.GetResponsePayload()
        stream = utils.BytearrayStream()
        args = (stream, )
        self.assertRaisesRegexp(
            ValueError,
            "Payload is missing the object type field.",
            payload.write,
            *args
        )

    def test_write_missing_unique_identifier(self):
        """
        Test that a ValueError gets raised when a required GetResponsePayload
        field is missing when encoding the struct.
        """
        payload = payloads.GetResponsePayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY
        )
        stream = utils.BytearrayStream()
        args = (stream, )
        self.assertRaisesRegexp(
            ValueError,
            "Payload is missing the unique identifier field.",
            payload.write,
            *args
        )

    def test_write_missing_secret(self):
        """
        Test that a ValueError gets raised when a required GetResponsePayload
        field is missing when encoding the struct.
        """
        payload = payloads.GetResponsePayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038'
        )
        stream = utils.BytearrayStream()
        args = (stream, )
        self.assertRaisesRegexp(
            ValueError,
            "Payload is missing the secret field.",
            payload.write,
            *args
        )

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        GetResponsePayload structs with the same data.
        """
        a = payloads.GetResponsePayload()
        b = payloads.GetResponsePayload()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        # TODO (peter-hamilton): Update this once equality is supported for
        # SymmetricKeys.
        secret = secrets.SymmetricKey(
                key_block=objects.KeyBlock(
                    key_format_type=misc.KeyFormatType(
                        enums.KeyFormatType.RAW
                    ),
                    key_value=objects.KeyValue(
                        key_material=objects.KeyMaterial(
                            b'\x73\x67\x57\x80\x51\x01\x2A\x6D'
                            b'\x13\x4A\x85\x5E\x25\xC8\xCD\x5E'
                            b'\x4C\xA1\x31\x45\x57\x29\xD3\xC8'
                        )
                    ),
                    cryptographic_algorithm=attributes.CryptographicAlgorithm(
                        enums.CryptographicAlgorithm.TRIPLE_DES
                    ),
                    cryptographic_length=attributes.CryptographicLength(168)
                )
            )

        a = payloads.GetResponsePayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            secret=secret
        )
        b = payloads.GetResponsePayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            secret=secret
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_object_type(self):
        """
        Test that the equality operator returns False when comparing two
        GetResponsePayload structs with different object type fields.
        """
        a = payloads.GetResponsePayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY
        )
        b = payloads.GetResponsePayload(
            object_type=enums.ObjectType.OPAQUE_DATA
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_unique_identifier(self):
        """
        Test that the equality operator returns False when comparing two
        GetResponsePayload structs with different unique identifier fields.
        """
        a = payloads.GetResponsePayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038'
        )
        b = payloads.GetResponsePayload(
            unique_identifier='49a1ca88-6bea-4fb2-ffff-7e58802c3038'
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_secrets(self):
        """
        Test that the equality operator returns False when comparing two
        GetResponsePayload structs with different secret fields.
        """
        # TODO (peter-hamilton): Update this test case once SymmetricKeys
        # support proper field-based equality.
        a = payloads.GetResponsePayload(
            secret=secrets.SymmetricKey(
                key_block=objects.KeyBlock(
                    key_format_type=misc.KeyFormatType(
                        enums.KeyFormatType.RAW
                    ),
                    key_value=objects.KeyValue(
                        key_material=objects.KeyMaterial(
                            b'\x73\x67\x57\x80\x51\x01\x2A\x6D'
                            b'\x13\x4A\x85\x5E\x25\xC8\xCD\x5E'
                            b'\x4C\xA1\x31\x45\x57\x29\xD3\xC8'
                        )
                    ),
                    cryptographic_algorithm=attributes.CryptographicAlgorithm(
                        enums.CryptographicAlgorithm.TRIPLE_DES
                    ),
                    cryptographic_length=attributes.CryptographicLength(168)
                )
            )
        )
        b = payloads.GetResponsePayload(
            secret=secrets.SymmetricKey(
                key_block=objects.KeyBlock(
                    key_format_type=misc.KeyFormatType(
                        enums.KeyFormatType.RAW
                    ),
                    key_value=objects.KeyValue(
                        key_material=objects.KeyMaterial(
                            b'\x73\x67\x57\x80\x51\x01\x2A\x6D'
                            b'\x13\x4A\x85\x5E\x25\xC8\xCD\x5E'
                            b'\x4C\xA1\x31\x45\x57\x29\xD3\xC8'
                        )
                    ),
                    cryptographic_algorithm=attributes.CryptographicAlgorithm(
                        enums.CryptographicAlgorithm.TRIPLE_DES
                    ),
                    cryptographic_length=attributes.CryptographicLength(168)
                )
            )
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operators returns False when comparing two
        GetResponsePayload structs with different types.
        """
        a = payloads.GetResponsePayload()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        GetResponsePayload structs with the same data.
        """
        a = payloads.GetResponsePayload()
        b = payloads.GetResponsePayload()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        # TODO (peter-hamilton): Update this once equality is supported for
        # SymmetricKeys.
        secret = secrets.SymmetricKey(
            key_block=objects.KeyBlock(
                key_format_type=misc.KeyFormatType(enums.KeyFormatType.RAW),
                key_value=objects.KeyValue(
                    key_material=objects.KeyMaterial(
                        b'\x73\x67\x57\x80\x51\x01\x2A\x6D'
                        b'\x13\x4A\x85\x5E\x25\xC8\xCD\x5E'
                        b'\x4C\xA1\x31\x45\x57\x29\xD3\xC8'
                    )
                ),
                cryptographic_algorithm=attributes.CryptographicAlgorithm(
                    enums.CryptographicAlgorithm.TRIPLE_DES
                ),
                cryptographic_length=attributes.CryptographicLength(168)
            )
        )

        a = payloads.GetResponsePayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            secret=secret
        )
        b = payloads.GetResponsePayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            secret=secret
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_object_type(self):
        """
        Test that the inequality operator returns True when comparing two
        GetResponsePayload structs with different object type fields.
        """
        a = payloads.GetResponsePayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY
        )
        b = payloads.GetResponsePayload(
            object_type=enums.ObjectType.OPAQUE_DATA
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_unique_identifier(self):
        """
        Test that the inequality operator returns True when comparing two
        GetResponsePayload structs with different unique identifier fields.
        """
        a = payloads.GetResponsePayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038'
        )
        b = payloads.GetResponsePayload(
            unique_identifier='49a1ca88-6bea-4fb2-ffff-7e58802c3038'
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_secrets(self):
        """
        Test that the inequality operator returns True when comparing two
        GetResponsePayload structs with different secret fields.
        """
        # TODO (peter-hamilton): Update this test case once SymmetricKeys
        # support proper field-based equality.
        a = payloads.GetResponsePayload(
            secret=secrets.SymmetricKey(
                key_block=objects.KeyBlock(
                    key_format_type=misc.KeyFormatType(
                        enums.KeyFormatType.RAW
                    ),
                    key_value=objects.KeyValue(
                        key_material=objects.KeyMaterial(
                            b'\x73\x67\x57\x80\x51\x01\x2A\x6D'
                            b'\x13\x4A\x85\x5E\x25\xC8\xCD\x5E'
                            b'\x4C\xA1\x31\x45\x57\x29\xD3\xC8'
                        )
                    ),
                    cryptographic_algorithm=attributes.CryptographicAlgorithm(
                        enums.CryptographicAlgorithm.TRIPLE_DES
                    ),
                    cryptographic_length=attributes.CryptographicLength(168)
                )
            )
        )
        b = payloads.GetResponsePayload(
            secret=secrets.SymmetricKey(
                key_block=objects.KeyBlock(
                    key_format_type=misc.KeyFormatType(
                        enums.KeyFormatType.RAW
                    ),
                    key_value=objects.KeyValue(
                        key_material=objects.KeyMaterial(
                            b'\x73\x67\x57\x80\x51\x01\x2A\x6D'
                            b'\x13\x4A\x85\x5E\x25\xC8\xCD\x5E'
                            b'\x4C\xA1\x31\x45\x57\x29\xD3\xC8'
                        )
                    ),
                    cryptographic_algorithm=attributes.CryptographicAlgorithm(
                        enums.CryptographicAlgorithm.TRIPLE_DES
                    ),
                    cryptographic_length=attributes.CryptographicLength(168)
                )
            )
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operators returns True when comparing two
        GetResponsePayload structs with different types.
        """
        a = payloads.GetResponsePayload()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test that repr can be applied to a GetResponsePayload struct.
        """
        payload = payloads.GetResponsePayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            secret=secrets.SymmetricKey(
                key_block=objects.KeyBlock(
                    key_format_type=misc.KeyFormatType(
                        enums.KeyFormatType.RAW
                    ),
                    key_value=objects.KeyValue(
                        key_material=objects.KeyMaterial(
                            b'\x73\x67\x57\x80\x51\x01\x2A\x6D'
                            b'\x13\x4A\x85\x5E\x25\xC8\xCD\x5E'
                            b'\x4C\xA1\x31\x45\x57\x29\xD3\xC8'
                        )
                    ),
                    cryptographic_algorithm=attributes.CryptographicAlgorithm(
                        enums.CryptographicAlgorithm.TRIPLE_DES
                    ),
                    cryptographic_length=attributes.CryptographicLength(168)
                )
            )
        )

        # TODO (peter-hamilton): Update the secret portion once SymmetricKeys
        # support repr/str.
        expected = (
            "GetResponsePayload("
            "object_type=ObjectType.SYMMETRIC_KEY, "
            "unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038', "
            "secret=Struct()"
            ")"
        )
        observed = repr(payload)

        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a GetResponsePayload struct.
        """
        secret = secrets.SymmetricKey(
            key_block=objects.KeyBlock(
                key_format_type=misc.KeyFormatType(enums.KeyFormatType.RAW),
                key_value=objects.KeyValue(
                    key_material=objects.KeyMaterial(
                        b'\x73\x67\x57\x80\x51\x01\x2A\x6D'
                        b'\x13\x4A\x85\x5E\x25\xC8\xCD\x5E'
                        b'\x4C\xA1\x31\x45\x57\x29\xD3\xC8'
                    )
                ),
                cryptographic_algorithm=attributes.CryptographicAlgorithm(
                    enums.CryptographicAlgorithm.TRIPLE_DES
                ),
                cryptographic_length=attributes.CryptographicLength(168)
            )
        )
        payload = payloads.GetResponsePayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            secret=secret
        )

        # TODO (peter-hamilton): Update the secret portion once SymmetricKeys
        # support repr/str.
        expected = str({
            'object_type': enums.ObjectType.SYMMETRIC_KEY,
            'unique_identifier': '49a1ca88-6bea-4fb2-b450-7e58802c3038',
            'secret': secret
        })
        observed = str(payload)

        self.assertEqual(expected, observed)
