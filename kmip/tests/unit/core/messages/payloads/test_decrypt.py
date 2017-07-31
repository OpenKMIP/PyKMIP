# Copyright (c) 2017 The Johns Hopkins University/Applied Physics Laboratory
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
from kmip.core import utils

from kmip.core.messages import payloads


class TestDecryptRequestPayload(testtools.TestCase):
    """
    Test suite for the Decrypt request payload.
    """

    def setUp(self):
        super(TestDecryptRequestPayload, self).setUp()

        # Encoding obtained in part from the KMIP 1.1 testing document,
        # Section 11.1. The rest of the encoding for KMIP 1.2+ features was
        # built by hand; later KMIP testing documents do not include the
        # encoding, so a manual construction is necessary.
        #
        # This encoding matches the following set of values:
        # Unique Identifier - b4faee10-aa2a-4446-8ad4-0881f3422959
        # Cryptographic Parameters
        #     Block Cipher Mode - CBC
        #     Padding Method - PKCS5
        #     Hashing Algorithm - SHA-1
        #     Key Role Type - KEK
        #     Digital Signature Algorithm - SHA-256 with RSA
        #     Cryptographic Algorithm - AES
        #     Random IV - True
        #     IV Length - 96
        #     Tag Length - 128
        #     Fixed Field Length - 32
        #     Invocation Field Length - 64
        #     Counter Length - 0
        #     Initial Counter Value - 1
        # Data - 0x0123456789ABCDEF
        # IV/Counter/Nonce - 0x01

        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x01\x28'
            b'\x42\x00\x94\x07\x00\x00\x00\x24\x62\x34\x66\x61\x65\x65\x31\x30'
            b'\x2D\x61\x61\x32\x61\x2D\x34\x34\x34\x36\x2D\x38\x61\x64\x34\x2D'
            b'\x30\x38\x38\x31\x66\x33\x34\x32\x32\x39\x35\x39\x00\x00\x00\x00'
            b'\x42\x00\x2B\x01\x00\x00\x00\xD0'
            b'\x42\x00\x11\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x5F\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x38\x05\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00'
            b'\x42\x00\x83\x05\x00\x00\x00\x04\x00\x00\x00\x0B\x00\x00\x00\x00'
            b'\x42\x00\xAE\x05\x00\x00\x00\x04\x00\x00\x00\x05\x00\x00\x00\x00'
            b'\x42\x00\x28\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\xC5\x06\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x01'
            b'\x42\x00\xCD\x02\x00\x00\x00\x04\x00\x00\x00\x60\x00\x00\x00\x00'
            b'\x42\x00\xCE\x02\x00\x00\x00\x04\x00\x00\x00\x80\x00\x00\x00\x00'
            b'\x42\x00\xCF\x02\x00\x00\x00\x04\x00\x00\x00\x20\x00\x00\x00\x00'
            b'\x42\x00\xD2\x02\x00\x00\x00\x04\x00\x00\x00\x40\x00\x00\x00\x00'
            b'\x42\x00\xD0\x02\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xD1\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\xC2\x08\x00\x00\x00\x08\x01\x23\x45\x67\x89\xAB\xCD\xEF'
            b'\x42\x00\x3D\x08\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00'
        )

        # Adapted from the full encoding above. This encoding matches the
        # following set of values:
        # Data - 0x0123456789ABCDEF

        self.minimum_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x10'
            b'\x42\x00\xC2\x08\x00\x00\x00\x08\x01\x02\x03\x04\x05\x06\x07\x08'
        )

        self.empty_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestDecryptRequestPayload, self).tearDown()

    def test_init(self):
        """
        Test that a Decrypt request payload can be constructed with no
        arguments.
        """
        payload = payloads.DecryptRequestPayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.cryptographic_parameters)
        self.assertEqual(None, payload.data)
        self.assertEqual(None, payload.iv_counter_nonce)

    def test_init_with_args(self):
        """
        Test that a Decrypt request payload can be constructed with valid
        values
        """
        payload = payloads.DecryptRequestPayload(
            unique_identifier='00000000-1111-2222-3333-444444444444',
            cryptographic_parameters=attributes.CryptographicParameters(),
            data=b'\x01\x02\x03',
            iv_counter_nonce=b'\x01'
        )

        self.assertEqual(
            '00000000-1111-2222-3333-444444444444',
            payload.unique_identifier
        )
        self.assertEqual(
            attributes.CryptographicParameters(),
            payload.cryptographic_parameters
        )
        self.assertEqual(b'\x01\x02\x03', payload.data)
        self.assertEqual(b'\x01', payload.iv_counter_nonce)

    def test_invalid_unique_identifier(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the unique identifier of a Decrypt request payload.
        """
        payload = payloads.DecryptRequestPayload()
        args = (payload, 'unique_identifier', 0)
        self.assertRaisesRegexp(
            TypeError,
            "unique identifier must be a string",
            setattr,
            *args
        )

    def test_invalid_cryptographic_parameters(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the cryptographic parameters of a Decrypt request payload.
        """
        payload = payloads.DecryptRequestPayload()
        args = (payload, 'cryptographic_parameters', 'invalid')
        self.assertRaisesRegexp(
            TypeError,
            "cryptographic parameters must be a CryptographicParameters "
            "struct",
            setattr,
            *args
        )

    def test_invalid_data(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the data of a Decrypt request payload.
        """
        payload = payloads.DecryptRequestPayload()
        args = (payload, 'data', 0)
        self.assertRaisesRegexp(
            TypeError,
            "data must be bytes",
            setattr,
            *args
        )

    def test_invalid_iv_counter_nonce(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the IV/counter/nonce of a Decrypt request payload.
        """
        payload = payloads.DecryptRequestPayload()
        args = (payload, 'iv_counter_nonce', 0)
        self.assertRaisesRegexp(
            TypeError,
            "IV/counter/nonce must be bytes",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a Decrypt request payload can be read from a data stream.
        """
        payload = payloads.DecryptRequestPayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.cryptographic_parameters)
        self.assertEqual(None, payload.data)
        self.assertEqual(None, payload.iv_counter_nonce)

        payload.read(self.full_encoding)

        self.assertEqual(
            'b4faee10-aa2a-4446-8ad4-0881f3422959',
            payload.unique_identifier
        )
        self.assertIsNotNone(payload.cryptographic_parameters)
        self.assertEqual(
            enums.BlockCipherMode.CBC,
            payload.cryptographic_parameters.block_cipher_mode
        )
        self.assertEqual(
            enums.PaddingMethod.PKCS5,
            payload.cryptographic_parameters.padding_method
        )
        self.assertEqual(
            enums.HashingAlgorithm.SHA_1,
            payload.cryptographic_parameters.hashing_algorithm
        )
        self.assertEqual(
            enums.KeyRoleType.KEK,
            payload.cryptographic_parameters.key_role_type
        )
        self.assertEqual(
            enums.DigitalSignatureAlgorithm.SHA256_WITH_RSA_ENCRYPTION,
            payload.cryptographic_parameters.digital_signature_algorithm
        )
        self.assertEqual(
            enums.CryptographicAlgorithm.AES,
            payload.cryptographic_parameters.cryptographic_algorithm
        )
        self.assertEqual(True, payload.cryptographic_parameters.random_iv)
        self.assertEqual(96, payload.cryptographic_parameters.iv_length)
        self.assertEqual(128, payload.cryptographic_parameters.tag_length)
        self.assertEqual(
            32,
            payload.cryptographic_parameters.fixed_field_length
        )
        self.assertEqual(
            64,
            payload.cryptographic_parameters.invocation_field_length
        )
        self.assertEqual(0, payload.cryptographic_parameters.counter_length)
        self.assertEqual(
            1,
            payload.cryptographic_parameters.initial_counter_value
        )
        self.assertEqual(b'\x01\x23\x45\x67\x89\xAB\xCD\xEF', payload.data)
        self.assertEqual(b'\x01', payload.iv_counter_nonce)

    def test_read_partial(self):
        """
        Test that a Decrypt request payload can be read from a partial data
        stream containing the minimum required attributes.
        """
        payload = payloads.DecryptRequestPayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.cryptographic_parameters)
        self.assertEqual(None, payload.data)
        self.assertEqual(None, payload.iv_counter_nonce)

        payload.read(self.minimum_encoding)

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.cryptographic_parameters)
        self.assertEqual(b'\x01\x02\x03\x04\x05\x06\x07\x08', payload.data)
        self.assertEqual(None, payload.iv_counter_nonce)

    def test_read_invalid(self):
        """
        Test that a ValueError gets raised when a required Decrypt request
        payload attribute is missing from the payload encoding.
        """
        payload = payloads.DecryptRequestPayload()
        args = (self.empty_encoding, )
        self.assertRaisesRegexp(
            ValueError,
            "invalid payload missing the data attribute",
            payload.read,
            *args
        )

    def test_write(self):
        """
        Test that a Decrypt request payload can be written to a data stream.
        """
        payload = payloads.DecryptRequestPayload(
            unique_identifier='b4faee10-aa2a-4446-8ad4-0881f3422959',
            cryptographic_parameters=attributes.CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.CBC,
                padding_method=enums.PaddingMethod.PKCS5,
                hashing_algorithm=enums.HashingAlgorithm.SHA_1,
                key_role_type=enums.KeyRoleType.KEK,
                digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
                SHA256_WITH_RSA_ENCRYPTION,
                cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
                random_iv=True,
                iv_length=96,
                tag_length=128,
                fixed_field_length=32,
                invocation_field_length=64,
                counter_length=0,
                initial_counter_value=1
            ),
            data=b'\x01\x23\x45\x67\x89\xAB\xCD\xEF',
            iv_counter_nonce=b'\x01'
        )
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_partial(self):
        """
        Test that a partially defined Decrypt request payload can be written
        to a data stream.
        """
        payload = payloads.DecryptRequestPayload(
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08'
        )
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.minimum_encoding), len(stream))
        self.assertEqual(str(self.minimum_encoding), str(stream))

    def test_write_invalid(self):
        """
        Test that a ValueError gets raised when a required Decrypt request
        payload attribute is missing when encoding the payload.
        """
        payload = payloads.DecryptRequestPayload()
        stream = utils.BytearrayStream()
        args = (stream, )
        self.assertRaisesRegexp(
            ValueError,
            "invalid payload missing the data attribute",
            payload.write,
            *args
        )

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        Decrypt request payloads with the same data.
        """
        a = payloads.DecryptRequestPayload()
        b = payloads.DecryptRequestPayload()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = payloads.DecryptRequestPayload(
            unique_identifier='b4faee10-aa2a-4446-8ad4-0881f3422959',
            cryptographic_parameters=attributes.CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.CBC,
                padding_method=enums.PaddingMethod.PKCS5,
                hashing_algorithm=enums.HashingAlgorithm.SHA_1,
                key_role_type=enums.KeyRoleType.KEK,
                digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
                SHA256_WITH_RSA_ENCRYPTION,
                cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
                random_iv=True,
                iv_length=96,
                tag_length=128,
                fixed_field_length=32,
                invocation_field_length=64,
                counter_length=0,
                initial_counter_value=1
            ),
            data=b'\x01\x23\x45\x67\x89\xAB\xCD\xEF',
            iv_counter_nonce=b'\x01'
        )
        b = payloads.DecryptRequestPayload(
            unique_identifier='b4faee10-aa2a-4446-8ad4-0881f3422959',
            cryptographic_parameters=attributes.CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.CBC,
                padding_method=enums.PaddingMethod.PKCS5,
                hashing_algorithm=enums.HashingAlgorithm.SHA_1,
                key_role_type=enums.KeyRoleType.KEK,
                digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
                SHA256_WITH_RSA_ENCRYPTION,
                cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
                random_iv=True,
                iv_length=96,
                tag_length=128,
                fixed_field_length=32,
                invocation_field_length=64,
                counter_length=0,
                initial_counter_value=1
            ),
            data=b'\x01\x23\x45\x67\x89\xAB\xCD\xEF',
            iv_counter_nonce=b'\x01'
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_unique_identifier(self):
        """
        Test that the equality operator returns False when comparing two
        Decrypt request payloads with different unique identifiers.
        """
        a = payloads.DecryptRequestPayload(
            unique_identifier='a'
        )
        b = payloads.DecryptRequestPayload(
            unique_identifier='b'
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_cryptographic_parameters(self):
        """
        Test that the equality operator returns False when comparing two
        Decrypt request payloads with different cryptographic parameters.
        """
        a = payloads.DecryptRequestPayload(
            cryptographic_parameters=attributes.CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.CBC
            )
        )
        b = payloads.DecryptRequestPayload(
            cryptographic_parameters=attributes.CryptographicParameters(
                hashing_algorithm=enums.HashingAlgorithm.MD5
            )
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_data(self):
        """
        Test that the equality operator returns False when comparing two
        Decrypt request payloads with different data.
        """
        a = payloads.DecryptRequestPayload(data=b'\x11')
        b = payloads.DecryptRequestPayload(data=b'\xFF')

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_iv_counter_nonce(self):
        """
        Test that the equality operator returns False when comparing two
        Decrypt request payloads with different IV/counter/nonce values.
        """
        a = payloads.DecryptRequestPayload(iv_counter_nonce=b'\x22')
        b = payloads.DecryptRequestPayload(iv_counter_nonce=b'\xAA')

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        Decrypt request payloads with different types.
        """
        a = payloads.DecryptRequestPayload()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        Decrypt request payloads with the same data.
        """
        a = payloads.DecryptRequestPayload()
        b = payloads.DecryptRequestPayload()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = payloads.DecryptRequestPayload(
            unique_identifier='b4faee10-aa2a-4446-8ad4-0881f3422959',
            cryptographic_parameters=attributes.CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.CBC,
                padding_method=enums.PaddingMethod.PKCS5,
                hashing_algorithm=enums.HashingAlgorithm.SHA_1,
                key_role_type=enums.KeyRoleType.KEK,
                digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
                SHA256_WITH_RSA_ENCRYPTION,
                cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
                random_iv=True,
                iv_length=96,
                tag_length=128,
                fixed_field_length=32,
                invocation_field_length=64,
                counter_length=0,
                initial_counter_value=1
            ),
            data=b'\x01\x23\x45\x67\x89\xAB\xCD\xEF',
            iv_counter_nonce=b'\x01'
        )
        b = payloads.DecryptRequestPayload(
            unique_identifier='b4faee10-aa2a-4446-8ad4-0881f3422959',
            cryptographic_parameters=attributes.CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.CBC,
                padding_method=enums.PaddingMethod.PKCS5,
                hashing_algorithm=enums.HashingAlgorithm.SHA_1,
                key_role_type=enums.KeyRoleType.KEK,
                digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
                SHA256_WITH_RSA_ENCRYPTION,
                cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
                random_iv=True,
                iv_length=96,
                tag_length=128,
                fixed_field_length=32,
                invocation_field_length=64,
                counter_length=0,
                initial_counter_value=1
            ),
            data=b'\x01\x23\x45\x67\x89\xAB\xCD\xEF',
            iv_counter_nonce=b'\x01'
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_unique_identifier(self):
        """
        Test that the inequality operator returns True when comparing two
        Decrypt request payloads with different unique identifiers.
        """
        a = payloads.DecryptRequestPayload(
            unique_identifier='a'
        )
        b = payloads.DecryptRequestPayload(
            unique_identifier='b'
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_cryptographic_parameters(self):
        """
        Test that the inequality operator returns True when comparing two
        Decrypt request payloads with different cryptographic parameters.
        """
        a = payloads.DecryptRequestPayload(
            cryptographic_parameters=attributes.CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.CBC
            )
        )
        b = payloads.DecryptRequestPayload(
            cryptographic_parameters=attributes.CryptographicParameters(
                hashing_algorithm=enums.HashingAlgorithm.MD5
            )
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_data(self):
        """
        Test that the inequality operator returns True when comparing two
        Decrypt request payloads with different data.
        """
        a = payloads.DecryptRequestPayload(data=b'\x11')
        b = payloads.DecryptRequestPayload(data=b'\xFF')

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_iv_counter_nonce(self):
        """
        Test that the inequality operator returns True when comparing two
        Decrypt request payloads with different IV/counter/nonce values.
        """
        a = payloads.DecryptRequestPayload(iv_counter_nonce=b'\x22')
        b = payloads.DecryptRequestPayload(iv_counter_nonce=b'\xAA')

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        Decrypt request payloads with different types.
        """
        a = payloads.DecryptRequestPayload()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test that repr can be applied to an Decrypt request payload.
        """
        payload = payloads.DecryptRequestPayload(
            unique_identifier='b4faee10-aa2a-4446-8ad4-0881f3422959',
            cryptographic_parameters=attributes.CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.CBC,
                padding_method=enums.PaddingMethod.PKCS5,
                hashing_algorithm=enums.HashingAlgorithm.SHA_1,
                key_role_type=enums.KeyRoleType.KEK,
                digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
                SHA256_WITH_RSA_ENCRYPTION,
                cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
                random_iv=True,
                iv_length=96,
                tag_length=128,
                fixed_field_length=32,
                invocation_field_length=64,
                counter_length=0,
                initial_counter_value=1
            ),
            data=b'\x01\x23\x45\x67\x89\xAB\xCD\xEF',
            iv_counter_nonce=b'\x01'
        )
        expected = (
            "DecryptRequestPayload("
            "unique_identifier='b4faee10-aa2a-4446-8ad4-0881f3422959', "
            "cryptographic_parameters=CryptographicParameters("
            "block_cipher_mode=BlockCipherMode.CBC, "
            "padding_method=PaddingMethod.PKCS5, "
            "hashing_algorithm=HashingAlgorithm.SHA_1, "
            "key_role_type=KeyRoleType.KEK, "
            "digital_signature_algorithm="
            "DigitalSignatureAlgorithm.SHA256_WITH_RSA_ENCRYPTION, "
            "cryptographic_algorithm=CryptographicAlgorithm.AES, "
            "random_iv=True, "
            "iv_length=96, "
            "tag_length=128, "
            "fixed_field_length=32, "
            "invocation_field_length=64, "
            "counter_length=0, "
            "initial_counter_value=1), "
            "data=" + str(b'\x01\x23\x45\x67\x89\xAB\xCD\xEF') + ", "
            "iv_counter_nonce=" + str(b'\x01') + ")"
        )
        observed = repr(payload)

        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to an Decrypt request payload
        """
        cryptographic_parameters = attributes.CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.CBC,
            padding_method=enums.PaddingMethod.PKCS5,
            hashing_algorithm=enums.HashingAlgorithm.SHA_1,
            key_role_type=enums.KeyRoleType.KEK,
            digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
            SHA256_WITH_RSA_ENCRYPTION,
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
            random_iv=True,
            iv_length=96,
            tag_length=128,
            fixed_field_length=32,
            invocation_field_length=64,
            counter_length=0,
            initial_counter_value=1
        )
        payload = payloads.DecryptRequestPayload(
            unique_identifier='b4faee10-aa2a-4446-8ad4-0881f3422959',
            cryptographic_parameters=cryptographic_parameters,
            data=b'\x01\x23\x45\x67\x89\xAB\xCD\xEF',
            iv_counter_nonce=b'\x01'
        )

        expected = str({
            'unique_identifier': 'b4faee10-aa2a-4446-8ad4-0881f3422959',
            'cryptographic_parameters': cryptographic_parameters,
            'data': b'\x01\x23\x45\x67\x89\xAB\xCD\xEF',
            'iv_counter_nonce': b'\x01'
        })
        observed = str(payload)

        self.assertEqual(expected, observed)


class TestDecryptResponsePayload(testtools.TestCase):
    """
    Test suite for the Decrypt response payload.
    """

    def setUp(self):
        super(TestDecryptResponsePayload, self).setUp()

        # Encoding obtained in part from the KMIP 1.1 testing document,
        # Section 11.1. The rest of the encoding for KMIP 1.2+ features was
        # built by hand; later KMIP testing documents do not include the
        # encoding, so a manual construction is necessary.
        #
        # This encoding matches the following set of values:
        # Unique Identifier - b4faee10-aa2a-4446-8ad4-0881f3422959
        # Data - 0x0123456789ABCDEF
        # IV/Counter/Nonce - 0x01

        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x40'
            b'\x42\x00\x94\x07\x00\x00\x00\x24\x62\x34\x66\x61\x65\x65\x31\x30'
            b'\x2D\x61\x61\x32\x61\x2D\x34\x34\x34\x36\x2D\x38\x61\x64\x34\x2D'
            b'\x30\x38\x38\x31\x66\x33\x34\x32\x32\x39\x35\x39\x00\x00\x00\x00'
            b'\x42\x00\xC2\x08\x00\x00\x00\x08\x01\x23\x45\x67\x89\xAB\xCD\xEF'
        )

        # Adapted from the minimum encoding above. This encoding matches the
        # following set of values:
        # Unique Identifier - b4faee10-aa2a-4446-8ad4-0881f3422959

        self.incomplete_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x30'
            b'\x42\x00\x94\x07\x00\x00\x00\x24\x62\x34\x66\x61\x65\x65\x31\x30'
            b'\x2D\x61\x61\x32\x61\x2D\x34\x34\x34\x36\x2D\x38\x61\x64\x34\x2D'
            b'\x30\x38\x38\x31\x66\x33\x34\x32\x32\x39\x35\x39\x00\x00\x00\x00'
        )

        self.empty_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestDecryptResponsePayload, self).tearDown()

    def test_init(self):
        """
        Test that an Decrypt response payload can be constructed with no
        arguments.
        """
        payload = payloads.DecryptResponsePayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.data)

    def test_init_with_args(self):
        """
        Test that a Decrypt response payload can be constructed with valid
        values
        """
        payload = payloads.DecryptResponsePayload(
            unique_identifier='00000000-1111-2222-3333-444444444444',
            data=b'\x01\x02\x03'
        )

        self.assertEqual(
            '00000000-1111-2222-3333-444444444444',
            payload.unique_identifier
        )
        self.assertEqual(b'\x01\x02\x03', payload.data)

    def test_invalid_unique_identifier(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the unique identifier of a Decrypt response payload.
        """
        payload = payloads.DecryptResponsePayload()
        args = (payload, 'unique_identifier', 0)
        self.assertRaisesRegexp(
            TypeError,
            "unique identifier must be a string",
            setattr,
            *args
        )

    def test_invalid_data(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the data of a Decrypt response payload.
        """
        payload = payloads.DecryptResponsePayload()
        args = (payload, 'data', 0)
        self.assertRaisesRegexp(
            TypeError,
            "data must be bytes",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a Decrypt response payload can be read from a data stream.
        """
        payload = payloads.DecryptResponsePayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.data)

        payload.read(self.full_encoding)

        self.assertEqual(
            'b4faee10-aa2a-4446-8ad4-0881f3422959',
            payload.unique_identifier
        )
        self.assertEqual(b'\x01\x23\x45\x67\x89\xAB\xCD\xEF', payload.data)

    def test_read_invalid(self):
        """
        Test that a ValueError gets raised when required Decrypt response
        payload attributes are missing from the payload encoding.
        """
        payload = payloads.DecryptResponsePayload()
        args = (self.empty_encoding, )
        self.assertRaisesRegexp(
            ValueError,
            "invalid payload missing the unique identifier attribute",
            payload.read,
            *args
        )

        payload = payloads.DecryptResponsePayload()
        args = (self.incomplete_encoding, )
        self.assertRaisesRegexp(
            ValueError,
            "invalid payload missing the data attribute",
            payload.read,
            *args
        )

    def test_write(self):
        """
        Test that a Decrypt response payload can be written to a data stream.
        """
        payload = payloads.DecryptResponsePayload(
            unique_identifier='b4faee10-aa2a-4446-8ad4-0881f3422959',
            data=b'\x01\x23\x45\x67\x89\xAB\xCD\xEF'
        )
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_invalid(self):
        """
        Test that a ValueError gets raised when required Decrypt response
        payload attributes are missing when encoding the payload.
        """
        payload = payloads.DecryptResponsePayload()
        self.assertIsNone(payload.unique_identifier)
        stream = utils.BytearrayStream()
        args = (stream, )
        self.assertRaisesRegexp(
            ValueError,
            "invalid payload missing the unique identifier attribute",
            payload.write,
            *args
        )

        payload = payloads.DecryptResponsePayload(
            unique_identifier='b4faee10-aa2a-4446-8ad4-0881f3422959'
        )
        stream = utils.BytearrayStream()
        args = (stream, )
        self.assertRaisesRegexp(
            ValueError,
            "invalid payload missing the data attribute",
            payload.write,
            *args
        )

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        Decrypt response payloads with the same data.
        """
        a = payloads.DecryptResponsePayload()
        b = payloads.DecryptResponsePayload()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = payloads.DecryptResponsePayload(
            unique_identifier='b4faee10-aa2a-4446-8ad4-0881f3422959',
            data=b'\x01\x23\x45\x67\x89\xAB\xCD\xEF'
        )
        b = payloads.DecryptResponsePayload(
            unique_identifier='b4faee10-aa2a-4446-8ad4-0881f3422959',
            data=b'\x01\x23\x45\x67\x89\xAB\xCD\xEF'
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_unique_identifier(self):
        """
        Test that the equality operator returns False when comparing two
        Decrypt response payloads with different unique identifiers.
        """
        a = payloads.DecryptResponsePayload(
            unique_identifier='a'
        )
        b = payloads.DecryptResponsePayload(
            unique_identifier='b'
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_data(self):
        """
        Test that the equality operator returns False when comparing two
        Decrypt response payloads with different data.
        """
        a = payloads.DecryptResponsePayload(data=b'\x11')
        b = payloads.DecryptResponsePayload(data=b'\xFF')

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        Decrypt response payloads with different types.
        """
        a = payloads.DecryptResponsePayload()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        Decrypt response payloads with the same data.
        """
        a = payloads.DecryptResponsePayload()
        b = payloads.DecryptResponsePayload()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = payloads.DecryptResponsePayload(
            unique_identifier='b4faee10-aa2a-4446-8ad4-0881f3422959',
            data=b'\x01\x23\x45\x67\x89\xAB\xCD\xEF'
        )
        b = payloads.DecryptResponsePayload(
            unique_identifier='b4faee10-aa2a-4446-8ad4-0881f3422959',
            data=b'\x01\x23\x45\x67\x89\xAB\xCD\xEF'
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_unique_identifier(self):
        """
        Test that the inequality operator returns True when comparing two
        Decrypt response payloads with different unique identifiers.
        """
        a = payloads.DecryptResponsePayload(
            unique_identifier='a'
        )
        b = payloads.DecryptResponsePayload(
            unique_identifier='b'
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_data(self):
        """
        Test that the inequality operator returns True when comparing two
        Decrypt response payloads with different data.
        """
        a = payloads.DecryptResponsePayload(data=b'\x11')
        b = payloads.DecryptResponsePayload(data=b'\xFF')

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        Decrypt response payloads with different types.
        """
        a = payloads.DecryptResponsePayload()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test that repr can be applied to a Decrypt response payload.
        """
        payload = payloads.DecryptResponsePayload(
            unique_identifier='b4faee10-aa2a-4446-8ad4-0881f3422959',
            data=b'\x01\x23\x45\x67\x89\xAB\xCD\xEF'
        )
        expected = (
            "DecryptResponsePayload("
            "unique_identifier='b4faee10-aa2a-4446-8ad4-0881f3422959', "
            "data=" + str(b'\x01\x23\x45\x67\x89\xAB\xCD\xEF') + ")"
        )
        observed = repr(payload)

        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a Decrypt response payload
        """
        payload = payloads.DecryptResponsePayload(
            unique_identifier='b4faee10-aa2a-4446-8ad4-0881f3422959',
            data=b'\x01\x23\x45\x67\x89\xAB\xCD\xEF'
        )

        expected = str({
            'unique_identifier': 'b4faee10-aa2a-4446-8ad4-0881f3422959',
            'data': b'\x01\x23\x45\x67\x89\xAB\xCD\xEF'
        })
        observed = str(payload)

        self.assertEqual(expected, observed)
