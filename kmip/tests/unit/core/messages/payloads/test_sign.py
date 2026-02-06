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

from kmip.core.messages.payloads import sign

class TestSignRequestPayload(testtools.TestCase):
    """
    Test suite for the Sign request payload.
    """

    def setUp(self):
        super(TestSignRequestPayload, self).setUp()

        # Encoding obtained in part from KMIP 1.4 testing document,
        # partially cobbled together by hand from other test cases
        # in this code base.
        #
        # This encoding matches the following set of values:
        # Unique Identifier - b4faee10-aa2a-4446-8ad4-0881f3422959
        # Cryptographic Parameters
        #     Cryptographic Algorithm - ECDSA
        # Data - 01020304050607080910111213141516

        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x60'
            b'\x42\x00\x94\x07\x00\x00\x00\x24\x62\x34\x66\x61\x65\x65\x31\x30'
            b'\x2D\x61\x61\x32\x61\x2D\x34\x34\x34\x36\x2D\x38\x61\x64\x34\x2D'
            b'\x30\x38\x38\x31\x66\x33\x34\x32\x32\x39\x35\x39\x00\x00\x00\x00'
            b'\x42\x00\x2B\x01\x00\x00\x00\x10'
            b'\x42\x00\x28\x05\x00\x00\x00\x04\x00\x00\x00\x06\x00\x00\x00\x00'
            b'\x42\x00\xC2\x08\x00\x00\x00\x10\x01\x02\x03\x04\x05\x06\x07\x08'
            b'\x09\x10\x11\x12\x13\x14\x15\x16'
        )

        self.minimum_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x18'
            b'\x42\x00\xC2\x08\x00\x00\x00\x10\x01\x02\x03\x04\x05\x06\x07\x08'
            b'\x09\x10\x11\x12\x13\x14\x15\x16'
        )

        self.empty_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestSignRequestPayload, self).tearDown()

    def test_init(self):
        """
        Test that a Sign request payload can be constructed with no arguments.
        """
        payload = sign.SignRequestPayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.cryptographic_parameters)
        self.assertEqual(None, payload.data)

    def test_init_with_args(self):
        """
        Test that a Sign request payload can be constructed with valid values.
        """
        payload = sign.SignRequestPayload(
            unique_identifier='00000000-1111-2222-3333-444444444444',
            cryptographic_parameters=attributes.CryptographicParameters(),
            data=b'\x01\x02\x03'
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

    def test_invalid_unique_identifier(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the unique identifier of a Sign request payload.
        """
        payload = sign.SignRequestPayload()
        args = (payload, 'unique_identifier', 0)
        self.assertRaisesRegex(
            TypeError,
            "unique identifier must be a string",
            setattr,
            *args
        )

    def test_invalid_cryptographic_parameters(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the cryptographic parameters of a Sign request payload.
        """
        payload = sign.SignRequestPayload()
        args = (payload, 'cryptographic_parameters', b'\x01\x02\x03')
        self.assertRaisesRegex(
            TypeError,
            "cryptographic parameters must be a CryptographicParameters "
            "struct",
            setattr,
            *args
        )

    def test_invalid_data(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the data of a Sign request payload.
        """
        payload = sign.SignRequestPayload()
        args = (payload, 'data', 0)
        self.assertRaisesRegex(
            TypeError,
            "data must be bytes",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a Sign request payload can be read from a data stream.
        """
        payload = sign.SignRequestPayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.cryptographic_parameters)
        self.assertEqual(None, payload.data)

        payload.read(self.full_encoding)

        self.assertEqual(
            'b4faee10-aa2a-4446-8ad4-0881f3422959',
            payload.unique_identifier
        )
        self.assertIsNotNone(payload.cryptographic_parameters)
        self.assertEqual(
            enums.CryptographicAlgorithm.ECDSA,
            payload.cryptographic_parameters.cryptographic_algorithm
        )
        self.assertEqual(
            b'\x01\x02\x03\x04\x05\x06\x07\x08'
            b'\x09\x10\x11\x12\x13\x14\x15\x16',
            payload.data
        )

    def test_read_partial(self):
        """
        Test that a Sign request payload can be read from a partial data
        stream containing the minimum required attributes.
        """
        payload = sign.SignRequestPayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.cryptographic_parameters)
        self.assertEqual(None, payload.data)

        payload.read(self.minimum_encoding)

        self.assertEqual(
            b'\x01\x02\x03\x04\x05\x06\x07\x08'
            b'\x09\x10\x11\x12\x13\x14\x15\x16',
            payload.data
        )

    def test_read_invalid(self):
        """
        Test that a ValueError gets raised when a required Sign request
        payload attribute is missing from the payload encoding.
        """
        payload = sign.SignRequestPayload()
        args = (self.empty_encoding, )
        self.assertRaisesRegex(
            ValueError,
            "invalid payload missing the data attribute",
            payload.read,
            *args
        )

    def test_write(self):
        """
        Test that a Sign request payload can be written to a data stream.
        """
        payload = sign.SignRequestPayload(
            unique_identifier='b4faee10-aa2a-4446-8ad4-0881f3422959',
            cryptographic_parameters=attributes.CryptographicParameters(
                cryptographic_algorithm=enums.CryptographicAlgorithm.ECDSA
            ),
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08'
                 b'\x09\x10\x11\x12\x13\x14\x15\x16'
        )
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_partial(self):
        """
        Test that a partially defined Sign request payload can be written
        to a data stream.
        """
        payload = sign.SignRequestPayload(
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08'
                 b'\x09\x10\x11\x12\x13\x14\x15\x16'
        )
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.minimum_encoding), len(stream))
        self.assertEqual(str(self.minimum_encoding), str(stream))

    def test_write_invalid(self):
        """
        Test that a ValueError gets raised when a required Sign request
        payload attribute is missing when encoding the payload.
        """
        payload = sign.SignRequestPayload()
        stream = utils.BytearrayStream()
        args = (stream, )
        self.assertRaisesRegex(
            ValueError,
            "invalid payload missing the data attribute",
            payload.write,
            *args
        )

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        Sign request payloads with the same data.
        """
        a = sign.SignRequestPayload()
        b = sign.SignRequestPayload()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = sign.SignRequestPayload(
            unique_identifier='b4faee10-aa2a-4446-8ad4-0881f3422959',
            cryptographic_parameters=attributes.CryptographicParameters(
                cryptographic_algorithm=enums.CryptographicAlgorithm.ECDSA
            ),
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08'
                 b'\x09\x10\x11\x12\x13\x14\x15\x16'
        )
        b = sign.SignRequestPayload(
            unique_identifier='b4faee10-aa2a-4446-8ad4-0881f3422959',
            cryptographic_parameters=attributes.CryptographicParameters(
                cryptographic_algorithm=enums.CryptographicAlgorithm.ECDSA
            ),
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08'
                 b'\x09\x10\x11\x12\x13\x14\x15\x16'
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_unique_identifier(self):
        """
        Test that the equality operator returns False when comparing two
        Sign request payloads with different unique identifiers.
        """
        a = sign.SignRequestPayload(
            unique_identifier='a'
        )
        b = sign.SignRequestPayload(
            unique_identifier='b'
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_cryptographic_parameters(self):
        """
        Test that the equality operator returns False when comparing two
        Sign request payloads with cryptographic parameters.
        """
        a = sign.SignRequestPayload(
            cryptographic_parameters=attributes.CryptographicParameters(
                hashing_algorithm=enums.HashingAlgorithm.MD5
            )
        )
        b = sign.SignRequestPayload(
            cryptographic_parameters=attributes.CryptographicParameters(
                cryptographic_algorithm=enums.CryptographicAlgorithm.ECDSA
            )
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_data(self):
        """
        Test that the equality operator returns False when comparing two
        Sign request payloads with different data.
        """
        a = sign.SignRequestPayload(data=b'\x01')
        b = sign.SignRequestPayload(data=b'\xFF')

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        Sign request payloads with different types.
        """
        a = sign.SignRequestPayload()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        Sign request payloads with the same data.
        """
        a = sign.SignRequestPayload()
        b = sign.SignRequestPayload()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = sign.SignRequestPayload(
            unique_identifier='b4faee10-aa2a-4446-8ad4-0881f3422959',
            cryptographic_parameters=attributes.CryptographicParameters(
                cryptographic_algorithm=enums.CryptographicAlgorithm.ECDSA
            ),
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08'
                 b'\x09\x10\x11\x12\x13\x14\x15\x16'
        )
        b = sign.SignRequestPayload(
            unique_identifier='b4faee10-aa2a-4446-8ad4-0881f3422959',
            cryptographic_parameters=attributes.CryptographicParameters(
                cryptographic_algorithm=enums.CryptographicAlgorithm.ECDSA
            ),
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08'
                 b'\x09\x10\x11\x12\x13\x14\x15\x16'
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_unique_identifier(self):
        """
        Test that the inequality operator returns True when comparing two
        Sign request payloads with different unique identifiers.
        """
        a = sign.SignRequestPayload(
            unique_identifier='a'
        )
        b = sign.SignRequestPayload(
            unique_identifier='b'
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_cryptographic_parameters(self):
        """
        Test that the equality operator returns False when comparing two
        Sign request payloads with cryptographic parameters.
        """
        a = sign.SignRequestPayload(
            cryptographic_parameters=attributes.CryptographicParameters(
                hashing_algorithm=enums.HashingAlgorithm.MD5
            )
        )
        b = sign.SignRequestPayload(
            cryptographic_parameters=attributes.CryptographicParameters(
                cryptographic_algorithm=enums.CryptographicAlgorithm.ECDSA
            )
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_data(self):
        """
        Test that the inequality operator returns True when comparing two
        Sign request payloads with different data.
        """
        a = sign.SignRequestPayload(data=b'\x01')
        b = sign.SignRequestPayload(data=b'\xFF')

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        Sign request payloads with different types.
        """
        a = sign.SignRequestPayload()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test that repr can be applied to a Sign request payload.
        """
        payload = sign.SignRequestPayload(
            unique_identifier='b4faee10-aa2a-4446-8ad4-0881f3422959',
            cryptographic_parameters=attributes.CryptographicParameters(
                cryptographic_algorithm=enums.CryptographicAlgorithm.ECDSA
            ),
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08'
        )
        expected = (
            "SignRequestPayload("
            "unique_identifier='b4faee10-aa2a-4446-8ad4-0881f3422959', "
            "cryptographic_parameters=CryptographicParameters("
            "block_cipher_mode=None, padding_method=None, "
            "hashing_algorithm=None, key_role_type=None, "
            "digital_signature_algorithm=None, "
            "cryptographic_algorithm=CryptographicAlgorithm.ECDSA, "
            "random_iv=None, iv_length=None, tag_length=None, "
            "fixed_field_length=None, invocation_field_length=None, "
            "counter_length=None, initial_counter_value=None), "
            "data=" + str(b'\x01\x02\x03\x04\x05\x06\x07\x08') + ")"
        )
        observed = repr(payload)

        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a Sign request payload.
        """
        crypto_params = attributes.CryptographicParameters(
             cryptographic_algorithm=enums.CryptographicAlgorithm.ECDSA
        )
        payload = sign.SignRequestPayload(
            unique_identifier='b4faee10-aa2a-4446-8ad4-0881f3422959',
            cryptographic_parameters=crypto_params,
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08',
        )

        expected = str({
            'unique_identifier': 'b4faee10-aa2a-4446-8ad4-0881f3422959',
            'cryptographic_parameters': crypto_params,
            'data': b'\x01\x02\x03\x04\x05\x06\x07\x08'
        })
        observed = str(payload)

        self.assertEqual(expected, observed)

    def test_read_valid(self):
        """
        Test that a Sign response payload can be read from a valid byte
        stream.
        """
        self.test_read()

    def test_read_missing_required_field(self):
        """
        Test that an exception is raised when reading a payload missing a
        required field.
        """
        self.test_read_invalid()

    def test_write_valid(self):
        """
        Test that a Sign response payload can be written to a byte stream.
        """
        self.test_write()

    def test_read_write_roundtrip(self):
        """
        Test that a Sign response payload can be read and written without
        changing the encoded bytes.
        """
        payload = sign.SignResponsePayload()
        payload.read(utils.BytearrayStream(self.full_encoding.buffer))

        buffer = utils.BytearrayStream()
        payload.write(buffer)

        self.assertEqual(str(self.full_encoding), str(buffer))

    def test_validate_invalid(self):
        """
        Test that an exception is raised when a field has an invalid type.
        """
        self.test_invalid_unique_identifier()

    def test_eq(self):
        """
        Test that two Sign response payloads with the same data are equal.
        """
        self.test_equal_on_equal()

    def test_ne(self):
        """
        Test that two Sign response payloads with different data are not
        equal.
        """
        self.test_not_equal_on_not_equal_unique_identifier()

    def test_read_valid(self):
        """
        Test that a Sign request payload can be read from a valid byte stream.
        """
        self.test_read()

    def test_read_missing_required_field(self):
        """
        Test that an exception is raised when reading a payload missing a
        required field.
        """
        self.test_read_invalid()

    def test_write_valid(self):
        """
        Test that a Sign request payload can be written to a byte stream.
        """
        self.test_write()

    def test_read_write_roundtrip(self):
        """
        Test that a Sign request payload can be read and written without
        changing the encoded bytes.
        """
        payload = sign.SignRequestPayload()
        payload.read(utils.BytearrayStream(self.full_encoding.buffer))

        buffer = utils.BytearrayStream()
        payload.write(buffer)

        self.assertEqual(str(self.full_encoding), str(buffer))

    def test_validate_invalid(self):
        """
        Test that an exception is raised when a field has an invalid type.
        """
        self.test_invalid_unique_identifier()

    def test_eq(self):
        """
        Test that two Sign request payloads with the same data are equal.
        """
        self.test_equal_on_equal()

    def test_ne(self):
        """
        Test that two Sign request payloads with different data are not equal.
        """
        self.test_not_equal_on_not_equal_unique_identifier()

class TestSignResponsePayload(testtools.TestCase):
    """
    Test suite for the Sign response payload.
    """

    def setUp(self):
        super(TestSignResponsePayload, self).setUp()
        # Encoding obtained in part from KMIP 1.4 testing document,
        # partially cobbled together by hand from other test cases
        # in this code base.
        #
        # This encoding matches the following set of values:
        # Unique Identifier - b4faee10-aa2a-4446-8ad4-0881f3422959
        # Signature Data - 01020304050607080910111213141516

        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x48'
            b'\x42\x00\x94\x07\x00\x00\x00\x24\x62\x34\x66\x61\x65\x65\x31\x30'
            b'\x2D\x61\x61\x32\x61\x2D\x34\x34\x34\x36\x2D\x38\x61\x64\x34\x2D'
            b'\x30\x38\x38\x31\x66\x33\x34\x32\x32\x39\x35\x39\x00\x00\x00\x00'
            b'\x42\x00\xC3\x08\x00\x00\x00\x10\x01\x02\x03\x04\x05\x06\x07\x08'
            b'\x09\x10\x11\x12\x13\x14\x15\x16'
        )
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
        super(TestSignResponsePayload, self).tearDown()

    def test_init(self):
        """
        Test that a Sign response payload can be constructed with no
        arguments.
        """
        payload = sign.SignResponsePayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.signature_data)

    def test_init_with_args(self):
        """
        Test that a Sign response payload can be constructed with valid
        values.
        """
        payload = sign.SignResponsePayload(
            unique_identifier='00000000-1111-2222-3333-444444444444',
            signature_data=b'\x01\x02\x03'
        )

        self.assertEqual(
            '00000000-1111-2222-3333-444444444444',
            payload.unique_identifier
        )
        self.assertEqual(b'\x01\x02\x03', payload.signature_data)

    def test_invalid_unique_identifier(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the unique identifier of a Sign response payload.
        """
        payload = sign.SignResponsePayload()
        args = (payload, 'unique_identifier', 0)
        self.assertRaisesRegex(
            TypeError,
            "unique identifier must be a string",
            setattr,
            *args
        )

    def test_invalid_signature_data(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the signature data of a Sign response payload.
        """
        payload = sign.SignResponsePayload()
        args = (payload, 'signature_data', 0)
        self.assertRaisesRegex(
            TypeError,
            "signature data must be bytes",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a Sign response payload can be read from a data stream.
        """
        payload = sign.SignResponsePayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.signature_data)

        payload.read(self.full_encoding)

        self.assertEqual(
            'b4faee10-aa2a-4446-8ad4-0881f3422959',
            payload.unique_identifier
        )
        self.assertEqual(
            b'\x01\x02\x03\x04\x05\x06\x07\x08'
            b'\x09\x10\x11\x12\x13\x14\x15\x16',
            payload.signature_data
        )

    def test_read_invalid(self):
        """
        Test that a ValueError gets raised when required Sign response
        payload attributes are missing from the payload encoding.
        """
        payload = sign.SignResponsePayload()
        args = (self.empty_encoding, )
        self.assertRaisesRegex(
            ValueError,
            "invalid payload missing the unique identifier attribute",
            payload.read,
            *args
        )

        payload = sign.SignResponsePayload()
        args = (self.incomplete_encoding, )
        self.assertRaisesRegex(
            ValueError,
            "invalid payload missing the signature data attribute",
            payload.read,
            *args
        )

    def test_write(self):
        """
        Test that a Sign response payload can be written to a data stream.
        """
        payload = sign.SignResponsePayload(
            unique_identifier='b4faee10-aa2a-4446-8ad4-0881f3422959',
            signature_data=b'\x01\x02\x03\x04\x05\x06\x07\x08'
                           b'\x09\x10\x11\x12\x13\x14\x15\x16'
        )
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_invalid(self):
        """
        Test that a ValueError gets raised when a required Sign response
        payload attribute is missing when encoding the payload.
        """
        payload = sign.SignResponsePayload()
        stream = utils.BytearrayStream()
        args = (stream, )
        self.assertRaisesRegex(
            ValueError,
            "invalid payload missing the unique identifier attribute",
            payload.write,
            *args
        )

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        equal sign response payloads
        """
        encoding = utils.BytearrayStream(self.full_encoding.buffer)
        a = sign.SignResponsePayload()
        b = sign.SignResponsePayload()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a.read(encoding)
        b.read(self.full_encoding)

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_unique_identifier(self):
        """
        Test that the equality operator returns False when comparing two
        sign response payloads with different unique_identifier.
        """
        a = sign.SignResponsePayload(unique_identifier='a',
                                     signature_data=b'\x01')

        b = sign.SignResponsePayload(unique_identifier='b',
                                     signature_data=b'\x01')

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_signature_data(self):
        """
        Test that the equality operator returns False when comparing two
        sign response payloads with different signature_data.
        """
        a = sign.SignResponsePayload(unique_identifier='a',
                                     signature_data=b'\x01')
        b = sign.SignResponsePayload(unique_identifier='a',
                                     signature_data=b'\x02')

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing a sign
        response payload to another type.
        """
        a = sign.SignResponsePayload()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns false when comparing two
        equal sign response payloads.
        """
        encoding = utils.BytearrayStream(self.full_encoding.buffer)
        a = sign.SignResponsePayload()
        b = sign.SignResponsePayload()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a.read(encoding)
        b.read(self.full_encoding)

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_unique_identifier(self):
        """
        Test that the inequality operator returns True when comparing two
        sign response payloads with different unique_identifier.
        """
        a = sign.SignResponsePayload(unique_identifier='a',
                                     signature_data=b'\x01')

        b = sign.SignResponsePayload(unique_identifier='b',
                                     signature_data=b'\x01')

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_signature_data(self):
        """
        Test that the inequality operator returns True when comparing two
        sign response payloads with different signature_data.
        """
        a = sign.SignResponsePayload(unique_identifier='a',
                                     signature_data=b'\x01')
        b = sign.SignResponsePayload(unique_identifier='a',
                                     signature_data=b'\x02')

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing a
        sign response payload to a different type.
        """
        a = sign.SignResponsePayload()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test that repr can applied to a sign response payload.
        """
        payload = sign.SignResponsePayload(
            unique_identifier='00000000-1111-2222-3333-444444444444',
            signature_data=b'\x01\x02\x03'
        )

        expected = (
            "SignResponsePayload("
            "unique_identifier='00000000-1111-2222-3333-444444444444', "
            "signature_data="+str(b'\x01\x02\x03') + ")"
        )

        observed = repr(payload)
        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a sign response payload.
        """
        payload = sign.SignResponsePayload(
            unique_identifier='00000000-1111-2222-3333-444444444444',
            signature_data=b'\x01\x02\x03'
        )

        expected = str({
            'unique_identifier': '00000000-1111-2222-3333-444444444444',
            'signature_data': b'\x01\x02\x03'
        })

        observed = str(payload)
        self.assertEqual(expected, observed)

    def test_read_valid(self):
        """
        Test that a Sign response payload can be read from a valid byte
        stream.
        """
        self.test_read()

    def test_read_missing_required_field(self):
        """
        Test that an exception is raised when reading a payload missing a
        required field.
        """
        self.test_read_invalid()

    def test_write_valid(self):
        """
        Test that a Sign response payload can be written to a byte stream.
        """
        self.test_write()

    def test_read_write_roundtrip(self):
        """
        Test that a Sign response payload can be read and written without
        changing the encoded bytes.
        """
        payload = sign.SignResponsePayload()
        payload.read(utils.BytearrayStream(self.full_encoding.buffer))

        buffer = utils.BytearrayStream()
        payload.write(buffer)

        self.assertEqual(str(self.full_encoding), str(buffer))

    def test_validate_invalid(self):
        """
        Test that an exception is raised when a field has an invalid type.
        """
        self.test_invalid_unique_identifier()

    def test_eq(self):
        """
        Test that two Sign response payloads with the same data are equal.
        """
        self.test_equal_on_equal()

    def test_ne(self):
        """
        Test that two Sign response payloads with different data are not
        equal.
        """
        self.test_not_equal_on_not_equal_unique_identifier()
