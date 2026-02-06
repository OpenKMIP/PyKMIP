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

from kmip.core import utils
from kmip.core.messages import payloads

class TestCheckRequestPayload(testtools.TestCase):
    """
    Test suite for the Check request payload.
    """

    def setUp(self):
        super(TestCheckRequestPayload, self).setUp()

        # Encoding obtained in part from the KMIP 1.1 testing document,
        # Section 5.1. The rest of the encoding was built by hand.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Unique Identifier - 2c23217e-f53c-4bdf-ad0a-58a31fd3d4b6
        #     Usage Limits Count - 500
        #     Cryptographic Usage Mask - Encrypt | Decrypt (4 | 8 -> 12 or C)
        #     Lease Time - 0

        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x60'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x32\x63\x32\x33\x32\x31\x37\x65\x2D\x66\x35\x33\x63\x2D\x34\x62'
            b'\x64\x66\x2D\x61\x64\x30\x61\x2D\x35\x38\x61\x33\x31\x66\x64\x33'
            b'\x64\x34\x62\x36\x00\x00\x00\x00'
            b'\x42\x00\x96\x03\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x01\xF4'
            b'\x42\x00\x2C\x02\x00\x00\x00\x04\x00\x00\x00\x0C\x00\x00\x00\x00'
            b'\x42\x00\x49\x0A\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00'
        )

        # This encoding matches the following set of values:
        # Request Payload
        #     Unique Identifier - 2c23217e-f53c-4bdf-ad0a-58a31fd3d4b6
        #     Usage Limits Count - 500
        self.partial_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x40'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x32\x63\x32\x33\x32\x31\x37\x65\x2D\x66\x35\x33\x63\x2D\x34\x62'
            b'\x64\x66\x2D\x61\x64\x30\x61\x2D\x35\x38\x61\x33\x31\x66\x64\x33'
            b'\x64\x34\x62\x36\x00\x00\x00\x00'
            b'\x42\x00\x96\x03\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x01\xF4'
        )

        self.empty_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestCheckRequestPayload, self).tearDown()

    def test_init(self):
        """
        Test that a Check request payload can be constructed with no arguments.
        """
        payload = payloads.CheckRequestPayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.usage_limits_count)
        self.assertEqual(None, payload.cryptographic_usage_mask)
        self.assertEqual(None, payload.lease_time)

    def test_init_with_args(self):
        """
        Test that a Check request payload can be constructed with valid values.
        """
        payload = payloads.CheckRequestPayload(
            unique_identifier='00000000-1111-2222-3333-444444444444',
            usage_limits_count=10,
            cryptographic_usage_mask=12,
            lease_time=1000000000
        )

        self.assertEqual(
            '00000000-1111-2222-3333-444444444444',
            payload.unique_identifier
        )
        self.assertEqual(10, payload.usage_limits_count)
        self.assertEqual(12, payload.cryptographic_usage_mask)
        self.assertEqual(1000000000, payload.lease_time)

    def test_invalid_unique_identifier(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the unique identifier of a Check request payload.
        """
        kwargs = {'unique_identifier': 0}
        self.assertRaisesRegex(
            TypeError,
            "Unique identifier must be a string.",
            payloads.CheckRequestPayload,
            **kwargs
        )

        payload = payloads.CheckRequestPayload()
        args = (payload, 'unique_identifier', 0)
        self.assertRaisesRegex(
            TypeError,
            "Unique identifier must be a string.",
            setattr,
            *args
        )

    def test_invalid_usage_limits_count(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the usage limits count of a Check request payload.
        """
        kwargs = {'usage_limits_count': 'invalid'}
        self.assertRaisesRegex(
            TypeError,
            "Usage limits count must be an integer.",
            payloads.CheckRequestPayload,
            **kwargs
        )

        payload = payloads.CheckRequestPayload()
        args = (payload, 'usage_limits_count', 'invalid')
        self.assertRaisesRegex(
            TypeError,
            "Usage limits count must be an integer.",
            setattr,
            *args
        )

    def test_invalid_cryptographic_usage_mask(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the cryptographic usage mask of a Check request payload.
        """
        kwargs = {'cryptographic_usage_mask': 'invalid'}
        self.assertRaisesRegex(
            TypeError,
            "Cryptographic usage mask must be an integer.",
            payloads.CheckRequestPayload,
            **kwargs
        )

        payload = payloads.CheckRequestPayload()
        args = (payload, 'cryptographic_usage_mask', 'invalid')
        self.assertRaisesRegex(
            TypeError,
            "Cryptographic usage mask must be an integer.",
            setattr,
            *args
        )

    def test_invalid_lease_time(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the lease time of a Check request payload.
        """
        kwargs = {'lease_time': 'invalid'}
        self.assertRaisesRegex(
            TypeError,
            "Lease time must be an integer.",
            payloads.CheckRequestPayload,
            **kwargs
        )

        payload = payloads.CheckRequestPayload()
        args = (payload, 'lease_time', 'invalid')
        self.assertRaisesRegex(
            TypeError,
            "Lease time must be an integer.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a Check request payload can be read from a data stream.
        """
        payload = payloads.CheckRequestPayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.usage_limits_count)
        self.assertEqual(None, payload.cryptographic_usage_mask)
        self.assertEqual(None, payload.lease_time)

        payload.read(self.full_encoding)

        self.assertEqual(
            '2c23217e-f53c-4bdf-ad0a-58a31fd3d4b6',
            payload.unique_identifier
        )
        self.assertEqual(500, payload.usage_limits_count)
        self.assertEqual(12, payload.cryptographic_usage_mask)
        self.assertEqual(0, payload.lease_time)

    def test_read_partial(self):
        """
        Test that a Check request payload can be read from a partial data
        stream.
        """
        payload = payloads.CheckRequestPayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.usage_limits_count)
        self.assertEqual(None, payload.cryptographic_usage_mask)
        self.assertEqual(None, payload.lease_time)

        payload.read(self.partial_encoding)

        self.assertEqual(
            '2c23217e-f53c-4bdf-ad0a-58a31fd3d4b6',
            payload.unique_identifier
        )
        self.assertEqual(500, payload.usage_limits_count)
        self.assertEqual(None, payload.cryptographic_usage_mask)
        self.assertEqual(None, payload.lease_time)

    def test_read_empty(self):
        """
        Test that a Check request payload can be read from an empty data
        stream.
        """
        payload = payloads.CheckRequestPayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.usage_limits_count)
        self.assertEqual(None, payload.cryptographic_usage_mask)
        self.assertEqual(None, payload.lease_time)

        payload.read(self.empty_encoding)

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.usage_limits_count)
        self.assertEqual(None, payload.cryptographic_usage_mask)
        self.assertEqual(None, payload.lease_time)

    def test_write(self):
        """
        Test that a Check request payload can be written to a data stream.
        """
        payload = payloads.CheckRequestPayload(
            unique_identifier='2c23217e-f53c-4bdf-ad0a-58a31fd3d4b6',
            usage_limits_count=500,
            cryptographic_usage_mask=12,
            lease_time=0
        )
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_partial(self):
        """
        Test that a partial Check request payload can be written to a data
        stream.
        """
        payload = payloads.CheckRequestPayload(
            unique_identifier='2c23217e-f53c-4bdf-ad0a-58a31fd3d4b6',
            usage_limits_count=500
        )
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.partial_encoding), len(stream))
        self.assertEqual(str(self.partial_encoding), str(stream))

    def test_write_empty(self):
        """
        Test that an empty Check request payload can be written to a data
        stream.
        """
        payload = payloads.CheckRequestPayload()
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.empty_encoding), len(stream))
        self.assertEqual(str(self.empty_encoding), str(stream))

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        Check request payloads with the same data.
        """
        a = payloads.CheckRequestPayload()
        b = payloads.CheckRequestPayload()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = payloads.CheckRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            usage_limits_count=200,
            cryptographic_usage_mask=4,
            lease_time=1511882848
        )
        b = payloads.CheckRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            usage_limits_count=200,
            cryptographic_usage_mask=4,
            lease_time=1511882848
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_unique_identifier(self):
        """
        Test that the equality operator returns False when comparing two
        Check request payloads with different unique identifiers.
        """
        a = payloads.CheckRequestPayload(
            unique_identifier='a'
        )
        b = payloads.CheckRequestPayload(
            unique_identifier='b'
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_usage_limits_count(self):
        """
        Test that the equality operator returns False when comparing two
        Check request payloads with different usage limits counts.
        """
        a = payloads.CheckRequestPayload(
            usage_limits_count=0
        )
        b = payloads.CheckRequestPayload(
            usage_limits_count=1
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_cryptographic_usage_mask(self):
        """
        Test that the equality operator returns False when comparing two
        Check request payloads with different cryptographic usage masks.
        """
        a = payloads.CheckRequestPayload(
            cryptographic_usage_mask=4
        )
        b = payloads.CheckRequestPayload(
            cryptographic_usage_mask=12
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_lease_time(self):
        """
        Test that the equality operator returns False when comparing two
        Check request payloads with different lease times.
        """
        a = payloads.CheckRequestPayload(
            lease_time=0
        )
        b = payloads.CheckRequestPayload(
            lease_time=1511882848
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        Check request payloads with different types.
        """
        a = payloads.CheckRequestPayload()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        Check request payloads with the same data.
        """
        a = payloads.CheckRequestPayload()
        b = payloads.CheckRequestPayload()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = payloads.CheckRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            usage_limits_count=200,
            cryptographic_usage_mask=4,
            lease_time=1511882848
        )
        b = payloads.CheckRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            usage_limits_count=200,
            cryptographic_usage_mask=4,
            lease_time=1511882848
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_unique_identifier(self):
        """
        Test that the inequality operator returns True when comparing two
        Check request payloads with different unique identifiers.
        """
        a = payloads.CheckRequestPayload(
            unique_identifier='a'
        )
        b = payloads.CheckRequestPayload(
            unique_identifier='b'
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_usage_limits_count(self):
        """
        Test that the inequality operator returns True when comparing two
        Check request payloads with different usage limits counts.
        """
        a = payloads.CheckRequestPayload(
            usage_limits_count=0
        )
        b = payloads.CheckRequestPayload(
            usage_limits_count=1
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_cryptographic_usage_mask(self):
        """
        Test that the inequality operator returns True when comparing two
        Check request payloads with different cryptographic usage masks.
        """
        a = payloads.CheckRequestPayload(
            cryptographic_usage_mask=4
        )
        b = payloads.CheckRequestPayload(
            cryptographic_usage_mask=12
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_lease_time(self):
        """
        Test that the inequality operator returns True when comparing two
        Check request payloads with different lease times.
        """
        a = payloads.CheckRequestPayload(
            lease_time=0
        )
        b = payloads.CheckRequestPayload(
            lease_time=1511882848
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        Check request payloads with different types.
        """
        a = payloads.CheckRequestPayload()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test that repr can be applied to a Check request payload.
        """
        payload = payloads.CheckRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            usage_limits_count=1000,
            cryptographic_usage_mask=8,
            lease_time=1511882898
        )
        expected = (
            "CheckRequestPayload("
            "unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038', "
            "usage_limits_count=1000, "
            "cryptographic_usage_mask=8, "
            "lease_time=1511882898)"
        )
        observed = repr(payload)

        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a Check request payload
        """
        payload = payloads.CheckRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            usage_limits_count=1000,
            cryptographic_usage_mask=8,
            lease_time=1511882898
        )

        expected = str({
            'unique_identifier': '49a1ca88-6bea-4fb2-b450-7e58802c3038',
            'usage_limits_count': 1000,
            'cryptographic_usage_mask': 8,
            'lease_time': 1511882898
        })
        observed = str(payload)

        self.assertEqual(expected, observed)

    def test_read_valid(self):
        """
        Test that a Check response payload can be read from a valid byte
        stream.
        """
        self.test_read()

    def test_read_missing_required_field(self):
        """
        Test that an exception is raised when reading a payload missing a
        required field.
        """
        payload = payloads.CheckResponsePayload()
        self.assertRaises(Exception, payload.read, utils.BytearrayStream(b""))

    def test_write_valid(self):
        """
        Test that a Check response payload can be written to a byte stream.
        """
        self.test_write()

    def test_read_write_roundtrip(self):
        """
        Test that a Check response payload can be read and written without
        changing the encoded bytes.
        """
        payload = payloads.CheckResponsePayload()
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
        Test that two Check response payloads with the same data are equal.
        """
        self.test_equal_on_equal()

    def test_ne(self):
        """
        Test that two Check response payloads with different data are not
        equal.
        """
        self.test_not_equal_on_not_equal_unique_identifier()

    def test_read_valid(self):
        """
        Test that a Check response payload can be read from a valid byte
        stream.
        """
        self.test_read()

    def test_read_missing_required_field(self):
        """
        Test that an exception is raised when reading a payload missing a
        required field.
        """
        payload = payloads.CheckResponsePayload()
        self.assertRaises(Exception, payload.read, utils.BytearrayStream(b""))

    def test_write_valid(self):
        """
        Test that a Check response payload can be written to a byte stream.
        """
        self.test_write()

    def test_read_write_roundtrip(self):
        """
        Test that a Check response payload can be read and written without
        changing the encoded bytes.
        """
        payload = payloads.CheckResponsePayload()
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
        Test that two Check response payloads with the same data are equal.
        """
        self.test_equal_on_equal()

    def test_ne(self):
        """
        Test that two Check response payloads with different data are not
        equal.
        """
        self.test_not_equal_on_not_equal_unique_identifier()

    def test_read_valid(self):
        """
        Test that a Check request payload can be read from a valid byte stream.
        """
        self.test_read()

    def test_read_missing_required_field(self):
        """
        Test that an exception is raised when reading a payload missing a
        required field.
        """
        payload = payloads.CheckRequestPayload()
        self.assertRaises(Exception, payload.read, utils.BytearrayStream(b""))

    def test_write_valid(self):
        """
        Test that a Check request payload can be written to a byte stream.
        """
        self.test_write()

    def test_read_write_roundtrip(self):
        """
        Test that a Check request payload can be read and written without
        changing the encoded bytes.
        """
        payload = payloads.CheckRequestPayload()
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
        Test that two Check request payloads with the same data are equal.
        """
        self.test_equal_on_equal()

    def test_ne(self):
        """
        Test that two Check request payloads with different data are not equal.
        """
        self.test_not_equal_on_not_equal_unique_identifier()

class TestCheckResponsePayload(testtools.TestCase):
    """
    Test suite for the Check response payload.
    """

    def setUp(self):
        super(TestCheckResponsePayload, self).setUp()

        # Encoding obtained in part from the KMIP 1.1 testing document,
        # Section 5.1. The rest of the encoding was built by hand.
        #
        # This encoding matches the following set of values:
        # Response Payload
        #     Unique Identifier - 2c23217e-f53c-4bdf-ad0a-58a31fd3d4b6
        #     Usage Limits Count - 500
        #     Cryptographic Usage Mask - Encrypt | Decrypt (4 | 8 -> 12 or C)
        #     Lease Time - 0

        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x60'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x32\x63\x32\x33\x32\x31\x37\x65\x2D\x66\x35\x33\x63\x2D\x34\x62'
            b'\x64\x66\x2D\x61\x64\x30\x61\x2D\x35\x38\x61\x33\x31\x66\x64\x33'
            b'\x64\x34\x62\x36\x00\x00\x00\x00'
            b'\x42\x00\x96\x03\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x01\xF4'
            b'\x42\x00\x2C\x02\x00\x00\x00\x04\x00\x00\x00\x0C\x00\x00\x00\x00'
            b'\x42\x00\x49\x0A\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00'
        )

        # This encoding matches the following set of values:
        # Response Payload
        #     Unique Identifier - 2c23217e-f53c-4bdf-ad0a-58a31fd3d4b6
        #     Usage Limits Count - 500
        self.partial_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x40'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x32\x63\x32\x33\x32\x31\x37\x65\x2D\x66\x35\x33\x63\x2D\x34\x62'
            b'\x64\x66\x2D\x61\x64\x30\x61\x2D\x35\x38\x61\x33\x31\x66\x64\x33'
            b'\x64\x34\x62\x36\x00\x00\x00\x00'
            b'\x42\x00\x96\x03\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x01\xF4'
        )

        self.empty_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestCheckResponsePayload, self).tearDown()

    def test_init(self):
        """
        Test that a Check response payload can be constructed with no
        arguments.
        """
        payload = payloads.CheckResponsePayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.usage_limits_count)
        self.assertEqual(None, payload.cryptographic_usage_mask)
        self.assertEqual(None, payload.lease_time)

    def test_init_with_args(self):
        """
        Test that a Check response payload can be constructed with valid
        values.
        """
        payload = payloads.CheckResponsePayload(
            unique_identifier='00000000-1111-2222-3333-444444444444',
            usage_limits_count=10,
            cryptographic_usage_mask=12,
            lease_time=1000000000
        )

        self.assertEqual(
            '00000000-1111-2222-3333-444444444444',
            payload.unique_identifier
        )
        self.assertEqual(10, payload.usage_limits_count)
        self.assertEqual(12, payload.cryptographic_usage_mask)
        self.assertEqual(1000000000, payload.lease_time)

    def test_invalid_unique_identifier(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the unique identifier of a Check response payload.
        """
        kwargs = {'unique_identifier': 0}
        self.assertRaisesRegex(
            TypeError,
            "Unique identifier must be a string.",
            payloads.CheckResponsePayload,
            **kwargs
        )

        payload = payloads.CheckResponsePayload()
        args = (payload, 'unique_identifier', 0)
        self.assertRaisesRegex(
            TypeError,
            "Unique identifier must be a string.",
            setattr,
            *args
        )

    def test_invalid_usage_limits_count(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the usage limits count of a Check response payload.
        """
        kwargs = {'usage_limits_count': 'invalid'}
        self.assertRaisesRegex(
            TypeError,
            "Usage limits count must be an integer.",
            payloads.CheckResponsePayload,
            **kwargs
        )

        payload = payloads.CheckResponsePayload()
        args = (payload, 'usage_limits_count', 'invalid')
        self.assertRaisesRegex(
            TypeError,
            "Usage limits count must be an integer.",
            setattr,
            *args
        )

    def test_invalid_cryptographic_usage_mask(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the cryptographic usage mask of a Check response payload.
        """
        kwargs = {'cryptographic_usage_mask': 'invalid'}
        self.assertRaisesRegex(
            TypeError,
            "Cryptographic usage mask must be an integer.",
            payloads.CheckResponsePayload,
            **kwargs
        )

        payload = payloads.CheckResponsePayload()
        args = (payload, 'cryptographic_usage_mask', 'invalid')
        self.assertRaisesRegex(
            TypeError,
            "Cryptographic usage mask must be an integer.",
            setattr,
            *args
        )

    def test_invalid_lease_time(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the lease time of a Check response payload.
        """
        kwargs = {'lease_time': 'invalid'}
        self.assertRaisesRegex(
            TypeError,
            "Lease time must be an integer.",
            payloads.CheckResponsePayload,
            **kwargs
        )

        payload = payloads.CheckResponsePayload()
        args = (payload, 'lease_time', 'invalid')
        self.assertRaisesRegex(
            TypeError,
            "Lease time must be an integer.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a Check response payload can be read from a data stream.
        """
        payload = payloads.CheckResponsePayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.usage_limits_count)
        self.assertEqual(None, payload.cryptographic_usage_mask)
        self.assertEqual(None, payload.lease_time)

        payload.read(self.full_encoding)

        self.assertEqual(
            '2c23217e-f53c-4bdf-ad0a-58a31fd3d4b6',
            payload.unique_identifier
        )
        self.assertEqual(500, payload.usage_limits_count)
        self.assertEqual(12, payload.cryptographic_usage_mask)
        self.assertEqual(0, payload.lease_time)

    def test_read_partial(self):
        """
        Test that a Check response payload can be read from a partial data
        stream.
        """
        payload = payloads.CheckResponsePayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.usage_limits_count)
        self.assertEqual(None, payload.cryptographic_usage_mask)
        self.assertEqual(None, payload.lease_time)

        payload.read(self.partial_encoding)

        self.assertEqual(
            '2c23217e-f53c-4bdf-ad0a-58a31fd3d4b6',
            payload.unique_identifier
        )
        self.assertEqual(500, payload.usage_limits_count)
        self.assertEqual(None, payload.cryptographic_usage_mask)
        self.assertEqual(None, payload.lease_time)

    def test_read_empty(self):
        """
        Test that a Check response payload can be read from an empty data
        stream.
        """
        payload = payloads.CheckResponsePayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.usage_limits_count)
        self.assertEqual(None, payload.cryptographic_usage_mask)
        self.assertEqual(None, payload.lease_time)

        payload.read(self.empty_encoding)

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.usage_limits_count)
        self.assertEqual(None, payload.cryptographic_usage_mask)
        self.assertEqual(None, payload.lease_time)

    def test_write(self):
        """
        Test that a Check response payload can be written to a data stream.
        """
        payload = payloads.CheckResponsePayload(
            unique_identifier='2c23217e-f53c-4bdf-ad0a-58a31fd3d4b6',
            usage_limits_count=500,
            cryptographic_usage_mask=12,
            lease_time=0
        )
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_partial(self):
        """
        Test that a partial Check response payload can be written to a data
        stream.
        """
        payload = payloads.CheckResponsePayload(
            unique_identifier='2c23217e-f53c-4bdf-ad0a-58a31fd3d4b6',
            usage_limits_count=500
        )
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.partial_encoding), len(stream))
        self.assertEqual(str(self.partial_encoding), str(stream))

    def test_write_empty(self):
        """
        Test that an empty Check response payload can be written to a data
        stream.
        """
        payload = payloads.CheckResponsePayload()
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.empty_encoding), len(stream))
        self.assertEqual(str(self.empty_encoding), str(stream))

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        Check response payloads with the same data.
        """
        a = payloads.CheckResponsePayload()
        b = payloads.CheckResponsePayload()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = payloads.CheckResponsePayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            usage_limits_count=200,
            cryptographic_usage_mask=4,
            lease_time=1511882848
        )
        b = payloads.CheckResponsePayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            usage_limits_count=200,
            cryptographic_usage_mask=4,
            lease_time=1511882848
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_unique_identifier(self):
        """
        Test that the equality operator returns False when comparing two
        Check response payloads with different unique identifiers.
        """
        a = payloads.CheckResponsePayload(
            unique_identifier='a'
        )
        b = payloads.CheckResponsePayload(
            unique_identifier='b'
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_usage_limits_count(self):
        """
        Test that the equality operator returns False when comparing two
        Check response payloads with different usage limits counts.
        """
        a = payloads.CheckResponsePayload(
            usage_limits_count=0
        )
        b = payloads.CheckResponsePayload(
            usage_limits_count=1
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_cryptographic_usage_mask(self):
        """
        Test that the equality operator returns False when comparing two
        Check response payloads with different cryptographic usage masks.
        """
        a = payloads.CheckResponsePayload(
            cryptographic_usage_mask=4
        )
        b = payloads.CheckResponsePayload(
            cryptographic_usage_mask=12
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_lease_time(self):
        """
        Test that the equality operator returns False when comparing two
        Check response payloads with different lease times.
        """
        a = payloads.CheckResponsePayload(
            lease_time=0
        )
        b = payloads.CheckResponsePayload(
            lease_time=1511882848
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        Check response payloads with different types.
        """
        a = payloads.CheckResponsePayload()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        Check response payloads with the same data.
        """
        a = payloads.CheckResponsePayload()
        b = payloads.CheckResponsePayload()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = payloads.CheckResponsePayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            usage_limits_count=200,
            cryptographic_usage_mask=4,
            lease_time=1511882848
        )
        b = payloads.CheckResponsePayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            usage_limits_count=200,
            cryptographic_usage_mask=4,
            lease_time=1511882848
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_unique_identifier(self):
        """
        Test that the inequality operator returns True when comparing two
        Check response payloads with different unique identifiers.
        """
        a = payloads.CheckResponsePayload(
            unique_identifier='a'
        )
        b = payloads.CheckResponsePayload(
            unique_identifier='b'
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_usage_limits_count(self):
        """
        Test that the inequality operator returns True when comparing two
        Check response payloads with different usage limits counts.
        """
        a = payloads.CheckResponsePayload(
            usage_limits_count=0
        )
        b = payloads.CheckResponsePayload(
            usage_limits_count=1
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_cryptographic_usage_mask(self):
        """
        Test that the inequality operator returns True when comparing two
        Check response payloads with different cryptographic usage masks.
        """
        a = payloads.CheckResponsePayload(
            cryptographic_usage_mask=4
        )
        b = payloads.CheckResponsePayload(
            cryptographic_usage_mask=12
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_lease_time(self):
        """
        Test that the inequality operator returns True when comparing two
        Check response payloads with different lease times.
        """
        a = payloads.CheckResponsePayload(
            lease_time=0
        )
        b = payloads.CheckResponsePayload(
            lease_time=1511882848
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        Check response payloads with different types.
        """
        a = payloads.CheckResponsePayload()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test that repr can be applied to a Check response payload.
        """
        payload = payloads.CheckResponsePayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            usage_limits_count=1000,
            cryptographic_usage_mask=8,
            lease_time=1511882898
        )
        expected = (
            "CheckResponsePayload("
            "unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038', "
            "usage_limits_count=1000, "
            "cryptographic_usage_mask=8, "
            "lease_time=1511882898)"
        )
        observed = repr(payload)

        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a Check response payload
        """
        payload = payloads.CheckResponsePayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            usage_limits_count=1000,
            cryptographic_usage_mask=8,
            lease_time=1511882898
        )

        expected = str({
            'unique_identifier': '49a1ca88-6bea-4fb2-b450-7e58802c3038',
            'usage_limits_count': 1000,
            'cryptographic_usage_mask': 8,
            'lease_time': 1511882898
        })
        observed = str(payload)

        self.assertEqual(expected, observed)
    def test_read_valid(self):
        """
        Test that a Check response payload can be read from a valid byte
        stream.
        """
        self.test_read()

    def test_read_missing_required_field(self):
        """
        Test that an exception is raised when reading a payload missing a
        required field.
        """
        payload = payloads.CheckResponsePayload()
        self.assertRaises(Exception, payload.read, utils.BytearrayStream(b""))

    def test_write_valid(self):
        """
        Test that a Check response payload can be written to a byte stream.
        """
        self.test_write()

    def test_read_write_roundtrip(self):
        """
        Test that a Check response payload can be read and written without
        changing the encoded bytes.
        """
        payload = payloads.CheckResponsePayload()
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
        Test that two Check response payloads with the same data are equal.
        """
        self.test_equal_on_equal()

    def test_ne(self):
        """
        Test that two Check response payloads with different data are not
        equal.
        """
        self.test_not_equal_on_not_equal_unique_identifier()
