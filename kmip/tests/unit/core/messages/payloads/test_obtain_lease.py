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

class TestObtainLeaseRequestPayload(testtools.TestCase):
    """
    Test suite for the ObtainLease request payload.
    """

    def setUp(self):
        super(TestObtainLeaseRequestPayload, self).setUp()

        # Encoding obtained from the KMIP 1.1 testing document, Section 9.5.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Unique Identifier - f4152f17-9312-431a-b3fb-4fe86a86a7a1

        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x30'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x66\x34\x31\x35\x32\x66\x31\x37\x2D\x39\x33\x31\x32\x2D\x34\x33'
            b'\x31\x61\x2D\x62\x33\x66\x62\x2D\x34\x66\x65\x38\x36\x61\x38\x36'
            b'\x61\x37\x61\x31\x00\x00\x00\x00'
        )

        self.empty_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestObtainLeaseRequestPayload, self).tearDown()

    def test_init(self):
        """
        Test that an ObtainLease request payload can be constructed with no
        arguments.
        """
        payload = payloads.ObtainLeaseRequestPayload()

        self.assertEqual(None, payload.unique_identifier)

    def test_init_with_args(self):
        """
        Test that an ObtainLease request payload can be constructed with valid
        values.
        """
        payload = payloads.ObtainLeaseRequestPayload(
            unique_identifier='00000000-1111-2222-3333-444444444444'
        )

        self.assertEqual(
            '00000000-1111-2222-3333-444444444444',
            payload.unique_identifier
        )

    def test_invalid_unique_identifier(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the unique identifier of an ObtainLease request payload.
        """
        kwargs = {'unique_identifier': 0}
        self.assertRaisesRegex(
            TypeError,
            "Unique identifier must be a string.",
            payloads.ObtainLeaseRequestPayload,
            **kwargs
        )

        payload = payloads.ObtainLeaseRequestPayload()
        args = (payload, 'unique_identifier', 0)
        self.assertRaisesRegex(
            TypeError,
            "Unique identifier must be a string.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that an ObtainLease request payload can be read from a data
        stream.
        """
        payload = payloads.ObtainLeaseRequestPayload()

        self.assertEqual(None, payload.unique_identifier)

        payload.read(self.full_encoding)

        self.assertEqual(
            'f4152f17-9312-431a-b3fb-4fe86a86a7a1',
            payload.unique_identifier
        )

    def test_read_empty(self):
        """
        Test that an ObtainLease request payload can be read from an empty
        data stream.
        """
        payload = payloads.ObtainLeaseRequestPayload()

        self.assertEqual(None, payload.unique_identifier)

        payload.read(self.empty_encoding)

        self.assertEqual(None, payload.unique_identifier)

    def test_write(self):
        """
        Test that an ObtainLease request payload can be written to a data
        stream.
        """
        payload = payloads.ObtainLeaseRequestPayload(
            unique_identifier='f4152f17-9312-431a-b3fb-4fe86a86a7a1'
        )
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_empty(self):
        """
        Test that an empty ObtainLease request payload can be written to a
        data stream.
        """
        payload = payloads.ObtainLeaseRequestPayload()
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.empty_encoding), len(stream))
        self.assertEqual(str(self.empty_encoding), str(stream))

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        ObtainLease request payloads with the same data.
        """
        a = payloads.ObtainLeaseRequestPayload()
        b = payloads.ObtainLeaseRequestPayload()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = payloads.ObtainLeaseRequestPayload(
            unique_identifier='f4152f17-9312-431a-b3fb-4fe86a86a7a1'
        )
        b = payloads.ObtainLeaseRequestPayload(
            unique_identifier='f4152f17-9312-431a-b3fb-4fe86a86a7a1'
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_unique_identifier(self):
        """
        Test that the equality operator returns False when comparing two
        ObtainLease request payloads with different unique identifiers.
        """
        a = payloads.ObtainLeaseRequestPayload(
            unique_identifier='a'
        )
        b = payloads.ObtainLeaseRequestPayload(
            unique_identifier='b'
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        ObtainLease request payloads with different types.
        """
        a = payloads.ObtainLeaseRequestPayload()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        ObtainLease request payloads with the same data.
        """
        a = payloads.ObtainLeaseRequestPayload()
        b = payloads.ObtainLeaseRequestPayload()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = payloads.ObtainLeaseRequestPayload(
            unique_identifier='f4152f17-9312-431a-b3fb-4fe86a86a7a1'
        )
        b = payloads.ObtainLeaseRequestPayload(
            unique_identifier='f4152f17-9312-431a-b3fb-4fe86a86a7a1'
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_unique_identifier(self):
        """
        Test that the inequality operator returns True when comparing two
        ObtainLease request payloads with different unique identifiers.
        """
        a = payloads.ObtainLeaseRequestPayload(
            unique_identifier='a'
        )
        b = payloads.ObtainLeaseRequestPayload(
            unique_identifier='b'
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        ObtainLease request payloads with different types.
        """
        a = payloads.ObtainLeaseRequestPayload()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test that repr can be applied to an ObtainLease request payload.
        """
        payload = payloads.ObtainLeaseRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038'
        )
        expected = (
            "ObtainLeaseRequestPayload("
            "unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038')"
        )
        observed = repr(payload)

        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to an ObtainLease request payload
        """
        payload = payloads.ObtainLeaseRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038'
        )

        expected = str({
            'unique_identifier': '49a1ca88-6bea-4fb2-b450-7e58802c3038'
        })
        observed = str(payload)

        self.assertEqual(expected, observed)

    def test_read_valid(self):
        """
        Test that an ObtainLease response payload can be read from a valid
        byte stream.
        """
        self.test_read()

    def test_read_missing_required_field(self):
        """
        Test that an exception is raised when reading a payload missing a
        required field.
        """
        payload = payloads.ObtainLeaseResponsePayload()
        self.assertRaises(Exception, payload.read, utils.BytearrayStream(b""))

    def test_write_valid(self):
        """
        Test that an ObtainLease response payload can be written to a byte
        stream.
        """
        self.test_write()

    def test_read_write_roundtrip(self):
        """
        Test that an ObtainLease response payload can be read and written
        without changing the encoded bytes.
        """
        payload = payloads.ObtainLeaseResponsePayload()
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
        Test that two ObtainLease response payloads with the same data are
        equal.
        """
        self.test_equal_on_equal()

    def test_ne(self):
        """
        Test that two ObtainLease response payloads with different data are not
        equal.
        """
        self.test_not_equal_on_not_equal_unique_identifier()

    def test_read_valid(self):
        """
        Test that an ObtainLease response payload can be read from a valid
        byte stream.
        """
        self.test_read()

    def test_read_missing_required_field(self):
        """
        Test that an exception is raised when reading a payload missing a
        required field.
        """
        payload = payloads.ObtainLeaseResponsePayload()
        self.assertRaises(Exception, payload.read, utils.BytearrayStream(b""))

    def test_write_valid(self):
        """
        Test that an ObtainLease response payload can be written to a byte
        stream.
        """
        self.test_write()

    def test_read_write_roundtrip(self):
        """
        Test that an ObtainLease response payload can be read and written
        without changing the encoded bytes.
        """
        payload = payloads.ObtainLeaseResponsePayload()
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
        Test that two ObtainLease response payloads with the same data are
        equal.
        """
        self.test_equal_on_equal()

    def test_ne(self):
        """
        Test that two ObtainLease response payloads with different data are not
        equal.
        """
        self.test_not_equal_on_not_equal_unique_identifier()

    def test_read_valid(self):
        """
        Test that an ObtainLease request payload can be read from a valid byte
        stream.
        """
        self.test_read()

    def test_read_missing_required_field(self):
        """
        Test that an exception is raised when reading a payload missing a
        required field.
        """
        payload = payloads.ObtainLeaseRequestPayload()
        self.assertRaises(Exception, payload.read, utils.BytearrayStream(b""))

    def test_write_valid(self):
        """
        Test that an ObtainLease request payload can be written to a byte
        stream.
        """
        self.test_write()

    def test_read_write_roundtrip(self):
        """
        Test that an ObtainLease request payload can be read and written
        without changing the encoded bytes.
        """
        payload = payloads.ObtainLeaseRequestPayload()
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
        Test that two ObtainLease request payloads with the same data are
        equal.
        """
        self.test_equal_on_equal()

    def test_ne(self):
        """
        Test that two ObtainLease request payloads with different data are not
        equal.
        """
        self.test_not_equal_on_not_equal_unique_identifier()

class TestObtainLeaseResponsePayload(testtools.TestCase):
    """
    Test suite for the ObtainLease response payload.
    """

    def setUp(self):
        super(TestObtainLeaseResponsePayload, self).setUp()

        # Encoding obtained from the KMIP 1.1 testing document, Section 9.5.
        #
        # This encoding matches the following set of values:
        # Response Payload
        #     Unique Identifier - f4152f17-9312-431a-b3fb-4fe86a86a7a1
        #     Lease Time - 0
        #     Last Change Date - 0x4F9A5564 (Fri Apr 27 10:14:28 CEST 2012)

        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x50'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x66\x34\x31\x35\x32\x66\x31\x37\x2D\x39\x33\x31\x32\x2D\x34\x33'
            b'\x31\x61\x2D\x62\x33\x66\x62\x2D\x34\x66\x65\x38\x36\x61\x38\x36'
            b'\x61\x37\x61\x31\x00\x00\x00\x00'
            b'\x42\x00\x49\x0A\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\x48\x09\x00\x00\x00\x08\x00\x00\x00\x00\x4F\x9A\x55\x64'
        )

        # This encoding matches the following set of values:
        # Response Payload
        #     Unique Identifier - f4152f17-9312-431a-b3fb-4fe86a86a7a1
        self.partial_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x30'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x66\x34\x31\x35\x32\x66\x31\x37\x2D\x39\x33\x31\x32\x2D\x34\x33'
            b'\x31\x61\x2D\x62\x33\x66\x62\x2D\x34\x66\x65\x38\x36\x61\x38\x36'
            b'\x61\x37\x61\x31\x00\x00\x00\x00'
        )

        self.empty_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestObtainLeaseResponsePayload, self).tearDown()

    def test_init(self):
        """
        Test that an ObtainLease response payload can be constructed with no
        arguments.
        """
        payload = payloads.ObtainLeaseResponsePayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.lease_time)
        self.assertEqual(None, payload.last_change_date)

    def test_init_with_args(self):
        """
        Test that an ObtainLease response payload can be constructed with valid
        values.
        """
        payload = payloads.ObtainLeaseResponsePayload(
            unique_identifier='00000000-1111-2222-3333-444444444444',
            lease_time=1000000000,
            last_change_date=1512400153
        )

        self.assertEqual(
            '00000000-1111-2222-3333-444444444444',
            payload.unique_identifier
        )
        self.assertEqual(1000000000, payload.lease_time)
        self.assertEqual(1512400153, payload.last_change_date)

    def test_invalid_unique_identifier(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the unique identifier of an ObtainLease response payload.
        """
        kwargs = {'unique_identifier': 0}
        self.assertRaisesRegex(
            TypeError,
            "Unique identifier must be a string.",
            payloads.ObtainLeaseResponsePayload,
            **kwargs
        )

        payload = payloads.ObtainLeaseResponsePayload()
        args = (payload, 'unique_identifier', 0)
        self.assertRaisesRegex(
            TypeError,
            "Unique identifier must be a string.",
            setattr,
            *args
        )

    def test_invalid_lease_time(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the lease time of an ObtainLease response payload.
        """
        kwargs = {'lease_time': 'invalid'}
        self.assertRaisesRegex(
            TypeError,
            "Lease time must be an integer.",
            payloads.ObtainLeaseResponsePayload,
            **kwargs
        )

        payload = payloads.ObtainLeaseResponsePayload()
        args = (payload, 'lease_time', 'invalid')
        self.assertRaisesRegex(
            TypeError,
            "Lease time must be an integer.",
            setattr,
            *args
        )

    def test_invalid_last_change_date(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the last change date of an ObtainLease response payload.
        """
        kwargs = {'last_change_date': 'invalid'}
        self.assertRaisesRegex(
            TypeError,
            "Last change date must be an integer.",
            payloads.ObtainLeaseResponsePayload,
            **kwargs
        )

        payload = payloads.ObtainLeaseResponsePayload()
        args = (payload, 'last_change_date', 'invalid')
        self.assertRaisesRegex(
            TypeError,
            "Last change date must be an integer.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that an ObtainLease response payload can be read from a data
        stream.
        """
        payload = payloads.ObtainLeaseResponsePayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.lease_time)
        self.assertEqual(None, payload.last_change_date)

        payload.read(self.full_encoding)

        self.assertEqual(
            'f4152f17-9312-431a-b3fb-4fe86a86a7a1',
            payload.unique_identifier
        )
        self.assertEqual(0, payload.lease_time)
        self.assertEqual(1335514468, payload.last_change_date)

    def test_read_partial(self):
        """
        Test that an ObtainLease response payload can be read from a partial
        data stream.
        """
        payload = payloads.ObtainLeaseResponsePayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.lease_time)
        self.assertEqual(None, payload.last_change_date)

        payload.read(self.partial_encoding)

        self.assertEqual(
            'f4152f17-9312-431a-b3fb-4fe86a86a7a1',
            payload.unique_identifier
        )
        self.assertEqual(None, payload.lease_time)
        self.assertEqual(None, payload.last_change_date)

    def test_read_empty(self):
        """
        Test that an ObtainLease response payload can be read from an empty
        data stream.
        """
        payload = payloads.ObtainLeaseResponsePayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.lease_time)
        self.assertEqual(None, payload.last_change_date)

        payload.read(self.empty_encoding)

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.lease_time)
        self.assertEqual(None, payload.last_change_date)

    def test_write(self):
        """
        Test that an ObtainLease response payload can be written to a data
        stream.
        """
        payload = payloads.ObtainLeaseResponsePayload(
            unique_identifier='f4152f17-9312-431a-b3fb-4fe86a86a7a1',
            lease_time=0,
            last_change_date=1335514468
        )
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_partial(self):
        """
        Test that a partial ObtainLease response payload can be written to a
        data stream.
        """
        payload = payloads.ObtainLeaseResponsePayload(
            unique_identifier='f4152f17-9312-431a-b3fb-4fe86a86a7a1'
        )
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.partial_encoding), len(stream))
        self.assertEqual(str(self.partial_encoding), str(stream))

    def test_write_empty(self):
        """
        Test that an empty ObtainLease response payload can be written to a
        data stream.
        """
        payload = payloads.ObtainLeaseResponsePayload()
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.empty_encoding), len(stream))
        self.assertEqual(str(self.empty_encoding), str(stream))

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        ObtainLease response payloads with the same data.
        """
        a = payloads.ObtainLeaseResponsePayload()
        b = payloads.ObtainLeaseResponsePayload()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = payloads.ObtainLeaseResponsePayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            lease_time=1511882848,
            last_change_date=1512410153
        )
        b = payloads.ObtainLeaseResponsePayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            lease_time=1511882848,
            last_change_date=1512410153
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_unique_identifier(self):
        """
        Test that the equality operator returns False when comparing two
        ObtainLease response payloads with different unique identifiers.
        """
        a = payloads.ObtainLeaseResponsePayload(
            unique_identifier='a'
        )
        b = payloads.ObtainLeaseResponsePayload(
            unique_identifier='b'
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_lease_time(self):
        """
        Test that the equality operator returns False when comparing two
        ObtainLease response payloads with different lease times.
        """
        a = payloads.ObtainLeaseResponsePayload(
            lease_time=0
        )
        b = payloads.ObtainLeaseResponsePayload(
            lease_time=1511882848
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_last_change_date(self):
        """
        Test that the equality operator returns False when comparing two
        ObtainLease response payloads with different last change dates.
        """
        a = payloads.ObtainLeaseResponsePayload(
            last_change_date=0
        )
        b = payloads.ObtainLeaseResponsePayload(
            last_change_date=1511882848
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        ObtainLease response payloads with different types.
        """
        a = payloads.ObtainLeaseResponsePayload()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        ObtainLease response payloads with the same data.
        """
        a = payloads.ObtainLeaseResponsePayload()
        b = payloads.ObtainLeaseResponsePayload()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = payloads.ObtainLeaseResponsePayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            lease_time=1511882848,
            last_change_date=0
        )
        b = payloads.ObtainLeaseResponsePayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            lease_time=1511882848,
            last_change_date=0
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_unique_identifier(self):
        """
        Test that the inequality operator returns True when comparing two
        ObtainLease response payloads with different unique identifiers.
        """
        a = payloads.ObtainLeaseResponsePayload(
            unique_identifier='a'
        )
        b = payloads.ObtainLeaseResponsePayload(
            unique_identifier='b'
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_lease_time(self):
        """
        Test that the inequality operator returns True when comparing two
        ObtainLease response payloads with different lease times.
        """
        a = payloads.ObtainLeaseResponsePayload(
            lease_time=0
        )
        b = payloads.ObtainLeaseResponsePayload(
            lease_time=1511882848
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_last_change_time(self):
        """
        Test that the inequality operator returns True when comparing two
        ObtainLease response payloads with different last change time.
        """
        a = payloads.ObtainLeaseResponsePayload(
            lease_time=0
        )
        b = payloads.ObtainLeaseResponsePayload(
            lease_time=1511882848
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        ObtainLease response payloads with different types.
        """
        a = payloads.ObtainLeaseResponsePayload()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test that repr can be applied to an ObtainLease response payload.
        """
        payload = payloads.ObtainLeaseResponsePayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            lease_time=1511882898,
            last_change_date=1512410153
        )
        expected = (
            "ObtainLeaseResponsePayload("
            "unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038', "
            "lease_time=1511882898, "
            "last_change_date=1512410153)"
        )
        observed = repr(payload)

        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to an ObtainLease response payload.
        """
        payload = payloads.ObtainLeaseResponsePayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            lease_time=1511882898,
            last_change_date=1512410153
        )

        expected = str({
            'unique_identifier': '49a1ca88-6bea-4fb2-b450-7e58802c3038',
            'lease_time': 1511882898,
            'last_change_date': 1512410153
        })
        observed = str(payload)

        self.assertEqual(expected, observed)
    def test_read_valid(self):
        """
        Test that an ObtainLease response payload can be read from a valid
        byte stream.
        """
        self.test_read()

    def test_read_missing_required_field(self):
        """
        Test that an exception is raised when reading a payload missing a
        required field.
        """
        payload = payloads.ObtainLeaseResponsePayload()
        self.assertRaises(Exception, payload.read, utils.BytearrayStream(b""))

    def test_write_valid(self):
        """
        Test that an ObtainLease response payload can be written to a byte
        stream.
        """
        self.test_write()

    def test_read_write_roundtrip(self):
        """
        Test that an ObtainLease response payload can be read and written
        without changing the encoded bytes.
        """
        payload = payloads.ObtainLeaseResponsePayload()
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
        Test that two ObtainLease response payloads with the same data are
        equal.
        """
        self.test_equal_on_equal()

    def test_ne(self):
        """
        Test that two ObtainLease response payloads with different data are not
        equal.
        """
        self.test_not_equal_on_not_equal_unique_identifier()
