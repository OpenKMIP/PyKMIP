# Copyright (c) 2015 Hewlett Packard Development Company, L.P.
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

from testtools import TestCase

from kmip.core import attributes
from kmip.core import enums
from kmip.core import objects
from kmip.core import primitives
from kmip.core import utils

from kmip.core.messages import payloads

class TestRevokeRequestPayload(TestCase):
    """
    Test suite for the RevokeRequestPayload class.

    Test encodings obtained from Sections 4.2 of the KMIP 1.1 Test
    Cases documentation.
    """

    def setUp(self):
        super(TestRevokeRequestPayload, self).setUp()

        self.uuid = attributes.UniqueIdentifier(
            '668eff89-3010-4258-bc0e-8c402309c746')

        self.encoding_a = utils.BytearrayStream((
            b'\x42\x00\x79\x01\x00\x00\x00\x58\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x36\x36\x38\x65\x66\x66\x38\x39\x2D\x33\x30\x31\x30\x2D\x34\x32'
            b'\x35\x38\x2D\x62\x63\x30\x65\x2D\x38\x63\x34\x30\x32\x33\x30\x39'
            b'\x63\x37\x34\x36\x00\x00\x00\x00\x42\x00\x81\x01\x00\x00\x00\x10'
            b'\x42\x00\x82\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x21\x09\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x06'
            ))

    def tearDown(self):
        super(TestRevokeRequestPayload, self).tearDown()

    def test_init_with_none(self):
        """
        Test that a RevokeRequestPayload object can be constructed with no
        specified value.
        """
        payloads.RevokeRequestPayload()

    def test_init_with_args(self):
        """
        Test that a RevokeRequestPayload object can be constructed with valid
        values.
        """
        payloads.RevokeRequestPayload(unique_identifier=self.uuid)

    def test_init(self):
        """
        Test that a RevokeRequestPayload object can be constructed with no
        arguments.
        """
        self.test_init_with_none()

    def test_validate_with_bad_uuid_type(self):
        """
        Test that a TypeError exception is raised when an invalid UUID type
        is used to construct a RevokeRequestPayload object.
        """
        self.assertRaisesRegex(
            TypeError, "invalid unique identifier",
            payloads.RevokeRequestPayload, "not-a-uuid")

    def test_validate_with_bad_date_type(self):
        """
        Test that a TypeError exception is raised when an invalid UUID type
        is used to construct a RevokeRequestPayload object.
        """
        reason = objects.RevocationReason()
        self.assertRaisesRegex(
            TypeError, "invalid compromise time",
            payloads.RevokeRequestPayload, self.uuid, reason, "not-a-date")

    def test_validate_with_bad_reason_type(self):
        """
        Test that a TypeError exception is raised when an invalid UUID type
        is used to construct a RevokeRequestPayload object.
        """
        self.assertRaisesRegex(
            TypeError, "invalid revocation reason",
            payloads.RevokeRequestPayload, self.uuid, "not-a-reason")

    def test_read_with_known_uuid(self):
        """
        Test that a RevokeRequestPayload object with known UUID can be read
        from a data stream.
        """
        payload = payloads.RevokeRequestPayload()
        payload.read(self.encoding_a)
        expected = '668eff89-3010-4258-bc0e-8c402309c746'
        observed = payload.unique_identifier.value

        msg = "Revoke UUID value mismatch"
        msg += "; expected {0}, received {1}".format(
            expected, observed)
        self.assertEqual(expected, observed, msg)

    def test_write_with_known_uuid(self):
        """
        Test that a RevokeRequestPayload object with a known UUID can be
        written to a data stream.
        """
        reason = objects.RevocationReason(
            code=enums.RevocationReasonCode.KEY_COMPROMISE)
        date = primitives.DateTime(
            tag=enums.Tags.COMPROMISE_OCCURRENCE_DATE, value=6)

        stream = utils.BytearrayStream()
        payload = payloads.RevokeRequestPayload(
            unique_identifier=self.uuid,
            revocation_reason=reason,
            compromise_occurrence_date=date)
        payload.write(stream)

        length_expected = len(self.encoding_a)
        length_received = len(stream)

        msg = "encoding lengths not equal"
        msg += "; expected {0}, received {1}".format(
            length_expected, length_received)
        self.assertEqual(length_expected, length_received, msg)

        msg = "encoding mismatch"
        msg += ";\nexpected:\n{0}\nreceived:\n{1}".format(self.encoding_a,
                                                          stream)

        self.assertEqual(self.encoding_a, stream, msg)

    def test_read_valid(self):
        """
        Test that a RevokeRequestPayload object can be read from a valid byte
        stream.
        """
        self.test_read_with_known_uuid()

    def test_read_missing_required_field(self):
        """
        Test that an exception is raised when reading a request payload
        missing the unique identifier.
        """
        payload = payloads.RevokeRequestPayload()
        empty_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x00'
        )
        self.assertRaises(Exception, payload.read, empty_encoding)

    def test_write_valid(self):
        """
        Test that a RevokeRequestPayload object can be written to a byte
        stream.
        """
        self.test_write_with_known_uuid()

    def test_read_write_roundtrip(self):
        """
        Test that a RevokeRequestPayload object can be read and written
        without changing the encoded bytes.
        """
        payload = payloads.RevokeRequestPayload()
        payload.read(utils.BytearrayStream(self.encoding_a.buffer))

        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(self.encoding_a, stream)

    def test_validate_invalid(self):
        """
        Test that an exception is raised when the unique identifier type is
        invalid.
        """
        self.test_validate_with_bad_uuid_type()

    def test_eq(self):
        """
        Test that a RevokeRequestPayload object compares equal to itself.
        """
        payload = payloads.RevokeRequestPayload()
        self.assertTrue(payload == payload)

    def test_ne(self):
        """
        Test that two different RevokeRequestPayload objects are not equal.
        """
        a = payloads.RevokeRequestPayload(self.uuid)
        b = payloads.RevokeRequestPayload(
            attributes.UniqueIdentifier(
                '11111111-2222-3333-4444-555555555555'
            )
        )
        self.assertTrue(a != b)

    def test_repr(self):
        """
        Test the repr output for a RevokeRequestPayload object.
        """
        payload = payloads.RevokeRequestPayload()
        self.assertIsInstance(repr(payload), str)

    def test_str(self):
        """
        Test the str output for a RevokeRequestPayload object.
        """
        payload = payloads.RevokeRequestPayload()
        self.assertIsInstance(str(payload), str)

class TestRevokeResponsePayload(TestCase):
    """
    Test encodings obtained from Sections 4.2 of the KMIP 1.1 Test
    Cases documentation.
    """

    def setUp(self):
        super(TestRevokeResponsePayload, self).setUp()

        self.uuid = attributes.UniqueIdentifier(
            '668eff89-3010-4258-bc0e-8c402309c746')

        self.encoding_a = utils.BytearrayStream((
            b'\x42\x00\x7C\x01\x00\x00\x00\x30\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x36\x36\x38\x65\x66\x66\x38\x39\x2D\x33\x30\x31\x30\x2D\x34\x32'
            b'\x35\x38\x2D\x62\x63\x30\x65\x2D\x38\x63\x34\x30\x32\x33\x30\x39'
            b'\x63\x37\x34\x36\x00\x00\x00\x00'))

    def tearDown(self):
        super(TestRevokeResponsePayload, self).tearDown()

    def test_init_with_none(self):
        """
        Test that a RevokeResponsePayload object can be constructed with no
        specified value.
        """
        payloads.RevokeResponsePayload()

    def test_init_with_args(self):
        """
        Test that a RevokeResponsePayload object can be constructed with
        valid values.
        """
        payloads.RevokeResponsePayload(unique_identifier=self.uuid)

    def test_init(self):
        """
        Test that a RevokeResponsePayload object can be constructed with no
        arguments.
        """
        self.test_init_with_none()

    def test_validate_with_invalid_uuid(self):
        """
        Test that a TypeError exception is raised when an invalid Operations
        list is used to construct a RevokeResponsePayload object.
        """
        self.assertRaisesRegex(
            TypeError, "invalid unique identifier",
            payloads.RevokeResponsePayload, "not-a-uuid")

    def test_read_with_known_uuid(self):
        """
        Test that a RevokeResponsePayload object with known UUID can be read
        from a data stream.
        """
        payload = payloads.RevokeResponsePayload()
        payload.read(self.encoding_a)
        expected = '668eff89-3010-4258-bc0e-8c402309c746'
        observed = payload.unique_identifier.value

        msg = "Revoke UUID value mismatch"
        msg += "; expected {0}, received {1}".format(
            expected, observed)
        self.assertEqual(expected, observed, msg)

    def test_write_with_known_uuid(self):
        """
        Test that a RevokeResponsePayload object with a known UUID can be
        written to a data stream.
        """
        stream = utils.BytearrayStream()
        payload = payloads.RevokeResponsePayload(self.uuid)
        payload.write(stream)

        length_expected = len(self.encoding_a)
        length_received = len(stream)

        msg = "encoding lengths not equal"
        msg += "; expected {0}, received {1}".format(
            length_expected, length_received)
        self.assertEqual(length_expected, length_received, msg)

        msg = "encoding mismatch"
        msg += ";\nexpected:\n{0}\nreceived:\n{1}".format(self.encoding_a,
                                                          stream)

        self.assertEqual(self.encoding_a, stream, msg)

    def test_read_valid(self):
        """
        Test that a RevokeResponsePayload object can be read from a valid byte
        stream.
        """
        self.test_read_with_known_uuid()

    def test_read_missing_required_field(self):
        """
        Test that an exception is raised when reading a response payload
        missing the unique identifier.
        """
        payload = payloads.RevokeResponsePayload()
        empty_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x00'
        )
        self.assertRaises(Exception, payload.read, empty_encoding)

    def test_write_valid(self):
        """
        Test that a RevokeResponsePayload object can be written to a byte
        stream.
        """
        self.test_write_with_known_uuid()

    def test_read_write_roundtrip(self):
        """
        Test that a RevokeResponsePayload object can be read and written
        without changing the encoded bytes.
        """
        payload = payloads.RevokeResponsePayload()
        payload.read(utils.BytearrayStream(self.encoding_a.buffer))

        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(self.encoding_a, stream)

    def test_validate_invalid(self):
        """
        Test that an exception is raised when the unique identifier type is
        invalid.
        """
        self.test_validate_with_invalid_uuid()

    def test_eq(self):
        """
        Test that a RevokeResponsePayload object compares equal to itself.
        """
        payload = payloads.RevokeResponsePayload()
        self.assertTrue(payload == payload)

    def test_ne(self):
        """
        Test that two different RevokeResponsePayload objects are not equal.
        """
        a = payloads.RevokeResponsePayload(self.uuid)
        b = payloads.RevokeResponsePayload(
            attributes.UniqueIdentifier(
                '11111111-2222-3333-4444-555555555555'
            )
        )
        self.assertTrue(a != b)

    def test_repr(self):
        """
        Test the repr output for a RevokeResponsePayload object.
        """
        payload = payloads.RevokeResponsePayload()
        self.assertIsInstance(repr(payload), str)

    def test_str(self):
        """
        Test the str output for a RevokeResponsePayload object.
        """
        payload = payloads.RevokeResponsePayload()
        self.assertIsInstance(str(payload), str)
