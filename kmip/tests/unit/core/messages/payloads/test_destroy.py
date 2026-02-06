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
from kmip.core import exceptions
from kmip.core import utils

from kmip.core.messages import payloads


class TestDestroyRequestPayload(testtools.TestCase):
    """
    Test suite for the Destroy request payload.
    """

    def setUp(self):
        super(TestDestroyRequestPayload, self).setUp()

        self.uuid = attributes.UniqueIdentifier(
            "668eff89-3010-4258-bc0e-8c402309c746"
        )

        self.full_encoding = utils.BytearrayStream(
            b"\x42\x00\x79\x01\x00\x00\x00\x30"
            b"\x42\x00\x94\x07\x00\x00\x00\x24"
            b"\x36\x36\x38\x65\x66\x66\x38\x39\x2D\x33\x30\x31\x30\x2D\x34\x32"
            b"\x35\x38\x2D\x62\x63\x30\x65\x2D\x38\x63\x34\x30\x32\x33\x30\x39"
            b"\x63\x37\x34\x36\x00\x00\x00\x00"
        )

        self.empty_encoding = utils.BytearrayStream(
            b"\x42\x00\x79\x01\x00\x00\x00\x00"
        )

    def tearDown(self):
        super(TestDestroyRequestPayload, self).tearDown()

    def test_init(self):
        """
        Test that a Destroy request payload can be constructed with no
        arguments.
        """
        payload = payloads.DestroyRequestPayload()
        self.assertIsNone(payload.unique_identifier)

    def test_init_with_args(self):
        """
        Test that a Destroy request payload can be constructed with valid
        values.
        """
        payload = payloads.DestroyRequestPayload(unique_identifier=self.uuid)
        self.assertEqual(self.uuid, payload.unique_identifier)

    def test_read_valid(self):
        """
        Test that a Destroy request payload can be read from a valid byte
        stream.
        """
        payload = payloads.DestroyRequestPayload()
        payload.read(utils.BytearrayStream(self.full_encoding.buffer))

        self.assertEqual(self.uuid.value, payload.unique_identifier.value)

    def test_read_missing_required_field(self):
        """
        Test that an exception is raised when reading a Destroy request
        payload missing the unique identifier.
        """
        payload = payloads.DestroyRequestPayload()
        self.assertRaises(
            exceptions.InvalidKmipEncoding,
            payload.read,
            utils.BytearrayStream(self.empty_encoding.buffer),
        )

    def test_write_valid(self):
        """
        Test that a Destroy request payload can be written to a byte stream.
        """
        payload = payloads.DestroyRequestPayload(unique_identifier=self.uuid)
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(self.full_encoding, stream)

    def test_read_write_roundtrip(self):
        """
        Test that a Destroy request payload can be read and written without
        changing the encoded bytes.
        """
        payload = payloads.DestroyRequestPayload()
        payload.read(utils.BytearrayStream(self.full_encoding.buffer))

        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(self.full_encoding, stream)

    def test_validate_invalid(self):
        """
        Test that a TypeError is raised when the unique identifier type is
        invalid.
        """
        self.assertRaisesRegex(
            TypeError,
            "invalid unique identifier",
            payloads.DestroyRequestPayload,
            "not-a-uuid",
        )

    def test_eq(self):
        """
        Test that two Destroy request payloads with the same data are equal.
        """
        a = payloads.DestroyRequestPayload(unique_identifier=self.uuid)
        b = payloads.DestroyRequestPayload(unique_identifier=self.uuid)

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_ne(self):
        """
        Test that two Destroy request payloads with different data are not
        equal.
        """
        a = payloads.DestroyRequestPayload(unique_identifier=self.uuid)
        b = payloads.DestroyRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(
                "11111111-2222-3333-4444-555555555555"
            )
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test the repr output for a Destroy request payload.
        """
        payload = payloads.DestroyRequestPayload()
        self.assertIsInstance(repr(payload), str)

    def test_str(self):
        """
        Test the str output for a Destroy request payload.
        """
        payload = payloads.DestroyRequestPayload()
        self.assertIsInstance(str(payload), str)


class TestDestroyResponsePayload(testtools.TestCase):
    """
    Test suite for the Destroy response payload.
    """

    def setUp(self):
        super(TestDestroyResponsePayload, self).setUp()

        self.uuid = attributes.UniqueIdentifier(
            "668eff89-3010-4258-bc0e-8c402309c746"
        )

        self.full_encoding = utils.BytearrayStream(
            b"\x42\x00\x7C\x01\x00\x00\x00\x30"
            b"\x42\x00\x94\x07\x00\x00\x00\x24"
            b"\x36\x36\x38\x65\x66\x66\x38\x39\x2D\x33\x30\x31\x30\x2D\x34\x32"
            b"\x35\x38\x2D\x62\x63\x30\x65\x2D\x38\x63\x34\x30\x32\x33\x30\x39"
            b"\x63\x37\x34\x36\x00\x00\x00\x00"
        )

        self.empty_encoding = utils.BytearrayStream(
            b"\x42\x00\x7C\x01\x00\x00\x00\x00"
        )

    def tearDown(self):
        super(TestDestroyResponsePayload, self).tearDown()

    def test_init(self):
        """
        Test that a Destroy response payload can be constructed with no
        arguments.
        """
        payload = payloads.DestroyResponsePayload()
        self.assertIsNone(payload.unique_identifier)

    def test_init_with_args(self):
        """
        Test that a Destroy response payload can be constructed with valid
        values.
        """
        payload = payloads.DestroyResponsePayload(unique_identifier=self.uuid)
        self.assertEqual(self.uuid, payload.unique_identifier)

    def test_read_valid(self):
        """
        Test that a Destroy response payload can be read from a valid byte
        stream.
        """
        payload = payloads.DestroyResponsePayload()
        payload.read(utils.BytearrayStream(self.full_encoding.buffer))

        self.assertEqual(self.uuid.value, payload.unique_identifier.value)

    def test_read_missing_required_field(self):
        """
        Test that an exception is raised when reading a Destroy response
        payload missing the unique identifier.
        """
        payload = payloads.DestroyResponsePayload()
        self.assertRaises(
            exceptions.InvalidKmipEncoding,
            payload.read,
            utils.BytearrayStream(self.empty_encoding.buffer),
        )

    def test_write_valid(self):
        """
        Test that a Destroy response payload can be written to a byte stream.
        """
        payload = payloads.DestroyResponsePayload(unique_identifier=self.uuid)
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(self.full_encoding, stream)

    def test_read_write_roundtrip(self):
        """
        Test that a Destroy response payload can be read and written without
        changing the encoded bytes.
        """
        payload = payloads.DestroyResponsePayload()
        payload.read(utils.BytearrayStream(self.full_encoding.buffer))

        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(self.full_encoding, stream)

    def test_validate_invalid(self):
        """
        Test that a TypeError is raised when the unique identifier type is
        invalid.
        """
        self.assertRaisesRegex(
            TypeError,
            "invalid unique identifier",
            payloads.DestroyResponsePayload,
            "not-a-uuid",
        )

    def test_eq(self):
        """
        Test that two Destroy response payloads with the same data are equal.
        """
        a = payloads.DestroyResponsePayload(unique_identifier=self.uuid)
        b = payloads.DestroyResponsePayload(unique_identifier=self.uuid)

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_ne(self):
        """
        Test that two Destroy response payloads with different data are not
        equal.
        """
        a = payloads.DestroyResponsePayload(unique_identifier=self.uuid)
        b = payloads.DestroyResponsePayload(
            unique_identifier=attributes.UniqueIdentifier(
                "11111111-2222-3333-4444-555555555555"
            )
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test the repr output for a Destroy response payload.
        """
        payload = payloads.DestroyResponsePayload()
        self.assertIsInstance(repr(payload), str)

    def test_str(self):
        """
        Test the str output for a Destroy response payload.
        """
        payload = payloads.DestroyResponsePayload()
        self.assertIsInstance(str(payload), str)
