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

from kmip.core import utils
from kmip.core import attributes

from kmip.core.messages import payloads


class TestActivateRequestPayload(TestCase):
    """
    Test suite for the ActivateRequestPayload class.

    Test encodings obtained from Sections 4.2 of the KMIP 1.1 Test
    Cases documentation.
    """

    def setUp(self):
        super(TestActivateRequestPayload, self).setUp()

        self.uuid = attributes.UniqueIdentifier(
            '668eff89-3010-4258-bc0e-8c402309c746')

        self.encoding_a = utils.BytearrayStream((
            b'\x42\x00\x79\x01\x00\x00\x00\x30\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x36\x36\x38\x65\x66\x66\x38\x39\x2D\x33\x30\x31\x30\x2D\x34\x32'
            b'\x35\x38\x2D\x62\x63\x30\x65\x2D\x38\x63\x34\x30\x32\x33\x30\x39'
            b'\x63\x37\x34\x36\x00\x00\x00\x00'))

    def tearDown(self):
        super(TestActivateRequestPayload, self).tearDown()

    def test_init_with_none(self):
        """
        Test that a ActivateRequestPayload object can be constructed with no
        specified value.
        """
        payloads.ActivateRequestPayload()

    def test_init_with_args(self):
        """
        Test that a ActivateRequestPayload object can be constructed with valid
        values.
        """
        payloads.ActivateRequestPayload(unique_identifier=self.uuid)

    def test_validate_with_bad_uuid_type(self):
        """
        Test that a TypeError exception is raised when an invalid UUID type
        is used to construct a ActivateRequestPayload object.
        """
        self.assertRaisesRegexp(
            TypeError, "invalid unique identifier",
            payloads.ActivateRequestPayload, "not-a-uuid")

    def test_read_with_known_uuid(self):
        """
        Test that a ActivateRequestPayload object with known UUID can be read
        from a data stream.
        """
        payload = payloads.ActivateRequestPayload()
        payload.read(self.encoding_a)
        expected = '668eff89-3010-4258-bc0e-8c402309c746'
        observed = payload.unique_identifier.value

        msg = "activate UUID value mismatch"
        msg += "; expected {0}, received {1}".format(
            expected, observed)
        self.assertEqual(expected, observed, msg)

    def test_write_with_known_uuid(self):
        """
        Test that a ActivateRequestPayload object with a known UUID can be
        written to a data stream.
        """
        stream = utils.BytearrayStream()
        payload = payloads.ActivateRequestPayload(self.uuid)
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


class TestActivateResponsePayload(TestCase):
    """
    Test encodings obtained from Sections 4.2 of the KMIP 1.1 Test
    Cases documentation.
    """

    def setUp(self):
        super(TestActivateResponsePayload, self).setUp()

        self.uuid = attributes.UniqueIdentifier(
            '668eff89-3010-4258-bc0e-8c402309c746')

        self.encoding_a = utils.BytearrayStream((
            b'\x42\x00\x7C\x01\x00\x00\x00\x30\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x36\x36\x38\x65\x66\x66\x38\x39\x2D\x33\x30\x31\x30\x2D\x34\x32'
            b'\x35\x38\x2D\x62\x63\x30\x65\x2D\x38\x63\x34\x30\x32\x33\x30\x39'
            b'\x63\x37\x34\x36\x00\x00\x00\x00'))

    def tearDown(self):
        super(TestActivateResponsePayload, self).tearDown()

    def test_init_with_none(self):
        """
        Test that a ActivateResponsePayload object can be constructed with no
        specified value.
        """
        payloads.ActivateResponsePayload()

    def test_init_with_args(self):
        """
        Test that a ActivateResponsePayload object can be constructed with
        valid values.
        """
        payloads.ActivateResponsePayload(unique_identifier=self.uuid)

    def test_validate_with_invalid_uuid(self):
        """
        Test that a TypeError exception is raised when an invalid Operations
        list is used to construct a ActivateResponsePayload object.
        """
        self.assertRaisesRegexp(
            TypeError, "invalid unique identifier",
            payloads.ActivateResponsePayload, "not-a-uuid")

    def test_read_with_known_uuid(self):
        """
        Test that a ActivateResponsePayload object with known UUID can be read
        from a data stream.
        """
        payload = payloads.ActivateResponsePayload()
        payload.read(self.encoding_a)
        expected = '668eff89-3010-4258-bc0e-8c402309c746'
        observed = payload.unique_identifier.value

        msg = "activate UUID value mismatch"
        msg += "; expected {0}, received {1}".format(
            expected, observed)
        self.assertEqual(expected, observed, msg)

    def test_write_with_known_uuid(self):
        """
        Test that a ActivateResponsePayload object with a known UUID can be
        written to a data stream.
        """
        stream = utils.BytearrayStream()
        payload = payloads.ActivateResponsePayload(self.uuid)
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
