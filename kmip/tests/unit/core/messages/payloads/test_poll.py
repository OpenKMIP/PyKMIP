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

class TestPollRequestPayload(testtools.TestCase):
    """
    Test suite for the Poll request payload.
    """

    def setUp(self):
        super(TestPollRequestPayload, self).setUp()

        # Encoding obtained from the KMIP 1.1 testing document, Section 10.1.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Asynchronous Correlation Value - 0xE7125DE85B3C90A6

        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x10'
            b'\x42\x00\x06\x08\x00\x00\x00\x08\xE7\x12\x5D\xE8\x5B\x3C\x90\xA6'
        )

        self.empty_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestPollRequestPayload, self).tearDown()

    def test_init(self):
        """
        Test that a Poll request payload can be constructed with no arguments.
        """
        payload = payloads.PollRequestPayload()

        self.assertEqual(None, payload.asynchronous_correlation_value)

    def test_init_with_args(self):
        """
        Test that an Poll request payload can be constructed with valid
        values.
        """
        payload = payloads.PollRequestPayload(
            asynchronous_correlation_value=b'\x01'
        )

        self.assertEqual(b'\x01', payload.asynchronous_correlation_value)

    def test_invalid_asynchronous_correlation_value(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the asynchronous correlation value of an Poll request payload.
        """
        kwargs = {'asynchronous_correlation_value': 0}
        self.assertRaisesRegex(
            TypeError,
            "Asynchronous correlation value must be bytes.",
            payloads.PollRequestPayload,
            **kwargs
        )

        payload = payloads.PollRequestPayload()
        args = (payload, 'asynchronous_correlation_value', 0)
        self.assertRaisesRegex(
            TypeError,
            "Asynchronous correlation value must be bytes.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a Poll request payload can be read from a data stream.
        """
        payload = payloads.PollRequestPayload()

        self.assertEqual(None, payload.asynchronous_correlation_value)

        payload.read(self.full_encoding)

        self.assertEqual(
            b'\xE7\x12\x5D\xE8\x5B\x3C\x90\xA6',
            payload.asynchronous_correlation_value
        )

    def test_read_empty(self):
        """
        Test that an Poll request payload can be read from an empty data
        stream.
        """
        payload = payloads.PollRequestPayload()

        self.assertEqual(None, payload.asynchronous_correlation_value)

        payload.read(self.empty_encoding)

        self.assertEqual(None, payload.asynchronous_correlation_value)

    def test_write(self):
        """
        Test that a Poll request payload can be written to a data stream.
        """
        payload = payloads.PollRequestPayload(
            asynchronous_correlation_value=b'\xE7\x12\x5D\xE8\x5B\x3C\x90\xA6'
        )
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_empty(self):
        """
        Test that an empty Poll request payload can be written to a data
        stream.
        """
        payload = payloads.PollRequestPayload()
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.empty_encoding), len(stream))
        self.assertEqual(str(self.empty_encoding), str(stream))

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two Poll
        request payloads with the same data.
        """
        a = payloads.PollRequestPayload()
        b = payloads.PollRequestPayload()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = payloads.PollRequestPayload(
            asynchronous_correlation_value=b'\x49\xa1\xca\x88'
        )
        b = payloads.PollRequestPayload(
            asynchronous_correlation_value=b'\x49\xa1\xca\x88'
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_asynchronous_correlation_value(self):
        """
        Test that the equality operator returns False when comparing two Poll
        request payloads with different asynchronous correlation values.
        """
        a = payloads.PollRequestPayload(
            asynchronous_correlation_value=b'\xaa'
        )
        b = payloads.PollRequestPayload(
            asynchronous_correlation_value=b'\xbb'
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two Poll
        request payloads with different types.
        """
        a = payloads.PollRequestPayload()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two Poll
        request payloads with the same data.
        """
        a = payloads.PollRequestPayload()
        b = payloads.PollRequestPayload()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = payloads.PollRequestPayload(
            asynchronous_correlation_value=b'\x49\xa1\xca\x88'
        )
        b = payloads.PollRequestPayload(
            asynchronous_correlation_value=b'\x49\xa1\xca\x88'
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_asynchronous_correlation_value(self):
        """
        Test that the inequality operator returns True when comparing two Poll
        request payloads with different asynchronous correlation values.
        """
        a = payloads.PollRequestPayload(
            asynchronous_correlation_value=b'\xaa'
        )
        b = payloads.PollRequestPayload(
            asynchronous_correlation_value=b'\xbb'
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two Poll
        request payloads with different types.
        """
        a = payloads.PollRequestPayload()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test that repr can be applied to a Poll request payload.
        """
        payload = payloads.PollRequestPayload(
            asynchronous_correlation_value=b'\xaa'
        )
        expected = (
            "PollRequestPayload("
            "asynchronous_correlation_value=" + str(b'\xaa') + ")"
        )
        observed = repr(payload)

        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a Poll request payload.
        """
        payload = payloads.PollRequestPayload(
            asynchronous_correlation_value=b'\xaa'
        )

        expected = str({
            'asynchronous_correlation_value': b'\xaa'
        })
        observed = str(payload)

        self.assertEqual(expected, observed)
