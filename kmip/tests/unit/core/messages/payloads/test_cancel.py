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

from kmip import enums
from kmip.core import utils
from kmip.core.messages import payloads

class TestCancelRequestPayload(testtools.TestCase):
    """
    Test suite for the Cancel request payload.
    """

    def setUp(self):
        super(TestCancelRequestPayload, self).setUp()

        # Encoding obtained from the KMIP 1.1 testing document, Section 10.1.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Asynchronous Correlation Value - 0x583B0036C1A2DD01

        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x10'
            b'\x42\x00\x06\x08\x00\x00\x00\x08\x58\x3B\x00\x36\xC1\xA2\xDD\x01'
        )

        self.empty_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestCancelRequestPayload, self).tearDown()

    def test_init(self):
        """
        Test that a Cancel request payload can be constructed with no
        arguments.
        """
        payload = payloads.CancelRequestPayload()

        self.assertEqual(None, payload.asynchronous_correlation_value)

    def test_init_with_args(self):
        """
        Test that a Cancel request payload can be constructed with valid
        values.
        """
        payload = payloads.CancelRequestPayload(
            asynchronous_correlation_value=b'\x01'
        )

        self.assertEqual(b'\x01', payload.asynchronous_correlation_value)

    def test_invalid_asynchronous_correlation_value(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the asynchronous correlation value of an Cancel request payload.
        """
        kwargs = {'asynchronous_correlation_value': 0}
        self.assertRaisesRegex(
            TypeError,
            "Asynchronous correlation value must be bytes.",
            payloads.CancelRequestPayload,
            **kwargs
        )

        payload = payloads.CancelRequestPayload()
        args = (payload, 'asynchronous_correlation_value', 0)
        self.assertRaisesRegex(
            TypeError,
            "Asynchronous correlation value must be bytes.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a Cancel request payload can be read from a data stream.
        """
        payload = payloads.CancelRequestPayload()

        self.assertEqual(None, payload.asynchronous_correlation_value)

        payload.read(self.full_encoding)

        self.assertEqual(
            b'\x58\x3B\x00\x36\xC1\xA2\xDD\x01',
            payload.asynchronous_correlation_value
        )

    def test_read_empty(self):
        """
        Test that an Cancel request payload can be read from an empty data
        stream.
        """
        payload = payloads.CancelRequestPayload()

        self.assertEqual(None, payload.asynchronous_correlation_value)

        payload.read(self.empty_encoding)

        self.assertEqual(None, payload.asynchronous_correlation_value)

    def test_write(self):
        """
        Test that a Cancel request payload can be written to a data stream.
        """
        payload = payloads.CancelRequestPayload(
            asynchronous_correlation_value=b'\x58\x3B\x00\x36\xC1\xA2\xDD\x01'
        )
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_empty(self):
        """
        Test that an empty Cancel request payload can be written to a data
        stream.
        """
        payload = payloads.CancelRequestPayload()
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.empty_encoding), len(stream))
        self.assertEqual(str(self.empty_encoding), str(stream))

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two Cancel
        request payloads with the same data.
        """
        a = payloads.CancelRequestPayload()
        b = payloads.CancelRequestPayload()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = payloads.CancelRequestPayload(
            asynchronous_correlation_value=b'\x49\xa1\xca\x88'
        )
        b = payloads.CancelRequestPayload(
            asynchronous_correlation_value=b'\x49\xa1\xca\x88'
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_asynchronous_correlation_value(self):
        """
        Test that the equality operator returns False when comparing two Cancel
        request payloads with different asynchronous correlation values.
        """
        a = payloads.CancelRequestPayload(
            asynchronous_correlation_value=b'\xaa'
        )
        b = payloads.CancelRequestPayload(
            asynchronous_correlation_value=b'\xbb'
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two Cancel
        request payloads with different types.
        """
        a = payloads.CancelRequestPayload()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        Cancel request payloads with the same data.
        """
        a = payloads.CancelRequestPayload()
        b = payloads.CancelRequestPayload()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = payloads.CancelRequestPayload(
            asynchronous_correlation_value=b'\x49\xa1\xca\x88'
        )
        b = payloads.CancelRequestPayload(
            asynchronous_correlation_value=b'\x49\xa1\xca\x88'
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_asynchronous_correlation_value(self):
        """
        Test that the inequality operator returns True when comparing two
        Cancel request payloads with different asynchronous correlation values.
        """
        a = payloads.CancelRequestPayload(
            asynchronous_correlation_value=b'\xaa'
        )
        b = payloads.CancelRequestPayload(
            asynchronous_correlation_value=b'\xbb'
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        Cancel request payloads with different types.
        """
        a = payloads.CancelRequestPayload()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test that repr can be applied to a Cancel request payload.
        """
        payload = payloads.CancelRequestPayload(
            asynchronous_correlation_value=b'\xaa'
        )
        expected = (
            "CancelRequestPayload("
            "asynchronous_correlation_value=" + str(b'\xaa') + ")"
        )
        observed = repr(payload)

        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a Cancel request payload.
        """
        payload = payloads.CancelRequestPayload(
            asynchronous_correlation_value=b'\xaa'
        )

        expected = str({
            'asynchronous_correlation_value': b'\xaa'
        })
        observed = str(payload)

        self.assertEqual(expected, observed)

class TestCancelResponsePayload(testtools.TestCase):
    """
    Test suite for the Cancel response payload.
    """

    def setUp(self):
        super(TestCancelResponsePayload, self).setUp()

        # Encoding obtained from the KMIP 1.1 testing document, Section 10.1.
        #
        # This encoding matches the following set of values:
        # Response Payload
        #     Asynchronous Correlation Value - 0x583B0036C1A2DD01
        #     Cancellation Result - 1 (Canceled)

        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x20'
            b'\x42\x00\x06\x08\x00\x00\x00\x08\x58\x3B\x00\x36\xC1\xA2\xDD\x01'
            b'\x42\x00\x12\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
        )

        self.empty_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestCancelResponsePayload, self).tearDown()

    def test_init(self):
        """
        Test that a Cancel response payload can be constructed with no
        arguments.
        """
        payload = payloads.CancelRequestPayload()

        self.assertEqual(None, payload.asynchronous_correlation_value)

    def test_init_with_args(self):
        """
        Test that a Cancel response payload can be constructed with valid
        values.
        """
        payload = payloads.CancelResponsePayload(
            asynchronous_correlation_value=b'\x01',
            cancellation_result=enums.CancellationResult.FAILED
        )

        self.assertEqual(b'\x01', payload.asynchronous_correlation_value)
        self.assertEqual(
            enums.CancellationResult.FAILED,
            payload.cancellation_result
        )

    def test_invalid_asynchronous_correlation_value(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the asynchronous correlation value of an Cancel response payload.
        """
        kwargs = {'asynchronous_correlation_value': 0}
        self.assertRaisesRegex(
            TypeError,
            "Asynchronous correlation value must be bytes.",
            payloads.CancelResponsePayload,
            **kwargs
        )

        payload = payloads.CancelResponsePayload()
        args = (payload, 'asynchronous_correlation_value', 0)
        self.assertRaisesRegex(
            TypeError,
            "Asynchronous correlation value must be bytes.",
            setattr,
            *args
        )

    def test_invalid_cancellation_result(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the cancellation result of an Cancel response payload.
        """
        kwargs = {'cancellation_result': 'invalid'}
        self.assertRaisesRegex(
            TypeError,
            "Cancellation result must be a CancellationResult enumeration.",
            payloads.CancelResponsePayload,
            **kwargs
        )

        payload = payloads.CancelResponsePayload()
        args = (payload, 'cancellation_result', 'invalid')
        self.assertRaisesRegex(
            TypeError,
            "Cancellation result must be a CancellationResult enumeration.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a Cancel response payload can be read from a data stream.
        """
        payload = payloads.CancelResponsePayload()

        self.assertEqual(None, payload.asynchronous_correlation_value)
        self.assertEqual(None, payload.cancellation_result)

        payload.read(self.full_encoding)

        self.assertEqual(
            b'\x58\x3B\x00\x36\xC1\xA2\xDD\x01',
            payload.asynchronous_correlation_value
        )
        self.assertEqual(
            enums.CancellationResult.CANCELED,
            payload.cancellation_result
        )

    def test_read_empty(self):
        """
        Test that an Cancel response payload can be read from an empty data
        stream.
        """
        payload = payloads.CancelResponsePayload()

        self.assertEqual(None, payload.asynchronous_correlation_value)
        self.assertEqual(None, payload.cancellation_result)

        payload.read(self.empty_encoding)

        self.assertEqual(None, payload.asynchronous_correlation_value)
        self.assertEqual(None, payload.cancellation_result)

    def test_write(self):
        """
        Test that a Cancel response payload can be written to a data stream.
        """
        payload = payloads.CancelResponsePayload(
            asynchronous_correlation_value=b'\x58\x3B\x00\x36\xC1\xA2\xDD\x01',
            cancellation_result=enums.CancellationResult.CANCELED
        )
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_empty(self):
        """
        Test that an empty Cancel response payload can be written to a data
        stream.
        """
        payload = payloads.CancelResponsePayload()
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.empty_encoding), len(stream))
        self.assertEqual(str(self.empty_encoding), str(stream))

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two Cancel
        response payloads with the same data.
        """
        a = payloads.CancelResponsePayload()
        b = payloads.CancelResponsePayload()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = payloads.CancelResponsePayload(
            asynchronous_correlation_value=b'\x49\xa1\xca\x88',
            cancellation_result=enums.CancellationResult.COMPLETED
        )
        b = payloads.CancelResponsePayload(
            asynchronous_correlation_value=b'\x49\xa1\xca\x88',
            cancellation_result=enums.CancellationResult.COMPLETED
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_asynchronous_correlation_value(self):
        """
        Test that the equality operator returns False when comparing two Cancel
        response payloads with different asynchronous correlation values.
        """
        a = payloads.CancelResponsePayload(
            asynchronous_correlation_value=b'\xaa'
        )
        b = payloads.CancelResponsePayload(
            asynchronous_correlation_value=b'\xbb'
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_cancellation_result(self):
        """
        Test that the equality operator returns False when comparing two Cancel
        response payloads with different cancellation results.
        """
        a = payloads.CancelResponsePayload(
            cancellation_result=enums.CancellationResult.FAILED
        )
        b = payloads.CancelResponsePayload(
            cancellation_result=enums.CancellationResult.COMPLETED
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two Cancel
        response payloads with different types.
        """
        a = payloads.CancelResponsePayload()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        Cancel response payloads with the same data.
        """
        a = payloads.CancelResponsePayload()
        b = payloads.CancelResponsePayload()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = payloads.CancelResponsePayload(
            asynchronous_correlation_value=b'\x49\xa1\xca\x88',
            cancellation_result=enums.CancellationResult.COMPLETED
        )
        b = payloads.CancelResponsePayload(
            asynchronous_correlation_value=b'\x49\xa1\xca\x88',
            cancellation_result=enums.CancellationResult.COMPLETED
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_asynchronous_correlation_value(self):
        """
        Test that the inequality operator returns True when comparing two
        Cancel response payloads with different asynchronous correlation
        values.
        """
        a = payloads.CancelResponsePayload(
            asynchronous_correlation_value=b'\xaa'
        )
        b = payloads.CancelResponsePayload(
            asynchronous_correlation_value=b'\xbb'
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_cancellation_result(self):
        """
        Test that the inequality operator returns True when comparing two
        Cancel response payloads with different cancellation results.
        """
        a = payloads.CancelResponsePayload(
            cancellation_result=enums.CancellationResult.FAILED
        )
        b = payloads.CancelResponsePayload(
            cancellation_result=enums.CancellationResult.COMPLETED
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        Cancel response payloads with different types.
        """
        a = payloads.CancelResponsePayload()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test that repr can be applied to a Cancel response payload.
        """
        payload = payloads.CancelResponsePayload(
            asynchronous_correlation_value=b'\xaa',
            cancellation_result=enums.CancellationResult.UNABLE_TO_CANCEL
        )
        expected = (
            "CancelResponsePayload("
            "asynchronous_correlation_value=" + str(b'\xaa') + ", "
            "cancellation_result=" + str(
                enums.CancellationResult.UNABLE_TO_CANCEL
            ) + ")"
        )
        observed = repr(payload)

        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a Cancel response payload.
        """
        payload = payloads.CancelResponsePayload(
            asynchronous_correlation_value=b'\xaa',
            cancellation_result=enums.CancellationResult.UNAVAILABLE
        )

        expected = str({
            'asynchronous_correlation_value': b'\xaa',
            'cancellation_result': enums.CancellationResult.UNAVAILABLE
        })
        observed = str(payload)

        self.assertEqual(expected, observed)
