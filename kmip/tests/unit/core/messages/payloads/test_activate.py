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

import testtools

from kmip.core import utils
from kmip.core.messages import payloads


class TestActivateRequestPayload(testtools.TestCase):
    """
    Test suite for the Activate request payload class.
    """

    def setUp(self):
        super(TestActivateRequestPayload, self).setUp()

        # Encoding obtained from the KMIP 1.1 testing document, Section 4.1.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Unique Identifier - 668eff89-3010-4258-bc0e-8c402309c746

        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x30'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x36\x36\x38\x65\x66\x66\x38\x39\x2D\x33\x30\x31\x30\x2D\x34\x32'
            b'\x35\x38\x2D\x62\x63\x30\x65\x2D\x38\x63\x34\x30\x32\x33\x30\x39'
            b'\x63\x37\x34\x36\x00\x00\x00\x00'
        )

        self.empty_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestActivateRequestPayload, self).tearDown()

    def test_init(self):
        """
        Test that an Activate request payload can be constructed with no
        arguments.
        """
        payload = payloads.ActivateRequestPayload()

        self.assertEqual(None, payload.unique_identifier)

    def test_init_with_args(self):
        """
        Test that an Activate request payload can be constructed with valid
        values.
        """
        payload = payloads.ActivateRequestPayload(
            unique_identifier='00000000-2222-4444-6666-888888888888'
        )

        self.assertEqual(
            '00000000-2222-4444-6666-888888888888',
            payload.unique_identifier
        )

    def test_invalid_unique_identifier(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the unique identifier of an Activate request payload.
        """
        kwargs = {'unique_identifier': 0}
        self.assertRaisesRegexp(
            TypeError,
            "Unique identifier must be a string.",
            payloads.ActivateRequestPayload,
            **kwargs
        )

        args = (payloads.ActivateRequestPayload(), 'unique_identifier', 0)
        self.assertRaisesRegexp(
            TypeError,
            "Unique identifier must be a string.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that an Activate request payload struct can be read from a data
        stream.
        """
        payload = payloads.ActivateRequestPayload()

        self.assertEqual(None, payload.unique_identifier)

        payload.read(self.full_encoding)

        self.assertEqual(
            '668eff89-3010-4258-bc0e-8c402309c746',
            payload.unique_identifier
        )

    def test_read_empty(self):
        """
        Test that an Activate request payload struct can be read from an empty
        data stream.
        """
        payload = payloads.ActivateRequestPayload()

        self.assertEqual(None, payload.unique_identifier)

        payload.read(self.empty_encoding)

        self.assertEqual(None, payload.unique_identifier)

    def test_write(self):
        """
        Test that an Activate request payload struct can be written to a data
        stream.
        """
        payload = payloads.ActivateRequestPayload(
            unique_identifier='668eff89-3010-4258-bc0e-8c402309c746'
        )
        stream = utils.BytearrayStream()

        payload.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_empty(self):
        """
        Test that an empty Activate request payload struct can be written to a
        data stream.
        """
        payload = payloads.ActivateRequestPayload()
        stream = utils.BytearrayStream()

        payload.write(stream)

        self.assertEqual(len(self.empty_encoding), len(stream))
        self.assertEqual(str(self.empty_encoding), str(stream))

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        Activate request payload structs with the same data.
        """
        a = payloads.ActivateRequestPayload()
        b = payloads.ActivateRequestPayload()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = payloads.ActivateRequestPayload(
            unique_identifier='668eff89-3010-4258-bc0e-8c402309c746'
        )
        b = payloads.ActivateRequestPayload(
            unique_identifier='668eff89-3010-4258-bc0e-8c402309c746'
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_unique_identifier(self):
        """
        Test that the equality operator returns False when comparing two
        Activate request payload structs with different unique identifiers.
        """
        a = payloads.ActivateRequestPayload(
            unique_identifier='668eff89-3010-4258-bc0e-8c402309c746'
        )
        b = payloads.ActivateRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c303f'
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        Activate request payload structs with different types.
        """
        a = payloads.ActivateRequestPayload()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        Activate request payload structs with the same data.
        """
        a = payloads.ActivateRequestPayload()
        b = payloads.ActivateRequestPayload()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = payloads.ActivateRequestPayload(
            unique_identifier='668eff89-3010-4258-bc0e-8c402309c746'
        )
        b = payloads.ActivateRequestPayload(
            unique_identifier='668eff89-3010-4258-bc0e-8c402309c746'
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_unique_identifier(self):
        """
        Test that the inequality operator returns True when comparing two
        Activate request payload structs with different unique identifiers.
        """
        a = payloads.ActivateRequestPayload(
            unique_identifier='668eff89-3010-4258-bc0e-8c402309c746'
        )
        b = payloads.ActivateRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c303f'
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        Activate request payload structs with different types.
        """
        a = payloads.ActivateRequestPayload()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test that repr can be applied to an Activate request payload struct.
        """
        payload = payloads.ActivateRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038'
        )

        expected = (
            "ActivateRequestPayload("
            "unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038')"
        )
        observed = repr(payload)

        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to an Activate request payload struct.
        """
        payload = payloads.ActivateRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038'
        )

        expected = str({
            'unique_identifier': '49a1ca88-6bea-4fb2-b450-7e58802c3038'
        })
        observed = str(payload)

        self.assertEqual(expected, observed)


class TestActivateResponsePayload(testtools.TestCase):
    """
    Test suite for the Activate request payload class.
    """

    def setUp(self):
        super(TestActivateResponsePayload, self).setUp()

        # Encoding obtained from the KMIP 1.1 testing document, Section 4.1.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Unique Identifier - 668eff89-3010-4258-bc0e-8c402309c746

        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x30'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x36\x36\x38\x65\x66\x66\x38\x39\x2D\x33\x30\x31\x30\x2D\x34\x32'
            b'\x35\x38\x2D\x62\x63\x30\x65\x2D\x38\x63\x34\x30\x32\x33\x30\x39'
            b'\x63\x37\x34\x36\x00\x00\x00\x00'
        )

        self.empty_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestActivateResponsePayload, self).tearDown()

    def test_init(self):
        """
        Test that an Activate response payload can be constructed with no
        arguments.
        """
        payload = payloads.ActivateResponsePayload()

        self.assertEqual(None, payload.unique_identifier)

    def test_init_with_args(self):
        """
        Test that an Activate response payload can be constructed with valid
        values.
        """
        payload = payloads.ActivateResponsePayload(
            unique_identifier='00000000-2222-4444-6666-888888888888'
        )

        self.assertEqual(
            '00000000-2222-4444-6666-888888888888',
            payload.unique_identifier
        )

    def test_invalid_unique_identifier(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the unique identifier of an Activate response payload.
        """
        kwargs = {'unique_identifier': 0}
        self.assertRaisesRegexp(
            TypeError,
            "Unique identifier must be a string.",
            payloads.ActivateResponsePayload,
            **kwargs
        )

        args = (payloads.ActivateResponsePayload(), 'unique_identifier', 0)
        self.assertRaisesRegexp(
            TypeError,
            "Unique identifier must be a string.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that an Activate response payload struct can be read from a data
        stream.
        """
        payload = payloads.ActivateResponsePayload()

        self.assertEqual(None, payload.unique_identifier)

        payload.read(self.full_encoding)

        self.assertEqual(
            '668eff89-3010-4258-bc0e-8c402309c746',
            payload.unique_identifier
        )

    def test_read_missing_unique_identifier(self):
        """
        Test that a ValueError gets raised when a required Activate request
        payload field is missing when decoding the struct.
        """
        payload = payloads.ActivateResponsePayload()
        args = (self.empty_encoding, )
        self.assertRaisesRegexp(
            ValueError,
            "Parsed payload encoding is missing the unique identifier field.",
            payload.read,
            *args
        )

    def test_write(self):
        """
        Test that an Activate response payload struct can be written to a data
        stream.
        """
        payload = payloads.ActivateResponsePayload(
            unique_identifier='668eff89-3010-4258-bc0e-8c402309c746'
        )
        stream = utils.BytearrayStream()

        payload.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_missing_unique_identifier(self):
        """
        Test that a ValueError gets raised when a required Activate response
        payload field is missing when encoding the struct.
        """
        payload = payloads.ActivateResponsePayload()
        stream = utils.BytearrayStream()
        args = (stream, )
        self.assertRaisesRegexp(
            ValueError,
            "Payload is missing the unique identifier field.",
            payload.write,
            *args
        )

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        Activate response payload structs with the same data.
        """
        a = payloads.ActivateResponsePayload()
        b = payloads.ActivateResponsePayload()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = payloads.ActivateResponsePayload(
            unique_identifier='668eff89-3010-4258-bc0e-8c402309c746'
        )
        b = payloads.ActivateResponsePayload(
            unique_identifier='668eff89-3010-4258-bc0e-8c402309c746'
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_unique_identifier(self):
        """
        Test that the equality operator returns False when comparing two
        Activate response payload structs with different unique identifiers.
        """
        a = payloads.ActivateResponsePayload(
            unique_identifier='668eff89-3010-4258-bc0e-8c402309c746'
        )
        b = payloads.ActivateResponsePayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c303f'
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        Activate response payload structs with different types.
        """
        a = payloads.ActivateResponsePayload()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        Activate response payload structs with the same data.
        """
        a = payloads.ActivateResponsePayload()
        b = payloads.ActivateResponsePayload()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = payloads.ActivateResponsePayload(
            unique_identifier='668eff89-3010-4258-bc0e-8c402309c746'
        )
        b = payloads.ActivateResponsePayload(
            unique_identifier='668eff89-3010-4258-bc0e-8c402309c746'
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_unique_identifier(self):
        """
        Test that the inequality operator returns True when comparing two
        Activate response payload structs with different unique identifiers.
        """
        a = payloads.ActivateResponsePayload(
            unique_identifier='668eff89-3010-4258-bc0e-8c402309c746'
        )
        b = payloads.ActivateResponsePayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c303f'
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        Activate response payload structs with different types.
        """
        a = payloads.ActivateResponsePayload()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test that repr can be applied to an Activate response payload struct.
        """
        payload = payloads.ActivateResponsePayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038'
        )

        expected = (
            "ActivateResponsePayload("
            "unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038')"
        )
        observed = repr(payload)

        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to an Activate response payload struct.
        """
        payload = payloads.ActivateResponsePayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038'
        )

        expected = str({
            'unique_identifier': '49a1ca88-6bea-4fb2-b450-7e58802c3038'
        })
        observed = str(payload)

        self.assertEqual(expected, observed)
