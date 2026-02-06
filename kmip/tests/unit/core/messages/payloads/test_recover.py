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

class TestRecoverRequestPayload(testtools.TestCase):
    """
    Test suite for the Recover request payload.
    """

    def setUp(self):
        super(TestRecoverRequestPayload, self).setUp()

        # Encoding obtained from the KMIP 1.1 testing document, Section 10.1.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Unique Identifier - f613dba1-b557-489a-87c5-3c0ecd4294e3

        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x30'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x66\x36\x31\x33\x64\x62\x61\x31\x2D\x62\x35\x35\x37\x2D\x34\x38'
            b'\x39\x61\x2D\x38\x37\x63\x35\x2D\x33\x63\x30\x65\x63\x64\x34\x32'
            b'\x39\x34\x65\x33\x00\x00\x00\x00'
        )

        self.empty_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestRecoverRequestPayload, self).tearDown()

    def test_init(self):
        """
        Test that a Recover request payload can be constructed with no
        arguments.
        """
        payload = payloads.RecoverRequestPayload()

        self.assertEqual(None, payload.unique_identifier)

    def test_init_with_args(self):
        """
        Test that a Recover request payload can be constructed with valid
        values.
        """
        payload = payloads.RecoverRequestPayload(
            unique_identifier='00000000-1111-2222-3333-444444444444'
        )

        self.assertEqual(
            '00000000-1111-2222-3333-444444444444',
            payload.unique_identifier
        )

    def test_invalid_unique_identifier(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the unique identifier of a Recover request payload.
        """
        kwargs = {'unique_identifier': 0}
        self.assertRaisesRegex(
            TypeError,
            "Unique identifier must be a string.",
            payloads.RecoverRequestPayload,
            **kwargs
        )

        payload = payloads.RecoverRequestPayload()
        args = (payload, 'unique_identifier', 0)
        self.assertRaisesRegex(
            TypeError,
            "Unique identifier must be a string.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a Recover request payload can be read from a data stream.
        """
        payload = payloads.RecoverRequestPayload()

        self.assertEqual(None, payload.unique_identifier)

        payload.read(self.full_encoding)

        self.assertEqual(
            'f613dba1-b557-489a-87c5-3c0ecd4294e3',
            payload.unique_identifier
        )

    def test_read_empty(self):
        """
        Test that a Recover request payload can be read from an empty data
        stream.
        """
        payload = payloads.RecoverRequestPayload()

        self.assertEqual(None, payload.unique_identifier)

        payload.read(self.empty_encoding)

        self.assertEqual(None, payload.unique_identifier)

    def test_write(self):
        """
        Test that a Recover request payload can be written to a data stream.
        """
        payload = payloads.RecoverRequestPayload(
            unique_identifier='f613dba1-b557-489a-87c5-3c0ecd4294e3'
        )
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_empty(self):
        """
        Test that an empty Recover request payload can be written
        to a data stream.
        """
        payload = payloads.RecoverRequestPayload()
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.empty_encoding), len(stream))
        self.assertEqual(str(self.empty_encoding), str(stream))

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        Recover request payloads with the same data.
        """
        a = payloads.RecoverRequestPayload()
        b = payloads.RecoverRequestPayload()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = payloads.RecoverRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038'
        )
        b = payloads.RecoverRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038'
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_unique_identifier(self):
        """
        Test that the equality operator returns False when comparing two
        Recover request payloads with different unique identifiers.
        """
        a = payloads.RecoverRequestPayload(
            unique_identifier='a'
        )
        b = payloads.RecoverRequestPayload(
            unique_identifier='b'
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        Recover request payloads with different types.
        """
        a = payloads.RecoverRequestPayload()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        Recover request payloads with the same data.
        """
        a = payloads.RecoverRequestPayload()
        b = payloads.RecoverRequestPayload()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = payloads.RecoverRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038'
        )
        b = payloads.RecoverRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038'
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_unique_identifier(self):
        """
        Test that the inequality operator returns True when comparing two
        Recover request payloads with different unique identifiers.
        """
        a = payloads.RecoverRequestPayload(
            unique_identifier='a'
        )
        b = payloads.RecoverRequestPayload(
            unique_identifier='b'
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        Recover request payloads with different types.
        """
        a = payloads.RecoverRequestPayload()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test that repr can be applied to a Recover request payload.
        """
        payload = payloads.RecoverRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038'
        )
        expected = (
            "RecoverRequestPayload("
            "unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038')"
        )
        observed = repr(payload)

        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a Recover request payload.
        """
        payload = payloads.RecoverRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038'
        )

        expected = str({
            'unique_identifier': '49a1ca88-6bea-4fb2-b450-7e58802c3038'
        })
        observed = str(payload)

        self.assertEqual(expected, observed)

class TestRecoverResponsePayload(testtools.TestCase):
    """
    Test suite for the Recover response payload.
    """

    def setUp(self):
        super(TestRecoverResponsePayload, self).setUp()

        # Encoding obtained from the KMIP 1.1 testing document, Section 10.1.
        #
        # This encoding matches the following set of values:
        # Response Payload
        #     Unique Identifier - f613dba1-b557-489a-87c5-3c0ecd4294e3

        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x30'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x66\x36\x31\x33\x64\x62\x61\x31\x2D\x62\x35\x35\x37\x2D\x34\x38'
            b'\x39\x61\x2D\x38\x37\x63\x35\x2D\x33\x63\x30\x65\x63\x64\x34\x32'
            b'\x39\x34\x65\x33\x00\x00\x00\x00'
        )

        self.empty_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestRecoverResponsePayload, self).tearDown()

    def test_init(self):
        """
        Test that a Recover response payload can be constructed with no
        arguments.
        """
        payload = payloads.RecoverResponsePayload()

        self.assertEqual(None, payload.unique_identifier)

    def test_init_with_args(self):
        """
        Test that a Recover response payload can be constructed with valid
        values.
        """
        payload = payloads.RecoverResponsePayload(
            unique_identifier='00000000-1111-2222-3333-444444444444'
        )

        self.assertEqual(
            '00000000-1111-2222-3333-444444444444',
            payload.unique_identifier
        )

    def test_invalid_unique_identifier(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the unique identifier of a Recover response payload.
        """
        kwargs = {'unique_identifier': 0}
        self.assertRaisesRegex(
            TypeError,
            "Unique identifier must be a string.",
            payloads.RecoverResponsePayload,
            **kwargs
        )

        payload = payloads.RecoverResponsePayload()
        args = (payload, 'unique_identifier', 0)
        self.assertRaisesRegex(
            TypeError,
            "Unique identifier must be a string.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a Recover response payload can be read from a data stream.
        """
        payload = payloads.RecoverResponsePayload()

        self.assertEqual(None, payload.unique_identifier)

        payload.read(self.full_encoding)

        self.assertEqual(
            'f613dba1-b557-489a-87c5-3c0ecd4294e3',
            payload.unique_identifier
        )

    def test_read_empty(self):
        """
        Test that a Recover response payload can be read from an empty data
        stream.
        """
        payload = payloads.RecoverResponsePayload()

        self.assertEqual(None, payload.unique_identifier)

        payload.read(self.empty_encoding)

        self.assertEqual(None, payload.unique_identifier)

    def test_write(self):
        """
        Test that a Recover response payload can be written to a data stream.
        """
        payload = payloads.RecoverResponsePayload(
            unique_identifier='f613dba1-b557-489a-87c5-3c0ecd4294e3'
        )
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_empty(self):
        """
        Test that an empty Recover response payload can be written to a data
        stream.
        """
        payload = payloads.RecoverResponsePayload()
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.empty_encoding), len(stream))
        self.assertEqual(str(self.empty_encoding), str(stream))

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        Recover response payloads with the same data.
        """
        a = payloads.RecoverResponsePayload()
        b = payloads.RecoverResponsePayload()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = payloads.RecoverResponsePayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038'
        )
        b = payloads.RecoverResponsePayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038'
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_unique_identifier(self):
        """
        Test that the equality operator returns False when comparing two
        Recover response payloads with different unique identifiers.
        """
        a = payloads.RecoverResponsePayload(
            unique_identifier='a'
        )
        b = payloads.RecoverResponsePayload(
            unique_identifier='b'
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        Recover response payloads with different types.
        """
        a = payloads.RecoverResponsePayload()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        Recover response payloads with the same data.
        """
        a = payloads.RecoverResponsePayload()
        b = payloads.RecoverResponsePayload()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = payloads.RecoverResponsePayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038'
        )
        b = payloads.RecoverResponsePayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038'
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_unique_identifier(self):
        """
        Test that the inequality operator returns True when comparing two
        Recover response payloads with different unique identifiers.
        """
        a = payloads.RecoverResponsePayload(
            unique_identifier='a'
        )
        b = payloads.RecoverResponsePayload(
            unique_identifier='b'
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        Recover response payloads with different types.
        """
        a = payloads.RecoverResponsePayload()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test that repr can be applied to a Recover response payload.
        """
        payload = payloads.RecoverResponsePayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038'
        )
        expected = (
            "RecoverResponsePayload("
            "unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038')"
        )
        observed = repr(payload)

        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a Recover response payload
        """
        payload = payloads.RecoverResponsePayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038'
        )

        expected = str({
            'unique_identifier': '49a1ca88-6bea-4fb2-b450-7e58802c3038'
        })
        observed = str(payload)

        self.assertEqual(expected, observed)
