# Copyright (c) 2015 The Johns Hopkins University/Applied Physics Laboratory
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

from kmip.core import enums
from kmip.core import exceptions
from kmip.core import primitives
from kmip.core import utils

from kmip.core.messages import payloads

class TestGetAttributeListRequestPayload(testtools.TestCase):
    """
    Test suite for the GetAttributeList request payload.
    """

    def setUp(self):
        super(TestGetAttributeListRequestPayload, self).setUp()

        # Encodings taken from Sections 3.1.4 of the KMIP 1.1 testing
        # documentation.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Unique Identifier - b4faee10-aa2a-4446-8ad4-0881f3422959
        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x30'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x62\x34\x66\x61\x65\x65\x31\x30\x2D\x61\x61\x32\x61\x2D\x34\x34'
            b'\x34\x36\x2D\x38\x61\x64\x34\x2D\x30\x38\x38\x31\x66\x33\x34\x32'
            b'\x32\x39\x35\x39\x00\x00\x00\x00'
        )

        # This encoding matches the following set of values:
        # Request Payload
        self.empty_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x00'
        )

        self.unique_identifier = 'b4faee10-aa2a-4446-8ad4-0881f3422959'

    def tearDown(self):
        super(TestGetAttributeListRequestPayload, self).tearDown()

    def test_init(self):
        """
        Test that a GetAttributeList request payload can be constructed with
        no arguments.
        """
        payloads.GetAttributeListRequestPayload()

    def test_init_with_args(self):
        """
        Test that a GetAttributeList request payload can be constructed with a
        valid value.
        """
        payloads.GetAttributeListRequestPayload(
            'test-unique-identifier',
        )

    def test_unique_identifier(self):
        """
        Test that the unique_identifier attribute of a GetAttributeList
        request payload can be properly set and retrieved.
        """
        payload = payloads.GetAttributeListRequestPayload()

        self.assertIsNone(payload.unique_identifier)
        self.assertIsNone(payload._unique_identifier)

        payload.unique_identifier = 'test-unique-identifier'

        self.assertEqual('test-unique-identifier', payload.unique_identifier)
        self.assertEqual(
            primitives.TextString(
                value='test-unique-identifier',
                tag=enums.Tags.UNIQUE_IDENTIFIER
            ),
            payload._unique_identifier
        )

    def test_unique_identifier_with_invalid_value(self):
        """
        Test that a TypeError is raised when an invalid ID is used to set
        the unique_identifier attribute of a GetAttributeList request payload.
        """
        payload = payloads.GetAttributeListRequestPayload()
        args = (payload, 'unique_identifier', 0)
        self.assertRaisesRegex(
            TypeError,
            "Unique identifier must be a string.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a GetAttributeList request payload can be read from a data
        stream.
        """
        payload = payloads.GetAttributeListRequestPayload()

        self.assertEqual(None, payload._unique_identifier)

        payload.read(self.full_encoding)

        self.assertEqual(self.unique_identifier, payload.unique_identifier)
        self.assertEqual(
            primitives.TextString(
                value=self.unique_identifier,
                tag=enums.Tags.UNIQUE_IDENTIFIER
            ),
            payload._unique_identifier
        )

    def test_read_with_no_content(self):
        """
        Test that a GetAttributeList response payload with no ID or attribute
        names can be read from a data stream.
        """
        payload = payloads.GetAttributeListRequestPayload()

        self.assertEqual(None, payload._unique_identifier)

        payload.read(self.empty_encoding)

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload._unique_identifier)

    def test_write(self):
        """
        Test that a GetAttributeList request payload can be written to a data
        stream.
        """
        payload = payloads.GetAttributeListRequestPayload(
            self.unique_identifier
        )
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_with_no_content(self):
        """
        Test that a GetAttributeList request payload with no ID or attribute
        names can be written to a data stream.
        """
        payload = payloads.GetAttributeListRequestPayload()
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.empty_encoding), len(stream))
        self.assertEqual(str(self.empty_encoding), str(stream))

    def test_repr(self):
        """
        Test that repr can be applied to a GetAttributeList request payload.
        """
        payload = payloads.GetAttributeListRequestPayload(
            self.unique_identifier
        )
        unique_identifier = "unique_identifier={0}".format(
            payload.unique_identifier
        )
        expected = "GetAttributeListRequestPayload({0})".format(
            unique_identifier
        )
        observed = repr(payload)
        self.assertEqual(expected, observed)

    def test_repr_with_no_content(self):
        """
        Test that repr can be applied to a GetAttributeList request payload
        with no ID or attribute names.
        """
        payload = payloads.GetAttributeListRequestPayload(
            None
        )
        unique_identifier = "unique_identifier={0}".format(
            payload.unique_identifier
        )
        expected = "GetAttributeListRequestPayload({0})".format(
            unique_identifier
        )
        observed = repr(payload)
        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a GetAttributeList request payload.
        """
        payload = payloads.GetAttributeListRequestPayload(
            self.unique_identifier
        )
        expected = str({
            'unique_identifier': self.unique_identifier
        })
        observed = str(payload)
        self.assertEqual(expected, observed)

    def test_str_with_no_content(self):
        """
        Test that str can be applied to a GetAttributeList request payload
        with no ID or attribute names.
        """
        payload = payloads.GetAttributeListRequestPayload(
            None
        )
        expected = str({
            'unique_identifier': None
        })
        observed = str(payload)
        self.assertEqual(expected, observed)

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        GetAttributeList request payloads with the same data.
        """
        a = payloads.GetAttributeListRequestPayload(
            self.unique_identifier
        )
        b = payloads.GetAttributeListRequestPayload(
            self.unique_identifier
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_unique_identifier(self):
        """
        Test that the equality operator returns False when comparing two
        GetAttributeList request payloads with different IDs.
        """
        a = payloads.GetAttributeListRequestPayload(
            self.unique_identifier
        )
        b = payloads.GetAttributeListRequestPayload(
            'invalid'
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing a
        GetAttributeList request payload to a non-GetAttributeList request
        payload.
        """
        a = payloads.GetAttributeListRequestPayload(
            self.unique_identifier
        )
        b = "invalid"

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing
        two GetAttributeList request payloads with the same internal data.
        """
        a = payloads.GetAttributeListRequestPayload(
            self.unique_identifier
        )
        b = payloads.GetAttributeListRequestPayload(
            self.unique_identifier
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_unique_identifier(self):
        """
        Test that the inequality operator returns True when comparing two
        GetAttributeList request payloads with different IDs.
        """
        a = payloads.GetAttributeListRequestPayload(
            self.unique_identifier
        )
        b = payloads.GetAttributeListRequestPayload(
            'invalid'
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns True when comparing a
        GetAttributeList request payload to a non-GetAttributeList request
        payload.
        """
        a = payloads.GetAttributeListRequestPayload(
            self.unique_identifier
        )
        b = "invalid"

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_read_valid(self):
        """
        Test that a GetAttributeList request payload can be read from a valid
        byte stream.
        """
        self.test_read()

    def test_read_missing_required_field(self):
        """
        Test that an exception is raised when reading a payload missing a
        required field.
        """
        payload = payloads.GetAttributeListRequestPayload()
        self.assertRaises(Exception, payload.read, utils.BytearrayStream(b""))

    def test_write_valid(self):
        """
        Test that a GetAttributeList request payload can be written to a byte
        stream.
        """
        self.test_write()

    def test_read_write_roundtrip(self):
        """
        Test that a GetAttributeList request payload can be read and written
        without changing the encoded bytes.
        """
        payload = payloads.GetAttributeListRequestPayload()
        payload.read(utils.BytearrayStream(self.full_encoding.buffer))

        buffer = utils.BytearrayStream()
        payload.write(buffer)

        self.assertEqual(str(self.full_encoding), str(buffer))

    def test_validate_invalid(self):
        """
        Test that an exception is raised when a field has an invalid type.
        """
        self.test_unique_identifier_with_invalid_value()

    def test_eq(self):
        """
        Test that two GetAttributeList request payloads with the same data are
        equal.
        """
        self.test_equal_on_equal()

    def test_ne(self):
        """
        Test that two GetAttributeList request payloads with different data are
        not equal.
        """
        self.test_not_equal_on_not_equal_unique_identifier()

class TestGetAttributeListResponsePayload(testtools.TestCase):
    """
    Test suite for the GetAttributeList response payload.
    """

    def setUp(self):
        super(TestGetAttributeListResponsePayload, self).setUp()

        # Encodings taken from Sections 3.1.4 of the KMIP 1.1 testing
        # documentation.
        #
        # This encoding matches the following set of values:
        # Response Payload
        #     Unique Identifier - b4faee10-aa2a-4446-8ad4-0881f3422959
        #     Attribute Name - Cryptographic Length
        #     Attribute Name - Cryptographic Algorithm
        #     Attribute Name - State
        #     Attribute Name - Digest
        #     Attribute Name - Lease Time
        #     Attribute Name - Initial Date
        #     Attribute Name - Unique Identifier
        #     Attribute Name - Name
        #     Attribute Name - Cryptographic Usage Mask
        #     Attribute Name - Object Type
        #     Attribute Name - Contact Information
        #     Attribute Name - Last Change Date
        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x01\x60'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x62\x34\x66\x61\x65\x65\x31\x30\x2D\x61\x61\x32\x61\x2D\x34\x34'
            b'\x34\x36\x2D\x38\x61\x64\x34\x2D\x30\x38\x38\x31\x66\x33\x34\x32'
            b'\x32\x39\x35\x39\x00\x00\x00\x00'
            b'\x42\x00\x0A\x07\x00\x00\x00\x14'
            b'\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x4C\x65'
            b'\x6E\x67\x74\x68\x00\x00\x00\x00'
            b'\x42\x00\x0A\x07\x00\x00\x00\x17'
            b'\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x41\x6C'
            b'\x67\x6F\x72\x69\x74\x68\x6D\x00'
            b'\x42\x00\x0A\x07\x00\x00\x00\x05\x53\x74\x61\x74\x65\x00\x00\x00'
            b'\x42\x00\x0A\x07\x00\x00\x00\x06\x44\x69\x67\x65\x73\x74\x00\x00'
            b'\x42\x00\x0A\x07\x00\x00\x00\x0A'
            b'\x4C\x65\x61\x73\x65\x20\x54\x69\x6D\x65\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\x0A\x07\x00\x00\x00\x0C'
            b'\x49\x6E\x69\x74\x69\x61\x6C\x20\x44\x61\x74\x65\x00\x00\x00\x00'
            b'\x42\x00\x0A\x07\x00\x00\x00\x11'
            b'\x55\x6E\x69\x71\x75\x65\x20\x49\x64\x65\x6E\x74\x69\x66\x69\x65'
            b'\x72\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\x0A\x07\x00\x00\x00\x04\x4E\x61\x6D\x65\x00\x00\x00\x00'
            b'\x42\x00\x0A\x07\x00\x00\x00\x18'
            b'\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x55\x73'
            b'\x61\x67\x65\x20\x4D\x61\x73\x6B'
            b'\x42\x00\x0A\x07\x00\x00\x00\x0B'
            b'\x4F\x62\x6A\x65\x63\x74\x20\x54\x79\x70\x65\x00\x00\x00\x00\x00'
            b'\x42\x00\x0A\x07\x00\x00\x00\x13'
            b'\x43\x6F\x6E\x74\x61\x63\x74\x20\x49\x6E\x66\x6F\x72\x6D\x61\x74'
            b'\x69\x6F\x6E\x00\x00\x00\x00\x00'
            b'\x42\x00\x0A\x07\x00\x00\x00\x10'
            b'\x4C\x61\x73\x74\x20\x43\x68\x61\x6E\x67\x65\x20\x44\x61\x74\x65'
        )

        # Encodings taken from Sections 3.1.4 of the KMIP 1.1 testing
        # documentation.
        #
        # This encoding matches the following set of values:
        # Response Payload
        #     Attribute Name - Cryptographic Length
        #     Attribute Name - Cryptographic Algorithm
        #     Attribute Name - State
        #     Attribute Name - Digest
        #     Attribute Name - Lease Time
        #     Attribute Name - Initial Date
        #     Attribute Name - Unique Identifier
        #     Attribute Name - Name
        #     Attribute Name - Cryptographic Usage Mask
        #     Attribute Name - Object Type
        #     Attribute Name - Contact Information
        #     Attribute Name - Last Change Date
        self.encoding_sans_unique_identifier = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x01\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x14'
            b'\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x4C\x65'
            b'\x6E\x67\x74\x68\x00\x00\x00\x00'
            b'\x42\x00\x0A\x07\x00\x00\x00\x17'
            b'\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x41\x6C'
            b'\x67\x6F\x72\x69\x74\x68\x6D\x00'
            b'\x42\x00\x0A\x07\x00\x00\x00\x05\x53\x74\x61\x74\x65\x00\x00\x00'
            b'\x42\x00\x0A\x07\x00\x00\x00\x06\x44\x69\x67\x65\x73\x74\x00\x00'
            b'\x42\x00\x0A\x07\x00\x00\x00\x0A'
            b'\x4C\x65\x61\x73\x65\x20\x54\x69\x6D\x65\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\x0A\x07\x00\x00\x00\x0C'
            b'\x49\x6E\x69\x74\x69\x61\x6C\x20\x44\x61\x74\x65\x00\x00\x00\x00'
            b'\x42\x00\x0A\x07\x00\x00\x00\x11'
            b'\x55\x6E\x69\x71\x75\x65\x20\x49\x64\x65\x6E\x74\x69\x66\x69\x65'
            b'\x72\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\x0A\x07\x00\x00\x00\x04\x4E\x61\x6D\x65\x00\x00\x00\x00'
            b'\x42\x00\x0A\x07\x00\x00\x00\x18'
            b'\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x55\x73'
            b'\x61\x67\x65\x20\x4D\x61\x73\x6B'
            b'\x42\x00\x0A\x07\x00\x00\x00\x0B'
            b'\x4F\x62\x6A\x65\x63\x74\x20\x54\x79\x70\x65\x00\x00\x00\x00\x00'
            b'\x42\x00\x0A\x07\x00\x00\x00\x13'
            b'\x43\x6F\x6E\x74\x61\x63\x74\x20\x49\x6E\x66\x6F\x72\x6D\x61\x74'
            b'\x69\x6F\x6E\x00\x00\x00\x00\x00'
            b'\x42\x00\x0A\x07\x00\x00\x00\x10'
            b'\x4C\x61\x73\x74\x20\x43\x68\x61\x6E\x67\x65\x20\x44\x61\x74\x65'
        )

        # Encodings taken from Sections 3.1.4 of the KMIP 1.1 testing
        # documentation.
        #
        # This encoding matches the following set of values:
        # Response Payload
        #     Unique Identifier - b4faee10-aa2a-4446-8ad4-0881f3422959
        self.encoding_sans_attribute_names = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x30'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x62\x34\x66\x61\x65\x65\x31\x30\x2D\x61\x61\x32\x61\x2D\x34\x34'
            b'\x34\x36\x2D\x38\x61\x64\x34\x2D\x30\x38\x38\x31\x66\x33\x34\x32'
            b'\x32\x39\x35\x39\x00\x00\x00\x00'
        )

        # Encodings adapted from Sections 3.1.2 of the KMIP 1.1 testing
        # documentation. Manually converted to the KMIP 2.0 format.
        #
        # This encoding matches the following set of values:
        # Response Payload
        #     Unique Identifier - 1703250b-4d40-4de2-93a0-c494a1d4ae40
        #     Attribute Reference - Object Group
        #     Attribute Reference - Application Specific Information
        #     Attribute Reference - Contact Information
        self.full_encoding_with_reference_enums = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x60'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x31\x37\x30\x33\x32\x35\x30\x62\x2D\x34\x64\x34\x30\x2D\x34\x64'
            b'\x65\x32\x2D\x39\x33\x61\x30\x2D\x63\x34\x39\x34\x61\x31\x64\x34'
            b'\x61\x65\x34\x30\x00\x00\x00\x00'
            b'\x42\x01\x3B\x05\x00\x00\x00\x04\x00\x42\x00\x56\x00\x00\x00\x00'
            b'\x42\x01\x3B\x05\x00\x00\x00\x04\x00\x42\x00\x04\x00\x00\x00\x00'
            b'\x42\x01\x3B\x05\x00\x00\x00\x04\x00\x42\x00\x22\x00\x00\x00\x00'
        )

        # Encodings adapted from Sections 3.1.2 of the KMIP 1.1 testing
        # documentation. Manually converted to the KMIP 2.0 format.
        #
        # This encoding matches the following set of values:
        # Response Payload
        #     Unique Identifier - 1703250b-4d40-4de2-93a0-c494a1d4ae40
        #     Attribute Reference
        #         Vendor Identification -
        #         Attribute Name - Object Group
        #     Attribute Reference
        #         Vendor Identification -
        #         Attribute Name - Application Specific Information
        #     Attribute Reference
        #         Vendor Identification -
        #         Attribute Name - Contact Information
        self.full_encoding_with_reference_structs = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\xD0'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x31\x37\x30\x33\x32\x35\x30\x62\x2D\x34\x64\x34\x30\x2D\x34\x64'
            b'\x65\x32\x2D\x39\x33\x61\x30\x2D\x63\x34\x39\x34\x61\x31\x64\x34'
            b'\x61\x65\x34\x30\x00\x00\x00\x00'
            b'\x42\x01\x3B\x01\x00\x00\x00\x20'
            b'\x42\x00\x9D\x07\x00\x00\x00\x00'
            b'\x42\x00\x0A\x07\x00\x00\x00\x0C'
            b'\x4F\x62\x6A\x65\x63\x74\x20\x47\x72\x6F\x75\x70\x00\x00\x00\x00'
            b'\x42\x01\x3B\x01\x00\x00\x00\x30'
            b'\x42\x00\x9D\x07\x00\x00\x00\x00'
            b'\x42\x00\x0A\x07\x00\x00\x00\x20'
            b'\x41\x70\x70\x6C\x69\x63\x61\x74\x69\x6F\x6E\x20\x53\x70\x65\x63'
            b'\x69\x66\x69\x63\x20\x49\x6E\x66\x6F\x72\x6D\x61\x74\x69\x6F\x6E'
            b'\x42\x01\x3B\x01\x00\x00\x00\x28'
            b'\x42\x00\x9D\x07\x00\x00\x00\x00'
            b'\x42\x00\x0A\x07\x00\x00\x00\x13'
            b'\x43\x6F\x6E\x74\x61\x63\x74\x20\x49\x6E\x66\x6F\x72\x6D\x61\x74'
            b'\x69\x6F\x6E\x00\x00\x00\x00\x00'
        )

        # Encodings adapted from Sections 3.1.2 of the KMIP 1.1 testing
        # documentation. Manually converted to the KMIP 2.0 format.
        #
        # This encoding matches the following set of values:
        # Response Payload
        #     Unique Identifier - 1703250b-4d40-4de2-93a0-c494a1d4ae40
        #     Attribute Reference - Object Group --> "encoded" as a ByteString
        self.invalid_attribute_reference_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x40'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x31\x37\x30\x33\x32\x35\x30\x62\x2D\x34\x64\x34\x30\x2D\x34\x64'
            b'\x65\x32\x2D\x39\x33\x61\x30\x2D\x63\x34\x39\x34\x61\x31\x64\x34'
            b'\x61\x65\x34\x30\x00\x00\x00\x00'
            b'\x42\x01\x3B\x08\x00\x00\x00\x04\x00\x42\x00\x56\x00\x00\x00\x00'
        )

        self.empty_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x00'
        )

        self.unique_identifier = 'b4faee10-aa2a-4446-8ad4-0881f3422959'
        self.attribute_names = [
            'Cryptographic Length',
            'Cryptographic Algorithm',
            'State',
            'Digest',
            'Lease Time',
            'Initial Date',
            'Unique Identifier',
            'Name',
            'Cryptographic Usage Mask',
            'Object Type',
            'Contact Information',
            'Last Change Date'
        ]

    def tearDown(self):
        super(TestGetAttributeListResponsePayload, self).tearDown()

    def test_init(self):
        """
        Test that a GetAttributeList response payload can be constructed with
        no arguments.
        """
        payloads.GetAttributeListResponsePayload()

    def test_init_with_args(self):
        """
        Test that a GetAttributeList response payload can be constructed with a
        valid value.
        """
        payloads.GetAttributeListResponsePayload(
            'test-unique-identifier',
            ['test-attribute-name-1', 'test-attribute-name-2']
        )

    def test_unique_identifier(self):
        """
        Test that the unique_identifier attribute of a GetAttributeList
        response payload can be properly set and retrieved.
        """
        payload = payloads.GetAttributeListResponsePayload()

        self.assertIsNone(payload.unique_identifier)
        self.assertIsNone(payload._unique_identifier)

        payload.unique_identifier = 'test-unique-identifier'

        self.assertEqual('test-unique-identifier', payload.unique_identifier)
        self.assertEqual(
            primitives.TextString(
                value='test-unique-identifier',
                tag=enums.Tags.UNIQUE_IDENTIFIER
            ),
            payload._unique_identifier
        )

    def test_unique_identifier_with_invalid_value(self):
        """
        Test that a TypeError is raised when an invalid ID is used to set
        the unique_identifier attribute of a GetAttributeList response
        payload.
        """
        payload = payloads.GetAttributeListResponsePayload()
        args = (payload, 'unique_identifier', 0)
        self.assertRaisesRegex(
            TypeError,
            "Unique identifier must be a string.",
            setattr,
            *args
        )

    def test_attribute_names(self):
        """
        Test that the attribute_names attribute of a GetAttributeList response
        payload can be properly set and retrieved.
        """
        payload = payloads.GetAttributeListResponsePayload()

        self.assertEqual(list(), payload.attribute_names)
        self.assertEqual(list(), payload._attribute_names)

        payload.attribute_names = [
            'test-attribute-name-1',
            'test-attribute-name-2'
        ]

        self.assertEqual(2, len(payload.attribute_names))
        self.assertEqual(2, len(payload._attribute_names))
        self.assertIn('test-attribute-name-1', payload.attribute_names)
        self.assertIn('test-attribute-name-2', payload.attribute_names)
        self.assertIn(
            primitives.TextString(
                value='test-attribute-name-1',
                tag=enums.Tags.ATTRIBUTE_NAME
            ),
            payload._attribute_names
        )
        self.assertIn(
            primitives.TextString(
                value='test-attribute-name-2',
                tag=enums.Tags.ATTRIBUTE_NAME
            ),
            payload._attribute_names
        )

    def test_attribute_names_with_invalid_value(self):
        """
        Test that a TypeError is raised when an invalid list is used to set
        the attribute_names attribute of a GetAttributeList response payload.
        """
        payload = payloads.GetAttributeListResponsePayload()
        args = (payload, 'attribute_names', 0)
        self.assertRaisesRegex(
            TypeError,
            "Attribute names must be a list of strings.",
            setattr,
            *args
        )

    def test_attribute_names_with_invalid_attribute_name(self):
        """
        Test that a TypeError is raised when an invalid attribute name is
        included in the list used to set the attribute_names attribute of a
        GetAttributeList response payload.
        """
        payload = payloads.GetAttributeListResponsePayload()
        args = (
            payload,
            'attribute_names',
            ['test-attribute-name-1', 0]
        )
        self.assertRaisesRegex(
            TypeError,
            "Attribute names must be a list of strings; "
            "item 2 has type {0}".format(type(0)),
            setattr,
            *args
        )

    def test_attribute_names_with_duplicates(self):
        """
        Test that duplicate attribute names are silently removed when setting
        the attribute_names attribute of a GetAttributeList response payload.
        """
        payload = payloads.GetAttributeListResponsePayload()

        self.assertEqual(list(), payload.attribute_names)
        self.assertEqual(list(), payload._attribute_names)

        payload.attribute_names = [
            'test-attribute-name-1',
            'test-attribute-name-1',
            'test-attribute-name-2'
        ]

        self.assertEqual(2, len(payload.attribute_names))
        self.assertEqual(2, len(payload._attribute_names))
        self.assertIn('test-attribute-name-1', payload.attribute_names)
        self.assertIn('test-attribute-name-2', payload.attribute_names)
        self.assertIn(
            primitives.TextString(
                value='test-attribute-name-1',
                tag=enums.Tags.ATTRIBUTE_NAME
            ),
            payload._attribute_names
        )
        self.assertIn(
            primitives.TextString(
                value='test-attribute-name-2',
                tag=enums.Tags.ATTRIBUTE_NAME
            ),
            payload._attribute_names
        )

    def test_read(self):
        """
        Test that a GetAttributeList response payload can be read from a data
        stream.
        """
        payload = payloads.GetAttributeListResponsePayload()

        self.assertEqual(None, payload._unique_identifier)
        self.assertEqual(list(), payload._attribute_names)

        payload.read(self.full_encoding)

        self.assertEqual(self.unique_identifier, payload.unique_identifier)
        self.assertEqual(
            primitives.TextString(
                value=self.unique_identifier,
                tag=enums.Tags.UNIQUE_IDENTIFIER
            ),
            payload._unique_identifier
        )
        self.assertEqual(
            set(self.attribute_names),
            set(payload.attribute_names)
        )
        for attribute_name in self.attribute_names:
            self.assertIn(
                primitives.TextString(
                    value=attribute_name,
                    tag=enums.Tags.ATTRIBUTE_NAME
                ),
                payload._attribute_names
            )

    def test_read_kmip_2_0_enums(self):
        """
        Test that a GetAttributeList response payload can be read from a data
        stream encoded with the KMIP 2.0 format using AttributeReference
        enumerations.
        """
        payload = payloads.GetAttributeListResponsePayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(list(), payload.attribute_names)

        payload.read(
            self.full_encoding_with_reference_enums,
            kmip_version=enums.KMIPVersion.KMIP_2_0
        )

        self.assertEqual(
            "1703250b-4d40-4de2-93a0-c494a1d4ae40",
            payload.unique_identifier
        )
        self.assertEqual(3, len(payload.attribute_names))
        self.assertEqual(
            [
                "Object Group",
                "Application Specific Information",
                "Contact Information"
            ],
            payload.attribute_names
        )

    def test_read_kmip_2_0_structs(self):
        """
        Test that a GetAttributeList response payload can be read from a data
        stream encoded with the KMIP 2.0 format using AttributeReference
        structures.
        """
        payload = payloads.GetAttributeListResponsePayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(list(), payload.attribute_names)

        payload.read(
            self.full_encoding_with_reference_structs,
            kmip_version=enums.KMIPVersion.KMIP_2_0
        )

        self.assertEqual(
            "1703250b-4d40-4de2-93a0-c494a1d4ae40",
            payload.unique_identifier
        )
        self.assertEqual(3, len(payload.attribute_names))
        self.assertEqual(
            [
                "Object Group",
                "Application Specific Information",
                "Contact Information"
            ],
            payload.attribute_names
        )

    def test_read_kmip_2_0_invalid_attribute_reference(self):
        """
        Test that an InvalidKmipEncoding error is raised during the decoding
        of a GetAttributeList response payload when the wrong type is found
        for the AttributeReference structure.
        """
        payload = payloads.GetAttributeListResponsePayload()

        args = (self.invalid_attribute_reference_encoding, )
        kwargs = {"kmip_version": enums.KMIPVersion.KMIP_2_0}
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The GetAttributeList response payload encoding contains an "
            "invalid AttributeReference type.",
            payload.read,
            *args,
            **kwargs
        )

    def test_read_with_no_unique_identifier(self):
        """
        Test that an InvalidKmipEncoding error is raised when a
        GetAttributeList response payload is read from a data stream with no
        unique identifier.
        """
        payload = payloads.GetAttributeListResponsePayload()

        self.assertEqual(None, payload._unique_identifier)
        self.assertEqual(list(), payload._attribute_names)

        args = (self.encoding_sans_unique_identifier, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The GetAttributeList response payload encoding is missing the "
            "unique identifier.",
            payload.read,
            *args
        )

    def test_read_with_no_attribute_names(self):
        """
        Test that an InvalidKmipEncoding error is raised when a
        GetAttributeList response payload is read from a data stream with no
        attribute names.
        """
        payload = payloads.GetAttributeListResponsePayload()

        self.assertEqual(None, payload._unique_identifier)
        self.assertEqual(list(), payload._attribute_names)

        args = (self.encoding_sans_attribute_names, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The GetAttributeList response payload encoding is missing the "
            "attribute names.",
            payload.read,
            *args
        )

    def test_write(self):
        """
        Test that a GetAttributeList response payload can be written to a data
        stream.
        """
        payload = payloads.GetAttributeListResponsePayload(
            self.unique_identifier,
            self.attribute_names
        )
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_kmip_2_0_enums(self):
        """
        Test that a GetAttributeList response payload can be written to a data
        stream encoded in the KMIP 2.0 format using AttributeReference
        enumerations.
        """
        payload = payloads.GetAttributeListResponsePayload(
            "1703250b-4d40-4de2-93a0-c494a1d4ae40",
            [
                "Object Group",
                "Application Specific Information",
                "Contact Information"
            ]
        )
        stream = utils.BytearrayStream()
        payload.write(stream, kmip_version=enums.KMIPVersion.KMIP_2_0)

        self.assertEqual(
            len(self.full_encoding_with_reference_enums),
            len(stream)
        )
        self.assertEqual(
            str(self.full_encoding_with_reference_enums),
            str(stream)
        )

    def test_write_with_no_unique_identifier(self):
        """
        Test that an InvalidField error is raised when a GetAttributeList
        response payload is written to a data stream with no unique identifier.
        """
        payload = payloads.GetAttributeListResponsePayload(
            None,
            self.attribute_names
        )
        args = (utils.BytearrayStream(), )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The GetAttributeList response payload is missing the unique "
            "identifier field.",
            payload.write,
            *args
        )

    def test_write_with_no_attribute_names(self):
        """
        Test that an InvalidField error is raised when a GetAttributeList
        response payload is written to a data stream with no attribute names.
        """
        payload = payloads.GetAttributeListResponsePayload(
            self.unique_identifier,
            None
        )
        args = (utils.BytearrayStream(), )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The GetAttributeList response payload is missing the attribute "
            "names field.",
            payload.write,
            *args
        )

    def test_repr(self):
        """
        Test that repr can be applied to a GetAttributeList response payload.
        """
        payload = payloads.GetAttributeListResponsePayload(
            self.unique_identifier,
            self.attribute_names
        )
        unique_identifier = "unique_identifier={0}".format(
            payload.unique_identifier
        )
        attribute_names = "attribute_names={0}".format(
            payload.attribute_names
        )
        expected = "GetAttributeListResponsePayload({0}, {1})".format(
            unique_identifier,
            attribute_names
        )
        observed = repr(payload)
        self.assertEqual(expected, observed)

    def test_repr_with_no_unique_identifier(self):
        """
        Test that repr can be applied to a GetAttributeList response payload
        with no ID.
        """
        payload = payloads.GetAttributeListResponsePayload(
            None,
            self.attribute_names
        )
        unique_identifier = "unique_identifier={0}".format(
            payload.unique_identifier
        )
        attribute_names = "attribute_names={0}".format(
            payload.attribute_names
        )
        expected = "GetAttributeListResponsePayload({0}, {1})".format(
            unique_identifier,
            attribute_names
        )
        observed = repr(payload)
        self.assertEqual(expected, observed)

    def test_repr_with_no_attribute_names(self):
        """
        Test that repr can be applied to a GetAttributeList response payload
        with no attribute names.
        """
        payload = payloads.GetAttributeListResponsePayload(
            self.unique_identifier,
            None
        )
        unique_identifier = "unique_identifier={0}".format(
            payload.unique_identifier
        )
        attribute_names = "attribute_names={0}".format(
            payload.attribute_names
        )
        expected = "GetAttributeListResponsePayload({0}, {1})".format(
            unique_identifier,
            attribute_names
        )
        observed = repr(payload)
        self.assertEqual(expected, observed)

    def test_repr_with_no_content(self):
        """
        Test that repr can be applied to a GetAttributeList response payload
        with no ID or attribute names.
        """
        payload = payloads.GetAttributeListResponsePayload(
            None,
            None
        )
        unique_identifier = "unique_identifier={0}".format(
            payload.unique_identifier
        )
        attribute_names = "attribute_names={0}".format(
            payload.attribute_names
        )
        expected = "GetAttributeListResponsePayload({0}, {1})".format(
            unique_identifier,
            attribute_names
        )
        observed = repr(payload)
        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a GetAttributeList response payload.
        """
        payload = payloads.GetAttributeListResponsePayload(
            self.unique_identifier,
            self.attribute_names
        )
        expected = str({
            'unique_identifier': self.unique_identifier,
            'attribute_names': self.attribute_names
        })
        observed = str(payload)
        self.assertEqual(expected, observed)

    def test_str_with_no_id(self):
        """
        Test that str can be applied to a GetAttributeList response payload
        with no ID.
        """
        payload = payloads.GetAttributeListResponsePayload(
            None,
            self.attribute_names
        )
        expected = str({
            'unique_identifier': None,
            'attribute_names': self.attribute_names
        })
        observed = str(payload)
        self.assertEqual(expected, observed)

    def test_str_with_no_attribute_names(self):
        """
        Test that str can be applied to a GetAttributeList response payload
        with no attribute names.
        """
        payload = payloads.GetAttributeListResponsePayload(
            self.unique_identifier,
            None
        )
        expected = str({
            'unique_identifier': self.unique_identifier,
            'attribute_names': list()
        })
        observed = str(payload)
        self.assertEqual(expected, observed)

    def test_str_with_no_content(self):
        """
        Test that str can be applied to a GetAttributeList response payload
        with no ID or attribute names.
        """
        payload = payloads.GetAttributeListResponsePayload(
            None,
            None
        )
        expected = str({
            'unique_identifier': None,
            'attribute_names': list()
        })
        observed = str(payload)
        self.assertEqual(expected, observed)

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        GetAttributeList response payloads with the same data.
        """
        a = payloads.GetAttributeListResponsePayload(
            self.unique_identifier,
            self.attribute_names
        )
        b = payloads.GetAttributeListResponsePayload(
            self.unique_identifier,
            self.attribute_names
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_with_mixed_attribute_names(self):
        """
        Test that the equality operator returns True when comparing two
        GetAttributeList response payload with the same attribute_name sets
        but with different attribute name orderings.
        """
        a = payloads.GetAttributeListResponsePayload(
            self.unique_identifier,
            self.attribute_names
        )
        self.attribute_names.reverse()
        b = payloads.GetAttributeListResponsePayload(
            self.unique_identifier,
            self.attribute_names
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_unique_identifier(self):
        """
        Test that the equality operator returns False when comparing two
        GetAttributeList response payloads with different IDs.
        """
        a = payloads.GetAttributeListResponsePayload(
            self.unique_identifier,
            self.attribute_names
        )
        b = payloads.GetAttributeListResponsePayload(
            'invalid',
            self.attribute_names
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_attribute_names(self):
        """
        Test that the equality operator returns False when comparing two
        GetAttributeList response payloads with different attribute names.
        """
        a = payloads.GetAttributeListResponsePayload(
            self.unique_identifier,
            self.attribute_names
        )
        b = payloads.GetAttributeListResponsePayload(
            self.unique_identifier,
            None
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing a
        GetAttributeList response payload to a non-GetAttributeList response
        payload.
        """
        a = payloads.GetAttributeListResponsePayload(
            self.unique_identifier,
            self.attribute_names
        )
        b = "invalid"

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing
        two GetAttributeList response payloads with the same internal data.
        """
        a = payloads.GetAttributeListResponsePayload(
            self.unique_identifier,
            self.attribute_names
        )
        b = payloads.GetAttributeListResponsePayload(
            self.unique_identifier,
            self.attribute_names
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_unique_identifier(self):
        """
        Test that the inequality operator returns True when comparing two
        GetAttributeList response payloads with different IDs.
        """
        a = payloads.GetAttributeListResponsePayload(
            self.unique_identifier,
            self.attribute_names
        )
        b = payloads.GetAttributeListResponsePayload(
            'invalid',
            self.attribute_names
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_attribute_names(self):
        """
        Test that the inequality operator returns True when comparing two
        GetAttributeList response payloads with different attribute names.
        """
        a = payloads.GetAttributeListResponsePayload(
            self.unique_identifier,
            self.attribute_names
        )
        b = payloads.GetAttributeListResponsePayload(
            self.unique_identifier,
            None
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns True when comparing a
        GetAttributeList response payload to a non-GetAttributeList response
        payload.
        """
        a = payloads.GetAttributeListResponsePayload(
            self.unique_identifier,
            self.attribute_names
        )
        b = "invalid"

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_read_valid(self):
        """
        Test that a GetAttributeList response payload can be read from a valid
        byte stream.
        """
        self.test_read()

    def test_read_missing_required_field(self):
        """
        Test that an exception is raised when reading a payload missing a
        required field.
        """
        payload = payloads.GetAttributeListResponsePayload()
        self.assertRaises(Exception, payload.read, utils.BytearrayStream(b""))

    def test_write_valid(self):
        """
        Test that a GetAttributeList response payload can be written to a byte
        stream.
        """
        self.test_write()

    def test_read_write_roundtrip(self):
        """
        Test that a GetAttributeList response payload can be read and written
        without changing the encoded bytes.
        """
        payload = payloads.GetAttributeListResponsePayload()
        payload.read(utils.BytearrayStream(self.full_encoding.buffer))

        buffer = utils.BytearrayStream()
        payload.write(buffer)

        self.assertEqual(str(self.full_encoding), str(buffer))

    def test_validate_invalid(self):
        """
        Test that an exception is raised when a field has an invalid type.
        """
        self.test_unique_identifier_with_invalid_value()

    def test_eq(self):
        """
        Test that two GetAttributeList response payloads with the same data are
        equal.
        """
        self.test_equal_on_equal()

    def test_ne(self):
        """
        Test that two GetAttributeList response payloads with different data are
        not equal.
        """
        self.test_not_equal_on_not_equal_unique_identifier()
