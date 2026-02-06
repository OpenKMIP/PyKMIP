# Copyright (c) 2019 The Johns Hopkins University/Applied Physics Laboratory
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
from kmip.core import objects
from kmip.core import primitives
from kmip.core import utils

from kmip.core.messages import payloads

class TestSetAttributeRequestPayload(testtools.TestCase):
    """
    A unit test suite for the SetAttribute request payload.
    """

    def setUp(self):
        super(TestSetAttributeRequestPayload, self).setUp()

        # This encoding was adapted from test case 3.1.4-7 from the KMIP 1.1
        # test suite. It was modified to reflect the new SetAttribute operation
        # in KMIP 2.0. The new attribute was manually added.
        #
        # This encoding matches the following set of values.
        # Request Payload
        #     Unique Identifier - b4faee10-aa2a-4446-8ad4-0881f3422959
        #     New Attribute
        #         Cryptographic Algorithm - AES
        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x48'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x62\x34\x66\x61\x65\x65\x31\x30\x2D\x61\x61\x32\x61\x2D\x34\x34'
            b'\x34\x36\x2D\x38\x61\x64\x34\x2D\x30\x38\x38\x31\x66\x33\x34\x32'
            b'\x32\x39\x35\x39\x00\x00\x00\x00'
            b'\x42\x01\x3D\x01\x00\x00\x00\x10'
            b'\x42\x00\x28\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
        )

        # This encoding was adapted from test case 3.1.4-7 from the KMIP 1.1
        # test suite. It was modified to reflect the new SetAttribute operation
        # in KMIP 2.0. The new attribute was manually added and the unique
        # identifier was removed.
        #
        # This encoding matches the following set of values.
        # Request Payload
        #     New Attribute
        #         Cryptographic Algorithm - AES
        self.no_unique_identifier_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x18'
            b'\x42\x01\x3D\x01\x00\x00\x00\x10'
            b'\x42\x00\x28\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
        )

        self.empty_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestSetAttributeRequestPayload, self).tearDown()

    def test_invalid_unique_identifier(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the unique identifier of a SetAttribute request payload.
        """
        kwargs = {"unique_identifier": 0}
        self.assertRaisesRegex(
            TypeError,
            "The unique identifier must be a string.",
            payloads.SetAttributeRequestPayload,
            **kwargs
        )

        args = (
            payloads.SetAttributeRequestPayload(),
            "unique_identifier",
            0
        )
        self.assertRaisesRegex(
            TypeError,
            "The unique identifier must be a string.",
            setattr,
            *args
        )

    def test_invalid_new_attribute(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the new attribute of a SetAttribute request payload.
        """
        kwargs = {"new_attribute": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The new attribute must be a NewAttribute object.",
            payloads.SetAttributeRequestPayload,
            **kwargs
        )

        args = (
            payloads.SetAttributeRequestPayload(),
            "new_attribute",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The new attribute must be a NewAttribute object.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a SetAttribute request payload can be read from a buffer.
        """
        payload = payloads.SetAttributeRequestPayload()

        self.assertIsNone(payload.unique_identifier)
        self.assertIsNone(payload.new_attribute)

        payload.read(self.full_encoding)

        self.assertEqual(
            "b4faee10-aa2a-4446-8ad4-0881f3422959",
            payload.unique_identifier
        )
        self.assertEqual(
            objects.NewAttribute(
                attribute=primitives.Enumeration(
                    enums.CryptographicAlgorithm,
                    enums.CryptographicAlgorithm.AES,
                    enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                )
            ),
            payload.new_attribute
        )

    def test_read_no_unique_identifier(self):
        """
        Test that a SetAttribute request payload can be read from a buffer
        even when the encoding is missing the unique identifier field.
        """
        payload = payloads.SetAttributeRequestPayload()

        self.assertIsNone(payload.unique_identifier)
        self.assertIsNone(payload.new_attribute)

        payload.read(self.no_unique_identifier_encoding)

        self.assertIsNone(payload.unique_identifier)
        self.assertEqual(
            objects.NewAttribute(
                attribute=primitives.Enumeration(
                    enums.CryptographicAlgorithm,
                    enums.CryptographicAlgorithm.AES,
                    enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                )
            ),
            payload.new_attribute
        )

    def test_read_no_new_attribute(self):
        """
        Test that an InvalidKmipEncoding error is raised when an invalid
        encoding containing no encoded new attribute is used to decode
        a SetAttribute request payload.
        """
        payload = payloads.SetAttributeRequestPayload()
        args = (self.empty_encoding, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The SetAttribute request payload encoding is missing the "
            "new attribute field.",
            payload.read,
            *args
        )

    def test_read_invalid_kmip_version(self):
        """
        Test that a VersionNotSupported error is raised when an unsupported
        version of KMIP is used to decode the SetAttribute request payload.
        """
        payload = payloads.SetAttributeRequestPayload()
        args = (self.empty_encoding, )
        kwargs = {"kmip_version": enums.KMIPVersion.KMIP_1_0}
        self.assertRaisesRegex(
            exceptions.VersionNotSupported,
            "KMIP 1.0 does not support the SetAttribute operation.",
            payload.read,
            *args,
            **kwargs
        )

    def test_write(self):
        """
        Test that a SetAttribute request payload can be written to a buffer.
        """
        payload = payloads.SetAttributeRequestPayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959",
            new_attribute=objects.NewAttribute(
                attribute=primitives.Enumeration(
                    enums.CryptographicAlgorithm,
                    enums.CryptographicAlgorithm.AES,
                    enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                )
            )
        )

        buffer = utils.BytearrayStream()
        payload.write(buffer)

        self.assertEqual(len(self.full_encoding), len(buffer))
        self.assertEqual(str(self.full_encoding), str(buffer))

    def test_write_no_unique_identifier(self):
        """
        Test that a SetAttribute request payload can be written to a buffer
        without the unique identifier field.
        """
        payload = payloads.SetAttributeRequestPayload(
            new_attribute=objects.NewAttribute(
                attribute=primitives.Enumeration(
                    enums.CryptographicAlgorithm,
                    enums.CryptographicAlgorithm.AES,
                    enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                )
            )
        )

        buffer = utils.BytearrayStream()
        payload.write(buffer)

        self.assertEqual(len(self.no_unique_identifier_encoding), len(buffer))
        self.assertEqual(str(self.no_unique_identifier_encoding), str(buffer))

    def test_write_no_new_attribute(self):
        """
        Test that an InvalidField error is raised when attempting to write
        a SetAttribute request payload to a buffer with no new attribute
        field specified.
        """
        payload = payloads.SetAttributeRequestPayload()

        args = (utils.BytearrayStream(), )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The SetAttribute request payload is missing the new attribute "
            "field.",
            payload.write,
            *args
        )

    def test_write_invalid_kmip_version(self):
        """
        Test that a VersionNotSupported error is raised when an unsupported
        version of KMIP is used to encode the SetAttribute request payload.
        """
        payload = payloads.SetAttributeRequestPayload()

        args = (utils.BytearrayStream(), )
        kwargs = {"kmip_version": enums.KMIPVersion.KMIP_1_0}
        self.assertRaisesRegex(
            exceptions.VersionNotSupported,
            "KMIP 1.0 does not support the SetAttribute operation.",
            payload.write,
            *args,
            **kwargs
        )

    def test_repr(self):
        """
        Test that repr can be applied to a SetAttribute request payload.
        """
        payload = payloads.SetAttributeRequestPayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959",
            new_attribute=None
        )

        args = [
            "unique_identifier='b4faee10-aa2a-4446-8ad4-0881f3422959'",
            "new_attribute=None"
        ]
        self.assertEqual(
            "SetAttributeRequestPayload({})".format(", ".join(args)),
            repr(payload)
        )

    def test_str(self):
        """
        Test that str can be applied to a SetAttribute request payload.
        """
        payload = payloads.SetAttributeRequestPayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959",
            new_attribute=None
        )
        s = str(
            {
                "unique_identifier": "b4faee10-aa2a-4446-8ad4-0881f3422959",
                "new_attribute": None
            }
        )
        self.assertEqual(s, str(payload))

    def test_comparison(self):
        """
        Test that the equality/inequality operators return True/False when
        comparing two SetAttribute request payloads with the same data.
        """
        a = payloads.SetAttributeRequestPayload()
        b = payloads.SetAttributeRequestPayload()

        self.assertTrue(a == b)
        self.assertTrue(b == a)
        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = payloads.SetAttributeRequestPayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959",
            new_attribute=objects.NewAttribute(
                attribute=primitives.Enumeration(
                    enums.CryptographicAlgorithm,
                    enums.CryptographicAlgorithm.AES,
                    enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                )
            )
        )
        b = payloads.SetAttributeRequestPayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959",
            new_attribute=objects.NewAttribute(
                attribute=primitives.Enumeration(
                    enums.CryptographicAlgorithm,
                    enums.CryptographicAlgorithm.AES,
                    enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                )
            )
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)
        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_comparison_on_different_unique_identifiers(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing two SetAttribute request payloads with different unique
        identifiers.
        """
        a = payloads.SetAttributeRequestPayload(unique_identifier="1")
        b = payloads.SetAttributeRequestPayload(unique_identifier="2")

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_comparison_on_different_new_attributes(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing two SetAttribute request payloads with different new
        attributes.
        """
        a = payloads.SetAttributeRequestPayload(
            new_attribute=objects.NewAttribute(
                attribute=primitives.Enumeration(
                    enums.CryptographicAlgorithm,
                    enums.CryptographicAlgorithm.AES,
                    enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                )
            )
        )
        b = payloads.SetAttributeRequestPayload(
            new_attribute=objects.NewAttribute(
                attribute=primitives.Integer(
                    128,
                    enums.Tags.CRYPTOGRAPHIC_LENGTH
                )
            )
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_comparison_on_type_mismatch(self):
        """
        Test that the equality/inequality operators return False/True when
        comparining a SetAttribute request payload against a different type.
        """
        a = payloads.SetAttributeRequestPayload()
        b = "invalid"

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_init(self):
        """
        Test that a SetAttribute request payload can be constructed with no
        arguments.
        """
        payload = payloads.SetAttributeRequestPayload()
        self.assertIsNone(payload.unique_identifier)
        self.assertIsNone(payload.new_attribute)

    def test_init_with_args(self):
        """
        Test that a SetAttribute request payload can be constructed with
        valid values.
        """
        payload = payloads.SetAttributeRequestPayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959",
            new_attribute=objects.NewAttribute(
                attribute=primitives.Enumeration(
                    enums.CryptographicAlgorithm,
                    enums.CryptographicAlgorithm.AES,
                    enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                )
            )
        )

        self.assertEqual(
            "b4faee10-aa2a-4446-8ad4-0881f3422959",
            payload.unique_identifier
        )
        self.assertIsInstance(payload.new_attribute, objects.NewAttribute)

    def test_read_valid(self):
        """
        Test that a SetAttribute request payload can be read from a valid byte
        stream.
        """
        self.test_read()

    def test_read_missing_required_field(self):
        """
        Test that an exception is raised when reading a payload missing a
        required field.
        """
        self.test_read_no_unique_identifier()

    def test_write_valid(self):
        """
        Test that a SetAttribute request payload can be written to a byte
        stream.
        """
        self.test_write()

    def test_read_write_roundtrip(self):
        """
        Test that a SetAttribute request payload can be read and written
        without changing the encoded bytes.
        """
        payload = payloads.SetAttributeRequestPayload()
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
        Test that a SetAttribute request payload compares equal to itself.
        """
        payload = payloads.SetAttributeRequestPayload()
        self.assertTrue(payload == payload)

    def test_ne(self):
        """
        Test that two different SetAttribute request payloads are not equal.
        """
        a = payloads.SetAttributeRequestPayload(unique_identifier="1")
        b = payloads.SetAttributeRequestPayload(unique_identifier="2")
        self.assertTrue(a != b)

class TestSetAttributeResponsePayload(testtools.TestCase):
    """
    A unit test suite for the SetAttribute response payload.
    """

    def setUp(self):
        super(TestSetAttributeResponsePayload, self).setUp()

        # This encoding was adapted from test case 3.1.4-7 from the KMIP 1.1
        # test suite.
        #
        # This encoding matches the following set of values:
        # Response Payload
        #     Unique Identifier - b4faee10-aa2a-4446-8ad4-0881f3422959
        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x30'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x62\x34\x66\x61\x65\x65\x31\x30\x2D\x61\x61\x32\x61\x2D\x34\x34'
            b'\x34\x36\x2D\x38\x61\x64\x34\x2D\x30\x38\x38\x31\x66\x33\x34\x32'
            b'\x32\x39\x35\x39\x00\x00\x00\x00'
        )

        self.empty_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestSetAttributeResponsePayload, self).tearDown()

    def test_invalid_unique_identifier(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the unique identifier of a SetAttribute response payload.
        """
        kwargs = {"unique_identifier": 0}
        self.assertRaisesRegex(
            TypeError,
            "The unique identifier must be a string.",
            payloads.SetAttributeResponsePayload,
            **kwargs
        )

        args = (
            payloads.SetAttributeResponsePayload(),
            "unique_identifier",
            0
        )
        self.assertRaisesRegex(
            TypeError,
            "The unique identifier must be a string.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a SetAttribute response payload can be read from a buffer.
        """
        payload = payloads.SetAttributeResponsePayload()

        self.assertIsNone(payload.unique_identifier)

        payload.read(self.full_encoding)

        self.assertEqual(
            "b4faee10-aa2a-4446-8ad4-0881f3422959",
            payload.unique_identifier
        )

    def test_read_no_unique_identifier(self):
        """
        Test that an InvalidKmipEncoding error is raised when an invalid
        encoding containing no encoded unique identifier is used to decode
        a SetAttribute response payload.
        """
        payload = payloads.SetAttributeResponsePayload()
        args = (self.empty_encoding, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The SetAttribute response payload encoding is missing the "
            "unique identifier field.",
            payload.read,
            *args
        )

    def test_read_invalid_kmip_version(self):
        """
        Test that a VersionNotSupported error is raised when an unsupported
        version of KMIP is used to decode the SetAttribute response payload.
        """
        payload = payloads.SetAttributeResponsePayload()
        args = (self.empty_encoding, )
        kwargs = {"kmip_version": enums.KMIPVersion.KMIP_1_0}
        self.assertRaisesRegex(
            exceptions.VersionNotSupported,
            "KMIP 1.0 does not support the SetAttribute operation.",
            payload.read,
            *args,
            **kwargs
        )

    def test_write(self):
        """
        Test that a SetAttribute response payload can be written to a
        buffer.
        """
        payload = payloads.SetAttributeResponsePayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959"
        )

        buffer = utils.BytearrayStream()
        payload.write(buffer)

        self.assertEqual(len(self.full_encoding), len(buffer))
        self.assertEqual(str(self.full_encoding), str(buffer))

    def test_write_no_unique_identifier(self):
        """
        Test that an InvalidField error is raised when attempting to write
        a SetAttribute response payload to a buffer with no unique
        identifier field specified.
        """
        payload = payloads.SetAttributeResponsePayload()

        args = (utils.BytearrayStream(), )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The SetAttribute response payload is missing the unique "
            "identifier field.",
            payload.write,
            *args
        )

    def test_write_invalid_kmip_version(self):
        """
        Test that a VersionNotSupported error is raised when an unsupported
        version of KMIP is used to encode the SetAttribute response payload.
        """
        payload = payloads.SetAttributeResponsePayload()

        args = (utils.BytearrayStream(), )
        kwargs = {"kmip_version": enums.KMIPVersion.KMIP_1_0}
        self.assertRaisesRegex(
            exceptions.VersionNotSupported,
            "KMIP 1.0 does not support the SetAttribute operation.",
            payload.write,
            *args,
            **kwargs
        )

    def test_repr(self):
        """
        Test that repr can be applied to a SetAttribute response payload.
        """
        payload = payloads.SetAttributeResponsePayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959"
        )

        args = [
            "unique_identifier='b4faee10-aa2a-4446-8ad4-0881f3422959'"
        ]
        self.assertEqual(
            "SetAttributeResponsePayload({})".format(", ".join(args)),
            repr(payload)
        )

    def test_str(self):
        """
        Test that str can be applied to a SetAttribute response payload.
        """
        payload = payloads.SetAttributeResponsePayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959"
        )
        s = str(
            {
                "unique_identifier": "b4faee10-aa2a-4446-8ad4-0881f3422959"
            }
        )
        self.assertEqual(s, str(payload))

    def test_comparison(self):
        """
        Test that the equality/inequality operators return True/False when
        comparing two SetAttribute response payloads with the same data.
        """
        a = payloads.SetAttributeResponsePayload()
        b = payloads.SetAttributeResponsePayload()

        self.assertTrue(a == b)
        self.assertTrue(b == a)
        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = payloads.SetAttributeResponsePayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959"
        )
        b = payloads.SetAttributeResponsePayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959"
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)
        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_comparison_on_different_unique_identifiers(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing two SetAttribute response payloads with different unique
        identifiers.
        """
        a = payloads.SetAttributeResponsePayload(unique_identifier="1")
        b = payloads.SetAttributeResponsePayload(unique_identifier="2")

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_comparison_on_type_mismatch(self):
        """
        Test that the equality/inequality operators return False/True when
        comparining a SetAttribute response payload against a different
        type.
        """
        a = payloads.SetAttributeResponsePayload()
        b = "invalid"

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_init(self):
        """
        Test that a SetAttribute response payload can be constructed with no
        arguments.
        """
        payload = payloads.SetAttributeResponsePayload()
        self.assertIsNone(payload.unique_identifier)

    def test_init_with_args(self):
        """
        Test that a SetAttribute response payload can be constructed with
        valid values.
        """
        payload = payloads.SetAttributeResponsePayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959"
        )
        self.assertEqual(
            "b4faee10-aa2a-4446-8ad4-0881f3422959",
            payload.unique_identifier
        )

    def test_read_valid(self):
        """
        Test that a SetAttribute response payload can be read from a valid
        byte stream.
        """
        self.test_read()

    def test_read_missing_required_field(self):
        """
        Test that an exception is raised when reading a payload missing a
        required field.
        """
        self.test_read_no_unique_identifier()

    def test_write_valid(self):
        """
        Test that a SetAttribute response payload can be written to a byte
        stream.
        """
        self.test_write()

    def test_read_write_roundtrip(self):
        """
        Test that a SetAttribute response payload can be read and written
        without changing the encoded bytes.
        """
        payload = payloads.SetAttributeResponsePayload()
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
        Test that a SetAttribute response payload compares equal to itself.
        """
        payload = payloads.SetAttributeResponsePayload()
        self.assertTrue(payload == payload)

    def test_ne(self):
        """
        Test that two different SetAttribute response payloads are not equal.
        """
        a = payloads.SetAttributeResponsePayload(unique_identifier="1")
        b = payloads.SetAttributeResponsePayload(unique_identifier="2")
        self.assertTrue(a != b)
