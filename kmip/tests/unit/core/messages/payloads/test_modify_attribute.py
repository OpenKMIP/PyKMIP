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

class TestModifyAttributeRequestPayload(testtools.TestCase):
    """
    A unit test suite for the ModifyAttribute request payload.
    """

    def setUp(self):
        super(TestModifyAttributeRequestPayload, self).setUp()

        # This encoding was taken from test case 3.1.4-6 from the KMIP 1.1
        # test suite.
        #
        # This encoding matches the following set of values.
        # Request Payload
        #     Unique Identifier - b4faee10-aa2a-4446-8ad4-0881f3422959
        #     Attribute
        #         Attribute Name - x-attribute1
        #         Attribute Value - ModifiedValue1
        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x68'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x62\x34\x66\x61\x65\x65\x31\x30\x2D\x61\x61\x32\x61\x2D\x34\x34'
            b'\x34\x36\x2D\x38\x61\x64\x34\x2D\x30\x38\x38\x31\x66\x33\x34\x32'
            b'\x32\x39\x35\x39\x00\x00\x00\x00'
            b'\x42\x00\x08\x01\x00\x00\x00\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x0C'
            b'\x78\x2D\x61\x74\x74\x72\x69\x62\x75\x74\x65\x31\x00\x00\x00\x00'
            b'\x42\x00\x0B\x07\x00\x00\x00\x0E'
            b'\x4D\x6F\x64\x69\x66\x69\x65\x64\x56\x61\x6C\x75\x65\x31\x00\x00'
        )

        # This encoding was adapted from test case 3.1.4-6 from the KMIP 1.1
        # test suite. It was modified to reflect the ModifyAttribute operation
        # changes in KMIP 2.0. The attribute encoding was removed and the
        # current and new attribute encodings were manually added.
        #
        # This encoding matches the following set of values.
        # Request Payload
        #     Unique Identifier - b4faee10-aa2a-4446-8ad4-0881f3422959
        #     Current Attribute
        #         Cryptographic Algorithm - AES
        #     New Attribute
        #         Cryptographic Algorithm - RSA
        self.full_encoding_kmip_2_0 = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x60'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x62\x34\x66\x61\x65\x65\x31\x30\x2D\x61\x61\x32\x61\x2D\x34\x34'
            b'\x34\x36\x2D\x38\x61\x64\x34\x2D\x30\x38\x38\x31\x66\x33\x34\x32'
            b'\x32\x39\x35\x39\x00\x00\x00\x00'
            b'\x42\x01\x3C\x01\x00\x00\x00\x10'
            b'\x42\x00\x28\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x01\x3D\x01\x00\x00\x00\x10'
            b'\x42\x00\x28\x05\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00'
        )

        self.empty_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestModifyAttributeRequestPayload, self).tearDown()

    def test_invalid_unique_identifier(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the unique identifier of a ModifyAttribute request payload.
        """
        kwargs = {"unique_identifier": 0}
        self.assertRaisesRegex(
            TypeError,
            "The unique identifier must be a string.",
            payloads.ModifyAttributeRequestPayload,
            **kwargs
        )

        args = (
            payloads.ModifyAttributeRequestPayload(),
            "unique_identifier",
            0
        )
        self.assertRaisesRegex(
            TypeError,
            "The unique identifier must be a string.",
            setattr,
            *args
        )

    def test_invalid_attribute(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the attribute of a ModifyAttribute request payload.
        """
        kwargs = {"attribute": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The attribute must be an Attribute object.",
            payloads.ModifyAttributeRequestPayload,
            **kwargs
        )

        args = (
            payloads.ModifyAttributeRequestPayload(),
            "attribute",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The attribute must be an Attribute object.",
            setattr,
            *args
        )

    def test_invalid_current_attribute(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the current attribute of a ModifyAttribute request payload.
        """
        kwargs = {"current_attribute": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The current attribute must be a CurrentAttribute object.",
            payloads.ModifyAttributeRequestPayload,
            **kwargs
        )

        args = (
            payloads.ModifyAttributeRequestPayload(),
            "current_attribute",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The current attribute must be a CurrentAttribute object.",
            setattr,
            *args
        )

    def test_invalid_new_attribute(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the new attribute of a ModifyAttribute request payload.
        """
        kwargs = {"new_attribute": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The new attribute must be a NewAttribute object.",
            payloads.ModifyAttributeRequestPayload,
            **kwargs
        )

        args = (
            payloads.ModifyAttributeRequestPayload(),
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
        Test that a ModifyAttribute request payload can be read from a buffer.
        """
        payload = payloads.ModifyAttributeRequestPayload()

        self.assertIsNone(payload.unique_identifier)
        self.assertIsNone(payload.attribute)
        self.assertIsNone(payload.current_attribute)
        self.assertIsNone(payload.new_attribute)

        payload.read(self.full_encoding)

        self.assertEqual(
            "b4faee10-aa2a-4446-8ad4-0881f3422959",
            payload.unique_identifier
        )
        self.assertEqual(
            objects.Attribute(
                attribute_name=objects.Attribute.AttributeName("x-attribute1"),
                attribute_value=primitives.TextString(
                    value="ModifiedValue1",
                    tag=enums.Tags.ATTRIBUTE_VALUE
                )
            ),
            payload.attribute
        )
        self.assertIsNone(payload.current_attribute)
        self.assertIsNone(payload.new_attribute)

    def test_read_kmip_2_0(self):
        """
        Test that a ModifyAttribute request payload can be read from a buffer
        with KMIP 2.0 fields.
        """
        payload = payloads.ModifyAttributeRequestPayload()

        self.assertIsNone(payload.unique_identifier)
        self.assertIsNone(payload.attribute)
        self.assertIsNone(payload.current_attribute)
        self.assertIsNone(payload.new_attribute)

        payload.read(
            self.full_encoding_kmip_2_0,
            kmip_version=enums.KMIPVersion.KMIP_2_0
        )

        self.assertEqual(
            "b4faee10-aa2a-4446-8ad4-0881f3422959",
            payload.unique_identifier
        )
        self.assertIsNone(payload.attribute)
        self.assertEqual(
            objects.CurrentAttribute(
                attribute=primitives.Enumeration(
                    enums.CryptographicAlgorithm,
                    enums.CryptographicAlgorithm.AES,
                    enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                )
            ),
            payload.current_attribute
        )
        self.assertEqual(
            objects.NewAttribute(
                attribute=primitives.Enumeration(
                    enums.CryptographicAlgorithm,
                    enums.CryptographicAlgorithm.RSA,
                    enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                )
            ),
            payload.new_attribute
        )

    def test_read_no_attribute(self):
        """
        Test that an InvalidKmipEncoding error is raised when an invalid
        encoding containing no encoded attribute is used to decode a
        ModifyAttribute request payload.
        """
        payload = payloads.ModifyAttributeRequestPayload()
        args = (self.empty_encoding, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The ModifyAttribute request payload encoding is missing the "
            "attribute field.",
            payload.read,
            *args
        )

    def test_read_no_new_attribute(self):
        """
        Test that an InvalidKmipEncoding error is raised when an invalid
        encoding containing no encoded new attribute is used to decode a
        ModifyAttribute request payload.
        """
        payload = payloads.ModifyAttributeRequestPayload()
        args = (self.empty_encoding, )
        kwargs = {"kmip_version": enums.KMIPVersion.KMIP_2_0}
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The ModifyAttribute request payload encoding is missing the "
            "new attribute field.",
            payload.read,
            *args,
            **kwargs
        )

    def test_write(self):
        """
        Test that a ModifyAttribute request payload can be written to a buffer.
        """
        payload = payloads.ModifyAttributeRequestPayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959",
            attribute=objects.Attribute(
                attribute_name=objects.Attribute.AttributeName("x-attribute1"),
                attribute_value=primitives.TextString(
                    value="ModifiedValue1",
                    tag=enums.Tags.ATTRIBUTE_VALUE
                )
            )
        )

        buffer = utils.BytearrayStream()
        payload.write(buffer)

        self.assertEqual(len(self.full_encoding), len(buffer))
        self.assertEqual(str(self.full_encoding), str(buffer))

    def test_write_kmip_2_0(self):
        """
        Test that a ModifyAttribute request payload can be written to a buffer
        with KMIP 2.0 fields.
        """
        payload = payloads.ModifyAttributeRequestPayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959",
            current_attribute=objects.CurrentAttribute(
                attribute=primitives.Enumeration(
                    enums.CryptographicAlgorithm,
                    enums.CryptographicAlgorithm.AES,
                    enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                )
            ),
            new_attribute=objects.NewAttribute(
                attribute=primitives.Enumeration(
                    enums.CryptographicAlgorithm,
                    enums.CryptographicAlgorithm.RSA,
                    enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                )
            )
        )

        buffer = utils.BytearrayStream()
        payload.write(buffer, kmip_version=enums.KMIPVersion.KMIP_2_0)

        self.assertEqual(len(self.full_encoding_kmip_2_0), len(buffer))
        self.assertEqual(str(self.full_encoding_kmip_2_0), str(buffer))

    def test_write_no_attribute(self):
        """
        Test that an InvalidField error is raised when attempting to write a
        ModifyAttribute request payload to a buffer with no attribute field
        specified.
        """
        payload = payloads.ModifyAttributeRequestPayload()
        args = (utils.BytearrayStream(), )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The ModifyAttribute request payload is missing the attribute "
            "field.",
            payload.write,
            *args
        )

    def test_write_no_new_attribute(self):
        """
        Test that an InvalidField error is raised when attempting to write a
        ModifyAttribute request payload to a buffer with no new attribute
        field specified.
        """
        payload = payloads.ModifyAttributeRequestPayload()
        args = (utils.BytearrayStream(), )
        kwargs = {"kmip_version": enums.KMIPVersion.KMIP_2_0}
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The ModifyAttribute request payload is missing the new attribute "
            "field.",
            payload.write,
            *args,
            **kwargs
        )

    def test_repr(self):
        """
        Test that repr can be applied to a ModifyAttribute request payload.
        """
        payload = payloads.ModifyAttributeRequestPayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959"
        )

        args = [
            "unique_identifier='b4faee10-aa2a-4446-8ad4-0881f3422959'",
            "attribute=None",
            "current_attribute=None",
            "new_attribute=None"
        ]
        self.assertEqual(
            "ModifyAttributeRequestPayload({})".format(", ".join(args)),
            repr(payload)
        )

    def test_str(self):
        """
        Test that str can be applied to a ModifyAttribute request payload.
        """
        payload = payloads.ModifyAttributeRequestPayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959"
        )
        s = str(
            {
                "unique_identifier": "b4faee10-aa2a-4446-8ad4-0881f3422959",
                "attribute": None,
                "current_attribute": None,
                "new_attribute": None
            }
        )
        self.assertEqual(s, str(payload))

    def test_comparison(self):
        """
        Test that the equality/inequality operators return True/False when
        comparing two ModifyAttribute request payloads with the same data.
        """
        a = payloads.ModifyAttributeRequestPayload()
        b = payloads.ModifyAttributeRequestPayload()

        self.assertTrue(a == b)
        self.assertTrue(b == a)
        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = payloads.ModifyAttributeRequestPayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959",
            attribute=objects.Attribute(
                attribute_name=objects.Attribute.AttributeName("x-attribute1"),
                attribute_value=primitives.TextString(
                    value="ModifiedValue1",
                    tag=enums.Tags.ATTRIBUTE_VALUE
                )
            ),
            current_attribute=objects.CurrentAttribute(
                attribute=primitives.Enumeration(
                    enums.CryptographicAlgorithm,
                    enums.CryptographicAlgorithm.AES,
                    enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                )
            ),
            new_attribute=objects.NewAttribute(
                attribute=primitives.Enumeration(
                    enums.CryptographicAlgorithm,
                    enums.CryptographicAlgorithm.RSA,
                    enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                )
            )
        )
        b = payloads.ModifyAttributeRequestPayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959",
            attribute=objects.Attribute(
                attribute_name=objects.Attribute.AttributeName("x-attribute1"),
                attribute_value=primitives.TextString(
                    value="ModifiedValue1",
                    tag=enums.Tags.ATTRIBUTE_VALUE
                )
            ),
            current_attribute=objects.CurrentAttribute(
                attribute=primitives.Enumeration(
                    enums.CryptographicAlgorithm,
                    enums.CryptographicAlgorithm.AES,
                    enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                )
            ),
            new_attribute=objects.NewAttribute(
                attribute=primitives.Enumeration(
                    enums.CryptographicAlgorithm,
                    enums.CryptographicAlgorithm.RSA,
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
        comparing two ModifyAttribute request payloads with different unique
        identifiers.
        """
        a = payloads.ModifyAttributeRequestPayload(unique_identifier="1")
        b = payloads.ModifyAttributeRequestPayload(unique_identifier="2")

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_comparison_on_different_attributes(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing two ModifyAttribute request payloads with different
        attributes.
        """
        a = payloads.ModifyAttributeRequestPayload(
            attribute=objects.Attribute(
                attribute_name=objects.Attribute.AttributeName("x-attribute1"),
                attribute_value=primitives.TextString(
                    value="ModifiedValue1",
                    tag=enums.Tags.ATTRIBUTE_VALUE
                )
            )
        )
        b = payloads.ModifyAttributeRequestPayload(
            attribute=objects.Attribute(
                attribute_name=objects.Attribute.AttributeName("x-attribute2"),
                attribute_value=primitives.TextString(
                    value="ModifiedValue2",
                    tag=enums.Tags.ATTRIBUTE_VALUE
                )
            )
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_comparison_on_different_current_attributes(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing two ModifyAttribute request payloads with different current
        attributes.
        """
        a = payloads.ModifyAttributeRequestPayload(
            current_attribute=objects.CurrentAttribute(
                attribute=primitives.Enumeration(
                    enums.CryptographicAlgorithm,
                    enums.CryptographicAlgorithm.AES,
                    enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                )
            )
        )
        b = payloads.ModifyAttributeRequestPayload(
            current_attribute=objects.CurrentAttribute(
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

    def test_comparison_on_different_new_attributes(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing two ModifyAttribute request payloads with different new
        attributes.
        """
        a = payloads.ModifyAttributeRequestPayload(
            new_attribute=objects.NewAttribute(
                attribute=primitives.Enumeration(
                    enums.CryptographicAlgorithm,
                    enums.CryptographicAlgorithm.AES,
                    enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                )
            )
        )
        b = payloads.ModifyAttributeRequestPayload(
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
        comparining a ModifyAttribute request payload against a different type.
        """
        a = payloads.ModifyAttributeRequestPayload()
        b = "invalid"

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_init(self):
        """
        Test that a ModifyAttribute request payload can be constructed with no
        arguments.
        """
        payload = payloads.ModifyAttributeRequestPayload()
        self.assertIsNone(payload.unique_identifier)
        self.assertIsNone(payload.attribute)
        self.assertIsNone(payload.current_attribute)
        self.assertIsNone(payload.new_attribute)

    def test_init_with_args(self):
        """
        Test that a ModifyAttribute request payload can be constructed with
        valid values.
        """
        payload = payloads.ModifyAttributeRequestPayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959",
            attribute=objects.Attribute(
                attribute_name=objects.Attribute.AttributeName("x-attribute1"),
                attribute_value=primitives.TextString(
                    value="ModifiedValue1",
                    tag=enums.Tags.ATTRIBUTE_VALUE
                )
            )
        )

        self.assertEqual(
            "b4faee10-aa2a-4446-8ad4-0881f3422959",
            payload.unique_identifier
        )
        self.assertIsInstance(payload.attribute, objects.Attribute)

    def test_read_valid(self):
        """
        Test that a ModifyAttribute request payload can be read from a valid
        byte stream.
        """
        self.test_read()

    def test_read_missing_required_field(self):
        """
        Test that an exception is raised when reading a payload missing a
        required field.
        """
        self.test_read_no_attribute()

    def test_write_valid(self):
        """
        Test that a ModifyAttribute request payload can be written to a byte
        stream.
        """
        self.test_write()

    def test_read_write_roundtrip(self):
        """
        Test that a ModifyAttribute request payload can be read and written
        without changing the encoded bytes.
        """
        payload = payloads.ModifyAttributeRequestPayload()
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
        Test that a ModifyAttribute request payload compares equal to itself.
        """
        payload = payloads.ModifyAttributeRequestPayload()
        self.assertTrue(payload == payload)

    def test_ne(self):
        """
        Test that two different ModifyAttribute request payloads are not equal.
        """
        a = payloads.ModifyAttributeRequestPayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959"
        )
        b = payloads.ModifyAttributeRequestPayload(
            unique_identifier="11111111-2222-3333-4444-555555555555"
        )
        self.assertTrue(a != b)

class TestModifyAttributeResponsePayload(testtools.TestCase):
    """
    A unit test suite for the ModifyAttribute response payload.
    """

    def setUp(self):
        super(TestModifyAttributeResponsePayload, self).setUp()

        # This encoding was taken from test case 3.1.4-6 from the KMIP 1.1
        # test suite.
        #
        # This encoding matches the following set of values:
        # Response Payload
        #     Unique Identifier - b4faee10-aa2a-4446-8ad4-0881f3422959
        #     Attribute
        #         Attribute Name - x-attribute1
        #         Attribute Value - ModifiedValue1
        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x68'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x62\x34\x66\x61\x65\x65\x31\x30\x2D\x61\x61\x32\x61\x2D\x34\x34'
            b'\x34\x36\x2D\x38\x61\x64\x34\x2D\x30\x38\x38\x31\x66\x33\x34\x32'
            b'\x32\x39\x35\x39\x00\x00\x00\x00'
            b'\x42\x00\x08\x01\x00\x00\x00\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x0C'
            b'\x78\x2D\x61\x74\x74\x72\x69\x62\x75\x74\x65\x31\x00\x00\x00\x00'
            b'\x42\x00\x0B\x07\x00\x00\x00\x0E'
            b'\x4D\x6F\x64\x69\x66\x69\x65\x64\x56\x61\x6C\x75\x65\x31\x00\x00'
        )

        # This encoding was adapted from test case 3.1.4-6 from the KMIP 1.1
        # test suite. The attribute encoding was removed.
        #
        # This encoding matches the following set of values:
        # Response Payload
        #     Unique Identifier - b4faee10-aa2a-4446-8ad4-0881f3422959
        self.full_encoding_kmip_2_0 = utils.BytearrayStream(
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
        super(TestModifyAttributeResponsePayload, self).tearDown()

    def test_invalid_unique_identifier(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the unique identifier of a ModifyAttribute response payload.
        """
        kwargs = {"unique_identifier": 0}
        self.assertRaisesRegex(
            TypeError,
            "The unique identifier must be a string.",
            payloads.ModifyAttributeResponsePayload,
            **kwargs
        )

        args = (
            payloads.ModifyAttributeResponsePayload(),
            "unique_identifier",
            0
        )
        self.assertRaisesRegex(
            TypeError,
            "The unique identifier must be a string.",
            setattr,
            *args
        )

    def test_invalid_attribute(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the attribute of a ModifyAttribute response payload.
        """
        kwargs = {"attribute": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The attribute must be an Attribute object.",
            payloads.ModifyAttributeResponsePayload,
            **kwargs
        )

        args = (
            payloads.ModifyAttributeResponsePayload(),
            "attribute",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The attribute must be an Attribute object.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a ModifyAttribute response payload can be read from a buffer.
        """
        payload = payloads.ModifyAttributeResponsePayload()

        self.assertIsNone(payload.unique_identifier)
        self.assertIsNone(payload.attribute)

        payload.read(self.full_encoding)

        self.assertEqual(
            "b4faee10-aa2a-4446-8ad4-0881f3422959",
            payload.unique_identifier
        )
        self.assertEqual(
            objects.Attribute(
                attribute_name=objects.Attribute.AttributeName("x-attribute1"),
                attribute_value=primitives.TextString(
                    value="ModifiedValue1",
                    tag=enums.Tags.ATTRIBUTE_VALUE
                )
            ),
            payload.attribute
        )

    def test_read_kmip_2_0(self):
        """
        Test that a ModifyAttribute response payload can be read from a buffer.
        """
        payload = payloads.ModifyAttributeResponsePayload()

        self.assertIsNone(payload.unique_identifier)
        self.assertIsNone(payload.attribute)

        payload.read(
            self.full_encoding_kmip_2_0,
            kmip_version=enums.KMIPVersion.KMIP_2_0
        )

        self.assertEqual(
            "b4faee10-aa2a-4446-8ad4-0881f3422959",
            payload.unique_identifier
        )
        self.assertIsNone(payload.attribute)

    def test_read_no_unique_identifier(self):
        """
        Test that an InvalidKmipEncoding error is raised when an invalid
        encoding containing no encoded unique identifier is used to decode
        a ModifyAttribute response payload.
        """
        payload = payloads.ModifyAttributeResponsePayload()
        args = (self.empty_encoding, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The ModifyAttribute response payload encoding is missing the "
            "unique identifier field.",
            payload.read,
            *args
        )

    def test_read_no_attribute(self):
        """
        Test that an InvalidKmipEncoding error is raised when an invalid
        encoding containing no encoded attribute is used to decode a
        ModifyAttribute response payload.
        """
        payload = payloads.ModifyAttributeResponsePayload()
        args = (self.full_encoding_kmip_2_0, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The ModifyAttribute response payload encoding is missing the "
            "attribute field.",
            payload.read,
            *args
        )

    def test_write(self):
        """
        Test that a ModifyAttribute response payload can be written to a
        buffer.
        """
        payload = payloads.ModifyAttributeResponsePayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959",
            attribute=objects.Attribute(
                attribute_name=objects.Attribute.AttributeName("x-attribute1"),
                attribute_value=primitives.TextString(
                    value="ModifiedValue1",
                    tag=enums.Tags.ATTRIBUTE_VALUE
                )
            )
        )

        buffer = utils.BytearrayStream()
        payload.write(buffer)

        self.assertEqual(len(self.full_encoding), len(buffer))
        self.assertEqual(str(self.full_encoding), str(buffer))

    def test_write_kmip_2_0(self):
        """
        Test that a ModifyAttribute response payload can be written to a
        buffer with KMIP 2.0 fields.
        """
        payload = payloads.ModifyAttributeResponsePayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959"
        )

        buffer = utils.BytearrayStream()
        payload.write(buffer, kmip_version=enums.KMIPVersion.KMIP_2_0)

        self.assertEqual(len(self.full_encoding_kmip_2_0), len(buffer))
        self.assertEqual(str(self.full_encoding_kmip_2_0), str(buffer))

    def test_write_no_unique_identifier(self):
        """
        Test that an InvalidField error is raised when attempting to write
        a ModifyAttribute response payload to a buffer with no unique
        identifier field specified.
        """
        payload = payloads.ModifyAttributeResponsePayload()

        args = (utils.BytearrayStream(), )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The ModifyAttribute response payload is missing the unique "
            "identifier field.",
            payload.write,
            *args
        )

    def test_write_no_attribute(self):
        """
        Test that an InvalidField error is raised when attempting to write
        a ModifyAttribute response payload to a buffer with no unique
        identifier field specified.
        """
        payload = payloads.ModifyAttributeResponsePayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959"
        )

        args = (utils.BytearrayStream(), )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The ModifyAttribute response payload is missing the attribute "
            "field.",
            payload.write,
            *args
        )

    def test_repr(self):
        """
        Test that repr can be applied to a ModifyAttribute response payload.
        """
        payload = payloads.ModifyAttributeResponsePayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959"
        )

        args = [
            "unique_identifier='b4faee10-aa2a-4446-8ad4-0881f3422959'",
            "attribute=None"
        ]
        self.assertEqual(
            "ModifyAttributeResponsePayload({})".format(", ".join(args)),
            repr(payload)
        )

    def test_str(self):
        """
        Test that str can be applied to a ModifyAttribute response payload.
        """
        payload = payloads.ModifyAttributeResponsePayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959"
        )
        s = str(
            {
                "unique_identifier": "b4faee10-aa2a-4446-8ad4-0881f3422959",
                "attribute": None
            }
        )
        self.assertEqual(s, str(payload))

    def test_comparison(self):
        """
        Test that the equality/inequality operators return True/False when
        comparing two ModifyAttribute response payloads with the same data.
        """
        a = payloads.ModifyAttributeResponsePayload()
        b = payloads.ModifyAttributeResponsePayload()

        self.assertTrue(a == b)
        self.assertTrue(b == a)
        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = payloads.ModifyAttributeResponsePayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959",
            attribute=objects.Attribute(
                attribute_name=objects.Attribute.AttributeName("x-attribute1"),
                attribute_value=primitives.TextString(
                    value="ModifiedValue1",
                    tag=enums.Tags.ATTRIBUTE_VALUE
                )
            )
        )
        b = payloads.ModifyAttributeResponsePayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959",
            attribute=objects.Attribute(
                attribute_name=objects.Attribute.AttributeName("x-attribute1"),
                attribute_value=primitives.TextString(
                    value="ModifiedValue1",
                    tag=enums.Tags.ATTRIBUTE_VALUE
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
        comparing two ModifyAttribute response payloads with different unique
        identifiers.
        """
        a = payloads.ModifyAttributeResponsePayload(unique_identifier="1")
        b = payloads.ModifyAttributeResponsePayload(unique_identifier="2")

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_comparison_on_different_attributes(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing two ModifyAttribute response payloads with different
        attributes.
        """
        a = payloads.ModifyAttributeResponsePayload(
            attribute=objects.Attribute(
                attribute_name=objects.Attribute.AttributeName("x-attribute1"),
                attribute_value=primitives.TextString(
                    value="ModifiedValue1",
                    tag=enums.Tags.ATTRIBUTE_VALUE
                )
            ))
        b = payloads.ModifyAttributeResponsePayload(
            attribute=objects.Attribute(
                attribute_name=objects.Attribute.AttributeName("x-attribute2"),
                attribute_value=primitives.TextString(
                    value="ModifiedValue2",
                    tag=enums.Tags.ATTRIBUTE_VALUE
                )
            ))

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_comparison_on_type_mismatch(self):
        """
        Test that the equality/inequality operators return False/True when
        comparining a ModifyAttribute response payload against a different
        type.
        """
        a = payloads.ModifyAttributeResponsePayload()
        b = "invalid"

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_init(self):
        """
        Test that a ModifyAttribute response payload can be constructed with
        no arguments.
        """
        payload = payloads.ModifyAttributeResponsePayload()
        self.assertIsNone(payload.unique_identifier)
        self.assertIsNone(payload.attribute)

    def test_init_with_args(self):
        """
        Test that a ModifyAttribute response payload can be constructed with
        valid values.
        """
        payload = payloads.ModifyAttributeResponsePayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959",
            attribute=objects.Attribute(
                attribute_name=objects.Attribute.AttributeName("x-attribute1"),
                attribute_value=primitives.TextString(
                    value="ModifiedValue1",
                    tag=enums.Tags.ATTRIBUTE_VALUE
                )
            )
        )

        self.assertEqual(
            "b4faee10-aa2a-4446-8ad4-0881f3422959",
            payload.unique_identifier
        )
        self.assertIsInstance(payload.attribute, objects.Attribute)

    def test_read_valid(self):
        """
        Test that a ModifyAttribute response payload can be read from a valid
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
        Test that a ModifyAttribute response payload can be written to a byte
        stream.
        """
        self.test_write()

    def test_read_write_roundtrip(self):
        """
        Test that a ModifyAttribute response payload can be read and written
        without changing the encoded bytes.
        """
        payload = payloads.ModifyAttributeResponsePayload()
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
        Test that a ModifyAttribute response payload compares equal to itself.
        """
        payload = payloads.ModifyAttributeResponsePayload()
        self.assertTrue(payload == payload)

    def test_ne(self):
        """
        Test that two different ModifyAttribute response payloads are not
        equal.
        """
        a = payloads.ModifyAttributeResponsePayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959"
        )
        b = payloads.ModifyAttributeResponsePayload(
            unique_identifier="11111111-2222-3333-4444-555555555555"
        )
        self.assertTrue(a != b)
