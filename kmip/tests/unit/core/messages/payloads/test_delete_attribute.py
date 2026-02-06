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

class TestDeleteAttributeRequestPayload(testtools.TestCase):
    """
    A unit test suite for the DeleteAttribute request payload.
    """

    def setUp(self):
        super(TestDeleteAttributeRequestPayload, self).setUp()

        # This encoding was adapted from test case 3.1.4-7 from the KMIP 1.1
        # test suite. The Attribute Index was manually added.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Unique Identifier - b4faee10-aa2a-4446-8ad4-0881f3422959
        #     Attribute Name - x-attribute1
        #     Attribute Index - 1
        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x58'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x62\x34\x66\x61\x65\x65\x31\x30\x2D\x61\x61\x32\x61\x2D\x34\x34'
            b'\x34\x36\x2D\x38\x61\x64\x34\x2D\x30\x38\x38\x31\x66\x33\x34\x32'
            b'\x32\x39\x35\x39\x00\x00\x00\x00'
            b'\x42\x00\x0A\x07\x00\x00\x00\x0C'
            b'\x78\x2D\x61\x74\x74\x72\x69\x62\x75\x74\x65\x31\x00\x00\x00\x00'
            b'\x42\x00\x09\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
        )

        # This encoding was taken from test case 3.1.4-7 from the KMIP 1.1
        # test suite.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Unique Identifier - b4faee10-aa2a-4446-8ad4-0881f3422959
        #     Attribute Name - x-attribute1
        self.no_attribute_index_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x48'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x62\x34\x66\x61\x65\x65\x31\x30\x2D\x61\x61\x32\x61\x2D\x34\x34'
            b'\x34\x36\x2D\x38\x61\x64\x34\x2D\x30\x38\x38\x31\x66\x33\x34\x32'
            b'\x32\x39\x35\x39\x00\x00\x00\x00'
            b'\x42\x00\x0A\x07\x00\x00\x00\x0C'
            b'\x78\x2D\x61\x74\x74\x72\x69\x62\x75\x74\x65\x31\x00\x00\x00\x00'
        )

        # This encoding was adapted from test case 3.1.4-7 from the KMIP 1.1
        # test suite. The current attribute and the attribute reference were
        # manually added.
        #
        # This encoding matches the following set of values.
        # Request Payload
        #     Unique Identifier - b4faee10-aa2a-4446-8ad4-0881f3422959
        #     Current Attribute
        #         Cryptographic Algorithm - AES
        #     Attribute Reference
        #         Vendor Identification - Acme Corporation
        #         Attribute Name - Delivery Date
        self.full_encoding_kmip_2_0 = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x80'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x62\x34\x66\x61\x65\x65\x31\x30\x2D\x61\x61\x32\x61\x2D\x34\x34'
            b'\x34\x36\x2D\x38\x61\x64\x34\x2D\x30\x38\x38\x31\x66\x33\x34\x32'
            b'\x32\x39\x35\x39\x00\x00\x00\x00'
            b'\x42\x01\x3C\x01\x00\x00\x00\x10'
            b'\x42\x00\x28\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x01\x3B\x01\x00\x00\x00\x30'
            b'\x42\x00\x9D\x07\x00\x00\x00\x10'
            b'\x41\x63\x6D\x65\x20\x43\x6F\x72\x70\x6F\x72\x61\x74\x69\x6F\x6E'
            b'\x42\x00\x0A\x07\x00\x00\x00\x0D'
            b'\x44\x65\x6C\x69\x76\x65\x72\x79\x20\x44\x61\x74\x65\x00\x00\x00'
        )

        # This encoding was adapted from test case 3.1.4-7 from the KMIP 1.1
        # test suite. The current attribute and the attribute reference were
        # manually added.
        #
        # This encoding matches the following set of values.
        # Request Payload
        #     Unique Identifier - b4faee10-aa2a-4446-8ad4-0881f3422959
        #     Attribute Reference
        #         Vendor Identification - Acme Corporation
        #         Attribute Name - Delivery Date
        self.no_current_attribute_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x68'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x62\x34\x66\x61\x65\x65\x31\x30\x2D\x61\x61\x32\x61\x2D\x34\x34'
            b'\x34\x36\x2D\x38\x61\x64\x34\x2D\x30\x38\x38\x31\x66\x33\x34\x32'
            b'\x32\x39\x35\x39\x00\x00\x00\x00'
            b'\x42\x01\x3B\x01\x00\x00\x00\x30'
            b'\x42\x00\x9D\x07\x00\x00\x00\x10'
            b'\x41\x63\x6D\x65\x20\x43\x6F\x72\x70\x6F\x72\x61\x74\x69\x6F\x6E'
            b'\x42\x00\x0A\x07\x00\x00\x00\x0D'
            b'\x44\x65\x6C\x69\x76\x65\x72\x79\x20\x44\x61\x74\x65\x00\x00\x00'
        )

        # This encoding was adapted from test case 3.1.4-7 from the KMIP 1.1
        # test suite. The current attribute and the attribute reference were
        # manually added.
        #
        # This encoding matches the following set of values.
        # Request Payload
        #     Unique Identifier - b4faee10-aa2a-4446-8ad4-0881f3422959
        #     Current Attribute
        #         Cryptographic Algorithm - AES
        self.no_attribute_reference_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x48'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x62\x34\x66\x61\x65\x65\x31\x30\x2D\x61\x61\x32\x61\x2D\x34\x34'
            b'\x34\x36\x2D\x38\x61\x64\x34\x2D\x30\x38\x38\x31\x66\x33\x34\x32'
            b'\x32\x39\x35\x39\x00\x00\x00\x00'
            b'\x42\x01\x3C\x01\x00\x00\x00\x10'
            b'\x42\x00\x28\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
        )

        self.empty_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestDeleteAttributeRequestPayload, self).tearDown()

    def test_invalid_unique_identifier(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the unique identifier of a DeleteAttribute request payload.
        """
        kwargs = {"unique_identifier": 0}
        self.assertRaisesRegex(
            TypeError,
            "The unique identifier must be a string.",
            payloads.DeleteAttributeRequestPayload,
            **kwargs
        )

        args = (
            payloads.DeleteAttributeRequestPayload(),
            "unique_identifier",
            0
        )
        self.assertRaisesRegex(
            TypeError,
            "The unique identifier must be a string.",
            setattr,
            *args
        )

    def test_invalid_attribute_name(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the attribute name of a DeleteAttribute request payload.
        """
        kwargs = {"attribute_name": 0}
        self.assertRaisesRegex(
            TypeError,
            "The attribute name must be a string.",
            payloads.DeleteAttributeRequestPayload,
            **kwargs
        )

        args = (
            payloads.DeleteAttributeRequestPayload(),
            "attribute_name",
            0
        )
        self.assertRaisesRegex(
            TypeError,
            "The attribute name must be a string.",
            setattr,
            *args
        )

    def test_invalid_attribute_index(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the attribute index of a DeleteAttribute request payload.
        """
        kwargs = {"attribute_index": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The attribute index must be an integer.",
            payloads.DeleteAttributeRequestPayload,
            **kwargs
        )

        args = (
            payloads.DeleteAttributeRequestPayload(),
            "attribute_index",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The attribute index must be an integer.",
            setattr,
            *args
        )

    def test_invalid_current_attribute(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the current attribute of a DeleteAttribute request payload.
        """
        kwargs = {"current_attribute": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The current attribute must be a CurrentAttribute object.",
            payloads.DeleteAttributeRequestPayload,
            **kwargs
        )

        args = (
            payloads.DeleteAttributeRequestPayload(),
            "current_attribute",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The current attribute must be a CurrentAttribute object.",
            setattr,
            *args
        )

    def test_invalid_attribute_reference(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the attribute reference of a DeleteAttribute request payload.
        """
        kwargs = {"attribute_reference": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The attribute reference must be an AttributeReference object.",
            payloads.DeleteAttributeRequestPayload,
            **kwargs
        )

        args = (
            payloads.DeleteAttributeRequestPayload(),
            "attribute_reference",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The attribute reference must be an AttributeReference object.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a DeleteAttribute request payload can be read from a buffer.
        """
        payload = payloads.DeleteAttributeRequestPayload()

        self.assertIsNone(payload.unique_identifier)
        self.assertIsNone(payload.attribute_name)
        self.assertIsNone(payload.attribute_index)
        self.assertIsNone(payload.current_attribute)
        self.assertIsNone(payload.attribute_reference)

        payload.read(self.full_encoding)

        self.assertEqual(
            "b4faee10-aa2a-4446-8ad4-0881f3422959",
            payload.unique_identifier
        )
        self.assertEqual("x-attribute1", payload.attribute_name)
        self.assertEqual(1, payload.attribute_index)
        self.assertIsNone(payload.current_attribute)
        self.assertIsNone(payload.attribute_reference)

    def test_read_kmip_2_0(self):
        """
        Test that a DeleteAttribute request payload can be read from a buffer
        with KMIP 2.0 features.
        """
        payload = payloads.DeleteAttributeRequestPayload()

        self.assertIsNone(payload.unique_identifier)
        self.assertIsNone(payload.attribute_name)
        self.assertIsNone(payload.attribute_index)
        self.assertIsNone(payload.current_attribute)
        self.assertIsNone(payload.attribute_reference)

        payload.read(
            self.full_encoding_kmip_2_0,
            kmip_version=enums.KMIPVersion.KMIP_2_0
        )

        self.assertEqual(
            "b4faee10-aa2a-4446-8ad4-0881f3422959",
            payload.unique_identifier
        )
        self.assertIsNone(payload.attribute_name)
        self.assertIsNone(payload.attribute_index)
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
            objects.AttributeReference(
                vendor_identification="Acme Corporation",
                attribute_name="Delivery Date"
            ),
            payload.attribute_reference
        )

    def test_read_no_attribute_name(self):
        """
        Test that an InvalidKmipEncoding error is raised when an invalid
        encoding containing no encoded attribute name is used to decode
        a DeleteAttribute request payload.
        """
        payload = payloads.DeleteAttributeRequestPayload()
        args = (self.empty_encoding, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The DeleteAttribute request payload encoding is missing the "
            "attribute name field.",
            payload.read,
            *args
        )

    def test_read_kmip_2_0_no_current_attribute_or_attribute_reference(self):
        """
        Test that an InvalidKmipEncoding error is raised when an invalid
        encoding containing no encoded current attribute or attribute
        reference is used to decode a DeleteAttribute request payload.
        """
        payload = payloads.DeleteAttributeRequestPayload()
        args = (self.empty_encoding, )
        kwargs = {"kmip_version": enums.KMIPVersion.KMIP_2_0}
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The DeleteAttribute encoding is missing either the current "
            "attribute or the attribute reference field.",
            payload.read,
            *args,
            **kwargs
        )

    def test_read_no_attribute_index(self):
        """
        Test that a DeleteAttribute request payload can be read from a buffer
        without including the attribute index encoding.
        """
        payload = payloads.DeleteAttributeRequestPayload()

        self.assertIsNone(payload.unique_identifier)
        self.assertIsNone(payload.attribute_name)
        self.assertIsNone(payload.attribute_index)
        self.assertIsNone(payload.current_attribute)
        self.assertIsNone(payload.attribute_reference)

        payload.read(self.no_attribute_index_encoding)

        self.assertEqual(
            "b4faee10-aa2a-4446-8ad4-0881f3422959",
            payload.unique_identifier
        )
        self.assertEqual("x-attribute1", payload.attribute_name)
        self.assertIsNone(payload.attribute_index)
        self.assertIsNone(payload.current_attribute)
        self.assertIsNone(payload.attribute_reference)

    def test_read_no_current_attribute(self):
        """
        Test that a DeleteAttribute request payload can be read from a buffer
        without including the current attribute encoding.
        """
        payload = payloads.DeleteAttributeRequestPayload()

        self.assertIsNone(payload.unique_identifier)
        self.assertIsNone(payload.attribute_name)
        self.assertIsNone(payload.attribute_index)
        self.assertIsNone(payload.current_attribute)
        self.assertIsNone(payload.attribute_reference)

        payload.read(
            self.no_current_attribute_encoding,
            kmip_version=enums.KMIPVersion.KMIP_2_0
        )

        self.assertEqual(
            "b4faee10-aa2a-4446-8ad4-0881f3422959",
            payload.unique_identifier
        )
        self.assertIsNone(payload.attribute_name)
        self.assertIsNone(payload.attribute_index)
        self.assertIsNone(payload.current_attribute)
        self.assertEqual(
            objects.AttributeReference(
                vendor_identification="Acme Corporation",
                attribute_name="Delivery Date"
            ),
            payload.attribute_reference
        )

    def test_read_no_attribute_reference(self):
        """
        Test that a DeleteAttribute request payload can be read from a buffer
        without including the attribute reference encoding.
        """
        payload = payloads.DeleteAttributeRequestPayload()

        self.assertIsNone(payload.unique_identifier)
        self.assertIsNone(payload.attribute_name)
        self.assertIsNone(payload.attribute_index)
        self.assertIsNone(payload.current_attribute)
        self.assertIsNone(payload.attribute_reference)

        payload.read(
            self.no_attribute_reference_encoding,
            kmip_version=enums.KMIPVersion.KMIP_2_0
        )

        self.assertEqual(
            "b4faee10-aa2a-4446-8ad4-0881f3422959",
            payload.unique_identifier
        )
        self.assertIsNone(payload.attribute_name)
        self.assertIsNone(payload.attribute_index)
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
        self.assertIsNone(payload.attribute_reference)

    def test_write(self):
        """
        Test that a DeleteAttribute request payload can be written to a buffer.
        """
        payload = payloads.DeleteAttributeRequestPayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959",
            attribute_name="x-attribute1",
            attribute_index=1
        )

        buffer = utils.BytearrayStream()
        payload.write(buffer)

        self.assertEqual(len(self.full_encoding), len(buffer))
        self.assertEqual(str(self.full_encoding), str(buffer))

    def test_write_kmip_2_0(self):
        """
        Test that a DeleteAttribute request payload can be written to a buffer
        with KMIP 2.0 features.
        """
        payload = payloads.DeleteAttributeRequestPayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959",
            current_attribute=objects.CurrentAttribute(
                attribute=primitives.Enumeration(
                    enums.CryptographicAlgorithm,
                    enums.CryptographicAlgorithm.AES,
                    enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                )
            ),
            attribute_reference=objects.AttributeReference(
                vendor_identification="Acme Corporation",
                attribute_name="Delivery Date"
            )
        )

        buffer = utils.BytearrayStream()
        payload.write(buffer, kmip_version=enums.KMIPVersion.KMIP_2_0)

        self.assertEqual(len(self.full_encoding_kmip_2_0), len(buffer))
        self.assertEqual(str(self.full_encoding_kmip_2_0), str(buffer))

    def test_write_no_attribute_name(self):
        """
        Test that an InvalidField error is raised when attempting to write
        a DeleteAttribute request payload to a buffer with no attribute name
        field specified.
        """
        payload = payloads.DeleteAttributeRequestPayload()

        args = (utils.BytearrayStream(), )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The DeleteAttribute request payload is missing the attribute "
            "name field.",
            payload.write,
            *args
        )

    def test_write_no_current_attribute_or_attribute_reference(self):
        """
        Test that an InvalidField error is raised when attempting to write
        a DeleteAttribute request payload to a buffer with KMIP 2.0 features
        with no current attribute or attribute reference field specified.
        """
        payload = payloads.DeleteAttributeRequestPayload()

        args = (utils.BytearrayStream(), )
        kwargs = {"kmip_version": enums.KMIPVersion.KMIP_2_0}
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The DeleteAttribute request payload is missing either the "
            "current attribute or the attribute reference field.",
            payload.write,
            *args,
            **kwargs
        )

    def test_repr(self):
        """
        Test that repr can be applied to a DeleteAttribute request payload.
        """
        payload = payloads.DeleteAttributeRequestPayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959",
            attribute_name="x-attribute1",
            attribute_index=1
        )

        args = [
            "unique_identifier='b4faee10-aa2a-4446-8ad4-0881f3422959'",
            "attribute_name='x-attribute1'",
            "attribute_index=1",
            "current_attribute=None",
            "attribute_reference=None"
        ]
        self.assertEqual(
            "DeleteAttributeRequestPayload({})".format(", ".join(args)),
            repr(payload)
        )

    def test_str(self):
        """
        Test that str can be applied to a DeleteAttribute request payload.
        """
        payload = payloads.DeleteAttributeRequestPayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959",
            attribute_name="x-attribute1",
            attribute_index=1
        )
        s = str(
            {
                "unique_identifier": "b4faee10-aa2a-4446-8ad4-0881f3422959",
                "attribute_name": "x-attribute1",
                "attribute_index": 1,
                "current_attribute": None,
                "attribute_reference": None
            }
        )
        self.assertEqual(s, str(payload))

    def test_comparison(self):
        """
        Test that the equality/inequality operators return True/False when
        comparing two DeleteAttribute request payloads with the same data.
        """
        a = payloads.DeleteAttributeRequestPayload()
        b = payloads.DeleteAttributeRequestPayload()

        self.assertTrue(a == b)
        self.assertTrue(b == a)
        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = payloads.DeleteAttributeRequestPayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959",
            attribute_name="x-attribute1",
            attribute_index=1,
            current_attribute=objects.CurrentAttribute(
                attribute=primitives.Enumeration(
                    enums.CryptographicAlgorithm,
                    enums.CryptographicAlgorithm.AES,
                    enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                )
            ),
            attribute_reference=objects.AttributeReference(
                vendor_identification="Acme Corporation",
                attribute_name="Delivery Date"
            )
        )
        b = payloads.DeleteAttributeRequestPayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959",
            attribute_name="x-attribute1",
            attribute_index=1,
            current_attribute=objects.CurrentAttribute(
                attribute=primitives.Enumeration(
                    enums.CryptographicAlgorithm,
                    enums.CryptographicAlgorithm.AES,
                    enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                )
            ),
            attribute_reference=objects.AttributeReference(
                vendor_identification="Acme Corporation",
                attribute_name="Delivery Date"
            )
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)
        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_comparison_on_different_unique_identifiers(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing two DeleteAttribute request payloads with different unique
        identifiers.
        """
        a = payloads.DeleteAttributeRequestPayload(unique_identifier="1")
        b = payloads.DeleteAttributeRequestPayload(unique_identifier="2")

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_comparison_on_different_attribute_names(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing two DeleteAttribute request payloads with different
        attribute names.
        """
        a = payloads.DeleteAttributeRequestPayload(attribute_name="1")
        b = payloads.DeleteAttributeRequestPayload(attribute_name="2")

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_comparison_on_different_attribute_indices(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing two DeleteAttribute request payloads with different
        attribute indices.
        """
        a = payloads.DeleteAttributeRequestPayload(attribute_index=1)
        b = payloads.DeleteAttributeRequestPayload(attribute_index=2)

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_comparison_on_different_current_attributes(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing two DeleteAttribute request payloads with different current
        attributes.
        """
        a = payloads.DeleteAttributeRequestPayload(
            current_attribute=objects.CurrentAttribute(
                attribute=primitives.Enumeration(
                    enums.CryptographicAlgorithm,
                    enums.CryptographicAlgorithm.AES,
                    enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                )
            )
        )
        b = payloads.DeleteAttributeRequestPayload(
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

    def test_comparison_on_different_attribute_references(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing two DeleteAttribute request payloads with different
        attribute references.
        """
        a = payloads.DeleteAttributeRequestPayload(
            attribute_reference=objects.AttributeReference(
                vendor_identification="Acme Corporation",
                attribute_name="Delivery Date"
            )
        )
        b = payloads.DeleteAttributeRequestPayload(
            attribute_reference=objects.AttributeReference(
                vendor_identification="Acme Corporation",
                attribute_name="Delivery Estimate"
            )
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_comparison_on_type_mismatch(self):
        """
        Test that the equality/inequality operators return False/True when
        comparining a DeleteAttribute request payload against a different type.
        """
        a = payloads.DeleteAttributeRequestPayload()
        b = "invalid"

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_init(self):
        """
        Test that a DeleteAttribute request payload can be constructed with no
        arguments.
        """
        payload = payloads.DeleteAttributeRequestPayload()
        self.assertIsNone(payload.unique_identifier)
        self.assertIsNone(payload.attribute_name)
        self.assertIsNone(payload.attribute_index)
        self.assertIsNone(payload.current_attribute)
        self.assertIsNone(payload.attribute_reference)

    def test_init_with_args(self):
        """
        Test that a DeleteAttribute request payload can be constructed with
        valid values.
        """
        payload = payloads.DeleteAttributeRequestPayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959",
            attribute_name="x-attribute1",
            attribute_index=1
        )

        self.assertEqual(
            "b4faee10-aa2a-4446-8ad4-0881f3422959",
            payload.unique_identifier
        )
        self.assertEqual("x-attribute1", payload.attribute_name)
        self.assertEqual(1, payload.attribute_index)

    def test_read_valid(self):
        """
        Test that a DeleteAttribute request payload can be read from a valid
        byte stream.
        """
        self.test_read()

    def test_read_missing_required_field(self):
        """
        Test that an exception is raised when reading a payload missing a
        required field.
        """
        self.test_read_no_attribute_name()

    def test_write_valid(self):
        """
        Test that a DeleteAttribute request payload can be written to a byte
        stream.
        """
        self.test_write()

    def test_read_write_roundtrip(self):
        """
        Test that a DeleteAttribute request payload can be read and written
        without changing the encoded bytes.
        """
        payload = payloads.DeleteAttributeRequestPayload()
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
        Test that a DeleteAttribute request payload compares equal to itself.
        """
        payload = payloads.DeleteAttributeRequestPayload()
        self.assertTrue(payload == payload)

    def test_ne(self):
        """
        Test that two different DeleteAttribute request payloads are not
        equal.
        """
        a = payloads.DeleteAttributeRequestPayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959"
        )
        b = payloads.DeleteAttributeRequestPayload(
            unique_identifier="11111111-2222-3333-4444-555555555555"
        )
        self.assertTrue(a != b)

class TestDeleteAttributeResponsePayload(testtools.TestCase):
    """
    A unit test suite for the DeleteAttribute response payload.
    """

    def setUp(self):
        super(TestDeleteAttributeResponsePayload, self).setUp()

        # This encoding was taken from test case 3.1.4-7 from the KMIP 1.1
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

        # This encoding was adapted from test case 3.1.4-7 from the KMIP 1.1
        # test suite. The attribute field was removed.
        #
        # This encoding matches the following set of values:
        # Response Payload
        #     Unique Identifier - b4faee10-aa2a-4446-8ad4-0881f3422959
        self.no_attribute_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x30'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x62\x34\x66\x61\x65\x65\x31\x30\x2D\x61\x61\x32\x61\x2D\x34\x34'
            b'\x34\x36\x2D\x38\x61\x64\x34\x2D\x30\x38\x38\x31\x66\x33\x34\x32'
            b'\x32\x39\x35\x39\x00\x00\x00\x00'
        )

        # This encoding was adapt from test case 3.1.4-7 from the KMIP 1.1
        # test suite. The attribute field was removed.
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
        super(TestDeleteAttributeResponsePayload, self).tearDown()

    def test_invalid_unique_identifier(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the unique identifier of a DeleteAttribute response payload.
        """
        kwargs = {"unique_identifier": 0}
        self.assertRaisesRegex(
            TypeError,
            "The unique identifier must be a string.",
            payloads.DeleteAttributeResponsePayload,
            **kwargs
        )

        args = (
            payloads.DeleteAttributeResponsePayload(),
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
        the attribute of a DeleteAttribute response payload.
        """
        kwargs = {"attribute": 0}
        self.assertRaisesRegex(
            TypeError,
            "The attribute must be an Attribute object.",
            payloads.DeleteAttributeResponsePayload,
            **kwargs
        )

        args = (
            payloads.DeleteAttributeResponsePayload(),
            "attribute",
            0
        )
        self.assertRaisesRegex(
            TypeError,
            "The attribute must be an Attribute object.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a DeleteAttribute response payload can be read from a buffer.
        """
        payload = payloads.DeleteAttributeResponsePayload()

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
                    "ModifiedValue1",
                    tag=enums.Tags.ATTRIBUTE_VALUE
                )
            ),
            payload.attribute
        )

    def test_read_kmip_2_0(self):
        """
        Test that a DeleteAttribute response payload can be read from a buffer
        with KMIP 2.0 features.
        """
        payload = payloads.DeleteAttributeResponsePayload()

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
        a DeleteAttribute response payload.
        """
        payload = payloads.DeleteAttributeResponsePayload()
        args = (self.empty_encoding, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The DeleteAttribute response payload encoding is missing the "
            "unique identifier field.",
            payload.read,
            *args
        )

    def test_read_no_attribute(self):
        """
        Test that an InvalidKmipEncoding error is raised when an invalid
        encoding containing no encoded attribute is used to decode a
        DeleteAttribute response payload.
        """
        payload = payloads.DeleteAttributeResponsePayload()
        args = (self.no_attribute_encoding, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The DeleteAttribute response payload encoding is missing the "
            "attribute field.",
            payload.read,
            *args
        )

    def test_write(self):
        """
        Test that a DeleteAttribute response payload can be written to a
        buffer.
        """
        payload = payloads.DeleteAttributeResponsePayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959",
            attribute=objects.Attribute(
                attribute_name=objects.Attribute.AttributeName("x-attribute1"),
                attribute_value=primitives.TextString(
                    "ModifiedValue1",
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
        Test that a DeleteAttribute response payload can be written to a buffer
        with KMIP 2.0 features.
        """
        payload = payloads.DeleteAttributeResponsePayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959"
        )

        buffer = utils.BytearrayStream()
        payload.write(buffer, kmip_version=enums.KMIPVersion.KMIP_2_0)

        self.assertEqual(len(self.full_encoding_kmip_2_0), len(buffer))
        self.assertEqual(str(self.full_encoding_kmip_2_0), str(buffer))

    def test_write_no_unique_identifier(self):
        """
        Test that an InvalidField error is raised when attempting to write
        a DeleteAttribute response payload to a buffer with no unique
        identifier field specified.
        """
        payload = payloads.DeleteAttributeResponsePayload()

        args = (utils.BytearrayStream(), )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The DeleteAttribute response payload is missing the unique "
            "identifier field.",
            payload.write,
            *args
        )

    def test_write_no_attribute(self):
        """
        Test that an InvalidField error is raised when attempting to write
        a DeleteAttribute response payload to a buffer with no attribute field
        specified.
        """
        payload = payloads.DeleteAttributeResponsePayload(
            unique_identifier="1"
        )

        args = (utils.BytearrayStream(), )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The DeleteAttribute response payload is missing the attribute "
            "field.",
            payload.write,
            *args
        )

    def test_repr(self):
        """
        Test that repr can be applied to a DeleteAttribute response payload.
        """
        payload = payloads.DeleteAttributeResponsePayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959",
            attribute=objects.Attribute(
                attribute_name=objects.Attribute.AttributeName("x-attribute1"),
                attribute_value=primitives.TextString(
                    "ModifiedValue1",
                    tag=enums.Tags.ATTRIBUTE_VALUE
                )
            )
        )

        args = [
            "unique_identifier='b4faee10-aa2a-4446-8ad4-0881f3422959'",
            "attribute=Attribute("
            "attribute_name=AttributeName(value='x-attribute1'), "
            "attribute_index=None, "
            "attribute_value=TextString(value='ModifiedValue1'))"
        ]
        self.assertEqual(
            "DeleteAttributeResponsePayload({})".format(", ".join(args)),
            repr(payload)
        )

    def test_str(self):
        """
        Test that str can be applied to a DeleteAttribute response payload.
        """
        payload = payloads.DeleteAttributeResponsePayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959",
            attribute=objects.Attribute(
                attribute_name=objects.Attribute.AttributeName("x-attribute1"),
                attribute_value=primitives.TextString(
                    "ModifiedValue1",
                    tag=enums.Tags.ATTRIBUTE_VALUE
                )
            )
        )
        s = str(
            {
                "unique_identifier": "b4faee10-aa2a-4446-8ad4-0881f3422959",
                "attribute": str(
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "x-attribute1"
                        ),
                        attribute_value=primitives.TextString(
                            "ModifiedValue1",
                            tag=enums.Tags.ATTRIBUTE_VALUE
                        )
                    )
                )
            }
        )
        self.assertEqual(s, str(payload))

    def test_comparison(self):
        """
        Test that the equality/inequality operators return True/False when
        comparing two DeleteAttribute response payloads with the same data.
        """
        a = payloads.DeleteAttributeResponsePayload()
        b = payloads.DeleteAttributeResponsePayload()

        self.assertTrue(a == b)
        self.assertTrue(b == a)
        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = payloads.DeleteAttributeResponsePayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959",
            attribute=objects.Attribute(
                attribute_name=objects.Attribute.AttributeName("x-attribute1"),
                attribute_value=primitives.TextString(
                    "ModifiedValue1",
                    tag=enums.Tags.ATTRIBUTE_VALUE
                )
            )
        )
        b = payloads.DeleteAttributeResponsePayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959",
            attribute=objects.Attribute(
                attribute_name=objects.Attribute.AttributeName("x-attribute1"),
                attribute_value=primitives.TextString(
                    "ModifiedValue1",
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
        comparing two DeleteAttribute response payloads with different unique
        identifiers.
        """
        a = payloads.DeleteAttributeResponsePayload(unique_identifier="1")
        b = payloads.DeleteAttributeResponsePayload(unique_identifier="2")

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_comparison_on_different_attributes(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing two DeleteAttribute response payloads with different
        attributes.
        """
        a = payloads.DeleteAttributeResponsePayload(
            attribute=objects.Attribute(
                attribute_name=objects.Attribute.AttributeName("x-attribute1"),
                attribute_value=primitives.TextString(
                    "ModifiedValue1",
                    tag=enums.Tags.ATTRIBUTE_VALUE
                )
            )
        )
        b = payloads.DeleteAttributeResponsePayload(
            attribute=objects.Attribute(
                attribute_name=objects.Attribute.AttributeName("x-attribute2"),
                attribute_value=primitives.TextString(
                    "ModifiedValue2",
                    tag=enums.Tags.ATTRIBUTE_VALUE
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
        comparining a DeleteAttribute response payload against a different
        type.
        """
        a = payloads.DeleteAttributeResponsePayload()
        b = "invalid"

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_init(self):
        """
        Test that a DeleteAttribute response payload can be constructed with
        no arguments.
        """
        payload = payloads.DeleteAttributeResponsePayload()
        self.assertIsNone(payload.unique_identifier)
        self.assertIsNone(payload.attribute)

    def test_init_with_args(self):
        """
        Test that a DeleteAttribute response payload can be constructed with
        valid values.
        """
        payload = payloads.DeleteAttributeResponsePayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959",
            attribute=objects.Attribute(
                attribute_name=objects.Attribute.AttributeName("x-attribute1"),
                attribute_value=primitives.TextString(
                    "ModifiedValue1",
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
        Test that a DeleteAttribute response payload can be read from a valid
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
        Test that a DeleteAttribute response payload can be written to a byte
        stream.
        """
        self.test_write()

    def test_read_write_roundtrip(self):
        """
        Test that a DeleteAttribute response payload can be read and written
        without changing the encoded bytes.
        """
        payload = payloads.DeleteAttributeResponsePayload()
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
        Test that a DeleteAttribute response payload compares equal to itself.
        """
        payload = payloads.DeleteAttributeResponsePayload()
        self.assertTrue(payload == payload)

    def test_ne(self):
        """
        Test that two different DeleteAttribute response payloads are not
        equal.
        """
        a = payloads.DeleteAttributeResponsePayload(
            unique_identifier="b4faee10-aa2a-4446-8ad4-0881f3422959"
        )
        b = payloads.DeleteAttributeResponsePayload(
            unique_identifier="11111111-2222-3333-4444-555555555555"
        )
        self.assertTrue(a != b)
