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


class TestCurrentAttribute(testtools.TestCase):
    """
    A unit test suite for the CurrentAttribute structure.
    """

    def setUp(self):
        super(TestCurrentAttribute, self).setUp()

        # This encoding matches the following set of values:
        # CurrentAttribute
        #     Cryptographic Algorithm - AES
        self.full_encoding = utils.BytearrayStream(
            b'\x42\x01\x3C\x01\x00\x00\x00\x10'
            b'\x42\x00\x28\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
        )

        self.empty_encoding = utils.BytearrayStream(
            b'\x42\x01\x3C\x01\x00\x00\x00\x00'
        )

        # This encoding matches the following set of values:
        # CurrentAttribute
        #     Non-existent Tag
        self.invalid_encoding = utils.BytearrayStream(
            b'\x42\x01\x3C\x01\x00\x00\x00\x10'
            b'\x42\xFF\xFF\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
        )

        # This encoding matches the following set of values:
        # CurrentAttribute
        #     Operation Policy Name - b4faee10-aa2a-4446-8ad4-0881f3422959
        self.unsupported_encoding = utils.BytearrayStream(
            b'\x42\x01\x3C\x01\x00\x00\x00\x30'
            b'\x42\x00\x5D\x07\x00\x00\x00\x24\x62\x34\x66\x61\x65\x65\x31\x30'
            b'\x2D\x61\x61\x32\x61\x2D\x34\x34\x34\x36\x2D\x38\x61\x64\x34\x2D'
            b'\x30\x38\x38\x31\x66\x33\x34\x32\x32\x39\x35\x39\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestCurrentAttribute, self).tearDown()

    def test_unrecognized_attribute(self):
        """
        Test that a TypeError is raised when an unrecognized attribute is used
        to create a CurrentAttribute object. Note that this unrecognized
        attribute is a valid PyKMIP object derived from Base, it just isn't an
        attribute.
        """
        kwargs = {
            "attribute": primitives.Enumeration(
                enums.WrappingMethod,
                enums.WrappingMethod.ENCRYPT,
                enums.Tags.WRAPPING_METHOD
            )
        }
        self.assertRaisesRegex(
            TypeError,
            "The attribute must be a supported attribute type.",
            objects.CurrentAttribute,
            **kwargs
        )

        args = (
            objects.CurrentAttribute(),
            "attribute",
            primitives.Enumeration(
                enums.WrappingMethod,
                enums.WrappingMethod.ENCRYPT,
                enums.Tags.WRAPPING_METHOD
            )
        )
        self.assertRaisesRegex(
            TypeError,
            "The attribute must be a supported attribute type.",
            setattr,
            *args
        )

    def test_invalid_attribute(self):
        """
        Test that a TypeError is raised when an invalid value is used to
        create a CurrentAttribute object. Note that the value is not a valid
        PyKMIP object derived from Base and therefore cannot be an attribute.
        """
        kwargs = {"attribute": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The attribute must be a Base object, not a {}.".format(
                type("invalid")
            ),
            objects.CurrentAttribute,
            **kwargs
        )

        args = (
            objects.CurrentAttribute(),
            "attribute",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The attribute must be a Base object, not a {}.".format(
                type("invalid")
            ),
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a CurrentAttribute structure can be correctly read in from
        a data stream.
        """
        current_attribute = objects.CurrentAttribute()

        self.assertIsNone(current_attribute.attribute)

        current_attribute.read(self.full_encoding)

        self.assertIsInstance(
            current_attribute.attribute,
            primitives.Enumeration
        )
        self.assertEqual(
            current_attribute.attribute.value,
            enums.CryptographicAlgorithm.AES
        )

    def test_read_no_attribute(self):
        """
        Test that an InvalidKmipEncoding error is raised when an invalid
        encoding with no encoded attribute is used to decode a CurrentAttribute
        object.
        """
        current_attribute = objects.CurrentAttribute()
        args = (self.empty_encoding, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The CurrentAttribute encoding is missing the attribute field.",
            current_attribute.read,
            *args
        )

    def test_read_invalid_attribute(self):
        """
        Test that an InvalidKmipEncoding error is raised when an invalid
        encoding containing an invalid attribute is used to decode a
        CurrentAttribute object.
        """
        current_attribute = objects.CurrentAttribute()
        args = (self.invalid_encoding, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The CurrentAttribute encoding is missing the attribute field.",
            current_attribute.read,
            *args
        )

    def test_read_unsupported_attribute(self):
        """
        Test that an AttributeNotSupported error is raised when an unsupported
        attribute is parsed while reading in a CurrentAttribute object from a
        data stream. This can occur when an older attribute is no longer
        supported by a newer version of KMIP, or vice versa.
        """
        current_attribute = objects.CurrentAttribute()
        args = (self.unsupported_encoding, )
        kwargs = {"kmip_version": enums.KMIPVersion.KMIP_2_0}
        self.assertRaisesRegex(
            exceptions.AttributeNotSupported,
            "Attribute OPERATION_POLICY_NAME is not supported by KMIP 2.0.",
            current_attribute.read,
            *args,
            **kwargs
        )

    def test_read_version_not_supported(self):
        """
        Test that a VersionNotSupported error is raised when an unsupported
        KMIP version is provided while reading in a CurrentAttribute object
        from a data stream. The CurrentAttribute structure is only supported
        in KMIP 2.0+.
        """
        current_attribute = objects.CurrentAttribute()
        args = (self.full_encoding, )
        kwargs = {"kmip_version": enums.KMIPVersion.KMIP_1_2}
        self.assertRaisesRegex(
            exceptions.VersionNotSupported,
            "KMIP 1.2 does not support the CurrentAttribute object.",
            current_attribute.read,
            *args,
            **kwargs
        )

    def test_write(self):
        """
        Test that a CurrentAttribute object can be written to a data stream.
        """
        current_attribute = objects.CurrentAttribute(
            attribute=primitives.Enumeration(
                enums.CryptographicAlgorithm,
                enums.CryptographicAlgorithm.AES,
                enums.Tags.CRYPTOGRAPHIC_ALGORITHM
            )
        )

        stream = utils.BytearrayStream()
        current_attribute.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_no_attribute(self):
        """
        Test that an InvalidField error is raised when an empty
        CurrentAttribute object is written to a data stream.
        """
        current_attribute = objects.CurrentAttribute()
        args = (utils.BytearrayStream(), )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The CurrentAttribute object is missing the attribute field.",
            current_attribute.write,
            *args
        )

    def test_write_unsupported_attribute(self):
        """
        Test that an AttributeNotSupported error is raised when an unsupported
        attribute is found while writing a CurrentAttribute object to a data
        stream. This can occur when an older attribute is no longer supported
        by a newer version of KMIP, or vice versa.
        """
        current_attribute = objects.CurrentAttribute(
            attribute=primitives.TextString(
                "default",
                tag=enums.Tags.OPERATION_POLICY_NAME
            )
        )
        args = (utils.BytearrayStream(), )
        kwargs = {"kmip_version": enums.KMIPVersion.KMIP_2_0}
        self.assertRaisesRegex(
            exceptions.AttributeNotSupported,
            "Attribute OPERATION_POLICY_NAME is not supported by KMIP 2.0.",
            current_attribute.write,
            *args,
            **kwargs
        )

    def test_write_version_not_supported(self):
        """
        Test that a VersionNotSupported error is raised when an unsupported
        KMIP version is provided while writing a CurrentAttribute object to
        a data stream. The CurrentAttribute structure is only supported in
        KMIP 2.0+.
        """
        current_attribute = objects.CurrentAttribute()
        args = (utils.BytearrayStream(), )
        kwargs = {"kmip_version": enums.KMIPVersion.KMIP_1_4}
        self.assertRaisesRegex(
            exceptions.VersionNotSupported,
            "KMIP 1.4 does not support the CurrentAttribute object.",
            current_attribute.write,
            *args,
            **kwargs
        )

    def test_repr(self):
        """
        Test that repr can be applied to a CurrentAttribute object.
        """
        current_attribute = objects.CurrentAttribute(
            attribute=primitives.Enumeration(
                enums.CryptographicAlgorithm,
                enums.CryptographicAlgorithm.AES,
                enums.Tags.CRYPTOGRAPHIC_ALGORITHM
            )
        )
        self.assertEqual(
            "CurrentAttribute("
            "attribute=Enumeration("
            "enum=CryptographicAlgorithm, "
            "value=CryptographicAlgorithm.AES, "
            "tag=Tags.CRYPTOGRAPHIC_ALGORITHM))",
            repr(current_attribute)
        )

    def test_str(self):
        """
        Test that str can be applied to a CurrentAttribute object.
        """
        current_attribute = objects.CurrentAttribute(
            attribute=primitives.Enumeration(
                enums.CryptographicAlgorithm,
                enums.CryptographicAlgorithm.AES,
                enums.Tags.CRYPTOGRAPHIC_ALGORITHM
            )
        )
        self.assertEqual(
            '{"attribute": Enumeration('
            'enum=CryptographicAlgorithm, '
            'value=CryptographicAlgorithm.AES, '
            'tag=Tags.CRYPTOGRAPHIC_ALGORITHM)}',
            str(current_attribute)
        )

    def test_comparison(self):
        """
        Test that the equality/inequality operators return True/False when
        comparing two CurrentAttribute objects with the same data.
        """
        a = objects.CurrentAttribute()
        b = objects.CurrentAttribute()

        self.assertTrue(a == b)
        self.assertTrue(b == a)
        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = objects.CurrentAttribute(
            attribute=primitives.Enumeration(
                enums.CryptographicAlgorithm,
                enums.CryptographicAlgorithm.AES,
                enums.Tags.CRYPTOGRAPHIC_ALGORITHM
            )
        )
        b = objects.CurrentAttribute(
            attribute=primitives.Enumeration(
                enums.CryptographicAlgorithm,
                enums.CryptographicAlgorithm.AES,
                enums.Tags.CRYPTOGRAPHIC_ALGORITHM
            )
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)
        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_comparison_on_different_attributes(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing two CurrentAttribute objects with different attributes.
        """
        a = objects.CurrentAttribute(
            attribute=primitives.Enumeration(
                enums.CryptographicAlgorithm,
                enums.CryptographicAlgorithm.AES,
                enums.Tags.CRYPTOGRAPHIC_ALGORITHM
            )
        )
        b = objects.CurrentAttribute(
            attribute=primitives.Integer(
                128,
                enums.Tags.CRYPTOGRAPHIC_LENGTH
            )
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_comparison_on_type_mismatch(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing two CurrentAttribute objects with different types.
        """
        a = objects.CurrentAttribute()
        b = "invalid"

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)
