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
from testtools import TestCase

from kmip.core import attributes
from kmip.core import enums
from kmip.core.enums import AttributeType
from kmip.core.enums import BlockCipherMode
from kmip.core.enums import HashingAlgorithm as HashingAlgorithmEnum
from kmip.core.enums import KeyRoleType
from kmip.core.enums import PaddingMethod
from kmip.core.enums import Tags

from kmip.core import exceptions

from kmip.core.factories.attributes import AttributeValueFactory

from kmip.core import objects
from kmip.core.objects import Attribute
from kmip.core.objects import ExtensionName
from kmip.core.objects import ExtensionTag
from kmip.core.objects import ExtensionType
from kmip.core.objects import KeyMaterialStruct

from kmip.core import primitives

from kmip.core import utils
from kmip.core.utils import BytearrayStream

class TestAttributeClass(TestCase):
    """
    A test suite for the Attribute class
    """

    def setUp(self):
        super(TestAttributeClass, self).setUp()

        name_a = 'CRYPTOGRAPHIC PARAMETERS'
        name_b = 'CRYPTOGRAPHIC ALGORITHM'

        self.attribute_name_a = Attribute.AttributeName(name_a)
        self.attribute_name_b = Attribute.AttributeName(name_b)

        self.factory = AttributeValueFactory()

        self.attribute_value_a = self.factory.create_attribute_value(
            AttributeType.CRYPTOGRAPHIC_PARAMETERS,
            {'block_cipher_mode': BlockCipherMode.CBC,
             'padding_method': PaddingMethod.PKCS5,
             'hashing_algorithm': HashingAlgorithmEnum.SHA_1,
             'key_role_type': KeyRoleType.BDK})

        self.attribute_value_b = self.factory.create_attribute_value(
            AttributeType.CRYPTOGRAPHIC_PARAMETERS,
            {'block_cipher_mode': BlockCipherMode.CCM,
             'padding_method': PaddingMethod.PKCS5,
             'hashing_algorithm': HashingAlgorithmEnum.SHA_1,
             'key_role_type': KeyRoleType.BDK})

        index_a = 2
        index_b = 3

        self.attribute_index_a = Attribute.AttributeIndex(index_a)
        self.attribute_index_b = Attribute.AttributeIndex(index_b)

        self.attributeObj_a = Attribute(
            attribute_name=self.attribute_name_a,
            attribute_value=self.attribute_value_a,
            attribute_index=self.attribute_index_a)

        self.attributeObj_b = Attribute(
            attribute_name=self.attribute_name_b,
            attribute_value=self.attribute_value_a,
            attribute_index=self.attribute_index_a)

        self.attributeObj_c = Attribute(
            attribute_name=self.attribute_name_a,
            attribute_value=self.attribute_value_b,
            attribute_index=self.attribute_index_a)

        self.attributeObj_d = Attribute(
            attribute_name=self.attribute_name_a,
            attribute_value=self.attribute_value_a,
            attribute_index=self.attribute_index_b)

        self.key_req_with_crypt_params = BytearrayStream((
            b'\x42\x00\x08\x01\x00\x00\x00\x78\x42\x00\x0a\x07\x00\x00\x00\x18'
            b'\x43\x52\x59\x50\x54\x4f\x47\x52\x41\x50\x48\x49\x43\x20\x50\x41'
            b'\x52\x41\x4d\x45\x54\x45\x52\x53'
            b'\x42\x00\x09\x02\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x0b\x01\x00\x00\x00\x40'
            b'\x42\x00\x11\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x5f\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x38\x05\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00'
            b'\x42\x00\x83\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
        ))

    def tearDown(self):
        super(TestAttributeClass, self).tearDown()

    def test_read(self):
        attrObj = Attribute()
        attrObj.read(self.key_req_with_crypt_params)
        self.assertEqual(self.attributeObj_a, attrObj)

    def test_write(self):
        attrObj = Attribute(self.attribute_name_a, self.attribute_index_a,
                            self.attribute_value_a)
        ostream = BytearrayStream()
        attrObj.write(ostream)

        self.assertEqual(self.key_req_with_crypt_params, ostream)

    def test_equal_on_equal(self):
        self.assertFalse(self.attributeObj_a == self.attributeObj_b)
        self.assertFalse(self.attributeObj_a == self.attributeObj_c)
        self.assertFalse(self.attributeObj_a == self.attributeObj_d)

    def test_not_equal_on_not_equal(self):
        self.assertTrue(self.attributeObj_a != self.attributeObj_b)

class TestAttributeReference(testtools.TestCase):

    def setUp(self):
        super(TestAttributeReference, self).setUp()

        # This encoding matches the following set of values.
        # AttributeReference
        #     Vendor Identification - Acme Corporation
        #     Attribute Name - Delivery Date
        self.full_encoding = utils.BytearrayStream(
            b'\x42\x01\x3B\x01\x00\x00\x00\x30'
            b'\x42\x00\x9D\x07\x00\x00\x00\x10'
            b'\x41\x63\x6D\x65\x20\x43\x6F\x72\x70\x6F\x72\x61\x74\x69\x6F\x6E'
            b'\x42\x00\x0A\x07\x00\x00\x00\x0D'
            b'\x44\x65\x6C\x69\x76\x65\x72\x79\x20\x44\x61\x74\x65\x00\x00\x00'
        )

        # This encoding matches the following set of values.
        # AttributeReference
        #     Attribute Name - Delivery Date
        self.no_vendor_identification_encoding = utils.BytearrayStream(
            b'\x42\x01\x3B\x01\x00\x00\x00\x18'
            b'\x42\x00\x0A\x07\x00\x00\x00\x0D'
            b'\x44\x65\x6C\x69\x76\x65\x72\x79\x20\x44\x61\x74\x65\x00\x00\x00'
        )

        # This encoding matches the following set of values.
        # AttributeReference
        #     Vendor Identification - Acme Corporation
        self.no_attribute_name_encoding = utils.BytearrayStream(
            b'\x42\x01\x3B\x01\x00\x00\x00\x18'
            b'\x42\x00\x9D\x07\x00\x00\x00\x10'
            b'\x41\x63\x6D\x65\x20\x43\x6F\x72\x70\x6F\x72\x61\x74\x69\x6F\x6E'
        )

    def tearDown(self):
        super(TestAttributeReference, self).tearDown()

    def test_invalid_vendor_identification(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the vendor identification of an AttributeReference structure.
        """
        kwargs = {"vendor_identification": 0}
        self.assertRaisesRegex(
            TypeError,
            "Vendor identification must be a string.",
            objects.AttributeReference,
            **kwargs
        )

        args = (objects.AttributeReference(), "vendor_identification", 0)
        self.assertRaisesRegex(
            TypeError,
            "Vendor identification must be a string.",
            setattr,
            *args
        )

    def test_invalid_attribute_name(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the attribute name of an AttributeReference structure.
        """
        kwargs = {"attribute_name": 0}
        self.assertRaisesRegex(
            TypeError,
            "Attribute name must be a string.",
            objects.AttributeReference,
            **kwargs
        )

        args = (objects.AttributeReference(), "attribute_name", 0)
        self.assertRaisesRegex(
            TypeError,
            "Attribute name must be a string.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that an AttributeReference structure can be correctly read in
        from a data stream.
        """
        attribute_reference = objects.AttributeReference()

        self.assertIsNone(attribute_reference.vendor_identification)
        self.assertIsNone(attribute_reference.attribute_name)

        attribute_reference.read(self.full_encoding)

        self.assertEqual(
            "Acme Corporation",
            attribute_reference.vendor_identification
        )
        self.assertEqual(
            "Delivery Date",
            attribute_reference.attribute_name
        )

    def test_read_unsupported_kmip_version(self):
        """
        Test that a VersionNotSupported error is raised during the decoding of
        an AttributeReference structure when the structure is read for an
        unsupported KMIP version.
        """
        attribute_reference = objects.AttributeReference()

        args = (self.full_encoding, )
        kwargs = {"kmip_version": enums.KMIPVersion.KMIP_1_4}
        self.assertRaisesRegex(
            exceptions.VersionNotSupported,
            "KMIP 1.4 does not support the AttributeReference object.",
            attribute_reference.read,
            *args,
            **kwargs
        )

    def test_read_missing_vendor_identification(self):
        """
        Test that an InvalidKmipEncoding error is raised during the decoding
        of an AttributeReference structure when the vendor identification is
        missing from the encoding.
        """
        attribute_reference = objects.AttributeReference()

        self.assertIsNone(attribute_reference.vendor_identification)

        args = (self.no_vendor_identification_encoding, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The AttributeReference encoding is missing the vendor "
            "identification string.",
            attribute_reference.read,
            *args
        )

    def test_read_missing_attribute_name(self):
        """
        Test that an InvalidKmipEncoding error is raised during the decoding
        of an AttributeReference structure when the attribute name is missing
        from the encoding.
        """
        attribute_reference = objects.AttributeReference()

        self.assertIsNone(attribute_reference.attribute_name)

        args = (self.no_attribute_name_encoding, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The AttributeReference encoding is missing the attribute name "
            "string.",
            attribute_reference.read,
            *args
        )

    def test_write(self):
        """
        Test that an AttributeReference structure can be written to a data
        stream.
        """
        attribute_reference = objects.AttributeReference(
            vendor_identification="Acme Corporation",
            attribute_name="Delivery Date"
        )

        buffer = utils.BytearrayStream()
        attribute_reference.write(buffer)

        self.assertEqual(len(self.full_encoding), len(buffer))
        self.assertEqual(str(self.full_encoding), str(buffer))

    def test_write_unsupported_kmip_version(self):
        """
        Test that a VersionNotSupported error is raised during the encoding of
        an AttributeReference structure when the structure is written for an
        unsupported KMIP version.
        """
        attribute_reference = objects.AttributeReference(
            vendor_identification="Acme Corporation",
            attribute_name="Delivery Date"
        )

        args = (utils.BytearrayStream(), )
        kwargs = {"kmip_version": enums.KMIPVersion.KMIP_1_4}
        self.assertRaisesRegex(
            exceptions.VersionNotSupported,
            "KMIP 1.4 does not support the AttributeReference object.",
            attribute_reference.write,
            *args,
            **kwargs
        )

    def test_write_missing_vendor_identification(self):
        """
        Test that an InvalidField error is raised during the encoding of an
        AttributeReference structure when the structure is missing the vendor
        identification field.
        """
        attribute_reference = objects.AttributeReference(
            attribute_name="Delivery Date"
        )

        args = (utils.BytearrayStream(), )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The AttributeReference is missing the vendor identification "
            "field.",
            attribute_reference.write,
            *args
        )

    def test_write_missing_attribute_name(self):
        """
        Test that an InvalidField error is raised during the encoding of an
        AttributeReference structure when the structure is missing the
        attribute name field.
        """
        attribute_reference = objects.AttributeReference(
            vendor_identification="Acme Corporation"
        )

        args = (utils.BytearrayStream(), )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The AttributeReference is missing the attribute name field.",
            attribute_reference.write,
            *args
        )

    def test_repr(self):
        """
        Test that repr can be applied to an AttributeReference structure.
        """
        attribute_reference = objects.AttributeReference(
            vendor_identification="Acme Corporation",
            attribute_name="Delivery Date"
        )
        v = 'vendor_identification="Acme Corporation"'
        a = 'attribute_name="Delivery Date"'
        r = "AttributeReference({}, {})".format(v, a)

        self.assertEqual(r, repr(attribute_reference))

    def test_str(self):
        """
        Test that str can be applied to an AttributeReference structure.
        """
        attribute_reference = objects.AttributeReference(
            vendor_identification="Acme Corporation",
            attribute_name="Delivery Date"
        )
        v = '"vendor_identification": "Acme Corporation"'
        a = '"attribute_name": "Delivery Date"'
        r = "{" + "{}, {}".format(v, a) + "}"

        self.assertEqual(r, str(attribute_reference))

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        AttributeReference structures with the same data.
        """
        a = objects.AttributeReference()
        b = objects.AttributeReference()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = objects.AttributeReference(
            vendor_identification="Acme Corporation",
            attribute_name="Delivery Date"
        )
        b = objects.AttributeReference(
            vendor_identification="Acme Corporation",
            attribute_name="Delivery Date"
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_vendor_identification(self):
        """
        Test that the equality operator returns False when comparing two
        AttributeReference structures with different vendor identification
        fields.
        """
        a = objects.AttributeReference(
            vendor_identification="Acme Corporation 1"
        )
        b = objects.AttributeReference(
            vendor_identification="Acme Corporation 2"
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_attribute_name(self):
        """
        Test that the equality operator returns False when comparing two
        AttributeReference structures with different attribute name fields.
        """
        a = objects.AttributeReference(
            attribute_name="Attribute 1"
        )
        b = objects.AttributeReference(
            attribute_name="Attribute 2"
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        AttributeReference structures with different types.
        """
        a = objects.AttributeReference()
        b = "invalid"

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        AttributeReference structures with the same data.
        """
        a = objects.AttributeReference()
        b = objects.AttributeReference()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = objects.AttributeReference(
            vendor_identification="Acme Corporation",
            attribute_name="Delivery Date"
        )
        b = objects.AttributeReference(
            vendor_identification="Acme Corporation",
            attribute_name="Delivery Date"
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_vendor_identification(self):
        """
        Test that the inequality operator returns True when comparing two
        AttributeReference structures with different vendor identification
        fields.
        """
        a = objects.AttributeReference(
            vendor_identification="Acme Corporation 1"
        )
        b = objects.AttributeReference(
            vendor_identification="Acme Corporation 2"
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_attribute_name(self):
        """
        Test that the inequality operator returns True when comparing two
        AttributeReference structures with different attribute name fields.
        """
        a = objects.AttributeReference(
            attribute_name="Attribute 1"
        )
        b = objects.AttributeReference(
            attribute_name="Attribute 2"
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        AttributeReference structures with different types.
        """
        a = objects.AttributeReference()
        b = "invalid"

        self.assertTrue(a != b)
        self.assertTrue(b != a)

class TestAttributes(TestCase):

    def setUp(self):
        super(TestAttributes, self).setUp()

        # This encoding matches the following set of values:
        # Attributes
        #     Cryptographic Algorithm - AES
        #     Cryptographic Length - 128
        self.full_encoding = utils.BytearrayStream(
            b'\x42\x01\x25\x01\x00\x00\x00\x20'
            b'\x42\x00\x28\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x2A\x02\x00\x00\x00\x04\x00\x00\x00\x80\x00\x00\x00\x00'
        )

        self.empty_encoding = utils.BytearrayStream(
            b'\x42\x01\x25\x01\x00\x00\x00\x00'
        )

        # This encoding matches the following set of values:
        # Attributes
        #     Cryptographic Algorithm - AES
        #     Non-existent Tag
        self.invalid_encoding = utils.BytearrayStream(
            b'\x42\x01\x25\x01\x00\x00\x00\x20'
            b'\x42\x00\x28\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\xFF\xFF\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
        )

        # This encoding matches the following set of values:
        # Attributes
        #     Operation Policy Name - b4faee10-aa2a-4446-8ad4-0881f3422959
        self.unsupported_encoding = utils.BytearrayStream(
            b'\x42\x01\x25\x01\x00\x00\x00\x30'
            b'\x42\x00\x5D\x07\x00\x00\x00\x24\x62\x34\x66\x61\x65\x65\x31\x30'
            b'\x2D\x61\x61\x32\x61\x2D\x34\x34\x34\x36\x2D\x38\x61\x64\x34\x2D'
            b'\x30\x38\x38\x31\x66\x33\x34\x32\x32\x39\x35\x39\x00\x00\x00\x00'
        )

        # This encoding matches the following set of values:
        # Private Key Attributes
        #     Cryptographic Algorithm - AES
        #     Cryptographic Length - 128
        self.alt_encoding = utils.BytearrayStream(
            b'\x42\x01\x27\x01\x00\x00\x00\x20'
            b'\x42\x00\x28\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x2A\x02\x00\x00\x00\x04\x00\x00\x00\x80\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestAttributes, self).tearDown()

    def test_unrecognized_attributes(self):
        """
        Test that a TypeError is raised when an unrecognized attribute is
        included in the attribute list. Note that this unrecognized attribute
        is a valid PyKMIP object derived from Base, it just isn't an attribute.
        """
        kwargs = {
            'attributes': [
                primitives.Enumeration(
                    enums.WrappingMethod,
                    enums.WrappingMethod.ENCRYPT,
                    enums.Tags.WRAPPING_METHOD
                )
            ]
        }
        self.assertRaisesRegex(
            TypeError,
            "Item 1 must be a supported attribute.",
            objects.Attributes,
            **kwargs
        )

        attrs = objects.Attributes()
        args = (
            attrs,
            'attributes',
            [
                primitives.Enumeration(
                    enums.CryptographicAlgorithm,
                    enums.CryptographicAlgorithm.AES,
                    enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                ),
                primitives.Enumeration(
                    enums.WrappingMethod,
                    enums.WrappingMethod.ENCRYPT,
                    enums.Tags.WRAPPING_METHOD
                )
            ]
        )
        self.assertRaisesRegex(
            TypeError,
            "Item 2 must be a supported attribute.",
            setattr,
            *args
        )

    def test_invalid_attributes(self):
        """
        Test that a TypeError is raised when an invalid value is included
        in the attribute list. Note that the value is not a valid PyKMIP
        object derived from Base and therefore cannot be an attribute.
        """
        kwargs = {
            'attributes': [0]
        }
        self.assertRaisesRegex(
            TypeError,
            "Item 1 must be a Base object, not a {}.".format(type(0)),
            objects.Attributes,
            **kwargs
        )

        attrs = objects.Attributes()
        args = (
            attrs,
            'attributes',
            [
                primitives.Enumeration(
                    enums.CryptographicAlgorithm,
                    enums.CryptographicAlgorithm.AES,
                    enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                ),
                primitives.Enumeration(
                    enums.KeyFormatType,
                    enums.KeyFormatType.RAW,
                    enums.Tags.KEY_FORMAT_TYPE
                ),
                1
            ]
        )
        self.assertRaisesRegex(
            TypeError,
            "Item 3 must be a Base object, not a {}.".format(type(0)),
            setattr,
            *args
        )

    def test_invalid_attributes_list(self):
        """
        Test that a TypeError is raised when an invalid attribute list is
        used with the Attributes structure.
        """
        kwargs = {
            'attributes': 'invalid'
        }
        self.assertRaisesRegex(
            TypeError,
            "Attributes must be a list of Base objects.",
            objects.Attributes,
            **kwargs
        )

        attrs = objects.Attributes()
        args = (
            attrs,
            'attributes',
            'invalid'
        )
        self.assertRaisesRegex(
            TypeError,
            "Attributes must be a list of Base objects.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that an Attributes structure can be correctly read in from a data
        stream.
        """
        attrs = objects.Attributes()

        self.assertEqual([], attrs.attributes)

        attrs.read(self.full_encoding)

        self.assertEqual(2, len(attrs.attributes))

        attr_1 = attrs.attributes[0]
        self.assertIsInstance(attr_1, primitives.Enumeration)
        self.assertEqual(enums.CryptographicAlgorithm.AES, attr_1.value)

        attr_2 = attrs.attributes[1]
        self.assertIsInstance(attr_2, primitives.Integer)
        self.assertEqual(128, attr_2.value)

    def test_read_no_attributes(self):
        """
        Test that an empty Attributes structure can be correctly read in from
        a data stream.
        """
        attrs = objects.Attributes()

        self.assertEqual([], attrs.attributes)

        attrs.read(self.empty_encoding)

        self.assertEqual([], attrs.attributes)

    def test_read_invalid_attribute(self):
        """
        Test that an unrecognized tag is correctly handled when reading in an
        Attributes structure from a data stream. Specifically, structure
        parsing should stop and an error should be raised indicating that more
        encoding data is available but could not be parsed.
        """
        attrs = objects.Attributes()

        self.assertEqual([], attrs.attributes)

        args = (self.invalid_encoding, )
        self.assertRaisesRegex(
            exceptions.StreamNotEmptyError,
            "Invalid length used to read Base, bytes remaining: 16",
            attrs.read,
            *args
        )

    def test_read_unsupported_attribute(self):
        """
        Test that an AttributeNotSupported error is raised when an unsupported
        attribute is parsed while reading in an Attributes structure from a
        data stream. This can occur when an older attribute is no longer
        supported by a newer version of KMIP, or vice versa.
        """
        attrs = objects.Attributes()

        self.assertEqual([], attrs.attributes)

        args = (self.unsupported_encoding, )
        kwargs = {"kmip_version": enums.KMIPVersion.KMIP_2_0}
        self.assertRaisesRegex(
            exceptions.AttributeNotSupported,
            "Attribute OPERATION_POLICY_NAME is not supported by KMIP 2.0.",
            attrs.read,
            *args,
            **kwargs
        )

    def test_read_alternative_tag(self):
        """
        Test that an Attributes structure can be correctly read in from a data
        stream with an alternative tag. This can occur if a variant of the
        Attributes structure is being used, like the Common Attributes, Public
        Key Attributes, or Private Key Attributes structures.
        """
        attrs = objects.Attributes(tag=enums.Tags.PRIVATE_KEY_ATTRIBUTES)

        self.assertEqual([], attrs.attributes)

        attrs.read(self.alt_encoding)

        self.assertEqual(2, len(attrs.attributes))

        attr_1 = attrs.attributes[0]
        self.assertIsInstance(attr_1, primitives.Enumeration)
        self.assertEqual(enums.CryptographicAlgorithm.AES, attr_1.value)

        attr_2 = attrs.attributes[1]
        self.assertIsInstance(attr_2, primitives.Integer)
        self.assertEqual(128, attr_2.value)

    def test_read_version_not_supported(self):
        """
        Test that a VersionNotSupported error is raised when an unsupported
        KMIP version is provided while reading in an Attributes structure from
        a data stream. The Attributes structure is only supported in KMIP 2.0+.
        """
        attrs = objects.Attributes()

        args = (self.full_encoding, )
        kwargs = {"kmip_version": enums.KMIPVersion.KMIP_1_2}
        self.assertRaisesRegex(
            exceptions.VersionNotSupported,
            "KMIP 1.2 does not support the Attributes object.",
            attrs.read,
            *args,
            **kwargs
        )

    def test_write(self):
        """
        Test that an Attributes structure can be correctly written to a data
        stream.
        """
        attrs = objects.Attributes(attributes=[
            primitives.Enumeration(
                enums.CryptographicAlgorithm,
                enums.CryptographicAlgorithm.AES,
                enums.Tags.CRYPTOGRAPHIC_ALGORITHM
            ),
            primitives.Integer(
                128,
                enums.Tags.CRYPTOGRAPHIC_LENGTH
            )
        ])

        stream = utils.BytearrayStream()
        attrs.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_no_attributes(self):
        """
        Test that an empty Attributes structure can be correctly written to
        a data stream.
        """
        attrs = objects.Attributes()

        stream = utils.BytearrayStream()
        attrs.write(stream)

        self.assertEqual(len(self.empty_encoding), len(stream))
        self.assertEqual(str(self.empty_encoding), str(stream))

    def test_write_unsupported_attribute(self):
        """
        Test that an AttributeNotSupported error is raised when an unsupported
        attribute is found while writing an Attributes structure to a data
        stream. This can occur when an older attribute is no longer supported
        by a newer version of KMIP, or vice versa.
        """
        attrs = objects.Attributes(attributes=[
            primitives.TextString(
                "default",
                tag=enums.Tags.OPERATION_POLICY_NAME
            )
        ])

        stream = utils.BytearrayStream()
        args = (stream, )
        kwargs = {"kmip_version": enums.KMIPVersion.KMIP_2_0}
        self.assertRaisesRegex(
            exceptions.AttributeNotSupported,
            "Attribute OPERATION_POLICY_NAME is not supported by KMIP 2.0.",
            attrs.write,
            *args,
            **kwargs
        )

    def test_write_alternative_tag(self):
        """
        Test that an Attributes structure can be correctly written to a data
        stream with an alternative tag. This can occur if a variant of the
        Attributes structure is being used, like the Common Attributes, Public
        Key Attributes, or Private Key Attributes structures.
        """
        attrs = objects.Attributes(
            attributes=[
                primitives.Enumeration(
                    enums.CryptographicAlgorithm,
                    enums.CryptographicAlgorithm.AES,
                    enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                ),
                primitives.Integer(
                    128,
                    enums.Tags.CRYPTOGRAPHIC_LENGTH
                )
            ],
            tag=enums.Tags.PRIVATE_KEY_ATTRIBUTES
        )

        stream = utils.BytearrayStream()
        attrs.write(stream)

        self.assertEqual(len(self.alt_encoding), len(stream))
        self.assertEqual(str(self.alt_encoding), str(stream))

    def test_write_version_not_supported(self):
        """
        Test that a VersionNotSupported error is raised when an unsupported
        KMIP version is provided while writing an Attributes structure to a
        data stream. The Attributes structure is only supported in KMIP 2.0+.
        """
        attrs = objects.Attributes(attributes=[
            primitives.TextString(
                "default",
                tag=enums.Tags.OPERATION_POLICY_NAME
            )
        ])

        stream = utils.BytearrayStream()
        args = (stream, )
        kwargs = {"kmip_version": enums.KMIPVersion.KMIP_1_1}
        self.assertRaisesRegex(
            exceptions.VersionNotSupported,
            "KMIP 1.1 does not support the Attributes object.",
            attrs.write,
            *args,
            **kwargs
        )

    def test_repr(self):
        """
        Test that repr can be applied to an Attributes structure.
        """
        attrs = objects.Attributes(attributes=[
            primitives.Enumeration(
                enums.CryptographicAlgorithm,
                enums.CryptographicAlgorithm.AES,
                enums.Tags.CRYPTOGRAPHIC_ALGORITHM
            ),
            primitives.Integer(
                128,
                enums.Tags.CRYPTOGRAPHIC_LENGTH
            )
        ])
        self.assertEqual(
            "Attributes(attributes=["
            "Enumeration("
            "enum=CryptographicAlgorithm, "
            "value=CryptographicAlgorithm.AES, "
            "tag=Tags.CRYPTOGRAPHIC_ALGORITHM), "
            "Integer(value=128)], "
            "tag=Tags.ATTRIBUTES)",
            repr(attrs)
        )

    def test_repr_alternative_tag(self):
        """
        Test that repr can be applied to an Attribute structure with an
        alternative tag. This can occur if a variant of the Attributes
        structure is being used, like the Common Attributes, Public Key
        Attributes, or Private Key Attributes structure.
        """
        attrs = objects.Attributes(tag=enums.Tags.COMMON_ATTRIBUTES)
        self.assertEqual(
            "Attributes(attributes=[], tag=Tags.COMMON_ATTRIBUTES)",
            repr(attrs)
        )

    def test_str(self):
        """
        Test that str can be applied to an Attributes structure.
        """
        attrs = objects.Attributes(attributes=[
            primitives.Enumeration(
                enums.CryptographicAlgorithm,
                enums.CryptographicAlgorithm.AES,
                enums.Tags.CRYPTOGRAPHIC_ALGORITHM
            ),
            primitives.Integer(
                128,
                enums.Tags.CRYPTOGRAPHIC_LENGTH
            )
        ])
        self.assertEqual(
            '{"attributes": [CryptographicAlgorithm.AES, 128]}',
            str(attrs)
        )

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        identical Attributes structures.
        """
        a = objects.Attributes()
        b = objects.Attributes()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = objects.Attributes(attributes=[
            primitives.Enumeration(
                enums.CryptographicAlgorithm,
                enums.CryptographicAlgorithm.AES,
                enums.Tags.CRYPTOGRAPHIC_ALGORITHM
            ),
            primitives.Integer(
                128,
                enums.Tags.CRYPTOGRAPHIC_LENGTH
            )
        ])
        b = objects.Attributes(attributes=[
            primitives.Enumeration(
                enums.CryptographicAlgorithm,
                enums.CryptographicAlgorithm.AES,
                enums.Tags.CRYPTOGRAPHIC_ALGORITHM
            ),
            primitives.Integer(
                128,
                enums.Tags.CRYPTOGRAPHIC_LENGTH
            )
        ])

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_attributes(self):
        """
        Test that the equality operator returns False when comparing two
        Attributes structures with different attributes lists.
        """
        a = objects.Attributes()
        b = objects.Attributes(attributes=[
            primitives.Enumeration(
                enums.CryptographicAlgorithm,
                enums.CryptographicAlgorithm.AES,
                enums.Tags.CRYPTOGRAPHIC_ALGORITHM
            ),
            primitives.Integer(
                128,
                enums.Tags.CRYPTOGRAPHIC_LENGTH
            )
        ])

        self.assertFalse(a == b)
        self.assertFalse(b == a)

        a = objects.Attributes(attributes=[
            primitives.Enumeration(
                enums.CryptographicAlgorithm,
                enums.CryptographicAlgorithm.AES,
                enums.Tags.CRYPTOGRAPHIC_ALGORITHM
            ),
            primitives.Integer(
                128,
                enums.Tags.CRYPTOGRAPHIC_LENGTH
            )
        ])
        b = objects.Attributes(attributes=[
            primitives.Integer(
                128,
                enums.Tags.CRYPTOGRAPHIC_LENGTH
            ),
            primitives.Enumeration(
                enums.CryptographicAlgorithm,
                enums.CryptographicAlgorithm.AES,
                enums.Tags.CRYPTOGRAPHIC_ALGORITHM
            )
        ])

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing an
        Attributes structure with another type.
        """
        a = objects.Attributes()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        identical Attributes structures.
        """
        a = objects.Attributes()
        b = objects.Attributes()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = objects.Attributes(attributes=[
            primitives.Enumeration(
                enums.CryptographicAlgorithm,
                enums.CryptographicAlgorithm.AES,
                enums.Tags.CRYPTOGRAPHIC_ALGORITHM
            ),
            primitives.Integer(
                128,
                enums.Tags.CRYPTOGRAPHIC_LENGTH
            )
        ])
        b = objects.Attributes(attributes=[
            primitives.Enumeration(
                enums.CryptographicAlgorithm,
                enums.CryptographicAlgorithm.AES,
                enums.Tags.CRYPTOGRAPHIC_ALGORITHM
            ),
            primitives.Integer(
                128,
                enums.Tags.CRYPTOGRAPHIC_LENGTH
            )
        ])

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_attributes(self):
        """
        Test that the inequality operator returns True when comparing two
        Attributes structures with different attributes lists.
        """
        a = objects.Attributes()
        b = objects.Attributes(attributes=[
            primitives.Enumeration(
                enums.CryptographicAlgorithm,
                enums.CryptographicAlgorithm.AES,
                enums.Tags.CRYPTOGRAPHIC_ALGORITHM
            ),
            primitives.Integer(
                128,
                enums.Tags.CRYPTOGRAPHIC_LENGTH
            )
        ])

        self.assertTrue(a != b)
        self.assertTrue(b != a)

        a = objects.Attributes(attributes=[
            primitives.Enumeration(
                enums.CryptographicAlgorithm,
                enums.CryptographicAlgorithm.AES,
                enums.Tags.CRYPTOGRAPHIC_ALGORITHM
            ),
            primitives.Integer(
                128,
                enums.Tags.CRYPTOGRAPHIC_LENGTH
            )
        ])
        b = objects.Attributes(attributes=[
            primitives.Integer(
                128,
                enums.Tags.CRYPTOGRAPHIC_LENGTH
            ),
            primitives.Enumeration(
                enums.CryptographicAlgorithm,
                enums.CryptographicAlgorithm.AES,
                enums.Tags.CRYPTOGRAPHIC_ALGORITHM
            )
        ])

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing an
        Attributes structure with another type.
        """
        a = objects.Attributes()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)

class TestAttributeUtilities(testtools.TestCase):

    def setUp(self):
        super(TestAttributeUtilities, self).setUp()

    def tearDown(self):
        super(TestAttributeUtilities, self).tearDown()

    def test_convert_template_attribute_to_attributes(self):
        template_attribute = objects.TemplateAttribute(
            attributes=[
                objects.Attribute(
                    attribute_name=objects.Attribute.AttributeName(
                        "State"
                    ),
                    attribute_value=primitives.Enumeration(
                        enums.State,
                        value=enums.State.PRE_ACTIVE,
                        tag=enums.Tags.STATE
                    )
                )
            ]
        )

        value = objects.convert_template_attribute_to_attributes(
            template_attribute
        )

        self.assertIsInstance(value, objects.Attributes)
        self.assertEqual(enums.Tags.ATTRIBUTES, value.tag)
        self.assertIsInstance(value.attributes, list)
        self.assertEqual(1, len(value.attributes))
        self.assertEqual(
            primitives.Enumeration(
                enums.State,
                value=enums.State.PRE_ACTIVE,
                tag=enums.Tags.STATE
            ),
            value.attributes[0]
        )

    def test_convert_common_template_attribute_to_attributes(self):
        template_attribute = objects.TemplateAttribute(
            attributes=[
                objects.Attribute(
                    attribute_name=objects.Attribute.AttributeName(
                        "Cryptographic Algorithm"
                    ),
                    attribute_value=primitives.Enumeration(
                        enums.CryptographicAlgorithm,
                        value=enums.CryptographicAlgorithm.AES,
                        tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                    )
                )
            ],
            tag=enums.Tags.COMMON_TEMPLATE_ATTRIBUTE
        )

        value = objects.convert_template_attribute_to_attributes(
            template_attribute
        )

        self.assertIsInstance(value, objects.Attributes)
        self.assertEqual(enums.Tags.COMMON_ATTRIBUTES, value.tag)
        self.assertIsInstance(value.attributes, list)
        self.assertEqual(1, len(value.attributes))
        self.assertEqual(
            primitives.Enumeration(
                enums.CryptographicAlgorithm,
                value=enums.CryptographicAlgorithm.AES,
                tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
            ),
            value.attributes[0]
        )

    def test_convert_private_key_template_attribute_to_attributes(self):
        template_attribute = objects.TemplateAttribute(
            attributes=[
                objects.Attribute(
                    attribute_name=objects.Attribute.AttributeName(
                        "Key Format Type"
                    ),
                    attribute_value=primitives.Enumeration(
                        enums.KeyFormatType,
                        value=enums.KeyFormatType.RAW,
                        tag=enums.Tags.KEY_FORMAT_TYPE
                    )
                )
            ],
            tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
        )

        value = objects.convert_template_attribute_to_attributes(
            template_attribute
        )

        self.assertIsInstance(value, objects.Attributes)
        self.assertEqual(enums.Tags.PRIVATE_KEY_ATTRIBUTES, value.tag)
        self.assertIsInstance(value.attributes, list)
        self.assertEqual(1, len(value.attributes))
        self.assertEqual(
            primitives.Enumeration(
                enums.KeyFormatType,
                value=enums.KeyFormatType.RAW,
                tag=enums.Tags.KEY_FORMAT_TYPE
            ),
            value.attributes[0]
        )

    def test_convert_public_key_template_attribute_to_attributes(self):
        template_attribute = objects.TemplateAttribute(
            attributes=[
                objects.Attribute(
                    attribute_name=objects.Attribute.AttributeName(
                        "Object Type"
                    ),
                    attribute_value=primitives.Enumeration(
                        enums.ObjectType,
                        value=enums.ObjectType.PUBLIC_KEY,
                        tag=enums.Tags.OBJECT_TYPE
                    )
                )
            ],
            tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
        )

        value = objects.convert_template_attribute_to_attributes(
            template_attribute
        )

        self.assertIsInstance(value, objects.Attributes)
        self.assertEqual(enums.Tags.PUBLIC_KEY_ATTRIBUTES, value.tag)
        self.assertIsInstance(value.attributes, list)
        self.assertEqual(1, len(value.attributes))
        self.assertEqual(
            primitives.Enumeration(
                enums.ObjectType,
                value=enums.ObjectType.PUBLIC_KEY,
                tag=enums.Tags.OBJECT_TYPE
            ),
            value.attributes[0]
        )

    def test_convert_template_attribute_to_attributes_invalid(self):
        args = ("invalid", )
        self.assertRaisesRegex(
            TypeError,
            "Input must be a TemplateAttribute structure.",
            objects.convert_template_attribute_to_attributes,
            *args
        )

    def test_convert_attributes_to_template_attribute(self):
        attributes = objects.Attributes(
            attributes=[
                primitives.Enumeration(
                    enums.State,
                    value=enums.State.PRE_ACTIVE,
                    tag=enums.Tags.STATE
                )
            ],
            tag=enums.Tags.ATTRIBUTES
        )

        value = objects.convert_attributes_to_template_attribute(attributes)

        self.assertIsInstance(value, objects.TemplateAttribute)
        self.assertEqual(value.tag, enums.Tags.TEMPLATE_ATTRIBUTE)
        self.assertIsInstance(value.attributes, list)
        self.assertEqual(1, len(value.attributes))
        self.assertIsInstance(
            value.attributes[0],
            objects.Attribute
        )
        self.assertEqual(
            "State",
            value.attributes[0].attribute_name.value
        )
        self.assertEqual(
            primitives.Enumeration(
                enums.State,
                value=enums.State.PRE_ACTIVE,
                tag=enums.Tags.ATTRIBUTE_VALUE
            ),
            value.attributes[0].attribute_value
        )

    def test_convert_attributes_to_common_template_attribute(self):
        attributes = objects.Attributes(
            attributes=[
                primitives.Enumeration(
                    enums.CryptographicAlgorithm,
                    value=enums.CryptographicAlgorithm.AES,
                    tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                )
            ],
            tag=enums.Tags.COMMON_ATTRIBUTES
        )

        value = objects.convert_attributes_to_template_attribute(attributes)

        self.assertIsInstance(value, objects.TemplateAttribute)
        self.assertEqual(value.tag, enums.Tags.COMMON_TEMPLATE_ATTRIBUTE)
        self.assertIsInstance(value.attributes, list)
        self.assertEqual(1, len(value.attributes))
        self.assertIsInstance(
            value.attributes[0],
            objects.Attribute
        )
        self.assertEqual(
            "Cryptographic Algorithm",
            value.attributes[0].attribute_name.value
        )
        self.assertEqual(
            primitives.Enumeration(
                enums.CryptographicAlgorithm,
                value=enums.CryptographicAlgorithm.AES,
                tag=enums.Tags.ATTRIBUTE_VALUE
            ),
            value.attributes[0].attribute_value
        )

    def test_convert_attributes_to_private_key_template_attribute(self):
        attributes = objects.Attributes(
            attributes=[
                primitives.Enumeration(
                    enums.KeyFormatType,
                    value=enums.KeyFormatType.RAW,
                    tag=enums.Tags.KEY_FORMAT_TYPE
                )
            ],
            tag=enums.Tags.PRIVATE_KEY_ATTRIBUTES
        )

        value = objects.convert_attributes_to_template_attribute(attributes)

        self.assertIsInstance(value, objects.TemplateAttribute)
        self.assertEqual(value.tag, enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE)
        self.assertIsInstance(value.attributes, list)
        self.assertEqual(1, len(value.attributes))
        self.assertIsInstance(
            value.attributes[0],
            objects.Attribute
        )
        self.assertEqual(
            "Key Format Type",
            value.attributes[0].attribute_name.value
        )
        self.assertEqual(
            primitives.Enumeration(
                enums.KeyFormatType,
                value=enums.KeyFormatType.RAW,
                tag=enums.Tags.ATTRIBUTE_VALUE
            ),
            value.attributes[0].attribute_value
        )

    def test_convert_attributes_to_public_key_template_attribute(self):
        attributes = objects.Attributes(
            attributes=[
                primitives.Enumeration(
                    enums.ObjectType,
                    value=enums.ObjectType.PUBLIC_KEY,
                    tag=enums.Tags.OBJECT_TYPE
                )
            ],
            tag=enums.Tags.PUBLIC_KEY_ATTRIBUTES
        )

        value = objects.convert_attributes_to_template_attribute(attributes)

        self.assertIsInstance(value, objects.TemplateAttribute)
        self.assertEqual(value.tag, enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE)
        self.assertIsInstance(value.attributes, list)
        self.assertEqual(1, len(value.attributes))
        self.assertIsInstance(
            value.attributes[0],
            objects.Attribute
        )
        self.assertEqual(
            "Object Type",
            value.attributes[0].attribute_name.value
        )
        self.assertEqual(
            primitives.Enumeration(
                enums.ObjectType,
                value=enums.ObjectType.PUBLIC_KEY,
                tag=enums.Tags.ATTRIBUTE_VALUE
            ),
            value.attributes[0].attribute_value
        )

    def test_convert_attributes_to_template_attribute_invalid(self):
        args = ("invalid", )
        self.assertRaisesRegex(
            TypeError,
            "Input must be an Attributes structure.",
            objects.convert_attributes_to_template_attribute,
            *args
        )

class TestKeyMaterialStruct(TestCase):
    """
    A test suite for the KeyMaterialStruct.

    A placeholder test suite. Should be removed when KeyMaterialStruct is
    removed from the code base.
    """

    def setUp(self):
        super(TestKeyMaterialStruct, self).setUp()

    def tearDown(self):
        super(TestKeyMaterialStruct, self).tearDown()

    def test_valid_tag(self):
        """
        Test that the KeyMaterialStruct tag is valid.
        """
        struct = KeyMaterialStruct()

        self.assertEqual(Tags.KEY_MATERIAL, struct.tag)

class TestExtensionName(TestCase):
    """
    A test suite for the ExtensionName class.

    Since ExtensionName is a simple wrapper for the TextString primitive, only
    a few tests pertaining to construction are needed.
    """

    def setUp(self):
        super(TestExtensionName, self).setUp()

    def tearDown(self):
        super(TestExtensionName, self).tearDown()

    def _test_init(self, value):
        if (isinstance(value, str)) or (value is None):
            extension_name = ExtensionName(value)

            if value is None:
                value = ''

            msg = "expected {0}, observed {1}".format(
                value, extension_name.value)
            self.assertEqual(value, extension_name.value, msg)
        else:
            self.assertRaises(TypeError, ExtensionName, value)

    def test_init_with_none(self):
        """
        Test that an ExtensionName object can be constructed with no specified
        value.
        """
        self._test_init(None)

    def test_init_with_valid(self):
        """
        Test that an ExtensionName object can be constructed with a valid
        string value.
        """
        self._test_init("valid")

    def test_init_with_invalid(self):
        """
        Test that a TypeError exception is raised when a non-string value is
        used to construct an ExtensionName object.
        """
        self._test_init(0)

class TestExtensionTag(TestCase):
    """
    A test suite for the ExtensionTag class.

    Since ExtensionTag is a simple wrapper for the Integer primitive, only a
    few tests pertaining to construction are needed.
    """

    def setUp(self):
        super(TestExtensionTag, self).setUp()

    def tearDown(self):
        super(TestExtensionTag, self).tearDown()

    def _test_init(self, value):
        if (isinstance(value, int)) or (value is None):
            extension_tag = ExtensionTag(value)

            if value is None:
                value = 0

            msg = "expected {0}, observed {1}".format(
                value, extension_tag.value)
            self.assertEqual(value, extension_tag.value, msg)
        else:
            self.assertRaises(TypeError, ExtensionTag, value)

    def test_init_with_none(self):
        """
        Test that an ExtensionTag object can be constructed with no specified
        value.
        """
        self._test_init(None)

    def test_init_with_valid(self):
        """
        Test that an ExtensionTag object can be constructed with a valid
        integer value.
        """
        self._test_init(0)

    def test_init_with_invalid(self):
        """
        Test that a TypeError exception is raised when a non-integer value is
        used to construct an ExtensionName object.
        """
        self._test_init("invalid")

class TestExtensionType(TestCase):
    """
    A test suite for the ExtensionType class.

    Since ExtensionType is a simple wrapper for the Integer primitive, only a
    few tests pertaining to construction are needed.
    """

    def setUp(self):
        super(TestExtensionType, self).setUp()

    def tearDown(self):
        super(TestExtensionType, self).tearDown()

    def _test_init(self, value):
        if (isinstance(value, int)) or (value is None):
            extension_type = ExtensionType(value)

            if value is None:
                value = 0

            msg = "expected {0}, observed {1}".format(
                value, extension_type.value)
            self.assertEqual(value, extension_type.value, msg)
        else:
            self.assertRaises(TypeError, ExtensionType, value)

    def test_init_with_none(self):
        """
        Test that an ExtensionType object can be constructed with no specified
        value.
        """
        self._test_init(None)

    def test_init_with_valid(self):
        """
        Test that an ExtensionType object can be constructed with a valid
        integer value.
        """
        self._test_init(0)

    def test_init_with_invalid(self):
        """
        Test that a TypeError exception is raised when a non-string value is
        used to construct an ExtensionType object.
        """
        self._test_init("invalid")

class TestEncryptionKeyInformation(testtools.TestCase):
    """
    Test suite for the EncryptionKeyInformation struct.
    """

    def setUp(self):
        super(TestEncryptionKeyInformation, self).setUp()

        # Encoding obtained from the KMIP 1.1 testing document, Section 14.1.
        #
        # This encoding matches the following set of values:
        # Unique Identifier - 100182d5-72b8-47aa-8383-4d97d512e98a
        # Cryptographic Parameters
        #     Block Cipher Mode - NIST_KEY_WRAP

        self.full_encoding = BytearrayStream(
            b'\x42\x00\x36\x01\x00\x00\x00\x48'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x31\x30\x30\x31\x38\x32\x64\x35\x2D\x37\x32\x62\x38\x2D\x34\x37'
            b'\x61\x61\x2D\x38\x33\x38\x33\x2D\x34\x64\x39\x37\x64\x35\x31\x32'
            b'\x65\x39\x38\x61\x00\x00\x00\x00'
            b'\x42\x00\x2B\x01\x00\x00\x00\x10'
            b'\x42\x00\x11\x05\x00\x00\x00\x04\x00\x00\x00\x0D\x00\x00\x00\x00'
        )

        # Adapted from the full encoding above. This encoding matches the
        # following set of values:
        # Unique Identifier - 100182d5-72b8-47aa-8383-4d97d512e98a

        self.partial_encoding = BytearrayStream(
            b'\x42\x00\x36\x01\x00\x00\x00\x30'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x31\x30\x30\x31\x38\x32\x64\x35\x2D\x37\x32\x62\x38\x2D\x34\x37'
            b'\x61\x61\x2D\x38\x33\x38\x33\x2D\x34\x64\x39\x37\x64\x35\x31\x32'
            b'\x65\x39\x38\x61\x00\x00\x00\x00'
        )

        self.empty_encoding = BytearrayStream(
            b'\x42\x00\x36\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestEncryptionKeyInformation, self).tearDown()

    def test_init(self):
        """
        Test that an EncryptionKeyInformation struct can be constructed with
        no arguments.
        """
        encryption_key_information = objects.EncryptionKeyInformation()

        self.assertEqual(None, encryption_key_information.unique_identifier)
        self.assertEqual(
            None,
            encryption_key_information.cryptographic_parameters
        )

    def test_init_with_args(self):
        """
        Test that an EncryptionKeyInformation struct can be constructed with
        valid values.
        """
        cryptographic_parameters = attributes.CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.CTR)
        encryption_key_information = objects.EncryptionKeyInformation(
            unique_identifier="00000000-1111-2222-3333-444444444444",
            cryptographic_parameters=cryptographic_parameters
        )

        self.assertEqual(
            "00000000-1111-2222-3333-444444444444",
            encryption_key_information.unique_identifier
        )
        self.assertIsInstance(
            encryption_key_information.cryptographic_parameters,
            attributes.CryptographicParameters
        )
        parameters = encryption_key_information.cryptographic_parameters
        self.assertEqual(
            enums.BlockCipherMode.CTR,
            parameters.block_cipher_mode
        )

        encryption_key_information = objects.EncryptionKeyInformation(
            unique_identifier="00000000-1111-2222-3333-444444444444",
            cryptographic_parameters={
                'block_cipher_mode': enums.BlockCipherMode.CTR
            }
        )

        self.assertEqual(
            "00000000-1111-2222-3333-444444444444",
            encryption_key_information.unique_identifier
        )
        self.assertIsInstance(
            encryption_key_information.cryptographic_parameters,
            attributes.CryptographicParameters
        )
        parameters = encryption_key_information.cryptographic_parameters
        self.assertEqual(
            enums.BlockCipherMode.CTR,
            parameters.block_cipher_mode
        )

    def test_invalid_unique_identifier(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the unique identifier of an EncryptionKeyInformation struct.
        """
        kwargs = {'unique_identifier': 0}
        self.assertRaisesRegex(
            TypeError,
            "Unique identifier must be a string.",
            objects.EncryptionKeyInformation,
            **kwargs
        )

        encryption_key_information = objects.EncryptionKeyInformation()
        args = (encryption_key_information, 'unique_identifier', 0)
        self.assertRaisesRegex(
            TypeError,
            "Unique identifier must be a string.",
            setattr,
            *args
        )

    def test_invalid_cryptographic_parameters(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the cryptographic parameters of an EncryptionKeyInformation struct.
        """
        kwargs = {'cryptographic_parameters': 'invalid'}
        self.assertRaisesRegex(
            TypeError,
            "Cryptographic parameters must be a CryptographicParameters "
            "struct.",
            objects.EncryptionKeyInformation,
            **kwargs
        )

        encryption_key_information = objects.EncryptionKeyInformation()
        args = (
            encryption_key_information,
            'cryptographic_parameters',
            'invalid'
        )
        self.assertRaisesRegex(
            TypeError,
            "Cryptographic parameters must be a CryptographicParameters "
            "struct.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that an EncryptionKeyInformation struct can be read from a data
        stream.
        """
        encryption_key_information = objects.EncryptionKeyInformation()

        self.assertEqual(None, encryption_key_information.unique_identifier)
        self.assertEqual(
            None,
            encryption_key_information.cryptographic_parameters
        )

        encryption_key_information.read(self.full_encoding)

        self.assertEqual(
            "100182d5-72b8-47aa-8383-4d97d512e98a",
            encryption_key_information.unique_identifier
        )
        self.assertIsInstance(
            encryption_key_information.cryptographic_parameters,
            attributes.CryptographicParameters
        )
        cryptographic_parameters = \
            encryption_key_information.cryptographic_parameters
        self.assertEqual(
            enums.BlockCipherMode.NIST_KEY_WRAP,
            cryptographic_parameters.block_cipher_mode
        )

    def test_read_partial(self):
        """
        Test that an EncryptionKeyInformation struct can be read from a partial
        data stream.
        """
        encryption_key_information = objects.EncryptionKeyInformation()

        self.assertEqual(None, encryption_key_information.unique_identifier)
        self.assertEqual(
            None,
            encryption_key_information.cryptographic_parameters
        )

        encryption_key_information.read(self.partial_encoding)

        self.assertEqual(
            "100182d5-72b8-47aa-8383-4d97d512e98a",
            encryption_key_information.unique_identifier
        )
        self.assertEqual(
            None,
            encryption_key_information.cryptographic_parameters
        )

    def test_read_invalid(self):
        """
        Test that a ValueError gets raised when a required
        EncryptionKeyInformation field is missing from the struct encoding.
        """
        encryption_key_information = objects.EncryptionKeyInformation()
        args = (self.empty_encoding,)
        self.assertRaisesRegex(
            ValueError,
            "Invalid struct missing the unique identifier attribute.",
            encryption_key_information.read,
            *args
        )

    def test_write(self):
        """
        Test that an EncryptionKeyInformation struct can be written to a data
        stream.
        """
        cryptographic_parameters = attributes.CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
        )
        encryption_key_information = objects.EncryptionKeyInformation(
            unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
            cryptographic_parameters=cryptographic_parameters
        )
        stream = BytearrayStream()
        encryption_key_information.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_partial(self):
        """
        Test that a partially defined EncryptionKeyInformation struct can be
        written to a data stream.
        """
        encryption_key_information = objects.EncryptionKeyInformation(
            unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a"
        )
        stream = BytearrayStream()
        encryption_key_information.write(stream)

        self.assertEqual(len(self.partial_encoding), len(stream))
        self.assertEqual(str(self.partial_encoding), str(stream))

    def test_write_invalid(self):
        """
        Test that a ValueError gets raised when a required
        EncryptionKeyInformation field is missing when encoding the struct.
        """
        encryption_key_information = objects.EncryptionKeyInformation()
        stream = utils.BytearrayStream()
        args = (stream,)
        self.assertRaisesRegex(
            ValueError,
            "Invalid struct missing the unique identifier attribute.",
            encryption_key_information.write,
            *args
        )

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        EncryptionKeyInformation structs with the same data.
        """
        a = objects.EncryptionKeyInformation()
        b = objects.EncryptionKeyInformation()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = objects.EncryptionKeyInformation(
            unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
            cryptographic_parameters=attributes.CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.CBC
            )
        )
        b = objects.EncryptionKeyInformation(
            unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
            cryptographic_parameters=attributes.CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.CBC
            )
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_unique_identifier(self):
        """
        Test that the equality operator returns False when comparing two
        EncryptionKeyInformation structs with different unique identifiers.
        """
        a = objects.EncryptionKeyInformation(
            unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a"
        )
        b = objects.EncryptionKeyInformation(
            unique_identifier="00000000-1111-2222-3333-444444444444"
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_cryptographic_parameters(self):
        """
        Test that the equality operator returns False when comparing two
        EncryptionKeyInformation structs with different cryptographic
        parameters.
        """
        a = objects.EncryptionKeyInformation(
            cryptographic_parameters=attributes.CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.CBC
            )
        )
        b = objects.EncryptionKeyInformation(
            cryptographic_parameters=attributes.CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.GCM
            )
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        EncryptionKeyInformation structs with different types.
        """
        a = objects.EncryptionKeyInformation()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        EncryptionKeyInformation structs with the same data.
        """
        a = objects.EncryptionKeyInformation()
        b = objects.EncryptionKeyInformation()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = objects.EncryptionKeyInformation(
            unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
            cryptographic_parameters=attributes.CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.CBC
            )
        )
        b = objects.EncryptionKeyInformation(
            unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
            cryptographic_parameters=attributes.CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.CBC
            )
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_unique_identifier(self):
        """
        Test that the inequality operator returns True when comparing two
        EncryptionKeyInformation structs with different unique identifiers.
        """
        a = objects.EncryptionKeyInformation(
            unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a"
        )
        b = objects.EncryptionKeyInformation(
            unique_identifier="00000000-1111-2222-3333-444444444444"
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_cryptographic_parameters(self):
        """
        Test that the inequality operator returns True when comparing two
        EncryptionKeyInformation structs with different cryptographic
        parameters.
        """
        a = objects.EncryptionKeyInformation(
            cryptographic_parameters=attributes.CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.CBC
            )
        )
        b = objects.EncryptionKeyInformation(
            cryptographic_parameters=attributes.CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.GCM
            )
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        EncryptionKeyInformation structs with different types.
        """
        a = objects.EncryptionKeyInformation()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test that repr can be applied to an EncryptionKeyInformation struct.
        """
        encryption_key_information = objects.EncryptionKeyInformation(
            unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
            cryptographic_parameters=attributes.CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.CBC
            )
        )

        expected = (
            "EncryptionKeyInformation("
            "unique_identifier='100182d5-72b8-47aa-8383-4d97d512e98a', "
            "cryptographic_parameters=CryptographicParameters("
            "block_cipher_mode=BlockCipherMode.CBC, "
            "padding_method=None, "
            "hashing_algorithm=None, "
            "key_role_type=None, "
            "digital_signature_algorithm=None, "
            "cryptographic_algorithm=None, "
            "random_iv=None, "
            "iv_length=None, "
            "tag_length=None, "
            "fixed_field_length=None, "
            "invocation_field_length=None, "
            "counter_length=None, "
            "initial_counter_value=None))"
        )
        observed = repr(encryption_key_information)

        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to an EncryptionKeyInformation struct.
        """
        cryptographic_parameters = attributes.CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.CBC
        )
        encryption_key_information = objects.EncryptionKeyInformation(
            unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
            cryptographic_parameters=cryptographic_parameters
        )

        expected = str({
            'unique_identifier': "100182d5-72b8-47aa-8383-4d97d512e98a",
            'cryptographic_parameters': cryptographic_parameters
        })
        observed = str(encryption_key_information)

        self.assertEqual(expected, observed)

class TestMACSignatureKeyInformation(testtools.TestCase):
    """
    Test suite for the MACSignatureKeyInformation struct.
    """

    def setUp(self):
        super(TestMACSignatureKeyInformation, self).setUp()

        # Encoding obtained in part from the KMIP 1.1 testing document,
        # Section 14.1. The rest of the encoding was built by hand.
        #
        # This encoding matches the following set of values:
        # Unique Identifier - 100182d5-72b8-47aa-8383-4d97d512e98a
        # Cryptographic Parameters
        #     Block Cipher Mode - NIST_KEY_WRAP

        self.full_encoding = BytearrayStream(
            b'\x42\x00\x4E\x01\x00\x00\x00\x48'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x31\x30\x30\x31\x38\x32\x64\x35\x2D\x37\x32\x62\x38\x2D\x34\x37'
            b'\x61\x61\x2D\x38\x33\x38\x33\x2D\x34\x64\x39\x37\x64\x35\x31\x32'
            b'\x65\x39\x38\x61\x00\x00\x00\x00'
            b'\x42\x00\x2B\x01\x00\x00\x00\x10'
            b'\x42\x00\x11\x05\x00\x00\x00\x04\x00\x00\x00\x0D\x00\x00\x00\x00'
        )

        # Adapted from the full encoding above. This encoding matches the
        # following set of values:
        # Unique Identifier - 100182d5-72b8-47aa-8383-4d97d512e98a

        self.partial_encoding = BytearrayStream(
            b'\x42\x00\x4E\x01\x00\x00\x00\x30'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x31\x30\x30\x31\x38\x32\x64\x35\x2D\x37\x32\x62\x38\x2D\x34\x37'
            b'\x61\x61\x2D\x38\x33\x38\x33\x2D\x34\x64\x39\x37\x64\x35\x31\x32'
            b'\x65\x39\x38\x61\x00\x00\x00\x00'
        )

        self.empty_encoding = BytearrayStream(
            b'\x42\x00\x4E\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestMACSignatureKeyInformation, self).tearDown()

    def test_init(self):
        """
        Test that a MACSignatureKeyInformation struct can be constructed with
        no arguments.
        """
        mac_signature_key_information = objects.MACSignatureKeyInformation()

        self.assertEqual(
            None,
            mac_signature_key_information.unique_identifier
        )
        self.assertEqual(
            None,
            mac_signature_key_information.cryptographic_parameters
        )

    def test_init_with_args(self):
        """
        Test that a MACSignatureKeyInformation struct can be constructed with
        valid values.
        """
        cryptographic_parameters = attributes.CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.CTR)
        mac_signature_key_information = objects.MACSignatureKeyInformation(
            unique_identifier="00000000-1111-2222-3333-444444444444",
            cryptographic_parameters=cryptographic_parameters
        )

        self.assertEqual(
            "00000000-1111-2222-3333-444444444444",
            mac_signature_key_information.unique_identifier
        )
        self.assertIsInstance(
            mac_signature_key_information.cryptographic_parameters,
            attributes.CryptographicParameters
        )
        parameters = mac_signature_key_information.cryptographic_parameters
        self.assertEqual(
            enums.BlockCipherMode.CTR,
            parameters.block_cipher_mode
        )

        mac_signature_key_information = objects.MACSignatureKeyInformation(
            unique_identifier="00000000-1111-2222-3333-444444444444",
            cryptographic_parameters={
                'block_cipher_mode': enums.BlockCipherMode.CTR
            }
        )

        self.assertEqual(
            "00000000-1111-2222-3333-444444444444",
            mac_signature_key_information.unique_identifier
        )
        self.assertIsInstance(
            mac_signature_key_information.cryptographic_parameters,
            attributes.CryptographicParameters
        )
        parameters = mac_signature_key_information.cryptographic_parameters
        self.assertEqual(
            enums.BlockCipherMode.CTR,
            parameters.block_cipher_mode
        )

    def test_invalid_unique_identifier(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the unique identifier of a MACSignatureKeyInformation struct.
        """
        kwargs = {'unique_identifier': 0}
        self.assertRaisesRegex(
            TypeError,
            "Unique identifier must be a string.",
            objects.MACSignatureKeyInformation,
            **kwargs
        )

        args = (objects.MACSignatureKeyInformation(), 'unique_identifier', 0)
        self.assertRaisesRegex(
            TypeError,
            "Unique identifier must be a string.",
            setattr,
            *args
        )

    def test_invalid_cryptographic_parameters(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the cryptographic parameters of a MACSignatureKeyInformation struct.
        """
        kwargs = {'cryptographic_parameters': 'invalid'}
        self.assertRaisesRegex(
            TypeError,
            "Cryptographic parameters must be a CryptographicParameters "
            "struct.",
            objects.MACSignatureKeyInformation,
            **kwargs
        )

        args = (
            objects.MACSignatureKeyInformation(),
            'cryptographic_parameters',
            'invalid'
        )
        self.assertRaisesRegex(
            TypeError,
            "Cryptographic parameters must be a CryptographicParameters "
            "struct.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a MACSignatureKeyInformation struct can be read from a data
        stream.
        """
        mac_signature_key_information = objects.MACSignatureKeyInformation()

        self.assertEqual(
            None,
            mac_signature_key_information.unique_identifier
        )
        self.assertEqual(
            None,
            mac_signature_key_information.cryptographic_parameters
        )

        mac_signature_key_information.read(self.full_encoding)

        self.assertEqual(
            "100182d5-72b8-47aa-8383-4d97d512e98a",
            mac_signature_key_information.unique_identifier
        )
        self.assertIsInstance(
            mac_signature_key_information.cryptographic_parameters,
            attributes.CryptographicParameters
        )
        cryptographic_parameters = \
            mac_signature_key_information.cryptographic_parameters
        self.assertEqual(
            enums.BlockCipherMode.NIST_KEY_WRAP,
            cryptographic_parameters.block_cipher_mode
        )

    def test_read_partial(self):
        """
        Test that a MACSignatureKeyInformation struct can be read from a
        partial data stream.
        """
        mac_signature_key_information = objects.MACSignatureKeyInformation()

        self.assertEqual(
            None,
            mac_signature_key_information.unique_identifier
        )
        self.assertEqual(
            None,
            mac_signature_key_information.cryptographic_parameters
        )

        mac_signature_key_information.read(self.partial_encoding)

        self.assertEqual(
            "100182d5-72b8-47aa-8383-4d97d512e98a",
            mac_signature_key_information.unique_identifier
        )
        self.assertEqual(
            None,
            mac_signature_key_information.cryptographic_parameters
        )

    def test_read_invalid(self):
        """
        Test that a ValueError gets raised when a required
        MACSignatureKeyInformation field is missing from the struct encoding.
        """
        mac_signature_key_information = objects.MACSignatureKeyInformation()
        args = (self.empty_encoding,)
        self.assertRaisesRegex(
            ValueError,
            "Invalid struct missing the unique identifier attribute.",
            mac_signature_key_information.read,
            *args
        )

    def test_write(self):
        """
        Test that a MACSignatureKeyInformation struct can be written to a data
        stream.
        """
        cryptographic_parameters = attributes.CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
        )
        mac_signature_key_information = objects.MACSignatureKeyInformation(
            unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
            cryptographic_parameters=cryptographic_parameters
        )
        stream = BytearrayStream()
        mac_signature_key_information.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_partial(self):
        """
        Test that a partially defined MACSignatureKeyInformation struct can be
        written to a data stream.
        """
        mac_signature_key_information = objects.MACSignatureKeyInformation(
            unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a"
        )
        stream = BytearrayStream()
        mac_signature_key_information.write(stream)

        self.assertEqual(len(self.partial_encoding), len(stream))
        self.assertEqual(str(self.partial_encoding), str(stream))

    def test_write_invalid(self):
        """
        Test that a ValueError gets raised when a required
        MACSignatureKeyInformation field is missing when encoding the struct.
        """
        mac_signature_key_information = objects.MACSignatureKeyInformation()
        stream = utils.BytearrayStream()
        args = (stream,)
        self.assertRaisesRegex(
            ValueError,
            "Invalid struct missing the unique identifier attribute.",
            mac_signature_key_information.write,
            *args
        )

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        MACSignatureKeyInformation structs with the same data.
        """
        a = objects.MACSignatureKeyInformation()
        b = objects.MACSignatureKeyInformation()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = objects.MACSignatureKeyInformation(
            unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
            cryptographic_parameters=attributes.CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.CBC
            )
        )
        b = objects.MACSignatureKeyInformation(
            unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
            cryptographic_parameters=attributes.CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.CBC
            )
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_unique_identifier(self):
        """
        Test that the equality operator returns False when comparing two
        MACSignatureKeyInformation structs with different unique identifiers.
        """
        a = objects.MACSignatureKeyInformation(
            unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a"
        )
        b = objects.MACSignatureKeyInformation(
            unique_identifier="00000000-1111-2222-3333-444444444444"
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_cryptographic_parameters(self):
        """
        Test that the equality operator returns False when comparing two
        MACSignatureKeyInformation structs with different cryptographic
        parameters.
        """
        a = objects.MACSignatureKeyInformation(
            cryptographic_parameters=attributes.CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.CBC
            )
        )
        b = objects.MACSignatureKeyInformation(
            cryptographic_parameters=attributes.CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.GCM
            )
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        MACSignatureKeyInformation structs with different types.
        """
        a = objects.MACSignatureKeyInformation()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        MACSignatureKeyInformation structs with the same data.
        """
        a = objects.MACSignatureKeyInformation()
        b = objects.MACSignatureKeyInformation()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = objects.MACSignatureKeyInformation(
            unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
            cryptographic_parameters=attributes.CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.CBC
            )
        )
        b = objects.MACSignatureKeyInformation(
            unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
            cryptographic_parameters=attributes.CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.CBC
            )
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_unique_identifier(self):
        """
        Test that the inequality operator returns True when comparing two
        MACSignatureKeyInformation structs with different unique identifiers.
        """
        a = objects.MACSignatureKeyInformation(
            unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a"
        )
        b = objects.MACSignatureKeyInformation(
            unique_identifier="00000000-1111-2222-3333-444444444444"
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_cryptographic_parameters(self):
        """
        Test that the inequality operator returns True when comparing two
        MACSignatureKeyInformation structs with different cryptographic
        parameters.
        """
        a = objects.MACSignatureKeyInformation(
            cryptographic_parameters=attributes.CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.CBC
            )
        )
        b = objects.MACSignatureKeyInformation(
            cryptographic_parameters=attributes.CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.GCM
            )
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        MACSignatureKeyInformation structs with different types.
        """
        a = objects.MACSignatureKeyInformation()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test that repr can be applied to an MACSignatureKeyInformation struct.
        """
        mac_signature_key_information = objects.MACSignatureKeyInformation(
            unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
            cryptographic_parameters=attributes.CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.CBC
            )
        )

        expected = (
            "MACSignatureKeyInformation("
            "unique_identifier='100182d5-72b8-47aa-8383-4d97d512e98a', "
            "cryptographic_parameters=CryptographicParameters("
            "block_cipher_mode=BlockCipherMode.CBC, "
            "padding_method=None, "
            "hashing_algorithm=None, "
            "key_role_type=None, "
            "digital_signature_algorithm=None, "
            "cryptographic_algorithm=None, "
            "random_iv=None, "
            "iv_length=None, "
            "tag_length=None, "
            "fixed_field_length=None, "
            "invocation_field_length=None, "
            "counter_length=None, "
            "initial_counter_value=None))"
        )
        observed = repr(mac_signature_key_information)

        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a MACSignatureKeyInformation struct.
        """
        cryptographic_parameters = attributes.CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.CBC
        )
        mac_signature_key_information = objects.MACSignatureKeyInformation(
            unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
            cryptographic_parameters=cryptographic_parameters
        )

        expected = str({
            'unique_identifier': "100182d5-72b8-47aa-8383-4d97d512e98a",
            'cryptographic_parameters': cryptographic_parameters
        })
        observed = str(mac_signature_key_information)

        self.assertEqual(expected, observed)

class TestKeyWrappingData(testtools.TestCase):
    """
    Test suite for the KeyWrappingData struct.
    """

    def setUp(self):
        super(TestKeyWrappingData, self).setUp()

        # Encoding obtained in part from the KMIP 1.1 testing document,
        # Sections 14.1. The rest was built by hand.
        #
        # This encoding matches the following set of values:
        #
        # Wrapping Method - ENCRYPT
        # Encryption Key Information
        #     Unique Identifier - 100182d5-72b8-47aa-8383-4d97d512e98a
        #     Cryptographic Parameters
        #         Block Cipher Mode - NIST_KEY_WRAP
        # MAC/Signature Key Information
        #     Unique Identifier - 100182d5-72b8-47aa-8383-4d97d512e98a
        #     Cryptographic Parameters
        #         Block Cipher Mode - NIST_KEY_WRAP
        # MAC/Signature - 0x0123456789ABCDEF
        # IV/Counter/Nonce - 0x01
        # Encoding Option - NO_ENCODING

        self.full_encoding = BytearrayStream(
            b'\x42\x00\x46\x01\x00\x00\x00\xE0'
            b'\x42\x00\x9E\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x36\x01\x00\x00\x00\x48'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x31\x30\x30\x31\x38\x32\x64\x35\x2D\x37\x32\x62\x38\x2D\x34\x37'
            b'\x61\x61\x2D\x38\x33\x38\x33\x2D\x34\x64\x39\x37\x64\x35\x31\x32'
            b'\x65\x39\x38\x61\x00\x00\x00\x00'
            b'\x42\x00\x2B\x01\x00\x00\x00\x10'
            b'\x42\x00\x11\x05\x00\x00\x00\x04\x00\x00\x00\x0D\x00\x00\x00\x00'
            b'\x42\x00\x4E\x01\x00\x00\x00\x48'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x31\x30\x30\x31\x38\x32\x64\x35\x2D\x37\x32\x62\x38\x2D\x34\x37'
            b'\x61\x61\x2D\x38\x33\x38\x33\x2D\x34\x64\x39\x37\x64\x35\x31\x32'
            b'\x65\x39\x38\x61\x00\x00\x00\x00'
            b'\x42\x00\x2B\x01\x00\x00\x00\x10'
            b'\x42\x00\x11\x05\x00\x00\x00\x04\x00\x00\x00\x0D\x00\x00\x00\x00'
            b'\x42\x00\x4D\x08\x00\x00\x00\x08\x01\x23\x45\x67\x89\xAB\xCD\xEF'
            b'\x42\x00\x3D\x08\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xA3\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
        )

        # Encoding obtained from the KMIP 1.1 testing document, Section 14.1.
        # This encoding matches the following set of values:
        #
        # Wrapping Method - ENCRYPT
        # Encryption Key Information
        #     Unique Identifier - 100182d5-72b8-47aa-8383-4d97d512e98a
        #     Cryptographic Parameters
        #         Block Cipher Mode - NIST_KEY_WRAP
        # Encoding Option - NO_ENCODING

        self.partial_encoding = BytearrayStream(
            b'\x42\x00\x46\x01\x00\x00\x00\x70'
            b'\x42\x00\x9E\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x36\x01\x00\x00\x00\x48'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x31\x30\x30\x31\x38\x32\x64\x35\x2D\x37\x32\x62\x38\x2D\x34\x37'
            b'\x61\x61\x2D\x38\x33\x38\x33\x2D\x34\x64\x39\x37\x64\x35\x31\x32'
            b'\x65\x39\x38\x61\x00\x00\x00\x00'
            b'\x42\x00\x2B\x01\x00\x00\x00\x10'
            b'\x42\x00\x11\x05\x00\x00\x00\x04\x00\x00\x00\x0D\x00\x00\x00\x00'
            b'\x42\x00\xA3\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
        )

        self.empty_encoding = BytearrayStream(
            b'\x42\x00\x46\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestKeyWrappingData, self).tearDown()

    def test_init(self):
        """
        Test that a KeyWrappingData struct can be constructed with no
        arguments.
        """
        key_wrapping_data = objects.KeyWrappingData()

        self.assertEqual(None, key_wrapping_data.wrapping_method)
        self.assertEqual(None, key_wrapping_data.encryption_key_information)
        self.assertEqual(None, key_wrapping_data.mac_signature_key_information)
        self.assertEqual(None, key_wrapping_data.mac_signature)
        self.assertEqual(None, key_wrapping_data.iv_counter_nonce)
        self.assertEqual(None, key_wrapping_data.encoding_option)

    def test_init_with_args(self):
        """
        Test that a KeyWrappingData struct can be constructed with valid
        values.
        """
        key_wrapping_data = objects.KeyWrappingData(
            wrapping_method=enums.WrappingMethod.ENCRYPT,
            encryption_key_information=objects.EncryptionKeyInformation(
                unique_identifier="12345678-9012-3456-7890-123456789012",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.CTR
                )
            ),
            mac_signature_key_information=objects.MACSignatureKeyInformation(
                unique_identifier="00000000-1111-2222-3333-444444444444",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                )
            ),
            mac_signature=b'\x01',
            iv_counter_nonce=b'\x02',
            encoding_option=enums.EncodingOption.TTLV_ENCODING
        )

        self.assertEqual(
            enums.WrappingMethod.ENCRYPT,
            key_wrapping_data.wrapping_method
        )
        self.assertIsInstance(
            key_wrapping_data.encryption_key_information,
            objects.EncryptionKeyInformation
        )
        e = key_wrapping_data.encryption_key_information
        self.assertEqual(
            "12345678-9012-3456-7890-123456789012",
            e.unique_identifier
        )
        self.assertIsInstance(
            e.cryptographic_parameters,
            attributes.CryptographicParameters
        )
        self.assertEqual(
            enums.BlockCipherMode.CTR,
            e.cryptographic_parameters.block_cipher_mode
        )
        self.assertIsInstance(
            key_wrapping_data.mac_signature_key_information,
            objects.MACSignatureKeyInformation
        )
        m = key_wrapping_data.mac_signature_key_information
        self.assertEqual(
            "00000000-1111-2222-3333-444444444444",
            m.unique_identifier
        )
        self.assertIsInstance(
            m.cryptographic_parameters,
            attributes.CryptographicParameters
        )
        self.assertEqual(
            enums.BlockCipherMode.NIST_KEY_WRAP,
            m.cryptographic_parameters.block_cipher_mode
        )
        self.assertEqual(b'\x01', key_wrapping_data.mac_signature)
        self.assertEqual(b'\x02', key_wrapping_data.iv_counter_nonce)
        self.assertEqual(
            enums.EncodingOption.TTLV_ENCODING,
            key_wrapping_data.encoding_option
        )

        key_wrapping_data = objects.KeyWrappingData(
            wrapping_method=enums.WrappingMethod.ENCRYPT,
            encryption_key_information={
                'unique_identifier': "12345678-9012-3456-7890-123456789012",
                'cryptographic_parameters': {
                    'block_cipher_mode': enums.BlockCipherMode.CTR
                }
            },
            mac_signature_key_information={
                'unique_identifier': "00000000-1111-2222-3333-444444444444",
                'cryptographic_parameters': {
                    'block_cipher_mode': enums.BlockCipherMode.NIST_KEY_WRAP
                }
            },
            mac_signature=b'\x01',
            iv_counter_nonce=b'\x02',
            encoding_option=enums.EncodingOption.TTLV_ENCODING
        )

        self.assertEqual(
            enums.WrappingMethod.ENCRYPT,
            key_wrapping_data.wrapping_method
        )
        self.assertIsInstance(
            key_wrapping_data.encryption_key_information,
            objects.EncryptionKeyInformation
        )
        e = key_wrapping_data.encryption_key_information
        self.assertEqual(
            "12345678-9012-3456-7890-123456789012",
            e.unique_identifier
        )
        self.assertIsInstance(
            e.cryptographic_parameters,
            attributes.CryptographicParameters
        )
        self.assertEqual(
            enums.BlockCipherMode.CTR,
            e.cryptographic_parameters.block_cipher_mode
        )
        self.assertIsInstance(
            key_wrapping_data.mac_signature_key_information,
            objects.MACSignatureKeyInformation
        )
        m = key_wrapping_data.mac_signature_key_information
        self.assertEqual(
            "00000000-1111-2222-3333-444444444444",
            m.unique_identifier
        )
        self.assertIsInstance(
            m.cryptographic_parameters,
            attributes.CryptographicParameters
        )
        self.assertEqual(
            enums.BlockCipherMode.NIST_KEY_WRAP,
            m.cryptographic_parameters.block_cipher_mode
        )
        self.assertEqual(b'\x01', key_wrapping_data.mac_signature)
        self.assertEqual(b'\x02', key_wrapping_data.iv_counter_nonce)
        self.assertEqual(
            enums.EncodingOption.TTLV_ENCODING,
            key_wrapping_data.encoding_option
        )

    def test_invalid_wrapping_method(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the wrapping method of a KeyWrappingData struct.
        """
        kwargs = {'wrapping_method': 'invalid'}
        self.assertRaisesRegex(
            TypeError,
            "Wrapping method must be a WrappingMethod enumeration.",
            objects.KeyWrappingData,
            **kwargs
        )

        args = (objects.KeyWrappingData(), 'wrapping_method', 0)
        self.assertRaisesRegex(
            TypeError,
            "Wrapping method must be a WrappingMethod enumeration.",
            setattr,
            *args
        )

    def test_invalid_encryption_key_information(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the encryption key information of a KeyWrappingData struct.
        """
        kwargs = {'encryption_key_information': 'invalid'}
        self.assertRaisesRegex(
            TypeError,
            "Encryption key information must be an EncryptionKeyInformation "
            "struct.",
            objects.KeyWrappingData,
            **kwargs
        )

        args = (
            objects.KeyWrappingData(),
            'encryption_key_information',
            'invalid'
        )
        self.assertRaisesRegex(
            TypeError,
            "Encryption key information must be an EncryptionKeyInformation "
            "struct.",
            setattr,
            *args
        )

    def test_invalid_mac_signature_key_information(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the MAC/signature key information of a KeyWrappingData struct.
        """
        kwargs = {'mac_signature_key_information': 'invalid'}
        self.assertRaisesRegex(
            TypeError,
            "MAC/signature key information must be an "
            "MACSignatureKeyInformation struct.",
            objects.KeyWrappingData,
            **kwargs
        )

        args = (
            objects.KeyWrappingData(),
            'mac_signature_key_information',
            'invalid'
        )
        self.assertRaisesRegex(
            TypeError,
            "MAC/signature key information must be an "
            "MACSignatureKeyInformation struct.",
            setattr,
            *args
        )

    def test_invalid_mac_signature(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the MAC/signature of a KeyWrappingData struct.
        """
        kwargs = {'mac_signature': 0}
        self.assertRaisesRegex(
            TypeError,
            "MAC/signature must be bytes.",
            objects.KeyWrappingData,
            **kwargs
        )

        args = (
            objects.KeyWrappingData(),
            'mac_signature',
            0
        )
        self.assertRaisesRegex(
            TypeError,
            "MAC/signature must be bytes.",
            setattr,
            *args
        )

    def test_invalid_iv_counter_nonce(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the IV/counter/nonce of a KeyWrappingData struct.
        """
        kwargs = {'iv_counter_nonce': 0}
        self.assertRaisesRegex(
            TypeError,
            "IV/counter/nonce must be bytes.",
            objects.KeyWrappingData,
            **kwargs
        )

        args = (
            objects.KeyWrappingData(),
            'iv_counter_nonce',
            0
        )
        self.assertRaisesRegex(
            TypeError,
            "IV/counter/nonce must be bytes.",
            setattr,
            *args
        )

    def test_invalid_encoding_option(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the encoding option of a KeyWrappingData struct.
        """
        kwargs = {'encoding_option': 'invalid'}
        self.assertRaisesRegex(
            TypeError,
            "Encoding option must be an EncodingOption enumeration.",
            objects.KeyWrappingData,
            **kwargs
        )

        args = (
            objects.KeyWrappingData(),
            'encoding_option',
            'invalid'
        )
        self.assertRaisesRegex(
            TypeError,
            "Encoding option must be an EncodingOption enumeration.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a KeyWrappingData struct can be read from a data stream.
        """
        key_wrapping_data = objects.KeyWrappingData()

        self.assertEqual(None, key_wrapping_data.wrapping_method)
        self.assertEqual(None, key_wrapping_data.encryption_key_information)
        self.assertEqual(None, key_wrapping_data.mac_signature_key_information)
        self.assertEqual(None, key_wrapping_data.mac_signature)
        self.assertEqual(None, key_wrapping_data.iv_counter_nonce)
        self.assertEqual(None, key_wrapping_data.encoding_option)

        key_wrapping_data.read(self.full_encoding)

        self.assertEqual(
            enums.WrappingMethod.ENCRYPT,
            key_wrapping_data.wrapping_method
        )
        self.assertIsInstance(
            key_wrapping_data.encryption_key_information,
            objects.EncryptionKeyInformation
        )
        e = key_wrapping_data.encryption_key_information
        self.assertEqual(
            "100182d5-72b8-47aa-8383-4d97d512e98a",
            e.unique_identifier
        )
        self.assertIsInstance(
            e.cryptographic_parameters,
            attributes.CryptographicParameters
        )
        self.assertEqual(
            enums.BlockCipherMode.NIST_KEY_WRAP,
            e.cryptographic_parameters.block_cipher_mode
        )
        self.assertIsInstance(
            key_wrapping_data.mac_signature_key_information,
            objects.MACSignatureKeyInformation
        )
        m = key_wrapping_data.mac_signature_key_information
        self.assertEqual(
            "100182d5-72b8-47aa-8383-4d97d512e98a",
            m.unique_identifier
        )
        self.assertIsInstance(
            m.cryptographic_parameters,
            attributes.CryptographicParameters
        )
        self.assertEqual(
            enums.BlockCipherMode.NIST_KEY_WRAP,
            m.cryptographic_parameters.block_cipher_mode
        )
        self.assertEqual(
            b'\x01\x23\x45\x67\x89\xAB\xCD\xEF',
            key_wrapping_data.mac_signature
        )
        self.assertEqual(
            b'\x01',
            key_wrapping_data.iv_counter_nonce
        )
        self.assertEqual(
            enums.EncodingOption.NO_ENCODING,
            key_wrapping_data.encoding_option
        )

    def test_read_partial(self):
        """
        Test that a KeyWrappingData struct can be read from a partial data
        stream.
        """
        key_wrapping_data = objects.KeyWrappingData()

        self.assertEqual(None, key_wrapping_data.wrapping_method)
        self.assertEqual(None, key_wrapping_data.encryption_key_information)
        self.assertEqual(None, key_wrapping_data.mac_signature_key_information)
        self.assertEqual(None, key_wrapping_data.mac_signature)
        self.assertEqual(None, key_wrapping_data.iv_counter_nonce)
        self.assertEqual(None, key_wrapping_data.encoding_option)

        key_wrapping_data.read(self.partial_encoding)

        self.assertEqual(
            enums.WrappingMethod.ENCRYPT,
            key_wrapping_data.wrapping_method
        )
        self.assertIsInstance(
            key_wrapping_data.encryption_key_information,
            objects.EncryptionKeyInformation
        )
        e = key_wrapping_data.encryption_key_information
        self.assertEqual(
            "100182d5-72b8-47aa-8383-4d97d512e98a",
            e.unique_identifier
        )
        self.assertIsInstance(
            e.cryptographic_parameters,
            attributes.CryptographicParameters
        )
        self.assertEqual(
            enums.BlockCipherMode.NIST_KEY_WRAP,
            e.cryptographic_parameters.block_cipher_mode
        )
        self.assertIsNone(key_wrapping_data.mac_signature_key_information)
        self.assertIsNone(key_wrapping_data.mac_signature)
        self.assertIsNone(key_wrapping_data.iv_counter_nonce)
        self.assertEqual(
            enums.EncodingOption.NO_ENCODING,
            key_wrapping_data.encoding_option
        )

    def test_read_invalid(self):
        """
        Test that a ValueError gets raised when a required KeyWrappingData
        field is missing from the struct encoding.
        """
        key_wrapping_data = objects.KeyWrappingData()
        args = (self.empty_encoding,)
        self.assertRaisesRegex(
            ValueError,
            "Invalid struct missing the wrapping method attribute.",
            key_wrapping_data.read,
            *args
        )

    def test_write(self):
        """
        Test that a KeyWrappingData struct can be written to a data stream.
        """
        key_wrapping_data = objects.KeyWrappingData(
            wrapping_method=enums.WrappingMethod.ENCRYPT,
            encryption_key_information=objects.EncryptionKeyInformation(
                unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                )
            ),
            mac_signature_key_information=objects.MACSignatureKeyInformation(
                unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                )
            ),
            mac_signature=b'\x01\x23\x45\x67\x89\xAB\xCD\xEF',
            iv_counter_nonce=b'\x01',
            encoding_option=enums.EncodingOption.NO_ENCODING
        )
        stream = BytearrayStream()
        key_wrapping_data.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_partial(self):
        """
        Test that a partially defined KeyWrappingData struct can be written to
        a data stream.
        """
        key_wrapping_data = objects.KeyWrappingData(
            wrapping_method=enums.WrappingMethod.ENCRYPT,
            encryption_key_information=objects.EncryptionKeyInformation(
                unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                )
            ),
            encoding_option=enums.EncodingOption.NO_ENCODING
        )
        stream = BytearrayStream()
        key_wrapping_data.write(stream)

        self.assertEqual(len(self.partial_encoding), len(stream))
        self.assertEqual(str(self.partial_encoding), str(stream))

    def test_write_invalid(self):
        """
        Test that a ValueError gets raised when a required KeyWrappingData
        field is missing when encoding the struct.
        """
        key_wrapping_data = objects.KeyWrappingData()
        stream = utils.BytearrayStream()
        args = (stream,)
        self.assertRaisesRegex(
            ValueError,
            "Invalid struct missing the wrapping method attribute.",
            key_wrapping_data.write,
            *args
        )

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        KeyWrappingData structs with the same data.
        """
        a = objects.KeyWrappingData()
        b = objects.KeyWrappingData()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = objects.KeyWrappingData(
            wrapping_method=enums.WrappingMethod.ENCRYPT,
            encryption_key_information=objects.EncryptionKeyInformation(
                unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                )
            ),
            mac_signature_key_information=objects.MACSignatureKeyInformation(
                unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                )
            ),
            mac_signature=b'\x01\x01\x01\x01\x01\x01\x01\x01',
            iv_counter_nonce=b'\x01',
            encoding_option=enums.EncodingOption.NO_ENCODING
        )
        b = objects.KeyWrappingData(
            wrapping_method=enums.WrappingMethod.ENCRYPT,
            encryption_key_information=objects.EncryptionKeyInformation(
                unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                )
            ),
            mac_signature_key_information=objects.MACSignatureKeyInformation(
                unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                )
            ),
            mac_signature=b'\x01\x01\x01\x01\x01\x01\x01\x01',
            iv_counter_nonce=b'\x01',
            encoding_option=enums.EncodingOption.NO_ENCODING
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_wrapping_method(self):
        """
        Test that the equality operator returns False when comparing two
        KeyWrappingData structs with different wrapping methods.
        """
        a = objects.KeyWrappingData(
            wrapping_method=enums.WrappingMethod.ENCRYPT
        )
        b = objects.KeyWrappingData(
            wrapping_method=enums.WrappingMethod.MAC_SIGN
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_encryption_key_information(self):
        """
        Test that the equality operator returns False when comparing two
        KeyWrappingData structs with different encryption key information.
        """
        a = objects.KeyWrappingData(
            encryption_key_information=objects.EncryptionKeyInformation(
                unique_identifier="100182d5-72b8-ffff-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.CBC
                )
            )
        )
        b = objects.KeyWrappingData(
            encryption_key_information=objects.EncryptionKeyInformation(
                unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                )
            )
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_mac_signature_key_information(self):
        """
        Test that the equality operator returns False when comparing two
        KeyWrappingData structs with different MAC/signature key information.
        """
        a = objects.KeyWrappingData(
            mac_signature_key_information=objects.MACSignatureKeyInformation(
                unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                )
            )
        )
        b = objects.KeyWrappingData(
            mac_signature_key_information=objects.MACSignatureKeyInformation(
                unique_identifier="100182d5-72b8-ffff-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.CBC
                )
            )
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_mac_signatures(self):
        """
        Test that the equality operator returns False when comparing two
        KeyWrappingData structs with different MAC/signatures.
        """
        a = objects.KeyWrappingData(mac_signature=b'\x01')
        b = objects.KeyWrappingData(mac_signature=b'\x10')

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_iv_counter_nonce(self):
        """
        Test that the equality operator returns False when comparing two
        KeyWrappingData structs with different IV/counter/nonces.
        """
        a = objects.KeyWrappingData(iv_counter_nonce=b'\x01')
        b = objects.KeyWrappingData(iv_counter_nonce=b'\x10')

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_encoding_option(self):
        """
        Test that the equality operator returns False when comparing two
        KeyWrappingData structs with different encoding options.
        """
        a = objects.KeyWrappingData(
            encoding_option=enums.EncodingOption.NO_ENCODING
        )
        b = objects.KeyWrappingData(
            encoding_option=enums.EncodingOption.TTLV_ENCODING
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        KeyWrappingData structs with different types.
        """
        a = objects.KeyWrappingData()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        KeyWrappingData structs with the same data.
        """
        a = objects.KeyWrappingData()
        b = objects.KeyWrappingData()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = objects.KeyWrappingData(
            wrapping_method=enums.WrappingMethod.ENCRYPT,
            encryption_key_information=objects.EncryptionKeyInformation(
                unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                )
            ),
            mac_signature_key_information=objects.MACSignatureKeyInformation(
                unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                )
            ),
            mac_signature=b'\x01\x01\x01\x01\x01\x01\x01\x01',
            iv_counter_nonce=b'\x01',
            encoding_option=enums.EncodingOption.NO_ENCODING
        )
        b = objects.KeyWrappingData(
            wrapping_method=enums.WrappingMethod.ENCRYPT,
            encryption_key_information=objects.EncryptionKeyInformation(
                unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                )
            ),
            mac_signature_key_information=objects.MACSignatureKeyInformation(
                unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                )
            ),
            mac_signature=b'\x01\x01\x01\x01\x01\x01\x01\x01',
            iv_counter_nonce=b'\x01',
            encoding_option=enums.EncodingOption.NO_ENCODING
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_wrapping_method(self):
        """
        Test that the inequality operator returns True when comparing two
        KeyWrappingData structs with different wrapping methods.
        """
        a = objects.KeyWrappingData(
            wrapping_method=enums.WrappingMethod.ENCRYPT
        )
        b = objects.KeyWrappingData(
            wrapping_method=enums.WrappingMethod.MAC_SIGN
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_encryption_key_information(self):
        """
        Test that the inequality operator returns True when comparing two
        KeyWrappingData structs with different encryption key information.
        """
        a = objects.KeyWrappingData(
            encryption_key_information=objects.EncryptionKeyInformation(
                unique_identifier="100182d5-72b8-ffff-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.CBC
                )
            )
        )
        b = objects.KeyWrappingData(
            encryption_key_information=objects.EncryptionKeyInformation(
                unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                )
            )
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_mac_signature_key_information(self):
        """
        Test that the inequality operator returns True when comparing two
        KeyWrappingData structs with different MAC/signature key information.
        """
        a = objects.KeyWrappingData(
            mac_signature_key_information=objects.MACSignatureKeyInformation(
                unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                )
            )
        )
        b = objects.KeyWrappingData(
            mac_signature_key_information=objects.MACSignatureKeyInformation(
                unique_identifier="100182d5-72b8-ffff-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.CBC
                )
            )
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_mac_signatures(self):
        """
        Test that the inequality operator returns True when comparing two
        KeyWrappingData structs with different MAC/signatures.
        """
        a = objects.KeyWrappingData(mac_signature=b'\x01')
        b = objects.KeyWrappingData(mac_signature=b'\x10')

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_iv_counter_nonce(self):
        """
        Test that the inequality operator returns True when comparing two
        KeyWrappingData structs with different IV/counter/nonces.
        """
        a = objects.KeyWrappingData(iv_counter_nonce=b'\x01')
        b = objects.KeyWrappingData(iv_counter_nonce=b'\x10')

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_encoding_option(self):
        """
        Test that the inequality operator returns True when comparing two
        KeyWrappingData structs with different encoding options.
        """
        a = objects.KeyWrappingData(
            encoding_option=enums.EncodingOption.NO_ENCODING
        )
        b = objects.KeyWrappingData(
            encoding_option=enums.EncodingOption.TTLV_ENCODING
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        KeyWrappingData structs with different types.
        """
        a = objects.KeyWrappingData()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test that repr can be applied to an KeyWrappingData struct.
        """
        key_wrapping_data = objects.KeyWrappingData(
            wrapping_method=enums.WrappingMethod.ENCRYPT,
            encryption_key_information=objects.EncryptionKeyInformation(
                unique_identifier="100182d5-72b8-ffff-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                )
            ),
            mac_signature_key_information=objects.MACSignatureKeyInformation(
                unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.CBC
                )
            ),
            mac_signature=b'\x01\x01\x02\x02\x03\x03\x04\x04',
            iv_counter_nonce=b'\xFF',
            encoding_option=enums.EncodingOption.TTLV_ENCODING
        )

        expected = (
            "KeyWrappingData("
            "wrapping_method=WrappingMethod.ENCRYPT, "
            "encryption_key_information=EncryptionKeyInformation("
            "unique_identifier='100182d5-72b8-ffff-8383-4d97d512e98a', "
            "cryptographic_parameters=CryptographicParameters("
            "block_cipher_mode=BlockCipherMode.NIST_KEY_WRAP, "
            "padding_method=None, "
            "hashing_algorithm=None, "
            "key_role_type=None, "
            "digital_signature_algorithm=None, "
            "cryptographic_algorithm=None, "
            "random_iv=None, "
            "iv_length=None, "
            "tag_length=None, "
            "fixed_field_length=None, "
            "invocation_field_length=None, "
            "counter_length=None, "
            "initial_counter_value=None)), "
            "mac_signature_key_information=MACSignatureKeyInformation("
            "unique_identifier='100182d5-72b8-47aa-8383-4d97d512e98a', "
            "cryptographic_parameters=CryptographicParameters("
            "block_cipher_mode=BlockCipherMode.CBC, "
            "padding_method=None, "
            "hashing_algorithm=None, "
            "key_role_type=None, "
            "digital_signature_algorithm=None, "
            "cryptographic_algorithm=None, "
            "random_iv=None, "
            "iv_length=None, "
            "tag_length=None, "
            "fixed_field_length=None, "
            "invocation_field_length=None, "
            "counter_length=None, "
            "initial_counter_value=None)), "
            "mac_signature={0}, "
            "iv_counter_nonce={1}, "
            "encoding_option=EncodingOption.TTLV_ENCODING)".format(
                b'\x01\x01\x02\x02\x03\x03\x04\x04',
                b'\xFF'
            )
        )
        observed = repr(key_wrapping_data)

        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a KeyWrappingData struct.
        """
        key_wrapping_data = objects.KeyWrappingData(
            wrapping_method=enums.WrappingMethod.ENCRYPT,
            encryption_key_information=objects.EncryptionKeyInformation(
                unique_identifier="100182d5-72b8-ffff-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                )
            ),
            mac_signature_key_information=objects.MACSignatureKeyInformation(
                unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.CBC
                )
            ),
            mac_signature=b'\x01\x01\x02\x02\x03\x03\x04\x04',
            iv_counter_nonce=b'\xFF',
            encoding_option=enums.EncodingOption.TTLV_ENCODING
        )

        expected = str({
            'wrapping_method': enums.WrappingMethod.ENCRYPT,
            'encryption_key_information': objects.EncryptionKeyInformation(
                unique_identifier="100182d5-72b8-ffff-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                )
            ),
            'mac_signature_key_information':
                objects.MACSignatureKeyInformation(
                unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.CBC
                )
            ),
            'mac_signature': b'\x01\x01\x02\x02\x03\x03\x04\x04',
            'iv_counter_nonce': b'\xFF',
            'encoding_option': enums.EncodingOption.TTLV_ENCODING
        })
        observed = str(key_wrapping_data)

        self.assertEqual(expected, observed)

class TestKeyWrappingSpecification(testtools.TestCase):
    """
    Test suite for the KeyWrappingSpecification struct.
    """

    def setUp(self):
        super(TestKeyWrappingSpecification, self).setUp()

        # Encoding obtained in part from the KMIP 1.1 testing document,
        # Sections 14.1 and 14.2. The rest was built by hand.
        #
        # This encoding matches the following set of values:
        #
        # Wrapping Method - Encrypt
        # Encryption Key Information
        #     Unique Identifier - 100182d5-72b8-47aa-8383-4d97d512e98a
        #     Cryptographic Parameters
        #         Block Cipher Mode - NIST_KEY_WRAP
        # MAC/Signature Key Information
        #     Unique Identifier - 100182d5-72b8-47aa-8383-4d97d512e98a
        #     Cryptographic Parameters
        #         Block Cipher Mode - NIST_KEY_WRAP
        # Attribute Names
        #     Cryptographic Usage Mask
        # Encoding Option - NO_ENCODING

        self.full_encoding = BytearrayStream(
            b'\x42\x00\x47\x01\x00\x00\x00\xE0'
            b'\x42\x00\x9E\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x36\x01\x00\x00\x00\x48'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x31\x30\x30\x31\x38\x32\x64\x35\x2D\x37\x32\x62\x38\x2D\x34\x37'
            b'\x61\x61\x2D\x38\x33\x38\x33\x2D\x34\x64\x39\x37\x64\x35\x31\x32'
            b'\x65\x39\x38\x61\x00\x00\x00\x00'
            b'\x42\x00\x2B\x01\x00\x00\x00\x10'
            b'\x42\x00\x11\x05\x00\x00\x00\x04\x00\x00\x00\x0D\x00\x00\x00\x00'
            b'\x42\x00\x4E\x01\x00\x00\x00\x48'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x31\x30\x30\x31\x38\x32\x64\x35\x2D\x37\x32\x62\x38\x2D\x34\x37'
            b'\x61\x61\x2D\x38\x33\x38\x33\x2D\x34\x64\x39\x37\x64\x35\x31\x32'
            b'\x65\x39\x38\x61\x00\x00\x00\x00'
            b'\x42\x00\x2B\x01\x00\x00\x00\x10'
            b'\x42\x00\x11\x05\x00\x00\x00\x04\x00\x00\x00\x0D\x00\x00\x00\x00'
            b'\x42\x00\x0A\x07\x00\x00\x00\x18'
            b'\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x55\x73'
            b'\x61\x67\x65\x20\x4D\x61\x73\x6B'
            b'\x42\x00\xA3\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
        )

        # Adapted from the full encoding above. This encoding matches the
        # following set of values:
        #
        # Wrapping Method - Encrypt
        # Encryption Key Information
        #     Unique Identifier - 100182d5-72b8-47aa-8383-4d97d512e98a
        #     Cryptographic Parameters
        #         Block Cipher Mode - NIST_KEY_WRAP

        self.partial_encoding = BytearrayStream(
            b'\x42\x00\x47\x01\x00\x00\x00\x60'
            b'\x42\x00\x9E\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x36\x01\x00\x00\x00\x48'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x31\x30\x30\x31\x38\x32\x64\x35\x2D\x37\x32\x62\x38\x2D\x34\x37'
            b'\x61\x61\x2D\x38\x33\x38\x33\x2D\x34\x64\x39\x37\x64\x35\x31\x32'
            b'\x65\x39\x38\x61\x00\x00\x00\x00'
            b'\x42\x00\x2B\x01\x00\x00\x00\x10'
            b'\x42\x00\x11\x05\x00\x00\x00\x04\x00\x00\x00\x0D\x00\x00\x00\x00'
        )

        self.empty_encoding = BytearrayStream(
            b'\x42\x00\x47\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestKeyWrappingSpecification, self).tearDown()

    def test_init(self):
        """
        Test that a KeyWrappingSpecification struct can be constructed with
        no arguments.
        """
        key_wrapping_specification = objects.KeyWrappingSpecification()

        self.assertEqual(None, key_wrapping_specification.wrapping_method)
        self.assertEqual(
            None,
            key_wrapping_specification.encryption_key_information
        )
        self.assertEqual(
            None,
            key_wrapping_specification.mac_signature_key_information
        )
        self.assertEqual(None, key_wrapping_specification.attribute_names)
        self.assertEqual(None, key_wrapping_specification.encoding_option)

    def test_init_with_args(self):
        """
        Test that a KeyWrappingSpecification struct can be constructed with
        valid values.
        """
        encryption_key_information = objects.EncryptionKeyInformation(
            unique_identifier="12345678-9012-3456-7890-123456789012",
            cryptographic_parameters=attributes.CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.CTR
            )
        )
        mac_signature_key_information = objects.MACSignatureKeyInformation(
            unique_identifier="00000000-1111-2222-3333-444444444444",
            cryptographic_parameters=attributes.CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
            )
        )
        key_wrapping_specification = objects.KeyWrappingSpecification(
            wrapping_method=enums.WrappingMethod.ENCRYPT,
            encryption_key_information=encryption_key_information,
            mac_signature_key_information=mac_signature_key_information,
            attribute_names=[
                'Cryptographic Algorithm',
                'Cryptographic Length',
                'Cryptographic Usage Mask'
            ],
            encoding_option=enums.EncodingOption.TTLV_ENCODING
        )

        self.assertEqual(
            enums.WrappingMethod.ENCRYPT,
            key_wrapping_specification.wrapping_method
        )
        self.assertIsInstance(
            key_wrapping_specification.encryption_key_information,
            objects.EncryptionKeyInformation
        )
        e = key_wrapping_specification.encryption_key_information
        self.assertEqual(
            "12345678-9012-3456-7890-123456789012",
            e.unique_identifier
        )
        self.assertIsInstance(
            e.cryptographic_parameters,
            attributes.CryptographicParameters
        )
        self.assertEqual(
            enums.BlockCipherMode.CTR,
            e.cryptographic_parameters.block_cipher_mode
        )
        self.assertIsInstance(
            key_wrapping_specification.mac_signature_key_information,
            objects.MACSignatureKeyInformation
        )
        m = key_wrapping_specification.mac_signature_key_information
        self.assertEqual(
            "00000000-1111-2222-3333-444444444444",
            m.unique_identifier
        )
        self.assertIsInstance(
            m.cryptographic_parameters,
            attributes.CryptographicParameters
        )
        self.assertEqual(
            enums.BlockCipherMode.NIST_KEY_WRAP,
            m.cryptographic_parameters.block_cipher_mode
        )
        self.assertIsInstance(
            key_wrapping_specification.attribute_names,
            list
        )
        self.assertEqual(3, len(key_wrapping_specification.attribute_names))
        self.assertEqual(
            'Cryptographic Algorithm',
            key_wrapping_specification.attribute_names[0]
        )
        self.assertEqual(
            'Cryptographic Length',
            key_wrapping_specification.attribute_names[1]
        )
        self.assertEqual(
            'Cryptographic Usage Mask',
            key_wrapping_specification.attribute_names[2]
        )
        self.assertEqual(
            enums.EncodingOption.TTLV_ENCODING,
            key_wrapping_specification.encoding_option
        )

    def test_invalid_wrapping_method(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the wrapping method of a KeyWrappingSpecification struct.
        """
        kwargs = {'wrapping_method': 'invalid'}
        self.assertRaisesRegex(
            TypeError,
            "Wrapping method must be a WrappingMethod enumeration.",
            objects.KeyWrappingSpecification,
            **kwargs
        )

        args = (objects.KeyWrappingSpecification(), 'wrapping_method', 0)
        self.assertRaisesRegex(
            TypeError,
            "Wrapping method must be a WrappingMethod enumeration.",
            setattr,
            *args
        )

    def test_invalid_encryption_key_information(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the encryption key information of a KeyWrappingSpecification struct.
        """
        kwargs = {'encryption_key_information': 'invalid'}
        self.assertRaisesRegex(
            TypeError,
            "Encryption key information must be an EncryptionKeyInformation "
            "struct.",
            objects.KeyWrappingSpecification,
            **kwargs
        )

        args = (
            objects.KeyWrappingSpecification(),
            'encryption_key_information',
            'invalid'
        )
        self.assertRaisesRegex(
            TypeError,
            "Encryption key information must be an EncryptionKeyInformation "
            "struct.",
            setattr,
            *args
        )

    def test_invalid_mac_signature_key_information(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the MAC/signature key information of a KeyWrappingSpecification
        struct.
        """
        kwargs = {'mac_signature_key_information': 'invalid'}
        self.assertRaisesRegex(
            TypeError,
            "MAC/signature key information must be an "
            "MACSignatureKeyInformation struct.",
            objects.KeyWrappingSpecification,
            **kwargs
        )

        args = (
            objects.KeyWrappingSpecification(),
            'mac_signature_key_information',
            'invalid'
        )
        self.assertRaisesRegex(
            TypeError,
            "MAC/signature key information must be an "
            "MACSignatureKeyInformation struct.",
            setattr,
            *args
        )

    def test_invalid_attribute_names(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the attribute names of a KeyWrappingSpecification struct.
        """
        kwargs = {'attribute_names': 'invalid'}
        self.assertRaisesRegex(
            TypeError,
            "Attribute names must be a list of strings.",
            objects.KeyWrappingSpecification,
            **kwargs
        )

        args = (
            objects.KeyWrappingSpecification(),
            'attribute_names',
            ['valid', 0]
        )
        self.assertRaisesRegex(
            TypeError,
            "Attribute names must be a list of strings.",
            setattr,
            *args
        )

    def test_invalid_encoding_option(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the encoding option of a KeyWrappingSpecification struct.
        """
        kwargs = {'encoding_option': 'invalid'}
        self.assertRaisesRegex(
            TypeError,
            "Encoding option must be an EncodingOption enumeration.",
            objects.KeyWrappingSpecification,
            **kwargs
        )

        args = (
            objects.KeyWrappingSpecification(),
            'encoding_option',
            'invalid'
        )
        self.assertRaisesRegex(
            TypeError,
            "Encoding option must be an EncodingOption enumeration.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a KeyWrappingSpecification struct can be read from a data
        stream.
        """
        key_wrapping_specification = objects.KeyWrappingSpecification()

        self.assertEqual(None, key_wrapping_specification.wrapping_method)
        self.assertEqual(
            None,
            key_wrapping_specification.encryption_key_information
        )
        self.assertEqual(
            None,
            key_wrapping_specification.mac_signature_key_information
        )
        self.assertEqual(None, key_wrapping_specification.attribute_names)
        self.assertEqual(None, key_wrapping_specification.encoding_option)

        key_wrapping_specification.read(self.full_encoding)

        self.assertEqual(
            enums.WrappingMethod.ENCRYPT,
            key_wrapping_specification.wrapping_method
        )
        self.assertIsInstance(
            key_wrapping_specification.encryption_key_information,
            objects.EncryptionKeyInformation
        )
        e = key_wrapping_specification.encryption_key_information
        self.assertEqual(
            "100182d5-72b8-47aa-8383-4d97d512e98a",
            e.unique_identifier
        )
        self.assertIsInstance(
            e.cryptographic_parameters,
            attributes.CryptographicParameters
        )
        self.assertEqual(
            enums.BlockCipherMode.NIST_KEY_WRAP,
            e.cryptographic_parameters.block_cipher_mode
        )
        self.assertIsInstance(
            key_wrapping_specification.mac_signature_key_information,
            objects.MACSignatureKeyInformation
        )
        m = key_wrapping_specification.mac_signature_key_information
        self.assertEqual(
            "100182d5-72b8-47aa-8383-4d97d512e98a",
            m.unique_identifier
        )
        self.assertIsInstance(
            m.cryptographic_parameters,
            attributes.CryptographicParameters
        )
        self.assertEqual(
            enums.BlockCipherMode.NIST_KEY_WRAP,
            m.cryptographic_parameters.block_cipher_mode
        )
        self.assertIsInstance(
            key_wrapping_specification.attribute_names,
            list
        )
        self.assertEqual(
            'Cryptographic Usage Mask',
            key_wrapping_specification.attribute_names[0]
        )
        self.assertEqual(
            enums.EncodingOption.NO_ENCODING,
            key_wrapping_specification.encoding_option
        )

    def test_read_partial(self):
        """
        Test that a KeyWrappingSpecification struct can be read from a
        partial data stream.
        """
        key_wrapping_specification = objects.KeyWrappingSpecification()

        self.assertEqual(None, key_wrapping_specification.wrapping_method)
        self.assertEqual(
            None,
            key_wrapping_specification.encryption_key_information
        )
        self.assertEqual(
            None,
            key_wrapping_specification.mac_signature_key_information
        )
        self.assertEqual(None, key_wrapping_specification.attribute_names)
        self.assertEqual(None, key_wrapping_specification.encoding_option)

        key_wrapping_specification.read(self.partial_encoding)

        self.assertEqual(
            enums.WrappingMethod.ENCRYPT,
            key_wrapping_specification.wrapping_method
        )
        self.assertIsInstance(
            key_wrapping_specification.encryption_key_information,
            objects.EncryptionKeyInformation
        )
        e = key_wrapping_specification.encryption_key_information
        self.assertEqual(
            "100182d5-72b8-47aa-8383-4d97d512e98a",
            e.unique_identifier
        )
        self.assertIsInstance(
            e.cryptographic_parameters,
            attributes.CryptographicParameters
        )
        self.assertEqual(
            enums.BlockCipherMode.NIST_KEY_WRAP,
            e.cryptographic_parameters.block_cipher_mode
        )
        self.assertIsNone(
            key_wrapping_specification.mac_signature_key_information
        )
        self.assertIsNone(
            key_wrapping_specification.attribute_names
        )
        self.assertIsNone(
            key_wrapping_specification.encoding_option
        )

    def test_read_invalid(self):
        """
        Test that a ValueError gets raised when a required
        MACSignatureKeyInformation field is missing from the struct encoding.
        """
        key_wrapping_specification = objects.KeyWrappingSpecification()
        args = (self.empty_encoding,)
        self.assertRaisesRegex(
            ValueError,
            "Invalid struct missing the wrapping method attribute.",
            key_wrapping_specification.read,
            *args
        )

    def test_write(self):
        """
        Test that a KeyWrappingSpecification struct can be written to a data
        stream.
        """
        key_wrapping_specification = objects.KeyWrappingSpecification(
            wrapping_method=enums.WrappingMethod.ENCRYPT,
            encryption_key_information=objects.EncryptionKeyInformation(
                unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                )
            ),
            mac_signature_key_information=objects.MACSignatureKeyInformation(
                unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                )
            ),
            attribute_names=['Cryptographic Usage Mask'],
            encoding_option=enums.EncodingOption.NO_ENCODING
        )
        stream = BytearrayStream()
        key_wrapping_specification.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_partial(self):
        """
        Test that a partially defined KeyWrappingSpecification struct can be
        written to a data stream.
        """
        key_wrapping_specification = objects.KeyWrappingSpecification(
            wrapping_method=enums.WrappingMethod.ENCRYPT,
            encryption_key_information=objects.EncryptionKeyInformation(
                unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                )
            )
        )
        stream = BytearrayStream()
        key_wrapping_specification.write(stream)

        self.assertEqual(len(self.partial_encoding), len(stream))
        self.assertEqual(str(self.partial_encoding), str(stream))

    def test_write_invalid(self):
        """
        Test that a ValueError gets raised when a required
        KeyWrappingSpecification field is missing when encoding the struct.
        """
        key_wrapping_specification = objects.KeyWrappingSpecification()
        stream = utils.BytearrayStream()
        args = (stream,)
        self.assertRaisesRegex(
            ValueError,
            "Invalid struct missing the wrapping method attribute.",
            key_wrapping_specification.write,
            *args
        )

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        KeyWrappingSpecification structs with the same data.
        """
        a = objects.KeyWrappingSpecification()
        b = objects.KeyWrappingSpecification()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = objects.KeyWrappingSpecification(
            wrapping_method=enums.WrappingMethod.ENCRYPT,
            encryption_key_information=objects.EncryptionKeyInformation(
                unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                )
            ),
            attribute_names=['Cryptographic Usage Mask'],
            encoding_option=enums.EncodingOption.NO_ENCODING
        )
        b = objects.KeyWrappingSpecification(
            wrapping_method=enums.WrappingMethod.ENCRYPT,
            encryption_key_information=objects.EncryptionKeyInformation(
                unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                )
            ),
            attribute_names=['Cryptographic Usage Mask'],
            encoding_option=enums.EncodingOption.NO_ENCODING
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_wrapping_method(self):
        """
        Test that the equality operator returns False when comparing two
        KeyWrappingSpecification structs with different wrapping methods.
        """
        a = objects.KeyWrappingSpecification(
            wrapping_method=enums.WrappingMethod.ENCRYPT
        )
        b = objects.KeyWrappingSpecification(
            wrapping_method=enums.WrappingMethod.MAC_SIGN
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_encryption_key_information(self):
        """
        Test that the equality operator returns False when comparing two
        KeyWrappingSpecification structs with different encryption key
        information.
        """
        a = objects.KeyWrappingSpecification(
            encryption_key_information=objects.EncryptionKeyInformation(
                unique_identifier="100182d5-72b8-ffff-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.CBC
                )
            )
        )
        b = objects.KeyWrappingSpecification(
            encryption_key_information=objects.EncryptionKeyInformation(
                unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                )
            )
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_mac_signature_key_information(self):
        """
        Test that the equality operator returns False when comparing two
        KeyWrappingSpecification structs with different MAC/signature key
        information.
        """
        a = objects.KeyWrappingSpecification(
            mac_signature_key_information=objects.MACSignatureKeyInformation(
                unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                )
            )
        )
        b = objects.KeyWrappingSpecification(
            mac_signature_key_information=objects.MACSignatureKeyInformation(
                unique_identifier="100182d5-72b8-ffff-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.CBC
                )
            )
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_attribute_names(self):
        """
        Test that the equality operator returns False when comparing two
        KeyWrappingSpecification structs with different attribute names.
        """
        a = objects.KeyWrappingSpecification(
            attribute_names=[
                'Cryptographic Algorithm',
                'Cryptographic Length'
            ]
        )
        b = objects.KeyWrappingSpecification(
            attribute_names=['Cryptographic Usage Mask']
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_encoding_option(self):
        """
        Test that the equality operator returns False when comparing two
        KeyWrappingSpecification structs with different encoding options.
        """
        a = objects.KeyWrappingSpecification(
            encoding_option=enums.EncodingOption.NO_ENCODING
        )
        b = objects.KeyWrappingSpecification(
            encoding_option=enums.EncodingOption.TTLV_ENCODING
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        KeyWrappingSpecification structs with different types.
        """
        a = objects.KeyWrappingSpecification()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        KeyWrappingSpecification structs with the same data.
        """
        a = objects.KeyWrappingSpecification()
        b = objects.KeyWrappingSpecification()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = objects.KeyWrappingSpecification(
            wrapping_method=enums.WrappingMethod.ENCRYPT,
            encryption_key_information=objects.EncryptionKeyInformation(
                unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                )
            ),
            attribute_names=['Cryptographic Usage Mask'],
            encoding_option=enums.EncodingOption.NO_ENCODING
        )
        b = objects.KeyWrappingSpecification(
            wrapping_method=enums.WrappingMethod.ENCRYPT,
            encryption_key_information=objects.EncryptionKeyInformation(
                unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                )
            ),
            attribute_names=['Cryptographic Usage Mask'],
            encoding_option=enums.EncodingOption.NO_ENCODING
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_wrapping_method(self):
        """
        Test that the inequality operator returns True when comparing two
        KeyWrappingSpecification structs with different wrapping methods.
        """
        a = objects.KeyWrappingSpecification(
            wrapping_method=enums.WrappingMethod.ENCRYPT
        )
        b = objects.KeyWrappingSpecification(
            wrapping_method=enums.WrappingMethod.MAC_SIGN
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_encryption_key_information(self):
        """
        Test that the inequality operator returns True when comparing two
        KeyWrappingSpecification structs with different encryption key
        information.
        """
        a = objects.KeyWrappingSpecification(
            encryption_key_information=objects.EncryptionKeyInformation(
                unique_identifier="100182d5-72b8-ffff-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.CBC
                )
            )
        )
        b = objects.KeyWrappingSpecification(
            encryption_key_information=objects.EncryptionKeyInformation(
                unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                )
            )
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_mac_signature_key_information(self):
        """
        Test that the inequality operator returns True when comparing two
        KeyWrappingSpecification structs with different MAC/signature key
        information.
        """
        a = objects.KeyWrappingSpecification(
            mac_signature_key_information=objects.MACSignatureKeyInformation(
                unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                )
            )
        )
        b = objects.KeyWrappingSpecification(
            mac_signature_key_information=objects.MACSignatureKeyInformation(
                unique_identifier="100182d5-72b8-ffff-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.CBC
                )
            )
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_attribute_names(self):
        """
        Test that the inequality operator returns True when comparing two
        KeyWrappingSpecification structs with different attribute names.
        """
        a = objects.KeyWrappingSpecification(
            attribute_names=[
                'Cryptographic Algorithm',
                'Cryptographic Length'
            ]
        )
        b = objects.KeyWrappingSpecification(
            attribute_names=['Cryptographic Usage Mask']
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_encoding_option(self):
        """
        Test that the inequality operator returns True when comparing two
        KeyWrappingSpecification structs with different encoding options.
        """
        a = objects.KeyWrappingSpecification(
            encoding_option=enums.EncodingOption.NO_ENCODING
        )
        b = objects.KeyWrappingSpecification(
            encoding_option=enums.EncodingOption.TTLV_ENCODING
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        KeyWrappingSpecification structs with different types.
        """
        a = objects.KeyWrappingSpecification()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test that repr can be applied to an KeyWrappingSpecification struct.
        """
        key_wrapping_specification = objects.KeyWrappingSpecification(
            wrapping_method=enums.WrappingMethod.ENCRYPT,
            encryption_key_information=objects.EncryptionKeyInformation(
                unique_identifier="100182d5-72b8-ffff-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                )
            ),
            mac_signature_key_information=objects.MACSignatureKeyInformation(
                unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.CBC
                )
            ),
            attribute_names=[
                'Cryptographic Algorithm',
                'Cryptographic Length'
            ],
            encoding_option=enums.EncodingOption.TTLV_ENCODING
        )

        expected = (
            "KeyWrappingSpecification("
            "wrapping_method=WrappingMethod.ENCRYPT, "
            "encryption_key_information=EncryptionKeyInformation("
            "unique_identifier='100182d5-72b8-ffff-8383-4d97d512e98a', "
            "cryptographic_parameters=CryptographicParameters("
            "block_cipher_mode=BlockCipherMode.NIST_KEY_WRAP, "
            "padding_method=None, "
            "hashing_algorithm=None, "
            "key_role_type=None, "
            "digital_signature_algorithm=None, "
            "cryptographic_algorithm=None, "
            "random_iv=None, "
            "iv_length=None, "
            "tag_length=None, "
            "fixed_field_length=None, "
            "invocation_field_length=None, "
            "counter_length=None, "
            "initial_counter_value=None)), "
            "mac_signature_key_information=MACSignatureKeyInformation("
            "unique_identifier='100182d5-72b8-47aa-8383-4d97d512e98a', "
            "cryptographic_parameters=CryptographicParameters("
            "block_cipher_mode=BlockCipherMode.CBC, "
            "padding_method=None, "
            "hashing_algorithm=None, "
            "key_role_type=None, "
            "digital_signature_algorithm=None, "
            "cryptographic_algorithm=None, "
            "random_iv=None, "
            "iv_length=None, "
            "tag_length=None, "
            "fixed_field_length=None, "
            "invocation_field_length=None, "
            "counter_length=None, "
            "initial_counter_value=None)), "
            "attribute_names=["
            "'Cryptographic Algorithm', 'Cryptographic Length'], "
            "encoding_option=EncodingOption.TTLV_ENCODING)"
        )
        observed = repr(key_wrapping_specification)

        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a KeyWrappingSpecification struct.
        """
        key_wrapping_specification = objects.KeyWrappingSpecification(
            wrapping_method=enums.WrappingMethod.ENCRYPT,
            encryption_key_information=objects.EncryptionKeyInformation(
                unique_identifier="100182d5-72b8-ffff-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                )
            ),
            mac_signature_key_information=objects.MACSignatureKeyInformation(
                unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.CBC
                )
            ),
            attribute_names=[
                'Cryptographic Algorithm',
                'Cryptographic Length'
            ],
            encoding_option=enums.EncodingOption.TTLV_ENCODING
        )

        expected = str({
            'wrapping_method': enums.WrappingMethod.ENCRYPT,
            'encryption_key_information': objects.EncryptionKeyInformation(
                unique_identifier="100182d5-72b8-ffff-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
                )
            ),
            'mac_signature_key_information':
                objects.MACSignatureKeyInformation(
                unique_identifier="100182d5-72b8-47aa-8383-4d97d512e98a",
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.CBC
                )
            ),
            'attribute_names': [
                'Cryptographic Algorithm',
                'Cryptographic Length'
            ],
            'encoding_option': enums.EncodingOption.TTLV_ENCODING
        })
        observed = str(key_wrapping_specification)

        self.assertEqual(expected, observed)

class TestObjectDefaults(testtools.TestCase):

    def setUp(self):
        super(TestObjectDefaults, self).setUp()

        # This encoding matches the following set of values:
        #
        # ObjectDefaults
        #     Object Type - Symmetric Key
        #     Attributes
        #         Cryptographic Algorithm - AES
        #         Cryptographic Length - 128
        #         Cryptographic Usage Mask - Encrypt | Decrypt
        self.full_encoding = utils.BytearrayStream(
            b'\x42\x01\x53\x01\x00\x00\x00\x48'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x01\x25\x01\x00\x00\x00\x30'
            b'\x42\x00\x28\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x2A\x02\x00\x00\x00\x04\x00\x00\x00\x80\x00\x00\x00\x00'
            b'\x42\x00\x2C\x02\x00\x00\x00\x04\x00\x00\x00\x0C\x00\x00\x00\x00'
        )

        # This encoding matches the following set of values:
        #
        # ObjectDefaults
        #     Attributes
        #         Cryptographic Algorithm - AES
        #         Cryptographic Length - 128
        #         Cryptographic Usage Mask - Encrypt | Decrypt
        self.no_object_type_encoding = utils.BytearrayStream(
            b'\x42\x01\x53\x01\x00\x00\x00\x38'
            b'\x42\x01\x25\x01\x00\x00\x00\x30'
            b'\x42\x00\x28\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x2A\x02\x00\x00\x00\x04\x00\x00\x00\x80\x00\x00\x00\x00'
            b'\x42\x00\x2C\x02\x00\x00\x00\x04\x00\x00\x00\x0C\x00\x00\x00\x00'
        )

        # This encoding matches the following set of values:
        #
        # ObjectDefaults
        #     Object Type - Symmetric Key
        self.no_attributes_encoding = utils.BytearrayStream(
            b'\x42\x01\x53\x01\x00\x00\x00\x10'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestObjectDefaults, self).tearDown()

    def test_invalid_object_type(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the object type of an ObjectDefaults structure.
        """
        kwargs = {"object_type": 0}
        self.assertRaisesRegex(
            TypeError,
            "Object type must be an ObjectType enumeration.",
            objects.ObjectDefaults,
            **kwargs
        )

        args = (objects.ObjectDefaults(), "object_type", 0)
        self.assertRaisesRegex(
            TypeError,
            "Object type must be an ObjectType enumeration.",
            setattr,
            *args
        )

    def test_invalid_attributes(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the attributes of an ObjectDefaults structure.
        """
        kwargs = {"attributes": 0}
        self.assertRaisesRegex(
            TypeError,
            "Attributes must be an Attributes structure.",
            objects.ObjectDefaults,
            **kwargs
        )

        args = (objects.ObjectDefaults(), "attributes", 0)
        self.assertRaisesRegex(
            TypeError,
            "Attributes must be an Attributes structure.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that an ObjectDefaults structure can be correctly read in from a
        data stream.
        """
        object_defaults = objects.ObjectDefaults()

        self.assertIsNone(object_defaults.object_type)
        self.assertIsNone(object_defaults.attributes)

        object_defaults.read(
            self.full_encoding,
            kmip_version=enums.KMIPVersion.KMIP_2_0
        )

        self.assertEqual(
            enums.ObjectType.SYMMETRIC_KEY,
            object_defaults.object_type
        )
        self.assertEqual(
            objects.Attributes(
                attributes=[
                    primitives.Enumeration(
                        enums.CryptographicAlgorithm,
                        value=enums.CryptographicAlgorithm.AES,
                        tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                    ),
                    primitives.Integer(
                        value=128,
                        tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                    ),
                    primitives.Integer(
                        value=(
                            enums.CryptographicUsageMask.ENCRYPT.value |
                            enums.CryptographicUsageMask.DECRYPT.value
                        ),
                        tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                    )
                ]
            ),
            object_defaults.attributes
        )

    def test_read_unsupported_kmip_version(self):
        """
        Test that a VersionNotSupported error is raised during the decoding of
        an ObjectDefaults structure when the structure is read for an
        unsupported KMIP version.
        """
        object_defaults = objects.ObjectDefaults()

        args = (self.full_encoding, )
        kwargs = {"kmip_version": enums.KMIPVersion.KMIP_1_4}
        self.assertRaisesRegex(
            exceptions.VersionNotSupported,
            "KMIP 1.4 does not support the ObjectDefaults object.",
            object_defaults.read,
            *args,
            **kwargs
        )

    def test_read_missing_object_type(self):
        """
        Test that an InvalidKmipEncoding error is raised during the decoding
        of an ObjectDefaults structure when the object type is missing from
        the encoding.
        """
        object_defaults = objects.ObjectDefaults()

        self.assertIsNone(object_defaults.object_type)

        args = (self.no_object_type_encoding, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The ObjectDefaults encoding is missing the object type "
            "enumeration.",
            object_defaults.read,
            *args
        )

    def test_read_missing_attributes(self):
        """
        Test that an InvalidKmipEncoding error is raised during the decoding
        of an ObjectDefaults structure when the attributes structure is missing
        from the encoding.
        """
        object_defaults = objects.ObjectDefaults()

        self.assertIsNone(object_defaults.attributes)

        args = (self.no_attributes_encoding, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The ObjectDefaults encoding is missing the attributes structure.",
            object_defaults.read,
            *args
        )

    def test_write(self):
        """
        Test that an ObjectDefaults structure can be written to a data stream.
        """
        object_defaults = objects.ObjectDefaults(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            attributes=objects.Attributes(
                attributes=[
                    primitives.Enumeration(
                        enums.CryptographicAlgorithm,
                        value=enums.CryptographicAlgorithm.AES,
                        tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                    ),
                    primitives.Integer(
                        value=128,
                        tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                    ),
                    primitives.Integer(
                        value=(
                            enums.CryptographicUsageMask.ENCRYPT.value |
                            enums.CryptographicUsageMask.DECRYPT.value
                        ),
                        tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                    )
                ]
            )
        )

        buffer = utils.BytearrayStream()
        object_defaults.write(buffer, kmip_version=enums.KMIPVersion.KMIP_2_0)

        self.assertEqual(len(self.full_encoding), len(buffer))
        self.assertEqual(str(self.full_encoding), str(buffer))

    def test_write_unsupported_kmip_version(self):
        """
        Test that a VersionNotSupported error is raised during the encoding of
        an ObjectDefaults structure when the structure is written for an
        unsupported KMIP version.
        """
        object_defaults = objects.ObjectDefaults(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            attributes=objects.Attributes(
                attributes=[
                    primitives.Enumeration(
                        enums.CryptographicAlgorithm,
                        value=enums.CryptographicAlgorithm.AES,
                        tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                    ),
                    primitives.Integer(
                        value=128,
                        tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                    ),
                    primitives.Integer(
                        value=(
                            enums.CryptographicUsageMask.ENCRYPT.value |
                            enums.CryptographicUsageMask.DECRYPT.value
                        ),
                        tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                    )
                ]
            )
        )

        args = (utils.BytearrayStream(), )
        kwargs = {"kmip_version": enums.KMIPVersion.KMIP_1_4}
        self.assertRaisesRegex(
            exceptions.VersionNotSupported,
            "KMIP 1.4 does not support the ObjectDefaults object.",
            object_defaults.write,
            *args,
            **kwargs
        )

    def test_write_missing_object_type(self):
        """
        Test that an InvalidField error is raised during the encoding of an
        ObjectDefaults structure when the structure is missing the object
        type field.
        """
        object_defaults = objects.ObjectDefaults(
            attributes=objects.Attributes(
                attributes=[
                    primitives.Enumeration(
                        enums.CryptographicAlgorithm,
                        value=enums.CryptographicAlgorithm.AES,
                        tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                    ),
                    primitives.Integer(
                        value=128,
                        tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                    ),
                    primitives.Integer(
                        value=(
                            enums.CryptographicUsageMask.ENCRYPT.value |
                            enums.CryptographicUsageMask.DECRYPT.value
                        ),
                        tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                    )
                ]
            )
        )

        args = (utils.BytearrayStream(), )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The ObjectDefaults structure is missing the object type field.",
            object_defaults.write,
            *args
        )

    def test_write_missing_attributes(self):
        """
        Test that an InvalidField error is raised during the encoding of an
        ObjectDefaults structure when the structure is missing the attributes
        field.
        """
        object_defaults = objects.ObjectDefaults(
            object_type=enums.ObjectType.SYMMETRIC_KEY
        )

        args = (utils.BytearrayStream(), )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The ObjectDefaults structure is missing the attributes field.",
            object_defaults.write,
            *args
        )

    def test_repr(self):
        """
        Test that repr can be applied to an ObjectDefaults structure.
        """
        object_defaults = objects.ObjectDefaults(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            attributes=objects.Attributes(
                attributes=[
                    primitives.Enumeration(
                        enums.CryptographicAlgorithm,
                        value=enums.CryptographicAlgorithm.AES,
                        tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                    ),
                    primitives.Integer(
                        value=128,
                        tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                    ),
                    primitives.Integer(
                        value=(
                            enums.CryptographicUsageMask.ENCRYPT.value |
                            enums.CryptographicUsageMask.DECRYPT.value
                        ),
                        tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                    )
                ]
            )
        )
        o = "object_type=ObjectType.SYMMETRIC_KEY"
        a1e = "enum=CryptographicAlgorithm"
        a1v = "value=CryptographicAlgorithm.AES"
        a1t = "tag=Tags.CRYPTOGRAPHIC_ALGORITHM"
        a1a = ", ".join([a1e, a1v, a1t])
        a1 = "Enumeration({})".format(a1a)
        a2 = "Integer(value=128)"
        a3 = "Integer(value=12)"
        aa = ", ".join([a1, a2, a3])
        t = "tag=Tags.ATTRIBUTES"
        a = "attributes=Attributes(attributes=[{}], {})".format(aa, t)
        r = "ObjectDefaults({}, {})".format(o, a)

        self.assertEqual(r, repr(object_defaults))

    def test_str(self):
        """
        Test that str can be applied to an ObjectDefaults structure.
        """
        object_defaults = objects.ObjectDefaults(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            attributes=objects.Attributes(
                attributes=[
                    primitives.Enumeration(
                        enums.CryptographicAlgorithm,
                        value=enums.CryptographicAlgorithm.AES,
                        tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                    ),
                    primitives.Integer(
                        value=128,
                        tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                    ),
                    primitives.Integer(
                        value=(
                            enums.CryptographicUsageMask.ENCRYPT.value |
                            enums.CryptographicUsageMask.DECRYPT.value
                        ),
                        tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                    )
                ]
            )
        )
        o = '"object_type": ObjectType.SYMMETRIC_KEY'
        aa = '{"attributes": [CryptographicAlgorithm.AES, 128, 12]}'
        a = '"attributes": {}'.format(aa)
        r = "{" + "{}, {}".format(o, a) + "}"

        self.assertEqual(r, str(object_defaults))

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        ObjectDefaults structures with the same data.
        """
        a = objects.ObjectDefaults()
        b = objects.ObjectDefaults()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = objects.ObjectDefaults(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            attributes=objects.Attributes(
                attributes=[
                    primitives.Enumeration(
                        enums.CryptographicAlgorithm,
                        value=enums.CryptographicAlgorithm.AES,
                        tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                    ),
                    primitives.Integer(
                        value=128,
                        tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                    ),
                    primitives.Integer(
                        value=(
                            enums.CryptographicUsageMask.ENCRYPT.value |
                            enums.CryptographicUsageMask.DECRYPT.value
                        ),
                        tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                    )
                ]
            )
        )
        b = objects.ObjectDefaults(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            attributes=objects.Attributes(
                attributes=[
                    primitives.Enumeration(
                        enums.CryptographicAlgorithm,
                        value=enums.CryptographicAlgorithm.AES,
                        tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                    ),
                    primitives.Integer(
                        value=128,
                        tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                    ),
                    primitives.Integer(
                        value=(
                            enums.CryptographicUsageMask.ENCRYPT.value |
                            enums.CryptographicUsageMask.DECRYPT.value
                        ),
                        tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                    )
                ]
            )
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_object_type(self):
        """
        Test that the equality operator returns False when comparing two
        ObjectDefaults structures with different object type fields.
        """
        a = objects.ObjectDefaults(object_type=enums.ObjectType.SYMMETRIC_KEY)
        b = objects.ObjectDefaults(object_type=enums.ObjectType.PUBLIC_KEY)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_attributes(self):
        """
        Test that the equality operator returns False when comparing two
        ObjectDefaults structures with different attributes fields.
        """
        a = objects.ObjectDefaults(
            attributes=objects.Attributes(
                attributes=[
                    primitives.Enumeration(
                        enums.CryptographicAlgorithm,
                        value=enums.CryptographicAlgorithm.AES,
                        tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                    )
                ]
            )
        )
        b = objects.ObjectDefaults(
            attributes=objects.Attributes(
                attributes=[
                    primitives.Integer(
                        value=128,
                        tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                    )
                ]
            )
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        ObjectDefaults structures with different types.
        """
        a = objects.ObjectDefaults()
        b = "invalid"

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        ObjectDefaults structures with the same data.
        """
        a = objects.ObjectDefaults()
        b = objects.ObjectDefaults()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = objects.ObjectDefaults(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            attributes=objects.Attributes(
                attributes=[
                    primitives.Enumeration(
                        enums.CryptographicAlgorithm,
                        value=enums.CryptographicAlgorithm.AES,
                        tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                    ),
                    primitives.Integer(
                        value=128,
                        tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                    ),
                    primitives.Integer(
                        value=(
                            enums.CryptographicUsageMask.ENCRYPT.value |
                            enums.CryptographicUsageMask.DECRYPT.value
                        ),
                        tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                    )
                ]
            )
        )
        b = objects.ObjectDefaults(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            attributes=objects.Attributes(
                attributes=[
                    primitives.Enumeration(
                        enums.CryptographicAlgorithm,
                        value=enums.CryptographicAlgorithm.AES,
                        tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                    ),
                    primitives.Integer(
                        value=128,
                        tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                    ),
                    primitives.Integer(
                        value=(
                            enums.CryptographicUsageMask.ENCRYPT.value |
                            enums.CryptographicUsageMask.DECRYPT.value
                        ),
                        tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                    )
                ]
            )
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_object_type(self):
        """
        Test that the inequality operator returns True when comparing two
        ObjectDefaults structures with different object type fields.
        """
        a = objects.ObjectDefaults(object_type=enums.ObjectType.SYMMETRIC_KEY)
        b = objects.ObjectDefaults(object_type=enums.ObjectType.PUBLIC_KEY)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_attributes(self):
        """
        Test that the inequality operator returns True when comparing two
        ObjectDefaults structures with different attributes fields.
        """
        a = objects.ObjectDefaults(
            attributes=objects.Attributes(
                attributes=[
                    primitives.Enumeration(
                        enums.CryptographicAlgorithm,
                        value=enums.CryptographicAlgorithm.AES,
                        tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                    )
                ]
            )
        )
        b = objects.ObjectDefaults(
            attributes=objects.Attributes(
                attributes=[
                    primitives.Integer(
                        value=128,
                        tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                    )
                ]
            )
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        ObjectDefaults structures with different types.
        """
        a = objects.ObjectDefaults()
        b = "invalid"

        self.assertTrue(a != b)
        self.assertTrue(b != a)

class TestDefaultsInformation(testtools.TestCase):

    def setUp(self):
        super(TestDefaultsInformation, self).setUp()

        # This encoding matches the following set of values:
        #
        # DefaultsInformation
        #     ObjectDefaults
        #         Object Type - Symmetric Key
        #         Attributes
        #             Cryptographic Algorithm - AES
        #             Cryptographic Length - 128
        #             Cryptographic Usage Mask - Encrypt | Decrypt
        self.full_encoding = utils.BytearrayStream(
            b'\x42\x01\x52\x01\x00\x00\x00\x50'
            b'\x42\x01\x53\x01\x00\x00\x00\x48'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x01\x25\x01\x00\x00\x00\x30'
            b'\x42\x00\x28\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x2A\x02\x00\x00\x00\x04\x00\x00\x00\x80\x00\x00\x00\x00'
            b'\x42\x00\x2C\x02\x00\x00\x00\x04\x00\x00\x00\x0C\x00\x00\x00\x00'
        )

        # This encoding matches the following set of values:
        #
        # DefaultsInformation
        self.no_object_defaults_encoding = utils.BytearrayStream(
            b'\x42\x01\x52\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestDefaultsInformation, self).tearDown()

    def test_invalid_object_defaults(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the object defaults of an DefaultsInformation structure.
        """
        kwargs = {"object_defaults": [0]}
        self.assertRaisesRegex(
            TypeError,
            "Object defaults must be a list of ObjectDefaults structures.",
            objects.DefaultsInformation,
            **kwargs
        )

        args = (objects.DefaultsInformation(), "object_defaults", 0)
        self.assertRaisesRegex(
            TypeError,
            "Object defaults must be a list of ObjectDefaults structures.",
            setattr,
            *args
        )

    def test_invalid_object_defaults_list(self):
        """
        Test that a TypeError is raised when an invalid object defaults list
        is used with the DefaultsInformation structure.
        """
        kwargs = {"object_defaults": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "Object defaults must be a list of ObjectDefaults structures.",
            objects.DefaultsInformation,
            **kwargs
        )

        args = (
            objects.DefaultsInformation(),
            "object_defaults",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "Object defaults must be a list of ObjectDefaults structures.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a DefaultsInformation structure can be correctly read in
        from a data stream.
        """
        defaults_information = objects.DefaultsInformation()

        self.assertIsNone(defaults_information.object_defaults)

        defaults_information.read(
            self.full_encoding,
            kmip_version=enums.KMIPVersion.KMIP_2_0
        )

        expected = [
            objects.ObjectDefaults(
                object_type=enums.ObjectType.SYMMETRIC_KEY,
                attributes=objects.Attributes(
                    attributes=[
                        primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.AES,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        ),
                        primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        ),
                        primitives.Integer(
                            value=(
                                enums.CryptographicUsageMask.ENCRYPT.value |
                                enums.CryptographicUsageMask.DECRYPT.value
                            ),
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    ]
                )
            )
        ]
        self.assertEqual(
            expected,
            defaults_information.object_defaults
        )

    def test_read_unsupported_kmip_version(self):
        """
        Test that a VersionNotSupported error is raised during the decoding of
        a DefaultsInformation structure when the structure is read for an
        unsupported KMIP version.
        """
        defaults_information = objects.DefaultsInformation()

        args = (self.full_encoding, )
        kwargs = {"kmip_version": enums.KMIPVersion.KMIP_1_4}
        self.assertRaisesRegex(
            exceptions.VersionNotSupported,
            "KMIP 1.4 does not support the DefaultsInformation object.",
            defaults_information.read,
            *args,
            **kwargs
        )

    def test_read_missing_object_defaults(self):
        """
        Test that an InvalidKmipEncoding error is raised during the decoding
        of a DefaultsInformation structure when the object type is missing
        from the encoding.
        """
        defaults_information = objects.DefaultsInformation()

        self.assertIsNone(defaults_information.object_defaults)

        args = (self.no_object_defaults_encoding, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The DefaultsInformation encoding is missing the object defaults "
            "structure.",
            defaults_information.read,
            *args
        )

    def test_write(self):
        """
        Test that a DefaultsInformation structure can be written to a data
        stream.
        """
        object_defaults = [
            objects.ObjectDefaults(
                object_type=enums.ObjectType.SYMMETRIC_KEY,
                attributes=objects.Attributes(
                    attributes=[
                        primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.AES,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        ),
                        primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        ),
                        primitives.Integer(
                            value=(
                                enums.CryptographicUsageMask.ENCRYPT.value |
                                enums.CryptographicUsageMask.DECRYPT.value
                            ),
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    ]
                )
            )
        ]
        defaults_information = objects.DefaultsInformation(
            object_defaults=object_defaults
        )

        buffer = utils.BytearrayStream()
        defaults_information.write(
            buffer,
            kmip_version=enums.KMIPVersion.KMIP_2_0
        )

        self.assertEqual(len(self.full_encoding), len(buffer))
        self.assertEqual(str(self.full_encoding), str(buffer))

    def test_write_unsupported_kmip_version(self):
        """
        Test that a VersionNotSupported error is raised during the encoding of
        a DefaultsInformation structure when the structure is written for an
        unsupported KMIP version.
        """
        object_defaults = objects.ObjectDefaults(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            attributes=objects.Attributes(
                attributes=[
                    primitives.Enumeration(
                        enums.CryptographicAlgorithm,
                        value=enums.CryptographicAlgorithm.AES,
                        tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                    ),
                    primitives.Integer(
                        value=128,
                        tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                    ),
                    primitives.Integer(
                        value=(
                            enums.CryptographicUsageMask.ENCRYPT.value |
                            enums.CryptographicUsageMask.DECRYPT.value
                        ),
                        tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                    )
                ]
            )
        )
        defaults_information = objects.DefaultsInformation(
            object_defaults=[object_defaults]
        )

        args = (utils.BytearrayStream(), )
        kwargs = {"kmip_version": enums.KMIPVersion.KMIP_1_4}
        self.assertRaisesRegex(
            exceptions.VersionNotSupported,
            "KMIP 1.4 does not support the DefaultsInformation object.",
            defaults_information.write,
            *args,
            **kwargs
        )

    def test_write_missing_object_defaults(self):
        """
        Test that an InvalidField error is raised during the encoding of an
        DefaultsInformation structure when the structure is missing the object
        defaults field.
        """
        defaults_information = objects.DefaultsInformation()

        args = (utils.BytearrayStream(), )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The DefaultsInformation structure is missing the object defaults "
            "field.",
            defaults_information.write,
            *args
        )

    def test_repr(self):
        """
        Test that repr can be applied to a DefaultsInformation structure.
        """
        object_defaults = objects.ObjectDefaults(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            attributes=objects.Attributes(
                attributes=[
                    primitives.Enumeration(
                        enums.CryptographicAlgorithm,
                        value=enums.CryptographicAlgorithm.AES,
                        tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                    ),
                    primitives.Integer(
                        value=128,
                        tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                    ),
                    primitives.Integer(
                        value=(
                            enums.CryptographicUsageMask.ENCRYPT.value |
                            enums.CryptographicUsageMask.DECRYPT.value
                        ),
                        tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                    )
                ]
            )
        )
        defaults_information = objects.DefaultsInformation(
            object_defaults=[object_defaults]
        )
        o = "object_type=ObjectType.SYMMETRIC_KEY"
        a1e = "enum=CryptographicAlgorithm"
        a1v = "value=CryptographicAlgorithm.AES"
        a1t = "tag=Tags.CRYPTOGRAPHIC_ALGORITHM"
        a1a = ", ".join([a1e, a1v, a1t])
        a1 = "Enumeration({})".format(a1a)
        a2 = "Integer(value=128)"
        a3 = "Integer(value=12)"
        aa = ", ".join([a1, a2, a3])
        t = "tag=Tags.ATTRIBUTES"
        a = "attributes=Attributes(attributes=[{}], {})".format(aa, t)
        r = "ObjectDefaults({}, {})".format(o, a)
        d = "DefaultsInformation(object_defaults=[{}])".format(r)

        self.assertEqual(d, repr(defaults_information))

    def test_str(self):
        """
        Test that str can be applied to a DefaultsInformation structure.
        """
        object_defaults = objects.ObjectDefaults(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            attributes=objects.Attributes(
                attributes=[
                    primitives.Enumeration(
                        enums.CryptographicAlgorithm,
                        value=enums.CryptographicAlgorithm.AES,
                        tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                    ),
                    primitives.Integer(
                        value=128,
                        tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                    ),
                    primitives.Integer(
                        value=(
                            enums.CryptographicUsageMask.ENCRYPT.value |
                            enums.CryptographicUsageMask.DECRYPT.value
                        ),
                        tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                    )
                ]
            )
        )
        defaults_information = objects.DefaultsInformation(
            object_defaults=[object_defaults]
        )
        o = '"object_type": ObjectType.SYMMETRIC_KEY'
        aa = '{"attributes": [CryptographicAlgorithm.AES, 128, 12]}'
        a = '"attributes": {}'.format(aa)
        r = "{" + "{}, {}".format(o, a) + "}"
        d = "{" + '"object_defaults": [' + r + "]}"

        self.assertEqual(d, str(defaults_information))

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        DefaultsInformation structures with the same data.
        """
        a = objects.DefaultsInformation()
        b = objects.DefaultsInformation()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = objects.DefaultsInformation(
            object_defaults=[objects.ObjectDefaults(
                object_type=enums.ObjectType.SYMMETRIC_KEY,
                attributes=objects.Attributes(
                    attributes=[
                        primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.AES,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        ),
                        primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        ),
                        primitives.Integer(
                            value=(
                                enums.CryptographicUsageMask.ENCRYPT.value |
                                enums.CryptographicUsageMask.DECRYPT.value
                            ),
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    ]
                )
            )]
        )
        b = objects.DefaultsInformation(
            object_defaults=[objects.ObjectDefaults(
                object_type=enums.ObjectType.SYMMETRIC_KEY,
                attributes=objects.Attributes(
                    attributes=[
                        primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.AES,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        ),
                        primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        ),
                        primitives.Integer(
                            value=(
                                enums.CryptographicUsageMask.ENCRYPT.value |
                                enums.CryptographicUsageMask.DECRYPT.value
                            ),
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    ]
                )
            )]
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_object_defaults(self):
        """
        Test that the equality operator returns False when comparing two
        DefaultsInformation structures with different object defaults fields.
        """
        a = objects.DefaultsInformation(
            object_defaults=[objects.ObjectDefaults(
                object_type=enums.ObjectType.SYMMETRIC_KEY,
                attributes=objects.Attributes(
                    attributes=[
                        primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.AES,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ]
                )
            )]
        )
        b = objects.DefaultsInformation(
            object_defaults=[objects.ObjectDefaults(
                object_type=enums.ObjectType.SYMMETRIC_KEY,
                attributes=objects.Attributes(
                    attributes=[
                        primitives.Integer(
                            value=(
                                enums.CryptographicUsageMask.ENCRYPT.value |
                                enums.CryptographicUsageMask.DECRYPT.value
                            ),
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    ]
                )
            )]
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        DefaultsInformation structures with different types.
        """
        a = objects.DefaultsInformation()
        b = "invalid"

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        DefaultsInformation structures with the same data.
        """
        a = objects.DefaultsInformation()
        b = objects.DefaultsInformation()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = objects.DefaultsInformation(
            object_defaults=[objects.ObjectDefaults(
                object_type=enums.ObjectType.SYMMETRIC_KEY,
                attributes=objects.Attributes(
                    attributes=[
                        primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.AES,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        ),
                        primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        ),
                        primitives.Integer(
                            value=(
                                enums.CryptographicUsageMask.ENCRYPT.value |
                                enums.CryptographicUsageMask.DECRYPT.value
                            ),
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    ]
                )
            )]
        )
        b = objects.DefaultsInformation(
            object_defaults=[objects.ObjectDefaults(
                object_type=enums.ObjectType.SYMMETRIC_KEY,
                attributes=objects.Attributes(
                    attributes=[
                        primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.AES,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        ),
                        primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        ),
                        primitives.Integer(
                            value=(
                                enums.CryptographicUsageMask.ENCRYPT.value |
                                enums.CryptographicUsageMask.DECRYPT.value
                            ),
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    ]
                )
            )]
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_object_defaults(self):
        """
        Test that the inequality operator returns True when comparing two
        DefaultsInformation structures with different object defaults fields.
        """
        a = objects.DefaultsInformation(
            object_defaults=[objects.ObjectDefaults(
                object_type=enums.ObjectType.SYMMETRIC_KEY,
                attributes=objects.Attributes(
                    attributes=[
                        primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.AES,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ]
                )
            )]
        )
        b = objects.DefaultsInformation(
            object_defaults=[objects.ObjectDefaults(
                object_type=enums.ObjectType.SYMMETRIC_KEY,
                attributes=objects.Attributes(
                    attributes=[
                        primitives.Integer(
                            value=(
                                enums.CryptographicUsageMask.ENCRYPT.value |
                                enums.CryptographicUsageMask.DECRYPT.value
                            ),
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    ]
                )
            )]
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        DefaultsInformation structures with different types.
        """
        a = objects.DefaultsInformation()
        b = "invalid"

        self.assertTrue(a != b)
        self.assertTrue(b != a)

class TestRNGParameters(testtools.TestCase):

    def setUp(self):
        super(TestRNGParameters, self).setUp()

        # This encoding matches the following set of values:
        #
        # RNGParameters
        #     RNG Algorithm - FIPS 186-2
        #     Cryptographic Algorithm - AES
        #     Cryptographic Length - 256
        #     Hashing Algorithm - SHA256
        #     DRBG Algorithm - Hash
        #     Recommended Curve - P-192
        #     FIPS186 Variation - GP x-Original
        #     Prediction Resistance - True
        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\xD9\x01\x00\x00\x00\x80'
            b'\x42\x00\xDA\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x28\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x2A\x02\x00\x00\x00\x04\x00\x00\x01\x00\x00\x00\x00\x00'
            b'\x42\x00\x38\x05\x00\x00\x00\x04\x00\x00\x00\x06\x00\x00\x00\x00'
            b'\x42\x00\xDB\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x75\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\xDC\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\xDD\x06\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x01'
        )

        # This encoding matches the following set of values:
        #
        # RNGParameters
        #     Cryptographic Algorithm - AES
        #     Cryptographic Length - 256
        #     Hashing Algorithm - SHA256
        #     DRBG Algorithm - Hash
        #     Recommended Curve - P-192
        #     FIPS186 Variation - GP x-Original
        #     Prediction Resistance - True
        self.no_rng_algorithm_encoding = utils.BytearrayStream(
            b'\x42\x00\xD9\x01\x00\x00\x00\x70'
            b'\x42\x00\x28\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x2A\x02\x00\x00\x00\x04\x00\x00\x01\x00\x00\x00\x00\x00'
            b'\x42\x00\x38\x05\x00\x00\x00\x04\x00\x00\x00\x06\x00\x00\x00\x00'
            b'\x42\x00\xDB\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x75\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\xDC\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\xDD\x06\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x01'
        )

        # This encoding matches the following set of values:
        #
        # RNGParameters
        #     RNG Algorithm - FIPS 186-2
        self.only_rng_algorithm_encoding = utils.BytearrayStream(
            b'\x42\x00\xD9\x01\x00\x00\x00\x10'
            b'\x42\x00\xDA\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestRNGParameters, self).tearDown()

    def test_invalid_rng_algorithm(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the RNG algorithm of an RNGParameters structure.
        """
        kwargs = {"rng_algorithm": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The RNG algorithm must be an RNGAlgorithm enumeration.",
            objects.RNGParameters,
            **kwargs
        )

        args = (objects.RNGParameters(), "rng_algorithm", "invalid")
        self.assertRaisesRegex(
            TypeError,
            "The RNG algorithm must be an RNGAlgorithm enumeration.",
            setattr,
            *args
        )

    def test_invalid_cryptographic_algorithm(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the cryptographic algorithm of an RNGParameters structure.
        """
        kwargs = {"cryptographic_algorithm": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The cryptographic algorithm must be a CryptographicAlgorithm "
            "enumeration.",
            objects.RNGParameters,
            **kwargs
        )

        args = (objects.RNGParameters(), "cryptographic_algorithm", "invalid")
        self.assertRaisesRegex(
            TypeError,
            "The cryptographic algorithm must be a CryptographicAlgorithm "
            "enumeration.",
            setattr,
            *args
        )

    def test_invalid_cryptographic_length(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the cryptographic length of an RNGParameters structure.
        """
        kwargs = {"cryptographic_length": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The cryptographic length must be an integer.",
            objects.RNGParameters,
            **kwargs
        )

        args = (objects.RNGParameters(), "cryptographic_length", "invalid")
        self.assertRaisesRegex(
            TypeError,
            "The cryptographic length must be an integer.",
            setattr,
            *args
        )

    def test_invalid_hashing_algorithm(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the hashing algorithm of an RNGParameters structure.
        """
        kwargs = {"hashing_algorithm": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The hashing algorithm must be a HashingAlgorithm enumeration.",
            objects.RNGParameters,
            **kwargs
        )

        args = (objects.RNGParameters(), "hashing_algorithm", "invalid")
        self.assertRaisesRegex(
            TypeError,
            "The hashing algorithm must be a HashingAlgorithm enumeration.",
            setattr,
            *args
        )

    def test_invalid_drbg_algorithm(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the DRBG algorithm of an RNGParameters structure.
        """
        kwargs = {"drbg_algorithm": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The DRBG algorithm must be a DRBGAlgorithm enumeration.",
            objects.RNGParameters,
            **kwargs
        )

        args = (objects.RNGParameters(), "drbg_algorithm", "invalid")
        self.assertRaisesRegex(
            TypeError,
            "The DRBG algorithm must be a DRBGAlgorithm enumeration.",
            setattr,
            *args
        )

    def test_invalid_recommended_curve(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the recommended curve of an RNGParameters structure.
        """
        kwargs = {"recommended_curve": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The recommended curve must be a RecommendedCurve enumeration.",
            objects.RNGParameters,
            **kwargs
        )

        args = (objects.RNGParameters(), "recommended_curve", "invalid")
        self.assertRaisesRegex(
            TypeError,
            "The recommended curve must be a RecommendedCurve enumeration.",
            setattr,
            *args
        )

    def test_invalid_fips186_variation(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the FIPS186 variation of an RNGParameters structure.
        """
        kwargs = {"fips186_variation": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The FIPS186 variation must be a FIPS186Variation enumeration.",
            objects.RNGParameters,
            **kwargs
        )

        args = (objects.RNGParameters(), "fips186_variation", "invalid")
        self.assertRaisesRegex(
            TypeError,
            "The FIPS186 variation must be a FIPS186Variation enumeration.",
            setattr,
            *args
        )

    def test_invalid_prediction_resistance(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the prediction resistance of an RNGParameters structure.
        """
        kwargs = {"prediction_resistance": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The prediction resistance must be a boolean.",
            objects.RNGParameters,
            **kwargs
        )

        args = (objects.RNGParameters(), "prediction_resistance", "invalid")
        self.assertRaisesRegex(
            TypeError,
            "The prediction resistance must be a boolean.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a RNGParameters structure can be correctly read in from a
        data stream.
        """
        rng_parameters = objects.RNGParameters()

        self.assertIsNone(rng_parameters.rng_algorithm)
        self.assertIsNone(rng_parameters.cryptographic_algorithm)
        self.assertIsNone(rng_parameters.cryptographic_length)
        self.assertIsNone(rng_parameters.hashing_algorithm)
        self.assertIsNone(rng_parameters.drbg_algorithm)
        self.assertIsNone(rng_parameters.recommended_curve)
        self.assertIsNone(rng_parameters.fips186_variation)
        self.assertIsNone(rng_parameters.prediction_resistance)

        rng_parameters.read(
            self.full_encoding,
            kmip_version=enums.KMIPVersion.KMIP_1_3
        )

        self.assertEqual(
            enums.RNGAlgorithm.FIPS186_2,
            rng_parameters.rng_algorithm
        )
        self.assertEqual(
            enums.CryptographicAlgorithm.AES,
            rng_parameters.cryptographic_algorithm
        )
        self.assertEqual(256, rng_parameters.cryptographic_length)
        self.assertEqual(
            enums.HashingAlgorithm.SHA_256,
            rng_parameters.hashing_algorithm
        )
        self.assertEqual(
            enums.DRBGAlgorithm.HASH,
            rng_parameters.drbg_algorithm
        )
        self.assertEqual(
            enums.RecommendedCurve.P_192,
            rng_parameters.recommended_curve
        )
        self.assertEqual(
            enums.FIPS186Variation.GP_X_ORIGINAL,
            rng_parameters.fips186_variation
        )
        self.assertTrue(rng_parameters.prediction_resistance)

    def test_read_unsupported_kmip_version(self):
        """
        Test that a VersionNotSupported error is raised during the decoding of
        an RNGParameters structure when the structure is read for an
        unsupported KMIP version.
        """
        rng_parameters = objects.RNGParameters()

        args = (self.full_encoding, )
        kwargs = {"kmip_version": enums.KMIPVersion.KMIP_1_2}
        self.assertRaisesRegex(
            exceptions.VersionNotSupported,
            "KMIP 1.2 does not support the RNGParameters object.",
            rng_parameters.read,
            *args,
            **kwargs
        )

    def test_read_missing_rng_algorithm(self):
        """
        Test that an InvalidKmipEncoding error is raised during the decoding
        of an RNGParameters structure when the RNG algorithm is missing
        from the encoding.
        """
        rng_parameters = objects.RNGParameters()

        args = (self.no_rng_algorithm_encoding, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The RNGParameters encoding is missing the RNG algorithm.",
            rng_parameters.read,
            *args
        )

    def test_read_only_rng_algorithm(self):
        """
        Test that a RNGParameters structure can be correctly read in from a
        data stream even when missing all fields except the RNG algorithm.
        """
        rng_parameters = objects.RNGParameters()

        self.assertIsNone(rng_parameters.rng_algorithm)
        self.assertIsNone(rng_parameters.cryptographic_algorithm)
        self.assertIsNone(rng_parameters.cryptographic_length)
        self.assertIsNone(rng_parameters.hashing_algorithm)
        self.assertIsNone(rng_parameters.drbg_algorithm)
        self.assertIsNone(rng_parameters.recommended_curve)
        self.assertIsNone(rng_parameters.fips186_variation)
        self.assertIsNone(rng_parameters.prediction_resistance)

        rng_parameters.read(
            self.only_rng_algorithm_encoding,
            kmip_version=enums.KMIPVersion.KMIP_1_3
        )

        self.assertEqual(
            enums.RNGAlgorithm.FIPS186_2,
            rng_parameters.rng_algorithm
        )
        self.assertIsNone(rng_parameters.cryptographic_algorithm)
        self.assertIsNone(rng_parameters.cryptographic_length)
        self.assertIsNone(rng_parameters.hashing_algorithm)
        self.assertIsNone(rng_parameters.drbg_algorithm)
        self.assertIsNone(rng_parameters.recommended_curve)
        self.assertIsNone(rng_parameters.fips186_variation)
        self.assertIsNone(rng_parameters.prediction_resistance)

    def test_write(self):
        """
        Test that an RNGParameters structure can be written to a data
        stream.
        """
        rng_parameters = objects.RNGParameters(
            rng_algorithm=enums.RNGAlgorithm.FIPS186_2,
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
            cryptographic_length=256,
            hashing_algorithm=enums.HashingAlgorithm.SHA_256,
            drbg_algorithm=enums.DRBGAlgorithm.HASH,
            recommended_curve=enums.RecommendedCurve.P_192,
            fips186_variation=enums.FIPS186Variation.GP_X_ORIGINAL,
            prediction_resistance=True
        )

        buffer = utils.BytearrayStream()
        rng_parameters.write(
            buffer,
            kmip_version=enums.KMIPVersion.KMIP_1_3
        )

        self.assertEqual(len(self.full_encoding), len(buffer))
        self.assertEqual(str(self.full_encoding), str(buffer))

    def test_write_unsupported_kmip_version(self):
        """
        Test that a VersionNotSupported error is raised during the encoding of
        an RNGParameters structure when the structure is written for an
        unsupported KMIP version.
        """
        rng_parameters = objects.RNGParameters(
            rng_algorithm=enums.RNGAlgorithm.FIPS186_2,
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
            cryptographic_length=256,
            hashing_algorithm=enums.HashingAlgorithm.SHA_256,
            drbg_algorithm=enums.DRBGAlgorithm.HASH,
            recommended_curve=enums.RecommendedCurve.P_192,
            fips186_variation=enums.FIPS186Variation.GP_X_ORIGINAL,
            prediction_resistance=True
        )

        args = (utils.BytearrayStream(), )
        kwargs = {"kmip_version": enums.KMIPVersion.KMIP_1_2}
        self.assertRaisesRegex(
            exceptions.VersionNotSupported,
            "KMIP 1.2 does not support the RNGParameters object.",
            rng_parameters.write,
            *args,
            **kwargs
        )

    def test_write_missing_rng_algorithm(self):
        """
        Test that an InvalidField error is raised during the encoding of an
        RNGParameters structure when the structure is missing the RNG
        algorithm field.
        """
        rng_parameters = objects.RNGParameters()

        args = (utils.BytearrayStream(), )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The RNGParameters structure is missing the RNG algorithm field.",
            rng_parameters.write,
            *args
        )

    def test_write_only_rng_algorithm(self):
        """
        Test that an RNGParameters structure can be written to a data
        stream even when missing all fields except the RNG algorithm.
        """
        rng_parameters = objects.RNGParameters(
            rng_algorithm=enums.RNGAlgorithm.FIPS186_2
        )

        buffer = utils.BytearrayStream()
        rng_parameters.write(
            buffer,
            kmip_version=enums.KMIPVersion.KMIP_1_3
        )

        self.assertEqual(len(self.only_rng_algorithm_encoding), len(buffer))
        self.assertEqual(str(self.only_rng_algorithm_encoding), str(buffer))

    def test_repr(self):
        """
        Test that repr can be applied to an RNGParameters structure.
        """
        rng_parameters = objects.RNGParameters(
            rng_algorithm=enums.RNGAlgorithm.FIPS186_2,
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
            cryptographic_length=256,
            hashing_algorithm=enums.HashingAlgorithm.SHA_256,
            drbg_algorithm=enums.DRBGAlgorithm.HASH,
            recommended_curve=enums.RecommendedCurve.P_192,
            fips186_variation=enums.FIPS186Variation.GP_X_ORIGINAL,
            prediction_resistance=True
        )

        a = "rng_algorithm=RNGAlgorithm.FIPS186_2"
        c = "cryptographic_algorithm=CryptographicAlgorithm.AES"
        e = "cryptographic_length=256"
        h = "hashing_algorithm=HashingAlgorithm.SHA_256"
        d = "drbg_algorithm=DRBGAlgorithm.HASH"
        r = "recommended_curve=RecommendedCurve.P_192"
        f = "fips186_variation=FIPS186Variation.GP_X_ORIGINAL"
        p = "prediction_resistance=True"

        v = ", ".join([a, c, e, h, d, r, f, p])

        self.assertEqual(
            "RNGParameters({})".format(v),
            repr(rng_parameters)
        )

    def test_str(self):
        """
        Test that str can be applied to an RNGParameters structure.
        """
        rng_parameters = objects.RNGParameters(
            rng_algorithm=enums.RNGAlgorithm.FIPS186_2,
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
            cryptographic_length=256,
            hashing_algorithm=enums.HashingAlgorithm.SHA_256,
            drbg_algorithm=enums.DRBGAlgorithm.HASH,
            recommended_curve=enums.RecommendedCurve.P_192,
            fips186_variation=enums.FIPS186Variation.GP_X_ORIGINAL,
            prediction_resistance=True
        )

        a = '"rng_algorithm": RNGAlgorithm.FIPS186_2'
        c = '"cryptographic_algorithm": CryptographicAlgorithm.AES'
        e = '"cryptographic_length": 256'
        h = '"hashing_algorithm": HashingAlgorithm.SHA_256'
        d = '"drbg_algorithm": DRBGAlgorithm.HASH'
        r = '"recommended_curve": RecommendedCurve.P_192'
        f = '"fips186_variation": FIPS186Variation.GP_X_ORIGINAL'
        p = '"prediction_resistance": True'

        v = ", ".join([a, c, e, h, d, r, f, p])

        self.assertEqual(
            "{" + v + "}",
            str(rng_parameters)
        )

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        RNGParameters structures with the same data.
        """
        a = objects.RNGParameters()
        b = objects.RNGParameters()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = objects.RNGParameters(
            rng_algorithm=enums.RNGAlgorithm.FIPS186_2,
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
            cryptographic_length=256,
            hashing_algorithm=enums.HashingAlgorithm.SHA_256,
            drbg_algorithm=enums.DRBGAlgorithm.HASH,
            recommended_curve=enums.RecommendedCurve.P_192,
            fips186_variation=enums.FIPS186Variation.GP_X_ORIGINAL,
            prediction_resistance=True
        )
        b = objects.RNGParameters(
            rng_algorithm=enums.RNGAlgorithm.FIPS186_2,
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
            cryptographic_length=256,
            hashing_algorithm=enums.HashingAlgorithm.SHA_256,
            drbg_algorithm=enums.DRBGAlgorithm.HASH,
            recommended_curve=enums.RecommendedCurve.P_192,
            fips186_variation=enums.FIPS186Variation.GP_X_ORIGINAL,
            prediction_resistance=True
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_rng_algorithm(self):
        """
        Test that the equality operator returns False when comparing two
        RNGParameters structures with different RNG algorithm fields.
        """
        a = objects.RNGParameters(rng_algorithm=enums.RNGAlgorithm.FIPS186_2)
        b = objects.RNGParameters(rng_algorithm=enums.RNGAlgorithm.UNSPECIFIED)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_cryptographic_algorithm(self):
        """
        Test that the equality operator returns False when comparing two
        RNGParameters structures with different cryptographic algorithm fields.
        """
        a = objects.RNGParameters(
            cryptographic_algorithm=enums.CryptographicAlgorithm.DES
        )
        b = objects.RNGParameters(
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_cryptographic_length(self):
        """
        Test that the equality operator returns False when comparing two
        RNGParameters structures with different cryptographic length fields.
        """
        a = objects.RNGParameters(cryptographic_length=128)
        b = objects.RNGParameters(cryptographic_length=256)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_hashing_algorithm(self):
        """
        Test that the equality operator returns False when comparing two
        RNGParameters structures with different hashing algorithm fields.
        """
        a = objects.RNGParameters(hashing_algorithm=enums.HashingAlgorithm.MD2)
        b = objects.RNGParameters(hashing_algorithm=enums.HashingAlgorithm.MD4)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_drbg_algorithm(self):
        """
        Test that the equality operator returns False when comparing two
        RNGParameters structures with different DRBG algorithm fields.
        """
        a = objects.RNGParameters(drbg_algorithm=enums.DRBGAlgorithm.HASH)
        b = objects.RNGParameters(
            drbg_algorithm=enums.DRBGAlgorithm.UNSPECIFIED
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_recommended_curve(self):
        """
        Test that the equality operator returns False when comparing two
        RNGParameters structures with different recommended curve fields.
        """
        a = objects.RNGParameters(
            recommended_curve=enums.RecommendedCurve.P_192
        )
        b = objects.RNGParameters(
            recommended_curve=enums.RecommendedCurve.K_163
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_fips186_variation(self):
        """
        Test that the equality operator returns False when comparing two
        RNGParameters structures with different FIPS186 variation fields.
        """
        a = objects.RNGParameters(
            fips186_variation=enums.FIPS186Variation.GP_X_ORIGINAL
        )
        b = objects.RNGParameters(
            fips186_variation=enums.FIPS186Variation.X_ORIGINAL
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_prediction_resistance(self):
        """
        Test that the equality operator returns False when comparing two
        RNGParameters structures with different prediction resistance fields.
        """
        a = objects.RNGParameters(prediction_resistance=True)
        b = objects.RNGParameters(prediction_resistance=False)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        RNGParameters structures with different types.
        """
        a = objects.RNGParameters()
        b = "invalid"

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        RNGParameters structures with the same data.
        """
        a = objects.RNGParameters()
        b = objects.RNGParameters()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = objects.RNGParameters(
            rng_algorithm=enums.RNGAlgorithm.FIPS186_2,
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
            cryptographic_length=256,
            hashing_algorithm=enums.HashingAlgorithm.SHA_256,
            drbg_algorithm=enums.DRBGAlgorithm.HASH,
            recommended_curve=enums.RecommendedCurve.P_192,
            fips186_variation=enums.FIPS186Variation.GP_X_ORIGINAL,
            prediction_resistance=True
        )
        b = objects.RNGParameters(
            rng_algorithm=enums.RNGAlgorithm.FIPS186_2,
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
            cryptographic_length=256,
            hashing_algorithm=enums.HashingAlgorithm.SHA_256,
            drbg_algorithm=enums.DRBGAlgorithm.HASH,
            recommended_curve=enums.RecommendedCurve.P_192,
            fips186_variation=enums.FIPS186Variation.GP_X_ORIGINAL,
            prediction_resistance=True
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_rng_algorithm(self):
        """
        Test that the inequality operator returns True when comparing two
        RNGParameters structures with different RNG algorithm fields.
        """
        a = objects.RNGParameters(rng_algorithm=enums.RNGAlgorithm.FIPS186_2)
        b = objects.RNGParameters(rng_algorithm=enums.RNGAlgorithm.UNSPECIFIED)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_cryptographic_algorithm(self):
        """
        Test that the inequality operator returns True when comparing two
        RNGParameters structures with different cryptographic algorithm fields.
        """
        a = objects.RNGParameters(
            cryptographic_algorithm=enums.CryptographicAlgorithm.DES
        )
        b = objects.RNGParameters(
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_cryptographic_length(self):
        """
        Test that the inequality operator returns True when comparing two
        RNGParameters structures with different cryptographic length fields.
        """
        a = objects.RNGParameters(cryptographic_length=128)
        b = objects.RNGParameters(cryptographic_length=256)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_hashing_algorithm(self):
        """
        Test that the inequality operator returns True when comparing two
        RNGParameters structures with different hashing algorithm fields.
        """
        a = objects.RNGParameters(hashing_algorithm=enums.HashingAlgorithm.MD2)
        b = objects.RNGParameters(hashing_algorithm=enums.HashingAlgorithm.MD4)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_drbg_algorithm(self):
        """
        Test that the inequality operator returns True when comparing two
        RNGParameters structures with different DRBG algorithm fields.
        """
        a = objects.RNGParameters(drbg_algorithm=enums.DRBGAlgorithm.HASH)
        b = objects.RNGParameters(
            drbg_algorithm=enums.DRBGAlgorithm.UNSPECIFIED
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_recommended_curve(self):
        """
        Test that the inequality operator returns True when comparing two
        RNGParameters structures with different recommended curve fields.
        """
        a = objects.RNGParameters(
            recommended_curve=enums.RecommendedCurve.P_192
        )
        b = objects.RNGParameters(
            recommended_curve=enums.RecommendedCurve.K_163
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_fips186_variation(self):
        """
        Test that the inequality operator returns True when comparing two
        RNGParameters structures with different FIPS186 variation fields.
        """
        a = objects.RNGParameters(
            fips186_variation=enums.FIPS186Variation.GP_X_ORIGINAL
        )
        b = objects.RNGParameters(
            fips186_variation=enums.FIPS186Variation.X_ORIGINAL
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_prediction_resistance(self):
        """
        Test that the inequality operator returns True when comparing two
        RNGParameters structures with different prediction resistance fields.
        """
        a = objects.RNGParameters(prediction_resistance=True)
        b = objects.RNGParameters(prediction_resistance=False)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        RNGParameters structures with different types.
        """
        a = objects.RNGParameters()
        b = "invalid"

        self.assertTrue(a != b)
        self.assertTrue(b != a)

class TestProfileInformation(testtools.TestCase):

    def setUp(self):
        super(TestProfileInformation, self).setUp()

        # This encoding matches the following set of values:
        #
        # Profile Information
        #     Profile Name - BASELINE_SERVER_BASIC_KMIPv12
        #     Server URI - https://example.com
        #     Server Port - 5696
        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\xEB\x01\x00\x00\x00\x40'
            b'\x42\x00\xEC\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\xED\x07\x00\x00\x00\x13'
            b'\x68\x74\x74\x70\x73\x3A\x2F\x2F\x65\x78\x61\x6D\x70\x6C\x65\x2E'
            b'\x63\x6F\x6D\x00\x00\x00\x00\x00'
            b'\x42\x00\xEE\x02\x00\x00\x00\x04\x00\x00\x16\x40\x00\x00\x00\x00'
        )

        # This encoding matches the following set of values:
        #
        # Profile Information
        #     Server URI - https://example.com
        #     Server Port - 5696
        self.no_profile_name_encoding = utils.BytearrayStream(
            b'\x42\x00\xEB\x01\x00\x00\x00\x30'
            b'\x42\x00\xED\x07\x00\x00\x00\x13'
            b'\x68\x74\x74\x70\x73\x3A\x2F\x2F\x65\x78\x61\x6D\x70\x6C\x65\x2E'
            b'\x63\x6F\x6D\x00\x00\x00\x00\x00'
            b'\x42\x00\xEE\x02\x00\x00\x00\x04\x00\x00\x16\x40\x00\x00\x00\x00'
        )

        # This encoding matches the following set of values:
        #
        # Profile Information
        #     Profile Name - BASELINE_SERVER_BASIC_KMIPv12
        self.only_profile_name_encoding = utils.BytearrayStream(
            b'\x42\x00\xEB\x01\x00\x00\x00\x10'
            b'\x42\x00\xEC\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestProfileInformation, self).tearDown()

    def test_invalid_profile_name(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the profile name of a ProfileInformation structure.
        """
        kwargs = {"profile_name": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The profile name must be a ProfileName enumeration.",
            objects.ProfileInformation,
            **kwargs
        )

        args = (objects.ProfileInformation(), "profile_name", "invalid")
        self.assertRaisesRegex(
            TypeError,
            "The profile name must be a ProfileName enumeration.",
            setattr,
            *args
        )

    def test_invalid_server_uri(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the server URI of a ProfileInformation structure.
        """
        kwargs = {"server_uri": 0}
        self.assertRaisesRegex(
            TypeError,
            "The server URI must be a string.",
            objects.ProfileInformation,
            **kwargs
        )

        args = (objects.ProfileInformation(), "server_uri", 0)
        self.assertRaisesRegex(
            TypeError,
            "The server URI must be a string.",
            setattr,
            *args
        )

    def test_invalid_server_port(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the server port of a ProfileInformation structure.
        """
        kwargs = {"server_port": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The server port must be an integer.",
            objects.ProfileInformation,
            **kwargs
        )

        args = (objects.ProfileInformation(), "server_port", "invalid")
        self.assertRaisesRegex(
            TypeError,
            "The server port must be an integer.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a ProfileInformation structure can be correctly read in
        from a data stream.
        """
        profile_information = objects.ProfileInformation()

        self.assertIsNone(profile_information.profile_name)
        self.assertIsNone(profile_information.server_uri)
        self.assertIsNone(profile_information.server_port)

        profile_information.read(
            self.full_encoding,
            kmip_version=enums.KMIPVersion.KMIP_1_3
        )

        self.assertEqual(
            enums.ProfileName.BASELINE_SERVER_BASIC_KMIPv12,
            profile_information.profile_name
        )
        self.assertEqual("https://example.com", profile_information.server_uri)
        self.assertEqual(5696, profile_information.server_port)

    def test_read_unsupported_kmip_version(self):
        """
        Test that a VersionNotSupported error is raised during the decoding of
        a ProfileInformation structure when the structure is read for an
        unsupported KMIP version.
        """
        profile_information = objects.ProfileInformation()

        args = (self.full_encoding, )
        kwargs = {"kmip_version": enums.KMIPVersion.KMIP_1_2}
        self.assertRaisesRegex(
            exceptions.VersionNotSupported,
            "KMIP 1.2 does not support the ProfileInformation object.",
            profile_information.read,
            *args,
            **kwargs
        )

    def test_read_missing_profile_name(self):
        """
        Test that an InvalidKmipEncoding error is raised during the decoding
        of a ProfileInformation structure when the profile name is missing
        from the encoding.
        """
        profile_information = objects.ProfileInformation()

        args = (self.no_profile_name_encoding, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The ProfileInformation encoding is missing the profile name.",
            profile_information.read,
            *args
        )

    def test_read_only_profile_name(self):
        """
        Test that a ProfileInformation structure can be correctly read in
        from a data stream even when missing all fields except the profile
        name.
        """
        profile_information = objects.ProfileInformation()

        self.assertIsNone(profile_information.profile_name)
        self.assertIsNone(profile_information.server_uri)
        self.assertIsNone(profile_information.server_port)

        profile_information.read(
            self.only_profile_name_encoding,
            kmip_version=enums.KMIPVersion.KMIP_1_3
        )

        self.assertEqual(
            enums.ProfileName.BASELINE_SERVER_BASIC_KMIPv12,
            profile_information.profile_name
        )
        self.assertIsNone(profile_information.server_uri)
        self.assertIsNone(profile_information.server_port)

    def test_write(self):
        """
        Test that a ProfileInformation structure can be written to a data
        stream.
        """
        profile_information = objects.ProfileInformation(
            profile_name=enums.ProfileName.BASELINE_SERVER_BASIC_KMIPv12,
            server_uri="https://example.com",
            server_port=5696
        )

        buffer = utils.BytearrayStream()
        profile_information.write(
            buffer,
            kmip_version=enums.KMIPVersion.KMIP_1_3
        )

        self.assertEqual(len(self.full_encoding), len(buffer))
        self.assertEqual(str(self.full_encoding), str(buffer))

    def test_write_unsupported_kmip_version(self):
        """
        Test that a VersionNotSupported error is raised during the encoding of
        a ProfileInformation structure when the structure is written for an
        unsupported KMIP version.
        """
        profile_information = objects.ProfileInformation(
            profile_name=enums.ProfileName.BASELINE_SERVER_BASIC_KMIPv12,
            server_uri="https://example.com",
            server_port=5696
        )

        args = (utils.BytearrayStream(), )
        kwargs = {"kmip_version": enums.KMIPVersion.KMIP_1_2}
        self.assertRaisesRegex(
            exceptions.VersionNotSupported,
            "KMIP 1.2 does not support the ProfileInformation object.",
            profile_information.write,
            *args,
            **kwargs
        )

    def test_write_missing_profile_name(self):
        """
        Test that an InvalidField error is raised during the encoding of an
        ProfileInformation structure when the structure is missing the profile
        name field.
        """
        profile_information = objects.ProfileInformation()

        args = (utils.BytearrayStream(), )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The ProfileInformation structure is missing the profile name "
            "field.",
            profile_information.write,
            *args
        )

    def test_write_only_profile_name(self):
        """
        Test that a ProfileInformation structure can be written to a data
        stream even when missing all fields except the profile name.
        """
        profile_information = objects.ProfileInformation(
            profile_name=enums.ProfileName.BASELINE_SERVER_BASIC_KMIPv12
        )

        buffer = utils.BytearrayStream()
        profile_information.write(
            buffer,
            kmip_version=enums.KMIPVersion.KMIP_1_3
        )

        self.assertEqual(len(self.only_profile_name_encoding), len(buffer))
        self.assertEqual(str(self.only_profile_name_encoding), str(buffer))

    def test_repr(self):
        """
        Test that repr can be applied to a ProfileInformation structure.
        """
        profile_information = objects.ProfileInformation(
            profile_name=enums.ProfileName.BASELINE_SERVER_BASIC_KMIPv12,
            server_uri="https://example.com",
            server_port=5696
        )

        n = "profile_name=ProfileName.BASELINE_SERVER_BASIC_KMIPv12"
        u = 'server_uri="https://example.com"'
        p = "server_port=5696"

        v = ", ".join([n, u, p])

        self.assertEqual(
            "ProfileInformation({})".format(v),
            repr(profile_information)
        )

    def test_str(self):
        """
        Test that str can be applied to a ProfileInformation structure.
        """
        profile_information = objects.ProfileInformation(
            profile_name=enums.ProfileName.BASELINE_SERVER_BASIC_KMIPv12,
            server_uri="https://example.com",
            server_port=5696
        )

        n = '"profile_name": ProfileName.BASELINE_SERVER_BASIC_KMIPv12'
        u = '"server_uri": "https://example.com"'
        p = '"server_port": 5696'

        v = ", ".join([n, u, p])

        self.assertEqual(
            "{" + v + "}",
            str(profile_information)
        )

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        ProfileInformation structures with the same data.
        """
        a = objects.ProfileInformation()
        b = objects.ProfileInformation()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = objects.ProfileInformation(
            profile_name=enums.ProfileName.BASELINE_SERVER_BASIC_KMIPv12,
            server_uri="https://example.com",
            server_port=5696
        )
        b = objects.ProfileInformation(
            profile_name=enums.ProfileName.BASELINE_SERVER_BASIC_KMIPv12,
            server_uri="https://example.com",
            server_port=5696
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_profile_name(self):
        """
        Test that the equality operator returns False when comparing two
        ProfileInformation structures with different profile name fields.
        """
        a = objects.ProfileInformation(
            profile_name=enums.ProfileName.BASELINE_SERVER_BASIC_KMIPv12
        )
        b = objects.ProfileInformation(
            profile_name=enums.ProfileName.TAPE_LIBRARY_CLIENT_KMIPv10
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_server_uri(self):
        """
        Test that the equality operator returns False when comparing two
        ProfileInformation structures with different server URI fields.
        """
        a = objects.ProfileInformation(server_uri="https://example.com")
        b = objects.ProfileInformation(server_uri="https://test.com")

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_server_port(self):
        """
        Test that the equality operator returns False when comparing two
        ProfileInformation structures with different server port fields.
        """
        a = objects.ProfileInformation(server_port=5696)
        b = objects.ProfileInformation(server_port=5697)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        ProfileInformation structures with different types.
        """
        a = objects.ProfileInformation()
        b = "invalid"

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        ProfileInformation structures with the same data.
        """
        a = objects.ProfileInformation()
        b = objects.ProfileInformation()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = objects.ProfileInformation(
            profile_name=enums.ProfileName.BASELINE_SERVER_BASIC_KMIPv12,
            server_uri="https://example.com",
            server_port=5696
        )
        b = objects.ProfileInformation(
            profile_name=enums.ProfileName.BASELINE_SERVER_BASIC_KMIPv12,
            server_uri="https://example.com",
            server_port=5696
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_profile_name(self):
        """
        Test that the inequality operator returns True when comparing two
        ProfileInformation structures with different profile name fields.
        """
        a = objects.ProfileInformation(
            profile_name=enums.ProfileName.BASELINE_SERVER_BASIC_KMIPv12
        )
        b = objects.ProfileInformation(
            profile_name=enums.ProfileName.TAPE_LIBRARY_CLIENT_KMIPv10
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_server_uri(self):
        """
        Test that the inequality operator returns True when comparing two
        ProfileInformation structures with different server URI fields.
        """
        a = objects.ProfileInformation(server_uri="https://example.com")
        b = objects.ProfileInformation(server_uri="https://test.com")

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_server_port(self):
        """
        Test that the inequality operator returns True when comparing two
        ProfileInformation structures with different server port fields.
        """
        a = objects.ProfileInformation(server_port=5696)
        b = objects.ProfileInformation(server_port=5697)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        ProfileInformation structures with different types.
        """
        a = objects.ProfileInformation()
        b = "invalid"

        self.assertTrue(a != b)
        self.assertTrue(b != a)

class TestValidationInformation(testtools.TestCase):

    def setUp(self):
        super(TestValidationInformation, self).setUp()

        # This encoding matches the following set of values:
        #
        # Validation Information
        #     Validation Authority Type - COMMON_CRITERIA
        #     Validation Authority Country - US
        #     Validation Authority URI - https://example.com
        #     Validation Version Major - 1
        #     Validation Version Minor - 0
        #     Validation Type - HYBRID
        #     Validation Level - 5
        #     Validation Certificate Identifier -
        #         c005d39e-604f-11e9-99df-080027fc1396
        #     Validation Certificate URI - https://test.com
        #     Validation Vendor URI - https://vendor.com
        #     Validation Profiles -
        #         Profile 1
        #         Profile 2
        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\xDF\x01\x00\x00\x01\x18'
            b'\x42\x00\xE0\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\xE1\x07\x00\x00\x00\x02\x55\x53\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xE2\x07\x00\x00\x00\x13'
            b'\x68\x74\x74\x70\x73\x3A\x2F\x2F\x65\x78\x61\x6D\x70\x6C\x65\x2E'
            b'\x63\x6F\x6D\x00\x00\x00\x00\x00'
            b'\x42\x00\xE3\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\xE4\x02\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xE5\x05\x00\x00\x00\x04\x00\x00\x00\x05\x00\x00\x00\x00'
            b'\x42\x00\xE6\x02\x00\x00\x00\x04\x00\x00\x00\x05\x00\x00\x00\x00'
            b'\x42\x00\xE7\x07\x00\x00\x00\x24'
            b'\x63\x30\x30\x35\x64\x33\x39\x65\x2D\x36\x30\x34\x66\x2D\x31\x31'
            b'\x65\x39\x2D\x39\x39\x64\x66\x2D\x30\x38\x30\x30\x32\x37\x66\x63'
            b'\x31\x33\x39\x36\x00\x00\x00\x00'
            b'\x42\x00\xE8\x07\x00\x00\x00\x10'
            b'\x68\x74\x74\x70\x73\x3A\x2F\x2F\x74\x65\x73\x74\x2E\x63\x6F\x6D'
            b'\x42\x00\xE9\x07\x00\x00\x00\x12'
            b'\x68\x74\x74\x70\x73\x3A\x2F\x2F\x76\x65\x6E\x64\x6F\x72\x2E\x63'
            b'\x6F\x6D\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xEA\x07\x00\x00\x00\x09'
            b'\x50\x72\x6F\x66\x69\x6C\x65\x20\x31\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xEA\x07\x00\x00\x00\x09'
            b'\x50\x72\x6F\x66\x69\x6C\x65\x20\x32\x00\x00\x00\x00\x00\x00\x00'
        )

        # This encoding matches the following set of values:
        #
        # Validation Information
        #     Validation Authority Country - US
        #     Validation Authority URI - https://example.com
        #     Validation Version Major - 1
        #     Validation Version Minor - 0
        #     Validation Type - HYBRID
        #     Validation Level - 5
        #     Validation Certificate Identifier -
        #         c005d39e-604f-11e9-99df-080027fc1396
        #     Validation Certificate URI - https://test.com
        #     Validation Vendor URI - https://vendor.com
        #     Validation Profiles -
        #         Profile 1
        #         Profile 2
        self.no_validation_authority_type_encoding = utils.BytearrayStream(
            b'\x42\x00\xDF\x01\x00\x00\x01\x08'
            b'\x42\x00\xE1\x07\x00\x00\x00\x02\x55\x53\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xE2\x07\x00\x00\x00\x13'
            b'\x68\x74\x74\x70\x73\x3A\x2F\x2F\x65\x78\x61\x6D\x70\x6C\x65\x2E'
            b'\x63\x6F\x6D\x00\x00\x00\x00\x00'
            b'\x42\x00\xE3\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\xE4\x02\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xE5\x05\x00\x00\x00\x04\x00\x00\x00\x05\x00\x00\x00\x00'
            b'\x42\x00\xE6\x02\x00\x00\x00\x04\x00\x00\x00\x05\x00\x00\x00\x00'
            b'\x42\x00\xE7\x07\x00\x00\x00\x24'
            b'\x63\x30\x30\x35\x64\x33\x39\x65\x2D\x36\x30\x34\x66\x2D\x31\x31'
            b'\x65\x39\x2D\x39\x39\x64\x66\x2D\x30\x38\x30\x30\x32\x37\x66\x63'
            b'\x31\x33\x39\x36\x00\x00\x00\x00'
            b'\x42\x00\xE8\x07\x00\x00\x00\x10'
            b'\x68\x74\x74\x70\x73\x3A\x2F\x2F\x74\x65\x73\x74\x2E\x63\x6F\x6D'
            b'\x42\x00\xE9\x07\x00\x00\x00\x12'
            b'\x68\x74\x74\x70\x73\x3A\x2F\x2F\x76\x65\x6E\x64\x6F\x72\x2E\x63'
            b'\x6F\x6D\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xEA\x07\x00\x00\x00\x09'
            b'\x50\x72\x6F\x66\x69\x6C\x65\x20\x31\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xEA\x07\x00\x00\x00\x09'
            b'\x50\x72\x6F\x66\x69\x6C\x65\x20\x32\x00\x00\x00\x00\x00\x00\x00'
        )

        # This encoding matches the following set of values:
        #
        # Validation Information
        #     Validation Authority Type - COMMON_CRITERIA
        #     Validation Authority Country - US
        #     Validation Authority URI - https://example.com
        #     Validation Version Minor - 0
        #     Validation Type - HYBRID
        #     Validation Level - 5
        #     Validation Certificate Identifier -
        #         c005d39e-604f-11e9-99df-080027fc1396
        #     Validation Certificate URI - https://test.com
        #     Validation Vendor URI - https://vendor.com
        #     Validation Profiles -
        #         Profile 1
        #         Profile 2
        self.no_validation_version_major_encoding = utils.BytearrayStream(
            b'\x42\x00\xDF\x01\x00\x00\x01\x08'
            b'\x42\x00\xE0\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\xE1\x07\x00\x00\x00\x02\x55\x53\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xE2\x07\x00\x00\x00\x13'
            b'\x68\x74\x74\x70\x73\x3A\x2F\x2F\x65\x78\x61\x6D\x70\x6C\x65\x2E'
            b'\x63\x6F\x6D\x00\x00\x00\x00\x00'
            b'\x42\x00\xE4\x02\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xE5\x05\x00\x00\x00\x04\x00\x00\x00\x05\x00\x00\x00\x00'
            b'\x42\x00\xE6\x02\x00\x00\x00\x04\x00\x00\x00\x05\x00\x00\x00\x00'
            b'\x42\x00\xE7\x07\x00\x00\x00\x24'
            b'\x63\x30\x30\x35\x64\x33\x39\x65\x2D\x36\x30\x34\x66\x2D\x31\x31'
            b'\x65\x39\x2D\x39\x39\x64\x66\x2D\x30\x38\x30\x30\x32\x37\x66\x63'
            b'\x31\x33\x39\x36\x00\x00\x00\x00'
            b'\x42\x00\xE8\x07\x00\x00\x00\x10'
            b'\x68\x74\x74\x70\x73\x3A\x2F\x2F\x74\x65\x73\x74\x2E\x63\x6F\x6D'
            b'\x42\x00\xE9\x07\x00\x00\x00\x12'
            b'\x68\x74\x74\x70\x73\x3A\x2F\x2F\x76\x65\x6E\x64\x6F\x72\x2E\x63'
            b'\x6F\x6D\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xEA\x07\x00\x00\x00\x09'
            b'\x50\x72\x6F\x66\x69\x6C\x65\x20\x31\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xEA\x07\x00\x00\x00\x09'
            b'\x50\x72\x6F\x66\x69\x6C\x65\x20\x32\x00\x00\x00\x00\x00\x00\x00'
        )

        # This encoding matches the following set of values:
        #
        # Validation Information
        #     Validation Authority Type - COMMON_CRITERIA
        #     Validation Authority Country - US
        #     Validation Authority URI - https://example.com
        #     Validation Version Major - 1
        #     Validation Version Minor - 0
        #     Validation Level - 5
        #     Validation Certificate Identifier -
        #         c005d39e-604f-11e9-99df-080027fc1396
        #     Validation Certificate URI - https://test.com
        #     Validation Vendor URI - https://vendor.com
        #     Validation Profiles -
        #         Profile 1
        #         Profile 2
        self.no_validation_type_encoding = utils.BytearrayStream(
            b'\x42\x00\xDF\x01\x00\x00\x01\x08'
            b'\x42\x00\xE0\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\xE1\x07\x00\x00\x00\x02\x55\x53\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xE2\x07\x00\x00\x00\x13'
            b'\x68\x74\x74\x70\x73\x3A\x2F\x2F\x65\x78\x61\x6D\x70\x6C\x65\x2E'
            b'\x63\x6F\x6D\x00\x00\x00\x00\x00'
            b'\x42\x00\xE3\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\xE4\x02\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xE6\x02\x00\x00\x00\x04\x00\x00\x00\x05\x00\x00\x00\x00'
            b'\x42\x00\xE7\x07\x00\x00\x00\x24'
            b'\x63\x30\x30\x35\x64\x33\x39\x65\x2D\x36\x30\x34\x66\x2D\x31\x31'
            b'\x65\x39\x2D\x39\x39\x64\x66\x2D\x30\x38\x30\x30\x32\x37\x66\x63'
            b'\x31\x33\x39\x36\x00\x00\x00\x00'
            b'\x42\x00\xE8\x07\x00\x00\x00\x10'
            b'\x68\x74\x74\x70\x73\x3A\x2F\x2F\x74\x65\x73\x74\x2E\x63\x6F\x6D'
            b'\x42\x00\xE9\x07\x00\x00\x00\x12'
            b'\x68\x74\x74\x70\x73\x3A\x2F\x2F\x76\x65\x6E\x64\x6F\x72\x2E\x63'
            b'\x6F\x6D\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xEA\x07\x00\x00\x00\x09'
            b'\x50\x72\x6F\x66\x69\x6C\x65\x20\x31\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xEA\x07\x00\x00\x00\x09'
            b'\x50\x72\x6F\x66\x69\x6C\x65\x20\x32\x00\x00\x00\x00\x00\x00\x00'
        )

        # This encoding matches the following set of values:
        #
        # Validation Information
        #     Validation Authority Type - COMMON_CRITERIA
        #     Validation Authority Country - US
        #     Validation Authority URI - https://example.com
        #     Validation Version Major - 1
        #     Validation Version Minor - 0
        #     Validation Type - HYBRID
        #     Validation Certificate Identifier -
        #         c005d39e-604f-11e9-99df-080027fc1396
        #     Validation Certificate URI - https://test.com
        #     Validation Vendor URI - https://vendor.com
        #     Validation Profiles -
        #         Profile 1
        #         Profile 2
        self.no_validation_level_encoding = utils.BytearrayStream(
            b'\x42\x00\xDF\x01\x00\x00\x01\x08'
            b'\x42\x00\xE0\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\xE1\x07\x00\x00\x00\x02\x55\x53\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xE2\x07\x00\x00\x00\x13'
            b'\x68\x74\x74\x70\x73\x3A\x2F\x2F\x65\x78\x61\x6D\x70\x6C\x65\x2E'
            b'\x63\x6F\x6D\x00\x00\x00\x00\x00'
            b'\x42\x00\xE3\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\xE4\x02\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xE5\x05\x00\x00\x00\x04\x00\x00\x00\x05\x00\x00\x00\x00'
            b'\x42\x00\xE7\x07\x00\x00\x00\x24'
            b'\x63\x30\x30\x35\x64\x33\x39\x65\x2D\x36\x30\x34\x66\x2D\x31\x31'
            b'\x65\x39\x2D\x39\x39\x64\x66\x2D\x30\x38\x30\x30\x32\x37\x66\x63'
            b'\x31\x33\x39\x36\x00\x00\x00\x00'
            b'\x42\x00\xE8\x07\x00\x00\x00\x10'
            b'\x68\x74\x74\x70\x73\x3A\x2F\x2F\x74\x65\x73\x74\x2E\x63\x6F\x6D'
            b'\x42\x00\xE9\x07\x00\x00\x00\x12'
            b'\x68\x74\x74\x70\x73\x3A\x2F\x2F\x76\x65\x6E\x64\x6F\x72\x2E\x63'
            b'\x6F\x6D\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xEA\x07\x00\x00\x00\x09'
            b'\x50\x72\x6F\x66\x69\x6C\x65\x20\x31\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xEA\x07\x00\x00\x00\x09'
            b'\x50\x72\x6F\x66\x69\x6C\x65\x20\x32\x00\x00\x00\x00\x00\x00\x00'
        )

        # This encoding matches the following set of values:
        #
        # Validation Information
        #     Validation Authority Type - COMMON_CRITERIA
        #     Validation Version Major - 1
        #     Validation Type - HYBRID
        #     Validation Level - 5
        self.only_essentials_encoding = utils.BytearrayStream(
            b'\x42\x00\xDF\x01\x00\x00\x00\x40'
            b'\x42\x00\xE0\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\xE3\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\xE5\x05\x00\x00\x00\x04\x00\x00\x00\x05\x00\x00\x00\x00'
            b'\x42\x00\xE6\x02\x00\x00\x00\x04\x00\x00\x00\x05\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestValidationInformation, self).tearDown()

    def test_invalid_validation_authority_type(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the validation authority type of a ValidationInformation structure.
        """
        kwargs = {"validation_authority_type": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The validation authority type must be a ValidationAuthorityType "
            "enumeration.",
            objects.ValidationInformation,
            **kwargs
        )

        args = (
            objects.ValidationInformation(),
            "validation_authority_type",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The validation authority type must be a ValidationAuthorityType "
            "enumeration.",
            setattr,
            *args
        )

    def test_invalid_validation_authority_country(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the validation authority country of a ValidationInformation structure.
        """
        kwargs = {"validation_authority_country": 0}
        self.assertRaisesRegex(
            TypeError,
            "The validation authority country must be a string.",
            objects.ValidationInformation,
            **kwargs
        )

        args = (
            objects.ValidationInformation(),
            "validation_authority_country",
            0
        )
        self.assertRaisesRegex(
            TypeError,
            "The validation authority country must be a string.",
            setattr,
            *args
        )

    def test_invalid_validation_authority_uri(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the validation authority URI of a ValidationInformation structure.
        """
        kwargs = {"validation_authority_uri": 0}
        self.assertRaisesRegex(
            TypeError,
            "The validation authority URI must be a string.",
            objects.ValidationInformation,
            **kwargs
        )

        args = (
            objects.ValidationInformation(),
            "validation_authority_uri",
            0
        )
        self.assertRaisesRegex(
            TypeError,
            "The validation authority URI must be a string.",
            setattr,
            *args
        )

    def test_invalid_validation_version_major(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the validation version major of a ValidationInformation structure.
        """
        kwargs = {"validation_version_major": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The validation version major must be an integer.",
            objects.ValidationInformation,
            **kwargs
        )

        args = (
            objects.ValidationInformation(),
            "validation_version_major",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The validation version major must be an integer.",
            setattr,
            *args
        )

    def test_invalid_validation_version_minor(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the validation version minor of a ValidationInformation structure.
        """
        kwargs = {"validation_version_minor": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The validation version minor must be an integer.",
            objects.ValidationInformation,
            **kwargs
        )

        args = (
            objects.ValidationInformation(),
            "validation_version_minor",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The validation version minor must be an integer.",
            setattr,
            *args
        )

    def test_invalid_validation_type(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the validation type of a ValidationInformation structure.
        """
        kwargs = {"validation_type": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The validation type must be a ValidationType enumeration.",
            objects.ValidationInformation,
            **kwargs
        )

        args = (
            objects.ValidationInformation(),
            "validation_type",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The validation type must be a ValidationType enumeration.",
            setattr,
            *args
        )

    def test_invalid_validation_level(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the validation level of a ValidationInformation structure.
        """
        kwargs = {"validation_level": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The validation level must be an integer.",
            objects.ValidationInformation,
            **kwargs
        )

        args = (
            objects.ValidationInformation(),
            "validation_level",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The validation level must be an integer.",
            setattr,
            *args
        )

    def test_invalid_validation_certificate_identifier(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the validation certificate identifier of a ValidationInformation
        structure.
        """
        kwargs = {"validation_certificate_identifier": 0}
        self.assertRaisesRegex(
            TypeError,
            "The validation certificate identifier must be a string.",
            objects.ValidationInformation,
            **kwargs
        )

        args = (
            objects.ValidationInformation(),
            "validation_certificate_identifier",
            0
        )
        self.assertRaisesRegex(
            TypeError,
            "The validation certificate identifier must be a string.",
            setattr,
            *args
        )

    def test_invalid_validation_certificate_uri(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the validation certificate URI of a ValidationInformation structure.
        """
        kwargs = {"validation_certificate_uri": 0}
        self.assertRaisesRegex(
            TypeError,
            "The validation certificate URI must be a string.",
            objects.ValidationInformation,
            **kwargs
        )

        args = (
            objects.ValidationInformation(),
            "validation_certificate_uri",
            0
        )
        self.assertRaisesRegex(
            TypeError,
            "The validation certificate URI must be a string.",
            setattr,
            *args
        )

    def test_invalid_validation_vendor_uri(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the validation vendor URI of a ValidationInformation structure.
        """
        kwargs = {"validation_vendor_uri": 0}
        self.assertRaisesRegex(
            TypeError,
            "The validation vendor URI must be a string.",
            objects.ValidationInformation,
            **kwargs
        )

        args = (
            objects.ValidationInformation(),
            "validation_vendor_uri",
            0
        )
        self.assertRaisesRegex(
            TypeError,
            "The validation vendor URI must be a string.",
            setattr,
            *args
        )

    def test_invalid_validation_profiles(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the validation profiles of a ValidationInformation structure.
        """
        kwargs = {"validation_profiles": 0}
        self.assertRaisesRegex(
            TypeError,
            "The validation profiles must be a list of strings.",
            objects.ValidationInformation,
            **kwargs
        )
        kwargs = {"validation_profiles": ["valid", 0]}
        self.assertRaisesRegex(
            TypeError,
            "The validation profiles must be a list of strings.",
            objects.ValidationInformation,
            **kwargs
        )

        args = (
            objects.ValidationInformation(),
            "validation_profiles",
            0
        )
        self.assertRaisesRegex(
            TypeError,
            "The validation profiles must be a list of strings.",
            setattr,
            *args
        )
        args = (
            objects.ValidationInformation(),
            "validation_profiles",
            ["valid", 0]
        )
        self.assertRaisesRegex(
            TypeError,
            "The validation profiles must be a list of strings.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a ValidationInformation structure can be correctly read in
        from a data stream.
        """
        validation_information = objects.ValidationInformation()

        self.assertIsNone(validation_information.validation_authority_type)
        self.assertIsNone(validation_information.validation_authority_country)
        self.assertIsNone(validation_information.validation_authority_uri)
        self.assertIsNone(validation_information.validation_version_major)
        self.assertIsNone(validation_information.validation_version_minor)
        self.assertIsNone(validation_information.validation_type)
        self.assertIsNone(validation_information.validation_level)
        self.assertIsNone(
            validation_information.validation_certificate_identifier
        )
        self.assertIsNone(validation_information.validation_certificate_uri)
        self.assertIsNone(validation_information.validation_vendor_uri)
        self.assertIsNone(
            validation_information.validation_profiles
        )

        validation_information.read(
            self.full_encoding,
            kmip_version=enums.KMIPVersion.KMIP_1_3
        )

        self.assertEqual(
            enums.ValidationAuthorityType.COMMON_CRITERIA,
            validation_information.validation_authority_type
        )
        self.assertEqual(
            "US",
            validation_information.validation_authority_country
        )
        self.assertEqual(
            "https://example.com",
            validation_information.validation_authority_uri
        )
        self.assertEqual(1, validation_information.validation_version_major)
        self.assertEqual(0, validation_information.validation_version_minor)
        self.assertEqual(
            enums.ValidationType.HYBRID,
            validation_information.validation_type
        )
        self.assertEqual(5, validation_information.validation_level)
        self.assertEqual(
            "c005d39e-604f-11e9-99df-080027fc1396",
            validation_information.validation_certificate_identifier
        )
        self.assertEqual(
            "https://test.com",
            validation_information.validation_certificate_uri
        )
        self.assertEqual(
            "https://vendor.com",
            validation_information.validation_vendor_uri
        )
        self.assertEqual(
            [
                "Profile 1",
                "Profile 2"
            ],
            validation_information.validation_profiles
        )

    def test_read_unsupported_kmip_version(self):
        """
        Test that a VersionNotSupported error is raised during the decoding of
        a ValidationInformation structure when the structure is read for an
        unsupported KMIP version.
        """
        validation_information = objects.ValidationInformation()

        args = (self.full_encoding, )
        kwargs = {"kmip_version": enums.KMIPVersion.KMIP_1_2}
        self.assertRaisesRegex(
            exceptions.VersionNotSupported,
            "KMIP 1.2 does not support the ValidationInformation object.",
            validation_information.read,
            *args,
            **kwargs
        )

    def test_read_missing_validation_authority_type(self):
        """
        Test that an InvalidKmipEncoding error is raised during the decoding
        of a ValidationInformation structure when the validation authority
        type is missing from the encoding.
        """
        validation_information = objects.ValidationInformation()

        args = (self.no_validation_authority_type_encoding, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The ValidationInformation encoding is missing the validation "
            "authority type.",
            validation_information.read,
            *args
        )

    def test_read_missing_validation_version_major(self):
        """
        Test that an InvalidKmipEncoding error is raised during the decoding
        of a ValidationInformation structure when the validation version major
        is missing from the encoding.
        """
        validation_information = objects.ValidationInformation()

        args = (self.no_validation_version_major_encoding, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The ValidationInformation encoding is missing the validation "
            "version major.",
            validation_information.read,
            *args
        )

    def test_read_missing_validation_type(self):
        """
        Test that an InvalidKmipEncoding error is raised during the decoding
        of a ValidationInformation structure when the validation type is
        missing from the encoding.
        """
        validation_information = objects.ValidationInformation()

        args = (self.no_validation_type_encoding, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The ValidationInformation encoding is missing the validation "
            "type.",
            validation_information.read,
            *args
        )

    def test_read_missing_validation_level(self):
        """
        Test that an InvalidKmipEncoding error is raised during the decoding
        of a ValidationInformation structure when the validation level is
        missing from the encoding.
        """
        validation_information = objects.ValidationInformation()

        args = (self.no_validation_level_encoding, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The ValidationInformation encoding is missing the validation "
            "level.",
            validation_information.read,
            *args
        )

    def test_read_only_essential_fields(self):
        """
        Test that a ProfileInformation structure can be correctly read in
        from a data stream even when missing all fields except the profile
        name.
        """
        validation_information = objects.ValidationInformation()

        self.assertIsNone(validation_information.validation_authority_type)
        self.assertIsNone(validation_information.validation_authority_country)
        self.assertIsNone(validation_information.validation_authority_uri)
        self.assertIsNone(validation_information.validation_version_major)
        self.assertIsNone(validation_information.validation_version_minor)
        self.assertIsNone(validation_information.validation_type)
        self.assertIsNone(validation_information.validation_level)
        self.assertIsNone(
            validation_information.validation_certificate_identifier
        )
        self.assertIsNone(validation_information.validation_certificate_uri)
        self.assertIsNone(validation_information.validation_vendor_uri)
        self.assertIsNone(
            validation_information.validation_profiles
        )

        validation_information.read(
            self.only_essentials_encoding,
            kmip_version=enums.KMIPVersion.KMIP_1_3
        )

        self.assertEqual(
            enums.ValidationAuthorityType.COMMON_CRITERIA,
            validation_information.validation_authority_type
        )
        self.assertIsNone(validation_information.validation_authority_country)
        self.assertIsNone(validation_information.validation_authority_uri)
        self.assertEqual(1, validation_information.validation_version_major)
        self.assertIsNone(validation_information.validation_version_minor)
        self.assertEqual(
            enums.ValidationType.HYBRID,
            validation_information.validation_type
        )
        self.assertEqual(5, validation_information.validation_level)
        self.assertIsNone(
            validation_information.validation_certificate_identifier
        )
        self.assertIsNone(validation_information.validation_certificate_uri)
        self.assertIsNone(validation_information.validation_vendor_uri)
        self.assertIsNone(
            validation_information.validation_profiles
        )

    def test_write(self):
        """
        Test that a ValidationInformation structure can be written to a data
        stream.
        """
        validation_information = objects.ValidationInformation(
            validation_authority_type=(
                enums.ValidationAuthorityType.COMMON_CRITERIA
            ),
            validation_authority_country="US",
            validation_authority_uri="https://example.com",
            validation_version_major=1,
            validation_version_minor=0,
            validation_type=enums.ValidationType.HYBRID,
            validation_level=5,
            validation_certificate_identifier=(
                "c005d39e-604f-11e9-99df-080027fc1396"
            ),
            validation_certificate_uri="https://test.com",
            validation_vendor_uri="https://vendor.com",
            validation_profiles=["Profile 1", "Profile 2"]
        )

        buffer = utils.BytearrayStream()
        validation_information.write(
            buffer,
            kmip_version=enums.KMIPVersion.KMIP_1_3
        )

        self.assertEqual(len(self.full_encoding), len(buffer))
        self.assertEqual(str(self.full_encoding), str(buffer))

    def test_write_unsupported_kmip_version(self):
        """
        Test that a VersionNotSupported error is raised during the encoding of
        a ValidationInformation structure when the structure is written for an
        unsupported KMIP version.
        """
        validation_information = objects.ValidationInformation(
            validation_authority_type=(
                enums.ValidationAuthorityType.COMMON_CRITERIA
            ),
            validation_authority_country="US",
            validation_authority_uri="https://example.com",
            validation_version_major=1,
            validation_version_minor=0,
            validation_type=enums.ValidationType.HYBRID,
            validation_level=5,
            validation_certificate_identifier=(
                "c005d39e-604f-11e9-99df-080027fc1396"
            ),
            validation_certificate_uri="https://test.com",
            validation_vendor_uri="https://vendor.com",
            validation_profiles=["Profile 1", "Profile 2"]
        )

        args = (utils.BytearrayStream(), )
        kwargs = {"kmip_version": enums.KMIPVersion.KMIP_1_2}
        self.assertRaisesRegex(
            exceptions.VersionNotSupported,
            "KMIP 1.2 does not support the ValidationInformation object.",
            validation_information.write,
            *args,
            **kwargs
        )

    def test_write_missing_validation_authority_type(self):
        """
        Test that an InvalidField error is raised during the encoding of an
        ValidationInformation structure when the structure is missing the
        validation authority type field.
        """
        validation_information = objects.ValidationInformation(
            validation_authority_country="US",
            validation_authority_uri="https://example.com",
            validation_version_major=1,
            validation_version_minor=0,
            validation_type=enums.ValidationType.HYBRID,
            validation_level=5,
            validation_certificate_identifier=(
                "c005d39e-604f-11e9-99df-080027fc1396"
            ),
            validation_certificate_uri="https://test.com",
            validation_vendor_uri="https://vendor.com",
            validation_profiles=["Profile 1", "Profile 2"]
        )

        args = (utils.BytearrayStream(), )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The ValidationInformation structure is missing the validation "
            "authority type field.",
            validation_information.write,
            *args
        )

    def test_write_missing_validation_version_major(self):
        """
        Test that an InvalidField error is raised during the encoding of an
        ValidationInformation structure when the structure is missing the
        validation version major field.
        """
        validation_information = objects.ValidationInformation(
            validation_authority_type=(
                enums.ValidationAuthorityType.COMMON_CRITERIA
            ),
            validation_authority_country="US",
            validation_authority_uri="https://example.com",
            validation_version_minor=0,
            validation_type=enums.ValidationType.HYBRID,
            validation_level=5,
            validation_certificate_identifier=(
                "c005d39e-604f-11e9-99df-080027fc1396"
            ),
            validation_certificate_uri="https://test.com",
            validation_vendor_uri="https://vendor.com",
            validation_profiles=["Profile 1", "Profile 2"]
        )

        args = (utils.BytearrayStream(), )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The ValidationInformation structure is missing the validation "
            "version major field.",
            validation_information.write,
            *args
        )

    def test_write_missing_validation_type(self):
        """
        Test that an InvalidField error is raised during the encoding of an
        ValidationInformation structure when the structure is missing the
        validation type field.
        """
        validation_information = objects.ValidationInformation(
            validation_authority_type=(
                enums.ValidationAuthorityType.COMMON_CRITERIA
            ),
            validation_authority_country="US",
            validation_authority_uri="https://example.com",
            validation_version_major=1,
            validation_version_minor=0,
            validation_level=5,
            validation_certificate_identifier=(
                "c005d39e-604f-11e9-99df-080027fc1396"
            ),
            validation_certificate_uri="https://test.com",
            validation_vendor_uri="https://vendor.com",
            validation_profiles=["Profile 1", "Profile 2"]
        )

        args = (utils.BytearrayStream(), )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The ValidationInformation structure is missing the validation "
            "type field.",
            validation_information.write,
            *args
        )

    def test_write_missing_validation_level(self):
        """
        Test that an InvalidField error is raised during the encoding of an
        ValidationInformation structure when the structure is missing the
        validation level field.
        """
        validation_information = objects.ValidationInformation(
            validation_authority_type=(
                enums.ValidationAuthorityType.COMMON_CRITERIA
            ),
            validation_authority_country="US",
            validation_authority_uri="https://example.com",
            validation_version_major=1,
            validation_version_minor=0,
            validation_type=enums.ValidationType.HYBRID,
            validation_certificate_identifier=(
                "c005d39e-604f-11e9-99df-080027fc1396"
            ),
            validation_certificate_uri="https://test.com",
            validation_vendor_uri="https://vendor.com",
            validation_profiles=["Profile 1", "Profile 2"]
        )

        args = (utils.BytearrayStream(), )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The ValidationInformation structure is missing the validation "
            "level field.",
            validation_information.write,
            *args
        )

    def test_write_only_essentials(self):
        """
        Test that a ValidationInformation structure can be written to a data
        stream when only containing essential required fields.
        """
        validation_information = objects.ValidationInformation(
            validation_authority_type=(
                enums.ValidationAuthorityType.COMMON_CRITERIA
            ),
            validation_version_major=1,
            validation_type=enums.ValidationType.HYBRID,
            validation_level=5,
        )

        buffer = utils.BytearrayStream()
        validation_information.write(
            buffer,
            kmip_version=enums.KMIPVersion.KMIP_1_3
        )

        self.assertEqual(len(self.only_essentials_encoding), len(buffer))
        self.assertEqual(str(self.only_essentials_encoding), str(buffer))

    def test_repr(self):
        """
        Test that repr can be applied to a ValidationInformation structure.
        """
        validation_information = objects.ValidationInformation(
            validation_authority_type=(
                enums.ValidationAuthorityType.COMMON_CRITERIA
            ),
            validation_authority_country="US",
            validation_authority_uri="https://example.com",
            validation_version_major=1,
            validation_version_minor=0,
            validation_type=enums.ValidationType.HYBRID,
            validation_level=5,
            validation_certificate_identifier=(
                "c005d39e-604f-11e9-99df-080027fc1396"
            ),
            validation_certificate_uri="https://test.com",
            validation_vendor_uri="https://vendor.com",
            validation_profiles=["Profile 1", "Profile 2"]
        )

        vat = "validation_authority_type=" + \
              "ValidationAuthorityType.COMMON_CRITERIA"
        vac = 'validation_authority_country="US"'
        vau = 'validation_authority_uri="https://example.com"'
        vvj = "validation_version_major=1"
        vvn = "validation_version_minor=0"
        vt = "validation_type=ValidationType.HYBRID"
        vl = "validation_level=5"
        vci = 'validation_certificate_identifier=' + \
              '"c005d39e-604f-11e9-99df-080027fc1396"'
        vcu = 'validation_certificate_uri="https://test.com"'
        vvu = 'validation_vendor_uri="https://vendor.com"'
        vp = 'validation_profiles=["Profile 1", "Profile 2"]'

        v = ", ".join([vat, vac, vau, vvj, vvn, vt, vl, vci, vcu, vvu, vp])

        self.assertEqual(
            "ValidationInformation({})".format(v),
            repr(validation_information)
        )

    def test_str(self):
        """
        Test that str can be applied to a ValidationInformation structure.
        """
        validation_information = objects.ValidationInformation(
            validation_authority_type=(
                enums.ValidationAuthorityType.COMMON_CRITERIA
            ),
            validation_authority_country="US",
            validation_authority_uri="https://example.com",
            validation_version_major=1,
            validation_version_minor=0,
            validation_type=enums.ValidationType.HYBRID,
            validation_level=5,
            validation_certificate_identifier=(
                "c005d39e-604f-11e9-99df-080027fc1396"
            ),
            validation_certificate_uri="https://test.com",
            validation_vendor_uri="https://vendor.com",
            validation_profiles=["Profile 1", "Profile 2"]
        )

        vat = '"validation_authority_type": ' + \
              'ValidationAuthorityType.COMMON_CRITERIA'
        vac = '"validation_authority_country": "US"'
        vau = '"validation_authority_uri": "https://example.com"'
        vvj = '"validation_version_major": 1'
        vvn = '"validation_version_minor": 0'
        vt = '"validation_type": ValidationType.HYBRID'
        vl = '"validation_level": 5'
        vci = '"validation_certificate_identifier": ' + \
              '"c005d39e-604f-11e9-99df-080027fc1396"'
        vcu = '"validation_certificate_uri": "https://test.com"'
        vvu = '"validation_vendor_uri": "https://vendor.com"'
        vp = '"validation_profiles": ["Profile 1", "Profile 2"]'

        v = ", ".join([vat, vac, vau, vvj, vvn, vt, vl, vci, vcu, vvu, vp])

        self.assertEqual(
            "{" + v + "}",
            str(validation_information)
        )

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        ValidationInformation structures with the same data.
        """
        a = objects.ValidationInformation()
        b = objects.ValidationInformation()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = objects.ValidationInformation(
            validation_authority_type=(
                enums.ValidationAuthorityType.COMMON_CRITERIA
            ),
            validation_authority_country="US",
            validation_authority_uri="https://example.com",
            validation_version_major=1,
            validation_version_minor=0,
            validation_type=enums.ValidationType.HYBRID,
            validation_level=5,
            validation_certificate_identifier=(
                "c005d39e-604f-11e9-99df-080027fc1396"
            ),
            validation_certificate_uri="https://test.com",
            validation_vendor_uri="https://vendor.com",
            validation_profiles=["Profile 1", "Profile 2"]
        )
        b = objects.ValidationInformation(
            validation_authority_type=(
                enums.ValidationAuthorityType.COMMON_CRITERIA
            ),
            validation_authority_country="US",
            validation_authority_uri="https://example.com",
            validation_version_major=1,
            validation_version_minor=0,
            validation_type=enums.ValidationType.HYBRID,
            validation_level=5,
            validation_certificate_identifier=(
                "c005d39e-604f-11e9-99df-080027fc1396"
            ),
            validation_certificate_uri="https://test.com",
            validation_vendor_uri="https://vendor.com",
            validation_profiles=["Profile 1", "Profile 2"]
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_validation_authority_type(self):
        """
        Test that the equality operator returns False when comparing two
        ValidationInformation structures with different validation authority
        type fields.
        """
        a = objects.ValidationInformation(
            validation_authority_type=(
                enums.ValidationAuthorityType.COMMON_CRITERIA
            )
        )
        b = objects.ValidationInformation(
            validation_authority_type=enums.ValidationAuthorityType.UNSPECIFIED
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_validation_authority_country(self):
        """
        Test that the equality operator returns False when comparing two
        ValidationInformation structures with different validation authority
        country fields.
        """
        a = objects.ValidationInformation(validation_authority_country="US")
        b = objects.ValidationInformation(validation_authority_country="UK")

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_validation_authority_uri(self):
        """
        Test that the equality operator returns False when comparing two
        ValidationInformation structures with different validation authority
        URI fields.
        """
        a = objects.ValidationInformation(
            validation_authority_uri="https://a.com"
        )
        b = objects.ValidationInformation(
            validation_authority_uri="https://b.com"
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_validation_version_major(self):
        """
        Test that the equality operator returns False when comparing two
        ValidationInformation structures with different validation version
        major fields.
        """
        a = objects.ValidationInformation(validation_version_major=1)
        b = objects.ValidationInformation(validation_version_major=2)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_validation_version_minor(self):
        """
        Test that the equality operator returns False when comparing two
        ValidationInformation structures with different validation version
        minor fields.
        """
        a = objects.ValidationInformation(validation_version_minor=1)
        b = objects.ValidationInformation(validation_version_minor=2)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_validation_type(self):
        """
        Test that the equality operator returns False when comparing two
        ValidationInformation structures with different validation type
        fields.
        """
        a = objects.ValidationInformation(
            validation_type=enums.ValidationType.HARDWARE
        )
        b = objects.ValidationInformation(
            validation_type=enums.ValidationType.SOFTWARE
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_validation_level(self):
        """
        Test that the equality operator returns False when comparing two
        ValidationInformation structures with different validation level
        fields.
        """
        a = objects.ValidationInformation(validation_level=1)
        b = objects.ValidationInformation(validation_level=2)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_validation_certificate_identifier(self):
        """
        Test that the equality operator returns False when comparing two
        ValidationInformation structures with different validation certificate
        identifier fields.
        """
        a = objects.ValidationInformation(
            validation_certificate_identifier="1"
        )
        b = objects.ValidationInformation(
            validation_certificate_identifier="2"
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_validation_certificate_uri(self):
        """
        Test that the equality operator returns False when comparing two
        ValidationInformation structures with different validation certificate
        URI fields.
        """
        a = objects.ValidationInformation(
            validation_certificate_uri="https://a.com"
        )
        b = objects.ValidationInformation(
            validation_certificate_uri="https://b.com"
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_validation_vendor_uri(self):
        """
        Test that the equality operator returns False when comparing two
        ValidationInformation structures with different validation vendor URI
        fields.
        """
        a = objects.ValidationInformation(
            validation_vendor_uri="https://a.com"
        )
        b = objects.ValidationInformation(
            validation_vendor_uri="https://b.com"
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_validation_profiles(self):
        """
        Test that the equality operator returns False when comparing two
        ValidationInformation structures with different validation profiles
        fields.
        """
        a = objects.ValidationInformation(
            validation_profiles=["Profile 1", "Profile 2"]
        )
        b = objects.ValidationInformation(
            validation_profiles=["Profile 2", "Profile 1"]
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        ValidationInformation structures with different types.
        """
        a = objects.ValidationInformation()
        b = "invalid"

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        ValidationInformation structures with the same data.
        """
        a = objects.ValidationInformation()
        b = objects.ValidationInformation()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = objects.ValidationInformation(
            validation_authority_type=(
                enums.ValidationAuthorityType.COMMON_CRITERIA
            ),
            validation_authority_country="US",
            validation_authority_uri="https://example.com",
            validation_version_major=1,
            validation_version_minor=0,
            validation_type=enums.ValidationType.HYBRID,
            validation_level=5,
            validation_certificate_identifier=(
                "c005d39e-604f-11e9-99df-080027fc1396"
            ),
            validation_certificate_uri="https://test.com",
            validation_vendor_uri="https://vendor.com",
            validation_profiles=["Profile 1", "Profile 2"]
        )
        b = objects.ValidationInformation(
            validation_authority_type=(
                enums.ValidationAuthorityType.COMMON_CRITERIA
            ),
            validation_authority_country="US",
            validation_authority_uri="https://example.com",
            validation_version_major=1,
            validation_version_minor=0,
            validation_type=enums.ValidationType.HYBRID,
            validation_level=5,
            validation_certificate_identifier=(
                "c005d39e-604f-11e9-99df-080027fc1396"
            ),
            validation_certificate_uri="https://test.com",
            validation_vendor_uri="https://vendor.com",
            validation_profiles=["Profile 1", "Profile 2"]
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_validation_authority_type(self):
        """
        Test that the inequality operator returns True when comparing two
        ValidationInformation structures with different validation authority
        type fields.
        """
        a = objects.ValidationInformation(
            validation_authority_type=(
                enums.ValidationAuthorityType.COMMON_CRITERIA
            )
        )
        b = objects.ValidationInformation(
            validation_authority_type=enums.ValidationAuthorityType.UNSPECIFIED
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_validation_authority_country(self):
        """
        Test that the inequality operator returns True when comparing two
        ValidationInformation structures with different validation authority
        country fields.
        """
        a = objects.ValidationInformation(validation_authority_country="US")
        b = objects.ValidationInformation(validation_authority_country="UK")

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_validation_authority_uri(self):
        """
        Test that the inequality operator returns True when comparing two
        ValidationInformation structures with different validation authority
        URI fields.
        """
        a = objects.ValidationInformation(
            validation_authority_uri="https://a.com"
        )
        b = objects.ValidationInformation(
            validation_authority_uri="https://b.com"
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_validation_version_major(self):
        """
        Test that the inequality operator returns True when comparing two
        ValidationInformation structures with different validation version
        major fields.
        """
        a = objects.ValidationInformation(validation_version_major=1)
        b = objects.ValidationInformation(validation_version_major=2)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_validation_version_minor(self):
        """
        Test that the inequality operator returns True when comparing two
        ValidationInformation structures with different validation version
        minor fields.
        """
        a = objects.ValidationInformation(validation_version_minor=1)
        b = objects.ValidationInformation(validation_version_minor=2)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_validation_type(self):
        """
        Test that the inequality operator returns True when comparing two
        ValidationInformation structures with different validation type
        fields.
        """
        a = objects.ValidationInformation(
            validation_type=enums.ValidationType.HARDWARE
        )
        b = objects.ValidationInformation(
            validation_type=enums.ValidationType.SOFTWARE
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_validation_level(self):
        """
        Test that the inequality operator returns True when comparing two
        ValidationInformation structures with different validation level
        fields.
        """
        a = objects.ValidationInformation(validation_level=1)
        b = objects.ValidationInformation(validation_level=2)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_validation_certificate_identifier(self):
        """
        Test that the inequality operator returns True when comparing two
        ValidationInformation structures with different validation certificate
        identifier fields.
        """
        a = objects.ValidationInformation(
            validation_certificate_identifier="1"
        )
        b = objects.ValidationInformation(
            validation_certificate_identifier="2"
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_validation_certificate_uri(self):
        """
        Test that the inequality operator returns True when comparing two
        ValidationInformation structures with different validation certificate
        URI fields.
        """
        a = objects.ValidationInformation(
            validation_certificate_uri="https://a.com"
        )
        b = objects.ValidationInformation(
            validation_certificate_uri="https://b.com"
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_validation_vendor_uri(self):
        """
        Test that the inequality operator returns True when comparing two
        ValidationInformation structures with different validation vendor URI
        fields.
        """
        a = objects.ValidationInformation(
            validation_vendor_uri="https://a.com"
        )
        b = objects.ValidationInformation(
            validation_vendor_uri="https://b.com"
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_validation_profiles(self):
        """
        Test that the inequality operator returns True when comparing two
        ValidationInformation structures with different validation profiles
        fields.
        """
        a = objects.ValidationInformation(
            validation_profiles=["Profile 1", "Profile 2"]
        )
        b = objects.ValidationInformation(
            validation_profiles=["Profile 2", "Profile 1"]
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        ValidationInformation structures with different types.
        """
        a = objects.ValidationInformation()
        b = "invalid"

        self.assertTrue(a != b)
        self.assertTrue(b != a)

class TestCapabilityInformation(testtools.TestCase):

    def setUp(self):
        super(TestCapabilityInformation, self).setUp()

        # This encoding matches the following set of values:
        #
        # Capability Information
        #     Streaming Capability - False
        #     Asynchronous Capability - True
        #     Attestation Capability - True
        #     Batch Undo Capability - False
        #     Batch Continue Capability - True
        #     Unwrap Mode - PROCESSED
        #     Destroy Action - SHREDDED
        #     Shredding Algorithm - CRYPTOGRAPHIC
        #     RNG Mode - NON_SHARED_INSTANTIATION
        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\xF7\x01\x00\x00\x00\x90'
            b'\x42\x00\xEF\x06\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xF0\x06\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x01'
            b'\x42\x00\xF1\x06\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x01'
            b'\x42\x00\xF9\x06\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xFA\x06\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x01'
            b'\x42\x00\xF2\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\xF3\x05\x00\x00\x00\x04\x00\x00\x00\x07\x00\x00\x00\x00'
            b'\x42\x00\xF4\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\xF5\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
        )

        # This encoding matches the following set of values:
        #
        # Capability Information
        #     Streaming Capability - False
        #     Asynchronous Capability - True
        #     Attestation Capability - True
        #     Unwrap Mode - PROCESSED
        #     Destroy Action - SHREDDED
        #     Shredding Algorithm - CRYPTOGRAPHIC
        #     RNG Mode - NON_SHARED_INSTANTIATION
        self.full_encoding_kmip_1_3 = utils.BytearrayStream(
            b'\x42\x00\xF7\x01\x00\x00\x00\x70'
            b'\x42\x00\xEF\x06\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xF0\x06\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x01'
            b'\x42\x00\xF1\x06\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x01'
            b'\x42\x00\xF2\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\xF3\x05\x00\x00\x00\x04\x00\x00\x00\x07\x00\x00\x00\x00'
            b'\x42\x00\xF4\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\xF5\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
        )

        # This encoding matches the following set of values:
        #
        # Capability Information
        self.empty_encoding = utils.BytearrayStream(
            b'\x42\x00\xF7\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestCapabilityInformation, self).tearDown()

    def test_invalid_streaming_capability(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the streaming capability of a CapabilityInformation structure.
        """
        kwargs = {"streaming_capability": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The streaming capability must be a boolean.",
            objects.CapabilityInformation,
            **kwargs
        )

        args = (
            objects.CapabilityInformation(),
            "streaming_capability",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The streaming capability must be a boolean.",
            setattr,
            *args
        )

    def test_invalid_asynchronous_capability(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the asynchronous capability of a CapabilityInformation structure.
        """
        kwargs = {"asynchronous_capability": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The asynchronous capability must be a boolean.",
            objects.CapabilityInformation,
            **kwargs
        )

        args = (
            objects.CapabilityInformation(),
            "asynchronous_capability",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The asynchronous capability must be a boolean.",
            setattr,
            *args
        )

    def test_invalid_attestation_capability(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the attestation capability of a CapabilityInformation structure.
        """
        kwargs = {"attestation_capability": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The attestation capability must be a boolean.",
            objects.CapabilityInformation,
            **kwargs
        )

        args = (
            objects.CapabilityInformation(),
            "attestation_capability",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The attestation capability must be a boolean.",
            setattr,
            *args
        )

    def test_invalid_batch_undo_capability(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the batch undo capability of a CapabilityInformation structure.
        """
        kwargs = {"batch_undo_capability": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The batch undo capability must be a boolean.",
            objects.CapabilityInformation,
            **kwargs
        )

        args = (
            objects.CapabilityInformation(),
            "batch_undo_capability",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The batch undo capability must be a boolean.",
            setattr,
            *args
        )

    def test_invalid_batch_continue_capability(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the batch continue capability of a CapabilityInformation structure.
        """
        kwargs = {"batch_continue_capability": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The batch continue capability must be a boolean.",
            objects.CapabilityInformation,
            **kwargs
        )

        args = (
            objects.CapabilityInformation(),
            "batch_continue_capability",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The batch continue capability must be a boolean.",
            setattr,
            *args
        )

    def test_invalid_unwrap_mode(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the unwrap mode of a CapabilityInformation structure.
        """
        kwargs = {"unwrap_mode": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The unwrap mode must be an UnwrapMode enumeration.",
            objects.CapabilityInformation,
            **kwargs
        )

        args = (
            objects.CapabilityInformation(),
            "unwrap_mode",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The unwrap mode must be an UnwrapMode enumeration.",
            setattr,
            *args
        )

    def test_invalid_destroy_action(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the destroy action of a CapabilityInformation structure.
        """
        kwargs = {"destroy_action": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The destroy action must be a DestroyAction enumeration.",
            objects.CapabilityInformation,
            **kwargs
        )

        args = (
            objects.CapabilityInformation(),
            "destroy_action",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The destroy action must be a DestroyAction enumeration.",
            setattr,
            *args
        )

    def test_invalid_shredding_algorithm(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the shredding algorithm of a CapabilityInformation structure.
        """
        kwargs = {"shredding_algorithm": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The shredding algorithm must be a ShreddingAlgorithm "
            "enumeration.",
            objects.CapabilityInformation,
            **kwargs
        )

        args = (
            objects.CapabilityInformation(),
            "shredding_algorithm",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The shredding algorithm must be a ShreddingAlgorithm "
            "enumeration.",
            setattr,
            *args
        )

    def test_invalid_rng_mode(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the RNG mode of a CapabilityInformation structure.
        """
        kwargs = {"rng_mode": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The RNG mode must be an RNGMode enumeration.",
            objects.CapabilityInformation,
            **kwargs
        )

        args = (
            objects.CapabilityInformation(),
            "rng_mode",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The RNG mode must be an RNGMode enumeration.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a CapabilityInformation structure can be correctly read in
        from a data stream.
        """
        capability_information = objects.CapabilityInformation()

        self.assertIsNone(capability_information.streaming_capability)
        self.assertIsNone(capability_information.asynchronous_capability)
        self.assertIsNone(capability_information.attestation_capability)
        self.assertIsNone(capability_information.batch_undo_capability)
        self.assertIsNone(capability_information.batch_continue_capability)
        self.assertIsNone(capability_information.unwrap_mode)
        self.assertIsNone(capability_information.destroy_action)
        self.assertIsNone(capability_information.shredding_algorithm)
        self.assertIsNone(capability_information.rng_mode)

        capability_information.read(
            self.full_encoding,
            kmip_version=enums.KMIPVersion.KMIP_1_4
        )

        self.assertFalse(capability_information.streaming_capability)
        self.assertTrue(capability_information.asynchronous_capability)
        self.assertTrue(capability_information.attestation_capability)
        self.assertFalse(capability_information.batch_undo_capability)
        self.assertTrue(capability_information.batch_continue_capability)
        self.assertEqual(
            enums.UnwrapMode.PROCESSED,
            capability_information.unwrap_mode
        )
        self.assertEqual(
            enums.DestroyAction.SHREDDED,
            capability_information.destroy_action
        )
        self.assertEqual(
            enums.ShreddingAlgorithm.CRYPTOGRAPHIC,
            capability_information.shredding_algorithm
        )
        self.assertEqual(
            enums.RNGMode.NON_SHARED_INSTANTIATION,
            capability_information.rng_mode
        )

    def test_read_unsupported_kmip_version(self):
        """
        Test that a VersionNotSupported error is raised during the decoding of
        a CapabilityInformation structure when the structure is read for an
        unsupported KMIP version.
        """
        capability_information = objects.CapabilityInformation()

        args = (self.full_encoding, )
        kwargs = {"kmip_version": enums.KMIPVersion.KMIP_1_2}
        self.assertRaisesRegex(
            exceptions.VersionNotSupported,
            "KMIP 1.2 does not support the CapabilityInformation object.",
            capability_information.read,
            *args,
            **kwargs
        )

    def test_read_kmip_1_3(self):
        """
        Test that a CapabilityInformation structure can be correctly read in
        from a data stream with only KMIP 1.3 features.
        """
        capability_information = objects.CapabilityInformation()

        self.assertIsNone(capability_information.streaming_capability)
        self.assertIsNone(capability_information.asynchronous_capability)
        self.assertIsNone(capability_information.attestation_capability)
        self.assertIsNone(capability_information.batch_undo_capability)
        self.assertIsNone(capability_information.batch_continue_capability)
        self.assertIsNone(capability_information.unwrap_mode)
        self.assertIsNone(capability_information.destroy_action)
        self.assertIsNone(capability_information.shredding_algorithm)
        self.assertIsNone(capability_information.rng_mode)

        capability_information.read(
            self.full_encoding_kmip_1_3,
            kmip_version=enums.KMIPVersion.KMIP_1_4
        )

        self.assertFalse(capability_information.streaming_capability)
        self.assertTrue(capability_information.asynchronous_capability)
        self.assertTrue(capability_information.attestation_capability)
        self.assertIsNone(capability_information.batch_undo_capability)
        self.assertIsNone(capability_information.batch_continue_capability)
        self.assertEqual(
            enums.UnwrapMode.PROCESSED,
            capability_information.unwrap_mode
        )
        self.assertEqual(
            enums.DestroyAction.SHREDDED,
            capability_information.destroy_action
        )
        self.assertEqual(
            enums.ShreddingAlgorithm.CRYPTOGRAPHIC,
            capability_information.shredding_algorithm
        )
        self.assertEqual(
            enums.RNGMode.NON_SHARED_INSTANTIATION,
            capability_information.rng_mode
        )

    def test_read_empty(self):
        """
        Test that a CapabilityInformation structure can be correctly read in
        from an empty data stream.
        """
        capability_information = objects.CapabilityInformation()

        self.assertIsNone(capability_information.streaming_capability)
        self.assertIsNone(capability_information.asynchronous_capability)
        self.assertIsNone(capability_information.attestation_capability)
        self.assertIsNone(capability_information.batch_undo_capability)
        self.assertIsNone(capability_information.batch_continue_capability)
        self.assertIsNone(capability_information.unwrap_mode)
        self.assertIsNone(capability_information.destroy_action)
        self.assertIsNone(capability_information.shredding_algorithm)
        self.assertIsNone(capability_information.rng_mode)

        capability_information.read(
            self.empty_encoding,
            kmip_version=enums.KMIPVersion.KMIP_1_4
        )

        self.assertIsNone(capability_information.streaming_capability)
        self.assertIsNone(capability_information.asynchronous_capability)
        self.assertIsNone(capability_information.attestation_capability)
        self.assertIsNone(capability_information.batch_undo_capability)
        self.assertIsNone(capability_information.batch_continue_capability)
        self.assertIsNone(capability_information.unwrap_mode)
        self.assertIsNone(capability_information.destroy_action)
        self.assertIsNone(capability_information.shredding_algorithm)
        self.assertIsNone(capability_information.rng_mode)

    def test_write(self):
        """
        Test that a CapabilityInformation structure can be written to a data
        stream.
        """
        capability_information = objects.CapabilityInformation(
            streaming_capability=False,
            asynchronous_capability=True,
            attestation_capability=True,
            batch_undo_capability=False,
            batch_continue_capability=True,
            unwrap_mode=enums.UnwrapMode.PROCESSED,
            destroy_action=enums.DestroyAction.SHREDDED,
            shredding_algorithm=enums.ShreddingAlgorithm.CRYPTOGRAPHIC,
            rng_mode=enums.RNGMode.NON_SHARED_INSTANTIATION
        )

        buffer = utils.BytearrayStream()
        capability_information.write(
            buffer,
            kmip_version=enums.KMIPVersion.KMIP_1_4
        )

        self.assertEqual(len(self.full_encoding), len(buffer))
        self.assertEqual(str(self.full_encoding), str(buffer))

    def test_write_unsupported_kmip_version(self):
        """
        Test that a VersionNotSupported error is raised during the encoding of
        a CapabilityInformation structure when the structure is written for an
        unsupported KMIP version.
        """
        capability_information = objects.CapabilityInformation(
            streaming_capability=False,
            asynchronous_capability=True,
            attestation_capability=True,
            batch_undo_capability=False,
            batch_continue_capability=True,
            unwrap_mode=enums.UnwrapMode.PROCESSED,
            destroy_action=enums.DestroyAction.SHREDDED,
            shredding_algorithm=enums.ShreddingAlgorithm.CRYPTOGRAPHIC,
            rng_mode=enums.RNGMode.NON_SHARED_INSTANTIATION
        )

        args = (utils.BytearrayStream(), )
        kwargs = {"kmip_version": enums.KMIPVersion.KMIP_1_2}
        self.assertRaisesRegex(
            exceptions.VersionNotSupported,
            "KMIP 1.2 does not support the CapabilityInformation object.",
            capability_information.write,
            *args,
            **kwargs
        )

    def test_write_kmip_1_3(self):
        """
        Test that a CapabilityInformation structure can be written to a data
        stream with only KMIP 1.3 features.
        """
        capability_information = objects.CapabilityInformation(
            streaming_capability=False,
            asynchronous_capability=True,
            attestation_capability=True,
            batch_undo_capability=False,
            batch_continue_capability=True,
            unwrap_mode=enums.UnwrapMode.PROCESSED,
            destroy_action=enums.DestroyAction.SHREDDED,
            shredding_algorithm=enums.ShreddingAlgorithm.CRYPTOGRAPHIC,
            rng_mode=enums.RNGMode.NON_SHARED_INSTANTIATION
        )

        buffer = utils.BytearrayStream()
        capability_information.write(
            buffer,
            kmip_version=enums.KMIPVersion.KMIP_1_3
        )

        self.assertEqual(len(self.full_encoding_kmip_1_3), len(buffer))
        self.assertEqual(str(self.full_encoding_kmip_1_3), str(buffer))

    def test_write_empty(self):
        """
        Test that an empty CapabilityInformation structure can be correctly
        written to a data stream.
        """
        capability_information = objects.CapabilityInformation()

        buffer = utils.BytearrayStream()
        capability_information.write(
            buffer,
            kmip_version=enums.KMIPVersion.KMIP_1_3
        )

        self.assertEqual(len(self.empty_encoding), len(buffer))
        self.assertEqual(str(self.empty_encoding), str(buffer))

    def test_repr(self):
        """
        Test that repr can be applied to a CapabilityInformation structure.
        """
        capability_information = objects.CapabilityInformation(
            streaming_capability=False,
            asynchronous_capability=True,
            attestation_capability=True,
            batch_undo_capability=False,
            batch_continue_capability=True,
            unwrap_mode=enums.UnwrapMode.PROCESSED,
            destroy_action=enums.DestroyAction.SHREDDED,
            shredding_algorithm=enums.ShreddingAlgorithm.CRYPTOGRAPHIC,
            rng_mode=enums.RNGMode.NON_SHARED_INSTANTIATION
        )

        sc = "streaming_capability=False"
        rc = "asynchronous_capability=True"
        tc = "attestation_capability=True"
        buc = "batch_undo_capability=False"
        bcc = "batch_continue_capability=True"
        um = "unwrap_mode=UnwrapMode.PROCESSED"
        da = "destroy_action=DestroyAction.SHREDDED"
        sa = "shredding_algorithm=ShreddingAlgorithm.CRYPTOGRAPHIC"
        rm = "rng_mode=RNGMode.NON_SHARED_INSTANTIATION"

        v = ", ".join([sc, rc, tc, buc, bcc, um, da, sa, rm])

        self.assertEqual(
            "CapabilityInformation({})".format(v),
            repr(capability_information)
        )

    def test_str(self):
        """
        Test that str can be applied to a CapabilityInformation structure.
        """
        capability_information = objects.CapabilityInformation(
            streaming_capability=False,
            asynchronous_capability=True,
            attestation_capability=True,
            batch_undo_capability=False,
            batch_continue_capability=True,
            unwrap_mode=enums.UnwrapMode.PROCESSED,
            destroy_action=enums.DestroyAction.SHREDDED,
            shredding_algorithm=enums.ShreddingAlgorithm.CRYPTOGRAPHIC,
            rng_mode=enums.RNGMode.NON_SHARED_INSTANTIATION
        )

        sc = '"streaming_capability": False'
        rc = '"asynchronous_capability": True'
        tc = '"attestation_capability": True'
        buc = '"batch_undo_capability": False'
        bcc = '"batch_continue_capability": True'
        um = '"unwrap_mode": UnwrapMode.PROCESSED'
        da = '"destroy_action": DestroyAction.SHREDDED'
        sa = '"shredding_algorithm": ShreddingAlgorithm.CRYPTOGRAPHIC'
        rm = '"rng_mode": RNGMode.NON_SHARED_INSTANTIATION'

        v = ", ".join([sc, rc, tc, buc, bcc, um, da, sa, rm])

        self.assertEqual(
            "{" + v + "}",
            str(capability_information)
        )

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        CapabilityInformation structures with the same data.
        """
        a = objects.CapabilityInformation()
        b = objects.CapabilityInformation()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = objects.CapabilityInformation(
            streaming_capability=False,
            asynchronous_capability=True,
            attestation_capability=True,
            batch_undo_capability=False,
            batch_continue_capability=True,
            unwrap_mode=enums.UnwrapMode.PROCESSED,
            destroy_action=enums.DestroyAction.SHREDDED,
            shredding_algorithm=enums.ShreddingAlgorithm.CRYPTOGRAPHIC,
            rng_mode=enums.RNGMode.NON_SHARED_INSTANTIATION
        )
        b = objects.CapabilityInformation(
            streaming_capability=False,
            asynchronous_capability=True,
            attestation_capability=True,
            batch_undo_capability=False,
            batch_continue_capability=True,
            unwrap_mode=enums.UnwrapMode.PROCESSED,
            destroy_action=enums.DestroyAction.SHREDDED,
            shredding_algorithm=enums.ShreddingAlgorithm.CRYPTOGRAPHIC,
            rng_mode=enums.RNGMode.NON_SHARED_INSTANTIATION
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_streaming_capability(self):
        """
        Test that the equality operator returns False when comparing two
        CapabilityInformation structures with different streaming capability
        fields.
        """
        a = objects.CapabilityInformation(streaming_capability=True)
        b = objects.CapabilityInformation(streaming_capability=False)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_asynchronous_capability(self):
        """
        Test that the equality operator returns False when comparing two
        CapabilityInformation structures with different asynchronous
        capability fields.
        """
        a = objects.CapabilityInformation(asynchronous_capability=True)
        b = objects.CapabilityInformation(asynchronous_capability=False)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_attestation_capability(self):
        """
        Test that the equality operator returns False when comparing two
        CapabilityInformation structures with different attestation capability
        fields.
        """
        a = objects.CapabilityInformation(attestation_capability=True)
        b = objects.CapabilityInformation(attestation_capability=False)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_batch_undo_capability(self):
        """
        Test that the equality operator returns False when comparing two
        CapabilityInformation structures with different batch undo capability
        fields.
        """
        a = objects.CapabilityInformation(batch_undo_capability=True)
        b = objects.CapabilityInformation(batch_undo_capability=False)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_batch_continue_capability(self):
        """
        Test that the equality operator returns False when comparing two
        CapabilityInformation structures with different batch continue
        capability fields.
        """
        a = objects.CapabilityInformation(batch_continue_capability=True)
        b = objects.CapabilityInformation(batch_continue_capability=False)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_unwrap_mode(self):
        """
        Test that the equality operator returns False when comparing two
        CapabilityInformation structures with different unwrap mode fields.
        """
        a = objects.CapabilityInformation(
            unwrap_mode=enums.UnwrapMode.PROCESSED
        )
        b = objects.CapabilityInformation(
            unwrap_mode=enums.UnwrapMode.NOT_PROCESSED
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_destroy_action(self):
        """
        Test that the equality operator returns False when comparing two
        CapabilityInformation structures with different destroy action fields.
        """
        a = objects.CapabilityInformation(
            destroy_action=enums.DestroyAction.DELETED
        )
        b = objects.CapabilityInformation(
            destroy_action=enums.DestroyAction.SHREDDED
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_shredding_algorithm(self):
        """
        Test that the equality operator returns False when comparing two
        CapabilityInformation structures with different shredding algorithm
        fields.
        """
        a = objects.CapabilityInformation(
            shredding_algorithm=enums.ShreddingAlgorithm.UNSPECIFIED
        )
        b = objects.CapabilityInformation(
            shredding_algorithm=enums.ShreddingAlgorithm.UNSUPPORTED
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_rng_mode(self):
        """
        Test that the equality operator returns False when comparing two
        CapabilityInformation structures with different RNG mode fields.
        """
        a = objects.CapabilityInformation(
            rng_mode=enums.RNGMode.SHARED_INSTANTIATION
        )
        b = objects.CapabilityInformation(
            rng_mode=enums.RNGMode.NON_SHARED_INSTANTIATION
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        CapabilityInformation structures with different types.
        """
        a = objects.CapabilityInformation()
        b = "invalid"

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        CapabilityInformation structures with the same data.
        """
        a = objects.CapabilityInformation()
        b = objects.CapabilityInformation()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = objects.CapabilityInformation(
            streaming_capability=False,
            asynchronous_capability=True,
            attestation_capability=True,
            batch_undo_capability=False,
            batch_continue_capability=True,
            unwrap_mode=enums.UnwrapMode.PROCESSED,
            destroy_action=enums.DestroyAction.SHREDDED,
            shredding_algorithm=enums.ShreddingAlgorithm.CRYPTOGRAPHIC,
            rng_mode=enums.RNGMode.NON_SHARED_INSTANTIATION
        )
        b = objects.CapabilityInformation(
            streaming_capability=False,
            asynchronous_capability=True,
            attestation_capability=True,
            batch_undo_capability=False,
            batch_continue_capability=True,
            unwrap_mode=enums.UnwrapMode.PROCESSED,
            destroy_action=enums.DestroyAction.SHREDDED,
            shredding_algorithm=enums.ShreddingAlgorithm.CRYPTOGRAPHIC,
            rng_mode=enums.RNGMode.NON_SHARED_INSTANTIATION
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_streaming_capability(self):
        """
        Test that the inequality operator returns True when comparing two
        CapabilityInformation structures with different streaming capability
        fields.
        """
        a = objects.CapabilityInformation(streaming_capability=True)
        b = objects.CapabilityInformation(streaming_capability=False)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_asynchronous_capability(self):
        """
        Test that the inequality operator returns True when comparing two
        CapabilityInformation structures with different asynchronous
        capability fields.
        """
        a = objects.CapabilityInformation(asynchronous_capability=True)
        b = objects.CapabilityInformation(asynchronous_capability=False)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_attestation_capability(self):
        """
        Test that the inequality operator returns True when comparing two
        CapabilityInformation structures with different attestation capability
        fields.
        """
        a = objects.CapabilityInformation(attestation_capability=True)
        b = objects.CapabilityInformation(attestation_capability=False)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_batch_undo_capability(self):
        """
        Test that the inequality operator returns True when comparing two
        CapabilityInformation structures with different batch undo capability
        fields.
        """
        a = objects.CapabilityInformation(batch_undo_capability=True)
        b = objects.CapabilityInformation(batch_undo_capability=False)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_batch_continue_capability(self):
        """
        Test that the inequality operator returns True when comparing two
        CapabilityInformation structures with different batch continue
        capability fields.
        """
        a = objects.CapabilityInformation(batch_continue_capability=True)
        b = objects.CapabilityInformation(batch_continue_capability=False)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_unwrap_mode(self):
        """
        Test that the inequality operator returns True when comparing two
        CapabilityInformation structures with different unwrap mode fields.
        """
        a = objects.CapabilityInformation(
            unwrap_mode=enums.UnwrapMode.PROCESSED
        )
        b = objects.CapabilityInformation(
            unwrap_mode=enums.UnwrapMode.NOT_PROCESSED
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_destroy_action(self):
        """
        Test that the inequality operator returns True when comparing two
        CapabilityInformation structures with different destroy action fields.
        """
        a = objects.CapabilityInformation(
            destroy_action=enums.DestroyAction.DELETED
        )
        b = objects.CapabilityInformation(
            destroy_action=enums.DestroyAction.SHREDDED
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_shredding_algorithm(self):
        """
        Test that the inequality operator returns True when comparing two
        CapabilityInformation structures with different shredding algorithm
        fields.
        """
        a = objects.CapabilityInformation(
            shredding_algorithm=enums.ShreddingAlgorithm.UNSPECIFIED
        )
        b = objects.CapabilityInformation(
            shredding_algorithm=enums.ShreddingAlgorithm.UNSUPPORTED
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_rng_mode(self):
        """
        Test that the inequality operator returns True when comparing two
        CapabilityInformation structures with different RNG mode fields.
        """
        a = objects.CapabilityInformation(
            rng_mode=enums.RNGMode.SHARED_INSTANTIATION
        )
        b = objects.CapabilityInformation(
            rng_mode=enums.RNGMode.NON_SHARED_INSTANTIATION
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        CapabilityInformation structures with different types.
        """
        a = objects.CapabilityInformation()
        b = "invalid"

        self.assertTrue(a != b)
        self.assertTrue(b != a)

class TestProtectionStorageMasks(testtools.TestCase):

    def setUp(self):
        super(TestProtectionStorageMasks, self).setUp()

        # This encoding matches the following set of values:
        #
        # Protection Storage Masks
        #     Protection Storage Mask - Software | Hardware
        #     Protection Storage Mask - On Premises | Off Premises
        self.full_encoding = utils.BytearrayStream(
            b'\x42\x01\x5F\x01\x00\x00\x00\x20'
            b'\x42\x01\x5E\x02\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x01\x5E\x02\x00\x00\x00\x04\x00\x00\x03\x00\x00\x00\x00\x00'
        )

        # This encoding matches the following set of values:
        #
        # Protection Storage Masks
        self.empty_encoding = utils.BytearrayStream(
            b'\x42\x01\x5F\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestProtectionStorageMasks, self).tearDown()

    def test_invalid_protection_storage_masks(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the protection storage masks of a ProtectionStorageMasks structure.
        """
        kwargs = {"protection_storage_masks": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The protection storage masks must be a list of integers "
            "representing combinations of ProtectionStorageMask enumerations.",
            objects.ProtectionStorageMasks,
            **kwargs
        )
        kwargs = {"protection_storage_masks": ["invalid"]}
        self.assertRaisesRegex(
            TypeError,
            "The protection storage masks must be a list of integers "
            "representing combinations of ProtectionStorageMask enumerations.",
            objects.ProtectionStorageMasks,
            **kwargs
        )
        kwargs = {"protection_storage_masks": [0x10000000]}
        self.assertRaisesRegex(
            TypeError,
            "The protection storage masks must be a list of integers "
            "representing combinations of ProtectionStorageMask enumerations.",
            objects.ProtectionStorageMasks,
            **kwargs
        )

        args = (
            objects.ProtectionStorageMasks(),
            "protection_storage_masks",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The protection storage masks must be a list of integers "
            "representing combinations of ProtectionStorageMask enumerations.",
            setattr,
            *args
        )
        args = (
            objects.ProtectionStorageMasks(),
            "protection_storage_masks",
            ["invalid"]
        )
        self.assertRaisesRegex(
            TypeError,
            "The protection storage masks must be a list of integers "
            "representing combinations of ProtectionStorageMask enumerations.",
            setattr,
            *args
        )
        args = (
            objects.ProtectionStorageMasks(),
            "protection_storage_masks",
            [0x10000000]
        )
        self.assertRaisesRegex(
            TypeError,
            "The protection storage masks must be a list of integers "
            "representing combinations of ProtectionStorageMask enumerations.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a ProtectionStorageMasks structure can be correctly read in
        from a data stream.
        """
        protection_storage_masks = objects.ProtectionStorageMasks()

        self.assertIsNone(protection_storage_masks.protection_storage_masks)

        protection_storage_masks.read(self.full_encoding)

        self.assertEqual(
            [0x03, 0x0300],
            protection_storage_masks.protection_storage_masks
        )

    def test_read_unsupported_kmip_version(self):
        """
        Test that a VersionNotSupported error is raised during the decoding of
        a ProtectionStorageMasks structure when the structure is read for an
        unsupported KMIP version.
        """
        protection_storage_masks = objects.ProtectionStorageMasks()

        args = (self.full_encoding, )
        kwargs = {"kmip_version": enums.KMIPVersion.KMIP_1_2}
        self.assertRaisesRegex(
            exceptions.VersionNotSupported,
            "KMIP 1.2 does not support the ProtectionStorageMasks object.",
            protection_storage_masks.read,
            *args,
            **kwargs
        )

    def test_read_empty(self):
        """
        Test that a ProtectionStorageMasks structure can be correctly read in
        from an empty data stream.
        """
        protection_storage_masks = objects.ProtectionStorageMasks()

        self.assertIsNone(protection_storage_masks.protection_storage_masks)

        protection_storage_masks.read(self.empty_encoding)

        self.assertIsNone(protection_storage_masks.protection_storage_masks)

    def test_write(self):
        """
        Test that a ProtectionStorageMasks structure can be written to a data
        stream.
        """
        protection_storage_masks = objects.ProtectionStorageMasks(
            protection_storage_masks=[
                (
                    enums.ProtectionStorageMask.SOFTWARE.value |
                    enums.ProtectionStorageMask.HARDWARE.value
                ),
                (
                    enums.ProtectionStorageMask.ON_PREMISES.value |
                    enums.ProtectionStorageMask.OFF_PREMISES.value
                )
            ]
        )

        buffer = utils.BytearrayStream()
        protection_storage_masks.write(buffer)

        self.assertEqual(len(self.full_encoding), len(buffer))
        self.assertEqual(str(self.full_encoding), str(buffer))

    def test_write_unsupported_kmip_version(self):
        """
        Test that a VersionNotSupported error is raised during the encoding of
        a ProtectionStorageMasks structure when the structure is written for an
        unsupported KMIP version.
        """
        protection_storage_masks = objects.ProtectionStorageMasks(
            protection_storage_masks=[
                (
                    enums.ProtectionStorageMask.SOFTWARE.value |
                    enums.ProtectionStorageMask.HARDWARE.value
                ),
                (
                    enums.ProtectionStorageMask.ON_PREMISES.value |
                    enums.ProtectionStorageMask.OFF_PREMISES.value
                )
            ]
        )

        args = (utils.BytearrayStream(), )
        kwargs = {"kmip_version": enums.KMIPVersion.KMIP_1_2}
        self.assertRaisesRegex(
            exceptions.VersionNotSupported,
            "KMIP 1.2 does not support the ProtectionStorageMasks object.",
            protection_storage_masks.write,
            *args,
            **kwargs
        )

    def test_write_empty(self):
        """
        Test that an empty ProtectionStorageMasks structure can be correctly
        written to a data stream.
        """
        protection_storage_masks = objects.ProtectionStorageMasks()

        buffer = utils.BytearrayStream()
        protection_storage_masks.write(buffer)

        self.assertEqual(len(self.empty_encoding), len(buffer))
        self.assertEqual(str(self.empty_encoding), str(buffer))

    def test_repr(self):
        """
        Test that repr can be applied to a ProtectionStorageMasks structure.
        """
        protection_storage_masks = objects.ProtectionStorageMasks(
            protection_storage_masks=[
                (
                    enums.ProtectionStorageMask.SOFTWARE.value |
                    enums.ProtectionStorageMask.HARDWARE.value
                ),
                (
                    enums.ProtectionStorageMask.ON_PREMISES.value |
                    enums.ProtectionStorageMask.OFF_PREMISES.value
                )
            ]
        )

        v = "protection_storage_masks=[3, 768]"

        self.assertEqual(
            "ProtectionStorageMasks({})".format(v),
            repr(protection_storage_masks)
        )

    def test_str(self):
        """
        Test that str can be applied to a ProtectionStorageMasks structure.
        """
        protection_storage_masks = objects.ProtectionStorageMasks(
            protection_storage_masks=[
                (
                    enums.ProtectionStorageMask.SOFTWARE.value |
                    enums.ProtectionStorageMask.HARDWARE.value
                ),
                (
                    enums.ProtectionStorageMask.ON_PREMISES.value |
                    enums.ProtectionStorageMask.OFF_PREMISES.value
                )
            ]
        )

        v = '"protection_storage_masks": [3, 768]'

        self.assertEqual(
            "{" + v + "}",
            str(protection_storage_masks)
        )

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        ProtectionStorageMasks structures with the same data.
        """
        a = objects.ProtectionStorageMasks()
        b = objects.ProtectionStorageMasks()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = objects.ProtectionStorageMasks(
            protection_storage_masks=[
                (
                    enums.ProtectionStorageMask.SOFTWARE.value |
                    enums.ProtectionStorageMask.HARDWARE.value
                ),
                (
                    enums.ProtectionStorageMask.ON_PREMISES.value |
                    enums.ProtectionStorageMask.OFF_PREMISES.value
                )
            ]
        )
        b = objects.ProtectionStorageMasks(
            protection_storage_masks=[
                (
                    enums.ProtectionStorageMask.SOFTWARE.value |
                    enums.ProtectionStorageMask.HARDWARE.value
                ),
                (
                    enums.ProtectionStorageMask.ON_PREMISES.value |
                    enums.ProtectionStorageMask.OFF_PREMISES.value
                )
            ]
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_protection_storage_masks(self):
        """
        Test that the equality operator returns False when comparing two
        ProtectionStorageMasks structures with different protection storage
        masks fields.
        """
        a = objects.ProtectionStorageMasks(
            protection_storage_masks=[
                (
                    enums.ProtectionStorageMask.SOFTWARE.value |
                    enums.ProtectionStorageMask.HARDWARE.value
                ),
                (
                    enums.ProtectionStorageMask.ON_PREMISES.value |
                    enums.ProtectionStorageMask.OFF_PREMISES.value
                )
            ]
        )
        b = objects.ProtectionStorageMasks(
            protection_storage_masks=[
                (
                    enums.ProtectionStorageMask.SOFTWARE.value |
                    enums.ProtectionStorageMask.HARDWARE.value
                ),
                (
                    enums.ProtectionStorageMask.ON_PREMISES.value
                )
            ]
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        ProtectionStorageMasks structures with different types.
        """
        a = objects.ProtectionStorageMasks()
        b = "invalid"

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        ProtectionStorageMasks structures with the same data.
        """
        a = objects.ProtectionStorageMasks()
        b = objects.ProtectionStorageMasks()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = objects.ProtectionStorageMasks(
            protection_storage_masks=[
                (
                    enums.ProtectionStorageMask.SOFTWARE.value |
                    enums.ProtectionStorageMask.HARDWARE.value
                ),
                (
                    enums.ProtectionStorageMask.ON_PREMISES.value |
                    enums.ProtectionStorageMask.OFF_PREMISES.value
                )
            ]
        )
        b = objects.ProtectionStorageMasks(
            protection_storage_masks=[
                (
                    enums.ProtectionStorageMask.SOFTWARE.value |
                    enums.ProtectionStorageMask.HARDWARE.value
                ),
                (
                    enums.ProtectionStorageMask.ON_PREMISES.value |
                    enums.ProtectionStorageMask.OFF_PREMISES.value
                )
            ]
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_protection_storage_masks(self):
        """
        Test that the inequality operator returns True when comparing two
        ProtectionStorageMasks structures with different protection storage
        masks fields.
        """
        a = objects.ProtectionStorageMasks(
            protection_storage_masks=[
                (
                    enums.ProtectionStorageMask.SOFTWARE.value |
                    enums.ProtectionStorageMask.HARDWARE.value
                ),
                (
                    enums.ProtectionStorageMask.ON_PREMISES.value |
                    enums.ProtectionStorageMask.OFF_PREMISES.value
                )
            ]
        )
        b = objects.ProtectionStorageMasks(
            protection_storage_masks=[
                (
                    enums.ProtectionStorageMask.SOFTWARE.value |
                    enums.ProtectionStorageMask.HARDWARE.value
                ),
                (
                    enums.ProtectionStorageMask.ON_PREMISES.value
                )
            ]
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        ProtectionStorageMasks structures with different types.
        """
        a = objects.ProtectionStorageMasks()
        b = "invalid"

        self.assertTrue(a != b)
        self.assertTrue(b != a)
