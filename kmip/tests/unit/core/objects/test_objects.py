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

from six import string_types
from testtools import TestCase

from kmip.core.enums import AttributeType
from kmip.core.enums import BlockCipherMode
from kmip.core.enums import HashingAlgorithm as HashingAlgorithmEnum
from kmip.core.enums import KeyRoleType
from kmip.core.enums import PaddingMethod
from kmip.core.enums import Tags

from kmip.core.factories.attributes import AttributeValueFactory

from kmip.core.objects import Attribute
from kmip.core.objects import ExtensionName
from kmip.core.objects import ExtensionTag
from kmip.core.objects import ExtensionType
from kmip.core.objects import KeyMaterialStruct

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
        if (isinstance(value, string_types)) or (value is None):
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
