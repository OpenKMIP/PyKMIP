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

from kmip.core.factories.attributes import AttributeValueFactory

from kmip.core import objects
from kmip.core.objects import Attribute
from kmip.core.objects import ExtensionName
from kmip.core.objects import ExtensionTag
from kmip.core.objects import ExtensionType
from kmip.core.objects import KeyMaterialStruct

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
        self.assertRaisesRegexp(
            TypeError,
            "Unique identifier must be a string.",
            objects.EncryptionKeyInformation,
            **kwargs
        )

        encryption_key_information = objects.EncryptionKeyInformation()
        args = (encryption_key_information, 'unique_identifier', 0)
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
            TypeError,
            "Unique identifier must be a string.",
            objects.MACSignatureKeyInformation,
            **kwargs
        )

        args = (objects.MACSignatureKeyInformation(), 'unique_identifier', 0)
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
            TypeError,
            "Wrapping method must be a WrappingMethod enumeration.",
            objects.KeyWrappingData,
            **kwargs
        )

        args = (objects.KeyWrappingData(), 'wrapping_method', 0)
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
            TypeError,
            "Wrapping method must be a WrappingMethod enumeration.",
            objects.KeyWrappingSpecification,
            **kwargs
        )

        args = (objects.KeyWrappingSpecification(), 'wrapping_method', 0)
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
