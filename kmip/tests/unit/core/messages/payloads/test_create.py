# Copyright (c) 2014 The Johns Hopkins University/Applied Physics Laboratory
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

class TestCreateRequestPayload(testtools.TestCase):

    def setUp(self):
        super(TestCreateRequestPayload, self).setUp()

        # Encoding obtained from the KMIP 1.1 testing document,
        # Section 3.1.1.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Object Type - Symmetric Key
        #     Template Attribute
        #         Attribute
        #             Attribute Name - Cryptographic Algorithm
        #             Attribute Value - AES
        #         Attribute
        #             Attribute Name - Cryptographic Length
        #             Attribute Value - 128
        #         Attribute
        #             Attribute Name - Cryptographic Usage Mask
        #             Attribute Value - Encrypt | Decrypt
        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\xC0'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x91\x01\x00\x00\x00\xA8'
            b'\x42\x00\x08\x01\x00\x00\x00\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x17'
            b'\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x41\x6C'
            b'\x67\x6F\x72\x69\x74\x68\x6D\x00'
            b'\x42\x00\x0B\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x08\x01\x00\x00\x00\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x14'
            b'\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x4C\x65'
            b'\x6E\x67\x74\x68\x00\x00\x00\x00'
            b'\x42\x00\x0B\x02\x00\x00\x00\x04\x00\x00\x00\x80\x00\x00\x00\x00'
            b'\x42\x00\x08\x01\x00\x00\x00\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x18'
            b'\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x55\x73'
            b'\x61\x67\x65\x20\x4D\x61\x73\x6B'
            b'\x42\x00\x0B\x02\x00\x00\x00\x04\x00\x00\x00\x0C\x00\x00\x00\x00'
        )

        # Encoding obtained from the KMIP 1.1 testing document,
        # Section 3.1.1, and manually converted into KMIP 2.0 format.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Object Type - Symmetric Key
        #     Attributes
        #         Cryptographic Algorithm - AES
        #         Cryptographic Length - 128
        #         Cryptographic Usage Mask - Encrypt | Decrypt
        #     Protection Storage Masks
        #         Protection Storage Mask - Software | Hardware
        self.full_encoding_with_attributes = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x60'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x01\x25\x01\x00\x00\x00\x30'
            b'\x42\x00\x28\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x2A\x02\x00\x00\x00\x04\x00\x00\x00\x80\x00\x00\x00\x00'
            b'\x42\x00\x2C\x02\x00\x00\x00\x04\x00\x00\x00\x0C\x00\x00\x00\x00'
            b'\x42\x01\x5F\x01\x00\x00\x00\x10'
            b'\x42\x01\x5E\x02\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
        )

        # Encoding obtained from the KMIP 1.1 testing document,
        # Section 3.1.1.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Template Attribute
        #         Attribute
        #             Attribute Name - Cryptographic Algorithm
        #             Attribute Value - AES
        #         Attribute
        #             Attribute Name - Cryptographic Length
        #             Attribute Value - 128
        #         Attribute
        #             Attribute Name - Cryptographic Usage Mask
        #             Attribute Value - Encrypt | Decrypt
        self.no_object_type_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\xB0'
            b'\x42\x00\x91\x01\x00\x00\x00\xA8'
            b'\x42\x00\x08\x01\x00\x00\x00\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x17'
            b'\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x41\x6C'
            b'\x67\x6F\x72\x69\x74\x68\x6D\x00'
            b'\x42\x00\x0B\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x08\x01\x00\x00\x00\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x14'
            b'\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x4C\x65'
            b'\x6E\x67\x74\x68\x00\x00\x00\x00'
            b'\x42\x00\x0B\x02\x00\x00\x00\x04\x00\x00\x00\x80\x00\x00\x00\x00'
            b'\x42\x00\x08\x01\x00\x00\x00\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x18'
            b'\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x55\x73'
            b'\x61\x67\x65\x20\x4D\x61\x73\x6B'
            b'\x42\x00\x0B\x02\x00\x00\x00\x04\x00\x00\x00\x0C\x00\x00\x00\x00'
        )

        # Encoding obtained from the KMIP 1.1 testing document,
        # Section 3.1.1.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Object Type - Symmetric Key
        self.no_template_attribute_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x10'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestCreateRequestPayload, self).tearDown()

    def test_init(self):
        """
        Test that a Create request payload can be constructed with no
        arguments.
        """
        payload = payloads.CreateRequestPayload()
        self.assertIsNone(payload.object_type)
        self.assertIsNone(payload.template_attribute)
        self.assertIsNone(payload.protection_storage_masks)

    def test_init_with_args(self):
        """
        Test that a Create request payload can be constructed with valid
        values.
        """
        payload = payloads.CreateRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.AES,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    )
                ]
            ),
            protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[
                    (
                        enums.ProtectionStorageMask.SOFTWARE.value |
                        enums.ProtectionStorageMask.HARDWARE.value
                    )
                ]
            )
        )

        self.assertEqual(
            enums.ObjectType.SYMMETRIC_KEY,
            payload.object_type
        )
        self.assertIsInstance(
            payload.template_attribute,
            objects.TemplateAttribute
        )
        self.assertIsInstance(
            payload.protection_storage_masks,
            objects.ProtectionStorageMasks
        )

    def test_invalid_object_type(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the object type of a Create request payload.
        """
        kwargs = {'object_type': 'invalid'}
        self.assertRaisesRegex(
            TypeError,
            "Object type must be an ObjectType enumeration.",
            payloads.CreateRequestPayload,
            **kwargs
        )

        args = (
            payloads.CreateRequestPayload(),
            'object_type',
            'invalid'
        )
        self.assertRaisesRegex(
            TypeError,
            "Object type must be an ObjectType enumeration.",
            setattr,
            *args
        )

    def test_invalid_template_attribute(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the template attribute of a Create request payload.
        """
        kwargs = {'template_attribute': 'invalid'}
        self.assertRaisesRegex(
            TypeError,
            "Template attribute must be a TemplateAttribute structure.",
            payloads.CreateRequestPayload,
            **kwargs
        )

        args = (
            payloads.CreateRequestPayload(),
            'template_attribute',
            'invalid'
        )
        self.assertRaisesRegex(
            TypeError,
            "Template attribute must be a TemplateAttribute structure.",
            setattr,
            *args
        )

    def test_invalid_protection_storage_masks(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the protection storage masks of a Create request payload.
        """
        kwargs = {"protection_storage_masks": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The protection storage masks must be a ProtectionStorageMasks "
            "structure.",
            payloads.CreateRequestPayload,
            **kwargs
        )
        kwargs = {
            "protection_storage_masks": objects.ProtectionStorageMasks(
                tag=enums.Tags.COMMON_PROTECTION_STORAGE_MASKS
            )
        }
        self.assertRaisesRegex(
            TypeError,
            "The protection storage masks must be a ProtectionStorageMasks "
            "structure with a ProtectionStorageMasks tag.",
            payloads.CreateRequestPayload,
            **kwargs
        )

        args = (
            payloads.CreateRequestPayload(),
            "protection_storage_masks",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The protection storage masks must be a ProtectionStorageMasks "
            "structure.",
            setattr,
            *args
        )
        args = (
            payloads.CreateRequestPayload(),
            "protection_storage_masks",
            objects.ProtectionStorageMasks(
                tag=enums.Tags.COMMON_PROTECTION_STORAGE_MASKS
            )
        )
        self.assertRaisesRegex(
            TypeError,
            "The protection storage masks must be a ProtectionStorageMasks "
            "structure with a ProtectionStorageMasks tag.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a Create request payload can be read from a data stream.
        """
        payload = payloads.CreateRequestPayload()

        self.assertIsNone(payload.object_type)
        self.assertIsNone(payload.template_attribute)
        self.assertIsNone(payload.protection_storage_masks)

        payload.read(self.full_encoding)

        self.assertEqual(
            enums.ObjectType.SYMMETRIC_KEY,
            payload.object_type
        )
        self.assertEqual(
            objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.AES,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Usage Mask'
                        ),
                        attribute_value=primitives.Integer(
                            value=(
                                enums.CryptographicUsageMask.ENCRYPT.value |
                                enums.CryptographicUsageMask.DECRYPT.value
                            ),
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ]
            ),
            payload.template_attribute
        )
        self.assertIsNone(payload.protection_storage_masks)

    def test_read_kmip_2_0(self):
        """
        Test that a Create request payload can be read from a data stream
        encoded with the KMIP 2.0 format.
        """
        payload = payloads.CreateRequestPayload()

        self.assertIsNone(payload.object_type)
        self.assertIsNone(payload.template_attribute)
        self.assertIsNone(payload.protection_storage_masks)

        payload.read(
            self.full_encoding_with_attributes,
            kmip_version=enums.KMIPVersion.KMIP_2_0
        )

        self.assertEqual(
            enums.ObjectType.SYMMETRIC_KEY,
            payload.object_type
        )
        self.assertEqual(
            objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.AES,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Usage Mask'
                        ),
                        attribute_value=primitives.Integer(
                            value=(
                                enums.CryptographicUsageMask.ENCRYPT.value |
                                enums.CryptographicUsageMask.DECRYPT.value
                            ),
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ]
            ),
            payload.template_attribute
        )
        self.assertEqual(
            objects.ProtectionStorageMasks(protection_storage_masks=[3]),
            payload.protection_storage_masks
        )

    def test_read_missing_object_type(self):
        """
        Test that an InvalidKmipEncoding error is raised during the decoding
        of a Create request payload when the object type is missing from the
        encoding.
        """
        payload = payloads.CreateRequestPayload()

        self.assertIsNone(payload.object_type)
        self.assertIsNone(payload.template_attribute)

        args = (self.no_object_type_encoding, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The Create request payload encoding is missing the object type.",
            payload.read,
            *args
        )

    def test_read_missing_template_attribute(self):
        """
        Test that an InvalidKmipEncoding error is raised during the decoding
        of a Create request payload when the template attribute is missing
        from the encoding.
        """
        payload = payloads.CreateRequestPayload()

        self.assertIsNone(payload.object_type)
        self.assertIsNone(payload.template_attribute)

        args = (self.no_template_attribute_encoding, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The Create request payload encoding is missing the template "
            "attribute.",
            payload.read,
            *args
        )

    def test_read_missing_attributes(self):
        """
        Test that an InvalidKmipEncoding error is raised during the decoding
        of a Create request payload when the attributes structure is missing
        from the encoding.
        """
        payload = payloads.CreateRequestPayload()

        self.assertIsNone(payload.object_type)
        self.assertIsNone(payload.template_attribute)

        args = (self.no_template_attribute_encoding, )
        kwargs = {"kmip_version": enums.KMIPVersion.KMIP_2_0}
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The Create request payload encoding is missing the attributes "
            "structure.",
            payload.read,
            *args,
            **kwargs
        )

    def test_write(self):
        """
        Test that a Create request payload can be written to a data stream.
        """
        payload = payloads.CreateRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.AES,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Usage Mask'
                        ),
                        attribute_value=primitives.Integer(
                            value=(
                                enums.CryptographicUsageMask.ENCRYPT.value |
                                enums.CryptographicUsageMask.DECRYPT.value
                            ),
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ]
            )
        )

        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_kmip_2_0(self):
        """
        Test that a Create request payload can be written to a data stream
        encoded with the KMIP 2.0 format.
        """
        payload = payloads.CreateRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.AES,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Usage Mask'
                        ),
                        attribute_value=primitives.Integer(
                            value=(
                                enums.CryptographicUsageMask.ENCRYPT.value |
                                enums.CryptographicUsageMask.DECRYPT.value
                            ),
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ]
            ),
            protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[
                    (
                        enums.ProtectionStorageMask.SOFTWARE.value |
                        enums.ProtectionStorageMask.HARDWARE.value
                    )
                ]
            )
        )

        stream = utils.BytearrayStream()
        payload.write(stream, kmip_version=enums.KMIPVersion.KMIP_2_0)

        self.assertEqual(len(self.full_encoding_with_attributes), len(stream))
        self.assertEqual(str(self.full_encoding_with_attributes), str(stream))

    def test_write_missing_object_type(self):
        """
        Test that an InvalidField error is raised during the encoding of a
        Create request payload when the payload is missing the object type.
        """
        payload = payloads.CreateRequestPayload(
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.AES,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ]
            )
        )

        stream = utils.BytearrayStream()
        args = (stream, )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The Create request payload is missing the object type field.",
            payload.write,
            *args
        )

    def test_write_missing_template_attribute(self):
        """
        Test that an InvalidField error is raised during the encoding of a
        Create request payload when the payload is missing the template
        attribute.
        """
        payload = payloads.CreateRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY
        )

        stream = utils.BytearrayStream()
        args = (stream, )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The Create request payload is missing the template attribute "
            "field.",
            payload.write,
            *args
        )

    def test_write_missing_attributes(self):
        """
        Test that an InvalidField error is raised during the encoding of a
        Create request payload when the payload is missing the template
        attribute.
        """
        payload = payloads.CreateRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY
        )

        stream = utils.BytearrayStream()
        args = (stream, )
        kwargs = {"kmip_version": enums.KMIPVersion.KMIP_2_0}
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The Create request payload is missing the template attribute "
            "field.",
            payload.write,
            *args,
            **kwargs
        )

    def test_repr(self):
        """
        Test that repr can be applied to a Create request payload structure.
        """
        payload = payloads.CreateRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.AES,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ]
            ),
            protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[
                    (
                        enums.ProtectionStorageMask.SOFTWARE.value |
                        enums.ProtectionStorageMask.HARDWARE.value
                    )
                ]
            )
        )
        self.assertEqual(
            "CreateRequestPayload("
            "object_type=ObjectType.SYMMETRIC_KEY, "
            "template_attribute=Struct(), "
            "protection_storage_masks=ProtectionStorageMasks("
            "protection_storage_masks=[3]))",
            repr(payload)
        )

    def test_str(self):
        """
        Test that str can be applied to a Create request payload structure.
        """
        payload = payloads.CreateRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.AES,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ]
            ),
            protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[
                    (
                        enums.ProtectionStorageMask.SOFTWARE.value |
                        enums.ProtectionStorageMask.HARDWARE.value
                    )
                ]
            )
        )
        self.assertEqual(
            '{'
            '"object_type": ObjectType.SYMMETRIC_KEY, '
            '"template_attribute": Struct(), '
            '"protection_storage_masks": {"protection_storage_masks": [3]}'
            '}',
            str(payload)
        )

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two Create
        request payloads with the same data.
        """
        a = payloads.CreateRequestPayload()
        b = payloads.CreateRequestPayload()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = payloads.CreateRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.AES,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Usage Mask'
                        ),
                        attribute_value=primitives.Integer(
                            value=(
                                enums.CryptographicUsageMask.ENCRYPT.value |
                                enums.CryptographicUsageMask.DECRYPT.value
                            ),
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ]
            ),
            protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[
                    (
                        enums.ProtectionStorageMask.SOFTWARE.value |
                        enums.ProtectionStorageMask.HARDWARE.value
                    )
                ]
            )
        )
        b = payloads.CreateRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.AES,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Usage Mask'
                        ),
                        attribute_value=primitives.Integer(
                            value=(
                                enums.CryptographicUsageMask.ENCRYPT.value |
                                enums.CryptographicUsageMask.DECRYPT.value
                            ),
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ]
            ),
            protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[
                    (
                        enums.ProtectionStorageMask.SOFTWARE.value |
                        enums.ProtectionStorageMask.HARDWARE.value
                    )
                ]
            )
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_object_type(self):
        """
        Test that the equality operator returns False when comparing two Create
        request payloads with different object types.
        """
        a = payloads.CreateRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY
        )
        b = payloads.CreateRequestPayload(
            object_type=enums.ObjectType.SECRET_DATA
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_template_attribute(self):
        """
        Test that the equality operator returns False when comparing two Create
        request payloads with different template attributes.
        """
        a = payloads.CreateRequestPayload(
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.AES,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    )
                ]
            )
        )
        b = payloads.CreateRequestPayload(
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ]
            )
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_protection_storage_masks(self):
        """
        Test that the equality operator returns False when comparing two Create
        request payloads with different protection storage masks.
        """
        a = payloads.CreateRequestPayload(
            protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[
                    (
                        enums.ProtectionStorageMask.SOFTWARE.value |
                        enums.ProtectionStorageMask.HARDWARE.value
                    )
                ]
            )
        )
        b = payloads.CreateRequestPayload(
            protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[
                    (
                        enums.ProtectionStorageMask.ON_SYSTEM.value |
                        enums.ProtectionStorageMask.OFF_SYSTEM.value
                    )
                ]
            )
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two Create
        request payloads with different types.
        """
        a = payloads.CreateRequestPayload()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_read_valid(self):
        """
        Test that a Create request payload can be read from a valid byte
        stream.
        """
        self.test_read()

    def test_read_missing_required_field(self):
        """
        Test that an exception is raised when reading a payload missing a
        required field.
        """
        self.test_read_missing_object_type()

    def test_write_valid(self):
        """
        Test that a Create request payload can be written to a byte stream.
        """
        self.test_write()

    def test_read_write_roundtrip(self):
        """
        Test that a Create request payload can be read and written without
        changing the encoded bytes.
        """
        payload = payloads.CreateRequestPayload()
        payload.read(utils.BytearrayStream(self.full_encoding.buffer))

        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(self.full_encoding, stream)

    def test_validate_invalid(self):
        """
        Test that an exception is raised when a field has an invalid type.
        """
        self.test_invalid_object_type()

    def test_eq(self):
        """
        Test that two Create request payloads with the same data are equal.
        """
        self.test_equal_on_equal()

    def test_ne(self):
        """
        Test that two Create request payloads with different data are not
        equal.
        """
        self.test_not_equal_on_not_equal_object_type()

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        Create request payloads with the same data.
        """
        a = payloads.CreateRequestPayload()
        b = payloads.CreateRequestPayload()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = payloads.CreateRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.AES,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Usage Mask'
                        ),
                        attribute_value=primitives.Integer(
                            value=(
                                enums.CryptographicUsageMask.ENCRYPT.value |
                                enums.CryptographicUsageMask.DECRYPT.value
                            ),
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ]
            ),
            protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[
                    (
                        enums.ProtectionStorageMask.SOFTWARE.value |
                        enums.ProtectionStorageMask.HARDWARE.value
                    )
                ]
            )
        )
        b = payloads.CreateRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.AES,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Usage Mask'
                        ),
                        attribute_value=primitives.Integer(
                            value=(
                                enums.CryptographicUsageMask.ENCRYPT.value |
                                enums.CryptographicUsageMask.DECRYPT.value
                            ),
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ]
            ),
            protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[
                    (
                        enums.ProtectionStorageMask.SOFTWARE.value |
                        enums.ProtectionStorageMask.HARDWARE.value
                    )
                ]
            )
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_object_type(self):
        """
        Test that the inequality operator returns True when comparing two
        Create request payloads with different object types.
        """
        a = payloads.CreateRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY
        )
        b = payloads.CreateRequestPayload(
            object_type=enums.ObjectType.SECRET_DATA
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_template_attribute(self):
        """
        Test that the inequality operator returns True when comparing two
        Create request payloads with different template attributes.
        """
        a = payloads.CreateRequestPayload(
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.AES,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    )
                ]
            )
        )
        b = payloads.CreateRequestPayload(
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ]
            )
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_protection_storage_masks(self):
        """
        Test that the inequality operator returns True when comparing two
        Create request payloads with different protection storage masks.
        """
        a = payloads.CreateRequestPayload(
            protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[
                    (
                        enums.ProtectionStorageMask.SOFTWARE.value |
                        enums.ProtectionStorageMask.HARDWARE.value
                    )
                ]
            )
        )
        b = payloads.CreateRequestPayload(
            protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[
                    (
                        enums.ProtectionStorageMask.ON_SYSTEM.value |
                        enums.ProtectionStorageMask.OFF_SYSTEM.value
                    )
                ]
            )
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        Create request payloads with different types.
        """
        a = payloads.CreateRequestPayload()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)

class TestCreateResponsePayload(testtools.TestCase):

    def setUp(self):
        super(TestCreateResponsePayload, self).setUp()

        # Encoding obtained in part from the KMIP 1.1 testing document,
        # Section 3.1.1. The TemplateAttribute was added manually from the
        # Create request payload encoding.
        #
        # This encoding matches the following set of values:
        # Response Payload
        #     Object Type - Symmetric Key
        #     Unique Identifier - fb4b5b9c-6188-4c63-8142-fe9c328129fc
        #     Template Attribute
        #         Attribute
        #             Attribute Name - State
        #             Attribute Value - PRE_ACTIVE
        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x70'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x66\x62\x34\x62\x35\x62\x39\x63\x2D\x36\x31\x38\x38\x2D\x34\x63'
            b'\x36\x33\x2D\x38\x31\x34\x32\x2D\x66\x65\x39\x63\x33\x32\x38\x31'
            b'\x32\x39\x66\x63\x00\x00\x00\x00'
            b'\x42\x00\x91\x01\x00\x00\x00\x28'
            b'\x42\x00\x08\x01\x00\x00\x00\x20'
            b'\x42\x00\x0A\x07\x00\x00\x00\x05'
            b'\x53\x74\x61\x74\x65\x00\x00\x00'
            b'\x42\x00\x0B\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
        )

        # Encoding obtained in part from the KMIP 1.1 testing document,
        # Section 3.1.1. The TemplateAttribute was added manually from the
        # Create request payload encoding.
        #
        # This encoding matches the following set of values:
        # Response Payload
        #     Unique Identifier - fb4b5b9c-6188-4c63-8142-fe9c328129fc
        #     Template Attribute
        #         Attribute
        #             Attribute Name - State
        #             Attribute Value - PRE_ACTIVE
        self.no_object_type_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x60'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x66\x62\x34\x62\x35\x62\x39\x63\x2D\x36\x31\x38\x38\x2D\x34\x63'
            b'\x36\x33\x2D\x38\x31\x34\x32\x2D\x66\x65\x39\x63\x33\x32\x38\x31'
            b'\x32\x39\x66\x63\x00\x00\x00\x00'
            b'\x42\x00\x91\x01\x00\x00\x00\x28'
            b'\x42\x00\x08\x01\x00\x00\x00\x20'
            b'\x42\x00\x0A\x07\x00\x00\x00\x05'
            b'\x53\x74\x61\x74\x65\x00\x00\x00'
            b'\x42\x00\x0B\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
        )

        # Encoding obtained in part from the KMIP 1.1 testing document,
        # Section 3.1.1. The TemplateAttribute was added manually from the
        # Create request payload encoding.
        #
        # This encoding matches the following set of values:
        # Response Payload
        #     Object Type - Symmetric Key
        #     Template Attribute
        #         Attribute
        #             Attribute Name - State
        #             Attribute Value - PRE_ACTIVE
        self.no_unique_identifier_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x50'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x91\x01\x00\x00\x00\x28'
            b'\x42\x00\x08\x01\x00\x00\x00\x20'
            b'\x42\x00\x0A\x07\x00\x00\x00\x05'
            b'\x53\x74\x61\x74\x65\x00\x00\x00'
            b'\x42\x00\x0B\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
        )

        # Encoding obtained in part from the KMIP 1.1 testing document,
        # Section 3.1.1.
        #
        # This encoding matches the following set of values:
        # Response Payload
        #     Object Type - Symmetric Key
        #     Unique Identifier - fb4b5b9c-6188-4c63-8142-fe9c328129fc
        self.no_template_attribute_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x40'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x66\x62\x34\x62\x35\x62\x39\x63\x2D\x36\x31\x38\x38\x2D\x34\x63'
            b'\x36\x33\x2D\x38\x31\x34\x32\x2D\x66\x65\x39\x63\x33\x32\x38\x31'
            b'\x32\x39\x66\x63\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestCreateResponsePayload, self).tearDown()

    def test_init(self):
        """
        Test that a Create response payload can be constructed with no
        arguments.
        """
        payload = payloads.CreateResponsePayload()
        self.assertIsNone(payload.object_type)
        self.assertIsNone(payload.unique_identifier)
        self.assertIsNone(payload.template_attribute)

    def test_init_with_args(self):
        """
        Test that a Create response payload can be constructed with valid
        values.
        """
        payload = payloads.CreateResponsePayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifier='00000000-1111-2222-3333-444444444444',
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.AES,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    )
                ]
            )
        )

        self.assertEqual(
            enums.ObjectType.SYMMETRIC_KEY,
            payload.object_type
        )
        self.assertEqual(
            '00000000-1111-2222-3333-444444444444',
            payload.unique_identifier
        )
        self.assertIsInstance(
            payload.template_attribute,
            objects.TemplateAttribute
        )

    def test_invalid_object_type(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the object type of a Create response payload.
        """
        kwargs = {'object_type': 'invalid'}
        self.assertRaisesRegex(
            TypeError,
            "Object type must be an ObjectType enumeration.",
            payloads.CreateResponsePayload,
            **kwargs
        )

        args = (
            payloads.CreateResponsePayload(),
            'object_type',
            'invalid'
        )
        self.assertRaisesRegex(
            TypeError,
            "Object type must be an ObjectType enumeration.",
            setattr,
            *args
        )

    def test_invalid_unique_identifier(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the unique identifier of a Create response payload.
        """
        kwargs = {'unique_identifier': 0}
        self.assertRaisesRegex(
            TypeError,
            "Unique identifier must be a string.",
            payloads.CreateResponsePayload,
            **kwargs
        )

        args = (payloads.CreateResponsePayload(), 'unique_identifier', 0)
        self.assertRaisesRegex(
            TypeError,
            "Unique identifier must be a string.",
            setattr,
            *args
        )

    def test_invalid_template_attribute(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the template attribute of a Create response payload.
        """
        kwargs = {'template_attribute': 'invalid'}
        self.assertRaisesRegex(
            TypeError,
            "Template attribute must be a TemplateAttribute structure.",
            payloads.CreateResponsePayload,
            **kwargs
        )

        args = (
            payloads.CreateResponsePayload(),
            'template_attribute',
            'invalid'
        )
        self.assertRaisesRegex(
            TypeError,
            "Template attribute must be a TemplateAttribute structure.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a Create response payload can be read from a data stream.
        """
        payload = payloads.CreateResponsePayload()

        self.assertEqual(None, payload.object_type)
        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.template_attribute)

        payload.read(self.full_encoding)

        self.assertEqual(
            enums.ObjectType.SYMMETRIC_KEY,
            payload.object_type
        )
        self.assertEqual(
            'fb4b5b9c-6188-4c63-8142-fe9c328129fc',
            payload.unique_identifier
        )
        self.assertEqual(
            objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'State'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.State,
                            value=enums.State.PRE_ACTIVE,
                            tag=enums.Tags.STATE
                        )
                    )
                ]
            ),
            payload.template_attribute
        )

    def test_read_kmip_2_0(self):
        """
        Test that a Create response payload can be read from a data stream
        encoded with the KMIP 2.0 format.
        """
        payload = payloads.CreateResponsePayload()

        self.assertIsNone(payload.object_type)
        self.assertIsNone(payload.unique_identifier)
        self.assertIsNone(payload.template_attribute)

        payload.read(
            self.no_template_attribute_encoding,
            kmip_version=enums.KMIPVersion.KMIP_2_0
        )

        self.assertEqual(
            enums.ObjectType.SYMMETRIC_KEY,
            payload.object_type
        )
        self.assertEqual(
            'fb4b5b9c-6188-4c63-8142-fe9c328129fc',
            payload.unique_identifier
        )
        self.assertIsNone(payload.template_attribute)

    def test_read_missing_object_type(self):
        """
        Test that an InvalidKmipEncoding error is raised during the decoding
        of a Create response payload when the object type is missing from the
        encoding.
        """
        payload = payloads.CreateResponsePayload()

        self.assertIsNone(payload.object_type)
        self.assertIsNone(payload.unique_identifier)
        self.assertIsNone(payload.template_attribute)

        args = (self.no_object_type_encoding, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The Create response payload encoding is missing the object type.",
            payload.read,
            *args
        )

    def test_read_missing_unique_identifier(self):
        """
        Test that an InvalidKmipEncoding error is raised during the decoding
        of a Create response payload when the unique identifier is missing
        from the encoding.
        """
        payload = payloads.CreateResponsePayload()

        self.assertIsNone(payload.object_type)
        self.assertIsNone(payload.unique_identifier)
        self.assertIsNone(payload.template_attribute)

        args = (self.no_unique_identifier_encoding, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The Create response payload encoding is missing the unique "
            "identifier.",
            payload.read,
            *args
        )

    def test_read_missing_template_attribute(self):
        """
        Test that a Create response payload can be read from a data stream
        event when missing the template attribute.
        """
        payload = payloads.CreateResponsePayload()

        self.assertEqual(None, payload.object_type)
        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.template_attribute)

        payload.read(self.no_template_attribute_encoding)

        self.assertEqual(
            enums.ObjectType.SYMMETRIC_KEY,
            payload.object_type
        )
        self.assertEqual(
            'fb4b5b9c-6188-4c63-8142-fe9c328129fc',
            payload.unique_identifier
        )
        self.assertIsNone(payload.template_attribute)

    def test_write(self):
        """
        Test that a Create response payload can be written to a data stream.
        """
        payload = payloads.CreateResponsePayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifier="fb4b5b9c-6188-4c63-8142-fe9c328129fc",
            template_attribute=objects.TemplateAttribute(
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
        )

        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_kmip_2_0(self):
        """
        Test that a Create response payload can be written to a data stream
        encoded with the KMIP 2.0 format.
        """
        payload = payloads.CreateResponsePayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifier="fb4b5b9c-6188-4c63-8142-fe9c328129fc",
            template_attribute=objects.TemplateAttribute(
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
        )

        stream = utils.BytearrayStream()
        payload.write(stream, kmip_version=enums.KMIPVersion.KMIP_2_0)

        self.assertEqual(len(self.no_template_attribute_encoding), len(stream))
        self.assertEqual(str(self.no_template_attribute_encoding), str(stream))

    def test_write_missing_object_type(self):
        """
        Test that an InvalidField error is raised during the encoding of a
        Create response payload when the payload is missing the object type.
        """
        payload = payloads.CreateResponsePayload(
            unique_identifier="fb4b5b9c-6188-4c63-8142-fe9c328129fc",
            template_attribute=objects.TemplateAttribute(
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
        )

        stream = utils.BytearrayStream()
        args = (stream, )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The Create response payload is missing the object type field.",
            payload.write,
            *args
        )

    def test_write_missing_unique_identifier(self):
        """
        Test that an InvalidField error is raised during the encoding of a
        Create response payload when the payload is missing the unique
        identifier.
        """
        payload = payloads.CreateResponsePayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            template_attribute=objects.TemplateAttribute(
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
        )

        stream = utils.BytearrayStream()
        args = (stream, )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The Create response payload is missing the unique identifier "
            "field.",
            payload.write,
            *args
        )

    def test_write_missing_template_attribute(self):
        """
        Test that a Create response payload can be written to a data stream
        even when missing the template attribute.
        """
        payload = payloads.CreateResponsePayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifier="fb4b5b9c-6188-4c63-8142-fe9c328129fc"
        )

        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.no_template_attribute_encoding), len(stream))
        self.assertEqual(str(self.no_template_attribute_encoding), str(stream))

    def test_repr(self):
        """
        Test that repr can be applied to a Create response payload structure.
        """
        payload = payloads.CreateResponsePayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifier="fb4b5b9c-6188-4c63-8142-fe9c328129fc",
            template_attribute=objects.TemplateAttribute(
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
        )
        self.assertEqual(
            "CreateResponsePayload("
            "object_type=ObjectType.SYMMETRIC_KEY, "
            "unique_identifier='fb4b5b9c-6188-4c63-8142-fe9c328129fc', "
            "template_attribute=Struct())",
            repr(payload)
        )

    def test_str(self):
        """
        Test that str can be applied to a Create response payload structure.
        """
        payload = payloads.CreateResponsePayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifier="fb4b5b9c-6188-4c63-8142-fe9c328129fc",
            template_attribute=objects.TemplateAttribute(
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
        )
        self.assertEqual(
            '{'
            '"object_type": ObjectType.SYMMETRIC_KEY, '
            '"unique_identifier": "fb4b5b9c-6188-4c63-8142-fe9c328129fc", '
            '"template_attribute": Struct()'
            '}',
            str(payload)
        )

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two Create
        response payloads with the same data.
        """
        a = payloads.CreateResponsePayload()
        b = payloads.CreateResponsePayload()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = payloads.CreateResponsePayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifier="fb4b5b9c-6188-4c63-8142-fe9c328129fc",
            template_attribute=objects.TemplateAttribute(
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
        )
        b = payloads.CreateResponsePayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifier="fb4b5b9c-6188-4c63-8142-fe9c328129fc",
            template_attribute=objects.TemplateAttribute(
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
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_object_type(self):
        """
        Test that the equality operator returns False when comparing two Create
        response payloads with different object types.
        """
        a = payloads.CreateResponsePayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY
        )
        b = payloads.CreateResponsePayload(
            object_type=enums.ObjectType.SECRET_DATA
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_unique_identifier(self):
        """
        Test that the equality operator returns False when comparing two Create
        response payloads with different unique identifiers.
        """
        a = payloads.CreateResponsePayload(unique_identifier="a")
        b = payloads.CreateResponsePayload(unique_identifier="b")

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_template_attribute(self):
        """
        Test that the equality operator returns False when comparing two Create
        response payloads with different template attributes.
        """
        a = payloads.CreateResponsePayload(
            template_attribute=objects.TemplateAttribute(
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
        )
        b = payloads.CreateResponsePayload(
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "State"
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.State,
                            value=enums.State.ACTIVE,
                            tag=enums.Tags.STATE
                        )
                    )
                ]
            )
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two Create
        response payloads with different types.
        """
        a = payloads.CreateResponsePayload()
        b = "invalid"

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        Create response payloads with the same data.
        """
        a = payloads.CreateResponsePayload()
        b = payloads.CreateResponsePayload()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = payloads.CreateResponsePayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifier="fb4b5b9c-6188-4c63-8142-fe9c328129fc",
            template_attribute=objects.TemplateAttribute(
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
        )
        b = payloads.CreateResponsePayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifier="fb4b5b9c-6188-4c63-8142-fe9c328129fc",
            template_attribute=objects.TemplateAttribute(
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
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_object_type(self):
        """
        Test that the inequality operator returns True when comparing two
        Create response payloads with different object types.
        """
        a = payloads.CreateResponsePayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY
        )
        b = payloads.CreateResponsePayload(
            object_type=enums.ObjectType.SECRET_DATA
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_unique_identifier(self):
        """
        Test that the inequality operator returns True when comparing two
        Create response payloads with different unique identifiers.
        """
        a = payloads.CreateResponsePayload(unique_identifier="a")
        b = payloads.CreateResponsePayload(unique_identifier="b")

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_template_attribute(self):
        """
        Test that the inequality operator returns True when comparing two
        Create response payloads with different template attributes.
        """
        a = payloads.CreateResponsePayload(
            template_attribute=objects.TemplateAttribute(
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
        )
        b = payloads.CreateResponsePayload(
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "State"
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.State,
                            value=enums.State.ACTIVE,
                            tag=enums.Tags.STATE
                        )
                    )
                ]
            )
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        Create response payloads with different types.
        """
        a = payloads.CreateResponsePayload()
        b = "invalid"

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_read_valid(self):
        """
        Test that a Create response payload can be read from a valid byte
        stream.
        """
        self.test_read()

    def test_read_missing_required_field(self):
        """
        Test that an exception is raised when reading a payload missing a
        required field.
        """
        self.test_read_missing_object_type()

    def test_write_valid(self):
        """
        Test that a Create response payload can be written to a byte stream.
        """
        self.test_write()

    def test_read_write_roundtrip(self):
        """
        Test that a Create response payload can be read and written without
        changing the encoded bytes.
        """
        payload = payloads.CreateResponsePayload()
        payload.read(utils.BytearrayStream(self.full_encoding.buffer))

        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(self.full_encoding, stream)

    def test_validate_invalid(self):
        """
        Test that an exception is raised when a field has an invalid type.
        """
        self.test_invalid_object_type()

    def test_eq(self):
        """
        Test that two Create response payloads with the same data are equal.
        """
        self.test_equal_on_equal()

    def test_ne(self):
        """
        Test that two Create response payloads with different data are not
        equal.
        """
        self.test_not_equal_on_not_equal_object_type()
