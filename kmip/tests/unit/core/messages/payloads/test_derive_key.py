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

from kmip.core import attributes
from kmip.core import enums
from kmip.core import exceptions
from kmip.core import objects
from kmip.core import primitives
from kmip.core import utils

from kmip.core.messages import payloads

class TestDeriveKeyRequestPayload(testtools.TestCase):
    """
    Test suite for the DeriveKey request payload.
    """

    def setUp(self):
        super(TestDeriveKeyRequestPayload, self).setUp()

        # Encoding obtained in part from the KMIP 1.1 testing document. The
        # rest of the encoding is a manual construction, since DeriveKey is
        # not specifically detailed by the testing document.
        #
        # This encoding matches the following set of values:
        # Object Type - SymmetricKey
        # Unique Identifiers
        #     fb4b5b9c-6188-4c63-8142-fe9c328129fc
        #     5c9b81ef-4ee5-42cd-ba2d-c002fdd0c7b3
        #     1703250b-4d40-4de2-93a0-c494a1d4ae40
        # Derivation Method - HMAC
        # Derivation Parameters
        #     Cryptographic Parameters
        #         Hashing Algorithm - SHA-256
        #     Initialization Vector - 0x39487432492834A3
        #     Derivation Data - 0xFAD98B6ACA6D87DD
        # Template Attribute
        #     Attribute
        #         Attribute Name - Cryptographic Algorithm
        #         Attribute Value - AES
        #     Attribute
        #         Attribute Name - Cryptographic Length
        #         Attribute Value - 128

        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x01\x68'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x94\x07\x00\x00\x00\x24\x66\x62\x34\x62\x35\x62\x39\x63'
            b'\x2D\x36\x31\x38\x38\x2D\x34\x63\x36\x33\x2D\x38\x31\x34\x32\x2D'
            b'\x66\x65\x39\x63\x33\x32\x38\x31\x32\x39\x66\x63\x00\x00\x00\x00'
            b'\x42\x00\x94\x07\x00\x00\x00\x24\x35\x63\x39\x62\x38\x31\x65\x66'
            b'\x2D\x34\x65\x65\x35\x2D\x34\x32\x63\x64\x2D\x62\x61\x32\x64\x2D'
            b'\x63\x30\x30\x32\x66\x64\x64\x30\x63\x37\x62\x33\x00\x00\x00\x00'
            b'\x42\x00\x94\x07\x00\x00\x00\x24\x31\x37\x30\x33\x32\x35\x30\x62'
            b'\x2D\x34\x64\x34\x30\x2D\x34\x64\x65\x32\x2D\x39\x33\x61\x30\x2D'
            b'\x63\x34\x39\x34\x61\x31\x64\x34\x61\x65\x34\x30\x00\x00\x00\x00'
            b'\x42\x00\x31\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x32\x01\x00\x00\x00\x38'
            b'\x42\x00\x2B\x01\x00\x00\x00\x10'
            b'\x42\x00\x38\x05\x00\x00\x00\x04\x00\x00\x00\x06\x00\x00\x00\x00'
            b'\x42\x00\x3A\x08\x00\x00\x00\x08\x39\x48\x74\x32\x49\x28\x34\xA3'
            b'\x42\x00\x30\x08\x00\x00\x00\x08\xFA\xD9\x8B\x6A\xCA\x6D\x87\xDD'
            b'\x42\x00\x91\x01\x00\x00\x00\x70'
            b'\x42\x00\x08\x01\x00\x00\x00\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x17\x43\x72\x79\x70\x74\x6F\x67\x72'
            b'\x61\x70\x68\x69\x63\x20\x41\x6C\x67\x6F\x72\x69\x74\x68\x6D\x00'
            b'\x42\x00\x0B\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x08\x01\x00\x00\x00\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x14\x43\x72\x79\x70\x74\x6F\x67\x72'
            b'\x61\x70\x68\x69\x63\x20\x4C\x65\x6E\x67\x74\x68\x00\x00\x00\x00'
            b'\x42\x00\x0B\x02\x00\x00\x00\x04\x00\x00\x00\x80\x00\x00\x00\x00'
        )

        # Encoding obtained in part from the KMIP 1.1 testing document. The
        # rest of the encoding is a manual construction, since DeriveKey is
        # not specifically detailed by the testing document. Manually converted
        # to the KMIP 2.0 format.
        #
        # This encoding matches the following set of values:
        # Object Type - SymmetricKey
        # Unique Identifiers
        #     fb4b5b9c-6188-4c63-8142-fe9c328129fc
        #     5c9b81ef-4ee5-42cd-ba2d-c002fdd0c7b3
        #     1703250b-4d40-4de2-93a0-c494a1d4ae40
        # Derivation Method - HMAC
        # Derivation Parameters
        #     Cryptographic Parameters
        #         Hashing Algorithm - SHA-256
        #     Initialization Vector - 0x39487432492834A3
        #     Derivation Data - 0xFAD98B6ACA6D87DD
        # Attributes
        #     Cryptographic Algorithm - AES
        #     Cryptographic Length - 128

        self.full_encoding_with_attributes = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x01\x18'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x94\x07\x00\x00\x00\x24\x66\x62\x34\x62\x35\x62\x39\x63'
            b'\x2D\x36\x31\x38\x38\x2D\x34\x63\x36\x33\x2D\x38\x31\x34\x32\x2D'
            b'\x66\x65\x39\x63\x33\x32\x38\x31\x32\x39\x66\x63\x00\x00\x00\x00'
            b'\x42\x00\x94\x07\x00\x00\x00\x24\x35\x63\x39\x62\x38\x31\x65\x66'
            b'\x2D\x34\x65\x65\x35\x2D\x34\x32\x63\x64\x2D\x62\x61\x32\x64\x2D'
            b'\x63\x30\x30\x32\x66\x64\x64\x30\x63\x37\x62\x33\x00\x00\x00\x00'
            b'\x42\x00\x94\x07\x00\x00\x00\x24\x31\x37\x30\x33\x32\x35\x30\x62'
            b'\x2D\x34\x64\x34\x30\x2D\x34\x64\x65\x32\x2D\x39\x33\x61\x30\x2D'
            b'\x63\x34\x39\x34\x61\x31\x64\x34\x61\x65\x34\x30\x00\x00\x00\x00'
            b'\x42\x00\x31\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x32\x01\x00\x00\x00\x38'
            b'\x42\x00\x2B\x01\x00\x00\x00\x10'
            b'\x42\x00\x38\x05\x00\x00\x00\x04\x00\x00\x00\x06\x00\x00\x00\x00'
            b'\x42\x00\x3A\x08\x00\x00\x00\x08\x39\x48\x74\x32\x49\x28\x34\xA3'
            b'\x42\x00\x30\x08\x00\x00\x00\x08\xFA\xD9\x8B\x6A\xCA\x6D\x87\xDD'
            b'\x42\x01\x25\x01\x00\x00\x00\x20'
            b'\x42\x00\x28\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x2A\x02\x00\x00\x00\x04\x00\x00\x00\x80\x00\x00\x00\x00'
        )

        # All of the following partial encodings are trimmed versions of the
        # above full encoding.

        self.partial_encoding_no_object_type = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x00'
        )
        self.partial_encoding_no_unique_identifiers = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x10'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
        )
        self.partial_encoding_no_derivation_method = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\xA0'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x94\x07\x00\x00\x00\x24\x66\x62\x34\x62\x35\x62\x39\x63'
            b'\x2D\x36\x31\x38\x38\x2D\x34\x63\x36\x33\x2D\x38\x31\x34\x32\x2D'
            b'\x66\x65\x39\x63\x33\x32\x38\x31\x32\x39\x66\x63\x00\x00\x00\x00'
            b'\x42\x00\x94\x07\x00\x00\x00\x24\x35\x63\x39\x62\x38\x31\x65\x66'
            b'\x2D\x34\x65\x65\x35\x2D\x34\x32\x63\x64\x2D\x62\x61\x32\x64\x2D'
            b'\x63\x30\x30\x32\x66\x64\x64\x30\x63\x37\x62\x33\x00\x00\x00\x00'
            b'\x42\x00\x94\x07\x00\x00\x00\x24\x31\x37\x30\x33\x32\x35\x30\x62'
            b'\x2D\x34\x64\x34\x30\x2D\x34\x64\x65\x32\x2D\x39\x33\x61\x30\x2D'
            b'\x63\x34\x39\x34\x61\x31\x64\x34\x61\x65\x34\x30\x00\x00\x00\x00'
        )
        self.partial_encoding_no_derivation_parameters = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\xB0'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x94\x07\x00\x00\x00\x24\x66\x62\x34\x62\x35\x62\x39\x63'
            b'\x2D\x36\x31\x38\x38\x2D\x34\x63\x36\x33\x2D\x38\x31\x34\x32\x2D'
            b'\x66\x65\x39\x63\x33\x32\x38\x31\x32\x39\x66\x63\x00\x00\x00\x00'
            b'\x42\x00\x94\x07\x00\x00\x00\x24\x35\x63\x39\x62\x38\x31\x65\x66'
            b'\x2D\x34\x65\x65\x35\x2D\x34\x32\x63\x64\x2D\x62\x61\x32\x64\x2D'
            b'\x63\x30\x30\x32\x66\x64\x64\x30\x63\x37\x62\x33\x00\x00\x00\x00'
            b'\x42\x00\x94\x07\x00\x00\x00\x24\x31\x37\x30\x33\x32\x35\x30\x62'
            b'\x2D\x34\x64\x34\x30\x2D\x34\x64\x65\x32\x2D\x39\x33\x61\x30\x2D'
            b'\x63\x34\x39\x34\x61\x31\x64\x34\x61\x65\x34\x30\x00\x00\x00\x00'
            b'\x42\x00\x31\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
        )
        self.partial_encoding_no_template_attribute = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\xF0'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x94\x07\x00\x00\x00\x24\x66\x62\x34\x62\x35\x62\x39\x63'
            b'\x2D\x36\x31\x38\x38\x2D\x34\x63\x36\x33\x2D\x38\x31\x34\x32\x2D'
            b'\x66\x65\x39\x63\x33\x32\x38\x31\x32\x39\x66\x63\x00\x00\x00\x00'
            b'\x42\x00\x94\x07\x00\x00\x00\x24\x35\x63\x39\x62\x38\x31\x65\x66'
            b'\x2D\x34\x65\x65\x35\x2D\x34\x32\x63\x64\x2D\x62\x61\x32\x64\x2D'
            b'\x63\x30\x30\x32\x66\x64\x64\x30\x63\x37\x62\x33\x00\x00\x00\x00'
            b'\x42\x00\x94\x07\x00\x00\x00\x24\x31\x37\x30\x33\x32\x35\x30\x62'
            b'\x2D\x34\x64\x34\x30\x2D\x34\x64\x65\x32\x2D\x39\x33\x61\x30\x2D'
            b'\x63\x34\x39\x34\x61\x31\x64\x34\x61\x65\x34\x30\x00\x00\x00\x00'
            b'\x42\x00\x31\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x32\x01\x00\x00\x00\x38'
            b'\x42\x00\x2B\x01\x00\x00\x00\x10'
            b'\x42\x00\x38\x05\x00\x00\x00\x04\x00\x00\x00\x06\x00\x00\x00\x00'
            b'\x42\x00\x3A\x08\x00\x00\x00\x08\x39\x48\x74\x32\x49\x28\x34\xA3'
            b'\x42\x00\x30\x08\x00\x00\x00\x08\xFA\xD9\x8B\x6A\xCA\x6D\x87\xDD'
        )

    def tearDown(self):
        super(TestDeriveKeyRequestPayload, self).tearDown()

    def test_init(self):
        """
        Test that a DeriveKey request payload can be constructed with no
        arguments.
        """
        payload = payloads.DeriveKeyRequestPayload()

        self.assertIsNone(payload.object_type)
        self.assertIsNone(payload.unique_identifiers)
        self.assertIsNone(payload.derivation_method)
        self.assertIsNone(payload.derivation_parameters)
        self.assertIsNone(payload.template_attribute)

    def test_init_with_args(self):
        """
        Test that a DeriveKey request payload can be constructed with valid
        values
        """
        payload = payloads.DeriveKeyRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifiers=["00000000-1111-2222-3333-444444444444"],
            derivation_method=enums.DerivationMethod.HASH,
            derivation_parameters=attributes.DerivationParameters(),
            template_attribute=objects.TemplateAttribute()
        )

        self.assertEqual(
            enums.ObjectType.SYMMETRIC_KEY,
            payload.object_type
        )
        self.assertEqual(
            ["00000000-1111-2222-3333-444444444444"],
            payload.unique_identifiers
        )
        self.assertEqual(
            enums.DerivationMethod.HASH,
            payload.derivation_method
        )
        self.assertEqual(
            attributes.DerivationParameters(),
            payload.derivation_parameters
        )
        self.assertEqual(
            objects.TemplateAttribute(),
            payload.template_attribute
        )

    def test_invalid_object_type(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the object type of a DeriveKey request payload.
        """
        payload = payloads.DeriveKeyRequestPayload()
        args = (payload, "object_type", "invalid")
        self.assertRaisesRegex(
            TypeError,
            "Object type must be an ObjectType enumeration.",
            setattr,
            *args
        )

    def test_invalid_unique_identifiers(self):
        """
        Test that a TypeError is raised when invalid values are used to set
        the unique identifiers of a DeriveKey request payload.
        """
        payload = payloads.DeriveKeyRequestPayload()
        args = (payload, "unique_identifiers", "invalid")
        self.assertRaisesRegex(
            TypeError,
            "Unique identifiers must be a list of strings.",
            setattr,
            *args
        )

        args = (payload, "unique_identifiers", [0])
        self.assertRaisesRegex(
            TypeError,
            "Unique identifiers must be a list of strings.",
            setattr,
            *args
        )

        args = (payload, "unique_identifiers", ["valid", "valid", 0])
        self.assertRaisesRegex(
            TypeError,
            "Unique identifiers must be a list of strings.",
            setattr,
            *args
        )

    def test_invalid_derivation_method(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the derivation method of a DeriveKey request payload.
        """
        payload = payloads.DeriveKeyRequestPayload()
        args = (payload, "derivation_method", "invalid")
        self.assertRaisesRegex(
            TypeError,
            "Derivation method must be a DerivationMethod enumeration.",
            setattr,
            *args
        )

    def test_invalid_derivation_parameters(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the derivation parameters of a DeriveKey request payload.
        """
        payload = payloads.DeriveKeyRequestPayload()
        args = (payload, "derivation_parameters", "invalid")
        self.assertRaisesRegex(
            TypeError,
            "Derivation parameters must be a DerivationParameters structure.",
            setattr,
            *args
        )

    def test_invalid_template_attribute(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the template attribute of a DeriveKey request payload.
        """
        payload = payloads.DeriveKeyRequestPayload()
        args = (payload, "template_attribute", "invalid")
        self.assertRaisesRegex(
            TypeError,
            "Template attribute must be a TemplateAttribute structure.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a DeriveKey request payload can be read from a data stream.
        """
        payload = payloads.DeriveKeyRequestPayload()

        self.assertIsNone(payload.object_type)
        self.assertIsNone(payload.unique_identifiers)
        self.assertIsNone(payload.derivation_method)
        self.assertIsNone(payload.derivation_parameters)
        self.assertIsNone(payload.template_attribute)

        payload.read(self.full_encoding)

        self.assertEqual(enums.ObjectType.SYMMETRIC_KEY, payload.object_type)
        self.assertEqual(
            [
                "fb4b5b9c-6188-4c63-8142-fe9c328129fc",
                "5c9b81ef-4ee5-42cd-ba2d-c002fdd0c7b3",
                "1703250b-4d40-4de2-93a0-c494a1d4ae40"
            ],
            payload.unique_identifiers
        )
        self.assertEqual(
            enums.DerivationMethod.HASH,
            payload.derivation_method
        )
        self.assertEqual(
            attributes.DerivationParameters(
                cryptographic_parameters=attributes.CryptographicParameters(
                    hashing_algorithm=enums.HashingAlgorithm.SHA_256
                ),
                initialization_vector=b'\x39\x48\x74\x32\x49\x28\x34\xA3',
                derivation_data=b'\xFA\xD9\x8B\x6A\xCA\x6D\x87\xDD'
            ),
            payload.derivation_parameters
        )
        self.assertEqual(
            objects.TemplateAttribute(
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
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Length"
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ]
            ),
            payload.template_attribute
        )

    def test_read_kmip_2_0(self):
        """
        Test that a DeriveKey request payload can be read from a data stream
        encoded with the KMIP 2.0 format.
        """
        payload = payloads.DeriveKeyRequestPayload()

        payload.read(
            self.full_encoding_with_attributes,
            kmip_version=enums.KMIPVersion.KMIP_2_0
        )

        self.assertEqual(enums.ObjectType.SYMMETRIC_KEY, payload.object_type)
        self.assertEqual(
            [
                "fb4b5b9c-6188-4c63-8142-fe9c328129fc",
                "5c9b81ef-4ee5-42cd-ba2d-c002fdd0c7b3",
                "1703250b-4d40-4de2-93a0-c494a1d4ae40"
            ],
            payload.unique_identifiers
        )
        self.assertEqual(
            enums.DerivationMethod.HASH,
            payload.derivation_method
        )
        self.assertEqual(
            attributes.DerivationParameters(
                cryptographic_parameters=attributes.CryptographicParameters(
                    hashing_algorithm=enums.HashingAlgorithm.SHA_256
                ),
                initialization_vector=b'\x39\x48\x74\x32\x49\x28\x34\xA3',
                derivation_data=b'\xFA\xD9\x8B\x6A\xCA\x6D\x87\xDD'
            ),
            payload.derivation_parameters
        )
        self.assertEqual(
            objects.TemplateAttribute(
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
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Length"
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ]
            ),
            payload.template_attribute
        )

    def test_read_missing_object_type(self):
        """
        Test that an InvalidKmipEncoding error gets raised when decoding a
        DeriveKey request payload encoding missing the object type.
        """
        payload = payloads.DeriveKeyRequestPayload()

        args = (self.partial_encoding_no_object_type, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The DeriveKey request payload encoding is missing the object "
            "type.",
            payload.read,
            *args
        )

    def test_read_missing_unique_identifiers(self):
        """
        Test that a ValueError gets raised when decoding a DeriveKey request
        payload encoding missing the unique identifiers.
        """
        payload = payloads.DeriveKeyRequestPayload()

        args = (self.partial_encoding_no_unique_identifiers, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The DeriveKey request payload encoding is missing the unique "
            "identifiers",
            payload.read,
            *args
        )

    def test_read_missing_derivation_method(self):
        """
        Test that an InvalidKmipEncoding error gets raised when decoding a
        DeriveKey request payload encoding missing the derivation method.
        """
        payload = payloads.DeriveKeyRequestPayload()

        args = (self.partial_encoding_no_derivation_method, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The DeriveKey request payload encoding is missing the derivation "
            "method.",
            payload.read,
            *args
        )

    def test_read_missing_derivation_parameters(self):
        """
        Test that an InvalidKmipEncoding error gets raised when decoding a
        DeriveKey request payload encoding missing the derivation parameters.
        """
        payload = payloads.DeriveKeyRequestPayload()

        args = (self.partial_encoding_no_derivation_parameters, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The DeriveKey request payload encoding is missing the derivation "
            "parameters.",
            payload.read,
            *args
        )

    def test_read_missing_template_attribute(self):
        """
        Test that an InvalidKmipEncoding error gets raised when decoding a
        DeriveKey request payload encoding missing the template attribute.
        """
        payload = payloads.DeriveKeyRequestPayload()

        args = (self.partial_encoding_no_template_attribute, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The DeriveKey request payload encoding is missing the template "
            "attribute.",
            payload.read,
            *args
        )

    def test_read_missing_attributes(self):
        """
        Test that an InvalidKmipEncoding error is raised during the decoding
        of a DeriveKey request payload when the attributes structure is missing
        from the encoding.
        """
        payload = payloads.DeriveKeyRequestPayload()

        args = (self.partial_encoding_no_template_attribute, )
        kwargs = {"kmip_version": enums.KMIPVersion.KMIP_2_0}
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The DeriveKey request payload encoding is missing the attributes "
            "structure.",
            payload.read,
            *args,
            **kwargs
        )

    def test_write(self):
        """
        Test that a DeriveKey request payload can be written to a data stream.
        """
        payload = payloads.DeriveKeyRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifiers=[
                "fb4b5b9c-6188-4c63-8142-fe9c328129fc",
                "5c9b81ef-4ee5-42cd-ba2d-c002fdd0c7b3",
                "1703250b-4d40-4de2-93a0-c494a1d4ae40"
            ],
            derivation_method=enums.DerivationMethod.HASH,
            derivation_parameters=attributes.DerivationParameters(
                cryptographic_parameters=attributes.CryptographicParameters(
                    hashing_algorithm=enums.HashingAlgorithm.SHA_256
                ),
                initialization_vector=b'\x39\x48\x74\x32\x49\x28\x34\xA3',
                derivation_data=b'\xFA\xD9\x8B\x6A\xCA\x6D\x87\xDD'
            ),
            template_attribute=objects.TemplateAttribute(
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
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Length"
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
        payload.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_kmip_2_0(self):
        """
        Test that a DeriveKey request payload can be written to a data stream
        encoded with the KMIP 2.0 format.
        """
        payload = payloads.DeriveKeyRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifiers=[
                "fb4b5b9c-6188-4c63-8142-fe9c328129fc",
                "5c9b81ef-4ee5-42cd-ba2d-c002fdd0c7b3",
                "1703250b-4d40-4de2-93a0-c494a1d4ae40"
            ],
            derivation_method=enums.DerivationMethod.HASH,
            derivation_parameters=attributes.DerivationParameters(
                cryptographic_parameters=attributes.CryptographicParameters(
                    hashing_algorithm=enums.HashingAlgorithm.SHA_256
                ),
                initialization_vector=b'\x39\x48\x74\x32\x49\x28\x34\xA3',
                derivation_data=b'\xFA\xD9\x8B\x6A\xCA\x6D\x87\xDD'
            ),
            template_attribute=objects.TemplateAttribute(
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
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Length"
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
        payload.write(stream, kmip_version=enums.KMIPVersion.KMIP_2_0)

        self.assertEqual(len(self.full_encoding_with_attributes), len(stream))
        self.assertEqual(str(self.full_encoding_with_attributes), str(stream))

    def test_write_missing_object_type(self):
        """
        Test that an InvalidField error gets raised when encoding a DeriveKey
        request payload missing the object type.
        """
        payload = payloads.DeriveKeyRequestPayload()

        args = (utils.BytearrayStream(), )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The DeriveKey request payload is missing the object type field.",
            payload.write,
            *args
        )

    def test_write_missing_unique_identifiers(self):
        """
        Test that an InvalidField error gets raised when encoding a DeriveKey
        request payload missing the unique identifiers.
        """
        payload = payloads.DeriveKeyRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY
        )

        args = (utils.BytearrayStream(), )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The DeriveKey request payload is missing the unique identifiers.",
            payload.write,
            *args
        )

    def test_write_missing_derivation_method(self):
        """
        Test that an InvalidField error gets raised when encoding a DeriveKey
        request payload missing the derivation method.
        """
        payload = payloads.DeriveKeyRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifiers=[
                "fb4b5b9c-6188-4c63-8142-fe9c328129fc",
                "5c9b81ef-4ee5-42cd-ba2d-c002fdd0c7b3",
                "1703250b-4d40-4de2-93a0-c494a1d4ae40"
            ]
        )

        args = (utils.BytearrayStream(), )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The DeriveKey request payload is missing the derivation method.",
            payload.write,
            *args
        )

    def test_write_missing_derivation_parameters(self):
        """
        Test that an InvalidField error gets raised when encoding a DeriveKey
        request payload missing the derivation parameters.
        """
        payload = payloads.DeriveKeyRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifiers=[
                "fb4b5b9c-6188-4c63-8142-fe9c328129fc",
                "5c9b81ef-4ee5-42cd-ba2d-c002fdd0c7b3",
                "1703250b-4d40-4de2-93a0-c494a1d4ae40"
            ],
            derivation_method=enums.DerivationMethod.HASH
        )

        args = (utils.BytearrayStream(), )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The DeriveKey request payload is missing the derivation "
            "parameters.",
            payload.write,
            *args
        )

    def test_write_missing_template_attribute(self):
        """
        Test that an InvalidField error gets raised when encoding a DeriveKey
        request payload missing the template attribute.
        """
        payload = payloads.DeriveKeyRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifiers=[
                "fb4b5b9c-6188-4c63-8142-fe9c328129fc",
                "5c9b81ef-4ee5-42cd-ba2d-c002fdd0c7b3",
                "1703250b-4d40-4de2-93a0-c494a1d4ae40"
            ],
            derivation_method=enums.DerivationMethod.HASH,
            derivation_parameters=attributes.DerivationParameters(
                cryptographic_parameters=attributes.CryptographicParameters(
                    hashing_algorithm=enums.HashingAlgorithm.SHA_256
                ),
                initialization_vector=b'\x39\x48\x74\x32\x49\x28\x34\xA3',
                derivation_data=b'\xFA\xD9\x8B\x6A\xCA\x6D\x87\xDD'
            )
        )

        args = (utils.BytearrayStream(), )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The DeriveKey request payload is missing the template attribute.",
            payload.write,
            *args
        )

    def test_write_missing_attributes(self):
        """
        Test that an InvalidField error gets raised when encoding a DeriveKey
        request payload missing the template attribute.
        """
        payload = payloads.DeriveKeyRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifiers=[
                "fb4b5b9c-6188-4c63-8142-fe9c328129fc",
                "5c9b81ef-4ee5-42cd-ba2d-c002fdd0c7b3",
                "1703250b-4d40-4de2-93a0-c494a1d4ae40"
            ],
            derivation_method=enums.DerivationMethod.HASH,
            derivation_parameters=attributes.DerivationParameters(
                cryptographic_parameters=attributes.CryptographicParameters(
                    hashing_algorithm=enums.HashingAlgorithm.SHA_256
                ),
                initialization_vector=b'\x39\x48\x74\x32\x49\x28\x34\xA3',
                derivation_data=b'\xFA\xD9\x8B\x6A\xCA\x6D\x87\xDD'
            )
        )

        args = (utils.BytearrayStream(), )
        kwargs = {"kmip_version": enums.KMIPVersion.KMIP_2_0}
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The DeriveKey request payload is missing the template attribute "
            "field.",
            payload.write,
            *args,
            **kwargs
        )

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        DeriveKey request payloads with the same data.
        """
        a = payloads.DeriveKeyRequestPayload()
        b = payloads.DeriveKeyRequestPayload()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = payloads.DeriveKeyRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifiers=[
                "fb4b5b9c-6188-4c63-8142-fe9c328129fc",
                "5c9b81ef-4ee5-42cd-ba2d-c002fdd0c7b3",
                "1703250b-4d40-4de2-93a0-c494a1d4ae40"
            ],
            derivation_method=enums.DerivationMethod.HASH,
            derivation_parameters=attributes.DerivationParameters(
                cryptographic_parameters=attributes.CryptographicParameters(
                    hashing_algorithm=enums.HashingAlgorithm.SHA_256
                ),
                initialization_vector=b'\x39\x48\x74\x32\x49\x28\x34\xA3',
                derivation_data=b'\xFA\xD9\x8B\x6A\xCA\x6D\x87\xDD'
            ),
            template_attribute=objects.TemplateAttribute(
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
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Length"
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ]
            )
        )
        b = payloads.DeriveKeyRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifiers=[
                "fb4b5b9c-6188-4c63-8142-fe9c328129fc",
                "5c9b81ef-4ee5-42cd-ba2d-c002fdd0c7b3",
                "1703250b-4d40-4de2-93a0-c494a1d4ae40"
            ],
            derivation_method=enums.DerivationMethod.HASH,
            derivation_parameters=attributes.DerivationParameters(
                cryptographic_parameters=attributes.CryptographicParameters(
                    hashing_algorithm=enums.HashingAlgorithm.SHA_256
                ),
                initialization_vector=b'\x39\x48\x74\x32\x49\x28\x34\xA3',
                derivation_data=b'\xFA\xD9\x8B\x6A\xCA\x6D\x87\xDD'
            ),
            template_attribute=objects.TemplateAttribute(
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
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Length"
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ]
            )
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_object_type(self):
        """
        Test that the equality operator returns False when comparing two
        DeriveKey request payloads with different object types.
        """
        a = payloads.DeriveKeyRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY
        )
        b = payloads.DeriveKeyRequestPayload(
            object_type=enums.ObjectType.SECRET_DATA
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_unique_identifiers(self):
        """
        Test that the equality operator returns False when comparing two
        DeriveKey request payloads with different sets of unique identifiers.
        """
        a = payloads.DeriveKeyRequestPayload(
            unique_identifiers=["fb4b5b9c-6188-4c63-8142-fe9c328129fc"]
        )
        b = payloads.DeriveKeyRequestPayload(
            unique_identifiers=["5c9b81ef-4ee5-42cd-ba2d-c002fdd0c7b3"]
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

        a = payloads.DeriveKeyRequestPayload(
            unique_identifiers=[
                "fb4b5b9c-6188-4c63-8142-fe9c328129fc",
                "5c9b81ef-4ee5-42cd-ba2d-c002fdd0c7b3",
                "1703250b-4d40-4de2-93a0-c494a1d4ae40"
            ]
        )
        b = payloads.DeriveKeyRequestPayload(
            unique_identifiers=[
                "1703250b-4d40-4de2-93a0-c494a1d4ae40",
                "5c9b81ef-4ee5-42cd-ba2d-c002fdd0c7b3",
                "fb4b5b9c-6188-4c63-8142-fe9c328129fc"
            ]
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

        a = payloads.DeriveKeyRequestPayload(
            unique_identifiers=[
                "fb4b5b9c-6188-4c63-8142-fe9c328129fc",
                "5c9b81ef-4ee5-42cd-ba2d-c002fdd0c7b3",
                "1703250b-4d40-4de2-93a0-c494a1d4ae40"
            ]
        )
        b = payloads.DeriveKeyRequestPayload(unique_identifiers=[])

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_derivation_method(self):
        """
        Test that the equality operator returns False when comparing two
        DeriveKey request payloads with different derivation methods.
        """
        a = payloads.DeriveKeyRequestPayload(
            derivation_method=enums.DerivationMethod.HASH
        )
        b = payloads.DeriveKeyRequestPayload(
            derivation_method=enums.DerivationMethod.PBKDF2
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_derivation_parameters(self):
        """
        Test that the equality operator returns False when comparing two
        DeriveKey request payloads with different derivation parameters.
        """
        a = payloads.DeriveKeyRequestPayload(
            derivation_parameters=attributes.DerivationParameters(
                cryptographic_parameters=attributes.CryptographicParameters(
                    hashing_algorithm=enums.HashingAlgorithm.SHA_256
                ),
                initialization_vector=b'\x39\x48\x74\x32\x49\x28\x34\xA3',
                derivation_data=b'\xFA\xD9\x8B\x6A\xCA\x6D\x87\xDD'
            )
        )
        b = payloads.DeriveKeyRequestPayload(
            derivation_parameters=attributes.DerivationParameters(
                cryptographic_parameters=attributes.CryptographicParameters(
                    hashing_algorithm=enums.HashingAlgorithm.SHA_1
                ),
                initialization_vector=b'\xFA\xD9\x8B\x6A\xCA\x6D\x87\xDD',
                derivation_data=b'\x39\x48\x74\x32\x49\x28\x34\xA3'
            )
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

        a = payloads.DeriveKeyRequestPayload(
            derivation_parameters=attributes.DerivationParameters(
                cryptographic_parameters=attributes.CryptographicParameters(
                    hashing_algorithm=enums.HashingAlgorithm.SHA_256
                ),
                initialization_vector=b'\x39\x48\x74\x32\x49\x28\x34\xA3',
                derivation_data=b'\xFA\xD9\x8B\x6A\xCA\x6D\x87\xDD'
            )
        )
        b = payloads.DeriveKeyRequestPayload(
            derivation_parameters=attributes.DerivationParameters()
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

        a = payloads.DeriveKeyRequestPayload(derivation_parameters=None)
        b = payloads.DeriveKeyRequestPayload(
            derivation_parameters=attributes.DerivationParameters(
                cryptographic_parameters=attributes.CryptographicParameters(
                    hashing_algorithm=enums.HashingAlgorithm.SHA_256
                ),
                initialization_vector=b'\x39\x48\x74\x32\x49\x28\x34\xA3',
                derivation_data=b'\xFA\xD9\x8B\x6A\xCA\x6D\x87\xDD'
            )
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_template_attribute(self):
        """
        Test that the equality operator returns False when comparing two
        DeriveKey request payloads with different template attributes.
        """
        a = payloads.DeriveKeyRequestPayload(
            template_attribute=objects.TemplateAttribute(
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
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Length"
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ]
            )
        )
        b = payloads.DeriveKeyRequestPayload(
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Algorithm"
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.BLOWFISH,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Length"
                        ),
                        attribute_value=primitives.Integer(
                            value=64,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ]
            )
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

        a = payloads.DeriveKeyRequestPayload(
            template_attribute=objects.TemplateAttribute(
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
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Length"
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ]
            )
        )
        b = payloads.DeriveKeyRequestPayload(
            template_attribute=objects.TemplateAttribute()
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

        a = payloads.DeriveKeyRequestPayload(template_attribute=None)
        b = payloads.DeriveKeyRequestPayload(
            template_attribute=objects.TemplateAttribute(
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
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Length"
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

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        DeriveKey request payloads with different types.
        """
        a = payloads.DeriveKeyRequestPayload()
        b = "invalid"

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        DeriveKey request payloads with the same data.
        """
        a = payloads.DeriveKeyRequestPayload()
        b = payloads.DeriveKeyRequestPayload()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = payloads.DeriveKeyRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifiers=[
                "fb4b5b9c-6188-4c63-8142-fe9c328129fc",
                "5c9b81ef-4ee5-42cd-ba2d-c002fdd0c7b3",
                "1703250b-4d40-4de2-93a0-c494a1d4ae40"
            ],
            derivation_method=enums.DerivationMethod.HASH,
            derivation_parameters=attributes.DerivationParameters(
                cryptographic_parameters=attributes.CryptographicParameters(
                    hashing_algorithm=enums.HashingAlgorithm.SHA_256
                ),
                initialization_vector=b'\x39\x48\x74\x32\x49\x28\x34\xA3',
                derivation_data=b'\xFA\xD9\x8B\x6A\xCA\x6D\x87\xDD'
            ),
            template_attribute=objects.TemplateAttribute(
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
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Length"
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ]
            )
        )
        b = payloads.DeriveKeyRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifiers=[
                "fb4b5b9c-6188-4c63-8142-fe9c328129fc",
                "5c9b81ef-4ee5-42cd-ba2d-c002fdd0c7b3",
                "1703250b-4d40-4de2-93a0-c494a1d4ae40"
            ],
            derivation_method=enums.DerivationMethod.HASH,
            derivation_parameters=attributes.DerivationParameters(
                cryptographic_parameters=attributes.CryptographicParameters(
                    hashing_algorithm=enums.HashingAlgorithm.SHA_256
                ),
                initialization_vector=b'\x39\x48\x74\x32\x49\x28\x34\xA3',
                derivation_data=b'\xFA\xD9\x8B\x6A\xCA\x6D\x87\xDD'
            ),
            template_attribute=objects.TemplateAttribute(
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
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Length"
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
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
        DeriveKey request payloads with different object types.
        """
        a = payloads.DeriveKeyRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY
        )
        b = payloads.DeriveKeyRequestPayload(
            object_type=enums.ObjectType.SECRET_DATA
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_unique_identifiers(self):
        """
        Test that the inequality operator returns True when comparing two
        DeriveKey request payloads with different sets of unique identifiers.
        """
        a = payloads.DeriveKeyRequestPayload(
            unique_identifiers=["fb4b5b9c-6188-4c63-8142-fe9c328129fc"]
        )
        b = payloads.DeriveKeyRequestPayload(
            unique_identifiers=["5c9b81ef-4ee5-42cd-ba2d-c002fdd0c7b3"]
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

        a = payloads.DeriveKeyRequestPayload(
            unique_identifiers=[
                "fb4b5b9c-6188-4c63-8142-fe9c328129fc",
                "5c9b81ef-4ee5-42cd-ba2d-c002fdd0c7b3",
                "1703250b-4d40-4de2-93a0-c494a1d4ae40"
            ]
        )
        b = payloads.DeriveKeyRequestPayload(
            unique_identifiers=[
                "1703250b-4d40-4de2-93a0-c494a1d4ae40",
                "5c9b81ef-4ee5-42cd-ba2d-c002fdd0c7b3",
                "fb4b5b9c-6188-4c63-8142-fe9c328129fc"
            ]
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

        a = payloads.DeriveKeyRequestPayload(
            unique_identifiers=[
                "fb4b5b9c-6188-4c63-8142-fe9c328129fc",
                "5c9b81ef-4ee5-42cd-ba2d-c002fdd0c7b3",
                "1703250b-4d40-4de2-93a0-c494a1d4ae40"
            ]
        )
        b = payloads.DeriveKeyRequestPayload(unique_identifiers=[])

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_derivation_method(self):
        """
        Test that the inequality operator returns True when comparing two
        DeriveKey request payloads with different derivation methods.
        """
        a = payloads.DeriveKeyRequestPayload(
            derivation_method=enums.DerivationMethod.HASH
        )
        b = payloads.DeriveKeyRequestPayload(
            derivation_method=enums.DerivationMethod.PBKDF2
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_derivation_parameters(self):
        """
        Test that the inequality operator returns True when comparing two
        DeriveKey request payloads with different derivation parameters.
        """
        a = payloads.DeriveKeyRequestPayload(
            derivation_parameters=attributes.DerivationParameters(
                cryptographic_parameters=attributes.CryptographicParameters(
                    hashing_algorithm=enums.HashingAlgorithm.SHA_256
                ),
                initialization_vector=b'\x39\x48\x74\x32\x49\x28\x34\xA3',
                derivation_data=b'\xFA\xD9\x8B\x6A\xCA\x6D\x87\xDD'
            )
        )
        b = payloads.DeriveKeyRequestPayload(
            derivation_parameters=attributes.DerivationParameters(
                cryptographic_parameters=attributes.CryptographicParameters(
                    hashing_algorithm=enums.HashingAlgorithm.SHA_1
                ),
                initialization_vector=b'\xFA\xD9\x8B\x6A\xCA\x6D\x87\xDD',
                derivation_data=b'\x39\x48\x74\x32\x49\x28\x34\xA3'
            )
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

        a = payloads.DeriveKeyRequestPayload(
            derivation_parameters=attributes.DerivationParameters(
                cryptographic_parameters=attributes.CryptographicParameters(
                    hashing_algorithm=enums.HashingAlgorithm.SHA_256
                ),
                initialization_vector=b'\x39\x48\x74\x32\x49\x28\x34\xA3',
                derivation_data=b'\xFA\xD9\x8B\x6A\xCA\x6D\x87\xDD'
            )
        )
        b = payloads.DeriveKeyRequestPayload(
            derivation_parameters=attributes.DerivationParameters()
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

        a = payloads.DeriveKeyRequestPayload(derivation_parameters=None)
        b = payloads.DeriveKeyRequestPayload(
            derivation_parameters=attributes.DerivationParameters(
                cryptographic_parameters=attributes.CryptographicParameters(
                    hashing_algorithm=enums.HashingAlgorithm.SHA_256
                ),
                initialization_vector=b'\x39\x48\x74\x32\x49\x28\x34\xA3',
                derivation_data=b'\xFA\xD9\x8B\x6A\xCA\x6D\x87\xDD'
            )
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_template_attribute(self):
        """
        Test that the inequality operator returns True when comparing two
        DeriveKey request payloads with different template attribute.
        """
        a = payloads.DeriveKeyRequestPayload(
            template_attribute=objects.TemplateAttribute(
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
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Length"
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ]
            )
        )
        b = payloads.DeriveKeyRequestPayload(
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Algorithm"
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.BLOWFISH,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Length"
                        ),
                        attribute_value=primitives.Integer(
                            value=64,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ]
            )
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

        a = payloads.DeriveKeyRequestPayload(
            template_attribute=objects.TemplateAttribute(
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
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Length"
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ]
            )
        )
        b = payloads.DeriveKeyRequestPayload(
            template_attribute=objects.TemplateAttribute()
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

        a = payloads.DeriveKeyRequestPayload(template_attribute=None)
        b = payloads.DeriveKeyRequestPayload(
            template_attribute=objects.TemplateAttribute(
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
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Length"
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

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        DeriveKey request payloads with different types.
        """
        a = payloads.DeriveKeyRequestPayload()
        b = "invalid"

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test that repr can be applied to a DeriveKey request payload.
        """
        derivation_parameters = attributes.DerivationParameters(
            cryptographic_parameters=attributes.CryptographicParameters(
                hashing_algorithm=enums.HashingAlgorithm.SHA_256
            ),
            initialization_vector=b'\x39\x48\x74\x32\x49\x28\x34\xA3',
            derivation_data=b'\xFA\xD9\x8B\x6A\xCA\x6D\x87\xDD'
        )
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
                ),
                objects.Attribute(
                    attribute_name=objects.Attribute.AttributeName(
                        "Cryptographic Length"
                    ),
                    attribute_value=primitives.Integer(
                        value=128,
                        tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                    )
                )
            ]
        )
        payload = payloads.DeriveKeyRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifiers=[
                "fb4b5b9c-6188-4c63-8142-fe9c328129fc",
                "5c9b81ef-4ee5-42cd-ba2d-c002fdd0c7b3",
                "1703250b-4d40-4de2-93a0-c494a1d4ae40"
            ],
            derivation_method=enums.DerivationMethod.HASH,
            derivation_parameters=derivation_parameters,
            template_attribute=template_attribute
        )

        # TODO(peter-hamilton) Update this test string when TemplateAttribute
        # supports repr.
        expected = (
            "DeriveKeyRequestPayload("
            "object_type=ObjectType.SYMMETRIC_KEY, "
            "unique_identifiers=["
            "'fb4b5b9c-6188-4c63-8142-fe9c328129fc', "
            "'5c9b81ef-4ee5-42cd-ba2d-c002fdd0c7b3', "
            "'1703250b-4d40-4de2-93a0-c494a1d4ae40'], "
            "derivation_method=DerivationMethod.HASH, "
            "derivation_parameters={0}, "
            "template_attribute={1})".format(
                repr(derivation_parameters),
                repr(template_attribute)
            )
        )
        observed = repr(payload)

        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a DeriveKey request payload
        """
        derivation_parameters = attributes.DerivationParameters(
            cryptographic_parameters=attributes.CryptographicParameters(
                hashing_algorithm=enums.HashingAlgorithm.SHA_256
            ),
            initialization_vector=b'\x39\x48\x74\x32\x49\x28\x34\xA3',
            derivation_data=b'\xFA\xD9\x8B\x6A\xCA\x6D\x87\xDD'
        )
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
                ),
                objects.Attribute(
                    attribute_name=objects.Attribute.AttributeName(
                        "Cryptographic Length"
                    ),
                    attribute_value=primitives.Integer(
                        value=128,
                        tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                    )
                )
            ]
        )
        payload = payloads.DeriveKeyRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifiers=[
                "fb4b5b9c-6188-4c63-8142-fe9c328129fc",
                "5c9b81ef-4ee5-42cd-ba2d-c002fdd0c7b3",
                "1703250b-4d40-4de2-93a0-c494a1d4ae40"
            ],
            derivation_method=enums.DerivationMethod.HASH,
            derivation_parameters=derivation_parameters,
            template_attribute=template_attribute
        )

        # TODO(peter-hamilton) Update this test string when TemplateAttribute
        # supports str.
        expected = str({
            "object_type": enums.ObjectType.SYMMETRIC_KEY,
            "unique_identifiers": [
                "fb4b5b9c-6188-4c63-8142-fe9c328129fc",
                "5c9b81ef-4ee5-42cd-ba2d-c002fdd0c7b3",
                "1703250b-4d40-4de2-93a0-c494a1d4ae40"
            ],
            "derivation_method": enums.DerivationMethod.HASH,
            "derivation_parameters": derivation_parameters,
            "template_attribute": template_attribute
        })
        observed = str(payload)

        self.assertEqual(expected, observed)

    def test_read_valid(self):
        """
        Test that a DeriveKey response payload can be read from a valid byte
        stream.
        """
        self.test_read()

    def test_read_missing_required_field(self):
        """
        Test that an exception is raised when reading a payload missing a
        required field.
        """
        self.test_read_missing_unique_identifier()

    def test_write_valid(self):
        """
        Test that a DeriveKey response payload can be written to a byte stream.
        """
        self.test_write()

    def test_read_write_roundtrip(self):
        """
        Test that a DeriveKey response payload can be read and written without
        changing the encoded bytes.
        """
        payload = payloads.DeriveKeyResponsePayload()
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
        Test that two DeriveKey response payloads with the same data are equal.
        """
        self.test_equal_on_equal()

    def test_ne(self):
        """
        Test that two DeriveKey response payloads with different data are not
        equal.
        """
        self.test_not_equal_on_not_equal_unique_identifier()

    def test_read_valid(self):
        """
        Test that a DeriveKey response payload can be read from a valid byte
        stream.
        """
        self.test_read()

    def test_read_missing_required_field(self):
        """
        Test that an exception is raised when reading a payload missing a
        required field.
        """
        self.test_read_missing_unique_identifier()

    def test_write_valid(self):
        """
        Test that a DeriveKey response payload can be written to a byte stream.
        """
        self.test_write()

    def test_read_write_roundtrip(self):
        """
        Test that a DeriveKey response payload can be read and written without
        changing the encoded bytes.
        """
        payload = payloads.DeriveKeyResponsePayload()
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
        Test that two DeriveKey response payloads with the same data are equal.
        """
        self.test_equal_on_equal()

    def test_ne(self):
        """
        Test that two DeriveKey response payloads with different data are not
        equal.
        """
        self.test_not_equal_on_not_equal_unique_identifier()

    def test_read_valid(self):
        """
        Test that a DeriveKey request payload can be read from a valid byte
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
        Test that a DeriveKey request payload can be written to a byte stream.
        """
        self.test_write()

    def test_read_write_roundtrip(self):
        """
        Test that a DeriveKey request payload can be read and written without
        changing the encoded bytes.
        """
        payload = payloads.DeriveKeyRequestPayload()
        payload.read(utils.BytearrayStream(self.full_encoding.buffer))

        buffer = utils.BytearrayStream()
        payload.write(buffer)

        self.assertEqual(str(self.full_encoding), str(buffer))

    def test_validate_invalid(self):
        """
        Test that an exception is raised when a field has an invalid type.
        """
        self.test_invalid_object_type()

    def test_eq(self):
        """
        Test that two DeriveKey request payloads with the same data are equal.
        """
        self.test_equal_on_equal()

    def test_ne(self):
        """
        Test that two DeriveKey request payloads with different data are not
        equal.
        """
        self.test_not_equal_on_not_equal_object_type()

class TestDeriveKeyResponsePayload(testtools.TestCase):
    """
    Test suite for the DeriveKey response payload.
    """

    def setUp(self):
        super(TestDeriveKeyResponsePayload, self).setUp()

        # Encoding obtained in part from the KMIP 1.1 testing document. The
        # rest of the encoding is a manual construction, since DeriveKey is
        # not specifically detailed by the testing document.
        #
        # This encoding matches the following set of values:
        # Unique Identifier - fb4b5b9c-6188-4c63-8142-fe9c328129fc
        # Template Attribute
        #     Attribute
        #         Attribute Name - Cryptographic Algorithm
        #         Attribute Value - AES
        #     Attribute
        #         Attribute Name - Cryptographic Length
        #         Attribute Value - 128

        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\xA8'
            b'\x42\x00\x94\x07\x00\x00\x00\x24\x66\x62\x34\x62\x35\x62\x39\x63'
            b'\x2D\x36\x31\x38\x38\x2D\x34\x63\x36\x33\x2D\x38\x31\x34\x32\x2D'
            b'\x66\x65\x39\x63\x33\x32\x38\x31\x32\x39\x66\x63\x00\x00\x00\x00'
            b'\x42\x00\x91\x01\x00\x00\x00\x70'
            b'\x42\x00\x08\x01\x00\x00\x00\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x17\x43\x72\x79\x70\x74\x6F\x67\x72'
            b'\x61\x70\x68\x69\x63\x20\x41\x6C\x67\x6F\x72\x69\x74\x68\x6D\x00'
            b'\x42\x00\x0B\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x08\x01\x00\x00\x00\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x14\x43\x72\x79\x70\x74\x6F\x67\x72'
            b'\x61\x70\x68\x69\x63\x20\x4C\x65\x6E\x67\x74\x68\x00\x00\x00\x00'
            b'\x42\x00\x0B\x02\x00\x00\x00\x04\x00\x00\x00\x80\x00\x00\x00\x00'
        )

        # All of the following partial encodings are trimmed versions of the
        # above full encoding.

        self.partial_encoding_no_unique_identifier = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x00'
        )
        self.partial_encoding_no_template_attribute = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x30'
            b'\x42\x00\x94\x07\x00\x00\x00\x24\x66\x62\x34\x62\x35\x62\x39\x63'
            b'\x2D\x36\x31\x38\x38\x2D\x34\x63\x36\x33\x2D\x38\x31\x34\x32\x2D'
            b'\x66\x65\x39\x63\x33\x32\x38\x31\x32\x39\x66\x63\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestDeriveKeyResponsePayload, self).tearDown()

    def test_init(self):
        """
        Test that a DeriveKey response payload can be constructed with no
        arguments.
        """
        payload = payloads.DeriveKeyResponsePayload()

        self.assertIsNone(payload.unique_identifier)
        self.assertIsNone(payload.template_attribute)

    def test_init_with_args(self):
        """
        Test that a DeriveKey response payload can be constructed with valid
        values
        """
        payload = payloads.DeriveKeyResponsePayload(
            unique_identifier="00000000-1111-2222-3333-444444444444",
            template_attribute=objects.TemplateAttribute()
        )

        self.assertEqual(
            "00000000-1111-2222-3333-444444444444",
            payload.unique_identifier
        )
        self.assertEqual(
            objects.TemplateAttribute(),
            payload.template_attribute
        )

    def test_invalid_unique_identifier(self):
        """
        Test that a TypeError is raised when invalid values are used to set
        the unique identifier of a DeriveKey request payload.
        """
        payload = payloads.DeriveKeyResponsePayload()
        args = (payload, "unique_identifier", 0)
        self.assertRaisesRegex(
            TypeError,
            "Unique identifier must be a string.",
            setattr,
            *args
        )

    def test_invalid_template_attribute(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the template attribute of a DeriveKey response payload.
        """
        payload = payloads.DeriveKeyResponsePayload()
        args = (payload, "template_attribute", "invalid")
        self.assertRaisesRegex(
            TypeError,
            "Template attribute must be a TemplateAttribute structure.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a DeriveKey response payload can be read from a data stream.
        """
        payload = payloads.DeriveKeyResponsePayload()

        self.assertIsNone(payload.unique_identifier)
        self.assertIsNone(payload.template_attribute)

        payload.read(self.full_encoding)

        self.assertEqual(
            "fb4b5b9c-6188-4c63-8142-fe9c328129fc",
            payload.unique_identifier
        )
        self.assertEqual(
            objects.TemplateAttribute(
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
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Length"
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ]
            ),
            payload.template_attribute
        )

    def test_read_kmip_2_0(self):
        """
        Test that a DeriveKey response payload can be read from a data stream
        encoded with the KMIP 2.0 format.
        """
        payload = payloads.DeriveKeyResponsePayload()

        self.assertIsNone(payload.unique_identifier)
        self.assertIsNone(payload.template_attribute)

        payload.read(
            self.partial_encoding_no_template_attribute,
            kmip_version=enums.KMIPVersion.KMIP_2_0
        )

        self.assertEqual(
            "fb4b5b9c-6188-4c63-8142-fe9c328129fc",
            payload.unique_identifier
        )
        self.assertIsNone(payload.template_attribute)

    def test_read_missing_unique_identifier(self):
        """
        Test that an InvalidKmipEncoding error gets raised when decoding a
        DeriveKey response payload encoding missing the unique identifier.
        """
        payload = payloads.DeriveKeyResponsePayload()

        args = (self.partial_encoding_no_unique_identifier, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The DeriveKey response payload encoding is missing the unique "
            "identifier.",
            payload.read,
            *args
        )

    def test_read_missing_template_attribute(self):
        """

        Test that a DeriveKey response payload missing a template attribute
        can be read from a data stream.
        """
        payload = payloads.DeriveKeyResponsePayload()

        payload.read(self.partial_encoding_no_template_attribute)

        self.assertEqual(
            "fb4b5b9c-6188-4c63-8142-fe9c328129fc",
            payload.unique_identifier
        )
        self.assertEqual(None, payload.template_attribute)

    def test_write(self):
        """
        Test that a DeriveKey response payload can be written to a data stream.
        """
        payload = payloads.DeriveKeyResponsePayload(
            unique_identifier="fb4b5b9c-6188-4c63-8142-fe9c328129fc",
            template_attribute=objects.TemplateAttribute(
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
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Length"
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
        payload.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_kmip_2_0(self):
        """
        Test that a DeriveKey response payload can be written to a data stream
        encoded with the KMIP 2.0 format.
        """
        payload = payloads.DeriveKeyResponsePayload(
            unique_identifier="fb4b5b9c-6188-4c63-8142-fe9c328129fc",
            template_attribute=objects.TemplateAttribute(
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
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Length"
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
        payload.write(stream, kmip_version=enums.KMIPVersion.KMIP_2_0)

        self.assertEqual(
            len(self.partial_encoding_no_template_attribute),
            len(stream)
        )
        self.assertEqual(
            str(self.partial_encoding_no_template_attribute),
            str(stream)
        )

    def test_write_missing_unique_identifier(self):
        """
        Test that an InvalidField error gets raised when encoding a DeriveKey
        response payload missing the unique identifier.
        """
        payload = payloads.DeriveKeyResponsePayload()

        args = (utils.BytearrayStream(), )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The DeriveKey response payload is missing the unique identifier "
            "field.",
            payload.write,
            *args
        )

    def test_write_missing_template_attribute(self):
        """
        Test that a ValueError gets raised when encoding a DeriveKey response
        payload missing the template attribute.
        """
        payload = payloads.DeriveKeyResponsePayload(
            unique_identifier="fb4b5b9c-6188-4c63-8142-fe9c328129fc"
        )
        stream = utils.BytearrayStream()

        payload.write(stream)

        self.assertEqual(
            len(self.partial_encoding_no_template_attribute),
            len(stream)
        )
        self.assertEqual(
            str(self.partial_encoding_no_template_attribute),
            str(stream)
        )

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        DeriveKey response payloads with the same data.
        """
        a = payloads.DeriveKeyResponsePayload()
        b = payloads.DeriveKeyResponsePayload()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = payloads.DeriveKeyResponsePayload(
            unique_identifier="fb4b5b9c-6188-4c63-8142-fe9c328129fc",
            template_attribute=objects.TemplateAttribute(
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
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Length"
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ]
            )
        )
        b = payloads.DeriveKeyResponsePayload(
            unique_identifier="fb4b5b9c-6188-4c63-8142-fe9c328129fc",
            template_attribute=objects.TemplateAttribute(
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
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Length"
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ]
            )
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_unique_identifier(self):
        """
        Test that the equality operator returns False when comparing two
        DeriveKey response payloads with different unique identifiers.
        """
        a = payloads.DeriveKeyResponsePayload(
            unique_identifier="fb4b5b9c-6188-4c63-8142-fe9c328129fc"
        )
        b = payloads.DeriveKeyResponsePayload(
            unique_identifier="5c9b81ef-4ee5-42cd-ba2d-c002fdd0c7b3"
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

        a = payloads.DeriveKeyResponsePayload(
            unique_identifier="1703250b-4d40-4de2-93a0-c494a1d4ae40"
        )
        b = payloads.DeriveKeyResponsePayload(unique_identifier=None)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_template_attribute(self):
        """
        Test that the equality operator returns False when comparing two
        DeriveKey response payloads with different template attributes.
        """
        a = payloads.DeriveKeyResponsePayload(
            template_attribute=objects.TemplateAttribute(
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
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Length"
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ]
            )
        )
        b = payloads.DeriveKeyResponsePayload(
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Algorithm"
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.BLOWFISH,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Length"
                        ),
                        attribute_value=primitives.Integer(
                            value=64,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ]
            )
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

        a = payloads.DeriveKeyResponsePayload(
            template_attribute=objects.TemplateAttribute(
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
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Length"
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ]
            )
        )
        b = payloads.DeriveKeyResponsePayload(
            template_attribute=objects.TemplateAttribute()
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

        a = payloads.DeriveKeyResponsePayload(template_attribute=None)
        b = payloads.DeriveKeyResponsePayload(
            template_attribute=objects.TemplateAttribute(
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
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Length"
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

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        DeriveKey response payloads with different types.
        """
        a = payloads.DeriveKeyResponsePayload()
        b = "invalid"

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        DeriveKey response payloads with the same data.
        """
        a = payloads.DeriveKeyResponsePayload()
        b = payloads.DeriveKeyResponsePayload()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = payloads.DeriveKeyResponsePayload(
            unique_identifier="fb4b5b9c-6188-4c63-8142-fe9c328129fc",
            template_attribute=objects.TemplateAttribute(
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
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Length"
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ]
            )
        )
        b = payloads.DeriveKeyResponsePayload(
            unique_identifier="fb4b5b9c-6188-4c63-8142-fe9c328129fc",
            template_attribute=objects.TemplateAttribute(
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
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Length"
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ]
            )
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_unique_identifier(self):
        """
        Test that the inequality operator returns True when comparing two
        DeriveKey response payloads with different unique identifiers.
        """
        a = payloads.DeriveKeyResponsePayload(
            unique_identifier="fb4b5b9c-6188-4c63-8142-fe9c328129fc"
        )
        b = payloads.DeriveKeyResponsePayload(
            unique_identifier="5c9b81ef-4ee5-42cd-ba2d-c002fdd0c7b3"
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

        a = payloads.DeriveKeyResponsePayload(
            unique_identifier="1703250b-4d40-4de2-93a0-c494a1d4ae40"
        )
        b = payloads.DeriveKeyResponsePayload(unique_identifier=None)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_template_attribute(self):
        """
        Test that the inequality operator returns True when comparing two
        DeriveKey response payloads with different template attribute.
        """
        a = payloads.DeriveKeyResponsePayload(
            template_attribute=objects.TemplateAttribute(
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
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Length"
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ]
            )
        )
        b = payloads.DeriveKeyResponsePayload(
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Algorithm"
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.BLOWFISH,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Length"
                        ),
                        attribute_value=primitives.Integer(
                            value=64,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ]
            )
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

        a = payloads.DeriveKeyResponsePayload(
            template_attribute=objects.TemplateAttribute(
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
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Length"
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ]
            )
        )
        b = payloads.DeriveKeyResponsePayload(
            template_attribute=objects.TemplateAttribute()
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

        a = payloads.DeriveKeyResponsePayload(template_attribute=None)
        b = payloads.DeriveKeyResponsePayload(
            template_attribute=objects.TemplateAttribute(
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
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Length"
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

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        DeriveKey response payloads with different types.
        """
        a = payloads.DeriveKeyResponsePayload()
        b = "invalid"

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test that repr can be applied to a DeriveKey response payload.
        """
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
                ),
                objects.Attribute(
                    attribute_name=objects.Attribute.AttributeName(
                        "Cryptographic Length"
                    ),
                    attribute_value=primitives.Integer(
                        value=128,
                        tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                    )
                )
            ]
        )
        payload = payloads.DeriveKeyResponsePayload(
            unique_identifier="fb4b5b9c-6188-4c63-8142-fe9c328129fc",
            template_attribute=template_attribute
        )

        # TODO(peter-hamilton) Update this test string when TemplateAttribute
        # supports repr.
        expected = (
            "DeriveKeyResponsePayload("
            "unique_identifier='fb4b5b9c-6188-4c63-8142-fe9c328129fc', "
            "template_attribute={0})".format(
                repr(template_attribute)
            )
        )
        observed = repr(payload)

        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a DeriveKey response payload
        """
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
                ),
                objects.Attribute(
                    attribute_name=objects.Attribute.AttributeName(
                        "Cryptographic Length"
                    ),
                    attribute_value=primitives.Integer(
                        value=128,
                        tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                    )
                )
            ]
        )
        payload = payloads.DeriveKeyResponsePayload(
            unique_identifier="fb4b5b9c-6188-4c63-8142-fe9c328129fc",
            template_attribute=template_attribute
        )

        # TODO(peter-hamilton) Update this test string when TemplateAttribute
        # supports str.
        expected = str({
            "unique_identifier": "fb4b5b9c-6188-4c63-8142-fe9c328129fc",
            "template_attribute": template_attribute
        })
        observed = str(payload)

        self.assertEqual(expected, observed)
    def test_read_valid(self):
        """
        Test that a DeriveKey response payload can be read from a valid byte
        stream.
        """
        self.test_read()

    def test_read_missing_required_field(self):
        """
        Test that an exception is raised when reading a payload missing a
        required field.
        """
        self.test_read_missing_unique_identifier()

    def test_write_valid(self):
        """
        Test that a DeriveKey response payload can be written to a byte stream.
        """
        self.test_write()

    def test_read_write_roundtrip(self):
        """
        Test that a DeriveKey response payload can be read and written without
        changing the encoded bytes.
        """
        payload = payloads.DeriveKeyResponsePayload()
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
        Test that two DeriveKey response payloads with the same data are equal.
        """
        self.test_equal_on_equal()

    def test_ne(self):
        """
        Test that two DeriveKey response payloads with different data are not
        equal.
        """
        self.test_not_equal_on_not_equal_unique_identifier()
