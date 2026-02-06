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

from kmip.core import attributes
from kmip.core import enums
from kmip.core import exceptions
from kmip.core import objects
from kmip.core import primitives
from kmip.core import utils

from kmip.core.messages import payloads

class TestCreateKeyPairRequestPayload(testtools.TestCase):

    def setUp(self):
        super(TestCreateKeyPairRequestPayload, self).setUp()

        # Encoding obtained from the KMIP 1.1 testing document, Section 8.1.0.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Common Template Attribute
        #         Attribute
        #             Attribute Name - Cryptographic Algorithm
        #             Attribute Value - RSA
        #         Attribute
        #             Attribute Name - Cryptographic Length
        #             Attribute Value - 1024
        #     Private Key Template Attribute
        #         Attribute
        #             Attribute Name - Name
        #             Attribute Value
        #                 Name Value - PrivateKey1
        #                 Name Type - Uninterpreted Text String
        #         Attribute
        #             Attribute Name - Cryptographic Usage Mask
        #             Attribute Value - Sign
        #     Public Key Template Attribute
        #         Attribute
        #             Attribute Name - Name
        #             Attribute Value
        #                 Name Value - PublicKey1
        #                 Name Type - Uninterpreted Text String
        #         Attribute
        #             Attribute Name - Cryptographic Usage Mask
        #             Attribute Value - Verify
        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x01\x88'
            b'\x42\x00\x1F\x01\x00\x00\x00\x70'
            b'\x42\x00\x08\x01\x00\x00\x00\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x17'
            b'\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x41\x6C'
            b'\x67\x6F\x72\x69\x74\x68\x6D\x00'
            b'\x42\x00\x0B\x05\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00'
            b'\x42\x00\x08\x01\x00\x00\x00\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x14'
            b'\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x4C\x65'
            b'\x6E\x67\x74\x68\x00\x00\x00\x00'
            b'\x42\x00\x0B\x02\x00\x00\x00\x04\x00\x00\x04\x00\x00\x00\x00\x00'
            b'\x42\x00\x65\x01\x00\x00\x00\x80'
            b'\x42\x00\x08\x01\x00\x00\x00\x40'
            b'\x42\x00\x0A\x07\x00\x00\x00\x04'
            b'\x4E\x61\x6D\x65\x00\x00\x00\x00'
            b'\x42\x00\x0B\x01\x00\x00\x00\x28'
            b'\x42\x00\x55\x07\x00\x00\x00\x0B'
            b'\x50\x72\x69\x76\x61\x74\x65\x4B\x65\x79\x31\x00\x00\x00\x00\x00'
            b'\x42\x00\x54\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x08\x01\x00\x00\x00\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x18'
            b'\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x55\x73'
            b'\x61\x67\x65\x20\x4D\x61\x73\x6B'
            b'\x42\x00\x0B\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x6E\x01\x00\x00\x00\x80'
            b'\x42\x00\x08\x01\x00\x00\x00\x40'
            b'\x42\x00\x0A\x07\x00\x00\x00\x04'
            b'\x4E\x61\x6D\x65\x00\x00\x00\x00'
            b'\x42\x00\x0B\x01\x00\x00\x00\x28'
            b'\x42\x00\x55\x07\x00\x00\x00\x0A'
            b'\x50\x75\x62\x6C\x69\x63\x4B\x65\x79\x31\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\x54\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x08\x01\x00\x00\x00\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x18'
            b'\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x55\x73'
            b'\x61\x67\x65\x20\x4D\x61\x73\x6B'
            b'\x42\x00\x0B\x02\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
        )

        # Encoding obtained from the KMIP 1.1 testing document, Section 8.1.0.
        # Manually converted to the KMIP 2.0 format.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Common Attributes
        #         Cryptographic Algorithm - RSA
        #         Cryptographic Length - 1024
        #     Private Key Attributes
        #         Name
        #             Name Value - PrivateKey1
        #             Name Type - Uninterpreted Text String
        #         Cryptographic Usage Mask - Sign
        #     Public Key Attributes
        #         Name
        #             Name Value - PublicKey1
        #             Name Type - Uninterpreted Text String
        #         Cryptographic Usage Mask - Verify
        self.full_encoding_with_attributes = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\xB8'
            b'\x42\x01\x26\x01\x00\x00\x00\x20'
            b'\x42\x00\x28\x05\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00'
            b'\x42\x00\x2A\x02\x00\x00\x00\x04\x00\x00\x04\x00\x00\x00\x00\x00'
            b'\x42\x01\x27\x01\x00\x00\x00\x40'
            b'\x42\x00\x53\x01\x00\x00\x00\x28'
            b'\x42\x00\x55\x07\x00\x00\x00\x0B'
            b'\x50\x72\x69\x76\x61\x74\x65\x4B\x65\x79\x31\x00\x00\x00\x00\x00'
            b'\x42\x00\x54\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x2C\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x01\x28\x01\x00\x00\x00\x40'
            b'\x42\x00\x53\x01\x00\x00\x00\x28'
            b'\x42\x00\x55\x07\x00\x00\x00\x0A'
            b'\x50\x75\x62\x6C\x69\x63\x4B\x65\x79\x31\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\x54\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x2C\x02\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
        )

        # Encoding obtained from the KMIP 1.1 testing document, Section 8.1.0.
        # Manually converted to the KMIP 2.0 format.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Common Attributes
        #         Cryptographic Algorithm - RSA
        #         Cryptographic Length - 1024
        #     Private Key Attributes
        #         Name
        #             Name Value - PrivateKey1
        #             Name Type - Uninterpreted Text String
        #         Cryptographic Usage Mask - Sign
        #     Public Key Attributes
        #         Name
        #             Name Value - PublicKey1
        #             Name Type - Uninterpreted Text String
        #         Cryptographic Usage Mask - Verify
        #     Common Protection Storage Masks
        #         Protection Storage Mask - Software | Hardware
        #         Protection Storage Mask - On Premises | Off Premises
        #     Private Protection Storage Masks
        #         Protection Storage Mask - On Premises | Off Premises
        #     Public Protection Storage Masks
        #         Protection Storage Mask - Software | Hardware
        self.full_encoding_with_protection_masks = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x01\x10'
            b'\x42\x01\x26\x01\x00\x00\x00\x20'
            b'\x42\x00\x28\x05\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00'
            b'\x42\x00\x2A\x02\x00\x00\x00\x04\x00\x00\x04\x00\x00\x00\x00\x00'
            b'\x42\x01\x27\x01\x00\x00\x00\x40'
            b'\x42\x00\x53\x01\x00\x00\x00\x28'
            b'\x42\x00\x55\x07\x00\x00\x00\x0B'
            b'\x50\x72\x69\x76\x61\x74\x65\x4B\x65\x79\x31\x00\x00\x00\x00\x00'
            b'\x42\x00\x54\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x2C\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x01\x28\x01\x00\x00\x00\x40'
            b'\x42\x00\x53\x01\x00\x00\x00\x28'
            b'\x42\x00\x55\x07\x00\x00\x00\x0A'
            b'\x50\x75\x62\x6C\x69\x63\x4B\x65\x79\x31\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\x54\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x2C\x02\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x01\x63\x01\x00\x00\x00\x20'
            b'\x42\x01\x5E\x02\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x01\x5E\x02\x00\x00\x00\x04\x00\x00\x03\x00\x00\x00\x00\x00'
            b'\x42\x01\x64\x01\x00\x00\x00\x10'
            b'\x42\x01\x5E\x02\x00\x00\x00\x04\x00\x00\x03\x00\x00\x00\x00\x00'
            b'\x42\x01\x65\x01\x00\x00\x00\x10'
            b'\x42\x01\x5E\x02\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
        )

        # Encoding obtained from the KMIP 1.1 testing document, Section 8.1.0.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Private Key Template Attribute
        #         Attribute
        #             Attribute Name - Name
        #             Attribute Value
        #                 Name Value - PrivateKey1
        #                 Name Type - Uninterpreted Text String
        #         Attribute
        #             Attribute Name - Cryptographic Usage Mask
        #             Attribute Value - Sign
        #     Public Key Template Attribute
        #         Attribute
        #             Attribute Name - Name
        #             Attribute Value
        #                 Name Value - PublicKey1
        #                 Name Type - Uninterpreted Text String
        #         Attribute
        #             Attribute Name - Cryptographic Usage Mask
        #             Attribute Value - Verify
        self.no_common_template_attribute_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x01\x10'
            b'\x42\x00\x65\x01\x00\x00\x00\x80'
            b'\x42\x00\x08\x01\x00\x00\x00\x40'
            b'\x42\x00\x0A\x07\x00\x00\x00\x04'
            b'\x4E\x61\x6D\x65\x00\x00\x00\x00'
            b'\x42\x00\x0B\x01\x00\x00\x00\x28'
            b'\x42\x00\x55\x07\x00\x00\x00\x0B'
            b'\x50\x72\x69\x76\x61\x74\x65\x4B\x65\x79\x31\x00\x00\x00\x00\x00'
            b'\x42\x00\x54\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x08\x01\x00\x00\x00\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x18'
            b'\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x55\x73'
            b'\x61\x67\x65\x20\x4D\x61\x73\x6B'
            b'\x42\x00\x0B\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x6E\x01\x00\x00\x00\x80'
            b'\x42\x00\x08\x01\x00\x00\x00\x40'
            b'\x42\x00\x0A\x07\x00\x00\x00\x04'
            b'\x4E\x61\x6D\x65\x00\x00\x00\x00'
            b'\x42\x00\x0B\x01\x00\x00\x00\x28'
            b'\x42\x00\x55\x07\x00\x00\x00\x0A'
            b'\x50\x75\x62\x6C\x69\x63\x4B\x65\x79\x31\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\x54\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x08\x01\x00\x00\x00\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x18'
            b'\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x55\x73'
            b'\x61\x67\x65\x20\x4D\x61\x73\x6B'
            b'\x42\x00\x0B\x02\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
        )

        # Encoding obtained from the KMIP 1.1 testing document, Section 8.1.0.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Common Template Attribute
        #         Attribute
        #             Attribute Name - Cryptographic Algorithm
        #             Attribute Value - RSA
        #         Attribute
        #             Attribute Name - Cryptographic Length
        #             Attribute Value - 1024
        #     Public Key Template Attribute
        #         Attribute
        #             Attribute Name - Name
        #             Attribute Value
        #                 Name Value - PublicKey1
        #                 Name Type - Uninterpreted Text String
        #         Attribute
        #             Attribute Name - Cryptographic Usage Mask
        #             Attribute Value - Verify
        self.no_private_key_template_attr_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x01\x00'
            b'\x42\x00\x1F\x01\x00\x00\x00\x70'
            b'\x42\x00\x08\x01\x00\x00\x00\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x17'
            b'\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x41\x6C'
            b'\x67\x6F\x72\x69\x74\x68\x6D\x00'
            b'\x42\x00\x0B\x05\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00'
            b'\x42\x00\x08\x01\x00\x00\x00\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x14'
            b'\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x4C\x65'
            b'\x6E\x67\x74\x68\x00\x00\x00\x00'
            b'\x42\x00\x0B\x02\x00\x00\x00\x04\x00\x00\x04\x00\x00\x00\x00\x00'
            b'\x42\x00\x6E\x01\x00\x00\x00\x80'
            b'\x42\x00\x08\x01\x00\x00\x00\x40'
            b'\x42\x00\x0A\x07\x00\x00\x00\x04'
            b'\x4E\x61\x6D\x65\x00\x00\x00\x00'
            b'\x42\x00\x0B\x01\x00\x00\x00\x28'
            b'\x42\x00\x55\x07\x00\x00\x00\x0A'
            b'\x50\x75\x62\x6C\x69\x63\x4B\x65\x79\x31\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\x54\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x08\x01\x00\x00\x00\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x18'
            b'\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x55\x73'
            b'\x61\x67\x65\x20\x4D\x61\x73\x6B'
            b'\x42\x00\x0B\x02\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
        )

        # Encoding obtained from the KMIP 1.1 testing document, Section 8.1.0.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Common Template Attribute
        #         Attribute
        #             Attribute Name - Cryptographic Algorithm
        #             Attribute Value - RSA
        #         Attribute
        #             Attribute Name - Cryptographic Length
        #             Attribute Value - 1024
        #     Private Key Template Attribute
        #         Attribute
        #             Attribute Name - Name
        #             Attribute Value
        #                 Name Value - PrivateKey1
        #                 Name Type - Uninterpreted Text String
        #         Attribute
        #             Attribute Name - Cryptographic Usage Mask
        #             Attribute Value - Sign
        #     Public Key Template Attribute
        #         Attribute
        #             Attribute Name - Name
        #             Attribute Value
        #                 Name Value - PublicKey1
        #                 Name Type - Uninterpreted Text String
        #         Attribute
        #             Attribute Name - Cryptographic Usage Mask
        #             Attribute Value - Verify
        self.no_public_key_template_attribute_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x01\x00'
            b'\x42\x00\x1F\x01\x00\x00\x00\x70'
            b'\x42\x00\x08\x01\x00\x00\x00\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x17'
            b'\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x41\x6C'
            b'\x67\x6F\x72\x69\x74\x68\x6D\x00'
            b'\x42\x00\x0B\x05\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00'
            b'\x42\x00\x08\x01\x00\x00\x00\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x14'
            b'\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x4C\x65'
            b'\x6E\x67\x74\x68\x00\x00\x00\x00'
            b'\x42\x00\x0B\x02\x00\x00\x00\x04\x00\x00\x04\x00\x00\x00\x00\x00'
            b'\x42\x00\x65\x01\x00\x00\x00\x80'
            b'\x42\x00\x08\x01\x00\x00\x00\x40'
            b'\x42\x00\x0A\x07\x00\x00\x00\x04'
            b'\x4E\x61\x6D\x65\x00\x00\x00\x00'
            b'\x42\x00\x0B\x01\x00\x00\x00\x28'
            b'\x42\x00\x55\x07\x00\x00\x00\x0B'
            b'\x50\x72\x69\x76\x61\x74\x65\x4B\x65\x79\x31\x00\x00\x00\x00\x00'
            b'\x42\x00\x54\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x08\x01\x00\x00\x00\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x18'
            b'\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x55\x73'
            b'\x61\x67\x65\x20\x4D\x61\x73\x6B'
            b'\x42\x00\x0B\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
        )

        # This encoding matches the following set of values:
        # Request Payload
        self.empty_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestCreateKeyPairRequestPayload, self).tearDown()

    def test_invalid_common_template_attribute(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the common template attribute of a CreateKeyPair request payload.
        """
        kwargs = {'common_template_attribute': 'invalid'}
        self.assertRaisesRegex(
            TypeError,
            "Common template attribute must be a TemplateAttribute structure.",
            payloads.CreateKeyPairRequestPayload,
            **kwargs
        )

        kwargs = {'common_template_attribute': objects.TemplateAttribute()}
        self.assertRaisesRegex(
            TypeError,
            "Common template attribute must be a TemplateAttribute structure "
            "with a CommonTemplateAttribute tag.",
            payloads.CreateKeyPairRequestPayload,
            **kwargs
        )

        args = (
            payloads.CreateKeyPairRequestPayload(),
            'common_template_attribute',
            'invalid'
        )
        self.assertRaisesRegex(
            TypeError,
            "Common template attribute must be a TemplateAttribute structure.",
            setattr,
            *args
        )

        args = (
            payloads.CreateKeyPairRequestPayload(),
            'common_template_attribute',
            objects.TemplateAttribute()
        )
        self.assertRaisesRegex(
            TypeError,
            "Common template attribute must be a TemplateAttribute structure "
            "with a CommonTemplateAttribute tag.",
            setattr,
            *args
        )

    def test_invalid_private_key_template_attribute(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the private key template attribute of a CreateKeyPair request payload.
        """
        kwargs = {"private_key_template_attribute": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "Private key template attribute must be a TemplateAttribute "
            "structure.",
            payloads.CreateKeyPairRequestPayload,
            **kwargs
        )

        kwargs = {
            "private_key_template_attribute": objects.TemplateAttribute()
        }
        self.assertRaisesRegex(
            TypeError,
            "Private key template attribute must be a TemplateAttribute "
            "structure with a PrivateKeyTemplateAttribute tag.",
            payloads.CreateKeyPairRequestPayload,
            **kwargs
        )

        args = (
            payloads.CreateKeyPairRequestPayload(),
            "private_key_template_attribute",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "Private key template attribute must be a TemplateAttribute "
            "structure.",
            setattr,
            *args
        )

        args = (
            payloads.CreateKeyPairRequestPayload(),
            "private_key_template_attribute",
            objects.TemplateAttribute()
        )
        self.assertRaisesRegex(
            TypeError,
            "Private key template attribute must be a TemplateAttribute "
            "structure with a PrivateKeyTemplateAttribute tag.",
            setattr,
            *args
        )

    def test_invalid_public_key_template_attribute(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the public key template attribute of a CreateKeyPair request payload.
        """
        kwargs = {"public_key_template_attribute": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "Public key template attribute must be a TemplateAttribute "
            "structure.",
            payloads.CreateKeyPairRequestPayload,
            **kwargs
        )

        kwargs = {"public_key_template_attribute": objects.TemplateAttribute()}
        self.assertRaisesRegex(
            TypeError,
            "Public key template attribute must be a TemplateAttribute "
            "structure with a PublicKeyTemplateAttribute tag.",
            payloads.CreateKeyPairRequestPayload,
            **kwargs
        )

        args = (
            payloads.CreateKeyPairRequestPayload(),
            "public_key_template_attribute",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "Public key template attribute must be a TemplateAttribute "
            "structure.",
            setattr,
            *args
        )

        args = (
            payloads.CreateKeyPairRequestPayload(),
            "public_key_template_attribute",
            objects.TemplateAttribute()
        )
        self.assertRaisesRegex(
            TypeError,
            "Public key template attribute must be a TemplateAttribute "
            "structure with a PublicKeyTemplateAttribute tag.",
            setattr,
            *args
        )

    def test_invalid_common_protection_storage_masks(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the common protection storage masks of a CreateKeyPair request payload.
        """
        kwargs = {"common_protection_storage_masks": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The common protection storage masks must be a "
            "ProtectionStorageMasks structure.",
            payloads.CreateKeyPairRequestPayload,
            **kwargs
        )
        kwargs = {
            "common_protection_storage_masks": objects.ProtectionStorageMasks()
        }
        self.assertRaisesRegex(
            TypeError,
            "The common protection storage masks must be a "
            "ProtectionStorageMasks structure with a "
            "CommonProtectionStorageMasks tag.",
            payloads.CreateKeyPairRequestPayload,
            **kwargs
        )

        args = (
            payloads.CreateKeyPairRequestPayload(),
            "common_protection_storage_masks",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The common protection storage masks must be a "
            "ProtectionStorageMasks structure.",
            setattr,
            *args
        )
        args = (
            payloads.CreateKeyPairRequestPayload(),
            "common_protection_storage_masks",
            objects.ProtectionStorageMasks()
        )
        self.assertRaisesRegex(
            TypeError,
            "The common protection storage masks must be a "
            "ProtectionStorageMasks structure with a "
            "CommonProtectionStorageMasks tag.",
            setattr,
            *args
        )

    def test_invalid_private_protection_storage_masks(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the private protection storage masks of a CreateKeyPair request
        payload.
        """
        kwargs = {"private_protection_storage_masks": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The private protection storage masks must be a "
            "ProtectionStorageMasks structure.",
            payloads.CreateKeyPairRequestPayload,
            **kwargs
        )
        kwargs = {
            "private_protection_storage_masks":
            objects.ProtectionStorageMasks()
        }
        self.assertRaisesRegex(
            TypeError,
            "The private protection storage masks must be a "
            "ProtectionStorageMasks structure with a "
            "PrivateProtectionStorageMasks tag.",
            payloads.CreateKeyPairRequestPayload,
            **kwargs
        )

        args = (
            payloads.CreateKeyPairRequestPayload(),
            "private_protection_storage_masks",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The private protection storage masks must be a "
            "ProtectionStorageMasks structure.",
            setattr,
            *args
        )
        args = (
            payloads.CreateKeyPairRequestPayload(),
            "private_protection_storage_masks",
            objects.ProtectionStorageMasks()
        )
        self.assertRaisesRegex(
            TypeError,
            "The private protection storage masks must be a "
            "ProtectionStorageMasks structure with a "
            "PrivateProtectionStorageMasks tag.",
            setattr,
            *args
        )

    def test_invalid_public_protection_storage_masks(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the public protection storage masks of a CreateKeyPair request
        payload.
        """
        kwargs = {"public_protection_storage_masks": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The public protection storage masks must be a "
            "ProtectionStorageMasks structure.",
            payloads.CreateKeyPairRequestPayload,
            **kwargs
        )
        kwargs = {
            "public_protection_storage_masks": objects.ProtectionStorageMasks()
        }
        self.assertRaisesRegex(
            TypeError,
            "The public protection storage masks must be a "
            "ProtectionStorageMasks structure with a "
            "PublicProtectionStorageMasks tag.",
            payloads.CreateKeyPairRequestPayload,
            **kwargs
        )

        args = (
            payloads.CreateKeyPairRequestPayload(),
            "public_protection_storage_masks",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The public protection storage masks must be a "
            "ProtectionStorageMasks structure.",
            setattr,
            *args
        )
        args = (
            payloads.CreateKeyPairRequestPayload(),
            "public_protection_storage_masks",
            objects.ProtectionStorageMasks()
        )
        self.assertRaisesRegex(
            TypeError,
            "The public protection storage masks must be a "
            "ProtectionStorageMasks structure with a "
            "PublicProtectionStorageMasks tag.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a CreateKeyPair request payload can be read from a data
        stream.
        """
        payload = payloads.CreateKeyPairRequestPayload()

        self.assertIsNone(payload.common_template_attribute)
        self.assertIsNone(payload.private_key_template_attribute)
        self.assertIsNone(payload.public_key_template_attribute)

        payload.read(self.full_encoding)

        self.assertEqual(
            objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.RSA,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=1024,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ],
                tag=enums.Tags.COMMON_TEMPLATE_ATTRIBUTE
            ),
            payload.common_template_attribute
        )
        self.assertEqual(
            objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName("Name"),
                        attribute_value=attributes.Name(
                            name_value=attributes.Name.NameValue(
                                "PrivateKey1"
                            ),
                            name_type=attributes.Name.NameType(
                                enums.NameType.UNINTERPRETED_TEXT_STRING
                            )
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            value=enums.CryptographicUsageMask.SIGN.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ],
                tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
            ),
            payload.private_key_template_attribute
        )
        self.assertEqual(
            objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName("Name"),
                        attribute_value=attributes.Name(
                            name_value=attributes.Name.NameValue(
                                "PublicKey1"
                            ),
                            name_type=attributes.Name.NameType(
                                enums.NameType.UNINTERPRETED_TEXT_STRING
                            )
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            value=enums.CryptographicUsageMask.VERIFY.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ],
                tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
            ),
            payload.public_key_template_attribute
        )

    def test_read_kmip_2_0(self):
        """
        Test that a CreateKeyPair request payload can be read from a data
        stream encoded with the KMIP 2.0 format.
        """
        payload = payloads.CreateKeyPairRequestPayload()

        self.assertIsNone(payload.common_template_attribute)
        self.assertIsNone(payload.private_key_template_attribute)
        self.assertIsNone(payload.public_key_template_attribute)
        self.assertIsNone(payload.common_protection_storage_masks)
        self.assertIsNone(payload.private_protection_storage_masks)
        self.assertIsNone(payload.public_protection_storage_masks)

        payload.read(
            self.full_encoding_with_protection_masks,
            kmip_version=enums.KMIPVersion.KMIP_2_0
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
                            value=enums.CryptographicAlgorithm.RSA,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=1024,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ],
                tag=enums.Tags.COMMON_TEMPLATE_ATTRIBUTE
            ),
            payload.common_template_attribute
        )
        self.assertEqual(
            objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName("Name"),
                        attribute_value=attributes.Name(
                            name_value=attributes.Name.NameValue(
                                "PrivateKey1"
                            ),
                            name_type=attributes.Name.NameType(
                                enums.NameType.UNINTERPRETED_TEXT_STRING
                            )
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            value=enums.CryptographicUsageMask.SIGN.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ],
                tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
            ),
            payload.private_key_template_attribute
        )
        self.assertEqual(
            objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName("Name"),
                        attribute_value=attributes.Name(
                            name_value=attributes.Name.NameValue(
                                "PublicKey1"
                            ),
                            name_type=attributes.Name.NameType(
                                enums.NameType.UNINTERPRETED_TEXT_STRING
                            )
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            value=enums.CryptographicUsageMask.VERIFY.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ],
                tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
            ),
            payload.public_key_template_attribute
        )
        self.assertEqual(
            objects.ProtectionStorageMasks(
                protection_storage_masks=[3, 768],
                tag=enums.Tags.COMMON_PROTECTION_STORAGE_MASKS
            ),
            payload.common_protection_storage_masks
        )
        self.assertEqual(
            objects.ProtectionStorageMasks(
                protection_storage_masks=[768],
                tag=enums.Tags.PRIVATE_PROTECTION_STORAGE_MASKS
            ),
            payload.private_protection_storage_masks
        )
        self.assertEqual(
            objects.ProtectionStorageMasks(
                protection_storage_masks=[3],
                tag=enums.Tags.PUBLIC_PROTECTION_STORAGE_MASKS
            ),
            payload.public_protection_storage_masks
        )

    def test_read_missing_common_template_attribute(self):
        """
        Test that a CreateKeyPair request payload can be read from a data
        stream even when missing the common template attribute.
        """
        payload = payloads.CreateKeyPairRequestPayload()

        self.assertIsNone(payload.common_template_attribute)
        self.assertIsNone(payload.private_key_template_attribute)
        self.assertIsNone(payload.public_key_template_attribute)

        payload.read(self.no_common_template_attribute_encoding)

        self.assertIsNone(payload.common_template_attribute)
        self.assertEqual(
            objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName("Name"),
                        attribute_value=attributes.Name(
                            name_value=attributes.Name.NameValue(
                                "PrivateKey1"
                            ),
                            name_type=attributes.Name.NameType(
                                enums.NameType.UNINTERPRETED_TEXT_STRING
                            )
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            value=enums.CryptographicUsageMask.SIGN.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ],
                tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
            ),
            payload.private_key_template_attribute
        )
        self.assertEqual(
            objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName("Name"),
                        attribute_value=attributes.Name(
                            name_value=attributes.Name.NameValue(
                                "PublicKey1"
                            ),
                            name_type=attributes.Name.NameType(
                                enums.NameType.UNINTERPRETED_TEXT_STRING
                            )
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            value=enums.CryptographicUsageMask.VERIFY.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ],
                tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
            ),
            payload.public_key_template_attribute
        )

    def test_read_missing_private_key_template_attribute(self):
        """
        Test that a CreateKeyPair request payload can be read from a data
        stream even when missing the private key template attribute.
        """
        payload = payloads.CreateKeyPairRequestPayload()

        self.assertIsNone(payload.common_template_attribute)
        self.assertIsNone(payload.private_key_template_attribute)
        self.assertIsNone(payload.public_key_template_attribute)

        payload.read(self.no_private_key_template_attr_encoding)

        self.assertEqual(
            objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.RSA,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=1024,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ],
                tag=enums.Tags.COMMON_TEMPLATE_ATTRIBUTE
            ),
            payload.common_template_attribute
        )
        self.assertIsNone(payload.private_key_template_attribute)
        self.assertEqual(
            objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName("Name"),
                        attribute_value=attributes.Name(
                            name_value=attributes.Name.NameValue(
                                "PublicKey1"
                            ),
                            name_type=attributes.Name.NameType(
                                enums.NameType.UNINTERPRETED_TEXT_STRING
                            )
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            value=enums.CryptographicUsageMask.VERIFY.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ],
                tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
            ),
            payload.public_key_template_attribute
        )

    def test_read_missing_public_key_template_attribute(self):
        """
        Test that a CreateKeyPair request payload can be read from a data
        stream even when missing the public key template attribute.
        """
        payload = payloads.CreateKeyPairRequestPayload()

        self.assertIsNone(payload.common_template_attribute)
        self.assertIsNone(payload.private_key_template_attribute)
        self.assertIsNone(payload.public_key_template_attribute)

        payload.read(self.no_public_key_template_attribute_encoding)

        self.assertEqual(
            objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.RSA,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=1024,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ],
                tag=enums.Tags.COMMON_TEMPLATE_ATTRIBUTE
            ),
            payload.common_template_attribute
        )
        self.assertEqual(
            objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName("Name"),
                        attribute_value=attributes.Name(
                            name_value=attributes.Name.NameValue(
                                "PrivateKey1"
                            ),
                            name_type=attributes.Name.NameType(
                                enums.NameType.UNINTERPRETED_TEXT_STRING
                            )
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            value=enums.CryptographicUsageMask.SIGN.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ],
                tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
            ),
            payload.private_key_template_attribute
        )
        self.assertIsNone(payload.public_key_template_attribute)

    def test_read_missing_everything(self):
        """
        Test that a CreateKeyPair request payload can be read from a data
        stream even when missing all fields.
        """
        payload = payloads.CreateKeyPairRequestPayload()

        self.assertIsNone(payload.common_template_attribute)
        self.assertIsNone(payload.private_key_template_attribute)
        self.assertIsNone(payload.public_key_template_attribute)

        payload.read(self.empty_encoding)

        self.assertIsNone(payload.common_template_attribute)
        self.assertIsNone(payload.private_key_template_attribute)
        self.assertIsNone(payload.public_key_template_attribute)

    def test_write(self):
        """
        Test that a CreateKeyPair request payload can be written to a data
        stream.
        """
        payload = payloads.CreateKeyPairRequestPayload(
            common_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.RSA,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=1024,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ],
                tag=enums.Tags.COMMON_TEMPLATE_ATTRIBUTE
            ),
            private_key_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName("Name"),
                        attribute_value=attributes.Name(
                            name_value=attributes.Name.NameValue(
                                "PrivateKey1"
                            ),
                            name_type=attributes.Name.NameType(
                                enums.NameType.UNINTERPRETED_TEXT_STRING
                            )
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            value=enums.CryptographicUsageMask.SIGN.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ],
                tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
            ),
            public_key_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName("Name"),
                        attribute_value=attributes.Name(
                            name_value=attributes.Name.NameValue(
                                "PublicKey1"
                            ),
                            name_type=attributes.Name.NameType(
                                enums.NameType.UNINTERPRETED_TEXT_STRING
                            )
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            value=enums.CryptographicUsageMask.VERIFY.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ],
                tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
            )
        )

        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_kmip_2_0(self):
        """
        Test that a CreateKeyPair request payload can be written to a data
        stream encoded with the KMIP 2.0 format.
        """
        payload = payloads.CreateKeyPairRequestPayload(
            common_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.RSA,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=1024,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ],
                tag=enums.Tags.COMMON_TEMPLATE_ATTRIBUTE
            ),
            private_key_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName("Name"),
                        attribute_value=attributes.Name(
                            name_value=attributes.Name.NameValue(
                                "PrivateKey1"
                            ),
                            name_type=attributes.Name.NameType(
                                enums.NameType.UNINTERPRETED_TEXT_STRING
                            )
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            value=enums.CryptographicUsageMask.SIGN.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ],
                tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
            ),
            public_key_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName("Name"),
                        attribute_value=attributes.Name(
                            name_value=attributes.Name.NameValue(
                                "PublicKey1"
                            ),
                            name_type=attributes.Name.NameType(
                                enums.NameType.UNINTERPRETED_TEXT_STRING
                            )
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            value=enums.CryptographicUsageMask.VERIFY.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ],
                tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
            ),
            common_protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[3, 768],
                tag=enums.Tags.COMMON_PROTECTION_STORAGE_MASKS
            ),
            private_protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[768],
                tag=enums.Tags.PRIVATE_PROTECTION_STORAGE_MASKS
            ),
            public_protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[3],
                tag=enums.Tags.PUBLIC_PROTECTION_STORAGE_MASKS
            )
        )

        stream = utils.BytearrayStream()
        payload.write(stream, kmip_version=enums.KMIPVersion.KMIP_2_0)

        self.assertEqual(
            len(self.full_encoding_with_protection_masks),
            len(stream)
        )
        self.assertEqual(
            str(self.full_encoding_with_protection_masks),
            str(stream)
        )

    def test_write_missing_common_template_attribute(self):
        """
        Test that a CreateKeyPair request payload can be written to a data
        stream even when missing the common template attribute.
        """
        payload = payloads.CreateKeyPairRequestPayload(
            private_key_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName("Name"),
                        attribute_value=attributes.Name(
                            name_value=attributes.Name.NameValue(
                                "PrivateKey1"
                            ),
                            name_type=attributes.Name.NameType(
                                enums.NameType.UNINTERPRETED_TEXT_STRING
                            )
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            value=enums.CryptographicUsageMask.SIGN.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ],
                tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
            ),
            public_key_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName("Name"),
                        attribute_value=attributes.Name(
                            name_value=attributes.Name.NameValue(
                                "PublicKey1"
                            ),
                            name_type=attributes.Name.NameType(
                                enums.NameType.UNINTERPRETED_TEXT_STRING
                            )
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            value=enums.CryptographicUsageMask.VERIFY.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ],
                tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
            )
        )

        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(
            len(self.no_common_template_attribute_encoding),
            len(stream)
        )
        self.assertEqual(
            str(self.no_common_template_attribute_encoding),
            str(stream)
        )

    def test_write_missing_private_key_template_attribute(self):
        """
        Test that a CreateKeyPair request payload can be written to a data
        stream even when missing the private key template attribute.
        """
        payload = payloads.CreateKeyPairRequestPayload(
            common_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.RSA,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=1024,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ],
                tag=enums.Tags.COMMON_TEMPLATE_ATTRIBUTE
            ),
            public_key_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName("Name"),
                        attribute_value=attributes.Name(
                            name_value=attributes.Name.NameValue(
                                "PublicKey1"
                            ),
                            name_type=attributes.Name.NameType(
                                enums.NameType.UNINTERPRETED_TEXT_STRING
                            )
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            value=enums.CryptographicUsageMask.VERIFY.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ],
                tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
            )
        )

        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(
            len(self.no_private_key_template_attr_encoding),
            len(stream)
        )
        self.assertEqual(
            str(self.no_private_key_template_attr_encoding),
            str(stream)
        )

    def test_write_missing_public_key_template_attribute(self):
        """
        Test that a CreateKeyPair request payload can be written to a data
        stream even when missing the public key template attribute.
        """
        payload = payloads.CreateKeyPairRequestPayload(
            common_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.RSA,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=1024,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ],
                tag=enums.Tags.COMMON_TEMPLATE_ATTRIBUTE
            ),
            private_key_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName("Name"),
                        attribute_value=attributes.Name(
                            name_value=attributes.Name.NameValue(
                                "PrivateKey1"
                            ),
                            name_type=attributes.Name.NameType(
                                enums.NameType.UNINTERPRETED_TEXT_STRING
                            )
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            value=enums.CryptographicUsageMask.SIGN.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ],
                tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
            )
        )

        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(
            len(self.no_public_key_template_attribute_encoding),
            len(stream)
        )
        self.assertEqual(
            str(self.no_public_key_template_attribute_encoding),
            str(stream)
        )

    def test_write_missing_everything(self):
        """
        Test that a CreateKeyPair request payload can be written to a data
        stream even when missing all fields.
        """
        payload = payloads.CreateKeyPairRequestPayload()

        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.empty_encoding), len(stream))
        self.assertEqual(str(self.empty_encoding), str(stream))

    def test_repr(self):
        """
        Test that repr can be applied to a CreateKeyPair request payload
        structure.
        """
        payload = payloads.CreateKeyPairRequestPayload(
            common_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.RSA,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=1024,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ],
                tag=enums.Tags.COMMON_TEMPLATE_ATTRIBUTE
            ),
            private_key_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName("Name"),
                        attribute_value=attributes.Name(
                            name_value=attributes.Name.NameValue(
                                "PrivateKey1"
                            ),
                            name_type=attributes.Name.NameType(
                                enums.NameType.UNINTERPRETED_TEXT_STRING
                            )
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            value=enums.CryptographicUsageMask.SIGN.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ],
                tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
            ),
            public_key_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName("Name"),
                        attribute_value=attributes.Name(
                            name_value=attributes.Name.NameValue(
                                "PublicKey1"
                            ),
                            name_type=attributes.Name.NameType(
                                enums.NameType.UNINTERPRETED_TEXT_STRING
                            )
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            value=enums.CryptographicUsageMask.VERIFY.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ],
                tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
            )
        )
        self.assertEqual(
            "CreateKeyPairRequestPayload("
            "common_template_attribute=Struct(), "
            "private_key_template_attribute=Struct(), "
            "public_key_template_attribute=Struct(), "
            "common_protection_storage_masks=None, "
            "private_protection_storage_masks=None, "
            "public_protection_storage_masks=None)",
            repr(payload)
        )

    def test_str(self):
        """
        Test that str can be applied to a CreateKeyPair request payload
        structure.
        """
        payload = payloads.CreateKeyPairRequestPayload(
            common_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.RSA,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=1024,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ],
                tag=enums.Tags.COMMON_TEMPLATE_ATTRIBUTE
            ),
            private_key_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName("Name"),
                        attribute_value=attributes.Name(
                            name_value=attributes.Name.NameValue(
                                "PrivateKey1"
                            ),
                            name_type=attributes.Name.NameType(
                                enums.NameType.UNINTERPRETED_TEXT_STRING
                            )
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            value=enums.CryptographicUsageMask.SIGN.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ],
                tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
            ),
            public_key_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName("Name"),
                        attribute_value=attributes.Name(
                            name_value=attributes.Name.NameValue(
                                "PublicKey1"
                            ),
                            name_type=attributes.Name.NameType(
                                enums.NameType.UNINTERPRETED_TEXT_STRING
                            )
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            value=enums.CryptographicUsageMask.VERIFY.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ],
                tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
            )
        )
        self.assertEqual(
            '{'
            '"common_template_attribute": Struct(), '
            '"private_key_template_attribute": Struct(), '
            '"public_key_template_attribute": Struct(), '
            '"common_protection_storage_masks": None, '
            '"private_protection_storage_masks": None, '
            '"public_protection_storage_masks": None'
            '}',
            str(payload)
        )

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        CreateKeyPair request payloads with the same data.
        """
        a = payloads.CreateKeyPairRequestPayload()
        b = payloads.CreateKeyPairRequestPayload()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = payloads.CreateKeyPairRequestPayload(
            common_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.RSA,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=1024,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ],
                tag=enums.Tags.COMMON_TEMPLATE_ATTRIBUTE
            ),
            private_key_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName("Name"),
                        attribute_value=attributes.Name(
                            name_value=attributes.Name.NameValue(
                                "PrivateKey1"
                            ),
                            name_type=attributes.Name.NameType(
                                enums.NameType.UNINTERPRETED_TEXT_STRING
                            )
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            value=enums.CryptographicUsageMask.SIGN.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ],
                tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
            ),
            public_key_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName("Name"),
                        attribute_value=attributes.Name(
                            name_value=attributes.Name.NameValue(
                                "PublicKey1"
                            ),
                            name_type=attributes.Name.NameType(
                                enums.NameType.UNINTERPRETED_TEXT_STRING
                            )
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            value=enums.CryptographicUsageMask.VERIFY.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ],
                tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
            ),
            common_protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[3, 768],
                tag=enums.Tags.COMMON_PROTECTION_STORAGE_MASKS
            ),
            private_protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[768],
                tag=enums.Tags.PRIVATE_PROTECTION_STORAGE_MASKS
            ),
            public_protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[3],
                tag=enums.Tags.PUBLIC_PROTECTION_STORAGE_MASKS
            )
        )
        b = payloads.CreateKeyPairRequestPayload(
            common_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.RSA,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=1024,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ],
                tag=enums.Tags.COMMON_TEMPLATE_ATTRIBUTE
            ),
            private_key_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName("Name"),
                        attribute_value=attributes.Name(
                            name_value=attributes.Name.NameValue(
                                "PrivateKey1"
                            ),
                            name_type=attributes.Name.NameType(
                                enums.NameType.UNINTERPRETED_TEXT_STRING
                            )
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            value=enums.CryptographicUsageMask.SIGN.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ],
                tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
            ),
            public_key_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName("Name"),
                        attribute_value=attributes.Name(
                            name_value=attributes.Name.NameValue(
                                "PublicKey1"
                            ),
                            name_type=attributes.Name.NameType(
                                enums.NameType.UNINTERPRETED_TEXT_STRING
                            )
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            value=enums.CryptographicUsageMask.VERIFY.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ],
                tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
            ),
            common_protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[3, 768],
                tag=enums.Tags.COMMON_PROTECTION_STORAGE_MASKS
            ),
            private_protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[768],
                tag=enums.Tags.PRIVATE_PROTECTION_STORAGE_MASKS
            ),
            public_protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[3],
                tag=enums.Tags.PUBLIC_PROTECTION_STORAGE_MASKS
            )
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_common_template_attribute(self):
        """
        Test that the equality operator returns False when comparing two
        CreateKeyPair request payloads with different common template
        attributes.
        """
        a = payloads.CreateKeyPairRequestPayload(
            common_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.RSA,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    )
                ],
                tag=enums.Tags.COMMON_TEMPLATE_ATTRIBUTE
            )
        )
        b = payloads.CreateKeyPairRequestPayload(
            common_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=1024,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ],
                tag=enums.Tags.COMMON_TEMPLATE_ATTRIBUTE
            )
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_private_key_template_attribute(self):
        """
        Test that the equality operator returns False when comparing two
        CreateKeyPair request payloads with different private key template
        attributes.
        """
        a = payloads.CreateKeyPairRequestPayload(
            private_key_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName("Name"),
                        attribute_value=attributes.Name(
                            name_value=attributes.Name.NameValue(
                                "PrivateKey1"
                            ),
                            name_type=attributes.Name.NameType(
                                enums.NameType.UNINTERPRETED_TEXT_STRING
                            )
                        )
                    )
                ],
                tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
            )
        )
        b = payloads.CreateKeyPairRequestPayload(
            private_key_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            value=enums.CryptographicUsageMask.SIGN.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ],
                tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
            )
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_public_key_template_attribute(self):
        """
        Test that the equality operator returns False when comparing two
        CreateKeyPair request payloads with different public key template
        attributes.
        """
        a = payloads.CreateKeyPairRequestPayload(
            public_key_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName("Name"),
                        attribute_value=attributes.Name(
                            name_value=attributes.Name.NameValue(
                                "PublicKey1"
                            ),
                            name_type=attributes.Name.NameType(
                                enums.NameType.UNINTERPRETED_TEXT_STRING
                            )
                        )
                    )
                ],
                tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
            )
        )
        b = payloads.CreateKeyPairRequestPayload(
            public_key_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            value=enums.CryptographicUsageMask.VERIFY.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ],
                tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
            )
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_common_protection_storage_masks(self):
        """
        Test that the equality operator returns False when comparing two
        CreateKeyPair request payloads with different common protection
        storage masks.
        """
        a = payloads.CreateKeyPairRequestPayload(
            common_protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[3],
                tag=enums.Tags.COMMON_PROTECTION_STORAGE_MASKS
            )
        )
        b = payloads.CreateKeyPairRequestPayload(
            common_protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[768],
                tag=enums.Tags.COMMON_PROTECTION_STORAGE_MASKS
            )
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_private_protection_storage_masks(self):
        """
        Test that the equality operator returns False when comparing two
        CreateKeyPair request payloads with different private protection
        storage masks.
        """
        a = payloads.CreateKeyPairRequestPayload(
            private_protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[3],
                tag=enums.Tags.PRIVATE_PROTECTION_STORAGE_MASKS
            )
        )
        b = payloads.CreateKeyPairRequestPayload(
            private_protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[768],
                tag=enums.Tags.PRIVATE_PROTECTION_STORAGE_MASKS
            )
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_public_protection_storage_masks(self):
        """
        Test that the equality operator returns False when comparing two
        CreateKeyPair request payloads with different public protection
        storage masks.
        """
        a = payloads.CreateKeyPairRequestPayload(
            public_protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[3],
                tag=enums.Tags.PUBLIC_PROTECTION_STORAGE_MASKS
            )
        )
        b = payloads.CreateKeyPairRequestPayload(
            public_protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[768],
                tag=enums.Tags.PUBLIC_PROTECTION_STORAGE_MASKS
            )
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        CreateKeyPair request payloads with different types.
        """
        a = payloads.CreateKeyPairRequestPayload()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        CreateKeyPair request payloads with the same data.
        """
        a = payloads.CreateKeyPairRequestPayload()
        b = payloads.CreateKeyPairRequestPayload()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = payloads.CreateKeyPairRequestPayload(
            common_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.RSA,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=1024,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ],
                tag=enums.Tags.COMMON_TEMPLATE_ATTRIBUTE
            ),
            private_key_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName("Name"),
                        attribute_value=attributes.Name(
                            name_value=attributes.Name.NameValue(
                                "PrivateKey1"
                            ),
                            name_type=attributes.Name.NameType(
                                enums.NameType.UNINTERPRETED_TEXT_STRING
                            )
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            value=enums.CryptographicUsageMask.SIGN.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ],
                tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
            ),
            public_key_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName("Name"),
                        attribute_value=attributes.Name(
                            name_value=attributes.Name.NameValue(
                                "PublicKey1"
                            ),
                            name_type=attributes.Name.NameType(
                                enums.NameType.UNINTERPRETED_TEXT_STRING
                            )
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            value=enums.CryptographicUsageMask.VERIFY.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ],
                tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
            ),
            common_protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[3, 768],
                tag=enums.Tags.COMMON_PROTECTION_STORAGE_MASKS
            ),
            private_protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[768],
                tag=enums.Tags.PRIVATE_PROTECTION_STORAGE_MASKS
            ),
            public_protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[3],
                tag=enums.Tags.PUBLIC_PROTECTION_STORAGE_MASKS
            )
        )
        b = payloads.CreateKeyPairRequestPayload(
            common_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.RSA,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=1024,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ],
                tag=enums.Tags.COMMON_TEMPLATE_ATTRIBUTE
            ),
            private_key_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName("Name"),
                        attribute_value=attributes.Name(
                            name_value=attributes.Name.NameValue(
                                "PrivateKey1"
                            ),
                            name_type=attributes.Name.NameType(
                                enums.NameType.UNINTERPRETED_TEXT_STRING
                            )
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            value=enums.CryptographicUsageMask.SIGN.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ],
                tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
            ),
            public_key_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName("Name"),
                        attribute_value=attributes.Name(
                            name_value=attributes.Name.NameValue(
                                "PublicKey1"
                            ),
                            name_type=attributes.Name.NameType(
                                enums.NameType.UNINTERPRETED_TEXT_STRING
                            )
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            value=enums.CryptographicUsageMask.VERIFY.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ],
                tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
            ),
            common_protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[3, 768],
                tag=enums.Tags.COMMON_PROTECTION_STORAGE_MASKS
            ),
            private_protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[768],
                tag=enums.Tags.PRIVATE_PROTECTION_STORAGE_MASKS
            ),
            public_protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[3],
                tag=enums.Tags.PUBLIC_PROTECTION_STORAGE_MASKS
            )
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_common_template_attribute(self):
        """
        Test that the inequality operator returns True when comparing two
        CreateKeyPair request payloads with different common template
        attributes.
        """
        a = payloads.CreateKeyPairRequestPayload(
            common_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.RSA,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    )
                ],
                tag=enums.Tags.COMMON_TEMPLATE_ATTRIBUTE
            )
        )
        b = payloads.CreateKeyPairRequestPayload(
            common_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=1024,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ],
                tag=enums.Tags.COMMON_TEMPLATE_ATTRIBUTE
            )
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_private_key_template_attribute(self):
        """
        Test that the inequality operator returns True when comparing two
        CreateKeyPair request payloads with different private key template
        attributes.
        """
        a = payloads.CreateKeyPairRequestPayload(
            private_key_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName("Name"),
                        attribute_value=attributes.Name(
                            name_value=attributes.Name.NameValue(
                                "PrivateKey1"
                            ),
                            name_type=attributes.Name.NameType(
                                enums.NameType.UNINTERPRETED_TEXT_STRING
                            )
                        )
                    )
                ],
                tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
            )
        )
        b = payloads.CreateKeyPairRequestPayload(
            private_key_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            value=enums.CryptographicUsageMask.SIGN.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ],
                tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
            )
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_public_key_template_attribute(self):
        """
        Test that the inequality operator returns True when comparing two
        CreateKeyPair request payloads with different public key template
        attributes.
        """
        a = payloads.CreateKeyPairRequestPayload(
            public_key_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName("Name"),
                        attribute_value=attributes.Name(
                            name_value=attributes.Name.NameValue(
                                "PublicKey1"
                            ),
                            name_type=attributes.Name.NameType(
                                enums.NameType.UNINTERPRETED_TEXT_STRING
                            )
                        )
                    )
                ],
                tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
            )
        )
        b = payloads.CreateKeyPairRequestPayload(
            public_key_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            value=enums.CryptographicUsageMask.VERIFY.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ],
                tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
            )
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_common_protection_storage_masks(self):
        """
        Test that the inequality operator returns True when comparing two
        CreateKeyPair request payloads with different common protection
        storage masks.
        """
        a = payloads.CreateKeyPairRequestPayload(
            common_protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[3],
                tag=enums.Tags.COMMON_PROTECTION_STORAGE_MASKS
            )
        )
        b = payloads.CreateKeyPairRequestPayload(
            common_protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[768],
                tag=enums.Tags.COMMON_PROTECTION_STORAGE_MASKS
            )
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_private_protection_storage_masks(self):
        """
        Test that the inequality operator returns True when comparing two
        CreateKeyPair request payloads with different private protection
        storage masks.
        """
        a = payloads.CreateKeyPairRequestPayload(
            private_protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[3],
                tag=enums.Tags.PRIVATE_PROTECTION_STORAGE_MASKS
            )
        )
        b = payloads.CreateKeyPairRequestPayload(
            private_protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[768],
                tag=enums.Tags.PRIVATE_PROTECTION_STORAGE_MASKS
            )
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_public_protection_storage_masks(self):
        """
        Test that the inequality operator returns True when comparing two
        CreateKeyPair request payloads with different public protection
        storage masks.
        """
        a = payloads.CreateKeyPairRequestPayload(
            public_protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[3],
                tag=enums.Tags.PUBLIC_PROTECTION_STORAGE_MASKS
            )
        )
        b = payloads.CreateKeyPairRequestPayload(
            public_protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[768],
                tag=enums.Tags.PUBLIC_PROTECTION_STORAGE_MASKS
            )
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        CreateKeyPair request payloads with different types.
        """
        a = payloads.CreateKeyPairRequestPayload()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_init(self):
        """
        Test that a CreateKeyPair request payload can be constructed with no
        arguments.
        """
        payload = payloads.CreateKeyPairRequestPayload()
        self.assertIsNone(payload.common_template_attribute)
        self.assertIsNone(payload.private_key_template_attribute)
        self.assertIsNone(payload.public_key_template_attribute)

    def test_init_with_args(self):
        """
        Test that a CreateKeyPair request payload can be constructed with
        valid values.
        """
        payload = payloads.CreateKeyPairRequestPayload(
            common_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.RSA,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=1024,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ],
                tag=enums.Tags.COMMON_TEMPLATE_ATTRIBUTE
            ),
            private_key_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName("Name"),
                        attribute_value=attributes.Name(
                            name_value=attributes.Name.NameValue(
                                "PrivateKey1"
                            ),
                            name_type=attributes.Name.NameType(
                                enums.NameType.UNINTERPRETED_TEXT_STRING
                            )
                        )
                    )
                ],
                tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
            ),
            public_key_template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName("Name"),
                        attribute_value=attributes.Name(
                            name_value=attributes.Name.NameValue(
                                "PublicKey1"
                            ),
                            name_type=attributes.Name.NameType(
                                enums.NameType.UNINTERPRETED_TEXT_STRING
                            )
                        )
                    )
                ],
                tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
            )
        )

        self.assertIsInstance(
            payload.common_template_attribute,
            objects.TemplateAttribute
        )
        self.assertIsInstance(
            payload.private_key_template_attribute,
            objects.TemplateAttribute
        )
        self.assertIsInstance(
            payload.public_key_template_attribute,
            objects.TemplateAttribute
        )

    def test_read_valid(self):
        """
        Test that a CreateKeyPair request payload can be read from a valid
        byte stream.
        """
        self.test_read()

    def test_read_missing_required_field(self):
        """
        Test that an exception is raised when reading a payload missing a
        required field.
        """
        payload = payloads.CreateKeyPairRequestPayload()
        self.assertRaises(Exception, payload.read, utils.BytearrayStream(b''))

    def test_write_valid(self):
        """
        Test that a CreateKeyPair request payload can be written to a byte
        stream.
        """
        self.test_write()

    def test_read_write_roundtrip(self):
        """
        Test that a CreateKeyPair request payload can be read and written
        without changing the encoded bytes.
        """
        payload = payloads.CreateKeyPairRequestPayload()
        payload.read(utils.BytearrayStream(self.full_encoding.buffer))

        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(str(self.full_encoding), str(stream))

    def test_validate_invalid(self):
        """
        Test that an exception is raised when a field has an invalid type.
        """
        self.test_invalid_common_template_attribute()

    def test_eq(self):
        """
        Test that two CreateKeyPair request payloads with the same data are
        equal.
        """
        self.test_equal_on_equal()

    def test_ne(self):
        """
        Test that two CreateKeyPair request payloads with different data are
        not equal.
        """
        self.test_not_equal_on_not_equal_common_template_attribute()

class TestCreateKeyPairResponsePayload(testtools.TestCase):

    def setUp(self):
        super(TestCreateKeyPairResponsePayload, self).setUp()

        # Encoding obtained from the KMIP 1.1 testing document, Section 8.1.0.
        # Modified to include the Private Key Template Attribute and the
        # Public Key Template Attribute.
        #
        # This encoding matches the following set of values:
        # Response Payload
        #     Private Key Unique Identifier -
        #         7f7ee394-40f9-444c-818c-fb1ae57bdf15
        #     Public Key Unique Identifier -
        #         79c0eb55-d020-43de-b72f-5e18c862647c
        #     Private Key Template Attribute
        #         Attribute
        #             Attribute Name - State
        #             Attribute Value - Pre-Active
        #     Public Key Template Attribute
        #         Attribute
        #             Attribute Name - State
        #             Attribute Value
        #                 Name Value - Pre-Active
        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\xC0'
            b'\x42\x00\x66\x07\x00\x00\x00\x24'
            b'\x37\x66\x37\x65\x65\x33\x39\x34\x2D\x34\x30\x66\x39\x2D\x34\x34'
            b'\x34\x63\x2D\x38\x31\x38\x63\x2D\x66\x62\x31\x61\x65\x35\x37\x62'
            b'\x64\x66\x31\x35\x00\x00\x00\x00'
            b'\x42\x00\x6F\x07\x00\x00\x00\x24'
            b'\x37\x39\x63\x30\x65\x62\x35\x35\x2D\x64\x30\x32\x30\x2D\x34\x33'
            b'\x64\x65\x2D\x62\x37\x32\x66\x2D\x35\x65\x31\x38\x63\x38\x36\x32'
            b'\x36\x34\x37\x63\x00\x00\x00\x00'
            b'\x42\x00\x65\x01\x00\x00\x00\x28'
            b'\x42\x00\x08\x01\x00\x00\x00\x20'
            b'\x42\x00\x0A\x07\x00\x00\x00\x05'
            b'\x53\x74\x61\x74\x65\x00\x00\x00'
            b'\x42\x00\x0B\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x6E\x01\x00\x00\x00\x28'
            b'\x42\x00\x08\x01\x00\x00\x00\x20'
            b'\x42\x00\x0A\x07\x00\x00\x00\x05'
            b'\x53\x74\x61\x74\x65\x00\x00\x00'
            b'\x42\x00\x0B\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
        )

        # Encoding obtained from the KMIP 1.1 testing document, Section 8.1.0.
        # Modified to include the Private Key Template Attribute and the
        # Public Key Template Attribute.
        #
        # This encoding matches the following set of values:
        # Response Payload
        #     Public Key Unique Identifier -
        #         79c0eb55-d020-43de-b72f-5e18c862647c
        #     Private Key Template Attribute
        #         Attribute
        #             Attribute Name - State
        #             Attribute Value - Pre-Active
        #     Public Key Template Attribute
        #         Attribute
        #             Attribute Name - State
        #             Attribute Value
        #                 Name Value - Pre-Active
        self.no_private_key_unique_identifier_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x90'
            b'\x42\x00\x6F\x07\x00\x00\x00\x24'
            b'\x37\x39\x63\x30\x65\x62\x35\x35\x2D\x64\x30\x32\x30\x2D\x34\x33'
            b'\x64\x65\x2D\x62\x37\x32\x66\x2D\x35\x65\x31\x38\x63\x38\x36\x32'
            b'\x36\x34\x37\x63\x00\x00\x00\x00'
            b'\x42\x00\x65\x01\x00\x00\x00\x28'
            b'\x42\x00\x08\x01\x00\x00\x00\x20'
            b'\x42\x00\x0A\x07\x00\x00\x00\x05'
            b'\x53\x74\x61\x74\x65\x00\x00\x00'
            b'\x42\x00\x0B\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x6E\x01\x00\x00\x00\x28'
            b'\x42\x00\x08\x01\x00\x00\x00\x20'
            b'\x42\x00\x0A\x07\x00\x00\x00\x05'
            b'\x53\x74\x61\x74\x65\x00\x00\x00'
            b'\x42\x00\x0B\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
        )

        # Encoding obtained from the KMIP 1.1 testing document, Section 8.1.0.
        # Modified to include the Private Key Template Attribute and the
        # Public Key Template Attribute.
        #
        # This encoding matches the following set of values:
        # Response Payload
        #     Private Key Unique Identifier -
        #         7f7ee394-40f9-444c-818c-fb1ae57bdf15
        #     Private Key Template Attribute
        #         Attribute
        #             Attribute Name - State
        #             Attribute Value - Pre-Active
        #     Public Key Template Attribute
        #         Attribute
        #             Attribute Name - State
        #             Attribute Value
        #                 Name Value - Pre-Active
        self.no_public_key_unique_identifier_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x90'
            b'\x42\x00\x66\x07\x00\x00\x00\x24'
            b'\x37\x66\x37\x65\x65\x33\x39\x34\x2D\x34\x30\x66\x39\x2D\x34\x34'
            b'\x34\x63\x2D\x38\x31\x38\x63\x2D\x66\x62\x31\x61\x65\x35\x37\x62'
            b'\x64\x66\x31\x35\x00\x00\x00\x00'
            b'\x42\x00\x65\x01\x00\x00\x00\x28'
            b'\x42\x00\x08\x01\x00\x00\x00\x20'
            b'\x42\x00\x0A\x07\x00\x00\x00\x05'
            b'\x53\x74\x61\x74\x65\x00\x00\x00'
            b'\x42\x00\x0B\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x6E\x01\x00\x00\x00\x28'
            b'\x42\x00\x08\x01\x00\x00\x00\x20'
            b'\x42\x00\x0A\x07\x00\x00\x00\x05'
            b'\x53\x74\x61\x74\x65\x00\x00\x00'
            b'\x42\x00\x0B\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
        )

        # Encoding obtained from the KMIP 1.1 testing document, Section 8.1.0.
        # Modified to include the Public Key Template Attribute.
        #
        # This encoding matches the following set of values:
        # Response Payload
        #     Private Key Unique Identifier -
        #         7f7ee394-40f9-444c-818c-fb1ae57bdf15
        #     Public Key Unique Identifier -
        #         79c0eb55-d020-43de-b72f-5e18c862647c
        #     Public Key Template Attribute
        #         Attribute
        #             Attribute Name - State
        #             Attribute Value
        #                 Name Value - Pre-Active
        self.no_private_key_template_attr_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x90'
            b'\x42\x00\x66\x07\x00\x00\x00\x24'
            b'\x37\x66\x37\x65\x65\x33\x39\x34\x2D\x34\x30\x66\x39\x2D\x34\x34'
            b'\x34\x63\x2D\x38\x31\x38\x63\x2D\x66\x62\x31\x61\x65\x35\x37\x62'
            b'\x64\x66\x31\x35\x00\x00\x00\x00'
            b'\x42\x00\x6F\x07\x00\x00\x00\x24'
            b'\x37\x39\x63\x30\x65\x62\x35\x35\x2D\x64\x30\x32\x30\x2D\x34\x33'
            b'\x64\x65\x2D\x62\x37\x32\x66\x2D\x35\x65\x31\x38\x63\x38\x36\x32'
            b'\x36\x34\x37\x63\x00\x00\x00\x00'
            b'\x42\x00\x6E\x01\x00\x00\x00\x28'
            b'\x42\x00\x08\x01\x00\x00\x00\x20'
            b'\x42\x00\x0A\x07\x00\x00\x00\x05'
            b'\x53\x74\x61\x74\x65\x00\x00\x00'
            b'\x42\x00\x0B\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
        )

        # Encoding obtained from the KMIP 1.1 testing document, Section 8.1.0.
        # Modified to include the Private Key Template Attribute.
        #
        # This encoding matches the following set of values:
        # Response Payload
        #     Private Key Unique Identifier -
        #         7f7ee394-40f9-444c-818c-fb1ae57bdf15
        #     Public Key Unique Identifier -
        #         79c0eb55-d020-43de-b72f-5e18c862647c
        #     Private Key Template Attribute
        #         Attribute
        #             Attribute Name - State
        #             Attribute Value - Pre-Active
        self.no_public_key_template_attribute_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x90'
            b'\x42\x00\x66\x07\x00\x00\x00\x24'
            b'\x37\x66\x37\x65\x65\x33\x39\x34\x2D\x34\x30\x66\x39\x2D\x34\x34'
            b'\x34\x63\x2D\x38\x31\x38\x63\x2D\x66\x62\x31\x61\x65\x35\x37\x62'
            b'\x64\x66\x31\x35\x00\x00\x00\x00'
            b'\x42\x00\x6F\x07\x00\x00\x00\x24'
            b'\x37\x39\x63\x30\x65\x62\x35\x35\x2D\x64\x30\x32\x30\x2D\x34\x33'
            b'\x64\x65\x2D\x62\x37\x32\x66\x2D\x35\x65\x31\x38\x63\x38\x36\x32'
            b'\x36\x34\x37\x63\x00\x00\x00\x00'
            b'\x42\x00\x65\x01\x00\x00\x00\x28'
            b'\x42\x00\x08\x01\x00\x00\x00\x20'
            b'\x42\x00\x0A\x07\x00\x00\x00\x05'
            b'\x53\x74\x61\x74\x65\x00\x00\x00'
            b'\x42\x00\x0B\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestCreateKeyPairResponsePayload, self).tearDown()

    def test_invalid_private_key_unique_identifier(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the private key unique identifier of a CreateKeyPair response payload.
        """
        kwargs = {"private_key_unique_identifier": 0}
        self.assertRaisesRegex(
            TypeError,
            "Private key unique identifier must be a string.",
            payloads.CreateKeyPairResponsePayload,
            **kwargs
        )

        args = (
            payloads.CreateKeyPairResponsePayload(),
            "private_key_unique_identifier",
            0
        )
        self.assertRaisesRegex(
            TypeError,
            "Private key unique identifier must be a string.",
            setattr,
            *args
        )

    def test_invalid_public_key_unique_identifier(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the public key unique identifier of a CreateKeyPair response payload.
        """
        kwargs = {"public_key_unique_identifier": 0}
        self.assertRaisesRegex(
            TypeError,
            "Public key unique identifier must be a string.",
            payloads.CreateKeyPairResponsePayload,
            **kwargs
        )

        args = (
            payloads.CreateKeyPairResponsePayload(),
            "public_key_unique_identifier",
            0
        )
        self.assertRaisesRegex(
            TypeError,
            "Public key unique identifier must be a string.",
            setattr,
            *args
        )

    def test_invalid_private_key_template_attribute(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the private key template attribute of a CreateKeyPair response payload.
        """
        kwargs = {"private_key_template_attribute": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "Private key template attribute must be a TemplateAttribute "
            "structure.",
            payloads.CreateKeyPairResponsePayload,
            **kwargs
        )

        kwargs = {
            "private_key_template_attribute": objects.TemplateAttribute()
        }
        self.assertRaisesRegex(
            TypeError,
            "Private key template attribute must be a TemplateAttribute "
            "structure with a PrivateKeyTemplateAttribute tag.",
            payloads.CreateKeyPairResponsePayload,
            **kwargs
        )

        args = (
            payloads.CreateKeyPairResponsePayload(),
            "private_key_template_attribute",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "Private key template attribute must be a TemplateAttribute "
            "structure.",
            setattr,
            *args
        )

        args = (
            payloads.CreateKeyPairResponsePayload(),
            "private_key_template_attribute",
            objects.TemplateAttribute()
        )
        self.assertRaisesRegex(
            TypeError,
            "Private key template attribute must be a TemplateAttribute "
            "structure with a PrivateKeyTemplateAttribute tag.",
            setattr,
            *args
        )

    def test_invalid_public_key_template_attribute(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the public key template attribute of a CreateKeyPair response payload.
        """
        kwargs = {"public_key_template_attribute": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "Public key template attribute must be a TemplateAttribute "
            "structure.",
            payloads.CreateKeyPairResponsePayload,
            **kwargs
        )

        kwargs = {"public_key_template_attribute": objects.TemplateAttribute()}
        self.assertRaisesRegex(
            TypeError,
            "Public key template attribute must be a TemplateAttribute "
            "structure with a PublicKeyTemplateAttribute tag.",
            payloads.CreateKeyPairResponsePayload,
            **kwargs
        )

        args = (
            payloads.CreateKeyPairResponsePayload(),
            "public_key_template_attribute",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "Public key template attribute must be a TemplateAttribute "
            "structure.",
            setattr,
            *args
        )

        args = (
            payloads.CreateKeyPairResponsePayload(),
            "public_key_template_attribute",
            objects.TemplateAttribute()
        )
        self.assertRaisesRegex(
            TypeError,
            "Public key template attribute must be a TemplateAttribute "
            "structure with a PublicKeyTemplateAttribute tag.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a CreateKeyPair response payload can be read from a data
        stream.
        """
        payload = payloads.CreateKeyPairResponsePayload()

        self.assertIsNone(payload.private_key_unique_identifier)
        self.assertIsNone(payload.public_key_unique_identifier)
        self.assertIsNone(payload.private_key_template_attribute)
        self.assertIsNone(payload.public_key_template_attribute)

        payload.read(self.full_encoding)

        self.assertEqual(
            "7f7ee394-40f9-444c-818c-fb1ae57bdf15",
            payload.private_key_unique_identifier
        )
        self.assertEqual(
            "79c0eb55-d020-43de-b72f-5e18c862647c",
            payload.public_key_unique_identifier
        )
        self.assertEqual(
            objects.TemplateAttribute(
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
                ],
                tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
            ),
            payload.private_key_template_attribute
        )
        self.assertEqual(
            objects.TemplateAttribute(
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
                ],
                tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
            ),
            payload.public_key_template_attribute
        )

    def test_read_missing_private_key_unique_identifier(self):
        """
        Test that an InvalidKmipEncoding error is raised during the decoding
        of a CreateKeyPair response payload when the private key unique
        identifier is missing from the encoding.
        """
        payload = payloads.CreateKeyPairResponsePayload()

        self.assertEqual(None, payload.private_key_unique_identifier)

        args = (self.no_private_key_unique_identifier_encoding, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The CreateKeyPair response payload encoding is missing the "
            "private key unique identifier.",
            payload.read,
            *args
        )

    def test_read_missing_public_key_unique_identifier(self):
        """
        Test that an InvalidKmipEncoding error is raised during the decoding
        of a CreateKeyPair response payload when the public key unique
        identifier is missing from the encoding.
        """
        payload = payloads.CreateKeyPairResponsePayload()

        self.assertEqual(None, payload.public_key_unique_identifier)

        args = (self.no_public_key_unique_identifier_encoding, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The CreateKeyPair response payload encoding is missing the "
            "public key unique identifier.",
            payload.read,
            *args
        )

    def test_read_missing_private_key_template_attribute(self):
        """
        Test that a CreateKeyPair response payload can be read from a data
        stream event when missing the private key template attribute.
        """
        payload = payloads.CreateKeyPairResponsePayload()

        self.assertIsNone(payload.private_key_unique_identifier)
        self.assertIsNone(payload.public_key_unique_identifier)
        self.assertIsNone(payload.private_key_template_attribute)
        self.assertIsNone(payload.public_key_template_attribute)

        payload.read(self.no_private_key_template_attr_encoding)

        self.assertEqual(
            "7f7ee394-40f9-444c-818c-fb1ae57bdf15",
            payload.private_key_unique_identifier
        )
        self.assertEqual(
            "79c0eb55-d020-43de-b72f-5e18c862647c",
            payload.public_key_unique_identifier
        )
        self.assertIsNone(payload.private_key_template_attribute)
        self.assertEqual(
            objects.TemplateAttribute(
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
                ],
                tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
            ),
            payload.public_key_template_attribute
        )

    def test_read_missing_public_key_template_attribute(self):
        """
        Test that a CreateKeyPair response payload can be read from a data
        stream event when missing the public key template attribute.
        """
        payload = payloads.CreateKeyPairResponsePayload()

        self.assertIsNone(payload.private_key_unique_identifier)
        self.assertIsNone(payload.public_key_unique_identifier)
        self.assertIsNone(payload.private_key_template_attribute)
        self.assertIsNone(payload.public_key_template_attribute)

        payload.read(self.no_public_key_template_attribute_encoding)

        self.assertEqual(
            "7f7ee394-40f9-444c-818c-fb1ae57bdf15",
            payload.private_key_unique_identifier
        )
        self.assertEqual(
            "79c0eb55-d020-43de-b72f-5e18c862647c",
            payload.public_key_unique_identifier
        )
        self.assertEqual(
            objects.TemplateAttribute(
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
                ],
                tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
            ),
            payload.private_key_template_attribute
        )
        self.assertIsNone(payload.public_key_template_attribute)

    def test_write(self):
        """
        Test that a CreateKeyPair response payload can be written to a data
        stream.
        """
        payload = payloads.CreateKeyPairResponsePayload(
            private_key_unique_identifier=(
                "7f7ee394-40f9-444c-818c-fb1ae57bdf15"
            ),
            public_key_unique_identifier=(
                "79c0eb55-d020-43de-b72f-5e18c862647c"
            ),
            private_key_template_attribute=objects.TemplateAttribute(
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
                ],
                tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
            ),
            public_key_template_attribute=objects.TemplateAttribute(
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
                ],
                tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
            )
        )

        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_missing_private_key_unique_identifier(self):
        """
        Test that an InvalidField error is raised during the encoding of a
        CreateKeyPair response payload when the payload is missing the private
        key unique identifier.
        """
        payload = payloads.CreateKeyPairResponsePayload(
            public_key_unique_identifier=(
                "79c0eb55-d020-43de-b72f-5e18c862647c"
            ),
            private_key_template_attribute=objects.TemplateAttribute(
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
                ],
                tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
            ),
            public_key_template_attribute=objects.TemplateAttribute(
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
                ],
                tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
            )
        )

        stream = utils.BytearrayStream()
        args = (stream, )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The CreateKeyPair response payload is missing the private key "
            "unique identifier field.",
            payload.write,
            *args
        )

    def test_write_missing_public_key_unique_identifier(self):
        """
        Test that an InvalidField error is raised during the encoding of a
        CreateKeyPair response payload when the payload is missing the public
        key unique identifier.
        """
        payload = payloads.CreateKeyPairResponsePayload(
            private_key_unique_identifier=(
                "7f7ee394-40f9-444c-818c-fb1ae57bdf15"
            ),
            private_key_template_attribute=objects.TemplateAttribute(
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
                ],
                tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
            ),
            public_key_template_attribute=objects.TemplateAttribute(
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
                ],
                tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
            )
        )

        stream = utils.BytearrayStream()
        args = (stream, )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The CreateKeyPair response payload is missing the public key "
            "unique identifier field.",
            payload.write,
            *args
        )

    def test_write_missing_private_key_template_attribute(self):
        """
        Test that a CreateKeyPair response payload can be written to a data
        stream even when missing the private key template attribute.
        """
        payload = payloads.CreateKeyPairResponsePayload(
            private_key_unique_identifier=(
                "7f7ee394-40f9-444c-818c-fb1ae57bdf15"
            ),
            public_key_unique_identifier=(
                "79c0eb55-d020-43de-b72f-5e18c862647c"
            ),
            public_key_template_attribute=objects.TemplateAttribute(
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
                ],
                tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
            )
        )

        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(
            len(self.no_private_key_template_attr_encoding),
            len(stream)
        )
        self.assertEqual(
            str(self.no_private_key_template_attr_encoding),
            str(stream)
        )

    def test_write_missing_public_key_template_attribute(self):
        """
        Test that a CreateKeyPair response payload can be written to a data
        stream even when missing the public key template attribute.
        """
        payload = payloads.CreateKeyPairResponsePayload(
            private_key_unique_identifier=(
                "7f7ee394-40f9-444c-818c-fb1ae57bdf15"
            ),
            public_key_unique_identifier=(
                "79c0eb55-d020-43de-b72f-5e18c862647c"
            ),
            private_key_template_attribute=objects.TemplateAttribute(
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
                ],
                tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
            )
        )

        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(
            len(self.no_public_key_template_attribute_encoding),
            len(stream)
        )
        self.assertEqual(
            str(self.no_public_key_template_attribute_encoding),
            str(stream)
        )

    def test_repr(self):
        """
        Test that repr can be applied to a CreateKeyPair response payload
        structure.
        """
        payload = payloads.CreateKeyPairResponsePayload(
            private_key_unique_identifier=(
                "7f7ee394-40f9-444c-818c-fb1ae57bdf15"
            ),
            public_key_unique_identifier=(
                "79c0eb55-d020-43de-b72f-5e18c862647c"
            ),
            private_key_template_attribute=objects.TemplateAttribute(
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
                ],
                tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
            ),
            public_key_template_attribute=objects.TemplateAttribute(
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
                ],
                tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
            )
        )
        self.assertEqual(
            "CreateKeyPairResponsePayload("
            "private_key_unique_identifier="
            "'7f7ee394-40f9-444c-818c-fb1ae57bdf15', "
            "public_key_unique_identifier="
            "'79c0eb55-d020-43de-b72f-5e18c862647c', "
            "private_key_template_attribute=Struct(), "
            "public_key_template_attribute=Struct())",
            repr(payload)
        )

    def test_str(self):
        """
        Test that str can be applied to a CreateKeyPair response payload
        structure.
        """
        payload = payloads.CreateKeyPairResponsePayload(
            private_key_unique_identifier=(
                "7f7ee394-40f9-444c-818c-fb1ae57bdf15"
            ),
            public_key_unique_identifier=(
                "79c0eb55-d020-43de-b72f-5e18c862647c"
            ),
            private_key_template_attribute=objects.TemplateAttribute(
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
                ],
                tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
            ),
            public_key_template_attribute=objects.TemplateAttribute(
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
                ],
                tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
            )
        )
        self.assertEqual(
            '{'
            '"private_key_unique_identifier": '
            '"7f7ee394-40f9-444c-818c-fb1ae57bdf15", '
            '"public_key_unique_identifier": '
            '"79c0eb55-d020-43de-b72f-5e18c862647c", '
            '"private_key_template_attribute": Struct(), '
            '"public_key_template_attribute": Struct()'
            '}',
            str(payload)
        )

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        CreateKeyPair response payloads with the same data.
        """
        a = payloads.CreateKeyPairResponsePayload()
        b = payloads.CreateKeyPairResponsePayload()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = payloads.CreateKeyPairResponsePayload(
            private_key_unique_identifier=(
                "7f7ee394-40f9-444c-818c-fb1ae57bdf15"
            ),
            public_key_unique_identifier=(
                "79c0eb55-d020-43de-b72f-5e18c862647c"
            ),
            private_key_template_attribute=objects.TemplateAttribute(
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
                ],
                tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
            ),
            public_key_template_attribute=objects.TemplateAttribute(
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
                ],
                tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
            )
        )
        b = payloads.CreateKeyPairResponsePayload(
            private_key_unique_identifier=(
                "7f7ee394-40f9-444c-818c-fb1ae57bdf15"
            ),
            public_key_unique_identifier=(
                "79c0eb55-d020-43de-b72f-5e18c862647c"
            ),
            private_key_template_attribute=objects.TemplateAttribute(
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
                ],
                tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
            ),
            public_key_template_attribute=objects.TemplateAttribute(
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
                ],
                tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
            )
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_private_key_unique_identifiers(self):
        """
        Test that the equality operator returns False when comparing two
        CreateKeyPair response payloads with different private key unique
        identifiers.
        """
        a = payloads.CreateKeyPairResponsePayload(
            private_key_unique_identifier="a"
        )
        b = payloads.CreateKeyPairResponsePayload(
            private_key_unique_identifier="b"
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_public_key_unique_identifiers(self):
        """
        Test that the equality operator returns False when comparing two
        CreateKeyPair response payloads with different public key unique
        identifiers.
        """
        a = payloads.CreateKeyPairResponsePayload(
            public_key_unique_identifier="a"
        )
        b = payloads.CreateKeyPairResponsePayload(
            public_key_unique_identifier="b"
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_private_key_template_attribute(self):
        """
        Test that the equality operator returns False when comparing two
        CreateKeyPair response payloads with different private key template
        attributes.
        """
        a = payloads.CreateKeyPairResponsePayload(
            private_key_template_attribute=objects.TemplateAttribute(
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
                ],
                tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
            )
        )
        b = payloads.CreateKeyPairResponsePayload(
            private_key_template_attribute=objects.TemplateAttribute(
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
                ],
                tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
            )
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_public_key_template_attribute(self):
        """
        Test that the equality operator returns False when comparing two
        CreateKeyPair response payloads with different public key template
        attributes.
        """
        a = payloads.CreateKeyPairResponsePayload(
            public_key_template_attribute=objects.TemplateAttribute(
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
                ],
                tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
            )
        )
        b = payloads.CreateKeyPairResponsePayload(
            public_key_template_attribute=objects.TemplateAttribute(
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
                ],
                tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
            )
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        CreateKeyPair response payloads with different types.
        """
        a = payloads.CreateKeyPairResponsePayload()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        CreateKeyPair response payloads with the same data.
        """
        a = payloads.CreateKeyPairResponsePayload()
        b = payloads.CreateKeyPairResponsePayload()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = payloads.CreateKeyPairResponsePayload(
            private_key_unique_identifier=(
                "7f7ee394-40f9-444c-818c-fb1ae57bdf15"
            ),
            public_key_unique_identifier=(
                "79c0eb55-d020-43de-b72f-5e18c862647c"
            ),
            private_key_template_attribute=objects.TemplateAttribute(
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
                ],
                tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
            ),
            public_key_template_attribute=objects.TemplateAttribute(
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
                ],
                tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
            )
        )
        b = payloads.CreateKeyPairResponsePayload(
            private_key_unique_identifier=(
                "7f7ee394-40f9-444c-818c-fb1ae57bdf15"
            ),
            public_key_unique_identifier=(
                "79c0eb55-d020-43de-b72f-5e18c862647c"
            ),
            private_key_template_attribute=objects.TemplateAttribute(
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
                ],
                tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
            ),
            public_key_template_attribute=objects.TemplateAttribute(
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
                ],
                tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
            )
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_private_key_unique_identifiers(self):
        """
        Test that the inequality operator returns True when comparing two
        CreateKeyPair response payloads with different private key unique
        identifiers.
        """
        a = payloads.CreateKeyPairResponsePayload(
            private_key_unique_identifier="a"
        )
        b = payloads.CreateKeyPairResponsePayload(
            private_key_unique_identifier="b"
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_public_key_unique_identifiers(self):
        """
        Test that the inequality operator returns True when comparing two
        CreateKeyPair response payloads with different public key unique
        identifiers.
        """
        a = payloads.CreateKeyPairResponsePayload(
            public_key_unique_identifier="a"
        )
        b = payloads.CreateKeyPairResponsePayload(
            public_key_unique_identifier="b"
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_private_key_template_attribute(self):
        """
        Test that the inequality operator returns True when comparing two
        CreateKeyPair response payloads with different private key template
        attributes.
        """
        a = payloads.CreateKeyPairResponsePayload(
            private_key_template_attribute=objects.TemplateAttribute(
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
                ],
                tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
            )
        )
        b = payloads.CreateKeyPairResponsePayload(
            private_key_template_attribute=objects.TemplateAttribute(
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
                ],
                tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
            )
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_public_key_template_attribute(self):
        """
        Test that the inequality operator returns True when comparing two
        CreateKeyPair response payloads with different public key template
        attributes.
        """
        a = payloads.CreateKeyPairResponsePayload(
            public_key_template_attribute=objects.TemplateAttribute(
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
                ],
                tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
            )
        )
        b = payloads.CreateKeyPairResponsePayload(
            public_key_template_attribute=objects.TemplateAttribute(
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
                ],
                tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
            )
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        CreateKeyPair response payloads with different types.
        """
        a = payloads.CreateKeyPairResponsePayload()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_init(self):
        """
        Test that a CreateKeyPair response payload can be constructed with no
        arguments.
        """
        payload = payloads.CreateKeyPairResponsePayload()
        self.assertIsNone(payload.private_key_unique_identifier)
        self.assertIsNone(payload.public_key_unique_identifier)
        self.assertIsNone(payload.private_key_template_attribute)
        self.assertIsNone(payload.public_key_template_attribute)

    def test_init_with_args(self):
        """
        Test that a CreateKeyPair response payload can be constructed with
        valid values.
        """
        payload = payloads.CreateKeyPairResponsePayload(
            private_key_unique_identifier=(
                "7f7ee394-40f9-444c-818c-fb1ae57bdf15"
            ),
            public_key_unique_identifier=(
                "79c0eb55-d020-43de-b72f-5e18c862647c"
            ),
            private_key_template_attribute=objects.TemplateAttribute(
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
                ],
                tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
            ),
            public_key_template_attribute=objects.TemplateAttribute(
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
                ],
                tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
            )
        )

        self.assertEqual(
            "7f7ee394-40f9-444c-818c-fb1ae57bdf15",
            payload.private_key_unique_identifier
        )
        self.assertEqual(
            "79c0eb55-d020-43de-b72f-5e18c862647c",
            payload.public_key_unique_identifier
        )
        self.assertIsInstance(
            payload.private_key_template_attribute,
            objects.TemplateAttribute
        )
        self.assertIsInstance(
            payload.public_key_template_attribute,
            objects.TemplateAttribute
        )

    def test_read_valid(self):
        """
        Test that a CreateKeyPair response payload can be read from a valid
        byte stream.
        """
        self.test_read()

    def test_read_missing_required_field(self):
        """
        Test that an exception is raised when reading a payload missing a
        required field.
        """
        self.test_read_missing_private_key_unique_identifier()

    def test_write_valid(self):
        """
        Test that a CreateKeyPair response payload can be written to a byte
        stream.
        """
        self.test_write()

    def test_read_write_roundtrip(self):
        """
        Test that a CreateKeyPair response payload can be read and written
        without changing the encoded bytes.
        """
        payload = payloads.CreateKeyPairResponsePayload()
        payload.read(utils.BytearrayStream(self.full_encoding.buffer))

        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(str(self.full_encoding), str(stream))

    def test_validate_invalid(self):
        """
        Test that an exception is raised when a field has an invalid type.
        """
        self.test_invalid_private_key_unique_identifier()

    def test_eq(self):
        """
        Test that two CreateKeyPair response payloads with the same data are
        equal.
        """
        self.test_equal_on_equal()

    def test_ne(self):
        """
        Test that two CreateKeyPair response payloads with different data are
        not equal.
        """
        self.test_not_equal_on_not_equal_private_key_unique_identifiers()
