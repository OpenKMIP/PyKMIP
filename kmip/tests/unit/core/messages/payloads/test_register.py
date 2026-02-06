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
from kmip.core import secrets
from kmip.core import utils

from kmip.core.messages import payloads

class TestRegisterRequestPayload(testtools.TestCase):

    def setUp(self):
        super(TestRegisterRequestPayload, self).setUp()

        self.certificate_value = (
            b'\x30\x82\x03\x12\x30\x82\x01\xFA\xA0\x03\x02\x01\x02\x02\x01\x01'
            b'\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05\x05\x00\x30'
            b'\x3B\x31\x0B\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x0D'
            b'\x30\x0B\x06\x03\x55\x04\x0A\x13\x04\x54\x45\x53\x54\x31\x0E\x30'
            b'\x0C\x06\x03\x55\x04\x0B\x13\x05\x4F\x41\x53\x49\x53\x31\x0D\x30'
            b'\x0B\x06\x03\x55\x04\x03\x13\x04\x4B\x4D\x49\x50\x30\x1E\x17\x0D'
            b'\x31\x30\x31\x31\x30\x31\x32\x33\x35\x39\x35\x39\x5A\x17\x0D\x32'
            b'\x30\x31\x31\x30\x31\x32\x33\x35\x39\x35\x39\x5A\x30\x3B\x31\x0B'
            b'\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x0D\x30\x0B\x06'
            b'\x03\x55\x04\x0A\x13\x04\x54\x45\x53\x54\x31\x0E\x30\x0C\x06\x03'
            b'\x55\x04\x0B\x13\x05\x4F\x41\x53\x49\x53\x31\x0D\x30\x0B\x06\x03'
            b'\x55\x04\x03\x13\x04\x4B\x4D\x49\x50\x30\x82\x01\x22\x30\x0D\x06'
            b'\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00\x03\x82\x01\x0F'
            b'\x00\x30\x82\x01\x0A\x02\x82\x01\x01\x00\xAB\x7F\x16\x1C\x00\x42'
            b'\x49\x6C\xCD\x6C\x6D\x4D\xAD\xB9\x19\x97\x34\x35\x35\x77\x76\x00'
            b'\x3A\xCF\x54\xB7\xAF\x1E\x44\x0A\xFB\x80\xB6\x4A\x87\x55\xF8\x00'
            b'\x2C\xFE\xBA\x6B\x18\x45\x40\xA2\xD6\x60\x86\xD7\x46\x48\x34\x6D'
            b'\x75\xB8\xD7\x18\x12\xB2\x05\x38\x7C\x0F\x65\x83\xBC\x4D\x7D\xC7'
            b'\xEC\x11\x4F\x3B\x17\x6B\x79\x57\xC4\x22\xE7\xD0\x3F\xC6\x26\x7F'
            b'\xA2\xA6\xF8\x9B\x9B\xEE\x9E\x60\xA1\xD7\xC2\xD8\x33\xE5\xA5\xF4'
            b'\xBB\x0B\x14\x34\xF4\xE7\x95\xA4\x11\x00\xF8\xAA\x21\x49\x00\xDF'
            b'\x8B\x65\x08\x9F\x98\x13\x5B\x1C\x67\xB7\x01\x67\x5A\xBD\xBC\x7D'
            b'\x57\x21\xAA\xC9\xD1\x4A\x7F\x08\x1F\xCE\xC8\x0B\x64\xE8\xA0\xEC'
            b'\xC8\x29\x53\x53\xC7\x95\x32\x8A\xBF\x70\xE1\xB4\x2E\x7B\xB8\xB7'
            b'\xF4\xE8\xAC\x8C\x81\x0C\xDB\x66\xE3\xD2\x11\x26\xEB\xA8\xDA\x7D'
            b'\x0C\xA3\x41\x42\xCB\x76\xF9\x1F\x01\x3D\xA8\x09\xE9\xC1\xB7\xAE'
            b'\x64\xC5\x41\x30\xFB\xC2\x1D\x80\xE9\xC2\xCB\x06\xC5\xC8\xD7\xCC'
            b'\xE8\x94\x6A\x9A\xC9\x9B\x1C\x28\x15\xC3\x61\x2A\x29\xA8\x2D\x73'
            b'\xA1\xF9\x93\x74\xFE\x30\xE5\x49\x51\x66\x2A\x6E\xDA\x29\xC6\xFC'
            b'\x41\x13\x35\xD5\xDC\x74\x26\xB0\xF6\x05\x02\x03\x01\x00\x01\xA3'
            b'\x21\x30\x1F\x30\x1D\x06\x03\x55\x1D\x0E\x04\x16\x04\x14\x04\xE5'
            b'\x7B\xD2\xC4\x31\xB2\xE8\x16\xE1\x80\xA1\x98\x23\xFA\xC8\x58\x27'
            b'\x3F\x6B\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05\x05'
            b'\x00\x03\x82\x01\x01\x00\xA8\x76\xAD\xBC\x6C\x8E\x0F\xF0\x17\x21'
            b'\x6E\x19\x5F\xEA\x76\xBF\xF6\x1A\x56\x7C\x9A\x13\xDC\x50\xD1\x3F'
            b'\xEC\x12\xA4\x27\x3C\x44\x15\x47\xCF\xAB\xCB\x5D\x61\xD9\x91\xE9'
            b'\x66\x31\x9D\xF7\x2C\x0D\x41\xBA\x82\x6A\x45\x11\x2F\xF2\x60\x89'
            b'\xA2\x34\x4F\x4D\x71\xCF\x7C\x92\x1B\x4B\xDF\xAE\xF1\x60\x0D\x1B'
            b'\xAA\xA1\x53\x36\x05\x7E\x01\x4B\x8B\x49\x6D\x4F\xAE\x9E\x8A\x6C'
            b'\x1D\xA9\xAE\xB6\xCB\xC9\x60\xCB\xF2\xFA\xE7\x7F\x58\x7E\xC4\xBB'
            b'\x28\x20\x45\x33\x88\x45\xB8\x8D\xD9\xAE\xEA\x53\xE4\x82\xA3\x6E'
            b'\x73\x4E\x4F\x5F\x03\xB9\xD0\xDF\xC4\xCA\xFC\x6B\xB3\x4E\xA9\x05'
            b'\x3E\x52\xBD\x60\x9E\xE0\x1E\x86\xD9\xB0\x9F\xB5\x11\x20\xC1\x98'
            b'\x34\xA9\x97\xB0\x9C\xE0\x8D\x79\xE8\x13\x11\x76\x2F\x97\x4B\xB1'
            b'\xC8\xC0\x91\x86\xC4\xD7\x89\x33\xE0\xDB\x38\xE9\x05\x08\x48\x77'
            b'\xE1\x47\xC7\x8A\xF5\x2F\xAE\x07\x19\x2F\xF1\x66\xD1\x9F\xA9\x4A'
            b'\x11\xCC\x11\xB2\x7E\xD0\x50\xF7\xA2\x7F\xAE\x13\xB2\x05\xA5\x74'
            b'\xC4\xEE\x00\xAA\x8B\xD6\x5D\x0D\x70\x57\xC9\x85\xC8\x39\xEF\x33'
            b'\x6A\x44\x1E\xD5\x3A\x53\xC6\xB6\xB6\x96\xF1\xBD\xEB\x5F\x7E\xA8'
            b'\x11\xEB\xB2\x5A\x7F\x86'
        )

        # Encoding obtained from the KMIP 1.1 testing document, Section 13.2.2.
        # Modified to exclude the Link attribute.
        #
        # TODO (ph) Add the Link attribute back in once Links are supported.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Object Type - Certificate
        #     Template Attribute
        #         Attribute
        #             Attribute Name - Cryptographic Usage Mask
        #             Attribute Value - Sign | Verify
        #     Certificate
        #         Certificate Type - X.509
        #         Certificate Value -
        #             0x30820312308201FAA003020102020101300D06092A864886F70D01
        #             01050500303B310B3009060355040613025553310D300B060355040A
        #             130454455354310E300C060355040B13054F41534953310D300B0603
        #             55040313044B4D4950301E170D3130313130313233353935395A170D
        #             3230313130313233353935395A303B310B3009060355040613025553
        #             310D300B060355040A130454455354310E300C060355040B13054F41
        #             534953310D300B060355040313044B4D495030820122300D06092A86
        #             4886F70D01010105000382010F003082010A0282010100AB7F161C00
        #             42496CCD6C6D4DADB919973435357776003ACF54B7AF1E440AFB80B6
        #             4A8755F8002CFEBA6B184540A2D66086D74648346D75B8D71812B205
        #             387C0F6583BC4D7DC7EC114F3B176B7957C422E7D03FC6267FA2A6F8
        #             9B9BEE9E60A1D7C2D833E5A5F4BB0B1434F4E795A41100F8AA214900
        #             DF8B65089F98135B1C67B701675ABDBC7D5721AAC9D14A7F081FCEC8
        #             0B64E8A0ECC8295353C795328ABF70E1B42E7BB8B7F4E8AC8C810CDB
        #             66E3D21126EBA8DA7D0CA34142CB76F91F013DA809E9C1B7AE64C541
        #             30FBC21D80E9C2CB06C5C8D7CCE8946A9AC99B1C2815C3612A29A82D
        #             73A1F99374FE30E54951662A6EDA29C6FC411335D5DC7426B0F60502
        #             03010001A321301F301D0603551D0E0416041404E57BD2C431B2E816
        #             E180A19823FAC858273F6B300D06092A864886F70D01010505000382
        #             010100A876ADBC6C8E0FF017216E195FEA76BFF61A567C9A13DC50D1
        #             3FEC12A4273C441547CFABCB5D61D991E966319DF72C0D41BA826A45
        #             112FF26089A2344F4D71CF7C921B4BDFAEF1600D1BAAA15336057E01
        #             4B8B496D4FAE9E8A6C1DA9AEB6CBC960CBF2FAE77F587EC4BB282045
        #             338845B88DD9AEEA53E482A36E734E4F5F03B9D0DFC4CAFC6BB34EA9
        #             053E52BD609EE01E86D9B09FB51120C19834A997B09CE08D79E81311
        #             762F974BB1C8C09186C4D78933E0DB38E905084877E147C78AF52FAE
        #             07192FF166D19FA94A11CC11B27ED050F7A27FAE13B205A574C4EE00
        #             AA8BD65D0D7057C985C839EF336A441ED53A53C6B6B696F1BDEB5F7E
        #             A811EBB25A7F86
        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x03\x88'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x91\x01\x00\x00\x00\x38'
            b'\x42\x00\x08\x01\x00\x00\x00\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x18'
            b'\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x55\x73'
            b'\x61\x67\x65\x20\x4D\x61\x73\x6B'
            b'\x42\x00\x0B\x02\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x13\x01\x00\x00\x03\x30'
            b'\x42\x00\x1D\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x1E\x08\x00\x00\x03\x16' + self.certificate_value +
            b'\x00\x00'
        )

        # Encoding obtained from the KMIP 1.1 testing document, Section 13.2.2.
        # Modified to exclude the Link attribute. Manually converted into the
        # KMIP 2.0 format.
        #
        # TODO (ph) Add the Link attribute back in once Links are supported.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Object Type - Certificate
        #     Attributes
        #         Cryptographic Usage Mask - Sign | Verify
        #     Certificate
        #         Certificate Type - X.509
        #         Certificate Value - See comment for the full encoding.
        #     Protection Storage Masks
        #         Protection Storage Mask - Software | Hardware
        self.full_encoding_with_attributes = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x03\x78'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x01\x25\x01\x00\x00\x00\x10'
            b'\x42\x00\x2C\x02\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x13\x01\x00\x00\x03\x30'
            b'\x42\x00\x1D\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x1E\x08\x00\x00\x03\x16' + self.certificate_value +
            b'\x00\x00'
            b'\x42\x01\x5F\x01\x00\x00\x00\x10'
            b'\x42\x01\x5E\x02\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
        )

        # Encoding obtained from the KMIP 1.1 testing document, Section 13.2.2.
        # Modified to exclude the Link attribute.
        #
        # TODO (ph) Add the Link attribute back in once Links are supported.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Template Attribute
        #         Attribute
        #             Attribute Name - Cryptographic Usage Mask
        #             Attribute Value - Sign | Verify
        #     Certificate
        #         Certificate Type - X.509
        #         Certificate Value - See comment for the full encoding.
        self.no_object_type_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x03\x78'
            b'\x42\x00\x91\x01\x00\x00\x00\x38'
            b'\x42\x00\x08\x01\x00\x00\x00\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x18'
            b'\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x55\x73'
            b'\x61\x67\x65\x20\x4D\x61\x73\x6B'
            b'\x42\x00\x0B\x02\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x13\x01\x00\x00\x03\x30'
            b'\x42\x00\x1D\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x1E\x08\x00\x00\x03\x16' + self.certificate_value +
            b'\x00\x00'
        )

        # Encoding obtained from the KMIP 1.1 testing document, Section 13.2.2.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Object Type - Certificate
        #     Certificate
        #         Certificate Type - X.509
        #         Certificate Value - See comment for the full encoding.
        self.no_template_attribute_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x03\x48'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x13\x01\x00\x00\x03\x30'
            b'\x42\x00\x1D\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x1E\x08\x00\x00\x03\x16' + self.certificate_value +
            b'\x00\x00'
        )

        # Encoding obtained from the KMIP 1.1 testing document, Section 13.2.2.
        # Modified to exclude the Link attribute.
        #
        # TODO (ph) Add the Link attribute back in once Links are supported.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Object Type - Certificate
        #     Template Attribute
        #         Attribute
        #             Attribute Name - Cryptographic Usage Mask
        #             Attribute Value - Sign | Verify
        self.no_managed_object_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x50'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x91\x01\x00\x00\x00\x38'
            b'\x42\x00\x08\x01\x00\x00\x00\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x18'
            b'\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x55\x73'
            b'\x61\x67\x65\x20\x4D\x61\x73\x6B'
            b'\x42\x00\x0B\x02\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestRegisterRequestPayload, self).tearDown()

    def test_invalid_object_type(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the object type of a Register request payload.
        """
        kwargs = {'object_type': 'invalid'}
        self.assertRaisesRegex(
            TypeError,
            "Object type must be an ObjectType enumeration.",
            payloads.RegisterRequestPayload,
            **kwargs
        )

        args = (
            payloads.RegisterRequestPayload(),
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
        the template attribute of a Register request payload.
        """
        kwargs = {'template_attribute': 'invalid'}
        self.assertRaisesRegex(
            TypeError,
            "Template attribute must be a TemplateAttribute structure.",
            payloads.RegisterRequestPayload,
            **kwargs
        )

        args = (
            payloads.RegisterRequestPayload(),
            'template_attribute',
            'invalid'
        )
        self.assertRaisesRegex(
            TypeError,
            "Template attribute must be a TemplateAttribute structure.",
            setattr,
            *args
        )

    def test_invalid_managed_object(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the managed object of a Register request payload.
        """
        kwargs = {'managed_object': 'invalid'}
        self.assertRaisesRegex(
            TypeError,
            "Managed object must be a supported managed object structure.",
            payloads.RegisterRequestPayload,
            **kwargs
        )

        args = (
            payloads.RegisterRequestPayload(),
            'managed_object',
            'invalid'
        )
        self.assertRaisesRegex(
            TypeError,
            "Managed object must be a supported managed object structure.",
            setattr,
            *args
        )

    def test_invalid_protection_storage_masks(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the protection storage masks of a Register request payload.
        """
        kwargs = {"protection_storage_masks": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The protection storage masks must be a ProtectionStorageMasks "
            "structure.",
            payloads.RegisterRequestPayload,
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
            payloads.RegisterRequestPayload,
            **kwargs
        )

        args = (
            payloads.RegisterRequestPayload(),
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
            payloads.RegisterRequestPayload(),
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
        Test that a Register request payload can be read from a data stream.
        """
        payload = payloads.RegisterRequestPayload()

        self.assertIsNone(payload.object_type)
        self.assertIsNone(payload.template_attribute)
        self.assertIsNone(payload.managed_object)
        self.assertIsNone(payload.protection_storage_masks)

        payload.read(self.full_encoding)

        self.assertEqual(enums.ObjectType.CERTIFICATE, payload.object_type)
        self.assertEqual(
            objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            enums.CryptographicUsageMask.SIGN.value |
                            enums.CryptographicUsageMask.VERIFY.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ]
            ),
            payload.template_attribute
        )
        self.assertEqual(
            secrets.Certificate(
                certificate_type=enums.CertificateType.X_509,
                certificate_value=self.certificate_value
            ),
            payload.managed_object
        )
        self.assertIsNone(payload.protection_storage_masks)

    def test_read_kmip_2_0(self):
        """
        Test that a Register request payload can be read from a data stream
        encoded with the KMIP 2.0 format.
        """
        payload = payloads.RegisterRequestPayload()

        self.assertIsNone(payload.object_type)
        self.assertIsNone(payload.template_attribute)
        self.assertIsNone(payload.managed_object)
        self.assertIsNone(payload.protection_storage_masks)

        payload.read(
            self.full_encoding_with_attributes,
            kmip_version=enums.KMIPVersion.KMIP_2_0
        )

        self.assertEqual(enums.ObjectType.CERTIFICATE, payload.object_type)
        self.assertEqual(
            objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            enums.CryptographicUsageMask.SIGN.value |
                            enums.CryptographicUsageMask.VERIFY.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ]
            ),
            payload.template_attribute
        )
        self.assertEqual(
            secrets.Certificate(
                certificate_type=enums.CertificateType.X_509,
                certificate_value=self.certificate_value
            ),
            payload.managed_object
        )
        self.assertEqual(
            objects.ProtectionStorageMasks(protection_storage_masks=[3]),
            payload.protection_storage_masks
        )

    def test_read_missing_object_type(self):
        """
        Test that an InvalidKmipEncoding error is raised during the decoding
        of a Register request payload when the object type is missing from the
        encoding.
        """
        payload = payloads.RegisterRequestPayload()

        args = (self.no_object_type_encoding, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The Register request payload encoding is missing the object "
            "type.",
            payload.read,
            *args
        )

    def test_read_missing_template_attribute(self):
        """
        Test that an InvalidKmipEncoding error is raised during the decoding
        of a Register request payload when the template attribute is missing
        from the encoding.
        """
        payload = payloads.RegisterRequestPayload()

        args = (self.no_template_attribute_encoding, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The Register request payload encoding is missing the template "
            "attribute.",
            payload.read,
            *args
        )

    def test_read_missing_attributes(self):
        """
        Test that an InvalidKmipEncoding error is raised during the decoding
        of a Register request payload when the attributes structure is missing
        from the encoding.
        """
        payload = payloads.RegisterRequestPayload()

        args = (self.no_template_attribute_encoding, )
        kwargs = {"kmip_version": enums.KMIPVersion.KMIP_2_0}
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The Register request payload encoding is missing the attributes "
            "structure.",
            payload.read,
            *args,
            **kwargs
        )

    def test_read_missing_managed_object(self):
        """
        Test that an InvalidKmipEncoding error is raised during the decoding
        of a Register request payload when the managed object is missing from
        the encoding.
        """
        payload = payloads.RegisterRequestPayload()

        args = (self.no_managed_object_encoding, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The Register request payload encoding is missing the managed "
            "object.",
            payload.read,
            *args
        )

    def test_write(self):
        """
        Test that a Register request payload can be written to a data stream.
        """
        payload = payloads.RegisterRequestPayload(
            object_type=enums.ObjectType.CERTIFICATE,
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            enums.CryptographicUsageMask.SIGN.value |
                            enums.CryptographicUsageMask.VERIFY.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ]
            ),
            managed_object=secrets.Certificate(
                certificate_type=enums.CertificateType.X_509,
                certificate_value=self.certificate_value
            )
        )

        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_kmip_2_0(self):
        """
        Test that a Register request payload can be written to a data stream
        encoded with the KMIP 2.0 format.
        """
        payload = payloads.RegisterRequestPayload(
            object_type=enums.ObjectType.CERTIFICATE,
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            enums.CryptographicUsageMask.SIGN.value |
                            enums.CryptographicUsageMask.VERIFY.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ]
            ),
            managed_object=secrets.Certificate(
                certificate_type=enums.CertificateType.X_509,
                certificate_value=self.certificate_value
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
        Register request payload when the payload is missing the object type.
        """
        payload = payloads.RegisterRequestPayload(
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            enums.CryptographicUsageMask.SIGN.value |
                            enums.CryptographicUsageMask.VERIFY.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ]
            ),
            managed_object=secrets.Certificate(
                certificate_type=enums.CertificateType.X_509,
                certificate_value=self.certificate_value
            )
        )

        args = (utils.BytearrayStream(), )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The Register request payload is missing the object type field.",
            payload.write,
            *args
        )

    def test_write_missing_template_attribute(self):
        """
        Test that an InvalidField error is raised during the encoding of a
        Register request payload when the payload is missing the template
        attribute.
        """
        payload = payloads.RegisterRequestPayload(
            object_type=enums.ObjectType.CERTIFICATE,
            managed_object=secrets.Certificate(
                certificate_type=enums.CertificateType.X_509,
                certificate_value=self.certificate_value
            )
        )

        args = (utils.BytearrayStream(), )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The Register request payload is missing the template attribute "
            "field.",
            payload.write,
            *args
        )

    def test_write_missing_attributes(self):
        """
        Test that an InvalidField error is raised during the encoding of a
        Register request payload when the payload is missing the attributes
        structure.
        """
        payload = payloads.RegisterRequestPayload(
            object_type=enums.ObjectType.CERTIFICATE,
            managed_object=secrets.Certificate(
                certificate_type=enums.CertificateType.X_509,
                certificate_value=self.certificate_value
            )
        )

        args = (utils.BytearrayStream(), )
        kwargs = {"kmip_version": enums.KMIPVersion.KMIP_2_0}
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The Register request payload is missing the template attribute "
            "field.",
            payload.write,
            *args,
            **kwargs
        )

    def test_write_missing_managed_object(self):
        """
        Test that an InvalidField error is raised during the encoding of a
        Register request payload when the payload is missing the managed
        object.
        """
        payload = payloads.RegisterRequestPayload(
            object_type=enums.ObjectType.SECRET_DATA,
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            enums.CryptographicUsageMask.VERIFY.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ]
            )
        )

        args = (utils.BytearrayStream(), )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The Register request payload is missing the managed object "
            "field.",
            payload.write,
            *args
        )

    def test_repr(self):
        """
        Test that repr can be applied to a Register request payload structure.
        """
        payload = payloads.RegisterRequestPayload(
            object_type=enums.ObjectType.SECRET_DATA,
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            enums.CryptographicUsageMask.VERIFY.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ]
            ),
            managed_object=secrets.SecretData(
                secret_data_type=primitives.Enumeration(
                    enums.SecretDataType,
                    value=enums.SecretDataType.PASSWORD,
                    tag=enums.Tags.SECRET_DATA_TYPE
                ),
                key_block=objects.KeyBlock(
                    key_format_type=objects.KeyFormatType(
                        enums.KeyFormatType.OPAQUE
                    ),
                    key_value=objects.KeyValue(
                        key_material=objects.KeyMaterial(
                            (
                                b'\x53\x65\x63\x72\x65\x74\x50\x61\x73\x73\x77'
                                b'\x6F\x72\x64'
                            )
                        )
                    )
                )
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
            "RegisterRequestPayload("
            "object_type=ObjectType.SECRET_DATA, "
            "template_attribute=Struct(), "
            "managed_object=Struct(), "
            "protection_storage_masks=ProtectionStorageMasks("
            "protection_storage_masks=[3]))",
            repr(payload)
        )

    def test_str(self):
        """
        Test that str can be applied to a Register request payload structure.
        """
        payload = payloads.RegisterRequestPayload(
            object_type=enums.ObjectType.SECRET_DATA,
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            enums.CryptographicUsageMask.VERIFY.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ]
            ),
            managed_object=secrets.SecretData(
                secret_data_type=primitives.Enumeration(
                    enums.SecretDataType,
                    value=enums.SecretDataType.PASSWORD,
                    tag=enums.Tags.SECRET_DATA_TYPE
                ),
                key_block=objects.KeyBlock(
                    key_format_type=objects.KeyFormatType(
                        enums.KeyFormatType.OPAQUE
                    ),
                    key_value=objects.KeyValue(
                        key_material=objects.KeyMaterial(
                            (
                                b'\x53\x65\x63\x72\x65\x74\x50\x61\x73\x73\x77'
                                b'\x6F\x72\x64'
                            )
                        )
                    )
                )
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
            '"object_type": ObjectType.SECRET_DATA, '
            '"template_attribute": Struct(), '
            '"managed_object": Struct(), '
            '"protection_storage_masks": {"protection_storage_masks": [3]}'
            '}',
            str(payload)
        )

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        Register request payloads with the same data.
        """
        a = payloads.RegisterRequestPayload()
        b = payloads.RegisterRequestPayload()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = payloads.RegisterRequestPayload(
            object_type=enums.ObjectType.CERTIFICATE,
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            enums.CryptographicUsageMask.SIGN.value |
                            enums.CryptographicUsageMask.VERIFY.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ]
            ),
            managed_object=secrets.Certificate(
                certificate_type=enums.CertificateType.X_509,
                certificate_value=self.certificate_value
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
        b = payloads.RegisterRequestPayload(
            object_type=enums.ObjectType.CERTIFICATE,
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            enums.CryptographicUsageMask.SIGN.value |
                            enums.CryptographicUsageMask.VERIFY.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ]
            ),
            managed_object=secrets.Certificate(
                certificate_type=enums.CertificateType.X_509,
                certificate_value=self.certificate_value
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
        Test that the equality operator returns False when comparing two
        Register request payloads with different object types.
        """
        a = payloads.RegisterRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY
        )
        b = payloads.RegisterRequestPayload(
            object_type=enums.ObjectType.SECRET_DATA
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_template_attribute(self):
        """
        Test that the equality operator returns False when comparing two
        Register request payloads with different template attributes.
        """
        a = payloads.RegisterRequestPayload(
            template_attribute=objects.TemplateAttribute(
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
                ]
            )
        )
        b = payloads.RegisterRequestPayload(
            template_attribute=objects.TemplateAttribute(
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
                ]
            )
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_managed_object(self):
        """
        Test that the equality operator returns False when comparing two
        Register request payloads with different managed objects.
        """
        a = payloads.RegisterRequestPayload(
            managed_object=secrets.Certificate(
                certificate_type=enums.CertificateType.X_509,
                certificate_value=self.certificate_value
            )
        )
        b = payloads.RegisterRequestPayload(
            managed_object=secrets.Certificate(
                certificate_type=enums.CertificateType.PGP,
                certificate_value=self.certificate_value
            )
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_protection_storage_masks(self):
        """
        Test that the equality operator returns False when comparing two Create
        request payloads with different protection storage masks.
        """
        a = payloads.RegisterRequestPayload(
            protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[
                    (
                        enums.ProtectionStorageMask.SOFTWARE.value |
                        enums.ProtectionStorageMask.HARDWARE.value
                    )
                ]
            )
        )
        b = payloads.RegisterRequestPayload(
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
        Test that the equality operator returns False when comparing two
        Register request payloads with different types.
        """
        a = payloads.RegisterRequestPayload()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        Register request payloads with the same data.
        """
        a = payloads.RegisterRequestPayload()
        b = payloads.RegisterRequestPayload()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = payloads.RegisterRequestPayload(
            object_type=enums.ObjectType.CERTIFICATE,
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            enums.CryptographicUsageMask.SIGN.value |
                            enums.CryptographicUsageMask.VERIFY.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ]
            ),
            managed_object=secrets.Certificate(
                certificate_type=enums.CertificateType.X_509,
                certificate_value=self.certificate_value
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
        b = payloads.RegisterRequestPayload(
            object_type=enums.ObjectType.CERTIFICATE,
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            enums.CryptographicUsageMask.SIGN.value |
                            enums.CryptographicUsageMask.VERIFY.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ]
            ),
            managed_object=secrets.Certificate(
                certificate_type=enums.CertificateType.X_509,
                certificate_value=self.certificate_value
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
        Register request payloads with different object types.
        """
        a = payloads.RegisterRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY
        )
        b = payloads.RegisterRequestPayload(
            object_type=enums.ObjectType.SECRET_DATA
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_template_attribute(self):
        """
        Test that the inequality operator returns True when comparing two
        Register request payloads with different template attributes.
        """
        a = payloads.RegisterRequestPayload(
            template_attribute=objects.TemplateAttribute(
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
                ]
            )
        )
        b = payloads.RegisterRequestPayload(
            template_attribute=objects.TemplateAttribute(
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
                ]
            )
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_managed_object(self):
        """
        Test that the inequality operator returns True when comparing two
        Register request payloads with different managed objects.
        """
        a = payloads.RegisterRequestPayload(
            managed_object=secrets.Certificate(
                certificate_type=enums.CertificateType.X_509,
                certificate_value=self.certificate_value
            )
        )
        b = payloads.RegisterRequestPayload(
            managed_object=secrets.Certificate(
                certificate_type=enums.CertificateType.PGP,
                certificate_value=self.certificate_value
            )
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_protection_storage_masks(self):
        """
        Test that the inequality operator returns True when comparing two
        Register request payloads with different protection storage masks.
        """
        a = payloads.RegisterRequestPayload(
            protection_storage_masks=objects.ProtectionStorageMasks(
                protection_storage_masks=[
                    (
                        enums.ProtectionStorageMask.SOFTWARE.value |
                        enums.ProtectionStorageMask.HARDWARE.value
                    )
                ]
            )
        )
        b = payloads.RegisterRequestPayload(
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
        Register request payloads with different types.
        """
        a = payloads.RegisterRequestPayload()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_init(self):
        """
        Test that a Register request payload can be constructed with no
        arguments.
        """
        payload = payloads.RegisterRequestPayload()
        self.assertIsNone(payload.object_type)
        self.assertIsNone(payload.template_attribute)
        self.assertIsNone(payload.managed_object)
        self.assertIsNone(payload.protection_storage_masks)

    def test_init_with_args(self):
        """
        Test that a Register request payload can be constructed with valid
        values.
        """
        payload = payloads.RegisterRequestPayload(
            object_type=enums.ObjectType.CERTIFICATE,
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            "Cryptographic Usage Mask"
                        ),
                        attribute_value=primitives.Integer(
                            enums.CryptographicUsageMask.SIGN.value |
                            enums.CryptographicUsageMask.VERIFY.value,
                            tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                        )
                    )
                ]
            ),
            managed_object=secrets.Certificate(
                certificate_type=enums.CertificateType.X_509,
                certificate_value=self.certificate_value
            )
        )

        self.assertEqual(enums.ObjectType.CERTIFICATE, payload.object_type)
        self.assertIsInstance(
            payload.template_attribute,
            objects.TemplateAttribute
        )
        self.assertIsInstance(payload.managed_object, secrets.Certificate)

    def test_read_valid(self):
        """
        Test that a Register request payload can be read from a valid byte
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
        Test that a Register request payload can be written to a byte stream.
        """
        self.test_write()

    def test_read_write_roundtrip(self):
        """
        Test that a Register request payload can be read and written without
        changing the encoded bytes.
        """
        payload = payloads.RegisterRequestPayload()
        payload.read(utils.BytearrayStream(self.full_encoding.buffer))

        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(str(self.full_encoding), str(stream))

    def test_validate_invalid(self):
        """
        Test that an exception is raised when a field has an invalid type.
        """
        self.test_invalid_object_type()

    def test_eq(self):
        """
        Test that two Register request payloads with the same data are equal.
        """
        self.test_equal_on_equal()

    def test_ne(self):
        """
        Test that two Register request payloads with different data are not
        equal.
        """
        self.test_not_equal_on_not_equal_object_type()

class TestRegisterResponsePayload(testtools.TestCase):

    def setUp(self):
        super(TestRegisterResponsePayload, self).setUp()

        # Encoding obtained from the KMIP 1.1 testing document, Section 13.2.2.
        # Modified to include the template attribute.
        #
        # This encoding matches the following set of values:
        # Response Payload
        #     Unique Identifier - 7091d0bf-548a-4d4a-93a6-6dd71cf75221
        #     Template Attribute
        #         Attribute
        #             Attribute Name - State
        #             Attribute Value - Pre-active
        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x60'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x37\x30\x39\x31\x64\x30\x62\x66\x2D\x35\x34\x38\x61\x2D\x34\x64'
            b'\x34\x61\x2D\x39\x33\x61\x36\x2D\x36\x64\x64\x37\x31\x63\x66\x37'
            b'\x35\x32\x32\x31\x00\x00\x00\x00'
            b'\x42\x00\x91\x01\x00\x00\x00\x28'
            b'\x42\x00\x08\x01\x00\x00\x00\x20'
            b'\x42\x00\x0A\x07\x00\x00\x00\x05'
            b'\x53\x74\x61\x74\x65\x00\x00\x00'
            b'\x42\x00\x0B\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
        )

        # Encoding obtained from the KMIP 1.1 testing document, Section 13.2.2.
        # Modified to include the template attribute.
        #
        # This encoding matches the following set of values:
        # Response Payload
        #     Template Attribute
        #         Attribute
        #             Attribute Name - State
        #             Attribute Value - Pre-active
        self.no_unique_identifier_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x30'
            b'\x42\x00\x91\x01\x00\x00\x00\x28'
            b'\x42\x00\x08\x01\x00\x00\x00\x20'
            b'\x42\x00\x0A\x07\x00\x00\x00\x05'
            b'\x53\x74\x61\x74\x65\x00\x00\x00'
            b'\x42\x00\x0B\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
        )

        # Encoding obtained from the KMIP 1.1 testing document, Section 13.2.2.
        #
        # This encoding matches the following set of values:
        # Response Payload
        #     Unique Identifier - 7091d0bf-548a-4d4a-93a6-6dd71cf75221
        self.no_template_attribute_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x30'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x37\x30\x39\x31\x64\x30\x62\x66\x2D\x35\x34\x38\x61\x2D\x34\x64'
            b'\x34\x61\x2D\x39\x33\x61\x36\x2D\x36\x64\x64\x37\x31\x63\x66\x37'
            b'\x35\x32\x32\x31\x00\x00\x00\x00'
        )

    def test_invalid_unique_identifier(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the unique identifier of a Register response payload.
        """
        kwargs = {'unique_identifier': 0}
        self.assertRaisesRegex(
            TypeError,
            "Unique identifier must be a string.",
            payloads.RegisterResponsePayload,
            **kwargs
        )

        args = (payloads.RegisterResponsePayload(), 'unique_identifier', 0)
        self.assertRaisesRegex(
            TypeError,
            "Unique identifier must be a string.",
            setattr,
            *args
        )

    def test_invalid_template_attribute(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the template attribute of a Register response payload.
        """
        kwargs = {'template_attribute': 'invalid'}
        self.assertRaisesRegex(
            TypeError,
            "Template attribute must be a TemplateAttribute structure.",
            payloads.RegisterResponsePayload,
            **kwargs
        )

        args = (
            payloads.RegisterResponsePayload(),
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
        Test that a Register response payload can be read from a data stream.
        """
        payload = payloads.RegisterResponsePayload()

        self.assertIsNone(payload.unique_identifier)
        self.assertIsNone(payload.template_attribute)

        payload.read(self.full_encoding)

        self.assertEqual(
            "7091d0bf-548a-4d4a-93a6-6dd71cf75221",
            payload.unique_identifier
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
                            enums.State.PRE_ACTIVE,
                            tag=enums.Tags.STATE
                        )
                    )
                ]
            ),
            payload.template_attribute
        )

    def test_read_kmip_2_0(self):
        """
        Test that a Register response payload can be read from a data stream
        encoded with the KMIP 2.0 format.
        """
        payload = payloads.RegisterResponsePayload()

        self.assertIsNone(payload.unique_identifier)
        self.assertIsNone(payload.template_attribute)

        payload.read(
            self.no_template_attribute_encoding,
            kmip_version=enums.KMIPVersion.KMIP_2_0
        )

        self.assertEqual(
            "7091d0bf-548a-4d4a-93a6-6dd71cf75221",
            payload.unique_identifier
        )
        self.assertIsNone(payload.template_attribute)

    def test_read_missing_unique_identifier(self):
        """
        Test that an InvalidKmipEncoding error is raised during the decoding
        of a Register response payload when the unique identifier is missing
        from the encoding.
        """
        payload = payloads.RegisterResponsePayload()

        self.assertIsNone(payload.unique_identifier)
        self.assertIsNone(payload.template_attribute)

        args = (self.no_unique_identifier_encoding, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The Register response payload encoding is missing the unique "
            "identifier.",
            payload.read,
            *args
        )

    def test_read_missing_template_attribute(self):
        """
        Test that a Register response payload can be read from a data stream
        event when missing the template attribute.
        """
        payload = payloads.RegisterResponsePayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.template_attribute)

        payload.read(self.no_template_attribute_encoding)

        self.assertEqual(
            "7091d0bf-548a-4d4a-93a6-6dd71cf75221",
            payload.unique_identifier
        )
        self.assertIsNone(payload.template_attribute)

    def test_write(self):
        """
        Test that a Register response payload can be written to a data stream.
        """
        payload = payloads.RegisterResponsePayload(
            unique_identifier="7091d0bf-548a-4d4a-93a6-6dd71cf75221",
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
        Test that a Register response payload can be written to a data stream
        encoded with the KMIP 2.0 format.
        """
        payload = payloads.RegisterResponsePayload(
            unique_identifier="7091d0bf-548a-4d4a-93a6-6dd71cf75221",
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

    def test_write_missing_unique_identifier(self):
        """
        Test that an InvalidField error is raised during the encoding of a
        Register response payload when the payload is missing the unique
        identifier.
        """
        payload = payloads.RegisterResponsePayload(
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
            "The Register response payload is missing the unique identifier "
            "field.",
            payload.write,
            *args
        )

    def test_write_missing_template_attribute(self):
        """
        Test that a Register response payload can be written to a data stream
        even when missing the template attribute.
        """
        payload = payloads.RegisterResponsePayload(
            unique_identifier="7091d0bf-548a-4d4a-93a6-6dd71cf75221"
        )

        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.no_template_attribute_encoding), len(stream))
        self.assertEqual(str(self.no_template_attribute_encoding), str(stream))

    def test_repr(self):
        """
        Test that repr can be applied to a Register response payload structure.
        """
        payload = payloads.RegisterResponsePayload(
            unique_identifier="7091d0bf-548a-4d4a-93a6-6dd71cf75221",
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
            "RegisterResponsePayload("
            "unique_identifier='7091d0bf-548a-4d4a-93a6-6dd71cf75221', "
            "template_attribute=Struct())",
            repr(payload)
        )

    def test_str(self):
        """
        Test that str can be applied to a Register response payload structure.
        """
        payload = payloads.RegisterResponsePayload(
            unique_identifier="7091d0bf-548a-4d4a-93a6-6dd71cf75221",
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
            '"unique_identifier": "7091d0bf-548a-4d4a-93a6-6dd71cf75221", '
            '"template_attribute": Struct()'
            '}',
            str(payload)
        )

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        Register response payloads with the same data.
        """
        a = payloads.RegisterResponsePayload()
        b = payloads.RegisterResponsePayload()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = payloads.RegisterResponsePayload(
            unique_identifier="7091d0bf-548a-4d4a-93a6-6dd71cf75221",
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
        b = payloads.RegisterResponsePayload(
            unique_identifier="7091d0bf-548a-4d4a-93a6-6dd71cf75221",
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

    def test_equal_on_not_equal_unique_identifier(self):
        """
        Test that the equality operator returns False when comparing two
        Register response payloads with different unique identifiers.
        """
        a = payloads.RegisterResponsePayload(unique_identifier="a")
        b = payloads.RegisterResponsePayload(unique_identifier="b")

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_template_attribute(self):
        """
        Test that the equality operator returns False when comparing two
        Register response payloads with different template attributes.
        """
        a = payloads.RegisterResponsePayload(
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
        b = payloads.RegisterResponsePayload(
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
        Test that the equality operator returns False when comparing two
        Register response payloads with different types.
        """
        a = payloads.RegisterResponsePayload()
        b = "invalid"

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        Register response payloads with the same data.
        """
        a = payloads.RegisterResponsePayload()
        b = payloads.RegisterResponsePayload()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = payloads.RegisterResponsePayload(
            unique_identifier="7091d0bf-548a-4d4a-93a6-6dd71cf75221",
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
        b = payloads.RegisterResponsePayload(
            unique_identifier="7091d0bf-548a-4d4a-93a6-6dd71cf75221",
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

    def test_not_equal_on_not_equal_unique_identifier(self):
        """
        Test that the inequality operator returns True when comparing two
        Register response payloads with different unique identifiers.
        """
        a = payloads.RegisterResponsePayload(unique_identifier="a")
        b = payloads.RegisterResponsePayload(unique_identifier="b")

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_template_attribute(self):
        """
        Test that the inequality operator returns True when comparing two
        Register response payloads with different template attributes.
        """
        a = payloads.RegisterResponsePayload(
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
        b = payloads.RegisterResponsePayload(
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
        Register response payloads with different types.
        """
        a = payloads.RegisterResponsePayload()
        b = "invalid"

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_init(self):
        """
        Test that a Register response payload can be constructed with no
        arguments.
        """
        payload = payloads.RegisterResponsePayload()
        self.assertIsNone(payload.unique_identifier)
        self.assertIsNone(payload.template_attribute)

    def test_init_with_args(self):
        """
        Test that a Register response payload can be constructed with valid
        values.
        """
        payload = payloads.RegisterResponsePayload(
            unique_identifier="7091d0bf-548a-4d4a-93a6-6dd71cf75221",
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
            "7091d0bf-548a-4d4a-93a6-6dd71cf75221",
            payload.unique_identifier
        )
        self.assertIsInstance(
            payload.template_attribute,
            objects.TemplateAttribute
        )

    def test_read_valid(self):
        """
        Test that a Register response payload can be read from a valid byte
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
        Test that a Register response payload can be written to a byte stream.
        """
        self.test_write()

    def test_read_write_roundtrip(self):
        """
        Test that a Register response payload can be read and written without
        changing the encoded bytes.
        """
        payload = payloads.RegisterResponsePayload()
        payload.read(utils.BytearrayStream(self.full_encoding.buffer))

        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(str(self.full_encoding), str(stream))

    def test_validate_invalid(self):
        """
        Test that an exception is raised when a field has an invalid type.
        """
        self.test_invalid_unique_identifier()

    def test_eq(self):
        """
        Test that two Register response payloads with the same data are equal.
        """
        self.test_equal_on_equal()

    def test_ne(self):
        """
        Test that two Register response payloads with different data are not
        equal.
        """
        self.test_not_equal_on_not_equal_unique_identifier()
