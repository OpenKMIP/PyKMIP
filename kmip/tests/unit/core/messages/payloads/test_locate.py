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
from kmip.core import objects
from kmip.core import primitives
from kmip.core import utils

from kmip.core.messages import payloads

class TestLocateRequestPayload(testtools.TestCase):

    def setUp(self):
        super(TestLocateRequestPayload, self).setUp()

        # Encoding obtained from the KMIP 1.1 testing document, Section 15.3.4.
        # Modified to include the Offset Items and Storage Status Mask fields.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Maximum Items - 1
        #     Offset Items - 1
        #     Storage Status Mask - Online Storage | Archival Storage
        #     Object Group Member - Group Member Default
        #     Attribute
        #         Attribute Name - Object Group
        #         Attribute Value - RoundRobinTestGroup
        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x80'
            b'\x42\x00\x4F\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\xD4\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x8E\x02\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\xAC\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x08\x01\x00\x00\x00\x38'
            b'\x42\x00\x0A\x07\x00\x00\x00\x0C'
            b'\x4F\x62\x6A\x65\x63\x74\x20\x47\x72\x6F\x75\x70\x00\x00\x00\x00'
            b'\x42\x00\x0B\x07\x00\x00\x00\x13'
            b'\x52\x6F\x75\x6E\x64\x52\x6F\x62\x69\x6E\x54\x65\x73\x74\x47\x72'
            b'\x6F\x75\x70\x00\x00\x00\x00\x00'
        )

        # Encoding obtained from the KMIP 1.1 testing document, Section 13.3.5.
        # Modified to include the Offset Items, Storage Status Mask, and Object
        # Group Member fields. Manually converted to the KMIP 2.0 format.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Maximum Items - 1
        #     Offset Items - 1
        #     Storage Status Mask - Online Storage | Archival Storage
        #     Object Group Member - Group Member Default
        #     Attributes
        #         Object Type - Public Key
        self.full_encoding_with_attributes = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x58'
            b'\x42\x00\x4F\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\xD4\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x8E\x02\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\xAC\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x01\x25\x01\x00\x00\x00\x10'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
        )

        # Encoding obtained from the KMIP 1.1 testing document, Section 15.3.4.
        # Modified to include the Offset Items and Storage Status Mask fields.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Offset Items - 1
        #     Storage Status Mask - Online Storage | Archival Storage
        #     Object Group Member - Group Member Default
        #     Attribute
        #         Attribute Name - Object Group
        #         Attribute Value - RoundRobinTestGroup
        self.no_maximum_items_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x70'
            b'\x42\x00\xD4\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x8E\x02\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\xAC\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x08\x01\x00\x00\x00\x38'
            b'\x42\x00\x0A\x07\x00\x00\x00\x0C'
            b'\x4F\x62\x6A\x65\x63\x74\x20\x47\x72\x6F\x75\x70\x00\x00\x00\x00'
            b'\x42\x00\x0B\x07\x00\x00\x00\x13'
            b'\x52\x6F\x75\x6E\x64\x52\x6F\x62\x69\x6E\x54\x65\x73\x74\x47\x72'
            b'\x6F\x75\x70\x00\x00\x00\x00\x00'
        )

        # Encoding obtained from the KMIP 1.1 testing document, Section 15.3.4.
        # Modified to include the Storage Status Mask field.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Maximum Items - 1
        #     Storage Status Mask - Online Storage | Archival Storage
        #     Object Group Member - Group Member Default
        #     Attribute
        #         Attribute Name - Object Group
        #         Attribute Value - RoundRobinTestGroup
        self.no_offset_items_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x70'
            b'\x42\x00\x4F\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x8E\x02\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\xAC\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x08\x01\x00\x00\x00\x38'
            b'\x42\x00\x0A\x07\x00\x00\x00\x0C'
            b'\x4F\x62\x6A\x65\x63\x74\x20\x47\x72\x6F\x75\x70\x00\x00\x00\x00'
            b'\x42\x00\x0B\x07\x00\x00\x00\x13'
            b'\x52\x6F\x75\x6E\x64\x52\x6F\x62\x69\x6E\x54\x65\x73\x74\x47\x72'
            b'\x6F\x75\x70\x00\x00\x00\x00\x00'
        )

        # Encoding obtained from the KMIP 1.1 testing document, Section 15.3.4.
        # Modified to include the Offset Items field.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Maximum Items - 1
        #     Offset Items - 1
        #     Object Group Member - Group Member Default
        #     Attribute
        #         Attribute Name - Object Group
        #         Attribute Value - RoundRobinTestGroup
        self.no_storage_status_mask_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x70'
            b'\x42\x00\x4F\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\xD4\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\xAC\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x08\x01\x00\x00\x00\x38'
            b'\x42\x00\x0A\x07\x00\x00\x00\x0C'
            b'\x4F\x62\x6A\x65\x63\x74\x20\x47\x72\x6F\x75\x70\x00\x00\x00\x00'
            b'\x42\x00\x0B\x07\x00\x00\x00\x13'
            b'\x52\x6F\x75\x6E\x64\x52\x6F\x62\x69\x6E\x54\x65\x73\x74\x47\x72'
            b'\x6F\x75\x70\x00\x00\x00\x00\x00'
        )

        # Encoding obtained from the KMIP 1.1 testing document, Section 15.3.4.
        # Modified to include the Offset Items and Storage Status Mask fields.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Maximum Items - 1
        #     Offset Items - 1
        #     Storage Status Mask - Online Storage | Archival Storage
        #     Attribute
        #         Attribute Name - Object Group
        #         Attribute Value - RoundRobinTestGroup
        self.no_object_group_member_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x70'
            b'\x42\x00\x4F\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\xD4\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x8E\x02\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x08\x01\x00\x00\x00\x38'
            b'\x42\x00\x0A\x07\x00\x00\x00\x0C'
            b'\x4F\x62\x6A\x65\x63\x74\x20\x47\x72\x6F\x75\x70\x00\x00\x00\x00'
            b'\x42\x00\x0B\x07\x00\x00\x00\x13'
            b'\x52\x6F\x75\x6E\x64\x52\x6F\x62\x69\x6E\x54\x65\x73\x74\x47\x72'
            b'\x6F\x75\x70\x00\x00\x00\x00\x00'
        )

        # Encoding obtained from the KMIP 1.1 testing document, Section 15.3.4.
        # Modified to include the Offset Items and Storage Status Mask fields.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Maximum Items - 1
        #     Offset Items - 1
        #     Storage Status Mask - Online Storage | Archival Storage
        #     Object Group Member - Group Member Default
        self.no_attributes_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x40'
            b'\x42\x00\x4F\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\xD4\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x8E\x02\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\xAC\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
        )

        # This encoding matches the following set of values:
        # Request Payload
        self.empty_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestLocateRequestPayload, self).tearDown()

    def test_invalid_maximum_items(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the maximum items of a Locate request payload.
        """
        kwargs = {"maximum_items": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "Maximum items must be an integer.",
            payloads.LocateRequestPayload,
            **kwargs
        )

        args = (
            payloads.LocateRequestPayload(),
            "maximum_items",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "Maximum items must be an integer.",
            setattr,
            *args
        )

    def test_invalid_offset_items(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the offset items of a Locate request payload.
        """
        kwargs = {"offset_items": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "Offset items must be an integer.",
            payloads.LocateRequestPayload,
            **kwargs
        )

        args = (
            payloads.LocateRequestPayload(),
            "offset_items",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "Offset items must be an integer.",
            setattr,
            *args
        )

    def test_invalid_storage_status_mask(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the storage status mask of a Locate request payload.
        """
        kwargs = {"storage_status_mask": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "Storage status mask must be an integer representing a valid "
            "StorageStatusMask bit mask.",
            payloads.LocateRequestPayload,
            **kwargs
        )

        kwargs = {"storage_status_mask": 55}
        self.assertRaisesRegex(
            TypeError,
            "Storage status mask must be an integer representing a valid "
            "StorageStatusMask bit mask.",
            payloads.LocateRequestPayload,
            **kwargs
        )

        args = (
            payloads.LocateRequestPayload(),
            "storage_status_mask",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "Storage status mask must be an integer representing a valid "
            "StorageStatusMask bit mask.",
            setattr,
            *args
        )

    def test_invalid_object_group_member(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the object group member of a Locate request payload.
        """
        kwargs = {"object_group_member": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "Object group member must be an ObjectGroupMember enumeration.",
            payloads.LocateRequestPayload,
            **kwargs
        )

        args = (
            payloads.LocateRequestPayload(),
            "object_group_member",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "Object group member must be an ObjectGroupMember enumeration.",
            setattr,
            *args
        )

    def test_invalid_attributes(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the attributes of a Locate request payload.
        """
        kwargs = {"attributes": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "Attributes must be a list of Attribute structures.",
            payloads.LocateRequestPayload,
            **kwargs
        )

        kwargs = {"attributes": ["invalid"]}
        self.assertRaisesRegex(
            TypeError,
            "Attributes must be a list of Attribute structures.",
            payloads.LocateRequestPayload,
            **kwargs
        )

        args = (
            payloads.LocateRequestPayload(),
            "attributes",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "Attributes must be a list of Attribute structures.",
            setattr,
            *args
        )

        args = (
            payloads.LocateRequestPayload(),
            "attributes",
            ["invalid"]
        )
        self.assertRaisesRegex(
            TypeError,
            "Attributes must be a list of Attribute structures.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a Locate request payload can be read from a data stream.
        """
        payload = payloads.LocateRequestPayload()

        self.assertIsNone(payload.maximum_items)
        self.assertIsNone(payload.offset_items)
        self.assertIsNone(payload.storage_status_mask)
        self.assertIsNone(payload.object_group_member)
        self.assertEqual([], payload.attributes)

        payload.read(self.full_encoding)

        self.assertEqual(1, payload.maximum_items)
        self.assertEqual(1, payload.offset_items)
        self.assertEqual(
            enums.get_bit_mask_from_enumerations(
                [
                    enums.StorageStatusMask.ONLINE_STORAGE,
                    enums.StorageStatusMask.ARCHIVAL_STORAGE
                ]
            ),
            payload.storage_status_mask
        )
        self.assertEqual(
            enums.ObjectGroupMember.GROUP_MEMBER_DEFAULT,
            payload.object_group_member
        )
        self.assertIsInstance(payload.attributes, list)
        self.assertEqual(1, len(payload.attributes))
        self.assertEqual(
            objects.Attribute(
                attribute_name=objects.Attribute.AttributeName("Object Group"),
                attribute_value=primitives.TextString(
                    value="RoundRobinTestGroup",
                    tag=enums.Tags.OBJECT_GROUP
                )
            ),
            payload.attributes[0]
        )

    def test_read_kmip_2_0(self):
        """
        Test that a Locate request payload can be read from a data stream
        encoded with the KMIP 2.0 format.
        """
        payload = payloads.LocateRequestPayload()

        self.assertIsNone(payload.maximum_items)
        self.assertIsNone(payload.offset_items)
        self.assertIsNone(payload.storage_status_mask)
        self.assertIsNone(payload.object_group_member)
        self.assertEqual([], payload.attributes)

        payload.read(
            self.full_encoding_with_attributes,
            kmip_version=enums.KMIPVersion.KMIP_2_0
        )

        self.assertEqual(1, payload.maximum_items)
        self.assertEqual(1, payload.offset_items)
        self.assertEqual(
            enums.get_bit_mask_from_enumerations(
                [
                    enums.StorageStatusMask.ONLINE_STORAGE,
                    enums.StorageStatusMask.ARCHIVAL_STORAGE
                ]
            ),
            payload.storage_status_mask
        )
        self.assertEqual(
            enums.ObjectGroupMember.GROUP_MEMBER_DEFAULT,
            payload.object_group_member
        )
        self.assertIsInstance(payload.attributes, list)
        self.assertEqual(1, len(payload.attributes))
        self.assertEqual(
            objects.Attribute(
                attribute_name=objects.Attribute.AttributeName("Object Type"),
                attribute_value=primitives.Enumeration(
                    enums.ObjectType,
                    value=enums.ObjectType.PUBLIC_KEY,
                    tag=enums.Tags.OBJECT_TYPE
                )
            ),
            payload.attributes[0]
        )

    def test_read_missing_maximum_items(self):
        """
        Test that a Locate request payload can be read from a data stream
        even when missing the maximum items.
        """
        payload = payloads.LocateRequestPayload()

        self.assertIsNone(payload.maximum_items)
        self.assertIsNone(payload.offset_items)
        self.assertIsNone(payload.storage_status_mask)
        self.assertIsNone(payload.object_group_member)
        self.assertEqual([], payload.attributes)

        payload.read(self.no_maximum_items_encoding)

        self.assertIsNone(payload.maximum_items)
        self.assertEqual(1, payload.offset_items)
        self.assertEqual(
            enums.get_bit_mask_from_enumerations(
                [
                    enums.StorageStatusMask.ONLINE_STORAGE,
                    enums.StorageStatusMask.ARCHIVAL_STORAGE
                ]
            ),
            payload.storage_status_mask
        )
        self.assertEqual(
            enums.ObjectGroupMember.GROUP_MEMBER_DEFAULT,
            payload.object_group_member
        )
        self.assertIsInstance(payload.attributes, list)
        self.assertEqual(1, len(payload.attributes))
        self.assertEqual(
            objects.Attribute(
                attribute_name=objects.Attribute.AttributeName("Object Group"),
                attribute_value=primitives.TextString(
                    value="RoundRobinTestGroup",
                    tag=enums.Tags.OBJECT_GROUP
                )
            ),
            payload.attributes[0]
        )

    def test_read_missing_offset_items(self):
        """
        Test that a Locate request payload can be read from a data stream
        even when missing the offset items.
        """
        payload = payloads.LocateRequestPayload()

        self.assertIsNone(payload.maximum_items)
        self.assertIsNone(payload.offset_items)
        self.assertIsNone(payload.storage_status_mask)
        self.assertIsNone(payload.object_group_member)
        self.assertEqual([], payload.attributes)

        payload.read(self.no_offset_items_encoding)

        self.assertEqual(1, payload.maximum_items)
        self.assertIsNone(payload.offset_items)
        self.assertEqual(
            enums.get_bit_mask_from_enumerations(
                [
                    enums.StorageStatusMask.ONLINE_STORAGE,
                    enums.StorageStatusMask.ARCHIVAL_STORAGE
                ]
            ),
            payload.storage_status_mask
        )
        self.assertEqual(
            enums.ObjectGroupMember.GROUP_MEMBER_DEFAULT,
            payload.object_group_member
        )
        self.assertIsInstance(payload.attributes, list)
        self.assertEqual(1, len(payload.attributes))
        self.assertEqual(
            objects.Attribute(
                attribute_name=objects.Attribute.AttributeName("Object Group"),
                attribute_value=primitives.TextString(
                    value="RoundRobinTestGroup",
                    tag=enums.Tags.OBJECT_GROUP
                )
            ),
            payload.attributes[0]
        )

    def test_read_missing_storage_status_mask(self):
        """
        Test that a Locate request payload can be read from a data stream
        even when missing the storage status mask.
        """
        payload = payloads.LocateRequestPayload()

        self.assertIsNone(payload.maximum_items)
        self.assertIsNone(payload.offset_items)
        self.assertIsNone(payload.storage_status_mask)
        self.assertIsNone(payload.object_group_member)
        self.assertEqual([], payload.attributes)

        payload.read(self.no_storage_status_mask_encoding)

        self.assertEqual(1, payload.maximum_items)
        self.assertEqual(1, payload.offset_items)
        self.assertIsNone(payload.storage_status_mask)
        self.assertEqual(
            enums.ObjectGroupMember.GROUP_MEMBER_DEFAULT,
            payload.object_group_member
        )
        self.assertIsInstance(payload.attributes, list)
        self.assertEqual(1, len(payload.attributes))
        self.assertEqual(
            objects.Attribute(
                attribute_name=objects.Attribute.AttributeName("Object Group"),
                attribute_value=primitives.TextString(
                    value="RoundRobinTestGroup",
                    tag=enums.Tags.OBJECT_GROUP
                )
            ),
            payload.attributes[0]
        )

    def test_read_missing_object_group_member(self):
        """
        Test that a Locate request payload can be read from a data stream
        even when missing the object group member.
        """
        payload = payloads.LocateRequestPayload()

        self.assertIsNone(payload.maximum_items)
        self.assertIsNone(payload.offset_items)
        self.assertIsNone(payload.storage_status_mask)
        self.assertIsNone(payload.object_group_member)
        self.assertEqual([], payload.attributes)

        payload.read(self.no_object_group_member_encoding)

        self.assertEqual(1, payload.maximum_items)
        self.assertEqual(1, payload.offset_items)
        self.assertEqual(
            enums.get_bit_mask_from_enumerations(
                [
                    enums.StorageStatusMask.ONLINE_STORAGE,
                    enums.StorageStatusMask.ARCHIVAL_STORAGE
                ]
            ),
            payload.storage_status_mask
        )
        self.assertIsNone(payload.object_group_member)
        self.assertIsInstance(payload.attributes, list)
        self.assertEqual(1, len(payload.attributes))
        self.assertEqual(
            objects.Attribute(
                attribute_name=objects.Attribute.AttributeName("Object Group"),
                attribute_value=primitives.TextString(
                    value="RoundRobinTestGroup",
                    tag=enums.Tags.OBJECT_GROUP
                )
            ),
            payload.attributes[0]
        )

    def test_read_missing_attributes(self):
        """
        Test that a Locate request payload can be read from a data stream
        even when missing the attributes.
        """
        payload = payloads.LocateRequestPayload()

        self.assertIsNone(payload.maximum_items)
        self.assertIsNone(payload.offset_items)
        self.assertIsNone(payload.storage_status_mask)
        self.assertIsNone(payload.object_group_member)
        self.assertEqual([], payload.attributes)

        payload.read(self.no_attributes_encoding)

        self.assertEqual(1, payload.maximum_items)
        self.assertEqual(1, payload.offset_items)
        self.assertEqual(
            enums.get_bit_mask_from_enumerations(
                [
                    enums.StorageStatusMask.ONLINE_STORAGE,
                    enums.StorageStatusMask.ARCHIVAL_STORAGE
                ]
            ),
            payload.storage_status_mask
        )
        self.assertEqual(
            enums.ObjectGroupMember.GROUP_MEMBER_DEFAULT,
            payload.object_group_member
        )
        self.assertEqual([], payload.attributes)

    def test_read_missing_everything(self):
        """
        Test that a Locate request payload can be read from a data stream
        even when missing all fields.
        """
        payload = payloads.LocateRequestPayload()

        self.assertIsNone(payload.maximum_items)
        self.assertIsNone(payload.offset_items)
        self.assertIsNone(payload.storage_status_mask)
        self.assertIsNone(payload.object_group_member)
        self.assertEqual([], payload.attributes)

        payload.read(self.empty_encoding)

        self.assertIsNone(payload.maximum_items)
        self.assertIsNone(payload.offset_items)
        self.assertIsNone(payload.storage_status_mask)
        self.assertIsNone(payload.object_group_member)
        self.assertEqual([], payload.attributes)

    def test_write(self):
        """
        Test that a Locate request payload can be written to a data stream.
        """
        payload = payloads.LocateRequestPayload(
            maximum_items=1,
            offset_items=1,
            storage_status_mask=3,
            object_group_member=enums.ObjectGroupMember.GROUP_MEMBER_DEFAULT,
            attributes=[
                objects.Attribute(
                    attribute_name=objects.Attribute.AttributeName(
                        "Object Group"
                    ),
                    attribute_value=primitives.TextString(
                        value="RoundRobinTestGroup",
                        tag=enums.Tags.OBJECT_GROUP
                    )
                )
            ]
        )

        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_kmip_2_0(self):
        """
        Test that a Locate request payload can be written to a data stream
        encoded with the KMIP 2.0 format.
        """
        payload = payloads.LocateRequestPayload(
            maximum_items=1,
            offset_items=1,
            storage_status_mask=3,
            object_group_member=enums.ObjectGroupMember.GROUP_MEMBER_DEFAULT,
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
            ]
        )

        stream = utils.BytearrayStream()
        payload.write(stream, kmip_version=enums.KMIPVersion.KMIP_2_0)

        self.assertEqual(len(self.full_encoding_with_attributes), len(stream))
        self.assertEqual(str(self.full_encoding_with_attributes), str(stream))

    def test_write_missing_maximum_items(self):
        """
        Test that a Locate request payload can be written to a data stream
        even when missing the maximum items.
        """
        payload = payloads.LocateRequestPayload(
            offset_items=1,
            storage_status_mask=3,
            object_group_member=enums.ObjectGroupMember.GROUP_MEMBER_DEFAULT,
            attributes=[
                objects.Attribute(
                    attribute_name=objects.Attribute.AttributeName(
                        "Object Group"
                    ),
                    attribute_value=primitives.TextString(
                        value="RoundRobinTestGroup",
                        tag=enums.Tags.OBJECT_GROUP
                    )
                )
            ]
        )

        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.no_maximum_items_encoding), len(stream))
        self.assertEqual(str(self.no_maximum_items_encoding), str(stream))

    def test_write_missing_offset_items(self):
        """
        Test that a Locate request payload can be written to a data stream
        even when missing the offset items.
        """
        payload = payloads.LocateRequestPayload(
            maximum_items=1,
            storage_status_mask=3,
            object_group_member=enums.ObjectGroupMember.GROUP_MEMBER_DEFAULT,
            attributes=[
                objects.Attribute(
                    attribute_name=objects.Attribute.AttributeName(
                        "Object Group"
                    ),
                    attribute_value=primitives.TextString(
                        value="RoundRobinTestGroup",
                        tag=enums.Tags.OBJECT_GROUP
                    )
                )
            ]
        )

        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.no_offset_items_encoding), len(stream))
        self.assertEqual(str(self.no_offset_items_encoding), str(stream))

    def test_write_missing_storage_status_mask(self):
        """
        Test that a Locate request payload can be written to a data stream
        even when missing the storage status mask.
        """
        payload = payloads.LocateRequestPayload(
            maximum_items=1,
            offset_items=1,
            object_group_member=enums.ObjectGroupMember.GROUP_MEMBER_DEFAULT,
            attributes=[
                objects.Attribute(
                    attribute_name=objects.Attribute.AttributeName(
                        "Object Group"
                    ),
                    attribute_value=primitives.TextString(
                        value="RoundRobinTestGroup",
                        tag=enums.Tags.OBJECT_GROUP
                    )
                )
            ]
        )

        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(
            len(self.no_storage_status_mask_encoding),
            len(stream)
        )
        self.assertEqual(
            str(self.no_storage_status_mask_encoding),
            str(stream)
        )

    def test_write_missing_object_group_member(self):
        """
        Test that a Locate request payload can be written to a data stream
        even when missing the object group member.
        """
        payload = payloads.LocateRequestPayload(
            maximum_items=1,
            offset_items=1,
            storage_status_mask=3,
            attributes=[
                objects.Attribute(
                    attribute_name=objects.Attribute.AttributeName(
                        "Object Group"
                    ),
                    attribute_value=primitives.TextString(
                        value="RoundRobinTestGroup",
                        tag=enums.Tags.OBJECT_GROUP
                    )
                )
            ]
        )

        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(
            len(self.no_object_group_member_encoding),
            len(stream)
        )
        self.assertEqual(
            str(self.no_object_group_member_encoding),
            str(stream)
        )

    def test_write_missing_attributes(self):
        """
        Test that a Locate request payload can be written to a data stream
        even when missing the attributes.
        """
        payload = payloads.LocateRequestPayload(
            maximum_items=1,
            offset_items=1,
            storage_status_mask=3,
            object_group_member=enums.ObjectGroupMember.GROUP_MEMBER_DEFAULT,
        )

        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.no_attributes_encoding), len(stream))
        self.assertEqual(str(self.no_attributes_encoding), str(stream))

    def test_write_missing_everything(self):
        """
        Test that a Locate request payload can be written to a data stream
        even when missing all fields.
        """
        payload = payloads.LocateRequestPayload()

        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.empty_encoding), len(stream))
        self.assertEqual(str(self.empty_encoding), str(stream))

    def test_repr(self):
        """
        Test that repr can be applied to a Locate request payload structure.
        """
        payload = payloads.LocateRequestPayload(
            maximum_items=1,
            offset_items=1,
            storage_status_mask=3,
            object_group_member=enums.ObjectGroupMember.GROUP_MEMBER_DEFAULT,
            attributes=[
                objects.Attribute(
                    attribute_name=objects.Attribute.AttributeName(
                        "Object Group"
                    ),
                    attribute_value=primitives.TextString(
                        value="RoundRobinTestGroup",
                        tag=enums.Tags.OBJECT_GROUP
                    )
                )
            ]
        )

        s = "LocateRequestPayload(" \
            "maximum_items=1, " \
            "offset_items=1, " \
            "storage_status_mask=3, " \
            "object_group_member=ObjectGroupMember.GROUP_MEMBER_DEFAULT, " \
            "attributes=["
#            "Attribute(" \
#            "attribute_name=AttributeName(value='Object Group'), " \
#            "attribute_index=None, " \
#            "attribute_value=TextString(value='RoundRobinTestGroup'))" \
#            "])"

        # TODO (ph) Uncomment above when Attribute repr fixed. Fix below too.

        self.assertTrue(repr(payload).startswith(s))

    def test_str(self):
        """
        Test that str can be applied to a Locate request payload structure.
        """
        payload = payloads.LocateRequestPayload(
            maximum_items=1,
            offset_items=1,
            storage_status_mask=3,
            object_group_member=enums.ObjectGroupMember.GROUP_MEMBER_DEFAULT,
            attributes=[
                objects.Attribute(
                    attribute_name=objects.Attribute.AttributeName(
                        "Object Group"
                    ),
                    attribute_value=primitives.TextString(
                        value="RoundRobinTestGroup",
                        tag=enums.Tags.OBJECT_GROUP
                    )
                )
            ]
        )

        s = '{' \
            '"maximum_items": 1, ' \
            '"offset_items": 1, ' \
            '"storage_status_mask": 3, ' \
            '"object_group_member": ObjectGroupMember.GROUP_MEMBER_DEFAULT, ' \
            '"attributes=[' \
            '{' \
            '"attribute_name": "Object Group", ' \
            '"attribute_index": None, ' \
            '"attribute_value": "RoundRobinTestGroup"' \
            '}]' \
            '}'

        self.assertEqual(s, str(payload))

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two Locate
        request payloads with the same data.
        """
        a = payloads.LocateRequestPayload()
        b = payloads.LocateRequestPayload()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = payloads.LocateRequestPayload(
            maximum_items=1,
            offset_items=1,
            storage_status_mask=3,
            object_group_member=enums.ObjectGroupMember.GROUP_MEMBER_DEFAULT,
            attributes=[
                objects.Attribute(
                    attribute_name=objects.Attribute.AttributeName(
                        "Object Group"
                    ),
                    attribute_value=primitives.TextString(
                        value="RoundRobinTestGroup",
                        tag=enums.Tags.OBJECT_GROUP
                    )
                )
            ]
        )
        b = payloads.LocateRequestPayload(
            maximum_items=1,
            offset_items=1,
            storage_status_mask=3,
            object_group_member=enums.ObjectGroupMember.GROUP_MEMBER_DEFAULT,
            attributes=[
                objects.Attribute(
                    attribute_name=objects.Attribute.AttributeName(
                        "Object Group"
                    ),
                    attribute_value=primitives.TextString(
                        value="RoundRobinTestGroup",
                        tag=enums.Tags.OBJECT_GROUP
                    )
                )
            ]
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_maximum_items(self):
        """
        Test that the equality operator returns False when comparing two
        Locate request payloads with different maximum items.
        """
        a = payloads.LocateRequestPayload(maximum_items=1)
        b = payloads.LocateRequestPayload(maximum_items=2)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_offset_items(self):
        """
        Test that the equality operator returns False when comparing two
        Locate request payloads with different offset items.
        """
        a = payloads.LocateRequestPayload(offset_items=1)
        b = payloads.LocateRequestPayload(offset_items=2)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_storage_status_mask(self):
        """
        Test that the equality operator returns False when comparing two
        Locate request payloads with different storage status mask.
        """
        a = payloads.LocateRequestPayload(storage_status_mask=1)
        b = payloads.LocateRequestPayload(storage_status_mask=2)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_object_group_member(self):
        """
        Test that the equality operator returns False when comparing two
        Locate request payloads with different object group member.
        """
        a = payloads.LocateRequestPayload(
            object_group_member=enums.ObjectGroupMember.GROUP_MEMBER_DEFAULT
        )
        b = payloads.LocateRequestPayload(
            object_group_member=enums.ObjectGroupMember.GROUP_MEMBER_FRESH
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_attributes(self):
        """
        Test that the equality operator returns False when comparing two
        Locate request payloads with different attributes.
        """
        a = payloads.LocateRequestPayload(
            attributes=[
                objects.Attribute(
                    attribute_name=objects.Attribute.AttributeName(
                        "Object Group"
                    ),
                    attribute_value=primitives.TextString(
                        value="RoundRobinTestGroup",
                        tag=enums.Tags.OBJECT_GROUP
                    )
                )
            ]
        )
        b = payloads.LocateRequestPayload(
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
            ]
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        Locate request payloads with different types.
        """
        a = payloads.LocateRequestPayload()
        b = "invalid"

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        Locate request payloads with the same data.
        """
        a = payloads.LocateRequestPayload()
        b = payloads.LocateRequestPayload()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = payloads.LocateRequestPayload(
            maximum_items=1,
            offset_items=1,
            storage_status_mask=3,
            object_group_member=enums.ObjectGroupMember.GROUP_MEMBER_DEFAULT,
            attributes=[
                objects.Attribute(
                    attribute_name=objects.Attribute.AttributeName(
                        "Object Group"
                    ),
                    attribute_value=primitives.TextString(
                        value="RoundRobinTestGroup",
                        tag=enums.Tags.OBJECT_GROUP
                    )
                )
            ]
        )
        b = payloads.LocateRequestPayload(
            maximum_items=1,
            offset_items=1,
            storage_status_mask=3,
            object_group_member=enums.ObjectGroupMember.GROUP_MEMBER_DEFAULT,
            attributes=[
                objects.Attribute(
                    attribute_name=objects.Attribute.AttributeName(
                        "Object Group"
                    ),
                    attribute_value=primitives.TextString(
                        value="RoundRobinTestGroup",
                        tag=enums.Tags.OBJECT_GROUP
                    )
                )
            ]
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_maximum_items(self):
        """
        Test that the inequality operator returns True when comparing two
        Locate request payloads with different maximum items.
        """
        a = payloads.LocateRequestPayload(maximum_items=1)
        b = payloads.LocateRequestPayload(maximum_items=2)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_offset_items(self):
        """
        Test that the inequality operator returns True when comparing two
        Locate request payloads with different offset items.
        """
        a = payloads.LocateRequestPayload(offset_items=1)
        b = payloads.LocateRequestPayload(offset_items=2)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_storage_status_mask(self):
        """
        Test that the inequality operator returns True when comparing two
        Locate request payloads with different storage status mask.
        """
        a = payloads.LocateRequestPayload(storage_status_mask=1)
        b = payloads.LocateRequestPayload(storage_status_mask=2)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_object_group_member(self):
        """
        Test that the inequality operator returns True when comparing two
        Locate request payloads with different object group member.
        """
        a = payloads.LocateRequestPayload(
            object_group_member=enums.ObjectGroupMember.GROUP_MEMBER_DEFAULT
        )
        b = payloads.LocateRequestPayload(
            object_group_member=enums.ObjectGroupMember.GROUP_MEMBER_FRESH
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_attributes(self):
        """
        Test that the inequality operator returns True when comparing two
        Locate request payloads with different attributes.
        """
        a = payloads.LocateRequestPayload(
            attributes=[
                objects.Attribute(
                    attribute_name=objects.Attribute.AttributeName(
                        "Object Group"
                    ),
                    attribute_value=primitives.TextString(
                        value="RoundRobinTestGroup",
                        tag=enums.Tags.OBJECT_GROUP
                    )
                )
            ]
        )
        b = payloads.LocateRequestPayload(
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
            ]
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        Locate request payloads with different types.
        """
        a = payloads.LocateRequestPayload()
        b = "invalid"

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_init(self):
        """
        Test that a Locate request payload can be constructed with no
        arguments.
        """
        payload = payloads.LocateRequestPayload()
        self.assertIsNone(payload.maximum_items)
        self.assertIsNone(payload.offset_items)
        self.assertIsNone(payload.storage_status_mask)
        self.assertIsNone(payload.object_group_member)
        self.assertEqual([], payload.attributes)

    def test_init_with_args(self):
        """
        Test that a Locate request payload can be constructed with valid
        values.
        """
        payload = payloads.LocateRequestPayload(
            maximum_items=1,
            offset_items=1,
            storage_status_mask=3,
            object_group_member=enums.ObjectGroupMember.GROUP_MEMBER_DEFAULT,
            attributes=[
                objects.Attribute(
                    attribute_name=objects.Attribute.AttributeName(
                        "Object Group"
                    ),
                    attribute_value=primitives.TextString(
                        value="RoundRobinTestGroup",
                        tag=enums.Tags.OBJECT_GROUP
                    )
                )
            ]
        )

        self.assertEqual(1, payload.maximum_items)
        self.assertEqual(1, payload.offset_items)
        self.assertEqual(3, payload.storage_status_mask)
        self.assertEqual(
            enums.ObjectGroupMember.GROUP_MEMBER_DEFAULT,
            payload.object_group_member
        )
        self.assertEqual(1, len(payload.attributes))

    def test_read_valid(self):
        """
        Test that a Locate request payload can be read from a valid byte
        stream.
        """
        self.test_read()

    def test_read_missing_required_field(self):
        """
        Test that an exception is raised when reading a payload missing a
        required field.
        """
        payload = payloads.LocateRequestPayload()
        self.assertRaises(Exception, payload.read, utils.BytearrayStream(b""))

    def test_write_valid(self):
        """
        Test that a Locate request payload can be written to a byte stream.
        """
        self.test_write()

    def test_read_write_roundtrip(self):
        """
        Test that a Locate request payload can be read and written without
        changing the encoded bytes.
        """
        payload = payloads.LocateRequestPayload()
        payload.read(utils.BytearrayStream(self.full_encoding.buffer))

        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(str(self.full_encoding), str(stream))

    def test_validate_invalid(self):
        """
        Test that an exception is raised when a field has an invalid type.
        """
        self.test_invalid_maximum_items()

    def test_eq(self):
        """
        Test that two Locate request payloads with the same data are equal.
        """
        self.test_equal_on_equal()

    def test_ne(self):
        """
        Test that two Locate request payloads with different data are not
        equal.
        """
        self.test_not_equal_on_not_equal_maximum_items()

    def test_str(self):
        """
        Test the str output for a Locate request payload.
        """
        payload = payloads.LocateRequestPayload()
        self.assertIsInstance(str(payload), str)

class TestLocateResponsePayload(testtools.TestCase):

    def setUp(self):
        super(TestLocateResponsePayload, self).setUp()

        # Encoding obtained from the KMIP 1.1 testing document, Section 15.3.4.
        # Modified to include the Located Items field.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Located Items - 1
        #     Unique Identifier - 8d945322-fd70-495d-bf7f-71481d1401f6
        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x40'
            b'\x42\x00\xD5\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x38\x64\x39\x34\x35\x33\x32\x32\x2D\x66\x64\x37\x30\x2D\x34\x39'
            b'\x35\x64\x2D\x62\x66\x37\x66\x2D\x37\x31\x34\x38\x31\x64\x31\x34'
            b'\x30\x31\x66\x36\x00\x00\x00\x00'
        )

        # Encoding obtained from the KMIP 1.1 testing document, Section 15.3.4.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Unique Identifier - 8d945322-fd70-495d-bf7f-71481d1401f6
        self.no_located_items_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x30'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x38\x64\x39\x34\x35\x33\x32\x32\x2D\x66\x64\x37\x30\x2D\x34\x39'
            b'\x35\x64\x2D\x62\x66\x37\x66\x2D\x37\x31\x34\x38\x31\x64\x31\x34'
            b'\x30\x31\x66\x36\x00\x00\x00\x00'
        )

        # Encoding obtained from the KMIP 1.1 testing document, Section 15.3.4.
        # Modified to include the Located Items field.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Located Items - 1
        self.no_unique_identifiers_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x10'
            b'\x42\x00\xD5\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
        )

        # This encoding matches the following set of values:
        # Request Payload
        self.empty_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestLocateResponsePayload, self).tearDown()

    def test_invalid_located_items(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the located items of a Locate response payload.
        """
        kwargs = {"located_items": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "Located items must be an integer.",
            payloads.LocateResponsePayload,
            **kwargs
        )

        args = (
            payloads.LocateResponsePayload(),
            "located_items",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "Located items must be an integer.",
            setattr,
            *args
        )

    def test_invalid_unique_identifiers(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the unique identifiers of a Locate response payload.
        """
        kwargs = {"unique_identifiers": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "Unique identifiers must be a list of strings.",
            payloads.LocateResponsePayload,
            **kwargs
        )

        kwargs = {"unique_identifiers": [0]}
        self.assertRaisesRegex(
            TypeError,
            "Unique identifiers must be a list of strings.",
            payloads.LocateResponsePayload,
            **kwargs
        )

        args = (
            payloads.LocateResponsePayload(),
            "unique_identifiers",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "Unique identifiers must be a list of strings.",
            setattr,
            *args
        )

        args = (
            payloads.LocateResponsePayload(),
            "unique_identifiers",
            [0]
        )
        self.assertRaisesRegex(
            TypeError,
            "Unique identifiers must be a list of strings.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a Locate response payload can be read from a data stream.
        """
        payload = payloads.LocateResponsePayload()

        self.assertIsNone(payload.located_items)
        self.assertEqual([], payload.unique_identifiers)

        payload.read(self.full_encoding)

        self.assertEqual(1, payload.located_items)
        self.assertIsInstance(payload.unique_identifiers, list)
        self.assertEqual(1, len(payload.unique_identifiers))
        self.assertEqual(
            ["8d945322-fd70-495d-bf7f-71481d1401f6"],
            payload.unique_identifiers
        )

    def test_read_missing_located_items(self):
        """
        Test that a Locate response payload can be read from a data stream
        even when missing the located items.
        """
        payload = payloads.LocateResponsePayload()

        self.assertIsNone(payload.located_items)
        self.assertEqual([], payload.unique_identifiers)

        payload.read(self.no_located_items_encoding)

        self.assertIsNone(payload.located_items)
        self.assertIsInstance(payload.unique_identifiers, list)
        self.assertEqual(1, len(payload.unique_identifiers))
        self.assertEqual(
            ["8d945322-fd70-495d-bf7f-71481d1401f6"],
            payload.unique_identifiers
        )

    def test_read_missing_unique_identifiers(self):
        """
        Test that a Locate response payload can be read from a data stream
        even when missing the unique identifiers.
        """
        payload = payloads.LocateResponsePayload()

        self.assertIsNone(payload.located_items)
        self.assertEqual([], payload.unique_identifiers)

        payload.read(self.no_unique_identifiers_encoding)

        self.assertEqual(1, payload.located_items)
        self.assertEqual([], payload.unique_identifiers)

    def test_read_missing_everything(self):
        """
        Test that a Locate response payload can be read from a data stream
        even when missing all fields.
        """
        payload = payloads.LocateResponsePayload()

        self.assertIsNone(payload.located_items)
        self.assertEqual([], payload.unique_identifiers)

        payload.read(self.empty_encoding)

        self.assertIsNone(payload.located_items)
        self.assertEqual([], payload.unique_identifiers)

    def test_write(self):
        """
        Test that a Locate response payload can be written to a data stream.
        """
        payload = payloads.LocateResponsePayload(
            located_items=1,
            unique_identifiers=["8d945322-fd70-495d-bf7f-71481d1401f6"]
        )

        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_missing_located_items(self):
        """
        Test that a Locate response payload can be written to a data stream
        even when missing the located items.
        """
        payload = payloads.LocateResponsePayload(
            located_items=1
        )

        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.no_unique_identifiers_encoding), len(stream))
        self.assertEqual(str(self.no_unique_identifiers_encoding), str(stream))

    def test_write_missing_unique_identifiers(self):
        """
        Test that a Locate response payload can be written to a data stream
        even when missing the unique identifiers.
        """
        payload = payloads.LocateResponsePayload(
            located_items=1,
            unique_identifiers=["8d945322-fd70-495d-bf7f-71481d1401f6"]
        )

        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_missing_everything(self):
        """
        Test that a Locate response payload can be written to a data stream
        even when missing all fields.
        """
        payload = payloads.LocateResponsePayload()

        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.empty_encoding), len(stream))
        self.assertEqual(str(self.empty_encoding), str(stream))

    def test_repr(self):
        """
        Test that repr can be applied to a Locate response payload structure.
        """
        payload = payloads.LocateResponsePayload(
            located_items=1,
            unique_identifiers=["8d945322-fd70-495d-bf7f-71481d1401f6"]
        )

        s = "LocateResponsePayload(" \
            "located_items=1, " \
            "unique_identifiers=['8d945322-fd70-495d-bf7f-71481d1401f6'])"

        self.assertEqual(s, repr(payload))

    def str(self):
        """
        Test that str can be applied to a Locate response payload structure.
        """
        payload = payloads.LocateResponsePayload(
            located_items=1,
            unique_identifiers=["8d945322-fd70-495d-bf7f-71481d1401f6"]
        )

        s = "LocateResponsePayload(" \
            "located_items=1, " \
            "unique_identifiers=['8d945322-fd70-495d-bf7f-71481d1401f6'])"

        self.assertEqual(s, repr(payload))

        s = '{' \
            '"located_items": 1, ' \
            '"unique_identifiers": [' \
            '"8d945322-fd70-495d-bf7f-71481d1401f6"]' \
            ']' \
            '}'

        self.assertEqual(s, str(payload))

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two Locate
        response payloads with the same data.
        """
        a = payloads.LocateResponsePayload()
        b = payloads.LocateResponsePayload()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = payloads.LocateResponsePayload(
            located_items=1,
            unique_identifiers=["8d945322-fd70-495d-bf7f-71481d1401f6"]
        )
        b = payloads.LocateResponsePayload(
            located_items=1,
            unique_identifiers=["8d945322-fd70-495d-bf7f-71481d1401f6"]
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_located_items(self):
        """
        Test that the equality operator returns False when comparing two
        Locate response payloads with different located items.
        """
        a = payloads.LocateResponsePayload(located_items=1)
        b = payloads.LocateResponsePayload(located_items=2)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_unique_identifiers(self):
        """
        Test that the equality operator returns False when comparing two
        Locate response payloads with different unique identifiers.
        """
        a = payloads.LocateResponsePayload(
            unique_identifiers=["8d945322-fd70-495d-bf7f-71481d1401f6"]
        )
        b = payloads.LocateResponsePayload(
            unique_identifiers=["49a1ca88-6bea-4fb2-b450-7e58802c3038"]
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        Locate response payloads with different types.
        """
        a = payloads.LocateResponsePayload()
        b = "invalid"

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        Locate response payloads with the same data.
        """
        a = payloads.LocateResponsePayload()
        b = payloads.LocateResponsePayload()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = payloads.LocateResponsePayload(
            located_items=1,
            unique_identifiers=["8d945322-fd70-495d-bf7f-71481d1401f6"]
        )
        b = payloads.LocateResponsePayload(
            located_items=1,
            unique_identifiers=["8d945322-fd70-495d-bf7f-71481d1401f6"]
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_located_items(self):
        """
        Test that the inequality operator returns True when comparing two
        Locate response payloads with different located items.
        """
        a = payloads.LocateResponsePayload(located_items=1)
        b = payloads.LocateResponsePayload(located_items=2)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_unique_identifiers(self):
        """
        Test that the inequality operator returns True when comparing two
        Locate response payloads with different unique identifiers.
        """
        a = payloads.LocateResponsePayload(
            unique_identifiers=["8d945322-fd70-495d-bf7f-71481d1401f6"]
        )
        b = payloads.LocateResponsePayload(
            unique_identifiers=["49a1ca88-6bea-4fb2-b450-7e58802c3038"]
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        Locate response payloads with different types.
        """
        a = payloads.LocateResponsePayload()
        b = "invalid"

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_init(self):
        """
        Test that a Locate response payload can be constructed with no
        arguments.
        """
        payload = payloads.LocateResponsePayload()
        self.assertIsNone(payload.located_items)
        self.assertEqual([], payload.unique_identifiers)

    def test_init_with_args(self):
        """
        Test that a Locate response payload can be constructed with valid
        values.
        """
        payload = payloads.LocateResponsePayload(
            located_items=1,
            unique_identifiers=["8d945322-fd70-495d-bf7f-71481d1401f6"]
        )

        self.assertEqual(1, payload.located_items)
        self.assertEqual(
            ["8d945322-fd70-495d-bf7f-71481d1401f6"],
            payload.unique_identifiers
        )

    def test_read_valid(self):
        """
        Test that a Locate response payload can be read from a valid byte
        stream.
        """
        self.test_read()

    def test_read_missing_required_field(self):
        """
        Test that an exception is raised when reading a payload missing a
        required field.
        """
        self.test_read_missing_located_items()

    def test_write_valid(self):
        """
        Test that a Locate response payload can be written to a byte stream.
        """
        self.test_write()

    def test_read_write_roundtrip(self):
        """
        Test that a Locate response payload can be read and written without
        changing the encoded bytes.
        """
        payload = payloads.LocateResponsePayload()
        payload.read(utils.BytearrayStream(self.full_encoding.buffer))

        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(str(self.full_encoding), str(stream))

    def test_validate_invalid(self):
        """
        Test that an exception is raised when a field has an invalid type.
        """
        self.test_invalid_located_items()

    def test_eq(self):
        """
        Test that two Locate response payloads with the same data are equal.
        """
        self.test_equal_on_equal()

    def test_ne(self):
        """
        Test that two Locate response payloads with different data are not
        equal.
        """
        self.test_not_equal_on_not_equal_located_items()

    def test_str(self):
        """
        Test the str output for a Locate response payload.
        """
        payload = payloads.LocateResponsePayload(
            located_items=1,
            unique_identifiers=["8d945322-fd70-495d-bf7f-71481d1401f6"]
        )
        self.assertIsInstance(str(payload), str)
