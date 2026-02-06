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

from kmip.core import enums
from kmip.core import objects
from kmip.core import primitives
from kmip.core import utils
from kmip.core.messages.payloads import base

class LocateRequestPayload(base.RequestPayload):
    """
    A request payload for the Locate operation.

    Attributes:
        maximum_items: The maximum number of object identifiers to be returned.
        offset_items: The number of object identifiers to skip when selecting
            the object identifiers to return.
        storage_status_mask: A bit mask specifying which types of stored
            objects should be searched.
        object_group_member: The object group member type for the searched
            objects.
        attributes: The attributes that should be used to filter and match
            objects.
    """

    def __init__(self,
                 maximum_items=None,
                 offset_items=None,
                 storage_status_mask=None,
                 object_group_member=None,
                 attributes=None):
        """
        Construct a Locate request payload structure.

        Args:
            maximum_items (int): An integer specifying the maximum number of
                object identifiers to be returned. Optional, defaults to None.
            offset_items (int): An integer specifying the number of object
                identifiers to skip when selecting the object identifiers to
                return. Optional, defaults to None.
            storage_status_mask (int, list): An integer bit mask or a
                corresponding list of StorageStatusMask enumerations indicating
                which types of stored objects should be searched. Optional,
                defaults to None.
            object_group_member (enum): An ObjectGroupMember enumeration
                specifying the object group member type for the searched
                objects. Optional, defaults to None.
            attributes (list): A list of Attribute structures containing the
                attribute values that should be used to filter and match
                objects. Optional, defaults to None. Required for read/write
                for KMIP 2.0+.
        """
        super(LocateRequestPayload, self).__init__()

        self._maximum_items = None
        self._offset_items = None
        self._storage_status_mask = None
        self._object_group_member = None
        self._attributes = None

        self.maximum_items = maximum_items
        self.offset_items = offset_items
        self.storage_status_mask = storage_status_mask
        self.object_group_member = object_group_member
        self.attributes = attributes

    @property
    def maximum_items(self):
        if self._maximum_items:
            return self._maximum_items.value
        else:
            return None

    @maximum_items.setter
    def maximum_items(self, value):
        if value is None:
            self._maximum_items = None
        elif isinstance(value, int):
            self._maximum_items = primitives.Integer(
                value=value,
                tag=enums.Tags.MAXIMUM_ITEMS
            )
        else:
            raise TypeError("Maximum items must be an integer.")

    @property
    def offset_items(self):
        if self._offset_items:
            return self._offset_items.value
        else:
            return None

    @offset_items.setter
    def offset_items(self, value):
        if value is None:
            self._offset_items = None
        elif isinstance(value, int):
            self._offset_items = primitives.Integer(
                value=value,
                tag=enums.Tags.OFFSET_ITEMS
            )
        else:
            raise TypeError("Offset items must be an integer.")

    @property
    def storage_status_mask(self):
        if self._storage_status_mask:
            return self._storage_status_mask.value
        else:
            return None

    @storage_status_mask.setter
    def storage_status_mask(self, value):
        if value is None:
            self._storage_status_mask = None
        elif isinstance(value, int):
            if enums.is_bit_mask(enums.StorageStatusMask, value):
                self._storage_status_mask = primitives.Integer(
                    value=value,
                    tag=enums.Tags.STORAGE_STATUS_MASK
                )
            else:
                raise TypeError(
                    "Storage status mask must be an integer representing a "
                    "valid StorageStatusMask bit mask."
                )
        else:
            raise TypeError(
                "Storage status mask must be an integer representing a valid "
                "StorageStatusMask bit mask."
            )

    @property
    def object_group_member(self):
        if self._object_group_member:
            return self._object_group_member.value
        else:
            return None

    @object_group_member.setter
    def object_group_member(self, value):
        if value is None:
            self._object_group_member = None
        elif isinstance(value, enums.ObjectGroupMember):
            self._object_group_member = primitives.Enumeration(
                enums.ObjectGroupMember,
                value=value,
                tag=enums.Tags.OBJECT_GROUP_MEMBER
            )
        else:
            raise TypeError(
                "Object group member must be an ObjectGroupMember enumeration."
            )

    @property
    def attributes(self):
        if self._attributes:
            return self._attributes
        return []

    @attributes.setter
    def attributes(self, value):
        if value is None:
            self._attributes = []
        elif isinstance(value, list):
            for v in value:
                if not isinstance(v, objects.Attribute):
                    raise TypeError(
                        "Attributes must be a list of Attribute structures."
                    )
            self._attributes = value
        else:
            raise TypeError(
                "Attributes must be a list of Attribute structures."
            )

    def read(self, input_buffer, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the Locate request payload and decode it into
        its constituent parts.

        Args:
            input_buffer (stream): A data buffer containing encoded object
                data, supporting a read method.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            InvalidKmipEncoding: Raised if the attributes structure is missing
                from the encoded payload for KMIP 2.0+ encodings.
        """
        super(LocateRequestPayload, self).read(
            input_buffer,
            kmip_version=kmip_version
        )
        local_buffer = utils.BytearrayStream(input_buffer.read(self.length))

        if self.is_tag_next(enums.Tags.MAXIMUM_ITEMS, local_buffer):
            self._maximum_items = primitives.Integer(
                tag=enums.Tags.MAXIMUM_ITEMS
            )
            self._maximum_items.read(
                local_buffer,
                kmip_version=kmip_version
            )

        if self.is_tag_next(enums.Tags.OFFSET_ITEMS, local_buffer):
            self._offset_items = primitives.Integer(
                tag=enums.Tags.OFFSET_ITEMS
            )
            self._offset_items.read(
                local_buffer,
                kmip_version=kmip_version
            )

        if self.is_tag_next(enums.Tags.STORAGE_STATUS_MASK, local_buffer):
            self._storage_status_mask = primitives.Integer(
                tag=enums.Tags.STORAGE_STATUS_MASK
            )
            self._storage_status_mask.read(
                local_buffer,
                kmip_version=kmip_version
            )

        if self.is_tag_next(enums.Tags.OBJECT_GROUP_MEMBER, local_buffer):
            self._object_group_member = primitives.Enumeration(
                enums.ObjectGroupMember,
                tag=enums.Tags.OBJECT_GROUP_MEMBER
            )
            self._object_group_member.read(
                local_buffer,
                kmip_version=kmip_version
            )

        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            while self.is_tag_next(enums.Tags.ATTRIBUTE, local_buffer):
                attribute = objects.Attribute()
                attribute.read(local_buffer, kmip_version=kmip_version)
                self._attributes.append(attribute)
        else:
            if self.is_tag_next(enums.Tags.ATTRIBUTES, local_buffer):
                attributes = objects.Attributes()
                attributes.read(local_buffer, kmip_version=kmip_version)
                # TODO (ph) Add a new utility to avoid using TemplateAttributes
                temp_attr = objects.convert_attributes_to_template_attribute(
                    attributes
                )
                self._attributes = temp_attr.attributes

    def write(self, output_buffer, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the Locate request payload to a buffer.

        Args:
            output_buffer (stream): A data buffer in which to encode object
                data, supporting a write method.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.
        """
        local_buffer = utils.BytearrayStream()

        if self._maximum_items:
            self._maximum_items.write(local_buffer, kmip_version=kmip_version)

        if self._offset_items:
            self._offset_items.write(local_buffer, kmip_version=kmip_version)

        if self._storage_status_mask:
            self._storage_status_mask.write(
                local_buffer,
                kmip_version=kmip_version
            )

        if self._object_group_member:
            self._object_group_member.write(
                local_buffer,
                kmip_version=kmip_version
            )

        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            if self._attributes:
                for attribute in self.attributes:
                    attribute.write(
                        local_buffer,
                        kmip_version=kmip_version
                    )
        else:
            if self._attributes:
                # TODO (ph) Add a new utility to avoid using TemplateAttributes
                template_attribute = objects.TemplateAttribute(
                    attributes=self.attributes
                )
                attributes = objects.convert_template_attribute_to_attributes(
                    template_attribute
                )
                attributes.write(local_buffer, kmip_version=kmip_version)

        self.length = local_buffer.length()
        super(LocateRequestPayload, self).write(
            output_buffer,
            kmip_version=kmip_version
        )
        output_buffer.write(local_buffer.buffer)

    def __eq__(self, other):
        if isinstance(other, LocateRequestPayload):
            if self.maximum_items != other.maximum_items:
                return False
            elif self.offset_items != other.offset_items:
                return False
            elif self.storage_status_mask != other.storage_status_mask:
                return False
            elif self.object_group_member != other.object_group_member:
                return False
            elif self.attributes != other.attributes:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, LocateRequestPayload):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "maximum_items={}".format(self.maximum_items),
            "offset_items={}".format(self.offset_items),
            "storage_status_mask={}".format(self.storage_status_mask),
            "object_group_member={}".format(self.object_group_member),
            "attributes={}".format(
                [repr(attribute) for attribute in self.attributes]
            )
        ])
        return "LocateRequestPayload({})".format(args)

    def __str__(self):
        value = ", ".join(
            [
                '"maximum_items": {}'.format(self.maximum_items),
                '"offset_items": {}'.format(self.offset_items),
                '"storage_status_mask": {}'.format(self.storage_status_mask),
                '"object_group_member": {}'.format(self.object_group_member),
                '"attributes": {}'.format(
                    [str(attribute) for attribute in self.attributes]
                )
            ]
        )
        return '{' + value + '}'

class LocateResponsePayload(base.ResponsePayload):
    """
    A response payload for the Locate operation.

    Attributes:
        located_items: The number of matching objects found by the server.
        unique_identifiers: The object identifiers for the matching objects.
    """

    def __init__(self,
                 located_items=None,
                 unique_identifiers=None):
        """
        Construct a Locate response payload structure.

        Args:
            located_items (int): An integer specifying the number of matching
                objects found by the server. Note that this may not equal the
                number of object identifiers returned in this payload.
                Optional, defaults to None.
            unique_identifiers (list): A list of strings specifying the object
                identifiers for matching objects. Optional, defaults to None.
        """
        super(LocateResponsePayload, self).__init__()

        self._located_items = None
        self._unique_identifiers = None

        self.located_items = located_items
        self.unique_identifiers = unique_identifiers

    @property
    def located_items(self):
        if self._located_items:
            return self._located_items.value
        return None

    @located_items.setter
    def located_items(self, value):
        if value is None:
            self._located_items = None
        elif isinstance(value, int):
            self._located_items = primitives.Integer(
                value=value,
                tag=enums.Tags.LOCATED_ITEMS
            )
        else:
            raise TypeError("Located items must be an integer.")

    @property
    def unique_identifiers(self):
        if self._unique_identifiers:
            return [x.value for x in self._unique_identifiers]
        return []

    @unique_identifiers.setter
    def unique_identifiers(self, value):
        if value is None:
            self._unique_identifiers = []
        elif isinstance(value, list):
            self._unique_identifiers = []
            for v in value:
                if not isinstance(v, str):
                    self._unique_identifiers = []
                    raise TypeError(
                        "Unique identifiers must be a list of strings."
                    )
                self._unique_identifiers.append(
                    primitives.TextString(
                        value=v,
                        tag=enums.Tags.UNIQUE_IDENTIFIER
                    )
                )
        else:
            raise TypeError("Unique identifiers must be a list of strings.")

    def read(self, input_buffer, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the Locate response payload and decode it
        into its constituent parts.

        Args:
            input_buffer (stream): A data buffer containing encoded object
                data, supporting a read method.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.
        """
        super(LocateResponsePayload, self).read(
            input_buffer,
            kmip_version=kmip_version
        )
        local_buffer = utils.BytearrayStream(input_buffer.read(self.length))

        if self.is_tag_next(enums.Tags.LOCATED_ITEMS, local_buffer):
            self._located_items = primitives.Integer(
                tag=enums.Tags.LOCATED_ITEMS
            )
            self._located_items.read(
                local_buffer,
                kmip_version=kmip_version
            )

        self._unique_identifiers = []
        while self.is_tag_next(enums.Tags.UNIQUE_IDENTIFIER, local_buffer):
            unique_identifier = primitives.TextString(
                tag=enums.Tags.UNIQUE_IDENTIFIER
            )
            unique_identifier.read(local_buffer, kmip_version=kmip_version)
            self._unique_identifiers.append(unique_identifier)

        self.is_oversized(local_buffer)

    def write(self, output_buffer, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the Locate response payload to a buffer.

        Args:
            output_buffer (stream): A data buffer in which to encode object
                data, supporting a write method.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.
        """
        local_buffer = utils.BytearrayStream()

        if self._located_items:
            self._located_items.write(local_buffer, kmip_version=kmip_version)

        if self._unique_identifiers:
            for unique_identifier in self._unique_identifiers:
                unique_identifier.write(
                    local_buffer,
                    kmip_version=kmip_version
                )

        self.length = local_buffer.length()
        super(LocateResponsePayload, self).write(
            output_buffer,
            kmip_version=kmip_version
        )
        output_buffer.write(local_buffer.buffer)

    def __eq__(self, other):
        if isinstance(other, LocateResponsePayload):
            if self.located_items != other.located_items:
                return False
            elif self.unique_identifiers != other.unique_identifiers:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, LocateResponsePayload):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "located_items={}".format(self.located_items),
            "unique_identifiers={}".format(self.unique_identifiers)
        ])
        return "LocateResponsePayload({})".format(args)

    def __str__(self):
        value = ", ".join(
            [
                '"located_items": {}'.format(self.located_items),
                '"unique_identifiers": {}'.format(self.unique_identifiers),
            ]
        )
        return '{' + value + '}'
