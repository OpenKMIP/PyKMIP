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
from kmip.core import exceptions
from kmip.core import objects
from kmip.core import primitives
from kmip.core import utils
from kmip.core.messages.payloads import base

class CreateRequestPayload(base.RequestPayload):
    """
    A request payload for the Create operation.

    Attributes:
        object_type: The type of the object to create.
        template_attribute: A group of attributes to set on the new object.
        protection_storage_masks: A ProtectionStorageMasks structure
            containing the storage masks permissible for the new object.
            Added in KMIP 2.0.
    """

    def __init__(self,
                 object_type=None,
                 template_attribute=None,
                 protection_storage_masks=None):
        """
        Construct a Create request payload structure.

        Args:
            object_type (enum): An ObjectType enumeration specifying the type
                of object to create. Optional, defaults to None. Required for
                read/write.
            template_attribute (TemplateAttribute): A TemplateAttribute
                structure containing a set of attributes to set on the new
                object. Optional, defaults to None. Required for read/write.
            protection_storage_masks (structure): A ProtectionStorageMasks
                structure containing the storage masks permissible for the new
                object. Added in KMIP 2.0. Optional, defaults to None.
        """
        super(CreateRequestPayload, self).__init__()

        self._object_type = None
        self._template_attribute = None
        self._protection_storage_masks = None

        self.object_type = object_type
        self.template_attribute = template_attribute
        self.protection_storage_masks = protection_storage_masks

    @property
    def object_type(self):
        if self._object_type:
            return self._object_type.value
        else:
            return None

    @object_type.setter
    def object_type(self, value):
        if value is None:
            self._object_type = None
        elif isinstance(value, enums.ObjectType):
            self._object_type = primitives.Enumeration(
                enums.ObjectType,
                value=value,
                tag=enums.Tags.OBJECT_TYPE
            )
        else:
            raise TypeError(
                "Object type must be an ObjectType enumeration."
            )

    @property
    def template_attribute(self):
        return self._template_attribute

    @template_attribute.setter
    def template_attribute(self, value):
        if value is None:
            self._template_attribute = None
        elif isinstance(value, objects.TemplateAttribute):
            self._template_attribute = value
        else:
            raise TypeError(
                "Template attribute must be a TemplateAttribute structure."
            )

    @property
    def protection_storage_masks(self):
        return self._protection_storage_masks

    @protection_storage_masks.setter
    def protection_storage_masks(self, value):
        if value is None:
            self._protection_storage_masks = None
        elif isinstance(value, objects.ProtectionStorageMasks):
            if value.tag == enums.Tags.PROTECTION_STORAGE_MASKS:
                self._protection_storage_masks = value
            else:
                raise TypeError(
                    "The protection storage masks must be a "
                    "ProtectionStorageMasks structure with a "
                    "ProtectionStorageMasks tag."
                )
        else:
            raise TypeError(
                "The protection storage masks must be a "
                "ProtectionStorageMasks structure."
            )

    def read(self, input_buffer, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the Create request payload and decode it into
        its constituent parts.

        Args:
            input_buffer (stream): A data buffer containing encoded object
                data, supporting a read method.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            InvalidKmipEncoding: Raised if the object type or template
                attribute is missing from the encoded payload.
        """
        super(CreateRequestPayload, self).read(
            input_buffer,
            kmip_version=kmip_version
        )
        local_buffer = utils.BytearrayStream(input_buffer.read(self.length))

        if self.is_tag_next(enums.Tags.OBJECT_TYPE, local_buffer):
            self._object_type = primitives.Enumeration(
                enums.ObjectType,
                tag=enums.Tags.OBJECT_TYPE
            )
            self._object_type.read(local_buffer, kmip_version=kmip_version)
        else:
            raise exceptions.InvalidKmipEncoding(
                "The Create request payload encoding is missing the object "
                "type."
            )

        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            if self.is_tag_next(enums.Tags.TEMPLATE_ATTRIBUTE, local_buffer):
                self._template_attribute = objects.TemplateAttribute()
                self._template_attribute.read(
                    local_buffer,
                    kmip_version=kmip_version
                )
            else:
                raise exceptions.InvalidKmipEncoding(
                    "The Create request payload encoding is missing the "
                    "template attribute."
                )
        else:
            # NOTE (ph) For now, leave attributes natively in TemplateAttribute
            # form and just convert to the KMIP 2.0 Attributes form as needed
            # for encoding/decoding purposes. Changing the payload to require
            # the new Attributes structure will trigger a bunch of second-order
            # effects across the client and server codebases that is beyond
            # the scope of updating the Create payloads to support KMIP 2.0.
            if self.is_tag_next(enums.Tags.ATTRIBUTES, local_buffer):
                attributes = objects.Attributes()
                attributes.read(local_buffer, kmip_version=kmip_version)
                value = objects.convert_attributes_to_template_attribute(
                    attributes
                )
                self._template_attribute = value
            else:
                raise exceptions.InvalidKmipEncoding(
                    "The Create request payload encoding is missing the "
                    "attributes structure."
                )

        if kmip_version >= enums.KMIPVersion.KMIP_2_0:
            if self.is_tag_next(
                enums.Tags.PROTECTION_STORAGE_MASKS,
                local_buffer
            ):
                protection_storage_masks = objects.ProtectionStorageMasks(
                    tag=enums.Tags.PROTECTION_STORAGE_MASKS
                )
                protection_storage_masks.read(
                    local_buffer,
                    kmip_version=kmip_version
                )
                self._protection_storage_masks = protection_storage_masks

        self.is_oversized(local_buffer)

    def write(self, output_buffer, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the Create request payload to a buffer.

        Args:
            output_buffer (stream): A data buffer in which to encode object
                data, supporting a write method.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            InvalidField: Raised if the object type attribute or template
                attribute is not defined.
        """
        local_buffer = utils.BytearrayStream()

        if self._object_type:
            self._object_type.write(local_buffer, kmip_version=kmip_version)
        else:
            raise exceptions.InvalidField(
                "The Create request payload is missing the object type field."
            )

        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            if self._template_attribute:
                self._template_attribute.write(
                    local_buffer,
                    kmip_version=kmip_version
                )
            else:
                raise exceptions.InvalidField(
                    "The Create request payload is missing the template "
                    "attribute field."
                )
        else:
            # NOTE (ph) For now, leave attributes natively in TemplateAttribute
            # form and just convert to the KMIP 2.0 Attributes form as needed
            # for encoding/decoding purposes. Changing the payload to require
            # the new Attributes structure will trigger a bunch of second-order
            # effects across the client and server codebases that is beyond
            # the scope of updating the Create payloads to support KMIP 2.0.
            if self._template_attribute:
                attributes = objects.convert_template_attribute_to_attributes(
                    self._template_attribute
                )
                attributes.write(local_buffer, kmip_version=kmip_version)
            else:
                raise exceptions.InvalidField(
                    "The Create request payload is missing the template "
                    "attribute field."
                )

        if kmip_version >= enums.KMIPVersion.KMIP_2_0:
            if self._protection_storage_masks:
                self._protection_storage_masks.write(
                    local_buffer,
                    kmip_version=kmip_version
                )

        self.length = local_buffer.length()
        super(CreateRequestPayload, self).write(
            output_buffer,
            kmip_version=kmip_version
        )
        output_buffer.write(local_buffer.buffer)

    def __eq__(self, other):
        if isinstance(other, CreateRequestPayload):
            if self.object_type != other.object_type:
                return False
            elif self.template_attribute != other.template_attribute:
                return False
            elif self.protection_storage_masks != \
                    other.protection_storage_masks:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, CreateRequestPayload):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "object_type={}".format(self.object_type),
            "template_attribute={}".format(repr(self.template_attribute)),
            "protection_storage_masks={}".format(
                repr(self.protection_storage_masks)
            )
        ])
        return "CreateRequestPayload({})".format(args)

    def __str__(self):
        value = ", ".join(
            [
                '"object_type": {}'.format(self.object_type),
                '"template_attribute": {}'.format(self.template_attribute),
                '"protection_storage_masks": {}'.format(
                    str(self.protection_storage_masks)
                )
            ]
        )
        return '{' + value + '}'

class CreateResponsePayload(base.ResponsePayload):
    """
    A response payload for the Create operation.

    Attributes:
        object_type: The type of the object created.
        unique_identifier: The unique ID of the new object.
        template_attribute: A group of attributes that were set on the new
            object.
    """

    def __init__(self,
                 object_type=None,
                 unique_identifier=None,
                 template_attribute=None):
        """
        Construct a Create response payload structure.

        Args:
            object_type (enum): An ObjectType enumeration specifying the type
                of object created. Optional, defaults to None. Required for
                read/write.
            unique_identifier (string): The ID of the new object. Optional,
                defaults to None. Required for read/write.
            template_attribute (TemplateAttribute): A TemplateAttribute
                structure containing a set of attributes that were set on the
                new object. Optional, defaults to None.
        """
        super(CreateResponsePayload, self).__init__()

        self._object_type = None
        self._unique_identifier = None
        self._template_attribute = None

        self.object_type = object_type
        self.unique_identifier = unique_identifier
        self.template_attribute = template_attribute

    @property
    def object_type(self):
        if self._object_type:
            return self._object_type.value
        else:
            return None

    @object_type.setter
    def object_type(self, value):
        if value is None:
            self._object_type = None
        elif isinstance(value, enums.ObjectType):
            self._object_type = primitives.Enumeration(
                enums.ObjectType,
                value=value,
                tag=enums.Tags.OBJECT_TYPE
            )
        else:
            raise TypeError(
                "Object type must be an ObjectType enumeration."
            )

    @property
    def unique_identifier(self):
        if self._unique_identifier:
            return self._unique_identifier.value
        else:
            return None

    @unique_identifier.setter
    def unique_identifier(self, value):
        if value is None:
            self._unique_identifier = None
        elif isinstance(value, str):
            self._unique_identifier = primitives.TextString(
                value=value,
                tag=enums.Tags.UNIQUE_IDENTIFIER
            )
        else:
            raise TypeError("Unique identifier must be a string.")

    @property
    def template_attribute(self):
        return self._template_attribute

    @template_attribute.setter
    def template_attribute(self, value):
        if value is None:
            self._template_attribute = None
        elif isinstance(value, objects.TemplateAttribute):
            self._template_attribute = value
        else:
            raise TypeError(
                "Template attribute must be a TemplateAttribute structure."
            )

    def read(self, input_buffer, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the Create response payload and decode it into
        its constituent parts.

        Args:
            input_buffer (stream): A data buffer containing encoded object
                data, supporting a read method.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            InvalidKmipEncoding: Raised if the object type or unique
                identifier is missing from the encoded payload.
        """
        super(CreateResponsePayload, self).read(
            input_buffer,
            kmip_version=kmip_version
        )
        local_buffer = utils.BytearrayStream(input_buffer.read(self.length))

        if self.is_tag_next(enums.Tags.OBJECT_TYPE, local_buffer):
            self._object_type = primitives.Enumeration(
                enums.ObjectType,
                tag=enums.Tags.OBJECT_TYPE
            )
            self._object_type.read(local_buffer, kmip_version=kmip_version)
        else:
            raise exceptions.InvalidKmipEncoding(
                "The Create response payload encoding is missing the object "
                "type."
            )

        if self.is_tag_next(enums.Tags.UNIQUE_IDENTIFIER, local_buffer):
            self._unique_identifier = primitives.TextString(
                tag=enums.Tags.UNIQUE_IDENTIFIER
            )
            self._unique_identifier.read(
                local_buffer,
                kmip_version=kmip_version
            )
        else:
            raise exceptions.InvalidKmipEncoding(
                "The Create response payload encoding is missing the unique "
                "identifier."
            )

        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            if self.is_tag_next(enums.Tags.TEMPLATE_ATTRIBUTE, local_buffer):
                self._template_attribute = objects.TemplateAttribute()
                self._template_attribute.read(
                    local_buffer,
                    kmip_version=kmip_version
                )

        self.is_oversized(local_buffer)

    def write(self, output_buffer, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the Create response payload to a buffer.

        Args:
            output_buffer (stream): A data buffer in which to encode object
                data, supporting a write method.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            InvalidField: Raised if the object type attribute or unique
                identifier is not defined.
        """
        local_buffer = utils.BytearrayStream()

        if self._object_type:
            self._object_type.write(local_buffer, kmip_version=kmip_version)
        else:
            raise exceptions.InvalidField(
                "The Create response payload is missing the object type field."
            )

        if self._unique_identifier:
            self._unique_identifier.write(
                local_buffer,
                kmip_version=kmip_version
            )
        else:
            raise exceptions.InvalidField(
                "The Create response payload is missing the unique identifier "
                "field."
            )

        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            if self._template_attribute:
                self._template_attribute.write(
                    local_buffer,
                    kmip_version=kmip_version
                )

        self.length = local_buffer.length()
        super(CreateResponsePayload, self).write(
            output_buffer,
            kmip_version=kmip_version
        )
        output_buffer.write(local_buffer.buffer)

    def __eq__(self, other):
        if isinstance(other, CreateResponsePayload):
            if self.object_type != other.object_type:
                return False
            elif self.unique_identifier != other.unique_identifier:
                return False
            elif self.template_attribute != other.template_attribute:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, CreateResponsePayload):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "object_type={}".format(self.object_type),
            "unique_identifier='{}'".format(self.unique_identifier),
            "template_attribute={}".format(repr(self.template_attribute))
        ])
        return "CreateResponsePayload({})".format(args)

    def __str__(self):
        value = ", ".join(
            [
                '"object_type": {}'.format(self.object_type),
                '"unique_identifier": "{}"'.format(self.unique_identifier),
                '"template_attribute": {}'.format(self.template_attribute)
            ]
        )
        return '{' + value + '}'
