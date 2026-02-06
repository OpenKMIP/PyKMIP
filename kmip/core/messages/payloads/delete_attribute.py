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

from kmip.core import enums
from kmip.core import exceptions
from kmip.core import objects
from kmip.core import primitives
from kmip.core import utils
from kmip.core.messages.payloads import base

class DeleteAttributeRequestPayload(base.RequestPayload):
    """
    A request payload for the DeleteAttribute operation.

    Attributes:
        unique_identifier: The unique ID of the object on which attribute
            deletion should be performed.
        attribute_name: The name of the attribute to be deleted. Used in
            KMIP 1.0 - 1.4.
        attribute_index: The index of the attribute to be deleted. Used in
            KMIP 1.0 - 1.4.
        current_attribute: The attribute to be deleted. Used in KMIP 2.0+.
        attribute_reference: The reference to the attribute to be deleted.
            Used in KMIP 2.0+.
    """

    def __init__(self,
                 unique_identifier=None,
                 attribute_name=None,
                 attribute_index=None,
                 current_attribute=None,
                 attribute_reference=None):
        """
        Construct a DeleteAttribute request payload.

        Args:
            unique_identifier (string): The unique ID of the object on which
                attribute deletion should be performed. Optional, defaults to
                None.
            attribute_name (string): The name of the attribute to be deleted.
                Used in KMIP 1.0 - 1.4. Defaults to None. Required for
                read/write.
            attribute_index (int): The index of the attribute to be deleted.
                Used in KMIP 1.0 - 1.4. Optional, defaults to None.
            current_attribute (struct): A CurrentAttribute structure containing
                the attribute to be deleted. Used in KMIP 2.0+. Optional,
                defaults to None. Must be specified if the attribute reference
                is not provided.
            attribute_reference (struct): An AttributeReference structure
                containing a reference to the attribute to be deleted. Used in
                KMIP 2.0+. Optional, defaults to None. Must be specified if the
                current attribute is not specified.
        """
        super(DeleteAttributeRequestPayload, self).__init__()

        self._unique_identifier = None
        self._attribute_name = None
        self._attribute_index = None
        self._current_attribute = None
        self._attribute_reference = None

        self.unique_identifier = unique_identifier
        self.attribute_name = attribute_name
        self.attribute_index = attribute_index
        self.current_attribute = current_attribute
        self.attribute_reference = attribute_reference

    @property
    def unique_identifier(self):
        if self._unique_identifier:
            return self._unique_identifier.value
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
            raise TypeError("The unique identifier must be a string.")

    @property
    def attribute_name(self):
        if self._attribute_name:
            return self._attribute_name.value
        return None

    @attribute_name.setter
    def attribute_name(self, value):
        if value is None:
            self._attribute_name = None
        elif isinstance(value, str):
            self._attribute_name = primitives.TextString(
                value=value,
                tag=enums.Tags.ATTRIBUTE_NAME
            )
        else:
            raise TypeError("The attribute name must be a string.")

    @property
    def attribute_index(self):
        if self._attribute_index:
            return self._attribute_index.value
        return None

    @attribute_index.setter
    def attribute_index(self, value):
        if value is None:
            self._attribute_index = None
        elif isinstance(value, int):
            self._attribute_index = primitives.Integer(
                value=value,
                tag=enums.Tags.ATTRIBUTE_INDEX
            )
        else:
            raise TypeError("The attribute index must be an integer.")

    @property
    def current_attribute(self):
        if self._current_attribute:
            return self._current_attribute
        return None

    @current_attribute.setter
    def current_attribute(self, value):
        if value is None:
            self._current_attribute = None
        elif isinstance(value, objects.CurrentAttribute):
            self._current_attribute = value
        else:
            raise TypeError(
                "The current attribute must be a CurrentAttribute object."
            )

    @property
    def attribute_reference(self):
        if self._attribute_reference:
            return self._attribute_reference
        return None

    @attribute_reference.setter
    def attribute_reference(self, value):
        if value is None:
            self._attribute_reference = None
        elif isinstance(value, objects.AttributeReference):
            self._attribute_reference = value
        else:
            raise TypeError(
                "The attribute reference must be an AttributeReference object."
            )

    def read(self, input_buffer, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the DeleteAttribute request payload and decode
        it into its constituent part.

        Args:
            input_buffer (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            InvalidKmipEncoding: Raised if fields are missing from the
                encoding.
        """
        super(DeleteAttributeRequestPayload, self).read(
            input_buffer,
            kmip_version=kmip_version
        )
        local_buffer = utils.BytearrayStream(input_buffer.read(self.length))

        if self.is_tag_next(enums.Tags.UNIQUE_IDENTIFIER, local_buffer):
            self._unique_identifier = primitives.TextString(
                tag=enums.Tags.UNIQUE_IDENTIFIER
            )
            self._unique_identifier.read(
                local_buffer,
                kmip_version=kmip_version
            )
        else:
            self._unique_identifier = None

        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            if self.is_tag_next(enums.Tags.ATTRIBUTE_NAME, local_buffer):
                self._attribute_name = primitives.TextString(
                    tag=enums.Tags.ATTRIBUTE_NAME
                )
                self._attribute_name.read(
                    local_buffer,
                    kmip_version=kmip_version
                )
            else:
                raise exceptions.InvalidKmipEncoding(
                    "The DeleteAttribute request payload encoding is missing "
                    "the attribute name field."
                )

            if self.is_tag_next(enums.Tags.ATTRIBUTE_INDEX, local_buffer):
                self._attribute_index = primitives.Integer(
                    tag=enums.Tags.ATTRIBUTE_INDEX
                )
                self._attribute_index.read(
                    local_buffer,
                    kmip_version=kmip_version
                )
            else:
                self._attribute_index = None
        else:
            if self.is_tag_next(enums.Tags.CURRENT_ATTRIBUTE, local_buffer):
                self._current_attribute = objects.CurrentAttribute()
                self._current_attribute.read(
                    local_buffer,
                    kmip_version=kmip_version
                )
            else:
                self._current_attribute = None

            if self.is_tag_next(enums.Tags.ATTRIBUTE_REFERENCE, local_buffer):
                self._attribute_reference = objects.AttributeReference()
                self._attribute_reference.read(
                    local_buffer,
                    kmip_version=kmip_version
                )
            else:
                self._attribute_reference = None

            if self._current_attribute == self._attribute_reference:
                raise exceptions.InvalidKmipEncoding(
                    "The DeleteAttribute encoding is missing either the "
                    "current attribute or the attribute reference field."
                )

        self.is_oversized(local_buffer)

    def write(self, output_buffer, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the DeleteAttribute request payload to a
        stream.

        Args:
            output_buffer (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            InvalidField
        """
        local_buffer = utils.BytearrayStream()

        if self._unique_identifier:
            self._unique_identifier.write(
                local_buffer,
                kmip_version=kmip_version
            )

        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            if self._attribute_name:
                self._attribute_name.write(
                    local_buffer,
                    kmip_version=kmip_version
                )
            else:
                raise exceptions.InvalidField(
                    "The DeleteAttribute request payload is missing the "
                    "attribute name field."
                )

            if self._attribute_index:
                self._attribute_index.write(
                    local_buffer,
                    kmip_version=kmip_version
                )
        else:
            if self._current_attribute == self._attribute_reference:
                raise exceptions.InvalidField(
                    "The DeleteAttribute request payload is missing either "
                    "the current attribute or the attribute reference field."
                )

            if self._current_attribute:
                self._current_attribute.write(
                    local_buffer,
                    kmip_version=kmip_version
                )
            if self._attribute_reference:
                self._attribute_reference.write(
                    local_buffer,
                    kmip_version=kmip_version
                )

        self.length = local_buffer.length()
        super(DeleteAttributeRequestPayload, self).write(
            output_buffer,
            kmip_version=kmip_version
        )
        output_buffer.write(local_buffer.buffer)

    def __repr__(self):
        args = [
            "unique_identifier='{}'".format(self.unique_identifier),
            "attribute_name='{}'".format(self.attribute_name),
            "attribute_index={}".format(self.attribute_index),
            "current_attribute={}".format(repr(
                self.current_attribute
            ) if self.current_attribute else None),
            "attribute_reference={}".format(repr(
                self.attribute_reference
            ) if self.attribute_reference else None)
        ]
        return "DeleteAttributeRequestPayload({})".format(", ".join(args))

    def __str__(self):
        return str(
            {
                "unique_identifier": self.unique_identifier,
                "attribute_name": self.attribute_name,
                "attribute_index": self.attribute_index,
                "current_attribute": str(
                    self.current_attribute
                ) if self.current_attribute else None,
                "attribute_reference": str(
                    self.attribute_reference
                ) if self.attribute_reference else None
            }
        )

    def __eq__(self, other):
        if isinstance(other, DeleteAttributeRequestPayload):
            if self.unique_identifier != other.unique_identifier:
                return False
            elif self.attribute_name != other.attribute_name:
                return False
            elif self.attribute_index != other.attribute_index:
                return False
            elif self.current_attribute != other.current_attribute:
                return False
            elif self.attribute_reference != other.attribute_reference:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, DeleteAttributeRequestPayload):
            return not self.__eq__(other)
        else:
            return NotImplemented

class DeleteAttributeResponsePayload(base.ResponsePayload):
    """
    A response payload for the DeleteAttribute operation.

    Attributes:
        unique_identifier: The unique ID of the object on which attribute
            deletion was performed. Optional, defaults to None.
        attribute: The attribute object deleted from the managed object. Used
            in KMIP 1.0 - 1.4.
    """

    def __init__(self, unique_identifier=None, attribute=None):
        """
        Construct a DeleteAttribute response payload.

        Args:
            unique_identifier (string): The unique ID of the object on
                which attribute deletion was performed. Defaults to None.
                Required for read/write.
            attribute (struct): An Attribute object containing the attribute
                that was deleted. Used in KMIP 1.0 - 1.4. Defaults to None.
                Required for read/write.
        """
        super(DeleteAttributeResponsePayload, self).__init__()

        self._unique_identifier = None
        self._attribute = None

        self.unique_identifier = unique_identifier
        self.attribute = attribute

    @property
    def unique_identifier(self):
        if self._unique_identifier:
            return self._unique_identifier.value
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
            raise TypeError("The unique identifier must be a string.")

    @property
    def attribute(self):
        if self._attribute:
            return self._attribute
        return None

    @attribute.setter
    def attribute(self, value):
        if value is None:
            self._attribute = None
        elif isinstance(value, objects.Attribute):
            self._attribute = value
        else:
            raise TypeError(
                "The attribute must be an Attribute object."
            )

    def read(self, input_buffer, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the DeleteAttribute response payload and decode
        it into its constituent parts.

        Args:
            input_buffer (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (enum): A KMIPVersion enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            InvalidKmipEncoding: Raised if any required fields are missing
                from the encoding.
        """
        super(DeleteAttributeResponsePayload, self).read(
            input_buffer,
            kmip_version=kmip_version
        )
        local_buffer = utils.BytearrayStream(input_buffer.read(self.length))

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
                "The DeleteAttribute response payload encoding is missing the "
                "unique identifier field."
            )

        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            if self.is_tag_next(enums.Tags.ATTRIBUTE, local_buffer):
                self._attribute = objects.Attribute()
                self._attribute.read(local_buffer, kmip_version=kmip_version)
            else:
                raise exceptions.InvalidKmipEncoding(
                    "The DeleteAttribute response payload encoding is missing "
                    "the attribute field."
                )

        self.is_oversized(local_buffer)

    def write(self, output_buffer, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the DeleteAttribute response payload to a
        buffer.

        Args:
            output_buffer (buffer): A data buffer in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.
            kmip_version (enum): A KMIPVersion enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            InvalidField: Raised if a required field is missing from the
                payload object.
        """
        local_buffer = utils.BytearrayStream()

        if self._unique_identifier:
            self._unique_identifier.write(
                local_buffer,
                kmip_version=kmip_version
            )
        else:
            raise exceptions.InvalidField(
                "The DeleteAttribute response payload is missing the unique "
                "identifier field."
            )

        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            if self._attribute:
                self._attribute.write(
                    local_buffer,
                    kmip_version=kmip_version
                )
            else:
                raise exceptions.InvalidField(
                    "The DeleteAttribute response payload is missing the "
                    "attribute field."
                )

        self.length = local_buffer.length()
        super(DeleteAttributeResponsePayload, self).write(
            output_buffer,
            kmip_version=kmip_version
        )
        output_buffer.write(local_buffer.buffer)

    def __repr__(self):
        args = [
            "unique_identifier='{}'".format(self.unique_identifier),
            "attribute={}".format(repr(self.attribute))
        ]
        return "DeleteAttributeResponsePayload({})".format(", ".join(args))

    def __str__(self):
        return str(
            {
                "unique_identifier": self.unique_identifier,
                "attribute": str(self.attribute)
            }
        )

    def __eq__(self, other):
        if isinstance(other, DeleteAttributeResponsePayload):
            if self.unique_identifier != other.unique_identifier:
                return False
            elif self.attribute != other.attribute:
                return False
            else:
                return True
        return NotImplemented

    def __ne__(self, other):
        if isinstance(other, DeleteAttributeResponsePayload):
            return not self.__eq__(other)
        return NotImplemented
