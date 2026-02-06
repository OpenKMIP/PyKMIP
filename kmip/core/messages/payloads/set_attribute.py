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

class SetAttributeRequestPayload(base.RequestPayload):
    """
    A request payload for the SetAttribute operation.

    Attributes:
        unique_identifier: The unique ID of the object on which attribute
            deletion should be performed.
        new_attribute: The attribute to set on the specified object.
    """

    def __init__(self,
                 unique_identifier=None,
                 new_attribute=None):
        """
        Construct a SetAttribute request payload.

        Args:
            unique_identifier (string): The unique ID of the object on which
                the attribute should be set. Optional, defaults to
                None.
            new_attribute (struct): A NewAttribute object containing the new
                attribute value to set on the specified object. Optional,
                defaults to None. Required for read/write.
        """
        super(SetAttributeRequestPayload, self).__init__()

        self._unique_identifier = None
        self._new_attribute = None

        self.unique_identifier = unique_identifier
        self.new_attribute = new_attribute

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
    def new_attribute(self):
        if self._new_attribute:
            return self._new_attribute
        return None

    @new_attribute.setter
    def new_attribute(self, value):
        if value is None:
            self._new_attribute = None
        elif isinstance(value, objects.NewAttribute):
            self._new_attribute = value
        else:
            raise TypeError(
                "The new attribute must be a NewAttribute object."
            )

    def read(self, input_buffer, kmip_version=enums.KMIPVersion.KMIP_2_0):
        """
        Read the data encoding the SetAttribute request payload and decode
        it into its constituent part.

        Args:
            input_buffer (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            VersionNotSupported: Raised when a KMIP version is provided that
                does not support the SetAttribute operation.
            InvalidKmipEncoding: Raised if fields are missing from the
                encoding.
        """
        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            raise exceptions.VersionNotSupported(
                "KMIP {} does not support the SetAttribute operation.".format(
                    kmip_version.value
                )
            )

        super(SetAttributeRequestPayload, self).read(
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

        if self.is_tag_next(enums.Tags.NEW_ATTRIBUTE, local_buffer):
            self._new_attribute = objects.NewAttribute()
            self._new_attribute.read(
                local_buffer,
                kmip_version=kmip_version
            )
        else:
            raise exceptions.InvalidKmipEncoding(
                "The SetAttribute request payload encoding is missing the new "
                "attribute field."
            )

        self.is_oversized(local_buffer)

    def write(self, output_buffer, kmip_version=enums.KMIPVersion.KMIP_2_0):
        """
        Write the data encoding the SetAttribute request payload to a
        stream.

        Args:
            output_buffer (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            VersionNotSupported: Raised when a KMIP version is provided that
                does not support the SetAttribute operation.
            InvalidField: Raised if a required field is missing from the
                payload object.
        """
        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            raise exceptions.VersionNotSupported(
                "KMIP {} does not support the SetAttribute operation.".format(
                    kmip_version.value
                )
            )

        local_buffer = utils.BytearrayStream()

        if self._unique_identifier:
            self._unique_identifier.write(
                local_buffer,
                kmip_version=kmip_version
            )

        if self._new_attribute:
            self._new_attribute.write(
                local_buffer,
                kmip_version=kmip_version
            )
        else:
            raise exceptions.InvalidField(
                "The SetAttribute request payload is missing the new "
                "attribute field."
            )

        self.length = local_buffer.length()
        super(SetAttributeRequestPayload, self).write(
            output_buffer,
            kmip_version=kmip_version
        )
        output_buffer.write(local_buffer.buffer)

    def __repr__(self):
        args = [
            "unique_identifier='{}'".format(self.unique_identifier),
            "new_attribute={}".format(
                repr(self.new_attribute) if self.new_attribute else None
            )
        ]
        return "SetAttributeRequestPayload({})".format(", ".join(args))

    def __str__(self):
        return str(
            {
                "unique_identifier": self.unique_identifier,
                "new_attribute": str(
                    self.new_attribute
                ) if self.new_attribute else None
            }
        )

    def __eq__(self, other):
        if isinstance(other, SetAttributeRequestPayload):
            if self.unique_identifier != other.unique_identifier:
                return False
            elif self.new_attribute != other.new_attribute:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, SetAttributeRequestPayload):
            return not self.__eq__(other)
        else:
            return NotImplemented

class SetAttributeResponsePayload(base.ResponsePayload):
    """
    A response payload for the SetAttribute operation.

    Attributes:
        unique_identifier: The unique ID of the object on which the attribute
            was set.
    """

    def __init__(self, unique_identifier=None):
        """
        Construct a SetAttribute response payload.

        Args:
            unique_identifier (string): The unique ID of the object on
                which the attribute was set. Defaults to None. Required for
                read/write.
        """
        super(SetAttributeResponsePayload, self).__init__()

        self._unique_identifier = None

        self.unique_identifier = unique_identifier

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

    def read(self, input_buffer, kmip_version=enums.KMIPVersion.KMIP_2_0):
        """
        Read the data encoding the SetAttribute response payload and decode
        it into its constituent parts.

        Args:
            input_buffer (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (enum): A KMIPVersion enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            VersionNotSupported: Raised when a KMIP version is provided that
                does not support the SetAttribute operation.
            InvalidKmipEncoding: Raised if any required fields are missing
                from the encoding.
        """
        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            raise exceptions.VersionNotSupported(
                "KMIP {} does not support the SetAttribute operation.".format(
                    kmip_version.value
                )
            )

        super(SetAttributeResponsePayload, self).read(
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
                "The SetAttribute response payload encoding is missing the "
                "unique identifier field."
            )

        self.is_oversized(local_buffer)

    def write(self, output_buffer, kmip_version=enums.KMIPVersion.KMIP_2_0):
        """
        Write the data encoding the SetAttribute response payload to a
        buffer.

        Args:
            output_buffer (buffer): A data buffer in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.
            kmip_version (enum): A KMIPVersion enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            VersionNotSupported: Raised when a KMIP version is provided that
                does not support the SetAttribute operation.
            InvalidField: Raised if a required field is missing from the
                payload object.
        """
        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            raise exceptions.VersionNotSupported(
                "KMIP {} does not support the SetAttribute operation.".format(
                    kmip_version.value
                )
            )

        local_buffer = utils.BytearrayStream()

        if self._unique_identifier:
            self._unique_identifier.write(
                local_buffer,
                kmip_version=kmip_version
            )
        else:
            raise exceptions.InvalidField(
                "The SetAttribute response payload is missing the unique "
                "identifier field."
            )

        self.length = local_buffer.length()
        super(SetAttributeResponsePayload, self).write(
            output_buffer,
            kmip_version=kmip_version
        )
        output_buffer.write(local_buffer.buffer)

    def __repr__(self):
        args = [
            "unique_identifier='{}'".format(self.unique_identifier)
        ]
        return "SetAttributeResponsePayload({})".format(", ".join(args))

    def __str__(self):
        return str(
            {
                "unique_identifier": self.unique_identifier
            }
        )

    def __eq__(self, other):
        if isinstance(other, SetAttributeResponsePayload):
            if self.unique_identifier != other.unique_identifier:
                return False
            else:
                return True
        return NotImplemented

    def __ne__(self, other):
        if isinstance(other, SetAttributeResponsePayload):
            return not self.__eq__(other)
        return NotImplemented
