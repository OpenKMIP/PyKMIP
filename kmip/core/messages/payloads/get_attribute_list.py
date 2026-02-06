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

from kmip.core import enums
from kmip.core import exceptions
from kmip.core import objects
from kmip.core import primitives
from kmip.core import utils
from kmip.core.messages.payloads import base

class GetAttributeListRequestPayload(base.RequestPayload):
    """
    A request payload for the GetAttributeList operation.

    The payload can contain the ID of the managed object the attributes should
    belong too. If omitted, the server will use the ID placeholder by default.
    See Section 4.13 of the KMIP 1.1 specification for more information.

    Attributes:
        unique_identifier: The unique ID of the managed object with which the
            retrieved attributes should be associated.
    """

    def __init__(self, unique_identifier=None):
        """
        Construct a GetAttributeList request payload.

        Args:
            unique_identifier (string): The ID of the managed object with
                which the retrieved attribute names should be associated.
                Optional, defaults to None.
        """
        super(GetAttributeListRequestPayload, self).__init__()

        self._unique_identifier = None

        self.unique_identifier = unique_identifier

    @property
    def unique_identifier(self):
        if self._unique_identifier:
            return self._unique_identifier.value
        else:
            return self._unique_identifier

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

    def read(self, input_buffer, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the GetAttributeList request payload and decode
        it into its constituent parts.

        Args:
            input_buffer (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.
        """
        super(GetAttributeListRequestPayload, self).read(
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

        self.is_oversized(local_buffer)

    def write(self, output_buffer, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the GetAttributeList request payload to a
        stream.

        Args:
            output_buffer (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.
        """
        local_buffer = utils.BytearrayStream()

        if self._unique_identifier:
            self._unique_identifier.write(
                local_buffer,
                kmip_version=kmip_version
            )

        self.length = local_buffer.length()
        super(GetAttributeListRequestPayload, self).write(
            output_buffer,
            kmip_version=kmip_version
        )
        output_buffer.write(local_buffer.buffer)

    def __repr__(self):
        uid = "unique_identifier={0}".format(self.unique_identifier)
        return "GetAttributeListRequestPayload({0})".format(uid)

    def __str__(self):
        return str({'unique_identifier': self.unique_identifier})

    def __eq__(self, other):
        if isinstance(other, GetAttributeListRequestPayload):
            if self.unique_identifier == other.unique_identifier:
                return True
            else:
                return False
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, GetAttributeListRequestPayload):
            return not self.__eq__(other)
        else:
            return NotImplemented

class GetAttributeListResponsePayload(base.ResponsePayload):
    """
    A response payload for the GetAttributeList operation.

    The payload contains the ID of the managed object with which the
    attributes are associated, along with a list of attribute names
    identifying the types of attributes associated with the aforementioned
    managed object.

    Attributes:
        unique_identifier: The unique ID of the managed object with which the
            retrieved attributes should be associated.
        attribute_names: A list of strings identifying the names of the
            attributes associated with the managed object.
    """

    def __init__(self, unique_identifier=None, attribute_names=None):
        """
        Construct a GetAttributeList response payload.

        Args:
            unique_identifier (string): The ID of the managed object with
                which the retrieved attribute names should be associated.
                Optional, defaults to None.
            attribute_names: A list of strings identifying the names of the
                attributes associated with the managed object. Optional,
                defaults to None.
        """

        super(GetAttributeListResponsePayload, self).__init__()

        self._unique_identifier = None
        self._attribute_names = list()

        self.unique_identifier = unique_identifier
        self.attribute_names = attribute_names

    @property
    def unique_identifier(self):
        if self._unique_identifier:
            return self._unique_identifier.value
        else:
            return self._unique_identifier

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
    def attribute_names(self):
        if self._attribute_names:
            names = list()
            for attribute_name in self._attribute_names:
                names.append(attribute_name.value)
            return names
        else:
            return self._attribute_names

    @attribute_names.setter
    def attribute_names(self, value):
        if value is None:
            self._attribute_names = list()
        elif isinstance(value, list):
            names = list()
            for i in range(len(value)):
                name = value[i]
                if not isinstance(name, str):
                    raise TypeError(
                        "Attribute names must be a list of strings; "
                        "item {0} has type {1}".format(i + 1, type(name))
                    )
                if name not in names:
                    names.append(name)
            self._attribute_names = list()
            for name in names:
                self._attribute_names.append(
                    primitives.TextString(
                        value=name,
                        tag=enums.Tags.ATTRIBUTE_NAME
                    )
                )
        else:
            raise TypeError("Attribute names must be a list of strings.")

    def read(self, input_buffer, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the GetAttributeList response payload and
        decode it into its constituent parts.

        Args:
            input_buffer (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            InvalidKmipEncoding: Raised if the unique identifier or attribute
                names are missing from the encoded payload.
        """
        super(GetAttributeListResponsePayload, self).read(
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
                "The GetAttributeList response payload encoding is missing "
                "the unique identifier."
            )

        names = list()
        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            while self.is_tag_next(enums.Tags.ATTRIBUTE_NAME, local_buffer):
                name = primitives.TextString(tag=enums.Tags.ATTRIBUTE_NAME)
                name.read(local_buffer, kmip_version=kmip_version)
                names.append(name)
            if len(names) == 0:
                raise exceptions.InvalidKmipEncoding(
                    "The GetAttributeList response payload encoding is "
                    "missing the attribute names."
                )
            self._attribute_names = names
        else:
            while self.is_tag_next(
                    enums.Tags.ATTRIBUTE_REFERENCE,
                    local_buffer
            ):
                if self.is_type_next(enums.Types.STRUCTURE, local_buffer):
                    reference = objects.AttributeReference()
                    reference.read(local_buffer, kmip_version=kmip_version)
                    names.append(
                        primitives.TextString(
                            value=reference.attribute_name,
                            tag=enums.Tags.ATTRIBUTE_NAME
                        )
                    )
                elif self.is_type_next(enums.Types.ENUMERATION, local_buffer):
                    reference = primitives.Enumeration(
                        enums.Tags,
                        tag=enums.Tags.ATTRIBUTE_REFERENCE
                    )
                    reference.read(local_buffer, kmip_version=kmip_version)
                    name = enums.convert_attribute_tag_to_name(reference.value)
                    names.append(
                        primitives.TextString(
                            value=name,
                            tag=enums.Tags.ATTRIBUTE_NAME
                        )
                    )
                else:
                    raise exceptions.InvalidKmipEncoding(
                        "The GetAttributeList response payload encoding "
                        "contains an invalid AttributeReference type."
                    )
            self._attribute_names = names

        self.is_oversized(local_buffer)

    def write(self, output_buffer, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the GetAttributeList response payload to a
        stream.

        Args:
            output_buffer (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            InvalidField: Raised if the unique identifier or attribute name
                are not defined.
        """
        local_buffer = utils.BytearrayStream()

        if self._unique_identifier:
            self._unique_identifier.write(
                local_buffer,
                kmip_version=kmip_version
            )
        else:
            raise exceptions.InvalidField(
                "The GetAttributeList response payload is missing the unique "
                "identifier field."
            )

        if self._attribute_names:
            if kmip_version < enums.KMIPVersion.KMIP_2_0:
                for attribute_name in self._attribute_names:
                    attribute_name.write(
                        local_buffer,
                        kmip_version=kmip_version
                    )
            else:
                # NOTE (ph) This approach simplifies backwards compatible
                #           issues but limits easy support for Attribute
                #           Reference structures going forward, specifically
                #           limiting the use of VendorIdentification for
                #           custom attributes. If custom attributes need to
                #           be retrieved using the GetAttributeList operation
                #           for KMIP 2.0 applications this code will need to
                #           change.
                for attribute_name in self._attribute_names:
                    t = enums.convert_attribute_name_to_tag(
                        attribute_name.value
                    )
                    e = primitives.Enumeration(
                        enums.Tags,
                        value=t,
                        tag=enums.Tags.ATTRIBUTE_REFERENCE
                    )
                    e.write(local_buffer, kmip_version=kmip_version)

        else:
            raise exceptions.InvalidField(
                "The GetAttributeList response payload is missing the "
                "attribute names field."
            )

        self.length = local_buffer.length()
        super(GetAttributeListResponsePayload, self).write(
            output_buffer,
            kmip_version=kmip_version
        )
        output_buffer.write(local_buffer.buffer)

    def __repr__(self):
        unique_identifier = "unique_identifier={0}".format(
            self.unique_identifier
        )
        attribute_names = "attribute_names={0}".format(self.attribute_names)
        return "GetAttributeListResponsePayload({0}, {1})".format(
            unique_identifier,
            attribute_names
        )

    def __str__(self):
        return str({
            'unique_identifier': self.unique_identifier,
            'attribute_names': self.attribute_names
        })

    def __eq__(self, other):
        if isinstance(other, GetAttributeListResponsePayload):
            if self.unique_identifier == other.unique_identifier:
                if set(self.attribute_names) == set(other.attribute_names):
                    return True
                else:
                    return False
            else:
                return False
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, GetAttributeListResponsePayload):
            return not self.__eq__(other)
        else:
            return NotImplemented
