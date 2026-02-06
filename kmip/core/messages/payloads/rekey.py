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

class RekeyRequestPayload(base.RequestPayload):
    """
    A request payload for the Rekey operation.

    Attributes:
        unique_identifier: The unique ID of the symmetric key to rekey.
        offset: The interval between the initialization and activation dates
            of the replacement key.
        template_attribute: A collection of attributes that should be set on
            the replacement key.
    """
    def __init__(self,
                 unique_identifier=None,
                 offset=None,
                 template_attribute=None):
        """
        Construct a Rekey request payload struct.

        Args:
            unique_identifier (string): The ID of the symmetric key to rekey.
                Optional, defaults to None.
            offset (int): The number of seconds between the initialization and
                activation dates of the replacement key. Optional, defaults to
                None.
            template_attribute (TemplateAttribute): A structure containing a
                set of attributes (e.g., cryptographic algorithm,
                cryptographic length) that should be set on the replacement
                key. Optional, defaults to None.
        """
        super(RekeyRequestPayload, self).__init__()

        self._unique_identifier = None
        self._offset = None
        self._template_attribute = None

        self.unique_identifier = unique_identifier
        self.offset = offset
        self.template_attribute = template_attribute

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
    def offset(self):
        if self._offset:
            return self._offset.value
        else:
            return None

    @offset.setter
    def offset(self, value):
        if value is None:
            self._offset = None
        elif isinstance(value, int):
            self._offset = primitives.Interval(
                value=value,
                tag=enums.Tags.OFFSET
            )
        else:
            raise TypeError("Offset must be an integer.")

    @property
    def template_attribute(self):
        if self._template_attribute:
            return self._template_attribute
        else:
            return None

    @template_attribute.setter
    def template_attribute(self, value):
        if value is None:
            self._template_attribute = None
        elif isinstance(value, objects.TemplateAttribute):
            self._template_attribute = value
        else:
            raise TypeError(
                "Template attribute must be a TemplateAttribute struct."
            )

    def read(self, input_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the Rekey request payload and decode it into
        its constituent parts.

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.
        """
        super(RekeyRequestPayload, self).read(
            input_stream,
            kmip_version=kmip_version
        )
        local_stream = utils.BytearrayStream(input_stream.read(self.length))

        if self.is_tag_next(enums.Tags.UNIQUE_IDENTIFIER, local_stream):
            self._unique_identifier = primitives.TextString(
                tag=enums.Tags.UNIQUE_IDENTIFIER
            )
            self._unique_identifier.read(
                local_stream,
                kmip_version=kmip_version
            )

        if self.is_tag_next(enums.Tags.OFFSET, local_stream):
            self._offset = primitives.Interval(
                tag=enums.Tags.OFFSET
            )
            self._offset.read(local_stream, kmip_version=kmip_version)

        if self.is_tag_next(enums.Tags.TEMPLATE_ATTRIBUTE, local_stream):
            self._template_attribute = objects.TemplateAttribute()
            self._template_attribute.read(
                local_stream,
                kmip_version=kmip_version
            )

        self.is_oversized(local_stream)

    def write(self, output_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the Rekey request payload to a stream.

        Args:
            output_stream (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.
        """
        local_stream = utils.BytearrayStream()

        if self._unique_identifier is not None:
            self._unique_identifier.write(
                local_stream,
                kmip_version=kmip_version
            )
        if self._offset is not None:
            self._offset.write(local_stream, kmip_version=kmip_version)
        if self._template_attribute is not None:
            self._template_attribute.write(
                local_stream,
                kmip_version=kmip_version
            )

        self.length = local_stream.length()
        super(RekeyRequestPayload, self).write(
            output_stream,
            kmip_version=kmip_version
        )
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, RekeyRequestPayload):
            if self.unique_identifier != other.unique_identifier:
                return False
            elif self.offset != other.offset:
                return False
            elif self.template_attribute != other.template_attribute:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, RekeyRequestPayload):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "unique_identifier='{0}'".format(self.unique_identifier),
            "offset={0}".format(self.offset),
            "template_attribute={0}".format(repr(self.template_attribute))
        ])
        return "RekeyRequestPayload({0})".format(args)

    def __str__(self):
        return str({
            'unique_identifier': self.unique_identifier,
            'offset': self.offset,
            'template_attribute': str(self.template_attribute)
        })

class RekeyResponsePayload(base.ResponsePayload):
    """
    A response payload for the Rekey operation.

    Attributes:
        unique_identifier: The unique ID of the replacement key.
        template_attribute: A collection of server attributes that were set on
            the replacement key.
    """
    def __init__(self,
                 unique_identifier=None,
                 template_attribute=None):
        """
        Construct a Rekey response payload struct.

        Args:
            unique_identifier (string): The ID of the replacement key.
                Optional, defaults to None. Required for read/write.
            template_attribute (TemplateAttribute): A structure containing a
                set of attributes (e.g., cryptographic algorithm,
                cryptographic length) that were set by the server on the
                replacement key. Optional, defaults to None.
        """
        super(RekeyResponsePayload, self).__init__()

        self._unique_identifier = None
        self._template_attribute = None

        self.unique_identifier = unique_identifier
        self.template_attribute = template_attribute

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
        if self._template_attribute:
            return self._template_attribute
        else:
            return None

    @template_attribute.setter
    def template_attribute(self, value):
        if value is None:
            self._template_attribute = None
        elif isinstance(value, objects.TemplateAttribute):
            self._template_attribute = value
        else:
            raise TypeError(
                "Template attribute must be a TemplateAttribute struct."
            )

    def read(self, input_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the Rekey response payload and decode it into
        its constituent parts.

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            ValueError: Raised if the unique identifier attribute is missing
                from the encoded payload.
        """
        super(RekeyResponsePayload, self).read(
            input_stream,
            kmip_version=kmip_version
        )
        local_stream = utils.BytearrayStream(input_stream.read(self.length))

        if self.is_tag_next(enums.Tags.UNIQUE_IDENTIFIER, local_stream):
            self._unique_identifier = primitives.TextString(
                tag=enums.Tags.UNIQUE_IDENTIFIER
            )
            self._unique_identifier.read(
                local_stream,
                kmip_version=kmip_version
            )
        else:
            raise ValueError(
                "The Rekey response payload encoding is missing the unique "
                "identifier."
            )

        if self.is_tag_next(enums.Tags.TEMPLATE_ATTRIBUTE, local_stream):
            self._template_attribute = objects.TemplateAttribute()
            self._template_attribute.read(
                local_stream,
                kmip_version=kmip_version
            )

        self.is_oversized(local_stream)

    def write(self, output_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the Rekey request payload to a stream.

        Args:
            output_stream (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            ValueError: Raised if the payload is missing the unique identifier.
        """
        local_stream = utils.BytearrayStream()

        if self._unique_identifier is not None:
            self._unique_identifier.write(
                local_stream,
                kmip_version=kmip_version
            )
        else:
            raise ValueError(
                "The Rekey response payload is missing the unique identifier."
            )
        if self._template_attribute is not None:
            self._template_attribute.write(
                local_stream,
                kmip_version=kmip_version
            )

        self.length = local_stream.length()
        super(RekeyResponsePayload, self).write(
            output_stream,
            kmip_version=kmip_version
        )
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, RekeyResponsePayload):
            if self.unique_identifier != other.unique_identifier:
                return False
            elif self.template_attribute != other.template_attribute:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, RekeyResponsePayload):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "unique_identifier='{0}'".format(self.unique_identifier),
            "template_attribute={0}".format(repr(self.template_attribute))
        ])
        return "RekeyResponsePayload({0})".format(args)

    def __str__(self):
        return str({
            'unique_identifier': self.unique_identifier,
            'template_attribute': str(self.template_attribute)
        })
