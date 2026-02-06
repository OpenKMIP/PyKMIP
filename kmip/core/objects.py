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

import abc

import struct

from kmip.core import attributes
from kmip.core.attributes import CryptographicParameters

from kmip.core.factories.attribute_values import AttributeValueFactory

from kmip.core import enums
from kmip.core.enums import AttributeType
from kmip.core.enums import Tags
from kmip.core.enums import Types
from kmip.core import exceptions

from kmip.core.misc import KeyFormatType

from kmip.core import primitives
from kmip.core.primitives import Struct
from kmip.core.primitives import TextString
from kmip.core.primitives import ByteString
from kmip.core.primitives import Integer
from kmip.core.primitives import Enumeration

from kmip.core import utils
from kmip.core.utils import BytearrayStream

# 2.1
# 2.1.1
class Attribute(Struct):

    class AttributeName(TextString):

        def __init__(self, value=None):
            super(Attribute.AttributeName, self).__init__(
                value, Tags.ATTRIBUTE_NAME)

        def __eq__(self, other):
            if isinstance(other, Attribute.AttributeName):
                if self.value != other.value:
                    return False
                else:
                    return True
            else:
                NotImplemented

        def __ne__(self, other):
            if isinstance(other, Attribute.AttributeName):
                return not (self == other)
            else:
                return NotImplemented

    class AttributeIndex(Integer):

        def __init__(self, value=None):
            super(Attribute.AttributeIndex, self).__init__(
                value, Tags.ATTRIBUTE_INDEX)

    def __init__(self,
                 attribute_name=None,
                 attribute_index=None,
                 attribute_value=None):
        super(Attribute, self).__init__(tag=Tags.ATTRIBUTE)

        self.value_factory = AttributeValueFactory()

        self.attribute_name = attribute_name
        self.attribute_index = attribute_index
        self.attribute_value = attribute_value

        if attribute_value is not None:
            attribute_value.tag = Tags.ATTRIBUTE_VALUE

    def read(self, istream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        super(Attribute, self).read(istream, kmip_version=kmip_version)
        tstream = BytearrayStream(istream.read(self.length))

        # Read the name of the attribute
        self.attribute_name = Attribute.AttributeName()
        self.attribute_name.read(tstream, kmip_version=kmip_version)

        # Read the attribute index if it is next
        if self.is_tag_next(Tags.ATTRIBUTE_INDEX, tstream):
            self.attribute_index = Attribute.AttributeIndex()
            self.attribute_index.read(tstream, kmip_version=kmip_version)

        # Lookup the attribute class that belongs to the attribute name
        name = self.attribute_name.value
        enum_name = name.replace('.', '_').replace(' ', '_').upper()
        enum_type = None

        try:
            enum_type = AttributeType[enum_name]
        except KeyError:
            # Likely custom attribute, pass raw name string as attribute type
            enum_type = name

        value = self.value_factory.create_attribute_value(enum_type, None)
        if value is None:
            raise Exception("No value type for {}".format(enum_name))
        self.attribute_value = value
        self.attribute_value.tag = Tags.ATTRIBUTE_VALUE
        self.attribute_value.read(tstream, kmip_version=kmip_version)

        self.is_oversized(tstream)

    def write(self, ostream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        tstream = BytearrayStream()

        self.attribute_name.write(tstream, kmip_version=kmip_version)
        if self.attribute_index is not None:
            self.attribute_index.write(tstream, kmip_version=kmip_version)
        self.attribute_value.write(tstream, kmip_version=kmip_version)

        # Write the length and value of the attribute
        self.length = tstream.length()
        super(Attribute, self).write(ostream, kmip_version=kmip_version)
        ostream.write(tstream.buffer)

    def __repr__(self):
        attribute_name = "attribute_name={0}".format(repr(self.attribute_name))
        attribute_index = "attribute_index={0}".format(
            repr(self.attribute_index)
        )
        attribute_value = "attribute_value={0}".format(
            repr(self.attribute_value)
        )
        return "Attribute({0}, {1}, {2})".format(
            attribute_name,
            attribute_index,
            attribute_value
        )

    def __str__(self):
        return str({
            'attribute_name': str(self.attribute_name),
            'attribute_index': str(self.attribute_index),
            'attribute_value': str(self.attribute_value)
        })

    def __eq__(self, other):
        if isinstance(other, Attribute):
            if self.attribute_name != other.attribute_name:
                return False
            elif self.attribute_index != other.attribute_index:
                return False
            elif self.attribute_value != other.attribute_value:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, Attribute):
            return not self.__eq__(other)
        else:
            return NotImplemented

class CurrentAttribute(primitives.Struct):
    """
    A structure containing a single attribute.

    This is intended for use with KMIP 2.0+.

    Attributes:
        attribute: An attribute instance.
    """

    def __init__(self, attribute=None):
        """
        Construct a CurrentAttribute structure.

        Args:
            attribute (struct): An attribute structure of varying type.
                Defaults to None. Required for read/write.
        """
        super(CurrentAttribute, self).__init__(
            tag=enums.Tags.CURRENT_ATTRIBUTE
        )

        self._factory = AttributeValueFactory()

        self._attribute = None

        self.attribute = attribute

    @property
    def attribute(self):
        if self._attribute:
            return self._attribute
        return None

    @attribute.setter
    def attribute(self, value):
        if value is None:
            self._attribute = None
        elif isinstance(value, primitives.Base):
            if enums.is_attribute(value.tag):
                self._attribute = value
            else:
                raise TypeError(
                    "The attribute must be a supported attribute type."
                )
        else:
            raise TypeError(
                "The attribute must be a Base object, not a {}.".format(
                    type(value)
                )
            )

    def read(self, input_buffer, kmip_version=enums.KMIPVersion.KMIP_2_0):
        """
        Read the data stream and decode the CurrentAttribute structure into
        its parts.

        Args:
            input_buffer (stream): A data stream containing encoded object
                data, supporting a read method.
            kmip_version (enum): A KMIPVersion enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 2.0.

        Raises:
            AttributeNotSupported: Raised when an invalid value is decoded as
                the attribute from the encoding.
            InvalidKmipEncoding: Raised if the attribute is missing from the
                encoding.
            VersionNotSupported: Raised when a KMIP version is provided that
                does not support the CurrentAttribute structure.
        """
        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            raise exceptions.VersionNotSupported(
                "KMIP {} does not support the CurrentAttribute object.".format(
                    kmip_version.value
                )
            )

        super(CurrentAttribute, self).read(
            input_buffer,
            kmip_version=kmip_version
        )
        local_buffer = BytearrayStream(input_buffer.read(self.length))

        if len(local_buffer) < 3:
            raise exceptions.InvalidKmipEncoding(
                "The CurrentAttribute encoding is missing the attribute field."
            )
        tag = struct.unpack('!I', b'\x00' + local_buffer.peek(3))[0]
        if enums.is_enum_value(enums.Tags, tag):
            tag = enums.Tags(tag)
            if enums.is_attribute(tag, kmip_version=kmip_version):
                value = self._factory.create_attribute_value_by_enum(tag, None)
                value.read(local_buffer, kmip_version=kmip_version)
                self._attribute = value
            else:
                raise exceptions.AttributeNotSupported(
                    "Attribute {} is not supported by KMIP {}.".format(
                        tag.name,
                        kmip_version.value
                    )
                )
        else:
            raise exceptions.InvalidKmipEncoding(
                "The CurrentAttribute encoding is missing the attribute field."
            )

        self.is_oversized(local_buffer)

    def write(self, output_buffer, kmip_version=enums.KMIPVersion.KMIP_2_0):
        """
        Write the CurrentAttribute structure encoding to the data stream.

        Args:
            output_buffer (stream): A data stream in which to encode
                CurrentAttribute structure data, supporting a write method.
            kmip_version (enum): A KMIPVersion enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 2.0.

        Raises:
            AttributeNotSupported: Raised if an unsupported attribute is
                found while encoding.
            InvalidField: Raised when the attribute is unspecified at write
                time.
            VersionNotSupported: Raised when a KMIP version is provided that
                does not support the CurrentAttribute object.
        """
        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            raise exceptions.VersionNotSupported(
                "KMIP {} does not support the CurrentAttribute object.".format(
                    kmip_version.value
                )
            )

        local_buffer = BytearrayStream()

        if self._attribute:
            tag = self._attribute.tag
            if not enums.is_attribute(tag, kmip_version=kmip_version):
                raise exceptions.AttributeNotSupported(
                    "Attribute {} is not supported by KMIP {}.".format(
                        tag.name,
                        kmip_version.value
                    )
                )
            self._attribute.write(local_buffer, kmip_version=kmip_version)
        else:
            raise exceptions.InvalidField(
                "The CurrentAttribute object is missing the attribute field."
            )

        self.length = local_buffer.length()
        super(CurrentAttribute, self).write(
            output_buffer,
            kmip_version=kmip_version
        )
        output_buffer.write(local_buffer.buffer)

    def __repr__(self):
        return "CurrentAttribute(attribute={})".format(repr(self.attribute))

    def __str__(self):
        value = '"attribute": {}'.format(repr(self.attribute))
        return '{' + value + '}'

    def __eq__(self, other):
        if not isinstance(other, CurrentAttribute):
            return NotImplemented
        elif self.attribute != other.attribute:
            return False
        return True

    def __ne__(self, other):
        if isinstance(other, CurrentAttribute):
            return not (self == other)
        else:
            return NotImplemented

class NewAttribute(primitives.Struct):
    """
    A structure containing a single attribute.

    This is intended for use with KMIP 2.0+.

    Attributes:
        attribute: An attribute instance.
    """

    def __init__(self, attribute=None):
        """
        Construct a NewAttribute structure.

        Args:
            attribute (struct): An attribute structure of varying type.
                Defaults to None. Required for read/write.
        """
        super(NewAttribute, self).__init__(
            tag=enums.Tags.NEW_ATTRIBUTE
        )

        self._factory = AttributeValueFactory()

        self._attribute = None

        self.attribute = attribute

    @property
    def attribute(self):
        if self._attribute:
            return self._attribute
        return None

    @attribute.setter
    def attribute(self, value):
        if value is None:
            self._attribute = None
        elif isinstance(value, primitives.Base):
            if enums.is_attribute(value.tag):
                self._attribute = value
            else:
                raise TypeError(
                    "The attribute must be a supported attribute type."
                )
        else:
            raise TypeError(
                "The attribute must be a Base object, not a {}.".format(
                    type(value)
                )
            )

    def read(self, input_buffer, kmip_version=enums.KMIPVersion.KMIP_2_0):
        """
        Read the data stream and decode the NewAttribute structure into
        its parts.

        Args:
            input_buffer (stream): A data stream containing encoded object
                data, supporting a read method.
            kmip_version (enum): A KMIPVersion enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 2.0.

        Raises:
            AttributeNotSupported: Raised when an invalid value is decoded as
                the attribute from the encoding.
            InvalidKmipEncoding: Raised if the attribute is missing from the
                encoding.
            VersionNotSupported: Raised when a KMIP version is provided that
                does not support the CurrentAttribute structure.
        """
        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            raise exceptions.VersionNotSupported(
                "KMIP {} does not support the NewAttribute object.".format(
                    kmip_version.value
                )
            )

        super(NewAttribute, self).read(
            input_buffer,
            kmip_version=kmip_version
        )
        local_buffer = BytearrayStream(input_buffer.read(self.length))

        if len(local_buffer) < 3:
            raise exceptions.InvalidKmipEncoding(
                "The NewAttribute encoding is missing the attribute field."
            )
        tag = struct.unpack('!I', b'\x00' + local_buffer.peek(3))[0]
        if enums.is_enum_value(enums.Tags, tag):
            tag = enums.Tags(tag)
            if enums.is_attribute(tag, kmip_version=kmip_version):
                value = self._factory.create_attribute_value_by_enum(tag, None)
                value.read(local_buffer, kmip_version=kmip_version)
                self._attribute = value
            else:
                raise exceptions.AttributeNotSupported(
                    "Attribute {} is not supported by KMIP {}.".format(
                        tag.name,
                        kmip_version.value
                    )
                )
        else:
            raise exceptions.InvalidKmipEncoding(
                "The NewAttribute encoding is missing the attribute field."
            )

        self.is_oversized(local_buffer)

    def write(self, output_buffer, kmip_version=enums.KMIPVersion.KMIP_2_0):
        """
        Write the NewAttribute structure encoding to the data stream.

        Args:
            output_buffer (stream): A data stream in which to encode
                NewAttribute structure data, supporting a write method.
            kmip_version (enum): A KMIPVersion enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 2.0.

        Raises:
            AttributeNotSupported: Raised if an unsupported attribute is
                found while encoding.
            InvalidField: Raised when the attribute is unspecified at write
                time.
            VersionNotSupported: Raised when a KMIP version is provided that
                does not support the NewAttribute object.
        """
        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            raise exceptions.VersionNotSupported(
                "KMIP {} does not support the NewAttribute object.".format(
                    kmip_version.value
                )
            )

        local_buffer = BytearrayStream()

        if self._attribute:
            tag = self._attribute.tag
            if not enums.is_attribute(tag, kmip_version=kmip_version):
                raise exceptions.AttributeNotSupported(
                    "Attribute {} is not supported by KMIP {}.".format(
                        tag.name,
                        kmip_version.value
                    )
                )
            self._attribute.write(local_buffer, kmip_version=kmip_version)
        else:
            raise exceptions.InvalidField(
                "The NewAttribute object is missing the attribute field."
            )

        self.length = local_buffer.length()
        super(NewAttribute, self).write(
            output_buffer,
            kmip_version=kmip_version
        )
        output_buffer.write(local_buffer.buffer)

    def __repr__(self):
        return "NewAttribute(attribute={})".format(repr(self.attribute))

    def __str__(self):
        value = '"attribute": {}'.format(repr(self.attribute))
        return '{' + value + '}'

    def __eq__(self, other):
        if not isinstance(other, NewAttribute):
            return NotImplemented
        elif self.attribute != other.attribute:
            return False
        return True

    def __ne__(self, other):
        if isinstance(other, NewAttribute):
            return not (self == other)
        else:
            return NotImplemented

class AttributeReference(primitives.Struct):
    """
    A structure containing reference information for an attribute.

    This is intended for use with KMIP 2.0+.

    Attributes:
        vendor_identification: A string identifying the vendor associated
            with the attribute.
        attribute_name: A string containing the attribute name.
    """

    def __init__(self, vendor_identification=None, attribute_name=None):
        """
        Construct an AttributeReference structure.

        Args:
            vendor_identification (string): A string identifying the vendor
                associated with the attribute. Optional, defaults to None.
                Required for read/write.
            attribute_name (string): A string containing the attribute name.
                Optional, defaults to None. Required for read/write.
        """
        super(AttributeReference, self).__init__(
            tag=enums.Tags.ATTRIBUTE_REFERENCE
        )

        self._vendor_identification = None
        self._attribute_name = None

        self.vendor_identification = vendor_identification
        self.attribute_name = attribute_name

    @property
    def vendor_identification(self):
        if self._vendor_identification:
            return self._vendor_identification.value
        else:
            return None

    @vendor_identification.setter
    def vendor_identification(self, value):
        if value is None:
            self._vendor_identification = None
        elif isinstance(value, str):
            self._vendor_identification = primitives.TextString(
                value,
                tag=enums.Tags.VENDOR_IDENTIFICATION
            )
        else:
            raise TypeError("Vendor identification must be a string.")

    @property
    def attribute_name(self):
        if self._attribute_name:
            return self._attribute_name.value
        else:
            return None

    @attribute_name.setter
    def attribute_name(self, value):
        if value is None:
            self._attribute_name = None
        elif isinstance(value, str):
            self._attribute_name = primitives.TextString(
                value,
                tag=enums.Tags.ATTRIBUTE_NAME
            )
        else:
            raise TypeError("Attribute name must be a string.")

    def read(self, input_buffer, kmip_version=enums.KMIPVersion.KMIP_2_0):
        """
        Read the data stream and decode the AttributeReference structure into
        its parts.

        Args:
            input_buffer (stream): A data stream containing encoded object
                data, supporting a read method.
            kmip_version (enum): A KMIPVersion enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 2.0.

        Raises:
            InvalidKmipEncoding: Raised if the vendor identification or
                attribute name is missing from the encoding.
            VersionNotSupported: Raised when a KMIP version is provided that
                does not support the AttributeReference structure.
        """
        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            raise exceptions.VersionNotSupported(
                "KMIP {} does not support the AttributeReference "
                "object.".format(
                    kmip_version.value
                )
            )

        super(AttributeReference, self).read(
            input_buffer,
            kmip_version=kmip_version
        )
        local_buffer = BytearrayStream(input_buffer.read(self.length))

        if self.is_tag_next(enums.Tags.VENDOR_IDENTIFICATION, local_buffer):
            self._vendor_identification = primitives.TextString(
                tag=enums.Tags.VENDOR_IDENTIFICATION
            )
            self._vendor_identification.read(
                local_buffer,
                kmip_version=kmip_version
            )
        else:
            raise exceptions.InvalidKmipEncoding(
                "The AttributeReference encoding is missing the vendor "
                "identification string."
            )

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
                "The AttributeReference encoding is missing the attribute "
                "name string."
            )

        self.is_oversized(local_buffer)

    def write(self, output_buffer, kmip_version=enums.KMIPVersion.KMIP_2_0):
        """
        Write the AttributeReference structure encoding to the data stream.

        Args:
            output_buffer (stream): A data stream in which to encode
                Attributes structure data, supporting a write method.
            kmip_version (enum): A KMIPVersion enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 2.0.

        Raises:
            InvalidField: Raised if the vendor identification or attribute name
                fields are not defined.
            VersionNotSupported: Raised when a KMIP version is provided that
                does not support the AttributeReference structure.
        """
        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            raise exceptions.VersionNotSupported(
                "KMIP {} does not support the AttributeReference "
                "object.".format(
                    kmip_version.value
                )
            )

        local_buffer = BytearrayStream()

        if self._vendor_identification:
            self._vendor_identification.write(
                local_buffer,
                kmip_version=kmip_version
            )
        else:
            raise exceptions.InvalidField(
                "The AttributeReference is missing the vendor identification "
                "field."
            )

        if self._attribute_name:
            self._attribute_name.write(
                local_buffer,
                kmip_version=kmip_version
            )
        else:
            raise exceptions.InvalidField(
                "The AttributeReference is missing the attribute name field."
            )

        self.length = local_buffer.length()
        super(AttributeReference, self).write(
            output_buffer,
            kmip_version=kmip_version
        )
        output_buffer.write(local_buffer.buffer)

    def __repr__(self):
        v = "vendor_identification={}".format(
            '"{}"'.format(
                self.vendor_identification
            ) if self.vendor_identification else None
        )
        a = "attribute_name={}".format(
            '"{}"'.format(self.attribute_name) if self.attribute_name else None
        )
        values = ", ".join([v, a])
        return "AttributeReference({})".format(values)

    def __str__(self):
        v = '"vendor_identification": "{}"'.format(
            "{}".format(
                self.vendor_identification
            ) if self.vendor_identification else None
        )
        a = '"attribute_name": "{}"'.format(
            "{}".format(self.attribute_name) if self.attribute_name else None
        )
        values = ", ".join([v, a])
        return '{' + values + '}'

    def __eq__(self, other):
        if isinstance(other, AttributeReference):
            if self.vendor_identification != other.vendor_identification:
                return False
            elif self.attribute_name != other.attribute_name:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, AttributeReference):
            return not (self == other)
        else:
            return NotImplemented

class Attributes(primitives.Struct):
    """
    A collection of KMIP attributes.

    This is intended for use with KMIP 2.0+ and replaces the old
    TemplateAttribute-style used for older KMIP versions.

    Attributes:
        attributes: A list of attribute objects.
        tag: A Tags enumeration specifying what type of Attributes structure
            is in use. Valid values include:
                * Tags.ATTRIBUTES
                * Tags.COMMON_ATTRIBUTES
                * Tags.PRIVATE_KEY_ATTRIBUTES
                * Tags.PUBLIC_KEY_ATTRIBUTES
    """

    def __init__(self, attributes=None, tag=enums.Tags.ATTRIBUTES):
        """
        Construct an Attributes structure.

        Args:
            attributes (list): A list of attribute objects. Each object must
                be some form of primitive, derived from Base. Optional,
                defaults to None which is interpreted as an empty list.
            tag (enum): A Tags enumeration specifying what type of Attributes
                structure is in use. Valid values include:
                    * Tags.ATTRIBUTES
                    * Tags.COMMON_ATTRIBUTES
                    * Tags.PRIVATE_KEY_ATTRIBUTES
                    * Tags.PUBLIC_KEY_ATTRIBUTES
                Optional, defaults to Tags.ATTRIBUTES.
        """
        super(Attributes, self).__init__(tag=tag)

        self._factory = AttributeValueFactory()

        self._attributes = []
        self.attributes = attributes

    @property
    def attributes(self):
        return self._attributes

    @attributes.setter
    def attributes(self, value):
        if (value is None) or (value == []):
            self._attributes = []
        elif isinstance(value, list):
            for i, attribute in enumerate(value):
                if isinstance(attribute, primitives.Base):
                    if not enums.is_attribute(attribute.tag):
                        raise TypeError(
                            "Item {} must be a supported attribute.".format(
                                i + 1
                            )
                        )
                else:
                    raise TypeError(
                        "Item {} must be a Base object, not a {}.".format(
                            i + 1,
                            type(attribute)
                        )
                    )
            self._attributes = value
        else:
            raise TypeError("Attributes must be a list of Base objects.")

    def read(self, input_stream, kmip_version=enums.KMIPVersion.KMIP_2_0):
        """
        Read the data stream and decode the Attributes structure into its
        parts.

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method.
            kmip_version (enum): A KMIPVersion enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 2.0.

        Raises:
            AttributeNotSupported: Raised if an unsupported attribute is
                encountered while decoding.
            VersionNotSupported: Raised when a KMIP version is provided that
                does not support the Attributes object.
        """
        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            raise exceptions.VersionNotSupported(
                "KMIP {} does not support the Attributes object.".format(
                    kmip_version.value
                )
            )

        super(Attributes, self).read(input_stream, kmip_version=kmip_version)
        local_stream = BytearrayStream(input_stream.read(self.length))

        while True:
            if len(local_stream) < 3:
                break
            tag = struct.unpack('!I', b'\x00' + local_stream.peek(3))[0]
            if enums.is_enum_value(enums.Tags, tag):
                tag = enums.Tags(tag)
                if not enums.is_attribute(tag, kmip_version=kmip_version):
                    raise exceptions.AttributeNotSupported(
                        "Attribute {} is not supported by KMIP {}.".format(
                            tag.name,
                            kmip_version.value
                        )
                    )
                value = self._factory.create_attribute_value_by_enum(tag, None)
                value.read(local_stream, kmip_version=kmip_version)
                self._attributes.append(value)
            else:
                break

        self.is_oversized(local_stream)

    def write(self, output_stream, kmip_version=enums.KMIPVersion.KMIP_2_0):
        """
        Write the Attributes structure encoding to the data stream.

        Args:
            output_stream (stream): A data stream in which to encode
                Attributes structure data, supporting a write method.
            kmip_version (enum): A KMIPVersion enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 2.0.

        Raises:
            AttributeNotSupported: Raised if an unsupported attribute is
                found in the attribute list while encoding.
            VersionNotSupported: Raised when a KMIP version is provided that
                does not support the Attributes object.
        """
        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            raise exceptions.VersionNotSupported(
                "KMIP {} does not support the Attributes object.".format(
                    kmip_version.value
                )
            )

        local_stream = BytearrayStream()

        for attribute in self._attributes:
            tag = attribute.tag
            if not enums.is_attribute(tag, kmip_version=kmip_version):
                raise exceptions.AttributeNotSupported(
                    "Attribute {} is not supported by KMIP {}.".format(
                        tag.name,
                        kmip_version.value
                    )
                )
            attribute.write(local_stream, kmip_version=kmip_version)

        self.length = local_stream.length()
        super(Attributes, self).write(output_stream, kmip_version=kmip_version)
        output_stream.write(local_stream.buffer)

    def __repr__(self):
        values = ", ".join([repr(x) for x in self.attributes])
        return "Attributes(attributes=[{}], tag={})".format(
            values,
            self.tag
        )

    def __str__(self):
        values = ", ".join([str(x) for x in self.attributes])
        value = '"attributes": [{}]'.format(values)
        return '{' + value + '}'

    def __eq__(self, other):
        if not isinstance(other, Attributes):
            return NotImplemented

        if len(self.attributes) != len(other.attributes):
            return False

        # TODO (ph) Allow order independence?

        for i in range(len(self.attributes)):
            a = self.attributes[i]
            b = other.attributes[i]

            if a != b:
                return False

        return True

    def __ne__(self, other):
        if isinstance(other, Attributes):
            return not (self == other)
        else:
            return NotImplemented

class Nonce(primitives.Struct):
    """
    A struct representing a Nonce object.

    Attributes:
        nonce_id (bytes): A binary string representing the ID of the nonce
            value.
        nonce_value (bytes): A binary string representing a random value.
    """

    def __init__(self, nonce_id=None, nonce_value=None):
        """
        Construct a Nonce struct.

        Args:
            nonce_id (bytes): A binary string representing the ID of the nonce
                value. Optional, defaults to None. Required for encoding and
                decoding.
            nonce_value (bytes): A binary string representing a random value.
                Optional, defaults to None. Required for encoding and decoding.
        """
        super(Nonce, self).__init__(tag=enums.Tags.NONCE)

        self._nonce_id = None
        self._nonce_value = None

        self.nonce_id = nonce_id
        self.nonce_value = nonce_value

    @property
    def nonce_id(self):
        if self._nonce_id:
            return self._nonce_id.value
        else:
            return None

    @nonce_id.setter
    def nonce_id(self, value):
        if value is None:
            self._nonce_id = None
        elif isinstance(value, bytes):
            self._nonce_id = primitives.ByteString(
                value=value,
                tag=enums.Tags.NONCE_ID
            )
        else:
            raise TypeError("Nonce ID must be bytes.")

    @property
    def nonce_value(self):
        if self._nonce_value:
            return self._nonce_value.value
        else:
            return None

    @nonce_value.setter
    def nonce_value(self, value):
        if value is None:
            self._nonce_value = None
        elif isinstance(value, bytes):
            self._nonce_value = primitives.ByteString(
                value=value,
                tag=enums.Tags.NONCE_VALUE
            )
        else:
            raise TypeError("Nonce value must be bytes.")

    def read(self, input_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the Nonce struct and decode it into its
        constituent parts.

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            ValueError: Raised if the nonce ID or nonce value is missing from
                the encoding.
        """
        super(Nonce, self).read(input_stream, kmip_version=kmip_version)
        local_stream = BytearrayStream(input_stream.read(self.length))

        if self.is_tag_next(enums.Tags.NONCE_ID, local_stream):
            self._nonce_id = primitives.ByteString(
                tag=enums.Tags.NONCE_ID
            )
            self._nonce_id.read(local_stream, kmip_version=kmip_version)
        else:
            raise ValueError(
                "Nonce encoding missing the nonce ID."
            )

        if self.is_tag_next(enums.Tags.NONCE_VALUE, local_stream):
            self._nonce_value = primitives.ByteString(
                tag=enums.Tags.NONCE_VALUE
            )
            self._nonce_value.read(local_stream, kmip_version=kmip_version)
        else:
            raise ValueError(
                "Nonce encoding missing the nonce value."
            )

        self.is_oversized(local_stream)

    def write(self, output_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the Nonce struct to a stream.

        Args:
            output_stream (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            ValueError: Raised if the nonce ID or nonce value is not defined.
        """
        local_stream = BytearrayStream()

        if self._nonce_id:
            self._nonce_id.write(local_stream, kmip_version=kmip_version)
        else:
            raise ValueError("Nonce struct is missing the nonce ID.")

        if self._nonce_value:
            self._nonce_value.write(local_stream, kmip_version=kmip_version)
        else:
            raise ValueError("Nonce struct is missing the nonce value.")

        self.length = local_stream.length()
        super(Nonce, self).write(output_stream, kmip_version=kmip_version)
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, Nonce):
            if self.nonce_id != other.nonce_id:
                return False
            elif self.nonce_value != other.nonce_value:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, Nonce):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "nonce_id={}".format(self.nonce_id),
            "nonce_value={}".format(self.nonce_value)
        ])
        return "Nonce({})".format(args)

    def __str__(self):
        body = ", ".join([
            "'nonce_id': {}".format(self.nonce_id),
            "'nonce_value': {}".format(self.nonce_value)
        ])
        return "{" + body + "}"

class CredentialValue(primitives.Struct, metaclass=abc.ABCMeta):
    """
    An empty, abstract base class to be used by Credential objects to easily
    group and type-check credential values.
    """

class UsernamePasswordCredential(CredentialValue):
    """
    A struct representing a UsernamePasswordCredential object.

    Attributes:
        username: The username identifying the credential.
        password: The password associated with the username.
    """

    def __init__(self, username=None, password=None):
        """
        Construct a UsernamePasswordCredential struct.

        Args:
            username (string): The username identifying the credential.
                Optional, defaults to None. Required for encoding and decoding.
            password (string): The password associated with the username.
                Optional, defaults to None.
        """
        super(UsernamePasswordCredential, self).__init__(
            tag=Tags.CREDENTIAL_VALUE
        )

        self._username = None
        self._password = None

        self.username = username
        self.password = password

    @property
    def username(self):
        if self._username:
            return self._username.value
        else:
            return None

    @username.setter
    def username(self, value):
        if value is None:
            self._username = None
        elif isinstance(value, str):
            self._username = primitives.TextString(
                value=value,
                tag=enums.Tags.USERNAME
            )
        else:
            raise TypeError("Username must be a string.")

    @property
    def password(self):
        if self._password:
            return self._password.value
        else:
            return None

    @password.setter
    def password(self, value):
        if value is None:
            self._password = None
        elif isinstance(value, str):
            self._password = primitives.TextString(
                value=value,
                tag=enums.Tags.PASSWORD
            )
        else:
            raise TypeError("Password must be a string.")

    def read(self, input_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the UsernamePasswordCredential struct and
        decode it into its constituent parts.

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            ValueError: Raised if the username is missing from the encoding.
        """
        super(UsernamePasswordCredential, self).read(
            input_stream,
            kmip_version=kmip_version
        )
        local_stream = BytearrayStream(input_stream.read(self.length))

        if self.is_tag_next(enums.Tags.USERNAME, local_stream):
            self._username = primitives.TextString(
                tag=enums.Tags.USERNAME
            )
            self._username.read(local_stream, kmip_version=kmip_version)
        else:
            raise ValueError(
                "Username/password credential encoding missing the username."
            )

        if self.is_tag_next(enums.Tags.PASSWORD, local_stream):
            self._password = primitives.TextString(
                tag=enums.Tags.PASSWORD
            )
            self._password.read(local_stream, kmip_version=kmip_version)

        self.is_oversized(local_stream)

    def write(self, output_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the UsernamePasswordCredential struct to a
        stream.

        Args:
            output_stream (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            ValueError: Raised if the username is not defined.
        """
        local_stream = BytearrayStream()

        if self._username:
            self._username.write(local_stream, kmip_version=kmip_version)
        else:
            raise ValueError(
                "Username/password credential struct missing the username."
            )

        if self._password:
            self._password.write(local_stream, kmip_version=kmip_version)

        self.length = local_stream.length()
        super(UsernamePasswordCredential, self).write(
            output_stream,
            kmip_version=kmip_version
        )
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, UsernamePasswordCredential):
            if self.username != other.username:
                return False
            elif self.password != other.password:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, UsernamePasswordCredential):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "username='{}'".format(self.username),
            "password='{}'".format(self.password)
        ])
        return "UsernamePasswordCredential({})".format(args)

    def __str__(self):
        return str({
            "username": self.username,
            "password": self.password
        })

class DeviceCredential(CredentialValue):
    """
    A struct representing a DeviceCredential object.

    Attributes:
        device_serial_number: The device serial number for the credential.
        password: The password associated with the credential.
        device_identifier: The device identifier for the credential.
        network_identifier: The network identifier for the credential.
        machine_identifier: The machine identifier for the credential.
        media_identifier: The media identifier for the credential.
    """

    def __init__(self,
                 device_serial_number=None,
                 password=None,
                 device_identifier=None,
                 network_identifier=None,
                 machine_identifier=None,
                 media_identifier=None):
        """
        Construct a DeviceCredential struct.

        Args:
            device_serial_number (string): The device serial number for the
                credential. Optional, defaults to None.
            password (string): The password associated with the credential.
                Optional, defaults to None.
            device_identifier (string): The device identifier for the
                credential. Optional, defaults to None.
            network_identifier (string): The network identifier for the
                credential. Optional, defaults to None.
            machine_identifier (string): The machine identifier for the
                credential. Optional, defaults to None.
            media_identifier (string): The media identifier for the
                credential. Optional, defaults to None.
        """
        super(DeviceCredential, self).__init__(tag=Tags.CREDENTIAL_VALUE)

        self._device_serial_number = None
        self._password = None
        self._device_identifier = None
        self._network_identifier = None
        self._machine_identifier = None
        self._media_identifier = None

        self.device_serial_number = device_serial_number
        self.password = password
        self.device_identifier = device_identifier
        self.network_identifier = network_identifier
        self.machine_identifier = machine_identifier
        self.media_identifier = media_identifier

    @property
    def device_serial_number(self):
        if self._device_serial_number:
            return self._device_serial_number.value
        else:
            return None

    @device_serial_number.setter
    def device_serial_number(self, value):
        if value is None:
            self._device_serial_number = None
        elif isinstance(value, str):
            self._device_serial_number = primitives.TextString(
                value=value,
                tag=enums.Tags.DEVICE_SERIAL_NUMBER
            )
        else:
            raise TypeError("Device serial number must be a string.")

    @property
    def password(self):
        if self._password:
            return self._password.value
        else:
            return None

    @password.setter
    def password(self, value):
        if value is None:
            self._password = None
        elif isinstance(value, str):
            self._password = primitives.TextString(
                value=value,
                tag=enums.Tags.PASSWORD
            )
        else:
            raise TypeError("Password must be a string.")

    @property
    def device_identifier(self):
        if self._device_identifier:
            return self._device_identifier.value
        else:
            return None

    @device_identifier.setter
    def device_identifier(self, value):
        if value is None:
            self._device_identifier = None
        elif isinstance(value, str):
            self._device_identifier = primitives.TextString(
                value=value,
                tag=enums.Tags.DEVICE_IDENTIFIER
            )
        else:
            raise TypeError("Device identifier must be a string.")

    @property
    def network_identifier(self):
        if self._network_identifier:
            return self._network_identifier.value
        else:
            return None

    @network_identifier.setter
    def network_identifier(self, value):
        if value is None:
            self._network_identifier = None
        elif isinstance(value, str):
            self._network_identifier = primitives.TextString(
                value=value,
                tag=enums.Tags.NETWORK_IDENTIFIER
            )
        else:
            raise TypeError("Network identifier must be a string.")

    @property
    def machine_identifier(self):
        if self._machine_identifier:
            return self._machine_identifier.value
        else:
            return None

    @machine_identifier.setter
    def machine_identifier(self, value):
        if value is None:
            self._machine_identifier = None
        elif isinstance(value, str):
            self._machine_identifier = primitives.TextString(
                value=value,
                tag=enums.Tags.MACHINE_IDENTIFIER
            )
        else:
            raise TypeError("Machine identifier must be a string.")

    @property
    def media_identifier(self):
        if self._media_identifier:
            return self._media_identifier.value
        else:
            return None

    @media_identifier.setter
    def media_identifier(self, value):
        if value is None:
            self._media_identifier = None
        elif isinstance(value, str):
            self._media_identifier = primitives.TextString(
                value=value,
                tag=enums.Tags.MEDIA_IDENTIFIER
            )
        else:
            raise TypeError("Media identifier must be a string.")

    def read(self, input_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the DeviceCredential struct and decode it into
        its constituent parts.

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.
        """
        super(DeviceCredential, self).read(
            input_stream,
            kmip_version=kmip_version
        )
        local_stream = BytearrayStream(input_stream.read(self.length))

        if self.is_tag_next(enums.Tags.DEVICE_SERIAL_NUMBER, local_stream):
            self._device_serial_number = primitives.TextString(
                tag=enums.Tags.DEVICE_SERIAL_NUMBER
            )
            self._device_serial_number.read(
                local_stream,
                kmip_version=kmip_version
            )

        if self.is_tag_next(enums.Tags.PASSWORD, local_stream):
            self._password = primitives.TextString(
                tag=enums.Tags.PASSWORD
            )
            self._password.read(local_stream, kmip_version=kmip_version)

        if self.is_tag_next(enums.Tags.DEVICE_IDENTIFIER, local_stream):
            self._device_identifier = primitives.TextString(
                tag=enums.Tags.DEVICE_IDENTIFIER
            )
            self._device_identifier.read(
                local_stream,
                kmip_version=kmip_version
            )

        if self.is_tag_next(enums.Tags.NETWORK_IDENTIFIER, local_stream):
            self._network_identifier = primitives.TextString(
                tag=enums.Tags.NETWORK_IDENTIFIER
            )
            self._network_identifier.read(
                local_stream,
                kmip_version=kmip_version
            )

        if self.is_tag_next(enums.Tags.MACHINE_IDENTIFIER, local_stream):
            self._machine_identifier = primitives.TextString(
                tag=enums.Tags.MACHINE_IDENTIFIER
            )
            self._machine_identifier.read(
                local_stream,
                kmip_version=kmip_version
            )

        if self.is_tag_next(enums.Tags.MEDIA_IDENTIFIER, local_stream):
            self._media_identifier = primitives.TextString(
                tag=enums.Tags.MEDIA_IDENTIFIER
            )
            self._media_identifier.read(
                local_stream,
                kmip_version=kmip_version
            )

        self.is_oversized(local_stream)

    def write(self, output_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the DeviceCredential struct to a stream.

        Args:
            output_stream (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.
        """
        local_stream = BytearrayStream()

        if self._device_serial_number is not None:
            self._device_serial_number.write(
                local_stream,
                kmip_version=kmip_version
            )
        if self._password is not None:
            self._password.write(
                local_stream,
                kmip_version=kmip_version
            )
        if self._device_identifier is not None:
            self._device_identifier.write(
                local_stream,
                kmip_version=kmip_version
            )
        if self._network_identifier is not None:
            self._network_identifier.write(
                local_stream,
                kmip_version=kmip_version)
        if self._machine_identifier is not None:
            self._machine_identifier.write(
                local_stream,
                kmip_version=kmip_version
            )
        if self._media_identifier is not None:
            self._media_identifier.write(
                local_stream,
                kmip_version=kmip_version
            )

        self.length = local_stream.length()
        super(DeviceCredential, self).write(
            output_stream,
            kmip_version=kmip_version
        )
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, DeviceCredential):
            if self.device_serial_number != other.device_serial_number:
                return False
            elif self.password != other.password:
                return False
            elif self.device_identifier != other.device_identifier:
                return False
            elif self.network_identifier != other.network_identifier:
                return False
            elif self.machine_identifier != other.machine_identifier:
                return False
            elif self.media_identifier != other.media_identifier:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, DeviceCredential):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "device_serial_number='{}'".format(self.device_serial_number),
            "password='{}'".format(self.password),
            "device_identifier='{}'".format(self.device_identifier),
            "network_identifier='{}'".format(self.network_identifier),
            "machine_identifier='{}'".format(self.machine_identifier),
            "media_identifier='{}'".format(self.media_identifier),
        ])
        return "DeviceCredential({})".format(args)

    def __str__(self):
        return str({
            "device_serial_number": self.device_serial_number,
            "password": self.password,
            "device_identifier": self.device_identifier,
            "network_identifier": self.network_identifier,
            "machine_identifier": self.machine_identifier,
            "media_identifier": self.media_identifier
        })

class AttestationCredential(CredentialValue):
    """
    A struct representing an AttestationCredential object.

    Attributes:
        nonce: A nonce value obtained from the key management server.
        attestation_type: The type of attestation being used.
        attestation_measurement: The attestation measurement of the client.
        attestation_assertion: The attestation assertion from a third party.
    """

    def __init__(self,
                 nonce=None,
                 attestation_type=None,
                 attestation_measurement=None,
                 attestation_assertion=None):
        """
        Construct an AttestationCredential struct.

        Args:
            nonce (Nonce): A Nonce structure containing nonce data obtained
                from the key management server. Optional, defaults to None.
                Required for encoding and decoding.
            attestation_type (enum): An AttestationType enumeration specifying
                the type of attestation being used. Optional, defaults to None.
                Required for encoding and decoding.
            attestation_measurement (bytes): The device identifier for the
                credential. Optional, defaults to None. Required for encoding
                and decoding if the attestation assertion is not provided.
            attestation_assertion (bytes): The network identifier for the
                credential. Optional, defaults to None. Required for encoding
                and decoding if the attestation measurement is not provided.
        """
        super(AttestationCredential, self).__init__(tag=Tags.CREDENTIAL_VALUE)

        self._nonce = None
        self._attestation_type = None
        self._attestation_measurement = None
        self._attestation_assertion = None

        self.nonce = nonce
        self.attestation_type = attestation_type
        self.attestation_measurement = attestation_measurement
        self.attestation_assertion = attestation_assertion

    @property
    def nonce(self):
        return self._nonce

    @nonce.setter
    def nonce(self, value):
        if value is None:
            self._nonce = None
        elif isinstance(value, Nonce):
            self._nonce = value
        else:
            raise TypeError("Nonce must be a Nonce struct.")

    @property
    def attestation_type(self):
        if self._attestation_type:
            return self._attestation_type.value
        else:
            return None

    @attestation_type.setter
    def attestation_type(self, value):
        if value is None:
            self._attestation_type = None
        elif isinstance(value, enums.AttestationType):
            self._attestation_type = Enumeration(
                enums.AttestationType,
                value=value,
                tag=Tags.ATTESTATION_TYPE
            )
        else:
            raise TypeError(
                "Attestation type must be an AttestationType enumeration."
            )

    @property
    def attestation_measurement(self):
        if self._attestation_measurement:
            return self._attestation_measurement.value
        else:
            return None

    @attestation_measurement.setter
    def attestation_measurement(self, value):
        if value is None:
            self._attestation_measurement = None
        elif isinstance(value, bytes):
            self._attestation_measurement = primitives.ByteString(
                value=value,
                tag=enums.Tags.ATTESTATION_MEASUREMENT
            )
        else:
            raise TypeError("Attestation measurement must be bytes.")

    @property
    def attestation_assertion(self):
        if self._attestation_assertion:
            return self._attestation_assertion.value
        else:
            return None

    @attestation_assertion.setter
    def attestation_assertion(self, value):
        if value is None:
            self._attestation_assertion = None
        elif isinstance(value, bytes):
            self._attestation_assertion = primitives.ByteString(
                value=value,
                tag=enums.Tags.ATTESTATION_ASSERTION
            )
        else:
            raise TypeError("Attestation assertion must be bytes.")

    def read(self, input_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the AttestationCredential struct and decode it
        into its constituent parts.

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            ValueError: Raised if either the nonce or attestation type are
                missing from the encoding. Also raised if neither the
                attestation measurement nor the attestation assertion are
                included in the encoding.

        """
        super(AttestationCredential, self).read(
            input_stream,
            kmip_version=kmip_version
        )
        local_stream = BytearrayStream(input_stream.read(self.length))

        if self.is_tag_next(enums.Tags.NONCE, local_stream):
            self._nonce = Nonce()
            self._nonce.read(local_stream, kmip_version=kmip_version)
        else:
            raise ValueError(
                "Attestation credential encoding is missing the nonce."
            )

        if self.is_tag_next(enums.Tags.ATTESTATION_TYPE, local_stream):
            self._attestation_type = primitives.Enumeration(
                enums.AttestationType,
                tag=enums.Tags.ATTESTATION_TYPE
            )
            self._attestation_type.read(
                local_stream,
                kmip_version=kmip_version
            )
        else:
            raise ValueError(
                "Attestation credential encoding is missing the attestation "
                "type."
            )

        self._attestation_measurement = None
        if self.is_tag_next(enums.Tags.ATTESTATION_MEASUREMENT, local_stream):
            self._attestation_measurement = primitives.ByteString(
                tag=enums.Tags.ATTESTATION_MEASUREMENT
            )
            self._attestation_measurement.read(
                local_stream,
                kmip_version=kmip_version
            )

        self._attestation_assertion = None
        if self.is_tag_next(enums.Tags.ATTESTATION_ASSERTION, local_stream):
            self._attestation_assertion = primitives.ByteString(
                tag=enums.Tags.ATTESTATION_ASSERTION
            )
            self._attestation_assertion.read(
                local_stream,
                kmip_version=kmip_version
            )

        if ((self._attestation_measurement is None) and
                (self._attestation_assertion is None)):
            raise ValueError(
                "Attestation credential encoding is missing either the "
                "attestation measurement or the attestation assertion."
            )

        self.is_oversized(local_stream)

    def write(self, output_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the AttestationCredential struct to a stream.

        Args:
            output_stream (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            ValueError: Raised if either the nonce or attestation type are
                not defined. Also raised if neither the attestation measurement
                nor the attestation assertion are defined.
        """
        local_stream = BytearrayStream()

        if self._nonce:
            self._nonce.write(local_stream, kmip_version=kmip_version)
        else:
            raise ValueError(
                "Attestation credential struct is missing the nonce."
            )

        if self._attestation_type:
            self._attestation_type.write(
                local_stream,
                kmip_version=kmip_version
            )
        else:
            raise ValueError(
                "Attestation credential struct is missing the attestation "
                "type."
            )

        if self._attestation_measurement:
            self._attestation_measurement.write(
                local_stream,
                kmip_version=kmip_version
            )
        if self._attestation_assertion:
            self._attestation_assertion.write(
                local_stream,
                kmip_version=kmip_version
            )

        if ((self._attestation_measurement is None) and
                (self._attestation_assertion is None)):
            raise ValueError(
                "Attestation credential struct is missing either the "
                "attestation measurement or the attestation assertion."
            )

        self.length = local_stream.length()
        super(AttestationCredential, self).write(
            output_stream,
            kmip_version=kmip_version
        )
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, AttestationCredential):
            if self.nonce != other.nonce:
                return False
            elif self.attestation_type != other.attestation_type:
                return False
            elif self.attestation_measurement != other.attestation_measurement:
                return False
            elif self.attestation_assertion != other.attestation_assertion:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, AttestationCredential):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "nonce={}".format(repr(self.nonce)),
            "attestation_type={}".format(self.attestation_type),
            "attestation_measurement={}".format(self.attestation_measurement),
            "attestation_assertion={}".format(self.attestation_assertion)
        ])
        return "AttestationCredential({})".format(args)

    def __str__(self):
        return "{" \
               "'nonce': " + str(self.nonce) + ", " \
               "'attestation_type': " + str(self.attestation_type) + ", " \
               "'attestation_measurement': " + \
               str(self.attestation_measurement) + ", " \
               "'attestation_assertion': " + \
               str(self.attestation_assertion) + "}"

class Credential(primitives.Struct):
    """
    A struct representing a Credential object.

    Attributes:
        credential_type: The credential type, a CredentialType enumeration.
        credential_value: The credential value, a CredentialValue instance.
    """

    def __init__(self, credential_type=None, credential_value=None):
        """
        Construct a Credential struct.

        Args:
            credential_type (CredentialType): An enumeration value that
                specifies the type of the credential struct. Optional,
                defaults to None. Required for encoding and decoding.
            credential_value (CredentialValue): The credential value
                corresponding to the credential type. Optional, defaults to
                None. Required for encoding and decoding.
        """
        super(Credential, self).__init__(tag=Tags.CREDENTIAL)

        self._credential_type = None
        self._credential_value = None

        self.credential_type = credential_type
        self.credential_value = credential_value

    @property
    def credential_type(self):
        if self._credential_type:
            return self._credential_type.value
        else:
            return None

    @credential_type.setter
    def credential_type(self, value):
        if value is None:
            self._credential_type = None
        elif isinstance(value, enums.CredentialType):
            self._credential_type = Enumeration(
                enums.CredentialType,
                value=value,
                tag=Tags.CREDENTIAL_TYPE
            )
        else:
            raise TypeError(
                "Credential type must be a CredentialType enumeration."
            )

    @property
    def credential_value(self):
        return self._credential_value

    @credential_value.setter
    def credential_value(self, value):
        if value is None:
            self._credential_value = None
        elif isinstance(value, CredentialValue):
            self._credential_value = value
        else:
            raise TypeError(
                "Credential value must be a CredentialValue struct."
            )

    def read(self, input_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the Credential struct and decode it into its
        constituent parts.

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            ValueError: Raised if either the credential type or value are
                missing from the encoding.
        """
        super(Credential, self).read(input_stream, kmip_version=kmip_version)
        local_stream = BytearrayStream(input_stream.read(self.length))

        if self.is_tag_next(enums.Tags.CREDENTIAL_TYPE, local_stream):
            self._credential_type = primitives.Enumeration(
                enum=enums.CredentialType,
                tag=enums.Tags.CREDENTIAL_TYPE
            )
            self._credential_type.read(local_stream, kmip_version=kmip_version)
        else:
            raise ValueError(
                "Credential encoding missing the credential type."
            )

        if self.is_tag_next(enums.Tags.CREDENTIAL_VALUE, local_stream):
            if self.credential_type == \
                    enums.CredentialType.USERNAME_AND_PASSWORD:
                self._credential_value = UsernamePasswordCredential()
            elif self.credential_type == enums.CredentialType.DEVICE:
                self._credential_value = DeviceCredential()
            elif self.credential_type == enums.CredentialType.ATTESTATION:
                self._credential_value = AttestationCredential()
            else:
                raise ValueError(
                    "Credential encoding includes unrecognized credential "
                    "type."
                )
            self._credential_value.read(
                local_stream,
                kmip_version=kmip_version
            )
        else:
            raise ValueError(
                "Credential encoding missing the credential value."
            )

        self.is_oversized(local_stream)

    def write(self, output_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the Credential struct to a stream.

        Args:
            output_stream (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            ValueError: Raised if either the credential type or value are not
                defined.
        """
        local_stream = BytearrayStream()

        if self._credential_type:
            self._credential_type.write(
                local_stream,
                kmip_version=kmip_version
            )
        else:
            raise ValueError(
                "Credential struct missing the credential type."
            )

        if self._credential_value:
            self._credential_value.write(
                local_stream,
                kmip_version=kmip_version
            )
        else:
            raise ValueError(
                "Credential struct missing the credential value."
            )

        self.length = local_stream.length()
        super(Credential, self).write(
            output_stream,
            kmip_version=kmip_version
        )
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, Credential):
            if self.credential_type != other.credential_type:
                return False
            elif self.credential_value != other.credential_value:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, Credential):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "credential_type={}".format(self.credential_type),
            "credential_value={}".format(repr(self.credential_value))
        ])
        return "Credential({})".format(args)

    def __str__(self):
        return str({
            "credential_type": self.credential_type,
            "credential_value": str(self.credential_value)
        })

class KeyBlock(Struct):

    class KeyCompressionType(Enumeration):

        def __init__(self, value=None):
            super(KeyBlock.KeyCompressionType, self).__init__(
                enums.KeyCompressionType, value, Tags.KEY_COMPRESSION_TYPE)

    def __init__(self,
                 key_format_type=None,
                 key_compression_type=None,
                 key_value=None,
                 cryptographic_algorithm=None,
                 cryptographic_length=None,
                 key_wrapping_data=None):
        super(KeyBlock, self).__init__(Tags.KEY_BLOCK)
        self.key_format_type = key_format_type
        self.key_compression_type = key_compression_type
        self.key_value = key_value
        self.cryptographic_algorithm = cryptographic_algorithm
        self.cryptographic_length = cryptographic_length
        self.key_wrapping_data = key_wrapping_data
        self.validate()

    def read(self, istream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        super(KeyBlock, self).read(istream, kmip_version=kmip_version)
        tstream = BytearrayStream(istream.read(self.length))

        self.key_format_type = KeyFormatType()
        self.key_format_type.read(tstream, kmip_version=kmip_version)

        if self.is_tag_next(Tags.KEY_COMPRESSION_TYPE, tstream):
            self.key_compression_type = KeyBlock.KeyCompressionType()
            self.key_compression_type.read(tstream, kmip_version=kmip_version)

        self.key_value = KeyValue()
        self.key_value.read(tstream, kmip_version=kmip_version)

        if self.is_tag_next(Tags.CRYPTOGRAPHIC_ALGORITHM, tstream):
            self.cryptographic_algorithm = attributes.CryptographicAlgorithm()
            self.cryptographic_algorithm.read(
                tstream,
                kmip_version=kmip_version
            )

        if self.is_tag_next(Tags.CRYPTOGRAPHIC_LENGTH, tstream):
            self.cryptographic_length = attributes.CryptographicLength()
            self.cryptographic_length.read(tstream, kmip_version=kmip_version)

        if self.is_tag_next(Tags.KEY_WRAPPING_DATA, tstream):
            self.key_wrapping_data = KeyWrappingData()
            self.key_wrapping_data.read(tstream, kmip_version=kmip_version)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        tstream = BytearrayStream()

        self.key_format_type.write(tstream, kmip_version=kmip_version)

        if self.key_compression_type is not None:
            self.key_compression_type.write(
                tstream,
                kmip_version=kmip_version
            )

        self.key_value.write(tstream, kmip_version=kmip_version)

        if self.cryptographic_algorithm is not None:
            self.cryptographic_algorithm.write(
                tstream,
                kmip_version=kmip_version
            )
        if self.cryptographic_length is not None:
            self.cryptographic_length.write(
                tstream,
                kmip_version=kmip_version
            )
        if self.key_wrapping_data is not None:
            self.key_wrapping_data.write(
                tstream,
                kmip_version=kmip_version
            )

        # Write the length and value of the credential
        self.length = tstream.length()
        super(KeyBlock, self).write(ostream, kmip_version=kmip_version)
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        if self.key_format_type is not None:
            if type(self.key_format_type) is not KeyFormatType:
                member = 'KeyBlock.key_format_type'
                exp_type = KeyFormatType
                rcv_type = type(self.key_format_type)
                msg = exceptions.ErrorStrings.BAD_EXP_RECV.format(
                    member,
                    'type',
                    exp_type,
                    rcv_type
                )
                raise TypeError(msg)

# 2.1.4
class KeyMaterial(ByteString):

    def __init__(self, value=None):
        super(KeyMaterial, self).__init__(value, Tags.KEY_MATERIAL)

# TODO (peter-hamilton) Get rid of this and replace with a KeyMaterial factory.
class KeyMaterialStruct(Struct):

    def __init__(self):
        super(KeyMaterialStruct, self).__init__(Tags.KEY_MATERIAL)

        self.data = BytearrayStream()

        self.validate()

    def read(self, istream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        super(KeyMaterialStruct, self).read(istream, kmip_version=kmip_version)
        tstream = BytearrayStream(istream.read(self.length))

        self.data = BytearrayStream(tstream.read())

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        tstream = BytearrayStream()
        tstream.write(self.data.buffer)

        self.length = tstream.length()
        super(KeyMaterialStruct, self).write(
            ostream,
            kmip_version=kmip_version
        )
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        # NOTE (peter-hamilton): Intentional pass, no way to validate data.
        pass

class KeyValue(Struct):

    def __init__(self,
                 key_material=None,
                 attributes=None):
        super(KeyValue, self).__init__(Tags.KEY_VALUE)

        if key_material is None:
            self.key_material = KeyMaterial()
        else:
            self.key_material = key_material

        if attributes is None:
            self.attributes = list()
        else:
            self.attributes = attributes

        self.validate()

    def read(self, istream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        super(KeyValue, self).read(istream, kmip_version=kmip_version)
        tstream = BytearrayStream(istream.read(self.length))

        # TODO (peter-hamilton) Replace this with a KeyMaterial factory.
        if self.is_type_next(Types.STRUCTURE, tstream):
            self.key_material = KeyMaterialStruct()
            self.key_material.read(tstream, kmip_version=kmip_version)
        else:
            self.key_material = KeyMaterial()
            self.key_material.read(tstream, kmip_version=kmip_version)

        while self.is_tag_next(Tags.ATTRIBUTE, tstream):
            attribute = Attribute()
            attribute.read(tstream, kmip_version=kmip_version)
            self.attributes.append(attribute)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        tstream = BytearrayStream()

        self.key_material.write(tstream, kmip_version=kmip_version)

        for attribute in self.attributes:
            attribute.write(tstream, kmip_version=kmip_version)

        self.length = tstream.length()
        super(KeyValue, self).write(ostream, kmip_version=kmip_version)
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        # TODO (peter-hamilton) Replace with check against KeyMaterial factory.
        if not isinstance(self.key_material, KeyMaterial):
            msg = "invalid key material"
            msg += "; expected {0}, received {1}".format(
                KeyMaterial, self.key_material)
            raise TypeError(msg)

        if isinstance(self.attributes, list):
            for i in range(len(self.attributes)):
                attribute = self.attributes[i]
                if not isinstance(attribute, Attribute):
                    msg = "invalid attribute ({0} in list)".format(i)
                    msg += "; expected {0}, received {1}".format(
                        Attribute, attribute)
                    raise TypeError(msg)
        else:
            msg = "invalid attributes list"
            msg += "; expected {0}, received {1}".format(
                list, self.attributes)
            raise TypeError(msg)

class EncryptionKeyInformation(Struct):
    """
    A set of values detailing how an encrypted value was encrypted.
    """

    def __init__(self,
                 unique_identifier=None,
                 cryptographic_parameters=None):
        """
        Construct an EncryptionKeyInformation struct.

        Args:
            unique_identifier (string): The ID of the managed object (e.g.,
                a symmetric key) used for encryption. Required for encoding
                and decoding.
            cryptographic_parameters (CryptographicParameters): A
                CryptographicParameters struct containing the settings for
                the encryption process. Optional, defaults to None. If not
                included, the CryptographicParameters associated with the
                managed object will be used instead.
        """
        super(EncryptionKeyInformation, self).__init__(
            tag=Tags.ENCRYPTION_KEY_INFORMATION
        )

        self._unique_identifier = None
        self._cryptographic_parameters = None

        self.unique_identifier = unique_identifier
        self.cryptographic_parameters = cryptographic_parameters

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
    def cryptographic_parameters(self):
        return self._cryptographic_parameters

    @cryptographic_parameters.setter
    def cryptographic_parameters(self, value):
        if not value:
            self._cryptographic_parameters = None
        elif isinstance(value, dict):
            self._cryptographic_parameters = CryptographicParameters(**value)
        elif isinstance(value, CryptographicParameters):
            self._cryptographic_parameters = value
        else:
            raise TypeError(
                "Cryptographic parameters must be a CryptographicParameters "
                "struct."
            )

    def read(self, input_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the EncryptionKeyInformation struct and decode
        it into its constituent parts.

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.
        """
        super(EncryptionKeyInformation, self).read(
            input_stream,
            kmip_version=kmip_version
        )
        local_stream = BytearrayStream(input_stream.read(self.length))

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
                "Invalid struct missing the unique identifier attribute."
            )

        if self.is_tag_next(
                enums.Tags.CRYPTOGRAPHIC_PARAMETERS,
                local_stream
        ):
            self._cryptographic_parameters = CryptographicParameters()
            self._cryptographic_parameters.read(
                local_stream,
                kmip_version=kmip_version
            )

        self.is_oversized(local_stream)

    def write(self, output_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the EncryptionKeyInformation struct to a
        stream.

        Args:
            output_stream (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.
        """
        local_stream = BytearrayStream()

        if self._unique_identifier:
            self._unique_identifier.write(
                local_stream,
                kmip_version=kmip_version
            )
        else:
            raise ValueError(
                "Invalid struct missing the unique identifier attribute."
            )

        if self._cryptographic_parameters:
            self._cryptographic_parameters.write(
                local_stream,
                kmip_version=kmip_version
            )

        self.length = local_stream.length()
        super(EncryptionKeyInformation, self).write(
            output_stream,
            kmip_version=kmip_version
        )
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, EncryptionKeyInformation):
            if self.unique_identifier != other.unique_identifier:
                return False
            elif self.cryptographic_parameters != \
                    other.cryptographic_parameters:
                return False
            else:
                return True

    def __ne__(self, other):
        if isinstance(other, EncryptionKeyInformation):
            return not self == other
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "unique_identifier='{0}'".format(self.unique_identifier),
            "cryptographic_parameters={0}".format(
                repr(self.cryptographic_parameters)
            )
        ])
        return "EncryptionKeyInformation({0})".format(args)

    def __str__(self):
        return str({
            'unique_identifier': self.unique_identifier,
            'cryptographic_parameters': self.cryptographic_parameters
        })

class MACSignatureKeyInformation(primitives.Struct):
    """
    A set of values detailing how an MAC/signed value was MAC/signed.
    """

    def __init__(self,
                 unique_identifier=None,
                 cryptographic_parameters=None):
        """
        Construct a MACSignatureKeyInformation struct.

        Args:
            unique_identifier (string): The ID of the managed object (e.g.,
                a symmetric key) used for MAC/signing. Required for encoding
                and decoding.
            cryptographic_parameters (CryptographicParameters): A
                CryptographicParameters struct containing the settings for
                the MAC/signing process. Optional, defaults to None. If not
                included, the CryptographicParameters associated with the
                managed object will be used instead.
        """
        super(MACSignatureKeyInformation, self).__init__(
            tag=Tags.MAC_SIGNATURE_KEY_INFORMATION
        )

        self._unique_identifier = None
        self._cryptographic_parameters = None

        self.unique_identifier = unique_identifier
        self.cryptographic_parameters = cryptographic_parameters

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
    def cryptographic_parameters(self):
        return self._cryptographic_parameters

    @cryptographic_parameters.setter
    def cryptographic_parameters(self, value):
        if not value:
            self._cryptographic_parameters = None
        elif isinstance(value, dict):
            self._cryptographic_parameters = CryptographicParameters(**value)
        elif isinstance(value, CryptographicParameters):
            self._cryptographic_parameters = value
        else:
            raise TypeError(
                "Cryptographic parameters must be a CryptographicParameters "
                "struct."
            )

    def read(self, input_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the MACSignatureKeyInformation struct and
        decode it into its constituent parts.

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.
        """
        super(MACSignatureKeyInformation, self).read(
            input_stream,
            kmip_version=kmip_version
        )
        local_stream = BytearrayStream(input_stream.read(self.length))

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
                "Invalid struct missing the unique identifier attribute."
            )

        if self.is_tag_next(
                enums.Tags.CRYPTOGRAPHIC_PARAMETERS,
                local_stream
        ):
            self._cryptographic_parameters = CryptographicParameters()
            self._cryptographic_parameters.read(
                local_stream,
                kmip_version=kmip_version
            )

        self.is_oversized(local_stream)

    def write(self, output_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the MACSignatureKeyInformation struct to a
        stream.

        Args:
            output_stream (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.
        """
        local_stream = BytearrayStream()

        if self._unique_identifier:
            self._unique_identifier.write(
                local_stream,
                kmip_version=kmip_version
            )
        else:
            raise ValueError(
                "Invalid struct missing the unique identifier attribute."
            )

        if self._cryptographic_parameters:
            self._cryptographic_parameters.write(
                local_stream,
                kmip_version=kmip_version
            )

        self.length = local_stream.length()
        super(MACSignatureKeyInformation, self).write(
            output_stream,
            kmip_version=kmip_version
        )
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, MACSignatureKeyInformation):
            if self.unique_identifier != other.unique_identifier:
                return False
            elif self.cryptographic_parameters != \
                    other.cryptographic_parameters:
                return False
            else:
                return True

    def __ne__(self, other):
        if isinstance(other, MACSignatureKeyInformation):
            return not self == other
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "unique_identifier='{0}'".format(self.unique_identifier),
            "cryptographic_parameters={0}".format(
                repr(self.cryptographic_parameters)
            )
        ])
        return "MACSignatureKeyInformation({0})".format(args)

    def __str__(self):
        return str({
            'unique_identifier': self.unique_identifier,
            'cryptographic_parameters': self.cryptographic_parameters
        })

class KeyWrappingData(Struct):
    """
    A set of key block values needed for key wrapping functionality
    """

    def __init__(self,
                 wrapping_method=None,
                 encryption_key_information=None,
                 mac_signature_key_information=None,
                 mac_signature=None,
                 iv_counter_nonce=None,
                 encoding_option=None):
        """
        Construct a KeyWrappingData struct.

        Args:
            wrapping_method (WrappingMethod): An enumeration value that
                specifies the method to use to wrap the key value. Optional,
                defaults to None. Required for encoding and decoding.
            encryption_key_information (EncryptionKeyInformation): A struct
                containing the unique identifier of the encryption key and
                associated cryptographic parameters. Optional, defaults to
                None.
            mac_signature_key_information (MACSignatureKeyInformation): A
                struct containing the unique identifier of the MAC/signature
                key and associated cryptographic parameters. Optional,
                defaults to None.
            mac_signature (bytes): Bytes containing a MAC or signature of the
                key value. Optional, defaults to None.
            iv_counter_nonce (bytes): Bytes containing an IV/counter/nonce
                value if it is required by the wrapping method. Optional,
                defaults to None.
            encoding_option (EncodingOption): An enumeration value that
                specifies the encoding of the key value before it is wrapped.
                Optional, defaults to None.
        """
        super(KeyWrappingData, self).__init__(Tags.KEY_WRAPPING_DATA)

        self._wrapping_method = None
        self._encryption_key_information = None
        self._mac_signature_key_information = None
        self._mac_signature = None
        self._iv_counter_nonce = None
        self._encoding_option = None

        self.wrapping_method = wrapping_method
        self.encryption_key_information = encryption_key_information
        self.mac_signature_key_information = mac_signature_key_information
        self.mac_signature = mac_signature
        self.iv_counter_nonce = iv_counter_nonce
        self.encoding_option = encoding_option

    @property
    def wrapping_method(self):
        if self._wrapping_method:
            return self._wrapping_method.value
        else:
            return None

    @wrapping_method.setter
    def wrapping_method(self, value):
        if value is None:
            self._wrapping_method = None
        elif isinstance(value, enums.WrappingMethod):
            self._wrapping_method = Enumeration(
                enums.WrappingMethod,
                value=value,
                tag=Tags.WRAPPING_METHOD
            )
        else:
            raise TypeError(
                "Wrapping method must be a WrappingMethod enumeration."
            )

    @property
    def encryption_key_information(self):
        return self._encryption_key_information

    @encryption_key_information.setter
    def encryption_key_information(self, value):
        if not value:
            self._encryption_key_information = None
        elif isinstance(value, dict):
            self._encryption_key_information = \
                EncryptionKeyInformation(**value)
        elif isinstance(value, EncryptionKeyInformation):
            self._encryption_key_information = value
        else:
            raise TypeError(
                "Encryption key information must be an "
                "EncryptionKeyInformation struct."
            )

    @property
    def mac_signature_key_information(self):
        return self._mac_signature_key_information

    @mac_signature_key_information.setter
    def mac_signature_key_information(self, value):
        if not value:
            self._mac_signature_key_information = None
        elif isinstance(value, dict):
            self._mac_signature_key_information = \
                MACSignatureKeyInformation(**value)
        elif isinstance(value, MACSignatureKeyInformation):
            self._mac_signature_key_information = value
        else:
            raise TypeError(
                "MAC/signature key information must be an "
                "MACSignatureKeyInformation struct."
            )

    @property
    def mac_signature(self):
        if self._mac_signature:
            return self._mac_signature.value
        else:
            return None

    @mac_signature.setter
    def mac_signature(self, value):
        if value is None:
            self._mac_signature = None
        elif isinstance(value, bytes):
            self._mac_signature = primitives.ByteString(
                value=value,
                tag=enums.Tags.MAC_SIGNATURE
            )
        else:
            raise TypeError("MAC/signature must be bytes.")

    @property
    def iv_counter_nonce(self):
        if self._iv_counter_nonce:
            return self._iv_counter_nonce.value
        else:
            return None

    @iv_counter_nonce.setter
    def iv_counter_nonce(self, value):
        if value is None:
            self._iv_counter_nonce = None
        elif isinstance(value, bytes):
            self._iv_counter_nonce = primitives.ByteString(
                value=value,
                tag=enums.Tags.IV_COUNTER_NONCE
            )
        else:
            raise TypeError("IV/counter/nonce must be bytes.")

    @property
    def encoding_option(self):
        if self._encoding_option:
            return self._encoding_option.value
        else:
            return None

    @encoding_option.setter
    def encoding_option(self, value):
        if value is None:
            self._encoding_option = None
        elif isinstance(value, enums.EncodingOption):
            self._encoding_option = Enumeration(
                enums.EncodingOption,
                value=value,
                tag=Tags.ENCODING_OPTION
            )
        else:
            raise TypeError(
                "Encoding option must be an EncodingOption enumeration."
            )

    def read(self, input_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the KeyWrappingData struct and decode it into
        its constituent parts.

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.
        """
        super(KeyWrappingData, self).read(
            input_stream,
            kmip_version=kmip_version
        )
        local_stream = BytearrayStream(input_stream.read(self.length))

        if self.is_tag_next(enums.Tags.WRAPPING_METHOD, local_stream):
            self._wrapping_method = primitives.Enumeration(
                enum=enums.WrappingMethod,
                tag=enums.Tags.WRAPPING_METHOD
            )
            self._wrapping_method.read(
                local_stream,
                kmip_version=kmip_version
            )
        else:
            raise ValueError(
                "Invalid struct missing the wrapping method attribute."
            )

        if self.is_tag_next(
                enums.Tags.ENCRYPTION_KEY_INFORMATION,
                local_stream
        ):
            self._encryption_key_information = EncryptionKeyInformation()
            self._encryption_key_information.read(
                local_stream,
                kmip_version=kmip_version
            )
        if self.is_tag_next(
                enums.Tags.MAC_SIGNATURE_KEY_INFORMATION,
                local_stream
        ):
            self._mac_signature_key_information = MACSignatureKeyInformation()
            self._mac_signature_key_information.read(
                local_stream,
                kmip_version=kmip_version
            )

        if self.is_tag_next(enums.Tags.MAC_SIGNATURE, local_stream):
            self._mac_signature = primitives.ByteString(
                tag=enums.Tags.MAC_SIGNATURE
            )
            self._mac_signature.read(
                local_stream,
                kmip_version=kmip_version
            )

        if self.is_tag_next(enums.Tags.IV_COUNTER_NONCE, local_stream):
            self._iv_counter_nonce = primitives.ByteString(
                tag=enums.Tags.IV_COUNTER_NONCE
            )
            self._iv_counter_nonce.read(
                local_stream,
                kmip_version=kmip_version
            )

        if self.is_tag_next(enums.Tags.ENCODING_OPTION, local_stream):
            self._encoding_option = primitives.Enumeration(
                enum=enums.EncodingOption,
                tag=enums.Tags.ENCODING_OPTION
            )
            self._encoding_option.read(
                local_stream,
                kmip_version=kmip_version
            )

        self.is_oversized(local_stream)

    def write(self, output_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the KeyWrappingData struct to a stream.

        Args:
            output_stream (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.
        """
        local_stream = BytearrayStream()

        if self._wrapping_method:
            self._wrapping_method.write(
                local_stream,
                kmip_version=kmip_version
            )
        else:
            raise ValueError(
                "Invalid struct missing the wrapping method attribute."
            )

        if self._encryption_key_information:
            self._encryption_key_information.write(
                local_stream,
                kmip_version=kmip_version
            )
        if self._mac_signature_key_information:
            self._mac_signature_key_information.write(
                local_stream,
                kmip_version=kmip_version
            )
        if self._mac_signature:
            self._mac_signature.write(
                local_stream,
                kmip_version=kmip_version
            )
        if self._iv_counter_nonce:
            self._iv_counter_nonce.write(
                local_stream,
                kmip_version=kmip_version
            )
        if self._encoding_option:
            self._encoding_option.write(
                local_stream,
                kmip_version=kmip_version
            )

        self.length = local_stream.length()
        super(KeyWrappingData, self).write(
            output_stream,
            kmip_version=kmip_version
        )
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, KeyWrappingData):
            if self.wrapping_method != other.wrapping_method:
                return False
            elif self.encryption_key_information != \
                    other.encryption_key_information:
                return False
            elif self.mac_signature_key_information != \
                    other.mac_signature_key_information:
                return False
            elif self.mac_signature != other.mac_signature:
                return False
            elif self.iv_counter_nonce != other.iv_counter_nonce:
                return False
            elif self.encoding_option != other.encoding_option:
                return False
            else:
                return True

    def __ne__(self, other):
        if isinstance(other, KeyWrappingData):
            return not self == other
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "wrapping_method={0}".format(self.wrapping_method),
            "encryption_key_information={0}".format(
                repr(self.encryption_key_information)
            ),
            "mac_signature_key_information={0}".format(
                repr(self.mac_signature_key_information)
            ),
            "mac_signature={0}".format(self.mac_signature),
            "iv_counter_nonce={0}".format(self.iv_counter_nonce),
            "encoding_option={0}".format(self.encoding_option)
        ])
        return "KeyWrappingData({0})".format(args)

    def __str__(self):
        return str({
            'wrapping_method': self.wrapping_method,
            'encryption_key_information': self.encryption_key_information,
            'mac_signature_key_information':
                self.mac_signature_key_information,
            'mac_signature': self.mac_signature,
            'iv_counter_nonce': self.iv_counter_nonce,
            'encoding_option': self.encoding_option
        })

class KeyWrappingSpecification(primitives.Struct):
    """
    A set of values needed for key wrapping functionality.
    """

    def __init__(self,
                 wrapping_method=None,
                 encryption_key_information=None,
                 mac_signature_key_information=None,
                 attribute_names=None,
                 encoding_option=None):
        """
        Construct a KeyWrappingSpecification struct.

        Args:
            wrapping_method (WrappingMethod): An enumeration value that
                specifies the method to use to wrap the key value. Optional,
                defaults to None. Required for encoding and decoding.
            encryption_key_information (EncryptionKeyInformation): A struct
                containing the unique identifier of the encryption key and
                associated cryptographic parameters. Optional, defaults to
                None.
            mac_signature_key_information (MACSignatureKeyInformation): A
                struct containing the unique identifier of the MAC/signature
                key and associated cryptographic parameters. Optional,
                defaults to None.
            attribute_names (list): A list of strings representing the names
                of attributes that should be wrapped with the key material.
                Optional, defaults to None.
            encoding_option (EncodingOption): An enumeration value that
                specifies the encoding of the key value before it is wrapped.
                Optional, defaults to None.
        """
        super(KeyWrappingSpecification, self).__init__(
            tag=Tags.KEY_WRAPPING_SPECIFICATION
        )

        self._wrapping_method = None
        self._encryption_key_information = None
        self._mac_signature_key_information = None
        self._attribute_names = None
        self._encoding_option = None

        self.wrapping_method = wrapping_method
        self.encryption_key_information = encryption_key_information
        self.mac_signature_key_information = mac_signature_key_information
        self.attribute_names = attribute_names
        self.encoding_option = encoding_option

    @property
    def wrapping_method(self):
        if self._wrapping_method:
            return self._wrapping_method.value
        else:
            return None

    @wrapping_method.setter
    def wrapping_method(self, value):
        if value is None:
            self._wrapping_method = None
        elif isinstance(value, enums.WrappingMethod):
            self._wrapping_method = Enumeration(
                enums.WrappingMethod,
                value=value,
                tag=Tags.WRAPPING_METHOD
            )
        else:
            raise TypeError(
                "Wrapping method must be a WrappingMethod enumeration."
            )

    @property
    def encryption_key_information(self):
        return self._encryption_key_information

    @encryption_key_information.setter
    def encryption_key_information(self, value):
        if value is None:
            self._encryption_key_information = None
        elif isinstance(value, EncryptionKeyInformation):
            self._encryption_key_information = value
        else:
            raise TypeError(
                "Encryption key information must be an "
                "EncryptionKeyInformation struct."
            )

    @property
    def mac_signature_key_information(self):
        return self._mac_signature_key_information

    @mac_signature_key_information.setter
    def mac_signature_key_information(self, value):
        if value is None:
            self._mac_signature_key_information = None
        elif isinstance(value, MACSignatureKeyInformation):
            self._mac_signature_key_information = value
        else:
            raise TypeError(
                "MAC/signature key information must be an "
                "MACSignatureKeyInformation struct."
            )

    @property
    def attribute_names(self):
        if self._attribute_names:
            attribute_names = []
            for i in self._attribute_names:
                attribute_names.append(i.value)
            return attribute_names
        else:
            return None

    @attribute_names.setter
    def attribute_names(self, value):
        if value is None:
            self._attribute_names = None
        elif isinstance(value, list):
            attribute_names = []
            for i in value:
                if isinstance(i, str):
                    attribute_names.append(
                        primitives.TextString(
                            value=i,
                            tag=enums.Tags.ATTRIBUTE_NAME
                        )
                    )
                else:
                    raise TypeError(
                        "Attribute names must be a list of strings."
                    )
            self._attribute_names = attribute_names
        else:
            raise TypeError("Attribute names must be a list of strings.")

    @property
    def encoding_option(self):
        if self._encoding_option:
            return self._encoding_option.value
        else:
            return None

    @encoding_option.setter
    def encoding_option(self, value):
        if value is None:
            self._encoding_option = None
        elif isinstance(value, enums.EncodingOption):
            self._encoding_option = Enumeration(
                enums.EncodingOption,
                value=value,
                tag=Tags.ENCODING_OPTION
            )
        else:
            raise TypeError(
                "Encoding option must be an EncodingOption enumeration."
            )

    def read(self, input_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the KeyWrappingSpecification struct and decode
        it into its constituent parts.

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.
        """
        super(KeyWrappingSpecification, self).read(
            input_stream,
            kmip_version=kmip_version
        )
        local_stream = BytearrayStream(input_stream.read(self.length))

        if self.is_tag_next(enums.Tags.WRAPPING_METHOD, local_stream):
            self._wrapping_method = primitives.Enumeration(
                enum=enums.WrappingMethod,
                tag=enums.Tags.WRAPPING_METHOD
            )
            self._wrapping_method.read(
                local_stream,
                kmip_version=kmip_version
            )
        else:
            raise ValueError(
                "Invalid struct missing the wrapping method attribute."
            )

        if self.is_tag_next(
                enums.Tags.ENCRYPTION_KEY_INFORMATION,
                local_stream
        ):
            self._encryption_key_information = EncryptionKeyInformation()
            self._encryption_key_information.read(
                local_stream,
                kmip_version=kmip_version
            )
        if self.is_tag_next(
                enums.Tags.MAC_SIGNATURE_KEY_INFORMATION,
                local_stream
        ):
            self._mac_signature_key_information = MACSignatureKeyInformation()
            self._mac_signature_key_information.read(
                local_stream,
                kmip_version=kmip_version
            )

        attribute_names = []
        while self.is_tag_next(enums.Tags.ATTRIBUTE_NAME, local_stream):
            attribute_name = primitives.TextString(
                tag=enums.Tags.ATTRIBUTE_NAME
            )
            attribute_name.read(local_stream, kmip_version=kmip_version)
            attribute_names.append(attribute_name)
        self._attribute_names = attribute_names

        if self.is_tag_next(enums.Tags.ENCODING_OPTION, local_stream):
            self._encoding_option = primitives.Enumeration(
                enum=enums.EncodingOption,
                tag=enums.Tags.ENCODING_OPTION
            )
            self._encoding_option.read(
                local_stream,
                kmip_version=kmip_version
            )

        self.is_oversized(local_stream)

    def write(self, output_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the KeyWrappingSpecification struct to a
        stream.

        Args:
            output_stream (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.
        """
        local_stream = BytearrayStream()

        if self._wrapping_method:
            self._wrapping_method.write(
                local_stream,
                kmip_version=kmip_version
            )
        else:
            raise ValueError(
                "Invalid struct missing the wrapping method attribute."
            )

        if self._encryption_key_information:
            self._encryption_key_information.write(
                local_stream,
                kmip_version=kmip_version
            )
        if self._mac_signature_key_information:
            self._mac_signature_key_information.write(
                local_stream,
                kmip_version=kmip_version
            )
        if self._attribute_names:
            for unique_identifier in self._attribute_names:
                unique_identifier.write(
                    local_stream,
                    kmip_version=kmip_version
                )
        if self._encoding_option:
            self._encoding_option.write(
                local_stream,
                kmip_version=kmip_version
            )

        self.length = local_stream.length()
        super(KeyWrappingSpecification, self).write(
            output_stream,
            kmip_version=kmip_version
        )
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, KeyWrappingSpecification):
            if self.wrapping_method != other.wrapping_method:
                return False
            elif self.encryption_key_information != \
                    other.encryption_key_information:
                return False
            elif self.mac_signature_key_information != \
                    other.mac_signature_key_information:
                return False
            elif self.attribute_names != other.attribute_names:
                return False
            elif self.encoding_option != other.encoding_option:
                return False
            else:
                return True

    def __ne__(self, other):
        if isinstance(other, KeyWrappingSpecification):
            return not self == other
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "wrapping_method={0}".format(self.wrapping_method),
            "encryption_key_information={0}".format(
                repr(self.encryption_key_information)
            ),
            "mac_signature_key_information={0}".format(
                repr(self.mac_signature_key_information)
            ),
            "attribute_names={0}".format(self.attribute_names),
            "encoding_option={0}".format(self.encoding_option)
        ])
        return "KeyWrappingSpecification({0})".format(args)

    def __str__(self):
        return str({
            'wrapping_method': self.wrapping_method,
            'encryption_key_information': self.encryption_key_information,
            'mac_signature_key_information':
                self.mac_signature_key_information,
            'attribute_names': self.attribute_names,
            'encoding_option': self.encoding_option
        })

class TemplateAttribute(Struct):

    def __init__(self,
                 names=None,
                 attributes=None,
                 tag=Tags.TEMPLATE_ATTRIBUTE):
        super(TemplateAttribute, self).__init__(tag)

        if names is None:
            self.names = list()
        else:
            self.names = names

        if attributes is None:
            self.attributes = list()
        else:
            self.attributes = attributes

        self.validate()

    def read(self, istream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        super(TemplateAttribute, self).read(
            istream,
            kmip_version=kmip_version
        )
        tstream = BytearrayStream(istream.read(self.length))

        self.names = list()
        self.attributes = list()

        # Read the names of the template attribute, 0 or more
        while self.is_tag_next(Tags.NAME, tstream):
            name = attributes.Name()
            name.read(tstream, kmip_version=kmip_version)
            self.names.append(name)

        # Read the attributes of the template attribute, 0 or more
        while self.is_tag_next(Tags.ATTRIBUTE, tstream):
            attribute = Attribute()
            attribute.read(tstream, kmip_version=kmip_version)
            self.attributes.append(attribute)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        tstream = BytearrayStream()

        # Write the names and attributes of the template attribute
        for name in self.names:
            name.write(tstream, kmip_version=kmip_version)
        for attribute in self.attributes:
            attribute.write(tstream, kmip_version=kmip_version)

        # Write the length and value of the template attribute
        self.length = tstream.length()
        super(TemplateAttribute, self).write(
            ostream,
            kmip_version=kmip_version
        )
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        # TODO (peter-hamilton) Finish implementation.
        pass

    def __eq__(self, other):
        if isinstance(other, TemplateAttribute):
            if len(self.names) != len(other.names):
                return False
            if len(self.attributes) != len(other.attributes):
                return False

            # TODO (peter-hamilton) Allow order independence?

            for i in range(len(self.names)):
                a = self.names[i]
                b = other.names[i]

                if a != b:
                    return False

            for i in range(len(self.attributes)):
                a = self.attributes[i]
                b = other.attributes[i]

                if a != b:
                    return False

            return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, TemplateAttribute):
            return not (self == other)
        else:
            return NotImplemented

class CommonTemplateAttribute(TemplateAttribute):

    def __init__(self,
                 names=None,
                 attributes=None):
        super(CommonTemplateAttribute, self).__init__(
            names, attributes, Tags.COMMON_TEMPLATE_ATTRIBUTE)

class PrivateKeyTemplateAttribute(TemplateAttribute):

    def __init__(self,
                 names=None,
                 attributes=None):
        super(PrivateKeyTemplateAttribute, self).__init__(
            names, attributes, Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE)

class PublicKeyTemplateAttribute(TemplateAttribute):

    def __init__(self,
                 names=None,
                 attributes=None):
        super(PublicKeyTemplateAttribute, self).__init__(
            names, attributes, Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE)

def convert_template_attribute_to_attributes(value):
    if not isinstance(value, TemplateAttribute):
        raise TypeError("Input must be a TemplateAttribute structure.")

    tag = enums.Tags.ATTRIBUTES
    if value.tag == enums.Tags.COMMON_TEMPLATE_ATTRIBUTE:
        tag = enums.Tags.COMMON_ATTRIBUTES
    elif value.tag == enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE:
        tag = enums.Tags.PRIVATE_KEY_ATTRIBUTES
    elif value.tag == enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE:
        tag = enums.Tags.PUBLIC_KEY_ATTRIBUTES

    attribute_values = []
    for attribute in value.attributes:
        attribute_tag = enums.convert_attribute_name_to_tag(
            attribute.attribute_name.value
        )
        attribute_value = attribute.attribute_value
        attribute_value.tag = attribute_tag
        attribute_values.append(attribute_value)

    return Attributes(attributes=attribute_values, tag=tag)

def convert_attributes_to_template_attribute(value):
    if not isinstance(value, Attributes):
        raise TypeError("Input must be an Attributes structure.")

    attribute_structures = []
    for attribute_value in value.attributes:
        attribute_name = enums.convert_attribute_tag_to_name(
            attribute_value.tag
        )
        attribute_structures.append(
            Attribute(
                attribute_name=Attribute.AttributeName(attribute_name),
                attribute_value=attribute_value
            )
        )

    template_tag = enums.Tags.TEMPLATE_ATTRIBUTE
    if value.tag == enums.Tags.COMMON_ATTRIBUTES:
        template_tag = enums.Tags.COMMON_TEMPLATE_ATTRIBUTE
    elif value.tag == enums.Tags.PRIVATE_KEY_ATTRIBUTES:
        template_tag = enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
    elif value.tag == enums.Tags.PUBLIC_KEY_ATTRIBUTES:
        template_tag = enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE

    return TemplateAttribute(
        attributes=attribute_structures,
        tag=template_tag
    )

# 2.1.9
class ExtensionName(TextString):
    """
    The name of an extended Object.

    A part of ExtensionInformation, specifically identifying an Object that is
    a custom vendor addition to the KMIP specification. See Section 2.1.9 of
    the KMIP 1.1 specification for more information.

    Attributes:
        value: The string data representing the extension name.
    """
    def __init__(self, value=''):
        """
        Construct an ExtensionName object.

        Args:
            value (str): The string data representing the extension name.
                Optional, defaults to the empty string.
        """
        super(ExtensionName, self).__init__(value, Tags.EXTENSION_NAME)

class ExtensionTag(Integer):
    """
    The tag of an extended Object.

    A part of ExtensionInformation. See Section 2.1.9 of the KMIP 1.1
    specification for more information.

    Attributes:
        value: The tag number identifying the extended object.
    """
    def __init__(self, value=0):
        """
        Construct an ExtensionTag object.

        Args:
            value (int): A number representing the extension tag. Often
                displayed in hex format. Optional, defaults to 0.
        """
        super(ExtensionTag, self).__init__(value, Tags.EXTENSION_TAG)

class ExtensionType(Integer):
    """
    The type of an extended Object.

    A part of ExtensionInformation, specifically identifying the type of the
    Object in the specification extension. See Section 2.1.9 of the KMIP 1.1
    specification for more information.

    Attributes:
        value: The type enumeration for the extended object.
    """
    def __init__(self, value=None):
        """
        Construct an ExtensionType object.

        Args:
            value (Types): A number representing a Types enumeration value,
                indicating the type of the extended Object. Optional, defaults
                to None.
        """
        super(ExtensionType, self).__init__(value, Tags.EXTENSION_TYPE)

class ExtensionInformation(Struct):
    """
    A structure describing Objects defined in KMIP specification extensions.

    It is used specifically for Objects with Item Tag values in the Extensions
    range and appears in responses to Query requests for server extension
    information. See Sections 2.1.9 and 4.25 of the KMIP 1.1 specification for
    more information.

    Attributes:
        extension_name: The name of the extended Object.
        extension_tag: The tag of the extended Object.
        extension_type: The type of the extended Object.
    """
    def __init__(self, extension_name=None, extension_tag=None,
                 extension_type=None):
        """
        Construct an ExtensionInformation object.

        Args:
            extension_name (ExtensionName): The name of the extended Object.
            extension_tag (ExtensionTag): The tag of the extended Object.
            extension_type (ExtensionType): The type of the extended Object.
        """
        super(ExtensionInformation, self).__init__(Tags.EXTENSION_INFORMATION)

        if extension_name is None:
            self.extension_name = ExtensionName()
        else:
            self.extension_name = extension_name

        self.extension_tag = extension_tag
        self.extension_type = extension_type

        self.validate()

    def read(self, istream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the ExtensionInformation object and decode it
        into its constituent parts.

        Args:
            istream (Stream): A data stream containing encoded object data,
                supporting a read method; usually a BytearrayStream object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.
        """
        super(ExtensionInformation, self).read(
            istream,
            kmip_version=kmip_version
        )
        tstream = BytearrayStream(istream.read(self.length))

        self.extension_name.read(tstream, kmip_version=kmip_version)

        if self.is_tag_next(Tags.EXTENSION_TAG, tstream):
            self.extension_tag = ExtensionTag()
            self.extension_tag.read(tstream, kmip_version=kmip_version)
        if self.is_tag_next(Tags.EXTENSION_TYPE, tstream):
            self.extension_type = ExtensionType()
            self.extension_type.read(tstream, kmip_version=kmip_version)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the ExtensionInformation object to a stream.

        Args:
            ostream (Stream): A data stream in which to encode object data,
                supporting a write method; usually a BytearrayStream object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.
        """
        tstream = BytearrayStream()

        self.extension_name.write(tstream, kmip_version=kmip_version)

        if self.extension_tag is not None:
            self.extension_tag.write(tstream, kmip_version=kmip_version)
        if self.extension_type is not None:
            self.extension_type.write(tstream, kmip_version=kmip_version)

        self.length = tstream.length()
        super(ExtensionInformation, self).write(
            ostream,
            kmip_version=kmip_version
        )
        ostream.write(tstream.buffer)

    def validate(self):
        """
        Error check the attributes of the ExtensionInformation object.
        """
        self.__validate()

    def __validate(self):
        if not isinstance(self.extension_name, ExtensionName):
            msg = "invalid extension name"
            msg += "; expected {0}, received {1}".format(
                ExtensionName, self.extension_name)
            raise TypeError(msg)

        if self.extension_tag is not None:
            if not isinstance(self.extension_tag, ExtensionTag):
                msg = "invalid extension tag"
                msg += "; expected {0}, received {1}".format(
                    ExtensionTag, self.extension_tag)
                raise TypeError(msg)

        if self.extension_type is not None:
            if not isinstance(self.extension_type, ExtensionType):
                msg = "invalid extension type"
                msg += "; expected {0}, received {1}".format(
                    ExtensionType, self.extension_type)
                raise TypeError(msg)

    def __eq__(self, other):
        if isinstance(other, ExtensionInformation):
            if self.extension_name != other.extension_name:
                return False
            elif self.extension_tag != other.extension_tag:
                return False
            elif self.extension_type != other.extension_type:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, ExtensionInformation):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        name = "extension_name={0}".format(repr(self.extension_name))
        tag = "extension_tag={0}".format(repr(self.extension_tag))
        typ = "extension_type={0}".format(repr(self.extension_type))
        return "ExtensionInformation({0}, {1}, {2})".format(name, tag, typ)

    def __str__(self):
        return repr(self)

    @classmethod
    def create(cls, extension_name=None, extension_tag=None,
               extension_type=None):
        """
        Construct an ExtensionInformation object from provided extension
        values.

        Args:
            extension_name (str): The name of the extension. Optional,
                defaults to None.
            extension_tag (int): The tag number of the extension. Optional,
                defaults to None.
            extension_type (int): The type index of the extension. Optional,
                defaults to None.

        Returns:
            ExtensionInformation: The newly created set of extension
                information.

        Example:
            >>> x = ExtensionInformation.create('extension', 1, 1)
            >>> x.extension_name.value
            ExtensionName(value='extension')
            >>> x.extension_tag.value
            ExtensionTag(value=1)
            >>> x.extension_type.value
            ExtensionType(value=1)
        """
        extension_name = ExtensionName(extension_name)
        extension_tag = ExtensionTag(extension_tag)
        extension_type = ExtensionType(extension_type)

        return ExtensionInformation(
            extension_name=extension_name,
            extension_tag=extension_tag,
            extension_type=extension_type)

# 2.1.10
class Data(ByteString):

    def __init__(self, value=None):
        super(Data, self).__init__(value, Tags.DATA)

# 2.1.13
class MACData(ByteString):

    def __init__(self, value=None):
        super(MACData, self).__init__(value, Tags.MAC_DATA)

# 3.31, 9.1.3.2.19
class RevocationReasonCode(Enumeration):

    def __init__(self, value=enums.RevocationReasonCode.UNSPECIFIED):
        super(RevocationReasonCode, self).__init__(
            enums.RevocationReasonCode, value=value,
            tag=Tags.REVOCATION_REASON_CODE)

# 3.31
class RevocationReason(Struct):
    """
    A structure describing  the reason for a revocation operation.

    See Sections 2.1.9 and 4.25 of the KMIP 1.1 specification for
    more information.

    Attributes:
        code: The revocation reason code enumeration
        message: An optional revocation message
    """

    def __init__(self, code=None, message=None):
        """
        Construct a RevocationReason object.

        Parameters:
            code(RevocationReasonCode): revocation reason code
            message(string): An optional revocation message
        """
        super(RevocationReason, self).__init__(tag=Tags.REVOCATION_REASON)
        if code is not None:
            self.revocation_code = RevocationReasonCode(value=code)
        else:
            self.revocation_code = RevocationReasonCode()

        if message is not None:
            self.revocation_message = TextString(
                value=message,
                tag=Tags.REVOCATION_MESSAGE)
        else:
            self.revocation_message = None

        self.validate()

    def read(self, istream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the RevocationReason object and decode it
        into its constituent parts.

        Args:
            istream (Stream): A data stream containing encoded object data,
                supporting a read method; usually a BytearrayStream object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.
        """
        super(RevocationReason, self).read(istream, kmip_version=kmip_version)
        tstream = BytearrayStream(istream.read(self.length))

        self.revocation_code = RevocationReasonCode()
        self.revocation_code.read(tstream, kmip_version=kmip_version)

        if self.is_tag_next(Tags.REVOCATION_MESSAGE, tstream):
            self.revocation_message = TextString(tag=Tags.REVOCATION_MESSAGE)
            self.revocation_message.read(tstream, kmip_version=kmip_version)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the RevocationReason object to a stream.

        Args:
            ostream (Stream): A data stream in which to encode object data,
                supporting a write method; usually a BytearrayStream object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.
        """
        tstream = BytearrayStream()

        self.revocation_code.write(tstream, kmip_version=kmip_version)
        if self.revocation_message is not None:
            self.revocation_message.write(tstream, kmip_version=kmip_version)

        # Write the length and value
        self.length = tstream.length()
        super(RevocationReason, self).write(ostream, kmip_version=kmip_version)
        ostream.write(tstream.buffer)

    def validate(self):
        """
        validate the RevocationReason object
        """
        if not isinstance(self.revocation_code, RevocationReasonCode):
            msg = "RevocationReaonCode expected"
            raise TypeError(msg)
        if self.revocation_message is not None:
            if not isinstance(self.revocation_message, TextString):
                msg = "TextString expect"
                raise TypeError(msg)

class ObjectDefaults(primitives.Struct):
    """
    A structure containing default object values used by the server.

    This is intended for use with KMIP 2.0+.

    Attributes:
        object_type: An ObjectType enumeration identifying the type to which
            the defaults pertain.
        attributes: An Attributes structure containing attribute values that
            are defaults for an object type.
    """

    def __init__(self, object_type=None, attributes=None):
        """
        Construct an ObjectDefaults structure.

        Args:
            object_type (enum): An ObjectType enumeration identifying the type
                to which the defaults pertain. Optional, defaults to None.
                Required for read/write.
            attributes (structure): An Attributes structure containing
                attribute values that are defaults for an object type.
                Optional, defaults to None. Required for read/write.
        """
        super(ObjectDefaults, self).__init__(tag=enums.Tags.OBJECT_DEFAULTS)

        self._object_type = None
        self._attributes = None

        self.object_type = object_type
        self.attributes = attributes

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
            raise TypeError("Object type must be an ObjectType enumeration.")

    @property
    def attributes(self):
        return self._attributes

    @attributes.setter
    def attributes(self, value):
        if value is None:
            self._attributes = None
        elif isinstance(value, Attributes):
            self._attributes = value
        else:
            raise TypeError("Attributes must be an Attributes structure.")

    def read(self, input_buffer, kmip_version=enums.KMIPVersion.KMIP_2_0):
        """
        Read the data encoding the ObjectDefaults structure and decode it into
        its constituent parts.

        Args:
            input_buffer (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 2.0.

        Raises:
            InvalidKmipEncoding: Raised if the object type or attributes are
                missing from the encoding.
            VersionNotSupported: Raised when a KMIP version is provided that
                does not support the ObjectDefaults structure.
        """
        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            raise exceptions.VersionNotSupported(
                "KMIP {} does not support the ObjectDefaults object.".format(
                    kmip_version.value
                )
            )

        super(ObjectDefaults, self).read(
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
                "The ObjectDefaults encoding is missing the object type "
                "enumeration."
            )

        if self.is_tag_next(enums.Tags.ATTRIBUTES, local_buffer):
            self._attributes = Attributes()
            self._attributes.read(local_buffer, kmip_version=kmip_version)
        else:
            raise exceptions.InvalidKmipEncoding(
                "The ObjectDefaults encoding is missing the attributes "
                "structure."
            )

        self.is_oversized(local_buffer)

    def write(self, output_buffer, kmip_version=enums.KMIPVersion.KMIP_2_0):
        """
        Write the ObjectDefaults structure encoding to the data stream.

        Args:
            output_buffer (stream): A data stream in which to encode
                Attributes structure data, supporting a write method.
            kmip_version (enum): A KMIPVersion enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 2.0.

        Raises:
            InvalidField: Raised if the object type or attributes fields are
                not defined.
            VersionNotSupported: Raised when a KMIP version is provided that
                does not support the ObjectDefaults structure.
        """
        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            raise exceptions.VersionNotSupported(
                "KMIP {} does not support the ObjectDefaults object.".format(
                    kmip_version.value
                )
            )

        local_buffer = BytearrayStream()

        if self._object_type:
            self._object_type.write(local_buffer, kmip_version=kmip_version)
        else:
            raise exceptions.InvalidField(
                "The ObjectDefaults structure is missing the object type "
                "field."
            )

        if self._attributes:
            self._attributes.write(local_buffer, kmip_version=kmip_version)
        else:
            raise exceptions.InvalidField(
                "The ObjectDefaults structure is missing the attributes field."
            )

        self.length = local_buffer.length()
        super(ObjectDefaults, self).write(
            output_buffer,
            kmip_version=kmip_version
        )
        output_buffer.write(local_buffer.buffer)

    def __repr__(self):
        o = "object_type={}".format(
            '{}'.format(
                self.object_type
            ) if self.object_type else None
        )
        a = "attributes={}".format(
            '{}'.format(repr(self.attributes)) if self.attributes else None
        )
        values = ", ".join([o, a])
        return "ObjectDefaults({})".format(values)

    def __str__(self):
        o = '"object_type": {}'.format(
            "{}".format(
                self.object_type
            ) if self.object_type else None
        )
        a = '"attributes": {}'.format(
            "{}".format(str(self.attributes)) if self.attributes else None
        )
        values = ", ".join([o, a])
        return '{' + values + '}'

    def __eq__(self, other):
        if isinstance(other, ObjectDefaults):
            if self.object_type != other.object_type:
                return False
            elif self.attributes != other.attributes:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, ObjectDefaults):
            return not (self == other)
        else:
            return NotImplemented

class DefaultsInformation(primitives.Struct):
    """
    """

    def __init__(self, object_defaults=None):
        """
        """
        super(DefaultsInformation, self).__init__(
            tag=enums.Tags.DEFAULTS_INFORMATION
        )

        self._object_defaults = None

        self.object_defaults = object_defaults

    @property
    def object_defaults(self):
        return self._object_defaults

    @object_defaults.setter
    def object_defaults(self, value):
        if value is None:
            self._object_defaults = None
        elif isinstance(value, list):
            object_defaults = []
            for v in value:
                if not isinstance(v, ObjectDefaults):
                    raise TypeError(
                        "Object defaults must be a list of ObjectDefaults "
                        "structures."
                    )
                else:
                    object_defaults.append(v)
            self._object_defaults = object_defaults
        else:
            raise TypeError(
                "Object defaults must be a list of ObjectDefaults structures."
            )

    def read(self, input_buffer, kmip_version=enums.KMIPVersion.KMIP_2_0):
        """
        Read the data encoding the DefaultsInformation structure and decode it
        into its constituent parts.

        Args:
            input_buffer (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 2.0.

        Raises:
            InvalidKmipEncoding: Raised if the object defaults are missing
                from the encoding.
            VersionNotSupported: Raised when a KMIP version is provided that
                does not support the DefaultsInformation structure.
        """
        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            raise exceptions.VersionNotSupported(
                "KMIP {} does not support the DefaultsInformation "
                "object.".format(
                    kmip_version.value
                )
            )

        super(DefaultsInformation, self).read(
            input_buffer,
            kmip_version=kmip_version
        )
        local_buffer = utils.BytearrayStream(input_buffer.read(self.length))

        object_defaults = []
        while self.is_tag_next(enums.Tags.OBJECT_DEFAULTS, local_buffer):
            object_default = ObjectDefaults()
            object_default.read(local_buffer, kmip_version=kmip_version)
            object_defaults.append(object_default)

        if len(object_defaults) == 0:
            raise exceptions.InvalidKmipEncoding(
                "The DefaultsInformation encoding is missing the object "
                "defaults structure."
            )
        else:
            self._object_defaults = object_defaults

        self.is_oversized(local_buffer)

    def write(self, output_buffer, kmip_version=enums.KMIPVersion.KMIP_2_0):
        """
        Write the DefaultsInformation structure encoding to the data stream.

        Args:
            output_buffer (stream): A data stream in which to encode
                Attributes structure data, supporting a write method.
            kmip_version (enum): A KMIPVersion enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 2.0.

        Raises:
            InvalidField: Raised if the object defaults field is not defined.
            VersionNotSupported: Raised when a KMIP version is provided that
                does not support the DefaultsInformation structure.
        """
        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            raise exceptions.VersionNotSupported(
                "KMIP {} does not support the DefaultsInformation "
                "object.".format(
                    kmip_version.value
                )
            )

        local_buffer = BytearrayStream()

        if self._object_defaults:
            for object_default in self._object_defaults:
                object_default.write(local_buffer, kmip_version=kmip_version)
        else:
            raise exceptions.InvalidField(
                "The DefaultsInformation structure is missing the object "
                "defaults field."
            )

        self.length = local_buffer.length()
        super(DefaultsInformation, self).write(
            output_buffer,
            kmip_version=kmip_version
        )
        output_buffer.write(local_buffer.buffer)

    def __repr__(self):
        d = "object_defaults={}".format(
            '{}'.format(
                repr(self.object_defaults)
            ) if self.object_defaults else None
        )
        return "DefaultsInformation({})".format(d)

    def __str__(self):
        d = '"object_defaults": {}'.format(
            "[{}]".format(
                ", ".join([str(x) for x in self.object_defaults])
            ) if self.object_defaults else None
        )
        return '{' + d + '}'

    def __eq__(self, other):
        if isinstance(other, DefaultsInformation):
            if self.object_defaults == other.object_defaults:
                return True
            else:
                return False
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, DefaultsInformation):
            return not (self == other)
        else:
            return NotImplemented

class RNGParameters(primitives.Struct):
    """
    A structure containing parameters for a random number generator.

    This is intended for use with KMIP 1.3+.

    Attributes:
        rng_algorithm: An RNGAlgorithm enumeration identifying the type of
            random number generator to which the parameters pertain.
        cryptographic_algorithm: A CryptographicAlgorithm enumeration
            identifying the cryptographic algorithm used by the RNG.
        cryptographic_length: An integer specifying the length to be used
            with the cryptographic algorithm.
        hashing_algorithm: A HashingAlgorithm enumeration identifying the
            hashing algorithm used by the RNG.
        drbg_algorithm: A DRBGAlgorithm enumeration identifying the DRBG
            algorithm used by the RNG.
        recommended_curve: A RecommendedCurve enumeration identifying the
            recommended curve used by the RNG.
        fips186_variation: A FIPS186Variation enumeration identifying the
            FIPS186 variation used by the RNG.
        prediction_resistance: A boolean indicating whether or not
            prediction resistance is leveraged by the RNG.
    """

    def __init__(self,
                 rng_algorithm=None,
                 cryptographic_algorithm=None,
                 cryptographic_length=None,
                 hashing_algorithm=None,
                 drbg_algorithm=None,
                 recommended_curve=None,
                 fips186_variation=None,
                 prediction_resistance=None):
        """
        Construct an RNGParameters structure.

        Args:
            rng_algorithm (enum): An RNGAlgorithm enumeration identifying the
                type of random number generator to which the parameters
                pertain. Optional, defaults to None. Required for read/write.
            cryptographic_algorithm (enum): A CryptographicAlgorithm
                enumeration identifying the cryptographic algorithm used by
                the RNG. Optional, defaults to None.
            cryptographic_length (int): An integer specifying the length to be
                used with the cryptographic algorithm. Optional, defaults to
                None.
            hashing_algorithm (enum): A HashingAlgorithm enumeration
                identifying the hashing algorithm used by the RNG. Optional,
                defaults to None.
            drbg_algorithm (enum): A DRBGAlgorithm enumeration identifying the
                DRBG algorithm used by the RNG. Optional, defaults to None.
            recommended_curve (enum): A RecommendedCurve enumeration
                identifying the recommended curve used by the RNG. Optional,
                defaults to None.
            fips186_variation (enum): A FIPS186Variation enumeration
                identifying the FIPS186 variation used by the RNG. Optional,
                defaults to None.
            prediction_resistance (bool): A boolean indicating whether or not
                prediction resistance is leveraged by the RNG. Optional,
                defaults to None.
        """
        super(RNGParameters, self).__init__(tag=enums.Tags.RNG_PARAMETERS)

        self._rng_algorithm = None
        self._cryptographic_algorithm = None
        self._cryptographic_length = None
        self._hashing_algorithm = None
        self._drbg_algorithm = None
        self._recommended_curve = None
        self._fips186_variation = None
        self._prediction_resistance = None

        self.rng_algorithm = rng_algorithm
        self.cryptographic_algorithm = cryptographic_algorithm
        self.cryptographic_length = cryptographic_length
        self.hashing_algorithm = hashing_algorithm
        self.drbg_algorithm = drbg_algorithm
        self.recommended_curve = recommended_curve
        self.fips186_variation = fips186_variation
        self.prediction_resistance = prediction_resistance

    @property
    def rng_algorithm(self):
        return self._rng_algorithm.value if self._rng_algorithm else None

    @rng_algorithm.setter
    def rng_algorithm(self, value):
        if value is None:
            self._rng_algorithm = None
        elif isinstance(value, enums.RNGAlgorithm):
            self._rng_algorithm = primitives.Enumeration(
                enums.RNGAlgorithm,
                value=value,
                tag=enums.Tags.RNG_ALGORITHM
            )
        else:
            raise TypeError(
                "The RNG algorithm must be an RNGAlgorithm enumeration."
            )

    @property
    def cryptographic_algorithm(self):
        if self._cryptographic_algorithm:
            return self._cryptographic_algorithm.value
        else:
            return None

    @cryptographic_algorithm.setter
    def cryptographic_algorithm(self, value):
        if value is None:
            self._cryptographic_algorithm = None
        elif isinstance(value, enums.CryptographicAlgorithm):
            self._cryptographic_algorithm = primitives.Enumeration(
                enums.CryptographicAlgorithm,
                value=value,
                tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
            )
        else:
            raise TypeError(
                "The cryptographic algorithm must be a "
                "CryptographicAlgorithm enumeration."
            )

    @property
    def cryptographic_length(self):
        if self._cryptographic_length:
            return self._cryptographic_length.value
        else:
            return None

    @cryptographic_length.setter
    def cryptographic_length(self, value):
        if value is None:
            self._cryptographic_length = None
        elif isinstance(value, int):
            self._cryptographic_length = primitives.Integer(
                value=value,
                tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
            )
        else:
            raise TypeError("The cryptographic length must be an integer.")

    @property
    def hashing_algorithm(self):
        if self._hashing_algorithm:
            return self._hashing_algorithm.value
        else:
            return None

    @hashing_algorithm.setter
    def hashing_algorithm(self, value):
        if value is None:
            self._hashing_algorithm = None
        elif isinstance(value, enums.HashingAlgorithm):
            self._hashing_algorithm = primitives.Enumeration(
                enums.HashingAlgorithm,
                value=value,
                tag=enums.Tags.HASHING_ALGORITHM
            )
        else:
            raise TypeError(
                "The hashing algorithm must be a HashingAlgorithm "
                "enumeration."
            )

    @property
    def drbg_algorithm(self):
        return self._drbg_algorithm.value if self._drbg_algorithm else None

    @drbg_algorithm.setter
    def drbg_algorithm(self, value):
        if value is None:
            self._drbg_algorithm = None
        elif isinstance(value, enums.DRBGAlgorithm):
            self._drbg_algorithm = primitives.Enumeration(
                enums.DRBGAlgorithm,
                value=value,
                tag=enums.Tags.DRBG_ALGORITHM
            )
        else:
            raise TypeError(
                "The DRBG algorithm must be a DRBGAlgorithm enumeration."
            )

    @property
    def recommended_curve(self):
        if self._recommended_curve:
            return self._recommended_curve.value
        else:
            return None

    @recommended_curve.setter
    def recommended_curve(self, value):
        if value is None:
            self._recommended_curve = None
        elif isinstance(value, enums.RecommendedCurve):
            self._recommended_curve = primitives.Enumeration(
                enums.RecommendedCurve,
                value=value,
                tag=enums.Tags.RECOMMENDED_CURVE
            )
        else:
            raise TypeError(
                "The recommended curve must be a RecommendedCurve "
                "enumeration."
            )

    @property
    def fips186_variation(self):
        if self._fips186_variation:
            return self._fips186_variation.value
        else:
            return None

    @fips186_variation.setter
    def fips186_variation(self, value):
        if value is None:
            self._fips186_variation = None
        elif isinstance(value, enums.FIPS186Variation):
            self._fips186_variation = primitives.Enumeration(
                enums.FIPS186Variation,
                value=value,
                tag=enums.Tags.FIPS186_VARIATION
            )
        else:
            raise TypeError(
                "The FIPS186 variation must be a FIPS186Variation "
                "enumeration."
            )

    @property
    def prediction_resistance(self):
        if self._prediction_resistance:
            return self._prediction_resistance.value
        else:
            return None

    @prediction_resistance.setter
    def prediction_resistance(self, value):
        if value is None:
            self._prediction_resistance = None
        elif isinstance(value, bool):
            self._prediction_resistance = primitives.Boolean(
                value=value,
                tag=enums.Tags.PREDICTION_RESISTANCE
            )
        else:
            raise TypeError("The prediction resistance must be a boolean.")

    def read(self, input_buffer, kmip_version=enums.KMIPVersion.KMIP_1_3):
        """
        Read the data encoding the RNGParameters structure and decode it
        into its constituent parts.

        Args:
            input_buffer (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 2.0.

        Raises:
            InvalidKmipEncoding: Raised if the RNG algorithm is missing from
                the encoding.
            VersionNotSupported: Raised when a KMIP version is provided that
                does not support the RNGParameters structure.
        """
        if kmip_version < enums.KMIPVersion.KMIP_1_3:
            raise exceptions.VersionNotSupported(
                "KMIP {} does not support the RNGParameters object.".format(
                    kmip_version.value
                )
            )

        super(RNGParameters, self).read(
            input_buffer,
            kmip_version=kmip_version
        )
        local_buffer = utils.BytearrayStream(input_buffer.read(self.length))

        if self.is_tag_next(enums.Tags.RNG_ALGORITHM, local_buffer):
            rng_algorithm = primitives.Enumeration(
                enums.RNGAlgorithm,
                tag=enums.Tags.RNG_ALGORITHM
            )
            rng_algorithm.read(local_buffer, kmip_version=kmip_version)
            self._rng_algorithm = rng_algorithm
        else:
            raise exceptions.InvalidKmipEncoding(
                "The RNGParameters encoding is missing the RNG algorithm."
            )

        if self.is_tag_next(enums.Tags.CRYPTOGRAPHIC_ALGORITHM, local_buffer):
            cryptographic_algorithm = primitives.Enumeration(
                enums.CryptographicAlgorithm,
                tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
            )
            cryptographic_algorithm.read(
                local_buffer,
                kmip_version=kmip_version
            )
            self._cryptographic_algorithm = cryptographic_algorithm

        if self.is_tag_next(enums.Tags.CRYPTOGRAPHIC_LENGTH, local_buffer):
            cryptographic_length = primitives.Integer(
                tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
            )
            cryptographic_length.read(local_buffer, kmip_version=kmip_version)
            self._cryptographic_length = cryptographic_length

        if self.is_tag_next(enums.Tags.HASHING_ALGORITHM, local_buffer):
            hashing_algorithm = primitives.Enumeration(
                enums.HashingAlgorithm,
                tag=enums.Tags.HASHING_ALGORITHM
            )
            hashing_algorithm.read(local_buffer, kmip_version=kmip_version)
            self._hashing_algorithm = hashing_algorithm

        if self.is_tag_next(enums.Tags.DRBG_ALGORITHM, local_buffer):
            drbg_algorithm = primitives.Enumeration(
                enums.DRBGAlgorithm,
                tag=enums.Tags.DRBG_ALGORITHM
            )
            drbg_algorithm.read(local_buffer, kmip_version=kmip_version)
            self._drbg_algorithm = drbg_algorithm

        if self.is_tag_next(enums.Tags.RECOMMENDED_CURVE, local_buffer):
            recommended_curve = primitives.Enumeration(
                enums.RecommendedCurve,
                tag=enums.Tags.RECOMMENDED_CURVE
            )
            recommended_curve.read(local_buffer, kmip_version=kmip_version)
            self._recommended_curve = recommended_curve

        if self.is_tag_next(enums.Tags.FIPS186_VARIATION, local_buffer):
            fips186_variation = primitives.Enumeration(
                enums.FIPS186Variation,
                tag=enums.Tags.FIPS186_VARIATION
            )
            fips186_variation.read(local_buffer, kmip_version=kmip_version)
            self._fips186_variation = fips186_variation

        if self.is_tag_next(enums.Tags.PREDICTION_RESISTANCE, local_buffer):
            prediction_resistance = primitives.Boolean(
                tag=enums.Tags.PREDICTION_RESISTANCE
            )
            prediction_resistance.read(
                local_buffer,
                kmip_version=kmip_version
            )
            self._prediction_resistance = prediction_resistance

        self.is_oversized(local_buffer)

    def write(self, output_buffer, kmip_version=enums.KMIPVersion.KMIP_1_3):
        """
        Write the RNGParameters structure encoding to the data stream.

        Args:
            output_buffer (stream): A data stream in which to encode
                Attributes structure data, supporting a write method.
            kmip_version (enum): A KMIPVersion enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 2.0.

        Raises:
            InvalidField: Raised if the RNG algorithm field is not defined.
            VersionNotSupported: Raised when a KMIP version is provided that
                does not support the RNGParameters structure.
        """
        if kmip_version < enums.KMIPVersion.KMIP_1_3:
            raise exceptions.VersionNotSupported(
                "KMIP {} does not support the RNGParameters object.".format(
                    kmip_version.value
                )
            )

        local_buffer = BytearrayStream()

        if self._rng_algorithm:
            self._rng_algorithm.write(local_buffer, kmip_version=kmip_version)
        else:
            raise exceptions.InvalidField(
                "The RNGParameters structure is missing the RNG algorithm "
                "field."
            )

        if self._cryptographic_algorithm:
            self._cryptographic_algorithm.write(
                local_buffer,
                kmip_version=kmip_version
            )

        if self._cryptographic_length:
            self._cryptographic_length.write(
                local_buffer,
                kmip_version=kmip_version
            )

        if self._hashing_algorithm:
            self._hashing_algorithm.write(
                local_buffer,
                kmip_version=kmip_version
            )

        if self._drbg_algorithm:
            self._drbg_algorithm.write(
                local_buffer,
                kmip_version=kmip_version
            )

        if self._recommended_curve:
            self._recommended_curve.write(
                local_buffer,
                kmip_version=kmip_version
            )

        if self._fips186_variation:
            self._fips186_variation.write(
                local_buffer,
                kmip_version=kmip_version
            )

        if self._prediction_resistance:
            self._prediction_resistance.write(
                local_buffer,
                kmip_version=kmip_version
            )

        self.length = local_buffer.length()
        super(RNGParameters, self).write(
            output_buffer,
            kmip_version=kmip_version
        )
        output_buffer.write(local_buffer.buffer)

    def __repr__(self):
        a = "rng_algorithm={}".format(self.rng_algorithm)
        c = "cryptographic_algorithm={}".format(self.cryptographic_algorithm)
        e = "cryptographic_length={}".format(self.cryptographic_length)
        h = "hashing_algorithm={}".format(self.hashing_algorithm)
        d = "drbg_algorithm={}".format(self.drbg_algorithm)
        r = "recommended_curve={}".format(self.recommended_curve)
        f = "fips186_variation={}".format(self.fips186_variation)
        p = "prediction_resistance={}".format(self.prediction_resistance)

        v = ", ".join([a, c, e, h, d, r, f, p])

        return "RNGParameters({})".format(v)

    def __str__(self):
        a = '"rng_algorithm": {}'.format(self.rng_algorithm)
        c = '"cryptographic_algorithm": {}'.format(
            self.cryptographic_algorithm
        )
        e = '"cryptographic_length": {}'.format(self.cryptographic_length)
        h = '"hashing_algorithm": {}'.format(self.hashing_algorithm)
        d = '"drbg_algorithm": {}'.format(self.drbg_algorithm)
        r = '"recommended_curve": {}'.format(self.recommended_curve)
        f = '"fips186_variation": {}'.format(self.fips186_variation)
        p = '"prediction_resistance": {}'.format(self.prediction_resistance)

        v = ", ".join([a, c, e, h, d, r, f, p])

        return '{' + v + '}'

    def __eq__(self, other):
        if isinstance(other, RNGParameters):
            if self.rng_algorithm != other.rng_algorithm:
                return False
            elif self.cryptographic_algorithm != other.cryptographic_algorithm:
                return False
            elif self.cryptographic_length != other.cryptographic_length:
                return False
            elif self.hashing_algorithm != other.hashing_algorithm:
                return False
            elif self.drbg_algorithm != other.drbg_algorithm:
                return False
            elif self.recommended_curve != other.recommended_curve:
                return False
            elif self.fips186_variation != other.fips186_variation:
                return False
            elif self.prediction_resistance != other.prediction_resistance:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, RNGParameters):
            return not (self == other)
        else:
            return NotImplemented

class ProfileInformation(primitives.Struct):
    """
    A structure containing details of supported KMIP profiles.

    This is intended for use with KMIP 1.3+.

    Attributes:
        profile_name: A ProfileName enumeration identifying the specific
            profile supported.
        server_uri: A string specifying a Uniform Resource Identifier that
            points to the location of the server supporting the profile.
        server_port: An integer specifying the port number to use when
            accessing the server supporting the profile.
    """

    def __init__(self, profile_name=None, server_uri=None, server_port=None):
        """
        Construct a ProfileInformation structure.

        Args:
            profile_name (enum): A ProfileName enumeration identifying the
                specific profile supported. Optional, defaults to None.
                Required for read/write.
            server_uri (string): A string specifying a Uniform Resource
                Identifier that points to the location of the server
                supporting the profile. Optional, defaults to None.
            server_port (int): An integer specifying the port number to use
                when accessing the server supporting the profile. Optional,
                defaults to None.
        """
        super(ProfileInformation, self).__init__(
            tag=enums.Tags.PROFILE_INFORMATION
        )

        self._profile_name = None
        self._server_uri = None
        self._server_port = None

        self.profile_name = profile_name
        self.server_uri = server_uri
        self.server_port = server_port

    @property
    def profile_name(self):
        if self._profile_name:
            return self._profile_name.value
        return None

    @profile_name.setter
    def profile_name(self, value):
        if value is None:
            self._profile_name = None
        elif isinstance(value, enums.ProfileName):
            self._profile_name = primitives.Enumeration(
                enums.ProfileName,
                value=value,
                tag=enums.Tags.PROFILE_NAME
            )
        else:
            raise TypeError(
                "The profile name must be a ProfileName enumeration."
            )

    @property
    def server_uri(self):
        if self._server_uri:
            return self._server_uri.value
        return None

    @server_uri.setter
    def server_uri(self, value):
        if value is None:
            self._server_uri = None
        elif isinstance(value, str):
            self._server_uri = primitives.TextString(
                value=value,
                tag=enums.Tags.SERVER_URI
            )
        else:
            raise TypeError("The server URI must be a string.")

    @property
    def server_port(self):
        if self._server_port:
            return self._server_port.value
        return None

    @server_port.setter
    def server_port(self, value):
        if value is None:
            self._server_port = None
        elif isinstance(value, int):
            self._server_port = primitives.Integer(
                value=value,
                tag=enums.Tags.SERVER_PORT
            )
        else:
            raise TypeError("The server port must be an integer.")

    def read(self, input_buffer, kmip_version=enums.KMIPVersion.KMIP_1_3):
        """
        Read the data encoding the ProfileInformation structure and decode it
        into its constituent parts.

        Args:
            input_buffer (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 2.0.

        Raises:
            InvalidKmipEncoding: Raised if the profile name is missing from
                the encoding.
            VersionNotSupported: Raised when a KMIP version is provided that
                does not support the ProfileInformation structure.
        """
        if kmip_version < enums.KMIPVersion.KMIP_1_3:
            raise exceptions.VersionNotSupported(
                "KMIP {} does not support the ProfileInformation "
                "object.".format(
                    kmip_version.value
                )
            )

        super(ProfileInformation, self).read(
            input_buffer,
            kmip_version=kmip_version
        )
        local_buffer = utils.BytearrayStream(input_buffer.read(self.length))

        if self.is_tag_next(enums.Tags.PROFILE_NAME, local_buffer):
            profile_name = primitives.Enumeration(
                enums.ProfileName,
                tag=enums.Tags.PROFILE_NAME
            )
            profile_name.read(local_buffer, kmip_version=kmip_version)
            self._profile_name = profile_name
        else:
            raise exceptions.InvalidKmipEncoding(
                "The ProfileInformation encoding is missing the profile name."
            )

        if self.is_tag_next(enums.Tags.SERVER_URI, local_buffer):
            server_uri = primitives.TextString(tag=enums.Tags.SERVER_URI)
            server_uri.read(local_buffer, kmip_version=kmip_version)
            self._server_uri = server_uri

        if self.is_tag_next(enums.Tags.SERVER_PORT, local_buffer):
            server_port = primitives.Integer(tag=enums.Tags.SERVER_PORT)
            server_port.read(local_buffer, kmip_version=kmip_version)
            self._server_port = server_port

        self.is_oversized(local_buffer)

    def write(self, output_buffer, kmip_version=enums.KMIPVersion.KMIP_1_3):
        """
        Write the ProfileInformation structure encoding to the data stream.

        Args:
            output_buffer (stream): A data stream in which to encode
                ProfileInformation structure data, supporting a write method.
            kmip_version (enum): A KMIPVersion enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 2.0.

        Raises:
            InvalidField: Raised if the profile name field is not defined.
            VersionNotSupported: Raised when a KMIP version is provided that
                does not support the ProfileInformation structure.
        """
        if kmip_version < enums.KMIPVersion.KMIP_1_3:
            raise exceptions.VersionNotSupported(
                "KMIP {} does not support the ProfileInformation "
                "object.".format(
                    kmip_version.value
                )
            )

        local_buffer = BytearrayStream()

        if self._profile_name:
            self._profile_name.write(local_buffer, kmip_version=kmip_version)
        else:
            raise exceptions.InvalidField(
                "The ProfileInformation structure is missing the profile "
                "name field."
            )

        if self._server_uri:
            self._server_uri.write(local_buffer, kmip_version=kmip_version)

        if self._server_port:
            self._server_port.write(local_buffer, kmip_version=kmip_version)

        self.length = local_buffer.length()
        super(ProfileInformation, self).write(
            output_buffer,
            kmip_version=kmip_version
        )
        output_buffer.write(local_buffer.buffer)

    def __repr__(self):
        n = "profile_name={}".format(self.profile_name)
        u = 'server_uri="{}"'.format(self.server_uri)
        p = "server_port={}".format(self.server_port)

        v = ", ".join([n, u, p])

        return "ProfileInformation({})".format(v)

    def __str__(self):
        n = '"profile_name": {}'.format(self.profile_name)
        u = '"server_uri": "{}"'.format(self.server_uri)
        p = '"server_port": {}'.format(self.server_port)

        v = ", ".join([n, u, p])

        return '{' + v + '}'

    def __eq__(self, other):
        if isinstance(other, ProfileInformation):
            if self.profile_name != other.profile_name:
                return False
            elif self.server_uri != other.server_uri:
                return False
            elif self.server_port != other.server_port:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, ProfileInformation):
            return not (self == other)
        else:
            return NotImplemented

class ValidationInformation(primitives.Struct):
    """
    A structure containing details of a formal validation.

    This is intended for use with KMIP 1.3+.

    Attributes:
        validation_authority_type: A ValidationAuthorityType enumeration
            identifying the type of the validation authority authorizing
            the validation event.
        validation_authority_country: A string specifying the country of
            the validation authority authorizing the validation event.
        validation_authority_uri: A string specifying a Uniform Resource
            Identifier that points to the validation authority authorizing
            the validation event.
        validation_version_major: An integer identifying the major version
            number of the validation event.
        validation_version_minor: An integer identifying the minor version
            number of the validation event.
        validation_type: A ValidationType enumeration identifying the type
            of validation taking place.
        validation_level: An integer identifying the level of the validation
            taking place.
        validation_certificate_identifier: A string identifying the
            certificate being used for the validation event.
        validation_certificate_uri: A string specifying a Uniform Resource
            Identifier that points to the certificate being used for the
            validation event.
        validation_vendor_uri: A string specifying a Uniform Resource
            Identifier that points to the vendor being used for the validation
            event.
        validation_profiles: A list of string specifying the profiles in
            use or associated with the validation event.
    """

    def __init__(self,
                 validation_authority_type=None,
                 validation_authority_country=None,
                 validation_authority_uri=None,
                 validation_version_major=None,
                 validation_version_minor=None,
                 validation_type=None,
                 validation_level=None,
                 validation_certificate_identifier=None,
                 validation_certificate_uri=None,
                 validation_vendor_uri=None,
                 validation_profiles=None):
        """
        Construct a ValidationInformation structure.

        Args:
            validation_authority_type (enum): A ValidationAuthorityType
                enumeration identifying the type of the validation authority
                authorizing the validation event. Optional, defaults to None.
                Required for read/write.
            validation_authority_country (string): A string specifying the
                country of the validation authority authorizing the validation
                event. Optional, defaults to None.
            validation_authority_uri (string): A string specifying a Uniform
                Resource Identifier that points to the validation authority
                authorizing the validation event. Optional, defaults to None.
            validation_version_major (int): An integer identifying the major
                version number of the validation event. Optional, defaults to
                None. Required for read/write.
            validation_version_minor (int): An integer identifying the minor
                version number of the validation event. Optional, defaults to
                None.
            validation_type (enum): A ValidationType enumeration identifying
                the type of validation taking place. Optional, defaults to
                None. Required for read/write.
            validation_level (int): An integer identifying the level of the
                validation taking place. Optional, defaults to None. Required
                for read/write.
            validation_certificate_identifier (string): A string identifying
                the certificate being used for the validation event. Optional,
                defaults to None.
            validation_certificate_uri (string): A string specifying a Uniform
                Resource Identifier that points to the certificate being used
                for the validation event. Optional, defaults to None.
            validation_vendor_uri (string): A string specifying a Uniform
                Resource Identifier that points to the vendor being used for
                the validation event. Optional, defaults to None.
            validation_profiles (string): A list of string specifying the
                profiles in use or associated with the validation event.
                Optional, defaults to None.
        """
        super(ValidationInformation, self).__init__(
            tag=enums.Tags.VALIDATION_INFORMATION
        )

        self._validation_authority_type = None
        self._validation_authority_country = None
        self._validation_authority_uri = None
        self._validation_version_major = None
        self._validation_version_minor = None
        self._validation_type = None
        self._validation_level = None
        self._validation_certificate_identifier = None
        self._validation_certificate_uri = None
        self._validation_vendor_uri = None
        self._validation_profiles = None

        self.validation_authority_type = validation_authority_type
        self.validation_authority_country = validation_authority_country
        self.validation_authority_uri = validation_authority_uri
        self.validation_version_major = validation_version_major
        self.validation_version_minor = validation_version_minor
        self.validation_type = validation_type
        self.validation_level = validation_level
        self.validation_certificate_identifier = \
            validation_certificate_identifier
        self.validation_certificate_uri = validation_certificate_uri
        self.validation_vendor_uri = validation_vendor_uri
        self.validation_profiles = validation_profiles

    @property
    def validation_authority_type(self):
        if self._validation_authority_type:
            return self._validation_authority_type.value
        return None

    @validation_authority_type.setter
    def validation_authority_type(self, value):
        if value is None:
            self._validation_authority_type = None
        elif isinstance(value, enums.ValidationAuthorityType):
            self._validation_authority_type = primitives.Enumeration(
                enums.ValidationAuthorityType,
                value=value,
                tag=enums.Tags.VALIDATION_AUTHORITY_TYPE
            )
        else:
            raise TypeError(
                "The validation authority type must be a "
                "ValidationAuthorityType enumeration."
            )

    @property
    def validation_authority_country(self):
        if self._validation_authority_country:
            return self._validation_authority_country.value
        return None

    @validation_authority_country.setter
    def validation_authority_country(self, value):
        if value is None:
            self._validation_authority_country = None
        elif isinstance(value, str):
            self._validation_authority_country = primitives.TextString(
                value=value,
                tag=enums.Tags.VALIDATION_AUTHORITY_COUNTRY
            )
        else:
            raise TypeError(
                "The validation authority country must be a string."
            )

    @property
    def validation_authority_uri(self):
        if self._validation_authority_uri:
            return self._validation_authority_uri.value
        return None

    @validation_authority_uri.setter
    def validation_authority_uri(self, value):
        if value is None:
            self._validation_authority_uri = None
        elif isinstance(value, str):
            self._validation_authority_uri = primitives.TextString(
                value=value,
                tag=enums.Tags.VALIDATION_AUTHORITY_URI
            )
        else:
            raise TypeError("The validation authority URI must be a string.")

    @property
    def validation_version_major(self):
        if self._validation_version_major:
            return self._validation_version_major.value
        return None

    @validation_version_major.setter
    def validation_version_major(self, value):
        if value is None:
            self._validation_version_major = None
        elif isinstance(value, int):
            self._validation_version_major = primitives.Integer(
                value=value,
                tag=enums.Tags.VALIDATION_VERSION_MAJOR
            )
        else:
            raise TypeError("The validation version major must be an integer.")

    @property
    def validation_version_minor(self):
        if self._validation_version_minor:
            return self._validation_version_minor.value
        return None

    @validation_version_minor.setter
    def validation_version_minor(self, value):
        if value is None:
            self._validation_version_minor = None
        elif isinstance(value, int):
            self._validation_version_minor = primitives.Integer(
                value=value,
                tag=enums.Tags.VALIDATION_VERSION_MINOR
            )
        else:
            raise TypeError("The validation version minor must be an integer.")

    @property
    def validation_type(self):
        if self._validation_type:
            return self._validation_type.value
        return None

    @validation_type.setter
    def validation_type(self, value):
        if value is None:
            self._validation_type = None
        elif isinstance(value, enums.ValidationType):
            self._validation_type = primitives.Enumeration(
                enums.ValidationType,
                value=value,
                tag=enums.Tags.VALIDATION_TYPE
            )
        else:
            raise TypeError(
                "The validation type must be a ValidationType enumeration."
            )

    @property
    def validation_level(self):
        if self._validation_level:
            return self._validation_level.value
        return None

    @validation_level.setter
    def validation_level(self, value):
        if value is None:
            self._validation_level = None
        elif isinstance(value, int):
            self._validation_level = primitives.Integer(
                value=value,
                tag=enums.Tags.VALIDATION_LEVEL
            )
        else:
            raise TypeError("The validation level must be an integer.")

    @property
    def validation_certificate_identifier(self):
        if self._validation_certificate_identifier:
            return self._validation_certificate_identifier.value
        return None

    @validation_certificate_identifier.setter
    def validation_certificate_identifier(self, value):
        if value is None:
            self._validation_certificate_identifier = None
        elif isinstance(value, str):
            self._validation_certificate_identifier = primitives.TextString(
                value=value,
                tag=enums.Tags.VALIDATION_CERTIFICATE_IDENTIFIER
            )
        else:
            raise TypeError(
                "The validation certificate identifier must be a string."
            )

    @property
    def validation_certificate_uri(self):
        if self._validation_certificate_uri:
            return self._validation_certificate_uri.value
        return None

    @validation_certificate_uri.setter
    def validation_certificate_uri(self, value):
        if value is None:
            self._validation_certificate_uri = None
        elif isinstance(value, str):
            self._validation_certificate_uri = primitives.TextString(
                value=value,
                tag=enums.Tags.VALIDATION_CERTIFICATE_URI
            )
        else:
            raise TypeError("The validation certificate URI must be a string.")

    @property
    def validation_vendor_uri(self):
        if self._validation_vendor_uri:
            return self._validation_vendor_uri.value
        return None

    @validation_vendor_uri.setter
    def validation_vendor_uri(self, value):
        if value is None:
            self._validation_vendor_uri = None
        elif isinstance(value, str):
            self._validation_vendor_uri = primitives.TextString(
                value=value,
                tag=enums.Tags.VALIDATION_VENDOR_URI
            )
        else:
            raise TypeError("The validation vendor URI must be a string.")

    @property
    def validation_profiles(self):
        if self._validation_profiles:
            return [x.value for x in self._validation_profiles]
        return None

    @validation_profiles.setter
    def validation_profiles(self, value):
        if value is None:
            self._validation_profiles = None
        elif isinstance(value, list):
            validation_profiles = []
            for v in value:
                if isinstance(v, str):
                    validation_profiles.append(
                        primitives.TextString(
                            value=v,
                            tag=enums.Tags.VALIDATION_PROFILE
                        )
                    )
                else:
                    raise TypeError(
                        "The validation profiles must be a list of strings."
                    )
            self._validation_profiles = validation_profiles
        else:
            raise TypeError(
                "The validation profiles must be a list of strings."
            )

    def read(self, input_buffer, kmip_version=enums.KMIPVersion.KMIP_1_3):
        """
        Read the data encoding the ValidationInformation structure and decode
        it into its constituent parts.

        Args:
            input_buffer (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 2.0.

        Raises:
            InvalidKmipEncoding: Raised if the validation authority type,
                validation version major, validation type, and/or validation
                level are missing from the encoding.
            VersionNotSupported: Raised when a KMIP version is provided that
                does not support the ValidationInformation structure.
        """
        if kmip_version < enums.KMIPVersion.KMIP_1_3:
            raise exceptions.VersionNotSupported(
                "KMIP {} does not support the ValidationInformation "
                "object.".format(
                    kmip_version.value
                )
            )

        super(ValidationInformation, self).read(
            input_buffer,
            kmip_version=kmip_version
        )
        local_buffer = utils.BytearrayStream(input_buffer.read(self.length))

        if self.is_tag_next(
            enums.Tags.VALIDATION_AUTHORITY_TYPE,
            local_buffer
        ):
            validation_authority_type = primitives.Enumeration(
                enums.ValidationAuthorityType,
                tag=enums.Tags.VALIDATION_AUTHORITY_TYPE
            )
            validation_authority_type.read(
                local_buffer,
                kmip_version=kmip_version
            )
            self._validation_authority_type = validation_authority_type
        else:
            raise exceptions.InvalidKmipEncoding(
                "The ValidationInformation encoding is missing the "
                "validation authority type."
            )

        if self.is_tag_next(
            enums.Tags.VALIDATION_AUTHORITY_COUNTRY,
            local_buffer
        ):
            validation_authority_country = primitives.TextString(
                tag=enums.Tags.VALIDATION_AUTHORITY_COUNTRY
            )
            validation_authority_country.read(
                local_buffer,
                kmip_version=kmip_version
            )
            self._validation_authority_country = validation_authority_country

        if self.is_tag_next(enums.Tags.VALIDATION_AUTHORITY_URI, local_buffer):
            validation_authority_uri = primitives.TextString(
                tag=enums.Tags.VALIDATION_AUTHORITY_URI
                )
            validation_authority_uri.read(
                local_buffer,
                kmip_version=kmip_version
            )
            self._validation_authority_uri = validation_authority_uri

        if self.is_tag_next(
            enums.Tags.VALIDATION_VERSION_MAJOR,
            local_buffer
        ):
            validation_version_major = primitives.Integer(
                tag=enums.Tags.VALIDATION_VERSION_MAJOR
            )
            validation_version_major.read(
                local_buffer,
                kmip_version=kmip_version
            )
            self._validation_version_major = validation_version_major
        else:
            raise exceptions.InvalidKmipEncoding(
                "The ValidationInformation encoding is missing the "
                "validation version major."
            )

        if self.is_tag_next(
            enums.Tags.VALIDATION_VERSION_MINOR,
            local_buffer
        ):
            validation_version_minor = primitives.Integer(
                tag=enums.Tags.VALIDATION_VERSION_MINOR
            )
            validation_version_minor.read(
                local_buffer,
                kmip_version=kmip_version
            )
            self._validation_version_minor = validation_version_minor

        if self.is_tag_next(enums.Tags.VALIDATION_TYPE, local_buffer):
            validation_type = primitives.Enumeration(
                enums.ValidationType,
                tag=enums.Tags.VALIDATION_TYPE
            )
            validation_type.read(
                local_buffer,
                kmip_version=kmip_version
            )
            self._validation_type = validation_type
        else:
            raise exceptions.InvalidKmipEncoding(
                "The ValidationInformation encoding is missing the "
                "validation type."
            )

        if self.is_tag_next(enums.Tags.VALIDATION_LEVEL, local_buffer):
            validation_level = primitives.Integer(
                tag=enums.Tags.VALIDATION_LEVEL
            )
            validation_level.read(local_buffer, kmip_version=kmip_version)
            self._validation_level = validation_level
        else:
            raise exceptions.InvalidKmipEncoding(
                "The ValidationInformation encoding is missing the "
                "validation level."
            )

        if self.is_tag_next(
            enums.Tags.VALIDATION_CERTIFICATE_IDENTIFIER,
            local_buffer
        ):
            validation_certificate_identifier = primitives.TextString(
                tag=enums.Tags.VALIDATION_CERTIFICATE_IDENTIFIER
            )
            validation_certificate_identifier.read(
                local_buffer,
                kmip_version=kmip_version
            )
            self._validation_certificate_identifier = \
                validation_certificate_identifier

        if self.is_tag_next(
            enums.Tags.VALIDATION_CERTIFICATE_URI,
            local_buffer
        ):
            validation_certificate_uri = primitives.TextString(
                tag=enums.Tags.VALIDATION_CERTIFICATE_URI
            )
            validation_certificate_uri.read(
                local_buffer,
                kmip_version=kmip_version
            )
            self._validation_certificate_uri = validation_certificate_uri

        if self.is_tag_next(enums.Tags.VALIDATION_VENDOR_URI, local_buffer):
            validation_vendor_uri = primitives.TextString(
                tag=enums.Tags.VALIDATION_VENDOR_URI
            )
            validation_vendor_uri.read(local_buffer, kmip_version=kmip_version)
            self._validation_vendor_uri = validation_vendor_uri

        validation_profiles = []
        while self.is_tag_next(enums.Tags.VALIDATION_PROFILE, local_buffer):
            validation_profile = primitives.TextString(
                tag=enums.Tags.VALIDATION_PROFILE
            )
            validation_profile.read(local_buffer, kmip_version=kmip_version)
            validation_profiles.append(validation_profile)
        self._validation_profiles = validation_profiles

        self.is_oversized(local_buffer)

    def write(self, output_buffer, kmip_version=enums.KMIPVersion.KMIP_1_3):
        """
        Write the ValidationInformation structure encoding to the data stream.

        Args:
            output_buffer (stream): A data stream in which to encode
                ValidationInformation structure data, supporting a write
                method.
            kmip_version (enum): A KMIPVersion enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 2.0.

        Raises:
            InvalidField: Raised if the validation authority type, validation
                version major, validation type, and/or validation level fields
                are not defined.
            VersionNotSupported: Raised when a KMIP version is provided that
                does not support the ValidationInformation structure.
        """
        if kmip_version < enums.KMIPVersion.KMIP_1_3:
            raise exceptions.VersionNotSupported(
                "KMIP {} does not support the ValidationInformation "
                "object.".format(
                    kmip_version.value
                )
            )

        local_buffer = BytearrayStream()

        if self._validation_authority_type:
            self._validation_authority_type.write(
                local_buffer,
                kmip_version=kmip_version
            )
        else:
            raise exceptions.InvalidField(
                "The ValidationInformation structure is missing the "
                "validation authority type field."
            )

        if self._validation_authority_country:
            self._validation_authority_country.write(
                local_buffer,
                kmip_version=kmip_version
            )

        if self._validation_authority_uri:
            self._validation_authority_uri.write(
                local_buffer,
                kmip_version=kmip_version
            )

        if self._validation_version_major:
            self._validation_version_major.write(
                local_buffer,
                kmip_version=kmip_version
            )
        else:
            raise exceptions.InvalidField(
                "The ValidationInformation structure is missing the "
                "validation version major field."
            )

        if self._validation_version_minor:
            self._validation_version_minor.write(
                local_buffer,
                kmip_version=kmip_version
            )

        if self._validation_type:
            self._validation_type.write(
                local_buffer,
                kmip_version=kmip_version
            )
        else:
            raise exceptions.InvalidField(
                "The ValidationInformation structure is missing the "
                "validation type field."
            )

        if self._validation_level:
            self._validation_level.write(
                local_buffer,
                kmip_version=kmip_version
            )
        else:
            raise exceptions.InvalidField(
                "The ValidationInformation structure is missing the "
                "validation level field."
            )

        if self._validation_certificate_identifier:
            self._validation_certificate_identifier.write(
                local_buffer,
                kmip_version=kmip_version
            )

        if self._validation_certificate_uri:
            self._validation_certificate_uri.write(
                local_buffer,
                kmip_version=kmip_version
            )

        if self._validation_vendor_uri:
            self._validation_vendor_uri.write(
                local_buffer,
                kmip_version=kmip_version
            )

        if self._validation_profiles:
            for validation_profile in self._validation_profiles:
                validation_profile.write(
                    local_buffer,
                    kmip_version=kmip_version
                )

        self.length = local_buffer.length()
        super(ValidationInformation, self).write(
            output_buffer,
            kmip_version=kmip_version
        )
        output_buffer.write(local_buffer.buffer)

    def __repr__(self):
        vat = "validation_authority_type={}".format(
            self.validation_authority_type
        )
        vac = 'validation_authority_country="{}"'.format(
            self.validation_authority_country
        )
        vau = 'validation_authority_uri="{}"'.format(
            self.validation_authority_uri
        )
        vvj = "validation_version_major={}".format(
            self.validation_version_major
        )
        vvn = "validation_version_minor={}".format(
            self.validation_version_minor
        )
        vt = "validation_type={}".format(self.validation_type)
        vl = "validation_level={}".format(self.validation_level)
        vci = 'validation_certificate_identifier="{}"'.format(
            self.validation_certificate_identifier
        )
        vcu = 'validation_certificate_uri="{}"'.format(
            self.validation_certificate_uri
        )
        vvu = 'validation_vendor_uri="{}"'.format(
            self.validation_vendor_uri
        )
        vp = 'validation_profiles={}'.format(
            '[{}]'.format(
                ", ".join(['"{}"'.format(x) for x in self.validation_profiles])
            ) if self.validation_profiles else None
        )

        v = ", ".join([vat, vac, vau, vvj, vvn, vt, vl, vci, vcu, vvu, vp])

        return "ValidationInformation({})".format(v)

    def __str__(self):
        vat = '"validation_authority_type": {}'.format(
            self.validation_authority_type
        )
        vac = '"validation_authority_country": "{}"'.format(
            self.validation_authority_country
        )
        vau = '"validation_authority_uri": "{}"'.format(
            self.validation_authority_uri
        )
        vvj = '"validation_version_major": {}'.format(
            self.validation_version_major
        )
        vvn = '"validation_version_minor": {}'.format(
            self.validation_version_minor
        )
        vt = '"validation_type": {}'.format(self.validation_type)
        vl = '"validation_level": {}'.format(self.validation_level)
        vci = '"validation_certificate_identifier": "{}"'.format(
            self.validation_certificate_identifier
        )
        vcu = '"validation_certificate_uri": "{}"'.format(
            self.validation_certificate_uri
        )
        vvu = '"validation_vendor_uri": "{}"'.format(
            self.validation_vendor_uri
        )
        vp = '"validation_profiles": {}'.format(
            '[{}]'.format(
                ', '.join(
                    ['"{}"'.format(x) for x in self.validation_profiles]
                )
            ) if self.validation_profiles else None
        )

        v = ", ".join([vat, vac, vau, vvj, vvn, vt, vl, vci, vcu, vvu, vp])

        return '{' + v + '}'

    def __eq__(self, other):
        if isinstance(other, ValidationInformation):
            if self.validation_authority_type != \
                    other.validation_authority_type:
                return False
            elif self.validation_authority_country != \
                    other.validation_authority_country:
                return False
            elif self.validation_authority_uri != \
                    other.validation_authority_uri:
                return False
            elif self.validation_version_major != \
                    other.validation_version_major:
                return False
            elif self.validation_version_minor != \
                    other.validation_version_minor:
                return False
            elif self.validation_type != other.validation_type:
                return False
            elif self.validation_level != other.validation_level:
                return False
            elif self.validation_certificate_identifier != \
                    other.validation_certificate_identifier:
                return False
            elif self.validation_certificate_uri != \
                    other.validation_certificate_uri:
                return False
            elif self.validation_vendor_uri != other.validation_vendor_uri:
                return False
            elif self.validation_profiles != other.validation_profiles:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, ValidationInformation):
            return not (self == other)
        else:
            return NotImplemented

class CapabilityInformation(primitives.Struct):
    """
    A structure containing details of supported server capabilities.

    This is intended for use with KMIP 1.3+.

    Attributes:
        streaming_capability: A boolean flag indicating whether or not
            the server supports streaming data.
        asynchronous_capability: A boolean flag indicating whether or not
            the server supports asynchronous operations.
        attestation_capability: A boolean flag indicating whether or not
            the server supports attestation.
        batch_undo_capability: A boolean flag indicating whether or not
            the server supports batch undo. Added in KMIP 1.4.
        batch_continue_capability: A boolean flag indicating whether or not
            the server supports batch continue. Added in KMIP 1.4.
        unwrap_mode: An UnwrapMode enumeration identifying the unwrap mode
            supported by the server.
        destroy_action: A DestroyAction enumeration identifying the destroy
            action supported by the server.
        shredding_algorithm: A ShreddingAlgorithm enumeration identifying
            the shredding algorithm supported by the server.
        rng_mode: An RNGMode enumeration identifying the RNG mode supported
            by the server.
    """

    def __init__(self,
                 streaming_capability=None,
                 asynchronous_capability=None,
                 attestation_capability=None,
                 batch_undo_capability=None,
                 batch_continue_capability=None,
                 unwrap_mode=None,
                 destroy_action=None,
                 shredding_algorithm=None,
                 rng_mode=None):
        """
        Construct a CapabilityInformation structure.

        Args:
            streaming_capability (bool): A boolean flag indicating whether or
                not the server supports streaming data. Optional, defaults to
                None.
            asynchronous_capability (bool): A boolean flag indicating whether
                or not the server supports asynchronous operations. Optional,
                defaults to None.
            attestation_capability (bool): A boolean flag indicating whether
                or not the server supports attestation. Optional, defaults to
                None.
            batch_undo_capability (bool): A boolean flag indicating whether or
                not the server supports batch undo. Added in KMIP 1.4.
                Optional, defaults to None.
            batch_continue_capability (bool): A boolean flag indicating whether
                or not the server supports batch continue. Added in KMIP 1.4.
                Optional, defaults to None.
            unwrap_mode (enum): An UnwrapMode enumeration identifying the
                unwrap mode supported by the server. Optional, defaults to
                None.
            destroy_action (enum): A DestroyAction enumeration identifying the
                destroy action supported by the server. Optional, defaults to
                None.
            shredding_algorithm (enum): A ShreddingAlgorithm enumeration
                identifying the shredding algorithm supported by the server.
                Optional, defaults to None.
            rng_mode (enum): An RNGMode enumeration identifying the RNG mode
                supported by the server. Optional, defaults to None.
        """
        super(CapabilityInformation, self).__init__(
            tag=enums.Tags.CAPABILITY_INFORMATION
        )

        self._streaming_capability = None
        self._asynchronous_capability = None
        self._attestation_capability = None
        self._batch_undo_capability = None
        self._batch_continue_capability = None
        self._unwrap_mode = None
        self._destroy_action = None
        self._shredding_algorithm = None
        self._rng_mode = None

        self.streaming_capability = streaming_capability
        self.asynchronous_capability = asynchronous_capability
        self.attestation_capability = attestation_capability
        self.batch_undo_capability = batch_undo_capability
        self.batch_continue_capability = batch_continue_capability
        self.unwrap_mode = unwrap_mode
        self.destroy_action = destroy_action
        self.shredding_algorithm = shredding_algorithm
        self.rng_mode = rng_mode

    @property
    def streaming_capability(self):
        if self._streaming_capability:
            return self._streaming_capability.value
        return None

    @streaming_capability.setter
    def streaming_capability(self, value):
        if value is None:
            self._streaming_capability = None
        elif isinstance(value, bool):
            self._streaming_capability = primitives.Boolean(
                value=value,
                tag=enums.Tags.STREAMING_CAPABILITY
            )
        else:
            raise TypeError("The streaming capability must be a boolean.")

    @property
    def asynchronous_capability(self):
        if self._asynchronous_capability:
            return self._asynchronous_capability.value
        return None

    @asynchronous_capability.setter
    def asynchronous_capability(self, value):
        if value is None:
            self._asynchronous_capability = None
        elif isinstance(value, bool):
            self._asynchronous_capability = primitives.Boolean(
                value=value,
                tag=enums.Tags.ASYNCHRONOUS_CAPABILITY
            )
        else:
            raise TypeError(
                "The asynchronous capability must be a boolean."
            )

    @property
    def attestation_capability(self):
        if self._attestation_capability:
            return self._attestation_capability.value
        return None

    @attestation_capability.setter
    def attestation_capability(self, value):
        if value is None:
            self._attestation_capability = None
        elif isinstance(value, bool):
            self._attestation_capability = primitives.Boolean(
                value=value,
                tag=enums.Tags.ATTESTATION_CAPABILITY
            )
        else:
            raise TypeError("The attestation capability must be a boolean.")

    @property
    def batch_undo_capability(self):
        if self._batch_undo_capability:
            return self._batch_undo_capability.value
        return None

    @batch_undo_capability.setter
    def batch_undo_capability(self, value):
        if value is None:
            self._batch_undo_capability = None
        elif isinstance(value, bool):
            self._batch_undo_capability = primitives.Boolean(
                value=value,
                tag=enums.Tags.BATCH_UNDO_CAPABILITY
            )
        else:
            raise TypeError("The batch undo capability must be a boolean.")

    @property
    def batch_continue_capability(self):
        if self._batch_continue_capability:
            return self._batch_continue_capability.value
        return None

    @batch_continue_capability.setter
    def batch_continue_capability(self, value):
        if value is None:
            self._batch_continue_capability = None
        elif isinstance(value, bool):
            self._batch_continue_capability = primitives.Boolean(
                value=value,
                tag=enums.Tags.BATCH_CONTINUE_CAPABILITY
            )
        else:
            raise TypeError(
                "The batch continue capability must be a boolean."
            )

    @property
    def unwrap_mode(self):
        if self._unwrap_mode:
            return self._unwrap_mode.value
        return None

    @unwrap_mode.setter
    def unwrap_mode(self, value):
        if value is None:
            self._unwrap_mode = None
        elif isinstance(value, enums.UnwrapMode):
            self._unwrap_mode = primitives.Enumeration(
                enums.UnwrapMode,
                value=value,
                tag=enums.Tags.UNWRAP_MODE
            )
        else:
            raise TypeError(
                "The unwrap mode must be an UnwrapMode enumeration."
            )

    @property
    def destroy_action(self):
        if self._destroy_action:
            return self._destroy_action.value
        return None

    @destroy_action.setter
    def destroy_action(self, value):
        if value is None:
            self._destroy_action = None
        elif isinstance(value, enums.DestroyAction):
            self._destroy_action = primitives.Enumeration(
                enums.DestroyAction,
                value=value,
                tag=enums.Tags.DESTROY_ACTION
            )
        else:
            raise TypeError(
                "The destroy action must be a DestroyAction enumeration."
            )

    @property
    def shredding_algorithm(self):
        if self._shredding_algorithm:
            return self._shredding_algorithm.value
        return None

    @shredding_algorithm.setter
    def shredding_algorithm(self, value):
        if value is None:
            self._shredding_algorithm = None
        elif isinstance(value, enums.ShreddingAlgorithm):
            self._shredding_algorithm = primitives.Enumeration(
                enums.ShreddingAlgorithm,
                value=value,
                tag=enums.Tags.SHREDDING_ALGORITHM
            )
        else:
            raise TypeError(
                "The shredding algorithm must be a ShreddingAlgorithm "
                "enumeration."
            )

    @property
    def rng_mode(self):
        if self._rng_mode:
            return self._rng_mode.value
        return None

    @rng_mode.setter
    def rng_mode(self, value):
        if value is None:
            self._rng_mode = None
        elif isinstance(value, enums.RNGMode):
            self._rng_mode = primitives.Enumeration(
                enums.RNGMode,
                value=value,
                tag=enums.Tags.RNG_MODE
            )
        else:
            raise TypeError("The RNG mode must be an RNGMode enumeration.")

    def read(self, input_buffer, kmip_version=enums.KMIPVersion.KMIP_1_3):
        """
        Read the data encoding the CapabilityInformation structure and decode
        it into its constituent parts.

        Args:
            input_buffer (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 2.0.

        Raises:
            VersionNotSupported: Raised when a KMIP version is provided that
                does not support the CapabilityInformation structure.
        """
        if kmip_version < enums.KMIPVersion.KMIP_1_3:
            raise exceptions.VersionNotSupported(
                "KMIP {} does not support the CapabilityInformation "
                "object.".format(
                    kmip_version.value
                )
            )

        super(CapabilityInformation, self).read(
            input_buffer,
            kmip_version=kmip_version
        )
        local_buffer = utils.BytearrayStream(input_buffer.read(self.length))

        if self.is_tag_next(enums.Tags.STREAMING_CAPABILITY, local_buffer):
            streaming_capability = primitives.Boolean(
                tag=enums.Tags.STREAMING_CAPABILITY
            )
            streaming_capability.read(local_buffer, kmip_version=kmip_version)
            self._streaming_capability = streaming_capability

        if self.is_tag_next(enums.Tags.ASYNCHRONOUS_CAPABILITY, local_buffer):
            asynchronous_capability = primitives.Boolean(
                tag=enums.Tags.ASYNCHRONOUS_CAPABILITY
            )
            asynchronous_capability.read(
                local_buffer,
                kmip_version=kmip_version
            )
            self._asynchronous_capability = asynchronous_capability

        if self.is_tag_next(enums.Tags.ATTESTATION_CAPABILITY, local_buffer):
            attestation_capability = primitives.Boolean(
                tag=enums.Tags.ATTESTATION_CAPABILITY
            )
            attestation_capability.read(
                local_buffer,
                kmip_version=kmip_version
            )
            self._attestation_capability = attestation_capability

        if kmip_version >= enums.KMIPVersion.KMIP_1_4:
            if self.is_tag_next(
                enums.Tags.BATCH_UNDO_CAPABILITY,
                local_buffer
            ):
                batch_undo_capability = primitives.Boolean(
                    tag=enums.Tags.BATCH_UNDO_CAPABILITY
                )
                batch_undo_capability.read(
                    local_buffer,
                    kmip_version=kmip_version
                )
                self._batch_continue_capability = batch_undo_capability

            if self.is_tag_next(
                enums.Tags.BATCH_CONTINUE_CAPABILITY,
                local_buffer
            ):
                batch_continue_capability = primitives.Boolean(
                    tag=enums.Tags.BATCH_CONTINUE_CAPABILITY
                )
                batch_continue_capability.read(
                    local_buffer,
                    kmip_version=kmip_version
                )
                self._batch_continue_capability = batch_continue_capability

        if self.is_tag_next(enums.Tags.UNWRAP_MODE, local_buffer):
            unwrap_mode = primitives.Enumeration(
                enums.UnwrapMode,
                tag=enums.Tags.UNWRAP_MODE
            )
            unwrap_mode.read(local_buffer, kmip_version=kmip_version)
            self._unwrap_mode = unwrap_mode

        if self.is_tag_next(enums.Tags.DESTROY_ACTION, local_buffer):
            destroy_action = primitives.Enumeration(
                enums.DestroyAction,
                tag=enums.Tags.DESTROY_ACTION
            )
            destroy_action.read(local_buffer, kmip_version=kmip_version)
            self._destroy_action = destroy_action

        if self.is_tag_next(enums.Tags.SHREDDING_ALGORITHM, local_buffer):
            shredding_algorithm = primitives.Enumeration(
                enums.ShreddingAlgorithm,
                tag=enums.Tags.SHREDDING_ALGORITHM
            )
            shredding_algorithm.read(local_buffer, kmip_version=kmip_version)
            self._shredding_algorithm = shredding_algorithm

        if self.is_tag_next(enums.Tags.RNG_MODE, local_buffer):
            rng_mode = primitives.Enumeration(
                enums.RNGMode,
                tag=enums.Tags.RNG_MODE
            )
            rng_mode.read(local_buffer, kmip_version=kmip_version)
            self._rng_mode = rng_mode

        self.is_oversized(local_buffer)

    def write(self, output_buffer, kmip_version=enums.KMIPVersion.KMIP_1_3):
        """
        Write the CapabilityInformation structure encoding to the data stream.

        Args:
            output_buffer (stream): A data stream in which to encode
                CapabilityInformation structure data, supporting a write
                method.
            kmip_version (enum): A KMIPVersion enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 2.0.

        Raises:
            VersionNotSupported: Raised when a KMIP version is provided that
                does not support the CapabilityInformation structure.
        """
        if kmip_version < enums.KMIPVersion.KMIP_1_3:
            raise exceptions.VersionNotSupported(
                "KMIP {} does not support the CapabilityInformation "
                "object.".format(
                    kmip_version.value
                )
            )

        local_buffer = BytearrayStream()

        if self._streaming_capability:
            self._streaming_capability.write(
                local_buffer,
                kmip_version=kmip_version
            )

        if self._asynchronous_capability:
            self._asynchronous_capability.write(
                local_buffer,
                kmip_version=kmip_version
            )

        if self._attestation_capability:
            self._attestation_capability.write(
                local_buffer,
                kmip_version=kmip_version
            )

        if kmip_version >= enums.KMIPVersion.KMIP_1_4:
            if self._batch_undo_capability:
                self._batch_undo_capability.write(
                    local_buffer,
                    kmip_version=kmip_version
                )

            if self._batch_continue_capability:
                self._batch_continue_capability.write(
                    local_buffer,
                    kmip_version=kmip_version
                )

        if self._unwrap_mode:
            self._unwrap_mode.write(
                local_buffer,
                kmip_version=kmip_version
            )

        if self._destroy_action:
            self._destroy_action.write(
                local_buffer,
                kmip_version=kmip_version
            )

        if self._shredding_algorithm:
            self._shredding_algorithm.write(
                local_buffer,
                kmip_version=kmip_version
            )

        if self._rng_mode:
            self._rng_mode.write(
                local_buffer,
                kmip_version=kmip_version
            )

        self.length = local_buffer.length()
        super(CapabilityInformation, self).write(
            output_buffer,
            kmip_version=kmip_version
        )
        output_buffer.write(local_buffer.buffer)

    def __repr__(self):
        sc = "streaming_capability={}".format(self.streaming_capability)
        rc = "asynchronous_capability={}".format(self.asynchronous_capability)
        tc = "attestation_capability={}".format(self.attestation_capability)
        buc = "batch_undo_capability={}".format(self.batch_undo_capability)
        bcc = "batch_continue_capability={}".format(
            self.batch_continue_capability
        )
        um = "unwrap_mode={}".format(self.unwrap_mode)
        da = "destroy_action={}".format(self.destroy_action)
        sa = "shredding_algorithm={}".format(self.shredding_algorithm)
        rm = "rng_mode={}".format(self.rng_mode)

        v = ", ".join([sc, rc, tc, buc, bcc, um, da, sa, rm])

        return "CapabilityInformation({})".format(v)

    def __str__(self):
        sc = '"streaming_capability": {}'.format(self.streaming_capability)
        rc = '"asynchronous_capability": {}'.format(
            self.asynchronous_capability
        )
        tc = '"attestation_capability": {}'.format(
            self.attestation_capability
        )
        buc = '"batch_undo_capability": {}'.format(self.batch_undo_capability)
        bcc = '"batch_continue_capability": {}'.format(
            self.batch_continue_capability
        )
        um = '"unwrap_mode": {}'.format(self.unwrap_mode)
        da = '"destroy_action": {}'.format(self.destroy_action)
        sa = '"shredding_algorithm": {}'.format(self.shredding_algorithm)
        rm = '"rng_mode": {}'.format(self.rng_mode)

        v = ", ".join([sc, rc, tc, buc, bcc, um, da, sa, rm])

        return '{' + v + '}'

    def __eq__(self, other):
        if isinstance(other, CapabilityInformation):
            if self.streaming_capability != other.streaming_capability:
                return False
            elif self.asynchronous_capability != other.asynchronous_capability:
                return False
            elif self.attestation_capability != other.attestation_capability:
                return False
            elif self.batch_undo_capability != other.batch_undo_capability:
                return False
            elif self.batch_continue_capability != \
                    other.batch_continue_capability:
                return False
            elif self.unwrap_mode != other.unwrap_mode:
                return False
            elif self.destroy_action != other.destroy_action:
                return False
            elif self.shredding_algorithm != other.shredding_algorithm:
                return False
            elif self.rng_mode != other.rng_mode:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, CapabilityInformation):
            return not (self == other)
        else:
            return NotImplemented

class ProtectionStorageMasks(primitives.Struct):
    """
    A structure containing a list of protection storage masks.

    This is intended for use with KMIP 2.0+.

    Attributes:
        protection_storage_masks: A list of integers representing
            combined sets of ProtectionStorageMask enumerations detailing
            the storage protections supported by the server.
    """

    def __init__(self,
                 protection_storage_masks=None,
                 tag=enums.Tags.PROTECTION_STORAGE_MASKS):
        """
        Construct a ProtectionStorageMasks structure.

        Args:
            protection_storage_masks (list): A list of integers representing
                combined sets of ProtectionStorageMask enumerations detailing
                the storage protections supported by the server. Optional,
                defaults to None.
            tag (enum): A Tags enumeration specifying which type of collection
                this of protection storage masks this object represents.
                Optional, defaults to Tags.PROTECTION_STORAGE_MASKS.
        """
        super(ProtectionStorageMasks, self).__init__(tag=tag)

        self._protection_storage_masks = None

        self.protection_storage_masks = protection_storage_masks

    @property
    def protection_storage_masks(self):
        if self._protection_storage_masks:
            return [x.value for x in self._protection_storage_masks]
        return None

    @protection_storage_masks.setter
    def protection_storage_masks(self, value):
        if value is None:
            self._protection_storage_masks = None
        elif isinstance(value, list):
            protection_storage_masks = []
            for x in value:
                if isinstance(x, int):
                    if enums.is_bit_mask(enums.ProtectionStorageMask, x):
                        protection_storage_masks.append(
                            primitives.Integer(
                                value=x,
                                tag=enums.Tags.PROTECTION_STORAGE_MASK
                            )
                        )
                    else:
                        raise TypeError(
                            "The protection storage masks must be a list of "
                            "integers representing combinations of "
                            "ProtectionStorageMask enumerations."
                        )
                else:
                    raise TypeError(
                        "The protection storage masks must be a list of "
                        "integers representing combinations of "
                        "ProtectionStorageMask enumerations."
                    )
            self._protection_storage_masks = protection_storage_masks
        else:
            raise TypeError(
                "The protection storage masks must be a list of "
                "integers representing combinations of "
                "ProtectionStorageMask enumerations."
            )

    def read(self, input_buffer, kmip_version=enums.KMIPVersion.KMIP_2_0):
        """
        Read the data encoding the ProtectionStorageMasks structure and decode
        it into its constituent parts.

        Args:
            input_buffer (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 2.0.

        Raises:
            VersionNotSupported: Raised when a KMIP version is provided that
                does not support the ProtectionStorageMasks structure.
        """
        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            raise exceptions.VersionNotSupported(
                "KMIP {} does not support the ProtectionStorageMasks "
                "object.".format(
                    kmip_version.value
                )
            )

        super(ProtectionStorageMasks, self).read(
            input_buffer,
            kmip_version=kmip_version
        )
        local_buffer = utils.BytearrayStream(input_buffer.read(self.length))

        protection_storage_masks = []
        while self.is_tag_next(
            enums.Tags.PROTECTION_STORAGE_MASK,
            local_buffer
        ):
            protection_storage_mask = primitives.Integer(
                tag=enums.Tags.PROTECTION_STORAGE_MASK
            )
            protection_storage_mask.read(
                local_buffer,
                kmip_version=kmip_version
            )
            protection_storage_masks.append(protection_storage_mask)
        self._protection_storage_masks = protection_storage_masks

        self.is_oversized(local_buffer)

    def write(self, output_buffer, kmip_version=enums.KMIPVersion.KMIP_2_0):
        """
        Write the ProtectionStorageMasks structure encoding to the data stream.

        Args:
            output_buffer (stream): A data stream in which to encode
                CapabilityInformation structure data, supporting a write
                method.
            kmip_version (enum): A KMIPVersion enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 2.0.

        Raises:
            VersionNotSupported: Raised when a KMIP version is provided that
                does not support the ProtectionStorageMasks structure.
        """
        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            raise exceptions.VersionNotSupported(
                "KMIP {} does not support the ProtectionStorageMasks "
                "object.".format(
                    kmip_version.value
                )
            )

        local_buffer = BytearrayStream()

        if self._protection_storage_masks:
            for protection_storage_mask in self._protection_storage_masks:
                protection_storage_mask.write(
                    local_buffer,
                    kmip_version=kmip_version
                )

        self.length = local_buffer.length()
        super(ProtectionStorageMasks, self).write(
            output_buffer,
            kmip_version=kmip_version
        )
        output_buffer.write(local_buffer.buffer)

    def __repr__(self):
        v = "protection_storage_masks={}".format(
            "[{}]".format(
                ", ".join(str(x) for x in self.protection_storage_masks)
            ) if self._protection_storage_masks else None
        )

        return "ProtectionStorageMasks({})".format(v)

    def __str__(self):
        v = '"protection_storage_masks": {}'.format(
            "[{}]".format(
                ", ".join(str(x) for x in self.protection_storage_masks)
            ) if self._protection_storage_masks else None
        )

        return '{' + v + '}'

    def __eq__(self, other):
        if isinstance(other, ProtectionStorageMasks):
            if self.protection_storage_masks != other.protection_storage_masks:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, ProtectionStorageMasks):
            return not (self == other)
        else:
            return NotImplemented
