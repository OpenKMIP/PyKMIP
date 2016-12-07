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

import six

from kmip.core import enums
from kmip.core import exceptions
from kmip.core import objects
from kmip.core import primitives
from kmip.core import utils


class GetAttributesRequestPayload(primitives.Struct):
    """
    A request payload for the GetAttributes operation.

    The payload contains the ID of the managed object the attributes should
    belong to, along with a list of attribute names for the attributes that
    should be returned in the response. If the ID is omitted, the server will
    use the ID placeholder by default. If the list of attribute names is
    omitted, all object attributes will be returned. There should be no
    duplicates in the attribute name list.

    Attributes:
        unique_identifier: The unique ID of the managed object with which the
            retrieved attributes should be associated.
        attribute_names: A list of strings identifying the names of the
            attributes associated with the managed object.
    """
    def __init__(self, unique_identifier=None, attribute_names=None):
        """
        Construct a GetAttributes request payload.

        Args:
            unique_identifier (string): The ID of the managed object with
                which the retrieved attributes should be associated. Optional,
                defaults to None.
            attribute_names: A list of strings identifying the names of the
                attributes associated with the managed object. Optional,
                defaults to None.
        """
        super(GetAttributesRequestPayload, self).__init__(
            enums.Tags.REQUEST_PAYLOAD)

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
        elif isinstance(value, six.string_types):
            self._unique_identifier = primitives.TextString(
                value=value,
                tag=enums.Tags.UNIQUE_IDENTIFIER
            )
        else:
            raise TypeError("unique identifier must be a string")

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
                if not isinstance(name, six.string_types):
                    raise TypeError(
                        "attribute_names must be a list of strings; "
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
            raise TypeError("attribute_names must be a list of strings")

    def read(self, istream):
        """
        Read the data encoding the GetAttributes request payload and decode
        it into its constituent parts.

        Args:
            istream (stream): A data stream containing encoded object data,
                supporting a read method; usually a BytearrayStream object.
        """
        super(GetAttributesRequestPayload, self).read(istream)
        tstream = utils.BytearrayStream(istream.read(self.length))

        if self.is_tag_next(enums.Tags.UNIQUE_IDENTIFIER, tstream):
            self._unique_identifier = primitives.TextString(
                tag=enums.Tags.UNIQUE_IDENTIFIER
            )
            self._unique_identifier.read(tstream)
        else:
            self._unique_identifier = None

        names = list()
        while self.is_tag_next(enums.Tags.ATTRIBUTE_NAME, tstream):
            name = primitives.TextString(tag=enums.Tags.ATTRIBUTE_NAME)
            name.read(tstream)
            names.append(name)
        self._attribute_names = names

        self.is_oversized(tstream)

    def write(self, ostream):
        """
        Write the data encoding the GetAttributes request payload to a
        stream.

        Args:
            ostream (stream): A data stream in which to encode object data,
                supporting a write method; usually a BytearrayStream object.
        """
        tstream = utils.BytearrayStream()

        if self._unique_identifier:
            self._unique_identifier.write(tstream)

        for attribute_name in self._attribute_names:
            attribute_name.write(tstream)

        self.length = tstream.length()
        super(GetAttributesRequestPayload, self).write(ostream)
        ostream.write(tstream.buffer)

    def __repr__(self):
        unique_identifier = "unique_identifier={0}".format(
            self.unique_identifier
        )
        attribute_names = "attribute_names={0}".format(self.attribute_names)
        return "GetAttributesRequestPayload({0}, {1})".format(
            unique_identifier,
            attribute_names
        )

    def __str__(self):
        return str({
            'unique_identifier': self.unique_identifier,
            'attribute_names': self.attribute_names
        })

    def __eq__(self, other):
        if isinstance(other, GetAttributesRequestPayload):
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
        if isinstance(other, GetAttributesRequestPayload):
            return not self.__eq__(other)
        else:
            return NotImplemented


class GetAttributesResponsePayload(primitives.Struct):
    """
    A response payload for the GetAttributes operation.

    The payload will contain the ID of the managed object with which the
    attributes are associated. It will also contain a list of attributes
    associated with the aforementioned managed object.

    Attributes:
        unique_identifier: The unique ID of the managed object with which
            the retrieved attributes should be associated.
        attributes: The list of attributes associated with managed object
            identified by the unique identifier above.
    """
    def __init__(self, unique_identifier=None, attributes=None):
        """
        Construct a GetAttributes response payload.

        Args:
            unique_identifier (string): The ID of the managed object with
                which the retrieved attributes should be associated. Optional,
                defaults to None.
            attributes (list): A list of attribute structures associated with
                the managed object. Optional, defaults to None.
        """
        super(GetAttributesResponsePayload, self).__init__(
            enums.Tags.RESPONSE_PAYLOAD)

        self._unique_identifier = None
        self._attributes = list()

        self.unique_identifier = unique_identifier
        self.attributes = attributes

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
        elif isinstance(value, six.string_types):
            self._unique_identifier = primitives.TextString(
                value=value,
                tag=enums.Tags.UNIQUE_IDENTIFIER
            )
        else:
            raise TypeError("unique identifier must be a string")

    @property
    def attributes(self):
        return self._attributes

    @attributes.setter
    def attributes(self, value):
        if value is None:
            self._attributes = list()
        elif isinstance(value, list):
            for i in range(len(value)):
                attribute = value[i]
                if not isinstance(attribute, objects.Attribute):
                    raise TypeError(
                        "attributes must be a list of attribute objects; "
                        "item {0} has type {1}".format(i + 1, type(attribute))
                    )
            self._attributes = value
        else:
            raise TypeError("attributes must be a list of attribute objects")

    def read(self, istream):
        """
        Read the data encoding the GetAttributes response payload and decode
        it into its constituent parts.

        Args:
            istream (stream): A data stream containing encoded object data,
                supporting a read method; usually a BytearrayStream object.
        """
        super(GetAttributesResponsePayload, self).read(istream)
        tstream = utils.BytearrayStream(istream.read(self.length))

        if self.is_tag_next(enums.Tags.UNIQUE_IDENTIFIER, tstream):
            unique_identifier = primitives.TextString(
                tag=enums.Tags.UNIQUE_IDENTIFIER
            )
            unique_identifier.read(tstream)
            self.unique_identifier = unique_identifier.value
        else:
            raise exceptions.InvalidKmipEncoding(
                "expected GetAttributes response unique identifier not found"
            )

        self._attributes = list()
        while self.is_tag_next(enums.Tags.ATTRIBUTE, tstream):
            attribute = objects.Attribute()
            attribute.read(tstream)
            self._attributes.append(attribute)

        self.is_oversized(tstream)

    def write(self, ostream):
        """
        Write the data encoding the GetAttributes response payload to a
        stream.

        Args:
            ostream (stream): A data stream in which to encode object data,
                supporting a write method; usually a BytearrayStream object.
        """
        tstream = utils.BytearrayStream()

        if self._unique_identifier:
            self._unique_identifier.write(tstream)
        else:
            raise exceptions.InvalidField(
                "The GetAttributes response unique identifier is required."
            )

        for attribute in self._attributes:
            attribute.write(tstream)

        self.length = tstream.length()
        super(GetAttributesResponsePayload, self).write(ostream)
        ostream.write(tstream.buffer)

    def __repr__(self):
        unique_identifier = "unique_identifier={0}".format(
            self.unique_identifier
        )
        names = "attributes={0}".format(self.attributes)
        return "GetAttributesResponsePayload({0}, {1})".format(
            unique_identifier,
            names
        )

    def __str__(self):
        return str({
            'unique_identifier': self.unique_identifier,
            'attributes': self.attributes
        })

    def __eq__(self, other):
        if isinstance(other, GetAttributesResponsePayload):
            if self.unique_identifier != other.unique_identifier:
                return False
            if len(self._attributes) != len(other._attributes):
                return False
            for i in range(len(self._attributes)):
                a = self._attributes[i]
                b = other._attributes[i]
                if a != b:
                    return False
            return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, GetAttributesResponsePayload):
            return not self.__eq__(other)
        else:
            return NotImplemented
