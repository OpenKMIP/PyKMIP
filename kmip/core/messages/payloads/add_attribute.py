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

import six

from kmip.core import enums
from kmip.core import exceptions
from kmip.core import objects
from kmip.core import primitives
from kmip.core import utils


class AddAttributeRequestPayload(primitives.Struct):
    """
    A request payload for the AddAttribute operation.

    The payload can contain the ID of the managed object the attributes should
    belong too. If omitted, the server will use the ID placeholder by default.
    See Section 4.13 of the KMIP 1.1 specification for more information.

    Attributes:
        uid: The unique ID of the managed object with which the retrieved
            attributes should be associated.
    """
    def __init__(self, uid=None, attribute=None):
        """
        Construct a AddAttribute request payload.

        Args:
            uid (string): The ID of the managed object with which the retrieved
                attributes should be associated. Optional, defaults to None.
        """
        super(AddAttributeRequestPayload, self).__init__(
            enums.Tags.REQUEST_PAYLOAD)
        self.uid = uid
        self.attribute = attribute

        self.validate()

    def read(self, istream):
        """
        Read the data encoding the AddAttribute request payload and decode
        it into its constituent parts.

        Args:
            istream (stream): A data stream containing encoded object data,
                supporting a read method; usually a BytearrayStream object.
        """
        super(AddAttributeRequestPayload, self).read(istream)
        tstream = utils.BytearrayStream(istream.read(self.length))

        if self.is_tag_next(enums.Tags.UNIQUE_IDENTIFIER, tstream):
            uid = primitives.TextString(tag=enums.Tags.UNIQUE_IDENTIFIER)
            uid.read(tstream)
            self.uid = uid.value
        else:
            self.uid = None

        if self.is_tag_next(enums.Tags.ATTRIBUTE, tstream):
            self.attribute = objects.Attribute()
            self.attribute.read(tstream)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        """
        Write the data encoding the AddAttribute request payload to a
        stream.

        Args:
            ostream (stream): A data stream in which to encode object data,
                supporting a write method; usually a BytearrayStream object.
        """
        tstream = utils.BytearrayStream()

        if self.uid:
            uid = primitives.TextString(
                value=self.uid, tag=enums.Tags.UNIQUE_IDENTIFIER)
            uid.write(tstream)

        if self.attribute:
            self.attribute.write(tstream)

        self.length = tstream.length()
        super(AddAttributeRequestPayload, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        """
        Error check the attributes of the AddAttribute request payload.
        """
        if self.uid is not None:
            if not isinstance(self.uid, six.string_types):
                raise TypeError(
                    "uid must be a string; "
                    "expected (one of): {0}, observed: {1}".format(
                        six.string_types, type(self.uid)))
        if self.attribute is not None:
            if not isinstance(self.attribute, objects.Attribute):
                raise TypeError(
                    "attribute must be a Attribute object, "
                    "observed: {1}".format(type(self.attribute)))

    def __repr__(self):
        uid = "uid={0}".format(self.uid)
        attribute = "attribute={0}".format(self.attribute)
        return "AddAttributeRequestPayload({0},{1})".format(
            uid,
            attribute)

    def __str__(self):
        return str({'uid': self.uid, 'attribute': self.attribute})

    def __eq__(self, other):
        if isinstance(other, AddAttributeRequestPayload):
            if self.uid != other.uid:
                return False
            elif self.attribute != other.attribute:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, AddAttributeRequestPayload):
            return not self.__eq__(other)
        else:
            return NotImplemented


class AddAttributeResponsePayload(primitives.Struct):
    """
    A response payload for the AddAttribute operation.

    The payload will contain the ID of the managed object with which the
    attributes are associated. It will also contain a list of attribute names
    identifying the types of attributes associated with the aforementioned
    managed object. See Section 4.13 of the KMIP 1.1 specification for more
    information.

    Attributes:
        uid: The unique ID of the managed object with which the retrieved
            attributes should be associated.
        attribute_names: The list of attribute names of the attributes
            associated with managed object identified by the uid above.
    """
    def __init__(self, uid=None, attribute=None):
        """
        Construct a AddAttribute response payload.

        Args:
            uid (string): The ID of the managed object with which the retrieved
                attributes should be associated. Optional, defaults to None.
            attribute (Attribute): required, the added attribute
                associated with the object
        """
        super(AddAttributeResponsePayload, self).__init__(
            enums.Tags.RESPONSE_PAYLOAD)

        self.uid = uid
        self.attribute = attribute

        self.validate()

    def read(self, istream):
        """
        Read the data encoding the AddAttribute response payload and decode
        it into its constituent parts.

        Args:
            istream (stream): A data stream containing encoded object data,
                supporting a read method; usually a BytearrayStream object.
        """
        super(AddAttributeResponsePayload, self).read(istream)
        tstream = utils.BytearrayStream(istream.read(self.length))

        if self.is_tag_next(enums.Tags.UNIQUE_IDENTIFIER, tstream):
            uid = primitives.TextString(tag=enums.Tags.UNIQUE_IDENTIFIER)
            uid.read(tstream)
            self.uid = uid.value
        else:
            raise exceptions.InvalidKmipEncoding(
                "expected uid encoding not found")

        if self.is_tag_next(enums.Tags.ATTRIBUTE, tstream):
            self.attribute = objects.Attribute()
            self.attribute.read(tstream)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        """
        Write the data encoding the AddAttribute response payload to a
        stream.

        Args:
            ostream (stream): A data stream in which to encode object data,
                supporting a write method; usually a BytearrayStream object.
        """
        tstream = utils.BytearrayStream()

        uid = primitives.TextString(
            value=self.uid, tag=enums.Tags.UNIQUE_IDENTIFIER)
        uid.write(tstream)

        if self.attribute:
            self.attribute.write(tstream)

        self.length = tstream.length()
        super(AddAttributeResponsePayload, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        """
        Error check the attributes of the AddAttribute response payload.
        """
        if self.uid is not None:
            if not isinstance(self.uid, six.string_types):
                raise TypeError(
                    "uid must be a string; "
                    "expected (one of): {0}, observed: {1}".format(
                        six.string_types, type(self.uid)))

        if self.attribute is not None:
            if not isinstance(self.attribute, objects.Attribute):
                raise TypeError(
                    "attribute must be a Attribute object, "
                    "observed: {1}".format(type(self.attribute)))

    def __repr__(self):
        uid = "uid={0}".format(self.uid)
        attribute = "attribute={0}".format(self.attribute)
        return "AddAttributeRequestPayload({0},{1})".format(
            uid,
            attribute)

    def __str__(self):
        return str({'uid': self.uid, 'attribute': self.attribute})

    def __eq__(self, other):
        if isinstance(other, AddAttributeRequestPayload):
            if self.uid != other.uid:
                return False
            elif self.attribute != other.attribute:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, AddAttributeRequestPayload):
            return not self.__eq__(other)
        else:
            return NotImplemented
