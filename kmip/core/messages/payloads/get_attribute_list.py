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
from kmip.core import primitives
from kmip.core import utils


class GetAttributeListRequestPayload(primitives.Struct):
    """
    A request payload for the GetAttributeList operation.

    The payload can contain the ID of the managed object the attributes should
    belong too. If omitted, the server will use the ID placeholder by default.
    See Section 4.13 of the KMIP 1.1 specification for more information.

    Attributes:
        uid: The unique ID of the managed object with which the retrieved
            attributes should be associated.
    """
    def __init__(self, uid=None):
        """
        Construct a GetAttributeList request payload.

        Args:
            uid (string): The ID of the managed object with which the retrieved
                attributes should be associated. Optional, defaults to None.
        """
        super(GetAttributeListRequestPayload, self).__init__(
            enums.Tags.REQUEST_PAYLOAD)

        self.uid = uid

        self.validate()

    def read(self, istream):
        """
        Read the data encoding the GetAttributeList request payload and decode
        it into its constituent parts.

        Args:
            istream (stream): A data stream containing encoded object data,
                supporting a read method; usually a BytearrayStream object.
        """
        super(GetAttributeListRequestPayload, self).read(istream)
        tstream = utils.BytearrayStream(istream.read(self.length))

        if self.is_tag_next(enums.Tags.UNIQUE_IDENTIFIER, tstream):
            uid = primitives.TextString(tag=enums.Tags.UNIQUE_IDENTIFIER)
            uid.read(tstream)
            self.uid = uid.value
        else:
            self.uid = None

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        """
        Write the data encoding the GetAttributeList request payload to a
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

        self.length = tstream.length()
        super(GetAttributeListRequestPayload, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        """
        Error check the attributes of the GetAttributeList request payload.
        """
        if self.uid is not None:
            if not isinstance(self.uid, six.string_types):
                raise TypeError(
                    "uid must be a string; "
                    "expected (one of): {0}, observed: {1}".format(
                        six.string_types, type(self.uid)))

    def __repr__(self):
        uid = "uid={0}".format(self.uid)
        return "GetAttributeListRequestPayload({0})".format(uid)

    def __str__(self):
        return str({'uid': self.uid})

    def __eq__(self, other):
        if isinstance(other, GetAttributeListRequestPayload):
            if self.uid == other.uid:
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


class GetAttributeListResponsePayload(primitives.Struct):
    """
    A response payload for the GetAttributeList operation.

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
    def __init__(self, uid=None, attribute_names=None):
        """
        Construct a GetAttributeList response payload.

        Args:
            uid (string): The ID of the managed object with which the retrieved
                attributes should be associated. Optional, defaults to None.
            attribute_names (list): A list of strings identifying the names of
                the attributes associated with the managed object. Optional,
                defaults to None.
        """
        super(GetAttributeListResponsePayload, self).__init__(
            enums.Tags.RESPONSE_PAYLOAD)

        self.uid = uid

        if attribute_names:
            self.attribute_names = attribute_names
        else:
            self.attribute_names = list()

        self.validate()

    def read(self, istream):
        """
        Read the data encoding the GetAttributeList response payload and decode
        it into its constituent parts.

        Args:
            istream (stream): A data stream containing encoded object data,
                supporting a read method; usually a BytearrayStream object.
        """
        super(GetAttributeListResponsePayload, self).read(istream)
        tstream = utils.BytearrayStream(istream.read(self.length))

        if self.is_tag_next(enums.Tags.UNIQUE_IDENTIFIER, tstream):
            uid = primitives.TextString(tag=enums.Tags.UNIQUE_IDENTIFIER)
            uid.read(tstream)
            self.uid = uid.value
        else:
            raise exceptions.InvalidKmipEncoding(
                "expected uid encoding not found")

        names = list()
        while(self.is_tag_next(enums.Tags.ATTRIBUTE_NAME, tstream)):
            name = primitives.TextString(tag=enums.Tags.ATTRIBUTE_NAME)
            name.read(tstream)
            names.append(name.value)
        self.attribute_names = names

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        """
        Write the data encoding the GetAttributeList response payload to a
        stream.

        Args:
            ostream (stream): A data stream in which to encode object data,
                supporting a write method; usually a BytearrayStream object.
        """
        tstream = utils.BytearrayStream()

        uid = primitives.TextString(
            value=self.uid, tag=enums.Tags.UNIQUE_IDENTIFIER)
        uid.write(tstream)

        for name in self.attribute_names:
            name = primitives.TextString(
                value=name, tag=enums.Tags.ATTRIBUTE_NAME)
            name.write(tstream)

        self.length = tstream.length()
        super(GetAttributeListResponsePayload, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        """
        Error check the attributes of the GetAttributeList response payload.
        """
        if self.uid is not None:
            if not isinstance(self.uid, six.string_types):
                raise TypeError(
                    "uid must be a string; "
                    "expected (one of): {0}, observed: {1}".format(
                        six.string_types, type(self.uid)))

        if self.attribute_names:
            if not isinstance(self.attribute_names, list):
                raise TypeError("attribute names must be a list")
            for i in range(len(self.attribute_names)):
                name = self.attribute_names[i]
                if not isinstance(name, six.string_types):
                    raise TypeError(
                        "attribute name ({0} of {1}) must be a string".format(
                            i + 1, len(self.attribute_names)))

    def __repr__(self):
        uid = "uid={0}".format(self.uid)
        names = "attribute_names={0}".format(self.attribute_names)
        return "GetAttributeListResponsePayload({0}, {1})".format(uid, names)

    def __str__(self):
        return str({'uid': self.uid, 'attribute_names': self.attribute_names})

    def __eq__(self, other):
        if isinstance(other, GetAttributeListResponsePayload):
            if self.uid != other.uid:
                return False
            elif ((isinstance(self.attribute_names, list) and
                   isinstance(other.attribute_names, list)) and
                  len(self.attribute_names) == len(other.attribute_names)):
                for name in self.attribute_names:
                    if name not in other.attribute_names:
                        return False
                return True
            else:
                return False
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, GetAttributeListResponsePayload):
            return not self.__eq__(other)
        else:
            return NotImplemented
