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

from kmip.core import attributes
from kmip.core import enums
from kmip.core.enums import Tags

from kmip.core.objects import Attribute

from kmip.core.primitives import Struct
from kmip.core.primitives import Enumeration
from kmip.core.primitives import Integer

from kmip.core.utils import BytearrayStream


class LocateRequestPayload(Struct):

    # 9.1.3.2.33
    class ObjectGroupMember(Enumeration):
        ENUM_TYPE = enums.ObjectGroupMember

        def __init__(self, value=None):
            super(self.__class__, self).__init__(value,
                                                 Tags.OBJECT_GROUP_MEMBER)

    class MaximumItems(Integer):
        def __init__(self, value=None):
            super(self.__class__, self).__init__(value,
                                                 Tags.MAXIMUM_ITEMS)

    # 9.1.3.3.2
    class StorageStatusMask(Enumeration):
        ENUM_TYPE = enums.StorageStatusMask

        def __init__(self, value=None):
            super(self.__class__, self).__init__(value,
                                                 Tags.STORAGE_STATUS_MASK)

    def __init__(self, maximum_items=None, storage_status_mask=None,
                 object_group_member=None, attributes=None):
        super(self.__class__, self).__init__(enums.Tags.REQUEST_PAYLOAD)
        self.maximum_items = maximum_items
        self.storage_status_mask = storage_status_mask
        self.object_group_member = object_group_member
        self.attributes = attributes or []
        self.validate()

    def read(self, istream):
        super(self.__class__, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))
        if self.is_tag_next(Tags.MAXIMUM_ITEMS, tstream):
            self.maximum_items = LocateRequestPayload.MaximumItems()
            self.maximum_items.read()
        if self.is_tag_next(Tags.STORAGE_STATUS_MASK, tstream):
            self.storage_status_mask = LocateRequestPayload.StorageStatusMask()
            self.storage_status_mask.read()
        if self.is_tag_next(Tags.OBJECT_GROUP_MEMBER, tstream):
            self.object_group_member = LocateRequestPayload.ObjectGroupMember()
            self.object_group_member.read(tstream)
        while self.is_tag_next(Tags.ATTRIBUTE, tstream):
            attr = Attribute()
            attr.read(tstream)
            self.attributes.append(attr)

        self.validate()

    def write(self, ostream):
        tstream = BytearrayStream()
        if self.maximum_items is not None:
            self.maximum_items.write(tstream)
        if self.storage_status_mask is not None:
            self.storage_status_mask.write(tstream)
        if self.attributes is not None:
            for a in self.attributes:
                a.write(tstream)

        # Write the length and value of the request payload
        self.length = tstream.length()
        super(self.__class__, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        self._validate()

    def _validate(self):
        # TODO Finish implementation.
        pass


class LocateResponsePayload(Struct):

    def __init__(self, unique_identifiers=[]):
        super(self.__class__, self).__init__(enums.Tags.RESPONSE_PAYLOAD)
        self.unique_identifiers = unique_identifiers or []
        self.validate()

    def read(self, istream):
        super(self.__class__, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        while self.is_tag_next(Tags.UNIQUE_IDENTIFIER, tstream):
            ui = attributes.UniqueIdentifier()
            ui.read(tstream)
            self.unique_identifiers.append(ui)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        tstream = BytearrayStream()

        for ui in self.unique_identifiers:
            ui.write(tstream)

        # Write the length and value of the request payload
        self.length = tstream.length()
        super(self.__class__, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        # TODO Finish implementation.
        pass
