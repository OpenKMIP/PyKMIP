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

from kmip.core.objects import TemplateAttribute

from kmip.core.primitives import Struct

from kmip.core.utils import BytearrayStream


class CreateRequestPayload(Struct):

    def __init__(self,
                 object_type=None,
                 template_attribute=None):
        super(CreateRequestPayload, self).__init__(
            tag=enums.Tags.REQUEST_PAYLOAD)
        self.object_type = object_type
        self.template_attribute = template_attribute
        self.validate()

    def read(self, istream):
        super(CreateRequestPayload, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        self.object_type = attributes.ObjectType()
        self.template_attribute = TemplateAttribute()

        self.object_type.read(tstream)
        self.template_attribute.read(tstream)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        tstream = BytearrayStream()

        # Write the object type and template attribute of the request payload
        self.object_type.write(tstream)
        self.template_attribute.write(tstream)

        # Write the length and value of the request payload
        self.length = tstream.length()
        super(CreateRequestPayload, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        # TODO (peter-hamilton) Finish implementation.
        pass


class CreateResponsePayload(Struct):

    def __init__(self,
                 object_type=None,
                 unique_identifier=None,
                 template_attribute=None):
        super(CreateResponsePayload, self).__init__(
            tag=enums.Tags.RESPONSE_PAYLOAD)
        self.object_type = object_type
        self.unique_identifier = unique_identifier
        self.template_attribute = template_attribute
        self.validate()

    def read(self, istream):
        super(CreateResponsePayload, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        self.object_type = attributes.ObjectType()
        self.unique_identifier = attributes.UniqueIdentifier()

        self.object_type.read(tstream)
        self.unique_identifier.read(tstream)

        if self.is_tag_next(Tags.TEMPLATE_ATTRIBUTE, tstream):
            self.template_attribute = TemplateAttribute()
            self.template_attribute.read(tstream)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        tstream = BytearrayStream()

        # Write the contents of the request payload
        self.object_type.write(tstream)
        self.unique_identifier.write(tstream)

        if self.template_attribute is not None:
            self.template_attribute.write(tstream)

        # Write the length and value of the request payload
        self.length = tstream.length()
        super(CreateResponsePayload, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        # TODO (peter-hamilton) Finish implementation.
        pass
