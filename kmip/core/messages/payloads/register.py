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

from kmip.core.factories.secrets import SecretFactory

from kmip.core import attributes
from kmip.core.enums import Tags

from kmip.core.objects import TemplateAttribute

from kmip.core.primitives import Struct

from kmip.core.utils import BytearrayStream


# 4.3
class RegisterRequestPayload(Struct):

    def __init__(self,
                 object_type=None,
                 template_attribute=None,
                 secret=None):
        super(RegisterRequestPayload, self).__init__(Tags.REQUEST_PAYLOAD)

        self.secret_factory = SecretFactory()
        self.object_type = object_type
        self.template_attribute = template_attribute
        self.secret = secret

        self.validate()

    def read(self, istream):
        super(RegisterRequestPayload, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        self.object_type = attributes.ObjectType()
        self.template_attribute = TemplateAttribute()

        self.object_type.read(tstream)
        self.template_attribute.read(tstream)

        secret_type = self.object_type.value
        secret = self.secret_factory.create(secret_type)

        if self.is_tag_next(secret.tag, tstream):
            self.secret = secret
            self.secret.read(tstream)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        tstream = BytearrayStream()

        # Write the contents of the request payload
        self.object_type.write(tstream)
        self.template_attribute.write(tstream)

        if self.secret is not None:
            self.secret.write(tstream)

        # Write the length and value of the request payload
        self.length = tstream.length()
        super(RegisterRequestPayload, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        # TODO (peter-hamilton) Finish implementation.
        pass


class RegisterResponsePayload(Struct):

    def __init__(self,
                 unique_identifier=None,
                 template_attribute=None):
        super(RegisterResponsePayload, self).__init__(Tags.RESPONSE_PAYLOAD)

        self.unique_identifier = unique_identifier
        self.template_attribute = template_attribute

        self.validate()

    def read(self, istream):
        super(RegisterResponsePayload, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        self.unique_identifier = attributes.UniqueIdentifier()
        self.unique_identifier.read(tstream)

        if self.is_tag_next(Tags.TEMPLATE_ATTRIBUTE, tstream):
            self.template_attribute = TemplateAttribute()
            self.template_attribute.read(tstream)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        tstream = BytearrayStream()

        # Write the contents of the request payload
        self.unique_identifier.write(tstream)

        if self.template_attribute is not None:
            self.template_attribute.write(tstream)

        # Write the length and value of the request payload
        self.length = tstream.length()
        super(RegisterResponsePayload, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        # TODO (peter-hamilton) Finish implementation.
        pass
