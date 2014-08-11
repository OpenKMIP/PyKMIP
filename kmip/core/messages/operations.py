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
from kmip.core import enums
from kmip.core.enums import Tags

from kmip.core.objects import KeyWrappingSpecification
from kmip.core.objects import TemplateAttribute

from kmip.core.primitives import Struct
from kmip.core.primitives import Enumeration

from kmip.core.utils import BytearrayStream


# 4.1
class CreateRequestPayload(Struct):

    def __init__(self,
                 object_type=None,
                 template_attribute=None):
        super(self.__class__, self).__init__(tag=enums.Tags.REQUEST_PAYLOAD)
        self.object_type = object_type
        self.template_attribute = template_attribute
        self.validate()

    def read(self, istream):
        super(self.__class__, self).read(istream)
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
        super(self.__class__, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        # TODO (peter-hamilton) Finish implementation.
        pass


class CreateResponsePayload(Struct):

    def __init__(self,
                 object_type=None,
                 unique_identifier=None,
                 template_attribute=None):
        super(self.__class__, self).__init__(tag=enums.Tags.RESPONSE_PAYLOAD)
        self.object_type = object_type
        self.unique_identifier = unique_identifier
        self.template_attribute = template_attribute
        self.validate()

    def read(self, istream):
        super(self.__class__, self).read(istream)
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
        super(self.__class__, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        # TODO (peter-hamilton) Finish implementation.
        pass


# 4.3
class RegisterRequestPayload(Struct):

    def __init__(self,
                 object_type=None,
                 template_attribute=None,
                 secret=None):
        super(self.__class__, self).__init__(Tags.REQUEST_PAYLOAD)

        self.secret_factory = SecretFactory()
        self.object_type = object_type
        self.template_attribute = template_attribute
        self.secret = secret

        self.validate()

    def read(self, istream):
        super(self.__class__, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        self.object_type = attributes.ObjectType()
        self.template_attribute = TemplateAttribute()

        self.object_type.read(tstream)
        self.template_attribute.read(tstream)

        secret_type = self.object_type.enum
        secret = self.secret_factory.create_secret(secret_type)

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
        super(self.__class__, self).write(ostream)
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
        super(self.__class__, self).__init__(Tags.RESPONSE_PAYLOAD)

        self.unique_identifier = unique_identifier
        self.template_attribute = template_attribute

        self.validate()

    def read(self, istream):
        super(self.__class__, self).read(istream)
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
        super(self.__class__, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        # TODO (peter-hamilton) Finish implementation.
        pass


# 4.11
class GetRequestPayload(Struct):

    # 9.1.3.2.2
    class KeyCompressionType(Enumeration):
        ENUM_TYPE = enums.KeyCompressionType

        def __init__(self, value=None):
            super(self.__class__, self).__init__(value,
                                                 Tags.KEY_COMPRESSION_TYPE)

    # 9.1.3.2.3
    class KeyFormatType(Enumeration):
        ENUM_TYPE = enums.KeyFormatType

        def __init__(self, value=None):
            super(self.__class__, self).__init__(value, Tags.KEY_FORMAT_TYPE)

    def __init__(self,
                 unique_identifier=None,
                 key_format_type=None,
                 key_compression_type=None,
                 key_wrapping_specification=None):
        super(self.__class__, self).__init__(tag=enums.Tags.REQUEST_PAYLOAD)
        self.unique_identifier = unique_identifier
        self.key_format_type = key_format_type
        self.key_compression_type = key_compression_type
        self.key_wrapping_specification = key_wrapping_specification
        self.validate()

    def read(self, istream):
        super(self.__class__, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        if self.is_tag_next(Tags.UNIQUE_IDENTIFIER, tstream):
            self.unique_identifier = attributes.UniqueIdentifier()
            self.unique_identifier.read(tstream)

        if self.is_tag_next(Tags.KEY_FORMAT_TYPE, tstream):
            self.key_format_type = GetRequestPayload.KeyFormatType()
            self.key_format_type.read(tstream)

        if self.is_tag_next(Tags.KEY_COMPRESSION_TYPE, tstream):
            self.key_compression_type = GetRequestPayload.KeyCompressionType()
            self.key_compression_type.read(tstream)

        if self.is_tag_next(Tags.KEY_WRAPPING_SPECIFICATION, tstream):
            self.key_wrapping_specification = KeyWrappingSpecification()
            self.key_wrapping_specification.read(tstream)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        tstream = BytearrayStream()

        # Write the contents of the request payload
        if self.unique_identifier is not None:
            self.unique_identifier.write(tstream)
        if self.key_format_type is not None:
            self.key_format_type.write(tstream)
        if self.key_compression_type is not None:
            self.key_compression_type.write(tstream)
        if self.key_wrapping_specification is not None:
            self.key_wrapping_specification.write(tstream)

        # Write the length and value of the request payload
        self.length = tstream.length()
        super(self.__class__, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        # TODO (peter-hamilton) Finish implementation
        pass


class GetResponsePayload(Struct):

    def __init__(self,
                 object_type=None,
                 unique_identifier=None,
                 secret=None):
        super(self.__class__, self).__init__(tag=Tags.RESPONSE_PAYLOAD)
        self.object_type = object_type
        self.unique_identifier = unique_identifier
        self.secret = secret
        self.secret_factory = SecretFactory()
        self.validate()

    def read(self, istream):
        super(self.__class__, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        self.object_type = attributes.ObjectType()
        self.unique_identifier = attributes.UniqueIdentifier()

        self.object_type.read(tstream)
        self.unique_identifier.read(tstream)

        secret_type = self.object_type.enum
        self.secret = self.secret_factory.create_secret(secret_type)
        self.secret.read(tstream)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        tstream = BytearrayStream()

        self.object_type.write(tstream)
        self.unique_identifier.write(tstream)
        self.secret.write(tstream)

        # Write the length and value of the request payload
        self.length = tstream.length()
        super(self.__class__, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        # TODO (peter-hamilton) Finish implementation.
        pass


# 4.21
class DestroyRequestPayload(Struct):

    def __init__(self,
                 unique_identifier=None):
        super(self.__class__, self).__init__(enums.Tags.REQUEST_PAYLOAD)
        self.unique_identifier = unique_identifier
        self.validate()

    def read(self, istream):
        super(self.__class__, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        if self.is_tag_next(Tags.UNIQUE_IDENTIFIER, tstream):
            self.unique_identifier = attributes.UniqueIdentifier()
            self.unique_identifier.read(tstream)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        tstream = BytearrayStream()

        if self.unique_identifier is not None:
            self.unique_identifier.write(tstream)

        # Write the length and value of the request payload
        self.length = tstream.length()
        super(self.__class__, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        # TODO (peter-hamilton) Finish implementation.
        pass


class DestroyResponsePayload(Struct):

    def __init__(self,
                 unique_identifier=None):
        super(self.__class__, self).__init__(enums.Tags.RESPONSE_PAYLOAD)
        self.unique_identifier = unique_identifier
        self.validate()

    def read(self, istream):
        super(self.__class__, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        self.unique_identifier = attributes.UniqueIdentifier()
        self.unique_identifier.read(tstream)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        tstream = BytearrayStream()

        self.unique_identifier.write(tstream)

        # Write the length and value of the request payload
        self.length = tstream.length()
        super(self.__class__, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        # TODO (peter-hamilton) Finish implementation.
        pass


REQUEST_MAP = {enums.Operation.CREATE: CreateRequestPayload,
               enums.Operation.GET: GetRequestPayload,
               enums.Operation.DESTROY: DestroyRequestPayload,
               enums.Operation.REGISTER: RegisterRequestPayload}
RESPONSE_MAP = {enums.Operation.CREATE: CreateResponsePayload,
                enums.Operation.GET: GetResponsePayload,
                enums.Operation.DESTROY: DestroyResponsePayload,
                enums.Operation.REGISTER: RegisterResponsePayload}
