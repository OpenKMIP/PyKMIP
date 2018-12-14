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
from kmip.core import objects

from kmip.core import enums
from kmip.core.enums import Tags

from kmip.core.primitives import Struct

from kmip.core.utils import BytearrayStream


class CreateKeyPairRequestPayload(Struct):

    def __init__(self,
                 common_template_attribute=None,
                 private_key_template_attribute=None,
                 public_key_template_attribute=None,
                 kmip_version=enums.KMIPVersion.KMIP_1_0):
        super(CreateKeyPairRequestPayload, self).__init__(
            Tags.REQUEST_PAYLOAD,
            kmip_version=kmip_version
        )

        self.common_template_attribute = common_template_attribute
        self.private_key_template_attribute = private_key_template_attribute
        self.public_key_template_attribute = public_key_template_attribute

        self.validate()

    def read(self, istream):
        super(CreateKeyPairRequestPayload, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        if self.is_tag_next(Tags.COMMON_TEMPLATE_ATTRIBUTE, tstream):
            self.common_template_attribute = objects.CommonTemplateAttribute()
            self.common_template_attribute.read(tstream)

        if self.is_tag_next(Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE, tstream):
            self.private_key_template_attribute = \
                objects.PrivateKeyTemplateAttribute()
            self.private_key_template_attribute.read(tstream)

        if self.is_tag_next(Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE, tstream):
            self.public_key_template_attribute = \
                objects.PublicKeyTemplateAttribute()
            self.public_key_template_attribute.read(tstream)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        tstream = BytearrayStream()

        if self.common_template_attribute is not None:
            self.common_template_attribute.write(tstream)

        if self.private_key_template_attribute is not None:
            self.private_key_template_attribute.write(tstream)

        if self.public_key_template_attribute is not None:
            self.public_key_template_attribute.write(tstream)

        self.length = tstream.length()
        super(CreateKeyPairRequestPayload, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        if self.common_template_attribute is not None:
            if not isinstance(self.common_template_attribute,
                              objects.CommonTemplateAttribute):
                msg = "invalid common template attribute"
                msg += "; expected {0}, received {1}".format(
                    objects.CommonTemplateAttribute,
                    self.common_template_attribute)
                raise TypeError(msg)

        if self.private_key_template_attribute is not None:
            if not isinstance(self.private_key_template_attribute,
                              objects.PrivateKeyTemplateAttribute):
                msg = "invalid private key template attribute"
                msg += "; expected {0}, received {1}".format(
                    objects.PrivateKeyTemplateAttribute,
                    self.private_key_template_attribute)
                raise TypeError(msg)

        if self.public_key_template_attribute is not None:
            if not isinstance(self.public_key_template_attribute,
                              objects.PublicKeyTemplateAttribute):
                msg = "invalid public key template attribute"
                msg += "; expected {0}, received {1}".format(
                    objects.PublicKeyTemplateAttribute,
                    self.public_key_template_attribute)
                raise TypeError(msg)


class CreateKeyPairResponsePayload(Struct):

    def __init__(self,
                 private_key_uuid=None,
                 public_key_uuid=None,
                 private_key_template_attribute=None,
                 public_key_template_attribute=None,
                 kmip_version=enums.KMIPVersion.KMIP_1_0):
        super(CreateKeyPairResponsePayload, self).__init__(
            Tags.RESPONSE_PAYLOAD,
            kmip_version=kmip_version
        )

        # Private and public UUIDs are required so make defaults as backup
        if private_key_uuid is None:
            self.private_key_uuid = attributes.PrivateKeyUniqueIdentifier('')
        else:
            self.private_key_uuid = private_key_uuid

        if public_key_uuid is None:
            self.public_key_uuid = attributes.PublicKeyUniqueIdentifier('')
        else:
            self.public_key_uuid = public_key_uuid

        self.private_key_template_attribute = private_key_template_attribute
        self.public_key_template_attribute = public_key_template_attribute

        self.validate()

    def read(self, istream):
        super(CreateKeyPairResponsePayload, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        self.private_key_uuid.read(tstream)
        self.public_key_uuid.read(tstream)

        if self.is_tag_next(Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE, tstream):
            self.private_key_template_attribute = \
                objects.PrivateKeyTemplateAttribute()
            self.private_key_template_attribute.read(tstream)

        if self.is_tag_next(Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE, tstream):
            self.public_key_template_attribute = \
                objects.PublicKeyTemplateAttribute()
            self.public_key_template_attribute.read(tstream)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        tstream = BytearrayStream()

        self.private_key_uuid.write(tstream)
        self.public_key_uuid.write(tstream)

        if self.private_key_template_attribute is not None:
            self.private_key_template_attribute.write(tstream)

        if self.public_key_template_attribute is not None:
            self.public_key_template_attribute.write(tstream)

        self.length = tstream.length()
        super(CreateKeyPairResponsePayload, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        if not isinstance(self.private_key_uuid,
                          attributes.PrivateKeyUniqueIdentifier):
            msg = "invalid private key unique identifier"
            msg += "; expected {0}, received {1}".format(
                attributes.PrivateKeyUniqueIdentifier,
                self.private_key_uuid)
            raise TypeError(msg)

        if not isinstance(self.public_key_uuid,
                          attributes.PublicKeyUniqueIdentifier):
            msg = "invalid public key unique identifier"
            msg += "; expected {0}, received {1}".format(
                attributes.PublicKeyUniqueIdentifier,
                self.public_key_uuid)
            raise TypeError(msg)

        if self.private_key_template_attribute is not None:
            if not isinstance(self.private_key_template_attribute,
                              objects.PrivateKeyTemplateAttribute):
                msg = "invalid private key template attribute"
                msg += "; expected {0}, received {1}".format(
                    objects.PrivateKeyTemplateAttribute,
                    self.private_key_template_attribute)
                raise TypeError(msg)

        if self.public_key_template_attribute is not None:
            if not isinstance(self.public_key_template_attribute,
                              objects.PublicKeyTemplateAttribute):
                msg = "invalid public key template attribute"
                msg += "; expected {0}, received {1}".format(
                    objects.PublicKeyTemplateAttribute,
                    self.public_key_template_attribute)
                raise TypeError(msg)
