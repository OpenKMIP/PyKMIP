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
from kmip.core import misc
from kmip.core import objects

from kmip.core import enums
from kmip.core.messages.payloads import base
from kmip.core.messages.payloads.create_key_pair import \
    CreateKeyPairResponsePayload
from kmip.core.utils import BytearrayStream

class RekeyKeyPairRequestPayload(base.RequestPayload):

    def __init__(self,
                 private_key_uuid=None,
                 offset=None,
                 common_template_attribute=None,
                 private_key_template_attribute=None,
                 public_key_template_attribute=None):
        super(RekeyKeyPairRequestPayload, self).__init__()

        self.private_key_uuid = private_key_uuid
        self.offset = offset
        self.common_template_attribute = common_template_attribute
        self.private_key_template_attribute = private_key_template_attribute
        self.public_key_template_attribute = public_key_template_attribute

        self.validate()

    def read(self, istream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        super(RekeyKeyPairRequestPayload, self).read(
            istream,
            kmip_version=kmip_version
        )
        tstream = BytearrayStream(istream.read(self.length))

        if self.is_tag_next(enums.Tags.PRIVATE_KEY_UNIQUE_IDENTIFIER, tstream):
            self.private_key_uuid = attributes.PrivateKeyUniqueIdentifier()
            self.private_key_uuid.read(tstream, kmip_version=kmip_version)

        if self.is_tag_next(enums.Tags.OFFSET, tstream):
            self.offset = misc.Offset()
            self.offset.read(tstream, kmip_version=kmip_version)

        if self.is_tag_next(enums.Tags.COMMON_TEMPLATE_ATTRIBUTE, tstream):
            self.common_template_attribute = objects.CommonTemplateAttribute()
            self.common_template_attribute.read(
                tstream,
                kmip_version=kmip_version
            )

        if self.is_tag_next(enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE,
                            tstream):
            self.private_key_template_attribute = \
                objects.PrivateKeyTemplateAttribute()
            self.private_key_template_attribute.read(
                tstream,
                kmip_version=kmip_version
            )

        if self.is_tag_next(enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE, tstream):
            self.public_key_template_attribute = \
                objects.PublicKeyTemplateAttribute()
            self.public_key_template_attribute.read(
                tstream,
                kmip_version=kmip_version
            )

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        tstream = BytearrayStream()

        if self.private_key_uuid is not None:
            self.private_key_uuid.write(tstream, kmip_version=kmip_version)

        if self.offset is not None:
            self.offset.write(tstream, kmip_version=kmip_version)

        if self.common_template_attribute is not None:
            self.common_template_attribute.write(
                tstream,
                kmip_version=kmip_version
            )

        if self.private_key_template_attribute is not None:
            self.private_key_template_attribute.write(
                tstream,
                kmip_version=kmip_version
            )

        if self.public_key_template_attribute is not None:
            self.public_key_template_attribute.write(
                tstream,
                kmip_version=kmip_version
            )

        self.length = tstream.length()
        super(RekeyKeyPairRequestPayload, self).write(
            ostream,
            kmip_version=kmip_version
        )
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        if self.private_key_uuid is not None:
            if not isinstance(self.private_key_uuid,
                              attributes.PrivateKeyUniqueIdentifier):
                msg = "invalid private key unique identifier"
                msg += "; expected {0}, received {1}".format(
                    attributes.PrivateKeyUniqueIdentifier,
                    self.private_key_uuid)
                raise TypeError(msg)

        if self.offset is not None:
            if not isinstance(self.offset, misc.Offset):
                msg = "invalid offset"
                msg += "; expected {0}, received {1}".format(
                    misc.Offset, self.offset)
                raise TypeError(msg)

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

# TODO (ph) Remove the dependency on the CreateKeyPairResponsePayload
class RekeyKeyPairResponsePayload(CreateKeyPairResponsePayload):

    def __init__(self,
                 private_key_uuid=None,
                 public_key_uuid=None,
                 private_key_template_attribute=None,
                 public_key_template_attribute=None):
        super(RekeyKeyPairResponsePayload, self).__init__(
            private_key_uuid, public_key_uuid, private_key_template_attribute,
            public_key_template_attribute)
