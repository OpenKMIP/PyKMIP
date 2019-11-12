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
from kmip.core.messages.payloads import base
from kmip.core.utils import BytearrayStream


# 4.21
class DestroyRequestPayload(base.RequestPayload):

    def __init__(self,
                 unique_identifier=None):
        super(DestroyRequestPayload, self).__init__()
        self.unique_identifier = unique_identifier
        self.validate()

    def read(self, istream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        super(DestroyRequestPayload, self).read(
            istream,
            kmip_version=kmip_version
        )
        tstream = BytearrayStream(istream.read(self.length))

        if self.is_tag_next(Tags.UNIQUE_IDENTIFIER, tstream):
            self.unique_identifier = attributes.UniqueIdentifier()
            self.unique_identifier.read(tstream, kmip_version=kmip_version)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        tstream = BytearrayStream()

        if self.unique_identifier is not None:
            self.unique_identifier.write(tstream, kmip_version=kmip_version)

        # Write the length and value of the request payload
        self.length = tstream.length()
        super(DestroyRequestPayload, self).write(
            ostream,
            kmip_version=kmip_version
        )
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        # TODO (peter-hamilton) Finish implementation.
        pass


class DestroyResponsePayload(base.ResponsePayload):

    def __init__(self,
                 unique_identifier=None):
        super(DestroyResponsePayload, self).__init__()
        self.unique_identifier = unique_identifier
        self.validate()

    def read(self, istream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        super(DestroyResponsePayload, self).read(
            istream,
            kmip_version=kmip_version
        )
        tstream = BytearrayStream(istream.read(self.length))

        self.unique_identifier = attributes.UniqueIdentifier()
        self.unique_identifier.read(tstream, kmip_version=kmip_version)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        tstream = BytearrayStream()

        self.unique_identifier.write(tstream, kmip_version=kmip_version)

        # Write the length and value of the request payload
        self.length = tstream.length()
        super(DestroyResponsePayload, self).write(
            ostream,
            kmip_version=kmip_version
        )
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        # TODO (peter-hamilton) Finish implementation.
        pass
