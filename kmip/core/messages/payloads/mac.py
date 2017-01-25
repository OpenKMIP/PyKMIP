# Copyright (c) 2017 Pure Storage, Inc. All Rights Reserved.
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

from kmip.core.objects import Data, MACData

from kmip.core.primitives import Struct

from kmip.core.utils import BytearrayStream


# 4.33
class MACRequestPayload(Struct):

    def __init__(self,
                 unique_identifier=None,
                 cryptographic_parameters=None,
                 data=None):
        super(MACRequestPayload, self).__init__(
            tag=enums.Tags.REQUEST_PAYLOAD)
        self.unique_identifier = unique_identifier
        self.cryptographic_parameters = cryptographic_parameters
        self.data = data
        self.validate()

    def read(self, istream):
        super(MACRequestPayload, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        if self.is_tag_next(Tags.UNIQUE_IDENTIFIER, tstream):
            self.unique_identifier = attributes.UniqueIdentifier()
            self.unique_identifier.read(tstream)

        if self.is_tag_next(Tags.CRYPTOGRAPHIC_PARAMETERS, tstream):
            self.cryptographic_parameters = \
                attributes.CryptographicParameters()
            self.cryptographic_parameters.read(tstream)

        if self.is_tag_next(Tags.DATA, tstream):
            self.data = Data()
            self.data.read(tstream)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        tstream = BytearrayStream()

        # Write the object type and template attribute of the request payload
        self.unique_identifier.write(tstream)
        self.cryptographic_parameters.write(tstream)
        self.data.write(tstream)

        # Write the length and value of the request payload
        self.length = tstream.length()
        super(MACRequestPayload, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        # TODO.
        pass


class MACResponsePayload(Struct):

    def __init__(self,
                 unique_identifier=None,
                 mac_data=None):
        super(MACResponsePayload, self).__init__(
            tag=enums.Tags.RESPONSE_PAYLOAD)
        self.unique_identifier = unique_identifier
        self.mac_data = mac_data
        self.validate()

    def read(self, istream):
        super(MACResponsePayload, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        self.unique_identifier = attributes.UniqueIdentifier()
        self.mac_data = MACData()
        self.unique_identifier.read(tstream)
        self.mac_data.read(tstream)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        tstream = BytearrayStream()

        self.unique_identifier.write(tstream)
        self.mac_data.write(tstream)

        self.length = tstream.length()
        super(MACResponsePayload, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        # TODO.
        pass
