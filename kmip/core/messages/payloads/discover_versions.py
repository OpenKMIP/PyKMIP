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

from kmip.core import enums
from kmip.core.messages.contents import ProtocolVersion
from kmip.core.messages.payloads import base
from kmip.core.utils import BytearrayStream

class DiscoverVersionsRequestPayload(base.RequestPayload):

    def __init__(self, protocol_versions=None):
        super(DiscoverVersionsRequestPayload, self).__init__()

        if protocol_versions is None:
            self.protocol_versions = list()
        else:
            self.protocol_versions = protocol_versions

        self.validate()

    def read(self, istream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        super(DiscoverVersionsRequestPayload, self).read(
            istream,
            kmip_version=kmip_version
        )
        tstream = BytearrayStream(istream.read(self.length))

        while (self.is_tag_next(enums.Tags.PROTOCOL_VERSION, tstream)):
            protocol_version = ProtocolVersion()
            protocol_version.read(tstream, kmip_version=kmip_version)
            self.protocol_versions.append(protocol_version)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        tstream = BytearrayStream()

        for protocol_version in self.protocol_versions:
            protocol_version.write(tstream, kmip_version=kmip_version)

        self.length = tstream.length()
        super(DiscoverVersionsRequestPayload, self).write(
            ostream,
            kmip_version=kmip_version
        )
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        if isinstance(self.protocol_versions, list):
            for i in range(len(self.protocol_versions)):
                protocol_version = self.protocol_versions[i]
                if not isinstance(protocol_version, ProtocolVersion):
                    msg = "invalid protocol version ({0} in list)".format(i)
                    msg += "; expected {0}, received {1}".format(
                        ProtocolVersion, protocol_version)
                    raise TypeError(msg)
        else:
            msg = "invalid protocol versions list"
            msg += "; expected {0}, received {1}".format(
                list, self.protocol_versions)
            raise TypeError(msg)

class DiscoverVersionsResponsePayload(base.ResponsePayload):

    def __init__(self, protocol_versions=None):
        super(DiscoverVersionsResponsePayload, self).__init__()

        if protocol_versions is None:
            self.protocol_versions = list()
        else:
            self.protocol_versions = protocol_versions

        self.validate()

    def read(self, istream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        super(DiscoverVersionsResponsePayload, self).read(
            istream,
            kmip_version=kmip_version
        )
        tstream = BytearrayStream(istream.read(self.length))

        while (self.is_tag_next(enums.Tags.PROTOCOL_VERSION, tstream)):
            protocol_version = ProtocolVersion()
            protocol_version.read(tstream, kmip_version=kmip_version)
            self.protocol_versions.append(protocol_version)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        tstream = BytearrayStream()

        for protocol_version in self.protocol_versions:
            protocol_version.write(tstream, kmip_version=kmip_version)

        self.length = tstream.length()
        super(DiscoverVersionsResponsePayload, self).write(
            ostream,
            kmip_version=kmip_version
        )
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        if isinstance(self.protocol_versions, list):
            for i in range(len(self.protocol_versions)):
                protocol_version = self.protocol_versions[i]
                if not isinstance(protocol_version, ProtocolVersion):
                    msg = "invalid protocol version ({0} in list)".format(i)
                    msg += "; expected {0}, received {1}".format(
                        ProtocolVersion, protocol_version)
                    raise TypeError(msg)
        else:
            msg = "invalid protocol versions list"
            msg += "; expected {0}, received {1}".format(
                list, self.protocol_versions)
            raise TypeError(msg)
