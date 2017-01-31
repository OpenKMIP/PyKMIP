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
from kmip.core import exceptions
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

        self._unique_identifier = None
        self._cryptographic_parameters = None
        self._data = None

        self.unique_identifier = unique_identifier
        self.cryptographic_parameters = cryptographic_parameters
        self.data = data

    @property
    def unique_identifier(self):
        return self._unique_identifier

    @unique_identifier.setter
    def unique_identifier(self, value):
        if value is None:
            self._unique_identifier = None
        elif isinstance(value, attributes.UniqueIdentifier):
            self._unique_identifier = value
        else:
            raise TypeError("unique identifier must be UniqueIdentifier type")

    @property
    def cryptographic_parameters(self):
        return self._cryptographic_parameters

    @cryptographic_parameters.setter
    def cryptographic_parameters(self, value):
        if value is None:
            self._cryptographic_parameters = None
        elif isinstance(value, attributes.CryptographicParameters):
            self._cryptographic_parameters = value
        else:
            raise TypeError("cryptographic parameters must "
                            "be CryptographicParameters type")

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, value):
        if value is None:
            self._data = None
        elif isinstance(value, Data):
            self._data = value
        else:
            raise TypeError("data must be Data type")

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
        else:
            raise exceptions.InvalidKmipEncoding(
                "expected mac request data not found"
            )

        self.is_oversized(tstream)

    def write(self, ostream):
        tstream = BytearrayStream()

        if self._unique_identifier is not None:
            self._unique_identifier.write(tstream)
        if self._cryptographic_parameters is not None:
            self._cryptographic_parameters.write(tstream)
        if self._data is not None:
            self.data.write(tstream)
        else:
            raise exceptions.InvalidField(
                "The mac request data is required"
            )

        self.length = tstream.length()
        super(MACRequestPayload, self).write(ostream)
        ostream.write(tstream.buffer)


class MACResponsePayload(Struct):

    def __init__(self,
                 unique_identifier=None,
                 mac_data=None):
        super(MACResponsePayload, self).__init__(
            tag=enums.Tags.RESPONSE_PAYLOAD)

        self._unique_identifier = None
        self._mac_data = None

        self.unique_identifier = unique_identifier
        self.mac_data = mac_data

    @property
    def unique_identifier(self):
        return self._unique_identifier

    @unique_identifier.setter
    def unique_identifier(self, value):
        if value is None:
            self._unique_identifier = None
        elif isinstance(value, attributes.UniqueIdentifier):
            self._unique_identifier = value
        else:
            raise TypeError("unique identifier must be UniqueIdentifier type")

    @property
    def mac_data(self):
        return self._mac_data

    @mac_data.setter
    def mac_data(self, value):
        if value is None:
            self._mac_data = None
        elif isinstance(value, MACData):
            self._mac_data = value
        else:
            raise TypeError("mac_data must be MACData type")

    def read(self, istream):
        super(MACResponsePayload, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        if self.is_tag_next(Tags.UNIQUE_IDENTIFIER, tstream):
            self._unique_identifier = attributes.UniqueIdentifier()
            self._unique_identifier.read(tstream)
        else:
            raise exceptions.InvalidKmipEncoding(
                "expected mac response unique identifier not found"
            )

        if self.is_tag_next(Tags.MAC_DATA, tstream):
            self._mac_data = MACData()
            self._mac_data.read(tstream)
        else:
            raise exceptions.InvalidKmipEncoding(
                "expected mac response mac data not found"
            )

        self.is_oversized(tstream)

    def write(self, ostream):
        tstream = BytearrayStream()

        if self._unique_identifier is not None:
            self._unique_identifier.write(tstream)
        else:
            raise exceptions.InvalidField(
                "The mac response unique identifier is required"
            )
        if self._mac_data is not None:
            self._mac_data.write(tstream)
        else:
            raise exceptions.InvalidField(
                "The mac response mac data is required"
            )
        self.length = tstream.length()
        super(MACResponsePayload, self).write(ostream)
        ostream.write(tstream.buffer)
