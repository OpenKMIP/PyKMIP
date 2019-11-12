# Copyright (c) 2017 The Johns Hopkins University/Applied Physics Laboratory
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

import six

from kmip import enums
from kmip.core import primitives
from kmip.core import utils
from kmip.core.messages.payloads import base


class ArchiveRequestPayload(base.RequestPayload):
    """
    A request payload for the Archive operation.

    Attributes:
        unique_identifier: The unique ID of the object to archive.
    """

    def __init__(self, unique_identifier=None):
        """
        Construct an Archive request payload struct.

        Args:
            unique_identifier (string): The ID of the managed object (e.g.,
                a public key) to archive. Optional, defaults to None.
        """
        super(ArchiveRequestPayload, self).__init__()

        self._unique_identifier = None
        self.unique_identifier = unique_identifier

    @property
    def unique_identifier(self):
        if self._unique_identifier:
            return self._unique_identifier.value
        else:
            return None

    @unique_identifier.setter
    def unique_identifier(self, value):
        if value is None:
            self._unique_identifier = None
        elif isinstance(value, six.string_types):
            self._unique_identifier = primitives.TextString(
                value=value,
                tag=enums.Tags.UNIQUE_IDENTIFIER
            )
        else:
            raise TypeError("Unique identifier must be a string.")

    def read(self, input_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the Archive request payload and decode it into
        its constituent parts.

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            ValueError: Raised if the data attribute is missing from the
                encoded payload.
        """
        super(ArchiveRequestPayload, self).read(
            input_stream,
            kmip_version=kmip_version
        )
        local_stream = utils.BytearrayStream(input_stream.read(self.length))

        if self.is_tag_next(enums.Tags.UNIQUE_IDENTIFIER, local_stream):
            self._unique_identifier = primitives.TextString(
                tag=enums.Tags.UNIQUE_IDENTIFIER
            )
            self._unique_identifier.read(
                local_stream,
                kmip_version=kmip_version
            )

        self.is_oversized(local_stream)

    def write(self, output_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the Archive request payload to a stream.

        Args:
            output_stream (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            ValueError: Raised if the data attribute is not defined.
        """
        local_stream = utils.BytearrayStream()

        if self._unique_identifier:
            self._unique_identifier.write(
                local_stream,
                kmip_version=kmip_version
            )

        self.length = local_stream.length()
        super(ArchiveRequestPayload, self).write(
            output_stream,
            kmip_version=kmip_version
        )
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, ArchiveRequestPayload):
            if self.unique_identifier != other.unique_identifier:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, ArchiveRequestPayload):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = "unique_identifier='{0}'".format(self.unique_identifier)
        return "ArchiveRequestPayload({0})".format(args)

    def __str__(self):
        return str({
            'unique_identifier': self.unique_identifier
        })


class ArchiveResponsePayload(base.ResponsePayload):
    """
    A response payload for the Archive operation.

    Attributes:
        unique_identifier: The unique ID of the object that was archived.
    """

    def __init__(self, unique_identifier=None):
        """
        Construct an Archive response payload struct.

        Args:
            unique_identifier (string): The ID of the managed object (e.g.,
                a public key) that was archived. Optional, defaults to None.
        """
        super(ArchiveResponsePayload, self).__init__()

        self._unique_identifier = None
        self.unique_identifier = unique_identifier

    @property
    def unique_identifier(self):
        if self._unique_identifier:
            return self._unique_identifier.value
        else:
            return None

    @unique_identifier.setter
    def unique_identifier(self, value):
        if value is None:
            self._unique_identifier = None
        elif isinstance(value, six.string_types):
            self._unique_identifier = primitives.TextString(
                value=value,
                tag=enums.Tags.UNIQUE_IDENTIFIER
            )
        else:
            raise TypeError("Unique identifier must be a string.")

    def read(self, input_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the Archive response payload and decode it
        into its constituent parts.

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            ValueError: Raised if the data attribute is missing from the
                encoded payload.
        """
        super(ArchiveResponsePayload, self).read(
            input_stream,
            kmip_version=kmip_version
        )
        local_stream = utils.BytearrayStream(input_stream.read(self.length))

        if self.is_tag_next(enums.Tags.UNIQUE_IDENTIFIER, local_stream):
            self._unique_identifier = primitives.TextString(
                tag=enums.Tags.UNIQUE_IDENTIFIER
            )
            self._unique_identifier.read(
                local_stream,
                kmip_version=kmip_version
            )

        self.is_oversized(local_stream)

    def write(self, output_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the Archive response payload to a stream.

        Args:
            output_stream (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            ValueError: Raised if the data attribute is not defined.
        """
        local_stream = utils.BytearrayStream()

        if self._unique_identifier:
            self._unique_identifier.write(
                local_stream,
                kmip_version=kmip_version
            )

        self.length = local_stream.length()
        super(ArchiveResponsePayload, self).write(
            output_stream,
            kmip_version=kmip_version
        )
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, ArchiveResponsePayload):
            if self.unique_identifier != other.unique_identifier:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, ArchiveResponsePayload):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = "unique_identifier='{0}'".format(self.unique_identifier)
        return "ArchiveResponsePayload({0})".format(args)

    def __str__(self):
        return str({
            'unique_identifier': self.unique_identifier,
        })
