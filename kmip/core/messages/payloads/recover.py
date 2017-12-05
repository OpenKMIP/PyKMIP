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


class RecoverRequestPayload(primitives.Struct):
    """
    A request payload for the Recover operation.

    Attributes:
        unique_identifier: The unique ID of the object to recover.
    """

    def __init__(self, unique_identifier=None):
        """
        Construct a Recover request payload struct.

        Args:
            unique_identifier (string): The ID of the managed object (e.g.,
                a public key) to recover. Optional, defaults to None.
        """
        super(RecoverRequestPayload, self).__init__(
            enums.Tags.REQUEST_PAYLOAD
        )

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

    def read(self, input_stream):
        """
        Read the data encoding the Recover request payload and decode it into
        its constituent parts.

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.

        Raises:
            ValueError: Raised if the data attribute is missing from the
                encoded payload.
        """
        super(RecoverRequestPayload, self).read(input_stream)
        local_stream = utils.BytearrayStream(input_stream.read(self.length))

        if self.is_tag_next(enums.Tags.UNIQUE_IDENTIFIER, local_stream):
            self._unique_identifier = primitives.TextString(
                tag=enums.Tags.UNIQUE_IDENTIFIER
            )
            self._unique_identifier.read(local_stream)

        self.is_oversized(local_stream)

    def write(self, output_stream):
        """
        Write the data encoding the Recover request payload to a stream.

        Args:
            output_stream (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.

        Raises:
            ValueError: Raised if the data attribute is not defined.
        """
        local_stream = utils.BytearrayStream()

        if self._unique_identifier:
            self._unique_identifier.write(local_stream)

        self.length = local_stream.length()
        super(RecoverRequestPayload, self).write(output_stream)
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, RecoverRequestPayload):
            if self.unique_identifier != other.unique_identifier:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, RecoverRequestPayload):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = "unique_identifier='{0}'".format(self.unique_identifier)
        return "RecoverRequestPayload({0})".format(args)

    def __str__(self):
        return str({
            'unique_identifier': self.unique_identifier
        })


class RecoverResponsePayload(primitives.Struct):
    """
    A response payload for the Recover operation.

    Attributes:
        unique_identifier: The unique ID of the object that was recovered.
    """

    def __init__(self, unique_identifier=None):
        """
        Construct a Recover response payload struct.

        Args:
            unique_identifier (string): The ID of the managed object (e.g.,
                a public key) that was recovered. Optional, defaults to None.
        """
        super(RecoverResponsePayload, self).__init__(
            enums.Tags.RESPONSE_PAYLOAD
        )

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

    def read(self, input_stream):
        """
        Read the data encoding the Recover response payload and decode it
        into its constituent parts.

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.

        Raises:
            ValueError: Raised if the data attribute is missing from the
                encoded payload.
        """
        super(RecoverResponsePayload, self).read(input_stream)
        local_stream = utils.BytearrayStream(input_stream.read(self.length))

        if self.is_tag_next(enums.Tags.UNIQUE_IDENTIFIER, local_stream):
            self._unique_identifier = primitives.TextString(
                tag=enums.Tags.UNIQUE_IDENTIFIER
            )
            self._unique_identifier.read(local_stream)

        self.is_oversized(local_stream)

    def write(self, output_stream):
        """
        Write the data encoding the Recover response payload to a stream.

        Args:
            output_stream (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.

        Raises:
            ValueError: Raised if the data attribute is not defined.
        """
        local_stream = utils.BytearrayStream()

        if self._unique_identifier:
            self._unique_identifier.write(local_stream)

        self.length = local_stream.length()
        super(RecoverResponsePayload, self).write(output_stream)
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, RecoverResponsePayload):
            if self.unique_identifier != other.unique_identifier:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, RecoverResponsePayload):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = "unique_identifier='{0}'".format(self.unique_identifier)
        return "RecoverResponsePayload({0})".format(args)

    def __str__(self):
        return str({
            'unique_identifier': self.unique_identifier,
        })
