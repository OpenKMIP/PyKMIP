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

from kmip import enums
from kmip.core import primitives
from kmip.core import utils
from kmip.core.messages.payloads import base

class PollRequestPayload(base.RequestPayload):
    """
    A request payload for the Poll operation.

    Attributes:
        asynchronous_correlation_value: The unique ID, in bytes, of the
            operation to poll.
    """

    def __init__(self, asynchronous_correlation_value=None):
        """
        Construct a Poll request payload struct.

        Args:
            asynchronous_correlation_value (bytes): The ID of a pending
                operation to poll the status of, in bytes. Optional, defaults
                to None.
        """
        super(PollRequestPayload, self).__init__()

        self._asynchronous_correlation_value = None
        self.asynchronous_correlation_value = asynchronous_correlation_value

    @property
    def asynchronous_correlation_value(self):
        if self._asynchronous_correlation_value:
            return self._asynchronous_correlation_value.value
        else:
            return None

    @asynchronous_correlation_value.setter
    def asynchronous_correlation_value(self, value):
        if value is None:
            self._asynchronous_correlation_value = None
        elif isinstance(value, bytes):
            self._asynchronous_correlation_value = primitives.ByteString(
                value=value,
                tag=enums.Tags.ASYNCHRONOUS_CORRELATION_VALUE
            )
        else:
            raise TypeError("Asynchronous correlation value must be bytes.")

    def read(self, input_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the Poll request payload and decode it into
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
        super(PollRequestPayload, self).read(
            input_stream,
            kmip_version=kmip_version
        )
        local_stream = utils.BytearrayStream(input_stream.read(self.length))

        if self.is_tag_next(
                enums.Tags.ASYNCHRONOUS_CORRELATION_VALUE,
                local_stream
        ):
            self._asynchronous_correlation_value = primitives.ByteString(
                tag=enums.Tags.ASYNCHRONOUS_CORRELATION_VALUE
            )
            self._asynchronous_correlation_value.read(
                local_stream,
                kmip_version=kmip_version
            )

        self.is_oversized(local_stream)

    def write(self, output_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the Poll request payload to a stream.

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

        if self._asynchronous_correlation_value:
            self._asynchronous_correlation_value.write(
                local_stream,
                kmip_version=kmip_version
            )

        self.length = local_stream.length()
        super(PollRequestPayload, self).write(
            output_stream,
            kmip_version=kmip_version
        )
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, PollRequestPayload):
            if self.asynchronous_correlation_value != \
                    other.asynchronous_correlation_value:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, PollRequestPayload):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = "asynchronous_correlation_value={0}".format(
            self.asynchronous_correlation_value
        )
        return "PollRequestPayload({0})".format(args)

    def __str__(self):
        return str({
            'asynchronous_correlation_value':
                self.asynchronous_correlation_value
        })
