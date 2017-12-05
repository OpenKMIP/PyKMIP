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


class CancelRequestPayload(primitives.Struct):
    """
    A request payload for the Cancel operation.

    Attributes:
        asynchronous_correlation_value: The unique ID, in bytes, of the
            operation to cancel.
    """

    def __init__(self, asynchronous_correlation_value=None):
        """
        Construct a Cancel request payload struct.

        Args:
            asynchronous_correlation_value (bytes): The ID of a pending
                operation to cancel, in bytes. Optional, defaults to None.
        """
        super(CancelRequestPayload, self).__init__(
            enums.Tags.REQUEST_PAYLOAD
        )

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
        elif isinstance(value, six.binary_type):
            self._asynchronous_correlation_value = primitives.ByteString(
                value=value,
                tag=enums.Tags.ASYNCHRONOUS_CORRELATION_VALUE
            )
        else:
            raise TypeError("Asynchronous correlation value must be bytes.")

    def read(self, input_stream):
        """
        Read the data encoding the Cancel request payload and decode it into
        its constituent parts.

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.

        Raises:
            ValueError: Raised if the data attribute is missing from the
                encoded payload.
        """
        super(CancelRequestPayload, self).read(input_stream)
        local_stream = utils.BytearrayStream(input_stream.read(self.length))

        if self.is_tag_next(
                enums.Tags.ASYNCHRONOUS_CORRELATION_VALUE,
                local_stream
        ):
            self._asynchronous_correlation_value = primitives.ByteString(
                tag=enums.Tags.ASYNCHRONOUS_CORRELATION_VALUE
            )
            self._asynchronous_correlation_value.read(local_stream)

        self.is_oversized(local_stream)

    def write(self, output_stream):
        """
        Write the data encoding the Cancel request payload to a stream.

        Args:
            output_stream (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.

        Raises:
            ValueError: Raised if the data attribute is not defined.
        """
        local_stream = utils.BytearrayStream()

        if self._asynchronous_correlation_value:
            self._asynchronous_correlation_value.write(local_stream)

        self.length = local_stream.length()
        super(CancelRequestPayload, self).write(output_stream)
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, CancelRequestPayload):
            if self.asynchronous_correlation_value != \
                    other.asynchronous_correlation_value:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, CancelRequestPayload):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = "asynchronous_correlation_value={0}".format(
            self.asynchronous_correlation_value
        )
        return "CancelRequestPayload({0})".format(args)

    def __str__(self):
        return str({
            'asynchronous_correlation_value':
                self.asynchronous_correlation_value
        })


class CancelResponsePayload(primitives.Struct):
    """
    A response payload for the Cancel operation.

    Attributes:
        asynchronous_correlation_value: The unique ID, in bytes, of the
            operation that was cancelled.
        cancellation_result: The result of canceling the operation.
    """

    def __init__(self,
                 asynchronous_correlation_value=None,
                 cancellation_result=None):
        """
        Construct a Cancel response payload struct.

        Args:
            asynchronous_correlation_value (bytes): The ID of a pending
                operation that was cancelled, in bytes. Optional, defaults to
                None.
            cancellation_result (enum): A CancellationResult enumeration
                specifying the result of canceling the operation. Optional,
                defaults to None.
        """
        super(CancelResponsePayload, self).__init__(
            enums.Tags.RESPONSE_PAYLOAD
        )

        self._asynchronous_correlation_value = None
        self._cancellation_result = None

        self.asynchronous_correlation_value = asynchronous_correlation_value
        self.cancellation_result = cancellation_result

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
        elif isinstance(value, six.binary_type):
            self._asynchronous_correlation_value = primitives.ByteString(
                value=value,
                tag=enums.Tags.ASYNCHRONOUS_CORRELATION_VALUE
            )
        else:
            raise TypeError("Asynchronous correlation value must be bytes.")

    @property
    def cancellation_result(self):
        if self._cancellation_result:
            return self._cancellation_result.value
        else:
            return None

    @cancellation_result.setter
    def cancellation_result(self, value):
        if value is None:
            self._cancellation_result = None
        elif isinstance(value, enums.CancellationResult):
            self._cancellation_result = primitives.Enumeration(
                enums.CancellationResult,
                value=value,
                tag=enums.Tags.CANCELLATION_RESULT
            )
        else:
            raise TypeError(
                "Cancellation result must be a CancellationResult enumeration."
            )

    def read(self, input_stream):
        """
        Read the data encoding the Cancel response payload and decode it into
        its constituent parts.

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.

        Raises:
            ValueError: Raised if the data attribute is missing from the
                encoded payload.
        """
        super(CancelResponsePayload, self).read(input_stream)
        local_stream = utils.BytearrayStream(input_stream.read(self.length))

        if self.is_tag_next(
                enums.Tags.ASYNCHRONOUS_CORRELATION_VALUE,
                local_stream
        ):
            self._asynchronous_correlation_value = primitives.ByteString(
                tag=enums.Tags.ASYNCHRONOUS_CORRELATION_VALUE
            )
            self._asynchronous_correlation_value.read(local_stream)
        if self.is_tag_next(enums.Tags.CANCELLATION_RESULT, local_stream):
            self._cancellation_result = primitives.Enumeration(
                enums.CancellationResult,
                tag=enums.Tags.CANCELLATION_RESULT
            )
            self._cancellation_result.read(local_stream)

        self.is_oversized(local_stream)

    def write(self, output_stream):
        """
        Write the data encoding the Cancel response payload to a stream.

        Args:
            output_stream (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.

        Raises:
            ValueError: Raised if the data attribute is not defined.
        """
        local_stream = utils.BytearrayStream()

        if self._asynchronous_correlation_value:
            self._asynchronous_correlation_value.write(local_stream)
        if self._cancellation_result:
            self._cancellation_result.write(local_stream)

        self.length = local_stream.length()
        super(CancelResponsePayload, self).write(output_stream)
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, CancelResponsePayload):
            if self.asynchronous_correlation_value != \
                    other.asynchronous_correlation_value:
                return False
            elif self.cancellation_result != other.cancellation_result:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, CancelResponsePayload):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "asynchronous_correlation_value={0}".format(
                self.asynchronous_correlation_value
            ),
            "cancellation_result={0}".format(self.cancellation_result)
        ])
        return "CancelResponsePayload({0})".format(args)

    def __str__(self):
        return str({
            'asynchronous_correlation_value':
                self.asynchronous_correlation_value,
            'cancellation_result': self.cancellation_result
        })
