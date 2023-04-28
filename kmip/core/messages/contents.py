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

import six

from kmip.core import enums
from kmip.core import objects
from kmip.core import utils

from kmip.core import primitives
from kmip.core.primitives import Struct
from kmip.core.primitives import Integer
from kmip.core.primitives import Enumeration
from kmip.core.primitives import Boolean
from kmip.core.primitives import TextString
from kmip.core.primitives import ByteString
from kmip.core.primitives import DateTime


class ProtocolVersion(primitives.Struct):
    """
    A struct representing a ProtocolVersion number.

    Attributes:
        major: The major protocol version number.
        minor: The minor protocol version number.
    """

    def __init__(self, major=None, minor=None):
        """
        Construct a ProtocolVersion struct.

        Args:
            major (int): The major protocol version number. Optional, defaults
                to None.
            minor (int): The minor protocol version number. Optional, defaults
                to None.
        """
        super(ProtocolVersion, self).__init__(enums.Tags.PROTOCOL_VERSION)

        self._major = None
        self._minor = None

        self.major = major
        self.minor = minor

    @property
    def major(self):
        if self._major:
            return self._major.value
        else:
            return None

    @major.setter
    def major(self, value):
        if value is None:
            self._major = None
        elif isinstance(value, six.integer_types):
            self._major = primitives.Integer(
                value=value,
                tag=enums.Tags.PROTOCOL_VERSION_MAJOR
            )
        else:
            raise TypeError(
                "Major protocol version number must be an integer."
            )

    @property
    def minor(self):
        if self._minor:
            return self._minor.value
        else:
            return None

    @minor.setter
    def minor(self, value):
        if value is None:
            self._minor = None
        elif isinstance(value, six.integer_types):
            self._minor = primitives.Integer(
                value=value,
                tag=enums.Tags.PROTOCOL_VERSION_MINOR
            )
        else:
            raise TypeError(
                "Minor protocol version number must be an integer."
            )

    def read(self, input_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the ProtocolVersion struct and decode it into
        its constituent parts.

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            ValueError: Raised if either the major or minor protocol versions
                are missing from the encoding.
        """
        super(ProtocolVersion, self).read(
            input_stream,
            kmip_version=kmip_version
        )
        local_stream = utils.BytearrayStream(input_stream.read(self.length))

        if self.is_tag_next(enums.Tags.PROTOCOL_VERSION_MAJOR, local_stream):
            self._major = primitives.Integer(
                tag=enums.Tags.PROTOCOL_VERSION_MAJOR
            )
            self._major.read(local_stream, kmip_version=kmip_version)
        else:
            raise ValueError(
                "Invalid encoding missing the major protocol version number."
            )

        if self.is_tag_next(enums.Tags.PROTOCOL_VERSION_MINOR, local_stream):
            self._minor = primitives.Integer(
                tag=enums.Tags.PROTOCOL_VERSION_MINOR
            )
            self._minor.read(local_stream, kmip_version=kmip_version)
        else:
            raise ValueError(
                "Invalid encoding missing the minor protocol version number."
            )

        self.is_oversized(local_stream)

    def write(self, output_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the ProtocolVersion struct to a stream.

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

        if self._major:
            self._major.write(local_stream, kmip_version=kmip_version)
        else:
            raise ValueError(
                "Invalid struct missing the major protocol version number."
            )

        if self._minor:
            self._minor.write(local_stream, kmip_version=kmip_version)
        else:
            raise ValueError(
                "Invalid struct missing the minor protocol version number."
            )

        self.length = local_stream.length()
        super(ProtocolVersion, self).write(
            output_stream,
            kmip_version=kmip_version
        )
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, ProtocolVersion):
            if self.major != other.major:
                return False
            elif self.minor != other.minor:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, ProtocolVersion):
            return not (self == other)
        else:
            return NotImplemented

    def __lt__(self, other):
        if isinstance(other, ProtocolVersion):
            if self.major < other.major:
                return True
            elif self.major > other.major:
                return False
            elif self.minor < other.minor:
                return True
            else:
                return False
        else:
            return NotImplemented

    def __gt__(self, other):
        if isinstance(other, ProtocolVersion):
            if (self == other) or (self < other):
                return False
            else:
                return True
        else:
            return NotImplemented

    def __le__(self, other):
        if isinstance(other, ProtocolVersion):
            if (self == other) or (self < other):
                return True
            else:
                return False
        else:
            return NotImplemented

    def __ge__(self, other):
        if isinstance(other, ProtocolVersion):
            if (self == other) or (self > other):
                return True
            else:
                return False
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "major={}".format(self.major),
            "minor={}".format(self.minor)
        ])
        return "ProtocolVersion({})".format(args)

    def __str__(self):
        return "{}.{}".format(self.major, self.minor)


def protocol_version_to_kmip_version(value):
    """
    Convert a ProtocolVersion struct to its KMIPVersion enumeration equivalent.

    Args:
        value (ProtocolVersion): A ProtocolVersion struct to be converted into
            a KMIPVersion enumeration.

    Returns:
        KMIPVersion: The enumeration equivalent of the struct. If the struct
            cannot be converted to a valid enumeration, None is returned.
    """
    if not isinstance(value, ProtocolVersion):
        return None

    if value.major == 1:
        if value.minor == 0:
            return enums.KMIPVersion.KMIP_1_0
        elif value.minor == 1:
            return enums.KMIPVersion.KMIP_1_1
        elif value.minor == 2:
            return enums.KMIPVersion.KMIP_1_2
        elif value.minor == 3:
            return enums.KMIPVersion.KMIP_1_3
        elif value.minor == 4:
            return enums.KMIPVersion.KMIP_1_4
        else:
            return None
    elif value.major == 2:
        if value.minor == 0:
            return enums.KMIPVersion.KMIP_2_0
        else:
            return None
    else:
        return None


# 6.2
class Operation(Enumeration):

    def __init__(self, value=None):
        super(Operation, self).__init__(
            enums.Operation, value, enums.Tags.OPERATION)


# 6.3
class MaximumResponseSize(Integer):
    def __init__(self, value=None):
        super(MaximumResponseSize, self).\
            __init__(value, enums.Tags.MAXIMUM_RESPONSE_SIZE)


# 6.4
class UniqueBatchItemID(ByteString):
    def __init__(self, value=None):
        super(UniqueBatchItemID, self)\
            .__init__(value, enums.Tags.UNIQUE_BATCH_ITEM_ID)


# 6.5
class TimeStamp(DateTime):
    def __init__(self, value=None):
        super(TimeStamp, self).__init__(value, enums.Tags.TIME_STAMP)


class Authentication(Struct):
    """
    A struct representing an Authentication bundle.

    Attributes:
        credentials: A list of Credential structs to be used for
            authentication.
    """

    def __init__(self, credentials=None):
        """
        Construct an Authentication struct.

        Args:
            credentials (list): A list of Credential structs to be used for
                authentication. Optional, defaults to None.
        """
        super(Authentication, self).__init__(enums.Tags.AUTHENTICATION)

        self._credentials = []
        self.credentials = credentials

    @property
    def credentials(self):
        return self._credentials

    @credentials.setter
    def credentials(self, value):
        if value is None:
            self._credentials = []
        elif isinstance(value, list):
            credentials = []
            for i in range(len(value)):
                credential = value[i]
                if not isinstance(credential, objects.Credential):
                    raise TypeError(
                        "Credentials must be a list of Credential structs. "
                        "Item {} has type: {}".format(i + 1, type(credential))
                    )
                credentials.append(credential)
            self._credentials = credentials
        else:
            raise TypeError(
                "Credentials must be a list of Credential structs."
            )

    def read(self, input_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the Authentication struct and decode it into
        its constituent parts.

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.
        """
        super(Authentication, self).read(
            input_stream,
            kmip_version=kmip_version
        )
        local_stream = utils.BytearrayStream(input_stream.read(self.length))

        credentials = []
        while self.is_tag_next(enums.Tags.CREDENTIAL, local_stream):
            credential = objects.Credential()
            credential.read(local_stream, kmip_version=kmip_version)
            credentials.append(credential)
        if len(credentials) == 0:
            raise ValueError("Authentication encoding missing credentials.")
        self._credentials = credentials

        self.is_oversized(local_stream)

    def write(self, output_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the Authentication struct to a stream.

        Args:
            output_stream (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.
        """
        local_stream = utils.BytearrayStream()

        if len(self._credentials) == 0:
            raise ValueError("Authentication struct missing credentials.")
        for credential in self._credentials:
            credential.write(local_stream, kmip_version=kmip_version)

        self.length = local_stream.length()
        super(Authentication, self).write(
            output_stream,
            kmip_version=kmip_version
        )
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, Authentication):
            if self.credentials != other.credentials:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, Authentication):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "credentials={}".format([x for x in self.credentials])
        ])
        return "Authentication({})".format(args)

    def __str__(self):
        credentials = ", ".join([str(x) for x in self.credentials])
        return "{'credentials': [" + credentials + "]}"


# 6.7
class AsynchronousIndicator(Boolean):
    def __init__(self, value=None):
        super(AsynchronousIndicator, self).\
            __init__(value, enums.Tags.ASYNCHRONOUS_INDICATOR)


# 6.8
class AsynchronousCorrelationValue(ByteString):
    def __init__(self, value=None):
        super(AsynchronousCorrelationValue, self).\
            __init__(value, enums.Tags.ASYNCHRONOUS_CORRELATION_VALUE)


# 6.9
class ResultStatus(Enumeration):

    def __init__(self, value=None):
        super(ResultStatus, self).__init__(
            enums.ResultStatus, value, enums.Tags.RESULT_STATUS)


# 6.10
class ResultReason(Enumeration):

    def __init__(self, value=None):
        super(ResultReason, self).__init__(
            enums.ResultReason, value, enums.Tags.RESULT_REASON)


# 6.11
class ResultMessage(TextString):
    def __init__(self, value=None):
        super(ResultMessage, self).__init__(value, enums.Tags.RESULT_MESSAGE)


# 6.12
class BatchOrderOption(Boolean):
    def __init__(self, value=None):
        super(BatchOrderOption, self).\
            __init__(value, enums.Tags.BATCH_ORDER_OPTION)


# 6.13
class BatchErrorContinuationOption(Enumeration):

    def __init__(self, value=None):
        super(BatchErrorContinuationOption, self).__init__(
            enums.BatchErrorContinuationOption, value,
            enums.Tags.BATCH_ERROR_CONTINUATION_OPTION)


# 6.14
class BatchCount(Integer):
    def __init__(self, value=None):
        super(BatchCount, self).__init__(value, enums.Tags.BATCH_COUNT)


# 6.16
class MessageExtension(Struct):
    def __init__(self):
        super(MessageExtension, self).__init__(enums.Tags.MESSAGE_EXTENSION)


# 6.19
class ServerCorrelationValue(TextString):
    def __init__(self, value=None):
        super(ServerCorrelationValue, self).__init__(
            value, enums.Tags.SERVER_CORRELATION_VALUE)


# 9.1.3.2.2
class KeyCompressionType(Enumeration):

    def __init__(self, value=None):
        super(KeyCompressionType, self).__init__(
            enums.KeyCompressionType, value, enums.Tags.KEY_COMPRESSION_TYPE)
