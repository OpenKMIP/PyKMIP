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

from kmip.core import enums
from kmip.core import objects
from kmip.core import utils

from kmip.core.primitives import Struct
from kmip.core.primitives import Integer
from kmip.core.primitives import Enumeration
from kmip.core.primitives import Boolean
from kmip.core.primitives import TextString
from kmip.core.primitives import ByteString
from kmip.core.primitives import DateTime


# 6.1
class ProtocolVersion(Struct):

    class ProtocolVersionMajor(Integer):
        def __init__(self, value=None):
            super(self.__class__, self).\
                __init__(value, enums.Tags.PROTOCOL_VERSION_MAJOR)

    class ProtocolVersionMinor(Integer):
        def __init__(self, value=None):
            super(self.__class__, self).\
                __init__(value, enums.Tags.PROTOCOL_VERSION_MINOR)

    def __init__(self,
                 protocol_version_major=None,
                 protocol_version_minor=None):
        super(self.__class__, self).__init__(tag=enums.Tags.PROTOCOL_VERSION)
        self.protocol_version_major = protocol_version_major
        self.protocol_version_minor = protocol_version_minor

    def read(self, istream):
        super(self.__class__, self).read(istream)
        tstream = utils.BytearrayStream(istream.read(self.length))

        # Read the major and minor portions of the version number
        self.protocol_version_major = ProtocolVersion.ProtocolVersionMajor()
        self.protocol_version_minor = ProtocolVersion.ProtocolVersionMinor()
        self.protocol_version_major.read(tstream)
        self.protocol_version_minor.read(tstream)

        self.is_oversized(tstream)

    def write(self, ostream):
        tstream = utils.BytearrayStream()

        # Write the major and minor portions of the protocol version
        self.protocol_version_major.write(tstream)
        self.protocol_version_minor.write(tstream)

        # Write the length and value of the protocol version
        self.length = tstream.length()
        super(self.__class__, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        # TODO (peter-hamilton) Finish implementation.
        pass

    @classmethod
    def create(cls, major, minor):
        major_version = cls.ProtocolVersionMajor(major)
        minor_version = cls.ProtocolVersionMinor(minor)
        return ProtocolVersion(major_version, minor_version)


# 6.2
class Operation(Enumeration):
    ENUM_TYPE = enums.Operation

    def __init__(self, value=None):
        super(self.__class__, self).__init__(value, enums.Tags.OPERATION)


# 6.3
class MaximumResponseSize(Integer):
    def __init__(self, value=None):
        super(self.__class__, self).\
            __init__(value, enums.Tags.MAXIMUM_RESPONSE_SIZE)


# 6.4
class UniqueBatchItemID(ByteString):
    def __init__(self, value=None):
        super(self.__class__, self)\
            .__init__(value, enums.Tags.UNIQUE_BATCH_ITEM_ID)


# 6.5
class TimeStamp(DateTime):
    def __init__(self, value=None):
        super(self.__class__, self).__init__(value, enums.Tags.TIME_STAMP)


# 6.6
class Authentication(Struct):

    def __init__(self, credential=None):
        super(self.__class__, self).__init__(tag=enums.Tags.AUTHENTICATION)
        self.credential = credential

    def read(self, istream):
        super(self.__class__, self).read(istream)
        tstream = utils.BytearrayStream(istream.read(self.length))

        # Read the credential
        self.credential = objects.Credential()
        self.credential.read(tstream)

        self.is_oversized(tstream)

    def write(self, ostream):
        tstream = utils.BytearrayStream()

        # Write the credential
        self.credential.write(tstream)

        # Write the length and value of the protocol version
        self.length = tstream.length()
        super(self.__class__, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        # TODO (peter-hamilton) Finish implementation.
        pass


# 6.7
class AsynchronousIndicator(Boolean):
    def __init__(self, value=None):
        super(self.__class__, self).\
            __init__(value, enums.Tags.ASYNCHRONOUS_INDICATOR)


# 6.8
class AsynchronousCorrelationValue(ByteString):
    def __init__(self, value=None):
        super(self.__class__, self).\
            __init__(value, enums.Tags.ASYNCHRONOUS_CORRELATION_VALUE)


# 6.9
class ResultStatus(Enumeration):
    ENUM_TYPE = enums.ResultStatus

    def __init__(self, value=None):
        super(self.__class__, self).__init__(value, enums.Tags.RESULT_STATUS)


# 6.10
class ResultReason(Enumeration):
    ENUM_TYPE = enums.ResultReason

    def __init__(self, value=None):
        super(self.__class__, self).__init__(value, enums.Tags.RESULT_REASON)


# 6.11
class ResultMessage(TextString):
    def __init__(self, value=None):
        super(self.__class__, self).__init__(value, enums.Tags.RESULT_MESSAGE)


# 6.12
class BatchOrderOption(Boolean):
    def __init__(self, value=None):
        super(self.__class__, self).\
            __init__(value, enums.Tags.BATCH_ORDER_OPTION)


# 6.13
class BatchErrorContinuationOption(Enumeration):
    ENUM_TYPE = enums.BatchErrorContinuationOption

    def __init__(self, value=None):
        super(self.__class__, self).\
            __init__(value, enums.Tags.BATCH_ERROR_CONTINUATION_OPTION)


# 6.14
class BatchCount(Integer):
    def __init__(self, value=None):
        super(self.__class__, self).__init__(value, enums.Tags.BATCH_COUNT)


# 6.16
class MessageExtension(Struct):
    def __init__(self):
        super(self.__class__, self).__init__(tag=enums.Tags.MESSAGE_EXTENSION)


# 9.1.3.2.2
class KeyCompressionType(Enumeration):
    ENUM_TYPE = enums.KeyCompressionType

    def __init__(self, value=None):
        super(self.__class__, self).\
            __init__(value, enums.Tags.KEY_COMPRESSION_TYPE)


# 9.1.3.2.3
class KeyFormatType(Enumeration):
    ENUM_TYPE = enums.KeyFormatType

    def __init__(self, value=None):
        super(self.__class__, self).\
            __init__(value, enums.Tags.KEY_FORMAT_TYPE)
