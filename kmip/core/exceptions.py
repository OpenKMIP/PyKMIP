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


class KmipError(Exception):
    """
    A generic KMIP error that is the base for the KMIP error hierarchy.
    """

    def __init__(self,
                 status=enums.ResultStatus.OPERATION_FAILED,
                 reason=enums.ResultReason.GENERAL_FAILURE,
                 message='A general failure occurred.'):
        """
        Create a KmipError exception.

        Args:
            status (ResultStatus): An enumeration detailing the result outcome.
            reason (ResultReason): An enumeration giving the status rationale.
            message (string): A string containing more information about the
                error.
        """
        super(KmipError, self).__init__(message)
        self.status = status
        self.reason = reason


class CryptographicFailure(KmipError):
    """
    An error generated when problems occur with cryptographic operations.
    """

    def __init__(self, message):
        """
        Create a CryptographicFailure exception.

        Args:
            message (string): A string containing information about the error.
        """
        super(CryptographicFailure, self).__init__(
            reason=enums.ResultReason.CRYPTOGRAPHIC_FAILURE,
            message=message
        )


class IndexOutOfBounds(KmipError):
    """
    An error generated when exceeding the attribute instance limit.
    """

    def __init__(self, message):
        """
        Create an IndexOutOfBounds exception.

        Args:
            message (string): A string containing information about the error.
        """
        super(IndexOutOfBounds, self).__init__(
            reason=enums.ResultReason.INDEX_OUT_OF_BOUNDS,
            message=message
        )


class InvalidField(KmipError):
    """
    An error generated when an invalid field value is processed.
    """

    def __init__(self, message):
        """
        Create an InvalidField exception.

        Args:
            message (string): A string containing information about the error.
        """
        super(InvalidField, self).__init__(
            reason=enums.ResultReason.INVALID_FIELD,
            message=message
        )


class InvalidMessage(KmipError):
    """
    An error generated when an invalid message is processed.
    """

    def __init__(self, message):
        """
        Create an InvalidMessage exception.

        Args:
            message (string): A string containing information about the error.
        """
        super(InvalidMessage, self).__init__(
            reason=enums.ResultReason.INVALID_MESSAGE,
            message=message
        )


class ItemNotFound(KmipError):
    """
    An error generated when a request item cannot be located.
    """

    def __init__(self, message):
        """
        Create an ItemNotFound exception.

        Args:
            message (string): A string containing information about the error.
        """
        super(ItemNotFound, self).__init__(
            reason=enums.ResultReason.ITEM_NOT_FOUND,
            message=message
        )


class KeyCompressionTypeNotSupported(KmipError):
    """
    An error generated when dealing with unsupported key compression types
    and operations.
    """

    def __init__(self, message):
        """
        Create a KeyCompressionTypeNotSupported exception.

        Args:
            message (string): A string containing information about the error.
        """
        super(KeyCompressionTypeNotSupported, self).__init__(
            reason=enums.ResultReason.KEY_COMPRESSION_TYPE_NOT_SUPPORTED,
            message=message
        )


class KeyFormatTypeNotSupported(KmipError):
    """
    An error generated when dealing with unsupported key formats
    and operations.
    """

    def __init__(self, message):
        """
        Create a KeyFormatTypeNotSupported exception.

        Args:
            message (string): A string containing information about the error.
        """
        super(KeyFormatTypeNotSupported, self).__init__(
            reason=enums.ResultReason.KEY_FORMAT_TYPE_NOT_SUPPORTED,
            message=message
        )


class OperationNotSupported(KmipError):
    """
    An error generated when an unsupported operation is invoked.
    """

    def __init__(self, message):
        """
        Create an OperationNotSupported exception.

        Args:
            message (string): A string containing information about the error.
        """
        super(OperationNotSupported, self).__init__(
            reason=enums.ResultReason.OPERATION_NOT_SUPPORTED,
            message=message
        )


class PermissionDenied(KmipError):
    """
    An error generated when permission constraints are violated.
    """

    def __init__(self, message):
        """
        Create a PermissionDenied exception.

        Args:
            message (string): A string containing information about the error.
        """
        super(PermissionDenied, self).__init__(
            reason=enums.ResultReason.PERMISSION_DENIED,
            message=message
        )


class ConfigurationError(Exception):
    """
    An error generated when a problem occurs with a client or server
    configuration.
    """
    pass


class ConnectionClosed(Exception):
    """
    An exception generated when attempting to use a connection that has been
    closed.
    """
    pass


class NetworkingError(Exception):
    """
    An error generated when a problem occurs with client or server networking
    activity.
    """
    pass


class InvalidKmipEncoding(Exception):
    """
    An exception raised when processing invalid KMIP message encodings.
    """
    pass


class InvalidPaddingBytes(Exception):
    """
    An exception raised for errors when processing the padding bytes of
    primitive encodings.
    """
    pass


class InvalidPrimitiveLength(Exception):
    """
    An exception raised for errors when processing primitives with invalid
    lengths.
    """
    pass
