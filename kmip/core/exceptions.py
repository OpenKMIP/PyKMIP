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

    def __eq__(self, other):
        if isinstance(other, KmipError):
            if str(self) != str(other):
                return False
            elif self.status != other.status:
                return False
            elif self.reason != other.reason:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, KmipError):
            return self == other
        else:
            return NotImplemented

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

class EncodingOptionError(KmipError):
    """
    An encoding error generated during key wrapping.

    This error is generated during key wrapping when a requested encoding
    option is not supported or is incompatible with other settings in the
    key wrapping request (e.g., attributes are requested with the key but
    the encoding does not support wrapping attributes with the key value).
    """
    def __init__(self, message):
        """
        Create an EncodingOptionError.

        Args:
            message (string): A string containing information about the error.
        """
        super(EncodingOptionError, self).__init__(
            reason=enums.ResultReason.ENCODING_OPTION_ERROR,
            message=message
        )

class IllegalOperation(KmipError):
    """
    An error generated when an improper operation is attempted. The operation
    can be 'illegal' for various reasons, including invalid permissions or
    literal object/operation mismatch (e.g., a Template item cannot be
    activated with the Activate operation since it has no state).
    """
    def __init__(self, message):
        """
        Create an IllegalOperation exception.

        Args:
            message (string): A string containing information about the error.
        """
        super(IllegalOperation, self).__init__(
            reason=enums.ResultReason.ILLEGAL_OPERATION,
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

class OperationFailure(KmipError):
    """
    An exception raised upon the failure of a KMIP appliance operation.
    """
    def __init__(self, status, reason, message):
        """
        Construct the error message and attributes for the KMIP operation
        failure.

        Args:
            status: a ResultStatus enumeration
            reason: a ResultReason enumeration
            message: a string providing additional error information
        """
        super(OperationFailure, self).__init__(status, reason, message)

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

class AttributeNotSupported(Exception):
    """
    An error generated when an unsupported attribute is processed.
    """
    pass

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

class ShutdownError(Exception):
    """
    An error generated when a problem occurs with shutting down the server.
    """

class VersionNotSupported(Exception):
    """
    An error generated when an unsupported KMIP version is referenced.
    """

class StreamNotEmptyError(Exception):
    def __init__(self, cls, extra):
        super(StreamNotEmptyError, self).__init__()

        self.cls = cls
        self.extra = extra

    def __str__(self):
        msg = "Invalid length used to read {0}, bytes remaining: {1}"
        return msg.format(self.cls, self.extra)

class ReadValueError(Exception):
    def __init__(self, cls, attr, exp, recv):
        super(ReadValueError, self).__init__()

        self.cls = cls
        self.attr = attr
        self.exp = exp
        self.recv = recv

    def __str__(self):
        msg = "Tried to read {0}.{1}: expected {2}, received {3}"
        return msg.format(self.cls, self.attr, self.exp, self.recv)

class WriteOverflowError(Exception):
    def __init__(self, cls, attr, exp, recv):
        super(WriteOverflowError, self).__init__()

        self.cls = cls
        self.attr = attr
        self.exp = exp
        self.recv = recv

    def __str__(self):
        msg = "Tried to write {0}.{1} with too many bytes: "
        msg += "expected {2}, received {3}"
        return msg.format(self.cls, self.attr, self.exp, self.recv)

class KMIPServerZombieError(Exception):
    """KMIP server error for hung and persistent live KMIP servers."""
    def __init__(self, pid):
        super(KMIPServerZombieError, self).__init__()

        self.message = 'KMIP server alive after termination: PID {0}'.format(
            pid
        )

    def __str__(self):
        return self.message

class KMIPServerSuicideError(Exception):
    """KMIP server error for prematurely dead KMIP servers."""
    def __init__(self, pid):
        super(KMIPServerSuicideError, self).__init__()

        self.message = 'KMIP server dead prematurely: PID {0}'.format(pid)

    def __str__(self):
        return self.message

class ErrorStrings:
    BAD_EXP_RECV = "Bad {0} {1}: expected {2}, received {3}"
    BAD_ENCODING = "Bad {0} {1}: encoding mismatch"
