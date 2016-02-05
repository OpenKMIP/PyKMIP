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
            message=message)


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
            message=message)


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
