# Copyright (c) 2026 The Johns Hopkins University/Applied Physics Laboratory
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

import testtools

from kmip.core import enums
from kmip.core import exceptions


def _build_exception_instances():
    status = enums.ResultStatus.OPERATION_FAILED
    reason = enums.ResultReason.GENERAL_FAILURE

    return [
        exceptions.KmipError(status, reason, "base"),
        exceptions.CryptographicFailure("crypto"),
        exceptions.EncodingOptionError("encoding"),
        exceptions.IllegalOperation("illegal"),
        exceptions.IndexOutOfBounds("index"),
        exceptions.InvalidField("invalid field"),
        exceptions.InvalidMessage("invalid message"),
        exceptions.ItemNotFound("not found"),
        exceptions.KeyCompressionTypeNotSupported("compression"),
        exceptions.KeyFormatTypeNotSupported("format"),
        exceptions.OperationFailure(status, reason, "operation failed"),
        exceptions.OperationNotSupported("op not supported"),
        exceptions.PermissionDenied("denied"),
        exceptions.AttributeNotSupported("attr"),
        exceptions.ConfigurationError("config"),
        exceptions.ConnectionClosed("closed"),
        exceptions.NetworkingError("network"),
        exceptions.InvalidKmipEncoding("encoding"),
        exceptions.InvalidPaddingBytes("padding"),
        exceptions.InvalidPrimitiveLength("length"),
        exceptions.ShutdownError("shutdown"),
        exceptions.VersionNotSupported("version"),
        exceptions.StreamNotEmptyError("Foo", 7),
        exceptions.ReadValueError("Foo", "bar", "exp", "recv"),
        exceptions.WriteOverflowError("Foo", "bar", 1, 2),
        exceptions.KMIPServerZombieError(123),
        exceptions.KMIPServerSuicideError(321)
    ]


class TestExceptionsExtended(testtools.TestCase):
    def test_each_exception_class_init(self):
        for exc in _build_exception_instances():
            self.assertIsInstance(exc, Exception)

    def test_each_exception_str_repr(self):
        for exc in _build_exception_instances():
            self.assertIsInstance(str(exc), str)
            self.assertIsInstance(repr(exc), str)

    def test_exception_hierarchy(self):
        kmip_subclasses = [
            exceptions.CryptographicFailure,
            exceptions.EncodingOptionError,
            exceptions.IllegalOperation,
            exceptions.IndexOutOfBounds,
            exceptions.InvalidField,
            exceptions.InvalidMessage,
            exceptions.ItemNotFound,
            exceptions.KeyCompressionTypeNotSupported,
            exceptions.KeyFormatTypeNotSupported,
            exceptions.OperationFailure,
            exceptions.OperationNotSupported,
            exceptions.PermissionDenied
        ]
        for cls in kmip_subclasses:
            instance = cls("message") if cls is not exceptions.OperationFailure \
                else cls(enums.ResultStatus.OPERATION_FAILED,
                         enums.ResultReason.GENERAL_FAILURE,
                         "operation failed")
            self.assertIsInstance(instance, exceptions.KmipError)

    def test_kmip_operation_failure_attributes(self):
        status = enums.ResultStatus.OPERATION_FAILED
        reason = enums.ResultReason.GENERAL_FAILURE
        message = "operation failed"
        exc = exceptions.OperationFailure(status, reason, message)
        self.assertEqual(status, exc.status)
        self.assertEqual(reason, exc.reason)
        self.assertEqual(message, str(exc))
        self.assertEqual(message, exc.args[0])

    def test_stream_not_empty_error_str(self):
        exc = exceptions.StreamNotEmptyError("Foo", 3)
        self.assertEqual(
            "Invalid length used to read Foo, bytes remaining: 3",
            str(exc)
        )

    def test_read_value_error_str(self):
        exc = exceptions.ReadValueError("Foo", "bar", "exp", "recv")
        self.assertEqual(
            "Tried to read Foo.bar: expected exp, received recv",
            str(exc)
        )

    def test_write_overflow_error_str(self):
        exc = exceptions.WriteOverflowError("Foo", "bar", 1, 2)
        self.assertEqual(
            "Tried to write Foo.bar with too many bytes: expected 1, "
            "received 2",
            str(exc)
        )

    def test_kmip_server_errors_str(self):
        zombie = exceptions.KMIPServerZombieError(10)
        suicide = exceptions.KMIPServerSuicideError(20)
        self.assertEqual(
            "KMIP server alive after termination: PID 10",
            str(zombie)
        )
        self.assertEqual(
            "KMIP server dead prematurely: PID 20",
            str(suicide)
        )
