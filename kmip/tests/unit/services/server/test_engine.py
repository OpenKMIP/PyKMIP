# Copyright (c) 2016 The Johns Hopkins University/Applied Physics Laboratory
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

import mock
import testtools
import time

import kmip

from kmip.core import enums
from kmip.core import exceptions
from kmip.core import misc
from kmip.core import objects

from kmip.core.messages import contents
from kmip.core.messages import messages

from kmip.core.messages.payloads import discover_versions
from kmip.core.messages.payloads import query

from kmip.services.server import engine


class MockRegexString(str):
    """
    A comparator string for doing simple containment regex comparisons
    for mock asserts.
    """
    def __eq__(self, other):
        return self in other


class TestKmipEngine(testtools.TestCase):
    """
    A test suite for the KmipEngine.
    """

    def setUp(self):
        super(TestKmipEngine, self).setUp()

    def tearDown(self):
        super(TestKmipEngine, self).tearDown()

    def _build_request(self):
        payload = discover_versions.DiscoverVersionsRequestPayload()
        batch = [
            messages.RequestBatchItem(
                operation=contents.Operation(
                    enums.Operation.DISCOVER_VERSIONS
                ),
                request_payload=payload
            )
        ]

        protocol = contents.ProtocolVersion.create(1, 0)
        max_size = contents.MaximumResponseSize(2 ** 20)
        asynch = contents.AsynchronousIndicator(False)

        # TODO (peterhamilton) Change this insanity in the substructs.
        username = objects.Credential.UsernamePasswordCredential.Username(
            "tester"
        )
        password = objects.Credential.UsernamePasswordCredential.Password(
            "password"
        )
        creds = objects.Credential.UsernamePasswordCredential(
            username=username,
            password=password
        )
        auth = contents.Authentication(creds)

        batch_error_option = contents.BatchErrorContinuationOption(
            enums.BatchErrorContinuationOption.STOP
        )
        batch_order_option = contents.BatchOrderOption(True)
        timestamp = contents.TimeStamp(int(time.time()))

        header = messages.RequestHeader(
            protocol_version=protocol,
            maximum_response_size=max_size,
            asynchronous_indicator=asynch,
            authentication=auth,
            batch_error_cont_option=batch_error_option,
            batch_order_option=batch_order_option,
            time_stamp=timestamp,
            batch_count=contents.BatchCount(len(batch))
        )

        return messages.RequestMessage(
            request_header=header,
            batch_items=batch
        )

    def test_init(self):
        """
        Test that a KmipEngine can be instantiated without any errors.
        """
        engine.KmipEngine()

    def test_version_operation_match(self):
        """
        Test that a valid response is generated when trying to invoke an
        operation supported by a specific version of KMIP.
        """
        e = engine.KmipEngine()
        e._logger = mock.MagicMock()

        payload = discover_versions.DiscoverVersionsRequestPayload()
        e._process_discover_versions(payload)

    def test_version_operation_mismatch(self):
        """
        Test that an OperationNotSupported error is generated when trying to
        invoke an operation unsupported by a specific version of KMIP.
        """
        e = engine.KmipEngine()
        e._logger = mock.MagicMock()
        e._protocol_version = contents.ProtocolVersion.create(1, 0)

        args = (None, )
        regex = "DiscoverVersions is not supported by KMIP {0}".format(
            e._protocol_version
        )
        self.assertRaisesRegexp(
            exceptions.OperationNotSupported,
            regex,
            e._process_discover_versions,
            *args
        )

    def test_process_request(self):
        """
        Test that a basic request is processed correctly.
        """
        e = engine.KmipEngine()
        e._logger = mock.MagicMock()

        protocol = contents.ProtocolVersion.create(1, 1)
        header = messages.RequestHeader(
            protocol_version=protocol,
            maximum_response_size=contents.MaximumResponseSize(2 ** 20),
            authentication=contents.Authentication(),
            batch_error_cont_option=contents.BatchErrorContinuationOption(
                enums.BatchErrorContinuationOption.STOP
            ),
            batch_order_option=contents.BatchOrderOption(True),
            time_stamp=contents.TimeStamp(int(time.time())),
            batch_count=contents.BatchCount(1)
        )
        payload = discover_versions.DiscoverVersionsRequestPayload()
        batch = list([
            messages.RequestBatchItem(
                operation=contents.Operation(
                    enums.Operation.DISCOVER_VERSIONS
                ),
                request_payload=payload
            )
        ])
        request = messages.RequestMessage(
            request_header=header,
            batch_items=batch
        )

        response, max_size = e.process_request(request)

        e._logger.info.assert_any_call(
            MockRegexString("Received request at time:")
        )
        e._logger.info.assert_any_call(
            "Processing operation: DiscoverVersions"
        )
        self.assertIsInstance(response, messages.ResponseMessage)
        self.assertEqual(2 ** 20, max_size)
        self.assertIsNotNone(response.response_header)

        header = response.response_header

        self.assertIsNotNone(header)
        self.assertEqual(
            contents.ProtocolVersion.create(1, 1),
            header.protocol_version
        )
        self.assertIsInstance(header.time_stamp, contents.TimeStamp)
        self.assertIsInstance(header.batch_count, contents.BatchCount)
        self.assertEqual(1, header.batch_count.value)

        batch = response.batch_items

        self.assertNotEqual(list(), batch)

        batch_item = batch[0]

        self.assertIsInstance(batch_item.operation, contents.Operation)
        self.assertEqual(
            enums.Operation.DISCOVER_VERSIONS,
            batch_item.operation.value
        )
        self.assertIsNone(batch_item.unique_batch_item_id)
        self.assertEqual(
            enums.ResultStatus.SUCCESS,
            batch_item.result_status.value
        )
        self.assertIsNone(batch_item.result_reason)
        self.assertIsNone(batch_item.result_message)
        self.assertIsNone(batch_item.async_correlation_value)
        self.assertIsInstance(
            batch_item.response_payload,
            discover_versions.DiscoverVersionsResponsePayload
        )
        self.assertIsNone(batch_item.message_extension)

    def test_process_request_unsupported_version(self):
        """
        Test that an InvalidMessage exception is raised when processing a
        request using an unsupported KMIP version.
        """
        e = engine.KmipEngine()
        e._logger = mock.MagicMock()

        protocol = contents.ProtocolVersion.create(0, 1)
        header = messages.RequestHeader(
            protocol_version=protocol
        )
        request = messages.RequestMessage(
            request_header=header
        )

        args = (request, )
        regex = "KMIP {0} is not supported by the server.".format(
            protocol
        )
        self.assertRaisesRegexp(
            exceptions.InvalidMessage,
            regex,
            e.process_request,
            *args
        )

    def test_process_request_stale_timestamp(self):
        """
        Test that an InvalidMessage exception is raised when processing a
        request with a stale timestamp.
        """
        e = engine.KmipEngine()
        e._logger = mock.MagicMock()

        protocol = contents.ProtocolVersion.create(1, 0)
        header = messages.RequestHeader(
            protocol_version=protocol,
            time_stamp=contents.TimeStamp(0)
        )
        request = messages.RequestMessage(
            request_header=header
        )

        args = (request, )
        regex = "Stale request rejected by server."
        self.assertRaisesRegexp(
            exceptions.InvalidMessage,
            regex,
            e.process_request,
            *args
        )

        e._logger.warning.assert_any_call(
            MockRegexString(
                "Received request with old timestamp. Possible replay attack."
            )
        )

    def test_process_request_future_timestamp(self):
        """
        Test that an InvalidMessage exception is raised when processing a
        request with a future timestamp.
        """
        e = engine.KmipEngine()
        e._logger = mock.MagicMock()

        protocol = contents.ProtocolVersion.create(1, 0)
        header = messages.RequestHeader(
            protocol_version=protocol,
            time_stamp=contents.TimeStamp(10 ** 10)
        )
        request = messages.RequestMessage(
            request_header=header
        )

        args = (request, )
        regex = "Future request rejected by server."
        self.assertRaisesRegexp(
            exceptions.InvalidMessage,
            regex,
            e.process_request,
            *args
        )

        e._logger.warning.assert_any_call(
            MockRegexString(
                "Received request with future timestamp."
            )
        )

    def test_process_request_unsupported_async_indicator(self):
        """
        Test than an InvalidMessage error is generated while processing a
        batch with an unsupported asynchronous indicator option.
        """
        e = engine.KmipEngine()
        e._logger = mock.MagicMock()

        protocol = contents.ProtocolVersion.create(1, 1)
        header = messages.RequestHeader(
            protocol_version=protocol,
            asynchronous_indicator=contents.AsynchronousIndicator(True)
        )
        request = messages.RequestMessage(
            request_header=header,
        )

        args = (request, )
        regex = "Asynchronous operations are not supported."
        self.assertRaisesRegexp(
            exceptions.InvalidMessage,
            regex,
            e.process_request,
            *args
        )

    def test_process_request_unsupported_batch_option(self):
        """
        Test that an InvalidMessage error is generated while processing a
        batch with an unsupported batch error continuation option.
        """
        e = engine.KmipEngine()
        e._logger = mock.MagicMock()

        protocol = contents.ProtocolVersion.create(1, 1)
        header = messages.RequestHeader(
            protocol_version=protocol,
            authentication=contents.Authentication(),
            batch_error_cont_option=contents.BatchErrorContinuationOption(
                enums.BatchErrorContinuationOption.UNDO
            )
        )
        request = messages.RequestMessage(
            request_header=header,
        )

        args = (request, )
        regex = "Undo option for batch handling is not supported."
        self.assertRaisesRegexp(
            exceptions.InvalidMessage,
            regex,
            e.process_request,
            *args
        )

    def test_build_error_response(self):
        """
        Test that a bare bones response containing a single error result can
        be constructed correctly.
        """
        e = engine.KmipEngine()
        e._logger = mock.MagicMock()

        response = e.build_error_response(
            contents.ProtocolVersion.create(1, 1),
            enums.ResultReason.GENERAL_FAILURE,
            "A general test failure occurred."
        )

        self.assertIsInstance(response, messages.ResponseMessage)

        header = response.response_header

        self.assertEqual(
            contents.ProtocolVersion.create(1, 1),
            header.protocol_version
        )
        self.assertIsNotNone(header.time_stamp)
        self.assertIsNotNone(header.batch_count)
        self.assertEqual(1, header.batch_count.value)

        batch = response.batch_items

        self.assertEqual(1, len(batch))

        batch_item = batch[0]

        self.assertIsNone(batch_item.operation)
        self.assertIsNone(batch_item.unique_batch_item_id)
        self.assertEqual(
            enums.ResultStatus.OPERATION_FAILED,
            batch_item.result_status.value
        )
        self.assertEqual(
            enums.ResultReason.GENERAL_FAILURE,
            batch_item.result_reason.value
        )
        self.assertEqual(
            "A general test failure occurred.",
            batch_item.result_message.value
        )
        self.assertIsNone(batch_item.async_correlation_value)
        self.assertIsNone(batch_item.response_payload)
        self.assertIsNone(batch_item.message_extension)

    def test_process_batch(self):
        """
        Test that a batch is processed correctly.
        """
        e = engine.KmipEngine()
        e._logger = mock.MagicMock()

        payload = discover_versions.DiscoverVersionsRequestPayload()
        batch = list([
            messages.RequestBatchItem(
                operation=contents.Operation(
                    enums.Operation.DISCOVER_VERSIONS
                ),
                request_payload=payload
            )
        ])

        results = e._process_batch(
            batch,
            enums.BatchErrorContinuationOption.STOP,
            True
        )

        self.assertIsNotNone(results)
        self.assertEqual(1, len(results))

    def test_process_multibatch(self):
        """
        Test that a batch containing multiple operations is processed
        correctly.
        """
        e = engine.KmipEngine()
        e._logger = mock.MagicMock()

        payload = discover_versions.DiscoverVersionsRequestPayload()
        batch = list([
            messages.RequestBatchItem(
                operation=contents.Operation(
                    enums.Operation.DISCOVER_VERSIONS
                ),
                unique_batch_item_id=contents.UniqueBatchItemID(1),
                request_payload=payload
            ),
            messages.RequestBatchItem(
                operation=contents.Operation(
                    enums.Operation.DISCOVER_VERSIONS
                ),
                unique_batch_item_id=contents.UniqueBatchItemID(2),
                request_payload=payload
            )
        ])

        results = e._process_batch(
            batch,
            enums.BatchErrorContinuationOption.STOP,
            True
        )

        self.assertIsNotNone(results)
        self.assertEqual(2, len(results))

    def test_process_batch_missing_batch_id(self):
        """
        Test that an InvalidMessage error is generated while processing a
        batch with missing batch IDs.
        """
        e = engine.KmipEngine()
        e._logger = mock.MagicMock()

        batch = list([
            messages.RequestBatchItem(),
            messages.RequestBatchItem()
        ])

        args = (batch, None, None)
        self.assertRaisesRegexp(
            exceptions.InvalidMessage,
            "Batch item ID is undefined.",
            e._process_batch,
            *args
        )

    def test_process_batch_expected_error(self):
        """
        Test than an expected KMIP error is handled appropriately while
        processing a batch of operations.
        """
        e = engine.KmipEngine()
        e._logger = mock.MagicMock()
        e._protocol_version = contents.ProtocolVersion.create(1, 0)

        batch = list([
            messages.RequestBatchItem(
                operation=contents.Operation(
                    enums.Operation.DISCOVER_VERSIONS
                )
            )
        ])

        results = e._process_batch(
            batch,
            enums.BatchErrorContinuationOption.STOP,
            True
        )

        self.assertIsNotNone(results)
        self.assertEqual(1, len(results))

        result = results[0]

        self.assertIsInstance(result, messages.ResponseBatchItem)
        self.assertIsNotNone(result.operation)
        self.assertEqual(
            enums.Operation.DISCOVER_VERSIONS,
            result.operation.value
        )
        self.assertIsNone(result.unique_batch_item_id)
        self.assertIsNotNone(result.result_status)
        self.assertEqual(
            enums.ResultStatus.OPERATION_FAILED,
            result.result_status.value
        )
        self.assertIsNotNone(result.result_reason)
        self.assertEqual(
            enums.ResultReason.OPERATION_NOT_SUPPORTED,
            result.result_reason.value
        )
        self.assertIsNotNone(result.result_message)
        error_message = "DiscoverVersions is not supported by KMIP {0}".format(
            e._protocol_version
        )
        self.assertEqual(error_message, result.result_message.value)
        self.assertIsNone(result.async_correlation_value)
        self.assertIsNone(result.response_payload)
        self.assertIsNone(result.message_extension)

    def test_process_batch_unexpected_error(self):
        """
        Test that an unexpected, non-KMIP error is handled appropriately
        while processing a batch of operations.
        """
        e = engine.KmipEngine()
        e._logger = mock.MagicMock()

        test_exception = Exception("A general test failure occurred.")
        e._process_operation = mock.MagicMock(side_effect=test_exception)

        batch = list([
            messages.RequestBatchItem(
                operation=contents.Operation(
                    enums.Operation.DISCOVER_VERSIONS
                )
            )
        ])

        results = e._process_batch(
            batch,
            enums.BatchErrorContinuationOption.STOP,
            True
        )

        self.assertIsNotNone(results)
        self.assertEqual(1, len(results))

        result = results[0]

        e._logger.warning.assert_called_with(
            "Error occurred while processing operation."
        )
        e._logger.exception.assert_called_with(test_exception)
        self.assertIsInstance(result, messages.ResponseBatchItem)
        self.assertIsNotNone(result.operation)
        self.assertEqual(
            enums.Operation.DISCOVER_VERSIONS,
            result.operation.value
        )
        self.assertIsNone(result.unique_batch_item_id)
        self.assertIsNotNone(result.result_status)
        self.assertEqual(
            enums.ResultStatus.OPERATION_FAILED,
            result.result_status.value
        )
        self.assertIsNotNone(result.result_reason)
        self.assertEqual(
            enums.ResultReason.GENERAL_FAILURE,
            result.result_reason.value
        )
        self.assertIsNotNone(result.result_message)
        self.assertEqual(
            "Operation failed. See the server logs for more information.",
            result.result_message.value
        )
        self.assertIsNone(result.async_correlation_value)
        self.assertIsNone(result.response_payload)
        self.assertIsNone(result.message_extension)

    def test_supported_operation(self):
        """
        Test that the right subroutine is called when invoking operations
        supported by the server.
        """
        e = engine.KmipEngine()
        e._logger = mock.MagicMock()

        e._process_query = mock.MagicMock()
        e._process_discover_versions = mock.MagicMock()

        e._process_operation(enums.Operation.QUERY, None)
        e._process_operation(enums.Operation.DISCOVER_VERSIONS, None)

        e._process_query.assert_called_with(None)
        e._process_discover_versions.assert_called_with(None)

    def test_unsupported_operation(self):
        """
        Test that an OperationNotSupported error is generated when invoking
        an operation not supported by the server.
        """
        e = engine.KmipEngine()
        e._logger = mock.MagicMock()

        args = (enums.Operation.POLL, None)
        regex = "{0} operation is not supported by the server.".format(
            args[0].name.title()
        )
        self.assertRaisesRegexp(
            exceptions.OperationNotSupported,
            regex,
            e._process_operation,
            *args
        )

    def test_query(self):
        """
        Test that a Query request can be processed correctly, for different
        versions of KMIP.
        """
        e = engine.KmipEngine()

        # Test for KMIP 1.0.
        e._logger = mock.MagicMock()
        e._protocol_version = contents.ProtocolVersion.create(1, 0)

        payload = query.QueryRequestPayload([
            misc.QueryFunction(enums.QueryFunction.QUERY_OPERATIONS),
            misc.QueryFunction(enums.QueryFunction.QUERY_OBJECTS),
            misc.QueryFunction(
                enums.QueryFunction.QUERY_SERVER_INFORMATION
            ),
            misc.QueryFunction(
                enums.QueryFunction.QUERY_APPLICATION_NAMESPACES
            ),
            misc.QueryFunction(enums.QueryFunction.QUERY_EXTENSION_LIST),
            misc.QueryFunction(enums.QueryFunction.QUERY_EXTENSION_MAP)
        ])

        result = e._process_query(payload)

        e._logger.info.assert_called_once_with("Processing operation: Query")
        self.assertIsInstance(result, query.QueryResponsePayload)
        self.assertIsNotNone(result.operations)
        self.assertEqual(1, len(result.operations))
        self.assertEqual(enums.Operation.QUERY, result.operations[0].value)
        self.assertEqual(list(), result.object_types)
        self.assertIsNotNone(result.vendor_identification)
        self.assertEqual(
            "PyKMIP {0} Software Server".format(kmip.__version__),
            result.vendor_identification.value
        )
        self.assertIsNone(result.server_information)
        self.assertEqual(list(), result.application_namespaces)
        self.assertEqual(list(), result.extension_information)

        # Test for KMIP 1.1.
        e._logger = mock.MagicMock()
        e._protocol_version = contents.ProtocolVersion.create(1, 1)

        result = e._process_query(payload)

        e._logger.info.assert_called_once_with("Processing operation: Query")
        self.assertIsNotNone(result.operations)
        self.assertEqual(2, len(result.operations))
        self.assertEqual(enums.Operation.QUERY, result.operations[0].value)
        self.assertEqual(
            enums.Operation.DISCOVER_VERSIONS,
            result.operations[1].value
        )

    def test_discover_versions(self):
        """
        Test that a DiscoverVersions request can be processed correctly for
        different inputs.
        """
        e = engine.KmipEngine()

        # Test default request.
        e._logger = mock.MagicMock()
        payload = discover_versions.DiscoverVersionsRequestPayload()

        result = e._process_discover_versions(payload)

        e._logger.info.assert_called_once_with(
            "Processing operation: DiscoverVersions"
        )
        self.assertIsInstance(
            result,
            discover_versions.DiscoverVersionsResponsePayload
        )
        self.assertIsNotNone(result.protocol_versions)
        self.assertEqual(3, len(result.protocol_versions))
        self.assertEqual(
            contents.ProtocolVersion.create(1, 2),
            result.protocol_versions[0]
        )
        self.assertEqual(
            contents.ProtocolVersion.create(1, 1),
            result.protocol_versions[1]
        )
        self.assertEqual(
            contents.ProtocolVersion.create(1, 0),
            result.protocol_versions[2]
        )

        # Test detailed request.
        e._logger = mock.MagicMock()
        payload = discover_versions.DiscoverVersionsRequestPayload([
            contents.ProtocolVersion.create(1, 0)
        ])

        result = e._process_discover_versions(payload)

        e._logger.info.assert_called_once_with(
            "Processing operation: DiscoverVersions"
        )
        self.assertIsNotNone(result.protocol_versions)
        self.assertEqual(1, len(result.protocol_versions))
        self.assertEqual(
            contents.ProtocolVersion.create(1, 0),
            result.protocol_versions[0]
        )

        # Test disjoint request.
        e._logger = mock.MagicMock()
        payload = discover_versions.DiscoverVersionsRequestPayload([
            contents.ProtocolVersion.create(0, 1)
        ])

        result = e._process_discover_versions(payload)

        e._logger.info.assert_called_once_with(
            "Processing operation: DiscoverVersions"
        )
        self.assertEqual([], result.protocol_versions)
