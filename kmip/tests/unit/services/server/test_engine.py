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

import six
import mock
import shutil
import sqlalchemy

from sqlalchemy.orm import exc

import tempfile
import testtools
import time

import kmip

from kmip.core import attributes
from kmip.core import enums
from kmip.core import exceptions
from kmip.core import misc
from kmip.core import objects
from kmip.core import primitives
from kmip.core import secrets

from kmip.core.factories import attributes as factory

from kmip.core.messages import contents
from kmip.core.messages import messages
from kmip.core.messages import payloads

from kmip.pie import objects as pie_objects
from kmip.pie import sqltypes

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

        self.engine = sqlalchemy.create_engine(
            'sqlite:///:memory:',
        )
        sqltypes.Base.metadata.create_all(self.engine)
        self.session_factory = sqlalchemy.orm.sessionmaker(
            bind=self.engine,
            expire_on_commit=False
        )

        self.temp_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.temp_dir)

    def tearDown(self):
        super(TestKmipEngine, self).tearDown()

    def _build_request(self):
        payload = payloads.DiscoverVersionsRequestPayload()
        batch = [
            messages.RequestBatchItem(
                operation=contents.Operation(
                    enums.Operation.DISCOVER_VERSIONS
                ),
                request_payload=payload
            )
        ]

        protocol = contents.ProtocolVersion(1, 0)
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

    @mock.patch('sqlalchemy.create_engine')
    def test_init_create_engine(self, create_engine_mock):
        """
        Test that the right arguments are used to create the engine's SQLite
        backend.
        """
        engine.KmipEngine()
        args = ("sqlite:////tmp/pykmip.database",)
        fargs = {
            'echo': False,
            'connect_args': {'check_same_thread': False}
        }
        create_engine_mock.assert_called_once_with(*args, **fargs)

    def test_version_operation_match(self):
        """
        Test that a valid response is generated when trying to invoke an
        operation supported by a specific version of KMIP.
        """
        e = engine.KmipEngine()
        e._logger = mock.MagicMock()

        payload = payloads.DiscoverVersionsRequestPayload()
        e._process_discover_versions(payload)

    def test_version_operation_mismatch(self):
        """
        Test that an OperationNotSupported error is generated when trying to
        invoke an operation unsupported by a specific version of KMIP.
        """
        e = engine.KmipEngine()
        e._logger = mock.MagicMock()
        e._protocol_version = contents.ProtocolVersion(1, 0)

        args = (None, )
        regex = "DiscoverVersions is not supported by KMIP {0}".format(
            e._protocol_version
        )
        six.assertRaisesRegex(
            self,
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

        protocol = contents.ProtocolVersion(1, 1)
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
        payload = payloads.DiscoverVersionsRequestPayload()
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
            contents.ProtocolVersion(1, 1),
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
            payloads.DiscoverVersionsResponsePayload
        )
        self.assertIsNone(batch_item.message_extension)

    def test_process_request_unsupported_version(self):
        """
        Test that an InvalidMessage exception is raised when processing a
        request using an unsupported KMIP version.
        """
        e = engine.KmipEngine()
        e._logger = mock.MagicMock()

        protocol = contents.ProtocolVersion(0, 1)
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
        six.assertRaisesRegex(
            self,
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

        protocol = contents.ProtocolVersion(1, 0)
        header = messages.RequestHeader(
            protocol_version=protocol,
            time_stamp=contents.TimeStamp(0)
        )
        request = messages.RequestMessage(
            request_header=header
        )

        args = (request, )
        regex = "Stale request rejected by server."
        six.assertRaisesRegex(
            self,
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

        protocol = contents.ProtocolVersion(1, 0)
        header = messages.RequestHeader(
            protocol_version=protocol,
            time_stamp=contents.TimeStamp(10 ** 10)
        )
        request = messages.RequestMessage(
            request_header=header
        )

        args = (request, )
        regex = "Future request rejected by server."
        six.assertRaisesRegex(
            self,
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

        protocol = contents.ProtocolVersion(1, 1)
        header = messages.RequestHeader(
            protocol_version=protocol,
            asynchronous_indicator=contents.AsynchronousIndicator(True)
        )
        request = messages.RequestMessage(
            request_header=header,
        )

        args = (request, )
        regex = "Asynchronous operations are not supported."
        six.assertRaisesRegex(
            self,
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

        protocol = contents.ProtocolVersion(1, 1)
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
        six.assertRaisesRegex(
            self,
            exceptions.InvalidMessage,
            regex,
            e.process_request,
            *args
        )

    def test_process_request_missing_credential(self):
        """
        Test that the engine does not immediately error out when retrieving
        a non-existent credential from the request.
        """
        e = engine.KmipEngine()
        e._logger = mock.MagicMock()

        protocol = contents.ProtocolVersion(1, 1)
        header = messages.RequestHeader(
            protocol_version=protocol,
            authentication=None,
            batch_error_cont_option=contents.BatchErrorContinuationOption(
                enums.BatchErrorContinuationOption.STOP
            ),
            batch_order_option=contents.BatchOrderOption(True),
            time_stamp=contents.TimeStamp(int(time.time())),
            batch_count=contents.BatchCount(1)
        )
        payload = payloads.DiscoverVersionsRequestPayload()
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

        e.process_request(request)

    def test_build_error_response(self):
        """
        Test that a bare bones response containing a single error result can
        be constructed correctly.
        """
        e = engine.KmipEngine()
        e._logger = mock.MagicMock()

        response = e.build_error_response(
            contents.ProtocolVersion(1, 1),
            enums.ResultReason.GENERAL_FAILURE,
            "A general test failure occurred."
        )

        self.assertIsInstance(response, messages.ResponseMessage)

        header = response.response_header

        self.assertEqual(
            contents.ProtocolVersion(1, 1),
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

        payload = payloads.DiscoverVersionsRequestPayload()
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

        payload = payloads.DiscoverVersionsRequestPayload()
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
        six.assertRaisesRegex(
            self,
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
        e._protocol_version = contents.ProtocolVersion(1, 0)

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

    def test_process_operation(self):
        """
        Test that the right subroutine is called when invoking operations
        supported by the server.
        """
        e = engine.KmipEngine()
        e._logger = mock.MagicMock()

        e._process_create = mock.MagicMock()
        e._process_create_key_pair = mock.MagicMock()
        e._process_register = mock.MagicMock()
        e._process_locate = mock.MagicMock()
        e._process_get = mock.MagicMock()
        e._process_get_attributes = mock.MagicMock()
        e._process_get_attribute_list = mock.MagicMock()
        e._process_activate = mock.MagicMock()
        e._process_revoke = mock.MagicMock()
        e._process_destroy = mock.MagicMock()
        e._process_query = mock.MagicMock()
        e._process_discover_versions = mock.MagicMock()
        e._process_encrypt = mock.MagicMock()
        e._process_decrypt = mock.MagicMock()
        e._process_signature_verify = mock.MagicMock()
        e._process_mac = mock.MagicMock()
        e._process_sign = mock.MagicMock()

        e._process_operation(enums.Operation.CREATE, None)
        e._process_operation(enums.Operation.CREATE_KEY_PAIR, None)
        e._process_operation(enums.Operation.REGISTER, None)
        e._process_operation(enums.Operation.LOCATE, None)
        e._process_operation(enums.Operation.GET, None)
        e._process_operation(enums.Operation.GET_ATTRIBUTES, None)
        e._process_operation(enums.Operation.GET_ATTRIBUTE_LIST, None)
        e._process_operation(enums.Operation.ACTIVATE, None)
        e._process_operation(enums.Operation.REVOKE, None)
        e._process_operation(enums.Operation.DESTROY, None)
        e._process_operation(enums.Operation.QUERY, None)
        e._process_operation(enums.Operation.DISCOVER_VERSIONS, None)
        e._process_operation(enums.Operation.ENCRYPT, None)
        e._process_operation(enums.Operation.DECRYPT, None)
        e._process_operation(enums.Operation.SIGN, None)
        e._process_operation(enums.Operation.SIGNATURE_VERIFY, None)
        e._process_operation(enums.Operation.MAC, None)

        e._process_create.assert_called_with(None)
        e._process_create_key_pair.assert_called_with(None)
        e._process_register.assert_called_with(None)
        e._process_locate.assert_called_with(None)
        e._process_get.assert_called_with(None)
        e._process_get_attributes.assert_called_with(None)
        e._process_get_attribute_list.assert_called_with(None)
        e._process_activate.assert_called_with(None)
        e._process_revoke.assert_called_with(None)
        e._process_destroy.assert_called_with(None)
        e._process_query.assert_called_with(None)
        e._process_discover_versions.assert_called_with(None)
        e._process_encrypt.assert_called_with(None)
        e._process_decrypt.assert_called_with(None)
        e._process_signature_verify.assert_called_with(None)
        e._process_mac.assert_called_with(None)

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
        six.assertRaisesRegex(
            self,
            exceptions.OperationNotSupported,
            regex,
            e._process_operation,
            *args
        )

    def test_get_object_type(self):
        """
        Test that the object type of a stored object can be retrieved
        correctly.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()

        obj_a = pie_objects.OpaqueObject(b'', enums.OpaqueDataType.NONE)

        e._data_session.add(obj_a)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        id_a = str(obj_a.unique_identifier)

        object_type = e._get_object_type(id_a)
        e._data_session.commit()

        self.assertEqual(pie_objects.OpaqueObject, object_type)

    def test_get_object_type_missing_object(self):
        """
        Test that an ItemNotFound error is generated when attempting to
        retrieve the object type of an object that does not exist.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()

        args = ('1', )
        regex = "Could not locate object: 1"
        six.assertRaisesRegex(
            self,
            exceptions.ItemNotFound,
            regex,
            e._get_object_type,
            *args
        )
        e._data_session.commit()
        e._logger.warning.assert_called_once_with(
            "Could not identify object type for object: 1"
        )

    def test_get_object_type_multiple_objects(self):
        """
        Test that a sqlalchemy.orm.exc.MultipleResultsFound error is generated
        when getting the object type of multiple objects map to the same
        object ID.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        test_exception = exc.MultipleResultsFound()
        e._data_session.query = mock.MagicMock(side_effect=test_exception)
        e._logger = mock.MagicMock()

        args = ('1', )
        self.assertRaises(
            exc.MultipleResultsFound,
            e._get_object_type,
            *args
        )
        e._data_session.commit()
        e._logger.warning.assert_called_once_with(
            "Multiple objects found for ID: 1"
        )

    def test_get_object_type_unsupported_type(self):
        """
        Test that an InvalidField error is generated when attempting to
        get the object type of an object with an unsupported object type.
        This should never happen by definition, but "Safety first!"
        """
        e = engine.KmipEngine()
        e._object_map = {enums.ObjectType.OPAQUE_DATA: None}
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()

        obj_a = pie_objects.OpaqueObject(b'', enums.OpaqueDataType.NONE)

        e._data_session.add(obj_a)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        id_a = str(obj_a.unique_identifier)

        args = (id_a, )
        name = enums.ObjectType.OPAQUE_DATA.name
        regex = "The {0} object type is not supported.".format(
            ''.join(
                [x.capitalize() for x in name.split('_')]
            )
        )

        six.assertRaisesRegex(
            self,
            exceptions.InvalidField,
            regex,
            e._get_object_type,
            *args
        )
        e._data_session.commit()

    def test_build_core_object(self):
        """
        Test that kmip.core objects can be built from simpler kmip.pie
        objects.
        """
        e = engine.KmipEngine()
        e._logger = mock.MagicMock()

        # Test building a Certificate.
        managed_object = pie_objects.X509Certificate(value=b'')
        core_object = e._build_core_object(managed_object)

        self.assertIsInstance(core_object, secrets.Certificate)
        self.assertEqual(
            b'',
            core_object.certificate_value.value
        )
        self.assertEqual(
            enums.CertificateType.X_509,
            core_object.certificate_type.value
        )

        # Test building a Symmetric Key.
        managed_object = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            0,
            b''
        )
        core_object = e._build_core_object(managed_object)

        self.assertIsInstance(core_object, secrets.SymmetricKey)
        self.assertEqual(
            enums.CryptographicAlgorithm.AES,
            core_object.key_block.cryptographic_algorithm.value
        )
        self.assertEqual(
            0,
            core_object.key_block.cryptographic_length.value
        )
        self.assertEqual(
            b'',
            core_object.key_block.key_value.key_material.value
        )

        # Test building a Public Key.
        managed_object = pie_objects.PublicKey(
            enums.CryptographicAlgorithm.RSA,
            0,
            b''
        )
        core_object = e._build_core_object(managed_object)

        self.assertIsInstance(core_object, secrets.PublicKey)
        self.assertEqual(
            enums.CryptographicAlgorithm.RSA,
            core_object.key_block.cryptographic_algorithm.value
        )
        self.assertEqual(
            0,
            core_object.key_block.cryptographic_length.value
        )
        self.assertEqual(
            b'',
            core_object.key_block.key_value.key_material.value
        )

        # Test building a Private Key.
        managed_object = pie_objects.PrivateKey(
            enums.CryptographicAlgorithm.RSA,
            0,
            b'',
            enums.KeyFormatType.PKCS_8
        )
        core_object = e._build_core_object(managed_object)

        self.assertIsInstance(core_object, secrets.PrivateKey)
        self.assertEqual(
            enums.CryptographicAlgorithm.RSA,
            core_object.key_block.cryptographic_algorithm.value
        )
        self.assertEqual(
            0,
            core_object.key_block.cryptographic_length.value
        )
        self.assertEqual(
            b'',
            core_object.key_block.key_value.key_material.value
        )
        self.assertEqual(
            enums.KeyFormatType.PKCS_8,
            core_object.key_block.key_format_type.value
        )

        # Test building a Secret Data.
        managed_object = pie_objects.SecretData(
            b'',
            enums.SecretDataType.PASSWORD
        )
        core_object = e._build_core_object(managed_object)

        self.assertIsInstance(core_object, secrets.SecretData)
        self.assertEqual(
            enums.SecretDataType.PASSWORD,
            core_object.secret_data_type.value
        )
        self.assertEqual(
            b'',
            core_object.key_block.key_value.key_material.value
        )

        # Test building an Opaque Data.
        managed_object = pie_objects.OpaqueObject(
            b'',
            enums.OpaqueDataType.NONE
        )
        core_object = e._build_core_object(managed_object)

        self.assertIsInstance(core_object, secrets.OpaqueObject)
        self.assertEqual(
            enums.OpaqueDataType.NONE,
            core_object.opaque_data_type.value
        )
        self.assertEqual(
            b'',
            core_object.opaque_data_value.value
        )

    def test_build_core_object_unsupported_type(self):
        """
        Test that an InvalidField error is generated when building
        kmip.core objects that are unsupported.
        """
        e = engine.KmipEngine()
        e._logger = mock.MagicMock()

        args = (None, )
        regex = "Cannot build an unsupported object type."
        six.assertRaisesRegex(
            self,
            exceptions.InvalidField,
            regex,
            e._build_core_object,
            *args
        )

        class DummyObject:
            def __init__(self):
                self._object_type = enums.ObjectType.SPLIT_KEY

        args = (DummyObject(), )
        regex = "The SplitKey object type is not supported."
        six.assertRaisesRegex(
            self,
            exceptions.InvalidField,
            regex,
            e._build_core_object,
            *args
        )

    def test_process_template_attribute(self):
        """
        Test that a template attribute structure can be processed correctly.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._logger = mock.MagicMock()

        attribute_factory = factory.AttributeFactory()

        name = attribute_factory.create_attribute(
            enums.AttributeType.NAME,
            attributes.Name.create(
                'Test Symmetric Key',
                enums.NameType.UNINTERPRETED_TEXT_STRING
            )
        )
        algorithm = attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
            enums.CryptographicAlgorithm.AES
        )
        length = attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
            128
        )
        mask = attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
            [
                enums.CryptographicUsageMask.ENCRYPT,
                enums.CryptographicUsageMask.DECRYPT
            ]
        )
        template_attribute = objects.TemplateAttribute(
            attributes=[name, algorithm, length, mask]
        )

        result = e._process_template_attribute(template_attribute)

        self.assertIsInstance(result, dict)
        self.assertEqual(4, len(result.keys()))
        self.assertIn('Name', result.keys())
        self.assertIn('Cryptographic Algorithm', result.keys())
        self.assertIn('Cryptographic Length', result.keys())
        self.assertIn('Cryptographic Usage Mask', result.keys())

        self.assertEqual([name.attribute_value], result.get('Name'))
        self.assertEqual(
            algorithm.attribute_value,
            result.get('Cryptographic Algorithm')
        )
        self.assertEqual(
            length.attribute_value,
            result.get('Cryptographic Length')
        )
        self.assertEqual(
            mask.attribute_value,
            result.get('Cryptographic Usage Mask')
        )

    def test_process_template_attribute_unsupported_features(self):
        """
        Test that the right errors are generated when unsupported features
        are referenced while processing a template attribute.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._logger = mock.MagicMock()

        attribute_factory = factory.AttributeFactory()

        # Test that providing template names generates an InvalidField error.
        template_attribute = objects.TemplateAttribute(
            names=[
                attributes.Name.create(
                    'invalid',
                    enums.NameType.UNINTERPRETED_TEXT_STRING
                )
            ]
        )

        args = (template_attribute, )
        regex = "Attribute templates are not supported."
        six.assertRaisesRegex(
            self,
            exceptions.ItemNotFound,
            regex,
            e._process_template_attribute,
            *args
        )

        # Test that an unrecognized attribute generates an InvalidField error.
        name = attribute_factory.create_attribute(
            enums.AttributeType.NAME,
            attributes.Name.create(
                'Test Symmetric Key',
                enums.NameType.UNINTERPRETED_TEXT_STRING
            )
        )
        name.attribute_name.value = 'invalid'
        template_attribute = objects.TemplateAttribute(attributes=[name])

        args = (template_attribute, )
        regex = "The invalid attribute is unsupported."
        six.assertRaisesRegex(
            self,
            exceptions.InvalidField,
            regex,
            e._process_template_attribute,
            *args
        )

        # Test that missing indices generate an InvalidField error.
        name_a = attribute_factory.create_attribute(
            enums.AttributeType.NAME,
            attributes.Name.create(
                'Test Symmetric Key',
                enums.NameType.UNINTERPRETED_TEXT_STRING
            )
        )
        name_b = attribute_factory.create_attribute(
            enums.AttributeType.NAME,
            attributes.Name.create(
                'Test Symmetric Key',
                enums.NameType.UNINTERPRETED_TEXT_STRING
            )
        )

        template_attribute = objects.TemplateAttribute(
            attributes=[name_a, name_b]
        )

        args = (template_attribute, )
        regex = "Attribute index missing from multivalued attribute."
        six.assertRaisesRegex(
            self,
            exceptions.InvalidField,
            regex,
            e._process_template_attribute,
            *args
        )

        # Test that a non-zero index generates an InvalidField error.
        algorithm = attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
            enums.CryptographicAlgorithm.AES,
            1
        )
        template_attribute = objects.TemplateAttribute(attributes=[algorithm])

        args = (template_attribute, )
        regex = "Non-zero attribute index found for single-valued attribute."
        six.assertRaisesRegex(
            self,
            exceptions.InvalidField,
            regex,
            e._process_template_attribute,
            *args
        )

        # Test that setting multiple values for a single-value attribute
        # generates an InvalidField error.
        algorithm_a = attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
            enums.CryptographicAlgorithm.AES
        )
        algorithm_b = attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
            enums.CryptographicAlgorithm.TRIPLE_DES
        )

        template_attribute = objects.TemplateAttribute(
            attributes=[algorithm_a, algorithm_b]
        )

        args = (template_attribute, )
        regex = (
            "Cannot set multiple instances of the Cryptographic Algorithm "
            "attribute."
        )
        six.assertRaisesRegex(
            self,
            exceptions.IndexOutOfBounds,
            regex,
            e._process_template_attribute,
            *args
        )

    def test_get_attributes_from_managed_object(self):
        """
        Test that multiple attributes can be retrieved from a given managed
        object.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()

        symmetric_key = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            0,
            b'',
            masks=[enums.CryptographicUsageMask.ENCRYPT,
                   enums.CryptographicUsageMask.DECRYPT]
        )
        symmetric_key.names = ['Name 1', 'Name 2']

        e._data_session.add(symmetric_key)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        result = e._get_attributes_from_managed_object(
            symmetric_key,
            ['Unique Identifier',
             'Name',
             'Cryptographic Algorithm',
             'Cryptographic Length',
             'Cryptographic Usage Mask',
             'invalid']
        )
        attribute_factory = factory.AttributeFactory()

        self.assertEqual(6, len(result))

        attribute = attribute_factory.create_attribute(
            enums.AttributeType.UNIQUE_IDENTIFIER,
            '1'
        )
        self.assertIn(attribute, result)

        attribute = attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
            enums.CryptographicAlgorithm.AES
        )
        self.assertIn(attribute, result)

        attribute = attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
            0
        )
        self.assertIn(attribute, result)

        attribute = attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
            [enums.CryptographicUsageMask.ENCRYPT,
             enums.CryptographicUsageMask.DECRYPT]
        )
        self.assertIn(attribute, result)

    def test_get_attributes_from_managed_object_with_missing_attribute(self):
        """
        Test that any exceptions are suppressed when attempting to retrieve
        non-existent attributes from managed objects.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()

        symmetric_key = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            0,
            b'',
            masks=[enums.CryptographicUsageMask.ENCRYPT,
                   enums.CryptographicUsageMask.DECRYPT]
        )
        symmetric_key.names = ['Name 1', 'Name 2']

        e._data_session.add(symmetric_key)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._get_attribute_from_managed_object = mock.Mock()
        e._get_attribute_from_managed_object.side_effect = Exception

        result = e._get_attributes_from_managed_object(
            symmetric_key,
            ['Unique Identifier',
             'Name',
             'Cryptographic Algorithm',
             'Cryptographic Length',
             'Cryptographic Usage Mask',
             'invalid']
        )

        self.assertEqual(0, len(result))

    def test_get_attribute_from_managed_object(self):
        """
        Test that an attribute can be retrieved from a given managed object.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._logger = mock.MagicMock()

        symmetric_key = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            0,
            b'',
            masks=[enums.CryptographicUsageMask.ENCRYPT,
                   enums.CryptographicUsageMask.DECRYPT]
        )
        certificate = pie_objects.X509Certificate(
            b''
        )
        opaque_object = pie_objects.OpaqueObject(
            b'',
            enums.OpaqueDataType.NONE
        )

        e._data_session.add(symmetric_key)
        e._data_session.add(certificate)
        e._data_session.add(opaque_object)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        result = e._get_attribute_from_managed_object(
            symmetric_key,
            'Unique Identifier'
        )
        self.assertEqual('1', result)

        result = e._get_attribute_from_managed_object(
            symmetric_key,
            'Name'
        )
        self.assertEqual(
            [attributes.Name(
                attributes.Name.NameValue('Symmetric Key'),
                attributes.Name.NameType(
                    enums.NameType.UNINTERPRETED_TEXT_STRING
                )
            )],
            result
        )

        result = e._get_attribute_from_managed_object(
            symmetric_key,
            'Object Type'
        )
        self.assertEqual(enums.ObjectType.SYMMETRIC_KEY, result)

        result = e._get_attribute_from_managed_object(
            symmetric_key,
            'Cryptographic Algorithm'
        )
        self.assertEqual(enums.CryptographicAlgorithm.AES, result)

        result = e._get_attribute_from_managed_object(
            symmetric_key,
            'Cryptographic Length'
        )
        self.assertEqual(0, result)

        result = e._get_attribute_from_managed_object(
            certificate,
            'Cryptographic Parameters'
        )
        self.assertEqual(None, result)

        result = e._get_attribute_from_managed_object(
            certificate,
            'Cryptographic Domain Parameters'
        )
        self.assertEqual(None, result)

        result = e._get_attribute_from_managed_object(
            certificate,
            'Certificate Type'
        )
        self.assertEqual(enums.CertificateType.X_509, result)

        result = e._get_attribute_from_managed_object(
            certificate,
            'Certificate Length'
        )
        self.assertEqual(None, result)

        result = e._get_attribute_from_managed_object(
            certificate,
            'X.509 Certificate Identifier'
        )
        self.assertEqual(None, result)

        result = e._get_attribute_from_managed_object(
            certificate,
            'X.509 Certificate Subject'
        )
        self.assertEqual(None, result)

        result = e._get_attribute_from_managed_object(
            certificate,
            'X.509 Certificate Issuer'
        )
        self.assertEqual(None, result)

        result = e._get_attribute_from_managed_object(
            certificate,
            'Certificate Identifier'
        )
        self.assertEqual(None, result)

        result = e._get_attribute_from_managed_object(
            certificate,
            'Certificate Subject'
        )
        self.assertEqual(None, result)

        result = e._get_attribute_from_managed_object(
            certificate,
            'Certificate Issuer'
        )
        self.assertEqual(None, result)

        result = e._get_attribute_from_managed_object(
            certificate,
            'Digital Signature Algorithm'
        )
        self.assertEqual(None, result)

        result = e._get_attribute_from_managed_object(
            opaque_object,
            'Digest'
        )
        self.assertEqual(None, result)

        result = e._get_attribute_from_managed_object(
            symmetric_key,
            'Operation Policy Name'
        )
        self.assertEqual('default', result)

        result = e._get_attribute_from_managed_object(
            symmetric_key,
            'Cryptographic Usage Mask'
        )
        self.assertEqual(
            [enums.CryptographicUsageMask.ENCRYPT,
             enums.CryptographicUsageMask.DECRYPT],
            result
        )

        result = e._get_attribute_from_managed_object(
            symmetric_key,
            'Lease Time'
        )
        self.assertEqual(None, result)

        result = e._get_attribute_from_managed_object(
            symmetric_key,
            'Usage Limits'
        )
        self.assertEqual(None, result)

        result = e._get_attribute_from_managed_object(
            symmetric_key,
            'State'
        )
        self.assertEqual(enums.State.PRE_ACTIVE, result)

        result = e._get_attribute_from_managed_object(
            symmetric_key,
            'Initial Date'
        )
        self.assertIsNotNone(result)
        self.assertIsInstance(result, six.integer_types)

        result = e._get_attribute_from_managed_object(
            symmetric_key,
            'Activation Date'
        )
        self.assertEqual(None, result)

        result = e._get_attribute_from_managed_object(
            symmetric_key,
            'Process Start Date'
        )
        self.assertEqual(None, result)

        result = e._get_attribute_from_managed_object(
            symmetric_key,
            'Protect Stop Date'
        )
        self.assertEqual(None, result)

        result = e._get_attribute_from_managed_object(
            symmetric_key,
            'Deactivation Date'
        )
        self.assertEqual(None, result)

        result = e._get_attribute_from_managed_object(
            symmetric_key,
            'Destroy Date'
        )
        self.assertEqual(None, result)

        result = e._get_attribute_from_managed_object(
            symmetric_key,
            'Compromise Occurrence Date'
        )
        self.assertEqual(None, result)

        result = e._get_attribute_from_managed_object(
            symmetric_key,
            'Compromise Date'
        )
        self.assertEqual(None, result)

        result = e._get_attribute_from_managed_object(
            symmetric_key,
            'Revocation Reason'
        )
        self.assertEqual(None, result)

        result = e._get_attribute_from_managed_object(
            symmetric_key,
            'Archive Date'
        )
        self.assertEqual(None, result)

        result = e._get_attribute_from_managed_object(
            symmetric_key,
            'Object Group'
        )
        self.assertEqual(None, result)

        result = e._get_attribute_from_managed_object(
            symmetric_key,
            'Fresh'
        )
        self.assertEqual(None, result)

        result = e._get_attribute_from_managed_object(
            symmetric_key,
            'Link'
        )
        self.assertEqual(None, result)

        result = e._get_attribute_from_managed_object(
            symmetric_key,
            'Application Specific Information'
        )
        self.assertEqual(None, result)

        result = e._get_attribute_from_managed_object(
            symmetric_key,
            'Contact Information'
        )
        self.assertEqual(None, result)

        result = e._get_attribute_from_managed_object(
            symmetric_key,
            'Last Change Date'
        )
        self.assertEqual(None, result)

        result = e._get_attribute_from_managed_object(
            symmetric_key,
            'invalid'
        )
        self.assertEqual(None, result)

    def test_set_attributes_on_managed_object(self):
        """
        Test that multiple attributes can be set on a given managed object.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._logger = mock.MagicMock()

        managed_object = pie_objects.SecretData(
            b'',
            enums.SecretDataType.PASSWORD
        )
        managed_object.names = []
        attribute_factory = factory.AttributeFactory()

        name = attribute_factory.create_attribute(
            enums.AttributeType.NAME,
            attributes.Name.create(
                'Test Secret Data',
                enums.NameType.UNINTERPRETED_TEXT_STRING
            )
        )
        mask = attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
            [
                enums.CryptographicUsageMask.ENCRYPT,
                enums.CryptographicUsageMask.DECRYPT
            ]
        )
        template_attribute = objects.TemplateAttribute(
            attributes=[name, mask]
        )
        object_attributes = e._process_template_attribute(template_attribute)

        self.assertEqual([], managed_object.names)
        self.assertEqual([], managed_object.cryptographic_usage_masks)

        e._set_attributes_on_managed_object(
            managed_object,
            object_attributes
        )

        self.assertEqual(['Test Secret Data'], managed_object.names)
        self.assertEqual(
            [
                enums.CryptographicUsageMask.ENCRYPT,
                enums.CryptographicUsageMask.DECRYPT
            ],
            managed_object.cryptographic_usage_masks
        )

    def test_set_attributes_on_managed_object_attribute_mismatch(self):
        """
        Test that an InvalidField error is generated when attempting to set
        an attribute that is not applicable for a given managed object.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._logger = mock.MagicMock()

        managed_object = pie_objects.OpaqueObject(
            b'',
            enums.OpaqueDataType.NONE
        )
        attribute_factory = factory.AttributeFactory()

        mask = attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
            [
                enums.CryptographicUsageMask.ENCRYPT,
                enums.CryptographicUsageMask.DECRYPT
            ]
        )
        template_attribute = objects.TemplateAttribute(attributes=[mask])
        object_attributes = e._process_template_attribute(template_attribute)

        args = (managed_object, object_attributes)
        regex = (
            "Cannot set Cryptographic Usage Mask attribute on OpaqueData "
            "object."
        )
        six.assertRaisesRegex(
            self,
            exceptions.InvalidField,
            regex,
            e._set_attributes_on_managed_object,
            *args
        )

    def test_set_attribute_on_managed_object(self):
        """
        Test that various attributes can be set correctly on a given
        managed object.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._logger = mock.MagicMock()

        attribute_factory = factory.AttributeFactory()

        name = attribute_factory.create_attribute(
            enums.AttributeType.NAME,
            attributes.Name.create(
                'Test Symmetric Key',
                enums.NameType.UNINTERPRETED_TEXT_STRING
            )
        )
        algorithm = attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
            enums.CryptographicAlgorithm.AES
        )
        length = attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
            0
        )
        mask = attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
            [
                enums.CryptographicUsageMask.ENCRYPT,
                enums.CryptographicUsageMask.DECRYPT
            ]
        )
        managed_object = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            0,
            b''
        )
        managed_object.names = []

        self.assertEqual([], managed_object.names)
        self.assertEqual(
            enums.CryptographicAlgorithm.AES,
            managed_object.cryptographic_algorithm
        )
        self.assertEqual(0, managed_object.cryptographic_length)
        self.assertEqual([], managed_object.cryptographic_usage_masks)

        e._set_attribute_on_managed_object(
            managed_object,
            ('Name', [name.attribute_value])
        )

        self.assertEqual(['Test Symmetric Key'], managed_object.names)

        e._set_attribute_on_managed_object(
            managed_object,
            ('Cryptographic Algorithm', algorithm.attribute_value)
        )

        self.assertEqual(
            enums.CryptographicAlgorithm.AES,
            managed_object.cryptographic_algorithm
        )

        e._set_attribute_on_managed_object(
            managed_object,
            ('Cryptographic Length', length.attribute_value)
        )

        self.assertEqual(0, managed_object.cryptographic_length)

        e._set_attribute_on_managed_object(
            managed_object,
            ('Cryptographic Usage Mask', mask.attribute_value)
        )

        self.assertEqual(
            [
                enums.CryptographicUsageMask.ENCRYPT,
                enums.CryptographicUsageMask.DECRYPT
            ],
            managed_object.cryptographic_usage_masks
        )

    def test_set_attribute_on_managed_object_unsupported_features(self):
        """
        Test that the right errors are generated when unsupported features
        are referenced while setting managed object attributes.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._logger = mock.MagicMock()

        attribute_factory = factory.AttributeFactory()

        managed_object = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            8,
            b'\x00'
        )

        # Test that multiple duplicate names cannot be set on an object.
        name_a = attribute_factory.create_attribute(
            enums.AttributeType.NAME,
            attributes.Name.create(
                'Test Symmetric Key',
                enums.NameType.UNINTERPRETED_TEXT_STRING
            )
        )
        name_b = attribute_factory.create_attribute(
            enums.AttributeType.NAME,
            attributes.Name.create(
                'Test Symmetric Key',
                enums.NameType.UNINTERPRETED_TEXT_STRING
            )
        )

        args = (
            managed_object,
            ('Name', [name_a.attribute_value, name_b.attribute_value])
        )
        regex = "Cannot set duplicate name values."
        six.assertRaisesRegex(
            self,
            exceptions.InvalidField,
            regex,
            e._set_attribute_on_managed_object,
            *args
        )

        # Test that a multivalued, unsupported attribute cannot be set on an
        # object.
        name_a = attribute_factory.create_attribute(
            enums.AttributeType.NAME,
            attributes.Name.create(
                'Test Symmetric Key',
                enums.NameType.UNINTERPRETED_TEXT_STRING
            )
        )
        name_b = attribute_factory.create_attribute(
            enums.AttributeType.NAME,
            attributes.Name.create(
                'Test Symmetric Key',
                enums.NameType.UNINTERPRETED_TEXT_STRING
            )
        )

        args = (
            managed_object,
            ('Digest', [name_a.attribute_value, name_b.attribute_value])
        )
        regex = "The Digest attribute is unsupported."
        six.assertRaisesRegex(
            self,
            exceptions.InvalidField,
            regex,
            e._set_attribute_on_managed_object,
            *args
        )

        # Test that a set attribute cannot be overwritten.
        length = attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
            128
        )

        args = (
            managed_object,
            ('Cryptographic Length', length.attribute_value)
        )
        regex = "Cannot overwrite the Cryptographic Length attribute."
        six.assertRaisesRegex(
            self,
            exceptions.InvalidField,
            regex,
            e._set_attribute_on_managed_object,
            *args
        )

        # Test that an unsupported attribute cannot be set.
        object_group = attribute_factory.create_attribute(
            enums.AttributeType.OBJECT_GROUP,
            'Test Group'
        )

        args = (
            managed_object,
            ('Object Group', object_group.attribute_value)
        )
        regex = "The Object Group attribute is unsupported."
        six.assertRaisesRegex(
            self,
            exceptions.InvalidField,
            regex,
            e._set_attribute_on_managed_object,
            *args
        )

    def test_is_allowed_by_operation_policy_granted(self):
        """
        Test that access granted by operation policy is processed correctly.
        """
        e = engine.KmipEngine()
        e.is_allowed = mock.Mock(return_value=True)

        result = e._is_allowed_by_operation_policy(
            'test_policy',
            ['test_user', ['test_group_A', 'test_group_B']],
            'test_user',
            enums.ObjectType.SYMMETRIC_KEY,
            enums.Operation.GET
        )

        e.is_allowed.assert_called_once_with(
            'test_policy',
            'test_user',
            'test_group_A',
            'test_user',
            enums.ObjectType.SYMMETRIC_KEY,
            enums.Operation.GET
        )
        self.assertTrue(result)

    def test_is_allowed_by_operation_policy_denied(self):
        """
        Test that access denied by operation policy is processed correctly.
        """
        e = engine.KmipEngine()
        e.is_allowed = mock.Mock(return_value=False)

        result = e._is_allowed_by_operation_policy(
            'test_policy',
            ['test_user', ['test_group_A', 'test_group_B']],
            'test_user',
            enums.ObjectType.SYMMETRIC_KEY,
            enums.Operation.GET
        )

        e.is_allowed.assert_any_call(
            'test_policy',
            'test_user',
            'test_group_A',
            'test_user',
            enums.ObjectType.SYMMETRIC_KEY,
            enums.Operation.GET
        )
        e.is_allowed.assert_any_call(
            'test_policy',
            'test_user',
            'test_group_B',
            'test_user',
            enums.ObjectType.SYMMETRIC_KEY,
            enums.Operation.GET
        )
        self.assertFalse(result)

    def test_is_allowed_by_operation_policy_no_groups(self):
        """
        Test that access by operation policy is processed correctly when no
        user groups are provided.
        """
        e = engine.KmipEngine()
        e.is_allowed = mock.Mock(return_value=True)

        result = e._is_allowed_by_operation_policy(
            'test_policy',
            ['test_user', None],
            'test_user',
            enums.ObjectType.SYMMETRIC_KEY,
            enums.Operation.GET
        )

        e.is_allowed.assert_called_once_with(
            'test_policy',
            'test_user',
            None,
            'test_user',
            enums.ObjectType.SYMMETRIC_KEY,
            enums.Operation.GET
        )
        self.assertTrue(result)

    def test_is_allowed_by_operation_policy_groups_empty(self):
        """
        Test that access by operation policy is processed correctly when the
        provided set of user groups is empty.

        Note that _is_allowed will always return True here, but because there
        are no groups to check, access is by default denied.
        """
        e = engine.KmipEngine()
        e.is_allowed = mock.Mock(return_value=True)

        result = e._is_allowed_by_operation_policy(
            'test_policy',
            ['test_user', []],
            'test_user',
            enums.ObjectType.SYMMETRIC_KEY,
            enums.Operation.GET
        )

        e.is_allowed.assert_not_called()
        self.assertFalse(result)

    def test_get_relevant_policy_section_policy_missing(self):
        """
        Test that the lookup for a non-existent policy is handled correctly.
        """
        e = engine.KmipEngine()
        e._operation_policies = {}
        e._logger = mock.MagicMock()

        result = e.get_relevant_policy_section('invalid')

        e._logger.warning.assert_called_once_with(
            "The 'invalid' policy does not exist."
        )
        self.assertIsNone(result)

    def test_get_relevant_policy_section_no_group(self):
        """
        Test that the lookup for a policy with no group specified is handled
        correctly.
        """
        e = engine.KmipEngine()
        e._operation_policies = {
            'test_policy': {
                'preset': {
                    enums.ObjectType.SYMMETRIC_KEY: {
                        enums.Operation.GET: enums.Policy.ALLOW_OWNER
                    }
                }
            }
        }

        expected = {
            enums.ObjectType.SYMMETRIC_KEY: {
                enums.Operation.GET: enums.Policy.ALLOW_OWNER
            }
        }

        result = e.get_relevant_policy_section('test_policy')
        self.assertEqual(expected, result)

    def test_get_relevant_policy_section_group(self):
        """
        Test that the lookup for a policy with a group specified is handled
        correctly.
        """
        e = engine.KmipEngine()
        e._operation_policies = {
            'test_policy': {
                'preset': {
                    enums.ObjectType.SYMMETRIC_KEY: {
                        enums.Operation.GET: enums.Policy.ALLOW_OWNER
                    }
                },
                'groups': {
                    'test_group': {
                        enums.ObjectType.CERTIFICATE: {
                            enums.Operation.CREATE: enums.Policy.ALLOW_ALL
                        }
                    }
                }
            }
        }

        expected = {
            enums.ObjectType.CERTIFICATE: {
                enums.Operation.CREATE: enums.Policy.ALLOW_ALL
            }
        }

        result = e.get_relevant_policy_section('test_policy', 'test_group')
        self.assertEqual(expected, result)

    def test_get_relevant_policy_section_group_not_supported(self):
        """
        Test that the lookup for a policy with a group specified but not
        supported is handled correctly.
        """
        e = engine.KmipEngine()
        e._logger = mock.MagicMock()
        e._operation_policies = {
            'test_policy': {
                'preset': {
                    enums.ObjectType.SYMMETRIC_KEY: {
                        enums.Operation.GET: enums.Policy.ALLOW_OWNER
                    }
                },
                'groups': {
                    'test_group_B': {
                        enums.ObjectType.CERTIFICATE: {
                            enums.Operation.CREATE: enums.Policy.ALLOW_ALL
                        }
                    }
                }
            }
        }

        result = e.get_relevant_policy_section('test_policy', 'test_group_A')

        e._logger.debug.assert_called_once_with(
            "The 'test_policy' policy does not support group 'test_group_A'."
        )
        self.assertIsNone(result)

    def test_get_relevant_policy_section_groups_not_supported(self):
        """
        Test that the lookup for a group-less policy with a group specified is
        handled correctly.
        """
        e = engine.KmipEngine()
        e._logger = mock.MagicMock()
        e._operation_policies = {
            'test_policy': {
                'preset': {
                    enums.ObjectType.SYMMETRIC_KEY: {
                        enums.Operation.GET: enums.Policy.ALLOW_OWNER
                    }
                }
            }
        }

        result = e.get_relevant_policy_section('test_policy', 'test_group_A')

        e._logger.debug.assert_called_once_with(
            "The 'test_policy' policy does not support groups."
        )
        self.assertIsNone(result)

    def test_is_allowed_policy_not_found(self):
        """
        Test that an access check using a non-existent policy is handled
        correctly.
        """
        e = engine.KmipEngine()
        e.get_relevant_policy_section = mock.Mock(return_value=None)

        result = e.is_allowed(
            'test_policy',
            'test_user',
            'test_group',
            'test_user',
            enums.ObjectType.SYMMETRIC_KEY,
            enums.Operation.GET
        )
        self.assertFalse(result)

    def test_is_allowed_policy_object_type_mismatch(self):
        """
        Test that an access check using a policy that does not support the
        specified object type is handled correctly.
        """
        e = engine.KmipEngine()
        e._logger = mock.Mock()
        e._get_enum_string = mock.Mock(return_value="Certificate")
        e.get_relevant_policy_section = mock.Mock(
            return_value={
                enums.ObjectType.SYMMETRIC_KEY: {
                    enums.Operation.GET: enums.Policy.ALLOW_OWNER
                }
            }
        )

        result = e.is_allowed(
            'test_policy',
            'test_user',
            'test_group',
            'test_user',
            enums.ObjectType.CERTIFICATE,
            enums.Operation.GET
        )

        e._logger.warning.assert_called_once_with(
            "The 'test_policy' policy does not apply to Certificate objects."
        )
        self.assertFalse(result)

    def test_is_allowed_policy_operation_mismatch(self):
        """
        Test that an access check using a policy that does not support the
        specified operation is handled correctly.
        """
        e = engine.KmipEngine()
        e._logger = mock.Mock()
        e._get_enum_string = mock.Mock(side_effect=["Create", "SymmetricKey"])
        e.get_relevant_policy_section = mock.Mock(
            return_value={
                enums.ObjectType.SYMMETRIC_KEY: {
                    enums.Operation.GET: enums.Policy.ALLOW_OWNER
                }
            }
        )

        result = e.is_allowed(
            'test_policy',
            'test_user',
            'test_group',
            'test_user',
            enums.ObjectType.SYMMETRIC_KEY,
            enums.Operation.CREATE
        )

        e._logger.warning.assert_called_once_with(
            "The 'test_policy' policy does not apply to Create operations on "
            "SymmetricKey objects."
        )
        self.assertFalse(result)

    def test_is_allowed_allow_all(self):
        """
        Test that an access check resulting in an "Allow All" policy is
        processed correctly.
        """
        e = engine.KmipEngine()
        e.get_relevant_policy_section = mock.Mock(
            return_value={
                enums.ObjectType.SYMMETRIC_KEY: {
                    enums.Operation.GET: enums.Policy.ALLOW_ALL
                }
            }
        )

        result = e.is_allowed(
            'test_policy',
            'test_user',
            'test_group',
            'test_user',
            enums.ObjectType.SYMMETRIC_KEY,
            enums.Operation.GET
        )
        self.assertTrue(result)

    def test_is_allowed_allow_owner(self):
        """
        Test that an access check resulting in an "Allow Owner" policy is
        processed correctly.
        """
        e = engine.KmipEngine()
        e.get_relevant_policy_section = mock.Mock(
            return_value={
                enums.ObjectType.SYMMETRIC_KEY: {
                    enums.Operation.GET: enums.Policy.ALLOW_OWNER
                }
            }
        )

        result = e.is_allowed(
            'test_policy',
            'test_user',
            'test_group',
            'test_user',
            enums.ObjectType.SYMMETRIC_KEY,
            enums.Operation.GET
        )
        self.assertTrue(result)

    def test_is_allowed_allow_owner_not_owner(self):
        """
        Test that an access check resulting in an "Allow Owner" policy is
        processed correctly when the user requesting access is not the owner.
        """
        e = engine.KmipEngine()
        e.get_relevant_policy_section = mock.Mock(
            return_value={
                enums.ObjectType.SYMMETRIC_KEY: {
                    enums.Operation.GET: enums.Policy.ALLOW_OWNER
                }
            }
        )

        result = e.is_allowed(
            'test_policy',
            'test_user_A',
            'test_group',
            'test_user_B',
            enums.ObjectType.SYMMETRIC_KEY,
            enums.Operation.GET
        )
        self.assertFalse(result)

    def test_is_allowed_disallow_all(self):
        """
        Test that an access check resulting in an "Disallow All" policy is
        processed correctly.
        """
        e = engine.KmipEngine()
        e.get_relevant_policy_section = mock.Mock(
            return_value={
                enums.ObjectType.SYMMETRIC_KEY: {
                    enums.Operation.GET: enums.Policy.DISALLOW_ALL
                }
            }
        )

        result = e.is_allowed(
            'test_policy',
            'test_user',
            'test_group',
            'test_user',
            enums.ObjectType.SYMMETRIC_KEY,
            enums.Operation.GET
        )
        self.assertFalse(result)

    def test_is_allowed_invalid_permission(self):
        """
        Test that an access check resulting in an invalid policy option is
        processed correctly.
        """
        e = engine.KmipEngine()
        e.get_relevant_policy_section = mock.Mock(
            return_value={
                enums.ObjectType.SYMMETRIC_KEY: {
                    enums.Operation.GET: 'invalid'
                }
            }
        )

        result = e.is_allowed(
            'test_policy',
            'test_user',
            'test_group',
            'test_user',
            enums.ObjectType.SYMMETRIC_KEY,
            enums.Operation.GET
        )
        self.assertFalse(result)

    def test_get_object_with_access_controls(self):
        """
        Test that an unallowed object access request is handled correctly.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=False)
        e._logger = mock.MagicMock()
        e._client_identity = 'test'

        obj_a = pie_objects.OpaqueObject(b'', enums.OpaqueDataType.NONE)
        obj_a._owner = 'admin'

        e._data_session.add(obj_a)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        id_a = str(obj_a.unique_identifier)

        # Test by specifying the ID of the object to retrieve and the
        # operation context.
        args = [id_a, enums.Operation.GET]
        six.assertRaisesRegex(
            self,
            exceptions.PermissionDenied,
            "Could not locate object: {0}".format(id_a),
            e._get_object_with_access_controls,
            *args
        )

    def test_create(self):
        """
        Test that a Create request can be processed correctly.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._logger = mock.MagicMock()

        attribute_factory = factory.AttributeFactory()

        # Build Create request
        object_type = attributes.ObjectType(enums.ObjectType.SYMMETRIC_KEY)
        template_attribute = objects.TemplateAttribute(
            attributes=[
                attribute_factory.create_attribute(
                    enums.AttributeType.NAME,
                    attributes.Name.create(
                        'Test Symmetric Key',
                        enums.NameType.UNINTERPRETED_TEXT_STRING
                    )
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                    enums.CryptographicAlgorithm.AES
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                    256
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    [
                        enums.CryptographicUsageMask.ENCRYPT,
                        enums.CryptographicUsageMask.DECRYPT
                    ]
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.OPERATION_POLICY_NAME,
                    'test'
                )
            ]
        )
        payload = payloads.CreateRequestPayload(
            object_type,
            template_attribute
        )

        response_payload = e._process_create(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Create"
        )

        uid = response_payload.unique_identifier.value
        self.assertEqual('1', uid)

        # Retrieve the stored object and verify all attributes were set
        # appropriately.
        symmetric_key = e._data_session.query(
            pie_objects.SymmetricKey
        ).filter(
            pie_objects.ManagedObject.unique_identifier == uid
        ).one()
        self.assertEqual(
            enums.KeyFormatType.RAW,
            symmetric_key.key_format_type
        )
        self.assertEqual(1, len(symmetric_key.names))
        self.assertIn('Test Symmetric Key', symmetric_key.names)
        self.assertEqual(256, len(symmetric_key.value) * 8)
        self.assertEqual(
            enums.CryptographicAlgorithm.AES,
            symmetric_key.cryptographic_algorithm
        )
        self.assertEqual(256, symmetric_key.cryptographic_length)
        self.assertEqual(2, len(symmetric_key.cryptographic_usage_masks))
        self.assertIn(
            enums.CryptographicUsageMask.ENCRYPT,
            symmetric_key.cryptographic_usage_masks
        )
        self.assertIn(
            enums.CryptographicUsageMask.DECRYPT,
            symmetric_key.cryptographic_usage_masks
        )
        self.assertEqual('test', symmetric_key.operation_policy_name)
        self.assertIsNotNone(symmetric_key.initial_date)
        self.assertNotEqual(0, symmetric_key.initial_date)

        self.assertEqual(uid, e._id_placeholder)

    def test_create_unsupported_object_type(self):
        """
        Test that an InvalidField error is generated when attempting to
        create an unsupported object type.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._logger = mock.MagicMock()

        object_type = attributes.ObjectType(enums.ObjectType.PUBLIC_KEY)
        payload = payloads.CreateRequestPayload(
            object_type
        )

        args = (payload, )
        regex = "Cannot create a PublicKey object with the Create operation."
        six.assertRaisesRegex(
            self,
            exceptions.InvalidField,
            regex,
            e._process_create,
            *args
        )

        e._logger.info.assert_any_call(
            "Processing operation: Create"
        )

    def test_create_omitting_attributes(self):
        """
        Test that InvalidField errors are generated when trying to create
        a symmetric key without required attributes.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._logger = mock.MagicMock()

        attribute_factory = factory.AttributeFactory()

        # Test the error for omitting the Cryptographic Algorithm
        object_type = attributes.ObjectType(enums.ObjectType.SYMMETRIC_KEY)
        template_attribute = objects.TemplateAttribute(
            attributes=[
                attribute_factory.create_attribute(
                    enums.AttributeType.NAME,
                    attributes.Name.create(
                        'Test Symmetric Key',
                        enums.NameType.UNINTERPRETED_TEXT_STRING
                    )
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                    256
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    [
                        enums.CryptographicUsageMask.ENCRYPT,
                        enums.CryptographicUsageMask.DECRYPT
                    ]
                )
            ]
        )
        payload = payloads.CreateRequestPayload(
            object_type,
            template_attribute
        )

        args = (payload, )
        regex = (
            "The cryptographic algorithm must be specified as an attribute."
        )
        six.assertRaisesRegex(
            self,
            exceptions.InvalidField,
            regex,
            e._process_create,
            *args
        )

        e._logger.info.assert_any_call(
            "Processing operation: Create"
        )
        e._logger.reset_mock()

        # Test the error for omitting the Cryptographic Length
        object_type = attributes.ObjectType(enums.ObjectType.SYMMETRIC_KEY)
        template_attribute = objects.TemplateAttribute(
            attributes=[
                attribute_factory.create_attribute(
                    enums.AttributeType.NAME,
                    attributes.Name.create(
                        'Test Symmetric Key',
                        enums.NameType.UNINTERPRETED_TEXT_STRING
                    )
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                    enums.CryptographicAlgorithm.AES
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    [
                        enums.CryptographicUsageMask.ENCRYPT,
                        enums.CryptographicUsageMask.DECRYPT
                    ]
                )
            ]
        )
        payload = payloads.CreateRequestPayload(
            object_type,
            template_attribute
        )

        args = (payload, )
        regex = (
            "The cryptographic length must be specified as an attribute."
        )
        six.assertRaisesRegex(
            self,
            exceptions.InvalidField,
            regex,
            e._process_create,
            *args
        )

        e._logger.info.assert_any_call(
            "Processing operation: Create"
        )
        e._logger.reset_mock()

        # Test the error for omitting the Cryptographic Usage Mask
        object_type = attributes.ObjectType(enums.ObjectType.SYMMETRIC_KEY)
        template_attribute = objects.TemplateAttribute(
            attributes=[
                attribute_factory.create_attribute(
                    enums.AttributeType.NAME,
                    attributes.Name.create(
                        'Test Symmetric Key',
                        enums.NameType.UNINTERPRETED_TEXT_STRING
                    )
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                    enums.CryptographicAlgorithm.AES
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                    256
                )
            ]
        )
        payload = payloads.CreateRequestPayload(
            object_type,
            template_attribute
        )

        args = (payload, )
        regex = (
            "The cryptographic usage mask must be specified as an attribute."
        )
        six.assertRaisesRegex(
            self,
            exceptions.InvalidField,
            regex,
            e._process_create,
            *args
        )

        e._logger.info.assert_any_call(
            "Processing operation: Create"
        )
        e._logger.reset_mock()

    def test_create_key_pair(self):
        """
        Test that a CreateKeyPair request can be processed correctly.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._logger = mock.MagicMock()

        attribute_factory = factory.AttributeFactory()

        common_template = objects.CommonTemplateAttribute(
            attributes=[
                attribute_factory.create_attribute(
                    enums.AttributeType.NAME,
                    attributes.Name.create(
                        'Test Asymmetric Key',
                        enums.NameType.UNINTERPRETED_TEXT_STRING
                    )
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                    enums.CryptographicAlgorithm.RSA
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                    2048
                )
            ]
        )
        public_template = objects.PublicKeyTemplateAttribute(
            attributes=[
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    [
                        enums.CryptographicUsageMask.ENCRYPT
                    ]
                )
            ]
        )
        private_template = objects.PrivateKeyTemplateAttribute(
            attributes=[
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    [
                        enums.CryptographicUsageMask.DECRYPT
                    ]
                )
            ]
        )
        payload = payloads.CreateKeyPairRequestPayload(
            common_template,
            private_template,
            public_template
        )

        response_payload = e._process_create_key_pair(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: CreateKeyPair"
        )

        public_id = response_payload.public_key_uuid.value
        self.assertEqual('1', public_id)
        private_id = response_payload.private_key_uuid.value
        self.assertEqual('2', private_id)

        # Retrieve the stored public key and verify all attributes were set
        # appropriately.
        public_key = e._data_session.query(
            pie_objects.PublicKey
        ).filter(
            pie_objects.ManagedObject.unique_identifier == public_id
        ).one()
        self.assertEqual(
            enums.KeyFormatType.PKCS_1,
            public_key.key_format_type
        )
        self.assertEqual(1, len(public_key.names))
        self.assertIn('Test Asymmetric Key', public_key.names)
        self.assertEqual(
            enums.CryptographicAlgorithm.RSA,
            public_key.cryptographic_algorithm
        )
        self.assertEqual(2048, public_key.cryptographic_length)
        self.assertEqual(1, len(public_key.cryptographic_usage_masks))
        self.assertIn(
            enums.CryptographicUsageMask.ENCRYPT,
            public_key.cryptographic_usage_masks
        )
        self.assertEqual('default', public_key.operation_policy_name)
        self.assertIsNotNone(public_key.initial_date)
        self.assertNotEqual(0, public_key.initial_date)

        # Retrieve the stored private key and verify all attributes were set
        # appropriately.
        private_key = e._data_session.query(
            pie_objects.PrivateKey
        ).filter(
            pie_objects.ManagedObject.unique_identifier == private_id
        ).one()
        self.assertEqual(
            enums.KeyFormatType.PKCS_8,
            private_key.key_format_type
        )
        self.assertEqual(1, len(private_key.names))
        self.assertIn('Test Asymmetric Key', private_key.names)
        self.assertEqual(
            enums.CryptographicAlgorithm.RSA,
            private_key.cryptographic_algorithm
        )
        self.assertEqual(2048, private_key.cryptographic_length)
        self.assertEqual(1, len(private_key.cryptographic_usage_masks))
        self.assertIn(
            enums.CryptographicUsageMask.DECRYPT,
            private_key.cryptographic_usage_masks
        )
        self.assertEqual('default', private_key.operation_policy_name)
        self.assertIsNotNone(private_key.initial_date)
        self.assertNotEqual(0, private_key.initial_date)

        self.assertEqual(private_id, e._id_placeholder)

    def test_create_key_pair_omitting_attributes(self):
        """
        Test that the right errors are generated when required attributes
        are missing from a CreateKeyPair request.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._logger = mock.MagicMock()

        attribute_factory = factory.AttributeFactory()

        # Test that a missing PublicKey CryptographicAlgorithm raises an error
        common_template = objects.CommonTemplateAttribute(
            attributes=[
                attribute_factory.create_attribute(
                    enums.AttributeType.NAME,
                    attributes.Name.create(
                        'Test Asymmetric Key',
                        enums.NameType.UNINTERPRETED_TEXT_STRING
                    )
                )
            ]
        )
        public_template = objects.PublicKeyTemplateAttribute(
            attributes=[
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                    2048
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    [
                        enums.CryptographicUsageMask.ENCRYPT
                    ]
                )
            ]
        )
        private_template = objects.PrivateKeyTemplateAttribute(
            attributes=[
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                    enums.CryptographicAlgorithm.RSA
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                    2048
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    [
                        enums.CryptographicUsageMask.DECRYPT
                    ]
                )
            ]
        )
        payload = payloads.CreateKeyPairRequestPayload(
            common_template,
            private_template,
            public_template
        )

        args = (payload, )
        regex = (
            "The cryptographic algorithm must be specified as an attribute "
            "for the public key."
        )
        six.assertRaisesRegex(
            self,
            exceptions.InvalidField,
            regex,
            e._process_create_key_pair,
            *args
        )
        e._logger.info.assert_any_call(
            "Processing operation: CreateKeyPair"
        )
        e._logger.reset_mock()

        # Test that a missing PrivateKey CryptographicAlgorithm raises an error
        common_template = objects.CommonTemplateAttribute(
            attributes=[
                attribute_factory.create_attribute(
                    enums.AttributeType.NAME,
                    attributes.Name.create(
                        'Test Asymmetric Key',
                        enums.NameType.UNINTERPRETED_TEXT_STRING
                    )
                )
            ]
        )
        public_template = objects.PublicKeyTemplateAttribute(
            attributes=[
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                    enums.CryptographicAlgorithm.RSA
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                    2048
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    [
                        enums.CryptographicUsageMask.ENCRYPT
                    ]
                )
            ]
        )
        private_template = objects.PrivateKeyTemplateAttribute(
            attributes=[
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                    2048
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    [
                        enums.CryptographicUsageMask.DECRYPT
                    ]
                )
            ]
        )
        payload = payloads.CreateKeyPairRequestPayload(
            common_template,
            private_template,
            public_template
        )

        args = (payload, )
        regex = (
            "The cryptographic algorithm must be specified as an attribute "
            "for the private key."
        )
        six.assertRaisesRegex(
            self,
            exceptions.InvalidField,
            regex,
            e._process_create_key_pair,
            *args
        )
        e._logger.info.assert_any_call(
            "Processing operation: CreateKeyPair"
        )
        e._logger.reset_mock()

        # Test that a missing PublicKey CryptographicLength raises an error
        common_template = objects.CommonTemplateAttribute(
            attributes=[
                attribute_factory.create_attribute(
                    enums.AttributeType.NAME,
                    attributes.Name.create(
                        'Test Asymmetric Key',
                        enums.NameType.UNINTERPRETED_TEXT_STRING
                    )
                )
            ]
        )
        public_template = objects.PublicKeyTemplateAttribute(
            attributes=[
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                    enums.CryptographicAlgorithm.RSA
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    [
                        enums.CryptographicUsageMask.ENCRYPT
                    ]
                )
            ]
        )
        private_template = objects.PrivateKeyTemplateAttribute(
            attributes=[
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                    enums.CryptographicAlgorithm.RSA
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                    2048
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    [
                        enums.CryptographicUsageMask.DECRYPT
                    ]
                )
            ]
        )
        payload = payloads.CreateKeyPairRequestPayload(
            common_template,
            private_template,
            public_template
        )

        args = (payload, )
        regex = (
            "The cryptographic length must be specified as an attribute for "
            "the public key."
        )
        six.assertRaisesRegex(
            self,
            exceptions.InvalidField,
            regex,
            e._process_create_key_pair,
            *args
        )
        e._logger.info.assert_any_call(
            "Processing operation: CreateKeyPair"
        )
        e._logger.reset_mock()

        # Test that a missing PrivateKey CryptographicLength raises an error
        common_template = objects.CommonTemplateAttribute(
            attributes=[
                attribute_factory.create_attribute(
                    enums.AttributeType.NAME,
                    attributes.Name.create(
                        'Test Asymmetric Key',
                        enums.NameType.UNINTERPRETED_TEXT_STRING
                    )
                )
            ]
        )
        public_template = objects.PublicKeyTemplateAttribute(
            attributes=[
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                    enums.CryptographicAlgorithm.RSA
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                    2048
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    [
                        enums.CryptographicUsageMask.ENCRYPT
                    ]
                )
            ]
        )
        private_template = objects.PrivateKeyTemplateAttribute(
            attributes=[
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                    enums.CryptographicAlgorithm.RSA
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    [
                        enums.CryptographicUsageMask.DECRYPT
                    ]
                )
            ]
        )
        payload = payloads.CreateKeyPairRequestPayload(
            common_template,
            private_template,
            public_template
        )

        args = (payload, )
        regex = (
            "The cryptographic length must be specified as an attribute for "
            "the private key."
        )
        six.assertRaisesRegex(
            self,
            exceptions.InvalidField,
            regex,
            e._process_create_key_pair,
            *args
        )
        e._logger.info.assert_any_call(
            "Processing operation: CreateKeyPair"
        )
        e._logger.reset_mock()

        # Test that a missing PublicKey CryptographicUsageMask raises an error
        common_template = objects.CommonTemplateAttribute(
            attributes=[
                attribute_factory.create_attribute(
                    enums.AttributeType.NAME,
                    attributes.Name.create(
                        'Test Asymmetric Key',
                        enums.NameType.UNINTERPRETED_TEXT_STRING
                    )
                )
            ]
        )
        public_template = objects.PublicKeyTemplateAttribute(
            attributes=[
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                    enums.CryptographicAlgorithm.RSA
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                    2048
                )
            ]
        )
        private_template = objects.PrivateKeyTemplateAttribute(
            attributes=[
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                    enums.CryptographicAlgorithm.RSA
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                    2048
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    [
                        enums.CryptographicUsageMask.DECRYPT
                    ]
                )
            ]
        )
        payload = payloads.CreateKeyPairRequestPayload(
            common_template,
            private_template,
            public_template
        )

        args = (payload, )
        regex = (
            "The cryptographic usage mask must be specified as an attribute "
            "for the public key."
        )
        six.assertRaisesRegex(
            self,
            exceptions.InvalidField,
            regex,
            e._process_create_key_pair,
            *args
        )
        e._logger.info.assert_any_call(
            "Processing operation: CreateKeyPair"
        )
        e._logger.reset_mock()

        # Test that a missing PrivateKey CryptographicUsageMask raises an error
        common_template = objects.CommonTemplateAttribute(
            attributes=[
                attribute_factory.create_attribute(
                    enums.AttributeType.NAME,
                    attributes.Name.create(
                        'Test Asymmetric Key',
                        enums.NameType.UNINTERPRETED_TEXT_STRING
                    )
                )
            ]
        )
        public_template = objects.PublicKeyTemplateAttribute(
            attributes=[
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                    enums.CryptographicAlgorithm.RSA
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                    2048
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    [
                        enums.CryptographicUsageMask.ENCRYPT
                    ]
                )
            ]
        )
        private_template = objects.PrivateKeyTemplateAttribute(
            attributes=[
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                    enums.CryptographicAlgorithm.RSA
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                    2048
                )
            ]
        )
        payload = payloads.CreateKeyPairRequestPayload(
            common_template,
            private_template,
            public_template
        )

        args = (payload, )
        regex = (
            "The cryptographic usage mask must be specified as an attribute "
            "for the private key."
        )
        six.assertRaisesRegex(
            self,
            exceptions.InvalidField,
            regex,
            e._process_create_key_pair,
            *args
        )
        e._logger.info.assert_any_call(
            "Processing operation: CreateKeyPair"
        )
        e._logger.reset_mock()

    def test_create_key_pair_mismatched_attributes(self):
        """
        Test that the right errors are generated when required attributes
        are mismatched in a CreateKeyPair request.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._logger = mock.MagicMock()

        attribute_factory = factory.AttributeFactory()

        # Test that mismatched CryptographicAlgorithms raise an error.
        common_template = objects.CommonTemplateAttribute(
            attributes=[
                attribute_factory.create_attribute(
                    enums.AttributeType.NAME,
                    attributes.Name.create(
                        'Test Asymmetric Key',
                        enums.NameType.UNINTERPRETED_TEXT_STRING
                    )
                )
            ]
        )
        public_template = objects.PublicKeyTemplateAttribute(
            attributes=[
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                    enums.CryptographicAlgorithm.RSA
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                    2048
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    [
                        enums.CryptographicUsageMask.ENCRYPT
                    ]
                )
            ]
        )
        private_template = objects.PrivateKeyTemplateAttribute(
            attributes=[
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                    enums.CryptographicAlgorithm.DSA
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                    2048
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    [
                        enums.CryptographicUsageMask.DECRYPT
                    ]
                )
            ]
        )
        payload = payloads.CreateKeyPairRequestPayload(
            common_template,
            private_template,
            public_template
        )

        args = (payload, )
        regex = (
            "The public and private key algorithms must be the same."
        )
        six.assertRaisesRegex(
            self,
            exceptions.InvalidField,
            regex,
            e._process_create_key_pair,
            *args
        )
        e._logger.info.assert_any_call(
            "Processing operation: CreateKeyPair"
        )
        e._logger.reset_mock()

        # Test that mismatched CryptographicAlgorithms raise an error.
        common_template = objects.CommonTemplateAttribute(
            attributes=[
                attribute_factory.create_attribute(
                    enums.AttributeType.NAME,
                    attributes.Name.create(
                        'Test Asymmetric Key',
                        enums.NameType.UNINTERPRETED_TEXT_STRING
                    )
                )
            ]
        )
        public_template = objects.PublicKeyTemplateAttribute(
            attributes=[
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                    enums.CryptographicAlgorithm.RSA
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                    2048
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    [
                        enums.CryptographicUsageMask.ENCRYPT
                    ]
                )
            ]
        )
        private_template = objects.PrivateKeyTemplateAttribute(
            attributes=[
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                    enums.CryptographicAlgorithm.RSA
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                    4096
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    [
                        enums.CryptographicUsageMask.DECRYPT
                    ]
                )
            ]
        )
        payload = payloads.CreateKeyPairRequestPayload(
            common_template,
            private_template,
            public_template
        )

        args = (payload, )
        regex = (
            "The public and private key lengths must be the same."
        )
        six.assertRaisesRegex(
            self,
            exceptions.InvalidField,
            regex,
            e._process_create_key_pair,
            *args
        )
        e._logger.info.assert_any_call(
            "Processing operation: CreateKeyPair"
        )
        e._logger.reset_mock()

    def test_register(self):
        """
        Test that a Register request can be processed correctly.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._logger = mock.MagicMock()

        attribute_factory = factory.AttributeFactory()

        # Build a SymmetricKey for registration.
        object_type = attributes.ObjectType(enums.ObjectType.SYMMETRIC_KEY)
        template_attribute = objects.TemplateAttribute(
            attributes=[
                attribute_factory.create_attribute(
                    enums.AttributeType.NAME,
                    attributes.Name.create(
                        'Test Symmetric Key',
                        enums.NameType.UNINTERPRETED_TEXT_STRING
                    )
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                    enums.CryptographicAlgorithm.AES
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                    128
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    [
                        enums.CryptographicUsageMask.ENCRYPT,
                        enums.CryptographicUsageMask.DECRYPT
                    ]
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.OPERATION_POLICY_NAME,
                    'test'
                )
            ]
        )
        key_bytes = (
            b'\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00'
        )
        secret = secrets.SymmetricKey(
            key_block=objects.KeyBlock(
                key_format_type=misc.KeyFormatType(enums.KeyFormatType.RAW),
                key_value=objects.KeyValue(
                    key_material=objects.KeyMaterial(key_bytes)
                ),
                cryptographic_algorithm=attributes.CryptographicAlgorithm(
                    enums.CryptographicAlgorithm.AES
                ),
                cryptographic_length=attributes.CryptographicLength(128)
            )
        )

        payload = payloads.RegisterRequestPayload(
            object_type=object_type,
            template_attribute=template_attribute,
            secret=secret
        )

        response_payload = e._process_register(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Register"
        )

        uid = response_payload.unique_identifier.value
        self.assertEqual('1', uid)

        # Retrieve the stored object and verify all attributes were set
        # appropriately.
        symmetric_key = e._data_session.query(
            pie_objects.SymmetricKey
        ).filter(
            pie_objects.ManagedObject.unique_identifier == uid
        ).one()
        self.assertEqual(
            enums.KeyFormatType.RAW,
            symmetric_key.key_format_type
        )
        self.assertEqual(1, len(symmetric_key.names))
        self.assertIn('Test Symmetric Key', symmetric_key.names)
        self.assertEqual(key_bytes, symmetric_key.value)
        self.assertEqual(
            enums.CryptographicAlgorithm.AES,
            symmetric_key.cryptographic_algorithm
        )
        self.assertEqual(128, symmetric_key.cryptographic_length)
        self.assertEqual(2, len(symmetric_key.cryptographic_usage_masks))
        self.assertIn(
            enums.CryptographicUsageMask.ENCRYPT,
            symmetric_key.cryptographic_usage_masks
        )
        self.assertIn(
            enums.CryptographicUsageMask.DECRYPT,
            symmetric_key.cryptographic_usage_masks
        )
        self.assertEqual('test', symmetric_key.operation_policy_name)
        self.assertIsNotNone(symmetric_key.initial_date)
        self.assertNotEqual(0, symmetric_key.initial_date)

        self.assertEqual(uid, e._id_placeholder)

    def test_register_unsupported_object_type(self):
        """
        Test that an InvalidField error is generated when attempting to
        register an unsupported object type.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._logger = mock.MagicMock()

        object_type = attributes.ObjectType(enums.ObjectType.SPLIT_KEY)
        payload = payloads.RegisterRequestPayload(object_type=object_type)

        args = (payload, )
        regex = "The SplitKey object type is not supported."
        six.assertRaisesRegex(
            self,
            exceptions.InvalidField,
            regex,
            e._process_register,
            *args
        )

    def test_request_omitting_secret(self):
        """
        Test that an InvalidField error is generate when trying to register
        a secret in absentia.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._logger = mock.MagicMock()

        object_type = attributes.ObjectType(enums.ObjectType.SYMMETRIC_KEY)
        payload = payloads.RegisterRequestPayload(object_type=object_type)

        args = (payload, )
        regex = "Cannot register a secret in absentia."
        six.assertRaisesRegex(
            self,
            exceptions.InvalidField,
            regex,
            e._process_register,
            *args
        )

    def test_derive_key(self):
        """
        Test that a DeriveKey request can be processed correctly.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        base_key = pie_objects.SymmetricKey(
            algorithm=enums.CryptographicAlgorithm.HMAC_SHA256,
            length=176,
            value=(
                b'\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
                b'\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
                b'\x0b\x0b\x0b\x0b\x0b\x0b'
            ),
            masks=[enums.CryptographicUsageMask.DERIVE_KEY]
        )
        e._data_session.add(base_key)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        attribute_factory = factory.AttributeFactory()

        # Derive a SymmetricKey object.
        payload = payloads.DeriveKeyRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifiers=[str(base_key.unique_identifier)],
            derivation_method=enums.DerivationMethod.HMAC,
            derivation_parameters=attributes.DerivationParameters(
                cryptographic_parameters=attributes.CryptographicParameters(
                    hashing_algorithm=enums.HashingAlgorithm.SHA_256
                ),
                derivation_data=(
                    b'\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7'
                    b'\xf8\xf9'
                ),
                salt=(
                    b'\x00\x01\x02\x03\x04\x05\x06\x07'
                    b'\x08\x09\x0a\x0b\x0c'
                )
            ),
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    attribute_factory.create_attribute(
                        enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                        336
                    ),
                    attribute_factory.create_attribute(
                        enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                        enums.CryptographicAlgorithm.AES
                    )
                ]
            )
        )

        response_payload = e._process_derive_key(payload)

        e._logger.info.assert_any_call("Processing operation: DeriveKey")
        e._logger.info.assert_any_call(
            "Object 1 will be used as the keying material for the derivation "
            "process."
        )
        e._logger.info.assert_any_call("Created a SymmetricKey with ID: 2")

        self.assertEqual("2", response_payload.unique_identifier)

        managed_object = e._data_session.query(
            pie_objects.SymmetricKey
        ).filter(
            pie_objects.SymmetricKey.unique_identifier == 2
        ).one()

        self.assertEqual(
            (
                b'\x3c\xb2\x5f\x25\xfa\xac\xd5\x7a'
                b'\x90\x43\x4f\x64\xd0\x36\x2f\x2a'
                b'\x2d\x2d\x0a\x90\xcf\x1a\x5a\x4c'
                b'\x5d\xb0\x2d\x56\xec\xc4\xc5\xbf'
                b'\x34\x00\x72\x08\xd5\xb8\x87\x18'
                b'\x58\x65'
            ),
            managed_object.value
        )
        self.assertEqual(
            enums.CryptographicAlgorithm.AES,
            managed_object.cryptographic_algorithm
        )
        self.assertEqual(
            336,
            managed_object.cryptographic_length
        )
        self.assertIsNotNone(managed_object.initial_date)

        e._logger.reset_mock()

        base_key = pie_objects.SymmetricKey(
            algorithm=enums.CryptographicAlgorithm.BLOWFISH,
            length=128,
            value=(
                b'\x01\x23\x45\x67\x89\xAB\xCD\xEF'
                b'\xF0\xE1\xD2\xC3\xB4\xA5\x96\x87'
            ),
            masks=[enums.CryptographicUsageMask.DERIVE_KEY]
        )
        e._data_session.add(base_key)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        # Derive a SecretData object.
        payload = payloads.DeriveKeyRequestPayload(
            object_type=enums.ObjectType.SECRET_DATA,
            unique_identifiers=[str(base_key.unique_identifier)],
            derivation_method=enums.DerivationMethod.ENCRYPT,
            derivation_parameters=attributes.DerivationParameters(
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.CBC,
                    padding_method=enums.PaddingMethod.PKCS5,
                    hashing_algorithm=enums.HashingAlgorithm.SHA_256,
                    cryptographic_algorithm=(
                        enums.CryptographicAlgorithm.BLOWFISH
                    )
                ),
                initialization_vector=b'\xFE\xDC\xBA\x98\x76\x54\x32\x10',
                derivation_data=(
                    b'\x37\x36\x35\x34\x33\x32\x31\x20'
                    b'\x4E\x6F\x77\x20\x69\x73\x20\x74'
                    b'\x68\x65\x20\x74\x69\x6D\x65\x20'
                    b'\x66\x6F\x72\x20\x00'
                ),
            ),
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    attribute_factory.create_attribute(
                        enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                        256
                    )
                ]
            )
        )

        response_payload = e._process_derive_key(payload)

        e._logger.info.assert_any_call("Processing operation: DeriveKey")
        e._logger.info.assert_any_call(
            "Object 3 will be used as the keying material for the derivation "
            "process."
        )
        e._logger.info.assert_any_call("Created a SecretData with ID: 4")

        self.assertEqual("4", response_payload.unique_identifier)

        managed_object = e._data_session.query(
            pie_objects.SecretData
        ).filter(
            pie_objects.SecretData.unique_identifier == 4
        ).one()

        self.assertEqual(
            (
                b'\x6B\x77\xB4\xD6\x30\x06\xDE\xE6'
                b'\x05\xB1\x56\xE2\x74\x03\x97\x93'
                b'\x58\xDE\xB9\xE7\x15\x46\x16\xD9'
                b'\x74\x9D\xEC\xBE\xC0\x5D\x26\x4B'
            ),
            managed_object.value
        )
        self.assertEqual(enums.SecretDataType.SEED, managed_object.data_type)
        self.assertIsNotNone(managed_object.initial_date)

    def test_derive_key_truncation(self):
        """
        Test that a derived key is properly truncated after it is generated if
        needed.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        base_key = pie_objects.SymmetricKey(
            algorithm=enums.CryptographicAlgorithm.BLOWFISH,
            length=128,
            value=(
                b'\x01\x23\x45\x67\x89\xAB\xCD\xEF'
                b'\xF0\xE1\xD2\xC3\xB4\xA5\x96\x87'
            ),
            masks=[enums.CryptographicUsageMask.DERIVE_KEY]
        )
        e._data_session.add(base_key)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        attribute_factory = factory.AttributeFactory()

        # Derive a SymmetricKey object.
        payload = payloads.DeriveKeyRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifiers=[str(base_key.unique_identifier)],
            derivation_method=enums.DerivationMethod.ENCRYPT,
            derivation_parameters=attributes.DerivationParameters(
                cryptographic_parameters=attributes.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.CBC,
                    padding_method=enums.PaddingMethod.PKCS5,
                    cryptographic_algorithm=enums.CryptographicAlgorithm.
                    BLOWFISH
                ),
                derivation_data=(
                    b'\x37\x36\x35\x34\x33\x32\x31\x20'
                    b'\x4E\x6F\x77\x20\x69\x73\x20\x74'
                    b'\x68\x65\x20\x74\x69\x6D\x65\x20'
                    b'\x66\x6F\x72\x20\x00'
                ),
                initialization_vector=b'\xFE\xDC\xBA\x98\x76\x54\x32\x10'
            ),
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    attribute_factory.create_attribute(
                        enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                        128
                    ),
                    attribute_factory.create_attribute(
                        enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                        enums.CryptographicAlgorithm.AES
                    )
                ]
            )
        )

        response_payload = e._process_derive_key(payload)

        e._logger.info.assert_any_call("Processing operation: DeriveKey")
        e._logger.info.assert_any_call(
            "Object 1 will be used as the keying material for the derivation "
            "process."
        )
        e._logger.info.assert_any_call("Created a SymmetricKey with ID: 2")

        self.assertEqual("2", response_payload.unique_identifier)

        managed_object = e._data_session.query(
            pie_objects.SymmetricKey
        ).filter(
            pie_objects.SymmetricKey.unique_identifier == 2
        ).one()

        self.assertEqual(
            (
                b'\x6B\x77\xB4\xD6\x30\x06\xDE\xE6'
                b'\x05\xB1\x56\xE2\x74\x03\x97\x93'
            ),
            managed_object.value
        )
        self.assertEqual(
            enums.CryptographicAlgorithm.AES,
            managed_object.cryptographic_algorithm
        )
        self.assertEqual(128, managed_object.cryptographic_length)
        self.assertIsNotNone(managed_object.initial_date)

    def test_derive_key_invalid_derivation_type(self):
        """
        Test that the right error is thrown when an invalid derivation type
        is provided with a DeriveKey request.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        payload = payloads.DeriveKeyRequestPayload(
            object_type=enums.ObjectType.CERTIFICATE
        )

        args = (payload, )
        self.assertRaisesRegexp(
            exceptions.InvalidField,
            "Key derivation can only generate a SymmetricKey or SecretData "
            "object.",
            e._process_derive_key,
            *args
        )

    def test_derive_key_invalid_base_key(self):
        """
        Test that the right error is thrown when an object not suitable for
        key derivation is provided as the base key with a DeriveKey request.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        invalid_key = pie_objects.OpaqueObject(
            b'\x01\x02\x04\x08\x10\x20\x40\x80',
            enums.OpaqueDataType.NONE
        )
        e._data_session.add(invalid_key)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        payload = payloads.DeriveKeyRequestPayload(
            object_type=enums.ObjectType.SECRET_DATA,
            unique_identifiers=[str(invalid_key.unique_identifier)]
        )

        args = (payload, )
        self.assertRaisesRegexp(
            exceptions.InvalidField,
            "Object 1 is not a suitable type for key derivation. Please "
            "specify a key or secret data.",
            e._process_derive_key,
            *args
        )

    def test_derive_key_non_derivable_base_key(self):
        """
        Test that the right error is thrown when an object suitable for
        key derivation but not marked as such is provided as the base key
        with a DeriveKey request.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        base_key = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            128,
            (
                b'\x00\x01\x02\x03\x04\x05\x06\x07'
                b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
            ),
            [enums.CryptographicUsageMask.ENCRYPT]
        )
        e._data_session.add(base_key)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        payload = payloads.DeriveKeyRequestPayload(
            object_type=enums.ObjectType.SECRET_DATA,
            unique_identifiers=[str(base_key.unique_identifier)]
        )

        args = (payload, )
        self.assertRaisesRegexp(
            exceptions.InvalidField,
            "The DeriveKey bit must be set in the cryptographic usage mask "
            "for object 1 for it to be used in key derivation.",
            e._process_derive_key,
            *args
        )

    def test_derive_key_alternate_derivation_data(self):
        """
        Test that a DeriveKey request can be processed correctly by
        specifying multiple base objects and no derivation data.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        base_key = pie_objects.SymmetricKey(
            algorithm=enums.CryptographicAlgorithm.HMAC_SHA256,
            length=176,
            value=(
                b'\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
                b'\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
                b'\x0b\x0b\x0b\x0b\x0b\x0b'
            ),
            masks=[enums.CryptographicUsageMask.DERIVE_KEY]
        )
        e._data_session.add(base_key)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        base_data = pie_objects.SecretData(
            value=(
                b'\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7'
                b'\xf8\xf9'
            ),
            data_type=enums.SecretDataType.SEED,
            masks=[enums.CryptographicUsageMask.DERIVE_KEY]
        )
        e._data_session.add(base_data)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        attribute_factory = factory.AttributeFactory()

        payload = payloads.DeriveKeyRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifiers=[
                str(base_key.unique_identifier),
                str(base_data.unique_identifier)
            ],
            derivation_method=enums.DerivationMethod.HMAC,
            derivation_parameters=attributes.DerivationParameters(
                cryptographic_parameters=attributes.CryptographicParameters(
                    hashing_algorithm=enums.HashingAlgorithm.SHA_256
                ),
                salt=(
                    b'\x00\x01\x02\x03\x04\x05\x06\x07'
                    b'\x08\x09\x0a\x0b\x0c'
                )
            ),
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    attribute_factory.create_attribute(
                        enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                        336
                    ),
                    attribute_factory.create_attribute(
                        enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                        enums.CryptographicAlgorithm.AES
                    )
                ]
            )
        )

        response_payload = e._process_derive_key(payload)

        e._logger.info.assert_any_call("Processing operation: DeriveKey")
        e._logger.info.assert_any_call(
            "2 derivation objects specified with the DeriveKey request."
        )
        e._logger.info.assert_any_call(
            "Object 1 will be used as the keying material for the derivation "
            "process."
        )
        e._logger.info.assert_any_call(
            "Object 2 will be used as the derivation data for the derivation "
            "process."
        )
        e._logger.info.assert_any_call("Created a SymmetricKey with ID: 3")

        self.assertEqual("3", response_payload.unique_identifier)

        managed_object = e._data_session.query(
            pie_objects.SymmetricKey
        ).filter(
            pie_objects.SymmetricKey.unique_identifier == 3
        ).one()

        self.assertEqual(
            (
                b'\x3c\xb2\x5f\x25\xfa\xac\xd5\x7a'
                b'\x90\x43\x4f\x64\xd0\x36\x2f\x2a'
                b'\x2d\x2d\x0a\x90\xcf\x1a\x5a\x4c'
                b'\x5d\xb0\x2d\x56\xec\xc4\xc5\xbf'
                b'\x34\x00\x72\x08\xd5\xb8\x87\x18'
                b'\x58\x65'
            ),
            managed_object.value
        )
        self.assertEqual(
            enums.CryptographicAlgorithm.AES,
            managed_object.cryptographic_algorithm
        )
        self.assertEqual(
            336,
            managed_object.cryptographic_length
        )
        self.assertIsNotNone(managed_object.initial_date)

    def test_derive_key_unspecified_iv(self):
        """
        """
        self.skip('')

    def test_derive_key_missing_cryptographic_length(self):
        """
        Test that the right error is thrown when the cryptographic length is
        missing from a DeriveKey request.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        base_key = pie_objects.SymmetricKey(
            algorithm=enums.CryptographicAlgorithm.HMAC_SHA256,
            length=160,
            value=(
                b'\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
                b'\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
                b'\x0b\x0b\x0b\x0b'
            ),
            masks=[enums.CryptographicUsageMask.DERIVE_KEY]
        )
        e._data_session.add(base_key)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        attribute_factory = factory.AttributeFactory()

        payload = payloads.DeriveKeyRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifiers=[str(base_key.unique_identifier)],
            derivation_method=enums.DerivationMethod.HMAC,
            derivation_parameters=attributes.DerivationParameters(
                cryptographic_parameters=attributes.CryptographicParameters(
                    hashing_algorithm=enums.HashingAlgorithm.SHA_256
                ),
                derivation_data=b'\x48\x69\x20\x54\x68\x65\x72\x65',
            ),
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    attribute_factory.create_attribute(
                        enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                        enums.CryptographicAlgorithm.AES
                    )
                ]
            )
        )

        args = (payload, )
        self.assertRaisesRegexp(
            exceptions.InvalidField,
            "The cryptographic length must be provided in the template "
            "attribute.",
            e._process_derive_key,
            *args
        )

    def test_derive_key_invalid_cryptographic_length(self):
        """
        Test that the right error is thrown when an invalid cryptographic
        length is provided with a DeriveKey request.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        base_key = pie_objects.SymmetricKey(
            algorithm=enums.CryptographicAlgorithm.HMAC_SHA256,
            length=160,
            value=(
                b'\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
                b'\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
                b'\x0b\x0b\x0b\x0b'
            ),
            masks=[enums.CryptographicUsageMask.DERIVE_KEY]
        )
        e._data_session.add(base_key)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        attribute_factory = factory.AttributeFactory()

        payload = payloads.DeriveKeyRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifiers=[str(base_key.unique_identifier)],
            derivation_method=enums.DerivationMethod.HMAC,
            derivation_parameters=attributes.DerivationParameters(
                cryptographic_parameters=attributes.CryptographicParameters(
                    hashing_algorithm=enums.HashingAlgorithm.SHA_256
                ),
                derivation_data=b'\x48\x69\x20\x54\x68\x65\x72\x65',
            ),
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    attribute_factory.create_attribute(
                        enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                        123
                    ),
                    attribute_factory.create_attribute(
                        enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                        enums.CryptographicAlgorithm.AES
                    )
                ]
            )
        )

        args = (payload, )
        self.assertRaisesRegexp(
            exceptions.InvalidField,
            "The cryptographic length must correspond to a valid number of "
            "bytes \(i.e., it must be a multiple of 8\).",
            e._process_derive_key,
            *args
        )

    def test_derive_key_missing_cryptographic_algorithm(self):
        """
        Test that the right error is thrown when the cryptographic algorithm
        is missing from a DeriveKey request when deriving a symmetric key.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        base_key = pie_objects.SymmetricKey(
            algorithm=enums.CryptographicAlgorithm.HMAC_SHA256,
            length=160,
            value=(
                b'\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
                b'\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
                b'\x0b\x0b\x0b\x0b'
            ),
            masks=[enums.CryptographicUsageMask.DERIVE_KEY]
        )
        e._data_session.add(base_key)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        attribute_factory = factory.AttributeFactory()

        payload = payloads.DeriveKeyRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifiers=[str(base_key.unique_identifier)],
            derivation_method=enums.DerivationMethod.HMAC,
            derivation_parameters=attributes.DerivationParameters(
                cryptographic_parameters=attributes.CryptographicParameters(
                    hashing_algorithm=enums.HashingAlgorithm.SHA_256
                ),
                derivation_data=b'\x48\x69\x20\x54\x68\x65\x72\x65',
            ),
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    attribute_factory.create_attribute(
                        enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                        256
                    )
                ]
            )
        )

        args = (payload, )
        self.assertRaisesRegexp(
            exceptions.InvalidField,
            "The cryptographic algorithm must be provided in the template "
            "attribute when deriving a symmetric key.",
            e._process_derive_key,
            *args
        )

    def test_derive_key_oversized_cryptographic_length(self):
        """
        Test that the right error is thrown when an invalid cryptographic
        length is provided with a DeriveKey request.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        base_key = pie_objects.SymmetricKey(
            algorithm=enums.CryptographicAlgorithm.HMAC_SHA256,
            length=160,
            value=(
                b'\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
                b'\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
                b'\x0b\x0b\x0b\x0b'
            ),
            masks=[enums.CryptographicUsageMask.DERIVE_KEY]
        )
        e._data_session.add(base_key)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._cryptography_engine = mock.MagicMock()
        e._cryptography_engine.derive_key.return_value = b''

        attribute_factory = factory.AttributeFactory()

        payload = payloads.DeriveKeyRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifiers=[str(base_key.unique_identifier)],
            derivation_method=enums.DerivationMethod.HMAC,
            derivation_parameters=attributes.DerivationParameters(
                cryptographic_parameters=attributes.CryptographicParameters(
                    hashing_algorithm=enums.HashingAlgorithm.SHA_256
                ),
                derivation_data=b'\x48\x69\x20\x54\x68\x65\x72\x65',
            ),
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    attribute_factory.create_attribute(
                        enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                        256
                    ),
                    attribute_factory.create_attribute(
                        enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                        enums.CryptographicAlgorithm.AES
                    )
                ]
            )
        )

        args = (payload, )
        self.assertRaisesRegexp(
            exceptions.CryptographicFailure,
            "The specified length exceeds the output of the derivation "
            "method.",
            e._process_derive_key,
            *args
        )

    def test_locate(self):
        """
        Test that a Locate request can be processed correctly.
        """
        # TODO Need add more extensive tests after locate operaton is
        # fully supported
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()

        obj_a = pie_objects.OpaqueObject(b'', enums.OpaqueDataType.NONE)
        obj_b = pie_objects.OpaqueObject(b'', enums.OpaqueDataType.NONE)

        # locate should return nothing at beginning
        payload = payloads.LocateRequestPayload()
        response_payload = e._process_locate(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Locate"
        )
        self.assertEqual(
           len(response_payload.unique_identifiers),
           0
        )

        # Add the first obj and test the locate
        e._data_session.add(obj_a)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        id_a = str(obj_a.unique_identifier)

        payload = payloads.LocateRequestPayload()
        e._logger.reset_mock()
        response_payload = e._process_locate(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Locate"
        )

        self.assertEqual(
           len(response_payload.unique_identifiers),
           1
        )
        self.assertEqual(
            id_a,
            response_payload.unique_identifiers[0].value
        )

        # Add the second obj and test the locate
        e._data_session.add(obj_b)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        id_b = str(obj_b.unique_identifier)

        payload = payloads.LocateRequestPayload()
        e._logger.reset_mock()
        response_payload = e._process_locate(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Locate"
        )

        self.assertEqual(
           len(response_payload.unique_identifiers),
           2
        )
        self.assertIn(
            id_a,
            [uid.value for uid in response_payload.unique_identifiers]
        )
        self.assertIn(
            id_b,
            [uid.value for uid in response_payload.unique_identifiers]
        )

    def test_locate_with_name(self):
        """
        Test locate operation when 'Name' attribute is given.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()

        key = (b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
               b'\x00\x00\x00\x00\x00')
        obj_a = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, key, name='name0')
        obj_b = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.DES, 128, key, name='name0')
        obj_c = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, key, name='name1')

        e._data_session.add(obj_a)
        e._data_session.add(obj_b)
        e._data_session.add(obj_c)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        id_a = str(obj_a.unique_identifier)
        id_b = str(obj_b.unique_identifier)
        id_c = str(obj_c.unique_identifier)

        attribute_factory = factory.AttributeFactory()

        # Locate the obj with name 'name0'
        attrs = [
                attribute_factory.create_attribute(
                    enums.AttributeType.NAME,
                    attributes.Name.create(
                        'name0',
                        enums.NameType.UNINTERPRETED_TEXT_STRING
                    )
                ),
        ]

        payload = payloads.LocateRequestPayload(attributes=attrs)
        e._logger.reset_mock()
        response_payload = e._process_locate(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Locate"
        )

        self.assertEqual(
           len(response_payload.unique_identifiers),
           2
        )
        self.assertIn(
            id_a,
            [uid.value for uid in response_payload.unique_identifiers]
        )
        self.assertIn(
            id_b,
            [uid.value for uid in response_payload.unique_identifiers]
        )

        # Locate the obj with name 'name1'
        attrs = [
                attribute_factory.create_attribute(
                    enums.AttributeType.NAME,
                    attributes.Name.create(
                        'name1',
                        enums.NameType.UNINTERPRETED_TEXT_STRING
                    )
                ),
        ]

        payload = payloads.LocateRequestPayload(attributes=attrs)
        e._logger.reset_mock()
        response_payload = e._process_locate(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Locate"
        )

        self.assertEqual(
           len(response_payload.unique_identifiers),
           1
        )
        self.assertIn(
            id_c,
            [uid.value for uid in response_payload.unique_identifiers]
        )

    def test_get(self):
        """
        Test that a Get request can be processed correctly.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()

        obj_a = pie_objects.OpaqueObject(b'', enums.OpaqueDataType.NONE)
        obj_b = pie_objects.OpaqueObject(b'', enums.OpaqueDataType.NONE)

        e._data_session.add(obj_a)
        e._data_session.add(obj_b)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        id_a = str(obj_a.unique_identifier)
        id_b = str(obj_b.unique_identifier)

        # Test by specifying the ID of the object to get.
        payload = payloads.GetRequestPayload(unique_identifier=id_a)

        response_payload = e._process_get(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Get"
        )
        self.assertEqual(
            enums.ObjectType.OPAQUE_DATA,
            response_payload.object_type
        )
        self.assertEqual(str(id_a), response_payload.unique_identifier)
        self.assertIsInstance(response_payload.secret, secrets.OpaqueObject)
        self.assertEqual(
            enums.OpaqueDataType.NONE,
            response_payload.secret.opaque_data_type.value
        )
        self.assertEqual(
            b'',
            response_payload.secret.opaque_data_value.value
        )

        e._data_session.commit()
        e._data_store_session_factory()
        e._logger.reset_mock()
        e._id_placeholder = str(id_b)

        # Test by using the ID placeholder to specify the object to get.
        payload = payloads.GetRequestPayload()

        response_payload = e._process_get(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Get"
        )
        self.assertEqual(
            enums.ObjectType.OPAQUE_DATA,
            response_payload.object_type
        )
        self.assertEqual(str(id_b), response_payload.unique_identifier)
        self.assertIsInstance(response_payload.secret, secrets.OpaqueObject)
        self.assertEqual(
            enums.OpaqueDataType.NONE,
            response_payload.secret.opaque_data_type.value
        )
        self.assertEqual(
            b'',
            response_payload.secret.opaque_data_value.value
        )

        e._data_session.commit()

    def test_get_unsupported_key_compression(self):
        """
        Test that the right error is generated when key compression is
        provided in a Get request.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._logger = mock.MagicMock()

        # Test that specifying the key compression type generates an error.
        k = enums.KeyCompressionType.EC_PUBLIC_KEY_TYPE_UNCOMPRESSED
        payload = payloads.GetRequestPayload(key_compression_type=k)

        args = (payload, )
        regex = "Key compression is not supported."
        six.assertRaisesRegex(
            self,
            exceptions.KeyCompressionTypeNotSupported,
            regex,
            e._process_get,
            *args
        )
        e._logger.info.assert_any_call(
            "Processing operation: Get"
        )

    def test_get_with_key_format_type(self):
        """
        Test that the key format type is handled properly in a Get request.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()

        obj_a = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            0,
            b''
        )

        e._data_session.add(obj_a)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        id_a = str(obj_a.unique_identifier)

        # Test that a key can be retrieved with the right key format.
        payload = payloads.GetRequestPayload(
            unique_identifier=id_a,
            key_format_type=enums.KeyFormatType.RAW
        )

        response_payload = e._process_get(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Get"
        )

        self.assertIsInstance(response_payload.secret, secrets.SymmetricKey)
        self.assertEqual(
            enums.CryptographicAlgorithm.AES,
            response_payload.secret.key_block.cryptographic_algorithm.value
        )
        self.assertEqual(
            0,
            response_payload.secret.key_block.cryptographic_length.value
        )
        self.assertEqual(
            b'',
            response_payload.secret.key_block.key_value.key_material.value
        )
        self.assertEqual(
            enums.KeyFormatType.RAW,
            response_payload.secret.key_block.key_format_type.value
        )

        # Test that an error is generated when a key format conversion is
        # required.
        e._logger.reset_mock()

        payload = payloads.GetRequestPayload(
            unique_identifier=id_a,
            key_format_type=enums.KeyFormatType.OPAQUE
        )

        args = (payload, )
        regex = "Key format conversion from RAW to OPAQUE is unsupported."
        six.assertRaisesRegex(
            self,
            exceptions.KeyFormatTypeNotSupported,
            regex,
            e._process_get,
            *args
        )
        e._logger.info.assert_any_call(
            "Processing operation: Get"
        )

        # Test that an error is generated when a key format is requested but
        # does not apply to the given managed object.
        e._data_session = e._data_store_session_factory()
        e._logger.reset_mock()

        obj_b = pie_objects.OpaqueObject(b'', enums.OpaqueDataType.NONE)

        e._data_session.add(obj_b)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        id_b = str(obj_b.unique_identifier)

        payload = payloads.GetRequestPayload(
            unique_identifier=id_b,
            key_format_type=enums.KeyFormatType.RAW
        )

        args = (payload, )
        regex = "Key format is not applicable to the specified object."
        six.assertRaisesRegex(
            self,
            exceptions.KeyFormatTypeNotSupported,
            regex,
            e._process_get,
            *args
        )
        e._logger.info.assert_any_call(
            "Processing operation: Get"
        )

    def test_get_not_allowed_by_policy(self):
        """
        Test that an unallowed request is handled correctly by Get.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=False)
        e._logger = mock.MagicMock()
        e._client_identity = 'test'

        obj_a = pie_objects.OpaqueObject(b'', enums.OpaqueDataType.NONE)
        obj_a._owner = 'admin'

        e._data_session.add(obj_a)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        id_a = str(obj_a.unique_identifier)
        payload = payloads.GetRequestPayload(unique_identifier=id_a)

        # Test by specifying the ID of the object to get.
        args = [payload]
        six.assertRaisesRegex(
            self,
            exceptions.PermissionDenied,
            "Could not locate object: {0}".format(id_a),
            e._process_get,
            *args
        )

    def test_get_wrapped_key(self):
        """
        Test that a Get request for a wrapped key can be processed correctly.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        wrapping_key = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            128,
            (
                b'\x00\x01\x02\x03\x04\x05\x06\x07'
                b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
            ),
            [enums.CryptographicUsageMask.WRAP_KEY]
        )
        wrapping_key.state = enums.State.ACTIVE

        unwrapped_key = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            128,
            (
                b'\x00\x11\x22\x33\x44\x55\x66\x77'
                b'\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF'
            ),
            [enums.CryptographicUsageMask.ENCRYPT]
        )

        e._data_session.add(wrapping_key)
        e._data_session.add(unwrapped_key)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        wrapping_key_uuid = str(wrapping_key.unique_identifier)
        unwrapped_key_uuid = str(unwrapped_key.unique_identifier)

        cryptographic_parameters = attributes.CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
        )
        payload = payloads.GetRequestPayload(
            unique_identifier=unwrapped_key_uuid,
            key_wrapping_specification=objects.KeyWrappingSpecification(
                wrapping_method=enums.WrappingMethod.ENCRYPT,
                encryption_key_information=objects.EncryptionKeyInformation(
                    unique_identifier=wrapping_key_uuid,
                    cryptographic_parameters=cryptographic_parameters
                ),
                encoding_option=enums.EncodingOption.NO_ENCODING
            )
        )

        response_payload = e._process_get(payload)

        e._logger.info.assert_any_call("Processing operation: Get")
        e._logger.info.assert_any_call(
            "Wrapping SymmetricKey 2 with SymmetricKey 1."
        )
        self.assertEqual(
            enums.ObjectType.SYMMETRIC_KEY,
            response_payload.object_type
        )
        self.assertEqual(
            unwrapped_key_uuid,
            response_payload.unique_identifier
        )
        self.assertIsInstance(
            response_payload.secret,
            secrets.SymmetricKey
        )
        self.assertEqual(
            (
                b'\x1F\xA6\x8B\x0A\x81\x12\xB4\x47'
                b'\xAE\xF3\x4B\xD8\xFB\x5A\x7B\x82'
                b'\x9D\x3E\x86\x23\x71\xD2\xCF\xE5'
            ),
            response_payload.secret.key_block.key_value.key_material.value
        )
        self.assertIsInstance(
            response_payload.secret.key_block.key_wrapping_data,
            objects.KeyWrappingData
        )
        k = response_payload.secret.key_block.key_wrapping_data
        self.assertEqual(
            enums.WrappingMethod.ENCRYPT,
            k.wrapping_method
        )
        self.assertIsInstance(
            k.encryption_key_information,
            objects.EncryptionKeyInformation
        )
        self.assertEqual(
            '1',
            k.encryption_key_information.unique_identifier
        )
        self.assertIsInstance(
            k.encryption_key_information.cryptographic_parameters,
            attributes.CryptographicParameters
        )
        c = k.encryption_key_information.cryptographic_parameters
        self.assertEqual(
            enums.BlockCipherMode.NIST_KEY_WRAP,
            c.block_cipher_mode
        )
        self.assertEqual(
            enums.EncodingOption.NO_ENCODING,
            k.encoding_option
        )

    def test_get_wrapped_key_unsupported_mac_sig(self):
        """
        Test that the right error is thrown when key wrapping is requested
        via MAC/signing in a Get request.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        wrapping_key = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            128,
            (
                b'\x00\x01\x02\x03\x04\x05\x06\x07'
                b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
            ),
            [enums.CryptographicUsageMask.WRAP_KEY]
        )
        wrapping_key.state = enums.State.ACTIVE

        unwrapped_key = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            128,
            (
                b'\x00\x11\x22\x33\x44\x55\x66\x77'
                b'\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF'
            ),
            [enums.CryptographicUsageMask.ENCRYPT]
        )

        e._data_session.add(wrapping_key)
        e._data_session.add(unwrapped_key)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        wrapping_key_uuid = str(wrapping_key.unique_identifier)
        unwrapped_key_uuid = str(unwrapped_key.unique_identifier)
        cryptographic_parameters = attributes.CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
        )
        payload = payloads.GetRequestPayload(
            unique_identifier=unwrapped_key_uuid,
            key_wrapping_specification=objects.KeyWrappingSpecification(
                wrapping_method=enums.WrappingMethod.MAC_SIGN,
                mac_signature_key_information=objects.
                MACSignatureKeyInformation(
                    unique_identifier=wrapping_key_uuid,
                    cryptographic_parameters=cryptographic_parameters
                ),
                encoding_option=enums.EncodingOption.NO_ENCODING
            )
        )

        args = (payload, )
        self.assertRaisesRegexp(
            exceptions.OperationNotSupported,
            "Wrapping method '{0}' is not supported.".format(
                enums.WrappingMethod.MAC_SIGN
            ),
            e._process_get,
            *args
        )

    def test_get_wrapped_key_unsupported_mac_sign_key_info(self):
        """
        Test that the right error is thrown when key wrapping is requested
        with MAC/signing key information in a Get request.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        wrapping_key = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            128,
            (
                b'\x00\x01\x02\x03\x04\x05\x06\x07'
                b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
            ),
            [enums.CryptographicUsageMask.WRAP_KEY]
        )
        wrapping_key.state = enums.State.ACTIVE

        unwrapped_key = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            128,
            (
                b'\x00\x11\x22\x33\x44\x55\x66\x77'
                b'\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF'
            ),
            [enums.CryptographicUsageMask.ENCRYPT]
        )

        e._data_session.add(wrapping_key)
        e._data_session.add(unwrapped_key)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        wrapping_key_uuid = str(wrapping_key.unique_identifier)
        unwrapped_key_uuid = str(unwrapped_key.unique_identifier)
        cryptographic_parameters = attributes.CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
        )
        payload = payloads.GetRequestPayload(
            unique_identifier=unwrapped_key_uuid,
            key_wrapping_specification=objects.KeyWrappingSpecification(
                wrapping_method=enums.WrappingMethod.ENCRYPT,
                mac_signature_key_information=objects.
                MACSignatureKeyInformation(
                    unique_identifier=wrapping_key_uuid,
                    cryptographic_parameters=cryptographic_parameters
                ),
                encoding_option=enums.EncodingOption.NO_ENCODING
            )
        )

        args = (payload, )
        self.assertRaisesRegexp(
            exceptions.PermissionDenied,
            "Key wrapping with MAC/signing key information is not supported.",
            e._process_get,
            *args
        )

    def test_get_wrapped_key_missing_key_information(self):
        """
        Test that the right error is thrown when key wrapping is requested
        with no settings in a Get request.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        unwrapped_key = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            128,
            (
                b'\x00\x11\x22\x33\x44\x55\x66\x77'
                b'\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF'
            ),
            [enums.CryptographicUsageMask.ENCRYPT]
        )

        e._data_session.add(unwrapped_key)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        unwrapped_key_uuid = str(unwrapped_key.unique_identifier)
        payload = payloads.GetRequestPayload(
            unique_identifier=unwrapped_key_uuid,
            key_wrapping_specification=objects.KeyWrappingSpecification(
                wrapping_method=enums.WrappingMethod.ENCRYPT,
                encoding_option=enums.EncodingOption.NO_ENCODING
            )
        )

        args = (payload, )
        self.assertRaisesRegexp(
            exceptions.PermissionDenied,
            "Either the encryption key information or the MAC/signature key "
            "information must be specified for key wrapping to be performed.",
            e._process_get,
            *args
        )

    def test_get_wrapped_key_nonexistent_wrapping_key(self):
        """
        Test that the right error is thrown when key wrapping is requested
        with a nonexistent wrapping key in a Get request.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        unwrapped_key = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            128,
            (
                b'\x00\x11\x22\x33\x44\x55\x66\x77'
                b'\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF'
            ),
            [enums.CryptographicUsageMask.ENCRYPT]
        )

        e._data_session.add(unwrapped_key)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        unwrapped_key_uuid = str(unwrapped_key.unique_identifier)

        cryptographic_parameters = attributes.CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
        )
        payload = payloads.GetRequestPayload(
            unique_identifier=unwrapped_key_uuid,
            key_wrapping_specification=objects.KeyWrappingSpecification(
                wrapping_method=enums.WrappingMethod.ENCRYPT,
                encryption_key_information=objects.EncryptionKeyInformation(
                    unique_identifier='invalid',
                    cryptographic_parameters=cryptographic_parameters
                ),
                encoding_option=enums.EncodingOption.NO_ENCODING
            )
        )

        args = (payload, )
        self.assertRaisesRegexp(
            exceptions.ItemNotFound,
            "Wrapping key does not exist.",
            e._process_get,
            *args
        )

    def test_get_wrapped_key_non_wrapping_key(self):
        """
        Test that the right error is thrown when key wrapping is requested
        with a non-wrapping key in a Get request.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        wrapping_key = pie_objects.SecretData(
            (
                b'\x00\x01\x02\x03\x04\x05\x06\x07'
                b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
            ),
            enums.SecretDataType.SEED,
            masks=[enums.CryptographicUsageMask.WRAP_KEY]
        )
        wrapping_key.state = enums.State.ACTIVE

        unwrapped_key = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            128,
            (
                b'\x00\x11\x22\x33\x44\x55\x66\x77'
                b'\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF'
            ),
            [enums.CryptographicUsageMask.ENCRYPT]
        )

        e._data_session.add(wrapping_key)
        e._data_session.add(unwrapped_key)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        wrapping_key_uuid = str(wrapping_key.unique_identifier)
        unwrapped_key_uuid = str(unwrapped_key.unique_identifier)

        cryptographic_parameters = attributes.CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
        )
        payload = payloads.GetRequestPayload(
            unique_identifier=unwrapped_key_uuid,
            key_wrapping_specification=objects.KeyWrappingSpecification(
                wrapping_method=enums.WrappingMethod.ENCRYPT,
                encryption_key_information=objects.EncryptionKeyInformation(
                    unique_identifier=wrapping_key_uuid,
                    cryptographic_parameters=cryptographic_parameters
                ),
                encoding_option=enums.EncodingOption.NO_ENCODING
            )
        )

        args = (payload, )
        self.assertRaisesRegexp(
            exceptions.IllegalOperation,
            "The wrapping encryption key specified by the encryption key "
            "information is not a key.",
            e._process_get,
            *args
        )

    def test_get_wrapped_key_inactive_wrapping_key(self):
        """
        Test that the right error is thrown when key wrapping is requested
        with an inactive wrapping key in a Get request.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        wrapping_key = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            128,
            (
                b'\x00\x01\x02\x03\x04\x05\x06\x07'
                b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
            ),
            [enums.CryptographicUsageMask.WRAP_KEY]
        )

        unwrapped_key = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            128,
            (
                b'\x00\x11\x22\x33\x44\x55\x66\x77'
                b'\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF'
            ),
            [enums.CryptographicUsageMask.ENCRYPT]
        )

        e._data_session.add(wrapping_key)
        e._data_session.add(unwrapped_key)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        wrapping_key_uuid = str(wrapping_key.unique_identifier)
        unwrapped_key_uuid = str(unwrapped_key.unique_identifier)

        cryptographic_parameters = attributes.CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
        )
        payload = payloads.GetRequestPayload(
            unique_identifier=unwrapped_key_uuid,
            key_wrapping_specification=objects.KeyWrappingSpecification(
                wrapping_method=enums.WrappingMethod.ENCRYPT,
                encryption_key_information=objects.EncryptionKeyInformation(
                    unique_identifier=wrapping_key_uuid,
                    cryptographic_parameters=cryptographic_parameters
                ),
                encoding_option=enums.EncodingOption.NO_ENCODING
            )
        )

        args = (payload, )
        self.assertRaisesRegexp(
            exceptions.PermissionDenied,
            "Encryption key 1 must be activated to be used for key "
            "wrapping.",
            e._process_get,
            *args
        )

    def test_get_wrapped_key_invalid_wrapping_key(self):
        """
        Test that the right error is thrown when key wrapping is requested
        with a wrapping key not designated for key wrapping in a Get request.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        wrapping_key = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            128,
            (
                b'\x00\x01\x02\x03\x04\x05\x06\x07'
                b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
            ),
            [enums.CryptographicUsageMask.ENCRYPT]
        )
        wrapping_key.state = enums.State.ACTIVE

        unwrapped_key = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            128,
            (
                b'\x00\x11\x22\x33\x44\x55\x66\x77'
                b'\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF'
            ),
            [enums.CryptographicUsageMask.ENCRYPT]
        )

        e._data_session.add(wrapping_key)
        e._data_session.add(unwrapped_key)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        wrapping_key_uuid = str(wrapping_key.unique_identifier)
        unwrapped_key_uuid = str(unwrapped_key.unique_identifier)

        cryptographic_parameters = attributes.CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
        )
        payload = payloads.GetRequestPayload(
            unique_identifier=unwrapped_key_uuid,
            key_wrapping_specification=objects.KeyWrappingSpecification(
                wrapping_method=enums.WrappingMethod.ENCRYPT,
                encryption_key_information=objects.EncryptionKeyInformation(
                    unique_identifier=wrapping_key_uuid,
                    cryptographic_parameters=cryptographic_parameters
                ),
                encoding_option=enums.EncodingOption.NO_ENCODING
            )
        )

        args = (payload, )
        self.assertRaisesRegexp(
            exceptions.PermissionDenied,
            "The WrapKey bit must be set in the cryptographic usage mask of "
            "encryption key 1 for it to be used for key wrapping.",
            e._process_get,
            *args
        )

    def test_get_wrapped_key_unsupported_attribute_wrapping(self):
        """
        Test that the right error is thrown when key wrapping is requested
        with attribute names in a Get request.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        wrapping_key = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            128,
            (
                b'\x00\x01\x02\x03\x04\x05\x06\x07'
                b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
            ),
            [enums.CryptographicUsageMask.WRAP_KEY]
        )
        wrapping_key.state = enums.State.ACTIVE

        unwrapped_key = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            128,
            (
                b'\x00\x11\x22\x33\x44\x55\x66\x77'
                b'\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF'
            ),
            [enums.CryptographicUsageMask.ENCRYPT]
        )

        e._data_session.add(wrapping_key)
        e._data_session.add(unwrapped_key)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        wrapping_key_uuid = str(wrapping_key.unique_identifier)
        unwrapped_key_uuid = str(unwrapped_key.unique_identifier)

        cryptographic_parameters = attributes.CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
        )
        payload = payloads.GetRequestPayload(
            unique_identifier=unwrapped_key_uuid,
            key_wrapping_specification=objects.KeyWrappingSpecification(
                wrapping_method=enums.WrappingMethod.ENCRYPT,
                encryption_key_information=objects.EncryptionKeyInformation(
                    unique_identifier=wrapping_key_uuid,
                    cryptographic_parameters=cryptographic_parameters
                ),
                attribute_names=['Cryptographic Algorithm'],
                encoding_option=enums.EncodingOption.NO_ENCODING
            )
        )

        args = (payload, )
        self.assertRaisesRegexp(
            exceptions.IllegalOperation,
            "Wrapping object attributes is not supported.",
            e._process_get,
            *args
        )

    def test_get_wrapped_key_invalid_encoding(self):
        """
        Test that the right error is thrown when key wrapping is requested
        with an unsupported encoding option in a Get request.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        wrapping_key = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            128,
            (
                b'\x00\x01\x02\x03\x04\x05\x06\x07'
                b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
            ),
            [enums.CryptographicUsageMask.WRAP_KEY]
        )
        wrapping_key.state = enums.State.ACTIVE

        unwrapped_key = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            128,
            (
                b'\x00\x11\x22\x33\x44\x55\x66\x77'
                b'\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF'
            ),
            [enums.CryptographicUsageMask.ENCRYPT]
        )

        e._data_session.add(wrapping_key)
        e._data_session.add(unwrapped_key)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        wrapping_key_uuid = str(wrapping_key.unique_identifier)
        unwrapped_key_uuid = str(unwrapped_key.unique_identifier)

        cryptographic_parameters = attributes.CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
        )
        payload = payloads.GetRequestPayload(
            unique_identifier=unwrapped_key_uuid,
            key_wrapping_specification=objects.KeyWrappingSpecification(
                wrapping_method=enums.WrappingMethod.ENCRYPT,
                encryption_key_information=objects.EncryptionKeyInformation(
                    unique_identifier=wrapping_key_uuid,
                    cryptographic_parameters=cryptographic_parameters
                ),
                encoding_option=enums.EncodingOption.TTLV_ENCODING
            )
        )

        args = (payload, )
        self.assertRaisesRegexp(
            exceptions.EncodingOptionError,
            "Encoding option '{0}' is not supported.".format(
                enums.EncodingOption.TTLV_ENCODING
            ),
            e._process_get,
            *args
        )

    def test_get_attributes(self):
        """
        Test that a GetAttributes request can be processed correctly.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()

        secret = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            0,
            b''
        )

        e._data_session.add(secret)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        payload = payloads.GetAttributesRequestPayload(
            unique_identifier='1',
            attribute_names=['Object Type', 'Cryptographic Algorithm']
        )

        response_payload = e._process_get_attributes(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: GetAttributes"
        )
        self.assertEqual(
            '1',
            response_payload.unique_identifier
        )
        self.assertEqual(
            2,
            len(response_payload.attributes)
        )

        attribute_factory = factory.AttributeFactory()

        attribute = attribute_factory.create_attribute(
            enums.AttributeType.OBJECT_TYPE,
            enums.ObjectType.SYMMETRIC_KEY
        )
        self.assertIn(attribute, response_payload.attributes)

        attribute = attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
            enums.CryptographicAlgorithm.AES
        )
        self.assertIn(attribute, response_payload.attributes)

    def test_get_attributes_with_no_arguments(self):
        """
        Test that a GetAttributes request with no arguments can be processed
        correctly.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()

        secret = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            0,
            b''
        )

        e._data_session.add(secret)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()
        e._id_placeholder = '1'

        payload = payloads.GetAttributesRequestPayload()

        response_payload = e._process_get_attributes(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: GetAttributes"
        )
        self.assertEqual(
            '1',
            response_payload.unique_identifier
        )
        self.assertEqual(
            9,
            len(response_payload.attributes)
        )

        attribute_factory = factory.AttributeFactory()

        attribute = attribute_factory.create_attribute(
            enums.AttributeType.OBJECT_TYPE,
            enums.ObjectType.SYMMETRIC_KEY
        )
        self.assertIn(attribute, response_payload.attributes)

        attribute = attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
            enums.CryptographicAlgorithm.AES
        )
        self.assertIn(attribute, response_payload.attributes)

        attribute = attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
            0
        )
        self.assertIn(attribute, response_payload.attributes)

        attribute = attribute_factory.create_attribute(
            enums.AttributeType.OPERATION_POLICY_NAME,
            'default'
        )
        self.assertIn(attribute, response_payload.attributes)

        attribute = attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
            []
        )
        self.assertIn(attribute, response_payload.attributes)

        attribute = attribute_factory.create_attribute(
            enums.AttributeType.STATE,
            enums.State.PRE_ACTIVE
        )
        self.assertIn(attribute, response_payload.attributes)

        attribute = attribute_factory.create_attribute(
            enums.AttributeType.UNIQUE_IDENTIFIER,
            '1'
        )
        self.assertIn(attribute, response_payload.attributes)

    def test_get_attributes_not_allowed_by_policy(self):
        """
        Test that an unallowed request is handled correctly by GetAttributes.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=False)
        e._logger = mock.MagicMock()
        e._client_identity = 'test'

        obj_a = pie_objects.OpaqueObject(b'', enums.OpaqueDataType.NONE)
        obj_a._owner = 'admin'

        e._data_session.add(obj_a)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        id_a = str(obj_a.unique_identifier)
        payload = payloads.GetAttributesRequestPayload(
            unique_identifier=id_a
        )

        # Test by specifying the ID of the object whose attributes should
        # be retrieved.
        args = [payload]
        self.assertRaisesRegex(
            exceptions.PermissionDenied,
            "Could not locate object: {0}".format(id_a),
            e._process_get_attributes,
            *args
        )

    def test_get_attribute_list(self):
        """
        Test that a GetAttributeList request can be processed correctly.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()

        secret = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            0,
            b''
        )

        e._data_session.add(secret)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        payload = payloads.GetAttributeListRequestPayload(
            unique_identifier='1'
        )

        response_payload = e._process_get_attribute_list(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: GetAttributeList"
        )
        self.assertEqual(
            '1',
            response_payload.unique_identifier
        )
        self.assertEqual(
            9,
            len(response_payload.attribute_names)
        )
        self.assertIn(
            "Object Type",
            response_payload.attribute_names
        )
        self.assertIn(
            "Name",
            response_payload.attribute_names
        )
        self.assertIn(
            "Cryptographic Algorithm",
            response_payload.attribute_names
        )
        self.assertIn(
            "Cryptographic Length",
            response_payload.attribute_names
        )
        self.assertIn(
            "Operation Policy Name",
            response_payload.attribute_names
        )
        self.assertIn(
            "Cryptographic Usage Mask",
            response_payload.attribute_names
        )
        self.assertIn(
            "State",
            response_payload.attribute_names
        )
        self.assertIn(
            "Unique Identifier",
            response_payload.attribute_names
        )
        self.assertIn(
            "Initial Date",
            response_payload.attribute_names
        )

    def test_get_attribute_list_with_no_arguments(self):
        """
        Test that a GetAttributeList request with no arguments can be
        processed correctly.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()

        secret = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            0,
            b''
        )

        e._data_session.add(secret)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()
        e._id_placeholder = '1'

        payload = payloads.GetAttributeListRequestPayload()

        response_payload = e._process_get_attribute_list(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: GetAttributeList"
        )
        self.assertEqual(
            '1',
            response_payload.unique_identifier
        )
        self.assertEqual(
            9,
            len(response_payload.attribute_names)
        )
        self.assertIn(
            "Object Type",
            response_payload.attribute_names
        )
        self.assertIn(
            "Name",
            response_payload.attribute_names
        )
        self.assertIn(
            "Cryptographic Algorithm",
            response_payload.attribute_names
        )
        self.assertIn(
            "Cryptographic Length",
            response_payload.attribute_names
        )
        self.assertIn(
            "Operation Policy Name",
            response_payload.attribute_names
        )
        self.assertIn(
            "Cryptographic Usage Mask",
            response_payload.attribute_names
        )
        self.assertIn(
            "State",
            response_payload.attribute_names
        )
        self.assertIn(
            "Unique Identifier",
            response_payload.attribute_names
        )
        self.assertIn(
            "Initial Date",
            response_payload.attribute_names
        )

    def test_get_attribute_list_not_allowed_by_policy(self):
        """
        Test that an unallowed request is handled correctly by
        GetAttributeList.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=False)
        e._logger = mock.MagicMock()
        e._client_identity = 'test'

        obj_a = pie_objects.OpaqueObject(b'', enums.OpaqueDataType.NONE)
        obj_a._owner = 'admin'

        e._data_session.add(obj_a)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        id_a = str(obj_a.unique_identifier)
        payload = payloads.GetAttributeListRequestPayload(
            unique_identifier=id_a
        )

        # Test by specifying the ID of the object whose attributes should
        # be retrieved.
        args = [payload]
        self.assertRaisesRegex(
            exceptions.PermissionDenied,
            "Could not locate object: {0}".format(id_a),
            e._process_get_attribute_list,
            *args
        )

    def test_activate(self):
        """
        Test that an Activate request can be processed correctly.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()

        managed_object = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            0,
            b''
        )
        e._data_session.add(managed_object)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        self.assertEqual(enums.State.PRE_ACTIVE, managed_object.state)

        object_id = str(managed_object.unique_identifier)

        # Test by specifying the ID of the object to activate.
        payload = payloads.ActivateRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(object_id)
        )

        response_payload = e._process_activate(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Activate"
        )
        self.assertEqual(
            str(object_id),
            response_payload.unique_identifier.value
        )

        symmetric_key = e._data_session.query(
            pie_objects.SymmetricKey
        ).filter(
            pie_objects.ManagedObject.unique_identifier == object_id
        ).one()

        self.assertEqual(enums.State.ACTIVE, symmetric_key.state)

        args = (payload,)
        regex = "The object state is not pre-active and cannot be activated."
        self.assertRaisesRegexp(
            exceptions.PermissionDenied,
            regex,
            e._process_activate,
            *args
        )

        # Test that the ID placeholder can also be used to specify activation.
        e._id_placeholder = str(object_id)
        payload = payloads.ActivateRequestPayload()
        args = (payload,)
        regex = "The object state is not pre-active and cannot be activated."
        self.assertRaisesRegexp(
            exceptions.PermissionDenied,
            regex,
            e._process_activate,
            *args
        )

    def test_activate_on_static_object(self):
        """
        Test that the right error is generated when an activation request is
        received for an object that cannot be activated.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()

        managed_object = pie_objects.OpaqueObject(
            b'',
            enums.OpaqueDataType.NONE
        )
        e._data_session.add(managed_object)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        object_id = str(managed_object.unique_identifier)

        # Test by specifying the ID of the object to activate.
        payload = payloads.ActivateRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(object_id)
        )

        args = (payload,)
        name = enums.ObjectType.OPAQUE_DATA.name
        regex = "An {0} object has no state and cannot be activated.".format(
            ''.join(
                [x.capitalize() for x in name.split('_')]
            )
        )
        self.assertRaisesRegexp(
            exceptions.IllegalOperation,
            regex,
            e._process_activate,
            *args
        )

    def test_activate_on_active_object(self):
        """
        Test that the right error is generated when an activation request is
        received for an object that is not pre-active.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()

        managed_object = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            0,
            b''
        )
        managed_object.state = enums.State.ACTIVE
        e._data_session.add(managed_object)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        object_id = str(managed_object.unique_identifier)

        # Test by specifying the ID of the object to activate.
        payload = payloads.ActivateRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(object_id)
        )

        args = (payload,)
        regex = "The object state is not pre-active and cannot be activated."
        self.assertRaisesRegexp(
            exceptions.PermissionDenied,
            regex,
            e._process_activate,
            *args
        )

    def test_activate_not_allowed_by_policy(self):
        """
        Test that an unallowed request is handled correctly by Activate.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=False)
        e._logger = mock.MagicMock()
        e._client_identity = 'test'

        obj_a = pie_objects.OpaqueObject(b'', enums.OpaqueDataType.NONE)
        obj_a._owner = 'admin'

        e._data_session.add(obj_a)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        id_a = str(obj_a.unique_identifier)
        payload = payloads.ActivateRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(id_a)
        )

        # Test by specifying the ID of the object to activate.
        args = [payload]
        self.assertRaisesRegex(
            exceptions.PermissionDenied,
            "Could not locate object: {0}".format(id_a),
            e._process_activate,
            *args
        )

    def test_revoke(self):
        """
        Test that an Revoke request can be processed correctly.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()

        managed_object = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            0,
            b''
        )
        managed_object.state = enums.State.ACTIVE
        e._data_session.add(managed_object)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        object_id = str(managed_object.unique_identifier)

        reason_unspecified = objects.RevocationReason(
            code=enums.RevocationReasonCode.UNSPECIFIED)
        reason_compromise = objects.RevocationReason(
            code=enums.RevocationReasonCode.KEY_COMPROMISE)
        date = primitives.DateTime(
            tag=enums.Tags.COMPROMISE_OCCURRENCE_DATE, value=6)

        # Test that reason UNSPECIFIED will put object into state
        # DEACTIVATED
        payload = payloads.RevokeRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(object_id),
            revocation_reason=reason_unspecified,
            compromise_occurrence_date=date)

        response_payload = e._process_revoke(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Revoke"
        )
        self.assertEqual(
            str(object_id),
            response_payload.unique_identifier.value
        )

        symmetric_key = e._data_session.query(
            pie_objects.SymmetricKey
        ).filter(
            pie_objects.ManagedObject.unique_identifier == object_id
        ).one()

        self.assertEqual(enums.State.DEACTIVATED, symmetric_key.state)

        # Test that reason KEY_COMPROMISE will put object not in DESTROYED
        # state into state COMPROMISED
        payload = payloads.RevokeRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(object_id),
            revocation_reason=reason_compromise,
            compromise_occurrence_date=date)

        e._logger.reset_mock()

        response_payload = e._process_revoke(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Revoke"
        )
        self.assertEqual(
            str(object_id),
            response_payload.unique_identifier.value
        )

        symmetric_key = e._data_session.query(
            pie_objects.SymmetricKey
        ).filter(
            pie_objects.ManagedObject.unique_identifier == object_id
        ).one()

        self.assertEqual(enums.State.COMPROMISED, symmetric_key.state)

        # Test that reason KEY_COMPROMISE will put object in DESTROYED
        # state into state DESTROYED_COMPROMISED
        symmetric_key.state = enums.State.DESTROYED
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()
        e._logger.reset_mock()

        payload = payloads.RevokeRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(object_id),
            revocation_reason=reason_compromise,
            compromise_occurrence_date=date)
        response_payload = e._process_revoke(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Revoke"
        )
        self.assertEqual(
            str(object_id),
            response_payload.unique_identifier.value
        )
        symmetric_key = e._data_session.query(
            pie_objects.SymmetricKey
        ).filter(
            pie_objects.ManagedObject.unique_identifier == object_id
        ).one()

        self.assertEqual(enums.State.DESTROYED_COMPROMISED,
                         symmetric_key.state)

        # Test that the ID placeholder can also be used to specify revocation.
        symmetric_key.state = enums.State.ACTIVE
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()
        e._logger.reset_mock()

        e._id_placeholder = str(object_id)
        payload = payloads.RevokeRequestPayload(
            revocation_reason=reason_unspecified,
            compromise_occurrence_date=date)

        response_payload = e._process_revoke(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Revoke"
        )
        self.assertEqual(
            str(object_id),
            response_payload.unique_identifier.value
        )

        symmetric_key = e._data_session.query(
            pie_objects.SymmetricKey
        ).filter(
            pie_objects.ManagedObject.unique_identifier == object_id
        ).one()

        self.assertEqual(enums.State.DEACTIVATED, symmetric_key.state)

    def test_revoke_missing_revocation_reason(self):
        """
        Test that the right error is generated when a revocation request is
        received with a missing revocation reason.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()

        managed_object = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            0,
            b''
        )
        e._data_session.add(managed_object)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        self.assertEqual(enums.State.PRE_ACTIVE, managed_object.state)

        object_id = str(managed_object.unique_identifier)

        date = primitives.DateTime(
            tag=enums.Tags.COMPROMISE_OCCURRENCE_DATE, value=6)

        payload = payloads.RevokeRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(object_id),
            revocation_reason=None,
            compromise_occurrence_date=date)
        payload.revocation_reason = None

        args = (payload, )
        self.assertRaisesRegexp(
            exceptions.InvalidField,
            "revocation reason code must be specified",
            e._process_revoke,
            *args
        )

    def test_revoke_on_not_active_object(self):
        """
        Test that the right error is generated when an revocation request is
        received for an object that is not active with the reason other than
        KEY_COMPROMISE.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()

        managed_object = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            0,
            b''
        )
        e._data_session.add(managed_object)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        self.assertEqual(enums.State.PRE_ACTIVE, managed_object.state)

        object_id = str(managed_object.unique_identifier)

        reason_unspecified = objects.RevocationReason(
            code=enums.RevocationReasonCode.UNSPECIFIED)
        date = primitives.DateTime(
            tag=enums.Tags.COMPROMISE_OCCURRENCE_DATE, value=6)

        payload = payloads.RevokeRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(object_id),
            revocation_reason=reason_unspecified,
            compromise_occurrence_date=date)

        args = (payload, )
        regex = "The object is not active and cannot be revoked with " \
                "reason other than KEY_COMPROMISE"
        self.assertRaisesRegexp(
            exceptions.IllegalOperation,
            regex,
            e._process_revoke,
            *args
        )

    def test_revoke_on_static_object(self):
        """
        Test that the right error is generated when an revoke request is
        received for an object that cannot be revoked.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()

        managed_object = pie_objects.OpaqueObject(
            b'',
            enums.OpaqueDataType.NONE
        )
        e._data_session.add(managed_object)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        object_id = str(managed_object.unique_identifier)

        reason_unspecified = objects.RevocationReason(
            code=enums.RevocationReasonCode.UNSPECIFIED)
        date = primitives.DateTime(
            tag=enums.Tags.COMPROMISE_OCCURRENCE_DATE, value=6)

        payload = payloads.RevokeRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(object_id),
            revocation_reason=reason_unspecified,
            compromise_occurrence_date=date)

        args = (payload,)
        name = enums.ObjectType.OPAQUE_DATA.name
        regex = "An {0} object has no state and cannot be revoked.".format(
            ''.join(
                [x.capitalize() for x in name.split('_')]
            )
        )
        self.assertRaisesRegexp(
            exceptions.IllegalOperation,
            regex,
            e._process_revoke,
            *args
        )

    def test_revoke_not_allowed_by_policy(self):
        """
        Test that an unallowed request is handled correctly by Revoke.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=False)
        e._logger = mock.MagicMock()
        e._client_identity = 'test'

        obj_a = pie_objects.OpaqueObject(b'', enums.OpaqueDataType.NONE)
        obj_a._owner = 'admin'

        e._data_session.add(obj_a)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        id_a = str(obj_a.unique_identifier)

        reason_unspecified = objects.RevocationReason(
            code=enums.RevocationReasonCode.UNSPECIFIED)
        date = primitives.DateTime(
            tag=enums.Tags.COMPROMISE_OCCURRENCE_DATE, value=6)

        payload = payloads.RevokeRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(id_a),
            revocation_reason=reason_unspecified,
            compromise_occurrence_date=date)

        args = [payload]
        self.assertRaisesRegex(
            exceptions.PermissionDenied,
            "Could not locate object: {0}".format(id_a),
            e._process_revoke,
            *args
        )

    def test_destroy(self):
        """
        Test that a Destroy request can be processed correctly.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()

        obj_a = pie_objects.OpaqueObject(b'', enums.OpaqueDataType.NONE)
        obj_b = pie_objects.OpaqueObject(b'', enums.OpaqueDataType.NONE)
        key = (b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
               b'\x00\x00\x00\x00\x00')
        algorithm = enums.CryptographicAlgorithm.AES
        obj_c = pie_objects.SymmetricKey(algorithm, 128, key)
        obj_c.state = enums.State.COMPROMISED

        e._data_session.add(obj_a)
        e._data_session.add(obj_b)
        e._data_session.add(obj_c)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        id_a = str(obj_a.unique_identifier)
        id_b = str(obj_b.unique_identifier)
        id_c = str(obj_c.unique_identifier)

        # Test by specifying the ID of the object to destroy.
        payload = payloads.DestroyRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(id_a)
        )

        response_payload = e._process_destroy(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Destroy"
        )
        self.assertEqual(str(id_a), response_payload.unique_identifier.value)

        args = (payload, )
        regex = "Could not locate object: {0}".format(id_a)
        six.assertRaisesRegex(
            self,
            exceptions.ItemNotFound,
            regex,
            e._process_destroy,
            *args
        )

        e._data_session.commit()
        e._data_store_session_factory()
        e._logger.reset_mock()
        e._id_placeholder = str(id_b)

        # Test by using the ID placeholder to specify the object to destroy.
        payload = payloads.DestroyRequestPayload()

        response_payload = e._process_destroy(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Destroy"
        )
        self.assertEqual(str(id_b), response_payload.unique_identifier.value)

        args = (payload, )
        regex = "Could not locate object: {0}".format(id_b)
        six.assertRaisesRegex(
            self,
            exceptions.ItemNotFound,
            regex,
            e._process_destroy,
            *args
        )

        e._data_session.commit()
        e._data_store_session_factory()
        e._logger.reset_mock()

        # Test that compromised object can be destroyed properly
        payload = payloads.DestroyRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(id_c)
        )
        response_payload = e._process_destroy(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Destroy"
        )
        self.assertEqual(str(id_c), response_payload.unique_identifier.value)

        args = (payload, )
        regex = "Could not locate object: {0}".format(id_c)
        six.assertRaisesRegex(
            self,
            exceptions.ItemNotFound,
            regex,
            e._process_destroy,
            *args
        )

        e._data_session.commit()

    def test_destroy_not_allowed_by_policy(self):
        """
        Test that an unallowed request is handled correctly by Destroy.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=False)
        e._logger = mock.MagicMock()
        e._client_identity = 'test'

        obj_a = pie_objects.OpaqueObject(b'', enums.OpaqueDataType.NONE)
        obj_a._owner = 'admin'

        e._data_session.add(obj_a)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        id_a = str(obj_a.unique_identifier)
        payload = payloads.DestroyRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(id_a)
        )

        # Test by specifying the ID of the object to destroy.
        args = [payload]
        six.assertRaisesRegex(
            self,
            exceptions.PermissionDenied,
            "Could not locate object: {0}".format(id_a),
            e._process_destroy,
            *args
        )

    def test_destroy_active_state(self):
        """
        Test that the right error is generated when destroy request is
        received for an object that is in 'active' state.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()

        key = (b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
               b'\x00\x00\x00\x00\x00')
        algorithm = enums.CryptographicAlgorithm.AES
        obj = pie_objects.SymmetricKey(algorithm, 128, key)
        obj.state = enums.State.ACTIVE

        e._data_session.add(obj)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        id = str(obj.unique_identifier)

        # Test by specifying the ID of the object to destroy.
        payload = payloads.DestroyRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(id)
        )

        args = (payload, )
        regex = "Object is active and cannot be destroyed."
        six.assertRaisesRegex(
            self,
            exceptions.PermissionDenied,
            regex,
            e._process_destroy,
            *args
        )

    def test_query_1_0(self):
        """
        Test that a Query request can be processed correctly, for KMIP 1.0.
        """
        e = engine.KmipEngine()

        e._logger = mock.MagicMock()
        e._protocol_version = contents.ProtocolVersion(1, 0)

        payload = payloads.QueryRequestPayload([
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
        self.assertIsInstance(result, payloads.QueryResponsePayload)
        self.assertIsNotNone(result.operations)
        self.assertEqual(12, len(result.operations))
        self.assertEqual(
            enums.Operation.CREATE,
            result.operations[0].value
        )
        self.assertEqual(
            enums.Operation.CREATE_KEY_PAIR,
            result.operations[1].value
        )
        self.assertEqual(
            enums.Operation.REGISTER,
            result.operations[2].value
        )
        self.assertEqual(
            enums.Operation.DERIVE_KEY,
            result.operations[3].value
        )
        self.assertEqual(
            enums.Operation.LOCATE,
            result.operations[4].value
        )
        self.assertEqual(
            enums.Operation.GET,
            result.operations[5].value
        )
        self.assertEqual(
            enums.Operation.GET_ATTRIBUTES,
            result.operations[6].value
        )
        self.assertEqual(
            enums.Operation.GET_ATTRIBUTE_LIST,
            result.operations[7].value
        )
        self.assertEqual(
            enums.Operation.ACTIVATE,
            result.operations[8].value
        )
        self.assertEqual(
            enums.Operation.REVOKE,
            result.operations[9].value
        )
        self.assertEqual(
            enums.Operation.DESTROY,
            result.operations[10].value
        )
        self.assertEqual(
            enums.Operation.QUERY,
            result.operations[11].value
        )
        self.assertEqual(list(), result.object_types)
        self.assertIsNotNone(result.vendor_identification)
        self.assertEqual(
            "PyKMIP {0} Software Server".format(kmip.__version__),
            result.vendor_identification.value
        )
        self.assertIsNone(result.server_information)
        self.assertEqual(list(), result.application_namespaces)
        self.assertEqual(list(), result.extension_information)

    def test_query_1_1(self):
        """
        Test that a Query request can be processed correctly, for KMIP 1.1.
        """
        e = engine.KmipEngine()

        e._logger = mock.MagicMock()
        e._protocol_version = contents.ProtocolVersion(1, 1)

        payload = payloads.QueryRequestPayload([
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
        self.assertIsInstance(result, payloads.QueryResponsePayload)
        self.assertIsNotNone(result.operations)
        self.assertEqual(13, len(result.operations))
        self.assertEqual(
            enums.Operation.CREATE,
            result.operations[0].value
        )
        self.assertEqual(
            enums.Operation.CREATE_KEY_PAIR,
            result.operations[1].value
        )
        self.assertEqual(
            enums.Operation.REGISTER,
            result.operations[2].value
        )
        self.assertEqual(
            enums.Operation.DERIVE_KEY,
            result.operations[3].value
        )
        self.assertEqual(
            enums.Operation.LOCATE,
            result.operations[4].value
        )
        self.assertEqual(
            enums.Operation.GET,
            result.operations[5].value
        )
        self.assertEqual(
            enums.Operation.GET_ATTRIBUTES,
            result.operations[6].value
        )
        self.assertEqual(
            enums.Operation.GET_ATTRIBUTE_LIST,
            result.operations[7].value
        )
        self.assertEqual(
            enums.Operation.ACTIVATE,
            result.operations[8].value
        )
        self.assertEqual(
            enums.Operation.REVOKE,
            result.operations[9].value
        )
        self.assertEqual(
            enums.Operation.DESTROY,
            result.operations[10].value
        )
        self.assertEqual(
            enums.Operation.QUERY,
            result.operations[11].value
        )
        self.assertEqual(
            enums.Operation.DISCOVER_VERSIONS,
            result.operations[12].value
        )
        self.assertEqual(list(), result.object_types)
        self.assertIsNotNone(result.vendor_identification)
        self.assertEqual(
            "PyKMIP {0} Software Server".format(kmip.__version__),
            result.vendor_identification.value
        )
        self.assertIsNone(result.server_information)
        self.assertEqual(list(), result.application_namespaces)
        self.assertEqual(list(), result.extension_information)

    def test_query_1_2(self):
        """
        Test that a Query request can be processed correctly, for KMIP 1.2.
        """
        e = engine.KmipEngine()

        e._logger = mock.MagicMock()
        e._protocol_version = contents.ProtocolVersion(1, 2)

        payload = payloads.QueryRequestPayload([
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
        self.assertIsInstance(result, payloads.QueryResponsePayload)
        self.assertIsNotNone(result.operations)
        self.assertEqual(18, len(result.operations))
        self.assertEqual(
            enums.Operation.CREATE,
            result.operations[0].value
        )
        self.assertEqual(
            enums.Operation.CREATE_KEY_PAIR,
            result.operations[1].value
        )
        self.assertEqual(
            enums.Operation.REGISTER,
            result.operations[2].value
        )
        self.assertEqual(
            enums.Operation.DERIVE_KEY,
            result.operations[3].value
        )
        self.assertEqual(
            enums.Operation.LOCATE,
            result.operations[4].value
        )
        self.assertEqual(
            enums.Operation.GET,
            result.operations[5].value
        )
        self.assertEqual(
            enums.Operation.GET_ATTRIBUTES,
            result.operations[6].value
        )
        self.assertEqual(
            enums.Operation.GET_ATTRIBUTE_LIST,
            result.operations[7].value
        )
        self.assertEqual(
            enums.Operation.ACTIVATE,
            result.operations[8].value
        )
        self.assertEqual(
            enums.Operation.REVOKE,
            result.operations[9].value
        )
        self.assertEqual(
            enums.Operation.DESTROY,
            result.operations[10].value
        )
        self.assertEqual(
            enums.Operation.QUERY,
            result.operations[11].value
        )
        self.assertEqual(
            enums.Operation.DISCOVER_VERSIONS,
            result.operations[12].value
        )
        self.assertEqual(
            enums.Operation.ENCRYPT,
            result.operations[13].value
        )
        self.assertEqual(
            enums.Operation.DECRYPT,
            result.operations[14].value
        )
        self.assertEqual(
            enums.Operation.SIGN,
            result.operations[15].value
        )
        self.assertEqual(
            enums.Operation.SIGNATURE_VERIFY,
            result.operations[16].value
        )
        self.assertEqual(
            enums.Operation.MAC,
            result.operations[17].value
        )
        self.assertEqual(list(), result.object_types)
        self.assertIsNotNone(result.vendor_identification)
        self.assertEqual(
            "PyKMIP {0} Software Server".format(kmip.__version__),
            result.vendor_identification.value
        )
        self.assertIsNone(result.server_information)
        self.assertEqual(list(), result.application_namespaces)
        self.assertEqual(list(), result.extension_information)

    def test_discover_versions(self):
        """
        Test that a DiscoverVersions request can be processed correctly for
        different inputs.
        """
        e = engine.KmipEngine()

        # Test default request.
        e._logger = mock.MagicMock()
        payload = payloads.DiscoverVersionsRequestPayload()

        result = e._process_discover_versions(payload)

        e._logger.info.assert_called_once_with(
            "Processing operation: DiscoverVersions"
        )
        self.assertIsInstance(
            result,
            payloads.DiscoverVersionsResponsePayload
        )
        self.assertIsNotNone(result.protocol_versions)
        self.assertEqual(3, len(result.protocol_versions))
        self.assertEqual(
            contents.ProtocolVersion(1, 2),
            result.protocol_versions[0]
        )
        self.assertEqual(
            contents.ProtocolVersion(1, 1),
            result.protocol_versions[1]
        )
        self.assertEqual(
            contents.ProtocolVersion(1, 0),
            result.protocol_versions[2]
        )

        # Test detailed request.
        e._logger = mock.MagicMock()
        payload = payloads.DiscoverVersionsRequestPayload([
            contents.ProtocolVersion(1, 0)
        ])

        result = e._process_discover_versions(payload)

        e._logger.info.assert_called_once_with(
            "Processing operation: DiscoverVersions"
        )
        self.assertIsNotNone(result.protocol_versions)
        self.assertEqual(1, len(result.protocol_versions))
        self.assertEqual(
            contents.ProtocolVersion(1, 0),
            result.protocol_versions[0]
        )

        # Test disjoint request.
        e._logger = mock.MagicMock()
        payload = payloads.DiscoverVersionsRequestPayload([
            contents.ProtocolVersion(0, 1)
        ])

        result = e._process_discover_versions(payload)

        e._logger.info.assert_called_once_with(
            "Processing operation: DiscoverVersions"
        )
        self.assertEqual([], result.protocol_versions)

    def test_encrypt(self):
        """
        Test that an Encrypt request can be processed correctly.

        The test vectors used here come from Eric Young's test set for
        Blowfish, via https://www.di-mgt.com.au/cryptopad.html.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        encryption_key = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.TRIPLE_DES,
            128,
            (
                b'\x01\x23\x45\x67\x89\xAB\xCD\xEF'
                b'\xF0\xE1\xD2\xC3\xB4\xA5\x96\x87'
            ),
            [enums.CryptographicUsageMask.ENCRYPT]
        )
        encryption_key.state = enums.State.ACTIVE

        e._data_session.add(encryption_key)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        unique_identifier = str(encryption_key.unique_identifier)
        cryptographic_parameters = attributes.CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.CBC,
            padding_method=enums.PaddingMethod.PKCS5,
            cryptographic_algorithm=enums.CryptographicAlgorithm.BLOWFISH
        )
        data = (
            b'\x37\x36\x35\x34\x33\x32\x31\x20'
            b'\x4E\x6F\x77\x20\x69\x73\x20\x74'
            b'\x68\x65\x20\x74\x69\x6D\x65\x20'
            b'\x66\x6F\x72\x20\x00'
        )
        iv_counter_nonce = b'\xFE\xDC\xBA\x98\x76\x54\x32\x10'

        payload = payloads.EncryptRequestPayload(
            unique_identifier,
            cryptographic_parameters,
            data,
            iv_counter_nonce
        )

        response_payload = e._process_encrypt(payload)

        e._logger.info.assert_any_call("Processing operation: Encrypt")
        self.assertEqual(
            unique_identifier,
            response_payload.unique_identifier
        )
        self.assertEqual(
            (
                b'\x6B\x77\xB4\xD6\x30\x06\xDE\xE6'
                b'\x05\xB1\x56\xE2\x74\x03\x97\x93'
                b'\x58\xDE\xB9\xE7\x15\x46\x16\xD9'
                b'\x74\x9D\xEC\xBE\xC0\x5D\x26\x4B'
            ),
            response_payload.data
        )
        self.assertIsNone(response_payload.iv_counter_nonce)

    def test_encrypt_no_iv_counter_nonce(self):
        """
        Test that an Encrypt request can be processed correctly when a
        specific IV/counter/nonce is not specified.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        encryption_key = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.TRIPLE_DES,
            128,
            (
                b'\x01\x23\x45\x67\x89\xAB\xCD\xEF'
                b'\xF0\xE1\xD2\xC3\xB4\xA5\x96\x87'
            ),
            [enums.CryptographicUsageMask.ENCRYPT]
        )
        encryption_key.state = enums.State.ACTIVE

        e._data_session.add(encryption_key)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        unique_identifier = str(encryption_key.unique_identifier)
        cryptographic_parameters = attributes.CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.CBC,
            padding_method=enums.PaddingMethod.PKCS5,
            cryptographic_algorithm=enums.CryptographicAlgorithm.BLOWFISH
        )
        data = (
            b'\x37\x36\x35\x34\x33\x32\x31\x20'
            b'\x4E\x6F\x77\x20\x69\x73\x20\x74'
            b'\x68\x65\x20\x74\x69\x6D\x65\x20'
            b'\x66\x6F\x72\x20\x00'
        )
        iv_counter_nonce = None

        payload = payloads.EncryptRequestPayload(
            unique_identifier,
            cryptographic_parameters,
            data,
            iv_counter_nonce
        )

        response_payload = e._process_encrypt(payload)

        e._logger.info.assert_any_call("Processing operation: Encrypt")
        self.assertEqual(
            unique_identifier,
            response_payload.unique_identifier
        )
        self.assertIsNotNone(response_payload.data)
        self.assertIsNotNone(response_payload.iv_counter_nonce)

    def test_encrypt_no_cryptographic_parameters(self):
        """
        Test that the right error is thrown when cryptographic parameters
        are not provided with an Encrypt request.

        Note: once the cryptographic parameters can be obtained from the
              encryption key's attributes, this test should be updated to
              reflect that.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        encryption_key = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.TRIPLE_DES,
            128,
            (
                b'\x01\x23\x45\x67\x89\xAB\xCD\xEF'
                b'\xF0\xE1\xD2\xC3\xB4\xA5\x96\x87'
            ),
            [enums.CryptographicUsageMask.ENCRYPT]
        )
        encryption_key.state = enums.State.ACTIVE

        e._data_session.add(encryption_key)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        unique_identifier = str(encryption_key.unique_identifier)
        cryptographic_parameters = None
        data = (
            b'\x37\x36\x35\x34\x33\x32\x31\x20'
            b'\x4E\x6F\x77\x20\x69\x73\x20\x74'
            b'\x68\x65\x20\x74\x69\x6D\x65\x20'
            b'\x66\x6F\x72\x20\x00'
        )
        iv_counter_nonce = b'\xFE\xDC\xBA\x98\x76\x54\x32\x10'

        payload = payloads.EncryptRequestPayload(
            unique_identifier,
            cryptographic_parameters,
            data,
            iv_counter_nonce
        )

        args = (payload, )
        self.assertRaisesRegexp(
            exceptions.InvalidField,
            "The cryptographic parameters must be specified.",
            e._process_encrypt,
            *args
        )

    def test_encrypt_invalid_encryption_key(self):
        """
        Test that the right error is thrown when an invalid encryption key
        is specified with an Encrypt request.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        encryption_key = pie_objects.OpaqueObject(
            b'\x01\x02\x03\x04',
            enums.OpaqueDataType.NONE
        )

        e._data_session.add(encryption_key)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        unique_identifier = str(encryption_key.unique_identifier)
        cryptographic_parameters = attributes.CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.CBC,
            padding_method=enums.PaddingMethod.PKCS5,
            cryptographic_algorithm=enums.CryptographicAlgorithm.BLOWFISH
        )
        data = (
            b'\x37\x36\x35\x34\x33\x32\x31\x20'
            b'\x4E\x6F\x77\x20\x69\x73\x20\x74'
            b'\x68\x65\x20\x74\x69\x6D\x65\x20'
            b'\x66\x6F\x72\x20\x00'
        )
        iv_counter_nonce = b'\xFE\xDC\xBA\x98\x76\x54\x32\x10'

        payload = payloads.EncryptRequestPayload(
            unique_identifier,
            cryptographic_parameters,
            data,
            iv_counter_nonce
        )

        args = (payload, )
        self.assertRaisesRegexp(
            exceptions.PermissionDenied,
            "The requested encryption key is not a symmetric key. "
            "Only symmetric encryption is currently supported.",
            e._process_encrypt,
            *args
        )

    def test_encrypt_inactive_encryption_key(self):
        """
        Test that the right error is thrown when an inactive encryption key
        is specified with an Encrypt request.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        encryption_key = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.TRIPLE_DES,
            128,
            (
                b'\x01\x23\x45\x67\x89\xAB\xCD\xEF'
                b'\xF0\xE1\xD2\xC3\xB4\xA5\x96\x87'
            ),
            [enums.CryptographicUsageMask.ENCRYPT]
        )

        e._data_session.add(encryption_key)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        unique_identifier = str(encryption_key.unique_identifier)
        cryptographic_parameters = attributes.CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.CBC,
            padding_method=enums.PaddingMethod.PKCS5,
            cryptographic_algorithm=enums.CryptographicAlgorithm.BLOWFISH
        )
        data = (
            b'\x37\x36\x35\x34\x33\x32\x31\x20'
            b'\x4E\x6F\x77\x20\x69\x73\x20\x74'
            b'\x68\x65\x20\x74\x69\x6D\x65\x20'
            b'\x66\x6F\x72\x20\x00'
        )
        iv_counter_nonce = b'\xFE\xDC\xBA\x98\x76\x54\x32\x10'

        payload = payloads.EncryptRequestPayload(
            unique_identifier,
            cryptographic_parameters,
            data,
            iv_counter_nonce
        )

        args = (payload,)
        self.assertRaisesRegexp(
            exceptions.PermissionDenied,
            "The encryption key must be in the Active state to be used "
            "for encryption.",
            e._process_encrypt,
            *args
        )

    def test_encrypt_non_encryption_key(self):
        """
        Test that the right error is thrown when a non-encryption key
        is specified with an Encrypt request.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        encryption_key = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.TRIPLE_DES,
            128,
            (
                b'\x01\x23\x45\x67\x89\xAB\xCD\xEF'
                b'\xF0\xE1\xD2\xC3\xB4\xA5\x96\x87'
            ),
            [enums.CryptographicUsageMask.DECRYPT]
        )
        encryption_key.state = enums.State.ACTIVE

        e._data_session.add(encryption_key)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        unique_identifier = str(encryption_key.unique_identifier)
        cryptographic_parameters = attributes.CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.CBC,
            padding_method=enums.PaddingMethod.PKCS5,
            cryptographic_algorithm=enums.CryptographicAlgorithm.BLOWFISH
        )
        data = (
            b'\x37\x36\x35\x34\x33\x32\x31\x20'
            b'\x4E\x6F\x77\x20\x69\x73\x20\x74'
            b'\x68\x65\x20\x74\x69\x6D\x65\x20'
            b'\x66\x6F\x72\x20\x00'
        )
        iv_counter_nonce = b'\xFE\xDC\xBA\x98\x76\x54\x32\x10'

        payload = payloads.EncryptRequestPayload(
            unique_identifier,
            cryptographic_parameters,
            data,
            iv_counter_nonce
        )

        args = (payload,)
        self.assertRaisesRegexp(
            exceptions.PermissionDenied,
            "The Encrypt bit must be set in the encryption key's "
            "cryptographic usage mask.",
            e._process_encrypt,
            *args
        )

    def test_decrypt(self):
        """
        Test that an Decrypt request can be processed correctly.

        The test vectors used here come from Eric Young's test set for
        Blowfish, via https://www.di-mgt.com.au/cryptopad.html.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        decryption_key = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.TRIPLE_DES,
            128,
            (
                b'\x01\x23\x45\x67\x89\xAB\xCD\xEF'
                b'\xF0\xE1\xD2\xC3\xB4\xA5\x96\x87'
            ),
            [enums.CryptographicUsageMask.DECRYPT]
        )
        decryption_key.state = enums.State.ACTIVE

        e._data_session.add(decryption_key)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        unique_identifier = str(decryption_key.unique_identifier)
        cryptographic_parameters = attributes.CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.CBC,
            padding_method=enums.PaddingMethod.PKCS5,
            cryptographic_algorithm=enums.CryptographicAlgorithm.BLOWFISH
        )
        data = (
            b'\x6B\x77\xB4\xD6\x30\x06\xDE\xE6'
            b'\x05\xB1\x56\xE2\x74\x03\x97\x93'
            b'\x58\xDE\xB9\xE7\x15\x46\x16\xD9'
            b'\x74\x9D\xEC\xBE\xC0\x5D\x26\x4B'
        )
        iv_counter_nonce = b'\xFE\xDC\xBA\x98\x76\x54\x32\x10'

        payload = payloads.DecryptRequestPayload(
            unique_identifier,
            cryptographic_parameters,
            data,
            iv_counter_nonce
        )

        response_payload = e._process_decrypt(payload)

        e._logger.info.assert_any_call("Processing operation: Decrypt")
        self.assertEqual(
            unique_identifier,
            response_payload.unique_identifier
        )
        self.assertEqual(
            (
                b'\x37\x36\x35\x34\x33\x32\x31\x20'
                b'\x4E\x6F\x77\x20\x69\x73\x20\x74'
                b'\x68\x65\x20\x74\x69\x6D\x65\x20'
                b'\x66\x6F\x72\x20\x00'
            ),
            response_payload.data
        )

    def test_decrypt_no_cryptographic_parameters(self):
        """
        Test that the right error is thrown when cryptographic parameters
        are not provided with a Decrypt request.

        Note: once the cryptographic parameters can be obtained from the
              encryption key's attributes, this test should be updated to
              reflect that.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        decryption_key = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.TRIPLE_DES,
            128,
            (
                b'\x01\x23\x45\x67\x89\xAB\xCD\xEF'
                b'\xF0\xE1\xD2\xC3\xB4\xA5\x96\x87'
            ),
            [enums.CryptographicUsageMask.DECRYPT]
        )
        decryption_key.state = enums.State.ACTIVE

        e._data_session.add(decryption_key)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        unique_identifier = str(decryption_key.unique_identifier)
        cryptographic_parameters = None
        data = (
            b'\x37\x36\x35\x34\x33\x32\x31\x20'
            b'\x4E\x6F\x77\x20\x69\x73\x20\x74'
            b'\x68\x65\x20\x74\x69\x6D\x65\x20'
            b'\x66\x6F\x72\x20\x00'
        )
        iv_counter_nonce = b'\xFE\xDC\xBA\x98\x76\x54\x32\x10'

        payload = payloads.DecryptRequestPayload(
            unique_identifier,
            cryptographic_parameters,
            data,
            iv_counter_nonce
        )

        args = (payload, )
        self.assertRaisesRegexp(
            exceptions.InvalidField,
            "The cryptographic parameters must be specified.",
            e._process_decrypt,
            *args
        )

    def test_decrypt_invalid_decryption_key(self):
        """
        Test that the right error is thrown when an invalid decryption key
        is specified with a Decrypt request.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        decryption_key = pie_objects.OpaqueObject(
            b'\x01\x02\x03\x04',
            enums.OpaqueDataType.NONE
        )

        e._data_session.add(decryption_key)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        unique_identifier = str(decryption_key.unique_identifier)
        cryptographic_parameters = attributes.CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.CBC,
            padding_method=enums.PaddingMethod.PKCS5,
            cryptographic_algorithm=enums.CryptographicAlgorithm.BLOWFISH
        )
        data = (
            b'\x37\x36\x35\x34\x33\x32\x31\x20'
            b'\x4E\x6F\x77\x20\x69\x73\x20\x74'
            b'\x68\x65\x20\x74\x69\x6D\x65\x20'
            b'\x66\x6F\x72\x20\x00'
        )
        iv_counter_nonce = b'\xFE\xDC\xBA\x98\x76\x54\x32\x10'

        payload = payloads.DecryptRequestPayload(
            unique_identifier,
            cryptographic_parameters,
            data,
            iv_counter_nonce
        )

        args = (payload, )
        self.assertRaisesRegexp(
            exceptions.PermissionDenied,
            "The requested decryption key is not a symmetric key. "
            "Only symmetric decryption is currently supported.",
            e._process_decrypt,
            *args
        )

    def test_decrypt_inactive_decryption_key(self):
        """
        Test that the right error is thrown when an inactive decryption key
        is specified with a Decrypt request.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        decryption_key = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.TRIPLE_DES,
            128,
            (
                b'\x01\x23\x45\x67\x89\xAB\xCD\xEF'
                b'\xF0\xE1\xD2\xC3\xB4\xA5\x96\x87'
            ),
            [enums.CryptographicUsageMask.DECRYPT]
        )

        e._data_session.add(decryption_key)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        unique_identifier = str(decryption_key.unique_identifier)
        cryptographic_parameters = attributes.CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.CBC,
            padding_method=enums.PaddingMethod.PKCS5,
            cryptographic_algorithm=enums.CryptographicAlgorithm.BLOWFISH
        )
        data = (
            b'\x37\x36\x35\x34\x33\x32\x31\x20'
            b'\x4E\x6F\x77\x20\x69\x73\x20\x74'
            b'\x68\x65\x20\x74\x69\x6D\x65\x20'
            b'\x66\x6F\x72\x20\x00'
        )
        iv_counter_nonce = b'\xFE\xDC\xBA\x98\x76\x54\x32\x10'

        payload = payloads.DecryptRequestPayload(
            unique_identifier,
            cryptographic_parameters,
            data,
            iv_counter_nonce
        )

        args = (payload,)
        self.assertRaisesRegexp(
            exceptions.PermissionDenied,
            "The decryption key must be in the Active state to be used "
            "for decryption.",
            e._process_decrypt,
            *args
        )

    def test_decrypt_non_decryption_key(self):
        """
        Test that the right error is thrown when a non-decryption key
        is specified with a Decrypt request.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        decryption_key = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.TRIPLE_DES,
            128,
            (
                b'\x01\x23\x45\x67\x89\xAB\xCD\xEF'
                b'\xF0\xE1\xD2\xC3\xB4\xA5\x96\x87'
            ),
            [enums.CryptographicUsageMask.ENCRYPT]
        )
        decryption_key.state = enums.State.ACTIVE

        e._data_session.add(decryption_key)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        unique_identifier = str(decryption_key.unique_identifier)
        cryptographic_parameters = attributes.CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.CBC,
            padding_method=enums.PaddingMethod.PKCS5,
            cryptographic_algorithm=enums.CryptographicAlgorithm.BLOWFISH
        )
        data = (
            b'\x37\x36\x35\x34\x33\x32\x31\x20'
            b'\x4E\x6F\x77\x20\x69\x73\x20\x74'
            b'\x68\x65\x20\x74\x69\x6D\x65\x20'
            b'\x66\x6F\x72\x20\x00'
        )
        iv_counter_nonce = b'\xFE\xDC\xBA\x98\x76\x54\x32\x10'

        payload = payloads.DecryptRequestPayload(
            unique_identifier,
            cryptographic_parameters,
            data,
            iv_counter_nonce
        )

        args = (payload,)
        self.assertRaisesRegexp(
            exceptions.PermissionDenied,
            "The Decrypt bit must be set in the decryption key's "
            "cryptographic usage mask.",
            e._process_decrypt,
            *args
        )

    def test_signature_verify(self):
        """
        Test that a SignatureVerify request can be processed correctly.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        signing_key = pie_objects.PublicKey(
            enums.CryptographicAlgorithm.RSA,
            1120,
            (
                b'\x30\x81\x89\x02\x81\x81\x00\xac\x13\xd9\xfd\xae\x7b\x73\x35'
                b'\xb6\x9c\xd9\x85\x67\xe9\x64\x7d\x99\xbf\x37\x3a\x9e\x05\xce'
                b'\x34\x35\xd6\x64\x65\xf3\x28\xb7\xf7\x33\x4b\x79\x2a\xee\x7e'
                b'\xfa\x04\x4e\xbc\x4c\x7a\x30\xb2\x1a\x5d\x7a\x89\xcd\xb3\xa3'
                b'\x0d\xfc\xd9\xfe\xe9\x99\x5e\x09\x41\x5e\xdc\x0b\xf9\xe5\xb4'
                b'\xc3\xf7\x4f\xf5\x3f\xb4\xd2\x94\x41\xbf\x1b\x7e\xd6\xcb\xdd'
                b'\x4a\x47\xf9\x25\x22\x69\xe1\x64\x6f\x6c\x1a\xee\x05\x14\xe9'
                b'\x3f\x6c\xb9\xdf\x71\xd0\x6c\x06\x0a\x21\x04\xb4\x7b\x72\x60'
                b'\xac\x37\xc1\x06\x86\x1d\xc7\x8c\xa5\xa2\x5f\xaa\x9c\xb2\xe3'
                b'\x02\x03\x01\x00\x01'
            ),
            masks=[
                enums.CryptographicUsageMask.SIGN,
                enums.CryptographicUsageMask.VERIFY
            ]
        )
        signing_key.state = enums.State.ACTIVE

        e._data_session.add(signing_key)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        # Test a valid signature
        unique_identifier = str(signing_key.unique_identifier)
        payload = payloads.SignatureVerifyRequestPayload(
            unique_identifier=unique_identifier,
            cryptographic_parameters=attributes.CryptographicParameters(
                padding_method=enums.PaddingMethod.PSS,
                digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
                SHA1_WITH_RSA_ENCRYPTION
            ),
            data=(
                b'\xe1\xc0\xf9\x8d\x53\xf8\xf8\xb1\x41\x90\x57\xd5\xb9\xb1\x0b'
                b'\x07\xfe\xea\xec\x32\xc0\x46\x3a\x4d\x68\x38\x2f\x53\x1b\xa1'
                b'\xd6\xcf\xe4\xed\x38\xa2\x69\x4a\x34\xb9\xc8\x05\xad\xf0\x72'
                b'\xff\xbc\xeb\xe2\x1d\x8d\x4b\x5c\x0e\x8c\x33\x45\x2d\xd8\xf9'
                b'\xc9\xbf\x45\xd1\xe6\x33\x75\x11\x33\x58\x82\x29\xd2\x93\xc6'
                b'\x49\x6b\x7c\x98\x3c\x2c\x72\xbd\x21\xd3\x39\x27\x2d\x78\x28'
                b'\xb0\xd0\x9d\x01\x0b\xba\xd3\x18\xd9\x98\xf7\x04\x79\x67\x33'
                b'\x8a\xce\xfd\x01\xe8\x74\xac\xe5\xf8\x6d\x2a\x60\xf3\xb3\xca'
                b'\xe1\x3f\xc5\xc6\x65\x08\xcf\xb7\x23\x78\xfd\xd6\xc8\xde\x24'
                b'\x97\x65\x10\x3c\xe8\xfe\x7c\xd3\x3a\xd0\xef\x16\x86\xfe\xb2'
                b'\x5e\x6a\x35\xfb\x64\xe0\x96\xa4'
            ),
            signature_data=(
                b'\x01\xf6\xe5\xff\x04\x22\x1a\xdc\x6c\x2f\x22\xa7\x61\x05\x3b'
                b'\xc4\x73\x27\x65\xdd\xdc\x3f\x76\x56\xd0\xd1\x22\xad\x3b\x8a'
                b'\x4e\x4f\x8f\xe5\x5b\xd0\xc0\x9e\xb1\x07\x80\xa1\x39\xcd\xa9'
                b'\x32\x34\xef\x98\x8f\xe2\x50\x20\x1e\xb2\xfe\xbd\x08\xb6\xee'
                b'\x85\xd7\x0d\x16\x05\xa5\xba\x56\x85\x21\x52\x99\xf0\x74\xc8'
                b'\x0b\xaf\xf8\x1e\x2c\xa3\x10\x7d\xa9\x17\x5c\x2f\x5a\x7c\x6b'
                b'\x60\xea\xa2\x8a\x75\x8c\xa9\x34\xf2\xff\x16\x98\x8f\xe8\x5f'
                b'\xf8\x41\x57\xd9\x51\x44\x8a\x85\xec\x1e\xd1\x71\xf9\xef\x8b'
                b'\xb8\xa1\x0c\xfa\x14\x7b\x7e\xf8'
            )
        )

        response_payload = e._process_signature_verify(payload)

        e._logger.info.assert_any_call(
            "Processing operation: Signature Verify"
        )
        self.assertEqual(
            unique_identifier,
            response_payload.unique_identifier
        )
        self.assertEqual(
            enums.ValidityIndicator.VALID,
            response_payload.validity_indicator
        )

        # Test an invalid signature
        payload = payloads.SignatureVerifyRequestPayload(
            unique_identifier=unique_identifier,
            cryptographic_parameters=attributes.CryptographicParameters(
                padding_method=enums.PaddingMethod.PSS,
                digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
                SHA1_WITH_RSA_ENCRYPTION
            ),
            data=(
                b'\xe1\xc0\xf9\x8d\x53\xf8\xf8\xb1\x41\x90\x57\xd5\xb9\xb1\x0b'
                b'\x07\xfe\xea\xec\x32\xc0\x46\x3a\x4d\x68\x38\x2f\x53\x1b\xa1'
                b'\xd6\xcf\xe4\xed\x38\xa2\x69\x4a\x34\xb9\xc8\x05\xad\xf0\x72'
                b'\xff\xbc\xeb\xe2\x1d\x8d\x4b\x5c\x0e\x8c\x33\x45\x2d\xd8\xf9'
                b'\xc9\xbf\x45\xd1\xe6\x33\x75\x11\x33\x58\x82\x29\xd2\x93\xc6'
                b'\x49\x6b\x7c\x98\x3c\x2c\x72\xbd\x21\xd3\x39\x27\x2d\x78\x28'
                b'\xb0\xd0\x9d\x01\x0b\xba\xd3\x18\xd9\x98\xf7\x04\x79\x67\x33'
                b'\x8a\xce\xfd\x01\xe8\x74\xac\xe5\xf8\x6d\x2a\x60\xf3\xb3\xca'
                b'\xe1\x3f\xc5\xc6\x65\x08\xcf\xb7\x23\x78\xfd\xd6\xc8\xde\x24'
                b'\x97\x65\x10\x3c\xe8\xfe\x7c\xd3\x3a\xd0\xef\x16\x86\xfe\xb2'
                b'\x5e\x6a\x35\xfb\x64\xe0\x96\xa4'
            ),
            signature_data=(
                b'\x01\xf6\xe5\xff\x04\x22\x1a\xdc\x6c\x2f\x22\xa7\x61\x05\x3b'
                b'\xc4\x73\x27\x65\xdd\xdc\x3f\x76\x56\xd0\xd1\x22\xad\x3b\x8a'
                b'\x4e\x4f\x8f\xe5\x5b\xd0\xc0\x9e\xb1\x07\x80\xa1\x39\xcd\xa9'
                b'\x32\x34\xef\x98\x8f\xe2\x50\x20\x1e\xb2\xfe\xbd\x08\xb6\xee'
                b'\x85\xd7\x0d\x16\x05\xa5\xba\x56\x85\x21\x52\x99\xf0\x74\xc8'
                b'\x0b\xaf\xf8\x1e\x2c\xa3\x10\x7d\xa9\x17\x5c\x2f\x5a\x7c\x6b'
                b'\x60\xea\xa2\x8a\x75\x8c\xa9\x34\xf2\xff\x16\x98\x8f\xe8\x5f'
                b'\xf8\x41\x57\xd9\x51\x44\x8a\x85\xec\x1e\xd1\x71\xf9\xef\x8b'
                b'\xb8\xa1\x0c\xfa\x14\x7b\x7e\x00'
            )
        )

        response_payload = e._process_signature_verify(payload)

        self.assertEqual(
            unique_identifier,
            response_payload.unique_identifier
        )
        self.assertEqual(
            enums.ValidityIndicator.INVALID,
            response_payload.validity_indicator
        )

    def test_signature_verify_no_cryptographic_parameters(self):
        """
        Test that the right error is thrown when cryptographic parameters
        are not provided with a SignatureVerify request.

        Note: once the cryptographic parameters can be obtained from the
              encryption key's attributes, this test should be updated to
              reflect that.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        signing_key = pie_objects.PublicKey(
            enums.CryptographicAlgorithm.RSA,
            1120,
            (
                b'\x30\x81\x89\x02\x81\x81\x00\xac\x13\xd9\xfd\xae\x7b\x73\x35'
                b'\xb6\x9c\xd9\x85\x67\xe9\x64\x7d\x99\xbf\x37\x3a\x9e\x05\xce'
                b'\x34\x35\xd6\x64\x65\xf3\x28\xb7\xf7\x33\x4b\x79\x2a\xee\x7e'
                b'\xfa\x04\x4e\xbc\x4c\x7a\x30\xb2\x1a\x5d\x7a\x89\xcd\xb3\xa3'
                b'\x0d\xfc\xd9\xfe\xe9\x99\x5e\x09\x41\x5e\xdc\x0b\xf9\xe5\xb4'
                b'\xc3\xf7\x4f\xf5\x3f\xb4\xd2\x94\x41\xbf\x1b\x7e\xd6\xcb\xdd'
                b'\x4a\x47\xf9\x25\x22\x69\xe1\x64\x6f\x6c\x1a\xee\x05\x14\xe9'
                b'\x3f\x6c\xb9\xdf\x71\xd0\x6c\x06\x0a\x21\x04\xb4\x7b\x72\x60'
                b'\xac\x37\xc1\x06\x86\x1d\xc7\x8c\xa5\xa2\x5f\xaa\x9c\xb2\xe3'
                b'\x02\x03\x01\x00\x01'
            ),
            masks=[
                enums.CryptographicUsageMask.SIGN,
                enums.CryptographicUsageMask.VERIFY
            ]
        )
        signing_key.state = enums.State.ACTIVE

        e._data_session.add(signing_key)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        unique_identifier = str(signing_key.unique_identifier)
        payload = payloads.SignatureVerifyRequestPayload(
            unique_identifier=unique_identifier,
            data=b'',
            signature_data=b''
        )

        args = (payload, )
        self.assertRaisesRegexp(
            exceptions.InvalidField,
            "The cryptographic parameters must be specified.",
            e._process_signature_verify,
            *args
        )

    def test_signature_verify_invalid_signing_key(self):
        """
        Test that the right error is thrown when an invalid signing key
        is specified with a SignatureVerify request.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        signing_key = pie_objects.OpaqueObject(
            b'\x01\x02\x03\x04',
            enums.OpaqueDataType.NONE
        )

        e._data_session.add(signing_key)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        unique_identifier = str(signing_key.unique_identifier)
        payload = payloads.SignatureVerifyRequestPayload(
            unique_identifier=unique_identifier,
            cryptographic_parameters=attributes.CryptographicParameters(
                padding_method=enums.PaddingMethod.PSS,
                digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
                SHA1_WITH_RSA_ENCRYPTION
            ),
            data=b'',
            signature_data=b''
        )

        args = (payload, )
        self.assertRaisesRegexp(
            exceptions.PermissionDenied,
            "The requested signing key is not a public key. A public key must "
            "be specified.",
            e._process_signature_verify,
            *args
        )

    def test_signature_verify_inactive_signing_key(self):
        """
        Test that the right error is thrown when an inactive signing key
        is specified with a SignatureVerify request.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        signing_key = pie_objects.PublicKey(
            enums.CryptographicAlgorithm.RSA,
            1120,
            (
                b'\x30\x81\x89\x02\x81\x81\x00\xac\x13\xd9\xfd\xae\x7b\x73\x35'
                b'\xb6\x9c\xd9\x85\x67\xe9\x64\x7d\x99\xbf\x37\x3a\x9e\x05\xce'
                b'\x34\x35\xd6\x64\x65\xf3\x28\xb7\xf7\x33\x4b\x79\x2a\xee\x7e'
                b'\xfa\x04\x4e\xbc\x4c\x7a\x30\xb2\x1a\x5d\x7a\x89\xcd\xb3\xa3'
                b'\x0d\xfc\xd9\xfe\xe9\x99\x5e\x09\x41\x5e\xdc\x0b\xf9\xe5\xb4'
                b'\xc3\xf7\x4f\xf5\x3f\xb4\xd2\x94\x41\xbf\x1b\x7e\xd6\xcb\xdd'
                b'\x4a\x47\xf9\x25\x22\x69\xe1\x64\x6f\x6c\x1a\xee\x05\x14\xe9'
                b'\x3f\x6c\xb9\xdf\x71\xd0\x6c\x06\x0a\x21\x04\xb4\x7b\x72\x60'
                b'\xac\x37\xc1\x06\x86\x1d\xc7\x8c\xa5\xa2\x5f\xaa\x9c\xb2\xe3'
                b'\x02\x03\x01\x00\x01'
            ),
            masks=[
                enums.CryptographicUsageMask.SIGN,
                enums.CryptographicUsageMask.VERIFY
            ]
        )

        e._data_session.add(signing_key)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        unique_identifier = str(signing_key.unique_identifier)
        payload = payloads.SignatureVerifyRequestPayload(
            unique_identifier=unique_identifier,
            cryptographic_parameters=attributes.CryptographicParameters(
                padding_method=enums.PaddingMethod.PSS,
                digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
                SHA1_WITH_RSA_ENCRYPTION
            ),
            data=b'',
            signature_data=b''
        )

        args = (payload,)
        self.assertRaisesRegexp(
            exceptions.PermissionDenied,
            "The signing key must be in the Active state to be used for "
            "signature verification.",
            e._process_signature_verify,
            *args
        )

    def test_signature_verify_non_verification_key(self):
        """
        Test that the right error is thrown when a non-verification key
        is specified with a SignatureVerify request.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        signing_key = pie_objects.PublicKey(
            enums.CryptographicAlgorithm.RSA,
            1120,
            (
                b'\x30\x81\x89\x02\x81\x81\x00\xac\x13\xd9\xfd\xae\x7b\x73\x35'
                b'\xb6\x9c\xd9\x85\x67\xe9\x64\x7d\x99\xbf\x37\x3a\x9e\x05\xce'
                b'\x34\x35\xd6\x64\x65\xf3\x28\xb7\xf7\x33\x4b\x79\x2a\xee\x7e'
                b'\xfa\x04\x4e\xbc\x4c\x7a\x30\xb2\x1a\x5d\x7a\x89\xcd\xb3\xa3'
                b'\x0d\xfc\xd9\xfe\xe9\x99\x5e\x09\x41\x5e\xdc\x0b\xf9\xe5\xb4'
                b'\xc3\xf7\x4f\xf5\x3f\xb4\xd2\x94\x41\xbf\x1b\x7e\xd6\xcb\xdd'
                b'\x4a\x47\xf9\x25\x22\x69\xe1\x64\x6f\x6c\x1a\xee\x05\x14\xe9'
                b'\x3f\x6c\xb9\xdf\x71\xd0\x6c\x06\x0a\x21\x04\xb4\x7b\x72\x60'
                b'\xac\x37\xc1\x06\x86\x1d\xc7\x8c\xa5\xa2\x5f\xaa\x9c\xb2\xe3'
                b'\x02\x03\x01\x00\x01'
            ),
            masks=[
                enums.CryptographicUsageMask.SIGN
            ]
        )
        signing_key.state = enums.State.ACTIVE

        e._data_session.add(signing_key)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        unique_identifier = str(signing_key.unique_identifier)
        payload = payloads.SignatureVerifyRequestPayload(
            unique_identifier=unique_identifier,
            cryptographic_parameters=attributes.CryptographicParameters(
                padding_method=enums.PaddingMethod.PSS,
                digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
                SHA1_WITH_RSA_ENCRYPTION
            ),
            data=b'',
            signature_data=b''
        )

        args = (payload,)
        self.assertRaisesRegexp(
            exceptions.PermissionDenied,
            "The Verify bit must be set in the signing key's cryptographic "
            "usage mask.",
            e._process_signature_verify,
            *args
        )

    def test_mac(self):
        """
        Test that a MAC request can be processed correctly.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        key = (b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
               b'\x00\x00\x00\x00\x00')
        data = (b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A'
                b'\x0B\x0C\x0D\x0E\x0F')
        algorithm_a = enums.CryptographicAlgorithm.AES
        algorithm_b = enums.CryptographicAlgorithm.HMAC_SHA512
        obj = pie_objects.SymmetricKey(
            algorithm_a, 128, key, [enums.CryptographicUsageMask.MAC_GENERATE])
        obj.state = enums.State.ACTIVE

        e._data_session.add(obj)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        uuid = str(obj.unique_identifier)

        cryptographic_parameters = attributes.CryptographicParameters(
            cryptographic_algorithm=algorithm_b
        )

        # Verify when cryptographic_parameters is specified in request
        payload = payloads.MACRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(uuid),
            cryptographic_parameters=cryptographic_parameters,
            data=objects.Data(data)
        )

        response_payload = e._process_mac(payload)

        e._logger.info.assert_any_call(
            "Processing operation: MAC"
        )
        e._cryptography_engine.logger.info.assert_any_call(
            "Generating a hash-based message authentication code using {0}".
            format(algorithm_b.name)
        )
        e._cryptography_engine.logger.reset_mock()
        self.assertEqual(str(uuid), response_payload.unique_identifier.value)
        self.assertIsInstance(response_payload.mac_data, objects.MACData)

        # Verify when cryptographic_parameters is not specified in request
        payload = payloads.MACRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(uuid),
            cryptographic_parameters=None,
            data=objects.Data(data)
        )

        response_payload = e._process_mac(payload)

        e._cryptography_engine.logger.info.assert_any_call(
            "Generating a cipher-based message authentication code using {0}".
            format(algorithm_a.name)
        )
        self.assertEqual(str(uuid), response_payload.unique_identifier.value)
        self.assertIsInstance(response_payload.mac_data, objects.MACData)

    def test_mac_with_missing_fields(self):
        """
        Test that the right errors are generated when required fields
        are missing.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()

        key = (b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
               b'\x00\x00\x00\x00')
        data = (b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B'
                b'\x0C\x0D\x0E\x0F')
        algorithm = enums.CryptographicAlgorithm.AES
        obj_no_key = pie_objects.OpaqueObject(b'', enums.OpaqueDataType.NONE)
        obj_no_algorithm = pie_objects.OpaqueObject(
            key, enums.OpaqueDataType.NONE)

        e._data_session.add(obj_no_key)
        e._data_session.add(obj_no_algorithm)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        uuid_no_key = str(obj_no_key.unique_identifier)
        uuid_no_algorithm = str(obj_no_algorithm.unique_identifier)

        cryptographic_parameters = attributes.CryptographicParameters(
            cryptographic_algorithm=algorithm
        )

        payload_no_key = payloads.MACRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(uuid_no_key),
            cryptographic_parameters=cryptographic_parameters,
            data=objects.Data(data)
        )

        args = (payload_no_key, )
        regex = "A secret key value must be specified"
        self.assertRaisesRegexp(
            exceptions.PermissionDenied,
            regex,
            e._process_mac,
            *args
        )

        payload_no_algorithm = payloads.MACRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(uuid_no_algorithm),
            cryptographic_parameters=None,
            data=objects.Data(data)
        )

        args = (payload_no_algorithm, )
        regex = "The cryptographic algorithm must be specified"
        self.assertRaisesRegexp(
            exceptions.PermissionDenied,
            regex,
            e._process_mac,
            *args
        )

        payload_no_data = payloads.MACRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(uuid_no_algorithm),
            cryptographic_parameters=cryptographic_parameters,
            data=None
        )

        args = (payload_no_data, )
        regex = "No data to be MACed"
        self.assertRaisesRegexp(
            exceptions.PermissionDenied,
            regex,
            e._process_mac,
            *args
        )

    def test_mac_not_active_state(self):
        """
        Test that the right error is generated when an MAC request is
        received for an object that is not in 'active' state.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        key = (b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
               b'\x00\x00\x00\x00\x00')
        data = (b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A'
                b'\x0B\x0C\x0D\x0E\x0F')
        algorithm_a = enums.CryptographicAlgorithm.AES
        algorithm_b = enums.CryptographicAlgorithm.HMAC_SHA512
        obj = pie_objects.SymmetricKey(
            algorithm_a, 128, key, [enums.CryptographicUsageMask.MAC_GENERATE])
        obj.state = enums.State.PRE_ACTIVE

        e._data_session.add(obj)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        uuid = str(obj.unique_identifier)

        cryptographic_parameters = attributes.CryptographicParameters(
            cryptographic_algorithm=algorithm_b
        )

        # Verify when cryptographic_parameters is specified in request
        payload = payloads.MACRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(uuid),
            cryptographic_parameters=cryptographic_parameters,
            data=objects.Data(data)
        )

        args = (payload,)
        regex = "Object is not in a state that can be used for MACing."
        self.assertRaisesRegexp(
            exceptions.PermissionDenied,
            regex,
            e._process_mac,
            *args
        )

    def test_mac_crypto_usage_mask_not_set(self):
        """
        Test that the right error is generated when an MAC request is
        received for an object without proper crypto usage mask set.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        key = (b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
               b'\x00\x00\x00\x00\x00')
        data = (b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A'
                b'\x0B\x0C\x0D\x0E\x0F')
        algorithm_a = enums.CryptographicAlgorithm.AES
        algorithm_b = enums.CryptographicAlgorithm.HMAC_SHA512
        obj = pie_objects.SymmetricKey(
            algorithm_a, 128, key, [enums.CryptographicUsageMask.MAC_VERIFY])
        obj.state = enums.State.ACTIVE

        e._data_session.add(obj)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        uuid = str(obj.unique_identifier)

        cryptographic_parameters = attributes.CryptographicParameters(
            cryptographic_algorithm=algorithm_b
        )

        # Verify when cryptographic_parameters is specified in request
        payload = payloads.MACRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(uuid),
            cryptographic_parameters=cryptographic_parameters,
            data=objects.Data(data)
        )

        args = (payload,)
        regex = "MAC Generate must be set in the object's cryptographic " \
                "usage mask"
        self.assertRaisesRegexp(
            exceptions.PermissionDenied,
            regex,
            e._process_mac,
            *args
        )

    def test_create_get_destroy(self):
        """
        Test that a managed object can be created, retrieved, and destroyed
        without error.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()

        attribute_factory = factory.AttributeFactory()

        # Build a SymmetricKey for registration.
        object_type = attributes.ObjectType(enums.ObjectType.SYMMETRIC_KEY)
        template_attribute = objects.TemplateAttribute(
            attributes=[
                attribute_factory.create_attribute(
                    enums.AttributeType.NAME,
                    attributes.Name.create(
                        'Test Symmetric Key',
                        enums.NameType.UNINTERPRETED_TEXT_STRING
                    )
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                    enums.CryptographicAlgorithm.AES
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                    256
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    [
                        enums.CryptographicUsageMask.ENCRYPT,
                        enums.CryptographicUsageMask.DECRYPT
                    ]
                )
            ]
        )

        # Create the symmetric key with the corresponding attributes
        payload = payloads.CreateRequestPayload(
            object_type=object_type,
            template_attribute=template_attribute
        )

        response_payload = e._process_create(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Create"
        )

        uid = response_payload.unique_identifier.value
        self.assertEqual('1', uid)

        e._logger.reset_mock()

        # Retrieve the created key using Get and verify all fields set
        payload = payloads.GetRequestPayload(unique_identifier=uid)

        response_payload = e._process_get(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Get"
        )
        self.assertEqual(
            enums.ObjectType.SYMMETRIC_KEY,
            response_payload.object_type
        )
        self.assertEqual(str(uid), response_payload.unique_identifier)
        self.assertIsInstance(response_payload.secret, secrets.SymmetricKey)

        key_block = response_payload.secret.key_block
        self.assertEqual(
            256,
            len(key_block.key_value.key_material.value) * 8
        )
        self.assertEqual(
            enums.KeyFormatType.RAW,
            key_block.key_format_type.value
        )
        self.assertEqual(
            enums.CryptographicAlgorithm.AES,
            key_block.cryptographic_algorithm.value
        )
        self.assertEqual(
            256,
            key_block.cryptographic_length.value
        )

        e._logger.reset_mock()

        # Destroy the symmetric key and verify it cannot be accessed again
        payload = payloads.DestroyRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(uid)
        )

        response_payload = e._process_destroy(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Destroy"
        )
        self.assertEqual(str(uid), response_payload.unique_identifier.value)

        args = (payload, )
        regex = "Could not locate object: {0}".format(uid)
        six.assertRaisesRegex(
            self,
            exceptions.ItemNotFound,
            regex,
            e._process_destroy,
            *args
        )

        e._data_session.commit()
        e._data_store_session_factory()

    def test_create_key_pair_get_destroy(self):
        """
        Test that a key pair can be created, retrieved, and destroyed without
        error.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()

        attribute_factory = factory.AttributeFactory()

        common_template = objects.CommonTemplateAttribute(
            attributes=[
                attribute_factory.create_attribute(
                    enums.AttributeType.NAME,
                    attributes.Name.create(
                        'Test Asymmetric Key',
                        enums.NameType.UNINTERPRETED_TEXT_STRING
                    )
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                    enums.CryptographicAlgorithm.RSA
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                    2048
                )
            ]
        )
        public_template = objects.PublicKeyTemplateAttribute(
            attributes=[
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    [
                        enums.CryptographicUsageMask.ENCRYPT
                    ]
                )
            ]
        )
        private_template = objects.PrivateKeyTemplateAttribute(
            attributes=[
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    [
                        enums.CryptographicUsageMask.DECRYPT
                    ]
                )
            ]
        )
        payload = payloads.CreateKeyPairRequestPayload(
            common_template,
            private_template,
            public_template
        )

        response_payload = e._process_create_key_pair(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: CreateKeyPair"
        )

        public_id = response_payload.public_key_uuid.value
        self.assertEqual('1', public_id)
        private_id = response_payload.private_key_uuid.value
        self.assertEqual('2', private_id)

        e._logger.reset_mock()

        # Retrieve the created public key using Get and verify all fields set
        payload = payloads.GetRequestPayload(unique_identifier=public_id)

        response_payload = e._process_get(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Get"
        )
        self.assertEqual(
            enums.ObjectType.PUBLIC_KEY,
            response_payload.object_type
        )
        self.assertEqual(str(public_id), response_payload.unique_identifier)
        self.assertIsInstance(response_payload.secret, secrets.PublicKey)

        key_block = response_payload.secret.key_block
        self.assertEqual(
            enums.KeyFormatType.PKCS_1,
            key_block.key_format_type.value
        )
        self.assertEqual(
            enums.CryptographicAlgorithm.RSA,
            key_block.cryptographic_algorithm.value
        )
        self.assertEqual(
            2048,
            key_block.cryptographic_length.value
        )

        e._logger.reset_mock()

        # Retrieve the created private key using Get and verify all fields set
        payload = payloads.GetRequestPayload(unique_identifier=private_id)

        response_payload = e._process_get(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Get"
        )
        self.assertEqual(
            enums.ObjectType.PRIVATE_KEY,
            response_payload.object_type
        )
        self.assertEqual(str(private_id), response_payload.unique_identifier)
        self.assertIsInstance(response_payload.secret, secrets.PrivateKey)

        key_block = response_payload.secret.key_block
        self.assertEqual(
            enums.KeyFormatType.PKCS_8,
            key_block.key_format_type.value
        )
        self.assertEqual(
            enums.CryptographicAlgorithm.RSA,
            key_block.cryptographic_algorithm.value
        )
        self.assertEqual(
            2048,
            key_block.cryptographic_length.value
        )

        e._data_session.commit()
        e._data_store_session_factory()
        e._logger.reset_mock()

        # Destroy the public key and verify it cannot be accessed again
        payload = payloads.DestroyRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(public_id)
        )

        response_payload = e._process_destroy(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Destroy"
        )
        self.assertEqual(
            str(public_id),
            response_payload.unique_identifier.value
        )

        e._data_session.commit()
        e._data_store_session_factory()
        e._logger.reset_mock()

        args = (payload, )
        regex = "Could not locate object: {0}".format(public_id)
        six.assertRaisesRegex(
            self,
            exceptions.ItemNotFound,
            regex,
            e._process_destroy,
            *args
        )

        e._data_session.commit()
        e._data_store_session_factory()
        e._logger.reset_mock()

        # Destroy the private key and verify it cannot be accessed again
        payload = payloads.DestroyRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(private_id)
        )

        response_payload = e._process_destroy(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Destroy"
        )
        self.assertEqual(
            str(private_id),
            response_payload.unique_identifier.value
        )

        e._data_session.commit()
        e._data_store_session_factory()
        e._logger.reset_mock()

        args = (payload, )
        regex = "Could not locate object: {0}".format(private_id)
        six.assertRaisesRegex(
            self,
            exceptions.ItemNotFound,
            regex,
            e._process_destroy,
            *args
        )

        e._data_session.commit()
        e._data_store_session_factory()

    def test_register_get_destroy(self):
        """
        Test that a managed object can be registered, retrieved, and destroyed
        without error.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()

        attribute_factory = factory.AttributeFactory()

        # Build a SymmetricKey for registration.
        object_type = attributes.ObjectType(enums.ObjectType.SYMMETRIC_KEY)
        template_attribute = objects.TemplateAttribute(
            attributes=[
                attribute_factory.create_attribute(
                    enums.AttributeType.NAME,
                    attributes.Name.create(
                        'Test Symmetric Key',
                        enums.NameType.UNINTERPRETED_TEXT_STRING
                    )
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                    enums.CryptographicAlgorithm.AES
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                    128
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    [
                        enums.CryptographicUsageMask.ENCRYPT,
                        enums.CryptographicUsageMask.DECRYPT
                    ]
                )
            ]
        )
        key_bytes = (
            b'\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00'
        )
        secret = secrets.SymmetricKey(
            key_block=objects.KeyBlock(
                key_format_type=misc.KeyFormatType(enums.KeyFormatType.RAW),
                key_value=objects.KeyValue(
                    key_material=objects.KeyMaterial(key_bytes)
                ),
                cryptographic_algorithm=attributes.CryptographicAlgorithm(
                    enums.CryptographicAlgorithm.AES
                ),
                cryptographic_length=attributes.CryptographicLength(128)
            )
        )

        # Register the symmetric key with the corresponding attributes
        payload = payloads.RegisterRequestPayload(
            object_type=object_type,
            template_attribute=template_attribute,
            secret=secret
        )

        response_payload = e._process_register(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Register"
        )

        uid = response_payload.unique_identifier.value
        self.assertEqual('1', uid)

        e._logger.reset_mock()

        # Retrieve the registered key using Get and verify all fields set
        payload = payloads.GetRequestPayload(unique_identifier=uid)

        response_payload = e._process_get(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Get"
        )
        self.assertEqual(
            enums.ObjectType.SYMMETRIC_KEY,
            response_payload.object_type
        )
        self.assertEqual(str(uid), response_payload.unique_identifier)
        self.assertIsInstance(response_payload.secret, secrets.SymmetricKey)
        self.assertEqual(
            key_bytes,
            response_payload.secret.key_block.key_value.key_material.value
        )
        self.assertEqual(
            enums.KeyFormatType.RAW,
            response_payload.secret.key_block.key_format_type.value
        )
        self.assertEqual(
            enums.CryptographicAlgorithm.AES,
            response_payload.secret.key_block.cryptographic_algorithm.value
        )
        self.assertEqual(
            128,
            response_payload.secret.key_block.cryptographic_length.value
        )

        e._logger.reset_mock()

        # Destroy the symmetric key and verify it cannot be accessed again
        payload = payloads.DestroyRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(uid)
        )

        response_payload = e._process_destroy(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Destroy"
        )
        self.assertEqual(str(uid), response_payload.unique_identifier.value)

        args = (payload, )
        regex = "Could not locate object: {0}".format(uid)
        six.assertRaisesRegex(
            self,
            exceptions.ItemNotFound,
            regex,
            e._process_destroy,
            *args
        )

        e._data_session.commit()
        e._data_store_session_factory()

    def test_register_activate_encrypt_decrypt_revoke_destroy(self):
        """
        Test that a symmetric key can be registered with the server,
        activated, used for encryption and decryption, revoked, and finally
        destroyed without error.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()

        attribute_factory = factory.AttributeFactory()

        # Build a SymmetricKey for registration.
        object_type = attributes.ObjectType(enums.ObjectType.SYMMETRIC_KEY)
        template_attribute = objects.TemplateAttribute(
            attributes=[
                attribute_factory.create_attribute(
                    enums.AttributeType.NAME,
                    attributes.Name.create(
                        'Test Symmetric Key',
                        enums.NameType.UNINTERPRETED_TEXT_STRING
                    )
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                    enums.CryptographicAlgorithm.BLOWFISH
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                    128
                ),
                attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    [
                        enums.CryptographicUsageMask.ENCRYPT,
                        enums.CryptographicUsageMask.DECRYPT
                    ]
                )
            ]
        )
        key_bytes = (
            b'\x01\x23\x45\x67\x89\xAB\xCD\xEF'
            b'\xF0\xE1\xD2\xC3\xB4\xA5\x96\x87'
        )
        secret = secrets.SymmetricKey(
            key_block=objects.KeyBlock(
                key_format_type=misc.KeyFormatType(enums.KeyFormatType.RAW),
                key_value=objects.KeyValue(
                    key_material=objects.KeyMaterial(key_bytes)
                ),
                cryptographic_algorithm=attributes.CryptographicAlgorithm(
                    enums.CryptographicAlgorithm.BLOWFISH
                ),
                cryptographic_length=attributes.CryptographicLength(128)
            )
        )

        # Register the symmetric key with the corresponding attributes
        payload = payloads.RegisterRequestPayload(
            object_type=object_type,
            template_attribute=template_attribute,
            secret=secret
        )

        response_payload = e._process_register(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Register"
        )

        uuid = response_payload.unique_identifier.value
        self.assertEqual('1', uuid)

        e._logger.reset_mock()

        # Activate the symmetric key
        payload = payloads.ActivateRequestPayload(
            attributes.UniqueIdentifier(uuid)
        )

        response_payload = e._process_activate(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Activate"
        )

        activated_uuid = response_payload.unique_identifier.value
        self.assertEqual(uuid, activated_uuid)

        # Encrypt some data using the symmetric key
        payload = payloads.EncryptRequestPayload(
            unique_identifier=uuid,
            cryptographic_parameters=attributes.CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.CBC,
                padding_method=enums.PaddingMethod.PKCS5,
                cryptographic_algorithm=enums.CryptographicAlgorithm.BLOWFISH
            ),
            data=(
                b'\x37\x36\x35\x34\x33\x32\x31\x20'
                b'\x4E\x6F\x77\x20\x69\x73\x20\x74'
                b'\x68\x65\x20\x74\x69\x6D\x65\x20'
                b'\x66\x6F\x72\x20\x00'
            ),
            iv_counter_nonce=b'\xFE\xDC\xBA\x98\x76\x54\x32\x10'
        )

        response_payload = e._process_encrypt(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Encrypt"
        )

        self.assertEqual(
            uuid,
            response_payload.unique_identifier
        )
        self.assertEqual(
            (
                b'\x6B\x77\xB4\xD6\x30\x06\xDE\xE6'
                b'\x05\xB1\x56\xE2\x74\x03\x97\x93'
                b'\x58\xDE\xB9\xE7\x15\x46\x16\xD9'
                b'\x74\x9D\xEC\xBE\xC0\x5D\x26\x4B'
            ),
            response_payload.data
        )

        # Decrypt the encrypted data using the symmetric key
        payload = payloads.DecryptRequestPayload(
            unique_identifier=uuid,
            cryptographic_parameters=attributes.CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.CBC,
                padding_method=enums.PaddingMethod.PKCS5,
                cryptographic_algorithm=enums.CryptographicAlgorithm.BLOWFISH
            ),
            data=response_payload.data,
            iv_counter_nonce=b'\xFE\xDC\xBA\x98\x76\x54\x32\x10'
        )

        response_payload = e._process_decrypt(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Decrypt"
        )

        self.assertEqual(
            uuid,
            response_payload.unique_identifier
        )
        self.assertEqual(
            (
                b'\x37\x36\x35\x34\x33\x32\x31\x20'
                b'\x4E\x6F\x77\x20\x69\x73\x20\x74'
                b'\x68\x65\x20\x74\x69\x6D\x65\x20'
                b'\x66\x6F\x72\x20\x00'
            ),
            response_payload.data
        )

        # Revoke the activated symmetric key to prepare it for deletion
        payload = payloads.RevokeRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(uuid)
        )

        response_payload = e._process_revoke(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Revoke"
        )

        self.assertEqual(uuid, response_payload.unique_identifier.value)

        # Destroy the symmetric key and verify it cannot be accessed again
        payload = payloads.DestroyRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(uuid)
        )

        response_payload = e._process_destroy(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Destroy"
        )
        self.assertEqual(str(uuid), response_payload.unique_identifier.value)

        args = (payload, )
        regex = "Could not locate object: {0}".format(uuid)
        six.assertRaisesRegex(
            self,
            exceptions.ItemNotFound,
            regex,
            e._process_destroy,
            *args
        )

        e._data_session.commit()
        e._data_store_session_factory()

    def test_sign(self):
        """
        Test that a Sign request can be processed correctly.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        signing_key = pie_objects.PrivateKey(
            enums.CryptographicAlgorithm.RSA,
            1024,
            (b'\x30\x82\x02\x5e\x02\x01\x00\x02\x81\x81\x00\xae\xba\xc1\xb9'
             b'\xa1\x74\x31\x5d\x27\xcc\x3c\x20\x1e\x21\x57\x89\x43\x72\xd6'
             b'\x45\x0d\x4c\xf8\x0c\xe0\xeb\xcf\x51\x69\x51\x9b\x9e\x85\x50'
             b'\x03\x6f\x4a\xbe\x0f\xe4\xf9\x4f\xbf\x9c\xca\x60\x6f\x39\x74'
             b'\x33\x65\x49\x96\x11\xba\x3f\x25\xa9\xa4\x71\x58\xba\x05\x21'
             b'\x4b\x65\x5f\x42\x58\xa4\xc2\x95\x16\xbe\xca\xa5\x83\xf2\xd2'
             b'\x66\x50\x69\x6a\xd6\xfc\x03\xd5\xb4\x7d\x3a\xba\x9c\x54\x79'
             b'\xfd\xb0\x47\x7d\x29\x51\x33\x99\xcb\x19\x28\x3c\xcd\xc2\x8d'
             b'\xbb\x23\xb7\xc7\xee\xe4\xb3\x5d\xc9\x40\xda\xca\x00\x55\xdc'
             b'\xd2\x8f\x50\x3b\x02\x03\x01\x00\x01\x02\x81\x81\x00\x92\x89'
             b'\x09\x42\xd6\xc6\x8d\x47\xa4\xc2\xc1\x81\xe6\x02\xec\x58\xaf'
             b'\x7a\x35\x7c\x7f\xa5\x17\x3a\x25\xbf\x5d\x84\xd7\x20\x9b\xb4'
             b'\x1b\xf5\x78\x8b\xf3\x50\xe6\x1f\x8f\x7e\x74\x21\xd8\x0f\x7b'
             b'\xf7\xe1\x1d\xe1\x4a\x0f\x53\x1a\xb1\x2e\xb2\xd0\xb8\x46\x42'
             b'\xeb\x5d\x18\x11\x70\xc2\xc5\x8a\xab\xbd\x67\x54\x84\x2f\xaf'
             b'\xee\x57\xfe\xf2\xf5\x45\xd0\x9f\xdc\x66\x49\x02\xe5\x5b\xac'
             b'\xed\x5a\x3c\x6d\x26\xf3\x46\x58\x59\xd3\x3a\x33\xa5\x55\x53'
             b'\x7d\xaf\x22\x63\xaa\xef\x28\x35\x4c\x8b\x53\x51\x31\x45\xa7'
             b'\xe2\x28\x82\x4d\xab\xb1\x02\x41\x00\xd3\xaa\x23\x7e\x89\x42'
             b'\xb9\x3d\x56\xa6\x81\x25\x4c\x27\xbe\x1f\x4a\x49\x6c\xa4\xa8'
             b'\x7f\xc0\x60\x4b\x0c\xff\x8f\x98\x0e\x74\x2d\x2b\xbb\x91\xb8'
             b'\x8a\x24\x7b\x6e\xbb\xed\x01\x45\x8c\x4a\xfd\xb6\x8c\x0f\x8c'
             b'\x6d\x4a\x37\xe0\x28\xc5\xfc\xb3\xa6\xa3\x9c\xa6\x4f\x02\x41'
             b'\x00\xd3\x54\x16\x8c\x61\x9c\x83\x6e\x85\x97\xfe\xf5\x01\x93'
             b'\xa6\xf4\x26\x07\x95\x2a\x1c\x87\xeb\xae\x91\xdb\x50\x43\xb8'
             b'\x85\x50\x72\xb4\xe9\x2a\xf5\xdc\xed\xb2\x14\x87\x73\xdf\xbd'
             b'\x21\x7b\xaf\xc8\xdc\x9d\xa8\xae\x8e\x75\x7e\x72\x48\xc1\xe5'
             b'\x13\xa1\x44\x68\x55\x02\x41\x00\x90\xfd\xa2\x14\xc2\xb7\xb7'
             b'\x26\x82\x5d\xca\x67\x9f\x34\x36\x33\x3e\xf2\xee\xfe\x18\x02'
             b'\x72\xe8\x43\x60\xe3\x0b\x1d\x11\x01\x9a\x13\xb4\x08\x0d\x0e'
             b'\x6c\x11\x35\x78\x7b\xd0\x7c\x30\xaf\x09\xfe\xeb\x10\x97\x94'
             b'\x21\xdc\x06\xac\x47\x7b\x64\x20\xc9\x40\xbc\x57\x02\x40\x16'
             b'\x4d\xe8\xb7\x56\x52\x13\x99\x25\xa6\x7e\x35\x53\xbe\x46\xbf'
             b'\xbc\x07\xce\xd9\x8b\xfb\x58\x87\xab\x43\x4f\x7c\x66\x4c\x43'
             b'\xca\x67\x87\xb8\x8e\x0c\x8c\x55\xe0\x4e\xcf\x8f\x0c\xc2\x2c'
             b'\xf0\xc7\xad\x69\x42\x75\x71\xf9\xba\xa7\xcb\x40\x13\xb2\x77'
             b'\xb1\xe5\xa5\x02\x41\x00\xca\xe1\x50\xf5\xfa\x55\x9b\x2e\x2c'
             b'\x39\x44\x4e\x0f\x5c\x65\x10\x34\x09\x2a\xc9\x7b\xac\x10\xd5'
             b'\x28\xdd\x15\xdf\xda\x25\x4c\xb0\x6b\xef\x41\xe3\x98\x81\xf7'
             b'\xe7\x49\x69\x10\xb4\x65\x56\x59\xdc\x84\x2d\x30\xb9\xae\x27'
             b'\x59\xf3\xc2\xcd\x41\xc7\x9a\x36\x84\xec'),
            enums.KeyFormatType.RAW,
            masks=[enums.CryptographicUsageMask.SIGN],
        )

        signing_key.state = enums.State.ACTIVE

        e._data_session.add(signing_key)
        e._data_session.commit()
        e.data_session = e._data_store_session_factory()

        unique_identifier = str(signing_key.unique_identifier)
        payload = payloads.SignRequestPayload(
            unique_identifier=unique_identifier,
            cryptographic_parameters=attributes.CryptographicParameters(
                padding_method=enums.PaddingMethod.PSS,
                digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
                SHA1_WITH_RSA_ENCRYPTION
            ),
            data=(
                b'\x01\x02\x03\x04\x05\x06\x07\x08'
                b'\x09\x10\x11\x12\x13\x14\x15\x16'
            )
        )

        response_payload = e._process_sign(payload)

        e._logger.info.assert_any_call(
            "Processing operation: Sign"
        )
        self.assertEqual(
            unique_identifier,
            response_payload.unique_identifier
        )

    def test_sign_no_cryptographic_parameters(self):
        """
        Test that the right error is thrown when cryptographic parameters
        are not provided with a SignatureVerify request.

        TODO (dane-fichter): update this test once cryptographic
        parameters can be fetched using the key's attributes.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        signing_key = pie_objects.PrivateKey(
            enums.CryptographicAlgorithm.RSA,
            1024,
            (b'\x30\x82\x02\x5e\x02\x01\x00\x02\x81\x81\x00\xae\xba\xc1\xb9'
             b'\xa1\x74\x31\x5d\x27\xcc\x3c\x20\x1e\x21\x57\x89\x43\x72\xd6'
             b'\x45\x0d\x4c\xf8\x0c\xe0\xeb\xcf\x51\x69\x51\x9b\x9e\x85\x50'
             b'\x03\x6f\x4a\xbe\x0f\xe4\xf9\x4f\xbf\x9c\xca\x60\x6f\x39\x74'
             b'\x33\x65\x49\x96\x11\xba\x3f\x25\xa9\xa4\x71\x58\xba\x05\x21'
             b'\x4b\x65\x5f\x42\x58\xa4\xc2\x95\x16\xbe\xca\xa5\x83\xf2\xd2'
             b'\x66\x50\x69\x6a\xd6\xfc\x03\xd5\xb4\x7d\x3a\xba\x9c\x54\x79'
             b'\xfd\xb0\x47\x7d\x29\x51\x33\x99\xcb\x19\x28\x3c\xcd\xc2\x8d'
             b'\xbb\x23\xb7\xc7\xee\xe4\xb3\x5d\xc9\x40\xda\xca\x00\x55\xdc'
             b'\xd2\x8f\x50\x3b\x02\x03\x01\x00\x01\x02\x81\x81\x00\x92\x89'
             b'\x09\x42\xd6\xc6\x8d\x47\xa4\xc2\xc1\x81\xe6\x02\xec\x58\xaf'
             b'\x7a\x35\x7c\x7f\xa5\x17\x3a\x25\xbf\x5d\x84\xd7\x20\x9b\xb4'
             b'\x1b\xf5\x78\x8b\xf3\x50\xe6\x1f\x8f\x7e\x74\x21\xd8\x0f\x7b'
             b'\xf7\xe1\x1d\xe1\x4a\x0f\x53\x1a\xb1\x2e\xb2\xd0\xb8\x46\x42'
             b'\xeb\x5d\x18\x11\x70\xc2\xc5\x8a\xab\xbd\x67\x54\x84\x2f\xaf'
             b'\xee\x57\xfe\xf2\xf5\x45\xd0\x9f\xdc\x66\x49\x02\xe5\x5b\xac'
             b'\xed\x5a\x3c\x6d\x26\xf3\x46\x58\x59\xd3\x3a\x33\xa5\x55\x53'
             b'\x7d\xaf\x22\x63\xaa\xef\x28\x35\x4c\x8b\x53\x51\x31\x45\xa7'
             b'\xe2\x28\x82\x4d\xab\xb1\x02\x41\x00\xd3\xaa\x23\x7e\x89\x42'
             b'\xb9\x3d\x56\xa6\x81\x25\x4c\x27\xbe\x1f\x4a\x49\x6c\xa4\xa8'
             b'\x7f\xc0\x60\x4b\x0c\xff\x8f\x98\x0e\x74\x2d\x2b\xbb\x91\xb8'
             b'\x8a\x24\x7b\x6e\xbb\xed\x01\x45\x8c\x4a\xfd\xb6\x8c\x0f\x8c'
             b'\x6d\x4a\x37\xe0\x28\xc5\xfc\xb3\xa6\xa3\x9c\xa6\x4f\x02\x41'
             b'\x00\xd3\x54\x16\x8c\x61\x9c\x83\x6e\x85\x97\xfe\xf5\x01\x93'
             b'\xa6\xf4\x26\x07\x95\x2a\x1c\x87\xeb\xae\x91\xdb\x50\x43\xb8'
             b'\x85\x50\x72\xb4\xe9\x2a\xf5\xdc\xed\xb2\x14\x87\x73\xdf\xbd'
             b'\x21\x7b\xaf\xc8\xdc\x9d\xa8\xae\x8e\x75\x7e\x72\x48\xc1\xe5'
             b'\x13\xa1\x44\x68\x55\x02\x41\x00\x90\xfd\xa2\x14\xc2\xb7\xb7'
             b'\x26\x82\x5d\xca\x67\x9f\x34\x36\x33\x3e\xf2\xee\xfe\x18\x02'
             b'\x72\xe8\x43\x60\xe3\x0b\x1d\x11\x01\x9a\x13\xb4\x08\x0d\x0e'
             b'\x6c\x11\x35\x78\x7b\xd0\x7c\x30\xaf\x09\xfe\xeb\x10\x97\x94'
             b'\x21\xdc\x06\xac\x47\x7b\x64\x20\xc9\x40\xbc\x57\x02\x40\x16'
             b'\x4d\xe8\xb7\x56\x52\x13\x99\x25\xa6\x7e\x35\x53\xbe\x46\xbf'
             b'\xbc\x07\xce\xd9\x8b\xfb\x58\x87\xab\x43\x4f\x7c\x66\x4c\x43'
             b'\xca\x67\x87\xb8\x8e\x0c\x8c\x55\xe0\x4e\xcf\x8f\x0c\xc2\x2c'
             b'\xf0\xc7\xad\x69\x42\x75\x71\xf9\xba\xa7\xcb\x40\x13\xb2\x77'
             b'\xb1\xe5\xa5\x02\x41\x00\xca\xe1\x50\xf5\xfa\x55\x9b\x2e\x2c'
             b'\x39\x44\x4e\x0f\x5c\x65\x10\x34\x09\x2a\xc9\x7b\xac\x10\xd5'
             b'\x28\xdd\x15\xdf\xda\x25\x4c\xb0\x6b\xef\x41\xe3\x98\x81\xf7'
             b'\xe7\x49\x69\x10\xb4\x65\x56\x59\xdc\x84\x2d\x30\xb9\xae\x27'
             b'\x59\xf3\xc2\xcd\x41\xc7\x9a\x36\x84\xec'),
            enums.KeyFormatType.RAW,
            masks=[enums.CryptographicUsageMask.SIGN],
        )

        signing_key.state = enums.State.ACTIVE

        e._data_session.add(signing_key)
        e._data_session.commit()
        e.data_session = e._data_store_session_factory()

        unique_identifier = str(signing_key.unique_identifier)
        payload = payloads.SignRequestPayload(
            unique_identifier=unique_identifier,
            data=b'',
        )

        args = (payload,)
        self.assertRaisesRegexp(
            exceptions.InvalidField,
            "The cryptographic parameters must be specified.",
            e._process_sign,
            *args
        )

    def test_sign_invalid_signing_key(self):
        """
        Test that the right error is thrown when an invalid signing key
        is specified with a Sign request.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        signing_key = pie_objects.OpaqueObject(
            b'\x01\x02\x03\x04',
            enums.OpaqueDataType.NONE
        )

        e._data_session.add(signing_key)
        e._data_session.commit()
        e.data_session = e._data_store_session_factory()

        unique_identifier = str(signing_key.unique_identifier)
        payload = payloads.SignRequestPayload(
            unique_identifier=unique_identifier,
            cryptographic_parameters=attributes.CryptographicParameters(
                padding_method=enums.PaddingMethod.PSS,
                digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
                SHA1_WITH_RSA_ENCRYPTION
            ),
            data=(
                b'\x01\x02\x03\x04\x05\x06\x07\x08'
                b'\x09\x10\x11\x12\x13\x14\x15\x16'
            )
        )

        args = (payload, )
        self.assertRaisesRegexp(
            exceptions.PermissionDenied,
            "The requested signing key is not a private key. "
            "A private key must be specified.",
            e._process_sign,
            *args
        )

    def test_sign_inactive_signing_key(self):
        """
        Test that the right error is thrown when an inactive signing key
        is specified in a Sign request.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        signing_key = pie_objects.PrivateKey(
            enums.CryptographicAlgorithm.RSA,
            1024,
            (b'\x30\x82\x02\x5e\x02\x01\x00\x02\x81\x81\x00\xae\xba\xc1\xb9'
             b'\xa1\x74\x31\x5d\x27\xcc\x3c\x20\x1e\x21\x57\x89\x43\x72\xd6'
             b'\x45\x0d\x4c\xf8\x0c\xe0\xeb\xcf\x51\x69\x51\x9b\x9e\x85\x50'
             b'\x03\x6f\x4a\xbe\x0f\xe4\xf9\x4f\xbf\x9c\xca\x60\x6f\x39\x74'
             b'\x33\x65\x49\x96\x11\xba\x3f\x25\xa9\xa4\x71\x58\xba\x05\x21'
             b'\x4b\x65\x5f\x42\x58\xa4\xc2\x95\x16\xbe\xca\xa5\x83\xf2\xd2'
             b'\x66\x50\x69\x6a\xd6\xfc\x03\xd5\xb4\x7d\x3a\xba\x9c\x54\x79'
             b'\xfd\xb0\x47\x7d\x29\x51\x33\x99\xcb\x19\x28\x3c\xcd\xc2\x8d'
             b'\xbb\x23\xb7\xc7\xee\xe4\xb3\x5d\xc9\x40\xda\xca\x00\x55\xdc'
             b'\xd2\x8f\x50\x3b\x02\x03\x01\x00\x01\x02\x81\x81\x00\x92\x89'
             b'\x09\x42\xd6\xc6\x8d\x47\xa4\xc2\xc1\x81\xe6\x02\xec\x58\xaf'
             b'\x7a\x35\x7c\x7f\xa5\x17\x3a\x25\xbf\x5d\x84\xd7\x20\x9b\xb4'
             b'\x1b\xf5\x78\x8b\xf3\x50\xe6\x1f\x8f\x7e\x74\x21\xd8\x0f\x7b'
             b'\xf7\xe1\x1d\xe1\x4a\x0f\x53\x1a\xb1\x2e\xb2\xd0\xb8\x46\x42'
             b'\xeb\x5d\x18\x11\x70\xc2\xc5\x8a\xab\xbd\x67\x54\x84\x2f\xaf'
             b'\xee\x57\xfe\xf2\xf5\x45\xd0\x9f\xdc\x66\x49\x02\xe5\x5b\xac'
             b'\xed\x5a\x3c\x6d\x26\xf3\x46\x58\x59\xd3\x3a\x33\xa5\x55\x53'
             b'\x7d\xaf\x22\x63\xaa\xef\x28\x35\x4c\x8b\x53\x51\x31\x45\xa7'
             b'\xe2\x28\x82\x4d\xab\xb1\x02\x41\x00\xd3\xaa\x23\x7e\x89\x42'
             b'\xb9\x3d\x56\xa6\x81\x25\x4c\x27\xbe\x1f\x4a\x49\x6c\xa4\xa8'
             b'\x7f\xc0\x60\x4b\x0c\xff\x8f\x98\x0e\x74\x2d\x2b\xbb\x91\xb8'
             b'\x8a\x24\x7b\x6e\xbb\xed\x01\x45\x8c\x4a\xfd\xb6\x8c\x0f\x8c'
             b'\x6d\x4a\x37\xe0\x28\xc5\xfc\xb3\xa6\xa3\x9c\xa6\x4f\x02\x41'
             b'\x00\xd3\x54\x16\x8c\x61\x9c\x83\x6e\x85\x97\xfe\xf5\x01\x93'
             b'\xa6\xf4\x26\x07\x95\x2a\x1c\x87\xeb\xae\x91\xdb\x50\x43\xb8'
             b'\x85\x50\x72\xb4\xe9\x2a\xf5\xdc\xed\xb2\x14\x87\x73\xdf\xbd'
             b'\x21\x7b\xaf\xc8\xdc\x9d\xa8\xae\x8e\x75\x7e\x72\x48\xc1\xe5'
             b'\x13\xa1\x44\x68\x55\x02\x41\x00\x90\xfd\xa2\x14\xc2\xb7\xb7'
             b'\x26\x82\x5d\xca\x67\x9f\x34\x36\x33\x3e\xf2\xee\xfe\x18\x02'
             b'\x72\xe8\x43\x60\xe3\x0b\x1d\x11\x01\x9a\x13\xb4\x08\x0d\x0e'
             b'\x6c\x11\x35\x78\x7b\xd0\x7c\x30\xaf\x09\xfe\xeb\x10\x97\x94'
             b'\x21\xdc\x06\xac\x47\x7b\x64\x20\xc9\x40\xbc\x57\x02\x40\x16'
             b'\x4d\xe8\xb7\x56\x52\x13\x99\x25\xa6\x7e\x35\x53\xbe\x46\xbf'
             b'\xbc\x07\xce\xd9\x8b\xfb\x58\x87\xab\x43\x4f\x7c\x66\x4c\x43'
             b'\xca\x67\x87\xb8\x8e\x0c\x8c\x55\xe0\x4e\xcf\x8f\x0c\xc2\x2c'
             b'\xf0\xc7\xad\x69\x42\x75\x71\xf9\xba\xa7\xcb\x40\x13\xb2\x77'
             b'\xb1\xe5\xa5\x02\x41\x00\xca\xe1\x50\xf5\xfa\x55\x9b\x2e\x2c'
             b'\x39\x44\x4e\x0f\x5c\x65\x10\x34\x09\x2a\xc9\x7b\xac\x10\xd5'
             b'\x28\xdd\x15\xdf\xda\x25\x4c\xb0\x6b\xef\x41\xe3\x98\x81\xf7'
             b'\xe7\x49\x69\x10\xb4\x65\x56\x59\xdc\x84\x2d\x30\xb9\xae\x27'
             b'\x59\xf3\xc2\xcd\x41\xc7\x9a\x36\x84\xec'),
            enums.KeyFormatType.RAW,
            masks=[enums.CryptographicUsageMask.SIGN],
        )

        e._data_session.add(signing_key)
        e._data_session.commit()
        e.data_session = e._data_store_session_factory()

        unique_identifier = str(signing_key.unique_identifier)
        payload = payloads.SignRequestPayload(
            unique_identifier=unique_identifier,
            cryptographic_parameters=attributes.CryptographicParameters(
                padding_method=enums.PaddingMethod.PSS,
                digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
                SHA1_WITH_RSA_ENCRYPTION
            ),
            data=(
                b'\x01\x02\x03\x04\x05\x06\x07\x08'
                b'\x09\x10\x11\x12\x13\x14\x15\x16'
            )
        )

        args = (payload, )
        self.assertRaisesRegexp(
            exceptions.PermissionDenied,
            "The signing key must be in the Active state to be "
            "used for signing.",
            e._process_sign,
            *args
        )

    def test_sign_non_signing_key(self):
        """
        Test that the right error is thrown when a non-signing key
        is specified in a Sign request.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._is_allowed_by_operation_policy = mock.Mock(return_value=True)
        e._logger = mock.MagicMock()
        e._cryptography_engine.logger = mock.MagicMock()

        signing_key = pie_objects.PrivateKey(
            enums.CryptographicAlgorithm.RSA,
            1024,
            (b'\x30\x82\x02\x5e\x02\x01\x00\x02\x81\x81\x00\xae\xba\xc1\xb9'
             b'\xa1\x74\x31\x5d\x27\xcc\x3c\x20\x1e\x21\x57\x89\x43\x72\xd6'
             b'\x45\x0d\x4c\xf8\x0c\xe0\xeb\xcf\x51\x69\x51\x9b\x9e\x85\x50'
             b'\x03\x6f\x4a\xbe\x0f\xe4\xf9\x4f\xbf\x9c\xca\x60\x6f\x39\x74'
             b'\x33\x65\x49\x96\x11\xba\x3f\x25\xa9\xa4\x71\x58\xba\x05\x21'
             b'\x4b\x65\x5f\x42\x58\xa4\xc2\x95\x16\xbe\xca\xa5\x83\xf2\xd2'
             b'\x66\x50\x69\x6a\xd6\xfc\x03\xd5\xb4\x7d\x3a\xba\x9c\x54\x79'
             b'\xfd\xb0\x47\x7d\x29\x51\x33\x99\xcb\x19\x28\x3c\xcd\xc2\x8d'
             b'\xbb\x23\xb7\xc7\xee\xe4\xb3\x5d\xc9\x40\xda\xca\x00\x55\xdc'
             b'\xd2\x8f\x50\x3b\x02\x03\x01\x00\x01\x02\x81\x81\x00\x92\x89'
             b'\x09\x42\xd6\xc6\x8d\x47\xa4\xc2\xc1\x81\xe6\x02\xec\x58\xaf'
             b'\x7a\x35\x7c\x7f\xa5\x17\x3a\x25\xbf\x5d\x84\xd7\x20\x9b\xb4'
             b'\x1b\xf5\x78\x8b\xf3\x50\xe6\x1f\x8f\x7e\x74\x21\xd8\x0f\x7b'
             b'\xf7\xe1\x1d\xe1\x4a\x0f\x53\x1a\xb1\x2e\xb2\xd0\xb8\x46\x42'
             b'\xeb\x5d\x18\x11\x70\xc2\xc5\x8a\xab\xbd\x67\x54\x84\x2f\xaf'
             b'\xee\x57\xfe\xf2\xf5\x45\xd0\x9f\xdc\x66\x49\x02\xe5\x5b\xac'
             b'\xed\x5a\x3c\x6d\x26\xf3\x46\x58\x59\xd3\x3a\x33\xa5\x55\x53'
             b'\x7d\xaf\x22\x63\xaa\xef\x28\x35\x4c\x8b\x53\x51\x31\x45\xa7'
             b'\xe2\x28\x82\x4d\xab\xb1\x02\x41\x00\xd3\xaa\x23\x7e\x89\x42'
             b'\xb9\x3d\x56\xa6\x81\x25\x4c\x27\xbe\x1f\x4a\x49\x6c\xa4\xa8'
             b'\x7f\xc0\x60\x4b\x0c\xff\x8f\x98\x0e\x74\x2d\x2b\xbb\x91\xb8'
             b'\x8a\x24\x7b\x6e\xbb\xed\x01\x45\x8c\x4a\xfd\xb6\x8c\x0f\x8c'
             b'\x6d\x4a\x37\xe0\x28\xc5\xfc\xb3\xa6\xa3\x9c\xa6\x4f\x02\x41'
             b'\x00\xd3\x54\x16\x8c\x61\x9c\x83\x6e\x85\x97\xfe\xf5\x01\x93'
             b'\xa6\xf4\x26\x07\x95\x2a\x1c\x87\xeb\xae\x91\xdb\x50\x43\xb8'
             b'\x85\x50\x72\xb4\xe9\x2a\xf5\xdc\xed\xb2\x14\x87\x73\xdf\xbd'
             b'\x21\x7b\xaf\xc8\xdc\x9d\xa8\xae\x8e\x75\x7e\x72\x48\xc1\xe5'
             b'\x13\xa1\x44\x68\x55\x02\x41\x00\x90\xfd\xa2\x14\xc2\xb7\xb7'
             b'\x26\x82\x5d\xca\x67\x9f\x34\x36\x33\x3e\xf2\xee\xfe\x18\x02'
             b'\x72\xe8\x43\x60\xe3\x0b\x1d\x11\x01\x9a\x13\xb4\x08\x0d\x0e'
             b'\x6c\x11\x35\x78\x7b\xd0\x7c\x30\xaf\x09\xfe\xeb\x10\x97\x94'
             b'\x21\xdc\x06\xac\x47\x7b\x64\x20\xc9\x40\xbc\x57\x02\x40\x16'
             b'\x4d\xe8\xb7\x56\x52\x13\x99\x25\xa6\x7e\x35\x53\xbe\x46\xbf'
             b'\xbc\x07\xce\xd9\x8b\xfb\x58\x87\xab\x43\x4f\x7c\x66\x4c\x43'
             b'\xca\x67\x87\xb8\x8e\x0c\x8c\x55\xe0\x4e\xcf\x8f\x0c\xc2\x2c'
             b'\xf0\xc7\xad\x69\x42\x75\x71\xf9\xba\xa7\xcb\x40\x13\xb2\x77'
             b'\xb1\xe5\xa5\x02\x41\x00\xca\xe1\x50\xf5\xfa\x55\x9b\x2e\x2c'
             b'\x39\x44\x4e\x0f\x5c\x65\x10\x34\x09\x2a\xc9\x7b\xac\x10\xd5'
             b'\x28\xdd\x15\xdf\xda\x25\x4c\xb0\x6b\xef\x41\xe3\x98\x81\xf7'
             b'\xe7\x49\x69\x10\xb4\x65\x56\x59\xdc\x84\x2d\x30\xb9\xae\x27'
             b'\x59\xf3\xc2\xcd\x41\xc7\x9a\x36\x84\xec'),
            enums.KeyFormatType.RAW,
            masks=[enums.CryptographicUsageMask.VERIFY],
        )

        signing_key.state = enums.State.ACTIVE

        e._data_session.add(signing_key)
        e._data_session.commit()
        e.data_session = e._data_store_session_factory()

        unique_identifier = str(signing_key.unique_identifier)
        payload = payloads.SignRequestPayload(
            unique_identifier=unique_identifier,
            cryptographic_parameters=attributes.CryptographicParameters(
                padding_method=enums.PaddingMethod.PSS,
                digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
                SHA1_WITH_RSA_ENCRYPTION
            ),
            data=(
                b'\x01\x02\x03\x04\x05\x06\x07\x08'
                b'\x09\x10\x11\x12\x13\x14\x15\x16'
            )
        )

        args = (payload, )
        self.assertRaisesRegexp(
            exceptions.PermissionDenied,
            "The Sign bit must be set in the signing key's cryptographic "
            "usage mask.",
            e._process_sign,
            *args
        )
