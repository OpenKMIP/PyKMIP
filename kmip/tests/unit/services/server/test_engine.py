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
import sqlalchemy

from sqlalchemy.orm import exc

import testtools
import time

import kmip

from kmip.core import attributes
from kmip.core import enums
from kmip.core import exceptions
from kmip.core import misc
from kmip.core import objects
from kmip.core import secrets

from kmip.core.factories import attributes as factory

from kmip.core.messages import contents
from kmip.core.messages import messages

from kmip.core.messages.payloads import create
from kmip.core.messages.payloads import create_key_pair
from kmip.core.messages.payloads import destroy
from kmip.core.messages.payloads import discover_versions
from kmip.core.messages.payloads import get
from kmip.core.messages.payloads import query
from kmip.core.messages.payloads import register

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
            bind=self.engine
        )

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

        e._process_create = mock.MagicMock()
        e._process_create_key_pair = mock.MagicMock()
        e._process_register = mock.MagicMock()
        e._process_get = mock.MagicMock()
        e._process_destroy = mock.MagicMock()
        e._process_query = mock.MagicMock()
        e._process_discover_versions = mock.MagicMock()

        e._process_operation(enums.Operation.CREATE, None)
        e._process_operation(enums.Operation.CREATE_KEY_PAIR, None)
        e._process_operation(enums.Operation.REGISTER, None)
        e._process_operation(enums.Operation.GET, None)
        e._process_operation(enums.Operation.DESTROY, None)
        e._process_operation(enums.Operation.QUERY, None)
        e._process_operation(enums.Operation.DISCOVER_VERSIONS, None)

        e._process_create.assert_called_with(None)
        e._process_create_key_pair.assert_called_with(None)
        e._process_register.assert_called_with(None)
        e._process_get.assert_called_with(None)
        e._process_destroy.assert_called_with(None)
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

    def test_get_object_type(self):
        """
        Test that the object type of a stored object can be retrieved
        correctly.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
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
        e._logger = mock.MagicMock()

        args = ('1', )
        regex = "Could not locate object: 1"
        self.assertRaisesRegexp(
            exceptions.ItemNotFound,
            regex,
            e._get_object_type,
            *args
        )
        e._data_session.commit()
        e._logger.warning.assert_called_once_with(
            "Could not identify object type for object: 1"
        )
        self.assertTrue(e._logger.exception.called)

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

        self.assertRaisesRegexp(
            exceptions.InvalidField,
            regex,
            e._get_object_type,
            *args
        )
        e._data_session.commit()

    def test_is_object_exists(self):
        """
        Test help method to check if object with the given OID
        exists
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._logger = mock.MagicMock()

        obj_a = pie_objects.OpaqueObject(b'', enums.OpaqueDataType.NONE)

        e._data_session.add(obj_a)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        id_a = str(obj_a.unique_identifier)
        id_b = str(obj_a.unique_identifier + 1)
        a_exists = e._is_object_exists(id_a)
        b_exists = e._is_object_exists(id_b)
        self.assertTrue(a_exists)
        self.assertFalse(b_exists)

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
            enums.CertificateTypeEnum.X_509,
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
            exceptions.IndexOutOfBounds,
            regex,
            e._process_template_attribute,
            *args
        )

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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
            exceptions.InvalidField,
            regex,
            e._set_attribute_on_managed_object,
            *args
        )

    def test_set_link_for_cryptographic_object(self):
        """
        Test that link can be set for CryptographicObject
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._logger = mock.MagicMock()

        dummy_key_args = (
            enums.CryptographicAlgorithm.RSA,
            0,
            b'',
            enums.KeyFormatType.RAW
        )
        public_key = pie_objects.PublicKey(*dummy_key_args)
        private_key = pie_objects.PrivateKey(*dummy_key_args)

        e._data_session.add_all([public_key, private_key])
        e._data_session.commit()

        attribute_factory = factory.AttributeFactory()
        ln_pubkey = attribute_factory.create_attribute(
                enums.AttributeType.LINK,
                [
                    enums.LinkType.PUBLIC_KEY_LINK,
                    public_key.unique_identifier
                ])
        private_key_attributes = {
            ln_pubkey.attribute_name.value: ln_pubkey.attribute_value
        }

        e._set_attributes_on_managed_object(
            private_key,
            private_key_attributes
        )

        self.assertIn(
            ln_pubkey.attribute_value,
            private_key.links
        )

    def test_set_link_for_non_cryptographic_object(self):
        """
        Test that error generated when trying to set link for non
        Cryptographic Object.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._logger = mock.MagicMock()

        opaque_obj = pie_objects.OpaqueObject(b'', enums.OpaqueDataType.NONE)
        public_key = pie_objects.PublicKey(
            enums.CryptographicAlgorithm.RSA,
            0,
            b'',
            enums.KeyFormatType.RAW
        )

        e._data_session.add_all([opaque_obj, public_key])
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        attribute_factory = factory.AttributeFactory()
        ln_pubkey = attribute_factory.create_attribute(
                enums.AttributeType.LINK,
                [
                    enums.LinkType.PUBLIC_KEY_LINK,
                    public_key.unique_identifier
                ])
        attribute = {
            ln_pubkey.attribute_name.value: ln_pubkey.attribute_value
        }

        args = (opaque_obj, attribute)
        regex = "Link attribute not supported by {0} object".format(
            opaque_obj.object_type.name)
        self.assertRaisesRegexp(
            exceptions.OperationNotSupported,
            regex,
            e._set_attributes_on_managed_object,
            *args
        )
        self.assertRaisesRegexp(
            exceptions.OperationNotSupported,
            regex,
            e._set_links,
            opaque_obj
        )
        self.assertRaisesRegexp(
            exceptions.OperationNotSupported,
            regex,
            e._set_links_for_certificate,
            opaque_obj
        )

    def test_set_non_existing_link(self):
        """
        Test that an error is generated when trying to link CryptographicObject
        with the non-existing object
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._logger = mock.MagicMock()

        non_existing_oid = "4321"
        dummy_key_args = (
            enums.CryptographicAlgorithm.RSA,
            0,
            b'',
            enums.KeyFormatType.RAW
        )
        private_key = pie_objects.PrivateKey(*dummy_key_args)

        e._data_session.add(private_key)
        e._data_session.commit()

        attribute_factory = factory.AttributeFactory()
        ln_pubkey = attribute_factory.create_attribute(
                enums.AttributeType.LINK,
                [
                    enums.LinkType.PUBLIC_KEY_LINK,
                    non_existing_oid
                ])
        private_key_attributes = {
            ln_pubkey.attribute_name.value: ln_pubkey.attribute_value
        }

        args = (private_key, private_key_attributes)
        regex = "Trying to link non-existing object {0}".format(
            non_existing_oid)
        self.assertRaisesRegexp(
            exceptions.InvalidField,
            regex,
            e._set_attributes_on_managed_object,
            *args
        )

    def test_second_link_of_the_same_type(self):
        """
        Test that an error is generated when trying to set two links of
        the same type
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._logger = mock.MagicMock()
        attribute_factory = factory.AttributeFactory()
        dummy_key_args = (
            enums.CryptographicAlgorithm.RSA,
            0,
            b'',
            enums.KeyFormatType.RAW
        )

        private_key = pie_objects.PrivateKey(*dummy_key_args)
        public_key = pie_objects.PublicKey(*dummy_key_args)
        public_key_bis = pie_objects.PublicKey(*dummy_key_args)

        e._data_session.add_all([
            private_key,
            public_key,
            public_key_bis])
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        ln_pubkey = attribute_factory.create_attribute(
                enums.AttributeType.LINK,
                [
                    enums.LinkType.PUBLIC_KEY_LINK,
                    public_key.unique_identifier
                ])
        private_key_attributes = {
            ln_pubkey.attribute_name.value: ln_pubkey.attribute_value
        }
        e._set_attributes_on_managed_object(
            private_key,
            private_key_attributes
        )
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        ln_pubkey_bis = attribute_factory.create_attribute(
                enums.AttributeType.LINK,
                [
                    enums.LinkType.PUBLIC_KEY_LINK,
                    public_key_bis.unique_identifier
                ])
        private_key_attributes = {
            ln_pubkey_bis.attribute_name.value: ln_pubkey_bis.attribute_value
        }

        args = (private_key, private_key_attributes)
        regex = "Only one {0} link allowed".format(
            enums.LinkType.PUBLIC_KEY_LINK)
        self.assertRaisesRegexp(
            exceptions.InvalidField,
            regex,
            e._set_attributes_on_managed_object,
            *args
        )

    def test_server_sets_certificate_links(self):
        """
        Test that link to public key created when registering certificate to
        repository that already contains public key correspinding
        to certificate.
        """
        blob_pubkey = (
            b'\x30\x5C\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05'
            b'\x00\x03\x4B\x00\x30\x48\x02\x41\x00\x91\xFA\xEC\x70\xC7\x04\x6F'
            b'\xF2\x63\xA2\xB6\x12\x90\x02\x89\x95\x13\x81\x7C\xC0\xCC\xE3\x7D'
            b'\x30\xF7\xDD\xF2\x34\x44\x9F\xBD\x03\xB9\x92\x01\xCD\x9A\x08\x26'
            b'\x51\xAC\x84\xEA\x88\x25\x51\x04\xCB\xBE\xCC\xD6\xFB\x1A\x4D\xD9'
            b'\xFB\x1C\xCF\x21\x3F\xED\xEE\xCC\xE7\x02\x03\x01\x00\x01')
        blob_cert = (
            b'\x30\x82\x01\xDD\x30\x82\x01\x87\xA0\x03\x02\x01\x02\x02\x09\x00'
            b'\xE7\x14\xF1\x22\x0A\x07\x85\x15\x30\x0D\x06\x09\x2A\x86\x48\x86'
            b'\xF7\x0D\x01\x01\x0B\x05\x00\x30\x4A\x31\x0D\x30\x0B\x06\x03\x55'
            b'\x04\x0A\x0C\x04\x4B\x4D\x49\x50\x31\x16\x30\x14\x06\x03\x55\x04'
            b'\x0B\x0C\x0D\x43\x72\x79\x70\x74\x6F\x20\x45\x6E\x67\x69\x6E\x65'
            b'\x31\x21\x30\x1F\x06\x03\x55\x04\x03\x0C\x18\x54\x65\x73\x74\x20'
            b'\x58\x35\x30\x39\x5F\x67\x65\x74\x5F\x70\x75\x62\x6C\x69\x63\x5F'
            b'\x6B\x65\x79\x30\x1E\x17\x0D\x31\x36\x30\x35\x31\x38\x30\x36\x35'
            b'\x31\x34\x36\x5A\x17\x0D\x31\x38\x30\x35\x30\x38\x30\x36\x35\x31'
            b'\x34\x36\x5A\x30\x4A\x31\x0D\x30\x0B\x06\x03\x55\x04\x0A\x0C\x04'
            b'\x4B\x4D\x49\x50\x31\x16\x30\x14\x06\x03\x55\x04\x0B\x0C\x0D\x43'
            b'\x72\x79\x70\x74\x6F\x20\x45\x6E\x67\x69\x6E\x65\x31\x21\x30\x1F'
            b'\x06\x03\x55\x04\x03\x0C\x18\x54\x65\x73\x74\x20\x58\x35\x30\x39'
            b'\x5F\x67\x65\x74\x5F\x70\x75\x62\x6C\x69\x63\x5F\x6B\x65\x79\x30'
            b'\x5C\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00'
            b'\x03\x4B\x00\x30\x48\x02\x41\x00\x91\xFA\xEC\x70\xC7\x04\x6F\xF2'
            b'\x63\xA2\xB6\x12\x90\x02\x89\x95\x13\x81\x7C\xC0\xCC\xE3\x7D\x30'
            b'\xF7\xDD\xF2\x34\x44\x9F\xBD\x03\xB9\x92\x01\xCD\x9A\x08\x26\x51'
            b'\xAC\x84\xEA\x88\x25\x51\x04\xCB\xBE\xCC\xD6\xFB\x1A\x4D\xD9\xFB'
            b'\x1C\xCF\x21\x3F\xED\xEE\xCC\xE7\x02\x03\x01\x00\x01\xA3\x50\x30'
            b'\x4E\x30\x1D\x06\x03\x55\x1D\x0E\x04\x16\x04\x14\x43\xE1\x07\xF3'
            b'\xB0\x58\x48\x1B\x18\x45\x2A\x86\x23\x14\x92\x19\x8C\xA8\x2C\xB7'
            b'\x30\x1F\x06\x03\x55\x1D\x23\x04\x18\x30\x16\x80\x14\x43\xE1\x07'
            b'\xF3\xB0\x58\x48\x1B\x18\x45\x2A\x86\x23\x14\x92\x19\x8C\xA8\x2C'
            b'\xB7\x30\x0C\x06\x03\x55\x1D\x13\x04\x05\x30\x03\x01\x01\xFF\x30'
            b'\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0B\x05\x00\x03\x41'
            b'\x00\x6F\xDD\xAE\x28\x2F\x65\x09\x7B\xE7\xD8\xA7\x00\x18\x14\xEB'
            b'\x9A\xE7\x14\xEA\xE9\x45\x2A\x8F\xF6\xCB\x6F\xDC\x2C\x17\x20\x7C'
            b'\xF8\x49\x12\x83\x91\xEA\x57\xAC\x8C\x2A\x3A\xF3\xCC\xB2\x39\xB2'
            b'\x3B\x22\x17\x80\xFB\x55\x6E\x44\xB0\x89\x45\x12\xAF\xEE\xB2\x2F'
            b'\xD6'
        )
        blob_cert_bis = (
            b'\x30\x82\x01\xC1\x30\x82\x01\x6B\xA0\x03\x02\x01\x02\x02\x09\x00'
            b'\xF4\x3C\x01\x8F\xA4\xD4\x9E\x82\x30\x0D\x06\x09\x2A\x86\x48\x86'
            b'\xF7\x0D\x01\x01\x0B\x05\x00\x30\x3C\x31\x0D\x30\x0B\x06\x03\x55'
            b'\x04\x0A\x0C\x04\x4B\x4D\x49\x50\x31\x13\x30\x11\x06\x03\x55\x04'
            b'\x0B\x0C\x0A\x55\x6E\x69\x74\x20\x54\x65\x73\x74\x73\x31\x16\x30'
            b'\x14\x06\x03\x55\x04\x03\x0C\x0D\x53\x65\x72\x76\x65\x72\x20\x45'
            b'\x6E\x67\x69\x6E\x65\x30\x1E\x17\x0D\x31\x36\x30\x35\x31\x38\x31'
            b'\x33\x33\x32\x32\x35\x5A\x17\x0D\x31\x38\x30\x35\x30\x38\x31\x33'
            b'\x33\x32\x32\x35\x5A\x30\x3C\x31\x0D\x30\x0B\x06\x03\x55\x04\x0A'
            b'\x0C\x04\x4B\x4D\x49\x50\x31\x13\x30\x11\x06\x03\x55\x04\x0B\x0C'
            b'\x0A\x55\x6E\x69\x74\x20\x54\x65\x73\x74\x73\x31\x16\x30\x14\x06'
            b'\x03\x55\x04\x03\x0C\x0D\x53\x65\x72\x76\x65\x72\x20\x45\x6E\x67'
            b'\x69\x6E\x65\x30\x5C\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01'
            b'\x01\x01\x05\x00\x03\x4B\x00\x30\x48\x02\x41\x00\xBB\x6B\xBE\x85'
            b'\xA8\x73\x22\xDB\x4D\x94\x7E\x81\x42\x6E\x6D\x42\x31\x98\x0C\xEE'
            b'\x8C\x9E\x15\x0A\x69\x96\x94\xF2\x97\xD0\x3F\xF7\x8F\x69\x2A\x78'
            b'\x3E\x0A\x13\x1A\xDD\xAA\x03\x05\xF5\x92\xCA\xF5\x30\xEA\x49\x8E'
            b'\xD7\x86\x04\x2B\xEF\xE1\xEB\x9D\x4D\x61\x2A\x6F\x02\x03\x01\x00'
            b'\x01\xA3\x50\x30\x4E\x30\x1D\x06\x03\x55\x1D\x0E\x04\x16\x04\x14'
            b'\x5A\x31\x08\x82\x6A\xBE\x02\x38\x39\xE1\x24\x3B\x92\x95\xF3\xE8'
            b'\xB4\x0B\x78\x9D\x30\x1F\x06\x03\x55\x1D\x23\x04\x18\x30\x16\x80'
            b'\x14\x5A\x31\x08\x82\x6A\xBE\x02\x38\x39\xE1\x24\x3B\x92\x95\xF3'
            b'\xE8\xB4\x0B\x78\x9D\x30\x0C\x06\x03\x55\x1D\x13\x04\x05\x30\x03'
            b'\x01\x01\xFF\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0B'
            b'\x05\x00\x03\x41\x00\x22\xE9\xD7\xD0\xC2\x22\xAE\x9D\x85\x86\x79'
            b'\x5A\x63\x05\x4B\x18\x98\xB6\x98\xB6\x08\xBB\xCB\xC5\x7E\xF9\xF0'
            b'\x14\xF7\x6E\xA0\x01\x58\x04\x79\xF0\x1D\x19\x9D\xA7\x66\x48\xFB'
            b'\x87\xAD\x2A\xCD\x19\xCF\xCA\xEE\x9A\xB9\x52\xF1\x71\xFD\x7E\xD2'
            b'\xE1\xBC\x4E\x78\xD9'
        )

        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._logger = mock.MagicMock()
        attribute_factory = factory.AttributeFactory()

        cert = pie_objects.X509Certificate(blob_cert)
        cert_bis = pie_objects.X509Certificate(blob_cert_bis)
        public_key = pie_objects.PublicKey(
            enums.CryptographicAlgorithm.RSA,
            512,
            blob_pubkey,
            enums.KeyFormatType.PKCS_1)

        e._data_session.add_all([public_key, cert])
        e._data_session.commit()

        # re-instantiate 'cert' object that
        # supposed to be expired after session commit
        cert_oid = cert.unique_identifier
        cert = e._data_session.query(
            pie_objects.X509Certificate
        ).filter(
            pie_objects.ManagedObject.unique_identifier == cert_oid
        ).one()

        ln_pubkey = attribute_factory.create_attribute(
            enums.AttributeType.LINK,
            [
                enums.LinkType.PUBLIC_KEY_LINK,
                public_key.unique_identifier
            ])
        cert_attributes = {
            ln_pubkey.attribute_name.value: ln_pubkey.attribute_value
        }

        # Let server set certificate attributes
        e._set_links(cert)
        self.assertEqual(1, len(cert.links))
        self.assertIn(ln_pubkey.attribute_value, cert.links)

        # Next call is silently ignored
        e._set_links(cert)
        self.assertEqual(1, len(cert.links))
        self.assertIn(ln_pubkey.attribute_value, cert.links)

        # Try to set the same attribute,
        # check that there is still only one link to public key
        e._set_attributes_on_managed_object(
            cert,
            cert_attributes
        )
        self.assertEqual(1, len(cert.links))
        self.assertIn(ln_pubkey.attribute_value, cert.links)

        # Let server set certificate attributes for which there is no
        # corresponding public key in repository
        e._set_links(cert_bis)
        self.assertEqual(0, len(cert_bis.links))

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
                )
            ]
        )
        payload = create.CreateRequestPayload(
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
        payload = create.CreateRequestPayload(
            object_type
        )

        args = (payload, )
        regex = "Cannot create a PublicKey object with the Create operation."
        self.assertRaisesRegexp(
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
        payload = create.CreateRequestPayload(
            object_type,
            template_attribute
        )

        args = (payload, )
        regex = (
            "The cryptographic algorithm must be specified as an attribute."
        )
        self.assertRaisesRegexp(
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
        payload = create.CreateRequestPayload(
            object_type,
            template_attribute
        )

        args = (payload, )
        regex = (
            "The cryptographic length must be specified as an attribute."
        )
        self.assertRaisesRegexp(
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
        payload = create.CreateRequestPayload(
            object_type,
            template_attribute
        )

        args = (payload, )
        regex = (
            "The cryptographic usage mask must be specified as an attribute."
        )
        self.assertRaisesRegexp(
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
        payload = create_key_pair.CreateKeyPairRequestPayload(
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

        # verify link to private key object
        self.assertEqual(1, len(public_key.links))
        link = public_key.links[0]
        self.assertIsInstance(link, attributes.Link)
        self.assertEqual(
            link.link_type,
            attributes.Link.LinkType(enums.LinkType.PRIVATE_KEY_LINK))
        self.assertEqual(
            link.linked_oid,
            attributes.Link.LinkedObjectID(private_id))

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

        self.assertEqual(private_id, e._id_placeholder)

        # verify link to public key object
        self.assertEqual(1, len(private_key.links))
        link = private_key.links[0]
        self.assertIsInstance(link, attributes.Link)
        self.assertEqual(
            link.link_type,
            attributes.Link.LinkType(enums.LinkType.PUBLIC_KEY_LINK))
        self.assertEqual(
            link.linked_oid,
            attributes.Link.LinkedObjectID(public_id))

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
        payload = create_key_pair.CreateKeyPairRequestPayload(
            common_template,
            private_template,
            public_template
        )

        args = (payload, )
        regex = (
            "The cryptographic algorithm must be specified as an attribute "
            "for the public key."
        )
        self.assertRaisesRegexp(
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
        payload = create_key_pair.CreateKeyPairRequestPayload(
            common_template,
            private_template,
            public_template
        )

        args = (payload, )
        regex = (
            "The cryptographic algorithm must be specified as an attribute "
            "for the private key."
        )
        self.assertRaisesRegexp(
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
        payload = create_key_pair.CreateKeyPairRequestPayload(
            common_template,
            private_template,
            public_template
        )

        args = (payload, )
        regex = (
            "The cryptographic length must be specified as an attribute for "
            "the public key."
        )
        self.assertRaisesRegexp(
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
        payload = create_key_pair.CreateKeyPairRequestPayload(
            common_template,
            private_template,
            public_template
        )

        args = (payload, )
        regex = (
            "The cryptographic length must be specified as an attribute for "
            "the private key."
        )
        self.assertRaisesRegexp(
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
        payload = create_key_pair.CreateKeyPairRequestPayload(
            common_template,
            private_template,
            public_template
        )

        args = (payload, )
        regex = (
            "The cryptographic usage mask must be specified as an attribute "
            "for the public key."
        )
        self.assertRaisesRegexp(
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
        payload = create_key_pair.CreateKeyPairRequestPayload(
            common_template,
            private_template,
            public_template
        )

        args = (payload, )
        regex = (
            "The cryptographic usage mask must be specified as an attribute "
            "for the private key."
        )
        self.assertRaisesRegexp(
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
        payload = create_key_pair.CreateKeyPairRequestPayload(
            common_template,
            private_template,
            public_template
        )

        args = (payload, )
        regex = (
            "The public and private key algorithms must be the same."
        )
        self.assertRaisesRegexp(
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
        payload = create_key_pair.CreateKeyPairRequestPayload(
            common_template,
            private_template,
            public_template
        )

        args = (payload, )
        regex = (
            "The public and private key lengths must be the same."
        )
        self.assertRaisesRegexp(
            exceptions.InvalidField,
            regex,
            e._process_create_key_pair,
            *args
        )
        e._logger.info.assert_any_call(
            "Processing operation: CreateKeyPair"
        )
        e._logger.reset_mock()

    def test_only_one_link_of_given_type(self):
        """
        Test that crypto-object can hold only one link of given type.
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
                        'Test Uniqueness of link',
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
        payload = create_key_pair.CreateKeyPairRequestPayload(
            common_template,
            private_template,
            public_template
        )

        response_payload = e._process_create_key_pair(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        private_id = response_payload.private_key_uuid.value

        # Retrieve the stored private key and verify all attributes were set
        # appropriately.
        private_key = e._data_session.query(
            pie_objects.PrivateKey
        ).filter(
            pie_objects.ManagedObject.unique_identifier == private_id
        ).one()

        attribute_factory = factory.AttributeFactory()
        link = attribute_factory.create_attribute(
            enums.AttributeType.LINK,
            [
                enums.LinkType.PUBLIC_KEY_LINK,
                '4321'
            ])
        private_key_server_attributes = {
            link.attribute_name.value: link.attribute_value
        }

        args = (private_key, private_key_server_attributes)
        regex = "Only one LinkType.PUBLIC_KEY_LINK link allowed"
        self.assertRaisesRegexp(
            exceptions.InvalidField,
            regex,
            e._set_attributes_on_managed_object,
            *args
        )

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

        payload = register.RegisterRequestPayload(
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
        payload = register.RegisterRequestPayload(object_type=object_type)

        args = (payload, )
        regex = "The SplitKey object type is not supported."
        self.assertRaisesRegexp(
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
        payload = register.RegisterRequestPayload(object_type=object_type)

        args = (payload, )
        regex = "Cannot register a secret in absentia."
        self.assertRaisesRegexp(
            exceptions.InvalidField,
            regex,
            e._process_register,
            *args
        )

    def test_get(self):
        """
        Test that a Get request can be processed correctly.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
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
        payload = get.GetRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(id_a)
        )

        response_payload = e._process_get(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Get"
        )
        self.assertEqual(
            enums.ObjectType.OPAQUE_DATA,
            response_payload.object_type.value
        )
        self.assertEqual(str(id_a), response_payload.unique_identifier.value)
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
        payload = get.GetRequestPayload()

        response_payload = e._process_get(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Get"
        )
        self.assertEqual(
            enums.ObjectType.OPAQUE_DATA,
            response_payload.object_type.value
        )
        self.assertEqual(str(id_b), response_payload.unique_identifier.value)
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

    def test_get_with_unsupported_features(self):
        """
        Test that the right errors are generated when unsupported features
        are used in a Get request.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._logger = mock.MagicMock()

        # Test that specifying the key compression type generates an error.
        payload = get.GetRequestPayload(
            key_compression_type=get.GetRequestPayload.KeyCompressionType(
                enums.KeyCompressionType.EC_PUBLIC_KEY_TYPE_UNCOMPRESSED
            )
        )

        args = (payload, )
        regex = "Key compression is not supported."
        self.assertRaisesRegexp(
            exceptions.KeyCompressionTypeNotSupported,
            regex,
            e._process_get,
            *args
        )
        e._logger.info.assert_any_call(
            "Processing operation: Get"
        )

        e._logger.reset_mock()

        # Test that specifying the key wrapping specification generates an
        # error.
        payload = get.GetRequestPayload(
            key_wrapping_specification=objects.KeyWrappingSpecification()
        )

        args = (payload, )
        regex = "Key wrapping is not supported."
        self.assertRaisesRegexp(
            exceptions.PermissionDenied,
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
        payload = get.GetRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(id_a),
            key_format_type=get.GetRequestPayload.KeyFormatType(
                enums.KeyFormatType.RAW
            )
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

        payload = get.GetRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(id_a),
            key_format_type=get.GetRequestPayload.KeyFormatType(
                enums.KeyFormatType.OPAQUE
            )
        )

        args = (payload, )
        regex = "Key format conversion from RAW to OPAQUE is unsupported."
        self.assertRaisesRegexp(
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

        payload = get.GetRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(id_b),
            key_format_type=get.GetRequestPayload.KeyFormatType(
                enums.KeyFormatType.RAW
            )
        )

        args = (payload, )
        regex = "Key format is not applicable to the specified object."
        self.assertRaisesRegexp(
            exceptions.KeyFormatTypeNotSupported,
            regex,
            e._process_get,
            *args
        )
        e._logger.info.assert_any_call(
            "Processing operation: Get"
        )

    def test_destroy(self):
        """
        Test that a Destroy request can be processed correctly.
        """
        e = engine.KmipEngine()
        e._data_store = self.engine
        e._data_store_session_factory = self.session_factory
        e._data_session = e._data_store_session_factory()
        e._logger = mock.MagicMock()

        obj_a = pie_objects.OpaqueObject(b'', enums.OpaqueDataType.NONE)
        obj_b = pie_objects.OpaqueObject(b'', enums.OpaqueDataType.NONE)

        e._data_session.add(obj_a)
        e._data_session.add(obj_b)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        id_a = str(obj_a.unique_identifier)
        id_b = str(obj_b.unique_identifier)

        # Test by specifying the ID of the object to destroy.
        payload = destroy.DestroyRequestPayload(
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
        self.assertRaisesRegexp(
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
        payload = destroy.DestroyRequestPayload()

        response_payload = e._process_destroy(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Destroy"
        )
        self.assertEqual(str(id_b), response_payload.unique_identifier.value)

        args = (payload, )
        regex = "Could not locate object: {0}".format(id_b)
        self.assertRaisesRegexp(
            exceptions.ItemNotFound,
            regex,
            e._process_destroy,
            *args
        )

        e._data_session.commit()

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
        self.assertEqual(6, len(result.operations))
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
            enums.Operation.GET,
            result.operations[3].value
        )
        self.assertEqual(
            enums.Operation.DESTROY,
            result.operations[4].value
        )
        self.assertEqual(
            enums.Operation.QUERY,
            result.operations[5].value
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

        # Test for KMIP 1.1.
        e._logger = mock.MagicMock()
        e._protocol_version = contents.ProtocolVersion.create(1, 1)

        result = e._process_query(payload)

        e._logger.info.assert_called_once_with("Processing operation: Query")
        self.assertIsNotNone(result.operations)
        self.assertEqual(7, len(result.operations))
        self.assertEqual(
            enums.Operation.DISCOVER_VERSIONS,
            result.operations[-1].value
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

    def test_create_get_destroy(self):
        """
        Test that a managed object can be created, retrieved, and destroyed
        without error.
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
        payload = create.CreateRequestPayload(
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
        payload = get.GetRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(uid)
        )

        response_payload = e._process_get(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Get"
        )
        self.assertEqual(
            enums.ObjectType.SYMMETRIC_KEY,
            response_payload.object_type.value
        )
        self.assertEqual(str(uid), response_payload.unique_identifier.value)
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
        payload = destroy.DestroyRequestPayload(
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
        self.assertRaisesRegexp(
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
        payload = create_key_pair.CreateKeyPairRequestPayload(
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
        payload = get.GetRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(public_id)
        )

        response_payload = e._process_get(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Get"
        )
        self.assertEqual(
            enums.ObjectType.PUBLIC_KEY,
            response_payload.object_type.value
        )
        self.assertEqual(
            str(public_id),
            response_payload.unique_identifier.value
        )
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
        payload = get.GetRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(private_id)
        )

        response_payload = e._process_get(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Get"
        )
        self.assertEqual(
            enums.ObjectType.PRIVATE_KEY,
            response_payload.object_type.value
        )
        self.assertEqual(
            str(private_id),
            response_payload.unique_identifier.value
        )
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
        payload = destroy.DestroyRequestPayload(
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
        self.assertRaisesRegexp(
            exceptions.ItemNotFound,
            regex,
            e._process_destroy,
            *args
        )

        e._data_session.commit()
        e._data_store_session_factory()
        e._logger.reset_mock()

        # Destroy the private key and verify it cannot be accessed again
        payload = destroy.DestroyRequestPayload(
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
        self.assertRaisesRegexp(
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
        payload = register.RegisterRequestPayload(
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
        payload = get.GetRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(uid)
        )

        response_payload = e._process_get(payload)
        e._data_session.commit()
        e._data_session = e._data_store_session_factory()

        e._logger.info.assert_any_call(
            "Processing operation: Get"
        )
        self.assertEqual(
            enums.ObjectType.SYMMETRIC_KEY,
            response_payload.object_type.value
        )
        self.assertEqual(str(uid), response_payload.unique_identifier.value)
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
        payload = destroy.DestroyRequestPayload(
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
        self.assertRaisesRegexp(
            exceptions.ItemNotFound,
            regex,
            e._process_destroy,
            *args
        )

        e._data_session.commit()
        e._data_store_session_factory()
