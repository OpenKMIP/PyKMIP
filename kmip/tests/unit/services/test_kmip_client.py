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

from testtools import TestCase

from kmip.core.attributes import CryptographicParameters
from kmip.core.attributes import DerivationParameters
from kmip.core.attributes import PrivateKeyUniqueIdentifier

from kmip.core import enums
from kmip.core.enums import AuthenticationSuite
from kmip.core.enums import ConformanceClause
from kmip.core.enums import CredentialType
from kmip.core.enums import ResultStatus as ResultStatusEnum
from kmip.core.enums import ResultReason as ResultReasonEnum
from kmip.core.enums import Operation as OperationEnum
from kmip.core.enums import QueryFunction as QueryFunctionEnum
from kmip.core.enums import CryptographicAlgorithm as \
                            CryptographicAlgorithmEnum

from kmip.core import exceptions

from kmip.core.factories.attributes import AttributeFactory
from kmip.core.factories.credentials import CredentialFactory
from kmip.core.factories.secrets import SecretFactory

from kmip.core.messages.messages import RequestBatchItem
from kmip.core.messages.messages import ResponseBatchItem
from kmip.core.messages.messages import ResponseMessage
from kmip.core.messages.contents import Operation
from kmip.core.messages.contents import ResultStatus
from kmip.core.messages.contents import ResultReason
from kmip.core.messages.contents import ResultMessage
from kmip.core.messages.contents import ProtocolVersion
from kmip.core.messages import payloads

from kmip.core.misc import Offset
from kmip.core.misc import ServerInformation

from kmip.core import objects
from kmip.core.objects import TemplateAttribute
from kmip.core.objects import CommonTemplateAttribute
from kmip.core.objects import PrivateKeyTemplateAttribute
from kmip.core.objects import PublicKeyTemplateAttribute
from kmip.core import primitives

from kmip.services.kmip_client import KMIPProxy

from kmip.services.results import CreateKeyPairResult
from kmip.services.results import DiscoverVersionsResult
from kmip.services.results import GetAttributesResult
from kmip.services.results import GetAttributeListResult
from kmip.services.results import OperationResult
from kmip.services.results import QueryResult
from kmip.services.results import RekeyKeyPairResult

import mock
import os
import socket
import ssl


class TestKMIPClient(TestCase):

    def setUp(self):
        super(TestKMIPClient, self).setUp()

        self.attr_factory = AttributeFactory()
        self.cred_factory = CredentialFactory()
        self.secret_factory = SecretFactory()

        self.client = KMIPProxy(config_file="/dev/null")

        KMIP_PORT = 9090
        CA_CERTS_PATH = os.path.normpath(os.path.join(os.path.dirname(
            os.path.abspath(__file__)), '../utils/certs/server.crt'))

        self.mock_client = KMIPProxy(host="IP_ADDR_1, IP_ADDR_2",
                                     port=KMIP_PORT, ca_certs=CA_CERTS_PATH)
        self.mock_client.socket = mock.MagicMock()
        self.mock_client.socket.connect = mock.MagicMock()
        self.mock_client.socket.close = mock.MagicMock()

    def tearDown(self):
        super(TestKMIPClient, self).tearDown()

    def test_kmip_version_get(self):
        """
        Test that the KMIP version can be obtained from the client.
        """
        client = KMIPProxy()
        self.assertEqual(client.kmip_version, enums.KMIPVersion.KMIP_1_2)

    def test_kmip_version_set(self):
        """
        Test that the KMIP version of the client can be set to a new value.
        """
        client = KMIPProxy()
        self.assertEqual(client.kmip_version, enums.KMIPVersion.KMIP_1_2)
        client.kmip_version = enums.KMIPVersion.KMIP_1_1
        self.assertEqual(client.kmip_version, enums.KMIPVersion.KMIP_1_1)

    def test_kmip_version_set_error(self):
        """
        Test that the right error gets raised when setting the client KMIP
        version with an invalid value.
        """
        client = KMIPProxy()
        args = (client, "kmip_version", None)
        self.assertRaisesRegex(
            ValueError,
            "KMIP version must be a KMIPVersion enumeration",
            setattr,
            *args
        )

    def test_init_with_invalid_config_file_value(self):
        """
        Test that the right error is raised when an invalid configuration file
        value is provided to the client.
        """
        kwargs = {'config_file': 1}
        self.assertRaisesRegex(
            ValueError,
            "The client configuration file argument must be a string.",
            KMIPProxy,
            **kwargs
        )

    def test_init_with_invalid_config_file_path(self):
        """
        Test that the right error is raised when an invalid configuration file
        path is provided to the client.
        """
        kwargs = {'config_file': 'invalid'}
        self.assertRaisesRegex(
            ValueError,
            "The client configuration file 'invalid' does not exist.",
            KMIPProxy,
            **kwargs
        )

    def test_close(self):
        """
        Test that calling close on the client works as expected.
        """
        c = KMIPProxy(
            host="IP_ADDR_1, IP_ADDR_2",
            port=9090,
            ca_certs=None
        )
        c.socket = mock.MagicMock()
        c_socket = c.socket

        c.socket.shutdown.assert_not_called()
        c.socket.close.assert_not_called()

        c.close()

        self.assertEqual(None, c.socket)
        c_socket.shutdown.assert_called_once_with(socket.SHUT_RDWR)
        c_socket.close.assert_called_once()

    def test_close_with_shutdown_error(self):
        """
        Test that calling close on an unconnected client does not trigger an
        exception.
        """
        c = KMIPProxy(
            host="IP_ADDR_1, IP_ADDR_2",
            port=9090,
            ca_certs=None
        )
        c.socket = mock.MagicMock()
        c_socket = c.socket
        c.socket.shutdown.side_effect = OSError

        c.socket.shutdown.assert_not_called()
        c.socket.close.assert_not_called()

        c.close()

        self.assertEqual(None, c.socket)
        c_socket.shutdown.assert_called_once_with(socket.SHUT_RDWR)
        c_socket.close.assert_not_called()

    # TODO (peter-hamilton) Modify for credential type and/or add new test
    def test_build_credential(self):
        username = 'username'
        password = 'password'
        self.client.username = username
        self.client.password = password

        credential = self.client._build_credential()

        self.assertEqual(
            CredentialType.USERNAME_AND_PASSWORD,
            credential.credential_type
        )
        self.assertEqual(username, credential.credential_value.username)
        self.assertEqual(password, credential.credential_value.password)

    def test_build_credential_no_username(self):
        username = None
        password = 'password'
        self.client.username = username
        self.client.password = password

        exception = self.assertRaises(ValueError,
                                      self.client._build_credential)
        self.assertEqual('cannot build credential, username is None',
                         str(exception))

    def test_build_credential_no_password(self):
        username = 'username'
        password = None
        self.client.username = username
        self.client.password = password

        exception = self.assertRaises(ValueError,
                                      self.client._build_credential)
        self.assertEqual('cannot build credential, password is None',
                         str(exception))

    def test_build_credential_no_creds(self):
        self.client.username = None
        self.client.password = None

        credential = self.client._build_credential()

        self.assertEqual(None, credential)

    def _test_build_create_key_pair_batch_item(self, common, private, public):
        batch_item = self.client._build_create_key_pair_batch_item(
            common_template_attribute=common,
            private_key_template_attribute=private,
            public_key_template_attribute=public)

        base = "expected {0}, received {1}"
        msg = base.format(RequestBatchItem, batch_item)
        self.assertIsInstance(batch_item, RequestBatchItem, msg)

        operation = batch_item.operation

        msg = base.format(Operation, operation)
        self.assertIsInstance(operation, Operation, msg)

        operation_enum = operation.value

        msg = base.format(OperationEnum.CREATE_KEY_PAIR, operation_enum)
        self.assertEqual(OperationEnum.CREATE_KEY_PAIR, operation_enum, msg)

        payload = batch_item.request_payload

        msg = base.format(payloads.CreateKeyPairRequestPayload, payload)
        self.assertIsInstance(
            payload,
            payloads.CreateKeyPairRequestPayload,
            msg
        )

        common_observed = payload.common_template_attribute
        private_observed = payload.private_key_template_attribute
        public_observed = payload.public_key_template_attribute

        msg = base.format(common, common_observed)
        self.assertEqual(common, common_observed, msg)

        msg = base.format(private, private_observed)
        self.assertEqual(private, private_observed, msg)

        msg = base.format(public, public_observed)
        self.assertEqual(public, public_observed)

    def test_build_create_key_pair_batch_item_with_input(self):
        self._test_build_create_key_pair_batch_item(
            CommonTemplateAttribute(),
            PrivateKeyTemplateAttribute(),
            PublicKeyTemplateAttribute())

    def test_build_create_key_pair_batch_item_no_input(self):
        self._test_build_create_key_pair_batch_item(None, None, None)

    def _test_build_rekey_key_pair_batch_item(self, uuid, offset, common,
                                              private, public):
        batch_item = self.client._build_rekey_key_pair_batch_item(
            private_key_uuid=uuid, offset=offset,
            common_template_attribute=common,
            private_key_template_attribute=private,
            public_key_template_attribute=public)

        base = "expected {0}, received {1}"
        msg = base.format(RequestBatchItem, batch_item)
        self.assertIsInstance(batch_item, RequestBatchItem, msg)

        operation = batch_item.operation

        msg = base.format(Operation, operation)
        self.assertIsInstance(operation, Operation, msg)

        operation_enum = operation.value

        msg = base.format(OperationEnum.REKEY_KEY_PAIR, operation_enum)
        self.assertEqual(OperationEnum.REKEY_KEY_PAIR, operation_enum, msg)

        payload = batch_item.request_payload

        msg = base.format(payloads.RekeyKeyPairRequestPayload, payload)
        self.assertIsInstance(
            payload,
            payloads.RekeyKeyPairRequestPayload,
            msg
        )

        private_key_uuid_observed = payload.private_key_uuid
        offset_observed = payload.offset
        common_observed = payload.common_template_attribute
        private_observed = payload.private_key_template_attribute
        public_observed = payload.public_key_template_attribute

        msg = base.format(uuid, private_key_uuid_observed)
        self.assertEqual(uuid, private_key_uuid_observed, msg)

        msg = base.format(offset, offset_observed)
        self.assertEqual(offset, offset_observed, msg)

        msg = base.format(common, common_observed)
        self.assertEqual(common, common_observed, msg)

        msg = base.format(private, private_observed)
        self.assertEqual(private, private_observed, msg)

        msg = base.format(public, public_observed)
        self.assertEqual(public, public_observed)

    def test_build_rekey_key_pair_batch_item_with_input(self):
        self._test_build_rekey_key_pair_batch_item(
            PrivateKeyUniqueIdentifier(), Offset(),
            CommonTemplateAttribute(),
            PrivateKeyTemplateAttribute(),
            PublicKeyTemplateAttribute())

    def test_build_rekey_key_pair_batch_item_no_input(self):
        self._test_build_rekey_key_pair_batch_item(
            None, None, None, None, None)

    def _test_build_query_batch_item(self, query_functions):
        batch_item = self.client._build_query_batch_item(query_functions)

        base = "expected {0}, received {1}"
        msg = base.format(RequestBatchItem, batch_item)
        self.assertIsInstance(batch_item, RequestBatchItem, msg)

        operation = batch_item.operation

        msg = base.format(Operation, operation)
        self.assertIsInstance(operation, Operation, msg)

        operation_enum = operation.value

        msg = base.format(OperationEnum.QUERY, operation_enum)
        self.assertEqual(OperationEnum.QUERY, operation_enum, msg)

        payload = batch_item.request_payload

        msg = base.format(payloads.QueryRequestPayload, payload)
        self.assertIsInstance(payload, payloads.QueryRequestPayload, msg)

        query_functions_observed = payload.query_functions
        self.assertEqual(query_functions, query_functions_observed)

    def test_build_query_batch_item_with_input(self):
        self._test_build_query_batch_item(
            [QueryFunctionEnum.QUERY_OBJECTS]
        )

    def test_build_query_batch_item_without_input(self):
        self._test_build_query_batch_item(None)

    def _test_build_discover_versions_batch_item(self, protocol_versions):
        batch_item = self.client._build_discover_versions_batch_item(
            protocol_versions)

        base = "expected {0}, received {1}"
        msg = base.format(RequestBatchItem, batch_item)
        self.assertIsInstance(batch_item, RequestBatchItem, msg)

        operation = batch_item.operation

        msg = base.format(Operation, operation)
        self.assertIsInstance(operation, Operation, msg)

        operation_enum = operation.value

        msg = base.format(OperationEnum.DISCOVER_VERSIONS, operation_enum)
        self.assertEqual(OperationEnum.DISCOVER_VERSIONS, operation_enum, msg)

        payload = batch_item.request_payload

        if protocol_versions is None:
            protocol_versions = list()

        msg = base.format(payloads.DiscoverVersionsRequestPayload, payload)
        self.assertIsInstance(
            payload,
            payloads.DiscoverVersionsRequestPayload,
            msg
        )

        observed = payload.protocol_versions

        msg = base.format(protocol_versions, observed)
        self.assertEqual(protocol_versions, observed, msg)

    def test_build_discover_versions_batch_item_with_input(self):
        protocol_versions = [ProtocolVersion(1, 0)]
        self._test_build_discover_versions_batch_item(protocol_versions)

    def test_build_discover_versions_batch_item_no_input(self):
        protocol_versions = None
        self._test_build_discover_versions_batch_item(protocol_versions)

    def test_build_get_attributes_batch_item(self):
        uuid = '00000000-1111-2222-3333-444444444444'
        attribute_names = [
            'Name',
            'Object Type'
        ]
        batch_item = self.client._build_get_attributes_batch_item(
            uuid,
            attribute_names
        )

        self.assertIsInstance(batch_item, RequestBatchItem)
        self.assertIsInstance(batch_item.operation, Operation)
        self.assertEqual(
            OperationEnum.GET_ATTRIBUTES,
            batch_item.operation.value
        )
        self.assertIsInstance(
            batch_item.request_payload,
            payloads.GetAttributesRequestPayload
        )
        self.assertEqual(uuid, batch_item.request_payload.unique_identifier)
        self.assertEqual(
            attribute_names,
            batch_item.request_payload.attribute_names
        )

    def test_build_get_attribute_list_batch_item(self):
        uid = '00000000-1111-2222-3333-444444444444'
        batch_item = self.client._build_get_attribute_list_batch_item(uid)

        self.assertIsInstance(batch_item, RequestBatchItem)
        self.assertIsInstance(batch_item.operation, Operation)
        self.assertEqual(
            OperationEnum.GET_ATTRIBUTE_LIST, batch_item.operation.value)
        self.assertIsInstance(
            batch_item.request_payload,
            payloads.GetAttributeListRequestPayload)
        self.assertEqual(uid, batch_item.request_payload.unique_identifier)

    def test_process_batch_items(self):
        batch_item = ResponseBatchItem(
            operation=Operation(OperationEnum.CREATE_KEY_PAIR),
            response_payload=payloads.CreateKeyPairResponsePayload())
        response = ResponseMessage(batch_items=[batch_item, batch_item])
        results = self.client._process_batch_items(response)

        base = "expected {0}, received {1}"
        msg = base.format(list, results)
        self.assertIsInstance(results, list, msg)

        msg = "number of results " + base.format(2, len(results))
        self.assertEqual(2, len(results), msg)

        for result in results:
            msg = base.format(CreateKeyPairResult, result)
            self.assertIsInstance(result, CreateKeyPairResult, msg)

    def test_process_batch_items_no_batch_items(self):
        response = ResponseMessage(batch_items=[])
        results = self.client._process_batch_items(response)

        base = "expected {0}, received {1}"
        msg = base.format(list, results)
        self.assertIsInstance(results, list, msg)

        msg = "number of results " + base.format(0, len(results))
        self.assertEqual(0, len(results), msg)

    def test_process_batch_item_with_error(self):
        result_status = ResultStatus(ResultStatusEnum.OPERATION_FAILED)
        result_reason = ResultReason(ResultReasonEnum.INVALID_MESSAGE)
        result_message = ResultMessage("message")

        batch_item = ResponseBatchItem(
            result_status=result_status,
            result_reason=result_reason,
            result_message=result_message)
        response = ResponseMessage(batch_items=[batch_item])
        results = self.client._process_batch_items(response)

        base = "expected {0}, received {1}"
        msg = "number of results " + base.format(1, len(results))
        self.assertEqual(1, len(results), msg)

        result = results[0]
        self.assertIsInstance(result, OperationResult)
        self.assertEqual(result.result_status, result_status)
        self.assertEqual(result.result_reason, result_reason)
        self.assertEqual(result.result_message.value, "message")

    def test_get_batch_item_processor(self):
        base = "expected {0}, received {1}"

        expected = self.client._process_create_key_pair_batch_item
        observed = self.client._get_batch_item_processor(
            OperationEnum.CREATE_KEY_PAIR)
        msg = base.format(expected, observed)
        self.assertEqual(expected, observed, msg)

        expected = self.client._process_rekey_key_pair_batch_item
        observed = self.client._get_batch_item_processor(
            OperationEnum.REKEY_KEY_PAIR)
        msg = base.format(expected, observed)
        self.assertEqual(expected, observed, msg)

        self.assertRaisesRegex(
            ValueError,
            "no processor for operation",
            self.client._get_batch_item_processor,
            0xA5A5A5A5
        )

        expected = self.client._process_get_attributes_batch_item
        observed = self.client._get_batch_item_processor(
            OperationEnum.GET_ATTRIBUTES
        )
        self.assertEqual(expected, observed)

        expected = self.client._process_get_attribute_list_batch_item
        observed = self.client._get_batch_item_processor(
            OperationEnum.GET_ATTRIBUTE_LIST)
        self.assertEqual(expected, observed)

    def _test_equality(self, expected, observed):
        msg = "expected {0}, observed {1}".format(expected, observed)
        self.assertEqual(expected, observed, msg)

    def test_process_create_key_pair_batch_item(self):
        batch_item = ResponseBatchItem(
            operation=Operation(OperationEnum.CREATE_KEY_PAIR),
            response_payload=payloads.CreateKeyPairResponsePayload())
        result = self.client._process_create_key_pair_batch_item(batch_item)

        msg = "expected {0}, received {1}".format(CreateKeyPairResult, result)
        self.assertIsInstance(result, CreateKeyPairResult, msg)

    def test_process_rekey_key_pair_batch_item(self):
        batch_item = ResponseBatchItem(
            operation=Operation(OperationEnum.REKEY_KEY_PAIR),
            response_payload=payloads.RekeyKeyPairResponsePayload())
        result = self.client._process_rekey_key_pair_batch_item(batch_item)

        msg = "expected {0}, received {1}".format(RekeyKeyPairResult, result)
        self.assertIsInstance(result, RekeyKeyPairResult, msg)

    def _test_process_query_batch_item(
            self,
            operations,
            object_types,
            vendor_identification,
            server_information,
            application_namespaces,
            extension_information):

        payload = payloads.QueryResponsePayload(
            operations,
            object_types,
            vendor_identification,
            server_information,
            application_namespaces,
            extension_information)
        batch_item = ResponseBatchItem(
            operation=Operation(OperationEnum.QUERY),
            response_payload=payload)

        result = self.client._process_query_batch_item(batch_item)

        base = "expected {0}, observed {1}"
        msg = base.format(QueryResult, result)
        self.assertIsInstance(result, QueryResult, msg)

        # The payload maps the following inputs to empty lists on None.
        if operations is None:
            operations = list()
        if object_types is None:
            object_types = list()
        if application_namespaces is None:
            application_namespaces = list()
        if extension_information is None:
            extension_information = list()

        self._test_equality(operations, result.operations)
        self._test_equality(object_types, result.object_types)
        self._test_equality(
            vendor_identification, result.vendor_identification)
        self._test_equality(server_information, result.server_information)
        self._test_equality(
            application_namespaces, result.application_namespaces)
        self._test_equality(
            extension_information, result.extension_information)

    def test_process_query_batch_item_with_results(self):
        self._test_process_query_batch_item(
            list(),
            list(),
            "",
            ServerInformation(),
            list(),
            list())

    def test_process_query_batch_item_without_results(self):
        self._test_process_query_batch_item(None, None, None, None, None, None)

    def _test_process_discover_versions_batch_item(self, protocol_versions):
        batch_item = ResponseBatchItem(
            operation=Operation(OperationEnum.DISCOVER_VERSIONS),
            response_payload=payloads.DiscoverVersionsResponsePayload(
                protocol_versions))
        result = self.client._process_discover_versions_batch_item(batch_item)

        base = "expected {0}, received {1}"
        msg = base.format(DiscoverVersionsResult, result)
        self.assertIsInstance(result, DiscoverVersionsResult, msg)

        # The payload maps protocol_versions to an empty list on None
        if protocol_versions is None:
            protocol_versions = list()

        msg = base.format(protocol_versions, result.protocol_versions)
        self.assertEqual(protocol_versions, result.protocol_versions, msg)

    def test_process_discover_versions_batch_item_with_results(self):
        protocol_versions = [ProtocolVersion(1, 0)]
        self._test_process_discover_versions_batch_item(protocol_versions)

    def test_process_discover_versions_batch_item_no_results(self):
        protocol_versions = None
        self._test_process_discover_versions_batch_item(protocol_versions)

    def test_process_get_attributes_batch_item(self):
        uuid = '00000000-1111-2222-3333-444444444444'
        attributes = []
        payload = payloads.GetAttributesResponsePayload(
            unique_identifier=uuid,
            attributes=attributes
        )
        batch_item = ResponseBatchItem(
            operation=Operation(OperationEnum.GET_ATTRIBUTES),
            response_payload=payload
        )
        result = self.client._process_get_attributes_batch_item(batch_item)

        self.assertIsInstance(result, GetAttributesResult)
        self.assertEqual(uuid, result.uuid)
        self.assertEqual(attributes, result.attributes)

    def test_process_get_attribute_list_batch_item(self):
        uid = '00000000-1111-2222-3333-444444444444'
        names = ['Cryptographic Algorithm', 'Cryptographic Length']
        payload = payloads.GetAttributeListResponsePayload(
            unique_identifier=uid, attribute_names=names)
        batch_item = ResponseBatchItem(
            operation=Operation(OperationEnum.GET_ATTRIBUTE_LIST),
            response_payload=payload)
        result = self.client._process_get_attribute_list_batch_item(batch_item)

        self.assertIsInstance(result, GetAttributeListResult)
        self.assertEqual(uid, result.uid)
        self.assertEqual(names, result.names)

    def test_host_list_import_string(self):
        """
        This test verifies that the client can process a string with
        multiple IP addresses specified in it. It also tests that
        unnecessary spaces are ignored.
        """

        host_list_string = '127.0.0.1,127.0.0.3,  127.0.0.5'
        host_list_expected = ['127.0.0.1', '127.0.0.3', '127.0.0.5']

        self.client._set_variables(
            host=host_list_string,
            port=None,
            keyfile=None,
            certfile=None,
            cert_reqs=None,
            ssl_version=None,
            ca_certs=None,
            do_handshake_on_connect=False,
            suppress_ragged_eofs=None,
            username=None,
            password=None,
            timeout=None,
            config_file=None
        )
        self.assertEqual(host_list_expected, self.client.host_list)

    def test_host_is_invalid_input(self):
        """
        This test verifies that invalid values are not processed when
        setting the client object parameters
        """
        host = 1337
        expected_error = TypeError

        kwargs = {'host': host, 'port': None, 'keyfile': None,
                  'certfile': None, 'cert_reqs': None, 'ssl_version': None,
                  'ca_certs': None, 'do_handshake_on_connect': False,
                  'suppress_ragged_eofs': None, 'username': None,
                  'password': None, 'timeout': None}

        self.assertRaises(expected_error, self.client._set_variables,
                          **kwargs)

    @mock.patch.object(KMIPProxy, '_create_socket')
    def test_open_server_conn_failover_fail(self, mock_create_socket):
        """
        This test verifies that the KMIP client throws an exception if no
        servers are available for connection
        """
        mock_create_socket.return_value = mock.MagicMock()

        # Assumes both IP addresses fail connection attempts
        self.mock_client.socket.connect.side_effect = [Exception, Exception]

        self.assertRaises(Exception, self.mock_client.open)

    @mock.patch.object(KMIPProxy, '_create_socket')
    def test_open_server_conn_failover_succeed(self, mock_create_socket):
        """
        This test verifies that the KMIP client can setup a connection if at
        least one connection is established
        """
        mock_create_socket.return_value = mock.MagicMock()

        # Assumes IP_ADDR_1 is a bad address and IP_ADDR_2 is a good address
        self.mock_client.socket.connect.side_effect = [Exception, None]

        self.mock_client.open()

        self.assertEqual('IP_ADDR_2', self.mock_client.host)

    def test_socket_ssl_wrap(self):
        """
        This test tests that the KMIP socket is successfully wrapped into an
        ssl socket
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client._create_socket(sock)
        self.assertEqual(ssl.SSLSocket, type(self.client.socket))

    @mock.patch(
        "kmip.services.kmip_client.KMIPProxy._build_request_message"
    )
    @mock.patch(
        "kmip.services.kmip_client.KMIPProxy._send_and_receive_message"
    )
    def test_send_request_payload(self, send_mock, build_mock):
        """
        Test that the client can send a request payload and correctly handle
        the resulting response messsage.
        """
        request_payload = payloads.DeleteAttributeRequestPayload(
            unique_identifier="1",
            attribute_name="Object Group",
            attribute_index=2
        )
        response_payload = payloads.DeleteAttributeResponsePayload(
            unique_identifier="1",
            attribute=None
        )

        batch_item = ResponseBatchItem(
            operation=Operation(OperationEnum.DELETE_ATTRIBUTE),
            result_status=ResultStatus(ResultStatusEnum.SUCCESS),
            response_payload=response_payload
        )
        response_message = ResponseMessage(batch_items=[batch_item])

        build_mock.return_value = None
        send_mock.return_value = response_message

        result = self.client.send_request_payload(
            OperationEnum.DELETE_ATTRIBUTE,
            request_payload
        )

        self.assertIsInstance(result, payloads.DeleteAttributeResponsePayload)
        self.assertEqual(result, response_payload)

    def test_send_request_payload_invalid_payload(self):
        """
        Test that a TypeError is raised when an invalid payload is used to
        send a request.
        """
        args = (OperationEnum.DELETE_ATTRIBUTE, "invalid")
        self.assertRaisesRegex(
            TypeError,
            "The request payload must be a RequestPayload object.",
            self.client.send_request_payload,
            *args
        )

    def test_send_request_payload_mismatch_operation_payload(self):
        """
        Test that a TypeError is raised when the operation and request payload
        do not match up when used to send a request.
        """
        args = (
            OperationEnum.DELETE_ATTRIBUTE,
            payloads.CreateRequestPayload()
        )
        self.assertRaisesRegex(
            TypeError,
            "The request payload for the DeleteAttribute operation must be a "
            "DeleteAttributeRequestPayload object.",
            self.client.send_request_payload,
            *args
        )

        args = (
            OperationEnum.SET_ATTRIBUTE,
            payloads.CreateRequestPayload()
        )
        self.assertRaisesRegex(
            TypeError,
            "The request payload for the SetAttribute operation must be a "
            "SetAttributeRequestPayload object.",
            self.client.send_request_payload,
            *args
        )

        args = (
            OperationEnum.MODIFY_ATTRIBUTE,
            payloads.CreateRequestPayload()
        )
        self.assertRaisesRegex(
            TypeError,
            "The request payload for the ModifyAttribute operation must be a "
            "ModifyAttributeRequestPayload object.",
            self.client.send_request_payload,
            *args
        )

    @mock.patch(
        "kmip.services.kmip_client.KMIPProxy._build_request_message"
    )
    @mock.patch(
        "kmip.services.kmip_client.KMIPProxy._send_and_receive_message"
    )
    def test_send_request_payload_incorrect_number_of_batch_items(
        self,
        send_mock,
        build_mock
    ):
        """
        Test that an InvalidMessage error is raised when the wrong number of
        response payloads are returned from the server.
        """
        build_mock.return_value = None
        send_mock.return_value = ResponseMessage(batch_items=[])

        args = (
            OperationEnum.DELETE_ATTRIBUTE,
            payloads.DeleteAttributeRequestPayload(
                unique_identifier="1",
                attribute_name="Object Group",
                attribute_index=2
            )
        )

        self.assertRaisesRegex(
            exceptions.InvalidMessage,
            "The response message does not have the right number of requested "
            "operation results.",
            self.client.send_request_payload,
            *args
        )

    @mock.patch(
        "kmip.services.kmip_client.KMIPProxy._build_request_message"
    )
    @mock.patch(
        "kmip.services.kmip_client.KMIPProxy._send_and_receive_message"
    )
    def test_send_request_payload_mismatch_response_operation(
        self,
        send_mock,
        build_mock
    ):
        """
        Test that an InvalidMessage error is raised when the wrong operation
        is returned from the server.
        """
        response_payload = payloads.DeleteAttributeResponsePayload(
            unique_identifier="1",
            attribute=None
        )

        batch_item = ResponseBatchItem(
            operation=Operation(OperationEnum.CREATE),
            result_status=ResultStatus(ResultStatusEnum.SUCCESS),
            response_payload=response_payload
        )
        build_mock.return_value = None
        send_mock.return_value = ResponseMessage(batch_items=[batch_item])

        args = (
            OperationEnum.DELETE_ATTRIBUTE,
            payloads.DeleteAttributeRequestPayload(
                unique_identifier="1",
                attribute_name="Object Group",
                attribute_index=2
            )
        )

        self.assertRaisesRegex(
            exceptions.InvalidMessage,
            "The response message does not match the request operation.",
            self.client.send_request_payload,
            *args
        )

    @mock.patch(
        "kmip.services.kmip_client.KMIPProxy._build_request_message"
    )
    @mock.patch(
        "kmip.services.kmip_client.KMIPProxy._send_and_receive_message"
    )
    def test_send_request_payload_mismatch_response_payload(
        self,
        send_mock,
        build_mock
    ):
        """
        Test that an InvalidMessage error is raised when the wrong payload
        is returned from the server.
        """
        response_payload = payloads.DestroyResponsePayload(
            unique_identifier="1"
        )

        batch_item = ResponseBatchItem(
            operation=Operation(OperationEnum.DELETE_ATTRIBUTE),
            result_status=ResultStatus(ResultStatusEnum.SUCCESS),
            response_payload=response_payload
        )
        build_mock.return_value = None
        send_mock.return_value = ResponseMessage(batch_items=[batch_item])

        args = (
            OperationEnum.DELETE_ATTRIBUTE,
            payloads.DeleteAttributeRequestPayload(
                unique_identifier="1",
                attribute_name="Object Group",
                attribute_index=2
            )
        )
        self.assertRaisesRegex(
            exceptions.InvalidMessage,
            "Invalid response payload received for the DeleteAttribute "
            "operation.",
            self.client.send_request_payload,
            *args
        )

        # Test SetAttribute
        batch_item = ResponseBatchItem(
            operation=Operation(OperationEnum.SET_ATTRIBUTE),
            result_status=ResultStatus(ResultStatusEnum.SUCCESS),
            response_payload=response_payload
        )
        send_mock.return_value = ResponseMessage(batch_items=[batch_item])
        args = (
            OperationEnum.SET_ATTRIBUTE,
            payloads.SetAttributeRequestPayload(
                unique_identifier="1",
                new_attribute=objects.NewAttribute(
                    attribute=primitives.Boolean(
                        value=True,
                        tag=enums.Tags.SENSITIVE
                    )
                )
            )
        )
        self.assertRaisesRegex(
            exceptions.InvalidMessage,
            "Invalid response payload received for the SetAttribute "
            "operation.",
            self.client.send_request_payload,
            *args
        )

        # Test ModifyAttribute
        batch_item = ResponseBatchItem(
            operation=Operation(OperationEnum.MODIFY_ATTRIBUTE),
            result_status=ResultStatus(ResultStatusEnum.SUCCESS),
            response_payload=response_payload
        )
        send_mock.return_value = ResponseMessage(batch_items=[batch_item])
        args = (
            OperationEnum.MODIFY_ATTRIBUTE,
            payloads.ModifyAttributeRequestPayload(
                unique_identifier="1",
                new_attribute=objects.NewAttribute(
                    attribute=primitives.Boolean(
                        value=True,
                        tag=enums.Tags.SENSITIVE
                    )
                )
            )
        )
        self.assertRaisesRegex(
            exceptions.InvalidMessage,
            "Invalid response payload received for the ModifyAttribute "
            "operation.",
            self.client.send_request_payload,
            *args
        )

    @mock.patch(
        "kmip.services.kmip_client.KMIPProxy._build_request_message"
    )
    @mock.patch(
        "kmip.services.kmip_client.KMIPProxy._send_and_receive_message"
    )
    def test_send_request_payload_operation_failure(
        self,
        send_mock,
        build_mock
    ):
        """
        Test that a KmipOperationFailure error is raised when a payload
        with a failure status is returned.
        """
        batch_item = ResponseBatchItem(
            operation=Operation(OperationEnum.DELETE_ATTRIBUTE),
            result_status=ResultStatus(ResultStatusEnum.OPERATION_FAILED),
            result_reason=ResultReason(ResultReasonEnum.GENERAL_FAILURE),
            result_message=ResultMessage("Test failed!")
        )
        build_mock.return_value = None
        send_mock.return_value = ResponseMessage(batch_items=[batch_item])

        args = (
            OperationEnum.DELETE_ATTRIBUTE,
            payloads.DeleteAttributeRequestPayload(
                unique_identifier="1",
                attribute_name="Object Group",
                attribute_index=2
            )
        )

        self.assertRaisesRegex(
            exceptions.OperationFailure,
            "Test failed!",
            self.client.send_request_payload,
            *args
        )

    @mock.patch(
        'kmip.services.kmip_client.KMIPProxy._build_request_message'
    )
    @mock.patch(
        'kmip.services.kmip_client.KMIPProxy._send_and_receive_message'
    )
    def test_check(self, send_mock, build_mock):
        """
        Test that the client can correctly build, send, and process a Check
        request.
        """
        payload = payloads.CheckResponsePayload(
            unique_identifier='1',
            usage_limits_count=100,
            cryptographic_usage_mask=12,
            lease_time=10000
        )
        batch_item = ResponseBatchItem(
            operation=Operation(OperationEnum.CHECK),
            result_status=ResultStatus(ResultStatusEnum.SUCCESS),
            response_payload=payload
        )
        response = ResponseMessage(batch_items=[batch_item])

        build_mock.return_value = None
        send_mock.return_value = response

        result = self.client.check(
            '1',
            100,
            [
                enums.CryptographicUsageMask.ENCRYPT,
                enums.CryptographicUsageMask.DECRYPT
            ],
            10000
        )

        self.assertEqual('1', result.get('unique_identifier'))
        self.assertEqual(100, result.get('usage_limits_count'))
        self.assertEqual(
            [
                enums.CryptographicUsageMask.ENCRYPT,
                enums.CryptographicUsageMask.DECRYPT
            ],
            result.get('cryptographic_usage_mask')
        )
        self.assertEqual(10000, result.get('lease_time'))
        self.assertEqual(
            ResultStatusEnum.SUCCESS,
            result.get('result_status')
        )
        self.assertEqual(None, result.get('result_reason'))
        self.assertEqual(None, result.get('result_message'))

    @mock.patch(
        'kmip.services.kmip_client.KMIPProxy._build_request_message'
    )
    @mock.patch(
        'kmip.services.kmip_client.KMIPProxy._send_and_receive_message'
    )
    def test_rekey(self, send_mock, build_mock):
        """
        Test that the client can correctly build, send, and process a Rekey
        request.
        """
        payload = payloads.RekeyResponsePayload(
            unique_identifier='1',
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.AES,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ]
            )
        )
        batch_item = ResponseBatchItem(
            operation=Operation(OperationEnum.REKEY),
            result_status=ResultStatus(ResultStatusEnum.SUCCESS),
            response_payload=payload
        )
        response = ResponseMessage(batch_items=[batch_item])

        build_mock.return_value = None
        send_mock.return_value = response

        result = self.client.rekey(
            uuid='1',
            offset=0,
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Activation Date'
                        ),
                        attribute_value=primitives.DateTime(
                            value=1136113200,
                            tag=enums.Tags.ACTIVATION_DATE
                        )
                    )
                ]
            )
        )

        self.assertEqual('1', result.get('unique_identifier'))
        self.assertEqual(
            objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.AES,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ]
            ),
            result.get('template_attribute')
        )
        self.assertEqual(
            ResultStatusEnum.SUCCESS,
            result.get('result_status')
        )
        self.assertEqual(None, result.get('result_reason'))
        self.assertEqual(None, result.get('result_message'))

    @mock.patch('kmip.services.kmip_client.KMIPProxy._build_request_message')
    @mock.patch(
        'kmip.services.kmip_client.KMIPProxy._send_and_receive_message'
    )
    def test_rekey_with_no_payload(self, send_mock, build_mock):
        """
        Test that the client correctly handles responses with no payload data.
        """
        batch_item = ResponseBatchItem(
            operation=Operation(OperationEnum.REKEY),
            result_status=ResultStatus(ResultStatusEnum.OPERATION_FAILED),
            result_reason=ResultReason(ResultReasonEnum.PERMISSION_DENIED),
            result_message=ResultMessage("Permission denied."),
            response_payload=None
        )
        response = ResponseMessage(batch_items=[batch_item])

        build_mock.return_value = None
        send_mock.return_value = response

        result = self.client.rekey(
            uuid='1',
            offset=0,
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Activation Date'
                        ),
                        attribute_value=primitives.DateTime(
                            value=1136113200,
                            tag=enums.Tags.ACTIVATION_DATE
                        )
                    )
                ]
            )
        )

        self.assertEqual(
            ResultStatusEnum.OPERATION_FAILED,
            result.get('result_status')
        )
        self.assertEqual(
            ResultReasonEnum.PERMISSION_DENIED,
            result.get('result_reason')
        )
        self.assertEqual("Permission denied.", result.get('result_message'))

    @mock.patch('kmip.services.kmip_client.KMIPProxy._build_request_message')
    @mock.patch(
        'kmip.services.kmip_client.KMIPProxy._send_and_receive_message'
    )
    def test_derive_key(self, send_mock, build_mock):
        """
        Test that the client can derive a key.
        """
        payload = payloads.DeriveKeyResponsePayload(
            unique_identifier='1',
        )
        batch_item = ResponseBatchItem(
            operation=Operation(OperationEnum.DERIVE_KEY),
            result_status=ResultStatus(ResultStatusEnum.SUCCESS),
            response_payload=payload
        )
        response = ResponseMessage(batch_items=[batch_item])

        build_mock.return_value = None
        send_mock.return_value = response

        result = self.client.derive_key(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifiers=['2', '3'],
            derivation_method=enums.DerivationMethod.ENCRYPT,
            derivation_parameters=DerivationParameters(
                cryptographic_parameters=CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.CBC,
                    padding_method=enums.PaddingMethod.PKCS1v15,
                    cryptographic_algorithm=enums.CryptographicAlgorithm.AES
                ),
                initialization_vector=b'\x01\x02\x03\x04',
                derivation_data=b'\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8'
            ),
            template_attribute=TemplateAttribute(
                attributes=[
                    self.attr_factory.create_attribute(
                        'Cryptographic Length',
                        128
                    ),
                    self.attr_factory.create_attribute(
                        'Cryptographic Algorithm',
                        enums.CryptographicAlgorithm.AES
                    )
                ]
            ),
        )

        self.assertEqual('1', result.get('unique_identifier'))
        self.assertEqual(
            ResultStatusEnum.SUCCESS,
            result.get('result_status')
        )
        self.assertEqual(None, result.get('result_reason'))
        self.assertEqual(None, result.get('result_message'))

    @mock.patch(
        'kmip.services.kmip_client.KMIPProxy._build_request_message'
    )
    @mock.patch(
        'kmip.services.kmip_client.KMIPProxy._send_and_receive_message'
    )
    def test_encrypt(self, send_mock, build_mock):
        """
        Test that the client can encrypt data.
        """
        payload = payloads.EncryptResponsePayload(
            unique_identifier='1',
            data=(
                b'\x6B\x77\xB4\xD6\x30\x06\xDE\xE6'
                b'\x05\xB1\x56\xE2\x74\x03\x97\x93'
                b'\x58\xDE\xB9\xE7\x15\x46\x16\xD9'
                b'\x74\x9D\xEC\xBE\xC0\x5D\x26\x4B'
            )
        )
        batch_item = ResponseBatchItem(
            operation=Operation(OperationEnum.ENCRYPT),
            result_status=ResultStatus(ResultStatusEnum.SUCCESS),
            response_payload=payload
        )
        response = ResponseMessage(batch_items=[batch_item])

        build_mock.return_value = None
        send_mock.return_value = response

        result = self.client.encrypt(
            (
                b'\x37\x36\x35\x34\x33\x32\x31\x20'
                b'\x4E\x6F\x77\x20\x69\x73\x20\x74'
                b'\x68\x65\x20\x74\x69\x6D\x65\x20'
                b'\x66\x6F\x72\x20\x00'
            ),
            unique_identifier='1',
            cryptographic_parameters=CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.CBC,
                padding_method=enums.PaddingMethod.PKCS5,
                cryptographic_algorithm=enums.CryptographicAlgorithm.BLOWFISH
            ),
            iv_counter_nonce=b'\xFE\xDC\xBA\x98\x76\x54\x32\x10'
        )

        self.assertEqual('1', result.get('unique_identifier'))
        self.assertEqual(
            (
                b'\x6B\x77\xB4\xD6\x30\x06\xDE\xE6'
                b'\x05\xB1\x56\xE2\x74\x03\x97\x93'
                b'\x58\xDE\xB9\xE7\x15\x46\x16\xD9'
                b'\x74\x9D\xEC\xBE\xC0\x5D\x26\x4B'
            ),
            result.get('data')
        )
        self.assertEqual(None, result.get('iv_counter_nonce'))
        self.assertEqual(
            ResultStatusEnum.SUCCESS,
            result.get('result_status')
        )
        self.assertEqual(None, result.get('result_reason'))
        self.assertEqual(None, result.get('result_message'))

    @mock.patch(
        'kmip.services.kmip_client.KMIPProxy._build_request_message'
    )
    @mock.patch(
        'kmip.services.kmip_client.KMIPProxy._send_and_receive_message'
    )
    def test_decrypt(self, send_mock, build_mock):
        """
        Test that the client can decrypt data.
        """
        payload = payloads.DecryptResponsePayload(
            unique_identifier='1',
            data=(
                b'\x37\x36\x35\x34\x33\x32\x31\x20'
                b'\x4E\x6F\x77\x20\x69\x73\x20\x74'
                b'\x68\x65\x20\x74\x69\x6D\x65\x20'
                b'\x66\x6F\x72\x20\x00'
            )
        )
        batch_item = ResponseBatchItem(
            operation=Operation(OperationEnum.DECRYPT),
            result_status=ResultStatus(ResultStatusEnum.SUCCESS),
            response_payload=payload
        )
        response = ResponseMessage(batch_items=[batch_item])

        build_mock.return_value = None
        send_mock.return_value = response

        result = self.client.decrypt(
            (
                b'\x6B\x77\xB4\xD6\x30\x06\xDE\xE6'
                b'\x05\xB1\x56\xE2\x74\x03\x97\x93'
                b'\x58\xDE\xB9\xE7\x15\x46\x16\xD9'
                b'\x74\x9D\xEC\xBE\xC0\x5D\x26\x4B'
            ),
            unique_identifier='1',
            cryptographic_parameters=CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.CBC,
                padding_method=enums.PaddingMethod.PKCS5,
                cryptographic_algorithm=enums.CryptographicAlgorithm.BLOWFISH
            ),
            iv_counter_nonce=b'\xFE\xDC\xBA\x98\x76\x54\x32\x10'
        )

        self.assertEqual('1', result.get('unique_identifier'))
        self.assertEqual(
            (
                b'\x37\x36\x35\x34\x33\x32\x31\x20'
                b'\x4E\x6F\x77\x20\x69\x73\x20\x74'
                b'\x68\x65\x20\x74\x69\x6D\x65\x20'
                b'\x66\x6F\x72\x20\x00'
            ),
            result.get('data')
        )
        self.assertEqual(
            ResultStatusEnum.SUCCESS,
            result.get('result_status')
        )
        self.assertEqual(None, result.get('result_reason'))
        self.assertEqual(None, result.get('result_message'))

    @mock.patch(
        'kmip.services.kmip_client.KMIPProxy._build_request_message'
    )
    @mock.patch(
        'kmip.services.kmip_client.KMIPProxy._send_and_receive_message'
    )
    def test_signature_verify(self, send_mock, build_mock):
        """
        Test that the client can verify a signature.
        """
        payload = payloads.SignatureVerifyResponsePayload(
            unique_identifier='1',
            validity_indicator=enums.ValidityIndicator.INVALID
        )
        batch_item = ResponseBatchItem(
            operation=Operation(OperationEnum.SIGNATURE_VERIFY),
            result_status=ResultStatus(ResultStatusEnum.SUCCESS),
            response_payload=payload
        )
        response = ResponseMessage(batch_items=[batch_item])

        build_mock.return_value = None
        send_mock.return_value = response

        result = self.client.signature_verify(
            (
                b'\x6B\x77\xB4\xD6\x30\x06\xDE\xE6'
                b'\x05\xB1\x56\xE2\x74\x03\x97\x93'
                b'\x58\xDE\xB9\xE7\x15\x46\x16\xD9'
                b'\x74\x9D\xEC\xBE\xC0\x5D\x26\x4B'
            ),
            (
                b'\x11\x11\x11\x11\x11\x11\x11\x11'
            ),
            unique_identifier='1',
            cryptographic_parameters=CryptographicParameters(
                padding_method=enums.PaddingMethod.PKCS1v15,
                cryptographic_algorithm=enums.CryptographicAlgorithm.RSA,
                hashing_algorithm=enums.HashingAlgorithm.SHA_224
            )
        )

        self.assertEqual('1', result.get('unique_identifier'))
        self.assertEqual(
            enums.ValidityIndicator.INVALID,
            result.get('validity_indicator')
        )
        self.assertEqual(
            ResultStatusEnum.SUCCESS,
            result.get('result_status')
        )
        self.assertEqual(None, result.get('result_reason'))
        self.assertEqual(None, result.get('result_message'))

    @mock.patch(
        'kmip.services.kmip_client.KMIPProxy._build_request_message'
    )
    @mock.patch(
        'kmip.services.kmip_client.KMIPProxy._send_and_receive_message'
    )
    def test_sign(self, send_mock, build_mock):
        """
        Test that the client can sign data
        """
        payload = payloads.SignResponsePayload(
            unique_identifier='1',
            signature_data=b'aaaaaaaaaaaaaaaa'
        )
        batch_item = ResponseBatchItem(
            operation=Operation(OperationEnum.SIGN),
            result_status=ResultStatus(ResultStatusEnum.SUCCESS),
            response_payload=payload
        )
        response = ResponseMessage(batch_items=[batch_item])

        build_mock.return_value = None
        send_mock.return_value = response

        result = self.client.sign(
            b'\x11\x11\x11\x11\x11\x11\x11\x11',
            unique_identifier='1',
            cryptographic_parameters=CryptographicParameters(
                padding_method=enums.PaddingMethod.PKCS1v15,
                cryptographic_algorithm=enums.CryptographicAlgorithm.RSA,
                hashing_algorithm=enums.HashingAlgorithm.SHA_224
            )
        )

        self.assertEqual('1', result.get('unique_identifier'))
        self.assertEqual(
            b'aaaaaaaaaaaaaaaa',
            result.get('signature')
        )
        self.assertEqual(
            ResultStatusEnum.SUCCESS,
            result.get('result_status')
        )
        self.assertEqual(None, result.get('result_reason'))
        self.assertEqual(None, result.get('result_message'))

    @mock.patch('kmip.services.kmip_client.KMIPProxy._send_message',
                mock.MagicMock())
    @mock.patch('kmip.services.kmip_client.KMIPProxy._receive_message',
                mock.MagicMock())
    def test_mac(self):

        from kmip.core.utils import BytearrayStream

        request_expected = (
            b'\x42\x00\x78\x01\x00\x00\x00\xa0\x42\x00\x77\x01\x00\x00\x00\x38'
            b'\x42\x00\x69\x01\x00\x00\x00\x20\x42\x00\x6a\x02\x00\x00\x00\x04'
            b'\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x6b\x02\x00\x00\x00\x04'
            b'\x00\x00\x00\x02\x00\x00\x00\x00\x42\x00\x0d\x02\x00\x00\x00\x04'
            b'\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x0f\x01\x00\x00\x00\x58'
            b'\x42\x00\x5c\x05\x00\x00\x00\x04\x00\x00\x00\x23\x00\x00\x00\x00'
            b'\x42\x00\x79\x01\x00\x00\x00\x40\x42\x00\x94\x07\x00\x00\x00\x01'
            b'\x31\x00\x00\x00\x00\x00\x00\x00\x42\x00\x2b\x01\x00\x00\x00\x10'
            b'\x42\x00\x28\x05\x00\x00\x00\x04\x00\x00\x00\x0b\x00\x00\x00\x00'
            b'\x42\x00\xc2\x08\x00\x00\x00\x10\x00\x01\x02\x03\x04\x05\x06\x07'
            b'\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f')
        response = (
            b'\x42\x00\x7b\x01\x00\x00\x00\xd8\x42\x00\x7a\x01\x00\x00\x00\x48'
            b'\x42\x00\x69\x01\x00\x00\x00\x20\x42\x00\x6a\x02\x00\x00\x00\x04'
            b'\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x6b\x02\x00\x00\x00\x04'
            b'\x00\x00\x00\x02\x00\x00\x00\x00\x42\x00\x92\x09\x00\x00\x00\x08'
            b'\x00\x00\x00\x00\x58\x8a\x3f\x23\x42\x00\x0d\x02\x00\x00\x00\x04'
            b'\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x0f\x01\x00\x00\x00\x80'
            b'\x42\x00\x5c\x05\x00\x00\x00\x04\x00\x00\x00\x23\x00\x00\x00\x00'
            b'\x42\x00\x7f\x05\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\x7c\x01\x00\x00\x00\x58\x42\x00\x94\x07\x00\x00\x00\x01'
            b'\x31\x00\x00\x00\x00\x00\x00\x00\x42\x00\xc6\x08\x00\x00\x00\x40'
            b'\x99\x8b\x55\x59\x90\x9b\x85\x87\x5b\x90\x63\x13\x12\xbb\x32\x9f'
            b'\x6a\xc4\xed\x97\x6e\xac\x99\xe5\x21\x53\xc4\x19\x28\xf2\x2a\x5b'
            b'\xef\x79\xa4\xbe\x05\x3b\x31\x49\x19\xe0\x75\x23\xb9\xbe\xc8\x23'
            b'\x35\x60\x7e\x49\xba\xa9\x7e\xe0\x9e\x6b\x3d\x55\xf4\x51\xff\x7c'
        )
        response_no_payload = (
            b'\x42\x00\x7b\x01\x00\x00\x00\x78\x42\x00\x7a\x01\x00\x00\x00\x48'
            b'\x42\x00\x69\x01\x00\x00\x00\x20\x42\x00\x6a\x02\x00\x00\x00\x04'
            b'\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x6b\x02\x00\x00\x00\x04'
            b'\x00\x00\x00\x02\x00\x00\x00\x00\x42\x00\x92\x09\x00\x00\x00\x08'
            b'\x00\x00\x00\x00\x58\x8a\x3f\x23\x42\x00\x0d\x02\x00\x00\x00\x04'
            b'\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x0f\x01\x00\x00\x00\x80'
            b'\x42\x00\x5c\x05\x00\x00\x00\x04\x00\x00\x00\x23\x00\x00\x00\x00'
            b'\x42\x00\x7f\x05\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00'
        )

        data = (b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B'
                b'\x0C\x0D\x0E\x0F')

        mdata = (b'\x99\x8b\x55\x59\x90\x9b\x85\x87\x5b\x90\x63\x13'
                 b'\x12\xbb\x32\x9f'
                 b'\x6a\xc4\xed\x97\x6e\xac\x99\xe5\x21\x53\xc4\x19'
                 b'\x28\xf2\x2a\x5b'
                 b'\xef\x79\xa4\xbe\x05\x3b\x31\x49\x19\xe0\x75\x23'
                 b'\xb9\xbe\xc8\x23'
                 b'\x35\x60\x7e\x49\xba\xa9\x7e\xe0\x9e\x6b\x3d\x55'
                 b'\xf4\x51\xff\x7c')

        def verify_request(message):
            stream = BytearrayStream()
            message.write(stream)
            self.assertEqual(stream.buffer, request_expected)

        uuid = '1'

        cryptographic_parameters = CryptographicParameters(
            cryptographic_algorithm=CryptographicAlgorithmEnum.HMAC_SHA512
        )

        self.client._send_message.side_effect = verify_request
        self.client._receive_message.return_value = BytearrayStream(response)

        result = self.client.mac(data, uuid, cryptographic_parameters)
        self.assertEqual(result.uuid.value, uuid)
        self.assertEqual(result.mac_data.value, mdata)

        self.client._receive_message.return_value = \
            BytearrayStream(response_no_payload)

        result = self.client.mac(data, uuid, cryptographic_parameters)
        self.assertEqual(result.uuid, None)
        self.assertEqual(result.mac_data, None)


class TestClientProfileInformation(TestCase):
    """
    A test suite for client profile information support.
    """

    def setUp(self):
        super(TestClientProfileInformation, self).setUp()

        self.client = KMIPProxy()

        self.conformance_clauses = [ConformanceClause.DISCOVER_VERSIONS]
        self.authentication_suites = [AuthenticationSuite.BASIC]

        self.client.conformance_clauses = self.conformance_clauses
        self.client.authentication_suites = self.authentication_suites

    def tearDown(self):
        super(TestClientProfileInformation, self).tearDown()

    def test_get_supported_conformance_clauses(self):
        """
        Test that the list of supporting conformance clauses can be retrieved.
        """
        conformance_clauses = self.client.get_supported_conformance_clauses()
        self.assertEqual(self.conformance_clauses, conformance_clauses)

    def test_get_supported_authentication_suites(self):
        """
        Test that the list of supporting authentication suites can be
        retrieved.
        """
        auth_suites = self.client.get_supported_authentication_suites()
        self.assertEqual(self.authentication_suites, auth_suites)

    def test_is_conformance_clause_supported_with_valid(self):
        """
        Test that the conformance clause support predicate returns True for
        a ConformanceClause that is supported.
        """
        clause = ConformanceClause.DISCOVER_VERSIONS
        supported = self.client.is_conformance_clause_supported(clause)
        self.assertTrue(supported)

    def test_is_conformance_clause_supported_with_invalid(self):
        """
        Test that the conformance clause support predicate returns False for
        a ConformanceClause that is not supported.
        """
        clause = ConformanceClause.BASELINE
        supported = self.client.is_conformance_clause_supported(clause)
        self.assertFalse(supported)

    def test_is_authentication_suite_supported_with_valid(self):
        """
        Test that the authentication suite support predicate returns True for
        an AuthenticationSuite that is supported.
        """
        suite = AuthenticationSuite.BASIC
        supported = self.client.is_authentication_suite_supported(suite)
        self.assertTrue(supported)

    def test_is_authentication_suite_supported_with_invalid(self):
        """
        Test that the authentication suite support predicate returns False for
        an AuthenticationSuite that is not supported.
        """
        suite = AuthenticationSuite.TLS12
        supported = self.client.is_authentication_suite_supported(suite)
        self.assertFalse(supported)

    def test_is_profile_supported(self):
        """
        Test that the profile support predicate returns True for valid profile
        components.
        """
        supported = self.client.is_profile_supported(
            ConformanceClause.DISCOVER_VERSIONS,
            AuthenticationSuite.BASIC)
        self.assertTrue(supported)

    # TODO (peter-hamilton) Replace following 3 tests with 1 parameterized test
    def test_is_profile_supported_with_invalid_conformance_clause(self):
        """
        Test that the profile support predicate returns False for an invalid
        conformance clause.
        """
        supported = self.client.is_profile_supported(
            ConformanceClause.BASELINE,
            AuthenticationSuite.BASIC)
        self.assertFalse(supported)

    def test_is_profile_supported_with_invalid_authentication_suite(self):
        """
        Test that the profile support predicate returns False for an invalid
        authentication suite.
        """
        supported = self.client.is_profile_supported(
            ConformanceClause.DISCOVER_VERSIONS,
            AuthenticationSuite.TLS12)
        self.assertFalse(supported)

    def test_is_profile_supported_with_invalid_profile_components(self):
        """
        Test that the profile support predicate returns False for invalid
        profile components.
        """
        supported = self.client.is_profile_supported(
            ConformanceClause.BASELINE,
            AuthenticationSuite.TLS12)
        self.assertFalse(supported)
