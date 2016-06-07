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

from kmip.core.attributes import PrivateKeyUniqueIdentifier

from kmip.core.enums import AttributeType
from kmip.core.enums import AuthenticationSuite
from kmip.core.enums import ConformanceClause
from kmip.core.enums import CredentialType
from kmip.core.enums import ResultStatus as ResultStatusEnum
from kmip.core.enums import ResultReason as ResultReasonEnum
from kmip.core.enums import Operation as OperationEnum
from kmip.core.enums import QueryFunction as QueryFunctionEnum

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

from kmip.core.messages.payloads.create_key_pair import \
    CreateKeyPairRequestPayload, CreateKeyPairResponsePayload
from kmip.core.messages.payloads.discover_versions import \
    DiscoverVersionsRequestPayload, DiscoverVersionsResponsePayload
from kmip.core.messages.payloads import get_attribute_list
from kmip.core.messages.payloads.query import \
    QueryRequestPayload, QueryResponsePayload
from kmip.core.messages.payloads.rekey_key_pair import \
    RekeyKeyPairRequestPayload, RekeyKeyPairResponsePayload
from kmip.core.messages.payloads.add_attribute import \
    AddAttributeRequestPayload, AddAttributeResponsePayload

from kmip.core.misc import Offset
from kmip.core.misc import QueryFunction
from kmip.core.misc import ServerInformation
from kmip.core.misc import VendorIdentification

from kmip.core.objects import CommonTemplateAttribute
from kmip.core.objects import PrivateKeyTemplateAttribute
from kmip.core.objects import PublicKeyTemplateAttribute

from kmip.services.kmip_client import KMIPProxy

from kmip.services.results import AddAttributeResult
from kmip.services.results import CreateKeyPairResult
from kmip.services.results import DiscoverVersionsResult
from kmip.services.results import GetAttributeListResult
from kmip.services.results import OperationResult
from kmip.services.results import QueryResult
from kmip.services.results import RekeyKeyPairResult

import kmip.core.utils as utils

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

        self.client = KMIPProxy()

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

    # TODO (peter-hamilton) Modify for credential type and/or add new test
    def test_build_credential(self):
        username = 'username'
        password = 'password'
        cred_type = CredentialType.USERNAME_AND_PASSWORD
        self.client.username = username
        self.client.password = password

        credential = self.client._build_credential()

        message = utils.build_er_error(credential.__class__, 'type',
                                       cred_type,
                                       credential.credential_type.value,
                                       'value')
        self.assertEqual(CredentialType.USERNAME_AND_PASSWORD,
                         credential.credential_type.value,
                         message)

        message = utils.build_er_error(
            credential.__class__, 'type', username,
            credential.credential_value.username.value, 'value')
        self.assertEqual(username, credential.credential_value.username.value,
                         message)

        message = utils.build_er_error(
            credential.__class__, 'type', password,
            credential.credential_value.password.value, 'value')
        self.assertEqual(password, credential.credential_value.password.value,
                         message)

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

        msg = base.format(CreateKeyPairRequestPayload, payload)
        self.assertIsInstance(payload, CreateKeyPairRequestPayload, msg)

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

        msg = base.format(RekeyKeyPairRequestPayload, payload)
        self.assertIsInstance(payload, RekeyKeyPairRequestPayload, msg)

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

        if query_functions is None:
            query_functions = list()

        msg = base.format(QueryRequestPayload, payload)
        self.assertIsInstance(payload, QueryRequestPayload, msg)

        query_functions_observed = payload.query_functions
        self.assertEqual(query_functions, query_functions_observed)

    def test_build_query_batch_item_with_input(self):
        self._test_build_query_batch_item(
            [QueryFunction(QueryFunctionEnum.QUERY_OBJECTS)])

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

        msg = base.format(DiscoverVersionsRequestPayload, payload)
        self.assertIsInstance(payload, DiscoverVersionsRequestPayload, msg)

        observed = payload.protocol_versions

        msg = base.format(protocol_versions, observed)
        self.assertEqual(protocol_versions, observed, msg)

    def test_build_discover_versions_batch_item_with_input(self):
        protocol_versions = [ProtocolVersion.create(1, 0)]
        self._test_build_discover_versions_batch_item(protocol_versions)

    def test_build_discover_versions_batch_item_no_input(self):
        protocol_versions = None
        self._test_build_discover_versions_batch_item(protocol_versions)

    def test_build_get_attribute_list_batch_item(self):
        uid = '00000000-1111-2222-3333-444444444444'
        batch_item = self.client._build_get_attribute_list_batch_item(uid)

        self.assertIsInstance(batch_item, RequestBatchItem)
        self.assertIsInstance(batch_item.operation, Operation)
        self.assertEqual(
            OperationEnum.GET_ATTRIBUTE_LIST, batch_item.operation.value)
        self.assertIsInstance(
            batch_item.request_payload,
            get_attribute_list.GetAttributeListRequestPayload)
        self.assertEqual(uid, batch_item.request_payload.uid)

    def _test_build_add_attribute_batch_item(self, uid=None, attribute=None):
        batch_item = self.client._build_add_attribute_batch_item(
            uid=uid, attribute=attribute)

        base = "expected {0}, received {1}"
        msg = base.format(RequestBatchItem, batch_item)
        self.assertIsInstance(batch_item, RequestBatchItem, msg)

        operation = batch_item.operation

        msg = base.format(Operation, operation)
        self.assertIsInstance(operation, Operation, msg)

        operation_enum = operation.value

        msg = base.format(OperationEnum.ADD_ATTRIBUTE, operation_enum)
        self.assertEqual(OperationEnum.ADD_ATTRIBUTE, operation_enum, msg)

        payload = batch_item.request_payload

        msg = base.format(AddAttributeRequestPayload, payload)
        self.assertIsInstance(payload, AddAttributeRequestPayload, msg)

        msg = base.format(uid, payload.uid)
        self.assertEqual(uid, payload.uid, msg)

        msg = base.format(attribute, payload.attribute)
        self.assertEqual(attribute, payload.attribute, msg)

    def test_build_add_attribute_batch_item_with_input(self):
        attribute = self.attr_factory.create_attribute(
            AttributeType.CONTACT_INFORMATION,
            'https://github.com/OpenKMIP/PyKMIP')

        self._test_build_add_attribute_batch_item(
            uid='3',
            attribute=attribute)

    def test_process_batch_items(self):
        batch_item = ResponseBatchItem(
            operation=Operation(OperationEnum.CREATE_KEY_PAIR),
            response_payload=CreateKeyPairResponsePayload())
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

        expected = self.client._process_get_attribute_list_batch_item
        observed = self.client._get_batch_item_processor(
            OperationEnum.GET_ATTRIBUTE_LIST)
        self.assertEqual(expected, observed)

        expected = self.client._process_add_attribute_batch_item
        observed = self.client._get_batch_item_processor(
            OperationEnum.ADD_ATTRIBUTE)
        self.assertEqual(expected, observed)

        self.assertRaisesRegexp(ValueError, "no processor for operation",
                                self.client._get_batch_item_processor,
                                0xA5A5A5A5)

    def _test_equality(self, expected, observed):
        msg = "expected {0}, observed {1}".format(expected, observed)
        self.assertEqual(expected, observed, msg)

    def test_process_create_key_pair_batch_item(self):
        batch_item = ResponseBatchItem(
            operation=Operation(OperationEnum.CREATE_KEY_PAIR),
            response_payload=CreateKeyPairResponsePayload())
        result = self.client._process_create_key_pair_batch_item(batch_item)

        msg = "expected {0}, received {1}".format(CreateKeyPairResult, result)
        self.assertIsInstance(result, CreateKeyPairResult, msg)

    def test_process_rekey_key_pair_batch_item(self):
        batch_item = ResponseBatchItem(
            operation=Operation(OperationEnum.REKEY_KEY_PAIR),
            response_payload=RekeyKeyPairResponsePayload())
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

        payload = QueryResponsePayload(
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
            VendorIdentification(),
            ServerInformation(),
            list(),
            list())

    def test_process_query_batch_item_without_results(self):
        self._test_process_query_batch_item(None, None, None, None, None, None)

    def _test_process_discover_versions_batch_item(self, protocol_versions):
        batch_item = ResponseBatchItem(
            operation=Operation(OperationEnum.DISCOVER_VERSIONS),
            response_payload=DiscoverVersionsResponsePayload(
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
        protocol_versions = [ProtocolVersion.create(1, 0)]
        self._test_process_discover_versions_batch_item(protocol_versions)

    def test_process_discover_versions_batch_item_no_results(self):
        protocol_versions = None
        self._test_process_discover_versions_batch_item(protocol_versions)

    def test_process_get_attribute_list_batch_item(self):
        uid = '00000000-1111-2222-3333-444444444444'
        names = ['Cryptographic Algorithm', 'Cryptographic Length']
        payload = get_attribute_list.GetAttributeListResponsePayload(
            uid=uid, attribute_names=names)
        batch_item = ResponseBatchItem(
            operation=Operation(OperationEnum.GET_ATTRIBUTE_LIST),
            response_payload=payload)
        result = self.client._process_get_attribute_list_batch_item(batch_item)

        self.assertIsInstance(result, GetAttributeListResult)
        self.assertEqual(uid, result.uid)
        self.assertEqual(names, result.names)

    def _test_process_add_attribute_batch_item(
            self,
            result_status,
            result_reason=None,
            result_message=None,
            uid=None,
            attribute=None):

        operation = Operation(OperationEnum.ADD_ATTRIBUTE)
        response_payload = AddAttributeResponsePayload(
            uid=uid, attribute=attribute)

        batch_item = ResponseBatchItem(
            result_status=result_status,
            result_reason=result_reason,
            result_message=result_message,
            operation=operation,
            response_payload=response_payload)

        result = self.client._process_add_attribute_batch_item(batch_item)

        base = "expected {0}, received {1}"
        msg = base.format(AddAttributeResult, result)
        self.assertIsInstance(result, AddAttributeResult, msg)

        msg = base.format(result_status, result.result_status)
        self.assertEqual(result_status, result.result_status, msg)

        msg = base.format(uid, result.uid)
        self.assertEqual(uid, result.uid, msg)

        msg = base.format(attribute, result.attribute)
        self.assertEqual(attribute, result.attribute, msg)

    def test_process_add_attribute_batch_item_with_success(self):
        result_status = ResultStatus(ResultStatusEnum.SUCCESS)
        result_message = ResultMessage("message")

        attribute = self.attr_factory.create_attribute(
            AttributeType.CONTACT_INFORMATION,
            'https://github.com/OpenKMIP/PyKMIP')

        self._test_process_add_attribute_batch_item(
            result_status=result_status,
            result_message=result_message,
            uid='3',
            attribute=attribute)

    def test_process_add_attribute_batch_item_with_failure(self):
        result_status = ResultStatus(ResultStatusEnum.OPERATION_FAILED)
        result_reason = ResultReason(ResultReasonEnum.INVALID_MESSAGE)
        result_message = ResultMessage("message")

        self._test_process_add_attribute_batch_item(
            result_status=result_status,
            result_reason=result_reason,
            result_message=result_message)

    def test_host_list_import_string(self):
        """
        This test verifies that the client can process a string with
        multiple IP addresses specified in it. It also tests that
        unnecessary spaces are ignored.
        """

        host_list_string = '127.0.0.1,127.0.0.3,  127.0.0.5'
        host_list_expected = ['127.0.0.1', '127.0.0.3', '127.0.0.5']

        self.client._set_variables(host=host_list_string,
                                   port=None, keyfile=None, certfile=None,
                                   cert_reqs=None, ssl_version=None,
                                   ca_certs=None,
                                   do_handshake_on_connect=False,
                                   suppress_ragged_eofs=None, username=None,
                                   password=None, timeout=None)
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
