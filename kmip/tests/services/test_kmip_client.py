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

from subprocess import Popen

import os
import sys
import time

from kmip.core.attributes import CryptographicAlgorithm
from kmip.core.attributes import CryptographicLength
from kmip.core.attributes import PrivateKeyUniqueIdentifier

from kmip.core.enums import AttributeType
from kmip.core.enums import AuthenticationSuite
from kmip.core.enums import ConformanceClause
from kmip.core.enums import CredentialType
from kmip.core.enums import CryptographicAlgorithm as CryptoAlgorithmEnum
from kmip.core.enums import CryptographicUsageMask
from kmip.core.enums import ObjectType
from kmip.core.enums import Operation as OperationEnum
from kmip.core.enums import KeyFormatType as KeyFormatTypeEnum
from kmip.core.enums import QueryFunction as QueryFunctionEnum
from kmip.core.enums import ResultStatus
from kmip.core.enums import ResultReason

from kmip.core.errors import KMIPServerSuicideError
from kmip.core.errors import KMIPServerZombieError

from kmip.core.factories.attributes import AttributeFactory
from kmip.core.factories.credentials import CredentialFactory
from kmip.core.factories.secrets import SecretFactory

from kmip.core.messages.messages import RequestBatchItem
from kmip.core.messages.messages import ResponseBatchItem
from kmip.core.messages.messages import ResponseMessage
from kmip.core.messages.contents import Operation
from kmip.core.messages.contents import ProtocolVersion
from kmip.core.messages.payloads.create_key_pair import \
    CreateKeyPairRequestPayload, CreateKeyPairResponsePayload
from kmip.core.messages.payloads.discover_versions import \
    DiscoverVersionsRequestPayload, DiscoverVersionsResponsePayload
from kmip.core.messages.payloads.query import \
    QueryRequestPayload, QueryResponsePayload
from kmip.core.messages.payloads.rekey_key_pair import \
    RekeyKeyPairRequestPayload, RekeyKeyPairResponsePayload

from kmip.core.misc import KeyFormatType
from kmip.core.misc import Offset
from kmip.core.misc import QueryFunction
from kmip.core.misc import ServerInformation
from kmip.core.misc import VendorIdentification

from kmip.core.objects import Attribute
from kmip.core.objects import CommonTemplateAttribute
from kmip.core.objects import KeyBlock
from kmip.core.objects import KeyMaterial
from kmip.core.objects import KeyValue
from kmip.core.objects import PrivateKeyTemplateAttribute
from kmip.core.objects import PublicKeyTemplateAttribute
from kmip.core.objects import TemplateAttribute

from kmip.core.secrets import SymmetricKey

from kmip.services.kmip_client import KMIPProxy

from kmip.services.results import CreateKeyPairResult
from kmip.services.results import DiscoverVersionsResult
from kmip.services.results import QueryResult
from kmip.services.results import RekeyKeyPairResult

import kmip.core.utils as utils


# TODO (peter-hamilton) Move integration tests into separate module
class TestKMIPClientIntegration(TestCase):
    STARTUP_TIME = 1.0
    SHUTDOWN_TIME = 0.1
    KMIP_PORT = 9090
    CA_CERTS_PATH = os.path.normpath(os.path.join(os.path.dirname(
        os.path.abspath(__file__)), '../../demos/certs/server.crt'))

    def setUp(self):
        super(TestKMIPClientIntegration, self).setUp()

        self.attr_factory = AttributeFactory()
        self.cred_factory = CredentialFactory()
        self.secret_factory = SecretFactory()

        # Set up the KMIP server process
        path = os.path.join(os.path.dirname(__file__), os.path.pardir,
                            'utils', 'server.py')
        self.server = Popen(['python', '{0}'.format(path), '-p',
                             '{0}'.format(self.KMIP_PORT)], stderr=sys.stdout)

        time.sleep(self.STARTUP_TIME)

        if self.server.poll() is not None:
            raise KMIPServerSuicideError(self.server.pid)

        # Set up and open the client proxy; shutdown the server if open fails
        try:
            self.client = KMIPProxy(port=self.KMIP_PORT,
                                    ca_certs=self.CA_CERTS_PATH)
            self.client.open()
        except Exception as e:
            self._shutdown_server()
            raise e

    def tearDown(self):
        super(TestKMIPClientIntegration, self).tearDown()

        # Close the client proxy and shutdown the server
        self.client.close()
        self._shutdown_server()

    def test_create(self):
        result = self._create_symmetric_key()

        self._check_result_status(result.result_status.enum, ResultStatus,
                                  ResultStatus.SUCCESS)
        self._check_object_type(result.object_type.enum, ObjectType,
                                ObjectType.SYMMETRIC_KEY)
        self._check_uuid(result.uuid.value, str)

        # Check the template attribute type
        self._check_template_attribute(result.template_attribute,
                                       TemplateAttribute, 2,
                                       [[str, 'Cryptographic Length', int,
                                         256],
                                        [str, 'Unique Identifier', str,
                                         None]])

    def test_get(self):
        credential_type = CredentialType.USERNAME_AND_PASSWORD
        credential_value = {'Username': 'Peter', 'Password': 'abc123'}
        credential = self.cred_factory.create_credential(credential_type,
                                                         credential_value)
        result = self._create_symmetric_key()
        uuid = result.uuid.value

        result = self.client.get(uuid=uuid, credential=credential)

        self._check_result_status(result.result_status.enum, ResultStatus,
                                  ResultStatus.SUCCESS)
        self._check_object_type(result.object_type.enum, ObjectType,
                                ObjectType.SYMMETRIC_KEY)
        self._check_uuid(result.uuid.value, str)

        # Check the secret type
        secret = result.secret

        expected = SymmetricKey
        message = utils.build_er_error(result.__class__, 'type', expected,
                                       secret, 'secret')
        self.assertIsInstance(secret, expected, message)

    def test_destroy(self):
        credential_type = CredentialType.USERNAME_AND_PASSWORD
        credential_value = {'Username': 'Peter', 'Password': 'abc123'}
        credential = self.cred_factory.create_credential(credential_type,
                                                         credential_value)
        result = self._create_symmetric_key()
        uuid = result.uuid.value

        # Verify the secret was created
        result = self.client.get(uuid=uuid, credential=credential)

        self._check_result_status(result.result_status.enum, ResultStatus,
                                  ResultStatus.SUCCESS)
        self._check_object_type(result.object_type.enum, ObjectType,
                                ObjectType.SYMMETRIC_KEY)
        self._check_uuid(result.uuid.value, str)

        secret = result.secret

        expected = SymmetricKey
        message = utils.build_er_error(result.__class__, 'type', expected,
                                       secret, 'secret')
        self.assertIsInstance(secret, expected, message)

        # Destroy the SYMMETRIC_KEY object
        result = self.client.destroy(uuid, credential)
        self._check_result_status(result.result_status.enum, ResultStatus,
                                  ResultStatus.SUCCESS)
        self._check_uuid(result.uuid.value, str)

        # Verify the secret was destroyed
        result = self.client.get(uuid=uuid, credential=credential)

        self._check_result_status(result.result_status.enum, ResultStatus,
                                  ResultStatus.OPERATION_FAILED)

        expected = ResultReason
        observed = type(result.result_reason.enum)
        message = utils.build_er_error(result.result_reason.__class__, 'type',
                                       expected, observed)
        self.assertEqual(expected, observed, message)

        expected = ResultReason.ITEM_NOT_FOUND
        observed = result.result_reason.enum
        message = utils.build_er_error(result.result_reason.__class__,
                                       'value', expected, observed)
        self.assertEqual(expected, observed, message)

    def test_register(self):
        credential_type = CredentialType.USERNAME_AND_PASSWORD
        credential_value = {'Username': 'Peter', 'Password': 'abc123'}
        credential = self.cred_factory.create_credential(credential_type,
                                                         credential_value)

        object_type = ObjectType.SYMMETRIC_KEY
        algorithm_value = CryptoAlgorithmEnum.AES
        mask_flags = [CryptographicUsageMask.ENCRYPT,
                      CryptographicUsageMask.DECRYPT]
        attribute_type = AttributeType.CRYPTOGRAPHIC_USAGE_MASK
        usage_mask = self.attr_factory.create_attribute(attribute_type,
                                                        mask_flags)
        attributes = [usage_mask]
        template_attribute = TemplateAttribute(attributes=attributes)

        key_format_type = KeyFormatType(KeyFormatTypeEnum.RAW)

        key_data = (
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00')

        key_material = KeyMaterial(key_data)
        key_value = KeyValue(key_material)
        cryptographic_algorithm = CryptographicAlgorithm(algorithm_value)
        cryptographic_length = CryptographicLength(128)

        key_block = KeyBlock(
            key_format_type=key_format_type,
            key_compression_type=None,
            key_value=key_value,
            cryptographic_algorithm=cryptographic_algorithm,
            cryptographic_length=cryptographic_length,
            key_wrapping_data=None)

        secret = SymmetricKey(key_block)

        result = self.client.register(object_type, template_attribute, secret,
                                      credential)

        self._check_result_status(result.result_status.enum, ResultStatus,
                                  ResultStatus.SUCCESS)
        self._check_uuid(result.uuid.value, str)

        # Check the template attribute type
        self._check_template_attribute(result.template_attribute,
                                       TemplateAttribute, 1,
                                       [[str, 'Unique Identifier', str,
                                         None]])
        # Check that the returned key bytes match what was provided
        uuid = result.uuid.value
        result = self.client.get(uuid=uuid, credential=credential)

        self._check_result_status(result.result_status.enum, ResultStatus,
                                  ResultStatus.SUCCESS)
        self._check_object_type(result.object_type.enum, ObjectType,
                                ObjectType.SYMMETRIC_KEY)
        self._check_uuid(result.uuid.value, str)

        # Check the secret type
        secret = result.secret

        expected = SymmetricKey
        message = utils.build_er_error(result.__class__, 'type', expected,
                                       secret, 'secret')
        self.assertIsInstance(secret, expected, message)

        key_block = result.secret.key_block
        key_value = key_block.key_value
        key_material = key_value.key_material

        expected = key_data
        observed = key_material.value
        message = utils.build_er_error(key_material.__class__, 'value',
                                       expected, observed, 'value')
        self.assertEqual(expected, observed, message)

    def _shutdown_server(self):
        if self.server.poll() is not None:
            return
        else:
            # Terminate the server process. If it resists, kill it.
            pid = self.server.pid
            self.server.terminate()
            time.sleep(self.SHUTDOWN_TIME)

            if self.server.poll() is None:
                raise KMIPServerZombieError(pid)

    def _create_symmetric_key(self):
        credential_type = CredentialType.USERNAME_AND_PASSWORD
        credential_value = {'Username': 'Peter', 'Password': 'abc123'}
        credential = self.cred_factory.create_credential(credential_type,
                                                         credential_value)

        object_type = ObjectType.SYMMETRIC_KEY
        attribute_type = AttributeType.CRYPTOGRAPHIC_ALGORITHM
        algorithm = self.attr_factory.create_attribute(
            attribute_type,
            CryptoAlgorithmEnum.AES)

        mask_flags = [CryptographicUsageMask.ENCRYPT,
                      CryptographicUsageMask.DECRYPT]
        attribute_type = AttributeType.CRYPTOGRAPHIC_USAGE_MASK
        usage_mask = self.attr_factory.create_attribute(attribute_type,
                                                        mask_flags)
        attributes = [algorithm, usage_mask]
        template_attribute = TemplateAttribute(attributes=attributes)

        return self.client.create(object_type, template_attribute,
                                  credential)

    def _check_result_status(self, result_status, result_status_type,
                             result_status_value):
        # Error check the result status type and value
        expected = result_status_type
        message = utils.build_er_error(result_status_type, 'type', expected,
                                       result_status)
        self.assertIsInstance(result_status, expected, message)

        expected = result_status_value
        message = utils.build_er_error(result_status_type, 'value', expected,
                                       result_status)
        self.assertEqual(expected, result_status, message)

    def _check_uuid(self, uuid, uuid_type):
        # Error check the UUID type and value
        not_expected = None
        message = utils.build_er_error(uuid_type, 'type',
                                       'not {0}'.format(not_expected), uuid)
        self.assertNotEqual(not_expected, uuid, message)

        expected = uuid_type
        message = utils.build_er_error(uuid_type, 'type', expected, uuid)
        self.assertEqual(expected, type(uuid), message)

    def _check_object_type(self, object_type, object_type_type,
                           object_type_value):
        # Error check the object type type and value
        expected = object_type_type
        message = utils.build_er_error(object_type_type, 'type', expected,
                                       object_type)
        self.assertIsInstance(object_type, expected, message)

        expected = object_type_value
        message = utils.build_er_error(object_type_type, 'value', expected,
                                       object_type)
        self.assertEqual(expected, object_type, message)

    def _check_template_attribute(self, template_attribute,
                                  template_attribute_type, num_attributes,
                                  attribute_features):
        # Error check the template attribute type
        expected = template_attribute_type
        message = utils.build_er_error(template_attribute.__class__, 'type',
                                       expected, template_attribute)
        self.assertIsInstance(template_attribute, expected, message)

        attributes = template_attribute.attributes

        expected = num_attributes
        observed = len(attributes)
        message = utils.build_er_error(TemplateAttribute.__class__, 'number',
                                       expected, observed, 'attributes')

        for i in range(num_attributes):
            features = attribute_features[i]
            self._check_attribute(attributes[i], features[0], features[1],
                                  features[2], features[3])

    def _check_attribute(self, attribute, attribute_name_type,
                         attribute_name_value, attribute_value_type,
                         attribute_value_value):
        # Error check the attribute name and value type and value
        attribute_name = attribute.attribute_name
        attribute_value = attribute.attribute_value

        self._check_attribute_name(attribute_name, attribute_name_type,
                                   attribute_name_value)

        if attribute_name_value == 'Unique Identifier':
            self._check_uuid(attribute_value.value, attribute_value_type)
        else:
            self._check_attribute_value(attribute_value, attribute_value_type,
                                        attribute_value_value)

    def _check_attribute_name(self, attribute_name, attribute_name_type,
                              attribute_name_value):
        # Error check the attribute name type and value
        expected = attribute_name_type
        observed = type(attribute_name.value)
        message = utils.build_er_error(attribute_name_type, 'type', expected,
                                       observed)
        self.assertEqual(expected, observed, message)

        expected = attribute_name_value
        observed = attribute_name.value
        message = utils.build_er_error(attribute_name_type, 'value', expected,
                                       observed)
        self.assertEqual(expected, observed, message)

    def _check_attribute_value(self, attribute_value, attribute_value_type,
                               attribute_value_value):
        expected = attribute_value_type
        observed = type(attribute_value.value)
        message = utils.build_er_error(Attribute, 'type', expected, observed,
                                       'attribute_value')
        self.assertEqual(expected, observed, message)

        expected = attribute_value_value
        observed = attribute_value.value
        message = utils.build_er_error(Attribute, 'value', expected, observed,
                                       'attribute_value')
        self.assertEqual(expected, observed, message)


class TestKMIPClient(TestCase):

    def setUp(self):
        super(TestKMIPClient, self).setUp()

        self.attr_factory = AttributeFactory()
        self.cred_factory = CredentialFactory()
        self.secret_factory = SecretFactory()

        self.client = KMIPProxy()

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
                                       credential.credential_type.enum,
                                       'value')
        self.assertEqual(CredentialType.USERNAME_AND_PASSWORD,
                         credential.credential_type.enum,
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

        operation_enum = operation.enum

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

        operation_enum = operation.enum

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

        operation_enum = operation.enum

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

        operation_enum = operation.enum

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

        self.assertRaisesRegexp(ValueError, "no processor for operation",
                                self.client._get_batch_item_processor, None)

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
