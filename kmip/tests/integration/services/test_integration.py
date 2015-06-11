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

import logging
import pytest
from testtools import TestCase

from kmip.core.attributes import CryptographicAlgorithm
from kmip.core.attributes import CryptographicLength
from kmip.core.attributes import Name


from kmip.core.enums import AttributeType
from kmip.core.enums import CredentialType
from kmip.core.enums import CryptographicAlgorithm as CryptoAlgorithmEnum
from kmip.core.enums import CryptographicUsageMask
from kmip.core.enums import KeyFormatType as KeyFormatTypeEnum
from kmip.core.enums import NameType
from kmip.core.enums import ObjectType
from kmip.core.enums import ResultStatus
from kmip.core.enums import ResultReason
from kmip.core.enums import QueryFunction as QueryFunctionEnum

from kmip.core.factories.attributes import AttributeFactory
from kmip.core.factories.credentials import CredentialFactory
from kmip.core.factories.secrets import SecretFactory

from kmip.core.misc import KeyFormatType

from kmip.core.objects import Attribute
from kmip.core.objects import KeyBlock
from kmip.core.objects import KeyMaterial
from kmip.core.objects import KeyValue
from kmip.core.objects import TemplateAttribute

from kmip.core.misc import QueryFunction

from kmip.core.secrets import SymmetricKey

import kmip.core.utils as utils



@pytest.mark.usefixtures("client")
class TestIntegration(TestCase):

    def setUp(self):
        super(TestIntegration, self).setUp()

        self.logger = logging.getLogger(__name__)

        self.attr_factory = AttributeFactory()
        self.cred_factory = CredentialFactory()
        self.secret_factory = SecretFactory()


    def tearDown(self):
        super(TestIntegration, self).tearDown()

    def _create_symmetric_key(self):

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
        key_length = 128
        attribute_type = AttributeType.CRYPTOGRAPHIC_LENGTH
        key_length_obj = self.attr_factory.create_attribute(attribute_type,
                                                            key_length)
        name = Attribute.AttributeName('Name')
        name_value = Name.NameValue('Integration Test Key')
        name_type = Name.NameType(NameType.UNINTERPRETED_TEXT_STRING)
        value = Name(name_value=name_value, name_type=name_type)
        name = Attribute(attribute_name=name, attribute_value=value)

        attributes = [algorithm, usage_mask, key_length_obj, name]
        template_attribute = TemplateAttribute(attributes=attributes)

        return self.client.create(object_type, template_attribute,
                                  credential=None)

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

    def test_discover_versions(self):
        result = self.client.discover_versions()

        expected = ResultStatus.SUCCESS
        observed = result.result_status.enum

        self.assertEqual(expected, observed)

    def test_query(self):
        # Build query function list, asking for all server data.
        query_functions = list()
        query_functions.append(
            QueryFunction(QueryFunctionEnum.QUERY_OPERATIONS))
        query_functions.append(
            QueryFunction(QueryFunctionEnum.QUERY_OBJECTS))
        query_functions.append(
            QueryFunction(QueryFunctionEnum.QUERY_SERVER_INFORMATION))
        query_functions.append(
            QueryFunction(QueryFunctionEnum.QUERY_APPLICATION_NAMESPACES))
        query_functions.append(
            QueryFunction(QueryFunctionEnum.QUERY_EXTENSION_LIST))
        query_functions.append(
            QueryFunction(QueryFunctionEnum.QUERY_EXTENSION_MAP))

        result = self.client.query(query_functions=query_functions)

        expected = ResultStatus.SUCCESS
        observed = result.result_status.enum

        self.assertEqual(expected, observed)

    def test_symmetric_key_create(self):
        result = self._create_symmetric_key()

        self.logger.debug(result)
        self.logger.debug(result.result_reason)
        self.logger.debug(result.result_message)

        self._check_result_status(result.result_status.enum, ResultStatus,
                                  ResultStatus.SUCCESS)
        self._check_object_type(result.object_type.enum, ObjectType,
                                ObjectType.SYMMETRIC_KEY)
        self._check_uuid(result.uuid.value, str)

        # Check the template attribute type
        self._check_template_attribute(result.template_attribute,
                                       TemplateAttribute, 2,
                                       [[str, 'Cryptographic Length', int,
                                         128],
                                        [str, 'Unique Identifier', str,
                                         None]])

    # def test_symmetric_key_create_v2(self):
    #
    #     object_type = ObjectType.SYMMETRIC_KEY
    #
    #     attribute_type = AttributeType.CRYPTOGRAPHIC_ALGORITHM
    #     algorithm_obj = self.attr_factory.create_attribute(
    #         attribute_type,
    #         CryptoAlgorithmEnum.AES)
    #
    #     mask_flags = [CryptographicUsageMask.ENCRYPT,
    #                   CryptographicUsageMask.DECRYPT]
    #     attribute_type = AttributeType.CRYPTOGRAPHIC_USAGE_MASK
    #     usage_mask = self.attr_factory.create_attribute(attribute_type,
    #                                                     mask_flags)
    #
    #     attribute_type = AttributeType.CRYPTOGRAPHIC_LENGTH
    #     length = 128
    #     length_obj = self.attr_factory.create_attribute(attribute_type,
    #                                                     length)
    #     name = Attribute.AttributeName('Name')
    #     name_value = Name.NameValue('Test Key')
    #     name_type = Name.NameType(NameType.UNINTERPRETED_TEXT_STRING)
    #     value = Name(name_value=name_value, name_type=name_type)
    #     name = Attribute(attribute_name=name, attribute_value=value)
    #
    #     attributes = [algorithm_obj, usage_mask, length_obj, name]
    #     template_attribute = TemplateAttribute(attributes=attributes)
    #
    #     # Create the SYMMETRIC_KEY object
    #     result = self.client.create(object_type, template_attribute,
    #                            credential=None)
    #
    #     # Display operation results
    #     self.logger.debug('create() result status: {0}'.format(
    #         result.result_status.enum))
    #
    #     if result.result_status.enum == ResultStatus.SUCCESS:
    #         self.logger.debug('created object type: {0}'.format(
    #             result.object_type.enum))
    #         self.logger.debug('created UUID: {0}'.format(result.uuid.value))
    #         self.logger.debug('created template attribute: {0}'.
    #                      format(result.template_attribute))
    #     else:
    #         self.logger.debug('create() result reason: {0}'.format(
    #             result.result_reason.enum))
    #         self.logger.debug('create() result message: {0}'.format(
    #             result.result_message.value))
    #
    #     self._check_result_status(result.result_status.enum, ResultStatus,
    #                               ResultStatus.SUCCESS)



    # def test_symmetric_key_register(self):
    #     credential_type = CredentialType.USERNAME_AND_PASSWORD
    #     credential_value = {'Username': 'Peter', 'Password': 'abc123'}
    #     credential = self.cred_factory.create_credential(credential_type,
    #                                                      credential_value)
    #
    #     object_type = ObjectType.SYMMETRIC_KEY
    #     algorithm_value = CryptoAlgorithmEnum.AES
    #     mask_flags = [CryptographicUsageMask.ENCRYPT,
    #                   CryptographicUsageMask.DECRYPT]
    #     attribute_type = AttributeType.CRYPTOGRAPHIC_USAGE_MASK
    #     usage_mask = self.attr_factory.create_attribute(attribute_type,
    #                                                     mask_flags)
    #     attributes = [usage_mask]
    #     template_attribute = TemplateAttribute(attributes=attributes)
    #
    #     key_format_type = KeyFormatType(KeyFormatTypeEnum.RAW)
    #
    #     key_data = (
    #         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    #         b'\x00')
    #
    #     key_material = KeyMaterial(key_data)
    #     key_value = KeyValue(key_material)
    #     cryptographic_algorithm = CryptographicAlgorithm(algorithm_value)
    #     cryptographic_length = CryptographicLength(128)
    #
    #     key_block = KeyBlock(
    #         key_format_type=key_format_type,
    #         key_compression_type=None,
    #         key_value=key_value,
    #         cryptographic_algorithm=cryptographic_algorithm,
    #         cryptographic_length=cryptographic_length,
    #         key_wrapping_data=None)
    #
    #     secret = SymmetricKey(key_block)
    #
    #     result = self.client.register(object_type, template_attribute, secret,
    #                                   credential)
    #
    #     self._check_result_status(result.result_status.enum, ResultStatus,
    #                               ResultStatus.SUCCESS)
    #     self._check_uuid(result.uuid.value, str)
    #
    #     # Check the template attribute type
    #     self._check_template_attribute(result.template_attribute,
    #                                    TemplateAttribute, 1,
    #                                    [[str, 'Unique Identifier', str,
    #                                      None]])
    #     # Check that the returned key bytes match what was provided
    #     uuid = result.uuid.value
    #     result = self.client.get(uuid=uuid, credential=credential)
    #
    #     self._check_result_status(result.result_status.enum, ResultStatus,
    #                               ResultStatus.SUCCESS)
    #     self._check_object_type(result.object_type.enum, ObjectType,
    #                             ObjectType.SYMMETRIC_KEY)
    #     self._check_uuid(result.uuid.value, str)
    #
    #     # Check the secret type
    #     secret = result.secret
    #
    #     expected = SymmetricKey
    #     message = utils.build_er_error(result.__class__, 'type', expected,
    #                                    secret, 'secret')
    #     self.assertIsInstance(secret, expected, message)
    #
    #     key_block = result.secret.key_block
    #     key_value = key_block.key_value
    #     key_material = key_value.key_material
    #
    #     expected = key_data
    #     observed = key_material.value
    #     message = utils.build_er_error(key_material.__class__, 'value',
    #                                    expected, observed, 'value')
    #     self.assertEqual(expected, observed, message)
    #
    #
    # def test_symmetric_key_get(self):
    #     credential_type = CredentialType.USERNAME_AND_PASSWORD
    #     credential_value = {'Username': 'Peter', 'Password': 'abc123'}
    #     credential = self.cred_factory.create_credential(credential_type,
    #                                                      credential_value)
    #     result = self._create_symmetric_key()
    #     uuid = result.uuid.value
    #
    #     result = self.client.get(uuid=uuid, credential=credential)
    #
    #     self._check_result_status(result.result_status.enum, ResultStatus,
    #                               ResultStatus.SUCCESS)
    #     self._check_object_type(result.object_type.enum, ObjectType,
    #                             ObjectType.SYMMETRIC_KEY)
    #     self._check_uuid(result.uuid.value, str)
    #
    #     # Check the secret type
    #     secret = result.secret
    #
    #     expected = SymmetricKey
    #     message = utils.build_er_error(result.__class__, 'type', expected,
    #                                    secret, 'secret')
    #     self.assertIsInstance(secret, expected, message)
    #
    # def test_symmetric_key_destroy(self):
    #     credential_type = CredentialType.USERNAME_AND_PASSWORD
    #     credential_value = {'Username': 'Peter', 'Password': 'abc123'}
    #     credential = self.cred_factory.create_credential(credential_type,
    #                                                      credential_value)
    #     result = self._create_symmetric_key()
    #     uuid = result.uuid.value
    #
    #     # Verify the secret was created
    #     result = self.client.get(uuid=uuid, credential=credential)
    #
    #     self._check_result_status(result.result_status.enum, ResultStatus,
    #                               ResultStatus.SUCCESS)
    #     self._check_object_type(result.object_type.enum, ObjectType,
    #                             ObjectType.SYMMETRIC_KEY)
    #     self._check_uuid(result.uuid.value, str)
    #
    #     secret = result.secret
    #
    #     expected = SymmetricKey
    #     message = utils.build_er_error(result.__class__, 'type', expected,
    #                                    secret, 'secret')
    #     self.assertIsInstance(secret, expected, message)
    #
    #     # Destroy the SYMMETRIC_KEY object
    #     result = self.client.destroy(uuid, credential)
    #     self._check_result_status(result.result_status.enum, ResultStatus,
    #                               ResultStatus.SUCCESS)
    #     self._check_uuid(result.uuid.value, str)
    #
    #     # Verify the secret was destroyed
    #     result = self.client.get(uuid=uuid, credential=credential)
    #
    #     self._check_result_status(result.result_status.enum, ResultStatus,
    #                               ResultStatus.OPERATION_FAILED)
    #
    #     expected = ResultReason
    #     observed = type(result.result_reason.enum)
    #     message = utils.build_er_error(result.result_reason.__class__, 'type',
    #                                    expected, observed)
    #     self.assertEqual(expected, observed, message)
    #
    #     expected = ResultReason.ITEM_NOT_FOUND
    #     observed = result.result_reason.enum
    #     message = utils.build_er_error(result.result_reason.__class__,
    #                                    'value', expected, observed)
    #     self.assertEqual(expected, observed, message)
    #
    #
    # def test_private_key_create(self):
    #     pass
    #
    # def test_private_key_register(self):
    #     pass
    #
    # def test_private_key_get(self):
    #     pass
    #
    # def test_private_key_destroy(self):
    #     pass
    #
    # def test_public_key_create(self):
    #     pass
    #
    # def test_public_key_register(self):
    #     pass
    #
    # def test_public_key_get(self):
    #     pass
    #
    # def test_public_key_destroy(self):
    #     pass
