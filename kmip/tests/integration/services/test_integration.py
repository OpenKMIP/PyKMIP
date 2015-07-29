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
from testtools import TestCase

from kmip.core.attributes import CryptographicAlgorithm
from kmip.core.attributes import CryptographicLength
from kmip.core.attributes import Name

from kmip.core.enums import AttributeType
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
from kmip.core.objects import PrivateKeyTemplateAttribute
from kmip.core.objects import PublicKeyTemplateAttribute
from kmip.core.objects import CommonTemplateAttribute

from kmip.core.misc import QueryFunction

from kmip.core.secrets import SymmetricKey
from kmip.core.secrets import PrivateKey
from kmip.core.secrets import PublicKey

import pytest


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

    def _create_symmetric_key(self, key_name=None):
        """
        Helper function for creating symmetric keys. Used any time a key
        needs to be created.
        :param key_name: name of the key to be created
        :return: returns the result of the "create key" operation as
        provided by the KMIP appliance
        """
        object_type = ObjectType.SYMMETRIC_KEY
        attribute_type = AttributeType.CRYPTOGRAPHIC_ALGORITHM
        algorithm = self.attr_factory.create_attribute(attribute_type,
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

        if key_name is None:
            key_name = 'Integration Test - Key'

        name_value = Name.NameValue(key_name)

        name_type = Name.NameType(NameType.UNINTERPRETED_TEXT_STRING)
        value = Name(name_value=name_value, name_type=name_type)
        name = Attribute(attribute_name=name, attribute_value=value)
        attributes = [algorithm, usage_mask, key_length_obj, name]
        template_attribute = TemplateAttribute(attributes=attributes)

        return self.client.create(object_type, template_attribute,
                                  credential=None)

    def _create_key_pair(self, key_name=None):
        """
        Helper function for creating private and public keys. Used any time
        a key pair needs to be created.
        :param key_name: name of the key to be created
        :return: returns the result of the "create key" operation as
        provided by the KMIP appliance
        """
        attribute_type = AttributeType.CRYPTOGRAPHIC_ALGORITHM
        algorithm = self.attr_factory.create_attribute(attribute_type,
                                                       CryptoAlgorithmEnum.RSA)
        mask_flags = [CryptographicUsageMask.ENCRYPT,
                      CryptographicUsageMask.DECRYPT]
        attribute_type = AttributeType.CRYPTOGRAPHIC_USAGE_MASK
        usage_mask = self.attr_factory.create_attribute(attribute_type,
                                                        mask_flags)
        key_length = 2048
        attribute_type = AttributeType.CRYPTOGRAPHIC_LENGTH
        key_length_obj = self.attr_factory.create_attribute(attribute_type,
                                                            key_length)
        name = Attribute.AttributeName('Name')

        if key_name is None:
            key_name = 'Integration Test - Key'

        priv_name_value = Name.NameValue(key_name + " Private")
        pub_name_value = Name.NameValue(key_name + " Public")
        name_type = Name.NameType(NameType.UNINTERPRETED_TEXT_STRING)
        priv_value = Name(name_value=priv_name_value, name_type=name_type)
        pub_value = Name(name_value=pub_name_value, name_type=name_type)
        priv_name = Attribute(attribute_name=name, attribute_value=priv_value)
        pub_name = Attribute(attribute_name=name, attribute_value=pub_value)

        common_attributes = [algorithm, usage_mask, key_length_obj]
        private_key_attributes = [priv_name]
        public_key_attributes = [pub_name]

        common = CommonTemplateAttribute(attributes=common_attributes)
        priv_templ_attr = PrivateKeyTemplateAttribute(
            attributes=private_key_attributes)
        pub_templ_attr = PublicKeyTemplateAttribute(
            attributes=public_key_attributes)

        return self.client.\
            create_key_pair(common_template_attribute=common,
                            private_key_template_attribute=priv_templ_attr,
                            public_key_template_attribute=pub_templ_attr)

    def _check_result_status(self, result, result_status_type,
                             result_status_value):
        """
        Helper function for checking the status of KMIP appliance actions.
        Verifies the result status type and value.
        :param result: result object
        :param result_status_type: type of result status received
        :param result_status_value: value of the result status
        """

        result_status = result.result_status.enum
        # Error check the result status type and value
        expected = result_status_type

        self.assertIsInstance(result_status, expected)

        expected = result_status_value

        if result_status is ResultStatus.OPERATION_FAILED:
            self.logger.error(result)
            self.logger.error(result.result_reason)
            self.logger.error(result.result_message)
        self.assertEqual(expected, result_status)

    def _check_uuid(self, uuid, uuid_type):
        """
        Helper function for checking UUID type and value for errors
        :param uuid: UUID of a created key
        :param uuid_type: UUID type
        :return:
        """
        # Error check the UUID type and value
        not_expected = None

        self.assertNotEqual(not_expected, uuid)

        expected = uuid_type
        self.assertEqual(expected, type(uuid))

    def _check_object_type(self, object_type, object_type_type,
                           object_type_value):
        """
        Checks the type and value of a given object type.
        :param object_type:
        :param object_type_type:
        :param object_type_value:
        """
        # Error check the object type type and value
        expected = object_type_type

        self.assertIsInstance(object_type, expected)

        expected = object_type_value

        self.assertEqual(expected, object_type)

    def _check_template_attribute(self, template_attribute,
                                  template_attribute_type, num_attributes,
                                  attribute_features):
        """
        Checks the value and type of a given template attribute
        :param template_attribute:
        :param template_attribute_type:
        :param num_attributes:
        :param attribute_features:
        """
        # Error check the template attribute type
        expected = template_attribute_type

        self.assertIsInstance(template_attribute, expected)

        attributes = template_attribute.attributes

        for i in range(num_attributes):
            features = attribute_features[i]
            self._check_attribute(attributes[i], features[0], features[1],
                                  features[2], features[3])

    def _check_attribute(self, attribute, attribute_name_type,
                         attribute_name_value, attribute_value_type,
                         attribute_value_value):
        """
        Checks the value and type of a given attribute
        :param attribute:
        :param attribute_name_type:
        :param attribute_name_value:
        :param attribute_value_type:
        :param attribute_value_value:
        """
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
        """
        Checks the attribute name for a given attribute
        :param attribute_name:
        :param attribute_name_type:
        :param attribute_name_value:
        """
        # Error check the attribute name type and value
        expected = attribute_name_type
        observed = type(attribute_name.value)

        self.assertEqual(expected, observed)

        expected = attribute_name_value
        observed = attribute_name.value

        self.assertEqual(expected, observed)

    def _check_attribute_value(self, attribute_value, attribute_value_type,
                               attribute_value_value):
        """
        Checks the attribute value for a given attribute
        :param attribute_value:
        :param attribute_value_type:
        :param attribute_value_value:
        """
        expected = attribute_value_type
        observed = type(attribute_value.value)

        self.assertEqual(expected, observed)

        expected = attribute_value_value
        observed = attribute_value.value

        self.assertEqual(expected, observed)

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

    def test_symmetric_key_create_get_destroy(self):
        """
        Test that symmetric keys are properly created
        """
        key_name = 'Integration Test - Create-Get-Destroy Key'
        result = self._create_symmetric_key(key_name=key_name)

        self._check_result_status(result, ResultStatus, ResultStatus.SUCCESS)
        self._check_object_type(result.object_type.enum, ObjectType,
                                ObjectType.SYMMETRIC_KEY)
        self._check_uuid(result.uuid.value, str)

        result = self.client.get(uuid=result.uuid.value, credential=None)

        self._check_result_status(result, ResultStatus, ResultStatus.SUCCESS)
        self._check_object_type(result.object_type.enum, ObjectType,
                                ObjectType.SYMMETRIC_KEY)
        self._check_uuid(result.uuid.value, str)

        # Check the secret type
        secret = result.secret

        expected = SymmetricKey
        self.assertIsInstance(secret, expected)

        self.logger.debug('Destroying key: ' + key_name + '\n With UUID: ' +
                          result.uuid.value)

        result = self.client.destroy(result.uuid.value)
        self._check_result_status(result, ResultStatus,
                                  ResultStatus.SUCCESS)
        self._check_uuid(result.uuid.value, str)

        # Verify the secret was destroyed
        result = self.client.get(uuid=result.uuid.value, credential=None)

        self._check_result_status(result, ResultStatus,
                                  ResultStatus.OPERATION_FAILED)

        expected = ResultReason
        observed = type(result.result_reason.enum)

        self.assertEqual(expected, observed)

        expected = ResultReason.ITEM_NOT_FOUND
        observed = result.result_reason.enum

        self.assertEqual(expected, observed)

    def test_symmetric_key_register_get_destroy(self):
        """
        Tests that symmetric keys are properly registered, retrieved,
        and destroyed.
        """
        object_type = ObjectType.SYMMETRIC_KEY
        algorithm_value = CryptoAlgorithmEnum.AES
        mask_flags = [CryptographicUsageMask.ENCRYPT,
                      CryptographicUsageMask.DECRYPT]
        attribute_type = AttributeType.CRYPTOGRAPHIC_USAGE_MASK
        usage_mask = self.attr_factory.create_attribute(attribute_type,
                                                        mask_flags)

        name = Attribute.AttributeName('Name')
        key_name = 'Integration Test - Register-Get-Destroy Key'
        name_value = Name.NameValue(key_name)
        name_type = Name.NameType(NameType.UNINTERPRETED_TEXT_STRING)
        value = Name(name_value=name_value, name_type=name_type)
        name = Attribute(attribute_name=name, attribute_value=value)

        attributes = [usage_mask, name]
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
                                      credential=None)

        self._check_result_status(result, ResultStatus, ResultStatus.SUCCESS)
        self._check_uuid(result.uuid.value, str)

        # Check that the returned key bytes match what was provided
        uuid = result.uuid.value
        result = self.client.get(uuid=uuid, credential=None)

        self._check_result_status(result, ResultStatus, ResultStatus.SUCCESS)
        self._check_object_type(result.object_type.enum, ObjectType,
                                ObjectType.SYMMETRIC_KEY)
        self._check_uuid(result.uuid.value, str)

        # Check the secret type
        secret = result.secret

        expected = SymmetricKey

        self.assertIsInstance(secret, expected)

        key_block = result.secret.key_block
        key_value = key_block.key_value
        key_material = key_value.key_material

        expected = key_data
        observed = key_material.value

        self.assertEqual(expected, observed)

        self.logger.debug('Destroying key: ' + key_name + '\nWith UUID: ' +
                          result.uuid.value)

        result = self.client.destroy(result.uuid.value)
        self._check_result_status(result, ResultStatus,
                                  ResultStatus.SUCCESS)
        self._check_uuid(result.uuid.value, str)

        # Verify the secret was destroyed
        result = self.client.get(uuid=uuid, credential=None)

        self._check_result_status(result, ResultStatus,
                                  ResultStatus.OPERATION_FAILED)

        expected = ResultReason
        observed = type(result.result_reason.enum)

        self.assertEqual(expected, observed)

        expected = ResultReason.ITEM_NOT_FOUND
        observed = result.result_reason.enum

        self.assertEqual(expected, observed)

    def test_key_pair_create_get_destroy(self):
        """
        Test that key pairs are properly created, retrieved, and destroyed.
        """
        key_name = 'Integration Test - Create-Get-Destroy Key Pair -'
        result = self._create_key_pair(key_name=key_name)

        self._check_result_status(result, ResultStatus, ResultStatus.SUCCESS)

        # Check UUID value for Private key
        self._check_uuid(result.private_key_uuid.value, str)
        # Check UUID value for Public key
        self._check_uuid(result.public_key_uuid.value, str)

        priv_key_uuid = result.private_key_uuid.value
        pub_key_uuid = result.public_key_uuid.value

        priv_key_result = self.client.get(uuid=priv_key_uuid, credential=None)
        pub_key_result = self.client.get(uuid=pub_key_uuid, credential=None)

        self._check_result_status(priv_key_result, ResultStatus,
                                  ResultStatus.SUCCESS)
        self._check_object_type(priv_key_result.object_type.enum, ObjectType,
                                ObjectType.PRIVATE_KEY)

        self._check_uuid(priv_key_result.uuid.value, str)
        self._check_result_status(pub_key_result, ResultStatus,
                                  ResultStatus.SUCCESS)
        self._check_object_type(pub_key_result.object_type.enum, ObjectType,
                                ObjectType.PUBLIC_KEY)

        self._check_uuid(pub_key_result.uuid.value, str)

        # Check the secret type
        priv_secret = priv_key_result.secret
        pub_secret = pub_key_result.secret

        priv_expected = PrivateKey
        pub_expected = PublicKey

        self.assertIsInstance(priv_secret, priv_expected)
        self.assertIsInstance(pub_secret, pub_expected)

        self.logger.debug('Destroying key: ' + key_name + ' Private' +
                          '\n With UUID: ' + result.private_key_uuid.value)
        destroy_priv_key_result = self.client.destroy(
            result.private_key_uuid.value)

        self._check_result_status(destroy_priv_key_result, ResultStatus,
                                  ResultStatus.SUCCESS)

        self.logger.debug('Destroying key: ' + key_name + ' Public' +
                          '\n With UUID: ' + result.public_key_uuid.value)
        destroy_pub_key_result = self.client.destroy(
            result.public_key_uuid.value)
        self._check_result_status(destroy_pub_key_result, ResultStatus,
                                  ResultStatus.SUCCESS)

        priv_key_uuid = destroy_priv_key_result.uuid.value
        pub_key_uuid = destroy_pub_key_result.uuid.value

        self._check_uuid(priv_key_uuid, str)
        self._check_uuid(pub_key_uuid, str)

        # Verify the secret was destroyed
        priv_key_destroyed_result = self.client.get(uuid=priv_key_uuid)
        pub_key_destroyed_result = self.client.get(uuid=pub_key_uuid)

        self._check_result_status(priv_key_destroyed_result, ResultStatus,
                                  ResultStatus.OPERATION_FAILED)
        self._check_result_status(pub_key_destroyed_result, ResultStatus,
                                  ResultStatus.OPERATION_FAILED)

        expected = ResultReason
        observed_priv = type(priv_key_destroyed_result.result_reason.enum)
        observed_pub = type(pub_key_destroyed_result.result_reason.enum)

        self.assertEqual(expected, observed_priv)
        self.assertEqual(expected, observed_pub)

    def test_private_key_register_get_destroy(self):
        """
        Tests that private keys are properly registered, retrieved,
        and destroyed.
        """
        priv_key_object_type = ObjectType.PRIVATE_KEY

        mask_flags = [CryptographicUsageMask.ENCRYPT,
                      CryptographicUsageMask.DECRYPT]
        attribute_type = AttributeType.CRYPTOGRAPHIC_USAGE_MASK
        usage_mask = self.attr_factory.create_attribute(attribute_type,
                                                        mask_flags)

        name = Attribute.AttributeName('Name')
        key_name = 'Integration Test - Register-Get-Destroy Key -'

        priv_name_value = Name.NameValue(key_name + " Private")

        name_type = Name.NameType(NameType.UNINTERPRETED_TEXT_STRING)
        priv_value = Name(name_value=priv_name_value, name_type=name_type)

        priv_name = Attribute(attribute_name=name, attribute_value=priv_value)

        priv_key_attributes = [usage_mask, priv_name]

        private_template_attribute = TemplateAttribute(
            attributes=priv_key_attributes)

        key_format_type = KeyFormatType(KeyFormatTypeEnum.RAW)

        key_data = (
            b'\x30\x82\x02\x76\x02\x01\x00\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7'
            b'\x0D\x01\x01\x01\x05\x00\x04\x82\x02\x60\x30\x82\x02\x5C\x02\x01'
            b'\x00\x02\x81\x81\x00\x93\x04\x51\xC9\xEC\xD9\x4F\x5B\xB9\xDA\x17'
            b'\xDD\x09\x38\x1B\xD2\x3B\xE4\x3E\xCA\x8C\x75\x39\xF3\x01\xFC\x8A'
            b'\x8C\xD5\xD5\x27\x4C\x3E\x76\x99\xDB\xDC\x71\x1C\x97\xA7\xAA\x91'
            b'\xE2\xC5\x0A\x82\xBD\x0B\x10\x34\xF0\xDF\x49\x3D\xEC\x16\x36\x24'
            b'\x27\xE5\x8A\xCC\xE7\xF6\xCE\x0F\x9B\xCC\x61\x7B\xBD\x8C\x90\xD0'
            b'\x09\x4A\x27\x03\xBA\x0D\x09\xEB\x19\xD1\x00\x5F\x2F\xB2\x65\x52'
            b'\x6A\xAC\x75\xAF\x32\xF8\xBC\x78\x2C\xDE\xD2\xA5\x7F\x81\x1E\x03'
            b'\xEA\xF6\x7A\x94\x4D\xE5\xE7\x84\x13\xDC\xA8\xF2\x32\xD0\x74\xE6'
            b'\xDC\xEA\x4C\xEC\x9F\x02\x03\x01\x00\x01\x02\x81\x80\x0B\x6A\x7D'
            b'\x73\x61\x99\xEA\x48\xA4\x20\xE4\x53\x7C\xA0\xC7\xC0\x46\x78\x4D'
            b'\xCB\xEA\xA6\x3B\xAE\xBC\x0B\xC1\x32\x78\x74\x49\xCD\xE8\xD7\xCA'
            b'\xD0\xC0\xC8\x63\xC0\xFE\xFB\x06\xC3\x06\x2B\xEF\xC5\x00\x33\xEC'
            b'\xF8\x7B\x4E\x33\xA9\xBE\x7B\xCB\xC8\xF1\x51\x1A\xE2\x15\xE8\x0D'
            b'\xEB\x5D\x8A\xF2\xBD\x31\x31\x9D\x78\x21\x19\x66\x40\x93\x5A\x0C'
            b'\xD6\x7C\x94\x59\x95\x79\xF2\x10\x0D\x65\xE0\x38\x83\x1F\xDA\xFB'
            b'\x0D\xBE\x2B\xBD\xAC\x00\xA6\x96\xE6\x7E\x75\x63\x50\xE1\xC9\x9A'
            b'\xCE\x11\xA3\x6D\xAB\xAC\x3E\xD3\xE7\x30\x96\x00\x59\x02\x41\x00'
            b'\xDD\xF6\x72\xFB\xCC\x5B\xDA\x3D\x73\xAF\xFC\x4E\x79\x1E\x0C\x03'
            b'\x39\x02\x24\x40\x5D\x69\xCC\xAA\xBC\x74\x9F\xAA\x0D\xCD\x4C\x25'
            b'\x83\xC7\x1D\xDE\x89\x41\xA7\xB9\xAA\x03\x0F\x52\xEF\x14\x51\x46'
            b'\x6C\x07\x4D\x4D\x33\x8F\xE6\x77\x89\x2A\xCD\x9E\x10\xFD\x35\xBD'
            b'\x02\x41\x00\xA9\x8F\xBC\x3E\xD6\xB4\xC6\xF8\x60\xF9\x71\x65\xAC'
            b'\x2F\x7B\xB6\xF2\xE2\xCB\x19\x2A\x9A\xBD\x49\x79\x5B\xE5\xBC\xF3'
            b'\x7D\x8E\xE6\x9A\x6E\x16\x9C\x24\xE5\xC3\x2E\x4E\x7F\xA3\x32\x65'
            b'\x46\x14\x07\xF9\x52\xBA\x49\xE2\x04\x81\x8A\x2F\x78\x5F\x11\x3F'
            b'\x92\x2B\x8B\x02\x40\x25\x3F\x94\x70\x39\x0D\x39\x04\x93\x03\x77'
            b'\x7D\xDB\xC9\x75\x0E\x9D\x64\x84\x9C\xE0\x90\x3E\xAE\x70\x4D\xC9'
            b'\xF5\x89\xB7\x68\x0D\xEB\x9D\x60\x9F\xD5\xBC\xD4\xDE\xCD\x6F\x12'
            b'\x05\x42\xE5\xCF\xF5\xD7\x6F\x2A\x43\xC8\x61\x5F\xB5\xB3\xA9\x21'
            b'\x34\x63\x79\x7A\xA9\x02\x41\x00\xA1\xDD\xF0\x23\xC0\xCD\x94\xC0'
            b'\x19\xBB\x26\xD0\x9B\x9E\x3C\xA8\xFA\x97\x1C\xB1\x6A\xA5\x8B\x9B'
            b'\xAF\x79\xD6\x08\x1A\x1D\xBB\xA4\x52\xBA\x53\x65\x3E\x28\x04\xBA'
            b'\x98\xFF\x69\xE8\xBB\x1B\x3A\x16\x1E\xA2\x25\xEA\x50\x14\x63\x21'
            b'\x6A\x8D\xAB\x9B\x88\xA7\x5E\x5F\x02\x40\x61\x78\x64\x6E\x11\x2C'
            b'\xF7\x9D\x92\x1A\x8A\x84\x3F\x17\xF6\xE7\xFF\x97\x4F\x68\x81\x22'
            b'\x36\x5B\xF6\x69\x0C\xDF\xC9\x96\xE1\x89\x09\x52\xEB\x38\x20\xDD'
            b'\x18\x90\xEC\x1C\x86\x19\xE8\x7A\x2B\xD3\x8F\x9D\x03\xB3\x7F\xAC'
            b'\x74\x2E\xFB\x74\x8C\x78\x85\x94\x2C\x39')

        key_material = KeyMaterial(key_data)
        key_value = KeyValue(key_material)

        algorithm_value = CryptoAlgorithmEnum.RSA
        cryptographic_algorithm = CryptographicAlgorithm(algorithm_value)
        cryptographic_length = CryptographicLength(2048)

        key_block = KeyBlock(
            key_format_type=key_format_type,
            key_compression_type=None,
            key_value=key_value,
            cryptographic_algorithm=cryptographic_algorithm,
            cryptographic_length=cryptographic_length,
            key_wrapping_data=None)

        priv_secret = PrivateKey(key_block)

        priv_key_result = self.client.register(priv_key_object_type,
                                               private_template_attribute,
                                               priv_secret, credential=None)

        self._check_result_status(priv_key_result, ResultStatus,
                                  ResultStatus.SUCCESS)

        self._check_uuid(priv_key_result.uuid.value, str)

        # Check that the returned key bytes match what was provided
        priv_uuid = priv_key_result.uuid.value

        priv_key_result = self.client.get(uuid=priv_uuid, credential=None)

        self._check_result_status(priv_key_result, ResultStatus,
                                  ResultStatus.SUCCESS)

        self._check_object_type(priv_key_result.object_type.enum, ObjectType,
                                ObjectType.PRIVATE_KEY)

        self._check_uuid(priv_key_result.uuid.value, str)

        # Check the secret type
        priv_secret = priv_key_result.secret

        priv_expected = PrivateKey

        self.assertIsInstance(priv_secret, priv_expected)

        priv_key_block = priv_key_result.secret.key_block
        priv_key_value = priv_key_block.key_value
        priv_key_material = priv_key_value.key_material

        expected = key_data

        priv_observed = priv_key_material.value

        self.assertEqual(expected, priv_observed)

        self.logger.debug('Destroying key: ' + key_name + " Private" +
                          '\nWith " "UUID: ' + priv_key_result.uuid.value)

        priv_result = self.client.destroy(priv_key_result.uuid.value)

        self._check_result_status(priv_result, ResultStatus,
                                  ResultStatus.SUCCESS)

        self._check_uuid(priv_result.uuid.value, str)

        # Verify the secret was destroyed
        priv_key_destroyed_result = self.client.get(uuid=priv_uuid,
                                                    credential=None)

        self._check_result_status(priv_key_destroyed_result, ResultStatus,
                                  ResultStatus.OPERATION_FAILED)

        expected = ResultReason
        priv_observed = type(priv_key_destroyed_result.result_reason.enum)

        self.assertEqual(expected, priv_observed)

    def test_public_key_register_get_destroy(self):
        """
        Tests that public keys are properly registered, retrieved,
        and destroyed.
        """
        pub_key_object_type = ObjectType.PUBLIC_KEY
        mask_flags = [CryptographicUsageMask.ENCRYPT,
                      CryptographicUsageMask.DECRYPT]
        attribute_type = AttributeType.CRYPTOGRAPHIC_USAGE_MASK
        usage_mask = self.attr_factory.create_attribute(attribute_type,
                                                        mask_flags)

        name = Attribute.AttributeName('Name')
        key_name = 'Integration Test - Register-Get-Destroy Key -'

        pub_name_value = Name.NameValue(key_name + " Public")
        name_type = Name.NameType(NameType.UNINTERPRETED_TEXT_STRING)
        pub_value = Name(name_value=pub_name_value, name_type=name_type)
        pub_name = Attribute(attribute_name=name, attribute_value=pub_value)
        pub_key_attributes = [usage_mask, pub_name]
        public_template_attribute = TemplateAttribute(
            attributes=pub_key_attributes)
        key_format_type = KeyFormatType(KeyFormatTypeEnum.RAW)
        key_data = (
            b'\x30\x81\x9F\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01'
            b'\x05\x00\x03\x81\x8D\x00\x30\x81\x89\x02\x81\x81\x00\x93\x04\x51'
            b'\xC9\xEC\xD9\x4F\x5B\xB9\xDA\x17\xDD\x09\x38\x1B\xD2\x3B\xE4\x3E'
            b'\xCA\x8C\x75\x39\xF3\x01\xFC\x8A\x8C\xD5\xD5\x27\x4C\x3E\x76\x99'
            b'\xDB\xDC\x71\x1C\x97\xA7\xAA\x91\xE2\xC5\x0A\x82\xBD\x0B\x10\x34'
            b'\xF0\xDF\x49\x3D\xEC\x16\x36\x24\x27\xE5\x8A\xCC\xE7\xF6\xCE\x0F'
            b'\x9B\xCC\x61\x7B\xBD\x8C\x90\xD0\x09\x4A\x27\x03\xBA\x0D\x09\xEB'
            b'\x19\xD1\x00\x5F\x2F\xB2\x65\x52\x6A\xAC\x75\xAF\x32\xF8\xBC\x78'
            b'\x2C\xDE\xD2\xA5\x7F\x81\x1E\x03\xEA\xF6\x7A\x94\x4D\xE5\xE7\x84'
            b'\x13\xDC\xA8\xF2\x32\xD0\x74\xE6\xDC\xEA\x4C\xEC\x9F\x02\x03\x01'
            b'\x00\x01')

        key_material = KeyMaterial(key_data)
        key_value = KeyValue(key_material)

        algorithm_value = CryptoAlgorithmEnum.RSA
        cryptographic_algorithm = CryptographicAlgorithm(algorithm_value)
        cryptographic_length = CryptographicLength(2048)

        key_block = KeyBlock(
            key_format_type=key_format_type,
            key_compression_type=None,
            key_value=key_value,
            cryptographic_algorithm=cryptographic_algorithm,
            cryptographic_length=cryptographic_length,
            key_wrapping_data=None)
        pub_secret = PublicKey(key_block)

        pub_key_result = self.client.register(pub_key_object_type,
                                              public_template_attribute,
                                              pub_secret, credential=None)
        self._check_result_status(pub_key_result, ResultStatus,
                                  ResultStatus.SUCCESS)
        # Check that the returned key bytes match what was provided
        pub_uuid = pub_key_result.uuid.value
        pub_key_result = self.client.get(uuid=pub_uuid, credential=None)
        self._check_result_status(pub_key_result, ResultStatus,
                                  ResultStatus.SUCCESS)

        self._check_object_type(pub_key_result.object_type.enum, ObjectType,
                                ObjectType.PUBLIC_KEY)
        self._check_uuid(pub_key_result.uuid.value, str)

        # Check the secret type
        pub_secret = pub_key_result.secret
        pub_expected = PublicKey
        self.assertIsInstance(pub_secret, pub_expected)

        pub_key_block = pub_key_result.secret.key_block
        pub_key_value = pub_key_block.key_value
        pub_key_material = pub_key_value.key_material

        expected = key_data
        pub_observed = pub_key_material.value
        self.assertEqual(expected, pub_observed)

        self.logger.debug('Destroying key: ' + key_name + " Public" +
                          '\nWith " "UUID: ' + pub_key_result.uuid.value)
        pub_result = self.client.destroy(pub_key_result.uuid.value)

        self._check_result_status(pub_result, ResultStatus,
                                  ResultStatus.SUCCESS)
        self._check_uuid(pub_result.uuid.value, str)

        pub_key_destroyed_result = self.client.get(uuid=pub_uuid,
                                                   credential=None)
        self._check_result_status(pub_key_destroyed_result, ResultStatus,
                                  ResultStatus.OPERATION_FAILED)
        expected = ResultReason
        pub_observed = type(pub_key_destroyed_result.result_reason.enum)

        self.assertEqual(expected, pub_observed)
