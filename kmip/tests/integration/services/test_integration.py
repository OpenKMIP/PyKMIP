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
import testtools
import time

from kmip.core.attributes import CryptographicAlgorithm
from kmip.core.attributes import CryptographicLength
from kmip.core.attributes import Name

from kmip.core import enums
from kmip.core.enums import AttributeType
from kmip.core.enums import CryptographicAlgorithm as CryptoAlgorithmEnum
from kmip.core.enums import CryptographicUsageMask
from kmip.core.enums import KeyFormatType as KeyFormatTypeEnum
from kmip.core.enums import CertificateType
from kmip.core.enums import NameType
from kmip.core.enums import ObjectType
from kmip.core.enums import OpaqueDataType
from kmip.core.enums import SecretDataType
from kmip.core.enums import ResultStatus
from kmip.core.enums import ResultReason
from kmip.core.enums import QueryFunction

from kmip.core.factories.attributes import AttributeFactory
from kmip.core.factories.credentials import CredentialFactory
from kmip.core.factories.secrets import SecretFactory

from kmip.core.messages import payloads
from kmip.core.misc import KeyFormatType

from kmip.core.objects import Attribute
from kmip.core.objects import KeyBlock
from kmip.core.objects import KeyMaterial
from kmip.core.objects import KeyValue
from kmip.core.objects import TemplateAttribute

from kmip.core.secrets import SymmetricKey
from kmip.core.secrets import PrivateKey
from kmip.core.secrets import PublicKey
from kmip.core.secrets import Certificate
from kmip.core.secrets import SecretData
from kmip.core.secrets import OpaqueObject
from kmip.core.secrets import SplitKey

@pytest.mark.usefixtures("client")
class TestIntegration(testtools.TestCase):

    def setUp(self):
        super(TestIntegration, self).setUp()

        self.logger = logging.getLogger(__name__)

        self.attr_factory = AttributeFactory()
        self.cred_factory = CredentialFactory()
        self.secret_factory = SecretFactory()

    def tearDown(self):
        super(TestIntegration, self).tearDown()

        result = self.client.locate()
        if result.result_status.value == ResultStatus.SUCCESS:
            for uuid in result.uuids:
                self.client.destroy(uuid=uuid)

    def _create_symmetric_key(self, key_name=None):
        """
        Helper function for creating symmetric keys. Used any time a key
        needs to be created.
        :param key_name: name of the key to be created
        :return: returns the result of the "create key" operation as
        provided by the KMIP appliance
        """
        cryptographic_algorithm = self.attr_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
            enums.CryptographicAlgorithm.AES
        )
        cryptographic_usage_mask = self.attr_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
            [
                enums.CryptographicUsageMask.ENCRYPT,
                enums.CryptographicUsageMask.DECRYPT
            ]
        )
        cryptographic_length = self.attr_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
            128
        )
        if key_name is None:
            key_name = "Integration Test - Key"
        name = self.attr_factory.create_attribute(
            enums.AttributeType.NAME,
            key_name
        )
        object_group = self.attr_factory.create_attribute(
            enums.AttributeType.OBJECT_GROUP,
            "IntegrationTestKeys"
        )
        application_specific_information = self.attr_factory.create_attribute(
            enums.AttributeType.APPLICATION_SPECIFIC_INFORMATION,
            {
                "application_namespace": "ssl",
                "application_data": "www.example.com"
            }
        )

        attributes = [
            cryptographic_algorithm,
            cryptographic_usage_mask,
            cryptographic_length,
            name,
            object_group,
            application_specific_information
        ]
        template_attribute = TemplateAttribute(attributes=attributes)

        return self.client.create(
            enums.ObjectType.SYMMETRIC_KEY,
            template_attribute,
            credential=None
        )

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

        common = TemplateAttribute(
            attributes=common_attributes,
            tag=enums.Tags.COMMON_TEMPLATE_ATTRIBUTE
        )
        priv_templ_attr = TemplateAttribute(
            attributes=private_key_attributes,
            tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
        )
        pub_templ_attr = TemplateAttribute(
            attributes=public_key_attributes,
            tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
        )

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

        result_status = result.result_status.value
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
        observed = result.result_status.value

        self.assertEqual(expected, observed)

    def test_query(self):
        # Build query function list, asking for all server data.
        query_functions = list(
            [
                QueryFunction.QUERY_OPERATIONS,
                QueryFunction.QUERY_OBJECTS,
                QueryFunction.QUERY_SERVER_INFORMATION,
                QueryFunction.QUERY_APPLICATION_NAMESPACES,
                QueryFunction.QUERY_EXTENSION_LIST,
                QueryFunction.QUERY_EXTENSION_MAP
            ]
        )

        result = self.client.query(query_functions=query_functions)

        expected = ResultStatus.SUCCESS
        observed = result.result_status.value

        self.assertEqual(expected, observed)

    def test_symmetric_key_create_get_destroy(self):
        """
        Test that symmetric keys are properly created
        """
        key_name = 'Integration Test - Create-Get-Destroy Key'
        result = self._create_symmetric_key(key_name=key_name)

        self._check_result_status(result, ResultStatus, ResultStatus.SUCCESS)
        self._check_object_type(result.object_type, ObjectType,
                                ObjectType.SYMMETRIC_KEY)
        self._check_uuid(result.uuid, str)

        result = self.client.get(uuid=result.uuid, credential=None)

        self._check_result_status(result, ResultStatus, ResultStatus.SUCCESS)
        self._check_object_type(result.object_type, ObjectType,
                                ObjectType.SYMMETRIC_KEY)
        self._check_uuid(result.uuid, str)

        # Check the secret type
        secret = result.secret

        expected = SymmetricKey
        self.assertIsInstance(secret, expected)

        self.logger.debug('Destroying key: ' + key_name + '\n With UUID: ' +
                          result.uuid)

        result = self.client.destroy(result.uuid)
        self._check_result_status(result, ResultStatus,
                                  ResultStatus.SUCCESS)
        self._check_uuid(result.uuid.value, str)

        # Verify the secret was destroyed
        result = self.client.get(uuid=result.uuid.value, credential=None)

        self._check_result_status(result, ResultStatus,
                                  ResultStatus.OPERATION_FAILED)

        expected = ResultReason
        observed = type(result.result_reason.value)

        self.assertEqual(expected, observed)

        expected = ResultReason.ITEM_NOT_FOUND
        observed = result.result_reason.value

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
        self._check_uuid(result.uuid, str)

        # Check that the returned key bytes match what was provided
        uuid = result.uuid
        result = self.client.get(uuid=uuid, credential=None)

        self._check_result_status(result, ResultStatus, ResultStatus.SUCCESS)
        self._check_object_type(result.object_type, ObjectType,
                                ObjectType.SYMMETRIC_KEY)
        self._check_uuid(result.uuid, str)

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
                          result.uuid)

        result = self.client.destroy(result.uuid)
        self._check_result_status(result, ResultStatus,
                                  ResultStatus.SUCCESS)
        self._check_uuid(result.uuid.value, str)

        # Verify the secret was destroyed
        result = self.client.get(uuid=uuid, credential=None)

        self._check_result_status(result, ResultStatus,
                                  ResultStatus.OPERATION_FAILED)

        expected = ResultReason
        observed = type(result.result_reason.value)

        self.assertEqual(expected, observed)

        expected = ResultReason.ITEM_NOT_FOUND
        observed = result.result_reason.value

        self.assertEqual(expected, observed)

    def test_key_pair_create_get_destroy(self):
        """
        Test that key pairs are properly created, retrieved, and destroyed.
        """
        key_name = 'Integration Test - Create-Get-Destroy Key Pair -'
        result = self._create_key_pair(key_name=key_name)

        self._check_result_status(result, ResultStatus, ResultStatus.SUCCESS)

        # Check UUID value for Private key
        self._check_uuid(result.private_key_uuid, str)
        # Check UUID value for Public key
        self._check_uuid(result.public_key_uuid, str)

        priv_key_uuid = result.private_key_uuid
        pub_key_uuid = result.public_key_uuid

        priv_key_result = self.client.get(uuid=priv_key_uuid, credential=None)
        pub_key_result = self.client.get(uuid=pub_key_uuid, credential=None)

        self._check_result_status(priv_key_result, ResultStatus,
                                  ResultStatus.SUCCESS)
        self._check_object_type(priv_key_result.object_type, ObjectType,
                                ObjectType.PRIVATE_KEY)

        self._check_uuid(priv_key_result.uuid, str)
        self._check_result_status(pub_key_result, ResultStatus,
                                  ResultStatus.SUCCESS)
        self._check_object_type(pub_key_result.object_type, ObjectType,
                                ObjectType.PUBLIC_KEY)

        self._check_uuid(pub_key_result.uuid, str)

        # Check the secret type
        priv_secret = priv_key_result.secret
        pub_secret = pub_key_result.secret

        priv_expected = PrivateKey
        pub_expected = PublicKey

        self.assertIsInstance(priv_secret, priv_expected)
        self.assertIsInstance(pub_secret, pub_expected)

        self.logger.debug('Destroying key: ' + key_name + ' Private' +
                          '\n With UUID: ' + result.private_key_uuid)
        destroy_priv_key_result = self.client.destroy(
            result.private_key_uuid)

        self._check_result_status(destroy_priv_key_result, ResultStatus,
                                  ResultStatus.SUCCESS)

        self.logger.debug('Destroying key: ' + key_name + ' Public' +
                          '\n With UUID: ' + result.public_key_uuid)
        destroy_pub_key_result = self.client.destroy(
            result.public_key_uuid)
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
        observed_priv = type(priv_key_destroyed_result.result_reason.value)
        observed_pub = type(pub_key_destroyed_result.result_reason.value)

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

        self._check_uuid(priv_key_result.uuid, str)

        # Check that the returned key bytes match what was provided
        priv_uuid = priv_key_result.uuid

        priv_key_result = self.client.get(uuid=priv_uuid, credential=None)

        self._check_result_status(priv_key_result, ResultStatus,
                                  ResultStatus.SUCCESS)

        self._check_object_type(priv_key_result.object_type, ObjectType,
                                ObjectType.PRIVATE_KEY)

        self._check_uuid(priv_key_result.uuid, str)

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
                          '\nWith " "UUID: ' + priv_key_result.uuid)

        priv_result = self.client.destroy(priv_key_result.uuid)

        self._check_result_status(priv_result, ResultStatus,
                                  ResultStatus.SUCCESS)

        self._check_uuid(priv_result.uuid.value, str)

        # Verify the secret was destroyed
        priv_key_destroyed_result = self.client.get(uuid=priv_uuid,
                                                    credential=None)

        self._check_result_status(priv_key_destroyed_result, ResultStatus,
                                  ResultStatus.OPERATION_FAILED)

        expected = ResultReason
        priv_observed = type(priv_key_destroyed_result.result_reason.value)

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
        pub_uuid = pub_key_result.uuid
        pub_key_result = self.client.get(uuid=pub_uuid, credential=None)
        self._check_result_status(pub_key_result, ResultStatus,
                                  ResultStatus.SUCCESS)

        self._check_object_type(pub_key_result.object_type, ObjectType,
                                ObjectType.PUBLIC_KEY)
        self._check_uuid(pub_key_result.uuid, str)

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
                          '\nWith " "UUID: ' + pub_key_result.uuid)
        pub_result = self.client.destroy(pub_key_result.uuid)

        self._check_result_status(pub_result, ResultStatus,
                                  ResultStatus.SUCCESS)
        self._check_uuid(pub_result.uuid.value, str)

        pub_key_destroyed_result = self.client.get(uuid=pub_uuid,
                                                   credential=None)
        self._check_result_status(pub_key_destroyed_result, ResultStatus,
                                  ResultStatus.OPERATION_FAILED)
        expected = ResultReason
        pub_observed = type(pub_key_destroyed_result.result_reason.value)

        self.assertEqual(expected, pub_observed)

    def test_cert_register_get_destroy(self):
        """
        Tests that certificates are properly registered, retrieved,
        and destroyed.
        """

        # properties copied from test case example :
        # http://docs.oasis-open.org/kmip/testcases/v1.1/cn01/kmip-testcases-v1.1-cn01.html#_Toc333488807

        cert_obj_type = ObjectType.CERTIFICATE

        mask_flags = [CryptographicUsageMask.SIGN,
                      CryptographicUsageMask.VERIFY]
        attribute_type = AttributeType.CRYPTOGRAPHIC_USAGE_MASK
        usage_mask = self.attr_factory.create_attribute(attribute_type,
                                                        mask_flags)

        name = Attribute.AttributeName('Name')
        cert_name = 'Integration Test - Register-Get-Destroy Certificate'

        cert_name_value = Name.NameValue(cert_name)

        name_type = Name.NameType(NameType.UNINTERPRETED_TEXT_STRING)
        cert_value = Name(name_value=cert_name_value, name_type=name_type)

        cert_name_attr = Attribute(attribute_name=name,
                                   attribute_value=cert_value)

        cert_attributes = [usage_mask, cert_name_attr]

        cert_template_attribute = TemplateAttribute(
            attributes=cert_attributes)

        cert_format_type = CertificateType.X_509

        cert_data = (
            b'\x30\x82\x03\x12\x30\x82\x01\xFA\xA0\x03\x02\x01\x02\x02\x01\x01'
            b'\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05\x05\x00\x30'
            b'\x3B\x31\x0B\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x0D'
            b'\x30\x0B\x06\x03\x55\x04\x0A\x13\x04\x54\x45\x53\x54\x31\x0E\x30'
            b'\x0C\x06\x03\x55\x04\x0B\x13\x05\x4F\x41\x53\x49\x53\x31\x0D\x30'
            b'\x0B\x06\x03\x55\x04\x03\x13\x04\x4B\x4D\x49\x50\x30\x1E\x17\x0D'
            b'\x31\x30\x31\x31\x30\x31\x32\x33\x35\x39\x35\x39\x5A\x17\x0D\x32'
            b'\x30\x31\x31\x30\x31\x32\x33\x35\x39\x35\x39\x5A\x30\x3B\x31\x0B'
            b'\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x0D\x30\x0B\x06'
            b'\x03\x55\x04\x0A\x13\x04\x54\x45\x53\x54\x31\x0E\x30\x0C\x06\x03'
            b'\x55\x04\x0B\x13\x05\x4F\x41\x53\x49\x53\x31\x0D\x30\x0B\x06\x03'
            b'\x55\x04\x03\x13\x04\x4B\x4D\x49\x50\x30\x82\x01\x22\x30\x0D\x06'
            b'\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00\x03\x82\x01\x0F'
            b'\x00\x30\x82\x01\x0A\x02\x82\x01\x01\x00\xAB\x7F\x16\x1C\x00\x42'
            b'\x49\x6C\xCD\x6C\x6D\x4D\xAD\xB9\x19\x97\x34\x35\x35\x77\x76\x00'
            b'\x3A\xCF\x54\xB7\xAF\x1E\x44\x0A\xFB\x80\xB6\x4A\x87\x55\xF8\x00'
            b'\x2C\xFE\xBA\x6B\x18\x45\x40\xA2\xD6\x60\x86\xD7\x46\x48\x34\x6D'
            b'\x75\xB8\xD7\x18\x12\xB2\x05\x38\x7C\x0F\x65\x83\xBC\x4D\x7D\xC7'
            b'\xEC\x11\x4F\x3B\x17\x6B\x79\x57\xC4\x22\xE7\xD0\x3F\xC6\x26\x7F'
            b'\xA2\xA6\xF8\x9B\x9B\xEE\x9E\x60\xA1\xD7\xC2\xD8\x33\xE5\xA5\xF4'
            b'\xBB\x0B\x14\x34\xF4\xE7\x95\xA4\x11\x00\xF8\xAA\x21\x49\x00\xDF'
            b'\x8B\x65\x08\x9F\x98\x13\x5B\x1C\x67\xB7\x01\x67\x5A\xBD\xBC\x7D'
            b'\x57\x21\xAA\xC9\xD1\x4A\x7F\x08\x1F\xCE\xC8\x0B\x64\xE8\xA0\xEC'
            b'\xC8\x29\x53\x53\xC7\x95\x32\x8A\xBF\x70\xE1\xB4\x2E\x7B\xB8\xB7'
            b'\xF4\xE8\xAC\x8C\x81\x0C\xDB\x66\xE3\xD2\x11\x26\xEB\xA8\xDA\x7D'
            b'\x0C\xA3\x41\x42\xCB\x76\xF9\x1F\x01\x3D\xA8\x09\xE9\xC1\xB7\xAE'
            b'\x64\xC5\x41\x30\xFB\xC2\x1D\x80\xE9\xC2\xCB\x06\xC5\xC8\xD7\xCC'
            b'\xE8\x94\x6A\x9A\xC9\x9B\x1C\x28\x15\xC3\x61\x2A\x29\xA8\x2D\x73'
            b'\xA1\xF9\x93\x74\xFE\x30\xE5\x49\x51\x66\x2A\x6E\xDA\x29\xC6\xFC'
            b'\x41\x13\x35\xD5\xDC\x74\x26\xB0\xF6\x05\x02\x03\x01\x00\x01\xA3'
            b'\x21\x30\x1F\x30\x1D\x06\x03\x55\x1D\x0E\x04\x16\x04\x14\x04\xE5'
            b'\x7B\xD2\xC4\x31\xB2\xE8\x16\xE1\x80\xA1\x98\x23\xFA\xC8\x58\x27'
            b'\x3F\x6B\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05\x05'
            b'\x00\x03\x82\x01\x01\x00\xA8\x76\xAD\xBC\x6C\x8E\x0F\xF0\x17\x21'
            b'\x6E\x19\x5F\xEA\x76\xBF\xF6\x1A\x56\x7C\x9A\x13\xDC\x50\xD1\x3F'
            b'\xEC\x12\xA4\x27\x3C\x44\x15\x47\xCF\xAB\xCB\x5D\x61\xD9\x91\xE9'
            b'\x66\x31\x9D\xF7\x2C\x0D\x41\xBA\x82\x6A\x45\x11\x2F\xF2\x60\x89'
            b'\xA2\x34\x4F\x4D\x71\xCF\x7C\x92\x1B\x4B\xDF\xAE\xF1\x60\x0D\x1B'
            b'\xAA\xA1\x53\x36\x05\x7E\x01\x4B\x8B\x49\x6D\x4F\xAE\x9E\x8A\x6C'
            b'\x1D\xA9\xAE\xB6\xCB\xC9\x60\xCB\xF2\xFA\xE7\x7F\x58\x7E\xC4\xBB'
            b'\x28\x20\x45\x33\x88\x45\xB8\x8D\xD9\xAE\xEA\x53\xE4\x82\xA3\x6E'
            b'\x73\x4E\x4F\x5F\x03\xB9\xD0\xDF\xC4\xCA\xFC\x6B\xB3\x4E\xA9\x05'
            b'\x3E\x52\xBD\x60\x9E\xE0\x1E\x86\xD9\xB0\x9F\xB5\x11\x20\xC1\x98'
            b'\x34\xA9\x97\xB0\x9C\xE0\x8D\x79\xE8\x13\x11\x76\x2F\x97\x4B\xB1'
            b'\xC8\xC0\x91\x86\xC4\xD7\x89\x33\xE0\xDB\x38\xE9\x05\x08\x48\x77'
            b'\xE1\x47\xC7\x8A\xF5\x2F\xAE\x07\x19\x2F\xF1\x66\xD1\x9F\xA9\x4A'
            b'\x11\xCC\x11\xB2\x7E\xD0\x50\xF7\xA2\x7F\xAE\x13\xB2\x05\xA5\x74'
            b'\xC4\xEE\x00\xAA\x8B\xD6\x5D\x0D\x70\x57\xC9\x85\xC8\x39\xEF\x33'
            b'\x6A\x44\x1E\xD5\x3A\x53\xC6\xB6\xB6\x96\xF1\xBD\xEB\x5F\x7E\xA8'
            b'\x11\xEB\xB2\x5A\x7F\x86')

        cert_obj = Certificate(cert_format_type, cert_data)

        cert_result = self.client.register(cert_obj_type,
                                           cert_template_attribute,
                                           cert_obj, credential=None)

        self._check_result_status(cert_result, ResultStatus,
                                  ResultStatus.SUCCESS)

        self._check_uuid(cert_result.uuid, str)

        # Check that the returned key bytes match what was provided
        cert_uuid = cert_result.uuid

        cert_result = self.client.get(uuid=cert_uuid, credential=None)

        self._check_result_status(cert_result, ResultStatus,
                                  ResultStatus.SUCCESS)

        self._check_object_type(cert_result.object_type, ObjectType,
                                ObjectType.CERTIFICATE)

        self._check_uuid(cert_result.uuid, str)

        # Check the secret type
        cert_secret = cert_result.secret

        cert_secret_expected = Certificate

        self.assertIsInstance(cert_secret, cert_secret_expected)

        cert_material = cert_result.secret.certificate_value.value

        expected = cert_data

        self.assertEqual(expected, cert_material)

        self.logger.debug('Destroying cert: ' + cert_name +
                          '\nWith " "UUID: ' + cert_result.uuid)

        cert_result = self.client.destroy(cert_result.uuid)

        self._check_result_status(cert_result, ResultStatus,
                                  ResultStatus.SUCCESS)

        self._check_uuid(cert_result.uuid.value, str)

        # Verify the secret was destroyed
        cert_result_destroyed_result = self.client.get(uuid=cert_uuid,
                                                       credential=None)

        self._check_result_status(cert_result_destroyed_result, ResultStatus,
                                  ResultStatus.OPERATION_FAILED)

        expected = ResultReason
        cert_observed = type(cert_result_destroyed_result.result_reason.value)

        self.assertEqual(expected, cert_observed)

    def test_passphrase_register_get_destroy(self):
        """
        Tests that passphrases can be properly registered, retrieved,
        and destroyed
        """

        # properties copied from test case example :
        # http://docs.oasis-open.org/kmip/testcases/v1.1/cn01/kmip-testcases-v1.1-cn01.html#_Toc333488777

        pass_obj_type = ObjectType.SECRET_DATA

        mask_flags = [CryptographicUsageMask.VERIFY]
        attribute_type = AttributeType.CRYPTOGRAPHIC_USAGE_MASK
        usage_mask = self.attr_factory.create_attribute(attribute_type,
                                                        mask_flags)

        name = Attribute.AttributeName('Name')
        pass_name = 'Integration Test - Register-Get-Destroy Passphrase'

        pass_name_value = Name.NameValue(pass_name)

        name_type = Name.NameType(NameType.UNINTERPRETED_TEXT_STRING)
        pass_value = Name(name_value=pass_name_value, name_type=name_type)

        pass_name_attr = Attribute(attribute_name=name,
                                   attribute_value=pass_value)

        pass_attributes = [usage_mask, pass_name_attr]

        pass_template_attribute = TemplateAttribute(
            attributes=pass_attributes)

        pass_format_type = SecretData.SecretDataType(
            SecretDataType.PASSWORD)

        key_format_type = KeyFormatType(KeyFormatTypeEnum.OPAQUE)
        key_data = b'\x70\x65\x65\x6b\x2d\x61\x2d\x62\x6f\x6f\x21\x21'

        key_material = KeyMaterial(key_data)
        key_value = KeyValue(key_material)

        key_block = KeyBlock(
            key_format_type=key_format_type,
            key_compression_type=None,
            key_value=key_value,
            key_wrapping_data=None)

        pass_obj = SecretData(secret_data_type=pass_format_type,
                              key_block=key_block)

        pass_result = self.client.register(pass_obj_type,
                                           pass_template_attribute,
                                           pass_obj, credential=None)

        self._check_result_status(pass_result, ResultStatus,
                                  ResultStatus.SUCCESS)

        self._check_uuid(pass_result.uuid, str)

        # Check that the returned key bytes match what was provided
        pass_uuid = pass_result.uuid

        pass_result = self.client.get(uuid=pass_uuid, credential=None)

        self._check_result_status(pass_result, ResultStatus,
                                  ResultStatus.SUCCESS)

        self._check_object_type(pass_result.object_type, ObjectType,
                                ObjectType.SECRET_DATA)

        self._check_uuid(pass_result.uuid, str)

        # Check the secret type
        pass_secret = pass_result.secret

        pass_secret_expected = SecretData

        self.assertIsInstance(pass_secret, pass_secret_expected)

        pass_material = pass_result.secret.key_block.key_value.key_material\
            .value

        expected = key_data

        self.assertEqual(expected, pass_material)

        self.logger.debug('Destroying cert: ' + pass_name +
                          '\nWith " "UUID: ' + pass_result.uuid)

        pass_result = self.client.destroy(pass_result.uuid)

        self._check_result_status(pass_result, ResultStatus,
                                  ResultStatus.SUCCESS)

        self._check_uuid(pass_result.uuid.value, str)

        # Verify the secret was destroyed
        pass_result_destroyed_result = self.client.get(uuid=pass_uuid,
                                                       credential=None)

        self._check_result_status(pass_result_destroyed_result, ResultStatus,
                                  ResultStatus.OPERATION_FAILED)

        expected = ResultReason
        pass_observed = type(pass_result_destroyed_result.result_reason.value)

        self.assertEqual(expected, pass_observed)

    def test_opaque_data_register_get_destroy(self):
        """
        Tests that opaque objects can be properly registered, retrieved,
        and destroyed
        """

        opaque_obj_type = ObjectType.OPAQUE_DATA
        opaque_obj_data_type = OpaqueObject.OpaqueDataType(OpaqueDataType.NONE)

        name = Attribute.AttributeName('Name')
        opaque_obj_name = 'Integration Test - Register-Get-Destroy Opaque Data'

        opaque_obj_name_value = Name.NameValue(opaque_obj_name)

        name_type = Name.NameType(NameType.UNINTERPRETED_TEXT_STRING)
        opaque_obj_value = Name(name_value=opaque_obj_name_value,
                                name_type=name_type)

        opaque_obj_name_attr = Attribute(attribute_name=name,
                                         attribute_value=opaque_obj_value)

        opaque_obj_attributes = [opaque_obj_name_attr]

        opaque_obj_template_attribute = TemplateAttribute(
            attributes=opaque_obj_attributes)

        opaque_obj_data = OpaqueObject.OpaqueDataValue((
            b'\x30\x82\x03\x12\x30\x82\x01\xFA\xA0\x03\x02\x01\x02\x02\x01\x01'
            b'\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05\x05\x00\x30'
            b'\x3B\x31\x0B\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x0D'
            b'\x30\x0B\x06\x03\x55\x04\x0A\x13\x04\x54\x45\x53\x54\x31\x0E\x30'
        ))

        opaque_obj = OpaqueObject(opaque_data_type=opaque_obj_data_type,
                                  opaque_data_value=opaque_obj_data)

        opaque_obj_result = self.client.register(opaque_obj_type,
                                                 opaque_obj_template_attribute,
                                                 opaque_obj, credential=None)

        self._check_result_status(opaque_obj_result, ResultStatus,
                                  ResultStatus.SUCCESS)

        self._check_uuid(opaque_obj_result.uuid, str)

        # Check that the returned key bytes match what was provided
        opaque_obj_uuid = opaque_obj_result.uuid

        opaque_obj_result = self.client.get(uuid=opaque_obj_uuid,
                                            credential=None)

        self._check_result_status(opaque_obj_result, ResultStatus,
                                  ResultStatus.SUCCESS)

        self._check_object_type(
            opaque_obj_result.object_type, ObjectType,
            ObjectType.OPAQUE_DATA)

        self._check_uuid(opaque_obj_result.uuid, str)

        # Check the secret type
        opaque_obj_secret = opaque_obj_result.secret

        opaque_obj_secret_expected = OpaqueObject

        self.assertIsInstance(opaque_obj_secret, opaque_obj_secret_expected)

        opaque_obj_material = opaque_obj_result.secret.opaque_data_value.value
        expected = opaque_obj_data.value

        self.assertEqual(expected, opaque_obj_material)

        self.logger.debug('Destroying opaque object: ' + opaque_obj_name +
                          '\nWith " "UUID: ' + opaque_obj_result.uuid)

        opaque_obj_result = self.client.destroy(opaque_obj_result.uuid)

        self._check_result_status(opaque_obj_result, ResultStatus,
                                  ResultStatus.SUCCESS)

        self._check_uuid(opaque_obj_result.uuid.value, str)

        # Verify the secret was destroyed
        opaque_obj_result_destroyed_result = self.client.get(
            uuid=opaque_obj_uuid, credential=None)

        self._check_result_status(opaque_obj_result_destroyed_result,
                                  ResultStatus, ResultStatus.OPERATION_FAILED)

        expected = ResultReason
        opaque_obj_observed = \
            type(opaque_obj_result_destroyed_result.result_reason.value)

        self.assertEqual(expected, opaque_obj_observed)

    def test_symmetric_key_create_getattributelist_destroy(self):
        """
        Test that the GetAttributeList operation works for a newly created key.
        """
        key_name = 'Integration Test - Create-GetAttributeList-Destroy Key'
        result = self._create_symmetric_key(key_name=key_name)
        uid = result.uuid

        self.assertEqual(ResultStatus.SUCCESS, result.result_status.value)
        self.assertEqual(ObjectType.SYMMETRIC_KEY, result.object_type)
        self.assertIsInstance(uid, str)

        try:
            result = self.client.get_attribute_list(uid)

            self.assertEqual(ResultStatus.SUCCESS, result.result_status.value)
            self.assertIsInstance(result.uid, str)
            self.assertIsInstance(result.names, list)

            for name in result.names:
                self.assertIsInstance(name, str)

            expected = [
                'Cryptographic Algorithm',
                'Cryptographic Length',
                'Cryptographic Usage Mask',
                'Unique Identifier',
                'Object Type']
            for name in expected:
                self.assertIn(name, result.names)

        finally:
            result = self.client.destroy(uid)
            self.assertEqual(ResultStatus.SUCCESS, result.result_status.value)

            result = self.client.get(uuid=result.uuid.value, credential=None)

            self.assertEqual(
                ResultStatus.OPERATION_FAILED, result.result_status.value)

    def test_certificate_register_locate_destroy(self):
        """
        Test that newly registered certificates can be located based on their
        attributes.
        """
        label = "Integration Test - Register-Locate-Destroy Certificate"
        value = (
            b'\x30\x82\x03\x12\x30\x82\x01\xFA\xA0\x03\x02\x01\x02\x02\x01\x01'
            b'\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05\x05\x00\x30'
            b'\x3B\x31\x0B\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x0D'
            b'\x30\x0B\x06\x03\x55\x04\x0A\x13\x04\x54\x45\x53\x54\x31\x0E\x30'
            b'\x0C\x06\x03\x55\x04\x0B\x13\x05\x4F\x41\x53\x49\x53\x31\x0D\x30'
            b'\x0B\x06\x03\x55\x04\x03\x13\x04\x4B\x4D\x49\x50\x30\x1E\x17\x0D'
            b'\x31\x30\x31\x31\x30\x31\x32\x33\x35\x39\x35\x39\x5A\x17\x0D\x32'
            b'\x30\x31\x31\x30\x31\x32\x33\x35\x39\x35\x39\x5A\x30\x3B\x31\x0B'
            b'\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x0D\x30\x0B\x06'
            b'\x03\x55\x04\x0A\x13\x04\x54\x45\x53\x54\x31\x0E\x30\x0C\x06\x03'
            b'\x55\x04\x0B\x13\x05\x4F\x41\x53\x49\x53\x31\x0D\x30\x0B\x06\x03'
            b'\x55\x04\x03\x13\x04\x4B\x4D\x49\x50\x30\x82\x01\x22\x30\x0D\x06'
            b'\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00\x03\x82\x01\x0F'
            b'\x00\x30\x82\x01\x0A\x02\x82\x01\x01\x00\xAB\x7F\x16\x1C\x00\x42'
            b'\x49\x6C\xCD\x6C\x6D\x4D\xAD\xB9\x19\x97\x34\x35\x35\x77\x76\x00'
            b'\x3A\xCF\x54\xB7\xAF\x1E\x44\x0A\xFB\x80\xB6\x4A\x87\x55\xF8\x00'
            b'\x2C\xFE\xBA\x6B\x18\x45\x40\xA2\xD6\x60\x86\xD7\x46\x48\x34\x6D'
            b'\x75\xB8\xD7\x18\x12\xB2\x05\x38\x7C\x0F\x65\x83\xBC\x4D\x7D\xC7'
            b'\xEC\x11\x4F\x3B\x17\x6B\x79\x57\xC4\x22\xE7\xD0\x3F\xC6\x26\x7F'
            b'\xA2\xA6\xF8\x9B\x9B\xEE\x9E\x60\xA1\xD7\xC2\xD8\x33\xE5\xA5\xF4'
            b'\xBB\x0B\x14\x34\xF4\xE7\x95\xA4\x11\x00\xF8\xAA\x21\x49\x00\xDF'
            b'\x8B\x65\x08\x9F\x98\x13\x5B\x1C\x67\xB7\x01\x67\x5A\xBD\xBC\x7D'
            b'\x57\x21\xAA\xC9\xD1\x4A\x7F\x08\x1F\xCE\xC8\x0B\x64\xE8\xA0\xEC'
            b'\xC8\x29\x53\x53\xC7\x95\x32\x8A\xBF\x70\xE1\xB4\x2E\x7B\xB8\xB7'
            b'\xF4\xE8\xAC\x8C\x81\x0C\xDB\x66\xE3\xD2\x11\x26\xEB\xA8\xDA\x7D'
            b'\x0C\xA3\x41\x42\xCB\x76\xF9\x1F\x01\x3D\xA8\x09\xE9\xC1\xB7\xAE'
            b'\x64\xC5\x41\x30\xFB\xC2\x1D\x80\xE9\xC2\xCB\x06\xC5\xC8\xD7\xCC'
            b'\xE8\x94\x6A\x9A\xC9\x9B\x1C\x28\x15\xC3\x61\x2A\x29\xA8\x2D\x73'
            b'\xA1\xF9\x93\x74\xFE\x30\xE5\x49\x51\x66\x2A\x6E\xDA\x29\xC6\xFC'
            b'\x41\x13\x35\xD5\xDC\x74\x26\xB0\xF6\x05\x02\x03\x01\x00\x01\xA3'
            b'\x21\x30\x1F\x30\x1D\x06\x03\x55\x1D\x0E\x04\x16\x04\x14\x04\xE5'
            b'\x7B\xD2\xC4\x31\xB2\xE8\x16\xE1\x80\xA1\x98\x23\xFA\xC8\x58\x27'
            b'\x3F\x6B\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05\x05'
            b'\x00\x03\x82\x01\x01\x00\xA8\x76\xAD\xBC\x6C\x8E\x0F\xF0\x17\x21'
            b'\x6E\x19\x5F\xEA\x76\xBF\xF6\x1A\x56\x7C\x9A\x13\xDC\x50\xD1\x3F'
            b'\xEC\x12\xA4\x27\x3C\x44\x15\x47\xCF\xAB\xCB\x5D\x61\xD9\x91\xE9'
            b'\x66\x31\x9D\xF7\x2C\x0D\x41\xBA\x82\x6A\x45\x11\x2F\xF2\x60\x89'
            b'\xA2\x34\x4F\x4D\x71\xCF\x7C\x92\x1B\x4B\xDF\xAE\xF1\x60\x0D\x1B'
            b'\xAA\xA1\x53\x36\x05\x7E\x01\x4B\x8B\x49\x6D\x4F\xAE\x9E\x8A\x6C'
            b'\x1D\xA9\xAE\xB6\xCB\xC9\x60\xCB\xF2\xFA\xE7\x7F\x58\x7E\xC4\xBB'
            b'\x28\x20\x45\x33\x88\x45\xB8\x8D\xD9\xAE\xEA\x53\xE4\x82\xA3\x6E'
            b'\x73\x4E\x4F\x5F\x03\xB9\xD0\xDF\xC4\xCA\xFC\x6B\xB3\x4E\xA9\x05'
            b'\x3E\x52\xBD\x60\x9E\xE0\x1E\x86\xD9\xB0\x9F\xB5\x11\x20\xC1\x98'
            b'\x34\xA9\x97\xB0\x9C\xE0\x8D\x79\xE8\x13\x11\x76\x2F\x97\x4B\xB1'
            b'\xC8\xC0\x91\x86\xC4\xD7\x89\x33\xE0\xDB\x38\xE9\x05\x08\x48\x77'
            b'\xE1\x47\xC7\x8A\xF5\x2F\xAE\x07\x19\x2F\xF1\x66\xD1\x9F\xA9\x4A'
            b'\x11\xCC\x11\xB2\x7E\xD0\x50\xF7\xA2\x7F\xAE\x13\xB2\x05\xA5\x74'
            b'\xC4\xEE\x00\xAA\x8B\xD6\x5D\x0D\x70\x57\xC9\x85\xC8\x39\xEF\x33'
            b'\x6A\x44\x1E\xD5\x3A\x53\xC6\xB6\xB6\x96\xF1\xBD\xEB\x5F\x7E\xA8'
            b'\x11\xEB\xB2\x5A\x7F\x86')
        name = self.attr_factory.create_attribute(
            enums.AttributeType.NAME,
            label
        )
        usage_mask = self.attr_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
            [
                enums.CryptographicUsageMask.ENCRYPT,
                enums.CryptographicUsageMask.VERIFY
            ]
        )
        template_attribute = TemplateAttribute(attributes=[usage_mask, name])

        certificate = Certificate(enums.CertificateType.X_509, value)
        result = self.client.register(
            enums.ObjectType.CERTIFICATE,
            template_attribute,
            certificate
        )
        uid_a = result.uuid

        self.assertEqual(
            enums.ResultStatus.SUCCESS,
            result.result_status.value
        )
        self.assertIsInstance(uid_a, str)

        # Test locating the certificate by its "Certificate Type" value.
        result = self.client.locate(
            attributes=[
                self.attr_factory.create_attribute(
                    enums.AttributeType.CERTIFICATE_TYPE,
                    enums.CertificateType.X_509
                )
            ]
        )
        self.assertEqual(ResultStatus.SUCCESS, result.result_status.value)
        self.assertEqual(1, len(result.uuids))
        self.assertEqual(uid_a, result.uuids[0])

        result = self.client.locate(
            attributes=[
                self.attr_factory.create_attribute(
                    enums.AttributeType.CERTIFICATE_TYPE,
                    enums.CertificateType.PGP
                )
            ]
        )
        self.assertEqual(ResultStatus.SUCCESS, result.result_status.value)
        self.assertEqual(0, len(result.uuids))

        # Clean up certificate
        result = self.client.destroy(uid_a)
        self.assertEqual(ResultStatus.SUCCESS, result.result_status.value)
        result = self.client.get(uuid=result.uuid.value, credential=None)
        self.assertEqual(
            ResultStatus.OPERATION_FAILED,
            result.result_status.value
        )

    def test_symmetric_key_create_getattributes_locate_destroy(self):
        """
        Test that newly created keys can be located based on their attributes.
        """
        start_time = int(time.time())
        time.sleep(2)

        key_name = "Integration Test - Create-GetAttributes-Locate-Destroy Key"
        result = self._create_symmetric_key(key_name=key_name)
        uid_a = result.uuid

        self.assertEqual(ResultStatus.SUCCESS, result.result_status.value)
        self.assertEqual(ObjectType.SYMMETRIC_KEY, result.object_type)
        self.assertIsInstance(uid_a, str)

        time.sleep(2)
        mid_time = int(time.time())
        time.sleep(2)

        key_name = "Integration Test - Create-GetAttributes-Locate-Destroy Key"
        result = self._create_symmetric_key(key_name=key_name)
        uid_b = result.uuid

        self.assertEqual(ResultStatus.SUCCESS, result.result_status.value)
        self.assertEqual(ObjectType.SYMMETRIC_KEY, result.object_type)
        self.assertIsInstance(uid_b, str)

        time.sleep(2)
        end_time = int(time.time())

        # Get the actual "Initial Date" values for each key
        result = self.client.get_attributes(
            uuid=uid_a,
            attribute_names=["Initial Date"]
        )

        self.assertEqual(ResultStatus.SUCCESS, result.result_status.value)
        self.assertEqual(1, len(result.attributes))
        self.assertEqual(
            "Initial Date",
            result.attributes[0].attribute_name.value
        )
        initial_date_a = result.attributes[0].attribute_value.value

        result = self.client.get_attributes(
            uuid=uid_b,
            attribute_names=["Initial Date"]
        )

        self.assertEqual(ResultStatus.SUCCESS, result.result_status.value)
        self.assertEqual(1, len(result.attributes))
        self.assertEqual(
            "Initial Date",
            result.attributes[0].attribute_name.value
        )
        initial_date_b = result.attributes[0].attribute_value.value

        # Test locating each key by its exact "Initial Date" value
        result = self.client.locate(
            attributes=[
                self.attr_factory.create_attribute(
                    enums.AttributeType.INITIAL_DATE,
                    initial_date_a
                )
            ]
        )
        self.assertEqual(ResultStatus.SUCCESS, result.result_status.value)
        self.assertEqual(1, len(result.uuids))
        self.assertEqual(uid_a, result.uuids[0])

        result = self.client.locate(
            attributes=[
                self.attr_factory.create_attribute(
                    enums.AttributeType.INITIAL_DATE,
                    initial_date_b
                )
            ]
        )
        self.assertEqual(ResultStatus.SUCCESS, result.result_status.value)
        self.assertEqual(1, len(result.uuids))
        self.assertEqual(uid_b, result.uuids[0])

        # Test locating each key by a range around its "Initial Date" value
        result = self.client.locate(
            attributes=[
                self.attr_factory.create_attribute(
                    enums.AttributeType.INITIAL_DATE,
                    start_time
                ),
                self.attr_factory.create_attribute(
                    enums.AttributeType.INITIAL_DATE,
                    mid_time
                )
            ]
        )
        self.assertEqual(ResultStatus.SUCCESS, result.result_status.value)
        self.assertEqual(1, len(result.uuids))
        self.assertEqual(uid_a, result.uuids[0])

        result = self.client.locate(
            attributes=[
                self.attr_factory.create_attribute(
                    enums.AttributeType.INITIAL_DATE,
                    mid_time
                ),
                self.attr_factory.create_attribute(
                    enums.AttributeType.INITIAL_DATE,
                    end_time
                )
            ]
        )
        self.assertEqual(ResultStatus.SUCCESS, result.result_status.value)
        self.assertEqual(1, len(result.uuids))
        self.assertEqual(uid_b, result.uuids[0])

        result = self.client.locate(
            attributes=[
                self.attr_factory.create_attribute(
                    enums.AttributeType.INITIAL_DATE,
                    start_time
                ),
                self.attr_factory.create_attribute(
                    enums.AttributeType.INITIAL_DATE,
                    end_time
                )
            ]
        )
        self.assertEqual(ResultStatus.SUCCESS, result.result_status.value)
        self.assertEqual(2, len(result.uuids))
        self.assertIn(uid_a, result.uuids)
        self.assertIn(uid_b, result.uuids)

        # Test locating each key based off of its name.
        result = self.client.locate(
            attributes=[
                self.attr_factory.create_attribute(
                    enums.AttributeType.NAME,
                    key_name
                )
            ]
        )
        self.assertEqual(ResultStatus.SUCCESS, result.result_status.value)
        self.assertEqual(2, len(result.uuids))
        self.assertIn(uid_a, result.uuids)
        self.assertIn(uid_b, result.uuids)

        # Test locating each key based off of its state.
        result = self.client.locate(
            attributes=[
                self.attr_factory.create_attribute(
                    enums.AttributeType.STATE,
                    enums.State.PRE_ACTIVE
                )
            ]
        )
        self.assertEqual(ResultStatus.SUCCESS, result.result_status.value)
        self.assertEqual(2, len(result.uuids))
        self.assertIn(uid_a, result.uuids)
        self.assertIn(uid_b, result.uuids)

        # Test locating each key based off of its object type.
        result = self.client.locate(
            attributes=[
                self.attr_factory.create_attribute(
                    enums.AttributeType.OBJECT_TYPE,
                    enums.ObjectType.SYMMETRIC_KEY
                )
            ]
        )
        self.assertEqual(ResultStatus.SUCCESS, result.result_status.value)
        self.assertEqual(2, len(result.uuids))
        self.assertIn(uid_a, result.uuids)
        self.assertIn(uid_b, result.uuids)

        # Test locating each key by its cryptographic algorithm.
        result = self.client.locate(
            attributes=[
                self.attr_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                    enums.CryptographicAlgorithm.AES
                )
            ]
        )
        self.assertEqual(ResultStatus.SUCCESS, result.result_status.value)
        self.assertEqual(2, len(result.uuids))
        self.assertIn(uid_a, result.uuids)
        self.assertIn(uid_b, result.uuids)

        result = self.client.locate(
            attributes=[
                self.attr_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                    enums.CryptographicAlgorithm.IDEA
                )
            ]
        )
        self.assertEqual(ResultStatus.SUCCESS, result.result_status.value)
        self.assertEqual(0, len(result.uuids))

        # Test locating each key by its cryptographic length.
        result = self.client.locate(
            attributes=[
                self.attr_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                    128
                )
            ]
        )
        self.assertEqual(2, len(result.uuids))
        self.assertIn(uid_a, result.uuids)
        self.assertIn(uid_b, result.uuids)

        result = self.client.locate(
            attributes=[
                self.attr_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                    2048
                )
            ]
        )
        self.assertEqual(0, len(result.uuids))

        # Test locating each key by its unique identifier.
        result = self.client.locate(
            attributes=[
                self.attr_factory.create_attribute(
                    enums.AttributeType.UNIQUE_IDENTIFIER,
                    uid_a
                )
            ]
        )
        self.assertEqual(1, len(result.uuids))
        self.assertIn(uid_a, result.uuids)

        result = self.client.locate(
            attributes=[
                self.attr_factory.create_attribute(
                    enums.AttributeType.UNIQUE_IDENTIFIER,
                    uid_b
                )
            ]
        )
        self.assertEqual(1, len(result.uuids))
        self.assertIn(uid_b, result.uuids)

        result = self.client.locate(
            attributes=[
                self.attr_factory.create_attribute(
                    enums.AttributeType.UNIQUE_IDENTIFIER,
                    "unknown"
                )
            ]
        )
        self.assertEqual(0, len(result.uuids))

        # Test locating each key by its operation policy name.
        result = self.client.locate(
            attributes=[
                self.attr_factory.create_attribute(
                    enums.AttributeType.OPERATION_POLICY_NAME,
                    "default"
                )
            ]
        )
        self.assertEqual(2, len(result.uuids))
        self.assertIn(uid_a, result.uuids)
        self.assertIn(uid_b, result.uuids)

        result = self.client.locate(
            attributes=[
                self.attr_factory.create_attribute(
                    enums.AttributeType.OPERATION_POLICY_NAME,
                    "unknown"
                )
            ]
        )
        self.assertEqual(0, len(result.uuids))

        # Test locating each key by its application specific information.
        result = self.client.locate(
            attributes=[
                self.attr_factory.create_attribute(
                    enums.AttributeType.APPLICATION_SPECIFIC_INFORMATION,
                    {
                        "application_namespace": "ssl",
                        "application_data": "www.example.com"
                    }
                )
            ]
        )
        self.assertEqual(2, len(result.uuids))
        self.assertIn(uid_a, result.uuids)
        self.assertIn(uid_b, result.uuids)

        # Test locating each key by its object group.
        result = self.client.locate(
            attributes=[
                self.attr_factory.create_attribute(
                    enums.AttributeType.OBJECT_GROUP,
                    "IntegrationTestKeys"
                )
            ]
        )
        self.assertEqual(2, len(result.uuids))
        self.assertIn(uid_a, result.uuids)
        self.assertIn(uid_b, result.uuids)

        # Test locating keys using offset and maximum item constraints.
        result = self.client.locate(offset_items=1)

        self.assertEqual(1, len(result.uuids))
        self.assertIn(uid_a, result.uuids)

        result = self.client.locate(maximum_items=1)

        self.assertEqual(1, len(result.uuids))
        self.assertIn(uid_b, result.uuids)

        result = self.client.locate(offset_items=1, maximum_items=1)

        self.assertEqual(1, len(result.uuids))
        self.assertIn(uid_a, result.uuids)

        # Test locating keys using their cryptographic usage masks
        mask = [enums.CryptographicUsageMask.ENCRYPT]
        result = self.client.locate(
            attributes=[
                self.attr_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    mask
                )
            ]
        )
        self.assertEqual(2, len(result.uuids))
        self.assertIn(uid_a, result.uuids)
        self.assertIn(uid_b, result.uuids)

        mask.append(enums.CryptographicUsageMask.DECRYPT)
        result = self.client.locate(
            attributes=[
                self.attr_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    mask
                )
            ]
        )
        self.assertEqual(2, len(result.uuids))
        self.assertIn(uid_a, result.uuids)
        self.assertIn(uid_b, result.uuids)

        mask.append(enums.CryptographicUsageMask.SIGN)
        result = self.client.locate(
            attributes=[
                self.attr_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    mask
                )
            ]
        )
        self.assertEqual(0, len(result.uuids))

        mask = [enums.CryptographicUsageMask.EXPORT]
        result = self.client.locate(
            attributes=[
                self.attr_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    mask
                )
            ]
        )
        self.assertEqual(0, len(result.uuids))

        # Clean up keys
        result = self.client.destroy(uid_a)
        self.assertEqual(ResultStatus.SUCCESS, result.result_status.value)
        result = self.client.get(uuid=result.uuid.value, credential=None)
        self.assertEqual(
            ResultStatus.OPERATION_FAILED,
            result.result_status.value
        )

        result = self.client.destroy(uid_b)
        self.assertEqual(ResultStatus.SUCCESS, result.result_status.value)
        result = self.client.get(uuid=result.uuid.value, credential=None)
        self.assertEqual(
            ResultStatus.OPERATION_FAILED,
            result.result_status.value
        )

    def test_split_key_register_get_destroy(self):
        """
        Tests that split keys are properly registered, retrieved, and
        destroyed.
        """
        usage_mask = self.attr_factory.create_attribute(
            AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
            [CryptographicUsageMask.ENCRYPT, CryptographicUsageMask.DECRYPT]
        )
        key_name = "Integration Test - Register-Get-Destroy Split Key"
        name = self.attr_factory.create_attribute(AttributeType.NAME, key_name)
        template_attribute = TemplateAttribute(attributes=[usage_mask, name])

        key_data = (
            b'\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00'
        )

        key_block = KeyBlock(
            key_format_type=KeyFormatType(KeyFormatTypeEnum.RAW),
            key_compression_type=None,
            key_value=KeyValue(KeyMaterial(key_data)),
            cryptographic_algorithm=CryptographicAlgorithm(
                CryptoAlgorithmEnum.AES
            ),
            cryptographic_length=CryptographicLength(128),
            key_wrapping_data=None
        )

        secret = SplitKey(
            split_key_parts=3,
            key_part_identifier=1,
            split_key_threshold=2,
            split_key_method=enums.SplitKeyMethod.XOR,
            prime_field_size=None,
            key_block=key_block
        )

        result = self.client.register(
            ObjectType.SPLIT_KEY,
            template_attribute,
            secret,
            credential=None
        )

        self._check_result_status(result, ResultStatus, ResultStatus.SUCCESS)
        self._check_uuid(result.uuid, str)

        # Check that the returned key bytes match what was provided
        uuid = result.uuid
        result = self.client.get(uuid=uuid, credential=None)

        self._check_result_status(result, ResultStatus, ResultStatus.SUCCESS)
        self._check_object_type(
            result.object_type,
            ObjectType,
            ObjectType.SPLIT_KEY
        )
        self._check_uuid(result.uuid, str)

        self.assertEqual(3, result.secret.split_key_parts)
        self.assertEqual(1, result.secret.key_part_identifier)
        self.assertEqual(2, result.secret.split_key_threshold)
        self.assertEqual(
            enums.SplitKeyMethod.XOR,
            result.secret.split_key_method
        )
        self.assertIsNone(result.secret.prime_field_size)

        # Check the secret type
        self.assertIsInstance(result.secret, SplitKey)
        self.assertEqual(
            key_data,
            result.secret.key_block.key_value.key_material.value
        )

        self.logger.debug(
            'Destroying key: ' + key_name + '\nWith UUID: ' + result.uuid
        )

        result = self.client.destroy(result.uuid)
        self._check_result_status(
            result,
            ResultStatus,
            ResultStatus.SUCCESS
        )
        self._check_uuid(result.uuid.value, str)

        # Verify the secret was destroyed
        result = self.client.get(uuid=uuid, credential=None)

        self._check_result_status(
            result,
            ResultStatus,
            ResultStatus.OPERATION_FAILED
        )
        self.assertIsInstance(result.result_reason.value, ResultReason)
        self.assertEqual(
            ResultReason.ITEM_NOT_FOUND,
            result.result_reason.value
        )

    def test_modify_delete_attribute(self):
        """
        Test that the KMIPProxy client can be used to set, modify, and delete
        attributes for an object stored by the server.
        """
        key_name = "Integration Test - Set-Modify-Delete-Attribute Key"
        result = self._create_symmetric_key(key_name=key_name)
        key_uuid = result.uuid

        self.assertEqual(ResultStatus.SUCCESS, result.result_status.value)
        self.assertEqual(ObjectType.SYMMETRIC_KEY, result.object_type)
        self.assertIsInstance(key_uuid, str)

        # Get the "Name" attribute for the key
        result = self.client.get_attributes(
            uuid=key_uuid,
            attribute_names=["Name"]
        )
        self.assertEqual(ResultStatus.SUCCESS, result.result_status.value)
        self.assertEqual(1, len(result.attributes))
        self.assertEqual(
            "Name",
            result.attributes[0].attribute_name.value
        )
        self.assertEqual(0, result.attributes[0].attribute_index.value)
        self.assertEqual(
            "Integration Test - Set-Modify-Delete-Attribute Key",
            result.attributes[0].attribute_value.name_value.value
        )

        # Modify the "Name" attribute for the key.
        response_payload = self.client.send_request_payload(
            enums.Operation.MODIFY_ATTRIBUTE,
            payloads.ModifyAttributeRequestPayload(
                unique_identifier=key_uuid,
                attribute=self.attr_factory.create_attribute(
                    enums.AttributeType.NAME,
                    "New Name",
                    index=0
                )
            )
        )
        self.assertEqual(key_uuid, response_payload.unique_identifier)
        self.assertEqual(
            "Name",
            response_payload.attribute.attribute_name.value
        )
        self.assertEqual(0, response_payload.attribute.attribute_index.value)
        self.assertEqual(
            "New Name",
            response_payload.attribute.attribute_value.name_value.value
        )

        # Get the "Name" attribute for the key to verify it was modified
        result = self.client.get_attributes(
            uuid=key_uuid,
            attribute_names=["Name"]
        )
        self.assertEqual(ResultStatus.SUCCESS, result.result_status.value)
        self.assertEqual(1, len(result.attributes))
        self.assertEqual(
            "Name",
            result.attributes[0].attribute_name.value
        )
        self.assertEqual(0, result.attributes[0].attribute_index.value)
        self.assertEqual(
            "New Name",
            result.attributes[0].attribute_value.name_value.value
        )

        # Delete the "Name" attribute for the key.
        response_payload = self.client.send_request_payload(
            enums.Operation.DELETE_ATTRIBUTE,
            payloads.DeleteAttributeRequestPayload(
                unique_identifier=key_uuid,
                attribute_name="Name",
                attribute_index=0
            )
        )
        self.assertEqual(key_uuid, response_payload.unique_identifier)
        self.assertEqual(
            "Name",
            response_payload.attribute.attribute_name.value
        )
        self.assertEqual(0, response_payload.attribute.attribute_index.value)
        self.assertEqual(
            "New Name",
            response_payload.attribute.attribute_value.name_value.value
        )
