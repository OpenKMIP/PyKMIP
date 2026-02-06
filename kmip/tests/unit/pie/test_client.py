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

import mock

import ssl
import testtools

from kmip.core import attributes as attr
from kmip.core import enums
from kmip.core import objects as obj

from kmip.core.factories import attributes
from kmip.core.messages import contents
from kmip.core.messages import payloads
from kmip.core import primitives
from kmip.core.primitives import DateTime

from kmip.services.kmip_client import KMIPProxy
from kmip.services import results

from kmip.pie.client import ProxyKmipClient

from kmip.pie.exceptions import ClientConnectionFailure
from kmip.pie.exceptions import ClientConnectionNotOpen
from kmip.pie.exceptions import KmipOperationFailure

from kmip.pie import factory
from kmip.pie import objects

class TestProxyKmipClient(testtools.TestCase):
    """
    Test suite for the ProxyKmipClient.
    """

    def setUp(self):
        super(TestProxyKmipClient, self).setUp()
        self.attribute_factory = attributes.AttributeFactory()

    def tearDown(self):
        super(TestProxyKmipClient, self).tearDown()

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_init(self):
        """
        Test that a ProxyKmipClient can be constructed with valid arguments.
        """
        ProxyKmipClient(
            hostname='127.0.0.1',
            port=5696,
            cert='/example/path/to/cert',
            key='/example/path/to/key',
            ca='/example/path/to/ca',
            ssl_version=ssl.PROTOCOL_TLSv1,
            username='username',
            password='password',
            config='test')

    def test_kmip_version_get(self):
        """
        Test that the KMIP version can be obtained from the client.
        """
        client = ProxyKmipClient()
        self.assertEqual(client.kmip_version, enums.KMIPVersion.KMIP_1_2)

    def test_kmip_version_set(self):
        """
        Test that the KMIP version of the client can be set to a new value.
        """
        client = ProxyKmipClient()
        self.assertEqual(client.kmip_version, enums.KMIPVersion.KMIP_1_2)
        client.kmip_version = enums.KMIPVersion.KMIP_1_1
        self.assertEqual(client.kmip_version, enums.KMIPVersion.KMIP_1_1)

    def test_kmip_version_set_error(self):
        """
        Test that the right error gets raised when setting the client KMIP
        version with an invalid value.
        """
        client = ProxyKmipClient()
        args = (client, "kmip_version", None)
        self.assertRaisesRegex(
            ValueError,
            "KMIP version must be a KMIPVersion enumeration",
            setattr,
            *args
        )

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_open(self):
        """
        Test that the client can open a connection.
        """
        client = ProxyKmipClient()
        client.open()
        client.proxy.open.assert_called_with()

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_open_on_open(self):
        """
        Test that a ClientConnectionFailure exception is raised when trying
        to open an opened client connection.
        """
        client = ProxyKmipClient()
        client.open()
        self.assertRaises(ClientConnectionFailure, client.open)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_open_on_proxy_failure(self):
        """
        Test that an Exception is raised when an error occurs while opening
        the client proxy connection.
        """
        client = ProxyKmipClient()
        client.proxy.open.side_effect = Exception
        self.assertRaises(Exception, client.open)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_open_on_proxy_failure_logs_error(self):
        """
        Test that open logs an error when the proxy fails to open.
        """
        client = ProxyKmipClient()
        client.logger = mock.MagicMock()
        test_exception = Exception("test")
        client.proxy.open.side_effect = test_exception

        self.assertRaises(Exception, client.open)
        client.logger.error.assert_called_once_with(
            "could not open client connection: %s",
            test_exception
        )

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_close(self):
        """
        Test that the client can close an open connection.
        """
        client = ProxyKmipClient()
        client.open()
        client.close()
        client.proxy.close.assert_called_with()

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_close_on_close(self):
        """
        Test that a closed client connection can be closed with no error.
        """
        client = ProxyKmipClient()
        client.close()

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_close_on_proxy_failure(self):
        """
        Test that an Exception is raised when an error occurs while closing
        the client proxy connection.
        """
        client = ProxyKmipClient()
        client._is_open = True
        client.proxy.close.side_effect = Exception
        self.assertRaises(Exception, client.close)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_close_on_proxy_failure_logs_error(self):
        """
        Test that close logs an error when the proxy fails to close.
        """
        client = ProxyKmipClient()
        client._is_open = True
        client.logger = mock.MagicMock()
        test_exception = Exception("test")
        client.proxy.close.side_effect = test_exception

        self.assertRaises(Exception, client.close)
        client.logger.error.assert_called_once_with(
            "could not close client connection: %s",
            test_exception
        )

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_enter(self):
        """
        Test the result and effect of the enter method for the context
        manager.
        """
        client = ProxyKmipClient()

        self.assertFalse(client._is_open)
        result = client.__enter__()
        self.assertEqual(result, client)
        self.assertTrue(client._is_open)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_exit(self):
        """
        Test the result and effect of the exit method for the context
        manager.
        """
        client = ProxyKmipClient()
        client.__enter__()

        self.assertTrue(client._is_open)
        client.__exit__(None, None, None)
        self.assertFalse(client._is_open)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_context_manager(self):
        """
        Test that the KmipClient can be used by the with-statement as a
        context manager.
        """
        with ProxyKmipClient() as client:
            self.assertTrue(client._is_open)
            client.proxy.open.assert_called_with()
        self.assertFalse(client._is_open)
        client.proxy.close.assert_called_with()

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_create(self):
        """
        Test that a symmetric key can be created with proper inputs and that
        its UID is returned properly.
        """
        # Create the template to test the create call
        algorithm = enums.CryptographicAlgorithm.AES
        length = 256
        algorithm_attribute = self.attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM, algorithm)
        length_attribute = self.attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_LENGTH, length)
        mask_attribute = self.attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
            [enums.CryptographicUsageMask.ENCRYPT,
             enums.CryptographicUsageMask.DECRYPT])

        attributes = [algorithm_attribute, length_attribute, mask_attribute]
        template = obj.TemplateAttribute(attributes=attributes)

        key_id = 'aaaaaaaa-1111-2222-3333-ffffffffffff'
        status = enums.ResultStatus.SUCCESS
        result = results.CreateResult(
            contents.ResultStatus(status),
            uuid=key_id
        )

        with ProxyKmipClient() as client:
            client.proxy.create.return_value = result

            uid = client.create(algorithm, length)
            client.proxy.create.assert_called_with(
                enums.ObjectType.SYMMETRIC_KEY, template)
            self.assertIsInstance(uid, str)
            self.assertEqual(uid, key_id)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_create_with_operation_policy_name(self):
        """
        Test that a symmetric key can be created with proper inputs,
        specifically testing that the operation policy name is correctly
        sent with the request.
        """
        # Create the template to test the create call
        algorithm = enums.CryptographicAlgorithm.AES
        length = 256
        algorithm_attribute = self.attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM, algorithm)
        length_attribute = self.attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_LENGTH, length)
        mask_attribute = self.attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
            [enums.CryptographicUsageMask.ENCRYPT,
             enums.CryptographicUsageMask.DECRYPT])
        opn_attribute = self.attribute_factory.create_attribute(
            enums.AttributeType.OPERATION_POLICY_NAME,
            'test'
        )

        key_attributes = [
            algorithm_attribute,
            length_attribute,
            mask_attribute,
            opn_attribute
        ]
        template = obj.TemplateAttribute(attributes=key_attributes)

        key_id = 'aaaaaaaa-1111-2222-3333-ffffffffffff'
        status = enums.ResultStatus.SUCCESS
        result = results.CreateResult(
            contents.ResultStatus(status),
            uuid=attr.UniqueIdentifier(key_id))

        with ProxyKmipClient() as client:
            client.proxy.create.return_value = result

            client.create(
                algorithm,
                length,
                operation_policy_name='test'
            )
            client.proxy.create.assert_called_with(
                enums.ObjectType.SYMMETRIC_KEY, template)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_create_with_name(self):
        """
        Test that a symmetric key can be created with proper inputs,
        specifically testing that the name is correctly
        sent with the request.
        """
        # Create the template to test the create call
        algorithm = enums.CryptographicAlgorithm.AES
        length = 256
        algorithm_attribute = self.attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM, algorithm)
        length_attribute = self.attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_LENGTH, length)
        mask_attribute = self.attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
            [enums.CryptographicUsageMask.ENCRYPT,
             enums.CryptographicUsageMask.DECRYPT])

        key_name = "symmetrickey"
        name_attribute = self.attribute_factory.create_attribute(
                enums.AttributeType.NAME,
                key_name)

        key_attributes = [
            algorithm_attribute,
            length_attribute,
            mask_attribute,
            name_attribute
            ]

        template = obj.TemplateAttribute(attributes=key_attributes)

        key_id = 'aaaaaaaa-1111-2222-3333-ffffffffffff'
        status = enums.ResultStatus.SUCCESS
        result = results.CreateResult(
            contents.ResultStatus(status),
            uuid=attr.UniqueIdentifier(key_id))

        with ProxyKmipClient() as client:
            client.proxy.create.return_value = result

            client.create(
                algorithm,
                length,
                name=key_name
            )
            client.proxy.create.assert_called_with(
                enums.ObjectType.SYMMETRIC_KEY, template)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_create_with_empty_name(self):
        """
        Test that an empty name is ignored during create.
        """
        algorithm = enums.CryptographicAlgorithm.AES
        length = 256
        algorithm_attribute = self.attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM, algorithm)
        length_attribute = self.attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_LENGTH, length)
        mask_attribute = self.attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
            [enums.CryptographicUsageMask.ENCRYPT,
             enums.CryptographicUsageMask.DECRYPT])

        attributes = [algorithm_attribute, length_attribute, mask_attribute]
        template = obj.TemplateAttribute(attributes=attributes)

        key_id = 'aaaaaaaa-1111-2222-3333-ffffffffffff'
        status = enums.ResultStatus.SUCCESS
        result = results.CreateResult(
            contents.ResultStatus(status),
            uuid=key_id)

        with ProxyKmipClient() as client:
            client.proxy.create.return_value = result

            uid = client.create(
                algorithm,
                length,
                operation_policy_name=None,
                name="",
                cryptographic_usage_mask=None
            )
            client.proxy.create.assert_called_with(
                enums.ObjectType.SYMMETRIC_KEY, template)
            self.assertEqual(uid, key_id)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_create_with_none_optionals(self):
        """
        Test that create accepts explicit None optional parameters.
        """
        algorithm = enums.CryptographicAlgorithm.AES
        length = 256
        algorithm_attribute = self.attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM, algorithm)
        length_attribute = self.attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_LENGTH, length)
        mask_attribute = self.attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
            [enums.CryptographicUsageMask.ENCRYPT,
             enums.CryptographicUsageMask.DECRYPT])

        attributes = [algorithm_attribute, length_attribute, mask_attribute]
        template = obj.TemplateAttribute(attributes=attributes)

        key_id = 'aaaaaaaa-1111-2222-3333-ffffffffffff'
        status = enums.ResultStatus.SUCCESS
        result = results.CreateResult(
            contents.ResultStatus(status),
            uuid=key_id)

        with ProxyKmipClient() as client:
            client.proxy.create.return_value = result

            uid = client.create(
                algorithm,
                length,
                operation_policy_name=None,
                name=None,
                cryptographic_usage_mask=None
            )
            client.proxy.create.assert_called_with(
                enums.ObjectType.SYMMETRIC_KEY, template)
            self.assertEqual(uid, key_id)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_create_with_cryptographic_usage_mask(self):
        """
        Test that a symmetric key can be created with proper inputs,
        specifically testing that the cryptographic usage mask is correctly
        sent with the request.
        """
        # Create the template to test the create call
        algorithm = enums.CryptographicAlgorithm.AES
        length = 256
        algorithm_attribute = self.attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM, algorithm)
        length_attribute = self.attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_LENGTH, length)
        masks = [enums.CryptographicUsageMask.ENCRYPT,
                 enums.CryptographicUsageMask.DECRYPT]
        masks_given = [enums.CryptographicUsageMask.MAC_GENERATE,
                       enums.CryptographicUsageMask.MAC_VERIFY]
        masks.extend(masks_given)
        mask_attribute = self.attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
            masks)

        key_attributes = [
            algorithm_attribute,
            length_attribute,
            mask_attribute,
            ]

        template = obj.TemplateAttribute(attributes=key_attributes)

        key_id = 'aaaaaaaa-1111-2222-3333-ffffffffffff'
        status = enums.ResultStatus.SUCCESS
        result = results.CreateResult(
            contents.ResultStatus(status),
            uuid=attr.UniqueIdentifier(key_id))

        with ProxyKmipClient() as client:
            client.proxy.create.return_value = result

            client.create(
                algorithm,
                length,
                cryptographic_usage_mask=masks_given
            )
            client.proxy.create.assert_called_with(
                enums.ObjectType.SYMMETRIC_KEY, template)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_create_on_invalid_algorithm(self):
        """
        Test that a TypeError exception is raised when trying to create a
        symmetric key with an invalid algorithm.
        """
        args = ['invalid', 256]
        with ProxyKmipClient() as client:
            self.assertRaises(TypeError, client.create, *args)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_create_on_invalid_algorithm_enum_type(self):
        """
        Test that a TypeError is raised for an enum of the wrong type.
        """
        args = [enums.ObjectType.SYMMETRIC_KEY, 256]
        with ProxyKmipClient() as client:
            self.assertRaises(TypeError, client.create, *args)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_create_on_invalid_algorithm_int(self):
        """
        Test that a TypeError is raised for a non-enum algorithm value.
        """
        args = [1, 256]
        with ProxyKmipClient() as client:
            self.assertRaises(TypeError, client.create, *args)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_create_on_invalid_length(self):
        """
        Test that a TypeError exception is raised when trying to create a
        symmetric key with an invalid length.
        """
        args = [enums.CryptographicAlgorithm.AES, 'invalid']
        with ProxyKmipClient() as client:
            self.assertRaises(TypeError, client.create, *args)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_create_on_non_positive_length(self):
        """
        Test that a TypeError is raised for non-positive key lengths.
        """
        for length in (0, -1):
            with ProxyKmipClient() as client:
                self.assertRaises(
                    TypeError,
                    client.create,
                    enums.CryptographicAlgorithm.AES,
                    length
                )

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_create_on_invalid_cryptographic_usage_mask(self):
        """
        Test that a TypeError exception is raised when trying to create a
        symmetric key with invalid cryptographic_usage_mask.
        """
        args = [enums.CryptographicAlgorithm.AES, 256]
        kwargs = {'cryptographic_usage_mask':
                  enums.CryptographicUsageMask.ENCRYPT}
        with ProxyKmipClient() as client:
            self.assertRaises(TypeError, client.create, *args, **kwargs)
        kwargs = {'cryptographic_usage_mask':
                  [enums.CryptographicUsageMask.ENCRYPT, 1]}
        with ProxyKmipClient() as client:
            self.assertRaises(TypeError, client.create, *args, **kwargs)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_create_on_closed(self):
        """
        Test that a ClientConnectionNotOpen exception is raised when trying
        to create a symmetric key on an unopened client connection.
        """
        client = ProxyKmipClient()
        args = [enums.CryptographicAlgorithm.AES, 256]
        self.assertRaises(
            ClientConnectionNotOpen, client.create, *args)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_create_on_operation_failure(self):
        """
        Test that a KmipOperationFailure exception is raised when the
        the backend fails to create a symmetric key.
        """
        status = enums.ResultStatus.OPERATION_FAILED
        reason = enums.ResultReason.GENERAL_FAILURE
        message = "Test failure message"

        result = results.OperationResult(
            contents.ResultStatus(status),
            contents.ResultReason(reason),
            contents.ResultMessage(message))
        error_msg = str(KmipOperationFailure(status, reason, message))

        client = ProxyKmipClient()
        client.open()
        client.proxy.create.return_value = result
        args = [enums.CryptographicAlgorithm.AES, 256]

        self.assertRaisesRegex(
            KmipOperationFailure, error_msg, client.create, *args)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_create_key_pair(self):
        """
        Test that an asymmetric key pair can be created with proper inputs
        and that the UIDs of the public and private keys are returned
        properly.
        """
        # Create the template to test the create key pair call
        algorithm = enums.CryptographicAlgorithm.RSA
        length = 2048
        algorithm_attribute = self.attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM, algorithm)
        length_attribute = self.attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_LENGTH, length)

        attributes = [algorithm_attribute, length_attribute]
        template = obj.TemplateAttribute(
            attributes=attributes,
            tag=enums.Tags.COMMON_TEMPLATE_ATTRIBUTE
        )

        status = enums.ResultStatus.SUCCESS
        result = results.CreateKeyPairResult(
            contents.ResultStatus(status),
            public_key_uuid="aaaaaaaa-1111-2222-3333-ffffffffffff",
            private_key_uuid="ffffffff-3333-2222-1111-aaaaaaaaaaaa"
        )

        with ProxyKmipClient() as client:
            client.proxy.create_key_pair.return_value = result

            public_uid, private_uid = client.create_key_pair(
                enums.CryptographicAlgorithm.RSA,
                2048
            )

            kwargs = {
                "common_template_attribute": template,
                "private_key_template_attribute": None,
                "public_key_template_attribute": None
            }
            client.proxy.create_key_pair.assert_called_with(**kwargs)
            self.assertIsInstance(public_uid, str)
            self.assertIsInstance(private_uid, str)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_create_key_pair_with_operation_policy_name(self):
        """
        Test that an asymmetric key pair can be created with proper inputs,
        specifically testing that the operation policy name is correctly
        sent with the request.
        """
        # Create the template to test the create key pair call
        algorithm = enums.CryptographicAlgorithm.RSA
        length = 2048
        algorithm_attribute = self.attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM, algorithm)
        length_attribute = self.attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_LENGTH, length)
        opn_attribute = self.attribute_factory.create_attribute(
            enums.AttributeType.OPERATION_POLICY_NAME,
            'test'
        )

        pair_attributes = [
            opn_attribute,
            algorithm_attribute,
            length_attribute
        ]
        template = obj.TemplateAttribute(
            attributes=pair_attributes,
            tag=enums.Tags.COMMON_TEMPLATE_ATTRIBUTE
        )

        status = enums.ResultStatus.SUCCESS
        result = results.CreateKeyPairResult(
            contents.ResultStatus(status),
            public_key_uuid="aaaaaaaa-1111-2222-3333-ffffffffffff",
            private_key_uuid="ffffffff-3333-2222-1111-aaaaaaaaaaaa"
        )

        with ProxyKmipClient() as client:
            client.proxy.create_key_pair.return_value = result

            public_uid, private_uid = client.create_key_pair(
                enums.CryptographicAlgorithm.RSA,
                2048,
                operation_policy_name='test'
            )

            kwargs = {
                "common_template_attribute": template,
                "private_key_template_attribute": None,
                "public_key_template_attribute": None
            }
            client.proxy.create_key_pair.assert_called_with(**kwargs)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_create_key_pair_with_key_names(self):
        """
        Test that an asymmetric key pair can be created with proper inputs,
        specifically testing that the private / public names are correctly
        sent with the request
        """
        common_template = obj.TemplateAttribute(
            attributes=[
                self.attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                    enums.CryptographicAlgorithm.RSA
                ),
                self.attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                    2048
                )
            ],
            tag=enums.Tags.COMMON_TEMPLATE_ATTRIBUTE
        )
        private_template = obj.TemplateAttribute(
            attributes=[
                self.attribute_factory.create_attribute(
                    enums.AttributeType.NAME,
                    "Test_Private_Key"
                )
            ],
            tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
        )
        public_template = obj.TemplateAttribute(
            attributes=[
                self.attribute_factory.create_attribute(
                    enums.AttributeType.NAME,
                    "Test_Public_Key"
                )
            ],
            tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
        )

        status = enums.ResultStatus.SUCCESS
        result = results.CreateKeyPairResult(
            contents.ResultStatus(status),
            public_key_uuid="aaaaaaaa-1111-2222-3333-ffffffffffff",
            private_key_uuid="ffffffff-3333-2222-1111-aaaaaaaaaaaa"
        )

        with ProxyKmipClient() as client:
            client.proxy.create_key_pair.return_value = result

            public_uid, private_uid = client.create_key_pair(
                enums.CryptographicAlgorithm.RSA,
                2048,
                public_name="Test_Public_Key",
                private_name="Test_Private_Key"
            )

            kwargs = {
                "common_template_attribute": common_template,
                "private_key_template_attribute": private_template,
                "public_key_template_attribute": public_template
            }
            client.proxy.create_key_pair.assert_called_with(**kwargs)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_create_key_pair_with_empty_names(self):
        """
        Test that empty key names are ignored.
        """
        common_template = obj.TemplateAttribute(
            attributes=[
                self.attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                    enums.CryptographicAlgorithm.RSA
                ),
                self.attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                    2048
                )
            ],
            tag=enums.Tags.COMMON_TEMPLATE_ATTRIBUTE
        )

        status = enums.ResultStatus.SUCCESS
        result = results.CreateKeyPairResult(
            contents.ResultStatus(status),
            public_key_uuid="aaaaaaaa-1111-2222-3333-ffffffffffff",
            private_key_uuid="ffffffff-3333-2222-1111-aaaaaaaaaaaa"
        )

        with ProxyKmipClient() as client:
            client.proxy.create_key_pair.return_value = result

            client.create_key_pair(
                enums.CryptographicAlgorithm.RSA,
                2048,
                public_name="",
                private_name=""
            )

            kwargs = {
                "common_template_attribute": common_template,
                "private_key_template_attribute": None,
                "public_key_template_attribute": None
            }
            client.proxy.create_key_pair.assert_called_with(**kwargs)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_create_key_pair_with_cryptographic_usage_masks(self):
        """
        Test that an asymmetric key pair can be created with proper inputs,
        specifically testing that the private / public usage masks are
        correctly sent with the request.
        """
        # Create the template to test the create key pair call
        algorithm = enums.CryptographicAlgorithm.RSA
        length = 2048
        algorithm_attribute = self.attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM, algorithm)
        length_attribute = self.attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_LENGTH, length)

        private_usage_mask = self.attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
            [enums.CryptographicUsageMask.SIGN]
        )
        public_usage_mask = self.attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
            [enums.CryptographicUsageMask.VERIFY]
        )

        pair_attributes = [
            algorithm_attribute,
            length_attribute
        ]

        template = obj.TemplateAttribute(
            attributes=pair_attributes,
            tag=enums.Tags.COMMON_TEMPLATE_ATTRIBUTE
        )
        private_template = obj.TemplateAttribute(
            attributes=[private_usage_mask],
            tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
        )
        public_template = obj.TemplateAttribute(
            attributes=[public_usage_mask],
            tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
        )

        status = enums.ResultStatus.SUCCESS
        result = results.CreateKeyPairResult(
            contents.ResultStatus(status),
            public_key_uuid="aaaaaaaa-1111-2222-3333-ffffffffffff",
            private_key_uuid="ffffffff-3333-2222-1111-aaaaaaaaaaaa"
        )

        with ProxyKmipClient() as client:
            client.proxy.create_key_pair.return_value = result

            _, _ = client.create_key_pair(
                enums.CryptographicAlgorithm.RSA,
                2048,
                public_usage_mask=[enums.CryptographicUsageMask.VERIFY],
                private_usage_mask=[enums.CryptographicUsageMask.SIGN]
            )

            kwargs = {
                "common_template_attribute": template,
                "private_key_template_attribute": private_template,
                "public_key_template_attribute": public_template
            }
            client.proxy.create_key_pair.assert_called_with(**kwargs)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_create_key_pair_on_invalid_algorithm(self):
        """
        Test that a TypeError exception is raised when trying to create an
        asymmetric key pair with an invalid algorithm.
        """
        args = ['invalid', 256]
        with ProxyKmipClient() as client:
            self.assertRaises(
                TypeError, client.create_key_pair, *args)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_create_key_pair_on_invalid_algorithm_enum_type(self):
        """
        Test that a TypeError is raised for an enum of the wrong type.
        """
        args = [enums.ObjectType.PUBLIC_KEY, 2048]
        with ProxyKmipClient() as client:
            self.assertRaises(
                TypeError, client.create_key_pair, *args)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_create_key_pair_on_invalid_algorithm_int(self):
        """
        Test that a TypeError is raised for a non-enum algorithm value.
        """
        args = [1, 2048]
        with ProxyKmipClient() as client:
            self.assertRaises(
                TypeError, client.create_key_pair, *args)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_create_key_pair_on_invalid_length(self):
        """
        Test that a TypeError exception is raised when trying to create an
        asymmetric key pair with an invalid length.
        """
        args = [enums.CryptographicAlgorithm.AES, 'invalid']
        with ProxyKmipClient() as client:
            self.assertRaises(
                TypeError, client.create_key_pair, *args)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_create_key_pair_on_non_positive_length(self):
        """
        Test that a TypeError is raised for non-positive key lengths.
        """
        for length in (0, -1):
            with ProxyKmipClient() as client:
                self.assertRaises(
                    TypeError,
                    client.create_key_pair,
                    enums.CryptographicAlgorithm.RSA,
                    length
                )

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_create_key_pair_with_none_optionals(self):
        """
        Test that create_key_pair accepts explicit None optional parameters.
        """
        common_template = obj.TemplateAttribute(
            attributes=[
                self.attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                    enums.CryptographicAlgorithm.RSA
                ),
                self.attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                    2048
                )
            ],
            tag=enums.Tags.COMMON_TEMPLATE_ATTRIBUTE
        )

        status = enums.ResultStatus.SUCCESS
        result = results.CreateKeyPairResult(
            contents.ResultStatus(status),
            public_key_uuid="aaaaaaaa-1111-2222-3333-ffffffffffff",
            private_key_uuid="ffffffff-3333-2222-1111-aaaaaaaaaaaa"
        )

        with ProxyKmipClient() as client:
            client.proxy.create_key_pair.return_value = result

            client.create_key_pair(
                enums.CryptographicAlgorithm.RSA,
                2048,
                operation_policy_name=None,
                public_name=None,
                public_usage_mask=None,
                private_name=None,
                private_usage_mask=None
            )

            kwargs = {
                "common_template_attribute": common_template,
                "private_key_template_attribute": None,
                "public_key_template_attribute": None
            }
            client.proxy.create_key_pair.assert_called_with(**kwargs)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_create_key_pair_on_closed(self):
        """
        Test that a ClientConnectionNotOpen exception is raised when trying
        to create an asymmetric key pair on an unopened client connection.
        """
        client = ProxyKmipClient()
        args = [enums.CryptographicAlgorithm.RSA, 2048]
        self.assertRaises(
            ClientConnectionNotOpen, client.create_key_pair, *args)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_create_key_pair_on_operation_failure(self):
        """
        Test that a KmipOperationFailure exception is raised when the
        backend fails to create an asymmetric key pair.
        """
        status = enums.ResultStatus.OPERATION_FAILED
        reason = enums.ResultReason.GENERAL_FAILURE
        message = "Test failure message"

        result = results.OperationResult(
            contents.ResultStatus(status),
            contents.ResultReason(reason),
            contents.ResultMessage(message))
        error_msg = str(KmipOperationFailure(status, reason, message))

        client = ProxyKmipClient()
        client.open()
        client.proxy.create_key_pair.return_value = result
        args = [enums.CryptographicAlgorithm.RSA, 2048]

        self.assertRaisesRegex(
            KmipOperationFailure, error_msg,
            client.create_key_pair, *args)

    @mock.patch(
        "kmip.pie.client.KMIPProxy",
        mock.MagicMock(spec_set=KMIPProxy)
    )
    def test_delete_attribute(self):
        """
        Test that the client can delete an attribute.
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

        with ProxyKmipClient() as client:
            client.proxy.send_request_payload.return_value = response_payload

            unique_identifier, attribute = client.delete_attribute(
                "1",
                attribute_name="Object Group",
                attribute_index=2
            )

            args = (
                enums.Operation.DELETE_ATTRIBUTE,
                request_payload
            )
            client.proxy.send_request_payload.assert_called_with(*args)
            self.assertEqual("1", unique_identifier)
            self.assertIsNone(attribute)

    @mock.patch(
        "kmip.pie.client.KMIPProxy",
        mock.MagicMock(spec_set=KMIPProxy)
    )
    def test_set_attribute(self):
        """
        Test that the client can set an attribute.
        """
        request_payload = payloads.SetAttributeRequestPayload(
            unique_identifier="1",
            new_attribute=obj.NewAttribute(
                attribute=primitives.Boolean(
                    value=True,
                    tag=enums.Tags.SENSITIVE
                )
            )
        )
        response_payload = payloads.SetAttributeResponsePayload(
            unique_identifier="1"
        )

        with ProxyKmipClient() as client:
            client.proxy.send_request_payload.return_value = response_payload

            unique_identifier = client.set_attribute(
                "1",
                attribute_name="Sensitive",
                attribute_value=True
            )

            args = (
                enums.Operation.SET_ATTRIBUTE,
                request_payload
            )
            client.proxy.send_request_payload.assert_called_with(*args)
            self.assertEqual("1", unique_identifier)

    @mock.patch(
        "kmip.pie.client.KMIPProxy",
        mock.MagicMock(spec_set=KMIPProxy)
    )
    def test_modify_attribute(self):
        """
        Test that the client can modify an attribute.
        """
        request_payload = payloads.ModifyAttributeRequestPayload(
            unique_identifier="1",
            new_attribute=obj.NewAttribute(
                attribute=primitives.Boolean(
                    value=True,
                    tag=enums.Tags.SENSITIVE
                )
            )
        )
        response_payload = payloads.ModifyAttributeResponsePayload(
            unique_identifier="1"
        )

        with ProxyKmipClient() as client:
            client.proxy.send_request_payload.return_value = response_payload

            unique_identifier, attribute = client.modify_attribute(
                unique_identifier="1",
                new_attribute=obj.NewAttribute(
                    attribute=primitives.Boolean(
                        value=True,
                        tag=enums.Tags.SENSITIVE
                    )
                )
            )

            args = (
                enums.Operation.MODIFY_ATTRIBUTE,
                request_payload
            )
            client.proxy.send_request_payload.assert_called_with(*args)
            self.assertEqual("1", unique_identifier)
            self.assertIsNone(attribute)

    @mock.patch(
        'kmip.pie.client.KMIPProxy', mock.MagicMock(spec_set=KMIPProxy)
    )
    def test_rekey(self):
        """
        Test that the client can rekey an object.
        """
        result = {
            'unique_identifier': '2',
            'result_status': enums.ResultStatus.SUCCESS
        }

        client = ProxyKmipClient()
        client.open()
        client.proxy.rekey.return_value = result

        checked_id = client.rekey(
            uid='1',
            offset=0,
            activation_date=1000000,
            process_start_date=1000001,
            protect_stop_date=1000002,
            deactivation_date=1000003
        )

        self.assertEqual('2', checked_id)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_rekey_on_invalid_unique_identifier(self):
        """
        Test that a TypeError exception is raised when trying to rekey an
        object with an invalid unique identifier.
        """
        kwargs = {'uid': 0}
        with ProxyKmipClient() as client:
            self.assertRaisesRegex(
                TypeError,
                "The unique identifier must be a string.",
                client.rekey,
                **kwargs
            )

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_rekey_on_invalid_offset(self):
        """
        Test that a TypeError exception is raised when trying to rekey an
        object with an invalid offset.
        """
        kwargs = {'offset': 'invalid'}
        with ProxyKmipClient() as client:
            self.assertRaisesRegex(
                TypeError,
                "The offset must be an integer.",
                client.rekey,
                **kwargs
            )

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_rekey_on_closed(self):
        """
        Test that a ClientConnectionNotOpen exception is raised when trying
        to rekey an object on an unopened client connection.
        """
        client = ProxyKmipClient()
        kwargs = {
            'uid': '1',
            'offset': 10
        }

        self.assertRaises(
            ClientConnectionNotOpen,
            client.rekey,
            **kwargs
        )

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_rekey_on_operation_failure(self):
        """
        Test that a KmipOperationFailure exception is raised when the
        backend fails to rekey a key.
        """
        status = enums.ResultStatus.OPERATION_FAILED
        reason = enums.ResultReason.GENERAL_FAILURE
        message = "Test failure message"

        result = {
            'result_status': status,
            'result_reason': reason,
            'result_message': message
        }
        error_message = str(KmipOperationFailure(status, reason, message))

        client = ProxyKmipClient()
        client.open()
        client.proxy.rekey.return_value = result
        kwargs = {
            'uid': '1',
            'offset': 1,
            'deactivation_date': 10000
        }

        self.assertRaisesRegex(
            KmipOperationFailure,
            error_message,
            client.rekey,
            **kwargs
        )

    @mock.patch(
        'kmip.pie.client.KMIPProxy', mock.MagicMock(spec_set=KMIPProxy)
    )
    def test_check(self):
        """
        Test that the client can check an object.
        """
        result = {
            'unique_identifier': '1',
            'result_status': enums.ResultStatus.SUCCESS
        }

        client = ProxyKmipClient()
        client.open()
        client.proxy.check.return_value = result

        checked_id = client.check(
            uid='1',
            usage_limits_count=100,
            cryptographic_usage_mask=[
                enums.CryptographicUsageMask.ENCRYPT,
                enums.CryptographicUsageMask.DECRYPT
            ],
            lease_time=10000
        )

        self.assertEqual('1', checked_id)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_check_on_invalid_unique_identifier(self):
        """
        Test that a TypeError exception is raised when trying to check an
        object with an invalid unique identifier.
        """
        kwargs = {'uid': 0}
        with ProxyKmipClient() as client:
            self.assertRaisesRegex(
                TypeError,
                "The unique identifier must be a string.",
                client.check,
                **kwargs
            )

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_check_on_invalid_usage_limits_count(self):
        """
        Test that a TypeError exception is raised when trying to check an
        object with an invalid usage limits count.
        """
        kwargs = {'usage_limits_count': 'invalid'}
        with ProxyKmipClient() as client:
            self.assertRaisesRegex(
                TypeError,
                "The usage limits count must be an integer.",
                client.check,
                **kwargs
            )

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_check_on_invalid_cryptographic_usage_mask(self):
        """
        Test that a TypeError exception is raised when trying to check an
        object with an invalid cryptographic usage mask.
        """
        kwargs = {'cryptographic_usage_mask': 'invalid'}
        with ProxyKmipClient() as client:
            self.assertRaisesRegex(
                TypeError,
                "The cryptographic usage mask must be a list of "
                "CryptographicUsageMask enumerations.",
                client.check,
                **kwargs
            )

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_check_on_invalid_lease_time(self):
        """
        Test that a TypeError exception is raised when trying to check an
        object with an invalid lease time.
        """
        kwargs = {'lease_time': 'invalid'}
        with ProxyKmipClient() as client:
            self.assertRaisesRegex(
                TypeError,
                "The lease time must be an integer.",
                client.check,
                **kwargs
            )

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_check_on_closed(self):
        """
        Test that a ClientConnectionNotOpen exception is raised when trying
        to check an object on an unopened client connection.
        """
        client = ProxyKmipClient()
        kwargs = {
            'uid': '1',
            'usage_limits_count': 100,
            'cryptographic_usage_mask': [
                enums.CryptographicUsageMask.ENCRYPT,
                enums.CryptographicUsageMask.DECRYPT
            ],
            'lease_time': 10000
        }

        self.assertRaises(
            ClientConnectionNotOpen,
            client.check,
            **kwargs
        )

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_check_on_operation_failure(self):
        """
        Test that a KmipOperationFailure exception is raised when the
        backend fails to derive a key.
        """
        status = enums.ResultStatus.OPERATION_FAILED
        reason = enums.ResultReason.GENERAL_FAILURE
        message = "Test failure message"

        result = {
            'result_status': status,
            'result_reason': reason,
            'result_message': message
        }
        error_message = str(KmipOperationFailure(status, reason, message))

        client = ProxyKmipClient()
        client.open()
        client.proxy.check.return_value = result
        kwargs = {
            'uid': '1',
            'usage_limits_count': 100,
            'cryptographic_usage_mask': [
                enums.CryptographicUsageMask.ENCRYPT,
                enums.CryptographicUsageMask.DECRYPT
            ],
            'lease_time': 10000
        }

        self.assertRaisesRegex(
            KmipOperationFailure,
            error_message,
            client.check,
            **kwargs
        )

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_get(self):
        """
        Test that a secret can be retrieved with proper input.
        """
        # Key encoding obtained from Section 14.2 of the KMIP 1.1 test
        # documentation.
        secret = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            128,
            (b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E'
             b'\x0F'))
        fact = factory.ObjectFactory()

        result = results.GetResult(
            contents.ResultStatus(enums.ResultStatus.SUCCESS),
            uuid=attr.PublicKeyUniqueIdentifier(
                'aaaaaaaa-1111-2222-3333-ffffffffffff'),
            secret=fact.convert(secret))

        with ProxyKmipClient() as client:
            client.proxy.get.return_value = result

            result = client.get('aaaaaaaa-1111-2222-3333-ffffffffffff')
            client.proxy.get.assert_called_with(
                'aaaaaaaa-1111-2222-3333-ffffffffffff',
                key_wrapping_specification=None
            )
            self.assertIsInstance(result, objects.SymmetricKey)
            self.assertEqual(result, secret)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_get_on_invalid_uid(self):
        """
        Test that a TypeError exception is raised when trying to retrieve a
        secret with an invalid ID.
        """
        args = [0]
        with ProxyKmipClient() as client:
            self.assertRaises(TypeError, client.get, *args)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_get_on_invalid_key_wrapping_specification(self):
        """
        Test that a TypeError exception is raised when trying to retrieve a
        secret with an invalid key wrapping specification.
        """
        args = ['1']
        kwargs = {'key_wrapping_specification': 'invalid'}
        with ProxyKmipClient() as client:
            self.assertRaisesRegex(
                TypeError,
                "Key wrapping specification must be a dictionary.",
                client.get,
                *args,
                **kwargs
            )

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_get_on_closed(self):
        """
        Test that a ClientConnectionNotOpen exception is raised when trying
        to retrieve a secret on an unopened client connection.
        """
        client = ProxyKmipClient()
        args = ['aaaaaaaa-1111-2222-3333-ffffffffffff']
        self.assertRaises(ClientConnectionNotOpen, client.get, *args)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_get_on_operation_failure(self):
        """
        Test that a KmipOperationFailure exception is raised when the
        backend fails to retrieve a secret.
        """
        status = enums.ResultStatus.OPERATION_FAILED
        reason = enums.ResultReason.GENERAL_FAILURE
        message = "Test failure message"

        result = results.OperationResult(
            contents.ResultStatus(status),
            contents.ResultReason(reason),
            contents.ResultMessage(message))
        error_msg = str(KmipOperationFailure(status, reason, message))

        client = ProxyKmipClient()
        client.open()
        client.proxy.get.return_value = result
        args = ['id']

        self.assertRaisesRegex(
            KmipOperationFailure, error_msg, client.get, *args)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_get_attributes(self):
        """
        Test that a secret's attributes can be retrieved with proper input.
        """
        result = results.GetAttributesResult(
            contents.ResultStatus(enums.ResultStatus.SUCCESS),
            uuid='aaaaaaaa-1111-2222-3333-ffffffffffff',
            attributes=[
                obj.Attribute(
                    attribute_name=obj.Attribute.AttributeName('Name'),
                    attribute_index=obj.Attribute.AttributeIndex(0),
                    attribute_value=attr.Name(
                        name_value=attr.Name.NameValue('Test Name'),
                        name_type=attr.Name.NameType(
                            enums.NameType.UNINTERPRETED_TEXT_STRING
                        )
                    )
                ),
                obj.Attribute(
                    attribute_name=obj.Attribute.AttributeName('Object Type'),
                    attribute_value=attr.ObjectType(
                        enums.ObjectType.SYMMETRIC_KEY
                    )
                )
            ]
        )

        with ProxyKmipClient() as client:
            client.proxy.get_attributes.return_value = result

            result = client.get_attributes(
                'aaaaaaaa-1111-2222-3333-ffffffffffff',
                ['Name', 'Object Type']
            )
            client.proxy.get_attributes.assert_called_with(
                'aaaaaaaa-1111-2222-3333-ffffffffffff',
                ['Name', 'Object Type']
            )
            self.assertIsInstance(result[0], str)
            self.assertIsInstance(result[1], list)
            for r in result[1]:
                self.assertIsInstance(r, obj.Attribute)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_get_attributes_on_invalid_uid(self):
        """
        Test that a TypeError exception is raised when trying to retrieve a
        secret's attributes with an invalid ID.
        """
        args = [0]
        with ProxyKmipClient() as client:
            self.assertRaisesRegex(
                TypeError,
                "uid must be a string",
                client.get_attributes,
                *args
            )

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_get_attributes_on_invalid_attribute_names(self):
        """
        Test that a TypeError exception is raised when trying to retrieve a
        secret's attributes with an invalid attribute name set.
        """
        args = [None, 0]
        with ProxyKmipClient() as client:
            self.assertRaisesRegex(
                TypeError,
                "attribute_names must be a list of strings",
                client.get_attributes,
                *args
            )

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_get_attributes_on_invalid_attribute_name(self):
        """
        Test that a TypeError exception is raised when trying to retrieve a
        secret's attributes with an invalid attribute name.
        """
        args = [None, [0]]
        with ProxyKmipClient() as client:
            self.assertRaisesRegex(
                TypeError,
                "attribute_names must be a list of strings",
                client.get_attributes,
                *args
            )

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_get_attributes_on_closed(self):
        """
        Test that a ClientConnectionNotOpen exception is raised when trying
        to retrieve a secret's attributes on an unopened client connection.
        """
        client = ProxyKmipClient()
        args = [
            'aaaaaaaa-1111-2222-3333-ffffffffffff',
            ['Name', 'Object Type']
        ]
        self.assertRaises(
            ClientConnectionNotOpen,
            client.get_attributes,
            *args
        )

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_get_attributes_on_operation_failure(self):
        """
        Test that a KmipOperationFailure exception is raised when the
        backend fails to retrieve a secret's attributes.
        """
        status = enums.ResultStatus.OPERATION_FAILED
        reason = enums.ResultReason.GENERAL_FAILURE
        message = "Test failure message"

        result = results.OperationResult(
            contents.ResultStatus(status),
            contents.ResultReason(reason),
            contents.ResultMessage(message))
        error_msg = str(KmipOperationFailure(status, reason, message))

        client = ProxyKmipClient()
        client.open()
        client.proxy.get_attributes.return_value = result
        args = ['id', []]

        self.assertRaisesRegex(
            KmipOperationFailure, error_msg, client.get_attributes, *args)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_get_attribute_list(self):
        """
        Test that the attribute names of a managed object can be retrieved
        with proper input.
        """
        uid = 'b4faee10-aa2a-4446-8ad4-0881f3422959'
        attribute_names = [
            'Cryptographic Length',
            'Cryptographic Algorithm',
            'State',
            'Digest',
            'Lease Time',
            'Initial Date',
            'Unique Identifier',
            'Name',
            'Cryptographic Usage Mask',
            'Object Type',
            'Contact Information',
            'Last Change Date']
        result = results.GetAttributeListResult(
            contents.ResultStatus(enums.ResultStatus.SUCCESS),
            uid=uid,
            names=attribute_names)

        with ProxyKmipClient() as client:
            client.proxy.get_attribute_list.return_value = result

            result = client.get_attribute_list(uid)
            client.proxy.get_attribute_list.assert_called_with(uid)
            self.assertIsInstance(result, list)
            self.assertCountEqual(attribute_names, result)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_get_attribute_list_on_invalid_uid(self):
        """
        Test that a TypeError exception is raised when trying to retrieve the
        attribute names of a managed object with an invalid ID.
        """
        args = [0]
        with ProxyKmipClient() as client:
            self.assertRaises(TypeError, client.get_attribute_list, *args)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_get_attribute_list_on_closed(self):
        """
        Test that a ClientConnectionNotOpen exception is raised when trying
        to retrieve the attribute names of a managed object on an unopened
        client connection.
        """
        client = ProxyKmipClient()
        args = ['aaaaaaaa-1111-2222-3333-ffffffffffff']
        self.assertRaises(
            ClientConnectionNotOpen, client.get_attribute_list, *args)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_get_attribute_list_on_operation_failure(self):
        """
        Test that a KmipOperationFailure exception is raised when the
        backend fails to retrieve the attribute names of a managed object.
        """
        status = enums.ResultStatus.OPERATION_FAILED
        reason = enums.ResultReason.GENERAL_FAILURE
        message = "Test failure message"

        result = results.OperationResult(
            contents.ResultStatus(status),
            contents.ResultReason(reason),
            contents.ResultMessage(message))
        error_msg = str(KmipOperationFailure(status, reason, message))

        client = ProxyKmipClient()
        client.open()
        client.proxy.get_attribute_list.return_value = result
        args = ['id']

        self.assertRaisesRegex(
            KmipOperationFailure, error_msg, client.get_attribute_list, *args)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_activate(self):
        """
        Test that the client can activate a secret.
        """
        status = enums.ResultStatus.SUCCESS
        result = results.OperationResult(contents.ResultStatus(status))

        with ProxyKmipClient() as client:
            client.proxy.activate.return_value = result
            result = client.activate(
                'aaaaaaaa-1111-2222-3333-ffffffffffff')
            client.proxy.activate.assert_called_with(
                'aaaaaaaa-1111-2222-3333-ffffffffffff')
            self.assertEqual(None, result)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_activate_on_invalid_uid(self):
        """
        Test that a TypeError exception is raised when trying to activate a
        secret with an invalid ID.
        """
        args = [0]
        with ProxyKmipClient() as client:
            self.assertRaises(TypeError, client.activate, *args)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_activate_on_closed(self):
        """
        Test that a ClientConnectionNotOpen exception is raised when trying
        to activate a secret on an unopened client connection.
        """
        client = ProxyKmipClient()
        args = ['aaaaaaaa-1111-2222-3333-ffffffffffff']
        self.assertRaises(
            ClientConnectionNotOpen, client.activate, *args)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_activate_on_operation_failure(self):
        """
        Test that a KmipOperationFailure exception is raised when the
        backend fails to activate a secret.
        """
        status = enums.ResultStatus.OPERATION_FAILED
        reason = enums.ResultReason.GENERAL_FAILURE
        message = "Test failure message"

        result = results.OperationResult(
            contents.ResultStatus(status),
            contents.ResultReason(reason),
            contents.ResultMessage(message))
        error_msg = str(KmipOperationFailure(status, reason, message))

        client = ProxyKmipClient()
        client.open()
        client.proxy.activate.return_value = result
        args = ['id']

        self.assertRaisesRegex(
            KmipOperationFailure, error_msg, client.activate, *args)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_revoke(self):
        """
        Test that the client can revoke a secret.
        """
        revocation_reason = enums.RevocationReasonCode.KEY_COMPROMISE
        uuid = 'aaaaaaaa-1111-2222-3333-ffffffffffff'
        revocation_message = 'Key compromised!'
        compromise_occurrence_date = 1

        status = enums.ResultStatus.SUCCESS
        result = results.OperationResult(contents.ResultStatus(status))

        with ProxyKmipClient() as client:
            client.proxy.revoke.return_value = result
            result = client.revoke(
                revocation_reason, uuid, revocation_message,
                compromise_occurrence_date)
            client.proxy.revoke.assert_called_with(
                revocation_reason, uuid, revocation_message,
                DateTime(compromise_occurrence_date,
                         enums.Tags.COMPROMISE_OCCURRENCE_DATE))
            self.assertEqual(None, result)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_revoke_on_invalid_inputs(self):
        """
        Test that a TypeError exception is raised when trying to revoke a
        secret with invalid inputs.
        """
        revocation_reason = enums.RevocationReasonCode.KEY_COMPROMISE
        revocation_reason_invalid = "key compromise"

        uuid = 'aaaaaaaa-1111-2222-3333-ffffffffffff'
        uuid_invalid = 123

        revocation_message = 'Key compromised!'
        revocation_message_invalid = 123

        compromise_occurrence_date = 1
        compromise_occurrence_date_invalid = '1'

        args = [revocation_reason_invalid, uuid, revocation_message,
                compromise_occurrence_date]
        with ProxyKmipClient() as client:
            self.assertRaisesRegex(
                TypeError,
                "revocation_reason must be a RevocationReasonCode enumeration",
                client.revoke,
                *args)

        args = [revocation_reason, uuid_invalid, revocation_message,
                compromise_occurrence_date]
        with ProxyKmipClient() as client:
            self.assertRaisesRegex(
                TypeError,
                "uid must be a string",
                client.revoke,
                *args)

        args = [revocation_reason, uuid, revocation_message_invalid,
                compromise_occurrence_date]
        with ProxyKmipClient() as client:
            self.assertRaisesRegex(
                TypeError,
                "revocation_message must be a string",
                client.revoke,
                *args)

        args = [revocation_reason, uuid, revocation_message,
                compromise_occurrence_date_invalid]
        with ProxyKmipClient() as client:
            self.assertRaisesRegex(
                TypeError,
                "compromise_occurrence_date must be an integer",
                client.revoke,
                *args)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_revoke_on_closed(self):
        """
        Test that a ClientConnectionNotOpen exception is raised when trying
        to revoke a secret on an unopened client connection.
        """
        client = ProxyKmipClient()
        revocation_reason = enums.RevocationReasonCode.KEY_COMPROMISE
        uuid = 'aaaaaaaa-1111-2222-3333-ffffffffffff'
        revocation_message = 'Key compromised!'
        compromise_occurrence_date = 1
        args = [revocation_reason, uuid, revocation_message,
                compromise_occurrence_date]
        self.assertRaises(
            ClientConnectionNotOpen, client.revoke, *args)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_revoke_on_operation_failure(self):
        """
        Test that a KmipOperationFailure exception is raised when the
        backend fails to revoke a secret.
        """
        status = enums.ResultStatus.OPERATION_FAILED
        reason = enums.ResultReason.GENERAL_FAILURE
        revocation_message = "Test failure message"

        result = results.OperationResult(
            contents.ResultStatus(status),
            contents.ResultReason(reason),
            contents.ResultMessage(revocation_message))
        error_msg = str(KmipOperationFailure(status, reason,
                                             revocation_message))

        client = ProxyKmipClient()
        client.open()
        client.proxy.revoke.return_value = result

        revocation_reason = enums.RevocationReasonCode.KEY_COMPROMISE
        uuid = 'aaaaaaaa-1111-2222-3333-ffffffffffff'
        revocation_message = 'Key compromised!'
        compromise_occurrence_date = 1
        args = [revocation_reason, uuid, revocation_message,
                compromise_occurrence_date]

        self.assertRaisesRegex(
            KmipOperationFailure, error_msg, client.revoke, *args)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_destroy(self):
        """
        Test that the client can destroy a secret.
        """
        status = enums.ResultStatus.SUCCESS
        result = results.OperationResult(contents.ResultStatus(status))

        with ProxyKmipClient() as client:
            client.proxy.destroy.return_value = result
            result = client.destroy(
                'aaaaaaaa-1111-2222-3333-ffffffffffff')
            client.proxy.destroy.assert_called_with(
                'aaaaaaaa-1111-2222-3333-ffffffffffff')
            self.assertEqual(None, result)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_destroy_on_invalid_uid(self):
        """
        Test that a TypeError exception is raised when trying to destroy a
        secret with an invalid ID.
        """
        args = [0]
        with ProxyKmipClient() as client:
            self.assertRaises(TypeError, client.destroy, *args)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_destroy_on_closed(self):
        """
        Test that a ClientConnectionNotOpen exception is raised when trying
        to destroy a secret on an unopened client connection.
        """
        client = ProxyKmipClient()
        args = ['aaaaaaaa-1111-2222-3333-ffffffffffff']
        self.assertRaises(
            ClientConnectionNotOpen, client.destroy, *args)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_destroy_on_operation_failure(self):
        """
        Test that a KmipOperationFailure exception is raised when the
        backend fails to destroy a secret.
        """
        status = enums.ResultStatus.OPERATION_FAILED
        reason = enums.ResultReason.GENERAL_FAILURE
        message = "Test failure message"

        result = results.OperationResult(
            contents.ResultStatus(status),
            contents.ResultReason(reason),
            contents.ResultMessage(message))
        error_msg = str(KmipOperationFailure(status, reason, message))

        client = ProxyKmipClient()
        client.open()
        client.proxy.destroy.return_value = result
        args = ['id']

        self.assertRaisesRegex(
            KmipOperationFailure, error_msg, client.destroy, *args)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_register(self):
        """
        Test that the client can register a key.
        """
        key = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            128,
            (b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E'
             b'\x0F')
        )
        key.operation_policy_name = 'default'

        result = results.RegisterResult(
            contents.ResultStatus(enums.ResultStatus.SUCCESS),
            uuid='aaaaaaaa-1111-2222-3333-ffffffffffff'
        )

        with ProxyKmipClient() as client:
            client.proxy.register.return_value = result
            uid = client.register(key)
            self.assertTrue(client.proxy.register.called)
            self.assertIsInstance(uid, str)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_register_on_invalid_uid(self):
        """
        Test that a TypeError exception is raised when trying to register a
        key with an invalid key object.
        """
        args = ['invalid']
        with ProxyKmipClient() as client:
            self.assertRaises(TypeError, client.register, *args)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_register_on_closed(self):
        """
        Test that a ClientConnectionNotOpen exception is raised when trying
        to register a key on an unopened client connection.
        """
        key = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            128,
            (b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E'
             b'\x0F'))
        client = ProxyKmipClient()
        args = [key]
        self.assertRaises(ClientConnectionNotOpen, client.register, *args)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_register_on_operation_failure(self):
        """
        Test that a KmipOperationFailure exception is raised when the
        backend fails to register a key.
        """
        status = enums.ResultStatus.OPERATION_FAILED
        reason = enums.ResultReason.GENERAL_FAILURE
        message = "Test failure message"

        result = results.OperationResult(
            contents.ResultStatus(status),
            contents.ResultReason(reason),
            contents.ResultMessage(message))
        error_msg = str(KmipOperationFailure(status, reason, message))

        # Key encoding obtained from Section 14.2 of the KMIP 1.1 test
        # documentation.
        key_value = (
            b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E'
            b'\x0F')
        key = objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, key_value)

        client = ProxyKmipClient()
        client.open()
        client.proxy.register.return_value = result
        args = [key]

        self.assertRaisesRegex(
            KmipOperationFailure, error_msg, client.register, *args)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_build_common_attributes(self):
        """
        Test that the right attribute objects are created.
        """
        client = ProxyKmipClient()
        client.open()

        operation_policy_name = 'test'
        common_attributes = client._build_common_attributes(
            operation_policy_name=operation_policy_name
        )

        self.assertEqual(1, len(common_attributes))

        opn = common_attributes[0]
        self.assertIsInstance(opn, obj.Attribute)
        self.assertIsInstance(opn.attribute_name, obj.Attribute.AttributeName)
        self.assertIsInstance(opn.attribute_value, attr.OperationPolicyName)
        self.assertEqual(opn.attribute_name.value, 'Operation Policy Name')
        self.assertEqual(opn.attribute_value.value, 'test')

    @mock.patch(
        'kmip.pie.client.KMIPProxy', mock.MagicMock(spec_set=KMIPProxy)
    )
    def test_derive_key(self):
        """
        Test that the client can derive a key.
        """
        result = {
            'unique_identifier': '1',
            'result_status': enums.ResultStatus.SUCCESS
        }

        client = ProxyKmipClient()
        client.open()
        client.proxy.derive_key.return_value = result

        derived_id = client.derive_key(
            enums.ObjectType.SYMMETRIC_KEY,
            ['2', '3'],
            enums.DerivationMethod.ENCRYPT,
            {
                'cryptographic_parameters': {
                    'cryptographic_algorithm':
                        enums.CryptographicAlgorithm.AES,
                    'block_cipher_mode': enums.BlockCipherMode.CBC,
                    'padding_method': enums.PaddingMethod.PKCS1v15
                },
                'initialization_vector': b'\x01\x02\x03\x04',
                'derivation_data': b'\xFF\xFE\xFE\xFC'
            },
            cryptographic_length=128,
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
            cryptographic_usage_mask=[
                enums.CryptographicUsageMask.ENCRYPT,
                enums.CryptographicUsageMask.DECRYPT
            ]
        )

        self.assertEqual('1', derived_id)

    @mock.patch(
        'kmip.pie.client.KMIPProxy', mock.MagicMock(spec_set=KMIPProxy)
    )
    def test_derive_key_invalid_object_type(self):
        """
        Test that the right error is raised when attempting to derive a key
        with an invalid object type.
        """
        client = ProxyKmipClient()
        client.open()
        client.proxy.derive_key.return_value = {}
        args = [
            'invalid',
            ['2', '3'],
            enums.DerivationMethod.ENCRYPT,
            {
                'cryptographic_parameters': {
                    'cryptographic_algorithm':
                        enums.CryptographicAlgorithm.AES,
                    'block_cipher_mode': enums.BlockCipherMode.CBC,
                    'padding_method': enums.PaddingMethod.PKCS1v15
                },
                'initialization_vector': b'\x01\x02\x03\x04',
                'derivation_data': b'\xFF\xFE\xFE\xFC'
            }
        ]
        kwargs = {
            'cryptographic_length': 128,
            'cryptographic_algorithm': enums.CryptographicAlgorithm.AES
        }

        self.assertRaisesRegex(
            TypeError,
            "Object type must be an ObjectType enumeration.",
            client.derive_key,
            *args,
            **kwargs
        )

    @mock.patch(
        'kmip.pie.client.KMIPProxy', mock.MagicMock(spec_set=KMIPProxy)
    )
    def test_derive_key_invalid_unique_identifiers(self):
        """
        Test that the right error is raised when attempting to derive a key
        with an invalid list of unique identifiers.
        """
        client = ProxyKmipClient()
        client.open()
        client.proxy.derive_key.return_value = {}
        args = [
            enums.ObjectType.SYMMETRIC_KEY,
            'invalid',
            enums.DerivationMethod.ENCRYPT,
            {
                'cryptographic_parameters': {
                    'cryptographic_algorithm':
                        enums.CryptographicAlgorithm.AES,
                    'block_cipher_mode': enums.BlockCipherMode.CBC,
                    'padding_method': enums.PaddingMethod.PKCS1v15
                },
                'initialization_vector': b'\x01\x02\x03\x04',
                'derivation_data': b'\xFF\xFE\xFE\xFC'
            }
        ]
        kwargs = {
            'cryptographic_length': 128,
            'cryptographic_algorithm': enums.CryptographicAlgorithm.AES
        }

        self.assertRaisesRegex(
            TypeError,
            "Unique identifiers must be a list of strings.",
            client.derive_key,
            *args,
            **kwargs
        )

        args = [
            enums.ObjectType.SYMMETRIC_KEY,
            [2, 3],
            enums.DerivationMethod.ENCRYPT,
            {
                'cryptographic_parameters': {
                    'cryptographic_algorithm':
                        enums.CryptographicAlgorithm.AES,
                    'block_cipher_mode': enums.BlockCipherMode.CBC,
                    'padding_method': enums.PaddingMethod.PKCS1v15
                },
                'initialization_vector': b'\x01\x02\x03\x04',
                'derivation_data': b'\xFF\xFE\xFE\xFC'
            }
        ]

        self.assertRaisesRegex(
            TypeError,
            "Unique identifiers must be a list of strings.",
            client.derive_key,
            *args,
            **kwargs
        )

    @mock.patch(
        'kmip.pie.client.KMIPProxy', mock.MagicMock(spec_set=KMIPProxy)
    )
    def test_derive_key_invalid_derivation_method(self):
        """
        Test that the right error is raised when attempting to derive a key
        with an invalid derivation method.
        """
        client = ProxyKmipClient()
        client.open()
        client.proxy.derive_key.return_value = {}
        args = [
            enums.ObjectType.SYMMETRIC_KEY,
            ['2', '3'],
            'invalid',
            {
                'cryptographic_parameters': {
                    'cryptographic_algorithm':
                        enums.CryptographicAlgorithm.AES,
                    'block_cipher_mode': enums.BlockCipherMode.CBC,
                    'padding_method': enums.PaddingMethod.PKCS1v15
                },
                'initialization_vector': b'\x01\x02\x03\x04',
                'derivation_data': b'\xFF\xFE\xFE\xFC'
            }
        ]
        kwargs = {
            'cryptographic_length': 128,
            'cryptographic_algorithm': enums.CryptographicAlgorithm.AES
        }

        self.assertRaisesRegex(
            TypeError,
            "Derivation method must be a DerivationMethod enumeration.",
            client.derive_key,
            *args,
            **kwargs
        )

    @mock.patch(
        'kmip.pie.client.KMIPProxy', mock.MagicMock(spec_set=KMIPProxy)
    )
    def test_derive_key_invalid_derivation_parameters(self):
        """
        Test that the right error is raised when attempting to derive a key
        with an invalid derivation parameters.
        """
        client = ProxyKmipClient()
        client.open()
        client.proxy.derive_key.return_value = {}
        args = [
            enums.ObjectType.SYMMETRIC_KEY,
            ['2', '3'],
            enums.DerivationMethod.ENCRYPT,
            'invalid'
        ]
        kwargs = {
            'cryptographic_length': 128,
            'cryptographic_algorithm': enums.CryptographicAlgorithm.AES
        }

        self.assertRaisesRegex(
            TypeError,
            "Derivation parameters must be a dictionary.",
            client.derive_key,
            *args,
            **kwargs
        )

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_derive_key_on_closed(self):
        """
        Test that a ClientConnectionNotOpen exception is raised when trying
        to derive a key on an unopened client connection.
        """
        client = ProxyKmipClient()
        args = [
            enums.ObjectType.SYMMETRIC_KEY,
            ['2', '3'],
            enums.DerivationMethod.ENCRYPT,
            {
                'cryptographic_parameters': {
                    'cryptographic_algorithm':
                        enums.CryptographicAlgorithm.AES,
                    'block_cipher_mode': enums.BlockCipherMode.CBC,
                    'padding_method': enums.PaddingMethod.PKCS1v15
                },
                'initialization_vector': b'\x01\x02\x03\x04',
                'derivation_data': b'\xFF\xFE\xFE\xFC'
            }
        ]
        kwargs = {
            'cryptographic_length': 128,
            'cryptographic_algorithm': enums.CryptographicAlgorithm.AES
        }

        self.assertRaises(
            ClientConnectionNotOpen,
            client.derive_key,
            *args,
            **kwargs
        )

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_derive_key_on_operation_failure(self):
        """
        Test that a KmipOperationFailure exception is raised when the
        backend fails to derive a key.
        """
        status = enums.ResultStatus.OPERATION_FAILED
        reason = enums.ResultReason.GENERAL_FAILURE
        message = "Test failure message"

        result = {
            'result_status': status,
            'result_reason': reason,
            'result_message': message
        }
        error_message = str(KmipOperationFailure(status, reason, message))

        client = ProxyKmipClient()
        client.open()
        client.proxy.derive_key.return_value = result
        args = [
            enums.ObjectType.SYMMETRIC_KEY,
            ['2', '3'],
            enums.DerivationMethod.ENCRYPT,
            {
                'cryptographic_parameters': {
                    'cryptographic_algorithm':
                        enums.CryptographicAlgorithm.AES,
                    'block_cipher_mode': enums.BlockCipherMode.CBC,
                    'padding_method': enums.PaddingMethod.PKCS1v15
                },
                'initialization_vector': b'\x01\x02\x03\x04',
                'derivation_data': b'\xFF\xFE\xFE\xFC'
            }
        ]
        kwargs = {
            'cryptographic_length': 128,
            'cryptographic_algorithm': enums.CryptographicAlgorithm.AES
        }

        self.assertRaisesRegex(
            KmipOperationFailure,
            error_message,
            client.derive_key,
            *args,
            **kwargs
        )

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_encrypt(self):
        """
        Test that the client can encrypt data.
        """
        result = {
            'data': (
                b'\x6B\x77\xB4\xD6\x30\x06\xDE\xE6'
                b'\x05\xB1\x56\xE2\x74\x03\x97\x93'
                b'\x58\xDE\xB9\xE7\x15\x46\x16\xD9'
                b'\x74\x9D\xEC\xBE\xC0\x5D\x26\x4B'
            ),
            'iv_counter_nonce': None,
            'result_status': enums.ResultStatus.SUCCESS
        }

        client = ProxyKmipClient()
        client.open()
        client.proxy.encrypt.return_value = result

        encrypted_data, iv_counter_nonce = client.encrypt(
            (
                b'\x37\x36\x35\x34\x33\x32\x31\x20'
                b'\x4E\x6F\x77\x20\x69\x73\x20\x74'
                b'\x68\x65\x20\x74\x69\x6D\x65\x20'
                b'\x66\x6F\x72\x20\x00'
            ),
            uid='1',
            cryptographic_parameters={
                'block_cipher_mode': enums.BlockCipherMode.CBC,
                'padding_method': enums.PaddingMethod.PKCS5,
                'cryptographic_algorithm':
                    enums.CryptographicAlgorithm.BLOWFISH
            },
            iv_counter_nonce=b'\xFE\xDC\xBA\x98\x76\x54\x32\x10'
        )

        self.assertEqual(result.get('data'), encrypted_data)
        self.assertEqual(result.get('iv_counter_nonce'), iv_counter_nonce)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_encrypt_on_invalid_inputs(self):
        """
        Test that TypeError exception are raised when trying to encrypt with
        invalid parameters.
        """
        client = ProxyKmipClient()
        client.open()
        client.proxy.encrypt.return_value = {}
        args = [None]
        kwargs = {
            'uid': '1',
            'cryptographic_parameters': {},
            'iv_counter_nonce': b'\x00\x00\x00\x00'
        }

        self.assertRaisesRegex(
            TypeError,
            "data must be bytes",
            client.encrypt,
            *args,
            **kwargs
        )

        args = [b'\x01\x02\x03\x04']
        kwargs = {
            'uid': 1,
            'cryptographic_parameters': {},
            'iv_counter_nonce': b'\x00\x00\x00\x00'
        }

        self.assertRaisesRegex(
            TypeError,
            "uid must be a string",
            client.encrypt,
            *args,
            **kwargs
        )

        args = [b'\x01\x02\x03\x04']
        kwargs = {
            'uid': '1',
            'cryptographic_parameters': 'invalid',
            'iv_counter_nonce': b'\x00\x00\x00\x00'
        }

        self.assertRaisesRegex(
            TypeError,
            "cryptographic_parameters must be a dict",
            client.encrypt,
            *args,
            **kwargs
        )

        args = [b'\x01\x02\x03\x04']
        kwargs = {
            'uid': '1',
            'cryptographic_parameters': {},
            'iv_counter_nonce': {}
        }

        self.assertRaisesRegex(
            TypeError,
            "iv_counter_nonce must be bytes",
            client.encrypt,
            *args,
            **kwargs
        )

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_encrypt_on_closed(self):
        """
        Test that a ClientConnectionNotOpen exception is raised when trying
        to encrypt data on an unopened client connection.
        """
        client = ProxyKmipClient()
        args = [b'\x01\x02\x03\x04']
        kwargs = {
            'uid': '1',
            'cryptographic_parameters': {},
            'iv_counter_nonce': b'\x00\x00\x00\x00'
        }

        self.assertRaises(
            ClientConnectionNotOpen,
            client.encrypt,
            *args,
            **kwargs
        )

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_encrypt_on_operation_failure(self):
        """
        Test that a KmipOperationFailure exception is raised when the
        backend fails to encrypt data.
        """
        status = enums.ResultStatus.OPERATION_FAILED
        reason = enums.ResultReason.GENERAL_FAILURE
        message = "Test failure message"

        result = {
            'result_status': status,
            'result_reason': reason,
            'result_message': message
        }
        error_message = str(KmipOperationFailure(status, reason, message))

        client = ProxyKmipClient()
        client.open()
        client.proxy.encrypt.return_value = result
        args = [b'\x01\x02\x03\x04']
        kwargs = {
            'uid': '1',
            'cryptographic_parameters': {},
            'iv_counter_nonce': b'\x00\x00\x00\x00'
        }

        self.assertRaisesRegex(
            KmipOperationFailure,
            error_message,
            client.encrypt,
            *args,
            **kwargs
        )

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_decrypt(self):
        """
        Test that the client can decrypt data.
        """
        result = {
            'data': (
                b'\x37\x36\x35\x34\x33\x32\x31\x20'
                b'\x4E\x6F\x77\x20\x69\x73\x20\x74'
                b'\x68\x65\x20\x74\x69\x6D\x65\x20'
                b'\x66\x6F\x72\x20\x00'
            ),
            'result_status': enums.ResultStatus.SUCCESS
        }

        client = ProxyKmipClient()
        client.open()
        client.proxy.decrypt.return_value = result

        decrypted_data = client.decrypt(
            (
                b'\x6B\x77\xB4\xD6\x30\x06\xDE\xE6'
                b'\x05\xB1\x56\xE2\x74\x03\x97\x93'
                b'\x58\xDE\xB9\xE7\x15\x46\x16\xD9'
                b'\x74\x9D\xEC\xBE\xC0\x5D\x26\x4B'
            ),
            uid='1',
            cryptographic_parameters={
                'block_cipher_mode': enums.BlockCipherMode.CBC,
                'padding_method': enums.PaddingMethod.PKCS5,
                'cryptographic_algorithm':
                    enums.CryptographicAlgorithm.BLOWFISH
            },
            iv_counter_nonce=b'\xFE\xDC\xBA\x98\x76\x54\x32\x10'
        )

        self.assertEqual(result.get('data'), decrypted_data)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_decrypt_on_invalid_inputs(self):
        """
        Test that TypeError exception are raised when trying to decrypt with
        invalid parameters.
        """
        client = ProxyKmipClient()
        client.open()
        client.proxy.decrypt.return_value = {}
        args = [None]
        kwargs = {
            'uid': '1',
            'cryptographic_parameters': {},
            'iv_counter_nonce': b'\x00\x00\x00\x00'
        }

        self.assertRaisesRegex(
            TypeError,
            "data must be bytes",
            client.decrypt,
            *args,
            **kwargs
        )

        args = [b'\x01\x02\x03\x04']
        kwargs = {
            'uid': 1,
            'cryptographic_parameters': {},
            'iv_counter_nonce': b'\x00\x00\x00\x00'
        }

        self.assertRaisesRegex(
            TypeError,
            "uid must be a string",
            client.decrypt,
            *args,
            **kwargs
        )

        args = [b'\x01\x02\x03\x04']
        kwargs = {
            'uid': '1',
            'cryptographic_parameters': 'invalid',
            'iv_counter_nonce': b'\x00\x00\x00\x00'
        }

        self.assertRaisesRegex(
            TypeError,
            "cryptographic_parameters must be a dict",
            client.decrypt,
            *args,
            **kwargs
        )

        args = [b'\x01\x02\x03\x04']
        kwargs = {
            'uid': '1',
            'cryptographic_parameters': {},
            'iv_counter_nonce': {}
        }

        self.assertRaisesRegex(
            TypeError,
            "iv_counter_nonce must be bytes",
            client.decrypt,
            *args,
            **kwargs
        )

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_decrypt_on_closed(self):
        """
        Test that a ClientConnectionNotOpen exception is raised when trying
        to decrypt data on an unopened client connection.
        """
        client = ProxyKmipClient()
        args = [b'\x01\x02\x03\x04']
        kwargs = {
            'uid': '1',
            'cryptographic_parameters': {},
            'iv_counter_nonce': b'\x00\x00\x00\x00'
        }

        self.assertRaises(
            ClientConnectionNotOpen,
            client.decrypt,
            *args,
            **kwargs
        )

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_decrypt_on_operation_failure(self):
        """
        Test that a KmipOperationFailure exception is raised when the
        backend fails to decrypt data.
        """
        status = enums.ResultStatus.OPERATION_FAILED
        reason = enums.ResultReason.GENERAL_FAILURE
        message = "Test failure message"

        result = {
            'result_status': status,
            'result_reason': reason,
            'result_message': message
        }
        error_message = str(KmipOperationFailure(status, reason, message))

        client = ProxyKmipClient()
        client.open()
        client.proxy.decrypt.return_value = result
        args = [b'\x01\x02\x03\x04']
        kwargs = {
            'uid': '1',
            'cryptographic_parameters': {},
            'iv_counter_nonce': b'\x00\x00\x00\x00'
        }

        self.assertRaisesRegex(
            KmipOperationFailure,
            error_message,
            client.decrypt,
            *args,
            **kwargs
        )

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_signature_verify(self):
        """
        Test that the client can verify a signature.
        """
        result = {
            'unique_identifier': '1',
            'validity_indicator': enums.ValidityIndicator.VALID,
            'result_status': enums.ResultStatus.SUCCESS
        }

        client = ProxyKmipClient()
        client.open()
        client.proxy.signature_verify.return_value = result

        validity = client.signature_verify(
            (
                b'\x6B\x77\xB4\xD6\x30\x06\xDE\xE6'
                b'\x05\xB1\x56\xE2\x74\x03\x97\x93'
                b'\x58\xDE\xB9\xE7\x15\x46\x16\xD9'
                b'\x74\x9D\xEC\xBE\xC0\x5D\x26\x4B'
            ),
            (
                b'\x00\x00\x00\x00\x00\x00\x00\x00'
            ),
            uid='1',
            cryptographic_parameters={
                'block_cipher_mode': enums.BlockCipherMode.CBC,
                'padding_method': enums.PaddingMethod.PKCS5,
                'cryptographic_algorithm':
                    enums.CryptographicAlgorithm.BLOWFISH
            }
        )

        self.assertEqual(enums.ValidityIndicator.VALID, validity)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_sign(self):
        """
        Test that the client can sign data.
        """
        mock_signature = b'aaaaaaaaaaaaaaaaaaaaaaaaaa'
        result = {
            'result_status': enums.ResultStatus.SUCCESS,
            'unique_identifier': '1',
            'signature': mock_signature
        }

        client = ProxyKmipClient()
        client.open()
        client.proxy.sign.return_value = result

        actual_signature = client.sign(
            b'\x01\x02\x03\x04\x05\x06\x07\x08',
            uid='1',
            cryptographic_parameters={
                 'padding_method': enums.PaddingMethod.PSS,
                 'cryptographic_algorithm':
                 enums.CryptographicAlgorithm.RSA
            }
        )

        self.assertEqual(mock_signature, actual_signature)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_sign_on_invalid_inputs(self):
        """
        Test that TypeError exceptions are raised when trying to sign
        data with invalid parameters.
        """
        client = ProxyKmipClient()
        client.open()
        client.proxy.sign.return_value = {}
        args = [1234]
        kwargs = {
            'uid': '1',
            'cryptographic_parameters': {}
        }
        self.assertRaisesRegex(
            TypeError,
            "Data to be signed must be bytes.",
            client.sign,
            *args,
            **kwargs
        )

        args = [
            b'\x01\x02\x03\x04'
        ]
        kwargs = {
            'uid': 0,
            'cryptographic_parameters': {}
        }
        self.assertRaisesRegex(
            TypeError,
            "Unique identifier must be a string.",
            client.sign,
            *args,
            **kwargs
        )

        kwargs = {
            'uid': '1',
            'cryptographic_parameters': 'invalid'
        }
        self.assertRaisesRegex(
            TypeError,
            "Cryptographic parameters must be a dictionary.",
            client.sign,
            *args,
            **kwargs
        )

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_signature_verify_on_invalid_inputs(self):
        """
        Test that TypeError exception are raised when trying to verify
        signatures with invalid parameters.
        """
        client = ProxyKmipClient()
        client.open()
        client.proxy.signature_verify.return_value = {}
        args = [
            [],
            b''
        ]
        kwargs = {
            'uid': '1',
            'cryptographic_parameters': {}
        }

        self.assertRaisesRegex(
            TypeError,
            "Message must be bytes.",
            client.signature_verify,
            *args,
            **kwargs
        )

        args = [
            b'\x01\x02\x03\x04',
            []
        ]
        kwargs = {
            'uid': '1',
            'cryptographic_parameters': {}
        }

        self.assertRaisesRegex(
            TypeError,
            "Signature must be bytes.",
            client.signature_verify,
            *args,
            **kwargs
        )

        args = [
            b'\x01\x02\x03\x04',
            b'\xFF\xFF\xFF\xFF'
        ]
        kwargs = {
            'uid': 0,
            'cryptographic_parameters': {}
        }
        self.assertRaisesRegex(
            TypeError,
            "Unique identifier must be a string.",
            client.signature_verify,
            *args,
            **kwargs
        )

        args = [
            b'\x01\x02\x03\x04',
            b'\xFF\xFF\xFF\xFF'
        ]
        kwargs = {
            'uid': '1',
            'cryptographic_parameters': 'invalid'
        }
        self.assertRaisesRegex(
            TypeError,
            "Cryptographic parameters must be a dictionary.",
            client.signature_verify,
            *args,
            **kwargs
        )

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_signature_verify_on_closed(self):
        """
        Test that a ClientConnectionNotOpen exception is raised when trying
        to verify a signature on an unopened client connection.
        """
        client = ProxyKmipClient()
        args = [
            b'\x01\x02\x03\x04',
            b'\xFF\xFF\xFF\xFF'
        ]
        kwargs = {
            'uid': '1',
            'cryptographic_parameters': {}
        }

        self.assertRaises(
            ClientConnectionNotOpen,
            client.signature_verify,
            *args,
            **kwargs
        )

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_signature_verify_on_operation_failure(self):
        """
        Test that a KmipOperationFailure exception is raised when the
        backend fails to verify a signature.
        """
        status = enums.ResultStatus.OPERATION_FAILED
        reason = enums.ResultReason.GENERAL_FAILURE
        message = "Test failure message"

        result = {
            'result_status': status,
            'result_reason': reason,
            'result_message': message
        }
        error_message = str(KmipOperationFailure(status, reason, message))

        client = ProxyKmipClient()
        client.open()
        client.proxy.signature_verify.return_value = result
        args = [
            b'\x01\x02\x03\x04',
            b'\xFF\xFF\xFF\xFF'
        ]
        kwargs = {
            'uid': '1',
            'cryptographic_parameters': {}
        }

        self.assertRaisesRegex(
            KmipOperationFailure,
            error_message,
            client.signature_verify,
            *args,
            **kwargs
        )

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_mac(self):
        """
        Test the MAC client with proper input.
        """
        uuid = 'aaaaaaaa-1111-2222-3333-ffffffffffff'
        algorithm = enums.CryptographicAlgorithm.HMAC_SHA256
        data = (b'\x00\x01\x02\x03\x04')

        result = results.MACResult(
            contents.ResultStatus(enums.ResultStatus.SUCCESS),
            uuid=attr.UniqueIdentifier(uuid),
            mac_data=obj.MACData(data))

        with ProxyKmipClient() as client:
            client.proxy.mac.return_value = result

            uid, mac_data = client.mac(data, uuid, algorithm)
            self.assertEqual(uid, uuid)
            self.assertEqual(mac_data, data)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_mac_on_invalid_inputs(self):
        """
        Test that a TypeError exception is raised when wrong type
        of arguments are given to mac operation.
        """
        uuid = 'aaaaaaaa-1111-2222-3333-ffffffffffff'
        uuid_invalid = int(123)

        algorithm = enums.CryptographicAlgorithm.HMAC_SHA256
        algorithm_invalid = enums.CryptographicUsageMask.MAC_GENERATE

        data = (b'\x00\x01\x02\x03\x04')
        data_invalid = int(123)

        result = results.MACResult(
            contents.ResultStatus(enums.ResultStatus.SUCCESS),
            uuid=attr.UniqueIdentifier(uuid),
            mac_data=obj.MACData(data))

        args = [data, uuid_invalid, algorithm]
        with ProxyKmipClient() as client:
            client.proxy.mac.return_value = result
            self.assertRaises(TypeError, client.mac, *args)

        args = [data, uuid, algorithm_invalid]
        with ProxyKmipClient() as client:
            client.proxy.mac.return_value = result
            self.assertRaises(TypeError, client.mac, *args)

        args = [data_invalid, uuid, algorithm]
        with ProxyKmipClient() as client:
            client.proxy.mac.return_value = result
            self.assertRaises(TypeError, client.mac, *args)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_mac_on_operation_failure(self):
        """
        Test that a KmipOperationFailure exception is raised when the
        backend fails to generate MAC.
        """
        uuid = 'aaaaaaaa-1111-2222-3333-ffffffffffff'
        algorithm = enums.CryptographicAlgorithm.HMAC_SHA256
        data = (b'\x00\x01\x02\x03\x04')

        status = enums.ResultStatus.OPERATION_FAILED
        reason = enums.ResultReason.GENERAL_FAILURE
        message = "Test failure message"

        result = results.OperationResult(
            contents.ResultStatus(status),
            contents.ResultReason(reason),
            contents.ResultMessage(message))
        error_msg = str(KmipOperationFailure(status, reason, message))

        client = ProxyKmipClient()
        client.open()
        client.proxy.mac.return_value = result
        args = [data, uuid, algorithm]

        self.assertRaisesRegex(
            KmipOperationFailure, error_msg, client.mac, *args)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_mac_on_closed(self):
        """
        Test that a ClientConnectionNotOpen exception is raised when trying
        to do mac on an unopened client connection.
        """
        client = ProxyKmipClient()
        uuid = 'aaaaaaaa-1111-2222-3333-ffffffffffff'
        algorithm = enums.CryptographicAlgorithm.HMAC_SHA256
        data = (b'\x00\x01\x02\x03\x04')
        args = [data, uuid, algorithm]
        self.assertRaises(
            ClientConnectionNotOpen, client.mac, *args)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_locate(self):
        """
        Test the locate client with proper input.
        """
        maximum_items = 10
        storage_status_mask = 1
        object_group_member = enums.ObjectGroupMember.GROUP_MEMBER_FRESH
        attributes = [
            obj.Attribute(
                attribute_name=obj.Attribute.AttributeName('Name'),
                attribute_index=obj.Attribute.AttributeIndex(0),
                attribute_value=attr.Name(
                    name_value=attr.Name.NameValue('Test Name'),
                    name_type=attr.Name.NameType(
                        enums.NameType.UNINTERPRETED_TEXT_STRING
                    )
                )
            ),
            obj.Attribute(
                attribute_name=obj.Attribute.AttributeName('Object Type'),
                attribute_value=attr.ObjectType(
                    enums.ObjectType.SYMMETRIC_KEY
                )
            )
        ]

        uuid0 = 'aaaaaaaa-1111-2222-3333-ffffffffffff'
        uuid1 = 'bbbbbbbb-4444-5555-6666-gggggggggggg'
        unique_identifiers = [uuid0, uuid1]

        result = results.LocateResult(
            contents.ResultStatus(enums.ResultStatus.SUCCESS),
            uuids=unique_identifiers)

        with ProxyKmipClient() as client:
            client.proxy.locate.return_value = result

            uuids = client.locate(
                maximum_items, storage_status_mask,
                object_group_member, attributes)
            self.assertIn(uuid0, uuids)
            self.assertIn(uuid1, uuids)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_locate_on_invalid_inputs(self):
        """
        Test that a TypeError exception is raised when wrong type
        of arguments are given to locate operation.
        """
        maximum_items = 10
        maximum_items_invalid = "10"

        storage_status_mask = 1
        storage_status_mask_invalid = '1'

        object_group_member = enums.ObjectGroupMember.GROUP_MEMBER_FRESH
        object_group_member_invalid = \
            enums.CryptographicUsageMask.MAC_GENERATE

        attributes = [
            obj.Attribute(
                attribute_name=obj.Attribute.AttributeName('Name'),
                attribute_index=obj.Attribute.AttributeIndex(0),
                attribute_value=attr.Name(
                    name_value=attr.Name.NameValue('Test Name'),
                    name_type=attr.Name.NameType(
                        enums.NameType.UNINTERPRETED_TEXT_STRING
                    )
                )
            ),
            obj.Attribute(
                attribute_name=obj.Attribute.AttributeName('Object Type'),
                attribute_value=attr.ObjectType(
                    enums.ObjectType.SYMMETRIC_KEY
                )
            )
        ]
        attributes_invalid0 = 123
        attributes_invalid1 = [
            obj.Attribute(
                attribute_name=obj.Attribute.AttributeName('Name'),
                attribute_index=obj.Attribute.AttributeIndex(0),
                attribute_value=attr.Name(
                    name_value=attr.Name.NameValue('Test Name'),
                    name_type=attr.Name.NameType(
                        enums.NameType.UNINTERPRETED_TEXT_STRING
                    )
                )
            ),
            123
        ]

        uuid0 = 'aaaaaaaa-1111-2222-3333-ffffffffffff'
        uuid1 = 'bbbbbbbb-4444-5555-6666-gggggggggggg'
        unique_identifiers = [attr.UniqueIdentifier(uuid0),
                              attr.UniqueIdentifier(uuid1)]

        result = results.LocateResult(
            contents.ResultStatus(enums.ResultStatus.SUCCESS),
            uuids=unique_identifiers)

        args = [maximum_items_invalid, storage_status_mask,
                object_group_member, attributes]
        with ProxyKmipClient() as client:
            client.proxy.locate.return_value = result
            self.assertRaises(TypeError, client.locate, *args)

        args = [maximum_items, storage_status_mask_invalid,
                object_group_member, attributes]
        with ProxyKmipClient() as client:
            client.proxy.locate.return_value = result
            self.assertRaises(TypeError, client.locate, *args)

        args = [maximum_items, storage_status_mask,
                object_group_member_invalid, attributes]
        with ProxyKmipClient() as client:
            client.proxy.locate.return_value = result
            self.assertRaises(TypeError, client.locate, *args)

        args = [maximum_items, storage_status_mask,
                object_group_member, attributes_invalid0]
        with ProxyKmipClient() as client:
            client.proxy.locate.return_value = result
            self.assertRaises(TypeError, client.locate, *args)

        args = [maximum_items, storage_status_mask,
                object_group_member, attributes_invalid1]
        with ProxyKmipClient() as client:
            client.proxy.locate.return_value = result
            self.assertRaises(TypeError, client.locate, *args)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_locate_on_operation_failure(self):
        """
        Test that a KmipOperationFailure exception is raised when the
        backend fails to locate.
        """
        maximum_items = 10
        storage_status_mask = 1
        object_group_member = enums.ObjectGroupMember.GROUP_MEMBER_FRESH
        attributes = [
            obj.Attribute(
                attribute_name=obj.Attribute.AttributeName('Name'),
                attribute_index=obj.Attribute.AttributeIndex(0),
                attribute_value=attr.Name(
                    name_value=attr.Name.NameValue('Test Name'),
                    name_type=attr.Name.NameType(
                        enums.NameType.UNINTERPRETED_TEXT_STRING
                    )
                )
            ),
            obj.Attribute(
                attribute_name=obj.Attribute.AttributeName('Object Type'),
                attribute_value=attr.ObjectType(
                    enums.ObjectType.SYMMETRIC_KEY
                )
            )
        ]

        status = enums.ResultStatus.OPERATION_FAILED
        reason = enums.ResultReason.GENERAL_FAILURE
        message = "Test failure message"

        result = results.OperationResult(
            contents.ResultStatus(status),
            contents.ResultReason(reason),
            contents.ResultMessage(message))
        error_msg = str(KmipOperationFailure(status, reason, message))

        client = ProxyKmipClient()
        client.open()
        client.proxy.locate.return_value = result
        args = [maximum_items, storage_status_mask,
                object_group_member, attributes]

        self.assertRaisesRegex(
            KmipOperationFailure, error_msg, client.locate, *args)

    @mock.patch('kmip.pie.client.KMIPProxy',
                mock.MagicMock(spec_set=KMIPProxy))
    def test_locate_on_closed(self):
        """
        Test that a ClientConnectionNotOpen exception is raised when trying
        to do locate on an unopened client connection.
        """
        client = ProxyKmipClient()
        maximum_items = 10
        storage_status_mask = 1
        object_group_member = enums.ObjectGroupMember.GROUP_MEMBER_FRESH
        attributes = [
            obj.Attribute(
                attribute_name=obj.Attribute.AttributeName('Name'),
                attribute_index=obj.Attribute.AttributeIndex(0),
                attribute_value=attr.Name(
                    name_value=attr.Name.NameValue('Test Name'),
                    name_type=attr.Name.NameType(
                        enums.NameType.UNINTERPRETED_TEXT_STRING
                    )
                )
            ),
            obj.Attribute(
                attribute_name=obj.Attribute.AttributeName('Object Type'),
                attribute_value=attr.ObjectType(
                    enums.ObjectType.SYMMETRIC_KEY
                )
            )
        ]
        args = [maximum_items, storage_status_mask,
                object_group_member, attributes]
        self.assertRaises(
           ClientConnectionNotOpen, client.locate, *args)

    def test_build_cryptographic_parameters_with_none(self):
        """
        Test that an empty set of cryptographic parameters is processed
        correctly.
        """
        client = ProxyKmipClient()
        result = client._build_cryptographic_parameters(None)
        self.assertEqual(None, result)

    def test_build_cryptographic_parameters_invalid(self):
        """
        Test that the right error is raised when attempting to build
        cryptographic parameters with an invalid value.
        """
        client = ProxyKmipClient()
        args = ['invalid']

        self.assertRaisesRegex(
            TypeError,
            "Cryptographic parameters must be a dictionary.",
            client._build_cryptographic_parameters,
            *args
        )

    def test_build_encryption_key_information(self):
        """
        Test that an EncryptionKeyInformation struct can be built from a
        dictionary.
        """
        client = ProxyKmipClient()

        # Test with no value
        result = client._build_encryption_key_information(None)

        self.assertEqual(None, result)

        # Test with a value
        result = client._build_encryption_key_information(
            {
                'unique_identifier': 'test',
                'cryptographic_parameters': {
                    'block_cipher_mode': enums.BlockCipherMode.CBC
                }
            }
        )

        self.assertIsInstance(result, obj.EncryptionKeyInformation)
        self.assertEqual('test', result.unique_identifier)
        self.assertIsInstance(
            result.cryptographic_parameters,
            obj.CryptographicParameters
        )
        self.assertEqual(
            enums.BlockCipherMode.CBC,
            result.cryptographic_parameters.block_cipher_mode
        )

    def test_build_encryption_key_information_invalid(self):
        """
        Test that the right error is raised when attempting to build
        an EncryptionKeyInformation struct with an invalid value.
        """
        client = ProxyKmipClient()
        args = ['invalid']

        self.assertRaisesRegex(
            TypeError,
            "Encryption key information must be a dictionary.",
            client._build_encryption_key_information,
            *args
        )

    def test_build_mac_signature_key_information(self):
        """
        Test that a MACSignatureKeyInformation struct can be built from a
        dictionary.
        """
        client = ProxyKmipClient()

        # Test with no value
        result = client._build_mac_signature_key_information(None)

        self.assertEqual(None, result)

        # Test with a value
        result = client._build_mac_signature_key_information(
            {
                'unique_identifier': '1',
                'cryptographic_parameters': {
                    'cryptographic_algorithm': enums.CryptographicAlgorithm.AES
                }
            }
        )

        self.assertIsInstance(result, obj.MACSignatureKeyInformation)
        self.assertEqual('1', result.unique_identifier)
        self.assertIsInstance(
            result.cryptographic_parameters,
            obj.CryptographicParameters
        )
        self.assertEqual(
            enums.CryptographicAlgorithm.AES,
            result.cryptographic_parameters.cryptographic_algorithm
        )

    def test_build_mac_signature_key_information_invalid(self):
        """
        Test that the right error is raised when attempting to build
        a MACSignatureKeyInformation struct with an invalid value.
        """
        client = ProxyKmipClient()
        args = ['invalid']

        self.assertRaisesRegex(
            TypeError,
            "MAC/signature key information must be a dictionary.",
            client._build_mac_signature_key_information,
            *args
        )

    def test_build_key_wrapping_specification(self):
        """
        Test that a KeyWrappingSpecification can be built from a dictionary.
        """
        client = ProxyKmipClient()

        # Test with no value
        result = client._build_key_wrapping_specification(None)

        self.assertEqual(None, result)

        # Test with a value
        result = client._build_key_wrapping_specification(
            {
                'wrapping_method': enums.WrappingMethod.ENCRYPT,
                'encryption_key_information': {
                    'unique_identifier': '1',
                    'cryptographic_parameters': {
                        'cryptographic_algorithm':
                            enums.CryptographicAlgorithm.AES
                    }
                },
                'mac_signature_key_information': {
                    'unique_identifier': '2',
                    'cryptographic_parameters': {
                        'padding_method': enums.PaddingMethod.PKCS5
                    }
                },
                'attribute_names': [
                    'Cryptographic Algorithm',
                    'Cryptographic Length'
                ],
                'encoding_option': enums.EncodingOption.NO_ENCODING
            }
        )

        self.assertIsInstance(result, obj.KeyWrappingSpecification)
        self.assertIsInstance(
            result.encryption_key_information,
            obj.EncryptionKeyInformation
        )
        info = result.encryption_key_information
        self.assertEqual('1', info.unique_identifier)
        self.assertIsInstance(
            info.cryptographic_parameters,
            obj.CryptographicParameters
        )
        self.assertEqual(
            enums.CryptographicAlgorithm.AES,
            info.cryptographic_parameters.cryptographic_algorithm
        )
        self.assertIsInstance(
            result.mac_signature_key_information,
            obj.MACSignatureKeyInformation
        )
        info = result.mac_signature_key_information
        self.assertEqual('2', info.unique_identifier)
        self.assertIsInstance(
            info.cryptographic_parameters,
            obj.CryptographicParameters
        )
        self.assertEqual(
            enums.PaddingMethod.PKCS5,
            info.cryptographic_parameters.padding_method
        )
        self.assertIsInstance(result.attribute_names, list)
        self.assertEqual(2, len(result.attribute_names))
        self.assertIn('Cryptographic Algorithm', result.attribute_names)
        self.assertIn('Cryptographic Length', result.attribute_names)
        self.assertEqual(
            enums.EncodingOption.NO_ENCODING,
            result.encoding_option
        )

    def test_build_key_wrapping_specification_invalid(self):
        """
        Test that the right error is raised when attempting to build
        a KeyWrappingSpecification struct with an invalid value.
        """
        client = ProxyKmipClient()
        args = ['invalid']

        self.assertRaisesRegex(
            TypeError,
            "Key wrapping specification must be a dictionary.",
            client._build_key_wrapping_specification,
            *args
        )
