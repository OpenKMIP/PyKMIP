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

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

import datetime
import mock
import socket
import testtools
import time

from kmip.core import enums
from kmip.core import exceptions
from kmip.core import objects
from kmip.core import utils

from kmip.core.messages import contents
from kmip.core.messages import messages

from kmip.services.server import engine
from kmip.services.server import session

def build_certificate(
        common_names,
        include_extension=True,
        bad_extension=False
):
    """
    Programmatically generate a self-signed certificate for testing purposes.

    Args:
        common_names (list): A list of strings for the common names of the
            cert.
        include_extension (boolean): A flag enabling/disabling the inclusion
            of certificate extensions.
        bad_extension (boolean): A flag enabling/disabling the setting of
            invalid certificate extension values.

    Returns:
        x509.Certificate: The newly generated certificate object.
    """
    names = []
    for common_name in common_names:
        names.append(
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, common_name)
        )
    name = x509.Name(names)

    t = datetime.datetime.now()
    delta = datetime.timedelta(days=30)
    not_valid_before = t - delta
    not_valid_after = t + delta

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    builder = x509.CertificateBuilder().serial_number(
        1
    ).issuer_name(
        name
    ).subject_name(
        name
    ).not_valid_before(
        not_valid_before
    ).not_valid_after(
        not_valid_after
    ).public_key(
        private_key.public_key()
    )\

    extended_key_usage_values = []
    if bad_extension:
        extended_key_usage_values.append(
            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH
        )
    else:
        extended_key_usage_values.append(
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH
        )

    if include_extension:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(extended_key_usage_values),
            True
        )

    return builder.sign(private_key, hashes.SHA256(), default_backend())

class TestKmipSession(testtools.TestCase):
    """
    A test suite for the KmipSession.
    """

    def setUp(self):
        super(TestKmipSession, self).setUp()

    def tearDown(self):
        super(TestKmipSession, self).tearDown()

    def test_init(self):
        """
        Test that a KmipSession can be created without errors.
        """
        session.KmipSession(None, None, None, 'name')

    def test_init_without_name(self):
        """
        Test that a KmipSession without 'name' can be created without errors.
        """
        session.KmipSession(None, None, None, None)

    def test_run(self):
        """
        Test that the message handling loop is handled properly on normal
        execution.
        """
        kmip_session = session.KmipSession(None, None, None, 'name')
        kmip_session._logger = mock.MagicMock()
        kmip_session._handle_message_loop = mock.MagicMock(
            side_effect=[
                None,
                exceptions.ConnectionClosed()
            ]
        )
        kmip_session._connection = mock.MagicMock()

        kmip_session.run()

        kmip_session._logger.info.assert_any_call("Starting session: name")
        self.assertTrue(kmip_session._handle_message_loop.called)
        kmip_session._connection.shutdown.assert_called_once_with(
            socket.SHUT_RDWR
        )
        kmip_session._connection.close.assert_called_once_with()
        kmip_session._logger.info.assert_called_with("Stopping session: name")

    def test_run_with_failure(self):
        """
        Test that the correct logging and error handling occurs when the
        thread encounters an error with the message handling loop.
        """
        kmip_session = session.KmipSession(None, None, None, 'name')
        kmip_session._logger = mock.MagicMock()
        kmip_session._connection = mock.MagicMock()

        test_exception = Exception("test")
        kmip_session._handle_message_loop = mock.MagicMock(
            side_effect=[
                test_exception,
                exceptions.ConnectionClosed()
            ]
        )

        kmip_session.run()

        kmip_session._logger.info.assert_any_call("Starting session: name")
        self.assertTrue(kmip_session._handle_message_loop.called)
        kmip_session._logger.info.assert_any_call(
            "Failure handling message loop"
        )
        kmip_session._logger.exception.assert_called_once_with(test_exception)
        kmip_session._connection.shutdown.assert_called_once_with(
            socket.SHUT_RDWR
        )
        kmip_session._connection.close.assert_called_once_with()
        kmip_session._logger.info.assert_called_with("Stopping session: name")

    @mock.patch('kmip.services.server.auth.get_certificate_from_connection')
    @mock.patch('kmip.core.messages.messages.RequestMessage')
    def test_handle_message_loop(self, request_mock, cert_mock):
        """
        Test that the correct logging and error handling occurs during the
        message handling loop.
        """
        data = utils.BytearrayStream()

        # Build a response and use it as a dummy processing result.
        batch_item = messages.ResponseBatchItem(
            result_status=contents.ResultStatus(
                enums.ResultStatus.SUCCESS
            ),
            result_reason=contents.ResultReason(
                enums.ResultReason.OBJECT_ARCHIVED
            ),
            result_message=contents.ResultMessage("Test message.")
        )
        batch_items = [batch_item]
        header = messages.ResponseHeader(
            protocol_version=contents.ProtocolVersion(1, 0),
            time_stamp=contents.TimeStamp(int(time.time())),
            batch_count=contents.BatchCount(len(batch_items))
        )
        message = messages.ResponseMessage(
            response_header=header,
            batch_items=batch_items
        )

        cert_mock.return_value = 'test_certificate'
        kmip_engine = engine.KmipEngine()
        kmip_engine._logger = mock.MagicMock()
        kmip_session = session.KmipSession(
            kmip_engine,
            None,
            None,
            name='name',
            enable_tls_client_auth=False
        )
        kmip_session._engine = mock.MagicMock()
        kmip_session.authenticate = mock.MagicMock()
        kmip_session.authenticate.return_value = (
            'test',
            ['group A', 'group B']
        )
        kmip_session._engine.process_request = mock.MagicMock(
            return_value=(
                message,
                kmip_session._max_response_size,
                contents.ProtocolVersion(1, 2)
            )
        )
        kmip_session._logger = mock.MagicMock()
        kmip_session._connection = mock.MagicMock()
        kmip_session._connection.shared_ciphers = mock.MagicMock(
            return_value=[
                ('AES128-SHA256', 'TLSv1/SSLv3', 128),
                ('AES256-SHA256', 'TLSv1/SSLv3', 256)
            ]
        )
        kmip_session._connection.cipher = mock.MagicMock(
            return_value=('AES128-SHA256', 'TLSv1/SSLv3', 128)
        )
        kmip_session._receive_request = mock.MagicMock(return_value=data)
        kmip_session._send_response = mock.MagicMock()
        kmip_session.authenticate = mock.MagicMock(
            return_value=("John Doe", ["Group A"])
        )

        kmip_session._handle_message_loop()

        kmip_session._receive_request.assert_called_once_with()
        kmip_session._logger.info.assert_any_call(
            "Session client identity: John Doe"
        )
        kmip_session._logger.debug.assert_any_call(
            "Possible session ciphers: 2"
        )
        kmip_session._logger.debug.assert_any_call(
            ('AES128-SHA256', 'TLSv1/SSLv3', 128)
        )
        kmip_session._logger.debug.assert_any_call(
            ('AES256-SHA256', 'TLSv1/SSLv3', 256)
        )
        kmip_session._logger.debug.assert_any_call(
            "Session cipher selected: {0}".format(
                ('AES128-SHA256', 'TLSv1/SSLv3', 128)
            )
        )
        kmip_session._logger.warning.assert_not_called()
        kmip_session._logger.exception.assert_not_called()
        self.assertTrue(kmip_session._send_response.called)

    @mock.patch('kmip.services.server.auth.get_certificate_from_connection')
    @mock.patch('kmip.core.messages.messages.RequestMessage.read',
                mock.MagicMock(side_effect=Exception()))
    def test_handle_message_loop_with_parse_failure(self, cert_mock):
        """
        Test that the correct logging and error handling occurs during the
        message handling loop.
        """
        data = utils.BytearrayStream(())

        cert_mock.return_value = 'test_certificate'
        kmip_engine = engine.KmipEngine()
        kmip_session = session.KmipSession(
            kmip_engine,
            None,
            None,
            name='name',
            enable_tls_client_auth=False
        )
        kmip_session.authenticate = mock.MagicMock()
        kmip_session.authenticate.return_value = (
            'test',
            ['group A', 'group B']
        )
        kmip_session._logger = mock.MagicMock()
        kmip_session._connection = mock.MagicMock()
        kmip_session._receive_request = mock.MagicMock(return_value=data)
        kmip_session._send_response = mock.MagicMock()

        kmip_session._handle_message_loop()

        kmip_session._receive_request.assert_called_once_with()
        kmip_session._logger.warning.assert_called_once_with(
            "Failure parsing request message."
        )
        self.assertTrue(kmip_session._logger.exception.called)
        kmip_session._logger.error.assert_not_called()
        self.assertTrue(kmip_session._send_response.called)

    @mock.patch('kmip.services.server.auth.get_certificate_from_connection')
    @mock.patch('kmip.core.messages.messages.RequestMessage')
    def test_handle_message_loop_with_response_too_long(self,
                                                        request_mock,
                                                        cert_mock):
        """
        Test that the correct logging and error handling occurs during the
        message handling loop.
        """
        data = utils.BytearrayStream(())

        cert_mock.return_value = 'test_certificate'
        kmip_engine = engine.KmipEngine()
        kmip_session = session.KmipSession(
            kmip_engine,
            None,
            None,
            name='name',
            enable_tls_client_auth=False
        )
        kmip_session.authenticate = mock.MagicMock()
        kmip_session.authenticate.return_value = (
            'test',
            ['group A', 'group B']
        )
        kmip_session._logger = mock.MagicMock()
        kmip_session._connection = mock.MagicMock()
        kmip_session._receive_request = mock.MagicMock(return_value=data)
        kmip_session._send_response = mock.MagicMock()
        kmip_session._max_response_size = 0

        kmip_session._handle_message_loop()

        kmip_session._receive_request.assert_called_once_with()
        self.assertTrue(kmip_session._logger.warning.called)
        kmip_session._logger.exception.assert_not_called()
        self.assertTrue(kmip_session._send_response.called)

    @mock.patch('kmip.services.server.auth.get_certificate_from_connection')
    @mock.patch('kmip.core.messages.messages.RequestMessage')
    def test_handle_message_loop_with_response_size_equal_limit(
            self,
            request_mock,
            cert_mock):
        """
        Test that a response exactly at the max size is allowed.
        """
        data = utils.BytearrayStream(())

        cert_mock.return_value = 'test_certificate'
        kmip_engine = engine.KmipEngine(database_path=':memory:')
        kmip_session = session.KmipSession(
            kmip_engine,
            None,
            None,
            name='name',
            enable_tls_client_auth=False
        )
        kmip_session.authenticate = mock.MagicMock(
            return_value=("John Doe", ["Group A"])
        )
        kmip_session._logger = mock.MagicMock()
        kmip_session._connection = mock.MagicMock()
        kmip_session._connection.shared_ciphers = mock.MagicMock(
            return_value=None
        )
        kmip_session._connection.cipher = mock.MagicMock(
            return_value=('AES128-SHA256', 'TLSv1/SSLv3', 128)
        )
        kmip_session._receive_request = mock.MagicMock(return_value=data)
        kmip_session._send_response = mock.MagicMock()

        batch_item = messages.ResponseBatchItem(
            result_status=contents.ResultStatus(
                enums.ResultStatus.SUCCESS
            )
        )
        batch_items = [batch_item]
        header = messages.ResponseHeader(
            protocol_version=contents.ProtocolVersion(1, 2),
            time_stamp=contents.TimeStamp(int(time.time())),
            batch_count=contents.BatchCount(len(batch_items))
        )
        response = messages.ResponseMessage(
            response_header=header,
            batch_items=batch_items
        )

        response_data = utils.BytearrayStream()
        kmip_version = contents.protocol_version_to_kmip_version(
            header.protocol_version
        )
        response.write(response_data, kmip_version=kmip_version)
        max_size = len(response_data)

        kmip_engine.process_request = mock.MagicMock(
            return_value=(response, max_size, header.protocol_version)
        )

        kmip_session._handle_message_loop()

        kmip_session._logger.warning.assert_not_called()
        self.assertTrue(kmip_session._send_response.called)

    @mock.patch('kmip.services.server.auth.get_certificate_from_connection')
    @mock.patch('kmip.core.messages.messages.RequestMessage')
    def test_handle_message_loop_with_unexpected_error(self,
                                                       request_mock,
                                                       cert_mock):
        """
        Test that the correct logging and error handling occurs when an
        unexpected error is generated while processing a request.
        """
        data = utils.BytearrayStream(())

        cert_mock.return_value = 'test_certificate'
        kmip_engine = engine.KmipEngine()
        kmip_engine._logger = mock.MagicMock()
        kmip_session = session.KmipSession(
            kmip_engine,
            None,
            None,
            name='name',
            enable_tls_client_auth=False
        )
        kmip_session.authenticate = mock.MagicMock()
        kmip_session.authenticate.return_value = (
            'test',
            ['group A', 'group B']
        )
        kmip_session._engine = mock.MagicMock()
        test_exception = Exception("Unexpected error.")
        kmip_session._engine.process_request = mock.MagicMock(
            side_effect=test_exception
        )
        kmip_session._logger = mock.MagicMock()
        kmip_session._connection = mock.MagicMock()
        kmip_session._receive_request = mock.MagicMock(return_value=data)
        kmip_session._send_response = mock.MagicMock()

        kmip_session._handle_message_loop()

        kmip_session._receive_request.assert_called_once_with()
        kmip_session._logger.warning.assert_called_once_with(
            "An unexpected error occurred while processing request."
        )
        kmip_session._logger.exception.assert_called_once_with(test_exception)
        self.assertTrue(kmip_session._send_response.called)

    @mock.patch('kmip.services.server.auth.get_certificate_from_connection')
    @mock.patch('kmip.core.messages.messages.RequestMessage')
    def test_handle_message_loop_with_authentication_failure(self,
                                                             request_mock,
                                                             cert_mock):
        """
        Test that the correct logging and error handling occurs when an
        authentication error is generated while processing a request.
        """
        data = utils.BytearrayStream(())

        cert_mock.return_value = 'test_certificate'
        kmip_engine = engine.KmipEngine()
        kmip_engine._logger = mock.MagicMock()
        kmip_session = session.KmipSession(
            kmip_engine,
            None,
            None,
            name='name',
            enable_tls_client_auth=False
        )
        kmip_session.authenticate = mock.MagicMock()
        kmip_session.authenticate.side_effect = exceptions.PermissionDenied(
            "Authentication failed."
        )
        kmip_session._engine = mock.MagicMock()
        kmip_session._engine.default_protocol_version = \
            kmip_engine.default_protocol_version
        kmip_session._logger = mock.MagicMock()
        kmip_session._connection = mock.MagicMock()
        kmip_session._receive_request = mock.MagicMock(return_value=data)
        kmip_session._send_response = mock.MagicMock()
        fake_version = contents.ProtocolVersion(1, 2)
        fake_credential = objects.Credential(
            credential_type=enums.CredentialType.USERNAME_AND_PASSWORD,
            credential_value=objects.UsernamePasswordCredential(
                username="John Doe",
                password="secret"
            )
        )
        fake_header = messages.RequestHeader(
            protocol_version=fake_version,
            authentication=contents.Authentication(
                credentials=[fake_credential]
            )
        )
        fake_request = messages.RequestMessage()
        fake_request.request_header = fake_header
        fake_request.read = mock.MagicMock()
        request_mock.return_value = fake_request

        kmip_session._handle_message_loop()

        kmip_session._receive_request.assert_called_once_with()
        fake_request.read.assert_called_once_with(
            data,
            kmip_version=enums.KMIPVersion.KMIP_1_2
        )
        kmip_session.authenticate.assert_called_once_with(
            "test_certificate",
            fake_request
        )
        kmip_session._logger.warning.assert_called_once_with(
            "Authentication failed."
        )
        kmip_session._engine.build_error_response.assert_called_once_with(
            fake_version,
            enums.ResultReason.AUTHENTICATION_NOT_SUCCESSFUL,
            "An error occurred during client authentication. "
            "See server logs for more information."
        )
        kmip_session._logger.exception.assert_not_called()
        self.assertTrue(kmip_session._send_response.called)

    @mock.patch('kmip.services.server.auth.get_certificate_from_connection')
    @mock.patch('kmip.core.messages.messages.RequestMessage')
    def test_handle_message_loop_no_certificate(self,
                                                request_mock,
                                                cert_mock):
        """
        Test that the correct logging and error handling occurs when no
        certificate is encountered while processing a request.
        """
        data = utils.BytearrayStream(())

        cert_mock.return_value = None
        kmip_engine = engine.KmipEngine()
        kmip_engine._logger = mock.MagicMock()
        kmip_session = session.KmipSession(
            kmip_engine,
            None,
            None,
            name='name',
            enable_tls_client_auth=True
        )
        kmip_session.authenticate = mock.MagicMock()
        kmip_session._engine = mock.MagicMock()
        kmip_session._logger = mock.MagicMock()
        kmip_session._connection = mock.MagicMock()
        kmip_session._receive_request = mock.MagicMock(return_value=data)
        kmip_session._send_response = mock.MagicMock()

        kmip_session._handle_message_loop()

        kmip_session._receive_request.assert_called_once_with()
        kmip_session._logger.warning(
            "Failure verifying the client certificate."
        )
        kmip_session._logger.exception.assert_called_once_with(
            exceptions.PermissionDenied(
                "The client certificate could not be loaded from the session "
                "connection."
            )
        )
        kmip_session._engine.build_error_response.assert_called_once_with(
            contents.ProtocolVersion(1, 0),
            enums.ResultReason.AUTHENTICATION_NOT_SUCCESSFUL,
            "Error verifying the client certificate. "
            "See server logs for more information."
        )
        self.assertTrue(kmip_session._send_response.called)

    @mock.patch(
        'kmip.services.server.auth.get_extended_key_usage_from_certificate'
    )
    @mock.patch('kmip.services.server.auth.get_certificate_from_connection')
    @mock.patch('kmip.core.messages.messages.RequestMessage')
    def test_handle_message_loop_no_certificate_extension(self,
                                                          request_mock,
                                                          cert_mock,
                                                          ext_mock):
        """
        Test that the correct logging and error handling occurs when an
        invalid certificate is encountered while processing a request.
        """
        data = utils.BytearrayStream(())

        cert_mock.return_value = 'test_certificate'
        ext_mock.return_value = None
        kmip_engine = engine.KmipEngine()
        kmip_engine._logger = mock.MagicMock()
        kmip_session = session.KmipSession(
            kmip_engine,
            None,
            None,
            name='name',
            enable_tls_client_auth=True
        )
        kmip_session.authenticate = mock.MagicMock()
        kmip_session._engine = mock.MagicMock()
        kmip_session._logger = mock.MagicMock()
        kmip_session._connection = mock.MagicMock()
        kmip_session._receive_request = mock.MagicMock(return_value=data)
        kmip_session._send_response = mock.MagicMock()

        kmip_session._handle_message_loop()

        kmip_session._receive_request.assert_called_once_with()
        kmip_session._logger.warning(
            "Failure verifying the client certificate."
        )
        kmip_session._logger.exception.assert_called_once_with(
            exceptions.PermissionDenied(
                "The extended key usage extension is missing from the client "
                "certificate."
            )
        )
        kmip_session._engine.build_error_response.assert_called_once_with(
            contents.ProtocolVersion(1, 0),
            enums.ResultReason.AUTHENTICATION_NOT_SUCCESSFUL,
            "Error verifying the client certificate. "
            "See server logs for more information."
        )
        self.assertTrue(kmip_session._send_response.called)

    @mock.patch(
        'kmip.services.server.auth.get_extended_key_usage_from_certificate'
    )
    @mock.patch('kmip.services.server.auth.get_certificate_from_connection')
    @mock.patch('kmip.core.messages.messages.RequestMessage')
    def test_handle_message_loop_invalid_certificate_extension(self,
                                                               request_mock,
                                                               cert_mock,
                                                               ext_mock):
        """
        Test that the correct logging and error handling occurs when an
        invalid certificate is encountered while processing a request.
        """
        data = utils.BytearrayStream(())

        cert_mock.return_value = 'test_certificate'
        ext_mock.return_value = []
        kmip_engine = engine.KmipEngine()
        kmip_engine._logger = mock.MagicMock()
        kmip_session = session.KmipSession(
            kmip_engine,
            None,
            None,
            name='name',
            enable_tls_client_auth=True
        )
        kmip_session.authenticate = mock.MagicMock()
        kmip_session._engine = mock.MagicMock()
        kmip_session._logger = mock.MagicMock()
        kmip_session._connection = mock.MagicMock()
        kmip_session._receive_request = mock.MagicMock(return_value=data)
        kmip_session._send_response = mock.MagicMock()

        kmip_session._handle_message_loop()

        kmip_session._receive_request.assert_called_once_with()
        kmip_session._logger.warning(
            "Failure verifying the client certificate."
        )
        kmip_session._logger.exception.assert_called_once_with(
            exceptions.PermissionDenied(
                "The extended key usage extension is not marked for client "
                "authentication in the client certificate."
            )
        )
        kmip_session._engine.build_error_response.assert_called_once_with(
            contents.ProtocolVersion(1, 0),
            enums.ResultReason.AUTHENTICATION_NOT_SUCCESSFUL,
            "Error verifying the client certificate. "
            "See server logs for more information."
        )
        self.assertTrue(kmip_session._send_response.called)

    @mock.patch(
        "kmip.services.server.auth.get_client_identity_from_certificate"
    )
    def test_authenticate(self, mock_get):
        """
        Test that the session correctly uses the authentication plugin
        framework to authenticate new connections.
        """
        mock_get.return_value = "John Doe"
        kmip_session = session.KmipSession(
            None,
            None,
            None,
            name='TestSession'
        )
        kmip_session._logger = mock.MagicMock()
        fake_request = messages.RequestMessage(
            request_header=messages.RequestHeader()
        )

        session_identity = kmip_session.authenticate(
            "fake_certificate",
            fake_request
        )

        kmip_session._logger.debug.assert_any_call(
            "No authentication plugins are enabled. The client identity will "
            "be extracted from the client certificate."
        )
        mock_get.assert_any_call("fake_certificate")
        kmip_session._logger.debug.assert_any_call(
            "Extraction succeeded for client identity: John Doe"
        )
        self.assertEqual(("John Doe", None), session_identity)

    @mock.patch("kmip.services.server.auth.SLUGSConnector")
    def test_authenticate_against_slugs(self, mock_connector):
        """
        Test that the session correctly handles authentication with SLUGS.
        """
        mock_instance = mock.MagicMock()
        mock_instance.authenticate.return_value = ("John Doe", ["Group A"])
        mock_connector.return_value = mock_instance
        kmip_session = session.KmipSession(
            None,
            None,
            ("127.0.0.1", 48026),
            name='TestSession',
            auth_settings=[(
                "auth:slugs",
                {"enabled": "True", "url": "test_url"}
            )]
        )
        kmip_session._logger = mock.MagicMock()
        fake_credential = objects.Credential(
            credential_type=enums.CredentialType.USERNAME_AND_PASSWORD,
            credential_value=objects.UsernamePasswordCredential(
                username="John Doe",
                password="secret"
            )
        )
        fake_request = messages.RequestMessage(
            request_header=messages.RequestHeader(
                authentication=contents.Authentication(
                    credentials=[fake_credential]
                )
            )
        )

        result = kmip_session.authenticate(
            "fake_certificate",
            fake_request
        )

        mock_connector.assert_any_call("test_url")
        kmip_session._logger.debug.assert_any_call(
            "Authenticating with plugin: auth:slugs"
        )
        mock_instance.authenticate.assert_any_call(
            "fake_certificate",
            (("127.0.0.1", 48026), kmip_session._session_time),
            fake_request.request_header.authentication.credentials
        )
        kmip_session._logger.debug(
            "Authentication succeeded for client identity: John Doe"
        )
        self.assertEqual(2, len(result))
        self.assertEqual("John Doe", result[0])
        self.assertEqual(["Group A"], result[1])

    @mock.patch("kmip.services.server.auth.SLUGSConnector")
    def test_authenticate_against_slugs_with_failure(self, mock_connector):
        """
        Test that the session correctly handles a SLUGS authentication error.
        """
        mock_instance = mock.MagicMock()
        test_exception = exceptions.PermissionDenied(
            "Unrecognized user ID: John Doe"
        )
        mock_instance.authenticate.side_effect = test_exception
        mock_connector.return_value = mock_instance
        kmip_session = session.KmipSession(
            None,
            None,
            ("127.0.0.1", 48026),
            name='TestSession',
            auth_settings=[(
                "auth:slugs",
                {"enabled": "True", "url": "test_url"}
            )]
        )
        kmip_session._logger = mock.MagicMock()
        fake_credential = objects.Credential(
            credential_type=enums.CredentialType.USERNAME_AND_PASSWORD,
            credential_value=objects.UsernamePasswordCredential(
                username="John Doe",
                password="secret"
            )
        )
        fake_request = messages.RequestMessage(
            request_header=messages.RequestHeader(
                authentication=contents.Authentication(
                    credentials=[fake_credential]
                )
            )
        )

        args = ("fake_certificate", fake_request)
        self.assertRaisesRegex(
            exceptions.PermissionDenied,
            "Authentication failed.",
            kmip_session.authenticate,
            *args
        )

        mock_connector.assert_any_call("test_url")
        kmip_session._logger.debug.assert_any_call(
            "Authenticating with plugin: auth:slugs"
        )
        kmip_session._logger.warning.assert_any_call("Authentication failed.")
        kmip_session._logger.exception.assert_any_call(test_exception)

    def test_authenticate_against_unrecognized_plugin(self):
        """
        Test that the session correctly handles an unrecognized plugin
        configuration.
        """
        kmip_session = session.KmipSession(
            None,
            None,
            None,
            name='TestSession',
            auth_settings=[("auth:unrecognized", {})]
        )
        kmip_session._logger = mock.MagicMock()
        fake_request = messages.RequestMessage(
            request_header=messages.RequestHeader()
        )

        args = ("fake_certificate", fake_request)
        self.assertRaisesRegex(
            exceptions.PermissionDenied,
            "Authentication failed.",
            kmip_session.authenticate,
            *args
        )

        kmip_session._logger.warning.assert_any_call(
            "Authentication plugin 'auth:unrecognized' is not supported."
        )

    def test_receive_request(self):
        """
        Test that the session can correctly receive and parse a message
        encoding.
        """
        content = b'\x00\x00\x00\x00\x00\x00\x00\x00'
        expected = utils.BytearrayStream((content))

        kmip_session = session.KmipSession(None, None, None, 'name')
        kmip_session._receive_bytes = mock.MagicMock(
            side_effect=[content, b'']
        )

        observed = kmip_session._receive_request()

        kmip_session._receive_bytes.assert_any_call(8)
        kmip_session._receive_bytes.assert_any_call(0)

        self.assertEqual(expected.buffer, observed.buffer)

    def test_receive_bytes(self):
        """
        Test that the session can receive a message.
        """
        content = b'\x00\x00\x00\x00\x00\x00\x00\x00'

        kmip_session = session.KmipSession(None, None, None, 'name')
        kmip_session._connection = mock.MagicMock()
        kmip_session._connection.recv = mock.MagicMock(
            side_effect=[content, content]
        )

        observed = kmip_session._receive_bytes(16)

        kmip_session._connection.recv.assert_any_call(16)
        kmip_session._connection.recv.assert_called_with(8)
        self.assertEqual(content + content, observed)

        kmip_session._connection.recv = mock.MagicMock(
            side_effect=['']
        )

        args = (8, )
        self.assertRaises(
            exceptions.ConnectionClosed,
            kmip_session._receive_bytes,
            *args
        )

    def test_receive_bytes_with_bad_length(self):
        """
        Test that the session generates an error on an incorrectly sized
        message.
        """
        content = b'\x00\x00\x00\x00\x00\x00\x00\x00'

        kmip_session = session.KmipSession(None, None, None, 'name')
        kmip_session._connection = mock.MagicMock()
        kmip_session._connection.recv = mock.MagicMock(
            side_effect=[content, content, None]
        )

        args = [32]
        self.assertRaises(ValueError, kmip_session._receive_bytes, *args)

        kmip_session._connection.recv.assert_any_call(16)
        kmip_session._connection.recv.assert_called_with(16)

    def test_send_message(self):
        """
        Test that a data buffer, regardless of length, is sent correctly.
        """
        buffer_full = utils.BytearrayStream((
            b'\x00\x00\x00\x00\x00\x00\x00\x00'
        ))
        buffer_empty = utils.BytearrayStream()

        kmip_session = session.KmipSession(None, None, None, 'name')
        kmip_session._connection = mock.MagicMock()

        kmip_session._send_response(buffer_empty.buffer)
        kmip_session._connection.sendall.assert_not_called()

        kmip_session._send_response(buffer_full.buffer)
        kmip_session._connection.sendall.assert_called_once_with(
            bytes(buffer_full.buffer)
        )
