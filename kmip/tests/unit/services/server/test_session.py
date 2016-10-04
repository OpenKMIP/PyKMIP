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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


import datetime
import mock
import socket
import testtools
import time

from kmip.core import enums
from kmip.core import exceptions
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
        session.KmipSession(None, None, 'name')

    def test_init_without_name(self):
        """
        Test that a KmipSession without 'name' can be created without errors.
        """
        session.KmipSession(None, None, None)

    def test_run(self):
        """
        Test that the message handling loop is handled properly on normal
        execution.
        """
        kmip_session = session.KmipSession(None, None, 'name')
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
        kmip_session = session.KmipSession(None, None, 'name')
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

    def test_get_client_identity(self):
        """
        Test that a client identity is obtained from a valid client
        certificate.
        """
        client_certificate = build_certificate([u'Test Identity'])
        der_encoding = client_certificate.public_bytes(
            serialization.Encoding.DER
        )

        kmip_session = session.KmipSession(None, None, 'name')
        kmip_session._logger = mock.MagicMock()
        kmip_session._connection = mock.MagicMock()
        kmip_session._connection.getpeercert.return_value = der_encoding

        identity = kmip_session._get_client_identity()
        self.assertEqual(u'Test Identity', identity)

        kmip_session._logger.info.assert_called_once_with(
            "Session client identity: Test Identity"
        )
        kmip_session._logger.warning.assert_not_called()

    def test_get_client_identity_with_no_certificate(self):
        """
        Test that the right error is generated when no certificate is
        available to provide the client identity.
        """
        kmip_session = session.KmipSession(None, None, 'name')
        kmip_session._logger = mock.MagicMock()
        kmip_session._connection = mock.MagicMock()
        kmip_session._connection.getpeercert.return_value = None

        self.assertRaisesRegexp(
            exceptions.PermissionDenied,
            "Failure loading the client certificate from the session "
            "connection. Could not retrieve client identity.",
            kmip_session._get_client_identity
        )

    def test_get_client_identity_with_no_extended_key_usage(self):
        """
        Test that the right error is generated when the client certificate
        is missing its extended key usage extension.
        """
        client_certificate = build_certificate([u'Test Identity'], False)
        der_encoding = client_certificate.public_bytes(
            serialization.Encoding.DER
        )

        kmip_session = session.KmipSession(None, None, 'name')
        kmip_session._logger = mock.MagicMock()
        kmip_session._connection = mock.MagicMock()
        kmip_session._connection.getpeercert.return_value = der_encoding

        self.assertRaisesRegexp(
            exceptions.PermissionDenied,
            "The extended key usage extension is missing from the client "
            "certificate. Session client identity unavailable.",
            kmip_session._get_client_identity
        )

    def test_get_client_identity_with_no_common_name(self):
        """
        Test that the right error is generated when the client certificate
        does not define a subject common name.
        """
        client_certificate = build_certificate([])
        der_encoding = client_certificate.public_bytes(
            serialization.Encoding.DER
        )

        kmip_session = session.KmipSession(None, None, 'name')
        kmip_session._logger = mock.MagicMock()
        kmip_session._connection = mock.MagicMock()
        kmip_session._connection.getpeercert.return_value = der_encoding

        self.assertRaisesRegexp(
            exceptions.PermissionDenied,
            "The client certificate does not define a subject common "
            "name. Session client identity unavailable.",
            kmip_session._get_client_identity
        )

    def test_get_client_identity_with_multiple_common_names(self):
        """
        Test that the right client identity is returned when the client
        certificate has multiple subject common names.
        """
        client_certificate = build_certificate([
            u'Test Identity 1',
            u'Test Identity 2'
        ])
        der_encoding = client_certificate.public_bytes(
            serialization.Encoding.DER
        )

        kmip_session = session.KmipSession(None, None, 'name')
        kmip_session._logger = mock.MagicMock()
        kmip_session._connection = mock.MagicMock()
        kmip_session._connection.getpeercert.return_value = der_encoding

        identity = kmip_session._get_client_identity()
        self.assertEqual(u'Test Identity 1', identity)

        kmip_session._logger.info.assert_called_once_with(
            "Session client identity: Test Identity 1"
        )
        kmip_session._logger.warning.assert_called_once_with(
            "Multiple client identities found. Using the first one processed."
        )

    def test_get_client_identity_with_incorrect_extended_key_usage(self):
        """
        Test that the right error is generated when the client certificate
        does not have client authentication set in its extended key usage
        extension.
        """
        client_certificate = build_certificate(
            [u'Test Identity'],
            bad_extension=True
        )
        der_encoding = client_certificate.public_bytes(
            serialization.Encoding.DER
        )

        kmip_session = session.KmipSession(None, None, 'name')
        kmip_session._logger = mock.MagicMock()
        kmip_session._connection = mock.MagicMock()
        kmip_session._connection.getpeercert.return_value = der_encoding

        self.assertRaisesRegexp(
            exceptions.PermissionDenied,
            "The extended key usage extension is not marked for client "
            "authentication in the client certificate. Session client "
            "identity unavailable.",
            kmip_session._get_client_identity
        )

    @mock.patch('kmip.core.messages.messages.RequestMessage')
    def test_handle_message_loop(self, request_mock):
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
            protocol_version=contents.ProtocolVersion.create(1, 0),
            time_stamp=contents.TimeStamp(int(time.time())),
            batch_count=contents.BatchCount(len(batch_items))
        )
        message = messages.ResponseMessage(
            response_header=header,
            batch_items=batch_items
        )

        kmip_engine = engine.KmipEngine()
        kmip_engine._logger = mock.MagicMock()
        kmip_session = session.KmipSession(kmip_engine, None, 'name')
        kmip_session._engine = mock.MagicMock()
        kmip_session._get_client_identity = mock.MagicMock()
        kmip_session._get_client_identity.return_value = 'test'
        kmip_session._engine.process_request = mock.MagicMock(
            return_value=(message, kmip_session._max_response_size)
        )
        kmip_session._logger = mock.MagicMock()
        kmip_session._connection = mock.MagicMock()
        kmip_session._receive_request = mock.MagicMock(return_value=data)
        kmip_session._send_response = mock.MagicMock()

        kmip_session._handle_message_loop()

        kmip_session._receive_request.assert_called_once_with()
        kmip_session._logger.info.assert_not_called()
        kmip_session._logger.warning.assert_not_called()
        kmip_session._logger.exception.assert_not_called()
        self.assertTrue(kmip_session._send_response.called)

    @mock.patch('kmip.core.messages.messages.RequestMessage.read',
                mock.MagicMock(side_effect=Exception()))
    def test_handle_message_loop_with_parse_failure(self):
        """
        Test that the correct logging and error handling occurs during the
        message handling loop.
        """
        data = utils.BytearrayStream(())

        kmip_engine = engine.KmipEngine()
        kmip_session = session.KmipSession(kmip_engine, None, 'name')
        kmip_session._get_client_identity = mock.MagicMock()
        kmip_session._get_client_identity.return_value = 'test'
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

    @mock.patch('kmip.core.messages.messages.RequestMessage')
    def test_handle_message_loop_with_response_too_long(self, request_mock):
        """
        Test that the correct logging and error handling occurs during the
        message handling loop.
        """
        data = utils.BytearrayStream(())

        kmip_engine = engine.KmipEngine()
        kmip_session = session.KmipSession(kmip_engine, None, 'name')
        kmip_session._get_client_identity = mock.MagicMock()
        kmip_session._get_client_identity.return_value = 'test'
        kmip_session._logger = mock.MagicMock()
        kmip_session._connection = mock.MagicMock()
        kmip_session._receive_request = mock.MagicMock(return_value=data)
        kmip_session._send_response = mock.MagicMock()
        kmip_session._max_response_size = 0

        kmip_session._handle_message_loop()

        kmip_session._receive_request.assert_called_once_with()
        kmip_session._logger.info.assert_not_called()
        self.assertTrue(kmip_session._logger.warning.called)
        kmip_session._logger.exception.assert_not_called()
        self.assertTrue(kmip_session._send_response.called)

    @mock.patch('kmip.core.messages.messages.RequestMessage')
    def test_handle_message_loop_with_unexpected_error(self, request_mock):
        """
        Test that the correct logging and error handling occurs when an
        unexpected error is generated while processing a request.
        """
        data = utils.BytearrayStream(())

        kmip_engine = engine.KmipEngine()
        kmip_engine._logger = mock.MagicMock()
        kmip_session = session.KmipSession(kmip_engine, None, 'name')
        kmip_session._get_client_identity = mock.MagicMock()
        kmip_session._get_client_identity.return_value = 'test'
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
        kmip_session._logger.info.assert_not_called()
        kmip_session._logger.warning.assert_called_once_with(
            "An unexpected error occurred while processing request."
        )
        kmip_session._logger.exception.assert_called_once_with(test_exception)
        self.assertTrue(kmip_session._send_response.called)

    def test_receive_request(self):
        """
        Test that the session can correctly receive and parse a message
        encoding.
        """
        content = b'\x00\x00\x00\x00\x00\x00\x00\x00'
        expected = utils.BytearrayStream((content))

        kmip_session = session.KmipSession(None, None, 'name')
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

        kmip_session = session.KmipSession(None, None, 'name')
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

        kmip_session = session.KmipSession(None, None, 'name')
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

        kmip_session = session.KmipSession(None, None, 'name')
        kmip_session._connection = mock.MagicMock()

        kmip_session._send_response(buffer_empty.buffer)
        kmip_session._connection.sendall.assert_not_called()

        kmip_session._send_response(buffer_full.buffer)
        kmip_session._connection.sendall.assert_called_once_with(
            bytes(buffer_full.buffer)
        )
