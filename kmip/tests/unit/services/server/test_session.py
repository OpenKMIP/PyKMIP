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
import socket
import testtools

from kmip.core import utils
from kmip.services.server import session


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
        kmip_session._handle_message_loop = mock.MagicMock()
        kmip_session._connection = mock.MagicMock()

        kmip_session.run()

        kmip_session._logger.info.assert_any_call("Starting session: name")
        kmip_session._handle_message_loop.assert_called_once_with()
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
            side_effect=test_exception
        )

        kmip_session.run()

        kmip_session._logger.info.assert_any_call("Starting session: name")
        kmip_session._handle_message_loop.assert_called_once_with()
        kmip_session._logger.info.assert_any_call(
            "Failure handling message loop"
        )
        kmip_session._logger.exception.assert_called_once_with(test_exception)
        kmip_session._connection.shutdown.assert_called_once_with(
            socket.SHUT_RDWR
        )
        kmip_session._connection.close.assert_called_once_with()
        kmip_session._logger.info.assert_called_with("Stopping session: name")

    @mock.patch('kmip.core.messages.messages.RequestMessage')
    def test_handle_message_loop(self, request_mock):
        """
        Test that the correct logging and error handling occurs during the
        message handling loop.
        """
        data = utils.BytearrayStream(())

        kmip_session = session.KmipSession(None, None, 'name')
        kmip_session._logger = mock.MagicMock()
        kmip_session._connection = mock.MagicMock()
        kmip_session._receive_request = mock.MagicMock(return_value=data)
        kmip_session._send_response = mock.MagicMock()

        kmip_session._handle_message_loop()

        kmip_session._receive_request.assert_called_once_with()
        kmip_session._logger.info.assert_not_called()
        kmip_session._logger.error.assert_not_called()
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

        kmip_session = session.KmipSession(None, None, 'name')
        kmip_session._logger = mock.MagicMock()
        kmip_session._connection = mock.MagicMock()
        kmip_session._receive_request = mock.MagicMock(return_value=data)
        kmip_session._send_response = mock.MagicMock()

        kmip_session._handle_message_loop()

        kmip_session._receive_request.assert_called_once_with()
        kmip_session._logger.info.assert_called_once_with(
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

        kmip_session = session.KmipSession(None, None, 'name')
        kmip_session._logger = mock.MagicMock()
        kmip_session._connection = mock.MagicMock()
        kmip_session._receive_request = mock.MagicMock(return_value=data)
        kmip_session._send_response = mock.MagicMock()
        kmip_session._max_response_size = 0

        kmip_session._handle_message_loop()

        kmip_session._receive_request.assert_called_once_with()
        kmip_session._logger.info.assert_not_called()
        self.assertTrue(kmip_session._logger.error.called)
        kmip_session._logger.exception.assert_not_called()
        self.assertTrue(kmip_session._send_response.called)

    def test_build_error_response(self):
        """
        Test that a default error response can be built correctly.

        TODO (peterhamilton): Remove this test when the KmipEngine is added.
        """
        from kmip.core import enums
        kmip_session = session.KmipSession(None, None, 'name')
        kmip_session._build_error_response(
            enums.ResultStatus.OPERATION_FAILED,
            enums.ResultReason.GENERAL_FAILURE,
            "General failure message."
        )

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
