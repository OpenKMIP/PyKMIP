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

import logging

try:
    import unittest.mock as mock
except Exception:
    import mock

import signal
import socket
import testtools

from kmip.core import exceptions
from kmip.services import auth
from kmip.services.server import server

class TestKmipServer(testtools.TestCase):
    """
    A test suite for the KmipServer.
    """

    def setUp(self):
        super(TestKmipServer, self).setUp()

    def tearDown(self):
        super(TestKmipServer, self).tearDown()

    @mock.patch('kmip.services.server.server.KmipServer._setup_logging')
    @mock.patch('kmip.services.server.server.KmipServer._setup_configuration')
    def test_init(self, config_mock, logging_mock):
        """
        Test that a KmipServer can be instantiated without error.
        """
        s = server.KmipServer()
        self.assertTrue(config_mock.called)
        self.assertTrue(logging_mock.called)

        self.assertIsInstance(s.auth_suite, auth.BasicAuthenticationSuite)
        self.assertEqual(1, s._session_id)
        self.assertFalse(s._is_serving)

    @mock.patch('logging.getLogger', side_effect=mock.MagicMock())
    @mock.patch('logging.handlers.RotatingFileHandler')
    @mock.patch('kmip.services.server.server.KmipServer._setup_configuration')
    @mock.patch('os.path.exists')
    @mock.patch('os.path.isdir')
    @mock.patch('os.makedirs')
    def test_setup_logging(
            self,
            makedirs_mock,
            isdir_mock,
            path_mock,
            config_mock,
            handler_mock,
            logging_mock):
        """
        Verify that the server logger is setup correctly.
        """
        path_mock.return_value = False
        isdir_mock.return_value = False
        open_mock = mock.mock_open()

        # Dynamically mock out the built-in open function. Approach changes
        # across Python versions.
        try:
            # For Python3+
            import builtins  # NOQA
            module = 'builtins'
        except ImportError:
            # For Python2+
            module = '__builtin__'

        with mock.patch('{0}.open'.format(module), open_mock):
            s = server.KmipServer(log_path='/test/path/server.log')

        path_mock.assert_called_once_with('/test/path/server.log')
        isdir_mock.assert_called_once_with('/test/path')
        makedirs_mock.assert_called_once_with('/test/path')
        open_mock.assert_called_once_with('/test/path/server.log', 'w')

        self.assertTrue(s._logger.addHandler.called)
        s._logger.setLevel.assert_any_call(logging.DEBUG)

    @mock.patch('kmip.services.server.engine.KmipEngine')
    @mock.patch('kmip.services.auth.TLS12AuthenticationSuite')
    @mock.patch('kmip.services.server.server.KmipServer._setup_logging')
    def test_setup_configuration(self, logging_mock, auth_mock, engine_mock):
        """
        Test that the server setup configuration works without error.
        """
        s = server.KmipServer(
            config_path=None,
            policy_path=None
        )
        s.config = mock.MagicMock()

        # Test the right calls are made when reinvoking config setup
        s._setup_configuration(
            '/etc/pykmip/server.conf',
            '127.0.0.1',
            5696,
            '/etc/pykmip/certs/server.crt',
            '/etc/pykmip/certs/server.key',
            '/etc/pykmip/certs/ca.crt',
            'Basic',
            '/etc/pykmip/policies',
            False,
            'TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA',
            'DEBUG',
            '/var/pykmip/pykmip.db'
        )

        s.config.load_settings.assert_called_with('/etc/pykmip/server.conf')
        s.config.set_setting.assert_any_call('hostname', '127.0.0.1')
        s.config.set_setting.assert_any_call('port', 5696)
        s.config.set_setting.assert_any_call(
            'certificate_path',
            '/etc/pykmip/certs/server.crt'
        )
        s.config.set_setting.assert_any_call(
            'key_path',
            '/etc/pykmip/certs/server.key'
        )
        s.config.set_setting.assert_any_call(
            'ca_path',
            '/etc/pykmip/certs/ca.crt'
        )
        s.config.set_setting.assert_any_call('auth_suite', 'Basic')
        s.config.set_setting.assert_any_call(
            'policy_path',
            '/etc/pykmip/policies'
        )
        s.config.set_setting.assert_any_call(
            'enable_tls_client_auth',
            False
        )
        s.config.set_setting.assert_any_call(
            'tls_cipher_suites',
            [
                'TLS_RSA_WITH_AES_128_CBC_SHA',
                'TLS_RSA_WITH_AES_256_CBC_SHA'
            ]
        )
        s.config.set_setting.assert_any_call('logging_level', 'DEBUG')
        s.config.set_setting.assert_any_call(
            'database_path',
            '/var/pykmip/pykmip.db'
        )

        # Test that an attempt is made to instantiate the TLS 1.2 auth suite
        s = server.KmipServer(
            auth_suite='TLS1.2',
            config_path=None,
            policy_path=None
        )
        self.assertEqual('TLS1.2', s.config.settings.get('auth_suite'))
        self.assertIsNotNone(s.auth_suite)

    @mock.patch('multiprocessing.Manager')
    @mock.patch('kmip.services.server.monitor.PolicyDirectoryMonitor')
    @mock.patch('kmip.services.server.engine.KmipEngine')
    @mock.patch('kmip.services.server.server.KmipServer._setup_logging')
    def test_start(self,
                   logging_mock,
                   engine_mock,
                   monitor_mock,
                   manager_mock):
        """
        Test that starting the KmipServer either runs as expected or generates
        the expected error.
        """
        monitor_instance_mock = mock.MagicMock()
        monitor_mock.return_value = monitor_instance_mock

        dict_mock = mock.MagicMock()
        manager_instance_mock = mock.MagicMock()
        manager_instance_mock.dict.return_value = dict_mock
        manager_mock.return_value = manager_instance_mock

        a_mock = mock.MagicMock()
        b_mock = mock.MagicMock()

        s = server.KmipServer(
            hostname='127.0.0.1',
            port=5696,
            auth_suite='Basic',
            config_path=None,
            policy_path=None,
            tls_cipher_suites='TLS_RSA_WITH_AES_128_CBC_SHA'
        )
        s._logger = mock.MagicMock()

        self.assertFalse(s._is_serving)

        # Test that in ideal cases no errors are generated and the right
        # log messages are.
        with mock.patch('socket.socket') as socket_mock:
            with mock.patch('ssl.wrap_socket') as ssl_mock:
                socket_mock.return_value = a_mock
                ssl_mock.return_value = b_mock

                manager_mock.assert_not_called()
                monitor_mock.assert_not_called()

                s.start()

                manager_mock.assert_called_once_with()
                monitor_mock.assert_called_once_with(
                    None,
                    dict_mock,
                    False
                )
                self.assertIsNotNone(s._engine)
                s._logger.info.assert_any_call(
                    "Starting server socket handler."
                )
                s._logger.debug.assert_any_call("Configured cipher suites: 1")
                s._logger.debug.assert_any_call("TLS_RSA_WITH_AES_128_CBC_SHA")
                s._logger.debug.assert_any_call(
                    "Authentication suite ciphers to use: 1"
                )
                s._logger.debug.assert_any_call("AES128-SHA")

                socket_mock.assert_called_once_with(
                    socket.AF_INET,
                    socket.SOCK_STREAM
                )
                a_mock.setsockopt.assert_called_once_with(
                    socket.SOL_SOCKET,
                    socket.SO_REUSEADDR,
                    1
                )
                self.assertTrue(ssl_mock.called)
                b_mock.bind.assert_called_once_with(('127.0.0.1', 5696))
                s._logger.info.assert_called_with(
                    "Server successfully bound socket handler to "
                    "127.0.0.1:5696"
                )

        monitor_instance_mock.stop.assert_not_called()
        handler = signal.getsignal(signal.SIGINT)
        handler(None, None)
        monitor_instance_mock.stop.assert_called_once_with()
        monitor_instance_mock.stop.reset_mock()
        monitor_instance_mock.stop.assert_not_called()
        handler = signal.getsignal(signal.SIGTERM)
        handler(None, None)
        monitor_instance_mock.stop.assert_called_once_with()

        self.assertTrue(s._is_serving)

        manager_mock.reset_mock()
        monitor_mock.reset_mock()
        a_mock.reset_mock()
        b_mock.reset_mock()

        # Test that a NetworkingError is generated if the socket bind fails.
        with mock.patch('socket.socket') as socket_mock:
            with mock.patch('ssl.wrap_socket') as ssl_mock:
                socket_mock.return_value = a_mock
                ssl_mock.return_value = b_mock

                test_exception = Exception()
                b_mock.bind.side_effect = test_exception

                manager_mock.assert_not_called()
                monitor_mock.assert_not_called()

                regex = (
                    "Server failed to bind socket handler to 127.0.0.1:5696"
                )
                self.assertRaisesRegex(
                    exceptions.NetworkingError,
                    regex,
                    s.start
                )

                manager_mock.assert_called_once_with()
                monitor_mock.assert_called_once_with(
                    None,
                    dict_mock,
                    False
                )
                s._logger.info.assert_any_call(
                    "Starting server socket handler."
                )
                s._logger.exception.assert_called_once_with(test_exception)

    @mock.patch('kmip.services.server.engine.KmipEngine')
    @mock.patch('kmip.services.server.server.KmipServer._setup_logging')
    def test_stop(self, logging_mock, engine_mock):
        """
        Test that the right calls and log messages are triggered while
        cleaning up the server and any remaining sessions.
        """
        s = server.KmipServer(
            hostname='127.0.0.1',
            port=5696,
            config_path=None,
            policy_path=None
        )
        s._logger = mock.MagicMock()
        s._socket = mock.MagicMock()

        # Test the expected behavior for a normal server stop sequence
        thread_mock = mock.MagicMock()
        thread_mock.join = mock.MagicMock()
        thread_mock.is_alive = mock.MagicMock(return_value=False)
        thread_mock.name = 'TestThread'

        with mock.patch('threading.enumerate') as threading_mock:
            threading_mock.return_value = [thread_mock]

            s.stop()
            s._logger.info.assert_any_call(
                "Cleaning up remaining connection threads."
            )
            self.assertTrue(threading_mock.called)
            thread_mock.join.assert_called_once_with(10.0)
            s._logger.info.assert_any_call(
                "Cleanup succeeded for thread: TestThread"
            )
            s._logger.info.assert_any_call(
                "Shutting down server socket handler."
            )
            s._socket.shutdown.assert_called_once_with(socket.SHUT_RDWR)
            s._socket.close.assert_called_once_with()

        # Test the expected behavior when stopping multiple server session
        # threads goes wrong
        thread_mock.reset_mock()
        test_exception = Exception()
        thread_mock.join = mock.MagicMock(side_effect=test_exception)

        s._logger.reset_mock()
        s._socket.reset_mock()

        with mock.patch('threading.enumerate') as threading_mock:
            threading_mock.return_value = [thread_mock]

            s.stop()
            s._logger.info.assert_any_call(
                "Cleaning up remaining connection threads."
            )
            self.assertTrue(threading_mock.called)
            thread_mock.join.assert_called_once_with(10.0)
            s._logger.info.assert_any_call(
                "Error occurred while attempting to cleanup thread: TestThread"
            )
            s._logger.exception.assert_called_once_with(test_exception)
            s._logger.info.assert_any_call(
                "Shutting down server socket handler."
            )
            s._socket.shutdown.assert_called_once_with(socket.SHUT_RDWR)
            s._socket.close.assert_called_once_with()

        thread_mock.reset_mock()
        test_exception = Exception()
        thread_mock.join = mock.MagicMock()
        thread_mock.is_alive = mock.MagicMock(return_value=True)

        s._logger.reset_mock()
        s._socket.reset_mock()

        with mock.patch('threading.enumerate') as threading_mock:
            threading_mock.return_value = [thread_mock]

            s.stop()
            s._logger.info.assert_any_call(
                "Cleaning up remaining connection threads."
            )
            self.assertTrue(threading_mock.called)
            thread_mock.join.assert_called_once_with(10.0)
            s._logger.warning.assert_any_call(
                "Cleanup failed for thread: TestThread. Thread is still alive"
            )
            s._logger.info.assert_any_call(
                "Shutting down server socket handler."
            )
            s._socket.shutdown.assert_called_once_with(socket.SHUT_RDWR)
            s._socket.close.assert_called_once_with()

        # Test that the right errors and log messages are generated when
        # stopping the server goes wrong
        s._logger.reset_mock()
        s._socket.reset_mock()

        test_exception = Exception()
        s._socket.close = mock.MagicMock(side_effect=test_exception)

        regex = "Server failed to shutdown socket handler."
        self.assertRaisesRegex(
            exceptions.NetworkingError,
            regex,
            s.stop
        )
        s._logger.info.assert_any_call(
            "Cleaning up remaining connection threads."
        )
        s._logger.info.assert_any_call(
            "Shutting down server socket handler."
        )
        s._socket.shutdown.assert_called_once_with(socket.SHUT_RDWR)
        s._socket.close.assert_called_once_with()
        s._logger.exception(test_exception)

    @mock.patch('kmip.services.server.engine.KmipEngine')
    @mock.patch('kmip.services.server.server.KmipServer._setup_logging')
    def test_stop_with_monitor_shutdown_error(self, logging_mock, engine_mock):
        """
        Test that the right calls and log messages are triggered when stopping
        the server results in an error while shutting down the policy monitor.
        """
        s = server.KmipServer(
            hostname='127.0.0.1',
            port=5696,
            config_path=None,
            policy_path=None
        )
        s._logger = mock.MagicMock()
        s._socket = mock.MagicMock()
        s.policy_monitor = mock.MagicMock()
        test_exception = Exception()
        s.policy_monitor.join.side_effect = test_exception

        # Test the expected behavior for a normal server stop sequence
        thread_mock = mock.MagicMock()
        thread_mock.join = mock.MagicMock()
        thread_mock.is_alive = mock.MagicMock(return_value=False)
        thread_mock.name = 'TestThread'

        regex = "Server failed to clean up the policy monitor."
        self.assertRaisesRegex(
            exceptions.ShutdownError,
            regex,
            s.stop
        )
        s._logger.info.assert_any_call(
            "Cleaning up remaining connection threads."
        )
        s._logger.info.assert_any_call(
            "Shutting down server socket handler."
        )
        s._socket.shutdown.assert_called_once_with(socket.SHUT_RDWR)
        s._socket.close.assert_called_once_with()

        s.policy_monitor.stop.assert_called_once_with()
        s.policy_monitor.join.assert_called_once_with()
        s._logger.exception(test_exception)

    @mock.patch('kmip.services.server.engine.KmipEngine')
    @mock.patch('kmip.services.server.server.KmipServer._setup_logging')
    def test_serve(self, logging_mock, engine_mock):
        """
        Test that the right calls and log messages are triggered while
        serving connections.
        """
        s = server.KmipServer(
            hostname='127.0.0.1',
            port=5696,
            config_path=None,
            policy_path=None
        )
        s._is_serving = True
        s._logger = mock.MagicMock()
        s._socket = mock.MagicMock()
        s._setup_connection_handler = mock.MagicMock()

        expected_error = KeyboardInterrupt

        # Test the expected behavior for a normal server/interrupt sequence
        s._socket.accept = mock.MagicMock(
            side_effect=[
                ('connection', 'address'),
                socket.timeout,
                expected_error
            ]
        )

        s.serve()
        s._socket.listen.assert_called_once_with(5)
        s._socket.accept.assert_any_call()
        s._setup_connection_handler.assert_called_once_with(
            'connection',
            'address'
        )
        s._logger.warning.assert_called_with(
            "Interrupting connection service."
        )
        s._logger.info.assert_called_with("Stopping connection service.")

        # Test the behavior for an unexpected socket error.
        unexpected_error = socket.error()
        s._is_serving = True
        s._logger.reset_mock()
        s._socket.accept = mock.MagicMock(
            side_effect=[unexpected_error, expected_error]
        )

        s.serve()
        s._socket.accept.assert_any_call()
        s._logger.warning.assert_any_call(
            "Error detected while establishing new connection."
        )
        s._logger.exception.assert_called_with(unexpected_error)
        s._logger.info.assert_called_with("Stopping connection service.")

        # Test the behavior for an unexpected error.
        unexpected_error = Exception()
        s._is_serving = True
        s._logger.reset_mock()
        s._socket.accept = mock.MagicMock(
            side_effect=[unexpected_error, expected_error]
        )

        s.serve()
        s._socket.accept.assert_any_call()
        s._logger.warning.assert_any_call(
            "Error detected while establishing new connection."
        )
        s._logger.exception.assert_called_with(unexpected_error)
        s._logger.info.assert_called_with("Stopping connection service.")

        # Test the signal handler for each expected signal
        s._is_serving = True
        handler = signal.getsignal(signal.SIGINT)
        args = (signal.SIGINT, None)
        self.assertRaisesRegex(
            KeyboardInterrupt,
            "SIGINT received",
            handler,
            *args
        )
        self.assertFalse(s._is_serving)

        s._is_serving = True
        handler = signal.getsignal(signal.SIGTERM)
        handler(None, None)
        self.assertFalse(s._is_serving)

    @mock.patch('kmip.services.server.engine.KmipEngine')
    @mock.patch('kmip.services.server.server.KmipServer._setup_logging')
    def test_setup_connection_handler(self, logging_mock, engine_mock):
        """
        Test that a KmipSession can be successfully created and spun off from
        the KmipServer.
        """
        s = server.KmipServer(
            hostname='127.0.0.1',
            port=5696,
            config_path=None,
            policy_path=None
        )
        s._logger = mock.MagicMock()
        s._engine = engine_mock

        # Test that the right calls and log messages are made when
        # starting a new session.
        with mock.patch(
            'kmip.services.server.session.KmipSession.start'
        ) as session_mock:
            address = ('127.0.0.1', 5696)
            s._setup_connection_handler(None, address)

            s._logger.info.assert_any_call(
                "Receiving incoming connection from: 127.0.0.1:5696"
            )
            s._logger.info.assert_any_call(
                "Dedicating session 00000001 to 127.0.0.1:5696"
            )
            session_mock.assert_called_once_with()

        self.assertEqual(2, s._session_id)

        # Test that the right error messages are logged when the session
        # fails to start.
        test_exception = Exception()
        with mock.patch(
            'kmip.services.server.session.KmipSession.start',
            side_effect=test_exception
        ) as session_mock:
            address = ('127.0.0.1', 5696)
            s._setup_connection_handler(None, address)

            s._logger.info.assert_any_call(
                "Receiving incoming connection from: 127.0.0.1:5696"
            )
            s._logger.info.assert_any_call(
                "Dedicating session 00000001 to 127.0.0.1:5696"
            )
            session_mock.assert_called_once_with()
            s._logger.warning.assert_called_once_with(
                "Failure occurred while starting session: 00000002"
            )
            s._logger.exception.assert_called_once_with(test_exception)

        self.assertEqual(3, s._session_id)

    @mock.patch('kmip.services.server.engine.KmipEngine')
    @mock.patch('kmip.services.server.server.KmipServer._setup_logging')
    def test_as_context_manager(self, logging_mock, engine_mock):
        """
        Test that the right methods are called when the KmipServer is used
        as a context manager.
        """
        s = server.KmipServer(
            hostname='127.0.0.1',
            port=5696,
            config_path=None,
            policy_path=None
        )
        s._logger = mock.MagicMock()
        s.start = mock.MagicMock()
        s.stop = mock.MagicMock()

        with s:
            pass

        self.assertTrue(s.start.called)
        self.assertTrue(s.stop.called)
