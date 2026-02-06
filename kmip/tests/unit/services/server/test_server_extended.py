# Copyright (c) 2026 The Johns Hopkins University/Applied Physics Laboratory
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
import os
import socket
import tempfile

import testtools

from unittest import mock

from kmip.core import exceptions
from kmip.services.server import server as kmip_server


class TestKmipServerExtended(testtools.TestCase):

    def setUp(self):
        super(TestKmipServerExtended, self).setUp()

    def tearDown(self):
        super(TestKmipServerExtended, self).tearDown()

    def _build_server_for_start(self):
        with mock.patch.object(kmip_server.KmipServer, '_setup_logging'), \
                mock.patch.object(
                    kmip_server.auth, 'BasicAuthenticationSuite'
                ) as basic_suite:
            basic_suite.return_value = mock.Mock(
                ciphers='cipher1:cipher2',
                protocol='PROTO'
            )
            server = kmip_server.KmipServer(
                config_path=None,
                log_path='log'
            )

        server._logger = mock.MagicMock()
        server.config.settings.update({
            'hostname': '127.0.0.1',
            'port': 5696,
            'certificate_path': 'cert.pem',
            'key_path': 'key.pem',
            'ca_path': 'ca.pem',
            'policy_path': '/tmp/policy',
            'tls_cipher_suites': ['TLS_TEST'],
            'database_path': None,
            'enable_tls_client_auth': True,
            'auth_suite': 'Basic'
        })
        server.auth_suite = mock.Mock(protocol='PROTO', ciphers='cipher1:cipher2')
        return server

    def test_init_defaults(self):
        """Test KmipServer initializes with default values."""
        with mock.patch.object(
            kmip_server.KmipServer,
            '_setup_logging'
        ) as logging_mock, mock.patch.object(
            kmip_server.KmipServer,
            '_setup_configuration'
        ) as config_mock, mock.patch.object(
            kmip_server.auth,
            'BasicAuthenticationSuite'
        ) as basic_suite:
            suite = mock.Mock(ciphers='cipher', protocol='proto')
            basic_suite.return_value = suite

            server = kmip_server.KmipServer(config_path=None, log_path='log')

        logging_mock.assert_called_once_with('log')
        config_mock.assert_called_once()
        basic_suite.assert_called_once_with([])
        self.assertEqual(1, server._session_id)
        self.assertFalse(server._is_serving)
        self.assertEqual(suite, server.auth_suite)
        self.assertEqual(logging.INFO, server.config.settings.get('logging_level'))

    def test_init_with_all_params(self):
        """Test KmipServer initializes with all explicit parameters."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cert_path = os.path.join(temp_dir, 'server.crt')
            key_path = os.path.join(temp_dir, 'server.key')
            ca_path = os.path.join(temp_dir, 'ca.crt')
            for path in [cert_path, key_path, ca_path]:
                with open(path, 'w'):
                    pass

            with mock.patch.object(
                kmip_server.KmipServer,
                '_setup_logging'
            ), mock.patch.object(
                kmip_server.auth,
                'TLS12AuthenticationSuite'
            ) as tls_suite:
                tls_suite.return_value = mock.Mock(
                    ciphers='cipher',
                    protocol='proto'
                )
                server = kmip_server.KmipServer(
                    hostname='127.0.0.1',
                    port=5696,
                    certificate_path=cert_path,
                    key_path=key_path,
                    ca_path=ca_path,
                    auth_suite='TLS1.2',
                    config_path=None,
                    log_path='log',
                    policy_path='/tmp/policy',
                    enable_tls_client_auth=False,
                    tls_cipher_suites='TLS_ONE,TLS_TWO',
                    logging_level='ERROR',
                    live_policies=True,
                    database_path='/tmp/server.db'
                )

            self.assertEqual('127.0.0.1', server.config.settings.get('hostname'))
            self.assertEqual(5696, server.config.settings.get('port'))
            self.assertEqual(cert_path, server.config.settings.get('certificate_path'))
            self.assertEqual(key_path, server.config.settings.get('key_path'))
            self.assertEqual(ca_path, server.config.settings.get('ca_path'))
            self.assertEqual('TLS1.2', server.config.settings.get('auth_suite'))
            self.assertEqual('/tmp/policy', server.config.settings.get('policy_path'))
            self.assertFalse(server.config.settings.get('enable_tls_client_auth'))
            self.assertEqual(
                {'TLS_ONE', 'TLS_TWO'},
                set(server.config.settings.get('tls_cipher_suites'))
            )
            self.assertEqual(logging.ERROR, server.config.settings.get('logging_level'))
            self.assertEqual('/tmp/server.db', server.config.settings.get('database_path'))
            self.assertTrue(server.live_policies)
            self.assertTrue(tls_suite.called)

    def test_init_with_config_file(self):
        """Test KmipServer loads settings from a config file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cert_path = os.path.join(temp_dir, 'server.crt')
            key_path = os.path.join(temp_dir, 'server.key')
            ca_path = os.path.join(temp_dir, 'ca.crt')
            config_path = os.path.join(temp_dir, 'server.conf')
            for path in [cert_path, key_path, ca_path]:
                with open(path, 'w'):
                    pass

            with open(config_path, 'w') as config_file:
                config_file.write(
                    "[server]\n"
                    "hostname=127.0.0.1\n"
                    "port=5696\n"
                    "certificate_path={}\n"
                    "key_path={}\n"
                    "ca_path={}\n"
                    "auth_suite=TLS1.2\n"
                    "policy_path=/tmp/policy\n"
                    "enable_tls_client_auth=True\n"
                    "tls_cipher_suites=TLS_RSA_WITH_AES_128_CBC_SHA256 "
                    "TLS_RSA_WITH_AES_256_CBC_SHA256\n"
                    "logging_level=DEBUG\n"
                    "database_path=/tmp/server.db\n".format(
                        cert_path,
                        key_path,
                        ca_path
                    )
                )

            with mock.patch.object(
                kmip_server.KmipServer,
                '_setup_logging'
            ), mock.patch.object(
                kmip_server.auth,
                'TLS12AuthenticationSuite'
            ) as tls_suite:
                tls_suite.return_value = mock.Mock(
                    ciphers='cipher',
                    protocol='proto'
                )
                server = kmip_server.KmipServer(
                    config_path=config_path,
                    log_path='log'
                )

            self.assertEqual('127.0.0.1', server.config.settings.get('hostname'))
            self.assertEqual(5696, server.config.settings.get('port'))
            self.assertEqual(cert_path, server.config.settings.get('certificate_path'))
            self.assertEqual(key_path, server.config.settings.get('key_path'))
            self.assertEqual(ca_path, server.config.settings.get('ca_path'))
            self.assertEqual('TLS1.2', server.config.settings.get('auth_suite'))
            self.assertEqual('/tmp/policy', server.config.settings.get('policy_path'))
            self.assertTrue(server.config.settings.get('enable_tls_client_auth'))
            self.assertEqual(
                {
                    'TLS_RSA_WITH_AES_128_CBC_SHA256',
                    'TLS_RSA_WITH_AES_256_CBC_SHA256'
                },
                set(server.config.settings.get('tls_cipher_suites'))
            )
            self.assertEqual(logging.DEBUG, server.config.settings.get('logging_level'))
            self.assertEqual('/tmp/server.db', server.config.settings.get('database_path'))
            self.assertTrue(tls_suite.called)

    def test_init_invalid_hostname(self):
        """Test KmipServer rejects invalid hostname values."""
        with mock.patch.object(kmip_server.KmipServer, '_setup_logging'):
            self.assertRaises(
                exceptions.ConfigurationError,
                kmip_server.KmipServer,
                hostname=123,
                config_path=None,
                log_path='log'
            )

    def test_init_invalid_port(self):
        """Test KmipServer rejects invalid port values."""
        with mock.patch.object(kmip_server.KmipServer, '_setup_logging'):
            self.assertRaises(
                exceptions.ConfigurationError,
                kmip_server.KmipServer,
                port=70000,
                config_path=None,
                log_path='log'
            )

    def test_start_creates_socket(self):
        """Test start sets up and binds the server socket."""
        server = self._build_server_for_start()
        wrapped_socket = mock.MagicMock()
        base_socket = mock.MagicMock()

        with mock.patch(
            'kmip.services.server.server.multiprocessing.Manager'
        ) as manager_mock, mock.patch(
            'kmip.services.server.server.monitor.PolicyDirectoryMonitor'
        ) as monitor_mock, mock.patch(
            'kmip.services.server.server.engine.KmipEngine'
        ), mock.patch(
            'kmip.services.server.server.socket.socket'
        ) as socket_mock, mock.patch(
            'kmip.services.server.server.socket.setdefaulttimeout'
        ), mock.patch(
            'kmip.services.server.server.ssl.wrap_socket'
        ) as wrap_socket_mock, mock.patch(
            'kmip.services.server.server.operation_policy.policies',
            {}
        ):
            manager_mock.return_value.dict.return_value = {}
            socket_mock.return_value = base_socket
            wrap_socket_mock.return_value = wrapped_socket

            server.start()

        socket_mock.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
        base_socket.setsockopt.assert_called_once_with(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1
        )
        wrapped_socket.bind.assert_called_once_with(('127.0.0.1', 5696))
        self.assertTrue(server._is_serving)
        monitor_mock.return_value.start.assert_called_once()

    def test_start_with_ssl_context(self):
        """Test start configures SSL with expected parameters."""
        server = self._build_server_for_start()
        wrapped_socket = mock.MagicMock()
        base_socket = mock.MagicMock()

        with mock.patch(
            'kmip.services.server.server.multiprocessing.Manager'
        ) as manager_mock, mock.patch(
            'kmip.services.server.server.monitor.PolicyDirectoryMonitor'
        ) as monitor_mock, mock.patch(
            'kmip.services.server.server.engine.KmipEngine'
        ), mock.patch(
            'kmip.services.server.server.socket.socket'
        ) as socket_mock, mock.patch(
            'kmip.services.server.server.socket.setdefaulttimeout'
        ), mock.patch(
            'kmip.services.server.server.ssl.wrap_socket'
        ) as wrap_socket_mock, mock.patch(
            'kmip.services.server.server.operation_policy.policies',
            {}
        ):
            manager_mock.return_value.dict.return_value = {}
            socket_mock.return_value = base_socket
            wrap_socket_mock.return_value = wrapped_socket

            server.start()

        wrap_socket_mock.assert_called_once_with(
            base_socket,
            keyfile='key.pem',
            certfile='cert.pem',
            server_side=True,
            cert_reqs=kmip_server.ssl.CERT_REQUIRED,
            ssl_version=server.auth_suite.protocol,
            ca_certs='ca.pem',
            do_handshake_on_connect=False,
            suppress_ragged_eofs=True,
            ciphers=server.auth_suite.ciphers
        )
        monitor_mock.return_value.start.assert_called_once()

    def test_start_with_invalid_cert(self):
        """Test start raises when SSL setup fails with invalid certs."""
        server = self._build_server_for_start()
        base_socket = mock.MagicMock()

        with mock.patch(
            'kmip.services.server.server.multiprocessing.Manager'
        ) as manager_mock, mock.patch(
            'kmip.services.server.server.monitor.PolicyDirectoryMonitor'
        ), mock.patch(
            'kmip.services.server.server.engine.KmipEngine'
        ), mock.patch(
            'kmip.services.server.server.socket.socket'
        ) as socket_mock, mock.patch(
            'kmip.services.server.server.socket.setdefaulttimeout'
        ), mock.patch(
            'kmip.services.server.server.ssl.wrap_socket',
            side_effect=FileNotFoundError("missing cert")
        ), mock.patch(
            'kmip.services.server.server.operation_policy.policies',
            {}
        ):
            manager_mock.return_value.dict.return_value = {}
            socket_mock.return_value = base_socket

            self.assertRaises(FileNotFoundError, server.start)

    def test_stop_graceful(self):
        """Test stop gracefully shuts down socket and threads."""
        server = self._build_server_for_start()
        server._logger = mock.MagicMock()
        server._socket = mock.MagicMock()
        server.policy_monitor = mock.MagicMock()

        current_thread = mock.MagicMock()
        other_thread = mock.MagicMock()
        other_thread.name = 'thread-1'
        other_thread.is_alive.return_value = False

        with mock.patch(
            'kmip.services.server.server.threading.enumerate',
            return_value=[current_thread, other_thread]
        ), mock.patch(
            'kmip.services.server.server.threading.current_thread',
            return_value=current_thread
        ):
            server.stop()

        other_thread.join.assert_called_once_with(10.0)
        server._socket.shutdown.assert_called_once_with(socket.SHUT_RDWR)
        server._socket.close.assert_called_once_with()
        server.policy_monitor.stop.assert_called_once_with()
        server.policy_monitor.join.assert_called_once_with()

    def test_stop_with_active_sessions(self):
        """Test stop handles active sessions that fail to terminate."""
        server = self._build_server_for_start()
        server._logger = mock.MagicMock()
        server._socket = mock.MagicMock()
        server.policy_monitor = mock.MagicMock()

        current_thread = mock.MagicMock()
        other_thread = mock.MagicMock()
        other_thread.name = 'thread-2'
        other_thread.is_alive.return_value = True

        with mock.patch(
            'kmip.services.server.server.threading.enumerate',
            return_value=[current_thread, other_thread]
        ), mock.patch(
            'kmip.services.server.server.threading.current_thread',
            return_value=current_thread
        ):
            server.stop()

        other_thread.join.assert_called_once_with(10.0)
        server._logger.warning.assert_called()

    def test_serve_accepts_connection(self):
        """Test serve accepts a connection and creates a session."""
        server = self._build_server_for_start()
        server._logger = mock.MagicMock()
        server._socket = mock.MagicMock()
        server._is_serving = True
        server._setup_connection_handler = mock.MagicMock()

        connection = mock.MagicMock()
        address = ('127.0.0.1', 1234)
        server._socket.accept.side_effect = [ (connection, address), KeyboardInterrupt() ]

        with mock.patch('kmip.services.server.server.signal.signal'):
            server.serve()

        server._socket.listen.assert_called_once_with(5)
        server._setup_connection_handler.assert_called_once_with(
            connection,
            address
        )
        self.assertFalse(server._is_serving)

    def test_serve_socket_timeout(self):
        """Test serve handles socket.accept timeouts."""
        server = self._build_server_for_start()
        server._logger = mock.MagicMock()
        server._socket = mock.MagicMock()
        server._is_serving = True
        server._setup_connection_handler = mock.MagicMock()

        def _accept_side_effect():
            server._is_serving = False
            raise socket.timeout()

        server._socket.accept.side_effect = _accept_side_effect

        with mock.patch('kmip.services.server.server.signal.signal'):
            server.serve()

        server._setup_connection_handler.assert_not_called()
        self.assertFalse(server._is_serving)

    def test_serve_keyboard_interrupt(self):
        """Test serve handles KeyboardInterrupt and stops."""
        server = self._build_server_for_start()
        server._logger = mock.MagicMock()
        server._socket = mock.MagicMock()
        server._is_serving = True
        server._setup_connection_handler = mock.MagicMock()

        server._socket.accept.side_effect = KeyboardInterrupt()

        with mock.patch('kmip.services.server.server.signal.signal'):
            server.serve()

        server._setup_connection_handler.assert_not_called()
        self.assertFalse(server._is_serving)

    def test_setup_logging_creates_handler(self):
        """Test setup_logging creates a rotating file handler."""
        server = kmip_server.KmipServer.__new__(kmip_server.KmipServer)
        server._logger = mock.MagicMock()

        with mock.patch(
            'kmip.services.server.server.os.path.exists',
            return_value=False
        ), mock.patch(
            'kmip.services.server.server.os.path.isdir',
            return_value=False
        ), mock.patch(
            'kmip.services.server.server.os.makedirs'
        ) as makedirs_mock, mock.patch(
            'kmip.services.server.server.open',
            mock.mock_open()
        ), mock.patch(
            'kmip.services.server.server.handlers.RotatingFileHandler'
        ) as handler_cls, mock.patch(
            'kmip.services.server.server.logging.Formatter'
        ) as formatter_cls:
            handler_instance = mock.MagicMock()
            formatter_instance = mock.MagicMock()
            handler_cls.return_value = handler_instance
            formatter_cls.return_value = formatter_instance

            server._setup_logging('C:\\logs\\server.log')

        makedirs_mock.assert_called_once_with('C:\\logs')
        handler_cls.assert_called_once_with(
            'C:\\logs\\server.log',
            mode='a',
            maxBytes=1000000,
            backupCount=5
        )
        handler_instance.setFormatter.assert_called_once_with(
            formatter_instance
        )
        server._logger.addHandler.assert_called_once_with(handler_instance)
        server._logger.setLevel.assert_called_once_with(logging.DEBUG)

    def test_setup_logging_custom_level(self):
        """Test init applies custom logging levels."""
        logger = mock.MagicMock()
        with mock.patch(
            'kmip.services.server.server.logging.getLogger',
            return_value=logger
        ), mock.patch.object(
            kmip_server.KmipServer,
            '_setup_logging'
        ), mock.patch.object(
            kmip_server.auth,
            'BasicAuthenticationSuite'
        ) as basic_suite:
            basic_suite.return_value = mock.Mock(
                ciphers='cipher',
                protocol='proto'
            )
            kmip_server.KmipServer(
                config_path=None,
                log_path='log',
                logging_level='ERROR'
            )

        logger.setLevel.assert_called_with(logging.ERROR)

    def test_signal_handler_sigint(self):
        """Test SIGINT handler raises KeyboardInterrupt and stops serving."""
        server = self._build_server_for_start()
        server._logger = mock.MagicMock()
        server._socket = mock.MagicMock()
        server._is_serving = False

        handlers = {}

        def _record_handler(sig, handler):
            handlers[sig] = handler

        with mock.patch(
            'kmip.services.server.server.signal.signal',
            side_effect=_record_handler
        ):
            server.serve()

        server._is_serving = True
        self.assertRaises(
            KeyboardInterrupt,
            handlers[kmip_server.signal.SIGINT],
            kmip_server.signal.SIGINT,
            None
        )
        self.assertFalse(server._is_serving)

    def test_signal_handler_sigterm(self):
        """Test SIGTERM handler stops serving without exception."""
        server = self._build_server_for_start()
        server._logger = mock.MagicMock()
        server._socket = mock.MagicMock()
        server._is_serving = False

        handlers = {}

        def _record_handler(sig, handler):
            handlers[sig] = handler

        with mock.patch(
            'kmip.services.server.server.signal.signal',
            side_effect=_record_handler
        ):
            server.serve()

        server._is_serving = True
        handlers[kmip_server.signal.SIGTERM](kmip_server.signal.SIGTERM, None)
        self.assertFalse(server._is_serving)
