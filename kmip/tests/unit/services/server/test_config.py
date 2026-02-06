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
import mock

import configparser
import testtools

from kmip.core import exceptions
from kmip.services.server import config

class TestKmipServerConfig(testtools.TestCase):
    """
    A test suite for the KmipServerConfig tool.
    """

    def setUp(self):
        super(TestKmipServerConfig, self).setUp()

    def tearDown(self):
        super(TestKmipServerConfig, self).tearDown()

    def test_init(self):
        """
        Test that a KmipServerConfig object can be created without error.
        """
        c = config.KmipServerConfig()

        self.assertIn('enable_tls_client_auth', c.settings.keys())
        self.assertEqual(
            True,
            c.settings.get('enable_tls_client_auth')
        )

        self.assertIn('tls_cipher_suites', c.settings.keys())
        self.assertEqual([], c.settings.get('tls_cipher_suites'))

    def test_set_setting(self):
        """
        Test that the right errors are raised and methods are called when
        setting individual settings.
        """
        c = config.KmipServerConfig()

        c._set_auth_suite = mock.MagicMock()
        c._set_ca_path = mock.MagicMock()
        c._set_certificate_path = mock.MagicMock()
        c._set_hostname = mock.MagicMock()
        c._set_key_path = mock.MagicMock()
        c._set_port = mock.MagicMock()
        c._set_policy_path = mock.MagicMock()
        c._set_enable_tls_client_auth = mock.MagicMock()
        c._set_tls_cipher_suites = mock.MagicMock()
        c._set_logging_level = mock.MagicMock()
        c._set_database_path = mock.MagicMock()

        # Test the right error is generated when setting an unsupported
        # setting.
        args = ('invalid', None)
        regex = "Setting 'invalid' is not supported."
        self.assertRaisesRegex(
            exceptions.ConfigurationError,
            regex,
            c.set_setting,
            *args
        )

        # Test the right methods are called when setting supported settings.
        c.set_setting('hostname', '127.0.0.1')
        c._set_hostname.assert_called_once_with('127.0.0.1')

        c.set_setting('port', 5696)
        c._set_port.assert_called_once_with(5696)

        c.set_setting('certificate_path', '/etc/pykmip/certs/server.crt')
        c._set_certificate_path.assert_called_once_with(
            '/etc/pykmip/certs/server.crt'
        )

        c.set_setting('key_path', '/etc/pykmip/certs/server.key')
        c._set_key_path.assert_called_once_with(
            '/etc/pykmip/certs/server.key'
        )

        c.set_setting('ca_path', '/etc/pykmip/certs/ca.crt')
        c._set_ca_path.assert_called_once_with('/etc/pykmip/certs/ca.crt')

        c.set_setting('auth_suite', 'Basic')
        c._set_auth_suite.assert_called_once_with('Basic')

        c.set_setting('policy_path', '/etc/pykmip/policies')
        c._set_policy_path.assert_called_once_with('/etc/pykmip/policies')

        c.set_setting('enable_tls_client_auth', False)
        c._set_enable_tls_client_auth.assert_called_once_with(False)

        c.set_setting('tls_cipher_suites', [])
        c._set_tls_cipher_suites.assert_called_once_with([])

        c.set_setting('logging_level', 'WARNING')
        c._set_logging_level.assert_called_once_with('WARNING')

        c.set_setting('database_path', '/var/pykmip/pykmip.db')
        c._set_database_path.assert_called_once_with('/var/pykmip/pykmip.db')

    def test_load_settings(self):
        """
        Test that the right calls are made and the right errors generated when
        loading configuration settings from a configuration file specified by
        a path string.
        """
        c = config.KmipServerConfig()
        c._logger = mock.MagicMock()
        c._parse_settings = mock.MagicMock()
        c.parse_auth_settings = mock.MagicMock()

        # Test that the right calls are made when correctly processing the
        # configuration file.
        with mock.patch('os.path.exists') as os_mock:
            os_mock.return_value = True
            with mock.patch(
                'configparser.ConfigParser.read'
            ) as parser_mock:
                c.load_settings("/test/path/server.conf")
                c._logger.info.assert_any_call(
                    "Loading server configuration settings from: "
                    "/test/path/server.conf"
                )
                parser_mock.assert_called_with("/test/path/server.conf")
                self.assertTrue(c._parse_settings.called)
                self.assertTrue(c.parse_auth_settings.called)

        # Test that a ConfigurationError is generated when the path is invalid.
        c._logger.reset_mock()

        with mock.patch('os.path.exists') as os_mock:
            os_mock.return_value = False
            args = ('/test/path/server.conf', )
            self.assertRaises(
                exceptions.ConfigurationError,
                c.load_settings,
                *args
            )

    def test_parse_auth_settings(self):
        """
        Test that server authentication plugin settings are parsed correctly.
        """
        parser = configparser.ConfigParser()
        parser.add_section('server')
        parser.add_section('auth:slugs')
        parser.set('auth:slugs', 'enabled', 'True')
        parser.set('auth:slugs', 'url', 'http://127.0.0.1:8080/slugs/')
        parser.add_section('auth:ldap')
        parser.set('auth:ldap', 'enabled', 'False')
        parser.set('auth:ldap', 'url', 'http://127.0.0.1:8080/ldap/')

        c = config.KmipServerConfig()
        c._logger = mock.MagicMock()

        self.assertEqual([], c.settings['auth_plugins'])

        c.parse_auth_settings(parser)
        configs = c.settings['auth_plugins']

        self.assertIsInstance(configs, list)
        self.assertEqual(2, len(configs))

        for c in configs:
            self.assertIsInstance(c, tuple)
            self.assertEqual(2, len(c))
            self.assertIn(c[0], ['auth:slugs', 'auth:ldap'])
            self.assertIsInstance(c[1], dict)

            if c[0] == 'auth:slugs':
                self.assertIn('enabled', c[1].keys())
                self.assertEqual('True', c[1]['enabled'])
                self.assertIn('url', c[1].keys())
                self.assertEqual('http://127.0.0.1:8080/slugs/', c[1]['url'])
            elif c[0] == 'auth:ldap':
                self.assertIn('enabled', c[1].keys())
                self.assertEqual('False', c[1]['enabled'])
                self.assertIn('url', c[1].keys())
                self.assertEqual('http://127.0.0.1:8080/ldap/', c[1]['url'])

    def test_parse_auth_settings_no_config(self):
        """
        Test that server authentication plugin settings are parsed correctly,
        even when not specified.
        """
        parser = configparser.ConfigParser()
        parser.add_section('server')

        c = config.KmipServerConfig()
        c._logger = mock.MagicMock()

        self.assertEqual([], c.settings['auth_plugins'])

        c.parse_auth_settings(parser)
        configs = c.settings['auth_plugins']

        self.assertIsInstance(configs, list)
        self.assertEqual(0, len(configs))

    def test_parse_settings(self):
        """
        Test that the right methods are called and the right errors generated
        when parsing the configuration settings.
        """
        c = config.KmipServerConfig()
        c._logger = mock.MagicMock()

        c._set_auth_suite = mock.MagicMock()
        c._set_ca_path = mock.MagicMock()
        c._set_certificate_path = mock.MagicMock()
        c._set_hostname = mock.MagicMock()
        c._set_key_path = mock.MagicMock()
        c._set_port = mock.MagicMock()
        c._set_policy_path = mock.MagicMock()
        c._set_enable_tls_client_auth = mock.MagicMock()
        c._set_tls_cipher_suites = mock.MagicMock()
        c._set_logging_level = mock.MagicMock()
        c._set_database_path = mock.MagicMock()

        # Test that the right calls are made when correctly parsing settings.
        parser = configparser.ConfigParser()
        parser.add_section('server')
        parser.set('server', 'hostname', '127.0.0.1')
        parser.set('server', 'port', '5696')
        parser.set('server', 'certificate_path', '/test/path/server.crt')
        parser.set('server', 'key_path', '/test/path/server.key')
        parser.set('server', 'ca_path', '/test/path/ca.crt')
        parser.set('server', 'auth_suite', 'Basic')
        parser.set('server', 'policy_path', '/test/path/policies')
        parser.set('server', 'enable_tls_client_auth', 'False')
        parser.set(
            'server',
            'tls_cipher_suites',
            "\n    TLS_RSA_WITH_AES_256_CBC_SHA256"
        )
        parser.set('server', 'logging_level', 'ERROR')
        parser.set('server', 'database_path', '/var/pykmip/pykmip.db')

        c._parse_settings(parser)

        c._set_hostname.assert_called_once_with('127.0.0.1')
        c._set_port.assert_called_once_with(5696)
        c._set_certificate_path.assert_called_once_with(
            '/test/path/server.crt'
        )
        c._set_key_path.assert_called_once_with('/test/path/server.key')
        c._set_ca_path.assert_called_once_with('/test/path/ca.crt')
        c._set_auth_suite.assert_called_once_with('Basic')
        c._set_policy_path.assert_called_once_with('/test/path/policies')
        c._set_enable_tls_client_auth.assert_called_once_with(False)
        c._set_tls_cipher_suites.assert_called_once_with(
            "\n    TLS_RSA_WITH_AES_256_CBC_SHA256"
        )
        c._set_logging_level.assert_called_once_with('ERROR')
        c._set_database_path.assert_called_once_with('/var/pykmip/pykmip.db')

        # Test that a ConfigurationError is generated when the expected
        # section is missing.
        parser = configparser.ConfigParser()

        args = (parser, )
        regex = (
            "The server configuration file does not have a 'server' section."
        )
        self.assertRaisesRegex(
            exceptions.ConfigurationError,
            regex,
            c._parse_settings,
            *args
        )

        # Test that a ConfigurationError is generated when an unexpected
        # setting is provided.
        parser = configparser.ConfigParser()
        parser.add_section('server')
        parser.set('server', 'invalid', 'invalid')

        args = (parser, )
        regex = (
            "Setting 'invalid' is not a supported setting. Please remove it "
            "from the configuration file."
        )
        self.assertRaisesRegex(
            exceptions.ConfigurationError,
            regex,
            c._parse_settings,
            *args
        )

        # Test that a ConfigurationError is generated when an expected
        # setting is missing.
        parser = configparser.ConfigParser()
        parser.add_section('server')

        args = (parser, )
        regex = (
            "Setting 'hostname' is missing from the configuration file."
        )
        self.assertRaisesRegex(
            exceptions.ConfigurationError,
            regex,
            c._parse_settings,
            *args
        )

        # Test that a ConfigurationError is generated when an expected
        # setting is missing.
        parser = configparser.ConfigParser()
        parser.add_section('server')

        args = (parser, )
        regex = (
            "Setting 'hostname' is missing from the configuration file."
        )
        self.assertRaisesRegex(
            exceptions.ConfigurationError,
            regex,
            c._parse_settings,
            *args
        )

    def test_set_hostname(self):
        """
        Test that the hostname configuration property can be set correctly.
        """
        c = config.KmipServerConfig()
        c._logger = mock.MagicMock()

        # Test that the setting is set correctly with a valid value.
        c._set_hostname('127.0.0.1')
        self.assertIn('hostname', c.settings.keys())
        self.assertEqual('127.0.0.1', c.settings.get('hostname'))

        # Test that a ConfigurationError is generated when setting the wrong
        # value.
        args = (0, )
        regex = "The hostname value must be a string."
        self.assertRaisesRegex(
            exceptions.ConfigurationError,
            regex,
            c._set_hostname,
            *args
        )
        self.assertNotEqual(0, c.settings.get('hostname'))

    def test_set_port(self):
        """
        Test that the port configuration property can be set correctly.
        """
        c = config.KmipServerConfig()
        c._logger = mock.MagicMock()

        # Test that the setting is set correctly with a valid value.
        c._set_port(5696)
        self.assertIn('port', c.settings.keys())
        self.assertEqual(5696, c.settings.get('port'))

        # Test that a ConfigurationError is generated when setting the wrong
        # value.
        args = ('invalid', )
        regex = "The port value must be an integer in the range 0 - 65535."
        self.assertRaisesRegex(
            exceptions.ConfigurationError,
            regex,
            c._set_port,
            *args
        )
        self.assertNotEqual('invalid', c.settings.get('port'))

        args = (0, )
        regex = "The port value must be an integer in the range 0 - 65535."
        self.assertRaisesRegex(
            exceptions.ConfigurationError,
            regex,
            c._set_port,
            *args
        )
        self.assertNotEqual(0, c.settings.get('port'))

        args = (65535, )
        regex = "The port value must be an integer in the range 0 - 65535."
        self.assertRaisesRegex(
            exceptions.ConfigurationError,
            regex,
            c._set_port,
            *args
        )
        self.assertNotEqual(65535, c.settings.get('port'))

        args = (65536, )
        regex = "The port value must be an integer in the range 0 - 65535."
        self.assertRaisesRegex(
            exceptions.ConfigurationError,
            regex,
            c._set_port,
            *args
        )
        self.assertNotEqual(65536, c.settings.get('port'))

    def test_set_certificate_path(self):
        """
        Test that the certificate_path configuration property can be set
        correctly.
        """
        c = config.KmipServerConfig()
        c._logger = mock.MagicMock()

        self.assertNotIn('certificate_path', c.settings.keys())

        # Test that the setting is set correctly with a valid value.
        with mock.patch('os.path.exists') as os_mock:
            os_mock.return_value = True
            c._set_certificate_path('/test/path/server.crt')

        self.assertIn('certificate_path', c.settings.keys())
        self.assertEqual(
            '/test/path/server.crt',
            c.settings.get('certificate_path')
        )

        c._set_certificate_path(None)
        self.assertIn('certificate_path', c.settings.keys())
        self.assertEqual(None, c.settings.get('certificate_path'))

        # Test that a ConfigurationError is generated when setting the wrong
        # value.
        c = config.KmipServerConfig()
        c._logger = mock.MagicMock()
        args = (0, )
        regex = (
            "The certificate path value, if specified, must be a valid "
            "string path to a certificate file."
        )
        self.assertRaisesRegex(
            exceptions.ConfigurationError,
            regex,
            c._set_certificate_path,
            *args
        )
        self.assertNotEqual(0, c.settings.get('certificate_path'))

        args = ('/test/path/server.crt', )
        regex = (
            "The certificate path value, if specified, must be a valid "
            "string path to a certificate file."
        )
        with mock.patch('os.path.exists') as os_mock:
            os_mock.return_value = False
            self.assertRaisesRegex(
                exceptions.ConfigurationError,
                regex,
                c._set_certificate_path,
                *args
            )
            self.assertNotEqual(
                '/test/path/server.crt',
                c.settings.get('certificate_path')
            )

    def test_set_key_path(self):
        """
        Test that the key_path configuration property can be set correctly.
        """
        c = config.KmipServerConfig()
        c._logger = mock.MagicMock()

        self.assertNotIn('key_path', c.settings.keys())

        # Test that the setting is set correctly with a valid value.
        with mock.patch('os.path.exists') as os_mock:
            os_mock.return_value = True
            c._set_key_path('/test/path/server.key')

        self.assertIn('key_path', c.settings.keys())
        self.assertEqual(
            '/test/path/server.key',
            c.settings.get('key_path')
        )

        c._set_key_path(None)
        self.assertIn('key_path', c.settings.keys())
        self.assertEqual(None, c.settings.get('key_path'))

        # Test that a ConfigurationError is generated when setting the wrong
        # value.
        c = config.KmipServerConfig()
        c._logger = mock.MagicMock()
        args = (0, )
        regex = (
            "The key path value, if specified, must be a valid string path "
            "to a certificate key file."
        )
        self.assertRaisesRegex(
            exceptions.ConfigurationError,
            regex,
            c._set_key_path,
            *args
        )
        self.assertNotEqual(0, c.settings.get('key_path'))

        args = ('/test/path/server.key', )
        regex = (
            "The key path value, if specified, must be a valid string path "
            "to a certificate key file."
        )
        with mock.patch('os.path.exists') as os_mock:
            os_mock.return_value = False
            self.assertRaisesRegex(
                exceptions.ConfigurationError,
                regex,
                c._set_key_path,
                *args
            )
            self.assertNotEqual(
                '/test/path/server.key',
                c.settings.get('key_path')
            )

    def test_set_ca_path(self):
        """
        Test that the ca_path configuration property can be set correctly.
        """
        c = config.KmipServerConfig()
        c._logger = mock.MagicMock()

        self.assertNotIn('ca_path', c.settings.keys())

        # Test that the setting is set correctly with a valid value.
        with mock.patch('os.path.exists') as os_mock:
            os_mock.return_value = True
            c._set_ca_path('/test/path/ca.crt')

        self.assertIn('ca_path', c.settings.keys())
        self.assertEqual(
            '/test/path/ca.crt',
            c.settings.get('ca_path')
        )

        c._set_ca_path(None)
        self.assertIn('ca_path', c.settings.keys())
        self.assertEqual(None, c.settings.get('ca_path'))

        # Test that a ConfigurationError is generated when setting the wrong
        # value.
        c._logger.reset_mock()
        args = (0, )
        self.assertRaises(
            exceptions.ConfigurationError,
            c._set_ca_path,
            *args
        )
        self.assertNotEqual(0, c.settings.get('ca_path'))

        args = ('/test/path/ca.crt', )
        with mock.patch('os.path.exists') as os_mock:
            os_mock.return_value = False
            self.assertRaises(
                exceptions.ConfigurationError,
                c._set_ca_path,
                *args
            )
            self.assertNotEqual(0, c.settings.get('ca_path'))

    def test_set_auth_suite(self):
        """
        Test that the auth_suite configuration property can be set correctly.
        """
        c = config.KmipServerConfig()
        c._logger = mock.MagicMock()

        # Test that the setting is set correctly with a valid value.
        c._set_auth_suite('Basic')
        self.assertIn('auth_suite', c.settings.keys())
        self.assertEqual('Basic', c.settings.get('auth_suite'))

        c._set_auth_suite('TLS1.2')
        self.assertIn('auth_suite', c.settings.keys())
        self.assertEqual('TLS1.2', c.settings.get('auth_suite'))

        # Test that a ConfigurationError is generated when setting the wrong
        # value.
        args = ('invalid', )
        regex = (
            "The authentication suite must be one of the following: "
            "Basic, TLS1.2"
        )
        self.assertRaisesRegex(
            exceptions.ConfigurationError,
            regex,
            c._set_auth_suite,
            *args
        )
        self.assertNotEqual('invalid', c.settings.get('auth_suite'))

    def test_set_policy_path(self):
        """
        Test that the policy_path configuration property can be set correctly.
        """
        c = config.KmipServerConfig()
        c._logger = mock.MagicMock()

        self.assertNotIn('policy_path', c.settings.keys())

        # Test that the setting is set correctly with a valid value.
        with mock.patch('os.path.exists') as os_mock:
            os_mock.return_value = True
            c._set_policy_path('/test/path/policies')

        self.assertIn('policy_path', c.settings.keys())
        self.assertEqual(
            '/test/path/policies',
            c.settings.get('policy_path')
        )

        c._set_policy_path(None)
        self.assertIn('policy_path', c.settings.keys())
        self.assertEqual(None, c.settings.get('policy_path'))

        # Test that a ConfigurationError is generated when setting the wrong
        # value.
        c._logger.reset_mock()
        args = (1, )
        self.assertRaises(
            exceptions.ConfigurationError,
            c._set_policy_path,
            *args
        )
        self.assertNotEqual(1, c.settings.get('policy_path'))

    def test_set_enable_tls_client_auth(self):
        """
        Test that the enable_tls_client_auth configuration property can be set
        correctly.
        """
        c = config.KmipServerConfig()
        c._logger = mock.MagicMock()

        # Test that the setting is set correctly with a valid value
        c._set_enable_tls_client_auth(False)
        self.assertEqual(
            False,
            c.settings.get('enable_tls_client_auth')
        )

        c._set_enable_tls_client_auth(None)
        self.assertEqual(
            True,
            c.settings.get('enable_tls_client_auth')
        )

        c._set_enable_tls_client_auth(True)
        self.assertEqual(
            True,
            c.settings.get('enable_tls_client_auth')
        )

        # Test that a ConfigurationError is generated when setting the wrong
        # value.
        args = ('invalid',)
        self.assertRaisesRegex(
            exceptions.ConfigurationError,
            "The flag enabling the TLS certificate client auth flag check "
            "must be a boolean.",
            c._set_enable_tls_client_auth,
            *args
        )

    def test_set_tls_cipher_suites(self):
        """
        Test that the tls_cipher_suites configuration property can be set
        correctly with a value expected from the config file.
        """
        c = config.KmipServerConfig()
        c._logger = mock.MagicMock()

        c._set_tls_cipher_suites(
            """
    TLS_RSA_WITH_AES_256_CBC_SHA256
    TLS_RSA_WITH_AES_128_CBC_SHA256
"""
        )
        self.assertEqual(2, len(c.settings.get('tls_cipher_suites')))
        self.assertIn(
            'TLS_RSA_WITH_AES_256_CBC_SHA256',
            c.settings.get('tls_cipher_suites')
        )
        self.assertIn(
            'TLS_RSA_WITH_AES_128_CBC_SHA256',
            c.settings.get('tls_cipher_suites')
        )

    def test_set_tls_cipher_suites_preparsed(self):
        """
        Test that the tls_cipher_suites configuration property can be set
        correctly with a preparsed list of TLS cipher suites, the value
        expected if the cipher suites were provided via constructor.
        """
        c = config.KmipServerConfig()
        c._logger = mock.MagicMock()

        c._set_tls_cipher_suites(
            [
                'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
                'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384',
                'DH-DSS-AES128-SHA'
            ]
        )
        self.assertEqual(3, len(c.settings.get('tls_cipher_suites')))
        self.assertIn(
            'DH-DSS-AES128-SHA',
            c.settings.get('tls_cipher_suites')
        )
        self.assertIn(
            'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
            c.settings.get('tls_cipher_suites')
        )
        self.assertIn(
            'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384',
            c.settings.get('tls_cipher_suites')
        )

    def test_set_tls_cipher_suites_empty(self):
        """
        Test that the tls_cipher_suites configuration property can be set
        correctly with an empty value.
        """
        c = config.KmipServerConfig()
        c._logger = mock.MagicMock()

        c._set_tls_cipher_suites(None)
        self.assertEqual([], c.settings.get('tls_cipher_suites'))

    def test_set_tls_cipher_suites_invalid_value(self):
        """
        Test that the right error is raised when an invalid value is used to
        set the tls_cipher_suites configuration property.
        """
        c = config.KmipServerConfig()
        c._logger = mock.MagicMock()

        args = (1,)
        self.assertRaisesRegex(
            exceptions.ConfigurationError,
            "The TLS cipher suites must be a set of strings representing "
            "cipher suite names.",
            c._set_tls_cipher_suites,
            *args
        )

    def test_set_tls_cipher_suites_invalid_list_value(self):
        """
        Test that the right error is raised when an invalid list value is used
        to set the tls_cipher_suites configuration property.
        """
        c = config.KmipServerConfig()
        c._logger = mock.MagicMock()

        args = ([0],)
        self.assertRaisesRegex(
            exceptions.ConfigurationError,
            "The TLS cipher suites must be a set of strings representing "
            "cipher suite names.",
            c._set_tls_cipher_suites,
            *args
        )

    def test_set_logging_level(self):
        """
        Test that the logging_level configuration property can be set
        correctly with a value expected from the config file.
        """
        c = config.KmipServerConfig()
        c._logger = mock.MagicMock()

        c._set_logging_level("DEBUG")
        self.assertEqual(logging.DEBUG, c.settings.get('logging_level'))

    def test_set_logging_level_enum(self):
        """
        Test that the logging_level configuration property can be set
        correctly with a value expected from the server constructor.
        """
        c = config.KmipServerConfig()
        c._logger = mock.MagicMock()

        c._set_logging_level(logging.DEBUG)
        self.assertEqual(logging.DEBUG, c.settings.get('logging_level'))

    def test_set_logging_level_default(self):
        """
        Test that the logging_level configuration property can be set
        correctly without specifying a value.
        """
        c = config.KmipServerConfig()
        c._logger = mock.MagicMock()

        c._set_logging_level(logging.DEBUG)
        self.assertEqual(logging.DEBUG, c.settings.get('logging_level'))

        c._set_logging_level(None)
        self.assertEqual(logging.INFO, c.settings.get('logging_level'))

    def test_set_logging_level_invalid_value(self):
        """
        Test that the right error is raised when an invalid value is used to
        set the tls_cipher_suites configuration property.
        """
        c = config.KmipServerConfig()
        c._logger = mock.MagicMock()

        args = (0,)
        self.assertRaisesRegex(
            exceptions.ConfigurationError,
            "The logging level must be a string representing a valid logging "
            "level.",
            c._set_logging_level,
            *args
        )

        args = ('invalid',)
        self.assertRaisesRegex(
            exceptions.ConfigurationError,
            "The logging level must be a string representing a valid logging "
            "level.",
            c._set_logging_level,
            *args
        )

    def test_set_database_path(self):
        """
        Test that the database_path configuration property can be set
        correctly.
        """
        c = config.KmipServerConfig()
        c._logger = mock.MagicMock()

        self.assertNotIn('database_path', c.settings.keys())

        with mock.patch('os.path.exists') as os_mock:
            os_mock.return_value = True
            c._set_database_path('/test/path/database.db')

        self.assertIn('database_path', c.settings.keys())
        self.assertEqual(
            '/test/path/database.db',
            c.settings.get('database_path')
        )

    def test_set_database_path_default(self):
        """
        Test that the database_path configuration property can be set correctly
        without specifying a value.
        """
        c = config.KmipServerConfig()
        c._logger = mock.MagicMock()

        self.assertNotIn('database_path', c.settings.keys())

        c._set_database_path(None)
        self.assertIn('database_path', c.settings.keys())
        self.assertEqual(None, c.settings.get('database_path'))

    def test_set_database_path_invalid_value(self):
        """
        Test that the right error is raised when an invalid value is used to
        set the database_path configuration property.
        """
        c = config.KmipServerConfig()
        c._logger = mock.MagicMock()

        self.assertNotIn('database_path', c.settings.keys())

        args = (1, )
        self.assertRaises(
            exceptions.ConfigurationError,
            c._set_database_path,
            *args
        )
        self.assertNotEqual(1, c.settings.get('database_path'))
