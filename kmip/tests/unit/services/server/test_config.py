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

from six.moves import configparser

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
        config.KmipServerConfig()

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

        # Test the right error is generated when setting an unsupported
        # setting.
        args = ('invalid', None)
        regex = "Setting 'invalid' is not supported."
        self.assertRaisesRegexp(
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

    def test_load_settings(self):
        """
        Test that the right calls are made and the right errors generated when
        loading configuration settings from a configuration file specified by
        a path string.
        """
        c = config.KmipServerConfig()
        c._logger = mock.MagicMock()
        c._parse_settings = mock.MagicMock()

        # Test that the right calls are made when correctly processing the
        # configuration file.
        with mock.patch('os.path.exists') as os_mock:
            os_mock.return_value = True
            with mock.patch(
                'six.moves.configparser.SafeConfigParser.read'
            ) as parser_mock:
                c.load_settings("/test/path/server.conf")
                c._logger.info.assert_any_call(
                    "Loading server configuration settings from: "
                    "/test/path/server.conf"
                )
                parser_mock.assert_called_with("/test/path/server.conf")
                self.assertTrue(c._parse_settings.called)

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

        # Test that the right calls are made when correctly parsing settings.
        parser = configparser.SafeConfigParser()
        parser.add_section('server')
        parser.set('server', 'hostname', '127.0.0.1')
        parser.set('server', 'port', '5696')
        parser.set('server', 'certificate_path', '/test/path/server.crt')
        parser.set('server', 'key_path', '/test/path/server.key')
        parser.set('server', 'ca_path', '/test/path/ca.crt')
        parser.set('server', 'auth_suite', 'Basic')
        parser.set('server', 'policy_path', '/test/path/policies')

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

        # Test that a ConfigurationError is generated when the expected
        # section is missing.
        parser = configparser.SafeConfigParser()

        args = (parser, )
        regex = (
            "The server configuration file does not have a 'server' section."
        )
        self.assertRaisesRegexp(
            exceptions.ConfigurationError,
            regex,
            c._parse_settings,
            *args
        )

        # Test that a ConfigurationError is generated when an unexpected
        # setting is provided.
        parser = configparser.SafeConfigParser()
        parser.add_section('server')
        parser.set('server', 'invalid', 'invalid')

        args = (parser, )
        regex = (
            "Setting 'invalid' is not a supported setting. Please remove it "
            "from the configuration file."
        )
        self.assertRaisesRegexp(
            exceptions.ConfigurationError,
            regex,
            c._parse_settings,
            *args
        )

        # Test that a ConfigurationError is generated when an expected
        # setting is missing.
        parser = configparser.SafeConfigParser()
        parser.add_section('server')

        args = (parser, )
        regex = (
            "Setting 'hostname' is missing from the configuration file."
        )
        self.assertRaisesRegexp(
            exceptions.ConfigurationError,
            regex,
            c._parse_settings,
            *args
        )

        # Test that a ConfigurationError is generated when an expected
        # setting is missing.
        parser = configparser.SafeConfigParser()
        parser.add_section('server')

        args = (parser, )
        regex = (
            "Setting 'hostname' is missing from the configuration file."
        )
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
            exceptions.ConfigurationError,
            regex,
            c._set_port,
            *args
        )
        self.assertNotEqual('invalid', c.settings.get('port'))

        args = (65536, )
        regex = "The port value must be an integer in the range 0 - 65535."
        self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
            self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
            self.assertRaisesRegexp(
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
        self.assertRaisesRegexp(
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
