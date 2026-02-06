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
import os

import configparser
from kmip.core import exceptions

class KmipServerConfig(object):
    """
    A configuration management tool for the KmipServer.
    """

    def __init__(self):
        """
        Create a KmipServerConfig object.
        """
        self._logger = logging.getLogger('kmip.server.config')

        self.settings = dict()
        self.settings['enable_tls_client_auth'] = True
        self.settings['tls_cipher_suites'] = []
        self.settings['logging_level'] = logging.INFO
        self.settings['auth_plugins'] = []

        self._expected_settings = [
            'hostname',
            'port',
            'certificate_path',
            'key_path',
            'ca_path',
            'auth_suite'
        ]
        self._optional_settings = [
            'policy_path',
            'enable_tls_client_auth',
            'tls_cipher_suites',
            'logging_level',
            'database_path'
        ]

    def set_setting(self, setting, value):
        """
        Set a specific setting value.

        This will overwrite the current setting value for the specified
        setting.

        Args:
            setting (string): The name of the setting to set (e.g.,
                'certificate_path', 'hostname'). Required.
            value (misc): The value of the setting to set. Type varies based
                on setting. Required.
        Raises:
            ConfigurationError: Raised if the setting is not supported or if
                the setting value is invalid.
        """
        if setting not in self._expected_settings + self._optional_settings:
            raise exceptions.ConfigurationError(
                "Setting '{0}' is not supported.".format(setting)
            )

        if setting == 'hostname':
            self._set_hostname(value)
        elif setting == 'port':
            self._set_port(value)
        elif setting == 'certificate_path':
            self._set_certificate_path(value)
        elif setting == 'key_path':
            self._set_key_path(value)
        elif setting == 'ca_path':
            self._set_ca_path(value)
        elif setting == 'auth_suite':
            self._set_auth_suite(value)
        elif setting == 'policy_path':
            self._set_policy_path(value)
        elif setting == 'enable_tls_client_auth':
            self._set_enable_tls_client_auth(value)
        elif setting == 'tls_cipher_suites':
            self._set_tls_cipher_suites(value)
        elif setting == 'logging_level':
            self._set_logging_level(value)
        else:
            self._set_database_path(value)

    def load_settings(self, path):
        """
        Load configuration settings from the file pointed to by path.

        This will overwrite all current setting values.

        Args:
            path (string): The path to the configuration file containing
                the settings to load. Required.
        Raises:
            ConfigurationError: Raised if the path does not point to an
                existing file or if a setting value is invalid.
        """
        if not os.path.exists(path):
            raise exceptions.ConfigurationError(
                "The server configuration file ('{0}') could not be "
                "located.".format(path)
            )

        self._logger.info(
            "Loading server configuration settings from: {0}".format(path)
        )

        parser = configparser.ConfigParser()
        parser.read(path)
        self._parse_settings(parser)
        self.parse_auth_settings(parser)

    def parse_auth_settings(self, parser):
        sections = [x for x in parser.sections() if x.startswith("auth:")]
        configs = [(x, dict(parser.items(x))) for x in sections]
        self.settings['auth_plugins'] = configs

    def _parse_settings(self, parser):
        if not parser.has_section('server'):
            raise exceptions.ConfigurationError(
                "The server configuration file does not have a 'server' "
                "section."
            )

        settings = [x[0] for x in parser.items('server')]
        for s in settings:
            if s not in self._expected_settings + self._optional_settings:
                raise exceptions.ConfigurationError(
                    "Setting '{0}' is not a supported setting. Please "
                    "remove it from the configuration file.".format(s)
                )
        for setting in self._expected_settings:
            if setting not in settings:
                raise exceptions.ConfigurationError(
                    "Setting '{0}' is missing from the configuration "
                    "file.".format(setting)
                )

        if parser.has_option('server', 'hostname'):
            self._set_hostname(parser.get('server', 'hostname'))
        if parser.has_option('server', 'port'):
            self._set_port(parser.getint('server', 'port'))
        if parser.has_option('server', 'certificate_path'):
            self._set_certificate_path(parser.get(
                'server',
                'certificate_path')
            )
        if parser.has_option('server', 'key_path'):
            self._set_key_path(parser.get('server', 'key_path'))
        if parser.has_option('server', 'ca_path'):
            self._set_ca_path(parser.get('server', 'ca_path'))
        if parser.has_option('server', 'auth_suite'):
            self._set_auth_suite(parser.get('server', 'auth_suite'))
        if parser.has_option('server', 'policy_path'):
            self._set_policy_path(parser.get('server', 'policy_path'))
        if parser.has_option('server', 'enable_tls_client_auth'):
            self._set_enable_tls_client_auth(
                parser.getboolean('server', 'enable_tls_client_auth')
            )
        if parser.has_option('server', 'tls_cipher_suites'):
            self._set_tls_cipher_suites(
                parser.get('server', 'tls_cipher_suites')
            )
        if parser.has_option('server', 'logging_level'):
            self._set_logging_level(
                parser.get('server', 'logging_level')
            )
        if parser.has_option('server', 'database_path'):
            self._set_database_path(parser.get('server', 'database_path'))

    def _set_hostname(self, value):
        if isinstance(value, str):
            self.settings['hostname'] = value
        else:
            raise exceptions.ConfigurationError(
                "The hostname value must be a string."
            )

    def _set_port(self, value):
        if isinstance(value, int):
            if 0 < value < 65535:
                self.settings['port'] = value
            else:
                raise exceptions.ConfigurationError(
                    "The port value must be an integer in the range 0 - 65535."
                )
        else:
            raise exceptions.ConfigurationError(
                "The port value must be an integer in the range 0 - 65535."
            )

    def _set_certificate_path(self, value):
        if value is None:
            self.settings['certificate_path'] = None
        elif isinstance(value, str):
            if os.path.exists(value):
                self.settings['certificate_path'] = value
            else:
                raise exceptions.ConfigurationError(
                    "The certificate path value, if specified, must be a "
                    "valid string path to a certificate file."
                )
        else:
            raise exceptions.ConfigurationError(
                "The certificate path value, if specified, must be a valid "
                "string path to a certificate file."
            )

    def _set_key_path(self, value):
        if value is None:
            self.settings['key_path'] = None
        elif isinstance(value, str):
            if os.path.exists(value):
                self.settings['key_path'] = value
            else:
                raise exceptions.ConfigurationError(
                    "The key path value, if specified, must be a valid string "
                    "path to a certificate key file."
                )
        else:
            raise exceptions.ConfigurationError(
                "The key path value, if specified, must be a valid string "
                "path to a certificate key file."
            )

    def _set_ca_path(self, value):
        if value is None:
            self.settings['ca_path'] = None
        elif isinstance(value, str):
            if os.path.exists(value):
                self.settings['ca_path'] = value
            else:
                raise exceptions.ConfigurationError(
                    "The certificate authority (CA) path value, if "
                    "specified, must be a valid string path to a CA "
                    "certificate file."
                )
        else:
            raise exceptions.ConfigurationError(
                "The certificate authority (CA) path value, if specified, "
                "must be a valid string path to a CA certificate file."
            )

    def _set_auth_suite(self, value):
        auth_suites = ['Basic', 'TLS1.2']
        if value not in auth_suites:
            raise exceptions.ConfigurationError(
                "The authentication suite must be one of the "
                "following: Basic, TLS1.2"
            )
        else:
            self.settings['auth_suite'] = value

    def _set_policy_path(self, value):
        if not value:
            self.settings['policy_path'] = None
        elif isinstance(value, str):
            self.settings['policy_path'] = value
        else:
            raise exceptions.ConfigurationError(
                "The policy path, if specified, must be a valid string path "
                "to a filesystem directory."
            )

    def _set_enable_tls_client_auth(self, value):
        if value is None:
            self.settings['enable_tls_client_auth'] = True
        elif isinstance(value, bool):
            self.settings['enable_tls_client_auth'] = value
        else:
            raise exceptions.ConfigurationError(
                "The flag enabling the TLS certificate client auth flag check "
                "must be a boolean."
            )

    def _set_tls_cipher_suites(self, value):
        if not value:
            self.settings['tls_cipher_suites'] = []
            return
        if isinstance(value, str):
            value = value.split()

        if isinstance(value, list):
            for entry in value:
                if not isinstance(entry, str):
                    raise exceptions.ConfigurationError(
                        "The TLS cipher suites must be a set of strings "
                        "representing cipher suite names."
                    )
            self.settings['tls_cipher_suites'] = list(set(value))
        else:
            raise exceptions.ConfigurationError(
                "The TLS cipher suites must be a set of strings representing "
                "cipher suite names."
            )

    def _set_logging_level(self, value):
        if value is None:
            self.settings['logging_level'] = logging.INFO
            return

        logging_levels = {
            "DEBUG":    logging.DEBUG,
            "INFO":     logging.INFO,
            "WARNING":  logging.WARNING,
            "ERROR":    logging.ERROR,
            "CRITICAL": logging.CRITICAL
        }
        if value in logging_levels.values():
            self.settings['logging_level'] = value
        elif isinstance(value, str):
            level = logging_levels.get(value.upper())
            if level:
                self.settings['logging_level'] = level
            else:
                raise exceptions.ConfigurationError(
                    "The logging level must be a string representing a valid "
                    "logging level."
                )
        else:
            raise exceptions.ConfigurationError(
                "The logging level must be a string representing a valid "
                "logging level."
            )

    def _set_database_path(self, value):
        if not value:
            self.settings['database_path'] = None
        elif isinstance(value, str):
            self.settings['database_path'] = value
        else:
            raise exceptions.ConfigurationError(
                "The database path, if specified, must be a valid path to a "
                "SQLite database file."
            )
