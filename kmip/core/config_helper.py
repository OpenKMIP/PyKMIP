# Copyright (c) 2014 The Johns Hopkins University/Applied Physics Laboratory
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
from configparser import ConfigParser
FILE_PATH = os.path.dirname(os.path.abspath(__file__))

# TODO (peter-hamilton): Remove support for kmipconfig.ini on future release.
CONFIG_FILE = [
    os.path.join(os.path.expanduser('~'), '.pykmip', 'pykmip.conf'),
    os.path.join(os.sep, 'etc', 'pykmip', 'pykmip.conf'),
    os.path.normpath(os.path.join(FILE_PATH, '../pykmip.conf')),
    os.path.normpath(os.path.join(FILE_PATH, '../kmipconfig.ini'))]

class ConfigHelper(object):
    NONE_VALUE = 'None'
    DEFAULT_HOST = "127.0.0.1"
    DEFAULT_PORT = 5696
    DEFAULT_CERTFILE = os.path.normpath(os.path.join(
        FILE_PATH, '../demos/certs/server.crt'))
    DEFAULT_KEYFILE = os.path.normpath(os.path.join(
        FILE_PATH, '../demos/certs/server.key'))
    DEFAULT_CA_CERTS = os.path.normpath(os.path.join(
        FILE_PATH, '../demos/certs/server.crt'))
    DEFAULT_SSL_VERSION = 'PROTOCOL_SSLv23'
    DEFAULT_USERNAME = None
    DEFAULT_PASSWORD = None

    # Timeout measured in seconds
    DEFAULT_TIMEOUT = 30

    def __init__(self, path=None):
        self.logger = logging.getLogger(__name__)
        # DEBUG logging here may expose passwords, so log at INFO by default.
        # However, if consumers know the risks, let them go ahead and override.
        if self.logger.level == logging.NOTSET:
            self.logger.setLevel(logging.INFO)

        self.conf = ConfigParser()

        filenames = path
        if not path:
            filenames = CONFIG_FILE

        if self.conf.read(filenames):
            self.logger.debug("Using config file at {0}".format(filenames))
        else:
            self.logger.warning(
                "Config file {0} not found".format(filenames))

    def get_valid_value(self, direct_value, config_section,
                        config_option_name, default_value):
        """Returns a value that can be used as a parameter in client or
        server. If a direct_value is given, that value will be returned
        instead of the value from the config file. If the appropriate config
        file option is not found, the default_value is returned.

        :param direct_value: represents a direct value that should be used.
                             supercedes values from config files
        :param config_section: which section of the config file to use
        :param config_option_name: name of config option value
        :param default_value: default value to be used if other options not
                              found
        :returns: a value that can be used as a parameter
        """
        ARG_MSG = "Using given value '{0}' for {1}"
        CONF_MSG = "Using value '{0}' from configuration file {1} for {2}"
        DEFAULT_MSG = "Using default value '{0}' for {1}"
        if direct_value:
            return_value = direct_value
            self.logger.debug(ARG_MSG.format(direct_value, config_option_name))
        else:
            try:
                return_value = self.conf.get(config_section,
                                             config_option_name)
                self.logger.debug(CONF_MSG.format(return_value,
                                                  CONFIG_FILE,
                                                  config_option_name))
            except Exception:
                return_value = default_value
                self.logger.debug(DEFAULT_MSG.format(default_value,
                                                     config_option_name))
        # TODO (peter-hamilton): Think about adding better value validation
        if return_value == self.NONE_VALUE:
            return None
        else:
            return return_value
