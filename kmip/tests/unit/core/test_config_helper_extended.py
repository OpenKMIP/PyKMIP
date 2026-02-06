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
import tempfile

try:
    import configparser
except ImportError:
    import ConfigParser as configparser

import mock
import testtools

from kmip.core import config_helper
from kmip.core.config_helper import ConfigHelper


class TestConfigHelperExtended(testtools.TestCase):
    def test_config_helper_init_default(self):
        mock_conf = mock.MagicMock()
        mock_conf.read.return_value = ["dummy"]

        with mock.patch("kmip.core.config_helper.ConfigParser",
                        return_value=mock_conf):
            ConfigHelper()

        mock_conf.read.assert_called_with(config_helper.CONFIG_FILE)

    def test_config_helper_init_with_path(self):
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.addCleanup(os.remove, temp_file.name)
        temp_file.write(b"[client]\nhost=example.com\n")
        temp_file.close()

        helper = ConfigHelper(temp_file.name)
        value = helper.get_valid_value(None, "client", "host", "default")
        self.assertEqual("example.com", value)

    def test_config_helper_missing_file(self):
        mock_conf = mock.MagicMock()
        mock_conf.read.return_value = []
        mock_logger = mock.MagicMock()
        mock_logger.level = logging.NOTSET

        with mock.patch("kmip.core.config_helper.logging.getLogger",
                        return_value=mock_logger):
            with mock.patch("kmip.core.config_helper.ConfigParser",
                            return_value=mock_conf):
                ConfigHelper()

        self.assertTrue(mock_logger.warning.called)

    def test_get_valid_value_direct(self):
        helper = ConfigHelper()
        helper.conf = mock.MagicMock()
        value = helper.get_valid_value("direct", "client", "host", "default")
        self.assertEqual("direct", value)
        self.assertFalse(helper.conf.get.called)

    def test_get_valid_value_empty_string_uses_config(self):
        helper = ConfigHelper()
        helper.conf = mock.MagicMock()
        helper.conf.get.return_value = "conf_value"
        value = helper.get_valid_value("", "client", "host", "default")
        helper.conf.get.assert_called_once_with("client", "host")
        self.assertEqual("conf_value", value)

    def test_get_valid_value_zero_uses_config(self):
        helper = ConfigHelper()
        helper.conf = mock.MagicMock()
        helper.conf.get.return_value = "conf_value"
        value = helper.get_valid_value(0, "client", "port", "default")
        helper.conf.get.assert_called_once_with("client", "port")
        self.assertEqual("conf_value", value)

    def test_get_valid_value_from_config(self):
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.addCleanup(os.remove, temp_file.name)
        temp_file.write(b"[client]\nport=5696\n")
        temp_file.close()

        helper = ConfigHelper(temp_file.name)
        value = helper.get_valid_value(None, "client", "port", "default")
        self.assertEqual("5696", value)

    def test_get_valid_value_default_fallback(self):
        helper = ConfigHelper()
        helper.conf = mock.MagicMock()
        helper.conf.get.side_effect = configparser.NoSectionError("missing")
        value = helper.get_valid_value(None, "missing", "option", "fallback")
        self.assertEqual("fallback", value)

    def test_get_valid_value_none_section(self):
        helper = ConfigHelper()
        helper.conf = mock.MagicMock()
        helper.conf.get.side_effect = configparser.NoSectionError("missing")
        value = helper.get_valid_value(None, None, None, "fallback")
        self.assertEqual("fallback", value)
