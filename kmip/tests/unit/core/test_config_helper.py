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

try:
    import configparser
except ImportError:
    import ConfigParser as configparser

from testtools import TestCase
from mock import MagicMock
from mock import Mock

from kmip.core.config_helper import ConfigHelper

class TestConfigHelper(TestCase):

    def setUp(self):
        def side_effect(arg1, arg2):
            if arg1 == 'conf_test_section' and arg2 == 'conf_test_option':
                return 'conf_test_value'
            elif arg1 == 'conf_test_section' and arg2 == 'conf_null_option':
                return ConfigHelper.NONE_VALUE
            else:
                raise configparser.NoSectionError
        super(TestConfigHelper, self).setUp()
        self.config_helper = ConfigHelper()
        self.config_helper.conf = MagicMock()
        self.config_helper.conf.get = Mock(side_effect=side_effect)

    def tearDown(self):
        super(TestConfigHelper, self).tearDown()

    def test_get_valid_value_null_input(self):
        value = self.config_helper.get_valid_value(None, None, None, None)
        self.assertEqual(None, value)

    def test_get_valid_value_direct_value_is_none(self):
        value = self.config_helper.get_valid_value(ConfigHelper.NONE_VALUE,
                                                   'conf_test_section',
                                                   'conf_test_option',
                                                   'test_default_option')
        self.assertFalse(self.config_helper.conf.get.called)
        self.assertEqual(None, value)

    def test_get_valid_value_config_value_is_none(self):
        value = self.config_helper.get_valid_value(None,
                                                   'conf_test_section',
                                                   'conf_null_option',
                                                   'test_default_option')
        self.assertTrue(self.config_helper.conf.get.called)
        self.config_helper.conf.get.assert_called_with('conf_test_section',
                                                       'conf_null_option')
        self.assertEqual(None, value)

    def test_get_valid_value_returns_direct(self):
        value = self.config_helper.get_valid_value('test_direct_value',
                                                   'conf_test_section',
                                                   'conf_test_option',
                                                   'test_default_value')
        self.assertFalse(self.config_helper.conf.get.called)
        self.assertEqual('test_direct_value', value)

    def test_get_valid_value_returns_conf_value(self):
        value = self.config_helper.get_valid_value(None,
                                                   'conf_test_section',
                                                   'conf_test_option',
                                                   'test_default_value')
        self.assertTrue(self.config_helper.conf.get.called)
        self.config_helper.conf.get.assert_called_with('conf_test_section',
                                                       'conf_test_option')
        self.assertEqual(value, 'conf_test_value')

    def test_get_valid_value_returns_default(self):
        value = self.config_helper.get_valid_value(None,
                                                   'invalid_section',
                                                   'invalid_option',
                                                   'test_default_value')
        self.assertTrue(self.config_helper.conf.get.called)
        self.config_helper.conf.get.assert_called_with('invalid_section',
                                                       'invalid_option')
        self.assertEqual(value, 'test_default_value')
