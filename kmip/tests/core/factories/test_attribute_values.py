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

from testtools import TestCase

from kmip.core.enums import AttributeType
from kmip.core.attributes import OperationPolicyName
from kmip.core.factories.attribute_values import AttributeValueFactory


class TestAttributeValueFactory(TestCase):

    def setUp(self):
        super(TestAttributeValueFactory, self).setUp()
        self.factory = AttributeValueFactory()

    def tearDown(self):
        super(TestAttributeValueFactory, self).tearDown()

    # TODO (peter-hamilton) Consider even further modularity
    def _test_operation_policy_name(self, opn, value):
        if value is None:
            value = ''

        msg = "expected {0}, received {1}".format(OperationPolicyName, opn)
        self.assertIsInstance(opn, OperationPolicyName, msg)

        msg = "expected {0}, received {1}".format(value, opn.value)
        self.assertEqual(value, opn.value, msg)

    def _test_create_attribute_value_operation_policy_name(self, value):
        opn = self.factory.create_attribute_value(
            AttributeType.OPERATION_POLICY_NAME, value)
        self._test_operation_policy_name(opn, value)

    def _test_create_operation_policy_name(self, value):
        opn = self.factory._create_operation_policy_name(value)
        self._test_operation_policy_name(opn, value)

    def test_create_attribute_value_operation_policy_name(self):
        self._test_create_attribute_value_operation_policy_name('test')

    def test_create_attribute_value_operation_policy_name_on_none(self):
        self._test_create_attribute_value_operation_policy_name(None)

    def test_create_operation_policy_name(self):
        self._test_create_operation_policy_name('test')

    def test_create_operation_policy_name_on_none(self):
        self._test_create_operation_policy_name(None)
