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
from kmip.core.enums import BlockCipherMode
from kmip.core.enums import HashingAlgorithm
from kmip.core.enums import PaddingMethod
from kmip.core.enums import KeyRoleType
from kmip.core.enums import Tags

from kmip.core import attributes
from kmip.core.attributes import CryptographicParameters
from kmip.core.attributes import OperationPolicyName

from kmip.core.primitives import DateTime

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

    def _test_cryptograpic_parameters(self, obj, block_cipher_mode,
                                      padding_method, key_role_type,
                                      hashing_algorithm):
        msg = "expected {0}, received {1}"
        self.assertIsInstance(obj, CryptographicParameters, msg.format(
            CryptographicParameters, obj.__class__))

        self.assertEqual(block_cipher_mode, obj.block_cipher_mode, msg.format(
            block_cipher_mode, obj.block_cipher_mode))

        self.assertEqual(padding_method, obj.padding_method, msg.format(
            padding_method, obj.padding_method))

        self.assertEqual(key_role_type, obj.key_role_type, msg.format(
            key_role_type, obj.hashing_algorithm))

        self.assertEqual(hashing_algorithm, obj.hashing_algorithm, msg.format(
            hashing_algorithm, obj.hashing_algorithm))

    def test_create_cryptograpic_parameters_none(self):
        cp = self.factory.create_attribute_value(
            AttributeType.CRYPTOGRAPHIC_PARAMETERS,
            {})
        self._test_cryptograpic_parameters(cp, None, None, None, None)

    def test_create_cryptograpic_parameters_block_cipher_mode(self):
        cp = self.factory.create_attribute_value(
            AttributeType.CRYPTOGRAPHIC_PARAMETERS,
            {'block_cipher_mode': BlockCipherMode.NIST_KEY_WRAP})

        self._test_cryptograpic_parameters(
            cp, CryptographicParameters.BlockCipherMode(
                BlockCipherMode.NIST_KEY_WRAP),
            None, None, None)

    def test_create_cryptograpic_parameters_padding_method(self):
        cp = self.factory.create_attribute_value(
            AttributeType.CRYPTOGRAPHIC_PARAMETERS,
            {'padding_method': PaddingMethod.ANSI_X9_23})

        # noqa - E128 continuation line under-indented for visual indent
        self._test_cryptograpic_parameters(cp, None,
            CryptographicParameters.PaddingMethod(PaddingMethod.ANSI_X9_23),
            None, None)  # noqa

    def test_create_cryptograpic_parameters_key_role_type(self):
        cp = self.factory.create_attribute_value(
            AttributeType.CRYPTOGRAPHIC_PARAMETERS,
            {'key_role_type': KeyRoleType.KEK})

        # noqa - E128 continuation line under-indented for visual indent
        self._test_cryptograpic_parameters(cp, None, None,
            CryptographicParameters.KeyRoleType(KeyRoleType.KEK),
            None)  # noqa

    def test_create_cryptograpic_parameters_hashing_algorithm(self):
        cp = self.factory.create_attribute_value(
            AttributeType.CRYPTOGRAPHIC_PARAMETERS,
            {'hashing_algorithm': HashingAlgorithm.SHA_512})

        # noqa - E128 continuation line under-indented for visual indent
        self._test_cryptograpic_parameters(cp, None, None, None,
            attributes.HashingAlgorithm(HashingAlgorithm.SHA_512))  # noqa

    def _test_date_value(self, date, value, tag):
        msg = "expected {0}, received {1}"
        self.assertIsInstance(date, DateTime, msg.format(
            DateTime, date.__class__))

        self.assertEqual(date.value, value, msg.format(value, date.value))
        self.assertEqual(date.tag, tag, msg.format(tag, date.tag))

    def test_create_initial_date(self):
        date = self.factory.create_attribute_value(
            AttributeType.INITIAL_DATE, 0)
        self._test_date_value(date, 0, Tags.INITIAL_DATE)

    def test_create_activation_date(self):
        date = self.factory.create_attribute_value(
            AttributeType.ACTIVATION_DATE, 0)
        self._test_date_value(date, 0, Tags.ACTIVATION_DATE)

    def test_create_process_start_date(self):
        date = self.factory.create_attribute_value(
            AttributeType.PROCESS_START_DATE, 0)
        self._test_date_value(date, 0, Tags.PROCESS_START_DATE)

    def test_create_protect_stop_date(self):
        date = self.factory.create_attribute_value(
            AttributeType.PROTECT_STOP_DATE, 0)
        self._test_date_value(date, 0, Tags.PROTECT_STOP_DATE)

    def test_create_deactivation_date(self):
        date = self.factory.create_attribute_value(
            AttributeType.DEACTIVATION_DATE, 0)
        self._test_date_value(date, 0, Tags.DEACTIVATION_DATE)

    def test_create_destroy_date(self):
        date = self.factory.create_attribute_value(
            AttributeType.DESTROY_DATE, 0)
        self._test_date_value(date, 0, Tags.DESTROY_DATE)

    def test_create_compromise_occurance_date(self):
        date = self.factory.create_attribute_value(
            AttributeType.COMPROMISE_OCCURRENCE_DATE, 0)
        self._test_date_value(date, 0, Tags.COMPROMISE_OCCURRENCE_DATE)

    def test_create_compromise_date(self):
        date = self.factory.create_attribute_value(
            AttributeType.COMPROMISE_DATE, 0)
        self._test_date_value(date, 0, Tags.COMPROMISE_DATE)

    def test_create_archive_date(self):
        date = self.factory.create_attribute_value(
            AttributeType.ARCHIVE_DATE, 0)
        self._test_date_value(date, 0, Tags.ARCHIVE_DATE)
