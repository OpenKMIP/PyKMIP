# Copyright (c) 2019 The Johns Hopkins University/Applied Physics Laboratory
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

import testtools

from kmip.core import enums


class TestEnumUtilityFunctions(testtools.TestCase):

    def setUp(self):
        super(TestEnumUtilityFunctions, self).setUp()

    def tearDown(self):
        super(TestEnumUtilityFunctions, self).tearDown()

    def test_is_enum_value(self):
        result = enums.is_enum_value(
            enums.CryptographicAlgorithm,
            enums.CryptographicAlgorithm.AES
        )
        self.assertTrue(result)

        result = enums.is_enum_value(
            enums.WrappingMethod,
            'invalid'
        )
        self.assertFalse(result)

    def test_is_attribute(self):
        # Test an attribute introduced in KMIP 1.0
        result = enums.is_attribute(enums.Tags.UNIQUE_IDENTIFIER)
        self.assertTrue(result)

        # Test an attribute introduced in KMIP 1.1
        result = enums.is_attribute(enums.Tags.FRESH)
        self.assertTrue(result)

        # Test an attribute introduced in KMIP 1.2
        result = enums.is_attribute(enums.Tags.KEY_VALUE_PRESENT)
        self.assertTrue(result)

        # Test an attribute introduced in KMIP 1.3
        result = enums.is_attribute(enums.Tags.RANDOM_NUMBER_GENERATOR)
        self.assertTrue(result)

        # Test an attribute introduced in KMIP 1.4
        result = enums.is_attribute(enums.Tags.COMMENT)
        self.assertTrue(result)

        # Test an attribute introduced in KMIP 2.0
        result = enums.is_attribute(enums.Tags.QUANTUM_SAFE)
        self.assertTrue(result)

    def test_is_attribute_added_in_kmip_1_0(self):
        result = enums.is_attribute(
            enums.Tags.UNIQUE_IDENTIFIER,
            enums.KMIPVersion.KMIP_1_0
        )
        self.assertTrue(result)

        result = enums.is_attribute(
            enums.Tags.UNIQUE_IDENTIFIER,
            enums.KMIPVersion.KMIP_1_1
        )
        self.assertTrue(result)

        result = enums.is_attribute(
            enums.Tags.UNIQUE_IDENTIFIER,
            enums.KMIPVersion.KMIP_1_2
        )
        self.assertTrue(result)

        result = enums.is_attribute(
            enums.Tags.UNIQUE_IDENTIFIER,
            enums.KMIPVersion.KMIP_1_3
        )
        self.assertTrue(result)

        result = enums.is_attribute(
            enums.Tags.UNIQUE_IDENTIFIER,
            enums.KMIPVersion.KMIP_1_4
        )
        self.assertTrue(result)

        result = enums.is_attribute(
            enums.Tags.UNIQUE_IDENTIFIER,
            enums.KMIPVersion.KMIP_2_0
        )
        self.assertTrue(result)

    def test_is_attribute_added_in_kmip_1_1(self):
        result = enums.is_attribute(
            enums.Tags.FRESH,
            enums.KMIPVersion.KMIP_1_0
        )
        self.assertFalse(result)

        result = enums.is_attribute(
            enums.Tags.FRESH,
            enums.KMIPVersion.KMIP_1_1
        )
        self.assertTrue(result)

        result = enums.is_attribute(
            enums.Tags.FRESH,
            enums.KMIPVersion.KMIP_1_2
        )
        self.assertTrue(result)

        result = enums.is_attribute(
            enums.Tags.FRESH,
            enums.KMIPVersion.KMIP_1_3
        )
        self.assertTrue(result)

        result = enums.is_attribute(
            enums.Tags.FRESH,
            enums.KMIPVersion.KMIP_1_4
        )
        self.assertTrue(result)

        result = enums.is_attribute(
            enums.Tags.FRESH,
            enums.KMIPVersion.KMIP_2_0
        )
        self.assertTrue(result)

    def test_is_attribute_added_in_kmip_1_2(self):
        result = enums.is_attribute(
            enums.Tags.KEY_VALUE_PRESENT,
            enums.KMIPVersion.KMIP_1_0
        )
        self.assertFalse(result)

        result = enums.is_attribute(
            enums.Tags.KEY_VALUE_PRESENT,
            enums.KMIPVersion.KMIP_1_1
        )
        self.assertFalse(result)

        result = enums.is_attribute(
            enums.Tags.KEY_VALUE_PRESENT,
            enums.KMIPVersion.KMIP_1_2
        )
        self.assertTrue(result)

        result = enums.is_attribute(
            enums.Tags.KEY_VALUE_PRESENT,
            enums.KMIPVersion.KMIP_1_3
        )
        self.assertTrue(result)

        result = enums.is_attribute(
            enums.Tags.KEY_VALUE_PRESENT,
            enums.KMIPVersion.KMIP_1_4
        )
        self.assertTrue(result)

        result = enums.is_attribute(
            enums.Tags.KEY_VALUE_PRESENT,
            enums.KMIPVersion.KMIP_2_0
        )
        self.assertTrue(result)

    def test_is_attribute_added_in_kmip_1_3(self):
        result = enums.is_attribute(
            enums.Tags.RANDOM_NUMBER_GENERATOR,
            enums.KMIPVersion.KMIP_1_0
        )
        self.assertFalse(result)

        result = enums.is_attribute(
            enums.Tags.RANDOM_NUMBER_GENERATOR,
            enums.KMIPVersion.KMIP_1_1
        )
        self.assertFalse(result)

        result = enums.is_attribute(
            enums.Tags.RANDOM_NUMBER_GENERATOR,
            enums.KMIPVersion.KMIP_1_2
        )
        self.assertFalse(result)

        result = enums.is_attribute(
            enums.Tags.RANDOM_NUMBER_GENERATOR,
            enums.KMIPVersion.KMIP_1_3
        )
        self.assertTrue(result)

        result = enums.is_attribute(
            enums.Tags.RANDOM_NUMBER_GENERATOR,
            enums.KMIPVersion.KMIP_1_4
        )
        self.assertTrue(result)

        result = enums.is_attribute(
            enums.Tags.RANDOM_NUMBER_GENERATOR,
            enums.KMIPVersion.KMIP_2_0
        )
        self.assertTrue(result)

    def test_is_attribute_added_in_kmip_1_4(self):
        result = enums.is_attribute(
            enums.Tags.COMMENT,
            enums.KMIPVersion.KMIP_1_0
        )
        self.assertFalse(result)

        result = enums.is_attribute(
            enums.Tags.COMMENT,
            enums.KMIPVersion.KMIP_1_1
        )
        self.assertFalse(result)

        result = enums.is_attribute(
            enums.Tags.COMMENT,
            enums.KMIPVersion.KMIP_1_2
        )
        self.assertFalse(result)

        result = enums.is_attribute(
            enums.Tags.COMMENT,
            enums.KMIPVersion.KMIP_1_3
        )
        self.assertFalse(result)

        result = enums.is_attribute(
            enums.Tags.COMMENT,
            enums.KMIPVersion.KMIP_1_4
        )
        self.assertTrue(result)

        result = enums.is_attribute(
            enums.Tags.COMMENT,
            enums.KMIPVersion.KMIP_2_0
        )
        self.assertTrue(result)

    def test_is_attribute_added_in_kmip_2_0(self):
        result = enums.is_attribute(
            enums.Tags.QUANTUM_SAFE,
            enums.KMIPVersion.KMIP_1_0
        )
        self.assertFalse(result)

        result = enums.is_attribute(
            enums.Tags.QUANTUM_SAFE,
            enums.KMIPVersion.KMIP_1_1
        )
        self.assertFalse(result)

        result = enums.is_attribute(
            enums.Tags.QUANTUM_SAFE,
            enums.KMIPVersion.KMIP_1_2
        )
        self.assertFalse(result)

        result = enums.is_attribute(
            enums.Tags.QUANTUM_SAFE,
            enums.KMIPVersion.KMIP_1_3
        )
        self.assertFalse(result)

        result = enums.is_attribute(
            enums.Tags.QUANTUM_SAFE,
            enums.KMIPVersion.KMIP_1_4
        )
        self.assertFalse(result)

        result = enums.is_attribute(
            enums.Tags.QUANTUM_SAFE,
            enums.KMIPVersion.KMIP_2_0
        )
        self.assertTrue(result)

    def test_is_attribute_removed_in_kmip_2_0(self):
        result = enums.is_attribute(
            enums.Tags.CUSTOM_ATTRIBUTE,
            enums.KMIPVersion.KMIP_1_0
        )
        self.assertTrue(result)

        result = enums.is_attribute(
            enums.Tags.CUSTOM_ATTRIBUTE,
            enums.KMIPVersion.KMIP_1_1
        )
        self.assertTrue(result)

        result = enums.is_attribute(
            enums.Tags.CUSTOM_ATTRIBUTE,
            enums.KMIPVersion.KMIP_1_2
        )
        self.assertTrue(result)

        result = enums.is_attribute(
            enums.Tags.CUSTOM_ATTRIBUTE,
            enums.KMIPVersion.KMIP_1_3
        )
        self.assertTrue(result)

        result = enums.is_attribute(
            enums.Tags.CUSTOM_ATTRIBUTE,
            enums.KMIPVersion.KMIP_1_4
        )
        self.assertTrue(result)

        result = enums.is_attribute(
            enums.Tags.CUSTOM_ATTRIBUTE,
            enums.KMIPVersion.KMIP_2_0
        )
        self.assertFalse(result)
