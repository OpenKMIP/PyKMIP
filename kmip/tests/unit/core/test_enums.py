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

class TestOrderedEnum(testtools.TestCase):

    def setUp(self):
        super(TestOrderedEnum, self).setUp()

    def tearDown(self):
        super(TestOrderedEnum, self).tearDown()

    def test_greater_than_or_equal(self):
        self.assertTrue(
            enums.KMIPVersion.KMIP_2_0 >= enums.KMIPVersion.KMIP_1_0
        )
        self.assertFalse(
            enums.KMIPVersion.KMIP_1_0 >= enums.KMIPVersion.KMIP_2_0
        )

        self.assertEqual(
            NotImplemented,
            enums.KMIPVersion.KMIP_2_0.__ge__(enums.WrappingMethod.ENCRYPT)
        )

    def test_greater_than(self):
        self.assertTrue(
            enums.KMIPVersion.KMIP_1_3 > enums.KMIPVersion.KMIP_1_1
        )
        self.assertFalse(
            enums.KMIPVersion.KMIP_1_1 > enums.KMIPVersion.KMIP_1_3
        )

        self.assertEqual(
            NotImplemented,
            enums.KMIPVersion.KMIP_2_0.__gt__(enums.WrappingMethod.ENCRYPT)
        )

    def test_less_than_or_equal(self):
        self.assertTrue(
            enums.KMIPVersion.KMIP_1_3 <= enums.KMIPVersion.KMIP_1_4
        )
        self.assertFalse(
            enums.KMIPVersion.KMIP_1_4 <= enums.KMIPVersion.KMIP_1_3
        )

        self.assertEqual(
            NotImplemented,
            enums.KMIPVersion.KMIP_2_0.__le__(enums.WrappingMethod.ENCRYPT)
        )

    def test_less_than(self):
        self.assertTrue(
            enums.KMIPVersion.KMIP_1_3 < enums.KMIPVersion.KMIP_2_0
        )
        self.assertFalse(
            enums.KMIPVersion.KMIP_2_0 < enums.KMIPVersion.KMIP_1_3
        )

        self.assertEqual(
            NotImplemented,
            enums.KMIPVersion.KMIP_2_0.__lt__(enums.WrappingMethod.ENCRYPT)
        )

class TestEnumUtilityFunctions(testtools.TestCase):

    def setUp(self):
        super(TestEnumUtilityFunctions, self).setUp()

    def tearDown(self):
        super(TestEnumUtilityFunctions, self).tearDown()

    def test_get_bit_mask_from_enumerations(self):
        self.assertEqual(
            7,
            enums.get_bit_mask_from_enumerations(
                [
                    enums.StorageStatusMask.ARCHIVAL_STORAGE,
                    enums.StorageStatusMask.DESTROYED_STORAGE,
                    enums.StorageStatusMask.ONLINE_STORAGE
                ]
            )
        )

    def test_get_enumerations_from_bit_mask(self):
        expected = [
                enums.StorageStatusMask.ARCHIVAL_STORAGE,
                enums.StorageStatusMask.DESTROYED_STORAGE,
                enums.StorageStatusMask.ONLINE_STORAGE
        ]
        observed = enums.get_enumerations_from_bit_mask(
            enums.StorageStatusMask,
            7
        )

        self.assertEqual(len(expected), len(observed))
        for x in expected:
            self.assertIn(x, observed)

    def test_is_bit_mask(self):
        self.assertTrue(
            enums.is_bit_mask(
                enums.StorageStatusMask,
                enums.StorageStatusMask.ARCHIVAL_STORAGE.value |
                enums.StorageStatusMask.ONLINE_STORAGE.value
            )
        )

        self.assertFalse(
            enums.is_bit_mask(
                enums.StorageStatusMask,
                enums.StorageStatusMask.DESTROYED_STORAGE
            )
        )

        self.assertFalse(
            enums.is_bit_mask(
                enums.WrappingMethod,
                enums.WrappingMethod.ENCRYPT.value
            )
        )

        self.assertFalse(
            enums.is_bit_mask(
                enums.ProtectionStorageMask,
                0x80000000
            )
        )

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

    def test_convert_attribute_name_to_tag(self):
        self.assertEqual(
            enums.Tags.OBJECT_TYPE,
            enums.convert_attribute_name_to_tag("Object Type")
        )

        args = (enums.Tags.COMMON_ATTRIBUTES, )
        self.assertRaisesRegex(
            ValueError,
            "The attribute name must be a string.",
            enums.convert_attribute_name_to_tag,
            *args
        )

        args = ("invalid", )
        self.assertRaisesRegex(
            ValueError,
            "Unrecognized attribute name: 'invalid'",
            enums.convert_attribute_name_to_tag,
            *args
        )

    def test_convert_attribute_name_to_tag_case_and_whitespace(self):
        args = ("object type", )
        self.assertRaisesRegex(
            ValueError,
            "Unrecognized attribute name: 'object type'",
            enums.convert_attribute_name_to_tag,
            *args
        )

        args = (" Object Type ", )
        self.assertRaisesRegex(
            ValueError,
            "Unrecognized attribute name: ' Object Type '",
            enums.convert_attribute_name_to_tag,
            *args
        )

    def test_convert_attribute_tag_to_name(self):
        self.assertEqual(
            "Always Sensitive",
            enums.convert_attribute_tag_to_name(enums.Tags.ALWAYS_SENSITIVE)
        )

        args = ("invalid", )
        self.assertRaisesRegex(
            ValueError,
            "The attribute tag must be a Tags enumeration.",
            enums.convert_attribute_tag_to_name,
            *args
        )

        args = (enums.Tags.COMMON_ATTRIBUTES, )
        self.assertRaisesRegex(
            ValueError,
            "Unrecognized attribute tag: {}".format(args[0]),
            enums.convert_attribute_tag_to_name,
            *args
        )

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
