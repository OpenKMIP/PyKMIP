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

import testtools

from kmip.core import enums
from kmip.pie import sqltypes


class TestSqlTypesExtended(testtools.TestCase):
    def test_enum_type_process_bind(self):
        enum_type = sqltypes.EnumType(enums.NameType)
        self.assertEqual(
            enums.NameType.URI.value,
            enum_type.process_bind_param(enums.NameType.URI, None)
        )
        self.assertEqual(-1, enum_type.process_bind_param(None, None))

    def test_enum_type_process_result(self):
        enum_type = sqltypes.EnumType(enums.NameType)
        self.assertIsNone(enum_type.process_result_value(-1, None))
        self.assertEqual(
            enums.NameType.URI,
            enum_type.process_result_value(enums.NameType.URI.value, None)
        )

    def test_usage_mask_type_roundtrip(self):
        usage_type = sqltypes.UsageMaskType()
        masks = [
            enums.CryptographicUsageMask.ENCRYPT,
            enums.CryptographicUsageMask.DECRYPT
        ]
        bitmask = usage_type.process_bind_param(masks, None)
        result_masks = usage_type.process_result_value(bitmask, None)
        self.assertEqual(set(masks), set(result_masks))

        empty_mask = usage_type.process_bind_param([], None)
        self.assertEqual([], usage_type.process_result_value(empty_mask, None))
