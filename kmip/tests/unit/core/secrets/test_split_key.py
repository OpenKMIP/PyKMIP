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
from kmip.core import exceptions
from kmip.core import misc
from kmip.core import objects
from kmip.core import primitives
from kmip.core import secrets
from kmip.core import utils

class TestSplitKey(testtools.TestCase):
    """
    Test suite for the SplitKey secret object.
    """

    def setUp(self):
        super(TestSplitKey, self).setUp()

        # This encoding was adapted from test case TC-SJ-2-20 from the KMIP
        # 2.0 test suite. The Prime Field Size was manually added.
        #
        # This encoding matches the following set of values:
        # SplitKey
        #     Split Key Parts - 4
        #     Key Part Identifier - 1
        #     Split Key Threshold - 2
        #     Split Key Method - Polynomial Sharing GF 2^8
        #     Prime Field Size - 104729
        #     Key Block
        #         Key Format Type - Raw
        #         Key Value
        #             Key Material - 0x66C46A7754F94DE420C7B1A7FFF5EC56
        #         Cryptographic Algorithm - AES
        #         Cryptographic Length - 128
        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x89\x01\x00\x00\x00\xA8'
            b'\x42\x00\x8B\x02\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00'
            b'\x42\x00\x44\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x8C\x02\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x8A\x05\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00'
            b'\x42\x00\x62\x04\x00\x00\x00\x08\x00\x00\x00\x00\x00\x01\x99\x19'
            b'\x42\x00\x40\x01\x00\x00\x00\x50'
            b'\x42\x00\x42\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x45\x01\x00\x00\x00\x18'
            b'\x42\x00\x43\x08\x00\x00\x00\x10'
            b'\x66\xC4\x6A\x77\x54\xF9\x4D\xE4\x20\xC7\xB1\xA7\xFF\xF5\xEC\x56'
            b'\x42\x00\x28\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x2A\x02\x00\x00\x00\x04\x00\x00\x00\x80\x00\x00\x00\x00'
        )

        # This encoding was adapted from test case TC-SJ-2-20 from the KMIP
        # 2.0 test suite.
        #
        # This encoding matches the following set of values:
        # SplitKey
        #     Key Part Identifier - 1
        self.no_split_key_parts_encoding = utils.BytearrayStream(
            b'\x42\x00\x89\x01\x00\x00\x00\x10'
            b'\x42\x00\x44\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
        )

        # This encoding was adapted from test case TC-SJ-2-20 from the KMIP
        # 2.0 test suite.
        #
        # This encoding matches the following set of values:
        # SplitKey
        #     Split Key Parts - 4
        self.no_key_part_identifier_encoding = utils.BytearrayStream(
            b'\x42\x00\x89\x01\x00\x00\x00\x10'
            b'\x42\x00\x8B\x02\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00'
        )

        # This encoding was adapted from test case TC-SJ-2-20 from the KMIP
        # 2.0 test suite.
        #
        # This encoding matches the following set of values:
        # SplitKey
        #     Split Key Parts - 4
        #     Key Part Identifier - 1
        self.no_split_key_threshold_encoding = utils.BytearrayStream(
            b'\x42\x00\x89\x01\x00\x00\x00\x20'
            b'\x42\x00\x8B\x02\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00'
            b'\x42\x00\x44\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
        )

        # This encoding was adapted from test case TC-SJ-2-20 from the KMIP
        # 2.0 test suite.
        #
        # This encoding matches the following set of values:
        # SplitKey
        #     Split Key Parts - 4
        #     Key Part Identifier - 1
        #     Split Key Threshold - 2
        self.no_split_key_method_encoding = utils.BytearrayStream(
            b'\x42\x00\x89\x01\x00\x00\x00\x30'
            b'\x42\x00\x8B\x02\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00'
            b'\x42\x00\x44\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x8C\x02\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
        )

        # This encoding was adapted from test case TC-SJ-2-20 from the KMIP
        # 2.0 test suite.
        #
        # This encoding matches the following set of values:
        # SplitKey
        #     Split Key Parts - 4
        #     Key Part Identifier - 1
        #     Split Key Threshold - 2
        #     Split Key Method - Polynomial Sharing Prime Field
        self.no_prime_field_size_encoding = utils.BytearrayStream(
            b'\x42\x00\x89\x01\x00\x00\x00\x40'
            b'\x42\x00\x8B\x02\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00'
            b'\x42\x00\x44\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x8C\x02\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x8A\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
        )

        # This encoding was adapted from test case TC-SJ-2-20 from the KMIP
        # 2.0 test suite.
        #
        # This encoding matches the following set of values:
        # SplitKey
        #     Split Key Parts - 4
        #     Key Part Identifier - 1
        #     Split Key Threshold - 2
        #     Split Key Method - Polynomial Sharing GF 2^8
        self.no_key_block_encoding = utils.BytearrayStream(
            b'\x42\x00\x89\x01\x00\x00\x00\x40'
            b'\x42\x00\x8B\x02\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00'
            b'\x42\x00\x44\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x8C\x02\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x8A\x05\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestSplitKey, self).tearDown()

    def test_invalid_split_key_parts(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the split key parts of a SplitKey object.
        """
        kwargs = {"split_key_parts": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The split key parts must be an integer.",
            secrets.SplitKey,
            **kwargs
        )

        args = (
            secrets.SplitKey(),
            "split_key_parts",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The split key parts must be an integer.",
            setattr,
            *args
        )

    def test_invalid_key_part_identifier(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the key part identifier of a SplitKey object.
        """
        kwargs = {"key_part_identifier": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The key part identifier must be an integer.",
            secrets.SplitKey,
            **kwargs
        )

        args = (
            secrets.SplitKey(),
            "key_part_identifier",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The key part identifier must be an integer.",
            setattr,
            *args
        )

    def test_invalid_split_key_threshold(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the split key threshold of a SplitKey object.
        """
        kwargs = {"split_key_threshold": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The split key threshold must be an integer.",
            secrets.SplitKey,
            **kwargs
        )

        args = (
            secrets.SplitKey(),
            "split_key_threshold",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The split key threshold must be an integer.",
            setattr,
            *args
        )

    def test_invalid_split_key_method(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the split key method of a SplitKey object.
        """
        kwargs = {"split_key_method": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The split key method must be a SplitKeyMethod enumeration.",
            secrets.SplitKey,
            **kwargs
        )

        args = (
            secrets.SplitKey(),
            "split_key_method",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The split key method must be a SplitKeyMethod enumeration.",
            setattr,
            *args
        )

    def test_invalid_prime_field_size(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the prime field size of a SplitKey object.
        """
        kwargs = {"prime_field_size": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The prime field size must be an integer.",
            secrets.SplitKey,
            **kwargs
        )

        args = (
            secrets.SplitKey(),
            "prime_field_size",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The prime field size must be an integer.",
            setattr,
            *args
        )

    def test_invalid_key_block(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the key block of a SplitKey object.
        """
        kwargs = {"key_block": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The key block must be a KeyBlock structure.",
            secrets.SplitKey,
            **kwargs
        )

        args = (
            secrets.SplitKey(),
            "key_block",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The key block must be a KeyBlock structure.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a SplitKey object can be read from a buffer.
        """
        split_key = secrets.SplitKey()

        self.assertIsNone(split_key.split_key_parts)
        self.assertIsNone(split_key.key_part_identifier)
        self.assertIsNone(split_key.split_key_threshold)
        self.assertIsNone(split_key.split_key_method)
        self.assertIsNone(split_key.prime_field_size)
        self.assertIsNone(split_key.key_block)

        split_key.read(self.full_encoding)

        self.assertEqual(4, split_key.split_key_parts)
        self.assertEqual(1, split_key.key_part_identifier)
        self.assertEqual(2, split_key.split_key_threshold)
        self.assertEqual(
            enums.SplitKeyMethod.POLYNOMIAL_SHARING_GF_2_8,
            split_key.split_key_method
        )
        self.assertEqual(104729, split_key.prime_field_size)
        self.assertIsInstance(split_key.key_block, objects.KeyBlock)
        self.assertEqual(
            enums.KeyFormatType.RAW,
            split_key.key_block.key_format_type.value
        )
        self.assertIsInstance(split_key.key_block.key_value, objects.KeyValue)
        self.assertIsInstance(
            split_key.key_block.key_value.key_material,
            primitives.ByteString
        )
        self.assertEqual(
            (
                b'\x66\xC4\x6A\x77\x54\xF9\x4D\xE4'
                b'\x20\xC7\xB1\xA7\xFF\xF5\xEC\x56'
            ),
            split_key.key_block.key_value.key_material.value
        )
        self.assertEqual(
            enums.CryptographicAlgorithm.AES,
            split_key.key_block.cryptographic_algorithm.value
        )
        self.assertEqual(128, split_key.key_block.cryptographic_length.value)

    def test_read_missing_split_key_parts(self):
        """
        Test that an InvalidKmipEncoding error is raised during the decoding
        of a SplitKey object when the split key parts are missing from the
        encoding.
        """
        split_key = secrets.SplitKey()

        self.assertIsNone(split_key.split_key_parts)

        args = (self.no_split_key_parts_encoding, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The SplitKey encoding is missing the SplitKeyParts field.",
            split_key.read,
            *args
        )

    def test_read_missing_key_part_identifier(self):
        """
        Test that an InvalidKmipEncoding error is raised during the decoding
        of a SplitKey object when the key part identifier is missing from the
        encoding.
        """
        split_key = secrets.SplitKey()

        self.assertIsNone(split_key.key_part_identifier)

        args = (self.no_key_part_identifier_encoding, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The SplitKey encoding is missing the KeyPartIdentifier field.",
            split_key.read,
            *args
        )

    def test_read_missing_split_key_threshold(self):
        """
        Test that an InvalidKmipEncoding error is raised during the decoding
        of a SplitKey object when the split key threshold is missing from the
        encoding.
        """
        split_key = secrets.SplitKey()

        self.assertIsNone(split_key.split_key_threshold)

        args = (self.no_split_key_threshold_encoding, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The SplitKey encoding is missing the SplitKeyThreshold field.",
            split_key.read,
            *args
        )

    def test_read_missing_split_key_method(self):
        """
        Test that an InvalidKmipEncoding error is raised during the decoding
        of a SplitKey object when the split key method is missing from the
        encoding.
        """
        split_key = secrets.SplitKey()

        self.assertIsNone(split_key.split_key_method)

        args = (self.no_split_key_method_encoding, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The SplitKey encoding is missing the SplitKeyMethod field.",
            split_key.read,
            *args
        )

    def test_read_missing_prime_field_size(self):
        """
        Test that an InvalidKmipEncoding error is raised during the decoding
        of a SplitKey object when the prime field size is missing from the
        encoding.
        """
        split_key = secrets.SplitKey()

        self.assertIsNone(split_key.prime_field_size)

        args = (self.no_prime_field_size_encoding, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The SplitKey encoding is missing the PrimeFieldSize "
            "field. This field is required when the SplitKeyMethod is "
            "PolynomialSharingPrimeField.",
            split_key.read,
            *args
        )

    def test_read_missing_key_block(self):
        """
        Test that an InvalidKmipEncoding error is raised during the decoding
        of a SplitKey object when the key block is missing from the encoding.
        """
        split_key = secrets.SplitKey()

        self.assertIsNone(split_key.key_block)

        args = (self.no_key_block_encoding, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The SplitKey encoding is missing the KeyBlock field.",
            split_key.read,
            *args
        )

    def test_write(self):
        """
        Test that a SplitKey object can be written to a buffer.
        """
        # TODO (peter-hamilton) Update this test when the KeyBlock supports
        # generic key format type and key value/material values.
        key_block = objects.KeyBlock(
            key_format_type=misc.KeyFormatType(enums.KeyFormatType.RAW),
            key_value=objects.KeyValue(
                key_material=objects.KeyMaterial(
                    value=(
                        b'\x66\xC4\x6A\x77\x54\xF9\x4D\xE4'
                        b'\x20\xC7\xB1\xA7\xFF\xF5\xEC\x56'
                    )
                )
            ),
            cryptographic_algorithm=primitives.Enumeration(
                enums.CryptographicAlgorithm,
                value=enums.CryptographicAlgorithm.AES,
                tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
            ),
            cryptographic_length=primitives.Integer(
                value=128,
                tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
            )
        )
        split_key = secrets.SplitKey(
            split_key_parts=4,
            key_part_identifier=1,
            split_key_threshold=2,
            split_key_method=enums.SplitKeyMethod.POLYNOMIAL_SHARING_GF_2_8,
            prime_field_size=104729,
            key_block=key_block
        )

        stream = utils.BytearrayStream()
        split_key.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_missing_split_key_parts(self):
        """
        Test that an InvalidField error is raised during the encoding of a
        SplitKey object when the object is missing the split key parts field.
        """
        split_key = secrets.SplitKey(key_part_identifier=1)

        stream = utils.BytearrayStream()
        args = (stream, )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The SplitKey object is missing the SplitKeyParts field.",
            split_key.write,
            *args
        )

    def test_write_missing_key_part_identifier(self):
        """
        Test that an InvalidField error is raised during the encoding of a
        SplitKey object when the object is missing the key part identifier
        field.
        """
        split_key = secrets.SplitKey(split_key_parts=4)

        stream = utils.BytearrayStream()
        args = (stream, )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The SplitKey object is missing the KeyPartIdentifier field.",
            split_key.write,
            *args
        )

    def test_write_missing_split_key_threshold(self):
        """
        Test that an InvalidField error is raised during the encoding of a
        SplitKey object when the object is missing the split key threshold
        field.
        """
        split_key = secrets.SplitKey(
            split_key_parts=4,
            key_part_identifier=1
        )

        stream = utils.BytearrayStream()
        args = (stream, )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The SplitKey object is missing the SplitKeyThreshold field.",
            split_key.write,
            *args
        )

    def test_write_missing_split_key_method(self):
        """
        Test that an InvalidField error is raised during the encoding of a
        SplitKey object when the object is missing the split key method field.
        """
        split_key = secrets.SplitKey(
            split_key_parts=4,
            key_part_identifier=1,
            split_key_threshold=2
        )

        stream = utils.BytearrayStream()
        args = (stream, )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The SplitKey object is missing the SplitKeyMethod field.",
            split_key.write,
            *args
        )

    def test_write_missing_prime_field_size(self):
        """
        Test that an InvalidField error is raised during the encoding of a
        SplitKey object when the object is missing the prime field size field.
        """
        split_key_method = enums.SplitKeyMethod.POLYNOMIAL_SHARING_PRIME_FIELD
        split_key = secrets.SplitKey(
            split_key_parts=4,
            key_part_identifier=1,
            split_key_threshold=2,
            split_key_method=split_key_method
        )

        stream = utils.BytearrayStream()
        args = (stream, )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The SplitKey object is missing the PrimeFieldSize field. "
            "This field is required when the SplitKeyMethod is "
            "PolynomialSharingPrimeField.",
            split_key.write,
            *args
        )

    def test_write_missing_key_block(self):
        """
        Test that an InvalidField error is raised during the encoding of a
        SplitKey object when the object is missing the key block field.
        """
        split_key = secrets.SplitKey(
            split_key_parts=4,
            key_part_identifier=1,
            split_key_threshold=2,
            split_key_method=enums.SplitKeyMethod.POLYNOMIAL_SHARING_GF_2_8
        )

        stream = utils.BytearrayStream()
        args = (stream, )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The SplitKey object is missing the KeyBlock field.",
            split_key.write,
            *args
        )

    def test_repr(self):
        """
        Test that repr can be applied to a SplitKey object.
        """
        key_block = objects.KeyBlock(
            key_format_type=misc.KeyFormatType(enums.KeyFormatType.RAW),
            key_value=objects.KeyValue(
                key_material=objects.KeyMaterial(
                    value=(
                        b'\x66\xC4\x6A\x77\x54\xF9\x4D\xE4'
                        b'\x20\xC7\xB1\xA7\xFF\xF5\xEC\x56'
                    )
                )
            ),
            cryptographic_algorithm=primitives.Enumeration(
                enums.CryptographicAlgorithm,
                value=enums.CryptographicAlgorithm.AES,
                tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
            ),
            cryptographic_length=primitives.Integer(
                value=128,
                tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
            )
        )
        split_key = secrets.SplitKey(
            split_key_parts=4,
            key_part_identifier=1,
            split_key_threshold=2,
            split_key_method=enums.SplitKeyMethod.POLYNOMIAL_SHARING_GF_2_8,
            prime_field_size=104729,
            key_block=key_block
        )

        args = [
            "split_key_parts=4",
            "key_part_identifier=1",
            "split_key_threshold=2",
            "split_key_method=SplitKeyMethod.POLYNOMIAL_SHARING_GF_2_8",
            "prime_field_size=104729",
            "key_block=Struct()"
        ]
        self.assertEqual(
            "SplitKey({})".format(", ".join(args)),
            repr(split_key)
        )

    def test_str(self):
        """
        Test that str can be applied to a SplitKey object.
        """
        key_block = objects.KeyBlock(
            key_format_type=misc.KeyFormatType(enums.KeyFormatType.RAW),
            key_value=objects.KeyValue(
                key_material=objects.KeyMaterial(
                    value=(
                        b'\x66\xC4\x6A\x77\x54\xF9\x4D\xE4'
                        b'\x20\xC7\xB1\xA7\xFF\xF5\xEC\x56'
                    )
                )
            ),
            cryptographic_algorithm=primitives.Enumeration(
                enums.CryptographicAlgorithm,
                value=enums.CryptographicAlgorithm.AES,
                tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
            ),
            cryptographic_length=primitives.Integer(
                value=128,
                tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
            )
        )
        split_key = secrets.SplitKey(
            split_key_parts=4,
            key_part_identifier=1,
            split_key_threshold=2,
            split_key_method=enums.SplitKeyMethod.POLYNOMIAL_SHARING_GF_2_8,
            prime_field_size=104729,
            key_block=key_block
        )

        args = [
            ("split_key_parts", 4),
            ("key_part_identifier", 1),
            ("split_key_threshold", 2),
            (
                "split_key_method",
                enums.SplitKeyMethod.POLYNOMIAL_SHARING_GF_2_8
            ),
            ("prime_field_size", 104729),
            ("key_block", str(key_block))
        ]
        value = "{}".format(
            ", ".join(['"{}": {}'.format(arg[0], arg[1]) for arg in args])
        )
        self.assertEqual(
            "{" + value + "}",
            str(split_key)
        )

    def test_comparison(self):
        """
        Test that the equality/inequality operators return True/False when
        comparing two SplitKey objects with the same data.
        """
        a = secrets.SplitKey()
        b = secrets.SplitKey()

        self.assertTrue(a == b)
        self.assertTrue(b == a)
        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = secrets.SplitKey(
            split_key_parts=4,
            key_part_identifier=1,
            split_key_threshold=2,
            split_key_method=enums.SplitKeyMethod.POLYNOMIAL_SHARING_GF_2_8,
            prime_field_size=104729,
            key_block=objects.KeyBlock(
                key_format_type=misc.KeyFormatType(enums.KeyFormatType.RAW),
                key_value=objects.KeyValue(
                    key_material=objects.KeyMaterial(
                        value=(
                            b'\x66\xC4\x6A\x77\x54\xF9\x4D\xE4'
                            b'\x20\xC7\xB1\xA7\xFF\xF5\xEC\x56'
                        )
                    )
                ),
                cryptographic_algorithm=primitives.Enumeration(
                    enums.CryptographicAlgorithm,
                    value=enums.CryptographicAlgorithm.AES,
                    tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                ),
                cryptographic_length=primitives.Integer(
                    value=128,
                    tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                )
            )
        )
        b = secrets.SplitKey(
            split_key_parts=4,
            key_part_identifier=1,
            split_key_threshold=2,
            split_key_method=enums.SplitKeyMethod.POLYNOMIAL_SHARING_GF_2_8,
            prime_field_size=104729,
            key_block=objects.KeyBlock(
                key_format_type=misc.KeyFormatType(enums.KeyFormatType.RAW),
                key_value=objects.KeyValue(
                    key_material=objects.KeyMaterial(
                        value=(
                            b'\x66\xC4\x6A\x77\x54\xF9\x4D\xE4'
                            b'\x20\xC7\xB1\xA7\xFF\xF5\xEC\x56'
                        )
                    )
                ),
                cryptographic_algorithm=primitives.Enumeration(
                    enums.CryptographicAlgorithm,
                    value=enums.CryptographicAlgorithm.AES,
                    tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                ),
                cryptographic_length=primitives.Integer(
                    value=128,
                    tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                )
            )
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)
        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_comparison_on_different_split_key_parts(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing two SplitKey objects with different split key parts.
        """
        a = secrets.SplitKey(split_key_parts=4)
        b = secrets.SplitKey(split_key_parts=6)

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_comparison_on_different_key_part_identifiers(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing two SplitKey objects with different key part identifiers.
        """
        a = secrets.SplitKey(key_part_identifier=1)
        b = secrets.SplitKey(key_part_identifier=2)

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_comparison_on_different_split_key_thresholds(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing two SplitKey objects with different split key thresholds.
        """
        a = secrets.SplitKey(split_key_threshold=3)
        b = secrets.SplitKey(split_key_threshold=4)

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_comparison_on_different_split_key_methods(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing two SplitKey objects with different split key methods.
        """
        a = secrets.SplitKey(split_key_method=enums.SplitKeyMethod.XOR)
        b = secrets.SplitKey(
            split_key_method=enums.SplitKeyMethod.POLYNOMIAL_SHARING_GF_2_8
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_comparison_on_different_prime_field_sizes(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing two SplitKey objects with different prime field sizes.
        """
        a = secrets.SplitKey(prime_field_size=104723)
        b = secrets.SplitKey(prime_field_size=104729)

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    # TODO (peter-hamilton) Fill in this test once the KeyBlock supports the
    # comparison operators.
    def test_comparison_on_different_key_blocks(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing two SplitKey objects with different key blocks.
        """
        self.skipTest(
            "The KeyBlock structure does not support the comparison operators."
        )

    def test_comparison_on_type_mismatch(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing two SplitKey objects with different types.
        """
        a = secrets.SplitKey()
        b = "invalid"

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)
