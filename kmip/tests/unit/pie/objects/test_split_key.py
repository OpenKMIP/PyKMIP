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

import binascii
import testtools
import sqlalchemy

from kmip.core import enums

from kmip.pie import objects
from kmip.pie import sqltypes

class TestSplitKey(testtools.TestCase):
    """
    Test suite for SplitKey.
    """

    def setUp(self):
        super(TestSplitKey, self).setUp()

        self.engine = sqlalchemy.create_engine("sqlite:///:memory:", echo=True)
        sqltypes.Base.metadata.create_all(self.engine)

    def tearDown(self):
        super(TestSplitKey, self).tearDown()

    def test_init(self):
        """
        Test that a SplitKey object can be instantiated.
        """
        split_key = objects.SplitKey()

        self.assertIsNone(split_key.cryptographic_algorithm)
        self.assertIsNone(split_key.cryptographic_length)
        self.assertIsNone(split_key.value)
        self.assertEqual(split_key.key_format_type, enums.KeyFormatType.RAW)
        self.assertEqual(split_key.cryptographic_usage_masks, [])
        self.assertEqual(split_key.names, ["Split Key"])
        self.assertIsNone(split_key.split_key_parts)
        self.assertIsNone(split_key.key_part_identifier)
        self.assertIsNone(split_key.split_key_threshold)
        self.assertIsNone(split_key.split_key_method)
        self.assertIsNone(split_key.prime_field_size)

    def test_init_with_args(self):
        """
        Test that a SplitKey object can be instantiated with all arguments.
        """
        split_key = objects.SplitKey(
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
            cryptographic_length=128,
            key_value=(
                b'\x66\xC4\x6A\x77\x54\xF9\x4D\xE4'
                b'\x20\xC7\xB1\xA7\xFF\xF5\xEC\x56'
            ),
            key_format_type=enums.KeyFormatType.RAW,
            cryptographic_usage_masks=[
                enums.CryptographicUsageMask.EXPORT
            ],
            name="Test Split Key",
            split_key_parts=4,
            key_part_identifier=1,
            split_key_threshold=2,
            split_key_method=enums.SplitKeyMethod.POLYNOMIAL_SHARING_GF_2_8,
            prime_field_size=104729
        )

        self.assertEqual(
            split_key.cryptographic_algorithm,
            enums.CryptographicAlgorithm.AES
        )
        self.assertEqual(split_key.cryptographic_length, 128)
        self.assertEqual(
            split_key.value,
            b'\x66\xC4\x6A\x77\x54\xF9\x4D\xE4\x20\xC7\xB1\xA7\xFF\xF5\xEC\x56'
        )
        self.assertEqual(split_key.key_format_type, enums.KeyFormatType.RAW)
        self.assertEqual(
            split_key.cryptographic_usage_masks,
            [enums.CryptographicUsageMask.EXPORT]
        )
        self.assertEqual(split_key.names, ["Test Split Key"])
        self.assertEqual(split_key.split_key_parts, 4)
        self.assertEqual(split_key.key_part_identifier, 1)
        self.assertEqual(split_key.split_key_threshold, 2)
        self.assertEqual(
            split_key.split_key_method,
            enums.SplitKeyMethod.POLYNOMIAL_SHARING_GF_2_8
        )
        self.assertEqual(split_key.prime_field_size, 104729)

    def test_invalid_split_key_parts(self):
        """
        Test that a TypeError is raised when an invalid split key parts value
        is used to construct a SplitKey.
        """
        kwargs = {"split_key_parts": "invalid"}

        self.assertRaisesRegex(
            TypeError,
            "The split key parts must be an integer.",
            objects.SplitKey,
            **kwargs
        )

        args = (
            objects.SplitKey(),
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
        Test that a TypeError is raised when an invalid key part identifier
        value is used to construct a SplitKey.
        """
        kwargs = {"key_part_identifier": "invalid"}

        self.assertRaisesRegex(
            TypeError,
            "The key part identifier must be an integer.",
            objects.SplitKey,
            **kwargs
        )

        args = (
            objects.SplitKey(),
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
        Test that a TypeError is raised when an invalid split key threshold
        value is used to construct a SplitKey.
        """
        kwargs = {"split_key_threshold": "invalid"}

        self.assertRaisesRegex(
            TypeError,
            "The split key threshold must be an integer.",
            objects.SplitKey,
            **kwargs
        )

        args = (
            objects.SplitKey(),
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
        Test that a TypeError is raised when an invalid split key method value
        is used to construct a SplitKey.
        """
        kwargs = {"split_key_method": "invalid"}

        self.assertRaisesRegex(
            TypeError,
            "The split key method must be a SplitKeyMethod enumeration.",
            objects.SplitKey,
            **kwargs
        )

        args = (
            objects.SplitKey(),
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
        Test that a TypeError is raised when an invalid prime field size value
        is used to construct a SplitKey.
        """
        kwargs = {"prime_field_size": "invalid"}

        self.assertRaisesRegex(
            TypeError,
            "The prime field size must be an integer.",
            objects.SplitKey,
            **kwargs
        )

        args = (
            objects.SplitKey(),
            "prime_field_size",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The prime field size must be an integer.",
            setattr,
            *args
        )

    def test_repr(self):
        """
        Test that repr can be applied to a SplitKey.
        """
        split_key = objects.SplitKey(
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
            cryptographic_length=128,
            key_value=(
                b'\x66\xC4\x6A\x77\x54\xF9\x4D\xE4'
                b'\x20\xC7\xB1\xA7\xFF\xF5\xEC\x56'
            ),
            key_format_type=enums.KeyFormatType.RAW,
            cryptographic_usage_masks=[
                enums.CryptographicUsageMask.EXPORT
            ],
            name="Test Split Key",
            split_key_parts=4,
            key_part_identifier=1,
            split_key_threshold=2,
            split_key_method=enums.SplitKeyMethod.POLYNOMIAL_SHARING_GF_2_8,
            prime_field_size=104729
        )

        args = [
            "cryptographic_algorithm={}".format(
                enums.CryptographicAlgorithm.AES
            ),
            "cryptographic_length={}".format(128),
            "key_value={}".format(
                binascii.hexlify(
                    b'\x66\xC4\x6A\x77\x54\xF9\x4D\xE4'
                    b'\x20\xC7\xB1\xA7\xFF\xF5\xEC\x56'
                )
            ),
            "key_format_type={}".format(enums.KeyFormatType.RAW),
            "key_wrapping_data={}".format({}),
            "cryptographic_usage_masks={}".format(
                [enums.CryptographicUsageMask.EXPORT]
            ),
            "name={}".format(["Test Split Key"]),
            "split_key_parts=4",
            "key_part_identifier=1",
            "split_key_threshold=2",
            "split_key_method={}".format(
                enums.SplitKeyMethod.POLYNOMIAL_SHARING_GF_2_8
            ),
            "prime_field_size=104729"
        ]

        expected = "SplitKey({})".format(", ".join(args))
        observed = repr(split_key)

        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a SplitKey.
        """
        split_key = objects.SplitKey(
            key_value=(
                b'\x66\xC4\x6A\x77\x54\xF9\x4D\xE4'
                b'\x20\xC7\xB1\xA7\xFF\xF5\xEC\x56'
            )
        )

        expected = str(binascii.hexlify(split_key.value))
        observed = str(split_key)

        self.assertEqual(expected, observed)

    def test_comparison_on_equal(self):
        """
        Test that the equality/inequality operators return True/False when
        comparing two SplitKey objects with the same data.
        """
        a = objects.SplitKey()
        b = objects.SplitKey()

        self.assertTrue(a == b)
        self.assertTrue(b == a)
        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = objects.SplitKey(
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
            cryptographic_length=128,
            key_value=(
                b'\x66\xC4\x6A\x77\x54\xF9\x4D\xE4'
                b'\x20\xC7\xB1\xA7\xFF\xF5\xEC\x56'
            ),
            key_format_type=enums.KeyFormatType.RAW,
            cryptographic_usage_masks=[
                enums.CryptographicUsageMask.EXPORT
            ],
            name="Test Split Key",
            split_key_parts=4,
            key_part_identifier=1,
            split_key_threshold=2,
            split_key_method=enums.SplitKeyMethod.POLYNOMIAL_SHARING_GF_2_8,
            prime_field_size=104729
        )
        b = objects.SplitKey(
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
            cryptographic_length=128,
            key_value=(
                b'\x66\xC4\x6A\x77\x54\xF9\x4D\xE4'
                b'\x20\xC7\xB1\xA7\xFF\xF5\xEC\x56'
            ),
            key_format_type=enums.KeyFormatType.RAW,
            cryptographic_usage_masks=[
                enums.CryptographicUsageMask.EXPORT
            ],
            name="Test Split Key",
            split_key_parts=4,
            key_part_identifier=1,
            split_key_threshold=2,
            split_key_method=enums.SplitKeyMethod.POLYNOMIAL_SHARING_GF_2_8,
            prime_field_size=104729
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)
        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_comparison_on_different_cryptographic_algorithms(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing two SplitKey objects with different cryptographic algorithms.
        """
        a = objects.SplitKey(
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES
        )
        b = objects.SplitKey(
            cryptographic_algorithm=enums.CryptographicAlgorithm.RSA
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_comparison_on_different_cryptographic_lengths(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing two SplitKey objects with different cryptographic lengths.
        """
        a = objects.SplitKey(cryptographic_length=128)
        b = objects.SplitKey(cryptographic_length=256)

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_comparison_on_different_values(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing two SplitKey objects with different values.
        """
        a = objects.SplitKey(key_value=b'\x00')
        b = objects.SplitKey(key_value=b'\xFF')

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_comparison_on_different_key_format_types(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing two SplitKey objects with different key format types.
        """
        a = objects.SplitKey(key_format_type=enums.KeyFormatType.RAW)
        b = objects.SplitKey(key_format_type=enums.KeyFormatType.OPAQUE)

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_comparison_on_different_key_wrapping_data(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing two SplitKey objects with different key wrapping data.
        """
        a = objects.SplitKey(key_wrapping_data={})
        b = objects.SplitKey(
            key_wrapping_data={"wrapping_method": enums.WrappingMethod.ENCRYPT}
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_comparison_on_different_cryptographic_usage_masks(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing two SplitKey objects with different cryptographic usage
        masks.
        """
        a = objects.SplitKey(
            cryptographic_usage_masks=[enums.CryptographicUsageMask.ENCRYPT]
        )
        b = objects.SplitKey(
            cryptographic_usage_masks=[enums.CryptographicUsageMask.EXPORT]
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_comparison_on_different_names(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing two SplitKey objects with different names.
        """
        a = objects.SplitKey(name="Test Split Key")
        b = objects.SplitKey(name="Split Key Test")

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_comparison_on_different_split_key_parts(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing two SplitKey objects with different split key parts.
        """
        a = objects.SplitKey(split_key_parts=4)
        b = objects.SplitKey(split_key_parts=5)

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_comparison_on_different_key_part_identifiers(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing two SplitKey objects with different key part identifiers.
        """
        a = objects.SplitKey(key_part_identifier=1)
        b = objects.SplitKey(key_part_identifier=2)

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_comparison_on_different_split_key_thresholds(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing two SplitKey objects with different split key thresholds.
        """
        a = objects.SplitKey(split_key_threshold=1)
        b = objects.SplitKey(split_key_threshold=2)

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_comparison_on_different_split_key_methods(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing two SplitKey objects with different split key methods.
        """
        a = objects.SplitKey(split_key_method=enums.SplitKeyMethod.XOR)
        b = objects.SplitKey(
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
        a = objects.SplitKey(prime_field_size=13)
        b = objects.SplitKey(prime_field_size=104729)

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_comparison_on_type_mismatch(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing a SplitKey object to a non-SplitKey object.
        """
        a = objects.SplitKey()
        b = "invalid"

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_save(self):
        """
        Test that a SplitKey object can be saved using SQLAlchemy. This will
        add it to the database, verify that no exceptions are thrown, and check
        that its unique identifier was set.
        """
        split_key = objects.SplitKey(
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
            cryptographic_length=128,
            key_value=(
                b'\x66\xC4\x6A\x77\x54\xF9\x4D\xE4'
                b'\x20\xC7\xB1\xA7\xFF\xF5\xEC\x56'
            ),
            key_format_type=enums.KeyFormatType.RAW,
            cryptographic_usage_masks=[
                enums.CryptographicUsageMask.EXPORT
            ],
            name="Test Split Key",
            split_key_parts=4,
            key_part_identifier=1,
            split_key_threshold=2,
            split_key_method=enums.SplitKeyMethod.POLYNOMIAL_SHARING_GF_2_8,
            prime_field_size=104729
        )

        session = sqlalchemy.orm.sessionmaker(bind=self.engine)()
        session.add(split_key)
        session.commit()

        self.assertIsNotNone(split_key.unique_identifier)

    def test_get(self):
        """
        Test that a SplitKey object can be saved and then retrieved using
        SQLAlchemy. This test adds the object to the database and then
        retrieves it by ID and verifies some of the attributes.
        """
        split_key = objects.SplitKey(
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
            cryptographic_length=128,
            key_value=(
                b'\x66\xC4\x6A\x77\x54\xF9\x4D\xE4'
                b'\x20\xC7\xB1\xA7\xFF\xF5\xEC\x56'
            ),
            key_format_type=enums.KeyFormatType.RAW,
            cryptographic_usage_masks=[
                enums.CryptographicUsageMask.EXPORT
            ],
            name="Test Split Key",
            split_key_parts=4,
            key_part_identifier=1,
            split_key_threshold=2,
            split_key_method=enums.SplitKeyMethod.POLYNOMIAL_SHARING_GF_2_8,
            prime_field_size=104729
        )

        session = sqlalchemy.orm.sessionmaker(
            bind=self.engine, expire_on_commit=False)()
        session.add(split_key)
        session.commit()

        session = sqlalchemy.orm.sessionmaker(bind=self.engine)()
        retrieved_key = session.query(objects.SplitKey).filter(
            objects.ManagedObject.unique_identifier ==
            split_key.unique_identifier
        ).one()
        session.commit()

        self.assertEqual(retrieved_key.names, ["Test Split Key"])
        self.assertEqual(
            retrieved_key.cryptographic_algorithm,
            enums.CryptographicAlgorithm.AES
        )
        self.assertEqual(retrieved_key.cryptographic_length, 128)
        self.assertEqual(
            retrieved_key.value,
            (
                b'\x66\xC4\x6A\x77\x54\xF9\x4D\xE4'
                b'\x20\xC7\xB1\xA7\xFF\xF5\xEC\x56'
            )
        )
        self.assertEqual(
            retrieved_key.key_format_type,
            enums.KeyFormatType.RAW
        )
        self.assertEqual(
            retrieved_key.cryptographic_usage_masks,
            [enums.CryptographicUsageMask.EXPORT]
        )
        self.assertEqual(retrieved_key.split_key_parts, 4)
        self.assertEqual(retrieved_key.key_part_identifier, 1)
        self.assertEqual(retrieved_key.split_key_threshold, 2)
        self.assertEqual(
            retrieved_key.split_key_method,
            enums.SplitKeyMethod.POLYNOMIAL_SHARING_GF_2_8
        )
        self.assertEqual(retrieved_key.prime_field_size, 104729)
