# Copyright (c) 2015 The Johns Hopkins University/Applied Physics Laboratory
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

from kmip.core import exceptions
from kmip.core import primitives
from kmip.core import utils

class TestLongInteger(testtools.TestCase):
    """
    Test suite for the LongInteger primitive.
    """

    def setUp(self):
        super(TestLongInteger, self).setUp()

    def tearDown(self):
        super(TestLongInteger, self).tearDown()

    def test_init(self):
        """
        Test that a LongInteger can be instantiated.
        """
        long_int = primitives.LongInteger(1)
        self.assertEqual(1, long_int.value)

    def test_init_unset(self):
        """
        Test that a LongInteger can be instantiated with no input.
        """
        long_int = primitives.LongInteger()
        self.assertEqual(0, long_int.value)

    def test_init_on_max(self):
        """
        Test that a LongInteger can be instantiated with the maximum possible
        signed 64-bit value.
        """
        primitives.LongInteger(primitives.LongInteger.MAX)

    def test_init_on_min(self):
        """
        Test that a LongInteger can be instantiated with the minimum possible
        signed 64-bit value.
        """
        primitives.LongInteger(primitives.LongInteger.MIN)

    def test_validate_on_valid(self):
        """
        Test that a LongInteger can be validated on good input.
        """
        long_int = primitives.LongInteger(1)
        long_int.validate()

    def test_validate_on_valid_unset(self):
        """
        Test that a LongInteger with no preset value can be validated.
        """
        long_int = primitives.LongInteger()
        long_int.validate()

    def test_validate_on_invalid_type(self):
        """
        Test that a TypeError is thrown on input of invalid type (e.g., str).
        """
        self.assertRaises(TypeError, primitives.LongInteger, 'invalid')

    def test_validate_on_invalid_value_too_big(self):
        """
        Test that a ValueError is thrown on input that is too large.
        """
        self.assertRaises(
            ValueError, primitives.LongInteger, primitives.LongInteger.MAX + 1)

    def test_validate_on_invalid_value_too_small(self):
        """
        Test that a ValueError is thrown on input that is too small.
        """
        self.assertRaises(
            ValueError, primitives.LongInteger, primitives.LongInteger.MIN - 1)

    def test_read_zero(self):
        """
        Test that a LongInteger representing the value 0 can be read from a
        byte stream.
        """
        encoding = (
            b'\x42\x00\x00\x03\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00'
            b'\x00')
        stream = utils.BytearrayStream(encoding)
        long_int = primitives.LongInteger()
        long_int.read(stream)
        self.assertEqual(0, long_int.value)

    def test_read_max_max(self):
        """
        Test that a LongInteger representing the maximum positive value can be
        read from a byte stream.
        """
        encoding = (
            b'\x42\x00\x00\x03\x00\x00\x00\x08\x7f\xff\xff\xff\xff\xff\xff'
            b'\xff')
        stream = utils.BytearrayStream(encoding)
        long_int = primitives.LongInteger()
        long_int.read(stream)
        self.assertEqual(primitives.LongInteger.MAX, long_int.value)

    def test_read_min_max(self):
        """
        Test that a LongInteger representing the minimum positive value can be
        read from a byte stream.
        """
        encoding = (
            b'\x42\x00\x00\x03\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00'
            b'\x01')
        stream = utils.BytearrayStream(encoding)
        long_int = primitives.LongInteger()
        long_int.read(stream)
        self.assertEqual(1, long_int.value)

    def test_read_max_min(self):
        """
        Test that a LongInteger representing the maximum negative value can be
        read from a byte stream.
        """
        encoding = (
            b'\x42\x00\x00\x03\x00\x00\x00\x08\xff\xff\xff\xff\xff\xff\xff'
            b'\xff')
        stream = utils.BytearrayStream(encoding)
        long_int = primitives.LongInteger()
        long_int.read(stream)
        self.assertEqual(-1, long_int.value)

    def test_read_min_min(self):
        """
        Test that a LongInteger representing the minimum negative value can be
        read from a byte stream.
        """
        encoding = (
            b'\x42\x00\x00\x03\x00\x00\x00\x08\x80\x00\x00\x00\x00\x00\x00'
            b'\x00')
        stream = utils.BytearrayStream(encoding)
        long_int = primitives.LongInteger(primitives.LongInteger.MIN)
        long_int.read(stream)
        self.assertEqual(primitives.LongInteger.MIN, long_int.value)

    def test_read_on_invalid_length(self):
        """
        Test that an InvalidPrimitiveLength exception is thrown when attempting
        to decode a LongInteger with an invalid length.
        """
        encoding = (
            b'\x42\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00')
        stream = utils.BytearrayStream(encoding)
        long_int = primitives.LongInteger()

        self.assertRaises(
            exceptions.InvalidPrimitiveLength, long_int.read, stream)

    def test_write_zero(self):
        """
        Test that a LongInteger representing the value 0 can be written to a
        byte stream.
        """
        encoding = (
            b'\x42\x00\x00\x03\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00'
            b'\x00')
        stream = utils.BytearrayStream()
        long_int = primitives.LongInteger(0)
        long_int.write(stream)

        result = stream.read()
        self.assertEqual(len(encoding), len(result))
        self.assertEqual(encoding, result)

    def test_write_max_max(self):
        """
        Test that a LongInteger representing the maximum positive value can be
        written to a byte stream.
        """
        encoding = (
            b'\x42\x00\x00\x03\x00\x00\x00\x08\x7f\xff\xff\xff\xff\xff\xff'
            b'\xff')
        stream = utils.BytearrayStream()
        long_int = primitives.LongInteger(primitives.LongInteger.MAX)
        long_int.write(stream)

        result = stream.read()
        self.assertEqual(len(encoding), len(result))
        self.assertEqual(encoding, result)

    def test_write_min_max(self):
        """
        Test that a LongInteger representing the minimum positive value can be
        written to a byte stream.
        """
        encoding = (
            b'\x42\x00\x00\x03\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00'
            b'\x01')
        stream = utils.BytearrayStream()
        long_int = primitives.LongInteger(1)
        long_int.write(stream)

        result = stream.read()
        self.assertEqual(len(encoding), len(result))
        self.assertEqual(encoding, result)

    def test_write_max_min(self):
        """
        Test that a LongInteger representing the maximum negative value can be
        written to a byte stream.
        """
        encoding = (
            b'\x42\x00\x00\x03\x00\x00\x00\x08\xff\xff\xff\xff\xff\xff\xff'
            b'\xff')
        stream = utils.BytearrayStream()
        long_int = primitives.LongInteger(-1)
        long_int.write(stream)

        result = stream.read()
        self.assertEqual(len(encoding), len(result))
        self.assertEqual(encoding, result)

    def test_write_min_min(self):
        """
        Test that a LongInteger representing the minimum negative value can be
        written to a byte stream.
        """
        encoding = (
            b'\x42\x00\x00\x03\x00\x00\x00\x08\x80\x00\x00\x00\x00\x00\x00'
            b'\x00')
        stream = utils.BytearrayStream()
        long_int = primitives.LongInteger(primitives.LongInteger.MIN)
        long_int.write(stream)

        result = stream.read()
        self.assertEqual(len(encoding), len(result))
        self.assertEqual(encoding, result)

    def test_repr(self):
        """
        Test that the representation of a LongInteger is formatted properly.
        """
        long_int = primitives.LongInteger()
        value = "value={0}".format(long_int.value)
        tag = "tag={0}".format(long_int.tag)
        self.assertEqual(
            "LongInteger({0}, {1})".format(value, tag), repr(long_int))

    def test_str(self):
        """
        Test that the string representation of a LongInteger is formatted
        properly.
        """
        self.assertEqual("0", str(primitives.LongInteger()))

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        LongIntegers.
        """
        a = primitives.LongInteger(1)
        b = primitives.LongInteger(1)

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_equal_and_empty(self):
        """
        Test that the equality operator returns True when comparing two
        LongIntegers.
        """
        a = primitives.LongInteger()
        b = primitives.LongInteger()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal(self):
        """
        Test that the equality operator returns False when comparing two
        LongIntegers with different values.
        """
        a = primitives.LongInteger(1)
        b = primitives.LongInteger(2)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing a
        LongInteger to a non-LongInteger object.
        """
        a = primitives.LongInteger()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing
        two LongIntegers with the same values.
        """
        a = primitives.LongInteger(1)
        b = primitives.LongInteger(1)

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_equal_and_empty(self):
        """
        Test that the inequality operator returns False when comparing
        two LongIntegers.
        """
        a = primitives.LongInteger()
        b = primitives.LongInteger()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal(self):
        """
        Test that the inequality operator returns True when comparing two
        LongIntegers with different values.
        """
        a = primitives.LongInteger(1)
        b = primitives.LongInteger(2)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing a
        LongInteger to a non-LongInteger object.
        """
        a = primitives.LongInteger()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)
