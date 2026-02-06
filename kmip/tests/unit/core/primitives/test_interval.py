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

class TestInterval(testtools.TestCase):
    """
    Test suite for the Interval primitive.
    """

    def setUp(self):
        super(TestInterval, self).setUp()

        # Encoding and value based on Section 9.1.2 of the KMIP 1.1
        # specification.
        self.value = 864000
        self.encoding = (
            b'\x42\x00\x00\x0A\x00\x00\x00\x04\x00\x0D\x2F\x00\x00\x00\x00'
            b'\x00')
        self.encoding_bad_length = (
            b'\x42\x00\x00\x0A\x00\x00\x00\x05\x00\x0D\x2F\x00\x00\x00\x00'
            b'\x00')
        self.encoding_bad_padding = (
            b'\x42\x00\x00\x0A\x00\x00\x00\x04\x00\x0D\x2F\x00\x00\x00\x00'
            b'\xFF')

    def tearDown(self):
        super(TestInterval, self).tearDown()

    def test_init(self):
        """
        Test that an Interval can be instantiated.
        """
        interval = primitives.Interval(1)
        self.assertEqual(1, interval.value)

    def test_init_unset(self):
        """
        Test that an Interval can be instantiated with no input.
        """
        interval = primitives.Interval()
        self.assertEqual(0, interval.value)

    def test_validate_on_invalid_type(self):
        """
        Test that a TypeError is thrown on input of invalid type (e.g., str).
        """
        self.assertRaises(TypeError, primitives.Interval, 'invalid')

    def test_validate_on_invalid_value_too_big(self):
        """
        Test that a ValueError is thrown on input that is too large.
        """
        self.assertRaises(
            ValueError, primitives.Interval, primitives.Interval.MAX + 1)

    def test_validate_on_invalid_value_too_small(self):
        """
        Test that a ValueError is thrown on input that is too small.
        """
        self.assertRaises(
            ValueError, primitives.Interval, primitives.Interval.MIN - 1)

    def test_read(self):
        """
        Test that an Interval can be read from a byte stream.
        """
        stream = utils.BytearrayStream(self.encoding)
        interval = primitives.Interval()
        interval.read(stream)
        self.assertEqual(self.value, interval.value)

    def test_read_on_invalid_length(self):
        """
        Test that an InvalidPrimitiveLength exception is thrown when attempting
        to decode an Interval with an invalid length.
        """
        stream = utils.BytearrayStream(self.encoding_bad_length)
        interval = primitives.Interval()
        self.assertRaises(
            exceptions.InvalidPrimitiveLength, interval.read, stream)

    def test_read_on_invalid_padding(self):
        """
        Test that an InvalidPaddingBytes exception is thrown when attempting
        to decode an Interval with invalid padding bytes.
        """
        stream = utils.BytearrayStream(self.encoding_bad_padding)
        interval = primitives.Interval()
        self.assertRaises(
            exceptions.InvalidPaddingBytes, interval.read, stream)

    def test_write(self):
        """
        Test that an Interval can be written to a byte stream.
        """
        stream = utils.BytearrayStream()
        interval = primitives.Interval(self.value)
        interval.write(stream)

        result = stream.read()
        self.assertEqual(len(self.encoding), len(result))
        self.assertEqual(self.encoding, result)

    def test_repr(self):
        """
        Test that the representation of a Interval is formatted properly.
        """
        long_int = primitives.Interval()
        value = "value={0}".format(long_int.value)
        tag = "tag={0}".format(long_int.tag)
        self.assertEqual(
            "Interval({0}, {1})".format(value, tag), repr(long_int))

    def test_str(self):
        """
        Test that the string representation of a Interval is formatted
        properly.
        """
        self.assertEqual("0", str(primitives.Interval()))

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        Intervals.
        """
        a = primitives.Interval(1)
        b = primitives.Interval(1)

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_equal_and_empty(self):
        """
        Test that the equality operator returns True when comparing two
        Intervals.
        """
        a = primitives.Interval()
        b = primitives.Interval()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal(self):
        """
        Test that the equality operator returns False when comparing two
        Intervals with different values.
        """
        a = primitives.Interval(1)
        b = primitives.Interval(2)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing a
        Interval to a non-Interval object.
        """
        a = primitives.Interval()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing
        two Intervals with the same values.
        """
        a = primitives.Interval(1)
        b = primitives.Interval(1)

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_equal_and_empty(self):
        """
        Test that the inequality operator returns False when comparing
        two Intervals.
        """
        a = primitives.Interval()
        b = primitives.Interval()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal(self):
        """
        Test that the inequality operator returns True when comparing two
        Intervals with different values.
        """
        a = primitives.Interval(1)
        b = primitives.Interval(2)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing a
        Interval to a non-Interval object.
        """
        a = primitives.Interval()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)
