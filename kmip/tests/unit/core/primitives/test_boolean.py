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

from testtools import TestCase

from kmip.core import primitives
from kmip.core import utils

class TestBoolean(TestCase):

    def setUp(self):
        super(TestBoolean, self).setUp()
        self.stream = utils.BytearrayStream()

    def tearDown(self):
        super(TestBoolean, self).tearDown()

    def test_init(self):
        """
        Test that a Boolean object can be instantiated.
        """
        boolean = primitives.Boolean(False)
        self.assertEqual(False, boolean.value)

    def test_init_unset(self):
        """
        Test that a Boolean object can be instantiated with no input.
        """
        boolean = primitives.Boolean()
        self.assertEqual(True, boolean.value)

    def test_validate_on_valid(self):
        """
        Test that a Boolean object can be validated on good input.
        """
        boolean = primitives.Boolean(True)
        boolean.validate()

    def test_validate_on_valid_unset(self):
        """
        Test that a Boolean object with no preset value can be validated.
        """
        boolean = primitives.Boolean()
        boolean.validate()

    def test_validate_on_invalid_type(self):
        """
        Test that a TypeError is raised when a Boolean object is built with an
        invalid value.
        """
        self.assertRaises(TypeError, primitives.Boolean, 'invalid')

    def test_read_true(self):
        """
        Test that a Boolean object representing the value True can be read
        from a byte stream.
        """
        encoding = (
            b'\x42\x00\x00\x06\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00'
            b'\x01')
        stream = utils.BytearrayStream(encoding)
        boolean = primitives.Boolean()
        boolean.read(stream)
        self.assertTrue(boolean.value)

    def test_read_false(self):
        """
        Test that a Boolean object representing the value False can be read
        from a byte stream.
        """
        encoding = (
            b'\x42\x00\x00\x06\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00'
            b'\x00')
        stream = utils.BytearrayStream(encoding)
        boolean = primitives.Boolean()
        boolean.read(stream)
        self.assertFalse(boolean.value)

    def test_read_bad_encoding(self):
        """
        Test that an Exception is raised when the Boolean read operation fails
        on a bad encoding.
        """
        encoding = (b'\x42\x00\x00\x06\x00\x00\x00\x08')
        stream = utils.BytearrayStream(encoding)
        boolean = primitives.Boolean()
        self.assertRaises(Exception, boolean.read, stream)

    def test_read_bad_value(self):
        """
        Test that a ValueError is raised when the Boolean read operations
        reads a valid integer but invalid Boolean.
        """
        encoding = (
            b'\x42\x00\x00\x06\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00'
            b'\x02')
        stream = utils.BytearrayStream(encoding)
        boolean = primitives.Boolean()
        self.assertRaises(ValueError, boolean.read, stream)

    def test_write_true(self):
        """
        Test that a Boolean object representing the value True can be written
        to a byte stream.
        """
        encoding = (
            b'\x42\x00\x00\x06\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00'
            b'\x01')
        stream = utils.BytearrayStream()
        boolean = primitives.Boolean(True)
        boolean.write(stream)
        self.assertEqual(encoding, stream.read())

    def test_write_false(self):
        """
        Test that a Boolean object representing the value False can be written
        to a byte stream.
        """
        encoding = (
            b'\x42\x00\x00\x06\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00'
            b'\x00')
        stream = utils.BytearrayStream()
        boolean = primitives.Boolean(False)
        boolean.write(stream)
        self.assertEqual(encoding, stream.read())

    def test_write_bad_value(self):
        """
        Test that an Exception is raised when the Boolean write operation fails
        on a bad Boolean value.
        """
        stream = utils.BytearrayStream()
        boolean = primitives.Boolean()
        boolean.value = 'invalid'
        self.assertRaises(Exception, boolean.write, stream)

    def test_repr_default(self):
        """
        Test that the representation of a Boolean object is formatted properly
        """
        boolean = primitives.Boolean()
        self.assertEqual("Boolean(value=True)", repr(boolean))

    def test_repr_true(self):
        """
        Test that the representation of a Boolean object representing the
        value True is formatted properly.
        """
        boolean = primitives.Boolean(True)
        self.assertEqual("Boolean(value=True)", repr(boolean))

    def test_repr_false(self):
        """
        Test that the representation of a Boolean object representing the
        value False is formatted properly.
        """
        boolean = primitives.Boolean(False)
        self.assertEqual("Boolean(value=False)", repr(boolean))

    def test_str_default(self):
        """
        Test that the string representation of a Boolean object is formatted
        properly.
        """
        self.assertEqual("True", str(primitives.Boolean()))

    def test_str_true(self):
        """
        Test that the string representation of a Boolean object representing
        the value True is formatted properly.
        """
        self.assertEqual("True", str(primitives.Boolean(True)))

    def test_str_false(self):
        """
        Test that the string representation of a Boolean object representing
        the value False is formatted properly.
        """
        self.assertEqual("False", str(primitives.Boolean(False)))

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        Boolean objects.
        """
        a = primitives.Boolean(False)
        b = primitives.Boolean(False)

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_equal_and_empty(self):
        """
        Test that the equality operator returns True when comparing two
        Boolean objects.
        """
        a = primitives.Boolean()
        b = primitives.Boolean()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal(self):
        """
        Test that the equality operator returns False when comparing two
        Boolean objects with different values.
        """
        a = primitives.Boolean(True)
        b = primitives.Boolean(False)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing a
        Boolean object to a non-Boolean object.
        """
        a = primitives.Boolean()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing
        two Boolean objects with the same values.
        """
        a = primitives.Boolean(False)
        b = primitives.Boolean(False)

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_equal_and_empty(self):
        """
        Test that the inequality operator returns False when comparing
        two Boolean objects.
        """
        a = primitives.Boolean()
        b = primitives.Boolean()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal(self):
        """
        Test that the inequality operator returns True when comparing two
        Boolean objects with different values.
        """
        a = primitives.Boolean(True)
        b = primitives.Boolean(False)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing a
        Boolean object to a non-Boolean object.
        """
        a = primitives.Boolean()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)
