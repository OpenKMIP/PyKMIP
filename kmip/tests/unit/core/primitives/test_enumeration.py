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

import enum as enumeration
import testtools

from kmip.core import enums
from kmip.core import exceptions
from kmip.core import primitives
from kmip.core import utils

# flake8: noqa
class DummyEnumeration(enumeration.Enum):
    SMALL     = primitives.Enumeration.MIN
    TOO_SMALL = primitives.Enumeration.MIN - 1
    LARGE     = primitives.Enumeration.MAX
    TOO_LARGE = primitives.Enumeration.MAX + 1
    INVALID   = 'invalid'

class TestEnumeration(testtools.TestCase):

    def setUp(self):
        super(TestEnumeration, self).setUp()

        self.encoding = (
            b'\x42\x00\x00\x05\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00'
            b'\x00')
        self.encoding_bad_length = (
            b'\x42\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00')
        self.encoding_bad_padding = (
            b'\x42\x00\x00\x05\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00'
            b'\xFF')

    def tearDown(self):
        super(TestEnumeration, self).tearDown()

    def test_init(self):
        """
        Test that an Enumeration can be instantiated.
        """
        enum = primitives.Enumeration(
            DummyEnumeration, DummyEnumeration.SMALL,
            enums.Tags.ACTIVATION_DATE)
        self.assertEqual(DummyEnumeration, enum.enum)
        self.assertEqual(DummyEnumeration.SMALL, enum.value)
        self.assertEqual(enums.Tags.ACTIVATION_DATE, enum.tag)

    def test_init_unset(self):
        """
        Test that an Enumeration can be instantiated with no input.
        """
        enum = primitives.Enumeration(DummyEnumeration)
        self.assertEqual(DummyEnumeration, enum.enum)
        self.assertEqual(None, enum.value)
        self.assertEqual(enums.Tags.DEFAULT, enum.tag)

    def test_validate_on_invalid_enum_type(self):
        """
        Test that a TypeError is thrown on input of invalid enum type
        (e.g., str).
        """
        args = ['invalid']
        kwargs = {'value': enums.Tags.DEFAULT}
        self.assertRaises(TypeError, primitives.Enumeration, *args, **kwargs)

    def test_validate_on_invalid_enum_value_type(self):
        """
        Test that a TypeError is thrown on input of invalid enum value type.
        """
        args = [DummyEnumeration]
        kwargs = {'value': enums.Tags.DEFAULT}
        self.assertRaises(TypeError, primitives.Enumeration, *args, **kwargs)

    def test_validate_on_invalid_value_type(self):
        """
        Test that a TypeError is thrown on input of invalid value type
        (e.g., str).
        """
        args = [DummyEnumeration]
        kwargs = {'value': DummyEnumeration.INVALID}
        self.assertRaises(TypeError, primitives.Enumeration, *args, **kwargs)

    def test_validate_on_invalid_value_too_big(self):
        """
        Test that a ValueError is thrown on input that is too large.
        """
        args = [DummyEnumeration]
        kwargs = {'value': DummyEnumeration.TOO_LARGE}
        self.assertRaises(ValueError, primitives.Enumeration, *args, **kwargs)

    def test_validate_on_invalid_value_too_small(self):
        """
        Test that a ValueError is thrown on input that is too small.
        """
        args = [DummyEnumeration]
        kwargs = {'value': DummyEnumeration.TOO_SMALL}
        self.assertRaises(ValueError, primitives.Enumeration, *args, **kwargs)

    def test_read(self):
        """
        Test that an Enumeration can be read from a byte stream.
        """
        stream = utils.BytearrayStream(self.encoding)
        enum = primitives.Enumeration(DummyEnumeration)
        enum.read(stream)
        self.assertEqual(DummyEnumeration.SMALL, enum.value)

    def test_read_on_invalid_length(self):
        """
        Test that an InvalidPrimitiveLength exception is thrown when attempting
        to decode an Enumeration with an invalid length.
        """
        stream = utils.BytearrayStream(self.encoding_bad_length)
        enum = primitives.Enumeration(enums.Tags)

        self.assertRaises(exceptions.InvalidPrimitiveLength, enum.read, stream)

    def test_read_on_invalid_padding(self):
        """
        Test that an InvalidPrimitiveLength exception is thrown when attempting
        to decode an Enumeration with invalid padding bytes.
        """
        stream = utils.BytearrayStream(self.encoding_bad_padding)
        enum = primitives.Enumeration(enums.Types)

        self.assertRaises(exceptions.InvalidPaddingBytes, enum.read, stream)

    def test_write(self):
        """
        Test that an Enumeration can be written to a byte stream.
        """
        stream = utils.BytearrayStream()
        enum = primitives.Enumeration(DummyEnumeration, DummyEnumeration.SMALL)
        enum.write(stream)

        result = stream.read()
        self.assertEqual(len(self.encoding), len(result))
        self.assertEqual(self.encoding, result)

    def test_repr(self):
        """
        Test that the representation of an Enumeration is formatted properly.
        """
        enum = "enum={0}".format(DummyEnumeration.__name__)
        value = "value={0}".format(DummyEnumeration.SMALL)
        tag = "tag={0}".format(enums.Tags.DEFAULT)
        r = "Enumeration({0}, {1}, {2})".format(enum, value, tag)

        enum = primitives.Enumeration(DummyEnumeration, DummyEnumeration.SMALL)
        self.assertEqual(r, repr(enum))

    def test_str(self):
        """
        Test that the string representation of an Enumeration is formatted
        properly.
        """
        enum = primitives.Enumeration(DummyEnumeration, DummyEnumeration.SMALL)
        self.assertEqual(str(DummyEnumeration.SMALL), str(enum.value))

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        Enumerations.
        """
        a = primitives.Enumeration(DummyEnumeration, DummyEnumeration.SMALL)
        b = primitives.Enumeration(DummyEnumeration, DummyEnumeration.SMALL)

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_equal_and_empty(self):
        """
        Test that the equality operator returns True when comparing two
        Enumerations.
        """
        a = primitives.Enumeration(DummyEnumeration)
        b = primitives.Enumeration(DummyEnumeration)

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal(self):
        """
        Test that the equality operator returns False when comparing two
        Enumerations with different values.
        """
        a = primitives.Enumeration(DummyEnumeration, DummyEnumeration.SMALL)
        b = primitives.Enumeration(DummyEnumeration, DummyEnumeration.LARGE)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_enum(self):
        """
        Test that the equality operator returns False when comparing two
        Enumerations with different enum types.
        """
        a = primitives.Enumeration(DummyEnumeration, DummyEnumeration.SMALL)
        b = primitives.Enumeration(enums.Tags, enums.Tags.DEFAULT)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing a
        Enumeration to a non-Enumeration object.
        """
        a = primitives.Enumeration(DummyEnumeration, DummyEnumeration.SMALL)
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing
        two Enumerations with the same values.
        """
        a = primitives.Enumeration(DummyEnumeration, DummyEnumeration.SMALL)
        b = primitives.Enumeration(DummyEnumeration, DummyEnumeration.SMALL)

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_equal_and_empty(self):
        """
        Test that the inequality operator returns False when comparing
        two Enumerations.
        """
        a = primitives.Enumeration(DummyEnumeration)
        b = primitives.Enumeration(DummyEnumeration)

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal(self):
        """
        Test that the inequality operator returns True when comparing two
        Enumerations with different values.
        """
        a = primitives.Enumeration(DummyEnumeration, DummyEnumeration.SMALL)
        b = primitives.Enumeration(DummyEnumeration, DummyEnumeration.LARGE)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_enum(self):
        """
        Test that the equality operator returns True when comparing two
        Enumerations with different enum types.
        """
        a = primitives.Enumeration(DummyEnumeration, DummyEnumeration.SMALL)
        b = primitives.Enumeration(enums.Tags, enums.Tags.DEFAULT)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing a
        Enumeration to a non-Enumeration object.
        """
        a = primitives.Enumeration(DummyEnumeration, DummyEnumeration.SMALL)
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)
