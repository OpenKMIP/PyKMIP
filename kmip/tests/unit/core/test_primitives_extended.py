
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

import enum
import struct
import time

import testtools
from unittest import mock

from kmip.core import enums
from kmip.core import exceptions
from kmip.core import primitives
from kmip.core import utils


def _ttlv(tag, typ, length, value_bytes):
    return (
        struct.pack('!I', tag.value)[1:] +
        struct.pack('!B', typ.value) +
        struct.pack('!I', length) +
        value_bytes
    )


def _pad_to_eight(value_bytes):
    pad_len = (8 - (len(value_bytes) % 8)) % 8
    return value_bytes + (b'\x00' * pad_len)


def _encode_integer(tag, value):
    return _ttlv(
        tag,
        enums.Types.INTEGER,
        4,
        _pad_to_eight(struct.pack('!i', value))
    )


def _encode_long_integer(tag, typ, value):
    return _ttlv(tag, typ, 8, struct.pack('!q', value))


def _encode_unsigned_int(tag, typ, value):
    return _ttlv(
        tag,
        typ,
        4,
        _pad_to_eight(struct.pack('!I', value))
    )


def _encode_boolean(tag, value):
    return _ttlv(tag, enums.Types.BOOLEAN, 8, struct.pack('!Q', value))


def _encode_text(tag, value):
    value_bytes = value.encode()
    return _ttlv(
        tag,
        enums.Types.TEXT_STRING,
        len(value_bytes),
        _pad_to_eight(value_bytes)
    )


def _encode_bytes(tag, value_bytes):
    return _ttlv(
        tag,
        enums.Types.BYTE_STRING,
        len(value_bytes),
        _pad_to_eight(value_bytes)
    )


def _encode_big_integer(tag, value_bytes):
    return _ttlv(tag, enums.Types.BIG_INTEGER, len(value_bytes), value_bytes)


class SampleEnum(enum.Enum):
    ONE = 1
    TWO = 2


class EdgeEnum(enum.Enum):
    MIN = 0
    MAX = 4294967295


class LargeEnum(enum.Enum):
    TOO_BIG = 4294967297
    TOO_SMALL = -1


class TestBase(testtools.TestCase):

    def setUp(self):
        super(TestBase, self).setUp()
        self.stream = utils.BytearrayStream()
        self.tag = enums.Tags.DEFAULT
        self.other_tag = enums.Tags.ACTIVATION_DATE

    def tearDown(self):
        super(TestBase, self).tearDown()

    def test_init_with_none(self):
        """Test Base initializes with defaults."""
        base = primitives.Base()
        self.assertEqual(enums.Tags.DEFAULT, base.tag)
        self.assertEqual(enums.Types.DEFAULT, base.type)
        self.assertIsNone(base.length)

    def test_init_with_valid_value(self):
        """Test Base accepts an explicit tag and type."""
        base = primitives.Base(tag=self.other_tag, type=enums.Types.INTEGER)
        self.assertEqual(self.other_tag, base.tag)
        self.assertEqual(enums.Types.INTEGER, base.type)

    def test_init_with_invalid_value(self):
        """Test Base rejects invalid type values during write."""
        base = primitives.Base(type='invalid')
        self.assertRaises(TypeError, base.write_type, self.stream)

    def test_init_with_tag(self):
        """Test Base stores a custom tag."""
        base = primitives.Base(tag=self.other_tag)
        self.assertEqual(self.other_tag, base.tag)

    def test_read_valid_encoding(self):
        """Test Base reads a valid TTLV header."""
        encoding = _ttlv(self.tag, enums.Types.DEFAULT, 0, b'')
        stream = utils.BytearrayStream(encoding)
        base = primitives.Base()
        base.read(stream)
        self.assertEqual(0, base.length)

    def test_read_invalid_encoding(self):
        """Test Base rejects a TTLV header with the wrong type."""
        encoding = _ttlv(self.tag, enums.Types.INTEGER, 0, b'')
        stream = utils.BytearrayStream(encoding)
        base = primitives.Base()
        self.assertRaises(exceptions.ReadValueError, base.read, stream)

    def test_read_oversized(self):
        """Test Base detects extra bytes after reading."""
        encoding = _ttlv(self.tag, enums.Types.DEFAULT, 0, b'') + b'\x00'
        stream = utils.BytearrayStream(encoding)
        base = primitives.Base()
        base.read(stream)
        self.assertRaises(exceptions.StreamNotEmptyError,
                          base.is_oversized, stream)

    def test_write_valid(self):
        """Test Base writes a valid TTLV header."""
        base = primitives.Base()
        base.length = 0
        base.write(self.stream)
        self.assertEqual(
            _ttlv(self.tag, enums.Types.DEFAULT, 0, b''),
            self.stream.read()
        )

    def test_read_write_roundtrip(self):
        """Test Base read/write round-trip preserves header data."""
        base = primitives.Base()
        base.length = 0
        stream = utils.BytearrayStream()
        base.write(stream)
        clone = primitives.Base()
        clone.read(utils.BytearrayStream(stream.read()))
        self.assertEqual(base.tag, clone.tag)
        self.assertEqual(base.type, clone.type)
        self.assertEqual(base.length, clone.length)

    def test_validate_valid(self):
        """Test Base validate is abstract."""
        base = primitives.Base()
        self.assertRaises(NotImplementedError, base.validate)

    def test_validate_invalid_type(self):
        """Test Base validate is abstract for invalid types."""
        base = primitives.Base()
        self.assertRaises(NotImplementedError, base.validate)

    def test_validate_out_of_range(self):
        """Test Base validate is abstract for range checks."""
        base = primitives.Base()
        self.assertRaises(NotImplementedError, base.validate)

    def test_eq_same_value(self):
        """Test Base equality on identical objects."""
        base = primitives.Base()
        self.assertTrue(base == base)

    def test_eq_different_value(self):
        """Test Base inequality for different objects."""
        base_one = primitives.Base()
        base_two = primitives.Base()
        self.assertFalse(base_one == base_two)

    def test_eq_different_type(self):
        """Test Base equality returns NotImplemented for other types."""
        base = primitives.Base()
        self.assertIs(base.__eq__('invalid'), NotImplemented)

    def test_ne(self):
        """Test Base inequality operator."""
        base_one = primitives.Base()
        base_two = primitives.Base()
        self.assertTrue(base_one != base_two)

    def test_hash_same_value(self):
        """Test Base hashes consistently for the same object."""
        base = primitives.Base()
        self.assertEqual(hash(base), hash(base))

    def test_repr(self):
        """Test Base representation includes the class name."""
        base = primitives.Base()
        self.assertIn('Base', repr(base))

    def test_str(self):
        """Test Base string conversion includes the class name."""
        base = primitives.Base()
        self.assertIn('Base', str(base))

    def test_boundary_values(self):
        """Test Base tag/type inspection helpers with boundary streams."""
        encoding = _ttlv(self.other_tag, enums.Types.INTEGER, 0, b'')
        stream = utils.BytearrayStream(encoding)
        empty = utils.BytearrayStream(b'')
        self.assertTrue(primitives.Base.is_tag_next(self.other_tag, stream))
        self.assertTrue(
            primitives.Base.is_type_next(enums.Types.INTEGER, stream))
        self.assertFalse(primitives.Base.is_tag_next(self.other_tag, empty))
        self.assertFalse(
            primitives.Base.is_type_next(enums.Types.INTEGER, empty))

class TestStruct(testtools.TestCase):

    def setUp(self):
        super(TestStruct, self).setUp()
        self.stream = utils.BytearrayStream()
        self.tag = enums.Tags.DEFAULT
        self.other_tag = enums.Tags.ACTIVATION_DATE

    def tearDown(self):
        super(TestStruct, self).tearDown()

    def test_init_with_none(self):
        """Test Struct initializes with defaults."""
        struct_obj = primitives.Struct()
        self.assertEqual(enums.Tags.DEFAULT, struct_obj.tag)
        self.assertEqual(enums.Types.STRUCTURE, struct_obj.type)
        self.assertIsNone(struct_obj.length)

    def test_init_with_valid_value(self):
        """Test Struct accepts a custom tag."""
        struct_obj = primitives.Struct(tag=self.other_tag)
        self.assertEqual(self.other_tag, struct_obj.tag)

    def test_init_with_invalid_value(self):
        """Test Struct rejects invalid type values during write."""
        struct_obj = primitives.Struct()
        struct_obj.type = 'invalid'
        self.assertRaises(TypeError, struct_obj.write_type, self.stream)

    def test_init_with_tag(self):
        """Test Struct stores a custom tag."""
        struct_obj = primitives.Struct(tag=self.other_tag)
        self.assertEqual(self.other_tag, struct_obj.tag)

    def test_read_valid_encoding(self):
        """Test Struct reads a valid TTLV header."""
        encoding = _ttlv(self.tag, enums.Types.STRUCTURE, 0, b'')
        stream = utils.BytearrayStream(encoding)
        struct_obj = primitives.Struct()
        struct_obj.read(stream)
        self.assertEqual(0, struct_obj.length)

    def test_read_invalid_encoding(self):
        """Test Struct rejects a TTLV header with the wrong type."""
        encoding = _ttlv(self.tag, enums.Types.INTEGER, 0, b'')
        stream = utils.BytearrayStream(encoding)
        struct_obj = primitives.Struct()
        self.assertRaises(exceptions.ReadValueError, struct_obj.read, stream)

    def test_read_oversized(self):
        """Test Struct detects extra bytes after reading."""
        encoding = _ttlv(self.tag, enums.Types.STRUCTURE, 0, b'') + b'\x00'
        stream = utils.BytearrayStream(encoding)
        struct_obj = primitives.Struct()
        struct_obj.read(stream)
        self.assertRaises(exceptions.StreamNotEmptyError,
                          struct_obj.is_oversized, stream)

    def test_write_valid(self):
        """Test Struct writes a valid TTLV header."""
        struct_obj = primitives.Struct()
        struct_obj.length = 0
        struct_obj.write(self.stream)
        self.assertEqual(
            _ttlv(self.tag, enums.Types.STRUCTURE, 0, b''),
            self.stream.read()
        )

    def test_read_write_roundtrip(self):
        """Test Struct read/write round-trip preserves header data."""
        struct_obj = primitives.Struct()
        struct_obj.length = 0
        stream = utils.BytearrayStream()
        struct_obj.write(stream)
        clone = primitives.Struct()
        clone.read(utils.BytearrayStream(stream.read()))
        self.assertEqual(struct_obj.tag, clone.tag)
        self.assertEqual(struct_obj.type, clone.type)
        self.assertEqual(struct_obj.length, clone.length)

    def test_validate_valid(self):
        """Test Struct validate is abstract."""
        struct_obj = primitives.Struct()
        self.assertRaises(NotImplementedError, struct_obj.validate)

    def test_validate_invalid_type(self):
        """Test Struct validate is abstract for invalid types."""
        struct_obj = primitives.Struct()
        self.assertRaises(NotImplementedError, struct_obj.validate)

    def test_validate_out_of_range(self):
        """Test Struct validate is abstract for range checks."""
        struct_obj = primitives.Struct()
        self.assertRaises(NotImplementedError, struct_obj.validate)

    def test_eq_same_value(self):
        """Test Struct equality on identical objects."""
        struct_obj = primitives.Struct()
        self.assertTrue(struct_obj == struct_obj)

    def test_eq_different_value(self):
        """Test Struct inequality for different objects."""
        struct_one = primitives.Struct()
        struct_two = primitives.Struct()
        self.assertFalse(struct_one == struct_two)

    def test_eq_different_type(self):
        """Test Struct equality returns NotImplemented for other types."""
        struct_obj = primitives.Struct()
        self.assertIs(struct_obj.__eq__('invalid'), NotImplemented)

    def test_ne(self):
        """Test Struct inequality operator."""
        struct_one = primitives.Struct()
        struct_two = primitives.Struct()
        self.assertTrue(struct_one != struct_two)

    def test_hash_same_value(self):
        """Test Struct hashes consistently for the same object."""
        struct_obj = primitives.Struct()
        self.assertEqual(hash(struct_obj), hash(struct_obj))

    def test_repr(self):
        """Test Struct representation formatting."""
        struct_obj = primitives.Struct()
        self.assertEqual('Struct()', repr(struct_obj))

    def test_str(self):
        """Test Struct string conversion includes the class name."""
        struct_obj = primitives.Struct()
        self.assertIn('Struct', str(struct_obj))

    def test_boundary_values(self):
        """Test Struct tag/type inspection helpers with boundary streams."""
        encoding = _ttlv(self.other_tag, enums.Types.STRUCTURE, 0, b'')
        stream = utils.BytearrayStream(encoding)
        empty = utils.BytearrayStream(b'')
        self.assertTrue(primitives.Base.is_tag_next(self.other_tag, stream))
        self.assertTrue(
            primitives.Base.is_type_next(enums.Types.STRUCTURE, stream))
        self.assertFalse(primitives.Base.is_tag_next(self.other_tag, empty))
        self.assertFalse(
            primitives.Base.is_type_next(enums.Types.STRUCTURE, empty))

    def test_empty_structure(self):
        """Test encoding and decoding an empty structure."""
        struct_obj = primitives.Struct()
        struct_obj.length = 0
        stream = utils.BytearrayStream()
        struct_obj.write(stream)
        clone = primitives.Struct()
        clone.read(utils.BytearrayStream(stream.read()))
        self.assertEqual(0, clone.length)

    def test_nested_structures(self):
        """Test decoding nested structure headers."""
        inner = primitives.Struct(tag=enums.Tags.APPLICATION_DATA)
        inner.length = 0
        inner_stream = utils.BytearrayStream()
        inner.write(inner_stream)
        inner_bytes = inner_stream.read()

        outer = primitives.Struct(tag=enums.Tags.APPLICATION_NAMESPACE)
        outer.length = len(inner_bytes)
        outer_stream = utils.BytearrayStream()
        outer.write(outer_stream)
        outer_bytes = outer_stream.read() + inner_bytes

        stream = utils.BytearrayStream(outer_bytes)
        read_outer = primitives.Struct(tag=enums.Tags.APPLICATION_NAMESPACE)
        read_outer.read(stream)
        self.assertEqual(len(inner_bytes), read_outer.length)

        read_inner = primitives.Struct(tag=enums.Tags.APPLICATION_DATA)
        read_inner.read(stream)
        self.assertEqual(0, read_inner.length)

class TestInteger(testtools.TestCase):

    def setUp(self):
        super(TestInteger, self).setUp()
        self.stream = utils.BytearrayStream()
        self.tag = enums.Tags.DEFAULT
        self.other_tag = enums.Tags.ACTIVATION_DATE

    def tearDown(self):
        super(TestInteger, self).tearDown()

    def test_init_with_none(self):
        """Test Integer initializes with default values."""
        integer = primitives.Integer()
        self.assertEqual(0, integer.value)
        self.assertEqual(primitives.Integer.LENGTH, integer.length)
        self.assertEqual(primitives.Integer.LENGTH, integer.padding_length)

    def test_init_with_valid_value(self):
        """Test Integer initializes with a valid value."""
        integer = primitives.Integer(8)
        self.assertEqual(8, integer.value)

    def test_init_with_invalid_value(self):
        """Test Integer rejects invalid types."""
        self.assertRaises(TypeError, primitives.Integer, 'invalid')

    def test_init_with_tag(self):
        """Test Integer stores a custom tag."""
        integer = primitives.Integer(1, tag=self.other_tag)
        self.assertEqual(self.other_tag, integer.tag)

    def test_read_valid_encoding(self):
        """Test Integer reads a valid TTLV encoding."""
        encoding = _encode_integer(self.tag, 8)
        stream = utils.BytearrayStream(encoding)
        integer = primitives.Integer()
        integer.read(stream)
        self.assertEqual(8, integer.value)

    def test_read_invalid_encoding(self):
        """Test Integer rejects invalid TTLV lengths."""
        encoding = _ttlv(self.tag, enums.Types.INTEGER, 0, b'')
        stream = utils.BytearrayStream(encoding)
        integer = primitives.Integer()
        self.assertRaises(exceptions.ReadValueError, integer.read, stream)

    def test_read_oversized(self):
        """Test Integer detects extra bytes after reading."""
        encoding = _encode_integer(self.tag, 1) + b'\x00'
        stream = utils.BytearrayStream(encoding)
        integer = primitives.Integer()
        integer.read(stream)
        self.assertRaises(exceptions.StreamNotEmptyError,
                          integer.is_oversized, stream)

    def test_write_valid(self):
        """Test Integer writes a valid TTLV encoding."""
        integer = primitives.Integer(8)
        integer.write(self.stream)
        self.assertEqual(_encode_integer(self.tag, 8), self.stream.read())

    def test_read_write_roundtrip(self):
        """Test Integer read/write round-trip."""
        integer = primitives.Integer(-1)
        stream = utils.BytearrayStream()
        integer.write(stream)
        clone = primitives.Integer()
        clone.read(utils.BytearrayStream(stream.read()))
        self.assertEqual(integer.value, clone.value)

    def test_validate_valid(self):
        """Test Integer validate accepts valid values."""
        integer = primitives.Integer(0)
        integer.validate()

    def test_validate_invalid_type(self):
        """Test Integer validate rejects invalid types."""
        self.assertRaises(TypeError, primitives.Integer, 'bad')

    def test_validate_out_of_range(self):
        """Test Integer validate rejects out-of-range values."""
        self.assertRaises(ValueError, primitives.Integer,
                          primitives.Integer.MAX + 1)
        self.assertRaises(ValueError, primitives.Integer,
                          primitives.Integer.MIN - 1)

    def test_eq_same_value(self):
        """Test Integer equality for identical values."""
        self.assertTrue(primitives.Integer(1) == primitives.Integer(1))

    def test_eq_different_value(self):
        """Test Integer inequality for different values."""
        self.assertFalse(primitives.Integer(1) == primitives.Integer(2))

    def test_eq_different_type(self):
        """Test Integer equality returns NotImplemented for other types."""
        integer = primitives.Integer(1)
        self.assertIs(integer.__eq__('invalid'), NotImplemented)

    def test_ne(self):
        """Test Integer inequality operator."""
        self.assertTrue(primitives.Integer(1) != primitives.Integer(2))

    def test_hash_same_value(self):
        """Test Integer is unhashable when equality is defined."""
        self.assertRaises(TypeError, hash, primitives.Integer(1))

    def test_repr(self):
        """Test Integer representation formatting."""
        integer = primitives.Integer(8)
        self.assertEqual('Integer(value=8)', repr(integer))

    def test_str(self):
        """Test Integer string conversion formatting."""
        self.assertEqual('8', str(primitives.Integer(8)))

    def test_max_value(self):
        """Test Integer accepts the maximum value."""
        integer = primitives.Integer(primitives.Integer.MAX)
        self.assertEqual(primitives.Integer.MAX, integer.value)

    def test_min_value(self):
        """Test Integer accepts the minimum value."""
        integer = primitives.Integer(primitives.Integer.MIN)
        self.assertEqual(primitives.Integer.MIN, integer.value)

    def test_boundary_values(self):
        """Test Integer boundary values round-trip correctly."""
        values = [primitives.Integer.MIN, -1, 0, 1, primitives.Integer.MAX]
        for value in values:
            integer = primitives.Integer(value)
            stream = utils.BytearrayStream()
            integer.write(stream)
            clone = primitives.Integer()
            clone.read(utils.BytearrayStream(stream.read()))
            self.assertEqual(value, clone.value)

    def test_specific_values(self):
        """Test Integer negative, zero, and boundary values."""
        self.assertEqual(-5, primitives.Integer(-5).value)
        self.assertEqual(0, primitives.Integer(0).value)
        self.assertEqual(primitives.Integer.MAX,
                         primitives.Integer(primitives.Integer.MAX).value)

class TestLongInteger(testtools.TestCase):

    def setUp(self):
        super(TestLongInteger, self).setUp()
        self.stream = utils.BytearrayStream()
        self.tag = enums.Tags.DEFAULT
        self.other_tag = enums.Tags.ACTIVATION_DATE

    def tearDown(self):
        super(TestLongInteger, self).tearDown()

    def test_init_with_none(self):
        """Test LongInteger initializes with default values."""
        long_int = primitives.LongInteger()
        self.assertEqual(0, long_int.value)
        self.assertEqual(primitives.LongInteger.LENGTH, long_int.length)

    def test_init_with_valid_value(self):
        """Test LongInteger initializes with a valid value."""
        long_int = primitives.LongInteger(5)
        self.assertEqual(5, long_int.value)

    def test_init_with_invalid_value(self):
        """Test LongInteger rejects invalid types."""
        self.assertRaises(TypeError, primitives.LongInteger, 'invalid')

    def test_init_with_tag(self):
        """Test LongInteger stores a custom tag."""
        long_int = primitives.LongInteger(1, tag=self.other_tag)
        self.assertEqual(self.other_tag, long_int.tag)

    def test_read_valid_encoding(self):
        """Test LongInteger reads a valid TTLV encoding."""
        encoding = _encode_long_integer(
            self.tag, enums.Types.LONG_INTEGER, 5)
        stream = utils.BytearrayStream(encoding)
        long_int = primitives.LongInteger()
        long_int.read(stream)
        self.assertEqual(5, long_int.value)

    def test_read_invalid_encoding(self):
        """Test LongInteger rejects invalid TTLV lengths."""
        encoding = _ttlv(self.tag, enums.Types.LONG_INTEGER, 4, b'')
        stream = utils.BytearrayStream(encoding)
        long_int = primitives.LongInteger()
        self.assertRaises(exceptions.InvalidPrimitiveLength,
                          long_int.read, stream)

    def test_read_oversized(self):
        """Test LongInteger detects extra bytes after reading."""
        encoding = _encode_long_integer(
            self.tag, enums.Types.LONG_INTEGER, 1) + b'\x00'
        stream = utils.BytearrayStream(encoding)
        long_int = primitives.LongInteger()
        long_int.read(stream)
        self.assertRaises(exceptions.StreamNotEmptyError,
                          long_int.is_oversized, stream)

    def test_write_valid(self):
        """Test LongInteger writes a valid TTLV encoding."""
        long_int = primitives.LongInteger(5)
        long_int.write(self.stream)
        self.assertEqual(
            _encode_long_integer(self.tag, enums.Types.LONG_INTEGER, 5),
            self.stream.read()
        )

    def test_read_write_roundtrip(self):
        """Test LongInteger read/write round-trip."""
        long_int = primitives.LongInteger(1234567890123)
        stream = utils.BytearrayStream()
        long_int.write(stream)
        clone = primitives.LongInteger()
        clone.read(utils.BytearrayStream(stream.read()))
        self.assertEqual(long_int.value, clone.value)

    def test_validate_valid(self):
        """Test LongInteger validate accepts valid values."""
        long_int = primitives.LongInteger(0)
        long_int.validate()

    def test_validate_invalid_type(self):
        """Test LongInteger validate rejects invalid types."""
        self.assertRaises(TypeError, primitives.LongInteger, 'bad')

    def test_validate_out_of_range(self):
        """Test LongInteger validate rejects out-of-range values."""
        self.assertRaises(ValueError, primitives.LongInteger,
                          primitives.LongInteger.MAX + 1)
        self.assertRaises(ValueError, primitives.LongInteger,
                          primitives.LongInteger.MIN - 1)

    def test_eq_same_value(self):
        """Test LongInteger equality for identical values."""
        self.assertTrue(primitives.LongInteger(1) == primitives.LongInteger(1))

    def test_eq_different_value(self):
        """Test LongInteger inequality for different values."""
        self.assertFalse(primitives.LongInteger(1) == primitives.LongInteger(2))

    def test_eq_different_type(self):
        """Test LongInteger equality returns NotImplemented for other types."""
        long_int = primitives.LongInteger(1)
        self.assertIs(long_int.__eq__('invalid'), NotImplemented)

    def test_ne(self):
        """Test LongInteger inequality operator."""
        self.assertTrue(primitives.LongInteger(1) != primitives.LongInteger(2))

    def test_hash_same_value(self):
        """Test LongInteger is unhashable when equality is defined."""
        self.assertRaises(TypeError, hash, primitives.LongInteger(1))

    def test_repr(self):
        """Test LongInteger representation formatting."""
        long_int = primitives.LongInteger(5)
        self.assertEqual(
            'LongInteger(value=5, tag={0})'.format(enums.Tags.DEFAULT),
            repr(long_int)
        )

    def test_str(self):
        """Test LongInteger string conversion formatting."""
        self.assertEqual('5', str(primitives.LongInteger(5)))

    def test_boundary_values(self):
        """Test LongInteger boundary values round-trip correctly."""
        values = [primitives.LongInteger.MIN, 0, primitives.LongInteger.MAX]
        for value in values:
            long_int = primitives.LongInteger(value)
            stream = utils.BytearrayStream()
            long_int.write(stream)
            clone = primitives.LongInteger()
            clone.read(utils.BytearrayStream(stream.read()))
            self.assertEqual(value, clone.value)

    def test_specific_values(self):
        """Test LongInteger supports values larger than 2^31."""
        value = 2 ** 40
        self.assertEqual(value, primitives.LongInteger(value).value)

class TestBigInteger(testtools.TestCase):

    def setUp(self):
        super(TestBigInteger, self).setUp()
        self.stream = utils.BytearrayStream()
        self.tag = enums.Tags.DEFAULT
        self.other_tag = enums.Tags.ACTIVATION_DATE

    def tearDown(self):
        super(TestBigInteger, self).tearDown()

    def test_init_with_none(self):
        """Test BigInteger initializes with a None value."""
        big_int = primitives.BigInteger(None)
        self.assertIsNone(big_int.value)

    def test_init_with_valid_value(self):
        """Test BigInteger initializes with a valid value."""
        big_int = primitives.BigInteger(1)
        self.assertEqual(1, big_int.value)

    def test_init_with_invalid_value(self):
        """Test BigInteger rejects invalid types."""
        self.assertRaises(TypeError, primitives.BigInteger, 'invalid')

    def test_init_with_tag(self):
        """Test BigInteger stores a custom tag."""
        big_int = primitives.BigInteger(1, tag=self.other_tag)
        self.assertEqual(self.other_tag, big_int.tag)

    def test_read_valid_encoding(self):
        """Test BigInteger reads a valid TTLV encoding."""
        value_bytes = b'\x00' * 7 + b'\x01'
        encoding = _encode_big_integer(self.tag, value_bytes)
        stream = utils.BytearrayStream(encoding)
        big_int = primitives.BigInteger()
        big_int.read(stream)
        self.assertEqual(1, big_int.value)

    def test_read_invalid_encoding(self):
        """Test BigInteger rejects invalid TTLV lengths."""
        encoding = _ttlv(self.tag, enums.Types.BIG_INTEGER, 7, b'\x00' * 7)
        stream = utils.BytearrayStream(encoding)
        big_int = primitives.BigInteger()
        self.assertRaises(exceptions.InvalidPrimitiveLength,
                          big_int.read, stream)

    def test_read_oversized(self):
        """Test BigInteger detects extra bytes after reading."""
        value_bytes = b'\x00' * 7 + b'\x01'
        encoding = _encode_big_integer(self.tag, value_bytes) + b'\x00'
        stream = utils.BytearrayStream(encoding)
        big_int = primitives.BigInteger()
        big_int.read(stream)
        self.assertRaises(exceptions.StreamNotEmptyError,
                          big_int.is_oversized, stream)

    def test_write_valid(self):
        """Test BigInteger writes a valid TTLV encoding."""
        big_int = primitives.BigInteger(1)
        big_int.write(self.stream)
        value_bytes = b'\x00' * 7 + b'\x01'
        self.assertEqual(
            _encode_big_integer(self.tag, value_bytes),
            self.stream.read()
        )

    def test_read_write_roundtrip(self):
        """Test BigInteger read/write round-trip for large values."""
        value = (1 << 1023) + 12345
        big_int = primitives.BigInteger(value)
        stream = utils.BytearrayStream()
        big_int.write(stream)
        clone = primitives.BigInteger()
        clone.read(utils.BytearrayStream(stream.read()))
        self.assertEqual(value, clone.value)

    def test_validate_valid(self):
        """Test BigInteger validate accepts valid values."""
        big_int = primitives.BigInteger(0)
        big_int.validate()

    def test_validate_invalid_type(self):
        """Test BigInteger validate rejects invalid types."""
        self.assertRaises(TypeError, primitives.BigInteger, 'bad')

    def test_eq_same_value(self):
        """Test BigInteger equality for identical values."""
        self.assertTrue(primitives.BigInteger(1) == primitives.BigInteger(1))

    def test_eq_different_value(self):
        """Test BigInteger inequality for different values."""
        self.assertFalse(primitives.BigInteger(1) == primitives.BigInteger(2))

    def test_eq_different_type(self):
        """Test BigInteger equality returns NotImplemented for other types."""
        big_int = primitives.BigInteger(1)
        self.assertIs(big_int.__eq__('invalid'), NotImplemented)

    def test_ne(self):
        """Test BigInteger inequality operator."""
        self.assertTrue(primitives.BigInteger(1) != primitives.BigInteger(2))

    def test_hash_same_value(self):
        """Test BigInteger is unhashable when equality is defined."""
        self.assertRaises(TypeError, hash, primitives.BigInteger(1))

    def test_repr(self):
        """Test BigInteger representation formatting."""
        big_int = primitives.BigInteger(5)
        self.assertEqual(
            'BigInteger(value=5, tag={0})'.format(enums.Tags.DEFAULT),
            repr(big_int)
        )

    def test_str(self):
        """Test BigInteger string conversion formatting."""
        self.assertEqual('5', str(primitives.BigInteger(5)))

    def test_boundary_values(self):
        """Test BigInteger boundary values round-trip correctly."""
        values = [0, 1, (1 << 64) - 1]
        for value in values:
            big_int = primitives.BigInteger(value)
            stream = utils.BytearrayStream()
            big_int.write(stream)
            clone = primitives.BigInteger()
            clone.read(utils.BytearrayStream(stream.read()))
            self.assertEqual(value, clone.value)

    def test_specific_values(self):
        """Test BigInteger supports 1024-bit values."""
        value = (1 << 1023) + 1
        self.assertEqual(value, primitives.BigInteger(value).value)

class TestEnumeration(testtools.TestCase):

    def setUp(self):
        super(TestEnumeration, self).setUp()
        self.stream = utils.BytearrayStream()
        self.tag = enums.Tags.DEFAULT
        self.other_tag = enums.Tags.ACTIVATION_DATE

    def tearDown(self):
        super(TestEnumeration, self).tearDown()

    def test_init_with_none(self):
        """Test Enumeration initializes with a None value."""
        enum_obj = primitives.Enumeration(SampleEnum, value=None)
        self.assertIsNone(enum_obj.value)

    def test_init_with_valid_value(self):
        """Test Enumeration initializes with a valid value."""
        enum_obj = primitives.Enumeration(SampleEnum, SampleEnum.ONE)
        self.assertEqual(SampleEnum.ONE, enum_obj.value)

    def test_init_with_invalid_value(self):
        """Test Enumeration rejects invalid enum values."""
        self.assertRaises(TypeError, primitives.Enumeration, SampleEnum, 1)

    def test_init_with_tag(self):
        """Test Enumeration stores a custom tag."""
        enum_obj = primitives.Enumeration(SampleEnum, SampleEnum.ONE,
                                          tag=self.other_tag)
        self.assertEqual(self.other_tag, enum_obj.tag)

    def test_read_valid_encoding(self):
        """Test Enumeration reads a valid TTLV encoding."""
        encoding = _encode_unsigned_int(
            self.tag, enums.Types.ENUMERATION, SampleEnum.ONE.value)
        stream = utils.BytearrayStream(encoding)
        enum_obj = primitives.Enumeration(SampleEnum)
        enum_obj.read(stream)
        self.assertEqual(SampleEnum.ONE, enum_obj.value)

    def test_read_invalid_encoding(self):
        """Test Enumeration rejects invalid padding bytes."""
        value_bytes = struct.pack('!I', SampleEnum.ONE.value) + b'\x00\x00\x00\x01'
        encoding = _ttlv(self.tag, enums.Types.ENUMERATION, 4, value_bytes)
        stream = utils.BytearrayStream(encoding)
        enum_obj = primitives.Enumeration(SampleEnum)
        self.assertRaises(exceptions.InvalidPaddingBytes,
                          enum_obj.read, stream)

    def test_read_oversized(self):
        """Test Enumeration detects extra bytes after reading."""
        encoding = _encode_unsigned_int(
            self.tag, enums.Types.ENUMERATION, SampleEnum.ONE.value) + b'\x00'
        stream = utils.BytearrayStream(encoding)
        enum_obj = primitives.Enumeration(SampleEnum)
        enum_obj.read(stream)
        self.assertRaises(exceptions.StreamNotEmptyError,
                          enum_obj.is_oversized, stream)

    def test_write_valid(self):
        """Test Enumeration writes a valid TTLV encoding."""
        enum_obj = primitives.Enumeration(SampleEnum, SampleEnum.ONE)
        enum_obj.write(self.stream)
        self.assertEqual(
            _encode_unsigned_int(
                self.tag, enums.Types.ENUMERATION, SampleEnum.ONE.value),
            self.stream.read()
        )

    def test_read_write_roundtrip(self):
        """Test Enumeration read/write round-trip."""
        enum_obj = primitives.Enumeration(SampleEnum, SampleEnum.TWO)
        stream = utils.BytearrayStream()
        enum_obj.write(stream)
        clone = primitives.Enumeration(SampleEnum)
        clone.read(utils.BytearrayStream(stream.read()))
        self.assertEqual(enum_obj.value, clone.value)

    def test_validate_valid(self):
        """Test Enumeration validate accepts valid values."""
        enum_obj = primitives.Enumeration(SampleEnum, SampleEnum.ONE)
        enum_obj.validate()

    def test_validate_invalid_type(self):
        """Test Enumeration validate rejects invalid enum types."""
        self.assertRaises(TypeError, primitives.Enumeration, 'bad', None)

    def test_validate_out_of_range(self):
        """Test Enumeration validate rejects out-of-range values."""
        self.assertRaises(ValueError,
                          primitives.Enumeration, LargeEnum, LargeEnum.TOO_BIG)
        self.assertRaises(ValueError,
                          primitives.Enumeration, LargeEnum, LargeEnum.TOO_SMALL)

    def test_eq_same_value(self):
        """Test Enumeration equality for identical values."""
        self.assertTrue(
            primitives.Enumeration(SampleEnum, SampleEnum.ONE) ==
            primitives.Enumeration(SampleEnum, SampleEnum.ONE)
        )

    def test_eq_different_value(self):
        """Test Enumeration inequality for different values."""
        self.assertFalse(
            primitives.Enumeration(SampleEnum, SampleEnum.ONE) ==
            primitives.Enumeration(SampleEnum, SampleEnum.TWO)
        )

    def test_eq_different_type(self):
        """Test Enumeration equality returns NotImplemented for other types."""
        enum_obj = primitives.Enumeration(SampleEnum, SampleEnum.ONE)
        self.assertIs(enum_obj.__eq__('invalid'), NotImplemented)

    def test_ne(self):
        """Test Enumeration inequality operator."""
        self.assertTrue(
            primitives.Enumeration(SampleEnum, SampleEnum.ONE) !=
            primitives.Enumeration(SampleEnum, SampleEnum.TWO)
        )

    def test_hash_same_value(self):
        """Test Enumeration is unhashable when equality is defined."""
        self.assertRaises(TypeError, hash,
                          primitives.Enumeration(SampleEnum, SampleEnum.ONE))

    def test_repr(self):
        """Test Enumeration representation formatting."""
        enum_obj = primitives.Enumeration(SampleEnum, SampleEnum.ONE)
        self.assertIn('Enumeration(enum=SampleEnum', repr(enum_obj))
        self.assertIn('value=SampleEnum.ONE', repr(enum_obj))
        self.assertIn('tag=Tags.DEFAULT', repr(enum_obj))

    def test_str(self):
        """Test Enumeration string conversion formatting."""
        self.assertEqual('SampleEnum.ONE',
                         str(primitives.Enumeration(SampleEnum, SampleEnum.ONE)))

    def test_boundary_values(self):
        """Test Enumeration boundary values round-trip correctly."""
        for value in (EdgeEnum.MIN, EdgeEnum.MAX):
            enum_obj = primitives.Enumeration(EdgeEnum, value)
            stream = utils.BytearrayStream()
            enum_obj.write(stream)
            clone = primitives.Enumeration(EdgeEnum)
            clone.read(utils.BytearrayStream(stream.read()))
            self.assertEqual(value, clone.value)

    def test_specific_values(self):
        """Test Enumeration with valid and invalid enum values."""
        self.assertEqual(SampleEnum.ONE,
                         primitives.Enumeration(SampleEnum, SampleEnum.ONE).value)
        self.assertRaises(TypeError, primitives.Enumeration, SampleEnum, 'bad')

class TestBoolean(testtools.TestCase):

    def setUp(self):
        super(TestBoolean, self).setUp()
        self.stream = utils.BytearrayStream()
        self.tag = enums.Tags.DEFAULT
        self.other_tag = enums.Tags.ACTIVATION_DATE

    def tearDown(self):
        super(TestBoolean, self).tearDown()

    def test_init_with_none(self):
        """Test Boolean initializes with a None value."""
        boolean = primitives.Boolean(None)
        self.assertIsNone(boolean.value)
        self.assertEqual(primitives.Boolean.LENGTH, boolean.length)

    def test_init_with_valid_value(self):
        """Test Boolean initializes with a valid value."""
        boolean = primitives.Boolean(True)
        self.assertTrue(boolean.value)

    def test_init_with_invalid_value(self):
        """Test Boolean rejects invalid values."""
        self.assertRaises(TypeError, primitives.Boolean, 1)

    def test_init_with_tag(self):
        """Test Boolean stores a custom tag."""
        boolean = primitives.Boolean(True, tag=self.other_tag)
        self.assertEqual(self.other_tag, boolean.tag)

    def test_read_valid_encoding(self):
        """Test Boolean reads a valid TTLV encoding."""
        encoding = _encode_boolean(self.tag, 1)
        stream = utils.BytearrayStream(encoding)
        boolean = primitives.Boolean()
        boolean.read(stream)
        self.assertTrue(boolean.value)

    def test_read_invalid_encoding(self):
        """Test Boolean rejects invalid TTLV values."""
        encoding = _encode_boolean(self.tag, 2)
        stream = utils.BytearrayStream(encoding)
        boolean = primitives.Boolean()
        self.assertRaises(ValueError, boolean.read, stream)

    def test_read_oversized(self):
        """Test Boolean detects extra bytes after reading."""
        encoding = _encode_boolean(self.tag, 0) + b'\x00'
        stream = utils.BytearrayStream(encoding)
        boolean = primitives.Boolean()
        boolean.read(stream)
        self.assertRaises(exceptions.StreamNotEmptyError,
                          boolean.is_oversized, stream)

    def test_write_valid(self):
        """Test Boolean writes a valid TTLV encoding."""
        boolean = primitives.Boolean(True)
        boolean.write(self.stream)
        self.assertEqual(_encode_boolean(self.tag, 1), self.stream.read())

    def test_read_write_roundtrip(self):
        """Test Boolean read/write round-trip."""
        boolean = primitives.Boolean(False)
        stream = utils.BytearrayStream()
        boolean.write(stream)
        clone = primitives.Boolean()
        clone.read(utils.BytearrayStream(stream.read()))
        self.assertFalse(clone.value)

    def test_validate_valid(self):
        """Test Boolean validate accepts valid values."""
        boolean = primitives.Boolean(True)
        boolean.validate()

    def test_validate_invalid_type(self):
        """Test Boolean validate rejects invalid types."""
        self.assertRaises(TypeError, primitives.Boolean, 'bad')

    def test_eq_same_value(self):
        """Test Boolean equality for identical values."""
        self.assertTrue(primitives.Boolean(True) == primitives.Boolean(True))

    def test_eq_different_value(self):
        """Test Boolean inequality for different values."""
        self.assertFalse(primitives.Boolean(True) == primitives.Boolean(False))

    def test_eq_different_type(self):
        """Test Boolean equality returns NotImplemented for other types."""
        boolean = primitives.Boolean(True)
        self.assertIs(boolean.__eq__('invalid'), NotImplemented)

    def test_ne(self):
        """Test Boolean inequality operator."""
        self.assertTrue(primitives.Boolean(True) != primitives.Boolean(False))

    def test_hash_same_value(self):
        """Test Boolean is unhashable when equality is defined."""
        self.assertRaises(TypeError, hash, primitives.Boolean(True))

    def test_repr(self):
        """Test Boolean representation formatting."""
        boolean = primitives.Boolean(True)
        self.assertEqual('Boolean(value=True)', repr(boolean))

    def test_str(self):
        """Test Boolean string conversion formatting."""
        self.assertEqual('True', str(primitives.Boolean(True)))

    def test_boundary_values(self):
        """Test Boolean accepts True and False values."""
        self.assertTrue(primitives.Boolean(True).value)
        self.assertFalse(primitives.Boolean(False).value)

    def test_specific_values(self):
        """Test Boolean handling of True/False/None/0/1."""
        self.assertIsNone(primitives.Boolean(None).value)
        self.assertEqual(0, primitives.Boolean(0).value)
        self.assertTrue(primitives.Boolean(True).value)
        self.assertFalse(primitives.Boolean(False).value)
        self.assertRaises(TypeError, primitives.Boolean, 1)

class TestTextString(testtools.TestCase):

    def setUp(self):
        super(TestTextString, self).setUp()
        self.stream = utils.BytearrayStream()
        self.tag = enums.Tags.DEFAULT
        self.other_tag = enums.Tags.ACTIVATION_DATE

    def tearDown(self):
        super(TestTextString, self).tearDown()

    def test_init_with_none(self):
        """Test TextString initializes with empty string."""
        text = primitives.TextString(None)
        self.assertEqual('', text.value)

    def test_init_with_valid_value(self):
        """Test TextString initializes with a valid value."""
        text = primitives.TextString('test')
        self.assertEqual('test', text.value)

    def test_init_with_invalid_value(self):
        """Test TextString rejects invalid types."""
        self.assertRaises(TypeError, primitives.TextString, b'bad')

    def test_init_with_tag(self):
        """Test TextString stores a custom tag."""
        text = primitives.TextString('test', tag=self.other_tag)
        self.assertEqual(self.other_tag, text.tag)

    def test_read_valid_encoding(self):
        """Test TextString reads a valid TTLV encoding."""
        encoding = _encode_text(self.tag, 'test')
        stream = utils.BytearrayStream(encoding)
        text = primitives.TextString()
        text.read(stream)
        self.assertEqual('test', text.value)

    def test_read_invalid_encoding(self):
        """Test TextString rejects invalid padding bytes."""
        value_bytes = b'test' + b'\x00\x00\x00\x01'
        encoding = _ttlv(self.tag, enums.Types.TEXT_STRING, 4, value_bytes)
        stream = utils.BytearrayStream(encoding)
        text = primitives.TextString()
        self.assertRaises(exceptions.ReadValueError, text.read, stream)

    def test_read_oversized(self):
        """Test TextString detects extra bytes after reading."""
        encoding = _encode_text(self.tag, 'test') + b'\x00'
        stream = utils.BytearrayStream(encoding)
        text = primitives.TextString()
        text.read(stream)
        self.assertRaises(exceptions.StreamNotEmptyError,
                          text.is_oversized, stream)

    def test_write_valid(self):
        """Test TextString writes a valid TTLV encoding."""
        text = primitives.TextString('test')
        text.write(self.stream)
        self.assertEqual(_encode_text(self.tag, 'test'), self.stream.read())

    def test_read_write_roundtrip(self):
        """Test TextString read/write round-trip."""
        text = primitives.TextString('roundtrip')
        stream = utils.BytearrayStream()
        text.write(stream)
        clone = primitives.TextString()
        clone.read(utils.BytearrayStream(stream.read()))
        self.assertEqual(text.value, clone.value)

    def test_validate_valid(self):
        """Test TextString validate accepts valid values."""
        text = primitives.TextString('ok')
        text.validate()

    def test_validate_invalid_type(self):
        """Test TextString validate rejects invalid types."""
        self.assertRaises(TypeError, primitives.TextString, b'bad')

    def test_eq_same_value(self):
        """Test TextString equality for identical values."""
        self.assertTrue(primitives.TextString('a') == primitives.TextString('a'))

    def test_eq_different_value(self):
        """Test TextString inequality for different values."""
        self.assertFalse(primitives.TextString('a') == primitives.TextString('b'))

    def test_eq_different_type(self):
        """Test TextString equality returns NotImplemented for other types."""
        text = primitives.TextString('a')
        self.assertIs(text.__eq__('invalid'), NotImplemented)

    def test_ne(self):
        """Test TextString inequality operator."""
        self.assertTrue(primitives.TextString('a') != primitives.TextString('b'))

    def test_hash_same_value(self):
        """Test TextString is unhashable when equality is defined."""
        self.assertRaises(TypeError, hash, primitives.TextString('a'))

    def test_repr(self):
        """Test TextString representation formatting."""
        text = primitives.TextString('test')
        self.assertEqual("TextString(value='test')", repr(text))

    def test_str(self):
        """Test TextString string conversion formatting."""
        self.assertEqual('test', str(primitives.TextString('test')))

    def test_empty_value(self):
        """Test TextString handles empty values."""
        self.assertEqual('', primitives.TextString('').value)

    def test_boundary_values(self):
        """Test TextString padding boundary lengths."""
        value_eight = 'a' * 8
        value_nine = 'b' * 9
        text_eight = primitives.TextString(value_eight)
        text_nine = primitives.TextString(value_nine)
        self.assertEqual(0, text_eight.padding_length)
        self.assertEqual(7, text_nine.padding_length)

    def test_specific_values(self):
        """Test TextString unicode, empty, and long values."""
        unicode_value = 'Unicode-' + chr(0x2603)
        long_value = 'x' * 1024
        self.assertEqual(unicode_value,
                         primitives.TextString(unicode_value).value)
        self.assertEqual('', primitives.TextString('').value)
        self.assertEqual(long_value, primitives.TextString(long_value).value)

class TestByteString(testtools.TestCase):

    def setUp(self):
        super(TestByteString, self).setUp()
        self.stream = utils.BytearrayStream()
        self.tag = enums.Tags.DEFAULT
        self.other_tag = enums.Tags.ACTIVATION_DATE

    def tearDown(self):
        super(TestByteString, self).tearDown()

    def test_init_with_none(self):
        """Test ByteString initializes with empty bytes."""
        data = primitives.ByteString(None)
        self.assertEqual(b'', data.value)

    def test_init_with_valid_value(self):
        """Test ByteString initializes with a valid value."""
        data = primitives.ByteString(b'\x01\x02')
        self.assertEqual(b'\x01\x02', data.value)

    def test_init_with_invalid_value(self):
        """Test ByteString rejects invalid types."""
        self.assertRaises(TypeError, primitives.ByteString, 'bad')

    def test_init_with_tag(self):
        """Test ByteString stores a custom tag."""
        data = primitives.ByteString(b'\x01', tag=self.other_tag)
        self.assertEqual(self.other_tag, data.tag)

    def test_read_valid_encoding(self):
        """Test ByteString reads a valid TTLV encoding."""
        encoding = _encode_bytes(self.tag, b'\x01\x02\x03')
        stream = utils.BytearrayStream(encoding)
        data = primitives.ByteString()
        data.read(stream)
        self.assertEqual(b'\x01\x02\x03', data.value)

    def test_read_invalid_encoding(self):
        """Test ByteString rejects invalid padding bytes."""
        value_bytes = b'\x01\x02\x03' + b'\x00\x00\x00\x01\x00'
        encoding = _ttlv(self.tag, enums.Types.BYTE_STRING, 3, value_bytes)
        stream = utils.BytearrayStream(encoding)
        data = primitives.ByteString()
        self.assertRaises(exceptions.ReadValueError, data.read, stream)

    def test_read_oversized(self):
        """Test ByteString detects extra bytes after reading."""
        encoding = _encode_bytes(self.tag, b'\x01') + b'\x00'
        stream = utils.BytearrayStream(encoding)
        data = primitives.ByteString()
        data.read(stream)
        self.assertRaises(exceptions.StreamNotEmptyError,
                          data.is_oversized, stream)

    def test_write_valid(self):
        """Test ByteString writes a valid TTLV encoding."""
        data = primitives.ByteString(b'\x01\x02\x03')
        data.write(self.stream)
        self.assertEqual(
            _encode_bytes(self.tag, b'\x01\x02\x03'),
            self.stream.read()
        )

    def test_read_write_roundtrip(self):
        """Test ByteString read/write round-trip."""
        data = primitives.ByteString(b'roundtrip')
        stream = utils.BytearrayStream()
        data.write(stream)
        clone = primitives.ByteString()
        clone.read(utils.BytearrayStream(stream.read()))
        self.assertEqual(data.value, clone.value)

    def test_validate_valid(self):
        """Test ByteString validate accepts valid values."""
        data = primitives.ByteString(b'\x01')
        data.validate()

    def test_validate_invalid_type(self):
        """Test ByteString validate rejects invalid types."""
        self.assertRaises(TypeError, primitives.ByteString, 'bad')

    def test_eq_same_value(self):
        """Test ByteString equality for identical values."""
        self.assertTrue(primitives.ByteString(b'a') ==
                        primitives.ByteString(b'a'))

    def test_eq_different_value(self):
        """Test ByteString inequality for different values."""
        self.assertFalse(primitives.ByteString(b'a') ==
                         primitives.ByteString(b'b'))

    def test_eq_different_type(self):
        """Test ByteString equality returns NotImplemented for other types."""
        data = primitives.ByteString(b'a')
        self.assertIs(data.__eq__('invalid'), NotImplemented)

    def test_ne(self):
        """Test ByteString inequality operator."""
        self.assertTrue(primitives.ByteString(b'a') !=
                        primitives.ByteString(b'b'))

    def test_hash_same_value(self):
        """Test ByteString is unhashable when equality is defined."""
        self.assertRaises(TypeError, hash, primitives.ByteString(b'a'))

    def test_repr(self):
        """Test ByteString representation formatting."""
        data = primitives.ByteString(b'\x01')
        self.assertEqual("ByteString(value=b'\\x01')", repr(data))

    def test_str(self):
        """Test ByteString string conversion formatting."""
        self.assertEqual("b'\\x01'", str(primitives.ByteString(b'\x01')))

    def test_empty_value(self):
        """Test ByteString handles empty values."""
        self.assertEqual(b'', primitives.ByteString(b'').value)

    def test_boundary_values(self):
        """Test ByteString padding boundary lengths."""
        value_eight = b'a' * 8
        value_nine = b'b' * 9
        data_eight = primitives.ByteString(value_eight)
        data_nine = primitives.ByteString(value_nine)
        self.assertEqual(0, data_eight.padding_length)
        self.assertEqual(7, data_nine.padding_length)

    def test_specific_values(self):
        """Test ByteString empty and repeated byte values."""
        self.assertEqual(b'', primitives.ByteString(b'').value)
        self.assertEqual(b'\x00' * 16,
                         primitives.ByteString(b'\x00' * 16).value)

class TestDateTime(testtools.TestCase):

    def setUp(self):
        super(TestDateTime, self).setUp()
        self.stream = utils.BytearrayStream()
        self.tag = enums.Tags.DEFAULT
        self.other_tag = enums.Tags.ACTIVATION_DATE

    def tearDown(self):
        super(TestDateTime, self).tearDown()

    def test_init_with_none(self):
        """Test DateTime initializes from current time."""
        with mock.patch('time.time', return_value=1234567890):
            date_time = primitives.DateTime()
        self.assertEqual(1234567890, date_time.value)

    def test_init_with_valid_value(self):
        """Test DateTime initializes with a valid value."""
        date_time = primitives.DateTime(0)
        self.assertEqual(0, date_time.value)

    def test_init_with_invalid_value(self):
        """Test DateTime rejects invalid types."""
        self.assertRaises(TypeError, primitives.DateTime, 'invalid')

    def test_init_with_tag(self):
        """Test DateTime stores a custom tag."""
        date_time = primitives.DateTime(0, tag=self.other_tag)
        self.assertEqual(self.other_tag, date_time.tag)

    def test_read_valid_encoding(self):
        """Test DateTime reads a valid TTLV encoding."""
        encoding = _encode_long_integer(
            self.tag, enums.Types.DATE_TIME, 0)
        stream = utils.BytearrayStream(encoding)
        date_time = primitives.DateTime(0)
        date_time.read(stream)
        self.assertEqual(0, date_time.value)

    def test_read_invalid_encoding(self):
        """Test DateTime rejects invalid TTLV lengths."""
        encoding = _ttlv(self.tag, enums.Types.DATE_TIME, 4, b'')
        stream = utils.BytearrayStream(encoding)
        date_time = primitives.DateTime(0)
        self.assertRaises(exceptions.InvalidPrimitiveLength,
                          date_time.read, stream)

    def test_read_oversized(self):
        """Test DateTime detects extra bytes after reading."""
        encoding = _encode_long_integer(
            self.tag, enums.Types.DATE_TIME, 0) + b'\x00'
        stream = utils.BytearrayStream(encoding)
        date_time = primitives.DateTime(0)
        date_time.read(stream)
        self.assertRaises(exceptions.StreamNotEmptyError,
                          date_time.is_oversized, stream)

    def test_write_valid(self):
        """Test DateTime writes a valid TTLV encoding."""
        date_time = primitives.DateTime(0)
        date_time.write(self.stream)
        self.assertEqual(
            _encode_long_integer(self.tag, enums.Types.DATE_TIME, 0),
            self.stream.read()
        )

    def test_read_write_roundtrip(self):
        """Test DateTime read/write round-trip."""
        date_time = primitives.DateTime(1439299135)
        stream = utils.BytearrayStream()
        date_time.write(stream)
        clone = primitives.DateTime(0)
        clone.read(utils.BytearrayStream(stream.read()))
        self.assertEqual(date_time.value, clone.value)

    def test_validate_valid(self):
        """Test DateTime validate accepts valid values."""
        date_time = primitives.DateTime(0)
        date_time.validate()

    def test_validate_invalid_type(self):
        """Test DateTime validate rejects invalid types."""
        self.assertRaises(TypeError, primitives.DateTime, 'bad')

    def test_validate_out_of_range(self):
        """Test DateTime validate rejects out-of-range values."""
        self.assertRaises(ValueError, primitives.DateTime,
                          primitives.LongInteger.MAX + 1)

    def test_eq_same_value(self):
        """Test DateTime equality for identical values."""
        self.assertTrue(primitives.DateTime(1) == primitives.DateTime(1))

    def test_eq_different_value(self):
        """Test DateTime inequality for different values."""
        self.assertFalse(primitives.DateTime(1) == primitives.DateTime(2))

    def test_eq_different_type(self):
        """Test DateTime equality returns NotImplemented for other types."""
        date_time = primitives.DateTime(1)
        self.assertIs(date_time.__eq__('invalid'), NotImplemented)

    def test_ne(self):
        """Test DateTime inequality operator."""
        self.assertTrue(primitives.DateTime(1) != primitives.DateTime(2))

    def test_hash_same_value(self):
        """Test DateTime is unhashable when equality is defined."""
        self.assertRaises(TypeError, hash, primitives.DateTime(1))

    def test_repr(self):
        """Test DateTime representation formatting."""
        date_time = primitives.DateTime(0)
        self.assertEqual(
            'DateTime(value=0, tag={0})'.format(enums.Tags.DEFAULT),
            repr(date_time)
        )

    def test_str(self):
        """Test DateTime string conversion formatting."""
        self.assertEqual('Thu Jan  1 00:00:00 1970',
                         str(primitives.DateTime(0)))

    def test_boundary_values(self):
        """Test DateTime boundary values round-trip correctly."""
        values = [0, 1, 2147483648]
        for value in values:
            date_time = primitives.DateTime(value)
            stream = utils.BytearrayStream()
            date_time.write(stream)
            clone = primitives.DateTime(0)
            clone.read(utils.BytearrayStream(stream.read()))
            self.assertEqual(value, clone.value)

    def test_specific_values(self):
        """Test DateTime epoch, current time, and future values."""
        with mock.patch('time.time', return_value=100):
            now = primitives.DateTime()
        future = primitives.DateTime(100000)
        epoch = primitives.DateTime(0)
        self.assertEqual(100, now.value)
        self.assertEqual(100000, future.value)
        self.assertEqual(0, epoch.value)

class TestInterval(testtools.TestCase):

    def setUp(self):
        super(TestInterval, self).setUp()
        self.stream = utils.BytearrayStream()
        self.tag = enums.Tags.DEFAULT
        self.other_tag = enums.Tags.ACTIVATION_DATE

    def tearDown(self):
        super(TestInterval, self).tearDown()

    def test_init_with_none(self):
        """Test Interval initializes with default values."""
        interval = primitives.Interval()
        self.assertEqual(0, interval.value)
        self.assertEqual(primitives.Interval.LENGTH, interval.length)

    def test_init_with_valid_value(self):
        """Test Interval initializes with a valid value."""
        interval = primitives.Interval(5)
        self.assertEqual(5, interval.value)

    def test_init_with_invalid_value(self):
        """Test Interval rejects invalid types."""
        self.assertRaises(TypeError, primitives.Interval, 'invalid')

    def test_init_with_tag(self):
        """Test Interval stores a custom tag."""
        interval = primitives.Interval(1, tag=self.other_tag)
        self.assertEqual(self.other_tag, interval.tag)

    def test_read_valid_encoding(self):
        """Test Interval reads a valid TTLV encoding."""
        encoding = _encode_unsigned_int(self.tag, enums.Types.INTERVAL, 5)
        stream = utils.BytearrayStream(encoding)
        interval = primitives.Interval()
        interval.read(stream)
        self.assertEqual(5, interval.value)

    def test_read_invalid_encoding(self):
        """Test Interval rejects invalid TTLV lengths."""
        encoding = _ttlv(self.tag, enums.Types.INTERVAL, 8, b'')
        stream = utils.BytearrayStream(encoding)
        interval = primitives.Interval()
        self.assertRaises(exceptions.InvalidPrimitiveLength,
                          interval.read, stream)

    def test_read_oversized(self):
        """Test Interval detects extra bytes after reading."""
        encoding = _encode_unsigned_int(self.tag, enums.Types.INTERVAL, 5) + b'\x00'
        stream = utils.BytearrayStream(encoding)
        interval = primitives.Interval()
        interval.read(stream)
        self.assertRaises(exceptions.StreamNotEmptyError,
                          interval.is_oversized, stream)

    def test_write_valid(self):
        """Test Interval writes a valid TTLV encoding."""
        interval = primitives.Interval(5)
        interval.write(self.stream)
        self.assertEqual(
            _encode_unsigned_int(self.tag, enums.Types.INTERVAL, 5),
            self.stream.read()
        )

    def test_read_write_roundtrip(self):
        """Test Interval read/write round-trip."""
        interval = primitives.Interval(123)
        stream = utils.BytearrayStream()
        interval.write(stream)
        clone = primitives.Interval()
        clone.read(utils.BytearrayStream(stream.read()))
        self.assertEqual(interval.value, clone.value)

    def test_validate_valid(self):
        """Test Interval validate accepts valid values."""
        interval = primitives.Interval(0)
        interval.validate()

    def test_validate_invalid_type(self):
        """Test Interval validate rejects invalid types."""
        self.assertRaises(TypeError, primitives.Interval, 'bad')

    def test_validate_out_of_range(self):
        """Test Interval validate rejects out-of-range values."""
        self.assertRaises(ValueError, primitives.Interval,
                          primitives.Interval.MAX + 1)
        self.assertRaises(ValueError, primitives.Interval,
                          primitives.Interval.MIN - 1)

    def test_eq_same_value(self):
        """Test Interval equality for identical values."""
        self.assertTrue(primitives.Interval(1) == primitives.Interval(1))

    def test_eq_different_value(self):
        """Test Interval inequality for different values."""
        self.assertFalse(primitives.Interval(1) == primitives.Interval(2))

    def test_eq_different_type(self):
        """Test Interval equality returns NotImplemented for other types."""
        interval = primitives.Interval(1)
        self.assertIs(interval.__eq__('invalid'), NotImplemented)

    def test_ne(self):
        """Test Interval inequality operator."""
        self.assertTrue(primitives.Interval(1) != primitives.Interval(2))

    def test_hash_same_value(self):
        """Test Interval is unhashable when equality is defined."""
        self.assertRaises(TypeError, hash, primitives.Interval(1))

    def test_repr(self):
        """Test Interval representation formatting."""
        interval = primitives.Interval(5)
        self.assertEqual(
            'Interval(value=5, tag={0})'.format(enums.Tags.DEFAULT),
            repr(interval)
        )

    def test_str(self):
        """Test Interval string conversion formatting."""
        self.assertEqual('5', str(primitives.Interval(5)))

    def test_boundary_values(self):
        """Test Interval boundary values round-trip correctly."""
        values = [primitives.Interval.MIN, 0, primitives.Interval.MAX]
        for value in values:
            interval = primitives.Interval(value)
            stream = utils.BytearrayStream()
            interval.write(stream)
            clone = primitives.Interval()
            clone.read(utils.BytearrayStream(stream.read()))
            self.assertEqual(value, clone.value)
