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

from six import string_types
from testtools import TestCase

from kmip.core.enums import Tags
from kmip.core.enums import Types

from kmip.core.utils import BytearrayStream

import kmip.core.errors as errors
from kmip.core.errors import ErrorStrings

from kmip.core.primitives import Base
from kmip.core.primitives import Integer
from kmip.core.primitives import LongInteger
from kmip.core.primitives import BigInteger
from kmip.core.primitives import Enumeration
from kmip.core.primitives import TextString
from kmip.core.primitives import ByteString


class TestBase(TestCase):

    def setUp(self):
        super(TestBase, self).setUp()
        self.stream = BytearrayStream()
        self.bad_init = 'Bad Base initialization: attribute {0} missing'
        self.bad_write = ErrorStrings.BAD_EXP_RECV.format('Base.{0}', 'write',
                                                          '{1}', '{2}')
        self.bad_encoding = ErrorStrings.BAD_ENCODING.format('Base.{0}',
                                                             'write')
        self.bad_match = ErrorStrings.BAD_EXP_RECV.format('Base.{0}',
                                                          'comparison', '{1}',
                                                          '{2}')

    def tearDown(self):
        super(TestBase, self).tearDown()

    def test_is_oversized(self):
        base = Base()

        # Check no exception thrown
        base.is_oversized(self.stream)

    def test_is_oversized_error(self):
        self.stream.write(b'\x00')
        base = Base()

        self.assertRaises(errors.StreamNotEmptyError, base.is_oversized,
                          self.stream)

    def test_read_tag(self):
        encoding = (b'\x42\x00\x00')
        base = Base()
        self.stream = BytearrayStream(encoding)

        # Check no exception thrown
        base.read_tag(self.stream)

    def test_read_tag_invalid(self):
        encoding = (b'\x42\x00\x01')
        base = Base()
        self.stream = BytearrayStream(encoding)

        self.assertRaises(errors.ReadValueError, base.read_tag, self.stream)

    def test_read_type(self):
        self.stream.write(b'\x00')
        base = Base()

        # Check no exception thrown
        base.read_type(self.stream)

    def test_read_type_error(self):
        self.stream.write(b'\x01')
        base = Base()

        self.assertRaises(errors.ReadValueError, base.read_type, self.stream)

    def test_read_type_underflow(self):
        base = Base()

        self.assertRaises(errors.ReadValueError, base.read_type,
                          self.stream)

    def test_read_type_overflow(self):
        self.stream.write(b'\x00\x00')
        base = Base()

        # Check no exception thrown
        base.read_type(self.stream)

    def test_read_length(self):
        self.stream.write(b'\x00\x00\x00\x04')
        base = Base()
        base.length = 4

        # Check no exception thrown
        base.read_length(self.stream)

    def test_read_length_underflow(self):
        self.stream.write(b'\x00')
        base = Base()
        base.length = 4

        self.assertRaises(errors.ReadValueError, base.read_length,
                          self.stream)

    def test_read_length_overflow(self):
        self.stream.write(b'\x00\x00\x00\x04\x00')
        base = Base()
        base.length = 4

        # Check no exception thrown
        base.read_length(self.stream)

    def test_read_value(self):
        base = Base()

        self.assertRaises(NotImplementedError, base.read_value, self.stream)

    def test_read(self):
        self.stream.write(b'\x42\x00\x00\x00\x00\x00\x00\x04')
        base = Base()
        base.length = 4

        # Check no exception thrown
        base.read(self.stream)

    def test_write_tag(self):
        encoding = (b'\x42\x00\x00')
        base = Base()
        base.write_tag(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv,
                         self.bad_write.format('tag',
                                               '{0} bytes'.format(len_exp),
                                               '{0} bytes'.format(len_rcv)))
        self.assertEqual(encoding, result, self.bad_encoding.format('tag'))

    def test_write_type(self):
        encoding = b'\x00'
        base = Base()
        base.write_type(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv,
                         self.bad_write.format('type',
                                               '{0} bytes'.format(len_exp),
                                               '{0} bytes'.format(len_rcv)))
        self.assertEqual(encoding, result, self.bad_encoding.format('type'))

    def test_write_type_invalid(self):
        base = Base()
        base.type = ''

        self.assertRaises(TypeError, base.write_type, self.stream)

    def test_write_length(self):
        encoding = b'\x00\x00\x00\x04'
        base = Base()
        base.length = 4
        base.write_length(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv,
                         self.bad_write.format('length',
                                               '{0} bytes'.format(len_exp),
                                               '{0} bytes'.format(len_rcv)))
        self.assertEqual(encoding, result, self.bad_encoding.format('length'))

    def test_write_length_invalid(self):
        base = Base()
        base.length = ''

        self.assertRaises(TypeError, base.write_length, self.stream)

    def test_write_length_overflow(self):
        self.skip('No easy way to test with a number requiring more than '
                  '2 ** 0xffffffff bytes for representation. Test preserved '
                  'for completeness.')

    def test_write_value(self):
        base = Base()

        self.assertRaises(NotImplementedError, base.write_value, self.stream)

    def test_write(self):
        encoding = b'\x42\x00\x00\x00\x00\x00\x00\x04'
        base = Base()
        base.length = 4
        base.write(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv,
                         self.bad_write.format('type/length',
                                               '{0} bytes'.format(len_exp),
                                               '{0} bytes'.format(len_rcv)))
        self.assertEqual(encoding, result,
                         self.bad_encoding.format('type/length'))

    def test_is_tag_next(self):
        encoding = (b'\x42\x00\x00')
        base = Base()
        self.stream = BytearrayStream(encoding)

        self.assertTrue(Base.is_tag_next(base.tag, self.stream),
                        self.bad_match.format('tag', 'match', 'mismatch'))

    def test_is_tag_next_invalid(self):
        encoding = (b'\x42\x00\x01')
        base = Base()
        self.stream = BytearrayStream(encoding)

        self.assertFalse(Base.is_tag_next(base.tag, self.stream),
                         self.bad_match.format('tag', 'mismatch', 'match'))


class TestInteger(TestCase):

    def setUp(self):
        super(TestInteger, self).setUp()
        self.stream = BytearrayStream()
        self.max_byte_int = 4294967295
        self.max_int = 2147483647
        self.bad_value = ('Bad Integer.{0} after init: expected {1}, '
                          'received {2}')
        self.bad_write = ('Bad Integer write: expected {0} bytes, '
                          'received {1} bytes')
        self.bad_encoding = 'Bad Integer write: encoding mismatch'
        self.bad_read = ('Bad Integer.value read: expected {0}, received {1}')

    def tearDown(self):
        super(TestInteger, self).tearDown()

    def test_init(self):
        i = Integer(0)

        self.assertEqual(0, i.value,
                         self.bad_value.format('value', 0, i.value))
        self.assertEqual(i.LENGTH, i.length,
                         self.bad_value.format('length', i.LENGTH, i.length))
        self.assertEqual(i.LENGTH, i.padding_length,
                         self.bad_value.format('padding_length', i.LENGTH,
                                               i.padding_length))

    def test_init_unset(self):
        i = Integer()

        self.assertEqual(0, i.value,
                         self.bad_value.format('value', 0, i.value))
        self.assertEqual(i.LENGTH, i.length,
                         self.bad_value.format('length', i.LENGTH, i.length))
        self.assertEqual(i.LENGTH, i.padding_length,
                         self.bad_value.format('padding_length', i.LENGTH,
                                               i.padding_length))

    def test_validate_on_valid(self):
        i = Integer()
        i.value = 0

        # Check no exception thrown
        i.validate()

    def test_validate_on_valid_unset(self):
        i = Integer()

        # Check no exception thrown
        i.validate()

    def test_validate_on_invalid_type(self):
        i = Integer()
        i.value = 'test'

        self.assertRaises(errors.StateTypeError, i.validate)

    def test_validate_on_invalid_value(self):
        self.assertRaises(errors.StateOverflowError, Integer,
                          self.max_byte_int + 1)

    def test_read_value(self):
        encoding = (b'\x00\x00\x00\x01\x00\x00\x00\x00')
        self.stream = BytearrayStream(encoding)
        i = Integer()
        i.read_value(self.stream)

        self.assertEqual(1, i.value, self.bad_read.format(1, i.value))

    def test_read_value_zero(self):
        encoding = (b'\x00\x00\x00\x00\x00\x00\x00\x00')
        self.stream = BytearrayStream(encoding)
        i = Integer()
        i.read_value(self.stream)

        self.assertEqual(0, i.value, self.bad_read.format(0, i.value))

    def test_read_value_max_positive(self):
        encoding = (b'\x7f\xff\xff\xff\x00\x00\x00\x00')
        self.stream = BytearrayStream(encoding)
        i = Integer()
        i.read_value(self.stream)

        self.assertEqual(self.max_int, i.value,
                         self.bad_read.format(1, i.value))

    def test_read_value_min_negative(self):
        encoding = (b'\xff\xff\xff\xff\x00\x00\x00\x00')
        self.stream = BytearrayStream(encoding)
        i = Integer()
        i.read_value(self.stream)

        self.assertEqual(-1, i.value,
                         self.bad_read.format(1, i.value))

    def test_read(self):
        encoding = (b'\x42\x00\x00\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00'
                    b'\x00\x00')
        self.stream = BytearrayStream(encoding)
        i = Integer()
        i.read(self.stream)

        self.assertEqual(1, i.value, self.bad_read.format(1, i.value))

    def test_read_on_invalid_length(self):
        encoding = (b'\x42\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    b'\x00\x00')
        self.stream = BytearrayStream(encoding)
        i = Integer()

        self.assertRaises(errors.ReadValueError, i.read, self.stream)

    def test_read_on_invalid_padding(self):
        encoding = (b'\x42\x00\x00\x02\x00\x00\x00\x04\x00\x00\x00\x00\xff\xff'
                    b'\xff\xff')
        self.stream = BytearrayStream(encoding)
        i = Integer()

        self.assertRaises(errors.ReadValueError, i.read, self.stream)

    def test_write_value(self):
        encoding = (b'\x00\x00\x00\x01\x00\x00\x00\x00')
        i = Integer(1)
        i.write_value(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv, self.bad_write.format(len_exp,
                                                                 len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)

    def test_write_value_zero(self):
        encoding = (b'\x00\x00\x00\x00\x00\x00\x00\x00')
        i = Integer(0)
        i.write_value(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv, self.bad_write.format(len_exp,
                                                                 len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)

    def test_write_value_max_positive(self):
        encoding = (b'\x7f\xff\xff\xff\x00\x00\x00\x00')
        i = Integer(self.max_int)
        i.write_value(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv, self.bad_write.format(len_exp,
                                                                 len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)

    def test_write_value_min_negative(self):
        encoding = (b'\xff\xff\xff\xff\x00\x00\x00\x00')
        i = Integer(-1)
        i.write_value(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv, self.bad_write.format(len_exp,
                                                                 len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)

    def test_write(self):
        encoding = (b'\x42\x00\x00\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00'
                    b'\x00\x00')
        i = Integer(1)
        i.write(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv, self.bad_write.format(len_exp,
                                                                 len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)


class TestLongInteger(TestCase):

    def setUp(self):
        super(TestLongInteger, self).setUp()
        self.stream = BytearrayStream()
        self.max_byte_long = 18446744073709551615
        self.max_long = 9223372036854775807
        self.bad_value = ('Bad LongInteger.{0} after init: expected {1}, '
                          'received {2}')
        self.bad_write = ('Bad LongInteger write: expected {0} bytes, '
                          'received {1} bytes')
        self.bad_encoding = 'Bad LongInteger write: encoding mismatch'
        self.bad_read = ('Bad LongInteger.value read: expected {0}, received '
                         '{1}')

    def tearDown(self):
        super(TestLongInteger, self).tearDown()

    def test_init(self):
        i = LongInteger(0)

        self.assertEqual(0, i.value,
                         self.bad_value.format('value', 0, i.value))
        self.assertEqual(i.LENGTH, i.length,
                         self.bad_value.format('length', i.LENGTH, i.length))

    def test_init_unset(self):
        i = LongInteger()

        self.assertEqual(None, i.value,
                         self.bad_value.format('value', None, i.value))
        self.assertEqual(i.LENGTH, i.length,
                         self.bad_value.format('length', i.LENGTH, i.length))

    def test_validate_on_valid(self):
        i = LongInteger()
        i.value = 0

        # Check no exception thrown
        i.validate()

    def test_validate_on_valid_long(self):
        i = LongInteger()
        i.value = self.max_long + 1

        # Check no exception thrown
        i.validate()

    def test_validate_on_valid_unset(self):
        i = LongInteger()

        # Check no exception thrown
        i.validate()

    def test_validate_on_invalid_type(self):
        i = LongInteger()
        i.value = 'test'

        self.assertRaises(errors.StateTypeError, i.validate)

    def test_validate_on_invalid_value(self):
        self.assertRaises(errors.StateOverflowError, LongInteger,
                          self.max_byte_long + 1)

    def test_read_value(self):
        encoding = (b'\x00\x00\x00\x00\x00\x00\x00\x01')
        self.stream = BytearrayStream(encoding)
        i = LongInteger()
        i.read_value(self.stream)

        self.assertEqual(1, i.value, self.bad_read.format(1, i.value))

    def test_read_value_zero(self):
        encoding = (b'\x00\x00\x00\x00\x00\x00\x00\x00')
        self.stream = BytearrayStream(encoding)
        i = LongInteger()
        i.read_value(self.stream)

        self.assertEqual(0, i.value, self.bad_read.format(0, i.value))

    def test_read_value_max_positive(self):
        encoding = (b'\x7f\xff\xff\xff\xff\xff\xff\xff')
        self.stream = BytearrayStream(encoding)
        i = LongInteger()
        i.read_value(self.stream)

        self.assertEqual(self.max_long, i.value,
                         self.bad_read.format(1, i.value))

    def test_read_value_min_negative(self):
        encoding = (b'\xff\xff\xff\xff\xff\xff\xff\xff')
        self.stream = BytearrayStream(encoding)
        i = LongInteger()
        i.read_value(self.stream)

        self.assertEqual(-1, i.value,
                         self.bad_read.format(1, i.value))

    def test_read(self):
        encoding = (b'\x42\x00\x00\x03\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00'
                    b'\x00\x01')
        self.stream = BytearrayStream(encoding)
        i = LongInteger()
        i.read(self.stream)

        self.assertEqual(1, i.value, self.bad_read.format(1, i.value))

    def test_read_on_invalid_length(self):
        encoding = (b'\x42\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    b'\x00\x00')
        self.stream = BytearrayStream(encoding)
        i = LongInteger()

        self.assertRaises(errors.ReadValueError, i.read, self.stream)

    def test_write_value(self):
        encoding = (b'\x00\x00\x00\x00\x00\x00\x00\x01')
        i = LongInteger(1)
        i.write_value(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv, self.bad_write.format(len_exp,
                                                                 len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)

    def test_write_value_zero(self):
        encoding = (b'\x00\x00\x00\x00\x00\x00\x00\x00')
        i = LongInteger(0)
        i.write_value(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv, self.bad_write.format(len_exp,
                                                                 len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)

    def test_write_value_max_positive(self):
        encoding = (b'\x7f\xff\xff\xff\xff\xff\xff\xff')
        i = LongInteger(self.max_long)
        i.write_value(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv, self.bad_write.format(len_exp,
                                                                 len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)

    def test_write_value_min_negative(self):
        encoding = (b'\xff\xff\xff\xff\xff\xff\xff\xff')
        i = LongInteger(-1)
        i.write_value(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv, self.bad_write.format(len_exp,
                                                                 len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)

    def test_write(self):
        encoding = (b'\x42\x00\x00\x03\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00'
                    b'\x00\x01')
        i = LongInteger(1)
        i.write(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv, self.bad_write.format(len_exp,
                                                                 len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)


class TestBigInteger(TestCase):

    def setUp(self):
        super(TestBigInteger, self).setUp()
        self.stream = BytearrayStream()
        self.max_byte_long = 18446744073709551615
        self.max_long = 9223372036854775807
        self.bad_value = ('Bad BigInteger.{0} after init: expected {1}, '
                          'received {2}')
        self.bad_write = ('Bad BigInteger write: expected {0} bytes, '
                          'received {1} bytes')
        self.bad_encoding = 'Bad BigInteger write: encoding mismatch'
        self.bad_read = ('Bad BigInteger.value read: expected {0}, '
                         'received {1}')

    def tearDown(self):
        super(TestBigInteger, self).tearDown()

    def test_big_integer(self):
        self.skip('BigInteger implementation incomplete')
        i = BigInteger(0)

        self.assertEqual(0, i.value,
                         self.bad_value.format('value', 0, i.value))
        self.assertEqual(1, i.length,
                         self.bad_value.format('length', 1, i.length))
        self.assertEqual(i.BLOCK_SIZE - 1, i.padding_length,
                         self.bad_value.format('padding_length',
                                               i.BLOCK_SIZE - 1,
                                               i.padding_length))

    def test_big_integer_unset(self):
        self.skip('BigInteger implementation incomplete')
        i = BigInteger()

        self.assertEqual(None, i.value,
                         self.bad_value.format('value', None, i.value))
        self.assertEqual(None, i.length,
                         self.bad_value.format('length', None, i.length))
        self.assertEqual(None, i.padding_length,
                         self.bad_value.format('padding_length', None,
                                               i.padding_length))

    def test_validate_on_valid(self):
        self.skip('BigInteger implementation incomplete')
        i = BigInteger()
        i.value = 0
        i.length = i.BLOCK_SIZE
        i.padding_length = 0

        # Check no exception thrown
        i.validate()

    def test_validate_on_valid_long(self):
        self.skip('BigInteger implementation incomplete')
        i = BigInteger()
        i.value = self.max_long + 1
        i.length = i.BLOCK_SIZE
        i.padding_length = 0

        # Check no exception thrown
        i.validate()

    def test_validate_on_valid_unset(self):
        self.skip('BigInteger implementation incomplete')
        i = BigInteger()

        # Check no exception thrown
        i.validate()

    def test_validate_on_invalid_type(self):
        self.skip('BigInteger implementation incomplete')
        i = BigInteger()
        i.value = 'test'

        self.assertRaises(errors.StateTypeError, i.validate)

    def test_write(self):
        self.skip('BigInteger implementation incomplete')
        encoding = (b'\x42\x00\x01\x04\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00'
                    b'\x00\x01')
        i = BigInteger(1)
        i.TAG = Tags.ACTIVATION_DATE
        i.write(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv, self.bad_write.format(len_exp,
                                                                 len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)

    def test_write_zero(self):
        self.skip('BigInteger implementation incomplete')
        encoding = (b'\x42\x00\x01\x04\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00'
                    b'\x00\x00')
        i = BigInteger(0)
        i.TAG = Tags.ACTIVATION_DATE
        i.write(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv, self.bad_write.format(len_exp,
                                                                 len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)

    def test_write_max_positive_value(self):
        self.skip('BigInteger implementation incomplete')
        encoding = (b'\x42\x00\x01\x04\x00\x00\x00\x08\x7f\xff\xff\xff\xff\xff'
                    b'\xff\xff')
        i = BigInteger(self.max_long)
        i.TAG = Tags.ACTIVATION_DATE
        i.write(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv, self.bad_write.format(len_exp,
                                                                 len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)

    def test_write_min_negative_value(self):
        self.skip('BigInteger implementation incomplete')
        encoding = (b'\x42\x00\x01\x04\x00\x00\x00\x08\xff\xff\xff\xff\xff\xff'
                    b'\xff\xff')
        i = BigInteger(-1)
        i.TAG = Tags.ACTIVATION_DATE
        i.write(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv, self.bad_write.format(len_exp,
                                                                 len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)

    def test_read(self):
        self.skip('BigInteger implementation incomplete')
        encoding = (b'\x42\x00\x01\x04\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00'
                    b'\x00\x01')
        self.stream = BytearrayStream(encoding)
        i = BigInteger()
        i.TAG = Tags.ACTIVATION_DATE
        i.read(self.stream)

        self.assertEqual(1, i.value, self.bad_read.format(1, i.value))

    def test_read_zero(self):
        self.skip('BigInteger implementation incomplete')
        encoding = (b'\x42\x00\x01\x04\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00'
                    b'\x00\x00')
        self.stream = BytearrayStream(encoding)
        i = BigInteger()
        i.TAG = Tags.ACTIVATION_DATE
        i.read(self.stream)

        self.assertEqual(0, i.value, self.bad_read.format(0, i.value))

    def test_read_max_positive_value(self):
        self.skip('BigInteger implementation incomplete')
        encoding = (b'\x42\x00\x01\x04\x00\x00\x00\x08\x7f\xff\xff\xff\xff\xff'
                    b'\xff\xff')
        self.stream = BytearrayStream(encoding)
        i = BigInteger()
        i.TAG = Tags.ACTIVATION_DATE
        i.read(self.stream)

        self.assertEqual(self.max_long, i.value,
                         self.bad_read.format(1, i.value))

    def test_read_min_negative_value(self):
        self.skip('BigInteger implementation incomplete')
        encoding = (b'\x42\x00\x01\x04\x00\x00\x00\x08\xff\xff\xff\xff\xff\xff'
                    b'\xff\xff')
        self.stream = BytearrayStream(encoding)
        i = BigInteger()
        i.TAG = Tags.ACTIVATION_DATE
        i.read(self.stream)

        self.assertEqual(-1, i.value,
                         self.bad_read.format(1, i.value))

    def test_read_on_invalid_length(self):
        self.skip('BigInteger implementation incomplete')
        encoding = (b'\x42\x00\x01\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    b'\x00\x00')
        self.stream = BytearrayStream(encoding)
        i = BigInteger()
        i.TAG = Tags.ACTIVATION_DATE

        self.assertRaises(errors.InvalidLengthError, i.read, self.stream)


class TestEnumeration(TestCase):

    def setUp(self):
        super(TestEnumeration, self).setUp()
        self.stream = BytearrayStream()
        Enumeration.ENUM_TYPE = Types
        self.bad_type = ErrorStrings.BAD_EXP_RECV.format('Enumeration.{0}',
                                                         'type', '{1}', '{2}')
        self.bad_value = ErrorStrings.BAD_EXP_RECV.format('Enumeration.{0}',
                                                          'value', '{1}',
                                                          '{2}')
        self.bad_write = ErrorStrings.BAD_EXP_RECV.format('Enumeration',
                                                          'write',
                                                          '{0} bytes',
                                                          '{1} bytes')
        self.bad_encoding = ErrorStrings.BAD_ENCODING.format('Enumeration',
                                                             'write')

    def tearDown(self):
        super(TestEnumeration, self).tearDown()

    def test_init(self):
        e = Enumeration(Types.DEFAULT)

        self.assertIsInstance(e.enum, Types,
                              self.bad_type.format('enum', Types,
                                                   type(e.enum)))
        self.assertEqual(Types.DEFAULT, e.enum,
                         self.bad_value.format('enum', Types.DEFAULT, e.enum))

        default = Types.DEFAULT
        self.assertEqual(default.value, e.value,
                         self.bad_value.format('value', default.value,
                                               e.value))

    def test_init_unset(self):
        e = Enumeration()

        self.assertEqual(None, e.enum,
                         self.bad_value.format('enum', None, e.enum))
        self.assertEqual(0, e.value,
                         self.bad_value.format('value', 0, e.value))

    def test_validate_on_valid(self):
        e = Enumeration()
        e.enum = Types.DEFAULT

        # Check no exception thrown
        e.validate()

    def test_validate_on_valid_unset(self):
        e = Enumeration()

        # Check no exception thrown
        e.validate()

    def test_validate_on_invalid_type(self):
        e = Enumeration()
        e.enum = 0

        self.assertRaises(TypeError, e.validate)

    def test_read(self):
        encoding = (b'\x42\x00\x00\x05\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00'
                    b'\x00\x00')
        self.stream = BytearrayStream(encoding)
        e = Enumeration()
        e.read(self.stream)

        self.assertIsInstance(e.enum, Types,
                              self.bad_type.format('enum', Types,
                                                   type(e.enum)))
        self.assertEqual(Types.DEFAULT, e.enum,
                         self.bad_value.format('enum', Types.DEFAULT,
                                               type(e.enum)))
        default = Types.DEFAULT
        self.assertEqual(default.value, e.value,
                         self.bad_value.format('value', default.value,
                                               e.value))

    def test_write(self):
        encoding = (b'\x42\x00\x00\x05\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00'
                    b'\x00\x00')
        e = Enumeration(Types.DEFAULT)
        e.write(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv, self.bad_write.format(len_exp,
                                                                 len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)


class TestBoolean(TestCase):

    def setUp(self):
        super(TestBoolean, self).setUp()
        self.stream = BytearrayStream()

    def tearDown(self):
        super(TestBoolean, self).tearDown()

    def test_init(self):
        self.skip('')

    def test_init_unset(self):
        self.skip('')

    def test_validate_on_valid(self):
        self.skip('')

    def test_validate_on_valid_unset(self):
        self.skip('')

    def test_validate_on_invalid_type(self):
        self.skip('')

    def test_read_value(self):
        self.skip('')

    def test_read(self):
        self.skip('')

    def test_write_value(self):
        self.skip('')

    def test_write(self):
        self.skip('')


class TestTextString(TestCase):

    def setUp(self):
        super(TestTextString, self).setUp()
        self.stream = BytearrayStream()
        self.bad_type = ErrorStrings.BAD_EXP_RECV.format('TextString.{0}',
                                                         'type', '{1}', '{2}')
        self.bad_value = ErrorStrings.BAD_EXP_RECV.format('TextString.{0}',
                                                          'value', '{1}',
                                                          '{2}')
        self.bad_read = ErrorStrings.BAD_EXP_RECV.format('TextString.{0}',
                                                         '', '{1}', '{2}')
        self.bad_write = ErrorStrings.BAD_EXP_RECV.format('TextString.{0}',
                                                          'write', '{1}',
                                                          '{2}')
        self.bad_encoding = ErrorStrings.BAD_ENCODING.format('TextString', '')
        self.bad_length = ErrorStrings.BAD_EXP_RECV.format('TextString',
                                                           'length',
                                                           '{0} bytes',
                                                           '{1} bytes')

    def tearDown(self):
        super(TestTextString, self).tearDown()

    def test_init(self):
        value = 'Hello World'
        ts = TextString(value)

        self.assertIsInstance(ts.value, str,
                              self.bad_type.format('value', str,
                                                   type(ts.value)))
        self.assertEqual(value, ts.value,
                         self.bad_value.format('value', value, ts.value))

    def test_init_unset(self):
        text_string = TextString()

        expected = string_types
        observed = text_string.value

        msg = "expected {0}, observed {1}".format(expected, observed)
        self.assertIsInstance(observed, expected, msg)

        expected = ''

        msg = "expected {0}, observed {1}".format(expected, observed)
        self.assertEqual(expected, observed, msg)

    def test_validate_on_valid(self):
        ts = TextString()
        ts.value = 'Hello World'

        # Check no exception thrown.
        ts.validate()

    def test_validate_on_valid_unset(self):
        ts = TextString()

        # Check no exception thrown.
        ts.validate()

    def test_validate_on_invalid_type(self):
        ts = TextString()
        ts.value = 0

        self.assertRaises(TypeError, ts.validate)

    def test_read_value(self):
        encoding = (b'\x48\x65\x6C\x6C\x6F\x20\x57\x6F\x72\x6C\x64\x00\x00\x00'
                    b'\x00\x00')
        self.stream = BytearrayStream(encoding)
        ts = TextString()
        ts.length = 0x0B
        ts.read_value(self.stream)

        expected = 'Hello World'
        self.assertEqual(expected, ts.value,
                         self.bad_read.format('value', expected, ts.value))

    def test_read_value_no_padding(self):
        encoding = (b'\x48\x65\x6C\x6C\x6F\x20\x57\x6F')
        self.stream = BytearrayStream(encoding)
        ts = TextString()
        ts.length = 0x08
        ts.read_value(self.stream)

        expected = 'Hello Wo'
        self.assertEqual(expected, ts.value,
                         self.bad_read.format('value', expected, ts.value))

    def test_read_value_max_padding(self):
        encoding = (b'\x48\x00\x00\x00\x00\x00\x00\x00')
        self.stream = BytearrayStream(encoding)
        ts = TextString()
        ts.length = 0x01
        ts.read_value(self.stream)

        expected = 'H'
        self.assertEqual(expected, ts.value,
                         self.bad_read.format('value', expected, ts.value))

    def test_read(self):
        encoding = (b'\x42\x00\x00\x07\x00\x00\x00\x0B\x48\x65\x6C\x6C\x6F\x20'
                    b'\x57\x6F\x72\x6C\x64\x00\x00\x00\x00\x00')
        self.stream = BytearrayStream(encoding)
        ts = TextString()
        ts.read(self.stream)

        expected = 'Hello World'
        self.assertEqual(expected, ts.value,
                         self.bad_read.format('value', expected, ts.value))

    def test_read_on_invalid_padding(self):
        encoding = (b'\x42\x00\x00\x07\x00\x00\x00\x0B\x48\x65\x6C\x6C\x6F\x20'
                    b'\x57\x6F\x72\x6C\x64\xff\xff\xff\xff\xff')
        self.stream = BytearrayStream(encoding)
        ts = TextString()

        self.assertRaises(errors.ReadValueError, ts.read, self.stream)

    def test_write_value(self):
        encoding = (b'\x48\x65\x6C\x6C\x6F\x20\x57\x6F\x72\x6C\x64\x00\x00\x00'
                    b'\x00\x00')
        self.stream = BytearrayStream()
        value = 'Hello World'
        ts = TextString(value)
        ts.write_value(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv,
                         self.bad_length.format(len_exp, len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)

    def test_write_value_no_padding(self):
        encoding = (b'\x48\x65\x6C\x6C\x6F\x20\x57\x6F')
        self.stream = BytearrayStream()
        value = 'Hello Wo'
        ts = TextString(value)
        ts.write_value(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv,
                         self.bad_length.format(len_exp, len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)

    def test_write_value_max_padding(self):
        encoding = (b'\x48\x00\x00\x00\x00\x00\x00\x00')
        self.stream = BytearrayStream()
        value = 'H'
        ts = TextString(value)
        ts.write_value(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv,
                         self.bad_length.format(len_exp, len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)

    def test_write(self):
        encoding = (b'\x42\x00\x00\x07\x00\x00\x00\x0B\x48\x65\x6C\x6C\x6F\x20'
                    b'\x57\x6F\x72\x6C\x64\x00\x00\x00\x00\x00')
        self.stream = BytearrayStream()
        value = 'Hello World'
        ts = TextString(value)
        ts.write(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv,
                         self.bad_length.format(len_exp, len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)


class TestByteString(TestCase):

    def setUp(self):
        super(TestByteString, self).setUp()
        self.stream = BytearrayStream()
        self.bad_type = ErrorStrings.BAD_EXP_RECV.format('ByteString.{0}',
                                                         'type', '{1}', '{2}')
        self.bad_value = ErrorStrings.BAD_EXP_RECV.format('ByteString.{0}',
                                                          'value', '{1}',
                                                          '{2}')
        self.bad_read = ErrorStrings.BAD_EXP_RECV.format('ByteString.{0}',
                                                         '', '{1}', '{2}')
        self.bad_write = ErrorStrings.BAD_EXP_RECV.format('ByteString.{0}',
                                                          'write', '{1}',
                                                          '{2}')
        self.bad_encoding = ErrorStrings.BAD_ENCODING.format('ByteString', '')
        self.bad_length = ErrorStrings.BAD_EXP_RECV.format('ByteString',
                                                           'length',
                                                           '{0} bytes',
                                                           '{1} bytes')

    def tearDown(self):
        super(TestByteString, self).tearDown()

    def test_init(self):
        value = b'\x01\x02\x03'
        bs = ByteString(value)

        self.assertIsInstance(bs.value, bytes,
                              self.bad_type.format('value', bytes,
                                                   type(bs.value)))
        self.assertEqual(value, bs.value,
                         self.bad_value.format('value', value, bs.value))

    def test_init_unset(self):
        bs = ByteString()

        self.assertIsInstance(bs.value, bytes,
                              self.bad_type.format('value', type(None),
                                                   type(bs.value)))
        self.assertEqual(bytes(), bs.value,
                         self.bad_value.format('value', None, bs.value))

    def test_validate_on_valid(self):
        bs = ByteString()
        bs.value = b'\x00'

        # Check no exception thrown.
        bs.validate()

    def test_validate_on_valid_unset(self):
        bs = ByteString()

        # Check no exception thrown.
        bs.validate()

    def test_validate_on_invalid_type(self):
        bs = ByteString()
        bs.value = 0

        self.assertRaises(TypeError, bs.validate)

    def test_read_value(self):
        encoding = b'\x01\x02\x03\x00\x00\x00\x00\x00'
        self.stream = BytearrayStream(encoding)
        bs = ByteString()
        bs.length = 0x03
        bs.read_value(self.stream)

        expected = b'\x01\x02\x03'
        self.assertEqual(expected, bs.value,
                         self.bad_read.format('value', expected, bs.value))

    def test_read_value_no_padding(self):
        encoding = b'\x01\x02\x03\x04\x05\x06\x07\x08'
        self.stream = BytearrayStream(encoding)
        bs = ByteString()
        bs.length = 0x08
        bs.read_value(self.stream)

        expected = b'\x01\x02\x03\x04\x05\x06\x07\x08'
        self.assertEqual(expected, bs.value,
                         self.bad_read.format('value', expected, bs.value))

    def test_read_value_max_padding(self):
        encoding = b'\x01\x00\x00\x00\x00\x00\x00\x00'
        self.stream = BytearrayStream(encoding)
        bs = ByteString()
        bs.length = 0x01
        bs.read_value(self.stream)

        expected = b'\x01'
        self.assertEqual(expected, bs.value,
                         self.bad_read.format('value', expected, bs.value))

    def test_read_value_zero(self):
        encoding = b'\x00\x00\x00\x00\x00\x00\x00\x00'
        self.stream = BytearrayStream(encoding)
        bs = ByteString()
        bs.length = 0x01
        bs.read_value(self.stream)

        expected = b'\x00'
        self.assertEqual(expected, bs.value,
                         self.bad_read.format('value', expected, bs.value))

    def test_read(self):
        encoding = (b'\x42\x00\x00\x08\x00\x00\x00\x03\x01\x02\x03\x00\x00\x00'
                    b'\x00\x00')
        self.stream = BytearrayStream(encoding)
        bs = ByteString()
        bs.read(self.stream)

        expected = b'\x01\x02\x03'
        self.assertEqual(expected, bs.value,
                         self.bad_read.format('value', expected, bs.value))

    def test_read_on_invalid_padding(self):
        encoding = (b'\x42\x00\x00\x08\x00\x00\x00\x03\x01\x02\x03\xff\xff\xff'
                    b'\xff\xff')
        self.stream = BytearrayStream(encoding)
        bs = ByteString()

        self.assertRaises(errors.ReadValueError, bs.read, self.stream)

    def test_write_value(self):
        encoding = b'\x01\x02\x03\x00\x00\x00\x00\x00'
        self.stream = BytearrayStream()
        value = b'\x01\x02\x03'
        bs = ByteString(value)
        bs.write_value(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv,
                         self.bad_length.format(len_exp, len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)

    def test_write_value_no_padding(self):
        encoding = b'\x01\x02\x03\x04\x05\x06\x07\x08'
        self.stream = BytearrayStream()
        value = b'\x01\x02\x03\x04\x05\x06\x07\x08'
        bs = ByteString(value)
        bs.write_value(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv,
                         self.bad_length.format(len_exp, len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)

    def test_write_value_max_padding(self):
        encoding = b'\x01\x00\x00\x00\x00\x00\x00\x00'
        self.stream = BytearrayStream()
        value = b'\x01'
        bs = ByteString(value)
        bs.write_value(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv,
                         self.bad_length.format(len_exp, len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)

    def test_write_value_zero(self):
        encoding = b'\x00\x00\x00\x00\x00\x00\x00\x00'
        self.stream = BytearrayStream()
        value = b'\x00'
        bs = ByteString(value)
        bs.write_value(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv,
                         self.bad_length.format(len_exp, len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)

    def test_write(self):
        encoding = (b'\x42\x00\x00\x08\x00\x00\x00\x03\x01\x02\x03\x00\x00\x00'
                    b'\x00\x00')
        self.stream = BytearrayStream()
        value = b'\x01\x02\x03'
        bs = ByteString(value)
        bs.write(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv,
                         self.bad_length.format(len_exp, len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)


class TestDateTime(TestCase):

    def setUp(self):
        super(TestDateTime, self).setUp()
        self.stream = BytearrayStream()

    def tearDown(self):
        super(TestDateTime, self).tearDown()

    def test_init(self):
        self.skip('')

    def test_init_unset(self):
        self.skip('')

    def test_validate_on_valid(self):
        self.skip('')

    def test_validate_on_valid_unset(self):
        self.skip('')

    def test_validate_on_invalid_type(self):
        self.skip('')

    def test_read(self):
        self.skip('')

    def test_write(self):
        self.skip('')


class TestInterval(TestCase):

    def setUp(self):
        super(TestInterval, self).setUp()
        self.stream = BytearrayStream()

    def tearDown(self):
        super(TestInterval, self).tearDown()

    def test_init(self):
        self.skip('')

    def test_init_unset(self):
        self.skip('')

    def test_validate_on_valid(self):
        self.skip('')

    def test_validate_on_valid_unset(self):
        self.skip('')

    def test_validate_on_invalid_type(self):
        self.skip('')

    def test_read(self):
        self.skip('')

    def test_write(self):
        self.skip('')
