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

from kmip.core import errors
from kmip.core import primitives
from kmip.core import utils


class TestLongInteger(testtools.TestCase):

    def setUp(self):
        super(TestLongInteger, self).setUp()
        self.stream = utils.BytearrayStream()
        self.max_byte_long = 18446744073709551615
        self.max_long = 9223372036854775807
        self.bad_value = (
            'Bad primitives.LongInteger.{0} after init: expected {1}, '
            'received {2}')
        self.bad_write = (
            'Bad primitives.LongInteger write: expected {0} bytes, '
            'received {1} bytes')
        self.bad_encoding = (
            'Bad primitives.LongInteger write: encoding mismatch')
        self.bad_read = (
            'Bad primitives.LongInteger.value read: expected {0}, '
            'received {1}')

    def tearDown(self):
        super(TestLongInteger, self).tearDown()

    def test_init(self):
        i = primitives.LongInteger(0)

        self.assertEqual(0, i.value,
                         self.bad_value.format('value', 0, i.value))
        self.assertEqual(i.LENGTH, i.length,
                         self.bad_value.format('length', i.LENGTH, i.length))

    def test_init_unset(self):
        i = primitives.LongInteger()

        self.assertEqual(None, i.value,
                         self.bad_value.format('value', None, i.value))
        self.assertEqual(i.LENGTH, i.length,
                         self.bad_value.format('length', i.LENGTH, i.length))

    def test_validate_on_valid(self):
        i = primitives.LongInteger()
        i.value = 0

        # Check no exception thrown
        i.validate()

    def test_validate_on_valid_long(self):
        i = primitives.LongInteger()
        i.value = self.max_long + 1

        # Check no exception thrown
        i.validate()

    def test_validate_on_valid_unset(self):
        i = primitives.LongInteger()

        # Check no exception thrown
        i.validate()

    def test_validate_on_invalid_type(self):
        i = primitives.LongInteger()
        i.value = 'test'

        self.assertRaises(errors.StateTypeError, i.validate)

    def test_validate_on_invalid_value(self):
        self.assertRaises(errors.StateOverflowError, primitives.LongInteger,
                          self.max_byte_long + 1)

    def test_read_value(self):
        encoding = (b'\x00\x00\x00\x00\x00\x00\x00\x01')
        self.stream = utils.BytearrayStream(encoding)
        i = primitives.LongInteger()
        i.read_value(self.stream)

        self.assertEqual(1, i.value, self.bad_read.format(1, i.value))

    def test_read_value_zero(self):
        encoding = (b'\x00\x00\x00\x00\x00\x00\x00\x00')
        self.stream = utils.BytearrayStream(encoding)
        i = primitives.LongInteger()
        i.read_value(self.stream)

        self.assertEqual(0, i.value, self.bad_read.format(0, i.value))

    def test_read_value_max_positive(self):
        encoding = (b'\x7f\xff\xff\xff\xff\xff\xff\xff')
        self.stream = utils.BytearrayStream(encoding)
        i = primitives.LongInteger()
        i.read_value(self.stream)

        self.assertEqual(self.max_long, i.value,
                         self.bad_read.format(1, i.value))

    def test_read_value_min_negative(self):
        encoding = (b'\xff\xff\xff\xff\xff\xff\xff\xff')
        self.stream = utils.BytearrayStream(encoding)
        i = primitives.LongInteger()
        i.read_value(self.stream)

        self.assertEqual(-1, i.value,
                         self.bad_read.format(1, i.value))

    def test_read(self):
        encoding = (
            b'\x42\x00\x00\x03\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00'
            b'\x01')
        self.stream = utils.BytearrayStream(encoding)
        i = primitives.LongInteger()
        i.read(self.stream)

        self.assertEqual(1, i.value, self.bad_read.format(1, i.value))

    def test_read_on_invalid_length(self):
        encoding = (
            b'\x42\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00')
        self.stream = utils.BytearrayStream(encoding)
        i = primitives.LongInteger()

        self.assertRaises(errors.ReadValueError, i.read, self.stream)

    def test_write_value(self):
        encoding = (b'\x00\x00\x00\x00\x00\x00\x00\x01')
        i = primitives.LongInteger(1)
        i.write_value(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv, self.bad_write.format(len_exp,
                                                                 len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)

    def test_write_value_zero(self):
        encoding = (b'\x00\x00\x00\x00\x00\x00\x00\x00')
        i = primitives.LongInteger(0)
        i.write_value(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv, self.bad_write.format(len_exp,
                                                                 len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)

    def test_write_value_max_positive(self):
        encoding = (b'\x7f\xff\xff\xff\xff\xff\xff\xff')
        i = primitives.LongInteger(self.max_long)
        i.write_value(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv, self.bad_write.format(len_exp,
                                                                 len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)

    def test_write_value_min_negative(self):
        encoding = (b'\xff\xff\xff\xff\xff\xff\xff\xff')
        i = primitives.LongInteger(-1)
        i.write_value(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv, self.bad_write.format(len_exp,
                                                                 len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)

    def test_write(self):
        encoding = (
            b'\x42\x00\x00\x03\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00'
            b'\x01')
        i = primitives.LongInteger(1)
        i.write(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv, self.bad_write.format(len_exp,
                                                                 len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)
