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


class TestInteger(testtools.TestCase):

    def setUp(self):
        super(TestInteger, self).setUp()
        self.stream = utils.BytearrayStream()
        self.max_byte_int = 4294967295
        self.max_int = 2147483647
        self.bad_value = (
            'Bad primitives.Integer.{0} after init: expected {1}, '
            'received {2}')
        self.bad_write = (
            'Bad primitives.Integer write: expected {0} bytes, '
            'received {1} bytes')
        self.bad_encoding = 'Bad primitives.Integer write: encoding mismatch'
        self.bad_read = (
            'Bad primitives.Integer.value read: expected {0}, received {1}')

    def tearDown(self):
        super(TestInteger, self).tearDown()

    def test_init(self):
        i = primitives.Integer(0)

        self.assertEqual(0, i.value,
                         self.bad_value.format('value', 0, i.value))
        self.assertEqual(i.LENGTH, i.length,
                         self.bad_value.format('length', i.LENGTH, i.length))
        self.assertEqual(i.LENGTH, i.padding_length,
                         self.bad_value.format('padding_length', i.LENGTH,
                                               i.padding_length))

    def test_init_unset(self):
        i = primitives.Integer()

        self.assertEqual(0, i.value,
                         self.bad_value.format('value', 0, i.value))
        self.assertEqual(i.LENGTH, i.length,
                         self.bad_value.format('length', i.LENGTH, i.length))
        self.assertEqual(i.LENGTH, i.padding_length,
                         self.bad_value.format('padding_length', i.LENGTH,
                                               i.padding_length))

    def test_validate_on_valid(self):
        i = primitives.Integer()
        i.value = 0

        # Check no exception thrown
        i.validate()

    def test_validate_on_valid_unset(self):
        i = primitives.Integer()

        # Check no exception thrown
        i.validate()

    def test_validate_on_invalid_type(self):
        """
        Test that a TypeError is thrown on input of invalid type (e.g., str).
        """
        self.assertRaises(TypeError, primitives.Integer, 'invalid')

    def test_validate_on_invalid_value_too_big(self):
        """
        Test that a ValueError is thrown on input that is too large.
        """
        self.assertRaises(
            ValueError, primitives.Integer, primitives.Integer.MAX + 1)

    def test_validate_on_invalid_value_too_small(self):
        """
        Test that a ValueError is thrown on input that is too small.
        """
        self.assertRaises(
            ValueError, primitives.Integer, primitives.Integer.MIN - 1)

    def test_read_value(self):
        encoding = (b'\x00\x00\x00\x01\x00\x00\x00\x00')
        self.stream = utils.BytearrayStream(encoding)
        i = primitives.Integer()
        i.read_value(self.stream)

        self.assertEqual(1, i.value, self.bad_read.format(1, i.value))

    def test_read_value_zero(self):
        encoding = (b'\x00\x00\x00\x00\x00\x00\x00\x00')
        self.stream = utils.BytearrayStream(encoding)
        i = primitives.Integer()
        i.read_value(self.stream)

        self.assertEqual(0, i.value, self.bad_read.format(0, i.value))

    def test_read_value_max_positive(self):
        encoding = (b'\x7f\xff\xff\xff\x00\x00\x00\x00')
        self.stream = utils.BytearrayStream(encoding)
        i = primitives.Integer()
        i.read_value(self.stream)

        self.assertEqual(self.max_int, i.value,
                         self.bad_read.format(1, i.value))

    def test_read_value_min_negative(self):
        encoding = (b'\xff\xff\xff\xff\x00\x00\x00\x00')
        self.stream = utils.BytearrayStream(encoding)
        i = primitives.Integer()
        i.read_value(self.stream)

        self.assertEqual(-1, i.value,
                         self.bad_read.format(1, i.value))

    def test_read(self):
        encoding = (
            b'\x42\x00\x00\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00'
            b'\x00')
        self.stream = utils.BytearrayStream(encoding)
        i = primitives.Integer()
        i.read(self.stream)

        self.assertEqual(1, i.value, self.bad_read.format(1, i.value))

    def test_read_on_invalid_length(self):
        encoding = (
            b'\x42\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00')
        self.stream = utils.BytearrayStream(encoding)
        i = primitives.Integer()

        self.assertRaises(errors.ReadValueError, i.read, self.stream)

    def test_read_on_invalid_padding(self):
        encoding = (
            b'\x42\x00\x00\x02\x00\x00\x00\x04\x00\x00\x00\x00\xff\xff\xff'
            b'\xff')
        self.stream = utils.BytearrayStream(encoding)
        i = primitives.Integer()

        self.assertRaises(errors.ReadValueError, i.read, self.stream)

    def test_write_value(self):
        encoding = (b'\x00\x00\x00\x01\x00\x00\x00\x00')
        i = primitives.Integer(1)
        i.write_value(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv, self.bad_write.format(len_exp,
                                                                 len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)

    def test_write_value_zero(self):
        encoding = (b'\x00\x00\x00\x00\x00\x00\x00\x00')
        i = primitives.Integer(0)
        i.write_value(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv, self.bad_write.format(len_exp,
                                                                 len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)

    def test_write_value_max_positive(self):
        encoding = (b'\x7f\xff\xff\xff\x00\x00\x00\x00')
        i = primitives.Integer(self.max_int)
        i.write_value(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv, self.bad_write.format(len_exp,
                                                                 len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)

    def test_write_value_min_negative(self):
        encoding = (b'\xff\xff\xff\xff\x00\x00\x00\x00')
        i = primitives.Integer(-1)
        i.write_value(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv, self.bad_write.format(len_exp,
                                                                 len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)

    def test_write(self):
        encoding = (
            b'\x42\x00\x00\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00'
            b'\x00')
        i = primitives.Integer(1)
        i.write(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv, self.bad_write.format(len_exp,
                                                                 len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)
