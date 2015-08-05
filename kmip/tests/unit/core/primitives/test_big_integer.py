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

from kmip.core import enums
from kmip.core import errors
from kmip.core import primitives
from kmip.core import utils


class TestBigInteger(testtools.TestCase):

    def setUp(self):
        super(TestBigInteger, self).setUp()
        self.stream = utils.BytearrayStream()
        self.max_byte_long = 18446744073709551615
        self.max_long = 9223372036854775807
        self.bad_value = (
            'Bad primitives.BigInteger.{0} after init: expected {1}, '
            'received {2}')
        self.bad_write = (
            'Bad primitives.BigInteger write: expected {0} bytes, '
            'received {1} bytes')
        self.bad_encoding = (
            'Bad primitives.BigInteger write: encoding mismatch')
        self.bad_read = (
            'Bad primitives.BigInteger.value read: expected {0}, '
            'received {1}')

    def tearDown(self):
        super(TestBigInteger, self).tearDown()

    def test_big_integer(self):
        self.skip('primitives.BigInteger implementation incomplete')
        i = primitives.BigInteger(0)

        self.assertEqual(0, i.value,
                         self.bad_value.format('value', 0, i.value))
        self.assertEqual(1, i.length,
                         self.bad_value.format('length', 1, i.length))
        self.assertEqual(i.BLOCK_SIZE - 1, i.padding_length,
                         self.bad_value.format('padding_length',
                                               i.BLOCK_SIZE - 1,
                                               i.padding_length))

    def test_big_integer_unset(self):
        self.skip('primitives.BigInteger implementation incomplete')
        i = primitives.BigInteger()

        self.assertEqual(None, i.value,
                         self.bad_value.format('value', None, i.value))
        self.assertEqual(None, i.length,
                         self.bad_value.format('length', None, i.length))
        self.assertEqual(None, i.padding_length,
                         self.bad_value.format('padding_length', None,
                                               i.padding_length))

    def test_validate_on_valid(self):
        self.skip('primitives.BigInteger implementation incomplete')
        i = primitives.BigInteger()
        i.value = 0
        i.length = i.BLOCK_SIZE
        i.padding_length = 0

        # Check no exception thrown
        i.validate()

    def test_validate_on_valid_long(self):
        self.skip('primitives.BigInteger implementation incomplete')
        i = primitives.BigInteger()
        i.value = self.max_long + 1
        i.length = i.BLOCK_SIZE
        i.padding_length = 0

        # Check no exception thrown
        i.validate()

    def test_validate_on_valid_unset(self):
        self.skip('primitives.BigInteger implementation incomplete')
        i = primitives.BigInteger()

        # Check no exception thrown
        i.validate()

    def test_validate_on_invalid_type(self):
        self.skip('primitives.BigInteger implementation incomplete')
        i = primitives.BigInteger()
        i.value = 'test'

        self.assertRaises(errors.StateTypeError, i.validate)

    def test_write(self):
        self.skip('primitives.BigInteger implementation incomplete')
        encoding = (
            b'\x42\x00\x01\x04\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00'
            b'\x01')
        i = primitives.BigInteger(1)
        i.TAG = enums.Tags.ACTIVATION_DATE
        i.write(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv, self.bad_write.format(len_exp,
                                                                 len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)

    def test_write_zero(self):
        self.skip('primitives.BigInteger implementation incomplete')
        encoding = (
            b'\x42\x00\x01\x04\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00'
            b'\x00')
        i = primitives.BigInteger(0)
        i.TAG = enums.Tags.ACTIVATION_DATE
        i.write(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv, self.bad_write.format(len_exp,
                                                                 len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)

    def test_write_max_positive_value(self):
        self.skip('primitives.BigInteger implementation incomplete')
        encoding = (
            b'\x42\x00\x01\x04\x00\x00\x00\x08\x7f\xff\xff\xff\xff\xff\xff'
            b'\xff')
        i = primitives.BigInteger(self.max_long)
        i.TAG = enums.Tags.ACTIVATION_DATE
        i.write(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv, self.bad_write.format(len_exp,
                                                                 len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)

    def test_write_min_negative_value(self):
        self.skip('primitives.BigInteger implementation incomplete')
        encoding = (
            b'\x42\x00\x01\x04\x00\x00\x00\x08\xff\xff\xff\xff\xff\xff\xff'
            b'\xff')
        i = primitives.BigInteger(-1)
        i.TAG = enums.Tags.ACTIVATION_DATE
        i.write(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv, self.bad_write.format(len_exp,
                                                                 len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)

    def test_read(self):
        self.skip('primitives.BigInteger implementation incomplete')
        encoding = (
            b'\x42\x00\x01\x04\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00'
            b'\x01')
        self.stream = utils.BytearrayStream(encoding)
        i = primitives.BigInteger()
        i.TAG = enums.Tags.ACTIVATION_DATE
        i.read(self.stream)

        self.assertEqual(1, i.value, self.bad_read.format(1, i.value))

    def test_read_zero(self):
        self.skip('primitives.BigInteger implementation incomplete')
        encoding = (
            b'\x42\x00\x01\x04\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00'
            b'\x00')
        self.stream = utils.BytearrayStream(encoding)
        i = primitives.BigInteger()
        i.TAG = enums.Tags.ACTIVATION_DATE
        i.read(self.stream)

        self.assertEqual(0, i.value, self.bad_read.format(0, i.value))

    def test_read_max_positive_value(self):
        self.skip('primitives.BigInteger implementation incomplete')
        encoding = (
            b'\x42\x00\x01\x04\x00\x00\x00\x08\x7f\xff\xff\xff\xff\xff\xff'
            b'\xff')
        self.stream = utils.BytearrayStream(encoding)
        i = primitives.BigInteger()
        i.TAG = enums.Tags.ACTIVATION_DATE
        i.read(self.stream)

        self.assertEqual(self.max_long, i.value,
                         self.bad_read.format(1, i.value))

    def test_read_min_negative_value(self):
        self.skip('primitives.BigInteger implementation incomplete')
        encoding = (
            b'\x42\x00\x01\x04\x00\x00\x00\x08\xff\xff\xff\xff\xff\xff\xff'
            b'\xff')
        self.stream = utils.BytearrayStream(encoding)
        i = primitives.BigInteger()
        i.TAG = enums.Tags.ACTIVATION_DATE
        i.read(self.stream)

        self.assertEqual(-1, i.value,
                         self.bad_read.format(1, i.value))

    def test_read_on_invalid_length(self):
        self.skip('primitives.BigInteger implementation incomplete')
        encoding = (
            b'\x42\x00\x01\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00')
        self.stream = utils.BytearrayStream(encoding)
        i = primitives.BigInteger()
        i.TAG = enums.Tags.ACTIVATION_DATE

        self.assertRaises(errors.InvalidLengthError, i.read, self.stream)
