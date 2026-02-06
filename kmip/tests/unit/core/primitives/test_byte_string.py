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

class TestByteString(testtools.TestCase):

    def setUp(self):
        super(TestByteString, self).setUp()
        self.stream = utils.BytearrayStream()
        self.bad_type = exceptions.ErrorStrings.BAD_EXP_RECV.format(
            'primitives.ByteString.{0}', 'type', '{1}', '{2}')
        self.bad_value = exceptions.ErrorStrings.BAD_EXP_RECV.format(
            'primitives.ByteString.{0}', 'value', '{1}', '{2}')
        self.bad_read = exceptions.ErrorStrings.BAD_EXP_RECV.format(
            'primitives.ByteString.{0}', '', '{1}', '{2}')
        self.bad_write = exceptions.ErrorStrings.BAD_EXP_RECV.format(
            'primitives.ByteString.{0}', 'write', '{1}', '{2}')
        self.bad_encoding = exceptions.ErrorStrings.BAD_ENCODING.format(
            'primitives.ByteString', '')
        self.bad_length = exceptions.ErrorStrings.BAD_EXP_RECV.format(
            'primitives.ByteString', 'length', '{0} bytes', '{1} bytes')

    def tearDown(self):
        super(TestByteString, self).tearDown()

    def test_init(self):
        value = b'\x01\x02\x03'
        bs = primitives.ByteString(value)

        self.assertIsInstance(bs.value, bytes,
                              self.bad_type.format('value', bytes,
                                                   type(bs.value)))
        self.assertEqual(value, bs.value,
                         self.bad_value.format('value', value, bs.value))

    def test_init_unset(self):
        bs = primitives.ByteString()

        self.assertIsInstance(bs.value, bytes,
                              self.bad_type.format('value', type(None),
                                                   type(bs.value)))
        self.assertEqual(bytes(), bs.value,
                         self.bad_value.format('value', None, bs.value))

    def test_validate_on_valid(self):
        bs = primitives.ByteString()
        bs.value = b'\x00'

        # Check no exception thrown.
        bs.validate()

    def test_validate_on_valid_unset(self):
        bs = primitives.ByteString()

        # Check no exception thrown.
        bs.validate()

    def test_validate_on_invalid_type(self):
        bs = primitives.ByteString()
        bs.value = 0

        self.assertRaises(TypeError, bs.validate)

    def test_read_value(self):
        encoding = b'\x01\x02\x03\x00\x00\x00\x00\x00'
        self.stream = utils.BytearrayStream(encoding)
        bs = primitives.ByteString()
        bs.length = 0x03
        bs.read_value(self.stream)

        expected = b'\x01\x02\x03'
        self.assertEqual(expected, bs.value,
                         self.bad_read.format('value', expected, bs.value))

    def test_read_value_no_padding(self):
        encoding = b'\x01\x02\x03\x04\x05\x06\x07\x08'
        self.stream = utils.BytearrayStream(encoding)
        bs = primitives.ByteString()
        bs.length = 0x08
        bs.read_value(self.stream)

        expected = b'\x01\x02\x03\x04\x05\x06\x07\x08'
        self.assertEqual(expected, bs.value,
                         self.bad_read.format('value', expected, bs.value))

    def test_read_value_max_padding(self):
        encoding = b'\x01\x00\x00\x00\x00\x00\x00\x00'
        self.stream = utils.BytearrayStream(encoding)
        bs = primitives.ByteString()
        bs.length = 0x01
        bs.read_value(self.stream)

        expected = b'\x01'
        self.assertEqual(expected, bs.value,
                         self.bad_read.format('value', expected, bs.value))

    def test_read_value_zero(self):
        encoding = b'\x00\x00\x00\x00\x00\x00\x00\x00'
        self.stream = utils.BytearrayStream(encoding)
        bs = primitives.ByteString()
        bs.length = 0x01
        bs.read_value(self.stream)

        expected = b'\x00'
        self.assertEqual(expected, bs.value,
                         self.bad_read.format('value', expected, bs.value))

    def test_read(self):
        encoding = (
            b'\x42\x00\x00\x08\x00\x00\x00\x03\x01\x02\x03\x00\x00\x00\x00'
            b'\x00')
        self.stream = utils.BytearrayStream(encoding)
        bs = primitives.ByteString()
        bs.read(self.stream)

        expected = b'\x01\x02\x03'
        self.assertEqual(expected, bs.value,
                         self.bad_read.format('value', expected, bs.value))

    def test_read_on_invalid_padding(self):
        encoding = (
            b'\x42\x00\x00\x08\x00\x00\x00\x03\x01\x02\x03\xff\xff\xff\xff'
            b'\xff')
        self.stream = utils.BytearrayStream(encoding)
        bs = primitives.ByteString()

        self.assertRaises(exceptions.ReadValueError, bs.read, self.stream)

    def test_write_value(self):
        encoding = b'\x01\x02\x03\x00\x00\x00\x00\x00'
        self.stream = utils.BytearrayStream()
        value = b'\x01\x02\x03'
        bs = primitives.ByteString(value)
        bs.write_value(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv,
                         self.bad_length.format(len_exp, len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)

    def test_write_value_no_padding(self):
        encoding = b'\x01\x02\x03\x04\x05\x06\x07\x08'
        self.stream = utils.BytearrayStream()
        value = b'\x01\x02\x03\x04\x05\x06\x07\x08'
        bs = primitives.ByteString(value)
        bs.write_value(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv,
                         self.bad_length.format(len_exp, len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)

    def test_write_value_max_padding(self):
        encoding = b'\x01\x00\x00\x00\x00\x00\x00\x00'
        self.stream = utils.BytearrayStream()
        value = b'\x01'
        bs = primitives.ByteString(value)
        bs.write_value(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv,
                         self.bad_length.format(len_exp, len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)

    def test_write_value_zero(self):
        encoding = b'\x00\x00\x00\x00\x00\x00\x00\x00'
        self.stream = utils.BytearrayStream()
        value = b'\x00'
        bs = primitives.ByteString(value)
        bs.write_value(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv,
                         self.bad_length.format(len_exp, len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)

    def test_write(self):
        encoding = (
            b'\x42\x00\x00\x08\x00\x00\x00\x03\x01\x02\x03\x00\x00\x00\x00'
            b'\x00')
        self.stream = utils.BytearrayStream()
        value = b'\x01\x02\x03'
        bs = primitives.ByteString(value)
        bs.write(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv,
                         self.bad_length.format(len_exp, len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)
