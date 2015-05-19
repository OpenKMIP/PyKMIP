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

from testtools import TestCase

from kmip.core.errors import ErrorStrings

from kmip.core import utils


class TestUtils(TestCase):

    def setUp(self):
        super(TestUtils, self).setUp()

    def tearDown(self):
        super(TestUtils, self).tearDown()

    def test_count_bytes(self):
        num = 65535
        bytes_exp = 2
        bytes_obs = utils.count_bytes(num)
        self.assertEqual(bytes_exp, bytes_obs,
                         'Value {0} requires {1} bytes to encode, '
                         'received {2} byte(s)'.format(num, bytes_exp,
                                                       bytes_obs))

    def test_count_bytes_overflow(self):
        num = 65536
        bytes_exp = 3
        bytes_obs = utils.count_bytes(num)
        self.assertEqual(bytes_exp, bytes_obs,
                         'Value {0} requires {1} bytes to encode, '
                         'received {2} bytes'.format(num, bytes_exp,
                                                     bytes_obs))

    def test_count_bytes_zero(self):
        num = 0
        bytes_exp = 1
        bytes_obs = utils.count_bytes(num)
        self.assertEqual(bytes_exp, bytes_obs,
                         'Value {0} requires {1} bytes to encode, '
                         'received {2} byte(s)'.format(num, bytes_exp,
                                                       bytes_obs))


class TestBytearrayStream(TestCase):

    def setUp(self):
        super(TestBytearrayStream, self).setUp()
        self.stream = utils.BytearrayStream()

        self.bad_type = ErrorStrings.BAD_EXP_RECV.format('BytearrayStream.{0}',
                                                         'type', '{1}', '{2}')
        self.bad_len = ErrorStrings.BAD_EXP_RECV.format('BytearrayStream.{0}',
                                                        'length', '{1}', '{2}')
        self.bad_val = ErrorStrings.BAD_EXP_RECV.format('BytearrayStream.{0}',
                                                        'value', '{1}', '{2}')

    def tearDown(self):
        super(TestBytearrayStream, self).tearDown()

    def test_init(self):
        value = b'\x00'
        b = utils.BytearrayStream(value)

        buf_type = type(b.buffer)
        msg = self.bad_type.format('buffer', type(b''), buf_type)
        self.assertIsInstance(b.buffer, type(b''),
                              msg.format(type(b''), type(b.buffer)))

        length = len(b.buffer)
        msg = self.bad_len.format('buffer', 1, length)
        self.assertEqual(1, length, msg)

        content = b.buffer
        msg = self.bad_val.format('buffer', value, content)
        self.assertEqual(value, content, msg)

    def test_init_unset(self):
        b = utils.BytearrayStream()

        buf_type = type(b.buffer)
        msg = self.bad_type.format('buffer', type(b''), buf_type)
        self.assertIsInstance(b.buffer, type(b''),
                              msg.format(type(b''), type(b.buffer)))

        length = len(b.buffer)
        msg = self.bad_len.format('buffer', 0, length)
        self.assertEqual(0, length, msg)

    def test_read(self):
        # TODO (peter-hamilton) Finish implementation.
        self.skip('')

    def test_write(self):
        # TODO (peter-hamilton) Finish implementation.
        self.skip('')

    def test_peek(self):
        # TODO (peter-hamilton) Finish implementation.
        value = (b'\x00\x01\x02\x03')
        expected = value
        b = expected
        expected = b
        b = utils.BytearrayStream(value)

    def test_peek_overflow(self):
        # TODO (peter-hamilton) Finish implementation.
        self.skip('')

    def test_peek_empty(self):
        # TODO (peter-hamilton) Finish implementation.
        self.skip('')

    def test_peek_none(self):
        # TODO (peter-hamilton) Finish implementation.
        self.skip('')

    def test_length(self):
        # TODO (peter-hamilton) Finish implementation.
        self.skip('')
